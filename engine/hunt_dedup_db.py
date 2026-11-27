"""
SQLite WAL Persistent Processed-Target & Drafted-Finding Deduplication Store (`hunt_dedup_db.py`).
==================================================================================================

Eliminates duplicate scans and duplicate HackerOne drafts across repeated `--hunt`, `--swarm`,
and `--cdp-url` runs by persisting both processed target revisions and drafted/submitted findings
in a crash-safe SQLite WAL database (`out/autonomous_hunt/hunt_state.sqlite3` by default):

  1. `processed_targets`:
     - Tracks `(program, target_key)` alongside its exact `git rev-parse HEAD` SHA (for repos)
       or deterministic `(rel_path, size, mtime_ns)` SHA-256 content digest (for local folders).
     - Automatically skips re-auditing unchanged repos/folders across back-to-back runs unless
       a new commit lands or `--force-rescan` is explicitly requested.
  2. `drafted_findings`:
     - Persists every locally ported Markdown draft (`local_md`), browser-staged HackerOne draft
       (`browser_staged`), API submission (`hackerone_api_v1`), and existing live HackerOne
       draft/open/closed report (`hackerone_existing_draft`, `hackerone_submitted`,
       `hackerone_closed`) synced from both `DraftSubmitTrackerDB` and live `/bugs.json`.
     - Enforces a 4-layer deterministic deduplication gate BEFORE porting or staging:
       (a) Exact SHA-256 fingerprint match
       (b) Same `(program, file_path, rule_id)` match (resilient to line shifts)
       (c) Same `(program, file_path, cwe)` match (cross-scanner dedup)
       (d) Program-scoped code-anchor (`run_eval.py`, `procfs.c`, etc.) + title Jaccard overlap
           against existing live HackerOne drafts and submitted/closed reports.
  3. `dedup_events`:
     - Records every skipped duplicate target, finding, or staging attempt for full auditability.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import subprocess
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_HUNT_DEDUP_DB = Path("out/autonomous_hunt/hunt_state.sqlite3")

REMOTE_OR_STAGED_MODES: frozenset[str] = frozenset(
    {
        "browser_staged",
        "hackerone_existing_draft",
        "hackerone_api_v1",
        "hackerone_submitted",
        "hackerone_closed",
    }
)

_DELIVERY_MODE_RANK: dict[str, int] = {
    "local_md": 1,
    "browser_staged": 2,
    "hackerone_existing_draft": 3,
    "hackerone_api_v1": 4,
    "hackerone_submitted": 5,
    "hackerone_closed": 6,
}

_STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "for",
        "via",
        "with",
        "from",
        "into",
        "that",
        "this",
        "when",
        "without",
        "missing",
        "unchecked",
        "unvalidated",
        "unsanitized",
        "improper",
        "possible",
        "potential",
        "security",
        "vulnerability",
        "defect",
        "issue",
        "error",
        "bug",
        "code",
        "file",
        "files",
        "allows",
        "allow",
        "bypass",
        "bypasses",
        "multiple",
        "default",
        "arbitrary",
        "local",
        "remote",
    }
)

_GENERIC_FILENAMES: frozenset[str] = frozenset(
    {
        "repository",
        "index.js",
        "index.ts",
        "main.py",
        "app.py",
        "init.py",
        "__init__.py",
        "utils.py",
        "helpers.py",
        "config.py",
        "readme.md",
    }
)

_SKIP_DIGEST_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "target",
        "dist",
        "build",
        ".mypy_cache",
        ".ruff_cache",
    }
)

_CODE_ANCHOR_RE = re.compile(
    r"\b([A-Za-z0-9_.-]+\.(?:py|ts|tsx|js|jsx|mjs|cjs|rb|go|java|kt|swift|rs|c|h|cc|cpp|cs|php|sh|yml|yaml|json|xml|conf|toml))\b",
    re.IGNORECASE,
)

_H1_REPORT_ID_RE = re.compile(r"/reports/(\d+)\b")


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_program(program: str) -> str:
    return str(program or "generic").strip().lower() or "generic"


def normalize_file_path(file_path: str) -> str:
    raw = str(file_path or "").strip().replace("\\", "/")
    if not raw:
        return ""
    # Strip temp/cache prefixes so `/tmp/.../repos_cache/org__repo/src/a.py` normalizes to `src/a.py`
    low = raw.lower()
    if "repos_cache/" in low:
        idx = low.index("repos_cache/") + len("repos_cache/")
        parts = raw[idx:].split("/", 1)
        if len(parts) == 2:
            raw = parts[1]
    raw = re.sub(r"^\./+", "", raw)
    return raw.strip("/").lower()


def extract_code_anchors(text: str = "", file_path: str = "") -> tuple[str, ...]:
    """Extracts concrete source-file anchors (e.g. `run_eval.py`, `procfs.c`) for dedup matching."""
    anchors: list[str] = []
    seen: set[str] = set()

    def _add(cand: str) -> None:
        c = str(cand or "").strip().lower()
        if not c or c in _GENERIC_FILENAMES or len(c) < 4:
            return
        if c not in seen:
            seen.add(c)
            anchors.append(c)

    norm_fp = normalize_file_path(file_path)
    if norm_fp:
        _add(Path(norm_fp).name)
    for m in _CODE_ANCHOR_RE.findall(str(text or "")):
        _add(Path(m).name)
    return tuple(anchors)


def normalize_title_tokens(title: str) -> set[str]:
    tokens = re.findall(r"[a-z0-9_]{3,}", str(title or "").lower())
    return {t for t in tokens if t not in _STOPWORDS and not t.isdigit()}


def normalize_title_key(title: str) -> str:
    return " ".join(sorted(normalize_title_tokens(title)))


def extract_remote_report_id(url: str) -> int | None:
    m = _H1_REPORT_ID_RE.search(str(url or ""))
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def compute_target_revision(target_dir: str | Path) -> tuple[str, str]:
    """
    Returns `(git_commit_sha, folder_content_digest)` for a local repo or folder.
    Uses `git rev-parse HEAD` for git repositories (fast, read-only, `shell=False`) and
    falls back to a bounded deterministic SHA-256 over `(rel_path, size, mtime_ns)`.
    """
    p = Path(target_dir).resolve()
    if not p.exists():
        return "", ""

    if (p / ".git").exists():
        try:
            proc = subprocess.run(
                ["git", "-C", str(p), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8.0,
                check=False,
            )
            sha = (proc.stdout or "").strip()
            if proc.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{7,64}", sha):
                return sha.lower(), ""
        except (OSError, subprocess.TimeoutExpired):
            pass

    hasher = hashlib.sha256()
    file_count = 0
    if p.is_file():
        st = p.stat()
        hasher.update(f"{p.name}:{st.st_size}:{st.st_mtime_ns}\n".encode())
        return "", hasher.hexdigest()[:24]

    entries: list[str] = []
    for root, dirs, files in os.walk(p):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIGEST_DIRS and not d.startswith(".git"))
        for fname in sorted(files):
            fp = Path(root) / fname
            try:
                st = fp.stat()
            except OSError:
                continue
            rel = str(fp.relative_to(p)).replace("\\", "/")
            entries.append(f"{rel}:{st.st_size}:{st.st_mtime_ns}")
            file_count += 1
            if file_count >= 4000:
                break
        if file_count >= 4000:
            break
    for line in entries:
        hasher.update((line + "\n").encode("utf-8", errors="replace"))
    return "", hasher.hexdigest()[:24]


def canonical_target_key(program: str, target_dir: str | Path, *, repo_slug: str = "") -> str:
    prog = normalize_program(program)
    if repo_slug and str(repo_slug).strip():
        return f"{prog}:repo:{str(repo_slug).strip().lower()}"
    resolved = str(Path(target_dir).resolve()).replace("\\", "/").lower()
    return f"{prog}:path:{resolved}"


class HuntDedupDB:
    """Thread-safe SQLite WAL persistent ledger for processed targets and drafted/submitted findings."""

    def __init__(self, db_path: str | Path = DEFAULT_HUNT_DEDUP_DB) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=15000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        for attempt in range(6):
            try:
                row = conn.execute("PRAGMA journal_mode;").fetchone()
                if row is None or str(row[0]).lower() != "wal":
                    conn.execute("PRAGMA journal_mode=WAL;")
                break
            except sqlite3.OperationalError as exc:
                if ("locked" in str(exc).lower() or "busy" in str(exc).lower()) and attempt < 5:
                    time.sleep(0.02 * (2 ** attempt))
                    continue
                raise
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS processed_targets (
                    target_key TEXT PRIMARY KEY,
                    program TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    repo_slug TEXT NOT NULL DEFAULT '',
                    commit_sha TEXT NOT NULL DEFAULT '',
                    content_digest TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'completed',
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    drafts_created INTEGER NOT NULL DEFAULT 0,
                    cycle_id TEXT NOT NULL DEFAULT '',
                    first_scanned_utc TEXT NOT NULL,
                    last_scanned_utc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS drafted_findings (
                    fingerprint TEXT PRIMARY KEY,
                    program TEXT NOT NULL,
                    draft_id TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL DEFAULT '',
                    title_norm TEXT NOT NULL DEFAULT '',
                    code_anchors TEXT NOT NULL DEFAULT '',
                    asset_identifier TEXT NOT NULL DEFAULT '',
                    file_path TEXT NOT NULL DEFAULT '',
                    line INTEGER NOT NULL DEFAULT 0,
                    rule_id TEXT NOT NULL DEFAULT '',
                    cwe TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'medium',
                    delivery_mode TEXT NOT NULL DEFAULT 'local_md',
                    remote_report_id INTEGER,
                    draft_url TEXT NOT NULL DEFAULT '',
                    markdown_path TEXT NOT NULL DEFAULT '',
                    created_utc TEXT NOT NULL,
                    updated_utc TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_drafted_program ON drafted_findings(program);
                CREATE INDEX IF NOT EXISTS idx_drafted_remote_id ON drafted_findings(remote_report_id);
                CREATE INDEX IF NOT EXISTS idx_drafted_prog_file_rule ON drafted_findings(program, file_path, rule_id);

                CREATE TABLE IF NOT EXISTS dedup_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_utc TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    program TEXT NOT NULL,
                    key_or_title TEXT NOT NULL,
                    matched_id TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT ''
                );
                """
            )

    # ------------------------------------------------------------------
    # Processed Target (Repo Commit SHA / Local Folder Digest) Tracking
    # ------------------------------------------------------------------
    def is_target_processed(
        self,
        program: str,
        target_dir: str | Path,
        *,
        repo_slug: str = "",
    ) -> tuple[bool, dict[str, Any] | None, str, str]:
        """
        Checks whether `(program, target_dir/repo_slug)` was already processed at its
        current git commit SHA or folder content digest.
        Returns `(already_processed, existing_record, current_commit_sha, current_digest)`.
        """
        t_key = canonical_target_key(program, target_dir, repo_slug=repo_slug)
        cur_sha, cur_digest = compute_target_revision(target_dir)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM processed_targets WHERE target_key = ?",
                (t_key,),
            ).fetchone()
        if row is None:
            return False, None, cur_sha, cur_digest
        rec = dict(row)
        if str(rec.get("status") or "") != "completed":
            return False, rec, cur_sha, cur_digest
        sha_match = bool(cur_sha) and str(rec.get("commit_sha") or "").lower() == cur_sha.lower()
        digest_match = bool(cur_digest) and str(rec.get("content_digest") or "").lower() == cur_digest.lower()
        return (sha_match or digest_match), rec, cur_sha, cur_digest

    def record_processed_target(
        self,
        program: str,
        target_dir: str | Path,
        *,
        repo_slug: str = "",
        commit_sha: str | None = None,
        content_digest: str | None = None,
        status: str = "completed",
        findings_count: int = 0,
        drafts_created: int = 0,
        cycle_id: str = "",
    ) -> dict[str, Any]:
        prog = normalize_program(program)
        t_key = canonical_target_key(prog, target_dir, repo_slug=repo_slug)
        if commit_sha is None and content_digest is None:
            eff_sha, eff_digest = compute_target_revision(target_dir)
        else:
            eff_sha = str(commit_sha or "").lower()
            eff_digest = str(content_digest or "").lower()
        now = _utc_now_iso()
        resolved_str = str(Path(target_dir).resolve())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO processed_targets (
                    target_key, program, target_path, repo_slug, commit_sha, content_digest,
                    status, findings_count, drafts_created, cycle_id, first_scanned_utc, last_scanned_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_key) DO UPDATE SET
                    target_path=excluded.target_path,
                    repo_slug=CASE WHEN excluded.repo_slug != '' THEN excluded.repo_slug ELSE processed_targets.repo_slug END,
                    commit_sha=excluded.commit_sha,
                    content_digest=excluded.content_digest,
                    status=excluded.status,
                    findings_count=excluded.findings_count,
                    drafts_created=excluded.drafts_created,
                    cycle_id=excluded.cycle_id,
                    last_scanned_utc=excluded.last_scanned_utc
                """,
                (
                    t_key,
                    prog,
                    resolved_str,
                    str(repo_slug or "").strip(),
                    eff_sha,
                    eff_digest,
                    str(status or "completed"),
                    int(findings_count),
                    int(drafts_created),
                    str(cycle_id or ""),
                    now,
                    now,
                ),
            )
        return {
            "target_key": t_key,
            "program": prog,
            "commit_sha": eff_sha,
            "content_digest": eff_digest,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Drafted / Submitted Finding Persistence & 4-Layer Dedup Gate
    # ------------------------------------------------------------------
    def record_drafted_finding(
        self,
        *,
        fingerprint: str,
        program: str,
        title: str = "",
        draft_id: str = "",
        asset_identifier: str = "",
        file_path: str = "",
        line: int = 0,
        rule_id: str = "",
        cwe: str = "",
        severity: str = "medium",
        delivery_mode: str = "local_md",
        remote_report_id: int | None = None,
        draft_url: str = "",
        markdown_path: str = "",
    ) -> None:
        fp = str(fingerprint or "").strip()
        if not fp:
            basis = f"{normalize_program(program)}|{normalize_file_path(file_path)}|{rule_id}|{title[:120]}"
            fp = hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()[:24]
        prog = normalize_program(program)
        norm_fp = normalize_file_path(file_path)
        anchors = ",".join(extract_code_anchors(f"{title} {asset_identifier}", norm_fp))
        t_norm = normalize_title_key(title)
        eff_rid = remote_report_id if remote_report_id is not None else extract_remote_report_id(draft_url)
        now = _utc_now_iso()
        new_rank = _DELIVERY_MODE_RANK.get(delivery_mode, 1)

        with self._connect() as conn:
            existing = conn.execute(
                "SELECT delivery_mode, remote_report_id, draft_url, markdown_path FROM drafted_findings WHERE fingerprint = ?",
                (fp,),
            ).fetchone()
            eff_mode = delivery_mode
            if existing is not None:
                old_mode = str(existing["delivery_mode"] or "local_md")
                if _DELIVERY_MODE_RANK.get(old_mode, 1) > new_rank:
                    eff_mode = old_mode
                if eff_rid is None and existing["remote_report_id"] is not None:
                    eff_rid = int(existing["remote_report_id"])
                if not draft_url and existing["draft_url"]:
                    draft_url = str(existing["draft_url"])
                if not markdown_path and existing["markdown_path"]:
                    markdown_path = str(existing["markdown_path"])

            conn.execute(
                """
                INSERT INTO drafted_findings (
                    fingerprint, program, draft_id, title, title_norm, code_anchors,
                    asset_identifier, file_path, line, rule_id, cwe, severity,
                    delivery_mode, remote_report_id, draft_url, markdown_path,
                    created_utc, updated_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    program=excluded.program,
                    draft_id=CASE WHEN excluded.draft_id != '' THEN excluded.draft_id ELSE drafted_findings.draft_id END,
                    title=CASE WHEN excluded.title != '' THEN excluded.title ELSE drafted_findings.title END,
                    title_norm=CASE WHEN excluded.title_norm != '' THEN excluded.title_norm ELSE drafted_findings.title_norm END,
                    code_anchors=CASE WHEN excluded.code_anchors != '' THEN excluded.code_anchors ELSE drafted_findings.code_anchors END,
                    asset_identifier=CASE WHEN excluded.asset_identifier != '' THEN excluded.asset_identifier ELSE drafted_findings.asset_identifier END,
                    file_path=CASE WHEN excluded.file_path != '' THEN excluded.file_path ELSE drafted_findings.file_path END,
                    line=CASE WHEN excluded.line > 0 THEN excluded.line ELSE drafted_findings.line END,
                    rule_id=CASE WHEN excluded.rule_id != '' THEN excluded.rule_id ELSE drafted_findings.rule_id END,
                    cwe=CASE WHEN excluded.cwe != '' THEN excluded.cwe ELSE drafted_findings.cwe END,
                    severity=excluded.severity,
                    delivery_mode=excluded.delivery_mode,
                    remote_report_id=COALESCE(excluded.remote_report_id, drafted_findings.remote_report_id),
                    draft_url=CASE WHEN excluded.draft_url != '' THEN excluded.draft_url ELSE drafted_findings.draft_url END,
                    markdown_path=CASE WHEN excluded.markdown_path != '' THEN excluded.markdown_path ELSE drafted_findings.markdown_path END,
                    updated_utc=excluded.updated_utc
                """,
                (
                    fp,
                    prog,
                    str(draft_id or ""),
                    str(title or "")[:240],
                    t_norm,
                    anchors,
                    str(asset_identifier or "")[:240],
                    norm_fp,
                    int(line or 0),
                    str(rule_id or "").strip(),
                    str(cwe or "").strip().upper(),
                    str(severity or "medium").strip().lower(),
                    eff_mode,
                    eff_rid,
                    str(draft_url or ""),
                    str(markdown_path or ""),
                    now,
                    now,
                ),
            )

    def sync_from_draft_tracker(
        self,
        tracker_db_path: str | Path | None = None,
        *,
        seed_defaults: bool = True,
    ) -> int:
        """
        Imports all known HackerOne drafts & submitted reports from `DraftSubmitTrackerDB`
        (and `SEEDED_DRAFTS`) into SQLite `drafted_findings` so they can never be re-drafted.
        """
        from engine.draft_submit_checker import SEEDED_DRAFTS, DraftSubmitTrackerDB

        synced = 0
        if seed_defaults:
            for report_id, program, _tier, severity, _rank, state, title in SEEDED_DRAFTS:
                mode = (
                    "hackerone_existing_draft"
                    if str(state).strip().lower() == "draft"
                    else "hackerone_submitted"
                )
                self.record_drafted_finding(
                    fingerprint=f"h1-report-{int(report_id)}",
                    program=program,
                    draft_id=f"H1-{int(report_id)}",
                    title=title,
                    severity=severity,
                    delivery_mode=mode,
                    remote_report_id=int(report_id),
                    draft_url=f"https://hackerone.com/reports/{int(report_id)}",
                )
                synced += 1

        if tracker_db_path is not None and Path(tracker_db_path).is_file():
            tracker = DraftSubmitTrackerDB(tracker_db_path)
            for td in tracker.list_drafts(only_drafts=False):
                st_low = str(td.state or "").strip().lower()
                sub_low = str(td.substate or "").strip().lower()
                if st_low == "draft" or sub_low == "editing":
                    mode = "hackerone_existing_draft"
                elif st_low == "closed" or sub_low in ("informative", "duplicate", "not-applicable", "spam", "resolved"):
                    mode = "hackerone_closed"
                else:
                    mode = "hackerone_submitted"
                self.record_drafted_finding(
                    fingerprint=f"h1-report-{int(td.report_id)}",
                    program=td.program,
                    draft_id=f"H1-{int(td.report_id)}",
                    title=td.title,
                    severity=td.severity,
                    delivery_mode=mode,
                    remote_report_id=int(td.report_id),
                    draft_url=td.url or f"https://hackerone.com/reports/{int(td.report_id)}",
                )
                synced += 1
        return synced

    def sync_from_live_hackerone_reports(self, reports: Sequence[dict[str, Any]]) -> int:
        """
        Persists live HackerOne `/bugs.json` report objects (Draft, Open, Triaged, Closed)
        into SQLite `drafted_findings` immediately after browser login.
        """
        synced = 0
        for item in reports or ():
            if not isinstance(item, dict):
                continue
            raw_id = item.get("id") or item.get("report_id")
            if raw_id is None:
                continue
            try:
                rid = int(raw_id)
            except (TypeError, ValueError):
                continue
            team = item.get("team") if isinstance(item.get("team"), dict) else {}
            prog = str(team.get("handle") or item.get("program") or "generic").strip().lower()
            title = str(item.get("title") or "").strip()
            state = str(item.get("state") or "").strip().lower()
            substate = str(item.get("substate") or "").strip().lower()
            sev = str(item.get("severity_rating") or item.get("severity") or "medium").strip().lower()
            url = str(item.get("url") or f"https://hackerone.com/reports/{rid}").strip()
            if url.startswith("/"):
                url = f"https://hackerone.com{url}"

            if state == "draft" or substate == "editing":
                mode = "hackerone_existing_draft"
            elif state == "closed" or substate in ("informative", "duplicate", "not-applicable", "spam", "resolved"):
                mode = "hackerone_closed"
            else:
                mode = "hackerone_submitted"

            self.record_drafted_finding(
                fingerprint=f"h1-report-{rid}",
                program=prog,
                draft_id=f"H1-{rid}",
                title=title,
                severity=sev,
                delivery_mode=mode,
                remote_report_id=rid,
                draft_url=url,
            )
            synced += 1
        return synced

    def find_duplicate(
        self,
        program: str,
        *,
        fingerprint: str = "",
        title: str = "",
        file_path: str = "",
        rule_id: str = "",
        cwe: str = "",
        asset_identifier: str = "",
        staged_or_remote_only: bool = False,
    ) -> dict[str, Any] | None:
        """
        4-layer deterministic deduplication check against persisted SQLite `drafted_findings`:
          1. Exact fingerprint match
          2. Same `(program, file_path, rule_id)` match
          3. Same `(program, file_path, cwe)` match (for specific CWEs)
          4. Same `program` + title Jaccard >= 0.55 OR shared concrete source-file anchor +
             overlapping vulnerability tokens / CWE.
        """
        prog = normalize_program(program)
        fp = str(fingerprint or "").strip()
        norm_file = normalize_file_path(file_path)
        norm_rule = str(rule_id or "").strip().lower()
        norm_cwe = str(cwe or "").strip().upper()
        cand_anchors = set(extract_code_anchors(f"{title} {asset_identifier}", norm_file))
        cand_tokens = normalize_title_tokens(title)

        def _row_allowed(r: sqlite3.Row) -> bool:
            if not staged_or_remote_only:
                return True
            return str(r["delivery_mode"] or "") in REMOTE_OR_STAGED_MODES

        def _format_match(r: sqlite3.Row, reason: str) -> dict[str, Any]:
            return {
                "reason": reason,
                "matched_fingerprint": str(r["fingerprint"] or ""),
                "matched_draft_id": str(r["draft_id"] or ""),
                "matched_remote_report_id": r["remote_report_id"],
                "matched_title": str(r["title"] or ""),
                "matched_delivery_mode": str(r["delivery_mode"] or ""),
                "matched_url": str(r["draft_url"] or ""),
            }

        with self._connect() as conn:
            # Layer 1: Exact fingerprint match
            if fp:
                row = conn.execute(
                    "SELECT * FROM drafted_findings WHERE fingerprint = ?",
                    (fp,),
                ).fetchone()
                if row is not None and _row_allowed(row):
                    return _format_match(row, "exact_fingerprint")

            rows = conn.execute(
                "SELECT * FROM drafted_findings WHERE program = ?",
                (prog,),
            ).fetchall()

        for row in rows:
            if not _row_allowed(row):
                continue

            row_file = str(row["file_path"] or "").strip().lower()
            row_rule = str(row["rule_id"] or "").strip().lower()
            row_cwe = str(row["cwe"] or "").strip().upper()
            row_anchors = {a for a in str(row["code_anchors"] or "").split(",") if a}
            row_tokens = normalize_title_tokens(str(row["title"] or ""))

            # Layer 2: Same program + same file + same rule_id
            same_file = bool(norm_file and row_file) and (
                norm_file == row_file
                or (
                    Path(norm_file).name == Path(row_file).name
                    and Path(norm_file).name not in _GENERIC_FILENAMES
                )
            )
            if same_file and norm_rule and row_rule == norm_rule:
                return _format_match(row, "same_file_and_rule")

            # Layer 3: Same program + same file + same specific CWE
            if same_file and norm_cwe and row_cwe == norm_cwe and norm_cwe not in ("CWE-20", "CWE-0"):
                return _format_match(row, "same_file_and_cwe")

            # Layer 4: Program-scoped title similarity OR shared concrete code anchor + keyword overlap
            shared_anchors = cand_anchors & row_anchors
            if cand_tokens and row_tokens:
                inter = cand_tokens & row_tokens
                union = cand_tokens | row_tokens
                jaccard = len(inter) / max(1, len(union))
                overlap_min = len(inter) / max(1, min(len(cand_tokens), len(row_tokens)))
                if jaccard >= 0.55 or (len(inter) >= 4 and overlap_min >= 0.70):
                    return _format_match(row, f"title_similarity:{jaccard:.2f}")
                if shared_anchors and (len(inter) >= 2 or (norm_cwe and norm_cwe == row_cwe)):
                    anchor_lbl = min(shared_anchors)
                    return _format_match(row, f"code_anchor_and_topic:{anchor_lbl}")

        return None

    def list_fingerprints(self, *, program: str | None = None) -> list[str]:
        with self._connect() as conn:
            if program:
                rows = conn.execute(
                    "SELECT fingerprint FROM drafted_findings WHERE program = ?",
                    (normalize_program(program),),
                ).fetchall()
            else:
                rows = conn.execute("SELECT fingerprint FROM drafted_findings").fetchall()
        return [str(r["fingerprint"]) for r in rows]

    def record_dedup_event(
        self,
        kind: str,
        program: str,
        key_or_title: str,
        matched_id: str = "",
        reason: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO dedup_events (event_utc, kind, program, key_or_title, matched_id, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (_utc_now_iso(), str(kind), normalize_program(program), str(key_or_title)[:240], str(matched_id)[:120], str(reason)[:160]),
            )

    def summary_counts(self) -> dict[str, Any]:
        with self._connect() as conn:
            pt_cnt = int(conn.execute("SELECT COUNT(*) FROM processed_targets").fetchone()[0])
            df_cnt = int(conn.execute("SELECT COUNT(*) FROM drafted_findings").fetchone()[0])
            ev_cnt = int(conn.execute("SELECT COUNT(*) FROM dedup_events").fetchone()[0])
            mode_rows = conn.execute(
                "SELECT delivery_mode, COUNT(*) AS cnt FROM drafted_findings GROUP BY delivery_mode"
            ).fetchall()
        by_mode = {str(r["delivery_mode"]): int(r["cnt"]) for r in mode_rows}
        staged_or_remote = sum(cnt for m, cnt in by_mode.items() if m in REMOTE_OR_STAGED_MODES)
        return {
            "db_path": str(self.db_path),
            "processed_targets_count": pt_cnt,
            "drafted_findings_count": df_cnt,
            "staged_or_remote_count": staged_or_remote,
            "by_delivery_mode": by_mode,
            "dedup_events_count": ev_cnt,
        }
