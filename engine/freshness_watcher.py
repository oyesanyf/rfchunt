"""
Freshness Watcher & Diff-First Bug Bounty Queue Engine (Revenue Track 1 — Blocker 1).
=====================================================================================
Monitors configured in-scope GitHub repositories for brand-new releases, newly merged PRs,
and commits landed within a configurable freshness window (default 72 hours), scores each
change by high-bounty attack surface, and outputs a prioritized Daily Fresh Hunt Queue.

Design Invariants:
- ETag-cached GitHub REST API requests (`If-None-Match`) backed by SQLite so unchanged
  endpoints return `304 Not Modified` at zero API rate-limit cost.
- Bounded multithreaded fan-out (`ThreadPoolExecutor`, capped at 8 workers).
- Process-scoped token loading (`GITHUB_TOKEN` / `.env.local`) — zero system env/registry edits.
- Zero `shell=True`, explicit UTF-8 file I/O, deterministic duplicate-SHA suppression.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_API_BASE = "https://api.github.com"
DEFAULT_FRESHNESS_HOURS = 72
DEFAULT_TIMEOUT_SEC = 12.0
MAX_WORKERS = 8


SURFACE_RULES: Tuple[Tuple[str, int, Tuple[str, ...]], ...] = (
    (
        "wasm_sandbox_ffi",
        35,
        (
            "wasm",
            "wasi",
            "sandbox",
            "seccomp",
            "seatbelt",
            "appcontainer",
            "acl",
            "reparse",
            "junction",
            "unsafe",
            "ffi",
            "ptr::",
            "memory",
            "limiter",
        ),
    ),
    (
        "auth_session_crypto",
        30,
        (
            "auth",
            "oauth",
            "jwt",
            "session",
            "hmac",
            "verify",
            "token",
            "crypto",
            "tls",
            "x509",
            "signer",
            "consensus",
            "permission",
            "rbac",
            "csrf",
        ),
    ),
    (
        "http_proxy_parser",
        25,
        (
            "proxy",
            "router",
            "routing",
            "http",
            "header",
            "sanitizer",
            "parser",
            "framing",
            "chunk",
            "desync",
            "redirect",
            "url",
            "cookie",
            "webview",
        ),
    ),
    (
        "ai_agent_mcp",
        25,
        (
            "mcp",
            "tool",
            "agent",
            "llm",
            "prompt",
            "escalation",
            "hook",
            "exec",
            "eval",
            "plugin",
            "rag",
        ),
    ),
)

_HIGH_VALUE_EXTENSIONS = {
    ".rs",
    ".go",
    ".ts",
    ".tsx",
    ".js",
    ".mjs",
    ".py",
    ".rb",
    ".kt",
    ".java",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".swift",
    ".sol",
}


@dataclass
class WatchTarget:
    """Single in-scope GitHub repository tracked for fresh releases/PRs/commits."""

    program: str
    repo: str  # "owner/name"
    bounty_tier: str = "Medium-High"
    scope_asset: str = ""
    notes: str = ""
    enabled: bool = True

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "WatchTarget":
        repo = str(raw.get("repo", "")).strip().strip("/")
        if "/" not in repo:
            raise ValueError(f"Invalid repo slug (expected 'owner/name'): {repo!r}")
        return cls(
            program=str(raw.get("program", "unknown")).strip(),
            repo=repo,
            bounty_tier=str(raw.get("bounty_tier", "Medium-High")).strip(),
            scope_asset=str(raw.get("scope_asset", f"https://github.com/{repo}")).strip(),
            notes=str(raw.get("notes", "")).strip(),
            enabled=bool(raw.get("enabled", True)),
        )


@dataclass
class FreshCandidate:
    """A newly landed release, merged PR, or commit ranked for immediate RFCHunt triage."""

    program: str
    repo: str
    event_type: str  # "release" | "merged_pr" | "commit"
    ref_id: str  # tag, PR number, or short SHA
    sha: str
    title: str
    url: str
    landed_at: str  # ISO-8601 UTC
    age_hours: float
    surface_score: int
    matched_surfaces: List[str] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)
    bounty_tier: str = "Medium-High"
    scope_asset: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program": self.program,
            "repo": self.repo,
            "event_type": self.event_type,
            "ref_id": self.ref_id,
            "sha": self.sha,
            "title": self.title,
            "url": self.url,
            "landed_at": self.landed_at,
            "age_hours": round(self.age_hours, 2),
            "surface_score": self.surface_score,
            "matched_surfaces": list(self.matched_surfaces),
            "changed_files": list(self.changed_files),
            "bounty_tier": self.bounty_tier,
            "scope_asset": self.scope_asset,
        }


@dataclass
class FreshnessRunReport:
    """Aggregated result of a Freshness Watcher poll cycle."""

    generated_at: str
    freshness_hours: int
    targets_checked: int
    etag_cache_hits: int
    candidates: List[FreshCandidate] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "freshness_hours": self.freshness_hours,
            "targets_checked": self.targets_checked,
            "etag_cache_hits": self.etag_cache_hits,
            "total_candidates": len(self.candidates),
            "candidates": [c.to_dict() for c in self.candidates],
            "errors": list(self.errors),
        }


def _parse_iso_utc(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    s = str(raw).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def load_github_token(workspace_root: Optional[Path] = None) -> Optional[str]:
    """Reads GITHUB_TOKEN from process env or local .env.local without mutating system env."""
    for key in ("GITHUB_TOKEN", "GH_TOKEN"):
        val = os.environ.get(key, "").strip()
        if val:
            return val
    root = workspace_root or Path.cwd()
    env_local = root / ".env.local"
    if env_local.is_file():
        try:
            for line in env_local.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                k, v = stripped.split("=", 1)
                if k.strip() in ("GITHUB_TOKEN", "GH_TOKEN"):
                    cleaned = v.strip().strip('"').strip("'")
                    if cleaned and cleaned != "REPLACE_ME":
                        return cleaned
        except OSError:
            pass
    return None


def score_diff_surface(
    changed_files: Sequence[str],
    title: str = "",
    body: str = "",
    event_type: str = "commit",
) -> Tuple[int, List[str]]:
    """
    Scores a newly landed release/PR/commit from 0 to 100 based on high-bounty attack surface.
    """
    haystack_parts = [title or "", body[:2000] if body else ""]
    code_files = 0
    for fpath in changed_files:
        haystack_parts.append(fpath)
        ext = Path(fpath).suffix.lower()
        if ext in _HIGH_VALUE_EXTENSIONS:
            code_files += 1
    haystack = " ".join(haystack_parts).lower()

    score = 0
    matched: List[str] = []
    for surface_name, weight, keywords in SURFACE_RULES:
        if any(kw in haystack for kw in keywords):
            score += weight
            matched.append(surface_name)

    if event_type == "release":
        score += 15
    elif event_type == "merged_pr":
        score += 10

    if code_files >= 1:
        score += min(15, code_files * 3)

    # Penalize pure docs/lockfile-only changes
    if changed_files and code_files == 0:
        if all(
            f.lower().endswith((".md", ".txt", ".rst", ".lock", ".png", ".svg"))
            or f.lower().startswith("docs/")
            for f in changed_files
        ):
            score = max(0, score - 25)

    return min(100, score), matched


class FreshnessStateStore:
    """Thread-safe SQLite store for GitHub ETag caching and already-triaged SHAs."""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS etag_cache (
                    url TEXT PRIMARY KEY,
                    etag TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS seen_refs (
                    repo TEXT NOT NULL,
                    sha TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    PRIMARY KEY (repo, sha)
                );
                """
            )
            self._conn.commit()

    def get_etag(self, url: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT etag FROM etag_cache WHERE url = ?", (url,)
            ).fetchone()
            return str(row[0]) if row else None

    def set_etag(self, url: str, etag: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO etag_cache (url, etag, updated_at) VALUES (?, ?, ?)",
                (url, etag, now),
            )
            self._conn.commit()

    def is_seen(self, repo: str, sha: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM seen_refs WHERE repo = ? AND sha = ?", (repo, sha)
            ).fetchone()
            return row is not None

    def mark_seen(self, repo: str, sha: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO seen_refs (repo, sha, first_seen_at) VALUES (?, ?, ?)",
                (repo, sha, now),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class FreshnessWatcher:
    """
    Polls in-scope GitHub repositories for fresh releases, merged PRs, and commits
    landed within `freshness_hours` (default 72h), ranking candidates by attack surface.
    """

    def __init__(
        self,
        api_base: str = DEFAULT_API_BASE,
        token: Optional[str] = None,
        state_db: Optional[Union[str, Path]] = None,
        timeout_sec: float = DEFAULT_TIMEOUT_SEC,
        now_utc: Optional[datetime] = None,
    ):
        self.api_base = api_base.rstrip("/")
        self.token = token if token is not None else load_github_token()
        self.timeout_sec = timeout_sec
        self._now_override = now_utc
        self.store = FreshnessStateStore(state_db or Path("out/freshness_state.db"))

    def _now(self) -> datetime:
        return self._now_override or datetime.now(timezone.utc)

    def _get_json(self, path: str) -> Tuple[Optional[Any], bool, Optional[str]]:
        """
        Fetches JSON from `api_base + path` with ETag caching.
        Returns `(payload, was_304_cache_hit, error_message)`.
        """
        url = f"{self.api_base}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "RFCHunt-FreshnessWatcher/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        cached_etag = self.store.get_etag(url)
        if cached_etag:
            headers["If-None-Match"] = cached_etag

        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                etag = resp.headers.get("ETag")
                if etag:
                    self.store.set_etag(url, etag)
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw), False, None
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return None, True, None
            return None, False, f"HTTP {exc.code} on {path}"
        except Exception as exc:
            return None, False, f"Request failed on {path}: {exc}"

    def _scan_target(
        self,
        target: WatchTarget,
        freshness_hours: int,
        min_score: int,
        skip_seen: bool,
    ) -> Tuple[List[FreshCandidate], int, List[str]]:
        now = self._now()
        cutoff = now - timedelta(hours=freshness_hours)
        since_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        candidates: List[FreshCandidate] = []
        cache_hits = 0
        errors: List[str] = []
        seen_local_shas: set[str] = set()

        # 1. Fresh Releases
        releases, hit, err = self._get_json(f"/repos/{target.repo}/releases?per_page=5")
        if hit:
            cache_hits += 1
        elif err:
            errors.append(f"{target.repo} releases: {err}")
        elif isinstance(releases, list):
            for rel in releases:
                ts = _parse_iso_utc(rel.get("published_at") or rel.get("created_at"))
                if not ts or ts < cutoff:
                    continue
                tag = str(rel.get("tag_name") or rel.get("name") or "release")
                sha = str(rel.get("target_commitish") or tag)
                if skip_seen and self.store.is_seen(target.repo, sha):
                    continue
                seen_local_shas.add(sha)
                title = f"[Release {tag}] {rel.get('name') or tag}"
                body = str(rel.get("body") or "")
                score, surfaces = score_diff_surface([], title=title, body=body, event_type="release")
                if score >= min_score:
                    candidates.append(
                        FreshCandidate(
                            program=target.program,
                            repo=target.repo,
                            event_type="release",
                            ref_id=tag,
                            sha=sha,
                            title=title,
                            url=str(rel.get("html_url") or f"https://github.com/{target.repo}/releases"),
                            landed_at=ts.isoformat(),
                            age_hours=max(0.0, (now - ts).total_seconds() / 3600.0),
                            surface_score=score,
                            matched_surfaces=surfaces,
                            changed_files=[],
                            bounty_tier=target.bounty_tier,
                            scope_asset=target.scope_asset,
                        )
                    )

        # 2. Fresh Merged Pull Requests
        pulls, hit, err = self._get_json(
            f"/repos/{target.repo}/pulls?state=closed&sort=updated&direction=desc&per_page=10"
        )
        if hit:
            cache_hits += 1
        elif err:
            errors.append(f"{target.repo} pulls: {err}")
        elif isinstance(pulls, list):
            for pr in pulls:
                merged_at = _parse_iso_utc(pr.get("merged_at"))
                if not merged_at or merged_at < cutoff:
                    continue
                sha = str(pr.get("merge_commit_sha") or (pr.get("head") or {}).get("sha") or "")
                if not sha or sha in seen_local_shas:
                    continue
                if skip_seen and self.store.is_seen(target.repo, sha):
                    continue
                seen_local_shas.add(sha)
                pr_num = pr.get("number")
                changed_files: List[str] = []
                if pr_num is not None:
                    files_json, fhit, _ = self._get_json(
                        f"/repos/{target.repo}/pulls/{pr_num}/files?per_page=30"
                    )
                    if fhit:
                        cache_hits += 1
                    elif isinstance(files_json, list):
                        changed_files = [
                            str(item.get("filename", ""))
                            for item in files_json
                            if item.get("filename")
                        ]
                title = f"[PR #{pr_num}] {pr.get('title') or ''}".strip()
                body = str(pr.get("body") or "")
                score, surfaces = score_diff_surface(
                    changed_files, title=title, body=body, event_type="merged_pr"
                )
                if score >= min_score:
                    candidates.append(
                        FreshCandidate(
                            program=target.program,
                            repo=target.repo,
                            event_type="merged_pr",
                            ref_id=f"#{pr_num}",
                            sha=sha[:12],
                            title=title,
                            url=str(pr.get("html_url") or f"https://github.com/{target.repo}/pull/{pr_num}"),
                            landed_at=merged_at.isoformat(),
                            age_hours=max(0.0, (now - merged_at).total_seconds() / 3600.0),
                            surface_score=score,
                            matched_surfaces=surfaces,
                            changed_files=changed_files[:15],
                            bounty_tier=target.bounty_tier,
                            scope_asset=target.scope_asset,
                        )
                    )

        # 3. Fresh Direct Commits
        commits, hit, err = self._get_json(
            f"/repos/{target.repo}/commits?since={urllib.parse.quote(since_iso)}&per_page=10"
        )
        if hit:
            cache_hits += 1
        elif err:
            errors.append(f"{target.repo} commits: {err}")
        elif isinstance(commits, list):
            for c in commits:
                sha = str(c.get("sha") or "")
                if not sha or sha in seen_local_shas:
                    continue
                if skip_seen and self.store.is_seen(target.repo, sha):
                    continue
                commit_obj = c.get("commit") or {}
                committer = commit_obj.get("committer") or commit_obj.get("author") or {}
                ts = _parse_iso_utc(committer.get("date"))
                if not ts or ts < cutoff:
                    continue
                msg = str(commit_obj.get("message") or "").splitlines()[0].strip()
                changed_files = [
                    str(f.get("filename", ""))
                    for f in (c.get("files") or [])
                    if isinstance(f, dict) and f.get("filename")
                ]
                score, surfaces = score_diff_surface(
                    changed_files, title=msg, body="", event_type="commit"
                )
                if score >= min_score:
                    candidates.append(
                        FreshCandidate(
                            program=target.program,
                            repo=target.repo,
                            event_type="commit",
                            ref_id=sha[:10],
                            sha=sha[:12],
                            title=msg,
                            url=str(c.get("html_url") or f"https://github.com/{target.repo}/commit/{sha}"),
                            landed_at=ts.isoformat(),
                            age_hours=max(0.0, (now - ts).total_seconds() / 3600.0),
                            surface_score=score,
                            matched_surfaces=surfaces,
                            changed_files=changed_files[:15],
                            bounty_tier=target.bounty_tier,
                            scope_asset=target.scope_asset,
                        )
                    )

        return candidates, cache_hits, errors

    def poll_watchlist(
        self,
        targets: Sequence[WatchTarget],
        freshness_hours: int = DEFAULT_FRESHNESS_HOURS,
        min_score: int = 20,
        skip_seen: bool = True,
        mark_returned_seen: bool = False,
    ) -> FreshnessRunReport:
        active = [t for t in targets if t.enabled]
        all_candidates: List[FreshCandidate] = []
        all_errors: List[str] = []
        total_cache_hits = 0

        worker_count = min(MAX_WORKERS, max(1, len(active)))
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = {
                pool.submit(self._scan_target, t, freshness_hours, min_score, skip_seen): t
                for t in active
            }
            for fut in as_completed(futures):
                try:
                    cands, hits, errs = fut.result()
                    all_candidates.extend(cands)
                    total_cache_hits += hits
                    all_errors.extend(errs)
                except Exception as exc:
                    t = futures[fut]
                    all_errors.append(f"{t.repo}: unhandled error: {exc}")

        all_candidates.sort(key=lambda c: (-c.surface_score, c.age_hours))

        if mark_returned_seen:
            for cand in all_candidates:
                self.store.mark_seen(cand.repo, cand.sha)

        return FreshnessRunReport(
            generated_at=self._now().isoformat(),
            freshness_hours=freshness_hours,
            targets_checked=len(active),
            etag_cache_hits=total_cache_hits,
            candidates=all_candidates,
            errors=all_errors,
        )

    def close(self) -> None:
        self.store.close()


def load_watchlist(path: Union[str, Path]) -> List[WatchTarget]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    raw_targets = data.get("targets", data) if isinstance(data, dict) else data
    return [WatchTarget.from_dict(item) for item in raw_targets]


def render_fresh_hunt_queue_markdown(report: FreshnessRunReport) -> str:
    """Renders a prioritized Markdown Daily Fresh Hunt Queue with shallow-clone commands."""
    lines = [
        "# RFCHunt Daily Fresh Hunt Queue",
        "",
        f"- **Generated (UTC):** `{report.generated_at}`",
        f"- **Freshness Window:** Last `{report.freshness_hours}` hours",
        f"- **Repositories Polled:** `{report.targets_checked}` (ETag 304 cache hits: `{report.etag_cache_hits}`)",
        f"- **Prioritized Candidates:** `{len(report.candidates)}`",
        "",
        "| Score | Age (h) | Program | Repository | Event | Surfaces | Title |",
        "|---:|---:|---|---|---|---|---|",
    ]
    for c in report.candidates:
        surfaces = ", ".join(c.matched_surfaces) or "general"
        safe_title = c.title.replace("|", "\\|")[:90]
        lines.append(
            f"| **{c.surface_score}** | {c.age_hours:.1f} | `{c.program}` | `{c.repo}` | "
            f"`{c.event_type}` `{c.ref_id}` | `{surfaces}` | [{safe_title}]({c.url}) |"
        )
    if report.candidates:
        lines.extend(["", "## Quick Triage Commands", ""])
        for c in report.candidates[:5]:
            repo_dir = re.sub(r"[^A-Za-z0-9_.-]+", "_", c.repo)
            lines.append(
                f"- **{c.repo} ({c.ref_id}, score {c.surface_score}):** "
                f"`git clone --depth 1 https://github.com/{c.repo}.git targets/{repo_dir}`"
            )
    if report.errors:
        lines.extend(["", "## Poll Warnings", ""])
        for e in report.errors:
            lines.append(f"- {e}")
    return "\n".join(lines) + "\n"
