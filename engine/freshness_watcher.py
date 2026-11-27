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

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import inspect
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union


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
            "o_nofollow",
            "symlink",
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
            "authz",
            "allowfrom",
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
            "sanitize",
            "sanitizer",
            "csp",
            "ssrf",
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


_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _validate_repo_slug(raw_repo: Any) -> str:
    repo = str(raw_repo or "").strip().strip("/")
    if not _REPO_SLUG_RE.fullmatch(repo):
        raise ValueError(f"Invalid repo slug (expected 'owner/name'): {repo!r}")
    owner, name = repo.split("/", 1)
    if owner in (".", "..") or name in (".", ".."):
        raise ValueError(f"Invalid repo slug segment: {repo!r}")
    return repo


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
        repo = _validate_repo_slug(raw.get("repo", ""))
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
    """Thread-safe SQLite WAL store for GitHub ETag caching and already-triaged SHAs."""

    def __init__(self, db_path: Union[str, Path]):
        self.raw_db_path = str(db_path)
        self.is_memory = self.raw_db_path == ":memory:"
        if not self.is_memory:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            connect_target = str(self.db_path)
        else:
            self.db_path = Path(":memory:")
            connect_target = ":memory:"

        self._lock = threading.RLock()
        self._closed = False
        self._conn = sqlite3.connect(connect_target, check_same_thread=False, timeout=10.0)
        self._configure_pragmas()
        self._init_schema()

    def _configure_pragmas(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA busy_timeout=10000;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            if not self.is_memory:
                self._conn.execute("PRAGMA journal_mode=WAL;")

    def _run_with_retry(self, fn: Callable[[], Any]) -> Any:
        last_exc: Optional[Exception] = None
        for attempt in range(6):
            try:
                with self._lock:
                    if self._closed:
                        raise RuntimeError("FreshnessStateStore is closed.")
                    return fn()
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                if "locked" in msg or "busy" in msg:
                    last_exc = exc
                    time.sleep(0.01 * (2 ** attempt))
                    continue
                raise
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("SQLite retry loop exited unexpectedly.")

    def _init_schema(self) -> None:
        def _create() -> None:
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

        self._run_with_retry(_create)

    def get_etag(self, url: str) -> Optional[str]:
        def _get() -> Optional[str]:
            row = self._conn.execute(
                "SELECT etag FROM etag_cache WHERE url = ?", (url,)
            ).fetchone()
            return str(row[0]) if row else None

        return self._run_with_retry(_get)

    def set_etag(self, url: str, etag: str) -> None:
        now = datetime.now(timezone.utc).isoformat()

        def _set() -> None:
            self._conn.execute(
                "INSERT OR REPLACE INTO etag_cache (url, etag, updated_at) VALUES (?, ?, ?)",
                (url, etag, now),
            )
            self._conn.commit()

        self._run_with_retry(_set)

    def is_seen(self, repo: str, sha: str) -> bool:
        def _seen() -> bool:
            row = self._conn.execute(
                "SELECT 1 FROM seen_refs WHERE repo = ? AND sha = ?", (repo, sha)
            ).fetchone()
            return row is not None

        return bool(self._run_with_retry(_seen))

    def mark_seen(self, repo: str, sha: str) -> None:
        now = datetime.now(timezone.utc).isoformat()

        def _mark() -> None:
            self._conn.execute(
                "INSERT OR IGNORE INTO seen_refs (repo, sha, first_seen_at) VALUES (?, ?, ?)",
                (repo, sha, now),
            )
            self._conn.commit()

        self._run_with_retry(_mark)

    def __enter__(self) -> "FreshnessStateStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                if not self.is_memory:
                    try:
                        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                    except Exception:
                        pass
                try:
                    self._conn.close()
                except Exception:
                    pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _is_sha_seen(store: FreshnessStateStore, repo: str, sha: str) -> bool:
    s = str(sha or "").strip()
    if not s:
        return False
    if store.is_seen(repo, s):
        return True
    if len(s) > 12 and store.is_seen(repo, s[:12]):
        return True
    return False


def _mark_sha_seen(store: FreshnessStateStore, repo: str, sha: str, full_sha: str = "") -> None:
    s = str(sha or "").strip()
    if s:
        store.mark_seen(repo, s)
    fs = str(full_sha or "").strip()
    if fs and fs != s:
        store.mark_seen(repo, fs)
    if len(fs) > 12 and fs[:12] != s:
        store.mark_seen(repo, fs[:12])


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
        self._sha_lock = threading.Lock()
        self._full_shas: Dict[Tuple[str, str], str] = {}

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
        repo_slug = _validate_repo_slug(target.repo)
        now = self._now()
        cutoff = now - timedelta(hours=freshness_hours)
        candidates: List[FreshCandidate] = []
        cache_hits = 0
        errors: List[str] = []
        seen_local_shas: set[str] = set()

        # 1. Fresh Releases
        releases, hit, err = self._get_json(f"/repos/{repo_slug}/releases?per_page=5")
        if hit:
            cache_hits += 1
        elif err:
            errors.append(f"{repo_slug} releases: {err}")
        elif isinstance(releases, list):
            for idx, rel in enumerate(releases):
                ts = _parse_iso_utc(rel.get("published_at") or rel.get("created_at"))
                if not ts or ts < cutoff:
                    continue
                tag = str(rel.get("tag_name") or rel.get("name") or "release")
                sha = str(rel.get("target_commitish") or tag)
                if skip_seen and _is_sha_seen(self.store, repo_slug, sha):
                    continue
                seen_local_shas.add(sha)
                if len(sha) > 12:
                    seen_local_shas.add(sha[:12])
                rel_changed: List[str] = [
                    str(f.get("filename", f) if isinstance(f, dict) else f)
                    for f in (rel.get("changed_files") or rel.get("files") or [])
                    if f
                ]
                if not rel_changed and idx + 1 < len(releases):
                    prev_tag = str(releases[idx + 1].get("tag_name") or "").strip()
                    if prev_tag and prev_tag != tag:
                        cmp_json, chit, _ = self._get_json(
                            f"/repos/{repo_slug}/compare/{urllib.parse.quote(prev_tag)}...{urllib.parse.quote(tag)}"
                        )
                        if chit:
                            cache_hits += 1
                        elif isinstance(cmp_json, dict):
                            rel_changed = [
                                str(item.get("filename", ""))
                                for item in (cmp_json.get("files") or [])
                                if isinstance(item, dict) and item.get("filename")
                            ]
                title = f"[Release {tag}] {rel.get('name') or tag}"
                body = str(rel.get("body") or "")
                score, surfaces = score_diff_surface(rel_changed, title=title, body=body, event_type="release")
                if score >= min_score:
                    with self._sha_lock:
                        self._full_shas[(repo_slug, sha)] = sha
                    candidates.append(
                        FreshCandidate(
                            program=target.program,
                            repo=repo_slug,
                            event_type="release",
                            ref_id=tag,
                            sha=sha,
                            title=title,
                            url=str(rel.get("html_url") or f"https://github.com/{repo_slug}/releases"),
                            landed_at=ts.isoformat(),
                            age_hours=max(0.0, (now - ts).total_seconds() / 3600.0),
                            surface_score=score,
                            matched_surfaces=surfaces,
                            changed_files=rel_changed[:15],
                            bounty_tier=target.bounty_tier,
                            scope_asset=target.scope_asset,
                        )
                    )

        # 2. Fresh Merged Pull Requests
        pulls, hit, err = self._get_json(
            f"/repos/{repo_slug}/pulls?state=closed&sort=updated&direction=desc&per_page=10"
        )
        if hit:
            cache_hits += 1
        elif err:
            errors.append(f"{repo_slug} pulls: {err}")
        elif isinstance(pulls, list):
            for pr in pulls:
                merged_at = _parse_iso_utc(pr.get("merged_at"))
                if not merged_at or merged_at < cutoff:
                    continue
                sha = str(pr.get("merge_commit_sha") or (pr.get("head") or {}).get("sha") or "")
                if not sha or sha in seen_local_shas or sha[:12] in seen_local_shas:
                    continue
                if skip_seen and _is_sha_seen(self.store, repo_slug, sha):
                    continue
                seen_local_shas.add(sha)
                if len(sha) > 12:
                    seen_local_shas.add(sha[:12])
                pr_num = pr.get("number")
                changed_files: List[str] = []
                if pr_num is not None:
                    files_json, fhit, _ = self._get_json(
                        f"/repos/{repo_slug}/pulls/{pr_num}/files?per_page=30"
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
                    short_sha = sha[:12]
                    with self._sha_lock:
                        self._full_shas[(repo_slug, short_sha)] = sha
                    candidates.append(
                        FreshCandidate(
                            program=target.program,
                            repo=repo_slug,
                            event_type="merged_pr",
                            ref_id=f"#{pr_num}",
                            sha=short_sha,
                            title=title,
                            url=str(pr.get("html_url") or f"https://github.com/{repo_slug}/pull/{pr_num}"),
                            landed_at=merged_at.isoformat(),
                            age_hours=max(0.0, (now - merged_at).total_seconds() / 3600.0),
                            surface_score=score,
                            matched_surfaces=surfaces,
                            changed_files=changed_files[:15],
                            bounty_tier=target.bounty_tier,
                            scope_asset=target.scope_asset,
                        )
                    )

        # 3. Fresh Direct Commits (invariant URL so GitHub ETag 304 cache hits across polls)
        commits, hit, err = self._get_json(
            f"/repos/{repo_slug}/commits?per_page=10"
        )
        if hit:
            cache_hits += 1
        elif err:
            errors.append(f"{repo_slug} commits: {err}")
        elif isinstance(commits, list):
            for c in commits:
                sha = str(c.get("sha") or "")
                if not sha or sha in seen_local_shas or sha[:12] in seen_local_shas:
                    continue
                if skip_seen and _is_sha_seen(self.store, repo_slug, sha):
                    continue
                commit_obj = c.get("commit") or {}
                committer = commit_obj.get("committer") or commit_obj.get("author") or {}
                ts = _parse_iso_utc(committer.get("date"))
                if not ts or ts < cutoff:
                    continue
                msg = str(commit_obj.get("message") or "").splitlines()[0].strip()
                changed_files: List[str] = []
                diff_chunks: List[str] = []
                for f in (c.get("files") or []):
                    if isinstance(f, dict) and f.get("filename"):
                        changed_files.append(str(f["filename"]))
                        if f.get("patch"):
                            diff_chunks.append(str(f["patch"])[:500])
                if not changed_files:
                    detail_json, dhit, _ = self._get_json(
                        f"/repos/{repo_slug}/commits/{urllib.parse.quote(sha)}"
                    )
                    if dhit:
                        cache_hits += 1
                    elif isinstance(detail_json, dict):
                        for f in (detail_json.get("files") or []):
                            if isinstance(f, dict) and f.get("filename"):
                                changed_files.append(str(f["filename"]))
                                if f.get("patch"):
                                    diff_chunks.append(str(f["patch"])[:500])
                score, surfaces = score_diff_surface(
                    changed_files, title=msg, body="\n".join(diff_chunks), event_type="commit"
                )
                if score >= min_score:
                    short_sha = sha[:12]
                    with self._sha_lock:
                        self._full_shas[(repo_slug, short_sha)] = sha
                    candidates.append(
                        FreshCandidate(
                            program=target.program,
                            repo=repo_slug,
                            event_type="commit",
                            ref_id=sha[:10],
                            sha=short_sha,
                            title=msg,
                            url=str(c.get("html_url") or f"https://github.com/{repo_slug}/commit/{sha}"),
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
        eligibility_db: Any = None,
        ml_rank: bool = False,
    ) -> FreshnessRunReport:
        active: List[WatchTarget] = []
        for t in targets:
            if not t.enabled:
                continue
            if eligibility_db is not None and not eligibility_db.is_eligible(t.program):
                continue
            active.append(t)
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

        if ml_rank and all_candidates:
            try:
                from engine.ml_diff_and_recon_ranker import CommitDiffRanker

                ranker = CommitDiffRanker()
                scored_pairs = []
                for cand in all_candidates:
                    s_res = ranker.score_candidate(cand.to_dict())
                    scored_pairs.append((float(s_res.get("ml_priority_score", 0.0)), cand))
                scored_pairs.sort(key=lambda pair: (-pair[0], -pair[1].surface_score, pair[1].age_hours))
                all_candidates = [pair[1] for pair in scored_pairs]
            except Exception:
                all_candidates.sort(key=lambda c: (-c.surface_score, c.age_hours))
        else:
            all_candidates.sort(key=lambda c: (-c.surface_score, c.age_hours))

        if mark_returned_seen:
            for cand in all_candidates:
                with self._sha_lock:
                    full_sha = self._full_shas.get((cand.repo, cand.sha), cand.sha)
                _mark_sha_seen(self.store, cand.repo, cand.sha, full_sha)

        return FreshnessRunReport(
            generated_at=self._now().isoformat(),
            freshness_hours=freshness_hours,
            targets_checked=len(active),
            etag_cache_hits=total_cache_hits,
            candidates=all_candidates,
            errors=all_errors,
        )

    def __enter__(self) -> "FreshnessWatcher":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        self.store.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


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


# ---------------------------------------------------------------------------
# Loop 1: 60-Second Async ETag Poller & Sibling Path Resolution
# ---------------------------------------------------------------------------


_MONOREPO_CONTAINERS: Tuple[str, ...] = (
    "packages",
    "apps",
    "crates",
    "plugins",
    "external_plugins",
    "services",
    "sdks",
    "sdk",
)


def _sanitize_safe_rel_path(
    raw_path: Any,
    *,
    repo_root: Optional[Path] = None,
) -> Optional[str]:
    """
    Validate and normalize a repository-relative path, rejecting traversal (`..`),
    absolute paths, drive letters (`:`), UNC paths (`\\\\`), null bytes, and
    percent-encoded traversal/separator sequences.
    """
    s = str(raw_path or "").strip()
    if not s:
        return None
    if "\x00" in s or "\\\\" in s or ":" in s:
        return None
    if s.startswith(("/", "\\")):
        return None
    low = s.lower()
    if any(tok in low for tok in ("%2e", "%2f", "%5c", "%00")):
        return None

    norm = s.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    if not norm or norm.startswith("/"):
        return None

    raw_parts = norm.split("/")
    if any(seg == ".." for seg in raw_parts):
        return None
    clean_parts = [seg for seg in raw_parts if seg and seg != "."]
    if not clean_parts:
        return None
    clean_rel = "/".join(clean_parts)

    if repo_root is not None and repo_root.is_dir():
        try:
            resolved_root = repo_root.resolve()
            cand = (repo_root / clean_rel).resolve()
            if not cand.is_relative_to(resolved_root):
                return None
            if not (repo_root / clean_rel).parent.resolve().is_relative_to(resolved_root):
                return None
        except (OSError, ValueError):
            return None
    return clean_rel


def resolve_changed_sibling_paths(
    changed_files: Sequence[str],
    *,
    repo_path: Optional[Union[str, Path]] = None,
    max_siblings: int = 32,
) -> List[str]:
    """
    Resolve sibling package/handler paths related to `changed_files`.

    When `repo_path` exists on disk, discovers concrete sibling files in
    monorepo sibling packages (`packages/*`, `apps/*`, `crates/*`, `sdks/*`)
    and sibling handlers in the same directory; otherwise returns normalized
    sibling directory prefixes for downstream scanning.
    """
    root_for_check = Path(repo_path) if repo_path is not None else None
    norm_changed: List[str] = []
    for f in changed_files:
        clean = _sanitize_safe_rel_path(f, repo_root=root_for_check)
        if clean is not None:
            norm_changed.append(clean)
    if not norm_changed:
        return []

    changed_set = set(norm_changed)
    siblings: List[str] = []
    seen: set[str] = set()

    def _add(item: str) -> None:
        if item and item not in changed_set and item not in seen and len(siblings) < max_siblings:
            seen.add(item)
            siblings.append(item)

    # Optional M1 parity auditor enrichment when present
    if repo_path is not None:
        root = Path(repo_path)
        if root.is_dir():
            resolved_root = root.resolve()
            try:
                from engine.parity_invariant_auditor import discover_sibling_files  # type: ignore

                for s in discover_sibling_files(root, norm_changed) or ():
                    clean_s = _sanitize_safe_rel_path(s, repo_root=root)
                    if clean_s is not None:
                        _add(clean_s)
            except Exception:
                pass

            # Monorepo sibling package discovery
            changed_pkg_roots: set[str] = set()
            for cf in norm_changed:
                parts = cf.split("/")
                if len(parts) >= 2 and parts[0].lower() in _MONOREPO_CONTAINERS:
                    changed_pkg_roots.add(f"{parts[0]}/{parts[1]}")

            for container in _MONOREPO_CONTAINERS:
                cdir = root / container
                if not cdir.is_dir():
                    continue
                for child in sorted(cdir.iterdir()):
                    if not child.is_dir():
                        continue
                    rel_pkg = f"{container}/{child.name}"
                    if rel_pkg in changed_pkg_roots:
                        continue
                    for p in sorted(child.rglob("*")):
                        if p.is_file():
                            try:
                                if not p.resolve().is_relative_to(resolved_root):
                                    continue
                                rel_p = p.relative_to(root).as_posix()
                            except (OSError, ValueError):
                                continue
                            low_p = rel_p.lower()
                            if "/tests/" in f"/{low_p}" or low_p.endswith((".md", ".txt", ".lock")):
                                continue
                            _add(rel_p)
                            break

            # Same-directory sibling files / handlers
            for cf in norm_changed:
                cf_abs = root / cf
                try:
                    if not cf_abs.resolve().is_relative_to(resolved_root):
                        continue
                    parent_abs = cf_abs.parent
                    if not parent_abs.resolve().is_relative_to(resolved_root):
                        continue
                except (OSError, ValueError):
                    continue
                if parent_abs.is_dir():
                    for p in sorted(parent_abs.iterdir()):
                        if p.is_file():
                            try:
                                if not p.resolve().is_relative_to(resolved_root):
                                    continue
                                rel_p = p.relative_to(root).as_posix()
                            except (OSError, ValueError):
                                continue
                            low_p = rel_p.lower()
                            if not low_p.endswith((".md", ".txt", ".lock")):
                                _add(rel_p)

    # Pure-path fallback prefixes when no local repo checkout is mounted yet
    if not siblings:
        for cf in norm_changed:
            parts = cf.split("/")
            if len(parts) >= 2 and parts[0].lower() in _MONOREPO_CONTAINERS:
                _add(f"{parts[0]}/*/{'/'.join(parts[2:])}" if len(parts) > 2 else f"{parts[0]}/*")
            parent = "/".join(parts[:-1])
            if parent:
                _add(f"{parent}/*")

    return siblings


class AsyncFreshnessPoller:
    """
    Loop 1: Lightweight 60-second async ETag (`If-None-Match`) poller over
    `UNLOCKED` programs (`ProgramEligibilityDB`), skipping `304 Not Modified`
    at zero API/scan cost and enqueuing diff + sibling `Intents` onto
    `SqliteBlackboard`.
    """

    def __init__(
        self,
        *,
        api_base: str = DEFAULT_API_BASE,
        token: Optional[str] = None,
        state_db: Union[str, Path] = Path("out/freshness_state.db"),
        timeout_sec: float = DEFAULT_TIMEOUT_SEC,
        max_concurrency: int = MAX_WORKERS,
        allow_loopback: bool = True,
        now_utc: Optional[datetime] = None,
    ) -> None:
        from engine.safe_network_validator import is_explicit_loopback_host, validate_target_host

        self.api_base = str(api_base or DEFAULT_API_BASE).rstrip("/")
        parsed = urllib.parse.urlparse(self.api_base)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError(f"Unsupported api_base scheme (expected http/https): {self.api_base!r}")
        host = parsed.hostname or ""
        if not host:
            raise ValueError(f"Invalid api_base URL (missing hostname): {self.api_base!r}")
        allow_priv = bool(allow_loopback and is_explicit_loopback_host(host))
        is_safe, reason = validate_target_host(host, allow_private=allow_priv)
        if not is_safe:
            raise ValueError(f"Unsafe api_base rejected by SSRF validator: {reason}")

        self.token = token if token is not None else load_github_token()
        self.timeout_sec = float(timeout_sec)
        self.max_concurrency = max(1, int(max_concurrency))
        self._now_override = now_utc
        self.store = FreshnessStateStore(state_db)

    def _now(self) -> datetime:
        return self._now_override or datetime.now(timezone.utc)

    def __enter__(self) -> "AsyncFreshnessPoller":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        self.store.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    async def _get_json_async(
        self,
        path: str,
        *,
        client: Any = None,
        http_get: Optional[Callable[..., Any]] = None,
    ) -> Tuple[Optional[Any], bool, Optional[str]]:
        url = f"{self.api_base}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "RFCHunt-AsyncFreshnessPoller/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        cached_etag = await asyncio.to_thread(self.store.get_etag, url)
        if cached_etag:
            headers["If-None-Match"] = cached_etag

        try:
            if http_get is not None:
                if inspect.iscoroutinefunction(http_get):
                    resp = await http_get(url, headers)
                else:
                    resp = await asyncio.to_thread(http_get, url, headers)
                    if inspect.isawaitable(resp):
                        resp = await resp
                status_code, resp_headers, raw_body = resp
                if int(status_code) == 304:
                    return None, True, None
                if int(status_code) >= 400:
                    return None, False, f"HTTP {status_code} on {path}"
                resp_etag = None
                if isinstance(resp_headers, dict):
                    resp_etag = resp_headers.get("ETag") or resp_headers.get("etag")
                if resp_etag:
                    await asyncio.to_thread(self.store.set_etag, url, str(resp_etag))
                if isinstance(raw_body, (dict, list)):
                    return raw_body, False, None
                if isinstance(raw_body, bytes):
                    raw_body = raw_body.decode("utf-8", errors="replace")
                return json.loads(str(raw_body)), False, None

            if client is None:
                raise RuntimeError("No httpx.AsyncClient or http_get provided.")
            resp = await client.get(url, headers=headers)
            if resp.status_code == 304:
                return None, True, None
            if resp.status_code >= 400:
                return None, False, f"HTTP {resp.status_code} on {path}"
            etag = resp.headers.get("ETag")
            if etag:
                await asyncio.to_thread(self.store.set_etag, url, etag)
            return resp.json(), False, None
        except Exception as exc:
            return None, False, f"Request failed on {path}: {exc}"

    async def _scan_target_async(
        self,
        target: WatchTarget,
        *,
        client: Any,
        http_get: Optional[Callable[..., Any]],
        freshness_hours: int,
        min_score: int,
        skip_seen: bool,
        repo_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[List[Dict[str, Any]], int, List[str]]:
        repo_slug = _validate_repo_slug(target.repo)
        now = self._now()
        cutoff = now - timedelta(hours=freshness_hours)
        records: List[Dict[str, Any]] = []
        cache_hits = 0
        errors: List[str] = []
        seen_local_shas: set[str] = set()

        # 1. Fresh Releases (with tag compare/commit diff file extraction)
        releases, hit, err = await self._get_json_async(
            f"/repos/{repo_slug}/releases?per_page=5",
            client=client,
            http_get=http_get,
        )
        if hit:
            cache_hits += 1
        elif err:
            errors.append(f"{repo_slug} releases: {err}")
        elif isinstance(releases, list):
            for idx, rel in enumerate(releases):
                ts = _parse_iso_utc(rel.get("published_at") or rel.get("created_at"))
                if not ts or ts < cutoff:
                    continue
                tag = str(rel.get("tag_name") or rel.get("name") or "release")
                sha = str(rel.get("target_commitish") or tag)
                if skip_seen and await asyncio.to_thread(_is_sha_seen, self.store, repo_slug, sha):
                    continue
                seen_local_shas.add(sha)
                if len(sha) > 12:
                    seen_local_shas.add(sha[:12])

                rel_files: List[str] = [
                    str(f.get("filename", f) if isinstance(f, dict) else f)
                    for f in (rel.get("changed_files") or rel.get("files") or [])
                    if f
                ]
                if not rel_files and idx + 1 < len(releases):
                    prev_tag = str(releases[idx + 1].get("tag_name") or "").strip()
                    if prev_tag and prev_tag != tag:
                        cmp_json, chit, _ = await self._get_json_async(
                            f"/repos/{repo_slug}/compare/{urllib.parse.quote(prev_tag)}...{urllib.parse.quote(tag)}",
                            client=client,
                            http_get=http_get,
                        )
                        if chit:
                            cache_hits += 1
                        elif isinstance(cmp_json, dict):
                            rel_files = [
                                str(item.get("filename", ""))
                                for item in (cmp_json.get("files") or [])
                                if isinstance(item, dict) and item.get("filename")
                            ]
                if not rel_files and sha:
                    c_json, chit2, _ = await self._get_json_async(
                        f"/repos/{repo_slug}/commits/{urllib.parse.quote(sha)}",
                        client=client,
                        http_get=http_get,
                    )
                    if chit2:
                        cache_hits += 1
                    elif isinstance(c_json, dict):
                        rel_files = [
                            str(item.get("filename", ""))
                            for item in (c_json.get("files") or [])
                            if isinstance(item, dict) and item.get("filename")
                        ]

                title = f"[Release {tag}] {rel.get('name') or tag}"
                body = str(rel.get("body") or "")
                score, surfaces = score_diff_surface(rel_files, title=title, body=body, event_type="release")
                if score >= min_score:
                    cand = FreshCandidate(
                        program=target.program,
                        repo=repo_slug,
                        event_type="release",
                        ref_id=tag,
                        sha=sha,
                        title=title,
                        url=str(rel.get("html_url") or f"https://github.com/{repo_slug}/releases"),
                        landed_at=ts.isoformat(),
                        age_hours=max(0.0, (now - ts).total_seconds() / 3600.0),
                        surface_score=score,
                        matched_surfaces=surfaces,
                        changed_files=rel_files[:15],
                        bounty_tier=target.bounty_tier,
                        scope_asset=target.scope_asset,
                    )
                    sib_files = await asyncio.to_thread(
                        resolve_changed_sibling_paths, cand.changed_files, repo_path=repo_path
                    )
                    records.append(
                        {
                            "candidate": cand,
                            "full_sha": sha,
                            "body": body,
                            "sibling_files": sib_files,
                            "repo_path": str(repo_path) if repo_path else "",
                        }
                    )

        # 2. Fresh Merged PRs
        pulls, hit, err = await self._get_json_async(
            f"/repos/{repo_slug}/pulls?state=closed&sort=updated&direction=desc&per_page=10",
            client=client,
            http_get=http_get,
        )
        if hit:
            cache_hits += 1
        elif err:
            errors.append(f"{repo_slug} pulls: {err}")
        elif isinstance(pulls, list):
            for pr in pulls:
                merged_at = _parse_iso_utc(pr.get("merged_at"))
                if not merged_at or merged_at < cutoff:
                    continue
                sha = str(pr.get("merge_commit_sha") or (pr.get("head") or {}).get("sha") or "")
                if not sha or sha in seen_local_shas or sha[:12] in seen_local_shas:
                    continue
                if skip_seen and await asyncio.to_thread(_is_sha_seen, self.store, repo_slug, sha):
                    continue
                seen_local_shas.add(sha)
                if len(sha) > 12:
                    seen_local_shas.add(sha[:12])
                pr_num = pr.get("number")
                changed_files: List[str] = []
                diff_chunks: List[str] = []
                if pr_num is not None:
                    files_json, fhit, _ = await self._get_json_async(
                        f"/repos/{repo_slug}/pulls/{pr_num}/files?per_page=30",
                        client=client,
                        http_get=http_get,
                    )
                    if fhit:
                        cache_hits += 1
                    elif isinstance(files_json, list):
                        for item in files_json:
                            if isinstance(item, dict) and item.get("filename"):
                                changed_files.append(str(item["filename"]))
                                if item.get("patch"):
                                    diff_chunks.append(str(item["patch"])[:500])

                title = f"[PR #{pr_num}] {pr.get('title') or ''}".strip()
                body = str(pr.get("body") or "")
                score, surfaces = score_diff_surface(
                    changed_files, title=title, body=body, event_type="merged_pr"
                )
                if score >= min_score:
                    cand = FreshCandidate(
                        program=target.program,
                        repo=repo_slug,
                        event_type="merged_pr",
                        ref_id=f"#{pr_num}",
                        sha=sha[:12],
                        title=title,
                        url=str(pr.get("html_url") or f"https://github.com/{repo_slug}/pull/{pr_num}"),
                        landed_at=merged_at.isoformat(),
                        age_hours=max(0.0, (now - merged_at).total_seconds() / 3600.0),
                        surface_score=score,
                        matched_surfaces=surfaces,
                        changed_files=changed_files[:15],
                        bounty_tier=target.bounty_tier,
                        scope_asset=target.scope_asset,
                    )
                    sib_files = await asyncio.to_thread(
                        resolve_changed_sibling_paths, cand.changed_files, repo_path=repo_path
                    )
                    records.append(
                        {
                            "candidate": cand,
                            "full_sha": sha,
                            "body": f"{body}\n" + "\n".join(diff_chunks),
                            "sibling_files": sib_files,
                            "repo_path": str(repo_path) if repo_path else "",
                        }
                    )

        # 3. Fresh Direct Commits (invariant URL so GitHub ETag 304 cache hits across polls)
        commits, hit, err = await self._get_json_async(
            f"/repos/{repo_slug}/commits?per_page=10",
            client=client,
            http_get=http_get,
        )
        if hit:
            cache_hits += 1
        elif err:
            errors.append(f"{repo_slug} commits: {err}")
        elif isinstance(commits, list):
            for c in commits:
                sha = str(c.get("sha") or "")
                if not sha or sha in seen_local_shas or sha[:12] in seen_local_shas:
                    continue
                if skip_seen and await asyncio.to_thread(_is_sha_seen, self.store, repo_slug, sha):
                    continue
                commit_obj = c.get("commit") or {}
                committer = commit_obj.get("committer") or commit_obj.get("author") or {}
                ts = _parse_iso_utc(committer.get("date"))
                if not ts or ts < cutoff:
                    continue
                msg = str(commit_obj.get("message") or "").splitlines()[0].strip()
                changed_files: List[str] = []
                diff_chunks: List[str] = []
                for f in (c.get("files") or []):
                    if isinstance(f, dict) and f.get("filename"):
                        changed_files.append(str(f["filename"]))
                        if f.get("patch"):
                            diff_chunks.append(str(f["patch"])[:500])
                if not changed_files:
                    detail_json, dhit, _ = await self._get_json_async(
                        f"/repos/{repo_slug}/commits/{urllib.parse.quote(sha)}",
                        client=client,
                        http_get=http_get,
                    )
                    if dhit:
                        cache_hits += 1
                    elif isinstance(detail_json, dict):
                        for f in (detail_json.get("files") or []):
                            if isinstance(f, dict) and f.get("filename"):
                                changed_files.append(str(f["filename"]))
                                if f.get("patch"):
                                    diff_chunks.append(str(f["patch"])[:500])

                diff_body = "\n".join(diff_chunks)
                score, surfaces = score_diff_surface(
                    changed_files, title=msg, body=diff_body, event_type="commit"
                )
                if score >= min_score:
                    cand = FreshCandidate(
                        program=target.program,
                        repo=repo_slug,
                        event_type="commit",
                        ref_id=sha[:10],
                        sha=sha[:12],
                        title=msg,
                        url=str(c.get("html_url") or f"https://github.com/{repo_slug}/commit/{sha}"),
                        landed_at=ts.isoformat(),
                        age_hours=max(0.0, (now - ts).total_seconds() / 3600.0),
                        surface_score=score,
                        matched_surfaces=surfaces,
                        changed_files=changed_files[:15],
                        bounty_tier=target.bounty_tier,
                        scope_asset=target.scope_asset,
                    )
                    sib_files = await asyncio.to_thread(
                        resolve_changed_sibling_paths, cand.changed_files, repo_path=repo_path
                    )
                    records.append(
                        {
                            "candidate": cand,
                            "full_sha": sha,
                            "body": diff_body,
                            "sibling_files": sib_files,
                            "repo_path": str(repo_path) if repo_path else "",
                        }
                    )

        return records, cache_hits, errors

    async def poll_once(
        self,
        targets: Sequence[WatchTarget],
        *,
        eligibility_db: Any = None,
        blackboard: Any = None,
        http_get: Optional[Callable[..., Any]] = None,
        freshness_hours: int = DEFAULT_FRESHNESS_HOURS,
        min_score: int = 20,
        skip_seen: bool = True,
        mark_returned_seen: bool = True,
        repo_paths: Optional[Dict[str, Union[str, Path]]] = None,
        lane: int = 2,
    ) -> Dict[str, Any]:
        """
        Execute one async ETag-cached poll cycle across `UNLOCKED` targets.
        Returns `304 Not Modified` immediately with zero re-scans/intents.
        """
        eligible_targets: List[WatchTarget] = []
        skipped_ineligible: List[str] = []
        for t in targets:
            if not t.enabled:
                continue
            if eligibility_db is not None and not eligibility_db.is_eligible(t.program):
                skipped_ineligible.append(t.program)
                continue
            eligible_targets.append(t)

        sem = asyncio.Semaphore(self.max_concurrency)
        all_records: List[Dict[str, Any]] = []
        total_cache_hits = 0
        all_errors: List[str] = []
        paths_map = repo_paths or {}

        async def _run_target(target: WatchTarget, client: Any) -> Tuple[List[Dict[str, Any]], int, List[str]]:
            async with sem:
                rpath = paths_map.get(target.repo) or paths_map.get(target.program)
                return await self._scan_target_async(
                    target,
                    client=client,
                    http_get=http_get,
                    freshness_hours=freshness_hours,
                    min_score=min_score,
                    skip_seen=skip_seen,
                    repo_path=rpath,
                )

        if http_get is not None:
            results = await asyncio.gather(
                *[_run_target(t, None) for t in eligible_targets]
            )
        else:
            import httpx

            async with httpx.AsyncClient(timeout=self.timeout_sec) as client:
                results = await asyncio.gather(
                    *[_run_target(t, client) for t in eligible_targets]
                )

        for recs, hits, errs in results:
            all_records.extend(recs)
            total_cache_hits += hits
            all_errors.extend(errs)

        all_records.sort(
            key=lambda r: (-r["candidate"].surface_score, r["candidate"].age_hours)
        )

        enqueued_intent_ids: List[str] = []
        candidates_out: List[FreshCandidate] = []
        for rec in all_records:
            cand: FreshCandidate = rec["candidate"]
            sibling_files: List[str] = list(rec["sibling_files"])
            body_text = str(rec.get("body") or "")
            rpath_str = str(rec.get("repo_path") or "")
            candidates_out.append(cand)

            if mark_returned_seen:
                await asyncio.to_thread(
                    _mark_sha_seen,
                    self.store,
                    cand.repo,
                    cand.sha,
                    str(rec.get("full_sha") or cand.sha),
                )

            if blackboard is not None:
                try:
                    from engine.async_blackboard_runtime import (
                        detect_security_fix_signal,
                        emit_sibling_parity_intents,
                    )

                    sec_signals = detect_security_fix_signal(cand.title, body_text)
                except Exception:
                    sec_signals = []
                    emit_sibling_parity_intents = None  # type: ignore[assignment]

                target_files = list(dict.fromkeys(list(cand.changed_files) + sibling_files))
                payload = {
                    "program": cand.program,
                    "repo": cand.repo,
                    "repo_path": rpath_str,
                    "event_type": cand.event_type,
                    "ref_id": cand.ref_id,
                    "sha": cand.sha,
                    "commit_message": cand.title,
                    "diff_text": body_text[:4000],
                    "changed_files": list(cand.changed_files),
                    "sibling_files": sibling_files,
                    "target_files": target_files,
                    "security_fix_signals": sec_signals,
                    "surface_score": cand.surface_score,
                }
                dedup = f"loop1:{cand.repo}:{cand.sha}:{cand.event_type}"
                if hasattr(blackboard, "aenqueue_intent"):
                    iid = await blackboard.aenqueue_intent(
                        "diff_scan",
                        payload,
                        program=cand.program,
                        repo=cand.repo,
                        lane=lane,
                        priority=float(cand.surface_score) / 100.0,
                        dedup_key=dedup,
                    )
                else:
                    iid = await asyncio.to_thread(
                        blackboard.enqueue_intent,
                        "diff_scan",
                        payload,
                        program=cand.program,
                        repo=cand.repo,
                        lane=lane,
                        priority=float(cand.surface_score) / 100.0,
                        dedup_key=dedup,
                    )
                enqueued_intent_ids.append(iid)

                if sec_signals and rpath_str and Path(rpath_str).is_dir() and emit_sibling_parity_intents is not None:
                    sibling_ids = await asyncio.to_thread(
                        emit_sibling_parity_intents,
                        blackboard,
                        repo_path=rpath_str,
                        changed_files=cand.changed_files,
                        trigger_reason=f"loop1_security_fix:{','.join(sec_signals)}",
                        parent_intent_id=iid,
                        program=cand.program,
                        repo=cand.repo,
                        lane=lane,
                    )
                    enqueued_intent_ids.extend(sibling_ids)

        return {
            "generated_at": self._now().isoformat(),
            "freshness_hours": freshness_hours,
            "targets_checked": len(eligible_targets),
            "skipped_ineligible": skipped_ineligible,
            "etag_cache_hits": total_cache_hits,
            "total_candidates": len(candidates_out),
            "candidates": [c.to_dict() for c in candidates_out],
            "enqueued_intent_ids": enqueued_intent_ids,
            "errors": all_errors,
        }

    async def run_loop(
        self,
        targets: Sequence[WatchTarget],
        *,
        interval_sec: float = 60.0,
        max_cycles: Optional[int] = None,
        stop_event: Optional[asyncio.Event] = None,
        **poll_kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """Run periodic 60-second async ETag poll cycles until stopped or `max_cycles` reached."""
        reports: List[Dict[str, Any]] = []
        cycles = 0
        eff_interval = max(0.01, float(interval_sec))
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            reports.append(await self.poll_once(targets, **poll_kwargs))
            cycles += 1
            if max_cycles is not None and cycles >= int(max_cycles):
                break
            if stop_event is not None:
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=eff_interval)
                    break
                except asyncio.TimeoutError:
                    continue
            else:
                await asyncio.sleep(eff_interval)
        return reports

