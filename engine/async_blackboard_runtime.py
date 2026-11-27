"""
Async SQLite WAL Blackboard & Windows-Spawn-Safe ProcessPoolExecutor Runtime
(`engine/async_blackboard_runtime.py`).
===========================================================================
Implements the persistent 3-table SQLite WAL Stigmergic Blackboard (`facts`,
`intents`, `hints`), Windows-spawn-safe `ProcessPoolExecutor` CPU workers,
Loop 2 security-fix & landed-fact sibling parity propagation, Loop 5 two-lane
self-adapting queue & auto-unlock draft staging, and `run_local_rfchunt_async`.

Design Invariants:
- Minimal top-level imports so Windows `multiprocessing.get_context("spawn")`
  child processes start quickly without importing heavy ML/LLM stacks.
- Only primitive JSON-serializable dict payloads cross `ProcessPoolExecutor`.
- M1 scanner modules are imported lazily inside individual `try ... except ImportError`
  blocks with deterministic fallbacks.
- `run_z3_formal_verification` is called without `scope_policy`/`target_intent`
  when `scope_bridge is None` to avoid `ScopeGateDeniedError` when optional
  `engine.rust_scope_bridge` is absent.
- Explicit `.close()` + context-manager support on `SqliteBlackboard` so
  Windows `-wal`/`-shm` handles release cleanly.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import multiprocessing
import os
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self

# Loop 2 Constants (PROJECT.md §5)
SECURITY_FIX_KEYWORDS: tuple[str, ...] = (
    "sanitize",
    "o_nofollow",
    "symlink",
    "allowfrom",
    "csp",
    "ssrf",
    "authz",
    "verify",
)

SIBLING_SDK_LANGUAGES: tuple[str, ...] = (
    "TS",
    "Python",
    "Go",
    "Java",
    "Ruby",
    "Rust",
)

# Loop 5 Default Lanes (PROJECT.md §5 — real VDPs in Lane 1 for Signal building)
LANE1_DEFAULT_PROGRAMS: tuple[str, ...] = (
    "henkel_vdp",
    "servicenow-disclosure",
    "rails",
    "ruby",
    "anthropic-cyber-jailbreak",
    "deptofdefense",
    "common_codes",
)

LANE2_DEFAULT_PROGRAMS: tuple[str, ...] = (
    "anthropic",
    "common_codes",
    "oppo_bbp",
    "amazonvrp",
    "temu",
)

_SDK_DIR_ALIASES: dict[str, tuple[str, ...]] = {
    "TS": ("ts", "typescript", "js", "javascript", "node", "sdk-ts", "ts-sdk"),
    "Python": ("python", "py", "sdk-python", "python-sdk"),
    "Go": ("go", "golang", "sdk-go", "go-sdk"),
    "Java": ("java", "jvm", "sdk-java", "java-sdk"),
    "Ruby": ("ruby", "rb", "sdk-ruby", "ruby-sdk"),
    "Rust": ("rust", "rs", "cargo", "sdk-rust", "rust-sdk"),
}

_DEFAULT_UNLOCK_REPOS: dict[str, tuple[str, ...]] = {
    "shopify": ("Shopify/shopify-app-js", "Shopify/function-runner", "Shopify/hydrogen"),
    "vercel": ("vercel/next.js", "vercel/vercel"),
    "cloudflare": ("cloudflare/pingora", "cloudflare/workers-sdk"),
    "anthropic": ("anthropics/sandbox-runtime", "anthropics/claude-code"),
}

_NOISE_PATH_PARTS: tuple[str, ...] = (
    "/tests/",
    "/test/",
    "/__tests__/",
    "/__fixtures__/",
    "/fixtures/",
    "/examples/",
    "/example/",
    "/docs/",
    "/doc/",
    "/benchmarks/",
)

_NOISE_FILE_SUFFIXES: tuple[str, ...] = (
    "_test.go",
    "_test.py",
    "_spec.rb",
    ".test.ts",
    ".test.tsx",
    ".test.js",
    ".test.jsx",
    ".spec.ts",
    ".spec.tsx",
    ".spec.js",
    ".spec.jsx",
    ".md",
    ".rst",
    ".txt",
)


def _utc_iso() -> str:
    return datetime.now(UTC).isoformat()


def _coerce_strict_bool(val: Any) -> bool:
    """Fail-closed boolean coercion rejecting `"false"`, `"0"`, `"no"`, `"off"`, `""`, and `None`."""
    if val is True:
        return True
    if isinstance(val, int) and not isinstance(val, bool):
        return val == 1
    if isinstance(val, str):
        return val.strip().lower() in {"true", "1", "yes", "on"}
    return False


def default_cpu_workers(requested: int | None = None) -> int:
    """Bounded CPU worker count (`min(8, max(2, cpu_count // 2))` by default)."""
    if requested is not None:
        return max(1, min(16, int(requested)))
    return min(8, max(2, (os.cpu_count() or 4) // 2))


def _sanitize_safe_rel_path(
    raw_path: Any,
    *,
    repo_root: Path | None = None,
) -> str | None:
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


def _has_js_ts_assets(
    repo_root: Path,
    active_target_files: Sequence[str],
    *,
    max_files: int = 80,
) -> bool:
    js_ts_suffixes = (".js", ".jsx", ".ts", ".tsx", ".mjs", "package.json")
    if active_target_files:
        return any(f.lower().endswith(js_ts_suffixes) for f in active_target_files)
    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"}
    visited = 0
    for _cur_root, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in skip_dirs]
        for fn in sorted(filenames):
            visited += 1
            if fn.lower().endswith(js_ts_suffixes):
                return True
            if visited >= max_files:
                return False
    return False


def _fallback_is_non_production_noise(
    file_path: str,
    metadata: dict[str, Any] | None = None,
    *,
    rule_id: str = "",
    summary: str = "",
) -> bool:
    """Deterministic fallback production-noise filter when M1 parity auditor is absent."""
    meta = metadata if isinstance(metadata, dict) else {}
    if bool(meta.get("non_production_noise", False)):
        return True
    norm = "/" + str(file_path or "").replace("\\", "/").lstrip("./").lower()
    base = norm.rsplit("/", 1)[-1]
    if any(part in norm for part in _NOISE_PATH_PARTS):
        return True
    if base.startswith("test_") or base.endswith(_NOISE_FILE_SUFFIXES):
        return True
    if base in ("readme", "changelog", "license", "contributing"):
        return True
    rid = str(rule_id or "").strip().lower()
    if any(tok in rid for tok in ("docstring", "lint-only", "formatting", "style-only")):
        return True
    sum_low = str(summary or "").strip().lower()
    return bool(any(tok in sum_low for tok in ("docstring only", "lint noise", "formatting only")))


# ---------------------------------------------------------------------------
# Async / Thread-Safe SQLite WAL Blackboard (facts, intents, hints)
# ---------------------------------------------------------------------------


class SqliteBlackboard:
    """
    Crash-recoverable SQLite WAL Stigmergic Blackboard (`facts`, `intents`, `hints`).

    Uses stdlib `sqlite3` protected by a `threading.RLock()` and bounded
    `SQLITE_BUSY` retries (no `aiosqlite` dependency required), plus `async`
    helper methods via `asyncio.to_thread(...)`.
    """

    def __init__(self, db_path: str | Path) -> None:
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
        self._conn = sqlite3.connect(
            connect_target,
            check_same_thread=False,
            timeout=10.0,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._configure_pragmas()
        self._init_schema()

    def _configure_pragmas(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA busy_timeout=10000;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            if not self.is_memory:
                self._conn.execute("PRAGMA journal_mode=WAL;")

    def _run_with_retry(self, fn: Callable[[], Any]) -> Any:
        last_exc: Exception | None = None
        for attempt in range(6):
            try:
                with self._lock:
                    if self._closed:
                        raise RuntimeError("SqliteBlackboard is closed.")
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
                CREATE TABLE IF NOT EXISTS facts (
                    fact_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL DEFAULT 'default',
                    program TEXT NOT NULL DEFAULT '',
                    repo TEXT NOT NULL DEFAULT '',
                    domain TEXT NOT NULL DEFAULT 'general',
                    title TEXT NOT NULL,
                    file_path TEXT NOT NULL DEFAULT '',
                    line INTEGER NOT NULL DEFAULT 0,
                    severity TEXT NOT NULL DEFAULT 'MEDIUM',
                    confidence REAL NOT NULL DEFAULT 0.5,
                    poc_verified INTEGER NOT NULL DEFAULT 0,
                    merkle_leaf_hash TEXT NOT NULL DEFAULT '',
                    source_engine TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    parent_intent_id TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_facts_task_domain
                    ON facts(task_id, domain, created_at_utc);

                CREATE TABLE IF NOT EXISTS intents (
                    intent_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL DEFAULT 'default',
                    program TEXT NOT NULL DEFAULT '',
                    repo TEXT NOT NULL DEFAULT '',
                    lane INTEGER NOT NULL DEFAULT 2,
                    intent_type TEXT NOT NULL,
                    priority REAL NOT NULL DEFAULT 0.0,
                    status TEXT NOT NULL CHECK(status IN ('PENDING','IN_PROGRESS','DONE','FAILED')),
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    max_retries INTEGER NOT NULL DEFAULT 3,
                    claimed_by TEXT NOT NULL DEFAULT '',
                    lease_expires_at REAL,
                    heartbeat_at REAL,
                    dedup_key TEXT UNIQUE,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    error_message TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_intents_status_lane_prio
                    ON intents(status, lane, priority DESC, created_at_utc ASC);

                CREATE TABLE IF NOT EXISTS hints (
                    hint_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL DEFAULT 'default',
                    domain TEXT NOT NULL DEFAULT 'general',
                    source TEXT NOT NULL DEFAULT '',
                    priority REAL NOT NULL DEFAULT 0.0,
                    active INTEGER NOT NULL DEFAULT 1,
                    content TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_hints_task_active
                    ON hints(task_id, active, priority DESC);
                """
            )

        self._run_with_retry(_create)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                if not self.is_memory:
                    try:
                        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                    except Exception:  # noqa: BLE001, S110
                        pass
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001, S110
                    pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001, S110
            pass

    # -- Facts --

    def add_fact(
        self,
        title: str | dict[str, Any] = "",
        *,
        task_id: str = "default",
        program: str = "",
        repo: str = "",
        domain: str = "general",
        file_path: str = "",
        line: int = 0,
        severity: str = "MEDIUM",
        confidence: float = 0.5,
        poc_verified: bool = False,
        merkle_leaf_hash: str = "",
        source_engine: str = "",
        payload: dict[str, Any] | None = None,
        parent_intent_id: str = "",
        fact_id: str | None = None,
    ) -> str:
        if isinstance(title, dict):
            raw = dict(title)
            title_str = str(raw.get("title", "untitled_fact"))
            task_id = str(raw.get("task_id", task_id))
            program = str(raw.get("program", program))
            repo = str(raw.get("repo", repo))
            domain = str(raw.get("domain", domain))
            file_path = str(raw.get("file_path", file_path))
            line = int(raw.get("line", line) or 0)
            severity = str(raw.get("severity", severity))
            confidence = float(raw.get("confidence", confidence))
            poc_verified = _coerce_strict_bool(raw.get("poc_verified", poc_verified))
            merkle_leaf_hash = str(raw.get("merkle_leaf_hash", merkle_leaf_hash))
            source_engine = str(raw.get("source_engine", source_engine))
            parent_intent_id = str(raw.get("parent_intent_id", parent_intent_id))
            payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else raw
            fact_id = str(raw.get("fact_id") or fact_id or f"fact_{uuid.uuid4().hex[:12]}")
        else:
            title_str = str(title or "untitled_fact")
            fact_id = fact_id or f"fact_{uuid.uuid4().hex[:12]}"

        now = _utc_iso()
        payload_str = json.dumps(payload or {}, ensure_ascii=False)

        def _insert() -> str:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                self._conn.execute(
                    """
                    INSERT INTO facts (
                        fact_id, task_id, program, repo, domain, title,
                        file_path, line, severity, confidence, poc_verified,
                        merkle_leaf_hash, source_engine, payload_json,
                        parent_intent_id, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fact_id,
                        task_id,
                        program,
                        repo,
                        domain,
                        title_str,
                        file_path,
                        int(line),
                        severity,
                        float(confidence),
                        1 if _coerce_strict_bool(poc_verified) else 0,
                        merkle_leaf_hash,
                        source_engine,
                        payload_str,
                        parent_intent_id,
                        now,
                    ),
                )
                self._conn.execute("COMMIT;")
                return fact_id
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return str(self._run_with_retry(_insert))

    def list_facts(
        self,
        *,
        task_id: str | None = None,
        program: str | None = None,
        domain: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        if program is not None:
            clauses.append("program = ?")
            params.append(program)
        if domain is not None:
            clauses.append("domain = ?")
            params.append(domain)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, int(limit)))

        def _query() -> list[dict[str, Any]]:
            rows = self._conn.execute(
                f"SELECT * FROM facts {where} ORDER BY rowid ASC LIMIT ?",
                params,
            ).fetchall()
            out: list[dict[str, Any]] = []
            for r in rows:
                d = dict(r)
                d["poc_verified"] = _coerce_strict_bool(d.get("poc_verified", 0))
                try:
                    d["payload"] = json.loads(d.get("payload_json") or "{}")
                except (json.JSONDecodeError, TypeError, ValueError):
                    d["payload"] = {}
                out.append(d)
            return out

        return list(self._run_with_retry(_query))

    # -- Intents --

    def enqueue_intent(
        self,
        intent_type: str = "stage1_cpu",
        payload: dict[str, Any] | None = None,
        *,
        task_id: str = "default",
        program: str = "",
        repo: str = "",
        lane: int = 2,
        priority: float = 0.0,
        max_retries: int = 3,
        dedup_key: str | None = None,
        intent_id: str | None = None,
    ) -> str:
        eff_id = intent_id or f"intent_{uuid.uuid4().hex[:12]}"
        eff_lane = 1 if int(lane) == 1 else 2
        now = _utc_iso()
        payload_str = json.dumps(payload or {}, ensure_ascii=False)

        def _enqueue() -> str:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                if dedup_key is not None:
                    existing = self._conn.execute(
                        "SELECT intent_id FROM intents WHERE dedup_key = ?",
                        (dedup_key,),
                    ).fetchone()
                    if existing is not None:
                        self._conn.execute("COMMIT;")
                        return str(existing["intent_id"])

                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO intents (
                        intent_id, task_id, program, repo, lane, intent_type,
                        priority, status, retry_count, max_retries, claimed_by,
                        lease_expires_at, heartbeat_at, dedup_key, payload_json,
                        result_json, error_message, created_at_utc, updated_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?, '', NULL, NULL, ?, ?, '{}', '', ?, ?)
                    """,
                    (
                        eff_id,
                        task_id,
                        program,
                        repo,
                        eff_lane,
                        str(intent_type),
                        float(priority),
                        max(0, int(max_retries)),
                        dedup_key,
                        payload_str,
                        now,
                        now,
                    ),
                )
                self._conn.execute("COMMIT;")
                return eff_id
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return str(self._run_with_retry(_enqueue))

    def _decode_intent_row(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        try:
            d["payload"] = json.loads(d.get("payload_json") or "{}")
        except Exception:  # noqa: BLE001
            d["payload"] = {}
        try:
            d["result"] = json.loads(d.get("result_json") or "{}")
        except (json.JSONDecodeError, TypeError, ValueError):
            d["result"] = {}
        return d

    def claim_intent(
        self,
        worker_id: str,
        *,
        lease_sec: float = 120.0,
        lane: int | None = None,
        task_id: str | None = None,
    ) -> dict[str, Any] | None:
        now_epoch = time.time()
        lease_exp = now_epoch + max(1.0, float(lease_sec))
        now_iso = _utc_iso()

        clauses = ["status = 'PENDING'"]
        params: list[Any] = []
        if lane is not None:
            clauses.append("lane = ?")
            params.append(1 if int(lane) == 1 else 2)
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        where = " AND ".join(clauses)

        def _claim() -> dict[str, Any] | None:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                row = self._conn.execute(
                    f"""
                    SELECT * FROM intents
                    WHERE {where}
                    ORDER BY priority DESC, rowid ASC
                    LIMIT 1
                    """,
                    params,
                ).fetchone()
                if row is None:
                    self._conn.execute("COMMIT;")
                    return None

                intent_id = str(row["intent_id"])
                cur = self._conn.execute(
                    """
                    UPDATE intents
                    SET status = 'IN_PROGRESS',
                        claimed_by = ?,
                        heartbeat_at = ?,
                        lease_expires_at = ?,
                        updated_at_utc = ?
                    WHERE intent_id = ? AND status = 'PENDING'
                    """,
                    (str(worker_id), now_epoch, lease_exp, now_iso, intent_id),
                )
                if cur.rowcount != 1:
                    self._conn.execute("ROLLBACK;")
                    return None
                updated = self._conn.execute(
                    "SELECT * FROM intents WHERE intent_id = ?",
                    (intent_id,),
                ).fetchone()
                self._conn.execute("COMMIT;")
                return self._decode_intent_row(updated) if updated is not None else None
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return self._run_with_retry(_claim)

    def heartbeat_intent(
        self,
        intent_id: str,
        worker_id: str,
        *,
        extend_sec: float = 120.0,
    ) -> bool:
        now_epoch = time.time()
        lease_exp = now_epoch + max(1.0, float(extend_sec))
        now_iso = _utc_iso()

        def _hb() -> bool:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = self._conn.execute(
                    """
                    UPDATE intents
                    SET heartbeat_at = ?,
                        lease_expires_at = ?,
                        updated_at_utc = ?
                    WHERE intent_id = ? AND status = 'IN_PROGRESS' AND claimed_by = ?
                    """,
                    (now_epoch, lease_exp, now_iso, intent_id, worker_id),
                )
                self._conn.execute("COMMIT;")
                return cur.rowcount == 1
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return bool(self._run_with_retry(_hb))

    def complete_intent(
        self,
        intent_id: str,
        result: dict[str, Any] | None = None,
    ) -> bool:
        now_iso = _utc_iso()
        res_str = json.dumps(result or {}, ensure_ascii=False)

        def _done() -> bool:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = self._conn.execute(
                    """
                    UPDATE intents
                    SET status = 'DONE',
                        result_json = ?,
                        lease_expires_at = NULL,
                        updated_at_utc = ?
                    WHERE intent_id = ?
                    """,
                    (res_str, now_iso, intent_id),
                )
                self._conn.execute("COMMIT;")
                return cur.rowcount == 1
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return bool(self._run_with_retry(_done))

    def fail_intent(self, intent_id: str, error: str = "") -> bool:
        now_iso = _utc_iso()

        def _fail() -> bool:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = self._conn.execute(
                    """
                    UPDATE intents
                    SET status = 'FAILED',
                        error_message = ?,
                        lease_expires_at = NULL,
                        updated_at_utc = ?
                    WHERE intent_id = ?
                    """,
                    (str(error)[:2000], now_iso, intent_id),
                )
                self._conn.execute("COMMIT;")
                return cur.rowcount == 1
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return bool(self._run_with_retry(_fail))

    def recover_stale_intents(
        self,
        *,
        force_all_in_progress: bool = False,
        now_epoch: float | None = None,
    ) -> dict[str, Any]:
        """
        Reset stale `IN_PROGRESS` intents back to `PENDING` (or `FAILED` if
        `retry_count + 1 > max_retries`). Never deletes or alters `facts`.
        """
        eff_now = time.time() if now_epoch is None else float(now_epoch)
        now_iso = _utc_iso()

        def _recover() -> dict[str, Any]:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                if force_all_in_progress:
                    rows = self._conn.execute(
                        "SELECT intent_id, retry_count, max_retries FROM intents WHERE status = 'IN_PROGRESS'"
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        """
                        SELECT intent_id, retry_count, max_retries
                        FROM intents
                        WHERE status = 'IN_PROGRESS'
                          AND lease_expires_at IS NOT NULL
                          AND lease_expires_at <= ?
                        """,
                        (eff_now,),
                    ).fetchall()

                recovered_ids: list[str] = []
                failed_ids: list[str] = []
                for r in rows:
                    iid = str(r["intent_id"])
                    new_retry = int(r["retry_count"]) + 1
                    max_ret = int(r["max_retries"])
                    if new_retry > max_ret:
                        self._conn.execute(
                            """
                            UPDATE intents
                            SET status = 'FAILED',
                                retry_count = ?,
                                claimed_by = '',
                                lease_expires_at = NULL,
                                error_message = 'Max retries exceeded during stale lease recovery.',
                                updated_at_utc = ?
                            WHERE intent_id = ?
                            """,
                            (new_retry, now_iso, iid),
                        )
                        failed_ids.append(iid)
                    else:
                        self._conn.execute(
                            """
                            UPDATE intents
                            SET status = 'PENDING',
                                retry_count = ?,
                                claimed_by = '',
                                lease_expires_at = NULL,
                                heartbeat_at = NULL,
                                updated_at_utc = ?
                            WHERE intent_id = ?
                            """,
                            (new_retry, now_iso, iid),
                        )
                        recovered_ids.append(iid)

                self._conn.execute("COMMIT;")
                return {
                    "recovered_to_pending": len(recovered_ids),
                    "exhausted_to_failed": len(failed_ids),
                    "intent_ids": recovered_ids,
                    "failed_ids": failed_ids,
                }
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return dict(self._run_with_retry(_recover))

    def list_intents(
        self,
        *,
        status: str | None = None,
        lane: int | None = None,
        task_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status.strip().upper())
        if lane is not None:
            clauses.append("lane = ?")
            params.append(1 if int(lane) == 1 else 2)
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, int(limit)))

        def _query() -> list[dict[str, Any]]:
            rows = self._conn.execute(
                f"SELECT * FROM intents {where} ORDER BY lane ASC, priority DESC, rowid ASC LIMIT ?",
                params,
            ).fetchall()
            return [self._decode_intent_row(r) for r in rows]

        return list(self._run_with_retry(_query))

    # -- Hints --

    def add_hint(
        self,
        content: str,
        *,
        task_id: str = "default",
        domain: str = "general",
        source: str = "",
        priority: float = 0.0,
        active: bool = True,
        payload: dict[str, Any] | None = None,
        hint_id: str | None = None,
    ) -> str:
        eff_id = hint_id or f"hint_{uuid.uuid4().hex[:12]}"
        now = _utc_iso()
        payload_str = json.dumps(payload or {}, ensure_ascii=False)

        def _insert() -> str:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO hints (
                        hint_id, task_id, domain, source, priority, active,
                        content, payload_json, created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        eff_id,
                        task_id,
                        domain,
                        source,
                        float(priority),
                        1 if active else 0,
                        str(content),
                        payload_str,
                        now,
                    ),
                )
                self._conn.execute("COMMIT;")
                return eff_id
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return str(self._run_with_retry(_insert))

    def list_hints(
        self,
        *,
        task_id: str | None = None,
        domain: str | None = None,
        active_only: bool = True,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        if domain is not None:
            clauses.append("domain = ?")
            params.append(domain)
        if active_only:
            clauses.append("active = 1")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, int(limit)))

        def _query() -> list[dict[str, Any]]:
            rows = self._conn.execute(
                f"SELECT * FROM hints {where} ORDER BY priority DESC, rowid ASC LIMIT ?",
                params,
            ).fetchall()
            out: list[dict[str, Any]] = []
            for r in rows:
                d = dict(r)
                d["active"] = bool(d.get("active", 1))
                try:
                    d["payload"] = json.loads(d.get("payload_json") or "{}")
                except (json.JSONDecodeError, TypeError, ValueError):
                    d["payload"] = {}
                out.append(d)
            return out

        return list(self._run_with_retry(_query))

    # -- Async Wrappers --

    async def aadd_fact(self, *args: Any, **kwargs: Any) -> str:
        return await asyncio.to_thread(self.add_fact, *args, **kwargs)

    async def alist_facts(self, **kwargs: Any) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self.list_facts, **kwargs)

    async def aenqueue_intent(self, *args: Any, **kwargs: Any) -> str:
        return await asyncio.to_thread(self.enqueue_intent, *args, **kwargs)

    async def aclaim_intent(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.claim_intent, *args, **kwargs)

    async def acomplete_intent(self, *args: Any, **kwargs: Any) -> bool:
        return await asyncio.to_thread(self.complete_intent, *args, **kwargs)

    async def afail_intent(self, *args: Any, **kwargs: Any) -> bool:
        return await asyncio.to_thread(self.fail_intent, *args, **kwargs)

    async def arecover_stale_intents(self, **kwargs: Any) -> dict[str, Any]:
        return await asyncio.to_thread(self.recover_stale_intents, **kwargs)


# ---------------------------------------------------------------------------
# Top-Level Picklable Windows-Spawn-Safe ProcessPoolExecutor CPU Workers
# ---------------------------------------------------------------------------


def _coerce_probe_bytes(raw_probe: Any) -> bytes:
    if isinstance(raw_probe, bytes):
        return raw_probe
    if isinstance(raw_probe, bytearray):
        return bytes(raw_probe)
    if isinstance(raw_probe, list):
        return bytes(int(b) & 0xFF for b in raw_probe)
    if isinstance(raw_probe, str):
        return raw_probe.encode("latin-1", errors="replace")
    return b""


def _discover_formal_spec_files(repo_root: Path, max_files: int = 8) -> dict[str, list[Path]]:
    """Bounded discovery of OpenAPI / IAM / StateMachine spec files in a repo."""
    discovered: dict[str, list[Path]] = {"openapi": [], "iam": [], "state_machine": []}
    if not repo_root.is_dir():
        return discovered

    scanned = 0
    for cur_root, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [
            d for d in dirnames
            if d not in (".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build")
        ]
        for fn in filenames:
            scanned += 1
            if scanned > 400:
                return discovered
            low = fn.lower()
            if not low.endswith((".json", ".yaml", ".yml")):
                continue
            fpath = Path(cur_root) / fn
            if any(k in low for k in ("openapi", "swagger")) and len(discovered["openapi"]) < max_files:
                discovered["openapi"].append(fpath)
            elif any(k in low for k in ("iam", "policy")) and len(discovered["iam"]) < max_files:
                discovered["iam"].append(fpath)
            elif any(k in low for k in ("state_machine", "statemachine", "workflow_sm")) and len(discovered["state_machine"]) < max_files:
                discovered["state_machine"].append(fpath)
    return discovered


def _normalize_finding_dict(item: Any, *, default_engine: str = "stage1_cpu") -> dict[str, Any]:
    if hasattr(item, "to_dict") and callable(item.to_dict):
        d = dict(item.to_dict())
    elif isinstance(item, dict):
        d = dict(item)
    else:
        d = {"title": str(item)}
    meta = dict(d.get("metadata")) if isinstance(d.get("metadata"), dict) else {}
    d.setdefault("engine", default_engine)
    d.setdefault("rule_id", "")
    d.setdefault("title", "Stage 1 deterministic finding")
    d.setdefault("severity", "MEDIUM")
    d.setdefault("confidence", 0.7)
    d.setdefault("file_path", "")
    d.setdefault("line", 0)
    d.setdefault("summary", "")
    d.setdefault("deterministic", True)
    d.setdefault("confirmed", True)
    d["poc_verified"] = _coerce_strict_bool(d.get("poc_verified", False))
    d["metadata"] = meta
    if "non_production_noise" not in d:
        d["non_production_noise"] = bool(meta.get("non_production_noise", False))
    return d


def run_formal_and_differential_check(intent_payload: dict[str, Any]) -> dict[str, Any]:
    """
    Top-level Windows-spawn-picklable worker running Z3 formal verification,
    Lean 4 domain checks, and 4-parser differential matrix analysis.
    """
    t0 = time.monotonic()
    payload = dict(intent_payload or {})
    worker_pid = os.getpid()
    findings: list[dict[str, Any]] = []
    z3_report_dict: dict[str, Any] | None = None
    lean_checks: list[dict[str, Any]] = []
    differential_out: dict[str, Any] | None = None
    errors: list[str] = []

    openapi_spec = payload.get("openapi_spec")
    iam_policy = payload.get("iam_policy")
    state_machine = payload.get("state_machine")
    target_description = payload.get("target_description")
    target_name = str(payload.get("target_name") or payload.get("program") or "rfchunt_formal_target")
    max_steps = int(payload.get("max_steps", 8))
    timeout_ms = int(payload.get("timeout_ms", 5000))

    # 1. Z3 Formal Verification (call WITHOUT scope_policy/target_intent when scope_bridge is None)
    if any(x is not None for x in (openapi_spec, iam_policy, state_machine, target_description)):
        try:
            from engine.z3_formal_verifier import run_z3_formal_verification

            rep = run_z3_formal_verification(
                openapi_spec=openapi_spec,
                iam_policy=iam_policy,
                state_machine=state_machine,
                target_description=target_description,
                target_name=target_name,
                offline=True,
                max_steps=max_steps,
                timeout_ms=timeout_ms,
                scope_bridge=None,
                scope_policy=None,
                target_intent=None,
            )
            z3_report_dict = rep.to_dict()
            for ef in rep.to_engine_findings(include_proven=False):
                findings.append(_normalize_finding_dict(ef, default_engine="z3_formal"))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"z3_formal_verification: {exc}")

    # 2. Lean 4 Domain Checks (http_framing / policy_guard / dotnet_pe / evaluate_lean_domains)
    lean_dir = str(payload.get("lean_dir") or "formal/lean4")
    http_framing = payload.get("http_framing")
    policy_guard = payload.get("policy_guard")
    dotnet_pe = payload.get("dotnet_pe")
    lean_findings = payload.get("lean_findings")
    repo_path = payload.get("repo_path")

    if any(x is not None for x in (http_framing, policy_guard, dotnet_pe, lean_findings)):
        try:
            from engine.lean_formal_verifier import (
                evaluate_lean_domains,
                verify_dotnet_pe_invariant,
                verify_http_framing_invariant,
                verify_policy_guard_invariant,
            )

            counterexamples: list[Any] = []
            if isinstance(http_framing, dict):
                pv_raw = http_framing.get("proxy_verdict")
                pv = tuple(pv_raw) if isinstance(pv_raw, (list, tuple)) and len(pv_raw) == 2 else None
                counterexamples.extend(
                    verify_http_framing_invariant(
                        content_lengths=http_framing.get("content_lengths", ()),
                        has_transfer_encoding_chunked=bool(http_framing.get("has_transfer_encoding_chunked", False)),
                        has_bare_lf=bool(http_framing.get("has_bare_lf", False)),
                        proxy_verdict=pv,  # type: ignore[arg-type]
                        lean_dir=lean_dir,
                    )
                )
            if isinstance(policy_guard, dict):
                counterexamples.extend(
                    verify_policy_guard_invariant(
                        action=str(policy_guard.get("action", "networkProbe")),
                        scope=str(policy_guard.get("scope", "inScopeAuthorized")),
                        in_workspace_root=bool(policy_guard.get("in_workspace_root", True)),
                        allow_destructive=bool(policy_guard.get("allow_destructive", False)),
                        rules=policy_guard.get("rules", (("permit", True),)),
                        confirmed_by_tool=policy_guard.get("confirmed_by_tool"),
                        llm_confirmed=policy_guard.get("llm_confirmed"),
                        observed_allowed=policy_guard.get("observed_allowed"),
                        observed_reconciled=policy_guard.get("observed_reconciled"),
                        lean_dir=lean_dir,
                    )
                )
            if isinstance(dotnet_pe, dict):
                counterexamples.extend(
                    verify_dotnet_pe_invariant(
                        pe_report=dotnet_pe.get("pe_report"),
                        is_valid_pe=bool(dotnet_pe.get("is_valid_pe", True)),
                        has_clr_descriptor=bool(dotnet_pe.get("has_clr_descriptor", True)),
                        has_executable_image_bit=bool(dotnet_pe.get("has_executable_image_bit", True)),
                        is_umci_enforced=bool(dotnet_pe.get("is_umci_enforced", True)),
                        is_signed_by_trusted_publisher=bool(dotnet_pe.get("is_signed_by_trusted_publisher", False)),
                        lean_dir=lean_dir,
                    )
                )
            if lean_findings is not None:
                dom_rep = evaluate_lean_domains(
                    findings=lean_findings,
                    repo_path=repo_path,
                    lean_dir=lean_dir,
                )
                counterexamples.extend(dom_rep.counterexamples)

            for cx in counterexamples:
                cx_dict = cx.to_dict() if hasattr(cx, "to_dict") else dict(cx)
                lean_checks.append(cx_dict)
                if cx_dict.get("violated"):
                    findings.append(
                        _normalize_finding_dict(
                            {
                                "engine": "lean4",
                                "rule_id": f"LEAN4-{cx_dict.get('domain', 'formal').upper()}-{cx_dict.get('theorem', 'check')}",
                                "title": f"Lean 4 invariant counterexample: {cx_dict.get('theorem', '')}",
                                "severity": "HIGH",
                                "confidence": 0.95,
                                "summary": str(cx_dict.get("detail") or cx_dict.get("summary") or cx_dict),
                                "deterministic": True,
                                "confirmed": True,
                                "non_production_noise": False,
                                "metadata": {"lean_counterexample": cx_dict},
                            },
                            default_engine="lean4",
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"lean_formal_verifier: {exc}")

    # 3. 4-Parser Differential Matrix
    raw_probe = payload.get("raw_probe")
    if raw_probe is not None:
        try:
            from engine.differential_oracle import MultiImplementationDifferentialOracle

            probe_bytes = _coerce_probe_bytes(raw_probe)
            rule_id = payload.get("rule_id")
            oracle = MultiImplementationDifferentialOracle()
            is_divergent, anomaly, matrix = oracle.evaluate_matrix_4parsers(
                probe_bytes,
                rule_id=str(rule_id) if rule_id is not None else None,
            )
            anomaly_dict = anomaly.to_dict() if anomaly is not None else None
            differential_out = {
                "is_divergent": bool(is_divergent),
                "matrix": matrix,
                "anomaly": anomaly_dict,
            }
            if is_divergent and anomaly_dict is not None:
                findings.append(
                    _normalize_finding_dict(
                        {
                            "engine": "differential_oracle",
                            "rule_id": str(rule_id or "DIFF4-PARSER-DIVERGENCE"),
                            "title": "4-Parser HTTP Differential Divergence Detected",
                            "severity": "HIGH",
                            "confidence": 0.92,
                            "summary": str(anomaly_dict.get("observed_behavior", "")),
                            "deterministic": True,
                            "confirmed": True,
                            "non_production_noise": False,
                            "metadata": {"differential": differential_out},
                        },
                        default_engine="differential_oracle",
                    )
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"differential_oracle: {exc}")

    # 4. Deterministic CPU verification jitter/work if requested for multi-worker scheduling tests
    cpu_work_iters = int(payload.get("cpu_work_iters", 0) or 0)
    work_digest = ""
    if cpu_work_iters > 0:
        acc = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).digest()
        for _ in range(min(250_000, cpu_work_iters)):
            acc = hashlib.sha256(acc).digest()
        work_digest = acc.hex()[:16]

    elapsed_ms = round((time.monotonic() - t0) * 1000.0, 3)
    return {
        "ok": len(errors) == 0,
        "worker_pid": worker_pid,
        "findings": findings,
        "z3_report": z3_report_dict,
        "lean_checks": lean_checks,
        "differential": differential_out,
        "work_digest": work_digest,
        "errors": errors,
        "elapsed_ms": elapsed_ms,
    }


def run_stage1_cpu_check(intent_payload: dict[str, Any]) -> dict[str, Any]:
    """
    Top-level Windows-spawn-picklable Stage 1 worker (0 LLM calls).

    Lazily imports available M1 scanners (`parity_invariant_auditor`,
    `trufflehog_scanner`, `mobile_app_auditor`, `api_jwt_sdjwt_auditor`,
    `ai_infra_guard_auditor`) inside individual `ImportError` guards, runs
    deterministic REA/Z3/Lean/Differential checks where inputs exist, and drops
    test/fixture/docstring/lint noise deterministically.
    """
    t0 = time.monotonic()
    payload = dict(intent_payload or {})
    worker_pid = os.getpid()

    repo_path_str = str(payload.get("repo_path") or "").strip()
    target_files = [str(f) for f in (payload.get("target_files") or ()) if str(f).strip()]
    program = str(payload.get("program") or "")
    embedded = bool(payload.get("embedded", False))
    no_external_scanners = bool(payload.get("no_external_scanners", False))
    intent_type = str(payload.get("intent_type") or "").strip().lower()
    is_sibling_parity = (intent_type == "sibling_parity") or bool(payload.get("sibling_kind"))
    has_explicit_targets = bool(target_files)
    skip_repo_wide_walkers = bool(is_sibling_parity and has_explicit_targets)

    scanners_run: list[str] = []
    scanners_unavailable: list[str] = []
    raw_findings: list[dict[str, Any]] = []
    errors: list[str] = []

    # 1. Production Noise Filter (reconcile M1 parity_invariant_auditor + M2 fallback)
    try:
        from engine.parity_invariant_auditor import is_non_production_noise  # type: ignore
    except ImportError:
        is_non_production_noise = _fallback_is_non_production_noise

    # Filter target_files ahead of expensive checks when explicit file list provided
    dropped_files: list[str] = []
    active_target_files: list[str] = []
    for tf in target_files:
        if bool(is_non_production_noise(tf) or _fallback_is_non_production_noise(tf)):
            dropped_files.append(tf)
        else:
            active_target_files.append(tf)

    # Pre-seeded candidate findings passed in payload (e.g. from upstream diff/triage)
    for cf in payload.get("candidate_findings") or ():
        if isinstance(cf, dict):
            raw_findings.append(_normalize_finding_dict(cf, default_engine=str(cf.get("engine") or "stage1_candidate")))

    repo_root = Path(repo_path_str) if repo_path_str else None
    repo_exists = bool(repo_root is not None and repo_root.is_dir())

    if repo_exists and repo_root is not None:
        parity_targets = active_target_files if has_explicit_targets else None
        raw_allowed = payload.get("allowed_scanners")
        allowed_set: set[str] | None = (
            {str(s).strip().lower() for s in raw_allowed if str(s).strip()}
            if isinstance(raw_allowed, (list, tuple, set)) and raw_allowed
            else None
        )
        if allowed_set is None and bool(payload.get("use_surface_router", False)) and active_target_files:
            try:
                from engine.ml_diff_and_recon_ranker import SurfaceToScannerRouter

                routed = SurfaceToScannerRouter().route_scanners(
                    changed_files=active_target_files,
                    text_context=(
                        f"{payload.get('commit_message') or ''} "
                        f"{str(payload.get('diff_text') or '')[:500]}"
                    ).strip(),
                )
                rec_scanners = routed.get("recommended_scanners") if isinstance(routed, dict) else routed
                if rec_scanners:
                    allowed_set = {str(s).strip().lower() for s in rec_scanners if str(s).strip()}
            except Exception:  # noqa: BLE001
                allowed_set = None

        def _scanner_enabled(name: str) -> bool:
            return allowed_set is None or name.lower() in allowed_set

        # 2. M1 Parity & Invariant Auditor
        if _scanner_enabled("parity_auditor"):
            try:
                from engine.parity_invariant_auditor import audit_parity_and_invariants  # type: ignore

                scanners_run.append("parity_auditor")
                res = audit_parity_and_invariants(
                    repo_root,
                    target_files=parity_targets,
                )
                for item in res or ():
                    raw_findings.append(_normalize_finding_dict(item, default_engine="parity_auditor"))
            except ImportError:
                scanners_unavailable.append("parity_auditor")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"parity_auditor: {exc}")

        if not skip_repo_wide_walkers:
            # 3. M1 TruffleHog Secret Scanner (diff-scoped when parity_targets provided)
            if _scanner_enabled("trufflehog"):
                try:
                    from engine.trufflehog_scanner import scan_secrets_with_trufflehog  # type: ignore

                    scanners_run.append("trufflehog")
                    res = scan_secrets_with_trufflehog(
                        repo_root,
                        embedded=embedded,
                        no_external_scanners=no_external_scanners,
                        target_files=parity_targets,
                    )
                    for item in res or ():
                        raw_findings.append(_normalize_finding_dict(item, default_engine="trufflehog"))
                except ImportError:
                    scanners_unavailable.append("trufflehog")
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"trufflehog: {exc}")

            # 4. M1 Mobile App Auditor (diff-scoped when parity_targets provided)
            if _scanner_enabled("mobile_mobsf"):
                try:
                    from engine.mobile_app_auditor import audit_mobile_app  # type: ignore

                    scanners_run.append("mobile_mobsf")
                    res = audit_mobile_app(
                        repo_root,
                        embedded=embedded,
                        no_external_scanners=no_external_scanners,
                        target_files=parity_targets,
                    )
                    for item in res or ():
                        raw_findings.append(_normalize_finding_dict(item, default_engine="mobile_mobsf"))
                except ImportError:
                    scanners_unavailable.append("mobile_mobsf")
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"mobile_mobsf: {exc}")

            # 5. M1 API Surface & JWT/SD-JWT Auditor (always allow_live=False in Stage 1, diff-scoped)
            if _scanner_enabled("api_jwt_sdjwt"):
                try:
                    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt  # type: ignore

                    scanners_run.append("api_jwt_sdjwt")
                    res = audit_api_and_jwt(
                        repo_root,
                        program=program,
                        embedded=embedded,
                        no_external_scanners=no_external_scanners,
                        allow_live=False,
                        target_files=parity_targets,
                    )
                    for item in res or ():
                        raw_findings.append(_normalize_finding_dict(item, default_engine="api_jwt_sdjwt"))
                except ImportError:
                    scanners_unavailable.append("api_jwt_sdjwt")
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"api_jwt_sdjwt: {exc}")

            # 6. M1 AI-Infra-Guard & DeepAudit Auditor (diff-scoped when parity_targets provided)
            if _scanner_enabled("ai_infra_guard"):
                try:
                    from engine.ai_infra_guard_auditor import audit_ai_infra  # type: ignore

                    scanners_run.append("ai_infra_guard")
                    res = audit_ai_infra(repo_root, target_files=parity_targets)
                    for item in res or ():
                        raw_findings.append(_normalize_finding_dict(item, default_engine="ai_infra_guard"))
                except ImportError:
                    scanners_unavailable.append("ai_infra_guard")
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"ai_infra_guard: {exc}")

            # 7. Existing deterministic REA hook (only when JS/TS assets exist, write_reports=False)
            try:
                has_js_ts = _has_js_ts_assets(repo_root, active_target_files, max_files=80)
                if has_js_ts:
                    from engine.linux_poc_runner import run_rea_hook

                    scanners_run.append("rea")
                    rea_res = run_rea_hook(repo_root)
                    for item in rea_res.get("findings") or ():
                        raw_findings.append(_normalize_finding_dict(item, default_engine="rea"))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"rea: {exc}")

            # 8. Bounded Formal spec check if OpenAPI/IAM/StateMachine files exist in repo_root
            try:
                specs = _discover_formal_spec_files(repo_root, max_files=2)
                if specs["openapi"] or specs["iam"] or specs["state_machine"]:
                    scanners_run.append("z3_formal")
                    formal_sub = run_formal_and_differential_check(
                        {
                            "openapi_spec": str(specs["openapi"][0]) if specs["openapi"] else None,
                            "iam_policy": str(specs["iam"][0]) if specs["iam"] else None,
                            "state_machine": str(specs["state_machine"][0]) if specs["state_machine"] else None,
                            "target_name": program or repo_root.name,
                        }
                    )
                    raw_findings.extend(formal_sub.get("findings") or [])
            except Exception as exc:  # noqa: BLE001
                errors.append(f"z3_formal: {exc}")

    # 9. Also run formal/differential subcheck if explicit formal inputs were supplied
    if any(
        payload.get(k) is not None
        for k in ("openapi_spec", "iam_policy", "state_machine", "raw_probe", "http_framing", "policy_guard", "dotnet_pe")
    ):
        scanners_run.append("formal_differential")
        formal_res = run_formal_and_differential_check(payload)
        raw_findings.extend(formal_res.get("findings") or [])
        errors.extend(formal_res.get("errors") or [])

    # 10. Partition findings strictly into production vs noise
    production_findings: list[dict[str, Any]] = []
    noise_findings: list[dict[str, Any]] = []
    for f in raw_findings:
        meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
        fp_str = str(f.get("file_path", ""))
        rid_str = str(f.get("rule_id", ""))
        sum_str = str(f.get("summary", ""))
        is_noise = bool(f.get("non_production_noise", False)) or bool(
            is_non_production_noise(fp_str, meta, rule_id=rid_str, summary=sum_str)
            or _fallback_is_non_production_noise(fp_str, meta, rule_id=rid_str, summary=sum_str)
        )
        f["non_production_noise"] = is_noise
        meta["non_production_noise"] = is_noise
        f["metadata"] = meta
        if is_noise:
            noise_findings.append(f)
        else:
            production_findings.append(f)

    # Optional CPU digest for deterministic multi-worker verification
    cpu_work_iters = int(payload.get("cpu_work_iters", 0) or 0)
    if cpu_work_iters > 0:
        acc = hashlib.sha256(f"{worker_pid}:{repo_path_str}".encode()).digest()
        for _ in range(min(250_000, cpu_work_iters)):
            acc = hashlib.sha256(acc).digest()

    elapsed_ms = round((time.monotonic() - t0) * 1000.0, 3)
    return {
        "ok": len(errors) == 0,
        "worker_pid": worker_pid,
        "production_findings": production_findings,
        "noise_findings": noise_findings,
        "dropped_noise_count": len(noise_findings) + len(dropped_files),
        "dropped_files": dropped_files,
        "scanned_files": active_target_files,
        "scanners_run": scanners_run,
        "scanners_unavailable": scanners_unavailable,
        "errors": errors,
        "elapsed_ms": elapsed_ms,
    }


# ---------------------------------------------------------------------------
# Loop 2: Security-Fix Detection & Sibling Parity Propagation
# ---------------------------------------------------------------------------


def detect_security_fix_signal(commit_message: str, diff_text: str = "") -> list[str]:
    """
    Detect security-fix signals (`sanitize`, `o_nofollow`, `symlink`, `allowfrom`,
    `csp`, `ssrf`, `authz`, `verify`) in commit messages or diffs.
    """
    blob = f"{commit_message or ''}\n{diff_text or ''}".lower()
    matched: list[str] = []
    for kw in SECURITY_FIX_KEYWORDS:
        if kw == "csp":
            if re.search(r"\bcsp\b|content-security-policy", blob):
                matched.append(kw)
        elif kw == "ssrf":
            if re.search(r"\bssrf\b", blob):
                matched.append(kw)
        elif kw == "authz":
            if re.search(r"\bauthz\b|authorization", blob):
                matched.append(kw)
        elif kw in blob:
            matched.append(kw)
    return matched


def _discover_sibling_targets(
    repo_root: Path,
    changed_files: Sequence[str],
) -> dict[str, Any]:
    """Bounded discovery of sibling packages, sibling handlers, and sibling SDK languages."""
    norm_changed: list[str] = []
    for f in changed_files:
        clean = _sanitize_safe_rel_path(f, repo_root=repo_root)
        if clean is not None:
            norm_changed.append(clean)
    changed_set = set(norm_changed)

    sibling_packages: dict[str, list[str]] = {}
    sibling_handlers: list[str] = []
    sdk_dirs: dict[str, list[str]] = {}
    sdk_roots_by_lang: dict[str, set[str]] = {}

    if not norm_changed or not repo_root.is_dir():
        return {
            "norm_changed": norm_changed,
            "sibling_packages": sibling_packages,
            "sibling_handlers": sibling_handlers,
            "sdk_dirs": sdk_dirs,
            "sdk_languages": [],
        }

    resolved_root = repo_root.resolve()

    # 1. Sibling packages under common monorepo containers
    changed_pkg_roots: set[str] = set()
    for cf in norm_changed:
        parts = cf.split("/")
        if len(parts) >= 2 and parts[0].lower() in ("packages", "apps", "crates", "plugins", "external_plugins", "services"):
            changed_pkg_roots.add(f"{parts[0]}/{parts[1]}")

    for container in ("packages", "apps", "crates", "plugins", "external_plugins", "services"):
        cdir = repo_root / container
        if not cdir.is_dir():
            continue
        for child in sorted(cdir.iterdir()):
            if not child.is_dir():
                continue
            rel = f"{container}/{child.name}"
            if rel in changed_pkg_roots:
                continue
            files: list[str] = []
            for p in sorted(child.rglob("*")):
                if p.is_file():
                    try:
                        if not p.resolve().is_relative_to(resolved_root):
                            continue
                        rel_p = p.relative_to(repo_root).as_posix()
                    except (OSError, ValueError):
                        continue
                    if not _fallback_is_non_production_noise(rel_p):
                        files.append(rel_p)
                        if len(files) >= 12:
                            break
            if files:
                sibling_packages[rel] = files

    # 2. Sibling handlers in same directories or handler/route folders
    candidate_handler_dirs: set[Path] = set()
    for cf in norm_changed:
        cf_abs = repo_root / cf
        try:
            if not cf_abs.resolve().is_relative_to(resolved_root):
                continue
            parent = cf_abs.parent
            if not parent.resolve().is_relative_to(resolved_root):
                continue
        except (OSError, ValueError):
            continue
        if parent.is_dir():
            candidate_handler_dirs.add(parent)
    for extra_name in ("handlers", "routes", "api", "entrypoints", "src/handlers", "src/routes"):
        ed = repo_root / extra_name
        try:
            if ed.is_dir() and ed.resolve().is_relative_to(resolved_root):
                candidate_handler_dirs.add(ed)
        except (OSError, ValueError):
            continue

    for hdir in sorted(candidate_handler_dirs):
        for p in sorted(hdir.iterdir()):
            if not p.is_file():
                continue
            try:
                if not p.resolve().is_relative_to(resolved_root):
                    continue
                rel = p.relative_to(repo_root).as_posix()
            except (OSError, ValueError):
                continue
            if rel in changed_set:
                continue
            if _fallback_is_non_production_noise(rel):
                continue
            low = p.name.lower()
            if any(tok in low for tok in ("handler", "route", "controller", "endpoint", "middleware", "auth", "proxy")) or hdir.name.lower() in ("handlers", "routes", "api", "entrypoints"):
                sibling_handlers.append(rel)

    # 3. Sibling language SDKs across TS, Python, Go, Java, Ruby, Rust (on-disk only)
    sdk_search_roots = [repo_root]
    for sub in ("sdks", "sdk", "clients", "packages", "languages"):
        sd = repo_root / sub
        if sd.is_dir():
            sdk_search_roots.append(sd)

    for search_root in sdk_search_roots:
        for child in sorted(search_root.iterdir()):
            if not child.is_dir():
                continue
            try:
                if not child.resolve().is_relative_to(resolved_root):
                    continue
                rel_dir = child.relative_to(repo_root).as_posix()
            except (OSError, ValueError):
                continue
            cname = child.name.lower()
            for lang, aliases in _SDK_DIR_ALIASES.items():
                if cname in aliases or any(cname.startswith(f"{a}-") or cname.endswith(f"-{a}") for a in aliases):
                    files: list[str] = []
                    for p in sorted(child.rglob("*")):
                        if p.is_file():
                            try:
                                if not p.resolve().is_relative_to(resolved_root):
                                    continue
                                rel_p = p.relative_to(repo_root).as_posix()
                            except (OSError, ValueError):
                                continue
                            if not _fallback_is_non_production_noise(rel_p):
                                files.append(rel_p)
                                if len(files) >= 12:
                                    break
                    if files:
                        sdk_roots_by_lang.setdefault(lang, set()).add(rel_dir)
                        existing = sdk_dirs.setdefault(lang, [])
                        for fpath in files:
                            if fpath not in existing and len(existing) < 12:
                                existing.append(fpath)

    # Exclude originating single SDK if all changed_files came solely from it and another sibling SDK exists
    if len(sdk_dirs) > 1 and norm_changed:
        originating_langs = [
            lang
            for lang, roots in sdk_roots_by_lang.items()
            if all(any(cf == r or cf.startswith(f"{r}/") for r in roots) for cf in norm_changed)
        ]
        if len(originating_langs) == 1 and len(sdk_dirs) > 1:
            sdk_dirs.pop(originating_langs[0], None)

    discovered_langs = [lang for lang in SIBLING_SDK_LANGUAGES if sdk_dirs.get(lang)]

    return {
        "norm_changed": norm_changed,
        "sibling_packages": sibling_packages,
        "sibling_handlers": sorted(set(sibling_handlers)),
        "sdk_dirs": sdk_dirs,
        "sdk_languages": discovered_langs,
    }


def emit_sibling_parity_intents(
    blackboard: SqliteBlackboard,
    *,
    repo_path: str | Path,
    changed_files: Sequence[str],
    trigger_reason: str,
    parent_intent_id: str = "",
    depth: int = 0,
    max_depth: int = 2,
    max_intents: int = 24,
    task_id: str = "default",
    program: str = "",
    repo: str = "",
    lane: int = 2,
    priority: float = 0.75,
) -> list[str]:
    """
    Loop 2 Sibling Parity Fan-Out:
    Emits bounded `sibling_parity` `Intents` onto `SqliteBlackboard` across
    sibling packages, sibling handlers, and discovered on-disk sibling language
    SDKs (`TS`, `Python`, `Go`, `Java`, `Ruby`, `Rust`).
    """
    if int(depth) >= int(max_depth):
        return []
    if not changed_files:
        return []

    repo_root = Path(repo_path)
    discovered = _discover_sibling_targets(repo_root, changed_files)
    norm_changed: list[str] = list(discovered.get("norm_changed") or ())
    if not norm_changed:
        return []

    enqueued_ids: list[str] = []
    next_depth = int(depth) + 1
    repo_str = str(repo_root)
    discovered_sdk_langs: list[str] = list(discovered.get("sdk_languages") or ())

    trigger_sig = json.dumps(
        {
            "changed_files": sorted(norm_changed),
            "trigger_reason": str(trigger_reason or ""),
            "parent_intent_id": str(parent_intent_id or ""),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    trigger_digest = hashlib.sha256(trigger_sig.encode("utf-8")).hexdigest()[:16]

    def _emit_one(scope_label: str, sibling_kind: str, files: Sequence[str], sdk_lang: str = "") -> None:
        if len(enqueued_ids) >= max_intents:
            return
        dedup = hashlib.sha256(
            f"{task_id}:{repo_str}:{sibling_kind}:{scope_label}:{next_depth}:{trigger_digest}".encode()
        ).hexdigest()[:24]
        iid = blackboard.enqueue_intent(
            "sibling_parity",
            {
                "repo_path": repo_str,
                "changed_files": list(norm_changed),
                "target_files": list(files),
                "sibling_kind": sibling_kind,
                "scope_label": scope_label,
                "sdk_language": sdk_lang,
                "sibling_sdk_languages": list(discovered_sdk_langs),
                "trigger_reason": trigger_reason,
                "parent_intent_id": parent_intent_id,
                "depth": next_depth,
                "program": program,
            },
            task_id=task_id,
            program=program,
            repo=repo,
            lane=lane,
            priority=priority,
            dedup_key=f"sibling_parity:{dedup}",
        )
        if iid not in enqueued_ids:
            enqueued_ids.append(iid)

    for pkg_name, pkg_files in sorted(discovered["sibling_packages"].items()):
        _emit_one(pkg_name, "package", pkg_files)

    sibling_handlers = discovered["sibling_handlers"]
    if len(sibling_handlers) == 1:
        _emit_one("sibling_handlers", "handler", sibling_handlers)
    else:
        for handler_file in sibling_handlers:
            _emit_one(f"sibling_handler:{handler_file}", "handler", [handler_file])

    # Fan out strictly across on-disk discovered sibling SDKs
    sdk_dirs: dict[str, list[str]] = discovered["sdk_dirs"]
    for lang in discovered_sdk_langs:
        lang_files = sdk_dirs.get(lang, [])
        if lang_files:
            _emit_one(f"sdk_{lang}", "sdk", lang_files, sdk_lang=lang)

    return enqueued_ids


# ---------------------------------------------------------------------------
# Loop 5: Two-Lane Self-Adapting Queue & Auto-Unlock Draft Staging
# ---------------------------------------------------------------------------


class TwoLaneBountyQueue:
    """
    Loop 5 Two-Lane Self-Adapting Bounty Queue backed by `TwoLanePolicyScheduler`,
    `ProgramEligibilityDB`, and `SqliteBlackboard`.
    """

    LANE1_DEFAULT_PROGRAMS: tuple[str, ...] = LANE1_DEFAULT_PROGRAMS
    LANE2_DEFAULT_PROGRAMS: tuple[str, ...] = LANE2_DEFAULT_PROGRAMS

    def __init__(
        self,
        eligibility_db: Any,
        blackboard: SqliteBlackboard,
        *,
        lane1_programs: Sequence[str] = LANE1_DEFAULT_PROGRAMS,
        lane2_programs: Sequence[str] = LANE2_DEFAULT_PROGRAMS,
        signal_score: float = 0.0,
        signal_threshold: float = 1.0,
    ) -> None:
        from engine.acdso_bridge import TwoLanePolicyScheduler

        self.eligibility_db = eligibility_db
        self.blackboard = blackboard
        self.lane1_programs = tuple(lane1_programs)
        self.lane2_programs = tuple(lane2_programs)
        self.signal_score = float(signal_score)
        self.scheduler = TwoLanePolicyScheduler(
            lane1_programs=self.lane1_programs,
            lane2_programs=self.lane2_programs,
            signal_threshold=signal_threshold,
        )

    def plan_cycle(
        self,
        *,
        queue_capacity: int = 10,
        signal_score: float | None = None,
        program_repos: dict[str, Sequence[str]] | None = None,
        task_id: str = "default",
        lane1_reward_history: Sequence[float] | None = None,
        lane2_reward_history: Sequence[float] | None = None,
        cycle_id: str = "cycle_0",
    ) -> dict[str, Any]:
        eff_signal = self.signal_score if signal_score is None else float(signal_score)
        alloc = self.scheduler.allocate_slots(
            queue_capacity,
            signal_score=eff_signal,
            lane1_reward_history=lane1_reward_history,
            lane2_reward_history=lane2_reward_history,
        )

        # Fail-closed eligibility filtering + dynamic DB repo hydration
        unlocked_records = list(self.eligibility_db.list_unlocked())
        unlocked_by_handle = {r.handle: r for r in unlocked_records}

        eligible_l1 = [p for p in self.lane1_programs if self.eligibility_db.is_eligible(p)]
        eligible_l2: list[str] = [p for p in self.lane2_programs if self.eligibility_db.is_eligible(p)]
        try:
            from engine.ml_program_selector import (
                classify_program_lane as _classify_lane,
            )
        except Exception:  # noqa: BLE001
            _classify_lane = None  # type: ignore[assignment]

        for rec in unlocked_records:
            h = rec.handle
            if h in eligible_l1 or h in eligible_l2:
                continue
            lane_label = _classify_lane(rec)[0] if _classify_lane is not None else "LANE_2_BBP_HIGH_EV"
            if lane_label == "LANE_1_VDP_FAST_SIGNAL" and h in self.lane1_programs:
                eligible_l1.append(h)
            elif h not in self.lane1_programs:
                eligible_l2.append(h)

        l1_queued: list[str] = []
        l2_queued: list[str] = []
        queued_intent_ids: list[str] = []
        repos_map = program_repos or {}

        def _repos_for(prog_handle: str) -> list[str]:
            if prog_handle in repos_map:
                return list(repos_map[prog_handle])
            rec = unlocked_by_handle.get(prog_handle)
            if rec is not None and getattr(rec, "in_scope_repos", None):
                return list(rec.in_scope_repos)
            return list(_DEFAULT_UNLOCK_REPOS.get(prog_handle, ()))

        if eligible_l1 and alloc["lane1_slots"] > 0:
            for slot_idx in range(alloc["lane1_slots"]):
                prog = eligible_l1[slot_idx % len(eligible_l1)]
                repo_list = _repos_for(prog)
                iid = self.blackboard.enqueue_intent(
                    "vdp_signal_lift",
                    {
                        "program": prog,
                        "lane": 1,
                        "repos": repo_list,
                        "signal_score": eff_signal,
                    },
                    task_id=task_id,
                    program=prog,
                    repo=repo_list[0] if repo_list else "",
                    lane=1,
                    priority=1.0,
                    dedup_key=f"loop5:{cycle_id}:lane1:{prog}:{slot_idx}",
                )
                l1_queued.append(prog)
                queued_intent_ids.append(iid)

        if eligible_l2 and alloc["lane2_slots"] > 0:
            for slot_idx in range(alloc["lane2_slots"]):
                prog = eligible_l2[slot_idx % len(eligible_l2)]
                repo_list = _repos_for(prog)
                iid = self.blackboard.enqueue_intent(
                    "diff_scan",
                    {
                        "program": prog,
                        "lane": 2,
                        "repos": repo_list,
                        "signal_score": eff_signal,
                    },
                    task_id=task_id,
                    program=prog,
                    repo=repo_list[0] if repo_list else "",
                    lane=2,
                    priority=0.8,
                    dedup_key=f"loop5:{cycle_id}:lane2:{prog}:{slot_idx}",
                )
                l2_queued.append(prog)
                queued_intent_ids.append(iid)

        return {
            **alloc,
            "eligible_lane1": eligible_l1,
            "eligible_lane2": eligible_l2,
            "lane1_programs_queued": l1_queued,
            "lane2_programs_queued": l2_queued,
            "queued_intent_ids": queued_intent_ids,
        }


def _infer_program_from_draft(raw: dict[str, Any], file_path: Path) -> str:
    for key in ("program_handle", "program", "handle"):
        val = str(raw.get(key) or "").strip().lower()
        if val:
            return val
    blob = " ".join(
        [
            str(raw.get("asset", "")),
            str(raw.get("asset_identifier", "")),
            str(raw.get("package", "")),
            str(raw.get("repo", "")),
            str(raw.get("submit_url", "")),
            file_path.name,
        ]
    ).lower()
    if "shopify" in blob:
        return "shopify"
    if "vercel" in blob or "next.js" in blob:
        return "vercel"
    if "cloudflare" in blob or "pingora" in blob:
        return "cloudflare"
    if "anthropic" in blob:
        return "anthropic"
    return ""


def _is_draft_poc_verified(raw: dict[str, Any]) -> bool:
    if "poc_verified" in raw:
        return _coerce_strict_bool(raw.get("poc_verified"))
    lane = str(raw.get("evidence_lane", "")).strip().upper()
    try:
        poe_level = int(raw.get("poe_level", 0) or 0)
    except (TypeError, ValueError):
        poe_level = 0
    return lane == "VERIFIED_EXPLOIT" and poe_level >= 3


def _scrub_draft_text(text: Any) -> str:
    raw = str(text or "")
    if not raw:
        return ""
    try:
        from engine.advisory_exporter import _redact_inline_tokens

        raw = _redact_inline_tokens(raw)
    except ImportError:
        pass
    try:
        from engine.hackerone_porter import _scrub_secrets_and_phi

        raw = _scrub_secrets_and_phi(raw)
    except ImportError:
        pass
    return raw


def sync_eligibility_and_stage_unlocks(
    eligibility_db: Any,
    blackboard: SqliteBlackboard | None = None,
    drafts_dir: str | Path = Path("reports/ensemble_hunt"),
    *,
    previously_unlocked: Iterable[str] | None = None,
    program_repos: dict[str, Sequence[str]] | None = None,
    out_dir: str | Path | None = None,
    task_id: str = "default",
) -> dict[str, Any]:
    """
    Loop 5 Auto-Unlock Watcher:
    1. Reads `ProgramEligibilityDB.list_unlocked()` and detects newly unlocked programs
       (e.g., `shopify`, `vercel`, `cloudflare`).
    2. Queues newly unlocked programs onto `SqliteBlackboard` (`lane=2`).
    3. Discovers saved verified drafts (`poc_verified == True`, starting with
       `@shopify/shopify-app-remix`) and stages them fail-closed when BOTH
       `eligibility_db.is_eligible(program)` AND `poc_verified == True` hold.
    """
    unlocked_records = eligibility_db.list_unlocked()
    current_unlocked = {r.handle.strip().lower() for r in unlocked_records if getattr(r, "handle", "")}

    prev_set: set[str] | None = None
    if previously_unlocked is not None:
        prev_set = {str(h).strip().lower() for h in previously_unlocked if str(h).strip()}
    elif blackboard is not None:
        hints = blackboard.list_hints(task_id=task_id, domain="eligibility_unlock_state", limit=10)
        if hints:
            prev_list = hints[-1].get("payload", {}).get("unlocked_handles", [])
            if isinstance(prev_list, list):
                prev_set = {str(h).strip().lower() for h in prev_list}

    if prev_set is None:
        # First observation without prior state: treat non-baseline high-signal targets as newly unlocked if present
        newly_unlocked = sorted(
            h for h in current_unlocked
            if h not in set(LANE1_DEFAULT_PROGRAMS) - {"common_codes"}
        )
    else:
        newly_unlocked = sorted(current_unlocked - prev_set)

    queued_intents: list[str] = []
    repos_map = program_repos or {}
    if blackboard is not None:
        for handle in newly_unlocked:
            repos = list(repos_map.get(handle, _DEFAULT_UNLOCK_REPOS.get(handle, ())))
            if not repos:
                repos = [handle]
            for repo_slug in repos:
                iid = blackboard.enqueue_intent(
                    "diff_scan",
                    {
                        "program": handle,
                        "repo": repo_slug,
                        "trigger": "program_unlocked",
                    },
                    task_id=task_id,
                    program=handle,
                    repo=repo_slug,
                    lane=2,
                    priority=0.95,
                    dedup_key=f"unlock:{handle}:{repo_slug}",
                )
                queued_intents.append(iid)
        blackboard.add_hint(
            f"Tracked {len(current_unlocked)} unlocked programs",
            task_id=task_id,
            domain="eligibility_unlock_state",
            source="sync_eligibility_and_stage_unlocks",
            payload={"unlocked_handles": sorted(current_unlocked)},
            hint_id=f"unlock_state_{task_id}",
        )

    # Scan saved draft JSON files
    draft_search_dirs: list[Path] = []
    primary_drafts = Path(drafts_dir)
    if primary_drafts.exists():
        draft_search_dirs.append(primary_drafts)
    default_h1_dir = Path("reports/hackerone")
    if primary_drafts == Path("reports/ensemble_hunt") and default_h1_dir.exists():
        draft_search_dirs.append(default_h1_dir)

    candidate_files: list[Path] = []
    for ddir in draft_search_dirs:
        if ddir.is_file() and ddir.suffix.lower() == ".json":
            candidate_files.append(ddir)
        elif ddir.is_dir():
            for p in sorted(ddir.rglob("*.json")):
                if p.name in ("READY_TO_SUBMIT.json", "submission_ledger.json", "staged_unlock_drafts.json"):
                    continue
                candidate_files.append(p)

    staged_drafts: list[dict[str, Any]] = []
    blocked_drafts: list[dict[str, Any]] = []
    eff_out_dir = Path(out_dir) if out_dir is not None else (primary_drafts if primary_drafts.is_dir() else primary_drafts.parent)

    for jf in candidate_files:
        try:
            raw_obj = json.loads(jf.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001, S112
            continue

        entries = raw_obj if isinstance(raw_obj, list) else (
            raw_obj.get("drafts", [raw_obj]) if isinstance(raw_obj, dict) else []
        )
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            # Must look like a draft record
            if not any(k in entry for k in ("title", "asset", "asset_identifier", "package", "vulnerability_information", "program_handle", "program")):
                continue

            prog = _infer_program_from_draft(entry, jf)
            poc_ok = _is_draft_poc_verified(entry)
            eligible_ok = bool(prog and eligibility_db.is_eligible(prog))
            asset_val = _scrub_draft_text(
                entry.get("asset") or entry.get("asset_identifier") or entry.get("package") or ""
            )
            pkg_val = _scrub_draft_text(entry.get("package") or asset_val)
            title_val = _scrub_draft_text(entry.get("title") or asset_val or jf.stem)
            summary_val = _scrub_draft_text(
                entry.get("summary") or entry.get("vulnerability_information") or ""
            )
            desc_val = _scrub_draft_text(entry.get("description") or "")
            impact_val = _scrub_draft_text(entry.get("impact") or "")
            poc_val = _scrub_draft_text(entry.get("poc") or entry.get("poc_transcript") or "")

            tm_passed = True
            tm_reasons: list[str] = []
            if prog and eligible_ok and poc_ok:
                try:
                    from engine.ensemble_orchestrator import (
                        evaluate_vendor_threat_model,
                    )

                    tm_verdict = evaluate_vendor_threat_model(
                        title=title_val,
                        summary=summary_val or desc_val or impact_val or title_val,
                        file_path=asset_val,
                        program=prog,
                        poc_verified=poc_ok,
                        poc_target_os=str(entry.get("poc_target_os") or ""),
                        target_os_required=str(entry.get("target_os_required") or ""),
                    )
                    tm_passed = bool(tm_verdict.passed)
                    tm_reasons = list(tm_verdict.reasons)
                except ImportError:
                    pass

            if not eligible_ok or not poc_ok or not tm_passed:
                reasons: list[str] = []
                if not prog:
                    reasons.append("missing_program_handle")
                elif not eligible_ok:
                    reasons.append(f"program_not_unlocked:{prog}")
                if not poc_ok:
                    reasons.append("poc_verified_false")
                if not tm_passed:
                    reasons.append("blocked_threat_model")
                    reasons.extend(tm_reasons)
                blocked_drafts.append(
                    {
                        "program_handle": prog,
                        "asset": asset_val,
                        "title": title_val,
                        "source_file": str(jf),
                        "reasons": reasons,
                    }
                )
                continue

            report_id = str(entry.get("report_id") or entry.get("hackerone_report_id") or "").strip()
            submit_url = _scrub_draft_text(
                entry.get("submit_url")
                or f"https://hackerone.com/{prog}/reports/new?type=team&report_type=vulnerability"
            )
            draft_url = _scrub_draft_text(
                entry.get("draft_url")
                or (f"https://hackerone.com/reports/{report_id}" if report_id else submit_url)
            )
            browser_spec = {
                "platform": "hackerone",
                "program_handle": prog,
                "action": "stage_draft",
                "target_url": draft_url,
                "staged_draft_path": str(jf),
                "hitl_invariants": [
                    "Never bypass CAPTCHA/Turnstile or login gates.",
                    "Verify `poc_verified == true` before submitting.",
                ],
            }
            staged_item: dict[str, Any] = {
                "status": "staged_ready",
                "program_handle": prog,
                "asset": asset_val,
                "package": pkg_val,
                "title": title_val,
                "severity_rating": str(entry.get("severity_rating") or entry.get("severity") or "High"),
                "weakness_cwe": str(entry.get("weakness_cwe") or entry.get("cwe") or ""),
                "poc_verified": True,
                "eligible": True,
                "report_id": report_id or None,
                "submit_url": submit_url,
                "draft_url": draft_url,
                "source_file": str(jf),
                "browser_handoff": browser_spec,
            }
            if summary_val:
                staged_item["summary"] = summary_val
            if desc_val:
                staged_item["description"] = desc_val
            if impact_val:
                staged_item["impact"] = impact_val
            if poc_val:
                staged_item["poc"] = poc_val
            staged_drafts.append(staged_item)

            if blackboard is not None:
                draft_id_key = str(report_id or jf)
                det_fact_hash = hashlib.sha256(
                    f"{task_id}:{prog}:{draft_id_key}:{pkg_val}".encode()
                ).hexdigest()[:16]
                det_fact_id = f"fact_unlock_{det_fact_hash}"
                existing_fact_ids = {
                    str(f.get("fact_id", ""))
                    for f in blackboard.list_facts(task_id=task_id, domain="loop5_unlock_stage", limit=500)
                }
                if det_fact_id not in existing_fact_ids:
                    blackboard.add_fact(
                        f"Auto-staged verified draft for unlocked program {prog}: {title_val}",
                        task_id=task_id,
                        program=prog,
                        domain="loop5_unlock_stage",
                        file_path=str(jf),
                        severity=str(staged_item["severity_rating"]).upper(),
                        confidence=0.95,
                        poc_verified=True,
                        source_engine="loop5_auto_unlock",
                        payload=staged_item,
                        fact_id=det_fact_id,
                    )

    if staged_drafts:
        eff_out_dir.mkdir(parents=True, exist_ok=True)
        ready_path = eff_out_dir / "READY_TO_SUBMIT.json"
        ready_payload = {
            "generated_at": _utc_iso(),
            "status": "READY_TO_SUBMIT",
            "staged_count": len(staged_drafts),
            "drafts": staged_drafts,
            "primary_url": staged_drafts[0]["draft_url"],
        }
        ready_path.write_text(json.dumps(ready_payload, indent=2), encoding="utf-8")

    return {
        "unlocked_programs": sorted(current_unlocked),
        "newly_unlocked": newly_unlocked,
        "queued_intents": queued_intents,
        "staged_drafts": staged_drafts,
        "blocked_drafts": blocked_drafts,
    }


# ---------------------------------------------------------------------------
# Main Async Blackboard + ProcessPoolExecutor Entrypoint
# ---------------------------------------------------------------------------


async def run_local_rfchunt_async(
    seed_intents: Sequence[dict[str, Any]] | None = None,
    *,
    repo_path: str | Path = ".",
    db_path: str | Path = "reports/ensemble_hunt/blackboard.sqlite3",
    max_cpu_workers: int | None = None,
    max_net_concurrency: int = 16,
    resume: bool = False,
    signal_score: float = 0.0,
    eligibility_db_path: str | Path | None = None,
    ollama_evaluator: Callable[..., Any] | None = None,
    remote_dispatcher: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """
    Crash-recoverable Async SQLite WAL Blackboard + Windows-spawn-safe
    `ProcessPoolExecutor` runtime unifying Loop 2, Loop 5, Stage 1 CPU triage,
    Stage 2 ACDSO Pareto/anomaly ranking, and single-slot Stage 3 evaluation.
    """
    t0 = time.monotonic()
    eff_workers = default_cpu_workers(max_cpu_workers)
    eff_net = max(1, int(max_net_concurrency))
    net_sem = asyncio.Semaphore(eff_net)
    stage3_sem = asyncio.Semaphore(1)

    blackboard = SqliteBlackboard(db_path)
    try:
        recovery_summary: dict[str, Any] = {
            "recovered_to_pending": 0,
            "exhausted_to_failed": 0,
            "intent_ids": [],
            "failed_ids": [],
        }
        if resume:
            recovery_summary = await blackboard.arecover_stale_intents(force_all_in_progress=True)

        # Enqueue seed intents (or a default repo scan if none exist and not resuming existing queue)
        if seed_intents:
            for idx, seed in enumerate(seed_intents):
                s = dict(seed)
                itype = str(s.get("intent_type") or "stage1_cpu")
                payload = dict(s.get("payload") if isinstance(s.get("payload"), dict) else s)
                payload.setdefault("repo_path", str(repo_path))
                await blackboard.aenqueue_intent(
                    itype,
                    payload,
                    task_id=str(s.get("task_id") or "default"),
                    program=str(s.get("program") or payload.get("program") or ""),
                    repo=str(s.get("repo") or payload.get("repo") or ""),
                    lane=int(s.get("lane", 2)),
                    priority=float(s.get("priority", 0.5)),
                    max_retries=int(s.get("max_retries", 3)),
                    dedup_key=s.get("dedup_key"),
                )
        elif not resume and not blackboard.list_intents(status="PENDING", limit=1):
            await blackboard.aenqueue_intent(
                "stage1_cpu",
                {"repo_path": str(repo_path)},
                lane=2,
                priority=0.5,
                dedup_key=f"seed_repo:{Path(repo_path).resolve()}",
            )

        # Loop 5 lane scheduling allocation
        from engine.acdso_bridge import TwoLanePolicyScheduler, rank_stage2_candidates

        scheduler = TwoLanePolicyScheduler()
        lane_allocation = scheduler.allocate_slots(10, signal_score=float(signal_score))

        eligibility_sync: dict[str, Any] | None = None
        if eligibility_db_path is not None:
            try:
                from engine.program_eligibility_db import ProgramEligibilityDB

                elig_db = ProgramEligibilityDB(eligibility_db_path)
                tlq = TwoLaneBountyQueue(elig_db, blackboard, signal_score=float(signal_score))
                drafts_root = Path(repo_path) / "reports" / "ensemble_hunt"
                sync_bb = None if seed_intents else blackboard
                eligibility_sync = await asyncio.to_thread(
                    sync_eligibility_and_stage_unlocks,
                    elig_db,
                    sync_bb,
                    drafts_root,
                    out_dir=Path(db_path).parent if str(db_path) != ":memory:" else drafts_root,
                )
                if not seed_intents and not resume:
                    eligibility_sync["lane_plan"] = tlq.plan_cycle(
                        queue_capacity=10,
                        signal_score=float(signal_score),
                    )
            except Exception as exc:  # noqa: BLE001
                eligibility_sync = {"error": str(exc)}

        worker_pids: set[int] = set()
        stage1_production_findings: list[dict[str, Any]] = []
        stage1_noise_count = 0
        intents_completed = 0
        intents_failed = 0
        loop2_emitted: list[str] = []
        state_lock = asyncio.Lock()
        work_cond = asyncio.Condition()
        in_flight_workers = 0
        loop = asyncio.get_running_loop()
        mp_ctx = multiprocessing.get_context("spawn")

        async def _worker_loop(worker_idx: int, pool: ProcessPoolExecutor) -> None:
            nonlocal stage1_noise_count, intents_completed, intents_failed, in_flight_workers
            worker_id = f"spawn_worker_{worker_idx}"
            while True:
                # Honor Lane 1 priority when signal_score < 1.0, otherwise pick highest priority across lanes
                preferred_lane = 1 if float(signal_score) < 1.0 else None
                async with work_cond:
                    intent = await blackboard.aclaim_intent(worker_id, lane=preferred_lane)
                    if intent is None and preferred_lane is not None:
                        intent = await blackboard.aclaim_intent(worker_id, lane=None)
                    if intent is None:
                        if in_flight_workers == 0:
                            work_cond.notify_all()
                            break
                        try:
                            await asyncio.wait_for(work_cond.wait(), timeout=0.05)
                        except TimeoutError:
                            pass
                        continue
                    in_flight_workers += 1

                iid = str(intent["intent_id"])
                itype = str(intent["intent_type"])
                payload = dict(intent.get("payload") or {})
                task_id = str(intent.get("task_id") or "default")
                program = str(intent.get("program") or payload.get("program") or "")
                repo = str(intent.get("repo") or payload.get("repo") or "")

                try:
                    has_local_repo = bool(str(payload.get("repo_path") or "").strip())
                    has_inline_work = bool(payload.get("candidate_findings")) or any(
                        payload.get(k) is not None
                        for k in (
                            "openapi_spec",
                            "iam_policy",
                            "state_machine",
                            "target_description",
                            "raw_probe",
                            "http_framing",
                            "policy_guard",
                            "dotnet_pe",
                            "lean_findings",
                        )
                    )
                    if itype in ("diff_scan", "vdp_signal_lift", "unlock_queued") and not has_local_repo and not has_inline_work:
                        if remote_dispatcher is not None and (repo or payload.get("repos")):
                            async with net_sem:
                                if inspect.iscoroutinefunction(remote_dispatcher):
                                    disp_out = await remote_dispatcher(intent)
                                else:
                                    disp_out = await asyncio.to_thread(remote_dispatcher, intent)
                                    if inspect.isawaitable(disp_out):
                                        disp_out = await disp_out
                            disp_dict = disp_out if isinstance(disp_out, dict) else {"result": disp_out}
                            remote_findings = [
                                _normalize_finding_dict(f, default_engine=str(f.get("engine") or itype))
                                for f in (disp_dict.get("findings") or disp_dict.get("production_findings") or ())
                                if isinstance(f, dict)
                            ]
                            if remote_findings:
                                async with state_lock:
                                    stage1_production_findings.extend(remote_findings)
                                for item in remote_findings:
                                    await blackboard.aadd_fact(
                                        str(item.get("title") or "Remote dispatched finding"),
                                        task_id=task_id,
                                        program=program,
                                        repo=repo,
                                        domain=str(item.get("engine") or itype),
                                        file_path=str(item.get("file_path") or ""),
                                        line=int(item.get("line") or 0),
                                        severity=str(item.get("severity") or "MEDIUM"),
                                        confidence=float(item.get("confidence", 0.7)),
                                        poc_verified=_coerce_strict_bool(item.get("poc_verified", False)),
                                        source_engine=str(item.get("engine") or itype),
                                        payload=item,
                                        parent_intent_id=iid,
                                    )
                            res = {
                                "ok": True,
                                "status": str(disp_dict.get("status") or "dispatched_remote"),
                                "intent_type": itype,
                                "program": program,
                                "repo": repo,
                                "worker_pid": 0,
                                "remote_findings_count": len(remote_findings),
                            }
                        else:
                            res = {
                                "ok": True,
                                "status": "queued_remote" if (repo or payload.get("repos")) else "skipped_no_local_repo",
                                "intent_type": itype,
                                "program": program,
                                "repo": repo,
                                "worker_pid": 0,
                            }
                        await blackboard.acomplete_intent(iid, res)
                        async with state_lock:
                            intents_completed += 1
                    else:
                        if itype in ("formal_check", "formal_and_differential", "differential_check"):
                            res = await loop.run_in_executor(pool, run_formal_and_differential_check, payload)
                            prod_items = list(res.get("findings") or [])
                        else:
                            worker_payload = {**payload, "intent_type": itype}
                            res = await loop.run_in_executor(pool, run_stage1_cpu_check, worker_payload)
                            prod_items = list(res.get("production_findings") or [])

                        pid = int(res.get("worker_pid", 0) or 0)
                        async with state_lock:
                            if pid > 0:
                                worker_pids.add(pid)
                            stage1_noise_count += int(res.get("dropped_noise_count", 0) or 0)
                            stage1_production_findings.extend(prod_items)

                        # Persist facts onto Blackboard
                        landed_fact = False
                        for item in prod_items:
                            await blackboard.aadd_fact(
                                str(item.get("title") or "Verified finding"),
                                task_id=task_id,
                                program=program,
                                repo=repo,
                                domain=str(item.get("engine") or itype),
                                file_path=str(item.get("file_path") or ""),
                                line=int(item.get("line") or 0),
                                severity=str(item.get("severity") or "MEDIUM"),
                                confidence=float(item.get("confidence", 0.7)),
                                poc_verified=_coerce_strict_bool(item.get("poc_verified", False)),
                                source_engine=str(item.get("engine") or itype),
                                payload=item,
                                parent_intent_id=iid,
                            )
                            landed_fact = True

                        # Loop 2: Security-fix keyword OR landed Fact triggers sibling parity propagation
                        sig_kws = detect_security_fix_signal(
                            str(payload.get("commit_message") or ""),
                            str(payload.get("diff_text") or ""),
                        )
                        cur_depth = int(payload.get("depth", 0) or 0)
                        max_depth = int(payload.get("max_depth", 2) or 2)
                        enable_loop2 = bool(payload.get("propagate_siblings", True))
                        if enable_loop2 and cur_depth < max_depth and (sig_kws or landed_fact):
                            eff_repo = str(payload.get("repo_path") or repo_path)
                            eff_changed = list(payload.get("changed_files") or payload.get("target_files") or ())
                            if not eff_changed and prod_items:
                                eff_changed = [
                                    str(f.get("file_path"))
                                    for f in prod_items
                                    if str(f.get("file_path") or "").strip()
                                ]
                            if eff_changed:
                                reason = f"security_fix:{','.join(sig_kws)}" if sig_kws else "landed_fact"
                                emitted = await asyncio.to_thread(
                                    emit_sibling_parity_intents,
                                    blackboard,
                                    repo_path=eff_repo,
                                    changed_files=eff_changed,
                                    trigger_reason=reason,
                                    parent_intent_id=iid,
                                    depth=cur_depth,
                                    max_depth=max_depth,
                                    task_id=task_id,
                                    program=program,
                                    repo=repo,
                                    lane=2,
                                )
                                async with state_lock:
                                    loop2_emitted.extend(emitted)
                                if emitted:
                                    async with work_cond:
                                        work_cond.notify_all()

                        await blackboard.acomplete_intent(iid, res)
                        async with state_lock:
                            intents_completed += 1
                except Exception as exc:  # noqa: BLE001
                    await blackboard.afail_intent(iid, str(exc))
                    async with state_lock:
                        intents_failed += 1
                finally:
                    async with work_cond:
                        in_flight_workers -= 1
                        work_cond.notify_all()

        with ProcessPoolExecutor(max_workers=eff_workers, mp_context=mp_ctx) as pool:
            await asyncio.gather(*[_worker_loop(idx, pool) for idx in range(eff_workers)])

        # Stage 2 ACDSO ranking (< 1s)
        stage2_result = rank_stage2_candidates(stage1_production_findings, top_k=5)
        stage2_selected = list(stage2_result.get("selected") or [])

        # Stage 3 Single-Slot LLM evaluation (bounded by both max_net_concurrency and stage3_sem=1)
        stage3_results: list[dict[str, Any]] = []
        if ollama_evaluator is not None and stage2_selected:
            async def _eval_one(cand: dict[str, Any]) -> dict[str, Any]:
                async with net_sem, stage3_sem:
                    if inspect.iscoroutinefunction(ollama_evaluator):
                        out = await ollama_evaluator(cand)
                    else:
                        out = await asyncio.to_thread(ollama_evaluator, cand)
                        if inspect.isawaitable(out):
                            out = await out
                    return out if isinstance(out, dict) else {"result": out}

            stage3_results = list(
                await asyncio.gather(*[_eval_one(c) for c in stage2_selected])
            )

        all_facts = await blackboard.alist_facts(limit=500)
        elapsed_ms = round((time.monotonic() - t0) * 1000.0, 3)
        return {
            "status": "completed",
            "db_path": str(db_path),
            "cpu_workers": eff_workers,
            "max_net_concurrency": eff_net,
            "worker_pids": sorted(worker_pids),
            "recovery": recovery_summary,
            "intents_completed": intents_completed,
            "intents_failed": intents_failed,
            "loop2_emitted_intents": loop2_emitted,
            "stage1_production_count": len(stage1_production_findings),
            "stage1_dropped_noise_count": stage1_noise_count,
            "stage2": stage2_result,
            "stage3_results": stage3_results,
            "facts": all_facts,
            "lane_allocation": lane_allocation,
            "eligibility_sync": eligibility_sync,
            "elapsed_ms": elapsed_ms,
        }
    finally:
        blackboard.close()


__all__ = [
    "LANE1_DEFAULT_PROGRAMS",
    "LANE2_DEFAULT_PROGRAMS",
    "SECURITY_FIX_KEYWORDS",
    "SIBLING_SDK_LANGUAGES",
    "SqliteBlackboard",
    "TwoLaneBountyQueue",
    "default_cpu_workers",
    "detect_security_fix_signal",
    "emit_sibling_parity_intents",
    "run_formal_and_differential_check",
    "run_local_rfchunt_async",
    "run_stage1_cpu_check",
    "sync_eligibility_and_stage_unlocks",
]
