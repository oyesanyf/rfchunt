"""
Shared offline fixtures for RFC-Hunt Cairn Blackboard & OODA E2E tests (`tests/e2e_blackboard/`).

Provides:
- `reset_blackboard_env` (`autouse=True`): sets `CI="true"`, `RFCHUNT_OFFLINE="1"`,
  `ARTEX_SECRET_KEY`, snapshots/restores `TargetAuthorizationGate.ALLOWED_TARGETS`,
  `_request_history`, `ExecutionPolicy.reset_instance()`, and `ARTEX_*`/`RFCHUNT_*` env vars.
- `bb_db` & `bb_db_factory`: isolated on-disk SQLite WAL `Database` handles under `tmp_path`
  with deterministic `close()` + `gc.collect()` cleanup.
- `pre_migration_db_builder`: builds realistic `"v003"` and `"pre_001"` legacy SQLite
  databases via raw `sqlite3.connect` with seeded rows and no `blackboard_nodes`.
- `local_rfc_cache`: seeds `rfc9112.txt`, `rfc7230.txt`, `rfc9113.txt`, `rfc9110.txt`
  with real ABNF blocks and normative framing text so `RFCFetcher` never hits the network.
- `isolated_swarm_workspace`: creates an isolated `tmp_path` workspace (`chdir`, DB path,
  `harness2_runs_dir`, `reports_dir`, `rfcs` cache) so repo working files are untouched.
- `loopback_lab_server`: local `TestLabServer(host="127.0.0.1", port=0)`.
- `loopback_http_server`: local `ThreadingHTTPServer(("127.0.0.1", 0))` recording requests.
- `loopback_raw_tcp_desync_server`: raw TCP `127.0.0.1:0` server simulating deterministic
  HTTP framing desync / pipelined marker reflection.
- `subprocess_recorder` & `offline_subprocess_env`.
- `_mp_claim_worker`: module-level picklable worker for Windows `spawn` multiprocessing.
"""

from __future__ import annotations

import gc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterator, List, Optional
import uuid

import pytest

from database import Database
from engine.execution_policy import ExecutionPolicy
from mcp_server import TargetAuthorizationGate
from test_lab_server import TestLabServer


REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_HEX_KEY = "0123456789abcdef" * 4

_TRACKED_EXACT_ENV_VARS = (
    "RFCHUNT_OFFLINE",
    "CI",
    "RFCHUNT_ALLOW_DESTRUCTIVE",
    "RFCHUNT_AUTHORIZED_TARGETS",
    "RFCHUNT_SUPERVISOR_TOKEN",
    "RFCHUNT_DISABLE_AT_REST_ENCRYPTION",
    "NO_COLOR",
    "OLLAMA_TIMEOUT",
)

_RFC_FIXTURES: Dict[str, str] = {
    "rfc9112.txt": (
        "RFC 9112 HTTP/1.1 Message Syntax and Framing June 2022\n\n"
        "1. Message Parsing and Framing\n"
        "HTTP/1.1 messages consist of a start-line followed by header fields and an optional message body. "
        "A server MUST reject any received request message that contains whitespace between a header field name and colon. "
        "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length. "
        "A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding header field.\n\n"
        "ABNF Grammar:\n"
        "HTTP-message   = start-line CRLF *( field-line CRLF ) CRLF [ message-body ]\n"
        "chunked-body   = *chunk last-chunk trailer-section CRLF\n"
        "chunk          = chunk-size [ chunk-ext ] CRLF chunk-data CRLF\n"
        "obs-fold       = OWS CRLF RWS\n\n"
        "2. Line Terminators and Obsolete Folding\n"
        "A recipient MUST recognize bare LF as a line terminator only when strict CRLF validation is disabled, and MUST reject obs-fold in requests. "
        "Chunk extensions MUST be parsed strictly before chunk-data delimiters.\n"
    ),
    "rfc7230.txt": (
        "RFC 7230 HTTP/1.1 Message Syntax and Routing June 2014\n\n"
        "3.3.2 Content-Length and Transfer-Encoding\n"
        "A proxy MUST NOT forward a message with multiple differing Content-Length header fields without rejecting it with 400 Bad Request. "
        "If a Transfer-Encoding header field is present in a request and the chunked transfer coding is not the final encoding, the message framing cannot be determined reliably.\n\n"
        "ABNF Grammar:\n"
        "Transfer-Encoding = 1#transfer-coding\n"
        "Content-Length = 1*DIGIT\n"
        "field-line = field-name \":\" OWS field-value OWS\n\n"
        "3.5 Message Parsing Robustness\n"
        "Although the line terminator for the start-line and header fields is the sequence CRLF, a recipient MAY recognize a single LF as a line terminator.\n"
    ),
    "rfc9113.txt": (
        "RFC 9113 HTTP/2 June 2022\n\n"
        "8.2 Connection-Specific Header Fields\n"
        "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields such as Transfer-Encoding or Keep-Alive. "
        "Any intermediary translating HTTP/2 streams to HTTP/1.1 MUST validate pseudo-headers and strip malformed CRLF sequences from header values.\n\n"
        "ABNF Grammar:\n"
        "header-block = *( field-line )\n"
        "pseudo-header = \":method\" / \":scheme\" / \":authority\" / \":path\"\n\n"
        "8.1.1 Upgrading and Stream Framing\n"
        "A server MUST treat a request with an invalid Content-Length in an HTTP/2 DATA frame stream as malformed.\n"
    ),
    "rfc9110.txt": (
        "RFC 9110 HTTP Semantics June 2022\n\n"
        "9.3 Methods and Intermediary Caching\n"
        "A HEAD response MUST NOT contain content even when a Content-Length header field is present in the response header section. "
        "A 304 Not Modified or 204 No Content response MUST be terminated by the end of the header section and MUST NOT contain message body bytes.\n\n"
        "ABNF Grammar:\n"
        "method = token\n"
        "status-code = 3DIGIT\n"
    ),
}


def _build_offline_subprocess_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a clean offline subprocess environment preserving PYTHONPATH and test ARTEX_SECRET_KEY."""
    env = dict(os.environ)
    env["CI"] = "true"
    env["RFCHUNT_OFFLINE"] = "1"
    env["ARTEX_SECRET_KEY"] = TEST_HEX_KEY
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    existing_pp = env.get("PYTHONPATH", "")
    repo_str = str(REPO_ROOT)
    if repo_str not in existing_pp.split(os.pathsep):
        env["PYTHONPATH"] = f"{repo_str}{os.pathsep}{existing_pp}" if existing_pp else repo_str
    env.pop("RFCHUNT_ALLOW_DESTRUCTIVE", None)
    env.pop("RFCHUNT_AUTHORIZED_TARGETS", None)
    if extra:
        env.update(extra)
    return env


@pytest.fixture
def offline_subprocess_env() -> Dict[str, str]:
    """Provide a clean offline subprocess environment dict for `subprocess.run(..., env=...)`."""
    return _build_offline_subprocess_env()


def _mp_claim_worker(
    db_path: str,
    key_path: str,
    worker_id: str,
    task_id: Optional[str],
    start_barrier: Any,
    out_queue: Any,
) -> None:
    """Module-level picklable worker for Windows `spawn` multiprocessing INTENT claim tests."""
    os.environ["ARTEX_SECRET_KEY"] = TEST_HEX_KEY
    os.environ["CI"] = "true"
    os.environ["RFCHUNT_OFFLINE"] = "1"
    db = Database(db_path, timeout=30.0, secret_key_path=key_path)
    claimed_ids: List[str] = []
    errors: List[str] = []
    try:
        start_barrier.wait(timeout=15.0)
        while True:
            try:
                item = db.claim_next_intent(worker_id, task_id=task_id)
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
                break
            if item is None:
                break
            claimed_ids.append(str(item["node_id"]))
    finally:
        db.close()
        out_queue.put({"worker_id": worker_id, "claimed": claimed_ids, "errors": errors})


@pytest.fixture(autouse=True)
def reset_blackboard_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Snapshot/restore security singletons and environment variables around each test."""
    orig_targets = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    orig_history = {k: list(v) for k, v in TargetAuthorizationGate._request_history.items()}
    tracked_keys = set(_TRACKED_EXACT_ENV_VARS) | {
        k for k in os.environ.keys() if k.startswith("ARTEX_")
    }
    orig_env: Dict[str, Optional[str]] = {k: os.environ.get(k) for k in tracked_keys}

    ExecutionPolicy.reset_instance()
    TargetAuthorizationGate.ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}
    TargetAuthorizationGate._request_history.clear()

    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("ARTEX_SECRET_KEY", TEST_HEX_KEY)
    monkeypatch.delenv("RFCHUNT_ALLOW_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("RFCHUNT_AUTHORIZED_TARGETS", raising=False)
    for k in list(os.environ.keys()):
        if k.startswith("ARTEX_") and k != "ARTEX_SECRET_KEY":
            monkeypatch.delenv(k, raising=False)

    try:
        yield
    finally:
        ExecutionPolicy.reset_instance()
        TargetAuthorizationGate.ALLOWED_TARGETS = orig_targets
        TargetAuthorizationGate._request_history.clear()
        for k, hist in orig_history.items():
            TargetAuthorizationGate._request_history[k] = hist

        current_artex = [k for k in os.environ.keys() if k.startswith("ARTEX_")]
        for k in set(orig_env.keys()) | set(current_artex):
            prev = orig_env.get(k)
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev


@pytest.fixture
def bb_db_factory(tmp_path: Path) -> Iterator[Callable[..., Database]]:
    """Open tracked isolated SQLite Database instances under `tmp_path` and close all on teardown."""
    opened: List[Database] = []
    repo_db = (REPO_ROOT / "terminator.db").resolve()

    def _open(name: Optional[str] = None, **kwargs: Any) -> Database:
        fname = name or f"bb_{uuid.uuid4().hex[:8]}.db"
        db_file = Path(fname) if Path(fname).is_absolute() else (tmp_path / fname)
        assert db_file.resolve() != repo_db, "Refusing to open repo terminator.db in E2E test"
        kwargs.setdefault("secret_key_path", str(tmp_path / "keys" / "secret.key"))
        db = Database(str(db_file), **kwargs)
        opened.append(db)
        return db

    try:
        yield _open
    finally:
        for db in reversed(opened):
            try:
                db.close()
            except Exception:
                pass
        gc.collect()


@pytest.fixture
def bb_db(bb_db_factory: Callable[..., Database]) -> Database:
    """Single isolated WAL Database instance inside `tmp_path`."""
    return bb_db_factory("e2e_blackboard.db")


@pytest.fixture
def pre_migration_db_builder(tmp_path: Path) -> Callable[[str, str], Path]:
    """
    Construct realistic pre-M1 SQLite databases (`v003` or `pre_001`) via raw `sqlite3.connect`
    with seeded legacy rows and without `blackboard_nodes`.
    """

    def _build(mode: str = "v003", filename: Optional[str] = None) -> Path:
        if mode not in ("v003", "pre_001"):
            raise ValueError(f"Unsupported pre_migration_db mode: {mode}")
        db_file = tmp_path / (filename or f"legacy_{mode}_{uuid.uuid4().hex[:6]}.db")
        conn = sqlite3.connect(str(db_file))
        try:
            with conn:
                conn.executescript(
                    """
                    CREATE TABLE rfcs (
                        rfc_id TEXT PRIMARY KEY,
                        title TEXT,
                        source_url TEXT,
                        doc_path TEXT,
                        fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE fragments (
                        fragment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rfc_id TEXT,
                        content TEXT NOT NULL,
                        keywords TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE probes (
                        probe_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fragment_id INTEGER,
                        rationale TEXT NOT NULL,
                        raw_request TEXT NOT NULL,
                        is_clean BOOLEAN DEFAULT 0,
                        source_type TEXT DEFAULT 'llm',
                        parent_probe_id INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE evaluations (
                        finding_status TEXT DEFAULT 'UNVERIFIED',
                        eval_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        probe_id INTEGER NOT NULL,
                        target_host TEXT NOT NULL,
                        target_port INTEGER NOT NULL,
                        is_vulnerable BOOLEAN NOT NULL,
                        desync_class TEXT,
                        details TEXT,
                        raw_evidence TEXT,
                        tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE schema_migrations (
                        version TEXT PRIMARY KEY,
                        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )
                if mode == "v003":
                    conn.executescript(
                        """
                        CREATE TABLE attack_chains (
                            chain_id TEXT PRIMARY KEY,
                            title TEXT NOT NULL,
                            attack_type TEXT NOT NULL,
                            target_host TEXT NOT NULL,
                            target_endpoint TEXT NOT NULL,
                            framing_anomaly_id TEXT,
                            ai_sink_id INTEGER,
                            steps_json TEXT NOT NULL,
                            raw_payload TEXT,
                            is_verified BOOLEAN DEFAULT 0,
                            severity TEXT DEFAULT 'HIGH',
                            task_id TEXT DEFAULT 'default',
                            poe_level INTEGER DEFAULT 0,
                            verification_status TEXT DEFAULT 'UNVERIFIED',
                            evidence_quote TEXT DEFAULT '',
                            traffic_id TEXT DEFAULT '',
                            hop_count INTEGER DEFAULT 1,
                            source_scanners_json TEXT DEFAULT '[]',
                            remote_artex_task_id TEXT DEFAULT '',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        CREATE TABLE chain_retests (
                            retest_id TEXT PRIMARY KEY,
                            chain_id TEXT NOT NULL,
                            verdict TEXT NOT NULL,
                            conditions TEXT DEFAULT '',
                            evidence TEXT DEFAULT '',
                            traffic_id TEXT DEFAULT '',
                            original_traffic_id TEXT DEFAULT '',
                            tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        CREATE TABLE approval_decisions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            task_id TEXT NOT NULL DEFAULT 'default',
                            action_type TEXT NOT NULL,
                            target TEXT DEFAULT '',
                            method TEXT DEFAULT '',
                            decision TEXT NOT NULL,
                            decided_by TEXT NOT NULL,
                            rule_id TEXT DEFAULT '',
                            rationale TEXT DEFAULT '',
                            action_summary TEXT DEFAULT '',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        """
                    )
                    conn.executemany(
                        "INSERT INTO schema_migrations (version) VALUES (?)",
                        [
                            ("001_attack_chains_artex_cols",),
                            ("002_chain_retests_original_traffic_id",),
                            ("003_approval_decisions_action_summary",),
                        ],
                    )
                else:
                    conn.executescript(
                        """
                        CREATE TABLE attack_chains (
                            chain_id TEXT PRIMARY KEY,
                            title TEXT NOT NULL,
                            attack_type TEXT NOT NULL,
                            target_host TEXT NOT NULL,
                            target_endpoint TEXT NOT NULL,
                            framing_anomaly_id TEXT,
                            ai_sink_id INTEGER,
                            steps_json TEXT NOT NULL,
                            raw_payload TEXT,
                            is_verified BOOLEAN DEFAULT 0,
                            severity TEXT DEFAULT 'HIGH',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        CREATE TABLE chain_retests (
                            retest_id TEXT PRIMARY KEY,
                            chain_id TEXT NOT NULL,
                            verdict TEXT NOT NULL,
                            conditions TEXT DEFAULT '',
                            evidence TEXT DEFAULT '',
                            traffic_id TEXT DEFAULT '',
                            tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        CREATE TABLE approval_decisions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            task_id TEXT NOT NULL DEFAULT 'default',
                            action_type TEXT NOT NULL,
                            target TEXT DEFAULT '',
                            method TEXT DEFAULT '',
                            decision TEXT NOT NULL,
                            decided_by TEXT NOT NULL,
                            rule_id TEXT DEFAULT '',
                            rationale TEXT DEFAULT '',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        """
                    )

                conn.execute(
                    "INSERT INTO rfcs (rfc_id, title, source_url, doc_path) VALUES (?, ?, ?, ?)",
                    ("RFC9112", "HTTP/1.1 Message Syntax", "https://example.invalid/rfc9112.txt", "rfcs/rfc9112.txt"),
                )
                conn.execute(
                    "INSERT INTO fragments (rfc_id, content, keywords) VALUES (?, ?, ?)",
                    ("RFC9112", "Transfer-Encoding overrides Content-Length.", "transfer-encoding,content-length"),
                )
                conn.execute(
                    "INSERT INTO probes (fragment_id, rationale, raw_request, is_clean, source_type) VALUES (?, ?, ?, ?, ?)",
                    (1, "legacy-probe", "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", 1, "llm"),
                )
                conn.execute(
                    "INSERT INTO evaluations (finding_status, probe_id, target_host, target_port, is_vulnerable, desync_class, details) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    ("CONFIRMED", 1, "127.0.0.1", 8080, 1, "CL.TE", "legacy-eval-row"),
                )
                conn.execute(
                    "INSERT INTO attack_chains (chain_id, title, attack_type, target_host, target_endpoint, steps_json, is_verified, severity) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("legacy-chain-1", "Legacy Chain", "DESYNC", "127.0.0.1", "/internal/service", "[]", 1, "HIGH"),
                )
        finally:
            conn.close()
        return db_file

    return _build


@pytest.fixture
def local_rfc_cache(tmp_path: Path) -> Path:
    """Seed local cached RFC files so `RFCFetcher` operates completely offline."""
    cache_dir = tmp_path / "rfcs"
    cache_dir.mkdir(parents=True, exist_ok=True)
    for fname, body in _RFC_FIXTURES.items():
        (cache_dir / fname).write_text(body, encoding="utf-8")
    return cache_dir


@pytest.fixture
def isolated_swarm_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, local_rfc_cache: Path
) -> SimpleNamespace:
    """
    Create an isolated working directory in `tmp_path` so swarm runs never touch
    repo `data/`, `caldera_export/`, `terminator_dashboard.html`, `terminator.db`, or `keys/secret.key`.
    """
    ws = tmp_path / "swarm_ws"
    ws.mkdir(parents=True, exist_ok=True)
    rfcs_dir = ws / "rfcs"
    rfcs_dir.mkdir(parents=True, exist_ok=True)
    for p in local_rfc_cache.iterdir():
        if p.is_file():
            (rfcs_dir / p.name).write_text(p.read_text(encoding="utf-8"), encoding="utf-8")

    (ws / "data").mkdir(parents=True, exist_ok=True)
    h2_dir = ws / "runs" / "harness2"
    h2_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = ws / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    db_path = ws / "terminator.db"
    key_path = ws / "keys" / "secret.key"

    monkeypatch.chdir(ws)
    return SimpleNamespace(
        root=ws,
        db_path=db_path,
        key_path=key_path,
        rfcs_dir=rfcs_dir,
        harness2_runs_dir=h2_dir,
        reports_dir=reports_dir,
    )


@pytest.fixture
def loopback_lab_server() -> Iterator[TestLabServer]:
    """Start ephemeral `TestLabServer` on `127.0.0.1:0` and shut down cleanly."""
    srv = TestLabServer(host="127.0.0.1", port=0, auth_boundary_patched=False)
    srv.start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture
def loopback_http_server() -> Iterator[SimpleNamespace]:
    """Start an ephemeral `ThreadingHTTPServer` on `127.0.0.1:0` with request recording."""
    req_lock = threading.Lock()
    requests_log: List[Dict[str, Any]] = []
    state: Dict[str, Any] = {"auth_patched": False}

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_body(self) -> str:
            raw_len = self.headers.get("Content-Length")
            if not raw_len:
                return ""
            try:
                length = max(0, int(raw_len))
            except ValueError:
                return ""
            return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self, method: str) -> None:
            body_text = self._read_body()
            clean_path = self.path.split("?", 1)[0]
            with req_lock:
                requests_log.append(
                    {
                        "method": method,
                        "path": self.path,
                        "headers": {k: v for k, v in self.headers.items()},
                        "body": body_text,
                    }
                )
            if clean_path in ("/", "/health"):
                self._send(200, json.dumps({"status": "ok", "service": "loopback-http"}).encode("utf-8"))
                return
            if clean_path == "/api/public":
                self._send(200, json.dumps({"public": True}).encode("utf-8"))
                return
            if clean_path in ("/api/admin", "/internal/service"):
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer ") or not auth[7:].strip():
                    self._send(401, json.dumps({"error": "unauthorized"}).encode("utf-8"))
                    return
                if state.get("auth_patched"):
                    self._send(403, json.dumps({"error": "forbidden"}).encode("utf-8"))
                    return
                self._send(200, json.dumps({"admin": True, "scope": "governance-admin"}).encode("utf-8"))
                return
            if clean_path in ("/api/chat", "/api/ai/chat"):
                self._send(200, json.dumps({"reply": "ok", "echo": body_text}).encode("utf-8"))
                return
            if clean_path == "/robots.txt":
                self._send(200, b"User-agent: *\nDisallow: /internal/service\n", content_type="text/plain")
                return
            self._send(404, json.dumps({"error": "not_found", "path": clean_path}).encode("utf-8"))

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_HEAD(self) -> None:
            self._handle("HEAD")

        def do_PUT(self) -> None:
            self._handle("PUT")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def _reset() -> None:
        with req_lock:
            requests_log.clear()

    try:
        yield SimpleNamespace(
            host="127.0.0.1",
            port=port,
            url=f"http://127.0.0.1:{port}",
            requests=requests_log,
            reset=_reset,
            state=state,
        )
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def loopback_raw_tcp_desync_server() -> Iterator[SimpleNamespace]:
    """
    Ephemeral `127.0.0.1:0` raw TCP server simulating deterministic HTTP framing desync
    (reflected smuggled marker / Transfer_Encoding obfuscation) for E2E framing tests.
    """
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(64)
    port = srv_sock.getsockname()[1]

    state: Dict[str, Any] = {"running": True, "poisoned_next": False, "received": []}
    lock = threading.Lock()

    def _handle_conn(conn: socket.socket) -> None:
        conn.settimeout(2.0)
        try:
            while state["running"]:
                data = conn.recv(8192)
                if not data:
                    break
                with lock:
                    state["received"].append(data)
                    was_poisoned = state["poisoned_next"]
                    if was_poisoned:
                        state["poisoned_next"] = False
                if was_poisoned:
                    body = b"terminator_marker reflected on queue!\n"
                    resp = (
                        b"HTTP/1.1 404 Not Found\r\n"
                        b"Content-Type: text/plain\r\n"
                        + f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n".encode("ascii")
                        + body
                    )
                    conn.sendall(resp)
                    continue
                if b"Transfer_Encoding" in data or b"multipart/byteranges" in data or b"obs-fold" in data.lower():
                    with lock:
                        state["poisoned_next"] = True
                    body = b"Trigger Accepted"
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        + f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n".encode("ascii")
                        + body
                    )
                    conn.sendall(resp)
                    continue
                body = b"OK"
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK"
                )
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _accept() -> None:
        while state["running"]:
            try:
                c, _ = srv_sock.accept()
                threading.Thread(target=_handle_conn, args=(c,), daemon=True).start()
            except Exception:
                break

    accept_thread = threading.Thread(target=_accept, daemon=True)
    accept_thread.start()

    try:
        yield SimpleNamespace(host="127.0.0.1", port=port, state=state)
    finally:
        state["running"] = False
        try:
            srv_sock.close()
        except Exception:
            pass
        accept_thread.join(timeout=1.0)


@pytest.fixture
def subprocess_recorder(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """
    Intercept `subprocess.run`, enforce `shell=False` and list/tuple argv, and return scripted responses.
    """
    calls: List[Dict[str, Any]] = []
    responses: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()

    def _norm_bin(token: str) -> str:
        base = Path(str(token).replace("\\", "/")).name.lower()
        return base[:-4] if base.endswith(".exe") else base

    def set_response(binary: str, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        with lock:
            responses[_norm_bin(binary)] = {
                "returncode": int(returncode),
                "stdout": stdout,
                "stderr": stderr,
            }

    def _fake_run(args: Any, *pos_args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        shell_val = kwargs.get("shell", False)
        assert shell_val is False, f"shell=True forbidden in subprocess calls: {args!r}"
        assert isinstance(args, (list, tuple)) and len(args) >= 1, (
            f"Subprocess argv must be non-empty list/tuple, got {type(args).__name__}"
        )
        with lock:
            calls.append({"argv": list(args), "shell": shell_val, "kwargs": dict(kwargs)})
            norm = _norm_bin(str(args[0]))
            resp = responses.get(norm)
            if resp is None and norm == "docker":
                for tok in args[1:]:
                    tok_norm = _norm_bin(str(tok).split(":")[0])
                    if tok_norm in responses:
                        resp = responses[tok_norm]
                        break
                    for rkey, rval in responses.items():
                        if rkey in str(tok).lower():
                            resp = rval
                            break
                    if resp is not None:
                        break
            if resp is None:
                resp = {"returncode": 0, "stdout": "", "stderr": ""}

        out_stdout = resp["stdout"]
        out_stderr = resp["stderr"]
        is_text = bool(kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding"))
        if not is_text:
            out_stdout = out_stdout.encode("utf-8") if isinstance(out_stdout, str) else out_stdout
            out_stderr = out_stderr.encode("utf-8") if isinstance(out_stderr, str) else out_stderr

        return subprocess.CompletedProcess(
            args=list(args),
            returncode=resp["returncode"],
            stdout=out_stdout,
            stderr=out_stderr,
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    return SimpleNamespace(calls=calls, set_response=set_response)
