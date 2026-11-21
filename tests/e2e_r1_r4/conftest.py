"""
Shared offline fixtures for RFCHunt R1-R4 E2E tests (`tests/e2e_r1_r4/`).

Provides:
- `reset_security_singletons` (`autouse=True`): saves/restores `ExecutionPolicy`,
  `TargetAuthorizationGate.ALLOWED_TARGETS` & `_request_history`, and security/ARTEX env vars.
- `isolated_db(tmp_path)`: isolated SQLite `Database` with `tmp_path` keyfile.
- `loopback_server`: local `ThreadingHTTPServer(("127.0.0.1", 0))` on daemon thread.
- `subprocess_recorder(monkeypatch)`: patches `subprocess.run` (and captures calls via
  `silent_subprocess_run` without double-recording), asserting `shell=False` list-argv execution.
- `mock_arbiter_factory`: deterministic `arbitrate_structured_json` stub builder.
- `module21_stub(monkeypatch)`: dynamic toggle for `morluto` / `morluto.rea` / `engine.morluto_rea`.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.abc
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import ModuleType, SimpleNamespace
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Union

import pytest

from database import Database
from engine.execution_policy import ExecutionPolicy
from mcp_server import TargetAuthorizationGate


_TRACKED_EXACT_ENV_VARS = (
    "RFCHUNT_OFFLINE",
    "CI",
    "RFCHUNT_ALLOW_DESTRUCTIVE",
    "RFCHUNT_AUTHORIZED_TARGETS",
    "RFCHUNT_SUPERVISOR_TOKEN",
    "RFCHUNT_DISABLE_AT_REST_ENCRYPTION",
    "NO_COLOR",
)


@pytest.fixture(autouse=True)
def reset_security_singletons(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Save and restore security singletons and environment variables around each test."""
    orig_targets = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    orig_history = {k: list(v) for k, v in TargetAuthorizationGate._request_history.items()}
    orig_env: Dict[str, Optional[str]] = {}

    tracked_keys = set(_TRACKED_EXACT_ENV_VARS) | {
        k for k in os.environ.keys() if k.startswith("ARTEX_")
    }
    for key in tracked_keys:
        orig_env[key] = os.environ.get(key)

    ExecutionPolicy.reset_instance()
    TargetAuthorizationGate.ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}
    TargetAuthorizationGate._request_history.clear()

    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.delenv("RFCHUNT_ALLOW_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("RFCHUNT_AUTHORIZED_TARGETS", raising=False)
    for k in list(os.environ.keys()):
        if k.startswith("ARTEX_"):
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
def isolated_db(tmp_path: Path) -> Iterator[Database]:
    """Open an isolated on-disk SQLite Database inside `tmp_path` with isolated secret key."""
    db_path = tmp_path / "e2e_isolated.db"
    key_path = tmp_path / "keys" / "secret.key"
    db = Database(str(db_path), secret_key_path=str(key_path))
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def loopback_server() -> Iterator[SimpleNamespace]:
    """Start an ephemeral ThreadingHTTPServer on 127.0.0.1 serving standard R1-R4 routes."""
    req_lock = threading.Lock()
    requests_log: List[Dict[str, Any]] = []
    state: Dict[str, Any] = {
        "ai_reply_override": None,
        "desync_override": None,
    }

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
            if length == 0:
                return ""
            return self.rfile.read(length).decode("utf-8", errors="replace")

        def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self, method: str) -> None:
            body_text = self._read_body()
            clean_path = self.path.split("?", 1)[0]
            headers_dict = {k: v for k, v in self.headers.items()}
            with req_lock:
                requests_log.append(
                    {
                        "method": method,
                        "path": self.path,
                        "headers": headers_dict,
                        "body": body_text,
                    }
                )

            if clean_path == "/" or clean_path == "/health":
                payload = json.dumps({"status": "ok", "service": "rfchunt-loopback"}).encode("utf-8")
                self._send(200, payload)
                return

            if clean_path == "/api/public":
                payload = json.dumps({"public": True, "service": "rfchunt-lab"}).encode("utf-8")
                self._send(200, payload)
                return

            if clean_path == "/api/admin":
                auth_header = self.headers.get("Authorization", "")
                if not auth_header.startswith("Bearer ") or len(auth_header[7:].strip()) == 0:
                    payload = json.dumps({"error": "unauthorized", "detail": "Bearer token required"}).encode("utf-8")
                    self._send(401, payload)
                    return
                payload = json.dumps({"admin": True, "role": "admin", "scope": "admin-panel"}).encode("utf-8")
                self._send(200, payload)
                return

            if clean_path == "/api/ai/chat":
                override = state.get("ai_reply_override")
                reply_val = override if override is not None else "ok"
                payload = json.dumps(
                    {"reply": reply_val, "model": "mock-llm", "echo": body_text}
                ).encode("utf-8")
                self._send(200, payload)
                return

            if clean_path == "/api/desync":
                override = state.get("desync_override")
                if override is not None:
                    payload = json.dumps(override).encode("utf-8")
                else:
                    payload = json.dumps({"desync": False, "path": "/api/desync"}).encode("utf-8")
                self._send(200, payload)
                return

            if clean_path == "/robots.txt":
                self._send(
                    200,
                    b"User-agent: *\nDisallow: /api/admin\nAllow: /api/public\n",
                    content_type="text/plain; charset=utf-8",
                )
                return

            if clean_path == "/app.js":
                self._send(
                    200,
                    b"fetch('/api/public');\nfetch('/api/admin');\nfetch('/api/ai/chat', {method:'POST'});\n",
                    content_type="application/javascript; charset=utf-8",
                )
                return

            self._send(404, json.dumps({"error": "not_found", "path": clean_path}).encode("utf-8"))

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PUT(self) -> None:
            self._handle("PUT")

        def do_DELETE(self) -> None:
            self._handle("DELETE")

        def do_HEAD(self) -> None:
            self._handle("HEAD")

        def do_OPTIONS(self) -> None:
            self._handle("OPTIONS")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def _reset() -> None:
        with req_lock:
            requests_log.clear()

    ns = SimpleNamespace(
        host="127.0.0.1",
        port=port,
        url=f"http://127.0.0.1:{port}",
        requests=requests_log,
        reset=_reset,
        state=state,
    )
    try:
        yield ns
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def subprocess_recorder(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """
    Intercepts `subprocess.run` (including calls routed through `silent_subprocess_run`),
    asserts `shell is False` and list/tuple `argv`, and returns scripted CompletedProcess responses.
    """
    calls: List[Dict[str, Any]] = []
    responses: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()

    def _norm_bin(token: str) -> str:
        base = Path(str(token).replace("\\", "/")).name.lower()
        if base.endswith(".exe"):
            base = base[:-4]
        return base

    def set_response(binary: str, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        key = _norm_bin(binary)
        with lock:
            responses[key] = {
                "returncode": int(returncode),
                "stdout": stdout,
                "stderr": stderr,
            }

    def _fake_subprocess_run(args: Any, *pos_args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        shell_val = kwargs.get("shell", False)
        assert shell_val is False, f"shell=True is strictly forbidden in subprocess calls: args={args!r}"
        assert isinstance(args, (list, tuple)) and len(args) >= 1, (
            f"Subprocess command must be a non-empty list/tuple of args, got {type(args).__name__}: {args!r}"
        )

        record = {
            "argv": list(args),
            "shell": shell_val,
            "kwargs": dict(kwargs),
        }
        with lock:
            calls.append(record)
            norm = _norm_bin(str(args[0]))
            resp = responses.get(norm)
            if resp is None and norm == "docker":
                # Allow tests to register response by either "docker" or the inner tool/image name
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

    monkeypatch.setattr(subprocess, "run", _fake_subprocess_run)
    return SimpleNamespace(calls=calls, set_response=set_response)


@pytest.fixture
def mock_arbiter_factory() -> Callable[[Union[Sequence[Dict[str, Any]], Exception, type, str]], Any]:
    """Build deterministic mock arbiters exposing `arbitrate_structured_json` and prompt history."""

    def _build(script: Union[Sequence[Dict[str, Any]], Exception, type, str]) -> Any:
        class _MockArbiter:
            def __init__(self) -> None:
                self.prompts: List[Dict[str, Any]] = []
                self._idx = 0

            def arbitrate_structured_json(
                self,
                task_name: str,
                system_prompt: str,
                user_prompt: str,
                default_payload: Optional[Dict[str, Any]] = None,
                num_predict: int = 512,
            ) -> Dict[str, Any]:
                self.prompts.append(
                    {
                        "task_name": task_name,
                        "system_prompt": system_prompt,
                        "user_prompt": user_prompt,
                        "default_payload": default_payload,
                        "num_predict": num_predict,
                    }
                )
                if isinstance(script, Exception):
                    raise script
                if isinstance(script, type) and issubclass(script, Exception):
                    raise script("Mock arbiter scripted failure")
                if isinstance(script, str):
                    return {
                        "data": script,
                        "status": "fused",
                        "tokens_used": 64,
                        "model": "mock-arbiter",
                    }
                if isinstance(script, Sequence):
                    if len(script) == 0:
                        return {
                            "data": default_payload or {},
                            "status": "fused",
                            "tokens_used": 32,
                            "model": "mock-arbiter",
                        }
                    item = script[min(self._idx, len(script) - 1)]
                    self._idx += 1
                    if isinstance(item, Exception):
                        raise item
                    if isinstance(item, dict) and "data" in item and ("status" in item or "tokens_used" in item):
                        return dict(item)
                    return {
                        "data": item,
                        "status": "fused",
                        "tokens_used": 100,
                        "model": "mock-arbiter",
                    }
                return {
                    "data": default_payload or {},
                    "status": "fused",
                    "tokens_used": 32,
                    "model": "mock-arbiter",
                }

        return _MockArbiter()

    return _build


class _Module21BlockedMetaPath(importlib.abc.MetaPathFinder):
    """Wraps existing `sys.meta_path` finders to hide `morluto*` and `engine.morluto_rea` cleanly."""

    BLOCKED_PREFIXES = ("morluto", "engine.morluto_rea")

    def __init__(self, inner_finder: Any) -> None:
        self._inner = inner_finder

    def find_spec(self, fullname: str, path: Any, target: Any = None) -> Any:
        for prefix in self.BLOCKED_PREFIXES:
            if fullname == prefix or fullname.startswith(prefix + "."):
                return None
        return self._inner.find_spec(fullname, path, target)

    def invalidate_caches(self) -> None:
        if hasattr(self._inner, "invalidate_caches"):
            self._inner.invalidate_caches()


@pytest.fixture
def module21_stub(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Toggle presence or absence of Module 21 (`morluto` / `morluto.rea` / `engine.morluto_rea`)."""

    def _configure(
        present: bool,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        *,
        raise_exc: Optional[Exception] = None,
    ) -> None:
        target_names = ("morluto", "morluto.rea", "engine.morluto_rea")
        unwrapped_meta = [
            f._inner if isinstance(f, _Module21BlockedMetaPath) else f
            for f in sys.meta_path
        ]

        if not present:
            for name in target_names:
                monkeypatch.delitem(sys.modules, name, raising=False)
            if "engine" in sys.modules:
                monkeypatch.delattr(sys.modules["engine"], "morluto_rea", raising=False)
            monkeypatch.setattr(
                sys,
                "meta_path",
                [_Module21BlockedMetaPath(f) for f in unwrapped_meta],
            )
            return

        monkeypatch.setattr(sys, "meta_path", unwrapped_meta)
        payload = (
            list(endpoints)
            if endpoints is not None
            else [{"route": "/api/v2/m21", "method": "POST", "source": "module21"}]
        )

        def _mine_surface(target_path: Optional[str] = None, query: str = "", **kwargs: Any) -> List[Dict[str, Any]]:
            if raise_exc is not None:
                raise raise_exc
            if not query:
                return list(payload)
            q_low = query.lower()
            filtered = [e for e in payload if q_low in json.dumps(e).lower()]
            return filtered if filtered else list(payload)

        morluto_pkg = ModuleType("morluto")
        morluto_pkg.__path__ = []  # mark as package
        rea_mod = ModuleType("morluto.rea")
        rea_mod.mine_surface = _mine_surface  # type: ignore[attr-defined]
        rea_mod.discover_surface = _mine_surface  # type: ignore[attr-defined]
        morluto_pkg.rea = rea_mod  # type: ignore[attr-defined]

        eng_rea_mod = ModuleType("engine.morluto_rea")
        eng_rea_mod.mine_surface = _mine_surface  # type: ignore[attr-defined]
        eng_rea_mod.discover_surface = _mine_surface  # type: ignore[attr-defined]

        monkeypatch.setitem(sys.modules, "morluto", morluto_pkg)
        monkeypatch.setitem(sys.modules, "morluto.rea", rea_mod)
        monkeypatch.setitem(sys.modules, "engine.morluto_rea", eng_rea_mod)
        if "engine" in sys.modules:
            monkeypatch.setattr(sys.modules["engine"], "morluto_rea", eng_rea_mod, raising=False)

    return _configure
