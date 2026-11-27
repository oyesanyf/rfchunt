"""
Shared fixtures, contract resolvers, real local servers, and Rust/CLI helpers
for `tests/e2e_formal_scope_gha/`.

Zero mocks, zero fake stubs, zero pytest.skip, strictly defensive-only.
"""

from __future__ import annotations

import ast
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_MISSING = object()

PROTECTED_FILES: Tuple[str, ...] = (
    "rfc_hunt_swarm.py",
    "mcp_server.py",
)

FORBIDDEN_PROTECTED_SYMBOLS: Tuple[str, ...] = (
    "z3_formal",
    "rust_scope_gatekeeper",
    "rust_scope_bridge",
    "RustScopeBridge",
)

_WEAPONIZED_INDICATORS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcurl\s+-[A-Za-z]*X\b", re.IGNORECASE),
    re.compile(r"\bsqlmap\b", re.IGNORECASE),
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\bnc\s+-e\b", re.IGNORECASE),
    re.compile(r"\bpowershell\s+-enc", re.IGNORECASE),
    re.compile(r"\bbash\s+-i\b", re.IGNORECASE),
    re.compile(r"#!/bin/(?:ba)?sh\b"),
    re.compile(r"\bInvoke-Expression\b", re.IGNORECASE),
    re.compile(r"\bmkfifo\b", re.IGNORECASE),
)

_PROXY_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def pytest_configure(config: pytest.Config) -> None:
    """Register tier1-tier4 markers cleanly when running this suite standalone."""
    config.addinivalue_line("markers", "tier1: Tier 1 core feature coverage tests (F1-F11)")
    config.addinivalue_line("markers", "tier2: Tier 2 boundary, corner-case, and negative tests (F1-F11)")
    config.addinivalue_line("markers", "tier3: Tier 3 pairwise cross-feature combination tests")
    config.addinivalue_line("markers", "tier4: Tier 4 realistic end-to-end defensive scenarios")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


_SESSION_INITIAL_PROTECTED_HASHES: Dict[str, str] = {
    rel: sha256_file(REPO_ROOT / rel)
    for rel in PROTECTED_FILES
    if (REPO_ROOT / rel).is_file()
}


def assert_protected_files_unmodified() -> None:
    """
    Verify `rfc_hunt_swarm.py` and `mcp_server.py` exist, are non-empty, pass
    `ast.parse(...)` syntax verification, match their session-start SHA256
    hashes (no in-session mutation), and contain zero Z3/Rust-scope symbols.
    """
    for rel in PROTECTED_FILES:
        p = REPO_ROOT / rel
        assert p.is_file(), f"Protected file missing: {p}"
        assert p.stat().st_size > 0, f"Protected file is empty: {p}"
        current_sha = sha256_file(p)
        session_sha = _SESSION_INITIAL_PROTECTED_HASHES.get(rel)
        assert session_sha is not None, (
            f"Protected file {rel} missing from session-initial hash snapshot"
        )
        assert current_sha == session_sha, (
            f"Protected file {rel} mutated during session: {session_sha} -> {current_sha}"
        )
        text = p.read_text(encoding="utf-8")
        assert text.strip(), f"Protected file {rel} has no non-whitespace content"
        ast.parse(text, filename=str(p))
        for sym in FORBIDDEN_PROTECTED_SYMBOLS:
            assert sym not in text, f"Forbidden symbol {sym!r} found in protected file {rel}"


def import_contract(module_path: str, symbol: str) -> Any:
    """
    Dynamically import `symbol` from `module_path` inside a test body.
    Fails loudly with AssertionError (never pytest.skip) if missing.
    """
    try:
        mod = importlib.import_module(module_path)
    except Exception as exc:
        raise AssertionError(
            f"Missing contract module {module_path!r} (required for {symbol!r}): {exc}"
        ) from exc
    if not hasattr(mod, symbol):
        raise AssertionError(
            f"Missing contract symbol {symbol!r} in module {module_path!r}"
        )
    return getattr(mod, symbol)


def import_first_available(candidates: Sequence[Tuple[str, str]]) -> Any:
    """Resolve the first available `(module_path, symbol)` pair from `candidates`."""
    errors: List[str] = []
    for mod_path, sym in candidates:
        try:
            mod = importlib.import_module(mod_path)
        except Exception as exc:
            errors.append(f"{mod_path}.{sym}: {exc}")
            continue
        if hasattr(mod, sym):
            return getattr(mod, sym)
        errors.append(f"{mod_path}.{sym}: attribute missing")
    raise AssertionError(
        "Missing contract symbol across candidates: " + "; ".join(errors)
    )


def extract_field(obj: Any, *names: str, default: Any = _MISSING) -> Any:
    """Read the first matching key/attribute from a dict or object."""
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    if default is not _MISSING:
        return default
    raise AssertionError(f"Expected one of {names!r} on {type(obj).__name__}: {obj!r}")


def extract_findings(res: Any) -> List[Any]:
    """
    Normalize return values from `verify_*_invariants(...)` and
    `run_z3_formal_verification(...)`, supporting both a direct `list`/`tuple`
    of findings and a `FormalVerificationReport`/dict with `.findings`.
    """
    if isinstance(res, (list, tuple)):
        return list(res)
    return list(extract_field(res, "findings", "results"))


def unpack_translation_result(res: Any) -> Tuple[Any, Dict[str, Any]]:
    """
    Normalize `translate_target_to_formal_model(...)` return values, supporting
    both `(model_or_none, telemetry)` tuples and direct IR/dict returns.
    """
    if isinstance(res, tuple) and len(res) == 2 and isinstance(res[1], dict):
        return res[0], res[1]
    return res, {}


@pytest.fixture(autouse=True)
def isolated_e2e_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """
    Enforce offline, non-destructive safety defaults and restore singleton policy
    gates before and after every test.
    """
    from engine.execution_policy import ExecutionPolicy
    from mcp_server import TargetAuthorizationGate

    orig_targets = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    orig_history = {k: list(v) for k, v in TargetAuthorizationGate._request_history.items()}

    ExecutionPolicy.reset_instance()
    TargetAuthorizationGate.ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}
    TargetAuthorizationGate._request_history.clear()

    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("RFCHUNT_AIR_GAPPED", "1")
    monkeypatch.setenv("RFCHUNT_AUTO_INSTALL_TOOLS", "0")
    monkeypatch.setenv("RFCHUNT_AUTO_PULL_MODELS", "0")
    monkeypatch.setenv("RFCHUNT_NO_EMOJI", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")
    monkeypatch.setenv("SEMGREP_SEND_METRICS", "off")
    monkeypatch.delenv("RFCHUNT_ALLOW_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("RFCHUNT_AUTHORIZED_TARGETS", raising=False)
    monkeypatch.delenv("RFCHUNT_SCOPE_GATEKEEPER_BIN", raising=False)
    for pkey in _PROXY_ENV_KEYS:
        monkeypatch.delenv(pkey, raising=False)

    try:
        yield
    finally:
        ExecutionPolicy.reset_instance()
        TargetAuthorizationGate.ALLOWED_TARGETS = orig_targets
        TargetAuthorizationGate._request_history.clear()
        for k, hist in orig_history.items():
            TargetAuthorizationGate._request_history[k] = hist


def assert_valid_sarif_210(sarif: Dict[str, Any], *, require_results: bool = False) -> None:
    """Validate OASIS SARIF 2.1.0 structure."""
    assert isinstance(sarif, dict), f"SARIF must be a dict, got {type(sarif)}"
    assert sarif.get("version") == "2.1.0", f"Invalid SARIF version: {sarif.get('version')!r}"
    schema = str(sarif.get("$schema") or "")
    assert "sarif-2.1.0" in schema, f"Unexpected SARIF $schema: {schema!r}"
    runs = sarif.get("runs")
    assert isinstance(runs, list) and len(runs) >= 1, "SARIF must have >= 1 run"
    run = runs[0]
    driver = (run.get("tool") or {}).get("driver") or {}
    assert driver.get("name"), "SARIF driver.name must be non-empty"
    rules = driver.get("rules")
    rule_ids: Optional[set[str]] = None
    if rules is not None:
        assert isinstance(rules, list), "SARIF driver.rules must be a list"
        rule_ids = {str(r.get("id")) for r in rules if isinstance(r, dict) and r.get("id")}
    results = run.get("results")
    assert isinstance(results, list), "SARIF run.results must be a list"
    if require_results:
        assert len(results) > 0, "Expected >= 1 SARIF result"
    for res in results:
        rid = str(res.get("ruleId") or "")
        assert rid, f"SARIF result missing ruleId: {res}"
        if rule_ids:
            assert rid in rule_ids, f"SARIF result ruleId {rid!r} not in driver.rules {rule_ids}"
        assert res.get("level") in ("error", "warning", "note", "none"), (
            f"Invalid SARIF level: {res.get('level')!r}"
        )
        locs = res.get("locations") or []
        if locs:
            phys = locs[0].get("physicalLocation") or {}
            art = phys.get("artifactLocation") or {}
            assert "uri" in art, f"SARIF location missing uri: {locs[0]}"


def assert_defensive_only_report(data: Any) -> None:
    """Ensure Z3 counterexamples and reports contain zero weaponized exploit scripts/commands."""
    if isinstance(data, str):
        serialized = data
    else:
        serialized = json.dumps(data, default=str)
    for pat in _WEAPONIZED_INDICATORS:
        m = pat.search(serialized)
        assert m is None, f"Weaponized indicator {m.group(0)!r} found in defensive report: {serialized[:400]}"


def _silent_subprocess_kwargs() -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "shell": False,
        "stdin": subprocess.DEVNULL,
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return kwargs


def resolve_scope_gatekeeper_bin() -> Path:
    """
    Resolve `rust_scope_gatekeeper[.exe]`, building it via `cargo build` once if
    the crate exists and the binary has not yet been compiled.
    """
    env_bin = os.environ.get("RFCHUNT_SCOPE_GATEKEEPER_BIN", "").strip()
    if env_bin:
        p = Path(env_bin)
        if p.is_file():
            return p

    crate_dir = REPO_ROOT / "rust_scope_gatekeeper"
    manifest = crate_dir / "Cargo.toml"
    assert manifest.is_file(), f"Missing Rust crate manifest: {manifest}"

    exe_name = "rust_scope_gatekeeper.exe" if os.name == "nt" else "rust_scope_gatekeeper"
    candidates = [
        crate_dir / "target" / "release" / exe_name,
        crate_dir / "target" / "debug" / exe_name,
    ]
    for cand in candidates:
        if cand.is_file():
            return cand

    cargo_exe = shutil.which("cargo")
    assert cargo_exe, "cargo executable not found on PATH"
    proc = subprocess.run(
        [cargo_exe, "build", "--manifest-path", str(manifest)],
        timeout=300,
        check=False,
        **_silent_subprocess_kwargs(),
    )
    assert proc.returncode == 0, f"cargo build failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    for cand in candidates:
        if cand.is_file():
            return cand
    raise AssertionError(f"Built cargo crate but binary not found in {candidates}")


def run_scope_gatekeeper_cli(
    payload: Union[str, Dict[str, Any]],
    *,
    bin_path: Optional[Path] = None,
    timeout_sec: float = 15.0,
) -> Tuple[int, str, str, Optional[Dict[str, Any]]]:
    """Execute the real `rust_scope_gatekeeper` binary with JSON stdin/stdout."""
    exe = bin_path or resolve_scope_gatekeeper_bin()
    raw_input = payload if isinstance(payload, str) else json.dumps(payload)
    kwargs = _silent_subprocess_kwargs()
    kwargs.pop("stdin", None)
    proc = subprocess.run(
        [str(exe)],
        input=raw_input,
        timeout=timeout_sec,
        check=False,
        **kwargs,
    )
    parsed: Optional[Dict[str, Any]] = None
    out_s = (proc.stdout or "").strip()
    if out_s:
        try:
            obj = json.loads(out_s)
            if isinstance(obj, dict):
                parsed = obj
        except json.JSONDecodeError:
            parsed = None
    return proc.returncode, proc.stdout or "", proc.stderr or "", parsed


def compile_rust_helper(tmp_path: Path, name: str, source_code: str) -> Path:
    """
    Compile a genuine single-file Rust binary using `rustc` inside `tmp_path`
    (never `.bat`/`.py` shims) so `shell=False` execution works natively on Windows.
    """
    rustc_exe = shutil.which("rustc")
    assert rustc_exe, "rustc executable not found on PATH"
    src_path = tmp_path / f"{name}.rs"
    src_path.write_text(source_code, encoding="utf-8")
    ext = ".exe" if os.name == "nt" else ""
    out_path = tmp_path / f"{name}{ext}"
    proc = subprocess.run(
        [rustc_exe, str(src_path), "-o", str(out_path)],
        timeout=120,
        check=False,
        **_silent_subprocess_kwargs(),
    )
    assert proc.returncode == 0, f"rustc failed for {name}:\n{proc.stderr}"
    assert out_path.is_file(), f"Compiled helper binary missing: {out_path}"
    return out_path


def run_revenue_cli_subprocess(
    args: Sequence[str],
    *,
    cwd: Path = REPO_ROOT,
    env_overrides: Optional[Dict[str, str]] = None,
    timeout_sec: float = 90.0,
) -> subprocess.CompletedProcess[str]:
    """Invoke `revenue_cli.py` as a real subprocess (`shell=False`)."""
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("RFCHUNT_OFFLINE", "1")
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-u", str(REPO_ROOT / "revenue_cli.py"), *args],
        cwd=str(cwd),
        env=env,
        timeout=timeout_sec,
        check=False,
        **_silent_subprocess_kwargs(),
    )


def _run_git(repo_dir: Path, args: Sequence[str], *, env_extra: Optional[Dict[str, str]] = None) -> None:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        env=env,
        timeout=30,
        check=False,
        **_silent_subprocess_kwargs(),
    )
    assert proc.returncode == 0, f"git {args} failed: {proc.stderr}"


def make_git_repo(
    base_dir: Path,
    name: str,
    files: Dict[str, Union[str, bytes]],
    *,
    commit_age_hours: float = 1.0,
    message: str = "initial commit",
) -> Path:
    """Create a real local git repository under `base_dir / name`."""
    repo_dir = base_dir / name
    repo_dir.mkdir(parents=True, exist_ok=True)
    _run_git(repo_dir, ["init"])
    _run_git(repo_dir, ["config", "user.email", "e2e-tester@rfchunt.local"])
    _run_git(repo_dir, ["config", "user.name", "RFCHunt E2E"])
    for rel_path, content in files.items():
        dest = repo_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            dest.write_bytes(content)
        else:
            dest.write_text(content, encoding="utf-8")
    commit_dt = datetime.now(timezone.utc) - timedelta(hours=float(commit_age_hours))
    iso_ts = commit_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    _run_git(repo_dir, ["add", "-A"])
    _run_git(
        repo_dir,
        ["commit", "-m", message],
        env_extra={"GIT_AUTHOR_DATE": iso_ts, "GIT_COMMITTER_DATE": iso_ts},
    )
    return repo_dir


@contextmanager
def start_loopback_ollama_server(
    models: Sequence[str],
    *,
    chat_responder: Optional[Callable[[Dict[str, Any]], Union[str, Dict[str, Any]]]] = None,
    openai_responder: Optional[Callable[[Dict[str, Any]], Union[str, Dict[str, Any]]]] = None,
) -> Iterator[Dict[str, Any]]:
    """
    Start a real local ThreadingHTTPServer on `127.0.0.1:0` speaking Ollama
    (`/api/tags`, `/api/chat`) and OpenAI-compatible (`/v1/chat/completions`).
    """
    requests_log: List[Dict[str, Any]] = []
    model_list = list(models)

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path.startswith("/api/tags"):
                self._send_json(
                    200,
                    {"models": [{"name": m, "model": m} for m in model_list]},
                )
                return
            self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                body = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                body = {"raw": raw}
            requests_log.append({"path": self.path, "body": body})

            if self.path.startswith("/api/chat"):
                reply: Union[str, Dict[str, Any]] = "{}"
                if chat_responder is not None:
                    reply = chat_responder(body)
                content = json.dumps(reply) if isinstance(reply, dict) else str(reply)
                self._send_json(
                    200,
                    {
                        "model": body.get("model") or (model_list[0] if model_list else "qwen2.5:7b"),
                        "message": {"role": "assistant", "content": content},
                        "done": True,
                    },
                )
                return

            if self.path.startswith("/v1/chat/completions"):
                fn = openai_responder or chat_responder
                reply = "I cannot assist with that request."
                if fn is not None:
                    reply = fn(body)
                content = json.dumps(reply) if isinstance(reply, dict) else str(reply)
                self._send_json(
                    200,
                    {
                        "id": "chatcmpl-loopback",
                        "object": "chat.completion",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": content},
                                "finish_reason": "stop",
                            }
                        ],
                    },
                )
                return

            self._send_json(404, {"error": "not found"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "url": f"http://127.0.0.1:{port}",
            "port": port,
            "requests": requests_log,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def sample_scope_policy(
    *,
    allowed_cidrs: Sequence[str] = ("192.0.2.0/24", "2001:db8::/32"),
    allowed_ports: Sequence[int] = (80, 443, 8443),
    blocked_patterns: Sequence[str] = ("DROP TABLE", "rm -rf", "--exploit", "weaponized"),
    blocked_methods: Sequence[str] = ("DELETE", "PUT", "PATCH", "DROP", "PURGE"),
    allow_destructive: bool = False,
) -> Dict[str, Any]:
    return {
        "allowed_cidrs": list(allowed_cidrs),
        "allowed_ports": list(allowed_ports),
        "blocked_patterns": list(blocked_patterns),
        "blocked_methods": list(blocked_methods),
        "allow_destructive": allow_destructive,
    }


def sample_scope_intent(
    *,
    target_url: str = "https://192.0.2.10:443/api/v1/status",
    host: str = "192.0.2.10",
    port: int = 443,
    method: str = "GET",
    action: str = "formal_verify",
    payload_preview: str = "",
    command: str = "",
) -> Dict[str, Any]:
    return {
        "target_url": target_url,
        "host": host,
        "port": port,
        "method": method,
        "action": action,
        "payload_preview": payload_preview,
        "command": command,
    }


def make_scope_request(
    *,
    policy: Optional[Dict[str, Any]] = None,
    intent: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "policy": policy if policy is not None else sample_scope_policy(),
        "intent": intent if intent is not None else sample_scope_intent(),
    }


def openapi_auth_bypass_yaml() -> str:
    return (
        "openapi: 3.0.3\n"
        "info:\n"
        "  title: SaaS Admin API\n"
        "  version: '1.0'\n"
        "components:\n"
        "  securitySchemes:\n"
        "    bearerAuth:\n"
        "      type: http\n"
        "      scheme: bearer\n"
        "paths:\n"
        "  /health:\n"
        "    get:\n"
        "      summary: Health check\n"
        "      security: []\n"
        "      responses:\n"
        "        '200':\n"
        "          description: OK\n"
        "  /admin/users:\n"
        "    get:\n"
        "      summary: Admin user listing missing auth\n"
        "      x-roles:\n"
        "        - guest\n"
        "        - admin\n"
        "      responses:\n"
        "        '200':\n"
        "          description: Users\n"
    )


def openapi_hardened_yaml() -> str:
    return (
        "openapi: 3.0.3\n"
        "info:\n"
        "  title: Hardened Admin API\n"
        "  version: '1.0'\n"
        "components:\n"
        "  securitySchemes:\n"
        "    bearerAuth:\n"
        "      type: http\n"
        "      scheme: bearer\n"
        "security:\n"
        "  - bearerAuth: []\n"
        "paths:\n"
        "  /admin/users:\n"
        "    get:\n"
        "      summary: Admin user listing\n"
        "      security:\n"
        "        - bearerAuth: []\n"
        "      x-roles:\n"
        "        - admin\n"
        "      responses:\n"
        "        '200':\n"
        "          description: Users\n"
    )


def iam_escalation_policy_dict() -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "LowPrivEscalation",
                "Effect": "Allow",
                "Principal": {"AWS": "role/tenant_a_support"},
                "Action": ["iam:AttachUserPolicy", "iam:PassRole"],
                "Resource": "*",
            }
        ],
    }


def iam_hardened_policy_dict() -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadOnlyLogs",
                "Effect": "Allow",
                "Principal": {"AWS": "role/analyst"},
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::tenant-a-logs/*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            },
            {
                "Sid": "ExplicitDenyAdmin",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["iam:*", "admin:*"],
                "Resource": "*",
            },
        ],
    }


def state_machine_vuln_dict() -> Dict[str, Any]:
    return {
        "states": ["anon", "user", "billing", "admin"],
        "initial_state": "anon",
        "privileged_states": ["admin"],
        "transitions": [
            {"from": "anon", "to": "user", "action": "login", "required_auth": True, "guards": {"auth": True}},
            {"from": "anon", "to": "admin", "action": "debug_promote", "required_auth": False, "guards": {}},
            {"from": "user", "to": "billing", "action": "view_billing", "required_auth": True, "guards": {"auth": True}},
        ],
    }


def state_machine_safe_dict() -> Dict[str, Any]:
    return {
        "states": ["anon", "user", "admin"],
        "initial_state": "anon",
        "privileged_states": ["admin"],
        "transitions": [
            {"from": "anon", "to": "user", "action": "login", "required_auth": True, "guards": {"auth": True}},
            {
                "from": "user",
                "to": "admin",
                "action": "elevate",
                "required_auth": True,
                "required_roles": ["admin"],
                "same_tenant_required": True,
                "guards": {"auth": True, "mfa_verified": True, "same_tenant": True},
            },
        ],
    }
