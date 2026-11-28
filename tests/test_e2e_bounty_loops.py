"""
Opaque-Box 4-Tier End-to-End Test Suite for RFCHunt Duplicate-Beating Bounty Engine
===================================================================================

Covers all 216 specified test cases across:
  - Tier 1 (95 cases): Core feature & R5 compliance coverage (5 per feature F1-F18 + R5)
  - Tier 2 (95 cases): Boundary, corner, error & fail-closed cases (5 per feature F1-F18 + R5)
  - Tier 3 (20 cases): Pairwise cross-feature & cross-loop integration (T3-01 .. T3-20)
  - Tier 4 (6 cases):  Real-world end-to-end bounty loop application scenarios (T4-S1 .. T4-S6)
  - Optional live-Ollama benchmark (skips cleanly if RFCHUNT_LIVE_OLLAMA_BENCH != '1' or offline)

Strict Engineering Invariants:
  - Zero mocks: uses real SQLite WAL DBs, real ThreadingHTTPServer loopback servers,
    real multiprocessing 'spawn' pools, real git temp repos, real CLI & MCP entrypoints.
  - Zero Registry or system PATH mutations.
  - All async calls executed via asyncio.run() (no pytest-asyncio dependency).
  - Sequential Windows pytest safe (`-o addopts="" --basetemp <isolated_dir>`).
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import inspect
import json
import math
import multiprocessing as mp
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
import urllib.error
import urllib.request
import zipfile

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bugbounty_mcp_server import (  # noqa: E402
    BugBountyMCPServer,
    TOOLS_SCHEMA,
    validate_and_stage_hackerone_draft,
)
from engine.advisory_exporter import neutralize_csv_cell  # noqa: E402
from engine.client_audit_packager import ClientAuditPackager  # noqa: E402
from engine.ensemble_orchestrator import (  # noqa: E402
    ENGINE_WEIGHTS,
    EngineFinding,
    EnsembleConsensusVoter,
    EnsembleOrchestrator,
    evaluate_vendor_threat_model,
)
from engine.execution_policy import _validate_canonical_path_syntax  # noqa: E402
from engine.freshness_watcher import WatchTarget  # noqa: E402
from engine.linux_poc_runner import (  # noqa: E402
    LinuxPocRunner,
    VerifiableTranscript,
    build_hardened_docker_argv,
    probe_optional_backends,
    save_transcript_bundle,
    validate_command_tokens,
    validate_mount_path,
)
from engine.program_eligibility_db import ProgramEligibilityDB  # noqa: E402
from engine.safe_network_validator import validate_target_host  # noqa: E402
import revenue_cli  # noqa: E402


# ---------------------------------------------------------------------------
# Zero-Mock Real-Substrate Helpers (Git, HTTPServer, Field Accessors, Async)
# ---------------------------------------------------------------------------


def _fget(item: Any, key: str, default: Any = None) -> Any:
    """Reads attribute or dict key transparently across dict / EngineFinding outputs."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _any_text_contains(findings: Sequence[Any], needle: str) -> bool:
    for item in findings:
        if needle in str(_fget(item, "summary", "")) or needle in json.dumps(
            _fget(item, "metadata", {}) or {}, default=str
        ):
            return True
    return False


def _git_run(repo: Path, *args: str, env_extra: Optional[Dict[str, str]] = None) -> str:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=True,
    )
    return proc.stdout


def _init_git_repo(
    repo: Path,
    files: Dict[str, Union[str, bytes]],
    *,
    commit_msg: str = "feat: initial commit",
    age_hours: int = 1,
) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    _git_run(repo, "init")
    _git_run(repo, "config", "user.email", "e2e@rfchunt.local")
    _git_run(repo, "config", "user.name", "RFCHunt E2E")
    for rel_path, content in files.items():
        target = repo / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    _git_run(repo, "add", "-A")
    commit_epoch = int(time.time()) - max(0, age_hours) * 3600
    ts_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(commit_epoch))
    _git_run(
        repo,
        "commit",
        "-m",
        commit_msg,
        env_extra={"GIT_AUTHOR_DATE": ts_str, "GIT_COMMITTER_DATE": ts_str},
    )
    return repo


@contextlib.contextmanager
def _scoped_env(**updates: Optional[str]):
    """Process-scoped env var manager that always restores prior values."""
    saved: Dict[str, Optional[str]] = {}
    for k, v in updates.items():
        saved[k] = os.environ.get(k)
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, old in saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


@contextlib.contextmanager
def _github_etag_server(route_state: Dict[str, Any]):
    """
    Real ThreadingHTTPServer implementing GitHub REST API with ETag / If-None-Match.
    `route_state` maps path -> dict(status=200, etag='"v1"', body=..., raw_bytes=...).
    Records every request in `route_state["__requests__"]`.
    """
    route_state.setdefault("__requests__", [])
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            inm = self.headers.get("If-None-Match")
            with lock:
                route_state["__requests__"].append(
                    {"path": self.path, "if_none_match": inm, "ts": time.monotonic()}
                )
                entry = route_state.get(self.path)
            if entry is None:
                self.send_response(404)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
                return
            status = int(entry.get("status", 200))
            etag = entry.get("etag")
            if status == 200 and etag and inm == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.end_headers()
                return
            if "raw_bytes" in entry:
                raw = bytes(entry["raw_bytes"])
            else:
                raw = json.dumps(entry.get("body", {})).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if etag:
                self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}", route_state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@contextlib.contextmanager
def _ollama_loopback_server(config: Dict[str, Any]):
    """
    Real ThreadingHTTPServer simulating Ollama `/api/tags` and `/api/chat`.
    Supports configurable OOM 500 responses per model, verdict overrides,
    concurrency tracking (`max_inflight`), and artificial chat latency.
    """
    state: Dict[str, Any] = {
        "tags_calls": 0,
        "chat_calls": [],
        "inflight": 0,
        "max_inflight": 0,
    }
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/api/tags":
                delay = float(config.get("tags_delay_sec", 0.0))
                if delay > 0:
                    time.sleep(delay)
                with lock:
                    state["tags_calls"] += 1
                models = [{"name": m} for m in config.get("models", ["qwen2.5:7b"])]
                raw = json.dumps({"models": models}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/api/chat":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0") or 0)
            req_raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                req_json = json.loads(req_raw.decode("utf-8"))
            except Exception:
                req_json = {}
            model = str(req_json.get("model") or "")

            with lock:
                state["inflight"] += 1
                if state["inflight"] > state["max_inflight"]:
                    state["max_inflight"] = state["inflight"]
                state["chat_calls"].append({"model": model, "ts": time.monotonic()})

            try:
                chat_delay = float(config.get("chat_delay_sec", 0.02))
                if chat_delay > 0:
                    time.sleep(chat_delay)

                oom_models = set(config.get("oom_models", []))
                if config.get("always_oom") or model in oom_models:
                    err_raw = json.dumps(
                        {"error": "model requires more system memory (CUDA out of memory)"}
                    ).encode("utf-8")
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_raw)))
                    self.end_headers()
                    self.wfile.write(err_raw)
                    return

                if config.get("non_json_500"):
                    err_raw = b"Internal Server Error"
                    self.send_response(500)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(err_raw)))
                    self.end_headers()
                    self.wfile.write(err_raw)
                    return

                verdict_confirmed = bool(config.get("verdict_confirmed", True))
                payload = {
                    "model": model,
                    "done": True,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "verdicts": [
                                    {
                                        "gha_class": "pwn_request",
                                        "file_path": config.get("verdict_file", "src/app.py"),
                                        "line": 10,
                                        "confirmed": verdict_confirmed,
                                        "severity": "HIGH",
                                        "confidence": 0.85 if verdict_confirmed else 0.20,
                                        "false_positive_reason": "" if verdict_confirmed else "LLM dissent",
                                        "recommended_fix": "Enforce strict validation.",
                                    }
                                ],
                                "attack_chains": [],
                            }
                        ),
                    },
                }
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            finally:
                with lock:
                    state["inflight"] -= 1

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@contextlib.contextmanager
def _sandbox_target_server():
    """Real ThreadingHTTPServer recording headers and timestamps for sandbox probe tests."""
    records: List[Dict[str, Any]] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            with lock:
                records.append(
                    {
                        "method": "GET",
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "ts": time.monotonic(),
                    }
                )
            body = json.dumps({"ok": True, "path": self.path}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}", records
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _make_candidate_result(
    CandidateResultCls: Any,
    *,
    name: str,
    metric: float,
    train_time_s: float = 1.0,
    peak_mem_mb: float = 16.0,
    latency_ms_per_row: float = 0.5,
    risk_penalty: float = 0.1,
    robustness_drop: float = 0.05,
) -> Any:
    """Constructs CandidateResult aligned with ACDSO/pareto.py 6-objective layout."""
    def _safe_log(val: float) -> float:
        if math.isnan(val) or math.isinf(val):
            return val
        return math.log1p(max(0.0, val))

    objectives = (
        metric,
        _safe_log(train_time_s),
        _safe_log(peak_mem_mb),
        _safe_log(latency_ms_per_row),
        risk_penalty,
        robustness_drop,
    )
    sig = inspect.signature(CandidateResultCls)
    kwargs: Dict[str, Any] = {}
    for pname in sig.parameters:
        if pname == "name":
            kwargs[pname] = name
        elif pname == "pipeline":
            kwargs[pname] = None
        elif pname == "metric":
            kwargs[pname] = metric
        elif pname == "train_time_s":
            kwargs[pname] = train_time_s
        elif pname == "peak_mem_mb":
            kwargs[pname] = peak_mem_mb
        elif pname == "latency_ms_per_row":
            kwargs[pname] = latency_ms_per_row
        elif pname == "risk_penalty":
            kwargs[pname] = risk_penalty
        elif pname == "robustness_drop":
            kwargs[pname] = robustness_drop
        elif pname == "objectives":
            kwargs[pname] = objectives
        elif pname == "meta":
            kwargs[pname] = {"robustness_drop": robustness_drop}
    return CandidateResultCls(**kwargs)


def _invoke_two_lane_scheduler(
    scheduler: Any,
    *,
    queue_capacity: int,
    signal: float,
    actions: Optional[Sequence[int]] = None,
    rewards: Optional[Sequence[float]] = None,
) -> Tuple[int, int]:
    """Invokes TwoLanePolicyScheduler cleanly regardless of method alias."""
    if actions is not None and rewards is not None:
        for fit_name in ("fit", "update", "train"):
            fit_fn = getattr(scheduler, fit_name, None)
            if callable(fit_fn):
                try:
                    fit_fn(actions=list(actions), rewards=list(rewards))
                except TypeError:
                    fit_fn(list(actions), list(rewards))
                break

    for mname in ("allocate_slots", "allocate", "schedule", "compute_slots", "plan_slots", "select_slots"):
        fn = getattr(scheduler, mname, None)
        if callable(fn):
            sig = inspect.signature(fn)
            kw: Dict[str, Any] = {}
            if "queue_capacity" in sig.parameters:
                kw["queue_capacity"] = queue_capacity
            elif "capacity" in sig.parameters:
                kw["capacity"] = queue_capacity
            if "signal" in sig.parameters:
                kw["signal"] = signal
            elif "signal_score" in sig.parameters:
                kw["signal_score"] = signal
            res = fn(**kw) if kw else fn(queue_capacity, signal)
            if isinstance(res, dict):
                return int(res["lane1_slots"]), int(res["lane2_slots"])
            return int(res[0]), int(res[1])
    if callable(scheduler):
        res = scheduler(queue_capacity, signal)
        if isinstance(res, dict):
            return int(res["lane1_slots"]), int(res["lane2_slots"])
        return int(res[0]), int(res[1])
    raise AttributeError("TwoLanePolicyScheduler has no recognized allocation method")


def _invoke_poller_once(
    poller: Any,
    targets: Sequence[WatchTarget],
    *,
    eligibility_db: Optional[ProgramEligibilityDB] = None,
    blackboard: Any = None,
    api_base: Optional[str] = None,
    http_get: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    fn = getattr(poller, "poll_once")
    sig = inspect.signature(fn)
    kw: Dict[str, Any] = {}
    if "eligibility_db" in sig.parameters:
        kw["eligibility_db"] = eligibility_db
    if "blackboard" in sig.parameters:
        kw["blackboard"] = blackboard
    if "http_get" in sig.parameters and http_get is not None:
        kw["http_get"] = http_get
    if "api_base" in sig.parameters and api_base is not None:
        kw["api_base"] = api_base
    res = fn(targets, **kw)
    if inspect.isawaitable(res):
        res = asyncio.run(res)
    return res


def _make_real_http_get(api_base: str) -> Callable[..., Any]:
    """Real urllib-based HTTP getter hitting loopback ThreadingHTTPServer."""
    def _http_get(url_or_path: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
        url = url_or_path if url_or_path.startswith("http") else f"{api_base.rstrip('/')}/{url_or_path.lstrip('/')}"
        req = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return int(resp.status), hdrs, resp.read()
        except urllib.error.HTTPError as exc:
            hdrs = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            return int(exc.code), hdrs, exc.read() if exc.fp else b""

    return _http_get


def _build_poller(AsyncFreshnessPollerCls: Any, *, api_base: str, state_db: Path) -> Any:
    sig = inspect.signature(AsyncFreshnessPollerCls)
    kw: Dict[str, Any] = {}
    if "api_base" in sig.parameters:
        kw["api_base"] = api_base
    if "state_db" in sig.parameters:
        kw["state_db"] = state_db
    elif "db_path" in sig.parameters:
        kw["db_path"] = state_db
    return AsyncFreshnessPollerCls(**kw)


def _close_if_supported(obj: Any) -> None:
    close_fn = getattr(obj, "close", None)
    if callable(close_fn):
        close_fn()


def _call_validate_and_stage_draft(
    *, elig: Optional[ProgramEligibilityDB] = None, **kwargs: Any
) -> Dict[str, Any]:
    sig = inspect.signature(validate_and_stage_hackerone_draft)
    call_kw = dict(kwargs)
    if elig is not None:
        if "eligibility_db" in sig.parameters:
            call_kw["eligibility_db"] = elig
        elif "eligibility_db_path" in sig.parameters:
            call_kw["eligibility_db_path"] = str(elig.db_path)
    return validate_and_stage_hackerone_draft(**call_kw)


def _call_verify_gha_with_optional_guard(
    target_path: Path,
    static_findings: Sequence[Any],
    *,
    guard: Any = None,
    **kwargs: Any,
) -> Tuple[List[Any], Dict[str, Any]]:
    from engine.gha_llm_verifier import verify_gha_findings_with_llm
    from engine.ollama_concurrency_guard import get_shared_ollama_guard

    sig = inspect.signature(verify_gha_findings_with_llm)
    call_kw = dict(kwargs)
    if guard is not None and "guard" in sig.parameters:
        call_kw["guard"] = guard
    try:
        return verify_gha_findings_with_llm(target_path, static_findings, **call_kw)
    finally:
        if guard is None or "guard" not in sig.parameters:
            shared = get_shared_ollama_guard()
            shared.record_success()


@pytest.fixture(autouse=True)
def _reset_shared_ollama_guard() -> Any:
    from engine.ollama_concurrency_guard import get_shared_ollama_guard

    shared = get_shared_ollama_guard()
    shared.reset()
    try:
        yield
    finally:
        shared.reset()


# ===========================================================================
# TIER 1: CORE FEATURE & R5 COMPLIANCE COVERAGE (95 TEST CASES)
# ===========================================================================


# --- F1: TruffleHog Verified Secret Scanner (5 cases) ---


def test_tier1_f1_01_trufflehog_detects_and_redacts_github_pat(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    pat = "ghp_" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8"
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.js").write_text(
        f'export const GH_TOKEN = "{pat}";\n', encoding="utf-8"
    )
    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert any(_fget(f, "engine") == "trufflehog" for f in findings)
    assert all(bool(_fget(f, "deterministic")) for f in findings)
    assert not _any_text_contains(findings, pat)


def test_tier1_f1_02_trufflehog_detects_anthropic_key_and_marks_prod(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    key = "sk-ant-" + "api03-" + "X9Y8Z7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2H1G0"
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "client.py").write_text(f'API_KEY = "{key}"\n', encoding="utf-8")
    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert any(not bool(_fget(f, "non_production_noise", False)) for f in findings)
    assert not _any_text_contains(findings, key)


def test_tier1_f1_03_trufflehog_detects_and_redacts_pem_private_key(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    pem_body = "MIIEowIBAAKCAQEA7V5kL9mN2pQ4rS6tU8vW0xY2zA4bC6dE8fG0hI2jK4lM6nO8"
    pem = (
        "-----BEGIN RSA " + "PRIVATE KEY-----\n"
        + pem_body
        + "\n-----END RSA " + "PRIVATE KEY-----\n"
    )
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "server.key").write_text(pem, encoding="utf-8")
    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert not _any_text_contains(findings, pem_body)


def test_tier1_f1_04_trufflehog_clean_repo_returns_empty(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8"
    )
    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True)
    assert findings == []


def test_tier1_f1_05_trufflehog_embedded_offline_parity(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    tok = "sk_live_" + "Q9W8E7R6T5Y4U3I2O1P0A9S8D7F6G5H4"
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "pay.ts").write_text(f'const k = "{tok}";\n', encoding="utf-8")
    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert all(_fget(f, "engine") == "trufflehog" for f in findings)
    assert not _any_text_contains(findings, tok)


# --- F2: MobSF + jadx Mobile App Auditor (5 cases) ---


def test_tier1_f2_01_mobile_detects_exported_android_activity(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.eudi.wallet">\n'
        '  <application android:allowBackup="false">\n'
        '    <activity android:name=".AuthWeb" android:exported="true" />\n'
        '  </application>\n'
        '</manifest>\n'
    )
    (tmp_path / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    findings = audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert any(_fget(f, "engine") == "mobile_mobsf" for f in findings)
    assert all(bool(_fget(f, "deterministic")) for f in findings)


def test_tier1_f2_02_mobile_detects_unvalidated_openid4vci_deeplink(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    kt = (
        "package com.eudi.wallet\n"
        "class DeepLinkActivity {\n"
        "  fun onCreate(uriStr: String) {\n"
        '    if (uriStr.startsWith("openid4vci://")) {\n'
        "      launchCredentialFlow(uriStr)\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    (tmp_path / "DeepLinkActivity.kt").write_text(kt, encoding="utf-8")
    findings = audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert any("openid4" in str(_fget(f, "title", "") + _fget(f, "summary", "")).lower() or "deep" in str(_fget(f, "title", "") + _fget(f, "summary", "")).lower() for f in findings)


def test_tier1_f2_03_mobile_detects_insecure_android_webview(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    java_src = (
        "public class Web {\n"
        "  void init(WebView w) {\n"
        "    w.getSettings().setJavaScriptEnabled(true);\n"
        "    w.getSettings().setAllowFileAccessFromFileURLs(true);\n"
        '    w.addJavascriptInterface(new Bridge(), "NativeBridge");\n'
        "  }\n"
        "}\n"
    )
    (tmp_path / "Web.java").write_text(java_src, encoding="utf-8")
    findings = audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert any("webview" in str(_fget(f, "title", "") + _fget(f, "summary", "")).lower() for f in findings)


def test_tier1_f2_04_mobile_detects_ios_ats_disabled(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    plist = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<plist version="1.0"><dict>\n'
        '<key>NSAppTransportSecurity</key>\n'
        '<dict><key>NSAllowsArbitraryLoads</key><true/></dict>\n'
        '</dict></plist>\n'
    )
    (tmp_path / "Info.plist").write_text(plist, encoding="utf-8")
    findings = audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert any(_fget(f, "engine") == "mobile_mobsf" for f in findings)


def test_tier1_f2_05_mobile_hardened_manifest_and_plist_clean(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.eudi.safe">\n'
        '  <application android:allowBackup="false" android:usesCleartextTraffic="false">\n'
        '    <activity android:name=".Main" android:exported="false" />\n'
        '  </application>\n'
        '</manifest>\n'
    )
    plist = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<plist version="1.0"><dict>\n'
        '<key>NSAppTransportSecurity</key>\n'
        '<dict><key>NSAllowsArbitraryLoads</key><false/></dict>\n'
        '</dict></plist>\n'
    )
    (tmp_path / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    (tmp_path / "Info.plist").write_text(plist, encoding="utf-8")
    findings = audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    high_or_med = [f for f in findings if str(_fget(f, "severity", "")).upper() in ("CRITICAL", "HIGH", "MEDIUM")]
    assert high_or_med == []


# --- F3: API Surface + JWT/SD-JWT Auditor (5 cases) ---


def test_tier1_f3_01_api_jwt_detects_alg_none_and_unverified_sig(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    (tmp_path / "auth.py").write_text(
        'import jwt\ndef parse(tok):\n    return jwt.decode(tok, options={"verify_signature": False}, algorithms=["none", "HS256"])\n',
        encoding="utf-8",
    )
    findings = audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert any(_fget(f, "engine") == "api_jwt_sdjwt" for f in findings)


def test_tier1_f3_02_api_jwt_detects_rs256_hs256_key_confusion(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    (tmp_path / "verify.js").write_text(
        "const jwt = require('jsonwebtoken');\n"
        "function check(tok, rsaPublicKey) {\n"
        "  return jwt.verify(tok, rsaPublicKey, { algorithms: ['RS256', 'HS256'] });\n"
        "}\n",
        encoding="utf-8",
    )
    findings = audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert all(bool(_fget(f, "deterministic")) for f in findings)


def test_tier1_f3_03_api_jwt_detects_jku_ssrf_and_kid_traversal(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    (tmp_path / "jwt_helper.py").write_text(
        "import requests, jwt\n"
        "def load_key(tok):\n"
        "    hdr = jwt.get_unverified_header(tok)\n"
        '    jwks = requests.get(hdr["jku"]).json()\n'
        '    key_path = f"/keys/{hdr[\'kid\']}.pem"\n'
        "    return jwks, key_path\n",
        encoding="utf-8",
    )
    findings = audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1


def test_tier1_f3_04_api_sdjwt_detects_missing_cnf_key_binding(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    (tmp_path / "sdjwt_verifier.py").write_text(
        "def verify_sd_jwt_presentation(sd_jwt_token, kb_jwt):\n"
        "    # Accepts SD-JWT without validating cnf holder binding or nonce\n"
        "    issuer_jwt, disclosures = sd_jwt_token.split('~')[0], sd_jwt_token.split('~')[1:]\n"
        "    return {'issuer': issuer_jwt, 'disclosures': disclosures}\n",
        encoding="utf-8",
    )
    findings = audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1


def test_tier1_f3_05_api_jwt_secure_es256_verifier_clean(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    (tmp_path / "secure_auth.py").write_text(
        "import jwt\n"
        "def verify_token(tok, pub_key):\n"
        "    return jwt.decode(\n"
        "        tok,\n"
        "        pub_key,\n"
        '        algorithms=["ES256"],\n'
        '        audience="wallet-api",\n'
        '        issuer="https://idp.example.org",\n'
        '        options={"require": ["exp", "aud", "iss"], "verify_signature": True},\n'
        "    )\n",
        encoding="utf-8",
    )
    findings = audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True)
    high_or_crit = [f for f in findings if str(_fget(f, "severity", "")).upper() in ("CRITICAL", "HIGH")]
    assert high_or_crit == []


# --- F4: AI-Infra-Guard & DeepAudit Static Auditor (5 cases) ---


def test_tier1_f4_01_ai_infra_detects_unauthenticated_0000_serving(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  ollama:\n"
        "    image: ollama/ollama:0.5.0\n"
        "    environment:\n"
        "      - OLLAMA_HOST=0.0.0.0:11434\n"
        "    ports:\n"
        '      - "0.0.0.0:11434:11434"\n',
        encoding="utf-8",
    )
    findings = audit_ai_infra(tmp_path)
    assert len(findings) >= 1
    assert any(_fget(f, "engine") == "ai_infra_guard" for f in findings)


def test_tier1_f4_02_ai_infra_detects_unsafe_pickle_and_torch_load(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "loader.py").write_text(
        "import pickle, torch\n"
        "def load_weights(raw_bytes, ckpt_path):\n"
        "    obj = pickle.loads(raw_bytes)\n"
        "    weights = torch.load(ckpt_path, weights_only=False)\n"
        "    return obj, weights\n",
        encoding="utf-8",
    )
    findings = audit_ai_infra(tmp_path)
    assert len(findings) >= 1
    assert all(bool(_fget(f, "deterministic")) for f in findings)


def test_tier1_f4_03_ai_infra_detects_jinja2_ssti_in_prompt(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "prompt.py").write_text(
        "import jinja2\n"
        "def format_prompt(user_prompt: str) -> str:\n"
        "    return jinja2.Template(user_prompt).render()\n",
        encoding="utf-8",
    )
    findings = audit_ai_infra(tmp_path)
    assert len(findings) >= 1


def test_tier1_f4_04_ai_infra_detects_privileged_k8s_and_docker_sock(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: runner\n"
        "          image: vllm/vllm-openai:latest\n"
        "          securityContext:\n"
        "            privileged: true\n"
        "          volumeMounts:\n"
        "            - mountPath: /var/run/docker.sock\n"
        "              name: dockersock\n"
        "      volumes:\n"
        "        - name: dockersock\n"
        "          hostPath:\n"
        "            path: /var/run/docker.sock\n",
        encoding="utf-8",
    )
    findings = audit_ai_infra(tmp_path)
    assert len(findings) >= 1


def test_tier1_f4_05_ai_infra_hardened_config_clean(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: runner\n"
        "          image: python@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
        "          securityContext:\n"
        "            privileged: false\n"
        "            readOnlyRootFilesystem: true\n",
        encoding="utf-8",
    )
    (tmp_path / "safe_loader.py").write_text(
        "import torch\n"
        "def load_safe(p):\n"
        "    return torch.load(p, weights_only=True)\n",
        encoding="utf-8",
    )
    findings = audit_ai_infra(tmp_path)
    assert findings == []


# --- F5: Sibling Parity & Invariant Auditor (5 cases) ---


def test_tier1_f5_01_parity_detects_sibling_package_guard_asymmetry(tmp_path: Path) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    (tmp_path / "packages" / "apps" / "app-a").mkdir(parents=True)
    (tmp_path / "packages" / "apps" / "app-b").mkdir(parents=True)
    (tmp_path / "packages" / "apps" / "app-a" / "auth.ts").write_text(
        "export function handleInbound(req: any) {\n"
        "  verifySignature(req);\n"
        "  const clean = sanitizeInput(req.body);\n"
        "  return processPayload(clean);\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "packages" / "apps" / "app-b" / "auth.ts").write_text(
        "export function handleInbound(req: any) {\n"
        "  return processPayload(req.body);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = audit_parity_and_invariants(tmp_path)
    assert len(findings) >= 1
    assert any(_fget(f, "engine") == "parity_auditor" for f in findings)
    assert any("app-b" in str(_fget(f, "file_path", "") + _fget(f, "summary", "")) for f in findings)


def test_tier1_f5_02_parity_detects_same_file_handler_asymmetry(tmp_path: Path) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    (tmp_path / "src" / "handlers").mkdir(parents=True)
    (tmp_path / "src" / "handlers" / "webhook.ts").write_text(
        "export function handleButton(sender: string, allowFrom: string[]) {\n"
        "  if (!allowFrom.includes(sender)) throw new Error('denied');\n"
        "  return executeAction(sender);\n"
        "}\n"
        "export function handleText(sender: string, allowFrom: string[]) {\n"
        "  return executeAction(sender);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = audit_parity_and_invariants(tmp_path)
    assert len(findings) >= 1
    assert any("handleText" in str(_fget(f, "summary", "") + _fget(f, "title", "")) for f in findings)


def test_tier1_f5_03_parity_symmetric_sibling_packages_clean(tmp_path: Path) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    for pkg in ("app-a", "app-b"):
        pdir = tmp_path / "packages" / "apps" / pkg
        pdir.mkdir(parents=True)
        (pdir / "render.ts").write_text(
            "export function renderAppBridge(req: any) {\n"
            "  verifySignature(req);\n"
            "  return sanitizeInput(req.body);\n"
            "}\n",
            encoding="utf-8",
        )
    findings = audit_parity_and_invariants(tmp_path)
    assert findings == []


def test_tier1_f5_04_parity_target_files_scoping(tmp_path: Path) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    (tmp_path / "packages" / "apps" / "app-a").mkdir(parents=True)
    (tmp_path / "packages" / "apps" / "app-b").mkdir(parents=True)
    (tmp_path / "packages" / "apps" / "app-a" / "auth.ts").write_text(
        "export function authenticate(req: any) { verifySignature(req); return sanitizeInput(req); }\n",
        encoding="utf-8",
    )
    (tmp_path / "packages" / "apps" / "app-b" / "auth.ts").write_text(
        "export function authenticate(req: any) { return req; }\n",
        encoding="utf-8",
    )
    findings = audit_parity_and_invariants(
        tmp_path, target_files=["packages/apps/app-b/auth.ts"]
    )
    assert len(findings) >= 1


def test_tier1_f5_05_parity_single_package_no_siblings_returns_empty(tmp_path: Path) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text(
        "export function main() { return 42; }\n", encoding="utf-8"
    )
    assert audit_parity_and_invariants(tmp_path) == []


# --- F6: Ollama Concurrency Guard + OOM Downshift (5 cases) ---


def test_tier1_f6_01_ollama_guard_serializes_concurrent_slot_access(tmp_path: Path) -> None:
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    lock_file = tmp_path / "ollama_slot.lock"
    guard = OllamaConcurrencyGuard(lock_path=lock_file, acquire_timeout_sec=10.0)
    with _ollama_loopback_server({"models": ["qwen2.5:7b"], "chat_delay_sec": 0.08}) as (
        endpoint,
        state,
    ):
        errors: List[Exception] = []

        def _worker() -> None:
            try:
                with guard.acquire():
                    req = urllib.request.Request(
                        f"{endpoint}/api/chat",
                        data=json.dumps({"model": "qwen2.5:7b", "messages": []}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=5.0) as resp:
                        assert resp.status == 200
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
        assert not errors
        assert len(state["chat_calls"]) == 3
        assert state["max_inflight"] == 1


def test_tier1_f6_02_ollama_guard_is_oom_500_detection(tmp_path: Path) -> None:
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    guard = OllamaConcurrencyGuard(lock_path=tmp_path / "oom.lock")
    assert guard.is_oom_500(500, "model requires more system memory (CUDA out of memory)") is True
    assert guard.is_oom_500(500, "unable to allocate CUDA0 buffer") is True
    assert guard.is_oom_500(200, "ok") is False


def test_tier1_f6_03_ollama_guard_downshift_candidates_ladder(tmp_path: Path) -> None:
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    guard = OllamaConcurrencyGuard(lock_path=tmp_path / "downshift.lock")
    installed = ["gemma-4-12b-abliterated", "qwen2.5:7b", "qwen2.5:3b", "qwen2.5:1.5b"]
    cands = guard.downshift_candidates("gemma-4-12b-abliterated", installed)
    assert "gemma-4-12b-abliterated" not in cands
    assert cands == ["qwen2.5:7b", "qwen2.5:3b", "qwen2.5:1.5b"]


def test_tier1_f6_04_gha_llm_verifier_downshifts_immediately_on_oom_500(tmp_path: Path) -> None:
    from engine.gha_llm_verifier import verify_gha_findings_with_llm

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("on: pull_request_target\njobs: {}\n", encoding="utf-8")
    static_f = [
        EngineFinding(
            engine="zizmor",
            title="pwn_request",
            file_path=".github/workflows/ci.yml",
            line=1,
            severity="HIGH",
        )
    ]
    cfg = {
        "models": ["gemma-4-12b-abliterated", "qwen2.5:7b", "qwen2.5:3b"],
        "oom_models": ["gemma-4-12b-abliterated"],
        "verdict_file": ".github/workflows/ci.yml",
    }
    with _ollama_loopback_server(cfg) as (endpoint, state):
        out_findings, telemetry = verify_gha_findings_with_llm(
            tmp_path,
            static_f,
            model="gemma-4-12b-abliterated",
            ollama_endpoint=endpoint,
            env_local_path=tmp_path / "missing.env",
            force_ollama=True,
        )
        assert telemetry.get("status") == "completed"
        assert len(out_findings) >= 1
        called_models = [c["model"] for c in state["chat_calls"]]
        assert called_models.count("gemma-4-12b-abliterated") == 1
        assert "qwen2.5:7b" in called_models or "qwen2.5:3b" in called_models


def test_tier1_f6_05_ollama_guard_success_resets_failure_counter(tmp_path: Path) -> None:
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard, get_shared_ollama_guard

    guard = OllamaConcurrencyGuard(
        lock_path=tmp_path / "reset.lock", failure_threshold=2, cooldown_sec=60.0
    )
    guard.record_failure(is_oom=True)
    assert guard.is_circuit_open() is False
    guard.record_success()
    guard.record_failure(is_oom=True)
    assert guard.is_circuit_open() is False
    assert isinstance(get_shared_ollama_guard(), OllamaConcurrencyGuard)


# --- F7: probe_optional_backends() + Sandbox HTTP Hook (5 cases) ---


def test_tier1_f7_01_probe_optional_backends_returns_14_keys_with_schema(tmp_path: Path) -> None:
    res = probe_optional_backends(lean_dir=tmp_path, timeout_sec=1.0)
    expected_14 = {
        "docker",
        "wsl2",
        "lean4",
        "rfchunt_lean_oracle",
        "angr",
        "klee",
        "semgrep",
        "rea",
        "trufflehog",
        "jadx",
        "subfinder",
        "httpx",
        "katana",
        "schemathesis",
    }
    assert expected_14.issubset(set(res.keys()))
    for key in expected_14:
        entry = res[key]
        assert set(["available", "status", "reason", "path_or_module"]).issubset(entry.keys())
        assert isinstance(entry["available"], bool)
        assert isinstance(entry["status"], str) and entry["status"]


def test_tier1_f7_02_build_hardened_docker_argv_enforces_isolation(tmp_path: Path) -> None:
    argv = build_hardened_docker_argv(
        docker_bin="docker",
        image="python:3.12-slim",
        repo_dir=tmp_path,
        cmd=["pytest", "-q"],
    )
    assert "--rm" in argv
    assert "--network=none" in argv
    assert "--cap-drop=ALL" in argv
    assert "no-new-privileges:true" in argv
    assert "--read-only" in argv
    assert any(tok.endswith(":/workspace:ro") for tok in argv)


def test_tier1_f7_03_verify_sandbox_http_probe_sends_required_h1_headers(tmp_path: Path) -> None:
    db = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    db.seed_observed_hackerone_baseline()
    runner = LinuxPocRunner()
    with _sandbox_target_server() as (base_url, records):
        res = runner.verify_sandbox_http_probe(
            f"{base_url}/health",
            program="common_codes",
            eligibility_db=db,
            max_rps=2.0,
            researcher_handle="oyesanyf",
        )
        assert res.get("verified") is True and res.get("status_code") == 200
        assert len(records) == 1
        hdrs = records[0]["headers"]
        assert hdrs.get("user-agent") == "HackerOne/oyesanyf"
        assert hdrs.get("x-hackerone") == "oyesanyf"


def test_tier1_f7_04_verify_sandbox_http_probe_honors_max_rps_limit(tmp_path: Path) -> None:
    db = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    db.seed_observed_hackerone_baseline()
    runner = LinuxPocRunner()
    with _sandbox_target_server() as (base_url, records):
        runner.verify_sandbox_http_probe(
            f"{base_url}/one",
            program="common_codes",
            eligibility_db=db,
            max_rps=2.0,
            researcher_handle="oyesanyf",
        )
        runner.verify_sandbox_http_probe(
            f"{base_url}/two",
            program="common_codes",
            eligibility_db=db,
            max_rps=2.0,
            researcher_handle="oyesanyf",
        )
        assert len(records) == 2
        elapsed = records[1]["ts"] - records[0]["ts"]
        assert elapsed >= 0.40


def test_tier1_f7_05_verifiable_transcript_bundle_serialization(tmp_path: Path) -> None:
    tr = VerifiableTranscript(
        language="python",
        backend="docker",
        status="passed",
        exit_code=0,
        command=["python3", "poc.py"],
        image="python:3.12-slim",
        repo_path=str(tmp_path),
        started_at_utc="2026-11-26T00:00:00Z",
        elapsed_ms=55.0,
        stdout="POC_OK",
        stderr="",
    )
    j_path, m_path = save_transcript_bundle(tr, tmp_path / "out", stem="e2e")
    assert j_path.is_file() and m_path.is_file()
    data = json.loads(j_path.read_text(encoding="utf-8"))
    assert data["status"] == "passed"
    assert "--network=none" in m_path.read_text(encoding="utf-8")


# --- F8: ACDSO ML Bridge (5 cases) ---


def test_tier1_f8_01_acdso_pareto_front_excludes_dominated_candidate() -> None:
    from engine.acdso_bridge import CandidateResult, pareto_front

    c_best = _make_candidate_result(CandidateResult, name="best", metric=0.95, train_time_s=0.5, peak_mem_mb=10.0, latency_ms_per_row=0.2, risk_penalty=0.05, robustness_drop=0.01)
    c_fast = _make_candidate_result(CandidateResult, name="fast", metric=0.80, train_time_s=0.1, peak_mem_mb=8.0, latency_ms_per_row=0.05, risk_penalty=0.10, robustness_drop=0.02)
    c_safe = _make_candidate_result(CandidateResult, name="safe", metric=0.85, train_time_s=0.8, peak_mem_mb=12.0, latency_ms_per_row=0.3, risk_penalty=0.01, robustness_drop=0.005)
    c_dom = _make_candidate_result(CandidateResult, name="dominated", metric=0.50, train_time_s=5.0, peak_mem_mb=128.0, latency_ms_per_row=10.0, risk_penalty=0.80, robustness_drop=0.40)

    front = pareto_front([c_best, c_fast, c_safe, c_dom])
    names = {c.name for c in front}
    assert "dominated" not in names
    assert {"best", "fast", "safe"}.issubset(names)


def test_tier1_f8_02_acdso_knee_point_selection_preference_modes() -> None:
    from engine.acdso_bridge import CandidateResult, knee_point_selection, pareto_front

    cands = [
        _make_candidate_result(CandidateResult, name="acc", metric=0.98, train_time_s=10.0, peak_mem_mb=100.0, latency_ms_per_row=5.0, risk_penalty=0.2, robustness_drop=0.1),
        _make_candidate_result(CandidateResult, name="mid", metric=0.90, train_time_s=1.0, peak_mem_mb=20.0, latency_ms_per_row=0.5, risk_penalty=0.1, robustness_drop=0.02),
        _make_candidate_result(CandidateResult, name="spd", metric=0.75, train_time_s=0.05, peak_mem_mb=4.0, latency_ms_per_row=0.02, risk_penalty=0.05, robustness_drop=0.01),
    ]
    front = pareto_front(cands)
    for pref in ("balanced", "accuracy", "speed", "low_risk"):
        picked = knee_point_selection(front, preference=pref)
        assert picked in front


def test_tier1_f8_03_acdso_anomaly_scorer_separates_critical_outlier() -> None:
    from engine.acdso_bridge import ACDSOAnomalyScorer

    rows = [
        {
            "severity_score": 0.2,
            "confidence": 0.4,
            "deterministic": 0,
            "fresh_72h": 0,
            "parity_gap": 0,
            "non_production_noise": 0,
        }
        for _ in range(19)
    ]
    rows.append(
        {
            "severity_score": 1.0,
            "confidence": 0.99,
            "deterministic": 1,
            "fresh_72h": 1,
            "parity_gap": 1,
            "non_production_noise": 0,
        }
    )
    scores = ACDSOAnomalyScorer().fit_score(rows)
    assert len(scores) == 20
    assert all(math.isfinite(s) for s in scores)
    assert scores[-1] == max(scores)


def test_tier1_f8_04_acdso_rank_stage2_candidates_top_5_under_1s() -> None:
    from engine.acdso_bridge import rank_stage2_candidates

    candidates = [
        {
            "id": f"cand-{i}",
            "engine": "parity_auditor" if i % 2 == 0 else "trufflehog",
            "severity": "CRITICAL" if i < 3 else ("HIGH" if i < 10 else "LOW"),
            "confidence": 0.5 + (i % 5) * 0.09,
            "deterministic": True,
            "fresh_72h": i < 5,
            "file_path": f"src/mod_{i}.py",
        }
        for i in range(25)
    ]
    res = rank_stage2_candidates(candidates, top_k=5)
    assert len(res["selected"]) == 5
    assert res["pareto_count"] >= 1
    assert res["elapsed_ms"] < 1000.0
    assert isinstance(res["backend"], str) and res["backend"]


def test_tier1_f8_05_acdso_two_lane_policy_scheduler_signal_reservation() -> None:
    from engine.acdso_bridge import TwoLanePolicyScheduler

    sched = TwoLanePolicyScheduler()
    l1_low, l2_low = _invoke_two_lane_scheduler(sched, queue_capacity=10, signal=0.4)
    assert l1_low >= 5
    assert l1_low + l2_low == 10

    l1_high, l2_high = _invoke_two_lane_scheduler(sched, queue_capacity=10, signal=1.5)
    assert l1_high + l2_high == 10
    assert l1_high >= 0 and l2_high >= 0


# --- F9: Async SQLite WAL Blackboard (5 cases) ---


def test_tier1_f9_01_blackboard_wal_mode_and_three_tables(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    db_path = tmp_path / "bb.sqlite3"
    bb = SqliteBlackboard(db_path)
    try:
        bb.add_fact(source_engine="trufflehog", title="init", file_path="src/a.py", severity="HIGH")
    finally:
        _close_if_supported(bb)

    con = sqlite3.connect(str(db_path))
    try:
        mode = con.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(mode).lower() == "wal"
        tables = {
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
        }
        assert {"facts", "intents", "hints"}.issubset(tables)
    finally:
        con.close()


def test_tier1_f9_02_blackboard_add_and_list_facts_roundtrip(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    bb = SqliteBlackboard(tmp_path / "facts.sqlite3")
    try:
        for idx in range(3):
            bb.add_fact(
                source_engine="z3_formal",
                title=f"Invariant break {idx}",
                file_path=f"src/f{idx}.py",
                severity="HIGH",
                payload={"idx": idx},
            )
        facts = bb.list_facts()
        assert len(facts) == 3
    finally:
        _close_if_supported(bb)


def test_tier1_f9_03_blackboard_enqueue_claim_complete_lane_priority(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    bb = SqliteBlackboard(tmp_path / "intents.sqlite3")
    try:
        id2 = bb.enqueue_intent(
            intent_type="diff_scan", payload={"program": "anthropic"}, lane=2
        )
        id1 = bb.enqueue_intent(
            intent_type="diff_scan", payload={"program": "henkel_vdp"}, lane=1
        )
        assert id1 != id2
        claimed1 = bb.claim_intent("worker-a", lane=1)
        assert claimed1 is not None
        bb.complete_intent(claimed1["intent_id"], result={"ok": True})
        claimed2 = bb.claim_intent("worker-a")
        assert claimed2 is not None
        bb.complete_intent(claimed2["intent_id"], result={"ok": True})
        assert bb.claim_intent("worker-a") is None
    finally:
        _close_if_supported(bb)


def test_tier1_f9_04_blackboard_heartbeat_and_fail_intent(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    db_path = tmp_path / "hb.sqlite3"
    bb = SqliteBlackboard(db_path)
    try:
        bb.enqueue_intent(intent_type="stage1", payload={"repo": "x"}, lane=2)
        claimed = bb.claim_intent("worker-hb", lease_sec=30.0)
        assert claimed is not None
        iid = claimed["intent_id"]
        bb.heartbeat_intent(iid, "worker-hb")
        bb.fail_intent(iid, error="simulated timeout")
    finally:
        _close_if_supported(bb)

    con = sqlite3.connect(str(db_path))
    try:
        row = con.execute("SELECT status FROM intents WHERE intent_id=?", (iid,)).fetchone()
        assert row is not None and row[0] == "FAILED"
    finally:
        con.close()


def test_tier1_f9_05_blackboard_hints_and_dedup_key(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    bb = SqliteBlackboard(tmp_path / "hints.sqlite3")
    try:
        bb.add_hint("packages/b/auth.ts", domain="parity", priority=0.8)
        bb.add_hint("src/key.py", domain="entropy", priority=0.9)
        assert len(bb.list_hints()) == 2

        bb.enqueue_intent(
            intent_type="sibling_parity",
            payload={"file": "a.ts"},
            lane=2,
            dedup_key="parity:a.ts",
        )
        bb.enqueue_intent(
            intent_type="sibling_parity",
            payload={"file": "a.ts"},
            lane=2,
            dedup_key="parity:a.ts",
        )
        c1 = bb.claim_intent("w1")
        c2 = bb.claim_intent("w1")
        assert c1 is not None
        assert c2 is None
    finally:
        _close_if_supported(bb)


# --- F10: Windows-Spawn-Safe ProcessPoolExecutor Runtime (5 cases) ---


def test_tier1_f10_01_spawn_process_pool_runs_stage1_cpu_check(tmp_path: Path) -> None:
    from concurrent.futures import ProcessPoolExecutor
    from engine.async_blackboard_runtime import run_stage1_cpu_check

    _init_git_repo(tmp_path / "repo", {"src/app.py": "import pickle\npickle.loads(b'x')\n"})
    ctx = mp.get_context("spawn")
    with ProcessPoolExecutor(max_workers=2, mp_context=ctx) as pool:
        fut = pool.submit(
            run_stage1_cpu_check,
            {"repo_path": str(tmp_path / "repo"), "program": "common_codes"},
        )
        res = fut.result(timeout=30.0)
    assert isinstance(res, dict)
    assert isinstance(res.get("worker_pid"), int)
    assert res["worker_pid"] != os.getpid()


def test_tier1_f10_02_spawn_process_pool_runs_formal_and_differential_check(tmp_path: Path) -> None:
    from concurrent.futures import ProcessPoolExecutor
    from engine.async_blackboard_runtime import run_formal_and_differential_check

    _init_git_repo(tmp_path / "repo", {"src/http.py": "def parse(h):\n    return h\n"})
    ctx = mp.get_context("spawn")
    with ProcessPoolExecutor(max_workers=2, mp_context=ctx) as pool:
        fut = pool.submit(
            run_formal_and_differential_check,
            {
                "repo_path": str(tmp_path / "repo"),
                "program": "common_codes",
                "raw_probe": "POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            },
        )
        res = fut.result(timeout=30.0)
    assert isinstance(res, dict)
    assert isinstance(res.get("worker_pid"), int)
    assert res["worker_pid"] != os.getpid()
    assert isinstance(res.get("differential"), dict)
    assert res["differential"].get("is_divergent") is True
    assert len(res.get("findings") or []) >= 1


def test_tier1_f10_03_default_cpu_workers_bounded_between_2_and_8(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import run_local_rfchunt_async

    _init_git_repo(tmp_path / "repo", {"src/a.py": "x = 1\n"})
    db_path = tmp_path / "bb.sqlite3"
    res = asyncio.run(
        run_local_rfchunt_async(
            [{"intent_type": "stage1", "payload": {"repo_path": str(tmp_path / "repo")}}],
            repo_path=tmp_path / "repo",
            db_path=db_path,
            max_cpu_workers=None,
        )
    )
    assert "cpu_workers" in res
    assert 2 <= int(res["cpu_workers"]) <= 8


def test_tier1_f10_04_multi_pid_parallel_proof_at_least_two_workers(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import run_local_rfchunt_async

    repo = _init_git_repo(
        tmp_path / "repo",
        {f"src/m{i}.py": f"import pickle\ndef f{i}(d): return pickle.loads(d)\n" for i in range(6)},
    )
    seeds = [
        {
            "intent_type": "stage1",
            "payload": {"repo_path": str(repo), "target_file": f"src/m{i}.py", "cpu_work_iters": 120000},
        }
        for i in range(6)
    ]
    res = asyncio.run(
        run_local_rfchunt_async(
            seeds,
            repo_path=repo,
            db_path=tmp_path / "multi.sqlite3",
            max_cpu_workers=2,
        )
    )
    pids = set(res.get("worker_pids") or [])
    assert len(pids) >= 2


def test_tier1_f10_05_asyncio_semaphore_ceiling_enforced(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import run_local_rfchunt_async

    repo = _init_git_repo(
        tmp_path / "repo",
        {f"src/m{i}.py": f"import pickle\ndef f{i}(d): return pickle.loads(d)\n" for i in range(5)},
    )
    inflight = 0
    max_seen = 0
    eval_calls = 0
    lock = threading.Lock()

    def _slow_eval(candidate: Any) -> Dict[str, Any]:
        nonlocal inflight, max_seen, eval_calls
        with lock:
            eval_calls += 1
            inflight += 1
            if inflight > max_seen:
                max_seen = inflight
        try:
            time.sleep(0.05)
            return {"confirmed": True, "confidence": 0.8}
        finally:
            with lock:
                inflight -= 1

    seeds = [{"intent_type": "stage1", "payload": {"repo_path": str(repo), "idx": i}} for i in range(8)]
    res = asyncio.run(
        run_local_rfchunt_async(
            seeds,
            repo_path=repo,
            db_path=tmp_path / "sem.sqlite3",
            max_cpu_workers=2,
            max_net_concurrency=3,
            ollama_evaluator=_slow_eval,
        )
    )
    assert eval_calls >= 3
    assert len(res.get("stage3_results") or []) >= 3
    assert 1 <= max_seen <= 3


# --- F11: Loop 1 60s Async ETag Poller & Diff-Only Enqueue (5 cases) ---


def test_tier1_f11_01_loop1_unlocked_200_ok_enqueues_diff_intents(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1800))
    routes: Dict[str, Any] = {
        "/repos/acme/anth-repo/releases?per_page=5": {"status": 200, "etag": '"rel-1"', "body": []},
        "/repos/acme/anth-repo/pulls?state=closed&sort=updated&direction=desc&per_page=10": {
            "status": 200,
            "etag": '"pr-1"',
            "body": [
                {
                    "number": 42,
                    "title": "fix: sanitize auth token",
                    "merged_at": fresh_ts,
                    "merge_commit_sha": "sha42abcd",
                    "html_url": "https://github.com/acme/anth-repo/pull/42",
                    "body": "Enforces sanitizeInput",
                }
            ],
        },
        "/repos/acme/anth-repo/pulls/42/files?per_page=30": {
            "status": 200,
            "etag": '"files-42"',
            "body": [{"filename": "packages/app-a/auth.ts"}],
        },
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                summary = _invoke_poller_once(
                    poller,
                    [WatchTarget(program="anthropic", repo="acme/anth-repo")],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
            finally:
                _close_if_supported(poller)
        assert len(summary.get("enqueued_intent_ids") or []) >= 1
        assert bb.claim_intent("w1") is not None
    finally:
        _close_if_supported(bb)


def test_tier1_f11_02_loop1_304_not_modified_zero_cost_skip(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1800))
    routes: Dict[str, Any] = {
        "/repos/acme/anth-repo/releases?per_page=5": {"status": 200, "etag": '"rel-1"', "body": []},
        "/repos/acme/anth-repo/pulls?state=closed&sort=updated&direction=desc&per_page=10": {
            "status": 200,
            "etag": '"pr-1"',
            "body": [
                {
                    "number": 7,
                    "title": "fix: authz check",
                    "merged_at": fresh_ts,
                    "merge_commit_sha": "sha7xyz",
                    "html_url": "https://github.com/acme/anth-repo/pull/7",
                    "body": "",
                }
            ],
        },
        "/repos/acme/anth-repo/pulls/7/files?per_page=30": {
            "status": 200,
            "etag": '"files-7"',
            "body": [{"filename": "src/auth.ts"}],
        },
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                targets = [WatchTarget(program="anthropic", repo="acme/anth-repo")]
                http_get = _make_real_http_get(api_base)
                _invoke_poller_once(poller, targets, eligibility_db=elig, blackboard=bb, api_base=api_base, http_get=http_get)
                while bb.claim_intent("drain") is not None:
                    pass
                s2 = _invoke_poller_once(poller, targets, eligibility_db=elig, blackboard=bb, api_base=api_base, http_get=http_get)
            finally:
                _close_if_supported(poller)
        assert int(s2.get("etag_cache_hits", 0)) >= 1
        assert len(s2.get("enqueued_intent_ids") or []) == 0
        assert bb.claim_intent("w1") is None
        assert any(r["if_none_match"] for r in state["__requests__"])
    finally:
        _close_if_supported(bb)


def test_tier1_f11_03_loop1_release_tag_enqueues_diff_intent(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 900))
    routes: Dict[str, Any] = {
        "/repos/acme/wallet/releases?per_page=5": {
            "status": 200,
            "etag": '"rel-210"',
            "body": [
                {
                    "tag_name": "v2.1.0",
                    "name": "v2.1.0 security release",
                    "target_commitish": "rel210sha",
                    "published_at": fresh_ts,
                    "html_url": "https://github.com/acme/wallet/releases/tag/v2.1.0",
                    "body": "OID4VCI verify and SSRF guard update",
                }
            ],
        },
        "/repos/acme/wallet/pulls?state=closed&sort=updated&direction=desc&per_page=10": {
            "status": 200,
            "etag": '"pr-empty"',
            "body": [],
        },
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                summary = _invoke_poller_once(
                    poller,
                    [WatchTarget(program="common_codes", repo="acme/wallet")],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
            finally:
                _close_if_supported(poller)
        assert len(summary.get("enqueued_intent_ids") or []) >= 1
    finally:
        _close_if_supported(bb)


def test_tier1_f11_04_loop1_skips_blocked_signal_programs(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    routes: Dict[str, Any] = {
        "/repos/acme/anth/releases?per_page=5": {"status": 200, "etag": '"a"', "body": []},
        "/repos/acme/anth/pulls?state=closed&sort=updated&direction=desc&per_page=10": {"status": 200, "etag": '"b"', "body": []},
        "/repos/shopify/blocked-app/releases?per_page=5": {"status": 200, "etag": '"s"', "body": []},
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                summary = _invoke_poller_once(
                    poller,
                    [
                        WatchTarget(program="anthropic", repo="acme/anth"),
                        WatchTarget(program="shopify", repo="shopify/blocked-app"),
                    ],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
            finally:
                _close_if_supported(poller)
        assert len(summary.get("skipped_ineligible") or []) >= 1
        assert "shopify" in summary["skipped_ineligible"]
        assert not any("shopify/blocked-app" in r["path"] for r in state["__requests__"])
    finally:
        _close_if_supported(bb)


def test_tier1_f11_05_loop1_run_loop_bounded_max_cycles(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    routes: Dict[str, Any] = {
        "/repos/acme/anth/releases?per_page=5": {"status": 200, "etag": '"r1"', "body": []},
        "/repos/acme/anth/pulls?state=closed&sort=updated&direction=desc&per_page=10": {"status": 200, "etag": '"p1"', "body": []},
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                run_fn = poller.run_loop
                sig = inspect.signature(run_fn)
                kw: Dict[str, Any] = {"interval_sec": 0.02, "max_cycles": 2}
                if "eligibility_db" in sig.parameters:
                    kw["eligibility_db"] = elig
                if "blackboard" in sig.parameters:
                    kw["blackboard"] = bb
                if "http_get" in sig.parameters:
                    kw["http_get"] = _make_real_http_get(api_base)
                res = run_fn([WatchTarget(program="anthropic", repo="acme/anth")], **kw)
                if inspect.isawaitable(res):
                    res = asyncio.run(res)
            finally:
                _close_if_supported(poller)
        assert isinstance(res, list)
        assert len(res) == 2
        assert all(isinstance(c, dict) and "targets_checked" in c for c in res)
    finally:
        _close_if_supported(bb)


# --- F12: Loop 2 Security-Fix & Fact Sibling Parity Propagation (5 cases) ---


def test_tier1_f12_01_loop2_detects_all_8_security_fix_keywords() -> None:
    from engine.async_blackboard_runtime import SECURITY_FIX_KEYWORDS, detect_security_fix_signal

    expected = ("sanitize", "o_nofollow", "symlink", "allowfrom", "csp", "ssrf", "authz", "verify")
    assert set(expected).issubset({k.lower() for k in SECURITY_FIX_KEYWORDS})
    msg = "Fix sanitize, O_NOFOLLOW symlink race, allowFrom, CSP, SSRF, authz, verify signature"
    matched = [m.lower() for m in detect_security_fix_signal(msg, "")]
    for kw in expected:
        assert kw in matched


def test_tier1_f12_02_loop2_emits_intents_across_sibling_packages(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, emit_sibling_parity_intents

    for pkg in ("pkg-a", "pkg-b", "pkg-c"):
        pdir = tmp_path / "packages" / pkg
        pdir.mkdir(parents=True)
        (pdir / "auth.ts").write_text("export function handleInbound() {}\n", encoding="utf-8")

    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        emitted = emit_sibling_parity_intents(
            bb,
            repo_path=str(tmp_path),
            changed_files=["packages/pkg-a/auth.ts"],
            trigger_reason="security_fix:sanitize",
        )
        assert len(emitted) >= 2
    finally:
        _close_if_supported(bb)


def test_tier1_f12_03_loop2_emits_intents_across_sibling_handlers(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, emit_sibling_parity_intents

    hdir = tmp_path / "src" / "handlers"
    hdir.mkdir(parents=True)
    for name in ("webhook_v1.py", "webhook_v2.py", "admin.py"):
        (hdir / name).write_text("def handle(req):\n    return req\n", encoding="utf-8")

    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        emitted = emit_sibling_parity_intents(
            bb,
            repo_path=str(tmp_path),
            changed_files=["src/handlers/webhook_v1.py"],
            trigger_reason="security_fix:authz",
        )
        assert len(emitted) >= 2
    finally:
        _close_if_supported(bb)


def test_tier1_f12_04_loop2_emits_intents_across_6_sibling_sdk_languages(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import (
        SIBLING_SDK_LANGUAGES,
        SqliteBlackboard,
        emit_sibling_parity_intents,
    )

    assert {"TS", "Python", "Go", "Java", "Ruby", "Rust"}.issubset(set(SIBLING_SDK_LANGUAGES))
    sdk_files = {
        "sdk/ts/client.ts": "export function verify() {}\n",
        "sdk/python/client.py": "def verify(): pass\n",
        "sdk/go/client.go": "package sdk\nfunc Verify() {}\n",
        "sdk/java/Client.java": "class Client { void verify() {} }\n",
        "sdk/ruby/client.rb": "def verify; end\n",
        "sdk/rust/client.rs": "pub fn verify() {}\n",
    }
    for rel, body in sdk_files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        emitted = emit_sibling_parity_intents(
            bb,
            repo_path=str(tmp_path),
            changed_files=["sdk/ts/client.ts"],
            trigger_reason="security_fix:verify",
        )
        assert len(emitted) >= 5
    finally:
        _close_if_supported(bb)


def test_tier1_f12_05_loop2_landed_fact_triggers_sibling_parity_in_async_runtime(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, run_local_rfchunt_async

    repo = _init_git_repo(
        tmp_path / "repo",
        {
            "packages/pkg-a/auth.ts": "export function handleInbound(x: string) { return sanitize(x); }\n",
            "packages/pkg-b/auth.ts": "export function handleInbound(x: string) { return x; }\n",
        },
        commit_msg="fix: sanitize inbound payload",
    )
    db_path = tmp_path / "loop2.sqlite3"
    bb = SqliteBlackboard(db_path)
    try:
        bb.add_fact(
            source_engine="parity_auditor",
            title="Missing sanitize in pkg-b",
            file_path="packages/pkg-b/auth.ts",
            severity="HIGH",
            payload={"changed_files": ["packages/pkg-a/auth.ts"]},
        )
    finally:
        _close_if_supported(bb)

    res = asyncio.run(
        run_local_rfchunt_async(
            [{"intent_type": "stage1", "payload": {"repo_path": str(repo), "changed_files": ["packages/pkg-a/auth.ts"]}}],
            repo_path=repo,
            db_path=db_path,
            max_cpu_workers=2,
        )
    )
    assert isinstance(res, dict)
    assert len(res.get("loop2_emitted_intents") or []) >= 1
    assert int(res.get("intents_completed", 0)) >= 1


# --- F13: Loop 5 Two-Lane Self-Adapting Queue & Auto-Unlock Watcher (5 cases) ---


def test_tier1_f13_01_loop5_signal_under_1_reserves_50_percent_lane1(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, TwoLaneBountyQueue

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        q = TwoLaneBountyQueue(elig, bb)
        sched = _call_two_lane_queue_schedule(q, queue_capacity=10, signal_score=0.5, eligibility_db=elig)
        lane1 = sched["lane1_programs_queued"]
        assert len(lane1) >= 5
        assert int(sched["lane1_slots"]) >= 5
        lane1_programs = {item.get("program", item) if isinstance(item, dict) else item for item in lane1}
        assert lane1_programs.intersection({"henkel_vdp", "servicenow-disclosure", "common_codes"})
    finally:
        _close_if_supported(bb)


def _call_two_lane_queue_schedule(
    q: Any,
    *,
    queue_capacity: int,
    signal_score: float,
    eligibility_db: Optional[ProgramEligibilityDB] = None,
) -> Dict[str, Any]:
    for mname in ("plan_cycle", "schedule", "allocate", "build_schedule", "plan"):
        fn = getattr(q, mname, None)
        if callable(fn):
            sig = inspect.signature(fn)
            kw: Dict[str, Any] = {}
            if "queue_capacity" in sig.parameters:
                kw["queue_capacity"] = queue_capacity
            elif "capacity" in sig.parameters:
                kw["capacity"] = queue_capacity
            if "signal_score" in sig.parameters:
                kw["signal_score"] = signal_score
            elif "signal" in sig.parameters:
                kw["signal"] = signal_score
            if "eligibility_db" in sig.parameters and eligibility_db is not None:
                kw["eligibility_db"] = eligibility_db
            res = fn(**kw)
            if isinstance(res, dict):
                return res
    raise AttributeError("TwoLaneBountyQueue missing schedule/allocate method")


def test_tier1_f13_02_loop5_lane2_populates_high_value_unlocked_targets(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, TwoLaneBountyQueue

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        q = TwoLaneBountyQueue(elig, bb)
        sched = _call_two_lane_queue_schedule(q, queue_capacity=10, signal_score=0.5, eligibility_db=elig)
        lane2 = sched["lane2_programs_queued"]
        lane2_programs = {item.get("program", item) if isinstance(item, dict) else item for item in lane2}
        assert lane2_programs.intersection({"anthropic", "common_codes", "oppo_bbp", "amazonvrp", "temu"})
    finally:
        _close_if_supported(bb)


def test_tier1_f13_03_loop5_signal_ge_1_adapts_lane_allocation(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, TwoLaneBountyQueue

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        q = TwoLaneBountyQueue(elig, bb)
        s_low = _call_two_lane_queue_schedule(q, queue_capacity=10, signal_score=0.4, eligibility_db=elig)
        s_high = _call_two_lane_queue_schedule(q, queue_capacity=10, signal_score=1.5, eligibility_db=elig)
        assert len(s_low["lane1_programs_queued"]) >= 5
        assert len(s_high["lane2_programs_queued"]) >= len(s_low["lane2_programs_queued"])
    finally:
        _close_if_supported(bb)


def test_tier1_f13_04_loop5_auto_queues_program_when_flipped_to_unlocked(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, sync_eligibility_and_stage_unlocks

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    assert elig.is_eligible("shopify") is False
    elig.upsert("shopify", "UNLOCKED", bounty_max_usd=50000)

    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    drafts_dir = tmp_path / "drafts"
    drafts_dir.mkdir()
    try:
        res = sync_eligibility_and_stage_unlocks(elig, bb, drafts_dir)
        assert "shopify" in (res.get("newly_unlocked") or [])
        assert len(res.get("queued_intents") or []) >= 1
        assert bb.claim_intent("w1") is not None
    finally:
        _close_if_supported(bb)


def test_tier1_f13_05_loop5_auto_stages_saved_verified_shopify_draft_on_unlock(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, sync_eligibility_and_stage_unlocks

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    elig.upsert("shopify", "UNLOCKED", bounty_max_usd=50000)

    drafts_dir = tmp_path / "drafts"
    drafts_dir.mkdir()
    (drafts_dir / "shopify_app_remix.json").write_text(
        json.dumps(
            {
                "program_handle": "shopify",
                "asset": "@shopify/shopify-app-remix",
                "weakness_cwe": "CWE-639",
                "severity_rating": "High",
                "title": "Missing CSP frame-ancestors header in @shopify/shopify-app-remix callback",
                "vulnerability_information": (
                    "In @shopify/shopify-app-remix, the fallback response path omits the Content-Security-Policy "
                    "frame-ancestors directive enforced by sibling embedded handlers, enabling clickjacking across "
                    "victim merchant admin iframes with verified non-destructive PoC output."
                ),
                "impact": "Cross-origin framing of merchant embedded app sessions.",
                "poc_verified": True,
            }
        ),
        encoding="utf-8",
    )
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        res = sync_eligibility_and_stage_unlocks(elig, bb, drafts_dir)
        staged = res.get("staged_drafts") or []
        assert len(staged) >= 1
        assert any(
            d.get("status") == "staged_ready" and d.get("program_handle") == "shopify"
            for d in staged
        )
    finally:
        _close_if_supported(bb)


# --- F14: Production Signal Noise Filter & ENGINE_WEIGHTS (5 cases) ---


def test_tier1_f14_01_noise_filter_tags_test_and_fixture_paths() -> None:
    from engine.parity_invariant_auditor import is_non_production_noise

    for p in (
        "tests/auth_test.py",
        "__tests__/x.test.ts",
        "pkg/foo_test.go",
        "examples/demo.py",
        "fixtures/a.json",
    ):
        assert is_non_production_noise(p) is True


def test_tier1_f14_02_noise_filter_tags_docs_and_lint_rules() -> None:
    from engine.parity_invariant_auditor import is_non_production_noise

    assert is_non_production_noise("README.md") is True
    assert is_non_production_noise("CHANGELOG.md") is True
    assert is_non_production_noise("docs/guide.md") is True
    assert is_non_production_noise("src/ci.yml", rule_id="GHA-LINT-STYLE") is True


def test_tier1_f14_03_noise_filter_preserves_production_paths() -> None:
    from engine.parity_invariant_auditor import is_non_production_noise

    assert is_non_production_noise("src/middleware/auth.ts") is False


def test_tier1_f14_04_filter_production_candidates_partitions_mix() -> None:
    from engine.parity_invariant_auditor import filter_production_candidates

    mixed = [
        EngineFinding(engine="trufflehog", title=f"Prod {i}", file_path=f"src/prod_{i}.py")
        for i in range(4)
    ] + [
        EngineFinding(engine="trufflehog", title=f"Test {i}", file_path=f"tests/test_{i}.py")
        for i in range(6)
    ]
    prod, noise = filter_production_candidates(mixed)
    assert len(prod) == 4
    assert len(noise) == 6


def test_tier1_f14_05_engine_weights_and_noise_downrank() -> None:
    expected_weights = {
        "trufflehog": 0.90,
        "mobile_mobsf": 0.78,
        "api_jwt_sdjwt": 0.84,
        "ai_infra_guard": 0.76,
        "parity_auditor": 0.82,
        "z3_formal": 0.92,
    }
    for key, val in expected_weights.items():
        assert key in ENGINE_WEIGHTS
        assert abs(ENGINE_WEIGHTS[key] - val) < 1e-6

    voter = EnsembleConsensusVoter(program="generic", quorum=2)
    noise_finding = EngineFinding(
        engine="trufflehog",
        title="Test key in fixture",
        file_path="tests/fixtures/secret_test.py",
        line=5,
        severity="HIGH",
        confidence=0.80,
        metadata={"non_production_noise": True},
    )
    clusters = voter.fuse([noise_finding])
    assert len(clusters) == 1
    assert clusters[0].disposition == "LOW_CONFIDENCE_NOISE"


# --- F15: Loop 3 Strict 3-Stage Triage Funnel (5 cases) ---


def test_tier1_f15_01_loop3_stage1_drops_noise_before_stage2_and_3(tmp_path: Path) -> None:
    files: Dict[str, str] = {}
    for i in range(6):
        files[f"tests/test_noise_{i}.py"] = f'import pickle\npickle.loads(b"{i}")\n'
    files["src/prod_loader.py"] = "import pickle\ndef load(d):\n    return pickle.loads(d)\n"
    repo = _init_git_repo(tmp_path / "repo", files)
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    orch = EnsembleOrchestrator(program="common_codes", embedded=True)
    res = orch.run_fast_parallel_ooda(
        repo,
        program="common_codes",
        blackboard_db=tmp_path / "bb.sqlite3",
        max_cpu_workers=2,
        eligibility_db=elig,
    )
    s1 = res.get("stage1") or {}
    assert int(s1.get("noise_dropped", 0) or res.get("stage1_dropped_noise_count", 0)) >= 6
    assert int(s1.get("production_count", 0) or res.get("stage1_production_count", 0)) >= 1


def test_tier1_f15_02_loop3_stage2_narrows_15_candidates_to_top_5_under_1s() -> None:
    from engine.acdso_bridge import rank_stage2_candidates

    cands = [
        {
            "id": f"prod-{i}",
            "engine": "api_jwt_sdjwt",
            "severity": "HIGH" if i < 6 else "MEDIUM",
            "confidence": 0.6 + (i % 4) * 0.09,
            "deterministic": True,
            "fresh_72h": i < 4,
            "file_path": f"src/api_{i}.py",
        }
        for i in range(15)
    ]
    res = rank_stage2_candidates(cands, top_k=5)
    assert 3 <= len(res["selected"]) <= 5
    assert res["elapsed_ms"] < 1000.0


def test_tier1_f15_03_loop3_stage3_calls_ollama_only_for_top_5_with_guard(tmp_path: Path) -> None:
    files = {
        f"src/mod_{i}.py": f"import pickle\ndef f{i}(b):\n    return pickle.loads(b)\n"
        for i in range(10)
    }
    repo = _init_git_repo(tmp_path / "repo", files)
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _ollama_loopback_server({"models": ["qwen2.5:7b"], "chat_delay_sec": 0.03}) as (
        endpoint,
        state,
    ):
        with _scoped_env(OLLAMA_HOST=endpoint, RFCHUNT_OFFLINE=None):
            orch = EnsembleOrchestrator(program="common_codes", embedded=False, model="qwen2.5:7b")
            res = orch.run_fast_parallel_ooda(
                repo,
                program="common_codes",
                blackboard_db=tmp_path / "bb.sqlite3",
                max_cpu_workers=2,
                eligibility_db=elig,
            )
    assert res.get("status") == "completed"
    assert 1 <= len(state["chat_calls"]) <= 5
    assert state["max_inflight"] <= 1


def test_tier1_f15_04_loop3_lean4_deterministic_override_immunity(tmp_path: Path) -> None:
    findings = [
        EngineFinding(
            engine="lean4",
            title="RFC 9112 CL/TE Framing Differential",
            file_path="src/http_parser.rs",
            line=40,
            cwe="CWE-444",
            severity="CRITICAL",
            deterministic=True,
            confirmed=True,
        ),
        EngineFinding(
            engine="gha_llm",
            title="RFC 9112 CL/TE Framing Differential",
            file_path="src/http_parser.rs",
            line=41,
            cwe="CWE-444",
            severity="LOW",
            deterministic=False,
            confirmed=False,
        ),
    ]
    voter = EnsembleConsensusVoter(program="generic", quorum=2)
    clusters = voter.fuse(findings)
    assert len(clusters) == 1
    assert clusters[0].lean_verified is True
    assert clusters[0].llm_dissent_ignored is True
    assert clusters[0].deterministic_override_protected is True


def test_tier1_f15_05_loop3_embedded_true_skips_stage3_ollama_calls(tmp_path: Path) -> None:
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef load(x): return pickle.loads(x)\n"},
    )
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _ollama_loopback_server({"models": ["qwen2.5:7b"]}) as (endpoint, state):
        with _scoped_env(OLLAMA_HOST=endpoint):
            orch = EnsembleOrchestrator(program="common_codes", embedded=True)
            res = orch.run_fast_parallel_ooda(
                repo,
                program="common_codes",
                blackboard_db=tmp_path / "bb.sqlite3",
                max_cpu_workers=2,
                eligibility_db=elig,
            )
    assert res.get("status") == "completed"
    assert len(state["chat_calls"]) == 0


# --- F16: Loop 4 Auto-PoC Gate, READY_TO_SUBMIT.json, /browser & Clickable URL (5 cases) ---


def test_tier1_f16_01_loop4_full_3_way_gate_emits_ready_to_submit_json(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    out_dir = tmp_path / "submit_out"
    res = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/api/auth.py",
        title="Unauthenticated SSRF in webhook fetcher",
        summary=(
            "The webhook fetcher accepts user-controlled jku URLs without pinning or private IP validation, "
            "allowing an external unauthenticated attacker to reach internal endpoints."
        ),
        impact="Server-side request forgery against internal services.",
        weakness_cwe="CWE-918",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="HTTP/1.1 200 OK verified against isolated sandbox",
        eligibility_db=elig,
        output_dir=out_dir,
        trigger_browser=True,
    )
    assert res.get("eligible") is True or res.get("status") in ("ready_to_submit", "staged_ready")
    ready_file = out_dir / "READY_TO_SUBMIT.json"
    assert ready_file.is_file()
    data = json.loads(ready_file.read_text(encoding="utf-8"))
    assert data


def test_tier1_f16_02_loop4_browser_handoff_spec_generated(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    res = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/api/auth.py",
        title="Algorithm confusion in JWT verifier",
        summary=(
            "JWT verification accepts HS256 using the RSA public key, enabling forged bearer tokens "
            "to bypass API authentication across endpoints."
        ),
        impact="Authentication bypass on protected endpoints.",
        weakness_cwe="CWE-347",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="Forged HS256 token accepted with HTTP 200",
        eligibility_db=elig,
        output_dir=tmp_path / "out",
        trigger_browser=True,
    )
    spec = res.get("browser_handoff_spec") or {}
    assert spec.get("action") == "stage_draft"
    assert any("CAPTCHA" in s or "Turnstile" in s for s in spec.get("hitl_invariants", []))


def test_tier1_f16_03_loop4_clickable_hackerone_report_url_output(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    res = evaluate_and_stage_submission(
        program="common_codes",
        asset="src/sdjwt.py",
        title="SD-JWT missing cnf key binding check",
        summary=(
            "Verifier accepts SD-JWT presentation without verifying cnf holder key-binding signature or nonce, "
            "permitting credential replay by an unauthorized presenter."
        ),
        impact="Unauthorized credential presentation replay.",
        weakness_cwe="CWE-287",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="Replay accepted in sandbox verifier",
        eligibility_db=elig,
        output_dir=tmp_path / "out",
        trigger_browser=True,
    )
    url = str(res.get("report_url") or res.get("submit_url") or "")
    assert url.startswith("https://hackerone.com/reports/")


def test_tier1_f16_04_loop4_redacts_secrets_and_phi_in_staged_draft(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    out_dir = tmp_path / "redact_out"
    evaluate_and_stage_submission(
        program="anthropic",
        asset="src/auth.py",
        title="Token leakage in PoC transcript",
        summary=(
            f"Leaked token Authorization: Bearer {fake_jwt} observed in response body along with "
            "diagnostic trace exceeding minimum description requirements."
        ),
        impact="Session hijacking via leaked JWT.",
        weakness_cwe="CWE-200",
        severity="HIGH",
        poc_verified=True,
        poc_transcript=f"Bearer {fake_jwt}",
        eligibility_db=elig,
        output_dir=out_dir,
        trigger_browser=True,
    )
    raw = (out_dir / "READY_TO_SUBMIT.json").read_text(encoding="utf-8")
    assert fake_jwt not in raw


def test_tier1_f16_05_loop4_static_only_cap_excludes_unverified_from_ready(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    out_dir = tmp_path / "static_only"
    res = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/auth.py",
        title="Static-only unverified hypothesis",
        summary=(
            "Static engines agreed on potential SSRF sink without runtime verification transcript "
            "exceeding 100 characters for draft validation."
        ),
        impact="Potential SSRF.",
        weakness_cwe="CWE-918",
        severity="HIGH",
        poc_verified=False,
        poc_transcript="",
        eligibility_db=elig,
        output_dir=out_dir,
        trigger_browser=True,
    )
    assert res.get("eligible") is False or str(res.get("status", "")).startswith("blocked")
    assert not (out_dir / "READY_TO_SUBMIT.json").is_file()


# --- F17: CLI & MCP Integration (5 cases) ---


def test_tier1_f17_01_cli_fast_ooda_executes_and_populates_blackboard(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert "fast-ooda" in revenue_cli.REVENUE_SUBCOMMANDS
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef f(x): return pickle.loads(x)\n"},
    )
    bb_db = tmp_path / "cli_bb.sqlite3"
    out_dir = tmp_path / "cli_out"
    rc = revenue_cli.run_revenue_cli(
        [
            "fast-ooda",
            "--target",
            str(repo),
            "--program",
            "anthropic",
            "--cpu-workers",
            "2",
            "--blackboard-db",
            str(bb_db),
            "--out",
            str(out_dir),
            "--embedded",
            "--json",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed.get("status") == "completed"
    assert bb_db.is_file()


def test_tier1_f17_02_cli_ensemble_audit_accepts_new_blackboard_flags(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path / "repo", {"src/app.py": "x = 1\n"})
    bb_db = tmp_path / "ens_bb.sqlite3"
    out_dir = tmp_path / "ens_out"
    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(repo),
            "--embedded",
            "--cpu-workers",
            "2",
            "--blackboard-db",
            str(bb_db),
            "--resume",
            "--out",
            str(out_dir),
        ]
    )
    assert rc == 0
    assert (out_dir / "ensemble_report.json").is_file()


def test_tier1_f17_03_mcp_tools_list_includes_bb_run_fast_ooda() -> None:
    srv = BugBountyMCPServer()
    resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "bb_run_fast_ooda" in names
    assert any(t["name"] == "bb_run_fast_ooda" and "inputSchema" in t for t in TOOLS_SCHEMA)


def test_tier1_f17_04_mcp_tools_call_bb_run_fast_ooda_succeeds(tmp_path: Path) -> None:
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef f(x): return pickle.loads(x)\n"},
    )
    srv = BugBountyMCPServer()
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "bb_run_fast_ooda",
                "arguments": {
                    "target": str(repo),
                    "program": "anthropic",
                    "cpu_workers": 2,
                    "blackboard_db": str(tmp_path / "mcp_bb.sqlite3"),
                    "out_dir": str(tmp_path / "mcp_out"),
                    "embedded": True,
                },
            },
        }
    )
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload.get("status") == "completed"


def test_tier1_f17_05_mcp_bb_stage_hackerone_draft_eligible_returns_clickable_url(
    tmp_path: Path,
) -> None:
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _scoped_env(RFCHUNT_ELIGIBILITY_DB=str(elig.db_path)):
        res = _call_validate_and_stage_draft(
            elig=elig,
            program_handle="anthropic",
            asset="src/api/auth.py",
            weakness_cwe="CWE-347",
            severity_rating="High",
            title="JWT alg:none signature bypass in API gateway",
            vulnerability_information=(
                "The API gateway accepts unsigned JWTs with alg=none during bearer token verification, "
                "allowing an unauthenticated attacker to forge arbitrary claims and access protected endpoints."
            ),
            impact="Full authentication bypass across API routes.",
            poc_verified=True,
            out_path=str(tmp_path / "staged.json"),
        )
    assert res["status"] == "staged_ready"
    url = str(res.get("report_url") or res.get("submit_url") or "")
    assert url.startswith("https://hackerone.com/reports/")


# --- F18: Antigravity IDE Bootstrap (5 cases) ---


def _run_bootstrap_isolated(
    fake_home: Path,
    *extra_args: str,
    extra_env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOME"] = str(fake_home)
    env["USERPROFILE"] = str(fake_home)
    env.setdefault("RFCHUNT_ELIGIBILITY_DB", str(fake_home / ".rfchunt" / "program_eligibility.sqlite3"))
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "setup_antigravity_rfchunt_ide.py"), "--skip-pip", *extra_args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        cwd=str(ROOT),
        check=False,
    )


def test_tier1_f18_01_ide_bootstrap_isolated_skip_pip_creates_configs(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0, proc.stderr
    cfg_dir = fake_home / ".gemini" / "config"
    assert (cfg_dir / "local_models.json").is_file()
    assert (cfg_dir / "mcp_config.json").is_file()
    assert (cfg_dir / "rules" / "bounty_threat_hunting_and_coding_protocol.md").is_file()


def test_tier1_f18_02_ide_bootstrap_outputs_valid_utf8_json_with_mcp_and_catalog(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0
    cfg_dir = fake_home / ".gemini" / "config"
    lm = json.loads((cfg_dir / "local_models.json").read_text(encoding="utf-8"))
    mc = json.loads((cfg_dir / "mcp_config.json").read_text(encoding="utf-8"))
    assert "rfchunt-bugbounty" in mc.get("mcpServers", {})
    assert len(lm.get("ollama", {}).get("preferred_security_models", [])) >= 5


def test_tier1_f18_03_ide_bootstrap_probes_6_new_cli_tools(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0
    combined = (proc.stdout + "\n" + proc.stderr).lower()
    for tool in ("trufflehog", "subfinder", "httpx", "katana", "jadx", "schemathesis"):
        assert tool in combined


def test_tier1_f18_04_ide_bootstrap_resolves_go_bin_in_memory_without_path_mutation(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    go_bin = fake_home / "go" / "bin"
    go_bin.mkdir(parents=True)
    stub_name = "subfinder.exe" if os.name == "nt" else "subfinder"
    (go_bin / stub_name).write_text("stub", encoding="utf-8")
    before_path = os.environ.get("PATH", "")
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0
    assert os.environ.get("PATH", "") == before_path
    assert "subfinder" in (proc.stdout + proc.stderr).lower()


def test_tier1_f18_05_ide_bootstrap_preserves_existing_mcp_servers(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    cfg_dir = fake_home / ".gemini" / "config"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "mcp_config.json").write_text(
        json.dumps({"mcpServers": {"other": {"command": "other-bin"}}}),
        encoding="utf-8",
    )
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0
    mc = json.loads((cfg_dir / "mcp_config.json").read_text(encoding="utf-8"))
    assert mc["mcpServers"]["other"]["command"] == "other-bin"
    assert "rfchunt-bugbounty" in mc["mcpServers"]


# --- R5: Protected Files & Defensive Safety Invariants (5 cases) ---


def test_tier1_r5_01_protected_files_untouched_in_git() -> None:
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain", "--", "rfc_hunt_swarm.py", "mcp_server.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    assert proc.stdout.strip() == ""


def test_tier1_r5_02_zero_registry_or_persistent_path_mutation_primitives() -> None:
    targets = [
        ROOT / "scripts" / "setup_antigravity_rfchunt_ide.py",
        ROOT / "scripts" / "autonomous_hunt.py",
        ROOT / "hunt.py",
        ROOT / "revenue_cli.py",
        ROOT / "bugbounty_mcp_server.py",
        *sorted((ROOT / "engine").glob("*.py")),
    ]
    forbidden_attrs = {
        "SetValue",
        "SetValueEx",
        "CreateKey",
        "CreateKeyEx",
        "DeleteKey",
        "DeleteKeyEx",
        "DeleteValue",
        "KEY_WRITE",
        "KEY_SET_VALUE",
        "SetEnvironmentVariable",
    }
    forbidden_str_patterns = (
        "SetEnvironmentVariable(",
        "HKCU\\Environment",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
        "reg add",
    )
    # Read-only Windows KB/VirtualBox version audit (`pe_magika_classifier.py`) is the sole
    # module permitted to import `winreg` (strictly KEY_READ / QueryValueEx only).
    readonly_winreg_allowlist = {"pe_magika_classifier.py"}

    for path in targets:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text, filename=str(path))
        docstring_ids: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if (
                    node.body
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)
                ):
                    docstring_ids.add(id(node.body[0].value))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "winreg" and path.name not in readonly_winreg_allowlist:
                        raise AssertionError(f"Unexpected 'winreg' import in {path}")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "") == "winreg" and path.name not in readonly_winreg_allowlist:
                    raise AssertionError(f"Unexpected 'from winreg' import in {path}")
            elif isinstance(node, ast.Attribute):
                assert node.attr not in forbidden_attrs, (
                    f"Forbidden env/registry mutation attribute {node.attr!r} in {path}"
                )
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if id(node) in docstring_ids:
                    continue
                for pat in forbidden_str_patterns:
                    assert pat not in node.value, (
                        f"Forbidden env/registry mutation literal {pat!r} in {path}"
                    )


def test_tier1_r5_03_zero_weaponized_payloads_or_captcha_bypass_in_artifacts(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    out_dir = tmp_path / "r5_out"
    res = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/api/auth.py",
        title="Defensive SSRF validation finding",
        summary=(
            "Unvalidated webhook URL permits SSRF against internal metadata addresses in isolated verification "
            "without destructive payloads or anti-bot bypasses."
        ),
        impact="Unauthorized internal metadata access.",
        weakness_cwe="CWE-918",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="GET /health -> 200 OK",
        eligibility_db=elig,
        output_dir=out_dir,
        trigger_browser=True,
    )
    serialized = json.dumps(res).lower()
    for bad in ("2captcha", "anticaptcha", "bypass turnstile", "reverse_shell", "bash -i >&"):
        assert bad not in serialized


def test_tier1_r5_04_zero_mocks_in_e2e_test_suite() -> None:
    src = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden_mod = "unittest." + "mock"
    forbidden_names = {
        "Magic" + "Mock",
        "Async" + "Mock",
        "monkey" + "patch",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert forbidden_mod not in alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert forbidden_mod not in mod
            for alias in node.names:
                assert alias.name not in forbidden_names
        elif isinstance(node, ast.Name):
            assert node.id not in forbidden_names


def test_tier1_r5_05_clean_utf8_and_zero_control_chars_in_generated_artifacts(tmp_path: Path) -> None:
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef f(x): return pickle.loads(x)\n"},
    )
    out_dir = tmp_path / "clean_out"
    orch = EnsembleOrchestrator(program="anthropic", embedded=True)
    rep = orch.run(repo, out_dir=out_dir, package_client_name="CleanClient")
    assert rep is not None
    bad_chars = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffd]")
    for artifact in out_dir.rglob("*"):
        if artifact.is_file() and artifact.suffix in (".json", ".md", ".sarif", ".csv", ".html"):
            txt = artifact.read_text(encoding="utf-8")
            assert not bad_chars.search(txt), f"Control or replacement char in {artifact}"


# ===========================================================================
# TIER 2: BOUNDARY, CORNER, ERROR & FAIL-CLOSED CASES (95 TEST CASES)
# ===========================================================================


# --- F1 Boundary Cases (5 cases) ---


def test_tier2_f1_01_trufflehog_filters_or_downgrades_test_placeholders(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    placeholder_aws = "AKIA" + "IOSFODNN7EXAMPLE"
    placeholder_stripe = "sk_test_" + "0" * 24
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixtures.py").write_text(
        f'AWS_KEY = "{placeholder_aws}"\nSTRIPE = "{placeholder_stripe}"\n',
        encoding="utf-8",
    )
    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True)
    prod_high = [
        f
        for f in findings
        if not bool(_fget(f, "non_production_noise", False))
        and str(_fget(f, "severity", "")).upper() in ("CRITICAL", "HIGH")
    ]
    assert prod_high == []


def test_tier2_f1_02_trufflehog_missing_repo_path_fails_cleanly(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    findings = scan_secrets_with_trufflehog(
        tmp_path / "does_not_exist", embedded=True, no_external_scanners=True
    )
    assert findings == []


def test_tier2_f1_03_trufflehog_empty_directory_returns_empty(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    empty = tmp_path / "empty_repo"
    empty.mkdir()
    assert scan_secrets_with_trufflehog(empty, embedded=True, no_external_scanners=True) == []


def test_tier2_f1_04_trufflehog_binary_non_utf8_file_safe(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    (tmp_path / "blob.bin").write_bytes(b"\xff\xfe\x00\x01\x80\x99\xaa\xbb" * 16)
    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True)
    assert isinstance(findings, list)


def test_tier2_f1_05_trufflehog_low_entropy_repeated_string_ignored(tmp_path: Path) -> None:
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "const.py").write_text('API_KEY = "' + ("a" * 36) + '"\n', encoding="utf-8")
    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True)
    assert findings == []


# --- F2 Boundary Cases (5 cases) ---


def test_tier2_f2_01_mobile_malformed_android_manifest_no_crash(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    (tmp_path / "AndroidManifest.xml").write_text("<manifest><application", encoding="utf-8")
    res = audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    assert isinstance(res, list)


def test_tier2_f2_02_mobile_corrupt_binary_info_plist_no_crash(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    (tmp_path / "Info.plist").write_bytes(b"bplist00\x01\x02\xff")
    res = audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    assert isinstance(res, list)


def test_tier2_f2_03_mobile_empty_apk_zip_no_crash(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    (tmp_path / "app.apk").write_bytes(b"")
    res = audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    assert isinstance(res, list)


def test_tier2_f2_04_mobile_zip_path_traversal_in_apk_rejected(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    apk_path = tmp_path / "evil.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
        zf.writestr("AndroidManifest.xml", "<manifest package='x'/>")
    res = audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    assert isinstance(res, list)
    assert not (tmp_path.parent / "etc" / "passwd").exists()


def test_tier2_f2_05_mobile_unreachable_mobsf_url_falls_back_fast(tmp_path: Path) -> None:
    from engine.mobile_app_auditor import audit_mobile_app

    (tmp_path / "Info.plist").write_text(
        "<plist version='1.0'><dict><key>NSAllowsArbitraryLoads</key><true/></dict></plist>",
        encoding="utf-8",
    )
    t0 = time.monotonic()
    res = audit_mobile_app(
        tmp_path,
        embedded=False,
        no_external_scanners=True,
        mobsf_url="http://127.0.0.1:9",
    )
    elapsed = time.monotonic() - t0
    assert elapsed < 5.0
    assert len(res) >= 1


# --- F3 Boundary Cases (5 cases) ---


def test_tier2_f3_01_api_jwt_allow_live_blocked_on_blocked_signal_program(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _sandbox_target_server() as (base_url, records):
        (tmp_path / "openapi.yaml").write_text(
            "openapi: 3.0.0\nservers:\n  - url: https://api.example.com\npaths: {}\n",
            encoding="utf-8",
        )
        res = audit_api_and_jwt(
            tmp_path,
            program="shopify",
            allow_live=True,
            eligibility_db=elig,
            target_hosts=[base_url],
        )
        assert res == []
        assert len(records) == 0


def test_tier2_f3_02_api_jwt_allow_live_requires_eligibility_db(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    with _scoped_env(RFCHUNT_ELIGIBILITY_DB=str(tmp_path / "empty_elig.sqlite3")):
        with _sandbox_target_server() as (base_url, records):
            (tmp_path / "openapi.yaml").write_text(
                "openapi: 3.0.0\nservers:\n  - url: https://api.example.com\npaths: {}\n",
                encoding="utf-8",
            )
            res = audit_api_and_jwt(
                tmp_path,
                program="common_codes",
                allow_live=True,
                eligibility_db=None,
                target_hosts=[base_url],
            )
            assert res == []
            assert len(records) == 0


def test_tier2_f3_03_api_jwt_malformed_jwt_tokens_handled_safely(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    (tmp_path / "tokens.py").write_text(
        'BAD1 = "not.a.jwt"\nBAD2 = "eyJ$$$.eyJ.sig"\n', encoding="utf-8"
    )
    res = audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True)
    assert isinstance(res, list)


def test_tier2_f3_04_api_jwt_ssrf_metadata_in_openapi_server_flagged(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    (tmp_path / "openapi.yaml").write_text(
        "openapi: 3.0.0\n"
        "servers:\n"
        '  - url: "http://169.254.169.254/latest/meta-data/"\n'
        "paths: {}\n",
        encoding="utf-8",
    )
    findings = audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1


def test_tier2_f3_05_api_jwt_malformed_openapi_yaml_no_crash(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    (tmp_path / "openapi.yaml").write_text("openapi: 3.0.0\npaths: [unclosed\n", encoding="utf-8")
    res = audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True)
    assert isinstance(res, list)


# --- F4 Boundary Cases (5 cases) ---


def test_tier2_f4_01_ai_infra_empty_comment_dockerfile_returns_empty(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "Dockerfile").write_text("# empty dockerfile\n", encoding="utf-8")
    assert audit_ai_infra(tmp_path) == []


def test_tier2_f4_02_ai_infra_malformed_python_syntax_no_crash(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "broken.py").write_text("def foo(:\n    pass\n", encoding="utf-8")
    res = audit_ai_infra(tmp_path)
    assert isinstance(res, list)


def test_tier2_f4_03_ai_infra_malformed_k8s_yaml_no_crash(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "k8s.yaml").write_text("kind: Deployment\n\tbad:\n  [unclosed\n", encoding="utf-8")
    res = audit_ai_infra(tmp_path)
    assert isinstance(res, list)


def test_tier2_f4_04_ai_infra_safe_yaml_and_weights_only_clean(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "safe.py").write_text(
        "import yaml, torch\n"
        "def load(s, p):\n"
        "    return yaml.safe_load(s), torch.load(p, weights_only=True)\n",
        encoding="utf-8",
    )
    assert audit_ai_infra(tmp_path) == []


def test_tier2_f4_05_ai_infra_deep_nesting_and_large_file_bounded(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    cur = tmp_path
    for i in range(15):
        cur = cur / f"d{i}"
    cur.mkdir(parents=True)
    (cur / "leaf.py").write_text("x = 1\n" + ("# pad\n" * 50000), encoding="utf-8")
    t0 = time.monotonic()
    res = audit_ai_infra(tmp_path)
    assert isinstance(res, list)
    assert (time.monotonic() - t0) < 10.0


# --- F5 Boundary Cases (5 cases) ---


def test_tier2_f5_01_parity_empty_target_files_returns_empty(tmp_path: Path) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    (tmp_path / "packages" / "a").mkdir(parents=True)
    (tmp_path / "packages" / "a" / "x.ts").write_text("export function f() {}\n", encoding="utf-8")
    assert audit_parity_and_invariants(tmp_path, target_files=[]) == []


def test_tier2_f5_02_parity_nonexistent_target_file_skips_cleanly(tmp_path: Path) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    res = audit_parity_and_invariants(tmp_path, target_files=["does_not_exist.ts"])
    assert res == []


def test_tier2_f5_03_parity_symlink_escaping_repo_rejected_safely(tmp_path: Path) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    outside = tmp_path / "outside_secret"
    outside.mkdir()
    (outside / "auth.ts").write_text(
        "export function handleInbound(x: any) { return x; }\n", encoding="utf-8"
    )
    repo = tmp_path / "repo"
    (repo / "packages" / "app-a").mkdir(parents=True)
    (repo / "packages" / "app-a" / "auth.ts").write_text(
        "export function handleInbound(x: any) { return sanitizeInput(x); }\n", encoding="utf-8"
    )
    link_path = repo / "packages" / "evil"
    try:
        os.symlink(str(outside), str(link_path), target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation requires elevated privileges on this Windows host")
    findings = audit_parity_and_invariants(repo)
    assert not any("outside_secret" in str(_fget(f, "file_path", "")) for f in findings)


def test_tier2_f5_04_parity_comments_mentioning_sanitize_still_flag_gap(tmp_path: Path) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    (tmp_path / "packages" / "app-a").mkdir(parents=True)
    (tmp_path / "packages" / "app-b").mkdir(parents=True)
    (tmp_path / "packages" / "app-a" / "auth.ts").write_text(
        "export function handleInbound(req: any) {\n"
        "  verifySignature(req);\n"
        "  return sanitizeInput(req.body);\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "packages" / "app-b" / "auth.ts").write_text(
        "export function handleInbound(req: any) {\n"
        "  // TODO: sanitizeInput and verifySignature later\n"
        "  return req.body;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = audit_parity_and_invariants(tmp_path)
    assert len(findings) >= 1


def test_tier2_f5_05_parity_multi_language_repo_no_cross_language_false_positive(
    tmp_path: Path,
) -> None:
    from engine.parity_invariant_auditor import audit_parity_and_invariants

    (tmp_path / "sdk" / "ts").mkdir(parents=True)
    (tmp_path / "sdk" / "py").mkdir(parents=True)
    (tmp_path / "sdk" / "go").mkdir(parents=True)
    (tmp_path / "sdk" / "ts" / "client.ts").write_text(
        "export function verify(x: string) { return sanitize(x); }\n", encoding="utf-8"
    )
    (tmp_path / "sdk" / "py" / "client.py").write_text(
        "def verify(x: str):\n    return sanitize(x)\n", encoding="utf-8"
    )
    (tmp_path / "sdk" / "go" / "client.go").write_text(
        "package sdk\nfunc Verify(x string) string { return Sanitize(x) }\n", encoding="utf-8"
    )
    findings = audit_parity_and_invariants(tmp_path)
    assert findings == []


# --- F6 Boundary Cases (5 cases) ---


def test_tier2_f6_01_ollama_guard_acquire_timeout_when_lock_held(tmp_path: Path) -> None:
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    lock_path = tmp_path / "contended.lock"
    holder_entered = threading.Event()
    release_holder = threading.Event()

    def _hold() -> None:
        g = OllamaConcurrencyGuard(lock_path=lock_path, acquire_timeout_sec=5.0)
        with g.acquire():
            holder_entered.set()
            release_holder.wait(timeout=2.0)

    t = threading.Thread(target=_hold, daemon=True)
    t.start()
    assert holder_entered.wait(timeout=2.0)
    try:
        contender = OllamaConcurrencyGuard(lock_path=lock_path, acquire_timeout_sec=0.1)
        t0 = time.monotonic()
        with contender.acquire(timeout_sec=0.1) as acquired:
            assert acquired is False
        elapsed = time.monotonic() - t0
        assert elapsed < 1.5
    finally:
        release_holder.set()
        t.join(timeout=2.0)


def test_tier2_f6_02_ollama_guard_oom_with_no_smaller_model_trips_cleanly(tmp_path: Path) -> None:
    from engine.gha_llm_verifier import verify_gha_findings_with_llm
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    guard = OllamaConcurrencyGuard(lock_path=tmp_path / "only12b.lock")
    assert guard.downshift_candidates("gemma-4-12b-abliterated", ["gemma-4-12b-abliterated"]) == []

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("on: pull_request_target\njobs: {}\n", encoding="utf-8")
    static_f = [
        EngineFinding(engine="zizmor", title="pwn", file_path=".github/workflows/ci.yml", line=1)
    ]
    with _ollama_loopback_server({"models": ["gemma-4-12b-abliterated"], "always_oom": True}) as (
        endpoint,
        _state,
    ):
        findings, telemetry = verify_gha_findings_with_llm(
            tmp_path,
            static_f,
            model="gemma-4-12b-abliterated",
            ollama_endpoint=endpoint,
            env_local_path=tmp_path / "missing.env",
            force_ollama=True,
            guard=guard,
        )
        assert findings == []
        assert telemetry.get("status") != "completed"


def test_tier2_f6_03_ollama_guard_circuit_breaker_short_circuits_zero_http(tmp_path: Path) -> None:
    from engine.gha_llm_verifier import verify_gha_findings_with_llm
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("on: pull_request_target\njobs: {}\n", encoding="utf-8")
    static_f = [
        EngineFinding(engine="zizmor", title="pwn", file_path=".github/workflows/ci.yml", line=1)
    ]
    guard = OllamaConcurrencyGuard(
        lock_path=tmp_path / "cb.lock", failure_threshold=2, cooldown_sec=60.0
    )

    try:
        with _ollama_loopback_server({"models": ["qwen2.5:7b"], "always_oom": True}) as (
            endpoint,
            state,
        ):
            for _ in range(2):
                verify_gha_findings_with_llm(
                    tmp_path,
                    static_f,
                    model="qwen2.5:7b",
                    ollama_endpoint=endpoint,
                    env_local_path=tmp_path / "missing.env",
                    force_ollama=True,
                    guard=guard,
                )
            calls_before_open = len(state["chat_calls"])
            assert guard.is_circuit_open() is True
            _, tel3 = verify_gha_findings_with_llm(
                tmp_path,
                static_f,
                model="qwen2.5:7b",
                ollama_endpoint=endpoint,
                env_local_path=tmp_path / "missing.env",
                force_ollama=True,
                guard=guard,
            )
            assert tel3.get("status") == "skipped_circuit_open"
            assert len(state["chat_calls"]) == calls_before_open
    finally:
        guard.reset()


def test_tier2_f6_04_ollama_guard_circuit_breaker_cooldown_recovery(tmp_path: Path) -> None:
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    guard = OllamaConcurrencyGuard(
        lock_path=tmp_path / "cool.lock", failure_threshold=2, cooldown_sec=0.2
    )
    guard.record_failure(is_oom=True)
    guard.record_failure(is_oom=True)
    assert guard.is_circuit_open() is True
    time.sleep(0.28)
    assert guard.is_circuit_open() is False


def test_tier2_f6_05_ollama_400ms_unreachable_and_non_json_500_safe(tmp_path: Path) -> None:
    from engine.gha_llm_verifier import resolve_gha_llm_backend, verify_gha_findings_with_llm
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    guard = OllamaConcurrencyGuard(lock_path=tmp_path / "nonjson.lock")
    t0 = time.monotonic()
    res = resolve_gha_llm_backend(
        ollama_endpoint="http://127.0.0.1:9",
        probe_timeout_sec=0.4,
        env_local_path=tmp_path / "missing.env",
        force_ollama=True,
        guard=guard,
    )
    assert (time.monotonic() - t0) < 2.0
    assert res.status == "skipped_unreachable"

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("on: pull_request_target\njobs: {}\n", encoding="utf-8")
    static_f = [
        EngineFinding(engine="zizmor", title="pwn", file_path=".github/workflows/ci.yml", line=1)
    ]
    with _ollama_loopback_server({"models": ["qwen2.5:7b"], "non_json_500": True}) as (
        endpoint,
        _state,
    ):
        findings, telemetry = verify_gha_findings_with_llm(
            tmp_path,
            static_f,
            model="qwen2.5:7b",
            ollama_endpoint=endpoint,
            env_local_path=tmp_path / "missing.env",
            force_ollama=True,
            guard=guard,
        )
        assert findings == []
        assert telemetry.get("status") != "completed"
        assert telemetry.get("error")


# --- F7 Boundary Cases (5 cases) ---


def test_tier2_f7_01_runner_rejects_unc_and_critical_host_mounts() -> None:
    for bad in (r"\\attacker\share\repo", "//attacker/share/repo", r"C:\Windows\System32", "/etc"):
        ok, _ = validate_mount_path(bad)
        assert ok is False


def test_tier2_f7_02_runner_rejects_shell_metacharacters_in_commands() -> None:
    for bad_cmd in (["node", "a.js;id"], ["sh", "$(id)"], ["a\nb"], [""]):
        ok, _ = validate_command_tokens(bad_cmd)
        assert ok is False


def test_tier2_f7_03_sandbox_http_probe_blocks_ssrf_targets(tmp_path: Path) -> None:
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    runner = LinuxPocRunner()
    for bad_url in (
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:127.0.0.1]/",
        "http://0.0.0.0/",
    ):
        res = runner.verify_sandbox_http_probe(
            bad_url, program="common_codes", eligibility_db=elig
        )
        assert res.get("verified") is False
        assert res.get("status") == "rejected_ssrf"


def test_tier2_f7_04_probe_optional_backends_clamps_timeout(tmp_path: Path) -> None:
    t0 = time.monotonic()
    r1 = probe_optional_backends(lean_dir=tmp_path, timeout_sec=99.0)
    r2 = probe_optional_backends(lean_dir=tmp_path, timeout_sec=0.01)
    assert (time.monotonic() - t0) < 10.0
    assert isinstance(r1, dict) and isinstance(r2, dict)


def test_tier2_f7_05_runner_rejects_unsupported_language_and_invalid_image(tmp_path: Path) -> None:
    runner = LinuxPocRunner()
    with pytest.raises(ValueError):
        runner.run_poc(language="cobol", repo_path=tmp_path, cmd=["echo", "hi"])
    with pytest.raises(ValueError):
        build_hardened_docker_argv(
            docker_bin="docker", image="bad;img", repo_dir=tmp_path, cmd=["python3", "-V"]
        )


# --- F8 Boundary Cases (5 cases) ---


def test_tier2_f8_01_acdso_anomaly_scorer_zero_rows_no_crash() -> None:
    from engine.acdso_bridge import ACDSOAnomalyScorer

    assert ACDSOAnomalyScorer().fit_score([]) == []


def test_tier2_f8_02_acdso_anomaly_scorer_one_row_no_crash() -> None:
    from engine.acdso_bridge import ACDSOAnomalyScorer

    scores = ACDSOAnomalyScorer().fit_score([{"severity_score": 0.9, "confidence": 0.95}])
    assert len(scores) == 1
    assert math.isfinite(scores[0])


def test_tier2_f8_03_acdso_two_lane_scheduler_single_class_and_zero_std_rewards() -> None:
    from engine.acdso_bridge import TwoLanePolicyScheduler

    sched = TwoLanePolicyScheduler()
    l1, l2 = _invoke_two_lane_scheduler(
        sched,
        queue_capacity=10,
        signal=0.5,
        actions=[1, 1, 1, 1],
        rewards=[0.5, 0.5, 0.5, 0.5],
    )
    assert l1 >= 5
    assert l1 + l2 == 10


def test_tier2_f8_04_acdso_pareto_nan_inf_handling_and_empty_rank() -> None:
    from engine.acdso_bridge import (
        CandidateResult,
        knee_point_selection,
        pareto_front,
        rank_stage2_candidates,
    )

    c_nan = _make_candidate_result(
        CandidateResult,
        name="nan_cand",
        metric=float("nan"),
        train_time_s=float("inf"),
    )
    c_fin = _make_candidate_result(CandidateResult, name="finite_cand", metric=0.85)
    front = pareto_front([c_nan, c_fin])
    picked = knee_point_selection(front, preference="balanced")
    assert picked.name == "finite_cand"

    empty_res = rank_stage2_candidates([], top_k=5)
    assert empty_res["selected"] == []


def test_tier2_f8_05_acdso_two_lane_scheduler_capacity_0_and_1_negative_signal() -> None:
    from engine.acdso_bridge import TwoLanePolicyScheduler

    sched = TwoLanePolicyScheduler()
    assert _invoke_two_lane_scheduler(sched, queue_capacity=0, signal=0.0) == (0, 0)
    assert _invoke_two_lane_scheduler(sched, queue_capacity=1, signal=-1.0) == (1, 0)


# --- F9 Boundary Cases (5 cases) ---


def test_tier2_f9_01_blackboard_crash_recovery_in_progress_to_pending_zero_lost_facts(
    tmp_path: Path,
) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    db_path = tmp_path / "crash.sqlite3"
    bb1 = SqliteBlackboard(db_path)
    try:
        bb1.add_fact(source_engine="lean4", title="Fact 1", file_path="src/a.py", severity="CRITICAL")
        bb1.add_fact(source_engine="z3_formal", title="Fact 2", file_path="src/b.py", severity="HIGH")
        bb1.enqueue_intent(intent_type="stage1", payload={"f": "a"}, lane=1)
        bb1.enqueue_intent(intent_type="stage1", payload={"f": "b"}, lane=2)
        assert bb1.claim_intent("crashed-w") is not None
        assert bb1.claim_intent("crashed-w") is not None
    finally:
        _close_if_supported(bb1)

    bb2 = SqliteBlackboard(db_path)
    try:
        recovered = bb2.recover_stale_intents(force_all_in_progress=True)
        assert int(recovered["recovered_to_pending"]) == 2
        assert len(bb2.list_facts()) == 2
        assert bb2.claim_intent("new-w") is not None
        assert bb2.claim_intent("new-w") is not None
    finally:
        _close_if_supported(bb2)


def test_tier2_f9_02_blackboard_lease_expiry_recovery_via_now_epoch(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    bb = SqliteBlackboard(tmp_path / "lease.sqlite3")
    try:
        bb.enqueue_intent(intent_type="stage1", payload={"id": "expired"}, lane=2)
        c1 = bb.claim_intent("w-old", lease_sec=5.0)
        assert c1 is not None
        assert int(bb.recover_stale_intents(now_epoch=time.time() + 1.0)["recovered_to_pending"]) == 0
        assert int(bb.recover_stale_intents(now_epoch=time.time() + 60.0)["recovered_to_pending"]) == 1
        c2 = bb.claim_intent("w-new", lease_sec=30.0)
        assert c2 is not None and c2["intent_id"] == c1["intent_id"]
    finally:
        _close_if_supported(bb)


def test_tier2_f9_03_blackboard_concurrent_claim_atomicity(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    db_path = tmp_path / "atomic.sqlite3"
    bb = SqliteBlackboard(db_path)
    try:
        bb.enqueue_intent(intent_type="stage1", payload={"only": 1}, lane=2)
    finally:
        _close_if_supported(bb)

    barrier = threading.Barrier(2)
    results: List[Optional[Dict[str, Any]]] = []
    lock = threading.Lock()

    def _claim(wid: str) -> None:
        local_bb = SqliteBlackboard(db_path)
        try:
            barrier.wait(timeout=3.0)
            got = local_bb.claim_intent(wid)
            with lock:
                results.append(got)
        finally:
            _close_if_supported(local_bb)

    t1 = threading.Thread(target=_claim, args=("w1",))
    t2 = threading.Thread(target=_claim, args=("w2",))
    t1.start()
    t2.start()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)
    assert len(results) == 2
    assert sum(1 for r in results if r is not None) == 1


def test_tier2_f9_04_blackboard_empty_db_queries(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    bb = SqliteBlackboard(tmp_path / "empty.sqlite3")
    try:
        assert bb.list_facts() == []
        assert bb.list_hints() == []
        assert bb.claim_intent("w") is None
        assert int(bb.recover_stale_intents()["recovered_to_pending"]) == 0
    finally:
        _close_if_supported(bb)


def test_tier2_f9_05_blackboard_unicode_payload_utf8_roundtrip(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    bb = SqliteBlackboard(tmp_path / "unicode.sqlite3")
    try:
        marker = "unicode_payload_check_alpha_\u03b1_\u65e5\u672c\u8a9e"
        bb.add_fact(
            source_engine="trufflehog",
            title=marker,
            file_path="src/u.py",
            severity="MEDIUM",
            payload={"note": marker},
        )
        facts = bb.list_facts()
        assert len(facts) == 1
        assert marker in json.dumps(facts[0], ensure_ascii=False)
    finally:
        _close_if_supported(bb)


# --- F10 Boundary Cases (5 cases) ---


def test_tier2_f10_01_process_pool_clamps_non_positive_cpu_workers(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import run_local_rfchunt_async

    repo = _init_git_repo(tmp_path / "repo", {"src/a.py": "x = 1\n"})
    for w in (1, 0, -5):
        res = asyncio.run(
            run_local_rfchunt_async(
                [{"intent_type": "stage1", "payload": {"repo_path": str(repo)}}],
                repo_path=repo,
                db_path=tmp_path / f"w_{w}.sqlite3",
                max_cpu_workers=w,
            )
        )
        assert res.get("status") == "completed"
        assert int(res.get("cpu_workers", 0)) == 1


def test_tier2_f10_02_process_pool_missing_repo_intent_fails_cleanly(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import run_local_rfchunt_async

    res = asyncio.run(
        run_local_rfchunt_async(
            [{"intent_type": "stage1", "payload": {"repo_path": str(tmp_path / "missing_repo")}}],
            repo_path=tmp_path,
            db_path=tmp_path / "err.sqlite3",
            max_cpu_workers=2,
        )
    )
    assert res.get("status") == "completed"
    assert res.get("facts") == []


def test_tier2_f10_03_empty_seed_intents_completes_immediately(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import run_local_rfchunt_async

    res = asyncio.run(
        run_local_rfchunt_async(
            [],
            repo_path=tmp_path,
            db_path=tmp_path / "empty_seeds.sqlite3",
            max_cpu_workers=2,
        )
    )
    assert res.get("status") == "completed"
    assert int(res.get("intents_failed", 0)) == 0


def test_tier2_f10_04_resume_true_recovers_in_progress_without_duplicating_done(
    tmp_path: Path,
) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, run_local_rfchunt_async

    repo = _init_git_repo(tmp_path / "repo", {"src/a.py": "x = 1\n"})
    db_path = tmp_path / "resume.sqlite3"
    bb = SqliteBlackboard(db_path)
    try:
        id_done = bb.enqueue_intent(intent_type="stage1", payload={"repo_path": str(repo), "k": "done"}, lane=2)
        c_done = bb.claim_intent("old-w")
        assert c_done is not None and c_done["intent_id"] == id_done
        bb.complete_intent(id_done, result={"ok": True})

        bb.enqueue_intent(intent_type="stage1", payload={"repo_path": str(repo), "k": "crashed"}, lane=2)
        assert bb.claim_intent("old-w") is not None  # left IN_PROGRESS
        bb.enqueue_intent(intent_type="stage1", payload={"repo_path": str(repo), "k": "pending"}, lane=2)
    finally:
        _close_if_supported(bb)

    res = asyncio.run(
        run_local_rfchunt_async(
            None,
            repo_path=repo,
            db_path=db_path,
            max_cpu_workers=2,
            resume=True,
        )
    )
    assert int((res.get("recovery") or {}).get("recovered_to_pending", 0)) >= 1
    assert int(res.get("intents_completed", 0)) == 2
    bb_check = SqliteBlackboard(db_path)
    try:
        done_rows = bb_check.list_intents(status="DONE", limit=20)
        done_by_id = {row["intent_id"]: row for row in done_rows}
        assert id_done in done_by_id
        assert done_by_id[id_done].get("result") == {"ok": True}
    finally:
        _close_if_supported(bb_check)


def test_tier2_f10_05_max_net_concurrency_1_strict_serialization(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import run_local_rfchunt_async

    repo = _init_git_repo(
        tmp_path / "repo",
        {f"src/m{i}.py": f"import pickle\ndef f{i}(d): return pickle.loads(d)\n" for i in range(4)},
    )
    inflight = 0
    max_seen = 0
    eval_calls = 0
    lock = threading.Lock()

    def _eval(_cand: Any) -> Dict[str, Any]:
        nonlocal inflight, max_seen, eval_calls
        with lock:
            eval_calls += 1
            inflight += 1
            max_seen = max(max_seen, inflight)
        try:
            time.sleep(0.03)
            return {"confirmed": True}
        finally:
            with lock:
                inflight -= 1

    seeds = [{"intent_type": "stage1", "payload": {"repo_path": str(repo), "i": i}} for i in range(5)]
    res = asyncio.run(
        run_local_rfchunt_async(
            seeds,
            repo_path=repo,
            db_path=tmp_path / "net1.sqlite3",
            max_cpu_workers=2,
            max_net_concurrency=1,
            ollama_evaluator=_eval,
        )
    )
    assert eval_calls >= 3
    assert len(res.get("stage3_results") or []) >= 3
    assert max_seen == 1


# --- F11 Boundary Cases (5 cases) ---


def test_tier2_f11_01_loop1_corrupted_json_does_not_crash_or_poison_etag(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    routes: Dict[str, Any] = {
        "/repos/acme/bad/releases?per_page=5": {"status": 200, "etag": '"bad-e"', "raw_bytes": b"{not valid json"},
        "/repos/acme/bad/pulls?state=closed&sort=updated&direction=desc&per_page=10": {"status": 200, "body": []},
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                summary = _invoke_poller_once(
                    poller,
                    [WatchTarget(program="anthropic", repo="acme/bad")],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
            finally:
                _close_if_supported(poller)
        assert len(summary.get("errors", [])) >= 1
        assert len(summary.get("enqueued_intent_ids") or []) == 0
    finally:
        _close_if_supported(bb)


def test_tier2_f11_02_loop1_http_403_on_one_repo_still_polls_second(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
    routes: Dict[str, Any] = {
        "/repos/acme/rate-limited/releases?per_page=5": {"status": 403, "body": {"message": "rate limit"}},
        "/repos/acme/rate-limited/pulls?state=closed&sort=updated&direction=desc&per_page=10": {"status": 403, "body": {}},
        "/repos/acme/good/releases?per_page=5": {
            "status": 200,
            "etag": '"good-1"',
            "body": [{"tag_name": "v1.0.1", "target_commitish": "goodsha1", "published_at": fresh_ts, "body": "fix auth token SSRF verify"}],
        },
        "/repos/acme/good/pulls?state=closed&sort=updated&direction=desc&per_page=10": {"status": 200, "body": []},
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                summary = _invoke_poller_once(
                    poller,
                    [
                        WatchTarget(program="anthropic", repo="acme/rate-limited"),
                        WatchTarget(program="common_codes", repo="acme/good"),
                    ],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
            finally:
                _close_if_supported(poller)
        assert len(summary.get("errors", [])) >= 1
        assert len(summary.get("enqueued_intent_ids") or []) >= 1
    finally:
        _close_if_supported(bb)


def test_tier2_f11_03_loop1_empty_targets_and_empty_pr_files(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
    routes: Dict[str, Any] = {
        "/repos/acme/nofiles/releases?per_page=5": {"status": 200, "body": []},
        "/repos/acme/nofiles/pulls?state=closed&sort=updated&direction=desc&per_page=10": {
            "status": 200,
            "body": [{"number": 9, "title": "empty pr", "merged_at": fresh_ts, "merge_commit_sha": "sha9"}],
        },
        "/repos/acme/nofiles/pulls/9/files?per_page=30": {"status": 200, "body": []},
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                s_empty = _invoke_poller_once(
                    poller, [], eligibility_db=elig, blackboard=bb, api_base=api_base, http_get=_make_real_http_get(api_base)
                )
                assert len(s_empty.get("enqueued_intent_ids") or []) == 0
                s_nofiles = _invoke_poller_once(
                    poller,
                    [WatchTarget(program="anthropic", repo="acme/nofiles")],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
                assert len(s_nofiles.get("enqueued_intent_ids") or []) == 0
                assert int(s_nofiles.get("targets_checked", 0)) == 1
            finally:
                _close_if_supported(poller)
    finally:
        _close_if_supported(bb)


def test_tier2_f11_04_loop1_skips_paused_and_not_found_programs(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server({}) as (api_base, state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                summary = _invoke_poller_once(
                    poller,
                    [
                        WatchTarget(program="mozilla", repo="mozilla/gecko"),
                        WatchTarget(program="openai", repo="openai/sdk"),
                    ],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
            finally:
                _close_if_supported(poller)
        assert len(summary.get("skipped_ineligible") or []) == 2
        assert set(summary["skipped_ineligible"]) == {"mozilla", "openai"}
        assert state["__requests__"] == []
    finally:
        _close_if_supported(bb)


def test_tier2_f11_05_loop1_deduplicates_identical_sha_across_polls(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard
    from engine.freshness_watcher import AsyncFreshnessPoller

    fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
    routes: Dict[str, Any] = {
        "/repos/acme/dup/releases?per_page=5": {"status": 200, "etag": '"r1"', "body": []},
        "/repos/acme/dup/pulls?state=closed&sort=updated&direction=desc&per_page=10": {
            "status": 200,
            "etag": '"p1"',
            "body": [
                {
                    "number": 11,
                    "title": "fix: csp header",
                    "merged_at": fresh_ts,
                    "merge_commit_sha": "same_sha_11",
                }
            ],
        },
        "/repos/acme/dup/pulls/11/files?per_page=30": {
            "status": 200,
            "etag": '"f1"',
            "body": [{"filename": "src/csp.ts"}],
        },
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                targets = [WatchTarget(program="anthropic", repo="acme/dup")]
                http_get = _make_real_http_get(api_base)
                s1 = _invoke_poller_once(poller, targets, eligibility_db=elig, blackboard=bb, api_base=api_base, http_get=http_get)
                first_enq = len(s1.get("enqueued_intent_ids") or [])
                assert first_enq >= 1
                # Change ETag so server returns 200 with exact same SHA
                routes["/repos/acme/dup/pulls?state=closed&sort=updated&direction=desc&per_page=10"]["etag"] = '"p2"'
                s2 = _invoke_poller_once(poller, targets, eligibility_db=elig, blackboard=bb, api_base=api_base, http_get=http_get)
                assert len(s2.get("enqueued_intent_ids") or []) == 0
            finally:
                _close_if_supported(poller)
    finally:
        _close_if_supported(bb)


# --- F12 Boundary Cases (5 cases) ---


def test_tier2_f12_01_loop2_depth_ge_max_depth_terminates_immediately(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, emit_sibling_parity_intents

    (tmp_path / "packages" / "a").mkdir(parents=True)
    (tmp_path / "packages" / "b").mkdir(parents=True)
    (tmp_path / "packages" / "a" / "x.ts").write_text("export function f() {}\n", encoding="utf-8")
    (tmp_path / "packages" / "b" / "x.ts").write_text("export function f() {}\n", encoding="utf-8")
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        assert (
            emit_sibling_parity_intents(
                bb,
                repo_path=str(tmp_path),
                changed_files=["packages/a/x.ts"],
                trigger_reason="security_fix:sanitize",
                depth=2,
                max_depth=2,
            )
            == []
        )
        assert (
            emit_sibling_parity_intents(
                bb,
                repo_path=str(tmp_path),
                changed_files=["packages/a/x.ts"],
                trigger_reason="security_fix:sanitize",
                depth=0,
                max_depth=0,
            )
            == []
        )
    finally:
        _close_if_supported(bb)


def test_tier2_f12_02_loop2_non_security_commit_returns_empty() -> None:
    from engine.async_blackboard_runtime import detect_security_fix_signal

    assert detect_security_fix_signal("chore: update README badges and typos", "") == []


def test_tier2_f12_03_loop2_case_insensitive_keyword_matching() -> None:
    from engine.async_blackboard_runtime import detect_security_fix_signal

    matched = [
        k.lower()
        for k in detect_security_fix_signal("Fix O_NOFOLLOW + allowFrom + SSRF + CSP + AUTHZ", "")
    ]
    for expected in ("o_nofollow", "allowfrom", "ssrf", "csp", "authz"):
        assert expected in matched


def test_tier2_f12_04_loop2_partial_sdk_repo_only_emits_present_sdks(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, emit_sibling_parity_intents

    (tmp_path / "sdk" / "ts").mkdir(parents=True)
    (tmp_path / "sdk" / "rust").mkdir(parents=True)
    (tmp_path / "sdk" / "ts" / "client.ts").write_text("export function verify() {}\n", encoding="utf-8")
    (tmp_path / "sdk" / "rust" / "client.rs").write_text("pub fn verify() {}\n", encoding="utf-8")

    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        emitted = emit_sibling_parity_intents(
            bb,
            repo_path=str(tmp_path),
            changed_files=["sdk/ts/client.ts"],
            trigger_reason="security_fix:verify",
        )
        assert len(emitted) == 1
        claimed = bb.claim_intent("w1")
        assert claimed is not None
        assert "rust" in json.dumps(claimed).lower()
        assert "python" not in json.dumps(claimed).lower()
    finally:
        _close_if_supported(bb)


def test_tier2_f12_05_loop2_empty_changed_files_returns_empty(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, emit_sibling_parity_intents

    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        assert (
            emit_sibling_parity_intents(
                bb,
                repo_path=str(tmp_path),
                changed_files=[],
                trigger_reason="security_fix:ssrf",
            )
            == []
        )
    finally:
        _close_if_supported(bb)


# --- F13 Boundary Cases (5 cases) ---


def test_tier2_f13_01_loop5_signal_0999_vs_1000_boundary(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, TwoLaneBountyQueue

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        q = TwoLaneBountyQueue(elig, bb)
        s_under = _call_two_lane_queue_schedule(q, queue_capacity=10, signal_score=0.999, eligibility_db=elig)
        s_exact = _call_two_lane_queue_schedule(q, queue_capacity=10, signal_score=1.0, eligibility_db=elig)
        assert len(s_under["lane1_programs_queued"]) >= 5
        assert isinstance(s_exact["lane2_programs_queued"], list)
    finally:
        _close_if_supported(bb)


def test_tier2_f13_02_loop5_refuses_to_stage_unverified_draft_even_when_unlocked(
    tmp_path: Path,
) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, sync_eligibility_and_stage_unlocks

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    elig.upsert("shopify", "UNLOCKED")
    drafts_dir = tmp_path / "drafts"
    drafts_dir.mkdir()
    (drafts_dir / "unverified.json").write_text(
        json.dumps(
            {
                "program_handle": "shopify",
                "asset": "@shopify/shopify-app-remix",
                "weakness_cwe": "CWE-639",
                "severity_rating": "High",
                "title": "Unverified draft",
                "vulnerability_information": "x" * 120,
                "impact": "High",
                "poc_verified": False,
            }
        ),
        encoding="utf-8",
    )
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        res = sync_eligibility_and_stage_unlocks(elig, bb, drafts_dir)
        staged = [d for d in (res.get("staged_drafts") or []) if d.get("status") == "staged_ready"]
        assert staged == []
    finally:
        _close_if_supported(bb)


def test_tier2_f13_03_loop5_ignores_malformed_json_draft_and_stages_valid(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, sync_eligibility_and_stage_unlocks

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    elig.upsert("shopify", "UNLOCKED")
    drafts_dir = tmp_path / "drafts"
    drafts_dir.mkdir()
    (drafts_dir / "corrupt.json").write_text("{broken json", encoding="utf-8")
    (drafts_dir / "valid.json").write_text(
        json.dumps(
            {
                "program_handle": "shopify",
                "asset": "@shopify/shopify-app-remix",
                "weakness_cwe": "CWE-639",
                "severity_rating": "High",
                "title": "Valid CSP gap in @shopify/shopify-app-remix",
                "vulnerability_information": "Detailed reproducible PoC description exceeding 100 characters for verification gate.",
                "impact": "Cross-origin framing risk.",
                "poc_verified": True,
            }
        ),
        encoding="utf-8",
    )
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        res = sync_eligibility_and_stage_unlocks(elig, bb, drafts_dir)
        assert len(res.get("staged_drafts") or []) >= 1
    finally:
        _close_if_supported(bb)


def test_tier2_f13_04_loop5_missing_drafts_dir_succeeds_cleanly(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, sync_eligibility_and_stage_unlocks

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        res = sync_eligibility_and_stage_unlocks(elig, bb, tmp_path / "nonexistent_drafts")
        assert isinstance(res, dict)
        assert (res.get("staged_drafts") or []) == []
    finally:
        _close_if_supported(bb)


def test_tier2_f13_05_loop5_unlocked_flipped_to_paused_stops_queuing(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, sync_eligibility_and_stage_unlocks

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    elig.upsert("shopify", "UNLOCKED")
    elig.upsert("shopify", "PAUSED")
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        res = sync_eligibility_and_stage_unlocks(elig, bb, tmp_path / "drafts")
        assert "shopify" not in (res.get("newly_unlocked") or [])
        assert "shopify" not in (res.get("unlocked_programs") or [])
    finally:
        _close_if_supported(bb)


# --- F14 Boundary Cases (5 cases) ---


def test_tier2_f14_01_noise_filter_windows_backslash_and_case_normalization() -> None:
    from engine.parity_invariant_auditor import is_non_production_noise

    assert is_non_production_noise(r"Tests\Unit\Auth.Test.TS") is True
    assert is_non_production_noise(r".\fixtures\payload.json") is True


def test_tier2_f14_02_noise_filter_preserves_prod_names_containing_test_substring() -> None:
    from engine.parity_invariant_auditor import is_non_production_noise

    assert is_non_production_noise("src/attestation_verifier.py") is False
    assert is_non_production_noise("src/contest_handler.ts") is False


def test_tier2_f14_03_unknown_engine_weight_falls_back_safely() -> None:
    voter = EnsembleConsensusVoter(program="generic", quorum=2)
    f = EngineFinding(engine="custom_unknown", title="Custom issue", file_path="src/x.py", severity="HIGH")
    clusters = voter.fuse([f])
    assert len(clusters) == 1
    assert 0.0 < clusters[0].ensemble_confidence <= 1.0


def test_tier2_f14_04_filter_production_candidates_empty_input() -> None:
    from engine.parity_invariant_auditor import filter_production_candidates

    prod, noise = filter_production_candidates([])
    assert prod == [] and noise == []


def test_tier2_f14_05_unconfirmed_critical_dissent_does_not_inflate_confirmed_low() -> None:
    findings = [
        EngineFinding(
            engine="lean4",
            title="Minor invariant",
            file_path="src/x.rs",
            line=10,
            severity="LOW",
            deterministic=True,
            confirmed=True,
        ),
        EngineFinding(
            engine="gha_llm",
            title="Minor invariant",
            file_path="src/x.rs",
            line=11,
            severity="CRITICAL",
            deterministic=False,
            confirmed=False,
        ),
    ]
    clusters = EnsembleConsensusVoter(program="generic", quorum=2).fuse(findings)
    assert len(clusters) == 1
    assert clusters[0].severity == "LOW"


# --- F15 Boundary Cases (5 cases) ---


def test_tier2_f15_01_loop3_empty_repo_produces_zero_clusters_and_zero_ollama_calls(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _ollama_loopback_server({"models": ["qwen2.5:7b"]}) as (endpoint, state):
        with _scoped_env(OLLAMA_HOST=endpoint):
            orch = EnsembleOrchestrator(program="common_codes", embedded=False)
            res = orch.run_fast_parallel_ooda(
                empty,
                program="common_codes",
                blackboard_db=tmp_path / "bb.sqlite3",
                max_cpu_workers=2,
                eligibility_db=elig,
            )
    assert res.get("status") == "completed"
    assert (res.get("stage2") or {}).get("selected", []) == []
    assert (res.get("clusters") or []) == []
    assert len(state["chat_calls"]) == 0


def test_tier2_f15_02_loop3_only_noise_findings_skips_stage2_and_stage3(tmp_path: Path) -> None:
    repo = _init_git_repo(
        tmp_path / "repo",
        {"tests/test_secret.py": 'KEY = "ghp_' + ("A1B2" * 9) + '"\n'},
    )
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _ollama_loopback_server({"models": ["qwen2.5:7b"]}) as (endpoint, state):
        with _scoped_env(OLLAMA_HOST=endpoint):
            orch = EnsembleOrchestrator(program="common_codes", embedded=False)
            res = orch.run_fast_parallel_ooda(
                repo,
                program="common_codes",
                blackboard_db=tmp_path / "bb.sqlite3",
                max_cpu_workers=2,
                eligibility_db=elig,
            )
    assert res.get("status") == "completed"
    assert (res.get("stage2") or {}).get("selected", []) == []
    assert len(state["chat_calls"]) == 0


def test_tier2_f15_03_loop3_stage3_oom_500_mid_funnel_downshifts_cleanly(tmp_path: Path) -> None:
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef f(x): return pickle.loads(x)\n"},
    )
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _ollama_loopback_server(
        {
            "models": ["gemma-4-12b-abliterated", "qwen2.5:7b"],
            "oom_models": ["gemma-4-12b-abliterated"],
            "verdict_file": "src/loader.py",
        }
    ) as (endpoint, state):
        with _scoped_env(OLLAMA_HOST=endpoint, RFCHUNT_OFFLINE=None):
            orch = EnsembleOrchestrator(
                program="common_codes", embedded=False, model="gemma-4-12b-abliterated"
            )
            res = orch.run_fast_parallel_ooda(
                repo,
                program="common_codes",
                blackboard_db=tmp_path / "bb.sqlite3",
                max_cpu_workers=2,
                eligibility_db=elig,
            )
    assert res.get("status") == "completed"
    called = [c["model"] for c in state["chat_calls"]]
    assert called.count("gemma-4-12b-abliterated") == 1
    assert "qwen2.5:7b" in called


def test_tier2_f15_04_loop3_stage3_circuit_open_preserves_deterministic_findings(
    tmp_path: Path,
) -> None:
    repo = _init_git_repo(
        tmp_path / "repo",
        {
            "src/loader1.py": "import pickle\ndef f1(x): return pickle.loads(x)\n",
            "src/loader2.py": "import pickle\ndef f2(x): return pickle.loads(x)\n",
        },
    )
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _ollama_loopback_server({"models": ["qwen2.5:7b"], "always_oom": True}) as (
        endpoint,
        _state,
    ):
        with _scoped_env(OLLAMA_HOST=endpoint, RFCHUNT_OFFLINE=None):
            orch = EnsembleOrchestrator(program="common_codes", embedded=False, model="qwen2.5:7b")
            res = orch.run_fast_parallel_ooda(
                repo,
                program="common_codes",
                blackboard_db=tmp_path / "bb.sqlite3",
                max_cpu_workers=2,
                eligibility_db=elig,
            )
    assert res.get("status") == "completed"
    assert len(res.get("facts") or res.get("clusters") or res.get("stage1", {}).get("findings", [])) >= 1


def test_tier2_f15_05_loop3_signal_under_1_with_resume_true_finishes_cleanly(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard

    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef f(x): return pickle.loads(x)\n"},
    )
    bb_path = tmp_path / "resumed_ooda.sqlite3"
    bb = SqliteBlackboard(bb_path)
    try:
        bb.enqueue_intent(intent_type="stage1", payload={"repo_path": str(repo)}, lane=1)
        assert bb.claim_intent("crashed") is not None
    finally:
        _close_if_supported(bb)

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    orch = EnsembleOrchestrator(program="henkel_vdp", embedded=True)
    res = orch.run_fast_parallel_ooda(
        repo,
        program="henkel_vdp",
        blackboard_db=bb_path,
        max_cpu_workers=2,
        resume=True,
        signal_score=0.4,
        eligibility_db=elig,
    )
    assert res.get("status") == "completed"
    assert int((res.get("recovery") or {}).get("recovered_to_pending", 0)) >= 1


# --- F16 Boundary Cases (5 cases) ---


def test_tier2_f16_01_loop4_blocked_signal_program_fails_closed(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    out_dir = tmp_path / "blocked_shopify"
    res = evaluate_and_stage_submission(
        program="shopify",
        asset="src/app.ts",
        title="CSP issue on blocked program",
        summary="Valid description exceeding 100 characters for verification against ProgramEligibilityDB gate.",
        impact="Impact description.",
        weakness_cwe="CWE-639",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="HTTP 200 verified",
        eligibility_db=elig,
        output_dir=out_dir,
        trigger_browser=True,
    )
    assert res.get("eligible") is False
    assert not (out_dir / "READY_TO_SUBMIT.json").is_file()


def test_tier2_f16_02_loop4_anthropic_srt_sandbox_held_out_of_threat_model(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    out_dir = tmp_path / "blocked_tm"
    res = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/sandbox.rs",
        title="Cross-session OpenProcess inside srt-sandbox",
        summary=(
            "Two processes inside srt-sandbox cross-session can inspect each other inside shared sandbox "
            "environment without crossing external boundary."
        ),
        impact="Local intra-sandbox inspection.",
        weakness_cwe="CWE-200",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="verified inside srt-sandbox",
        eligibility_db=elig,
        output_dir=out_dir,
        trigger_browser=True,
    )
    assert res.get("eligible") is False
    assert not (out_dir / "READY_TO_SUBMIT.json").is_file()


def test_tier2_f16_03_loop4_macos_os_mismatch_fails_closed(tmp_path: Path) -> None:
    verdict = evaluate_vendor_threat_model(
        title="macOS APFS case-sensitivity Seatbelt bypass",
        summary="Static check on sandbox-exec SBPL.",
        file_path="src/seatbelt.rs",
        program="anthropic",
        poc_verified=True,
        poc_target_os="linux",
    )
    assert verdict.passed is False
    assert "OS_RUNTIME_MISMATCH" in verdict.matched_rules


def test_tier2_f16_04_loop4_poc_verified_false_fails_closed(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    out_dir = tmp_path / "no_poc"
    res = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/auth.py",
        title="Unverified SSRF lead",
        summary="Detailed description exceeding 100 characters but missing live non-destructive PoC verification.",
        impact="Potential SSRF.",
        weakness_cwe="CWE-918",
        severity="HIGH",
        poc_verified=False,
        poc_transcript="",
        eligibility_db=elig,
        output_dir=out_dir,
        trigger_browser=True,
    )
    assert res.get("eligible") is False
    assert not (out_dir / "READY_TO_SUBMIT.json").is_file()


def test_tier2_f16_05_stage_draft_rejects_long_title_and_short_description(tmp_path: Path) -> None:
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _scoped_env(RFCHUNT_ELIGIBILITY_DB=str(elig.db_path)):
        r_title = _call_validate_and_stage_draft(
            elig=elig,
            program_handle="anthropic",
            asset="src/a.py",
            weakness_cwe="CWE-918",
            severity_rating="High",
            title="T" * 155,
            vulnerability_information="D" * 120,
            impact="High",
            poc_verified=True,
            out_path=str(tmp_path / "t1.json"),
        )
        assert r_title["status"] == "blocked_quality_gate"

        r_body = _call_validate_and_stage_draft(
            elig=elig,
            program_handle="anthropic",
            asset="src/a.py",
            weakness_cwe="CWE-918",
            severity_rating="High",
            title="Short valid title",
            vulnerability_information="Too short",
            impact="High",
            poc_verified=True,
            out_path=str(tmp_path / "t2.json"),
        )
        assert r_body["status"] == "blocked_quality_gate"


# --- F17 Boundary Cases (5 cases) ---


def test_tier2_f17_01_cli_fast_ooda_missing_target_exits_2() -> None:
    with pytest.raises(SystemExit) as exc:
        revenue_cli.run_revenue_cli(["fast-ooda"])
    assert exc.value.code == 2


def test_tier2_f17_02_mcp_unknown_tool_returns_is_error_true() -> None:
    srv = BugBountyMCPServer()
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "bb_nonexistent", "arguments": {}},
        }
    )
    assert resp["result"]["isError"] is True


def test_tier2_f17_03_mcp_unknown_jsonrpc_method_returns_32601() -> None:
    srv = BugBountyMCPServer()
    resp = srv.handle_request({"jsonrpc": "2.0", "id": 9, "method": "bad/method"})
    assert resp["error"]["code"] == -32601


def test_tier2_f17_04_mcp_bb_stage_hackerone_draft_blocks_ineligible_shopify(tmp_path: Path) -> None:
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    srv = BugBountyMCPServer()
    args: Dict[str, Any] = {
        "program_handle": "shopify",
        "asset": "@shopify/shopify-app-remix",
        "weakness_cwe": "CWE-639",
        "severity_rating": "High",
        "title": "Blocked program draft should fail closed",
        "vulnerability_information": "Detailed description exceeding 100 characters for testing fail-closed ProgramEligibilityDB gate.",
        "impact": "Blocked by signal gate.",
        "poc_verified": True,
        "out_path": str(tmp_path / "blocked_draft.json"),
        "eligibility_db_path": str(elig.db_path),
    }
    with _scoped_env(RFCHUNT_ELIGIBILITY_DB=str(elig.db_path)):
        resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "bb_stage_hackerone_draft", "arguments": args},
            }
        )
    payload = json.loads(resp["result"]["content"][0]["text"])
    if resp["result"]["isError"]:
        err_txt = str(payload.get("error") or payload).lower()
        assert any(k in err_txt for k in ("eligib", "unlock", "blocked", "signal"))
    else:
        assert str(payload.get("status", "")).startswith("blocked")
        assert any(k in json.dumps(payload).lower() for k in ("eligib", "unlock", "blocked", "signal"))


def test_tier2_f17_05_mcp_bb_run_fast_ooda_missing_target_returns_is_error() -> None:
    srv = BugBountyMCPServer()
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "bb_run_fast_ooda", "arguments": {}},
        }
    )
    assert resp["result"]["isError"] is True


# --- F18 Boundary Cases (5 cases) ---


def test_tier2_f18_01_ide_bootstrap_recovers_corrupt_local_models_json(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    cfg_dir = fake_home / ".gemini" / "config"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "local_models.json").write_text("{bad json", encoding="utf-8")
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0
    parsed = json.loads((cfg_dir / "local_models.json").read_text(encoding="utf-8"))
    assert "ollama" in parsed


def test_tier2_f18_02_ide_bootstrap_normalizes_list_mcp_config_json(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    cfg_dir = fake_home / ".gemini" / "config"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "mcp_config.json").write_text("[]", encoding="utf-8")
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0
    parsed = json.loads((cfg_dir / "mcp_config.json").read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    assert "rfchunt-bugbounty" in parsed.get("mcpServers", {})


def test_tier2_f18_03_ide_bootstrap_install_go_tools_when_go_absent_graceful(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    empty_bin = tmp_path / "empty_bin"
    empty_bin.mkdir()
    before_path = os.environ.get("PATH", "")
    proc = _run_bootstrap_isolated(
        fake_home,
        "--install-go-tools",
        extra_env={"PATH": str(empty_bin)},
    )
    assert proc.returncode == 0
    assert os.environ.get("PATH", "") == before_path


def test_tier2_f18_04_ide_bootstrap_creates_missing_parent_dirs(tmp_path: Path) -> None:
    fake_home = tmp_path / "nested" / "deep" / "home"
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0
    assert (fake_home / ".gemini" / "config" / "mcp_config.json").is_file()


def test_tier2_f18_05_ide_bootstrap_idempotent_double_run(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    p1 = _run_bootstrap_isolated(fake_home)
    assert p1.returncode == 0
    first_mcp = (fake_home / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8")
    p2 = _run_bootstrap_isolated(fake_home)
    assert p2.returncode == 0
    second_mcp = (fake_home / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8")
    assert json.loads(first_mcp) == json.loads(second_mcp)


# --- R5 Boundary Cases (5 cases) ---


def test_tier2_r5_01_execution_policy_rejects_drive_relative_ads_and_nul_paths() -> None:
    for bad in ("C:foo", "file.txt:stream", "foo\x00bar"):
        assert _validate_canonical_path_syntax(bad) is not None


def test_tier2_r5_02_safe_network_validator_blocks_mapped_ipv6_cgnat_metadata() -> None:
    ok_mapped, _ = validate_target_host("::ffff:127.0.0.1", allow_private=True)
    ok_meta, _ = validate_target_host("169.254.169.254", allow_private=True)
    ok_cgnat, _ = validate_target_host("100.64.0.1", allow_private=False)
    assert ok_mapped is False
    assert ok_meta is False
    assert ok_cgnat is False


def test_tier2_r5_03_program_eligibility_db_rejects_invalid_handle_and_status(
    tmp_path: Path,
) -> None:
    db = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    with pytest.raises(ValueError):
        db.upsert("", "UNLOCKED")
    with pytest.raises(ValueError):
        db.upsert("valid_handle", "INVALID_STATUS")


def test_tier2_r5_04_csv_formula_injection_neutralized(tmp_path: Path) -> None:
    payload = "=cmd|'/C calc'!A0"
    assert neutralize_csv_cell(payload).startswith("'")
    bundle = ClientAuditPackager().package(
        client_name="TestClient",
        scope_description="CSV injection test",
        findings=[
            {
                "finding_id": "F-1",
                "title": payload,
                "severity": "HIGH",
                "cwe": "CWE-1236",
                "affected_location": "src/export.py",
                "summary": "Formula test",
                "impact": "CSV injection",
            }
        ],
        out_dir=tmp_path / "pkg",
    )
    csv_text = bundle.findings_tracker_csv.read_text(encoding="utf-8")
    assert "'=cmd" in csv_text


def test_tier2_r5_05_protected_files_sha256_invariant_across_orchestrator_run(
    tmp_path: Path,
) -> None:
    swarm_path = ROOT / "rfc_hunt_swarm.py"
    mcp_path = ROOT / "mcp_server.py"
    before = {
        swarm_path: hashlib.sha256(swarm_path.read_bytes()).hexdigest(),
        mcp_path: hashlib.sha256(mcp_path.read_bytes()).hexdigest(),
    }
    repo = _init_git_repo(tmp_path / "repo", {"src/a.py": "x = 1\n"})
    EnsembleOrchestrator(program="generic", embedded=True).run(repo, out_dir=tmp_path / "out")
    for p, digest in before.items():
        assert hashlib.sha256(p.read_bytes()).hexdigest() == digest


# ===========================================================================
# TIER 3: PAIRWISE CROSS-FEATURE & CROSS-LOOP INTEGRATION (20 TEST CASES)
# ===========================================================================


def test_tier3_01_loop1_etag_pr_triggers_loop2_sibling_parity_intents(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import (
        SqliteBlackboard,
        detect_security_fix_signal,
        emit_sibling_parity_intents,
    )
    from engine.freshness_watcher import AsyncFreshnessPoller

    repo = _init_git_repo(
        tmp_path / "repo",
        {
            "packages/pkg-a/auth.ts": "export function sanitize(x: string) { return x.trim(); }\n",
            "packages/pkg-b/auth.ts": "export function sanitize(x: string) { return x; }\n",
        },
    )
    fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 900))
    routes: Dict[str, Any] = {
        "/repos/acme/monorepo/releases?per_page=5": {"status": 200, "etag": '"r1"', "body": []},
        "/repos/acme/monorepo/pulls?state=closed&sort=updated&direction=desc&per_page=10": {
            "status": 200,
            "etag": '"p1"',
            "body": [
                {
                    "number": 55,
                    "title": "fix: sanitize untrusted auth header",
                    "merged_at": fresh_ts,
                    "merge_commit_sha": "sha55",
                }
            ],
        },
        "/repos/acme/monorepo/pulls/55/files?per_page=30": {
            "status": 200,
            "etag": '"f55"',
            "body": [{"filename": "packages/pkg-a/auth.ts"}],
        },
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "t3_01.sqlite3")
    try:
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                summary = _invoke_poller_once(
                    poller,
                    [WatchTarget(program="anthropic", repo="acme/monorepo")],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
            finally:
                _close_if_supported(poller)
        assert len(summary.get("enqueued_intent_ids") or []) >= 1
        assert "sanitize" in [k.lower() for k in detect_security_fix_signal("fix: sanitize untrusted auth header")]
        emitted = emit_sibling_parity_intents(
            bb,
            repo_path=str(repo),
            changed_files=["packages/pkg-a/auth.ts"],
            trigger_reason="security_fix:sanitize",
        )
        assert len(emitted) >= 1
    finally:
        _close_if_supported(bb)


def test_tier3_02_loop2_fact_emits_6_sdk_intents_executed_in_spawn_pool(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import (
        SqliteBlackboard,
        emit_sibling_parity_intents,
        run_local_rfchunt_async,
    )

    repo = _init_git_repo(
        tmp_path / "polyglot",
        {
            "sdk/ts/client.ts": "export function verify() {}\n",
            "sdk/python/client.py": "def verify(): pass\n",
            "sdk/go/client.go": "package sdk\nfunc Verify() {}\n",
            "sdk/java/Client.java": "class Client { void verify() {} }\n",
            "sdk/ruby/client.rb": "def verify; end\n",
            "sdk/rust/client.rs": "pub fn verify() {}\n",
        },
    )
    db_path = tmp_path / "t3_02.sqlite3"
    bb = SqliteBlackboard(db_path)
    try:
        bb.add_fact(
            source_engine="parity_auditor",
            title="Verification gap in sdk/ts",
            file_path="sdk/ts/client.ts",
            severity="HIGH",
        )
        emitted = emit_sibling_parity_intents(
            bb,
            repo_path=str(repo),
            changed_files=["sdk/ts/client.ts"],
            trigger_reason="landed_fact:verify",
        )
        assert len(emitted) >= 5
        rows = bb._conn.execute("SELECT intent_id, payload_json FROM intents WHERE status = 'PENDING'").fetchall()
        for row_id, p_json in rows:
            p_obj = json.loads(p_json or "{}")
            p_obj["cpu_work_iters"] = 120000
            bb._conn.execute(
                "UPDATE intents SET payload_json = ? WHERE intent_id = ?",
                (json.dumps(p_obj), row_id),
            )
        bb._conn.commit()
    finally:
        _close_if_supported(bb)

    res = asyncio.run(
        run_local_rfchunt_async(
            None,
            repo_path=repo,
            db_path=db_path,
            max_cpu_workers=2,
            resume=True,
        )
    )
    assert len(set(res.get("worker_pids") or [])) >= 2


def test_tier3_03_m1_scanners_combined_with_noise_filter(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt
    from engine.mobile_app_auditor import audit_mobile_app
    from engine.parity_invariant_auditor import (
        audit_parity_and_invariants,
        filter_production_candidates,
    )
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    tok = "ghp_" + "Q1W2E3R4T5Y6U7I8O9P0A1S2D3F4G5H6J7K8"
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "packages" / "a").mkdir(parents=True)
    (tmp_path / "packages" / "b").mkdir(parents=True)

    (tmp_path / "src" / "key.py").write_text(f'TOKEN = "{tok}"\n', encoding="utf-8")
    (tmp_path / "src" / "jwt_auth.py").write_text(
        'import jwt\ndef f(t): return jwt.decode(t, options={"verify_signature": False})\n',
        encoding="utf-8",
    )
    (tmp_path / "src" / "ml.py").write_text("import pickle\npickle.loads(b'x')\n", encoding="utf-8")
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest package="com.x"><application><activity android:name=".A" android:exported="true"/></application></manifest>',
        encoding="utf-8",
    )
    (tmp_path / "packages" / "a" / "auth.ts").write_text(
        "export function handleInbound(x: any) { verifySignature(x); return sanitizeInput(x); }\n",
        encoding="utf-8",
    )
    (tmp_path / "packages" / "b" / "auth.ts").write_text(
        "export function handleInbound(x: any) { return x; }\n",
        encoding="utf-8",
    )
    (tmp_path / "tests" / "test_jwt.py").write_text(
        'import jwt\njwt.decode("x", options={"verify_signature": False})\n', encoding="utf-8"
    )

    all_findings = []
    all_findings.extend(scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True))
    all_findings.extend(audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True))
    all_findings.extend(audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True))
    all_findings.extend(audit_ai_infra(tmp_path))
    all_findings.extend(audit_parity_and_invariants(tmp_path))

    prod, noise = filter_production_candidates(all_findings)
    assert len(prod) >= 4
    assert all("tests/" not in str(_fget(f, "file_path", "")).replace("\\", "/") for f in prod)


def test_tier3_04_noise_filter_to_acdso_stage2_ranking(tmp_path: Path) -> None:
    from engine.acdso_bridge import rank_stage2_candidates
    from engine.parity_invariant_auditor import filter_production_candidates

    mixed = [
        EngineFinding(engine="trufflehog", title=f"Prod {i}", file_path=f"src/p{i}.py", severity="HIGH", deterministic=True)
        for i in range(12)
    ] + [
        EngineFinding(engine="trufflehog", title=f"Test {i}", file_path=f"tests/t{i}.py", severity="LOW")
        for i in range(8)
    ]
    prod, noise = filter_production_candidates(mixed)
    assert len(prod) == 12 and len(noise) == 8
    ranked = rank_stage2_candidates([p.to_dict() for p in prod], top_k=5)
    assert 3 <= len(ranked["selected"]) <= 5
    assert ranked["elapsed_ms"] < 1000.0


def test_tier3_05_acdso_top_candidates_routed_through_ollama_concurrency_guard(
    tmp_path: Path,
) -> None:
    from engine.acdso_bridge import rank_stage2_candidates
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("on: pull_request_target\njobs: {}\n", encoding="utf-8")
    cands = [
        {
            "engine": "zizmor",
            "title": f"GHA issue {i}",
            "file_path": ".github/workflows/ci.yml",
            "line": i + 1,
            "severity": "HIGH",
            "confidence": 0.6 + (i % 4) * 0.09,
            "deterministic": True,
        }
        for i in range(12)
    ]
    stage2 = rank_stage2_candidates(cands, top_k=4)
    selected_findings = [
        EngineFinding(
            engine=c["engine"],
            title=c["title"],
            file_path=c["file_path"],
            line=c["line"],
            severity=c["severity"],
            confidence=c["confidence"],
            deterministic=True,
        )
        for c in stage2["selected"]
    ]
    guard = OllamaConcurrencyGuard(lock_path=tmp_path / "t3_05.lock")
    with _ollama_loopback_server({"models": ["qwen2.5:7b"], "verdict_file": ".github/workflows/ci.yml"}) as (
        endpoint,
        state,
    ):
        _, tel = _call_verify_gha_with_optional_guard(
            tmp_path,
            selected_findings,
            guard=guard,
            model="qwen2.5:7b",
            ollama_endpoint=endpoint,
            env_local_path=tmp_path / "missing.env",
            force_ollama=True,
        )
        assert tel["status"] == "completed"
        assert state["max_inflight"] <= 1


def test_tier3_06_oom_downshift_mid_loop3_funnel(tmp_path: Path) -> None:
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef f(x): return pickle.loads(x)\n"},
    )
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _ollama_loopback_server(
        {
            "models": ["gemma-4-12b-abliterated", "qwen2.5:7b"],
            "oom_models": ["gemma-4-12b-abliterated"],
            "verdict_file": "src/loader.py",
        }
    ) as (endpoint, state):
        with _scoped_env(OLLAMA_HOST=endpoint, RFCHUNT_OFFLINE=None):
            orch = EnsembleOrchestrator(
                program="common_codes", embedded=False, model="gemma-4-12b-abliterated"
            )
            res = orch.run_fast_parallel_ooda(
                repo,
                program="common_codes",
                blackboard_db=tmp_path / "t3_06.sqlite3",
                max_cpu_workers=2,
                eligibility_db=elig,
            )
    assert res.get("status") == "completed"
    called = [c["model"] for c in state["chat_calls"]]
    assert len(called) >= 2
    assert called[0] == "gemma-4-12b-abliterated"
    assert "qwen2.5:7b" in called


def test_tier3_07_lean4_deterministic_immune_to_ollama_dissent(tmp_path: Path) -> None:
    findings = [
        EngineFinding(
            engine="lean4",
            title="Formal invariant failure",
            file_path="src/auth.rs",
            line=10,
            cwe="CWE-287",
            severity="CRITICAL",
            deterministic=True,
            confirmed=True,
        ),
        EngineFinding(
            engine="gha_llm",
            title="Formal invariant failure",
            file_path="src/auth.rs",
            line=10,
            cwe="CWE-287",
            severity="INFO",
            deterministic=False,
            confirmed=False,
        ),
    ]
    clusters = EnsembleConsensusVoter(program="anthropic", quorum=2).fuse(findings)
    assert clusters[0].lean_verified is True
    assert clusters[0].llm_dissent_ignored is True
    assert clusters[0].disposition == "ENSEMBLE_CORROBORATED_STATIC"


def test_tier3_08_loop3_to_sandbox_http_probe_to_loop4_ready_to_submit(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    runner = LinuxPocRunner()
    with _sandbox_target_server() as (base_url, records):
        probe_res = runner.verify_sandbox_http_probe(
            f"{base_url}/verify",
            program="common_codes",
            eligibility_db=elig,
            max_rps=2.0,
            researcher_handle="oyesanyf",
        )
        assert len(records) == 1
        assert records[0]["headers"]["x-hackerone"] == "oyesanyf"
        sub = evaluate_and_stage_submission(
            program="common_codes",
            asset="src/sdjwt.py",
            title="OID4VCI verifier accepts unpinned key",
            summary=(
                "Live sandbox probe confirmed endpoint accepts unpinned key resolution without cnf validation "
                "against isolated verification server."
            ),
            impact="Credential forgery risk.",
            weakness_cwe="CWE-347",
            severity="HIGH",
            poc_verified=bool(probe_res.get("verified", True)),
            poc_transcript=json.dumps(probe_res),
            eligibility_db=elig,
            output_dir=tmp_path / "out",
            trigger_browser=True,
        )
        assert (tmp_path / "out" / "READY_TO_SUBMIT.json").is_file()
        assert str(sub.get("report_url") or sub.get("submit_url") or "").startswith(
            "https://hackerone.com/reports/"
        )


def test_tier3_09_loop4_filters_blocked_and_threat_model_keeps_valid_anthropic(
    tmp_path: Path,
) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()

    res_blocked = evaluate_and_stage_submission(
        program="vercel",
        asset="examples/app/route.ts",
        title="Blocked vercel example finding",
        summary="Long enough summary exceeding 100 characters to pass length check while failing eligibility and threat model.",
        impact="Blocked.",
        weakness_cwe="CWE-79",
        severity="MEDIUM",
        poc_verified=True,
        poc_transcript="ok",
        eligibility_db=elig,
        output_dir=tmp_path / "out_bad",
        trigger_browser=True,
    )
    assert res_blocked.get("eligible") is False
    assert not (tmp_path / "out_bad" / "READY_TO_SUBMIT.json").is_file()

    res_ok = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/api/auth.py",
        title="External SSRF in API gateway",
        summary="Unauthenticated external attacker can trigger arbitrary outbound requests from production API gateway.",
        impact="Internal network exposure.",
        weakness_cwe="CWE-918",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="HTTP 200 SSRF verified",
        eligibility_db=elig,
        output_dir=tmp_path / "out_ok",
        trigger_browser=True,
    )
    assert res_ok.get("eligible") is True
    assert (tmp_path / "out_ok" / "READY_TO_SUBMIT.json").is_file()


def test_tier3_10_cli_fast_ooda_and_mcp_bb_run_fast_ooda_parity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef f(x): return pickle.loads(x)\n"},
    )
    cli_out = tmp_path / "cli_out"
    rc = revenue_cli.run_revenue_cli(
        [
            "fast-ooda",
            "--target",
            str(repo),
            "--program",
            "anthropic",
            "--cpu-workers",
            "2",
            "--blackboard-db",
            str(tmp_path / "cli_bb.sqlite3"),
            "--out",
            str(cli_out),
            "--embedded",
            "--json",
        ]
    )
    assert rc == 0
    cli_json = json.loads(capsys.readouterr().out)

    srv = BugBountyMCPServer()
    mcp_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 310,
            "method": "tools/call",
            "params": {
                "name": "bb_run_fast_ooda",
                "arguments": {
                    "target": str(repo),
                    "program": "anthropic",
                    "cpu_workers": 2,
                    "blackboard_db": str(tmp_path / "mcp_bb.sqlite3"),
                    "out_dir": str(tmp_path / "mcp_out"),
                    "embedded": True,
                },
            },
        }
    )
    assert mcp_resp["result"]["isError"] is False
    mcp_json = json.loads(mcp_resp["result"]["content"][0]["text"])
    assert cli_json.get("status") == "completed" and mcp_json.get("status") == "completed"
    assert (tmp_path / "cli_bb.sqlite3").is_file()
    assert (tmp_path / "mcp_bb.sqlite3").is_file()


def test_tier3_11_loop5_lane1_reservation_feeds_loop1_etag_poller(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, TwoLaneBountyQueue
    from engine.freshness_watcher import AsyncFreshnessPoller

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        q = TwoLaneBountyQueue(elig, bb)
        sched = _call_two_lane_queue_schedule(q, queue_capacity=10, signal_score=0.4, eligibility_db=elig)
        assert len(sched["lane1_programs_queued"]) >= 5

        fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
        routes: Dict[str, Any] = {
            "/repos/henkel/vdp-app/releases?per_page=5": {
                "status": 200,
                "etag": '"h1"',
                "body": [
                    {
                        "tag_name": "v1.0",
                        "name": "v1.0 auth token fix",
                        "target_commitish": "hsha1",
                        "published_at": fresh_ts,
                        "body": "Verify auth session token",
                    }
                ],
            },
            "/repos/henkel/vdp-app/pulls?state=closed&sort=updated&direction=desc&per_page=10": {"status": 200, "body": []},
        }
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3"
            )
            try:
                summary = _invoke_poller_once(
                    poller,
                    [WatchTarget(program="henkel_vdp", repo="henkel/vdp-app")],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
            finally:
                _close_if_supported(poller)
        assert len(summary.get("enqueued_intent_ids") or []) >= 1
    finally:
        _close_if_supported(bb)


def test_tier3_12_eligibility_flip_to_auto_stage_to_mcp_hackerone_url(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, sync_eligibility_and_stage_unlocks

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    elig.upsert("shopify", "UNLOCKED", bounty_max_usd=50000)

    drafts_dir = tmp_path / "drafts"
    drafts_dir.mkdir()
    draft_payload = {
        "program_handle": "shopify",
        "asset": "@shopify/shopify-app-remix",
        "weakness_cwe": "CWE-639",
        "severity_rating": "High",
        "title": "CSP frame-ancestors omission in @shopify/shopify-app-remix",
        "vulnerability_information": (
            "The @shopify/shopify-app-remix embedded handler omits CSP frame-ancestors on fallback error responses, "
            "allowing merchant admin clickjacking verified with non-destructive test harness."
        ),
        "impact": "Merchant session framing.",
        "poc_verified": True,
    }
    (drafts_dir / "shopify_remix.json").write_text(json.dumps(draft_payload), encoding="utf-8")

    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        sync_res = sync_eligibility_and_stage_unlocks(elig, bb, drafts_dir)
        assert len(sync_res.get("staged_drafts") or []) >= 1
    finally:
        _close_if_supported(bb)

    srv = BugBountyMCPServer()
    with _scoped_env(RFCHUNT_ELIGIBILITY_DB=str(elig.db_path)):
        resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 312,
                "method": "tools/call",
                "params": {
                    "name": "bb_stage_hackerone_draft",
                    "arguments": {
                        **draft_payload,
                        "out_path": str(tmp_path / "mcp_staged.json"),
                        "eligibility_db_path": str(elig.db_path),
                    },
                },
            }
        )
    assert resp["result"]["isError"] is False
    staged = json.loads(resp["result"]["content"][0]["text"])
    assert staged["status"] == "staged_ready"
    url = str(staged.get("report_url") or staged.get("submit_url") or "")
    assert url.startswith("https://hackerone.com/reports/")


def test_tier3_13_trufflehog_finding_redacted_through_submission_draft(tmp_path: Path) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission
    from engine.trufflehog_scanner import scan_secrets_with_trufflehog

    raw_tok = "ghp_" + "Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2"
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "cfg.py").write_text(f'TOKEN = "{raw_tok}"\n', encoding="utf-8")
    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True, no_external_scanners=True)
    assert len(findings) >= 1
    assert not _any_text_contains(findings, raw_tok)

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    out_dir = tmp_path / "draft_out"
    evaluate_and_stage_submission(
        program="anthropic",
        asset="src/cfg.py",
        title="Exposed GitHub token in production module",
        summary=(
            f"Scanner detected leaked credential {raw_tok} in production configuration file "
            "requiring immediate revocation and secret rotation."
        ),
        impact="Unauthorized repository access.",
        weakness_cwe="CWE-798",
        severity="HIGH",
        poc_verified=True,
        poc_transcript=f"Token preview: {raw_tok}",
        eligibility_db=elig,
        output_dir=out_dir,
        trigger_browser=True,
    )
    raw_json = (out_dir / "READY_TO_SUBMIT.json").read_text(encoding="utf-8")
    assert raw_tok not in raw_json


def test_tier3_14_probe_optional_backends_paired_with_api_jwt_audit(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

    backends = probe_optional_backends(lean_dir=tmp_path, timeout_sec=1.0)
    assert {"subfinder", "httpx", "katana", "schemathesis"}.issubset(backends.keys())

    (tmp_path / "auth.py").write_text(
        'import jwt\njwt.decode("x", options={"verify_signature": False})\n', encoding="utf-8"
    )
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    findings = audit_api_and_jwt(
        tmp_path, program="common_codes", embedded=True, no_external_scanners=True, eligibility_db=elig
    )
    assert len(findings) >= 1


def test_tier3_15_blackboard_crash_recovery_resumes_in_spawn_pool(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, run_local_rfchunt_async

    repo = _init_git_repo(
        tmp_path / "repo",
        {f"src/f{i}.py": f"import pickle\npickle.loads(b'{i}')\n" for i in range(4)},
    )
    db_path = tmp_path / "crash_spawn.sqlite3"
    bb = SqliteBlackboard(db_path)
    try:
        bb.add_fact(source_engine="lean4", title="Pre-crash fact", file_path="src/f0.py", severity="CRITICAL")
        for i in range(4):
            bb.enqueue_intent(
                intent_type="stage1",
                payload={"repo_path": str(repo), "idx": i, "cpu_work_iters": 120000},
                lane=2,
            )
        assert bb.claim_intent("dead-worker-1") is not None
        assert bb.claim_intent("dead-worker-2") is not None
    finally:
        _close_if_supported(bb)

    res = asyncio.run(
        run_local_rfchunt_async(
            None,
            repo_path=repo,
            db_path=db_path,
            max_cpu_workers=2,
            resume=True,
        )
    )
    assert int((res.get("recovery") or {}).get("recovered_to_pending", 0)) >= 2
    assert len(set(res.get("worker_pids") or [])) >= 2
    bb_check = SqliteBlackboard(db_path)
    try:
        assert len(bb_check.list_facts()) >= 1
    finally:
        _close_if_supported(bb_check)


def test_tier3_16_bootstrap_seeded_db_read_by_two_lane_queue(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, TwoLaneBountyQueue

    elig = ProgramEligibilityDB(tmp_path / "seeded.sqlite3")
    elig.seed_observed_hackerone_baseline()
    assert elig.is_eligible("henkel_vdp") is True
    assert elig.is_eligible("servicenow-disclosure") is True
    assert elig.is_eligible("common_codes") is True
    assert elig.is_eligible("shopify") is False

    bb = SqliteBlackboard(tmp_path / "bb.sqlite3")
    try:
        q = TwoLaneBountyQueue(elig, bb)
        sched = _call_two_lane_queue_schedule(q, queue_capacity=8, signal_score=0.2, eligibility_db=elig)
        assert len(sched["lane1_programs_queued"]) >= 4
    finally:
        _close_if_supported(bb)


def test_tier3_17_bootstrap_mcp_config_matches_live_bugbounty_mcp_server(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0
    mc = json.loads((fake_home / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8"))
    assert "rfchunt-bugbounty" in mc["mcpServers"]

    srv = BugBountyMCPServer()
    tools_resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
    assert {"bb_run_fast_ooda", "bb_stage_hackerone_draft"}.issubset(tool_names)


def test_tier3_18_mobile_oid4vci_fuses_with_api_jwt_via_engine_weights(tmp_path: Path) -> None:
    from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt
    from engine.mobile_app_auditor import audit_mobile_app

    (tmp_path / "wallet.kt").write_text(
        'fun handle(u: String) { if (u.startsWith("openid4vci://")) openUrl(u) }\n',
        encoding="utf-8",
    )
    (tmp_path / "wallet_jwt.py").write_text(
        'import jwt\ndef verify(t): return jwt.decode(t, options={"verify_signature": False})\n',
        encoding="utf-8",
    )
    m_findings = [
        EngineFinding(**f) if isinstance(f, dict) else f
        for f in audit_mobile_app(tmp_path, embedded=True, no_external_scanners=True)
    ]
    a_findings = [
        EngineFinding(**f) if isinstance(f, dict) else f
        for f in audit_api_and_jwt(tmp_path, embedded=True, no_external_scanners=True)
    ]
    assert m_findings and a_findings
    clusters = EnsembleConsensusVoter(program="common_codes", quorum=1).fuse(m_findings + a_findings)
    assert len(clusters) >= 1
    assert "mobile_mobsf" in ENGINE_WEIGHTS and "api_jwt_sdjwt" in ENGINE_WEIGHTS


def test_tier3_19_ai_infra_guard_paired_with_vendor_threat_model(tmp_path: Path) -> None:
    from engine.ai_infra_guard_auditor import audit_ai_infra

    (tmp_path / "src").mkdir()
    (tmp_path / "examples").mkdir()
    (tmp_path / "src" / "serve.py").write_text(
        "import pickle\ndef load_model(b): return pickle.loads(b)\n", encoding="utf-8"
    )
    (tmp_path / "examples" / "demo.py").write_text(
        "import pickle\ndef demo(b): return pickle.loads(b)\n", encoding="utf-8"
    )
    findings = audit_ai_infra(tmp_path)
    assert len(findings) >= 1
    v_anth = evaluate_vendor_threat_model(
        title="Unsafe pickle deserialization in model loader",
        summary="External user payload passed to pickle.loads in production handler.",
        file_path="src/serve.py",
        program="anthropic",
        poc_verified=True,
    )
    v_vercel_ex = evaluate_vendor_threat_model(
        title="Unsafe pickle deserialization in demo",
        summary="Example app only.",
        file_path="examples/demo.py",
        program="vercel",
        poc_verified=True,
    )
    assert v_anth.passed is True
    assert v_vercel_ex.passed is False


def test_tier3_20_full_5_loop_chain_end_to_end(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import (
        SqliteBlackboard,
        TwoLaneBountyQueue,
        emit_sibling_parity_intents,
    )
    from engine.ensemble_orchestrator import evaluate_and_stage_submission
    from engine.freshness_watcher import AsyncFreshnessPoller

    repo = _init_git_repo(
        tmp_path / "repo",
        {
            "packages/a/auth.ts": "export function handleInbound(x: any) { verifySignature(x); return sanitizeInput(x); }\n",
            "packages/b/auth.ts": "export function handleInbound(x: any) { return x; }\n",
            "src/loader.py": "import pickle\ndef f(x): return pickle.loads(x)\n",
        },
        commit_msg="fix: sanitize and verify inbound requests",
    )
    fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
    routes: Dict[str, Any] = {
        "/repos/acme/chain/releases?per_page=5": {"status": 200, "etag": '"r1"', "body": []},
        "/repos/acme/chain/pulls?state=closed&sort=updated&direction=desc&per_page=10": {
            "status": 200,
            "etag": '"p1"',
            "body": [{"number": 1, "title": "fix: sanitize auth", "merged_at": fresh_ts, "merge_commit_sha": "shachain1"}],
        },
        "/repos/acme/chain/pulls/1/files?per_page=30": {
            "status": 200,
            "etag": '"f1"',
            "body": [{"filename": "packages/a/auth.ts"}],
        },
    }
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb_path = tmp_path / "chain_bb.sqlite3"
    bb = SqliteBlackboard(bb_path)
    try:
        # Loop 5 lane accounting
        sched = _call_two_lane_queue_schedule(TwoLaneBountyQueue(elig, bb), queue_capacity=10, signal_score=0.5, eligibility_db=elig)
        assert len(sched["lane1_programs_queued"]) >= 5
        # Loop 1 ETag poll
        with _github_etag_server(routes) as (api_base, _state):
            poller = _build_poller(AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "fresh.sqlite3")
            try:
                _invoke_poller_once(
                    poller,
                    [WatchTarget(program="anthropic", repo="acme/chain")],
                    eligibility_db=elig,
                    blackboard=bb,
                    api_base=api_base,
                    http_get=_make_real_http_get(api_base),
                )
            finally:
                _close_if_supported(poller)
        # Loop 2 parity propagation
        emit_sibling_parity_intents(
            bb,
            repo_path=str(repo),
            changed_files=["packages/a/auth.ts"],
            trigger_reason="security_fix:sanitize",
        )
        bb.add_hint("packages/b/auth.ts", domain="loop_chain", priority=0.9)
    finally:
        _close_if_supported(bb)

    # Loop 3 fast OODA funnel
    orch = EnsembleOrchestrator(program="anthropic", embedded=True)
    ooda_res = orch.run_fast_parallel_ooda(
        repo,
        program="anthropic",
        blackboard_db=bb_path,
        max_cpu_workers=2,
        eligibility_db=elig,
    )
    assert ooda_res.get("status") == "completed"

    # Loop 4 fail-closed submission gate
    sub = evaluate_and_stage_submission(
        program="anthropic",
        asset="packages/b/auth.ts",
        title="Missing sanitizeInput parity guard in packages/b/auth.ts",
        summary="Sibling package packages/b/auth.ts omits sanitizeInput enforced by packages/a/auth.ts, verified cleanly.",
        impact="Unsanitized input reaches sink.",
        weakness_cwe="CWE-20",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="Verified asymmetry PoC output",
        eligibility_db=elig,
        output_dir=tmp_path / "chain_submit",
        trigger_browser=True,
    )
    assert (tmp_path / "chain_submit" / "READY_TO_SUBMIT.json").is_file()
    assert str(sub.get("report_url") or sub.get("submit_url") or "").startswith("https://hackerone.com/reports/")


# ===========================================================================
# TIER 4: REAL-WORLD END-TO-END APPLICATION SCENARIOS (6 TEST CASES)
# ===========================================================================


def test_tier4_s1_polyglot_3stage_triage_funnel_cli_and_orchestrator(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tok = "ghp_" + "M1N2B3V4C5X6Z7L8K9J0H1G2F3D4S5A6Q7W8"
    files: Dict[str, str] = {
        "src/key.py": f'API_TOKEN = "{tok}"\n',
        "src/jwt.py": 'import jwt\ndef parse(t): return jwt.decode(t, options={"verify_signature": False})\n',
        "src/ml.py": "import pickle\ndef load(d): return pickle.loads(d)\n",
        "packages/a/auth.ts": "export function handleInbound(r: any) { verifySignature(r); return sanitizeInput(r); }\n",
        "packages/b/auth.ts": "export function handleInbound(r: any) { return r; }\n",
        "AndroidManifest.xml": '<manifest package="com.eudi.app"><application><activity android:name=".Web" android:exported="true"/></application></manifest>\n',
        "deploy.yaml": 'services:\n  ollama:\n    image: ollama/ollama:0.5.0\n    ports:\n      - "0.0.0.0:11434:11434"\n',
        "README.md": "# Demo\n",
        "examples/demo.js": "const jwt = require('jsonwebtoken'); jwt.verify(t, k, {algorithms: ['RS256', 'HS256']});\n",
    }
    for i in range(6):
        files[f"tests/test_noise_{i}.py"] = f'import pickle\npickle.loads(b"{i}")\n'

    repo = _init_git_repo(tmp_path / "polyglot_repo", files, age_hours=2)
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    bb_path = tmp_path / "s1_bb.sqlite3"
    out_dir = tmp_path / "s1_out"

    with _ollama_loopback_server({"models": ["qwen2.5:7b"], "verdict_file": "src/ml.py", "chat_delay_sec": 0.02}) as (
        endpoint,
        state,
    ):
        with _scoped_env(OLLAMA_HOST=endpoint, RFCHUNT_OFFLINE=None):
            orch = EnsembleOrchestrator(program="common_codes", embedded=False, model="qwen2.5:7b")
            res = orch.run_fast_parallel_ooda(
                repo,
                program="common_codes",
                blackboard_db=bb_path,
                max_cpu_workers=2,
                eligibility_db=elig,
            )
    assert len(set(res.get("worker_pids") or [])) >= 2
    s2 = res.get("stage2") or {}
    assert 3 <= len(s2.get("selected") or []) <= 5
    assert float(s2.get("elapsed_ms", 0.0)) < 1000.0
    assert 1 <= len(state["chat_calls"]) <= 5
    assert state["max_inflight"] <= 1

    rc = revenue_cli.run_revenue_cli(
        [
            "fast-ooda",
            "--target",
            str(repo),
            "--program",
            "common_codes",
            "--cpu-workers",
            "2",
            "--blackboard-db",
            str(tmp_path / "s1_cli_bb.sqlite3"),
            "--out",
            str(out_dir),
            "--embedded",
            "--json",
        ]
    )
    assert rc == 0
    cli_payload = json.loads(capsys.readouterr().out)
    assert cli_payload.get("status") == "completed"
    assert (tmp_path / "s1_cli_bb.sqlite3").is_file()


def test_tier4_s2_shopify_app_remix_unlock_flip_to_draft_staging_and_url(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, sync_eligibility_and_stage_unlocks
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    assert elig.is_eligible("shopify") is False

    drafts_dir = tmp_path / "drafts"
    drafts_dir.mkdir()
    remix_draft = {
        "program_handle": "shopify",
        "asset": "@shopify/shopify-app-remix",
        "weakness_cwe": "CWE-639",
        "severity_rating": "High",
        "title": "Missing CSP frame-ancestors header in @shopify/shopify-app-remix",
        "vulnerability_information": (
            "Fallback response handler in @shopify/shopify-app-remix omits Content-Security-Policy frame-ancestors, "
            "breaking parity with primary handler and permitting iframe clickjacking verified locally."
        ),
        "impact": "Merchant admin session framing.",
        "poc_verified": True,
    }
    (drafts_dir / "shopify_app_remix.json").write_text(json.dumps(remix_draft), encoding="utf-8")

    bb = SqliteBlackboard(tmp_path / "s2_bb.sqlite3")
    try:
        before_res = sync_eligibility_and_stage_unlocks(elig, bb, drafts_dir)
        assert "shopify" not in (before_res.get("newly_unlocked") or [])
        assert "shopify" not in (before_res.get("unlocked_programs") or [])
        assert not [d for d in (before_res.get("staged_drafts") or []) if d.get("status") == "staged_ready"]

        elig.upsert("shopify", "UNLOCKED", bounty_max_usd=50000)
        assert elig.is_eligible("shopify") is True

        after_res = sync_eligibility_and_stage_unlocks(elig, bb, drafts_dir)
        assert "shopify" in (after_res.get("newly_unlocked") or [])
        assert len(after_res.get("queued_intents") or []) >= 1
        assert any(d.get("status") == "staged_ready" for d in (after_res.get("staged_drafts") or []))
    finally:
        _close_if_supported(bb)

    out_dir = tmp_path / "s2_submit"
    gate_res = evaluate_and_stage_submission(
        program="shopify",
        asset=remix_draft["asset"],
        title=remix_draft["title"],
        summary=remix_draft["vulnerability_information"],
        impact=remix_draft["impact"],
        weakness_cwe=remix_draft["weakness_cwe"],
        severity="HIGH",
        poc_verified=True,
        poc_transcript="Verified CSP frame-ancestors missing in @shopify/shopify-app-remix",
        eligibility_db=elig,
        output_dir=out_dir,
        trigger_browser=True,
    )
    assert (out_dir / "READY_TO_SUBMIT.json").is_file()
    assert gate_res.get("browser_handoff_spec", {}).get("action") == "stage_draft"
    assert str(gate_res.get("report_url") or gate_res.get("submit_url") or "").startswith(
        "https://hackerone.com/reports/"
    )


def test_tier4_s3_henkel_servicenow_two_lane_etag_304_200_and_6sdk_fanout(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import (
        SIBLING_SDK_LANGUAGES,
        SqliteBlackboard,
        TwoLaneBountyQueue,
        detect_security_fix_signal,
        emit_sibling_parity_intents,
    )
    from engine.freshness_watcher import AsyncFreshnessPoller

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()

    repo = _init_git_repo(
        tmp_path / "sdk_repo",
        {
            "sdk/ts/client.ts": "export function openSafe() {}\n",
            "sdk/python/client.py": "def open_safe(): pass\n",
            "sdk/go/client.go": "package sdk\nfunc OpenSafe() {}\n",
            "sdk/java/Client.java": "class Client { void openSafe() {} }\n",
            "sdk/ruby/client.rb": "def open_safe; end\n",
            "sdk/rust/client.rs": "pub fn open_safe() {}\n",
        },
    )
    fresh_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
    commit_msg = "fix: enforce O_NOFOLLOW and sanitize SSRF in auth proxy"
    routes: Dict[str, Any] = {
        "/repos/acme/sdk/releases?per_page=5": {"status": 200, "etag": '"v1"', "body": []},
        "/repos/acme/sdk/pulls?state=closed&sort=updated&direction=desc&per_page=10": {
            "status": 200,
            "etag": '"pr-v1"',
            "body": [{"number": 88, "title": commit_msg, "merged_at": fresh_ts, "merge_commit_sha": "sdksha88"}],
        },
        "/repos/acme/sdk/pulls/88/files?per_page=30": {
            "status": 200,
            "etag": '"files-88"',
            "body": [{"filename": "sdk/ts/client.ts"}],
        },
    }
    bb = SqliteBlackboard(tmp_path / "s3_bb.sqlite3")
    try:
        sched = _call_two_lane_queue_schedule(
            TwoLaneBountyQueue(elig, bb), queue_capacity=10, signal_score=0.4, eligibility_db=elig
        )
        lane1_programs = {x.get("program", x) if isinstance(x, dict) else x for x in sched["lane1_programs_queued"]}
        lane2_programs = {x.get("program", x) if isinstance(x, dict) else x for x in sched["lane2_programs_queued"]}
        assert len(sched["lane1_programs_queued"]) >= 5
        assert lane1_programs.intersection({"henkel_vdp", "servicenow-disclosure", "common_codes"})
        assert lane2_programs.intersection({"anthropic", "common_codes", "oppo_bbp", "amazonvrp", "temu"})

        while bb.claim_intent("drain-init") is not None:
            pass

        with _github_etag_server(routes) as (api_base, state):
            poller = _build_poller(
                AsyncFreshnessPoller, api_base=api_base, state_db=tmp_path / "s3_fresh.sqlite3"
            )
            try:
                targets = [
                    WatchTarget(program="anthropic", repo="acme/sdk"),
                    WatchTarget(program="shopify", repo="shopify/private-app"),
                ]
                http_get = _make_real_http_get(api_base)
                s1 = _invoke_poller_once(poller, targets, eligibility_db=elig, blackboard=bb, api_base=api_base, http_get=http_get)
                assert len(s1.get("enqueued_intent_ids") or []) >= 1
                assert not any("shopify/private-app" in r["path"] for r in state["__requests__"])

                assert {"o_nofollow", "sanitize", "ssrf"}.issubset(
                    {k.lower() for k in detect_security_fix_signal(commit_msg)}
                )
                emitted = emit_sibling_parity_intents(
                    bb,
                    repo_path=str(repo),
                    changed_files=["sdk/ts/client.ts"],
                    trigger_reason="security_fix:o_nofollow,sanitize,ssrf",
                )
                assert len(emitted) >= 5
                assert len(SIBLING_SDK_LANGUAGES) >= 6

                while bb.claim_intent("drain") is not None:
                    pass
                s2 = _invoke_poller_once(poller, targets, eligibility_db=elig, blackboard=bb, api_base=api_base, http_get=http_get)
                assert int(s2.get("etag_cache_hits", 0)) >= 1
                assert len(s2.get("enqueued_intent_ids") or []) == 0
            finally:
                _close_if_supported(poller)
    finally:
        _close_if_supported(bb)


def test_tier4_s4_fail_closed_blocked_submissions_and_sandbox_header_enforcement(
    tmp_path: Path,
) -> None:
    from engine.ensemble_orchestrator import evaluate_and_stage_submission

    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    assert elig.is_eligible("vercel") is False
    assert elig.is_eligible("anthropic") is True

    # (A) vercel BLOCKED_SIGNAL with poc_verified=True -> blocked
    r_a = evaluate_and_stage_submission(
        program="vercel",
        asset="src/api/route.ts",
        title="SSRF on blocked vercel program",
        summary="Detailed reproducible SSRF exceeding 100 chars on program whose signal gate is still blocked.",
        impact="Internal fetch.",
        weakness_cwe="CWE-918",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="HTTP 200",
        eligibility_db=elig,
        output_dir=tmp_path / "out_a",
        trigger_browser=True,
    )
    assert r_a.get("eligible") is False
    assert not (tmp_path / "out_a" / "READY_TO_SUBMIT.json").is_file()

    # (B) anthropic srt-sandbox cross-session -> blocked by vendor threat model
    r_b = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/sandbox.rs",
        title="Cross-session inspection in srt-sandbox",
        summary="Two processes inside srt-sandbox cross-session share PID namespace without external boundary crossing.",
        impact="Intra-sandbox read.",
        weakness_cwe="CWE-200",
        severity="MEDIUM",
        poc_verified=True,
        poc_transcript="pid read inside srt-sandbox",
        eligibility_db=elig,
        output_dir=tmp_path / "out_b",
        trigger_browser=True,
    )
    assert r_b.get("eligible") is False
    assert not (tmp_path / "out_b" / "READY_TO_SUBMIT.json").is_file()

    # (C) anthropic valid prod finding with poc_verified=False -> blocked
    r_c = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/api/auth.py",
        title="Unverified SSRF in API gateway",
        summary="Static finding exceeding 100 chars without runtime PoC verification output attached.",
        impact="Potential SSRF.",
        weakness_cwe="CWE-918",
        severity="HIGH",
        poc_verified=False,
        poc_transcript="",
        eligibility_db=elig,
        output_dir=tmp_path / "out_c",
        trigger_browser=True,
    )
    assert r_c.get("eligible") is False
    assert not (tmp_path / "out_c" / "READY_TO_SUBMIT.json").is_file()

    # Sandbox HTTP probe checks: common_codes sends H1 headers <= 2 rps; vercel sends 0 requests
    runner = LinuxPocRunner()
    with _sandbox_target_server() as (base_url, records):
        runner.verify_sandbox_http_probe(
            f"{base_url}/probe1",
            program="common_codes",
            eligibility_db=elig,
            max_rps=2.0,
            researcher_handle="oyesanyf",
        )
        runner.verify_sandbox_http_probe(
            f"{base_url}/probe2",
            program="common_codes",
            eligibility_db=elig,
            max_rps=2.0,
            researcher_handle="oyesanyf",
        )
        assert len(records) == 2
        assert records[1]["ts"] - records[0]["ts"] >= 0.40
        for rec in records:
            assert rec["headers"].get("user-agent") == "HackerOne/oyesanyf"
            assert rec["headers"].get("x-hackerone") == "oyesanyf"

        count_before_vercel = len(records)
        v_res = runner.verify_sandbox_http_probe(
            f"{base_url}/blocked",
            program="vercel",
            eligibility_db=elig,
            max_rps=2.0,
            researcher_handle="oyesanyf",
        )
        assert v_res.get("verified") is False
        assert v_res.get("status") == "blocked_ineligible"
        assert len(records) == count_before_vercel


def test_tier4_s5_windows_spawn_crash_recovery_and_oom_500_circuit_breaker(tmp_path: Path) -> None:
    from engine.async_blackboard_runtime import SqliteBlackboard, run_local_rfchunt_async
    from engine.gha_llm_verifier import verify_gha_findings_with_llm
    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    repo = _init_git_repo(
        tmp_path / "repo",
        {
            ".github/workflows/ci.yml": "on: pull_request_target\njobs: {}\n",
            **{f"src/m{i}.py": f"import pickle\npickle.loads(b'{i}')\n" for i in range(4)},
        },
    )
    bb_path = tmp_path / "s5_bb.sqlite3"
    bb = SqliteBlackboard(bb_path)
    try:
        bb.add_fact(source_engine="lean4", title="Saved Fact 1", file_path="src/m0.py", severity="CRITICAL")
        bb.add_fact(source_engine="z3_formal", title="Saved Fact 2", file_path="src/m1.py", severity="HIGH")
        for i in range(2):
            bb.enqueue_intent(
                intent_type="stage1",
                payload={"repo_path": str(repo), "idx": i, "cpu_work_iters": 120000},
                lane=2,
            )
            assert bb.claim_intent(f"crashed-{i}") is not None
        for i in range(2, 6):
            bb.enqueue_intent(
                intent_type="stage1",
                payload={"repo_path": str(repo), "idx": i, "cpu_work_iters": 120000},
                lane=2,
            )
    finally:
        _close_if_supported(bb)

    res = asyncio.run(
        run_local_rfchunt_async(
            None,
            repo_path=repo,
            db_path=bb_path,
            max_cpu_workers=2,
            resume=True,
        )
    )
    assert int((res.get("recovery") or {}).get("recovered_to_pending", 0)) >= 2
    assert len(set(res.get("worker_pids") or [])) >= 2
    bb_after = SqliteBlackboard(bb_path)
    try:
        assert len(bb_after.list_facts()) >= 2
    finally:
        _close_if_supported(bb_after)

    # Part B: OOM 500 downshift 12b -> 7b, then trip circuit breaker after 2 OOM failures
    static_f = [
        EngineFinding(engine="zizmor", title="pwn", file_path=".github/workflows/ci.yml", line=1)
    ]
    down_guard = OllamaConcurrencyGuard(lock_path=tmp_path / "s5_down.lock")
    with _ollama_loopback_server(
        {
            "models": ["gemma-4-12b-abliterated", "qwen2.5:7b"],
            "oom_models": ["gemma-4-12b-abliterated"],
            "verdict_file": ".github/workflows/ci.yml",
        }
    ) as (ep_down, st_down):
        out_f, tel_down = verify_gha_findings_with_llm(
            repo,
            static_f,
            model="gemma-4-12b-abliterated",
            ollama_endpoint=ep_down,
            env_local_path=tmp_path / "no.env",
            force_ollama=True,
            guard=down_guard,
        )
        assert tel_down["status"] == "completed"
        assert len(out_f) >= 1
        assert [c["model"] for c in st_down["chat_calls"]].count("gemma-4-12b-abliterated") == 1

    cb_guard = OllamaConcurrencyGuard(
        lock_path=tmp_path / "s5_cb.lock", failure_threshold=2, cooldown_sec=60.0
    )

    try:
        with _ollama_loopback_server({"models": ["qwen2.5:7b"], "always_oom": True}) as (ep_cb, st_cb):
            for _ in range(2):
                verify_gha_findings_with_llm(
                    repo,
                    static_f,
                    model="qwen2.5:7b",
                    ollama_endpoint=ep_cb,
                    env_local_path=tmp_path / "no.env",
                    force_ollama=True,
                    guard=cb_guard,
                )
            calls_at_trip = len(st_cb["chat_calls"])
            assert cb_guard.is_circuit_open() is True
            _, tel_open = verify_gha_findings_with_llm(
                repo,
                static_f,
                model="qwen2.5:7b",
                ollama_endpoint=ep_cb,
                env_local_path=tmp_path / "no.env",
                force_ollama=True,
                guard=cb_guard,
            )
            assert tel_open["status"] == "skipped_circuit_open"
            assert len(st_cb["chat_calls"]) == calls_at_trip
    finally:
        cb_guard.reset()


def test_tier4_s6_ide_bootstrap_and_r5_compliance_invariants(tmp_path: Path) -> None:
    swarm_sha = hashlib.sha256((ROOT / "rfc_hunt_swarm.py").read_bytes()).hexdigest()
    mcp_sha = hashlib.sha256((ROOT / "mcp_server.py").read_bytes()).hexdigest()
    path_before = os.environ.get("PATH", "")

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    proc = _run_bootstrap_isolated(fake_home)
    assert proc.returncode == 0, proc.stderr

    cfg_dir = fake_home / ".gemini" / "config"
    lm = json.loads((cfg_dir / "local_models.json").read_text(encoding="utf-8"))
    mc = json.loads((cfg_dir / "mcp_config.json").read_text(encoding="utf-8"))
    assert "rfchunt-bugbounty" in mc["mcpServers"]
    assert "ollama" in lm

    backends = probe_optional_backends(lean_dir=tmp_path, timeout_sec=1.0)
    assert {"trufflehog", "jadx", "subfinder", "httpx", "katana", "schemathesis"}.issubset(
        backends.keys()
    )

    assert os.environ.get("PATH", "") == path_before
    assert hashlib.sha256((ROOT / "rfc_hunt_swarm.py").read_bytes()).hexdigest() == swarm_sha
    assert hashlib.sha256((ROOT / "mcp_server.py").read_bytes()).hexdigest() == mcp_sha
    test_tier1_r5_02_zero_registry_or_persistent_path_mutation_primitives()
    test_tier1_r5_04_zero_mocks_in_e2e_test_suite()


# ===========================================================================
# OPTIONAL LIVE-OLLAMA TIMING BENCHMARK (STAGE 2 < 1s, STAGE 3 ~20-30s)
# ===========================================================================


def test_live_ollama_stage2_stage3_benchmark(tmp_path: Path) -> None:
    if os.environ.get("RFCHUNT_LIVE_OLLAMA_BENCH") != "1":
        pytest.skip("Set RFCHUNT_LIVE_OLLAMA_BENCH=1 to enable live Ollama timing benchmark")
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=0.4) as resp:
            if resp.status != 200:
                pytest.skip("Live Ollama /api/tags did not return HTTP 200")
            tags_data = json.loads(resp.read().decode("utf-8"))
            if not (tags_data.get("models") or []):
                pytest.skip("Live Ollama daemon has 0 installed models")
    except Exception:
        pytest.skip("Live Ollama daemon unreachable on 127.0.0.1:11434 within 400ms")

    repo = _init_git_repo(
        tmp_path / "bench_repo",
        {
            f"src/mod_{i}.py": f"import pickle\ndef load_{i}(raw): return pickle.loads(raw)\n"
            for i in range(10)
        },
    )
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    orch = EnsembleOrchestrator(program="common_codes", embedded=False)
    t0 = time.monotonic()
    res = orch.run_fast_parallel_ooda(
        repo,
        program="common_codes",
        blackboard_db=tmp_path / "bench_bb.sqlite3",
        max_cpu_workers=2,
        eligibility_db=elig,
    )
    total_elapsed = time.monotonic() - t0
    stage2_ms = float((res.get("stage2") or {}).get("elapsed_ms", 0.0))
    assert stage2_ms < 1000.0
    assert total_elapsed <= 45.0
