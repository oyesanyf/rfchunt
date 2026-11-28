"""
Zero-Mock Integration Tests for RFCHunt M3 Bounty Loops, CLI, MCP & IDE Bootstrap.
=================================================================================
Exercises genuine end-to-end execution across:
  - `_redact_inline_tokens` across all 8 secret/token classes
  - `ProgramEligibilityDB` `RFCHUNT_ELIGIBILITY_DB` environment override
  - Loop 3 `EnsembleOrchestrator.run_fast_parallel_ooda` (Stage 1 noise drop +
    Windows spawn multi-worker PIDs, Stage 2 ACDSO <1s top 3-5, Stage 3 real
    loopback `ThreadingHTTPServer` single-slot `OllamaConcurrencyGuard` + OOM 500
    downshift + circuit breaker, `resume=True` crash recovery)
  - Loop 4 `evaluate_and_stage_submission` & `LinuxPocRunner.verify_sandbox_http_probe`
    (required `HackerOne/oyesanyf` headers, fail-closed 3-way gating,
    `READY_TO_SUBMIT.json`, `browser_handoff_spec`, clickable H1 URL)
  - `revenue_cli` (`fast-ooda`, `ensemble-audit --cpu-workers --blackboard-db --resume`)
  - `bugbounty_mcp_server` (`bb_run_fast_ooda`, `bb_stage_hackerone_draft`, 14-key probe)
  - `scripts/setup_antigravity_rfchunt_ide.py` isolated subprocess bootstrap
"""

from __future__ import annotations

import ast
import contextlib
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import bugbounty_mcp_server
import revenue_cli
from bugbounty_mcp_server import (
    TOOLS_SCHEMA,
    BugBountyMCPServer,
    _probe_toolchain_status_safe,
)
from engine.advisory_exporter import _redact_inline_tokens
from engine.async_blackboard_runtime import SqliteBlackboard
from engine.ensemble_orchestrator import (
    EnsembleOrchestrator,
    evaluate_and_stage_submission,
)
from engine.linux_poc_runner import LinuxPocRunner, probe_optional_backends
from engine.ollama_concurrency_guard import get_shared_ollama_guard
from engine.program_eligibility_db import ProgramEligibilityDB


@contextlib.contextmanager
def _scoped_env(**updates: str | None):
    saved: dict[str, str | None] = {k: os.environ.get(k) for k in updates}
    try:
        for k, v in updates.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, prev in saved.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev


def _git(repo: Path, *args: str) -> None:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    assert proc.returncode == 0


def _init_git_repo(repo: Path, files: dict[str, str], *, commit_msg: str = "init") -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init")
    _git(repo, "config", "user.email", "integration@rfchunt.local")
    _git(repo, "config", "user.name", "RFCHunt Integration")
    for rel, content in files.items():
        fp = repo / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", commit_msg)
    return repo


@contextlib.contextmanager
def _ollama_loopback_server(config: dict[str, Any]):
    """Real loopback ThreadingHTTPServer speaking Ollama `/api/tags` and `/api/chat`."""
    state: dict[str, Any] = {
        "chat_calls": [],
        "inflight": 0,
        "max_inflight": 0,
    }
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.startswith("/api/tags"):
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

        def do_POST(self) -> None:
            if self.path != "/api/chat":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0") or 0)
            req_raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                req_json = json.loads(req_raw.decode("utf-8"))
            except (json.JSONDecodeError, TypeError, ValueError):
                req_json = {}
            model = str(req_json.get("model") or "")

            with lock:
                state["inflight"] += 1
                state["max_inflight"] = max(state["max_inflight"], state["inflight"])
                state["chat_calls"].append({"model": model, "ts": time.monotonic()})

            try:
                delay = float(config.get("chat_delay_sec", 0.02))
                if delay > 0:
                    time.sleep(delay)

                oom_models = set(config.get("oom_models", []))
                if config.get("always_oom") or model in oom_models:
                    err = json.dumps(
                        {"error": "model requires more system memory (CUDA out of memory)"}
                    ).encode("utf-8")
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                    return

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
                                        "file_path": config.get("verdict_file", "src/prod_0.py"),
                                        "line": 2,
                                        "confirmed": True,
                                        "severity": "HIGH",
                                        "confidence": 0.85,
                                        "false_positive_reason": "",
                                        "recommended_fix": "Validate untrusted inputs.",
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

        def log_message(self, format: str, *args: Any) -> None:
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
    """Real loopback ThreadingHTTPServer recording request headers and timestamps."""
    records: list[dict[str, Any]] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with lock:
                records.append(
                    {
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

        def log_message(self, format: str, *args: Any) -> None:
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


def test_zero_test_doubles_ast_invariant() -> None:
    src = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "unittest.mock" not in alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert "unittest.mock" not in mod


def test_redact_inline_tokens_scrubs_all_8_secret_classes() -> None:
    tok_ghp = "ghp_" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8"
    tok_pat = "github_pat_" + "11AAAAAA00000000000000_BBBBBBBBBBBBBBBBBBBBBB"
    tok_ant = "sk-ant-" + "api03_ABCDEFGHIJKLMNOPQRSTUVWX123456"
    tok_aws = "AKIA" + "IOSFODNN7EXAMPLE"
    tok_stripe = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz1234"
    tok_slack = "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
    tok_jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJ1c2VyMTIzNDUifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    tok_bearer = "Bearer " + "opaque_secret_bearer_token_987654321"

    sample = "\n".join(
        [
            f"gh={tok_ghp}",
            f"pat={tok_pat}",
            f"ant={tok_ant}",
            f"aws={tok_aws}",
            f"stripe={tok_stripe}",
            f"slack={tok_slack}",
            f"jwt={tok_jwt}",
            f"auth={tok_bearer}",
        ]
    )
    redacted = _redact_inline_tokens(sample)
    for raw in (
        tok_ghp,
        tok_pat,
        tok_ant,
        tok_aws,
        tok_stripe,
        tok_slack,
        tok_jwt,
        "opaque_secret_bearer_token_987654321",
    ):
        assert raw not in redacted


def test_program_eligibility_db_env_override_and_unlock_flip(tmp_path: Path) -> None:
    env_db_path = tmp_path / "override_elig.sqlite3"
    with _scoped_env(RFCHUNT_ELIGIBILITY_DB=str(env_db_path)):
        db = ProgramEligibilityDB()
        assert Path(db.db_path).resolve() == env_db_path.resolve()
        counts = db.seed_observed_hackerone_baseline()
        assert counts["UNLOCKED"] >= 1
        assert db.is_eligible("anthropic") is True
        assert db.is_eligible("shopify") is False
        db.upsert("shopify", "UNLOCKED", bounty_max_usd=50000)
        assert db.is_eligible("shopify") is True


def test_loop3_fast_parallel_ooda_stage1_noise_drop_spawn_pids_and_stage2_under_1s(
    tmp_path: Path,
) -> None:
    files: dict[str, str] = {}
    for i in range(6):
        files[f"tests/test_noise_{i}.py"] = f"import pickle\npickle.loads(b'{i}')\n"
    for i in range(6):
        files[f"src/prod_{i}.py"] = f"import pickle\ndef load_{i}(d):\n    return pickle.loads(d)\n"

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
    assert res.get("status") == "completed"
    s1 = res.get("stage1") or {}
    assert int(s1.get("noise_dropped", 0) or res.get("stage1_dropped_noise_count", 0)) >= 6
    assert int(s1.get("production_count", 0) or res.get("stage1_production_count", 0)) >= 6
    assert len(set(res.get("worker_pids") or [])) >= 2

    s2 = res.get("stage2") or {}
    selected = s2.get("selected") or []
    assert 3 <= len(selected) <= 5
    assert float(s2.get("elapsed_ms", 9999.0)) < 1000.0


def test_loop3_stage3_loopback_ollama_guard_oom_downshift_and_circuit_breaker(
    tmp_path: Path,
) -> None:
    files = {
        f"src/prod_{i}.py": f"import pickle\ndef f{i}(raw):\n    return pickle.loads(raw)\n"
        for i in range(4)
    }
    repo = _init_git_repo(tmp_path / "repo", files)
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()

    guard = get_shared_ollama_guard()
    guard.reset()
    try:
        with _ollama_loopback_server(
            {
                "models": ["gemma-4-12b-abliterated", "qwen2.5:7b"],
                "oom_models": ["gemma-4-12b-abliterated"],
                "verdict_file": "src/prod_0.py",
                "chat_delay_sec": 0.02,
            }
        ) as (endpoint, state), _scoped_env(OLLAMA_HOST=endpoint, RFCHUNT_OFFLINE=None):
            orch = EnsembleOrchestrator(
                program="common_codes",
                embedded=False,
                model="gemma-4-12b-abliterated",
            )
            res_down = orch.run_fast_parallel_ooda(
                repo,
                program="common_codes",
                blackboard_db=tmp_path / "bb_down.sqlite3",
                max_cpu_workers=2,
                eligibility_db=elig,
            )
        assert res_down.get("status") == "completed"
        assert state["max_inflight"] <= 1
        assert 1 <= len(state["chat_calls"]) <= 5
        called_models = [c["model"] for c in state["chat_calls"]]
        assert called_models.count("gemma-4-12b-abliterated") == 1
        assert "qwen2.5:7b" in called_models

        guard.reset()
        with (
            _ollama_loopback_server({"models": ["qwen2.5:7b"], "always_oom": True}) as (
                ep_oom,
                _state_oom,
            ),
            _scoped_env(OLLAMA_HOST=ep_oom, RFCHUNT_OFFLINE=None),
        ):
            orch_oom = EnsembleOrchestrator(
                program="common_codes",
                embedded=False,
                model="qwen2.5:7b",
            )
            res_cb = orch_oom.run_fast_parallel_ooda(
                repo,
                program="common_codes",
                blackboard_db=tmp_path / "bb_cb.sqlite3",
                max_cpu_workers=2,
                eligibility_db=elig,
            )
        assert res_cb.get("status") == "completed"
        assert len(res_cb.get("facts") or res_cb.get("clusters") or []) >= 1
    finally:
        guard.reset()


def test_loop3_blackboard_crash_recovery_resume_true(tmp_path: Path) -> None:
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef load(x):\n    return pickle.loads(x)\n"},
    )
    bb_path = tmp_path / "resume_bb.sqlite3"
    bb = SqliteBlackboard(bb_path)
    try:
        bb.add_fact(
            source_engine="lean4",
            title="Preserved formal fact",
            file_path="src/loader.py",
            severity="CRITICAL",
        )
        bb.enqueue_intent(intent_type="stage1", payload={"repo_path": str(repo)}, lane=1)
        assert bb.claim_intent("crashed-worker") is not None
    finally:
        bb.close()

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

    bb_after = SqliteBlackboard(bb_path)
    try:
        assert any(f["title"] == "Preserved formal fact" for f in bb_after.list_facts())
    finally:
        bb_after.close()


def test_loop4_sandbox_http_probe_headers_and_fail_closed_3way_gate(tmp_path: Path) -> None:
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
        assert probe_res.get("verified") is True
        assert len(records) == 1
        assert records[0]["headers"].get("user-agent") == "HackerOne/oyesanyf"
        assert records[0]["headers"].get("x-hackerone") == "oyesanyf"

        blocked_probe = runner.verify_sandbox_http_probe(
            f"{base_url}/blocked",
            program="vercel",
            eligibility_db=elig,
            max_rps=2.0,
            researcher_handle="oyesanyf",
        )
        assert blocked_probe.get("verified") is False
        assert blocked_probe.get("status") == "blocked_ineligible"
        assert len(records) == 1

    # Gate 1: Ineligible program (shopify BLOCKED_SIGNAL) fails closed
    r_inelig = evaluate_and_stage_submission(
        program="shopify",
        asset="src/app.ts",
        title="Blocked program test",
        summary="Detailed vulnerability description exceeding 100 chars for fail-closed eligibility test.",
        impact="Blocked.",
        weakness_cwe="CWE-639",
        severity="HIGH",
        poc_verified=True,
        poc_transcript="HTTP 200 OK",
        eligibility_db=elig,
        output_dir=tmp_path / "out_inelig",
        trigger_browser=True,
    )
    assert r_inelig.get("eligible") is False
    assert not (tmp_path / "out_inelig" / "READY_TO_SUBMIT.json").is_file()

    # Gate 2: Threat model failure (anthropic srt-sandbox cross-session) fails closed
    r_tm = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/sandbox.rs",
        title="Cross-session inspection in srt-sandbox",
        summary="Two processes inside srt-sandbox cross-session can inspect each other without boundary crossing.",
        impact="Intra-sandbox inspection.",
        weakness_cwe="CWE-200",
        severity="MEDIUM",
        poc_verified=True,
        poc_transcript="pid read inside srt-sandbox",
        eligibility_db=elig,
        output_dir=tmp_path / "out_tm",
        trigger_browser=True,
    )
    assert r_tm.get("eligible") is False
    assert not (tmp_path / "out_tm" / "READY_TO_SUBMIT.json").is_file()

    # Gate 3: Unverified PoC fails closed
    r_unver = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/api/auth.py",
        title="Unverified SSRF lead",
        summary="Static finding exceeding 100 chars without live PoC verification transcript attached.",
        impact="Potential SSRF.",
        weakness_cwe="CWE-918",
        severity="HIGH",
        poc_verified=False,
        poc_transcript="",
        eligibility_db=elig,
        output_dir=tmp_path / "out_unver",
        trigger_browser=True,
    )
    assert r_unver.get("eligible") is False
    assert not (tmp_path / "out_unver" / "READY_TO_SUBMIT.json").is_file()

    # All 3 gates passing -> READY_TO_SUBMIT.json + redaction + browser_handoff_spec + clickable URL
    raw_secret = "ghp_" + "Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2"
    out_ok = tmp_path / "out_ok"
    r_ok = evaluate_and_stage_submission(
        program="common_codes",
        asset="src/sdjwt.py",
        title="SD-JWT missing cnf holder binding check",
        summary=(
            "Verifier accepts SD-JWT presentations without validating cnf holder key binding against nonce, "
            "allowing unauthorized credential replay."
        ),
        impact="Unauthorized credential presentation replay.",
        weakness_cwe="CWE-287",
        severity="HIGH",
        poc_verified=True,
        poc_transcript=f"Verified replay transcript token={raw_secret}",
        eligibility_db=elig,
        output_dir=out_ok,
        trigger_browser=True,
    )
    assert r_ok.get("eligible") is True
    ready_path = out_ok / "READY_TO_SUBMIT.json"
    assert ready_path.is_file()
    assert raw_secret not in ready_path.read_text(encoding="utf-8")
    assert (r_ok.get("browser_handoff_spec") or {}).get("action") == "stage_draft"
    url = str(r_ok.get("report_url") or r_ok.get("submit_url") or "")
    assert url.startswith("https://hackerone.com/reports/")


def test_revenue_cli_fast_ooda_and_ensemble_audit_blackboard_flags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert "fast-ooda" in revenue_cli.REVENUE_SUBCOMMANDS
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef f(x):\n    return pickle.loads(x)\n"},
    )
    bb_ooda = tmp_path / "cli_ooda_bb.sqlite3"
    out_ooda = tmp_path / "cli_ooda_out"
    rc1 = revenue_cli.run_revenue_cli(
        [
            "fast-ooda",
            "--target",
            str(repo),
            "--program",
            "anthropic",
            "--cpu-workers",
            "2",
            "--blackboard-db",
            str(bb_ooda),
            "--out",
            str(out_ooda),
            "--embedded",
            "--json",
        ]
    )
    assert rc1 == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed.get("status") == "completed"
    assert bb_ooda.is_file()
    assert (out_ooda / "fast_ooda_report.json").is_file()

    bb_ens = tmp_path / "cli_ens_bb.sqlite3"
    out_ens = tmp_path / "cli_ens_out"
    rc2 = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(repo),
            "--embedded",
            "--cpu-workers",
            "2",
            "--blackboard-db",
            str(bb_ens),
            "--resume",
            "--out",
            str(out_ens),
        ]
    )
    assert rc2 == 0
    assert bb_ens.is_file()
    assert (out_ens / "ensemble_report.json").is_file()


def test_bugbounty_mcp_server_fast_ooda_stage_draft_and_toolchain_14_keys(tmp_path: Path) -> None:
    srv = BugBountyMCPServer()
    list_resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tool_names = {t["name"] for t in list_resp["result"]["tools"]}
    assert "bb_run_fast_ooda" in tool_names
    assert any(t["name"] == "bb_run_fast_ooda" and "inputSchema" in t for t in TOOLS_SCHEMA)

    # Empty target must fail closed with isError=True
    err_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "bb_run_fast_ooda", "arguments": {}},
        }
    )
    assert err_resp["result"]["isError"] is True

    # Valid bb_run_fast_ooda call
    repo = _init_git_repo(
        tmp_path / "repo",
        {"src/loader.py": "import pickle\ndef f(x):\n    return pickle.loads(x)\n"},
    )
    bb_path = tmp_path / "mcp_bb.sqlite3"
    ok_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "bb_run_fast_ooda",
                "arguments": {
                    "target": str(repo),
                    "program": "anthropic",
                    "cpu_workers": 2,
                    "blackboard_db": str(bb_path),
                    "out_dir": str(tmp_path / "mcp_out"),
                    "embedded": True,
                },
            },
        }
    )
    assert ok_resp["result"]["isError"] is False
    ok_payload = json.loads(ok_resp["result"]["content"][0]["text"])
    assert ok_payload.get("status") == "completed"
    assert bb_path.is_file()

    # bb_stage_hackerone_draft fail-closed on ineligible shopify & clickable URL + redaction on anthropic
    elig = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig.seed_observed_hackerone_baseline()
    with _scoped_env(RFCHUNT_ELIGIBILITY_DB=str(elig.db_path)):
        blocked_resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "bb_stage_hackerone_draft",
                    "arguments": {
                        "program_handle": "shopify",
                        "asset": "@shopify/shopify-app-remix",
                        "weakness_cwe": "CWE-639",
                        "severity_rating": "High",
                        "title": "Blocked program draft",
                        "vulnerability_information": "D" * 120,
                        "impact": "Blocked by signal gate.",
                        "poc_verified": True,
                        "out_path": str(tmp_path / "blocked.json"),
                        "eligibility_db_path": str(elig.db_path),
                    },
                },
            }
        )
        blocked_body = json.loads(blocked_resp["result"]["content"][0]["text"])
        assert str(blocked_body.get("status", "")).startswith("blocked")

        raw_ant = "sk-ant-" + "api03_IntegrationSecretValue12345678"
        staged_path = tmp_path / "staged_ok.json"
        staged_resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "bb_stage_hackerone_draft",
                    "arguments": {
                        "program_handle": "anthropic",
                        "asset": "src/api/auth.py",
                        "weakness_cwe": "CWE-347",
                        "severity_rating": "High",
                        "title": "JWT verification bypass in API gateway",
                        "vulnerability_information": (
                            f"Token leak {raw_ant} and signature bypass in API gateway verified cleanly "
                            "across protected endpoints exceeding minimum length."
                        ),
                        "impact": "Authentication bypass.",
                        "poc_verified": True,
                        "out_path": str(staged_path),
                        "eligibility_db_path": str(elig.db_path),
                    },
                },
            }
        )
        assert staged_resp["result"]["isError"] is False
        staged_body = json.loads(staged_resp["result"]["content"][0]["text"])
        assert staged_body["status"] == "staged_ready"
        assert str(staged_body.get("report_url") or "").startswith("https://hackerone.com/reports/")
        assert raw_ant not in staged_path.read_text(encoding="utf-8")

    # _probe_toolchain_status_safe fallback keys match all 14 keys of probe_optional_backends
    expected_keys = set(probe_optional_backends(lean_dir=tmp_path, timeout_sec=1.0).keys())
    assert len(expected_keys) == 14
    assert set(bugbounty_mcp_server._ALL_TOOLCHAIN_KEYS) == expected_keys
    embedded_status = _probe_toolchain_status_safe(tmp_path, True)
    if embedded_status:
        assert expected_keys.issubset(embedded_status.keys())


def test_setup_antigravity_rfchunt_ide_bootstrap_and_install_go_tools_empty_path(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "home"
    go_bin = fake_home / "go" / "bin"
    go_bin.mkdir(parents=True)
    stub_name = "subfinder.exe" if os.name == "nt" else "subfinder"
    (go_bin / stub_name).write_text("stub", encoding="utf-8")

    elig_db_path = tmp_path / "bootstrap_elig.sqlite3"
    before_path = os.environ.get("PATH", "")

    env1 = os.environ.copy()
    env1["HOME"] = str(fake_home)
    env1["USERPROFILE"] = str(fake_home)
    env1["RFCHUNT_ELIGIBILITY_DB"] = str(elig_db_path)

    proc1 = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "setup_antigravity_rfchunt_ide.py"), "--skip-pip"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env1,
        cwd=str(ROOT),
        check=False,
    )
    assert proc1.returncode == 0, proc1.stderr
    assert os.environ.get("PATH", "") == before_path
    assert elig_db_path.is_file()

    cfg_dir = fake_home / ".gemini" / "config"
    lm = json.loads((cfg_dir / "local_models.json").read_text(encoding="utf-8"))
    mc = json.loads((cfg_dir / "mcp_config.json").read_text(encoding="utf-8"))
    assert "ollama" in lm
    assert "rfchunt-bugbounty" in mc.get("mcpServers", {})
    assert (cfg_dir / "rules" / "bounty_threat_hunting_and_coding_protocol.md").is_file()

    out_low = (proc1.stdout + "\n" + proc1.stderr).lower()
    for tool in ("trufflehog", "subfinder", "httpx", "katana", "jadx", "schemathesis"):
        assert tool in out_low

    # Graceful --install-go-tools when go is absent from PATH
    empty_bin = tmp_path / "empty_bin"
    empty_bin.mkdir()
    env2 = dict(env1)
    env2["PATH"] = str(empty_bin)
    proc2 = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "setup_antigravity_rfchunt_ide.py"),
            "--skip-pip",
            "--install-go-tools",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env2,
        cwd=str(ROOT),
        check=False,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert os.environ.get("PATH", "") == before_path
