"""
Tier-5 Adversarial Hardening & Coverage Gap Regression Suite.

Covers all Challenger-confirmed bugs/bypasses (Category A: A1-A9, B1-B7),
coverage gaps (Category B: Docker -m after unknown flags, composite ApprovalGate +
RunBudgetLedger + tokens_used edge cases, ingest_from_database idempotency &
cascade_hypotheses, MCP edge cases, cli_render Rich-TTY / as_json / LiveScanProgress /
non-str summary, external_scanners OSError / failed / a / host / _classify_nuclei_capability /
seen_batch / partial / disabled / valid extra_flags / docker-image & docker-network parity),
and preserved M1-M4 / Tier 1-4 contracts (Category C).

Runs 100% offline under CI=true, RFCHUNT_OFFLINE=1.
"""

from __future__ import annotations

import concurrent.futures
import copy
import inspect
import io
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import types
from typing import Any, Dict, Iterator, List
import urllib.error
import urllib.request
from unittest.mock import MagicMock

import httpx
import pytest

from database import Database
from engine.approval_gate import ApprovalGate, ApprovalRule
from engine.artex_bridge import (
    ArtexRestClient,
    CapturedExchange,
    TrafficCaptureSession,
    _validate_endpoint_url,
)
import engine.cli_render as cli_render
from engine.dual_graph_engine import (
    AssetGraph,
    DualGraphAttackEngine,
    RunBudgetLedger,
)
from engine.execution_policy import ExecutionPolicy
import engine.external_scanners as es
from engine.live_executors import LiveWorkerExecutorRegistry
from engine.mantis_integrator import run_unified_all_scans
from engine.safe_network_validator import (
    is_cloud_metadata,
    is_safe_target_ip,
    validate_and_authorize_target,
    validate_target_host,
)
from mcp_server import MCPHttpServer, TargetAuthorizationGate, TerminatorMCPServer


@pytest.fixture(autouse=True)
def _tier5_reset_singletons(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    orig_targets = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    orig_history = {k: list(v) for k, v in TargetAuthorizationGate._request_history.items()}
    ExecutionPolicy.reset_instance()
    TargetAuthorizationGate.ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}
    TargetAuthorizationGate._request_history.clear()
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.delenv("RFCHUNT_ALLOW_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("RFCHUNT_AUTHORIZED_TARGETS", raising=False)
    try:
        yield
    finally:
        ExecutionPolicy.reset_instance()
        TargetAuthorizationGate.ALLOWED_TARGETS = orig_targets
        TargetAuthorizationGate._request_history.clear()
        for k, hist in orig_history.items():
            TargetAuthorizationGate._request_history[k] = hist


# =============================================================================
# Category A — Confirmed Bugs & Security Bypasses (A1-A9, B1-B7)
# =============================================================================


def test_tier5_a1_surface_mining_multikey_and_ai_sinks_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(TargetAuthorizationGate, "ALLOWED_TARGETS", {"127.0.0.1"})
    payload = {
        "endpoints": [
            {"url": "http://127.0.0.1:8000/api/users", "node_type": "ENDPOINT"},
            {"url": "http://127.0.0.1:8000/api/users", "node_type": "ENDPOINT"},  # dup deduped
        ],
        "ai_sinks": [{"url": "http://127.0.0.1:8000/api/chat"}],
        "assets": [{"url": "http://127.0.0.1:8000/admin", "node_type": "ASSET"}],
    }
    norm = LiveWorkerExecutorRegistry._normalize_module21_items(payload)
    routes = {item.get("route") for item in norm}
    assert routes == {
        "http://127.0.0.1:8000/api/users",
        "http://127.0.0.1:8000/api/chat",
        "http://127.0.0.1:8000/admin",
    }
    assert len(norm) == 3

    ai_only = LiveWorkerExecutorRegistry._normalize_module21_items(
        {"ai_sinks": [{"route": "/api/chat"}]}
    )
    assert len(ai_only) == 1
    assert ai_only[0]["node_type"].upper() == "AI_SINK"

    plain_list = LiveWorkerExecutorRegistry._normalize_module21_items(["/health", "/ready"])
    assert [it["route"] for it in plain_list] == ["/health", "/ready"]

    reg = LiveWorkerExecutorRegistry(
        host="127.0.0.1",
        port=8000,
        authorized=True,
        surface_provider=lambda target_path=None, query="": payload,
    )
    res = reg._surface_mining_impl(query="")
    assert res["ok"] is True
    assert res["count"] == 3
    assert len(res["ai_sinks"]) == 1
    assert len(res["assets"]) == 1
    assert len(res["endpoints"]) == 2


@pytest.mark.parametrize(
    "cmd",
    [
        ["python", "-m", "runpy", "tools.sqlmap", "--version"],
        ["python", "-mrunpy", "tools.sqlmap"],
        ["python", "-um", "runpy", "tools.sqlmap"],
        ["python", "-m", "cProfile", "-m", "tools.sqlmap"],
        ["python", "-m", "profile", "-m", "nmap"],
        ["python", "-m", "pdb", "-m", "tools.sqlmap"],
        ["python", "-m", "trace", "-t", "-m", "tools.sqlmap"],
        ["python", "-m", "timeit", "import os"],
        ["python", "-m", "code"],
        ["python", "-m", "runpy", "sqlmap.py"],
        ["docker", "run", "--rm", "python:3.11-slim", "-m", "timeit", "import os"],
        ["docker", "run", "--rm", "python:3.11-slim", "-m", "cProfile", "-m", "tools.sqlmap"],
        ["docker", "run", "--rm", "--entrypoint=python3", "ubuntu:22.04", "-m", "runpy", "tools.sqlmap"],
        ["docker", "run", "--rm", "--unknown-flag", "val", "python:3.11-slim", "-mrunpy", "tools.sqlmap"],
        ["docker", "run", "--rm", "--entrypoint=/usr/bin/python3.11", "--unknown-flag", "val", "ubuntu:22.04", "-um", "runpy", "tools.sqlmap"],
        ["docker", "run", "--rm", "--entrypoint=python3", "ubuntu:22.04", "--unknown-flag", "val", "-m", "timeit", "import os"],
    ],
)
def test_tier5_a2_blocks_python_stdlib_runner_indirection(cmd: List[str]) -> None:
    policy = ExecutionPolicy()
    ok, reason = policy.validate_subprocess_command(cmd)
    assert ok is False, f"ExecutionPolicy failed to block {cmd!r}: {reason}"

    gate = ApprovalGate(mode="policy")
    dec = gate.check(action_type="subprocess_exec", target=" ".join(cmd), command=cmd, is_high_risk=False)
    assert dec.approved is False, f"ApprovalGate failed to block {cmd!r}: {dec.reason}"


@pytest.mark.parametrize(
    ("cmd", "target"),
    [
        (["python", "-m", "pytest", "-q"], "python -m pytest -q"),
        (["python", "-m", "http.server", "8080"], "python -m http.server 8080"),
        (["python", "scripts/benign_check.py"], "python scripts/benign_check.py"),
        (["docker", "run", "--rm", "projectdiscovery/httpx:latest", "-u", "http://127.0.0.1:8080", "-jsonl", "-method", "-rl", "5"], "http://127.0.0.1:8080"),
    ],
)
def test_tier5_a2_allows_benign_python_and_scanner_controls(cmd: List[str], target: str) -> None:
    ok, reason = ExecutionPolicy().validate_subprocess_command(cmd)
    assert ok is True, reason
    dec = ApprovalGate(mode="policy").check(action_type="subprocess_exec", target=target, command=cmd)
    assert dec.approved is True, dec.reason


def test_tier5_a3_ingest_from_database_standard_legacy_multiline_and_idempotency(
    tmp_path: Path,
) -> None:
    std_db = Database(db_path=str(tmp_path / "std.db"))
    try:
        pid = std_db.save_probe(None, "probe", "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        eid = std_db.record_evaluation(pid, "127.0.0.1", 8000, True, "CL.TE", "desync", "HTTP/1.1 200 OK")
        aid = std_db.record_anomaly(eid, "auth_bypass", "Admin token accepted without signature", b"HTTP/1.1 200 OK")
        with std_db._lock, std_db.conn:
            std_db.conn.execute(
                "INSERT INTO reproducible_vulnerabilities (vuln_id, anomaly_id, impact, minimized_probe, reproducibility_rate) VALUES (?, ?, ?, ?, ?)",
                ("RV-T5-1", str(aid), "CRITICAL", "GET /admin HTTP/1.1", 1.0),
            )
        std_db.save_cascade_hypothesis(eid, "auth", "Bypass leads to RCE", [{"route": "/admin"}])
        std_db.save_mantis_finding({
            "finding_id": "f1", "file_path": "app.py", "line_number": 10,
            "rule_id": "B101", "title": "Use of assert", "severity": "MEDIUM",
            "calibrated_severity": "MEDIUM", "target_path": "app.py", "component": "bandit",
        })
        std_db.save_mantis_finding({
            "finding_id": "f2", "file_path": "app.py", "line_number": 42,
            "rule_id": "B101", "title": "Use of assert", "severity": "MEDIUM",
            "calibrated_severity": "MEDIUM", "target_path": "app.py", "component": "bandit",
        })

        eng = DualGraphAttackEngine(db=std_db, reports_dir=str(tmp_path / "rep_std"))
        summary1 = eng.ingest_from_database()
        assert summary1["reproducible_vulnerabilities"] == 1
        assert summary1["anomalies"] == 1
        assert summary1["evaluations"] == 1
        assert summary1["mantis_findings"] == 2
        assert summary1["cascade_hypotheses"] == 1

        # Second call on same engine must be 100% idempotent
        summary2 = eng.ingest_from_database()
        assert all(v == 0 for v in summary2.values()), summary2

        # Fresh engine against same DB hydrates persisted dual_graph_primitives without duplicating tables
        eng_fresh = DualGraphAttackEngine(db=std_db, reports_dir=str(tmp_path / "rep_fresh"))
        summary_fresh = eng_fresh.ingest_from_database()
        assert summary_fresh["reproducible_vulnerabilities"] == 0
        assert summary_fresh["anomalies"] == 0
        assert summary_fresh["evaluations"] == 0
        assert summary_fresh["mantis_findings"] == 0
        assert summary_fresh["cascade_hypotheses"] == 0
        assert summary_fresh["dual_graph_primitives"] == 6
    finally:
        std_db.conn.close()

    # Legacy SQLite schema (id + details, both with and without sqlite3.Row)
    leg_conn = sqlite3.connect(str(tmp_path / "legacy.db"))
    try:
        leg_conn.execute(
            "CREATE TABLE reproducible_vulnerabilities (id INTEGER PRIMARY KEY, vuln_id TEXT, anomaly_id TEXT, impact TEXT, minimized_probe TEXT, reproducibility_rate REAL)"
        )
        leg_conn.execute("INSERT INTO reproducible_vulnerabilities VALUES (1, 'rv1', 'a1', 'HIGH', 'p1', 1.0)")
        leg_conn.execute("CREATE TABLE anomalies (anomaly_id TEXT, anomaly_type TEXT, details TEXT)")
        leg_conn.execute("INSERT INTO anomalies VALUES ('a1', 'ssrf', 'Legacy details col')")
        leg_conn.commit()

        class LegacyDB:
            conn = leg_conn

        eng_leg = DualGraphAttackEngine(db=LegacyDB(), reports_dir=str(tmp_path / "rep_leg"))
        leg_summary = eng_leg.ingest_from_database()
        assert leg_summary["reproducible_vulnerabilities"] == 1
        assert leg_summary["anomalies"] == 1
    finally:
        leg_conn.close()


def test_tier5_a4_desync_and_harness_enforce_raw_request_destructive_verb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(TargetAuthorizationGate, "ALLOWED_TARGETS", {"127.0.0.1"})
    policy = ExecutionPolicy.get_instance()
    monkeypatch.setattr(policy, "allow_destructive", False)
    monkeypatch.delenv("RFCHUNT_ALLOW_DESTRUCTIVE", raising=False)

    reg_default = LiveWorkerExecutorRegistry(host="127.0.0.1", port=8000, authorized=True)
    called = {"count": 0}

    class SpyHarness:
        def __init__(self, **kw: Any) -> None:
            pass

        def run_evaluation(self, payload: Any) -> Any:
            called["count"] += 1
            return False, None, "ok", {"anomalies": [], "baseline_resp": "HTTP/1.1 200 OK\r\n\r\n"}

    fake_mod = types.ModuleType("deterministic_harness")
    fake_mod.DeterministicHarness = SpyHarness  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "deterministic_harness", fake_mod)

    with pytest.raises(PermissionError):
        reg_default._deterministic_harness_impl(
            route="/api/users/1",
            raw_request="DELETE /api/users/1 HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
        )
    with pytest.raises(PermissionError):
        reg_default._verify_desync({
            "target_route": "/api/users/1",
            "raw_probe": "DELETE /api/users/1 HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
        })
    assert called["count"] == 0

    # Explicit ApprovalRule DENY DELETE also blocks even if allow_destructive=True
    monkeypatch.setattr(policy, "allow_destructive", True)
    deny_del_gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="DENY-DEL", rule_type="http_method", action="DENY", pattern="DELETE")],
    )
    reg_rule = LiveWorkerExecutorRegistry(host="127.0.0.1", port=8000, authorized=True, approval_gate=deny_del_gate)
    with pytest.raises(PermissionError):
        reg_rule._deterministic_harness_impl(
            route="/api/users/1",
            raw_request="DELETE /api/users/1 HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
        )
    with pytest.raises(PermissionError):
        reg_rule._verify_desync({
            "target_route": "/api/users/1",
            "raw_probe": "DELETE /api/users/1 HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
        })
    assert called["count"] == 0

    # Benign GET remains allowed
    ok_res = reg_rule._deterministic_harness_impl(
        route="/health",
        raw_request="GET /health HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
    )
    assert ok_res["ok"] is True
    assert called["count"] == 1


@pytest.mark.parametrize(
    "bad_path",
    [
        r"\\evil-smb.example\share\secret",
        "//evil-smb.example/share/secret",
        r"\\?\C:\Windows\System32",
        r"\\.\pipe\evil",
        "reports/ok\x00.json",
    ],
)
def test_tier5_a5_surface_mining_blocks_unc_device_and_nul_before_stat(
    monkeypatch: pytest.MonkeyPatch, bad_path: str
) -> None:
    monkeypatch.setattr(TargetAuthorizationGate, "ALLOWED_TARGETS", {"127.0.0.1"})
    touched: List[str] = []
    monkeypatch.setattr(Path, "exists", lambda self: touched.append(str(self)) or False)

    reg = LiveWorkerExecutorRegistry(host="127.0.0.1", port=8000, authorized=True)
    res = reg._surface_mining_impl(target_path=bad_path, query="")
    assert touched == [], f"Unsafe path reached filesystem stat: {touched}"
    assert res.get("ok") is False
    assert res.get("error")


def test_tier5_a6_multiturn_enforces_intent_token_budget_when_intent_id_omitted_and_tokens_edge_cases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(TargetAuthorizationGate, "ALLOWED_TARGETS", {"127.0.0.1"})

    class FakeArbiter:
        def arbitrate_structured_json(self, *a: Any, **kw: Any) -> Dict[str, Any]:
            return {
                "action": "tool_call",
                "tool": "verify_auth_boundary",
                "args": {"route": "/x"},
                "tokens_used": 40,
            }

    # 1. node_id fallback enforces max_intent_tokens when intent_id=""
    ledger = RunBudgetLedger(max_task_turns=10, max_task_tokens=10000, max_intent_tokens=50, max_intent_turns=10)
    reg = LiveWorkerExecutorRegistry(host="127.0.0.1", port=8000, authorized=True, budget_ledger=ledger)
    monkeypatch.setattr(reg, "_verify_auth_boundary", lambda **kw: {"ok": True, "confirmed": False, "evidence_quote": ""})

    _, _, _, meta = reg.execute_candidate_multiturn(
        {"node_id": "n1", "target_route": "/x", "attack_type": "AUTH_BYPASS"},
        max_turns=4,
        arbiter=FakeArbiter(),
        intent_id="",
    )
    assert meta["turns_used"] == 1
    assert "Intent token budget exhausted" in str(meta.get("stop_reason") or "")

    # 2. Even when both intent_id and node_id are omitted, synthetic key enforces max_intent_tokens
    ledger2 = RunBudgetLedger(max_task_turns=10, max_task_tokens=10000, max_intent_tokens=50, max_intent_turns=10)
    reg2 = LiveWorkerExecutorRegistry(host="127.0.0.1", port=8000, authorized=True, budget_ledger=ledger2)
    monkeypatch.setattr(reg2, "_verify_auth_boundary", lambda **kw: {"ok": True, "confirmed": False, "evidence_quote": ""})
    _, _, _, meta2 = reg2.execute_candidate_multiturn(
        {"target_route": "/y", "attack_type": "AUTH_BYPASS"},
        max_turns=4,
        arbiter=FakeArbiter(),
        intent_id="",
    )
    assert meta2["turns_used"] == 1
    assert "Intent token budget exhausted" in str(meta2.get("stop_reason") or "")

    # 3. _extract_turn_tokens edge cases: usage.total_tokens vs tokens_used vs bool/non-int
    assert LiveWorkerExecutorRegistry._extract_turn_tokens({"tokens_used": 25}, "s", "u") == 25
    assert LiveWorkerExecutorRegistry._extract_turn_tokens({"usage": {"total_tokens": 33}}, "s", "u") == 33
    # bool must NOT be treated as int=1 when usage.total_tokens is provided
    assert LiveWorkerExecutorRegistry._extract_turn_tokens(
        {"tokens_used": True, "usage": {"total_tokens": 19}}, "s", "u"
    ) == 19
    approx = LiveWorkerExecutorRegistry._extract_turn_tokens({"tokens_used": "bad", "usage": {"total_tokens": False}}, "sys", "usr")
    assert approx >= 1


def test_tier5_a7_ipv4_compatible_ipv6_metadata_blocked_even_with_allow_private() -> None:
    assert is_cloud_metadata(ipaddress.ip_address("::169.254.169.254")) is True
    assert is_safe_target_ip("::169.254.169.254", allow_private=True) is False
    ok, _ = validate_target_host("::169.254.169.254", allow_private=True)
    assert ok is False

    assert is_safe_target_ip("::127.0.0.1", allow_private=False) is False
    assert is_safe_target_ip("::10.0.0.1", allow_private=False) is False

    # Control: ::1 loopback stays permitted under allow_private=True
    ok_lo, _ = validate_target_host("::1", allow_private=True)
    assert ok_lo is True


def test_tier5_a8_replay_exchange_brackets_ipv6_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(TargetAuthorizationGate, "ALLOWED_TARGETS", {"::1"})
    sess = TrafficCaptureSession()
    ex = CapturedExchange(
        traffic_id="TRAF-V6",
        method="GET",
        url="http://[::1]:8000/test",
        host="::1",
        port=8000,
        status_code=200,
        response_body_bytes=b"ok",
    )
    sess.exchanges["TRAF-V6"] = ex

    mock_resp = MagicMock(status_code=200, headers={}, content=b"ok")
    mock_client = MagicMock()
    mock_client.request.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    monkeypatch.setattr(httpx, "Client", lambda **kw: mock_client)

    rep = sess.replay_exchange("TRAF-V6", authorized=True, target_host="::1", target_port=8001)
    assert rep.url.startswith("http://[::1]:8001")


def test_tier5_a9_download_task_archive_rejects_traversal_and_unc(tmp_path: Path) -> None:
    mock_http = MagicMock()
    mock_http.get.return_value = MagicMock(content=b"PK\x03\x04test")
    client = ArtexRestClient(base_url="http://127.0.0.1:9999", authorized=True, http_client=mock_http)

    escaped = tmp_path / "reports" / ".." / ".." / "outside.zip"
    with pytest.raises((PermissionError, ValueError)):
        client.download_task_archive("task-1", escaped)
    assert not escaped.resolve().exists()

    with pytest.raises((PermissionError, ValueError)):
        client.download_task_archive("task-1", r"\\evil-smb\share\x.zip")

    # Valid tmp_path write remains permitted
    valid_out = tmp_path / "valid_archive.zip"
    saved = client.download_task_archive("task-1", valid_out)
    assert Path(saved).read_bytes() == b"PK\x03\x04test"


def test_tier5_b1_scanner_no_duplicate_flags_when_extra_flags_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: List[List[str]] = []

    class _FakeCompleted:
        def __init__(self, stdout: str = "") -> None:
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    def fake_run(argv: List[str], **kwargs: Any) -> _FakeCompleted:
        recorded.append(list(argv))
        return _FakeCompleted("")

    monkeypatch.setattr(es.subprocess, "run", fake_run)
    monkeypatch.setattr(es, "_resolve_host_binary", lambda bp, tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(es, "validate_and_authorize_target", lambda host, **kw: (True, "ok"))

    # 1. httpx with -rl 2, -timeout 10, -retries 2
    cfg_http = es.ExternalScannerConfig(enabled=True)
    es.HttpxScannerAdapter(cfg_http).run(
        "http://127.0.0.1:8080",
        authorized=True,
        extra_flags=["-rl", "2", "-timeout", "10", "-retries", "2"],
    )
    httpx_argv = recorded[-1]
    assert sum(1 for t in httpx_argv if t in ("-rl", "-rate-limit") or t.startswith(("-rl=", "-rate-limit="))) == 1
    assert httpx_argv.count("-timeout") == 1
    assert httpx_argv.count("-retries") == 1

    # 2. katana with -rl=2, -depth=1, -crawl-duration=5, -timeout=10
    cfg_kat = es.ExternalScannerConfig(enabled=True)
    es.KatanaScannerAdapter(cfg_kat).run(
        "http://127.0.0.1:8080",
        authorized=True,
        extra_flags=["-rl=2", "-depth=1", "-crawl-duration=5", "-timeout=10"],
    )
    kat_argv = recorded[-1]
    assert sum(1 for t in kat_argv if t in ("-rl", "-rate-limit") or t.startswith(("-rl=", "-rate-limit="))) == 1
    assert kat_argv.count("-depth") == 1
    assert kat_argv.count("-crawl-duration") == 1
    assert kat_argv.count("-timeout") == 1

    # 3. nuclei with -rate-limit 2 (alias of -rl)
    cfg_nuc = es.ExternalScannerConfig(enabled=True)
    es.NucleiScannerAdapter(cfg_nuc).run(
        "http://127.0.0.1:8080",
        authorized=True,
        extra_flags=["-rate-limit", "2"],
    )
    nuc_argv = recorded[-1]
    assert sum(1 for t in nuc_argv if t in ("-rl", "-rate-limit") or t.startswith(("-rl=", "-rate-limit="))) == 1

    # 4. docker mode preserves single-emission invariant
    cfg_doc = es.ExternalScannerConfig(
        enabled=True,
        execution_mode="docker",
        docker_image="projectdiscovery/httpx:latest",
    )
    es.HttpxScannerAdapter(cfg_doc).run(
        "http://127.0.0.1:8080",
        authorized=True,
        extra_flags=["-rl", "2", "-timeout", "10", "-retries", "2"],
    )
    doc_argv = recorded[-1]
    assert sum(1 for t in doc_argv if t in ("-rl", "-rate-limit") or t.startswith(("-rl=", "-rate-limit="))) == 1
    assert doc_argv.count("-timeout") == 1
    assert doc_argv.count("-retries") == 1

    # 5. -rl=N and -rate-limit=N ceiling check
    for eq_flag in ("-rl=99", "-rate-limit=99"):
        cfg_eq = es.ExternalScannerConfig(enabled=True, rate_limit=5)
        with pytest.raises(ValueError, match="rate_limit"):
            es.HttpxScannerAdapter(cfg_eq).run(
                "http://127.0.0.1:8080", authorized=True, extra_flags=[eq_flag]
            )


def test_tier5_b2_mcp_artex_multitarget_host_port_scoping(tmp_path: Path) -> None:
    db_path = str(tmp_path / "mt_scope.db")
    srv = TerminatorMCPServer(db_path=db_path)
    try:
        TargetAuthorizationGate.authorize_target("127.0.0.1")
        r1_resp = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "artex_run_attack_chain",
                "arguments": {
                    "host": "127.0.0.1",
                    "port": 18001,
                    "endpoints": ["/target-a-ep"],
                    "ai_sinks": [],
                    "hydrate_db": False,
                    "rounds": 1,
                    "reports_dir": str(tmp_path / "rep_a"),
                },
            },
        })
        assert "result" in r1_resp

        r2_resp = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "artex_run_attack_chain",
                "arguments": {
                    "host": "127.0.0.1",
                    "port": 18002,
                    "hydrate_db": True,
                    "rounds": 1,
                    "reports_dir": str(tmp_path / "rep_b"),
                },
            },
        })
        assert "result" in r2_resp

        assets = srv.db.get_dual_graph_nodes(graph_type="ASSET")
        b_eps = [
            a for a in assets
            if a["node_type"] == "ENDPOINT"
            and (a.get("attributes") or {}).get("host") == "127.0.0.1"
            and int((a.get("attributes") or {}).get("port") or 0) == 18002
        ]
        assert len(b_eps) >= 1, f"Target B endpoints were suppressed by Target A: {assets}"
    finally:
        srv.close()


def test_tier5_b3_auth_gate_thread_isolation_and_no_cross_scope_clobber() -> None:
    t_mcp = "mcp-thread-a.example.com"
    t_other_mcp = "mcp-thread-b.example.com"
    t_cli = "cli-perm.example.com"

    try:
        entered = threading.Event()
        proceed = threading.Event()
        observed: Dict[str, Any] = {}

        def worker_a() -> None:
            with TargetAuthorizationGate.mcp_request_scope(authorized_request=True):
                TargetAuthorizationGate.authorize_target(t_mcp)
                entered.set()
                proceed.wait(timeout=5.0)

        th = threading.Thread(target=worker_a)
        th.start()
        assert entered.wait(timeout=5.0)

        try:
            # 1. Outside mcp_request_scope must NOT see t_mcp
            assert t_mcp not in TargetAuthorizationGate.get_allowed_targets()

            # 2. Concurrent authorized MCP scope on another thread must NOT see t_mcp
            with TargetAuthorizationGate.mcp_request_scope(authorized_request=True):
                TargetAuthorizationGate.authorize_target(t_other_mcp)
                observed["concurrent_sees_a"] = t_mcp in TargetAuthorizationGate.get_allowed_targets()

            # 3. Outside authorize_target while worker_a is inside scope must persist in ALLOWED_TARGETS
            TargetAuthorizationGate.authorize_target(t_cli)
        finally:
            proceed.set()
            th.join(timeout=5.0)

        assert observed["concurrent_sees_a"] is False
        assert t_mcp not in TargetAuthorizationGate.get_allowed_targets()
        assert t_cli in TargetAuthorizationGate.get_allowed_targets()
    finally:
        TargetAuthorizationGate.ALLOWED_TARGETS.discard(t_mcp)
        TargetAuthorizationGate.ALLOWED_TARGETS.discard(t_other_mcp)
        TargetAuthorizationGate.ALLOWED_TARGETS.discard(t_cli)


def test_tier5_b4_advisory_filename_prefix_parity(tmp_path: Path) -> None:
    db_path = str(tmp_path / "adv.db")
    srv = TerminatorMCPServer(db_path=db_path)
    try:
        srv.db.save_attack_chain(
            chain_id="CHAIN-T5-1",
            title="Desync Chain T5",
            attack_type="DESYNC_CHAIN",
            target_host="127.0.0.1",
            target_endpoint="/api",
            steps=[{"step": 1, "desc": "Probe"}],
            is_verified=True,
            severity="HIGH",
            task_id="TASK-T5",
            poe_level=2,
            evidence_quote="Confirmed",
            hop_count=2,
        )
        out_dir = tmp_path / "advisories"
        resp = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "artex_export_advisory",
                "arguments": {"chain_id": "CHAIN-T5-1", "output_dir": str(out_dir)},
            },
        })
        payload = json.loads(resp["result"]["content"][0]["text"])
        assert payload["advisories_exported"] == 1
        md_files = sorted(p.name for p in out_dir.glob("*.md"))
        assert md_files == ["advisory_CHAIN-T5-1.md"]
    finally:
        srv.close()


def test_tier5_b5_cli_budget_port_clean_db_and_docker_parity(tmp_path: Path) -> None:
    root = str(Path(__file__).resolve().parent.parent)
    env = {**os.environ, "CI": "true", "RFCHUNT_OFFLINE": "1", "PYTHONPATH": root}

    # 1. Negative artex-budget-turns, artex-intent-turns, artex-intent-tokens parity in main.py all, rfc_hunt_swarm.py --all, and run_unified_all_scans
    for neg_flag in ("--artex-budget-turns", "--artex-intent-turns", "--artex-intent-tokens"):
        p_main = subprocess.run(
            [sys.executable, "main.py", "all", "--db", str(tmp_path / "m.db"), "--host", "127.0.0.1", neg_flag, "-1"],
            cwd=root, env=env, capture_output=True, text=True, timeout=30,
        )
        assert p_main.returncode == 1, f"main.py all failed to exit 1 on {neg_flag}=-1"

        p_swarm = subprocess.run(
            [sys.executable, "rfc_hunt_swarm.py", "--all", "--db", str(tmp_path / "s.db"), "--host", "127.0.0.1", neg_flag, "-1"],
            cwd=root, env=env, capture_output=True, text=True, timeout=30,
        )
        assert p_swarm.returncode == 1, f"rfc_hunt_swarm.py --all failed to exit 1 on {neg_flag}=-1"

    with pytest.raises(ValueError, match="artex_budget_turns"):
        run_unified_all_scans(
            host="127.0.0.1",
            authorized=True,
            artex_budget_turns=-1,
            reports_dir=str(tmp_path / "rep_neg"),
            quiet=True,
        )

    # 2. main.py scanner http://127.0.0.1 (no --port) -> http://127.0.0.1:80; bare 127.0.0.1 -> https://127.0.0.1:443
    p_http = subprocess.run(
        [sys.executable, "main.py", "scanner", "--db", str(tmp_path / "sc1.db"), "--host", "http://127.0.0.1", "--json"],
        cwd=root, env=env, capture_output=True, text=True, timeout=30,
    )
    assert p_http.returncode == 0, p_http.stderr
    assert json.loads(p_http.stdout)["target"] == "http://127.0.0.1:80"

    p_bare = subprocess.run(
        [sys.executable, "main.py", "scanner", "--db", str(tmp_path / "sc2.db"), "--host", "127.0.0.1", "--json"],
        cwd=root, env=env, capture_output=True, text=True, timeout=30,
    )
    assert p_bare.returncode == 0, p_bare.stderr
    assert json.loads(p_bare.stdout)["target"] == "https://127.0.0.1:443"

    # 3. rfc_hunt_swarm.py --clean-db --all does NOT skip --all
    rep_clean = tmp_path / "rep_clean_all"
    p_clean_all = subprocess.run(
        [
            sys.executable, "rfc_hunt_swarm.py",
            "--clean-db", "--all",
            "--db", str(tmp_path / "clean_all.db"),
            "--repo", str(tmp_path),
            "--output-dir", str(rep_clean),
            "--json",
        ],
        cwd=root, env=env, capture_output=True, text=True, timeout=60,
    )
    assert p_clean_all.returncode == 0, p_clean_all.stderr
    clean_payload = json.loads(p_clean_all.stdout)
    assert clean_payload["mode"] == "unified_all_scans"
    assert Path(clean_payload["report_files"]["combined_sarif"]).is_file()

    # 4. --docker-image / --docker-network signature parity
    sig_all = inspect.signature(run_unified_all_scans)
    assert "docker_image" in sig_all.parameters
    assert "docker_network" in sig_all.parameters


def test_tier5_b6_discovery_docker_image_multitool_and_single_adapter_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: List[List[str]] = []

    class _FakeCompleted:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(es.subprocess, "run", lambda argv, **kw: recorded.append(list(argv)) or _FakeCompleted())
    monkeypatch.setattr(es, "_resolve_host_binary", lambda bp, tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(es, "validate_and_authorize_target", lambda host, **kw: (True, "ok"))

    cfg = es.ExternalScannerConfig(
        enabled=True,
        execution_mode="docker",
        docker_image="projectdiscovery/httpx:latest",
        docker_network="none",
    )
    res = es.run_opt_in_external_discovery(
        "http://127.0.0.1:8080",
        config=cfg,
        authorized=True,
        run_httpx=True,
        run_katana=True,
    )
    assert res["ok"] is True
    assert len(recorded) == 2
    assert "projectdiscovery/httpx:latest" in recorded[0]
    assert es.DEFAULT_DOCKER_IMAGES["katana"] in recorded[1]
    assert "--network" in recorded[0] and "none" in recorded[0]

    # Single-adapter mismatch MUST still raise ValueError
    with pytest.raises(ValueError, match="does not match adapter tool"):
        es.HttpxScannerAdapter(
            es.ExternalScannerConfig(
                enabled=True,
                execution_mode="docker",
                docker_image="projectdiscovery/nuclei:latest",
            )
        )

    # Discovery with nuclei-only image MUST still raise ValueError
    with pytest.raises(ValueError, match="does not match adapter tool"):
        es.run_opt_in_external_discovery(
            "http://127.0.0.1:8080",
            config=es.ExternalScannerConfig(
                enabled=True,
                execution_mode="docker",
                docker_image="projectdiscovery/nuclei:latest",
            ),
            authorized=True,
            run_httpx=True,
            run_katana=True,
        )


# =============================================================================
# Category B — Coverage Gaps Across MCP, cli_render, external_scanners, Ledger
# =============================================================================


def test_tier5_gap_mcp_edge_cases_and_http_batch(tmp_path: Path) -> None:
    srv = TerminatorMCPServer(db_path=str(tmp_path / "mcp_edge.db"))
    http_srv = MCPHttpServer(srv, host="127.0.0.1", port=0)
    host, port = http_srv.start()
    try:
        # 1. Missing chain_id in artex_retest_chain -> -32602 Invalid parameter (not -32000)
        resp_miss = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "artex_retest_chain", "arguments": {}},
        })
        assert resp_miss["error"]["code"] == -32602

        # 2. Blank targets=" , " in run_all_scans hits rate limit AND returns -32602
        TargetAuthorizationGate._request_history.clear()
        resp_blank = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "run_all_scans", "arguments": {"targets": " , "}},
        })
        assert resp_blank["error"]["code"] == -32602
        assert len(TargetAuthorizationGate._request_history.get("default", [])) == 1

        # 3. HTTP empty batch [] -> 400 JSON-RPC -32600; invalid batch [123] -> 200 [{"error": -32600}]
        req_empty = urllib.request.Request(
            f"http://{host}:{port}/http",
            data=b"[]",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_empty, timeout=5.0)
        assert exc_info.value.code == 400
        err_body = json.loads(exc_info.value.read().decode("utf-8"))
        assert err_body["error"]["code"] == -32600

        req_bad_elem = urllib.request.Request(
            f"http://{host}:{port}/http",
            data=b"[123]",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_bad_elem, timeout=5.0) as r_bad:
            assert r_bad.status == 200
            bad_body = json.loads(r_bad.read().decode("utf-8"))
            assert isinstance(bad_body, list) and bad_body[0]["error"]["code"] == -32600

        # Valid notification batch still returns 202
        req_notif = urllib.request.Request(
            f"http://{host}:{port}/http",
            data=json.dumps([{"jsonrpc": "2.0", "method": "notifications/initialized"}]).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_notif, timeout=5.0) as r_notif:
            assert r_notif.status == 202
    finally:
        http_srv.stop()
        srv.close()


def test_tier5_gap_cli_render_rich_tty_as_json_live_progress_and_non_str_safety(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 1. as_json=True across all renderers
    sample_chains = [{"chain_id": "C1", "summary": 12345, "steps": ["s1"], "confidence": 0.9}]
    cli_render.render_chains(sample_chains, as_json=True)
    assert json.loads(capsys.readouterr().out) == sample_chains

    cli_render.render_traces(sample_chains, as_json=True)
    assert json.loads(capsys.readouterr().out) == sample_chains

    cov = {"total_in_scope_assets": 4, "tested_assets": 2, "untested_assets": 2, "coverage_pct": 50.0}
    cli_render.render_coverage(cov, as_json=True)
    assert json.loads(capsys.readouterr().out) == cov

    retests = [{"retest_id": "R1", "chain_id": "C1", "verdict": "FIXED", "summary": {"nested": 1}}]
    cli_render.render_retest_results(retests, as_json=True)
    assert json.loads(capsys.readouterr().out) == retests

    poe_bd = {"VERIFIED_EXPLOIT": 1, "ACTIVE_INDICATOR": 0, "PASSIVE_CORRELATION": 0, "NONE": 0}
    cli_render.render_poe_summary(poe_bd, coverage=cov, chains=sample_chains, traces=sample_chains, as_json=True)
    poe_json = json.loads(capsys.readouterr().out)
    assert poe_json["poe_breakdown"] == poe_bd

    # 2. Non-string summary must not crash ASCII table render
    monkeypatch.setattr(cli_render, "_use_rich", lambda plain=False: False)
    cli_render.render_traces([{"trace_id": "T1", "summary": 99999}])
    assert "T1" in capsys.readouterr().out
    cli_render.render_retest_results([{"retest_id": "R1", "chain_id": "C1", "verdict": "OK", "summary": 12345}])
    assert "R1" in capsys.readouterr().out

    # 3. Non-TTY LiveScanProgress lifecycle
    with cli_render.LiveScanProgress("tier5", plain=True) as prog:
        prog.update("step1", "OK", "detail1")
        prog.update("step2", "DONE", "detail2")
    out_prog = capsys.readouterr().out
    assert "step1" in out_prog and "step2" in out_prog

    # 4. Rich TTY branch with fake Console & Live
    if cli_render._RICH_AVAILABLE:
        monkeypatch.setattr(cli_render, "_use_rich", lambda plain=False: not plain)
        printed: List[Any] = []
        buf = io.StringIO()

        class _FakeConsole:
            def print(self, obj: Any) -> None:
                printed.append(obj)

        class _FakeLive:
            def __init__(self, *a: Any, **kw: Any) -> None:
                pass

            def __enter__(self) -> "_FakeLive":
                return self

            def update(self, tbl: Any) -> None:
                buf.write("live_update\n")

            def __exit__(self, *a: Any) -> None:
                pass

        monkeypatch.setattr(cli_render, "Console", _FakeConsole)
        monkeypatch.setattr(cli_render, "Live", _FakeLive)
        cli_render.render_poe_summary(poe_bd, coverage=cov, chains=sample_chains, traces=[{"trace_id": "T1", "summary": 777}])
        assert len(printed) >= 3
        with cli_render.LiveScanProgress("tier5-tty", plain=False) as lprog:
            lprog.update("phase", "RUN", "ok")
        assert "live_update" in buf.getvalue()


def test_tier5_gap_external_scanners_oserror_jsonl_classify_dedup_and_discovery_statuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(es, "_resolve_host_binary", lambda bp, tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(es, "validate_and_authorize_target", lambda host, **kw: (True, "ok"))

    # 1. Non-FileNotFoundError OSError -> status="error"
    def _raise_perm(*a: Any, **kw: Any) -> Any:
        raise PermissionError("access denied")

    monkeypatch.setattr(es.subprocess, "run", _raise_perm)
    res_err = es.HttpxScannerAdapter(es.ExternalScannerConfig(enabled=True)).run("http://127.0.0.1:8080", authorized=True)
    assert res_err.status == "error" and res_err.ok is False and "access denied" in res_err.error

    # 2. Httpx failed=True skip and rec["a"] / rec["host"] IP fallback
    httpx_jsonl = "\n".join([
        json.dumps({"url": "http://127.0.0.1:8080/dead", "failed": True}),
        json.dumps({"url": "http://127.0.0.1:8080/live-a", "status_code": 200, "a": ["127.0.0.1"]}),
        json.dumps({"url": "http://127.0.0.1:8080/live-h", "status_code": 200, "host": "127.0.0.1"}),
    ])

    class _Proc:
        def __init__(self, stdout: str, rc: int = 0) -> None:
            self.returncode = rc
            self.stdout = stdout
            self.stderr = ""

    monkeypatch.setattr(es.subprocess, "run", lambda argv, **kw: _Proc(httpx_jsonl))
    ag = AssetGraph()
    res_hx = es.HttpxScannerAdapter(es.ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=ag
    )
    assert res_hx.ok is True
    assert not any("/dead" in ep for ep in res_hx.endpoints_discovered)
    assert any("/live-a" in ep for ep in res_hx.endpoints_discovered)
    assert any("/live-h" in ep for ep in res_hx.endpoints_discovered)

    # 3. _classify_nuclei_capability branches
    assert es._classify_nuclei_capability(
        probe_dict={"rule_id": "R1", "title": "CL.TE Request Smuggling", "description": "", "evidence": ""},
        tags=["http"], cwe_str="CWE-444", cve_str="", severity="HIGH"
    ) == "DESYNC"
    assert es._classify_nuclei_capability(
        probe_dict={"rule_id": "R2", "title": "Outdated Lib", "description": "", "evidence": ""},
        tags=["cve"], cwe_str="", cve_str="CVE-2024-0001", severity="MEDIUM"
    ) == "SUPPLY_CHAIN"
    assert es._classify_nuclei_capability(
        probe_dict={"rule_id": "R3", "title": "Weak Cipher", "description": "", "evidence": ""},
        tags=["tls"], cwe_str="", cve_str="", severity="LOW"
    ) == "CRYPTO_WEAK"
    assert es._classify_nuclei_capability(
        probe_dict={"rule_id": "R4", "title": "Open Cors", "description": "", "evidence": ""},
        tags=["misconfig"], cwe_str="", cve_str="", severity="MEDIUM"
    ) == "MISCONFIG"

    # 4. Nuclei intra-batch seen_batch deduplication & valid extra_flags
    dup_rec = json.dumps({
        "template-id": "hdr-check",
        "matched-at": "http://127.0.0.1:8080/api",
        "matcher-name": "m1",
        "info": {"name": "Missing Header", "severity": "low", "tags": ["headers"]},
    })
    monkeypatch.setattr(es.subprocess, "run", lambda argv, **kw: _Proc(f"{dup_rec}\n{dup_rec}\n"))
    eng = DualGraphAttackEngine()
    res_nuc = es.NucleiScannerAdapter(es.ExternalScannerConfig(enabled=True, rate_limit=5)).run(
        "http://127.0.0.1:8080",
        authorized=True,
        dual_graph_engine=eng,
        extra_flags=["-threads", "4", "-tags", "headers", "-s=low", "-rl", "2"],
    )
    assert res_nuc.ok is True
    assert len(res_nuc.findings) == 1 and res_nuc.findings_ingested == 1

    # 5. run_opt_in_external_discovery disabled-both and partial status
    res_none = es.run_opt_in_external_discovery(
        "http://127.0.0.1:8080",
        config=es.ExternalScannerConfig(enabled=True),
        authorized=True,
        run_httpx=False,
        run_katana=False,
    )
    assert res_none["status"] == "completed" and res_none["endpoints_added"] == 0

    call_idx = {"i": 0}

    def _partial_run(argv: List[str], **kw: Any) -> _Proc:
        call_idx["i"] += 1
        if call_idx["i"] == 1:
            return _Proc(json.dumps({"url": "http://127.0.0.1:8080/p1", "status_code": 200}), rc=0)
        return _Proc("", rc=2)

    monkeypatch.setattr(es.subprocess, "run", _partial_run)
    res_partial = es.run_opt_in_external_discovery(
        "http://127.0.0.1:8080",
        config=es.ExternalScannerConfig(enabled=True),
        authorized=True,
        run_httpx=True,
        run_katana=True,
    )
    assert res_partial["status"] == "partial" and res_partial["ok"] is True


# =============================================================================
# Category C — Preserved Contracts (DO NOT BREAK)
# =============================================================================


def test_tier5_c_preserved_dns_fail_closed_approval_and_url_contracts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # 1. validate_target_host & validate_and_authorize_target fail-closed on DNS failure
    ok_host, reason_host = validate_target_host("offline-unresolvable.example.invalid", allow_private=False)
    assert ok_host is False and "DNS resolution failed" in reason_host
    ok_auth, _ = validate_and_authorize_target("offline-unresolvable.example.invalid", authorized=True, allow_private=False)
    assert ok_auth is False

    # While TargetAuthorizationGate.authorize_target permits offline domain registration
    TargetAuthorizationGate.authorize_target("offline-unresolvable.example.invalid")
    assert TargetAuthorizationGate.validate_target("offline-unresolvable.example.invalid")[0] is True

    # 2. ApprovalGate exact_host trailing dot and bracketed IPv6 matching
    g_v4 = ApprovalGate(mode="policy", rules=[ApprovalRule("R1", "exact_host", "DENY", "127.0.0.1")])
    assert g_v4.check(action_type="network_socket", target="http://127.0.0.1./x").approved is False
    g_v6 = ApprovalGate(mode="policy", rules=[ApprovalRule("R2", "exact_host", "DENY", "::1")])
    assert g_v6.check(action_type="network_socket", target="http://[::1]:8000/x").approved is False

    # 3. artex_bridge._validate_endpoint_url backslash authority SSRF rejection
    with pytest.raises(PermissionError):
        _validate_endpoint_url("http://127.0.0.1\\@169.254.169.254/", authorized=True)

    # 4. _parse_endpoint_url scheme-switch port accuracy & dot-segment preservation vs AssetGraph deny normalization
    p_http = es._parse_endpoint_url("http://127.0.0.1/./rel/../up", fallback_host="127.0.0.1")
    assert p_http is not None and p_http[1] == 80 and p_http[2] == "/./rel/../up"
    p_https = es._parse_endpoint_url("https://127.0.0.1/x", fallback_host="127.0.0.1", fallback_port=80)
    assert p_https is not None and p_https[1] == 443

    ag = AssetGraph(scope_hosts={"127.0.0.1"}, deny_routes=["/admin"])
    assert es._is_asset_graph_target_allowed(ag, "127.0.0.1", "/public/../admin/users", "127.0.0.1") is False

    # 5. CLI default port contracts (main.py & rfc_hunt_swarm.py)
    import main as main_mod
    import rfc_hunt_swarm as swarm_mod

    captured: List[Dict[str, Any]] = []
    monkeypatch.setattr(main_mod, "cmd_all", lambda a: captured.append({"fn": "all", "port": getattr(a, "port", None)}))
    monkeypatch.setattr(main_mod, "cmd_scanner", lambda a: captured.append({"fn": "scanner", "port": getattr(a, "port", None)}))
    monkeypatch.setattr(main_mod, "cmd_artex", lambda a: captured.append({"fn": "artex", "port": getattr(a, "port", None), "rounds": getattr(a, "artex_rounds", None)}))

    db_file = str(tmp_path / "c_ports.db")
    for argv_case, exp in [
        (["main.py", "--db", db_file, "--host", "127.0.0.1", "all"], {"fn": "all", "port": 443}),
        (["main.py", "--db", db_file, "--host", "127.0.0.1", "scanner"], {"fn": "scanner", "port": 443}),
        (["main.py", "--db", db_file, "--host", "127.0.0.1", "artex"], {"fn": "artex", "port": 8080, "rounds": 2}),
        (["main.py", "--db", db_file, "--host", "127.0.0.1", "artex-loop"], {"fn": "artex", "port": 8080, "rounds": 1}),
    ]:
        monkeypatch.setattr(sys, "argv", argv_case)
        main_mod.main()
        assert captured[-1] == exp

    import engine.mantis_integrator as mi_mod
    swarm_ports: List[Any] = []
    monkeypatch.setattr(
        mi_mod,
        "run_unified_all_scans",
        lambda **kw: swarm_ports.append(kw.get("port")) or {
            "elapsed_sec": 0.1,
            "fusion_enabled": True,
            "fusion_models": [],
            "total_aggregated_findings": 0,
            "severity_counts": {},
            "engines": {},
            "attack_chaining": {},
            "report_files": {"combined_sarif": "", "combined_json": ""},
        },
    )
    monkeypatch.setattr("engine.safe_network_validator.validate_and_authorize_target", lambda h, **kw: (True, "ok"))

    swarm_mod.main_swarm(["--all", "--db", db_file, "--host", "127.0.0.1", "--output-dir", str(tmp_path / "rep_sw1"), "--json"])
    assert swarm_ports[-1] == 5006
    swarm_mod.main_swarm(["--all", "--db", db_file, "--host", "example.com", "--authorized", "--output-dir", str(tmp_path / "rep_sw2"), "--json"])
    assert swarm_ports[-1] == 443
    swarm_mod.main_swarm(["--all", "--db", db_file, "--output-dir", str(tmp_path / "rep_sw3"), "--json"])
    assert swarm_ports[-1] is None


# =============================================================================
# Iteration 2 Hardening — G1–G3 & R2-1..R2-4 Regressions
# =============================================================================


@pytest.mark.parametrize(
    "cmd",
    [
        ["python", "-m", "unittest", "tools.sqlmap"],
        ["python", "-W", "ignore", "-m", "unittest", "tools.sqlmap"],
        ["python", "-m", "pydoc", "tools.sqlmap"],
        ["python", "-m", "doctest", "tools/sqlmap.py"],
        ["python", "-m", "trace", "-c", "import os"],
        ["docker", "run", "--rm", "python:3.11-slim", "-m", "unittest", "tools.sqlmap"],
        ["docker", "run", "--rm", "python:3.11-slim", "-m", "pydoc", "tools.sqlmap"],
        ["docker", "run", "--rm", "python:3.11-slim", "-m", "doctest", "tools/sqlmap.py"],
    ],
)
def test_tier5_g1_blocks_python_unittest_pydoc_doctest_runner_indirection(cmd: List[str]) -> None:
    ok, reason = ExecutionPolicy().validate_subprocess_command(cmd)
    assert ok is False, f"ExecutionPolicy failed to block {cmd!r}: {reason}"
    dec = ApprovalGate(mode="policy").check(action_type="subprocess_exec", target=" ".join(cmd), command=cmd)
    assert dec.approved is False, f"ApprovalGate failed to block {cmd!r}: {dec.reason}"


@pytest.mark.parametrize(
    "benign_cmd",
    [
        ["python", "-m", "pytest", "-q"],
        ["python", "-m", "http.server", "8080"],
        ["python", "-m", "unittest", "tests/test_ok.py"],
        ["python", "-m", "trace", "-C", "sqlmap_out", "tests/test_ok.py"],
        ["python", "scripts/benign_check.py"],
    ],
)
def test_tier5_g1_benign_python_runner_controls_allowed(benign_cmd: List[str]) -> None:
    ok, reason = ExecutionPolicy().validate_subprocess_command(benign_cmd)
    assert ok is True, f"ExecutionPolicy falsely blocked benign command {benign_cmd!r}: {reason}"


def test_tier5_g2_nat64_and_multicast_blocked_even_with_allow_private() -> None:
    assert is_cloud_metadata(ipaddress.ip_address("64:ff9b::169.254.169.254")) is True
    assert is_safe_target_ip("64:ff9b::169.254.169.254", allow_private=True) is False
    ok_nat64, _ = validate_target_host("64:ff9b::169.254.169.254", allow_private=True)
    assert ok_nat64 is False
    ok_mcast, _ = validate_target_host("::224.0.0.1", allow_private=True)
    assert ok_mcast is False
    assert is_safe_target_ip("64:ff9b::8.8.8.8", allow_private=False) is False
    # Control: ::1, 127.0.0.1, and RFC1918 remain allowed with allow_private=True
    assert validate_target_host("::1", allow_private=True)[0] is True
    assert validate_target_host("127.0.0.1", allow_private=True)[0] is True
    assert validate_target_host("10.0.0.1", allow_private=True)[0] is True


def test_tier5_g3_deterministic_harness_records_actual_http_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(TargetAuthorizationGate, "ALLOWED_TARGETS", {"127.0.0.1"})
    policy = ExecutionPolicy.get_instance()
    monkeypatch.setattr(policy, "allow_destructive", True)

    class _SpyHarness:
        def __init__(self, **kw: Any) -> None:
            pass

        def run_evaluation(self, payload: Any) -> Any:
            return False, None, "ok", {"anomalies": [], "baseline_resp": "HTTP/1.1 200 OK\r\n\r\n"}

    fake_mod = types.ModuleType("deterministic_harness")
    fake_mod.DeterministicHarness = _SpyHarness  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "deterministic_harness", fake_mod)

    reg = LiveWorkerExecutorRegistry(host="127.0.0.1", port=8000, authorized=True)
    res = reg._deterministic_harness_impl(
        route="/api/items/1",
        raw_request="PUT /api/items/1 HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
    )
    ex = reg.traffic_session.get_exchange(res["traffic_id"])
    assert ex is not None and ex.method == "PUT"


def test_tier5_r2_swarm_http_scanner_and_all_docker_forwarding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import main as main_mod
    import rfc_hunt_swarm as swarm_mod

    root = str(Path(__file__).resolve().parent.parent)
    env = {**os.environ, "CI": "true", "RFCHUNT_OFFLINE": "1", "PYTHONPATH": root}

    # 1. rfc_hunt_swarm.py scanner --host http://127.0.0.1 (no --port) -> http://127.0.0.1:80
    p_sw_http = subprocess.run(
        [sys.executable, "rfc_hunt_swarm.py", "scanner", "--db", str(tmp_path / "sw_http.db"), "--host", "http://127.0.0.1", "--json"],
        cwd=root, env=env, capture_output=True, text=True, timeout=30,
    )
    assert p_sw_http.returncode == 0, p_sw_http.stderr
    assert json.loads(p_sw_http.stdout)["target"] == "http://127.0.0.1:80"

    # Preserved contract: bare 127.0.0.1 -> https://127.0.0.1:443
    p_sw_bare = subprocess.run(
        [sys.executable, "rfc_hunt_swarm.py", "scanner", "--db", str(tmp_path / "sw_bare.db"), "--host", "127.0.0.1", "--json"],
        cwd=root, env=env, capture_output=True, text=True, timeout=30,
    )
    assert p_sw_bare.returncode == 0, p_sw_bare.stderr
    assert json.loads(p_sw_bare.stdout)["target"] == "https://127.0.0.1:443"

    # 1b. main.py all & rfc_hunt_swarm.py --all http://127.0.0.1 (no --port) -> 127.0.0.1:80
    p_main_all_http = subprocess.run(
        [sys.executable, "main.py", "all", "--db", str(tmp_path / "ma_http.db"), "--host", "http://127.0.0.1", "--output-dir", str(tmp_path / "rep_mah"), "--json"],
        cwd=root, env=env, capture_output=True, text=True, timeout=60,
    )
    assert p_main_all_http.returncode == 0, p_main_all_http.stderr
    assert json.loads(p_main_all_http.stdout)["target_path"] == "127.0.0.1:80"

    p_swarm_all_http = subprocess.run(
        [sys.executable, "rfc_hunt_swarm.py", "--all", "--db", str(tmp_path / "swa_http.db"), "--host", "http://127.0.0.1", "--output-dir", str(tmp_path / "rep_swah"), "--json"],
        cwd=root, env=env, capture_output=True, text=True, timeout=60,
    )
    assert p_swarm_all_http.returncode == 0, p_swarm_all_http.stderr
    assert json.loads(p_swarm_all_http.stdout)["target_path"] == "127.0.0.1:80"

    # Preserved bare defaults in main.py all (443) and rfc_hunt_swarm.py --all (5006)
    p_main_all_bare = subprocess.run(
        [sys.executable, "main.py", "all", "--db", str(tmp_path / "ma_bare.db"), "--host", "127.0.0.1", "--output-dir", str(tmp_path / "rep_mab"), "--json"],
        cwd=root, env=env, capture_output=True, text=True, timeout=60,
    )
    assert p_main_all_bare.returncode == 0, p_main_all_bare.stderr
    assert json.loads(p_main_all_bare.stdout)["target_path"] == "127.0.0.1:443"

    # 2. Runtime --docker-image + --docker-network forwarding across main.py all, rfc_hunt_swarm.py --all, and MCP run_all_scans
    recorded: List[List[str]] = []

    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(es.subprocess, "run", lambda argv, **kw: recorded.append(list(argv)) or _Proc())
    monkeypatch.setattr(es, "_resolve_host_binary", lambda bp, tool: f"/usr/bin/{tool}")

    # 2a. All-3 external scanners enabled with single httpx docker_image must NOT crash on nuclei
    res_all = run_unified_all_scans(
        host="127.0.0.1",
        port=8080,
        use_tls=False,
        authorized=True,
        reports_dir=str(tmp_path / "rep_all_doc"),
        quiet=True,
        enable_external_scanners=True,
        scanner_isolation="docker",
        docker_image="projectdiscovery/httpx:v1.6.0",
        docker_network="none",
    )
    assert len(recorded) == 3
    assert "projectdiscovery/httpx:v1.6.0" in recorded[0]
    assert es.DEFAULT_DOCKER_IMAGES["katana"] in recorded[1]
    assert es.DEFAULT_DOCKER_IMAGES["nuclei"] in recorded[2]
    assert all("--network" in argv and "none" in argv for argv in recorded)
    assert res_all["engines"]["external_discovery"]["execution_mode"] == "docker"

    # 2a-ii. Single-tool mismatch on nuclei-only must still raise ValueError
    with pytest.raises(ValueError, match="does not match adapter tool"):
        run_unified_all_scans(
            host="127.0.0.1",
            port=8080,
            use_tls=False,
            authorized=True,
            reports_dir=str(tmp_path / "rep_nuc_mismatch"),
            quiet=True,
            nuclei_scan=True,
            httpx_scan=False,
            katana_scan=False,
            scanner_isolation="docker",
            docker_image="projectdiscovery/httpx:v1.6.0",
        )

    # 2b. main.py all & rfc_hunt_swarm.py --all CLI arg forwarding
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py", "--db", str(tmp_path / "ma_doc.db"), "all",
            "--host", "127.0.0.1", "--port", "8080",
            "--httpx-scan", "--scanner-isolation", "docker",
            "--docker-image", "projectdiscovery/httpx:v1.6.0",
            "--docker-network", "none",
            "--output-dir", str(tmp_path / "rep_ma_doc"), "--json",
        ],
    )
    recorded.clear()
    main_mod.main()
    capsys.readouterr()
    assert len(recorded) == 1
    assert "projectdiscovery/httpx:v1.6.0" in recorded[0] and "--network" in recorded[0] and "none" in recorded[0]

    recorded.clear()
    swarm_mod.main_swarm([
        "--all", "--db", str(tmp_path / "sw_doc.db"),
        "--host", "127.0.0.1", "--port", "8080",
        "--httpx-scan", "--scanner-isolation", "docker",
        "--docker-image", "projectdiscovery/httpx:v1.6.0",
        "--docker-network", "none",
        "--output-dir", str(tmp_path / "rep_sw_doc"), "--json",
    ])
    capsys.readouterr()
    assert len(recorded) == 1
    assert "projectdiscovery/httpx:v1.6.0" in recorded[0] and "--network" in recorded[0] and "none" in recorded[0]

    # 2b-ii. main.py scanner all-3 external scanners with httpx docker_image
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py", "--db", str(tmp_path / "ms_doc.db"), "scanner",
            "--host", "http://127.0.0.1:8080",
            "--enable-external-scanners", "--scanner-isolation", "docker",
            "--docker-image", "projectdiscovery/httpx:v1.6.0",
            "--docker-network", "none", "--json",
        ],
    )
    recorded.clear()
    main_mod.main()
    capsys.readouterr()
    assert len(recorded) == 3
    assert "projectdiscovery/httpx:v1.6.0" in recorded[0]
    assert es.DEFAULT_DOCKER_IMAGES["katana"] in recorded[1]
    assert es.DEFAULT_DOCKER_IMAGES["nuclei"] in recorded[2]

    # 2c. MCP run_all_scans forwarding
    recorded.clear()
    srv = TerminatorMCPServer(db_path=str(tmp_path / "mcp_doc.db"))
    try:
        resp = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "run_all_scans",
                "arguments": {
                    "host": "127.0.0.1",
                    "port": 8080,
                    "tls": False,
                    "httpx_scan": True,
                    "scanner_isolation": "docker",
                    "docker_image": "projectdiscovery/httpx:v1.6.0",
                    "docker_network": "none",
                    "output_dir": str(tmp_path / "rep_mcp_doc"),
                },
            },
        })
        assert "result" in resp
        assert len(recorded) == 1
        assert "projectdiscovery/httpx:v1.6.0" in recorded[0] and "--network" in recorded[0] and "none" in recorded[0]
    finally:
        srv.close()


def test_tier5_r2_mcp_missing_ids_and_main_clean_db_all(tmp_path: Path) -> None:
    # 1. artex_get_worker_trace / artex_budget_status missing or empty required params -> -32602
    srv = TerminatorMCPServer(db_path=str(tmp_path / "mcp_r23.db"))
    try:
        for tool_name, bad_args in (
            ("artex_get_worker_trace", {}),
            ("artex_get_worker_trace", {"trace_id": "   "}),
            ("artex_budget_status", {}),
            ("artex_budget_status", {"task_id": ""}),
        ):
            resp = srv.handle_request({
                "jsonrpc": "2.0",
                "id": 101,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": bad_args},
            })
            assert resp["error"]["code"] == -32602, f"Expected -32602 for {tool_name}({bad_args}), got {resp}"
    finally:
        srv.close()

    # 2. main.py --clean-db --all closes DB cleanly before cmd_all and exits 0
    root = str(Path(__file__).resolve().parent.parent)
    env = {**os.environ, "CI": "true", "RFCHUNT_OFFLINE": "1", "PYTHONPATH": root}
    p_clean_all = subprocess.run(
        [
            sys.executable, "main.py",
            "--clean-db", "--all",
            "--db", str(tmp_path / "main_clean_all.db"),
            "--repo", str(tmp_path),
            "--output-dir", str(tmp_path / "rep_main_clean_all"),
            "--json",
        ],
        cwd=root, env=env, capture_output=True, text=True, timeout=60,
    )
    assert p_clean_all.returncode == 0, p_clean_all.stderr
    payload = json.loads(p_clean_all.stdout)
    assert payload["mode"] == "unified_all_scans"


def test_tier5_r2_auth_gate_nested_scope_and_exception_unwind() -> None:
    with TargetAuthorizationGate.mcp_request_scope(authorized_request=True):
        TargetAuthorizationGate.authorize_target("outer.example.com")
        assert "outer.example.com" in TargetAuthorizationGate.get_allowed_targets()
        with TargetAuthorizationGate.mcp_request_scope(authorized_request=False):
            assert "outer.example.com" not in TargetAuthorizationGate.get_allowed_targets()
            TargetAuthorizationGate.authorize_target("inner.example.com")
            assert "inner.example.com" not in TargetAuthorizationGate.get_allowed_targets()
        assert "outer.example.com" in TargetAuthorizationGate.get_allowed_targets()
        assert "inner.example.com" not in TargetAuthorizationGate.get_allowed_targets()
    assert "outer.example.com" not in TargetAuthorizationGate.get_allowed_targets()

    with pytest.raises(RuntimeError, match="boom"):
        with TargetAuthorizationGate.mcp_request_scope(authorized_request=True):
            TargetAuthorizationGate.authorize_target("exc.example.com")
            raise RuntimeError("boom")
    assert "exc.example.com" not in TargetAuthorizationGate.get_allowed_targets()


@pytest.mark.parametrize(
    "cmd",
    [
        ["python", "-m", "unittest", "-f", "tools.sqlmap"],
        ["python", "-m", "unittest", "-s", "tools.sqlmap"],
        ["python", "-m", "unittest", "-o", "tools.sqlmap"],
        ["python", "-m", "unittest", "-C", "tools.sqlmap"],
        ["python", "-m", "doctest", "-f", "tools/sqlmap.py"],
        ["python", "-m", "pydoc", "-f", "tools.sqlmap"],
        ["python", "-m", "trace", "-C", "outdir", "-m", "unittest", "-f", "tools.sqlmap"],
        ["docker", "run", "--rm", "python:3.11-slim", "-m", "unittest", "-f", "tools.sqlmap"],
        ["docker", "run", "--rm", "alpine", "-C", "id"],
        ["docker", "run", "--rm", "python:3.11-slim", "-m", "trace", "-c", "import os"],
        ["docker", "run", "--rm", "python:3.11-slim", "--command", "import os"],
    ],
)
def test_tier5_r3_1_blocks_python_runner_flag_value_confusion(cmd: List[str]) -> None:
    ok, reason = ExecutionPolicy().validate_subprocess_command(cmd)
    assert ok is False, f"ExecutionPolicy failed to block {cmd!r}: {reason}"
    dec = ApprovalGate(mode="policy").check(action_type="subprocess_exec", target=" ".join(cmd), command=cmd)
    assert dec.approved is False, f"ApprovalGate failed to block {cmd!r}: {dec.reason}"


@pytest.mark.parametrize(
    "cmd",
    [
        ["python", "-m", "trace", "-C", "sqlmap_out", "-m", "pytest"],
        ["python", "-m", "cProfile", "-o", "out.prof", "-m", "pytest"],
        ["docker", "run", "--rm", "python:3.11-slim", "-m", "trace", "-C", "outdir", "-m", "pytest"],
    ],
)
def test_tier5_r3_1_allows_legit_trace_cprofile_and_docker_trace_c(cmd: List[str]) -> None:
    ok, reason = ExecutionPolicy().validate_subprocess_command(cmd)
    assert ok is True, f"Expected {cmd!r} to be allowed, got: {reason}"
    dec = ApprovalGate(mode="policy").check(action_type="subprocess_exec", target=" ".join(cmd), command=cmd)
    assert dec.approved is True, f"Expected ApprovalGate to allow {cmd!r}: {dec.reason}"


def test_tier5_r3_2_ipv6_zone_id_cloud_metadata_blocked_even_with_allow_private() -> None:
    for meta_ip in ("fd00:ec2::254%eth0", "fd00:ec2::254%0", "fe80::1%eth0", "64:ff9b::169.254.169.254%eth0"):
        assert is_cloud_metadata(ipaddress.ip_address(meta_ip)) is True, meta_ip
        assert is_safe_target_ip(meta_ip, allow_private=True) is False, meta_ip
        ok_z, _ = validate_target_host(meta_ip, allow_private=True)
        assert ok_z is False, meta_ip
    assert validate_target_host("::1", allow_private=True)[0] is True
    assert is_safe_target_ip("::1%eth0", allow_private=True) is True
    assert validate_target_host("::1%eth0", allow_private=True)[0] is True


def test_tier5_r3_3_verify_desync_records_actual_http_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(TargetAuthorizationGate, "ALLOWED_TARGETS", {"127.0.0.1"})
    policy = ExecutionPolicy.get_instance()
    monkeypatch.setattr(policy, "allow_destructive", True)

    class _SpyHarness:
        def __init__(self, **kw: Any) -> None:
            pass

        def run_evaluation(self, payload: Any) -> Any:
            return True, "CL.TE", "confirmed", {"anomalies": [], "baseline_resp": "HTTP/1.1 200 OK\r\n\r\n"}

    fake_mod = types.ModuleType("deterministic_harness")
    fake_mod.DeterministicHarness = _SpyHarness  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "deterministic_harness", fake_mod)

    for verb in ("PUT", "DELETE", "PATCH", "TRACE"):
        reg = LiveWorkerExecutorRegistry(host="127.0.0.1", port=8000, authorized=True)
        _, _, _, meta = reg._verify_desync({
            "target_route": "/api/items/1",
            "raw_probe": f"{verb} /api/items/1 HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
        })
        ex = reg.traffic_session.get_exchange(meta["traffic_id"])
        assert ex is not None and ex.method == verb, f"Expected {verb}, got {ex.method if ex else None}"

    class _SpyHarnessNeg:
        def __init__(self, **kw: Any) -> None:
            pass

        def run_evaluation(self, payload: Any) -> Any:
            return False, None, "no desync", {"anomalies": [], "baseline_resp": "HTTP/1.1 200 OK\r\n\r\n"}

    fake_mod.DeterministicHarness = _SpyHarnessNeg  # type: ignore[attr-defined]
    reg_neg = LiveWorkerExecutorRegistry(host="127.0.0.1", port=8000, authorized=True)
    _, _, _, meta_neg = reg_neg._verify_desync({
        "target_route": "/api/items/1",
        "raw_probe": "DELETE /api/items/1 HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
    })
    ex_neg = reg_neg.traffic_session.get_exchange(meta_neg["traffic_id"])
    assert ex_neg is not None
    expected_last_method = LiveWorkerExecutorRegistry._parse_raw_http_method(ex_neg.request_body, default="GET")
    assert expected_last_method == "POST"
    assert ex_neg.method == expected_last_method


def test_tier5_r3_https_swarm_all_mcp_http_port_and_cli_render_markup_safety(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = str(Path(__file__).resolve().parent.parent)
    env = {**os.environ, "CI": "true", "RFCHUNT_OFFLINE": "1", "PYTHONPATH": root}

    # 1. rfc_hunt_swarm.py --all --host https://127.0.0.1 -> 127.0.0.1:443 (bare 127.0.0.1 stays 5006)
    p_sw_https = subprocess.run(
        [sys.executable, "rfc_hunt_swarm.py", "--all", "--db", str(tmp_path / "sw_https.db"), "--host", "https://127.0.0.1", "--output-dir", str(tmp_path / "rep_swh"), "--json"],
        cwd=root, env=env, capture_output=True, text=True, timeout=60,
    )
    assert p_sw_https.returncode == 0, p_sw_https.stderr
    assert json.loads(p_sw_https.stdout)["target_path"] == "127.0.0.1:443"

    p_sw_bare = subprocess.run(
        [sys.executable, "rfc_hunt_swarm.py", "--all", "--db", str(tmp_path / "sw_bare.db"), "--host", "127.0.0.1", "--output-dir", str(tmp_path / "rep_swb"), "--json"],
        cwd=root, env=env, capture_output=True, text=True, timeout=60,
    )
    assert p_sw_bare.returncode == 0, p_sw_bare.stderr
    assert json.loads(p_sw_bare.stdout)["target_path"] == "127.0.0.1:5006"

    # 2. run_unified_all_scans / MCP run_all_scans with http://127.0.0.1 (port=None) & --targets http://127.0.0.1 -> 80 (bare 127.0.0.1 stays 443)
    res_http = run_unified_all_scans(
        host="http://127.0.0.1",
        authorized=True,
        reports_dir=str(tmp_path / "rep_u_http"),
        quiet=True,
    )
    assert res_http["target_path"] == "127.0.0.1:80"

    res_bare = run_unified_all_scans(
        host="127.0.0.1",
        authorized=True,
        reports_dir=str(tmp_path / "rep_u_bare"),
        quiet=True,
    )
    assert res_bare["target_path"] == "127.0.0.1:443"

    res_targets = run_unified_all_scans(
        targets="http://127.0.0.1,http://localhost",
        authorized=True,
        reports_dir=str(tmp_path / "rep_u_targets"),
        quiet=True,
    )
    assert res_targets["target_path"] == "127.0.0.1:80"
    assert res_targets["engines"]["differential_oracle"]["targets"] == ["127.0.0.1:80", "localhost:80"]

    # 3. MCP run_all_scans(host="http://127.0.0.1") -> 80, external_* URL/port/TLS/IPv6 handling, limit validation -> -32602
    recorded: List[List[str]] = []

    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(es.subprocess, "run", lambda argv, **kw: recorded.append(list(argv)) or _Proc())
    monkeypatch.setattr(es, "_resolve_host_binary", lambda bp, tool: f"/usr/bin/{tool}")

    srv = TerminatorMCPServer(db_path=str(tmp_path / "mcp_r3.db"))
    try:
        r_all = srv.handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "run_all_scans", "arguments": {"host": "http://127.0.0.1", "output_dir": str(tmp_path / "rep_mcp_http")}},
        })
        assert json.loads(r_all["result"]["content"][0]["text"])["target_path"] == "127.0.0.1:80"

        for tool_name in ("external_httpx_discover", "external_katana_crawl", "external_nuclei_scan"):
            r_ext = srv.handle_request({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": tool_name, "arguments": {"host": "http://127.0.0.1/v1?q=1", "port": 8080, "enabled": True}},
            })
            assert "result" in r_ext, r_ext
            assert "http://127.0.0.1:8080/v1?q=1" in recorded[-1]

        r_v6 = srv.handle_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "external_httpx_discover", "arguments": {"host": "http://[::1]/v1", "port": 8080, "enabled": True}},
        })
        assert "result" in r_v6, r_v6
        assert "http://[::1]:8080/v1" in recorded[-1]

        r_tls = srv.handle_request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "external_httpx_discover", "arguments": {"host": "http://127.0.0.1/v1", "use_tls": True, "enabled": True}},
        })
        assert "result" in r_tls, r_tls
        assert "https://127.0.0.1/v1" in recorded[-1]

        for tname in ("artex_list_worker_traces", "artex_search_worker_traces", "artex_get_attack_chains", "artex_approval_history"):
            r_ok = srv.handle_request({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": tname, "arguments": {}},
            })
            assert "result" in r_ok, r_ok
            for bad_lim in (None, 0, -1, "10", True):
                r_lim = srv.handle_request({
                    "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                    "params": {"name": tname, "arguments": {"limit": bad_lim}},
                })
                assert r_lim["error"]["code"] == -32602, f"Expected -32602 for {tname} limit={bad_lim!r}, got {r_lim}"
    finally:
        srv.close()

    # 4. Rich TTY cli_render must escape brackets / closing tags instead of raising MarkupError
    if cli_render._RICH_AVAILABLE:
        from rich.console import Console
        sio = io.StringIO()
        con = Console(file=sio, force_terminal=True, no_color=True, width=120)
        monkeypatch.setattr(cli_render, "_use_rich", lambda plain=False: True)
        monkeypatch.setattr(cli_render, "Console", lambda *a, **kw: con)
        cli_render.render_kv_panel("Panel[/close]", {"Target[/k]": "http://[::1]:8080/[/close]", "Note": "[raw/tag]"})
        cli_render.render_table("Tbl[/close]", ["Col[/c]"], [["[/close]"], ["[raw/tag]"]])
        prog = cli_render.LiveScanProgress("Live[/close]", plain=False)
        prog.update("phase[/p]", "OK[/s]", "[/close] [raw/tag]")
        con.print(prog._build_table())
        rendered = sio.getvalue()
        assert "[/close]" in rendered and "[raw/tag]" in rendered
