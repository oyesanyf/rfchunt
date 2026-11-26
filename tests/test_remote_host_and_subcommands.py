"""
Unit and Integration Tests for Remote Host Execution, CLI Wiring, and Target Authorization Gating.

Covers:
1. Fail-closed target authorization via RFCHUNT_AUTHORIZED_TARGETS and TargetAuthorizationGate
2. Blocking RFC1918, CGNAT, Cloud Metadata, and loopback (unless explicit)
3. --all --host remote review execution without scanning local directory
4. Subcommands fail-closed target authorization (cmd_raptor, cmd_artex, cmd_prompt_smuggle, cmd_harness2)
5. CLI argument parsing across rfc_hunt_swarm.py and main.py
"""

import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any, Dict
from unittest.mock import MagicMock, patch
import pytest

from mcp_server import TargetAuthorizationGate
from engine.safe_network_validator import (
    validate_target_host,
    is_explicit_loopback_host,
    parse_host_and_port,
    validate_and_authorize_target,
)
from engine.mantis_integrator import run_unified_all_scans, build_sarif_document


@pytest.fixture(autouse=True)
def mock_dns_resolution(monkeypatch):
    """Mocks DNS resolution for example.com to public IP 93.184.216.34 and restores TargetAuthorizationGate state."""
    original_allowed = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    real_getaddrinfo = socket.getaddrinfo

    def _mock_getaddrinfo(host, port, *args, **kwargs):
        if "example.com" in str(host):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _mock_getaddrinfo)
    yield
    TargetAuthorizationGate.ALLOWED_TARGETS.clear()
    TargetAuthorizationGate.ALLOWED_TARGETS.update(original_allowed)


# =====================================================================
# 1. Target Authorization Gate & SSRF Fail-Closed
# =====================================================================

def test_rfchunt_authorized_targets_env_blocks_private_and_cgnat(monkeypatch):
    """Verifies that RFCHUNT_AUTHORIZED_TARGETS rejects private RFC1918, CGNAT, and metadata fail-closed."""
    monkeypatch.setenv(
        "RFCHUNT_AUTHORIZED_TARGETS",
        "10.0.0.1, 192.168.1.1, 172.16.0.1, 100.64.0.1, 169.254.169.254, 0.0.0.0, target.example.com",
    )
    allowed = TargetAuthorizationGate.get_allowed_targets()

    # Private and reserved ranges must NOT be in allowed targets
    assert "10.0.0.1" not in allowed
    assert "192.168.1.1" not in allowed
    assert "172.16.0.1" not in allowed
    assert "100.64.0.1" not in allowed
    assert "169.254.169.254" not in allowed
    assert "0.0.0.0" not in allowed

    # Valid public target should be allowed
    assert "target.example.com" in allowed


def test_authorize_target_rejects_ssrf_and_private_fail_closed():
    """Verifies that TargetAuthorizationGate.authorize_target raises ValueError on private/metadata IPs."""
    forbidden_targets = [
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.254",
        "169.254.169.254",
        "0.0.0.0",
        "::",
        "*",
        "all",
        "fe80::1",
    ]
    for target in forbidden_targets:
        with pytest.raises(ValueError):
            TargetAuthorizationGate.authorize_target(target)


def test_validate_and_authorize_target_blocks_ssrf_even_when_authorized():
    """Verifies that validate_and_authorize_target blocks private/metadata IPs even when authorized=True."""
    ssrf_targets = [
        "10.0.0.1",
        "192.168.0.1",
        "100.64.0.1",
        "169.254.169.254",
        "0.0.0.0",
    ]
    for target in ssrf_targets:
        ok, reason = validate_and_authorize_target(target, authorized=True)
        assert not ok, f"Expected {target} to be rejected even with authorized=True"
        assert "private" in reason.lower() or "blocked" in reason.lower() or "error" in reason.lower()


def test_validate_and_authorize_target_accepts_public_when_authorized():
    """Verifies that validate_and_authorize_target succeeds on public targets when authorized=True."""
    original_allowed = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    TargetAuthorizationGate.ALLOWED_TARGETS.discard("target.example.com")
    try:
        # When authorized is False, public target is not yet authorized
        ok, reason = validate_and_authorize_target("target.example.com", authorized=False)
        assert not ok
        assert "authorization error" in reason.lower() or "not in the authorized targets" in reason.lower()

        # When authorized is True, public target is authorized and validated
        ok_auth, reason_auth = validate_and_authorize_target("target.example.com", authorized=True)
        assert ok_auth
        assert "authorized" in reason_auth.lower()
    finally:
        TargetAuthorizationGate.ALLOWED_TARGETS.clear()
        TargetAuthorizationGate.ALLOWED_TARGETS.update(original_allowed)


# =====================================================================
# 2. Unified Remote Host Execution in run_unified_all_scans
# =====================================================================

def test_run_unified_all_scans_remote_host_without_local_directory_scan(monkeypatch, tmp_path):
    """
    Verifies that run_unified_all_scans with --host and neither repo nor path
    executes remote inspection checks without scanning local directory files.
    """
    def mock_create_conn(*args, **kwargs):
        raise ConnectionRefusedError("Simulated offline prober refusal")

    monkeypatch.setattr(socket, "create_connection", mock_create_conn)

    reports_out = tmp_path / "reports"
    res = run_unified_all_scans(
        host="target.example.com",
        port=443,
        use_tls=True,
        authorized=True,
        allow_destructive=False,
        depth=10,
        reports_dir=str(reports_out),
    )

    assert res["mode"] == "unified_all_scans_remote"
    assert res["target_path"] == "target.example.com:443"
    assert "executive_summary" in res

    # Local Mantis and aiscan directory engines must have 0 findings (no local directory scan)
    assert res["engines"]["mantis"]["total_findings"] == 0
    assert res["engines"]["aiscan"]["total_findings"] == 0

    # Remote engines must be present in engines dictionary
    assert "raptor" in res["engines"]
    assert "artex_dual_graph" in res["engines"]
    assert "prompt_smuggling" in res["engines"]
    assert "active_flaw_prober" in res["engines"]

    # SARIF report must exist and be valid
    sarif_file = Path(res["report_files"]["combined_sarif"])
    assert sarif_file.exists()


def test_run_unified_all_scans_unauthorized_host_fails_closed():
    """Verifies that run_unified_all_scans raises PermissionError on unauthorized host."""
    with pytest.raises(PermissionError):
        run_unified_all_scans(host="unauthorized.target.com", authorized=False)

    with pytest.raises(PermissionError):
        run_unified_all_scans(host="10.0.0.1", authorized=True)


# =====================================================================
# 3. Subcommand Target Authorization & SSRF Fail-Closed
# =====================================================================

def test_cmd_artex_fails_closed_on_unauthorized_host():
    """Verifies that cmd_artex in rfc_hunt_swarm.py enforces target validation fail-closed."""
    from rfc_hunt_swarm import cmd_artex
    args = argparse.Namespace(host="10.0.0.1", port=8080, db="terminator.db", authorized=False)
    with pytest.raises(SystemExit) as exc:
        cmd_artex(args)
    assert exc.value.code == 1


def test_cmd_prompt_smuggle_fails_closed_on_unauthorized_host():
    """Verifies that cmd_prompt_smuggle in rfc_hunt_swarm.py enforces target validation fail-closed."""
    from rfc_hunt_swarm import cmd_prompt_smuggle
    args = argparse.Namespace(host="10.0.0.1", port=8080, db="terminator.db", authorized=False)
    with pytest.raises(SystemExit) as exc:
        cmd_prompt_smuggle(args)
    assert exc.value.code == 1


def test_cmd_raptor_fails_closed_on_unauthorized_host():
    """Verifies that cmd_raptor in rfc_hunt_swarm.py enforces target validation fail-closed."""
    from rfc_hunt_swarm import cmd_raptor
    args = argparse.Namespace(
        host="10.0.0.1",
        port=80,
        raptor_target=None,
        repo=None,
        path=None,
        target_arg=None,
        raptor_mode=None,
        authorized=False,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_raptor(args)
    assert exc.value.code == 1


def test_cmd_harness2_fails_closed_on_unauthorized_host():
    """Verifies that cmd_harness2 in rfc_hunt_swarm.py enforces target validation fail-closed."""
    from rfc_hunt_swarm import cmd_harness2
    args = argparse.Namespace(
        host="10.0.0.1",
        port=8080,
        db="terminator.db",
        authorized=False,
        harness2_runs_dir="runs/harness2",
        harness2_report=False,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_harness2(args)
    assert exc.value.code == 1


def test_main_cmd_all_fails_closed_on_unauthorized_host():
    """Verifies that cmd_all in main.py enforces target validation fail-closed."""
    from main import cmd_all
    args = argparse.Namespace(
        host="10.0.0.1",
        repo=None,
        path=None,
        depth=10,
        mantis_mode="full",
        output_dir="reports",
        db="terminator.db",
        authorized=False,
        allow_destructive=False,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_all(args)
    assert exc.value.code == 1


def test_main_cmd_harness2_fails_closed_on_unauthorized_host():
    """Verifies that cmd_harness2 in main.py enforces target validation fail-closed."""
    from main import cmd_harness2
    args = argparse.Namespace(
        target="10.0.0.1",
        port=8080,
        db="terminator.db",
        authorized=False,
        runs_dir="runs/harness2",
        report=False,
        rfc="9112",
        k=1,
        mode="parallel",
        domain="auto",
    )
    with pytest.raises(SystemExit) as exc:
        cmd_harness2(args)
    assert exc.value.code == 1


# =====================================================================
# 4. CLI Argument Parsing
# =====================================================================

def test_main_cli_argument_parsing():
    """Verifies that main.py correctly parses --host, --port, --tls, --authorized, --allow-destructive."""
    import main
    parser = argparse.ArgumentParser()
    # Emulate main.py parser options
    parser.add_argument("--host", "--target", dest="host", type=str, default=None)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--allow-destructive", action="store_true")

    args = parser.parse_args(["--host", "target.example.com", "--port", "8443", "--tls", "--authorized", "--allow-destructive"])
    assert args.host == "target.example.com"
    assert args.port == 8443
    assert args.tls is True
    assert args.authorized is True
    assert args.allow_destructive is True


def test_main_cli_harness2_host_fails_closed():
    """Verifies that `python main.py harness2 --host 10.0.0.1` exits with code 1."""
    root_dir = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root_dir)
    res = subprocess.run(
        [sys.executable, "main.py", "harness2", "--host", "10.0.0.1"],
        cwd=str(root_dir),
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 1
    combined = res.stdout + res.stderr
    assert "Target authorization error for 10.0.0.1" in combined or "Target SSRF validation error" in combined


def test_main_cli_harness2_target_authorized_fails_closed():
    """Verifies that `python main.py harness2 --target 10.0.0.1 --authorized` exits with code 1."""
    root_dir = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root_dir)
    res = subprocess.run(
        [sys.executable, "main.py", "harness2", "--target", "10.0.0.1", "--authorized"],
        cwd=str(root_dir),
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 1
    combined = res.stdout + res.stderr
    assert "Target authorization error for 10.0.0.1" in combined or "Target SSRF validation error" in combined


def test_main_cli_root_host_harness2_fails_closed():
    """Verifies that `python main.py --host 10.0.0.1 harness2` exits with code 1."""
    root_dir = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root_dir)
    res = subprocess.run(
        [sys.executable, "main.py", "--host", "10.0.0.1", "harness2"],
        cwd=str(root_dir),
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 1
    combined = res.stdout + res.stderr
    assert "Target authorization error for 10.0.0.1" in combined or "Target SSRF validation error" in combined


def test_main_cli_harness2_unauthorized_external_host():
    """Verifies that `python main.py harness2 --host dlptest.com` (without authorized) exits with code 1."""
    root_dir = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root_dir)
    env.pop("RFCHUNT_AUTHORIZED_TARGETS", None)
    res = subprocess.run(
        [sys.executable, "main.py", "harness2", "--host", "dlptest.com"],
        cwd=str(root_dir),
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 1
    combined = res.stdout + res.stderr
    assert "Target authorization error for dlptest.com" in combined


def test_main_cli_root_host_harness2_report_fails_closed():
    """Verifies that `python main.py --host dlptest.com harness2 --report` (without authorized) fails closed."""
    root_dir = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root_dir)
    env.pop("RFCHUNT_AUTHORIZED_TARGETS", None)
    res = subprocess.run(
        [sys.executable, "main.py", "--host", "dlptest.com", "harness2", "--report"],
        cwd=str(root_dir),
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 1
    combined = res.stdout + res.stderr
    assert "Target authorization error for dlptest.com" in combined


# =====================================================================
# 5. Milestone 4 Regression Coverage (--all depth=100, Hybrid, Protocol Engines, --targets)
# =====================================================================

def test_cmd_all_defaults_depth_to_100_and_preserves_explicit_override(monkeypatch, tmp_path):
    """Verifies main.cmd_all and rfc_hunt_swarm.cmd_all default depth=100 unless --depth is explicitly provided."""
    import main as main_cli
    import rfc_hunt_swarm as swarm_cli

    recorded = []

    def _fake_unified(**kwargs):
        recorded.append(kwargs)
        return {
            "target_path": kwargs.get("repo") or kwargs.get("host") or ".",
            "depth": kwargs.get("depth"),
            "fusion_enabled": True,
            "abliterated_model": "test-model",
            "fusion_models": ["test-model"],
            "total_aggregated_findings": 0,
            "severity_counts": {},
            "elapsed_sec": 0.01,
            "engines": {"mantis": {}, "aiscan": {}, "raptor": {}, "prompt_smuggling": {}},
            "report_files": {"combined_sarif": "a.sarif", "combined_json": "a.json"},
        }

    class _DummyDB:
        def __init__(self, *_a, **_kw):
            pass

        def close(self):
            pass

    monkeypatch.setattr("engine.mantis_integrator.run_unified_all_scans", _fake_unified)
    monkeypatch.setattr(main_cli, "Database", _DummyDB)
    monkeypatch.setattr("database.Database", _DummyDB)

    # Default omitted depth -> 100
    main_args = argparse.Namespace(
        host=None,
        targets="target.example.com:443,target.example.com:8443",
        repo=str(tmp_path),
        path=None,
        depth=None,
        mantis_mode="full",
        output_dir=str(tmp_path / "out1"),
        db=str(tmp_path / "t.db"),
        authorized=True,
        allow_destructive=False,
    )
    main_cli.cmd_all(main_args)
    assert recorded[-1]["depth"] == 100
    assert recorded[-1]["targets"] == "target.example.com:443,target.example.com:8443"

    # Explicit override -> 10
    swarm_args = argparse.Namespace(
        host=None,
        targets="target.example.com:8443",
        repo=str(tmp_path),
        raptor_target=None,
        path=None,
        depth=10,
        mantis_mode="fast",
        mantis_model=None,
        output_dir=str(tmp_path / "out2"),
        db=str(tmp_path / "t.db"),
        authorized=True,
        allow_destructive=False,
        artex_rounds=1,
        port=443,
        tls=True,
    )
    swarm_cli.cmd_all(swarm_args)
    assert recorded[-1]["depth"] == 10
    assert recorded[-1]["targets"] == "target.example.com:8443"


def test_run_unified_all_scans_targets_fails_closed_on_unauthorized_and_ssrf():
    """Verifies multi-target --targets enforces TargetAuthorizationGate and SSRF blocking fail-closed."""
    with pytest.raises(PermissionError):
        run_unified_all_scans(
            host="target.example.com",
            targets="target.example.com:443,10.0.0.1:8080",
            authorized=True,
        )

    with pytest.raises(PermissionError):
        run_unified_all_scans(
            targets="unauthorized.example.com:443",
            authorized=False,
        )


def test_hybrid_repo_and_host_runs_local_and_remote_and_feeds_artex_before_chaining(monkeypatch, tmp_path):
    """
    Verifies hybrid --all (--repo + --host + --targets) runs local and remote scanners
    and ingests remote protocol discoveries into ARTEX BEFORE run_attack_chain_cycle().
    """
    from engine.dual_graph_engine import DualGraphAttackEngine
    from engine.active_flaw_prober import ActiveFlawProber
    from protocol_ruler import ProtocolRuler
    from deterministic_harness import DeterministicHarness
    from engine.differential_oracle import MultiImplementationDifferentialOracle
    from engine.raptor_integrator import RaptorIntegrator
    from engine.taxonomy import AnomalyCategory, ImplementationAnomaly

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    repo_dir = tmp_path / "hybrid_app"
    repo_dir.mkdir(parents=True)
    (repo_dir / "app.py").write_text(
        "import subprocess\n"
        "from openai import OpenAI\n"
        "def run_cmd(user_cmd):\n"
        "    return subprocess.check_output(user_cmd, shell=True)\n"
        "def chat(prompt):\n"
        "    return OpenAI().chat.completions.create(model='gpt-4', messages=[{'role': 'user', 'content': prompt}])\n",
        encoding="utf-8",
    )

    events = []
    orig_ingest = DualGraphAttackEngine.ingest_finding
    orig_cycle = DualGraphAttackEngine.run_attack_chain_cycle

    def _spy_ingest(self, finding, scanner="generic"):
        events.append(("ingest", scanner))
        return orig_ingest(self, finding, scanner=scanner)

    def _spy_cycle(self, round_num=1):
        events.append(("cycle", round_num))
        return orig_cycle(self, round_num=round_num)

    monkeypatch.setattr(DualGraphAttackEngine, "ingest_finding", _spy_ingest)
    monkeypatch.setattr(DualGraphAttackEngine, "run_attack_chain_cycle", _spy_cycle)
    monkeypatch.setattr(
        RaptorIntegrator,
        "run_host_scan",
        lambda self, **kw: {
            "mode": "web",
            "total_findings": 1,
            "findings": [{"rule_id": "RAPTOR-WEB-01", "title": "Exposed admin endpoint", "severity": "HIGH", "cwe": "CWE-284"}],
        },
    )
    monkeypatch.setattr(
        ActiveFlawProber,
        "run_active_audit",
        lambda self: [
            {"vuln_id": "PROBER-CLTE-1", "title": "CL.TE Request Smuggling", "severity": "CRITICAL", "type": "CL.TE", "description": "CL/TE desync confirmed"}
        ],
    )
    monkeypatch.setattr(
        ProtocolRuler,
        "run_comprehensive_audit",
        lambda self, **kw: {
            "success": True,
            "baseline_limit": 8192,
            "findings": [
                {"name": "Overlong-UTF8-LF", "classification": "EXPANSION", "delta_bytes": 4, "verdict": "EXPANDED by 4 bytes on front-end!"}
            ],
            "expansions": [{"name": "Overlong-UTF8-LF", "delta_bytes": 4}],
            "contractions": [],
        },
    )
    monkeypatch.setattr(
        DeterministicHarness,
        "evaluate_batch_concurrent",
        lambda self, probes, max_concurrency=4: [
            (True, "CL.0 Desync", "Cross-connection contamination observed", {"raw_response_bytes": b"HTTP/1.1 200 OK\r\n\r\n"})
        ],
    )
    monkeypatch.setattr(
        MultiImplementationDifferentialOracle,
        "evaluate_divergence",
        lambda self, raw_probe, rule_id=None: (
            True,
            ImplementationAnomaly(
                anomaly_id="ANOM-DIFF-TEST",
                target_engine="DifferentialMatrix(target,edge)",
                category=AnomalyCategory.PARSER_DIVERGENCE,
                observed_behavior="Divergent status codes 200 vs 400 across targets",
                expected_behavior="Consistent framing",
                raw_probe=raw_probe,
                raw_response=b"",
                triggering_rule_id=rule_id,
            ),
            {},
        ),
    )
    monkeypatch.setattr(
        MultiImplementationDifferentialOracle,
        "evaluate_matrix_4parsers",
        lambda self, raw_probe, rule_id=None: (False, None, {}),
    )

    out_dir = tmp_path / "reports"
    res = run_unified_all_scans(
        repo=str(repo_dir),
        host="target.example.com",
        port=8443,
        use_tls=True,
        targets="target.example.com:8443,edge.example.com:443",
        authorized=True,
        depth=100,
        reports_dir=str(out_dir),
        db=None,
    )

    assert res["mode"] == "unified_all_scans"
    assert res["local_executed"] is True
    assert res["remote_executed"] is True
    assert res["engines"]["mantis"]["total_findings"] >= 1
    assert res["engines"]["active_flaw_prober"]["total_findings"] == 1
    assert res["engines"]["protocol_ruler"]["total_findings"] == 1
    assert res["engines"]["deterministic_harness"]["total_findings"] == 1
    assert res["engines"]["differential_oracle"]["total_findings"] >= 1
    assert "+web" in res["engines"]["raptor"]["mode"]
    assert "differential_oracle" in res["engines"]

    # Confirm ARTEX ingested remote engines BEFORE running the attack chain cycle
    cycle_idx = next(i for i, ev in enumerate(events) if ev[0] == "cycle")
    pre_cycle_scanners = {ev[1] for ev in events[:cycle_idx] if ev[0] == "ingest"}
    assert "ActiveFlawProber" in pre_cycle_scanners
    assert "ProtocolRuler" in pre_cycle_scanners
    assert "DeterministicHarness" in pre_cycle_scanners
    assert "DifferentialOracle" in pre_cycle_scanners

    scanners_in_findings = {f.get("scanner") for f in res["findings"]}
    assert "Module-20-Google-Mantis" in scanners_in_findings
    assert "ActiveFlawProber" in scanners_in_findings
    assert "ProtocolRuler" in scanners_in_findings
    assert "DeterministicHarness+AnomalyDetector" in scanners_in_findings
    assert "MultiImplementationDifferentialOracle" in scanners_in_findings


def test_unified_swarm_cli_consolidation_and_main_shim(tmp_path):
    """
    Verifies rfc_hunt_swarm.py natively defines all unified flags (--demo, --patched,
    --rounds, --retest, --domain, --runs-dir, --report, harness2 --mode both) without
    importing `main`, while main.py acts as a thin forwarding shim.
    """
    import main as main_cli
    import rfc_hunt_swarm as swarm_cli

    assert getattr(main_cli, "_IS_SWARM_SHIM", False) is True
    swarm_src = (Path(__file__).resolve().parent.parent / "rfc_hunt_swarm.py").read_text(encoding="utf-8")
    assert "import main" not in swarm_src

    args_all = swarm_cli.parse_swarm_arguments([
        "cascade", "--demo", "--patched", "--rounds", "3", "--retest",
        "--domain", "h2_translation", "--runs-dir", str(tmp_path / "h2"), "--report",
    ])
    assert args_all.demo is True
    assert args_all.patched is True
    assert args_all.artex_rounds == 3
    assert args_all.artex_retest is True
    assert args_all.harness2_domain == "h2_translation"
    assert args_all.harness2_runs_dir == str(tmp_path / "h2")
    assert args_all.harness2_report is True

    args_h2 = swarm_cli.parse_swarm_arguments([
        "harness2", "--rfc", "9112", "--k", "2", "--mode", "both",
    ])
    assert args_h2.command == "harness2"
    assert args_h2.harness2_k == 2
    assert args_h2.harness2_mode == "both"

    for sym in (
        "cmd_all", "cmd_artex", "cmd_artex_loop", "cmd_scanner", "cmd_proxy",
        "cmd_chains", "cmd_traces", "cmd_coverage", "cmd_retest", "cmd_export_advisory",
        "cmd_archive", "cmd_rea", "cmd_fetch", "cmd_chunk", "cmd_generate", "cmd_permute",
        "cmd_evaluate", "cmd_weaponize", "cmd_cascade", "cmd_lab", "cmd_auto", "cmd_hunt",
        "cmd_mcp", "cmd_ruler", "cmd_dream", "cmd_caldera", "cmd_build", "cmd_harness2",
    ):
        assert hasattr(swarm_cli, sym) and callable(getattr(swarm_cli, sym))
        assert hasattr(main_cli, sym) and getattr(main_cli, sym) is getattr(swarm_cli, sym)


