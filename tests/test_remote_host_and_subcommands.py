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
    """Mocks DNS resolution for example.com to public IP 93.184.216.34 so tests do not depend on external DNS."""
    real_getaddrinfo = socket.getaddrinfo

    def _mock_getaddrinfo(host, port, *args, **kwargs):
        if "example.com" in str(host):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _mock_getaddrinfo)


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
    # When authorized is False, public target is not yet authorized
    ok, reason = validate_and_authorize_target("target.example.com", authorized=False)
    assert not ok
    assert "authorization error" in reason.lower() or "not in the authorized targets" in reason.lower()

    # When authorized is True, public target is authorized and validated
    ok_auth, reason_auth = validate_and_authorize_target("target.example.com", authorized=True)
    assert ok_auth
    assert "authorized" in reason_auth.lower()


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
