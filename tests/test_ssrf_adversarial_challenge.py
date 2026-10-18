"""
Adversarial Challenge Test Suite: Mathematical SSRF Validation & Prober Fail-Closed Gating.
Author: Challenger M4-1 (SSRF Adversarial Fuzzing)
Milestone: M4 Adversarial Audit

Tests:
1. Dotted decimal, integer, hex, octal IP variations
2. IPv4-mapped IPv6 evasion representations
3. IPv6 Unique Local Address (ULA)
4. Cloud metadata / link-local endpoints
5. Carrier-Grade NAT (CGNAT RFC 6598)
6. Unspecified bind addresses (0.0.0.0, 0.0.0.0/8, ::)
7. Multi-record DNS rebinding / split-horizon DNS scenarios
8. CLI target rejection & non-auto-whitelisting verification
9. Empirical socket spy verification on all 5 raw socket probers
"""

import ipaddress
import socket
import subprocess
import sys
from typing import List
import pytest

from engine.safe_network_validator import (
    validate_target_host,
    is_safe_target_ip,
    is_cloud_metadata,
)
from mcp_server import TargetAuthorizationGate
from deterministic_harness import DeterministicHarness
from weaponizer import RQPWeaponizer
from engine.active_flaw_prober import ActiveFlawProber
from engine.differential_oracle import MultiImplementationDifferentialOracle, TargetEndpoint
from protocol_ruler import ProtocolRuler


# =====================================================================
# 1. Adversarial IP Representations & Encoding Variations
# =====================================================================

@pytest.mark.parametrize(
    "adversarial_target",
    [
        "0177.0.0.1",       # Octal representation of 127.0.0.1
        "0x7f.1",           # Mixed hex/decimal
        "2130706433",       # 32-bit integer representation of 127.0.0.1
        "0x7f000001",       # Full hex integer representation of 127.0.0.1
        "017700000001",     # Octal full integer
        "0x7f.0.0.1",       # Leading hex byte
        "0177.1",           # Octal first byte, 24-bit trailing
        "127.1",            # 2-part dotted decimal loopback
    ],
)
def test_ssrf_rejects_dotted_decimal_integer_hex_variations(adversarial_target):
    """
    Asserts that validate_target_host strictly rejects octal, hex, and integer
    IP representations without allowing them to resolve to loopback or bypass filtering.
    """
    is_safe, reason = validate_target_host(adversarial_target, allow_private=False)
    assert not is_safe, f"Adversarial representation '{adversarial_target}' unexpectedly passed validation!"
    assert len(reason) > 0, f"Expected rejection reason for '{adversarial_target}'"


@pytest.mark.parametrize(
    "mapped_target",
    [
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "::ffff:100.64.0.1",
        "[::ffff:127.0.0.1]",
        "[::ffff:169.254.169.254]",
        "::ffff:7f00:1",
        "::ffff:a9fe:a9fe",
        "::ffff:0a00:0001",
        "::ffff:6440:0001",
    ],
)
def test_ssrf_rejects_ipv4_mapped_ipv6_variations(mapped_target):
    """
    Asserts that IPv4-mapped IPv6 representations are strictly rejected under all
    conditions, even if allow_private=True.
    """
    is_safe_default, reason_default = validate_target_host(mapped_target, allow_private=False)
    assert not is_safe_default, f"IPv4-mapped target '{mapped_target}' passed with allow_private=False"

    is_safe_priv, reason_priv = validate_target_host(mapped_target, allow_private=True)
    assert not is_safe_priv, f"IPv4-mapped target '{mapped_target}' passed even with allow_private=True"
    assert "ipv4-mapped" in reason_priv.lower() or "metadata" in reason_priv.lower() or "blocked" in reason_priv.lower()


@pytest.mark.parametrize(
    "ula_target",
    [
        "fc00::1",
        "fd12:3456:789a::1",
        "fd00::1",
        "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ],
)
def test_ssrf_rejects_ipv6_ula(ula_target):
    """
    Asserts that IPv6 Unique Local Addresses (fc00::/7) are strictly rejected
    by default (allow_private=False).
    """
    is_safe, reason = validate_target_host(ula_target, allow_private=False)
    assert not is_safe, f"IPv6 ULA target '{ula_target}' unexpectedly passed validation"
    assert "private" in reason.lower() or "reserved" in reason.lower() or "blocked" in reason.lower()


@pytest.mark.parametrize(
    "metadata_target",
    [
        "169.254.169.254",
        "fe80::1",
        "fd00:ec2::254",
        "169.254.0.1",
        "169.254.254.254",
        "fe80::200:5aee:feaa:20a2",
        "http://169.254.169.254:80/latest/meta-data",
        "https://[fd00:ec2::254]:80",
        "http://[fe80::1]:80",
    ],
)
def test_ssrf_rejects_cloud_metadata_and_link_local(metadata_target):
    """
    Asserts that AWS/GCP/Azure IMDS and IPv4/IPv6 link-local addresses are rejected
    under both allow_private=False and allow_private=True.
    """
    ok_default, reason_def = validate_target_host(metadata_target, allow_private=False)
    assert not ok_default, f"Metadata target '{metadata_target}' passed allow_private=False"

    ok_priv, reason_priv = validate_target_host(metadata_target, allow_private=True)
    assert not ok_priv, f"Metadata target '{metadata_target}' passed allow_private=True"
    assert "metadata" in reason_priv.lower() or "link-local" in reason_priv.lower()


@pytest.mark.parametrize(
    "cgnat_target",
    [
        "100.64.0.1",
        "100.127.255.254",
        "100.64.0.0",
        "100.127.255.255",
        "100.80.12.34",
    ],
)
def test_ssrf_rejects_cgnat_shared_address_space(cgnat_target):
    """
    Asserts that Carrier-Grade NAT (100.64.0.0/10) addresses are strictly rejected
    by default.
    """
    is_safe, reason = validate_target_host(cgnat_target, allow_private=False)
    assert not is_safe, f"CGNAT target '{cgnat_target}' unexpectedly passed validation"


@pytest.mark.parametrize(
    "unspecified_target",
    [
        "0.0.0.0",
        "0.0.0.1",
        "0.1.2.3",
        "0.255.255.255",
        "::",
    ],
)
def test_ssrf_rejects_unspecified_bind_addresses(unspecified_target):
    """
    Asserts that 0.0.0.0, 0.0.0.0/8, and :: are rejected as invalid destinations.
    """
    is_safe, reason = validate_target_host(unspecified_target, allow_private=False)
    assert not is_safe, f"Unspecified target '{unspecified_target}' unexpectedly passed validation"


# =====================================================================
# 2. DNS Rebinding / Split-Horizon DNS Multi-Record Scenarios
# =====================================================================

@pytest.mark.parametrize(
    "scenario_name,resolved_ips",
    [
        ("rebind_rfc1918", ["93.184.216.34", "10.0.0.1"]),
        ("rebind_metadata_v4", ["93.184.216.34", "169.254.169.254"]),
        ("rebind_loopback", ["93.184.216.34", "127.0.0.1"]),
        ("rebind_ula_fc", ["93.184.216.34", "fc00::1"]),
        ("rebind_ula_fd", ["93.184.216.34", "fd00::1"]),
        ("rebind_ipv4_mapped", ["93.184.216.34", "::ffff:127.0.0.1"]),
        ("rebind_cgnat", ["93.184.216.34", "100.64.0.1"]),
        ("rebind_unspecified", ["93.184.216.34", "0.0.0.0"]),
        ("rebind_metadata_v6", ["93.184.216.34", "fd00:ec2::254"]),
    ],
)
def test_ssrf_rejects_dns_rebinding_multi_record_matrix(monkeypatch, scenario_name, resolved_ips):
    """
    Asserts that validate_target_host checks every resolved IP address in multi-record DNS responses,
    failing closed if ANY address belongs to a prohibited subnet.
    """
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80)) for ip in resolved_ips]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = validate_target_host(f"{scenario_name}.attacker.example", allow_private=False)
    assert not ok, f"DNS rebinding scenario '{scenario_name}' unexpectedly passed validation!"


# =====================================================================
# 3. CLI Strict Target Rejection & Whitelist Protection
# =====================================================================

@pytest.mark.parametrize(
    "cli_target",
    [
        "169.254.169.254",
        "10.0.0.1",
        "100.64.0.1",
        "0.0.0.0",
        "unauthorized-target.example.org",
    ],
)
def test_cli_strictly_rejects_ssrf_and_unauthorized_targets(cli_target):
    """
    Executes rfc_hunt_swarm.py --host <target> as a subprocess and asserts that:
    1. It exits with code 1 (failure).
    2. It does not crash with an unhandled traceback.
    3. TargetAuthorizationGate.ALLOWED_TARGETS is not mutated.
    """
    initial_allowed = set(TargetAuthorizationGate.ALLOWED_TARGETS)

    res = subprocess.run(
        [sys.executable, "rfc_hunt_swarm.py", "--host", cli_target],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0, f"CLI invocation with target '{cli_target}' unexpectedly succeeded (code 0)!"
    assert "validation error" in res.stdout.lower() or "authorization error" in res.stdout.lower()

    # Verify whitelist was not contaminated
    current_allowed = TargetAuthorizationGate.get_allowed_targets()
    assert cli_target not in current_allowed, f"CLI target '{cli_target}' was auto-whitelisted into ALLOWED_TARGETS!"


# =====================================================================
# 4. Prober Fail-Closed Socket Gating Verification
# =====================================================================

def test_deterministic_harness_fails_closed_zero_sockets(monkeypatch):
    """Verifies that DeterministicHarness makes 0 socket connections to SSRF target."""
    socket_calls = []

    def spy_create_connection(addr, *args, **kwargs):
        socket_calls.append(addr)
        raise ConnectionRefusedError("Mock connection blocked")

    monkeypatch.setattr(socket, "create_connection", spy_create_connection)

    harness = DeterministicHarness(host="169.254.169.254", port=80)
    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary"):
        harness._open_connection()

    # Evaluation method must also not open sockets
    harness.run_evaluation({"raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n"})
    assert len(socket_calls) == 0, f"DeterministicHarness opened {len(socket_calls)} sockets to forbidden target!"


def test_weaponizer_fails_closed_zero_sockets(monkeypatch):
    """Verifies that RQPWeaponizer makes 0 socket connections to SSRF target."""
    socket_calls = []

    def spy_create_connection(addr, *args, **kwargs):
        socket_calls.append(addr)
        raise ConnectionRefusedError("Mock connection blocked")

    monkeypatch.setattr(socket, "create_connection", spy_create_connection)

    w = RQPWeaponizer(host="169.254.169.254", port=80)
    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary"):
        w._open_connection()

    w.test_dangling_byte_rqp("POST / HTTP/1.1\r\nHost: target.local\r\n$PAYLOAD")
    w.test_connection_locked_desync("GET / HTTP/1.1\r\nHost: target.local\r\n$PAYLOAD")
    w.test_head_range_gadget("/")
    assert len(socket_calls) == 0, f"RQPWeaponizer opened {len(socket_calls)} sockets to forbidden target!"


def test_differential_oracle_fails_closed_zero_sockets(monkeypatch):
    """Verifies that MultiImplementationDifferentialOracle makes 0 socket connections to SSRF target."""
    socket_calls = []

    def spy_create_connection(addr, *args, **kwargs):
        socket_calls.append(addr)
        raise ConnectionRefusedError("Mock connection blocked")

    monkeypatch.setattr(socket, "create_connection", spy_create_connection)

    oracle = MultiImplementationDifferentialOracle()
    bad_endpoint = TargetEndpoint(name="Malicious", host="169.254.169.254", port=80)
    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary"):
        oracle.dispatch_single_target(bad_endpoint, b"GET / HTTP/1.1\r\n\r\n")

    assert len(socket_calls) == 0, f"DifferentialOracle opened {len(socket_calls)} sockets to forbidden target!"


def test_protocol_ruler_fails_closed_zero_sockets(monkeypatch):
    """Verifies that ProtocolRuler fails closed on __init__ with 0 socket connections."""
    socket_calls = []

    def spy_create_connection(addr, *args, **kwargs):
        socket_calls.append(addr)
        raise ConnectionRefusedError("Mock connection blocked")

    monkeypatch.setattr(socket, "create_connection", spy_create_connection)

    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary"):
        ProtocolRuler(host="169.254.169.254", port=80)

    assert len(socket_calls) == 0, f"ProtocolRuler opened {len(socket_calls)} sockets to forbidden target!"


def test_active_flaw_prober_run_active_audit_socket_gating_finding(monkeypatch):
    """
    CRITICAL EMPIRICAL CHALLENGE FINDING:
    Demonstrates whether ActiveFlawProber.run_active_audit() fails closed without opening sockets.
    Currently, ActiveFlawProber._open_connection() is an unused helper; run_active_audit()
    delegates directly to self.seq_engine.run_pipelined_canary_sequence() which invokes
    socket.create_connection() without SSRF gating, sending 23 raw socket connections to the target.
    """
    socket_calls = []

    def spy_create_connection(addr, *args, **kwargs):
        socket_calls.append(addr)
        raise ConnectionRefusedError("Simulated connection refusal")

    monkeypatch.setattr(socket, "create_connection", spy_create_connection)

    prober = ActiveFlawProber(host="169.254.169.254", port=80)

    # _open_connection is gated...
    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary"):
        prober._open_connection()

    # BUT run_active_audit() executes without gating and attempts socket connections!
    prober.run_active_audit()

    # Asserting that 0 sockets were opened:
    # If this fails, ActiveFlawProber breaches SSRF containment!
    assert len(socket_calls) == 0, (
        f"SSRF CONTAINMENT BREACH: ActiveFlawProber.run_active_audit() attempted {len(socket_calls)} "
        f"socket connections to {socket_calls[0] if socket_calls else 'None'} without SSRF validation!"
    )
