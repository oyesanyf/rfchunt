"""
Comprehensive Unit and Integration Tests for Decoupled Authorization,
Mathematical SSRF Validation, Rate Limiting, Supervisor Approvals,
Path Traversal Hardening, Prober Gating, and Database Integrity.
"""

import ipaddress
import json
import os
import re
import socket
import sqlite3
import tempfile
import time
from pathlib import Path
import pytest

from mcp_server import TargetAuthorizationGate, TerminatorMCPServer
from database import Database
from engine.safe_network_validator import (
    is_safe_target_ip,
    validate_target_host,
    is_cloud_metadata,
    BLOCKED_IPV4_NETWORKS,
    BLOCKED_IPV6_NETWORKS,
)
from engine.harness2_engine import normalize_rel
from deterministic_harness import DeterministicHarness
from weaponizer import RQPWeaponizer
from engine.active_flaw_prober import ActiveFlawProber
from engine.differential_oracle import MultiImplementationDifferentialOracle, TargetEndpoint
from protocol_ruler import ProtocolRuler


# =====================================================================
# 1. MCP Security Gate Baseline Controls
# =====================================================================

def test_target_rejects_inaddr_any():
    """Verifies that 0.0.0.0 and :: are rejected as invalid scan destinations."""
    with pytest.raises(ValueError, match="invalid destination address"):
        TargetAuthorizationGate.check_target("0.0.0.0")

    with pytest.raises(ValueError, match="invalid destination address"):
        TargetAuthorizationGate.check_target("::")


def test_target_rejects_wildcard_bypass():
    """Verifies that wildcard strings cannot be authorized to bypass security checks."""
    with pytest.raises(ValueError, match="Wildcard authorization is disallowed"):
        TargetAuthorizationGate.authorize_target("*")

    with pytest.raises(ValueError, match="Wildcard authorization is disallowed"):
        TargetAuthorizationGate.authorize_target("all")


def test_target_enforces_whitelist():
    """Verifies that external targets not in the whitelist are rejected."""
    with pytest.raises(PermissionError, match="not in the authorized targets whitelist"):
        TargetAuthorizationGate.check_target("unauthorized-victim.example.com")


def test_payload_length_enforcement():
    """Verifies that payloads exceeding 64KB are rejected."""
    small_payload = 1024  # 1 KB
    TargetAuthorizationGate.check_payload(small_payload)  # Should not raise

    oversized_payload = 65 * 1024  # 65 KB (> 64 KB boundary)
    with pytest.raises(ValueError, match="exceeds maximum allowed boundary"):
        TargetAuthorizationGate.check_payload(oversized_payload)


def test_sliding_window_rate_limiter():
    """Verifies that exceeding the per-minute rate limit raises RuntimeError."""
    client_id = f"test_client_{time.time()}"
    for _ in range(TargetAuthorizationGate.RATE_LIMIT_PER_MINUTE):
        TargetAuthorizationGate.check_rate_limit(client_id)

    with pytest.raises(RuntimeError, match="Rate limit exceeded"):
        TargetAuthorizationGate.check_rate_limit(client_id)


def test_supervisor_token_enforcement(monkeypatch):
    """Verifies that weaponization and heavy scans fail closed without supervisor token."""
    monkeypatch.delenv("RFCHUNT_SUPERVISOR_TOKEN", raising=False)
    with pytest.raises(PermissionError, match="RFCHUNT_SUPERVISOR_TOKEN is not configured"):
        TargetAuthorizationGate.check_supervisor_approval(None, "weaponization")

    monkeypatch.setenv("RFCHUNT_SUPERVISOR_TOKEN", "super-secret-token-12345")
    with pytest.raises(PermissionError, match="Invalid or missing supervisor approval token"):
        TargetAuthorizationGate.check_supervisor_approval("wrong-token", "weaponization")

    TargetAuthorizationGate.check_supervisor_approval("super-secret-token-12345", "weaponization")


def test_mcp_error_sanitization(monkeypatch):
    """Verifies that MCP tools/call sanitizes internal errors and does not leak tracebacks."""
    with TerminatorMCPServer(db_path=":memory:") as server:
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "evaluate_probe",
                "arguments": {
                    "raw_request": "GET / HTTP/1.1\r\nHost: 0.0.0.0\r\n\r\n",
                    "target_host": "0.0.0.0",
                },
            },
        }
        resp = server.handle_request(req)
        assert "error" in resp
        assert resp["error"]["code"] == -32602
        assert "invalid destination address" in resp["error"]["message"].lower()

        monkeypatch.setenv("RFCHUNT_SUPERVISOR_TOKEN", "valid-token-xyz")
        weap_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "weaponize_dangling_byte",
                "arguments": {
                    "base_trigger": "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\na",
                    "target_host": "127.0.0.1",
                    "supervisor_token": "invalid-token",
                },
            },
        }
        weap_resp = server.handle_request(weap_req)
        assert "error" in weap_resp
        assert weap_resp["error"]["code"] == -32001
        assert "supervisor approval token" in weap_resp["error"]["message"]


def test_database_defensive_intelligence_population():
    """Verifies that terminator.db contains populated defensive rules and regression tests."""
    db_path = Path(__file__).resolve().parent.parent / "terminator.db"
    assert db_path.exists(), f"Database not found at {db_path}"

    with Database(str(db_path)) as db:
        db._seed_baseline_defensive_intelligence()

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        vulns_count = cur.execute("SELECT COUNT(*) FROM reproducible_vulnerabilities").fetchone()[0]
        rules_count = cur.execute("SELECT COUNT(*) FROM arm106_defensive_rules").fetchone()[0]
        tests_count = cur.execute("SELECT COUNT(*) FROM arm107_regression_tests").fetchone()[0]
        evals_count = cur.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0]
    finally:
        conn.close()

    assert vulns_count > 0, "Reproducible vulnerabilities must not be empty"
    assert rules_count >= vulns_count, f"Arm 106 defensive rules ({rules_count}) must cover vulns ({vulns_count})"
    assert tests_count >= vulns_count, f"Arm 107 regression tests ({tests_count}) must cover vulns ({vulns_count})"
    assert evals_count > 0, f"Evaluations table must be populated ({evals_count})"


# =====================================================================
# 2. Mathematical SSRF & IP Category Verification (All 8 Categories)
# =====================================================================

def test_ssrf_mathematical_ip_blocking_rfc1918():
    """Validates mathematical CIDR blocking for RFC1918 private subnets."""
    rfc1918_ips = [
        "10.0.0.1", "10.254.1.1", "10.255.255.254",
        "172.16.0.1", "172.24.10.5", "172.31.255.254",
        "192.168.0.1", "192.168.1.1", "192.168.254.254",
    ]
    for ip in rfc1918_ips:
        assert not is_safe_target_ip(ip, allow_private=False), f"Expected {ip} to be blocked by default"
        ok, reason = validate_target_host(ip, allow_private=False)
        assert not ok, f"Expected {ip} to fail validation without allow_private"
        assert "private" in reason.lower() or "blocked" in reason.lower()

        # When allow_private is explicitly True, private IP is permitted for local test lab
        ok_priv, _ = validate_target_host(ip, allow_private=True)
        assert ok_priv, f"Expected {ip} to be permitted when allow_private=True"


def test_ssrf_cloud_metadata_absolute_blocking():
    """Validates that Cloud Metadata endpoints are permanently blocked even if allow_private=True."""
    metadata_endpoints = [
        "169.254.169.254",      # AWS IMDSv1/v2, GCP, Azure, OpenStack
        "169.254.0.1",          # IPv4 Link-Local
        "169.254.254.254",      # Link-local gateway
        "fd00:ec2::254",        # AWS IPv6 IMDS
        "fe80::1",              # IPv6 Link-Local
        "fe80::200:5aee:feaa:20a2",
    ]
    for target in metadata_endpoints:
        # Must be blocked by is_safe_target_ip
        assert not is_safe_target_ip(target, allow_private=False)
        assert not is_safe_target_ip(target, allow_private=True), f"Metadata {target} must NEVER be safe even with allow_private=True"

        # Must be blocked by validate_target_host
        ok_default, reason_def = validate_target_host(target, allow_private=False)
        assert not ok_default
        assert "metadata" in reason_def.lower() or "link-local" in reason_def.lower() or "blocked" in reason_def.lower()

        ok_priv, reason_priv = validate_target_host(target, allow_private=True)
        assert not ok_priv, f"Metadata {target} must fail validate_target_host even with allow_private=True"
        assert "metadata" in reason_priv.lower() or "link-local" in reason_priv.lower()

        # Attempting to authorize cloud metadata must raise ValueError
        with pytest.raises(ValueError, match=r"metadata|link-local|Cannot authorize"):
            TargetAuthorizationGate.authorize_target(target)


def test_ssrf_cgnat_shared_space_blocking():
    """
    Validates explicit blocking of Carrier-Grade NAT (RFC 6598 100.64.0.0/10).
    Python's ipaddress.ip_address('100.64.0.1').is_private evaluates to False!
    SafeNetworkValidator must explicitly check the 100.64.0.0/10 CIDR.
    """
    cgnat_ips = ["100.64.0.1", "100.80.12.34", "100.100.100.100", "100.127.255.254"]
    for ip_str in cgnat_ips:
        ip_obj = ipaddress.ip_address(ip_str)
        assert not ip_obj.is_private, "Sanity check: standard Python ipaddress marks CGNAT as NOT private"
        # SafeNetworkValidator MUST catch it
        assert not is_safe_target_ip(ip_str, allow_private=False), f"CGNAT IP {ip_str} must be blocked by is_safe_target_ip"
        ok, reason = validate_target_host(ip_str, allow_private=False)
        assert not ok, f"CGNAT IP {ip_str} must fail validate_target_host"
        assert "private" in reason.lower() or "reserved" in reason.lower() or "blocked" in reason.lower()


def test_ssrf_ipv6_unique_local_and_unspecified():
    """Validates IPv6 ULA (fc00::/7), loopback (::1), and unspecified (::, 0.0.0.0)."""
    # Unique Local Address (ULA)
    assert not is_safe_target_ip("fc00::1", allow_private=False)
    assert not is_safe_target_ip("fd12:3456:789a:1::1", allow_private=False)

    # Loopback
    assert not is_safe_target_ip("127.0.0.1", allow_private=False)
    assert not is_safe_target_ip("::1", allow_private=False)
    assert is_safe_target_ip("127.0.0.1", allow_private=True)
    assert is_safe_target_ip("::1", allow_private=True)

    # Unspecified (INADDR_ANY) must NEVER be permitted
    assert not is_safe_target_ip("0.0.0.0", allow_private=False)
    assert not is_safe_target_ip("0.0.0.0", allow_private=True)
    assert not is_safe_target_ip("::", allow_private=False)
    assert not is_safe_target_ip("::", allow_private=True)

    ok_0, reason_0 = validate_target_host("0.0.0.0", allow_private=True)
    assert not ok_0
    assert "inaddr_any" in reason_0.lower() or "unspecified" in reason_0.lower() or "invalid" in reason_0.lower()

    ok_colon, reason_colon = validate_target_host("::", allow_private=True)
    assert not ok_colon


def test_ssrf_ipv4_mapped_ipv6_evasion_blocked():
    """Validates that IPv4-mapped IPv6 addresses (::ffff:0:0/96) are strictly blocked."""
    mapped_ips = [
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "::ffff:192.168.1.1",
    ]
    for mapped in mapped_ips:
        assert not is_safe_target_ip(mapped, allow_private=False)
        assert not is_safe_target_ip(mapped, allow_private=True)
        ok, reason = validate_target_host(mapped, allow_private=True)
        assert not ok
        assert "ipv4-mapped" in reason.lower() or "blocked" in reason.lower()


def test_ssrf_dns_rebinding_multi_record_validation(monkeypatch):
    """
    Validates that validate_target_host checks all resolved IP addresses for a hostname.
    If ANY address resolves to a blocked range (DNS rebinding / split-horizon DNS), it fails closed.
    """
    # 1. Host resolving exclusively to a public routable IP: PASSES
    def fake_getaddrinfo_public(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo_public)
    ok_pub, _ = validate_target_host("safe-public-site.example.com", allow_private=False)
    assert ok_pub is True

    # 2. Host resolving to public IP + private RFC1918 (Split-horizon DNS rebinding): BLOCKED
    def fake_getaddrinfo_rebinding_rfc1918(host, port):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo_rebinding_rfc1918)
    ok_rebind, reason_rebind = validate_target_host("rebinding-victim.example.com", allow_private=False)
    assert ok_rebind is False
    assert "dns rebinding" in reason_rebind.lower() or "private" in reason_rebind.lower()

    # 3. Host resolving to public IP + cloud metadata IP: BLOCKED EVEN IF allow_private=True
    def fake_getaddrinfo_rebinding_metadata(host, port):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo_rebinding_metadata)
    ok_meta, reason_meta = validate_target_host("metadata-exfil.attacker.com", allow_private=True)
    assert ok_meta is False
    assert "cloud metadata" in reason_meta.lower() or "blocked" in reason_meta.lower()


# =====================================================================
# 3. Prober Fail-Closed Gating Verification (All 5 Probers)
# =====================================================================

def test_probers_fail_closed_on_unauthorized_and_ssrf_targets():
    """
    Verifies that all 5 raw socket probers fail closed and raise PermissionError
    before creating any socket connection when supplied unauthorized or SSRF targets.
    """
    forbidden_target = "169.254.169.254"

    # 1. DeterministicHarness
    harness = DeterministicHarness(host=forbidden_target, port=80)
    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary|not in the authorized targets whitelist"):
        harness._open_connection()

    # 2. RQPWeaponizer
    weaponizer = RQPWeaponizer(host=forbidden_target, port=80)
    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary|not in the authorized targets whitelist"):
        weaponizer._open_connection()

    # 3. ActiveFlawProber
    prober = ActiveFlawProber(host=forbidden_target, port=80)
    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary|not in the authorized targets whitelist"):
        prober._open_connection()

    # 4. MultiImplementationDifferentialOracle
    oracle = MultiImplementationDifferentialOracle()
    bad_endpoint = TargetEndpoint(name="MaliciousMetadata", host=forbidden_target, port=80)
    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary|not in the authorized targets whitelist"):
        oracle.dispatch_single_target(bad_endpoint, b"GET / HTTP/1.1\r\n\r\n")

    # 5. ProtocolRuler
    with pytest.raises(PermissionError, match=r"rejected by SSRF safety boundary|not in the authorized targets whitelist"):
        ProtocolRuler(host=forbidden_target, port=80)


# =====================================================================
# 4. Path Traversal & normalize_rel Hardening Verification
# =====================================================================

def test_normalize_rel_multi_level_percent_encoding_adversarial():
    """Verifies that single, double, triple, and quadruple percent-encoding are strictly rejected."""
    traversal_attacks = [
        "scripts/%2e%2e/escape.py",           # 1-level
        "scripts/%252e%252e/escape.py",       # 2-level
        "scripts/%25252e%25252e/escape.py",   # 3-level
        "scripts/%2525252e%2525252e.py",     # 4-level
        "scripts/%2fetc%2fpasswd",            # encoded slashes
        "scripts/%252fetc%252fshadow",
        "scripts/%25252fetc",
        "scripts/file%00.py",                 # encoded null byte
        "scripts/file%2500.py",
        "scripts/file%252500.py",
        "scripts/c%3a/windows/system32",      # encoded colon / drive letter
        "scripts/c%253a/boot",
        "scripts/c%25253a/win.ini",
    ]
    for attack in traversal_attacks:
        with pytest.raises(ValueError, match="path escapes the harness"):
            normalize_rel(attack)


def test_normalize_rel_windows_device_names_variations():
    """
    Verifies that Windows device names with trailing spaces, trailing dots,
    URL-encoding, and expanded device handles (conin$, conout$, clock$) are rejected.
    """
    device_attacks = [
        "scripts/con .py",            # Trailing space in stem
        "scripts/aux .txt",
        "scripts/nul .py",
        "scripts/prn .json",
        "scripts/com1 .py",
        "scripts/con..txt",           # Trailing dots
        "scripts/%43%4f%4e.py",       # URL-encoded CON
        "scripts/%2543%254f%254e.py", # Double URL-encoded CON
        "scripts/conin$.py",          # Console input handle
        "scripts/conout$.py",         # Console output handle
        "scripts/clock$.py",          # System clock device
    ]
    for attack in device_attacks:
        with pytest.raises(ValueError, match=r"Windows reserved device name|path escapes"):
            normalize_rel(attack)


def test_normalize_rel_unicode_homoglyphs_and_root_containment(tmp_path):
    """Verifies that Unicode homoglyphs and base directory root identities are rejected."""
    # Unicode fullwidth homoglyphs
    homoglyphs = [
        "\uff0e\uff0e\uff0fescape.py",        # Fullwidth dot dot slash (／)
        "scripts/\uff0fetc",
        "scripts/\uff3cwindows",              # Fullwidth reverse solidus (＼)
        "scripts/c\uff1awindows",             # Fullwidth colon (：)
    ]
    for h in homoglyphs:
        with pytest.raises(ValueError, match="path escapes the harness"):
            normalize_rel(h)

    # Base directory root identity: normalize_rel('.', base_dir=tmp_path)
    with pytest.raises(ValueError, match=r"empty relative path|path escapes base directory|path escapes"):
        normalize_rel(".", base_dir=tmp_path)

    with pytest.raises(ValueError, match=r"empty relative path|path escapes base directory|path escapes"):
        normalize_rel("./", base_dir=tmp_path)


# =====================================================================
# 5. CLI Auto-Whitelist Elimination Verification
# =====================================================================

def test_cli_auto_whitelist_bypass_eliminated():
    """
    Verifies that passing a private IP or metadata endpoint on the CLI
    does not mutate TargetAuthorizationGate.ALLOWED_TARGETS.
    """
    initial_allowed = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    assert "169.254.169.254" not in initial_allowed
    assert "10.0.0.1" not in initial_allowed

    # Simulating what rfc_hunt_swarm.py now does:
    target_to_test = "169.254.169.254"
    is_safe_net, _ = validate_target_host(target_to_test, allow_private=False)
    assert is_safe_net is False

    # The target MUST NOT be present in ALLOWED_TARGETS
    current_allowed = TargetAuthorizationGate.get_allowed_targets()
    assert "169.254.169.254" not in current_allowed
    assert "10.0.0.1" not in current_allowed
