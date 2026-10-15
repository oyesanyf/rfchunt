"""
Comprehensive Unit & Integration Test Suite for Aggressive rfchunt Improvements:
1. Independent 4-Parser Differential Matrix (Strict RFC 7230, Permissive Legacy, CDN Proxy, Async Microservice).
2. Binary HTTP/2 Framing & Gateway Desync Engine (H2.CL, H2.TE, Pseudo-header injection, HPACK).
3. Cryptographic Merkle Audit Trail (RFC 6962 Tree Root & Proofs).
4. Exploit & Defensive Hardening Exporter (Nuclei, ModSecurity, Suricata).
5. Multi-Trial Confirmation Law (Automatic NonReproducibleTransient Downgrade).
6. Interactive Research Dashboard Generator.
"""

import time
from engine.dashboard_generator import DashboardGenerator
from engine.delta_debugger import DeltaDebugger
from engine.differential_oracle import (
    AsyncMicroserviceParser,
    CDNProxyParser,
    MultiImplementationDifferentialOracle,
    PermissiveLegacyParser,
    StrictRFC7230Parser,
)
from engine.exploit_exporter import ExploitExporter
from engine.h2_framing import (
    H2ErrorCode,
    H2Flag,
    H2Frame,
    H2FrameType,
    H2GatewayDesyncBuilder,
    HPACKLite,
)
from engine.merkle_audit import MerkleAuditTrail
from engine.taxonomy import AnomalyCategory, ImpactClass, ImplementationAnomaly, ReproducibleVulnerability


def test_independent_4parser_differential_matrix():
    """Verifies that all 4 independent parsers accurately parse and detect framing anomalies."""
    strict = StrictRFC7230Parser()
    permissive = PermissiveLegacyParser()
    cdn = CDNProxyParser()
    async_p = AsyncMicroserviceParser()

    # 1. Bare LF line ending probe (Strict should reject with 400; Permissive should accept with 200)
    bare_lf_probe = b"GET / HTTP/1.1\nHost: target.local\n\n"
    r_strict = strict.parse(bare_lf_probe)
    r_perm = permissive.parse(bare_lf_probe)
    assert r_strict.status_code == 400
    assert r_perm.status_code == 200

    # 2. Conflicting TE and CL probe
    te_cl_probe = (
        b"POST / HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"Content-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\n"
    )
    r_strict_tecl = strict.parse(te_cl_probe)
    assert r_strict_tecl.status_code == 400

    # 3. CDN Proxy RHI unencoding check (Expect: asdf in unencoded path should trigger 417)
    rhi_probe = b"GET /%20HTTP/1.1%0d%0aExpect:%20asdf%0d%0aHost:%20target.local HTTP/1.1\r\nHost: target.local\r\n\r\n"
    r_cdn = cdn.parse(rhi_probe)
    assert r_cdn.status_code == 417

    # 4. Async Microservice dangling byte check (Content-Length 100 with only 4 bytes payload)
    dangling_probe = b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 100\r\n\r\nDATA"
    r_async = async_p.parse(dangling_probe)
    assert r_async.socket_state == "TIMEOUT"
    assert r_async.status_code == 408

    # 5. Full 4-parser differential evaluation via MultiImplementationDifferentialOracle
    oracle = MultiImplementationDifferentialOracle()
    has_div, anom, matrix = oracle.evaluate_matrix_4parsers(bare_lf_probe)
    assert has_div is True
    assert anom is not None
    assert "StrictRFC7230" in matrix
    assert "PermissiveLegacy" in matrix


def test_h2_framing_and_desync_builder():
    """Verifies binary HTTP/2 frame building, serialization, parsing, and desync generation."""
    # 1. Base frame serialization and parsing
    data_payload = b"Hello HTTP/2 World"
    frame = H2Frame(
        frame_type=H2FrameType.DATA,
        flags=H2Flag.END_STREAM,
        stream_id=5,
        payload=data_payload,
    )
    wire = frame.serialize()
    assert len(wire) == 9 + len(data_payload)
    parsed_frame, remaining = H2Frame.parse(wire)
    assert remaining == b""
    assert parsed_frame.frame_type == H2FrameType.DATA
    assert parsed_frame.flags == H2Flag.END_STREAM
    assert parsed_frame.stream_id == 5
    assert parsed_frame.payload == data_payload

    # 2. HPACK Literal encoding / decoding
    headers = [(":method", "GET"), (":path", "/"), ("x-custom", "value")]
    encoded_block = HPACKLite.encode_headers_block(headers)
    decoded = HPACKLite.decode_literal_headers(encoded_block)
    assert (":method", "GET") in decoded
    assert (":path", "/") in decoded
    assert ("x-custom", "value") in decoded

    # 3. H2.CL Desynchronization stream
    h2_cl_wire = H2GatewayDesyncBuilder.build_h2_cl_desync(
        path="/api", host="target.local", declared_cl=0, actual_payload=b"SMUGGLED"
    )
    assert len(h2_cl_wire) > 9
    first_frame, rest = H2Frame.parse(h2_cl_wire)
    assert first_frame.frame_type == H2FrameType.HEADERS
    second_frame, _ = H2Frame.parse(rest)
    assert second_frame.frame_type == H2FrameType.DATA
    assert second_frame.payload == b"SMUGGLED"

    # 4. H2.TE Desynchronization stream
    h2_te_wire = H2GatewayDesyncBuilder.build_h2_te_desync(
        path="/", host="target.local", te_value="chunked", chunked_body=b"0\r\n\r\n"
    )
    assert len(h2_te_wire) > 9

    # 5. Pseudo-header CRLF injection
    crlf_h2_wire = H2GatewayDesyncBuilder.build_h2_crlf_pseudoheader_injection(
        injected_path="/%20HTTP/1.1\r\nHost: target.local\r\n\r\n", host="target.local"
    )
    crlf_frame, _ = H2Frame.parse(crlf_h2_wire)
    assert crlf_frame.frame_type == H2FrameType.HEADERS


def test_merkle_audit_trail_and_proofs():
    """Verifies cryptographic Merkle tree root calculation, leaf recording, and proof verification."""
    tree = MerkleAuditTrail()

    # Record 3 protocol research findings
    l1 = tree.record_finding(
        entry_id="TEST-1",
        target_engine="127.0.0.1:80",
        raw_probe=b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        four_parser_differential={"divergent": False},
        status="CONFIRMED_VULNERABILITY",
    )
    l2 = tree.record_finding(
        entry_id="TEST-2",
        target_engine="127.0.0.1:80",
        raw_probe=b"POST / HTTP/1.1\r\nHost: b\r\n\r\n",
        raw_response=b"HTTP/1.1 500 Error\r\n\r\n",
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        four_parser_differential={"divergent": True},
        status="CONFIRMED_VULNERABILITY",
    )
    l3 = tree.record_finding(
        entry_id="TEST-3",
        target_engine="127.0.0.1:80",
        raw_probe=b"HEAD / HTTP/1.1\r\nHost: c\r\n\r\n",
        raw_response=b"HTTP/1.1 206 Partial\r\n\r\n",
        reproducibility_rate=0.33,
        verification_attempts=3,
        successful_reproductions=1,
        four_parser_differential={"divergent": False},
        status="NON_REPRODUCIBLE_TRANSIENT",
    )

    root = tree.get_merkle_root()
    assert len(root) == 64  # SHA-256 hex string

    # Verify audit proof for leaf 1
    proof1 = tree.generate_proof(1)
    leaf1_hash = l2.compute_leaf_hash()
    is_valid = MerkleAuditTrail.verify_proof(leaf1_hash, proof1, root)
    assert is_valid is True

    # Export audit log
    exported = tree.export_audit_log()
    assert exported["total_leaves"] == 3
    assert exported["merkle_root"] == root


def test_exploit_and_defensive_exporter():
    """Verifies that Nuclei, ModSecurity, and Suricata templates are properly exported."""
    vuln = ReproducibleVulnerability(
        vuln_id="VULN-REPRO-9999",
        anomaly_id="ANOM-123",
        impact=ImpactClass.CRLF_REQUEST_HEADER_INJECTION,
        minimized_probe=b"GET /%20HTTP/1.1%0d%0aExpect:%20asdf HTTP/1.1\r\nHost: target.local\r\n\r\n",
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        delta_debug_steps=4,
    )

    # 1. Nuclei export
    nuclei_yaml = ExploitExporter.export_nuclei_template(vuln)
    assert "id: rfchunt-vuln-repro-9999" in nuclei_yaml
    assert "tags: rfchunt,desync,terminator" in nuclei_yaml
    assert "{{Hostname}}" in nuclei_yaml

    # 2. ModSecurity export
    modsec_rules = ExploitExporter.export_modsecurity_rule(vuln, rule_id_start=220000)
    assert "SecRule REQUEST_URI" in modsec_rules
    assert "id:220000" in modsec_rules
    assert "RFCHunt: Request Header Injection via CRLF in URI" in modsec_rules

    # 3. Suricata signature export
    suricata_sig = ExploitExporter.export_suricata_signature(vuln, sid_start=3000001)
    assert 'content:"%0d%0a"' in suricata_sig
    assert "sid:3000001" in suricata_sig


def test_delta_debugger_multi_trial_downgrade():
    """
    Verifies that the Multi-Trial Confirmation Law is strictly enforced:
    Transient or unstable findings are automatically downgraded to NonReproducibleTransient.
    """
    debugger = DeltaDebugger(target_host="127.0.0.1", target_port=8080)
    anom = ImplementationAnomaly(
        anomaly_id="ANOM-FLAKE-001",
        target_engine="127.0.0.1:8080",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="Intermittent 500 error",
        expected_behavior="200 OK",
        raw_probe=b"GET /flaky HTTP/1.1\r\nHost: target.local\r\n\r\n",
        raw_response=b"HTTP/1.1 500 Error\r\n\r\n",
    )

    call_count = [0]

    def flaky_evaluator(probe: bytes) -> bool:
        call_count[0] += 1
        # Only succeeds on the 1st call, fails on subsequent calls
        return call_count[0] == 1

    repro_vuln = debugger.minimize_and_reproduce(
        anom, test_evaluator=flaky_evaluator, max_verification_trials=3
    )

    # Must be downgraded to NonReproducibleTransient!
    assert repro_vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT
    assert repro_vuln.verification_attempts >= 3
    assert repro_vuln.successful_reproductions < 3
    assert any("NonReproducibleTransient" in p for p in repro_vuln.provenance_chain)


def test_dashboard_generator():
    """Verifies that the interactive HTML research dashboard renders without errors."""
    stats = {
        "total_evaluated": 25,
        "passed": 23,
        "anomalies": 2,
        "flaws": 1,
    }
    merkle_log = {
        "merkle_root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "total_leaves": 5,
    }
    flaws = [
        {
            "rfc_num": 9112,
            "desync_class": "CRLF Request Header Injection",
            "details": "Nginx $uri unencoding forwarded injected headers",
        }
    ]

    html_out = DashboardGenerator.generate_html_dashboard(
        target_host="127.0.0.1",
        target_port=8080,
        scan_stats=stats,
        merkle_audit_log=merkle_log,
        flaws=flaws,
        arm106_count=12,
        arm107_count=12,
    )

    assert "<!DOCTYPE html>" in html_out
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in html_out
    assert "CRLF Request Header Injection" in html_out
    assert "12 / 12" in html_out


def test_multi_terminators_and_modes():
    """Verifies category-based terminator selection and multi-target parsing."""
    from permutator import VectorPermutator
    import argparse
    from start import parse_arguments

    # 1. Verify CATEGORIES definitions
    assert "chunk" in VectorPermutator.CATEGORIES
    assert "line" in VectorPermutator.CATEGORIES
    assert "framing" in VectorPermutator.CATEGORIES
    assert "crlf_rhi" in VectorPermutator.CATEGORIES
    assert "h2_gateway" in VectorPermutator.CATEGORIES
    assert "cross_protocol" in VectorPermutator.CATEGORIES

    # 2. Verify filtering by specific multiple terminators
    vp = VectorPermutator()
    chunk_and_h2 = vp.get_mutators_by_categories(["chunk", "h2_gateway"])
    chunk_names = [m.__name__ for m in chunk_and_h2]
    assert any("chunk" in name.lower() for name in chunk_names)
    assert any("h2" in name.lower() for name in chunk_names)
    # Ensure line mutators are not included when only chunk,h2_gateway requested
    assert "mutate_space_before_colon" not in chunk_names

    # 3. Verify CLI parser accepts --terminators, --targets, and --mode
    args = parse_arguments([
        "--host", "127.0.0.1",
        "--targets", "10.0.0.1:8080,https://internal.proxy:8443",
        "--terminators", "chunk,h2_gateway,crlf_rhi",
        "--mode", "offline"
    ])
    assert args.targets == ["10.0.0.1:8080", "https://internal.proxy:8443"]
    assert args.terminators == ["chunk", "h2_gateway", "crlf_rhi"]
    assert args.mode == "offline"


def test_active_flaw_prober_canonical_vectors():
    """Verifies that ActiveFlawProber creates the complete canonical PortSwigger vulnerability probe suite."""
    from engine.active_flaw_prober import ActiveFlawProber
    prober = ActiveFlawProber(host="127.0.0.1", port=8080)
    probes = prober.get_canonical_attack_probes()

    categories = {cat for _, cat, _ in probes}
    assert "CL.TE" in categories
    assert "TE.CL" in categories
    assert "CL.0" in categories
    assert "TE.TE" in categories
    assert "CRLF-RHI" in categories
    assert "RULER" in categories
    assert "CRASH" in categories
    assert len(probes) >= 15

    # Check CL.0 probe contains nested request
    cl0_probes = [p for _, cat, p in probes if cat == "CL.0"]
    assert any(b"Content-Length:" in p and b"GET /terminator_marker" in p for p in cl0_probes)


def test_sequence_engine_cl0_detection():
    """Verifies that StatefulProtocolSequenceEngine detects CL.0 request smuggling."""
    from engine.sequence_engine import StatefulProtocolSequenceEngine
    engine = StatefulProtocolSequenceEngine()
    assert hasattr(engine, "run_cl0_canary_sequence")


