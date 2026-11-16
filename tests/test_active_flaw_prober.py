"""
Unit tests for ActiveFlawProber (Feature 13 & Milestone 3 requirements):
- Verifies canonical 36 Transfer-Encoding (TE.TE) mutator catalog.
- Verifies retention and processing of ALL anomalies from cascade_anoms (no single-element drop).
- Verifies fail-closed behavior on safe network validator and authorization gating.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from engine.active_flaw_prober import ActiveFlawProber
from engine.taxonomy import ImplementationAnomaly, AnomalyCategory, ImpactClass, ReproducibleVulnerability


def test_active_flaw_prober_canonical_36_te_mutators():
    """Feature 13: ActiveFlawProber must build at least 36 canonical TE.TE mutators."""
    prober = ActiveFlawProber(host="127.0.0.1", port=8080)
    probes = prober.get_canonical_attack_probes()

    te_probes = [p for p in probes if p[1] == "TE.TE"]
    assert len(te_probes) >= 36, f"Expected at least 36 TE.TE mutators, found {len(te_probes)}"

    names = [p[0] for p in te_probes]
    assert any("Space Before Colon" in n for n in names)
    assert any("Tab Separator" in n for n in names)
    assert any("Vertical Tab" in n for n in names)
    assert any("Dual Header" in n for n in names)
    assert any("Identity" in n for n in names)
    assert any("Chunk Extension" in n for n in names)
    assert any("Null Byte" in n for n in names)
    assert any("Line Folding" in n for n in names)
    assert any("Prefix Space" in n for n in names)
    assert any("Prefix Tab" in n for n in names)


def test_active_flaw_prober_cascade_retention():
    """Feature 13: ActiveFlawProber must retain and process ALL cascade anomalies, not just index 0."""
    prober = ActiveFlawProber(host="127.0.0.1", port=8080)

    # Synthetic response that triggers multiple structural anomalies
    # e.g., Double HTML and Injected HTTP Header
    multi_anomaly_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"X-Injected: Bad\r\n"
        b"\r\n"
        b"<html><body>First</body></html>"
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body>Second</body></html>"
    )

    mock_step = MagicMock()
    mock_step.step_name = "Candidate Probe"
    mock_step.received_bytes = multi_anomaly_resp
    mock_step.status_code = 200

    mock_seq_report = MagicMock()
    mock_seq_report.has_desynchronization = False
    mock_seq_report.has_pipeline_leak = False
    mock_seq_report.steps = [mock_step]

    synthetic_anoms = [
        {"type": "DOUBLE_HTML", "description": "Multiple HTML documents in single stream"},
        {"type": "INLINE_HEADERS", "description": "Secondary HTTP response header detected in payload"},
    ]

    mock_vuln = ReproducibleVulnerability(
        vuln_id="VULN-REPRO-1",
        anomaly_id="ANOM-1",
        impact=ImpactClass.REQUEST_SMUGGLING,
        minimized_probe=b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        delta_debug_steps=1,
    )

    reproduced_count = 0

    def mock_minimize(anom, max_verification_trials=3):
        nonlocal reproduced_count
        reproduced_count += 1
        return mock_vuln

    with patch.object(prober.seq_engine, "run_pipelined_canary_sequence", return_value=mock_seq_report), \
         patch("anomaly_detector.AnomalyDetector.analyze_response", return_value=synthetic_anoms), \
         patch.object(prober.debugger, "minimize_and_reproduce", side_effect=mock_minimize), \
         patch.object(prober, "_check_safety"):

        # Single probe run for test
        prober.get_canonical_attack_probes = lambda: [
            ("Test Cascade Probe", "TEST", b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        ]

        vulns = prober.run_active_audit()

        # Both anomalies must be evaluated and reproduced
        assert reproduced_count == 2, f"Expected 2 reproduced anomalies, got {reproduced_count}"
        assert len(vulns) == 2


def test_active_flaw_prober_unauthorized_target_rejected():
    """ActiveFlawProber must fail closed when target host is rejected by authorization gate."""
    with patch("engine.safe_network_validator.validate_target_host", return_value=(False, "Private IP prohibited")), \
         patch("mcp_server.TargetAuthorizationGate.check_target", side_effect=PermissionError("Forbidden")):
        prober = ActiveFlawProber(host="10.0.0.1")
        assert prober._is_safe is False
        assert prober._is_authorized is False
        with pytest.raises(PermissionError):
            prober._check_safety()
        with pytest.raises(PermissionError):
            prober._open_connection()
