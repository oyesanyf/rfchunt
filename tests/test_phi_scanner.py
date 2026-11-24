"""
Tests for Module 22 (`--phi` Presidio + GLiNER + RedactX-v3 18 HIPAA Safe Harbor PHI Scanner)
and Universal `--dry-run` across RFCHunt CLI flags and modes.
"""

from __future__ import annotations

import base64
import json
import math
from pathlib import Path
import urllib.parse

import pytest

from engine.mantis_integrator import run_unified_all_scans
from engine.phi_scanner import (
    GlinerSpanNerEngine,
    PhiScanner,
    PresidioGlinerPiiZeroGuard,
    RedactXStructuredValidator,
    luhn_check,
)
from rfc_hunt_swarm import main_swarm, parse_swarm_arguments


def _make_valid_mod11_mrn(prefix_digits: str) -> str:
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    total = sum(int(ch) * weights[i % len(weights)] for i, ch in enumerate(prefix_digits))
    check = (11 - (total % 11)) % 10
    return f"{prefix_digits}{check}"


def test_redactx_v3_mathematical_hipaa_validators() -> None:
    # 1. NPI Luhn with ISO prefix 80840 (official CMS example 1234567893)
    assert RedactXStructuredValidator.npi_valid("1234567893") is True
    assert RedactXStructuredValidator.npi_valid("1234567890") is False
    assert RedactXStructuredValidator.npi_valid("12345") is False

    # 2. Mod-11 MRN weighted checksum
    valid_mrn = _make_valid_mod11_mrn("4829103")
    assert RedactXStructuredValidator.mod11_valid(valid_mrn) is True
    bad_last = str((int(valid_mrn[-1]) + 1) % 10)
    assert RedactXStructuredValidator.mod11_valid(valid_mrn[:-1] + bad_last) is False

    # 3. Strict SSA SSN validation
    assert RedactXStructuredValidator.ssn_valid("123", "45", "6789") is True
    assert RedactXStructuredValidator.ssn_valid("000", "45", "6789") is False
    assert RedactXStructuredValidator.ssn_valid("666", "45", "6789") is False
    assert RedactXStructuredValidator.ssn_valid("901", "45", "6789") is False
    assert RedactXStructuredValidator.ssn_valid("123", "00", "6789") is False
    assert RedactXStructuredValidator.ssn_valid("123", "45", "0000") is False

    # 4. Luhn PAN + CMS MBI + DEA + RFC 5321 email
    assert luhn_check("4532015112830366") is True
    assert luhn_check("4532015112830367") is False
    assert RedactXStructuredValidator.mbi_valid("1EG4TE5MK72") is True
    assert RedactXStructuredValidator.mbi_valid("1SG4TE5MK72") is False  # 'S' forbidden in MBI
    # DEA checksum: (1+3+5) + 2*(2+4+6) = 9 + 24 = 33 -> check digit 3
    assert RedactXStructuredValidator.dea_valid("AB1234563") is True
    assert RedactXStructuredValidator.dea_valid("AB1234564") is False
    assert RedactXStructuredValidator.rfc5321_email_valid("alice@hospital.org") is True
    assert RedactXStructuredValidator.rfc5321_email_valid("bad@.org") is False


def test_depth8_recursive_unwrapping_and_platt_zk_quarantine_proof() -> None:
    # Exact Platt calibration T=1.08 parity with AgentOctopus semantic_dlp.rs
    expected = 1.0 / (1.0 + math.exp(-2.0 / 1.08))
    assert abs(PresidioGlinerPiiZeroGuard.platt_calibrate(2.0) - expected) < 1e-9

    # Nest an SSN inside Base64 -> URL -> Hex (3 encoding layers)
    raw_phi = "Patient Jane Roe SSN 234-56-7890"
    b64_layer = base64.b64encode(raw_phi.encode("utf-8")).decode("ascii")
    url_layer = urllib.parse.quote(b64_layer, safe="")
    hex_layer = url_layer.encode("utf-8").hex()

    guard = PresidioGlinerPiiZeroGuard(enable_ml=False, enable_presidio=False)
    entities = guard.detect_entities(hex_layer)
    ssn_hits = [e for e in entities if e.entity_type == "SSN"]
    assert len(ssn_hits) >= 1
    assert ssn_hits[0].encoding_depth >= 2
    assert ssn_hits[0].zk_commitment.startswith("<ZK_PII:SSN:")

    # Direct scrub + zero-leakage proof verification
    scrubbed, proof = guard.scrub_and_prove(raw_phi)
    assert "234-56-7890" not in scrubbed
    assert "Jane Roe" not in scrubbed
    assert "<ZK_PII:SSN:" in scrubbed
    assert proof.zero_leakage_verified is True
    assert proof.redacted_entity_count >= 2
    assert len(proof.commitment_hash) == 64

    # GLiNER deterministic span scoring parity
    gliner = GlinerSpanNerEngine(enable_ml=False)
    assert gliner.score_span("123-45-6789", "us_ssn") == 0.99
    assert gliner.score_span("1234567893", "hipaa_npi") == 0.98


def test_phi_repository_scanner_zero_leakage_and_redacted_exports(tmp_path: Path) -> None:
    valid_mrn = _make_valid_mod11_mrn("6190425")
    sample_repo = tmp_path / "clinic_app"
    sample_repo.mkdir()
    (sample_repo / "patient_handler.py").write_text(
        "\n".join(
            [
                "import logging",
                "logger = logging.getLogger(__name__)",
                f'DEMO_PATIENT = {{"patient_name": "Alice Mercer", "ssn": "345-67-8901", "npi": "1234567893", "mrn": "{valid_mrn}"}}',
                "def handle_patient(patient):",
                "    logger.info(f'Processing patient.ssn={patient.ssn}')",
                "    return True",
            ]
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "reports"
    scanner = PhiScanner(enable_ml=False, enable_presidio=False)
    res = scanner.scan_repository(str(sample_repo), output_dir=str(out_dir), write_redacted_copies=True)

    assert res["status"] == "completed"
    assert res["zero_leakage_enforced"] is True
    assert res["total_findings"] >= 4
    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "PHI-HIPAA-SSN" in rule_ids
    assert "PHI-HIPAA-NPI" in rule_ids
    assert "PHI-HIPAA-MRN" in rule_ids
    assert "PHI-LOG-SINK-001" in rule_ids

    # Critical Zero-Leakage Invariant: raw SSN/NPI/MRN must NEVER appear in the written JSON report
    raw_report_text = Path(res["report_path"]).read_text(encoding="utf-8")
    assert "345-67-8901" not in raw_report_text
    assert "1234567893" not in raw_report_text
    assert valid_mrn not in raw_report_text
    assert "<ZK_PII:SSN:" in raw_report_text

    # Verify redacted file copy was generated cleanly without mutating original source
    assert res["redacted_files_count"] == 1
    redacted_copy = Path(res["redaction_receipts"][0]["redacted_file"])
    assert redacted_copy.is_file()
    redacted_text = redacted_copy.read_text(encoding="utf-8")
    assert "345-67-8901" not in redacted_text
    assert "<ZK_PII:SSN:" in redacted_text

    # Verify live HTTP response scanning
    http_res = scanner.scan_http_response(
        '{"patient": "Robert Vance", "ssn": "456-78-9012", "diagnosis": "E11.9"}',
        source_url="https://clinic.internal/api/patient/42",
    )
    assert http_res["total_findings"] >= 2
    assert "456-78-9012" not in http_res["scrubbed_preview"]
    assert http_res["quarantine_proof"]["zero_leakage_verified"] is True


def test_unified_all_with_phi_flag_integrates_lane2_findings(tmp_path: Path) -> None:
    repo = tmp_path / "health_svc"
    repo.mkdir()
    (repo / "intake.py").write_text(
        'PATIENT_RECORD = {"patient": "Clara Kent", "ssn": "512-34-5678", "npi": "1234567893"}\n',
        encoding="utf-8",
    )
    out = tmp_path / "all_out"
    res = run_unified_all_scans(
        repo=str(repo),
        depth=10,
        reports_dir=str(out),
        enable_external_scanners=False,
        enable_phi_scan=True,
        phi_enable_ml=False,
        auto_install_tools=False,
        include_models=False,
    )
    phi_eng = (res.get("engines") or {}).get("phi_scanner") or {}
    assert phi_eng.get("status") == "completed"
    assert phi_eng.get("total_findings", 0) >= 2
    det_rules = {f.get("rule_id") for f in (res.get("deterministic_static_findings") or [])}
    assert "PHI-HIPAA-SSN" in det_rules
    assert "512-34-5678" not in Path(res["report_files"]["combined_json"]).read_text(encoding="utf-8")


def test_universal_dry_run_works_across_all_cli_flags(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sample = tmp_path / "sample_repo"
    sample.mkdir()
    (sample / "app.py").write_text("print('ok')\n", encoding="utf-8")

    # 1. --all --phi --hackerone --dry-run --json
    main_swarm(
        [
            "--all",
            "--repo",
            str(sample),
            "--phi",
            "--hackerone",
            "--hackerone-program",
            "anthropic-vdp",
            "--dry-run",
            "--json",
        ]
    )
    out_all = json.loads(capsys.readouterr().out)
    assert out_all["dry_run"] is True
    assert out_all["side_effects"]["network_packets_sent"] == 0
    assert out_all["side_effects"]["filesystem_mutations"] == 0
    assert out_all["side_effects"]["browser_launched"] is False
    assert "Module-22-PhiScanner(Presidio+GLiNER+RedactX-v3)" in out_all["planned_modules"]
    assert "phi" in out_all["sub_plans"]
    assert "hackerone" in out_all["sub_plans"]

    # 2. Standalone --phi --dry-run --json
    main_swarm(["--phi", "--repo", str(sample), "--phi-redact", "--dry-run", "--json"])
    out_phi = json.loads(capsys.readouterr().out)
    assert out_phi["dry_run"] is True
    assert out_phi["candidate_files_count"] == 1
    assert out_phi["filesystem_mutations"] == 0

    # 3. Standalone --hackerone --hackerone-auto --dry-run --json
    main_swarm(
        [
            "--hackerone",
            "--hackerone-auto",
            "--hackerone-program",
            "agoda",
            "--hackerone-username",
            "researcher1",
            "--dry-run",
            "--json",
        ]
    )
    out_h1 = json.loads(capsys.readouterr().out)
    assert out_h1["dry_run"] is True
    assert out_h1["safe_harbor_roe_enforced"] is True
    assert out_h1["programs_evaluated"] == 1

    # 4. --serve-ui --dry-run --json (must NOT bind socket or hang!)
    main_swarm(["--serve-ui", "--dry-run", "--json"])
    out_ui = json.loads(capsys.readouterr().out)
    assert out_ui["dry_run"] is True
    assert any("MissionControlServer" in m for m in out_ui["planned_modules"])

    # 5. --deep-audit --proxy --dry-run --json
    main_swarm(["--deep-audit", "--repo", str(sample), "--proxy", "--dry-run", "--json"])
    out_deep = json.loads(capsys.readouterr().out)
    assert out_deep["dry_run"] is True
    assert any("DeepRepoAudit" in m for m in out_deep["planned_modules"])

    # 6. CLI flag parsing check for all new --phi / --dry-run / --hackerone-auto flags
    parsed = parse_swarm_arguments(
        [
            "--phi",
            "--phi-redact",
            "--phi-model",
            "urchade/gliner_multi_pii-v1",
            "--no-phi-ml",
            "--hackerone-auto",
            "--hackerone-username",
            "alice_h1",
            "--hackerone-ai-disclosure",
            "--dry-run",
        ]
    )
    assert parsed.enable_phi is True
    assert parsed.phi_redact is True
    assert parsed.no_phi_ml is True
    assert parsed.hackerone_auto is True
    assert parsed.hackerone_username == "alice_h1"
    assert parsed.hackerone_ai_disclosure is True
    assert parsed.dry_run is True
