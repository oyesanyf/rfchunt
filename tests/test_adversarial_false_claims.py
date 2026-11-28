"""
Adversarial "Valid-File + False-Claim" Test Suite, Lean 4 Conformance Tests,
Patched-vs.-Unpatched Ground-Truth Tests, and `--folder --dry-run` Tests
(`tests/test_adversarial_false_claims.py`).
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from benchmarks.eval_epistemic_rigor import (
    run_adversarial_false_claim_suite,
    run_full_evaluation,
    run_lean4_epistemic_conformance_audit,
    run_patched_vs_unpatched_benchmark,
)
from engine.claim_verifier import ClaimPreconditionVerifier
from engine.epistemic_state import (
    EpistemicStatus,
    attach_epistemic_metadata,
    can_promote_to_proven_runtime,
    derive_epistemic_status,
    enrich_sarif_result_epistemic,
    map_legacy_label_to_epistemic,
)
from engine.formal_verifier import find_lean4_binary
from engine.mantis_integrator import build_sarif_document
from engine.poe_container_verifier import POEVerificationResult
from engine.verification_inversion_hunter import (
    z3_verify_comparator_contract,
    z3_verify_numeric_bounds,
)


def test_adversarial_valid_file_false_claims_zero_false_promotion():
    """
    Even with mocked 3/3 unanimous multi-model LLM agreement pointing to REAL files
    and REAL line numbers, false_promotion_rate MUST be strictly 0.0.
    """
    res = run_adversarial_false_claim_suite()
    assert res["total_cases"] >= 10
    assert res["false_promotions"] == 0
    assert res["false_promotion_rate"] == 0.0
    for c in res["cases"]:
        assert c["promoted"] is False
        assert c["epistemic_status"] in ("REFUTED", "UNRESOLVED")
        assert len(c["correlated_oracles"]) == 3
        if c["epistemic_status"] == "UNRESOLVED":
            assert len(c["missing_evidence"]) > 0
        else:
            assert len(c["failed_checks"]) > 0


def test_independent_patched_vs_unpatched_ground_truth_benchmark():
    """
    Independent CVE/CWE patched-vs.-unpatched pairs:
      - Patched files MUST have 0.0 false_promotion_rate and 0.0 false_positive_rate.
      - Vulnerable files MUST achieve high deterministic recall (>= 0.90).
    """
    res = run_patched_vs_unpatched_benchmark()
    assert res["total_pairs"] >= 14
    assert res["false_positives"] == 0
    assert res["false_positive_rate"] == 0.0
    assert res["false_promotion_rate"] == 0.0
    assert res["precision"] == 1.0
    assert res["recall"] >= 0.90


def test_exhaustive_python_to_lean4_epistemic_conformance():
    """
    Exhaustively tests all 864 input combinations of `evaluate_epistemic_transition`
    against the 8 Lean 4 theorems proved in `formal/lean4/EpistemicPromotionInvariants.lean`.
    """
    res = run_lean4_epistemic_conformance_audit(use_native_lean=False)
    assert res["conformance_states_checked"] >= 800
    assert res["conformance_violations"] == 0
    assert res["conformance_passed"] is True

    # Also test native Lean 4 compiler directly if installed in tools/lean4
    lean_bin = find_lean4_binary(Path(__file__).resolve().parent.parent)
    if lean_bin is not None:
        native_res = run_lean4_epistemic_conformance_audit(use_native_lean=True)
        assert native_res["lean4_kernel_verification"]["all_modules_proved"] is True


def test_epistemic_state_unifies_sarif_poe_and_legacy_labels(tmp_path: Path):
    """Verifies SARIF properties, POE docker-unavailable UNRESOLVED state, and legacy mappings."""
    assert map_legacy_label_to_epistemic("skipped_docker_unavailable") == "UNRESOLVED"
    assert map_legacy_label_to_epistemic("LEAD_PASSIVE_CORRELATION") == "UNRESOLVED"
    assert map_legacy_label_to_epistemic("FALSE_POSITIVE") == "REFUTED"
    assert map_legacy_label_to_epistemic("VERIFIED", poe_level=3, has_independent_oracle=False) == "UNRESOLVED"
    assert map_legacy_label_to_epistemic("VERIFIED", poe_level=3, has_independent_oracle=True) == "PROVEN_RUNTIME"

    assert can_promote_to_proven_runtime(
        independent_oracles=["llm_gemma", "llm_qwen"],
        runtime_poe_executed=True,
        runtime_poe_passed=True,
        poe_level=3,
    ) is False
    assert can_promote_to_proven_runtime(
        independent_oracles=["runtime_poe_container"],
        runtime_poe_executed=True,
        runtime_poe_passed=True,
        poe_level=3,
    ) is True

    poe_skip = POEVerificationResult(
        finding_id="F-1",
        title="Candidate",
        original_severity="HIGH",
        calibrated_severity="HIGH",
        status="skipped_docker_unavailable",
        poe_level=1,
        verified=False,
        false_positive=False,
        verification_mode="skipped_docker_unavailable",
    ).to_dict()
    assert poe_skip["epistemic_status"] == "UNRESOLVED"
    assert "docker_unavailable" in poe_skip["status_justification"]["missing_evidence"]

    # SARIF document carries epistemic_status + status_justification on every result
    f = tmp_path / "safe.py"
    f.write_text("import yaml\nx = yaml.safe_load('a: 1')\n", encoding="utf-8")
    sarif = build_sarif_document(
        tool_name="RFCHunt-Test",
        tool_uri="https://example.invalid",
        target_root=str(tmp_path),
        findings=ClaimPreconditionVerifier.apply_to_findings(
            [{
                "rule_id": "DESER-01",
                "title": "Unsafe YAML",
                "cwe": "CWE-502",
                "file_path": str(f),
                "line_number": 2,
                "severity": "HIGH",
            }],
            repo_root=tmp_path,
        ),
    )
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["epistemic_status"] == "REFUTED"
    assert "status_justification" in props
    assert props["status_justification"]["epistemic_status"] == "REFUTED"


def test_live_z3_bounds_and_comparator_sat_unsat():
    """Verifies real Z3 SMT produces SAT witnesses on flaws and UNSAT on safe guards."""
    z_vuln = z3_verify_numeric_bounds(var_name="content_length", has_lower_bound=False, has_upper_bound=False)
    assert z_vuln["z3_status"] == "sat"
    assert z_vuln["epistemic_status"] == "PROVEN_STATIC_INVARIANT"
    assert "content_length" in z_vuln["witness"]

    z_safe = z3_verify_numeric_bounds(
        var_name="content_length",
        has_lower_bound=True,
        lower_bound=0,
        has_upper_bound=True,
        upper_bound=65536,
    )
    assert z_safe["z3_status"] == "unsat"
    assert z_safe["epistemic_status"] == "REFUTED"

    c_vuln = z3_verify_comparator_contract(checks_aud=False, checks_iss=False)
    assert c_vuln["z3_status"] == "sat"
    assert c_vuln["witness"]["aud_valid"] is False or c_vuln["witness"]["iss_valid"] is False

    c_safe = z3_verify_comparator_contract(
        checks_sig=True,
        checks_exp=True,
        checks_aud=True,
        checks_iss=True,
        forbid_overrides_permit=True,
        inverted_role_check=False,
    )
    assert c_safe["z3_status"] == "unsat"
    assert c_safe["epistemic_status"] == "REFUTED"


def test_scorecard_json_and_markdown_export(tmp_path: Path):
    """Scorecard emits versioned JSON & Markdown with commit SHA, metrics, and replay commands."""
    sc = run_full_evaluation(output_dir=tmp_path, use_native_lean=False)
    json_f = Path(sc["report_files"]["json"])
    md_f = Path(sc["report_files"]["markdown"])
    assert json_f.is_file() and md_f.is_file()
    data = json.loads(json_f.read_text(encoding="utf-8"))
    assert data["suite_a_adversarial_false_claims"]["false_promotion_rate"] == 0.0
    assert data["suite_b_patched_vs_unpatched"]["false_positive_rate"] == 0.0
    assert data["metadata"]["replay_commands"]
    md_txt = md_f.read_text(encoding="utf-8")
    assert "RFCHunt Epistemic Rigor & Ground-Truth Scorecard" in md_txt
    assert "Exact Replay Commands" in md_txt


def test_standalone_folder_dry_run_reports_local_all_mode(tmp_path: Path):
    """Standalone `rfc_hunt_swarm.py --folder <dir> --dry-run --json` reports local-code audit mode."""
    (tmp_path / "sample.py").write_text("x = 1\n", encoding="utf-8")
    repo_root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [
            sys.executable,
            str(repo_root / "rfc_hunt_swarm.py"),
            "--folder",
            str(tmp_path),
            "--dry-run",
            "--json",
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    assert plan["active_mode"] == "all"
    assert plan["target_host"] is None
    assert plan["dry_run"] is True
    assert str(tmp_path.resolve()) in str(plan["target_repo_or_path"])
