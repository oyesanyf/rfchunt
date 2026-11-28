"""
Tests for Correlated LLM vs. Independent Oracle Separation and Devil's-Advocate
AST-Verified Refutation Pass in `fusion_engine.py`.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from fusion_engine import CandidateProposal, FusionArbiter


def _make_offline_arbiter() -> FusionArbiter:
    with patch.object(FusionArbiter, "_fetch_available_tags", return_value=["gemma2:2b", "qwen2.5:1.5b", "llama3:8b"]):
        arb = FusionArbiter(db=None, preferred_model="gemma2:2b")
    return arb


def test_unanimous_3_model_llm_agreement_stays_unresolved_without_independent_oracle(tmp_path: Path):
    """Even 3/3 unanimous correlated LLM agreement NEVER promotes out of UNRESOLVED / Lane 3."""
    target = tmp_path / "handler.py"
    target.write_text(
        "def helper_call(x):\n"
        "    return str(x).strip()\n",
        encoding="utf-8",
    )
    arb = _make_offline_arbiter()
    candidate = {
        "rule_id": "LLM-CLAIMED-BUG",
        "title": "Hypothetical injection claim",
        "cwe": "CWE-999",
        "file_path": str(target),
        "line_number": 2,
        "severity": "CRITICAL",
        "poe_level": 3,  # Even if an LLM optimistically claims POE=3!
        "verification_status": "VERIFIED_EXPLOIT",
    }
    res = arb.arbitrate_finding_epistemic(
        candidate,
        llm_votes=["gemma4:12b", "qwen2.5:7b", "llama3:8b"],
        independent_oracles=[],
        repo_root=str(tmp_path),
        use_llm_refutation=False,
    )
    assert res["epistemic_status"] == "UNRESOLVED"
    assert res["evidence_lane"] == "LLM_HEURISTIC"
    assert res["poe_level"] < 3
    just = res["status_justification"]
    assert just["epistemic_status"] == "UNRESOLVED"
    assert just["independent_oracles"] == []
    assert len(just["correlated_oracles"]) == 3
    assert "independent_oracle_missing" in just["missing_evidence"]
    assert "correlated_llm_agreement_cannot_promote" in just["missing_evidence"]


def test_orthogonal_independent_oracle_permits_promotion(tmp_path: Path):
    """Adding an orthogonal independent oracle (Z3 SMT / runtime POE) enables legitimate promotion."""
    target = tmp_path / "vuln_sql.py"
    target.write_text(
        "def get_user(cursor, user_id):\n"
        "    return cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n",
        encoding="utf-8",
    )
    arb = _make_offline_arbiter()

    # Static invariant witness (AST + Z3)
    res_static = arb.arbitrate_finding_epistemic(
        {
            "rule_id": "SQLI-01",
            "title": "SQL Injection via f-string",
            "cwe": "CWE-89",
            "file_path": str(target),
            "line_number": 2,
            "severity": "HIGH",
            "z3_status": "sat",
            "z3_witness": {"user_id": "1 OR 1=1"},
        },
        llm_votes=["gemma4:12b"],
        independent_oracles=["z3_smt"],
        repo_root=str(tmp_path),
        use_llm_refutation=False,
    )
    assert res_static["epistemic_status"] == "PROVEN_STATIC_INVARIANT"
    assert "z3_smt" in res_static["status_justification"]["independent_oracles"]

    # Runtime PoE == 3 execution
    res_rt = arb.arbitrate_finding_epistemic(
        {
            "rule_id": "SQLI-01",
            "title": "SQL Injection via f-string",
            "cwe": "CWE-89",
            "file_path": str(target),
            "line_number": 2,
            "severity": "CRITICAL",
            "poe_level": 3,
            "runtime_poe_verified": True,
        },
        llm_votes=["gemma4:12b"],
        independent_oracles=["runtime_poe_container"],
        repo_root=str(tmp_path),
        use_llm_refutation=False,
    )
    assert res_rt["epistemic_status"] == "PROVEN_RUNTIME"
    assert "runtime_poe_container" in res_rt["status_justification"]["independent_oracles"]


def test_devils_advocate_refutation_catches_sanitizer_and_callee_guards(tmp_path: Path):
    """Refutation pass inspects enclosing function + callees and marks dominating sanitizer REFUTED."""
    safe_file = tmp_path / "safe_download.py"
    safe_file.write_text(
        "from pathlib import Path\n"
        "\n"
        "def _enforce_root(base_dir: Path, raw_name: str) -> Path:\n"
        "    resolved = (base_dir / raw_name).resolve()\n"
        "    if not resolved.is_relative_to(base_dir.resolve()):\n"
        "        raise PermissionError('Path traversal blocked')\n"
        "    return resolved\n"
        "\n"
        "def download_file(base_dir: Path, filename: str) -> bytes:\n"
        "    safe_path = _enforce_root(base_dir, filename)\n"
        "    return open(safe_path, 'rb').read()\n",
        encoding="utf-8",
    )
    arb = _make_offline_arbiter()
    ctx = arb.extract_function_and_callees_context(str(safe_file), 11)
    assert ctx["enclosing_function"] == "download_file"
    assert "_enforce_root" in ctx["callees"]

    res = arb.arbitrate_finding_epistemic(
        {
            "rule_id": "LLM-CWE22",
            "title": "Path traversal in download_file",
            "cwe": "CWE-22",
            "file_path": str(safe_file),
            "line_number": 11,
            "severity": "HIGH",
        },
        llm_votes=["gemma4:12b", "qwen2.5:7b", "llama3:8b"],
        repo_root=str(tmp_path),
        use_llm_refutation=False,
    )
    # Dominating sanitizer in callee or direct AST check refutes the false claim
    assert res["epistemic_status"] in ("REFUTED", "UNRESOLVED")
    assert res["epistemic_status"] != "PROVEN_RUNTIME"


def test_devils_advocate_rejects_hallucinated_llm_line_citations(tmp_path: Path, monkeypatch):
    """If the Devil's-Advocate LLM hallucinates line numbers with no real guard, AST rejects them."""
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    target = tmp_path / "ambiguous.py"
    target.write_text(
        "def process_record(item):\n"
        "    label = str(item)\n"
        "    return label.upper()\n",
        encoding="utf-8",
    )
    arb = _make_offline_arbiter()
    fake_llm_resp = json.dumps({
        "refuted": True,
        "cited_lines": [2, 999],  # Line 2 has no sanitizer/auth guard; 999 is out of range!
        "reason": "Claimed sanitizer on line 2 (hallucinated)",
    })
    with patch.object(arb, "_query_model", return_value=fake_llm_resp):
        ref = arb.run_refutation_pass(
            {
                "rule_id": "GEN-01",
                "title": "Generic claim",
                "cwe": "CWE-999",
                "file_path": str(target),
                "line_number": 3,
            },
            repo_root=str(tmp_path),
            use_llm=True,
        )
    assert ref["refuted"] is False
    assert ref["source"] == "llm_refutation_citations_rejected_by_ast"
    assert ref["verified_lines"] == []
    assert 2 in ref["rejected_lines"]


def test_gate2_unanimous_labels_correlated_oracles():
    """Gate 2 Unanimous in _arbitrate_proposals marks multi-LLM agreement as correlated_oracles + UNRESOLVED."""
    arb = _make_offline_arbiter()
    req = "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 5\r\n\r\n$PAYLOAD"
    proposals = [
        CandidateProposal("c1", "gemma2:2b", "Spec1", "r1", req, False),
        CandidateProposal("c2", "qwen2.5:1.5b", "Spec2", "r2", req, False),
        CandidateProposal("c3", "llama3:8b", "Spec3", "r3", req, False),
    ]
    res = arb._arbitrate_proposals(
        rfc_fragment="RFC 9112 section 6.3",
        fragment_id=None,
        proposals=proposals,
        participating_models=["gemma2:2b", "qwen2.5:1.5b", "llama3:8b"],
        unique_specialists=["gemma2:2b", "qwen2.5:1.5b", "llama3:8b"],
        hint_block="",
        fact_block="",
    )
    assert res.consensus_type == "Unanimous"
    assert res.metadata["epistemic_status"] == "UNRESOLVED"
    assert res.metadata["independent_oracles"] == []
    assert len(res.metadata["correlated_oracles"]) == 3
