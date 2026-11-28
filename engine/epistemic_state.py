"""
First-Class Epistemic State Machine for RFCHunt (`engine/epistemic_state.py`).

Unifies verification states across `mantis_integrator.py`, `poe_container_verifier.py`,
`poc_generator.py`, `fusion_engine.py`, `verification_inversion_hunter.py`,
`formal_verifier.py`, and `ensemble_orchestrator.py` around four strict epistemic states
and a mandatory machine-readable `status_justification` block:

  - `PROVEN_RUNTIME`: `poe_level >= 3` — isolated container or >= 3-trial differential
    behavioral execution succeeded with independent execution evidence.
  - `PROVEN_STATIC_INVARIANT`: deterministic AST/call-graph/SMT invariant violated with
    concrete witness and NO dominating sanitizer.
  - `UNRESOLVED`: fail-closed default whenever proof obligations are incomplete, Docker
    is unavailable, caller reachability is unproven, or only correlated LLM/heuristic
    signals exist.
  - `REFUTED`: deterministic AST/sanitizer check, SMT `unsat`, or container replay
    disproved the claim.

Formal Specification Correspondence:
  `evaluate_epistemic_transition(...)` is the 1-to-1 Python executable counterpart of
  `RFCHunt.Epistemic.deriveState` formally machine-checked in
  `formal/lean4/EpistemicPromotionInvariants.lean` (Lean 4 v4.36.0, zero `sorry`).
  Lean 4 verifies this gating specification; AST checks, Z3 SMT witnesses, runtime PoE
  execution, and empirical ground-truth benchmarks verify claims about target code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence


class EpistemicStatus(str, Enum):
    PROVEN_RUNTIME = "PROVEN_RUNTIME"
    PROVEN_STATIC_INVARIANT = "PROVEN_STATIC_INVARIANT"
    UNRESOLVED = "UNRESOLVED"
    REFUTED = "REFUTED"


ALL_EPISTEMIC_STATUSES = (
    EpistemicStatus.PROVEN_RUNTIME.value,
    EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
    EpistemicStatus.UNRESOLVED.value,
    EpistemicStatus.REFUTED.value,
)

# Canonical independent (orthogonal, non-LLM) oracle identifiers
INDEPENDENT_ORACLE_KINDS = frozenset({
    "ast_rule",
    "ast_invariant",
    "ast_refutation_verifier",
    "claim_precondition_ast",
    "call_graph_taint",
    "z3_smt",
    "lean4_kernel",
    "runtime_poe_container",
    "runtime_3trial_wire",
    "differential_oracle",
    "semgrep_native",
    "trivy_native",
    "trufflehog_native",
    "infisical_native",
    "bumblebee_threat_intel",
    "aiscan_native",
    "raptor_native",
    "codeql_native",
    "deterministic_static",
})

# Scanner names that provide correlated LLM / speculative / heuristic signals rather than independent proof
_CORRELATED_ONLY_SCANNERS = frozenset({
    "modelfusion",
    "fusionarbiter",
    "llm",
    "llm_review",
    "local_diff_review",
    "codex_security",
    "module-17-artex",
    "module-17-artex-dualgraph",
    "module-19-promptsmuggler",
})


def _dedupe_str_list(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    seen = set()
    for v in values:
        s = str(v or "").strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def is_correlated_oracle_name(name: str) -> bool:
    low = str(name or "").strip().lower()
    if not low:
        return False
    return (
        low.startswith(("llm_", "llm:", "model_", "ollama_", "openai_", "anthropic_", "gemini_", "grok_", "fusion_"))
        or "gemma" in low
        or "qwen" in low
        or "llama" in low
        or "claude" in low
        or "gpt-" in low
        or "deepseek" in low
        or "mistral" in low
        or low in _CORRELATED_ONLY_SCANNERS
    )


def evaluate_epistemic_transition(
    *,
    independent_oracles_count: int,
    correlated_llm_oracles_count: int = 0,
    poe_level: int = 0,
    runtime_poe_executed: bool = False,
    runtime_poe_passed: bool = False,
    static_invariant_witness: bool = False,
    dominating_sanitizer_found: bool = False,
    refuted: bool = False,
    missing_obligations_count: int = 0,
) -> str:
    """
    Pure, deterministic state-machine transition kernel mirroring
    `RFCHunt.Epistemic.deriveState` in `formal/lean4/EpistemicPromotionInvariants.lean`.

    Invariants (machine-checked in Lean 4):
      1. `refuted` or `dominating_sanitizer_found` -> strictly `REFUTED`.
      2. `independent_oracles_count <= 0` -> strictly `UNRESOLVED` (even if
         `correlated_llm_oracles_count >= 3`).
      3. `missing_obligations_count > 0` -> strictly `UNRESOLVED`.
      4. `runtime_poe_executed and runtime_poe_passed and poe_level >= 3` -> `PROVEN_RUNTIME`.
      5. `static_invariant_witness` -> `PROVEN_STATIC_INVARIANT`.
      6. Otherwise -> `UNRESOLVED` (fail closed).
    """
    _ = correlated_llm_oracles_count  # Deliberately cannot promote without independent oracles
    if bool(refuted) or bool(dominating_sanitizer_found):
        return EpistemicStatus.REFUTED.value
    if int(independent_oracles_count) <= 0:
        return EpistemicStatus.UNRESOLVED.value
    if int(missing_obligations_count) > 0:
        return EpistemicStatus.UNRESOLVED.value
    if bool(runtime_poe_executed) and bool(runtime_poe_passed) and int(poe_level) >= 3:
        return EpistemicStatus.PROVEN_RUNTIME.value
    if bool(static_invariant_witness):
        return EpistemicStatus.PROVEN_STATIC_INVARIANT.value
    return EpistemicStatus.UNRESOLVED.value


def can_promote_to_proven_runtime(
    *,
    independent_oracles: Sequence[str],
    runtime_poe_executed: bool,
    runtime_poe_passed: bool,
    poe_level: int,
    refuted: bool = False,
    dominating_sanitizer_found: bool = False,
    missing_evidence: Sequence[str] = (),
) -> bool:
    non_llm = [o for o in independent_oracles if o and not is_correlated_oracle_name(o)]
    state = evaluate_epistemic_transition(
        independent_oracles_count=len(non_llm),
        poe_level=int(poe_level),
        runtime_poe_executed=bool(runtime_poe_executed),
        runtime_poe_passed=bool(runtime_poe_passed),
        static_invariant_witness=False,
        dominating_sanitizer_found=bool(dominating_sanitizer_found),
        refuted=bool(refuted),
        missing_obligations_count=len([m for m in missing_evidence if str(m).strip()]),
    )
    return state == EpistemicStatus.PROVEN_RUNTIME.value


@dataclass
class StatusJustification:
    """Mandatory machine-readable epistemic justification embedded in JSON & SARIF outputs."""

    epistemic_status: str = EpistemicStatus.UNRESOLVED.value
    satisfied_checks: List[str] = field(default_factory=list)
    failed_checks: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    independent_oracles: List[str] = field(default_factory=list)
    correlated_oracles: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "epistemic_status": str(self.epistemic_status),
            "satisfied_checks": _dedupe_str_list(self.satisfied_checks),
            "failed_checks": _dedupe_str_list(self.failed_checks),
            "missing_evidence": _dedupe_str_list(self.missing_evidence),
            "independent_oracles": _dedupe_str_list(self.independent_oracles),
            "correlated_oracles": _dedupe_str_list(self.correlated_oracles),
        }


def map_legacy_label_to_epistemic(label: Any, *, poe_level: int = 0, has_independent_oracle: bool = False) -> str:
    """Maps legacy RFCHunt verification/triage status strings onto the 4 strict epistemic states."""
    norm = str(label or "").strip().upper()
    if norm in ALL_EPISTEMIC_STATUSES:
        if norm in (EpistemicStatus.PROVEN_RUNTIME.value, EpistemicStatus.PROVEN_STATIC_INVARIANT.value) and not has_independent_oracle:
            return EpistemicStatus.UNRESOLVED.value
        return norm
    if norm in (
        "FALSE_POSITIVE",
        "DOWNGRADED_FALSE_POSITIVE",
        "REFUTED",
        "REJECTED",
        "REJECTED_COMMENT_LINE",
        "REJECTED_REGEX_PATTERN",
        "REJECTED_PLACEHOLDER",
        "REJECTED_CONSTANT_COMMAND",
        "REJECTED_CONSTANT_BINDING",
        "REJECTED_TEST_FIXTURE",
        "DOWNGRADED_PASSIVE_CHAIN",
        "TEST_FIXTURE",
        "HARDENING_NOTE",
        "UNSAT",
    ):
        return EpistemicStatus.REFUTED.value
    if norm in (
        "VERIFIED",
        "VERIFIED_EXPLOIT",
        "VERIFIED_POE",
        "VERIFIED_POE3",
        "VERIFIED_CHAIN_POE3",
        "VERIFIED_REPRODUCIBLE",
        "TIER_3_CONTAINER_POE",
    ):
        if int(poe_level) >= 3 and has_independent_oracle:
            return EpistemicStatus.PROVEN_RUNTIME.value
        if has_independent_oracle:
            return EpistemicStatus.PROVEN_STATIC_INVARIANT.value
        return EpistemicStatus.UNRESOLVED.value
    if norm in (
        "SKIPPED_DOCKER_UNAVAILABLE",
        "SKIPPED_BELOW_THRESHOLD",
        "REJECTED_UNSAFE_TARGET",
        "LEAD_ACTIVE_INDICATOR",
        "LEAD_PASSIVE_CORRELATION",
        "UNVERIFIED_CANDIDATE",
        "UNVERIFIED",
        "SPECULATIVE_HYPOTHESIS",
        "LLM_HEURISTIC",
        "MANUAL_REVIEW_LEAD",
        "ERROR",
        "UNKNOWN",
        "",
    ):
        return EpistemicStatus.UNRESOLVED.value
    return EpistemicStatus.UNRESOLVED.value


def _extract_oracles_from_finding(finding: Dict[str, Any]) -> tuple[List[str], List[str]]:
    """Separates independent orthogonal oracles from correlated LLM/model oracles."""
    indep: List[str] = []
    corr: List[str] = []

    existing_j = finding.get("status_justification")
    if isinstance(existing_j, dict):
        for o in existing_j.get("independent_oracles") or []:
            if is_correlated_oracle_name(str(o)):
                corr.append(str(o))
            else:
                indep.append(str(o))
        for o in existing_j.get("correlated_oracles") or []:
            corr.append(str(o))

    for o in finding.get("independent_oracles") or []:
        if is_correlated_oracle_name(str(o)):
            corr.append(str(o))
        else:
            indep.append(str(o))
    for o in finding.get("correlated_oracles") or []:
        corr.append(str(o))

    # Extract LLM voters / participating models strictly into correlated_oracles
    for key in ("corroborated_by_models", "participating_models", "llm_models", "llm_voters"):
        vals = finding.get(key)
        if isinstance(vals, (list, tuple, set)):
            for m in vals:
                ms = str(m or "").strip()
                if ms:
                    tag = ms if ms.lower().startswith("llm_") else f"llm_{ms}"
                    corr.append(tag)
        elif isinstance(vals, str) and vals.strip():
            tag = vals.strip()
            corr.append(tag if tag.lower().startswith("llm_") else f"llm_{tag}")

    # Infer independent oracles from concrete non-LLM provenance
    scanner = str(finding.get("scanner") or "").strip()
    scanner_l = scanner.lower()
    if finding.get("z3_witness") or finding.get("z3_status") in ("sat", "unsat") or "z3" in scanner_l:
        indep.append("z3_smt")
    if finding.get("lean4_verified") or "lean4" in scanner_l:
        indep.append("lean4_kernel")
    if str(finding.get("poe_verification_status") or "").lower() == "verified" or (
        int(finding.get("poe_level") or 0) >= 3
        and str(finding.get("reproduction_tier") or "") in ("TIER_3_CONTAINER_POE", "TIER_3_RUNTIME_REPLAY")
    ):
        indep.append("runtime_poe_container")
    if scanner in ("LiveH2DesyncProber", "TwoAccountAuthzDiffer") and int(finding.get("poe_level") or 0) >= 3:
        indep.append("runtime_3trial_wire")
    if finding.get("runtime_poe_verified") is True or finding.get("differential_trials_passed", 0) >= 3:
        indep.append("runtime_3trial_wire")

    # Classify scanner if not purely LLM/speculative
    ev_lane = str(finding.get("evidence_lane") or "").upper()
    if ev_lane == "LLM_HEURISTIC" or finding.get("llm_only") is True:
        if scanner and not any(scanner_l in c.lower() for c in corr):
            corr.append(f"llm_{scanner}" if not scanner_l.startswith("llm_") else scanner)
    elif scanner and scanner_l not in _CORRELATED_ONLY_SCANNERS and not is_correlated_oracle_name(scanner):
        if "semgrep" in scanner_l:
            indep.append("semgrep_native")
        elif "trivy" in scanner_l:
            indep.append("trivy_native")
        elif "trufflehog" in scanner_l:
            indep.append("trufflehog_native")
        elif "infisical" in scanner_l:
            indep.append("infisical_native")
        elif "bumblebee" in scanner_l:
            indep.append("bumblebee_threat_intel")
        elif "aiscan" in scanner_l:
            indep.append("aiscan_native")
        elif "raptor" in scanner_l:
            indep.append("raptor_native")
        elif "codeql" in scanner_l:
            indep.append("codeql_native")
        elif "verificationinversion" in scanner_l:
            indep.append("ast_invariant")
        elif ev_lane == "DETERMINISTIC_STATIC":
            indep.append("ast_rule")

    return _dedupe_str_list(indep), _dedupe_str_list(corr)


def derive_epistemic_status(
    finding: Dict[str, Any],
    *,
    claim_result: Optional[Any] = None,
    runtime_poe_verified: bool = False,
    static_invariant_verified: bool = False,
    refuted: bool = False,
) -> Dict[str, Any]:
    """
    Derives the strict 4-state epistemic status and machine-readable `status_justification`
    block for a finding, enforcing fail-closed semantics via `evaluate_epistemic_transition`.
    """
    indep, corr = _extract_oracles_from_finding(finding)

    existing_j = finding.get("status_justification") if isinstance(finding.get("status_justification"), dict) else {}
    satisfied: List[str] = list(existing_j.get("satisfied_checks") or [])
    failed: List[str] = list(existing_j.get("failed_checks") or [])
    missing: List[str] = list(existing_j.get("missing_evidence") or [])

    dominating_sanitizer = False
    claim_static_witness = False
    claim_refuted = False
    claim_unresolved = False

    if claim_result is not None:
        cr = claim_result.to_dict() if hasattr(claim_result, "to_dict") else dict(claim_result)
        satisfied.extend(cr.get("satisfied_checks") or [])
        failed.extend(cr.get("failed_checks") or [])
        missing.extend(cr.get("missing_evidence") or [])
        for o in cr.get("independent_oracles") or []:
            if not is_correlated_oracle_name(str(o)):
                indep.append(str(o))
        if cr.get("sanitizer_found"):
            dominating_sanitizer = True
        cr_status = str(cr.get("epistemic_status") or "").upper()
        if cr_status == EpistemicStatus.REFUTED.value:
            claim_refuted = True
        elif cr_status == EpistemicStatus.PROVEN_STATIC_INVARIANT.value:
            claim_static_witness = True
        elif cr_status == EpistemicStatus.UNRESOLVED.value:
            claim_unresolved = True

    try:
        poe_level = int(finding.get("poe_level") or 0)
    except (TypeError, ValueError):
        poe_level = 0

    poe_status_str = str(finding.get("poe_verification_status") or finding.get("status") or "").strip().lower()
    ver_status_str = str(finding.get("verification_status") or finding.get("verdict") or "").strip().upper()
    z3_status = str(finding.get("z3_status") or "").strip().lower()

    is_refuted = bool(refuted) or claim_refuted or bool(finding.get("false_positive") is True) or (
        z3_status == "unsat"
    ) or (
        poe_status_str in ("downgraded_false_positive", "refuted")
    ) or (
        ver_status_str in (
            "FALSE_POSITIVE",
            "DOWNGRADED_FALSE_POSITIVE",
            "REFUTED",
            "REJECTED_COMMENT_LINE",
            "REJECTED_REGEX_PATTERN",
            "REJECTED_PLACEHOLDER",
            "REJECTED_CONSTANT_COMMAND",
            "REJECTED_CONSTANT_BINDING",
            "REJECTED_TEST_FIXTURE",
            "DOWNGRADED_PASSIVE_CHAIN",
            "TEST_FIXTURE",
        )
    )

    if is_refuted and not failed:
        if z3_status == "unsat":
            failed.append("z3_smt_unsat_no_exploit_path")
        elif poe_status_str == "downgraded_false_positive":
            failed.append("runtime_poe_container_not_reproduced")
        elif dominating_sanitizer:
            failed.append("dominating_sanitizer_present")
        else:
            failed.append("claim_refuted_by_verifier")

    # Determine independent runtime execution evidence (NEVER satisfied by LLM consensus alone)
    rt_executed = bool(
        runtime_poe_verified
        or finding.get("runtime_poe_executed") is True
        or finding.get("runtime_poe_verified") is True
        or poe_status_str == "verified"
        or str(finding.get("reproduction_tier") or "") in ("TIER_3_CONTAINER_POE", "TIER_3_RUNTIME_REPLAY")
        or (int(finding.get("differential_trials_passed") or 0) >= 3)
        or (poe_level >= 3 and bool(finding.get("reproduced")) and bool(indep))
    )
    rt_passed = bool(
        runtime_poe_verified
        or finding.get("runtime_poe_passed") is True
        or finding.get("runtime_poe_verified") is True
        or poe_status_str == "verified"
        or (int(finding.get("differential_trials_passed") or 0) >= 3)
        or (poe_level >= 3 and bool(finding.get("verified") is True or finding.get("reproduced") is True) and bool(indep))
    )
    if runtime_poe_verified:
        poe_level = max(poe_level, 3)
        if "runtime_poe_container" not in indep and "runtime_3trial_wire" not in indep:
            indep.append("runtime_poe_container")
        satisfied.append("runtime_poe_verified")

    # Determine independent static/formal invariant witness
    has_concrete_witness = bool(
        static_invariant_verified
        or claim_static_witness
        or (z3_status == "sat" and bool(finding.get("z3_witness") or finding.get("counterexample_witness")))
    )
    if static_invariant_verified and not indep:
        indep.append("ast_invariant")
    if has_concrete_witness and not claim_unresolved:
        satisfied.append("static_invariant_witness")

    # Record missing obligations transparently
    if poe_status_str == "skipped_docker_unavailable":
        missing.append("docker_unavailable")
        missing.append("runtime_poe_not_executed")
    elif not rt_executed and not has_concrete_witness and not is_refuted:
        missing.append("runtime_poe_not_executed")

    if not indep and not is_refuted:
        missing.append("independent_oracle_missing")
        if corr:
            missing.append("correlated_llm_agreement_cannot_promote")

    if str(finding.get("evidence_lane") or "").upper() in ("SPECULATIVE_HYPOTHESIS", "LLM_HEURISTIC") and not has_concrete_witness and not rt_passed:
        missing.append("static_or_runtime_proof_missing")

    if claim_unresolved and not any("unproven" in m or "missing" in m or "not_executed" in m for m in missing):
        missing.append("caller_sanitization_unproven")

    indep_clean = _dedupe_str_list(o for o in indep if not is_correlated_oracle_name(o))
    corr_clean = _dedupe_str_list(corr)
    satisfied_clean = _dedupe_str_list(satisfied)
    failed_clean = _dedupe_str_list(failed)
    missing_clean = _dedupe_str_list(missing)

    # Clear runtime_poe_not_executed if we HAVE a verified static/formal witness with no unresolved obligations
    if has_concrete_witness and not claim_unresolved and not is_refuted and not dominating_sanitizer and indep_clean:
        missing_for_gate = [
            m for m in missing_clean
            if m not in ("runtime_poe_not_executed", "docker_unavailable")
        ]
    elif rt_executed and rt_passed and poe_level >= 3 and not is_refuted and indep_clean:
        missing_for_gate = [
            m for m in missing_clean
            if m not in ("runtime_poe_not_executed", "docker_unavailable")
        ]
    else:
        missing_for_gate = list(missing_clean)

    final_state = evaluate_epistemic_transition(
        independent_oracles_count=len(indep_clean),
        correlated_llm_oracles_count=len(corr_clean),
        poe_level=poe_level,
        runtime_poe_executed=rt_executed,
        runtime_poe_passed=rt_passed,
        static_invariant_witness=has_concrete_witness and not claim_unresolved,
        dominating_sanitizer_found=dominating_sanitizer,
        refuted=is_refuted,
        missing_obligations_count=len(missing_for_gate),
    )

    if final_state == EpistemicStatus.UNRESOLVED.value and not missing_clean:
        missing_clean.append("proof_obligations_incomplete")

    return StatusJustification(
        epistemic_status=final_state,
        satisfied_checks=satisfied_clean,
        failed_checks=failed_clean,
        missing_evidence=missing_clean if final_state == EpistemicStatus.UNRESOLVED.value else (
            [] if final_state == EpistemicStatus.PROVEN_RUNTIME.value else missing_clean
        ),
        independent_oracles=indep_clean,
        correlated_oracles=corr_clean,
    ).to_dict()


def attach_epistemic_metadata(
    finding: Dict[str, Any],
    justification: Optional[Dict[str, Any]] = None,
    *,
    claim_result: Optional[Any] = None,
    runtime_poe_verified: bool = False,
    static_invariant_verified: bool = False,
    refuted: bool = False,
) -> Dict[str, Any]:
    """
    Attaches canonical `epistemic_status` and `status_justification` onto a finding dict
    and enforces the hard fail-closed cap: findings with empty `independent_oracles` or
    `UNRESOLVED`/`REFUTED` state can NEVER carry `VERIFIED_EXPLOIT` / `PROVEN_*`.
    """
    j = (
        dict(justification)
        if isinstance(justification, dict) and "epistemic_status" in justification
        else derive_epistemic_status(
            finding,
            claim_result=claim_result,
            runtime_poe_verified=runtime_poe_verified,
            static_invariant_verified=static_invariant_verified,
            refuted=refuted,
        )
    )

    # Re-enforce the Lean 4 hard cap even if caller supplied a custom justification dict
    indep = _dedupe_str_list(
        o for o in (j.get("independent_oracles") or []) if not is_correlated_oracle_name(str(o))
    )
    corr = _dedupe_str_list(
        list(j.get("correlated_oracles") or [])
        + [str(o) for o in (j.get("independent_oracles") or []) if is_correlated_oracle_name(str(o))]
    )
    ep = str(j.get("epistemic_status") or EpistemicStatus.UNRESOLVED.value).upper()
    if ep not in ALL_EPISTEMIC_STATUSES:
        ep = EpistemicStatus.UNRESOLVED.value
    if ep in (EpistemicStatus.PROVEN_RUNTIME.value, EpistemicStatus.PROVEN_STATIC_INVARIANT.value) and not indep:
        ep = EpistemicStatus.UNRESOLVED.value
        miss = list(j.get("missing_evidence") or [])
        miss.append("independent_oracle_missing")
        if corr:
            miss.append("correlated_llm_agreement_cannot_promote")
        j["missing_evidence"] = _dedupe_str_list(miss)

    j["epistemic_status"] = ep
    j["independent_oracles"] = indep
    j["correlated_oracles"] = corr
    j["satisfied_checks"] = _dedupe_str_list(j.get("satisfied_checks") or [])
    j["failed_checks"] = _dedupe_str_list(j.get("failed_checks") or [])
    j["missing_evidence"] = _dedupe_str_list(j.get("missing_evidence") or [])

    finding["epistemic_status"] = ep
    finding["status_justification"] = j

    # Hard-cap legacy promotion labels so no LLM-only or refuted finding leaks as VERIFIED_EXPLOIT
    if ep == EpistemicStatus.REFUTED.value:
        if str(finding.get("evidence_lane") or "").upper() == "VERIFIED_EXPLOIT":
            finding["evidence_lane"] = "REFUTED"
        if str(finding.get("finding_tier") or "").upper() == "VERIFIED_EXPLOIT":
            finding["finding_tier"] = "REFUTED"
        finding["false_positive"] = True
        if int(finding.get("poe_level") or 0) >= 3:
            finding["poe_level"] = 0
    elif ep == EpistemicStatus.UNRESOLVED.value:
        if not indep:
            if str(finding.get("evidence_lane") or "").upper() == "VERIFIED_EXPLOIT":
                finding["evidence_lane"] = "LLM_HEURISTIC"
            if str(finding.get("finding_tier") or "").upper() == "VERIFIED_EXPLOIT":
                finding["finding_tier"] = "MANUAL_REVIEW_LEAD"
            if int(finding.get("poe_level") or 0) >= 3:
                finding["poe_level"] = 1
            if str(finding.get("verification_status") or "").upper() in ("VERIFIED", "VERIFIED_EXPLOIT"):
                finding["verification_status"] = "UNRESOLVED"

    return finding


def enrich_sarif_result_epistemic(sarif_result: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures every SARIF 2.1.0 result carries `properties.epistemic_status` and `properties.status_justification`."""
    enriched_finding = attach_epistemic_metadata(dict(finding))
    props = sarif_result.setdefault("properties", {})
    props["epistemic_status"] = enriched_finding["epistemic_status"]
    props["status_justification"] = enriched_finding["status_justification"]
    if enriched_finding["epistemic_status"] == EpistemicStatus.REFUTED.value:
        sarif_result["level"] = "note"
    elif enriched_finding["epistemic_status"] == EpistemicStatus.UNRESOLVED.value and not enriched_finding["status_justification"]["independent_oracles"]:
        sarif_result["level"] = "note"
    return sarif_result


__all__ = [
    "ALL_EPISTEMIC_STATUSES",
    "EpistemicStatus",
    "INDEPENDENT_ORACLE_KINDS",
    "StatusJustification",
    "attach_epistemic_metadata",
    "can_promote_to_proven_runtime",
    "derive_epistemic_status",
    "enrich_sarif_result_epistemic",
    "evaluate_epistemic_transition",
    "is_correlated_oracle_name",
    "map_legacy_label_to_epistemic",
]
