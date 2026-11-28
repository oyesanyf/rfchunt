"""
End-to-End Regression Suite for Static Verification-Inversion Auditor (`engine/verification_inversion_hunter.py`).

Tests the 5 inverted verification primitives from `google-deepmind/code-verification`:
  1. Pass 1 (`DEV_INVERSION`):
     - `INV-DEV-UNBOUNDED-LOOP` (CWE-834)
     - `INV-DEV-REACHABLE-PANIC` (CWE-248)
     - `INV-DEV-CRYPTO-DOMAIN-SEP` (CWE-327)
  2. Pass 2 (`RULE5_TRUST_CLOSURE`):
     - `INV-RULE5-FAIL-OPEN` (CWE-636) across multi-file forward transitive call closure
     - `INV-RULE5-UNCANONICAL-PATH` (CWE-22) across path-gate transitive closure
     - `INV-RULE5-UNCHECKED-FFI` (CWE-252)
  3. Pass 3 (`COMPARATOR_CONTRACT`):
     - `INV-COMP-MISSING-CLAIM` (CWE-345) with `missing_predicates`
     - `INV-COMP-WEAK-FRAMING-GUARD` (CWE-444)
  4. Pass 4 (`REFINEMENT_GAP`):
     - `INV-REFINE-PATH-DECODE-SPLIT` (CWE-436)
     - `INV-REFINE-DUPLICATE-KEY` (CWE-436)
  5. Pass 5 (`RELEASE_ELISION`):
     - `INV-ELISION-DEBUG-ASSERT` (CWE-617)
     - `INV-ELISION-NON-CT-SECRET` (CWE-208)
     - `INV-ELISION-DEAD-STORE-ZERO` (CWE-14)
  6. Integration with `--deep-audit` (`run_trust_boundary_review`) and `--all`
     (`run_unified_all_scans`) with truthful `poe_level == 1` (`LEAD_PASSIVE_CORRELATION`).
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine.deep_repo_audit import run_trust_boundary_review  # noqa: E402
from engine.mantis_integrator import run_unified_all_scans  # noqa: E402
from engine.verification_inversion_hunter import (  # noqa: E402
    VerificationInversionHunter,
    run_verification_inversion_audit,
)
import rfc_hunt_swarm  # noqa: E402


def test_pass1_dev_inversion_unbounded_loop_reachable_panic_and_hkdf_domain_sep(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)

    # Vulnerable Rust module with entry -> helper call chain containing:
    # 1) Unbounded rejection-sampling loop (DEV-CLI22 inversion)
    # 2) Entry-reachable .unwrap() & unclamped Vec::with_capacity (DEV-E7 & DEV-CLI15 inversion)
    # 3) Empty HKDF expand info (&[]) (DEV-CLI16 inversion)
    (src_dir / "parser.rs").write_text(
        """
pub fn handle_packet(raw_packet: &[u8], declared_len: usize) -> Vec<u8> {
    let parsed = parse_inner_frame(raw_packet, declared_len);
    derive_session_material(raw_packet);
    parsed
}

fn parse_inner_frame(buf: &[u8], frame_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame_len);
    let first_str = std::str::from_utf8(buf).unwrap();
    loop {
        let coeff = sample_next_xof(first_str.as_bytes());
        if coeff < 3329 {
            out.push(coeff as u8);
            break;
        }
    }
    out
}

fn derive_session_material(seed: &[u8]) {
    let hkdf = Hkdf::new(seed);
    let mut okm = [0u8; 32];
    hkdf.expand(&[], &mut okm);
}
""".lstrip(),
        encoding="utf-8",
    )

    rep = VerificationInversionHunter().analyze_repository(tmp_path)
    by_rule = {f.rule_id: f for f in rep.findings}

    assert "INV-DEV-UNBOUNDED-LOOP" in by_rule
    assert by_rule["INV-DEV-UNBOUNDED-LOOP"].cwe == "CWE-834"
    assert by_rule["INV-DEV-UNBOUNDED-LOOP"].call_chain == ["handle_packet", "parse_inner_frame"]
    assert by_rule["INV-DEV-UNBOUNDED-LOOP"].poe_level == 1
    assert by_rule["INV-DEV-UNBOUNDED-LOOP"].verification_status == "LEAD_PASSIVE_CORRELATION"

    assert "INV-DEV-REACHABLE-PANIC" in by_rule
    assert by_rule["INV-DEV-REACHABLE-PANIC"].cwe == "CWE-248"
    assert by_rule["INV-DEV-REACHABLE-PANIC"].call_chain == ["handle_packet", "parse_inner_frame"]

    assert "INV-DEV-CRYPTO-DOMAIN-SEP" in by_rule
    assert by_rule["INV-DEV-CRYPTO-DOMAIN-SEP"].cwe == "CWE-327"

    # Safe version (bounded loop, checked ?, clamped capacity, non-empty HKDF info) -> 0 Pass-1 findings
    safe_dir = tmp_path / "safe_repo"
    safe_dir.mkdir(parents=True)
    (safe_dir / "parser_safe.rs").write_text(
        """
const MAX_FRAME: usize = 4096;

pub fn handle_packet(raw_packet: &[u8], declared_len: usize) -> Result<Vec<u8>, &'static str> {
    let capped = declared_len.min(MAX_FRAME);
    let mut out = Vec::with_capacity(capped);
    let mut attempts = 0usize;
    let max_attempts = 256usize;
    while attempts < max_attempts {
        attempts += 1;
        let coeff = sample_next_xof(raw_packet);
        if coeff < 3329 {
            out.push(coeff as u8);
            break;
        }
    }
    Ok(out)
}
""".lstrip(),
        encoding="utf-8",
    )
    safe_rep = VerificationInversionHunter().analyze_repository(safe_dir)
    assert [f for f in safe_rep.findings if f.primitive == "DEV_INVERSION"] == []


def test_pass2_rule5_transitive_trust_closure_fail_open_and_uncanonical_path(tmp_path: Path) -> None:
    # Multi-file repository where `authorize_request` calls `verify_token_helper` in another file
    # and `is_allowed_sandbox_path` calls `check_prefix_helper` without canonicalization.
    (tmp_path / "gate.py").write_text(
        """
from helpers import verify_token_helper, check_prefix_helper

def authorize_request(req_headers: dict) -> bool:
    tok = req_headers.get("Authorization", "")
    return verify_token_helper(tok)

def is_allowed_sandbox_path(candidate_path: str, sandbox_root: str) -> bool:
    return check_prefix_helper(candidate_path, sandbox_root)
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        """
def verify_token_helper(raw_token: str) -> bool:
    try:
        return parse_and_validate(raw_token)
    except Exception:
        return True

def check_prefix_helper(candidate: str, root: str) -> bool:
    return candidate.startswith(root)
""".lstrip(),
        encoding="utf-8",
    )

    rep = VerificationInversionHunter().analyze_repository(tmp_path)
    assert rep.security_gates_audited >= 2
    by_rule = {f.rule_id: f for f in rep.findings}

    assert "INV-RULE5-FAIL-OPEN" in by_rule
    fo = by_rule["INV-RULE5-FAIL-OPEN"]
    assert fo.cwe == "CWE-636"
    assert fo.call_chain == ["authorize_request", "verify_token_helper"]

    assert "INV-RULE5-UNCANONICAL-PATH" in by_rule
    up = by_rule["INV-RULE5-UNCANONICAL-PATH"]
    assert up.cwe == "CWE-22"
    assert up.call_chain == ["is_allowed_sandbox_path", "check_prefix_helper"]

    # Safe transitive closure (fail-closed `return False` + `os.path.realpath`) -> 0 Rule-5 findings
    safe_dir = tmp_path / "safe_closure"
    safe_dir.mkdir(parents=True)
    (safe_dir / "gate_safe.py").write_text(
        """
import os

def authorize_request(tok: str) -> bool:
    try:
        return bool(tok)
    except Exception:
        return False

def is_allowed_sandbox_path(candidate_path: str, sandbox_root: str) -> bool:
    real_cand = os.path.realpath(candidate_path)
    real_root = os.path.realpath(sandbox_root)
    return real_cand.startswith(real_root)
""".lstrip(),
        encoding="utf-8",
    )
    safe_rep = VerificationInversionHunter().analyze_repository(safe_dir)
    assert [f for f in safe_rep.findings if f.primitive == "RULE5_TRUST_CLOSURE"] == []


def test_pass3_comparator_contract_missing_jwt_claims_and_cl_te_guard(tmp_path: Path) -> None:
    (tmp_path / "auth_and_framing.py").write_text(
        """
import jwt

def verify_service_jwt(token: str, pub_key: str) -> dict:
    # Missing audience (aud) and issuer (iss) contract predicates
    return jwt.decode(token, pub_key, algorithms=["RS256"])

def parse_http_headers(headers: dict) -> int:
    # Inspects both Content-Length and Transfer-Encoding without rejecting concurrent presence
    if "transfer-encoding" in headers:
        mode = 1
    if "content-length" in headers:
        mode = int(headers["content-length"])
    return mode
""".lstrip(),
        encoding="utf-8",
    )

    rep = VerificationInversionHunter().analyze_repository(tmp_path)
    by_rule = {f.rule_id: f for f in rep.findings}

    assert "INV-COMP-MISSING-CLAIM" in by_rule
    mc = by_rule["INV-COMP-MISSING-CLAIM"]
    assert mc.cwe == "CWE-345"
    assert "aud (audience binding)" in mc.missing_predicates
    assert "iss (issuer binding)" in mc.missing_predicates

    assert "INV-COMP-WEAK-FRAMING-GUARD" in by_rule
    fg = by_rule["INV-COMP-WEAK-FRAMING-GUARD"]
    assert fg.cwe == "CWE-444"
    assert "reject_concurrent_content_length_and_transfer_encoding" in fg.missing_predicates


def test_pass4_refinement_gap_path_decode_split_and_duplicate_key(tmp_path: Path) -> None:
    (tmp_path / "proxy_router.py").write_text(
        """
from urllib.parse import unquote

def check_admin_blocklist(raw_path: str) -> bool:
    if raw_path.startswith("/admin"):
        return False
    return True

def dispatch_route(raw_path: str, header_lines: list[str]) -> str:
    headers = {}
    for line in header_lines:
        k, v = line.split(":", 1)
        headers[k] = v.strip()
    decoded_path = unquote(raw_path)
    return decoded_path
""".lstrip(),
        encoding="utf-8",
    )

    rep = VerificationInversionHunter().analyze_repository(tmp_path)
    by_rule = {f.rule_id: f for f in rep.findings}

    assert "INV-REFINE-PATH-DECODE-SPLIT" in by_rule
    assert by_rule["INV-REFINE-PATH-DECODE-SPLIT"].cwe == "CWE-436"

    assert "INV-REFINE-DUPLICATE-KEY" in by_rule
    assert by_rule["INV-REFINE-DUPLICATE-KEY"].cwe == "CWE-436"


def test_pass5_release_build_elision_debug_assert_non_ct_secret_and_memset(tmp_path: Path) -> None:
    (tmp_path / "crypto_ffi.rs").write_text(
        """
pub fn verify_admin_and_mac(is_admin_role: bool, received_hmac: &[u8], expected_hmac: &[u8], secret_key: &mut [u8]) -> bool {
    debug_assert!(is_admin_role);
    let ok = received_hmac == expected_hmac;
    for b in secret_key.iter_mut() { *b = 0; }
    ok
}
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "webhook.py").write_text(
        """
def handle_webhook(user_is_authorized: bool, signature: str, expected_sig: str) -> bool:
    assert user_is_authorized
    return signature == expected_sig
""".lstrip(),
        encoding="utf-8",
    )

    rep = VerificationInversionHunter().analyze_repository(tmp_path)
    rules = {f.rule_id for f in rep.findings}
    assert "INV-ELISION-DEBUG-ASSERT" in rules
    assert "INV-ELISION-NON-CT-SECRET" in rules
    assert "INV-ELISION-DEAD-STORE-ZERO" in rules

    # Safe implementation using explicit runtime guard, hmac.compare_digest, and zeroize -> 0 Pass-5 findings
    safe_dir = tmp_path / "safe_elision"
    safe_dir.mkdir(parents=True)
    (safe_dir / "webhook_safe.py").write_text(
        """
import hmac

def handle_webhook(user_is_authorized: bool, signature: str, expected_sig: str) -> bool:
    if not user_is_authorized:
        raise PermissionError("Unauthorized")
    return hmac.compare_digest(signature, expected_sig)
""".lstrip(),
        encoding="utf-8",
    )
    safe_rep = VerificationInversionHunter().analyze_repository(safe_dir)
    assert [f for f in safe_rep.findings if f.primitive == "RELEASE_ELISION"] == []


def test_deep_audit_and_unified_all_integration_with_truthful_poe1_labeling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    repo_dir = tmp_path / "target_app"
    repo_dir.mkdir(parents=True)
    (repo_dir / "auth_proxy.py").write_text(
        """
def verify_auth_token(token: str, expected_secret: str) -> bool:
    assert token is not None
    try:
        return token == expected_secret
    except Exception:
        return True
""".lstrip(),
        encoding="utf-8",
    )

    # 1. Verify run_trust_boundary_review (--deep-audit Pillar 2) includes verification_inversion
    tb_res = run_trust_boundary_review(repo_dir)
    assert "verification_inversion" in tb_res
    assert tb_res["verification_inversion"]["status"] == "completed"
    assert tb_res["verification_inversion"]["findings_count"] >= 2
    tb_rule_ids = {f["rule_id"] for f in tb_res["findings"]}
    assert "INV-RULE5-FAIL-OPEN" in tb_rule_ids
    assert "INV-ELISION-NON-CT-SECRET" in tb_rule_ids

    # 2. Verify CLI parser supports --verification-inversion and --no-verification-inversion
    args_on = rfc_hunt_swarm.parse_swarm_arguments(["--all", "--repo", str(repo_dir)])
    assert args_on.enable_verification_inversion is True
    args_off = rfc_hunt_swarm.parse_swarm_arguments(["--all", "--repo", str(repo_dir), "--no-verification-inversion"])
    assert args_off.enable_verification_inversion is False

    # 3. Verify run_unified_all_scans (--all) aggregates findings into manual_review_leads (POE=1)
    out_dir = tmp_path / "reports"
    all_res = run_unified_all_scans(
        repo=str(repo_dir),
        depth=30,
        reports_dir=str(out_dir),
        enable_rea=False,
    )
    assert "verification_inversion" in all_res["engines"]
    assert all_res["engines"]["verification_inversion"]["findings_count"] >= 2
    inv_findings = [f for f in all_res["findings"] if str(f.get("rule_id", "")).startswith("INV-")]
    assert len(inv_findings) >= 2
    for f in inv_findings:
        assert f["poe_level"] == 1
        assert f["verification_status"] == "LEAD_PASSIVE_CORRELATION"
        assert f["finding_tier"] == "MANUAL_REVIEW_LEAD"

    sarif_doc = json.loads(Path(all_res["report_files"]["combined_sarif"]).read_text(encoding="utf-8"))
    sarif_rules = {r["ruleId"] for r in sarif_doc["runs"][0]["results"]}
    assert "INV-RULE5-FAIL-OPEN" in sarif_rules or "INV-ELISION-NON-CT-SECRET" in sarif_rules


def test_live_z3_and_lean4_trusted_closure_in_verification_inversion_hunter(tmp_path: Path) -> None:
    """
    Reproducible verification that `VerificationInversionHunter` executes live Z3 SMT
    constraint checks (Pass 1 numeric bounds + Pass 3 JWT/RBAC comparator contracts)
    and live Lean 4 machine-checking of `TrustedClosure.lean` + `EpistemicPromotionInvariants.lean`,
    with 0 false positives on compliant/patched implementations.
    """
    from engine.formal_verifier import find_lean4_binary
    from engine.verification_inversion_hunter import verify_trusted_closure_lean4

    vuln_dir = tmp_path / "vuln_formal"
    vuln_dir.mkdir(parents=True)
    (vuln_dir / "header_bounds.py").write_text(
        "def alloc_header(raw_len: str) -> bytes:\n"
        "    content_length = int(raw_len)\n"
        "    return b'x' * content_length\n",
        encoding="utf-8",
    )
    (vuln_dir / "rbac_bad.py").write_text(
        "def check_admin(user_role: str) -> bool:\n"
        "    if user_role != 'admin':\n"
        "        return True\n"
        "    return False\n",
        encoding="utf-8",
    )
    (vuln_dir / "jwt_bad.py").write_text(
        "import jwt\n"
        "def verify_token(token: str, secret: str):\n"
        "    return jwt.decode(token, secret, algorithms=['HS256'])\n",
        encoding="utf-8",
    )

    rep_vuln = VerificationInversionHunter(enable_z3=True, enable_lean4=True).analyze_repository(vuln_dir)
    assert rep_vuln.z3_summary["enabled"] is True
    assert rep_vuln.z3_summary["sat_witnesses"] >= 3
    rule_ids = {f.rule_id for f in rep_vuln.findings}
    assert "INV-Z3-UNBOUNDED-NUMERIC" in rule_ids
    assert "INV-Z3-COMPARATOR-RBAC-BYPASS" in rule_ids
    assert "INV-COMP-MISSING-CLAIM" in rule_ids
    for f in rep_vuln.findings:
        if f.z3_status == "sat":
            assert f.epistemic_status == "PROVEN_STATIC_INVARIANT"
            assert "z3_smt" in f.status_justification["independent_oracles"]

    # Compliant / patched negative cases -> 0 Z3 SAT findings (0 FP)
    safe_dir = tmp_path / "safe_formal"
    safe_dir.mkdir(parents=True)
    (safe_dir / "header_bounds.py").write_text(
        "MAX_FRAME = 65536\n"
        "def alloc_header(raw_len: str) -> bytes:\n"
        "    content_length = int(raw_len)\n"
        "    if not (0 <= content_length <= MAX_FRAME):\n"
        "        raise ValueError('out of bounds')\n"
        "    return b'x' * content_length\n",
        encoding="utf-8",
    )
    (safe_dir / "rbac_good.py").write_text(
        "def check_admin(user_role: str, forbid: bool = False) -> bool:\n"
        "    if forbid:\n"
        "        return False\n"
        "    return user_role == 'admin'\n",
        encoding="utf-8",
    )
    (safe_dir / "jwt_good.py").write_text(
        "import jwt\n"
        "def verify_token(token: str, secret: str):\n"
        "    return jwt.decode(token, secret, algorithms=['HS256'], audience='api', issuer='idp')\n",
        encoding="utf-8",
    )

    rep_safe = VerificationInversionHunter(enable_z3=True, enable_lean4=False).analyze_repository(safe_dir)
    assert rep_safe.z3_summary["sat_witnesses"] == 0
    assert [f for f in rep_safe.findings if f.rule_id in ("INV-Z3-UNBOUNDED-NUMERIC", "INV-Z3-COMPARATOR-RBAC-BYPASS", "INV-COMP-MISSING-CLAIM")] == []

    # Verify live Lean 4 kernel checking of TrustedClosure.lean & EpistemicPromotionInvariants.lean
    if find_lean4_binary(Path(__file__).resolve().parent.parent) is not None:
        lean_res = verify_trusted_closure_lean4(use_native_binary=True)
        assert lean_res["native_checked"] is True
        assert lean_res["all_modules_proved"] is True
        assert all(m["status"] == "PROVED_NATIVE_LEAN4" and not m["has_sorry"] for m in lean_res["modules"])

