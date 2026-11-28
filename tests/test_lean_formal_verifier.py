"""
Unit tests for RFCHunt's Lean 4 formal specifications and Python hybrid bridge.
"""

from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import engine.lean_formal_verifier as lfv
from engine.lean_formal_verifier import (
    LeanCounterexample,
    LeanDomainReport,
    LeanProofDiagnostic,
    _parse_lake_diagnostics,
    audit_lean_file,
    dotnet_pe_integrity_mirror,
    evaluate_lean_domains,
    evaluate_policy_mirror,
    evaluate_policy_verified,
    find_lean_oracle_binary,
    permissive_cl_first_proxy_mirror,
    reconcile_verdict_mirror,
    run_differential_parity_check,
    strict_rfc9112_oracle,
    verify_dotnet_pe_invariant,
    verify_http_framing_invariant,
    verify_lean_workspace,
    verify_policy_guard_invariant,
)


def _lean_root() -> Path:
    p = Path("formal/lean4")
    if p.is_dir():
        return p
    return Path("D:/harfile/rfchunt/formal/lean4")


def test_lean4_workspace_has_zero_sorry_and_all_11_proven_theorems():
    report = verify_lean_workspace(_lean_root())
    assert report.status in ("machine_checked", "static_audited_lean_not_installed")
    assert len(report.modules) == 3
    assert report.total_theorems == 11
    for mod in report.modules:
        assert mod.has_sorry is False
        assert mod.has_custom_axiom is False
        assert mod.clean_proofs is True


def test_lean_audit_catches_sorry_cheat(tmp_path: Path):
    bad = tmp_path / "Bad.lean"
    bad.write_text("theorem fake : True := by sorry\n", encoding="utf-8")
    res = audit_lean_file(bad)
    assert res.has_sorry is True
    assert res.clean_proofs is False


def test_policy_guard_mirror_matches_lean_theorems():
    # forbid_overrides_permit
    assert (
        evaluate_policy_mirror(
            action="networkProbe",
            scope="inScopeAuthorized",
            in_workspace_root=True,
            allow_destructive=True,
            rules=[("permit", True), ("forbid", True)],
        )
        is False
    )
    # shell_exec_never_permitted
    assert (
        evaluate_policy_mirror(
            action="shellExec",
            scope="inScopeAuthorized",
            in_workspace_root=True,
            allow_destructive=True,
            rules=[("permit", True)],
        )
        is False
    )
    # out_of_scope_probe_always_denied
    assert (
        evaluate_policy_mirror(
            action="networkProbe",
            scope="privateOrLoopbackBlocked",
            in_workspace_root=True,
            allow_destructive=False,
            rules=[("permit", True)],
        )
        is False
    )
    # outside_workspace_read_denied
    assert (
        evaluate_policy_mirror(
            action="readWorkspaceFile",
            scope="inScopeAuthorized",
            in_workspace_root=False,
            allow_destructive=False,
            rules=[("permit", True)],
        )
        is False
    )
    # deterministic_confirmation_immutable
    assert reconcile_verdict_mirror(True, False) is True
    assert reconcile_verdict_mirror(True, True) is True


def test_http_framing_oracle_mirror_matches_lean_theorems():
    # strict_rejects_cl_te_conflict
    assert strict_rfc9112_oracle([42], True) == ("reject400", None)
    # strict_rejects_mismatched_dual_cl
    assert strict_rfc9112_oracle([10, 20], False) == ("reject400", None)
    # differential_witness_cl_te
    assert strict_rfc9112_oracle([42], True) != permissive_cl_first_proxy_mirror([42], True)


def test_compiled_lean4_oracle_and_exhaustive_differential_parity():
    root = _lean_root()
    allowed, backend = evaluate_policy_verified(
        action="shellExec",
        scope="inScopeAuthorized",
        in_workspace_root=True,
        allow_destructive=True,
        rules=[("permit", True)],
        lean_dir=root,
    )
    assert allowed is False
    if find_lean_oracle_binary(root) is not None:
        assert backend == "lean4_compiled_binary"
        diff = run_differential_parity_check(root)
        assert diff["status"] == "passed", f"Lean vs Python divergence: {diff['divergences']}"
        assert diff["cases_checked"] >= 300
        assert diff["divergences"] == []
    else:
        assert backend == "python_mirror"
        # Exhaustively check DotNetPeIntegrity mirror invariants even offline
        anom, unp, pat = dotnet_pe_integrity_mirror(
            is_valid_pe=True,
            has_clr_descriptor=True,
            has_executable_image_bit=False,
            is_umci_enforced=True,
            is_signed_by_trusted_publisher=False,
        )
        assert anom is True
        assert unp == "loadedViaUncheckedFlatMemoryFallback"
        assert pat == "rejectedInvalidOrUnsigned"


# ---------------------------------------------------------------------------
# M1 Extended Unit Tests: Diagnostics, Domain Invariants & Degradation
# ---------------------------------------------------------------------------


def test_parse_lake_diagnostics_formats(tmp_path: Path):
    sample_lean = tmp_path / "RFCHunt" / "PolicyGuard.lean"
    sample_lean.parent.mkdir(parents=True, exist_ok=True)
    sample_lean.write_text(
        "\n".join(
            [
                "theorem shell_exec_never_permitted : True := by",
                "  trivial",
                "theorem forbid_overrides_permit : False := by",
                "  trivial",
            ]
        ),
        encoding="utf-8",
    )

    stderr = "\n".join(
        [
            "error: RFCHunt/PolicyGuard.lean:4:2: unsolved goals",
            "case inl",
            "h : True",
            "⊢ False",
            r"D:\harfile\rfchunt\formal\lean4\RFCHunt\HttpFramingOracle.lean:63:4: error: type mismatch",
            "  rfl",
            "has type Bool but is expected to have type Nat",
            "RFCHunt/DotNetPeIntegrity.lean:58:2: warning: declaration uses 'sorry'",
            "error: RFCHunt/PolicyGuard.lean:2:10: unknown identifier 'fooBar'",
            "RFCHunt/PolicyGuard.lean:2:2: error: tactic 'simp' failed, nested error",
            "error: build failed",
        ]
    )
    diags = _parse_lake_diagnostics("", stderr, lean_dir=tmp_path)
    kinds = [d.kind for d in diags]
    assert "unsolved_goals" in kinds
    assert "type_mismatch" in kinds
    assert "sorry" in kinds
    assert "unknown_identifier" in kinds
    assert "tactic_failed" in kinds

    unsolved = next(d for d in diags if d.kind == "unsolved_goals")
    assert unsolved.module == "RFCHunt.PolicyGuard"
    assert unsolved.theorem == "forbid_overrides_permit"
    assert unsolved.line == 4
    assert unsolved.column == 2
    assert "inl" in unsolved.branch_summary
    assert "⊢ False" in unsolved.branch_summary

    tm = next(d for d in diags if d.kind == "type_mismatch")
    assert tm.module == "RFCHunt.HttpFramingOracle"
    assert tm.line == 63

    # Fallback when no .lean:<line>:<col> header exists
    fallback = _parse_lake_diagnostics("", "error: deterministic timeout after 120s")
    assert len(fallback) == 1
    assert fallback[0].kind == "timeout"
    assert fallback[0].module == "lake"


def test_verify_lean_workspace_proof_integrity_violation_populates_diagnostics(tmp_path: Path):
    pkg = tmp_path / "RFCHunt"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "WithSorry.lean").write_text(
        "-- sorry in comment should be ignored\n"
        "theorem bad_thm : True := by\n"
        "  sorry\n",
        encoding="utf-8",
    )
    (pkg / "WithAxiom.lean").write_text(
        "axiom cheat_ax : False\n"
        "theorem ok_thm : True := by trivial\n",
        encoding="utf-8",
    )
    (pkg / "EmptyThms.lean").write_text("def helper : Nat := 1\n", encoding="utf-8")

    rep = verify_lean_workspace(tmp_path)
    assert rep.status == "proof_integrity_violation"
    assert rep.machine_checked is False
    kinds = {d.kind for d in rep.diagnostics}
    assert {"sorry", "custom_axiom", "zero_theorems"}.issubset(kinds)

    sorry_diag = next(d for d in rep.diagnostics if d.kind == "sorry")
    assert sorry_diag.line == 3
    assert sorry_diag.theorem == "bad_thm"
    assert sorry_diag.module == "RFCHunt.WithSorry"

    as_dict = rep.to_dict()
    assert isinstance(as_dict["diagnostics"], list)
    assert len(as_dict["diagnostics"]) >= 3

    # Also test missing_modules case
    empty_dir = tmp_path / "empty_ws"
    empty_dir.mkdir()
    missing_rep = verify_lean_workspace(empty_dir)
    assert missing_rep.status == "proof_integrity_violation"
    assert missing_rep.diagnostics[0].kind == "missing_modules"


def test_verify_lean_workspace_kernel_failed_populates_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    pkg = tmp_path / "RFCHunt"
    pkg.mkdir(parents=True, exist_ok=True)
    (tmp_path / "lakefile.lean").write_text("package test\n", encoding="utf-8")
    (pkg / "Sample.lean").write_text("theorem sample_thm : True := by trivial\n", encoding="utf-8")

    monkeypatch.setattr(
        lfv.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in ("lean", "lake") else None,
    )
    monkeypatch.setattr(
        lfv,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=(
                "error: RFCHunt/Sample.lean:1:32: unsolved goals\n"
                "case pos\n"
                "⊢ True\n"
            ),
        ),
    )

    rep = verify_lean_workspace(tmp_path)
    assert rep.status == "kernel_failed"
    assert rep.machine_checked is False
    assert len(rep.diagnostics) == 1
    assert rep.diagnostics[0].kind == "unsolved_goals"
    assert rep.diagnostics[0].theorem == "sample_thm"
    assert rep.to_dict()["diagnostics"][0]["kind"] == "unsolved_goals"

    def _raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd=["lake", "build"], timeout=5.0)

    monkeypatch.setattr(lfv, "silent_subprocess_run", _raise_timeout)
    t_rep = verify_lean_workspace(tmp_path, timeout_sec=5.0)
    assert t_rep.status == "kernel_failed"
    assert t_rep.machine_checked is False
    assert len(t_rep.diagnostics) == 1
    assert t_rep.diagnostics[0].kind == "timeout"


def test_http_framing_invariant_evaluates_conflicts_and_clean_cases():
    cl_te = verify_http_framing_invariant(
        content_lengths=[42],
        has_transfer_encoding_chunked=True,
    )
    assert any(c.theorem == "differential_witness_cl_te" and c.violated for c in cl_te)
    assert any(c.theorem == "strict_rejects_cl_te_conflict" and not c.violated for c in cl_te)

    dual_cl = verify_http_framing_invariant(content_lengths=[10, 20])
    assert len(dual_cl) == 1
    assert dual_cl[0].theorem == "strict_rejects_mismatched_dual_cl"
    assert dual_cl[0].violated is True

    bare_lf = verify_http_framing_invariant(has_bare_lf=True)
    assert len(bare_lf) == 1
    assert bare_lf[0].theorem == "strict_rfc9112_bare_lf"
    assert bare_lf[0].violated is True

    clean = verify_http_framing_invariant(content_lengths=[42])
    assert len(clean) == 1
    assert clean[0].violated is False

    with pytest.raises(ValueError):
        verify_http_framing_invariant(content_lengths=[-1])


def test_policy_guard_invariant_all_five_theorems():
    # Compliant mirror evaluations across all 5 theorems -> violated=False
    c1 = verify_policy_guard_invariant(
        action="shellExec", scope="inScopeAuthorized", rules=[("permit", True)]
    )
    c2 = verify_policy_guard_invariant(
        action="networkProbe", scope="outOfScope", rules=[("permit", True)]
    )
    c3 = verify_policy_guard_invariant(
        action="readWorkspaceFile", in_workspace_root=False, rules=[("permit", True)]
    )
    c4 = verify_policy_guard_invariant(
        action="networkProbe",
        scope="inScopeAuthorized",
        rules=[("permit", True), ("forbid", True)],
    )
    c5 = verify_policy_guard_invariant(
        confirmed_by_tool=True, llm_confirmed=False
    )
    for checks in (c1, c2, c3, c4, c5):
        assert all(not c.violated for c in checks)

    assert c1[0].theorem == "shell_exec_never_permitted"
    assert c2[0].theorem == "out_of_scope_probe_always_denied"
    assert c3[0].theorem == "outside_workspace_read_denied"
    assert c4[0].theorem == "forbid_overrides_permit"
    assert any(c.theorem == "deterministic_confirmation_immutable" for c in c5)

    # Violations when observed runtime behavior breaks invariants
    v_shell = verify_policy_guard_invariant(action="shellExec", observed_allowed=True)
    assert v_shell[0].violated is True
    v_rec = verify_policy_guard_invariant(
        confirmed_by_tool=True, llm_confirmed=False, observed_reconciled=False
    )
    assert any(
        c.theorem == "deterministic_confirmation_immutable" and c.violated
        for c in v_rec
    )


def test_dotnet_pe_invariant_cve_2026_108398_and_umci():
    anom = verify_dotnet_pe_invariant(
        is_valid_pe=True,
        has_clr_descriptor=True,
        has_executable_image_bit=False,
        is_umci_enforced=True,
        is_signed_by_trusted_publisher=False,
    )
    assert any(c.theorem == "anomaly_triggers_unpatched_fallback" and c.violated for c in anom)
    assert any(c.theorem == "patched_loader_enforces_umci" and not c.violated for c in anom)

    pe_dict = {
        "is_pe": True,
        "is_executable_image": False,
        "dot_net": {"is_dot_net": True, "clr_header_rva": 0x2008},
        "has_forshaw_cve_2026_108398_anomaly": True,
    }
    from_rep = verify_dotnet_pe_invariant(pe_report=pe_dict)
    assert any(c.violated for c in from_rep)

    clean_signed = verify_dotnet_pe_invariant(
        is_valid_pe=True,
        has_clr_descriptor=True,
        has_executable_image_bit=True,
        is_umci_enforced=True,
        is_signed_by_trusted_publisher=True,
    )
    assert all(not c.violated for c in clean_signed)


def test_evaluate_lean_domains_graceful_degradation_and_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # 1. Clean baseline with no findings & no binary -> zero fabricated violations
    rep_clean = evaluate_lean_domains(findings=None, lean_dir=tmp_path)
    assert isinstance(rep_clean, LeanDomainReport)
    assert rep_clean.oracle_backend == "python_mirror"
    assert rep_clean.machine_checked is False
    assert rep_clean.status == "passed"
    assert rep_clean.violations_count == 0
    assert rep_clean.degradation_reason
    assert set(rep_clean.domains_checked) == {"http_framing", "policy_guard", "dotnet_pe"}
    assert set(rep_clean.domain_checks.keys()) == {"http_framing", "policy_guard", "dotnet_pe"}
    assert len(rep_clean.diagnostics) >= 1  # missing_modules from empty tmp_path

    # 2. Findings trigger counterexamples across all 3 domains
    findings = [
        {
            "rule_id": "HTTP-SMUGGLE-CL-TE",
            "cwe": "CWE-444",
            "title": "CL+TE request smuggling desync",
            "summary": "Proxy honors Content-Length while backend honors Transfer-Encoding",
        },
        {
            "rule_id": "PE-DOTNET-CVE-2026-108398",
            "cwe": "CWE-693",
            "title": ".NET Framework 4 UMCI fallback anomaly",
            "summary": "IMAGE_FILE_EXECUTABLE_IMAGE bit cleared on CLR PE",
        },
        {
            "rule_id": "POLICY-OVERRIDE-01",
            "title": "LLM dissent attempted override of deterministic confirmation",
            "summary": "llm_dissent override_immunity check",
            "metadata": {"observed_reconciled": False},
        },
    ]
    rep_bad = evaluate_lean_domains(findings=findings, lean_dir=_lean_root())
    assert rep_bad.status == "counterexample_found"
    assert rep_bad.violations_count >= 3
    d = rep_bad.to_dict()
    assert len(d["violations"]) == rep_bad.violations_count
    assert d["domain_checks"]["http_framing"]["violations"] >= 1
    assert d["domain_checks"]["dotnet_pe"]["violations"] >= 1
    assert d["domain_checks"]["policy_guard"]["violations"] >= 1
    assert "workspace_report" in d

    # 3. machine_checked MUST stay False if binary exists but lake workspace is not machine_checked
    fake_bin = tmp_path / ".lake" / "build" / "bin" / "rfchunt-lean-oracle.exe"
    fake_bin.parent.mkdir(parents=True, exist_ok=True)
    fake_bin.write_text("stub", encoding="utf-8")
    monkeypatch.setattr(lfv.LeanCompiledOracle, "strict_rfc9112", lambda *a, **kw: ("reject400", None))
    monkeypatch.setattr(lfv.LeanCompiledOracle, "evaluate_policy", lambda *a, **kw: False)
    monkeypatch.setattr(lfv.LeanCompiledOracle, "reconcile_verdict", lambda self, t, l: bool(t or l))
    monkeypatch.setattr(
        lfv.LeanCompiledOracle,
        "evaluate_dotnet_pe",
        lambda self, **kw: dotnet_pe_integrity_mirror(**kw),
    )
    rep_partial = evaluate_lean_domains(findings=None, lean_dir=tmp_path)
    assert rep_partial.oracle_backend == "lean4_compiled_binary"
    assert rep_partial.machine_checked is False
    assert rep_partial.degradation_reason


def test_formal_lean4_models_remain_unmodified_and_complete():
    root = _lean_root()
    expected = {
        "PolicyGuard.lean": {
            "forbid_overrides_permit",
            "shell_exec_never_permitted",
            "out_of_scope_probe_always_denied",
            "outside_workspace_read_denied",
            "deterministic_confirmation_immutable",
        },
        "HttpFramingOracle.lean": {
            "strict_rejects_cl_te_conflict",
            "strict_rejects_mismatched_dual_cl",
            "differential_witness_cl_te",
        },
        "DotNetPeIntegrity.lean": {
            "anomaly_triggers_unpatched_fallback",
            "patched_loader_never_uses_unchecked_fallback",
            "patched_loader_enforces_umci",
        },
    }
    for fname, expected_thms in expected.items():
        audit = audit_lean_file(root / "RFCHunt" / fname)
        assert audit.has_sorry is False
        assert audit.has_custom_axiom is False
        assert audit.clean_proofs is True
        assert set(audit.theorems) == expected_thms


def test_lean_comment_scanner_blocks_line_comment_bypass_and_handles_nested_blocks(tmp_path: Path):
    pkg = tmp_path / "RFCHunt"
    pkg.mkdir(parents=True, exist_ok=True)

    # 1. Anti-cheat bypass attempt: `-- /-` and `-- -/` inside line comments MUST NOT hide sorry/axiom
    bypass = pkg / "Bypass.lean"
    bypass.write_text(
        "theorem ok_thm : True := by trivial\n"
        "-- /-\n"
        "theorem cheat_thm : False := by sorry\n"
        "axiom hidden_ax : False\n"
        "-- -/\n",
        encoding="utf-8",
    )
    audit_bypass = audit_lean_file(bypass)
    assert audit_bypass.has_sorry is True
    assert audit_bypass.has_custom_axiom is True
    assert audit_bypass.clean_proofs is False
    assert audit_bypass.theorems == ["ok_thm", "cheat_thm"]

    rep_bypass = verify_lean_workspace(tmp_path)
    assert rep_bypass.status == "proof_integrity_violation"
    sorry_diag = next(d for d in rep_bypass.diagnostics if d.kind == "sorry")
    ax_diag = next(d for d in rep_bypass.diagnostics if d.kind == "custom_axiom")
    assert sorry_diag.theorem == "cheat_thm"
    assert sorry_diag.line == 3
    assert sorry_diag.column == 33
    assert ax_diag.theorem == "hidden_ax"
    assert ax_diag.line == 4

    # 2. Nested Lean 4 block comments `/- outer /- inner -/ sorry -/` must NOT false-positive
    nested = tmp_path / "NestedOk.lean"
    nested.write_text(
        "/- outer /- inner -/ sorry still in comment\n"
        "   axiom still_in_comment : False -/\n"
        'def label : String := "-- /- not a comment"\n'
        "theorem nested_ok : True := by trivial\n",
        encoding="utf-8",
    )
    audit_nested = audit_lean_file(nested)
    assert audit_nested.has_sorry is False
    assert audit_nested.has_custom_axiom is False
    assert audit_nested.clean_proofs is True
    assert audit_nested.theorems == ["nested_ok"]


def test_lean_audit_masks_string_literals_without_hiding_real_violations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(lfv.shutil, "which", lambda _name: None)

    # 1. Valid Lean file with sorry/axiom/comment tokens inside single-line & multiline strings
    clean_ws = tmp_path / "clean_ws"
    clean_pkg = clean_ws / "RFCHunt"
    clean_pkg.mkdir(parents=True, exist_ok=True)
    clean_file = clean_pkg / "CleanStrings.lean"
    clean_file.write_text(
        'def s1 : String := "-- sorry /-"\n'
        'def s2 : String := "a\\" /- sorry"\n'
        'def multi : String := "hello\n'
        'axiom fake_ax : False\n'
        'theorem fake_thm : True := by trivial\n'
        '"\n'
        "theorem clean_thm : True := by trivial\n",
        encoding="utf-8",
    )

    audit_clean = audit_lean_file(clean_file)
    assert audit_clean.has_sorry is False
    assert audit_clean.has_custom_axiom is False
    assert audit_clean.clean_proofs is True
    assert audit_clean.theorems == ["clean_thm"]

    rep_clean = verify_lean_workspace(clean_ws)
    assert rep_clean.status == "static_audited_lean_not_installed"
    assert rep_clean.total_theorems == 1
    assert rep_clean.diagnostics == []

    # 2. Same string literals followed by a real sorry & real axiom -> caught at exact line/col
    bad_ws = tmp_path / "bad_ws"
    bad_pkg = bad_ws / "RFCHunt"
    bad_pkg.mkdir(parents=True, exist_ok=True)
    bad_file = bad_pkg / "MixedStringsAndReal.lean"
    bad_file.write_text(
        'def s1 : String := "-- sorry /-"\n'
        'def s2 : String := "a\\" /- sorry"\n'
        'def multi : String := "hello\n'
        'axiom fake_ax : False\n'
        '"\n'
        "theorem real_bad : False := by sorry\n"
        "axiom real_ax : False\n",
        encoding="utf-8",
    )

    audit_bad = audit_lean_file(bad_file)
    assert audit_bad.has_sorry is True
    assert audit_bad.has_custom_axiom is True
    assert audit_bad.clean_proofs is False
    assert audit_bad.theorems == ["real_bad"]

    rep_bad = verify_lean_workspace(bad_ws)
    assert rep_bad.status == "proof_integrity_violation"
    assert len(rep_bad.diagnostics) == 2
    sorry_diag = next(d for d in rep_bad.diagnostics if d.kind == "sorry")
    ax_diag = next(d for d in rep_bad.diagnostics if d.kind == "custom_axiom")
    assert sorry_diag.theorem == "real_bad"
    assert sorry_diag.line == 6
    assert sorry_diag.column == 32
    assert ax_diag.theorem == "real_ax"
    assert ax_diag.line == 7
    assert ax_diag.column == 7


def test_parse_lake_diagnostics_retains_multicase_unsolved_goals_across_blank_lines():
    stderr = "\n".join(
        [
            r"error: C:\Users\My User\repo\RFCHunt\HttpFramingOracle.lean:5:2: unsolved goals",
            "case inl",
            "h1 : True",
            "⊢ False",
            "",
            "case inr",
            "h2 : False",
            "⊢ True",
            "",
            "error: RFCHunt/PolicyGuard.lean:10:4: type mismatch",
            "  rfl",
            "error: build failed",
        ]
    )
    diags = _parse_lake_diagnostics("", stderr)
    assert len(diags) == 2
    unsolved = diags[0]
    assert unsolved.kind == "unsolved_goals"
    assert "inl" in unsolved.branch_summary
    assert "inr" in unsolved.branch_summary
    assert "⊢ False" in unsolved.branch_summary
    assert "⊢ True" in unsolved.branch_summary
    assert "case inr" in unsolved.raw_excerpt
    assert "h2 : False" in unsolved.raw_excerpt
    assert diags[1].kind == "type_mismatch"
    assert diags[1].module == "RFCHunt.PolicyGuard"


def test_dotnet_pe_invariant_supports_flat_pe_reports():
    flat_vuln = verify_dotnet_pe_invariant(
        pe_report={"is_pe": True, "is_dot_net": True, "is_executable_image": False}
    )
    assert any(c.theorem == "anomaly_triggers_unpatched_fallback" and c.violated for c in flat_vuln)

    flat_alt_keys = verify_dotnet_pe_invariant(
        pe_report={"is_valid_pe": True, "has_clr_descriptor": True, "has_executable_image_bit": False}
    )
    assert any(c.theorem == "anomaly_triggers_unpatched_fallback" and c.violated for c in flat_alt_keys)

    flat_non_dotnet = verify_dotnet_pe_invariant(
        pe_report={"is_pe": True, "is_executable_image": False}
    )
    assert all(not c.violated for c in flat_non_dotnet)


def test_evaluate_lean_domains_handles_malformed_metadata_and_tight_policy_heuristic():
    # 1. Negative content_lengths in finding metadata must NOT crash evaluate_lean_domains
    findings = [
        {
            "rule_id": "HTTP-BAD-META",
            "cwe": "CWE-444",
            "title": "Malformed framing witness",
            "metadata": {"http_framing": {"content_lengths": [-5]}},
        },
        {
            "rule_id": "HTTP-VALID-CLTE",
            "cwe": "CWE-444",
            "title": "CL+TE request smuggling desync",
            "summary": "Valid follow-up finding must still be evaluated",
        },
    ]
    rep = evaluate_lean_domains(findings=findings, lean_dir=_lean_root())
    assert rep.status == "counterexample_found"
    assert any(d.kind == "invalid_witness" and d.module == "RFCHunt.HttpFramingOracle" for d in rep.diagnostics)
    assert rep.domain_checks["http_framing"]["violations"] >= 1

    # 2. Informational/passed/unconfirmed policy_guard mentions must NOT fabricate violations
    info_findings = [
        {
            "rule_id": "POLICY-INFO-01",
            "title": "policy_guard verification passed cleanly",
            "summary": "shellexec and out_of_scope checks passed",
            "severity": "INFO",
            "status": "passed",
            "confirmed": False,
        },
        {
            "rule_id": "POLICY-NEUTRAL-02",
            "title": "policy_guard audit summary",
            "summary": "Reviewed policy_guard rules",
        },
    ]
    rep_info = evaluate_lean_domains(findings=info_findings, lean_dir=_lean_root())
    assert rep_info.violations_count == 0
    assert rep_info.status == "passed"

    # 3. Active policy failure / explicit observed_allowed=True DOES trigger violation
    active_findings = [
        {
            "rule_id": "POLICY-FAIL-01",
            "title": "shellexec guard bypassed",
            "severity": "HIGH",
            "status": "failed",
        }
    ]
    rep_fail = evaluate_lean_domains(findings=active_findings, lean_dir=_lean_root())
    assert rep_fail.status == "counterexample_found"
    assert rep_fail.domain_checks["policy_guard"]["violations"] >= 1


def test_lean_audit_handles_char_literals_and_prime_identifiers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(lfv.shutil, "which", lambda _name: None)

    # 1. Char literals ('"', '\"', '\\', '\'', '\x22', '\u0022') must not hide sorry/axiom
    bad_ws = tmp_path / "char_bypass_ws"
    bad_pkg = bad_ws / "RFCHunt"
    bad_pkg.mkdir(parents=True, exist_ok=True)
    bad_file = bad_pkg / "CharQuote.lean"
    bad_file.write_text(
        "theorem ok' : True := by trivial\n"
        "def q1 : Char := '\"'\n"
        "theorem cheat : False := by sorry\n"
        "axiom hidden_after_char : False\n"
        "def q2 : Char := '\"'\n"
        "def q3 : Char := '\\\"'\n"
        "def q4 : Char := '\\\\'\n",
        encoding="utf-8",
    )
    audit_bad = audit_lean_file(bad_file)
    assert audit_bad.has_sorry is True
    assert audit_bad.has_custom_axiom is True
    assert audit_bad.clean_proofs is False
    assert audit_bad.theorems == ["ok'", "cheat"]

    rep_bad = verify_lean_workspace(bad_ws)
    assert rep_bad.status == "proof_integrity_violation"
    sorry_diag = next(d for d in rep_bad.diagnostics if d.kind == "sorry")
    ax_diag = next(d for d in rep_bad.diagnostics if d.kind == "custom_axiom")
    assert sorry_diag.theorem == "cheat"
    assert sorry_diag.line == 3
    assert ax_diag.theorem == "hidden_after_char"
    assert ax_diag.line == 4

    # 2. Clean file with Char literals & prime / guillemet-prime identifiers passes cleanly
    clean_ws = tmp_path / "char_clean_ws"
    clean_pkg = clean_ws / "RFCHunt"
    clean_pkg.mkdir(parents=True, exist_ok=True)
    clean_file = clean_pkg / "CharClean.lean"
    clean_file.write_text(
        "def q1 : Char := '\"'\n"
        "def q2 : Char := '\\\"'\n"
        "def q3 : Char := '\\\\'\n"
        "def q4 : Char := '\\''\n"
        "def q5 : Char := '\\x22'\n"
        "def q6 : Char := '\\u0022'\n"
        "theorem ok' : True := by trivial\n"
        "theorem x'' : True := by trivial\n"
        "theorem «foo»' : True := by trivial\n",
        encoding="utf-8",
    )
    audit_clean = audit_lean_file(clean_file)
    assert audit_clean.has_sorry is False
    assert audit_clean.has_custom_axiom is False
    assert audit_clean.clean_proofs is True
    assert audit_clean.theorems == ["ok'", "x''", "«foo»'"]


def test_verify_lean_workspace_bare_and_guillemet_axiom_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(lfv.shutil, "which", lambda _name: None)

    bare_ws = tmp_path / "bare_ws"
    bare_pkg = bare_ws / "RFCHunt"
    bare_pkg.mkdir(parents=True, exist_ok=True)
    (bare_pkg / "Bare.lean").write_text(
        "theorem ok_thm : True := by trivial\n"
        "axiom\n"
        "theorem after_bare : True := by trivial\n",
        encoding="utf-8",
    )
    rep_bare = verify_lean_workspace(bare_ws)
    assert rep_bare.status == "proof_integrity_violation"
    assert len(rep_bare.diagnostics) == 1
    assert rep_bare.diagnostics[0].kind == "custom_axiom"
    assert rep_bare.diagnostics[0].theorem == "unknown"
    assert rep_bare.diagnostics[0].line == 2
    assert rep_bare.modules[0].theorems == ["ok_thm", "after_bare"]

    guil_ws = tmp_path / "guil_ws"
    guil_pkg = guil_ws / "RFCHunt"
    guil_pkg.mkdir(parents=True, exist_ok=True)
    (guil_pkg / "Guil.lean").write_text(
        "theorem «thm_g» : True := by trivial\n"
        "axiom «cheat» : False\n",
        encoding="utf-8",
    )
    rep_guil = verify_lean_workspace(guil_ws)
    assert rep_guil.status == "proof_integrity_violation"
    assert len(rep_guil.diagnostics) == 1
    assert rep_guil.diagnostics[0].kind == "custom_axiom"
    assert rep_guil.diagnostics[0].theorem == "«cheat»"
    assert rep_guil.diagnostics[0].line == 2
    assert rep_guil.modules[0].theorems == ["«thm_g»"]
