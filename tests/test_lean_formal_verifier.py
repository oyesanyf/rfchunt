"""
Unit tests for RFCHunt's Lean 4 formal specifications and Python hybrid bridge.
"""

from pathlib import Path

from engine.lean_formal_verifier import (
    audit_lean_file,
    evaluate_policy_mirror,
    permissive_cl_first_proxy_mirror,
    reconcile_verdict_mirror,
    strict_rfc9112_oracle,
    verify_lean_workspace,
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
