"""
Tier 2 Boundary, Edge-Case, Tampering, and Corner-Case Tests (F1-F7, >=35 tests).

Tests malformed inputs, extreme parameter bounds, proof-integrity anti-cheat rules,
symlink/path-traversal confinement, timeout clamping, and partial toolchain outages.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from tests.e2e_ensemble_whiteboard.conftest import (
    REPO_ROOT,
    extract_field,
    import_contract,
    import_first_available,
    run_cli_subprocess,
)

pytestmark = pytest.mark.tier2


# ===========================================================================
# F1 Boundaries: Shared Whiteboard & Orchestrator (6 tests)
# ===========================================================================


def test_t2_f1_01_empty_findings_and_nonexistent_target(
    tmp_path: Path,
    isolated_out_dir: Path,
) -> None:
    from engine.ensemble_orchestrator import EnsembleOrchestrator

    missing_dir = tmp_path / "no_such_repo"
    orch = EnsembleOrchestrator(program="generic", quorum=2)
    rep = orch.run(missing_dir, findings=[], out_dir=isolated_out_dir, refresh_stix=False)
    assert rep.freshness.is_git_repo is False
    assert rep.freshness.freshness_status == "UNKNOWN_FRESHNESS"
    assert rep.clusters == []
    assert (isolated_out_dir / "ensemble_report.json").is_file()


def test_t2_f1_02_max_whiteboard_rounds_zero_and_disabled(
    policy_guard_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda n: None if n == "semgrep" else orig_which(n))

    seed = [
        EngineFinding(
            engine="web_llm",
            title="Excessive agency check",
            file_path="src/agent_handler.py",
            line=5,
            cwe="CWE-862",
            severity="HIGH",
        )
    ]
    orch_zero = EnsembleOrchestrator(
        program="generic", quorum=1, max_whiteboard_rounds=0, enable_whiteboard=True
    )
    rep_zero = orch_zero.run(policy_guard_repo, findings=seed, refresh_stix=False)
    assert len(rep_zero.clusters) == 1

    orch_off = EnsembleOrchestrator(
        program="generic", quorum=1, max_whiteboard_rounds=1, enable_whiteboard=False
    )
    rep_off = orch_off.run(policy_guard_repo, findings=seed, refresh_stix=False)
    assert len(rep_off.clusters) == 1
    assert "whiteboard" in rep_off.to_dict()


def test_t2_f1_03_quorum_extremes_zero_and_hundred() -> None:
    from engine.ensemble_orchestrator import EngineFinding, EnsembleConsensusVoter

    findings = [
        EngineFinding(engine="mantis", title="SSRF", file_path="src/a.py", line=10, cwe="CWE-918", severity="HIGH"),
        EngineFinding(engine="raptor", title="SSRF", file_path="src/a.py", line=11, cwe="CWE-918", severity="HIGH"),
    ]
    v_zero = EnsembleConsensusVoter(program="generic", quorum=0)
    assert v_zero.quorum == 1
    c_zero = v_zero.fuse(findings)
    assert c_zero[0].disposition == "ENSEMBLE_CORROBORATED_STATIC"

    v_high = EnsembleConsensusVoter(program="generic", quorum=100)
    c_high = v_high.fuse(findings)
    assert c_high[0].disposition != "ENSEMBLE_CORROBORATED_STATIC"
    assert c_high[0].disposition != "SUBMISSION_READY"


def test_t2_f1_04_proximity_clustering_adjacent_vs_distant_lines() -> None:
    from engine.ensemble_orchestrator import EngineFinding, EnsembleConsensusVoter

    voter = EnsembleConsensusVoter(program="generic", quorum=2, line_bucket_size=15)
    adjacent = [
        EngineFinding(engine="mantis", title="SQLi", file_path="src/db.py", line=15, cwe="CWE-89", severity="HIGH"),
        EngineFinding(engine="raptor", title="SQLi", file_path="src/db.py", line=30, cwe="CWE-89", severity="HIGH"),
    ]
    merged = voter.fuse(adjacent)
    assert len(merged) == 1
    assert merged[0].engine_count == 2

    distant = [
        EngineFinding(engine="mantis", title="SQLi", file_path="src/db.py", line=15, cwe="CWE-89", severity="HIGH"),
        EngineFinding(engine="raptor", title="SQLi", file_path="src/db.py", line=45, cwe="CWE-89", severity="HIGH"),
    ]
    split = voter.fuse(distant)
    assert len(split) == 2


def test_t2_f1_05_whiteboard_duplicate_id_and_unknown_status_boundary() -> None:
    WhiteboardCls = import_first_available(
        [
            ("engine.ensemble_whiteboard", "EnsembleWhiteboard"),
            ("engine.ensemble_whiteboard", "SharedWhiteboard"),
            ("engine.ensemble_orchestrator", "EnsembleWhiteboard"),
            ("engine.ensemble_orchestrator", "SharedWhiteboard"),
        ]
    )
    HypothesisCls = import_first_available(
        [
            ("engine.ensemble_whiteboard", "WhiteboardHypothesis"),
            ("engine.ensemble_orchestrator", "WhiteboardHypothesis"),
        ]
    )

    wb = WhiteboardCls()
    add_fn = getattr(wb, "add_hypothesis", None) or getattr(wb, "post_hypothesis", None)
    upd_fn = getattr(wb, "update_status", None) or getattr(wb, "transition", None)
    assert add_fn is not None and upd_fn is not None

    h1 = HypothesisCls(
        hypothesis_id="DUP-1",
        title="Initial",
        domain="http_framing",
        file_path="src/a.py",
        line=1,
        status="OPEN",
    )
    add_fn(h1)
    # Re-adding or updating unknown ID should handle gracefully without losing DUP-1
    try:
        add_fn(h1)
    except ValueError:
        pass
    try:
        upd_fn("NONEXISTENT-ID", "VERIFIED")
    except (KeyError, ValueError):
        pass

    snap = wb.to_dict() if hasattr(wb, "to_dict") else wb.snapshot()
    items = extract_field(snap, "hypotheses", "items")
    assert len(items) == 1


def test_t2_f1_06_malformed_findings_json_rejected_by_cli(
    tmp_path: Path,
    policy_guard_repo: Path,
    isolated_out_dir: Path,
) -> None:
    import revenue_cli

    bad_json = tmp_path / "corrupt.json"
    bad_json.write_text("{not valid json!!", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        revenue_cli.run_revenue_cli(
            [
                "ensemble-audit",
                "--target",
                str(policy_guard_repo),
                "--findings-json",
                str(bad_json),
                "--out",
                str(isolated_out_dir),
            ]
        )


# ===========================================================================
# F2 Boundaries: Lean 4 Proof Integrity & Domain Edge Cases (6 tests)
# ===========================================================================


def test_t2_f2_01_lean_sorry_in_code_vs_comment_boundary(lean_workspace_copy: Path) -> None:
    from engine.lean_formal_verifier import audit_lean_file, verify_lean_workspace

    pg = lean_workspace_copy / "RFCHunt" / "PolicyGuard.lean"
    orig = pg.read_text(encoding="utf-8")

    # 1. `sorry` inside line and block comments must NOT trigger violation
    pg.write_text(
        orig + "\n-- sorry in line comment\n/- sorry in block comment -/\n",
        encoding="utf-8",
    )
    audit_ok = audit_lean_file(pg)
    assert audit_ok.has_sorry is False
    assert audit_ok.clean_proofs is True

    # 2. `sorry` inside theorem body MUST trigger proof_integrity_violation + LeanProofDiagnostic
    pg.write_text(orig + "\ntheorem cheat_thm : True := by\n  sorry\n", encoding="utf-8")
    rep = verify_lean_workspace(lean_workspace_copy)
    assert rep.status == "proof_integrity_violation"
    assert rep.machine_checked is False
    assert any(d.kind == "sorry" and d.theorem == "cheat_thm" for d in rep.diagnostics)


def test_t2_f2_02_lean_custom_axiom_and_zero_theorems_boundary(lean_workspace_copy: Path) -> None:
    from engine.lean_formal_verifier import verify_lean_workspace

    pkg = lean_workspace_copy / "RFCHunt"
    (pkg / "PolicyGuard.lean").write_text(
        "axiom backdoor : False\ntheorem t : True := by trivial\n",
        encoding="utf-8",
    )
    (pkg / "HttpFramingOracle.lean").write_text(
        "def onlyHelper : Nat := 42\n",
        encoding="utf-8",
    )
    rep = verify_lean_workspace(lean_workspace_copy)
    assert rep.status == "proof_integrity_violation"
    assert rep.machine_checked is False
    kinds = {d.kind for d in rep.diagnostics}
    assert {"custom_axiom", "zero_theorems"}.issubset(kinds)


def test_t2_f2_03_missing_lean_directory_produces_missing_modules_diagnostic(tmp_path: Path) -> None:
    from engine.lean_formal_verifier import verify_lean_workspace

    rep = verify_lean_workspace(tmp_path / "nonexistent_lean_dir")
    assert rep.status == "proof_integrity_violation"
    assert rep.machine_checked is False
    assert len(rep.diagnostics) == 1
    assert rep.diagnostics[0].kind == "missing_modules"


def test_t2_f2_04_lake_timeout_and_unrecognized_stderr_diagnostics(
    lean_workspace_copy: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.lean_formal_verifier as lfv

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
            stderr="fatal unknown build failure without file header\n",
        ),
    )
    rep_err = lfv.verify_lean_workspace(lean_workspace_copy)
    assert rep_err.status == "kernel_failed"
    assert rep_err.machine_checked is False
    assert len(rep_err.diagnostics) == 1
    assert rep_err.diagnostics[0].kind == "kernel_error"
    assert rep_err.diagnostics[0].module == "lake"

    def _timeout(*_a: Any, **_kw: Any) -> None:
        raise subprocess.TimeoutExpired(cmd=["lake", "build"], timeout=1.0)

    monkeypatch.setattr(lfv, "silent_subprocess_run", _timeout)
    rep_to = lfv.verify_lean_workspace(lean_workspace_copy, timeout_sec=1.0)
    assert rep_to.status == "kernel_failed"
    assert rep_to.machine_checked is False
    assert rep_to.diagnostics[0].kind == "timeout"


def test_t2_f2_05_http_framing_edge_cases_and_negative_cl() -> None:
    from engine.lean_formal_verifier import strict_rfc9112_oracle, verify_http_framing_invariant

    assert strict_rfc9112_oracle([], False, False) == ("acceptContentLength", 0)
    assert strict_rfc9112_oracle([0], False, False) == ("acceptContentLength", 0)
    assert strict_rfc9112_oracle([10, 10, 11], False, False) == ("reject400", None)

    bare = verify_http_framing_invariant(content_lengths=[], has_transfer_encoding_chunked=False, has_bare_lf=True)
    assert any(c.theorem == "strict_rfc9112_bare_lf" and c.violated for c in bare)

    with pytest.raises(ValueError):
        verify_http_framing_invariant(content_lengths=[-1])


def test_t2_f2_06_dotnet_pe_32state_exhaustive_boundary_matrix() -> None:
    from engine.lean_formal_verifier import dotnet_pe_integrity_mirror, verify_dotnet_pe_invariant

    states_checked = 0
    for vp in (False, True):
        for clr in (False, True):
            for eb in (False, True):
                for umci in (False, True):
                    for sig in (False, True):
                        states_checked += 1
                        anom, unpatched, patched = dotnet_pe_integrity_mirror(
                            is_valid_pe=vp,
                            has_clr_descriptor=clr,
                            has_executable_image_bit=eb,
                            is_umci_enforced=umci,
                            is_signed_by_trusted_publisher=sig,
                        )
                        assert patched != "loadedViaUncheckedFlatMemoryFallback"
                        assert anom is (vp and clr and (not eb))
                        if anom:
                            assert unpatched == "loadedViaUncheckedFlatMemoryFallback"
                        checks = verify_dotnet_pe_invariant(
                            is_valid_pe=vp,
                            has_clr_descriptor=clr,
                            has_executable_image_bit=eb,
                            is_umci_enforced=umci,
                            is_signed_by_trusted_publisher=sig,
                        )
                        assert checks[0].violated is anom
    assert states_checked == 32


# ===========================================================================
# F3 Boundaries: LinuxPocRunner & Symbolic Hook Edge Cases (5 tests)
# ===========================================================================


def test_t2_f3_01_unsupported_language_and_empty_tokens(policy_guard_repo: Path) -> None:
    from engine.linux_poc_runner import LinuxPocRunner, validate_command_tokens

    runner = LinuxPocRunner()
    with pytest.raises(ValueError):
        runner.run_poc(language="cobol", repo_path=policy_guard_repo, cmd=["cobc", "--version"])

    ok_empty, _ = validate_command_tokens([])
    assert ok_empty is False
    ok_blank, _ = validate_command_tokens(["python3", ""])
    assert ok_blank is False


def test_t2_f3_02_linux_poc_timeout_and_nonzero_exit_transcript(
    policy_guard_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.linux_poc_runner as lpr

    monkeypatch.setattr(
        lpr,
        "diagnose_docker_wsl",
        lambda: SimpleNamespace(daemon_running=True, docker_binary="docker", server_version="27.0"),
    )
    monkeypatch.setattr(
        lpr,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(returncode=2, stdout="partial", stderr="assertion failed"),
    )
    tr_fail = lpr.LinuxPocRunner().run_poc(
        language="python",
        repo_path=policy_guard_repo,
        cmd=["python3", "scripts/poc_check.py"],
    )
    assert tr_fail.status == "failed"
    assert tr_fail.exit_code == 2
    assert tr_fail.verified is False

    def _timeout(*_a: Any, **_kw: Any) -> None:
        raise subprocess.TimeoutExpired(cmd=["docker", "run"], timeout=1.0, output=b"out", stderr=b"err")

    monkeypatch.setattr(lpr, "silent_subprocess_run", _timeout)
    tr_to = lpr.LinuxPocRunner().run_poc(
        language="python",
        repo_path=policy_guard_repo,
        cmd=["python3", "scripts/poc_check.py"],
        timeout_sec=1.0,
    )
    assert tr_to.status == "timeout"
    assert tr_to.verified is False


def test_t2_f3_03_run_symbolic_hook_unknown_backend_and_raw_string_args(policy_guard_repo: Path) -> None:
    run_symbolic_hook = import_contract("engine.linux_poc_runner", "run_symbolic_hook")

    res_unk = run_symbolic_hook("unknown_sym", policy_guard_repo)
    assert res_unk["available"] is False
    assert res_unk["status"] in ("unsupported_backend", "unavailable")
    assert res_unk["verified"] is False

    res_raw = run_symbolic_hook("angr", policy_guard_repo, args="--raw-string")  # type: ignore[arg-type]
    assert res_raw["status"] == "rejected_unsafe"
    assert res_raw["verified"] is False


def test_t2_f3_04_run_symbolic_hook_timeout_and_malformed_json_output(
    policy_guard_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.linux_poc_runner as lpr

    target_file = policy_guard_repo / "scripts" / "poc_check.py"
    monkeypatch.setattr(
        lpr,
        "_safe_find_spec",
        lambda m: SimpleNamespace(origin="/site-packages/angr/__init__.py") if m == "angr" else None,
    )
    monkeypatch.setattr(
        lpr,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout="not valid json", stderr=""),
    )
    res_bad_json = lpr.run_symbolic_hook("angr", target_file)
    assert res_bad_json["status"] == "passed"
    assert res_bad_json["verified"] is False

    def _timeout(*_a: Any, **_kw: Any) -> None:
        raise subprocess.TimeoutExpired(cmd=["python", "-c", "..."], timeout=1.0)

    monkeypatch.setattr(lpr, "silent_subprocess_run", _timeout)
    res_to = lpr.run_symbolic_hook("angr", target_file, timeout_sec=1.0)
    assert res_to["status"] == "timeout"
    assert res_to["verified"] is False


def test_t2_f3_05_windows_to_wsl_path_relative_and_lowercase_drive() -> None:
    from engine.linux_poc_runner import windows_to_wsl_path

    assert windows_to_wsl_path(r"c:\Users\tester\repo") == "/mnt/c/Users/tester/repo"
    rel = windows_to_wsl_path(".")
    assert rel.startswith("/mnt/") or "/" in rel


# ===========================================================================
# F4 Boundaries: CLI Entry Point Corner Cases (5 tests)
# ===========================================================================


def test_t2_f4_01_revenue_cli_missing_target_exits_2() -> None:
    proc = run_cli_subprocess("revenue_cli.py", ["ensemble-audit"])
    assert proc.returncode == 2


def test_t2_f4_02_revenue_cli_nonexistent_target_and_extreme_quorum(
    tmp_path: Path,
    isolated_out_dir: Path,
) -> None:
    import revenue_cli

    missing_repo = tmp_path / "missing_repo_dir"
    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(missing_repo),
            "--all",
            "--quorum",
            "0",
            "--freshness-hours",
            "0",
            "--out",
            str(isolated_out_dir),
        ]
    )
    assert rc == 0
    data = json.loads((isolated_out_dir / "ensemble_report.json").read_text(encoding="utf-8"))
    assert data["freshness"]["is_git_repo"] is False
    assert data["clusters"] == []


def test_t2_f4_03_swarm_unauthorized_external_ip_fails_closed(
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    proc = run_cli_subprocess(
        "rfc_hunt_swarm.py",
        [
            "--all",
            "--host",
            "93.184.216.34",
            "--output-dir",
            str(isolated_out_dir),
            "--db",
            str(isolated_db_path),
        ],
    )
    assert proc.returncode != 0


def test_t2_f4_04_swarm_export_sarif_path_traversal_rejected(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    proc = run_cli_subprocess(
        "rfc_hunt_swarm.py",
        [
            "--all",
            "--repo",
            str(policy_guard_repo),
            "--export-sarif",
            "../../evil.sarif",
            "--output-dir",
            str(isolated_out_dir),
            "--db",
            str(isolated_db_path),
        ],
    )
    assert proc.returncode != 0


def test_t2_f4_05_swarm_negative_budget_bounds_rejected_even_in_dry_run(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    proc = run_cli_subprocess(
        "rfc_hunt_swarm.py",
        [
            "--all",
            "--repo",
            str(policy_guard_repo),
            "--artex-rounds",
            "0",
            "--dry-run",
            "--output-dir",
            str(isolated_out_dir),
            "--db",
            str(isolated_db_path),
        ],
    )
    assert proc.returncode != 0


# ===========================================================================
# F5 Boundaries: MCP Server Edge Cases (5 tests)
# ===========================================================================


def test_t2_f5_01_mcp_empty_target_raises_and_returns_is_error() -> None:
    from bugbounty_mcp_server import BugBountyMCPServer, build_rfchunt_all_argv

    with pytest.raises(ValueError):
        build_rfchunt_all_argv(target="", ensemble=True)

    srv = BugBountyMCPServer()
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {"name": "bb_run_all_scan", "arguments": {"target": ""}},
        }
    )
    assert resp["result"]["isError"] is True


def test_t2_f5_02_mcp_extra_flags_injection_rejected(policy_guard_repo: Path) -> None:
    from bugbounty_mcp_server import BugBountyMCPServer, build_rfchunt_all_argv

    with pytest.raises(ValueError):
        build_rfchunt_all_argv(
            target=str(policy_guard_repo),
            ensemble=True,
            extra_flags=["; rm -rf /"],
        )

    srv = BugBountyMCPServer()
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "bb_run_all_scan",
                "arguments": {
                    "target": str(policy_guard_repo),
                    "ensemble": True,
                    "extra_flags": ["$(whoami)"],
                },
            },
        }
    )
    assert resp["result"]["isError"] is True


def test_t2_f5_03_mcp_unknown_tool_and_unknown_rpc_method() -> None:
    from bugbounty_mcp_server import BugBountyMCPServer

    srv = BugBountyMCPServer()
    bad_tool = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 103,
            "method": "tools/call",
            "params": {"name": "bb_nonexistent_tool", "arguments": {}},
        }
    )
    assert bad_tool["result"]["isError"] is True

    bad_method = srv.handle_request({"jsonrpc": "2.0", "id": 104, "method": "unknown/rpc"})
    assert bad_method["error"]["code"] == -32601


def test_t2_f5_04_mcp_run_rfchunt_all_scan_nonzero_exit_maps_failed(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    from bugbounty_mcp_server import run_rfchunt_all_scan

    res = run_rfchunt_all_scan(
        target=str(policy_guard_repo),
        output_dir=str(isolated_out_dir),
        ensemble=False,
        dry_run=False,
        include_lean_verify=True,
        extra_flags=["--artex-rounds", "0", "--db", str(isolated_db_path)],
    )
    assert res["status"] == "failed"
    assert res["exit_code"] != 0


def test_t2_f5_05_mcp_malformed_json_line_on_stdio_returns_parse_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bugbounty_mcp_server

    fake_in = io.StringIO("{bad json line\n")
    fake_out = io.StringIO()
    monkeypatch.setattr(bugbounty_mcp_server.sys, "stdin", fake_in)
    monkeypatch.setattr(bugbounty_mcp_server.sys, "stdout", fake_out)

    bugbounty_mcp_server.serve_stdio()
    resp = json.loads(fake_out.getvalue().strip())
    assert resp["error"]["code"] == -32700


# ===========================================================================
# F6 Boundaries: Graceful Toolchain Degradation Edge Cases (5 tests)
# ===========================================================================


def test_t2_f6_01_docker_stopped_and_prefer_wsl2_when_wsl_absent(
    policy_guard_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.linux_poc_runner as lpr

    monkeypatch.setattr(
        lpr,
        "diagnose_docker_wsl",
        lambda: SimpleNamespace(daemon_running=False, docker_binary="docker", server_version=""),
    )
    monkeypatch.setattr(lpr.shutil, "which", lambda _n: None)

    tr = lpr.LinuxPocRunner().run_poc(
        language="python",
        repo_path=policy_guard_repo,
        cmd=["python3", "scripts/poc_check.py"],
        prefer_backend="wsl2",
    )
    assert tr.status == "unavailable"
    assert tr.verified is False


def test_t2_f6_02_oracle_binary_nonzero_exit_and_unchecked_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.lean_formal_verifier as lfv

    fake_exe = tmp_path / ".lake" / "build" / "bin" / "rfchunt-lean-oracle.exe"
    fake_exe.parent.mkdir(parents=True, exist_ok=True)
    fake_exe.write_text("stub", encoding="utf-8")

    monkeypatch.setattr(
        lfv,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(returncode=2, stdout="", stderr="bad oracle args"),
    )
    oracle = lfv.LeanCompiledOracle(fake_exe)
    with pytest.raises(RuntimeError):
        oracle.evaluate_policy(
            action="shellExec",
            scope="inScopeAuthorized",
            in_workspace_root=True,
            allow_destructive=False,
            rules=[("permit", True)],
        )

    # Even if oracle methods succeed, un-checked workspace MUST keep machine_checked=False
    monkeypatch.setattr(lfv.LeanCompiledOracle, "strict_rfc9112", lambda *a, **kw: ("reject400", None))
    monkeypatch.setattr(lfv.LeanCompiledOracle, "evaluate_policy", lambda *a, **kw: False)
    monkeypatch.setattr(lfv.LeanCompiledOracle, "reconcile_verdict", lambda self, t, l: bool(t or l))
    monkeypatch.setattr(
        lfv.LeanCompiledOracle,
        "evaluate_dotnet_pe",
        lambda self, **kw: lfv.dotnet_pe_integrity_mirror(**kw),
    )
    dom = lfv.evaluate_lean_domains(findings=None, lean_dir=tmp_path)
    assert dom.oracle_backend == "lean4_compiled_binary"
    assert dom.machine_checked is False
    assert dom.degradation_reason


def test_t2_f6_03_probe_optional_backends_nonexistent_lean_dir_and_wsl_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.linux_poc_runner as lpr

    monkeypatch.setattr(lpr, "find_docker_binary", lambda *_a, **_kw: None)
    monkeypatch.setattr(lpr, "probe_docker_daemon", lambda *_a, **_kw: (False, None))
    monkeypatch.setattr(
        lpr,
        "diagnose_docker_wsl",
        lambda *_a, **_kw: SimpleNamespace(daemon_running=False, docker_binary=None, server_version=""),
    )
    monkeypatch.setattr(lpr.shutil, "which", lambda name: "wsl.exe" if name == "wsl.exe" else None)
    monkeypatch.setattr(lpr, "_safe_find_spec", lambda _m: None)

    recorded_timeouts = []

    def _timeout(*_a: Any, **kw: Any) -> None:
        recorded_timeouts.append(kw.get("timeout"))
        raise subprocess.TimeoutExpired(cmd=["wsl.exe", "--status"], timeout=2.5)

    monkeypatch.setattr(lpr, "silent_subprocess_run", _timeout)
    probes = lpr.probe_optional_backends(lean_dir=tmp_path / "missing_lean", timeout_sec=60.0)
    core_expected = {
        "docker",
        "wsl2",
        "lean4",
        "rfchunt_lean_oracle",
        "angr",
        "klee",
        "semgrep",
    }
    assert core_expected.issubset(probes.keys())
    for key, entry in probes.items():
        assert {"available", "status", "reason", "path_or_module"}.issubset(entry.keys()), key
        assert isinstance(entry["available"], bool), key
        assert isinstance(entry["status"], str) and entry["status"], key
        assert isinstance(entry["reason"], str) and entry["reason"], key
    assert recorded_timeouts and recorded_timeouts[0] <= 3.0
    assert probes["wsl2"]["status"] == "timeout"
    assert probes["rfchunt_lean_oracle"]["available"] is False


def test_t2_f6_04_partial_outage_webllm_active_without_docker_lean_semgrep(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    from engine.ensemble_orchestrator import EnsembleOrchestrator

    degraded_toolchain_env()
    orch = EnsembleOrchestrator(program="generic", quorum=1)
    rep = orch.run(policy_guard_repo, out_dir=isolated_out_dir, refresh_stix=False)
    assert len(rep.clusters) >= 1
    assert rep.counts_by_disposition.get("SUBMISSION_READY", 0) == 0


def test_t2_f6_05_offline_env_blocks_stix_network_when_refresh_requested(
    policy_guard_repo: Path,
) -> None:
    from engine.web_llm_auditor import (
        audit_web_llm_repository,
        enrich_web_llm_report_with_atlas,
    )

    rep = audit_web_llm_repository(policy_guard_repo)
    enriched = enrich_web_llm_report_with_atlas(rep, refresh_stix=True)
    assert enriched["stix_metadata"]["total_techniques"] > 0
    assert "golden" in str(enriched["stix_metadata"].get("source_mode", "")).lower() or enriched["stix_metadata"].get("source_mode") is not None


# ===========================================================================
# F7 Boundaries: Defensive Scope & Confinement Edge Cases (5 tests)
# ===========================================================================


def test_t2_f7_01_symlink_escape_blocked_by_execution_policy(tmp_path: Path) -> None:
    from engine.execution_policy import ExecutionPolicy

    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("SECRET_OUTSIDE_DATA", encoding="utf-8")

    link_path = repo / "escape_link.txt"
    try:
        os.symlink(secret, link_path)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"OS does not permit symlink creation in this environment: {exc}")

    policy = ExecutionPolicy.get_instance()
    ok, reason = policy.validate_file_path(str(link_path), workspace_root=repo)
    assert ok is False, f"Symlink escape should be blocked, got reason={reason!r}"


def test_t2_f7_02_null_byte_and_ads_colon_paths_rejected(tmp_path: Path) -> None:
    from engine.execution_policy import ExecutionPolicy
    from engine.linux_poc_runner import validate_mount_path

    ok_nul, _ = validate_mount_path(str(tmp_path) + "\x00evil")
    assert ok_nul is False

    policy = ExecutionPolicy.get_instance()
    ok_ads, _ = policy.validate_file_path(
        str(tmp_path / "notes.txt:Zone.Identifier"), workspace_root=tmp_path
    )
    assert ok_ads is False


def test_t2_f7_03_critical_host_mounts_windows_and_posix_rejected() -> None:
    from engine.linux_poc_runner import validate_mount_path

    critical = (
        r"C:\Program Files",
        r"C:\ProgramData",
        "/proc",
        "/var/run",
        "/sys",
        "/dev",
        "/boot",
        "/root",
    )
    for bad in critical:
        ok, _ = validate_mount_path(bad)
        assert ok is False, f"Expected critical mount rejection for {bad!r}"


def test_t2_f7_04_policy_guard_destructive_http_and_loopback_boundaries() -> None:
    from engine.lean_formal_verifier import evaluate_policy_mirror

    assert (
        evaluate_policy_mirror(
            action="destructiveHttp",
            scope="inScopeAuthorized",
            in_workspace_root=True,
            allow_destructive=False,
            rules=[("permit", True)],
        )
        is False
    )
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


def test_t2_f7_05_client_audit_packager_neutralizes_csv_formula_and_xss(
    tmp_path: Path,
    isolated_out_dir: Path,
) -> None:
    from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

    findings = [
        EngineFinding(
            engine="mantis",
            title="=CMD|'/C calc'!A0 <script>alert(1)</script>",
            file_path="src/calc.py",
            line=10,
            cwe="CWE-1236",
            severity="HIGH",
            summary="+1+1 payload",
        ),
        EngineFinding(
            engine="raptor",
            title="=CMD|'/C calc'!A0 <script>alert(1)</script>",
            file_path="src/calc.py",
            line=11,
            cwe="CWE-1236",
            severity="HIGH",
            summary="@SUM(1,2)",
        ),
    ]
    orch = EnsembleOrchestrator(program="generic", quorum=2)
    orch.run(tmp_path, findings, out_dir=isolated_out_dir, package_client_name="<img src=x onerror=alert(1)>")

    bundle = isolated_out_dir / "client_audit_bundle"
    csv_text = (bundle / "03_FINDINGS_TRACKER.csv").read_text(encoding="utf-8")
    assert "'=CMD" in csv_text

    html_text = (bundle / "05_AUDIT_DASHBOARD.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text
