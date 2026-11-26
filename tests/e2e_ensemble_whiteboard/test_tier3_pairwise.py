"""
Tier 3 Pairwise Combinatorial Tests (16 tests covering all 21 pairs of F1-F7).

Each test exercises genuine cross-feature interactions between two or more feature areas:
F1 (Whiteboard/Orchestrator), F2 (Lean 4 Domains/Diagnostics), F3 (LinuxPocRunner/Symbolic),
F4 (CLI), F5 (MCP), F6 (Graceful Degradation), F7 (Defensive Scope Enforcement).
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any

import pytest

from tests.e2e_ensemble_whiteboard.conftest import (
    REPO_ROOT,
    extract_field,
    import_contract,
    make_verified_transcript,
    run_cli_subprocess,
)

pytestmark = pytest.mark.tier3


# (F1, F2)
def test_t3_01_whiteboard_consumes_lean_domain_counterexamples(
    http_framing_repo: Path,
    isolated_out_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

    evaluate_lean_domains = import_contract("engine.lean_formal_verifier", "evaluate_lean_domains")
    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda n: None if n == "semgrep" else orig_which(n))

    findings = [
        EngineFinding(
            engine="smuggling",
            title="CL+TE request smuggling desync",
            file_path="src/http_proxy.py",
            line=4,
            cwe="CWE-444",
            severity="HIGH",
            summary="CL+TE conflict in http_proxy.py",
            metadata={"http_framing": {"content_lengths": [42], "has_transfer_encoding_chunked": True}},
        ),
        EngineFinding(
            engine="mantis",
            title="CL+TE request smuggling desync",
            file_path="src/http_proxy.py",
            line=5,
            cwe="CWE-444",
            severity="HIGH",
            deterministic=False,
            confirmed=False,  # LLM dissent must not veto deterministic Lean 4 witness
        ),
    ]
    dom = evaluate_lean_domains(findings=findings, repo_path=http_framing_repo, lean_dir=REPO_ROOT / "formal" / "lean4")
    assert dom.status == "counterexample_found"

    orch = EnsembleOrchestrator(program="generic", quorum=1, max_whiteboard_rounds=2)
    rep = orch.run(http_framing_repo, findings=findings, out_dir=isolated_out_dir, refresh_stix=False)
    rep_d = rep.to_dict()

    assert "whiteboard" in rep_d
    assert "lean_verification" in rep_d
    wb_hyps = extract_field(rep_d["whiteboard"], "hypotheses", "items")
    if isinstance(wb_hyps, dict):
        wb_hyps = list(wb_hyps.values())
    assert any(extract_field(h, "status") == "COUNTEREXAMPLE_FOUND" for h in wb_hyps)
    assert any(c.lean_verified and c.deterministic_override_protected for c in rep.clusters)


# (F1, F3)
def test_t3_02_whiteboard_dispatches_linux_poc_and_promotes_only_verified(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator
    from engine.linux_poc_runner import VerifiableTranscript

    degraded_toolchain_env()
    seed = [
        EngineFinding(
            engine="web_llm",
            title="Excessive agency in agent_handler",
            file_path="src/agent_handler.py",
            line=6,
            cwe="CWE-862",
            severity="HIGH",
        ),
        EngineFinding(
            engine="gha_agent",
            title="Excessive agency in agent_handler",
            file_path="src/agent_handler.py",
            line=7,
            cwe="CWE-862",
            severity="HIGH",
        ),
    ]
    orch = EnsembleOrchestrator(program="generic", quorum=2, max_whiteboard_rounds=2)

    # 1. Unavailable LinuxPocRunner keeps cluster capped at ENSEMBLE_CORROBORATED_STATIC
    rep_unavail = orch.run(
        policy_guard_repo,
        findings=seed,
        poc_lang="python",
        poc_cmd=["python3", "scripts/poc_check.py"],
        refresh_stix=False,
    )
    assert rep_unavail.clusters[0].disposition == "ENSEMBLE_CORROBORATED_STATIC"
    assert rep_unavail.clusters[0].poc_verified is False

    # 2. Failed transcript also keeps cluster capped
    tr_fail = VerifiableTranscript(
        language="python",
        backend="docker",
        status="failed",
        exit_code=1,
        command=["python3", "scripts/poc_check.py"],
        image="python:3.12-slim",
        repo_path=str(policy_guard_repo),
        started_at_utc="2026-11-26T00:00:00Z",
        elapsed_ms=25.0,
    )
    rep_fail = orch.run(
        policy_guard_repo,
        findings=seed,
        poc_transcripts={"src/agent_handler.py": tr_fail},
        refresh_stix=False,
    )
    assert rep_fail.clusters[0].disposition == "ENSEMBLE_CORROBORATED_STATIC"

    # 3. Passed transcript promotes to SUBMISSION_READY
    tr_ok = make_verified_transcript(policy_guard_repo)
    rep_ok = orch.run(
        policy_guard_repo,
        findings=seed,
        poc_transcripts={"src/agent_handler.py": tr_ok},
        out_dir=isolated_out_dir,
        refresh_stix=False,
    )
    assert rep_ok.clusters[0].disposition == "SUBMISSION_READY"
    assert rep_ok.clusters[0].poc_verified is True


# (F1, F4)
def test_t3_03_cli_ensemble_audit_drives_whiteboard_and_artifacts(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import revenue_cli

    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda n: None if n == "semgrep" else orig_which(n))

    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(policy_guard_repo),
            "--all",
            "--essemble",
            "--program",
            "anthropic",
            "--quorum",
            "1",
            "--out",
            str(isolated_out_dir),
        ]
    )
    assert rc == 0
    assert (isolated_out_dir / "ensemble_report.json").is_file()
    assert (isolated_out_dir / "ensemble_summary.md").is_file()
    assert (isolated_out_dir / "ensemble_findings.sarif").is_file()

    rep = json.loads((isolated_out_dir / "ensemble_report.json").read_text(encoding="utf-8"))
    assert "whiteboard" in rep
    assert "counts_by_disposition" in rep
    # Anthropic threat-model gate holds intra-runner /tmp hygiene findings
    assert any(
        c["disposition"] == "HELD_OUT_OF_THREAT_MODEL"
        and "/tmp/" in json.dumps(c).lower()
        for c in rep["clusters"]
    )


# (F1, F5)
def test_t3_04_mcp_bb_run_all_scan_surfaces_whiteboard_and_clusters(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    from bugbounty_mcp_server import BugBountyMCPServer

    srv = BugBountyMCPServer()
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 304,
            "method": "tools/call",
            "params": {
                "name": "bb_run_all_scan",
                "arguments": {
                    "target": str(policy_guard_repo),
                    "output_dir": str(isolated_out_dir),
                    "ensemble": True,
                    "program": "generic",
                    "freshness_hours": 72,
                    "ensemble_quorum": 1,
                    "dry_run": False,
                    "extra_flags": [
                        "--db",
                        str(isolated_db_path),
                        "--no-external-scanners",
                        "--no-preflight-live",
                        "--no-include-models",
                        "--no-auto-install",
                    ],
                },
            },
        }
    )
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["status"] == "completed"
    assert payload["mode"] == "--all --ensemble"
    assert "ensemble" in payload
    assert "whiteboard" in payload["ensemble"]
    assert "clusters" in payload["ensemble"]
    assert "toolchain_status" in payload["ensemble"]
    assert "lean_verification" in payload


# (F1, F6)
def test_t3_05_whiteboard_degrades_gracefully_without_fabricating(
    clean_hardened_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    from engine.ensemble_orchestrator import EnsembleOrchestrator

    degraded_toolchain_env()
    orch = EnsembleOrchestrator(program="generic", quorum=1, max_whiteboard_rounds=2)
    rep = orch.run(
        clean_hardened_repo,
        poc_lang="python",
        poc_cmd=["python3", "-V"],
        out_dir=isolated_out_dir,
        refresh_stix=False,
    )
    d = rep.to_dict()
    assert rep.counts_by_disposition.get("SUBMISSION_READY", 0) == 0
    assert rep.clusters == []
    assert d["toolchain_status"]["docker"]["available"] is False
    assert d["toolchain_status"]["lean4"]["available"] is False


# (F1, F7)
def test_t3_06_whiteboard_blocks_weaponized_and_out_of_scope_hypotheses(
    policy_guard_repo: Path,
) -> None:
    from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

    findings = [
        EngineFinding(
            engine="raptor",
            title="ucp-cli local CLI self-execution via user-supplied --exec",
            file_path="cmd/ucp-cli/main.go",
            line=22,
            cwe="CWE-78",
            severity="HIGH",
        )
    ]
    orch = EnsembleOrchestrator(program="shopify", quorum=1)
    rep = orch.run(
        policy_guard_repo,
        findings=findings,
        poc_lang="python",
        poc_cmd=["python3", "-c", "id; rm -rf /"],
        refresh_stix=False,
    )
    assert len(rep.clusters) == 1
    assert rep.clusters[0].disposition == "HELD_OUT_OF_THREAT_MODEL"
    assert rep.clusters[0].poc_verified is False


# (F2, F3)
def test_t3_07_lean_domains_and_symbolic_hook_coexist_cleanly(
    dotnet_pe_repo: Path,
    degraded_toolchain_env: Any,
) -> None:
    evaluate_lean_domains = import_contract("engine.lean_formal_verifier", "evaluate_lean_domains")
    probe_optional_backends = import_contract("engine.linux_poc_runner", "probe_optional_backends")
    run_symbolic_hook = import_contract("engine.linux_poc_runner", "run_symbolic_hook")

    degraded_toolchain_env()
    probes = probe_optional_backends(lean_dir=REPO_ROOT / "formal" / "lean4")
    assert probes["angr"]["available"] is False

    sym = run_symbolic_hook("angr", dotnet_pe_repo / "bin" / "cve_2026_108398_bypass.dll")
    assert sym["status"] == "unavailable"
    assert sym["verified"] is False

    dom = evaluate_lean_domains(
        findings=[{"rule_id": "HTTP-CL-TE", "cwe": "CWE-444", "title": "CL+TE smuggling"}],
        repo_path=dotnet_pe_repo,
        lean_dir=REPO_ROOT / "formal" / "lean4",
    )
    assert dom.status == "counterexample_found"
    assert dom.domain_checks["http_framing"]["violations"] >= 1
    assert dom.domain_checks["dotnet_pe"]["violations"] >= 1


# (F2, F4)
def test_t3_08_cli_lean_verify_and_swarm_dry_run_flags(
    http_framing_repo: Path,
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    import io
    import contextlib
    import revenue_cli

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = revenue_cli.run_revenue_cli(["lean-verify", "--lean-dir", str(REPO_ROOT / "formal" / "lean4")])
    assert rc == 0
    lean_json = json.loads(buf.getvalue())
    assert lean_json["total_theorems"] == 11
    assert isinstance(lean_json["diagnostics"], list)

    proc = run_cli_subprocess(
        "rfc_hunt_swarm.py",
        [
            "--all",
            "--repo",
            str(http_framing_repo),
            "--essemble",
            "--program",
            "generic",
            "--quorum",
            "2",
            "--dry-run",
            "--json",
            "--output-dir",
            str(isolated_out_dir),
            "--db",
            str(isolated_db_path),
        ],
    )
    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    assert plan["status"] == "dry_run_plan_ready"
    assert plan["side_effects"]["network_packets_sent"] == 0


# (F2, F5)
def test_t3_09_mcp_lean_verify_and_all_scan_emit_diagnostics(dotnet_pe_repo: Path, isolated_out_dir: Path) -> None:
    from bugbounty_mcp_server import BugBountyMCPServer

    srv = BugBountyMCPServer()
    lean_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3091,
            "method": "tools/call",
            "params": {"name": "bb_lean_formal_verify", "arguments": {"lean_dir": str(REPO_ROOT / "formal" / "lean4")}},
        }
    )
    assert lean_resp["result"]["isError"] is False
    lean_data = json.loads(lean_resp["result"]["content"][0]["text"])
    assert lean_data["total_theorems"] == 11
    assert isinstance(lean_data["diagnostics"], list)

    scan_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3092,
            "method": "tools/call",
            "params": {
                "name": "bb_run_all_scan",
                "arguments": {
                    "target": str(dotnet_pe_repo),
                    "output_dir": str(isolated_out_dir),
                    "dry_run": True,
                    "ensemble": True,
                    "include_lean_verify": True,
                },
            },
        }
    )
    assert scan_resp["result"]["isError"] is False
    scan_data = json.loads(scan_resp["result"]["content"][0]["text"])
    assert scan_data["lean_verification"]["total_theorems"] == 11
    assert isinstance(scan_data["lean_verification"]["diagnostics"], list)


# (F2, F6)
def test_t3_10_lean_proof_integrity_violation_and_missing_lake_degradation(
    lean_workspace_copy: Path,
    degraded_toolchain_env: Any,
) -> None:
    from engine.lean_formal_verifier import verify_lean_workspace

    degraded_toolchain_env()
    # Clean copy without `lake` degrades to static_audited_lean_not_installed
    clean_rep = verify_lean_workspace(lean_workspace_copy)
    assert clean_rep.status == "static_audited_lean_not_installed"
    assert clean_rep.machine_checked is False

    # Inject `sorry` cheat -> proof_integrity_violation + LeanProofDiagnostic
    pg = lean_workspace_copy / "RFCHunt" / "PolicyGuard.lean"
    pg.write_text(
        pg.read_text(encoding="utf-8") + "\ntheorem cheat : True := by sorry\n",
        encoding="utf-8",
    )
    bad_rep = verify_lean_workspace(lean_workspace_copy)
    assert bad_rep.status == "proof_integrity_violation"
    assert bad_rep.machine_checked is False
    assert any(d.kind == "sorry" for d in bad_rep.diagnostics)


# (F2, F7)
def test_t3_11_lean_policy_guard_enforces_defensive_scope_invariants() -> None:
    verify_pg = import_contract("engine.lean_formal_verifier", "verify_policy_guard_invariant")
    from engine.lean_formal_verifier import reconcile_verdict_mirror

    for checks in (
        verify_pg(action="shellExec", scope="inScopeAuthorized", rules=[("permit", True)]),
        verify_pg(action="networkProbe", scope="outOfScope", rules=[("permit", True)]),
        verify_pg(action="networkProbe", scope="privateOrLoopbackBlocked", rules=[("permit", True)]),
        verify_pg(action="readWorkspaceFile", in_workspace_root=False, rules=[("permit", True)]),
        verify_pg(action="networkProbe", scope="inScopeAuthorized", rules=[("permit", True), ("forbid", True)]),
    ):
        assert all(not c.violated for c in checks)
        assert checks[0].observed_verdict == "allowed=False"

    assert reconcile_verdict_mirror(True, False) is True


# (F3, F4)
def test_t3_12_cli_linux_poc_and_swarm_essemble_sandbox_flags(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    import revenue_cli
    from engine.linux_poc_runner import build_hardened_docker_argv

    degraded_toolchain_env()
    rc = revenue_cli.run_revenue_cli(
        [
            "linux-poc",
            "--lang",
            "python",
            "--repo",
            str(policy_guard_repo),
            "--out",
            str(isolated_out_dir),
            "--",
            "python3",
            "scripts/poc_check.py",
        ]
    )
    assert rc == 1
    tr_json = json.loads((isolated_out_dir / "poc_transcript.json").read_text(encoding="utf-8"))
    assert tr_json["status"] == "unavailable"
    assert tr_json["verified"] is False

    argv = build_hardened_docker_argv(
        docker_bin="docker",
        image="python:3.12-slim",
        repo_dir=policy_guard_repo,
        cmd=["python3", "scripts/poc_check.py"],
    )
    assert "--network=none" in argv and "--read-only" in argv


# (F3, F5)
def test_t3_13_mcp_run_linux_poc_and_bb_run_all_scan_degradation(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    from bugbounty_mcp_server import BugBountyMCPServer

    degraded_toolchain_env()
    srv = BugBountyMCPServer()

    poc_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3131,
            "method": "tools/call",
            "params": {
                "name": "bb_run_linux_poc",
                "arguments": {
                    "language": "python",
                    "repo_path": str(policy_guard_repo),
                    "cmd": ["python3", "scripts/poc_check.py"],
                    "out_dir": str(isolated_out_dir / "poc"),
                },
            },
        }
    )
    assert poc_resp["result"]["isError"] is False
    poc_data = json.loads(poc_resp["result"]["content"][0]["text"])
    assert poc_data["status"] == "unavailable"
    assert poc_data["verified"] is False

    all_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3132,
            "method": "tools/call",
            "params": {
                "name": "bb_run_all_scan",
                "arguments": {
                    "target": str(policy_guard_repo),
                    "output_dir": str(isolated_out_dir / "scan"),
                    "ensemble": True,
                    "dry_run": True,
                },
            },
        }
    )
    assert all_resp["result"]["isError"] is False
    all_data = json.loads(all_resp["result"]["content"][0]["text"])
    assert "toolchain_status" in all_data or "toolchain_status" in all_data.get("ensemble", {})


# (F3, F6) and (F3, F7)
def test_t3_14_symbolic_hook_and_docker_runner_degrade_and_reject_unsafe(
    policy_guard_repo: Path,
    degraded_toolchain_env: Any,
) -> None:
    from engine.linux_poc_runner import LinuxPocRunner

    run_symbolic_hook = import_contract("engine.linux_poc_runner", "run_symbolic_hook")
    degraded_toolchain_env()

    # (F3, F6): absent klee degrades cleanly
    res_klee = run_symbolic_hook("klee", policy_guard_repo)
    assert res_klee["available"] is False
    assert res_klee["status"] == "unavailable"
    assert res_klee["verified"] is False

    # (F3, F7): unsafe target/tokens fail closed
    res_unsafe = run_symbolic_hook("angr", r"C:\Windows\System32")
    assert res_unsafe["status"] == "rejected_unsafe"
    assert res_unsafe["verified"] is False

    tr_bad_mount = LinuxPocRunner().run_poc(
        language="python",
        repo_path=r"\\attacker\share",
        cmd=["python3", "scripts/poc_check.py"],
    )
    assert tr_bad_mount.status == "rejected_unsafe"

    tr_bad_cmd = LinuxPocRunner().run_poc(
        language="python",
        repo_path=policy_guard_repo,
        cmd=["python3", "x.py; id"],
    )
    assert tr_bad_cmd.status == "rejected_unsafe"


# (F4, F5), (F4, F6), (F4, F7), (F5, F6), (F5, F7)
def test_t3_15_cli_and_mcp_share_argv_degradation_and_scope_guards(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    import rfc_hunt_swarm
    import revenue_cli
    from bugbounty_mcp_server import build_rfchunt_all_argv, run_rfchunt_all_scan
    from engine.docker_wsl_doctor import repair_docker_wsl

    degraded_toolchain_env()

    # (F4, F5): MCP build_rfchunt_all_argv tokens parse cleanly in rfc_hunt_swarm.parse_swarm_arguments
    argv = build_rfchunt_all_argv(
        target=str(policy_guard_repo),
        output_dir=str(isolated_out_dir),
        ensemble=True,
        program="cloudflare",
        ensemble_quorum=3,
        dry_run=True,
    )
    parsed = rfc_hunt_swarm.parse_swarm_arguments(argv[2:])
    assert getattr(parsed, "run_all_scans", False) is True
    assert getattr(parsed, "dry_run", False) is True

    # (F4, F7) & (F5, F7): traversal SARIF & shell-injected extra_flags fail closed
    with pytest.raises(ValueError):
        build_rfchunt_all_argv(target=str(policy_guard_repo), extra_flags=["; rm -rf /"])

    proc_trav = run_cli_subprocess(
        "rfc_hunt_swarm.py",
        ["--all", "--repo", str(policy_guard_repo), "--export-sarif", "../escape.sarif"],
    )
    assert proc_trav.returncode != 0

    # (F4, F6) & (F5, F6): degraded toolchains degrade cleanly in both CLI and MCP
    rc_cli = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(policy_guard_repo),
            "--all",
            "--essemble",
            "--proxy",
            "http://127.0.0.1:8888",
            "--out",
            str(isolated_out_dir / "cli_deg"),
        ]
    )
    assert rc_cli == 0
    cli_rep = json.loads((isolated_out_dir / "cli_deg" / "ensemble_report.json").read_text(encoding="utf-8"))
    assert cli_rep["toolchain_status"]["docker"]["available"] is False

    mcp_res = run_rfchunt_all_scan(
        target=str(policy_guard_repo),
        output_dir=str(isolated_out_dir / "mcp_deg"),
        ensemble=True,
        dry_run=True,
    )
    assert mcp_res["status"] == "dry_run_ready"
    assert mcp_res["lean_verification"]["machine_checked"] is False
    assert repair_docker_wsl().status == "skipped_guard"


# (F6, F7)
def test_t3_16_degraded_toolchain_preserves_defensive_scope_and_non_bypass(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    from engine.docker_wsl_doctor import repair_docker_wsl
    from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator
    from engine.linux_poc_runner import LinuxPocRunner, validate_command_tokens, validate_mount_path

    evaluate_lean_domains = import_contract("engine.lean_formal_verifier", "evaluate_lean_domains")
    degraded_toolchain_env()

    assert repair_docker_wsl(approval_mode="deny").status == "skipped_guard"
    assert validate_mount_path(r"C:\Windows\System32")[0] is False
    assert validate_command_tokens(["python3", "x.py | cat"])[0] is False
    assert LinuxPocRunner().run_poc(language="python", repo_path=r"\\evil\share", cmd=["python3"]).status == "rejected_unsafe"

    dom = evaluate_lean_domains(
        findings=[{"rule_id": "PG-SHELL", "title": "shellExec bypass", "metadata": {"observed_allowed": True}}],
        lean_dir=REPO_ROOT / "formal" / "lean4",
    )
    assert dom.violations_count >= 1

    orch = EnsembleOrchestrator(program="arc-bbp", quorum=1)
    rep = orch.run(
        policy_guard_repo,
        findings=[
            EngineFinding(
                engine="raptor",
                title="TODO style nit informational",
                file_path="src/agent_handler.py",
                line=1,
                cwe="CWE-200",
                severity="INFO",
            )
        ],
        out_dir=isolated_out_dir,
        refresh_stix=False,
    )
    assert rep.clusters[0].disposition == "HELD_OUT_OF_THREAT_MODEL"
