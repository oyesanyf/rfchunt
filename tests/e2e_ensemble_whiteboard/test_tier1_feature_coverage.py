"""
Tier 1 Feature Coverage Tests (F1-F7, >=35 tests, >=5 per feature area).

Opaque-box, zero-mock-SUT verification of RFCHunt's Planner-Worker-Verifier
whiteboard, Lean 4 domain/diagnostic verification, LinuxPocRunner & symbolic hooks,
CLI/MCP entry points, graceful toolchain degradation, and defensive scope enforcement.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from tests.e2e_ensemble_whiteboard.conftest import (
    REPO_ROOT,
    extract_field,
    import_contract,
    import_first_available,
    make_verified_transcript,
    run_cli_subprocess,
)

pytestmark = pytest.mark.tier1


# ===========================================================================
# F1: Planner-Worker-Verifier Shared Whiteboard (6 tests)
# ===========================================================================


def test_t1_f1_01_whiteboard_hypothesis_lifecycle_transitions() -> None:
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
    hyp = HypothesisCls(
        hypothesis_id="HYP-001",
        title="CL+TE Request Smuggling Candidate",
        domain="http_framing",
        file_path="src/http_proxy.py",
        line=12,
        status="OPEN",
    )

    if hasattr(wb, "add_hypothesis"):
        wb.add_hypothesis(hyp)
    elif hasattr(wb, "post_hypothesis"):
        wb.post_hypothesis(hyp)
    else:
        raise AssertionError("Whiteboard missing add_hypothesis / post_hypothesis method")

    for next_status in ("DISPATCHED", "COUNTEREXAMPLE_FOUND"):
        if hasattr(wb, "update_status"):
            wb.update_status("HYP-001", next_status, evidence={"theorem": "differential_witness_cl_te"})
        elif hasattr(wb, "transition"):
            wb.transition("HYP-001", next_status, evidence={"theorem": "differential_witness_cl_te"})
        else:
            raise AssertionError("Whiteboard missing update_status / transition method")

    snap = wb.to_dict() if hasattr(wb, "to_dict") else wb.snapshot()
    assert isinstance(snap, dict)
    items = extract_field(snap, "hypotheses", "items")
    assert len(items) >= 1
    first = items[0] if isinstance(items, list) else next(iter(items.values()))
    assert extract_field(first, "status") == "COUNTEREXAMPLE_FOUND"


def test_t1_f1_02_whiteboard_thread_safe_concurrent_updates() -> None:
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

    def _worker(idx: int) -> None:
        hid = f"HYP-CONC-{idx:03d}"
        add_fn(
            HypothesisCls(
                hypothesis_id=hid,
                title=f"Concurrent Hypothesis {idx}",
                domain="policy_guard",
                file_path=f"src/mod_{idx}.py",
                line=idx + 1,
                status="OPEN",
            )
        )
        upd_fn(hid, "DISPATCHED")
        upd_fn(hid, "VERIFIED" if idx % 2 == 0 else "REFUTED")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_worker, range(24)))

    snap = wb.to_dict() if hasattr(wb, "to_dict") else wb.snapshot()
    items = extract_field(snap, "hypotheses", "items")
    assert len(items) == 24


def test_t1_f1_03_orchestrator_runs_parallel_workers_and_exports_artifacts(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    # Keep Semgrep out of network auto-config inside unit-speed Tier 1 test while keeping real WebLLM+GHA+Lean4
    import engine.linux_poc_runner as lpr
    from engine.ensemble_orchestrator import EnsembleOrchestrator

    # Only disable semgrep network config lookup if semgrep is present; leave real WebLLM/GHA/Lean4 active
    orig_which = lpr.shutil.which
    import shutil
    monkeypatch_ctx = pytest.MonkeyPatch()
    monkeypatch_ctx.setattr(
        shutil,
        "which",
        lambda name: None if name == "semgrep" else orig_which(name),
    )
    try:
        orch = EnsembleOrchestrator(
            program="generic",
            quorum=1,
            max_whiteboard_rounds=2,
            enable_whiteboard=True,
        )
        report = orch.run(
            policy_guard_repo,
            out_dir=isolated_out_dir,
            package_client_name="Acme Security",
            refresh_stix=False,
        )
    finally:
        monkeypatch_ctx.undo()

    rep_dict = report.to_dict()
    assert "whiteboard" in rep_dict and isinstance(rep_dict["whiteboard"], dict)
    assert "lean_verification" in rep_dict and isinstance(rep_dict["lean_verification"], dict)
    assert "toolchain_status" in rep_dict and isinstance(rep_dict["toolchain_status"], dict)
    assert len(report.clusters) >= 1

    json_path = isolated_out_dir / "ensemble_report.json"
    md_path = isolated_out_dir / "ensemble_summary.md"
    sarif_path = isolated_out_dir / "ensemble_findings.sarif"
    bundle_dir = isolated_out_dir / "client_audit_bundle"
    assert json_path.is_file()
    assert md_path.is_file()
    assert sarif_path.is_file()
    assert bundle_dir.is_dir()

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(report.clusters)


def test_t1_f1_04_orchestrator_non_fabrication_on_clean_hardened_repo(
    clean_hardened_repo: Path,
    isolated_out_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import shutil
    from engine.ensemble_orchestrator import EnsembleOrchestrator

    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda n: None if n == "semgrep" else orig_which(n))

    orch = EnsembleOrchestrator(program="generic", quorum=1, max_whiteboard_rounds=2)
    report = orch.run(clean_hardened_repo, out_dir=isolated_out_dir, refresh_stix=False)

    assert report.counts_by_disposition.get("SUBMISSION_READY", 0) == 0
    assert report.clusters == []
    rep_dict = report.to_dict()
    assert "whiteboard" in rep_dict
    wb_items = extract_field(rep_dict["whiteboard"], "hypotheses", "items", default=[])
    if isinstance(wb_items, dict):
        wb_items = list(wb_items.values())
    for item in wb_items:
        assert extract_field(item, "status") not in ("VERIFIED", "COUNTEREXAMPLE_FOUND")


def test_t1_f1_05_consensus_voter_deterministic_override_immunity() -> None:
    from engine.ensemble_orchestrator import EngineFinding, EnsembleConsensusVoter

    findings = [
        EngineFinding(
            engine="lean4",
            title="RFC 9112 CL+TE Framing Divergence",
            file_path="src/http_proxy.py",
            line=15,
            cwe="CWE-444",
            severity="CRITICAL",
            deterministic=True,
            confirmed=True,
        ),
        EngineFinding(
            engine="mantis",
            title="RFC 9112 CL+TE Framing Divergence",
            file_path="src/http_proxy.py",
            line=16,
            cwe="CWE-444",
            severity="CRITICAL",
            deterministic=False,
            confirmed=False,
        ),
    ]
    voter = EnsembleConsensusVoter(program="generic", quorum=2)
    clusters = voter.fuse(findings)
    assert len(clusters) == 1
    c = clusters[0]
    assert c.lean_verified is True
    assert c.deterministic_override_protected is True
    assert c.llm_dissent_ignored is True
    assert c.disposition == "ENSEMBLE_CORROBORATED_STATIC"


def test_t1_f1_06_stage0_freshness_and_stage4_poc_promotion(http_framing_repo: Path) -> None:
    from engine.ensemble_orchestrator import (
        EngineFinding,
        EnsembleConsensusVoter,
        inspect_repo_freshness,
    )

    snap = inspect_repo_freshness(http_framing_repo, freshness_hours=72)
    assert snap.is_git_repo is True
    assert snap.freshness_status == "FRESH_UNDER_72H"
    assert "src/http_proxy.py" in snap.fresh_files
    assert "src/old_parser.py" not in snap.fresh_files

    findings = [
        EngineFinding(engine="mantis", title="Stale framing issue", file_path="src/old_parser.py", line=5, cwe="CWE-444", severity="HIGH"),
        EngineFinding(engine="raptor", title="Stale framing issue", file_path="src/old_parser.py", line=6, cwe="CWE-444", severity="HIGH"),
        EngineFinding(engine="mantis", title="Fresh framing issue", file_path="src/http_proxy.py", line=5, cwe="CWE-444", severity="HIGH"),
        EngineFinding(engine="raptor", title="Fresh framing issue", file_path="src/http_proxy.py", line=6, cwe="CWE-444", severity="HIGH"),
    ]
    voter = EnsembleConsensusVoter(program="generic", quorum=2)

    static_clusters = voter.fuse(findings, freshness=snap)
    assert static_clusters[0].file_path == "src/http_proxy.py"
    assert static_clusters[0].freshness_status == "FRESH_UNDER_72H"
    assert all(c.disposition == "ENSEMBLE_CORROBORATED_STATIC" for c in static_clusters)

    tr = make_verified_transcript(http_framing_repo, language="python", backend="docker")
    promoted = voter.fuse(findings, freshness=snap, poc_transcripts={"src/http_proxy.py": tr})
    assert promoted[0].file_path == "src/http_proxy.py"
    assert promoted[0].disposition == "SUBMISSION_READY"
    assert promoted[0].poc_verified is True
    assert promoted[1].disposition == "ENSEMBLE_CORROBORATED_STATIC"


# ===========================================================================
# F2: Lean 4 Formal Invariant & Counterexample Verification (6 tests)
# ===========================================================================


def test_t1_f2_01_verify_lean_workspace_audits_all_modules_and_theorems() -> None:
    from engine.lean_formal_verifier import verify_lean_workspace

    rep = verify_lean_workspace(REPO_ROOT / "formal" / "lean4")
    assert rep.status in ("machine_checked", "static_audited_lean_not_installed")
    assert len(rep.modules) == 3
    assert rep.total_theorems == 11
    for mod in rep.modules:
        assert mod.has_sorry is False
        assert mod.has_custom_axiom is False
        assert mod.clean_proofs is True
    if rep.lake_binary is None:
        assert rep.machine_checked is False


def test_t1_f2_02_http_framing_invariant_detects_cl_te_and_dual_cl() -> None:
    verify_http = import_contract("engine.lean_formal_verifier", "verify_http_framing_invariant")
    LeanCounterexample = import_contract("engine.lean_formal_verifier", "LeanCounterexample")

    cl_te = verify_http(
        content_lengths=[42],
        has_transfer_encoding_chunked=True,
        lean_dir=REPO_ROOT / "formal" / "lean4",
    )
    assert all(isinstance(c, LeanCounterexample) for c in cl_te)
    assert any(c.domain == "http_framing" and c.theorem == "differential_witness_cl_te" and c.violated for c in cl_te)

    dual_cl = verify_http(
        content_lengths=[10, 20],
        has_transfer_encoding_chunked=False,
        lean_dir=REPO_ROOT / "formal" / "lean4",
    )
    assert any(c.theorem == "strict_rejects_mismatched_dual_cl" and c.violated for c in dual_cl)

    clean = verify_http(
        content_lengths=[42],
        has_transfer_encoding_chunked=False,
        lean_dir=REPO_ROOT / "formal" / "lean4",
    )
    assert all(not c.violated for c in clean)


def test_t1_f2_03_policy_guard_invariant_enforces_containment_theorems() -> None:
    verify_pg = import_contract("engine.lean_formal_verifier", "verify_policy_guard_invariant")

    c_shell = verify_pg(action="shellExec", scope="inScopeAuthorized", rules=[("permit", True)])
    assert c_shell[0].theorem == "shell_exec_never_permitted"
    assert c_shell[0].violated is False

    c_scope = verify_pg(action="networkProbe", scope="outOfScope", rules=[("permit", True)])
    assert c_scope[0].theorem == "out_of_scope_probe_always_denied"
    assert c_scope[0].violated is False

    c_override = verify_pg(confirmed_by_tool=True, llm_confirmed=False, observed_reconciled=False)
    assert any(c.theorem == "deterministic_confirmation_immutable" and c.violated for c in c_override)


def test_t1_f2_04_dotnet_pe_invariant_detects_cve_2026_108398() -> None:
    verify_pe = import_contract("engine.lean_formal_verifier", "verify_dotnet_pe_invariant")

    anom = verify_pe(
        is_valid_pe=True,
        has_clr_descriptor=True,
        has_executable_image_bit=False,
        is_umci_enforced=True,
        is_signed_by_trusted_publisher=False,
    )
    assert any(c.domain == "dotnet_pe" and c.theorem == "anomaly_triggers_unpatched_fallback" and c.violated for c in anom)
    assert any("loadedViaUncheckedFlatMemoryFallback" in c.observed_verdict for c in anom)

    clean = verify_pe(
        is_valid_pe=True,
        has_clr_descriptor=True,
        has_executable_image_bit=True,
        is_umci_enforced=True,
        is_signed_by_trusted_publisher=True,
    )
    assert all(not c.violated for c in clean)


def test_t1_f2_05_evaluate_lean_domains_aggregates_findings_and_repo_pes(dotnet_pe_repo: Path) -> None:
    evaluate_lean_domains = import_contract("engine.lean_formal_verifier", "evaluate_lean_domains")

    findings = [
        {
            "rule_id": "HTTP-CL-TE",
            "cwe": "CWE-444",
            "title": "CL+TE request smuggling desync",
            "summary": "Per-hop framing discrepancy",
        },
        {
            "rule_id": "POLICY-IMMUT-01",
            "title": "LLM dissent on deterministic tool confirmation",
            "summary": "llm_dissent override_immunity",
            "metadata": {"observed_reconciled": False},
        },
    ]
    rep = evaluate_lean_domains(
        findings=findings,
        repo_path=dotnet_pe_repo,
        lean_dir=REPO_ROOT / "formal" / "lean4",
    )
    d = rep.to_dict()
    assert rep.status == "counterexample_found"
    assert set(rep.domains_checked) == {"http_framing", "policy_guard", "dotnet_pe"}
    assert d["domain_checks"]["http_framing"]["violations"] >= 1
    assert d["domain_checks"]["policy_guard"]["violations"] >= 1
    assert d["domain_checks"]["dotnet_pe"]["violations"] >= 1


def test_t1_f2_06_lake_proof_diagnostic_parsing_and_serialization(
    lean_workspace_copy: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.lean_formal_verifier as lfv

    LeanProofDiagnostic = import_contract("engine.lean_formal_verifier", "LeanProofDiagnostic")
    verify_lean_workspace = import_contract("engine.lean_formal_verifier", "verify_lean_workspace")

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
                "error: RFCHunt/PolicyGuard.lean:74:2: unsolved goals\n"
                "case inr\n"
                "⊢ False\n"
            ),
        ),
    )

    rep = verify_lean_workspace(lean_workspace_copy)
    assert rep.status == "kernel_failed"
    assert rep.machine_checked is False
    assert len(rep.diagnostics) == 1
    diag = rep.diagnostics[0]
    assert isinstance(diag, LeanProofDiagnostic)
    assert diag.module == "RFCHunt.PolicyGuard"
    assert diag.kind == "unsolved_goals"
    assert diag.line == 74
    assert diag.column == 2
    assert "⊢ False" in diag.branch_summary
    assert rep.to_dict()["diagnostics"][0]["kind"] == "unsolved_goals"


# ===========================================================================
# F3: LinuxPocRunner & Optional Symbolic Hooks (5 tests)
# ===========================================================================


def test_t1_f3_01_build_hardened_docker_argv_invariants(policy_guard_repo: Path) -> None:
    from engine.linux_poc_runner import LANGUAGE_PROFILES, build_hardened_docker_argv

    for lang, profile in LANGUAGE_PROFILES.items():
        argv = build_hardened_docker_argv(
            docker_bin="docker",
            image=profile["image"],
            repo_dir=policy_guard_repo,
            cmd=profile["version_cmd"],
        )
        assert "--rm" in argv
        assert "--network=none" in argv
        assert "--cap-drop=ALL" in argv
        assert "no-new-privileges:true" in argv
        assert "--read-only" in argv
        assert "--memory" in argv
        assert "--cpus" in argv
        assert "--pids-limit" in argv
        assert any(tok.endswith(":/workspace:ro") for tok in argv), f"Missing :ro mount for {lang}"


def test_t1_f3_02_probe_optional_backends_schema() -> None:
    probe_optional_backends = import_contract("engine.linux_poc_runner", "probe_optional_backends")
    probe_alias = import_contract("engine.linux_poc_runner", "probe_toolchain_availability")
    assert probe_alias is probe_optional_backends

    res = probe_optional_backends(lean_dir=REPO_ROOT / "formal" / "lean4")
    core_expected = {
        "docker",
        "wsl2",
        "lean4",
        "rfchunt_lean_oracle",
        "angr",
        "klee",
        "semgrep",
    }
    assert core_expected.issubset(res.keys())
    for key, entry in res.items():
        assert set(entry.keys()) >= {"available", "status", "reason", "path_or_module"}, key
        assert isinstance(entry["available"], bool), key
        assert isinstance(entry["status"], str) and entry["status"], key
        assert isinstance(entry["reason"], str) and entry["reason"], key


def test_t1_f3_03_run_symbolic_hook_angr_and_klee_contract(policy_guard_repo: Path) -> None:
    run_symbolic_hook = import_contract("engine.linux_poc_runner", "run_symbolic_hook")
    target_file = policy_guard_repo / "scripts" / "poc_check.py"

    for backend in ("angr", "klee"):
        res = run_symbolic_hook(backend, target_file, timeout_sec=5.0)
        assert res["backend"] == backend
        assert isinstance(res["available"], bool)
        assert isinstance(res["status"], str) and res["status"]
        assert isinstance(res["findings"], list)
        if not res["available"]:
            assert res["status"] == "unavailable"
            assert res["verified"] is False
            assert res["remediation_hint"]


def test_t1_f3_04_transcript_bundle_and_wsl_path_conversion(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
) -> None:
    from engine.linux_poc_runner import (
        VerifiableTranscript,
        save_transcript_bundle,
        windows_to_wsl_path,
    )

    assert windows_to_wsl_path(r"D:\harfile\rfchunt") == "/mnt/d/harfile/rfchunt"

    tr_pass = make_verified_transcript(policy_guard_repo, status="passed", exit_code=0)
    assert tr_pass.verified is True
    j_path, m_path = save_transcript_bundle(tr_pass, isolated_out_dir, stem="t1_pass")
    assert j_path.is_file() and m_path.is_file()
    payload = json.loads(j_path.read_text(encoding="utf-8"))
    assert payload["verified"] is True

    tr_fail = VerifiableTranscript(
        language="python",
        backend="docker",
        status="failed",
        exit_code=1,
        command=["python3", "scripts/poc_check.py"],
        image="python:3.12-slim",
        repo_path=str(policy_guard_repo),
        started_at_utc="2026-11-26T00:00:00Z",
        elapsed_ms=10.0,
    )
    assert tr_fail.verified is False


def test_t1_f3_05_validate_mount_path_and_command_tokens_valid_inputs(policy_guard_repo: Path) -> None:
    from engine.linux_poc_runner import (
        LANGUAGE_PROFILES,
        validate_command_tokens,
        validate_mount_path,
    )

    ok_m, resolved = validate_mount_path(policy_guard_repo)
    assert ok_m is True
    assert Path(resolved) == policy_guard_repo.resolve()

    for prof in LANGUAGE_PROFILES.values():
        ok_c, msg = validate_command_tokens([prof["binary"], *prof["default_args"]])
        assert ok_c is True, msg


# ===========================================================================
# F4: CLI Entry Points (5 tests)
# ===========================================================================


def test_t1_f4_01_revenue_cli_ensemble_audit_all_ensemble(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import shutil
    import revenue_cli

    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda n: None if n == "semgrep" else orig_which(n))

    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(policy_guard_repo),
            "--all",
            "--ensemble",
            "--quorum",
            "1",
            "--out",
            str(isolated_out_dir),
        ]
    )
    assert rc == 0
    rep_json = isolated_out_dir / "ensemble_report.json"
    assert rep_json.is_file()
    data = json.loads(rep_json.read_text(encoding="utf-8"))
    assert "whiteboard" in data
    assert "lean_verification" in data
    assert "toolchain_status" in data
    assert len(data["clusters"]) >= 1


def test_t1_f4_02_revenue_cli_ensemble_audit_essemble_and_proxy(
    http_framing_repo: Path,
    isolated_out_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import shutil
    import revenue_cli

    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda n: None if n == "semgrep" else orig_which(n))

    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(http_framing_repo),
            "--all",
            "--essemble",
            "--proxy",
            "http://127.0.0.1:8080",
            "--out",
            str(isolated_out_dir),
        ]
    )
    assert rc == 0
    rep_json = isolated_out_dir / "ensemble_report.json"
    assert rep_json.is_file()
    data = json.loads(rep_json.read_text(encoding="utf-8"))
    assert "whiteboard" in data
    assert "toolchain_status" in data
    # Verify --proxy was propagated (either on report/whiteboard or orchestrator metadata)
    serialized = json.dumps(data)
    assert "127.0.0.1:8080" in serialized


def test_t1_f4_03_revenue_cli_lean_verify_outputs_diagnostics_json() -> None:
    proc = run_cli_subprocess(
        "revenue_cli.py",
        ["lean-verify", "--lean-dir", "formal/lean4"],
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["total_theorems"] == 11
    assert len(data["modules"]) == 3
    assert isinstance(data["diagnostics"], list)


def test_t1_f4_04_swarm_all_ensemble_dry_run_flags(
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
            "--ensemble",
            "--program",
            "generic",
            "--freshness-hours",
            "72",
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
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    plan = json.loads(proc.stdout)
    assert plan["status"] == "dry_run_plan_ready"
    assert plan["dry_run"] is True
    assert plan["side_effects"]["network_packets_sent"] == 0
    assert plan["side_effects"]["filesystem_mutations"] == 0
    assert plan["side_effects"]["browser_launched"] is False


def test_t1_f4_05_swarm_all_essemble_alias_dry_run(
    http_framing_repo: Path,
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    proc = run_cli_subprocess(
        "rfc_hunt_swarm.py",
        [
            "--all",
            "--repo",
            str(http_framing_repo),
            "--essemble",
            "--program",
            "generic",
            "--freshness-hours",
            "48",
            "--quorum",
            "1",
            "--dry-run",
            "--json",
            "--output-dir",
            str(isolated_out_dir),
            "--db",
            str(isolated_db_path),
        ],
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    plan = json.loads(proc.stdout)
    assert plan["status"] == "dry_run_plan_ready"
    assert plan["dry_run"] is True


# ===========================================================================
# F5: MCP Entry Point (5 tests)
# ===========================================================================


def test_t1_f5_01_mcp_tools_list_advertises_ensemble_schema() -> None:
    from bugbounty_mcp_server import BugBountyMCPServer

    srv = BugBountyMCPServer()
    resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tools = {t["name"]: t for t in resp["result"]["tools"]}
    assert "bb_run_all_scan" in tools
    props = tools["bb_run_all_scan"]["inputSchema"]["properties"]
    for field in ("ensemble", "program", "freshness_hours", "ensemble_quorum", "include_lean_verify"):
        assert field in props


def test_t1_f5_02_build_rfchunt_all_argv_safe_flags(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
) -> None:
    from bugbounty_mcp_server import build_rfchunt_all_argv

    argv = build_rfchunt_all_argv(
        target=str(policy_guard_repo),
        output_dir=str(isolated_out_dir),
        ensemble=True,
        program="shopify",
        freshness_hours=48,
        ensemble_quorum=3,
        dry_run=True,
    )
    assert "--all" in argv
    assert "--ensemble" in argv
    assert "--dry-run" in argv
    assert "--program" in argv and argv[argv.index("--program") + 1] == "shopify"
    assert "--freshness-hours" in argv and argv[argv.index("--freshness-hours") + 1] == "48"
    assert "--quorum" in argv and argv[argv.index("--quorum") + 1] == "3"


def test_t1_f5_03_run_rfchunt_all_scan_dry_run_with_lean(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
) -> None:
    from bugbounty_mcp_server import run_rfchunt_all_scan

    res = run_rfchunt_all_scan(
        target=str(policy_guard_repo),
        output_dir=str(isolated_out_dir),
        ensemble=True,
        dry_run=True,
        include_lean_verify=True,
    )
    assert res["status"] == "dry_run_ready"
    assert res["mode"] == "--all --ensemble"
    assert res["lean_verification"]["total_theorems"] == 11
    assert "toolchain_status" in res or "ensemble" in res


def test_t1_f5_04_mcp_bb_run_all_scan_end_to_end(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    from bugbounty_mcp_server import BugBountyMCPServer

    srv = BugBountyMCPServer()
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 42,
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
                    "include_lean_verify": True,
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
    assert payload["exit_code"] == 0
    assert "lean_verification" in payload and payload["lean_verification"]["total_theorems"] == 11
    assert "ensemble" in payload and isinstance(payload["ensemble"], dict)
    assert "whiteboard" in payload["ensemble"]
    assert "clusters" in payload["ensemble"]
    assert "toolchain_status" in payload["ensemble"]


def test_t1_f5_05_mcp_bb_lean_formal_verify_rpc() -> None:
    from bugbounty_mcp_server import BugBountyMCPServer

    srv = BugBountyMCPServer()
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 55,
            "method": "tools/call",
            "params": {
                "name": "bb_lean_formal_verify",
                "arguments": {"lean_dir": str(REPO_ROOT / "formal" / "lean4")},
            },
        }
    )
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["total_theorems"] == 11
    assert len(payload["modules"]) == 3
    assert isinstance(payload["diagnostics"], list)


# ===========================================================================
# F6: Graceful Toolchain Degradation (5 tests)
# ===========================================================================


def test_t1_f6_01_missing_docker_and_wsl_degrades_cleanly(
    policy_guard_repo: Path,
    degraded_toolchain_env: Any,
) -> None:
    from engine.linux_poc_runner import LinuxPocRunner

    degraded_toolchain_env()
    tr = LinuxPocRunner().run_poc(
        language="python",
        repo_path=policy_guard_repo,
        cmd=["python3", "scripts/poc_check.py"],
    )
    assert tr.status == "unavailable"
    assert tr.backend == "unavailable"
    assert tr.verified is False
    assert tr.remediation_hint


def test_t1_f6_02_missing_lean_degrades_without_machine_checked(
    degraded_toolchain_env: Any,
) -> None:
    verify_lean_workspace = import_contract("engine.lean_formal_verifier", "verify_lean_workspace")
    evaluate_lean_domains = import_contract("engine.lean_formal_verifier", "evaluate_lean_domains")

    degraded_toolchain_env()
    ws = verify_lean_workspace(REPO_ROOT / "formal" / "lean4")
    assert ws.status == "static_audited_lean_not_installed"
    assert ws.machine_checked is False

    dom = evaluate_lean_domains(lean_dir=REPO_ROOT / "formal" / "lean4")
    assert dom.machine_checked is False
    assert dom.oracle_backend == "python_mirror"
    assert dom.degradation_reason


def test_t1_f6_03_missing_angr_and_klee_degrade_cleanly(
    policy_guard_repo: Path,
    degraded_toolchain_env: Any,
) -> None:
    probe_optional_backends = import_contract("engine.linux_poc_runner", "probe_optional_backends")
    run_symbolic_hook = import_contract("engine.linux_poc_runner", "run_symbolic_hook")

    degraded_toolchain_env()
    probes = probe_optional_backends(lean_dir=REPO_ROOT / "formal" / "lean4")
    assert probes["angr"]["available"] is False and probes["angr"]["status"] == "unavailable"
    assert probes["klee"]["available"] is False and probes["klee"]["status"] == "unavailable"

    for backend in ("angr", "klee"):
        res = run_symbolic_hook(backend, policy_guard_repo)
        assert res["available"] is False
        assert res["status"] == "unavailable"
        assert res["verified"] is False
        assert res["findings"] == []


def test_t1_f6_04_missing_semgrep_completes_other_engines(
    policy_guard_repo: Path,
    degraded_toolchain_env: Any,
) -> None:
    from engine.ensemble_orchestrator import EnsembleOrchestrator

    degraded_toolchain_env()
    findings, tele = EnsembleOrchestrator.run_exhaustive_local_engines(
        policy_guard_repo, refresh_stix=False
    )
    assert "raptor_semgrep" in tele
    assert tele["raptor_semgrep"]["status"] in ("semgrep_not_installed", "unavailable")
    assert any(f.engine in ("web_llm", "gha_agent") for f in findings)


def test_t1_f6_05_full_toolchain_outage_completes_with_explicit_telemetry(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    from engine.ensemble_orchestrator import EnsembleOrchestrator

    degraded_toolchain_env()
    orch = EnsembleOrchestrator(program="generic", quorum=1, max_whiteboard_rounds=2)
    report = orch.run(
        policy_guard_repo,
        poc_lang="python",
        poc_cmd=["python3", "scripts/poc_check.py"],
        out_dir=isolated_out_dir,
        refresh_stix=False,
    )
    d = report.to_dict()
    assert "toolchain_status" in d
    assert d["toolchain_status"]["docker"]["available"] is False
    assert d["toolchain_status"]["lean4"]["available"] is False
    assert report.counts_by_disposition.get("SUBMISSION_READY", 0) == 0


# ===========================================================================
# F7: Defensive Scope Enforcement (5 tests)
# ===========================================================================


def test_t1_f7_01_validate_mount_path_rejects_unc_and_critical_host_dirs() -> None:
    from engine.linux_poc_runner import validate_mount_path

    for bad in (r"\\attacker\share\repo", r"C:\Windows\System32", r"C:\ProgramData", "/etc", "/var/run/docker.sock"):
        ok, _msg = validate_mount_path(bad)
        assert ok is False, f"Expected rejection for {bad!r}"


def test_t1_f7_02_validate_command_tokens_rejects_shell_metacharacters() -> None:
    from engine.linux_poc_runner import validate_command_tokens

    for bad_tok in ("x; id", "x | cat", "$(whoami)", "`id`", "a && b", "a > out", "a < in", "a\nb", "a\x00b"):
        ok, _msg = validate_command_tokens(["python3", bad_tok])
        assert ok is False, f"Expected shell metacharacter rejection for {bad_tok!r}"


def test_t1_f7_03_build_hardened_docker_argv_rejects_bad_image_and_enforces_ro_nonet(
    policy_guard_repo: Path,
) -> None:
    from engine.linux_poc_runner import build_hardened_docker_argv

    with pytest.raises(ValueError):
        build_hardened_docker_argv(
            docker_bin="docker",
            image="python:3.12; rm -rf /",
            repo_dir=policy_guard_repo,
            cmd=["python3", "--version"],
        )

    argv = build_hardened_docker_argv(
        docker_bin="docker",
        image="python:3.12-slim",
        repo_dir=policy_guard_repo,
        cmd=["python3", "--version"],
    )
    assert "--network=none" in argv
    assert any(tok.endswith(":/workspace:ro") for tok in argv)


def test_t1_f7_04_vendor_threat_model_holds_out_of_scope_findings() -> None:
    from engine.ensemble_orchestrator import (
        EngineFinding,
        EnsembleConsensusVoter,
        evaluate_vendor_threat_model,
    )

    v_anth = evaluate_vendor_threat_model(
        title="Cross-session OpenProcess inside srt-sandbox",
        summary="Same UID processes in srt-sandbox",
        file_path="src/sandbox.rs",
        program="anthropic",
    )
    assert v_anth.passed is False

    v_shop = evaluate_vendor_threat_model(
        title="ucp-cli local CLI self-execution",
        summary="Local user invokes ucp-cli",
        file_path="cmd/ucp-cli/main.go",
        program="shopify",
    )
    assert v_shop.passed is False

    v_mac = evaluate_vendor_threat_model(
        title="macOS Seatbelt APFS bypass",
        summary="Static sandbox-exec check",
        file_path="src/seatbelt.rs",
        program="generic",
        poc_verified=True,
        poc_target_os="linux",
    )
    assert v_mac.passed is False

    voter = EnsembleConsensusVoter(program="shopify", quorum=1)
    clusters = voter.fuse(
        [
            EngineFinding(
                engine="raptor",
                title="ucp-cli local CLI self-execution",
                file_path="cmd/ucp-cli/main.go",
                line=10,
                cwe="CWE-78",
                severity="HIGH",
            )
        ]
    )
    assert clusters[0].disposition == "HELD_OUT_OF_THREAT_MODEL"


def test_t1_f7_05_mcp_argv_and_symbolic_hook_enforce_scope_invariants() -> None:
    from bugbounty_mcp_server import build_rfchunt_all_argv

    run_symbolic_hook = import_contract("engine.linux_poc_runner", "run_symbolic_hook")

    with pytest.raises(ValueError):
        build_rfchunt_all_argv(target="repo; rm -rf /", ensemble=True)

    res_path = run_symbolic_hook("angr", r"C:\Windows\System32")
    assert res_path["status"] == "rejected_unsafe"
    assert res_path["verified"] is False

    res_args = run_symbolic_hook("klee", str(REPO_ROOT / "formal" / "lean4"), args=["--flag; id"])
    assert res_args["status"] == "rejected_unsafe"
    assert res_args["verified"] is False
