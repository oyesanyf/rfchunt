"""Comprehensive unit & integration tests for M2 Whiteboard, Lean 4 Consensus, and Toolchain Degradation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

from database import Database
from engine.ensemble_orchestrator import (
    HYPOTHESIS_STATUSES,
    EngineFinding,
    EnsembleOrchestrator,
    EnsembleWhiteboard,
    SharedWhiteboard,
    WhiteboardHypothesis,
    render_ensemble_markdown,
)
from engine.ensemble_whiteboard import (
    EnsembleWhiteboard as DirectWhiteboard,
    SharedWhiteboard as DirectSharedWhiteboard,
    WhiteboardHypothesis as DirectHypothesis,
)
from engine.linux_poc_runner import VerifiableTranscript

REPO_ROOT = Path(__file__).resolve().parent.parent


def _disable_docker_and_wsl(
    monkeypatch: pytest.MonkeyPatch,
    *,
    include_semgrep: bool = True,
    include_lean: bool = False,
) -> None:
    import engine.docker_wsl_doctor as dwd
    import engine.linux_poc_runner as lpr

    orig_which = shutil.which
    blocked = {"docker", "wsl", "wsl.exe"}
    if include_semgrep:
        blocked.add("semgrep")
    if include_lean:
        blocked.update({"lean", "lake", "angr", "klee"})

    if include_semgrep and include_lean:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
    else:
        monkeypatch.setattr(
            shutil,
            "which",
            lambda n: None if n in blocked else orig_which(n),
        )

    disabled_diag = dwd.DockerWSLDiagnosis(
        platform="windows",
        docker_binary=None,
        docker_desktop_exe=None,
        daemon_running=False,
        server_version=None,
        issues=["Docker disabled in test"],
        healthy=False,
    )
    for mod in (lpr, dwd):
        monkeypatch.setattr(mod, "find_docker_binary", lambda *_a, **_kw: None)
        monkeypatch.setattr(mod, "probe_docker_daemon", lambda *_a, **_kw: (False, "disabled in test"))
        monkeypatch.setattr(mod, "diagnose_docker_wsl", lambda *_a, **_kw: disabled_diag)


def test_whiteboard_reexports_lifecycle_and_validation() -> None:
    assert EnsembleWhiteboard is DirectWhiteboard
    assert SharedWhiteboard is DirectSharedWhiteboard is EnsembleWhiteboard
    assert WhiteboardHypothesis is DirectHypothesis
    assert {
        "OPEN",
        "DISPATCHED",
        "TESTING",
        "VERIFIED",
        "COUNTEREXAMPLE_FOUND",
        "REFUTED",
        "UNVERIFIED_UNAVAILABLE",
    }.issubset(HYPOTHESIS_STATUSES)

    wb = EnsembleWhiteboard(proxy="http://127.0.0.1:8080")
    hyp = WhiteboardHypothesis(
        hypothesis_id="HYP-001",
        title="CL/TE Smuggling Candidate",
        domain="http_framing",
        file_path="src/proxy.py",
        line=14,
        cwe="CWE-444",
        severity="HIGH",
    )
    wb.post_hypothesis(hyp)

    with pytest.raises(ValueError, match="Duplicate hypothesis_id"):
        wb.add_hypothesis(hyp)

    wb.add_hypothesis(hyp, overwrite=True)

    with pytest.raises(ValueError, match="Invalid hypothesis status"):
        wb.update_status("HYP-001", "BOGUS_STATUS")

    with pytest.raises(KeyError, match="Unknown hypothesis_id"):
        wb.update_status("HYP-404", "VERIFIED")

    wb.transition("HYP-001", "DISPATCHED", worker_id="w1", round_idx=1)
    wb.update_status("HYP-001", "TESTING", worker_id="w1", round_idx=1)
    wb.update_status(
        "HYP-001",
        "COUNTEREXAMPLE_FOUND",
        worker_id="w1",
        round_idx=1,
        evidence={"theorem": "differential_witness_cl_te"},
        counterexamples=[{"domain": "http_framing", "violated": True}],
    )
    wb.record_round(1, dispatched=1, updated=1)

    snap = wb.snapshot()
    assert snap["proxy"] == "http://127.0.0.1:8080"
    assert snap["counts_by_status"]["COUNTEREXAMPLE_FOUND"] == 1
    assert len(snap["transitions"]) == 3
    assert len(snap["rounds"]) == 1
    assert snap["hypotheses"][0]["counterexamples"][0]["violated"] is True


def test_whiteboard_thread_safety_and_cairn_db_sync(tmp_path: Path) -> None:
    db = Database(db_path=str(tmp_path / "cairn_wb.db"))
    try:
        wb = EnsembleWhiteboard(task_id="task-m2-sync", db=db)

        def _worker(idx: int) -> None:
            hid = f"HYP-T-{idx:03d}"
            wb.add_hypothesis(
                WhiteboardHypothesis(
                    hypothesis_id=hid,
                    title=f"Concurrent item {idx}",
                    domain="policy_guard",
                    file_path=f"src/file_{idx}.py",
                    line=idx + 1,
                )
            )
            wb.update_status(hid, "DISPATCHED", worker_id=f"w-{idx % 4}", round_idx=1)
            wb.update_status(
                hid,
                "COUNTEREXAMPLE_FOUND" if idx % 2 == 0 else "REFUTED",
                worker_id=f"w-{idx % 4}",
                round_idx=1,
                evidence={"idx": idx},
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(_worker, range(24)))

        snap = wb.to_dict()
        assert len(snap["hypotheses"]) == 24
        assert snap["db_synced"] is True
        assert snap["sync_errors"] == []

        intents = db.get_blackboard_nodes(node_type="INTENT", task_id="task-m2-sync", limit=100)
        facts = db.get_facts(task_id="task-m2-sync", limit=100)
        assert len(intents) == 24
        assert all(i["status"] == "DONE" for i in intents)
        assert len(facts) == 12
    finally:
        db.conn.close()


def test_orchestrator_lean4_counterexample_consensus_sarif_and_poc_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_docker_and_wsl(monkeypatch, include_semgrep=True, include_lean=False)

    repo = tmp_path / "http_repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "http_proxy.py").write_text("def parse(): pass\n", encoding="utf-8")

    findings = [
        EngineFinding(
            engine="smuggling",
            title="CL+TE Request Smuggling",
            file_path="src/http_proxy.py",
            line=10,
            cwe="CWE-444",
            severity="HIGH",
            metadata={"http_framing": {"content_lengths": [42], "has_transfer_encoding_chunked": True}},
        ),
        EngineFinding(
            engine="mantis",
            title="CL+TE Request Smuggling",
            file_path="src/http_proxy.py",
            line=11,
            cwe="CWE-444",
            severity="HIGH",
            confirmed=False,  # LLM dissent must not veto deterministic Lean 4 witness
        ),
    ]

    orch = EnsembleOrchestrator(
        program="generic",
        quorum=2,
        max_whiteboard_rounds=2,
        proxy="http://127.0.0.1:8888",
    )
    out_dir = tmp_path / "out_static"
    rep_static = orch.run(
        repo,
        findings=findings,
        poc_language="python",
        poc_command=["python3", "-c", "print('ok')"],
        all_scan_summary={"engines": ["smuggling"]},
        out_dir=out_dir,
        refresh_stix=False,
    )

    assert len(rep_static.clusters) == 1
    c = rep_static.clusters[0]
    assert c.lean_verified is True
    assert c.deterministic_override_protected is True
    assert c.llm_dissent_ignored is True
    assert c.poc_verified is False
    assert c.disposition == "ENSEMBLE_CORROBORATED_STATIC"
    assert len(c.counterexamples) >= 1

    d = rep_static.to_dict()
    assert d["proxy"] == "http://127.0.0.1:8888"
    assert d["all_scan_summary"] == {"engines": ["smuggling"]}
    assert any(h["status"] == "COUNTEREXAMPLE_FOUND" for h in d["whiteboard"]["hypotheses"])
    assert any(h["status"] == "UNVERIFIED_UNAVAILABLE" for h in d["whiteboard"]["hypotheses"] if h["domain"] == "runtime_poc")
    assert d["lean_verification"]["status"] == "counterexample_found"

    sarif = json.loads((out_dir / "ensemble_findings.sarif").read_text(encoding="utf-8"))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["lean_verified"] is True
    assert props["counterexamples_count"] >= 1
    md = render_ensemble_markdown(rep_static)
    assert "## Whiteboard Summary" in md
    assert "## Lean 4 Formal Verification" in md
    assert "## Toolchain Availability" in md

    # Verified transcript promotes to SUBMISSION_READY
    tr = VerifiableTranscript(
        language="python",
        backend="docker",
        status="passed",
        exit_code=0,
        command=["python3", "poc.py"],
        image="python:3.12-slim",
        repo_path=str(repo),
        started_at_utc="2026-11-26T00:00:00Z",
        elapsed_ms=42.0,
        stdout="CONFIRMED",
    )
    rep_ready = orch.run(repo, findings=findings, poc_transcripts={"src/http_proxy.py": tr}, refresh_stix=False)
    assert rep_ready.clusters[0].disposition == "SUBMISSION_READY"
    assert rep_ready.clusters[0].poc_verified is True


def test_lean4_failed_proof_branch_surfaces_in_consensus_and_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_docker_and_wsl(monkeypatch, include_semgrep=True, include_lean=False)

    lean_copy = tmp_path / "lean_ws"
    shutil.copytree(REPO_ROOT / "formal" / "lean4", lean_copy, ignore=shutil.ignore_patterns(".lake"))
    pg = lean_copy / "RFCHunt" / "PolicyGuard.lean"
    pg.write_text(pg.read_text(encoding="utf-8") + "\ntheorem broken_branch : True := by\n  sorry\n", encoding="utf-8")

    target_repo = tmp_path / "clean_target"
    target_repo.mkdir()
    (target_repo / "app.py").write_text("def ok(): return True\n", encoding="utf-8")

    orch = EnsembleOrchestrator(program="generic", quorum=1, lean_dir=lean_copy)
    rep = orch.run(target_repo, refresh_stix=False)

    ws = rep.lean_verification["workspace_report"]
    assert ws["status"] == "proof_integrity_violation"
    assert any(d["kind"] == "sorry" and d["theorem"] == "broken_branch" for d in rep.lean_verification["diagnostics"])
    assert any(c.lean_verified and c.lean_diagnostics for c in rep.clusters)


def test_non_fabrication_degraded_toolchain_and_unsafe_poc_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_docker_and_wsl(monkeypatch, include_semgrep=True, include_lean=True)

    clean_repo = tmp_path / "clean_repo"
    clean_repo.mkdir()
    (clean_repo / "README.md").write_text("# Clean hardened service\n", encoding="utf-8")
    (clean_repo / "safe.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    orch = EnsembleOrchestrator(program="generic", quorum=1, max_whiteboard_rounds=2)
    rep = orch.run(
        clean_repo,
        poc_lang="python",
        poc_cmd=["python3", "-c", "id; rm -rf /"],
        refresh_stix=False,
    )

    assert rep.clusters == []
    d = rep.to_dict()
    assert d["toolchain_status"]["docker"]["available"] is False
    assert d["toolchain_status"]["lean4"]["available"] is False
    assert d["toolchain_status"]["angr"]["available"] is False
    assert d["toolchain_status"]["klee"]["available"] is False
    for h in d["whiteboard"]["hypotheses"]:
        assert h["status"] not in ("VERIFIED", "COUNTEREXAMPLE_FOUND")
        if h["domain"] == "runtime_poc":
            assert h["status"] == "UNVERIFIED_UNAVAILABLE"
            assert h["evidence"]["status"] == "rejected_unsafe"


def test_embedded_mode_zero_subprocess_and_disabled_whiteboard_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm test\n",
        encoding="utf-8",
    )

    spawned: list[Any] = []

    def _fail_popen(args: Any, *a: Any, **kw: Any) -> Any:
        spawned.append(args)
        raise AssertionError(f"Subprocess spawned in embedded=True mode: {args!r}")

    monkeypatch.setattr(subprocess, "Popen", _fail_popen)
    orch = EnsembleOrchestrator(program="generic", quorum=1, embedded=True, enable_whiteboard=False, max_whiteboard_rounds=0)
    rep = orch.run(
        tmp_path,
        poc_language="python",
        poc_command=["python3", "-V"],
        refresh_stix=False,
    )

    assert spawned == []
    d = rep.to_dict()
    assert d["toolchain_status"]["docker"]["status"] == "skipped_embedded"
    assert d["toolchain_status"]["lean4"]["status"] == "skipped_embedded"
    assert d["lean_verification"]["machine_checked"] is False
    assert "whiteboard" in d and d["whiteboard"]["enabled"] is False
    assert len(rep.clusters) >= 1


def test_semgrep_offline_guard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

    # 1. When semgrep is absent -> semgrep_not_installed even if RFCHUNT_OFFLINE=1
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setattr(shutil, "which", lambda n: None if n == "semgrep" else None)
    _, tele_missing = EnsembleOrchestrator.run_exhaustive_local_engines(repo, refresh_stix=False)
    assert tele_missing["raptor_semgrep"]["status"] == "semgrep_not_installed"

    # 2. When semgrep is present and RFCHUNT_OFFLINE=1 -> skipped_offline (no network hang)
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/semgrep" if n == "semgrep" else None)
    _, tele_offline = EnsembleOrchestrator.run_exhaustive_local_engines(repo, refresh_stix=False)
    assert tele_offline["raptor_semgrep"]["status"] == "skipped_offline"


def test_empty_cwe_single_cluster_merge_across_lean_domains(tmp_path: Path) -> None:
    repo = tmp_path / "empty_cwe_repo"
    repo.mkdir()
    orch = EnsembleOrchestrator(program="generic", quorum=1, embedded=True)

    # 1. http_framing with cwe=""
    rep_http = orch.run(
        repo,
        findings=[
            EngineFinding(
                engine="smuggling",
                title="CL+TE Request Smuggling",
                file_path="src/http.py",
                line=10,
                cwe="",
                severity="HIGH",
                metadata={"http_framing": {"content_lengths": [42], "has_transfer_encoding_chunked": True}},
            )
        ],
        refresh_stix=False,
    )
    assert len(rep_http.clusters) == 1
    c_http = rep_http.clusters[0]
    assert c_http.engine_count == 2
    assert c_http.lean_verified is True
    assert c_http.cwe_family == "CWE-444"
    assert sorted(c_http.engines) == ["lean4", "smuggling"]

    # 2. policy_guard with cwe=""
    rep_pg = orch.run(
        repo,
        findings=[
            EngineFinding(
                engine="aiscan",
                title="Unauthorized shell execution",
                file_path="src/policy.py",
                line=20,
                cwe="",
                severity="HIGH",
                metadata={"policy_guard": {"action": "shellExec", "scope": "inScopeAuthorized", "observed_allowed": True}},
            )
        ],
        refresh_stix=False,
    )
    assert len(rep_pg.clusters) == 1
    c_pg = rep_pg.clusters[0]
    assert c_pg.engine_count == 2
    assert c_pg.lean_verified is True
    assert c_pg.cwe_family == "CWE-862"
    assert sorted(c_pg.engines) == ["aiscan", "lean4"]

    # 3. dotnet_pe with cwe=""
    rep_pe = orch.run(
        repo,
        findings=[
            EngineFinding(
                engine="pe_magika",
                title="CLR image bit bypassed",
                file_path="bin/app.dll",
                line=1,
                cwe="",
                severity="HIGH",
                metadata={"has_forshaw_cve_2026_108398_anomaly": True},
            )
        ],
        refresh_stix=False,
    )
    assert len(rep_pe.clusters) == 1
    c_pe = rep_pe.clusters[0]
    assert c_pe.engine_count == 2
    assert c_pe.lean_verified is True
    assert c_pe.cwe_family == "CWE-347"
    assert sorted(c_pe.engines) == ["lean4", "pe_magika"]

    # 4. gha_class propagation with cwe="" triggering policy_guard
    rep_gha = orch.run(
        repo,
        findings=[
            EngineFinding(
                engine="gha_agent",
                title="Policy guard shellExec in workflow",
                file_path=".github/workflows/ci.yml",
                line=12,
                cwe="",
                severity="HIGH",
                metadata={
                    "gha_class": "pwn_request",
                    "policy_guard": {"action": "shellExec", "scope": "inScopeAuthorized", "observed_allowed": True},
                },
            )
        ],
        refresh_stix=False,
    )
    assert len(rep_gha.clusters) == 1
    assert rep_gha.clusters[0].engine_count == 2
    assert rep_gha.clusters[0].lean_verified is True
    assert rep_gha.clusters[0].gha_class == "pwn_request"


def test_dual_workspace_sorry_diagnostics_within_15_lines_deduplicated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_docker_and_wsl(monkeypatch, include_semgrep=True, include_lean=False)

    lean_copy = tmp_path / "lean_ws"
    shutil.copytree(REPO_ROOT / "formal" / "lean4", lean_copy, ignore=shutil.ignore_patterns(".lake"))
    pg = lean_copy / "RFCHunt" / "PolicyGuard.lean"
    pg.write_text(
        pg.read_text(encoding="utf-8")
        + "\ntheorem broken_a : True := by\n  sorry\n\ntheorem broken_b : True := by\n  sorry\n",
        encoding="utf-8",
    )

    target_repo = tmp_path / "clean_target"
    target_repo.mkdir()
    (target_repo / "app.py").write_text("def ok(): return True\n", encoding="utf-8")

    orch = EnsembleOrchestrator(program="generic", quorum=1, lean_dir=lean_copy)
    rep = orch.run(target_repo, refresh_stix=False)

    diag_clusters = [c for c in rep.clusters if c.lean_diagnostics]
    assert len(diag_clusters) == 1
    c = diag_clusters[0]
    assert len(c.lean_diagnostics) == 2
    assert [d["theorem"] for d in c.lean_diagnostics] == ["broken_a", "broken_b"]
    sarif_res = c.to_sarif_result()
    assert sarif_res["properties"]["lean_diagnostics_count"] == 2


def test_whiteboard_raising_property_db_caught_in_sync_errors() -> None:
    class RaisingPropertyDB:
        @property
        def queue_intent(self) -> Any:
            raise RuntimeError("property queue_intent boom")

        @property
        def complete_intent(self) -> Any:
            raise RuntimeError("property complete_intent boom")

        @property
        def add_fact(self) -> Any:
            raise OSError("property add_fact boom")

    wb = EnsembleWhiteboard(task_id="task-prop-boom", db=RaisingPropertyDB())
    wb.add_hypothesis(
        WhiteboardHypothesis(
            hypothesis_id="H-PROP-1",
            title="Broken DB property check",
            domain="policy_guard",
        )
    )
    wb.update_status("H-PROP-1", "COUNTEREXAMPLE_FOUND", worker_id="w1", round_idx=1)
    wb.add_fact("policy_check", "extra fact")

    snap = wb.to_dict()
    assert snap["db_synced"] is False
    assert len(snap["sync_errors"]) == 4
    assert any("queue_intent(H-PROP-1): property queue_intent boom" in e for e in snap["sync_errors"])
    assert any("complete_intent(H-PROP-1): property complete_intent boom" in e for e in snap["sync_errors"])
    assert any("add_fact(H-PROP-1): property add_fact boom" in e for e in snap["sync_errors"])
    assert any("add_fact(policy_check): property add_fact boom" in e for e in snap["sync_errors"])


def test_string_poc_command_normalization_and_unsafe_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    repo = tmp_path / "poc_str_repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

    orch = EnsembleOrchestrator(program="generic", quorum=1, embedded=True)
    rep_ok = orch.run(
        repo,
        findings=[],
        poc_language="python",
        poc_command="python3 -V",
        refresh_stix=False,
    )
    poc_hyps = [h for h in rep_ok.whiteboard["hypotheses"] if h["domain"] == "runtime_poc"]
    assert len(poc_hyps) == 1
    assert poc_hyps[0]["metadata"]["poc_command"] == ["python3", "-V"]
    assert poc_hyps[0]["evidence"]["command"] == ["python3", "-V"]
    assert poc_hyps[0]["evidence"]["status"] == "skipped_embedded"

    for bad_cmd in ("python -c 'x'; rm -rf /", "python -c 'x; rm -rf /"):
        rep_bad = orch.run(
            repo,
            findings=[],
            poc_language="python",
            poc_command=bad_cmd,
            refresh_stix=False,
        )
        bad_hyps = [h for h in rep_bad.whiteboard["hypotheses"] if h["domain"] == "runtime_poc"]
        assert len(bad_hyps) == 1
        assert bad_hyps[0]["status"] == "UNVERIFIED_UNAVAILABLE"
        assert bad_hyps[0]["evidence"]["status"] == "rejected_unsafe"


def test_crashing_oracle_and_multi_cluster_wb_matching(tmp_path: Path) -> None:
    class CrashingOracle:
        def strict_rfc9112(self, *_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("rfchunt-lean-oracle crashed (rc=139)")

    orch = EnsembleOrchestrator(program="generic", quorum=1, embedded=False)
    wb = EnsembleWhiteboard()
    hyp = WhiteboardHypothesis(
        hypothesis_id="HYP-CRASH",
        title="CL+TE Request Smuggling",
        domain="http_framing",
        file_path="src/http.py",
        line=10,
        cwe="CWE-444",
        metadata={"http_framing": {"content_lengths": [42], "has_transfer_encoding_chunked": True}},
    )
    wb.add_hypothesis(hyp)
    res = orch._run_whiteboard_worker(
        hyp,
        finding=None,
        target_p=tmp_path,
        target_str=str(tmp_path),
        eff_poc_lang=None,
        eff_poc_cmd=None,
        oracle=CrashingOracle(),
        whiteboard=wb,
        round_idx=1,
        worker_idx=1,
    )
    assert res["witness_evaluated"] is False
    assert "rfchunt-lean-oracle crashed" in str(res["invalid_error"])

    # Multiple clusters in the same file should match only their own whiteboard hypothesis IDs
    repo = tmp_path / "multi_cluster_repo"
    repo.mkdir()
    orch_emb = EnsembleOrchestrator(program="generic", quorum=1, embedded=True)
    rep_multi = orch_emb.run(
        repo,
        findings=[
            EngineFinding(
                engine="smuggling",
                title="CL+TE Request Smuggling",
                file_path="src/shared.py",
                line=10,
                cwe="",
                severity="HIGH",
                metadata={"http_framing": {"content_lengths": [42], "has_transfer_encoding_chunked": True}},
            ),
            EngineFinding(
                engine="aiscan",
                title="Policy guard violation",
                file_path="src/shared.py",
                line=12,
                cwe="CWE-862",
                severity="HIGH",
                metadata={"policy_guard": {"action": "shellExec", "scope": "inScopeAuthorized", "observed_allowed": True}},
            ),
            EngineFinding(
                engine="raptor",
                title="SQL Injection",
                file_path="src/shared.py",
                line=90,
                cwe="CWE-89",
                severity="HIGH",
            ),
        ],
        refresh_stix=False,
    )
    assert len(rep_multi.clusters) == 3
    by_fam = {c.cwe_family: c for c in rep_multi.clusters}
    assert by_fam["CWE-444"].whiteboard_hypothesis_ids == ["HYP-001"]
    assert by_fam["CWE-862"].whiteboard_hypothesis_ids == ["HYP-002"]
    assert by_fam["CWE-89"].whiteboard_hypothesis_ids == ["HYP-003"]


def test_crashing_oracle_full_orchestrator_run_degrades_gracefully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.lean_formal_verifier as lfv

    _disable_docker_and_wsl(monkeypatch, include_semgrep=True, include_lean=True)

    finding = EngineFinding(
        engine="smuggling",
        title="CL+TE Request Smuggling",
        file_path="src/http.py",
        line=10,
        cwe="CWE-444",
        severity="HIGH",
        metadata={"http_framing": {"content_lengths": [42], "has_transfer_encoding_chunked": True}},
    )

    # 1. Compiled rfchunt-lean-oracle binary crashes with RuntimeError during full run()
    lean_ws = tmp_path / "lean_ws"
    shutil.copytree(REPO_ROOT / "formal" / "lean4", lean_ws, ignore=shutil.ignore_patterns(".lake"))
    bin_dir = lean_ws / ".lake" / "build" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    oracle_exe = bin_dir / ("rfchunt-lean-oracle.exe" if os.name == "nt" else "rfchunt-lean-oracle")
    oracle_exe.write_bytes(b"stub-oracle")

    repo1 = tmp_path / "repo_oracle_crash"
    repo1.mkdir()
    (repo1 / "http.py").write_text("def parse(): pass\n", encoding="utf-8")

    def _crash_run(self_oracle: Any, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("rfchunt-lean-oracle crashed (rc=139)")

    with monkeypatch.context() as mp:
        mp.setattr(lfv.LeanCompiledOracle, "_run", _crash_run)
        orch1 = EnsembleOrchestrator(program="generic", quorum=1, embedded=False, lean_dir=lean_ws)
        rep1 = orch1.run(repo1, findings=[finding], refresh_stix=False)

    hyp1 = next(h for h in rep1.whiteboard["hypotheses"] if h["hypothesis_id"] == "HYP-001")
    assert hyp1["status"] == "UNVERIFIED_UNAVAILABLE"
    assert rep1.lean_verification["machine_checked"] is False
    assert "rfchunt-lean-oracle crashed (rc=139)" in (rep1.lean_verification.get("degradation_reason") or "")
    assert any(fact.get("fact_type") == "lean_oracle_error" for fact in rep1.whiteboard.get("facts", []))

    # 2. verify_http_framing_invariant itself raises subprocess.SubprocessError during full run()
    repo2 = tmp_path / "repo_verify_crash"
    repo2.mkdir()
    (repo2 / "http.py").write_text("def parse(): pass\n", encoding="utf-8")

    def _crash_verify(*_args: Any, **_kwargs: Any) -> Any:
        raise subprocess.SubprocessError("oracle binary segfault")

    with monkeypatch.context() as mp:
        mp.setattr(lfv, "verify_http_framing_invariant", _crash_verify)
        orch2 = EnsembleOrchestrator(program="generic", quorum=1, embedded=False)
        rep2 = orch2.run(repo2, findings=[finding], refresh_stix=False)

    hyp2 = next(h for h in rep2.whiteboard["hypotheses"] if h["hypothesis_id"] == "HYP-001")
    assert hyp2["status"] == "UNVERIFIED_UNAVAILABLE"
    assert rep2.lean_verification["machine_checked"] is False
    assert "oracle binary segfault" in (rep2.lean_verification.get("degradation_reason") or "")
    assert any(fact.get("fact_type") == "lean_oracle_error" for fact in rep2.whiteboard.get("facts", []))


def test_embedded_true_zero_subprocess_even_when_compiled_oracle_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression test for f02: embedded=True must never spawn LeanCompiledOracle subprocesses."""
    _disable_docker_and_wsl(monkeypatch, include_semgrep=True, include_lean=True)

    lean_ws = tmp_path / "lean_ws"
    shutil.copytree(REPO_ROOT / "formal" / "lean4", lean_ws, ignore=shutil.ignore_patterns(".lake"))
    bin_dir = lean_ws / ".lake" / "build" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for bin_name in ("rfchunt-lean-oracle.exe", "rfchunt-lean-oracle"):
        (bin_dir / bin_name).write_bytes(b"MZ-stub-oracle")

    repo = tmp_path / "repo_embedded"
    repo.mkdir()
    (repo / "proxy.py").write_text("def handle(): pass\n", encoding="utf-8")

    popen_calls = 0

    def _blocked_popen(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal popen_calls
        popen_calls += 1
        raise OSError("subprocess.Popen is forbidden in embedded=True mode")

    domain_findings = [
        EngineFinding(
            engine="smuggling",
            title="CL+TE Request Smuggling",
            file_path="proxy.py",
            line=10,
            cwe="CWE-444",
            severity="HIGH",
            metadata={"http_framing": {"content_lengths": [42], "has_transfer_encoding_chunked": True}},
        ),
        EngineFinding(
            engine="aiscan",
            title="Policy guard shellExec breach",
            file_path="proxy.py",
            line=20,
            cwe="CWE-862",
            severity="HIGH",
            metadata={"policy_guard": {"action": "shellExec", "scope": "inScopeAuthorized", "observed_allowed": True}},
        ),
        EngineFinding(
            engine="pe_magika",
            title="DotNet PE CVE-2026-108398 anomaly",
            file_path="bin/app.dll",
            line=1,
            cwe="CWE-347",
            rule_id="PE-DOTNET-001",
            severity="HIGH",
            metadata={"has_forshaw_cve_2026_108398_anomaly": True},
        ),
    ]

    with monkeypatch.context() as mp:
        mp.setattr(subprocess, "Popen", _blocked_popen)
        # 1. Empty findings path (_evaluate_lean_domains_embedded)
        rep_empty = EnsembleOrchestrator(
            program="generic",
            quorum=1,
            embedded=True,
            lean_dir=lean_ws,
        ).run(repo, findings=[], refresh_stix=False)
        # 2. Non-empty domain findings path (_run_whiteboard_worker + _evaluate_lean_domains_embedded)
        rep_findings = EnsembleOrchestrator(
            program="generic",
            quorum=1,
            embedded=True,
            lean_dir=lean_ws,
        ).run(repo, findings=domain_findings, refresh_stix=False)

    assert popen_calls == 0
    for rep in (rep_empty, rep_findings):
        lv = rep.lean_verification
        assert lv["oracle_backend"] == "python_mirror"
        assert lv["machine_checked"] is False
        assert lv["checks_total"] >= 3
        assert lv["workspace_report"]["total_theorems"] > 0
        assert lv["workspace_report"]["status"] == "skipped_embedded"
    assert rep_findings.lean_verification["violations_count"] >= 3


def test_crashing_compiled_oracle_degrades_to_python_mirror_and_combines_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Regression test for p01 + ValueError guard + combined degradation_reason:
    when LeanCompiledOracle._run crashes or emits malformed output, embedded=False
    must fall back to `python_mirror` (not `unavailable`), and dual failure must
    preserve both primary and secondary errors in `degradation_reason`.
    """
    import engine.lean_formal_verifier as lfv

    _disable_docker_and_wsl(monkeypatch, include_semgrep=True, include_lean=True)

    lean_ws = tmp_path / "lean_ws_p01"
    shutil.copytree(REPO_ROOT / "formal" / "lean4", lean_ws, ignore=shutil.ignore_patterns(".lake"))
    bin_dir = lean_ws / ".lake" / "build" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for bin_name in ("rfchunt-lean-oracle.exe", "rfchunt-lean-oracle"):
        (bin_dir / bin_name).write_bytes(b"MZ-stub-oracle")

    repo = tmp_path / "repo_p01"
    repo.mkdir()
    (repo / "http.py").write_text("def parse(): pass\n", encoding="utf-8")

    finding = EngineFinding(
        engine="smuggling",
        title="CL+TE Request Smuggling",
        file_path="http.py",
        line=10,
        cwe="CWE-444",
        severity="HIGH",
        metadata={"http_framing": {"content_lengths": [42], "has_transfer_encoding_chunked": True}},
    )

    # 1. LeanCompiledOracle._run raises RuntimeError -> degrades to python_mirror (p01)
    with monkeypatch.context() as mp:
        mp.setattr(
            lfv.LeanCompiledOracle,
            "_run",
            lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("rfchunt-lean-oracle crashed (rc=139)")),
        )
        rep_rt = EnsembleOrchestrator(
            program="generic",
            quorum=1,
            embedded=False,
            lean_dir=lean_ws,
        ).run(repo, findings=[finding], refresh_stix=False)

    assert rep_rt.lean_verification["oracle_backend"] == "python_mirror"
    assert rep_rt.lean_verification["machine_checked"] is False
    assert rep_rt.lean_verification["checks_total"] >= 3
    assert "rfchunt-lean-oracle crashed (rc=139)" in (rep_rt.lean_verification.get("degradation_reason") or "")
    assert any(fact.get("fact_type") == "lean_oracle_error" for fact in rep_rt.whiteboard.get("facts", []))

    # 2. Malformed compiled-oracle stdout raising ValueError -> degrades to python_mirror
    with monkeypatch.context() as mp:
        mp.setattr(
            lfv.LeanCompiledOracle,
            "_run",
            lambda *_a, **_kw: "corrupted_non_integer_stdout",
        )
        rep_val = EnsembleOrchestrator(
            program="generic",
            quorum=1,
            embedded=False,
            lean_dir=lean_ws,
        ).run(repo, findings=[finding], refresh_stix=False)

    assert rep_val.lean_verification["oracle_backend"] == "python_mirror"
    assert rep_val.lean_verification["machine_checked"] is False
    assert rep_val.lean_verification["checks_total"] >= 3
    assert "Compiled Lean 4 oracle failed" in (rep_val.lean_verification.get("degradation_reason") or "")

    # 3. Both primary evaluate_lean_domains and secondary fallback raise -> both errors preserved
    import engine.ensemble_orchestrator as eo

    def _primary_boom(*_a: Any, **_kw: Any) -> Any:
        raise ValueError("malformed oracle stdout")

    def _secondary_boom(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("secondary mirror boom")

    with monkeypatch.context() as mp:
        mp.setattr(lfv, "evaluate_lean_domains", _primary_boom)
        mp.setattr(eo, "_evaluate_lean_domains_embedded", _secondary_boom)
        rep_dual = EnsembleOrchestrator(
            program="generic",
            quorum=1,
            embedded=False,
            lean_dir=lean_ws,
        ).run(repo, findings=[finding], refresh_stix=False)

    lv_dual = rep_dual.lean_verification
    assert lv_dual["oracle_backend"] == "unavailable"
    assert lv_dual["machine_checked"] is False
    assert lv_dual["checks_total"] == 0
    reason = lv_dual.get("degradation_reason") or ""
    assert "malformed oracle stdout" in reason
    assert "secondary mirror boom" in reason
    assert lv_dual["workspace_report"]["stderr"] == "secondary mirror boom"

