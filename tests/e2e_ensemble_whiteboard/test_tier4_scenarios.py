"""
Tier 4 Realistic End-to-End Defensive Audit Scenarios (>=6 scenarios).

Exercises full multi-stage pipelines across real synthetic git repositories,
CLI/MCP entry points, Lean 4 formal domain oracles, PoC transcripts, and
offline/degraded toolchain conditions without mocking the core SUT.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

from tests.e2e_ensemble_whiteboard.conftest import (
    REPO_ROOT,
    extract_field,
    import_contract,
    make_verified_transcript,
    run_cli_subprocess,
)

pytestmark = pytest.mark.tier4


def test_t4_scenario1_http_framing_repo_orchestrator_and_lean4(
    http_framing_repo: Path,
    isolated_out_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario 1 (F1, F2, F6, F7): HTTP parser repo with CL/TE framing ambiguity via EnsembleOrchestrator + Lean 4."""
    from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

    evaluate_lean_domains = import_contract("engine.lean_formal_verifier", "evaluate_lean_domains")
    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda n: None if n == "semgrep" else orig_which(n))

    probe_payload = json.loads((http_framing_repo / "fixtures" / "cl_te_probe.json").read_text(encoding="utf-8"))
    seed_findings = [
        EngineFinding(
            engine="smuggling",
            title="Stale parser header check",
            file_path="src/old_parser.py",
            line=1,
            cwe="CWE-444",
            severity="HIGH",
        ),
        EngineFinding(
            engine="raptor",
            title="Stale parser header check",
            file_path="src/old_parser.py",
            line=2,
            cwe="CWE-444",
            severity="HIGH",
        ),
        EngineFinding(
            engine="smuggling",
            title="CL+TE HTTP/1.1 framing desync in proxy",
            file_path="src/http_proxy.py",
            line=4,
            cwe="CWE-444",
            severity="HIGH",
            summary="Permissive CL-first proxy diverges from strict RFC 9112 on CL+TE",
            metadata={"http_framing": probe_payload},
        ),
    ]

    dom = evaluate_lean_domains(
        findings=seed_findings,
        repo_path=http_framing_repo,
        lean_dir=REPO_ROOT / "formal" / "lean4",
    )
    assert dom.status == "counterexample_found"
    assert any(c.domain == "http_framing" and c.violated for c in dom.counterexamples)

    orch = EnsembleOrchestrator(program="generic", quorum=2, max_whiteboard_rounds=2)
    report = orch.run(
        http_framing_repo,
        findings=seed_findings,
        out_dir=isolated_out_dir,
        refresh_stix=False,
    )
    rep_d = report.to_dict()

    # Stage 0 freshness ranks fresh <72h src/http_proxy.py ahead of stale src/old_parser.py
    assert report.freshness.freshness_status == "FRESH_UNDER_72H"
    assert report.clusters[0].file_path == "src/http_proxy.py"
    assert report.clusters[0].changed_in_fresh_diff is True
    assert report.counts_by_disposition.get("SUBMISSION_READY", 0) == 0

    # Whiteboard & Lean verification surfaced in exported artifacts
    assert "whiteboard" in rep_d
    assert "lean_verification" in rep_d
    wb_hyps = extract_field(rep_d["whiteboard"], "hypotheses", "items")
    if isinstance(wb_hyps, dict):
        wb_hyps = list(wb_hyps.values())
    assert any(extract_field(h, "status") == "COUNTEREXAMPLE_FOUND" for h in wb_hyps)

    sarif = json.loads((isolated_out_dir / "ensemble_findings.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert (isolated_out_dir / "ensemble_summary.md").is_file()


def test_t4_scenario2_policy_config_repo_cli_ensemble_audit_all(
    policy_guard_repo: Path,
    isolated_out_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario 2 (F1, F2, F4, F7): Policy config repo via CLI `ensemble-audit --all --ensemble`."""
    import revenue_cli

    verify_pg = import_contract("engine.lean_formal_verifier", "verify_policy_guard_invariant")
    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda n: None if n == "semgrep" else orig_which(n))

    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(policy_guard_repo),
            "--all",
            "--ensemble",
            "--program",
            "anthropic",
            "--quorum",
            "1",
            "--out",
            str(isolated_out_dir),
        ]
    )
    assert rc == 0

    rep = json.loads((isolated_out_dir / "ensemble_report.json").read_text(encoding="utf-8"))
    sarif = json.loads((isolated_out_dir / "ensemble_findings.sarif").read_text(encoding="utf-8"))
    assert "whiteboard" in rep
    assert "toolchain_status" in rep
    assert sarif["version"] == "2.1.0"

    # Real WebLLM + GHA findings detected, with Anthropic intra-runner /tmp hygiene held
    titles_and_rules = json.dumps(rep["clusters"])
    assert "GHA-TRIGGER-INJECT-001" in titles_and_rules or "Workflow Expression" in titles_and_rules
    assert any(
        c["disposition"] == "HELD_OUT_OF_THREAT_MODEL"
        for c in rep["clusters"]
    )

    # Lean PolicyGuard invariant refuses shellExec & outOfScope
    assert verify_pg(action="shellExec", rules=[("permit", True)])[0].observed_verdict == "allowed=False"
    assert verify_pg(action="networkProbe", scope="outOfScope", rules=[("permit", True)])[0].observed_verdict == "allowed=False"


def test_t4_scenario3_dotnet_pe_audit_via_mcp_bb_run_all_scan(
    dotnet_pe_repo: Path,
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    """Scenario 3 (F2, F5, F6): .NET PE assembly integrity audit via MCP `bb_run_all_scan(ensemble=True)`."""
    from bugbounty_mcp_server import BugBountyMCPServer

    evaluate_lean_domains = import_contract("engine.lean_formal_verifier", "evaluate_lean_domains")

    srv = BugBountyMCPServer()
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 403,
            "method": "tools/call",
            "params": {
                "name": "bb_run_all_scan",
                "arguments": {
                    "target": str(dotnet_pe_repo),
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
    assert payload["exit_code"] == 0
    assert payload["lean_verification"]["total_theorems"] == 11
    assert "ensemble" in payload
    assert "whiteboard" in payload["ensemble"]
    assert "clusters" in payload["ensemble"]
    assert "toolchain_status" in payload["ensemble"]

    dom = evaluate_lean_domains(repo_path=dotnet_pe_repo, lean_dir=REPO_ROOT / "formal" / "lean4")
    assert dom.domain_checks["dotnet_pe"]["violations"] >= 1
    assert any(
        c.domain == "dotnet_pe" and c.theorem == "anomaly_triggers_unpatched_fallback" and c.violated
        for c in dom.counterexamples
    )


def test_t4_scenario4_clean_hardened_repo_zero_fabricated_findings(
    clean_hardened_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    """Scenario 4 (F1, F3, F4, F6): Clean hardened repo yields zero fabricated findings under degraded host."""
    import revenue_cli
    from engine.ensemble_orchestrator import EnsembleOrchestrator

    degraded_toolchain_env()
    orch = EnsembleOrchestrator(program="generic", quorum=1, max_whiteboard_rounds=2)
    rep = orch.run(
        clean_hardened_repo,
        poc_lang="python",
        poc_cmd=["python3", "-c", "print('ok')"],
        out_dir=isolated_out_dir / "orch",
        refresh_stix=False,
    )
    assert rep.clusters == []
    assert rep.counts_by_disposition.get("SUBMISSION_READY", 0) == 0
    assert rep.to_dict()["toolchain_status"]["docker"]["available"] is False

    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(clean_hardened_repo),
            "--all",
            "--ensemble",
            "--out",
            str(isolated_out_dir / "cli"),
        ]
    )
    assert rc == 0
    cli_rep = json.loads((isolated_out_dir / "cli" / "ensemble_report.json").read_text(encoding="utf-8"))
    assert cli_rep["clusters"] == []
    assert cli_rep["counts_by_disposition"].get("SUBMISSION_READY", 0) == 0


def test_t4_scenario5_multi_module_swarm_all_essemble_offline_degraded(
    multi_module_repo: Path,
    isolated_out_dir: Path,
    isolated_db_path: Path,
) -> None:
    """Scenario 5 (F1, F3, F4, F6, F7): Multi-module repo via `rfc_hunt_swarm.py --all --essemble` offline."""
    proc = run_cli_subprocess(
        "rfc_hunt_swarm.py",
        [
            "--all",
            "--repo",
            str(multi_module_repo),
            "--essemble",
            "--program",
            "generic",
            "--freshness-hours",
            "72",
            "--quorum",
            "2",
            "--output-dir",
            str(isolated_out_dir),
            "--db",
            str(isolated_db_path),
            "--no-external-scanners",
            "--no-preflight-live",
            "--no-include-models",
            "--no-auto-install",
            "--json",
        ],
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    data = json.loads(proc.stdout)
    assert isinstance(data, dict)
    assert "ensemble" in data
    assert "whiteboard" in data["ensemble"]
    assert "toolchain_status" in data["ensemble"]

    # Target repo working tree must remain completely untouched
    git_status = subprocess.run(
        ["git", "-C", str(multi_module_repo), "status", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    assert git_status.stdout.strip() == ""


def test_t4_scenario6_mixed_domain_poc_symbolic_probe_and_consensus_voter(
    multi_module_repo: Path,
    isolated_out_dir: Path,
    degraded_toolchain_env: Any,
) -> None:
    """Scenario 6 (F1, F2, F3, F6, F7): Mixed-domain audit with symbolic hook probes + PoC + consensus voter."""
    from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

    probe_optional_backends = import_contract("engine.linux_poc_runner", "probe_optional_backends")
    run_symbolic_hook = import_contract("engine.linux_poc_runner", "run_symbolic_hook")
    evaluate_lean_domains = import_contract("engine.lean_formal_verifier", "evaluate_lean_domains")

    degraded_toolchain_env()
    probes = probe_optional_backends(lean_dir=REPO_ROOT / "formal" / "lean4")
    assert probes["angr"]["status"] == "unavailable"
    assert probes["klee"]["status"] == "unavailable"

    sym_angr = run_symbolic_hook("angr", multi_module_repo)
    sym_klee = run_symbolic_hook("klee", multi_module_repo)
    assert sym_angr["status"] == "unavailable" and sym_angr["verified"] is False
    assert sym_klee["status"] == "unavailable" and sym_klee["verified"] is False

    findings = [
        EngineFinding(
            engine="lean4",
            title="RFC 9112 CL+TE Framing Divergence",
            file_path="src/http_proxy.py",
            line=3,
            cwe="CWE-444",
            severity="CRITICAL",
            deterministic=True,
            confirmed=True,
            metadata={"http_framing": {"content_lengths": [42], "has_transfer_encoding_chunked": True}},
        ),
        EngineFinding(
            engine="mantis",
            title="RFC 9112 CL+TE Framing Divergence",
            file_path="src/http_proxy.py",
            line=4,
            cwe="CWE-444",
            severity="CRITICAL",
            deterministic=False,
            confirmed=False,  # LLM dissent
        ),
        EngineFinding(
            engine="web_llm",
            title="Excessive agency tool binding",
            file_path="src/agent_tool.py",
            line=6,
            cwe="CWE-862",
            severity="HIGH",
        ),
        EngineFinding(
            engine="gha_agent",
            title="Excessive agency tool binding",
            file_path="src/agent_tool.py",
            line=7,
            cwe="CWE-862",
            severity="HIGH",
        ),
    ]

    dom = evaluate_lean_domains(
        findings=findings,
        repo_path=multi_module_repo,
        lean_dir=REPO_ROOT / "formal" / "lean4",
    )
    assert dom.status == "counterexample_found"
    assert dom.machine_checked is False

    # Only `src/http_proxy.py` receives a verified non-destructive transcript
    verified_tr = make_verified_transcript(multi_module_repo, language="python", backend="docker")
    orch = EnsembleOrchestrator(program="generic", quorum=2, max_whiteboard_rounds=2)
    report = orch.run(
        multi_module_repo,
        findings=findings,
        poc_transcripts={"src/http_proxy.py": verified_tr},
        out_dir=isolated_out_dir,
        refresh_stix=False,
    )

    by_file = {c.file_path: c for c in report.clusters}
    http_cluster = by_file["src/http_proxy.py"]
    agent_cluster = by_file["src/agent_tool.py"]

    assert http_cluster.disposition == "SUBMISSION_READY"
    assert http_cluster.lean_verified is True
    assert http_cluster.deterministic_override_protected is True
    assert http_cluster.llm_dissent_ignored is True
    assert http_cluster.poc_verified is True

    assert agent_cluster.disposition == "ENSEMBLE_CORROBORATED_STATIC"
    assert agent_cluster.poc_verified is False
