"""
Comprehensive Tests for Native-First Multi-Tool Wrappers, Perplexity Bumblebee,
Universal `--folder` Support, Z3 SMT + Lean 4 Formal Verification, and Dynamic STRIDE.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from engine.aiscan_integrator import AiscanIntegrator
from engine.ensemble_orchestrator import (
    AiscanNativeAdapter,
    BumblebeeAdapter,
    CodeQLNativeAdapter,
    CodexSecurityAdapter,
    EnsembleConsensusEngine,
    EnsembleOrchestrator,
    InfisicalScanAdapter,
    ScannerRegistry,
    SemgrepNativeAdapter,
    TrivyAdapter,
    _normalize_semgrep_check_id,
    find_semgrep_executable,
)
from engine.formal_verifier import Lean4FormalVerifier, Z3FormalVerifier, run_formal_verification_suite
from engine.mantis_integrator import MantisThreatModeler
from engine.stride_engine import DynamicStrideThreatEngine
from engine.tool_provisioner import ToolProvisioner
from mcp_server import TerminatorMCPServer
from rfc_hunt_swarm import parse_swarm_arguments


def test_scanner_registry_includes_all_tools_no_tool_left_behind() -> None:
    reg = ScannerRegistry()
    ids = {s["tool_id"] for s in reg.list_scanners()}
    expected = {
        "aiscan", "trivy", "trufflehog", "infisical", "semgrep_oss", "bumblebee",
        "skillspector", "mantis", "raptor", "rea", "phi", "artex",
        "formal_z3", "formal_lean4", "stride_threat_model", "external_scanners",
        "cloudflare_audit", "compliance_mapper", "codeql",
        "local_diff_review", "codex_security", "pyrit_eval",
    }
    missing = expected - ids
    assert not missing, f"Tools missing from ScannerRegistry: {missing}"


def test_universal_folder_flag_propagates_across_all_cli_modes(tmp_path: Path) -> None:
    target = tmp_path / "my_local_app"
    target.mkdir()

    a1 = parse_swarm_arguments(["--folder", str(target)])
    assert a1.folder == str(target)
    assert a1.repo == str(target)
    assert a1.raptor_target == str(target)
    assert a1.aiscan_target == str(target)

    a2 = parse_swarm_arguments(["--ensemble", "--folder", str(target)])
    assert a2.enable_ensemble_flag is True
    assert a2.folder == str(target)

    a3 = parse_swarm_arguments(["--aiscan", "--folder", str(target)])
    assert a3.enable_aiscan is True
    assert a3.aiscan_target == str(target)

    a4 = parse_swarm_arguments(["--formal", "--folder", str(target)])
    assert a4.enable_formal_flag is True
    assert a4.folder == str(target)

    a5 = parse_swarm_arguments(["--stride", "--folder", str(target)])
    assert a5.enable_stride_flag is True
    assert a5.folder == str(target)


def test_aiscan_real_v01_audit_json_schema_parsing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "chat.py").write_text(
        '@app.post("/api/chat")\ndef chat(u):\n    return u\n',
        encoding="utf-8",
    )
    fake_payload = {
        "metadata": {"version": "1.0.0", "scan_duration_ms": 42, "tool_version": "0.1.0"},
        "inventory_summary": {"total_ai_calls": 1, "unique_wrappers": ["openai_config"], "files_with_ai": 1},
        "security_summary": {"total_findings": 2, "high": 2},
        "findings": [
            {
                "id": "LLM-001",
                "severity": "High",
                "file": str(tmp_path / "chat.py"),
                "line": 2,
                "issue_type": "LLM01PromptInjection",
                "description": "Potential prompt injection vulnerability",
                "fix": "Validate and sanitize all untrusted inputs",
            },
            {
                "id": "STATIC-001",
                "severity": "High",
                "file": str(tmp_path / "chat.py"),
                "line": 1,
                "issue_type": "ApiKeyExposure",
                "description": "Hardcoded OpenAI key",
                "fix": "Use environment variables",
            },
        ],
        "recommendations": ["Rotate API keys"],
    }

    captured_argv = []

    class FakeProc:
        returncode = 0
        stdout = json.dumps(fake_payload)
        stderr = ""

    def fake_run(argv, **kwargs):
        captured_argv.append(list(argv))
        return FakeProc()

    integrator = AiscanIntegrator(reports_dir=tmp_path / "rep", use_native_binary=True)
    monkeypatch.setattr(integrator, "binary_path", Path("bin/aiscan.exe"))
    monkeypatch.setattr(subprocess, "run", fake_run)

    res = integrator.scan_target(tmp_path)
    assert captured_argv and captured_argv[0][1:3] == ["audit", "--json"]
    assert res["engine"] == "haasonsaas/aiscan"
    assert res["native_inventory_summary"]["total_ai_calls"] == 1
    assert any(f["finding_type"] == "LLM01PromptInjection" for f in res["findings"])
    assert any(f["finding_type"] == "ApiKeyExposure" for f in res["findings"])
    assert len(res["endpoints"]) >= 1


def test_infisical_toml_allowlist_is_valid_utf8_no_bom_and_no_silent() -> None:
    toml_txt = InfisicalScanAdapter._build_allowlist_toml()
    assert not toml_txt.startswith("\ufeff")
    assert "'''" in toml_txt
    assert "useDefault = true" in toml_txt
    assert ".pytest_temp" in toml_txt


def test_semgrep_check_id_normalization_and_executable_lookup() -> None:
    assert _normalize_semgrep_check_id("C.Users.foo.Temp.rfchunt.py.subprocess-shell-true") == "rfchunt.py.subprocess-shell-true"
    assert _normalize_semgrep_check_id("custom.rule") == "custom.rule"
    sg_cmd = find_semgrep_executable()
    assert sg_cmd is None or isinstance(sg_cmd, list)


def test_bumblebee_readonly_inventory_matches_threat_intel_and_never_leaks_mcp_env(tmp_path: Path) -> None:
    repo = tmp_path / "proj"
    repo.mkdir()
    # Plant a lockfile matching a real threat_intel entry plus an MCP config with a secret in `env`
    (repo / "package-lock.json").write_text(
        json.dumps({
            "name": "demo",
            "packages": {
                "node_modules/evil-pkg": {"name": "evil-pkg", "version": "1.2.3"},
                "node_modules/safe-pkg": {"name": "safe-pkg", "version": "2.0.0"},
            },
        }),
        encoding="utf-8",
    )
    (repo / "mcp.json").write_text(
        json.dumps({
            "mcpServers": {
                "demo-mcp": {
                    "command": "python",
                    "env": {"SUPER_SECRET_TOKEN": "DO_NOT_EMIT_THIS_RAW_SECRET"},
                }
            }
        }),
        encoding="utf-8",
    )
    bb_root = tmp_path / "bb_repo"
    ti_dir = bb_root / "threat_intel"
    ti_dir.mkdir(parents=True)
    (ti_dir / "sample-campaign.json").write_text(
        json.dumps({
            "schema_version": "0.2.0",
            "entries": [
                {
                    "id": "demo-2026-evil-pkg",
                    "name": "evil-pkg supply-chain compromise",
                    "ecosystem": "npm",
                    "package": "evil-pkg",
                    "versions": ["1.2.3"],
                    "severity": "critical",
                    "source": "https://example.org/advisory",
                }
            ],
        }),
        encoding="utf-8",
    )

    rep_dir = tmp_path / "reports"
    res = BumblebeeAdapter.run(
        str(repo),
        binary_path=None,
        bumblebee_root=bb_root,
        reports_dir=rep_dir,
        use_native_binary=False,
    )
    assert res["threat_intel_catalogs_loaded"] == 1
    assert res["inventory_records_count"] >= 3
    assert res["total_findings"] == 1
    assert res["findings"][0]["rule_id"] == "BUMBLEBEE-DEMO-2026-EVIL-PKG"
    assert res["findings"][0]["cwe"] == "CWE-1395"

    # Security invariant: raw MCP env secrets MUST NEVER appear in bumblebee_inventory.ndjson
    ndjson_text = (rep_dir / "bumblebee_inventory.ndjson").read_text(encoding="utf-8")
    assert "demo-mcp" in ndjson_text
    assert "DO_NOT_EMIT_THIS_RAW_SECRET" not in ndjson_text


def test_z3_and_lean4_formal_verification_suite(tmp_path: Path) -> None:
    repo = tmp_path / "target_app"
    repo.mkdir()
    (repo / "policy.rego").write_text("package authz\ndefault allow = true\n", encoding="utf-8")
    (repo / "views.py").write_text(
        "def list_items(request):\n    limit = int(request.args.get('limit', 10))\n    return limit\n",
        encoding="utf-8",
    )
    rep_dir = tmp_path / "reports"
    res = run_formal_verification_suite(
        str(repo),
        reports_dir=rep_dir,
        findings_count=5,
        use_native_binary=False,
    )
    z3_r = res["z3_smt"]
    assert z3_r["z3_available"] is True
    assert z3_r["proved_count"] >= 5
    # Z3 must synthesize concrete counterexamples for both Rego default-allow and unclamped limit!
    assert z3_r["counterexamples_count"] >= 2
    assert any(f["rule_id"] == "Z3-RBAC-AUTHZ-BYPASS" for f in z3_r["findings"])
    assert any(f["rule_id"] == "Z3-UNBOUNDED-NUMERIC-PARAM" for f in z3_r["findings"])

    ln_r = res["lean4"]
    assert ln_r["proof_modules_total"] >= 5  # 4 core modules + synthesized TargetInvariants.lean
    assert ln_r["total_theorems"] >= 10
    assert ln_r["zero_sorry_verified"] is True
    assert (rep_dir / "lean4" / "TargetInvariants.lean").is_file()
    assert (rep_dir / "formal_verification_report.json").is_file()


def test_dynamic_stride_threat_engine_and_mantis_upgrade(tmp_path: Path) -> None:
    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "api.py").write_text(
        "import subprocess, sqlite3, openai\n"
        "@app.post('/api/chat')\n"
        "def chat(prompt):\n"
        "    subprocess.run(prompt, shell=True)\n",
        encoding="utf-8",
    )
    (repo / "Dockerfile").write_text("FROM python:latest\n", encoding="utf-8")

    rep_dir = tmp_path / "reports"
    stride_res = DynamicStrideThreatEngine.analyze_repository(
        str(repo),
        findings=[{"cwe": "CWE-78", "severity": "CRITICAL", "file_path": str(repo / "api.py")}],
        reports_dir=rep_dir,
    )
    assert stride_res["components_discovered"] >= 3
    assert len(stride_res["threat_scenarios"]) >= 4
    assert len(stride_res["mitre_attack_mapping"]) >= 3
    assert len(stride_res["zero_trust_assessment"]) == 5
    assert len(stride_res["security_requirements"]) >= 4
    assert len(stride_res["attack_trees"]) >= 2

    # Check 5-section downloadable reports + pure-Python SVG diagrams
    md_text = (rep_dir / "stride_threat_model_report.md").read_text(encoding="utf-8")
    for sec in ("1. Executive Summary", "2. Threat Model Diagram", "3. Threat Scenarios", "4. Security Requirements", "5. Attack Trees"):
        assert sec in md_text
    assert "<svg" in (rep_dir / "threat_model_diagram.svg").read_text(encoding="utf-8")
    assert "<svg" in (rep_dir / "attack_tree_diagram.svg").read_text(encoding="utf-8")
    assert (rep_dir / "stride_threat_model_report.html").is_file()

    # Verify MantisThreatModeler also emits enriched dynamic STRIDE
    tm = MantisThreatModeler().build_threat_model(str(repo), [str(repo / "api.py"), str(repo / "Dockerfile")])
    assert len(tm.components) >= 3
    assert len(tm.attack_trees) >= 1
    assert len(tm.zero_trust_assessment) == 5


def test_tool_provisioner_rfc_cache_and_mcp_folder_tools(tmp_path: Path) -> None:
    prov = ToolProvisioner()
    rfc_st = prov.check_tool_status("rfc_cache", allow_probes=False)
    assert rfc_st.installed is True, f"Expected rfc_cache READY, got: {rfc_st}"
    assert "25/25" in rfc_st.detail

    z3_st = prov.check_tool_status("z3_solver", allow_probes=False)
    assert z3_st.installed is True

    # Verify MCP server exposes run_formal_verification, run_stride_threat_model, and folder arg
    srv = TerminatorMCPServer(db_path=":memory:")
    try:
        tools = {t["name"]: t for t in srv._get_tool_definitions()}
        assert "run_ensemble_scan" in tools
        assert "folder" in tools["run_ensemble_scan"]["inputSchema"]["properties"]
        assert "folder" in tools["run_all_scans"]["inputSchema"]["properties"]
        assert "run_formal_verification" in tools
        assert "run_stride_threat_model" in tools

        repo = tmp_path / "mcp_proj"
        repo.mkdir()
        (repo / "app.py").write_text("import os\ndef ok(): return 1\n", encoding="utf-8")
        out_dir = tmp_path / "mcp_reports"

        fv = srv._execute_tool("run_formal_verification", {"folder": str(repo), "output_dir": str(out_dir)})
        assert fv["z3_smt"]["proved_count"] >= 5
        st = srv._execute_tool("run_stride_threat_model", {"folder": str(repo), "output_dir": str(out_dir)})
        assert st["components_discovered"] >= 1
    finally:
        srv.db.close()
