"""
Tests for Resource-Conditional & Authorization-Gated Strix (`usestrix/strix`) Integration.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from engine.ensemble_orchestrator import (
    CONDITIONAL_RESOURCE_GATED_TOOLS,
    IntelligentEnsemblePlanner,
    RuntimeCapabilities,
    RuntimeCapabilityProbe,
    ScannerRegistry,
    StrixAdapter,
)
from engine.tool_provisioner import ToolProvisioner
from mcp_server import TerminatorMCPServer
from ollama_manager import get_runtime_system_resources
from rfc_hunt_swarm import parse_swarm_arguments


def _caps(
    *,
    total_ram_gb: float = 32.0,
    free_ram_gb: float = 12.0,
    cpu_count: int = 8,
    free_disk_gb: float = 80.0,
    docker_daemon: bool = True,
    strix_bin: str | None = None,
) -> RuntimeCapabilities:
    reasons = []
    if total_ram_gb < 12.0:
        reasons.append(f"insufficient_total_ram ({total_ram_gb:.1f}GB < 12.0GB)")
    if free_ram_gb < 4.0:
        reasons.append(f"insufficient_free_ram ({free_ram_gb:.1f}GB < 4.0GB)")
    if cpu_count < 4:
        reasons.append(f"insufficient_cpu_cores ({cpu_count} < 4)")
    if free_disk_gb < 10.0:
        reasons.append(f"insufficient_free_disk ({free_disk_gb:.1f}GB < 10.0GB)")
    if not docker_daemon:
        reasons.append("docker_daemon_unavailable")
    return RuntimeCapabilities(
        free_ram_gb=free_ram_gb,
        free_vram_mb=0.0,
        max_scanner_workers=4,
        docker_cli=docker_daemon,
        docker_daemon=docker_daemon,
        node_cli=False,
        cargo_cli=False,
        git_cli=True,
        ollama_ready=False,
        semgrep_installed=False,
        skillspector_pkg=False,
        cloudflare_skill_repo=False,
        pyrit_installed=False,
        total_ram_gb=total_ram_gb,
        cpu_count=cpu_count,
        free_disk_gb=free_disk_gb,
        strix_installed=bool(strix_bin),
        strix_resource_eligible=(len(reasons) == 0),
        strix_resource_reasons=reasons,
        binaries={"strix": strix_bin},
        backend_matrix={},
    )


def test_runtime_system_resources_calculator_returns_all_fields() -> None:
    res = get_runtime_system_resources(allow_in_tests=False)
    assert res["total_ram_gb"] > 0
    assert res["free_ram_gb"] > 0
    assert res["cpu_count"] >= 1
    assert res["free_disk_gb"] >= 0
    assert "strix" in CONDITIONAL_RESOURCE_GATED_TOOLS
    assert ScannerRegistry().get("strix") is not None


def test_strix_skipped_fail_closed_on_low_ram_or_missing_docker(tmp_path: Path) -> None:
    # 1. Low RAM laptop (8 GB total, 2 GB free) even WITH Docker -> skipped safely
    low_ram_caps = _caps(total_ram_gb=7.9, free_ram_gb=2.0, cpu_count=4, free_disk_gb=50.0, docker_daemon=True)
    res_ram = StrixAdapter.run(str(tmp_path), capabilities=low_ram_caps)
    assert res_ram["status"].startswith("skipped:insufficient_resources:")
    assert res_ram["resource_check"]["eligible"] is False
    assert any("insufficient_total_ram" in r for r in res_ram["resource_check"]["reasons"])
    assert any("insufficient_free_ram" in r for r in res_ram["resource_check"]["reasons"])

    # 2. High RAM workstation WITHOUT Docker daemon -> skipped safely
    no_docker_caps = _caps(total_ram_gb=32.0, free_ram_gb=16.0, cpu_count=8, free_disk_gb=100.0, docker_daemon=False)
    res_doc = StrixAdapter.run(str(tmp_path), capabilities=no_docker_caps)
    assert res_doc["status"].startswith("skipped:insufficient_resources:")
    assert "docker_daemon_unavailable" in res_doc["resource_check"]["reasons"]

    # 3. Planner automatically gates off Strix even when --strix is passed on under-resourced hosts
    plan = IntelligentEnsemblePlanner.build_plan(str(tmp_path), low_ram_caps, enable_strix=True)
    strix_entry = next(s for s in plan["scheduled_scanners"] if s["tool_id"] == "strix")
    assert strix_entry["enabled"] is False
    assert strix_entry["reason"].startswith("gated_insufficient_resources:")


def test_strix_blocks_unauthorized_remote_target() -> None:
    high_caps = _caps(total_ram_gb=32.0, free_ram_gb=16.0, docker_daemon=True)
    res = StrixAdapter.run("https://example.com", capabilities=high_caps, authorized=False)
    assert res["status"].startswith("blocked:authorization_required:")
    assert res["total_findings"] == 0


def test_strix_executes_natively_when_resources_and_docker_qualify_and_grounds_epistemic(tmp_path: Path) -> None:
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    safe_file = app_dir / "safe_db.py"
    safe_file.write_text(
        "def lookup(cur, user_id):\n"
        "    return cur.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()\n",
        encoding="utf-8",
    )
    vuln_file = app_dir / "vuln_sql.py"
    vuln_file.write_text(
        "def bad_lookup(cur, user_id):\n"
        "    return cur.execute(f'SELECT * FROM users WHERE id = {user_id}').fetchone()\n",
        encoding="utf-8",
    )
    fake_strix = tmp_path / "strix.exe"
    fake_strix.write_text("fake", encoding="utf-8")

    strix_json = json.dumps({
        "findings": [
            {
                "id": "STRIX-001",
                "title": "SQL Injection in bad_lookup",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "file_path": str(vuln_file),
                "line_number": 2,
                "verified": True,
            },
            {
                "id": "STRIX-002",
                "title": "False SQLi in safe_db",
                "severity": "HIGH",
                "cwe": "CWE-89",
                "file_path": str(safe_file),
                "line_number": 2,
                "verified": False,
            },
        ]
    })

    captured = {}

    class FakeProc:
        returncode = 0
        stdout = strix_json
        stderr = ""

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        return FakeProc()

    high_caps = _caps(total_ram_gb=32.0, free_ram_gb=12.0, cpu_count=8, free_disk_gb=80.0, docker_daemon=True, strix_bin=str(fake_strix))
    with patch("engine.ensemble_orchestrator._run_safe_subprocess", side_effect=fake_run):
        res = StrixAdapter.run(
            str(app_dir),
            capabilities=high_caps,
            binary_path=str(fake_strix),
            scan_mode="standard",
            reports_dir=tmp_path / "reports",
            use_native_binary=True,
        )

    assert res["status"] == "executed_native"
    assert res["mode"] == "docker_strix_standard"
    assert captured["argv"][:5] == [str(fake_strix), "-n", "--target", str(app_dir), "--scan-mode"]
    assert captured["argv"][5] == "standard"
    assert res["total_findings"] == 2

    by_id = {f["rule_id"]: f for f in res["findings"]}
    # Verified finding keeps PROVEN_RUNTIME / PROVEN_STATIC_INVARIANT; false SQLi on parameterized query is REFUTED by AST!
    assert by_id["STRIX-001"]["epistemic_status"] in ("PROVEN_RUNTIME", "PROVEN_STATIC_INVARIANT")
    assert by_id["STRIX-002"]["epistemic_status"] == "REFUTED"
    assert "status_justification" in by_id["STRIX-002"]


def test_cli_mcp_and_provisioner_expose_resource_gated_strix(tmp_path: Path) -> None:
    args = parse_swarm_arguments(["--ensemble", "--folder", str(tmp_path), "--strix", "--strix-mode", "standard"])
    assert args.enable_strix is True
    assert args.strix_mode == "standard"

    prov = ToolProvisioner()
    st = prov.check_tool_status("strix", allow_probes=False)
    assert st.tool_id == "strix"
    assert st.category == "docker"

    srv = TerminatorMCPServer(db_path=":memory:")
    try:
        tools = {t["name"]: t for t in srv._get_tool_definitions()}
        props = tools["run_ensemble_scan"]["inputSchema"]["properties"]
        assert "enable_strix" in props
        assert "strix_mode" in props
    finally:
        srv.db.close()

    # Dry-run CLI reports Strix resource eligibility cleanly with zero side effects
    repo_root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, str(repo_root / "rfc_hunt_swarm.py"), "--ensemble", "--folder", str(tmp_path), "--strix", "--dry-run", "--json"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    assert any(m.startswith("StrixAgent(") for m in plan["planned_modules"])


def test_unified_resource_budget_and_conditional_docker_auto_provision() -> None:
    from engine.ensemble_orchestrator import EXCLUDED_PAID_OR_HEAVY_TOOLS, RESOURCE_BUDGET_PROFILES, evaluate_resource_budget

    # Nothing is hardcoded-excluded due to system resources; all heavy capabilities are resource-conditional
    assert EXCLUDED_PAID_OR_HEAVY_TOOLS == {}
    for prof_name in ("docker_runtime", "strix", "codeql", "raptor_docker", "poe_container", "docker_parser_matrix"):
        assert prof_name in RESOURCE_BUDGET_PROFILES

    # Low-resource laptop: docker_runtime is cleanly resource_gated (never force-installs Docker!)
    low_res = {"total_ram_gb": 7.9, "free_ram_gb": 1.8, "cpu_count": 2, "free_disk_gb": 6.0, "docker_daemon": False}
    low_eval = evaluate_resource_budget("docker_runtime", resources=low_res)
    assert low_eval["eligible"] is False
    assert any("insufficient_free_ram" in r for r in low_eval["reasons"])

    prov = ToolProvisioner()
    with patch.object(prov, "_docker_available", return_value=None), patch.object(prov, "_docker_daemon_responsive", return_value=False):
        dk_low = prov.ensure_docker_if_resources_available(resources_override=low_res)
    assert dk_low["status"] == "resource_gated"
    assert dk_low["docker_ready"] is False

    # High-resource workstation (32 GB RAM, 16 GB free, 8 CPUs, 120 GB disk) unlocks every profile!
    high_res = {"total_ram_gb": 32.0, "free_ram_gb": 16.0, "cpu_count": 8, "free_disk_gb": 120.0, "docker_daemon": True}
    for prof_name in RESOURCE_BUDGET_PROFILES:
        ev = evaluate_resource_budget(prof_name, resources=high_res, docker_daemon=True)
        assert ev["eligible"] is True, f"{prof_name} should unlock on high-resource host: {ev}"

    # When Docker daemon is already responsive, auto-provisioner reports already_ready cleanly
    with patch.object(prov, "_docker_available", return_value="/usr/bin/docker"), patch.object(prov, "_docker_daemon_responsive", return_value=True):
        dk_ok = prov.ensure_docker_if_resources_available(resources_override=high_res)
    assert dk_ok["status"] == "already_ready"
    assert dk_ok["docker_ready"] is True

