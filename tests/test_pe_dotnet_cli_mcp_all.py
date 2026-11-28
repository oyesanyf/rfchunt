"""
Comprehensive Unit & Integration Tests for Milestone M4:
- `ScannerTask.PE_DOTNET_AUDIT` & `ExecutionPolicy` `FILE_READ` confinement
- `engine/swarm_cli_board.py` (`pe_dotnet_auditor` registration + nested/flat result updates)
- `rfc_hunt_swarm.py` (`pe-audit` mode, `--pe-audit` / `--workspace-root` / `--dry-run`, `--all`)
- `engine/mantis_integrator.py` (`run_unified_all_scans` PE/.NET integration, `DETERMINISTIC_STATIC`, SARIF/JSON, R1+R2+R3 coexistence)
- `mcp_server.py` (`RFCHUNT_WORKSPACE_ROOT` fallback, `run_pe_dotnet_audit` + confinement, `run_all_scans`/`mantis_scan_all`)
- `engine/aiscan_integrator.py` (symlink/NTFS-junction pruning in `scan_directory`, `build_ai_bom`, `scan_target`, `scan_file`)
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import struct
import sys
import threading
from typing import Any, Dict, List, Tuple

import pytest

from database import Database
from engine.aiscan_integrator import AiscanIntegrator, PythonAIScanner
from engine.execution_policy import ActionType, ExecutionPolicy, ScannerTask, StructuredIntentProposal
from engine.mantis_integrator import run_unified_all_scans
from engine.pe_magika_classifier import (
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    IMAGE_FILE_DLL,
    IMAGE_FILE_EXECUTABLE_IMAGE,
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
)
from engine.swarm_cli_board import create_all_scan_board, update_all_board_from_result
from fusion_engine import FusionArbiter
from mcp_server import TerminatorMCPServer
import rfc_hunt_swarm as swarm


def _build_synthetic_dotnet_pe(*, clear_exec_flag: bool = False) -> bytes:
    """Builds a minimal valid PE32+ .NET assembly (optionally clearing IMAGE_FILE_EXECUTABLE_IMAGE)."""
    e_lfanew = 0x80
    buf = bytearray(0x1000)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"

    chars = IMAGE_FILE_DLL if clear_exec_flag else (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL)
    coff = e_lfanew + 4
    struct.pack_into("<HHIIIHH", buf, coff, 0x8664, 1, 0, 0, 0, 240, chars)

    opt = coff + 20
    struct.pack_into("<HBBIIIIIII", buf, opt, 0x20B, 14, 0, 0x200, 0, 0, 0x2000, 0x2000, 0, 0)
    struct.pack_into("<QIIHHHHHHIIIIHHQQQQII", buf, opt + 24,
        0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x3000, 0x200, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dd_off = opt + 112
    struct.pack_into("<II", buf, dd_off + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * 8, 0x2000, 72)

    sec_off = opt + 240
    struct.pack_into(
        "<8sIIIIIIHHI",
        buf,
        sec_off,
        b".text\x00\x00\x00",
        0x200,
        0x2000,
        0x200,
        0x400,
        0, 0, 0, 0,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    )
    cor20_off = 0x400
    struct.pack_into("<IHHIIIII", buf, cor20_off, 72, 2, 5, 0x2080, 0x100, 1, 0x06000001, 0)
    buf[0x480:0x484] = b"BSJB"
    struct.pack_into("<HHIIH", buf, 0x484, 1, 1, 0, 12, 0)
    buf[0x494:0x494 + 12] = b"v4.0.30319\x00\x00"
    return bytes(buf)


def test_execution_policy_pe_dotnet_audit_task_and_file_read(tmp_path: Path) -> None:
    pol = ExecutionPolicy.get_instance()
    assert ScannerTask.PE_DOTNET_AUDIT.value == "pe_dotnet_audit"
    assert pol.is_approved_scanner_task(ScannerTask.PE_DOTNET_AUDIT) is True
    assert pol.is_approved_scanner_task("pe_dotnet_audit") is True

    ws = tmp_path / "ws"
    ws.mkdir()
    sample = ws / "sample.dll"
    sample.write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=False))
    outside = tmp_path / "outside.dll"
    outside.write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=True))

    assert pol.validate_intent(
        StructuredIntentProposal(
            task=ScannerTask.PE_DOTNET_AUDIT,
            action_type=ActionType.FILE_READ,
            file_path=str(sample),
            workspace_root=str(ws),
        )
    ) is True

    with pytest.raises(PermissionError):
        pol.validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.PE_DOTNET_AUDIT,
                action_type=ActionType.FILE_READ,
                file_path=str(outside),
                workspace_root=str(ws),
            )
        )


def test_swarm_cli_board_pe_dotnet_auditor_flat_and_nested_engines() -> None:
    board_flat = create_all_scan_board("repo_flat", plain=True)
    assert "pe_dotnet_auditor" in board_flat.tasks
    assert board_flat.tasks["pe_dotnet_auditor"].thread_id == "static_ai"

    update_all_board_from_result(
        board_flat,
        {
            "mantis": {"status": "completed", "total_findings": 1},
            "pe_dotnet_auditor": {"status": "completed", "total_findings": 2},
        },
    )
    assert board_flat.tasks["pe_dotnet_auditor"].state == "Done"
    assert "count=2" in board_flat.tasks["pe_dotnet_auditor"].note
    rendered_flat = board_flat.render(plain=True, width=100)
    assert "RFCHunt --all" in rendered_flat
    assert "pe" in rendered_flat.lower()

    # Nested `res["engines"]` payload emitted by run_unified_all_scans / cmd_all
    board_nested = create_all_scan_board("repo_nested", plain=True)
    update_all_board_from_result(
        board_nested,
        {
            "engines": {
                "mantis": {"status": "completed", "total_findings": 0},
                "pe_dotnet_auditor": {"status": "completed", "total_findings": 3},
                "aiscan": {"total_findings": 0},
            }
        },
    )
    assert board_nested.tasks["pe_dotnet_auditor"].state == "Done"
    assert "count=3" in board_nested.tasks["pe_dotnet_auditor"].note


def test_cli_pe_audit_mode_flags_dry_run_and_confinement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert {"pe-audit", "pe_audit", "pe-dotnet", "pe_dotnet"}.issubset(set(swarm.ALL_MODES))
    parser = swarm.build_swarm_parser()
    opts = {opt for act in parser._actions for opt in act.option_strings}
    assert {"--pe-audit", "--pe-dotnet", "--no-pe-audit", "--pe-include-host-audit", "--pe-no-host-audit", "--pe-no-yara", "--workspace-root"}.issubset(opts)

    repo = tmp_path / "repo"
    out_dir = tmp_path / "out_dry"
    outside = tmp_path / "outside"
    repo.mkdir()
    out_dir.mkdir()
    outside.mkdir()
    (repo / "clean.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=False))
    (repo / "bypass.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=True))

    # Dry-run must have zero side effects and write zero files
    swarm.main_swarm([
        "pe-audit",
        "--path", str(repo),
        "--output-dir", str(out_dir),
        "--dry-run",
        "--json",
    ])
    dry_stdout = capsys.readouterr().out
    dry_plan = json.loads(dry_stdout)
    assert dry_plan["dry_run"] is True
    assert dry_plan["side_effects"]["filesystem_mutations"] == 0
    assert any("PE-DotNet-Auditor" in m for m in dry_plan["planned_modules"])
    assert list(out_dir.iterdir()) == []

    # Live --pe-audit --pe-no-host-audit --json (output_dir inside --workspace-root)
    live_out = repo / "out_live"
    swarm.main_swarm([
        "--pe-audit",
        "--path", str(repo),
        "--workspace-root", str(repo),
        "--output-dir", str(live_out),
        "--pe-no-host-audit",
        "--json",
    ])
    live_stdout = capsys.readouterr().out
    live_res = json.loads(live_stdout)
    assert live_res["files_scanned"] == 2
    assert live_res["cve_2026_108398_count"] == 1
    assert (live_out / "pe_dotnet_audit.json").is_file()

    # Out-of-workspace output_dir rejected with SystemExit(1) and writes nothing
    outside_pe_out = outside / "pe_out_blocked"
    with pytest.raises(SystemExit) as exc_out:
        swarm.main_swarm([
            "--pe-audit",
            "--workspace-root", str(repo),
            "--path", str(repo),
            "--output-dir", str(outside_pe_out),
            "--pe-no-host-audit",
            "--json",
        ])
    assert exc_out.value.code == 1
    assert not (outside_pe_out / "pe_dotnet_audit.json").exists()

    # Out-of-workspace path rejected with SystemExit(1)
    with pytest.raises(SystemExit) as exc_info:
        swarm.main_swarm([
            "--pe-audit",
            "--workspace-root", str(repo),
            "--path", str(outside),
            "--pe-no-host-audit",
            "--json",
        ])
    assert exc_info.value.code == 1


def test_run_unified_all_scans_pe_dotnet_sarif_json_and_r1_r2_r3_coexistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    repo = tmp_path / "poly_repo"
    out_dir = tmp_path / "reports"
    repo.mkdir()
    out_dir.mkdir()
    (repo / "clean.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=False))
    (repo / "bypass.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=True))

    import engine.aiscan_integrator as ai_mod
    import engine.mantis_integrator as mi_mod

    class _TagsHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/api/tags":
                payload = json.dumps({"models": [{"name": "glm4:9b"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), _TagsHandler)
    ep = f"http://127.0.0.1:{srv.server_address[1]}"
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    arb_calls: List[Dict[str, Any]] = []
    db = Database(str(tmp_path / "test.db"))
    try:
        monkeypatch.setattr(mi_mod.MantisIntegrator, "run_scan", lambda *a, **kw: {"findings": [], "threat_model": None, "total_findings": 0})
        monkeypatch.setattr(ai_mod.AiscanIntegrator, "scan_target", lambda *a, **kw: {"findings": [], "endpoints": [], "total_findings": 0})
        monkeypatch.setattr(mi_mod, "_run_cross_platform_raptor_fallback", lambda *a, **kw: {"findings": [], "total_findings": 0})

        arb = FusionArbiter(endpoint=ep, quiet=True)

        def _suppress_arbiter(*args: Any, **kwargs: Any) -> Dict[str, Any]:
            arb_calls.append({"args": args, "kwargs": dict(kwargs)})
            return {"executive_summary": "0 vulnerabilities found. Everything is completely safe."}

        monkeypatch.setattr(arb, "arbitrate_structured_json", _suppress_arbiter)
        try:
            res = run_unified_all_scans(
                repo=str(repo),
                db=db,
                reports_dir=str(out_dir),
                arbiter=arb,
                artex_rounds=0,
                enable_external_scanners=False,
                enable_rea=False,
                enable_h2_desync=False,
                enable_verification_inversion=False,
                enable_arxiv_detect=False,
                enable_last30days_skills=False,
                enable_preflight=False,
                quiet=True,
            )
        finally:
            arb.close()
    finally:
        srv.shutdown()
        srv.server_close()
        db.close()

    pe_eng = res["engines"]["pe_dotnet_auditor"]
    assert pe_eng["status"] == "completed"
    assert pe_eng["files_scanned"] == 2
    assert pe_eng["cve_2026_108398_count"] == 1
    assert pe_eng["total_findings"] >= 1

    det_pe = [f for f in res["deterministic_static_findings"] if str(f.get("rule_id") or "").startswith("PE-")]
    assert det_pe
    assert all(f["evidence_lane"] == "DETERMINISTIC_STATIC" for f in det_pe)
    assert all(f["poe_level"] == 2 for f in det_pe)
    assert all(f["scanner"] == "Module-PE-DotNet-Auditor" for f in det_pe)

    # R1 XML nonce fencing on unified summary call
    assert len(arb_calls) >= 1
    user_prompt = arb_calls[-1]["kwargs"].get("user_prompt", "")
    assert '<untrusted_data nonce="' in user_prompt
    assert "</untrusted_data>" in user_prompt

    # R2 override immunity triggered even when ONLY PE/.NET findings exist
    assert res["llm_override_blocked"] is True
    assert "0 vulnerabilities found" not in res["executive_summary"].lower()

    sarif_doc = json.loads(Path(res["report_files"]["combined_sarif"]).read_text(encoding="utf-8"))
    sarif_rules = {r["ruleId"] for r in sarif_doc["runs"][0]["results"]}
    assert "PE-DOTNET-CVE-2026-108398" in sarif_rules

    summary_doc = json.loads(Path(res["report_files"]["combined_json"]).read_text(encoding="utf-8"))
    assert "pe_dotnet_auditor" in summary_doc["engines"]
    assert summary_doc["llm_override_blocked"] is True


def test_mcp_server_rfchunt_workspace_root_and_pe_dotnet_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "mcp_repo"
    outside = tmp_path / "mcp_outside"
    out_dir = repo / "reports"
    repo.mkdir()
    outside.mkdir()
    out_dir.mkdir()
    (repo / "bypass.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=True))
    (outside / "secret.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=True))

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.delenv("RFCHUNT_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setenv("RFCHUNT_WORKSPACE_ROOT", str(repo))

    srv = TerminatorMCPServer(db_path=str(tmp_path / "mcp.db"))
    assert srv.workspace_root == repo.resolve()

    tools = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})["result"]["tools"]
    tool_names = {t["name"] for t in tools}
    assert "run_pe_dotnet_audit" in tool_names

    ok_resp = srv.handle_request({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "run_pe_dotnet_audit",
            "arguments": {"target_path": str(repo), "include_host_audit": False},
        },
    })
    assert "error" not in ok_resp
    pe_payload = json.loads(ok_resp["result"]["content"][0]["text"])
    assert pe_payload["cve_2026_108398_count"] == 1

    # Out-of-root target_path must fail closed
    bad_resp = srv.handle_request({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "run_pe_dotnet_audit",
            "arguments": {"target_path": str(outside), "include_host_audit": False},
        },
    })
    assert bad_resp["error"]["code"] == -32001

    # run_all_scans forwards enable_pe_audit=False cleanly
    all_disabled = srv.handle_request({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "run_all_scans",
            "arguments": {
                "repo": str(repo),
                "output_dir": str(out_dir),
                "depth": 10,
                "mantis_mode": "fast",
                "enable_rea": False,
                "enable_external_scanners": False,
                "enable_pe_audit": False,
            },
        },
    })
    assert "error" not in all_disabled
    all_payload = json.loads(all_disabled["result"]["content"][0]["text"])
    assert all_payload["engines"]["pe_dotnet_auditor"]["status"] == "disabled"

    # output_dir traversal / non-temp outside dir must be rejected
    trav_out_resp = srv.handle_request({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "run_all_scans",
            "arguments": {"repo": str(repo), "output_dir": "../escape_reports"},
        },
    })
    assert trav_out_resp["error"]["code"] == -32001


def test_aiscan_integrator_prunes_directory_junction_and_symlink_escapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "ai_ws"
    outside = tmp_path / "ai_outside"
    ws.mkdir()
    outside.mkdir()

    (ws / "inroot.py").write_text("import os\n", encoding="utf-8")
    (outside / "secret_ai.py").write_text(
        'OPENAI_API_KEY = "sk-ant-1234567890abcdef1234567890abcdef"\nprompt = f"hi {user}"\n',
        encoding="utf-8",
    )
    (outside / "weights.gguf").write_bytes(b"GGUF\x00\x00\x00\x00")
    (outside / "mcp.json").write_text("{}", encoding="utf-8")

    # 1. Real junction or symlink escape inside ws
    esc_dir = ws / "evil_dir"
    created = False
    if sys.platform == "win32":
        try:
            import _winapi  # type: ignore[attr-defined]
            _winapi.CreateJunction(str(outside), str(esc_dir))
            created = True
        except OSError:
            pass
    if not created:
        try:
            os.symlink(str(outside), str(esc_dir), target_is_directory=True)
            created = True
        except OSError:
            pass

    scanner = PythonAIScanner()
    if created:
        findings, endpoints = scanner.scan_directory(ws)
        assert findings == []
        bom = scanner.build_ai_bom(ws, findings, endpoints)
        assert bom["weights_files"] == []
        assert bom["mcp_servers"] == []

    # 2. Simulated <=3.11 NTFS junction (is_symlink() == False, FILE_ATTRIBUTE_REPARSE_POINT set)
    sim_ws = tmp_path / "sim_ai_ws"
    sim_ws.mkdir()
    (sim_ws / "inroot.py").write_text("x = 1\n", encoding="utf-8")
    sim_esc = sim_ws / "sim_junction"
    sim_esc.mkdir()
    (sim_esc / "secret_ai.py").write_text('OPENAI_API_KEY = "sk-ant-1234567890abcdef1234567890abcdef"\n', encoding="utf-8")
    (sim_esc / "weights.gguf").write_bytes(b"GGUF\x00\x00\x00\x00")

    import engine.execution_policy as pol_mod

    monkeypatch.setattr(pol_mod, "_is_symlink_or_reparse", lambda p: Path(p).name == "sim_junction")
    monkeypatch.setattr("engine.aiscan_integrator._is_symlink_or_reparse", lambda p: Path(p).name == "sim_junction")
    orig_readlink = os.readlink
    monkeypatch.setattr(os, "readlink", lambda p: str(outside) if Path(p).name == "sim_junction" else orig_readlink(p))

    findings_sim, endpoints_sim = scanner.scan_directory(sim_ws)
    assert findings_sim == []
    bom_sim = scanner.build_ai_bom(sim_ws, findings_sim, endpoints_sim)
    assert bom_sim["weights_files"] == []

    # 3. Direct scan_file(root_dir=...) and AiscanIntegrator.scan_target(workspace_root=...) confinement
    with pytest.raises(PermissionError):
        scanner.scan_file(outside / "secret_ai.py", root_dir=ws)

    integrator = AiscanIntegrator(db=None, reports_dir=str(tmp_path / "ai_reports"), auto_install=False, use_native_binary=False)
    with pytest.raises(PermissionError):
        integrator.scan_target(outside, workspace_root=ws)


def test_mcp_ws_none_output_dir_and_sensitive_path_confinement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tempfile

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.delenv("RFCHUNT_WORKSPACE_ROOT", raising=False)
    monkeypatch.delenv("RFCHUNT_MCP_WORKSPACE_ROOT", raising=False)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

    srv = TerminatorMCPServer(db_path=str(tmp_path / "mcp_nows.db"), workspace_root=None)
    try:
        for bad_out in (
            r"C:\Windows",
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Windows\Temp\evil_rep",
            tempfile.gettempdir(),
            "~/.ssh",
            "~/.aws",
            "~/.gnupg",
            "~/.kube",
            r"C:\nonexistent_outside_probe_dir\rep",
        ):
            with pytest.raises(PermissionError):
                srv._validate_mcp_output_dir(bad_out)

        ok_out = srv._validate_mcp_output_dir(str(tmp_path / "valid_reports"))
        assert Path(ok_out).resolve(strict=False) == (tmp_path / "valid_reports").resolve(strict=False)

        # run_all_scans with ws=None must still reject C:\Windows\SysWOW64\evil_rep
        bad_all = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "run_all_scans",
                "arguments": {"repo": str(repo), "output_dir": r"C:\Windows\SysWOW64\evil_rep"},
            },
        })
        assert bad_all["error"]["code"] == -32001
    finally:
        srv.close()

    # Even with explicit workspace_root set, ~/.ssh must be blocked
    srv_ws = TerminatorMCPServer(db_path=str(tmp_path / "mcp_ws.db"), workspace_root=repo)
    try:
        with pytest.raises(PermissionError):
            srv_ws._validate_mcp_scan_path("~/.ssh")
    finally:
        srv_ws.close()


def test_mcp_workspace_root_whitespace_file_and_narrowing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "ws"
    sub = ws / "sub"
    outside = tmp_path / "outside"
    sub.mkdir(parents=True)
    outside.mkdir()
    (ws / "root.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=True))
    (sub / "sub.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=True))
    not_a_dir = tmp_path / "not_a_dir.txt"
    not_a_dir.write_text("file", encoding="utf-8")

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.delenv("RFCHUNT_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setenv("RFCHUNT_WORKSPACE_ROOT", "   ")
    with pytest.raises(PermissionError):
        TerminatorMCPServer(db_path=str(tmp_path / "ws_space.db"))

    monkeypatch.delenv("RFCHUNT_WORKSPACE_ROOT", raising=False)
    monkeypatch.setenv("RFCHUNT_MCP_WORKSPACE_ROOT", "   ")
    with pytest.raises(PermissionError):
        TerminatorMCPServer(db_path=str(tmp_path / "mcp_space.db"))

    monkeypatch.delenv("RFCHUNT_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setenv("RFCHUNT_WORKSPACE_ROOT", str(not_a_dir))
    with pytest.raises(PermissionError):
        TerminatorMCPServer(db_path=str(tmp_path / "ws_file.db"))

    monkeypatch.delenv("RFCHUNT_WORKSPACE_ROOT", raising=False)
    srv = TerminatorMCPServer(db_path=str(tmp_path / "ws_narrow.db"), workspace_root=ws)
    try:
        assert srv._resolve_mcp_workspace_root({"workspace_root": str(sub)}) == sub.resolve()
        with pytest.raises(PermissionError):
            srv._resolve_mcp_workspace_root({"workspace_root": str(outside)})

        # Narrowing blocks scanning parent ws even though srv.workspace_root == ws
        bad_narrow = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "run_pe_dotnet_audit",
                "arguments": {"target_path": str(ws), "workspace_root": str(sub), "include_host_audit": False},
            },
        })
        assert bad_narrow["error"]["code"] == -32001

        ok_narrow = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "run_pe_dotnet_audit",
                "arguments": {"target_path": str(sub), "workspace_root": str(sub), "include_host_audit": False},
            },
        })
        assert "error" not in ok_narrow
        payload = json.loads(ok_narrow["result"]["content"][0]["text"])
        assert payload["files_scanned"] == 1
    finally:
        srv.close()


def test_mantis_unified_ws_none_reports_dir_and_sensitive_path_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tempfile

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    db = Database(str(tmp_path / "mantis_nows.db"))
    try:
        for bad_rep in (
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Windows\Temp\evil_rep",
            "~/.ssh",
            tempfile.gettempdir(),
            r"C:\nonexistent_outside_probe_dir\rep",
        ):
            with pytest.raises(PermissionError):
                run_unified_all_scans(
                    repo=str(repo),
                    db=db,
                    reports_dir=bad_rep,
                    workspace_root=None,
                    enable_external_scanners=False,
                    enable_rea=False,
                    enable_preflight=False,
                    quiet=True,
                )
    finally:
        db.close()


def test_aiscan_ws_none_direct_and_intermediate_junction_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "ws_junc"
    outside = tmp_path / "outside_junc"
    ws.mkdir()
    outside.mkdir()
    secret_f = outside / "secret_ai.py"
    secret_f.write_text('OPENAI_API_KEY = "sk-ant-1234567890abcdef1234567890abcdef"\n', encoding="utf-8")

    junc_dir = ws / "junc_out"
    created = False
    if sys.platform == "win32":
        try:
            import _winapi  # type: ignore[attr-defined]
            _winapi.CreateJunction(str(outside), str(junc_dir))
            created = True
        except OSError:
            pass
    if not created:
        try:
            os.symlink(str(outside), str(junc_dir), target_is_directory=True)
            created = True
        except OSError:
            pass

    scanner = PythonAIScanner()
    integrator = AiscanIntegrator(
        db=None,
        reports_dir=str(tmp_path / "ai_rep"),
        auto_install=False,
        use_native_binary=False,
    )
    if created:
        with pytest.raises(PermissionError):
            scanner.scan_directory(junc_dir)
        with pytest.raises(PermissionError):
            scanner.build_ai_bom(junc_dir, [], [])
        with pytest.raises(PermissionError):
            scanner.scan_file(junc_dir / "secret_ai.py", root_dir=None)
        with pytest.raises(PermissionError):
            integrator.scan_target(junc_dir / "secret_ai.py", workspace_root=None)

        dead_target = tmp_path / "dead_ai_target"
        dead_target.mkdir()
        broken_junc = ws / "broken_junc"
        broken_created = False
        if sys.platform == "win32":
            try:
                import _winapi  # type: ignore[attr-defined]
                _winapi.CreateJunction(str(dead_target), str(broken_junc))
                broken_created = True
            except OSError:
                pass
        if not broken_created:
            try:
                os.symlink(str(dead_target), str(broken_junc), target_is_directory=True)
                broken_created = True
            except OSError:
                pass
        if broken_created:
            dead_target.rmdir()
            with pytest.raises(PermissionError):
                scanner.scan_directory(broken_junc)
            with pytest.raises(PermissionError):
                scanner.scan_file(broken_junc / "secret_ai.py", root_dir=None)
            with pytest.raises(PermissionError):
                integrator.scan_target(broken_junc / "secret_ai.py", workspace_root=None)

    # Simulated Python <=3.11 reparse point (is_symlink/isjunction False, lstat FILE_ATTRIBUTE_REPARSE_POINT)
    sim_dir = ws / "sim_junc"
    sim_dir.mkdir()
    (sim_dir / "secret_ai.py").write_text('OPENAI_API_KEY = "sk-ant-1234567890abcdef1234567890abcdef"\n', encoding="utf-8")

    import engine.aiscan_integrator as ai_mod
    import engine.execution_policy as pol_mod

    monkeypatch.setattr(ai_mod, "_is_symlink_or_reparse", lambda p: Path(p).name == "sim_junc")
    monkeypatch.setattr(pol_mod, "_is_symlink_or_reparse", lambda p: Path(p).name == "sim_junc")

    with pytest.raises(PermissionError):
        scanner.scan_directory(sim_dir)
    with pytest.raises(PermissionError):
        scanner.scan_file(sim_dir / "secret_ai.py", root_dir=None)
    with pytest.raises(PermissionError):
        integrator.scan_target(sim_dir / "secret_ai.py", workspace_root=None)


def test_cli_export_sarif_escape_and_dry_run_negative_turns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    repo = tmp_path / "cli_repo"
    out_dir = tmp_path / "cli_out"
    outside_dir = tmp_path / "cli_outside"
    repo.mkdir()
    out_dir.mkdir()
    outside_dir.mkdir()
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")

    # 1. Relative --export-sarif escape must exit cleanly with SystemExit(1) (no uncaught ValueError)
    with pytest.raises(SystemExit) as exc_rel:
        swarm.main_swarm([
            "--all",
            "--repo", str(repo),
            "--output-dir", str(out_dir),
            "--db", str(tmp_path / "cli1.db"),
            "--export-sarif", "../escape.sarif",
            "--no-external-scanners",
            "--no-preflight",
            "--no-auto-install",
            "--json",
        ])
    assert exc_rel.value.code == 1
    assert not (tmp_path / "escape.sarif").exists()

    # 2. Absolute out-of-root --export-sarif must exit cleanly with SystemExit(1) and not write file
    abs_target = outside_dir / "abs_escape.sarif"
    with pytest.raises(SystemExit) as exc_abs:
        swarm.main_swarm([
            "--all",
            "--repo", str(repo),
            "--output-dir", str(out_dir),
            "--db", str(tmp_path / "cli2.db"),
            "--export-sarif", str(abs_target),
            "--no-external-scanners",
            "--no-preflight",
            "--no-auto-install",
            "--json",
        ])
    assert exc_abs.value.code == 1
    assert not abs_target.exists()

    # 3. --dry-run with negative --artex-intent-turns must exit with SystemExit(1)
    with pytest.raises(SystemExit) as exc_dry:
        swarm.main_swarm([
            "--all",
            "--repo", str(repo),
            "--artex-intent-turns", "-1",
            "--dry-run",
            "--json",
        ])
    assert exc_dry.value.code == 1


def test_challenger2c_cmd_pe_audit_output_dir_confinement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import tempfile

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    ws = tmp_path / "ws_pe"
    outside = tmp_path / "outside_pe"
    ws.mkdir()
    outside.mkdir()
    (ws / "bypass.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=True))

    # 1. Sensitive host paths, bare %TEMP%, and arbitrary outside paths rejected by RFCHunt validation
    for bad_out in (
        r"C:\Windows\System32",
        "~/.ssh",
        tempfile.gettempdir(),
        r"C:\nonexistent_rfchunt_pe_outside\rep",
    ):
        with pytest.raises(SystemExit) as exc_info:
            swarm.main_swarm([
                "--pe-audit",
                "--path", str(ws),
                "--output-dir", bad_out,
                "--pe-no-host-audit",
                "--pe-no-yara",
                "--json",
            ])
        assert exc_info.value.code == 1
        err_txt = capsys.readouterr().err
        assert "Errno 13" not in err_txt

    # 2. Out-of-workspace --output-dir rejected when --workspace-root is set
    out_ws_escape = outside / "pe_ws_escape"
    with pytest.raises(SystemExit) as exc_ws:
        swarm.main_swarm([
            "--pe-audit",
            "--workspace-root", str(ws),
            "--path", str(ws),
            "--output-dir", str(out_ws_escape),
            "--pe-no-host-audit",
            "--pe-no-yara",
            "--json",
        ])
    assert exc_ws.value.code == 1
    assert not (out_ws_escape / "pe_dotnet_audit.json").exists()

    # 3. NTFS junction escape in --output-dir rejected when ws_root=None
    if sys.platform == "win32":
        try:
            import _winapi  # type: ignore[attr-defined]
            junc_out = ws / "junc_out"
            _winapi.CreateJunction(str(outside), str(junc_out))
            with pytest.raises(SystemExit) as exc_junc:
                swarm.main_swarm([
                    "--pe-audit",
                    "--path", str(ws),
                    "--output-dir", str(junc_out / "pe_junc_out"),
                    "--pe-no-host-audit",
                    "--pe-no-yara",
                    "--json",
                ])
            assert exc_junc.value.code == 1
            assert not (outside / "pe_junc_out" / "pe_dotnet_audit.json").exists()
        except OSError:
            pass

    # 4. Legitimate %TEMP% subdirectory without --workspace-root succeeds
    ok_out = tmp_path / "ok_pe_out"
    swarm.main_swarm([
        "--pe-audit",
        "--path", str(ws),
        "--output-dir", str(ok_out),
        "--pe-no-host-audit",
        "--pe-no-yara",
        "--json",
    ])
    _ = capsys.readouterr()
    assert (ok_out / "pe_dotnet_audit.json").is_file()


def test_challenger2c_artex_mcp_output_dir_and_uncollapsed_reparse_dotdot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tempfile
    from engine.pe_magika_classifier import audit_pe_dotnet_target

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.delenv("RFCHUNT_WORKSPACE_ROOT", raising=False)
    monkeypatch.delenv("RFCHUNT_MCP_WORKSPACE_ROOT", raising=False)

    # 1. Sibling MCP Artex output tools enforce _validate_mcp_output_dir when workspace_root=None
    with TerminatorMCPServer(db_path=str(tmp_path / "artex_nows.db"), workspace_root=None) as srv:
        for bad_dir in (
            tempfile.gettempdir(),
            r"C:\Windows\System32",
            "~/.ssh",
            r"C:\nonexistent_rfchunt_outside_probe\rep",
        ):
            with pytest.raises(PermissionError):
                srv._execute_tool("artex_run_attack_chain", {"reports_dir": bad_dir})
            with pytest.raises(PermissionError):
                srv._execute_tool("artex_export_advisory", {"output_dir": bad_dir})
            bad_archive = bad_dir if bad_dir == tempfile.gettempdir() else (bad_dir + "/leak.rfca")
            with pytest.raises(PermissionError):
                srv._execute_tool(
                    "artex_export_advisory",
                    {"output_dir": str(tmp_path / "adv_ok"), "archive_path": bad_archive},
                )

    # 2. junc_out\..\target lexical collapse rejected when workspace_root=None
    ws = tmp_path / "ws_dotdot"
    outside = tmp_path / "outside_dotdot"
    ws.mkdir()
    outside.mkdir()
    (ws / "ws_cve.dll").write_bytes(_build_synthetic_dotnet_pe(clear_exec_flag=True))
    (ws / "app.py").write_text('OPENAI_API_KEY = "sk-ant-1234567890abcdef1234567890abcdef"\n', encoding="utf-8")

    junc_dir = ws / "junc_out"
    created = False
    if sys.platform == "win32":
        try:
            import _winapi  # type: ignore[attr-defined]
            _winapi.CreateJunction(str(outside), str(junc_dir))
            created = True
        except OSError:
            pass
    if created:
        dotdot_pe = str(ws / "junc_out" / ".." / "ws_cve.dll")
        dotdot_ai = str(ws / "junc_out" / ".." / "app.py")
        dotdot_dir = str(ws / "junc_out" / ".." / "ws_dotdot") if False else str(ws / "junc_out" / "..")

        with pytest.raises(PermissionError):
            audit_pe_dotnet_target(dotdot_pe, include_host_audit=False, include_yara=False, workspace_root=None)

        scanner = PythonAIScanner()
        integrator = AiscanIntegrator(
            db=None,
            reports_dir=str(tmp_path / "ai_dd_rep"),
            auto_install=False,
            use_native_binary=False,
        )
        with pytest.raises(PermissionError):
            integrator.scan_target(dotdot_ai, workspace_root=None)
        with pytest.raises(PermissionError):
            scanner.scan_file(dotdot_ai, root_dir=None)
        with pytest.raises(PermissionError):
            scanner.scan_directory(dotdot_dir)
        with pytest.raises(PermissionError):
            scanner.build_ai_bom(dotdot_dir, [], [])


def test_mcp_http_server_keepalive_body_drain_on_401_403_404(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import http.client
    from mcp_server import MCPHttpServer

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    ws = tmp_path / "http_ws"
    ws.mkdir()
    with TerminatorMCPServer(db_path=str(tmp_path / "http_ka.db"), workspace_root=ws) as srv:
        http_srv = MCPHttpServer(srv, host="127.0.0.1", port=0, bearer_token="ka-secret-token")
        host, port = http_srv.start()
        conn = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}})

            # 401 missing auth -> 401 wrong auth -> 403 bad Origin -> 404 unknown /message?sessionId -> 200 valid
            conn.request("POST", "/mcp", body=body, headers={"Content-Type": "application/json"})
            r1 = conn.getresponse()
            r1.read()
            assert r1.status == 401

            conn.request(
                "POST",
                "/mcp",
                body=body,
                headers={"Content-Type": "application/json", "Authorization": "Bearer wrong"},
            )
            r2 = conn.getresponse()
            r2.read()
            assert r2.status == 401

            conn.request(
                "POST",
                "/mcp",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer ka-secret-token",
                    "Origin": "https://evil.example",
                },
            )
            r3 = conn.getresponse()
            r3.read()
            assert r3.status == 403

            conn.request(
                "POST",
                "/message?sessionId=nonexistent_sid",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer ka-secret-token",
                    "Origin": "http://127.0.0.1",
                },
            )
            r4 = conn.getresponse()
            r4.read()
            assert r4.status == 404

            conn.request(
                "POST",
                "/mcp",
                body=json.dumps({"jsonrpc": "2.0", "id": 99, "method": "initialize", "params": {}}),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer ka-secret-token",
                    "Origin": "http://127.0.0.1",
                },
            )
            r5 = conn.getresponse()
            payload5 = json.loads(r5.read().decode("utf-8"))
            assert r5.status == 200
            assert payload5["result"]["protocolVersion"] == "2024-11-05"
        finally:
            if conn is not None:
                conn.close()
            http_srv.stop()


def _read_raw_http_response(sock: Any) -> Tuple[str, Dict[str, str], bytes]:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
    raw = bytes(buf)
    head_raw, _, rest = raw.partition(b"\r\n\r\n")
    lines = head_raw.decode("iso-8859-1", errors="replace").split("\r\n")
    status_line = lines[0] if lines else ""
    hdrs: Dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    cl = int(hdrs["content-length"]) if hdrs.get("content-length", "").isdigit() else 0
    body = bytearray(rest)
    while len(body) < cl:
        chunk = sock.recv(min(65536, cl - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    return status_line, hdrs, bytes(body[:cl])


def test_mcp_http_server_chunked_keepalive_and_smuggling_hardening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket
    from mcp_server import MCPHttpServer

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    ws = tmp_path / "http_chunk_ws"
    ws.mkdir()
    with TerminatorMCPServer(db_path=str(tmp_path / "http_chunk.db"), workspace_root=ws) as srv:
        http_srv = MCPHttpServer(srv, host="127.0.0.1", port=0, bearer_token="chunk-secret-tok")
        host, port = http_srv.start()
        try:
            # 1) Authenticated POST /http with valid Transfer-Encoding: chunked + persistent follow-up
            rpc1 = json.dumps({"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}}).encode("utf-8")
            mid = len(rpc1) // 2
            part1, part2 = rpc1[:mid], rpc1[mid:]
            chunked_payload = (
                f"{len(part1):x};ext=ok\r\n".encode("ascii")
                + part1
                + b"\r\n"
                + f"{len(part2):x}\r\n".encode("ascii")
                + part2
                + b"\r\n0\r\nX-Ignored-Trailer: 1\r\n\r\n"
            )
            req1 = (
                f"POST /http HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Authorization: Bearer chunk-secret-tok\r\n"
                f"Origin: http://{host}:{port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            ).encode("ascii") + chunked_payload

            rpc2 = json.dumps({"jsonrpc": "2.0", "id": 11, "method": "ping", "params": {}}).encode("utf-8")
            req2 = (
                f"POST /http HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Authorization: Bearer chunk-secret-tok\r\n"
                f"Origin: http://{host}:{port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(rpc2)}\r\n"
                f"\r\n"
            ).encode("ascii") + rpc2

            with socket.create_connection((host, port), timeout=5) as sock:
                sock.sendall(req1)
                st1, h1, b1 = _read_raw_http_response(sock)
                assert "200 OK" in st1
                assert h1.get("connection", "").lower() != "close"
                j1 = json.loads(b1.decode("utf-8"))
                assert j1["id"] == 10
                assert "tools" in j1["result"]

                sock.sendall(req2)
                st2, h2, b2 = _read_raw_http_response(sock)
                assert "200 OK" in st2
                j2 = json.loads(b2.decode("utf-8"))
                assert j2["id"] == 11
                assert j2["result"] == {}

            # 2) Malformed / smuggling / invalid Content-Length cases must return 400 + Connection: close
            bad_requests = [
                # Malformed chunked size
                (
                    f"POST /http HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer chunk-secret-tok\r\n"
                    f"Origin: http://{host}:{port}\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n0\r\n\r\n"
                ).encode("ascii"),
                # CL + TE smuggling conflict
                (
                    f"POST /http HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer chunk-secret-tok\r\n"
                    f"Origin: http://{host}:{port}\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                ).encode("ascii"),
                # Unsupported TE: gzip
                (
                    f"POST /http HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer chunk-secret-tok\r\n"
                    f"Origin: http://{host}:{port}\r\nTransfer-Encoding: gzip\r\n\r\n"
                ).encode("ascii"),
                # Negative Content-Length
                (
                    f"POST /http HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer chunk-secret-tok\r\n"
                    f"Origin: http://{host}:{port}\r\nContent-Length: -5\r\n\r\n"
                ).encode("ascii"),
                # Non-digit Content-Length (+10 / 1_0)
                (
                    f"POST /http HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer chunk-secret-tok\r\n"
                    f"Origin: http://{host}:{port}\r\nContent-Length: +10\r\n\r\n"
                ).encode("ascii"),
                # Duplicate Content-Length
                (
                    f"POST /http HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer chunk-secret-tok\r\n"
                    f"Origin: http://{host}:{port}\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"
                ).encode("ascii"),
                # > 10 MiB Content-Length
                (
                    f"POST /http HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer chunk-secret-tok\r\n"
                    f"Origin: http://{host}:{port}\r\nContent-Length: 10485761\r\n\r\n"
                ).encode("ascii"),
            ]
            for raw_bad in bad_requests:
                with socket.create_connection((host, port), timeout=5) as sock:
                    sock.sendall(raw_bad)
                    st_b, h_b, b_b = _read_raw_http_response(sock)
                    assert "400 Bad Request" in st_b, f"Expected 400, got {st_b} ({b_b!r})"
                    assert h_b.get("connection", "").lower() == "close", f"Missing Connection: close in {h_b}"
                    err_obj = json.loads(b_b.decode("utf-8"))
                    assert err_obj["error"]["code"] == -32700
        finally:
            http_srv.stop()


def test_mcp_output_dir_rejects_tilde_ssh_when_env_workspace_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "env_ws"
    ws.mkdir()
    monkeypatch.setenv("RFCHUNT_WORKSPACE_ROOT", str(ws))
    with TerminatorMCPServer(db_path=str(tmp_path / "env_ws.db"), workspace_root=None) as srv:
        with pytest.raises(PermissionError):
            srv._validate_mcp_output_dir("~/.ssh")
        with pytest.raises(PermissionError):
            srv._validate_mcp_output_dir(".ssh")
        rel_reports = srv._validate_mcp_output_dir("reports")
        assert Path(rel_reports).resolve(strict=False) == (ws / "reports").resolve(strict=False)


def test_fuzz_bridge_parse_llm_synthesis_payload_unwraps_json_string_and_fenced() -> None:
    from engine.fuzz_bridge import _parse_llm_synthesis_payload

    json_str = json.dumps({"status": "fused", "data": {"seeds": ["d"], "dictionary_tokens": ["t3"]}})
    assert _parse_llm_synthesis_payload(json_str) == {"seeds": ["d"], "dictionary_tokens": ["t3"]}

    nested_fenced = (
        "Here is the synthesis:\n```json\n"
        + json.dumps(
            {
                "status": "ok",
                "data": {
                    "status": "fused",
                    "data": {"harness_code": "fn main() {}", "seeds": ["s1"], "dictionary_tokens": ["k1"]},
                },
            }
        )
        + "\n```\n"
    )
    assert _parse_llm_synthesis_payload(nested_fenced) == {
        "harness_code": "fn main() {}",
        "seeds": ["s1"],
        "dictionary_tokens": ["k1"],
    }
