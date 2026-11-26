#!/usr/bin/env python3
"""
tests/test_arxiv_security_bridge.py
End-to-end tests for ArxivSecurityBridge (5 AI Security + 5 App Code Security
research-to-code detectors, multi-article D:\\harfile\\arixiv-to-code conversion,
--reseach-num / --research-num CLI flag, and MCP Agent Tools).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import sys
import pytest

from engine.arxiv_security_bridge import BUILTIN_RESEARCH_DETECTORS, ArxivSecurityBridge
from mcp_server import TerminatorMCPServer
from rfc_hunt_swarm import parse_swarm_arguments


def test_builtin_10_research_detectors_all_have_code_and_github_repos() -> None:
    assert len(BUILTIN_RESEARCH_DETECTORS) == 10
    ai_specs = [d for d in BUILTIN_RESEARCH_DETECTORS if d.domain == "AI_SECURITY"]
    app_specs = [d for d in BUILTIN_RESEARCH_DETECTORS if d.domain == "APP_CODE_SECURITY"]
    assert len(ai_specs) == 5
    assert len(app_specs) == 5
    for spec in BUILTIN_RESEARCH_DETECTORS:
        assert spec.has_code_repo is True
        assert spec.code_repo_url.startswith("https://github.com/")


def test_multi_article_discover_and_convert_research_with_research_num(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    if os.name == "nt" or sys.platform == "win32":
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        monkeypatch.setattr(platform, "machine", lambda: "AMD64")
    bridge = ArxivSecurityBridge(detectors_dir=tmp_path / "detectors", research_num=3)
    res = bridge.discover_and_convert_research(
        query="",
        domain="both",
        research_num=3,
        require_code_repo=True,
        evolve=False,
        auto_repair=False,
        output_dir=tmp_path / "detectors",
    )
    assert res["status"] == "completed"
    assert res["research_num_per_domain"] == 3
    assert res["total_converted_articles"] == 6  # 3 AI Security + 3 App Code Security
    for art in res["converted_articles"]:
        assert art["has_code_repo"] is True
        assert art["code_repo_url"].startswith("https://github.com/")
        assert art["verification_verdict"] == "PASS"
        mod_file = Path(art["synthesized_module_path"])
        assert mod_file.exists()
        src = mod_file.read_text(encoding="utf-8")
        assert "# EVOLVE-BLOCK-START" in src


def test_all_10_arxiv_detectors_catch_seeded_ai_and_appsec_flaws(tmp_path: Path) -> None:
    # Seed 5 AI Security flaws
    ai_file = tmp_path / "agent_service.py"
    ai_file.write_text(
        """
def delegate_worker(task):
    invoke_subagent("worker", permissions=["*"], enable_all_tools=True)

def build_rag_prompt(retrieved_chunks):
    msg = {"role": "system", "content": f"You are an assistant: {retrieved_chunks}"}
    return msg

def guard_input(long_text):
    sanitize_prompt(long_text[:1024])

def dispatch_tool(agent_thought, tool_call):
    if verify_safety(agent_thought):
        return tool_call()

def verify_guardrail(x):
    try:
        return run_check(x)
    except Exception:
        return True
""",
        encoding="utf-8",
    )

    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        "services:\n  agent:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )

    # Seed 5 Application Code Security flaws
    app_py = tmp_path / "web_controller.py"
    app_py.write_text(
        """
@app.get("/api/orders/{id}")
def get_order_admin(id: str):
    require_role("admin")
    return db.get(id)

@app.delete("/api/orders/{id}")
def delete_order_bola(id: str):
    return db.delete(id)

def run_diag(request):
    raw_cmd = request.args.get("cmd")
    subprocess.run(raw_cmd, shell=True)

def proxy_downgrade(header_name, header_val):
    allow_h2_transfer_encoding = True
    return f"{header_name}: {header_val}"
""",
        encoding="utf-8",
    )

    rust_file = tmp_path / "unsafe_buffer.rs"
    rust_file.write_text(
        """
struct RawHandle {
    ptr: *mut u8,
}
unsafe impl Send for RawHandle {}

pub unsafe fn fill_vec(count: usize, elem_size: usize) {
    let mut v: Vec<u8> = Vec::with_capacity(count * elem_size);
    v.set_len(count);
    let _x = may_fail().unwrap();
}
""",
        encoding="utf-8",
    )

    bridge = ArxivSecurityBridge(detectors_dir=tmp_path / "det_reg")
    report = bridge.scan_repository(tmp_path, domain="both")
    assert report["status"] == "completed"
    rules_hit = set(report["findings_by_rule"].keys())
    expected_10 = {
        "ARXIV-AI-01-BOUNDED-AGENTS-APC",
        "ARXIV-AI-02-SANDBOX-ESCAPE-BENCH",
        "ARXIV-AI-03-ADAPTIVE-IPI-AGENT",
        "ARXIV-AI-04-PISANITIZER-LONGCTX",
        "ARXIV-AI-05-GUARDREASONER-DRIFT",
        "ARXIV-APPSEC-01-IRIS-TAINT",
        "ARXIV-APPSEC-02-ACFIX-RBAC-BOLA",
        "ARXIV-APPSEC-03-RUDRA-UNSAFE-RUST",
        "ARXIV-APPSEC-04-LLMSAN-DATAFLOW",
        "ARXIV-APPSEC-05-H2-PROXY-DESYNC",
    }
    assert expected_10.issubset(rules_hit), f"Missing rules: {expected_10 - rules_hit}"


def test_cli_reseach_num_flag_and_mcp_tools(tmp_path: Path) -> None:
    args1 = parse_swarm_arguments(["--all", "--reseach-num", "4"])
    assert args1.research_num == 4
    args2 = parse_swarm_arguments(["--all", "--research-num", "7"])
    assert args2.research_num == 7

    db_file = tmp_path / "mcp_arxiv.db"
    with TerminatorMCPServer(db_path=str(db_file)) as srv:
        tools_resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
        assert "arxiv_discover_and_convert_security_research" in tool_names
        assert "run_arxiv_ai_security_detectors" in tool_names
        assert "run_arxiv_appsec_code_detectors" in tool_names
        assert "run_all_arxiv_research_detectors" in tool_names
        assert "list_active_arxiv_research_detectors" in tool_names

        cat_resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "list_active_arxiv_research_detectors", "arguments": {"domain": "all"}},
            }
        )
        cat_data = json.loads(cat_resp["result"]["content"][0]["text"])
        assert cat_data["total_detectors"] >= 10
        det_ids = {d["detector_id"] for d in cat_data.get("detectors", [])}
        assert "ARXIV-AI-01-BOUNDED-AGENTS-APC" in det_ids
