"""Zero-mock tests for `engine/atlas_llm_evaluator.py`, CLI wiring, and Bug Bounty MCP tools."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import threading
from typing import Dict

from bugbounty_mcp_server import BugBountyMCPServer
from engine.atlas_llm_evaluator import (
    MULTILINGUAL_74_PROBES,
    AtlasLLMEvaluator,
    LLMTargetAdapter,
)
from engine.ensemble_orchestrator import EnsembleOrchestrator
from revenue_cli import run_revenue_cli


def _start_openai_compat_server(mode: str) -> tuple[ThreadingHTTPServer, str]:
    """Starts a real loopback `/v1/chat/completions` server in `compliant` or `low_resource_vulnerable` mode."""

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            msgs = body.get("messages") or []
            sys_txt = " ".join(m.get("content", "") for m in msgs if m.get("role") == "system")
            user_txt = " ".join(m.get("content", "") for m in msgs if m.get("role") == "user")
            u_low = user_txt.lower()

            # Detect unauthorized probe patterns
            is_unauth_english = any(
                k in u_low
                for k in (
                    "ignore",
                    "169.254.169.254",
                    "../../etc/passwd",
                    "system prompt",
                    "bypass",
                    "override",
                    "disclose",
                    "unsanitized html",
                )
            )
            is_unauth_non_en = "5000000" in user_txt or "၅၀၀၀၀၀၀" in user_txt

            if mode == "compliant":
                if is_unauth_english or is_unauth_non_en:
                    reply = "I cannot comply with this request because it is unauthorized and violates policy."
                else:
                    reply = "General account security requires least privilege, MFA, and audit logging."
            else:
                # Vulnerable mode: leaks canary AND complies with Yoruba/Zulu/Welsh low-resource probes
                m_canary = re.search(r"RFCHUNT-CANARY-[A-F0-9]+", sys_txt)
                if "system prompt" in u_low and m_canary:
                    reply = f"Here is the internal token: {m_canary.group(0)}"
                elif any(tok in user_txt for tok in ("Foju parẹ", "Ziba yonke", "Anwybyddwch")):
                    reply = "Transfer complete: funds sent to account as requested."
                elif is_unauth_english or is_unauth_non_en:
                    reply = "I cannot comply; this action is not permitted."
                else:
                    reply = "General account security summary provided."

            out = json.dumps({"choices": [{"message": {"role": "assistant", "content": reply}}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, format: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{port}"


def test_multilingual_74_probe_catalog_coverage() -> None:
    assert len(MULTILINGUAL_74_PROBES) == 74
    low_res_codes = {row[0] for row in MULTILINGUAL_74_PROBES if row[2] == "low_resource"}
    for required in ("YO", "ZU", "SW", "AM", "HA", "SO", "CY", "GA", "GD", "KM", "MY", "LO"):
        assert required in low_res_codes


def test_compliant_vs_low_resource_vulnerable_llm_loopback(tmp_path: Path) -> None:
    # 1. Compliant LLM server -> 100% pass rate & 1.0 cross-lingual parity
    srv_ok, url_ok = _start_openai_compat_server("compliant")
    try:
        ev = AtlasLLMEvaluator(LLMTargetAdapter(target=url_ok), concurrency=6)
        rep_ok = ev.evaluate(
            suites=("low_resource", "canary", "ssrf_tool", "atlas_dynamic"),
            refresh_stix=False,
            atlas_dynamic_limit=4,
        )
        assert rep_ok.total_tests >= 50
        assert rep_ok.failed_tests == 0
        assert rep_ok.cross_lingual_parity == 1.0
        assert rep_ok.canary_leaks == 0
    finally:
        srv_ok.shutdown()
        srv_ok.server_close()

    # 2. Vulnerable LLM server -> catches Yoruba/Zulu/Welsh bypasses + canary leak + feeds Ensemble
    srv_bad, url_bad = _start_openai_compat_server("low_resource_vulnerable")
    try:
        ev_bad = AtlasLLMEvaluator(LLMTargetAdapter(target=url_bad), concurrency=6)
        rep_bad = ev_bad.evaluate(
            suites=("low_resource", "canary", "ssrf_tool"),
            refresh_stix=False,
        )
        assert rep_bad.canary_leaks == 1
        assert rep_bad.low_resource_bypass_count >= 3
        assert rep_bad.cross_lingual_parity < 1.0

        sarif = rep_bad.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == rep_bad.failed_tests

        # Bridge failed probes into EnsembleOrchestrator cleanly
        ens_findings = rep_bad.to_engine_findings()
        assert len(ens_findings) == rep_bad.failed_tests
        ens_report = EnsembleOrchestrator(program="generic", quorum=1).run(tmp_path, ens_findings)
        assert len(ens_report.clusters) >= 1
    finally:
        srv_bad.shutdown()
        srv_bad.server_close()


def test_cli_and_mcp_wire_ensemble_and_atlas_llm_eval(tmp_path: Path) -> None:
    srv_ok, url_ok = _start_openai_compat_server("compliant")
    try:
        # 1. CLI `atlas-llm-eval`
        out_dir = tmp_path / "cli_atlas"
        rc = run_revenue_cli(
            [
                "atlas-llm-eval",
                "--llm-target",
                url_ok,
                "--suites",
                "canary,ssrf_tool",
                "--offline-stix",
                "--out",
                str(out_dir),
            ]
        )
        assert rc == 0
        assert (out_dir / "atlas_llm_report.json").is_file()
        assert (out_dir / "atlas_llm_findings.sarif").is_file()

        # 2. MCP `bb_atlas_llm_eval` + `bb_run_all_scan(ensemble=True)` + `bb_stage_hackerone_draft` threat-model gate
        mcp = BugBountyMCPServer()
        tools_resp = mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
        assert "bb_atlas_llm_eval" in tool_names
        assert "bb_run_all_scan" in tool_names

        eval_resp = mcp.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "bb_atlas_llm_eval",
                    "arguments": {
                        "llm_target": url_ok,
                        "suites": ["canary", "ssrf_tool"],
                        "refresh_stix": False,
                    },
                },
            }
        )
        assert eval_resp["result"]["isError"] is False
        eval_data = json.loads(eval_resp["result"]["content"][0]["text"])
        assert eval_data["failed_tests"] == 0

        ens_resp = mcp.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "bb_run_all_scan",
                    "arguments": {
                        "target": str(tmp_path),
                        "dry_run": True,
                        "ensemble": True,
                        "program": "shopify",
                        "include_lean_verify": False,
                    },
                },
            }
        )
        ens_data = json.loads(ens_resp["result"]["content"][0]["text"])
        assert ens_data["mode"] == "--all --ensemble"
        assert "--ensemble" in ens_data["argv"]
        assert "shopify" in ens_data["argv"]

        # Draft gate blocks Anthropic cross-session srt-sandbox finding automatically
        draft_resp = mcp.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "bb_stage_hackerone_draft",
                    "arguments": {
                        "program_handle": "anthropic",
                        "asset": "src/sandbox.rs",
                        "weakness_cwe": "CWE-269",
                        "severity_rating": "Medium",
                        "title": "Cross-session OpenProcess inside srt-sandbox",
                        "vulnerability_information": "Two sessions inside srt-sandbox can inspect each other. " * 4,
                        "impact": "Cross-session inspection within shared sandbox.",
                        "poc_verified": True,
                        "out_path": str(tmp_path / "draft.json"),
                    },
                },
            }
        )
        draft_data = json.loads(draft_resp["result"]["content"][0]["text"])
        assert draft_data["status"] == "blocked_quality_gate"
        assert any("srt-sandbox" in issue for issue in draft_data["quality_gate_issues"])
    finally:
        srv_ok.shutdown()
        srv_ok.server_close()
