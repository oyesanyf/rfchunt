"""
Unit tests for ClientAuditPackager and BugBountyMCPServer.
"""

import json
from pathlib import Path

from bugbounty_mcp_server import BugBountyMCPServer
from engine.client_audit_packager import ClientAuditPackager


def test_client_audit_packager_emits_all_5_artifacts_with_redaction_and_escaping(tmp_path: Path):
    packager = ClientAuditPackager()
    findings = [
        {
            "finding_id": "01",
            "title": "=CMD|' /C calc'!A0 <script>alert(1)</script> Auth Bypass",
            "severity": "HIGH",
            "weakness_cwe": "CWE-287",
            "affected_files": ["src/auth/verify.rs:42"],
            "summary": "Leaked Bearer supersecrettoken12345 in error log.",
            "impact": "Allows unauthorized admin API access.",
            "remediation": "Enforce strict iss/dest verification.",
            "poc_verified": True,
            "poc_transcript": "PASS: reproduced with Bearer secret99999999",
            "headers": {"Authorization": "Bearer live_token_abc123", "Host": "api.example.com"},
        }
    ]
    bundle = packager.package(
        client_name="Acme Fintech",
        scope_description="Core API & Wasm Runtime",
        findings=findings,
        out_dir=tmp_path / "audit_out",
    )

    assert bundle.executive_summary_md.is_file()
    assert bundle.technical_findings_md.is_file()
    assert bundle.findings_tracker_csv.is_file()
    assert bundle.findings_sarif.is_file()
    assert bundle.dashboard_html.is_file()

    tech_md = bundle.technical_findings_md.read_text(encoding="utf-8")
    assert "supersecrettoken12345" not in tech_md
    assert "live_token_abc123" not in tech_md
    assert "Bearer <REDACTED>" in tech_md

    csv_text = bundle.findings_tracker_csv.read_text(encoding="utf-8")
    assert "'=CMD" in csv_text

    html_text = bundle.dashboard_html.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text

    sarif = json.loads(bundle.findings_sarif.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1


def test_bugbounty_mcp_server_initialize_list_and_tools(tmp_path: Path):
    srv = BugBountyMCPServer()

    init_resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init_resp["result"]["serverInfo"]["name"] == "rfchunt-bugbounty-mcp"

    list_resp = srv.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tool_names = {t["name"] for t in list_resp["result"]["tools"]}
    assert {
        "bb_freshness_watch",
        "bb_run_linux_poc",
        "bb_package_client_audit",
        "bb_stage_hackerone_draft",
        "bb_browser_handoff_spec",
    }.issubset(tool_names)

    # Quality gate blocks unverified PoC by default
    blocked_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "bb_stage_hackerone_draft",
                "arguments": {
                    "program_handle": "shopify",
                    "asset": "https://github.com/Shopify/*",
                    "weakness_cwe": "CWE-200",
                    "severity_rating": "Medium",
                    "title": "Sample Verified Title",
                    "vulnerability_information": "x" * 150,
                    "impact": "Concrete impact",
                    "poc_verified": False,
                    "out_path": str(tmp_path / "draft_blocked.json"),
                },
            },
        }
    )
    blocked_data = json.loads(blocked_resp["result"]["content"][0]["text"])
    assert blocked_data["status"] == "blocked_quality_gate"
    assert any("poc_verified" in msg for msg in blocked_data["quality_gate_issues"])

    # Browser handoff spec returns structured HITL steps
    handoff_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "bb_browser_handoff_spec",
                "arguments": {
                    "platform": "hackerone",
                    "program_handle": "shopify",
                    "action": "stage_draft",
                    "staged_draft_path": str(tmp_path / "draft_blocked.json"),
                },
            },
        }
    )
    handoff_data = json.loads(handoff_resp["result"]["content"][0]["text"])
    assert handoff_data["platform"] == "hackerone"
    assert "hackerone.com/shopify" in handoff_data["target_url"]
    assert len(handoff_data["browser_steps"]) >= 3


def test_revenue_cli_package_audit_dispatch(tmp_path: Path):
    from revenue_cli import maybe_dispatch_revenue_cli

    findings_file = tmp_path / "findings.json"
    findings_file.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": "01",
                        "title": "Sample Wasm Memory Bug",
                        "severity": "MEDIUM",
                        "weakness_cwe": "CWE-770",
                        "affected_files": ["src/io.rs:123"],
                        "impact": "4 GiB host heap allocation",
                        "poc_verified": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    out_dir = tmp_path / "cli_out"
    rc = maybe_dispatch_revenue_cli(
        [
            "package-audit",
            "--client",
            "Demo Corp",
            "--findings-json",
            str(findings_file),
            "--out",
            str(out_dir),
        ]
    )
    assert rc == 0
    assert (out_dir / "01_EXECUTIVE_SUMMARY.md").is_file()
    assert (out_dir / "04_FINDINGS.sarif").is_file()
    assert maybe_dispatch_revenue_cli(["--all", "."]) is None
