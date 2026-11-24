"""
Tests for `--hackerone` / `--hackone` Campaign Finder & HITL Computer-Use Report Porter.
"""

from __future__ import annotations

import json
from pathlib import Path
import time
import urllib.request

import pytest

from engine.hackerone_porter import (
    HackerOneApiClient,
    HackerOneCampaign,
    HackerOneComputerUsePorter,
    HackerOnePorter,
    build_hackerone_report_draft,
    filter_eligible_findings,
    validate_hackerone_handle,
    validate_hackerone_url,
)
from engine.mission_control_server import MissionControlOrchestrator, MissionControlServer
from rfc_hunt_swarm import parse_swarm_arguments


def test_hackerone_cli_flags_and_alias_parsed() -> None:
    args_full = parse_swarm_arguments(
        [
            "--hackerone",
            "--hackerone-program",
            "anthropic-vdp",
            "--hackerone-query",
            "anthropic",
            "--hackerone-browser",
            "--hackerone-api",
            "--hackerone-bounties-only",
            "--hackerone-min-severity",
            "high",
            "--hackerone-max-reports",
            "3",
        ]
    )
    assert args_full.enable_hackerone is True
    assert args_full.hackerone_program == "anthropic-vdp"
    assert args_full.hackerone_query == "anthropic"
    assert args_full.hackerone_browser is True
    assert args_full.hackerone_api is True
    assert args_full.hackerone_bounties_only is True
    assert args_full.hackerone_min_severity == "high"
    assert args_full.hackerone_max_reports == 3

    args_alias = parse_swarm_arguments(["--hackone", "--hackone-program", "github", "--hackone-browser"])
    assert args_alias.enable_hackerone is True
    assert args_alias.hackerone_program == "github"
    assert args_alias.hackerone_browser is True


def test_hackerone_handle_and_url_strict_pinning() -> None:
    assert validate_hackerone_handle("Anthropic-VDP") == "anthropic-vdp"
    with pytest.raises(ValueError):
        validate_hackerone_handle("../evil/path")
    with pytest.raises(ValueError):
        validate_hackerone_handle("bad handle with spaces")

    assert validate_hackerone_url("https://hackerone.com/anthropic-vdp/reports/new").startswith("https://hackerone.com/")
    assert validate_hackerone_url("https://api.hackerone.com/v1/hackers/programs").startswith("https://api.hackerone.com/")
    with pytest.raises(PermissionError):
        validate_hackerone_url("http://hackerone.com/anthropic-vdp")
    with pytest.raises(PermissionError):
        validate_hackerone_url("https://evil.example.com/hackerone.com")


def test_anti_slop_gate_rejects_speculative_lane3_and_duplicates_and_redacts_secrets(tmp_path: Path) -> None:
    sample_findings = [
        {
            "rule_id": "ARTEX-CHAIN-001",
            "title": "LEAD [POE=1]: Speculative multi-hop chain",
            "severity": "CRITICAL",
            "evidence_lane": "SPECULATIVE_HYPOTHESIS",
            "scanner": "Module-17-ARTEX",
            "file_path": "network-target",
            "line_number": 1,
            "poe_level": 1,
            "description": "Speculative correlation",
        },
        {
            "rule_id": "INV-REFINE-TLS-SNIFF-OPAQUE-BYPASS",
            "title": "TLS ClientHello sniffer rejects outer record version 0x0304",
            "severity": "HIGH",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "scanner": "VerificationInversionHunter",
            "cwe": "CWE-436",
            "file_path": "src/sandbox/tls-terminate-proxy.ts",
            "line_number": 100,
            "poe_level": 1,
            "evidence": "buf[2]! <= 0x03 with leaked token Bearer secret_token_1234567890",
            "counterexample_trace": [
                "1. Send ClientHello with 16 03 04",
                "2. looksLikeClientHello returns false",
                "3. Proxy falls back to opaque TCP tunnel",
            ],
            "violated_invariant_formula": "forall buf: (buf[0]==0x16 && buf[1]==0x03) => isTLS(buf)",
            "remediation": "Accept any 0x03XX outer legacy_record_version.",
        },
        {
            "rule_id": "LOW-INFO-001",
            "title": "Minor low issue",
            "severity": "LOW",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "scanner": "RAPTOR",
            "file_path": "src/foo.ts",
            "line_number": 5,
            "poe_level": 1,
            "evidence": "low signal",
        },
    ]

    porter = HackerOnePorter(output_dir=str(tmp_path / "h1"))
    res = porter.port_findings(
        sample_findings,
        program_handle="anthropic-vdp",
        min_severity="medium",
        max_reports=5,
    )
    assert res["anti_slop_gate_enforced"] is True
    assert res["final_submit_requires_hitl"] is True
    assert res["eligible_drafts_count"] == 1
    assert res["rejected_findings_count"] == 2
    rejected_reasons = {r["reason"] for r in res["rejected"]}
    assert "rejected_speculative_hypothesis_lane3" in rejected_reasons

    draft = res["drafts"][0]
    assert draft["program_handle"] == "anthropic-vdp"
    assert draft["submit_url"] == "https://hackerone.com/anthropic-vdp/reports/new"
    assert draft["weakness_cwe"] == "CWE-436"
    assert draft["severity_rating"] == "high"
    # Secret token must be redacted
    assert "secret_token_1234567890" not in draft["vulnerability_information"]
    assert "Bearer <REDACTED>" in draft["vulnerability_information"]
    assert Path(draft["markdown_path"]).is_file()
    assert Path(res["bundle_path"]).is_file()

    # Duplicate ledger protection: once submitted, re-running rejects duplicate
    d_obj = build_hackerone_report_draft(
        sample_findings[1],
        HackerOneCampaign(
            handle="anthropic-vdp",
            name="Anthropic VDP",
            url="https://hackerone.com/anthropic-vdp",
            submit_url="https://hackerone.com/anthropic-vdp/reports/new",
        ),
    )
    porter._save_ledger_record(d_obj, delivery_mode="manual_browser_hitl")
    res_dup = porter.port_findings(sample_findings, program_handle="anthropic-vdp", min_severity="medium")
    assert res_dup["eligible_drafts_count"] == 0
    assert any(r["reason"] == "duplicate_in_submission_ledger" for r in res_dup["rejected"])


def test_api_submission_fails_closed_without_hitl_approval_and_browser_fallback_is_safe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = HackerOneApiClient(username="researcher", api_token="tok_example_123")
    camp = HackerOneCampaign(
        handle="anthropic-vdp",
        name="Anthropic VDP",
        url="https://hackerone.com/anthropic-vdp",
        submit_url="https://hackerone.com/anthropic-vdp/reports/new",
    )
    draft = build_hackerone_report_draft(
        {
            "rule_id": "INV-REFINE-TLS-SNIFF-OPAQUE-BYPASS",
            "title": "TLS sniffer bypass",
            "severity": "HIGH",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "cwe": "CWE-436",
            "file_path": "src/sandbox/tls-terminate-proxy.ts",
            "line_number": 100,
            "evidence": "buf[2]! <= 0x03",
        },
        camp,
    )
    with pytest.raises(PermissionError):
        client.submit_report_api(draft, hitl_approved=False)

    # Browser porter gracefully falls back when playwright is unavailable and NEVER auto-submits
    monkeypatch.setattr(HackerOneComputerUsePorter, "_is_playwright_available", staticmethod(lambda: False))
    porter = HackerOnePorter(output_dir=str(tmp_path / "h1_browser"))
    res = porter.port_findings(
        [
            {
                "rule_id": "INV-REFINE-TLS-SNIFF-OPAQUE-BYPASS",
                "title": "TLS sniffer bypass",
                "severity": "HIGH",
                "evidence_lane": "DETERMINISTIC_STATIC",
                "cwe": "CWE-436",
                "file_path": "src/sandbox/tls-terminate-proxy.ts",
                "line_number": 100,
                "evidence": "buf[2]! <= 0x03",
            }
        ],
        program_handle="anthropic-vdp",
        use_browser=True,
    )
    assert res["browser_session"]["status"] == "playwright_not_installed_fallback_bundle_ready"
    assert res["browser_session"]["final_submit_blocked_for_hitl"] is True


def test_mission_control_hackerone_preview_endpoint(tmp_path: Path) -> None:
    def _runner(**kwargs):
        return {
            "verified_exploits": [],
            "deterministic_static_findings": [
                {
                    "rule_id": "INV-ALG-MISSING-SHELL-STARTUP-DENY",
                    "severity": "MEDIUM",
                    "evidence_lane": "DETERMINISTIC_STATIC",
                    "scanner": "VerificationInversionHunter",
                    "cwe": "CWE-732",
                    "file_path": "src/sandbox/sandbox-utils.ts",
                    "line_number": 21,
                    "title": "Missing .zshenv in DANGEROUS_FILES",
                    "evidence": "DANGEROUS_FILES = ['.zshrc', '.bashrc']",
                    "poe_level": 1,
                }
            ],
            "speculative_hypotheses": [
                {
                    "rule_id": "ARTEX-CHAIN-001",
                    "severity": "LOW",
                    "evidence_lane": "SPECULATIVE_HYPOTHESIS",
                    "scanner": "Module-17-ARTEX",
                    "file_path": "network-target",
                    "line_number": 1,
                    "title": "Speculative lead",
                    "poe_level": 1,
                }
            ],
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0},
            "speculative_severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 0},
            "merkle_audit": {"status": "no_live_differential_wire_findings", "total_leaves": 0},
            "defensive_intelligence": {"status": "skipped_no_verified_wire_exploits", "rules_published": 0},
            "report_files": {},
        }

    orch = MissionControlOrchestrator(reports_root=str(tmp_path / "mc"), db_path=str(tmp_path / "mc.db"), scan_runner=_runner)
    srv = MissionControlServer(host="127.0.0.1", port=0, orchestrator=orch)
    host, port = srv.start_background()
    base = f"http://{host}:{port}"
    tok_hdr = {"X-RFCHunt-Token": srv.session_token, "Content-Type": "application/json"}
    try:
        req = urllib.request.Request(
            f"{base}/api/tasks",
            data=json.dumps({"target": str(tmp_path), "mode": "repo_all"}).encode("utf-8"),
            headers=tok_hdr,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            tid = json.loads(resp.read().decode("utf-8"))["task"]["task_id"]
        for _ in range(40):
            with urllib.request.urlopen(f"{base}/api/tasks/{tid}", timeout=5.0) as r2:
                if json.loads(r2.read().decode("utf-8"))["task"]["status"] == "completed":
                    break
            time.sleep(0.05)

        h1_req = urllib.request.Request(
            f"{base}/api/hackerone/preview",
            data=json.dumps({"program_handle": "anthropic-vdp", "min_severity": "medium"}).encode("utf-8"),
            headers=tok_hdr,
            method="POST",
        )
        with urllib.request.urlopen(h1_req, timeout=5.0) as h1_resp:
            assert h1_resp.status == 200
            body = json.loads(h1_resp.read().decode("utf-8"))
            assert body["eligible_drafts_count"] == 1
            assert body["rejected_findings_count"] == 1
            assert body["drafts"][0]["source_rule_id"] == "INV-ALG-MISSING-SHELL-STARTUP-DENY"
    finally:
        srv.stop()
