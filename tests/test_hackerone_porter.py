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
    HackerOneAutonomousRunner,
    HackerOneCampaign,
    HackerOneComputerUsePorter,
    HackerOnePorter,
    build_hackerone_report_draft,
    check_hackerone_signal_exclusions,
    detect_cool_off_notice,
    filter_eligible_findings,
    is_safe_save_draft_button_label,
    parse_hackerone_program_policy,
    validate_hackerone_handle,
    validate_hackerone_url,
    validate_source_repo_url,
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

        # Verify Mission Control /api/phi/scan zero-leakage endpoint
        phi_req = urllib.request.Request(
            f"{base}/api/phi/scan",
            data=json.dumps({"text": "Patient John Doe SSN 123-45-6789 NPI 1234567893"}).encode("utf-8"),
            headers=tok_hdr,
            method="POST",
        )
        with urllib.request.urlopen(phi_req, timeout=5.0) as phi_resp:
            assert phi_resp.status == 200
            phi_body = json.loads(phi_resp.read().decode("utf-8"))
            assert phi_body["total_findings"] >= 2
            assert "123-45-6789" not in phi_body["scrubbed_preview"]
            assert phi_body["quarantine_proof"]["zero_leakage_verified"] is True
    finally:
        srv.stop()


def test_hackerone_roe_three_tier_policy_parser_and_safe_harbor() -> None:
    # Tier 1: Explicitly Prohibited (e.g. Agoda) -> blocks live scanning to preserve Safe Harbor
    agoda_rules = parse_hackerone_program_policy(
        "agoda",
        "Agoda explicitly prohibits performing automated security testing or scanning against production.",
        structured_scopes=[
            {"attributes": {"asset_identifier": "www.agoda.com", "asset_type": "URL", "eligible_for_submission": True}},
            {"attributes": {"asset_identifier": "oauth.thirdparty.com", "asset_type": "URL", "eligible_for_submission": False}},
        ],
        researcher_username="alice_h1",
    )
    assert agoda_rules.automation_tier == "explicitly_prohibited"
    assert agoda_rules.automated_scanning_prohibited is True
    assert agoda_rules.max_rps == 0.0
    assert agoda_rules.safe_harbor_status == "blocked_to_preserve_safe_harbor"
    assert agoda_rules.no_out_of_scope_redirects is True
    assert "oauth.thirdparty.com" in agoda_rules.out_of_scope_assets

    # Tier 2: Permitted with Rate Limits & Attribution Header + AI Disclosure
    policy_tier2 = (
        "Automated testing is allowed up to 5 requests per second. "
        "You must include header X-HackerOne: <username> on all traffic. "
        "Please disclose any use of AI or automated tools in your report. "
        "Open-source repo: https://github.com/example-org/example-proxy"
    )
    tier2_ok = parse_hackerone_program_policy(
        "example-bounty",
        policy_tier2,
        researcher_username="alice_h1",
    )
    assert tier2_ok.automation_tier == "permitted_with_limits_and_attribution"
    assert tier2_ok.automated_scanning_prohibited is False
    assert tier2_ok.max_rps == 5.0
    assert "X-HackerOne: alice_h1" in tier2_ok.required_headers
    assert tier2_ok.missing_attribution_username is False
    assert tier2_ok.ai_disclosure_required is True
    assert "https://github.com/example-org/example-proxy" in tier2_ok.in_scope_repos

    # Tier 2 fail-closed when required attribution username is missing
    tier2_missing = parse_hackerone_program_policy("example-bounty", policy_tier2, researcher_username="")
    assert tier2_missing.missing_attribution_username is True
    assert tier2_missing.safe_harbor_status == "missing_researcher_attribution_username"

    # Untrusted source repo host must fail closed
    with pytest.raises(PermissionError):
        validate_source_repo_url("http://evil.local/org/repo")


def test_hackerone_autonomous_runner_enforces_roe_redacts_phi_and_supports_dry_run(tmp_path: Path) -> None:
    repo = tmp_path / "in_scope_repo"
    repo.mkdir()
    (repo / "billing.py").write_text(
        'PATIENT_DATA = {"patient": "Eva Lin", "ssn": "623-45-6789", "npi": "1234567893"}\n',
        encoding="utf-8",
    )

    runner = HackerOneAutonomousRunner(output_dir=str(tmp_path / "h1_auto"))

    # 1. Dry-run verifies RoE parsing & Safe Harbor block with zero filesystem writes
    dry_res = runner.run_campaign_workflow(
        program_handle="agoda",
        local_repo_path=str(repo),
        policy_text_override="Do not use automated scanners. Disclose any use of AI tools.",
        researcher_username="alice_h1",
        enable_phi_scan=True,
        dry_run=True,
    )
    assert dry_res["dry_run"] is True
    assert dry_res["safe_harbor_roe_enforced"] is True
    roe_dry = dry_res["program_results"][0]["roe_compliance"]
    assert roe_dry["automated_scanning_prohibited"] is True
    assert roe_dry["live_scan_policy_decision"] == "BLOCKED_BY_ROE_EXPLICITLY_PROHIBITED_SAFE_HARBOR"
    assert not (tmp_path / "h1_auto" / "hackerone_autonomous_summary.json").exists()

    # 2. Live read-only local audit + --phi + draft export with zero PHI leakage + AI disclosure
    live_res = runner.run_campaign_workflow(
        program_handle="clinic-vdp",
        local_repo_path=str(repo),
        policy_text_override="Cap automated traffic at 2 requests per second with X-HackerOne: <username>. Disclose use of AI tools.",
        researcher_username="alice_h1",
        enable_phi_scan=True,
        min_severity="medium",
        dry_run=False,
    )
    assert live_res["status"] == "autonomous_workflow_completed"
    pr = live_res["program_results"][0]
    assert pr["roe_compliance"]["max_rps"] == 2.0
    assert "X-HackerOne: alice_h1" in pr["roe_compliance"]["required_headers"]
    port_r = pr["port_result"]
    assert port_r["eligible_drafts_count"] >= 1
    first_draft = port_r["drafts"][0]
    assert first_draft["ai_disclosure_included"] is True
    # Zero raw SSN/NPI leakage in HackerOne draft!
    assert "623-45-6789" not in first_draft["vulnerability_information"]
    assert "1234567893" not in first_draft["vulnerability_information"]
    assert Path(live_res["summary_path"]).is_file()


def test_cool_off_draft_only_lock_blocks_all_submissions_even_with_hitl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # CLI flags for cool-off / draft-only + site draft saving
    args = parse_swarm_arguments(
        [
            "--hackerone",
            "--hackerone-program",
            "example-bounty",
            "--hackerone-cool-off",
            "--hackerone-save-site-draft",
        ]
    )
    assert args.hackerone_cool_off is True
    assert args.hackerone_save_site_draft is True
    assert args.hackerone_signal_filter is True

    args_alias = parse_swarm_arguments(["--hackone", "--hackerone-draft-only", "--no-hackerone-signal-filter"])
    assert args_alias.hackerone_cool_off is True
    assert args_alias.hackerone_signal_filter is False

    finding = {
        "rule_id": "INV-AUTHZ-BYPASS-01",
        "title": "Tenant authorization bypass in policy evaluator",
        "severity": "HIGH",
        "evidence_lane": "DETERMINISTIC_STATIC",
        "epistemic_status": "PROVEN_STATIC_INVARIANT",
        "independent_oracles": ["ast_invariant", "z3_smt"],
        "scanner": "VerificationInversionHunter",
        "cwe": "CWE-863",
        "file_path": "src/auth/policy.py",
        "line_number": 42,
        "poe_level": 2,
        "evidence": "Z3 counterexample: role=viewer bypasses admin check",
    }

    camp = HackerOneCampaign(
        handle="example-bounty",
        name="Example Bounty",
        url="https://hackerone.com/example-bounty",
        submit_url="https://hackerone.com/example-bounty/reports/new",
    )
    draft = build_hackerone_report_draft(finding, camp, cool_off_mode=True)
    client = HackerOneApiClient(username="researcher", api_token="tok_example_123")

    # Even with hitl_approved=True, cool-off mode MUST fail closed
    with pytest.raises(PermissionError, match="cool-off"):
        client.submit_report_api(draft, hitl_approved=True, cool_off_mode=True)

    # Dry-run must report blocked_by_cool_off_draft_only_mode
    dry_api = client.submit_report_api(draft, hitl_approved=True, cool_off_mode=True, dry_run=True)
    assert dry_api["status"] == "blocked_by_cool_off_draft_only_mode"
    assert dry_api["submitted"] is False

    # Environment variable lock RFCHUNT_HACKERONE_COOL_OFF=1 also blocks submission unconditionally
    monkeypatch.setenv("RFCHUNT_HACKERONE_COOL_OFF", "1")
    draft_plain = build_hackerone_report_draft(finding, camp, cool_off_mode=False)
    with pytest.raises(PermissionError, match="cool-off"):
        client.submit_report_api(draft_plain, hitl_approved=True)

    porter = HackerOnePorter(output_dir=str(tmp_path / "h1_cooloff"))
    with pytest.raises(PermissionError, match="cool-off"):
        porter.port_findings([finding], program_handle="example-bounty", submit_api=True, hitl_approved=True)

    # Local draft save succeeds cleanly under cool-off and tags Markdown banner
    res = porter.port_findings([finding], program_handle="example-bounty", cool_off_mode=True)
    assert res["cool_off_mode"] is True
    assert res["draft_only_enforced"] is True
    assert res["local_drafts_saved"] == 1
    md_text = Path(res["drafts"][0]["markdown_path"]).read_text(encoding="utf-8")
    assert "DRAFT ONLY — COOL-OFF ACTIVE" in md_text
    assert "PROVEN_STATIC_INVARIANT" in md_text


def test_four_state_epistemic_gate_rejects_refuted_unresolved_and_llm_only() -> None:
    findings = [
        {
            "rule_id": "REFUTED-01",
            "title": "Sanitized SQL query",
            "severity": "CRITICAL",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "epistemic_status": "REFUTED",
            "scanner": "ClaimPreconditionVerifier",
            "file_path": "src/db/query.py",
            "line_number": 10,
            "evidence": "parameterized query",
        },
        {
            "rule_id": "UNRESOLVED-01",
            "title": "Unverified SSRF candidate",
            "severity": "HIGH",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "epistemic_status": "UNRESOLVED",
            "scanner": "RAPTOR",
            "file_path": "src/net/fetch.py",
            "line_number": 25,
            "evidence": "docker unavailable",
        },
        {
            "rule_id": "LLM-CONSENSUS-01",
            "title": "3-LLM unanimous RCE claim without independent oracle",
            "severity": "CRITICAL",
            "evidence_lane": "VERIFIED_EXPLOIT",
            "epistemic_status": "PROVEN_RUNTIME",  # spoofed label with only correlated LLM voters
            "scanner": "ModelFusion",
            "corroborated_by_models": ["gemma4", "qwen3", "llama3"],
            "file_path": "src/app.py",
            "line_number": 12,
            "poe_level": 3,
            "evidence": "All 3 LLMs agreed",
        },
        {
            "rule_id": "Z3-UNSAT-01",
            "title": "Disproved integer underflow",
            "severity": "HIGH",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "scanner": "VerificationInversionHunter",
            "z3_status": "unsat",
            "file_path": "src/math/bounds.py",
            "line_number": 55,
            "evidence": "unsat",
        },
        {
            "rule_id": "PROVEN-RT-01",
            "title": "Command injection verified in isolated container",
            "severity": "CRITICAL",
            "evidence_lane": "VERIFIED_EXPLOIT",
            "epistemic_status": "PROVEN_RUNTIME",
            "independent_oracles": ["runtime_poe_container", "claim_precondition_ast"],
            "scanner": "PoEContainerVerifier",
            "cwe": "CWE-78",
            "file_path": "src/exec/runner.py",
            "line_number": 88,
            "poe_level": 3,
            "runtime_poe_verified": True,
            "evidence": "Isolated container PoE marker RFCHUNT_POE_OK observed",
        },
    ]

    eligible, rejected = filter_eligible_findings(findings, program_handle="example-bounty", min_severity="medium")
    assert [f["rule_id"] for f in eligible] == ["PROVEN-RT-01"]
    assert eligible[0]["epistemic_status"] == "PROVEN_RUNTIME"

    reasons = {r["rule_id"]: r["reason"] for r in rejected}
    assert reasons["REFUTED-01"] == "rejected_epistemic_refuted"
    assert reasons["UNRESOLVED-01"] == "rejected_epistemic_unresolved"
    assert reasons["LLM-CONSENSUS-01"] == "rejected_epistemic_llm_only_no_independent_oracle"
    assert reasons["Z3-UNSAT-01"] == "rejected_epistemic_refuted"


def test_hackerone_signal_and_safe_harbor_exclusion_filter() -> None:
    policy = parse_hackerone_program_policy(
        "example-bounty",
        "Non-qualifying vulnerabilities: graphql introspection, swagger exposure, and missing CSP.",
    )
    assert "graphql introspection" in policy.excluded_vuln_classes

    findings = [
        {
            "rule_id": "HDR-01",
            "title": "Missing Content-Security-Policy security header",
            "severity": "MEDIUM",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "scanner": "Semgrep",
            "file_path": "src/http/middleware.py",
            "line_number": 14,
            "evidence": "No CSP header configured",
        },
        {
            "rule_id": "DOS-01",
            "title": "Regular Expression DoS (ReDoS) in email parser",
            "severity": "HIGH",
            "evidence_lane": "VERIFIED_EXPLOIT",
            "epistemic_status": "PROVEN_RUNTIME",
            "independent_oracles": ["runtime_poe_container"],
            "scanner": "PoEContainerVerifier",
            "file_path": "src/util/email.py",
            "line_number": 30,
            "poe_level": 3,
            "runtime_poe_verified": True,
            "evidence": "Backtracking latency spike",
        },
        {
            "rule_id": "TEST-FIX-01",
            "title": "Hardcoded SQL string in unit test fixture",
            "severity": "HIGH",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "scanner": "Semgrep",
            "file_path": "tests/fixtures/mock_db.py",
            "line_number": 9,
            "evidence": "SELECT * FROM users WHERE id=" + "'1'",
        },
        {
            "rule_id": "GQL-01",
            "title": "GraphQL introspection enabled on public endpoint",
            "severity": "MEDIUM",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "scanner": "Semgrep",
            "file_path": "src/api/schema.py",
            "line_number": 11,
            "evidence": "introspection=True",
        },
        {
            "rule_id": "OR-CHAIN-01",
            "title": "Open redirect chained to OAuth token theft",
            "severity": "HIGH",
            "evidence_lane": "VERIFIED_EXPLOIT",
            "epistemic_status": "PROVEN_RUNTIME",
            "independent_oracles": ["runtime_poe_container"],
            "scanner": "PoEContainerVerifier",
            "file_path": "src/oauth/callback.py",
            "line_number": 77,
            "poe_level": 3,
            "runtime_poe_verified": True,
            "evidence": "OAuth access_token leaked to attacker redirect_uri in 3/3 trials",
        },
    ]

    eligible, rejected = filter_eligible_findings(
        findings,
        program_handle="example-bounty",
        policy_rules=policy,
        min_severity="medium",
    )
    # Only the PROVEN_RUNTIME chained exploit passes; DoS is blocked EVEN at PoE=3!
    assert [f["rule_id"] for f in eligible] == ["OR-CHAIN-01"]
    reasons = {r["rule_id"]: r["reason"] for r in rejected}
    assert reasons["HDR-01"] == "rejected_h1_non_qualifying_missing_security_headers"
    assert reasons["DOS-01"] == "rejected_h1_safe_harbor_excluded_dos_ddos_resource_exhaustion"
    assert reasons["TEST-FIX-01"] == "rejected_h1_non_qualifying_test_or_fixture_path"
    assert reasons["GQL-01"].startswith("rejected_h1_program_policy_excluded_graphql_introspection")


def test_site_draft_button_guard_cool_off_banner_detection_and_dry_run_plan(tmp_path: Path) -> None:
    # Strict button label validation: ONLY explicit Save Draft, NEVER Submit
    assert is_safe_save_draft_button_label("Save draft") is True
    assert is_safe_save_draft_button_label("Save as draft") is True
    assert is_safe_save_draft_button_label("Submit report") is False
    assert is_safe_save_draft_button_label("Save draft and submit") is False
    assert is_safe_save_draft_button_label("Publish") is False
    assert is_safe_save_draft_button_label("") is False

    # Cool-off banner detector
    assert detect_cool_off_notice("You are currently in a cool-off period until Dec 5.") is not None
    assert detect_cool_off_notice("Submission limit reached for this program.") is not None
    assert detect_cool_off_notice("Welcome to HackerOne report form.") is None

    # Dual local + on-site draft dry-run plan guarantees submission_hard_blocked
    porter = HackerOnePorter(output_dir=str(tmp_path / "h1_site_draft"))
    finding = {
        "rule_id": "INV-PATH-TRAVERSAL-01",
        "title": "Path traversal in artifact extractor",
        "severity": "HIGH",
        "evidence_lane": "DETERMINISTIC_STATIC",
        "epistemic_status": "PROVEN_STATIC_INVARIANT",
        "independent_oracles": ["claim_precondition_ast"],
        "scanner": "ClaimPreconditionVerifier",
        "cwe": "CWE-22",
        "file_path": "src/archive/extract.py",
        "line_number": 31,
        "evidence": "os.path.join(base_dir, member.name) without realpath prefix check",
    }
    res = porter.port_findings(
        [finding],
        program_handle="example-bounty",
        cool_off_mode=True,
        save_draft_on_site=True,
        dry_run=True,
    )
    assert res["cool_off_mode"] is True
    assert res["save_draft_on_site"] is True
    assert res["browser_session"]["site_draft_action"] == "fill_and_save_draft_only_never_submit"
    assert res["browser_session"]["submission_hard_blocked"] is True
    assert res["browser_session"]["final_submit_blocked_for_hitl"] is True


def test_site_draft_mocked_playwright_saves_both_locally_and_on_site_never_submits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verifies local Markdown+JSON save AND clicking ONLY 'Save draft' (never 'Submit report')."""
    clicked_buttons: list[str] = []
    filled_values: dict[str, str] = {}

    class _FakeLocator:
        def __init__(self, selector: str, page_mode: str = "normal") -> None:
            self.selector = selector
            self.page_mode = page_mode

        @property
        def first(self) -> "_FakeLocator":
            return self

        def count(self) -> int:
            if self.page_mode == "cool_off_blocked":
                return 1 if self.selector == "body" else 0
            if self.selector in (
                "body",
                'input[name*="title"]',
                'textarea[name*="vulnerability_information"]',
                'textarea[name*="impact"]',
                'button:has-text("Save draft")',
            ):
                return 1
            return 0

        def inner_text(self) -> str:
            if self.selector == "body":
                if self.page_mode == "cool_off_blocked":
                    return "You are currently in a cool-off period and cannot submit new reports right now."
                return "Submit a vulnerability report — You may Save draft while in cool-off period."
            if "Save draft" in self.selector:
                return "Save draft"
            return ""

        def get_attribute(self, name: str) -> str:
            return ""

        def fill(self, value: str) -> None:
            filled_values[self.selector] = value

        def click(self) -> None:
            clicked_buttons.append(self.inner_text())

    class _FakePage:
        def __init__(self, mode: str) -> None:
            self.mode = mode
            self.urls: list[str] = []

        def goto(self, url: str, **kwargs) -> None:
            self.urls.append(url)

        def wait_for_timeout(self, ms: int) -> None:
            pass

        def locator(self, selector: str) -> _FakeLocator:
            return _FakeLocator(selector, page_mode=self.mode)

    class _FakeContext:
        def __init__(self, mode: str) -> None:
            self.page = _FakePage(mode)

        def new_page(self) -> _FakePage:
            return self.page

        def close(self) -> None:
            pass

    class _FakeBrowser:
        def __init__(self, mode: str) -> None:
            self.mode = mode

        def new_context(self) -> _FakeContext:
            return _FakeContext(self.mode)

        def close(self) -> None:
            pass

    class _FakePlaywrightCM:
        def __init__(self, mode: str) -> None:
            self.mode = mode

        def __enter__(self):
            class _P:
                def __init__(inner_self) -> None:
                    class _Chromium:
                        def launch(c_self, headless: bool = False):
                            assert headless is False  # Always visible HITL window
                            return _FakeBrowser(self.mode)

                    inner_self.chromium = _Chromium()

            return _P()

        def __exit__(self, exc_type, exc, tb):
            return False

    import sys
    import types

    def _install_fake_playwright(mode: str) -> None:
        fake_sync_api = types.ModuleType("playwright.sync_api")
        fake_sync_api.sync_playwright = lambda: _FakePlaywrightCM(mode)  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("playwright")
        fake_pkg.sync_api = fake_sync_api  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "playwright", fake_pkg)
        monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync_api)
        monkeypatch.setattr(HackerOneComputerUsePorter, "_is_playwright_available", staticmethod(lambda: True))

    finding = {
        "rule_id": "INV-SSRF-01",
        "title": "SSRF metadata bypass in webhook fetcher",
        "severity": "HIGH",
        "evidence_lane": "DETERMINISTIC_STATIC",
        "epistemic_status": "PROVEN_STATIC_INVARIANT",
        "independent_oracles": ["claim_precondition_ast"],
        "scanner": "ClaimPreconditionVerifier",
        "cwe": "CWE-918",
        "file_path": "src/webhooks/fetch.py",
        "line_number": 44,
        "evidence": "requests.get(user_url) with no RFC1918/metadata block",
    }

    # Case 1: Normal /reports/new form with Save draft button -> saves locally AND clicks Save draft (never Submit)
    _install_fake_playwright("normal")
    porter = HackerOnePorter(output_dir=str(tmp_path / "h1_both"))
    res = porter.port_findings(
        [finding],
        program_handle="example-bounty",
        cool_off_mode=True,
        save_draft_on_site=True,
        wait_for_human_fn=lambda prompt: "",
    )
    assert res["local_drafts_saved"] == 1
    assert res["site_drafts_saved"] == 1
    assert Path(res["drafts"][0]["markdown_path"]).is_file()
    assert Path(res["bundle_path"]).is_file()
    assert clicked_buttons == ["Save draft"]
    assert res["browser_session"]["status"] == "hitl_browser_site_drafts_saved"
    assert res["browser_session"]["filled_drafts"][0]["auto_submitted"] is False
    assert res["browser_session"]["filled_drafts"][0]["site_draft_saved"] is True
    assert res["browser_session"]["submission_hard_blocked"] is True

    # Case 2: Site blocks /reports/new completely during cool-off -> preserves local draft cleanly, zero clicks
    clicked_buttons.clear()
    _install_fake_playwright("cool_off_blocked")
    porter2 = HackerOnePorter(output_dir=str(tmp_path / "h1_blocked"))
    res2 = porter2.port_findings(
        [finding],
        program_handle="example-bounty",
        cool_off_mode=True,
        save_draft_on_site=True,
        wait_for_human_fn=lambda prompt: "",
    )
    assert res2["local_drafts_saved"] == 1
    assert res2["site_drafts_saved"] == 0
    assert Path(res2["drafts"][0]["markdown_path"]).is_file()
    assert clicked_buttons == []
    assert res2["browser_session"]["status"] == "hitl_browser_blocked_by_cool_off_local_preserved"
    assert res2["browser_session"]["filled_drafts"][0]["site_draft_status"] == (
        "blocked_by_site_cool_off_banner_local_draft_preserved"
    )

