"""
Zero-Mock Tests for `scripts/autonomous_hunt.py` (Standalone Headless Hunting Runner).
Verifies safety violation checks, ProgramEligibilityDB gating, repo-slug validation,
dry-run planning, and real end-to-end single-cycle embedded execution with zero mocks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.hackerone_porter import (
    HackerOneCampaign,
    HackerOneComputerUsePorter,
    HackerOneReportDraft,
)
from engine.program_eligibility_db import ProgramEligibilityDB
import hunt as root_hunt
from scripts.autonomous_hunt import (
    build_parser,
    check_program_eligibility,
    execute_hunt_cycle,
    extract_verified_findings_from_cycle,
    main as hunt_main,
    open_urls_in_chrome,
    scan_draft_safety_violations,
    validate_repo_slug,
)


def test_safety_violation_scanner_catches_secrets_entities_and_control_chars() -> None:
    clean_draft = "# Valid Draft\n\nConfirmed CWE-22 at `src/store.ts:48` (`len < 64`).\n"
    assert scan_draft_safety_violations(clean_draft) == []

    # Synthetic fake token format + HTML entity leak + BEL control char
    dirty_draft = (
        "Title: `test` with &lt; comparison\n"
        "Leaked: AKIAIOSFODNN7EXAMPLE\n"
        "Control: bad\x07char\n"
    )
    violations = scan_draft_safety_violations(dirty_draft)
    codes = {v["code"] for v in violations}
    assert "SECRET_LEAK:aws_access_key" in codes
    assert "HTML_ENTITY_CORRUPTION" in codes
    assert "CONTROL_CHAR_OR_MOJIBAKE" in codes


def test_repo_slug_validation_blocks_traversal_and_shell_chars() -> None:
    assert validate_repo_slug("Shopify/shopify-app-js") == "Shopify/shopify-app-js"
    for bad in ("../etc/passwd", "owner/repo;rm -rf /", "owner/repo$(id)", "just_one_part"):
        with pytest.raises(ValueError):
            validate_repo_slug(bad)


def test_program_eligibility_gate_blocks_signal_locked_and_allows_unlocked(tmp_path: Path) -> None:
    db_path = tmp_path / "elig.sqlite3"
    db = ProgramEligibilityDB(db_path=db_path)
    db.upsert(
        "locked_prog",
        "BLOCKED_SIGNAL",
        signal_required=1.0,
        submit_url="https://hackerone.com/locked_prog/reports/new",
    )
    db.upsert(
        "open_prog",
        "UNLOCKED",
        signal_required=0.0,
        submit_url="https://hackerone.com/open_prog/reports/new",
    )

    ok_locked, reason_locked = check_program_eligibility("locked_prog", eligibility_db_path=str(db_path))
    assert not ok_locked
    assert "BLOCKED_SIGNAL" in reason_locked

    ok_open, reason_open = check_program_eligibility("open_prog", eligibility_db_path=str(db_path))
    assert ok_open
    assert reason_open == "unlocked"


def test_autonomous_hunt_dry_run_and_embedded_cycle(tmp_path: Path) -> None:
    repo_dir = tmp_path / "sample_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    out_dir = tmp_path / "hunt_out"
    parser = build_parser()
    dry_args = parser.parse_args(
        [
            "--target",
            str(repo_dir),
            "--program",
            "generic",
            "--out",
            str(out_dir),
            "--dry-run",
            "--skip-freshness",
            "--skip-lean",
        ]
    )
    dry_summary = execute_hunt_cycle(dry_args, 1)
    assert dry_summary["dry_run"] is True
    assert dry_summary["browser_used"] is False
    assert dry_summary["auto_submit_forbidden"] is True
    assert not out_dir.exists()

    # Real headless embedded cycle on the temporary workspace (zero mocks, zero network)
    rc = hunt_main(
        [
            "--target",
            str(repo_dir),
            "--program",
            "generic",
            "--out",
            str(out_dir),
            "--embedded",
            "--no-llm",
            "--no-external-scanners",
            "--skip-freshness",
            "--skip-lean",
            "--skip-qa-drafts",
            "--skip-check-drafts",
        ]
    )
    assert rc == 0
    latest_json = out_dir / "latest_summary.json"
    latest_md = out_dir / "latest_summary.md"
    ready_md = out_dir / "READY_TO_CLICK_SUBMIT.md"
    assert latest_json.is_file()
    assert latest_md.is_file()
    assert ready_md.is_file()
    parsed = json.loads(latest_json.read_text(encoding="utf-8"))
    assert parsed["browser_used"] is False
    assert parsed["anti_junk_guard_enabled"] is True
    assert parsed["safety_violations_count"] == 0
    assert len(parsed["targets_audited"]) == 1


def test_extract_verified_findings_filters_noise_and_stage_draft_blocks_submit(tmp_path: Path) -> None:
    report_path = tmp_path / "fast_ooda_report.json"
    report_path.write_text(
        json.dumps(
            {
                "clusters": [
                    {
                        "title": "Unverified speculative alert",
                        "file_path": "src/a.py",
                        "line": 10,
                        "disposition": "SPECULATIVE",
                        "poc_verified": False,
                    },
                    {
                        "title": "Verified symlink escape",
                        "file_path": "src/store.ts",
                        "line": 48,
                        "cwe": "CWE-59",
                        "severity": "HIGH",
                        "disposition": "CONFIRMED",
                        "poc_verified": True,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    verified = extract_verified_findings_from_cycle(tmp_path)
    assert len(verified) == 1
    assert verified[0]["file_path"] == "src/store.ts"
    assert verified[0]["evidence_lane"] == "LANE_1_POC"

    camp = HackerOneCampaign(
        handle="common_codes",
        name="Common Codes",
        url="https://hackerone.com/common_codes",
        submit_url="https://hackerone.com/common_codes/reports/new",
    )
    draft = HackerOneReportDraft(
        draft_id="H1-COMMON-1234",
        fingerprint="1234abcd",
        program_handle="common_codes",
        submit_url="https://hackerone.com/common_codes/reports/new",
        title="Verified symlink escape",
        weakness_cwe="CWE-59",
        severity_rating="high",
        asset_identifier="github.com/common-codes/app",
        evidence_lane="LANE_1_POC",
        poe_level=3,
        vulnerability_information="Reproducible PoC",
        impact="Arbitrary write",
        source_rule_id="PARITY-SYMLINK",
        source_scanner="parity_auditor",
        scope_match_status="in_scope",
    )
    res = HackerOneComputerUsePorter().stage_draft_ready_to_submit(camp, draft, dry_run=True)
    assert res["status"] == "dry_run_draft_stage_planned"
    assert res["auto_submit_forbidden"] is True
    assert res["captcha_bypass_forbidden"] is True
    assert res["final_submit_blocked_for_hitl"] is True
    assert res["auto_submitted"] is False

    # Chrome launcher validates strictly pinned https://hackerone.com/... URLs and rejects external domains
    chrome_plan = open_urls_in_chrome(
        ["https://hackerone.com/reports/4244042", "https://hackerone.com/reports/4244042"],
        dry_run=True,
    )
    assert chrome_plan["status"] == "dry_run_chrome_planned"
    assert chrome_plan["opened_urls"] == ["https://hackerone.com/reports/4244042"]
    with pytest.raises((ValueError, PermissionError)):
        open_urls_in_chrome(["https://evil.example.com/phish"], dry_run=True)


def test_python_hunt_entrypoint_builds_full_turnkey_argv(tmp_path: Path) -> None:
    ns_default = root_hunt.build_parser().parse_args([])
    argv_default = root_hunt.build_hunt_argv(ns_default)
    assert "--start-modelfusion" in argv_default
    assert "--clone-unlocked" in argv_default
    assert "--from-eligibility-db" in argv_default
    assert "--stage-drafts" in argv_default
    assert "--open-chrome" in argv_default
    assert "--watch" in argv_default

    ns_once = root_hunt.build_parser().parse_args(["--target", "repo_x", "--program", "common_codes", "--once", "--dry-run"])
    argv_once = root_hunt.build_hunt_argv(ns_once)
    assert "--target" in argv_once
    assert "common_codes" in argv_once
    assert "--watch" not in argv_once
    assert "--dry-run" in argv_once
    assert "--open-chrome" in argv_once

    # Bare `python hunt.py --dry-run` MUST NOT enter infinite --watch loop and MUST execute cleanly with 0 side effects
    ns_dry = root_hunt.build_parser().parse_args(["--dry-run"])
    argv_dry = root_hunt.build_hunt_argv(ns_dry)
    assert "--dry-run" in argv_dry
    assert "--watch" not in argv_dry
    dry_out = tmp_path / "hunt_dry_test"
    rc = root_hunt.main(["--dry-run", "--sync-public-directory", "--out", str(dry_out), "--json"])
    assert rc == 0
    assert not dry_out.exists()
