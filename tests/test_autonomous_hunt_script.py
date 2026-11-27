"""
Zero-Mock Tests for `scripts/autonomous_hunt.py` (Standalone Headless Hunting Runner).
Verifies safety violation checks, ProgramEligibilityDB gating, repo-slug validation,
dry-run planning, and real end-to-end single-cycle embedded execution with zero mocks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.program_eligibility_db import ProgramEligibilityDB
from scripts.autonomous_hunt import (
    build_parser,
    check_program_eligibility,
    execute_hunt_cycle,
    main as hunt_main,
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
    assert latest_json.is_file()
    assert latest_md.is_file()
    parsed = json.loads(latest_json.read_text(encoding="utf-8"))
    assert parsed["browser_used"] is False
    assert parsed["anti_junk_guard_enabled"] is True
    assert parsed["safety_violations_count"] == 0
    assert len(parsed["targets_audited"]) == 1
