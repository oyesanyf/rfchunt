"""
Zero-Mock Tests for SQLite Program Eligibility & Signal-Requirement Registry.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.program_eligibility_db import ProgramEligibilityDB  # noqa: E402


def test_seed_baseline_and_fail_closed_eligibility(tmp_path: Path):
    db_file = tmp_path / "eligibility.sqlite3"
    db = ProgramEligibilityDB(db_file)
    base_time = datetime(2026, 11, 26, 16, 35, 0, tzinfo=timezone.utc)
    counts = db.seed_observed_hackerone_baseline(now=base_time)

    assert counts["UNLOCKED"] >= 12
    assert counts["BLOCKED_SIGNAL"] >= 160
    assert counts["PAUSED"] >= 12
    assert counts["NOT_FOUND"] >= 40

    assert db.is_eligible("anthropic") is True
    assert db.is_eligible("amazonvrp") is True
    assert db.is_eligible("temu") is True
    assert db.is_eligible("common_codes") is True
    assert db.is_eligible("henkel_vdp") is True
    assert db.is_eligible("oppo_bbp") is True

    # Signal-blocked, paused, not-found, and unknown programs fail closed
    assert db.is_eligible("shopify") is False
    assert db.is_eligible("vercel") is False
    assert db.is_eligible("cloudflare") is False
    assert db.is_eligible("mozilla") is False
    assert db.is_eligible("django") is False
    assert db.is_eligible("openai") is False
    assert db.is_eligible("never_seen_program") is False

    unlocked = db.list_unlocked()
    assert unlocked[0].handle == "amazonvrp"
    assert unlocked[0].bounty_max_usd == 30000
    assert unlocked[1].handle == "temu"


def test_periodic_recheck_detects_when_signal_violation_lifted(tmp_path: Path):
    db_file = tmp_path / "recheck.sqlite3"
    db = ProgramEligibilityDB(db_file)
    t0 = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
    db.upsert("shopify", "BLOCKED_SIGNAL", signal_required=1.0, recheck_hours=24, now=t0)

    # Not due immediately or 12h later
    assert db.list_due_for_recheck(now=t0 + timedelta(hours=12)) == []

    # Due after 25h
    due = db.list_due_for_recheck(now=t0 + timedelta(hours=25))
    assert [r.handle for r in due] == ["shopify"]

    # Once lifted, upsert UNLOCKED makes it eligible immediately
    db.upsert("shopify", "UNLOCKED", bounty_max_usd=50000, now=t0 + timedelta(hours=25))
    assert db.is_eligible("shopify") is True
    assert db.list_due_for_recheck(now=t0 + timedelta(hours=25)) == []
