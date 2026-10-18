"""
Unit and Integration Tests for Module 16: Google Research Harness² Engine
(Recursive Agent Harnessing for an Open World, arXiv:2610.14224, Google LLC 2026).
"""

import shutil
from pathlib import Path
import pytest

from database import Database
from engine.harness2_engine import (
    BudgetError,
    Harness2ProtocolEngine,
    Ledger,
    Library,
    RFCHUNT_SURFACE,
    autotrigger,
    diff_summary,
    diversity,
    expected_rollouts,
    expected_sessions,
    is_allowed,
    merge_tree_proposal,
    normalize_rel,
    read_tree,
    skill_names,
    subagent_names,
    validate_tree,
    write_tree,
)
from rfc_hunt_swarm import main_swarm, parse_swarm_arguments


def test_c1_c8_surface_and_path_escape_guard(tmp_path: Path):
    """Verifies c1..c8 surface validation, path escape rejection, and skill autotriggering."""
    # 1. Path traversal & injection rejection
    for bad_path in (
        "../secret.txt",
        "/etc/passwd",
        "C:\\Windows\\System32\\cmd.exe",
        "skills/%2e%2e/SKILL.md",
        "scripts/foo%2fbar.py",
        "scripts/bad\x00.py",
    ):
        with pytest.raises(ValueError):
            normalize_rel(bad_path)
        assert not is_allowed(RFCHUNT_SURFACE, bad_path)

    # 2. Allowed c1..c8 components
    assert is_allowed(RFCHUNT_SURFACE, "systemprompt.md")
    assert is_allowed(RFCHUNT_SURFACE, "guardrails.md")
    assert is_allowed(RFCHUNT_SURFACE, "LongTermMEMORY.md")
    assert is_allowed(RFCHUNT_SURFACE, "tool_descriptions/tool_guidance.md")
    assert is_allowed(RFCHUNT_SURFACE, "skills/chunk_framing/SKILL.md")
    assert is_allowed(RFCHUNT_SURFACE, "sub_agents/rfc_parser/AGENT.md")
    assert is_allowed(RFCHUNT_SURFACE, "scripts/frame_calc.py")
    assert is_allowed(RFCHUNT_SURFACE, "plugin/strict_crlf.ts")
    assert not is_allowed(RFCHUNT_SURFACE, "random_off_surface.txt")

    # 3. Autotrigger injects missing skill trigger into guardrails.md
    engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")
    base = engine.build_base_harness("http11_framing")
    delta = {
        "skills/h2_downgrade/SKILL.md": (
            "---\n"
            "name: h2_downgrade\n"
            "description: auditing HTTP/2 to HTTP/1.1 gateway translation\n"
            "---\n"
            "# H2 Downgrade Skill\n"
        )
    }
    merged = merge_tree_proposal(RFCHUNT_SURFACE, base, delta)
    assert "h2_downgrade" in skill_names(RFCHUNT_SURFACE, merged)
    assert "load the `h2_downgrade` skill" in merged["guardrails.md"]
    validate_tree(RFCHUNT_SURFACE, merged)

    # 4. Write & read back tree (excluding README stubs)
    dest = write_tree(RFCHUNT_SURFACE, merged, tmp_path / "staged_tree", stubs=True)
    assert (dest / "scripts" / "README.md").is_file()
    roundtrip = read_tree(RFCHUNT_SURFACE, dest)
    assert roundtrip == merged


def test_tree_validation_rejects_invalid_scripts_and_frontmatter(tmp_path: Path):
    """Verifies that invalid Python syntax, reserved scripts, or mismatched skill frontmatter fail closed."""
    engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")
    base = engine.build_base_harness()

    # Mismatched skill name
    bad_skill = dict(base)
    bad_skill["skills/my_skill/SKILL.md"] = "---\nname: wrong_name\ndescription: desc\n---\n"
    with pytest.raises(ValueError, match="must match directory"):
        validate_tree(RFCHUNT_SURFACE, bad_skill)

    # Reserved script overwrite
    bad_reserved = dict(base)
    bad_reserved["scripts/read_doc.py"] = "print('overwrite')\n"
    with pytest.raises(ValueError, match="reserved"):
        validate_tree(RFCHUNT_SURFACE, bad_reserved)

    # Invalid Python AST in c7 script
    bad_syntax = dict(base)
    bad_syntax["scripts/broken_helper.py"] = "def broken(:\n    pass\n"
    with pytest.raises(ValueError, match="syntax error"):
        validate_tree(RFCHUNT_SURFACE, bad_syntax)


def test_ledger_budget_identity_enforcement():
    """Verifies R = 4k rollouts and P = 3k improvement stages budget identity."""
    k = 2
    assert expected_rollouts(k) == 8
    assert expected_sessions(k) == 6

    ledger = Ledger(mode="agg", task_id="RFC9112", k=k)
    for i in range(7):
        ledger.rollout(f"r{i}")
    for i in range(6):
        ledger.session(f"s{i}")

    # Missing 1 rollout -> must raise BudgetError
    with pytest.raises(BudgetError):
        ledger.assert_identity()

    ledger.rollout("r7")
    ledger.assert_identity()
    assert ledger.to_dict()["budget_verified"] is True


def test_parallel_and_sequential_recursion_and_library(tmp_path: Path):
    """Verifies parallel ('agg') and sequential ('seq') Propose-Probe-Compose and Library persistence."""
    runs_dir = tmp_path / "harness2_runs"
    db_file = tmp_path / "test_h2.db"
    db = Database(str(db_file))
    engine = Harness2ProtocolEngine(
        runs_root=runs_dir,
        target_host="127.0.0.1",
        target_port=8080,
        db_path=str(db_file),
    )

    # 1. Parallel mode with k=2 (R=8 rollouts, P=6 sessions)
    res_agg = engine.run_mode("parallel", "RFC9112", k=2, domain="http11_framing", run_tag="exp1")
    assert res_agg.ok
    assert res_agg.mode == "agg"
    assert res_agg.ledger is not None
    assert res_agg.ledger.rollouts_count == 8
    assert res_agg.ledger.sessions_count == 6
    assert res_agg.adopted_label in ("agg1", "agg2")
    assert len(res_agg.finals) == 2

    # Check domain library files on disk
    lib = Library(root=runs_dir / "exp1" / "agg", domain="http11_framing")
    assert lib.exists()
    assert "RFC9112" in lib.entries()
    assert (lib.entry_dir("RFC9112") / "EXPERIENCE.md").is_file()
    lessons = lib.load_domain_lessons()
    assert len(lessons) == 1
    assert "RFC9112" in lessons[0]["cue"]

    # 2. Sequential mode with k=2 (R=8 rollouts, P=6 sessions) on second task in same domain
    res_seq = engine.run_mode("sequential", "RFC7230", k=2, domain="http11_framing", run_tag="exp1")
    assert res_seq.ok
    assert res_seq.mode == "seq"
    assert res_seq.ledger is not None
    assert res_seq.ledger.rollouts_count == 8
    assert res_seq.ledger.sessions_count == 6
    assert res_seq.adopted_label in ("c1", "c2")

    # 3. Persist to SQLite and verify retrieval
    row_id = db.save_harness2_run(res_agg.to_dict())
    assert row_id > 0
    saved_runs = db.get_harness2_runs()
    assert len(saved_runs) == 1
    assert saved_runs[0]["task_id"] == "RFC9112"
    assert saved_runs[0]["rollouts_count"] == 8
    assert saved_runs[0]["sessions_count"] == 6


def test_cli_harness2_execution(tmp_path: Path, capsys):
    """Verifies CLI parsing and execution of `rfc_hunt_swarm.py harness2` and `--harness2-report`."""
    db_file = str(tmp_path / "cli_h2.db")
    runs_dir = str(tmp_path / "cli_runs")

    args = parse_swarm_arguments([
        "harness2",
        "--rfc", "9112",
        "--harness2-k", "1",
        "--harness2-mode", "parallel",
        "--harness2-runs-dir", runs_dir,
        "--db", db_file,
    ])
    assert args.command == "harness2"
    assert args.harness2_k == 1
    assert args.harness2_mode == "parallel"

    main_swarm([
        "harness2",
        "--rfc", "9112",
        "--harness2-k", "1",
        "--harness2-mode", "parallel",
        "--harness2-runs-dir", runs_dir,
        "--db", db_file,
    ])
    out = capsys.readouterr().out
    assert "GOOGLE RESEARCH HARNESS²" in out
    assert "Rollouts (R = 4k) : 4/4" in out
    assert "Stages (P = 3k) : 3/3" in out

    # Now run --harness2-report
    main_swarm([
        "harness2",
        "--harness2-report",
        "--db", db_file,
    ])
    report_out = capsys.readouterr().out
    assert "HISTORICAL HARNESS² RECURSION RUNS" in report_out
    assert "RFC9112" in report_out
