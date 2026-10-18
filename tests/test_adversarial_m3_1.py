"""
Empirical Adversarial Challenge Test Suite for Module 16: Google Research Harness² Engine.
Challenger: Challenger M3-1 (Harness² Adversarial Fuzzing)
Working Directory: D:\\harfile\\rfchunt\\.agents\\teamwork\\challenger_m3_1

Verifies the 5 Dispatch Invariants:
1. Surface validation with empty c8 plugin (plugin/exploit.ts: ""), whitespace-only files, and ValueError.
2. Always-on empty component rejection across all combinations of c1..c4.
3. Frontmatter quote variations (nested quotes, single/double quotes, edge-case escaping).
4. normalize_rel with Windows device names (CON, PRN, AUX, NUL, COM1..9, LPT1..9), double percent-encoding, and base_dir containment.
5. Mathematical budget ledger identity (R=4k, P=3k) with corrupted rollouts/sessions confirming BudgetError.
"""

from pathlib import Path
import pytest

from engine.harness2_engine import (
    BudgetError,
    Entry,
    Harness2ProtocolEngine,
    Ledger,
    RFCHUNT_SURFACE,
    SurfaceSpec,
    _frontmatter_field,
    autotrigger,
    expected_rollouts,
    expected_sessions,
    is_allowed,
    normalize_rel,
    validate_tree,
)


# =====================================================================
# 1. Surface Validation: Empty c8 Plugin & Whitespace Files
# =====================================================================

def test_surface_validation_empty_and_whitespace_c8_plugin(tmp_path: Path):
    """Empirically asserts that empty or whitespace-only c8 plugin files raise ValueError."""
    engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")
    base = engine.build_base_harness()

    # 1. Empty string plugin/exploit.ts
    tree_empty = dict(base)
    tree_empty["plugin/exploit.ts"] = ""
    with pytest.raises(ValueError, match=r"plugin 'plugin/exploit\.ts' \(c8\) cannot be empty"):
        validate_tree(RFCHUNT_SURFACE, tree_empty)

    # 2. Whitespace-only permutations (spaces, tabs, newlines, carriage returns)
    for ws_payload in ("   ", "\t\t", "\r\n\r\n", " \t \r\n \t ", "\n"):
        tree_ws = dict(base)
        tree_ws["plugin/exploit.ts"] = ws_payload
        with pytest.raises(ValueError, match=r"plugin 'plugin/exploit\.ts' \(c8\) cannot be empty"):
            validate_tree(RFCHUNT_SURFACE, tree_ws)

    # 3. Multiple plugins: valid plugin alongside empty plugin
    tree_multi = dict(base)
    tree_multi["plugin/valid.ts"] = "export function filter(): boolean { return true; }"
    tree_multi["plugin/exploit.ts"] = ""
    with pytest.raises(ValueError, match=r"plugin 'plugin/exploit\.ts' \(c8\) cannot be empty"):
        validate_tree(RFCHUNT_SURFACE, tree_multi)

    # 4. Valid c8 plugin with code passes without raising
    tree_valid = dict(base)
    tree_valid["plugin/exploit.ts"] = "export function hook(p: string) { return p.length > 0; }"
    validate_tree(RFCHUNT_SURFACE, tree_valid)

    # 5. Off-surface plugin extension (.js instead of .ts) rejected
    tree_off_ext = dict(base)
    tree_off_ext["plugin/exploit.js"] = "module.exports = {};"
    with pytest.raises(ValueError, match=r"off-surface path rejected"):
        validate_tree(RFCHUNT_SURFACE, tree_off_ext)

    # 6. Off-surface nested plugin path rejected
    tree_nested = dict(base)
    tree_nested["plugin/sub/exploit.ts"] = "export const x = 1;"
    with pytest.raises(ValueError, match=r"off-surface path rejected"):
        validate_tree(RFCHUNT_SURFACE, tree_nested)


# =====================================================================
# 2. Always-On Empty Component Rejection (c1..c4)
# =====================================================================

def test_always_on_empty_component_rejection(tmp_path: Path):
    """Empirically asserts that any empty or whitespace-only always-on component raises ValueError."""
    engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")
    base = engine.build_base_harness()

    # 1. Completely empty tree raises ValueError
    with pytest.raises(ValueError, match=r"always-on harness components \(c1\.\.c4\) cannot be empty"):
        validate_tree(RFCHUNT_SURFACE, {})

    # 2. Tree with no always-on components at all raises ValueError
    no_always_on = {
        "scripts/helper.py": "def f(): pass\n",
        "plugin/guard.ts": "export const x = 1;",
    }
    with pytest.raises(ValueError, match=r"always-on harness components \(c1\.\.c4\) cannot be empty"):
        validate_tree(RFCHUNT_SURFACE, no_always_on)

    # 3. Individual always-on components set to empty string or whitespace
    always_on_files = [
        "systemprompt.md",
        "guardrails.md",
        "LongTermMEMORY.md",
        "tool_descriptions/tool_guidance.md",
    ]
    for target in always_on_files:
        # Empty string
        tree_target_empty = dict(base)
        tree_target_empty[target] = ""
        with pytest.raises(ValueError, match=r"always-on harness components \(c1\.\.c4\) cannot be empty"):
            validate_tree(RFCHUNT_SURFACE, tree_target_empty)

        # Whitespace-only string
        tree_target_ws = dict(base)
        tree_target_ws[target] = "   \r\n\t   "
        with pytest.raises(ValueError, match=r"always-on harness components \(c1\.\.c4\) cannot be empty"):
            validate_tree(RFCHUNT_SURFACE, tree_target_ws)

    # 4. Exceeding always-on character cap (24,000 chars) raises ValueError
    tree_oversized = dict(base)
    tree_oversized["systemprompt.md"] = "A" * 25_000
    with pytest.raises(ValueError, match=r"exceeds cap"):
        validate_tree(RFCHUNT_SURFACE, tree_oversized)


# =====================================================================
# 3. Frontmatter Quote Variations (Single, Double, Nested Quotes)
# =====================================================================

def test_frontmatter_quote_variations(tmp_path: Path):
    """Empirically tests frontmatter quote stripping, nested quotes, and quotation resilience."""
    engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")
    base = engine.build_base_harness()

    # 1. Direct unit verification of _frontmatter_field with various quote configurations
    test_cases = [
        ("name: simple_skill", "name", "simple_skill"),
        ("name: 'single_quoted'", "name", "single_quoted"),
        ('name: "double_quoted"', "name", "double_quoted"),
        ('name: "\'nested_quoted\'"', "name", "nested_quoted"),
        ('mode: "subagent"', "mode", "subagent"),
        ("mode: 'subagent'", "mode", "subagent"),
        ('description: "auditing \'RFC 9112\' and \'RFC 9110\' boundaries"', "description", "auditing 'RFC 9112' and 'RFC 9110' boundaries"),
        ("description: 'auditing \"RFC 9112\" and \"RFC 9110\" boundaries'", "description", 'auditing "RFC 9112" and "RFC 9110" boundaries'),
        ('name:   "spaced_value"   ', "name", "spaced_value"),
        ("name:   'spaced_single'   ", "name", "spaced_single"),
    ]
    for body, key, expected in test_cases:
        assert _frontmatter_field(body, key) == expected

    # 2. Skill with double quotes passes validate_tree
    tree_double = dict(base)
    tree_double["skills/quote_test_double/SKILL.md"] = (
        "---\n"
        'name: "quote_test_double"\n'
        'description: "specialist for RFC 9112 double-quoted parsing"\n'
        "---\n"
        "# Content\n"
    )
    validate_tree(RFCHUNT_SURFACE, tree_double)

    # 3. Skill with single quotes passes validate_tree
    tree_single = dict(base)
    tree_single["skills/quote_test_single/SKILL.md"] = (
        "---\n"
        "name: 'quote_test_single'\n"
        "description: 'specialist for RFC 9112 single-quoted parsing'\n"
        "---\n"
        "# Content\n"
    )
    validate_tree(RFCHUNT_SURFACE, tree_single)

    # 4. Skill with nested quotes in description passes validate_tree
    tree_nested = dict(base)
    tree_nested["skills/quote_test_nested/SKILL.md"] = (
        "---\n"
        'name: "quote_test_nested"\n'
        'description: "testing \'nested single quotes\' inside double quotes"\n'
        "---\n"
        "# Content\n"
    )
    validate_tree(RFCHUNT_SURFACE, tree_nested)

    # 5. Subagent with quoted mode passes validate_tree
    tree_subagent = dict(base)
    tree_subagent["sub_agents/quoted_agent/AGENT.md"] = (
        "---\n"
        'mode: "subagent"\n'
        'description: "quoted subagent mode test"\n'
        "---\n"
        "# Subagent\n"
    )
    validate_tree(RFCHUNT_SURFACE, tree_subagent)

    # 6. Mismatched skill name even if quoted must fail closed
    tree_mismatched = dict(base)
    tree_mismatched["skills/real_dir/SKILL.md"] = (
        "---\n"
        'name: "wrong_dir"\n'
        'description: "desc"\n'
        "---\n"
    )
    with pytest.raises(ValueError, match=r"must match directory"):
        validate_tree(RFCHUNT_SURFACE, tree_mismatched)


# =====================================================================
# 4. normalize_rel: Windows Device Names, Double Percent-Encoding, base_dir
# =====================================================================

def test_normalize_rel_adversarial_matrix(tmp_path: Path):
    """Empirically stress-tests normalize_rel against Windows devices, encoding escapes, and base_dir."""
    # 1. Exhaustive Windows reserved device names: CON, PRN, AUX, NUL, COM1..9, LPT1..9
    devices = [
        "con", "prn", "aux", "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    ]
    for dev in devices:
        # Bare stem
        with pytest.raises(ValueError, match=r"Windows reserved device name"):
            normalize_rel(f"scripts/{dev}.py")

        # Uppercase stem
        with pytest.raises(ValueError, match=r"Windows reserved device name"):
            normalize_rel(f"scripts/{dev.upper()}.py")

        # Mixed-case stem in skill directory
        with pytest.raises(ValueError, match=r"Windows reserved device name"):
            normalize_rel(f"skills/{dev.title()}/SKILL.md")

        # Multi-dot file stem
        with pytest.raises(ValueError, match=r"Windows reserved device name"):
            normalize_rel(f"scripts/{dev}.backup.py")

        # Plugin path
        with pytest.raises(ValueError, match=r"Windows reserved device name"):
            normalize_rel(f"plugin/{dev}.ts")

    # 2. Double percent-encoding attacks rejected by normalize_rel
    double_encoding_attacks = [
        "%252e%252e",
        "scripts/%252e%252e/escape.py",
        "scripts/%252e/same.py",
        "scripts/%255cwin_slash.py",
        "scripts/%252fslash.py",
        "scripts/%2500null.py",
        "scripts/%253acolon.py",
        "skills/%252e%252e/SKILL.md",
        "plugin/%252fexploit.ts",
    ]
    for attack in double_encoding_attacks:
        with pytest.raises(ValueError, match=r"path escapes the harness"):
            normalize_rel(attack)
        assert not is_allowed(RFCHUNT_SURFACE, attack)

    # 3. Triple percent-encoding (%25252e): rejected by is_allowed and validate_tree
    triple_attack = "scripts/%25252e%25252e.py"
    assert not is_allowed(RFCHUNT_SURFACE, triple_attack)
    engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")
    base = engine.build_base_harness()
    tree_triple = dict(base)
    tree_triple[triple_attack] = "x = 1\n"
    with pytest.raises(ValueError, match=r"off-surface path rejected"):
        validate_tree(RFCHUNT_SURFACE, tree_triple)

    # 4. Standard traversal and breakout attempts
    traversal_attacks = [
        "../escape.py",
        "scripts/../../escape.py",
        "/etc/shadow",
        "C:/Windows/System32/calc.exe",
        "D:\\Windows\\cmd.exe",
        "scripts/bad\x00byte.py",
        "",
        "   ",
        "///",
        "./",
    ]
    for attack in traversal_attacks:
        with pytest.raises(ValueError):
            normalize_rel(attack)

    # 4. base_dir containment validation
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    # Valid internal paths return resolved Path strictly inside base_dir
    valid_paths = [
        "scripts/helper.py",
        "systemprompt.md",
        "plugin/guard.ts",
        "skills/framing/SKILL.md",
    ]
    for vp in valid_paths:
        resolved = normalize_rel(vp, base_dir=sandbox)
        assert isinstance(resolved, Path)
        assert resolved == (sandbox / vp).resolve()
        assert resolved.is_relative_to(sandbox)

    # Path escape outside base_dir using path resolution
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    # Even if someone attempts to pass a path that escapes, normalize_rel blocks it
    with pytest.raises(ValueError):
        normalize_rel("../outside/escaped.py", base_dir=sandbox)


# =====================================================================
# 5. Mathematical Budget Ledger Identity (R=4k, P=3k)
# =====================================================================

def test_mathematical_budget_ledger_corrupted_rollouts_and_sessions():
    """Empirically proves that any deviation from R=4k and P=3k strictly raises BudgetError."""
    # Test across k = 1, 2, 3, 4
    for k in (1, 2, 3, 4):
        exp_r = expected_rollouts(k)
        exp_p = expected_sessions(k)
        assert exp_r == 4 * k
        assert exp_p == 3 * k

        # 1. Baseline valid ledger
        valid_ledger = Ledger(mode="agg", task_id=f"RFC_K{k}", k=k)
        for i in range(exp_r):
            valid_ledger.rollout(f"r_{i}")
        for j in range(exp_p):
            valid_ledger.session(f"s_{j}")
        assert valid_ledger.verify_budget() is True
        valid_dict = valid_ledger.to_dict()
        assert valid_dict["budget_verified"] is True
        assert valid_dict["actual_rollouts"] == exp_r
        assert valid_dict["actual_sessions"] == exp_p

        # 2. Deficit rollouts (exp_r - 1)
        ledger_def_r = Ledger(mode="agg", task_id=f"RFC_K{k}", k=k)
        for i in range(exp_r - 1):
            ledger_def_r.rollout(f"r_{i}")
        for j in range(exp_p):
            ledger_def_r.session(f"s_{j}")
        with pytest.raises(BudgetError, match=rf"expected R={exp_r} rollouts & P={exp_p} sessions, got R={exp_r - 1} & P={exp_p}"):
            ledger_def_r.assert_identity()
        assert ledger_def_r.to_dict()["budget_verified"] is False

        # 3. Excess rollouts (exp_r + 1)
        ledger_exc_r = Ledger(mode="agg", task_id=f"RFC_K{k}", k=k)
        for i in range(exp_r + 1):
            ledger_exc_r.rollout(f"r_{i}")
        for j in range(exp_p):
            ledger_exc_r.session(f"s_{j}")
        with pytest.raises(BudgetError, match=rf"expected R={exp_r} rollouts & P={exp_p} sessions, got R={exp_r + 1} & P={exp_p}"):
            ledger_exc_r.assert_identity()
        assert ledger_exc_r.to_dict()["budget_verified"] is False

        # 4. Deficit sessions (exp_p - 1)
        ledger_def_p = Ledger(mode="agg", task_id=f"RFC_K{k}", k=k)
        for i in range(exp_r):
            ledger_def_p.rollout(f"r_{i}")
        for j in range(exp_p - 1):
            ledger_def_p.session(f"s_{j}")
        with pytest.raises(BudgetError, match=rf"expected R={exp_r} rollouts & P={exp_p} sessions, got R={exp_r} & P={exp_p - 1}"):
            ledger_def_p.assert_identity()
        assert ledger_def_p.to_dict()["budget_verified"] is False

        # 5. Excess sessions (exp_p + 1)
        ledger_exc_p = Ledger(mode="agg", task_id=f"RFC_K{k}", k=k)
        for i in range(exp_r):
            ledger_exc_p.rollout(f"r_{i}")
        for j in range(exp_p + 1):
            ledger_exc_p.session(f"s_{j}")
        with pytest.raises(BudgetError, match=rf"expected R={exp_r} rollouts & P={exp_p} sessions, got R={exp_r} & P={exp_p + 1}"):
            ledger_exc_p.assert_identity()
        assert ledger_exc_p.to_dict()["budget_verified"] is False

        # 6. Both corrupted: deficit rollouts and excess sessions
        ledger_corrupt = Ledger(mode="agg", task_id=f"RFC_K{k}", k=k)
        for i in range(exp_r - 2):
            ledger_corrupt.rollout(f"r_{i}")
        for j in range(exp_p + 3):
            ledger_corrupt.session(f"s_{j}")
        with pytest.raises(BudgetError):
            ledger_corrupt.assert_identity()

        # 7. Zero rollouts and zero sessions
        ledger_empty = Ledger(mode="agg", task_id=f"RFC_K{k}", k=k)
        with pytest.raises(BudgetError):
            ledger_empty.assert_identity()

        # 8. Unrecognized entry kinds do not satisfy budget
        ledger_fake = Ledger(mode="agg", task_id=f"RFC_K{k}", k=k)
        for i in range(exp_r):
            ledger_fake.entries.append(Entry("unknown_kind", f"fake_r_{i}"))
        for j in range(exp_p):
            ledger_fake.entries.append(Entry("unknown_kind", f"fake_s_{j}"))
        with pytest.raises(BudgetError):
            ledger_fake.assert_identity()

    # 9. Verify BudgetError subclass invariant
    assert issubclass(BudgetError, AssertionError)


def test_engine_end_to_end_parallel_and_sequential_ledger_identity(tmp_path: Path):
    """Verifies that actual Harness2ProtocolEngine execution produces valid ledgers that fail if corrupted."""
    engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")

    # 1. Parallel execution with k=1
    res_par = engine.run_parallel("RFC9112_LEDGER_TEST", k=1, domain="http11_framing")
    assert res_par.ledger is not None
    assert res_par.ledger.rollouts_count == 4
    assert res_par.ledger.sessions_count == 3
    assert res_par.ledger.verify_budget() is True

    # Artificially corrupt the completed parallel ledger and assert BudgetError
    res_par.ledger.rollout("corrupt_extra_rollout")
    with pytest.raises(BudgetError, match=r"Harness² budget violation"):
        res_par.ledger.assert_identity()

    # 2. Sequential execution with k=1
    res_seq = engine.run_sequential("RFC9112_LEDGER_TEST_SEQ", k=1, domain="http11_framing")
    assert res_seq.ledger is not None
    assert res_seq.ledger.rollouts_count == 4
    assert res_seq.ledger.sessions_count == 3
    assert res_seq.ledger.verify_budget() is True

    # Artificially corrupt the completed sequential ledger and assert BudgetError
    res_seq.ledger.session("corrupt_extra_session")
    with pytest.raises(BudgetError, match=r"Harness² budget violation"):
        res_seq.ledger.assert_identity()



# =====================================================================
# 6. Surface Scripts & Subagent Boundary Validation
# =====================================================================

def test_surface_scripts_and_subagent_boundary_validation(tmp_path: Path):
    """Empirically tests Python script syntax checking, reserved scripts, and subagent frontmatter constraints."""
    engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")
    base = engine.build_base_harness()

    # 1. Invalid Python syntax in script raises ValueError with ast.parse details
    bad_syntax_script = dict(base)
    bad_syntax_script["scripts/broken_syntax.py"] = "def invalid_python(:\n    pass\n"
    with pytest.raises(ValueError, match=r"Python syntax error in harness script"):
        validate_tree(RFCHUNT_SURFACE, bad_syntax_script)

    # 2. Reserved scripts (read_doc.py, pack.py, unpack.py) cannot be overwritten
    for reserved in ("read_doc.py", "pack.py", "unpack.py"):
        bad_reserved = dict(base)
        bad_reserved[f"scripts/{reserved}"] = "print('tampering')\n"
        with pytest.raises(ValueError, match=r"is reserved and cannot be overwritten"):
            validate_tree(RFCHUNT_SURFACE, bad_reserved)

    # 3. Subagent with invalid mode raises ValueError
    bad_mode_subagent = dict(base)
    bad_mode_subagent["sub_agents/worker/AGENT.md"] = (
        "---\n"
        "mode: worker\n"
        "description: invalid mode subagent\n"
        "---\n"
    )
    with pytest.raises(ValueError, match=r"requires frontmatter `mode: subagent`"):
        validate_tree(RFCHUNT_SURFACE, bad_mode_subagent)

    # 4. Subagent without description raises ValueError
    no_desc_subagent = dict(base)
    no_desc_subagent["sub_agents/worker2/AGENT.md"] = (
        "---\n"
        "mode: subagent\n"
        "---\n"
    )
    with pytest.raises(ValueError, match=r"requires frontmatter `description:`"):
        validate_tree(RFCHUNT_SURFACE, no_desc_subagent)


# =====================================================================
# 7. Library Persistence, Experience Contract & Chronological Ordering
# =====================================================================

def test_library_persistence_and_experience_validation(tmp_path: Path):
    """Empirically asserts experience validation, INDEX.md update idempotence, and chronological entry ordering."""
    from engine.harness2_engine import Library, has_experience

    lib = Library(root=tmp_path / "lib_root", domain="http11_framing")
    engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")
    base = engine.build_base_harness()

    # 1. has_experience validator checks
    assert has_experience({"cue": "c", "lesson": "l", "evidence": "e"}) is True
    assert has_experience({"cue": "", "lesson": "l", "evidence": "e"}) is False
    assert has_experience({"cue": "c", "lesson": "   ", "evidence": "e"}) is False
    assert has_experience({"cue": "c", "lesson": "l"}) is False
    assert has_experience(None) is False

    # 2. record() raises ValueError when experience contract is violated
    with pytest.raises(ValueError, match=r"must include non-empty 'cue', 'lesson', and 'evidence'"):
        lib.record("TASK_BAD_EXP", base, {"cue": "", "lesson": "l", "evidence": "e"})

    # 3. Valid record() writes INDEX.md and EXPERIENCE.md
    edir = lib.record(
        "RFC9112_TEST",
        base,
        {"cue": "cue1", "lesson": "lesson1", "evidence": "ev1"},
        picked_label="agg1",
        contrast_score=15.0,
    )
    assert edir.is_dir()
    assert (edir / "EXPERIENCE.md").is_file()
    assert lib.index.is_file()
    idx_content = lib.index.read_text(encoding="utf-8")
    assert "| `RFC9112_TEST` | `agg1` | `15.00` | cue1 | lesson1 |" in idx_content

    # 4. Re-recording replaces row in INDEX.md idempotently (no duplicate row)
    lib.record(
        "RFC9112_TEST",
        base,
        {"cue": "cue1_updated", "lesson": "lesson1_updated", "evidence": "ev1_updated"},
        picked_label="agg2",
        contrast_score=30.0,
    )
    idx_updated = lib.index.read_text(encoding="utf-8")
    assert idx_updated.count("| `RFC9112_TEST` |") == 1
    assert "| `RFC9112_TEST` | `agg2` | `30.00` | cue1_updated | lesson1_updated |" in idx_updated
    assert "lesson1 |" not in idx_updated

    # 5. Chronological ordering in load_domain_lessons
    import time
    time.sleep(0.05)
    lib.record(
        "RFC7230_TEST",
        base,
        {"cue": "cue2", "lesson": "lesson2", "evidence": "ev2"},
        picked_label="agg1",
        contrast_score=20.0,
    )
    lessons = lib.load_domain_lessons()
    assert len(lessons) == 2
    assert lessons[0]["task"] == "RFC9112_TEST"
    assert lessons[1]["task"] == "RFC7230_TEST"
