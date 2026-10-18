# Handoff Report: Challenger M3-1 (Harness² Adversarial Fuzzing)

- **Agent**: Challenger M3-1
- **Role**: Empirical Challenger / Critic / Specialist
- **Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\challenger_m3_1`
- **Parent / Caller ID**: `48cb9587-3e1b-40a9-9a84-e3452d5f5108`
- **Date**: 2026-10-18T20:41:00Z
- **Verdict**: **`APPROVE`**

---

## Challenge Summary

**Overall risk assessment**: **LOW**

Challenger M3-1 subjected Module 16 Harness² (`engine/harness2_engine.py`) and Milestone 3 deliverables to an exhaustive adversarial fuzzing and empirical stress-testing suite across all five challenge vectors:
1. **Surface validation**: Empty `c8` plugins (`plugin/exploit.ts`: `""`) and whitespace-only files strictly raise `ValueError("plugin 'plugin/exploit.ts' (c8) cannot be empty")`.
2. **Always-on components**: Empty or whitespace-only files across any of `c1..c4` (`systemprompt.md`, `guardrails.md`, `LongTermMEMORY.md`, `tool_descriptions/tool_guidance.md`) strictly raise `ValueError("always-on harness components (c1..c4) cannot be empty")`.
3. **Frontmatter quote variations**: Double, single, and nested quotation marks are parsed cleanly without corruption, preserving nested strings and enforcing directory name matching.
4. **Path traversal & Windows devices**: All Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`), double percent-encoding (`%252e%252e`, `%255c`, `%252f`, `%2500`, `%253a`), and `base_dir` containment strictly fail closed.
5. **Mathematical budget ledger identity**: $R = 4k$ rollouts and $P = 3k$ sessions are strictly enforced; any deficit, excess, corruption, or unrecognized entry kind strictly raises `BudgetError` across $k \in \{1, 2, 3, 4\}$.

All findings and invariant proofs are embodied in the newly created empirical test suite `tests/test_adversarial_m3_1.py` (8 test suites, 100% passing).

---

## 1. Observation

Direct code-level and empirical execution observations:

1. **Empty `c8` Plugin & Whitespace Handling (`engine/harness2_engine.py:322-325`)**:
   ```python
   elif "plugin" in r and r["plugin"].fullmatch(norm):
       if not body.strip():
           raise ValueError(f"plugin {norm!r} (c8) cannot be empty")
   ```
   - When fuzzed with `tree["plugin/exploit.ts"] = ""`:
     Verbatim error: `ValueError: plugin 'plugin/exploit.ts' (c8) cannot be empty`.
   - When fuzzed with whitespace-only variations (`"   "`, `"\t\t"`, `"\r\n\r\n"`, `" \t \r\n \t "`):
     Verbatim error: `ValueError: plugin 'plugin/exploit.ts' (c8) cannot be empty`.
   - When a valid plugin is paired with an empty plugin, validation fails closed on the empty component.
   - Off-surface plugin attempts (`plugin/exploit.js`, `plugin/sub/exploit.ts`) are rejected at line 283: `ValueError: off-surface path rejected: 'plugin/exploit.js'`.
   - Empirically verified in `tests/test_adversarial_m3_1.py::test_surface_validation_empty_and_whitespace_c8_plugin`.

2. **Always-On Empty Component Rejection (`engine/harness2_engine.py:285-289`)**:
   ```python
   if surface.reject_empty_always_on:
       if not any(a in tree for a in surface.always_on) or not all(
           tree.get(a, "").strip() for a in surface.always_on if a in tree
       ):
           raise ValueError("always-on harness components (c1..c4) cannot be empty")
   ```
   - When fuzzed with `{}` (empty tree):
     Verbatim error: `ValueError: always-on harness components (c1..c4) cannot be empty`.
   - When fuzzed with a tree containing zero always-on components (e.g. only scripts or plugins):
     Verbatim error: `ValueError: always-on harness components (c1..c4) cannot be empty`.
   - When any individual always-on file (`systemprompt.md`, `guardrails.md`, `LongTermMEMORY.md`, `tool_descriptions/tool_guidance.md`) is set to `""` or `"   \r\n\t   "`:
     Verbatim error: `ValueError: always-on harness components (c1..c4) cannot be empty`.
   - When always-on text exceeds `always_on_max` (24,000 characters):
     Verbatim error: `ValueError: always-on text length (25000) exceeds cap (24000): every token here competes with the agent's own wire synthesis budget`.
   - Empirically verified in `tests/test_adversarial_m3_1.py::test_always_on_empty_component_rejection`.

3. **Frontmatter Quotation & Escaping (`engine/harness2_engine.py:244-246`)**:
   ```python
   def _frontmatter_field(body: str, key: str) -> str:
       m = re.search(rf"^{re.escape(key)}:\s*(.+)$", body[:800], re.M)
       return m.group(1).strip().strip("'\"") if m else ""
   ```
   - Double quotes: `name: "my_skill"` -> resolves to `"my_skill"`.
   - Single quotes: `name: 'my_skill'` -> resolves to `"my_skill"`.
   - Nested quotes: `description: "specialist for 'RFC 9112' framing"` -> resolves to `"specialist for 'RFC 9112' framing"`.
   - Nested reverse quotes: `description: 'specialist for "RFC 9112" framing'` -> resolves to `'specialist for "RFC 9112" framing'`.
   - Subagent mode: `mode: "subagent"` and `mode: 'subagent'` both satisfy `fm_mode == "subagent"`.
   - Mismatched skill directory: `name: "wrong_name"` in `skills/real_name/SKILL.md` raises `ValueError: skill 'skills/real_name/SKILL.md' frontmatter `name: 'wrong_name'` must match directory `real_name``.
   - Empirically verified in `tests/test_adversarial_m3_1.py::test_frontmatter_quote_variations`.

4. **`normalize_rel` Windows Devices & Double Percent-Encoding (`engine/harness2_engine.py:165-210`)**:
   - Windows device names:
     `WIN_DEVICE_NAMES = frozenset({"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))})`
     `stem in WIN_DEVICE_NAMES or part.lower() in WIN_DEVICE_NAMES` checks catch all variations:
     `scripts/con.py`, `scripts/CON.py`, `skills/Aux/SKILL.md`, `scripts/com1.backup.py`, `plugin/nul.ts`.
     Verbatim error: `ValueError: path contains Windows reserved device name: 'scripts/con.py'`.
   - Double percent-encoding:
     `%252e%252e`, `scripts/%252e%252e/escape.py`, `scripts/%252e/same.py`, `scripts/%255cwin_slash.py`, `scripts/%252fslash.py`, `scripts/%2500null.py`, `scripts/%253acolon.py`.
     Verbatim error: `ValueError: path escapes the harness: 'scripts/%252e%252e/escape.py'`.
   - Multi-stage encoding observation: Triple percent-encoding (`scripts/%25252e%25252e.py`) bypasses the single-stage `normalize_rel` regex, but is strictly rejected by `is_allowed()` and `validate_tree()` (`ValueError: off-surface path rejected: 'scripts/%25252e%25252e.py'`).
   - `base_dir` containment:
     When `base_dir` is supplied, `(base_path / cleaned).resolve().relative_to(base_path)` returns canonical `Path` and raises `ValueError: path escapes base directory` if outside.
   - Empirically verified in `tests/test_adversarial_m3_1.py::test_normalize_rel_adversarial_matrix`.

5. **Budget Accounting Ledger Identity (`engine/harness2_engine.py:515-523`)**:
   ```python
   def assert_identity(self) -> None:
       exp_r = expected_rollouts(self.k)
       exp_p = expected_sessions(self.k)
       if self.rollouts_count != exp_r or self.sessions_count != exp_p:
           raise BudgetError(
               f"Harness² budget violation on task={self.task_id!r} (mode={self.mode}, k={self.k}): "
               f"expected R={exp_r} rollouts & P={exp_p} sessions, "
               f"got R={self.rollouts_count} & P={self.sessions_count}"
           )
   ```
   - Tested across $k \in \{1, 2, 3, 4\}$ ($R=4,8,12,16$ and $P=3,6,9,12$):
     * Deficit rollouts ($R-1$) -> `BudgetError`
     * Excess rollouts ($R+1$) -> `BudgetError`
     * Deficit sessions ($P-1$) -> `BudgetError`
     * Excess sessions ($P+1$) -> `BudgetError`
     * Corrupted entries (`Entry("unknown_kind", ...)`): do not increment `rollouts_count` or `sessions_count`, failing budget identity.
     * End-to-end `Harness2ProtocolEngine` runs (`run_parallel` and `run_sequential` on `RFC9112`): both generate exact $R=4k$ and $P=3k$ ledgers; artificially corrupting either completed ledger immediately triggers `BudgetError`.
   - Empirically verified in `tests/test_adversarial_m3_1.py::test_mathematical_budget_ledger_corrupted_rollouts_and_sessions` and `test_engine_end_to_end_parallel_and_sequential_ledger_identity`.

---

## 2. Logic Chain

1. **Surface Validation Logic**:
   - Observation 1 proves that `body.strip()` correctly identifies empty and whitespace-only TypeScript plugins and raises `ValueError` with component context.
   - Line 283 prevents off-surface injection by requiring every relative path to be normalized and permitted by `RFCHUNT_SURFACE`.

2. **Always-On Non-Emptiness Logic**:
   - Observation 2 proves that `reject_empty_always_on` uses an exhaustive conjunction: `any(a in tree)` asserts presence, and `all(tree.get(a, "").strip())` asserts non-emptiness for every present component.
   - This eliminates the prior defect where a single non-empty always-on file masked other blank files.

3. **Frontmatter Quotation Logic**:
   - Observation 3 shows that `.strip().strip("'\"")` safely strips outer quotation marks without modifying internal quotation characters in descriptions.
   - Frontmatter directory-matching rules remain strictly enforced.

4. **Path Sanitization & Device Defense Logic**:
   - Observation 4 demonstrates that checking `WIN_DEVICE_NAMES` against both `stem` and `part.lower()` prevents Windows reserved device collision under all extension and subdirectory forms.
   - Explicitly screening `%252e`, `%255c`, `%252f`, `%2500`, `%253a` neutralizes double percent-encoding.
   - For multi-stage percent encoding, while `normalize_rel` permits non-matched characters, the strict alphanumeric whitelist in `is_allowed()` (`scripts/[a-z0-9_]+\.py`) fails closed, preventing filesystem escapes.

5. **Ledger Invariant Logic**:
   - Observation 5 confirms that `assert_identity()` uses strict integer equality (`self.rollouts_count != exp_r or self.sessions_count != exp_p`).
   - Because `rollout()` and `session()` strictly track their respective kinds, no untyped or corrupted entry can satisfy the budget ledger identity.

---

## 3. Caveats

- **Multi-Stage URL Decoding (Milestone 4 Boundary)**:
  Triple percent-encoding (`%25252e`) passes `normalize_rel`'s single-pass check, but is blocked by `is_allowed()` and `validate_tree()`. Full recursive decoding is planned for Milestone 4 (Feature 16: Path Traversal Hardening).
- **Windows SQLite Test Temp Contention**:
  When running the full 300+ test suite, Windows file locking on SQLite database files in the shared `--basetemp=d:/harfile/.pytest_temp` can cause transient `PermissionError` [WinError 32] during test directory cleanup. Using an isolated `--basetemp` or completing Milestone 4 (Feature 17: SQLite WAL & Concurrency Locks) eliminates this contention.
- No other caveats; all Milestone 3 components execute deterministically offline without network dependencies.

---

## 4. Conclusion

**Verdict: `APPROVE`**

Milestone 3 (Module 16 Google Research Harness² and Protocol Ruler) satisfies all five empirical challenge requirements with mathematical precision:
- $R=4k$ rollouts and $P=3k$ sessions are strictly enforced across both parallel and sequential recursion.
- All 8 `c1..c8` surface components undergo rigorous syntax and non-emptiness checks.
- Windows device name and path traversal defenses are robust.
- The 43-test Milestone 3 verification suite passes 100% cleanly.

---

## 5. Verification Method

To independently verify all findings and assertions:

1. **Run Challenger Adversarial Fuzzing Suite**:
   ```powershell
   python.cmd -m pytest tests/test_adversarial_m3_1.py -v
   ```
   *Expected Result*: 8 passed in ~1.3 seconds.

2. **Run Full Milestone 3 Target Suite**:
   ```powershell
   python.cmd -m pytest tests/test_harness2_integration.py tests/test_adversarial_m3_1.py test_protocol_ruler.py tests/test_research_engine.py -q
   ```
   *Expected Result*: 43 passed in ~19 seconds.

3. **Verify Build Pipeline Step 7**:
   ```powershell
   python.cmd -u build_all.py
   ```
   *Expected Result*: Step 7 passes: `[+] PASS: Harness² Engine verified (8 c1..c8 components valid, adopted=agg1, R=4/4, P=3/3, Library INDEX.md verified)`.
