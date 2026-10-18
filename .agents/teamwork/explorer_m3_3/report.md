# Exhaustive Test Coverage & Verification Report: Google Research Harness² Engine & Protocol Research Test Suites

**Author**: Explorer M3-3 (Harness² Integration & Test Coverage)  
**Date**: 2026-10-18  
**Scope**: `tests/test_harness2_integration.py`, `tests/test_research_engine.py` (and `tests/test_engine_12_modules.py`), `build_all.py` (`step_7_verify_harness2`), and `engine/harness2_engine.py`.

---

## Executive Summary

This investigation performed an exhaustive empirical and code-level audit of the Google Research Harness² integration test suite (`tests/test_harness2_integration.py`), the protocol research test suites, and Step 7 of the unified build pipeline (`build_step_harness2` in `build_all.py`).

### Key Findings
1. **Missing Test File Resolved**: `tests/test_research_engine.py` (referenced in `ORIGINAL_REQUEST.md:27` and dispatch) **does not exist on disk**. The 12 protocol research engine modules are instead comprehensively tested in `tests/test_engine_12_modules.py` (14 passing tests, 100% pass rate).
2. **Harness² Engine Test Suite Status**: `tests/test_harness2_integration.py` currently contains 5 unit and integration tests (all 5 passing in ~6.5s). The tests verify core surface validation, AST syntax checks, budget identity enforcement for $k=2$, parallel/sequential execution, and CLI swarm execution.
3. **Zero Mock Dependencies**: Conforming strictly to the `no_mocks_write_actual_code.md` rule, neither `Harness2ProtocolEngine` nor `test_harness2_integration.py` uses fake mocks, monkeypatch stubs, or dummy constants. Probe simulation is driven by the offline `ProtocolWorldModel` (Markov Decision Process replay) and the `MultiImplementationDifferentialOracle` (4 in-process algorithmic reference parsers).
4. **Build Step 7 Analysis**: `build_step_harness2` in `build_all.py` successfully verifies base tree surface constraints, executes `run_parallel("RFC-9112", k=1)`, and asserts the budget ledger identity ($R=4, P=3$). However, it **bypasses Level 2 Experience Library persistence** because it invokes `run_parallel` directly without passing `library`, and it does not exercise sequential mode.
5. **Identified Test Gaps & Edge Cases**: 8 distinct categories of test gaps and edge cases were identified, including unverified budget ledger boundaries (over-budget rollouts, session deficits/excesses), untested surface constraints (`always_on_max` cap, empty always-on rejection, subagent frontmatter missing `mode`/`description`), cross-task Level 2 library inheritance, proposal fallback/retry self-healing, and candidate diversity metrics.

---

## 1. Status of `tests/test_research_engine.py` vs Codebase Reality

### Observation
- `ORIGINAL_REQUEST.md:27` lists:
  > `Existing test suites: tests/test_harness2_integration.py, tests/test_authorization_and_safety.py, tests/test_terminator_improvements.py, tests/test_dream_and_caldera.py, tests/test_research_engine.py, test_protocol_ruler.py`
- Directory search (`find_by_name`, `list_dir`) and ripgrep across the entire repository revealed that **`tests/test_research_engine.py` does not exist**.
- Inspection of `tests/` revealed that research modules are tested under:
  - `tests/test_engine_12_modules.py` (Modules 1–12 and `ProtocolResearchOrchestrator`)
  - `tests/test_dream_rsi.py` (Module 13: Dream-RSI World Model & Optimizer)
  - `tests/test_caldera_bridge.py` (Module 14: Caldera Adversary Emulation)
  - `tests/test_raptor_integration.py` (Module 15: Raptor Security Framework)
  - `tests/test_harness2_integration.py` (Module 16: Google Research Harness²)

### Logic Chain
1. `tests/test_engine_12_modules.py` tests all 12 modules of the protocol research engine:
   - Mod 1: `ABNFGrammarEngine`
   - Mod 2: `AdaptiveBanditScheduler`
   - Mod 3: `SemanticConstraintCompiler`
   - Mod 4: `MultiImplementationDifferentialOracle`
   - Mod 5: `StatefulProtocolSequenceEngine`
   - Mod 6: `RFCEvolutionTracker`
   - Mod 7: `MetamorphicTestingEngine`
   - Mod 8: `DeltaDebugger`
   - Mod 9: `CausalAnomalyClassifier`
   - Mod 10: `CrossProtocolBoundaryAnalyzer`
   - Mod 11: `ResearchKnowledgeGraph`
   - Mod 12: `DefensiveIntelligencePublisher`
   - Orchestrator: `ProtocolResearchOrchestrator` (ingestion and end-to-end cycle)
2. All 14 tests in `tests/test_engine_12_modules.py` pass cleanly in ~6.4s (`py -3.12 -m pytest tests/test_engine_12_modules.py -v`).
3. If an automated script or audit relies on the literal path `tests/test_research_engine.py`, pytest fails with `file not found`.

### Recommendation
Author `tests/test_research_engine.py` as an explicit test entrypoint that exercises the multi-module research engine or re-exports/wraps `test_engine_12_modules.py` to ensure complete backwards-compatibility with all audit runners.

---

## 2. Test Coverage Audit of Google Research Harness² (`engine/harness2_engine.py`)

### 2.1 $R=4k / P=3k$ Budget Ledger & `BudgetError` Enforcement
The Google Research Harness² paper (arXiv:2610.14224) establishes the exact mathematical identity:
- $R = 4k$ rollouts: $k$ shared base rollouts + $2k$ candidate rollouts + $k$ final rollouts.
- $P = 3k$ sessions: $k$ INV proposals + $k$ DOM proposals + $k$ compositions.

#### Current Coverage
- `test_ledger_budget_identity_enforcement` (`tests/test_harness2_integration.py:108-127`):
  - Asserts `expected_rollouts(2) == 8` and `expected_sessions(2) == 6`.
  - Simulates 7 rollouts and 6 sessions, asserting that `ledger.assert_identity()` raises `BudgetError`.
  - Appends 8th rollout, asserting that `ledger.assert_identity()` succeeds and `ledger.to_dict()["budget_verified"] is True`.
- `test_parallel_and_sequential_recursion_and_library`:
  - Verifies `res_agg.ledger.rollouts_count == 8` and `res_agg.ledger.sessions_count == 6` for parallel mode with $k=2$.
  - Verifies `res_seq.ledger.rollouts_count == 8` and `res_seq.ledger.sessions_count == 6` for sequential mode with $k=2$.
- `test_cli_harness2_execution`:
  - Verifies $k=1$ outputs `"Rollouts (R = 4k) : 4/4"` and `"Stages (P = 3k) : 3/3"`.

#### Coverage Gaps
1. **Excess Rollouts ($R > 4k$)**: No test asserts that exceeding the budget ($R=9$ when $4k=8$) raises `BudgetError`.
2. **Session Deficit ($P < 3k$)**: No test asserts that under-budget sessions ($P=5$ when $3k=6$) raise `BudgetError`.
3. **Session Excess ($P > 3k$)**: No test asserts that over-budget sessions ($P=7$ when $3k=6$) raise `BudgetError`.
4. **`verify_budget()` Method**: `ledger.verify_budget()` (which calls `assert_identity()` and returns `True`) is never asserted in unit tests.
5. **Cost/USD Accounting**: `Entry(usd=...)` tracking, caching flags, and attempt counters in `ledger.to_dict()` are not asserted.

---

### 2.2 `parallel` (`agg`) vs `sequential` (`seq`) Propose-Probe-Compose Recursion

#### Current Coverage
- `test_parallel_and_sequential_recursion_and_library` (`tests/test_harness2_integration.py:129-177`):
  - **Parallel Mode**: `engine.run_mode("parallel", "RFC9112", k=2, domain="http11_framing", run_tag="exp1")`.
    - Verifies `res_agg.ok`, `res_agg.mode == "agg"`.
    - Verifies `res_agg.adopted_label in ("agg1", "agg2")` and `len(res_agg.finals) == 2`.
  - **Sequential Mode**: `engine.run_mode("sequential", "RFC7230", k=2, domain="http11_framing", run_tag="exp1")`.
    - Verifies `res_seq.ok`, `res_seq.mode == "seq"`.
    - Verifies `res_seq.adopted_label in ("c1", "c2")`.

#### Coverage Gaps
1. **Invalid Mode Exception**: `engine.run_mode("invalid", ...)` (line 1406 in `harness2_engine.py`) raises `ValueError("unknown mode 'invalid'...")`. This exception path is untested.
2. **Mode Aliases**: Testing `"agg"` and `"seq"` directly passed to `run_mode` alongside `"parallel"` and `"sequential"`.
3. **Sequential Intermediate Propagation**: In sequential mode, round $t$ composes $c_t$ and carries it forward as the baseline for round $t+1$. No test asserts that modifications made in $c_1$ persist into the baseline tree of $c_2$.
4. **`run_suite` Runner**: `Harness2ProtocolEngine.run_suite()` (`harness2_engine.py:1442-1461`) supports multi-RFC suites and `mode="both"`. This method is completely untested.

---

### 2.3 `c1..c8` Surface Specification (`RFCHUNT_SURFACE`) & Path Validation

The 8 editable harness components defined in `RFCHUNT_SURFACE` (`engine/harness2_engine.py:87-135`):
- `c1`: `systemprompt.md` (Always-on system directive)
- `c2`: `guardrails.md` (Always-on invariants & skill triggers)
- `c3`: `LongTermMEMORY.md` (Always-on empirical memory)
- `c4`: `tool_descriptions/tool_guidance.md` (Always-on tool execution instructions)
- `c5`: `sub_agents/<name>/AGENT.md` (Delegated subagents)
- `c6`: `skills/<name>/SKILL.md` (On-demand skills)
- `c7`: `scripts/<name>.py` (Deterministic Python helpers)
- `c8`: `plugin/<name>.ts` (In-loop guard plugins)

#### Current Coverage
- `test_c1_c8_surface_and_path_escape_guard`:
  - Path traversal and injection rejection: `../secret.txt`, `/etc/passwd`, Windows drive path, `%2e%2e`, `%2f`, and null byte `\x00`.
  - Allowed component matching: asserts `is_allowed(RFCHUNT_SURFACE, p)` for all 8 components.
  - Rejection of off-surface filename: `random_off_surface.txt`.
  - Autotrigger injection: missing skill trigger added into `guardrails.md`.
  - Roundtrip read/write: excludes README stubs and matches dictionary content.
- `test_tree_validation_rejects_invalid_scripts_and_frontmatter`:
  - Rejection of mismatched skill name in YAML frontmatter.
  - Rejection of overwriting reserved scripts (`read_doc.py`).
  - Rejection of invalid Python AST syntax in `scripts/*.py`.

#### Coverage Gaps
1. **Always-On Character Cap (`always_on_max = 24_000`)**: If `sum(len(tree[a])) > 24_000`, `validate_tree` raises `ValueError`. Untested boundary condition.
2. **Empty Always-On Rejection (`reject_empty_always_on = True`)**: If all `always_on` files are empty strings, `validate_tree` raises `ValueError`. Untested.
3. **Off-Surface Files inside Tree**: Passing an off-surface path inside the `tree` dictionary directly to `validate_tree` raises `ValueError("off-surface path rejected")`. Untested.
4. **Subagent Frontmatter Validation**:
   - Subagent missing `mode: subagent` (e.g. `mode: worker` or missing) raises `ValueError`. Untested.
   - Subagent missing `description:` raises `ValueError`. Untested.
   - Subagent disabled (`allow_subagents=False`) raises `ValueError`. Untested.
5. **Skill Missing Description**: Skill with frontmatter missing `description:` raises `ValueError`. Untested.
6. **Nested Skill Script Python AST Checking**: `skills/<name>/scripts/<helper>.py` with invalid Python syntax must be compiled and rejected when `compile_skill_scripts=True`. Untested.

---

### 2.4 Per-Domain Experience Library (`INDEX.md` and `EXPERIENCE.md`)

#### Current Coverage
- `test_parallel_and_sequential_recursion_and_library`:
  - Verifies library directory creation: `runs_dir / "exp1" / "agg" / "http11_framing"`.
  - Verifies `lib.exists() == True`.
  - Verifies entry folder creation: `lib.entries() == ["RFC9112"]`.
  - Verifies `EXPERIENCE.md` file existence.
  - Verifies `lib.load_domain_lessons()` extracts `cue`, `lesson`, and `evidence`.

#### Coverage Gaps
1. **Level 2 Cross-Task Inheritance**: The central premise of Google Research Harness² Level 2 recursion is that when Task B runs in the same domain and mode after Task A, it inherits the adopted tree of Task A as its starting base tree (`harness2_engine.py:1416-1422`). In the existing test, Task 1 was run under `"agg"` and Task 2 under `"seq"`, which used distinct library directories and prevented inheritance. This cross-task inheritance must be explicitly tested.
2. **Experience Schema Validation**: `Library.record()` requires non-empty `cue`, `lesson`, and `evidence` strings (`harness2_engine.py:530-535`, `579-582`). Missing or empty keys must raise `ValueError`. Untested.
3. **`INDEX.md` Idempotence**: Recording the same task twice should not produce duplicate table rows in `INDEX.md`. Untested.
4. **Resilience to Corrupt Records**: `load_domain_lessons()` should gracefully skip entries missing one of the required header lines. Untested.

---

### 2.5 Diversity & Token Similarity Metrics (`diversity`)

#### Current Coverage
- `diversity()` is called inside `run_parallel` and `run_sequential`, but the resulting dictionary values (`mean_jaccard_similarity`, `diversity_index`, `pairwise`) are not asserted in any unit test.

#### Coverage Gaps
1. **Single Tree Edge Case**: `len(labels) < 2` returns `{"mean_jaccard_similarity": 1.0, "pairwise": {}}`.
2. **Identical Trees**: Two identical trees return similarity `1.0` and `diversity_index = 0.0`.
3. **Disjoint Trees**: Two completely different trees return low similarity and high `diversity_index`.

---

### 2.6 Self-Healing Proposal Retry & Fallback Mechanism

#### Current Coverage
- In `_run_stage` (`harness2_engine.py:980-1035`), if proposal synthesis or validation throws an exception, the engine retries up to `STAGE_ATTEMPTS = 2` times. If both attempts fail, it falls back to `copy.deepcopy(fallback)` and marks `s.fell_back = True`, `s.kept_base = True`.

#### Coverage Gaps
- Currently, all proposals in unit tests succeed on attempt 1.
- No test injects an invalid proposal or validation error to verify that `_run_stage` correctly retries and falls back cleanly without crashing the recursion loop.

---

## 3. Audit of `build_all.py` Step 7 (`build_step_harness2`)

### Exact Implementation in `build_all.py:152-173`
```python
def build_step_harness2() -> Tuple[bool, str]:
    """Verifies Google Research Harness² c1..c8 surface, Propose-Probe-Compose loop, and R=4k/P=3k ledger."""
    try:
        from engine.harness2_engine import Harness2ProtocolEngine, RFCHUNT_SURFACE, validate_tree

        engine = Harness2ProtocolEngine(
            runs_root=ROOT_DIR / "runs" / "harness2",
            target_host="127.0.0.1",
            target_port=8080,
            db_path=str(ROOT_DIR / "terminator.db"),
        )
        base_tree = engine.build_base_harness(domain="http11_framing")
        validate_tree(RFCHUNT_SURFACE, base_tree)
        res = engine.run_parallel("RFC-9112", k=1, domain="http11_framing", base_tree=base_tree)
        res.ledger.verify_budget()
        return True, (
            f"Harness² Engine verified (8 c1..c8 components valid, adopted={res.adopted_label}, "
            f"R={res.ledger.rollouts}/{res.ledger.expected_rollouts}, P={res.ledger.sessions}/{res.ledger.expected_sessions})."
        )
    except Exception as e:
        return False, f"Harness² verification failure: {e}"
```

### Execution Behavior
- When executed (`py -3.12 -c "import build_all; ok, msg = build_all.build_step_harness2(); print(ok, msg)"`), it passes in ~0.25 seconds:
  `OK=True, MSG=Harness² Engine verified (8 c1..c8 components valid, adopted=agg1, R=4/4, P=3/3).`
- It verifies that the base harness satisfies `validate_tree` across all 8 components.
- It executes 4 rollouts (1 base, 2 candidates, 1 final) and 3 stages (1 INV, 1 DOM, 1 AGG) in parallel mode.
- It verifies `res.ledger.verify_budget() == True`.

### Deficiencies & Recommendations for Step 7
1. **Library Persistence Bypassed**: `build_step_harness2` calls `engine.run_parallel` directly. Because `run_parallel` defaults to `library=None`, `library.record()` is not called!
   - *Fix*: Call `engine.run_mode("parallel", "RFC-9112", k=1, domain="http11_framing")` instead of `run_parallel`, or pass `library=Library(root=ROOT_DIR / "runs" / "harness2" / "build", domain="http11_framing")`. This ensures `INDEX.md` and `EXPERIENCE.md` are verified during `main.py build`.
2. **Missing Sequential Mode Check**: `build_step_harness2` checks only parallel mode. Adding a quick sequential verification (`run_mode("sequential", "RFC-9112", k=1)`) guarantees both recursion modes work in the production build.
3. **Output Isolation**: Build artifacts are written to `runs/harness2/work/RFC-9112`. Using a dedicated `runs/harness2/build_verification` subdirectory prevents polluting active research run directories.

---

## 4. Mock Dependencies & Offline Determinism Audit

### Audit against `RULE: no_mocks_write_actual_code.md`
- **Zero Fake Mock Objects**: No `unittest.mock.MagicMock`, dummy monkeypatches, or synthetic stub objects are used in `Harness2ProtocolEngine` or `tests/test_harness2_integration.py`.
- **Offline World Model (`ProtocolWorldModel`)**:
  - `engine/dream_world_model.py` provides an offline stateful HTTP replay simulator.
  - Replays historical traces ingested from SQLite `terminator.db` (`probes` and `evaluations` tables).
  - Uses structural heuristic generalizations for novel probes (RFC 9112 §6.1 un-framed body detection, dual Content-Length conflict detection, obs-fold, and path NUL).
  - Generates zero network traffic to external or unauthorized IP addresses.
- **Offline 4-Parser Differential Matrix (`MultiImplementationDifferentialOracle`)**:
  - `evaluate_matrix_4parsers` tests probes against 4 distinct in-memory algorithmic reference parsers:
    1. `StrictRFC7230Parser`
    2. `PermissiveLegacyParser`
    3. `CDNProxyParser`
    4. `AsyncMicroserviceParser`
  - Fully in-process and deterministic with zero live sockets or external connections.
- **Filesystem Integrity**: All trees are written to real temporary directory paths (`tmp_path`) using standard UTF-8 file operations (`write_tree`, `read_tree`).

---

## 5. Comprehensive Hardening & Test Authoring Plan

To remediate all identified test gaps without modifying production code during this read-only investigation, the following concrete additions are proposed for Milestone 5 test suite expansion:

### A. Author `tests/test_research_engine.py`
Create `tests/test_research_engine.py` to satisfy `ORIGINAL_REQUEST.md:27` and provide a consolidated entrypoint for research engine modules and the `ProtocolResearchOrchestrator`:
```python
"""
Consolidated Protocol Research Engine test suite covering Modules 1-12 and orchestration.
Resolves tests/test_research_engine.py specification in ORIGINAL_REQUEST.md.
"""
from tests.test_engine_12_modules import (
    test_mod1_abnf_extraction_and_inversions,
    test_mod2_bandit_and_genetic_scheduler,
    test_mod3_semantic_compiler,
    test_mod4_differential_oracle,
    test_mod5_stateful_sequence_engine,
    test_mod6_errata_tracker,
    test_mod7_metamorphic_engine,
    test_mod8_delta_debugger,
    test_mod9_causal_classifier,
    test_mod10_cross_protocol_boundary,
    test_mod11_knowledge_graph,
    test_mod12_defensive_publisher,
    test_orchestrator_rfc_ingestion,
    test_orchestrator_end_to_end_research_cycle,
)
```

### B. Expand `tests/test_harness2_integration.py` with Edge Case Tests
1. **Budget Ledger Boundary Suite**:
   - `test_ledger_budget_excess_rollouts_raises()`: 9 rollouts when $4k=8 \implies$ `BudgetError`.
   - `test_ledger_budget_deficit_sessions_raises()`: 5 sessions when $3k=6 \implies$ `BudgetError`.
   - `test_ledger_budget_excess_sessions_raises()`: 7 sessions when $3k=6 \implies$ `BudgetError`.
   - `test_ledger_verify_budget_return_value()`: Asserts `ledger.verify_budget() is True`.
2. **Surface Constraints Suite**:
   - `test_surface_cap_always_on_max_raises()`: String $> 24,000$ chars $\implies$ `ValueError`.
   - `test_surface_reject_empty_always_on_raises()`: Empty always-on files $\implies$ `ValueError`.
   - `test_surface_reject_off_surface_dict_key()`: Key `"bad.sh"` in tree $\implies$ `ValueError`.
   - `test_subagent_validation_constraints()`: Missing `mode: subagent` or missing `description:` $\implies$ `ValueError`.
   - `test_skill_missing_description_raises()`: Skill with no `description:` in frontmatter $\implies$ `ValueError`.
   - `test_nested_skill_script_syntax_error()`: `skills/s/scripts/bad.py` with bad AST $\implies$ `ValueError`.
3. **Domain Library Level 2 Recursion Suite**:
   - `test_domain_library_cross_task_inheritance()`: Run Task 1 (`RFC9112`) in `agg`, then Task 2 (`RFC7230`) in `agg`. Assert that Task 2's starting base tree contains the skills/scripts adopted by Task 1.
   - `test_domain_library_record_validation()`: Experience dict missing `'cue'`, `'lesson'`, or `'evidence'` $\implies$ `ValueError`.
   - `test_domain_library_index_idempotency()`: Recording the same task twice does not duplicate rows in `INDEX.md`.
4. **Diversity Metric Suite**:
   - `test_diversity_identical_and_disjoint_trees()`: Identical trees yield `diversity_index == 0.0`; disjoint trees yield high diversity.
5. **Proposal Fallback & Resilience Suite**:
   - `test_stage_proposal_retry_and_fallback()`: Proposal throwing error retries twice and sets `s.fell_back = True` without aborting the recursion run.
6. **Build Step 7 Enhancement**:
   - Update `build_step_harness2()` in `build_all.py` to invoke `run_mode("parallel", "RFC-9112", k=1)` so that Level 2 experience library recording is verified during `py -3.12 -u main.py build`.

---

## 6. Summary Verification Table

| Component | Target Requirement | Status in Codebase | Coverage Quality | Identified Gap / Remediating Action |
| :--- | :--- | :--- | :--- | :--- |
| **Budget Ledger ($R=4k/P=3k$)** | Enforce exact mathematical identity & `BudgetError` | Implemented in `Ledger.assert_identity()` | High | Add tests for excess rollouts, deficit sessions, excess sessions |
| **`parallel` Mode (`agg`)** | Width exploration, $k$ base + $2k$ cand + $k$ finals | Implemented in `run_parallel()` | High | Add diversity assertions and candidate ranking checks |
| **`sequential` Mode (`seq`)** | Depth refinement, iterative $c_t$ carryover | Implemented in `run_sequential()` | High | Verify $c_1 \to c_2$ state carryover across rounds |
| **Surface Spec (`c1..c8`)** | Validate all 8 components & path traversal guards | Implemented in `RFCHUNT_SURFACE` & `validate_tree()` | High | Add boundary tests: `always_on_max`, empty always-on, subagent mode |
| **Domain Library** | Persistent `INDEX.md` and `EXPERIENCE.md` per domain | Implemented in `Library.record()` | High | Test Level 2 cross-task inheritance across multiple tasks in domain |
| **Build Step 7** | `step_7_verify_harness2` in `build_all.py` | Implemented in `build_step_harness2()` | Medium | Wire `run_mode` to exercise `Library` persistence during build |
| **Mock Dependencies** | Zero mocks, real offline determinism | Zero mocks, in-memory reference models | Flawless | None; perfectly adheres to `no_mocks_write_actual_code.md` |
| **`test_research_engine.py`** | Listed in `ORIGINAL_REQUEST.md:27` | Missing from disk; covered in `test_engine_12_modules.py` | Gap | Author wrapper test file for 100% path compatibility |
