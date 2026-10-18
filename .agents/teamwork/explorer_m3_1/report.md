# Comprehensive Investigation Report: Google Research Harness² Architecture (Module 16)

**Agent**: Explorer M3-1 (Harness² Architecture)  
**Date**: 2026-10-18  
**Target File**: `engine/harness2_engine.py`  
**Associated Files**: `tests/test_harness2_integration.py`, `docs/HARNESS2_INTEGRATION.md`, `rfc_hunt_swarm.py`, `build_all.py`  
**Milestone**: M3 (Module 16 Google Research Harness² & Protocol Ruler)

---

## 1. Executive Summary

Module 16 (`engine/harness2_engine.py`) implements Google Research's **Harness²** (*Recursive Agent Harnessing for an Open World*, Xu et al., Google Research, arXiv:2610.14224, 2026) within the HTTP Terminator / RFC Hunt Swarm architecture. The module enables recursive optimization of the agent harness around fixed local models (`ModelFusion` / Ollama panel) across two recursive levels:
1. **Level 1 (Task-Level Recursion)**: An iterative **Propose–Probe–Compose** cycle across 8 editable surface components (`c1..c8`) that optimizes the protocol research harness for a specific IETF RFC without ground-truth labels by evaluating behavioral contrast against the 4-Parser Differential Matrix and the Open-Dream-RSI World Model.
2. **Level 2 (Harnessing-Level Recursion)**: A persistent, per-domain experience library (`Library`) that records adopted `c1..c8` trees and evidence-backed lessons (`cue`, `lesson`, `evidence`) into `INDEX.md` and `EXPERIENCE.md` files on disk, compounding cross-RFC discoveries across successive tasks.

Our investigation confirmed that the core architecture is sound, the mathematical budget ledger ($R = 4k$ rollouts, $P = 3k$ stages) is strictly accounted for and verified via `BudgetError` in both parallel (`agg`) and sequential (`seq`) modes, and the integration tests in `tests/test_harness2_integration.py` pass cleanly. However, our deep static analysis identified **10 specific logic defects, edge cases, and specification deviations** in `engine/harness2_engine.py` that warrant remediation in Milestone M3/M4.

---

## 2. Detailed Verification of the 8-Component Surface (`c1..c8` / `RFCHUNT_SURFACE`)

The editable agent harness surface is defined by `RFCHUNT_SURFACE` (an instance of `SurfaceSpec`, lines 87–135) and governed by `validate_tree()`, `is_allowed()`, `autotrigger()`, `normalize_rel()`, `write_tree()`, and `read_tree()`.

### Surface Component Matrix

| ID | Path Pattern | Role in Swarm | Validation Rules in `harness2_engine.py` | Status & Integrity |
| :---: | :--- | :--- | :--- | :--- |
| **`c1`** | `systemprompt.md` | Core RFC normative grammar synthesis instructions | In `surface.always_on`; checked against `always_on_max` cap (24,000 chars); checked by `reject_empty_always_on`. | **VALIDATED** (Defect noted on empty check) |
| **`c2`** | `guardrails.md` | Invariant constraints & skill autotrigger injection | In `surface.always_on`; auto-injected by `autotrigger()`. | **VALIDATED** (Defect noted on substring match) |
| **`c3`** | `LongTermMEMORY.md` | Persistent cross-RFC terminator quirk memory | In `surface.always_on`; checked against `always_on_max` cap. | **VALIDATED** |
| **`c4`** | `tool_descriptions/tool_guidance.md` | Guidance for 3-Step Canary, Protocol Ruler, Delta Debugger | In `surface.always_on`; checked against `always_on_max` cap. | **VALIDATED** |
| **`c5`** | `sub_agents/<name>/AGENT.md` | Delegated protocol specialist subagents | Regex `sub_agents/([a-z0-9][a-z0-9_\-]*)/AGENT\.md`; frontmatter requires `mode: subagent` and non-empty `description:`. | **VALIDATED** |
| **`c6`** | `skills/<name>/SKILL.md` | Reusable protocol audit workflows | Regex `skills/([a-z0-9][a-z0-9_\-]*)/SKILL\.md`; frontmatter `name:` must match directory; non-empty `description:` required; autotriggered into `guardrails.md`. | **VALIDATED** |
| **`c7`** | `scripts/<name>.py` | Deterministic Python wire-frame synthesis helpers | Regex `scripts/[a-z0-9_][a-z0-9_]*\.py`; blocks reserved scripts (`RESERVED_SCRIPTS = {"read_doc.py", "pack.py", "unpack.py"}`); syntax validated via `ast.parse()`. | **VALIDATED** |
| **`c8`** | `plugin/<name>.ts` | In-loop framing invariant enforcement hooks | Regex `plugin/([a-z0-9][a-z0-9_\-]*)\.ts`; checked by `is_allowed()`. | **DEFECT**: Missing non-empty body validation in `validate_tree()`. |

### Architectural Invariants Observed:
1. **README Component Stubs**: Component directories contain guidance README files (`scripts/README.md`, `sub_agents/README.md`, `plugin/README.md`, `skills/README.md`). `write_tree()` writes these stubs to disk, while `read_tree()` explicitly excludes them from editable candidate trees (`stubs = frozenset(rel for rel, _ in surface.stubs)`), preserving surface cleanliness.
2. **Cap Enforcement**: The total character count of all `always_on` components is strictly checked against `always_on_max` (24,000 chars, ~6,000 tokens) with clear rationale: *"every token here competes with the agent's own wire synthesis budget"*.
3. **Python AST Parse Guard**: Every script on `c7` and every skill script on `c6` (`skills/<name>/scripts/<file>.py`) is dynamically compiled via `ast.parse(body, filename=norm)` inside `validate_tree()`, preventing invalid syntax from ever entering an executable harness.

---

## 3. Propose–Probe–Compose Recursive Engine Flow

The recursive search operates under two execution topologies:

### A. Parallel Mode (`run_parallel` / `agg` — Width Exploration)
1. **Base Probing**: Executes $k$ independent rollouts of the base harness (`base1 .. basek`) against `ProtocolWorldModel` and `MultiImplementationDifferentialOracle` to establish the baseline behavioral score.
2. **Propose ($2k$ stages)**: Concurrently generates $k$ general invariant (`inv1 .. invk`) and $k$ RFC domain-specific (`dom1 .. domk`) candidate edits via `ThreadPoolExecutor(max_workers=PHASE_WIDTH)`.
   - `INV` proposals specialize `guardrails.md` with strict byte-length differential checks, add an `inv_ruler_norm_{index}` skill, and synthesize an `inv_helper_{index}.py` script.
   - `DOM` proposals specialize `LongTermMEMORY.md` with prior domain lessons, update `tool_guidance.md` with protocol boundary vectors, add a domain skill `dom_{domain}_{index}`, and generate a domain subagent `sub_agents/dom_specialist_{index}/AGENT.md`.
3. **Candidate Probing ($2k$ rollouts)**: Each candidate harness is evaluated across the probe suite against the 4-Parser Differential Matrix and the World Model.
4. **Compose ($k$ stages)**: Constructs a contrastive behavioral evidence pool `pool_ev` sorted by `cand_view.behavioral_score`. Synthesizes $k$ composed candidates (`agg1 .. aggk`) by merging winning component edits, augmenting `systemprompt.md`, and generating composed wire test suites (`scripts/composed_agg_agg{i}.py`).
5. **Final Probing ($k$ rollouts)**: Evaluates all $k$ composed harnesses. The candidate with the highest contrast score is adopted (`result.adopted_label = best_final`).

### B. Sequential Mode (`run_sequential` / `seq` — Depth Refinement)
1. **Base Probing**: Executes $k$ shared base rollouts (`base1 .. basek`).
2. **Iterative Refinement ($t = 1 \dots k$ rounds)**:
   - Round $t$ starts with `current_harness` (inherited from round $t-1$, or base for $t=1$).
   - Generates `inv{t}` and `dom{t}` conditioned on `current_harness`, probes both, and records rollouts.
   - Contrasts the cumulative history `round_pool` to compose `c{t}`, probes `c{t}`, and carries `c{t}` forward as the base harness for round $t+1$.
3. **Final Selection**: Adopts the highest-scoring composed candidate among `c1 .. ck`.

### C. Behavioral Contrast Evaluation Engine (`_probe_harness`)
Candidate harnesses are evaluated without ground truth labels using a multi-dimensional behavioral scoring objective (lines 1086–1094):
$$\text{Score} = 10.0 \cdot V + 4.0 \cdot D + 3.0 \cdot A + 1.5 \cdot |\text{skills}| + 1.5 \cdot |\text{subagents}| + 1.0 \cdot |\text{scripts}| - 8.0 \cdot \text{FP}$$
where:
- $V$ = simulated vulnerabilities from `ProtocolWorldModel.simulate_probe()`
- $D$ = parser divergences across `StrictRFC7230`, `PermissiveLegacy`, `CDNProxy`, and `AsyncMicroservice`
- $A$ = simulated protocol anomalies
- $\text{FP}$ = simulated client framing omissions / false positives

---

## 4. Mathematical Budget Ledger Identity ($R = 4k, P = 3k$)

### Formal Accounting Proof
For any integer recursion budget $k \ge 1$:

| Mode | Phase | Sessions / Stages ($P$) | Rollouts ($R$) | Running $P$ | Running $R$ |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Parallel (`agg`)** | 1. Base Probe | 0 | $k$ | 0 | $k$ |
| | 2. Propose Candidates | $2k$ (`inv1..k`, `dom1..k`) | 0 | $2k$ | $k$ |
| | 3. Probe Candidates | 0 | $2k$ | $2k$ | $3k$ |
| | 4. Compose Aggregates | $k$ (`agg1..aggk`) | 0 | $3k$ | $3k$ |
| | 5. Probe Aggregates | 0 | $k$ | $3k$ | $4k$ |
| **Sequential (`seq`)** | 1. Base Probe | 0 | $k$ | 0 | $k$ |
| | Across $t = 1..k$ rounds: | | | | |
| | - Propose `inv{t}`, `dom{t}` | $2 \times k = 2k$ | 0 | $2k$ | $k$ |
| | - Probe `inv{t}`, `dom{t}` | 0 | $2 \times k = 2k$ | $2k$ | $3k$ |
| | - Compose `c{t}` | $1 \times k = k$ | 0 | $3k$ | $3k$ |
| | - Probe `c{t}` | 0 | $1 \times k = k$ | $3k$ | $4k$ |

In both modes:
$$\mathbf{R = 4k \quad \text{and} \quad P = 3k}$$

### Enforcement Mechanism
1. `Ledger.assert_identity()` (lines 477–486) verifies:
   ```python
   if self.rollouts_count != exp_r or self.sessions_count != exp_p:
       raise BudgetError(...)
   ```
2. Any discrepancy raises `BudgetError` (inheriting from `AssertionError`), which immediately halts execution and prevents unverified runs from completing.
3. Fallback recovery in `_run_stage` guarantees that even if a candidate generation attempt fails twice, a fallback stage is still recorded in the ledger (`ledger.session(...)`) and subsequently probed (`ledger.rollout(...)`), ensuring the invariant is never broken by candidate proposal exceptions.

---

## 5. Per-Domain Experience Library Persistence (`INDEX.md` and `EXPERIENCE.md`)

Level 2 Harnessing-Level Recursion is managed by the `Library` class (lines 538–638):
- **On-Disk Directory Structure**:
  ```
  runs/harness2/<run_tag>/<mode>/<domain>/
  ├── INDEX.md
  └── harnesses/
      ├── <slug_task_1>/
      │   ├── EXPERIENCE.md
      │   └── harness/ (full c1..c8 tree)
      └── <slug_task_2>/
          ├── EXPERIENCE.md
          └── harness/
  ```
- **`EXPERIENCE.md` Schema**:
  Requires non-empty fields:
  - `- **Domain**: <domain>`
  - `- **Adopted Candidate**: <label>`
  - `- **Behavioral Contrast Score**: <score>`
  - `- **Cue**: <operational trigger situation>`
  - `- **Lesson**: <concrete tactical rule learned>`
  - `- **Evidence**: <empirical contrast score gain and divergence metrics>`
- **`INDEX.md` Table**:
  Maintains a markdown summary table with columns: `| Task ID | Adopted Stage | Contrast Score | Cue | Lesson |`.
- **Harnessing-Level Knowledge Transfer**:
  When `run_mode()` executes for a new task in a domain:
  1. `lib.load_domain_lessons()` extracts all prior lessons from `EXPERIENCE.md` files.
  2. The most recent lesson is injected directly into `LongTermMEMORY.md` during domain candidate proposal (`_propose_candidate_tree`).
  3. `lib.entries()` loads the prior adopted tree and merges it into `base_tree` via `merge_tree_proposal()`, ensuring continuous compound learning.

---

## 6. Catalog of Bugs, Logic Defects, and Deviations

Through deep line-by-line inspection, we identified the following 10 defects and deviations:

### Defect 1: Lack of `c8` (`plugin/<name>.ts`) Content Validation in `validate_tree`
- **Location**: `engine/harness2_engine.py:265–298`
- **Observation**: In `validate_tree()`, while `skill`, `subagent`, and `script` have explicit AST/frontmatter validation loops, there is no validation branch for `plugin` (`c8`). An empty string (`""`) or invalid TypeScript file in `tree["plugin/guard.ts"]` is accepted without error.
- **Spec Impact**: Deviates from `docs/HARNESS2_INTEGRATION.md` Table line 38 (*"c8: Non-empty TypeScript module"*).
- **Remediation**: Add an explicit check in `validate_tree()`:
  ```python
  elif r.get("plugin") and r["plugin"].fullmatch(norm):
      if not body.strip():
          raise ValueError(f"plugin {norm!r} (c8) cannot be empty")
  ```

### Defect 2: `reject_empty_always_on` Uses `not any(...)` Instead of Checking Individual Always-On Files
- **Location**: `engine/harness2_engine.py:253–255`
- **Observation**:
  ```python
  if surface.reject_empty_always_on:
      if not any(tree.get(a, "").strip() for a in surface.always_on):
          raise ValueError("always-on harness components (c1..c4) cannot all be empty")
  ```
  If `systemprompt.md` has text but `guardrails.md` or `tool_guidance.md` is an empty string, `any(...)` evaluates to `True`, so no error is raised. In `write_tree()`, the empty component is written out as a 0-byte file.
- **Remediation**: Verify that if any always-on file is present in `tree`, it must not be blank, or if a full harness is validated, all always-on components must be non-empty.

### Defect 3: `normalize_rel` Signature and Traversal Filtering Deviates from `PROJECT.md` Contract
- **Location**: `engine/harness2_engine.py:159–179`
- **Observation**:
  1. `PROJECT.md` interface contract defines `normalize_rel(path_str: str, base_dir: Optional[Path] = None) -> Path: ...`. In `harness2_engine.py`, the signature is `normalize_rel(rel: str) -> str:`.
  2. Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`) are not checked. Attempting to write a file named `scripts/nul.py` or `scripts/con.py` on Windows results in OS-level file handle collisions or errors.
  3. Double percent-encoding (`%252e`, `%255c`, `%252f`, `%2500`) and encoded colons (`%3a`) are not checked.
- **Remediation**: Update `normalize_rel` to support optional `base_dir`, check Windows device names, double-encoding, and post-join canonical path containment.

### Defect 4: Substring False-Positive in `autotrigger()`
- **Location**: `engine/harness2_engine.py:228`
- **Observation**:
  `if name not in always_text:` performs a raw substring search. If a skill is named `h2`, and `always_text` contains `h2_translation`, `h2 in always_text` is `True`. `autotrigger()` falsely concludes that the skill trigger line already exists in `guardrails.md` and fails to inject it.
- **Remediation**: Search for the exact backticked name `f"`{name}`" in always_text` or use a regex word boundary `rf"\b{re.escape(name)}\b"`.

### Defect 5: Frontmatter Parsing Does Not Strip Outer Quotation Marks
- **Location**: `engine/harness2_engine.py:213–215`
- **Observation**:
  ```python
  def _frontmatter_field(body: str, key: str) -> str:
      m = re.search(rf"^{re.escape(key)}:\s*(.+)$", body[:800], re.M)
      return m.group(1).strip() if m else ""
  ```
  If a skill or subagent uses quoted YAML values (e.g. `name: "desync_framing"` or `description: 'differential specialist'`), `fm_name` becomes `'"desync_framing"'`. The check `if fm_name != skill_id:` fails with `ValueError: skill frontmatter name '"desync_framing"' must match directory 'desync_framing'`.
- **Remediation**: Strip outer matching quotes: `m.group(1).strip().strip("'\"")`.

### Defect 6: `INDEX.md` Does Not Update Existing Task Rows on Re-Runs
- **Location**: `engine/harness2_engine.py:608–610`
- **Observation**:
  ```python
  if f"| `{task_id}` |" not in current_idx:
      current_idx += row
  self.index.write_text(current_idx, encoding="utf-8")
  ```
  When a task is re-run (e.g., with higher $k$ or updated models), `EXPERIENCE.md` and `harness/` are updated with the new results, but `INDEX.md` retains the old row with stale contrast scores and lessons.
- **Remediation**: Replace existing rows for `task_id` using regex substitution or append a timestamped run record.

### Defect 7: `Library.entries()` Sorts Alphabetically Instead of Chronologically
- **Location**: `engine/harness2_engine.py:564`
- **Observation**:
  ```python
  def entries(self) -> List[str]:
      d = self.dir / "harnesses"
      return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.is_dir() else []
  ```
  `run_mode()` uses `prior_entries[-1]` to inherit the most recent adopted tree. Because `entries()` sorts alphabetically, `RFC9112` will always sort after `RFC7230`, regardless of which one was executed last.
- **Remediation**: Sort directory entries by modification timestamp `key=lambda p: p.stat().st_mtime`.

### Defect 8: `ModeResult.errors` Is Never Appended To
- **Location**: `engine/harness2_engine.py:709, 712–713`
- **Observation**:
  `ModeResult` defines `errors: List[str] = field(default_factory=list)` and `ok` property checks `bool(self.finals) and not self.errors`. However, in `run_parallel()` and `run_sequential()`, `result.errors` is never appended to, even when proposals fail and fall back to the base tree (`st.fell_back`). As a result, `res.ok` can be `True` even if multiple stages encountered syntax or execution errors.
- **Remediation**: Append stage fallback error messages (`if st.fell_back: result.errors.append(f"{st.label}: {st.error}")`) or distinguish warning fallbacks from fatal run aborts.

### Defect 9: `_probe_harness.sample_probes` Slices Only the First 3 Static Probes
- **Location**: `engine/harness2_engine.py:1109`
- **Observation**:
  ```python
  sample_probes=[p.decode("latin-1", errors="replace")[:80] for p in probe_suite[:3]]
  ```
  The first 3 probes in `probe_suite` are always the hardcoded base probes (`GET /`, `POST / chunked`, `GET / X-Fold`). When domain skills (`dom_`) or composed scripts are added, new probes are appended to `probe_suite[3:]`, but `sample_probes` only captures `[:3]`. Telemetry and inspection cards never display the newly synthesized domain/invariant probes.
- **Remediation**: Include dynamic probes in `sample_probes` by taking a representative sample or the tail of `probe_suite`.

### Defect 10: Composition Determinism in Parallel Mode for $k \ge 2$
- **Location**: `engine/harness2_engine.py:941–975, 1187–1205`
- **Observation**:
  In `run_parallel()`, when $k \ge 2$, `agg_specs = [(f"agg{i}", i) for i in range(1, k + 1)]`. In `_propose_candidate_tree`, the composition logic for `dim == "AGG"` iterates deterministically over the exact same `ranked_pool` and adopts all candidates with `behavioral_score >= 0`. Consequently, `agg1`, `agg2`, ... produce virtually identical trees except for the label string in `systemprompt.md` and the filename `scripts/composed_agg_agg{i}.py`.
- **Remediation**: Differentiate compositions across $i \in [1..k]$ by varying the selection temperature, top-$m$ candidate subsets, or prioritizing distinct skill clusters.

---

## 7. Actionable Recommendations for Implementation Team (Worker M3)

1. **Harden `validate_tree`**:
   - Add explicit validation for `c8` (`plugin/<name>.ts`): reject empty/whitespace-only content.
   - Enforce that any specified always-on component is non-empty.
2. **Refine `_frontmatter_field`**:
   - Strip leading and trailing quotation marks (`strip("'\"")`) to prevent spurious validation errors on standard YAML.
3. **Refine `autotrigger`**:
   - Match backticked skill names ``f"`{name}`"`` rather than unadorned substrings.
4. **Harden `normalize_rel`**:
   - Reject Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
   - Reject double percent-encoding (`%252e`, `%255c`, `%252f`).
   - Accept optional `base_dir: Optional[Path] = None` and verify post-join canonical path containment.
5. **Update `Library.record` & `entries`**:
   - Update `INDEX.md` rows when a task is re-recorded rather than ignoring duplicate task IDs.
   - Sort `Library.entries()` by modification time (`st_mtime`) for proper chronological inheritance.
