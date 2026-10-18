# Google Research Harness² Integration Guide (`engine/harness2_engine.py`)

> **Academic Reference & Attribution**
> - **Title**: *Harness²: Recursive Agent Harnessing for an Open World*
> - **Authors**: Ruiyao Xu, Yanfei Chen, Zhongying CuiZhu, Bhavana Dalvi Mishra, Yifei Ming, Han Yu, Rujun Han, Chen-Yu Lee, and Tomas Pfister (Google Research, 2026)
> - **Paper**: <https://arxiv.org/abs/2610.14224>
> - **Upstream Repository**: <https://github.com/google-research/harness2>

---

## 1. Architectural Overview

While foundation model weights remain fixed during local Ollama inference (`gemma2:2b`, `fenkohq/foundation-sec-8b:latest`, `deepseek-r1:1.5b`), agentic protocol research performance depends heavily on the **agent harness**—the surrounding configuration of system prompts, guardrails, long-term memory, tool descriptions, delegated subagents, reusable skills, helper scripts, and in-loop plugins.

**Module 16 (`engine/harness2_engine.py`)** implements Google Research's **Harness²** two-level recursive optimization framework directly inside `rfchunt`:

1. **Level 1 — Task-Level Recursion (`Propose–Probe–Compose`)**:
   - Adapts the 8-component harness (`c1..c8`) to each active IETF RFC specification at test time without ground-truth labels.
   - Evaluates candidate harnesses via **behavioral contrast** against the **4-Parser Differential Matrix** (`Strict RFC 9112`, `Legacy RFC 2616`, `CDN Edge Proxy`, `Async Microservice Gateway`) and the **Open-Dream-RSI World Model**.
2. **Level 2 — Harnessing-Level Recursion (`Library`, `INDEX.md`, `EXPERIENCE.md`)**:
   - Accumulates adopted `c1..c8` harness trees and structured lessons (`cue`, `lesson`, `evidence`) into persistent per-domain libraries (`http11_framing`, `h2_translation`, `h3_quic`, `tls13_pqc`, `uri_normalization`, `smtp_pipeline`) so each solved RFC compounds capabilities for future unseen RFCs.

---

## 2. The 8 Editable Harness Components (`c1..c8` / `RFCHUNT_SURFACE`)

Every candidate harness is represented as a validated relative-path dictionary (`Tree = Dict[str, str]`) governed by `RFCHUNT_SURFACE`:

| Component ID | Relative Path Pattern | Role in Protocol Research Swarm | Validation Invariants |
| :---: | :--- | :--- | :--- |
| **`c1`** | `systemprompt.md` | Core RFC micro-inspiration & normative grammar synthesis instructions | Non-empty markdown |
| **`c2`** | `guardrails.md` | Anti-anchoring rules, 3-trial verification invariants, and auto-triggered skill rules | Non-empty; synced via `autotrigger()` |
| **`c3`** | `LongTermMEMORY.md` | Persistent memory of target terminator quirks (`CL.0`, `obs-fold`, header buffer limits) | Non-empty markdown |
| **`c4`** | `tool_descriptions/tool_guidance.md` | Operational guidance for 3-Step Canary Pipeline, Protocol Ruler, and Delta Debugger | Non-empty markdown |
| **`c5`** | `sub_agents/<name>/AGENT.md` | Specialized delegated subagents (e.g., `boundary_arbiter`) | YAML frontmatter (`mode: subagent`, `description`) |
| **`c6`** | `skills/<name>/SKILL.md` | Reusable protocol audit workflows (e.g., `desync_framing`, `inv_ruler_norm_1`) | YAML frontmatter (`name`, `description`) |
| **`c7`** | `scripts/<name>.py` | Deterministic Python wire-frame synthesis helpers | Syntax-checked via `ast.parse()`; blocks reserved names |
| **`c8`** | `plugin/<name>.ts` | In-loop framing invariant enforcement hooks | Non-empty TypeScript module |

---

## 3. Width vs. Depth Recursion & Exact Budget Accounting ($R = 4k, P = 3k$)

For any user-specified recursion parameter $k \ge 1$, both modes satisfy the exact budget identity enforced by `Ledger.verify_budget()`:
- **Rollouts**: $R = 4k$
- **Improvement Stages (`Propose` + `Compose`)**: $P = 3k$

### Parallel Mode (`--harness2-mode parallel` / `agg` — Width Exploration)
1. **Base Probe**: Executes $k$ base harness rollouts (`base_1 .. base_k`).
2. **Propose ($2k$ stages)**: Generates $k$ General Invariant (`inv1 .. invk`) and $k$ RFC Domain-Specific (`dom1 .. domk`) candidate harnesses.
3. **Probe ($2k$ rollouts)**: Evaluates each candidate harness against the 4-Parser Differential Matrix and Protocol World Model.
4. **Compose ($k$ stages + $k$ rollouts)**: Contrasts all $2k$ candidates to synthesize $k$ composed harnesses (`agg1 .. aggk`), probes them, and adopts the highest-contrast candidate.

### Sequential Mode (`--harness2-mode sequential` / `seq` — Depth Refinement)
Runs $k$ iterative rounds ($t = 1 \dots k$):
1. **Round 1 Base Probe**: Executes `r1_base` (and additional base probes if $k > 1$).
2. **Iterative Propose–Probe–Compose**: In each round $t$, proposes `rt_inv` and `rt_dom` conditioned on all prior round trees and rollouts, probes both, and composes `rt_compose`, which becomes the base harness for round $t+1$.

---

## 4. CLI Usage & Examples

```powershell
# 1. Run both Parallel (Width) and Sequential (Depth) Harness² recursion on RFC 9112
py -3.12 -u rfc_hunt_swarm.py --mode harness2 --rfc 9112 --harness2-k 1 --harness2-mode both

# 2. Run Parallel (Width) recursion with k=2 (R=8 rollouts, P=6 stages)
py -3.12 -u rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-k 2 --harness2-mode parallel

# 3. Run Sequential (Depth) recursion across multiple RFCs to compound domain experience
py -3.12 -u rfc_hunt_swarm.py harness2 --rfc 9112,9110,9113 --harness2-k 2 --harness2-mode sequential

# 4. Override the protocol domain explicitly and store artifacts in a custom directory
py -3.12 -u rfc_hunt_swarm.py harness2 --rfc 9113 --harness2-domain h2_translation --harness2-runs-dir runs/custom_h2

# 5. Inspect persisted Harness² runs, R=4k / P=3k budget proofs, and domain experience libraries
py -3.12 -u rfc_hunt_swarm.py --harness2-report
```
