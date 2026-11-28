# RFCHunt Workspace Rules (Single Source of Truth)

> Keep this file as the **only** workspace instruction file in `c:\harfile\rfchunt` (do not create duplicate `GEMINI.md` or `.agents/rules/*` files, and do not register duplicate `rfchunt` MCP entries in `~/.gemini/config/mcp_config.json`).

## 1. Environment & Resource Discipline (8 GB RAM Laptop Safety)
- **Python**: `C:\Users\oyesanyf\AppData\Local\Python\pythoncore-3.14-64\python.exe` (includes `z3-solver` 5.4.1, `semgrep` 1.187.0, `pytest`, `uv`).
- **Portable Lean 4**: `tools/lean4/lean-4.36.0-windows/bin/lean.exe` (zero Windows Registry / global `PATH` mutations).
- **Docker**: Per-user Windows Docker Desktop installs at `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe` (auto-discovered by `engine/docker_wsl_doctor.py`, `ToolProvisioner._docker_available()`, and `RuntimeCapabilityProbe`).
- **No Heavy Parallel Agents**: Work as a **solo developer** (single agent, sequential edits/tests). Do not spawn multi-worker `/swarm` or parallel pytest processes on 8 GB RAM laptops.
- **Language Server Stability**: Keep `tools/`, `bin/`, `.pytest_temp/`, `reports/`, `rfcs/`, `runs/`, and `*.db` excluded via `.antigravityignore` and `.vscode/settings.json`.
- **Running Tests**: Always set `$env:RFCHUNT_OFFLINE = "1"` and run small targeted `pytest` batches (`-q --tb=short`) rather than stacking all E2E suites in one heavy process.

## 2. Architecture & Dynamic Resource-Gating Policy
- **Native-First Wrappers (Zero Tools Statically Excluded)**: Wrap real native binaries (`bin/*.exe`, `semgrep.exe`, `lean.exe`, `raptor.py`, `tools/bumblebee`, `strix`) rather than stubs. Never statically exclude a tool because of low local hardware—gate heavy/Docker engines dynamically via `RESOURCE_BUDGET_PROFILES` and `evaluate_resource_budget(...)` in `engine/ensemble_orchestrator.py` using live memory/CPU/disk from `ollama_manager.get_runtime_system_resources()`.
- **Universal Local Code Flag**: Preserve `--folder` (alias for `--repo` / `--dir`) across all CLI modes and `folder` parameter aliases across MCP tools (`mcp_server.py`).
- **Zero-Skip Lossless Accounting**: Preserve `dropped_count == 0` in `EnsembleConsensusEngine` (`ensemble_all_findings.json` and `ensemble_report.sarif`). `REFUTED` findings remain recorded with `epistemic_status="REFUTED"`, never silently deleted.

## 3. Epistemic Rigor & Formal Verification Invariants
- **Strict 4-State Epistemic Lattice (`engine/epistemic_state.py`)**: Every finding and SARIF result carries `epistemic_status` (`PROVEN_RUNTIME`, `PROVEN_STATIC_INVARIANT`, `UNRESOLVED`, `REFUTED`) and a machine-readable `status_justification` block (`satisfied_checks`, `failed_checks`, `missing_evidence`, `independent_oracles`, `correlated_oracles`).
- **Hard Cap on LLM-Only Consensus**: Multi-LLM agreement is strictly labeled `correlated_oracles` and must NEVER promote a finding past `UNRESOLVED` / `LLM_HEURISTIC` without an orthogonal independent oracle (AST/CFG verifier, Z3 SMT, Lean 4 kernel, or runtime PoE execution).
- **Honest Formal Verification Scope**:
  - `formal/lean4/*.lean` (6 core modules: `AuthorizationInvariants`, `EpistemicPromotionInvariants`, `HttpFramingInvariants`, `MeetSemilatticeInvariants`, `MerkleAuditInvariants`, `TrustedClosure` — zero `sorry`, machine-checked by `lean.exe`) verify RFCHunt's **gating & security invariant specifications**.
  - Target-code security claims are verified by `engine/claim_verifier.py` (AST preconditions), `engine/verification_inversion_hunter.py` (live Z3 SMT witnesses), `engine/poe_container_verifier.py` (runtime PoE), and `benchmarks/eval_epistemic_rigor.py` (adversarial false-claim & patched-vs.-unpatched CVE scorecard).

## 4. Non-Negotiable Security & Execution Guardrails (Zero Violations)
- Never use `shell=True`; always pass argv lists with `shell=False` and `CREATE_NO_WINDOW` on Windows.
- Never mutate Windows Registry, global `PATH`, or `setx`.
- Preserve `--authorized` gating, `validate_and_authorize_target()` SSRF/metadata/RFC1918 blocks, `ALLOWED_NUCLEI_TAGS` / `FORBIDDEN_NUCLEI_TAGS`, TruffleHog `--no-verification`, secret redaction, and Bumblebee's zero-MCP-`env`-emission rule.
- Never stage or commit `.env.local`, `bin/`, `tools/`, `reports/`, `*.db`, or `.pytest_temp/`.

## 5. Git & Commit Conventions
- Repo-local author is configured in `.git/config` (`femi oyesanya <oyesanyf@gmail.com>`).
- Run relevant syntax/unit checks before every commit.
- Solo-developer direct pushes to `main` are allowed when explicitly requested by the user; if zero GitHub branch-protection bypass notices are desired, open a short feature branch + PR instead.
