# Handoff Report: Explorer Survey 1 (Protocol & Framing Focus)
**Date**: 2026-10-18  
**Agent**: Explorer Survey 1  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\explorer_survey_1`  
**Recipient**: Project Orchestrator (`48cb9587-3e1b-40a9-9a84-e3452d5f5108`)  

---

## 1. Observation

Direct observations from inspecting `D:\harfile\rfchunt`:

1. **The 16 Protocol Research Modules**:
   - `engine/orchestrator.py:4-17` lists modules 1 through 12.
   - `README.md:376-397` documents all 16 modules in a comprehensive table:
     - Mod 1: `engine/abnf_engine.py` (`ABNFGrammarEngine`)
     - Mod 2: `probe_generator.py` (`ProbeGenerator`) & `engine/bandit_scheduler.py` (`AdaptiveBanditScheduler`)
     - Mod 3: `engine/semantic_compiler.py` (`SemanticConstraintCompiler`)
     - Mod 4: `engine/differential_oracle.py` (`MultiImplementationDifferentialOracle`)
     - Mod 5: `engine/sequence_engine.py` (`StatefulProtocolSequenceEngine`)
     - Mod 6: `engine/errata_tracker.py` (`RFCEvolutionTracker`)
     - Mod 7: `engine/metamorphic_engine.py` (`MetamorphicTestingEngine`)
     - Mod 8: `engine/delta_debugger.py` (`DeltaDebugger`)
     - Mod 9: `engine/causal_classifier.py` (`CausalAnomalyClassifier`)
     - Mod 10: `engine/boundary_analyzer.py` (`CrossProtocolBoundaryAnalyzer`)
     - Mod 11: `engine/knowledge_graph.py` (`ResearchKnowledgeGraph`)
     - Mod 12: `engine/defensive_publisher.py` (`DefensiveIntelligencePublisher`)
     - Mod 13: `engine/dream_world_model.py` (`ProtocolWorldModel`), `engine/dream_rsi_optimizer.py`, `engine/dream_policy_store.py`
     - Mod 14: `engine/caldera_bridge.py` (`CalderaBridge`)
     - Mod 15: `engine/raptor_integrator.py` (`RaptorIntegrator`)
     - Mod 16: `engine/harness2_engine.py` (`Harness2ProtocolEngine`)

2. **ABNF Grammars (RFC 9112, 9110, 9113, 7230, 2616)**:
   - `engine/abnf_engine.py:21-36`: Preloads `CORE_HTTP_RULES` (`OWS`, `RWS`, `BWS`, `obs-fold`, `chunk-ext`, `header-field`, `request-line`, `tchar`, `transfer-coding`).
   - `engine/abnf_engine.py:94-158`: `generate_inversions()` synthesizes boundary mutations (OWS bare control chars, pre-colon whitespace, obs-fold CRLF/LF tabs, chunk-ext invalid syntax and runaway padding, Transfer-Encoding case mixing and illegal codings).
   - `engine/terminator_rfc_selector.py:39-140`: Explicitly maps and weights RFC 9112 (1.00), RFC 9110 (0.95), RFC 7230 (0.90), RFC 2616 (0.85), RFC 9113 (0.80), RFC 7540 (0.75), RFC 9114 (0.70), RFC 8446 (0.65).
   - In `engine/abnf_engine.py:21-24`, `ABNF_RULE_REGEX = re.compile(r"^[ \t]*([a-zA-Z][a-zA-Z0-9_-]*)[ \t]*=[ \t]*(.+?)(?=;.*)?$", re.MULTILINE)` parses single-line ABNF statements, but does not capture indented multi-line continuations (RFC 5234 §2.1).

3. **3-Step Pipelined Canary & 3-Trial Reproducibility Invariant**:
   - `engine/sequence_engine.py:48-264`: `run_pipelined_canary_sequence()` executes Step 1 (REQ 1 baseline on clean socket), Step 2 (REQ 2 candidate probe), and Step 3 (REQ 3 canary with unique random token `CANARY_{randint}`) over a persistent TCP/TLS connection using `HTTPFramingReader.read_response`.
   - `engine/sequence_engine.py:133-137`: Guards against scanner artifacts (residual baseline HTML bytes on socket).
   - `engine/sequence_engine.py:209-230`: Specifically analyzes RFC 9112 §6.1 un-framed body omissions (where client sends body without CL or TE; length is 0, trailing bytes trigger server 400 rejection; classified as conforming HTTP behavior, not a pipeline leak).
   - `engine/delta_debugger.py:45-66`: Enforces `effective_trials = max(3, max_verification_trials)`. If `successes < 3` or `repro_rate < 0.60`, automatically downgrades to `ImpactClass.NON_REPRODUCIBLE_TRANSIENT`.
   - `engine/merkle_audit.py:16-68`: `AuditLeaf` computes SHA-256 with RFC 6962 `0x00` leaf prefix, recording `reproducibility_rate`, `four_parser_differential`, and `status`.

4. **Protocol Ruler Calibration & test_protocol_ruler.py**:
   - `protocol_ruler.py:146-235`: `calibrate_baseline_limit()` performs coarse bracket search over `[1024..131072]` followed by single-byte binary search to pinpoint backend header buffer limits (e.g. 64,040 bytes).
   - `protocol_ruler.py:237-300`: `measure_sequence_transformation()` binary searches mutated cliff around baseline limit to measure $\Delta = L_{\text{base}} - L_{\text{mutated}}$ (Expansion $\Delta > 0$, Contraction $\Delta < 0$, Verbatim $\Delta = 0$).
   - `test_protocol_ruler.py:14-75`: Tests against live `TestLabServer` (`test_lab_server.py:18-180`): validates 64,040 baseline calibration (`test_01`), Kettle overlong `\xc0\x8a` 10-byte expansion (`test_02`), verbatim slash (`test_03`), full catalog audit (`test_04`), and rejection of `0.0.0.0`/`::` listening addresses (`test_05`).

5. **4-Parser Differential Matrix**:
   - `engine/differential_oracle.py:277-440` defines 4 reference parsers:
     - `StrictRFC7230Parser`: Strict RFC 7230/9112 (rejects bare LF/CR, obs-fold, pre-colon whitespace, conflicting CL, TE+CL).
     - `PermissiveLegacyParser`: Historic pre-RFC 7230 / RFC 2616 (tolerates bare LF/CR, folds obs-fold, tolerates pre-colon whitespace, picks first CL).
     - `CDNProxyParser`: Cloud reverse proxy/WAF (unencodes path for RHI detection, handles `Expect: 100-continue`, prioritizes TE over CL).
     - `AsyncMicroserviceParser`: Event-driven gateway (detects dangling bytes $\rightarrow$ `408 Request Timeout`, validates hex chunk size).
   - **Defect Noted**: `engine/differential_oracle.py:116-139` contains a truncated duplicate method stub for `evaluate_divergence` without a return statement, which is subsequently re-defined at line 196.

6. **Module 16 (Google Research Harness²)**:
   - `engine/harness2_engine.py:87-135` defines `RFCHUNT_SURFACE` (`c1..c8`).
   - `engine/harness2_engine.py:465-515`: `Ledger` enforces exact budget identity ($R = 4k$ rollouts, $P = 3k$ stages), raising `BudgetError` on violation.
   - `engine/harness2_engine.py:538-637`: `Library` persists `INDEX.md` and `EXPERIENCE.md` per domain under `runs/harness2/<run_tag>/<mode>/<domain>/`.
   - `tests/test_harness2_integration.py`: Validates surface paths, script syntax checking, ledger identities, parallel/sequential execution, and library persistence.

7. **Subprocess Noise & Missing Host Containment**:
   - `build_all.py:179` and `engine/raptor_integrator.py:108, 166, 235, 323` invoke `subprocess.run` without passing `creationflags=0x08000000` (`CREATE_NO_WINDOW`) or `stdin=subprocess.DEVNULL`.
   - `engine/host_containment.py` does not currently exist in the repository.

---

## 2. Logic Chain

1. **Modules 1–16 Scope Verification**:
   - Traced `engine/orchestrator.py`, `rfc_hunt_swarm.py`, `README.md`, `tests/test_engine_12_modules.py`, and `tests/test_harness2_integration.py`.
   - Verified that all 16 modules are structurally mapped, implemented, and referenced in documentation and test suites.

2. **ABNF Grammars and Inversion Fidelity**:
   - Examined `engine/abnf_engine.py`. The regex pattern `ABNF_RULE_REGEX` extracts grammar rules from RFC texts.
   - Identified that `generate_inversions()` provides explicit mutations for OWS, header-field, chunk-ext, obs-fold, and transfer-coding, reflecting RFC 9112 and RFC 7230 edge cases.
   - Noted that multiline ABNF definitions with indented continuation lines (per RFC 5234 §2.1) are truncated by the single-line regex.

3. **3-Step Pipelined Canary & Multi-Trial Invariant**:
   - Traced `engine/sequence_engine.py:48-250`. The implementation strictly reads via `HTTPFramingReader.read_response`, passing `initial_bytes=framed.unconsumed_bytes` to subsequent steps on persistent sockets.
   - Confirmed that residual baseline HTML body bytes and RFC 9112 §6.1 un-framed body omissions are explicitly prevented from generating false positive leaks.
   - Traced `engine/delta_debugger.py:45-66`. Found that the loop runs `effective_trials = max(3, max_verification_trials)`. Findings with $< 3$ successes or $< 60\%$ reproducibility rate are automatically downgraded to `NonReproducibleTransient`, fulfilling the Protocol Research Reproducibility Invariant.

4. **Protocol Ruler Calibration & Verification**:
   - Traced `protocol_ruler.py`. Verified the two-phase calibration: stepped bracket search followed by binary search down to 1 byte.
   - Traced `test_protocol_ruler.py` and `test_lab_server.py`. Confirmed that `test_lab_server.py` simulates Kettle's overlong UTF-8 expansion (`\xc0\x8a` $\rightarrow$ 10-byte expansion, mutated cliff at 64,030 vs 64,040 baseline).

5. **4-Parser Differential Matrix**:
   - Examined `engine/differential_oracle.py:277-440`. All four parsers (`StrictRFC7230`, `PermissiveLegacy`, `CDNProxy`, `AsyncMicroservice`) execute in memory with zero external dependencies.
   - Discovered the duplicate stub at lines 116–139.

6. **Module 16 (Harness²)**:
   - Traced `engine/harness2_engine.py`. Verified that the eight components `c1..c8` are rigorously validated: character caps on `c1..c4` ($\le 24,000$), AST compilation on `c7` scripts, autotriggering of `c6` skills into `guardrails.md`, and path traversal blocking via `normalize_rel`.
   - Verified that `Ledger` raises `BudgetError` if $R \ne 4k$ or $P \ne 3k$.
   - Verified that `Library` writes both `INDEX.md` and `EXPERIENCE.md`.

---

## 3. Caveats

1. **Subprocess Silence**: In the current Windows environment, external subprocess calls in `build_all.py` and `engine/raptor_integrator.py` lack `CREATE_NO_WINDOW (0x08000000)` and `stdin=subprocess.DEVNULL`.
2. **Missing Module `engine/host_containment.py`**: The native host containment manager specified in R2 (Windows WFP dynamic session lifecycle and Linux netlink sockets) is not yet implemented.
3. **Dead Code in `differential_oracle.py`**: Lines 116–139 in `engine/differential_oracle.py` should be cleaned up by the implementation agent to eliminate the dead method stub.
4. **ABNF Multiline Support**: Rules spanning multiple lines in RFCs are currently parsed as single-line fragments. While core HTTP rules are preloaded in `CORE_HTTP_RULES`, dynamic extraction of complex multi-line rules from custom RFCs would benefit from indented continuation support.

---

## 4. Conclusion

The protocol research modules in `D:\harfile\rfchunt` are structurally mature and demonstrate high fidelity to James Kettle's DEF CON 34 methodology and Google Research's Harness² architecture.
The 3-step canary evaluation, 3-trial reproducibility gate, Protocol Ruler calibration, 4-parser differential matrix, and Harness² recursive harnessing are fully designed and verified with existing unit tests.
Remediating the duplicate stub in `engine/differential_oracle.py`, adding `CREATE_NO_WINDOW` to subprocess calls, and implementing `engine/host_containment.py` will bring the entire project into 100% compliance with the user request.

---

## 5. Verification Method

To independently verify the observations and logic in this report:

1. **Review Detailed Survey Report**:
   - Inspect `D:\harfile\rfchunt\.agents\teamwork\explorer_survey_1\report.md`.

2. **Inspect Code Locations**:
   - 16 Modules catalog: `D:\harfile\rfchunt\README.md:376-397` and `engine/orchestrator.py:4-17`
   - ABNF Engine & Inversions: `D:\harfile\rfchunt\engine\abnf_engine.py:21-36, 94-158`
   - 3-Step Canary Pipeline: `D:\harfile\rfchunt\engine\sequence_engine.py:48-264`
   - 3-Trial Reproducibility Invariant: `D:\harfile\rfchunt\engine\delta_debugger.py:45-66` and `engine/merkle_audit.py:16-68`
   - Protocol Ruler: `D:\harfile\rfchunt\protocol_ruler.py:146-300` and `test_protocol_ruler.py:14-75`
   - 4-Parser Differential Matrix: `D:\harfile\rfchunt\engine\differential_oracle.py:277-440` (and duplicate stub at lines 116–139)
   - Module 16 Harness²: `D:\harfile\rfchunt\engine\harness2_engine.py:87-135, 465-515, 538-637` and `tests/test_harness2_integration.py`

3. **Verify via Automated Tests**:
   - `py -3.12 -m pytest tests/test_engine_12_modules.py tests/test_harness2_integration.py tests/test_http_framing_and_pipeline.py test_protocol_ruler.py -v`
   - `py -3.12 -u main.py build --skip-tests`
