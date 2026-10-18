# Dispatch Assignment: Worker M2 (Protocol Framing & 4-Parser Differential Matrix)

## Identity
- Role: Worker (Protocol Framing Implementation & Verification)
- Working Directory: D:\harfile\rfchunt\.agents\teamwork\worker_m2

## Objective
Read:
- `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md`
- `D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_survey_1\report.md`

Implement Milestone 2:
1. **Clean up `engine/differential_oracle.py`**:
   - Remove the dead, truncated method stub at lines 116–139.
   - Ensure the 4 reference parsers (`StrictRFC7230Parser`, `PermissiveLegacyParser`, `CDNProxyParser`, `AsyncMicroserviceParser`) operate cleanly offline without network access.
2. **Harden `engine/abnf_engine.py`**:
   - Update ABNF grammar parser to support multi-line indented continuation rules per RFC 5234 §2.1.
   - Verify ABNF rule inversion synthesis across RFC 9112, 9110, 9113, 7230, and 2616.
3. **Verify & Harden 3-Step Pipelined Canary Sequence (`engine/sequence_engine.py`)**:
   - Ensure `REQ 1` (clean baseline), `REQ 2` (candidate probe), and `REQ 3` (canary check) strictly enforce `HTTPFramingReader` (RFC 9112 §6).
   - Ensure scanner artifacts (residual baseline HTML body bytes) are cleanly recognized and filtered.
   - Ensure connection closures and timeout-based desync probes operate cleanly without uncaught socket exceptions.
4. **Enforce 3-Trial Protocol Research Reproducibility Invariant**:
   - In `engine/delta_debugger.py`, `engine/merkle_audit.py`, and `engine/causal_classifier.py`:
     Verify that candidate findings undergo >= 3 repeated trials and require >= 60% reproducibility rate before promotion; otherwise, ensure clean downgrade to `ImpactClass.NON_REPRODUCIBLE_TRANSIENT`.
5. **Add Comprehensive Unit Tests**:
   - Add/update tests in `tests/test_differential_matrix.py` or `tests/test_framing_and_matrix.py` verifying:
     - Dead stub removal in `differential_oracle.py`
     - Multi-line indented ABNF rule extraction
     - 4-parser differential divergence matrix offline behavior
     - 3-trial stability requirement enforcement
6. **Run Verification**:
   - `python.cmd -m pytest tests/ -v`
   - `python.cmd -m pytest test_protocol_ruler.py -v`
   - `python.cmd build_all.py`

## Mandatory Integrity Warning
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Write Ownership
- `engine/differential_oracle.py`
- `engine/abnf_engine.py`
- `engine/sequence_engine.py`
- `engine/delta_debugger.py`
- `engine/causal_classifier.py`
- `tests/test_framing_and_matrix.py`

## Output
Write your handoff report to:
`D:\harfile\rfchunt\.agents\teamwork\worker_m2\handoff.md`
Send a completion message back to the orchestrator.


## 2026-10-18T19:05:15Z
[Message] timestamp=2026-10-18T19:05:15Z sender=48cb9587-3e1b-40a9-9a84-e3452d5f5108 priority=MESSAGE_PRIORITY_HIGH content=You are Worker M2 (Protocol Framing & 4-Parser Differential Matrix).
Your working directory is: D:\harfile\rfchunt\.agents\teamwork\worker_m2
Read:
- D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md
- D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md
- D:\harfile\rfchunt\.agents\teamwork\explorer_survey_1\report.md
- D:\harfile\rfchunt\.agents\teamwork\worker_m2\DISPATCH.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your write ownership:
- engine/differential_oracle.py
- engine/abnf_engine.py
- engine/sequence_engine.py
- engine/delta_debugger.py
- engine/causal_classifier.py
- tests/test_framing_and_matrix.py

Implement Milestone 2:
1. Remove dead truncated stub in engine/differential_oracle.py:116-139.
2. Harden engine/abnf_engine.py to support multi-line indented ABNF rule continuations (RFC 5234 §2.1).
3. Verify 3-step canary sequence in engine/sequence_engine.py (REQ 1 baseline, REQ 2 probe, REQ 3 canary, HTTPFramingReader, artifact filtering).
4. Verify 3-trial stability invariant in engine/delta_debugger.py (effective_trials >= 3, repro_rate >= 0.60).
5. Add comprehensive unit tests in tests/test_framing_and_matrix.py.
6. Verify all tests pass (python.cmd -m pytest tests/ test_protocol_ruler.py -v) and python.cmd build_all.py passes.
7. Write handoff to D:\harfile\rfchunt\.agents\teamwork\worker_m2\handoff.md and message orchestrator when done.
