# Handoff Report: Challenger M2-2 (3-Trial Invariant & Canary Stress Test)

**Agent**: Challenger M2-2  
**Role**: Adversarial Challenger (critic, specialist)  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\challenger_m2_2`  
**Parent / Caller ID**: `48cb9587-3e1b-40a9-9a84-e3452d5f5108`  
**Verdict**: **APPROVE**  
**Date**: 2026-10-18  

---

## 1. Observation

1. **Protocol Research Reproducibility Invariant Verification**:
   - `engine/delta_debugger.py:46-66` enforces:
     ```python
     effective_trials = max(3, max_verification_trials)
     successes = 0
     for _ in range(effective_trials):
         if evaluator(minimized):
             successes += 1
         time.sleep(0.05)
     repro_rate = successes / effective_trials if effective_trials > 0 else 0.0
     if successes < 3 or repro_rate < 0.60:
         impact = ImpactClass.NON_REPRODUCIBLE_TRANSIENT
         provenance.append("Downgraded to NonReproducibleTransient: Failed minimum 3-trial stability requirement.")
     ```
   - `engine/causal_classifier.py:113-119` enforces the downstream gate:
     ```python
     if vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT:
         return False, "Finding was classified as NonReproducibleTransient; failed minimum 3-trial stability requirement."
     if vuln.verification_attempts < 3 or vuln.reproducibility_rate < 0.60:
         return False, f"Low reproducibility rate ({vuln.successful_reproductions}/{vuln.verification_attempts}, {vuln.reproducibility_rate:.1%}); failed minimum 3-trial stability requirement."
     ```
   - When empirically tested against flaky evaluators:
     * 0/3 successes (0% repro rate) -> `vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT`, `validate_evidence` returns `False`.
     * 1/3 successes (33.3% repro rate) -> `vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT`, `validate_evidence` returns `False`.
     * 2/3 successes (66.7% repro rate): even though repro rate $\ge 60\%$, total successes is $2 < 3$ -> `vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT`, `validate_evidence` returns `False`.
     * 3/3 successes (100% repro rate) -> `vuln.impact != ImpactClass.NON_REPRODUCIBLE_TRANSIENT`, `validate_evidence` returns `True`.
     * Clamping: passing `max_verification_trials` in `[0, 1, 2, -1, -100]` yields `effective_trials >= 3` in 100% of cases.
     * Extended trials: 2/5 (40%) and 5/10 (50%) are downgraded to `NON_REPRODUCIBLE_TRANSIENT`; 3/5 (60%) and 6/10 (60%) pass.
     * `engine/merkle_audit.py` accepts and commits `NON_REPRODUCIBLE_TRANSIENT` with RFC 6962 0x00 leaf hashing and valid Merkle root derivation.

2. **3-Step Pipelined Canary Sequence under Simulated Network Disconnection**:
   - `engine/sequence_engine.py` was tested against raw wire network drop conditions on real localhost TCP sockets:
     * Connection Refused (closed port): returns cleanly with `has_desynchronization = False`, `has_pipeline_leak = False`.
     * Step 1 Disconnects: Immediate EOF (0 bytes), TCP RST mid-headers (`SO_LINGER` l_onoff=1, l_linger=0), Premature EOF mid-body (`Content-Length: 100` with 10 bytes received), and socket timeout halt the pipeline at Step 1 with `has_desynchronization = False`, `has_pipeline_leak = False`.
     * Step 1 `Connection: close`: halts immediately, recognizing persistent pipelining is not supported.
     * Step 2 Disconnects: Immediate TCP RST, server 400 error with `Connection: close`, and 500 error with close cleanly terminate Step 3 with `has_desynchronization = False`, `has_pipeline_leak = False`.
     * Step 2 -> Step 3 Transition Disconnect: Abrupt TCP RST before Step 3 read resulted in `framed3 = None`; `socket_error=framed3.error if framed3 else str(e)` in line 204 safely prevented `AttributeError: 'NoneType' object has no attribute 'error'`.
     * Step 3 Timeout: recorded cleanly in `step3.socket_error` without unhandled exceptions.

3. **Short Baseline Body Response Handling**:
   - Tested variations:
     * `Content-Length: 0` (`b""`): completes 3 steps cleanly without false artifact abortion.
     * `204 No Content` (RFC 9112 §6.3 item 1): completes 3 steps cleanly (`has_desynchronization = False`).
     * `304 Not Modified` (RFC 9112 §6.3 item 1): completes 3 steps cleanly.
     * 1-byte body (`Content-Length: 1`, `b"Z"`): completes 3 steps cleanly.
     * 2-byte body (`Content-Length: 2`, `b"OK"`): line 133 `is_http_response = resp2.startswith((b"HTTP/1.", b"HTTP/2", b"HTTP/0.9"))` prevents false positive scanner artifact abortion when Step 2 probe returns `HTTP/1.1 200 OK`.
     * Batched socket buffer preservation: `HTTPFramingReader` consumes exact baseline body (`b"OK"`), places subsequent pipelined bytes (`b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\nPONG"`) into `unconsumed_bytes`, which are successfully consumed in Step 2 without waiting for extra network segments.
     * True non-HTTP residual body echo (`b"UNIQUE_BASELINE_PAYLOAD_ABC123"`): correctly flagged as `"Scanner Artifact: Residual baseline response bytes detected on socket; not a pipeline leak."`
     * Valid Desynchronizations: Timeout CL/TE (`Timeout-Based Desynchronization`), queue poisoning markers (`Queue Desynchronization`), and framing leaks corrupting canary to 400 (`Pipeline Leak`) all trigger positive detection correctly.

4. **Empirical Test Suite Execution**:
   - `tests/test_challenger_m2_empirical.py` (28 dedicated adversarial tests): 28 passed in 5.61s.
   - Combined Milestone 2 test suites (`tests/test_framing_and_matrix.py` + `tests/test_challenger_m2_empirical.py`): 43 passed in 10.13s.
   - Full unified build `py -3.12 build_all.py`: all 8 stages passed, 201 total tests passed in 64.46s with exit code 0.

---

## 2. Logic Chain

1. **Protocol Research Reproducibility Invariant Soundness**:
   - From Observation 1, the condition `if successes < 3 or repro_rate < 0.60:` mathematically ensures that neither a high reproduction rate with insufficient trials (e.g. 2/3 = 66.7%, but $2 < 3$) nor an adequate trial count with low rate (e.g. 5/10 = 50% < 60%) can ever be classified as confirmed.
   - Because `effective_trials = max(3, max_verification_trials)`, any caller attempting to bypass multi-trial confirmation by specifying 1 or 2 trials is clamped to at least 3 trials.
   - Downstream, `CausalAnomalyClassifier.validate_evidence` checks both `vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT` and `vuln.verification_attempts < 3 or vuln.reproducibility_rate < 0.60`, preventing transient findings from reaching weaponization, rule generation, or active defenses.

2. **Canary Sequence Robustness under Network Faults**:
   - From Observation 2, every step of the 3-step persistent connection lifecycle is wrapped in exception handling and state validation.
   - In Step 1, failures in TCP handshake, header parsing, body consumption, or non-persistent `Connection: close` immediately halt execution, preventing subsequent steps on a broken connection.
   - In Step 2, server error responses (400/500 with close) are recognized as expected HTTP error behavior rather than pipeline contamination.
   - In Step 3, the `framed3 is not None` guard guarantees that abrupt socket RSTs or EOF conditions do not trigger `AttributeError`, and connection drop is cleanly reported.

3. **Short Baseline Body Resilience**:
   - From Observation 3, RFC 9112 §6.3 item 1 zero-body responses (204, 304, HEAD) and `Content-Length: 0` are handled natively without stalling or false buffer overflow.
   - The addition of `is_http_response` guard in `engine/sequence_engine.py:133` completely resolves the false-positive scanner artifact defect for short bodies like `b"OK"` while preserving true artifact detection for non-HTTP body reflections.

4. **Independent Verification**:
   - 28 dedicated empirical stress tests were written in `tests/test_challenger_m2_empirical.py` and executed on real localhost sockets.
   - All 28 tests passed.
   - The unified build pipeline `build_all.py` passed all 8 stages and 201 total tests with exit code 0.

---

## 3. Caveats

1. **OS-Level SQLite Concurrency on Windows**:
   - During continuous multi-file pytest runs, running with `--basetemp` on Windows can encounter transient `PermissionError: [WinError 32]` if another process or unclosed SQLite handle accesses `.pytest_temp`. Cleaning `.pytest_temp` prior to runs resolves this completely. Milestone 4 has scheduled dedicated tasks for SQLite WAL mode and concurrency locks.
2. **TLS Invariance**:
   - The adversarial tests used cleartext HTTP/1.1 TCP sockets. TLS wrapping uses Python's standard `ssl.wrap_socket`, which follows the identical `socket` interface semantics tested here.

---

## 4. Conclusion

**Verdict: APPROVE**

Milestone 2 (Protocol Framing & 4-Parser Differential Matrix) has passed all empirical challenges without defect:
1. The 3-trial Protocol Research Reproducibility Invariant strictly enforces $\ge 3$ trials and $\ge 60\%$ stability, automatically downgrading flakes (including 0/3, 1/3, 2/3, 2/5, 5/10) to `NonReproducibleTransient` and blocking downstream publication.
2. The 3-step pipelined canary sequence gracefully survives simulated network disconnections, immediate TCP RSTs, premature EOFs, and socket timeouts across all three steps without unhandled exceptions or false positive pipeline leaks.
3. Short baseline bodies (0 bytes, 204 No Content, 304 Not Modified, 1 byte, 2 bytes `b"OK"`) are processed with exact byte accounting and zero false artifact rejections.
4. All 201 tests and all 8 build stages pass with exit code 0.

---

## 5. Verification Method

To independently reproduce and verify this empirical challenge:

1. **Execute Challenger Empirical Stress Suite**:
   ```powershell
   py -3.12 -m pytest tests/test_challenger_m2_empirical.py -v
   ```
   Expected: 28 passed in ~5.6s.

2. **Execute Full Milestone 2 Test Suites**:
   ```powershell
   py -3.12 -m pytest tests/test_framing_and_matrix.py tests/test_challenger_m2_empirical.py -v
   ```
   Expected: 43 passed in ~10.1s.

3. **Execute Full Unified Build Pipeline**:
   ```powershell
   py -3.12 build_all.py
   ```
   Expected: All 8 stages pass, 201 tests passed in ~64s, exit code 0.
