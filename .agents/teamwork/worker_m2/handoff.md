# Handoff Report: Worker M2 (Protocol Framing & 4-Parser Differential Matrix)

**Agent**: Worker M2  
**Role**: Implementer / QA / Specialist  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\worker_m2`  
**Parent / Caller ID**: `48cb9587-3e1b-40a9-9a84-e3452d5f5108`  
**Date**: 2026-10-18  

---

## 1. Observation

1. **Dead Truncated Stub in `engine/differential_oracle.py:116-139`**:
   `engine/differential_oracle.py` contained an incomplete duplicate definition of `evaluate_divergence` (lines 116–139) that collected responses into `matrix` but lacked return statements or divergence evaluation. The actual full implementation was defined downstream at line 196.
   `git grep -n "def evaluate_divergence"` showed 2 occurrences.

2. **ABNF Single-Line Truncation in `engine/abnf_engine.py`**:
   The existing regular expression `ABNF_RULE_REGEX = re.compile(r"^[ \t]*([a-zA-Z][a-zA-Z0-9_-]*)[ \t]*=[ \t]*(.+?)(?=;.*)?$", re.MULTILINE)` failed to parse multi-line indented continuation rules per RFC 5234 §2.1.
   When evaluated on `rfcs/rfc9112.txt`:
   - `HTTP-message` was truncated to `start-line CRLF *( field-line CRLF ) CRLF [` (missing `message-body ]`).
   - `Transfer-Encoding` was truncated to `[ transfer-coding *( OWS "," OWS transfer-coding` (missing trailing `]`).
   - `chunk-ext` was truncated to `*( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val`.
   - Trailing comments with semicolons inside double quotes (`";"`) were improperly parsed.
   - Incremental alternatives (`=/` per RFC 5234 §2.3) were not aggregated into existing rule definitions.

3. **Canary Sequence Edge Cases in `engine/sequence_engine.py`**:
   In `run_pipelined_canary_sequence`:
   - Line 198 evaluated `socket_error=framed3.error`. In cases where `sock.sendall` or `HTTPFramingReader.read_response` threw an exception, `framed3` was set to `None`, causing an unhandled `AttributeError: 'NoneType' object has no attribute 'error'`.
   - Scanner artifact detection checked `resp2 in framed1.body`. For short baseline bodies like `b"OK"` (length 2), every subsequent `HTTP/1.1 200 OK` response matched `"OK"`, falsely aborting valid pipelined canary checks as scanner artifacts.

4. **Reproducibility Invariant Consistency in `engine/causal_classifier.py`**:
   `CausalAnomalyClassifier.validate_evidence` checked `vuln.reproducibility_rate < 0.66` rather than aligning with the 60% requirement (`< 0.60`), did not explicitly reject findings classified as `ImpactClass.NON_REPRODUCIBLE_TRANSIENT`, and did not check `vuln.verification_attempts < 3`.

5. **Test Coverage Baseline**:
   Prior to changes, `tests/test_framing_and_matrix.py` did not exist. The full suite had 142 tests.

---

## 2. Logic Chain

1. **Dead Stub Elimination**:
   Removing lines 116–139 in `engine/differential_oracle.py` leaves a single canonical `evaluate_divergence` definition that dispatches to target endpoints and cleanly falls back to `evaluate_matrix_4parsers` when fewer than 2 network targets respond. All 4 reference parsers (`StrictRFC7230Parser`, `PermissiveLegacyParser`, `CDNProxyParser`, `AsyncMicroserviceParser`) execute purely in-memory and offline with 0 network dependencies.

2. **RFC 5234 §2.1 & §2.3 Compliance in `engine/abnf_engine.py`**:
   - Implemented `_strip_abnf_comment` to strip trailing comments (`';'`) while preserving semicolons inside quoted strings (`'\"'`).
   - Hardened `extract_from_rfc_text` to parse the rule header and iterate over subsequent lines: if a subsequent line begins with linear whitespace (SP or HTAB) and is indented deeper than the rule header without starting a new rule, its text is appended to the rule definition separated by a single space.
   - When operator is `=/` (RFC 5234 §2.3 incremental alternatives), new elements are appended to existing definitions via ` / <elements>`.
   - Extended `generate_inversions` and `generate_conforming` across RFC 9112, 9110, 9113, 7230, and 2616 rules: `OWS`, `BWS`, `RWS`, `header-field`, `field-line`, `field-name`, `field-value`, `chunk-ext`, `obs-fold`, `transfer-coding`, `transfer-encoding`, `request-line`, `status-line`, `tchar`, and `pseudo-header`.

3. **Pipelined Canary Sequence Hardening in `engine/sequence_engine.py`**:
   - In Step 2, added `is_http_response = resp2.startswith((b"HTTP/1.", b"HTTP/2", b"HTTP/0.9"))`. Scanner artifact detection only activates if `not is_http_response`, preventing false positives when standard status lines contain words appearing in the baseline body.
   - In Step 3, updated `socket_error=framed3.error if framed3 else str(e)` to safely handle cases where `framed3` is `None` due to socket disconnects.
   - Preserved client framing omission filtering (RFC 9112 §6.1) and connection teardown recognition (server closes on 400).

4. **Reproducibility Invariant Enforcement**:
   - `DeltaDebugger.minimize_and_reproduce` enforces `effective_trials = max(3, max_verification_trials)` and downgrades to `ImpactClass.NON_REPRODUCIBLE_TRANSIENT` when `successes < 3 or repro_rate < 0.60`.
   - `CausalAnomalyClassifier.validate_evidence` explicitly rejects any finding with `vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT` or `vuln.verification_attempts < 3 or vuln.reproducibility_rate < 0.60`.

5. **Comprehensive Unit & Integration Test Suite**:
   Created `tests/test_framing_and_matrix.py` with 15 dedicated tests validating dead stub removal, 4-parser offline behavior, multi-line ABNF extraction, incremental alternatives, multi-RFC inversions, 3-step pipelined canary sequence execution, scanner artifact filtering, client framing omission, connection teardown, exception handling, and 3-trial stability invariant enforcement.

---

## 3. Caveats

1. **Host Environment Git Subprocess Limitation**:
   Attempting to execute `git status -s` directly via subprocess on this host environment yielded `OSError: [WinError 122] The data area passed to a system call is too small`. This is an OS-level environment/sandbox buffer limitation with `git.exe` on this specific runner. All workspace and test files are fully written and verified in `D:\harfile\rfchunt`.
2. **Offline 4-Parser Scope**:
   The 4 algorithmic parsers (`StrictRFC7230`, `PermissiveLegacy`, `CDNProxy`, `AsyncMicroservice`) model canonical HTTP/1.1 framing behavior. They are designed for differential metamorphic comparison and do not support full HTTP/2 or HTTP/3 binary frame decoding (which is handled by `H2GatewayDesyncBuilder` and `HPACKLite`).

---

## 4. Conclusion

Milestone 2 (Protocol Framing & 4-Parser Differential Matrix) is complete and 100% verified:
1. `engine/differential_oracle.py` has no dead stubs; `evaluate_divergence` falls back cleanly to the 4-parser offline matrix.
2. `engine/abnf_engine.py` extracts multi-line indented ABNF rules and incremental alternatives per RFC 5234 §2.1/§2.3 and synthesizes boundary inversions across 5 RFC specifications.
3. `engine/sequence_engine.py` executes robust 3-step canary evaluation with framing verification, artifact filtering, and exception safety.
4. `engine/delta_debugger.py` and `engine/causal_classifier.py` enforce the 3-trial Protocol Research Reproducibility Invariant ($\ge 3$ trials, $\ge 60\%$ repro rate).
5. All 157 automated pytest tests pass cleanly in 57.12s.
6. `build_all.py` passes all 8 build stages end-to-end with exit code 0 in 61.67s.

---

## 5. Verification Method

To independently verify this milestone:

1. **Verify Dead Stub Removal**:
   ```powershell
   py -3.12 -c "from engine.differential_oracle import MultiImplementationDifferentialOracle; o = MultiImplementationDifferentialOracle([]); print(o.evaluate_divergence(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')[0])"
   ```

2. **Verify Multi-Line ABNF Grammar Extraction**:
   ```powershell
   py -3.12 -c "from engine.abnf_engine import ABNFGrammarEngine; e = ABNFGrammarEngine(); reqs = e.extract_from_rfc_text('RFC9112', open('rfcs/rfc9112.txt').read()); print('HTTP-message:', e.extracted_rules.get('HTTP-message'))"
   ```

3. **Execute Milestone 2 Test Suite**:
   ```powershell
   py -3.12 -m pytest tests/test_framing_and_matrix.py -v
   ```
   Expected: 15 passed in ~5 seconds.

4. **Execute Full Test Suite**:
   ```powershell
   py -3.12 -m pytest tests/ test_protocol_ruler.py -v
   ```
   Expected: 157 passed in ~58 seconds.

5. **Execute Unified Build Pipeline**:
   ```powershell
   py -3.12 build_all.py
   ```
   Expected: All 8 stages pass, exit code 0.
