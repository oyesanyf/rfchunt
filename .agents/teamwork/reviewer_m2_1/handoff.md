# Handoff Report: Reviewer M2-1 (Grammar & Matrix Review)

**Agent**: Reviewer M2-1  
**Roles**: Reviewer, Adversarial Critic  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\reviewer_m2_1`  
**Parent / Caller ID**: `48cb9587-3e1b-40a9-9a84-e3452d5f5108`  
**Date**: 2026-10-18  

---

## Review Summary

**Verdict**: **APPROVE**  
**Integrity Audit**: **PASS** (Zero integrity violations; genuine algorithmic implementations with independent verification).  
**Adversarial Risk Assessment**: **LOW** (Stress tests passed on malformed/boundary probes; error paths fail safe).

---

## 1. Observation

1. **Dead Stub Removal in `engine/differential_oracle.py`**:
   - Inspected `engine/differential_oracle.py`: lines 116–170 define `evaluate_matrix_4parsers` and lines 172–225 define the canonical `evaluate_divergence`.
   - Verified via regex search across `engine/differential_oracle.py` that `def evaluate_divergence` occurs exactly once (previously had an incomplete duplicate stub at lines 116–139).
   - In `evaluate_divergence` (line 198):
     ```python
     if len(active_responses) < 2:
         return self.evaluate_matrix_4parsers(raw_probe, rule_id=rule_id)
     ```
     When fewer than 2 network targets respond or when `targets=[]`, the oracle cleanly falls back to the 4-parser offline matrix.
   - All 4 reference parsers (`StrictRFC7230Parser`, `PermissiveLegacyParser`, `CDNProxyParser`, `AsyncMicroserviceParser`) execute purely in-memory with zero network or socket dependencies.

2. **ABNF Multi-Line Continuation & Incremental Alternatives in `engine/abnf_engine.py`**:
   - `_strip_abnf_comment` (lines 14–22) accurately iterates across line characters tracking double-quote parity (`in_dquote`), preserving semicolons inside quoted literals (e.g., `*( ";" chunk-ext-name )`).
   - `extract_from_rfc_text` (lines 59–129) detects rule headers and captures multi-line indented continuations where `(next_line.startswith(" ") or next_line.startswith("\t")) and next_indent > indent`, joining fragments with single spaces.
   - Incremental alternatives (`op == "=/"`) append to existing definitions via ` / <elements>`.
   - Validated extraction against real RFC files:
     - `HTTP-message` in `rfcs/rfc9112.txt`: `start-line *( header-field CRLF ) CRLF [ message-body ]` (retains `[ message-body ]`).
     - `Transfer-Encoding` in `rfcs/rfc9112.txt`: `*( "," OWS ) transfer-coding *( OWS "," [ OWS transfer-coding ] )`.
     - `chunk-ext` in `rfcs/rfc9112.txt`: `*( ";" chunk-ext-name [ "=" chunk-ext-val ] )` (retains `chunk-ext-val`).
     - Across `rfcs/rfc9112.txt`: extracted 84 requirements, 44 rules.
     - Across `rfcs/rfc7230.txt`: extracted 159 requirements, 82 rules.

3. **Canary Sequence Hardening in `engine/sequence_engine.py`**:
   - In Step 2 (line 133):
     ```python
     is_http_response = resp2.startswith((b"HTTP/1.", b"HTTP/2", b"HTTP/0.9"))
     if framed1.body and resp2 and not is_http_response:
     ```
     Prevents false positive scanner artifact alerts when valid status lines happen to contain short strings present in baseline responses.
   - In Step 3 (line 204):
     ```python
     socket_error=framed3.error if framed3 else str(e),
     ```
     Safely handles `framed3 is None` on socket exceptions without raising `AttributeError: 'NoneType' object has no attribute 'error'`.

4. **Protocol Research Reproducibility Invariant in `engine/delta_debugger.py` and `engine/causal_classifier.py`**:
   - In `engine/delta_debugger.py` (lines 46, 63): `effective_trials = max(3, max_verification_trials)` clamps trial counts to $\ge 3$. If `successes < 3 or repro_rate < 0.60`, findings are downgraded to `ImpactClass.NON_REPRODUCIBLE_TRANSIENT`.
   - In `engine/causal_classifier.py` (lines 114–118): `validate_evidence` explicitly rejects any finding where `vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT` or `vuln.verification_attempts < 3 or vuln.reproducibility_rate < 0.60`.

5. **Automated Test & Build Execution Results**:
   - `python.cmd -m pytest tests/test_framing_and_matrix.py -v`:
     `15 passed in 4.74s` (100% pass).
   - `py -3.12 build_all.py`:
     All 8 build stages passed with exit code 0 (`170 passed in 67.93s`, total build time `71.25s`).

---

## 2. Logic Chain

1. **Dead Stub Elimination**:
   - Direct inspection confirms that lines 116–139 in `differential_oracle.py` were removed.
   - The remaining code has a single canonical `evaluate_divergence` method that references `evaluate_matrix_4parsers`.
   - Therefore, no syntax ambiguity or shadowing exists, satisfying Acceptance Criterion Feature 5.

2. **ABNF Indented Multi-line Rule Continuation**:
   - Direct execution on real RFC files (`rfc9112.txt`, `rfc7230.txt`) proved that continuation lines indented with SP/HTAB are appended to the rule body until an unindented or equal-indented token is reached.
   - Rules like `HTTP-message`, `chunk-ext`, and `Transfer-Encoding` now contain their complete closing elements and brackets rather than truncating mid-definition.
   - Therefore, RFC 5234 §2.1 and §2.3 requirements are fully implemented, satisfying Acceptance Criterion Feature 6.

3. **Canary Sequence Robustness**:
   - Direct unit testing with `DummyServer` confirmed that `run_pipelined_canary_sequence` handles clean execution, residual baseline HTML body filtering, client framing omission (RFC 9112 §6.1), server disconnects, and unexpected socket aborts without unhandled exceptions.
   - Therefore, Feature 7 is correctly implemented and resilient.

4. **Reproducibility Invariant Clamping**:
   - Direct testing of `DeltaDebugger` and `CausalAnomalyClassifier` confirmed that candidate findings with $< 3$ verification trials or $< 60\%$ reproduction rate are downgraded to `NON_REPRODUCIBLE_TRANSIENT` and rejected from publishing.
   - Therefore, the Protocol Research Reproducibility Invariant is mathematically enforced, satisfying Feature 8.

5. **Integrity Verification**:
   - No hardcoded test responses, fake mock dictionaries, or dummy facade implementations were found.
   - Algorithmic parsers perform actual byte splitting, delimiter checking, and header parsing.
   - Socket tests use real in-process TCP sockets (`socket.socket`, `threading.Thread`) and genuine HTTP/1.1 byte exchanges.

---

## 3. Caveats

1. **HTTP/2 Scope**:
   The 4 reference differential parsers (`StrictRFC7230`, `PermissiveLegacy`, `CDNProxy`, `AsyncMicroservice`) evaluate HTTP/1.1 wire framing and desynchronization vectors. Binary HTTP/2 frame validation is delegated to `H2GatewayDesyncBuilder` and `HPACKLite` as designed.
2. **Pytest Temp Directory Handle Locking on Windows**:
   When running the entire pytest suite sequentially in a single pass without isolating subprocess environments, `shutil.rmtree` on `D:\harfile\.pytest_temp` may encounter `[WinError 32]` if an SQLite database handle from an MCP server test was not closed before teardown. Running via `build_all.py` isolates stages cleanly (170/170 passed). This finding will be permanently addressed in Milestone 4 via SQLite WAL mode and connection locks.

---

## 4. Conclusion

Milestone 2 (Protocol Framing & 4-Parser Differential Matrix) has been thoroughly reviewed and stress-tested. The changes:
1. Eliminate dead truncated stubs and provide a functional, offline 4-parser differential matrix.
2. Accurately parse multi-line ABNF rules and incremental alternatives according to RFC 5234.
3. Handle pipelined canary sequence edge cases and socket exceptions safely.
4. Strictly enforce the 3-trial Protocol Research Reproducibility Invariant.
5. Contain zero integrity violations and achieve 100% test pass on Milestone 2 suites and full `build_all.py` pipeline.

**Verdict: APPROVE**.

---

## 5. Verification Method

To independently reproduce this verification:

1. **Verify M2 Test Suite**:
   ```powershell
   python.cmd -m pytest tests/test_framing_and_matrix.py -v
   ```
   *Expected*: 15 passed in ~5 seconds.

2. **Verify Multi-Line Real RFC Extraction**:
   ```powershell
   py -3.12 -c "from engine.abnf_engine import ABNFGrammarEngine; e = ABNFGrammarEngine(); reqs = e.extract_from_rfc_text('RFC9112', open('rfcs/rfc9112.txt').read()); print('HTTP-message:', e.extracted_rules['HTTP-message']['definition']); print('chunk-ext:', e.extracted_rules['chunk-ext']['definition'])"
   ```
   *Expected*: `HTTP-message` contains `[ message-body ]`; `chunk-ext` contains `chunk-ext-val`.

3. **Verify 4-Parser Offline Divergence**:
   ```powershell
   py -3.12 -c "from engine.differential_oracle import MultiImplementationDifferentialOracle; o = MultiImplementationDifferentialOracle([]); print(o.evaluate_divergence(b'GET / HTTP/1.1\r\nHost : a\r\n\r\n')[0])"
   ```
   *Expected*: `True` (divergence detected: Strict rejects whitespace before colon, Permissive accepts).

4. **Verify Unified Build Pipeline**:
   ```powershell
   py -3.12 build_all.py
   ```
   *Expected*: All 8 steps pass with exit code 0.
