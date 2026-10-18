# Handoff Report: Challenger M2-1 (Adversarial ABNF & 4-Parser Matrix Fuzzing)

**Agent**: Challenger M2-1  
**Role**: Empirical Challenger / Critic / Specialist  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\challenger_m2_1`  
**Parent / Caller ID**: `48cb9587-3e1b-40a9-9a84-e3452d5f5108`  
**Date**: 2026-10-18  
**Verdict**: **`REQUEST_CHANGES`**

---

## Challenge Summary

**Overall risk assessment**: **HIGH**

While Worker M2 successfully removed the dead truncated stub in `engine/differential_oracle.py`, implemented the baseline 4-parser offline matrix, and introduced multi-line ABNF continuation support, adversarial stress-testing and fuzzing uncovered four concrete defects:
1. **[CRITICAL] Unhandled `ValueError` Crash on Extreme Content-Length Fuzzing**: Probes with >4,300 digits in `Content-Length` crash `AsyncMicroserviceParser` and tear down `evaluate_matrix_4parsers` due to Python 3.11+ `int()` string conversion limits without exception shielding.
2. **[HIGH] False-Positive `408 TIMEOUT` on Custom `X-Content-Length` Headers**: Unanchored regex in `AsyncMicroserviceParser` treats any custom header ending with `content-length:` (e.g. `X-Content-Length`) as the request body length.
3. **[HIGH] ABNF Nested Sub-Rule Swallowing**: When a grammar definition indents a child rule deeper than its parent rule, the continuation parser swallows the entire child rule definition into the parent rule.
4. **[MEDIUM] Strict RFC 7230 Parser Accepts Bare LF and Bare CR**: `StrictRFC7230Parser` only checks `b"\r\r" in head or b"\n\r" in head`, allowing bare `\n` and bare `\r` inside header values to be accepted with `200 OK` rather than rejected with `400 Bad Request`.

All findings are backed by empirical test proofs in `tests/test_adversarial_m2.py`.

---

## 1. Observation

1. **Crash in `engine/differential_oracle.py:397-400` & `engine/differential_oracle.py:134-136`**:
   In `AsyncMicroserviceParser.parse`:
   ```python
   cl_match = re.search(rb"content-length:\s*(\d+)", lower_head)
   if cl_match:
       declared_len = int(cl_match.group(1))
   ```
   In `MultiImplementationDifferentialOracle.evaluate_matrix_4parsers`:
   ```python
   responses: Dict[str, TargetResponse] = {}
   for p in parsers:
       responses[p.name] = p.parse(raw_probe)
   ```
   When fuzzed with an adversarial payload containing >4,300 digits of `Content-Length` (common in integer wrap-around vulnerability discovery):
   ```powershell
   py -3.12 -c "from engine.differential_oracle import MultiImplementationDifferentialOracle; MultiImplementationDifferentialOracle([]).evaluate_matrix_4parsers(b'POST / HTTP/1.1\r\nContent-Length: ' + (b'9' * 5000) + b'\r\n\r\n')"
   ```
   Verbatim error:
   ```
   ValueError: Exceeds the limit (4300 digits) for integer string conversion: value has 5000 digits; use sys.set_int_max_str_digits() to increase the limit
   ```
   Because `evaluate_matrix_4parsers` lacks `try...except`, the entire differential evaluation crashes.
   Empirically confirmed in `tests/test_adversarial_m2.py::test_challenge_finding_1_huge_content_length_crashes_matrix`.

2. **Unanchored Regex in `engine/differential_oracle.py:397`**:
   ```python
   cl_match = re.search(rb"content-length:\s*(\d+)", lower_head)
   ```
   When probe contains diagnostic or proxy headers like `X-Content-Length: 99999`:
   ```powershell
   py -3.12 -c "from engine.differential_oracle import AsyncMicroserviceParser; print(AsyncMicroserviceParser().parse(b'GET / HTTP/1.1\r\nHost: test\r\nX-Content-Length: 99999\r\n\r\n'))"
   ```
   Output:
   ```
   TargetResponse(target_name='AsyncMicroservice', status_code=408, headers={}, raw_response=b'', latency=0.1005, socket_state='TIMEOUT')
   ```
   This triggers a false-positive `408 TIMEOUT` and false parser divergence against conforming servers.
   Empirically confirmed in `tests/test_adversarial_m2.py::test_challenge_finding_2_custom_content_length_header_false_timeout`.

3. **Sub-rule Swallowing in `engine/abnf_engine.py:89-96`**:
   In `ABNFGrammarEngine.extract_from_rfc_text`:
   ```python
   cont_m = rule_head_re.match(next_line)
   if cont_m and len(cont_m.group(1)) <= indent:
       break
   next_indent = len(next_line) - len(next_line.lstrip(" \t"))
   if (next_line.startswith(" ") or next_line.startswith("\t")) and next_indent > indent:
       cont_text = _strip_abnf_comment(next_line).strip()
       if cont_text:
           body_parts.append(cont_text)
       i += 1
   ```
   When provided:
   ```abnf
   rule1 = val1
     rule2 = val2
   ```
   `cont_m` matches `rule2 = val2`, but `len(cont_m.group(1)) <= indent` (2 <= 0) is `False`. The loop continues, and `rule2 = val2` is appended to `rule1`'s definition. `rule2` is completely dropped from `self.extracted_rules`.
   Empirically confirmed in `tests/test_adversarial_m2.py::test_challenge_finding_3_abnf_rule_swallowing_deeper_indentation`.

4. **Incomplete Bare Delimiter Check in `engine/differential_oracle.py:268-270`**:
   In `StrictRFC7230Parser.parse`:
   ```python
   # Check for bare LF or bare CR inside head
   if b"\r\r" in head or b"\n\r" in head:
       return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid line terminator", time.time() - t0, "OK")
   ```
   When sent:
   `b"GET / HTTP/1.1\r\nHost: example.local\nInjected: evil\r\n\r\n"` (bare `\n`) or  
   `b"GET / HTTP/1.1\r\nHost: example.local\rInjected: evil\r\n\r\n"` (bare `\r`):
   Neither `b"\r\r"` nor `b"\n\r"` is present. `StrictRFC7230Parser` accepts the probe and returns `200 OK`, violating RFC 7230 §3.2.4 / RFC 9112 §2.2 strict rejection requirements.
   Empirically confirmed in `tests/test_adversarial_m2.py::test_challenge_finding_4_strict_parser_accepts_bare_lf_and_cr`.

---

## 2. Logic Chain

1. **Protocol Fuzzing Invariant**: Adversarial fuzz testing in HTTP research harnesses synthesizes extreme edge cases, including multibyte numeric strings to trigger integer overflows in target servers.
2. **Runtime Vulnerability**: Python 3.11+ enforces `sys.get_int_max_str_digits()` (default 4300) to mitigate algorithmic complexity attacks. Attempting `int()` on unvalidated regex captures without catching `ValueError` creates a denial of service in the fuzzing orchestrator.
3. **Differential Matrix Integrity**: Reference parsers must be robust and never raise unhandled exceptions. In addition, regex patterns parsing standard HTTP header fields (`Content-Length`) must match full header names anchored at the start of a line (`(?:^|\r\n)content-length:`), avoiding false positives on legitimate headers (`X-Content-Length`).
4. **Grammar Extraction Soundness**: RFC 5234 defines ABNF rules as `rulename = elements`. When extracting grammar rules, any line matching a rule definition header (`rulename = ...` or `rulename =/ ...`) represents the start of a distinct rule, regardless of its relative visual indentation.
5. **Strict Parser Fidelity**: RFC 9112 §2.2 explicitly mandates: *"A recipient MUST reject any received request message that contains bare CR or bare LF."* A strict reference model must enforce this across all header lines.

---

## 3. Caveats

1. Canonical IETF RFC files in `rfcs/` (e.g. `rfc9112.txt`, `rfc9110.txt`, `rfc7230.txt`) use uniform indentation (3 spaces), so sub-rule swallowing does not alter extraction from standard RFC files; it affects indented extracts, markdown specifications, errata, and fuzz inputs.
2. The 4 reference parsers are deterministic in-memory differential models designed for metamorphic testing, not full network HTTP servers.
3. The `ValueError` crash requires >4,300 decimal digits in `Content-Length`; smaller probes run without exception.

---

## 4. Challenges & Concrete Mitigations

### [Critical] Challenge 1: Unhandled `ValueError` in `AsyncMicroserviceParser` & Matrix Crash
- **Assumption challenged**: Assumed `int(cl_match.group(1))` will always convert cleanly.
- **Attack scenario**: Probe with 5,000-digit `Content-Length`.
- **Blast radius**: Crashes the entire differential oracle and halts the active scanning run.
- **Mitigation**:
  1. In `AsyncMicroserviceParser.parse`:
     ```python
     try:
         declared_len = int(cl_match.group(1))
     except (ValueError, OverflowError):
         return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid Content-Length", time.time() - t0, "OK")
     ```
  2. In `evaluate_matrix_4parsers`:
     ```python
     for p in parsers:
         try:
             responses[p.name] = p.parse(raw_probe)
         except Exception as e:
             responses[p.name] = TargetResponse(p.name, 500, {}, str(e).encode(), 0.0, "ERROR")
     ```

### [High] Challenge 2: Regex Overmatch on Custom `X-Content-Length` Headers
- **Assumption challenged**: Assumed `rb"content-length:\s*(\d+)"` only matches `Content-Length`.
- **Attack scenario**: Probe with `X-Content-Length: 99999` and an empty body.
- **Blast radius**: False-positive `408 TIMEOUT` and false parser divergence.
- **Mitigation**:
  Anchor regex to line beginning:
  ```python
  cl_match = re.search(rb"(?:^|\r\n)content-length:\s*(\d+)", lower_head)
  ```

### [High] Challenge 3: ABNF Nested Sub-Rule Swallowing
- **Assumption challenged**: Assumed sub-rules would never have deeper indentation than parent rules.
- **Attack scenario**: Grammar text with nested rule indentations (`rule1 = a\n  rule2 = b`).
- **Blast radius**: Loss of extracted specification rules and broken grammar inversion coverage.
- **Mitigation**:
  In `engine/abnf_engine.py:91`, break unconditionally whenever `cont_m` matches a rule definition:
  ```python
  cont_m = rule_head_re.match(next_line)
  if cont_m:
      break
  ```

### [Medium] Challenge 4: Bare LF / Bare CR Accepted by Strict Parser
- **Assumption challenged**: Assumed checking `b"\r\r" in head or b"\n\r" in head` was sufficient to catch bare line terminators.
- **Attack scenario**: Header lines with bare `\n` or bare `\r` (e.g. `Host: test\nInjected: evil`).
- **Blast radius**: Strict reference parser accepts non-conforming messages with `200 OK`, hiding real parser divergence.
- **Mitigation**:
  In `StrictRFC7230Parser.parse`:
  ```python
  head_no_crlf = head.replace(b"\r\n", b"")
  if b"\r" in head_no_crlf or b"\n" in head_no_crlf:
      return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nBare delimiter error", time.time() - t0, "OK")
  ```

---

## 5. Stress Test Results

| Test Scenario | Expected Behavior | Actual Behavior | Result |
|---|---|---|---|
| 64KB Chunk Extension (`test_differential_matrix_giant_chunk_extension`) | Parsed without crash, status 200/400 | Completed in 0.01s, status 200/400 | **PASS** |
| Dangling Bytes Detection (`test_differential_matrix_dangling_bytes_scenarios`) | AsyncMicroservice returns 408 TIMEOUT, Strict 200 | Returns 408 and 200, divergence flagged | **PASS** |
| Path RHI Injections (`test_differential_matrix_rhi_injections`) | CDNProxy detects Expect (417) and TE (501) | Returns 417 and 501, divergence flagged | **PASS** |
| Conflicting Headers (`test_differential_matrix_conflicting_headers`) | Strict rejects (400), Permissive accepts (200) | Strict=400, Permissive=200, divergence flagged | **PASS** |
| Matrix Determinism (`test_differential_matrix_reproducibility`) | 5 identical runs yield identical matrix results | 100% identical | **PASS** |
| ABNF Multiline & Comments (`test_abnf_multiline_with_pure_comment_lines`) | Interleaved comments stripped cleanly | Cleanly extracted | **PASS** |
| ABNF Massive Continuation (`test_abnf_massive_continuation_lines`) | 2000 continuation lines parsed in <1s | Parsed in 0.05s | **PASS** |
| 5000-digit Content-Length (`test_challenge_finding_1_huge_content_length_crashes_matrix`) | Safe rejection (400) or error response | Unhandled `ValueError` crash | **CONFIRMED DEFECT** |
| `X-Content-Length` (`test_challenge_finding_2_custom_content_length_header_false_timeout`) | Ignored as body length; returns 200 | False `408 TIMEOUT` | **CONFIRMED DEFECT** |
| Nested ABNF Indentation (`test_challenge_finding_3_abnf_rule_swallowing_deeper_indentation`) | Both rules extracted separately | `rule2` swallowed into `rule1` | **CONFIRMED DEFECT** |
| Bare LF in Header (`test_challenge_finding_4_strict_parser_accepts_bare_lf_and_cr`) | Rejected with 400 Bad Request | Accepted with 200 OK | **CONFIRMED DEFECT** |

---

## 6. Unchallenged Areas

- **HTTP/2 / HTTP/3 Binary Framing**: Evaluated canonical HTTP/1.1 wire framing and metamorphic differential matrix; HTTP/2 multiplexed frame parsing is handled by `H2GatewayDesyncBuilder` and `HPACKLite` and is scoped to subsequent milestones.

---

## 7. Conclusion

**Verdict: `REQUEST_CHANGES`**

Milestone 2 cannot be approved in its current state due to the unhandled crash in the differential matrix under adversarial fuzz payloads, false-positive timeouts on custom headers, grammar rule swallowing on indented sub-rules, and strict parser leniency toward bare LF/CR line terminators.

Worker M2 should apply the four targeted mitigations documented in Section 4. Once applied, all 16 tests in `tests/test_adversarial_m2.py` and the 15 tests in `tests/test_framing_and_matrix.py` will establish complete, resilient RFC compliance.

---

## 8. Verification Method

To independently verify all findings and stress tests:

1. **Execute Challenger M2-1 Adversarial Test Suite**:
   ```powershell
   py -3.12 -m pytest tests/test_adversarial_m2.py -v
   ```
   Confirms all 16 adversarial tests (including empirical defect proofs) execute in ~0.2s.

2. **Execute Worker M2 Baseline Framing & Matrix Test Suite**:
   ```powershell
   py -3.12 -m pytest tests/test_framing_and_matrix.py -v
   ```
   Confirms baseline test suite passes (15 passed).

3. **Verify Defect 1 Direct Reproduction**:
   ```powershell
   py -3.12 -c "from engine.differential_oracle import MultiImplementationDifferentialOracle; MultiImplementationDifferentialOracle([]).evaluate_matrix_4parsers(b'POST / HTTP/1.1\r\nContent-Length: ' + (b'9' * 5000) + b'\r\n\r\nbody')"
   ```
   Expected: `ValueError: Exceeds the limit (4300 digits) for integer string conversion`.
