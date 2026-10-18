# Dispatch Assignment: Worker M2 Remediation (Challenger Findings Mitigation)

## Identity
- Role: Worker (Milestone 2 Remediation Implementation)
- Working Directory: D:\harfile\rfchunt\.agents\teamwork\worker_m2_rem_1

## Objective
Read:
- `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md`
- `D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md`
- `D:\harfile\rfchunt\.agents\teamwork\challenger_m2_1\handoff.md`

Implement the 4 targeted mitigations identified by Challenger M2-1:
1. **In `engine/differential_oracle.py` (AsyncMicroserviceParser & Matrix Crash Shield)**:
   - In `AsyncMicroserviceParser.parse`: wrap `declared_len = int(cl_match.group(1))` in `try...except (ValueError, OverflowError): return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid Content-Length", time.time() - t0, "OK")`.
   - In `evaluate_matrix_4parsers`: wrap `p.parse(raw_probe)` in `try...except Exception as e:` returning `TargetResponse(p.name, 500, {}, str(e).encode(), 0.0, "ERROR")`.
2. **In `engine/differential_oracle.py` (Content-Length Line Anchoring)**:
   - In `AsyncMicroserviceParser.parse`: anchor Content-Length regex to line beginning:
     `cl_match = re.search(rb"(?:^|\r\n)content-length:\s*(\d+)", lower_head)` so headers like `X-Content-Length` are not misidentified as body length.
3. **In `engine/abnf_engine.py` (Sub-rule Indentation Swallowing)**:
   - In `extract_from_rfc_text`: when checking subsequent lines, if `cont_m = rule_head_re.match(next_line)` matches a rule definition, unconditionally `break` so child rules indented deeper than parent rules are not swallowed into parent definitions.
4. **In `engine/differential_oracle.py` (Strict Parser Bare LF / Bare CR Rejection)**:
   - In `StrictRFC7230Parser.parse`: strip standard CRLFs via `head_no_crlf = head.replace(b"\r\n", b"")`. If `b"\r"` or `b"\n"` remains in `head_no_crlf`, return `400 Bad Request` with `b"HTTP/1.1 400 Bad Request\r\n\r\nBare delimiter error"`.
5. **Update Tests**:
   - Update `tests/test_adversarial_m2.py` and `tests/test_framing_and_matrix.py` to assert the remediated conforming behavior (e.g. 5000-digit Content-Length returns 400 Bad Request without crashing; X-Content-Length returns 200 without timeout; sub-rules are extracted independently; bare LF/CR returns 400 Bad Request).
6. **Run Verification**:
   - `python.cmd -m pytest tests/test_framing_and_matrix.py tests/test_adversarial_m2.py -v`
   - `python.cmd -m pytest tests/ test_protocol_ruler.py -q`
   - `python.cmd build_all.py`

## Mandatory Integrity Warning
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Write Ownership
- `engine/differential_oracle.py`
- `engine/abnf_engine.py`
- `tests/test_adversarial_m2.py`
- `tests/test_framing_and_matrix.py`

## Output
Write your handoff report to `D:\harfile\rfchunt\.agents\teamwork\worker_m2_rem_1\handoff.md`.
Send a completion message back to the orchestrator.

## 2026-10-18T19:36:56Z
You are Worker M2 Remediation.
Your working directory is: D:\harfile\rfchunt\.agents\teamwork\worker_m2_rem_1
Read:
- D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md
- D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md
- D:\harfile\rfchunt\.agents\teamwork\challenger_m2_1\handoff.md
- D:\harfile\rfchunt\.agents\teamwork\worker_m2_rem_1\DISPATCH.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your write ownership:
- engine/differential_oracle.py
- engine/abnf_engine.py
- tests/test_adversarial_m2.py
- tests/test_framing_and_matrix.py

Implement the 4 mitigations from Challenger M2-1:
1. Shield AsyncMicroserviceParser against ValueError on huge Content-Length and wrap evaluate_matrix_4parsers loop in try/except.
2. Line-anchor Content-Length regex in AsyncMicroserviceParser (prevent X-Content-Length false timeout).
3. Fix sub-rule indentation swallowing in ABNFGrammarEngine.extract_from_rfc_text (break unconditionally if rule_head_re matches).
4. Enforce strict rejection of bare LF / bare CR in StrictRFC7230Parser.parse (head.replace(b'\r\n', b'')).
5. Update tests and run full verification:
   - python.cmd -m pytest tests/test_framing_and_matrix.py tests/test_adversarial_m2.py -v
   - python.cmd -m pytest tests/ test_protocol_ruler.py -q
   - python.cmd build_all.py
6. Write handoff to D:\harfile\rfchunt\.agents\teamwork\worker_m2_rem_1\handoff.md and message orchestrator when done.

