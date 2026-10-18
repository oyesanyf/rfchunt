# Protocol Ruler & Calibration Investigation Report (M3-2)

**Author**: Explorer M3-2 (Protocol Ruler & Calibration Specialist)  
**Date**: 2026-10-18T20:09:00Z  
**Target Codebase**: `protocol_ruler.py`, `test_protocol_ruler.py`, `test_lab_server.py`, `engine/http_framing.py`  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_2`  
**Reference Invariants**: `ORIGINAL_REQUEST.md` (R1, Acceptance Criteria), `protocol_research_reproducibility.md`, `no_mocks_write_actual_code.md`

---

## Executive Summary

An exhaustive investigation of the Protocol Ruler engine (`protocol_ruler.py`) and its automated verification suite (`test_protocol_ruler.py`) was conducted. The Protocol Ruler implements James Kettle's benchmark technique from *"Can AI do novel security research?"*, using backend HTTP header length limits as a precision ruler to detect front-end byte mutations (expansions, normalizations, contractions, and IP spoofing header transformations) without requiring header reflection.

While the baseline concept is sound and the 6 existing tests pass, the investigation uncovered **critical defects in resource management, calibration logic, and anomaly classification**:
1. **Critical Resource Leak in Socket Exception Paths**: In `send_probe()`, `sock.close()` is located inside the `try` block. If `sendall()` or `read_response()` raises a socket error or times out, the socket is never closed due to the lack of a `finally` block, leaking OS file descriptors during intensive boundary probing.
2. **Bracket Calibration Defect on Custom `min_size`**: `calibrate_baseline_limit()` fails to insert `min_size` into `brackets` when `min_size` does not match the hardcoded bracket list. Consequently, if a backend's limit is lower than `1024` (e.g. 800 bytes with `min_size=500`), the ruler skips probing `min_size`, tests `1024` first, receives HTTP 400, and erroneously aborts claiming the server rejected `min_size`.
3. **Severe False-Positive Expansion Defect on Rejections**: In `measure_sequence_transformation()`, `last_ok` is initialized to `low_bound`. If a sequence is rejected outright at all lengths (e.g. invalid syntax, WAF block, or NUL byte), `is_error_boundary()` is always `True`, leaving `mutated_limit = low_bound`. The method then misreports a massive `search_radius` expansion (`delta = +128`) and logs `A: ... -> 400 OK`.
4. **Missing HTTP Error Status Codes**: `is_error_boundary()` omits HTTP `413` (Content Too Large) and `500` (Internal Server Error buffer crashes), leading to false positives if backends return 413 or 500 on buffer overflow.
5. **Absence of 3-Trial Reproducibility Confirmation**: Neither `calibrate_baseline_limit` nor `measure_sequence_transformation` enforces the mandatory 3-trial stability invariant on candidate findings before classification.
6. **CLI Hex Escaped Sequence Parser Crash**: Passing sequences such as `\xc0\x8a\r\n` or `\r\n ` causes an unhandled `ValueError` crash or literal string interpretation.
7. **Dead Code**: `format_kettle_ruler_bytes()` is defined but unreferenced.
8. **Test Suite Coverage Deficiencies**: Missing contraction tests (`delta < 0`), resource cleanup tests, bracket edge-case tests, status code tests, and brittle hardcoded port allocation (`8092`).

---

## 1. Protocol Ruler Calibration Logic Analysis

### 1.1 Coarse Stepped Bracket Search
The calibration process begins in `calibrate_baseline_limit()` (`protocol_ruler.py:169-198`):
```python
brackets = [1024, 2048, 4096, 8192, 16384, 32768, 64000, 64040, 65536, 98304, 131072]
brackets = [b for b in brackets if min_size <= b <= max_size]
if max_size not in brackets:
    brackets.append(max_size)
```

#### Defect: Missing `min_size` Inclusion
- **Root Cause**: `max_size` is appended if absent, but `min_size` is **not**.
- **Empirical Demonstration**:
  When tested against a test server configured with `max_header_limit = 800` using `calibrate_baseline_limit(min_size=500, max_size=2000)`:
  - `brackets` evaluated to `[1024, 2048, 2000]`.
  - The first probe sent had length `1024`, which exceeded the 800-byte limit and returned HTTP 400.
  - The loop broke immediately with `low = None`.
  - The function aborted with: `[-] Target rejected even minimum size (500 bytes). Server might be down or blocking requests.`
  - 500 bytes was **never sent to the server**.
- **Fix**:
  ```python
  if min_size not in brackets:
      brackets.append(min_size)
  if max_size not in brackets:
      brackets.append(max_size)
  brackets.sort()
  ```

#### Non-General Bracket Coupling
- `brackets` contains `64040`, which is the exact arbitrary buffer limit configured in `test_lab_server.py:18`. While this ensures the test lab succeeds in a single step, in real targets, standard power-of-two intervals (`[1024, 2048, 4096, 8192, 16384, 32768, 49152, 65536, 98304, 131072]`) are standard. The binary search will locate any arbitrary value (including `64040`) without requiring hardcoded test constants.

---

### 1.2 Single-Byte Binary Search Calibration
Once `low` and `high` are established such that `low` is non-error and `high` is an error boundary, Step 2 runs binary search (`protocol_ruler.py:203-218`):
```python
left = low
right = high
last_ok = low

while left <= right:
    mid = (left + right) // 2
    req = _build_request(mid)
    code, resp, lat = self.send_probe(req)

    if not self.is_error_boundary(code):
        last_ok = mid
        left = mid + 1
    else:
        right = mid - 1

limit = last_ok
```

#### Efficiency Observation
- `low` is already proven to be non-error in Step 1.
- `high` is already proven to be an error in Step 1.
- Initializing `left = low` and `right = high` redundantly reprobes `low` and `high` during the search. When `high == low + 1`, 2 superfluous network probes occur. Initializing `left = low + 1` and `right = high - 1` eliminates redundant network round-trips.

#### Defect: Step 3 Verification Lacks Assertion / Validation
Lines 220-224:
```python
# Step 3: Verification of the cliff in Kettle trace format
req_ok = _build_request(limit)
code_ok, _, lat_ok = self.send_probe(req_ok)
req_err = _build_request(limit + 1)
code_err, _, lat_err = self.send_probe(req_err)
```
- **Flaw**: The method executes `send_probe(req_ok)` and `send_probe(req_err)` for display purposes, but **never asserts** `not is_error_boundary(code_ok)` and `is_error_boundary(code_err)`.
- If transient jitter or rate limiting returns HTTP 429/400 for `req_ok` or HTTP 200 for `req_err`, the method still logs `AAA...{limit} -> 400 OK` and returns `limit`.
- **Fix**: Enforce that `limit` must be non-error and `limit + 1` must be an error boundary; if verification fails, retry or return `None`.

---

### 1.3 Sequence Transformation Measurement Defect (`measure_sequence_transformation`)
Lines 261-285:
```python
low_bound = max(10, baseline_limit - search_radius)
high_bound = baseline_limit + search_radius
...
left = low_bound
right = high_bound
last_ok = low_bound

while left <= right:
    mid = (left + right) // 2
    req = _build_mutated_request(mid)
    code, _, _ = self.send_probe(req)

    if not self.is_error_boundary(code):
        last_ok = mid
        left = mid + 1
    else:
        right = mid - 1

mutated_limit = last_ok
delta = baseline_limit - mutated_limit
```

#### Critical Logic Defect: False Expansion on Rejected Sequences
- When a candidate sequence is rejected by the server at **all** lengths (e.g., NUL byte `\x00`, invalid HTTP header line, WAF rule block, or non-ASCII characters):
  1. Every probe in `[low_bound, high_bound]` returns HTTP 400 (`is_error_boundary(code) == True`).
  2. `last_ok` is **never updated**, remaining at `low_bound`.
  3. `mutated_limit` becomes `low_bound`.
  4. `delta = baseline_limit - low_bound = search_radius` (128 bytes).
  5. The method concludes:
     - `classification = "EXPANSION"`
     - `verdict = "EXPANDED by 128 bytes on front-end!"`
     - Step 3 logs: `A: ... -> 400 OK`!
- **Demonstration**:
  A simulated probe rejecting `b"BAD_SEQ"` with HTTP 400 was tested. The ruler output:
  ```
  Classification: EXPANSION
  Delta: 128
  Code OK: 400
  Verdict: EXPANDED by 128 bytes on front-end!
  ```
- **Fix**:
  Probe `low_bound` before running binary search. If `low_bound` returns an error boundary, the sequence is rejected outright or its expansion exceeds `search_radius`. Return `classification = "REJECTED_OR_OVERSIZED"`. Similarly, if `high_bound + 1` returns non-error, classify as `ACCEPTED_BEYOND_BOUND`.

#### Minimum Lower Bound vs Sequence Length
- In `_build_mutated_request`:
  `payload = sequence_bytes + (b"A" * max(0, padding_len - seq_len))`
- When `padding_len < seq_len`, `payload` is identical to `sequence_bytes`. Probing between `10` and `seq_len` generates identical network requests.
- **Fix**: `low_bound = max(seq_len, baseline_limit - search_radius)`.

---

## 2. Socket Handling, Timeouts, Resource Cleanup, and Exceptions

### 2.1 Critical Socket Leak in `send_probe()`
Lines 125-136:
```python
try:
    sock = self._open_socket()
    sock.sendall(request_bytes)
    framed = HTTPFramingReader.read_response(sock, timeout=self.timeout)
    sock.close()
    status_code = framed.status_code
    response_bytes = framed.raw_response
    latency = (time.time() - t0) * 1000
    return status_code, response_bytes, latency
except Exception:
    latency = (time.time() - t0) * 1000
    return 0, b"", latency
```
- **Flaw**: `sock.close()` is on line 129. If `sock.sendall()` or `HTTPFramingReader.read_response()` raises an exception (e.g. `ConnectionResetError`, `BrokenPipeError`, `socket.timeout`), control jumps directly to `except Exception:`.
- `sock.close()` is **bypassed**.
- **Empirical Demonstration**: Injected `ConnectionResetError` into `read_response`. Verified that `sock.fileno() != -1` (socket handle remained open and leaked).
- In a full audit scanning dozens of boundaries where connection drops and resets are expected, this leaks dozens of OS socket handles.
- **Fix**: Add a `finally:` block:
  ```python
  sock = None
  try:
      sock = self._open_socket()
      ...
  except Exception:
      ...
  finally:
      if sock is not None:
          try:
              sock.close()
          except Exception:
              pass
  ```

### 2.2 Raw Socket Leak in `_open_socket()` on TLS Handshake Failure
Lines 108-115:
```python
def _open_socket(self) -> socket.socket:
    raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
    if self.use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context.wrap_socket(raw_sock, server_hostname=self.host)
    return raw_sock
```
- **Flaw**: If `context.wrap_socket(...)` raises an exception (e.g. `ssl.SSLError`, handshake failure, plain-HTTP response on TLS port), `raw_sock` is not closed.
- **Fix**: Wrap `wrap_socket` in `try...except` and close `raw_sock` on error before re-raising.

### 2.3 Incomplete Status Code Coverage in `is_error_boundary()`
Line 144:
`return status_code in (400, 431, 414, 502, 504, 0)`
- **Missing**:
  - `413` (*Payload Too Large* / *Content Too Large* / *Request Entity Too Large*). Standard response from Nginx, Apache, Envoy, and Node.js when request headers or payloads exceed buffer limits.
  - `500` (*Internal Server Error*). Legacy and embedded servers frequently crash with 500 when buffer allocations fail.
  - `503` (*Service Unavailable*).
- If a target returns 413 or 500, `is_error_boundary()` returns `False`, causing the binary search to falsely mark the oversized request as acceptable.
- **Fix**:
  `return status_code in (400, 413, 414, 431, 500, 502, 503, 504, 0)`

### 2.4 Timeout Parameter Validation
- `ProtocolRuler(timeout=...)` does not validate `timeout`.
- If a user passes `--timeout 0` or negative values, `socket.settimeout(0)` places the socket into non-blocking mode, raising `BlockingIOError` on `sendall` and causing all probes to report status 0.
- **Fix**: Guard `timeout = max(0.1, float(timeout))`.

---

## 3. Review of `test_protocol_ruler.py` Coverage and Missing Edge Cases

### Current Test Suite Overview
`test_protocol_ruler.py` contains 6 tests:
1. `test_01_calibrate_baseline_limit`: Validates exact 64,040 byte limit.
2. `test_02_detect_c0_8a_expansion`: Validates +10 byte expansion on `\xc0\x8a`.
3. `test_03_detect_verbatim_sequence`: Validates 0 byte delta on `/`.
4. `test_04_comprehensive_audit_run`: Validates audit execution.
5. `test_05_reject_inaddr_any_host`: Validates rejection of `0.0.0.0` and `::`.
6. `test_06_connection_drop_handling`: Validates status 0 on dead port.

### Missing Test Coverage & Edge Cases

| # | Gap / Edge Case | Description | Severity |
|---|----------------|-------------|----------|
| 1 | **Port 8092 Race Condition** | `SERVER_PORT = 8092` is hardcoded. If port 8092 is in `TIME_WAIT` or another process binds it, tests crash on `setUpClass`. Should use `port=0` for dynamic port allocation. | High |
| 2 | **Contraction / Stripping Detection** | No test validates `delta < 0` (`classification == "CONTRACTION"`), despite `TestLabServer` implementing contraction logic for `\xef\xac\x81` (ligature fi, -1 byte) and `\r\n ` (-2 bytes). | High |
| 3 | **Socket Cleanup on Exception** | Zero tests verify that socket handles are closed (`fileno() == -1`) when `sendall` or `read_response` raises exceptions. | Critical |
| 4 | **Bracket `min_size` Inclusion** | No test validates that bracket search succeeds when `min_size` is non-default (e.g., `min_size=500` against an 800-byte server limit). | High |
| 5 | **Unconditional Sequence Rejection** | No test validates that an outright rejected sequence is classified as `REJECTED_OR_OVERSIZED` rather than a false `EXPANSION`. | High |
| 6 | **HTTP Error Boundary Status Codes** | No unit test for `is_error_boundary()` asserting 413, 500, 431, 414, 502, 504, 0. | Medium |
| 7 | **`format_kettle_ruler_bytes()` Compression** | The Kettle run-length compression utility has 0 tests. | Medium |
| 8 | **Custom User Sequences** | Testing user-supplied custom sequences in `run_comprehensive_audit` is not verified. | Medium |

---

## 4. Defects and Deviations from `ORIGINAL_REQUEST.md`

1. **R1 Multi-Trial Reproducibility Invariant Omission**:
   - `ORIGINAL_REQUEST.md` (R1) specifies: *"Ensure all wire-level parsers, framing mutators, and multi-trial reproducibility gates operate with 100% RFC fidelity and zero unhandled socket, TLS, or encoding errors."*
   - Protocol Ruler currently classifies mutations from a single pass. Discrepancies (`delta != 0`) must be confirmed via 3 repeated trials before promotion.
2. **Acceptance Criteria Resource Leak Invariant**:
   - `ORIGINAL_REQUEST.md` specifies: *"All 16 modules in D:\harfile\rfchunt pass static syntax compilation (py_compile) and runtime execution without unhandled exceptions or resource leaks."*
   - As proven in Section 2.1, `protocol_ruler.py` leaks open socket descriptors whenever network errors occur during `send_probe()`.
3. **CLI Escaped Sequence Parsing Crash**:
   - In `main()` (`protocol_ruler.py:447-454`), parsing `--sequence "\xc0\x8a\r\n"` crashes with `ValueError: non-hexadecimal number found in fromhex()`.
   - Python-style escape sequences (`\r`, `\n`, `\t`, `\x..`) should be parsed via `codecs.decode(..., 'unicode_escape')`.
4. **Dead Code**:
   - `format_kettle_ruler_bytes()` is defined but never called in logging traces.

---

## 5. Artifacts Produced

1. **`report.md`** (this document): Complete investigation, root-cause analyses, and empirical proofs.
2. **`protocol_ruler_remediation.patch`**: Complete unified diff remedying all identified defects in `protocol_ruler.py`.
3. **`test_protocol_ruler_expansion.patch`**: Complete unified diff extending `test_protocol_ruler.py` with 6 new unit tests covering contractions, socket cleanup, bracket edge-cases, error boundaries, and dynamic port allocation.
4. **`handoff.md`**: Formal 5-component handoff report.
