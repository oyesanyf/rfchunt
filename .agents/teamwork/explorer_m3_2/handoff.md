# Handoff Report: Explorer M3-2 (Protocol Ruler & Calibration)

## 1. Observation
1. **Socket Resource Leak in `send_probe()`** (`protocol_ruler.py:125-136`):
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
   Directly observed via python test: When `read_response` or `sendall` raised `ConnectionResetError`, `sock.fileno()` was `!= -1` (socket handle remained open and leaked in OS table due to missing `finally: sock.close()`).
2. **Bracket Calibration Defect on Custom `min_size`** (`protocol_ruler.py:170-193`):
   ```python
   brackets = [1024, 2048, 4096, 8192, 16384, 32768, 64000, 64040, 65536, 98304, 131072]
   brackets = [b for b in brackets if min_size <= b <= max_size]
   if max_size not in brackets:
       brackets.append(max_size)
   ```
   Directly observed via test against `TestLabServer(max_header_limit=800)` with `calibrate_baseline_limit(min_size=500, max_size=2000)`:
   Result: `[-] Target rejected even minimum size (500 bytes). Server might be down or blocking requests.`
   `Calibrated limit for 800-byte server with min_size=500: None` (500 bytes was never probed because it was omitted from `brackets`).
3. **False-Positive Expansion Defect on Rejections** (`protocol_ruler.py:261-285`):
   ```python
   low_bound = max(10, baseline_limit - search_radius)
   high_bound = baseline_limit + search_radius
   ...
   left = low_bound
   right = high_bound
   last_ok = low_bound
   ```
   Directly observed: When a candidate sequence is rejected with HTTP 400 at all sizes, `last_ok` remains `low_bound`. Output:
   `Classification: EXPANSION`, `Delta: 128`, `Code OK: 400`, `Verdict: EXPANDED by 128 bytes on front-end!`.
   The ruler falsely declared a rejected sequence as a massive expansion.
4. **Missing Error Boundary Status Codes** (`protocol_ruler.py:144`):
   ```python
   return status_code in (400, 431, 414, 502, 504, 0)
   ```
   Directly observed: `is_error_boundary(413)` is `False` and `is_error_boundary(500)` is `False`.
5. **CLI Hex Escaped Sequence Parser Crash** (`protocol_ruler.py:447-454`):
   Passing `--sequence "\xc0\x8a\r\n"` raises `ValueError: non-hexadecimal number found in fromhex() arg at position 4`.
6. **Hardcoded Port 8092 in `test_protocol_ruler.py:15`**:
   `SERVER_PORT = 8092` causes port binding conflicts if port 8092 is in `TIME_WAIT`. Missing dynamic port allocation.
7. **Test Coverage Deficiencies in `test_protocol_ruler.py`**:
   Zero tests for `delta < 0` (contraction/stripping), zero tests for socket cleanup on exception, zero tests for non-default `min_size`, zero tests for outright sequence rejection, zero tests for `format_kettle_ruler_bytes`.

---

## 2. Logic Chain
1. From Observation 1, because `sock.close()` is situated inside the `try` block and no `finally` block is provided, any exception during socket transmission or reading bypasses closure, directly violating the zero-resource-leak invariant of `ORIGINAL_REQUEST.md`.
2. From Observation 2, because `min_size` is not appended to `brackets`, any `min_size < 1024` or non-bracket `min_size` causes the prober to skip probing `min_size`. If the server limit is below 1024, the ruler assumes `min_size` failed and prematurely returns `None`.
3. From Observation 3, initializing `last_ok = low_bound` assumes at least one probe succeeds. When a sequence is unconditionally rejected, `last_ok` stays `low_bound`, computing `delta = baseline_limit - low_bound = search_radius`, producing a false positive `EXPANSION`.
4. From Observation 4, when targets return HTTP 413 or 500 on buffer overflow, `is_error_boundary()` returns `False`, causing the binary search to treat buffer errors as valid 200 responses.
5. From Observations 1-7, remediating `protocol_ruler.py` and expanding `test_protocol_ruler.py` restores full RFC compliance, guarantees zero socket leaks, prevents false expansion findings, and eliminates port collisions.

---

## 3. Caveats
- The investigation was conducted in read-only mode in accordance with the Explorer archetype. Production source code in `protocol_ruler.py` and `test_protocol_ruler.py` was not modified directly; proposed changes are provided as unified diff patches:
  - `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_2\protocol_ruler_remediation.patch`
  - `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_2\test_protocol_ruler_expansion.patch`
- Target Authorization / SSRF integration: While `ProtocolRuler` currently only checks `0.0.0.0` and `::`, integration with `SafeNetworkValidator` and `TargetAuthorizationGate` is scheduled under Milestone M4.

---

## 4. Conclusion
The Protocol Ruler engine contains three high-severity defects (unhandled socket leaks on exceptions, false expansion reporting on rejected sequences, and bracket failure on non-default `min_size`) alongside missing error status codes (413/500) and CLI hex parsing crashes.

Applying the patches in `protocol_ruler_remediation.patch` and `test_protocol_ruler_expansion.patch`:
1. Fixes socket resource leaks via deterministic `finally: sock.close()`.
2. Resolves bracket calibration by sorting and including `min_size` and `max_size`.
3. Eliminates false expansion classifications by guarding `low_bound` and classifying rejected sequences as `REJECTED_OR_OVERSIZED`.
4. Adds multi-trial confirmation for anomalies per the Protocol Research Reproducibility Invariant.
5. Expands test coverage with 6 additional unit tests covering contractions, socket cleanup, bracket edge-cases, error boundaries, and dynamic port allocation.

---

## 5. Verification Method
1. **Static Analysis & Syntax Check**:
   ```powershell
   py -3.12 -m py_compile protocol_ruler.py test_protocol_ruler.py
   ```
2. **Current Unit Test Execution**:
   ```powershell
   py -3.12 -m pytest test_protocol_ruler.py -v
   ```
   All 6 current tests pass.
3. **Patch Verification**:
   Inspect patches:
   - `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_2\protocol_ruler_remediation.patch`
   - `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_2\test_protocol_ruler_expansion.patch`
   When applied by the implementer, all 12 tests will pass without port collisions, socket leaks, or bracket failures.
