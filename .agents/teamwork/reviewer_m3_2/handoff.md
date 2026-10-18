# Handoff Report: Reviewer M3-2 (Protocol Ruler & Research Suite)

- **Agent**: Reviewer M3-2
- **Role**: Reviewer, Adversarial Critic
- **Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\reviewer_m3_2`
- **Date**: 2026-10-18T20:37:00Z
- **Target Files**:
  * `protocol_ruler.py`
  * `test_protocol_ruler.py`
  * `tests/test_research_engine.py`
- **Verdict**: **APPROVE**

---

## 1. Observation

Direct observations and verification commands executed against `D:\harfile\rfchunt`:

1. **Deterministic Socket Cleanup (`protocol_ruler.py`)**:
   - Lines 108–122 (`_open_socket`):
     ```python
     raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
     if self.use_tls:
         try:
             context = ssl.create_default_context()
             context.check_hostname = False
             context.verify_mode = ssl.CERT_NONE
             return context.wrap_socket(raw_sock, server_hostname=self.host)
         except Exception:
             try:
                 raw_sock.close()
             except Exception:
                 pass
             raise
     return raw_sock
     ```
   - Lines 124–150 (`send_probe`):
     ```python
     sock = None
     try:
         sock = self._open_socket()
         sock.sendall(request_bytes)
         framed = HTTPFramingReader.read_response(sock, timeout=self.timeout)
         ...
         return status_code, response_bytes, latency
     except Exception:
         latency = (time.time() - t0) * 1000
         return 0, b"", latency
     finally:
         if sock is not None:
             try:
                 sock.close()
             except Exception:
                 pass
     ```
   - Verbatim observation: Socket handle `sock` is guaranteed to be closed via the `finally:` block regardless of whether `sendall`, `read_response`, or an unhandled exception occurs. In `_open_socket`, if TLS wrapping fails, `raw_sock` is explicitly closed before re-raising.

2. **Bracket Calibration Sorting (`protocol_ruler.py`)**:
   - Lines 184–190:
     ```python
     brackets = [1024, 2048, 4096, 8192, 16384, 32768, 64000, 64040, 65536, 98304, 131072]
     brackets = [b for b in brackets if min_size <= b <= max_size]
     if min_size not in brackets:
         brackets.append(min_size)
     if max_size not in brackets:
         brackets.append(max_size)
     brackets.sort()
     ```
   - Verbatim observation: Custom `min_size` and `max_size` are guaranteed to be in `brackets`, and `brackets.sort()` ensures strictly monotonic ascending order before the coarse stepped probe loop executes.

3. **Classification of Rejected Sequences (`protocol_ruler.py`)**:
   - Lines 289–306 (`measure_sequence_transformation`):
     ```python
     # Guard: Ensure sequence is not rejected outright at low_bound
     req_low = _build_mutated_request(low_bound)
     code_low, _, _ = self.send_probe(req_low)
     if self.is_error_boundary(code_low):
         self._log(f"[-] Sequence '{name}' rejected at lower search bound ({low_bound:,} bytes). Outright rejected or expansion > {search_radius}.")
         return {
             "name": name,
             "sequence_hex": sequence_bytes.hex(),
             "sequence_repr": repr(sequence_bytes),
             "sequence_length": seq_len,
             "baseline_limit": baseline_limit,
             "mutated_limit": None,
             "delta_bytes": None,
             "classification": "REJECTED_OR_OVERSIZED",
             "verdict": f"Rejected by target at low bound ({low_bound} bytes); sequence rejected or expansion exceeds search radius {search_radius}.",
             "code_ok": code_low,
             "code_err": None,
         }
     ```
   - Verbatim observation: Probing `low_bound` before the binary search prevents outright rejected or syntax-error sequences from defaulting `last_ok` to `low_bound` and falsely reporting an expansion of `search_radius` (+128 bytes).

4. **Error Boundary Status Codes (`protocol_ruler.py`)**:
   - Lines 151–158:
     ```python
     def is_error_boundary(self, status_code: int) -> bool:
         return status_code in (400, 413, 414, 431, 500, 502, 503, 504, 0)
     ```
   - Verbatim observation: Status codes `413` (Content Too Large) and `500` (Internal Server Error buffer fault) are present, along with `400`, `414`, `431`, `502`, `503`, `504`, and `0`.

5. **Dynamic Port Allocation (`test_protocol_ruler.py`)**:
   - Lines 18–21 & 87–91:
     ```python
     cls.server = TestLabServer(host="127.0.0.1", port=0, max_header_limit=cls.MAX_LIMIT)
     cls.server.start()
     cls.SERVER_PORT = cls.server.port
     ```
     and in `test_08_bracket_min_size_inclusion`:
     ```python
     mini_server = TestLabServer(host="127.0.0.1", port=0, max_header_limit=800)
     mini_server.start()
     ...
     mini_ruler = ProtocolRuler(host="127.0.0.1", port=mini_server.port, timeout=1.0)
     ```
   - Verbatim observation: All test servers bind to `port=0` (dynamic port allocation), preventing hardcoded TCP port collisions.

6. **Test Suite Execution Results**:
   - `python.cmd -m pytest test_protocol_ruler.py -v`:
     `12 passed in 4.98s` (100% pass, 0 failures, 0 errors).
   - `python.cmd -m pytest tests/test_research_engine.py -v`:
     `14 passed in 6.21s` (100% pass, 0 failures, 0 errors).
   - `python.cmd -m pytest tests/test_harness2_integration.py -v`:
     `9 passed in 8.20s` (100% pass, 0 failures, 0 errors).

---

## 2. Logic Chain

1. **Deterministic Socket Lifecycle**:
   - Observation 1 demonstrates that `sock` is assigned within the `try:` block and unconditionally closed in the `finally:` block of `send_probe()`.
   - In `_open_socket()`, any TLS wrapping exception closes the underlying `raw_sock` before propagating.
   - Test 10 in `test_protocol_ruler.py` proves that injecting a `ConnectionResetError` into `HTTPFramingReader.read_response` results in `sock.fileno() == -1`, verifying no leaked OS file handles.

2. **Bracket Boundary Robustness**:
   - Observation 2 demonstrates that custom `min_size` (e.g. 500) and `max_size` (e.g. 2000) are explicitly appended to `brackets` and sorted ascending.
   - Test 08 validates that calibrating against a server with `max_header_limit = 800` using `min_size = 500` and `max_size = 2000` accurately pinpoints 800 down to single-byte resolution.

3. **Elimination of False Expansion Artifacts**:
   - Observation 3 shows the pre-binary-search probe of `low_bound`. If the server rejects the probe at `low_bound` (e.g., returning HTTP 400), the method immediately returns `classification: "REJECTED_OR_OVERSIZED"` and `delta_bytes: None`.
   - Test 09 confirms that injecting an outright rejection (`b"DISALLOWED"`) does not report an expansion, resolving the Kettle ruler edge case.

4. **Multi-Trial Confirmation Law Compliance**:
   - `measure_sequence_transformation` enforces a 3-trial verification loop for all candidate non-zero deltas (`if delta != 0:`). If the boundary does not repeat stably across all trials, it is downgraded to `"UNCONFIRMED_TRANSIENT"`, strictly satisfying `protocol_research_reproducibility.md`.

5. **Research Engine Integration**:
   - Observation 6 verifies that `tests/test_research_engine.py` re-exports all 14 research module tests (ABNF inversion, bandit scheduler, semantic compiler, differential oracle, sequence engine, errata tracker, metamorphic engine, delta debugger, causal classifier, boundary analyzer, knowledge graph, defensive publisher, and orchestrator cycle), satisfying `ORIGINAL_REQUEST.md:27`.

---

## 3. Caveats

- **Cross-Process Temp Directory Locking on Windows**: During full test suite regression runs without isolated `--basetemp`, Windows file locking on SQLite database files (`cli_h2.db` in `d:\harfile\.pytest_temp`) can cause `PermissionError: [WinError 32]` if multiple test runs or background processes share the folder. Specifying an isolated `--basetemp` executes all tests cleanly (100% pass). This will be further fortified under Milestone 4 with SQLite WAL mode and 30s busy timeouts.
- No caveats regarding `protocol_ruler.py`, `test_protocol_ruler.py`, or `tests/test_research_engine.py`.

---

## 4. Conclusion & Quality Review

### Quality Review Summary

**Verdict**: **APPROVE**

### Findings

- **No Critical, Major, or Minor Defects**: All 8 items from the dispatch instructions were thoroughly inspected and verified.
- **Integrity Verification**:
  - No hardcoded test responses or facade stubs found.
  - Live network socket tests run against genuine multi-threaded socket servers.
  - Multi-trial confirmation logic is mathematically sound and adheres to reproducibility invariants.

### Adversarial Challenge & Stress Test Summary

| Challenge / Scenario | Expected Behavior | Actual Behavior | Result |
|----------------------|-------------------|-----------------|--------|
| Immediate TCP Connection Reset | Socket closed, returns code 0 | `sock.fileno() == -1`, code 0 | PASS |
| Non-default `min_size` (500 < 1024) | Brackets sorted, finds 800-byte limit | Calibrates exact 800 limit | PASS |
| Outright rejected sequence (`DISALLOWED`) | Classified as `REJECTED_OR_OVERSIZED` | Classified as `REJECTED_OR_OVERSIZED` | PASS |
| Buffer fault status codes (`413`, `500`) | Treated as error boundaries | `is_error_boundary()` returns True | PASS |
| Dynamic port binding (`port=0`) | Allocates random high unprivileged port | Bound port dynamically resolved | PASS |
| Unicode/Hex CLI sequence parsing | Parsed cleanly without exception | Escaped sequences properly decoded | PASS |

---

## 5. Verification Method

To independently reproduce and verify this review, run the following commands in `D:\harfile\rfchunt`:

```powershell
# 1. Verify Protocol Ruler unit & integration tests (12 tests)
python.cmd -m pytest test_protocol_ruler.py -v

# 2. Verify Protocol Research Engine consolidated suite (14 tests)
python.cmd -m pytest tests/test_research_engine.py -v

# 3. Verify Harness2 integration suite (9 tests)
python.cmd -m pytest tests/test_harness2_integration.py -v

# 4. Verify isolated run of ruler and research engine
python.cmd -m pytest test_protocol_ruler.py tests/test_research_engine.py --basetemp=.pytest_temp_m3_2 -v
```
