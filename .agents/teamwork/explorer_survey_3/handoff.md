# Handoff Report: Security Boundaries, Concurrency & Test Suite Survey

**From:** Explorer 3 (Security Boundaries, Build & Test Suite Survey Focus)  
**To:** Project Orchestrator (`48cb9587-3e1b-40a9-9a84-e3452d5f5108`) / Implementers  
**Working Directory:** `D:\harfile\rfchunt\.agents\teamwork\explorer_survey_3`  
**Reference Report:** `D:\harfile\rfchunt\.agents\teamwork\explorer_survey_3\report.md`  
**Date:** 2026-10-18  

---

## 1. Observation

### Target Authorization & SSRF Observations
1. **Target Gate Implementation:** In `mcp_server.py` lines 17–130, `TargetAuthorizationGate` manages target validation via `ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}` and `RFCHUNT_AUTHORIZED_TARGETS`.
2. **Auto-Authorization CLI Defect:** In `rfc_hunt_swarm.py` lines 2268–2270:
   ```python
   for t_host, t_port, t_tls in target_list:
       TargetAuthorizationGate.authorize_target(t_host)
       is_valid_target, target_reason = TargetAuthorizationGate.validate_target(t_host)
   ```
   `authorize_target` unconditionally adds `t_host` into `ALLOWED_TARGETS` before `validate_target` is invoked, completely bypassing the whitelist.
3. **Absence of Mathematical IP Validation:** Ripgrep search for `ipaddress` across `D:\harfile\rfchunt` returned 0 occurrences. Target checks in `mcp_server.py` (lines 46, 55) and `protocol_ruler.py` (line 92) perform only naive string matching: `if cleaned in ("0.0.0.0", "::")`.
4. **Direct Raw Socket Connections:** Sockets are opened directly without gate checks in:
   - `deterministic_harness.py:48`
   - `weaponizer.py:38`
   - `engine/active_flaw_prober.py:57`
   - `engine/differential_oracle.py:55`
   - `engine/delta_debugger.py:170`
   - `engine/metamorphic_engine.py:165`
   - `engine/sequence_engine.py:71, 286`
   - `protocol_ruler.py:109`

### Path Traversal Observations
1. **`normalize_rel` Implementation:** In `engine/harness2_engine.py` lines 159–179:
   - Evaluates `r.startswith("/")`, `":" in r`, `r.split("/")` containing `..`, and substring presence of `%2e`, `%2f`, `%5c`, `%00`, `\x00`.
   - Does not perform iterative `urllib.parse.unquote()`, permitting multi-layer percent-encoding escapes (`%252e%252e%252f`).
   - Does not filter encoded colon `%3a` (used in Windows ADS and drive letters) or Windows device names (`CON`, `PRN`, `AUX`, `NUL`).
   - Destination file creation at line 374 (`p = dest / normalize_rel(a)`) omits `p.resolve().is_relative_to(dest.resolve())`.

### SQLite Concurrency & Locking Observations
1. **Missing WAL & Default Timeout:** In `database.py` line 18:
   `self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)`
   - No `PRAGMA journal_mode = WAL;` exists anywhere in the repository.
   - `timeout` is omitted, defaulting to 5.0 seconds.
2. **Unsynchronized Read Cursors:** While write methods use `with self._lock: with self.conn:`, read methods (`get_ingested_rfc_ids:231`, `get_unprocessed_fragments:249`, `get_pending_probes:289`, `get_confirmed_findings:360`, `get_tier_taxonomy_counts:535`, etc.) do not hold `self._lock`, leading to concurrent cursor race conditions on a single `Connection` handle.
3. **External Uncoordinated Connections:** Raw connections are instantiated in `rfc_hunt_swarm.py:1314`, `engine/caldera_bridge.py:202`, and `engine/dream_world_model.py:134`.

### Build & Test Suite Observations
1. **Full Pytest Health:** Running `python.cmd -m pytest tests/ test_protocol_ruler.py -q` executed 106 tests across 16 test files. Result: **106 passed in 95.08s (100% PASS)**.
2. **Build Pipeline Health:** Running `python.cmd build_all.py --skip-tests` passed all 7 pre-test build targets in 2.65 seconds (67 Python files syntax-checked, 16 tables verified, 25 RFCs pre-cached, Caldera plugin exported, Dream-RSI Gen 1 fitness 437.0 verified, Harness² R=4k/P=3k ledger verified).
3. **Subprocess Noise:** In `build_all.py` (line 179), `ollama_manager.py` (lines 119, 152, 209, 254), and `engine/raptor_integrator.py` (lines 108, 166, 235, 323), `stdin=subprocess.DEVNULL` and `creationflags=subprocess.CREATE_NO_WINDOW (0x08000000)` are missing.
4. **Ollama Hang Fragility:** If Ollama hangs on localhost:11434, `test_explain_vulnerability_concept` in `tests/test_rfcs.py` can freeze for up to 270 seconds due to 120s initial timeout plus 5 x 30s fallbacks.

---

## 2. Logic Chain

1. **Target Authorization:** From Observation 2 (blind call to `authorize_target` on CLI input in `rfc_hunt_swarm.py`), it follows that any target given to the CLI is admitted into `ALLOWED_TARGETS`, rendering `validate_target` incapable of enforcing the whitelist. Coupled with Observation 4 (raw socket calls throughout `engine/`), arbitrary target hosts can be probed directly without authorization checks.
2. **SSRF IP-Range Guards:** From Observation 3 (zero `ipaddress` imports and naive string matching `in ("0.0.0.0", "::")`), any alternative representation of unspecified IP (`0`, `0x0`, `::0`), IPv4-mapped IPv6 (`::ffff:0.0.0.0`), private RFC1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Cloud metadata endpoints (`169.254.169.254`), CGNAT (`100.64.0.0/10`), and IPv6 ULA (`fc00::/7`) slips past validation.
3. **Path Traversal:** From Observation 5 (`normalize_rel` string checks without URL decoding), an attacker or prompt providing double-encoded tokens (`%252e%252e`) or encoded colons (`%3a`) bypasses substring tests. Without `is_relative_to` verification, resolved file operations could theoretically write outside the sandbox.
4. **Database Locking:** From Observations 6–8 (absence of WAL mode, 5s default timeout, and unsynchronized read cursors), under high-concurrency swarm runs, simultaneous write transactions acquire exclusive database locks and block concurrent readers, resulting in `database is locked` exceptions.
5. **Subprocess Silencing:** From Observation 11, external process invocations without `CREATE_NO_WINDOW` or `DEVNULL` generate visible console popups on Windows and risk hanging on standard input streams.

---

## 3. Caveats

1. **Investigation Read-Only Scope:** In accordance with the Explorer role, no modifications to project source code were made; all proposed remediations are documented for the implementer agent.
2. **Local Environment Variations:** Test runtime was measured on Python 3.12.10 (AMD64) on Windows with local Ollama installed. Machines without Ollama or with different execution aliases will rely on the offline grammar fallback.
3. **No Caveats on Test Completeness:** All 106 existing tests were executed and cataloged without omitting any test modules.

---

## 4. Conclusion

The core algorithmic protocol logic across HTTP Terminator / RFC Hunt Swarm (Modules 1–16, 4-parser differential matrix, Google Research Harness², and Protocol Ruler) is healthy and 100% verified (106/106 tests passing). However, significant security boundary and concurrency fortifications are necessary:
1. **Target Authorization:** Must eliminate the blind `authorize_target` call in `rfc_hunt_swarm.py`, wire centralized validation into all raw socket connection methods, and enforce strict whitelist gating.
2. **SSRF Protection:** Must refactor `TargetAuthorizationGate` with mathematical `ipaddress` parsing, blocking RFC1918, link-local/cloud metadata, CGNAT, IPv6 ULA, IPv4-mapped IPv6, and resolving hostnames via `socket.getaddrinfo`.
3. **Path Traversal:** Must harden `normalize_rel` with iterative unquoting, `%3a` rejection, device name blocking, and `is_relative_to` assertions.
4. **SQLite Concurrency:** Must enable `PRAGMA journal_mode = WAL;`, `busy_timeout = 60000;`, `timeout = 60.0`, and lock all read operations.
5. **Host Containment & Subprocess:** Must implement `engine/host_containment.py` (Windows WFP dynamic session / Linux Netlink) and add `CREATE_NO_WINDOW` and `DEVNULL` across all subprocess calls.

---

## 5. Verification Method

To independently reproduce and verify all observations and test results:

```powershell
# 1. Run full automated pytest verification suite (all 106 tests)
python.cmd -m pytest tests/ test_protocol_ruler.py -v

# 2. Run the unified build pipeline in offline verification mode
python.cmd build_all.py --skip-tests

# 3. Run the unified build pipeline end-to-end
python.cmd build_all.py

# 4. Verify absence of ipaddress in current codebase
grep_search "ipaddress" in D:\harfile\rfchunt
```

Invalidation Conditions:
- If `python.cmd -m pytest tests/ test_protocol_ruler.py` fails any of the 106 tests, test health has regressed.
- If `TargetAuthorizationGate.check_target("169.254.169.254")` does not raise `PermissionError` or `ValueError` after remediation, SSRF protection remains incomplete.
