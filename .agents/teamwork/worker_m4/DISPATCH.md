# Dispatch: Worker M4 (Security Boundaries & Concurrency Locks)

**Role**: Worker M4 (Implementation & Fortification)
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\worker_m4`
**Timestamp**: 2026-10-18T21:05:00Z

## Inputs & Reports to Read:
1. `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md` (authoritative user requirements)
2. `D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md`
3. `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_1\report.md` & `handoff.md` (Target Auth & SSRF Validation)
4. `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_2\report.md` & `handoff.md` (Path Traversal & normalize_rel)
5. `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_3\report.md` & `handoff.md` (SQLite WAL & Concurrency Locks)

## Mandatory Integrity Warning:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Write Ownership:
- `engine/safe_network_validator.py` (new production validator)
- `mcp_server.py` (`TargetAuthorizationGate` updates)
- `rfc_hunt_swarm.py` (remove line 2271 auto-whitelist bypass, add close methods)
- `deterministic_harness.py` (wire target authorization & safe network validation)
- `weaponizer.py` (wire target authorization & safe network validation)
- `engine/active_flaw_prober.py` (wire target authorization & safe network validation)
- `engine/differential_oracle.py` (wire target authorization & safe network validation)
- `protocol_ruler.py` (wire target authorization & safe network validation)
- `engine/harness2_engine.py` (harden `normalize_rel` with iterative URL decoding, NFKC normalization, expanded `WIN_DEVICE_NAMES`, and strict `base_dir` containment)
- `database.py` (configure WAL mode, `busy_timeout = 30000`, `synchronous = NORMAL`, `threading.RLock()`, implement `close()`, `__enter__`, `__exit__`, `__del__`, and lock all 9 read methods)
- `continuous_scanner.py` (add `close()` lifecycle)
- `build_all.py` (ensure clean `Database` closing in step 1)
- `tests/test_authorization_and_safety.py` (comprehensive SSRF suite covering all 8 IP categories, cloud metadata, DNS rebinding, and prober gates)
- `tests/test_raptor_integration.py` (deterministic database close)
- `tests/test_terminator_rfc_selector.py` (deterministic database close)
- `tests/test_harness2_integration.py` (deterministic database close)
- `tests/test_swarm_agent.py` (deterministic database close)
- `tests/test_rfcs.py` (deterministic database close)
- `tests/conftest.py` (autouse cleanup fixture clearing file locks and forcing gc)

## Tasks:
1. **Mathematical SSRF & Target Authorization**:
   - Create `engine/safe_network_validator.py`:
     - Provide `is_safe_target_ip(ip_str: str, allow_private: bool = False) -> bool`
     - Provide `validate_target_host(target: str, allow_private: bool = False) -> tuple[bool, str]`
     - Strict mathematical CIDR blocking via `ipaddress`:
       * RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
       * Loopback: `127.0.0.0/8`, `::1` (only permitted when `allow_private=True`)
       * Link-Local / Cloud Metadata: `169.254.0.0/16`, `fe80::/10` (ALWAYS blocked, even if `allow_private=True`)
       * CGNAT: `100.64.0.0/10` (explicit check, because `ip.is_private` returns `False`)
       * Unique Local IPv6: `fc00::/7`
       * Unspecified: `0.0.0.0/8`, `::`
       * IPv4-mapped IPv6: `::ffff:0:0/96`
       * Multi-record DNS resolution validation to block DNS rebinding to any restricted IP
   - In `rfc_hunt_swarm.py:2271`, delete the auto-whitelist call `TargetAuthorizationGate.authorize_target(t_host)`. Require fail-closed validation against `validate_target_host` and `TargetAuthorizationGate.validate_target`.
   - Gate all 5 probers (`DeterministicHarness`, `RQPWeaponizer`, `ActiveFlawProber`, `MultiImplementationDifferentialOracle`, `ProtocolRuler`) using `validate_target_host` before connecting.

2. **Path Traversal & normalize_rel Hardening**:
   - In `engine/harness2_engine.py`:
     - Harden `normalize_rel`:
       * Iterative URL decoding (up to 10 iterations) to fixed point, and check regex `r"%(?:25)*(?:2e|2f|5c|3a|00)"`.
       * Apply `unicodedata.normalize("NFKC", ...)` to defeat homoglyphs.
       * Expand `WIN_DEVICE_NAMES` to include `conin$`, `conout$`, `clock$`.
       * Strip trailing spaces and dots when checking Windows device names: `part.split(".")[0].rstrip(" .").lower()` and `part.rstrip(" .").lower()`.
       * Reject `cleaned == "."` and enforce `resolved != base_path and resolved.is_relative_to(base_path)`.

3. **SQLite WAL Mode & Concurrency Locks**:
   - In `database.py`:
     - In `Database.__init__`, use `sqlite3.connect(..., timeout=30.0)` and `self._lock = threading.RLock()`.
     - Execute `PRAGMA journal_mode = WAL;` (except on in-memory DBs), `PRAGMA busy_timeout = 30000;`, `PRAGMA synchronous = NORMAL;`, `PRAGMA foreign_keys = ON;`.
     - Implement `close()`, `is_closed` property, `__enter__`, `__exit__`, and `__del__`.
     - Protect ALL 9 read methods with `with self._lock:` to eliminate API misuse / InterfaceError under concurrent load.
   - Add `close()`, `__enter__`, and `__exit__` to wrapper classes (`ProtocolResearchSwarm`, `TerminatorMCPServer`, `ContinuousScanner`).
   - Cleanly close database handles across CLI commands (`cmd_harness2`, `cmd_hosts`, `cmd_raptor`) and `build_all.py:72`.
   - Update tests (`test_raptor_integration.py`, `test_terminator_rfc_selector.py`, `test_harness2_integration.py`, `test_swarm_agent.py`, `test_rfcs.py`, `test_authorization_and_safety.py`) to deterministically call `close()`.
   - In `tests/conftest.py`, ensure autouse cleanup closes handles, runs `gc.collect()`, and eliminates Windows `[WinError 32]` collisions in `d:/harfile/.pytest_temp`.

4. **Test Suite & Verification**:
   - Expand `tests/test_authorization_and_safety.py` to cover:
     * All 8 IP categories
     * Cloud metadata immunity
     * CGNAT `100.64.0.0/10`
     * DNS rebinding
     * All 5 probers fail-closed rejection
     * Multi-level percent-encoding path attacks
     * Windows device name path attacks with trailing dots/spaces
   - Run verification commands:
     - `py -3.12 -m pytest tests/test_authorization_and_safety.py tests/test_harness2_integration.py -v`
     - `py -3.12 -m pytest tests/ test_protocol_ruler.py -q`
     - `py -3.12 -u main.py build` (all 8 stages exit code 0)
   - Write comprehensive report to `D:\harfile\rfchunt\.agents\teamwork\worker_m4\handoff.md`.


## 2026-10-18T20:55:36Z
[Message] sender=48cb9587-3e1b-40a9-9a84-e3452d5f5108 priority=MESSAGE_PRIORITY_HIGH
Worker M4 (Security Boundaries & Concurrency Locks) activated.
Implement Milestone 4: Target Authorization & Mathematical SSRF Validation, Path Traversal & normalize_rel Hardening, SQLite WAL Mode & Concurrency Locks, and Test Verification.
