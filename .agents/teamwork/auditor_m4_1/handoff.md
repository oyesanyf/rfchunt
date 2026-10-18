# Forensic Audit Report & Handoff: Milestone 4 (Security Boundaries & Concurrency Locks)

**Work Product**: Milestone 4 Implementation (`engine/safe_network_validator.py`, Prober Gating, `engine/harness2_engine.py` `normalize_rel`, `database.py`, test and build pipelines)  
**Profile**: General Project (Development Mode / Integrity Invariants)  
**Auditor**: Forensic Auditor M4-1 (Integrity Forensics)  
**Date**: 2026-10-18T21:43:30Z  
**Verdict**: **INTEGRITY VIOLATION** (WORK PRODUCT REJECTED)

---

## 1. Observation

Direct code observations, verbatim tool outputs, and empirical test execution results:

1. **Facade Prober Gating in `engine/active_flaw_prober.py`**:
   - `engine/active_flaw_prober.py:56-70` defines `_open_connection()` with `validate_target_host` and `TargetAuthorizationGate.check_target(self.host)`.
   - However, `_open_connection()` is **never called** anywhere within `ActiveFlawProber` or its operational methods.
   - `ActiveFlawProber.__init__` (`lines 36-54`) performs zero validation or authorization checks on `self.host`.
   - `ActiveFlawProber.run_active_audit()` (`lines 164-284`) iterates through all attack probes and directly invokes:
     ```python
     seq_report = self.seq_engine.run_pipelined_canary_sequence(
         self.host, self.port, probe_bytes, use_tls=self.use_tls
     )
     ```
   - `self.seq_engine` (`engine/sequence_engine.py`) has zero imports or invocations of `validate_target_host` or `TargetAuthorizationGate`.
   - When `ActiveFlawProber(host="169.254.169.254", port=80).run_active_audit()` is executed, it sends 23 raw socket connections directly to `169.254.169.254:80` (AWS cloud metadata endpoint) without hitting any SSRF safety boundary or target authorization gate.

2. **Test Suite Failure (`tests/test_ssrf_adversarial_challenge.py`)**:
   - Command: `python.cmd -m pytest tests/test_ssrf_adversarial_challenge.py -v`
   - Verbatim failure output:
     ```
     FAILED tests/test_ssrf_adversarial_challenge.py::test_active_flaw_prober_run_active_audit_socket_gating_finding - AssertionError: SSRF CONTAINMENT BREACH: ActiveFlawProber.run_active_audit() attempted 23 socket connections to ('169.254.169.254', 80) without SSRF validation!
     assert 23 == 0
      +  where 23 = len([('169.254.169.254', 80), ('169.254.169.254', 80), ...])
     ======================== 1 failed, 59 passed in 18.96s ========================
     ```

3. **Unified Build Pipeline Failure (`build_all.py`)**:
   - Command: `python.cmd build_all.py`
   - Build Step 8 (`Full Automated Pytest Verification Suite`) executed `[sys.executable, "-m", "pytest", "tests/", "test_protocol_ruler.py", "-q"]` and failed with exit code 1:
     ```
     [STEP 8] Full Automated Pytest Verification Suite
     -------------------------------------------------------
     [!] FAIL: Test suite failed:
     ........................................................................ [ 17%]
     ........................................................................ [ 35%]
     ........................................................................ [ 52%]
     ........................................................................ [ 70%]
     ........................................................................ [ 87%]
     ........................F.........................                       [100%]
     ================================== FAILURES ===================================
     _______ test_active_flaw_prober_run_active_audit_socket_gating_finding ________
     ...
     E       AssertionError: SSRF CONTAINMENT BREACH: ActiveFlawProber.run_active_audit() attempted 23 socket connections to ('169.254.169.254', 80) without SSRF validation!
     E       assert 23 == 0
     =========================== short test summary info ===========================
     FAILED tests/test_ssrf_adversarial_challenge.py::test_active_flaw_prober_run_active_audit_socket_gating_finding
     1 failed, 409 passed in 101.63s (0:01:41)

     ============================================================================
       BUILD SUMMARY
     ============================================================================
     [FAILURE] Build failed after 104.80 seconds. Please check the logs above.
     ```

4. **Components Passing Verification**:
   - `engine/safe_network_validator.py`: genuine `ipaddress.IPv4Network` / `IPv6Network` mathematical CIDR range checking, zero fake static string checks.
   - `normalize_rel` in `engine/harness2_engine.py`: genuine 10-iteration URL decoding to fixed point, NFKC normalization, multi-level percent-encoding regex rejection, and expanded `WIN_DEVICE_NAMES`.
   - `database.py`: genuine SQLite WAL mode PRAGMAs, `busy_timeout = 30000`, `synchronous = NORMAL`, `threading.RLock()` across all read/write methods, and deterministic `close()` / context-manager lifecycle.
   - Universal zero-touch PATH and environment invariant: process-scoped only in `ollama_manager.py:60`, zero system registry mutations.
   - Prober gating in `deterministic_harness.py`, `weaponizer.py`, `engine/differential_oracle.py`, and `protocol_ruler.py`: verified fail-closed.

---

## 2. Logic Chain

1. In Milestone 4, the user's ground-truth requirement R3 (`ORIGINAL_REQUEST.md:23-25`) and the dispatch assignment mandate:
   *"Audit all target authorization, SSRF IP-range guards (RFC1918, loopback, link-local, CGNAT, IPv6 unique-local, IPv4-mapped IPv6), path traversal guards (`normalize_rel`), and SQLite concurrency locks across `D:\harfile\rfchunt` so that no unvalidated input, path escape, or unauthorized target probe can bypass containment."*
   And dispatch item 1 explicitly requires:
   *"Check prober gating: genuine validation in deterministic_harness.py, weaponizer.py, engine/active_flaw_prober.py, engine/differential_oracle.py, protocol_ruler.py."*
2. Prohibited Pattern #2 under the Integrity Forensics standard explicitly prohibits:
   *"Facade implementations: Correct-looking interfaces with no genuine logic... or modules that import the reference implementation and delegate all calls / interfaces that are bypassed."*
3. The implementation of `ActiveFlawProber` added a correct-looking helper method `_open_connection()`, creating the illusion of safety gating. However, the primary operational entry point of `ActiveFlawProber` (`run_active_audit()`) bypasses `_open_connection()` entirely and routes probe execution to `self.seq_engine.run_pipelined_canary_sequence()`.
4. As demonstrated by `test_active_flaw_prober_run_active_audit_socket_gating_finding`, invoking `run_active_audit()` against a prohibited SSRF target (`169.254.169.254`) fires 23 unvalidated socket connection attempts to the cloud metadata endpoint.
5. In accordance with Dispatch requirement 3, `python.cmd build_all.py` must complete all 8 stages with exit code 0. Because of the failing test in `tests/test_ssrf_adversarial_challenge.py`, Step 8 of `build_all.py` fails and the build process exits with code 1.
6. Under the Integrity Forensics governing rules:
   *"Trust nothing — verify empirically. If ANY check fails, your verdict is INTEGRITY VIOLATION and you MUST reject the work product."*
7. Therefore, the Milestone 4 work product contains an integrity violation (facade prober gating permitting live SSRF containment breach, causing build failure) and must be rejected.

---

## 3. Caveats

No caveats. The failure was independently reproduced and verified across isolated pytest execution and the complete unified build pipeline.

---

## 4. Conclusion

**Verdict: INTEGRITY VIOLATION**

Milestone 4 is **REJECTED**. The implementation contains a facade prober gate in `engine/active_flaw_prober.py` where `_open_connection()` is bypassed by `run_active_audit()`, causing 23 raw socket connections to breach SSRF containment when scanning cloud metadata targets, and causing `build_all.py` to fail at Step 8 with exit code 1.

**Required Remediation**:
1. Gate `ActiveFlawProber.__init__` and/or `ActiveFlawProber.run_active_audit()` with `validate_target_host(self.host, allow_private=is_local)` and `TargetAuthorizationGate.check_target(self.host)` so `run_active_audit()` fails closed immediately before firing any sequence steps.
2. In `engine/sequence_engine.py`, ensure `run_pipelined_canary_sequence()` and `run_cl0_canary_sequence()` also validate destination targets prior to socket connection.
3. Re-run `python.cmd -m pytest tests/test_ssrf_adversarial_challenge.py -v` and `python.cmd build_all.py` to achieve 100% test pass rate and clean build exit code 0.

---

## 5. Verification Method

To independently reproduce the integrity failure:

```powershell
# 1. Reproduce failing prober gating test:
python.cmd -m pytest tests/test_ssrf_adversarial_challenge.py -k test_active_flaw_prober_run_active_audit_socket_gating_finding -v

# 2. Reproduce unified build failure:
python.cmd build_all.py
```
Expected output:
- Test fails with: `AssertionError: SSRF CONTAINMENT BREACH: ActiveFlawProber.run_active_audit() attempted 23 socket connections to ('169.254.169.254', 80) without SSRF validation!`
- `build_all.py` exits with code 1 at `[STEP 8] Full Automated Pytest Verification Suite`.
