# Handoff Report: Challenger M4-1 (SSRF Adversarial Fuzzing)

**Agent**: Challenger M4-1 (SSRF Adversarial Fuzzing)  
**Roles**: critic, specialist  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\challenger_m4_1`  
**Milestone**: M4 (Security Boundaries & Concurrency Locks)  
**Date**: 2026-10-18T21:42:00Z  
**Verdict**: **REQUEST_CHANGES**  
**Handoff Type**: Hard (Challenge Evaluation Complete)

---

## 1. Observation

Direct empirical observations, verbatim commands, file paths, line numbers, and tool execution outputs:

1. **Adversarial IP Representations & Encoding Variations (`engine/safe_network_validator.py`)**:
   - Tested 54 adversarial targets across 7 distinct attack categories:
     * **Dotted decimal / integer / hex / octal**: `0177.0.0.1`, `0x7f.1`, `2130706433`, `0x7f000001`, `017700000001`, `0x7f.0.0.1`, `0177.1`, `127.1`.
     * **IPv4-mapped IPv6**: `::ffff:127.0.0.1`, `::ffff:169.254.169.254`, `::ffff:10.0.0.1`, `::ffff:100.64.0.1`, `[::ffff:127.0.0.1]`, `[::ffff:169.254.169.254]`, `::ffff:7f00:1`, `::ffff:a9fe:a9fe`, `::ffff:0a00:0001`, `::ffff:6440:0001`.
     * **IPv6 Unique Local Address (ULA)**: `fc00::1`, `fd12:3456:789a::1`, `fd00::1`, `fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`.
     * **Cloud Metadata / Link-Local**: `169.254.169.254`, `fe80::1`, `fd00:ec2::254`, `169.254.0.1`, `169.254.254.254`, `fe80::200:5aee:feaa:20a2`, `http://169.254.169.254:80/latest/meta-data`, `https://[fd00:ec2::254]:80`, `http://[fe80::1]:80`.
     * **Carrier-Grade NAT (RFC 6598)**: `100.64.0.1`, `100.127.255.254`, `100.64.0.0`, `100.127.255.255`, `100.80.12.34`.
     * **Unspecified Bind Addresses**: `0.0.0.0`, `0.0.0.1`, `0.1.2.3`, `0.255.255.255`, `::`.
     * **DNS Rebinding Matrix (Split-Horizon DNS)**: 9 multi-record combinations where public IPs (`93.184.216.34`) were mixed with private RFC1918, metadata IPv4, loopback, IPv6 ULA (`fc00::/7` and `fd00::/8`), IPv4-mapped IPv6, CGNAT, unspecified (`0.0.0.0`), and metadata IPv6 (`fd00:ec2::254`).
   - In all 54 cases, `validate_target_host(target, allow_private=False)` returned `False, <reason>` with descriptive rejection diagnostics. Cloud metadata and IPv4-mapped IPv6 remained strictly blocked even when `allow_private=True`.

2. **CLI Target Authorization & Whitelist Tampering (`rfc_hunt_swarm.py`)**:
   - Subprocess executions of `py -3.12 rfc_hunt_swarm.py --host <target>` with `169.254.169.254`, `10.0.0.1`, `100.64.0.1`, `0.0.0.0`, and `unauthorized-victim.example.com` all exited with return code `1` and printed explicit SSRF or target authorization error diagnostics.
   - `TargetAuthorizationGate.ALLOWED_TARGETS` remained strictly unmutated (`{'127.0.0.1', '::1', '[::1]', 'localhost'}`). The prior CLI auto-whitelisting bypass at line 2271 was verified permanently eliminated.

3. **Gated Probers Socket Verification**:
   - Attached an empirical spy tracker to `socket.create_connection` to record all socket connection attempts when probers were invoked against `169.254.169.254`:
     * `DeterministicHarness(host='169.254.169.254', port=80)`: `run_evaluation()` made **0** socket connection attempts (PASSED).
     * `RQPWeaponizer(host='169.254.169.254', port=80)`: `test_dangling_byte_rqp()`, `test_connection_locked_desync()`, `test_head_range_gadget()` made **0** socket connection attempts (PASSED).
     * `MultiImplementationDifferentialOracle()`: `dispatch_single_target()` made **0** socket connection attempts (PASSED).
     * `ProtocolRuler(host='169.254.169.254', port=80)`: `__init__` raised `PermissionError` immediately, making **0** socket connection attempts (PASSED).

4. **CRITICAL DEFECT OBSERVED: `ActiveFlawProber` SSRF Containment Breach**:
   - Inspecting `engine/active_flaw_prober.py`:
     * Lines 56-70 define `def _open_connection(self) -> socket.socket:`.
     * A full static scan reveals `_open_connection` is **never called anywhere else** in `engine/active_flaw_prober.py`.
     * `ActiveFlawProber.__init__` (lines 35-55) does **not** call `validate_target_host` or `TargetAuthorizationGate.check_target`.
     * `ActiveFlawProber.run_active_audit()` (lines 162-230) does **not** call `validate_target_host` or `TargetAuthorizationGate.check_target`.
     * Line 179 of `active_flaw_prober.py`:
       ```python
       seq_report = self.seq_engine.run_pipelined_canary_sequence(
           self.host, self.port, probe_bytes, use_tls=self.use_tls
       )
       ```
     * In `engine/sequence_engine.py:71`:
       ```python
       sock = socket.create_connection((host, port), timeout=self.default_timeout)
       ```
     * `StatefulProtocolSequenceEngine` creates raw socket connections directly with zero SSRF validation.
   - When running `ActiveFlawProber(host="169.254.169.254", port=80).run_active_audit()`:
     * **23 raw socket connections were attempted directly to `('169.254.169.254', 80)`** (AWS Cloud Metadata IMDSv1/v2).
   - In `tests/test_ssrf_adversarial_challenge.py`:
     ```
     FAILED tests/test_ssrf_adversarial_challenge.py::test_active_flaw_prober_run_active_audit_socket_gating_finding
     AssertionError: SSRF CONTAINMENT BREACH: ActiveFlawProber.run_active_audit() attempted 23 socket connections to ('169.254.169.254', 80) without SSRF validation!
     assert 23 == 0
     ```

5. **Associated Defense-in-Depth Socket Breaches**:
   - `ProtocolResearchOrchestrator(primary_host='169.254.169.254').execute_research_cycle()` attempted 2 raw socket connections to `('169.254.169.254', 80)` via `self.sequence_engine` and `self.metamorphic`.
   - `engine/delta_debugger.py:170` (`DeltaDebugger._default_oracle`) calls `socket.create_connection` with no SSRF validation.
   - `engine/metamorphic_engine.py:165` (`MetamorphicTestingEngine._execute_raw`) calls `socket.create_connection` with no SSRF validation.

---

## 2. Logic Chain

1. **SSRF Validator Integrity**:
   - `engine/safe_network_validator.py` accurately implements RFC CIDR boundaries (`BLOCKED_IPV4_NETWORKS`, `BLOCKED_IPV6_NETWORKS`, `CLOUD_METADATA_IPS`).
   - All adversarial representations (octal, hex, decimal integers, IPv4-mapped IPv6, ULA, link-local, CGNAT, 0.0.0.0/8, and multi-record DNS rebinding) are correctly rejected by `validate_target_host`.

2. **Prober Gating Asymmetry**:
   - Worker M4 intended to gate all 5 probers. In `DeterministicHarness`, `RQPWeaponizer`, `DifferentialOracle`, and `ProtocolRuler`, the socket creation path is routed through methods that invoke `validate_target_host`.
   - In `ActiveFlawProber`, Worker M4 implemented `_open_connection()`, but `ActiveFlawProber` does not use `_open_connection()`. Its operational entry point, `run_active_audit()`, delegates directly to `StatefulProtocolSequenceEngine`.
   - Because neither `ActiveFlawProber.__init__`, `run_active_audit()`, nor `StatefulProtocolSequenceEngine` validate the destination address, `ActiveFlawProber` completely bypasses the SSRF boundary.

3. **Masked Verification Gap**:
   - In `tests/test_authorization_and_safety.py:330`, Worker M4 tested `ActiveFlawProber` with:
     ```python
     prober = ActiveFlawProber(host=forbidden_target, port=80)
     with pytest.raises(PermissionError):
         prober._open_connection()
     ```
   - This test only verified the unused helper method `_open_connection()`. It never tested `prober` instantiation or `prober.run_active_audit()`, allowing the 23-socket SSRF leak to go completely unnoticed.

4. **Invariants Violation**:
   - Rule `containment_ring_breakout_invariants.md` mandates:
     *"All agent containment architectures ... must enforce mathematical and cryptographic verification at every boundary."*
   - Dispatch R3 mandates:
     *"Assert that all 5 probers (DeterministicHarness, RQPWeaponizer, ActiveFlawProber, MultiImplementationDifferentialOracle, ProtocolRuler) fail closed without opening socket connections to these addresses."*
   - Because `ActiveFlawProber` opens 23 unvalidated sockets to forbidden destinations, it fails closed requirements.

---

## 3. Caveats

1. `validate_target_host` in `engine/safe_network_validator.py` is robust and complete. No bugs were found in the validator itself.
2. The CLI in `rfc_hunt_swarm.py` is secure and correctly rejects unauthorized targets without auto-whitelisting them.
3. The defect is strictly caused by missing wiring in `ActiveFlawProber` (and sub-engines `sequence_engine.py`, `delta_debugger.py`, `metamorphic_engine.py`, and `orchestrator.py`) failing to invoke the validator before establishing TCP connections.

---

## 4. Conclusion

**Verdict: REQUEST_CHANGES**

Milestone 4 cannot be approved until `ActiveFlawProber` and its subordinate socket engines fail closed before establishing any raw socket connections.

### Required Remediations

1. **Harden `engine/active_flaw_prober.py`**:
   - In `__init__`, add immediate target validation matching `ProtocolRuler`:
     ```python
     if host in ("0.0.0.0", "::"):
         raise ValueError(f"Target host cannot be {host} (INADDR_ANY listening address). Use 127.0.0.1 or localhost.")
     is_local = host in ("127.0.0.1", "localhost", "::1", "[::1]") or host.startswith("127.")
     from engine.safe_network_validator import validate_target_host
     is_safe, reason = validate_target_host(host, allow_private=is_local)
     if not is_safe:
         raise PermissionError(f"Target '{host}' rejected by SSRF safety boundary: {reason}")
     from mcp_server import TargetAuthorizationGate
     TargetAuthorizationGate.check_target(host)
     ```
   - In `run_active_audit()`, re-verify `validate_target_host(self.host, allow_private=is_local)` at the method entry, raising `PermissionError` before starting the probe loop.

2. **Defense-in-Depth Socket Gating in Sub-Engines**:
   - `engine/sequence_engine.py`: In `run_pipelined_canary_sequence()` and `run_cl0_canary_sequence()`, invoke `validate_target_host(host, allow_private=is_local)` before `socket.create_connection((host, port))`.
   - `engine/delta_debugger.py`: In `_default_oracle()`, invoke `validate_target_host(self.host, allow_private=is_local)` before `socket.create_connection`.
   - `engine/metamorphic_engine.py`: In `_execute_raw()`, invoke `validate_target_host(host, allow_private=is_local)` before `socket.create_connection`.
   - `engine/orchestrator.py`: In `ProtocolResearchOrchestrator.__init__`, validate `primary_host` using `validate_target_host` and `TargetAuthorizationGate.check_target`.

3. **Update Test in `tests/test_authorization_and_safety.py`**:
   - Replace the dead `prober._open_connection()` test with assertions verifying `ActiveFlawProber(host=forbidden_target)` fails closed on initialization and `run_active_audit()` raises `PermissionError` with 0 socket attempts.

---

## 5. Verification Method

### Reproduction Commands

```powershell
# 1. Run the empirical SSRF adversarial challenge test suite:
py -3.12 -m pytest tests/test_ssrf_adversarial_challenge.py -v

# 2. Directly reproduce the 23-socket leak from ActiveFlawProber:
py -3.12 -c "
import socket
from engine.active_flaw_prober import ActiveFlawProber
calls = []
def spy_cc(addr, *args, **kwargs):
    calls.append(addr)
    raise ConnectionRefusedError('Blocked')
socket.create_connection = spy_cc

p = ActiveFlawProber(host='169.254.169.254', port=80)
p.run_active_audit()
print('Total socket connections attempted to metadata:', len(calls))
assert len(calls) == 0, f'LEAK DETECTED: {len(calls)} sockets opened!'
"
```

### Invalidation Conditions
This challenge finding will be invalidated and Milestone 4 approved when:
- `ActiveFlawProber(host="169.254.169.254", port=80)` raises `PermissionError` on `__init__` or `run_active_audit()`.
- `test_active_flaw_prober_run_active_audit_socket_gating_finding` passes with exactly 0 socket connection attempts.
- All 60 tests in `tests/test_ssrf_adversarial_challenge.py` pass cleanly.
