# Dispatch: Worker M4 Remediation (SSRF Socket Gating)

**Role**: Worker M4 Remediation
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\worker_m4_rem_1`
**Timestamp**: 2026-10-18T21:55:00Z

## Read:
- `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md`
- `D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md`
- `D:\harfile\rfchunt\.agents\teamwork\auditor_m4_1\handoff.md` (Integrity Violation Report)
- `D:\harfile\rfchunt\.agents\teamwork\challenger_m4_1\handoff.md` (Challenger Report)
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_rem_1\report.md` (FULL BLUEPRINTS & DROP-IN CODE DIFFS)
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_rem_1\handoff.md`

## Mandatory Integrity Warning:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Write Ownership:
- `engine/active_flaw_prober.py`
- `engine/sequence_engine.py`
- `engine/delta_debugger.py`
- `engine/metamorphic_engine.py`
- `engine/orchestrator.py`

## Implementation Tasks (from explorer_m4_rem_1/report.md §3):
1. **`engine/active_flaw_prober.py`**:
   - In `__init__`: check listening address (`0.0.0.0`, `::`) -> `ValueError`. Precompute `self._is_safe` and `self._is_authorized` using `validate_target_host(host, allow_private=is_local)` and `TargetAuthorizationGate.check_target(host)`.
   - Add `_check_safety(self)` raising `PermissionError` if not safe or not authorized.
   - In `_open_connection(self)`: call `self._check_safety()`.
   - In `run_active_audit(self)`: call `self._check_safety()`, catch `PermissionError`, log containment trace via `self.on_trace`, and immediately return `[]` (0 sockets opened).

2. **`engine/sequence_engine.py`**:
   - In `run_pipelined_canary_sequence()` and `run_cl0_canary_sequence()`: before calling `socket.create_connection`, check `validate_target_host(host, allow_private=is_local)` and `TargetAuthorizationGate.check_target(host)`. If rejected, populate `report.details`, set flags to `False`, and return `report` immediately (0 sockets opened).

3. **`engine/delta_debugger.py`**:
   - In `__init__`: precompute `self._is_safe` and `self._is_authorized`.
   - In `_default_oracle()` and inner `oracle()`: if not safe/authorized, return `False` immediately before `socket.create_connection`.

4. **`engine/metamorphic_engine.py`**:
   - In `_execute_raw()`: before `socket.create_connection`, validate target via `validate_target_host` and `TargetAuthorizationGate.check_target`. If not safe/authorized, return `0, b""` immediately (0 sockets opened).

5. **`engine/orchestrator.py`**:
   - In `ProtocolResearchOrchestrator.__init__`: validate listening address (`0.0.0.0`, `::`) -> `ValueError`, check `validate_target_host(primary_host, allow_private=is_local)` -> `PermissionError`, and check `TargetAuthorizationGate.check_target(primary_host)`.

6. **Verification**:
   - Run: `py -3.12 -m pytest tests/test_ssrf_adversarial_challenge.py -v` (assert all 60 tests pass 100%)
   - Run: `py -3.12 -m pytest tests/test_authorization_and_safety.py -v` (assert all 19 tests pass 100%)
   - Run: `py -3.12 -m pytest tests/ test_protocol_ruler.py -q` (assert all 410+ tests pass)
   - Run: `py -3.12 -u build_all.py` (assert all 8 stages pass with exit code 0)

Write handoff report to `D:\harfile\rfchunt\.agents\teamwork\worker_m4_rem_1\handoff.md` and send a completion message back to orchestrator.
