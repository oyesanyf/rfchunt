# Dispatch Assignment: Worker M1 Remediation (Audit Fix Implementation)

## Identity
- Role: Worker (Audit Remediation Implementation)
- Working Directory: D:\harfile\rfchunt\.agents\teamwork\worker_m1_rem_1

## Objective
Read:
- `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md`
- `D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md`
- `D:\harfile\rfchunt\.agents\teamwork\auditor_m1_1\handoff.md`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m1_rem_1\report.md`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m1_rem_1\handoff.md`

Implement the exact remediation plan to resolve the Forensic Audit Integrity Violation:
1. **In `engine/host_containment.py`**:
   - Update constants:
     ```python
     RPC_C_AUTHN_WINNT: int = 10
     RPC_C_AUTHN_DEFAULT: int = 0xFFFFFFFF
     ERROR_ACCESS_DENIED: int = 5
     ```
   - In `WindowsWFPContainmentBackend.start()`:
     Verify `dll.FwpmEngineOpen0` passes `RPC_C_AUTHN_DEFAULT` (`0xFFFFFFFF`).
   - In `transaction_begin()`:
     If `status in (FWP_E_ACCESS_DENIED, ERROR_ACCESS_DENIED)` or status == 5: raise `PermissionError` instead of generic `RuntimeError`.
   - In `HostContainmentManager.add_containment_rule()`:
     Handle `PermissionError` cleanly if running unprivileged.
2. **In `tests/test_host_containment.py`**:
   - Add live un-mocked tests against `fwpuclnt.dll` (no MagicMock on `_get_dll`):
     - `test_wfp_live_dll_session_lifecycle`: asserts `backend.start() is True`, `backend.is_active is True`, `backend._engine_handle` is non-null and non-zero, `backend.stop() is True`, and `backend._engine_handle is None`.
     - `test_wfp_live_dll_context_manager`: tests `with WindowsWFPContainmentBackend() as backend:` live session open/close.
     - `test_host_containment_manager_live_windows_session`: tests `with HostContainmentManager(fallback_to_mock=False) as mgr:`, asserting `isinstance(mgr.backend, WindowsWFPContainmentBackend)`.
   - In `test_wfp_dynamic_session_flag_and_structures`: assert `RPC_C_AUTHN_DEFAULT == 0xFFFFFFFF` and `RPC_C_AUTHN_WINNT == 10`.
3. **Run Verification**:
   - `python.cmd -m pytest tests/test_host_containment.py -v`
   - `python.cmd -m pytest tests/test_containment_adversarial_challenge.py -v`
   - `python.cmd -m pytest tests/ test_protocol_ruler.py -q`
   - `python.cmd build_all.py`

## Mandatory Integrity Warning
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Write Ownership
- `engine/host_containment.py`
- `tests/test_host_containment.py`

## Output
Write your handoff report to:
`D:\harfile\rfchunt\.agents\teamwork\worker_m1_rem_1\handoff.md`
Send a completion message back to the orchestrator.


## 2026-10-18T18:43:11Z
Message received from orchestrator (48cb9587-3e1b-40a9-9a84-e3452d5f5108):
Implement remediation for M1:
1. engine/host_containment.py: Fix RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF, RPC_C_AUTHN_WINNT = 10, ERROR_ACCESS_DENIED = 5. Pass RPC_C_AUTHN_DEFAULT to FwpmEngineOpen0. Refine permission error classification in transaction_begin() and add_containment_rule().
2. tests/test_host_containment.py: Add live un-mocked tests against fwpuclnt.dll and assert constant values.
3. Verification and handoff.
