# Dispatch Assignment: Worker M1 (Host Containment & Subprocess Silencing)

## Identity
- Role: Worker (Implementation & Unit Test Verification)
- Working Directory: D:\harfile\rfchunt\.agents\teamwork\worker_m1

## Objective
Read `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md` and `D:\harfile\rfchunt\.agents\teamwork\explorer_survey_2\report.md`.
Implement Milestone 1: Native Host-Restoring Network Containment & Subprocess Silencing.

## Specific Tasks
1. **Implement `engine/host_containment.py`**:
   - `HostContainmentManager` with context manager (`__enter__`, `__exit__`), explicit `start()`, `stop()`, `close()`, and `atexit` registration.
   - Windows WFP (`fwpuclnt.dll` via `ctypes`):
     - `FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001` inside `FWPM_SESSION0`.
     - Atomic transaction primitives (`FwpmTransactionBegin0`, `FwpmTransactionCommit0`, `FwpmTransactionAbort0`).
     - Strict handle pointer / null checks on every operation (`if not self._engine_handle or self._engine_handle.value == 0`).
     - Deterministic cleanup via `FwpmEngineClose0` on stop/exit/atexit.
   - Linux Netlink sockets (`AF_NETLINK` / `NETLINK_NETFILTER`):
     - 16-byte `nlmsghdr`, 4-byte `nfgenmsg`, 4-byte aligned `nlattr` attributes, and transactional batch teardown (`NFNL_MSG_BATCH_BEGIN` / `NFNL_MSG_BATCH_END`).
   - `MockContainmentBackend` for unprivileged / testing / non-WFP fallback environments.
   - Centralized subprocess silencing helpers:
     - `CREATE_NO_WINDOW = 0x08000000`
     - `get_silent_subprocess_kwargs()` returning `creationflags=CREATE_NO_WINDOW` (on Windows) and `stdin=subprocess.DEVNULL`.
     - `silent_subprocess_run()` and `silent_subprocess_popen()`.
2. **Wire Host Containment**:
   - `engine/defensive_publisher.py`: Accept optional `containment_manager` and invoke `apply_defensive_rule` when findings are published.
   - `rfc_hunt_swarm.py`, `continuous_scanner.py`, `main.py`: Ensure containment lifecycle surrounds scanning and hunt executions.
3. **Subprocess Noise Silencing**:
   - In `build_all.py`, `engine/raptor_integrator.py`, and `ollama_manager.py`: pass `creationflags=0x08000000` (on win32) and `stdin=subprocess.DEVNULL` to all `subprocess.run` / `subprocess.Popen` invocations.
4. **Implement Test Suite**:
   - Create `tests/test_host_containment.py` thoroughly testing:
     - WFP handle initialization and null checks
     - `FWPM_SESSION_FLAG_DYNAMIC` (0x00000001) flag assignment
     - Transaction begin/commit/abort behavior
     - Deterministic `FwpmEngineClose0` cleanup in stop(), close(), and context manager exit
     - Idempotent multiple `stop()` calls
     - Netlink message framing and batch message structure
     - `get_silent_subprocess_kwargs` and subprocess silencing flags
5. **Run Verification**:
   - Run `py -3.12 -m pytest tests/test_host_containment.py -v`
   - Run full existing test suite: `py -3.12 -m pytest tests/ test_protocol_ruler.py -v`
   - Document all commands and results in your handoff report.

## Write Ownership
You exclusively own:
- `engine/host_containment.py`
- `engine/defensive_publisher.py`
- `rfc_hunt_swarm.py`
- `continuous_scanner.py`
- `main.py`
- `build_all.py`
- `engine/raptor_integrator.py`
- `ollama_manager.py`
- `tests/test_host_containment.py`

## Mandatory Integrity Warning
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Output
Write your handoff report to:
`D:\harfile\rfchunt\.agents\teamwork\worker_m1\handoff.md`
Send a completion message back to the orchestrator.


## 2026-10-18T18:11:21Z
Received dispatch message:
You are Worker M1 (Host Containment & Subprocess Silencing).
Your working directory is: D:\harfile\rfchunt\.agents\teamwork\worker_m1
Read D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md, D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md, D:\harfile\rfchunt\.agents\teamwork\explorer_survey_2\report.md, and D:\harfile\rfchunt\.agents\teamwork\worker_m1\DISPATCH.md.
