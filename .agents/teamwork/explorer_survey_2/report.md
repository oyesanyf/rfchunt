# Host Containment, Network Filtering, and Subprocess Silencing Survey Report

**Explorer**: Explorer 2 (Host Containment & Subprocess Silencing Focus)  
**Date**: 2026-10-18  
**Repository**: `D:\harfile\rfchunt`  
**Integrity Mode**: Development  

---

## Executive Summary

An exhaustive audit of `D:\harfile\rfchunt` was performed focusing on Requirement R2: implementing a crash-safe native host network containment manager (Windows WFP `fwpuclnt.dll` with `FWPM_SESSION_FLAG_DYNAMIC`, Linux `AF_NETLINK` sockets, and `CREATE_NO_WINDOW` subprocess silencing), integrating it with `engine/defensive_publisher.py` and the swarm lifecycle, and verifying test stability.

Key Findings:
1. **Host Containment Module (`engine/host_containment.py`)**: Currently does NOT exist in the repository. A clean, modular implementation is required.
2. **Defensive Publisher (`engine/defensive_publisher.py`)**: Module 12 exists and manages `Arm106DefensiveRule` and `Arm107RegressionTest`, but lacks active hooks into host network containment.
3. **Windows WFP Bindings (`fwpuclnt.dll`)**: `C:\Windows\System32\fwpuclnt.dll` is present on the host. `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001` must be passed inside `FWPM_SESSION0` to `FwpmEngineOpen0` to ensure the Windows kernel automatically purges dynamic filters on process exit or crash. Atomic transaction primitives (`FwpmTransactionBegin0`, `FwpmTransactionCommit0`, `FwpmTransactionAbort0`) and strict pointer/handle null checks with deterministic `FwpmEngineClose0` cleanup must be implemented via `ctypes`.
4. **Linux Netlink (`AF_NETLINK` / `NETLINK_NETFILTER`)**: Requires socket encapsulation with 16-byte `nlmsghdr` framing, 4-byte `nfgenmsg` subsystem framing, 4-byte aligned `nlattr` attributes, and transactional batch teardown (`NFNL_MSG_BATCH_BEGIN` / `NFNL_MSG_BATCH_END`).
5. **Subprocess Noise Audit**:
   - `engine/raptor_integrator.py`: 4 `subprocess.run` calls (lines 108, 166, 235, 323) lack `CREATE_NO_WINDOW (0x08000000)` and `stdin=subprocess.DEVNULL`.
   - `build_all.py`: line 179 (`build_step_run_tests`) lacks `CREATE_NO_WINDOW` and `stdin=subprocess.DEVNULL`.
   - `ollama_manager.py`: lines 119, 152, 162 lack window flags; lines 209 and 254 lack `stdin=subprocess.DEVNULL`.
6. **Current Test Status**: All 106 existing tests (`tests/` 100/100 and `test_protocol_ruler.py` 6/6) pass with 100% success on Python 3.12 (`python.cmd`). Currently, 0 tests exist for host containment; a dedicated test suite `tests/test_host_containment.py` must be added.

---

## 1. Deep Dive: `engine/host_containment.py` & `engine/defensive_publisher.py`

### 1.1 Current State
- `engine/host_containment.py`: File does not exist anywhere in the repository.
- `engine/defensive_publisher.py`:
  - Contains `DefensiveIntelligencePublisher`, which publishes findings into:
    - Arm 106 (`Arm106DefensiveRule`)
    - Arm 107 (`Arm107RegressionTest`)
    - SQLite tables (`arm106_defensive_rules`, `arm107_regression_tests`)
    - JSON files in `data/` (`defensive_rules_arm106.json`, `regression_suite_arm107.json`)
  - Currently, `DefensiveIntelligencePublisher` has no parameter or hook for host network containment.
  - When verified desync/boundary vulnerabilities or rogue probe vectors are identified, there is no coordination with host firewall layers.

### 1.2 Required Architecture for `engine/host_containment.py`
The new module must provide:
1. `HostContainmentManager`: High-level facade providing:
   - Context manager protocol (`__enter__`, `__exit__`)
   - Explicit lifecycle controls (`start()`, `stop()`, `close()`)
   - `atexit` registration (`atexit.register(self.stop)`)
   - Safe idempotence (multiple `stop()` calls do not double-close or error)
   - Dynamic containment rules management (`add_containment_rule`, `remove_containment_rule`)
   - Platform backend routing:
     - `WindowsWFPContainmentBackend` on `sys.platform == 'win32'`
     - `LinuxNetlinkContainmentBackend` on `sys.platform.startswith('linux')`
     - `MockContainmentBackend` for unprivileged / testing / fallback environments
2. Subprocess silencing utility functions:
   - `get_silent_subprocess_kwargs()`
   - `silent_subprocess_run(*args, **kwargs)`
   - `silent_subprocess_popen(*args, **kwargs)`

### 1.3 Missing Swarm Lifecycle Hooks
The host containment manager must wrap the active lifecycle in:
1. `rfc_hunt_swarm.py`:
   - `ProtocolResearchSwarm.__init__`: Instantiate `self.containment = HostContainmentManager()`
   - `main_swarm`: Context manager or `try...finally:` ensuring `containment.start()` before running scans and `containment.stop()` in `finally:`.
2. `continuous_scanner.py`:
   - `ContinuousFlawHunter.__init__` and `run_until_flaw`: Wrap loop in containment lifecycle.
3. `main.py`:
   - `cmd_hunt`, `cmd_evaluate`, `cmd_auto`, `cmd_harness2`: Ensure containment session is active during probe transmission.
4. `engine/defensive_publisher.py`:
   - Add optional `containment_manager: Optional[HostContainmentManager] = None` to `DefensiveIntelligencePublisher.__init__`.
   - In `publish_finding`: When an active finding is confirmed and verified, invoke `self.containment_manager.apply_defensive_rule(arm106_rule)` if available.

---

## 2. Windows Filtering Platform (WFP) ctypes Technical Specification

### 2.1 Library and Symbols
- Target DLL: `C:\Windows\System32\fwpuclnt.dll`
- Functions to bind via `ctypes.WinDLL`:
  - `FwpmEngineOpen0`
  - `FwpmEngineClose0`
  - `FwpmTransactionBegin0`
  - `FwpmTransactionCommit0`
  - `FwpmTransactionAbort0`
  - `FwpmFilterAdd0`
  - `FwpmFilterDeleteById0`

### 2.2 Constant Definitions
```python
FWPM_SESSION_FLAG_DYNAMIC = 0x00000001
RPC_C_AUTHN_DEFAULT = 0
RPC_C_AUTHN_WINNT = 10
FWP_E_ACCESS_DENIED = 0x80320005
ERROR_SUCCESS = 0
```

### 2.3 ctypes Structures
```python
import ctypes
from ctypes import wintypes

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]

class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [
        ("name", wintypes.LPWSTR),
        ("description", wintypes.LPWSTR),
    ]

class FWPM_SESSION0(ctypes.Structure):
    _fields_ = [
        ("sessionKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", wintypes.UINT),               # Must set FWPM_SESSION_FLAG_DYNAMIC (0x00000001)
        ("txnWaitTimeoutInMSec", wintypes.UINT),
        ("processId", wintypes.DWORD),
        ("sid", ctypes.c_void_p),
        ("username", wintypes.LPWSTR),
        ("kernelMode", wintypes.BOOL),
    ]
```

### 2.4 Strict Pointer/Handle Null Checks & Cleanup Contract
1. **Handle Allocation**:
   - `engine_handle = wintypes.HANDLE(0)`
   - Call `FwpmEngineOpen0(None, RPC_C_AUTHN_DEFAULT, None, ctypes.byref(session), ctypes.byref(engine_handle))`
   - Verify `status == ERROR_SUCCESS` AND `engine_handle.value is not None` AND `engine_handle.value != 0`.
2. **Handle Null Guard**:
   - Every operation (`transaction_begin`, `transaction_commit`, `transaction_abort`, `filter_add`, `engine_close`) must verify:
     ```python
     if not self._engine_handle or self._engine_handle.value == 0:
         raise RuntimeError("WFP Engine handle is null or closed")
     ```
3. **Transaction Primitives**:
   - `FwpmTransactionBegin0(handle, 0)` begins an atomic configuration block.
   - If any filter configuration fails: `FwpmTransactionAbort0(handle)`.
   - On success: `FwpmTransactionCommit0(handle)`.
4. **Kernel-Level Cleanup Invariant (`FWPM_SESSION_FLAG_DYNAMIC`)**:
   - Because `FWPM_SESSION_FLAG_DYNAMIC` is passed at `FwpmEngineOpen0`, the Windows kernel associates all session objects with the calling process handle.
   - If `FwpmEngineClose0` is called, the kernel cleanly removes all dynamic filters.
   - If the process terminates, crashes, or is killed via `SIGKILL`/Task Manager, the Windows kernel automatically purges all dynamic filters, restoring the host to pre-session state.
5. **Deterministic User-Space Cleanup**:
   - `FwpmEngineClose0(handle)` is called in `stop()`, context manager `__exit__`, and `atexit` handler.
   - After closure: `self._engine_handle = None` and `self._is_active = False` to prevent double-free.

---

## 3. Linux Netlink Sockets Technical Specification

### 3.1 Constants and Protocol
- Address family: `AF_NETLINK = getattr(socket, 'AF_NETLINK', 16)`
- Protocol: `NETLINK_NETFILTER = getattr(socket, 'NETLINK_NETFILTER', 12)`
- Socket type: `socket.SOCK_RAW`

### 3.2 Binary Message Framing
1. **Netlink Message Header (`nlmsghdr`, 16 bytes)**:
   ```
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          nlmsg_len                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          nlmsg_type           |          nlmsg_flags          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          nlmsg_seq                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          nlmsg_pid                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ```
   Packed with `struct.pack("=IHHII", nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid)`
2. **Netfilter Subsystem Header (`nfgenmsg`, 4 bytes)**:
   ```
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  nfgen_family |    version    |            res_id             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ```
   Packed with `struct.pack("=BBH", nfgen_family, version, res_id)`
3. **Netlink Attributes (`nlattr`)**:
   - `nla_len` (uint16), `nla_type` (uint16), payload
   - Padded with `((len + 3) & ~3) - len` zero bytes for 4-byte boundary alignment.

### 3.3 Transactional Teardown Contract
- Begin batch: `nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFNL_MSG_BATCH_BEGIN`
- Rule / Table operations framed within batch.
- End batch: `nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFNL_MSG_BATCH_END`
- On `stop()`: Send table deletion / teardown message in batch, then close the Netlink socket descriptor.
- Zero leftover firewall rules or dangling chains.

---

## 4. Subprocess Silencing Audit Across Modules

Exhaustive search revealed all external process invocations across `D:\harfile\rfchunt`:

| File | Line | Command / Function | Missing Requirements | Remediation |
|---|---|---|---|---|
| `engine/raptor_integrator.py` | 108 | `docker image inspect` | `CREATE_NO_WINDOW`, `stdin=DEVNULL` | Add `creationflags=CREATE_NO_WINDOW`, `stdin=subprocess.DEVNULL` |
| `engine/raptor_integrator.py` | 166 | `docker run (describe)` | `CREATE_NO_WINDOW`, `stdin=DEVNULL` | Add `creationflags=CREATE_NO_WINDOW`, `stdin=subprocess.DEVNULL` |
| `engine/raptor_integrator.py` | 235 | `docker run (scan)` | `CREATE_NO_WINDOW`, `stdin=DEVNULL` | Add `creationflags=CREATE_NO_WINDOW`, `stdin=subprocess.DEVNULL` |
| `engine/raptor_integrator.py` | 323 | `docker run (host_scan)` | `CREATE_NO_WINDOW`, `stdin=DEVNULL` | Add `creationflags=CREATE_NO_WINDOW`, `stdin=subprocess.DEVNULL` |
| `build_all.py` | 179 | `sys.executable -m pytest` | `CREATE_NO_WINDOW`, `stdin=DEVNULL` | Add `creationflags=CREATE_NO_WINDOW`, `stdin=subprocess.DEVNULL` |
| `ollama_manager.py` | 119 | `winget install` | `CREATE_NO_WINDOW`, `stdin=DEVNULL`, stdout/stderr silence | Add `creationflags`, `stdin=DEVNULL`, `stdout=DEVNULL`, `stderr=DEVNULL` |
| `ollama_manager.py` | 152 | `OllamaSetup.exe /SILENT` | `CREATE_NO_WINDOW`, `stdin=DEVNULL`, stdout/stderr silence | Add `creationflags`, `stdin=DEVNULL`, `stdout=DEVNULL`, `stderr=DEVNULL` |
| `ollama_manager.py` | 162 | `install.sh` (Unix) | `stdin=DEVNULL`, stdout/stderr silence | Add `stdin=DEVNULL`, `stdout=DEVNULL`, `stderr=DEVNULL` |
| `ollama_manager.py` | 209 | `ollama serve` (Popen) | `stdin=subprocess.DEVNULL` (already has `stdout=DEVNULL, stderr=DEVNULL, creationflags`) | Add `stdin=subprocess.DEVNULL` |
| `ollama_manager.py` | 254 | `ollama pull` (run) | `stdin=subprocess.DEVNULL` (already has `stdout=DEVNULL, stderr=DEVNULL, creationflags`) | Add `stdin=subprocess.DEVNULL` |

### Recommended Helper Implementation
In `engine/host_containment.py`:
```python
def get_silent_subprocess_kwargs(**overrides) -> Dict[str, Any]:
    kwargs = {
        "stdin": subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    kwargs.update(overrides)
    return kwargs
```

---

## 5. Existing Tests & Verification Plan

### 5.1 Current Baseline Execution
- Ran full test suite via `python.cmd -m pytest tests/`: **100 passed in 176.13s (0:02:56)**
- Ran protocol ruler suite via `python.cmd -m pytest test_protocol_ruler.py`: **6 passed in 4.22s**
- Baseline stability is 100% (106 / 106 passing).

### 5.2 Tests Required for Requirement R2 (`tests/test_host_containment.py`)
A dedicated test suite `tests/test_host_containment.py` must be implemented with the following test cases:
1. `test_manager_instantiation_and_backend_detection`: Verifies backend selection (WFP on Windows, Netlink on Linux, Mock on test/fallback).
2. `test_context_manager_lifecycle`: Verifies `with HostContainmentManager() as cm:` starts and deterministically stops on block exit.
3. `test_wfp_dynamic_session_flag`: Verifies `FWPM_SESSION_FLAG_DYNAMIC (0x00000001)` is encoded in session flags.
4. `test_wfp_handle_null_checks`: Verifies null handles (`None` or `0`) raise `RuntimeError` on operations.
5. `test_wfp_transaction_primitives`: Verifies begin, commit, and abort rollback on simulated failure.
6. `test_wfp_engine_close_idempotency`: Verifies calling `stop()` or `close()` multiple times is safe and deterministic.
7. `test_atexit_cleanup_registration`: Verifies cleanup callback is registered with `atexit`.
8. `test_linux_netlink_framing`: Verifies 16-byte `nlmsghdr`, 4-byte `nfgenmsg`, and 4-byte padded `nlattr` serialization.
9. `test_subprocess_silencing_kwargs`: Verifies `get_silent_subprocess_kwargs()` enforces `CREATE_NO_WINDOW (0x08000000)` on Windows and `stdin=subprocess.DEVNULL`.
10. `test_defensive_publisher_containment_hook`: Verifies `DefensiveIntelligencePublisher` properly coordinates with `HostContainmentManager`.
11. `test_subprocess_calls_audited`: Verifies that `build_all.py`, `engine/raptor_integrator.py`, and `ollama_manager.py` pass `CREATE_NO_WINDOW` and `stdin=subprocess.DEVNULL`.

---

## 6. Implementation Plan & Concrete Recommendations for Implementer

1. **Step 1**: Create `engine/host_containment.py` with:
   - `HostContainmentManager`
   - `WindowsWFPContainmentBackend` (`fwpuclnt.dll`, `FwpmEngineOpen0`, `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`, `FwpmTransactionBegin0`, `FwpmTransactionCommit0`, `FwpmTransactionAbort0`, `FwpmEngineClose0`)
   - `LinuxNetlinkContainmentBackend` (`AF_NETLINK`, `NETLINK_NETFILTER`, `nlmsghdr`, `nfgenmsg`)
   - `MockContainmentBackend` (mock/dry-run for unprivileged execution & CI)
   - `get_silent_subprocess_kwargs()`, `silent_subprocess_run()`, `silent_subprocess_popen()`
2. **Step 2**: Integrate `HostContainmentManager` into `engine/defensive_publisher.py`:
   - Accept optional `containment_manager` in constructor.
   - Add hook in `publish_finding()` to register containment rules.
3. **Step 3**: Integrate `HostContainmentManager` into swarm lifecycle:
   - `rfc_hunt_swarm.py` (`ProtocolResearchSwarm` and `main_swarm`)
   - `continuous_scanner.py` (`ContinuousFlawHunter`)
   - `main.py` (`cmd_hunt`, `cmd_evaluate`, `cmd_auto`, `cmd_harness2`)
4. **Step 4**: Patch subprocess calls across:
   - `engine/raptor_integrator.py`
   - `build_all.py`
   - `ollama_manager.py`
5. **Step 5**: Create `tests/test_host_containment.py` and run full verification:
   - `python.cmd -m pytest tests/ test_protocol_ruler.py -v`
   - `python.cmd build_all.py`
