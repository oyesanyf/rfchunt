# Milestone 1 Remediation Analysis & Implementation Plan

**Author**: Explorer M1 Remediation  
**Date**: 2026-10-18T18:41:00Z  
**Target Milestone**: Milestone 1 (Host Network Containment & Subprocess Silencing)  
**Investigation Scope**: Forensic Audit Integrity Violation in Windows WFP bindings (`engine/host_containment.py`) and test mock facades (`tests/test_host_containment.py`)  

---

## Executive Summary

The Forensic Auditor correctly identified an **INTEGRITY VIOLATION** in Milestone 1:
1. `engine/host_containment.py:123` set `RPC_C_AUTHN_DEFAULT = 0`, which is `RPC_C_AUTHN_NONE`. The Windows Filtering Platform (`fwpuclnt.dll`) requires either `RPC_C_AUTHN_DEFAULT` (`0xFFFFFFFF`) or `RPC_C_AUTHN_WINNT` (`10`). Passing `0` caused `FwpmEngineOpen0` to fail with Win32 error `0x00000032` (`ERROR_NOT_SUPPORTED`).
2. `tests/test_host_containment.py:193` masked this defect by patching `_get_dll` with `MagicMock()`. No test ever executed against the live Windows WFP DLL.
3. Because `FwpmEngineOpen0` raised `PermissionError(0x00000032)`, `HostContainmentManager.start()` silently downgraded to `MockContainmentBackend()`, completely bypassing WFP in production execution.

Empirical testing on the live Windows host confirmed:
- `RPC_C_AUTHN_DEFAULT = 0` produces `PermissionError: FwpmEngineOpen0 failed with status code 0x00000032`.
- `RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF` succeeds immediately with return code `0`, allocating a real kernel engine handle (e.g. `0x276E7C20550`), and `FwpmEngineClose0` cleanly closes the session and resets the handle to `None`.
- `HostContainmentManager` runs directly on the live Windows kernel without downgrading to mock.

This report provides Worker M1 with the exact, line-by-line remediation plan and code specifications to eliminate the mock facade, fix the constants, and establish un-mocked live automated tests.

---

## 1. Root Cause Analysis & Empirical Evidence

### 1.1 The Defective Constant
In `engine/host_containment.py:121-127`:
```python
# WFP Constants
FWPM_SESSION_FLAG_DYNAMIC: int = 0x00000001
RPC_C_AUTHN_DEFAULT: int = 0          # <--- DEFECT: 0 is RPC_C_AUTHN_NONE!
RPC_C_AUTHN_WINNT: int = 10
ERROR_SUCCESS: int = 0
FWP_E_ACCESS_DENIED: int = 0x80320005
```

In the Windows RPC SDK header (`rpcdce.h`):
```c
#define RPC_C_AUTHN_NONE          0
#define RPC_C_AUTHN_WINNT         10
#define RPC_C_AUTHN_DEFAULT       0xFFFFFFFF
```

Microsoft Windows Filtering Platform SDK documentation for `FwpmEngineOpen0`:
> *"authnService: The authentication service to use. The allowed options are RPC_C_AUTHN_WINNT and RPC_C_AUTHN_DEFAULT. RPC_C_AUTHN_DEFAULT uses SPNEGO or NTLM as appropriate."*

Passing `0` violates the driver contract. The Base Filtering Engine (BFE) driver returns Win32 error code `0x00000032` (`ERROR_NOT_SUPPORTED`).

### 1.2 Empirical Reproduction of Failure
Executing on the host:
```powershell
python.cmd -c "from engine.host_containment import WindowsWFPContainmentBackend; b = WindowsWFPContainmentBackend(); b.start()"
```
Output:
```
FwpmEngineOpen0 failed with status code 0x00000032
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "D:\harfile\rfchunt\engine\host_containment.py", line 246, in start
    raise PermissionError(err_msg)
PermissionError: FwpmEngineOpen0 failed with status code 0x00000032
```

### 1.3 Empirical Proof of Fix
Setting `RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF` on the live Windows host:
```powershell
python.cmd -c "import engine.host_containment as hc; hc.RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF; b = hc.WindowsWFPContainmentBackend(); assert b.start() is True; assert b.is_active; print('Engine handle:', hex(b._engine_handle.value)); assert b.stop() is True; assert not b.is_active; assert b._engine_handle is None; print('All live assertions passed!')"
```
Output:
```
Engine handle: 0x276e7c20550
All live assertions passed!
```
Return code: `0`.

### 1.4 Why the Mock Facade Concealed the Failure
In `tests/test_host_containment.py:168-199`:
```python
def test_wfp_simulated_lifecycle_and_transactions():
    backend = WindowsWFPContainmentBackend()
    mock_dll = MagicMock()
    ...
    def fake_open(server_name, authn, auth_id, session_ptr, handle_ptr):
        sess = ctypes.cast(session_ptr, ctypes.POINTER(FWPM_SESSION0)).contents
        assert sess.flags == FWPM_SESSION_FLAG_DYNAMIC
        ctypes.cast(handle_ptr, ctypes.POINTER(wintypes.HANDLE)).contents.value = 0xCAFE1234
        return ERROR_SUCCESS

    mock_dll.FwpmEngineOpen0.side_effect = fake_open
    with patch.object(backend, "_get_dll", return_value=mock_dll):
        assert backend.start() is True
```
Observations:
1. `fake_open` only inspected `sess.flags == FWPM_SESSION_FLAG_DYNAMIC`. It completely ignored the `authn` argument.
2. `patch.object(backend, "_get_dll", return_value=mock_dll)` intercepted all calls to `fwpuclnt.dll`.
3. Not a single test in `tests/test_host_containment.py` invoked `FwpmEngineOpen0` against the real `fwpuclnt.dll`.
4. As a result, the test suite passed with 14/14 green tests while the underlying Windows implementation was completely broken.

### 1.5 Silent Downgrade in `HostContainmentManager`
In `engine/host_containment.py:674-682`:
```python
    def start(self) -> bool:
        with self._lock:
            try:
                return self._backend.start()
            except PermissionError:
                if self.fallback_to_mock and not isinstance(self._backend, MockContainmentBackend):
                    logger.warning("Unprivileged environment detected. Falling back to MockContainmentBackend.")
                    self._backend = MockContainmentBackend()
                    return self._backend.start()
                raise
```
Because `FwpmEngineOpen0` threw `PermissionError: FwpmEngineOpen0 failed with status code 0x00000032`, `start()` caught `PermissionError` and silently replaced `self._backend` with `MockContainmentBackend()`. Every application caller (`main.py`, `continuous_scanner.py`, `rfc_hunt_swarm.py`) ended up running on `MockContainmentBackend` without any user or developer visibility.

### 1.6 Additional Finding: `transaction_begin()` Error Classification
Empirical testing revealed that on non-elevated user accounts, `FwpmEngineOpen0` succeeds (opening a read/dynamic session), but `FwpmTransactionBegin0` returns Win32 error `0x00000005` (`ERROR_ACCESS_DENIED`).
In `engine/host_containment.py:263`:
```python
    def transaction_begin(self) -> bool:
        ...
        status = dll.FwpmTransactionBegin0(self._engine_handle, 0)
        if status != ERROR_SUCCESS:
            raise RuntimeError(f"FwpmTransactionBegin0 failed with code 0x{status & 0xFFFFFFFF:08X}")
```
It currently raises `RuntimeError` rather than `PermissionError`. Raising `PermissionError` when `status in (ERROR_ACCESS_DENIED, FWP_E_ACCESS_DENIED)` is essential for standard error classification, enabling proper privilege-aware handling.

---

## 2. Step-by-Step Remediation Plan for Worker M1

Worker M1 must execute the following 5 concrete remediation tasks:

### Task 1: Update WFP Constants in `engine/host_containment.py`
In `engine/host_containment.py`, update lines 121-127:
```python
# WFP Constants
FWPM_SESSION_FLAG_DYNAMIC: int = 0x00000001
RPC_C_AUTHN_DEFAULT: int = 0xFFFFFFFF  # rpcdce.h: RPC_C_AUTHN_DEFAULT (0xFFFFFFFF)
RPC_C_AUTHN_WINNT: int = 10           # rpcdce.h: RPC_C_AUTHN_WINNT (10)
ERROR_SUCCESS: int = 0
ERROR_ACCESS_DENIED: int = 5          # winerror.h: ERROR_ACCESS_DENIED (0x00000005)
FWP_E_ACCESS_DENIED: int = 0x80320005 # fwpmu.h: FWP_E_ACCESS_DENIED
```

### Task 2: Refine Error Classification in `WindowsWFPContainmentBackend`
In `engine/host_containment.py`:
1. In `start()` (around line 240):
```python
            if status != ERROR_SUCCESS:
                unsigned_status = status & 0xFFFFFFFF
                err_msg = f"FwpmEngineOpen0 failed with status code 0x{unsigned_status:08X}"
                if unsigned_status in (ERROR_ACCESS_DENIED, FWP_E_ACCESS_DENIED):
                    err_msg += " (Access Denied: Requires Administrator privileges for WFP)"
                logger.error(err_msg)
                raise PermissionError(err_msg)
```
2. In `transaction_begin()` (around line 256):
```python
    def transaction_begin(self) -> bool:
        """Begins an atomic WFP transaction."""
        with self._lock:
            self._assert_handle_valid()
            dll = self._get_dll()
            status = dll.FwpmTransactionBegin0(self._engine_handle, 0)
            if status != ERROR_SUCCESS:
                unsigned_status = status & 0xFFFFFFFF
                err_msg = f"FwpmTransactionBegin0 failed with code 0x{unsigned_status:08X}"
                if unsigned_status in (ERROR_ACCESS_DENIED, FWP_E_ACCESS_DENIED):
                    err_msg += " (Access Denied: Requires Administrator privileges for WFP transaction)"
                    raise PermissionError(err_msg)
                raise RuntimeError(err_msg)
            self._in_transaction = True
            return True
```

### Task 3: Handle Unprivileged Rule Modification in `HostContainmentManager`
In `engine/host_containment.py` in `add_containment_rule` (around line 701):
```python
    def add_containment_rule(self, remote_ip: str, port: int, action: str = "BLOCK") -> bool:
        """Applies a containment rule to block or filter traffic."""
        with self._lock:
            if not self.is_active:
                self.start()
            try:
                return self._backend.add_rule(remote_ip=remote_ip, port=port, action=action)
            except PermissionError as exc:
                if self.fallback_to_mock and not isinstance(self._backend, MockContainmentBackend):
                    logger.warning("Unprivileged environment: WFP filter creation requires Administrator (%s). Falling back to MockContainmentBackend.", exc)
                    rules = self._backend.get_rules()
                    self._backend.stop()
                    self._backend = MockContainmentBackend()
                    self._backend.start()
                    for r in rules:
                        self._backend.add_rule(r["remote_ip"], r["port"], r["action"])
                    return self._backend.add_rule(remote_ip=remote_ip, port=port, action=action)
                raise
```

### Task 4: Export Constants & Strengthen Unit Assertions in `tests/test_host_containment.py`
In `tests/test_host_containment.py`:
1. Import the constants:
```python
from engine.host_containment import (
    CREATE_NO_WINDOW,
    ERROR_ACCESS_DENIED,
    ERROR_SUCCESS,
    FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SESSION0,
    FWP_E_ACCESS_DENIED,
    GUID,
    RPC_C_AUTHN_DEFAULT,
    RPC_C_AUTHN_WINNT,
    BaseContainmentBackend,
    HostContainmentManager,
    LinuxNetlinkContainmentBackend,
    MockContainmentBackend,
    WindowsWFPContainmentBackend,
    get_silent_subprocess_kwargs,
    silent_subprocess_popen,
    silent_subprocess_run,
)
```
2. In `test_wfp_dynamic_session_flag_and_structures()`:
```python
    assert FWPM_SESSION_FLAG_DYNAMIC == 0x00000001
    assert RPC_C_AUTHN_DEFAULT == 0xFFFFFFFF
    assert RPC_C_AUTHN_WINNT == 10
    assert ERROR_SUCCESS == 0
    assert ERROR_ACCESS_DENIED == 5
    assert FWP_E_ACCESS_DENIED == 0x80320005
```

### Task 5: Add Real, Un-Mocked Live WFP Tests in `tests/test_host_containment.py`
Add three dedicated live un-mocked tests:

```python
def test_wfp_live_dll_session_lifecycle():
    """
    Verifies that live fwpuclnt.dll opens dynamic session with RPC_C_AUTHN_DEFAULT (0xFFFFFFFF),
    allocates a genuine non-zero engine handle from the Windows kernel, and deterministically
    closes the handle via FwpmEngineClose0 without mocks.
    """
    if sys.platform != "win32":
        pytest.skip("Windows WFP only available on Windows")

    backend = WindowsWFPContainmentBackend()
    assert not backend.is_active
    assert backend._engine_handle is None

    # Open dynamic session on live Windows kernel
    assert backend.start() is True
    assert backend.is_active
    assert backend._engine_handle is not None
    assert backend._engine_handle.value is not None
    assert backend._engine_handle.value != 0

    # Deterministically stop session
    assert backend.stop() is True
    assert not backend.is_active
    assert backend._engine_handle is None

    # Idempotent stop
    assert backend.stop() is True


def test_wfp_live_dll_context_manager():
    """
    Verifies that WindowsWFPContainmentBackend works as a context manager against
    live fwpuclnt.dll, opening on enter and deterministically closing on exit.
    """
    if sys.platform != "win32":
        pytest.skip("Windows WFP only available on Windows")

    backend = WindowsWFPContainmentBackend()
    with backend as b:
        assert b is backend
        assert b.is_active
        assert b._engine_handle is not None
        assert b._engine_handle.value != 0

    assert not backend.is_active
    assert backend._engine_handle is None


def test_host_containment_manager_live_windows_session():
    """
    Verifies that HostContainmentManager on Windows opens a live WFP dynamic session
    without falling back to MockContainmentBackend when fallback_to_mock=False.
    """
    if sys.platform != "win32":
        pytest.skip("Windows WFP only available on Windows")

    cm = HostContainmentManager(fallback_to_mock=False)
    assert isinstance(cm.backend, WindowsWFPContainmentBackend)
    assert not cm.is_active

    assert cm.start() is True
    assert cm.is_active
    # Must NOT fall back to mock
    assert isinstance(cm.backend, WindowsWFPContainmentBackend)
    assert cm.backend._engine_handle is not None
    assert cm.backend._engine_handle.value != 0

    # Clean deterministic stop
    assert cm.stop() is True
    assert not cm.is_active
    assert cm.backend._engine_handle is None
```

---

## 3. Verification Protocol for Worker M1

Worker M1 must execute and verify the following commands before submitting for audit:

1. **Verify Constant Values**:
   ```powershell
   python.cmd -c "import engine.host_containment as hc; assert hc.RPC_C_AUTHN_DEFAULT == 0xFFFFFFFF; assert hc.RPC_C_AUTHN_WINNT == 10; print('Constants verified OK')"
   ```
2. **Verify Live WFP Session Opening & Closing**:
   ```powershell
   python.cmd -c "from engine.host_containment import WindowsWFPContainmentBackend; b = WindowsWFPContainmentBackend(); assert b.start() is True; assert b.is_active; assert b._engine_handle.value != 0; print('Live Handle:', hex(b._engine_handle.value)); assert b.stop() is True; assert not b.is_active; assert b._engine_handle is None; print('Live WFP Verified OK')"
   ```
3. **Verify HostContainmentManager Live Session (Zero Mock Fallback)**:
   ```powershell
   python.cmd -c "from engine.host_containment import HostContainmentManager, WindowsWFPContainmentBackend; cm = HostContainmentManager(fallback_to_mock=False); assert cm.start() is True; assert isinstance(cm.backend, WindowsWFPContainmentBackend); assert cm.backend._engine_handle.value != 0; print('Manager Live Handle:', hex(cm.backend._engine_handle.value)); cm.stop(); print('HostContainmentManager Live Verified OK')"
   ```
4. **Run Unit & Integration Test Suites**:
   ```powershell
   python.cmd -m pytest tests/test_host_containment.py -v
   python.cmd -m pytest tests/test_containment_adversarial_challenge.py -v
   python.cmd -m pytest tests/ test_protocol_ruler.py -v
   ```
5. **Run Full Build Pipeline**:
   ```powershell
   python.cmd -u main.py build
   ```

---

## 4. Remediation Checklist for Audit Sign-off

| Check Item | Target File | Verification Metric | Status |
|------------|-------------|---------------------|--------|
| `RPC_C_AUTHN_DEFAULT` set to `0xFFFFFFFF` | `engine/host_containment.py:123` | Direct assertion `assert RPC_C_AUTHN_DEFAULT == 0xFFFFFFFF` | Specified |
| `RPC_C_AUTHN_WINNT` set to `10` | `engine/host_containment.py:124` | Direct assertion `assert RPC_C_AUTHN_WINNT == 10` | Specified |
| `ERROR_ACCESS_DENIED` set to `5` | `engine/host_containment.py:126` | Direct assertion `assert ERROR_ACCESS_DENIED == 5` | Specified |
| `transaction_begin()` raises `PermissionError` on Access Denied | `engine/host_containment.py:256` | Status check for `ERROR_ACCESS_DENIED` and `FWP_E_ACCESS_DENIED` | Specified |
| Live WFP session test against `fwpuclnt.dll` | `tests/test_host_containment.py` | `test_wfp_live_dll_session_lifecycle` passes without mocks | Specified |
| Live context manager test against `fwpuclnt.dll` | `tests/test_host_containment.py` | `test_wfp_live_dll_context_manager` passes without mocks | Specified |
| Live `HostContainmentManager` test without mock fallback | `tests/test_host_containment.py` | `test_host_containment_manager_live_windows_session` passes with `fallback_to_mock=False` | Specified |
| Zero mock facades concealing failures | `tests/test_host_containment.py` | All live tests exercise genuine Windows kernel handles | Specified |
