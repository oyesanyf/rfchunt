# Milestone 1 Forensic Audit Report & Handoff

**Auditor**: Forensic Auditor M1-1  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\auditor_m1_1`  
**Milestone**: Milestone 1 (Host Network Containment & Subprocess Silencing)  
**Profile**: General Project  
**Integrity Mode**: Development (from `ORIGINAL_REQUEST.md`)  
**Verdict**: **INTEGRITY VIOLATION** (REJECTED)  

---

## Forensic Audit Summary

```markdown
## Forensic Audit Report

**Work Product**: engine/host_containment.py, tests/test_host_containment.py, subprocess silencing in build_all.py, raptor_integrator.py, ollama_manager.py
**Profile**: General Project
**Verdict**: INTEGRITY VIOLATION

### Phase Results
- [Hardcoded test results]: PASS — No fake PASS/FAIL test strings or precomputed answers detected.
- [Facade implementations]: FAIL — Windows WFP backend uses invalid constant `RPC_C_AUTHN_DEFAULT = 0`, causing live `FwpmEngineOpen0` to always fail with `0x00000032` (ERROR_NOT_SUPPORTED); `HostContainmentManager` silently downgrades to `MockContainmentBackend` in all Windows execution; `add_rule()` only records into a Python dictionary.
- [Fabricated verification outputs]: PASS — No pre-seeded log files or false attestation artifacts.
- [Self-certifying / Mocked tests]: FAIL — `tests/test_host_containment.py` mocks out the WFP DLL via `MagicMock()`, concealing the live DLL failure and failing to prove genuine WFP session handle lifecycle.
- [Linux Netlink binary structs]: PASS — Genuine 16-byte `nlmsghdr`, 4-byte `nfgenmsg`, 4-byte aligned `nlattr`, and transactional batch begin/end framing.
- [Subprocess silencing]: PASS — Genuine `CREATE_NO_WINDOW = 0x08000000` and `stdin=subprocess.DEVNULL` across `build_all.py`, `engine/raptor_integrator.py`, and `ollama_manager.py`.
```

---

## 1. Observation

### 1.1 The WFP Authentication Constant Defect (`engine/host_containment.py:123, 234`)
In `engine/host_containment.py`:
```python
122: FWPM_SESSION_FLAG_DYNAMIC: int = 0x00000001
123: RPC_C_AUTHN_DEFAULT: int = 0
124: RPC_C_AUTHN_WINNT: int = 10
...
231:             handle = wintypes.HANDLE(0)
232:             status = dll.FwpmEngineOpen0(
233:                 None,
234:                 RPC_C_AUTHN_DEFAULT,
235:                 None,
236:                 ctypes.byref(session),
237:                 ctypes.byref(handle),
238:             )
```

In the Windows RPC SDK header (`rpcdce.h`), authentication service constants are defined as:
```c
#define RPC_C_AUTHN_NONE          0
#define RPC_C_AUTHN_WINNT         10
#define RPC_C_AUTHN_DEFAULT       0xFFFFFFFF
```
Microsoft's API contract for `FwpmEngineOpen0` states:
> *"authnService: The authentication service to use. The allowed options are RPC_C_AUTHN_WINNT and RPC_C_AUTHN_DEFAULT."*

Because `engine/host_containment.py` defined `RPC_C_AUTHN_DEFAULT = 0` (`RPC_C_AUTHN_NONE`), passing `0` causes `FwpmEngineOpen0` to always fail with Win32 error `0x00000032` (`ERROR_NOT_SUPPORTED`).

### 1.2 Verbatim Empirical Tool Output: Live DLL Failure
Running real WFP initialization against `C:\Windows\System32\fwpuclnt.dll` using the current codebase:
```powershell
python.cmd -c "from engine.host_containment import WindowsWFPContainmentBackend; b = WindowsWFPContainmentBackend(); b.start()"
```
**Output**:
```
FwpmEngineOpen0 failed with status code 0x00000032
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "D:\harfile\rfchunt\engine\host_containment.py", line 246, in start
    raise PermissionError(err_msg)
PermissionError: FwpmEngineOpen0 failed with status code 0x00000032
```

### 1.3 Verbatim Empirical Tool Output: Successful Session with Correct Constants
Verifying against `fwpuclnt.dll` with the correct RPC constants (`0xFFFFFFFF` or `10`):
```powershell
python.cmd -c "import ctypes; from ctypes import wintypes; from engine.host_containment import FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC; dll = ctypes.WinDLL('fwpuclnt.dll'); handle = wintypes.HANDLE(0); sess = FWPM_SESSION0(); sess.flags = FWPM_SESSION_FLAG_DYNAMIC; err = dll.FwpmEngineOpen0(None, 0xFFFFFFFF, None, ctypes.byref(sess), ctypes.byref(handle)); print('Open with 0xFFFFFFFF:', err, 'handle:', handle.value); err_close = dll.FwpmEngineClose0(handle); print('Close:', err_close)"
```
**Output**:
```
Open with 0xFFFFFFFF: 0 handle: 2615567587216
Close: 0
```
This empirically proves that `FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001` and `FwpmEngineClose0` works 100% out of the box on standard Windows user accounts, but was completely broken in the submitted implementation by the invalid `0` constant.

### 1.4 Test Mocking Masking the Broken WFP Binding (`tests/test_host_containment.py:173-199`)
In `tests/test_host_containment.py`:
```python
176:     mock_dll = MagicMock()
177:     mock_dll.FwpmEngineOpen0.return_value = ERROR_SUCCESS
...
193:     with patch.object(backend, "_get_dll", return_value=mock_dll):
194:         # 1. Start dynamic session
195:         assert backend.start() is True
```
No test in `tests/test_host_containment.py` ever called `FwpmEngineOpen0` on `fwpuclnt.dll` without `MagicMock()`. As a result, the unit test suite falsely passed 14/14 tests while the actual Windows WFP backend was completely non-functional.

### 1.5 Silent Runtime Degradation to Mock Backend (`engine/host_containment.py:676-681`)
Because `FwpmEngineOpen0` failed with `0x00000032`, `WindowsWFPContainmentBackend.start()` raised `PermissionError`. In `HostContainmentManager.start()`:
```python
676:             try:
677:                 return self._backend.start()
678:             except PermissionError:
679:                 if self.fallback_to_mock and not isinstance(self._backend, MockContainmentBackend):
680:                     logger.warning("Unprivileged environment detected. Falling back to MockContainmentBackend.")
681:                     self._backend = MockContainmentBackend()
682:                     return self._backend.start()
```
Because of this silent fallback, every execution of `HostContainmentManager()` across `main.py`, `rfc_hunt_swarm.py`, and `continuous_scanner.py` silently downgraded to `MockContainmentBackend()`, completely bypassing WFP.

### 1.6 Acceptance Criteria Violation (`ORIGINAL_REQUEST.md:38`)
The user's acceptance criterion explicitly states:
> *"On Windows, `HostContainmentManager` binds `fwpuclnt.dll` (`FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`, `FwpmTransactionBegin0`, `FwpmTransactionCommit0`, `FwpmTransactionAbort0`, `FwpmEngineClose0`), verifies non-null engine handles, and proves via automated tests that `stop()` / `close()` / context-exit releases the handle via `FwpmEngineClose0` and restores the host to 100% pre-session state."*

The automated tests failed to prove this against `fwpuclnt.dll` because the test exclusively patched `_get_dll` with `MagicMock()`.

---

## 2. Logic Chain

1. **Premise 1**: The user requirements (`ORIGINAL_REQUEST.md`) and project plan (`PROJECT.md`) mandate a production-grade host containment module using Windows Filtering Platform (`fwpuclnt.dll`) with `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001` and deterministic handle release via `FwpmEngineClose0`.
2. **Premise 2**: In `engine/host_containment.py:123`, `RPC_C_AUTHN_DEFAULT` is erroneously declared as `0` instead of `0xFFFFFFFF` (or `RPC_C_AUTHN_WINNT = 10`).
3. **Premise 3**: Invoking `FwpmEngineOpen0` with `authnService = 0` violates the Windows BFE API contract and returns `0x00000032` (`ERROR_NOT_SUPPORTED`).
4. **Premise 4**: Empirical execution confirms that `WindowsWFPContainmentBackend().start()` crashes with `PermissionError` when executed on the target Windows system.
5. **Premise 5**: In `tests/test_host_containment.py`, Worker M1 used `unittest.mock.patch.object(backend, "_get_dll", return_value=mock_dll)` to simulate `FwpmEngineOpen0`, hiding the fact that the live DLL call fails.
6. **Premise 6**: Under the Integrity Forensics protocol (Prohibited Pattern 2: Facade implementations, and Prohibited Pattern 4: Self-certifying / mocked tests), shipping code that fails against live OS APIs while claiming verification through mocks constitutes an integrity violation.
7. **Conclusion**: The Milestone 1 deliverable fails integrity verification and must be rejected for remediation.

---

## 3. Caveats

- **Linux Netlink Implementation**: Verified as clean. The binary struct packing (`struct.pack("=IHHII")`, `struct.pack("=BBH")`, and 4-byte aligned attribute padding) conforms strictly to Linux kernel Netfilter Netlink specifications (`linux/netfilter/nfnetlink.h`).
- **Subprocess Silencing**: Verified as clean. All external subprocess invocations in `build_all.py`, `engine/raptor_integrator.py`, and `ollama_manager.py` specify `CREATE_NO_WINDOW = 0x08000000` on Windows and redirect `stdin=subprocess.DEVNULL`.
- **WFP Structures & Handle Guards**: Struct layouts (`GUID`, `FWPM_DISPLAY_DATA0`, `FWPM_SESSION0`), handle null guards (`_assert_handle_valid`), and `FwpmEngineClose0` bindings are structurally correct once `RPC_C_AUTHN_DEFAULT` is fixed.

---

## 4. Conclusion & Required Remediation

Milestone 1 is **REJECTED** with verdict **INTEGRITY VIOLATION**.

### Specific Remediation Required for Worker M1:
1. **Fix RPC Constants**:
   In `engine/host_containment.py:123`:
   ```python
   # Correct Windows RPC authentication service constants
   RPC_C_AUTHN_WINNT: int = 10
   RPC_C_AUTHN_DEFAULT: int = 0xFFFFFFFF
   ```
2. **Use Correct Constant in `FwpmEngineOpen0`**:
   Ensure `dll.FwpmEngineOpen0(None, RPC_C_AUTHN_DEFAULT, ...)` passes `0xFFFFFFFF` (or `RPC_C_AUTHN_WINNT`).
3. **Add Real, Non-Mocked Live WFP Test**:
   In `tests/test_host_containment.py`, add a test that runs against the actual `fwpuclnt.dll` without mocking `_get_dll`:
   ```python
   def test_wfp_live_dll_session_lifecycle():
       """Verifies that live fwpuclnt.dll can open and close dynamic session without mocks."""
       if sys.platform != "win32":
           pytest.skip("Windows WFP only available on Windows")
       backend = WindowsWFPContainmentBackend()
       assert backend.start() is True
       assert backend.is_active
       assert backend._engine_handle is not None and backend._engine_handle.value != 0
       assert backend.stop() is True
       assert not backend.is_active
       assert backend._engine_handle is None
   ```
4. **Refine Permission & Access Denied Classification**:
   Ensure `transaction_begin()` distinguishes between general errors and `ERROR_ACCESS_DENIED (0x5)`.

---

## 5. Verification Method

To independently reproduce the finding:
1. **Reproduce the Live Failure**:
   ```powershell
   python.cmd -c "from engine.host_containment import WindowsWFPContainmentBackend; b = WindowsWFPContainmentBackend(); b.start()"
   ```
   *Actual Result*: Fails with `PermissionError: FwpmEngineOpen0 failed with status code 0x00000032`.
2. **Verify Correct Constant Works on Same Host**:
   ```powershell
   python.cmd -c "from engine.host_containment import WindowsWFPContainmentBackend; import engine.host_containment as hc; hc.RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF; b = WindowsWFPContainmentBackend(); b.start(); print('Handle:', b._engine_handle.value); b.stop()"
   ```
   *Expected Result*: `Handle: <non-zero integer>` and clean termination.
3. **Inspect Test Mock**:
   Inspect `tests/test_host_containment.py:193` to observe `patch.object(backend, "_get_dll", return_value=mock_dll)`.
