# Explorer Survey 2 Handoff Report: Host Containment & Subprocess Silencing

## 1. Observation

1. **Host Containment Absence**:
   - `find_by_name` for `*containment*` across `D:\harfile\rfchunt` returned 0 results.
   - `engine/host_containment.py` does not exist in the codebase.
2. **Defensive Publisher Hook Status**:
   - Inspection of `engine/defensive_publisher.py` (lines 20–83) showed `DefensiveIntelligencePublisher` publishes `Arm106DefensiveRule` and `Arm107RegressionTest` to SQLite and `data/` JSON files, but contains zero references or parameters for host network containment or firewall integration.
3. **Windows Filtering Platform DLL**:
   - `Test-Path 'C:\Windows\System32\fwpuclnt.dll'` returned `True`.
   - Windows API functions `FwpmEngineOpen0`, `FwpmEngineClose0`, `FwpmTransactionBegin0`, `FwpmTransactionCommit0`, `FwpmTransactionAbort0`, `FwpmFilterAdd0`, `FwpmFilterDeleteById0` reside in `fwpuclnt.dll`.
   - `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001` is the documented Windows kernel flag that binds dynamic filters to the session handle lifecycle, ensuring automatic kernel cleanup upon termination or crash.
4. **Subprocess Noise & Missing Silencing Flags**:
   - `engine/raptor_integrator.py`:
     - Line 108: `res = subprocess.run(["docker", "image", "inspect", ...], capture_output=True, text=True)` lacks `creationflags=CREATE_NO_WINDOW` and `stdin=subprocess.DEVNULL`.
     - Line 166: `proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)` lacks `creationflags=CREATE_NO_WINDOW` and `stdin=subprocess.DEVNULL`.
     - Line 235: `proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, check=False)` lacks `creationflags=CREATE_NO_WINDOW` and `stdin=subprocess.DEVNULL`.
     - Line 323: `proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, check=False)` lacks `creationflags=CREATE_NO_WINDOW` and `stdin=subprocess.DEVNULL`.
   - `build_all.py`:
     - Line 179: `res = subprocess.run(cmd, cwd=str(ROOT_DIR), capture_output=True, text=True, ...)` in `build_step_run_tests` lacks `creationflags=CREATE_NO_WINDOW` and `stdin=subprocess.DEVNULL`.
   - `ollama_manager.py`:
     - Line 119: `subprocess.run([winget_bin, "install", ...])` lacks `creationflags`, `stdin=DEVNULL`, `stdout=DEVNULL`, `stderr=DEVNULL`.
     - Line 152: `subprocess.run([str(installer_path), "/SILENT"], ...)` lacks `creationflags`, `stdin=DEVNULL`, `stdout=DEVNULL`, `stderr=DEVNULL`.
     - Line 162: `subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, ...)` lacks `stdin=DEVNULL`, `stdout=DEVNULL`, `stderr=DEVNULL`.
     - Line 209: `subprocess.Popen([ollama_bin, "serve"], ...)` lacks `stdin=subprocess.DEVNULL`.
     - Line 254: `subprocess.run([ollama_bin, "pull", model_name], ...)` lacks `stdin=subprocess.DEVNULL`.
5. **Existing Test Suite Baseline**:
   - `python.cmd -m pytest tests/` executed 100 unit/integration tests: `100 passed in 176.13s`.
   - `python.cmd -m pytest test_protocol_ruler.py -v` executed 6 tests: `6 passed in 4.22s`.
   - Zero containment tests currently exist in `tests/`.

## 2. Logic Chain

1. From Observation 1, because `engine/host_containment.py` does not exist, Requirement R2 cannot be satisfied until this module is implemented with the required Windows WFP (`fwpuclnt.dll`) and Linux Netlink (`AF_NETLINK` / `NETLINK_NETFILTER`) backends.
2. From Observation 2, because `engine/defensive_publisher.py` currently operates in isolation from network filtering, integrating an optional `HostContainmentManager` hook into `DefensiveIntelligencePublisher` will allow defensive rules derived from confirmed desync flaws to register active host-level containment barriers.
3. From Observation 3, implementing `WindowsWFPContainmentBackend` using `ctypes.WinDLL('fwpuclnt.dll')` with `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001` in `FWPM_SESSION0` passed to `FwpmEngineOpen0` guarantees that the Windows kernel itself manages the lifetime of dynamic containment filters: if the swarm stops cleanly, `FwpmEngineClose0` removes them; if the process is terminated abnormally or crashes, the kernel purges them automatically.
4. From Observation 3, wrapping filter operations in `FwpmTransactionBegin0`, `FwpmTransactionCommit0`, and `FwpmTransactionAbort0` ensures filter changes are atomic, while strict null checks on `self._engine_handle` prevent null pointer dereferences.
5. From Observation 4, external tool executions currently fail the zero console noise invariant because they do not supply `creationflags=0x08000000` (`CREATE_NO_WINDOW`) on Windows and omit `stdin=subprocess.DEVNULL`. Providing centralized helpers (`get_silent_subprocess_kwargs`, `silent_subprocess_run`, `silent_subprocess_popen`) in `engine/host_containment.py` and updating `engine/raptor_integrator.py`, `build_all.py`, and `ollama_manager.py` resolves console popping and hanging stdin descriptors.
6. From Observation 5, because 106 existing tests pass cleanly, adding `tests/test_host_containment.py` will verify handle lifecycle, `FWPM_SESSION_FLAG_DYNAMIC`, `FwpmEngineClose0` cleanup, transaction rollback, Netlink framing, and subprocess silencing invariants without regressing existing test coverage.

## 3. Caveats

- Operating System Privileges: Windows WFP filter additions require elevated privileges (Administrator). When running without elevation (standard user), `FwpmEngineOpen0` returns `FWP_E_ACCESS_DENIED (0x80320005)`. The `HostContainmentManager` design must fail gracefully into a safe `MockContainmentBackend` / dry-run mode for unprivileged development and automated CI testing while issuing appropriate diagnostic warnings.
- Linux Environment: The current test environment is Windows 10/11. Linux Netlink framing must be verified via byte-level structure serialization tests (`struct.pack` validation of `nlmsghdr`, `nfgenmsg`, and `nlattr`).
- No source code in the repository was modified during this survey (strictly read-only).

## 4. Conclusion

The host containment subsystem is completely specified and ready for implementation.
1. Implement `engine/host_containment.py` defining `HostContainmentManager` with:
   - `WindowsWFPContainmentBackend` (`FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`, `FwpmEngineOpen0`, `FwpmTransactionBegin0`, `FwpmTransactionCommit0`, `FwpmTransactionAbort0`, `FwpmEngineClose0`, strict handle null checks, `atexit` cleanup).
   - `LinuxNetlinkContainmentBackend` (`AF_NETLINK`, `NETLINK_NETFILTER`, 16-byte `nlmsghdr`, 4-byte `nfgenmsg`, 4-byte padded `nlattr`, batch teardown).
   - `MockContainmentBackend` (fallback for unprivileged runs & testing).
   - Subprocess silencing helper `get_silent_subprocess_kwargs()` enforcing `CREATE_NO_WINDOW (0x08000000)` and `stdin=subprocess.DEVNULL`.
2. Wire `HostContainmentManager` into `engine/defensive_publisher.py` and swarm lifecycles in `rfc_hunt_swarm.py`, `continuous_scanner.py`, and `main.py`.
3. Patch the identified subprocess calls in `engine/raptor_integrator.py`, `build_all.py`, and `ollama_manager.py`.
4. Add `tests/test_host_containment.py` covering all lifecycle, transactional, dynamic flag, and silencing invariants.

## 5. Verification Method

To independently verify the survey findings:
1. Confirm absence of containment module:
   ```powershell
   Test-Path D:\harfile\rfchunt\engine\host_containment.py
   # Expected: False
   ```
2. Verify WFP DLL presence:
   ```powershell
   Test-Path C:\Windows\System32\fwpuclnt.dll
   # Expected: True
   ```
3. Verify baseline test stability (106 tests):
   ```powershell
   python.cmd -m pytest tests/ -q
   python.cmd -m pytest test_protocol_ruler.py -v
   # Expected: 100 passed in tests/, 6 passed in test_protocol_ruler.py
   ```
4. Verify lack of `CREATE_NO_WINDOW` in `engine/raptor_integrator.py` and `build_all.py`:
   ```powershell
   Select-String -Path D:\harfile\rfchunt\engine\raptor_integrator.py -Pattern "CREATE_NO_WINDOW"
   # Expected: 0 matches
   Select-String -Path D:\harfile\rfchunt\build_all.py -Pattern "CREATE_NO_WINDOW"
   # Expected: 0 matches
   ```
5. Invalidation conditions:
   - If `FwpmEngineOpen0` does not accept `FWPM_SESSION_FLAG_DYNAMIC (0x00000001)`, or
   - If existing tests fail on Python 3.12, this handoff's assumptions are invalidated.
