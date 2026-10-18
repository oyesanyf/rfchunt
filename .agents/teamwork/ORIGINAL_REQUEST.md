# Original User Request

## 2026-10-18T17:50:00Z

Requested team: Full multi-agent team (parallel RFC specialists, security auditors, implementers, and independent verifiers)

Perform an exhaustive IETF RFC-compliance and offensive/defensive security engineering review of the HTTP Terminator / RFC Hunt Swarm (`D:\harfile\rfchunt`), remediating any protocol framing, differential parser, or security boundary defects across all 16 modules while implementing a native, crash-safe host network containment manager (Windows WFP `fwpuclnt.dll` with `FWPM_SESSION_FLAG_DYNAMIC` / `FwpmEngineClose0`, Linux `AF_NETLINK` sockets, and `CREATE_NO_WINDOW` subprocess silencing) that guarantees stopping the service or crashing immediately restores the host to a clean state.

Working directory: D:\harfile\rfchunt
Integrity mode: development

## Requirements

### R1. IETF RFC Expert Protocol & Framing Audit (Modules 1–16)
Audit and harden all 16 protocol research modules in `D:\harfile\rfchunt`—including RFC 9112/9110/9113/7230/2616 ABNF grammar extraction, 3-step pipelined canary evaluation (`REQ 1` baseline, `REQ 2` candidate, `REQ 3` canary), Protocol Ruler binary search calibration, the 4-Parser Differential Matrix (`Strict RFC 9112`, `Legacy RFC 2616`, `CDN Edge Proxy`, `Async Microservice Gateway`), and Module 16 Google Research Harness² (`c1..c8` surface, `Propose–Probe–Compose`, `R=4k / P=3k` budget ledger, and per-domain `Library`). Ensure all wire-level parsers, framing mutators, and multi-trial reproducibility gates operate with 100% RFC fidelity and zero unhandled socket, TLS, or encoding errors.

### R2. Native Host-Restoring Containment & Subprocess Hardening
Implement and integrate a production-grade host network containment module in `D:\harfile\rfchunt` (`engine/host_containment.py` wired into `engine/defensive_publisher.py` and the swarm lifecycle):
1. **Windows Filtering Platform (`fwpuclnt.dll`) Dynamic Session Lifecycle**: Open the WFP engine with `FWPM_SESSION_FLAG_DYNAMIC (0x00000001)` (`FwpmEngineOpen0`), enforce strict pointer/handle null checks, wrap filter additions in atomic WFP transactions (`FwpmTransactionBegin0` / `FwpmTransactionCommit0` / `FwpmTransactionAbort0`), and guarantee deterministic handle closure via `FwpmEngineClose0` on service stop, context exit, or `atexit`—ensuring the Windows kernel automatically purges all dynamic filters if the process stops or crashes mid-configuration.
2. **Linux Native Netlink Socket Support (`AF_NETLINK` / `NETLINK_NETFILTER`)**: Provide an in-memory Netlink socket interface on Linux with transactional message framing and deterministic teardown on service stop, without leaving stale `iptables`/`nft` rules behind.
3. **Zero Console Noise (`CREATE_NO_WINDOW` + `DEVNULL`)**: Ensure every external subprocess invocation across the codebase (`engine/raptor_engine.py`, `build_all.py`, fallback wrappers) silences `stdout`/`stderr` or pipes them cleanly with `stdin=subprocess.DEVNULL` and passes `CREATE_NO_WINDOW (0x08000000)` on Windows.

### R3. Security Expert Boundary & Invariant Verification
Audit all target authorization, SSRF IP-range guards (RFC1918, loopback, link-local, CGNAT, IPv6 unique-local, IPv4-mapped IPv6), path traversal guards (`normalize_rel`), and SQLite concurrency locks across `D:\harfile\rfchunt` so that no unvalidated input, path escape, or unauthorized target probe can bypass containment.

## Verification Resources
- Existing test suites: `tests/test_harness2_integration.py`, `tests/test_authorization_and_safety.py`, `tests/test_terminator_improvements.py`, `tests/test_dream_and_caldera.py`, `tests/test_research_engine.py`, `test_protocol_ruler.py`
- Unified build pipeline: `py -3.12 -u main.py build` (`build_all.py`)

## Acceptance Criteria

### Protocol & Security Audit Completeness
- [ ] All 16 modules in `D:\harfile\rfchunt` pass static syntax compilation (`py_compile`) and runtime execution without unhandled exceptions or resource leaks.
- [ ] The 4-Parser Differential Matrix and 3-Step Canary Pipeline enforce the 3-trial Protocol Research Reproducibility Invariant on all candidate findings.
- [ ] Module 16 (Google Research Harness²) validates all 8 `c1..c8` surface components, enforces the exact $R = 4k$ rollouts and $P = 3k$ stages ledger identity in both `parallel` (`agg`) and `sequential` (`seq`) modes, and persists `INDEX.md` and `EXPERIENCE.md` per protocol domain.

### Host-Restoring Containment & Subprocess Silence
- [ ] On Windows, `HostContainmentManager` binds `fwpuclnt.dll` (`FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`, `FwpmTransactionBegin0`, `FwpmTransactionCommit0`, `FwpmTransactionAbort0`, `FwpmEngineClose0`), verifies non-null engine handles, and proves via automated tests that `stop()` / `close()` / context-exit releases the handle via `FwpmEngineClose0` and restores the host to 100% pre-session state.
- [ ] On Linux, `HostContainmentManager` constructs valid `AF_NETLINK` (`NETLINK_NETFILTER`) messages with deterministic teardown on `stop()`.
- [ ] Every subprocess call on Windows uses `CREATE_NO_WINDOW (0x08000000)` and safe stream redirection so zero console popup windows or hanging descriptors occur.

### Automated Test & Build Verification
- [ ] `py -3.12 -m pytest tests/ test_protocol_ruler.py -v` passes 100% of existing and newly added unit/integration tests (including dedicated tests for `HostContainmentManager` handle lifecycle, `FWPM_SESSION_FLAG_DYNAMIC`, `FwpmEngineClose0` cleanup on stop/exception, and `CREATE_NO_WINDOW` enforcement).
- [ ] `py -3.12 -u main.py build` passes all build steps end-to-end with exit code `0`.
