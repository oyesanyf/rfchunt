# Dispatch Log

## 2026-10-18T17:51:14Z

You are the Project Orchestrator for the RFC Hunt Swarm project at D:\harfile\rfchunt.

Your working directory is:
D:\harfile\rfchunt\.agents\teamwork\orchestrator_1

Read the authoritative user request at:
D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md

Project Root: D:\harfile\rfchunt

Mission Summary:
Perform an exhaustive IETF RFC-compliance and offensive/defensive security engineering review of the HTTP Terminator / RFC Hunt Swarm (D:\harfile\rfchunt), remediating any protocol framing, differential parser, or security boundary defects across all 16 modules while implementing a native, crash-safe host network containment manager (Windows WFP fwpuclnt.dll with FWPM_SESSION_FLAG_DYNAMIC / FwpmEngineClose0, Linux AF_NETLINK sockets, and CREATE_NO_WINDOW subprocess silencing) that guarantees stopping the service or crashing immediately restores the host to a clean state.

Key Requirements:
1. R1: IETF RFC Expert Protocol & Framing Audit across all 16 modules in D:\harfile\rfchunt (RFC 9112/9110/9113/7230/2616 ABNF grammar, 3-step pipelined canary evaluation REQ 1 baseline, REQ 2 candidate, REQ 3 canary; Protocol Ruler binary search calibration; 4-Parser Differential Matrix; Module 16 Google Research Harness² c1..c8 surface, Propose-Probe-Compose, R=4k / P=3k budget ledger, per-domain Library).
2. R2: Native Host-Restoring Containment (engine/host_containment.py wired into engine/defensive_publisher.py and swarm lifecycle):
   - Windows WFP fwpuclnt.dll with FWPM_SESSION_FLAG_DYNAMIC (0x00000001), FwpmEngineOpen0, FwpmTransactionBegin0/Commit0/Abort0, deterministic FwpmEngineClose0 on stop/exit/atexit.
   - Linux AF_NETLINK / NETLINK_NETFILTER in-memory sockets with deterministic teardown.
   - Subprocess silencing: CREATE_NO_WINDOW (0x08000000) and stdin=subprocess.DEVNULL across all external subprocesses.
3. R3: Security Expert Boundary & Invariant Verification: target authorization, SSRF IP-range guards (RFC1918, loopback, link-local, CGNAT, IPv6 unique-local, IPv4-mapped IPv6), path traversal guards (normalize_rel), SQLite concurrency locks.
4. User Rules & Invariants:
   - No mocks / fake dummy data (write genuine working code).
   - Mandatory 3-trial Protocol Research Reproducibility Invariant.
   - Zero-touch PATH and environment.
   - Automatic Git commit & push upon task completion.
5. Verification:
   - py -3.12 -m pytest tests/ test_protocol_ruler.py -v (all tests pass)
   - py -3.12 -u main.py build (exit code 0)

Decompose tasks, dispatch specialist subagents (implementers, reviewers, verifiers), track progress in your progress.md and BRIEFING.md, and notify when complete so victory auditing can be performed.
