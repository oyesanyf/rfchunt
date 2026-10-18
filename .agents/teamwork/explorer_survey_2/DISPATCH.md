# Dispatch Assignment: Explorer Survey 2 (Host Containment & Subprocess Silencing Focus)

## Identity
- Role: Explorer (Host Containment & Process Silencing Survey)
- Working Directory: D:\harfile\rfchunt\.agents\teamwork\explorer_survey_2

## Objective
Read `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md` and conduct an exhaustive survey of host containment, network filtering, and subprocess handling across `D:\harfile\rfchunt`.
Specifically investigate:
1. `engine/host_containment.py` and `engine/defensive_publisher.py` (current code, missing hooks, integration with swarm lifecycle).
2. Windows WFP bindings via `fwpuclnt.dll`: ctypes definitions, `FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`, transaction primitives (`FwpmTransactionBegin0`, `FwpmTransactionCommit0`, `FwpmTransactionAbort0`), handle null checks, and deterministic cleanup via `FwpmEngineClose0` on stop/exit/atexit.
3. Linux Netlink sockets (`AF_NETLINK` / `NETLINK_NETFILTER`): socket creation, netfilter message framing, transactional teardown.
4. Subprocess silencing across all modules (`engine/raptor_engine.py`, `build_all.py`, fallback wrappers, etc.): check for `CREATE_NO_WINDOW (0x08000000)`, `stdin=subprocess.DEVNULL`, and stdout/stderr capture/redirection.
5. Existing containment tests and what tests need to be written to verify handle lifecycle and cleanup.

## Output
Write your comprehensive survey and findings report to:
`D:\harfile\rfchunt\.agents\teamwork\explorer_survey_2\report.md`
and write your self-contained handoff to:
`D:\harfile\rfchunt\.agents\teamwork\explorer_survey_2\handoff.md`
Then send a completion message to the Project Orchestrator.
