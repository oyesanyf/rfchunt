# Project: RFC Hunt Swarm IETF RFC-Compliance & Security Remediation

## Architecture
The HTTP Terminator / RFC Hunt Swarm is an autonomous network protocol security research system comprising 16 modular subsystems, a native host containment firewall layer, a 4-parser differential oracle, and recursive agent harnessing.
- **Protocol Grammar & Synthesis**: Modules 1-3 (`abnf_engine.py`, `probe_generator.py`, `bandit_scheduler.py`, `semantic_compiler.py`)
- **Differential & Sequencing Oracles**: Modules 4-7 (`differential_oracle.py`, `sequence_engine.py`, `errata_tracker.py`, `metamorphic_engine.py`)
- **Minimization, Attribution & Boundary Analysis**: Modules 8-11 (`delta_debugger.py`, `causal_classifier.py`, `boundary_analyzer.py`, `knowledge_graph.py`)
- **Defensive Publishing & Bridge Ecosystems**: Modules 12-15 (`defensive_publisher.py`, `dream_world_model.py`, `caldera_bridge.py`, `raptor_integrator.py`)
- **Recursive Agent Harnessing**: Module 16 (`harness2_engine.py`)
- **Host Containment Layer**: `engine/host_containment.py` (Windows WFP dynamic sessions via `fwpuclnt.dll`, Linux `AF_NETLINK` sockets, subprocess silencing)
- **Security Boundaries**: Target authorization gate, mathematical SSRF validator, hardened `normalize_rel`, SQLite WAL concurrency locks.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Windows WFP Dynamic Containment | `fwpuclnt.dll` `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`, `FwpmEngineOpen0`, transactions, deterministic `FwpmEngineClose0` on stop/exit/atexit | M1 | R2 |
| 2 | Linux Netlink Containment | `AF_NETLINK` / `NETLINK_NETFILTER` in-memory sockets with transactional batch teardown | M1 | R2 |
| 3 | Subprocess Silencing | `CREATE_NO_WINDOW (0x08000000)` and `stdin=subprocess.DEVNULL` across all external subprocesses | M1 | R2 |
| 4 | Host Containment Swarm Wiring | Wire `HostContainmentManager` into `defensive_publisher.py`, `rfc_hunt_swarm.py`, `continuous_scanner.py`, `main.py` | M1 | R2 |
| 5 | Differential Oracle Clean-up | Remove dead stub in `engine/differential_oracle.py:116-139` and ensure offline 4-parser matrix integrity | M2 | R1 |
| 6 | ABNF Multi-Line Grammar Parsing | Harden `engine/abnf_engine.py` for multi-line indented ABNF rule continuations | M2 | R1 |
| 7 | 3-Step Pipelined Canary Sequence | Enforce `REQ 1` baseline, `REQ 2` probe, `REQ 3` canary with `HTTPFramingReader` and artifact rejection | M2 | R1 |
| 8 | 3-Trial Reproducibility Invariant | Delta debugger, Merkle audit, and causal classifier enforce >=3 trials and >=60% repro rate | M2 | R1 |
| 9 | 4-Parser Differential Matrix | Strict RFC 9112, Legacy RFC 2616, CDN Proxy, Async Microservice differential divergence testing | M2 | R1 |
| 10 | Module 16 Harness² Surface | Validate all 8 `c1..c8` surface components (`RFCHUNT_SURFACE`) and Propose-Probe-Compose recursion | M3 | R1 |
| 11 | Module 16 Budget Ledger | Enforce exact mathematical identities $R = 4k$ rollouts and $P = 3k$ stages in parallel (`agg`) and sequential (`seq`) modes | M3 | R1 |
| 12 | Module 16 Experience Library | Persist domain-specific `INDEX.md` and `EXPERIENCE.md` with operational cues and empirical evidence | M3 | R1 |
| 13 | Protocol Ruler Calibration | Verify coarse stepped bracket and single-byte binary search calibration down to 1-byte resolution | M3 | R1 |
| 14 | Target Authorization Remediation | Remediate CLI auto-authorization bypass in `rfc_hunt_swarm.py:2269` and gate all raw socket probers | M4 | R3 |
| 15 | Mathematical SSRF Guards | Mathematical IP validation via `ipaddress` blocking RFC1918, loopback, link-local/cloud metadata, CGNAT, IPv6 ULA, IPv4-mapped IPv6, and DNS resolution validation | M4 | R3 |
| 16 | Path Traversal Hardening | Harden `normalize_rel` against double percent-encoding, encoded colons, Windows device names, and post-join escape | M4 | R3 |
| 17 | SQLite WAL & Concurrency Locks | Enable `PRAGMA journal_mode = WAL;`, busy timeout 30s, and connection locks across concurrent tasks | M4 | R3 |
| 18 | Containment Unit & Integration Tests | Comprehensive tests in `tests/test_host_containment.py` for handle lifecycle, DYNAMIC flag, and subprocess silencing | M5 | Acceptance |
| 19 | Full Pytest Suite Verification | `py -3.12 -m pytest tests/ test_protocol_ruler.py -v` (100% pass) | M5 | Acceptance |
| 20 | Unified Build Verification | `py -3.12 -u main.py build` (all 8 stages exit code 0) | M5 | Acceptance |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Host Containment & Subprocess Silencing | `engine/host_containment.py`, Windows WFP `fwpuclnt.dll` DYNAMIC session, Linux Netlink, `CREATE_NO_WINDOW` & `DEVNULL` silencing, integration hooks | none | IN_PROGRESS |
| M2 | Protocol Framing & 4-Parser Differential Matrix | Dead stub removal, ABNF multi-line rules, 3-step canary pipeline, 3-trial reproducibility invariant, 4-parser differential matrix | none | PLANNED |
| M3 | Module 16 Google Research Harness² & Protocol Ruler | `c1..c8` surface verification, Propose-Probe-Compose, $R=4k$ / $P=3k$ ledger identity, per-domain library persistence, Protocol Ruler verification | M2 | PLANNED |
| M4 | Security Boundaries & Concurrency Locks | Target authorization fix, mathematical `ipaddress` SSRF validation, hardened `normalize_rel`, SQLite WAL & locks | M1, M2 | PLANNED |
| M5 | Full Verification, E2E Testing & Build Pipeline | `tests/test_host_containment.py`, all unit/integration tests (`pytest tests/ test_protocol_ruler.py -v`), `main.py build` exit 0 | M1, M2, M3, M4 | PLANNED |

## Interface Contracts
### HostContainmentManager ↔ DefensivePublisher & Swarm
```python
class HostContainmentManager:
    def __init__(self, fallback_to_mock: bool = True) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def close(self) -> None: ...
    def __enter__(self) -> "HostContainmentManager": ...
    def __exit__(self, exc_type, exc_val, exc_tb) -> None: ...
    def add_containment_rule(self, remote_ip: str, port: int, action: str = "BLOCK") -> bool: ...
    def apply_defensive_rule(self, rule: Any) -> bool: ...
```

### SafeNetworkValidator ↔ Probers & Swarm
```python
def is_safe_target_ip(ip_str: str) -> bool: ...
def validate_target_host(target: str, allow_private: bool = False) -> tuple[bool, str]: ...
```

### Path Sanitizer ↔ Harness² Engine
```python
def normalize_rel(path_str: str, base_dir: Optional[Path] = None) -> Path: ...
```

## Code Layout
- `engine/host_containment.py`: Production-grade WFP dynamic session and Netlink containment manager
- `engine/defensive_publisher.py`: Arm 106/107 publisher wired to `HostContainmentManager`
- `engine/differential_oracle.py`: 4-parser differential matrix with dead stub removed
- `engine/abnf_engine.py`: Multi-line indented ABNF grammar parser
- `engine/sequence_engine.py`: 3-step pipelined canary sequence evaluator
- `engine/harness2_engine.py`: Module 16 Google Research Harness²
- `engine/safe_network_validator.py`: Mathematical SSRF validator using `ipaddress`
- `database.py`: SQLite connection factory with WAL mode and concurrency locks
- `tests/test_host_containment.py`: Comprehensive containment lifecycle and subprocess silencing test suite
