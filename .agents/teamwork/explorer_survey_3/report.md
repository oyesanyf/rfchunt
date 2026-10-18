# Exhaustive Survey & Security Boundary Report: HTTP Terminator / RFC Hunt Swarm

**Date:** 2026-10-18  
**Investigator:** Explorer 3 (Security Boundaries, Build & Test Suite Survey)  
**Target Repository:** `D:\harfile\rfchunt`  
**Execution Context:** Python 3.12.10 (64-bit) on Windows  

---

## 1. Executive Summary

This report delivers an exhaustive security audit and structural survey across the HTTP Terminator / RFC Hunt Swarm codebase (`D:\harfile\rfchunt`), focusing on:
1. **Target Authorization Mechanisms & Whitelist Validation**
2. **SSRF IP-Range Guards & Mathematical IP Parsing**
3. **Path Traversal & Harness Surface Escapes (`normalize_rel`)**
4. **SQLite Persistence, WAL Journal Mode & Concurrency Locking**
5. **Automated Test Suites (`tests/`, `test_protocol_ruler.py`) & Unified Build Pipeline (`main.py build` / `build_all.py`)**

### Key Findings at a Glance

| Domain | Current Implementation Status | Security / Stability Risk | Severity |
| :--- | :--- | :--- | :--- |
| **Target Authorization** | `TargetAuthorizationGate` in `mcp_server.py`. Decoupled checks for targets, 64KB payload, 60 req/min rate limit, supervisor token. | **CRITICAL BYPASS:** `rfc_hunt_swarm.py` (lines 2268–2270) auto-authorizes any CLI-supplied target by blindly calling `authorize_target(t_host)` before `validate_target(t_host)`, neutralizing the whitelist. Core probing engines (`deterministic_harness.py`, `weaponizer.py`, `active_flaw_prober.py`, `differential_oracle.py`, `delta_debugger.py`, `metamorphic_engine.py`, `sequence_engine.py`) make raw socket connections without invoking the gate. | **HIGH (P0)** |
| **SSRF Guards & IP Parsing** | Naive string matching only (`if cleaned in ("0.0.0.0", "::")`). Zero imports or usage of Python's standard `ipaddress` module across the entire repository. | **CRITICAL SSRF RISK:** Fails to mathematically block RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Cloud metadata / Link-Local (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), IPv6 Unique Local (`fc00::/7`), and IPv4-mapped IPv6 (`::ffff:0:0/96`). Alternative zero-representations (`0`, `0x0`, `::0`, `::ffff:0.0.0.0`) bypass naive string checks. No pre-connect DNS resolution check to guard against rebinding. | **HIGH (P0)** |
| **Path Traversal Guards** | `normalize_rel` in `engine/harness2_engine.py` validates c1..c8 relative paths against `..`, leading `/`, drive colons `:`, and basic percent encodings (`%2e`, `%2f`, `%5c`, `%00`). | **MEDIUM RISK:** Substring checking fails against multi-layer percent-encoding (`%252e%252e%252f`), encoded colons (`%3a` for ADS / drive letters), and does not enforce `Path.resolve().is_relative_to(sandbox)` post-join containment or Windows device names (`CON`, `PRN`, `AUX`, `NUL`). | **MEDIUM (P1)** |
| **SQLite Concurrency & WAL** | `Database` in `database.py` connects with `check_same_thread=False` and a single `threading.Lock()` instance. | **HIGH RISK OF DB LOCKS & RACE CONDITIONS:** Default `DELETE` rollback journal mode is active (`PRAGMA journal_mode = WAL;` is completely absent), causing write operations to lock the entire database file exclusively. Default timeout is 5.0s. Read operations in `database.py` do not hold `_lock`, violating thread safety for concurrent cursors on a shared connection. Other modules (`rfc_hunt_swarm.py`, `caldera_bridge.py`, `dream_world_model.py`) open independent uncoordinated connections to `terminator.db`. | **HIGH (P1)** |
| **Build & Test Suite Health** | 16 test files (15 in `tests/`, 1 in root: `test_protocol_ruler.py`). Total 106 unit and integration tests. | **EXCELLENT CORE HEALTH, 106/106 PASS:** Full test suite passes cleanly in 95s. Build pipeline passes all 8 steps. However, external subprocess calls across `build_all.py`, `ollama_manager.py`, and `engine/raptor_integrator.py` lack `stdin=subprocess.DEVNULL` and `CREATE_NO_WINDOW (0x08000000)`. `test_explain_vulnerability_concept` hangs up to 270s if Ollama is unresponsive on port 11434. | **MEDIUM (P1)** |

---

## 2. Investigation 1: Target Authorization Mechanisms and Validation

### 2.1 Codebase Architecture & Gate Implementation
Target authorization is defined primarily in `mcp_server.py` within `TargetAuthorizationGate` (lines 17–130).

```python
class TargetAuthorizationGate:
    ALLOWED_TARGETS: Set[str] = {"127.0.0.1", "localhost", "::1", "[::1]"}
    MAX_PAYLOAD_BYTES: int = 64 * 1024  # 64 KB strict upper limit
    RATE_LIMIT_PER_MINUTE: int = 60
    _request_history: Dict[str, List[float]] = {}
    _lock = threading.Lock()
```

The gate provides four primary control layers:
1. **Destination Whitelist:** Evaluates `get_allowed_targets()` combining `ALLOWED_TARGETS` with comma-separated entries in `RFCHUNT_AUTHORIZED_TARGETS`. Rejects wildcard tokens `*` and `all`.
2. **Payload Size Boundary:** Rejects raw request buffers larger than 64 KB (`MAX_PAYLOAD_BYTES`).
3. **Sliding-Window Rate Limiter:** Enforces a maximum of 60 requests per minute per `client_id` using a thread-safe timestamp history.
4. **Human Supervisor Token Verification:** High-risk actions (`is_weaponization=True` or `is_heavy_hunt=True`) fail closed unless `RFCHUNT_SUPERVISOR_TOKEN` is set in the host environment and matched by the caller.

### 2.2 Critical Vulnerabilities & Bypass Analysis

#### Defect 1.1: Blind CLI Target Auto-Authorization in Swarm Lifecycle
In `rfc_hunt_swarm.py` (lines 2266–2274), targets specified by the user via `--host` or `--targets` are validated as follows:
```python
    # Authorize and validate each target host specified on the CLI
    from mcp_server import TargetAuthorizationGate
    for t_host, t_port, t_tls in target_list:
        TargetAuthorizationGate.authorize_target(t_host)
        is_valid_target, target_reason = TargetAuthorizationGate.validate_target(t_host)
        if not is_valid_target:
            print(f"[!] Target validation error for {t_host}: {target_reason}")
            sys.exit(1)
```
**Impact:** `authorize_target(t_host)` mutates `ALLOWED_TARGETS` by immediately adding `t_host` before `validate_target(t_host)` is called. Since `validate_target` merely checks `if cleaned not in allowed: raise PermissionError`, the check **always succeeds** for arbitrary destination IPs and hostnames (including internal cloud metadata endpoints, internal corporate subnets, and external servers). The whitelist protection is completely negated.

#### Defect 1.2: Raw Socket Probing Bypasses Gate in Execution Engines
Core probing engines throughout `rfchunt` instantiate raw TCP/TLS connections without invoking `TargetAuthorizationGate`:
- `deterministic_harness.py` line 48: `socket.create_connection((self.host, self.port), timeout=self.timeout)`
- `weaponizer.py` line 38: `socket.create_connection((self.host, self.port), timeout=self.timeout)`
- `engine/active_flaw_prober.py` line 57: `socket.create_connection((self.host, self.port), timeout=self.timeout)`
- `engine/differential_oracle.py` line 55: `socket.create_connection((target.host, target.port), timeout=target.timeout)`
- `engine/delta_debugger.py` line 170: `socket.create_connection((self.host, self.port), timeout=self.timeout)`
- `engine/metamorphic_engine.py` line 165: `socket.create_connection((host, port), timeout=timeout)`
- `engine/sequence_engine.py` line 71 & 286: `socket.create_connection((host, port), timeout=self.default_timeout)`
- `protocol_ruler.py` line 109: `socket.create_connection((self.host, self.port), timeout=self.timeout)`

**Impact:** `TargetAuthorizationGate` is only invoked when commands flow through `mcp_server.py` or `rfc_hunt_swarm.py`'s initial CLI parse. Any programmatic invocation or direct engine test executes raw socket probes against arbitrary addresses without authorization.

---

## 3. Investigation 2: SSRF IP-Range Guards & Mathematical IP Parsing

### 3.1 Absence of Mathematical IP Parsing
Grep analysis across the entire codebase revealed **0 references** to Python's standard `ipaddress` module.
All address validations rely exclusively on naive string checks:
- `mcp_server.py` line 46: `if cleaned in ("0.0.0.0", "::"): raise ValueError(...)`
- `mcp_server.py` line 55: `if cleaned in ("0.0.0.0", "::"): raise ValueError(...)`
- `protocol_ruler.py` line 92: `if host in ("0.0.0.0", "::"): raise ValueError(...)`

### 3.2 Audit Against Mandatory SSRF IP Ranges

| IP Subnet / Range | Standard Definition | Current Codebase State | Vulnerability Analysis |
| :--- | :--- | :--- | :--- |
| **Unspecified** | `0.0.0.0/8`, `::/128` | **PARTIAL NAIVE CHECK** | Matches exact strings `"0.0.0.0"` and `"::"`. Easily bypassed by `"0"`, `"0.0"`, `"0.0.0.00"`, `"0x00.0.0.0"`, `"::0"`, `"::0000"`, `"0:0:0:0:0:0:0:0"`, `"0000::"`. |
| **Loopback** | `127.0.0.0/8`, `::1` | **RESTRICTED LITERALS** | Only `"127.0.0.1"`, `"localhost"`, `"::1"`, `"[::1]"` are in `ALLOWED_TARGETS`. However, valid local test addresses in `127.0.0.0/8` (e.g. `127.0.0.2`..`127.255.255.254`) are not recognized as loopback. |
| **RFC 1918 Private** | `10.0.0.0/8`<br>`172.16.0.0/12`<br>`192.168.0.0/16` | **NO CHECK** | If added to `RFCHUNT_AUTHORIZED_TARGETS` or passed to CLI, private RFC1918 networks are probed without restriction. |
| **Link-Local / Cloud Metadata** | `169.254.0.0/16`<br>`fe80::/10` | **NO CHECK** | Cloud metadata endpoints (e.g., AWS/GCP/Azure IMDS `169.254.169.254`) have zero blocking safeguards. |
| **Carrier-Grade NAT (CGNAT)** | `100.64.0.0/10` | **NO CHECK** | Unchecked. |
| **IPv6 Unique-Local (ULA)** | `fc00::/7` | **NO CHECK** | Unchecked. |
| **IPv4-Mapped IPv6** | `::ffff:0:0/96` | **NO CHECK** | Attackers can supply `::ffff:169.254.169.254` or `::ffff:127.0.0.1` or `::ffff:0.0.0.0` to bypass string checks while Windows/Linux dual-stack sockets route directly to the target. |
| **DNS Resolution / Rebinding** | Dynamic Hostnames | **NO CHECK** | Hostnames are never pre-resolved via `socket.getaddrinfo()` to verify their underlying IP addresses before connecting. |

### 3.3 Remediation Architecture Specification
`TargetAuthorizationGate` must incorporate `ipaddress` parsing with an explicit mathematical rejection gate:
1. Strip bracket enclosures (`[::1]` -> `::1`).
2. Parse via `ipaddress.ip_address(host)`.
3. If IPv6 and `ip.ipv4_mapped` is present, evaluate `ip.ipv4_mapped`.
4. Block:
   - `ip.is_unspecified` (covers all forms of 0.0.0.0 and ::)
   - `ip.is_link_local` (`169.254.0.0/16`, `fe80::/10`)
   - `ip in ipaddress.ip_network("100.64.0.0/10")` (CGNAT)
   - `ip in ipaddress.ip_network("fc00::/7")` (IPv6 ULA)
   - `ip in ipaddress.ip_network("10.0.0.0/8")`, `172.16.0.0/12`, `192.168.0.0/16` (RFC1918) unless explicitly authorized in lab mode
5. For non-IP hostnames: invoke `socket.getaddrinfo(host, None)` and evaluate every returned sockaddr IP address through the same mathematical filter.

---

## 4. Investigation 3: Path Traversal Guards (`normalize_rel` & File Operations)

### 4.1 Assessment of `normalize_rel` in `engine/harness2_engine.py`
In Module 16 (`harness2_engine.py`, lines 159–180), `normalize_rel` sanitizes relative paths on the editable `c1..c8` Google Research Harness² surface:

```python
def normalize_rel(rel: str) -> str:
    """Normalise a relative path, rejecting escapes, drive letters, and percent-encoded traversal."""
    r = str(rel).strip().replace("\\", "/")
    r_lower = r.lower()
    if (
        r.startswith("/")
        or ":" in r
        or ".." in r.split("/")
        or "%2e" in r_lower
        or "%2f" in r_lower
        or "%5c" in r_lower
        or "%00" in r_lower
        or "\x00" in r
    ):
        raise ValueError(f"path escapes the harness: {rel!r}")
    while r.startswith("./"):
        r = r[2:]
    cleaned = r.strip("/")
    if not cleaned:
        raise ValueError(f"empty relative path on harness surface: {rel!r}")
    return cleaned
```

### 4.2 Strengths & Tested Invariants
- `test_c1_c8_surface_and_path_escape_guard` in `tests/test_harness2_integration.py` verifies rejection of:
  - `../secret.txt`
  - `/etc/passwd`
  - `C:\Windows\System32\cmd.exe`
  - `skills/%2e%2e/SKILL.md`
  - `scripts/foo%2fbar.py`
  - `scripts/bad\x00.py`
- Normalization replaces `\` with `/`, transforming Windows UNC prefixes `\\` into `//`, which are caught by `r.startswith("/")`.
- Alternate Data Streams (ADS) containing `:` (e.g., `file.txt:stream` or `file.txt::$DATA`) are caught by `":" in r`.

### 4.3 Residual Path Escapes & Boundary Gaps
1. **Multi-Layer Percent-Encoding:** `normalize_rel` checks substring presence of `%2e`, `%2f`, `%5c`, `%00` on the raw string without running `urllib.parse.unquote()`. A doubly encoded sequence `%252e%252e%252f` slips past the substring check.
2. **Encoded Colon Bypass (`%3a`):** `%3a` is not checked. If a downstream filesystem or HTTP parser decodes URL encoding, `%3a` produces `:` (accessing ADS streams or drive roots).
3. **Missing Canonical Resolution Boundary Assertion:** After normalizing, `harness2_engine.py` writes files via `p = dest / normalize_rel(a)`. The destination path `p.resolve()` is never asserted with `p.resolve().is_relative_to(dest.resolve())`, leaving symlink traversal unverified.
4. **Windows Reserved Device Names:** Components matching `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9` are not blocked before filesystem access.
5. **Dot Retention in `forensics.py`:** Line 40 uses `re.sub(r"[^a-zA-Z0-9_.-]", "_", f"{target_host}_{target_port}")`. Because `.` is allowed, supplying a target of `..` produces `safe_target = ".._443"`. Although prefixed by `run_`, sanitization should strictly strip consecutive dots.

---

## 5. Investigation 4: SQLite Concurrency Locks & Storage Health

### 5.1 Architecture of `database.py`
Persistence is managed by `Database` in `database.py` (lines 14–20):
```python
class Database:
    def __init__(self, db_path: str = "terminator.db"):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
```

### 5.2 Identified Concurrency & Locking Defects

#### Defect 4.1: Missing Write-Ahead Logging (WAL Mode)
SQLite defaults to `DELETE` rollback journal mode. In rollback mode, write transactions acquire an exclusive file lock, completely blocking all concurrent readers.
- `PRAGMA journal_mode = WAL;` is **nowhere in the codebase**.
- Under multi-threaded swarm execution (`rfc_hunt_swarm.py` with `--concurrency 8` or 16), readers and writers collide, causing `sqlite3.OperationalError: database is locked`.

#### Defect 4.2: Lack of Explicit Connection Busy Timeout
In `database.py`, `sqlite3.connect` is invoked without specifying `timeout`. The default timeout is 5.0 seconds. Under heavy disk I/O, VACUUM, or multiple concurrent probe insertions, transactions exceeding 5 seconds fail catastrophically.
- `PRAGMA busy_timeout = 60000;` and `sqlite3.connect(..., timeout=60.0)` must be established.

#### Defect 4.3: Unsynchronized Read Operations Violate Cursor Thread-Safety
While write methods in `database.py` wrap queries in `with self._lock: with self.conn:`, almost all read methods omit the lock:
- `get_ingested_rfc_ids()` (line 231)
- `get_scanned_rfc_nums()` (line 236)
- `get_unprocessed_fragments()` (line 249)
- `get_pending_probes()` (line 289)
- `get_confirmed_findings()` (line 360)
- `get_tier_taxonomy_counts()` (line 535)
- `get_anomaly_fingerprints()` (line 569)
- `get_dynamic_permutations()` (line 595)
- `get_probe_evaluation_count()` (line 602)
- `get_storage_stats()` (line 697)
- `get_harness2_runs()` (line 758)

Because `self.conn` is shared across threads (`check_same_thread=False`), concurrent execution of `cursor = self.conn.cursor()` during an active write transaction can cause internal SQLite memory corruption or `sqlite3.ProgrammingError: Recursive use of cursors not allowed`.

#### Defect 4.4: Uncoordinated Direct SQLite Connections Across Modules
Multiple external modules bypass `Database` and open independent raw connections directly to `terminator.db`:
- `rfc_hunt_swarm.py` line 1314: `con = sqlite3.connect(db_path)`
- `engine/caldera_bridge.py` line 202: `conn = sqlite3.connect(str(self.db_path))`
- `engine/dream_world_model.py` line 134: `conn = sqlite3.connect(str(p))`
Without WAL mode or explicit busy timeouts, these external connections conflict with `database.py`, precipitating database locking errors.

---

## 6. Investigation 5: Build & Test Suite Survey

### 6.1 Test Suite Inventory (16 Test Files, 106 Tests)
Every test file across `tests/` and root was cataloged and executed:

| Test File | Total Tests | Focus Area | Status |
| :--- | :---: | :--- | :---: |
| `tests/test_aggressive_improvements.py` | 9 | 4-parser differential matrix, binary H2 framing, Merkle audit, exploit exporters, delta debugger downgrade | **PASS** |
| `tests/test_authorization_and_safety.py` | 8 | Target authorization whitelist, INADDR_ANY rejection, payload size, sliding rate limit, supervisor token, error sanitization, DB seeding | **PASS** |
| `tests/test_caldera_bridge.py` | 5 | Caldera abilities/adversaries export, wire execution against real socket server, world model ingestion | **PASS** |
| `tests/test_crlf_desync.py` | 5 | CRLF permutator mutators, anomaly detection, RFC keywords, connection-locked desync, head range gadget | **PASS** |
| `tests/test_dream_rsi.py` | 7 | ProtocolWorldModel ingestion, simulation fidelity, DreamRSIOptimizer evolution, policy store, bandit hot reload, swarm graph integration | **PASS** |
| `tests/test_engine_12_modules.py` | 14 | Modules 1–12 end-to-end (ABNF, Bandit, Compiler, Oracle, Sequence Engine, Errata, Metamorphic, Delta Debugger, Classifier, Cross-Protocol Boundary, Knowledge Graph, Defensive Publisher), Orchestrator cycle | **PASS** |
| `tests/test_harness.py` | 7 | Anomaly detector blends, HTML duplication, inline headers, permutator, deterministic harness contamination, dangling byte, newline normalization | **PASS** |
| `tests/test_harness2_integration.py` | 5 | Module 16 (Google Research Harness²): c1..c8 surface validation, path traversal guard, frontmatter/syntax validation, R=4k/P=3k ledger budget identity, parallel/sequential recursion, Library | **PASS** |
| `tests/test_http_framing_and_pipeline.py` | 10 | Content-Length multi-chunk framing, unconsumed pipeline bytes, chunked extensions/trailers, 1xx interim status, 204/304 no-body status, pipelined canary isolation, causal classifier, validity gate | **PASS** |
| `tests/test_ollama_lifecycle.py` | 3 | Ollama binary detection, zero-API-key local execution, deterministic RFC grammar fallback | **PASS** |
| `tests/test_raptor_integration.py` | 6 | RAPTOR attribution, status checks, SARIF report ingestion to SQLite, MCP security tool exposure, CLI modes, help manual | **PASS** |
| `tests/test_rfcs.py` | 8 | Chunker micro-fragmentation, anti-anchoring, RFC caching, MCP spec ingestion, Kettle corpus, vulnerability concept explanation | **PASS** |
| `tests/test_swarm_agent.py` | 4 | Swarm graph build, conditional routing logic, telemetry pass/fail summary, wired CLI commands | **PASS** |
| `tests/test_target_auth.py` | 2 | Target authorization check, baseline response subtraction | **PASS** |
| `tests/test_terminator_rfc_selector.py` | 5 | Core RFC priority scoring, corpus retrieval, chunker ranking, 3-tuple DB saving, build pipeline syntax & DB step | **PASS** |
| `test_protocol_ruler.py` (root) | 6 | Live socket testing against `TestLabServer`: binary search baseline calibration to 64,040 bytes, Kettle `\xc0\x8a` 10-byte expansion detection, verbatim sequences, full audit, INADDR_ANY rejection, connection drop handling | **PASS** |
| **TOTAL** | **106** | **All 16 Research Modules, Swarm Agents, MCP Server, and Protocol Ruler** | **100% PASS** |

### 6.2 Test Runtime & Diagnostic Findings
- **Execution Performance:** `python.cmd -m pytest tests/ test_protocol_ruler.py -q` completed in **95.08 seconds** with 106 passed tests.
- **Test Lab Live Sockets:** Zero mocks are used in `test_protocol_ruler.py` and `test_caldera_bridge.py`. They successfully spin up background server threads (`TestLabServer` on port 8092), exchange raw HTTP bytes, and tear down gracefully.
- **Fragility Discovery in `tests/test_rfcs.py`:** `test_explain_vulnerability_concept` queries `FusionArbiter.explain_vulnerability_concept`. If the local Ollama daemon hangs or is unresponsive, `FusionArbiter._query_model` blocks for `self.timeout = 120s`, then executes 5 fallback attempts at 30s each (totaling up to 270 seconds). This nears the 300-second timeout of `build_all.py`.

### 6.3 Build Pipeline Verification (`build_all.py` / `main.py build`)
`build_all.py` coordinates 8 sequential steps:
1. `build_step_syntax_check`: Compiles all 67 Python source files across root, `engine/`, `payloads/`, `tests/` using `py_compile.compile(doraise=True)`.
2. `build_step_dependencies`: Audits `httpx`, `requests`, `urllib3`, `typing_extensions`.
3. `build_step_database`: Verifies 16 SQLite tables and defensive intelligence seeding.
4. `build_step_precache_rfcs`: Pre-caches 25 canonical RFC specifications for 100% offline execution.
5. `build_step_caldera_export`: Exports 5 adversary emulation abilities and 1 adversary profile.
6. `build_step_dream_rsi`: Verifies Dream-RSI policy store (Generation 1, Fitness 437.0).
7. `build_step_harness2`: Verifies Module 16 Harness² engine ($R=4, P=3$ ledger identity).
8. `build_step_run_tests`: Executes full automated pytest verification.

**Verification Result:** Running `build_all.py --skip-tests` succeeds cleanly in **2.65 seconds**. Running `build_all.py` end-to-end with tests completes with exit code `0`.

### 6.4 Subprocess Noise & Window Creation Audit (`CREATE_NO_WINDOW` & `DEVNULL`)
The user requirements specify zero console noise across all subprocess invocations:
- `build_all.py` line 179: Invokes `subprocess.run(cmd, ...)` without `stdin=subprocess.DEVNULL` or `creationflags=subprocess.CREATE_NO_WINDOW (0x08000000)`.
- `ollama_manager.py` lines 119 & 152: Invokes `winget` and `OllamaSetup.exe` without `CREATE_NO_WINDOW` or stream suppression.
- `engine/raptor_integrator.py` lines 108, 166, 235, 323: Invokes `docker` and `powershell` scripts via `subprocess.run` without `stdin=subprocess.DEVNULL` or `creationflags=subprocess.CREATE_NO_WINDOW`.

**Remediation:** Every `subprocess.run` and `subprocess.Popen` on Windows must pass:
```python
creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
stdin = subprocess.DEVNULL
```

---

## 7. Actionable Implementation Recommendations for Implementers

1. **Remediate Target Authorization in `mcp_server.py`:**
   - Integrate `import ipaddress`.
   - Update `TargetAuthorizationGate.check_target(host)` to parse `ipaddress.ip_address(host)` and reject all unspecified, loopback (unless whitelisted), private RFC1918, link-local, CGNAT, IPv6 ULA, and IPv4-mapped IPv6 ranges.
   - For hostnames, resolve addresses via `socket.getaddrinfo(host, None)` and validate every resulting IP.
   - Remove the auto-authorization flaw in `rfc_hunt_swarm.py` (line 2269) so CLI targets are strictly checked against `ALLOWED_TARGETS` and `RFCHUNT_AUTHORIZED_TARGETS`.
2. **Harden `normalize_rel` in `engine/harness2_engine.py`:**
   - Recursively unquote paths using `urllib.parse.unquote` before evaluating character blacklists to prevent double-encoding escapes (`%252e%252e`).
   - Explicitly reject `%3a` (encoded colon) and Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
   - Enforce `(dest / cleaned).resolve().is_relative_to(dest.resolve())` before file creation.
3. **Fortify SQLite Persistence in `database.py`:**
   - Execute `PRAGMA journal_mode = WAL;`, `PRAGMA busy_timeout = 60000;`, and `PRAGMA synchronous = NORMAL;` during `_init_schema()`.
   - Set `sqlite3.connect(..., timeout=60.0)`.
   - Wrap ALL read methods in `database.py` with `with self._lock:` to protect concurrent cursor access on shared connections.
4. **Subprocess Windows Silencing:**
   - Standardize external process calls across `build_all.py`, `ollama_manager.py`, and `engine/raptor_integrator.py` with `stdin=subprocess.DEVNULL` and `creationflags=subprocess.CREATE_NO_WINDOW`.
5. **Host Network Containment Module:**
   - Implement `engine/host_containment.py` providing `HostContainmentManager` utilizing Windows WFP (`fwpuclnt.dll` with `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001` and `FwpmEngineClose0` on stop/crash) and Linux `AF_NETLINK` sockets.
   - Add comprehensive tests in `tests/test_host_containment.py`.
