# RAPTOR Framework Integration & Architecture Guide

## Overview

The RFC Hunt Swarm integrates the **RAPTOR Autonomous Offensive/Defensive Research Framework** to provide a unified offensive and defensive protocol and application security testing suite.

By bridging **wire-level protocol desynchronization** (PortSwigger methodology by James Kettle) with **source-code static analysis and dynamic web application testing** (RAPTOR methodology by Gadi Evron, Daniel Cuthbert, and Thomas Dullien), security researchers and engineers can correlate network-layer request smuggling vulnerabilities directly with underlying software defects.

---

## Academic Credit & Attribution

The RAPTOR Framework is an autonomous offensive/defensive research framework created by:

- **Gadi Evron**
- **Daniel Cuthbert** ([ORCID: 0009-0000-6443-0251](https://orcid.org/0009-0000-6443-0251))
- **Thomas Dullien ("Halvar Flake")**

### Project References
- **Official Repository**: [https://github.com/gadievron/raptor](https://github.com/gadievron/raptor)
- **Container Registry**: `danielcuthbert/raptor:latest` (Docker Hub)
- **License**: MIT License

### Citation
```bibtex
@software{Evron_RAPTOR_2026,
  author = {Evron, Gadi and Cuthbert, Daniel and Dullien, Thomas},
  title = {{RAPTOR: Autonomous Offensive/Defensive Research Framework}},
  url = {https://github.com/gadievron/raptor},
  version = {3.1.0},
  year = {2026}
}
```

---

## Architectural Synergy: Wire vs. Code

```
┌────────────────────────────────────────────────────────────────────────┐
│                      DUAL-PERSPECTIVE AUDIT ENGINE                      │
├───────────────────────────────────┬────────────────────────────────────┤
│   Outside-In: Wire Protocol       │      Inside-Out: Implementation    │
│   (RFC Hunt Swarm / Kettle)       │         (RAPTOR Framework)         │
├───────────────────────────────────┼────────────────────────────────────┤
│ • RFC ABNF Normative Grammar      │ • Static Analysis (Semgrep/CodeQL) │
│ • Differential 4-Parser Matrix    │ • Dynamic Web Application Fuzzing  │
│ • Asymmetric Timing & Desync      │ • Local LLM Triage (Foundation-Sec)│
│ • Stateful Canary Sequences       │ • Post-Quantum Cryptography Audits │
│ • HTTP/2 Gateway Framing          │ • Dependency & Supply-Chain (SCA)  │
└─────────────────┬─────────────────┴──────────────────┬─────────────────┘
                  │                                    │
                  └───────────────┬────────────────────┘
                                  ▼
                  ┌───────────────────────────────┐
                  │    Unified SQLite Database    │
                  │        (terminator.db)        │
                  ├───────────────────────────────┤
                  │ • Implementation Anomalies    │
                  │ • Reproducible Vulnerabilities│
                  │ • Host-to-Finding Mappings    │
                  │ • RFC 6962 Merkle Audit Trail │
                  └───────────────┬───────────────┘
                                  ▼
                  ┌───────────────────────────────┐
                  │   Defensive Export & Web UI   │
                  ├───────────────────────────────┤
                  │ • ModSecurity WAF Rules       │
                  │ • Nuclei Exploit Templates    │
                  │ • Suricata IDS Signatures     │
                  │ • Interactive HTML Dashboard  │
                  └───────────────────────────────┘
```

---

## CLI Capabilities & Usage

All RAPTOR capabilities can be executed directly through the unified `rfc_hunt_swarm.py` CLI:

### 1. Pre-Flight Diagnostics & Status Check
Verifies Docker daemon readiness, checks the `danielcuthbert/raptor:latest` container image, and queries local Ollama security models (`fenkohq/foundation-sec-8b:latest`).

```powershell
py -3.12 rfc_hunt_swarm.py raptor --status
```

### 2. Live Remote Host Web Auditing (`raptor.py web`)
Executes phased dynamic application security testing (DAST) against a remote target host (e.g. `vanguardngr.com:443`, `dlptest.com:443`, or staging environments):

```powershell
# Scan HTTPS target on port 443:
py -3.12 rfc_hunt_swarm.py raptor --host vanguardngr.com --port 443 --tls

# Scan using explicit mode:
py -3.12 rfc_hunt_swarm.py --mode raptor --host dlptest.com --port 443 --tls
```

The web scanner performs:
- **Phase 0: Preflight**: Reachability and TLS handshake verification.
- **Phase 2: Discovery**: Robots, sitemap, API specs, and server fingerprinting.
- **Phase 4: Passive Checks**: ASVS-mapped security header checks.
- **Phase 6: Parameter Fuzzing & Injection**: Form and parameter injection probes.

### 3. Autonomous Source Code Pentest (`--raptor-mode agentic`)
Runs static analysis (Semgrep + Coccinelle) combined with autonomous LLM exploitability triage powered by local Ollama models:

```powershell
py -3.12 rfc_hunt_swarm.py raptor --repo D:\path\to\repository --raptor-mode agentic
```

### 4. Post-Quantum Cryptography (PQC) Audit (`--raptor-mode crypto`)
Audits repository cryptography implementations against quantum-resistant standards (ML-KEM, HPKE, hybrid key exchange):

```powershell
py -3.12 rfc_hunt_swarm.py raptor --repo D:\path\to\repository --raptor-mode crypto
```

### 5. Dependency & Supply Chain Scan (`--raptor-mode sca`)
Audits third-party packages, dependencies, and known CVE advisories:

```powershell
py -3.12 rfc_hunt_swarm.py raptor --repo D:\path\to\repository --raptor-mode sca
```

### 6. Review Findings & SARIF Reports
Lists and formats all vulnerability findings stored in `D:\docker\raptor\out` and `terminator.db`:

```powershell
py -3.12 rfc_hunt_swarm.py raptor --findings
```

---

## MCP (Model Context Protocol) Integration

`mcp_server.py` exposes the RAPTOR Framework tools over JSON-RPC 2.0 stdio, allowing AI assistants (Antigravity, Claude, Cursor) to invoke RAPTOR autonomously:

| MCP Tool Name | Description |
|---|---|
| `raptor_status` | Verifies Docker container and local Ollama model readiness. |
| `raptor_describe_target` | Profiles repository language mix, SLOC, and attack surface. |
| `raptor_scan_project` | Executes static, agentic, crypto, or web scans, ingesting SARIF findings into `terminator.db`. |
| `raptor_list_findings` | Reads and summarizes SARIF findings from previous audits. |

---

## Database Ingestion Schema

Findings discovered by RAPTOR are normalized into `terminator.db`:

- **Table**: `implementation_anomalies`
  - `anomaly_id`: `ANOM-RAPTOR-<timestamp>-<index>`
  - `target_engine`: Target host (`vanguardngr.com:443`) or repo (`repo:<name>`)
  - `category`: `RAPTOR_VULNERABILITY`
  - `observed_behavior`: `[<SEVERITY>] <RULE_ID> in <FILE>:<LINE> - <MESSAGE>`
  - `expected_behavior`: Standard security invariant conformant with rule
  - `raw_probe`: File snippet and rule definition
  - `raw_response`: Severity, tool driver, and explanation

This enables cross-querying all confirmed wire desync flaws and source code defects in one query:

```powershell
py -3.12 rfc_hunt_swarm.py vulns
```
