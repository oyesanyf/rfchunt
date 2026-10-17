# RAPTOR Security Framework: Comprehensive Operator & Architecture Manual

## Executive Summary & Core Attribution

The **RAPTOR Autonomous Offensive/Defensive Research Framework** is an enterprise-grade autonomous security research platform developed by:

- **Gadi Evron**
- **Daniel Cuthbert** ([ORCID: 0009-0000-6443-0251](https://orcid.org/0009-0000-6443-0251))
- **Thomas Dullien ("Halvar Flake")**

### Project & Distribution
- **Source Repository**: [https://github.com/gadievron/raptor](https://github.com/gadievron/raptor)
- **Official Container Image**: `danielcuthbert/raptor:latest` (Docker Hub)
- **License**: MIT License

### Academic Citation
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

## Technical Architecture & The Dual-Perspective Audit

The integration between **RFC Hunt Swarm** and **RAPTOR** delivers a unified two-tiered audit capability:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   DUAL-TIER SECURITY RESEARCH PIPELINE                    │
├─────────────────────────────────────┬────────────────────────────────────┤
│   TIER 1: WIRE PROTOCOL (OUTSIDE-IN)│  TIER 2: SOURCE CODE (INSIDE-OUT)  │
│   PortSwigger HTTP Terminator       │  RAPTOR Security Framework         │
├─────────────────────────────────────┼────────────────────────────────────┤
│ • RFC Normative Grammar Extractor   │ • Static Analysis (Semgrep/Coccin) │
│ • Stateful Connection A/B Canaries  │ • Deep Taint Tracking (CodeQL)     │
│ • Asymmetric Delay Desynchronization│ • Autonomous Agentic Triage        │
│ • 4-Parser Differential Matrix      │ • Live Dynamic Web Testing (DAST)  │
│ • CRLF Request Header Injection     │ • Quantum-Resistant PQC Auditing   │
│ • Binary HTTP/2 Gateway Framing     │ • Dependency & Supply-Chain (SCA)  │
└──────────────────┬──────────────────┴─────────────────┬──────────────────┘
                   │                                    │
                   └─────────────────┬──────────────────┘
                                     ▼
                   ┌────────────────────────────────────┐
                   │     Unified SQLite Database        │
                   │         (terminator.db)            │
                   ├────────────────────────────────────┤
                   │ • Merkle Audit Trail (RFC 6962)    │
                   │ • Implementation Anomalies         │
                   │ • Confirmed Vulnerabilities        │
                   │ • Host-to-Finding Correlation      │
                   └─────────────────┬──────────────────┘
                                     ▼
                   ┌────────────────────────────────────┐
                   │    Defense Rule & Report Export    │
                   ├────────────────────────────────────┤
                   │ • ModSecurity WAF Rules (SecRule)  │
                   │ • Nuclei Exploit Templates (YAML)  │
                   │ • Suricata IDS Signatures          │
                   │ • Interactive HTML Research Web UI │
                   └────────────────────────────────────┘
```

---

## Detailed Operating Modes

### 1. Dynamic Web Application Testing (`--raptor-mode web` / `--host`)
Runs RAPTOR's autonomous web application scanner (`packages/web/scanner.py`) against live remote hosts.

#### Scanner Phases:
- **Phase 0: Preflight**: Tests network reachability, verifies TLS handshake, and resets telemetry.
- **Phase 1: Authentication**: Optional cookie, bearer token, form, or HTTP basic auth injection.
- **Phase 2: Discovery**: Automatically crawls robots.txt, sitemaps, API specs, and finger-prints edge proxies.
- **Phase 3: BFS Crawl**: High-speed breadth-first traversal of application HTML and JS routes.
- **Phase 4: Passive Checks**: Validates ASVS-mapped security invariants without injecting payloads.
- **Phase 6: Parameter Fuzzing & Injection**: Uses multi-gate oracle verification to test for input validation, header injection, and boundary violations.
- **Phase 7: Reporting**: Emits SARIF reports and evidence ledgers.

#### CLI Execution:
```powershell
# Live remote HTTPS target:
py -3.12 rfc_hunt_swarm.py raptor --host vanguardngr.com --port 443 --tls

# Live target on custom port:
py -3.12 rfc_hunt_swarm.py raptor --host dlptest.com --port 443 --tls

# Local target test server:
py -3.12 rfc_hunt_swarm.py --mode raptor --host 127.0.0.1 --port 3030
```

---

### 2. Autonomous Agentic Code Pentesting (`--raptor-mode agentic`)
Executes static security rules (Semgrep, Coccinelle, optional CodeQL) followed by autonomous LLM exploitability triage.

#### LLM Triage Engine:
- Uses 100% local Ollama inference (`fenkohq/foundation-sec-8b:latest` by default).
- Slices source-code context around flagged lines.
- Evaluates whether an attacker can control inputs to reach sensitive sinks.
- Generates reproduction hypotheses and severity adjustments.

#### CLI Execution:
```powershell
# Full agentic audit on local repository:
py -3.12 rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode agentic

# With specific Ollama model:
py -3.12 rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode agentic --raptor-model fenkohq/foundation-sec-8b:latest

# With deep CodeQL compilation:
py -3.12 rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode agentic --include-codeql
```

---

### 3. Post-Quantum Cryptography & Algorithm Audit (`--raptor-mode crypto`)
Audits repository cryptographic primitives against quantum-resistant standards (NIST ML-KEM, HPKE, hybrid key exchange):

#### CLI Execution:
```powershell
py -3.12 rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode crypto
```

---

### 4. Software Composition Analysis (`--raptor-mode sca`)
Audits repository lockfiles, packages, and dependency graphs against CVE advisory feeds:

#### CLI Execution:
```powershell
py -3.12 rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode sca
```

---

### 5. Repository Surface Profiler (`--describe`)
Analyzes target repository size, language mix, lines of code, build systems, and attack surface before starting an audit:

#### CLI Execution:
```powershell
py -3.12 rfc_hunt_swarm.py raptor --describe D:\harfile\my_project
```

---

## Pre-Flight Status & Diagnostics

To check Docker daemon readiness, verify the container image, and check local Ollama models:

```powershell
py -3.12 rfc_hunt_swarm.py raptor --status
```

**Example Output:**
```text
===========================================================================
[*] RAPTOR Framework Integration Enabled
    Project  : RAPTOR: Autonomous Offensive/Defensive Research Framework
    Authors  : Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake)
    Source   : https://github.com/gadievron/raptor
    Engine   : danielcuthbert/raptor:latest (Docker Container)
===========================================================================

[*] RAPTOR SYSTEM STATUS:
    Docker Image Ready     : YES (sha256:75cb7)
    Framework Installed    : YES (D:\docker\raptor)
    Ollama Daemon Ready    : YES
    Preferred Model Ready  : YES (fenkohq/foundation-sec-8b:latest)
    Installed Models       : mistral:latest, deepseek-r1:1.5b, fenkohq/foundation-sec-8b:latest, qwen2.5:1.5b, strix-qwen:latest
===========================================================================
```

---

## Reviewing Findings & Querying the Database

### List SARIF Reports in Console:
```powershell
py -3.12 rfc_hunt_swarm.py raptor --findings
```

### Query All Findings Mapped by Host Name:
```powershell
py -3.12 rfc_hunt_swarm.py vulns
py -3.12 rfc_hunt_swarm.py vulns --host dlptest.com
```

### Launch Interactive HTML Dashboard:
```powershell
py -3.12 rfc_hunt_swarm.py ui
# Or:
py -3.12 rfc_hunt_swarm.py dashboard --serve
```

---

## Model Context Protocol (MCP) JSON-RPC Interface

`mcp_server.py` allows external AI coding harnesses (Antigravity, Claude, Cursor) to invoke RAPTOR over JSON-RPC 2.0 stdio:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "raptor_scan_project",
    "arguments": {
      "target_path": "https://vanguardngr.com",
      "mode": "web"
    }
  }
}
```

Available Tools:
1. `raptor_status`: Query container and model readiness.
2. `raptor_describe_target`: Map codebase architecture and SLOC.
3. `raptor_scan_project`: Execute static, agentic, crypto, or web audits.
4. `raptor_list_findings`: Retrieve normalized SARIF findings.
