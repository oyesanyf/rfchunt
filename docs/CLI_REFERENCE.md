# HTTP Terminator: Complete CLI Reference & Flag Manual

> **Research Attribution & Academic Citation**
>
> 1. **HTTP Terminator & Protocol Desynchronization Research**:
>    - Conceived & Designed by **James Kettle** (Director of Research, PortSwigger)
>    - Reference: *"Can AI Do Novel Security Research? Meet the HTTP Terminator"* (DEF CON 34 / Black Hat USA 2026)
>    - URL: <https://portswigger.net/research/can-ai-do-novel-security-research>
>
> 2. **RAPTOR Autonomous Offensive/Defensive Framework**:
>    - Authored by **Gadi Evron**, **Daniel Cuthbert** ([ORCID: 0009-0000-6443-0251](https://orcid.org/0009-0000-6443-0251)), and **Thomas Dullien ("Halvar Flake")**
>    - Docker Engine: `danielcuthbert/raptor:latest` | Repo: <https://github.com/gadievron/raptor>

---

## Complete Table of CLI Flags

| Flag | Type | Default | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `command` | positional | `None` | Primary execution subcommand / mode | `python rfc_hunt_swarm.py terminator` |
| `--mode` | string | `single` | Execution mode across 16 pipeline capabilities | `--mode terminator` |
| `--host`, `--target` | string | `127.0.0.1` | Target IP address or domain name | `--host dlptest.com` |
| `--port` | int | `5006` | Target TCP port | `--port 3030` |
| `--tls` | flag | `False` | Enable TLS/HTTPS encryption (auto if port 443) | `--tls` |
| `--rfc` | string | `9112` | Specific RFC specification identifier | `--rfc 9112` |
| `--targets` | string | `None` | Comma-separated multi-target terminators | `--targets "127.0.0.1:8080,target.local:8443"` |
| `--terminators` | string | `all` | Filter terminator categories | `--terminators chunk,h2_gateway,crlf_rhi` |
| `--list-terminators` | flag | `False` | Print catalog of 25 RFCs and 36 mutators | `--list-terminators` |
| `--clean-db` | flag | `False` | Wipe transient exploration tables and run SQLite VACUUM | `--clean-db` |
| `--keep-rfcs-on-clean`, `--keep-rfcs` | flag | `False` | Retain cached RFC specifications during database clean | `--clean-db --keep-rfcs` |
| `--keep-findings-on-clean`, `--keep-findings` | flag | `False` | Retain confirmed vulnerabilities during database clean | `--clean-db --keep-findings` |
| `--db` | string | `terminator.db` | SQLite database path | `--db custom_terminator.db` |
| `--cache-dir` | string | `rfcs` | Directory to cache downloaded RFC texts | `--cache-dir my_rfcs` |
| `--ui` | flag | `False` | Launch interactive research dashboard web UI | `--ui` |
| `--ui-port` | int | `0` (auto) | Explicit local port for the UI dashboard server | `--ui-port 8088` |
| `--serve` | flag | `False` | Keep UI dashboard server active after scan completes | `--serve` |
| `--random-port`, `--high-port` | flag | `False` | Force servers to use high random unprivileged ports | `--random-port` |
| `--dashboard-out` | string | `terminator_dashboard.html` | HTML research dashboard output path | `--dashboard-out reports/scan.html` |
| `--export-rules-dir` | string | `defense_rules` | Directory to save exported Nuclei/WAF/IDS rules | `--export-rules-dir ./waf_rules` |
| `--probe` | string | `None` | Custom raw wire probe (ASCII or hex) | `--probe "GET / HTTP/1.1\r\n\r\n"` |
| `--kettle` | flag | `False` | Shortcut to scan James Kettle's 138-RFC corpus | `--kettle` |
| `--all-active` | flag | `False` | Shortcut to cycle through ALL active IETF RFCs | `--all-active` |
| `--max-rfcs`, `--count` | int | `None` | Maximum number of RFCs to evaluate in run | `--max-rfcs 5` |
| `--keywords` | string | `None` | Filter active RFCs by comma-separated keywords | `--keywords "chunked,trailer,websocket"` |
| `--comb-only`, `--offline` | flag | `False` | Offline RFC parsing & probe synthesis without packets | `--comb-only` |
| `--no-lab` | flag | `False` | Do not auto-spawn local mock server on localhost | `--no-lab` |
| `--cycles` | int | `3` | Maximum mutation cycles per RFC | `--cycles 4` |
| `--timeout` | float | `900.0` | Ollama LLM inference timeout (0 for unlimited) | `--timeout 300.0` |
| `--model` | string | `gemma2:2b` | Primary protocol specialist model | `--model qwen2.5:7b` |
| `--sec-model` | string | `None` | Secondary security model for ModelFusion | `--sec-model fenkohq/foundation-sec-8b:latest` |
| `--no-fusion` | flag | `False` | Disable multi-model panel fusion | `--no-fusion` |
| `--concurrency`, `--threads` | int | `8` | Maximum concurrent probe execution threads | `--concurrency 16` |
| `--sentences` | int | `2` | Sentences per chunk during text fragmentation | `--sentences 3` |
| `--limit`, `--fragments` | int | `5` | Maximum fragments/probes to process per RFC | `--limit 10` |
| `--variants` | int | `3` | Permutation variants generated per probe | `--variants 4` |
| `--discover-recent` | int | `0` | Discover newly published RFCs from index | `--discover-recent 5` |
| `--keep-going` | flag | `False` | Continue hunting after discovering the first flaw | `--keep-going` |
| `--debug` | flag | `False` | Enable deep socket telemetry & step tracing | `--debug` |
| `--show-response` | flag | `False` | Print raw responses received from target host | `--show-response` |
| `-v`, `--verbose` | flag | `False` | Enable verbose execution telemetry | `-v` |
| `--authorized`, `--allow-all` | flag | `False` | Explicitly authorize testing against remote host | `--authorized` |
| `--sequence` | string | `None` | Custom byte sequence for Protocol Ruler | `--sequence "\xc0\x8a"` |
| `--name` | string | `Custom Probe`| Sequence label for Protocol Ruler | `--name "Overlong-LF"` |
| `--max-size` | int | `131072` | Maximum header buffer size for Protocol Ruler | `--max-size 65536` |
| `--dream-rsi` | flag | `True` | Enable Open Dream-RSI policy self-improvement | `--dream-rsi` |
| `--no-dream-rsi` | flag | `False` | Disable Open Dream-RSI evolution cycle | `--no-dream-rsi` |
| `--dream-rollouts`, `--rollouts` | int | `300` | Simulated rollouts per dream policy candidate | `--dream-rollouts 500` |
| `--generations` | int | `3` | Evolutionary dream generations per cycle | `--generations 5` |
| `--dream-export`, `--export` | string | `data/dream_policies.json` | Path to export evolved Dream-RSI policies | `--dream-export data/policies.json` |
| `--export-caldera` | string | `caldera_export`| Output directory for Caldera adversary plugin | `--export-caldera ./my_caldera` |
| `--no-caldera` | flag | `False` | Disable default Caldera plugin auto-sync | `--no-caldera` |
| `--caldera-url`, `--push` | string | `None` | Live Caldera server URL to push abilities | `--caldera-url http://127.0.0.1:8888` |
| `--caldera-key` | string | `ADMIN123` | API key for Caldera REST authentication | `--caldera-key SECRET123` |
| `--build` | flag | `False` | Shortcut to run unified Build All pipeline | `--build` |
| `--skip-tests` | flag | `False` | Skip pytest execution during Build All | `--build --skip-tests` |
| `--mcp` | flag | `False` | Shortcut to run Model Context Protocol stdio server | `--mcp` |
| `--raptor`, `--enable-raptor` | flag | `False` | Enable RAPTOR Autonomous Framework execution | `--raptor` |
| `--raptor-mode` | string | `web` / `scan` | RAPTOR mode (`web`, `scan`, `agentic`, `crypto`, `sca`, `describe`) | `--raptor-mode agentic` |
| `--raptor-target`, `--repo` | string | `None` | Path to repository/codebase for RAPTOR audit | `--repo D:\harfile\my_project` |
| `--raptor-model` | string | `fenkohq/foundation-sec-8b:latest` | Ollama model for RAPTOR agentic triage | `--raptor-model fenkohq/foundation-sec-8b:latest` |
| `--raptor-status`, `--status` | flag | `False` | Check RAPTOR Docker container and Ollama status | `--raptor-status` |
| `--raptor-findings`, `--findings`| flag | `False` | List recent SARIF vulnerability findings from RAPTOR | `--raptor-findings` |
| `--policy-groups` | string | `""` | Filter Semgrep policy groups (e.g. `secrets,owasp`) | `--policy-groups "secrets,crypto"` |
| `--include-codeql` | flag | `False` | Enable CodeQL compilation in RAPTOR agentic mode | `--include-codeql` |
| `--harness2` | flag | `True` | Enable Google Research Harness² recursive agent harnessing | `--harness2` |
| `--no-harness2` | flag | `False` | Disable Google Research Harness² recursive agent harnessing | `--no-harness2` |
| `--harness2-k`, `--k` | int | `1` | Task-level recursion budget $k$ ($R=4k$ rollouts, $P=3k$ stages) | `--harness2-k 2` |
| `--harness2-mode` | string | `parallel` | Recursion topology: `parallel` (`agg` width) or `sequential` (`seq` depth) | `--harness2-mode sequential` |
| `--harness2-domain` | string | `auto` | Protocol domain for Harness² experience library (`http11_framing`, `h2_translation`, etc.) | `--harness2-domain h2_translation` |
| `--harness2-runs-dir` | string | `runs/harness2` | Directory for persisted Harness² `c1..c8` trees, `INDEX.md`, and `EXPERIENCE.md` | `--harness2-runs-dir runs/h2` |
| `--harness2-report` | flag | `False` | Display historical Harness² runs, $R=4k/P=3k$ ledger proofs, and learned lessons | `--harness2-report` |

---

## Detailed Examples for Every Flag

### 1. Primary Execution & Scope Modes
```powershell
# --mode terminator (25 core HTTP/1.1, H2, H3, and Gateway framing specs)
py -3.12 -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030

# --mode corpus (James Kettle's curated 138-RFC HTTP/SMTP research corpus)
py -3.12 -u rfc_hunt_swarm.py --mode corpus --host 127.0.0.1 --port 3030

# --mode all (Cycle through ALL active IETF protocol standards)
py -3.12 -u rfc_hunt_swarm.py --mode all --host 127.0.0.1 --port 3030

# --mode single with --rfc (Target specific RFC)
py -3.12 -u rfc_hunt_swarm.py --mode single --rfc 9112 --host 127.0.0.1 --port 3030

# --kettle (Shortcut flag for 138-RFC corpus)
py -3.12 -u rfc_hunt_swarm.py --kettle --host 127.0.0.1 --port 3030

# --all-active (Shortcut flag for all active RFCs)
py -3.12 -u rfc_hunt_swarm.py --all-active --host 127.0.0.1 --port 3030

# --max-rfcs / --count (Cap number of RFCs evaluated)
py -3.12 -u rfc_hunt_swarm.py --mode terminator --max-rfcs 5

# --keywords (Filter active RFC specifications)
py -3.12 -u rfc_hunt_swarm.py --mode all --keywords "chunked,trailer,websocket,boundary"
```

### 2. Remote Host Targeting & Multiplexing
```powershell
# --host / --target and --port
py -3.12 -u rfc_hunt_swarm.py --host dlptest.com --port 443

# --tls (Enable HTTPS encryption)
py -3.12 -u rfc_hunt_swarm.py --host dlptest.com --port 443 --tls

# --authorized (Explicit permission gate for public/remote targets)
py -3.12 -u rfc_hunt_swarm.py --host dlptest.com --port 443 --tls --authorized

# --targets (Multiplex across multiple intermediate proxies / terminators)
py -3.12 -u rfc_hunt_swarm.py --targets "127.0.0.1:8080,https://target.local:8443,10.0.0.5:8000"

# --terminators (Filter mutator categories)
py -3.12 -u rfc_hunt_swarm.py --terminators line,chunk,framing,cross_protocol,crlf_rhi,h2_gateway

# --list-terminators (Print catalog of all 25 RFCs and 36 mutators and exit)
py -3.12 -u rfc_hunt_swarm.py --list-terminators

# --no-lab (Do not auto-spawn local mock lab when targeting localhost)
py -3.12 -u rfc_hunt_swarm.py --host 127.0.0.1 --port 3030 --no-lab
```

### 3. Database Maintenance & Storage Reclaim
```powershell
# --clean-db (Full clean: truncate transient tables and execute VACUUM)
py -3.12 -u rfc_hunt_swarm.py --clean-db

# Positional command equivalent
py -3.12 -u rfc_hunt_swarm.py clean-db

# Clean database before running an active scan
py -3.12 -u rfc_hunt_swarm.py --clean-db --mode terminator --host 127.0.0.1 --port 3030 --ui --raptor

# --keep-rfcs-on-clean / --keep-rfcs (Wipe probes/evaluations but keep downloaded RFC texts)
py -3.12 -u rfc_hunt_swarm.py --clean-db --keep-rfcs

# --keep-findings-on-clean / --keep-findings (Wipe probes/evaluations but preserve confirmed vulnerabilities)
py -3.12 -u rfc_hunt_swarm.py --clean-db --keep-findings

# --db (Specify custom database file)
py -3.12 -u rfc_hunt_swarm.py --db /data/research_run_2026.db

# --cache-dir (Specify custom directory for downloaded RFC specifications)
py -3.12 -u rfc_hunt_swarm.py --cache-dir /cache/ietf_rfcs
```

### 4. Interactive Dashboard, UI & Rule Export
```powershell
# --ui (Launch live interactive research dashboard on high random available port)
py -3.12 -u rfc_hunt_swarm.py ui

# --ui-port (Bind dashboard server to an explicit port)
py -3.12 -u rfc_hunt_swarm.py ui --ui-port 8088

# Background daemon dashboard running alongside active scan
py -3.12 -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --ui

# --serve (Serve dashboard after generating report)
py -3.12 -u rfc_hunt_swarm.py dashboard --serve

# --random-port / --high-port (Force servers to use random unprivileged port)
py -3.12 -u rfc_hunt_swarm.py ui --random-port

# --dashboard-out (Custom output path for generated HTML report)
py -3.12 -u rfc_hunt_swarm.py dashboard --dashboard-out reports/production_audit.html

# --export-rules-dir (Export Nuclei templates, ModSecurity SecRules, and Suricata IDS signatures)
py -3.12 -u rfc_hunt_swarm.py export --export-rules-dir ./waf_rules
```

### 5. RAPTOR Autonomous Offensive/Defensive Engine
```powershell
# --raptor / --enable-raptor (Enable RAPTOR during active scan)
py -3.12 -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --debug --ui --raptor

# --raptor-status / --status (Verify Docker container and Ollama model readiness)
py -3.12 -u rfc_hunt_swarm.py raptor --status

# Live Remote Host Web Application Pentest (Phase 0-6 DAST)
py -3.12 -u rfc_hunt_swarm.py raptor --host dlptest.com --port 443 --tls

# Autonomous Agentic Source Code Pentest with Foundation-Sec-8B
py -3.12 -u rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode agentic

# --raptor-model (Specify Ollama model for LLM triage)
py -3.12 -u rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode agentic --raptor-model fenkohq/foundation-sec-8b:latest

# --raptor-mode crypto (Post-Quantum Cryptography & algorithm audit)
py -3.12 -u rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode crypto

# --raptor-mode sca (Software Composition Analysis for dependencies & advisories)
py -3.12 -u rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode sca

# --raptor-mode describe (Attack surface and language mix profiling)
py -3.12 -u rfc_hunt_swarm.py raptor --describe D:\harfile\my_project

# --policy-groups (Filter Semgrep rule categories)
py -3.12 -u rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --policy-groups secrets,owasp,crypto

# --include-codeql (Enable CodeQL database compilation in agentic mode)
py -3.12 -u rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode agentic --include-codeql

# --raptor-findings / --findings (List and summarize historical SARIF findings)
py -3.12 -u rfc_hunt_swarm.py raptor --findings
```

### 6. Protocol Ruler & Differential Testing
```powershell
# Protocol Ruler custom byte sequence measurement
py -3.12 -u rfc_hunt_swarm.py ruler --host 127.0.0.1 --port 3030 --sequence "\xc0\x8a" --name "Overlong-LF"

# --max-size (Set custom max header buffer limit)
py -3.12 -u rfc_hunt_swarm.py ruler --host 127.0.0.1 --port 3030 --sequence "\xc0\x8a" --max-size 65536

# 4-Parser Differential Matrix (RFC 7230, Permissive, CDN Proxy, Async Microservice)
py -3.12 -u rfc_hunt_swarm.py oracle

# --probe (Evaluate custom raw wire probe against differential matrix)
py -3.12 -u rfc_hunt_swarm.py oracle --probe "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n"

# HTTP/2 Gateway Binary Desync Synthesizer
py -3.12 -u rfc_hunt_swarm.py h2 --host 127.0.0.1 --port 8080

# Cryptographic Merkle Audit Trail Verification (RFC 6962 SHA-256 tree root)
py -3.12 -u rfc_hunt_swarm.py audit

# Query confirmed vulnerabilities by host
py -3.12 -u rfc_hunt_swarm.py vulns --host dlptest.com
```

### 7. AI ModelFusion & Genetic Evolutionary Tuning
```powershell
# --model (Select primary protocol specialist model)
py -3.12 -u rfc_hunt_swarm.py --model gemma2:2b

# --sec-model (Select secondary security specialist model)
py -3.12 -u rfc_hunt_swarm.py --sec-model fenkohq/foundation-sec-8b:latest

# --no-fusion (Disable multi-model panel fusion; query primary model only)
py -3.12 -u rfc_hunt_swarm.py --no-fusion

# --timeout (Adjust inference timeout; 0 for unlimited)
py -3.12 -u rfc_hunt_swarm.py --timeout 600.0

# --cycles (Mutation iterations per RFC)
py -3.12 -u rfc_hunt_swarm.py --cycles 5

# --limit / --fragments (Fragments processed per RFC)
py -3.12 -u rfc_hunt_swarm.py --limit 8

# --variants (Candidate probes per fragment)
py -3.12 -u rfc_hunt_swarm.py --variants 4

# --sentences (Granularity of RFC micro-inspiration chunks)
py -3.12 -u rfc_hunt_swarm.py --mode chunk --sentences 3

# --concurrency / --threads (Parallel execution workers)
py -3.12 -u rfc_hunt_swarm.py --concurrency 16

# --comb-only / --offline (Offline probe synthesis into database)
py -3.12 -u rfc_hunt_swarm.py --comb-only --max-rfcs 10
```

### 8. Open Dream-RSI, Google Research Harness² & Caldera Adversary Integration
```powershell
# Google Research Harness²: Parallel (Width) Propose-Probe-Compose recursion (k=2 -> R=8 rollouts, P=6 stages)
py -3.12 -u rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-k 2 --harness2-mode parallel

# Google Research Harness²: Sequential (Depth) Propose-Probe-Compose recursion (k=2 iterative rounds)
py -3.12 -u rfc_hunt_swarm.py harness2 --rfc 9113 --harness2-k 2 --harness2-mode sequential --harness2-domain h2_translation

# Google Research Harness²: View historical recursion runs, R=4k/P=3k ledger verification, and domain lessons
py -3.12 -u rfc_hunt_swarm.py harness2 --harness2-report

# --harness2 / --no-harness2 (Enable or disable Harness² during active Swarm scans)
py -3.12 -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --harness2 --harness2-k 1
py -3.12 -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --no-harness2

# --harness2-runs-dir (Custom output directory for persisted c1..c8 trees, INDEX.md & EXPERIENCE.md)
py -3.12 -u rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-runs-dir ./runs/custom_harness2

# --dream-rsi / --no-dream-rsi (Control recursive self-improvement)
py -3.12 -u rfc_hunt_swarm.py --dream-rsi
py -3.12 -u rfc_hunt_swarm.py --no-dream-rsi

# --dream-rollouts / --rollouts (Simulated episodes per candidate policy)
py -3.12 -u rfc_hunt_swarm.py --dream-rollouts 500

# --generations (Evolutionary generations per dream cycle)
py -3.12 -u rfc_hunt_swarm.py --generations 5

# --dream-export / --export (Export evolved policy weights to JSON)
py -3.12 -u rfc_hunt_swarm.py --dream-export data/dream_policies.json

# --export-caldera (Specify custom Caldera plugin export path)
py -3.12 -u rfc_hunt_swarm.py --export-caldera ./my_caldera_plugin

# --no-caldera (Disable default Caldera auto-sync)
py -3.12 -u rfc_hunt_swarm.py --no-caldera

# --caldera-url and --caldera-key (Push abilities live to running Caldera instance)
py -3.12 -u rfc_hunt_swarm.py --caldera-url http://127.0.0.1:8888 --caldera-key ADMIN123
```

### 9. Logging, Telemetry & Diagnostics
```powershell
# --debug (Deep telemetry: raw socket bytes, candidate payloads, host responses)
py -3.12 -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --debug

# --show-response (Print raw HTTP responses received from target host)
py -3.12 -u rfc_hunt_swarm.py --mode single --rfc 9112 --show-response

# -v / --verbose (Verbose pipeline status tracing)
py -3.12 -u rfc_hunt_swarm.py -v

# --keep-going (Continuous flaw hunting; do not stop on first confirmed flaw)
py -3.12 -u rfc_hunt_swarm.py --mode hunt --keep-going

# --build (Execute full Build All verification pipeline)
py -3.12 -u rfc_hunt_swarm.py build

# --skip-tests (Run Build All without executing pytest)
py -3.12 -u rfc_hunt_swarm.py build --skip-tests

# --mcp (Run Model Context Protocol JSON-RPC stdio server)
py -3.12 -u rfc_hunt_swarm.py mcp
```
