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
>
> 3. **Google Research Harness² Recursive Agent Harnessing Engine**:
>    - Authored by **Ruiyao Xu, Yanfei Chen, Zhongying CuiZhu, Bhavana Dalvi Mishra, Yifei Ming, Han Yu, Rujun Han, Chen-Yu Lee, and Tomas Pfister** (Google Research, 2026)
>    - Paper: *"Harness²: Recursive Agent Harnessing for an Open World"* (`arXiv:2610.14224`) | Repo: <https://github.com/google-research/harness2>

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
| `--model` | string | `hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M` | Primary refusal-free abliterated model (no safety alignment filtering; supports overrides) | `--model hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M` |
| `--abliteration`, `--obliterated` | flag | `True` | Enabled by default: uses refusal-free abliterated models (no safety/refusal guardrails) across ModelFusion panel (`Abliterated Gemma` + `Cisco Foundation-Sec` + `GLM`) | `--abliteration` |
| `--sec-model` | string | `None` (auto `fenkohq/foundation-sec-8b:latest` / abliterated) | Secondary security model for ModelFusion | `--sec-model fenkohq/foundation-sec-8b:latest` |
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
| `--authorized`, `--allow-all` | flag | `False` | Explicitly authorize testing against remote host (with `validate_target_host` SSRF checks enforced) | `--authorized` |
| `--allow-destructive` | flag | `False` | Explicitly allow state-mutating HTTP methods (`PUT`, `DELETE`, `PATCH`, `DROP`, `PURGE`) on authorized targets (`RFCHUNT_ALLOW_DESTRUCTIVE=1`) | `--allow-destructive` |
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
| `--raptor-target` | string | `None` | Path to repository/codebase for RAPTOR audit | `--raptor-target D:\harfile\my_project` |
| `--repo` | string | `None` | Repository directory path for `--all`, `--mantis`, or `--raptor` scans | `--all --repo .` |
| `--path` | string | `None` | Specific file or directory path for `--all`, `--mantis`, or `--raptor` scans | `--all --path engine/mantis_integrator.py` |
| `--all`, `--run-all`, `--all-scans` | flag | `False` | Run ALL integrated scanners (Google Mantis, aiscan, ARTEX Dual-Graph & Attack Chaining, RAPTOR, Prompt Smuggling) with ModelFusion + Abliterated models | `--all --repo .` |
| `--artex`, `--dual-graph` | flag | `False` | Run BaaRai/ARTEX Dual-Graph durable attack chaining engine (Module 17) | `artex --host 127.0.0.1 --port 8080` |
| `--artex-rounds` | int | `1` | Number of multi-round durable planning & verification cycles | `--all --repo . --artex-rounds 2` |
| `--artex-url` | string | `None` | Headless BaaRai/ARTEX REST+SSE backend URL (e.g. `http://127.0.0.1:8787`, or `ARTEX_API_URL`) | `--all --repo . --artex-url http://127.0.0.1:8787` |
| `--artex-token` | string | `None` | Bearer JWT token for headless ARTEX REST API (or `ARTEX_API_TOKEN`) | `--artex-token <jwt>` |
| `--artex-proxy` | string | `None` | ARTEX recording MITM proxy URL (`http://127.0.0.1:8788`, or `ARTEX_PROXY_URL`) | `--all --repo . --artex-proxy http://127.0.0.1:8788` |
| `--artex-ca-cert` | string | `None` | Optional CA certificate path for ARTEX MITM proxy TLS verification | `--artex-ca-cert ./artex-ca.pem` |
| `--artex-noise-profile` | string | `off` | Target traffic noise governor profile (`off`, `quiet`, `balanced`, `aggressive`) | `--artex-noise-profile quiet` |
| `--artex-llm-profiles` | string | `None` | Comma-separated LLM profile IDs for ARTEX worker rotation (`PUT /api/tasks/{id}/llm`) | `--artex-llm-profiles profA,profB` |
| `--artex-llm-rotate` | flag | `False` | Enable round-robin multi-LLM worker rotation (`A, B, A, B`) | `--artex-llm-rotate` |
| `--artex-wait-sse` | flag | `False` | Stream ARTEX SSE activity events on `:8787` until terminal task completion | `--artex-wait-sse` |
| `--artex-budget-turns` | int | `0` | Optional max task turn budget for ARTEX attack chaining (`0` = unlimited) | `--artex-budget-turns 25` |
| `--artex-retest` | flag | `False` | Run ARTEX chain retest loop (`STILL_REPRODUCIBLE` / `FIXED` / `CANNOT_CONFIRM`) | `--artex-retest` |
| `--mcp-transport` | string | `stdio` | Remote MCP server transport: `stdio`, `http` (`/http`), `sse` (`/sse`), or `both` | `mcp --mcp-transport both --mcp-port 8790` |
| `--mcp-host` / `--mcp-port` | str/int | `127.0.0.1:8790` | Bind host and port for remote Streamable HTTP / Legacy SSE MCP server | `--mcp-host 127.0.0.1 --mcp-port 8790` |
| `--mcp-token` | string | `None` | Optional Bearer token for remote HTTP/SSE MCP clients (`RFCHUNT_MCP_TOKEN`) | `--mcp-token <secret>` |
| `--mantis`, `--enable-mantis` | flag | `False` | Enable Google Mantis Security Toolkit (Module 20) with ModelFusion + Abliterated models | `--mantis --repo .` |
| `--mantis-mode` | string | `full` | Google Mantis mode (`full`, `fast`, `threat-model`, `scan`, `reproduce`, `patch`) | `--mantis-mode patch` |
| `--depth`, `--mantis-depth` | int | `30` | Google Mantis audit depth `1..100` (scales coverage, passes, and rule tiers) | `--depth 100` |
| `--mantis-target` | string | `None` | Target path for Google Mantis scan | `--mantis-target .` |
| `--mantis-model` | string | `hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M` | Refusal-free abliterated ModelFusion model for Google Mantis | `--mantis-model hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M` |
| `--mantis-report` | flag | `False` | Display stored Google Mantis findings from `terminator.db` | `--mantis-report` |
| `--output-dir` | string | `reports` | Output directory for SARIF 2.1.0, JSON, and summary reports | `--output-dir reports` |
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
| `--deep-audit` / `deep-audit` | flag / cmd | `False` | Run 3-pillar code-repo audit: live loopback proxy fuzzing, structural trust-boundary review, and root + nested-crate coverage fuzzing | `deep-audit --repo . --proxy --poc` |
| `--proxy` | optional str | `None` (`auto` if bare) | Live loopback-only (`127.0.0.1`/`localhost`/`::1` fail-closed) 3-trial RFC 9112 proxy fuzzer: bare `--proxy` (auto-spawn), `<port>`, `127.0.0.1:<port>`, `http://localhost:<port>`, or safe launch command | `--repo . --proxy 127.0.0.1:8080` |
| `--live-proxy-fuzz` | flag | `False` | Enable Pillar 1 live loopback proxy RFC 9112 fuzzing explicitly (auto-enabled by `--proxy`) | `deep-audit --repo . --live-proxy-fuzz --proxy-port 8080` |
| `--proxy-host` / `--proxy-port` | str / int | `127.0.0.1` / `None` | Explicit loopback host and running proxy port for Pillar 1 fuzzing | `--proxy-host 127.0.0.1 --proxy-port 3128` |
| `--proxy-cmd` | string | `None` | Safe local command (`shell=False`) to spawn target proxy on ephemeral `127.0.0.1:<PORT>` | `--proxy-cmd "node dist/server.js"` |
| `--docker-parser-matrix` | flag | `False` | Cross-check proxy probes against local Docker multi-parser matrix (nginx, envoy, haproxy, undici, go, hyper) | `deep-audit --repo . --proxy 8080 --docker-parser-matrix` |
| `--trust-boundary-review` | flag | `False` | Enable Pillar 2 line-by-line structural trust-boundary review (14+ multi-token checks incl. TLS ClientHello cap, TRACE/TRACK echo, Win32 reparse flags, WFP inbound layers, bwrap pre-seccomp, POSIX ERE brackets, URL canonicalizer) | `deep-audit --repo . --trust-boundary-review --plain` |
| `--trust-max-files` | int | `80` | Max top-ranked production trust-boundary files to audit line-by-line | `--trust-max-files 100` |
| `--coverage-fuzz` | flag | `False` | Enable Pillar 3 coverage-guided fuzzing across root repo and nested crates (`vendor/*/Cargo.toml`), writing artifacts strictly outside target repo | `deep-audit --repo . --coverage-fuzz --fuzz-dry-run` |
| `--poc` / `poc` | flag / cmd | `False` | Strictly non-destructive false-positive triage & proof-of-concept verifier generator | `--all --repo . --poc --output-dir reports` |
| `docker-doctor` | cmd | — | Diagnose & repair Windows Docker Desktop / WSL2 NTFS-compressed VHDX startup errors (`--fix`, `--include-all-wsl`) | `docker-doctor --fix --include-all-wsl --plain` |

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

# --authorized (Explicit permission gate for public/remote targets; SSRF/private/CGNAT/metadata always blocked)
py -3.12 -u rfc_hunt_swarm.py --host dlptest.com --port 443 --tls --authorized

# Unified --all against a remote host (runs remote review checks without scanning local '.')
py -3.12 -u rfc_hunt_swarm.py --all --host target.example.com --port 443 --tls --authorized
py -3.12 -u main.py --all --host target.example.com --port 443 --tls --authorized

# Opt in to state-mutating HTTP methods (PUT/DELETE/PATCH) on an authorized target
py -3.12 -u rfc_hunt_swarm.py --all --host target.example.com --authorized --allow-destructive

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

### 7. AI ModelFusion, Refusal-Free Abliterated Models (No Safety Alignment) & Genetic Evolutionary Tuning
```powershell
# Default behavior: Refusal-free abliterated ModelFusion panel (NO safety filtering/refusal guardrails)
# Automatically orchestrates: Abliterated Gemma-4-12B + Cisco Foundation-Sec-8B + GLM-4 (abliterated preferred)
py -3.12 -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --debug

# --abliteration / --obliterated (Enabled by default across all commands)
py -3.12 -u rfc_hunt_swarm.py --mode terminator --abliteration --host 127.0.0.1 --port 3030 --debug

# --model (Explicitly target hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M or aliases)
py -3.12 -u rfc_hunt_swarm.py --model hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M

# Use shorthand alias 'gemma-4-12b-obliterated' or 'obliteratus'
py -3.12 -u rfc_hunt_swarm.py --model gemma-4-12b-obliterated

# Full Trio Panel Fusion: Abliterated Gemma-4-12B (Protocol) + Cisco Foundation-Sec-8B (Boundary) + GLM-4 (Arbiter)
py -3.12 -u rfc_hunt_swarm.py --model gemma-4-12b-obliterated --sec-model fenkohq/foundation-sec-8b:latest

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

# Google Mantis & Unified --all Multi-Scanner (Fusion + Abliterated Enforced)
py -3.12 -u rfc_hunt_swarm.py --all --repo . --depth 30
py -3.12 -u rfc_hunt_swarm.py --all --path engine/mantis_integrator.py --depth 50
py -3.12 -u rfc_hunt_swarm.py --mantis --repo . --mantis-mode patch --depth 100
py -3.12 -u main.py all --repo . --depth 30
py -3.12 -u main.py mantis --path . --mantis-mode scan

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

# --mcp (Run Model Context Protocol server over stdio, Streamable HTTP /http, or Legacy SSE /sse for ARTEX)
py -3.12 -u rfc_hunt_swarm.py mcp
py -3.12 -u rfc_hunt_swarm.py mcp --mcp-transport both --mcp-host 127.0.0.1 --mcp-port 8790 --mcp-token secret-token
py -3.12 -u main.py mcp --transport both --mcp-port 8790 --mcp-token secret-token

# BaaRai/ARTEX Durable Attack Chaining & Headless REST+SSE / MITM Proxy Integration (Standalone & --all)
py -3.12 -u main.py artex --host 127.0.0.1 --port 8080 --artex-rounds 2 --artex-noise-profile balanced
py -3.12 -u rfc_hunt_swarm.py --all --repo . --artex-rounds 2 --artex-url http://127.0.0.1:8787 --artex-proxy http://127.0.0.1:8788 --artex-llm-rotate --artex-wait-sse --artex-retest
```

### 10. Pure-CLI ARTEX Parity & Advisory Subcommands (Zero-GUI)
```powershell
# Start embedded pure-CLI recording HTTP/HTTPS MITM proxy (auto-generates keys/rfchunt_ca.crt)
python main.py proxy --port 8788 --noise-profile balanced --rewrite-rule "trace:X-RFCHunt=1"

# Unified --all with embedded MITM proxy, OpenAPI/HAR surface import, multi-role auth profiles, live workers & exports
python main.py --all --repo . --host 127.0.0.1 --port 8080 --authorized --embedded-proxy \
  --import-openapi spec.yaml --import-har session.har --auth-profile auth.yaml --scope-file scope.yaml \
  --artex-workers 4 --approval-mode policy --approval-rules rules.yaml --strict-poe \
  --export-advisory --export-csv

# Query persisted attack chains, shared worker traces, and asset coverage ledger (TTY Rich tables, --plain, or --json)
python main.py chains --min-poe 2 --verified-only
python main.py chains --json
python main.py traces --query "AUTH_BOUNDARY" --limit 50
python main.py coverage --json

# Replay persisted chains (offline receipt check or live HTTP replay)
python main.py retest --all-chains --live --authorized

# Export GHSA-ready Markdown advisories (redacted receipts) and formula-neutralized CSV
python main.py export-advisory --out reports/advisories --csv

# Export / decrypt & verify AES-256-GCM encrypted task archives (.rfca) with SHA-256 checksums
python main.py archive --export reports/task_backup.rfca
python main.py archive --import reports/task_backup.rfca
```

### 11. Deep Code-Repo Audit (`--deep-audit`), Live Loopback Proxy Fuzzing (`--proxy`), `--poc` & `docker-doctor`
```powershell
# Focused built-in CLI help & examples for --proxy and deep-audit:
python -u rfc_hunt_swarm.py --proxy --help
python -u rfc_hunt_swarm.py deep-audit --help

# 1. Bare --proxy: auto-spawn compiled Node repo proxy on ephemeral 127.0.0.1:0 (zero repo writes)
python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy --plain

# 2. Fuzz an already-running local proxy by port number (assumes 127.0.0.1)
python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy 8080 --plain

# 3. Fuzz an explicit loopback host:port (IPv4 or IPv6 — non-loopback fails closed)
python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy 127.0.0.1:3128 --plain
python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy [::1]:8080 --plain

# 4. Fuzz an explicit loopback URL with local Docker differential parser matrix
python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy http://localhost:8888 --docker-parser-matrix --plain

# 5. Spawn a custom local proxy command on ephemeral 127.0.0.1:<PORT> (shell=False, auto-cleaned)
python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy "node dist/server.js" --plain

# Targeted line-by-line structural trust-boundary review only (default top 80 production TS/Rust/Py/Go/C files)
python -u rfc_hunt_swarm.py deep-audit --repo D:\path\to\repo --trust-boundary-review --plain

# Full 3-pillar deep audit + auto-spawn loopback proxy + non-destructive --poc triage
python -u rfc_hunt_swarm.py deep-audit --repo D:\path\to\repo --proxy --poc --output-dir reports --plain

# Combined unified --all + --deep-audit + live --proxy + --poc (also works via main.py)
python -u rfc_hunt_swarm.py --all --repo D:\path\to\repo --deep-audit --proxy --poc --plain
python -u main.py --repo D:\path\to\repo --proxy --plain

# Windows Docker Desktop & WSL2 NTFS-compression VHDX diagnostic / self-healing repair
python -u rfc_hunt_swarm.py docker-doctor --plain
python -u rfc_hunt_swarm.py docker-doctor --fix --include-all-wsl --plain
```

### 12. Revenue Engine, HackerOne QA Phase (`qa-drafts`), Cooldown Monitor (`check-drafts`), Autonomous Hunt & ConPTY Watchdog
```powershell
# 1. QA Phase: audit & auto-repair a local draft Markdown file before staging
python revenue_cli.py qa-drafts --markdown-file draft.md --title "My Report Title" --program oppo_bbp --write-repaired draft_clean.md --strict

# 2. QA Phase: batch-audit exported HackerOne draft JSONs with live raw.githubusercontent.com line & #define checks
python revenue_cli.py qa-drafts --snapshot-json reports/ensemble_hunt/drafts_snapshot.json --out-md reports/ensemble_hunt/qa_draft_audit.md --out-edit-queue reports/ensemble_hunt/qa_edit_queue.json --strict

# 3. Cooldown Monitor: probe whether HackerOne `can_submit_draft?` has cleared (1 polite request)
python revenue_cli.py check-drafts --probe-only

# 4. Cooldown Monitor: inspect seeded priority queue offline or run continuous watch loop
python revenue_cli.py check-drafts --seed-only
python revenue_cli.py check-drafts --watch --interval-minutes 120 --max-per-day 2
python revenue_cli.py check-drafts --mark-submitted 4243972

# 5. Exhaustive Stage 0-5 ensemble audit & fast OODA funnel
python -u revenue_cli.py ensemble-audit --target D:\path\to\repo --program anthropic --all --ensemble --proxy auto --out reports/ensemble_hunt/out
python -u revenue_cli.py fast-ooda --target D:\path\to\repo --program common_codes --out out/fast_ooda --json

# 6. Standalone headless autonomous hunting runner (zero /browser) & Windows Scheduled Task installer
python scripts/autonomous_hunt.py --target D:\path\to\repo --program common_codes --dry-run
python scripts/autonomous_hunt.py --target D:\path\to\repo --embedded --json
powershell -ExecutionPolicy Bypass -File scripts/install_hunt_schedule.ps1 -IntervalMinutes 60 -CloneUnlocked

# 7. Global Windows ConPTY deadlock cleaner & 5-minute OS-level Scheduled Task watchdog
powershell -ExecutionPolicy Bypass -File scripts/clear_conpty_deadlocks.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File scripts/install_global_deadlock_watchdog.ps1
```

### 13. One-Command Turnkey Runner (`hunt.py`) & ACDSO ML Program Selection, JS Analysis, Recon Clustering & ATLAS AI Gate
```powershell
# 0. ONE-COMMAND TURNKEY PYTHON RUNNER (runs ML ranking, unlocked freshness watch, OODA, ensemble audit, Lean 4, QA & Chrome handoff)
python hunt.py --dry-run
python hunt.py --sync-public-directory --once
python hunt.py

# 1. Rank UNLOCKED HackerOne programs (newest launches, >=80% efficiency, wide scope, Lane 1/2 portfolio knapsack)
python revenue_cli.py rank-programs --min-efficiency 80 --capacity 6 --budget-minutes 120 --json
python revenue_cli.py rank-programs --preset signal_fast --use-boost --json

# 2. Sync HackerOne public directory & structured scopes into ProgramEligibilityDB v2 (public newest-first, API, or offline snapshot)
python revenue_cli.py sync-directory --public-directory --min-efficiency 80 --limit 25 --json
python revenue_cli.py sync-directory --snapshot-json h1_directory.json --json
python revenue_cli.py sync-directory --query "api" --limit 25 --json

# 3. Poll fresh <72h diffs strictly from UNLOCKED DB repos with invariant ETag caching + CommitDiffRanker ML scoring
python revenue_cli.py freshness-watch --from-eligibility-db --ml-rank --hours 72 --min-score 20

# 4. Analyze JavaScript bundles & cluster/classify anomalous HTTP responses (enforces strict DNS-boundary scope allowlist)
python revenue_cli.py analyze-js --input ./js_bundles --program common_codes --json
python revenue_cli.py cluster-recon --input recon_endpoints.json --program common_codes --json

# 5. Adversarial LLM prompt injection / indirect data exfiltration / guardrail bypass (fails closed unless AI is in scope)
python revenue_cli.py atlas-llm-eval --llm-target https://ai.example.com --program anthropic --suites low_resource,canary,indirect_exfil,ssrf_tool

# 6. Log real HackerOne report triage outcomes to continuously update Cox survival, GroupKFold LTR & LinUCB/Thompson models
python revenue_cli.py record-outcome --handle henkel_vdp --outcome TRIAGED --lane 1 --signal-delta 7.0 --bounty-usd 0 --triage-hours 16
```
