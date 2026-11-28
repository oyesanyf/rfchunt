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

## Complete Table of CLI Flags (100% Coverage with Runnable Examples)

> Every flag registered on `rfc_hunt_swarm.py` includes a concrete CLI example both here and in `python rfc_hunt_swarm.py --help`.

| Flag(s) | Type | Default | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `--rfc` | string | `9112` | Specific RFC ID to analyze (e.g. 9112 or MCP) | ``python rfc_hunt_swarm.py --all --repo . --rfc 9112`` |
| `--mode` | choice | `single` | Execution mode (default: single) | ``python rfc_hunt_swarm.py --all --repo . --mode single`` |
| `--list-terminators` | flag | `False` | Print the complete catalog of 25 Terminator RFC specifications and 36 wire/chunk/cross-protocol terminator mutators and exit | ``python rfc_hunt_swarm.py --all --repo . --list-terminators`` |
| `--host`, `--target` | string | `127.0.0.1` | Target host (domain or IP, default: 127.0.0.1) | ``python rfc_hunt_swarm.py --all --host target.example.com --port 443 --tls --authorized --dry-run`` |
| `--port` | int | `5006` | Target port (default: 5006) | ``python rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030`` |
| `--tls` | flag | `False` | Enable TLS/HTTPS for remote host (auto-enabled if port is 443) | ``python rfc_hunt_swarm.py --mode terminator --host target.example.com --port 443 --tls --authorized`` |
| `--targets` | string | `None` | Comma-separated target terminators (e.g. '127.0.0.1:8080,https://target.local:8443') | ``python rfc_hunt_swarm.py --all --repo . --targets .`` |
| `--terminators` | string | `all` | Comma-separated terminator categories: 'line,chunk,framing,cross_protocol,crlf_rhi,h2_gateway' or 'all' (default: all) | ``python rfc_hunt_swarm.py --all --repo . --terminators all`` |
| `--dashboard-out` | string | `terminator_dashboard.html` | Output path for generated HTML research dashboard (default: terminator_dashboard.html) | ``python rfc_hunt_swarm.py --all --repo . --dashboard-out terminator_dashboard.html`` |
| `--export-rules-dir` | string | `defense_rules` | Output directory for exported Nuclei, ModSecurity, and Suricata rules (default: defense_rules) | ``python rfc_hunt_swarm.py --all --repo . --export-rules-dir ./reports`` |
| `--probe` | string | `None` | Custom raw wire probe string or hex for oracle, h2, and differential modes | ``python rfc_hunt_swarm.py --all --repo . --probe "GET / HTTP/1.1\r\n\r\n"`` |
| `--random-port`, `--high-port` | flag | `False` | Use a high random available port for the UI and lab servers | ``python rfc_hunt_swarm.py ui --random-port`` |
| `--ui` | flag | `False` | Launch the interactive research dashboard web UI on a high random available port | ``python rfc_hunt_swarm.py ui --ui`` |
| `--ui-port` | int | `0` | Explicit port to bind the interactive UI dashboard server (default: auto-allocated high random port) | ``python rfc_hunt_swarm.py ui --ui-port 5`` |
| `--serve` | flag | `False` | Serve the dashboard UI on a high random available port after generation | ``python rfc_hunt_swarm.py ui --serve`` |
| `--kettle` | flag | `False` | Shortcut to scan James Kettle's curated 138 HTTP & SMTP RFC corpus | ``python rfc_hunt_swarm.py --all --repo . --kettle`` |
| `--all-active` | flag | `False` | Shortcut to scan all active IETF protocol specifications | ``python rfc_hunt_swarm.py --all --repo . --all-active`` |
| `--cycles` | int | `3` | Max mutation cycles to run per RFC | ``python rfc_hunt_swarm.py --all --repo . --cycles 3`` |
| `--timeout` | float | `900.0` | Ollama LLM inference timeout in seconds (default: 900.0 = 15m; 0 for unlimited) | ``python rfc_hunt_swarm.py --all --repo . --timeout 900.0`` |
| `--model` | string | `hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M` | Preferred primary base model (default: refusal-free hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M) | ``python rfc_hunt_swarm.py --all --repo . --model hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M`` |
| `--env-local` | string | `None` | Path to `.env.local` containing paid/enterprise LLM model credentials (when paid models are present in `.env.local`, RFCHunt uses them directly and bypasses Ollama) | ``python rfc_hunt_swarm.py --all --repo . --env-local .env.local`` |
| `--force-ollama` | flag | `False` | Force local Ollama backend even if `.env.local` defines paid model credentials | ``python rfc_hunt_swarm.py --all --repo . --force-ollama`` |
| `--abliteration`, `--obliterated` | flag | `True` | Default ON: Use refusal-free abliterated models (no safety filtering) across ModelFusion panel (Gemma + Cisco Foundation-Sec + GLM) | ``python rfc_hunt_swarm.py --all --repo . --abliteration`` |
| `--sec-model` | string | `None` | Secondary security specialist model (default: Cisco fenkohq/foundation-sec-8b:latest / abliterated) | ``python rfc_hunt_swarm.py --all --repo . --sec-model hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M`` |
| `--no-fusion` | flag | `True` | Disable multi-model panel fusion | ``python rfc_hunt_swarm.py --all --repo . --no-fusion`` |
| `--db` | string | `terminator.db` | SQLite database path (default: terminator.db) | ``python rfc_hunt_swarm.py --all --repo . --db terminator.db`` |
| `--clean-db` | flag | `False` | Clean the SQLite database (truncate transient evaluations, anomalies, probes, fragments, and VACUUM to reclaim disk space) | ``python rfc_hunt_swarm.py --all --repo . --clean-db`` |
| `--keep-rfcs-on-clean`, `--keep-rfcs` | flag | `False` | When cleaning the database, retain the cached RFC specifications and index | ``python rfc_hunt_swarm.py --clean-db --keep-rfcs-on-clean`` |
| `--keep-findings-on-clean`, `--keep-findings` | flag | `False` | When cleaning the database, retain confirmed vulnerabilities and defensive rules | ``python rfc_hunt_swarm.py --clean-db --keep-findings-on-clean`` |
| `--cache-dir` | string | `rfcs` | Local directory to cache RFCs (default: rfcs) | ``python rfc_hunt_swarm.py --all --repo . --cache-dir ./reports`` |
| `--max-rfcs`, `--count` | int | `None` | Maximum number of RFCs to cycle through | ``python rfc_hunt_swarm.py --all --repo . --max-rfcs 5`` |
| `--keywords` | string | `None` | Comma-separated keywords to filter active RFCs (e.g. 'chunked,trailer,websocket') | ``python rfc_hunt_swarm.py --all --repo . --keywords config.yaml`` |
| `--comb-only`, `--offline` | flag | `False` | Offline RFC ingestion & probe generation into database without sending packets to any host | ``python rfc_hunt_swarm.py --all --repo . --comb-only`` |
| `--no-lab` | flag | `False` | Do not auto-spawn the built-in local TestLabServer when targeting localhost/127.0.0.1 | ``python rfc_hunt_swarm.py --all --repo . --no-lab`` |
| `--patched` | flag | `False` | Start TestLabServer with /internal/service auth-boundary patched (returns 403) | ``python rfc_hunt_swarm.py --all --repo . --patched`` |
| `--demo` | flag | `False` | Run cascade extrapolation demonstration when no confirmed findings exist | ``python rfc_hunt_swarm.py --all --repo . --demo`` |
| `--mcp` | flag | `False` | Shortcut to launch the Model Context Protocol (MCP) JSON-RPC server over stdio | ``python rfc_hunt_swarm.py mcp --mcp`` |
| `--build` | flag | `False` | Shortcut to run the unified 'Build All' verification pipeline | ``python rfc_hunt_swarm.py --all --repo . --build`` |
| `--skip-tests` | flag | `False` | Skip running pytest when executing --mode build / --build | ``python rfc_hunt_swarm.py --all --repo . --skip-tests`` |
| `--sequence` | string | `None` | Custom byte sequence to test in Protocol Ruler mode (e.g. '\xc0\x8a') | ``python rfc_hunt_swarm.py ruler --host 127.0.0.1 --port 3030 --sequence "\xc0\x8a"`` |
| `--name` | string | `Custom Probe` | Name for custom sequence in Protocol Ruler mode | ``python rfc_hunt_swarm.py ruler --host 127.0.0.1 --port 3030 --name "Custom Probe"`` |
| `--max-size` | int | `131072` | Max header length to test in Protocol Ruler mode (default: 131072) | ``python rfc_hunt_swarm.py ruler --host 127.0.0.1 --port 3030 --max-size 131072`` |
| `--sentences` | int | `2` | Sentences per chunk in chunk/auto modes (default: 2) | ``python rfc_hunt_swarm.py --all --repo . --sentences 2`` |
| `--limit`, `--fragments` | int | `5` | Max fragments/probes to process in modular modes (default: 5) | ``python rfc_hunt_swarm.py --all --repo . --limit 5`` |
| `--variants` | int | `3` | Permutation variants per probe (default: 3) | ``python rfc_hunt_swarm.py --all --repo . --variants 3`` |
| `--discover-recent` | int | `0` | Discover recent RFCs from index in fetch/auto modes | ``python rfc_hunt_swarm.py --all --repo . --discover-recent 5`` |
| `--keep-going` | flag | `False` | Continue hunting after finding first flaw in hunt mode | ``python rfc_hunt_swarm.py --all --repo . --keep-going`` |
| `--generations` | int | `3` | Evolutionary dream generations (default: 3) | ``python rfc_hunt_swarm.py --all --repo . --generations 3`` |
| `--debug` | flag | `False` | Enable comprehensive debugging mode (prints raw host responses, socket telemetry, and sequence pipeline steps) | ``python rfc_hunt_swarm.py --all --repo . --debug`` |
| `--show-response` | flag | `False` | Print full raw HTTP/TLS responses received from the target host | ``python rfc_hunt_swarm.py --all --repo . --show-response`` |
| `-v`, `--verbose` | flag | `False` | Enable verbose execution telemetry and full payload/response tracing | ``python rfc_hunt_swarm.py --all --repo . --verbose`` |
| `--authorized`, `--allow-all`, `--allow-target`, `--allow-any` | flag | `False` | Explicitly authorize active security testing against remote/public target (e.g. target.example.com) or allow any target | ``python rfc_hunt_swarm.py --all --host target.example.com --port 443 --tls --authorized`` |
| `--allow-destructive` | flag | `False` | Explicitly permit state-mutating requests (PUT, DELETE, PATCH) and active response theft on authorized targets | ``python rfc_hunt_swarm.py --all --host target.example.com --authorized --allow-destructive --dry-run`` |
| `--dream-rsi` | flag | `True` | Enable Open Dream-RSI: recursive off-policy self-improvement between cycles (enabled by default) | ``python rfc_hunt_swarm.py --mode dream --dream-rsi`` |
| `--no-dream-rsi` | flag | `True` | Disable default Open Dream-RSI evolution cycle | ``python rfc_hunt_swarm.py --all --repo . --no-dream-rsi`` |
| `--dream-rollouts`, `--rollouts` | int | `300` | Number of simulated rollouts per dream generation (default: 300) | ``python rfc_hunt_swarm.py --mode dream --dream-rollouts 300`` |
| `--dream-export`, `--export` | string | `data/dream_policies.json` | Path to export evolved Dream-RSI policies | ``python rfc_hunt_swarm.py --mode dream --dream-export data/dream_policies.json`` |
| `--dream-benchmark` | flag | `False` | Run 4-baseline matched-seed empirical Dream-RSI RL benchmark with 95%% CIs | ``python rfc_hunt_swarm.py --mode dream --dream-benchmark`` |
| `--dream-seeds` | int | `10` | Number of matched episode seeds for --dream-benchmark (default: 10) | ``python rfc_hunt_swarm.py --mode dream --dream-seeds 10`` |
| `--dream-budget` | int | `40` | Step budget per episode for --dream-benchmark (default: 40) | ``python rfc_hunt_swarm.py --mode dream --dream-budget 40`` |
| `--dream-live-lab`, `--live-lab` | flag | `False` | Run --dream-benchmark against local loopback 127.0.0.1 TestLabServer (zero external traffic) | ``python rfc_hunt_swarm.py --mode dream --dream-live-lab`` |
| `--dream-stack-profile` | string | `None` | Optional target stack profile for stack-specific Dream-RSI policies (e.g. nginx, envoy, node, rust) | ``python rfc_hunt_swarm.py --mode dream --dream-stack-profile config.yaml`` |
| `--export-caldera` | string | `caldera_export` | Directory to export Caldera plugin structure (default: caldera_export, runs automatically) | ``python rfc_hunt_swarm.py --all --repo . --export-caldera caldera_export`` |
| `--no-caldera` | flag | `False` | Disable default Caldera export | ``python rfc_hunt_swarm.py --all --repo . --no-caldera`` |
| `--caldera-url`, `--push` | string | `None` | Optional Caldera server URL to push confirmed findings live | ``python rfc_hunt_swarm.py caldera --caldera-url http://127.0.0.1:8787`` |
| `--caldera-key`, `--api-key` | string | `ADMIN123` | Caldera API authentication key (default: ADMIN123) | ``python rfc_hunt_swarm.py caldera --caldera-key ADMIN123`` |
| `--concurrency`, `--threads` | int | `8` | Maximum concurrent probe execution threads (bounded by semaphore, default: 8) | ``python rfc_hunt_swarm.py --all --repo . --concurrency 8`` |
| `--harness2` | flag | `True` | Enable Google Research Harness² recursive agent harnessing (c1..c8 Propose-Probe-Compose; enabled by default) | ``python rfc_hunt_swarm.py harness2 --rfc 9112 --harness2`` |
| `--no-harness2` | flag | `True` | Disable Google Research Harness² recursive agent harnessing | ``python rfc_hunt_swarm.py --all --repo . --no-harness2`` |
| `--harness2-k`, `--k` | int | `1` | Harness² task-level recursion budget k (R=4k rollouts, P=3k improvement stages; default: 1) | ``python rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-k 1`` |
| `--harness2-mode` | choice | `parallel` | Harness² recursion mode: 'parallel' ('agg' width exploration), 'sequential' ('seq' depth refinement), or 'both' | ``python rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-mode parallel`` |
| `--harness2-domain`, `--domain` | string | `auto` | Protocol domain for Harness² experience library (e.g. http11_framing, h2_translation, tls13_pqc, auto) | ``python rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-domain traffic.har`` |
| `--harness2-runs-dir`, `--runs-dir` | string | `runs/harness2` | Output directory for persisted Harness² domain libraries, INDEX.md, and EXPERIENCE.md (default: runs/harness2) | ``python rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-runs-dir traffic.har`` |
| `--harness2-report`, `--report` | flag | `False` | Display historical Harness² recursion runs, R=4k/P=3k ledger verification, and learned domain lessons | ``python rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-report`` |
| `--raptor`, `--enable-raptor` | flag | `False` | Enable RAPTOR Autonomous Framework (Web application & source code pentesting; credit: Gadi Evron, Daniel Cuthbert, Halvar Flake) | ``python rfc_hunt_swarm.py raptor --repo . --raptor`` |
| `--raptor-mode` | choice | `None` | RAPTOR analysis mode: 'all'/'full' (runs describe + scan + crypto + sca + agentic), 'web' (live host DAST), 'scan' (fast static), 'agentic' (LLM triage), 'crypto' (PQC), 'sca' (dependencies) | ``python rfc_hunt_swarm.py raptor --repo . --raptor-mode web`` |
| `--raptor-target`, `--folder`, `--dir` | string | `None` | Any local folder or repository path to audit with RAPTOR | ``python rfc_hunt_swarm.py raptor --repo . --raptor-target .`` |
| `--raptor-model` | string | `fenkohq/foundation-sec-8b:latest` | Ollama LLM for RAPTOR agentic triage (default: fenkohq/foundation-sec-8b:latest) | ``python rfc_hunt_swarm.py raptor --repo . --raptor-model hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M`` |
| `--raptor-status`, `--status` | flag | `False` | Check RAPTOR Docker container (danielcuthbert/raptor:latest) and Ollama security model readiness | ``python rfc_hunt_swarm.py raptor --repo . --raptor-status`` |
| `--raptor-setup`, `--install-raptor` | flag | `False` | Automatically clone, configure, and pull the RAPTOR Security Framework (https://github.com/gadievron/raptor & danielcuthbert/raptor:latest) | ``python rfc_hunt_swarm.py raptor --repo . --raptor-setup`` |
| `--raptor-findings`, `--findings` | flag | `False` | List and summarize recent SARIF vulnerability findings from RAPTOR scans | ``python rfc_hunt_swarm.py raptor --repo . --raptor-findings`` |
| `--policy-groups` | string | `` | Optional policy groups for RAPTOR scan (e.g. 'secrets,owasp,crypto') | ``python rfc_hunt_swarm.py --all --repo . --policy-groups config.yaml`` |
| `--include-codeql` | flag | `False` | Include deep CodeQL compilation during RAPTOR agentic scan | ``python rfc_hunt_swarm.py --all --repo . --include-codeql`` |
| `--aiscan`, `--enable-aiscan` | flag | `False` | Enable haasonsaas/aiscan AI & model risk scanner (Module 18) | ``python rfc_hunt_swarm.py aiscan --aiscan`` |
| `--aiscan-target` | string | `.` | Target directory to audit for AI vulnerabilities, prompt injection sinks, and exposed model credentials (default: '.') | ``python rfc_hunt_swarm.py aiscan --aiscan-target .`` |
| `--aiscan-report` | flag | `False` | Print summary of recent AI security audit findings from terminator.db | ``python rfc_hunt_swarm.py aiscan --aiscan-report`` |
| `--artex`, `--dual-graph` | flag | `False` | Enable BaaRai/ARTEX Dual-Graph planner/worker attack chaining engine (Module 17) | ``python rfc_hunt_swarm.py --all --repo . --artex`` |
| `--artex-rounds`, `--rounds` | int | `1` | Number of multi-round planning cycles to execute in ARTEX Dual-Graph (default: 1) | ``python rfc_hunt_swarm.py --all --repo . --artex-rounds 1`` |
| `--artex-url` | string | `None` | Headless BaaRai/ARTEX REST+SSE server URL (e.g. http://127.0.0.1:8787) | ``python rfc_hunt_swarm.py --all --repo . --artex-url http://127.0.0.1:8787`` |
| `--artex-token` | string | `None` | Bearer JWT token for headless ARTEX REST API | ``python rfc_hunt_swarm.py --all --repo . --artex-token demo-token`` |
| `--artex-proxy` | string | `None` | ARTEX recording MITM proxy URL (e.g. http://127.0.0.1:8788) | ``python rfc_hunt_swarm.py --all --repo . --artex-proxy example`` |
| `--artex-ca-cert` | string | `None` | Optional CA certificate path for ARTEX MITM proxy | ``python rfc_hunt_swarm.py --all --repo . --artex-ca-cert config.yaml`` |
| `--artex-noise-profile` | choice | `None` | ARTEX target noise governor profile (off\|quiet\|balanced\|aggressive) | ``python rfc_hunt_swarm.py --all --repo . --artex-noise-profile off`` |
| `--artex-llm-profiles` | string | `None` | Comma-separated LLM profile IDs for ARTEX worker rotation | ``python rfc_hunt_swarm.py --all --repo . --artex-llm-profiles profA,profB`` |
| `--artex-llm-rotate` | flag | `False` | Enable round-robin multi-LLM worker rotation (A, B, A, B) | ``python rfc_hunt_swarm.py --all --repo . --artex-llm-rotate`` |
| `--artex-wait-sse` | flag | `False` | Stream headless ARTEX SSE events until terminal completion | ``python rfc_hunt_swarm.py --all --repo . --artex-wait-sse`` |
| `--artex-budget-turns` | int | `0` | Optional max task turn budget for ARTEX attack chaining (0 = unlimited) | ``python rfc_hunt_swarm.py --all --repo . --artex-budget-turns 5`` |
| `--artex-retest`, `--retest` | flag | `False` | Run ARTEX chain retest loop after attack chaining | ``python rfc_hunt_swarm.py --all --repo . --artex-retest`` |
| `--artex-workers` | int | `3` | Concurrent ARTEX worker pool size (default: 3) | ``python rfc_hunt_swarm.py --all --repo . --artex-workers 3`` |
| `--artex-live` | flag | `None` | Force live non-destructive ARTEX worker verification | ``python rfc_hunt_swarm.py --all --repo . --artex-live`` |
| `--no-artex-live` | flag | `False` | Disable auto-live ARTEX worker verification | ``python rfc_hunt_swarm.py --all --repo . --no-artex-live`` |
| `--embedded-proxy` | flag | `False` | Start embedded pure-CLI recording MITM proxy during scan | ``python rfc_hunt_swarm.py --all --repo . --embedded-proxy`` |
| `--no-embedded-proxy` | flag | `False` | Disable embedded MITM recording proxy even when --hybrid is enabled | ``python rfc_hunt_swarm.py --hybrid --repo . --host 127.0.0.1 --no-embedded-proxy --dry-run`` |
| `--embedded-proxy-port` | int | `0` | Port for embedded MITM proxy (0 = ephemeral) | ``python rfc_hunt_swarm.py --all --repo . --embedded-proxy-port 5`` |
| `--auth-profile` | string | `None` | Path(s) to JSON/YAML multi-role auth profiles (repeatable or comma-separated for 2-account BOLA/IDOR differential replay) | ``python rfc_hunt_swarm.py --all --repo . --auth-profile config.yaml`` |
| `--header`, `--bounty-header` | string | `[]` | Repeatable custom HTTP header ('Name: Value', e.g. 'X-Bug-Bounty: handle') propagated across all raw sockets, HTTP/2 frames, HTTP clients, and external scanners | ``python rfc_hunt_swarm.py --all --host target.example.com --authorized --header "X-Bug-Bounty: researcher"`` |
| `--user-agent` | string | `None` | Custom User-Agent header propagated across all raw sockets, HTTP/2 frames, HTTP clients, and external scanners | ``python rfc_hunt_swarm.py --all --host target.example.com --authorized --user-agent "RFCHunt-Researcher/1.0"`` |
| `--max-rps` | float | `0.0` | Global shared token-bucket requests-per-second rate cap across all raw sockets, HTTP clients, and external scanners (0 = unlimited) | ``python rfc_hunt_swarm.py --all --host target.example.com --authorized --max-rps 2.0`` |
| `--h2-desync` | flag | `True` | Enable live 3-trial binary HTTP/2 (ALPN h2 / h2c) desync probing (H2.CL, H2.TE, pseudo-header smuggling; default: True) | ``python rfc_hunt_swarm.py --all --repo . --h2-desync`` |
| `--no-h2-desync` | flag | `True` | Disable live binary HTTP/2 desync probing during --all | ``python rfc_hunt_swarm.py --all --repo . --no-h2-desync`` |
| `--import-har` | string | `None` | Import HAR 1.2 recording into AssetGraph + traffic_evidence | ``python rfc_hunt_swarm.py --all --repo . --import-har traffic.har`` |
| `--import-openapi` | string | `None` | Import OpenAPI/Swagger spec into AssetGraph | ``python rfc_hunt_swarm.py --all --repo . --import-openapi openapi.yaml`` |
| `--scope-file` | string | `None` | Path to YAML/JSON allow/deny scope rules | ``python rfc_hunt_swarm.py --all --repo . --scope-file config.yaml`` |
| `--approval-mode` | choice | `policy` | Approval gate mode (policy\|prompt\|deny) | ``python rfc_hunt_swarm.py --all --repo . --approval-mode policy`` |
| `--approval-rules` | string | `None` | Path to YAML/JSON approval rules file | ``python rfc_hunt_swarm.py --all --repo . --approval-rules config.yaml`` |
| `--strict-poe` | flag | `False` | Require POE==3 verified exploit proof (default on advisory exports unless --include-leads) | ``python rfc_hunt_swarm.py --all --repo . --strict-poe`` |
| `--include-leads` | flag | `False` | Include POE=1-2 manual review leads in advisory exports and --strict-poe reports | ``python rfc_hunt_swarm.py --all --repo . --include-leads`` |
| `--export-advisory` | flag | `False` | Export GHSA-ready Markdown advisories (defaults to POE==3 verified exploits unless --include-leads) | ``python rfc_hunt_swarm.py --all --repo . --export-advisory`` |
| `--export-csv` | flag | `False` | Export formula-neutralized CSV of findings & chains | ``python rfc_hunt_swarm.py --all --repo . --export-csv`` |
| `--poc` | flag | `False` | Generate non-destructive PoC verification scripts, false-positive triage, and POC_INDEX.md bundle under <output-dir>/pocs/ | ``python rfc_hunt_swarm.py --all --repo . --poc --output-dir reports`` |
| `--poc-dir` | string | `None` | Optional output directory for --poc verification bundle (defaults to <output-dir>/pocs) | ``python rfc_hunt_swarm.py --all --repo . --poc --poc-dir ./reports`` |
| `--poc-include-rejected` | flag | `False` | Also emit verification scripts for rejected false positives and test fixtures during --poc | ``python rfc_hunt_swarm.py --all --repo . --poc --poc-include-rejected`` |
| `--poc-max` | int | `50` | Maximum number of verification scripts to generate during --poc (default: 50) | ``python rfc_hunt_swarm.py --all --repo . --poc --poc-max 50`` |
| `--poc-container-verify` | flag | `False` | Run isolated Docker ContainerPOEVerifier on surviving HIGH/CRITICAL candidates during --poc | ``python rfc_hunt_swarm.py --all --repo . --poc --poc-container-verify`` |
| `--fix`, `--fix-docker` | flag | `False` | Run non-destructive Windows Docker Desktop / WSL2 VHDX compression & bootstrap self-heal (for `docker-doctor`) | ``python rfc_hunt_swarm.py docker-doctor --fix`` |
| `--include-all-wsl` | flag | `False` | Also decompress non-Docker WSL2 distro VHDX files (e.g. Ubuntu) during `docker-doctor --fix` | ``python rfc_hunt_swarm.py docker-doctor --include-all-wsl`` |
| `--reset-docker-distro` | flag | `False` | Also unregister ONLY the stateless `docker-desktop` WSL runtime distro during `docker-doctor --fix` (preserves docker_data.vhdx) | ``python rfc_hunt_swarm.py docker-doctor --reset-docker-distro`` |
| `--deep-audit` | flag | `False` | Enable 3-pillar deep repo audit (live 127.0.0.1 proxy fuzzing + line-by-line trust-boundary review + root & nested-crate coverage-guided fuzzing) | ``python rfc_hunt_swarm.py deep-audit --repo . --proxy --poc --plain`` |
| `--proxy` | string | `None` | Enable live loopback-only (127.0.0.1) proxy fuzzing; pass bare `--proxy` to auto-spawn repo proxy on 127.0.0.1:0, or pass `<port>` / `127.0.0.1:<port>` / `http://127.0.0.1:<port>` / safe launch command | ``python rfc_hunt_swarm.py --repo . --proxy 127.0.0.1:8080 --plain`` |
| `--live-proxy-fuzz` | flag | `False` | Enable live loopback-only (127.0.0.1) proxy RFC 9112 fuzzing + differential parser cross-check | ``python rfc_hunt_swarm.py deep-audit --repo . --live-proxy-fuzz`` |
| `--trust-boundary-review` | flag | `False` | Enable targeted line-by-line trust-boundary security review (proxies, path resolvers, authz/ACL, shell sinks, Rust FFI) | ``python rfc_hunt_swarm.py deep-audit --repo . --trust-boundary-review`` |
| `--coverage-fuzz` | flag | `False` | Enable coverage-guided fuzzing across root repo parsers and nested crates (e.g. vendor/*/Cargo.toml) | ``python rfc_hunt_swarm.py --all --repo . --coverage-fuzz`` |
| `--proxy-host` | string | `127.0.0.1` | Loopback-only proxy host for --live-proxy-fuzz (default: 127.0.0.1) | ``python rfc_hunt_swarm.py deep-audit --repo . --proxy-host 127.0.0.1`` |
| `--proxy-port` | int | `None` | Existing loopback 127.0.0.1 proxy port to fuzz with --live-proxy-fuzz | ``python rfc_hunt_swarm.py deep-audit --repo . --proxy-port 5`` |
| `--proxy-cmd` | string | `None` | Optional safe command to launch target repo proxy on 127.0.0.1:<PORT> during --live-proxy-fuzz (shell=False) | ``python rfc_hunt_swarm.py deep-audit --repo . --proxy-cmd example`` |
| `--allow-repo-exec` | flag | `False` | Explicit opt-in required to dynamically import/execute compiled target repository proxy code (dist/*.js) or run --proxy-cmd inside target repo directory | ``python rfc_hunt_swarm.py --all --repo . --allow-repo-exec`` |
| `--trust-max-files` | int | `80` | Max top-ranked trust-boundary files to audit line-by-line (default: 80) | ``python rfc_hunt_swarm.py deep-audit --repo . --trust-max-files 80`` |
| `--enable-external-scanners` | flag | `False` | Enable external black-box scanners (httpx, katana, nuclei) — included in --all by default for live hosts; opt-in for standalone `scanner` mode | ``python rfc_hunt_swarm.py --all --repo . --enable-external-scanners`` |
| `--no-external-scanners` | flag | `False` | Disable external black-box scanners (httpx, katana, nuclei) during --all | ``python rfc_hunt_swarm.py --all --repo . --no-external-scanners`` |
| `--httpx-scan` | flag | `None` | Enable ProjectDiscovery httpx discovery (included in --all by default for live hosts) | ``python rfc_hunt_swarm.py --all --repo . --httpx-scan`` |
| `--no-httpx-scan` | flag | `True` | Disable ProjectDiscovery httpx discovery during --all | ``python rfc_hunt_swarm.py --all --repo . --no-httpx-scan`` |
| `--katana-scan` | flag | `None` | Enable ProjectDiscovery katana crawling (included in --all by default for live hosts) | ``python rfc_hunt_swarm.py --all --repo . --katana-scan`` |
| `--no-katana-scan` | flag | `True` | Disable ProjectDiscovery katana crawling during --all | ``python rfc_hunt_swarm.py --all --repo . --no-katana-scan`` |
| `--nuclei-scan` | flag | `None` | Enable ProjectDiscovery nuclei non-destructive scanning (included in --all by default for live hosts) | ``python rfc_hunt_swarm.py --all --repo . --nuclei-scan`` |
| `--no-nuclei-scan` | flag | `True` | Disable ProjectDiscovery nuclei scanning during --all | ``python rfc_hunt_swarm.py --all --repo . --no-nuclei-scan`` |
| `--nuclei-tags` | string | `None` | Comma-separated non-destructive nuclei tags (e.g. tech,misconfig,exposure,headers) | ``python rfc_hunt_swarm.py --all --repo . --nuclei-tags tech,misconfig,exposure`` |
| `--scanner-isolation` | choice | `host` | External scanner execution isolation mode (host\|docker) | ``python rfc_hunt_swarm.py --all --repo . --scanner-isolation host`` |
| `--docker-image` | string | `None` | Optional explicit OCI image for docker isolation | ``python rfc_hunt_swarm.py docker-doctor --docker-image python:3.12-slim`` |
| `--docker-network` | choice | `None` | Docker network mode for external scanner isolation (bridge\|none) | ``python rfc_hunt_swarm.py docker-doctor --docker-network bridge`` |
| `--artex-multiturn` | flag | `False` | Enable bounded multi-turn ArtexWorker adaptive tool loop | ``python rfc_hunt_swarm.py --all --repo . --artex-multiturn`` |
| `--no-artex-multiturn` | flag | `False` | Disable bounded multi-turn ArtexWorker adaptive tool loop even under --hybrid | ``python rfc_hunt_swarm.py --hybrid --repo . --host 127.0.0.1 --no-artex-multiturn --dry-run`` |
| `--artex-intent-turns` | int | `0` | Max turns per ARTEX intent (0 = default/unlimited) | ``python rfc_hunt_swarm.py --all --repo . --artex-intent-turns 5`` |
| `--artex-intent-tokens` | int | `0` | Max tokens per ARTEX intent (0 = unlimited) | ``python rfc_hunt_swarm.py --all --repo . --artex-intent-tokens 5`` |
| `--json` | flag | `False` | Emit machine-readable JSON output | ``python rfc_hunt_swarm.py --all --repo . --dry-run --json`` |
| `--plain` | flag | `False` | Force plain ASCII output | ``python rfc_hunt_swarm.py --all --repo . --plain`` |
| `--chain-id` | string | `None` | Specific chain ID for retest or export-advisory | ``python rfc_hunt_swarm.py chains --chain-id example`` |
| `--min-poe` | int | `0` | Minimum POE level filter (0..3) for chains | ``python rfc_hunt_swarm.py chains --min-poe 5`` |
| `--verified-only` | flag | `False` | Filter chains to verified only | ``python rfc_hunt_swarm.py chains --verified-only`` |
| `--all-chains` | flag | `False` | Retest all persisted chains | ``python rfc_hunt_swarm.py retest --all-chains`` |
| `--live` | flag | `False` | Enable live replay in retest mode | ``python rfc_hunt_swarm.py retest --live`` |
| `--task-id` | string | `None` | Filter by ARTEX task ID | ``python rfc_hunt_swarm.py --all --repo . --task-id example`` |
| `--worker-id` | string | `None` | Filter traces by worker ID | ``python rfc_hunt_swarm.py traces --worker-id example`` |
| `--query`, `-q` | string | `None` | Search query for worker traces | ``python rfc_hunt_swarm.py traces --query "auth bypass"`` |
| `--out` | string | `reports` | Output directory for export-advisory | ``python rfc_hunt_swarm.py export-advisory --out reports/advisories`` |
| `--csv` | flag | `False` | Export formula-safe CSV in export-advisory | ``python rfc_hunt_swarm.py --all --repo . --csv`` |
| `--export-archive` | string | `None` | Output AES-256-GCM encrypted .rfca task archive path (omit path under --all/--hybrid to auto-write into output-dir) | ``python rfc_hunt_swarm.py --all --repo . --export-archive reports/audit.rfca`` |
| `--no-export-archive` | flag | `False` | Disable automatic AES-256-GCM encrypted .rfca task archive export under --hybrid | ``python rfc_hunt_swarm.py --hybrid --repo . --no-export-archive --dry-run`` |
| `--import`, `--import-archive` | string | `None` | Input encrypted .rfca archive file path | ``python rfc_hunt_swarm.py archive --import reports/task_backup.rfca`` |
| `--key-file` | string | `None` | Optional encryption key file path for archive | ``python rfc_hunt_swarm.py archive --key-file config.yaml`` |
| `--ca-dir` | string | `keys` | CA directory for proxy mode | ``python rfc_hunt_swarm.py proxy --ca-dir ./reports`` |
| `--noise-profile` | choice | `None` | Noise governor profile for proxy mode | ``python rfc_hunt_swarm.py proxy --noise-profile off`` |
| `--rewrite-rule` | string | `[]` | Header rewrite rule for proxy mode (name:Header=Value) | ``python rfc_hunt_swarm.py proxy --rewrite-rule "add-hdr:X-Test=1"`` |
| `--duration` | float | `None` | Optional run duration in seconds for proxy mode | ``python rfc_hunt_swarm.py proxy --duration 10.0`` |
| `--mcp-transport`, `--transport` | choice | `stdio` | MCP transport for `mcp` mode: stdio, http (/http), sse (/sse), or both | ``python rfc_hunt_swarm.py mcp --mcp-transport stdio`` |
| `--mcp-host` | string | `127.0.0.1` | Bind address for remote HTTP/SSE MCP server (default: 127.0.0.1) | ``python rfc_hunt_swarm.py mcp --mcp-host 127.0.0.1`` |
| `--mcp-port` | int | `8790` | Port for remote HTTP/SSE MCP server (default: 8790) | ``python rfc_hunt_swarm.py mcp --mcp-port 8790`` |
| `--mcp-token` | string | `None` | Optional Bearer token for remote HTTP/SSE MCP clients | ``python rfc_hunt_swarm.py mcp --mcp-token demo-token`` |
| `--prompt-smuggle` | flag | `False` | Synthesize and verify novel cross-layer Desynchronized Prompt Injection attack chains | ``python rfc_hunt_swarm.py --all --repo . --prompt-smuggle`` |
| `--export-sarif` | string | `None` | Export aggregated vulnerability findings to specified SARIF file in reports/ | ``python rfc_hunt_swarm.py --all --repo . --export-sarif reports/audit.sarif`` |
| `--all`, `--run-all`, `--all-scans` | flag | `False` | Execute ALL integrated scanners (Google Mantis, aiscan, ARTEX Dual-Graph, RAPTOR, Prompt Smuggling, Module 21 REA + rea-agents CLI, and httpx/katana/nuclei for live hosts) with mandatory ModelFusion + Abliterated models | ``python rfc_hunt_swarm.py --all --repo . --dry-run`` |
| `--hybrid` | flag | `False` | Execute turnkey unified --hybrid local codebase + live remote audit (auto-enables --all, ARTEX multi-turn workers, strict POE=3, live retester, embedded MITM recording proxy, static+live REA drift correlation, GHSA advisories, formula-safe CSV, encrypted .rfca archive, and auto-STRIDE) | ``python rfc_hunt_swarm.py --hybrid --repo . --host 127.0.0.1 --port 8080 --dry-run`` |
| `--repo` | string | `None` | Repository directory path for --all, --mantis, or --raptor audits | ``python rfc_hunt_swarm.py --all --repo ./target_repo`` |
| `--path` | string | `None` | Specific file or directory path for --all, --mantis, or --raptor audits | ``python rfc_hunt_swarm.py --all --path engine/mantis_integrator.py`` |
| `--mantis`, `--enable-mantis` | flag | `False` | Enable Google Mantis toolkit (Module 20: threat modeling, depth hypotheses, Tier 1/2 repro, CVSS rubric, patching) | ``python rfc_hunt_swarm.py --mantis --repo . --mantis`` |
| `--mantis-mode` | choice | `full` | Google Mantis execution mode (default: full) | ``python rfc_hunt_swarm.py --mantis --repo . --mantis-mode full`` |
| `--depth`, `--mantis-depth` | int | `None` | Google Mantis audit depth 1..100 (default: 100 for --all, 30 for mantis; scales coverage, passes, and rule tiers) | ``python rfc_hunt_swarm.py --all --repo . --depth 5`` |
| `--mantis-target` | string | `None` | Target repository or file path for Google Mantis scan | ``python rfc_hunt_swarm.py --mantis --repo . --mantis-target .`` |
| `--mantis-model` | string | `hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M` | Refusal-free abliterated ModelFusion model for Google Mantis | ``python rfc_hunt_swarm.py --mantis --repo . --mantis-model hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M`` |
| `--mantis-report` | flag | `False` | Display stored Google Mantis findings from terminator.db | ``python rfc_hunt_swarm.py --mantis --repo . --mantis-report`` |
| `--rea` | flag | `False` | Run Module 21 (morluto/rea) JS/Electron/.asar/source-map & same-origin bundle surface analyzer | ``python rfc_hunt_swarm.py rea --path . --rea`` |
| `--rea-target` | string | `None` | Target JS/Electron/.asar/web bundle path for Module 21 REA | ``python rfc_hunt_swarm.py rea --path . --rea-target .`` |
| `--rea-cli` | flag | `None` | Enable locally installed rea-agents CLI (shell=False; included in --all by default) | ``python rfc_hunt_swarm.py rea --path . --rea-cli`` |
| `--no-rea-cli` | flag | `True` | Disable rea-agents CLI invocation during --all (use embedded Python REA analyzer only) | ``python rfc_hunt_swarm.py --all --repo . --no-rea-cli`` |
| `--no-rea` | flag | `False` | Disable Module 21 REA during --all | ``python rfc_hunt_swarm.py --all --repo . --no-rea`` |
| `--output-dir` | string | `reports` | Output directory for SARIF, JSON, and text audit reports (default: reports) | ``python rfc_hunt_swarm.py --all --repo . --output-dir reports/audit_run`` |
| `--setup`, `--install-tools`, `--provision-tools` | flag | `False` | Inspect and dynamically install ALL required & integrated RFCHunt tools (aiscan, RAPTOR, httpx, katana, nuclei, artex, rea-agents, semgrep, Python deps, Ollama) | ``python rfc_hunt_swarm.py --all --repo . --setup`` |
| `--tool-status`, `--tools-status`, `--check-tools` | flag | `False` | Print installation status across the complete integrated toolchain | ``python rfc_hunt_swarm.py --all --repo . --tool-status`` |
| `--tools` | string | `None` | Optional comma-separated tool IDs for setup/status (e.g. 'aiscan,raptor,httpx,katana,nuclei,rea_agents') | ``python rfc_hunt_swarm.py --setup --tools aiscan,raptor,httpx`` |
| `--include-docker` | flag | `True` | Include Docker container images during tool provisioning (default: True) | ``python rfc_hunt_swarm.py --setup --include-docker`` |
| `--no-docker-tools` | flag | `True` | Skip Docker image pulls during tool provisioning | ``python rfc_hunt_swarm.py --setup --no-docker-tools`` |
| `--no-include-models` | flag | `True` | Skip pulling Ollama AI models during setup and --all auto-provisioning | ``python rfc_hunt_swarm.py --all --repo . --no-include-models`` |
| `--force-install` | flag | `False` | Force reinstall/re-verify cached tools during setup | ``python rfc_hunt_swarm.py --setup --force-install`` |
| `--no-auto-install` | flag | `True` | Disable automatic runtime installation of missing tools | ``python rfc_hunt_swarm.py --all --repo . --no-auto-install`` |
| `--hint` | string | `None` | Inject a live operator steering HINT into the SQLite blackboard | ``python rfc_hunt_swarm.py hint --hint "Focus auth boundaries" --hint example`` |
| `--hint-domain` | string | `global` | Protocol domain scope for --hint (default: global) | ``python rfc_hunt_swarm.py hint --hint "Focus auth boundaries" --hint-domain global`` |
| `--hint-priority` | float | `10.0` | Numeric priority score for --hint (default: 10.0) | ``python rfc_hunt_swarm.py hint --hint "Focus auth boundaries" --hint-priority 10.0`` |
| `--hint-task-id` | string | `default` | Task ID scope for --hint (default: default) | ``python rfc_hunt_swarm.py hint --hint "Focus auth boundaries" --hint-task-id default`` |
| `--hint-rfc` | string | `` | Optional RFC identifier for --hint | ``python rfc_hunt_swarm.py hint --hint "Focus auth boundaries" --hint-rfc example`` |
| `--dispatch`, `--dispatch-config` | string | `None` | Path to unified swarm_dispatch.yaml configuration | ``python rfc_hunt_swarm.py --all --repo . --dispatch example`` |
| `--verification-inversion` | flag | `True` | Enable 6-pass Static Verification-Inversion Auditor (DEV-* loop/panic slicer, Rule-5 trust-closure, Comparator contract diff, Refinement gap, Release/FFI elision, State-machine epoch rollback; default-ON in --all and --deep-audit) | ``python rfc_hunt_swarm.py --all --repo . --verification-inversion`` |
| `--no-verification-inversion` | flag | `True` | Disable Static Verification-Inversion Auditor during --all | ``python rfc_hunt_swarm.py --all --repo . --no-verification-inversion`` |
| `--reseach-num`, `--research-num` | int | `5` | Number of research articles (ArXiv-to-Code) to extract and convert per domain (default: 5) | ``python rfc_hunt_swarm.py --all --repo . --reseach-num 5`` |
| `--skills-num`, `--skill-num` | int | `None` | Number of zero-API last-30-days security & pentesting skills to harvest and convert per domain (defaults to --reseach-num / 5) | ``python rfc_hunt_swarm.py --all --repo . --skills-num 5`` |
| `--arxiv-detect` | flag | `True` | Enable 10 ArXiv-to-Code research-backed security detectors (5 AI Security + 5 App Code Security; default-ON in --all and --deep-audit) | ``python rfc_hunt_swarm.py --all --repo . --arxiv-detect`` |
| `--no-arxiv-detect` | flag | `True` | Disable ArXiv-to-Code research detectors during --all | ``python rfc_hunt_swarm.py --all --repo . --no-arxiv-detect`` |
| `--arxiv-sync` | flag | `False` | Sync and synthesize --reseach-num new research papers with code & GitHub repos from D:\harfile\arixiv-to-code | ``python rfc_hunt_swarm.py --all --repo . --arxiv-sync`` |
| `--arxiv-query` | string | `None` | Custom arXiv search query for --arxiv-sync research-to-code synthesis | ``python rfc_hunt_swarm.py --all --repo . --arxiv-query "auth bypass"`` |
| `--arxiv-rl` | flag | `False` | Optimize synthesized ArXiv-to-Code detector modules using Dream-RSI RL (arXiv:2609.14858) | ``python rfc_hunt_swarm.py --all --repo . --arxiv-rl`` |
| `--arxiv-verify-panel` | flag | `False` | Run ModelFusion Panel-of-Models verification (glm4:9b + qwen2.5:7b -> Judge glm4:9b) on synthesized ArXiv detectors | ``python rfc_hunt_swarm.py --all --repo . --arxiv-verify-panel`` |
| `--arxiv-panel-size` | int | `2` | Number of panelists for --arxiv-verify-panel (default: 2) | ``python rfc_hunt_swarm.py --all --repo . --arxiv-panel-size 2`` |
| `--arxiv-auto-repair` | flag | `True` | Enable iterative Auto-Repair retry loop (Ruff + mypy --strict + 310-property fuzzing + pytest + Ollama patcher; default-ON) | ``python rfc_hunt_swarm.py --all --repo . --arxiv-auto-repair`` |
| `--no-arxiv-auto-repair` | flag | `True` | Disable iterative Auto-Repair retry loop during --arxiv-sync | ``python rfc_hunt_swarm.py --all --repo . --no-arxiv-auto-repair`` |
| `--arxiv-max-repairs` | int | `3` | Maximum auto-repair retry attempts for generated ArXiv detector modules (default: 3) | ``python rfc_hunt_swarm.py --all --repo . --arxiv-max-repairs 3`` |
| `--last30days-skills` | flag | `True` | Enable 10 zero-API last30days-skill security & pentesting detectors (5 AI/Agent Security + 5 App/Web Bug-Bounty; default-ON in --all and --deep-audit) | ``python rfc_hunt_swarm.py --all --repo . --last30days-skills`` |
| `--no-last30days-skills` | flag | `True` | Disable zero-API last30days-skill security detectors during --all | ``python rfc_hunt_swarm.py --all --repo . --no-last30days-skills`` |
| `--last30days-sync` | flag | `False` | Harvest and synthesize --reseach-num zero-API last-30-days security skills from keyless sources (Reddit, HN, GitHub, arXiv, dev.to) | ``python rfc_hunt_swarm.py --all --repo . --last30days-sync`` |
| `--last30days-topic` | string | `None` | Custom topic for --last30days-sync zero-API security skill discovery | ``python rfc_hunt_swarm.py --all --repo . --last30days-topic "auth bypass"`` |
| `--no-call-graph-slice` | flag | `False` | Disable whole-repo call-graph & taint slicing during --all | ``python rfc_hunt_swarm.py --all --repo . --no-call-graph-slice`` |
| `--slice-max-depth` | int | `8` | Maximum call-graph traversal depth for taint slicing (default: 8) | ``python rfc_hunt_swarm.py slice --repo . --slice-max-depth 8`` |
| `--slice-max-slices` | int | `200` | Maximum taint slices to extract (default: 200) | ``python rfc_hunt_swarm.py slice --repo . --slice-max-slices 200`` |
| `--slice-codeql` | flag | `False` | Enable optional CodeQL CLI path extraction in CallGraphSlicer | ``python rfc_hunt_swarm.py slice --repo . --slice-codeql`` |
| `--escalation-fraction` | float | `0.05` | Top high-signal fraction for tiered model escalation (default: 0.05) | ``python rfc_hunt_swarm.py slice --repo . --escalation-fraction 0.05`` |
| `--min-poe-escalation` | int | `1` | Minimum POE level required for tiered model escalation (default: 1) | ``python rfc_hunt_swarm.py --all --repo . --min-poe-escalation 1`` |
| `--frontier-api-opt-in` | flag | `False` | Explicitly opt-in to configured frontier API backend for top escalated candidates (default: False, local-only) | ``python rfc_hunt_swarm.py slice --repo . --frontier-api-opt-in`` |
| `--fuzz-bridge` | flag | `False` | Explicitly enable multi-language isolated container fuzzing bridge in --all | ``python rfc_hunt_swarm.py fuzz-bridge --repo . --fuzz-bridge`` |
| `--no-fuzz-bridge` | flag | `False` | Disable multi-language coverage fuzzing bridge during --all | ``python rfc_hunt_swarm.py --all --repo . --no-fuzz-bridge`` |
| `--fuzz-languages` | string | `None` | Comma-separated languages for fuzzing bridge (rust,cpp,c,python,js,ts,java) | ``python rfc_hunt_swarm.py fuzz-bridge --repo . --fuzz-languages python,rust`` |
| `--fuzz-timeout` | float | `60.0` | Per-target wall timeout in seconds for isolated fuzz container (default: 60.0) | ``python rfc_hunt_swarm.py fuzz-bridge --repo . --fuzz-timeout 60.0`` |
| `--fuzz-max-time` | int | `30` | Max fuzzer run time in seconds inside container (default: 30) | ``python rfc_hunt_swarm.py fuzz-bridge --repo . --fuzz-max-time 30`` |
| `--fuzz-cpp-backend` | choice | `afl++` | C/C++ coverage fuzzer backend (default: afl++) | ``python rfc_hunt_swarm.py fuzz-bridge --repo . --fuzz-cpp-backend afl++`` |
| `--fuzz-dry-run` | flag | `False` | Generate harnesses, seed corpora, and dictionaries without executing Docker containers | ``python rfc_hunt_swarm.py fuzz-bridge --repo . --fuzz-dry-run`` |
| `--docker-parser-matrix` | flag | `False` | Run real local Docker differential parser matrix (nginx, envoy, haproxy, node_undici, go_net_http, rust_hyper) | ``python rfc_hunt_swarm.py docker-doctor --docker-parser-matrix`` |
| `--no-docker-parser-matrix` | flag | `False` | Disable Docker differential parser matrix during --all | ``python rfc_hunt_swarm.py --all --repo . --no-docker-parser-matrix`` |
| `--parsers` | string | `None` | Comma-separated parser names for Docker parser matrix (e.g. nginx,envoy,haproxy,node_undici,go_net_http,rust_hyper) | ``python rfc_hunt_swarm.py --all --repo . --parsers nginx,envoy,haproxy`` |
| `--fallback-4parsers` | flag | `False` | Fall back to offline 4-parser matrix if Docker parser matrix is unavailable | ``python rfc_hunt_swarm.py --all --repo . --fallback-4parsers`` |
| `--sandbox-invariants` | flag | `False` | Explicitly run isolated --network=none container repo security invariants in --all | ``python rfc_hunt_swarm.py sandbox-invariants --repo . --sandbox-invariants`` |
| `--no-sandbox-invariants` | flag | `False` | Disable sandboxed repo invariant runner during --all | ``python rfc_hunt_swarm.py --all --repo . --no-sandbox-invariants`` |
| `--invariant-runtime` | string | `None` | Optional preferred runtime for sandbox invariant runner (python\|node) | ``python rfc_hunt_swarm.py sandbox-invariants --repo . --invariant-runtime python`` |
| `--invariant-image` | string | `None` | Optional explicit OCI image for sandbox invariant runner | ``python rfc_hunt_swarm.py sandbox-invariants --repo . --invariant-image python:3.12-slim`` |
| `--poe-verify` | flag | `False` | Explicitly run containerized non-destructive POE==3 verification on HIGH/CRITICAL findings in --all | ``python rfc_hunt_swarm.py poe-verify --repo . --poe-verify`` |
| `--no-poe-verify` | flag | `False` | Disable containerized POE==3 verification during --all | ``python rfc_hunt_swarm.py --all --repo . --no-poe-verify`` |
| `--drop-unverified-fp` | flag | `False` | Drop unverified false positives downgraded by POE==3 verifier from final findings list | ``python rfc_hunt_swarm.py poe-verify --repo . --drop-unverified-fp`` |
| `--findings-json` | string | `None` | Optional JSON findings file path for standalone `poe-verify` mode | ``python rfc_hunt_swarm.py poe-verify --repo . --findings-json example`` |
| `--refresh-novelty-corpus` | string | `[]` | Explicitly ingest local JSON/YAML/Nuclei catalog paths (or opt-in URLs with --novelty-allow-network) into the novelty corpus | ``python rfc_hunt_swarm.py novelty --refresh-novelty-corpus example`` |
| `--novelty-allow-network` | flag | `False` | Explicitly allow remote HTTP(S) feeds during --refresh-novelty-corpus (default: False, strictly offline) | ``python rfc_hunt_swarm.py novelty --novelty-allow-network`` |
| `--novelty-threshold` | float | `0.72` | Maximum structural similarity threshold below which 3-trial invariant-violating findings are tagged novel (default: 0.72) | ``python rfc_hunt_swarm.py novelty --novelty-threshold 0.72`` |
| `--novelty-export` | string | `None` | Optional output JSON path to export the merged novelty corpus catalog | ``python rfc_hunt_swarm.py novelty --novelty-export config.yaml`` |
| `--swarm` | flag | `False` | Enable full multi-agent parallel Swarm orchestration (--all + --ensemble + --fast-ooda + --swarm-board on repos/folders, parallel target fan-out on --hunt, or 12-agent LangGraph protocol swarm on --host) | ``python rfc_hunt_swarm.py --swarm --repo . --dry-run`` |
| `--swarm-workers` | int | `None` | Bounded concurrent worker count for --swarm target fan-out and parallel CPU checks (1..8) | ``python rfc_hunt_swarm.py --swarm --swarm-workers 4 --repo . --folder ./extra --dry-run`` |
| `--swarm-board` | flag | `False` | Render live pure-CLI Swarm Overview board with color emojis & pipeline graph during --all and OODA Swarm runs (--plain for ASCII, zero GUI) | ``python rfc_hunt_swarm.py --all --repo . --swarm-board`` |
| `--no-swarm-board` | flag | `True` | Disable pure-CLI Swarm Overview board rendering | ``python rfc_hunt_swarm.py --all --repo . --no-swarm-board`` |
| `--emoji` | flag | `None` | Explicitly enable color emoji icons on the Swarm Overview board (auto-enabled on UTF-8 terminals) | ``python rfc_hunt_swarm.py swarm-board --emoji`` |
| `--no-emoji` | flag | `True` | Use geometric Unicode icons instead of color emojis on the Swarm Overview board | ``python rfc_hunt_swarm.py swarm-board --no-emoji`` |
| `--watch` | flag | `False` | Continuously refresh `swarm-board` from SQLite DB until interrupted | ``python rfc_hunt_swarm.py swarm-board --watch`` |
| `--interval` | float | `1.0` | Refresh interval in seconds for `swarm-board --watch` (default: 1.0) | ``python rfc_hunt_swarm.py swarm-board --interval 1.0`` |
| `--board-width` | int | `100` | Column width for pure-CLI Swarm Overview board (default: 100) | ``python rfc_hunt_swarm.py swarm-board --board-width 100`` |
| `--board-events` | int | `15` | Max recent blackboard events shown in `swarm-board` (default: 15) | ``python rfc_hunt_swarm.py swarm-board --board-events 15`` |
| `--serve-ui` | flag | `False` | Launch self-hosted Mission Control Web GUI & full-lifecycle REST/SSE orchestration server (loopback 127.0.0.1:8789 by default) | ``python rfc_hunt_swarm.py --serve-ui --ui-host 127.0.0.1 --ui-port 8789`` |
| `--ui-host` | string | `127.0.0.1` | Bind host for --serve-ui Mission Control server (default: 127.0.0.1) | ``python rfc_hunt_swarm.py ui --ui-host 127.0.0.1`` |
| `--ui-allow-non-loopback` | flag | `False` | Explicitly permit binding --serve-ui on a non-loopback interface | ``python rfc_hunt_swarm.py ui --ui-allow-non-loopback`` |
| `--network-lifecycle` | flag | `False` | Run turnkey multi-target network lifecycle profile (--all + opt-in httpx/katana/nuclei discovery + Dual-Graph + retest) | ``python rfc_hunt_swarm.py --network-lifecycle --host target.example.com --authorized --dry-run`` |
| `--dry-run` | flag | `False` | Universal zero-side-effect dry-run across ALL RFCHunt flags and modes (0 network packets, 0 disk mutations, 0 browser launches, 0 API submissions; prints complete execution & RoE compliance plan) | ``python rfc_hunt_swarm.py --all --repo . --dry-run --json`` |
| `--preflight` | flag | `True` | Execute fresh zero-cache pre-flight stack/PQC/HackerOne/research/safe-skill discovery at start of every --all run (default-ON) | ``python rfc_hunt_swarm.py --all --repo . --preflight`` |
| `--no-preflight` | flag | `True` | Disable Module 23 pre-flight discovery during --all | ``python rfc_hunt_swarm.py --all --repo . --no-preflight`` |
| `--preflight-only` | flag | `False` | Run Module 23 fresh pre-flight discovery standalone and print the Pre-Flight Checklist (Markdown or --json) | ``python rfc_hunt_swarm.py --preflight-only --repo . --json`` |
| `--preflight-live` | flag | `True` | Run fresh keyless live research & OSV.dev exact-version CVE queries during online pre-flight (default-ON; auto-skipped offline/CI/--dry-run) | ``python rfc_hunt_swarm.py --preflight-only --repo . --preflight-live`` |
| `--no-preflight-live` | flag | `True` | Disable live network lookups during pre-flight discovery (local manifest/PQC/skill scan only) | ``python rfc_hunt_swarm.py --all --repo . --no-preflight-live`` |
| `--preflight-pqc` | flag | `True` | Enable Post-Quantum Cryptography (FIPS 203/204/205/XMSS/LMS/Hybrid TLS/HNDL) pre-flight auditor (default-ON) | ``python rfc_hunt_swarm.py --preflight-only --repo . --preflight-pqc`` |
| `--no-preflight-pqc` | flag | `True` | Disable Post-Quantum Cryptography static audit pass during pre-flight | ``python rfc_hunt_swarm.py --all --repo . --no-preflight-pqc`` |
| `--preflight-prompt` | string | `` | Optional user prompt or scope notes included in pre-flight domain/protocol/PQC detection | ``python rfc_hunt_swarm.py --preflight-only --repo . --preflight-prompt "auth bypass"`` |
| `--preflight-skills-dirs` | string | `None` | Comma-separated extra local skill directories to safety-audit and load during pre-flight | ``python rfc_hunt_swarm.py --preflight-only --repo . --preflight-skills-dirs ./reports`` |
| `--no-home-skills` | flag | `False` | Restrict local skill discovery to workspace directories only (skip ~/.claude/skills, ~/.gemini/...) | ``python rfc_hunt_swarm.py --all --repo . --no-home-skills`` |
| `--preflight-timeout` | float | `15.0` | Total live research time budget in seconds for pre-flight keyless queries (default: 15.0) | ``python rfc_hunt_swarm.py --preflight-only --repo . --preflight-timeout 15.0`` |
| `--phi` | flag | `False` | Enable Presidio + GLiNER + RedactX-v3 18 HIPAA Safe Harbor PHI/PII detector & zero-knowledge redactor (standalone or chained into --all) | ``python rfc_hunt_swarm.py --phi --repo . --phi-redact`` |
| `--phi-target` | string | `None` | Explicit file or directory path for --phi scanning (defaults to --repo / --path / '.') | ``python rfc_hunt_swarm.py --phi --phi-target ./records`` |
| `--phi-redact` | flag | `False` | Write zero-knowledge scrubbed copies (`<ZK_PII:TYPE:HASH8>`) with quarantine proofs under reports/phi_redacted/ | ``python rfc_hunt_swarm.py --phi --repo . --phi-redact`` |
| `--phi-model` | string | `urchade/gliner_multi_pii-v1` | GLiNER Span NER model identifier for --phi (default: urchade/gliner_multi_pii-v1) | ``python rfc_hunt_swarm.py --phi --repo . --phi-model urchade/gliner_multi_pii-v1`` |
| `--no-phi-ml` | flag | `False` | Force deterministic offline RedactX-v3 + GLiNER fallback without loading HuggingFace GLiNER or Presidio ML weights | ``python rfc_hunt_swarm.py --phi --repo . --no-phi-ml`` |
| `--stride` | flag | `False` | Generate an advanced Fusion-powered STRIDE, MITRE ATT&CK, Zero Trust, Trust Boundary, Security Requirements & Attack Tree SVG Threat Model (standalone or chained into --all / --ensemble; auto-runs when a codebase lacks a threat model) | ``python rfc_hunt_swarm.py --stride --repo . --dry-run`` |
| `--no-stride` | flag | `False` | Disable automatic STRIDE threat model generation during --all / --ensemble when a repository lacks a threat model | ``python rfc_hunt_swarm.py --all --repo . --no-stride --dry-run`` |
| `--stride-diagram` | string | `[]` | Optional uploaded system architecture diagram (.mmd, .svg, .drawio, .puml, .json, .yaml, .png, .jpg) to include in STRIDE & Trust Boundary analysis (repeatable) | ``python rfc_hunt_swarm.py --stride --repo . --stride-diagram docs/architecture.mmd --dry-run`` |
| `--stride-out` | string | `None` | Output directory for THREAT_MODEL_STRIDE.md, JSON/SARIF, and downloadable SVG architecture/attack-tree diagrams | ``python rfc_hunt_swarm.py --stride --repo . --stride-out reports/stride_threat_model`` |
| `--stride-write-repo` | flag | `False` | Also write THREAT_MODEL.md directly into the target repository root when generating a STRIDE threat model | ``python rfc_hunt_swarm.py --stride --repo ./target_repo --stride-write-repo --dry-run`` |
| `--hackerone`, `--hackone` | flag | `False` | Discover a HackerOne campaign, parse its 3-tier RoE policy, and port verified/deterministic RFCHunt findings into redacted HackerOne report drafts with HITL review | ``python rfc_hunt_swarm.py --hackerone --hackerone-program anthropic --dry-run`` |
| `--hackerone-auto`, `--hackone-auto` | flag | `False` | Policy-aware autonomous HackerOne workflow: after human login, discovers open campaigns, enforces RoE rules/Safe Harbor, audits in-scope repos (--all + --phi), and pre-fills drafts up to final human Submit | ``python rfc_hunt_swarm.py --hackerone-auto --hackerone-max-programs 2 --dry-run`` |
| `--hackerone-username`, `--hackone-username` | string | `` | Researcher HackerOne username for program-mandated attribution headers (e.g. X-HackerOne: <username>) | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-username researcher`` |
| `--hackerone-program`, `--hackone-program` | string | `None` | Target HackerOne program handle (e.g. 'anthropic-vdp') | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-program example`` |
| `--hackerone-query`, `--hackone-query` | string | `` | Search keyword for HackerOne campaign discovery | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-query "auth bypass"`` |
| `--hackerone-max-programs` | int | `2` | Max campaigns to inspect per --hackerone-auto run (default: 2) | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-max-programs 2`` |
| `--hackerone-policy-file` | string | `None` | Optional local policy text file for offline RoE compliance evaluation & dry-run testing | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-policy-file config.yaml`` |
| `--hackerone-ai-disclosure` | flag | `False` | Include explicit RFCHunt research-assistance & manual PoC verification disclosure section in drafts | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-ai-disclosure`` |
| `--hackerone-browser`, `--hackone-browser` | flag | `False` | Launch visible HITL Playwright browser session for HackerOne login (human completes 2FA/CAPTCHA) and report form pre-fill (stops before final Submit) | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-browser`` |
| `--hackerone-api`, `--hackone-api` | flag | `False` | Query HackerOne Hacker API v1 for live campaign/scope/policy discovery using HACKERONE_API_USERNAME and HACKERONE_API_TOKEN | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-api`` |
| `--hackerone-submit-api` | flag | `False` | Explicit opt-in to submit eligible drafts via HackerOne API v1 after interactive HITL confirmation | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-submit-api`` |
| `--hackerone-bounties-only` | flag | `False` | Filter HackerOne API campaign discovery to paid bounty programs only | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-bounties-only`` |
| `--hackerone-min-severity` | choice | `medium` | Minimum severity eligible for HackerOne porting (default: medium) | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-min-severity low`` |
| `--hackerone-max-reports` | int | `5` | Maximum eligible drafts to generate per run (default: 5) | ``python rfc_hunt_swarm.py --hackerone --dry-run --hackerone-max-reports 5`` |
| `--crlf-desync`, `--crlf-conformance` | flag | `False` | Run Module 24 static Nginx/OpenResty $uri config audit and safe 3-trial RFC 9112 header conformance checks | ``python rfc_hunt_swarm.py --crlf-desync --repo . --json`` |
| `--web-llm` | flag | `False` | Run Module 25 static Web LLM security auditor (excessive agency, tool-arg taint, insecure output handling, prompt-only authz, RAG scrubbing) | ``python rfc_hunt_swarm.py --web-llm --repo . --json`` |
| `--workspace-root` | string | `None` | Explicit workspace root directory for strict file_path/target_path confinement | ``python rfc_hunt_swarm.py --all --repo . --workspace-root .`` |
| `--pe-audit`, `--pe-dotnet` | flag | `False` | Run PE & .NET Code Integrity Anomaly Auditor (Magika hybrid PE, CVE-2026-108398, UMCI/SEC_COMMIT fallback, YARA, KB5127694/VirtualBox host patch audit) | ``python rfc_hunt_swarm.py --pe-audit --repo . --json`` |
| `--no-pe-audit`, `--no-pe-dotnet` | flag | `False` | Disable PE & .NET Code Integrity Anomaly Auditor during --all | ``python rfc_hunt_swarm.py --all --repo . --no-pe-audit`` |
| `--pe-include-host-audit` | flag | `None` | Include Windows KB5127694 & VirtualBox 7.2.18+ host patch audit during --all / --pe-audit | ``python rfc_hunt_swarm.py --pe-audit --repo . --pe-include-host-audit`` |
| `--pe-no-host-audit` | flag | `True` | Disable host patch-level audit during --pe-audit | ``python rfc_hunt_swarm.py --pe-audit --repo . --pe-no-host-audit`` |
| `--pe-no-yara` | flag | `True` | Disable defensive YARA rule evaluation during PE & .NET auditing | ``python rfc_hunt_swarm.py --pe-audit --repo . --pe-no-yara`` |
| `--ensemble`, `--essemble`, `--essample` | flag | `False` | Enable Planner-Worker-Verifier shared-whiteboard + Lean 4 formal ensemble orchestration in --all | ``python rfc_hunt_swarm.py --all --ensemble --repo . --program generic --quorum 2`` |
| `--program` | string | `generic` | Vendor threat-model profile for --ensemble (generic, shopify, anthropic, arc-bbp, cloudflare, coinbase) | ``python rfc_hunt_swarm.py --all --ensemble --repo . --program anthropic`` |
| `--freshness-hours` | int | `72` | Git commit freshness lookback window in hours for --ensemble (default: 72) | ``python rfc_hunt_swarm.py --all --ensemble --repo . --freshness-hours 72`` |
| `--quorum` | int | `2` | Minimum independent engine quorum for static corroboration in --ensemble (default: 2) | ``python rfc_hunt_swarm.py --all --ensemble --repo . --quorum 2`` |
| `--embedded`, `--embeded` | flag | `False` | Run --ensemble strictly in-process offline without spawning external scanner subprocesses | ``python rfc_hunt_swarm.py --all --ensemble --repo . --embedded --no-llm`` |
| `--no-llm` | flag | `False` | Disable optional LLM semantic verification layer in --ensemble | ``python rfc_hunt_swarm.py --all --ensemble --repo . --no-llm`` |
| `--gha-only` | flag | `False` | Restrict --ensemble local engine fan-out to GitHub Actions workflow scanners | ``python rfc_hunt_swarm.py --all --ensemble --repo . --gha-only`` |
| `--package-client` | string | `None` | Optional client organization name to emit 5-file ClientAuditPackager bundle in --ensemble | ``python rfc_hunt_swarm.py --all --ensemble --repo . --package-client "Acme Corp"`` |
| `--start-modelfusion` | flag | `False` | Auto-start local ModelFusion (:5000) server with VRAM-gated abliterated open-weight models and Anti-Junk & Grounding Guards before scanning | ``python rfc_hunt_swarm.py --all --repo . --start-modelfusion --dry-run`` |
| `--fast-ooda` | flag | `False` | Run the 3-Stage Parallel OODA Funnel (Stage 1 CPU SQLite WAL Blackboard -> Stage 2 ACDSO Pareto AutoML -> Stage 3 Abliterated Consensus behind OllamaConcurrencyGuard) standalone or chained into --all | ``python rfc_hunt_swarm.py --fast-ooda --repo . --embedded --json`` |
| `--cpu-workers` | int | `None` | Bounded ProcessPoolExecutor CPU workers for --fast-ooda / --ensemble (default: clamped 2..8) | ``python rfc_hunt_swarm.py --fast-ooda --repo . --cpu-workers 4 --embedded`` |
| `--blackboard-db` | string | `None` | SQLite WAL Blackboard database path for --fast-ooda / --ensemble | ``python rfc_hunt_swarm.py --fast-ooda --repo . --blackboard-db reports/blackboard.sqlite3`` |
| `--resume` | flag | `False` | Recover stale IN_PROGRESS intents from SQLite WAL Blackboard before running --fast-ooda / --ensemble | ``python rfc_hunt_swarm.py --fast-ooda --repo . --resume --embedded`` |
| `--signal-score` | float | `0.0` | HackerOne Signal score for two-lane scheduling in --fast-ooda / --hunt (default: 0.0) | ``python rfc_hunt_swarm.py --fast-ooda --repo . --signal-score 1.5 --embedded`` |
| `--hunt` | flag | `False` | Run the turnkey autonomous RFCHunt + ModelFusion bug bounty pipeline (syncs directory, ranks unlocked programs via ACDSO ML, runs freshness-watch, fast-ooda, ensemble-audit, Lean 4, QA-drafts & HITL Chrome handoff; omit for regular pentesting) | ``python rfc_hunt_swarm.py --hunt --hunt-url https://hackerone.com/opportunities/all --dry-run`` |
| `--hunt-target` | string | `[]` | Local repository or folder directory to audit during --hunt (repeatable; --target / --repo / --folder / --dir / --path also supported) | ``python rfc_hunt_swarm.py --hunt --hunt-target ./target_repo --program common_codes --once --dry-run`` |
| `--hunt-repo` | string | `[]` | Extra 'owner/repo' GitHub slug or local repo to include during --hunt (repeatable) | ``python rfc_hunt_swarm.py --hunt --hunt-repo Shopify/shopify-app-js --once --dry-run`` |
| `--clone-unlocked` | flag | `False` | Also shallow-clone and hunt UNLOCKED watchlist/EligibilityDB repos alongside local --repo / --folder / --target scans during --hunt | ``python rfc_hunt_swarm.py --hunt --repo ./my_repo --folder ./my_folder --clone-unlocked --dry-run`` |
| `--no-clone-unlocked` | flag | `False` | Audit only explicitly passed local --repo / --folder / --target paths during --hunt without cloning additional unlocked watchlist repos | ``python rfc_hunt_swarm.py --hunt --repo ./my_repo --folder ./my_folder --no-clone-unlocked --once --dry-run`` |
| `--sync-public-directory` | flag | `False` | Refresh public HackerOne Program Directory sorted by newest launch date before ML ranking during --hunt | ``python rfc_hunt_swarm.py --hunt --sync-public-directory --min-efficiency 80 --dry-run`` |
| `--eligibility-db` | string | `None` | Optional ProgramEligibilityDB SQLite path for --hunt / --all | ``python rfc_hunt_swarm.py --hunt --eligibility-db reports/program_eligibility.sqlite3 --dry-run`` |
| `--min-efficiency` | float | `80.0` | Minimum HackerOne response efficiency %% during --hunt (default: 80.0) | ``python rfc_hunt_swarm.py --hunt --min-efficiency 85 --dry-run`` |
| `--portfolio-capacity` | int | `6` | Daily Two-Phase Knapsack portfolio capacity during --hunt (default: 6) | ``python rfc_hunt_swarm.py --hunt --portfolio-capacity 6 --dry-run`` |
| `--max-repos` | int | `4` | Maximum unlocked watchlist repos to audit per --hunt cycle (default: 4) | ``python rfc_hunt_swarm.py --hunt --max-repos 4 --dry-run`` |
| `--watchlist` | string | `None` | Optional custom JSON watchlist path for --hunt (omitting uses UNLOCKED ProgramEligibilityDB repos) | ``python rfc_hunt_swarm.py --hunt --watchlist config/freshness_watchlist.example.json --dry-run`` |
| `--interval-minutes` | float | `60.0` | Minutes between continuous --hunt cycles (default: 60.0) | ``python rfc_hunt_swarm.py --hunt --interval-minutes 60 --max-cycles 2`` |
| `--max-cycles` | int | `0` | Stop --hunt after N cycles (0 = run continuously unless --once or --dry-run) | ``python rfc_hunt_swarm.py --hunt --max-cycles 1 --headless-only`` |
| `--once` | flag | `False` | Run a single complete --hunt cycle and exit | ``python rfc_hunt_swarm.py --hunt --once --headless-only`` |
| `--hunt-url`, `--bug-hunt-url` | string | `None` | Official bug bounty directory or program URL opened in Chromium by --hunt so you log in and RFCHunt runs every /browser workflow automatically (default: https://hackerone.com/opportunities/all) | ``python rfc_hunt_swarm.py --hunt --hunt-url https://hackerone.com/opportunities/all --dry-run`` |
| `--browser-hunt` | flag | `False` | Explicitly enable interactive browser hunt on --hunt-url (auto-enabled by --hunt unless --headless-only, --embedded, or --no-browser-hunt is set) | ``python rfc_hunt_swarm.py --hunt --browser-hunt --hunt-url https://hackerone.com/opportunities/all --dry-run`` |
| `--no-browser-hunt` | flag | `False` | Disable opening --hunt-url in interactive browser mode during --hunt | ``python rfc_hunt_swarm.py --hunt --no-browser-hunt --once --dry-run`` |
| `--browser-profile` | string | `None` | Persistent Chromium profile directory for --hunt so your bug bounty login persists across cycles (default: out/autonomous_hunt/h1_browser_profile) | ``python rfc_hunt_swarm.py --hunt --browser-profile out/autonomous_hunt/h1_browser_profile --dry-run`` |
| `--cdp-url` | string | `None` | Attach --hunt to an already-signed-in Chrome or HugOS Browser CDP endpoint (e.g. http://127.0.0.1:9222) | ``python rfc_hunt_swarm.py --hunt --cdp-url http://127.0.0.1:9222 --dry-run`` |
| `--login-timeout` | float | `300.0` | Maximum seconds --hunt waits for you to complete login, 2FA, and any CAPTCHA directly in the browser (default: 300.0) | ``python rfc_hunt_swarm.py --hunt --login-timeout 180 --dry-run`` |
| `--probe-report-id` | int | `4243972` | HackerOne report ID probed read-only during --hunt to check live account cooldown (`can_submit_draft?`, default: 4243972) | ``python rfc_hunt_swarm.py --hunt --probe-report-id 4243972 --dry-run`` |
| `--dedup-db` | string | `None` | SQLite WAL database path persisting processed target SHAs and drafted/submitted findings to eliminate duplicates (default: <out>/hunt_state.sqlite3) | ``python rfc_hunt_swarm.py --hunt --dedup-db out/autonomous_hunt/hunt_state.sqlite3 --dry-run`` |
| `--force-rescan` | flag | `False` | Re-scan targets during --hunt even if their current commit SHA or folder digest is already recorded in SQLite (duplicate drafts stay blocked) | ``python rfc_hunt_swarm.py --hunt --repo ./target_repo --force-rescan --once --dry-run`` |
| `--no-stage-drafts` | flag | `False` | During --hunt, skip opening /reports/new or saving drafts on HackerOne while keeping browser discovery, scanning, and SQLite dedup active | ``python rfc_hunt_swarm.py --hunt --hunt-url https://hackerone.com/anthropic --no-stage-drafts --once --dry-run`` |
| `--headless-only` | flag | `False` | During --hunt, skip browser login/discovery, draft staging, and Chrome launch; write READY_TO_CLICK_SUBMIT.md only | ``python rfc_hunt_swarm.py --hunt --once --headless-only --embedded`` |
| `--allow-blocked` | flag | `False` | Allow Signal-blocked programs for local offline research during --hunt | ``python rfc_hunt_swarm.py --hunt --target ./repo --program shopify --allow-blocked --once --dry-run`` |
| `--install-schedule` | flag | `False` | Install recurring native OS schedule for `rfc_hunt_swarm.py --hunt --once` (zero Registry/PATH mutation) | ``python rfc_hunt_swarm.py --hunt --install-schedule --interval-minutes 60 --dry-run`` |
| `--uninstall-schedule` | flag | `False` | Remove the recurring native OS schedule for --hunt | ``python rfc_hunt_swarm.py --hunt --uninstall-schedule --task-name RFCHunt-Autonomous-Defensive-Hunt`` |
| `--run-now` | flag | `False` | Trigger an immediate scheduled task run right after --hunt --install-schedule | ``python rfc_hunt_swarm.py --hunt --install-schedule --run-now --dry-run`` |
| `--task-name` | string | `RFCHunt-Autonomous-Defensive-Hunt` | OS Scheduled Task name for --hunt --install-schedule | ``python rfc_hunt_swarm.py --hunt --install-schedule --task-name RFCHunt-Nightly --dry-run`` |
