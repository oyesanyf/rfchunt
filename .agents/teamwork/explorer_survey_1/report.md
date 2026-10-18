# Exhaustive Protocol & Framing Architectural Survey Report
**Agent**: Explorer Survey 1 (Protocol & Framing Focus)  
**Date**: 2026-10-18  
**Repository**: `D:\harfile\rfchunt`  
**Target Specifications**: IETF RFC 9112, RFC 9110, RFC 9113, RFC 7230, RFC 2616, RFC 8446, RFC 3986  

---

## 1. Executive Summary

This report delivers an exhaustive architectural survey of the protocol research engine and framing validation suite in `D:\harfile\rfchunt`. The system implements specification-grounded autonomous network protocol research inspired by James Kettle's PortSwigger DEF CON 34 research (*Can AI Do Novel Security Research?*, October 2026) and Google Research's *Harness²: Recursive Agent Harnessing for an Open World* (Xu et al., arXiv:2610.14224, 2026).

Key findings of this survey:
1. **The 16 Protocol Modules**: The architecture comprises 16 discrete research modules organized across `engine/`, `tests/`, and root orchestrators. Modules 1–12 provide the core specification extraction, multi-armed bandit scheduling, differential parsing, persistent TCP sequencing, metamorphic testing, delta-debugging, and defensive arm publishing. Modules 13–16 extend the system into offline world simulation (Dream-RSI), adversary emulation (MITRE Caldera), autonomous application security testing (RAPTOR), and recursive agent harnessing (Google Research Harness²).
2. **Protocol ABNF Extraction**: RFC 5234-compliant Augmented Backus-Naur Form (ABNF) parsing operates in `engine/abnf_engine.py`, mapping normative rules from RFC 9112, 9110, 9113, 7230, and 2616 into boundary-inverting test payloads (e.g. OWS/BWS control character injections, pre-colon whitespace, obs-fold, chunk extension corruption, and Transfer-Encoding mutations).
3. **3-Step Pipelined Canary Evaluation**: Implemented in `engine/sequence_engine.py` over persistent TCP/TLS sockets. It executes `REQ 1` (clean baseline), `REQ 2` (candidate boundary probe), and `REQ 3` (unique canary token probe). It enforces strict response frame consumption via `HTTPFramingReader` (RFC 9112 §6), guards against scanner artifacts (residual baseline HTML bytes), and distinguishes true pipeline leaks from RFC 9112 §6.1 un-framed body omissions.
4. **3-Trial Protocol Research Reproducibility Invariant**: Governed by `DeltaDebugger` (`engine/delta_debugger.py`), `MerkleAuditTrail` (`engine/merkle_audit.py`), and `CausalAnomalyClassifier` (`engine/causal_classifier.py`). Any transient anomaly failing 3 consecutive verification trials or achieving < 60% reproduction rate is automatically downgraded to `ImpactClass.NON_REPRODUCIBLE_TRANSIENT`.
5. **Protocol Ruler Calibration**: Implemented in `protocol_ruler.py` and validated in `test_protocol_ruler.py`. Pinpoints backend header buffer limits (e.g. 64,040 bytes) down to single-byte resolution using binary search over raw TCP sockets, measuring front-end byte expansion ($\Delta > 0$), contraction ($\Delta < 0$), or verbatim transmission ($\Delta = 0$) without requiring header reflection.
6. **4-Parser Differential Matrix**: Defined in `engine/differential_oracle.py`, deploying four independent reference parsers (`StrictRFC7230Parser`, `PermissiveLegacyParser`, `CDNProxyParser`, and `AsyncMicroserviceParser`) to evaluate metamorphic divergences offline.
7. **Module 16 (Google Research Harness²)**: Defined in `engine/harness2_engine.py`, providing recursive agent harness self-improvement across the 8-component `c1..c8` surface (`RFCHUNT_SURFACE`), enforcing exact budget identities ($R = 4k$ rollouts, $P = 3k$ improvement stages) across `parallel` (`agg`) and `sequential` (`seq`) modes, and persisting domain experience libraries (`INDEX.md`, `EXPERIENCE.md`).

---

## 2. Exhaustive Survey of the 16 Protocol Research Modules

| Module # | Module Name | Primary Source File | Key Classes & Interfaces | Core Responsibilities & Mechanisms |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **ABNF Grammar Inversion Engine** | `engine/abnf_engine.py` | `ABNFGrammarEngine` | Extracts formal ABNF rules via regex matching (`ABNF_RULE_REGEX`); preloads canonical RFC 9112 rules (`OWS`, `RWS`, `BWS`, `obs-fold`, `chunk-ext`, `header-field`, `request-line`, `transfer-coding`); synthesizes boundary-violating mutations. |
| **2** | **Context-Free Generator & Bandit Scheduler** | `probe_generator.py`, `engine/bandit_scheduler.py` | `ProbeGenerator`, `AdaptiveBanditScheduler`, `BanditArmStats`, `GeneticIndividual` | Context-free probe synthesis using micro-inspiration fragments without buzzwords; UCB1 & $\epsilon$-greedy multi-armed bandit arm selection across 8 mutation families; genetic breeding pool with header crossover and point mutation. |
| **3** | **RFC Semantic Constraint Compiler** | `engine/semantic_compiler.py` | `SemanticConstraintCompiler`, `SpecificationAssertion` | Scans RFC texts for RFC 2119 imperative keywords (`MUST`, `MUST NOT`, `SHALL`, `SHOULD`); precompiles executable wire assertions for RFC 9112 §5.1 (pre-colon whitespace), §6.1 (duplicate conflicting CL), and §6.3 (TE/CL coexistence). |
| **4** | **Differential Oracle & 4-Parser Matrix** | `engine/differential_oracle.py` | `MultiImplementationDifferentialOracle`, `StrictRFC7230Parser`, `PermissiveLegacyParser`, `CDNProxyParser`, `AsyncMicroserviceParser` | Dispatches probes to live target endpoints or offline to the 4-parser reference matrix; detects divergence across status codes, socket states, and connection headers; generates `ImplementationAnomaly` records. |
| **5** | **Stateful Protocol Sequence Engine** | `engine/sequence_engine.py` | `StatefulProtocolSequenceEngine`, `SequenceStepResult`, `SequenceExecutionReport` | Choreographs multi-request stateful sequences on persistent TCP/TLS sockets (`run_pipelined_canary_sequence`, `run_cl0_canary_sequence`); detects queue poisoning, timeout desync, and residual byte leakage. |
| **6** | **RFC Evolution & Errata Tracker** | `engine/errata_tracker.py` | `RFCEvolutionTracker`, `SpecificationShift` | Catalogs historical specification shifts from RFC 2616 to RFC 7230 and RFC 9112 (obs-fold, pre-colon whitespace, TE/CL conflicts, duplicate CL, chunk extensions); attributes parser anomalies to legacy leniency. |
| **7** | **Metamorphic Testing Engine** | `engine/metamorphic_engine.py` | `MetamorphicTestingEngine`, `MetamorphicRelation` | Evaluates metamorphic invariants without golden reference: `MR-HEADER-CASE` (field name casing invariance), `MR-OWS-EQUIVALENCE` (tab vs space in OWS), and `MR-CHUNK-SLICING` (subdividing chunk transfer blocks). |
| **8** | **Delta-Debugging Engine & Minimizer** | `engine/delta_debugger.py` | `DeltaDebugger` | Applies hierarchical binary delta-debugging (header line elimination, body chunk trimming) to minimize anomalous probes to MRE; enforces the 3-trial stability requirement before vulnerability promotion. |
| **9** | **Causal Anomaly & Novelty Classifier** | `engine/causal_classifier.py` | `CausalAnomalyClassifier` | Counterfactual causal attribution; filters environmental socket noise (port exhaustion, reset drops); detects framing artifacts (unconsumed baseline HTML, client framing omission); classifies genuine novelty. |
| **10** | **Cross-Protocol Boundary Analyzer** | `engine/boundary_analyzer.py` | `CrossProtocolBoundaryAnalyzer`, `CrossBoundaryTestVector` | Investigates translation anomalies at protocol boundaries: H2-to-H1 downgrade (CRLF in `:path`, CL/DATA mismatch), WebSocket premature tunnel upgrade, and HTTP-to-SMTP command encapsulation. |
| **11** | **Research Knowledge Graph** | `engine/knowledge_graph.py` | `ResearchKnowledgeGraph`, `GraphNode`, `GraphEdge` | Bipartite directed SQLite knowledge graph connecting RFC specifications, sections, grammar tokens, requirements, test events, anomalies, and vulnerabilities; calculates specification coverage and blind spots. |
| **12** | **Defensive Intelligence Publisher** | `engine/defensive_publisher.py` | `DefensiveIntelligencePublisher` | Transforms verified vulnerabilities into Arm 106 defensive hardening rules (Rust parser guards, Suricata/Snort signatures, ModSecurity WAF rules) and Arm 107 regression test suites (`test_octo_arm107_...`). |
| **13** | **Open-Dream-RSI World Model** | `engine/dream_world_model.py`, `engine/dream_rsi_optimizer.py`, `engine/dream_policy_store.py` | `ProtocolWorldModel`, `DreamRSIOptimizer`, `DreamPolicyStore`, `WorldModelTrajectory` | In-memory off-policy Markov Decision Process (MDP) simulator; replays historical executions from `terminator.db`; simulates protocol state transitions and predicts desync risk for offline policy optimization. |
| **14** | **MITRE Caldera Adversary Export** | `engine/caldera_bridge.py` | `CalderaBridge` | Maps protocol vulnerabilities into non-MITRE Caldera tactics (`protocol-framing`, `queue-poisoning`, `metamorphic-divergence`, `parser-differential`) and techniques (`RFC-9112-DESYNC`, `RFC-9113-MULTIPLEX`); exports plugin structure and pushes to Caldera REST API. |
| **15** | **RAPTOR Autonomous Framework** | `engine/raptor_integrator.py` | `RaptorIntegrator` | Integrates RAPTOR (Evron, Cuthbert, Dullien); runs containerized Semgrep, CodeQL, and local Ollama (`fenkohq/foundation-sec-8b:latest`) agentic triage; correlates source code defects with wire desync anomalies in `terminator.db`. |
| **16** | **Google Research Harness² Engine** | `engine/harness2_engine.py` | `Harness2ProtocolEngine`, `SurfaceSpec`, `Ledger`, `Library`, `BudgetError` | Two-level recursive agent harnessing (Xu et al., 2026); edits `c1..c8` surface (`RFCHUNT_SURFACE`); enforces $R = 4k$ rollouts and $P = 3k$ stages ledger identity in `parallel` (`agg`) and `sequential` (`seq`) modes; persists domain experience libraries (`INDEX.md`, `EXPERIENCE.md`). |

---

## 3. Protocol ABNF Grammars & Specification Lineage

### 3.1 Targeted RFC Specifications
The system tracks and extracts formal grammar across 5 foundational HTTP/intermediary specifications:
1. **RFC 9112 (HTTP/1.1 Message Syntax and Framing, June 2022)**:
   - Line Terminators (§2.2): Mandates `CRLF` (`\r\n`). Recommends recipient leniency for bare `LF` on start-line, but strictly forbids bare `CR`.
   - Field Syntax (§5.1): `field-name ":" OWS field-value OWS`. Mandates rejection with `400 Bad Request` if whitespace precedes the colon.
   - Obsolete Line Folding (§5.2): `obs-fold = CRLF 1*( SP / HTAB )`. Mandates that servers MUST reject incoming requests containing obs-fold with `400 Bad Request`.
   - Message Length (§6.1, §6.3): If `Transfer-Encoding` is present, it overrides `Content-Length`. Multiple differing `Content-Length` headers MUST be rejected with `400 Bad Request`. Un-framed message bodies have length 0.
   - Chunked Transfer Coding (§7.1): `chunk-ext = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )`. Servers MUST parse and ignore unrecognized extensions; invalid syntax MUST be rejected.
2. **RFC 9110 (HTTP Semantics, June 2022)**:
   - Intermediary routing (§6.3) and connection-specific headers (`Connection: close`, `keep-alive`, `Upgrade`).
   - Authority and Host identification (§7.2): Rules for parsing `Host: [uri-host]`.
   - Status code semantics (§15): Non-body status codes (1xx, 204, 304).
3. **RFC 7230 (HTTP/1.1 Message Syntax and Routing, June 2014 - Predecessor Standard)**:
   - Defines the standard implemented by many active reverse proxies and load balancers (AWS ALB, Nginx, Envoy, Cloudflare).
   - Differences with RFC 9112 (e.g. obs-fold leniency in legacy configurations, handling of whitespace around colons) are the primary source of intermediary desynchronization.
4. **RFC 2616 (Hypertext Transfer Protocol -- HTTP/1.1, June 1999 - Historic Standard)**:
   - Historic baseline: Tolerated line folding, allowed ambiguous pre-colon whitespace, and had permissive multipart/byteranges handling (§19.2, §19.4.6).
5. **RFC 9113 (HTTP/2, June 2022) & RFC 7540**:
   - Section 8: Gateway translation rules from HTTP/2 binary frames to HTTP/1.1 streams.
   - Prohibits CR, LF, or NUL in pseudo-headers (`:path`, `:authority`, `:method`) and header values. Violations trigger `H2.CL` and `H2.TE` request smuggling when translated to backend HTTP/1.1 streams.

### 3.2 ABNF Inversion Mutation Mechanics (`engine/abnf_engine.py`)
`ABNFGrammarEngine.generate_inversions(rule_name)` synthesizes concrete wire-level inverted payloads:
- **`OWS` / `BWS` Inversions**: Bare vertical tab (`\x0b`), null byte (`\x00`), Unicode non-breaking space (`\xc2\xa0`), solo carriage return (`\r`), solo line feed (`\n`).
- **`header-field` Inversions**: Pre-colon space (`X-Custom-Header : ...`), pre-colon tab (`X-Custom-Header\t: ...`), obs-fold LF space (`fold\n continuing`), obs-fold CRLF tab (`fold\r\n\tcontinuing`), embedded null in name (`X-Cust\x00om:`), duplicate colon (`::`).
- **`chunk-ext` Inversions**: Standalone empty semicolon (`;\r\n`), unclosed quote in parameter (`;name="unclosed`), null byte in parameter (`;ext\x00=value`), 2048-byte runaway padding, double semicolon (`;;key=val`).
- **`obs-fold` Inversions**: Standalone `\r\n `, multiple tabs `\r\n\t\t\t`, CR-only space `\r `, LF-only space `\n `.
- **`transfer-coding` / `transfer-encoding` Inversions**: Mixed case `cHuNkEd`, double whitespace `Transfer-Encoding:  chunked`, space after value `chunked `, comma prefix `,chunked`, dual `identity, chunked`, illegal token `chunked, cow`.

---

## 4. 3-Step Pipelined Canary Evaluation & Reproducibility Invariant

### 4.1 Pipelined Canary Sequence Execution (`engine/sequence_engine.py`)
The pipelined canary sequence probes persistent TCP/TLS sockets to prove state contamination directly:
```
[Client Socket] ─── Step 1: REQ 1 (Clean Baseline) ───> [Target Server]
                <─── HTTP/1.1 200 OK (Keep-Alive) ───────
[Client Socket] ─── Step 2: REQ 2 (Candidate Probe) ───> [Target Server]
                <─── Response (or Hanging Socket) ────────
[Client Socket] ─── Step 3: REQ 3 (Canary Check) ───────> [Target Server]
                <─── Evaluates Contamination/Leak ───────
```

1. **Step 1 (REQ 1 - Baseline)**:
   - Request: `GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n`.
   - Read via `HTTPFramingReader.read_response`.
   - Invariant: Response must be complete (`is_complete == True`) and persistent (`is_connection_closed == False`). If the server closes the connection or fails to parse, the sequence aborts cleanly.
2. **Step 2 (REQ 2 - Candidate Probe)**:
   - Sends the candidate mutation or desync probe.
   - Reads response via `HTTPFramingReader.read_response(sock, initial_bytes=framed1.unconsumed_bytes)`.
   - **Scanner Artifact Guard**: If `resp2` contains residual baseline HTML body bytes from Step 1, it is classified as a scanner artifact, avoiding false positive reporting.
   - **Timeout-Based Desync Check**: If the target hangs ($\ge 85\%$ of socket timeout) on a probe containing `Content-Length` or `Transfer-Encoding` while Step 1 was fast ($< 1.2\text{s}$), flags timeout-based desynchronization (`CL.TE`, `TE.CL`, or `CL.0`).
   - **Connection Teardown Guard**: If the server terminates the socket (`framed2.is_connection_closed == True`), Step 3 records connection closure as expected HTTP error behavior, not a leak.
3. **Step 3 (REQ 3 - Canary Request)**:
   - Generates unique token: `canary_token = f"CANARY_{random.randint(10000, 99999)}"`.
   - Request: `GET /check_{canary_token} HTTP/1.1\r\nHost: {host}\r\nX-Canary-ID: {canary_token}\r\nConnection: keep-alive\r\n\r\n`.
   - Evaluates response:
     - **Normal Route**: Server returns `404 Not Found` for `/check_{canary_token}` $\rightarrow$ clean state.
     - **Client Framing Omission Analysis**: If Step 3 returns `400 Bad Request` but the candidate probe contained an un-framed body without `Content-Length` or `Transfer-Encoding`, RFC 9112 §6.1 dictates body length is 0. Trailing bytes on the socket triggered the 400 $\rightarrow$ conforming HTTP rejection, NOT a pipeline leak.
     - **Direct Queue Desynchronization**: If `terminator_marker` or `x-smuggle` appears in the canary response $\rightarrow$ confirmed stateful queue desynchronization.

### 4.2 3-Trial Protocol Research Reproducibility Invariant
Governed across three layers:
1. **Delta-Debugging Execution (`engine/delta_debugger.py:45-66`)**:
   - `effective_trials = max(3, max_verification_trials)` (guaranteeing $\ge 3$ repeated trials).
   - If `successes < 3` or `repro_rate < 0.60`, the finding is automatically downgraded:
     ```python
     impact = ImpactClass.NON_REPRODUCIBLE_TRANSIENT
     provenance.append("Downgraded to NonReproducibleTransient: Failed minimum 3-trial stability requirement.")
     ```
2. **Causal Classification Gate (`engine/causal_classifier.py:113-115`)**:
   - Requires `vuln.reproducibility_rate >= 0.66` before allowing promotion to confirmed vulnerability.
3. **Cryptographic Merkle Audit Trail (`engine/merkle_audit.py`)**:
   - Every audit leaf records `reproducibility_rate`, `verification_attempts`, `successful_reproductions`, and status (`CONFIRMED_VULNERABILITY` vs `NON_REPRODUCIBLE_TRANSIENT`).

---

## 5. Protocol Ruler Binary Search Calibration Logic

### 5.1 Physical Micrometer Principle
Web servers enforce strict buffer limits on incoming request headers ($L_{\text{base}}$, e.g. 64,040 bytes). Exceeding this limit triggers `400 Bad Request` or `431 Request Header Fields Too Large`. When an intermediary reverse proxy expands or contracts characters, the backend receives a shifted total header length:
$$\Delta = L_{\text{base}} - L_{\text{mutated}}$$
- $\Delta > 0$: Front-end **EXPANDED** the sequence by $\Delta$ bytes.
- $\Delta < 0$: Front-end **STRIPPED/CONTRACTED** the sequence by $|\Delta|$ bytes.
- $\Delta = 0$: Passed through verbatim.

### 5.2 Algorithm Implementation (`protocol_ruler.py`)
1. **Coarse Bracket Search**:
   - Probes stepped brackets: `[1024, 2048, 4096, 8192, 16384, 32768, 64000, 64040, 65536, 98304, 131072]`.
   - Constructs requests with `padding_len` bytes in header `A: AAAA...`.
   - Locates bracket $[low, high]$ where $low \rightarrow 200\text{ OK}$ and $high \rightarrow 400/431/\text{Drop}$.
2. **Single-Byte Binary Search**:
   ```python
   left, right, last_ok = low, high, low
   while left <= right:
       mid = (left + right) // 2
       req = _build_request(mid)
       code, resp, lat = self.send_probe(req)
       if not self.is_error_boundary(code):
           last_ok = mid
           left = mid + 1
       else:
           right = mid - 1
   limit = last_ok
   ```
3. **Cliff Verification**:
   - Confirms `limit` yields non-error status (200 OK).
   - Confirms `limit + 1` triggers error boundary (400 Bad Request).
4. **Sequence Transformation Measurement (`measure_sequence_transformation`)**:
   - Replaces `len(sequence_bytes)` padding with candidate sequence (e.g. `\xc0\x8a`).
   - Binary searches mutated cliff in radius $[L_{\text{base}} - 128, L_{\text{base}} + 128]$.
   - Computes $\Delta = L_{\text{base}} - L_{\text{mutated}}$.

### 5.3 Test Suite Verification (`test_protocol_ruler.py`)
- Evaluates against `TestLabServer` configured with `max_header_limit=64040`.
- Verifies:
  - Baseline calibration pinpoints exact 64,040-byte boundary (`test_01`).
  - Kettle overlong UTF-8 `\xc0\x8a` expands by 10 bytes ($\Delta = 10$, mutated limit = 64,030) (`test_02`).
  - Standard slash `/` passes verbatim ($\Delta = 0$) (`test_03`).
  - Full catalog audit identifies expansions (`test_04`).
  - Target host rejects `0.0.0.0` and `::` listening addresses with `ValueError` (`test_05`).
  - Connection drop returns status code 0 cleanly (`test_06`).

---

## 6. 4-Parser Differential Matrix

Defined in `engine/differential_oracle.py`, the 4 reference parsers operate completely offline without external network dependencies:

| Parser Name | Class Name | Target Implementation Archetype | Behavioral Profile & Quirks |
| :--- | :--- | :--- | :--- |
| **Strict RFC 9112 / RFC 7230** | `StrictRFC7230Parser` | Canonical conforming reference (Node.js llhttp / Envoy strict mode) | Rejects bare LF or bare CR (`400 Bad Request`); requires exactly 3 tokens in Request-Line; rejects obs-fold; rejects whitespace before colon (`400`); rejects conflicting duplicate `Content-Length`; rejects simultaneous `Transfer-Encoding` and `Content-Length`. |
| **Permissive Legacy RFC 2616** | `PermissiveLegacyParser` | Historic pre-RFC 7230 server (Apache 2.2 / legacy embedded HTTPd) | Tolerates bare LF and bare CR; folds obs-fold (replaces CRLF+SP with single space); tolerates whitespace before colon; silently picks first `Content-Length`; emits HTTP/1.0 200 OK. |
| **CDN Edge Proxy** | `CDNProxyParser` | Cloud reverse proxy & WAF (Nginx / Cloudflare / AWS CloudFront) | Path unencoding & normalization (unmasks `%0d%0a`, `%20`); detects Request Header Injection (RHI) in path (`Expect: asdf` $\rightarrow$ 417, `Transfer-Encoding` $\rightarrow$ 501, `13.37` $\rightarrow$ 505); emits interim `100 Continue` for `Expect: 100-continue`; prioritizes `Transfer-Encoding: chunked` over `Content-Length`. |
| **Async Microservice Gateway** | `AsyncMicroserviceParser` | Event-driven non-blocking gateway (Netty / Tornado / Node.js) | Dangling-byte detection: if declared `Content-Length > len(body)`, pauses awaiting stream completion (`408 Request Timeout`); validates hex chunk size in chunked stream (`400 Bad Request: Invalid chunk size hex`); emits `Connection: keep-alive`. |

When live network endpoints are unreachable or fewer than 2 respond, `MultiImplementationDifferentialOracle.evaluate_divergence` automatically evaluates candidate probes against this 4-parser differential matrix.

---

## 7. Module 16: Google Research Harness² Deep Dive

### 7.1 The Eight Editable Harness Components (`c1..c8` Surface)
Defined in `SurfaceSpec` (`RFCHUNT_SURFACE`) in `engine/harness2_engine.py`:
- `c1` (`systemprompt.md`): Core micro-inspiration directive and protocol boundary synthesis prompt.
- `c2` (`guardrails.md`): Anti-anchoring constraints, 3-trial verification rules, and automated skill trigger lines.
- `c3` (`LongTermMEMORY.md`): Cross-RFC empirical protocol memory (known header buffer limits, chunk parser tolerances, H2 downgrade quirks).
- `c4` (`tool_descriptions/tool_guidance.md`): Guidance for orchestrating Protocol Ruler, 3-Step Canary Pipeline, and 4-Parser Differential Matrix.
- `c5` (`sub_agents/<name>/AGENT.md`): Delegated protocol specialist subagents (frontmatter `mode: subagent` and `description:`).
- `c6` (`skills/<name>/SKILL.md`): Reusable protocol audit workflows (frontmatter `name:` matching directory and `description:`).
- `c7` (`scripts/<name>.py`): Deterministic Python wire-framing and boundary calculation helpers (validated via `ast.parse`).
- `c8` (`plugin/<name>.ts`): In-loop guard plugins enforcing protocol invariants directly inside the execution loop.

Validation rules:
- Path traversal rejection (`normalize_rel` rejects `..`, `%2e`, `%2f`, `%5c`, `\x00`, drive letters, UNC paths).
- Always-on character cap: 24,000 characters across `c1..c4`.
- Skill autotriggering: `autotrigger` automatically injects trigger lines into `guardrails.md` for any `c6` skill missing from always-on text.
- Reserved script protection: `read_doc.py`, `pack.py`, and `unpack.py` cannot be overwritten.

### 7.2 Propose–Probe–Compose Recursion (Level 1)
- **`Propose`**: Synthesizes proposed edits along two orthogonal dimensions:
  - `INV` (Invariant): General protocol framing rules and grammar invariants.
  - `DOM` (Domain): Specialized for the specific RFC domain (e.g. `http11_framing`, `h2_translation`, `tls13_pqc`).
- **`Probe`**: Evaluates behavioral contrast against the 4-Parser Differential Matrix and `ProtocolWorldModel` without ground-truth labels.
- **`Compose`**: Composes winning candidate edits into refined harnesses:
  - `parallel` (`agg`): Explores width. Executes $k$ shared base rollouts, proposes $2k$ candidates ($k$ INV + $k$ DOM), and composes $k$ aggregated harnesses (`agg1..aggk`).
  - `sequential` (`seq`): Explores depth. Runs $k$ sequential iterative rounds ($t = 1..k$), carrying forward the composed harness $c_t$ to round $t+1$.

### 7.3 Budget Accounting Ledger ($R = 4k$, $P = 3k$)
Strictly enforces mathematical ledger identities:
- **Rollouts Identity**:
  $$R = 4k = k\text{ (base)} + 2k\text{ (candidates)} + k\text{ (finals)}$$
- **Improvement Stages Identity**:
  $$P = 3k = k\text{ (INV)} + k\text{ (DOM)} + k\text{ (compositions)}$$
If `actual_rollouts != 4k` or `actual_stages != 3k`, `Ledger.assert_identity()` raises `BudgetError`.

### 7.4 Per-Domain Experience Library (Level 2)
Persists full adopted trees and evidence-supported lessons into `runs/harness2/<run_tag>/<mode>/<domain>/`:
- **`INDEX.md`**: Master index of tasks, adopted stages, contrast scores, cues, and lessons.
- **`EXPERIENCE.md`**: Per-task record containing:
  - `cue`: The operational condition triggering the lesson.
  - `lesson`: The generalizable protocol engineering principle learned.
  - `evidence`: Empirical differential score gain and rollout metrics.
- Prior lessons are loaded before subsequent tasks via `load_domain_lessons()` to guide future exploration.

---

## 8. Identified Codebase Defects, Inconsistencies, & Downstream Action Items

During this survey, the following code-level defects and discrepancies were uncovered:

### Defect 1: Truncated Method Stub & Duplicate Definition in `engine/differential_oracle.py`
- **Location**: `engine/differential_oracle.py:116-139` vs `lines 196-248`.
- **Detail**: Lines 116–139 define `evaluate_divergence` without a return statement or divergence evaluation logic. The method is re-defined in full at line 196. The dead stub at lines 116–139 should be removed.

### Defect 2: Subprocess Windows Isolation Missing (`CREATE_NO_WINDOW` & `DEVNULL`)
- **Locations**:
  - `build_all.py:179-187`: `subprocess.run(cmd, ...)`
  - `engine/raptor_integrator.py:108, 166, 235, 323`: `subprocess.run(...)`
- **Detail**: Neither file passes `creationflags=0x08000000` (`CREATE_NO_WINDOW`) or `stdin=subprocess.DEVNULL` on Windows, causing console window popups and potential hanging on standard input.

### Defect 3: Missing Host Network Containment Module
- **Location**: `engine/host_containment.py` (does not exist).
- **Detail**: Requirement R2 specifies implementing Windows WFP dynamic session lifecycle (`fwpuclnt.dll` with `FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`, `FwpmEngineOpen0`, `FwpmTransactionBegin0/Commit0/Abort0`, `FwpmEngineClose0`) and Linux `AF_NETLINK` sockets. This module must be created and integrated into `engine/defensive_publisher.py` and the swarm lifecycle.

### Defect 4: Single-Line ABNF Regex Parser Limitation in `engine/abnf_engine.py`
- **Location**: `engine/abnf_engine.py:21-24`.
- **Detail**: `ABNF_RULE_REGEX = re.compile(r"^[ \t]*([a-zA-Z][a-zA-Z0-9_-]*)[ \t]*=[ \t]*(.+?)(?=;.*)?$", re.MULTILINE)`.
- **Impact**: Multi-line ABNF rules with indented continuation lines (per RFC 5234 §2.1) have their continuations truncated. Consider adding multi-line continuation handling for indented lines.

---

## 9. Conclusion

The protocol research modules in `D:\harfile\rfchunt` demonstrate advanced specification-grounded architecture. The core framing engine, 3-step pipelined canary, 3-trial reproducibility invariant, Protocol Ruler calibration, 4-parser differential matrix, and Module 16 Harness² recursion operate with high RFC fidelity. Addressing the dead stub in `engine/differential_oracle.py`, enforcing `CREATE_NO_WINDOW` across all subprocess calls, and implementing the native `HostContainmentManager` in `engine/host_containment.py` will fulfill all acceptance criteria outlined in `ORIGINAL_REQUEST.md`.
