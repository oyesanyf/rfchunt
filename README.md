# RFC Hunt Swarm: Specification-Driven Autonomous Protocol Research Engine

An autonomous, 12-agent research swarm orchestrated via **LangGraph** that extracts normative grammar rules and micro-inspiration from IETF RFC specifications, synthesizes novel boundary and desynchronization probes via **ModelFusion**, executes stateful pipelined canary sequences against live HTTP/TLS endpoints, and delta-debugs reproducible anomalies.

---

## Architecture & Core Innovations

1. **Micro-Inspiration Engine**:
   - Splitting RFC documents into isolated 1–3 sentence fragments solves the LLM *context-contamination* and over-anchoring problem (as documented in James Kettle's *HTTP Terminator* research).
   - Prevents models from merely regurgitating known attacks (`CL.TE`, `TE.CL`) and drives discovery of novel semantic vectors (e.g. `multipart/byteranges`, dual-matching headers, PQC hybrid extensions).

2. **ModelFusion Multi-Model Consensus**:
   - **Protocol Specialist**: `gemma2:2b`
   - **Boundary Specialist**: `fenkohq/foundation-sec-8b:latest` (or `qwen2.5:7b`)
   - **Reasoning Arbiter**: `deepseek-r1:1.5b`
   - Arbitrates edge cases through consensus filtering before execution.

3. **12 Protocol Research Modules**:
   - **Mod 1**: ABNF Grammar Extractor
   - **Mod 2**: Context-Free Micro-Inspiration Generator
   - **Mod 3**: Semantic Constraint Compiler
   - **Mod 4**: Multi-Implementation Differential Oracle
   - **Mod 5**: Stateful Protocol Sequence Engine (Pipelined Canary Sequences)
   - **Mod 6**: RFC Evolution & Errata Tracker
   - **Mod 7**: Metamorphic Invariance Oracle
   - **Mod 8**: Delta-Debugging & Minimization Engine
   - **Mod 9**: Causal Anomaly & Novelty Classifier
   - **Mod 10**: Cross-Protocol Boundary Analyzer
   - **Mod 11**: Research Knowledge Graph
   - **Mod 12**: Defensive Intelligence Publisher (Snort/Suricata & Regression Suites)

4. **Kettle Evaluation Oracle & Debug Telemetry**:
   - Deep `--debug` mode traces socket connection events (`[CONNECT]`), baseline requests, candidate probes, and pipelined canary requests side-by-side with exact server responses.
   - Automatically applies protocol-ruler byte compression (`AAA...{64040}`) to large repetitive sequences.

---

## Installation & Setup

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.ai/) running locally on `http://127.0.0.1:11434`
- Recommended local models:
  ```bash
  ollama pull gemma2:2b
  ollama pull deepseek-r1:1.5b
  ollama pull qwen2.5:7b
  # Optional: fenkohq/foundation-sec-8b:latest
  ```

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Research a Single RFC against Local Target
```bash
python -u rfc_hunt_swarm.py --mode single --rfc 9112 --host 127.0.0.1 --port 8080
```

### 2. Research the Curated James Kettle Corpus (138 core RFCs)
```bash
python -u rfc_hunt_swarm.py --mode corpus --host 127.0.0.1 --port 8080 --cycles 5
```

### 3. Post-Quantum Cryptography (PQC) & Hybrid TLS Specifications
```bash
python -u rfc_hunt_swarm.py --mode pqc --host test-lab.internal --port 443 --tls
```

### 4. Deep Debugging with Live Host Responses & Socket Telemetry
```bash
python -u rfc_hunt_swarm.py --mode pqc --host test-lab.internal --port 443 --tls --debug
```

### 5. High-Speed Resident Model Scanning
```bash
python -u rfc_hunt_swarm.py --mode corpus --sec-model qwen2.5:7b --timeout 300
```

---

## CLI Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--mode` | Scan scope: `single`, `corpus` (Kettle 138), `all` (IETF registry), `pqc` (Post-Quantum) | `single` |
| `--rfc` | Specific RFC ID to evaluate when in single mode (e.g. `9112`, `7230`, `8446`) | `9112` |
| `--host` | Target hostname or IP address | `127.0.0.1` |
| `--port` | Target port | `5006` |
| `--tls` | Enable TLS/HTTPS for remote targets (auto-enabled if port is 443) | `False` |
| `--cycles` | Maximum mutation and exploration cycles per RFC | `3` |
| `--timeout` | Ollama model inference timeout in seconds (`0` for unlimited) | `900.0` |
| `--sec-model` | Secondary security model (e.g. `qwen2.5:7b`, `foundation-sec-8b`) | None |
| `--debug` | Enable comprehensive Kettle transaction trace and socket telemetry | `False` |
| `--show-response` | Print raw HTTP/TLS responses received from the target host | `False` |
| `-v`, `--verbose` | Enable verbose execution telemetry and full payload tracing | `False` |

---

## Telemetry & Evidence

- **Database**: All discovered implementation anomalies, minimized vulnerabilities, and novel techniques are persisted in `terminator.db`.
- **Forensics**: Raw socket captures, timing metrics, and standalone reproduction scripts are logged to `./forensics/`.
- **Defenses**: Snort/Suricata signatures and automated regression test suites are exported to `./data/`.

---

## Research Attribution & Acknowledgements

This project implements and expands upon the autonomous protocol research paradigm pioneered by **James Kettle** (Director of Research, PortSwigger):

- **Seminal Research Paper**: [Can AI Do Novel Security Research?](https://portswigger.net/research/can-ai-do-novel-security-research) (PortSwigger Research, October 2026)
- **Author**: James Kettle ([@albinowax](https://x.com/albinowax) / [jameskettle.com](https://jameskettle.com/))
- **Reference Tool**: [HTTP Terminator (GitHub)](https://github.com/portswigger/http-terminator)

### Core Methodologies Derived from James Kettle's Research:
1. **Micro-Inspiration Engine**:
   Overcoming LLM "context-contamination" and over-anchoring by chunking normative IETF RFC standards into isolated 1–3 sentence prompts rather than asking generic fuzzer questions.
2. **State Machine Canary Sequences**:
   Evaluating desync triggers via persistent TCP state machine transitions (`Baseline GET` $\rightarrow$ `Candidate Probe` $\rightarrow$ `Pipelined Canary GET`) to measure boundary contamination without client-side connection-reuse illusions.
3. **The Protocol-Ruler Technique**:
   Using backend length limits and delimiter boundaries as a ruler to detect input rewriting, Unicode normalization/mojibake, and header injection.
4. **The Discovery Cascade**:
   Systematically interrogating every verified finding with autonomous hypothesis generation to explore adjacent branches of the vulnerability landscape (e.g., *Shared-Parser Confusion*, *Response Forking*, and the *Dangling-Byte Technique*).

---

## License

Apache 2.0 / MIT.
