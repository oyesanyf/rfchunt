import argparse
import operator
import re
import time
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, StateGraph

# External/Core components from original continuous_scanner
from database import Database
from forensics import ForensicLogger
from permutator import VectorPermutator
from probe_generator import ProbeGenerator
from rfc_chunker import RFCChunker
from rfc_fetcher import RFCFetcher
from cascade import DiscoveryCascade

# 12 Engine Modules
from engine.abnf_engine import ABNFGrammarEngine
from engine.bandit_scheduler import AdaptiveBanditScheduler
from engine.boundary_analyzer import CrossProtocolBoundaryAnalyzer
from engine.causal_classifier import CausalAnomalyClassifier
from engine.defensive_publisher import DefensiveIntelligencePublisher
from engine.delta_debugger import DeltaDebugger
from engine.differential_oracle import MultiImplementationDifferentialOracle, TargetEndpoint
from engine.errata_tracker import RFCEvolutionTracker
from engine.knowledge_graph import ResearchKnowledgeGraph
from engine.metamorphic_engine import MetamorphicTestingEngine
from engine.semantic_compiler import SemanticConstraintCompiler
from engine.sequence_engine import StatefulProtocolSequenceEngine
from engine.taxonomy import (
    AnomalyCategory,
    ImplementationAnomaly,
    NovelTechnique,
    ReproducibleVulnerability,
)

# 1. State Definition (Encompassing all original functionality)
class ResearchState(TypedDict):
    rfc_num: str
    rfc_text: str
    fragments: List[str]
    current_fragment: str
    generated_candidates: List[Dict[str, Any]]
    current_probe: bytes
    reward: float
    current_anomaly: Optional[ImplementationAnomaly]
    current_vuln: Optional[ReproducibleVulnerability]
    novel_technique_found: Optional[str]
    cascade_results: Optional[Dict[str, Any]]
    cycle_count: int
    max_cycles: int
    history: Annotated[List[str], operator.add]


def format_kettle_http_bytes(raw_bytes: bytes, max_len: int = 4000, is_debug: bool = True) -> str:
    """
    Formats raw HTTP wire bytes in the style of James Kettle's HTTP Terminator evaluation traces:
    - Decodes latin-1 safely.
    - Compresses long repeated byte sequences (e.g. 'A'*64040 -> 'A: AAA...{64040}').
    - Truncates oversized binary sequences unless in deep debug mode.
    """
    if not raw_bytes:
        return ""
    text = raw_bytes.decode('latin-1', errors='replace')
    
    # Compress repeated character runs longer than 24 chars (e.g. 'A'*64040 -> 'AAA...{64040}')
    def _replacer(m):
        c = m.group(1)
        length = len(m.group(0))
        return f"{c*3}...{{{length}}}"
        
    text = re.sub(r'([^\r\n])\1{23,}', _replacer, text)
    
    if len(text) > max_len and not is_debug:
        return text[:max_len] + f"\n... [truncated {len(text)-max_len} bytes; use --debug for full body]"
    return text.rstrip()


class ProtocolResearchSwarm:
    def __init__(
        self,
        host: str,
        port: int,
        db_path: str = "terminator.db",
        sec_model: Optional[str] = None,
        use_tls: bool = False,
        show_response: bool = False,
        verbose: bool = False,
        debug: bool = False,
    ):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.debug = debug
        self.show_response = show_response or debug
        self.verbose = verbose or debug
        
        # Original Scanner Core Components
        self.db = Database(db_path)
        self.fetcher = RFCFetcher(db=self.db)
        self.generator = ProbeGenerator(preferred_model="gemma2:2b", use_fusion=True, db=self.db, sec_model=sec_model)
        self.permutator = VectorPermutator(db=self.db)
        self.cascade_engine = DiscoveryCascade(preferred_model="gemma2:2b", use_fusion=True, db=self.db)
        self.forensics = ForensicLogger(target_host=host, target_port=port)
        
        # The 12 Protocol Research Modules
        self.abnf = ABNFGrammarEngine()
        self.bandit = AdaptiveBanditScheduler()
        self.compiler = SemanticConstraintCompiler()
        self.oracle = MultiImplementationDifferentialOracle(
            targets=[TargetEndpoint(name="Primary", host=host, port=port)]
        )
        self.sequence_engine = StatefulProtocolSequenceEngine()
        self.errata = RFCEvolutionTracker()
        self.metamorphic = MetamorphicTestingEngine()
        self.debugger = DeltaDebugger(host, port, use_tls=self.use_tls)
        self.classifier = CausalAnomalyClassifier()
        self.boundary = CrossProtocolBoundaryAnalyzer()
        self.knowledge_graph = ResearchKnowledgeGraph()
        self.publisher = DefensiveIntelligencePublisher()

    # Agent 1: Fetch and Chunk (Replaces manual string entry)
    def fetch_and_chunk_agent(self, state: ResearchState) -> dict:
        rfc_num = int(state.get("rfc_num", "9112").replace("RFC", ""))
        # Fetch actual text
        rfc_text = self.fetcher.fetch_rfc_by_number(rfc_num)
        
        # Mod 1 & 3: Extractor / Compiler
        self.knowledge_graph.add_node(f"RFC{rfc_num}", "RFC", f"Specification RFC{rfc_num}")
        abnf_reqs = self.abnf.extract_from_rfc_text(f"RFC{rfc_num}", rfc_text)
        for req in abnf_reqs:
            self.knowledge_graph.add_node(req.requirement_id, "REQUIREMENT", req.raw_statement[:40])
            self.knowledge_graph.add_edge(f"RFC{rfc_num}", req.requirement_id, "DEFINES")

        # Chunk for LLM Generator
        fragments = RFCChunker.chunk_document(rfc_text)
        self.db.save_fragments(f"RFC{rfc_num}", fragments)
        
        return {
            "rfc_text": rfc_text,
            "fragments": fragments,
            "history": [f"fetch_and_chunk: Fetched RFC{rfc_num}, Extracted {len(abnf_reqs)} ABNF rules, Chunked into {len(fragments)} fragments."]
        }

    # Agent 2: LLM Probe Generation (Original Generator)
    def llm_generator_agent(self, state: ResearchState) -> dict:
        fragments = state.get("fragments", [])
        if not fragments:
            return {"history": ["llm_generator: No fragments left to process."]}
        
        current_frag_tuple = fragments.pop(0)
        frag_text = current_frag_tuple[0] if isinstance(current_frag_tuple, tuple) else current_frag_tuple
        
        preview = frag_text.strip().replace("\r", " ").replace("\n", " ")[:70]
        print(f"\n[llm_generator_agent] Synthesizing probes for fragment ({len(fragments) + 1} remaining in queue): \"{preview}...\"")
        
        # Call Local LLM to generate probes based on this RFC fragment
        llm_probes = self.generator.generate_candidate_probes(frag_text)
        
        # Permutate them
        all_candidates = []
        for p in llm_probes:
            perms = self.permutator.permute_probe(p)
            all_candidates.extend(perms)
            
        print(f"[llm_generator_agent] -> LLM generated {len(llm_probes)} base probes -> {len(all_candidates)} permuted candidates ready for execution.")
        return {
            "fragments": fragments,
            "current_fragment": frag_text,
            "generated_candidates": all_candidates,
            "history": [f"llm_generator: Fragment processed. LLM yielded {len(llm_probes)} base probes -> {len(all_candidates)} permuted candidates."]
        }

    # Route: Check if we have candidates to test
    def route_after_generation(self, state: ResearchState) -> str:
        cands = state.get("generated_candidates", [])
        if not cands:
            # If no candidates were generated, loop back if fragments remain, else end
            if not state.get("fragments"):
                return END
            return "llm_generator_agent"
        return "execution_oracle_agent"

    # Agent 3: Execution and Differential Oracle (Combines sequence and metamorphic)
    def execution_oracle_agent(self, state: ResearchState) -> dict:
        cands = state.get("generated_candidates", [])
        if not cands:
            return {"history": ["execution_oracle: No candidates to execute."]}
        
        # Pop one candidate to test
        candidate = cands.pop(0)
        probe_bytes = candidate.get("raw_request", b"")
        if isinstance(probe_bytes, str):
            probe_bytes = probe_bytes.encode('latin-1', errors='replace')
            
        # Dynamically normalize Host header for remote targets
        if b"target.local" in probe_bytes and self.host != "127.0.0.1":
            probe_bytes = probe_bytes.replace(b"target.local", self.host.encode("latin-1", errors="replace"))
            
        # Run stateful pipeline engine (Mod 5)
        seq_report = self.sequence_engine.run_pipelined_canary_sequence(
            self.host, self.port, probe_bytes, use_tls=self.use_tls
        )
        
        # Telemetry: Extract target host response
        candidate_step = next((s for s in seq_report.steps if "Candidate" in s.step_name), None)
        if candidate_step:
            resp_bytes = candidate_step.received_bytes
            status_code = candidate_step.status_code
            latency_ms = candidate_step.latency * 1000
            sock_err = candidate_step.socket_error
        elif seq_report.steps:
            last_step = seq_report.steps[-1]
            resp_bytes = last_step.received_bytes
            status_code = last_step.status_code
            latency_ms = last_step.latency * 1000
            sock_err = last_step.socket_error
        else:
            resp_bytes = b""
            status_code = 0
            latency_ms = 0.0
            sock_err = seq_report.details or "No response"

        # Format human-readable response summary
        if resp_bytes:
            first_line = resp_bytes.split(b"\r\n")[0].decode("latin-1", errors="replace").strip()
            resp_summary = f"{first_line} ({len(resp_bytes)} bytes in {latency_ms:.1f}ms)"
        elif sock_err:
            resp_summary = f"[{sock_err}] ({latency_ms:.1f}ms)"
        else:
            resp_summary = f"[0 bytes / Connection closed by server] ({latency_ms:.1f}ms)"

        proto_prefix = "https" if self.use_tls else "http"
        
        # Check if user requested Kettle-style deep debug mode
        if self.debug:
            print(f"\n{'='*75}")
            print(f"[*] PROTOCOL EVALUATION TRACE [Kettle Evaluation Oracle]")
            print(f"{'='*75}")
            print(f"[CONNECT] -> {proto_prefix}://{self.host}:{self.port} (Socket Connected | TLS: {self.use_tls})")
            
            for idx, s in enumerate(seq_report.steps, 1):
                sent_fmt = format_kettle_http_bytes(s.sent_bytes, max_len=4000, is_debug=True)
                resp_fmt = format_kettle_http_bytes(s.received_bytes, max_len=4000, is_debug=True)
                
                print(f"\n>>> [REQ {idx}: {s.step_name.upper()}] ({len(s.sent_bytes)} bytes)")
                print(sent_fmt)
                
                if s.received_bytes:
                    first_line = s.received_bytes.split(b"\r\n")[0].decode("latin-1", errors="replace").strip()
                    print(f"\n<<< [RESP {idx}] {first_line} ({len(s.received_bytes)} bytes in {s.latency*1000:.1f}ms)")
                    print(resp_fmt)
                elif s.socket_error:
                    print(f"\n<<< [RESP {idx}] [Socket Error: {s.socket_error}] ({s.latency*1000:.1f}ms)")
                else:
                    print(f"\n<<< [RESP {idx}] [0 bytes / Connection closed by server] ({s.latency*1000:.1f}ms)")
            
            print(f"\n--- SEQUENCE EVALUATION ---")
            print(f"  Desynchronization : {seq_report.has_desynchronization}")
            print(f"  Pipeline Leak     : {seq_report.has_pipeline_leak}")
            print(f"  Verdict           : {seq_report.details}")
            print(f"{'='*75}\n")
        elif self.show_response or self.verbose:
            print(f"\n{'='*28} PROBE TRANSMISSION {'='*28}")
            print(f"Target: {proto_prefix}://{self.host}:{self.port}")
            print(f"--- Raw Probe Sent ({len(probe_bytes)} bytes) ---")
            print(format_kettle_http_bytes(probe_bytes, max_len=2000, is_debug=self.verbose))
            print(f"--- Host Response: {resp_summary} ---")
            if resp_bytes:
                print(format_kettle_http_bytes(resp_bytes, max_len=2000, is_debug=self.verbose))
            else:
                print(f"[{sock_err or '0 bytes received / Connection closed'}]")
            print(f"{'='*76}\n")

        anomaly = None
        if seq_report.has_desynchronization or seq_report.has_pipeline_leak:
            anomaly = ImplementationAnomaly(
                anomaly_id=f"ANOM-SEQ-{int(time.time() * 1000)}",
                target_engine=f"{self.host}:{self.port}",
                category=AnomalyCategory.PIPELINE_LEAK if seq_report.has_pipeline_leak else AnomalyCategory.PARSER_DIVERGENCE,
                observed_behavior=seq_report.details,
                expected_behavior="Clean request separation.",
                raw_probe=probe_bytes,
                raw_response=resp_bytes if resp_bytes else (seq_report.steps[-1].received_bytes if seq_report.steps else b""),
            )
            
        # Fallback to Metamorphic Oracle (Mod 7/4) if no sequence anomaly
        if not anomaly:
            meta_results = self.metamorphic.test_metamorphic_invariance(
                self.host, self.port, probe_bytes, use_tls=self.use_tls
            )
            for mr, is_valid, reason, meta_anomaly in meta_results:
                if self.debug:
                    print(f"[*] METAMORPHIC ORACLE [{mr.relation_id}] -> {reason}")
                if not is_valid and meta_anomaly:
                    anomaly = meta_anomaly
                    break
        
        if anomaly:
            # SAVE to Database exactly like the original code
            self.db.save_implementation_anomaly(
                anomaly_id=anomaly.anomaly_id,
                target_engine=anomaly.target_engine,
                category=anomaly.category.value,
                observed_behavior=anomaly.observed_behavior,
                expected_behavior=anomaly.expected_behavior,
                raw_probe=anomaly.raw_probe.decode("latin-1", errors="replace"),
                raw_response=anomaly.raw_response.decode("latin-1", errors="replace"),
            )
            return {
                "generated_candidates": cands,
                "current_probe": probe_bytes,
                "current_anomaly": anomaly,
                "history": [f"execution_oracle: Probed {self.host}:{self.port} -> Host: {resp_summary} | ANOMALY DETECTED! Saved to DB ({anomaly.anomaly_id})."]
            }

        return {
            "generated_candidates": cands,
            "current_probe": probe_bytes,
            "current_anomaly": None,
            "history": [f"execution_oracle: Probed {self.host}:{self.port} -> Host: {resp_summary} | Target healthy/conformant."]
        }

    def route_after_execution(self, state: ResearchState) -> str:
        if state.get("current_anomaly"):
            return "triage_debugger_agent"
        # If no anomaly, keep looping through candidates
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        
        # Cycle count logic
        cc = state.get("cycle_count", 0) + 1
        if cc >= state.get("max_cycles", 3):
            return END
            
        # Get more from LLM
        return "llm_generator_agent"

    # Agent 4: Triage & Delta Debugger (Mods 8 & 9)
    def triage_debugger_agent(self, state: ResearchState) -> dict:
        anomaly = state["current_anomaly"]
        
        # Noise filter
        is_noise = self.classifier.filter_environmental_noise(anomaly, baseline_is_healthy=True)
        if is_noise:
            return {"current_anomaly": None, "history": ["triage_debugger: Discarded anomaly as environmental noise."]}
            
        # Minimize (Mod 8)
        vuln = self.debugger.minimize_and_reproduce(anomaly, max_verification_trials=3)
        if vuln.reproducibility_rate >= 0.66:
            # SAVE to Database
            self.db.save_reproducible_vulnerability(
                vuln_id=vuln.vuln_id,
                anomaly_id=anomaly.anomaly_id,
                impact=vuln.impact.value,
                minimized_probe=vuln.minimized_probe.decode("latin-1", errors="replace"),
                reproducibility_rate=vuln.reproducibility_rate,
                verification_attempts=vuln.verification_attempts,
                successful_reproductions=vuln.successful_reproductions,
                delta_debug_steps=vuln.delta_debug_steps,
                provenance_chain=vuln.provenance_chain,
            )
            
            # Novelty Classifier (Mod 9)
            is_novel, tech = self.classifier.classify_novelty(vuln)
            novel_name = None
            if is_novel and tech:
                self.db.save_novel_technique(
                    technique_id=tech.technique_id, title=tech.title,
                    conceptual_model=tech.conceptual_model, inversion_pattern=tech.inversion_pattern,
                    affected_architectures=tech.affected_architectures, supporting_vulnerabilities=tech.supporting_vulnerabilities,
                    recommended_mitigation=tech.recommended_mitigation
                )
                novel_name = tech.title
                
            return {
                "current_vuln": vuln, 
                "novel_technique_found": novel_name, 
                "history": [f"triage_debugger: Confirmed Vulnerability {vuln.vuln_id}! Saved to DB."]
            }
        
        return {"current_vuln": None, "history": ["triage_debugger: Failed reproducibility verification."]}

    def route_after_triage(self, state: ResearchState) -> str:
        if state.get("current_vuln"):
            return "cascade_and_publish_agent"
        # If discarded or failed to reproduce, keep testing
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        return "llm_generator_agent"

    # Agent 5: Discovery Cascade, Knowledge Graph, Publish, & Forensics
    def cascade_and_publish_agent(self, state: ResearchState) -> dict:
        vuln = state["current_vuln"]
        anomaly = state["current_anomaly"]
        frag_text = state.get("current_fragment", "")
        rfc_num = state.get("rfc_num", "9112").replace("RFC", "")
        
        # 1. Cascade (LLM extrapolation)
        cascade_res = self.cascade_engine.cascade_from_finding({
            "rationale": "Swarm detected vulnerability.",
            "rfc_fragment": frag_text,
            "details": anomaly.observed_behavior,
        })
        
        # 2. Update Knowledge Graph (Mod 11)
        self.knowledge_graph.add_node(vuln.vuln_id, "VULNERABILITY", f"{vuln.impact.value} ({vuln.vuln_id})")
        self.knowledge_graph.add_edge(anomaly.anomaly_id, vuln.vuln_id, "PROVES_VULN")
        
        # 3. Publish Arm 106 & 107 (Mod 12)
        arm106, arm107 = self.publisher.publish_finding(vuln, rfc_anchor=f"RFC{rfc_num}")
        
        # 4. Forensic Logging (Original functionality)
        self.forensics.record_finding(
            rfc_num=int(rfc_num) if rfc_num.isdigit() else 0,
            rfc_fragment=frag_text,
            rationale="Swarm node detection",
            raw_request=vuln.minimized_probe.decode('latin-1', errors='replace'),
            is_vuln=True,
            desync_class=vuln.impact.value,
            details=anomaly.observed_behavior,
            metadata={"arm106": arm106.rule_id, "arm107": arm107.test_id},
            weaponization=None,
            cascade=cascade_res,
            concept_analysis=None
        )
        self.forensics.save_forensic_report()

        cc = state.get("cycle_count", 0) + 1
        return {
            "cascade_results": cascade_res,
            "cycle_count": cc,
            "history": [f"cascade_publish: Ran Cascade, Published rules ({arm106.rule_id}), and saved Forensic trace!"]
        }

    def route_after_publish(self, state: ResearchState) -> str:
        # Check cycles or go back to testing candidates
        if state.get("cycle_count", 0) >= state.get("max_cycles", 3):
            return END
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        return "llm_generator_agent"


    def build_graph(self) -> StateGraph:
        builder = StateGraph(ResearchState)

        # Add Nodes
        builder.add_node("fetch_and_chunk_agent", self.fetch_and_chunk_agent)
        builder.add_node("llm_generator_agent", self.llm_generator_agent)
        builder.add_node("execution_oracle_agent", self.execution_oracle_agent)
        builder.add_node("triage_debugger_agent", self.triage_debugger_agent)
        builder.add_node("cascade_and_publish_agent", self.cascade_and_publish_agent)

        # Edges
        builder.set_entry_point("fetch_and_chunk_agent")
        builder.add_edge("fetch_and_chunk_agent", "llm_generator_agent")
        
        builder.add_conditional_edges("llm_generator_agent", self.route_after_generation)
        builder.add_conditional_edges("execution_oracle_agent", self.route_after_execution)
        builder.add_conditional_edges("triage_debugger_agent", self.route_after_triage)
        builder.add_conditional_edges("cascade_and_publish_agent", self.route_after_publish)

        return builder.compile()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
===============================================================================
RFC HUNT SWARM: Specification-Driven Autonomous Protocol Research Engine
===============================================================================
A LangGraph-orchestrated 12-agent research swarm that:
  1. Fetches and parses normative RFC specifications and ABNF grammars.
  2. Generates novel protocol edge-cases using ModelFusion (Gemma + Foundation-Sec).
  3. Executes stateful pipelined sequences and metamorphic differential oracles.
  4. Automatically delta-debugs, minimizes, and verifies reproducible vulnerabilities.
  5. Formulates novel architectural concepts and publishes Arm 106 & 107 defenses.
""",
        epilog="""
===============================================================================
USAGE EXAMPLES:
===============================================================================

1. Scan a single RFC against the local target:
   python -u rfc_hunt_swarm.py --mode single --rfc 9112

2. Scan the curated James Kettle Research Corpus (138 core HTTP/SMTP RFCs):
   python -u rfc_hunt_swarm.py --mode corpus

3. Scan ALL active IETF protocol specifications (HTTP, TLS, WebSockets, etc.):
   python -u rfc_hunt_swarm.py --mode all

4. Research POST-QUANTUM Cryptography (PQC, ML-KEM, HPKE, Quantum-Resistant TLS):
   python -u rfc_hunt_swarm.py --mode pqc

5. Scan with an extended 15-minute timeout for large (16GB) security models:
   python -u rfc_hunt_swarm.py --mode corpus --timeout 900

6. Scan with UNLIMITED timeout (disables timeout aborts completely):
   python -u rfc_hunt_swarm.py --mode corpus --timeout 0

7. Use a faster 4.7GB secondary security specialist model:
   python -u rfc_hunt_swarm.py --mode corpus --sec-model qwen2.5:7b

8. Target a custom host and port:
   python -u rfc_hunt_swarm.py --mode single --rfc 7230 --host 127.0.0.1 --port 8080

9. Run against a REMOTE HTTP host (auto-normalizes Host headers):
   python -u rfc_hunt_swarm.py --mode single --rfc 9112 --host staging.corp.internal --port 80

10. Run against a REMOTE HTTPS / TLS host (port 443):
    python -u rfc_hunt_swarm.py --mode corpus --host target-app.example.com --port 443 --tls

11. Run an intensive deep-search with 10 mutation cycles per RFC:
    python -u rfc_hunt_swarm.py --mode corpus --cycles 10

12. Print live host HTTP/TLS responses for every probe:
    python -u rfc_hunt_swarm.py --mode pqc --host 127.0.0.1 --port 8080 --show-response

13. Deep debugging mode (host responses + socket pipeline telemetry):
    python -u rfc_hunt_swarm.py --mode pqc --host test-lab.internal --port 443 --tls --debug

14. Enable full verbose telemetry and payload tracing:
    python -u rfc_hunt_swarm.py --mode single --rfc 9112 --verbose
===============================================================================
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--rfc", type=str, default="9112", help="Specific RFC ID to analyze (e.g. 9112)")
    parser.add_argument("--mode", type=str, choices=["single", "corpus", "all", "pqc"], default="single", help="Scan mode: single RFC, Kettle corpus, all protocol RFCs, or pqc (Post-Quantum)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Target host (domain or IP)")
    parser.add_argument("--port", type=int, default=5006, help="Target port")
    parser.add_argument("--tls", action="store_true", help="Enable TLS/HTTPS for remote host (auto-enabled if port is 443)")
    parser.add_argument("--cycles", type=int, default=3, help="Max mutation cycles to run per RFC")
    parser.add_argument("--timeout", type=float, default=900.0, help="Ollama LLM inference timeout in seconds (default: 900.0 = 15m; 0 for unlimited)")
    parser.add_argument("--sec-model", type=str, default=None, help="Secondary security specialist model (e.g. fenkohq/foundation-sec-8b:latest, qwen2.5:7b, strix-qwen:latest)")
    parser.add_argument("--debug", action="store_true", help="Enable comprehensive debugging mode (prints raw host responses, socket telemetry, and sequence pipeline steps)")
    parser.add_argument("--show-response", action="store_true", help="Print full raw HTTP/TLS responses received from the target host")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose execution telemetry and full payload/response tracing")
    args = parser.parse_args()

    import os
    os.environ["OLLAMA_TIMEOUT"] = str(args.timeout)

    use_tls = bool(args.tls or (args.port == 443))
    proto_str = "https" if use_tls else "http"

    print(f"[*] Initializing Full LangGraph Swarm against {proto_str}://{args.host}:{args.port} (TLS: {use_tls}, LLM Timeout: {'Unlimited' if args.timeout <= 0 else f'{args.timeout}s'})")
    if args.debug:
        print("[*] Deep Swarm Debug Mode: ENABLED (Live Host Responses + Pipeline Telemetry)")
    elif args.show_response or args.verbose:
        print("[*] Live Host Response Printing: ENABLED")
    swarm = ProtocolResearchSwarm(
        host=args.host,
        port=args.port,
        db_path="terminator.db",
        sec_model=args.sec_model,
        use_tls=use_tls,
        show_response=args.show_response,
        verbose=args.verbose,
        debug=args.debug,
    )
    graph = swarm.build_graph()
    
    # Determine which RFCs to scan based on the selected mode
    if args.mode == "single":
        rfcs_to_scan = [args.rfc.replace("RFC", "")]
    elif args.mode == "corpus":
        print("[*] Resolving James Kettle Research Corpus...")
        rfcs_to_scan = swarm.fetcher.get_kettle_corpus()
    elif args.mode == "all":
        print("[*] Discovering all active protocol RFCs from IETF registry...")
        rfcs_to_scan = swarm.fetcher.discover_active_protocol_rfcs(unrestricted=False)
    elif args.mode == "pqc":
        print("[*] Resolving Post-Quantum Cryptography (PQC) & Hybrid TLS Specifications...")
        rfcs_to_scan = swarm.fetcher.get_pqc_corpus()
        
    print(f"\n[*] Queue ready: {len(rfcs_to_scan)} RFC(s) scheduled for Swarm processing.\n" + "="*60)

    for rfc_item in rfcs_to_scan:
        rfc_num_str = str(rfc_item)
        print(f"\n[*] --- Initiating Swarm Cycle for RFC {rfc_num_str} ---")
        
        initial_state = {
            "rfc_num": rfc_num_str,
            "rfc_text": "",
            "fragments": [],
            "current_fragment": "",
            "generated_candidates": [],
            "current_probe": b"",
            "reward": 0.0,
            "current_anomaly": None,
            "current_vuln": None,
            "novel_technique_found": None,
            "cascade_results": None,
            "cycle_count": 0,
            "max_cycles": args.cycles,
            "history": []
        }

        try:
            for event in graph.stream(initial_state, {"recursion_limit": 5000}):
                for node_name, state_update in event.items():
                    last_hist = state_update.get('history', [])[-1] if state_update.get('history') else ''
                    print(f"[{node_name}] -> {last_hist}")
                    if "current_vuln" in state_update and state_update["current_vuln"]:
                        print(f"    !!! VULNERABILITY CONFIRMED: {state_update['current_vuln'].vuln_id}")
        except Exception as e:
            print(f"[!] Swarm encountered a critical fault on RFC {rfc_num_str}: {e}")
            continue
            
    print("\n[*] Swarm Execution Completed. All evidence saved to DB and Forensics Log.")
