"""
RFC HUNT SWARM: Specification-Driven Autonomous Protocol Research Engine
========================================================================

An autonomous, 12-agent research swarm orchestrated via LangGraph that extracts
normative grammar rules and micro-inspiration from Post-Quantum Cryptography (PQC)
and IETF RFC specifications, synthesizes novel boundary and desynchronization probes via
ModelFusion, executes stateful pipelined canary sequences against live HTTP/TLS endpoints,
and delta-debugs reproducible anomalies.

Inspired by James Kettle (Director of Research, PortSwigger):
  "Can AI Do Novel Security Research?" (PortSwigger Research, October 2026)
  https://portswigger.net/research/can-ai-do-novel-security-research

Core Mechanisms:
  - Micro-inspiration chunking from Post-Quantum (PQC) and IETF RFC specifications
  - ModelFusion multi-model consensus (Protocol Specialist + Boundary Specialist + Reasoning Arbiter)
  - Stateful pipelined canary sequences (Baseline GET -> Candidate Probe -> Canary GET)
  - Metamorphic differential oracles & hierarchical delta-debugging
  - Autonomous discovery cascade & Post-Quantum Cryptography (PQC) standards
"""

import argparse
import concurrent.futures
import operator
import re
import sys
import threading
import time
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, StateGraph

# External/Core components from original continuous_scanner
from anomaly_detector import AnomalyDetector
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
from engine.dream_world_model import ProtocolWorldModel
from engine.dream_rsi_optimizer import DreamRSIOptimizer, DreamPolicy
from engine.dream_policy_store import DreamPolicyStore

# 1. State Definition (Encompassing all original functionality + Dream-RSI)
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
    baseline_resp: Optional[bytes]
    enable_dream_rsi: bool
    dream_rollouts: int
    current_dream_policy: Optional[Dict[str, Any]]
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
        return text[:max_len] + f"\n... [truncated {len(text)-max_len} bytes; use -v/--verbose for full body]"
    return text.rstrip()


def format_clean_kettle_response(resp_bytes: bytes, latency_ms: float = 0.0, sock_error: Optional[str] = None, is_verbose: bool = False) -> Tuple[str, str]:
    """
    Parses and sanitizes server response bytes in James Kettle's publication style:
    - Never dumps minified HTML/CSS/JS or analytics tracking blobs.
    - Accurately identifies whether bytes are a true HTTP status line or an unaligned body leak.
    - Preserves vital protocol headers (Server, Content-Type, Content-Length, Connection, Transfer-Encoding).
    """
    if not resp_bytes:
        if sock_error:
            return f"[{sock_error}]", ""
        return f"[0 bytes / Connection closed by server in {latency_ms:.1f}ms]", ""

    # Check if this begins with an HTTP status line
    if resp_bytes.startswith(b"HTTP/1.") or resp_bytes.startswith(b"HTTP/2.") or resp_bytes.startswith(b"HTTP/0.9"):
        parts = resp_bytes.split(b"\r\n\r\n", 1)
        header_block = parts[0]
        body_block = parts[1] if len(parts) > 1 else b""
        
        header_lines = header_block.split(b"\r\n")
        status_line = header_lines[0].decode("latin-1", errors="replace").strip()
        
        # Filter for relevant protocol headers only (drop noisy CSP, Nel, GTM, cookies)
        key_headers = []
        for line in header_lines[1:]:
            line_str = line.decode("latin-1", errors="replace").strip()
            lower = line_str.lower()
            if any(lower.startswith(k) for k in [
                "server:", "content-type:", "content-length:", "connection:",
                "transfer-encoding:", "location:", "x-amzn-trace-id:", "trace-id:"
            ]):
                key_headers.append(line_str)
                
        # Handle body cleanly
        body_display = ""
        if body_block:
            if is_verbose:
                body_display = body_block.decode("latin-1", errors="replace").rstrip()
            else:
                body_lower = body_block[:500].lower()
                if b"<!doctype" in body_lower or b"<html" in body_lower or b"<head" in body_lower:
                    title_match = re.search(r'<title>(.*?)</title>', body_block.decode("latin-1", errors="replace"), re.IGNORECASE)
                    title_str = f' "{title_match.group(1).strip()}"' if title_match else ""
                    body_display = f"[HTML Document{title_str}: {len(body_block):,} bytes]"
                elif b"{" in body_block and b"}" in body_block and len(body_block) < 300:
                    body_display = body_block.decode("latin-1", errors="replace").strip()
                elif len(body_block) < 200 and not any(c in body_block for c in b"<>{};"):
                    body_display = body_block.decode("latin-1", errors="replace").strip()
                else:
                    body_display = f"[Body Payload: {len(body_block):,} bytes]"
                
        details = "\n".join(key_headers)
        if body_display:
            details = (details + "\n" + body_display).strip() if details else body_display
            
        summary = f"{status_line} (in {latency_ms:.1f}ms)"
        return summary, details

    # Not an HTTP status line -> It's non-HTTP data or unconsumed response body
    body_lower = resp_bytes[:300].lower()
    if b"<" in body_lower and (b"meta" in body_lower or b"div" in body_lower or b"html" in body_lower or b"style" in body_lower or b"script" in body_lower or b"!doctype" in body_lower):
        summary = f"[Unconsumed Response Body: {len(resp_bytes):,} bytes in {latency_ms:.1f}ms]"
        details = f"[Residual HTML body fragment from socket buffer: {len(resp_bytes):,} bytes]"
    else:
        summary = f"[Non-HTTP Socket Data: {len(resp_bytes):,} bytes in {latency_ms:.1f}ms]"
        details = f"[Non-HTTP data: {len(resp_bytes):,} bytes]"
        
    return summary, details


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
        concurrency: int = 8,
    ):
        host = re.sub(r"^https?://", "", str(host).strip(), flags=re.IGNORECASE).split("/")[0]
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.debug = debug
        self.show_response = show_response or debug
        self.verbose = verbose or debug
        self.concurrency = max(1, concurrency)
        self.probe_semaphore = threading.BoundedSemaphore(self.concurrency)
        self.llm_semaphore = threading.BoundedSemaphore(1)
        
        # Original Scanner Core Components
        self.db_path = db_path
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
        self.publisher = DefensiveIntelligencePublisher(db=self.db)
        self.publisher.sync_db_findings()

        # Open Dream-RSI Engine (Modules 13-15)
        self.dream_world_model = ProtocolWorldModel(target_host=host, target_port=port)
        self.dream_world_model.ingest_history_from_db(db_path=db_path)
        self.dream_optimizer = DreamRSIOptimizer(self.dream_world_model)
        self.dream_store = DreamPolicyStore()
        latest_pol = self.dream_store.get_latest_policy()
        if latest_pol:
            self.bandit.apply_dream_policy(latest_pol)

        # Run-level Pass/Fail Telemetry
        self.stats_lock = threading.Lock()
        self.active_rfc_id = "RFC9112"
        self.run_stats: Dict[str, Any] = {
            "start_time": time.time(),
            "rfcs_scheduled": 0,
            "rfcs_completed": 0,
            "rfcs_errored": 0,
            "fragments_processed": 0,
            "base_probes_generated": 0,
            "total_candidates_executed": 0,
            "probes_passed": 0,
            "probes_failed_anomaly": 0,
            "socket_errors": 0,
            "triage_discarded": 0,
            "anomalies_recorded": [],
            "vulnerabilities_confirmed": [],
            "per_rfc": {},
        }

    def _ensure_rfc_stat(self, rfc_id: str) -> Dict[str, Any]:
        if rfc_id not in self.run_stats["per_rfc"]:
            self.run_stats["per_rfc"][rfc_id] = {
                "fragments": 0,
                "base_probes": 0,
                "executed": 0,
                "passed": 0,
                "failed_anomalies": 0,
                "socket_errors": 0,
                "triage_discarded": 0,
                "confirmed_vulns": 0,
                "status": "RUNNING",
                "error": None,
            }
        return self.run_stats["per_rfc"][rfc_id]

    # Agent 1: Fetch and Chunk (Replaces manual string entry)
    def fetch_and_chunk_agent(self, state: ResearchState) -> dict:
        raw_rfc = str(state.get("rfc_num", "9112")).strip().upper().replace("RFC-", "").replace("RFC", "")
        rfc_num = 0 if raw_rfc in ("0", "MCP") or not raw_rfc.isdigit() else int(raw_rfc)
        rfc_label = f"RFC{rfc_num}"
        with self.stats_lock:
            self.active_rfc_id = rfc_label
            r_stat = self._ensure_rfc_stat(rfc_label)
        # Fetch actual text
        rfc_text = self.fetcher.fetch_rfc_by_number(rfc_num) or ""
        if not rfc_text:
            with self.stats_lock:
                r_stat["status"] = "UNAVAILABLE"
            return {
                "rfc_text": "",
                "fragments": [],
                "history": [f"fetch_and_chunk: RFC{rfc_num} unavailable or empty."],
            }

        # Mod 1 & 3: Extractor / Compiler
        self.knowledge_graph.add_node(f"RFC{rfc_num}", "RFC", f"Specification RFC{rfc_num}")
        abnf_reqs = self.abnf.extract_from_rfc_text(f"RFC{rfc_num}", rfc_text)
        for req in abnf_reqs:
            self.knowledge_graph.add_node(req.requirement_id, "REQUIREMENT", req.raw_statement[:40])
            self.knowledge_graph.add_edge(f"RFC{rfc_num}", req.requirement_id, "DEFINES")

        # Chunk for LLM Generator (prioritizing Terminator framing/delimiter fragments)
        fragments = RFCChunker.chunk_document_for_terminator(rfc_text, rfc_num=rfc_num)
        self.db.save_fragments(f"RFC{rfc_num}", fragments)
        
        return {
            "rfc_text": rfc_text,
            "fragments": fragments,
            "history": [f"fetch_and_chunk: Fetched RFC{rfc_num}, Extracted {len(abnf_reqs)} ABNF rules, Chunked into {len(fragments)} fragments."]
        }

    # Agent 2: LLM Probe Generation (Original Generator)
    def llm_generator_agent(self, state: ResearchState) -> dict:
        fragments = list(state.get("fragments", []))
        new_cycle_count = state.get("cycle_count", 0) + 1
        if not fragments:
            return {
                "generated_candidates": [],
                "cycle_count": new_cycle_count,
                "history": ["llm_generator: No fragments left to process."],
            }
        
        current_frag_tuple = fragments.pop(0)
        frag_text = current_frag_tuple[0] if isinstance(current_frag_tuple, tuple) else current_frag_tuple
        
        preview = frag_text.strip().replace("\r", " ").replace("\n", " ")[:70]
        print(f"\n[llm_generator_agent] [Cycle {new_cycle_count}/{state.get('max_cycles', 3)}] Synthesizing probes for fragment ({len(fragments) + 1} remaining in queue): \"{preview}...\"")
        
        # Call Local LLM to generate probes based on this RFC fragment (guarded by semaphore)
        with self.llm_semaphore:
            llm_probes = self.generator.generate_candidate_probes(frag_text)
        
        # Retain base LLM probes and append permuted variants
        all_candidates = list(llm_probes)
        for p in llm_probes:
            perms = self.permutator.permute_probe(p)
            all_candidates.extend(perms)

        with self.stats_lock:
            self.run_stats["fragments_processed"] += 1
            self.run_stats["base_probes_generated"] += len(llm_probes)
            r_stat = self._ensure_rfc_stat(self.active_rfc_id)
            r_stat["fragments"] += 1
            r_stat["base_probes"] += len(llm_probes)
            
        print(f"[llm_generator_agent] -> LLM generated {len(llm_probes)} base probes -> {len(all_candidates)} total candidates ready for execution.")
        return {
            "fragments": fragments,
            "current_fragment": frag_text,
            "generated_candidates": all_candidates,
            "cycle_count": new_cycle_count,
            "history": [f"llm_generator: Fragment processed (cycle {new_cycle_count}). LLM yielded {len(llm_probes)} base probes -> {len(all_candidates)} total candidates."]
        }

    # Route: Check if we have candidates to test
    def route_after_generation(self, state: ResearchState) -> str:
        cands = state.get("generated_candidates", [])
        if not cands:
            if not state.get("fragments") or state.get("cycle_count", 0) >= state.get("max_cycles", 3):
                if state.get("enable_dream_rsi", False):
                    return "dream_rsi_agent"
                return END
            return "llm_generator_agent"
        return "execution_oracle_agent"

    def _evaluate_single_candidate(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Worker evaluating an individual candidate probe guarded by self.probe_semaphore."""
        with self.probe_semaphore:
            raw_req = candidate.get("raw_request", b"")
            if isinstance(raw_req, bytes):
                probe_str = raw_req.decode("latin-1", errors="replace")
            else:
                probe_str = str(raw_req)

            if "\r\n" not in probe_str and "\\r\\n" in probe_str:
                try:
                    probe_str = probe_str.encode("utf-8").decode("unicode_escape")
                except Exception:
                    probe_str = probe_str.replace("\\r\\n", "\r\n")

            probe_str = probe_str.replace("target.local", self.host)
            nested_marker = f"GET /terminator_marker_8821 HTTP/1.1\r\nHost: {self.host}\r\nX-Ignore: 1\r\n\r\n"
            probe_str = probe_str.replace("$PAYLOAD", nested_marker)
            if "\r\n\r\n" in probe_str and re.search(r"Content-Length:\s*(\$LENGTH|N)\b", probe_str, re.IGNORECASE):
                _, body_part = probe_str.split("\r\n\r\n", 1)
                body_len = len(body_part.encode("latin-1", errors="replace"))
                probe_str = re.sub(
                    r"(Content-Length:\s*)(?:\$LENGTH|N)\b",
                    rf"\g<1>{body_len}",
                    probe_str,
                    flags=re.IGNORECASE,
                )
            probe_bytes = probe_str.encode("latin-1", errors="replace")
                
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

            # Format human-readable response summary and sanitized details
            resp_summary, resp_details = format_clean_kettle_response(
                resp_bytes, latency_ms=latency_ms, sock_error=sock_err, is_verbose=self.verbose
            )

            baseline_step = next((s for s in seq_report.steps if "Baseline" in s.step_name), None)
            baseline_resp_bytes = baseline_step.received_bytes if baseline_step else b""

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

            # Check single-response Anomaly Detection Cascade (Text/Binary Blend, Double HTML, Inline Headers, Clean Dual-Response, Status-Line Reflection, Range Cache Mismatch)
            if not anomaly and resp_bytes:
                cascade_anoms = AnomalyDetector.analyze_response(
                    resp_bytes,
                    baseline_response=baseline_resp_bytes,
                    is_clean_probe=bool(candidate.get("is_clean", False)),
                    db=self.db,
                )
                if cascade_anoms:
                    first_anom = cascade_anoms[0]
                    anomaly = ImplementationAnomaly(
                        anomaly_id=f"ANOM-CASC-{int(time.time() * 1000)}",
                        target_engine=f"{self.host}:{self.port}",
                        category=AnomalyCategory.STATE_DESYNC if first_anom["type"] == "clean_dual_response" else AnomalyCategory.PARSER_DIVERGENCE,
                        observed_behavior=f"[{first_anom['type']}] {first_anom['description']}",
                        expected_behavior="Single well-framed HTTP response without structural anomalies.",
                        raw_probe=probe_bytes,
                        raw_response=resp_bytes,
                    )

            # Fallback to Metamorphic Oracle (Mod 7/4) on base probes if no sequence anomaly
            if not anomaly and candidate.get("source_type") in ("llm", "fusion", None):
                meta_results = self.metamorphic.test_metamorphic_invariance(
                    self.host, self.port, probe_bytes, use_tls=self.use_tls
                )
                for mr, is_valid, reason, meta_anomaly in meta_results:
                    if self.debug:
                        print(f"[*] METAMORPHIC ORACLE [{mr.relation_id}] -> {reason}")
                    if not is_valid and meta_anomaly:
                        anomaly = meta_anomaly
                        break

            # Record live step in Dream-RSI World Model
            self.dream_world_model.record_step(
                probe_bytes=probe_bytes,
                status_code=status_code,
                raw_response=resp_bytes,
                latency=latency_ms / 1000.0,
                is_anomaly=bool(anomaly),
                anomaly_category=anomaly.category.value if anomaly else None,
                is_vulnerability=False,
                details=resp_summary,
            )

            return {
                "candidate": candidate,
                "probe_bytes": probe_bytes,
                "seq_report": seq_report,
                "resp_bytes": resp_bytes,
                "resp_summary": resp_summary,
                "resp_details": resp_details,
                "anomaly": anomaly,
                "baseline_resp_bytes": baseline_resp_bytes,
            }

    # Agent 3: Execution and Differential Oracle (Combines sequence and metamorphic with multithreaded semaphore)
    def execution_oracle_agent(self, state: ResearchState) -> dict:
        cands = state.get("generated_candidates", [])
        if not cands:
            return {"history": ["execution_oracle: No candidates to execute."]}
        
        # Batch evaluation bounded by semaphore
        batch_size = min(len(cands), self.concurrency)
        batch = [cands.pop(0) for _ in range(batch_size)]

        if self.concurrency > 1 and len(batch) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                eval_results = list(executor.map(self._evaluate_single_candidate, batch))
        else:
            eval_results = [self._evaluate_single_candidate(b) for b in batch]

        proto_prefix = "https" if self.use_tls else "http"
        detected_anomaly = None
        detected_probe = b""
        detected_baseline = b""
        first_resp_summary = ""

        for item in eval_results:
            p_bytes = item["probe_bytes"]
            seq_report = item["seq_report"]
            resp_summary = item["resp_summary"]
            resp_details = item["resp_details"]
            anomaly = item["anomaly"]
            b_resp = item["baseline_resp_bytes"]

            if not first_resp_summary:
                first_resp_summary = resp_summary

            with self.stats_lock:
                self.run_stats["total_candidates_executed"] += 1
                r_stat = self._ensure_rfc_stat(self.active_rfc_id)
                r_stat["executed"] += 1
                if anomaly:
                    self.run_stats["probes_failed_anomaly"] += 1
                    r_stat["failed_anomalies"] += 1
                    self.run_stats["anomalies_recorded"].append({
                        "rfc": self.active_rfc_id,
                        "anomaly_id": anomaly.anomaly_id,
                        "category": anomaly.category.value,
                        "behavior": anomaly.observed_behavior,
                    })
                elif not item["resp_bytes"] and any(s.socket_error for s in seq_report.steps):
                    self.run_stats["socket_errors"] += 1
                    r_stat["socket_errors"] += 1
                else:
                    self.run_stats["probes_passed"] += 1
                    r_stat["passed"] += 1

            if self.debug:
                print(f"\n{'='*75}")
                print(f"[*] PROTOCOL EVALUATION TRACE [Kettle Evaluation Oracle] (Threaded Semaphore Pool)")
                print(f"{'='*75}")
                print(f"[CONNECT] -> {proto_prefix}://{self.host}:{self.port} (Socket Connected | TLS: {self.use_tls})")
                for idx, s in enumerate(seq_report.steps, 1):
                    sent_fmt = format_kettle_http_bytes(s.sent_bytes, max_len=2000, is_debug=self.verbose)
                    s_sum, s_det = format_clean_kettle_response(
                        s.received_bytes, latency_ms=s.latency * 1000, sock_error=s.socket_error, is_verbose=self.verbose
                    )
                    print(f"\n>>> [REQ {idx}: {s.step_name.upper()}] ({len(s.sent_bytes)} bytes)")
                    print(sent_fmt)
                    print(f"\n<<< [RESP {idx}] {s_sum}")
                    if s_det:
                        print(s_det)
                print(f"\n--- SEQUENCE EVALUATION ---")
                print(f"  Desynchronization : {seq_report.has_desynchronization}")
                print(f"  Pipeline Leak     : {seq_report.has_pipeline_leak}")
                print(f"  Verdict           : {seq_report.details}")
                print(f"{'='*75}\n")
            elif self.show_response or self.verbose:
                print(f"\n{'='*28} PROBE TRANSMISSION {'='*28}")
                print(f"Target: {proto_prefix}://{self.host}:{self.port}")
                print(f"--- Raw Probe Sent ({len(p_bytes)} bytes) ---")
                print(format_kettle_http_bytes(p_bytes, max_len=2000, is_debug=self.verbose))
                print(f"--- Host Response: {resp_summary} ---")
                if resp_details:
                    print(resp_details)
                print(f"{'='*76}\n")

            if anomaly and not detected_anomaly:
                detected_anomaly = anomaly
                detected_probe = p_bytes
                detected_baseline = b_resp

        if detected_anomaly:
            # SAVE to Database thread-safely
            self.db.save_implementation_anomaly(
                anomaly_id=detected_anomaly.anomaly_id,
                target_engine=detected_anomaly.target_engine,
                category=detected_anomaly.category.value,
                observed_behavior=detected_anomaly.observed_behavior,
                expected_behavior=detected_anomaly.expected_behavior,
                raw_probe=detected_anomaly.raw_probe.decode("latin-1", errors="replace"),
                raw_response=detected_anomaly.raw_response.decode("latin-1", errors="replace"),
            )
            return {
                "generated_candidates": cands,
                "current_probe": detected_probe,
                "current_anomaly": detected_anomaly,
                "baseline_resp": detected_baseline,
                "history": [f"execution_oracle (multithreaded): Batch of {len(batch)} probes completed. ANOMALY DETECTED! Saved to DB ({detected_anomaly.anomaly_id})."]
            }

        last_item = eval_results[-1] if eval_results else {}
        return {
            "generated_candidates": cands,
            "current_probe": last_item.get("probe_bytes", b""),
            "current_anomaly": None,
            "baseline_resp": last_item.get("baseline_resp_bytes", b""),
            "history": [f"execution_oracle (multithreaded): Batch of {len(batch)} probes evaluated concurrently -> Host: {first_resp_summary} | Target healthy/conformant."]
        }

    def route_after_execution(self, state: ResearchState) -> str:
        if state.get("current_anomaly"):
            return "triage_debugger_agent"
        # If no anomaly, keep looping through candidates
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        
        # Cycle count & fragment exhaustion logic
        if state.get("cycle_count", 0) >= state.get("max_cycles", 3) or not state.get("fragments"):
            if state.get("enable_dream_rsi", False):
                return "dream_rsi_agent"
            return END
            
        # Get more from LLM
        return "llm_generator_agent"

    # Agent 4: Triage & Delta Debugger (Mods 8 & 9)
    def triage_debugger_agent(self, state: ResearchState) -> dict:
        anomaly = state["current_anomaly"]
        baseline_resp = state.get("baseline_resp")
        
        # 1. Framing Artifact / Leftover Baseline Guard:
        # Never classify leftover baseline-response bytes as a confirmed vulnerability
        is_artifact, artifact_reason = self.classifier.is_framing_artifact(anomaly, baseline_resp=baseline_resp)
        if is_artifact:
            with self.stats_lock:
                self.run_stats["triage_discarded"] += 1
                self._ensure_rfc_stat(self.active_rfc_id)["triage_discarded"] += 1
            return {"current_anomaly": None, "current_vuln": None, "history": [f"triage_debugger: Discarded anomaly: {artifact_reason}"]}

        # 2. Environmental Noise Filter
        is_noise = self.classifier.filter_environmental_noise(anomaly, baseline_is_healthy=True, baseline_resp=baseline_resp)
        if is_noise:
            with self.stats_lock:
                self.run_stats["triage_discarded"] += 1
                self._ensure_rfc_stat(self.active_rfc_id)["triage_discarded"] += 1
            return {"current_anomaly": None, "current_vuln": None, "history": ["triage_debugger: Discarded anomaly as environmental noise / framing artifact."]}
            
        # 3. Minimize & Reproduce (Mod 8)
        vuln = self.debugger.minimize_and_reproduce(anomaly, max_verification_trials=3)
        if vuln.reproducibility_rate >= 0.66:
            # 4. Evidence Validation Gate: Confirm finding cannot be explained by ordinary framing
            is_valid_evidence, evidence_reason = self.classifier.validate_evidence(vuln, anomaly, baseline_resp=baseline_resp)
            if not is_valid_evidence:
                with self.stats_lock:
                    self.run_stats["triage_discarded"] += 1
                    self._ensure_rfc_stat(self.active_rfc_id)["triage_discarded"] += 1
                return {
                    "current_anomaly": None,
                    "current_vuln": None,
                    "history": [f"triage_debugger: Discarded finding: evidence validator rejected ({evidence_reason})."]
                }

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

            with self.stats_lock:
                r_stat = self._ensure_rfc_stat(self.active_rfc_id)
                r_stat["confirmed_vulns"] += 1
                self.run_stats["vulnerabilities_confirmed"].append({
                    "rfc": self.active_rfc_id,
                    "vuln_id": vuln.vuln_id,
                    "anomaly_id": anomaly.anomaly_id,
                    "impact": vuln.impact.value,
                    "repro": f"{vuln.reproducibility_rate * 100:.0f}% ({vuln.successful_reproductions}/{vuln.verification_attempts})",
                    "behavior": anomaly.observed_behavior,
                })
                
            return {
                "current_vuln": vuln, 
                "novel_technique_found": novel_name, 
                "history": [f"triage_debugger: Confirmed Vulnerability {vuln.vuln_id}! Saved to DB."]
            }
        
        with self.stats_lock:
            self.run_stats["triage_discarded"] += 1
            self._ensure_rfc_stat(self.active_rfc_id)["triage_discarded"] += 1
        return {"current_vuln": None, "history": ["triage_debugger: Failed reproducibility verification."]}

    def route_after_triage(self, state: ResearchState) -> str:
        if state.get("current_vuln"):
            return "cascade_and_publish_agent"
        # If discarded or failed to reproduce, keep testing
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        if state.get("cycle_count", 0) >= state.get("max_cycles", 3) or not state.get("fragments"):
            if state.get("enable_dream_rsi", False):
                return "dream_rsi_agent"
            return END
        return "llm_generator_agent"

    # Agent 5: Discovery Cascade, Knowledge Graph, Publish, & Forensics
    def cascade_and_publish_agent(self, state: ResearchState) -> dict:
        vuln = state["current_vuln"]
        anomaly = state["current_anomaly"]
        baseline_resp = state.get("baseline_resp")
        frag_text = state.get("current_fragment", "")
        rfc_num = str(state.get("rfc_num", "9112")).replace("RFC-", "").replace("RFC", "")
        
        # Evidence Validation Gate:
        # Suspend automatic publication of new detection rules until the evidence validator
        # confirms that the anomalous bytes cannot be explained by ordinary response framing.
        is_confirmed, validation_reason = self.classifier.validate_evidence(vuln, anomaly, baseline_resp=baseline_resp)
        if not is_confirmed:
            print(f"[*] [SUSPENDED] Automatic rule publication suspended for {vuln.vuln_id}: {validation_reason}")
            return {
                "cascade_results": None,
                "history": [f"cascade_publish: Suspended automatic publication ({validation_reason})."]
            }

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
        arm106, arm107 = self.publisher.publish_finding(vuln, rfc_anchor=f"RFC{rfc_num}", evidence_verified=True)
        
        # 4. Forensic Logging (Original functionality)
        self.forensics.record_finding(
            rfc_num=int(rfc_num) if rfc_num.isdigit() else 0,
            rfc_fragment=frag_text,
            rationale="Swarm node detection",
            raw_request=vuln.minimized_probe.decode('latin-1', errors='replace'),
            is_vuln=True,
            desync_class=vuln.impact.value,
            details=anomaly.observed_behavior,
            metadata={"arm106": arm106.rule_id if arm106 else "", "arm107": arm107.test_id if arm107 else ""},
            weaponization=None,
            cascade=cascade_res,
            concept_analysis=None
        )
        self.forensics.save_forensic_report()

        # 5. Caldera Auto-Sync (Runs by default without requiring flags)
        try:
            from engine.caldera_bridge import CalderaBridge
            bridge = CalderaBridge(db_path=self.db_path)
            finding_data = {
                "vuln_id": vuln.vuln_id,
                "impact": vuln.impact.value,
                "minimized_probe": vuln.minimized_probe,
                "details": anomaly.observed_behavior,
                "rationale": frag_text,
            }
            bridge.export_plugin(output_dir="caldera_export", findings=[finding_data])
        except Exception:
            pass

        arm_id = arm106.rule_id if arm106 else "SUSPENDED"
        return {
            "cascade_results": cascade_res,
            "history": [f"cascade_publish: Ran Cascade, Published rules ({arm_id}), and saved Forensic trace!"]
        }

    # Agent 13: Dream-RSI (Recursive Self-Improvement through Evolving Worlds)
    def dream_rsi_agent(self, state: ResearchState) -> dict:
        rollouts = state.get("dream_rollouts", 300)
        print(f"\n[*] [DREAM-RSI] Initiating Off-Policy Dreaming Cycle ({rollouts} rollouts)...")
        evolved_policy = self.dream_optimizer.evolve_policy_generation(rollouts_per_candidate=rollouts)
        self.dream_store.save_policy(evolved_policy)
        self.bandit.apply_dream_policy(evolved_policy)

        gain_str = f"+{evolved_policy.rsi_gain * 100:.1f}%" if evolved_policy.rsi_gain > 0 else "0.0%"
        print(f"[+] [DREAM-RSI] Policy Evolved: Gen {evolved_policy.generation} | RSI Gain: {gain_str} | Hot-reloaded into Swarm Scheduler.")
        return {
            "current_dream_policy": evolved_policy.to_dict(),
            "history": [f"dream_rsi: Evolved Gen {evolved_policy.generation} policy (gain: {gain_str})."]
        }

    def route_after_publish(self, state: ResearchState) -> str:
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        if state.get("cycle_count", 0) >= state.get("max_cycles", 3) or not state.get("fragments"):
            if state.get("enable_dream_rsi", False):
                return "dream_rsi_agent"
            return END
        return "llm_generator_agent"


    def build_graph(self) -> StateGraph:
        builder = StateGraph(ResearchState)

        # Add Nodes
        builder.add_node("fetch_and_chunk_agent", self.fetch_and_chunk_agent)
        builder.add_node("llm_generator_agent", self.llm_generator_agent)
        builder.add_node("execution_oracle_agent", self.execution_oracle_agent)
        builder.add_node("triage_debugger_agent", self.triage_debugger_agent)
        builder.add_node("cascade_and_publish_agent", self.cascade_and_publish_agent)
        builder.add_node("dream_rsi_agent", self.dream_rsi_agent)

        # Edges
        builder.set_entry_point("fetch_and_chunk_agent")
        builder.add_edge("fetch_and_chunk_agent", "llm_generator_agent")
        builder.add_edge("dream_rsi_agent", END)
        
        builder.add_conditional_edges("llm_generator_agent", self.route_after_generation)
        builder.add_conditional_edges("execution_oracle_agent", self.route_after_execution)
        builder.add_conditional_edges("triage_debugger_agent", self.route_after_triage)
        builder.add_conditional_edges("cascade_and_publish_agent", self.route_after_publish)

        return builder.compile()

    def print_run_summary(self) -> str:
        """
        Formats and prints a comprehensive Pass/Fail statistics summary table at the end of a Swarm run.
        Includes overall probe pass/fail counts, triage filtering stats, per-RFC verdicts, and detailed findings.
        """
        with self.stats_lock:
            elapsed = max(0.001, time.time() - self.run_stats["start_time"])
            total_exec = self.run_stats["total_candidates_executed"]
            passed = self.run_stats["probes_passed"]
            failed_anom = self.run_stats["probes_failed_anomaly"]
            sock_errs = self.run_stats["socket_errors"]
            triage_disc = self.run_stats["triage_discarded"]
            vulns = list(self.run_stats["vulnerabilities_confirmed"])
            anoms = list(self.run_stats["anomalies_recorded"])
            per_rfc = dict(self.run_stats["per_rfc"])
            rfcs_sched = self.run_stats["rfcs_scheduled"] or len(per_rfc)
            rfcs_comp = self.run_stats["rfcs_completed"]
            rfcs_err = self.run_stats["rfcs_errored"]
            frags_proc = self.run_stats["fragments_processed"]
            base_gen = self.run_stats["base_probes_generated"]

        pass_pct = (passed / total_exec * 100.0) if total_exec > 0 else 0.0
        fail_pct = (failed_anom / total_exec * 100.0) if total_exec > 0 else 0.0
        err_pct = (sock_errs / total_exec * 100.0) if total_exec > 0 else 0.0
        proto_str = "https" if self.use_tls else "http"

        lines = [
            "",
            "=" * 86,
            "  SWARM RUN TELEMETRY & PASS / FAIL SUMMARY",
            "=" * 86,
            f"  Target Endpoint               : {proto_str}://{self.host}:{self.port} (TLS: {self.use_tls})",
            f"  Total Runtime                 : {elapsed:.1f}s",
            f"  RFC Specifications            : {rfcs_comp}/{rfcs_sched} completed ({rfcs_err} errored)",
            f"  RFC Fragments Analyzed        : {frags_proc} fragments -> {base_gen} base probes synthesized",
            "-" * 86,
            f"  TOTAL WIRE PROBES EXECUTED    : {total_exec}",
            f"  [+] PASSED (Target Conformant): {passed} ({pass_pct:.1f}%)",
            f"  [-] FAILED (Anomaly Triggered): {failed_anom} ({fail_pct:.1f}%)",
            f"      |- Triage Filtered/Benign : {triage_disc} (Compliant rejection / framing noise)",
            f"      +- CONFIRMED VULNS (MRE)  : {len(vulns)} (Verified across >=3 trials)",
            f"  [!] Socket / Timeout Errors   : {sock_errs} ({err_pct:.1f}%)",
            "=" * 86,
        ]

        if per_rfc:
            lines.append("  PER-RFC PASS / FAIL BREAKDOWN:")
            lines.append(f"  {'RFC':<10} | {'Frags':>5} | {'Executed':>8} | {'Passed':>8} | {'Failed':>8} | {'Vulns':>5} | {'Verdict'}")
            lines.append("  " + "-" * 82)
            for rfc_id, st in per_rfc.items():
                ex = st["executed"]
                pa = st["passed"]
                fa = st["failed_anomalies"]
                vu = st["confirmed_vulns"]
                fr = st["fragments"]
                if st.get("status") == "ERROR":
                    verdict = f"ERROR ({st.get('error', 'fault')[:24]})"
                elif st.get("status") == "UNAVAILABLE":
                    verdict = "SKIPPED (RFC unavailable)"
                elif vu > 0:
                    verdict = "FAIL (VULNERABILITY CONFIRMED)"
                elif fa > 0:
                    verdict = "WARN (ANOMALY - TRIAGED)"
                elif ex > 0:
                    verdict = "PASS (100% CONFORMANT)"
                else:
                    verdict = st.get("status", "PASS")
                lines.append(f"  {rfc_id:<10} | {fr:>5} | {ex:>8} | {pa:>8} | {fa:>8} | {vu:>5} | {verdict}")
            lines.append("=" * 86)

        if vulns:
            lines.append(f"  [!] CONFIRMED REPRODUCIBLE VULNERABILITIES ({len(vulns)}):")
            for idx, v in enumerate(vulns, 1):
                lines.append(f"    {idx}. [{v['rfc']}] {v['vuln_id']} ({v['impact']}) | Repro: {v['repro']}")
                lines.append(f"       Behavior: {v['behavior']}")
            lines.append("=" * 86)
        elif anoms:
            lines.append(f"  [*] RECORDED PROTOCOL ANOMALIES ({len(anoms)} total, {triage_disc} filtered in triage):")
            for idx, a in enumerate(anoms[:10], 1):
                lines.append(f"    {idx}. [{a['rfc']}] {a['anomaly_id']} ({a['category']}): {a['behavior'][:95]}")
            if len(anoms) > 10:
                lines.append(f"    ... and {len(anoms) - 10} additional anomalies saved in {self.db_path}")
            lines.append("=" * 86)

        overall_verdict = (
            f"FAIL ({len(vulns)} Confirmed Vulnerability/ies)"
            if vulns
            else (
                f"PASS WITH WARNINGS ({failed_anom} Anomalies Triaged, 0 Confirmed Vulns)"
                if failed_anom > 0
                else "PASS (Target Conformant Across All Executed Probes)"
            )
        )
        lines.append(f"  OVERALL RUN VERDICT: {overall_verdict}")
        lines.append("=" * 86 + "\n")

        summary_text = "\n".join(lines)
        print(summary_text)
        return summary_text

if __name__ == "__main__":
    ALL_MODES = [
        "single", "terminator", "corpus", "all", "pqc", "ruler",
        "build", "lab", "mcp", "hunt", "auto",
        "fetch", "chunk", "generate", "permute", "evaluate",
        "weaponize", "cascade", "dream", "caldera",
    ]

    parser = argparse.ArgumentParser(
        description="""
===============================================================================
RFC HUNT SWARM: Unified Autonomous Protocol Research & Compliance Engine
===============================================================================
The unified primary CLI entrypoint combining:
  - 12-Agent LangGraph Protocol Research Swarm (rfc_hunt_swarm.py)
  - One-Click Local Test Lab Auto-Launcher & Continuous Flaw Hunter (start.py)
  - Modular Pipeline, Build-All Verification, Dream-RSI & Caldera CLI (main.py)

Based on the autonomous protocol research methodology by James Kettle
(Director of Research, PortSwigger):
  "Can AI Do Novel Security Research? Meet the HTTP Terminator"
  https://portswigger.net/research/can-ai-do-novel-security-research
""",
        epilog="""
===============================================================================
USAGE EXAMPLES (All run directly via rfc_hunt_swarm.py):
===============================================================================

1. Scan a Single RFC against a local or remote target:
   python -u rfc_hunt_swarm.py --mode single --rfc 9112 --host remote-target.com --port 443 --tls --debug
   python -u rfc_hunt_swarm.py --mode single --rfc 9112 --host 127.0.0.1 --port 3030 --cycles 2 --debug

2. Scan the full 25-RFC Terminator & Gateway Suite against a Remote Host:
   python -u rfc_hunt_swarm.py --mode terminator --host remote-target.com --port 443 --tls --concurrency 8 --debug
   (Covers RFC 9112, 9110, 9111, 7230, 2616, 9113, 7540, 9297, 9651, 8297, 8446, etc.)

3. Scan James Kettle's Full 138-RFC Research Corpus against a Remote Host:
   python -u rfc_hunt_swarm.py --mode corpus --host remote-target.com --port 443 --tls --concurrency 8 --debug
   (Covers all 138 curated HTTP, caching, transport, and SMTP/MIME cross-protocol specifications)

4. Discover & Scan ALL Active IETF Protocol Specifications from the RFC Editor index:
   python -u rfc_hunt_swarm.py --mode all --host remote-target.com --port 443 --tls --concurrency 8 --debug

5. Filter Active IETF Specifications by Protocol Keywords:
   python -u rfc_hunt_swarm.py --mode all --keywords "chunked,trailer,websocket,proxy" --host remote-target.com --port 443 --tls --debug

6. Post-Quantum Cryptography (PQC) & Hybrid TLS Testing:
   python -u rfc_hunt_swarm.py --mode pqc --host remote-target.com --port 443 --tls --debug
   python -u rfc_hunt_swarm.py --mode single --rfc 9180 --host remote-target.com --port 443 --tls --debug
   python -u rfc_hunt_swarm.py --mode single --rfc 9370 --host remote-target.com --port 443 --tls --debug

7. Local Plaintext HTTP Testing (No --tls, custom port or full URL):
   python -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --debug
   python -u rfc_hunt_swarm.py --mode terminator --host http://127.0.0.1:3030/ --debug

8. High-Speed Multithreaded Evaluation (Semaphore-bounded socket thread pool):
   python -u rfc_hunt_swarm.py --mode terminator --host remote-target.com --port 443 --tls --concurrency 16

9. Protocol Ruler mode (measure front-end byte transformations using backend length limits):
   python -u rfc_hunt_swarm.py --mode ruler --host remote-target.com --port 443 --tls --debug
   python -u rfc_hunt_swarm.py --mode ruler --host 127.0.0.1 --port 3030 --sequence "\\xc0\\x8a" --name "Overlong-LF"

10. Offline RFC ingestion & probe generation into terminator.db (zero network packets sent):
    python -u rfc_hunt_swarm.py --mode terminator --comb-only --max-rfcs 25

11. Unified 'Build All' pipeline (syntax check, DB schema, 25 RFC cache, Caldera, Dream-RSI, pytest):
    python -u rfc_hunt_swarm.py --mode build
    python -u rfc_hunt_swarm.py build --skip-tests

12. Modular pipeline stages & standalone services:
    python -u rfc_hunt_swarm.py --mode lab --host 127.0.0.1 --port 8080
    python -u rfc_hunt_swarm.py --mode mcp
    python -u rfc_hunt_swarm.py --mode hunt --host 127.0.0.1 --port 3030 --max-rfcs 15
    python -u rfc_hunt_swarm.py --mode auto --host 127.0.0.1 --port 3030 --concurrency 8
    python -u rfc_hunt_swarm.py --mode dream --dream-rollouts 300
    python -u rfc_hunt_swarm.py --mode caldera --export-caldera ./caldera_export

13. List all 25 Terminator RFC Specifications and 25 Wire/Chunk Terminator Mutators:
    python -u rfc_hunt_swarm.py --list-terminators
===============================================================================
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=ALL_MODES,
        default=None,
        help="Optional positional mode/subcommand (e.g. build, ruler, lab, mcp, hunt, auto, terminator)",
    )
    parser.add_argument("--rfc", type=str, default="9112", help="Specific RFC ID to analyze (e.g. 9112 or MCP)")
    parser.add_argument(
        "--mode",
        type=str,
        choices=ALL_MODES,
        default="single",
        help="Execution mode: single, terminator, corpus, all, pqc, ruler, build, lab, mcp, hunt, auto, fetch, chunk, generate, permute, evaluate, weaponize, cascade, dream, caldera",
    )
    parser.add_argument("--list-terminators", action="store_true", help="Print the complete catalog of 25 Terminator RFC specifications and 25 wire/chunk/cross-protocol terminator mutators and exit")
    parser.add_argument("--host", "--target", dest="host", type=str, default="127.0.0.1", help="Target host (domain or IP, default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5006, help="Target port (default: 5006)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS/HTTPS for remote host (auto-enabled if port is 443)")
    parser.add_argument("--cycles", type=int, default=3, help="Max mutation cycles to run per RFC")
    parser.add_argument("--timeout", type=float, default=900.0, help="Ollama LLM inference timeout in seconds (default: 900.0 = 15m; 0 for unlimited)")
    parser.add_argument("--model", type=str, default="gemma2:2b", help="Preferred primary base model (default: gemma2:2b)")
    parser.add_argument("--sec-model", type=str, default=None, help="Secondary security specialist model (e.g. fenkohq/foundation-sec-8b:latest, qwen2.5:7b, strix-qwen:latest)")
    parser.add_argument("--no-fusion", dest="fusion", action="store_false", default=True, help="Disable multi-model panel fusion")
    parser.add_argument("--db", type=str, default="terminator.db", help="SQLite database path (default: terminator.db)")
    parser.add_argument("--cache-dir", type=str, default="rfcs", help="Local directory to cache RFCs (default: rfcs)")
    parser.add_argument("--max-rfcs", "--count", dest="max_rfcs", type=int, default=None, help="Maximum number of RFCs to cycle through")
    parser.add_argument("--keywords", type=str, default=None, help="Comma-separated keywords to filter active RFCs (e.g. 'chunked,trailer,websocket')")
    parser.add_argument("--comb-only", "--offline", dest="comb_only", action="store_true", help="Offline RFC ingestion & probe generation into database without sending packets to any host")
    parser.add_argument("--no-lab", action="store_true", help="Do not auto-spawn the built-in local TestLabServer when targeting localhost/127.0.0.1")
    parser.add_argument("--mcp", action="store_true", help="Shortcut to launch the Model Context Protocol (MCP) JSON-RPC server over stdio")
    parser.add_argument("--build", action="store_true", help="Shortcut to run the unified 'Build All' verification pipeline")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running pytest when executing --mode build / --build")
    parser.add_argument("--sequence", type=str, default=None, help="Custom byte sequence to test in Protocol Ruler mode (e.g. '\\xc0\\x8a')")
    parser.add_argument("--name", type=str, default="Custom Probe", help="Name for custom sequence in Protocol Ruler mode")
    parser.add_argument("--max-size", type=int, default=131072, help="Max header length to test in Protocol Ruler mode (default: 131072)")
    parser.add_argument("--sentences", type=int, default=2, help="Sentences per chunk in chunk/auto modes (default: 2)")
    parser.add_argument("--limit", "--fragments", dest="limit", type=int, default=5, help="Max fragments/probes to process in modular modes (default: 5)")
    parser.add_argument("--variants", type=int, default=3, help="Permutation variants per probe (default: 3)")
    parser.add_argument("--discover-recent", type=int, default=0, help="Discover recent RFCs from index in fetch/auto modes")
    parser.add_argument("--keep-going", action="store_true", help="Continue hunting after finding first flaw in hunt mode")
    parser.add_argument("--generations", type=int, default=3, help="Evolutionary dream generations (default: 3)")
    parser.add_argument("--debug", action="store_true", help="Enable comprehensive debugging mode (prints raw host responses, socket telemetry, and sequence pipeline steps)")
    parser.add_argument("--show-response", action="store_true", help="Print full raw HTTP/TLS responses received from the target host")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose execution telemetry and full payload/response tracing")
    parser.add_argument(
        "--authorized",
        "--allow-all",
        "--allow-target",
        "--allow-any",
        dest="authorized",
        action="store_true",
        help="Explicitly authorize active security testing against remote/public target (e.g. target.example.com) or allow any target",
    )
    parser.add_argument("--dream-rsi", dest="dream_rsi", action="store_true", default=True, help="Enable Open Dream-RSI: recursive off-policy self-improvement between cycles (enabled by default)")
    parser.add_argument("--no-dream-rsi", dest="dream_rsi", action="store_false", help="Disable default Open Dream-RSI evolution cycle")
    parser.add_argument("--dream-rollouts", "--rollouts", dest="dream_rollouts", type=int, default=300, help="Number of simulated rollouts per dream generation (default: 300)")
    parser.add_argument("--dream-export", "--export", dest="dream_export", type=str, default="data/dream_policies.json", help="Path to export evolved Dream-RSI policies")
    parser.add_argument("--export-caldera", type=str, default="caldera_export", help="Directory to export Caldera plugin structure (default: caldera_export, runs automatically)")
    parser.add_argument("--no-caldera", action="store_true", help="Disable default Caldera export")
    parser.add_argument("--caldera-url", "--push", dest="caldera_url", type=str, default=None, help="Optional Caldera server URL to push confirmed findings live")
    parser.add_argument("--caldera-key", "--api-key", dest="caldera_key", type=str, default=None, help="Optional Caldera API key for REST authentication")
    parser.add_argument("--concurrency", "--threads", type=int, default=8, help="Maximum concurrent probe execution threads (bounded by semaphore, default: 8)")
    args = parser.parse_args()

    # Resolve positional command / shortcut flags into active_mode
    active_mode = args.command or args.mode
    if args.build:
        active_mode = "build"
    elif args.mcp:
        active_mode = "mcp"

    if args.list_terminators:
        from engine.terminator_rfc_selector import TerminatorRFCSelector
        specs = TerminatorRFCSelector.get_terminator_specs()
        print("\n" + "=" * 78)
        print(f"  HTTP TERMINATOR RFC SUITE ({len(specs)} SPECIFICATIONS)")
        print("=" * 78)
        for idx, sp in enumerate(specs, 1):
            print(f"  {idx:2d}. {sp.rfc_id:<8} (Weight: {sp.weight:.2f}) [{sp.category}]")
            print(f"      Title : {sp.title}")
            print(f"      Focus : {sp.discrepancy_focus}")
        perm = VectorPermutator()
        muts = perm.get_terminator_mutators()
        print("\n" + "=" * 78)
        print(f"  WIRE, CHUNK & CROSS-PROTOCOL TERMINATOR MUTATORS ({len(muts)} MUTATORS)")
        print("=" * 78)
        sample_req = "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 10\r\n\r\n$PAYLOAD"
        for idx, fn in enumerate(muts, 1):
            _, m_name = fn(sample_req)
            doc = (fn.__doc__ or "").strip().splitlines()[0] if fn.__doc__ else ""
            print(f"  {idx:2d}. {m_name or fn.__name__:<45} - {doc}")
        print("=" * 78 + "\n")
        sys.exit(0)

    # Handle standalone modes that do not require target authorization first
    if active_mode == "build":
        from build_all import run_full_build
        ok = run_full_build(skip_tests=args.skip_tests)
        sys.exit(0 if ok else 1)

    if active_mode == "mcp":
        from mcp_server import TerminatorMCPServer
        print("[+] Launching Model Context Protocol (MCP) Server over JSON-RPC stdio...")
        TerminatorMCPServer().run_stdio()
        sys.exit(0)

    # Normalize args.host (strip http://, https://, trailing slashes/paths, and inline :port)
    if args.host:
        raw_h = str(args.host).strip()
        if raw_h.lower().startswith("https://"):
            args.tls = True
        clean_h = re.sub(r"^https?://", "", raw_h, flags=re.IGNORECASE).split("/")[0]
        if ":" in clean_h and not clean_h.startswith("["):
            parts = clean_h.split(":", 1)
            clean_h = parts[0]
            if len(parts) > 1 and parts[1].isdigit() and args.port == 5006:
                args.port = int(parts[1])
        args.host = clean_h

    # Authorize and validate target host specified on the CLI
    from mcp_server import TargetAuthorizationGate
    TargetAuthorizationGate.authorize_target(args.host)
    is_valid_target, target_reason = TargetAuthorizationGate.validate_target(args.host)
    if not is_valid_target:
        print(f"[!] Target validation error: {target_reason}")
        sys.exit(1)

    import os
    import socket as _sock
    os.environ["OLLAMA_TIMEOUT"] = str(args.timeout)

    use_tls = bool(args.tls or (args.port == 443))
    proto_str = "https" if use_tls else "http"

    if active_mode == "lab":
        from test_lab_server import TestLabServer
        server = TestLabServer(host=args.host, port=args.port)
        server.start()
        print(f"[*] Standalone Test Lab Server running on http://{args.host}:{args.port}. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.stop()
        sys.exit(0)

    if active_mode == "ruler":
        from protocol_ruler import ProtocolRuler
        print(f"\n{'='*75}")
        print(f"[*] LAUNCHING PROTOCOL RULER ENGINE (James Kettle Benchmark Technique)")
        print(f"[*] Target: {proto_str}://{args.host}:{args.port}")
        print(f"{'='*75}")
        ruler = ProtocolRuler(
            host=args.host,
            port=args.port,
            use_tls=use_tls,
            timeout=args.timeout if (0 < args.timeout <= 30.0) else 3.5,
            verbose=args.verbose,
            debug=args.debug,
        )
        custom_seqs = None
        if args.sequence:
            seq_str = args.sequence
            if seq_str.startswith("\\x"):
                seq_bytes = bytes.fromhex(seq_str.replace("\\x", ""))
            else:
                try:
                    seq_bytes = bytes.fromhex(seq_str)
                except ValueError:
                    seq_bytes = seq_str.encode("latin-1")
            custom_seqs = [(args.name, seq_bytes, f"Custom sequence: {seq_str}")]
        ruler.run_comprehensive_audit(custom_sequences=custom_seqs, max_size=args.max_size)
        print("\n[*] Protocol Ruler Audit Completed.")
        sys.exit(0)

    # Delegate modular pipeline subcommands from main.py if selected
    if active_mode in ("fetch", "chunk", "generate", "permute", "evaluate", "weaponize", "cascade", "dream", "caldera", "auto"):
        import main as _main_cli
        # Map unified args to main.py namespace expectations
        args.target = args.host
        args.count = args.max_rfcs or 3
        args.fragments = args.limit
        args.rollouts = args.dream_rollouts
        args.export = args.export_caldera if active_mode == "caldera" else args.dream_export
        args.push = args.caldera_url
        args.api_key = args.caldera_key
        dispatch_map = {
            "fetch": _main_cli.cmd_fetch,
            "chunk": _main_cli.cmd_chunk,
            "generate": _main_cli.cmd_generate,
            "permute": _main_cli.cmd_permute,
            "evaluate": _main_cli.cmd_evaluate,
            "weaponize": _main_cli.cmd_weaponize,
            "cascade": _main_cli.cmd_cascade,
            "dream": _main_cli.cmd_dream,
            "caldera": _main_cli.cmd_caldera,
            "auto": _main_cli.cmd_auto,
        }
        dispatch_map[active_mode](args)
        sys.exit(0)

    # Auto-spawn local TestLabServer if targeting localhost/127.0.0.1 and nothing is listening on args.port
    bg_lab_server = None
    is_local_host = args.host in ("127.0.0.1", "localhost", "::1", "[::1]")
    if is_local_host and not use_tls and not args.no_lab and not args.comb_only:
        port_open = False
        try:
            with _sock.create_connection((args.host, args.port), timeout=0.4):
                port_open = True
        except Exception:
            port_open = False
        if not port_open:
            from test_lab_server import TestLabServer
            bg_lab_server = TestLabServer(host=args.host, port=args.port)
            try:
                bg_lab_server.start()
                time.sleep(0.25)
                print(f"[+] Auto-started local Protocol Test Lab Server on http://{args.host}:{args.port}")
            except Exception as e:
                print(f"[!] Could not auto-start local Test Lab Server on {args.host}:{args.port}: {e}")
                bg_lab_server = None

    if active_mode == "hunt" or args.comb_only:
        from continuous_scanner import ContinuousFlawHunter
        kw_list = [k.strip() for k in args.keywords.split(",") if k.strip()] if args.keywords else None
        hunter = ContinuousFlawHunter(
            target_host=args.host,
            target_port=args.port,
            use_tls=use_tls,
            preferred_model=args.model,
            use_fusion=args.fusion,
            db_path=args.db,
            verbose=args.verbose or args.debug,
            sec_model=args.sec_model,
        )
        try:
            hunter.run_until_flaw(
                max_rfcs=args.max_rfcs or 15,
                fragments_per_rfc=args.limit,
                permutations_per_probe=args.variants,
                stop_on_first_flaw=not args.keep_going,
                all_active=(active_mode == "all"),
                kettle=(active_mode != "all"),
                keywords=kw_list,
                target_rfc=args.rfc if active_mode == "single" else None,
                comb_only=args.comb_only,
            )
        finally:
            if bg_lab_server:
                bg_lab_server.stop()
        sys.exit(0)

    print(f"[*] Initializing Full LangGraph Swarm against {proto_str}://{args.host}:{args.port} (TLS: {use_tls}, Concurrency: {args.concurrency} threads, LLM Timeout: {'Unlimited' if args.timeout <= 0 else f'{args.timeout}s'})")
    if args.debug:
        print("[*] Deep Swarm Debug Mode: ENABLED (Live Host Responses + Pipeline Telemetry)")
    elif args.show_response or args.verbose:
        print("[*] Live Host Response Printing: ENABLED")
    swarm = ProtocolResearchSwarm(
        host=args.host,
        port=args.port,
        db_path=args.db,
        sec_model=args.sec_model,
        use_tls=use_tls,
        show_response=args.show_response,
        verbose=args.verbose,
        debug=args.debug,
        concurrency=args.concurrency,
    )
    graph = swarm.build_graph()
    
    # Determine which RFCs to scan based on the selected mode
    kw_list = [k.strip() for k in args.keywords.split(",") if k.strip()] if args.keywords else None
    if active_mode == "single":
        rfcs_to_scan = [args.rfc.replace("RFC", "")]
    elif active_mode == "terminator":
        print("[*] Resolving Terminator Core RFC Suite (25 HTTP/1.1, H2, H3, Gateway & Framing Specs)...")
        rfcs_to_scan = swarm.fetcher.get_terminator_corpus(max_rfcs=args.max_rfcs)
    elif active_mode == "corpus":
        print("[*] Resolving James Kettle Research Corpus...")
        rfcs_to_scan = swarm.fetcher.get_kettle_corpus(max_rfcs=args.max_rfcs or 138)
    elif active_mode == "all":
        if kw_list:
            print(f"[*] Discovering active RFCs matching keywords: {kw_list}...")
            rfcs_to_scan = swarm.fetcher.get_all_active_rfcs(keywords=kw_list, max_rfcs=args.max_rfcs, reverse=True)
        else:
            print("[*] Discovering all active protocol RFCs from IETF registry...")
            rfcs_to_scan = swarm.fetcher.discover_active_protocol_rfcs(unrestricted=False, max_rfcs=args.max_rfcs)
    elif active_mode == "pqc":
        print("[*] Resolving Post-Quantum Cryptography (PQC) & Hybrid TLS Specifications...")
        rfcs_to_scan = swarm.fetcher.get_pqc_corpus()
        if args.max_rfcs:
            rfcs_to_scan = rfcs_to_scan[:args.max_rfcs]
        
    swarm.run_stats["rfcs_scheduled"] = len(rfcs_to_scan)
    print(f"\n[*] Queue ready: {len(rfcs_to_scan)} RFC(s) scheduled for Swarm processing.\n" + "="*60)

    try:
        for rfc_item in rfcs_to_scan:
            rfc_num_str = str(rfc_item)
            rfc_label = f"RFC{rfc_num_str.replace('RFC', '')}"
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
                "baseline_resp": b"",
                "enable_dream_rsi": bool(args.dream_rsi),
                "dream_rollouts": args.dream_rollouts,
                "current_dream_policy": None,
                "history": []
            }

            try:
                for event in graph.stream(initial_state, {"recursion_limit": 5000}):
                    for node_name, state_update in event.items():
                        last_hist = state_update.get('history', [])[-1] if state_update.get('history') else ''
                        print(f"[{node_name}] -> {last_hist}")
                        if "current_vuln" in state_update and state_update["current_vuln"]:
                            print(f"    !!! VULNERABILITY CONFIRMED: {state_update['current_vuln'].vuln_id}")
                with swarm.stats_lock:
                    swarm.run_stats["rfcs_completed"] += 1
                    r_st = swarm._ensure_rfc_stat(rfc_label)
                    if r_st["status"] == "RUNNING":
                        r_st["status"] = "COMPLETED"
            except Exception as e:
                print(f"[!] Swarm encountered a critical fault on RFC {rfc_num_str}: {e}")
                with swarm.stats_lock:
                    swarm.run_stats["rfcs_errored"] += 1
                    r_st = swarm._ensure_rfc_stat(rfc_label)
                    r_st["status"] = "ERROR"
                    r_st["error"] = str(e)
    except KeyboardInterrupt:
        print("\n[*] Swarm interrupted by user (Ctrl+C). Generating Pass/Fail run summary...")
    finally:
        if bg_lab_server:
            bg_lab_server.stop()
        swarm.print_run_summary()

    print("[*] Swarm Execution Completed. All evidence saved to DB and Forensics Log.")

    # Caldera Auto-Sync: Runs by default on every run without requiring any flags
    if not args.no_caldera:
        from engine.caldera_bridge import CalderaBridge
        caldera_dir = args.export_caldera or "caldera_export"
        print(f"\n[*] [Caldera Auto-Sync] Syncing verified findings to Caldera plugin at {caldera_dir}...")
        bridge = CalderaBridge(db_path=args.db)
        res = bridge.export_plugin(output_dir=caldera_dir)
        # Also sync in-tree caldera_plugin directory
        bridge.export_plugin(output_dir=".")
        print(f"[+] Caldera Auto-Sync Complete: {res['abilities_count']} abilities and {res['adversaries_count']} adversaries ready.")

    if args.caldera_url:
        from engine.caldera_bridge import CalderaBridge
        bridge = CalderaBridge(db_path=args.db)
        findings = bridge.fetch_confirmed_findings_from_db()
        abilities = [bridge.generate_ability(f) for f in findings]
        adversary = bridge.generate_adversary(abilities) if abilities else None
        res = bridge.push_to_caldera(args.caldera_url, args.caldera_key or "ADMIN123", abilities=abilities, adversary=adversary)
        print(f"[+] Caldera API Push: {res['pushed_abilities']} abilities, {res['pushed_adversaries']} adversaries pushed.")
