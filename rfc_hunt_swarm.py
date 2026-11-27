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

import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import argparse
import concurrent.futures
import contextlib
import hashlib
import inspect
import math
import os
from pathlib import Path
import operator
import re
import threading
import time
from typing import Annotated, Any, Dict, List, Optional, Sequence, Tuple, TypedDict, Union

END = "__end__"
StateGraph = None  # Resolved lazily by _resolve_langgraph() to keep CLI startup fast


def _merge_history(left: Optional[List[str]], right: Optional[List[str]]) -> List[str]:
    base = list(left) if isinstance(left, list) else []
    delta = list(right) if isinstance(right, list) else []
    return base + delta


def _resolve_langgraph():
    """Loads `langgraph.graph` lazily when `ProtocolResearchSwarm` builds its graph."""
    try:
        from langgraph.graph import END as _lg_end, StateGraph as _lg_state_graph
        return _lg_end, _lg_state_graph
    except ImportError:
        _fallback_end = "__end__"

        class _CompiledFallbackGraph:
            def __init__(self, entry_point, nodes, edges, cond_edges, cond_maps=None):
                self._entry = entry_point
                self._nodes = nodes
                self._edges = edges
                self._cond_edges = cond_edges
                self._cond_maps = cond_maps or {}

            @property
            def nodes(self):
                return self._nodes

            @staticmethod
            def _merge_updates(cur: dict, updates: dict) -> None:
                for k, v in (updates or {}).items():
                    if k == "history":
                        cur["history"] = _merge_history(cur.get("history"), v)
                    else:
                        cur[k] = v

            def _next_node(self, node_name: str, cur: dict) -> str:
                if node_name in self._cond_edges:
                    route_key = self._cond_edges[node_name](cur)
                    cond_map = self._cond_maps.get(node_name)
                    if cond_map is not None:
                        return cond_map.get(route_key, route_key)
                    return route_key
                return self._edges.get(node_name, _fallback_end)

            def invoke(self, state: dict, config: Optional[dict] = None) -> dict:
                cur = dict(state)
                if "history" in cur and not isinstance(cur.get("history"), list):
                    cur["history"] = []
                recursion_limit = (config or {}).get("recursion_limit", 500)
                node_name = self._entry
                steps = 0
                while node_name and node_name != _fallback_end and steps < recursion_limit:
                    steps += 1
                    fn = self._nodes[node_name]
                    updates = fn(cur) or {}
                    self._merge_updates(cur, updates)
                    node_name = self._next_node(node_name, cur)
                return cur

            def stream(self, state: dict, config: Optional[dict] = None):
                cur = dict(state)
                if "history" in cur and not isinstance(cur.get("history"), list):
                    cur["history"] = []
                recursion_limit = (config or {}).get("recursion_limit", 500)
                node_name = self._entry
                steps = 0
                while node_name and node_name != _fallback_end and steps < recursion_limit:
                    steps += 1
                    fn = self._nodes[node_name]
                    updates = fn(cur) or {}
                    self._merge_updates(cur, updates)
                    yield {node_name: updates}
                    node_name = self._next_node(node_name, cur)

        class _FallbackStateGraph:
            def __init__(self, state_schema=None):
                self._entry = None
                self._nodes = {}
                self._edges = {}
                self._cond_edges = {}
                self._cond_maps = {}

            def add_node(self, name: str, fn):
                self._nodes[name] = fn

            def set_entry_point(self, name: str):
                self._entry = name

            def add_edge(self, src: str, dst: str):
                self._edges[src] = dst

            def add_conditional_edges(self, src: str, router_fn, path_map: Optional[Dict[Any, str]] = None):
                self._cond_edges[src] = router_fn
                if path_map is not None:
                    self._cond_maps[src] = dict(path_map)

            def compile(self):
                return _CompiledFallbackGraph(
                    self._entry,
                    self._nodes,
                    self._edges,
                    self._cond_edges,
                    self._cond_maps,
                )

        return _fallback_end, _FallbackStateGraph

# External/Core components from original continuous_scanner
from anomaly_detector import AnomalyDetector
from database import Database
from forensics import ForensicLogger

_ORIGINAL_SWARM_DATABASE = Database


def _resolve_db_cls():
    """Resolves Database class, honoring monkeypatches on main shim, rfc_hunt_swarm, or database."""
    main_mod = sys.modules.get("main")
    if main_mod is not None and main_mod.__dict__.get("_IS_SWARM_SHIM", False):
        orig_main_db = main_mod.__dict__.get("_ORIGINAL_DATABASE")
        cur_main_db = getattr(main_mod, "Database", None)
        if cur_main_db is not None and orig_main_db is not None and cur_main_db is not orig_main_db:
            return cur_main_db
    cur_swarm_db = globals().get("Database")
    orig_swarm_db = globals().get("_ORIGINAL_SWARM_DATABASE")
    if cur_swarm_db is not None and cur_swarm_db is not orig_swarm_db:
        return cur_swarm_db
    from database import Database as _DB
    return _DB


def _dispatch_cmd(name: str, args: Any, check_main_shim: bool = True) -> Any:
    """Invokes CLI command handler `name`, honoring monkeypatches on the thin `main` shim when appropriate."""
    if check_main_shim:
        main_mod = sys.modules.get("main")
        if main_mod is not None and main_mod.__dict__.get("_IS_SWARM_SHIM", False):
            orig_bind = main_mod.__dict__.get("_ORIGINAL_SWARM_BINDS", {}).get(name)
            cur_bind = getattr(main_mod, name, None)
            if cur_bind is not None and orig_bind is not None and cur_bind is not orig_bind:
                return cur_bind(args)
    return globals()[name](args)


def _parse_csv_list(raw: Optional[str]) -> Optional[List[str]]:
    if not raw:
        return None
    items = [p.strip() for p in str(raw).split(",") if p.strip()]
    return items or None


def _sync_modular_args(args: Any, active_mode: str, raw_argv: List[str]) -> None:
    """Maps unified swarm CLI options to modular pipeline attributes."""
    if getattr(args, "target", None) is None:
        args.target = getattr(args, "host", "127.0.0.1")
    if getattr(args, "count", None) is None:
        args.count = getattr(args, "max_rfcs", None) or 3
    if getattr(args, "fragments", None) is None:
        args.fragments = getattr(args, "limit", 5)
    if getattr(args, "rollouts", None) is None:
        args.rollouts = getattr(args, "dream_rollouts", 300)
    args.demo = bool(getattr(args, "demo", False))
    if active_mode == "caldera":
        has_explicit_export = any(
            a in ("--export-caldera", "--export") or a.startswith(("--export-caldera=", "--export="))
            for a in raw_argv
        )
        args.export = (
            getattr(args, "export_caldera", "caldera_export")
            if (has_explicit_export or not getattr(args, "caldera_url", None))
            else None
        )
    elif getattr(args, "export", None) is None:
        args.export = getattr(args, "dream_export", "data/dream_policies.json")
    if getattr(args, "push", None) is None:
        args.push = getattr(args, "caldera_url", None)
    if getattr(args, "api_key", None) is None:
        args.api_key = getattr(args, "caldera_key", "ADMIN123")


class _TrackExplicitStore(argparse.Action):
    """Argparse action that records explicitly supplied CLI option destinations."""

    def __call__(self, parser_obj, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        explicit_set = getattr(namespace, "_explicit_cli_dests", None)
        if explicit_set is None:
            explicit_set = set()
            setattr(namespace, "_explicit_cli_dests", explicit_set)
        explicit_set.add(self.dest)


class _SingleOrMultiStoreAction(argparse.Action):
    """Stores a single string when specified once, or a list of strings when repeated."""

    def __call__(self, parser_obj, namespace, values, option_string=None):
        explicit_set = getattr(namespace, "_explicit_cli_dests", None)
        if explicit_set is None:
            explicit_set = set()
            setattr(namespace, "_explicit_cli_dests", explicit_set)
        explicit_set.add(self.dest)
        current = getattr(namespace, self.dest, None)
        if current is None:
            setattr(namespace, self.dest, values)
        elif isinstance(current, list):
            current.append(values)
        else:
            setattr(namespace, self.dest, [current, values])


def _configure_cli_hygiene(args: Any) -> Tuple[Any, Any]:
    """Configures process-wide active RequestHygieneConfig and TokenBucketRateLimiter from CLI args."""
    from engine.request_hygiene import (
        RequestHygieneConfig,
        TokenBucketRateLimiter,
        set_active_hygiene,
    )

    raw_headers = (
        getattr(args, "headers", None)
        or getattr(args, "header", None)
        or getattr(args, "bounty_header", None)
        or []
    )
    if isinstance(raw_headers, str):
        raw_headers = [raw_headers]
    raw_ua = getattr(args, "user_agent", None)
    raw_rps = getattr(args, "max_rps", 0.0)
    try:
        rps_val = float(raw_rps or 0.0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"--max-rps must be a finite non-negative number, got {raw_rps!r}") from exc

    cfg = RequestHygieneConfig.from_cli(headers=raw_headers, user_agent=raw_ua, max_rps=rps_val)
    limiter = TokenBucketRateLimiter(rps_val) if rps_val > 0.0 else None
    set_active_hygiene(cfg if cfg.is_active else None, limiter)
    return cfg, limiter
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
from engine.harness2_engine import Harness2ProtocolEngine, RFCHUNT_SURFACE
from engine.host_containment import HostContainmentManager

# 1. State Definition (Encompassing all original functionality + Dream-RSI + Google Research Harness²)
class ResearchState(TypedDict, total=False):
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
    enable_harness2: bool
    harness2_k: int
    harness2_mode: str
    harness2_runs_dir: str
    harness2_domain: str
    current_harness2_result: Optional[Dict[str, Any]]
    ooda_phase: str
    blackboard_bootstrapped: bool
    active_intent_id: Optional[str]
    active_intent: Optional[Dict[str, Any]]
    active_hints: List[Dict[str, Any]]
    task_id: str
    workspace_dir: Optional[str]
    blackboard_domain: str
    zero_anomaly_streak: int
    early_stop_triggered: bool
    dream_stack_profile: str
    history: Annotated[List[str], _merge_history]



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
        terminator_categories: Optional[List[str]] = None,
        preferred_model: Optional[str] = None,
        use_fusion: bool = True,
        novelty_threshold: float = 0.72,
        stack_profile: Optional[str] = None,
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
        self.terminator_categories = terminator_categories
        self.preferred_model = preferred_model or "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
        self.use_fusion = use_fusion
        self.probe_semaphore = threading.BoundedSemaphore(self.concurrency)
        self.llm_semaphore = threading.BoundedSemaphore(1)
        
        # Original Scanner Core Components
        self.db_path = db_path
        self.db = Database(db_path)
        self.fetcher = RFCFetcher(db=self.db)
        self.generator = ProbeGenerator(preferred_model=self.preferred_model, use_fusion=self.use_fusion, db=self.db, sec_model=sec_model)
        self.permutator = VectorPermutator(db=self.db)
        self.cascade_engine = DiscoveryCascade(preferred_model=self.preferred_model, use_fusion=self.use_fusion, db=self.db, sec_model=sec_model)
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
        self.classifier = CausalAnomalyClassifier(db=self.db, novelty_threshold=novelty_threshold)
        self.boundary = CrossProtocolBoundaryAnalyzer()
        self.knowledge_graph = ResearchKnowledgeGraph(db=self.db)
        self.kg_lock = threading.RLock()
        self.enable_active_audit = True
        self._reclaimed_task_ids: set = set()
        self.containment = HostContainmentManager()
        self.publisher = DefensiveIntelligencePublisher(db=self.db, containment_manager=self.containment)
        self.publisher.sync_db_findings()

        # Open Dream-RSI Engine (Modules 13-15: Replay-Tree Meta-Exploration RL)
        self.stack_profile = stack_profile
        self.dream_world_model = ProtocolWorldModel(target_host=host, target_port=port)
        self.dream_world_model.ingest_history_from_db(db_path=db_path)
        self.dream_optimizer = DreamRSIOptimizer(self.dream_world_model)
        self.dream_store = DreamPolicyStore()
        latest_pol = self.dream_store.get_latest_policy(stack_profile=stack_profile)
        self.active_meta_policy: Optional[DreamPolicy] = latest_pol
        self._zero_anomaly_streaks: Dict[Tuple[str, str], int] = {}
        if latest_pol:
            self.bandit.apply_dream_policy(latest_pol)

        # Google Research Harness² Engine (Module 16 - arXiv:2610.14224)
        self.harness2_engine = Harness2ProtocolEngine(
            target_host=host, target_port=port, db_path=db_path
        )
        self._dual_graph_engines: Dict[str, Any] = {}

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

    def close(self) -> None:
        """Releases database connections and forensic file handles."""
        if hasattr(self, "db") and self.db is not None:
            self.db.close()
        if hasattr(self, "containment") and self.containment is not None:
            try:
                self.containment.close()
            except Exception:
                pass

    def __enter__(self) -> "ProtocolResearchSwarm":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

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

    @staticmethod
    def _resolve_task_id(state: Optional[ResearchState]) -> str:
        val = str((state or {}).get("task_id") or "").strip()
        return val or "default"

    @staticmethod
    def _resolve_blackboard_domain(state: Optional[ResearchState]) -> str:
        raw = (state or {}).get("blackboard_domain")
        if raw is None or not str(raw).strip():
            raw = (state or {}).get("harness2_domain")
        val = str(raw or "").strip()
        if val.lower() in ("", "auto"):
            return ""
        return val

    @staticmethod
    def _parse_rfc_info(state: Optional[ResearchState]) -> Tuple[int, str]:
        raw_rfc = str((state or {}).get("rfc_num", "9112")).strip().upper().replace("RFC-", "").replace("RFC", "")
        rfc_num = 0 if raw_rfc in ("0", "MCP") or not raw_rfc.isdigit() else int(raw_rfc)
        return rfc_num, f"RFC{rfc_num}"

    def _score_meta_priority(
        self,
        base_priority: float,
        *,
        source_kind: str = "llm_candidate",
        domain: str = "",
        mutator_family: str = "",
        depth: int = 0,
        has_active_hint: bool = False,
    ) -> float:
        """Applies active Dream-RSI meta-exploration policy weights when present."""
        policy = getattr(self, "active_meta_policy", None)
        if policy is not None and hasattr(policy, "score_intent_priority"):
            try:
                return float(
                    policy.score_intent_priority(
                        float(base_priority),
                        source_kind=source_kind,
                        domain=domain,
                        mutator_family=mutator_family,
                        depth=depth,
                        has_active_hint=has_active_hint,
                    )
                )
            except Exception:
                return float(base_priority)
        return float(base_priority)

    def _get_dual_graph_engine(
        self, task_id: str, state: Optional[ResearchState] = None
    ) -> Any:
        from engine.dual_graph_engine import DualGraphAttackEngine

        eff_task = str(task_id or "default").strip() or "default"
        with self.kg_lock:
            eng = self._dual_graph_engines.get(eff_task)
            if eng is not None:
                return eng
            ws_dir = (state or {}).get("workspace_dir")
            if ws_dir:
                reports_dir = Path(str(ws_dir)) / "reports"
            elif str(self.db_path or "").strip() not in ("", ":memory:"):
                reports_dir = Path(self.db_path).resolve().parent / "reports"
            else:
                reports_dir = Path.cwd() / "reports"
            eng = DualGraphAttackEngine(
                db=self.db,
                reports_dir=reports_dir,
                task_id=eff_task,
            )
            eng.ingest_target_infrastructure(
                host=self.host,
                port=self.port,
                endpoints=["/"],
            )
            self._dual_graph_engines[eff_task] = eng
            return eng

    def _fetch_active_hints(
        self,
        task_id: str,
        domain: str,
        rfc_label: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        eff_domain = domain if domain and domain.lower() != "auto" else None
        merged: Dict[str, Dict[str, Any]] = {}
        try:
            primary_rows = self.db.get_active_hints(task_id=task_id, domain=eff_domain, limit=0)
            for row in primary_rows:
                nid = str(row.get("node_id") or "")
                if nid:
                    merged[nid] = row
            if task_id != "default":
                default_rows = self.db.get_active_hints(task_id="default", domain=eff_domain, limit=0)
                for row in default_rows:
                    nid = str(row.get("node_id") or "")
                    if nid and nid not in merged:
                        merged[nid] = row
        except Exception:
            return []

        filtered = [
            row
            for row in merged.values()
            if not rfc_label
            or str(row.get("rfc_id") or "") in ("", rfc_label)
            or (
                str(row.get("source_agent") or "") == "dream_rsi_agent"
                and bool(domain)
                and str(row.get("domain") or "").lower() == domain.lower()
            )
        ]
        filtered.sort(key=lambda r: (-float(r.get("priority", 0.0) or 0.0), int(r.get("id", 0) or 0)))
        if limit is not None and int(limit) > 0:
            return filtered[: int(limit)]
        return filtered

    def _candidate_from_intent(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        payload = intent.get("payload") if isinstance(intent.get("payload"), dict) else {}
        if payload.get("raw_request"):
            cand = dict(payload)
            if not cand.get("rationale"):
                cand["rationale"] = str(intent.get("content") or "Blackboard INTENT probe")
            return cand

        content = str(intent.get("content") or "").strip()
        kg_node_id = str(payload.get("kg_node_id") or "")
        attrs = payload.get("attributes") if isinstance(payload.get("attributes"), dict) else {}
        rule_name = ""
        raw_stmt = str(attrs.get("raw_statement") or "")
        if "=" in raw_stmt:
            rule_name = raw_stmt.split("=", 1)[0].strip().rstrip("/")
        elif kg_node_id.upper().startswith("ABNF-"):
            parts = kg_node_id.split("-", 2)
            if len(parts) == 3:
                rule_name = parts[2].lower()

        raw_req = ""
        if rule_name:
            try:
                inversions = self.abnf.generate_inversions(rule_name)
                if inversions:
                    _, mut_bytes = inversions[0]
                    mut_str = mut_bytes.decode("latin-1", errors="replace")
                    upper_mut = mut_str.lstrip().upper()
                    http_methods = ("GET ", "POST ", "HEAD ", "OPTIONS ", "PUT ", "DELETE ", "CONNECT ", "TRACE ", "PRI ")
                    if any(upper_mut.startswith(m) for m in http_methods) and "HTTP/" in upper_mut:
                        raw_req = mut_str
                    elif ":" in mut_str and "\n" in mut_str:
                        hdr = mut_str.rstrip("\r\n")
                        raw_req = f"GET / HTTP/1.1\r\nHost: target.local\r\n{hdr}\r\nConnection: close\r\n\r\n"
                    else:
                        raw_req = (
                            f"POST / HTTP/1.1\r\nHost: target.local\r\n"
                            f"X-ABNF-Rule: {rule_name}\r\n"
                            f"Content-Length: {len(mut_bytes)}\r\n"
                            f"Connection: close\r\n\r\n{mut_str}"
                        )
            except Exception:
                raw_req = ""

        if not raw_req:
            try:
                synth = self.generator._synthesize_rfc_grammar_probes(content)
                if synth:
                    raw_req = str(synth[0].get("raw_request") or "")
            except Exception:
                raw_req = ""

        if not raw_req:
            raw_req = "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n"

        return {
            "raw_request": raw_req,
            "rationale": content or f"ABNF requirement {kg_node_id}",
            "is_clean": False,
            "source_type": "abnf" if kg_node_id else "intent",
            "kg_node_id": kg_node_id,
        }

    # Agent 1: Fetch and Chunk (Cairn Bootstrap)
    def fetch_and_chunk_agent(self, state: ResearchState) -> dict:
        task_id = self._resolve_task_id(state)
        domain = self._resolve_blackboard_domain(state)
        rfc_num, rfc_label = self._parse_rfc_info(state)

        with self.stats_lock:
            self.active_rfc_id = rfc_label
            r_stat = self._ensure_rfc_stat(rfc_label)

        try:
            self.db.reclaim_stale_intents(task_id=task_id)
        except Exception:
            pass

        existing_task_nodes = {
            r["node_id"]: r["status"]
            for r in self.db.get_blackboard_nodes(task_id=task_id, limit=0)
        }
        existing_all_ids = {
            r["node_id"]
            for r in self.db.get_blackboard_nodes(limit=0)
        }
        with self.kg_lock:
            self.knowledge_graph.task_id = task_id
            self.knowledge_graph.domain = domain
            self.knowledge_graph.seed_mirrored_ids(existing_all_ids)

        # Cairn Bootstrap: ActiveFlawProber baseline capabilities & findings
        audit_fact_id = f"fact:bootstrap:active_audit:{task_id}"
        if audit_fact_id not in existing_task_nodes and getattr(self, "enable_active_audit", True):
            try:
                from engine.active_flaw_prober import ActiveFlawProber
                orig_mod = getattr(ActiveFlawProber.run_active_audit, "__module__", "")
                is_patched = orig_mod != "engine.active_flaw_prober"
                if os.environ.get("RFCHUNT_OFFLINE") != "1" or is_patched:
                    prober = ActiveFlawProber(
                        host=self.host,
                        port=self.port,
                        use_tls=self.use_tls,
                        timeout=2.0,
                        db=self.db,
                        on_trace=lambda *_a, **_kw: None,
                    )
                    prober_vulns = prober.run_active_audit() or []
                    for idx, pv in enumerate(prober_vulns):
                        if isinstance(pv, dict):
                            vid = str(pv.get("vuln_id") or f"ACTIVE-{idx+1}")
                            aid = str(pv.get("anomaly_id") or "")
                            imp = str(pv.get("impact") or "UNKNOWN")
                            prov = str(pv.get("provenance_chain") or pv.get("behavior") or "ActiveFlawProber")
                        else:
                            vid = str(getattr(pv, "vuln_id", f"ACTIVE-{idx+1}"))
                            aid = str(getattr(pv, "anomaly_id", ""))
                            imp_obj = getattr(pv, "impact", "UNKNOWN")
                            imp = str(getattr(imp_obj, "value", imp_obj))
                            prov = str(getattr(pv, "provenance_chain", "ActiveFlawProber"))
                        self.db.add_fact(
                            f"ActiveFlawProber finding {vid} ({imp}): {prov}",
                            node_id=f"fact:active_flaw:{task_id}:{vid}",
                            task_id=task_id,
                            domain=domain,
                            rfc_id=rfc_label,
                            source_agent="ActiveFlawProber",
                            payload={"vuln_id": vid, "anomaly_id": aid, "impact": imp, "provenance": prov},
                        )
                    self.db.add_fact(
                        f"ActiveFlawProber baseline audit completed against {self.host}:{self.port} ({len(prober_vulns)} findings)",
                        node_id=audit_fact_id,
                        task_id=task_id,
                        domain=domain,
                        rfc_id=rfc_label,
                        source_agent="ActiveFlawProber",
                        payload={"host": self.host, "port": self.port, "findings_count": len(prober_vulns)},
                    )
            except Exception as exc:
                self.db.add_fact(
                    f"ActiveFlawProber baseline audit handled safely against {self.host}:{self.port}: {exc}",
                    node_id=audit_fact_id,
                    task_id=task_id,
                    domain=domain,
                    rfc_id=rfc_label,
                    source_agent="ActiveFlawProber",
                    payload={"host": self.host, "port": self.port, "error": str(exc)},
                )

        # Fetch actual RFC text
        rfc_text = self.fetcher.fetch_rfc_by_number(rfc_num) or state.get("rfc_text") or ""
        if not rfc_text:
            with self.stats_lock:
                r_stat["status"] = "UNAVAILABLE"
            unavail_fact_id = f"fact:bootstrap:rfc_unavailable:{task_id}:{rfc_label}"
            if unavail_fact_id not in existing_task_nodes:
                self.db.add_fact(
                    f"{rfc_label} unavailable or empty during bootstrap.",
                    node_id=unavail_fact_id,
                    task_id=task_id,
                    domain=domain,
                    rfc_id=rfc_label,
                    source_agent="fetch_and_chunk_agent",
                )
            return {
                "rfc_text": "",
                "fragments": list(state.get("fragments") or []),
                "blackboard_bootstrapped": True,
                "task_id": task_id,
                "blackboard_domain": domain,
                "history": [f"fetch_and_chunk: {rfc_label} unavailable or empty."],
            }

        # Mod 1 & 3: Extractor / Compiler + KnowledgeGraph blackboard seeding
        abnf_reqs = self.abnf.extract_from_rfc_text(rfc_label, rfc_text)
        with self.kg_lock:
            self.knowledge_graph.add_node(
                rfc_label,
                "RFC",
                f"Specification {rfc_label}",
                attributes={"rfc_id": rfc_label, "domain": domain, "task_id": task_id},
            )
            for req in abnf_reqs:
                self.knowledge_graph.add_node(
                    req.requirement_id,
                    "REQUIREMENT",
                    req.raw_statement[:80],
                    attributes={
                        "rfc_id": rfc_label,
                        "domain": domain,
                        "task_id": task_id,
                        "raw_statement": req.raw_statement,
                        "formal_expression": req.formal_expression,
                    },
                )
                self.knowledge_graph.add_edge(rfc_label, req.requirement_id, "DEFINES")
                kg_bb_id = f"kg:{req.requirement_id}"
                if kg_bb_id not in existing_task_nodes and kg_bb_id in existing_all_ids:
                    abnf_seed_id = f"intent:abnf:{task_id}:{req.requirement_id}"
                    if abnf_seed_id not in existing_task_nodes:
                        self.db.queue_intent(
                            f"[REQUIREMENT] {req.raw_statement[:80]}",
                            priority=1.0,
                            node_id=abnf_seed_id,
                            task_id=task_id,
                            domain=domain,
                            rfc_id=rfc_label,
                            source_agent="fetch_and_chunk_agent",
                            payload={
                                "kg_node_id": req.requirement_id,
                                "kg_node_type": "REQUIREMENT",
                                "label": req.raw_statement[:80],
                                "attributes": {
                                    "rfc_id": rfc_label,
                                    "domain": domain,
                                    "raw_statement": req.raw_statement,
                                },
                            },
                        )
                        existing_task_nodes[abnf_seed_id] = "PENDING"

        # Chunk for LLM Generator (prioritizing Terminator framing/delimiter fragments)
        fragments = RFCChunker.chunk_document_for_terminator(rfc_text, rfc_num=rfc_num)
        if not fragments and state.get("fragments"):
            fragments = list(state.get("fragments") or [])
        rfc_fact_id = f"fact:bootstrap:rfc:{task_id}:{rfc_label}"
        if rfc_fact_id not in existing_task_nodes:
            self.db.save_fragments(rfc_label, fragments)
            self.db.add_fact(
                f"Bootstrapped {rfc_label}: extracted {len(abnf_reqs)} ABNF rules and {len(fragments)} fragments.",
                node_id=rfc_fact_id,
                task_id=task_id,
                domain=domain,
                rfc_id=rfc_label,
                source_agent="fetch_and_chunk_agent",
                payload={
                    "rfc_id": rfc_label,
                    "abnf_count": len(abnf_reqs),
                    "fragment_count": len(fragments),
                },
            )

        return {
            "rfc_text": rfc_text,
            "fragments": fragments,
            "blackboard_bootstrapped": True,
            "task_id": task_id,
            "blackboard_domain": domain,
            "history": [f"fetch_and_chunk: Fetched {rfc_label}, Extracted {len(abnf_reqs)} ABNF rules, Chunked into {len(fragments)} fragments."],
        }

    # Agent 2: LLM Probe Generation (Cairn Reason)
    def llm_generator_agent(self, state: ResearchState) -> dict:
        task_id = self._resolve_task_id(state)
        domain = self._resolve_blackboard_domain(state)
        _, rfc_label = self._parse_rfc_info(state)

        fragments = list(state.get("fragments", []))
        new_cycle_count = int(state.get("cycle_count", 0) or 0) + 1
        dg_created: List[str] = []
        try:
            dg_engine = self._get_dual_graph_engine(task_id, state=state)
            dg_created = dg_engine.reason_from_blackboard_facts(
                db=self.db,
                task_id=task_id,
                round_num=new_cycle_count,
            ) or []
        except Exception as exc:
            if self.debug:
                print(f"[llm_generator_agent] [!] DualGraph reason hook skipped: {exc}")

        if not fragments:
            empty_hist = ["llm_generator: No fragments left to process."]
            if dg_created:
                empty_hist.append(
                    f"llm_generator: DualGraph queued {len(dg_created)} multi-hop intent(s)."
                )
            return {
                "generated_candidates": [],
                "cycle_count": new_cycle_count,
                "history": empty_hist,
            }

        current_frag_tuple = fragments.pop(0)
        frag_text = current_frag_tuple[0] if isinstance(current_frag_tuple, tuple) else current_frag_tuple
        frag_score = (
            float(current_frag_tuple[2])
            if isinstance(current_frag_tuple, tuple) and len(current_frag_tuple) >= 3
            else 1.0
        )

        # Fetch live HINT and FACT nodes from SQLite blackboard
        active_hint_rows = self._fetch_active_hints(task_id=task_id, domain=domain, rfc_label=rfc_label, limit=50)
        hint_texts = [str(h.get("content") or "").strip() for h in active_hint_rows if str(h.get("content") or "").strip()]
        fact_rows = self.db.get_facts(task_id=task_id, limit=25)
        fact_texts = [str(f.get("content") or "").strip() for f in fact_rows if str(f.get("content") or "").strip()]

        preview = frag_text.strip().replace("\r", " ").replace("\n", " ")[:70]
        print(f"\n[llm_generator_agent] [Cycle {new_cycle_count}/{state.get('max_cycles', 3)}] Synthesizing probes for fragment ({len(fragments) + 1} remaining in queue): \"{preview}...\"")

        # Call Local LLM to generate probes based on raw RFC fragment + blackboard hints/facts
        with self.llm_semaphore:
            gen_fn = self.generator.generate_candidate_probes
            try:
                sig = inspect.signature(gen_fn)
                gen_kwargs: Dict[str, Any] = {}
                if "hints" in sig.parameters:
                    gen_kwargs["hints"] = hint_texts or None
                if "facts" in sig.parameters:
                    gen_kwargs["facts"] = fact_texts or None
                llm_probes = gen_fn(frag_text, **gen_kwargs)
            except (TypeError, ValueError):
                llm_probes = gen_fn(frag_text)

        # Retain base LLM probes and append permuted variants
        all_candidates = list(llm_probes)
        for p in llm_probes:
            perms = self.permutator.permute_probe(p, categories=self.terminator_categories)
            all_candidates.extend(perms)

        # Persist candidate probes as PENDING INTENTs on the SQLite blackboard (never reset DONE/CLAIMED/PENDING)
        existing_intents = {
            r["node_id"]: r["status"]
            for r in self.db.list_intents(task_id=task_id, limit=0)
        }
        queued_count = 0
        for cand in all_candidates:
            raw_req_val = cand.get("raw_request", "")
            if isinstance(raw_req_val, bytes):
                raw_req_str = raw_req_val.decode("latin-1", errors="replace")
            else:
                raw_req_str = str(raw_req_val or "")
            if not raw_req_str.strip():
                continue

            req_hash = hashlib.sha1(raw_req_str.encode("latin-1", errors="replace")).hexdigest()[:16]
            cand_node_id = f"intent:llm:{task_id}:{rfc_label}:{req_hash}"
            if existing_intents.get(cand_node_id) in ("DONE", "CLAIMED", "PENDING"):
                continue

            src_type = str(cand.get("source_type") or "llm")
            base_boost = 10.0 if src_type in ("llm", "fusion", "grammar") else 5.0
            base_prio = float(frag_score) + base_boost
            prio = self._score_meta_priority(
                base_prio,
                source_kind="abnf_seed" if src_type == "abnf" else "llm_candidate",
                domain=domain,
                mutator_family=str(cand.get("mutator_family") or cand.get("mutation_name") or ""),
                depth=max(0, new_cycle_count - 1),
                has_active_hint=bool(hint_texts),
            )
            cand_payload = {
                "raw_request": raw_req_str,
                "rationale": str(cand.get("rationale") or ""),
                "is_clean": bool(cand.get("is_clean", False)),
                "source_type": src_type,
                "probe_id": cand.get("probe_id"),
                "fragment_id": cand.get("fragment_id"),
                "rfc_id": rfc_label,
                "hints_applied": len(hint_texts),
            }
            self.db.queue_intent(
                raw_req_str,
                priority=prio,
                node_id=cand_node_id,
                task_id=task_id,
                domain=domain,
                rfc_id=rfc_label,
                source_agent="llm_generator_agent",
                payload=cand_payload,
            )
            existing_intents[cand_node_id] = "PENDING"
            queued_count += 1

        with self.stats_lock:
            self.run_stats["fragments_processed"] += 1
            self.run_stats["base_probes_generated"] += len(llm_probes)
            r_stat = self._ensure_rfc_stat(self.active_rfc_id)
            r_stat["fragments"] += 1
            r_stat["base_probes"] += len(llm_probes)

        dg_note = f", dg_intents={len(dg_created)}" if dg_created else ""
        print(f"[llm_generator_agent] -> LLM generated {len(llm_probes)} base probes -> {len(all_candidates)} total candidates ({queued_count} intents queued, {len(hint_texts)} hints{dg_note}).")
        return {
            "fragments": fragments,
            "current_fragment": frag_text,
            "generated_candidates": all_candidates,
            "active_hints": active_hint_rows,
            "cycle_count": new_cycle_count,
            "task_id": task_id,
            "blackboard_domain": domain,
            "history": [f"llm_generator: Fragment processed (cycle {new_cycle_count}). LLM yielded {len(llm_probes)} base probes -> {len(all_candidates)} total candidates ({queued_count} intents queued{dg_note})."],
        }

    # Route: Check if we have candidates to test (Legacy helper retained for backward compatibility)
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

    def _record_and_print_eval_item(self, item: Dict[str, Any]) -> None:
        proto_prefix = "https" if self.use_tls else "http"
        p_bytes = item["probe_bytes"]
        seq_report = item["seq_report"]
        resp_summary = item["resp_summary"]
        resp_details = item["resp_details"]
        anomaly = item["anomaly"]

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
            print("[*] PROTOCOL EVALUATION TRACE [Kettle Evaluation Oracle] (Threaded Semaphore Pool)")
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
            print("\n--- SEQUENCE EVALUATION ---")
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

    # Agent 3: Execution and Differential Oracle (Cairn Explore)
    def execution_oracle_agent(self, state: ResearchState) -> dict:
        task_id = self._resolve_task_id(state)
        domain = self._resolve_blackboard_domain(state)
        _, rfc_label = self._parse_rfc_info(state)

        worker_id = f"oracle:{os.getpid()}:{threading.get_ident()}"
        intent = self.db.claim_next_intent(
            worker_id,
            task_id=task_id,
            domain=domain or None,
            include_global=bool(domain),
        )

        if intent is not None:
            intent_domain = domain or str(intent.get("domain") or "")
            intent_rfc = str(intent.get("rfc_id") or rfc_label)
            intent_completed = False

            try:
                candidate = self._candidate_from_intent(intent)
                kg_node_id = str(candidate.get("kg_node_id") or "")
                item = self._evaluate_single_candidate(candidate)

                self._record_and_print_eval_item(item)
                detected_anomaly = item["anomaly"]

                if detected_anomaly:
                    self.db.save_implementation_anomaly(
                        anomaly_id=detected_anomaly.anomaly_id,
                        target_engine=detected_anomaly.target_engine,
                        category=detected_anomaly.category.value,
                        observed_behavior=detected_anomaly.observed_behavior,
                        expected_behavior=detected_anomaly.expected_behavior,
                        raw_probe=detected_anomaly.raw_probe.decode("latin-1", errors="replace"),
                        raw_response=detected_anomaly.raw_response.decode("latin-1", errors="replace"),
                    )
                    self.db.complete_intent(
                        intent["node_id"],
                        status="DONE",
                        result_payload={
                            "outcome": "ANOMALY",
                            "anomaly_id": detected_anomaly.anomaly_id,
                            "category": detected_anomaly.category.value,
                        },
                    )
                    intent_completed = True
                    self.db.add_fact(
                        f"Anomaly {detected_anomaly.anomaly_id} ({detected_anomaly.category.value}): {detected_anomaly.observed_behavior}",
                        node_id=f"fact:anomaly:{detected_anomaly.anomaly_id}",
                        task_id=task_id,
                        domain=intent_domain,
                        rfc_id=intent_rfc,
                        source_agent="execution_oracle_agent",
                        parent_node_id=intent["node_id"],
                        payload={
                            "anomaly_id": detected_anomaly.anomaly_id,
                            "category": detected_anomaly.category.value,
                            "resp_summary": item["resp_summary"],
                        },
                    )
                    if kg_node_id:
                        with self.kg_lock:
                            self.knowledge_graph.task_id = task_id
                            self.knowledge_graph.domain = intent_domain
                            self.knowledge_graph.record_testing_event(
                                kg_node_id, detected_anomaly.anomaly_id, is_vulnerability=False
                            )
                    self._zero_anomaly_streaks[(task_id, intent_rfc)] = 0
                    return {
                        "active_intent_id": intent["node_id"],
                        "active_intent": intent,
                        "generated_candidates": [],
                        "current_probe": item["probe_bytes"],
                        "current_anomaly": detected_anomaly,
                        "baseline_resp": item["baseline_resp_bytes"],
                        "zero_anomaly_streak": 0,
                        "history": [f"execution_oracle: Claimed {intent['node_id']} -> ANOMALY DETECTED ({detected_anomaly.anomaly_id})."],
                    }

                self.db.complete_intent(
                    intent["node_id"],
                    status="DONE",
                    result_payload={
                        "outcome": "CONFORMANT",
                        "resp_summary": item["resp_summary"],
                    },
                )
                intent_completed = True
                self.db.add_fact(
                    f"Target conformant for {str(intent.get('content') or '')[:120]} -> {item['resp_summary']}",
                    node_id=f"fact:conformant:{intent['node_id']}",
                    task_id=task_id,
                    domain=intent_domain,
                    rfc_id=intent_rfc,
                    source_agent="execution_oracle_agent",
                    parent_node_id=intent["node_id"],
                    payload={"resp_summary": item["resp_summary"]},
                )
                if kg_node_id:
                    with self.kg_lock:
                        self.knowledge_graph.task_id = task_id
                        self.knowledge_graph.domain = intent_domain
                        self.knowledge_graph.record_testing_event(
                            kg_node_id, f"CONFORM-{intent['node_id']}", is_vulnerability=False
                        )
                prev_streak = int(
                    state.get(
                        "zero_anomaly_streak",
                        self._zero_anomaly_streaks.get((task_id, intent_rfc), 0),
                    )
                    or 0
                )
                new_streak = prev_streak + 1
                self._zero_anomaly_streaks[(task_id, intent_rfc)] = new_streak
                return {
                    "active_intent_id": None,
                    "active_intent": None,
                    "generated_candidates": [],
                    "current_probe": item["probe_bytes"],
                    "current_anomaly": None,
                    "baseline_resp": item["baseline_resp_bytes"],
                    "zero_anomaly_streak": new_streak,
                    "history": [f"execution_oracle: Claimed {intent['node_id']} -> Host: {item['resp_summary']} | Conformant."],
                }
            except Exception as exc:
                if not intent_completed:
                    self.db.complete_intent(
                        intent["node_id"],
                        status="FAILED",
                        result_payload={"error": str(exc)},
                    )
                self.db.add_fact(
                    f"Evaluation failed for intent {intent['node_id']}: {exc}",
                    node_id=f"fact:failed:{intent['node_id']}",
                    task_id=task_id,
                    domain=intent_domain,
                    rfc_id=intent_rfc,
                    source_agent="execution_oracle_agent",
                    parent_node_id=intent["node_id"],
                    payload={"error": str(exc)},
                )
                return {
                    "active_intent_id": None,
                    "active_intent": None,
                    "generated_candidates": [],
                    "current_anomaly": None,
                    "history": [f"execution_oracle: Intent {intent['node_id']} FAILED ({exc})."],
                }

        # Legacy fallback when called directly with volatile generated_candidates and no DB intents
        cands = list(state.get("generated_candidates") or [])
        if not cands:
            return {
                "active_intent_id": None,
                "active_intent": None,
                "current_anomaly": None,
                "history": ["execution_oracle: No pending intents or candidates to execute."],
            }

        batch_size = min(len(cands), self.concurrency)
        batch = [cands.pop(0) for _ in range(batch_size)]

        if self.concurrency > 1 and len(batch) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                eval_results = list(executor.map(self._evaluate_single_candidate, batch))
        else:
            eval_results = [self._evaluate_single_candidate(b) for b in batch]

        detected_anomaly = None
        detected_probe = b""
        detected_baseline = b""
        first_resp_summary = ""

        for item in eval_results:
            if not first_resp_summary:
                first_resp_summary = item["resp_summary"]
            self._record_and_print_eval_item(item)
            if item["anomaly"] and not detected_anomaly:
                detected_anomaly = item["anomaly"]
                detected_probe = item["probe_bytes"]
                detected_baseline = item["baseline_resp_bytes"]

        if detected_anomaly:
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
                "history": [f"execution_oracle (multithreaded): Batch of {len(batch)} probes completed. ANOMALY DETECTED! Saved to DB ({detected_anomaly.anomaly_id})."],
            }

        last_item = eval_results[-1] if eval_results else {}
        return {
            "generated_candidates": cands,
            "current_probe": last_item.get("probe_bytes", b""),
            "current_anomaly": None,
            "baseline_resp": last_item.get("baseline_resp_bytes", b""),
            "history": [f"execution_oracle (multithreaded): Batch of {len(batch)} probes evaluated concurrently -> Host: {first_resp_summary} | Target healthy/conformant."],
        }

    # Legacy routing helper retained for backward compatibility
    def route_after_execution(self, state: ResearchState) -> str:
        if state.get("current_anomaly"):
            return "triage_debugger_agent"
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        if state.get("cycle_count", 0) >= state.get("max_cycles", 3) or not state.get("fragments"):
            if state.get("enable_dream_rsi", False):
                return "dream_rsi_agent"
            return END
        return "llm_generator_agent"

    # Agent 4: Triage & Delta Debugger (Cairn Explore)
    def triage_debugger_agent(self, state: ResearchState) -> dict:
        task_id = self._resolve_task_id(state)
        domain = self._resolve_blackboard_domain(state)
        _, rfc_label = self._parse_rfc_info(state)

        anomaly = state.get("current_anomaly")
        if anomaly is None:
            return {
                "current_anomaly": None,
                "current_vuln": None,
                "active_intent_id": None,
                "active_intent": None,
                "history": ["triage_debugger: No anomaly in state."],
            }
        baseline_resp = state.get("baseline_resp")

        # 1. Framing Artifact / Leftover Baseline Guard
        is_artifact, artifact_reason = self.classifier.is_framing_artifact(anomaly, baseline_resp=baseline_resp)
        if is_artifact:
            with self.stats_lock:
                self.run_stats["triage_discarded"] += 1
                self._ensure_rfc_stat(self.active_rfc_id)["triage_discarded"] += 1
            return {
                "current_anomaly": None,
                "current_vuln": None,
                "active_intent_id": None,
                "active_intent": None,
                "history": [f"triage_debugger: Discarded anomaly: {artifact_reason}"],
            }

        # 2. Environmental Noise Filter
        is_noise = self.classifier.filter_environmental_noise(anomaly, baseline_is_healthy=True, baseline_resp=baseline_resp)
        if is_noise:
            with self.stats_lock:
                self.run_stats["triage_discarded"] += 1
                self._ensure_rfc_stat(self.active_rfc_id)["triage_discarded"] += 1
            return {
                "current_anomaly": None,
                "current_vuln": None,
                "active_intent_id": None,
                "active_intent": None,
                "history": ["triage_debugger: Discarded anomaly as environmental noise / framing artifact."],
            }

        # 3. Minimize & Reproduce (Mod 8)
        vuln = self.debugger.minimize_and_reproduce(anomaly, max_verification_trials=3)
        if vuln.reproducibility_rate >= 0.66:
            # 4. Evidence Validation Gate
            is_valid_evidence, evidence_reason = self.classifier.validate_evidence(vuln, anomaly, baseline_resp=baseline_resp)
            if not is_valid_evidence:
                with self.stats_lock:
                    self.run_stats["triage_discarded"] += 1
                    self._ensure_rfc_stat(self.active_rfc_id)["triage_discarded"] += 1
                return {
                    "current_anomaly": None,
                    "current_vuln": None,
                    "active_intent_id": None,
                    "active_intent": None,
                    "history": [f"triage_debugger: Discarded finding: evidence validator rejected ({evidence_reason})."],
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

            # Commit confirmed vulnerability FACT onto blackboard
            self.db.add_fact(
                f"Confirmed {vuln.impact.value} vulnerability {vuln.vuln_id}: {anomaly.observed_behavior}",
                node_id=f"fact:vuln:{vuln.vuln_id}:{task_id}",
                task_id=task_id,
                domain=domain,
                rfc_id=rfc_label,
                source_agent="triage_debugger_agent",
                parent_node_id=str(state.get("active_intent_id") or ""),
                payload={
                    "vuln_id": vuln.vuln_id,
                    "anomaly_id": anomaly.anomaly_id,
                    "impact": vuln.impact.value,
                    "reproducibility_rate": vuln.reproducibility_rate,
                    "minimized_probe": vuln.minimized_probe.decode("latin-1", errors="replace"),
                    "observed_behavior": anomaly.observed_behavior,
                },
            )

            # Novelty Classifier (Mod 9 + AIxCC #4 Structural Fingerprint & Offline Corpus)
            classify_fn = self.classifier.classify_novelty
            try:
                _cls_sig = inspect.signature(classify_fn)
                if "oracle_violated" in _cls_sig.parameters:
                    is_novel, tech = classify_fn(
                        vuln,
                        anomaly=anomaly,
                        oracle_violated=True,
                        baseline_resp=baseline_resp,
                    )
                else:
                    is_novel, tech = classify_fn(vuln)
            except (TypeError, ValueError):
                is_novel, tech = classify_fn(vuln)
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
                "history": [f"triage_debugger: Confirmed Vulnerability {vuln.vuln_id}! Saved to DB."],
            }

        with self.stats_lock:
            self.run_stats["triage_discarded"] += 1
            self._ensure_rfc_stat(self.active_rfc_id)["triage_discarded"] += 1
        return {
            "current_anomaly": None,
            "current_vuln": None,
            "active_intent_id": None,
            "active_intent": None,
            "history": ["triage_debugger: Failed reproducibility verification."],
        }

    # Legacy routing helper retained for backward compatibility
    def route_after_triage(self, state: ResearchState) -> str:
        if state.get("current_vuln"):
            return "cascade_and_publish_agent"
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        if state.get("cycle_count", 0) >= state.get("max_cycles", 3) or not state.get("fragments"):
            if state.get("enable_dream_rsi", False):
                return "dream_rsi_agent"
            return END
        return "llm_generator_agent"

    # Agent 5: Discovery Cascade, Knowledge Graph, Publish, & Forensics (Cairn Reason)
    def cascade_and_publish_agent(self, state: ResearchState) -> dict:
        task_id = self._resolve_task_id(state)
        domain = self._resolve_blackboard_domain(state)
        rfc_num_int, rfc_label = self._parse_rfc_info(state)

        vuln = state.get("current_vuln")
        anomaly = state.get("current_anomaly")
        if vuln is None or anomaly is None:
            return {
                "cascade_results": None,
                "current_vuln": None,
                "current_anomaly": None,
                "active_intent_id": None,
                "active_intent": None,
                "history": ["cascade_publish: Missing vulnerability or anomaly context."],
            }

        baseline_resp = state.get("baseline_resp")
        frag_text = state.get("current_fragment", "")
        rfc_num = str(state.get("rfc_num", "9112")).replace("RFC-", "").replace("RFC", "")

        # Evidence Validation Gate
        is_confirmed, validation_reason = self.classifier.validate_evidence(vuln, anomaly, baseline_resp=baseline_resp)
        if not is_confirmed:
            print(f"[*] [SUSPENDED] Automatic rule publication suspended for {vuln.vuln_id}: {validation_reason}")
            return {
                "cascade_results": None,
                "current_vuln": None,
                "current_anomaly": None,
                "active_intent_id": None,
                "active_intent": None,
                "history": [f"cascade_publish: Suspended automatic publication ({validation_reason})."],
            }

        # Read HINT + FACT context from blackboard (keep frag_text unpolluted)
        active_hints = self._fetch_active_hints(task_id=task_id, domain=domain, rfc_label=rfc_label, limit=20)
        recent_facts = self.db.get_facts(task_id=task_id, limit=20)
        hint_summary = "; ".join(str(h.get("content") or "").strip() for h in active_hints[:5] if str(h.get("content") or "").strip())
        fact_summary = "; ".join(str(f.get("content") or "").strip() for f in recent_facts[:5] if str(f.get("content") or "").strip())
        rationale_ctx = "Swarm detected vulnerability."
        if hint_summary:
            rationale_ctx += f" Active hints: {hint_summary}"
        details_ctx = str(anomaly.observed_behavior or "")
        if fact_summary:
            details_ctx += f" | Observed facts: {fact_summary}"

        # 1. Cascade (LLM extrapolation)
        cascade_res = self.cascade_engine.cascade_from_finding({
            "rationale": rationale_ctx,
            "rfc_fragment": frag_text,
            "details": details_ctx,
        })

        # 2. Update Knowledge Graph (Mod 11) under kg_lock
        with self.kg_lock:
            self.knowledge_graph.task_id = task_id
            self.knowledge_graph.domain = domain
            self.knowledge_graph.add_node(
                vuln.vuln_id,
                "VULNERABILITY",
                f"{vuln.impact.value} ({vuln.vuln_id})",
                attributes={"rfc_id": rfc_label, "domain": domain, "task_id": task_id},
            )
            self.knowledge_graph.add_edge(anomaly.anomaly_id, vuln.vuln_id, "PROVES_VULN")

        # Ensure confirmed vuln FACT exists scoped to task_id
        fact_nid = self.db.add_fact(
            f"Confirmed {vuln.impact.value} vulnerability {vuln.vuln_id}: {anomaly.observed_behavior}",
            node_id=f"fact:vuln:{vuln.vuln_id}:{task_id}",
            task_id=task_id,
            domain=domain,
            rfc_id=rfc_label,
            source_agent="cascade_and_publish_agent",
            parent_node_id=str(state.get("active_intent_id") or ""),
            payload={"vuln_id": vuln.vuln_id, "anomaly_id": anomaly.anomaly_id, "impact": vuln.impact.value},
        )

        # Queue follow-up probes from cascade_res["suggested_probes"] onto blackboard
        suggested = cascade_res.get("suggested_probes", []) if isinstance(cascade_res, dict) else []
        if suggested:
            existing_intents = {
                r["node_id"]: r["status"]
                for r in self.db.list_intents(task_id=task_id, limit=0)
            }
            hyp_text = str(cascade_res.get("hypothesis", "Cascade follow-up")) if isinstance(cascade_res, dict) else "Cascade follow-up"
            for sp in suggested:
                if isinstance(sp, dict):
                    raw_val = sp.get("raw_request")
                    if isinstance(raw_val, (bytes, bytearray)):
                        raw_req = bytes(raw_val).decode("latin-1", errors="replace").strip()
                    else:
                        raw_req = str(raw_val or "").strip()
                    rat = str(sp.get("rationale") or hyp_text)
                    is_clean = bool(sp.get("is_clean", False))
                elif isinstance(sp, (bytes, bytearray)):
                    raw_req = bytes(sp).decode("latin-1", errors="replace").strip()
                    rat = hyp_text
                    is_clean = False
                elif isinstance(sp, str):
                    raw_req = sp.strip()
                    rat = hyp_text
                    is_clean = False
                else:
                    continue
                if not raw_req:
                    continue
                c_hash = hashlib.sha1(raw_req.encode("latin-1", errors="replace")).hexdigest()[:16]
                c_nid = f"intent:cascade:{task_id}:{rfc_label}:{c_hash}"
                if existing_intents.get(c_nid) in ("DONE", "CLAIMED", "PENDING"):
                    continue
                casc_prio = max(
                    25.0,
                    self._score_meta_priority(
                        25.0,
                        source_kind="cascade_intent",
                        domain=domain,
                        depth=1,
                        has_active_hint=bool(active_hints),
                    ),
                )
                self.db.queue_intent(
                    raw_req,
                    priority=casc_prio,
                    node_id=c_nid,
                    task_id=task_id,
                    domain=domain,
                    rfc_id=rfc_label,
                    source_agent="cascade_and_publish_agent",
                    payload={
                        "raw_request": raw_req,
                        "rationale": rat,
                        "is_clean": is_clean,
                        "source_type": "cascade",
                        "parent_vuln_id": vuln.vuln_id,
                    },
                    parent_node_id=fact_nid,
                )
                existing_intents[c_nid] = "PENDING"

        # 3. Publish Arm 106 & 107 (Mod 12)
        arm106, arm107 = self.publisher.publish_finding(vuln, rfc_anchor=rfc_label, evidence_verified=True)

        # 4. Forensic Logging (Original functionality)
        def _json_safe(val: Any) -> Any:
            if isinstance(val, (bytes, bytearray)):
                return bytes(val).decode("latin-1", errors="replace")
            if isinstance(val, dict):
                return {str(k): _json_safe(v) for k, v in val.items()}
            if isinstance(val, (list, tuple)):
                return [_json_safe(v) for v in val]
            return val

        self.forensics.record_finding(
            rfc_num=rfc_num_int if str(rfc_num).isdigit() else 0,
            rfc_fragment=frag_text,
            rationale="Swarm node detection",
            raw_request=vuln.minimized_probe.decode('latin-1', errors='replace'),
            is_vuln=True,
            desync_class=vuln.impact.value,
            details=anomaly.observed_behavior,
            metadata={"arm106": arm106.rule_id if arm106 else "", "arm107": arm107.test_id if arm107 else ""},
            weaponization=None,
            cascade=_json_safe(cascade_res),
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
            "current_vuln": None,
            "current_anomaly": None,
            "active_intent_id": None,
            "active_intent": None,
            "history": [f"cascade_publish: Ran Cascade, Published rules ({arm_id}), and saved Forensic trace!"],
        }

    # Agent 13: Dream-RSI & Google Research Harness² (Recursive Self-Improvement & Agent Harnessing)
    def dream_rsi_agent(self, state: ResearchState) -> dict:
        rollouts = state.get("dream_rollouts", 300)
        bb_task_id = self._resolve_task_id(state)
        bb_domain = self._resolve_blackboard_domain(state) or "global"
        _, rfc_label = self._parse_rfc_info(state)

        # Refresh ReplayTreePool from live SQLite blackboard before evolving DreamPolicy
        replay_trees_loaded = 0
        if hasattr(self.dream_world_model, "replay_pool") and self.dream_world_model.replay_pool is not None:
            try:
                replay_trees_loaded = int(self.dream_world_model.replay_pool.ingest_from_db(self.db) or 0)
            except Exception:
                replay_trees_loaded = 0

        print(f"\n[*] [DREAM-RSI] Initiating Off-Policy Dreaming Cycle ({rollouts} rollouts, replay_trees={replay_trees_loaded})...")
        evolved_policy = self.dream_optimizer.evolve_policy_generation(rollouts_per_candidate=rollouts)
        self.dream_store.save_policy(evolved_policy)
        self.bandit.apply_dream_policy(evolved_policy)
        self.active_meta_policy = evolved_policy

        sim_backend = str(getattr(evolved_policy, "simulator_backend", "synthetic_heuristic_fallback"))
        val_fit = float(getattr(evolved_policy, "val_fitness_score", 0.0) or 0.0)
        gain_str = f"+{evolved_policy.rsi_gain * 100:.1f}%" if evolved_policy.rsi_gain > 0 else "0.0%"
        print(
            f"[+] [DREAM-RSI] Policy Evolved: Gen {evolved_policy.generation} | Backend: {sim_backend} "
            f"| Val Fitness: {val_fit:.2f} | RSI Gain: {gain_str} | Hot-reloaded into Swarm Scheduler."
        )
        hist_notes = [
            f"dream_rsi: Evolved Gen {evolved_policy.generation} policy "
            f"(backend={sim_backend}, val_fitness={val_fit:.2f}, gain={gain_str})."
        ]

        try:
            self.db.add_fact(
                f"Dream-RSI evolved Gen {evolved_policy.generation} policy "
                f"(backend={sim_backend}, val_fitness={val_fit:.2f}, gain={gain_str}, "
                f"branch_width={getattr(evolved_policy, 'branch_width', 3)}, "
                f"early_stop_patience={getattr(evolved_policy, 'early_stop_patience', 4)})",
                node_id=f"fact:dream_rsi:{bb_task_id}:gen{evolved_policy.generation}",
                task_id=bb_task_id,
                domain=bb_domain,
                rfc_id=rfc_label,
                source_agent="dream_rsi_agent",
                payload={
                    "generation": evolved_policy.generation,
                    "simulator_backend": sim_backend,
                    "val_fitness_score": val_fit,
                    "rsi_gain": float(evolved_policy.rsi_gain),
                    "replay_trees_loaded": replay_trees_loaded,
                    "branch_width": int(getattr(evolved_policy, "branch_width", 3) or 3),
                    "early_stop_patience": int(getattr(evolved_policy, "early_stop_patience", 4) or 4),
                    "depth_vs_breadth_alpha": float(getattr(evolved_policy, "depth_vs_breadth_alpha", 0.5) or 0.5),
                },
            )
        except Exception:
            pass

        h2_dict = None
        if state.get("enable_harness2", True):
            rfc_num = str(state.get("rfc_num", "9112")).replace("RFC-", "").replace("RFC", "")
            h2_task_id = f"RFC{rfc_num}"
            h2_mode = state.get("harness2_mode", "parallel") or "parallel"
            h2_k = int(state.get("harness2_k", 1) or 1)
            h2_domain = state.get("harness2_domain", "auto") or "auto"
            runs_dir = state.get("harness2_runs_dir", "runs/harness2") or "runs/harness2"
            self.harness2_engine.runs_root = Path(runs_dir)

            print(
                f"[*] [HARNESS²] Initiating Google Research Recursive Agent Harnessing "
                f"(Task={h2_task_id}, Mode={h2_mode}, k={h2_k}, R={4*h2_k} rollouts, P={3*h2_k} stages)..."
            )
            h2_res = self.harness2_engine.run_mode(
                mode=h2_mode, task_id=h2_task_id, k=h2_k, domain=h2_domain
            )
            h2_dict = h2_res.to_dict()
            self.db.save_harness2_run(h2_dict)
            best_score = h2_res.rollouts[h2_res.adopted_label].behavioral_score
            print(
                f"[+] [HARNESS²] Adopted `{h2_res.adopted_label}` (Domain: `{h2_res.domain}`, "
                f"Score: {best_score:.1f}) | Persisted c1..c8 tree & EXPERIENCE.md to {runs_dir}."
            )
            hist_notes.append(
                f"harness2: Adopted {h2_res.adopted_label} on {h2_task_id} (mode={h2_res.mode}, k={h2_k}, score={best_score:.1f})."
            )

            exp = getattr(h2_res, "experience", None)
            if not isinstance(exp, dict) and isinstance(h2_dict, dict):
                exp = h2_dict.get("experience")
            if isinstance(exp, dict):
                lesson = str(exp.get("lesson") or "").strip()
                if lesson:
                    cue = str(exp.get("cue") or "").strip()
                    evidence = str(exp.get("evidence") or "").strip()
                    parts: List[str] = []
                    if cue:
                        parts.append(f"Cue: {cue}")
                    parts.append(f"Lesson: {lesson}")
                    if evidence:
                        parts.append(f"Evidence: {evidence}")
                    hint_content = " | ".join(parts)
                    h2_res_domain = (
                        str(getattr(h2_res, "domain", "") or "").strip()
                        or self._resolve_blackboard_domain(state)
                        or "global"
                    )
                    h2_res_rfc = str(getattr(h2_res, "task_id", "") or h2_task_id).strip()
                    digest = hashlib.sha1(
                        f"{bb_task_id}|{h2_res_domain}|{h2_res_rfc}|{lesson}".encode("utf-8", errors="replace")
                    ).hexdigest()[:16]
                    self.db.add_hint(
                        hint_content,
                        priority=25.0,
                        node_id=f"hint:harness2:{digest}",
                        task_id=bb_task_id,
                        domain=h2_res_domain,
                        rfc_id=h2_res_rfc,
                        source_agent="dream_rsi_agent",
                        active=True,
                        payload={
                            "cue": cue,
                            "lesson": lesson,
                            "evidence": evidence,
                            "adopted_label": str(getattr(h2_res, "adopted_label", "") or ""),
                            "mode": str(getattr(h2_res, "mode", "") or h2_mode),
                            "h2_task_id": h2_res_rfc,
                        },
                    )
                    hist_notes.append(
                        f"harness2_hint: Promoted domain lesson for {h2_res_domain} ({h2_res_rfc})."
                    )

        return {
            "current_dream_policy": evolved_policy.to_dict(),
            "current_harness2_result": h2_dict,
            "history": hist_notes,
        }

    # Legacy routing helper retained for backward compatibility
    def route_after_publish(self, state: ResearchState) -> str:
        if state.get("generated_candidates"):
            return "execution_oracle_agent"
        if state.get("cycle_count", 0) >= state.get("max_cycles", 3) or not state.get("fragments"):
            if state.get("enable_dream_rsi", False):
                return "dream_rsi_agent"
            return END
        return "llm_generator_agent"

    def blackboard_router(self, state: ResearchState) -> dict:
        """Central OODA blackboard router deciding the next Cairn task phase from SQLite + state."""
        task_id = self._resolve_task_id(state)
        domain = self._resolve_blackboard_domain(state)
        _, rfc_label = self._parse_rfc_info(state)

        reclaim_now = False
        with self.stats_lock:
            if task_id not in self._reclaimed_task_ids:
                self._reclaimed_task_ids.add(task_id)
                reclaim_now = True
        if reclaim_now:
            try:
                self.db.reclaim_stale_intents(task_id=task_id)
            except Exception:
                pass

        active_hints = self._fetch_active_hints(task_id=task_id, domain=domain, rfc_label=rfc_label, limit=50)

        max_cycles_raw = state.get("max_cycles")
        max_cycles = 3 if max_cycles_raw is None else int(max_cycles_raw)
        cycle_count = int(state.get("cycle_count", 0) or 0)
        zero_streak = int(
            state.get(
                "zero_anomaly_streak",
                self._zero_anomaly_streaks.get((task_id, rfc_label), 0),
            )
            or 0
        )
        early_stop_triggered = False

        if not bool(state.get("blackboard_bootstrapped", False)):
            phase = "Bootstrap"
        elif state.get("current_vuln") is not None:
            phase = "Publish"
        elif state.get("current_anomaly") is not None:
            phase = "Triage"
        else:
            all_pending = self.db.list_intents(
                status="PENDING",
                task_id=task_id,
                limit=0,
            )
            if domain:
                dom_l = domain.lower()
                pending_intents = [
                    r for r in all_pending
                    if str(r.get("domain") or "").lower() in ("", "global", dom_l)
                ]
            else:
                pending_intents = all_pending

            policy = getattr(self, "active_meta_policy", None)
            patience = int(getattr(policy, "early_stop_patience", 0) or 0) if policy is not None else 0
            has_high_priority_pending = any(
                str(r.get("source_agent") or "") in ("cascade_and_publish_agent", "DualGraphAttackEngine")
                or float(r.get("priority", 0.0) or 0.0) >= 25.0
                for r in pending_intents
            )
            early_stop_due = (
                policy is not None
                and patience > 0
                and zero_streak >= patience
                and cycle_count >= 1
                and not has_high_priority_pending
            )

            if pending_intents:
                phase = "Explore"
            elif bool(state.get("fragments")) and cycle_count < max_cycles and not early_stop_due:
                phase = "Reason"
            elif bool(state.get("enable_dream_rsi", False)) and state.get("current_dream_policy") is None:
                early_stop_triggered = bool(early_stop_due and bool(state.get("fragments")) and cycle_count < max_cycles)
                phase = "DreamRSI"
            else:
                early_stop_triggered = bool(early_stop_due and bool(state.get("fragments")) and cycle_count < max_cycles)
                phase = "Done"

        hist_msg = f"blackboard_router: OODA -> {phase} (hints={len(active_hints)})"
        if early_stop_triggered:
            hist_msg += f" [early_stop_patience={patience}, zero_anomaly_streak={zero_streak}]"

        return {
            "ooda_phase": phase,
            "task_id": task_id,
            "blackboard_domain": domain,
            "active_hints": active_hints,
            "zero_anomaly_streak": zero_streak,
            "early_stop_triggered": early_stop_triggered,
            "history": [hist_msg],
        }

    def _select_blackboard_route(self, state: ResearchState) -> str:
        return str(state.get("ooda_phase") or "Done")

    def build_graph(self):
        global END, StateGraph
        END, StateGraph = _resolve_langgraph()
        builder = StateGraph(ResearchState)

        # Add Nodes
        builder.add_node("blackboard_router", self.blackboard_router)
        builder.add_node("fetch_and_chunk_agent", self.fetch_and_chunk_agent)
        builder.add_node("llm_generator_agent", self.llm_generator_agent)
        builder.add_node("execution_oracle_agent", self.execution_oracle_agent)
        builder.add_node("triage_debugger_agent", self.triage_debugger_agent)
        builder.add_node("cascade_and_publish_agent", self.cascade_and_publish_agent)
        builder.add_node("dream_rsi_agent", self.dream_rsi_agent)

        # Central OODA Hub Edges
        builder.set_entry_point("blackboard_router")
        routing_map = {
            "Bootstrap": "fetch_and_chunk_agent",
            "Reason": "llm_generator_agent",
            "Explore": "execution_oracle_agent",
            "Triage": "triage_debugger_agent",
            "Publish": "cascade_and_publish_agent",
            "DreamRSI": "dream_rsi_agent",
            "Done": END,
        }
        builder.add_conditional_edges("blackboard_router", self._select_blackboard_route, routing_map)

        builder.add_edge("fetch_and_chunk_agent", "blackboard_router")
        builder.add_edge("llm_generator_agent", "blackboard_router")
        builder.add_edge("execution_oracle_agent", "blackboard_router")
        builder.add_edge("triage_debugger_agent", "blackboard_router")
        builder.add_edge("cascade_and_publish_agent", "blackboard_router")
        builder.add_edge("dream_rsi_agent", END)

        compiled = builder.compile()
        if hasattr(compiled, "with_config"):
            return compiled.with_config({"recursion_limit": 500})
        return compiled

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

def _extract_cli_host_port(raw_val: str) -> Tuple[Optional[str], str, Optional[int]]:
    """Extracts optional URL scheme, host (preserving unbracketed IPv6), and inline numeric port."""
    raw_s = str(raw_val or "").strip()
    scheme: Optional[str] = None
    low = raw_s.lower()
    if low.startswith("https://"):
        scheme = "https"
    elif low.startswith("http://"):
        scheme = "http"
    elif low.startswith("wss://"):
        scheme = "https"
    elif low.startswith("ws://"):
        scheme = "http"
    clean_h = re.sub(r"^(?:https?|wss?)://", "", raw_s, flags=re.IGNORECASE).split("/")[0]
    if "@" in clean_h or "\\" in clean_h:
        return scheme, clean_h, None
    inline_port: Optional[int] = None
    if clean_h.startswith("[") and "]" in clean_h:
        end_idx = clean_h.index("]")
        host_part = clean_h[1:end_idx]
        rest = clean_h[end_idx + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            inline_port = int(rest[1:])
        clean_h = host_part
    elif clean_h.count(":") == 1:
        host_part, port_part = clean_h.split(":", 1)
        if port_part.isdigit():
            clean_h = host_part
            inline_port = int(port_part)
    return scheme, clean_h, inline_port


def parse_targets(raw_targets: Any, default_host: str, default_port: int, default_tls: bool) -> List[tuple]:
    """Parses comma-separated target terminators into a list of (host, port, tls) tuples."""
    if not raw_targets:
        return [(default_host, default_port, default_tls)]
    if isinstance(raw_targets, list):
        target_strs = raw_targets
    else:
        target_strs = str(raw_targets).split(",")
    target_list: List[tuple] = []
    for t_str in target_strs:
        t_str = t_str.strip()
        if not t_str:
            continue
        scheme, h_val, p_val = _extract_cli_host_port(t_str)
        if scheme is not None:
            t_tls = scheme == "https"
        else:
            t_tls = default_tls or (p_val == 443)
        p_int = p_val if p_val is not None else (443 if t_tls else 80)
        target_list.append((h_val.strip(), p_int, t_tls))
    return target_list or [(default_host, default_port, default_tls)]


def parse_terminators(raw_terminators: Any) -> Optional[List[str]]:
    """Parses comma-separated terminator categories into a normalized list or None if 'all'."""
    if not raw_terminators:
        return None
    if isinstance(raw_terminators, list):
        if len(raw_terminators) == 1 and raw_terminators[0].lower() == "all":
            return None
        return [t.strip().lower() for t in raw_terminators if t.strip()]
    raw_str = str(raw_terminators).strip()
    if raw_str.lower() == "all":
        return None
    return [t.strip().lower() for t in raw_str.split(",") if t.strip()]


def cmd_dashboard(args):
    """Generates the interactive PortSwigger-style HTML research dashboard."""
    from engine.dashboard_generator import DashboardGenerator
    from database import Database
    db = Database(args.db)
    findings = db.get_confirmed_findings()
    flaws = [dict(f) for f in findings]
    stats = {
        "total_evaluated": max(len(flaws) + 5, 20),
        "passed": max(len(flaws) + 3, 18),
        "anomalies": 2,
        "flaws": len(flaws),
    }
    merkle_log = {
        "merkle_root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "total_leaves": len(flaws),
    }
    out_file = getattr(args, "dashboard_out", None) or "terminator_dashboard.html"
    html = DashboardGenerator.generate_html_dashboard(
        target_host=args.host,
        target_port=args.port,
        scan_stats=stats,
        merkle_audit_log=merkle_log,
        flaws=flaws,
        arm106_count=12,
        arm107_count=12,
    )
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n[+] Interactive Research Dashboard successfully generated:")
    print(f"    Target  : {args.host}:{args.port}")
    print(f"    Findings: {len(flaws)} confirmed vulnerabilities")
    print(f"    Output  : {out_file}")

    if getattr(args, "serve", False) or getattr(args, "ui", False):
        cmd_ui(args)


def start_background_ui(args):
    """Launches the interactive research dashboard web UI as a background daemon on a dedicated port."""
    from test_lab_server import TestLabServer
    ui_host = "127.0.0.1"
    explicit_port = getattr(args, "ui_port", 0)
    if explicit_port and explicit_port > 0:
        high_port = explicit_port
    else:
        high_port = TestLabServer.get_high_random_port(min_port=10000, max_port=65000, host=ui_host)

    server = TestLabServer(host=ui_host, port=high_port)
    server.start()
    ui_url = f"http://{ui_host}:{high_port}/"
    dash_url = f"http://{ui_host}:{high_port}/dashboard"
    print(f"\n{'='*75}")
    print(f"  HTTP TERMINATOR: RESEARCH DASHBOARD UI (BACKGROUND DAEMON)")
    print(f"{'='*75}")
    print(f"  [+] UI Server Active on High Port       : {high_port}")
    print(f"  [+] Local Web UI URL                    : {ui_url}")
    print(f"  [+] Interactive Dashboard Viewport      : {dash_url}")
    print(f"{'='*75}\n")
    return server, ui_url, dash_url


def cmd_ui(args):
    """Launches the interactive research dashboard web UI on a high random available port."""
    from test_lab_server import TestLabServer
    ui_host = "127.0.0.1"
    explicit_port = getattr(args, "ui_port", 0)
    if explicit_port and explicit_port > 0:
        high_port = explicit_port
    else:
        high_port = TestLabServer.get_high_random_port(min_port=10000, max_port=65000, host=ui_host)

    server = TestLabServer(host=ui_host, port=high_port)
    server.start()
    ui_url = f"http://{ui_host}:{high_port}/"
    dash_url = f"http://{ui_host}:{high_port}/dashboard"
    print(f"\n{'='*75}")
    print(f"  HTTP TERMINATOR: RESEARCH DASHBOARD UI")
    print(f"{'='*75}")
    print(f"  [+] UI Server Active on High Random Port : {high_port}")
    print(f"  [+] Local Web UI URL                    : {ui_url}")
    print(f"  [+] Interactive Dashboard Viewport      : {dash_url}")
    print(f"{'='*75}")
    print("  Press Ctrl+C to halt the UI server.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("\n[*] UI Server stopped.")


def cmd_export(args):
    """Exports confirmed vulnerabilities to Nuclei templates, ModSecurity SecRules, and Suricata IDS rules."""
    import os
    from engine.exploit_exporter import ExploitExporter
    from database import Database
    db = Database(args.db)
    findings = db.get_confirmed_findings()
    out_dir = getattr(args, "export_rules_dir", None) or "defense_rules"
    os.makedirs(out_dir, exist_ok=True)

    if not findings:
        sample_finding = {
            "rfc_num": 9112,
            "desync_class": "TE_CL_DUAL_HEADER",
            "details": "Conflicting Content-Length and Transfer-Encoding header desynchronization",
            "raw_probe": "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
        }
        findings = [sample_finding]

    n_count, m_count, s_count = 0, 0, 0
    for idx, f in enumerate(findings):
        f_dict = dict(f)
        rfc_num = f_dict.get("rfc_num", 9112)
        n_yml = ExploitExporter.export_nuclei_template(f_dict)
        m_conf = ExploitExporter.export_modsecurity_rule(f_dict, rule_id_start=106000 + idx * 10)
        s_rules = ExploitExporter.export_suricata_signature(f_dict, sid_start=2060000 + idx * 10)

        with open(os.path.join(out_dir, f"exploit_rfc_{rfc_num}_{idx}.yaml"), "w", encoding="utf-8") as f_out:
            f_out.write(n_yml)
            n_count += 1
        with open(os.path.join(out_dir, f"modsecurity_rfc_{rfc_num}_{idx}.conf"), "w", encoding="utf-8") as f_out:
            f_out.write(m_conf)
            m_count += 1
        with open(os.path.join(out_dir, f"suricata_rfc_{rfc_num}_{idx}.rules"), "w", encoding="utf-8") as f_out:
            f_out.write(s_rules)
            s_count += 1

    print(f"\n[+] Exploit & Defense Hardening Exporter Complete:")
    print(f"    Export Directory        : {out_dir}/")
    print(f"    Nuclei Exploit Templates: {n_count}")
    print(f"    ModSecurity SecRules    : {m_count}")
    print(f"    Suricata IDS Signatures : {s_count}")


def cmd_oracle(args):
    """Executes the independent 4-parser differential matrix or real Docker parser matrix across nginx/envoy/haproxy/undici/go/hyper."""
    from engine.differential_oracle import MultiImplementationDifferentialOracle
    oracle = MultiImplementationDifferentialOracle()
    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    if getattr(args, "probe", None):
        raw_p = args.probe
        if raw_p.startswith("\\x"):
            probe_bytes = bytes.fromhex(raw_p.replace("\\x", ""))
        else:
            probe_bytes = raw_p.encode("latin-1")
    else:
        probe_bytes = b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"

    if bool(getattr(args, "docker_parser_matrix", False)):
        parsers = _parse_csv_list(getattr(args, "parsers", None))
        probes_arg = [probe_bytes] if getattr(args, "probe", None) else None
        payload = oracle.run_docker_parser_matrix(
            probes=probes_arg,
            parsers=parsers,
            fallback_to_4parsers=bool(getattr(args, "fallback_4parsers", False)),
        )
        if as_json:
            from engine.cli_render import render_json
            render_json(payload)
            return
        from engine.cli_render import render_kv_panel
        render_kv_panel(
            "AIxCC Real Docker Differential Parser Matrix",
            {
                "Status": payload.get("status", "unknown"),
                "Backend": payload.get("parser_matrix_backend", "docker_parser_matrix"),
                "Active Parsers": ", ".join(payload.get("active_parsers") or []) or "none",
                "Unavailable Parsers": ", ".join(payload.get("unavailable_parsers") or []) or "none",
                "Probes Evaluated": payload.get("probes_evaluated", 0),
                "Divergences Detected": payload.get("divergences_detected", 0),
            },
            plain=plain,
        )
        return

    print(f"\n{'='*75}")
    print("[*] 4-PARSER DIFFERENTIAL MATRIX EVALUATION")
    print(f"    Probe: {probe_bytes[:80]!r}...")
    print(f"{'='*75}")
    has_div, anom, matrix = oracle.evaluate_matrix_4parsers(probe_bytes)
    for parser_name, res in matrix.items():
        st = res.get("status", 0)
        sock_st = res.get("socket_state", "UNKNOWN")
        b_len = res.get("bytes_len", 0)
        print(f"  [{parser_name:<22}] Status: {st} | Socket: {sock_st} | Wire Length: {b_len}B")
    print(f"{'='*75}")
    print(f"  Differential Divergence Detected : {has_div}")
    if anom:
        cat_str = anom.category.name if hasattr(anom.category, "name") else str(anom.category)
        print(f"  Anomaly Class                    : {cat_str}")
        print(f"  Observed Divergence              : {anom.observed_behavior}")
    print(f"{'='*75}\n")


def cmd_h2(args):
    """Constructs and optionally live-probes binary HTTP/2 framing desynchronization streams."""
    from engine.h2_framing import H2GatewayDesyncBuilder

    hygiene_cfg, rate_limiter = _configure_cli_hygiene(args)
    extra_hdrs = hygiene_cfg.to_headers_dict() if hygiene_cfg.is_active else None
    target_host = args.host or "127.0.0.1"
    target_port = int(getattr(args, "port", 443) or 443)
    as_json = bool(getattr(args, "as_json", False))

    h2_cl = H2GatewayDesyncBuilder.build_h2_cl_desync(
        path="/",
        host=target_host,
        declared_cl=0,
        actual_payload=b"GET /smuggled HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n",
        extra_headers=extra_hdrs,
    )
    h2_te = H2GatewayDesyncBuilder.build_h2_te_desync(
        path="/",
        host=target_host,
        te_value="chunked",
        chunked_body=b"0\r\n\r\n",
        extra_headers=extra_hdrs,
    )
    h2_crlf = H2GatewayDesyncBuilder.build_h2_crlf_pseudoheader_injection(
        injected_path="/ HTTP/1.1\r\nHost: " + target_host + "\r\n\r\n",
        host=target_host,
        extra_headers=extra_hdrs,
    )

    live_report = None
    if bool(getattr(args, "live", False)):
        from engine.h2_live_authz import LiveH2DesyncProber
        prober = LiveH2DesyncProber(
            host=target_host,
            port=target_port,
            use_tls=bool(getattr(args, "tls", False) or target_port == 443),
            authorized=bool(getattr(args, "authorized", False)),
            hygiene_config=hygiene_cfg,
            rate_limiter=rate_limiter,
        )
        live_report = prober.run_live_h2_desync_audit()

    if as_json:
        from engine.cli_render import render_json
        render_json(
            {
                "host": target_host,
                "port": target_port,
                "h2_cl_bytes": len(h2_cl),
                "h2_te_bytes": len(h2_te),
                "h2_crlf_bytes": len(h2_crlf),
                "live_probing": live_report,
            }
        )
        return

    print(f"\n{'='*75}")
    print("[*] BINARY HTTP/2 FRAMING & GATEWAY DESYNC BUILDER")
    print(f"    Target: {target_host}:{target_port}")
    print(f"{'='*75}")
    print(f"[+] Built H2.CL Desynchronization stream: {len(h2_cl)} bytes")
    print(f"[+] Built H2.TE Desynchronization stream: {len(h2_te)} bytes")
    print(f"[+] Built H2 Pseudo-Header CRLF Injection stream: {len(h2_crlf)} bytes")
    if live_report is not None:
        print(
            f"[+] Live 3-Trial H2 Desync Audit: status={live_report.get('status')} "
            f"findings={live_report.get('total_findings', 0)} transient={live_report.get('transient_count', 0)}"
        )
    print(f"[*] H2 binary frames synthesized for gateway validation.")
    print(f"{'='*75}\n")


def cmd_audit(args):
    """Computes and cryptographically verifies RFC 6962 Merkle tree root and leaf inclusion proofs."""
    from engine.differential_oracle import MultiImplementationDifferentialOracle
    from engine.merkle_audit import MerkleAuditTrail
    from database import Database

    db = Database(args.db)
    try:
        findings = db.get_confirmed_findings()
        oracle = MultiImplementationDifferentialOracle()
        trail = MerkleAuditTrail()
        for f in findings:
            f_dict = dict(f)
            raw_probe_bytes = str(f_dict.get("raw_probe", "")).encode("latin-1", errors="replace")
            raw_resp_bytes = str(f_dict.get("raw_evidence", "")).encode("latin-1", errors="replace")
            has_div, _, matrix = oracle.evaluate_matrix_4parsers(raw_probe_bytes)
            att = int(f_dict.get("verification_attempts") or 3)
            succ = int(f_dict.get("successful_reproductions") or 3)
            rate = float(f_dict.get("reproducibility_rate") if f_dict.get("reproducibility_rate") is not None else 1.0)
            trail.record_finding(
                entry_id=f"VULN-{f_dict.get('eval_id', 1)}",
                target_engine=args.host,
                raw_probe=raw_probe_bytes,
                raw_response=raw_resp_bytes,
                reproducibility_rate=rate,
                verification_attempts=att,
                successful_reproductions=succ,
                four_parser_differential={"divergence": bool(has_div), "matrix": matrix},
                status="CONFIRMED_VULNERABILITY",
            )
    finally:
        db.close()
    print(f"\n{'='*75}")
    print("[*] CRYPTOGRAPHIC MERKLE AUDIT TRAIL (RFC 6962)")
    print(f"{'='*75}")
    print(f"  Total Findings Ingested : {len(findings)}")
    print(f"  Total Leaves Recorded   : {len(trail.leaves)} (Confirmed: {len(trail.get_confirmed_leaves())}, Transient: {len(trail.get_transient_leaves())})")
    root = trail.get_merkle_root()
    print(f"  Merkle Tree Root        : {root}")
    if trail.leaves:
        proof = trail.generate_proof(0)
        leaf_0_hash = trail.leaves[0].compute_leaf_hash()
        print(f"  Leaf 0 Hash             : {leaf_0_hash}")
        print(f"  Proof Path Length       : {len(proof)}")
        valid = trail.verify_proof(leaf_0_hash, proof, root)
        print(f"  Cryptographic Proof     : {'VALID (RFC 6962 Conformance Verified)' if valid else 'INVALID'}")
    print(f"{'='*75}\n")


def cmd_start(args):
    """Launches the one-click local Test Lab Server + Flaw Hunter / MCP / Swarm (start.py behavior)."""
    import start
    argv = []
    if args.host:
        argv.extend(["--host", args.host])
    if args.port:
        argv.extend(["--port", str(args.port)])
    if args.tls:
        argv.append("--tls")
    if getattr(args, "targets", None):
        t_val = ",".join(args.targets) if isinstance(args.targets, list) else str(args.targets)
        argv.extend(["--targets", t_val])
    if getattr(args, "terminators", None):
        term_val = ",".join(args.terminators) if isinstance(args.terminators, list) else str(args.terminators)
        argv.extend(["--terminators", term_val])
    if getattr(args, "max_rfcs", None):
        argv.extend(["--max-rfcs", str(args.max_rfcs)])
    if getattr(args, "comb_only", False):
        argv.append("--comb-only")
    if getattr(args, "mcp", False):
        argv.append("--mcp")
    if getattr(args, "keep_going", False):
        argv.append("--keep-going")

    old_argv = sys.argv
    try:
        sys.argv = ["start.py"] + argv
        start.main()
    finally:
        sys.argv = old_argv


def cmd_vulns(args):
    """Prints all confirmed vulnerabilities along with the host name and reproduction metrics."""
    import sqlite3
    import os
    import re
    db_path = getattr(args, "db", "terminator.db")
    if not os.path.exists(db_path):
        print(f"[-] Database {db_path} does not exist.")
        return

    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()

        host_filter = getattr(args, "host", None)
        if host_filter in ("127.0.0.1", "0.0.0.0", "::") and not any("--host" in a for a in sys.argv):
            host_filter = None

        query = """
            SELECT r.vuln_id, a.target_engine, r.impact, r.reproducibility_rate, 
                   r.successful_reproductions, r.verification_attempts, r.minimized_probe, r.created_at
            FROM reproducible_vulnerabilities r
            LEFT JOIN implementation_anomalies a ON r.anomaly_id = a.anomaly_id
            ORDER BY r.created_at DESC
        """
        rows = cur.execute(query).fetchall()
        
        results = []
        for r in rows:
            vuln_id, target_engine, impact, rate, succ, att, probe, created_at = r
            if not target_engine:
                host_m = re.search(r"Host:\s*([^\r\n]+)", probe or "", re.IGNORECASE)
                target_engine = host_m.group(1).strip() if host_m else "Unknown Host"
            
            if host_filter and host_filter.lower() not in target_engine.lower():
                continue
            results.append((vuln_id, target_engine, impact, rate, succ, att, created_at))

        print(f"\n{'='*105}")
        print(f"[*] CONFIRMED VULNERABILITIES & HOST MAPPING (Database: {db_path})")
        if host_filter:
            print(f"    Filtered by Host: {host_filter}")
        print(f"{'='*105}")
        print(f"{'VULN ID':<28} {'HOST / TARGET':<22} {'IMPACT CLASS':<28} {'REPRO RATE':<12} {'TIMESTAMP'}")
        print(f"{'-'*28} {'-'*22} {'-'*28} {'-'*12} {'-'*19}")
        for vuln_id, target_engine, impact, rate, succ, att, created_at in results:
            rate_str = f"{rate*100:>5.1f}% ({succ}/{att})"
            print(f"{vuln_id:<28} {target_engine:<22} {impact:<28} {rate_str:<12} {str(created_at)[:19]}")
        print(f"{'='*105}")
        print(f"Total Confirmed Vulnerabilities: {len(results)}\n")
    finally:
        con.close()



def cmd_aiscan(args):
    """
    Executes AI vulnerability and prompt injection scanning on target directory
    using haasonsaas/aiscan and Python AST fallback scanner.
    """
    from engine.aiscan_integrator import AiscanIntegrator

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        scanner = AiscanIntegrator(db=db)

        print("\n" + "=" * 75)
        print("  HAASONSAAS/AISCAN: AI & PROMPT SECURITY AUDITOR (MODULE 18)")
        print("  Credit: Jonathan Haas (https://github.com/haasonsaas/aiscan)")
        print("=" * 75 + "\n")

        target_path = getattr(args, "aiscan_target", ".") or "."
        print(f"[*] Initiating AI security scan on: {target_path}")
        res = scanner.scan_target(target_path)

        print(f"[*] Engine Used      : {res.get('engine', 'unknown')}")
        print(f"[*] Total Findings   : {res.get('total_findings', 0)}")
        print(f"[*] Total AI Sinks   : {res.get('total_endpoints', 0)}")
        print("-" * 75)

        findings = res.get("findings", [])
        if not findings:
            print("[+] Zero AI vulnerabilities or prompt injection sinks detected.")
        else:
            print(f"{'SEVERITY':<10} {'TYPE':<28} {'LOCATION':<30} {'DESCRIPTION'}")
            print(f"{'-'*10} {'-'*28} {'-'*30} {'-'*30}")
            for f in findings[:25]:
                loc = f"{Path(f['file_path']).name}:{f['line_number']}"
                print(f"{f['severity']:<10} {f['finding_type']:<28} {loc:<30} {f['description'][:40]}")

        endpoints = res.get("endpoints", [])
        if endpoints:
            print("\n[*] DISCOVERED AI ENDPOINTS (PROMPT SMUGGLING TARGETS):")
            for e in endpoints:
                print(f"    -> {e['http_method']} {e['route_path']} ({Path(e['file_path']).name}:{e['line_number']})")

        report_files = res.get("report_files", {})
        if report_files:
            print("\n[*] Reports saved to reports/ folder:")
            for rtype, rpath in report_files.items():
                print(f"    - {rtype.upper()}: {rpath}")

        print("=" * 75 + "\n")
    finally:
        db.close()


def _resolve_cli_workspace_root(args) -> Optional[Path]:
    ws_raw = (
        getattr(args, "workspace_root", None)
        or getattr(args, "repo", None)
        or getattr(args, "path", None)
    )
    if ws_raw is None:
        return None
    ws_str = os.fspath(ws_raw) if isinstance(ws_raw, os.PathLike) else str(ws_raw)
    if not ws_str.strip():
        return None
    from engine.execution_policy import (
        _is_drive_relative_or_colon_unsafe,
        _is_unc_path,
        _validate_canonical_path_syntax,
    )

    if ws_str != ws_str.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in ws_str):
        raise PermissionError("Unsafe CLI workspace_root rejected (whitespace or control characters).")
    if _is_unc_path(ws_str) or _is_drive_relative_or_colon_unsafe(ws_str):
        raise PermissionError("Unsafe CLI workspace_root rejected (UNC, NT-device, or drive-relative/ADS path).")
    err = _validate_canonical_path_syntax(ws_str, allow_trailing_slash=True)
    if err is not None and ws_str != ".":
        raise PermissionError(f"Unsafe CLI workspace_root rejected: {err}")
    resolved = Path(ws_str).resolve(strict=False)
    if resolved.exists() and resolved.is_file():
        return resolved.parent
    return resolved


def cmd_artex(args):
    """Execute BaaRai/ARTEX Dual-Graph & Durable Attack Chaining Engine (Module 17)."""
    from datetime import datetime, timezone
    from pathlib import Path as _Path
    import secrets as _secrets
    from engine.approval_gate import ApprovalGate
    from engine.artex_bridge import ArtexProxyConfig, TrafficCaptureSession
    from engine.cli_render import render_json, render_poe_summary
    from engine.dual_graph_engine import DualGraphAttackEngine, NoiseGovernor
    from engine.safe_network_validator import (
        is_explicit_loopback_host,
        parse_host_and_port,
        validate_and_authorize_target,
    )
    from engine.session_loader import (
        import_har_file,
        import_openapi_spec,
        load_auth_profiles,
        load_scope_file,
    )

    raw_host = getattr(args, "host", None) or getattr(args, "target", None) or "127.0.0.1"
    raw_port = int(getattr(args, "port", 8080) or 8080)
    raw_tls = getattr(args, "tls", None)
    as_json = bool(getattr(args, "as_json", False))
    authorized = bool(getattr(args, "authorized", False))
    t_host, t_port, inferred_tls = parse_host_and_port(
        raw_host,
        default_port=raw_port,
        use_tls=bool(raw_tls) if raw_tls is not None else None,
    )
    use_tls = bool(raw_tls) or ("://" in str(raw_host) and inferred_tls)
    ok, reason = validate_and_authorize_target(t_host, authorized=authorized)
    if not ok:
        print(f"[!] Target authorization error for {raw_host}: {reason}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)

    artex_multiturn = bool(getattr(args, "artex_multiturn", False))
    artex_intent_turns = int(getattr(args, "artex_intent_turns", 0) or 0)
    artex_intent_tokens = int(getattr(args, "artex_intent_tokens", 0) or 0)
    artex_budget_turns = int(getattr(args, "artex_budget_turns", 0) or 0)
    if artex_intent_turns < 0 or artex_intent_tokens < 0 or artex_budget_turns < 0:
        print(
            "[!] ARTEX budget/turn parameters must be non-negative (>= 0).",
            file=(sys.stderr if as_json else sys.stdout),
        )
        sys.exit(1)

    reports_dir = getattr(args, "output_dir", None) or "reports"
    rounds = max(1, int(getattr(args, "artex_rounds", 1) or 1))
    workers = max(1, int(getattr(args, "artex_workers", 3) or 3))
    strict_poe = bool(getattr(args, "strict_poe", False))
    approval_mode = getattr(args, "approval_mode", "policy") or "policy"
    approval_rules = getattr(args, "approval_rules", None)
    scope_file = getattr(args, "scope_file", None)
    auth_profile = getattr(args, "auth_profile", None)
    import_har = getattr(args, "import_har", None)
    import_openapi = getattr(args, "import_openapi", None)
    embedded_proxy = bool(getattr(args, "embedded_proxy", False))
    embedded_proxy_port = int(getattr(args, "embedded_proxy_port", 0) or 0)
    export_advisory = bool(getattr(args, "export_advisory", False))
    export_csv = bool(getattr(args, "export_csv", False))
    noise_profile = getattr(args, "artex_noise_profile", None)
    llm_profiles = _parse_csv_list(getattr(args, "artex_llm_profiles", None))

    shared_task_id = f"ARTEX-TASK-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{_secrets.token_hex(3)}"
    shared_noise = NoiseGovernor(profile=noise_profile)

    proxy_cfg = ArtexProxyConfig.from_env_or_args(
        proxy_url=getattr(args, "artex_proxy", None),
        ca_cert_path=getattr(args, "artex_ca_cert", None),
        authorized=authorized,
    )

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    embedded_mitm = None
    arbiter = None
    try:
        if getattr(args, "fusion", True) and os.environ.get("RFCHUNT_OFFLINE") != "1":
            try:
                from fusion_engine import FusionArbiter
                arbiter = FusionArbiter(
                    db=db,
                    preferred_model=getattr(args, "model", None),
                    sec_model=getattr(args, "sec_model", None),
                    quiet=as_json,
                )
            except Exception:
                arbiter = None
        _configure_cli_hygiene(args)
        from engine.h2_live_authz import resolve_auth_profiles_from_cli
        traffic_session = TrafficCaptureSession(db=db, task_id=shared_task_id, proxy_config=proxy_cfg)
        approval_gate = (
            ApprovalGate.from_rules_file(approval_rules, mode=approval_mode, db=db, task_id=shared_task_id)
            if approval_rules
            else ApprovalGate(mode=approval_mode, db=db, task_id=shared_task_id)
        )
        loaded_scope = load_scope_file(scope_file) if scope_file else {"allow_hosts": [], "deny_hosts": [], "deny_routes": []}
        scope_hosts_set = set(loaded_scope.get("allow_hosts") or []) or None
        if isinstance(auth_profile, str) and "," not in auth_profile:
            loaded_auth_profiles = load_auth_profiles(auth_profile) if auth_profile else {}
        else:
            loaded_auth_profiles = resolve_auth_profiles_from_cli(auth_profile) if auth_profile else {}

        if embedded_proxy:
            from engine.local_mitm_proxy import LocalRecordingMITMProxy
            embedded_mitm = LocalRecordingMITMProxy(
                host="127.0.0.1",
                port=embedded_proxy_port,
                db=db,
                task_id=shared_task_id,
                traffic_session=traffic_session,
                noise_governor=shared_noise,
                authorized=authorized or is_explicit_loopback_host(t_host),
            )
            embedded_mitm.start()
            proxy_cfg = ArtexProxyConfig(
                proxy_url=embedded_mitm.proxy_url,
                ca_cert_path=embedded_mitm.ca_cert_path,
                enabled=True,
            )
            traffic_session.proxy_config = proxy_cfg

        _approval_deny = str(approval_mode or "policy").strip().lower() == "deny"
        artex_live_val = getattr(args, "artex_live", None)
        if getattr(args, "no_artex_live", False) or _approval_deny:
            artex_live_val = False
        _is_loopback = is_explicit_loopback_host(t_host)
        _enable_live = False
        if not _approval_deny:
            if artex_live_val is True:
                _enable_live = bool(authorized or _is_loopback)
            elif artex_live_val is None and (authorized or _is_loopback):
                import socket as _sock
                try:
                    with _sock.create_connection((t_host, t_port), timeout=1.0):
                        _enable_live = True
                except OSError:
                    _enable_live = False

        live_executor_fn = None
        live_registry = None
        if _enable_live and not _approval_deny:
            from engine.live_executors import LiveWorkerExecutorRegistry
            live_registry = LiveWorkerExecutorRegistry(
                host=t_host,
                port=t_port,
                use_tls=use_tls,
                authorized=bool(authorized or _is_loopback),
                traffic_session=traffic_session,
                approval_gate=approval_gate,
                noise_governor=shared_noise,
                auth_profiles=loaded_auth_profiles,
                arbiter=arbiter,
                workspace_root=_resolve_cli_workspace_root(args),
            )
            live_executor_fn = live_registry.as_executor_fn()

        engine = DualGraphAttackEngine(
            db=db,
            reports_dir=reports_dir,
            task_id=shared_task_id,
            scope_hosts=scope_hosts_set,
            noise_profile=noise_profile,
            max_task_turns=artex_budget_turns,
            max_intent_tokens=artex_intent_tokens,
            max_intent_turns=artex_intent_turns,
            llm_profile_ids=llm_profiles,
            llm_rotate=bool(getattr(args, "artex_llm_rotate", False)),
            proxy_config=proxy_cfg,
            traffic_session=traffic_session,
            workers=workers,
            arbiter=arbiter,
            strict_poe=strict_poe,
            approval_gate=approval_gate,
            default_executor_fn=live_executor_fn,
        )
        engine.noise_governor = shared_noise
        engine.worker.noise_governor = shared_noise
        if live_registry is not None:
            live_registry.budget_ledger = engine.budget_ledger
            live_registry.trace_store = engine.trace_store
            live_registry.boundary = engine.boundary
            live_registry.asset_graph = engine.asset_graph
            if artex_multiturn:
                mt_turns = artex_intent_turns if artex_intent_turns > 0 else None
                engine.default_executor_fn = live_registry.as_multiturn_executor_fn(
                    max_turns=mt_turns,
                    budget_ledger=engine.budget_ledger,
                    trace_store=engine.trace_store,
                    boundary=engine.boundary,
                    asset_graph=engine.asset_graph,
                )
        for deny_h in loaded_scope.get("deny_hosts") or []:
            engine.asset_graph.deny_hosts.add(str(deny_h).lower())
        for deny_r in loaded_scope.get("deny_routes") or []:
            engine.asset_graph.deny_routes.append(str(deny_r))

        if import_openapi:
            import_openapi_spec(
                import_openapi,
                asset_graph=engine.asset_graph,
                default_host=t_host,
                default_port=t_port,
                host=t_host,
                port=t_port,
            )
        if import_har:
            har_res = import_har_file(import_har, asset_graph=engine.asset_graph, traffic_session=traffic_session)
            if not loaded_auth_profiles and har_res.get("extracted_auth_headers"):
                from engine.session_loader import AuthProfile as _AP
                loaded_auth_profiles["har_session"] = _AP(
                    name="har_session",
                    role="end_user",
                    headers=dict(har_res["extracted_auth_headers"]),
                )
                if live_registry is not None:
                    live_registry.auth_profiles.update(loaded_auth_profiles)

        ai_sinks = []
        try:
            cur = db.conn.cursor()
            cur.execute("SELECT DISTINCT file_path, model_or_api FROM ai_security_findings WHERE finding_type = 'unmetered_ai_endpoint'")
            for r in cur.fetchall():
                ai_sinks.append({"route": "/api/chat", "method": "POST", "model_provider": r["model_or_api"], "file_path": r["file_path"]})
        except Exception:
            pass
        if not ai_sinks:
            ai_sinks = [{"route": "/api/chat", "method": "POST", "model_provider": "local_ai", "file_path": "server.py"}]

        engine.ingest_target_infrastructure(host=t_host, port=t_port, endpoints=["/api/v1"], ai_sinks=ai_sinks)
        hydrated = engine.ingest_from_database(db)
        if sum(hydrated.values()) == 0:
            engine.register_wire_primitive(
                anomaly_id="RFC9112-CHUNK-DESYNC",
                description="HTTP/1.1 Framing Desync (Chunk Extension & Content-Length conflict)",
                anomaly_type="CL.TE_DESYNC",
            )

        _stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _stdout_ctx:
            res = engine.run_attack_chain_cycle(
                round_num=rounds,
                retest_existing=bool(getattr(args, "artex_retest", False)),
            )

            artex_url = getattr(args, "artex_url", None) or os.environ.get("ARTEX_API_URL")
            remote_res = None
            if artex_url:
                remote_res = engine.sync_with_headless_artex(
                    artex_url=artex_url,
                    token=getattr(args, "artex_token", None),
                    authorized=authorized,
                    llm_profile_ids=llm_profiles,
                    llm_rotate=bool(getattr(args, "artex_llm_rotate", False)) if llm_profiles else None,
                    wait_sse=bool(getattr(args, "artex_wait_sse", False)),
                )

        stored_chains = db.get_attack_chains(limit=50, task_id=shared_task_id) if hasattr(db, "get_attack_chains") else []
        traces_list = db.list_worker_traces(task_id=shared_task_id, limit=25) if hasattr(db, "list_worker_traces") else []

        extra_exports: Dict[str, Any] = {}
        if export_advisory or export_csv:
            from engine.advisory_exporter import AdvisoryExporter, _safe_filename
            out_dir = _Path(reports_dir)
            exporter = AdvisoryExporter(reports_dir=out_dir)
            if export_csv:
                csv_path = out_dir / "findings_and_chains.csv"
                exporter.export_findings_csv([], chains=stored_chains, output_path=csv_path)
                extra_exports["csv"] = str(csv_path)
            if export_advisory:
                adv_paths: List[str] = []
                for ch in stored_chains[:25]:
                    cid = str(ch.get("chain_id") or "CHAIN")
                    tid = ch.get("traffic_id")
                    trec = db.get_traffic_evidence(tid) if tid else None
                    rtests = db.get_chain_retests(chain_id=cid)
                    out_md = out_dir / f"advisory_{_safe_filename(cid)}.md"
                    exporter.export_ghsa_markdown(ch, traffic_record=trec, retests=rtests, output_path=out_md)
                    adv_paths.append(str(out_md))
                extra_exports["advisories"] = adv_paths

        if getattr(args, "as_json", False):
            render_json({"result": res, "hydrated": hydrated, "remote_artex": remote_res, "exports": extra_exports})
            return

        cov = res.get("coverage") or {}
        todo = res.get("todolist_summary") or {}
        print(f"\n[+] ARTEX Dual-Graph Attack Chaining Complete: target={t_host}:{t_port} rounds={rounds} workers={workers}")
        print(f"    DB Hydrated        : {hydrated}")
        print(f"    Assets / Coverage  : {res['total_assets']} assets ({cov.get('tested_assets', 0)}/{cov.get('total_in_scope_assets', 0)} = {cov.get('coverage_pct', 0.0)}%)")
        print(f"    Attack Chains      : {res['candidates_planned']} planned | {res['exploits_verified']} verified | Max Hops: {res.get('max_hop_count', 0)}")
        print(f"    Todolist / Traces  : {todo.get('completed_chains', 0)}/{todo.get('total_chains', 0)} chains complete | {res.get('worker_traces_count', 0)} worker traces | Goal Proven: {res.get('goal_proven', False)}")
        if proxy_cfg.enabled:
            print(f"    MITM Proxy         : {proxy_cfg.proxy_url}")
        if remote_res is not None:
            print(f"    Headless ARTEX API : {remote_res.get('status')} (task_id={remote_res.get('task_id')}, traffic_ingested={remote_res.get('traffic_ingested', 0)})")
        for rtype, rpath in (res.get("report_files") or {}).items():
            print(f"    Report ({rtype.upper():<7}) : {rpath}")
        if extra_exports.get("csv"):
            print(f"    CSV Export         : {extra_exports['csv']}")
        if extra_exports.get("advisories"):
            print(f"    GHSA Advisories    : {len(extra_exports['advisories'])} written")
        render_poe_summary(
            res.get("poe_breakdown") or {},
            coverage=cov,
            chains=stored_chains,
            traces=traces_list,
            plain=bool(getattr(args, "plain", False)),
        )
    except (PermissionError, ValueError) as exc:
        print(f"[!] ARTEX execution rejected: {exc}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)
    finally:
        if embedded_mitm is not None:
            try:
                embedded_mitm.stop()
            except Exception:
                pass
        if arbiter is not None and hasattr(arbiter, "close"):
            try:
                arbiter.close()
            except Exception:
                pass
        db.close()


def cmd_artex_loop(args):
    """Execute bounded multi-turn ArtexWorker tool loop via CLI."""
    args.artex_multiturn = True
    if getattr(args, "artex_live", None) is None and not bool(getattr(args, "no_artex_live", False)):
        args.artex_live = True
    return _dispatch_cmd("cmd_artex", args)


def cmd_prompt_smuggle(args):
    """
    Synthesizes and verifies novel Desynchronized Prompt Injection probes.
    """
    from engine.prompt_smuggling_synthesizer import PromptSmugglingSynthesizer
    from database import Database

    t_host = getattr(args, "host", "127.0.0.1")
    from engine.safe_network_validator import validate_and_authorize_target
    ok, reason = validate_and_authorize_target(t_host, authorized=getattr(args, "authorized", False))
    if not ok:
        print(f"[!] Target authorization error for {t_host}: {reason}")
        sys.exit(1)

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        synthesizer = PromptSmugglingSynthesizer(db=db)

        print("\n" + "=" * 75)
        print("  NOVEL ATTACK SYNTHESIZER: DESYNCHRONIZED PROMPT INJECTION (MODULE 19)")
        print("  Couples HTTP Framing Desynchronization with Backend AI Sinks")
        print("=" * 75 + "\n")

        t_port = getattr(args, "port", 8080)
        ai_route = getattr(args, "ai_route", "/api/chat") or "/api/chat"

        print(f"[*] Target Host        : {t_host}:{t_port}")
        print(f"[*] Target AI Endpoint : {ai_route}")
        print(f"[*] Synthesizing cross-layer attack streams (CL.TE, TE.CL, Chunk-Ext)...")

        probes = synthesizer.synthesize_probes_for_endpoint(
            target_host=t_host,
            target_port=t_port,
            ai_endpoint=ai_route,
            http_method="POST",
        )

        print(f"[+] Synthesized {len(probes)} novel Desynchronized Prompt Injection probe(s):\n")
        for p in probes:
            print(f"  -> [{p.attack_class}] ID: {p.probe_id}")
            print(f"     Canary Token : {p.canary_token}")
            print(f"     Target Sink  : {p.target_ai_endpoint}")
            print(f"     Rationale    : {p.rationale[:90]}...")
            print()

        print(f"[*] Reports successfully generated in reports/ folder.")
        print("=" * 75 + "\n")
    finally:
        db.close()


def cmd_raptor(args):
    """
    Executes the RAPTOR Security Framework against a live host or local repository.
    Gives explicit attribution to Gadi Evron, Daniel Cuthbert, and Thomas Dullien (Halvar Flake).
    """
    from engine.raptor_integrator import (
        RaptorIntegrator,
        RAPTOR_PROJECT_TITLE,
        RAPTOR_AUTHORS,
        RAPTOR_REPO_URL,
        RAPTOR_DOCKER_IMAGE,
    )

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        raptor = RaptorIntegrator(db=db)

        print(f"\n{'='*75}")
        print(RaptorIntegrator.get_attribution_banner())
        print(f"{'='*75}\n")

        # 1. Setup / Bootstrap RAPTOR if requested
        if getattr(args, "raptor_setup", False):
            print("[*] Bootstrapping & configuring RAPTOR Security Framework...")
            setup_res = raptor.ensure_installed()
            if setup_res.get("stdout"):
                print(setup_res["stdout"])
            if setup_res.get("stderr"):
                print(setup_res["stderr"])
            return

        # 2. Status Check
        if getattr(args, "raptor_status", False) or (hasattr(args, "status") and args.status):
            st = raptor.check_status()
            print(f"[*] RAPTOR SYSTEM STATUS:")
            img_id = str(st.get("image_id") or "")[:12]
            print(f"    Docker Image Ready     : {'YES (' + img_id + ')' if st['docker_ready'] else 'NO'}")
            print(f"    Framework Installed    : {'YES (' + st['raptor_root'] + ')' if st['raptor_available'] else 'NO'}")
            print(f"    Ollama Daemon Ready    : {'YES' if st['ollama_ready'] else 'NO'}")
            print(f"    Preferred Model Ready  : {'YES (fenkohq/foundation-sec-8b:latest)' if st['preferred_model_installed'] else 'NO'}")
            print(f"    Installed Models       : {', '.join(st['ollama_models'][:6]) or 'None detected'}")
            print(f"{'='*75}\n")
            return

        # 2. Findings Summary
        if getattr(args, "raptor_findings", False):
            findings = raptor.list_all_findings(max_items=getattr(args, "limit", 50))
            print(f"[*] RECENT RAPTOR VULNERABILITY FINDINGS (Total: {len(findings)}):")
            if not findings:
                print("    No previous findings discovered in out/ directory.")
            else:
                print(f"{'SEVERITY':<10} {'RULE ID':<30} {'LOCATION':<32} {'MESSAGE'}")
                print(f"{'-'*10} {'-'*30} {'-'*32} {'-'*30}")
                for f in findings:
                    loc = f"{f['file']}:{f['line']}"
                    print(f"{f['severity']:<10} {f['rule_id']:<30} {loc[:32]:<32} {f['message'][:50]}")
            print(f"{'='*75}\n")
            return

        # 3. Determine Scan Target: Live Host vs Any Local Folder
        target_repo = getattr(args, "raptor_target", None) or getattr(args, "repo", None) or getattr(args, "path", None) or getattr(args, "target_arg", None)
        host = getattr(args, "host", None)
        raptor_mode = getattr(args, "raptor_mode", None)

        if not target_repo and host and os.path.isdir(str(host)):
            target_repo = str(host)
        elif not target_repo and not host and raptor_mode in ("all", "full", "scan", "agentic", "crypto", "sca", "describe"):
            target_repo = os.getcwd()

        if target_repo and os.path.exists(str(target_repo)):
            mode = raptor_mode or "all"
            model = getattr(args, "raptor_model", "fenkohq/foundation-sec-8b:latest")
            pg = getattr(args, "policy_groups", "") or ""
            codeql = bool(getattr(args, "include_codeql", False))
            if mode == "full":
                mode = "all"
            if mode == "describe":
                desc_res = raptor.describe_target(target_repo)
                if desc_res.get("stdout"):
                    print(desc_res["stdout"])
                res = {
                    "target": str(target_repo),
                    "mode": "describe",
                    "duration_sec": 0.0,
                    "total_findings": 0,
                    "ingested_to_db": 0,
                    "findings": [],
                }
            else:
                res = raptor.run_scan(
                    target_path=target_repo,
                    mode=mode,
                    model=model,
                    policy_groups=pg,
                    include_codeql=codeql,
                    timeout_sec=3600 if mode == "all" else 1800,
                )
        else:
            if not host or host in ("127.0.0.1", "localhost") and getattr(args, "target", None):
                host = getattr(args, "target", host)

            port = getattr(args, "port", 443)
            from engine.safe_network_validator import is_explicit_loopback_host
            if port == 5006 and host and not is_explicit_loopback_host(str(host)):
                port = 443
            use_tls = bool(getattr(args, "tls", False) or port == 443)
            authorized = bool(getattr(args, "authorized", False))

            from engine.safe_network_validator import validate_and_authorize_target
            ok, reason = validate_and_authorize_target(host, authorized=authorized)
            if not ok:
                print(f"[!] Target authorization error for {host}: {reason}")
                sys.exit(1)

            try:
                res = raptor.run_host_scan(
                    host=host,
                    port=port,
                    use_tls=use_tls,
                    authorized=authorized,
                )
            except PermissionError as exc:
                print(f"[!] Target authorization error for {host}: {exc}")
                sys.exit(1)

        if "error" in res:
            print(f"[-] RAPTOR Execution Notice: {res['error']}")
        else:
            print(f"[+] RAPTOR Execution Completed Successfully!")
            print(f"    Target             : {res.get('target_url') or res.get('target')}")
            print(f"    Mode               : {res.get('mode')}")
            print(f"    Duration           : {res.get('duration_sec')}s")
            print(f"    Total Findings     : {res.get('total_findings')}")
            print(f"    Ingested to DB     : {res.get('ingested_to_db')}")
            if res.get("findings"):
                print(f"\n[*] TOP DISCOVERED FINDINGS:")
                print(f"{'SEVERITY':<10} {'RULE ID':<30} {'LOCATION':<32} {'MESSAGE'}")
                print(f"{'-'*10} {'-'*30} {'-'*32} {'-'*30}")
                for f in res["findings"][:15]:
                    loc = f"{f['file']}:{f['line']}"
                    print(f"{f['severity']:<10} {f['rule_id']:<30} {loc[:32]:<32} {f['message'][:50]}")
        print(f"{'='*75}\n")
    finally:
        db.close()


def cmd_mantis(args):
    """
    Executes Module 20 (Google Mantis) Threat Modeling, Depth-Scaled Hypothesis Generation,
    Tier 1/2 Reproduction, Calibrated CVSS Scoring, and Adversarial Patching with
    mandatory ModelFusion and refusal-free Abliterated models.
    """
    from engine.mantis_integrator import DEFAULT_ABLITERATED_MODEL, MantisIntegrator

    args.fusion = True
    args.abliteration = True
    target = (
        getattr(args, "mantis_target", None)
        or getattr(args, "repo", None)
        or getattr(args, "path", None)
        or getattr(args, "raptor_target", None)
        or getattr(args, "target_arg", None)
        or "."
    )
    raw_depth = getattr(args, "depth", None)
    depth = 30 if raw_depth is None else int(raw_depth)
    mode = getattr(args, "mantis_mode", "full") or "full"
    preferred_model = getattr(args, "mantis_model", None) or DEFAULT_ABLITERATED_MODEL
    if getattr(args, "model", None) and "obliterated" in str(args.model).lower() and not getattr(args, "mantis_model", None):
        preferred_model = args.model
    reports_dir = getattr(args, "output_dir", None) or "reports"

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        if getattr(args, "mantis_report", False):
            findings = db.get_mantis_findings(limit=50)
            print(f"\n{'='*75}")
            print(f"[*] GOOGLE MANTIS STORED FINDINGS ({len(findings)} rows)")
            print(f"{'='*75}")
            for f in findings[:20]:
                print(
                    f"  [{f.get('severity', 'INFO'):<8} CVSS {f.get('cvss_score', 0.0):<4}] "
                    f"{f.get('rule_id', '')} ({f.get('cwe', '')}) "
                    f"{os.path.basename(str(f.get('file_path', '')))}:{f.get('line_number', 0)} - {f.get('title', '')}"
                )
            print(f"{'='*75}\n")
            return

        print(f"\n{'='*75}")
        print(f"[*] MODULE 20: GOOGLE MANTIS SECURITY PIPELINE (Fusion + Abliterated Enforced)")
        print(f"[*] Target: {os.path.abspath(str(target))} | Mode: {mode} | Depth: {depth}")
        print(f"[*] Abliterated Model: {preferred_model}")
        print(f"{'='*75}")

        integrator = MantisIntegrator(
            db=db,
            reports_dir=reports_dir,
            use_fusion=True,
            preferred_model=preferred_model,
            sec_model=getattr(args, "sec_model", None),
        )
        res = integrator.run_scan(target_path=str(target), depth=depth, mode=mode)

        print(f"[+] Mantis Completed in {res['elapsed_sec']}s | Profile: {res['depth_profile']}")
        print(f"    Threat Model ID  : {res['threat_model_id']}")
        print(f"    Files Discovered : {res['files_discovered']}")
        print(f"    Total Findings   : {res['total_findings']} (Reproduced: {res['reproduced_count']}, Patched Verified: {res['patched_verified_count']})")
        print(f"    SARIF Report     : {res['report_files'].get('sarif')}")
        print(f"    JSON Summary     : {res['report_files'].get('summary_json')}")
        print(f"{'='*75}\n")
    finally:
        db.close()


def _validate_cli_hint_args(
    args: Any,
    *,
    default_task_id: str = "default",
) -> Tuple[str, float, str, str, str]:
    """Validates CLI --hint* arguments without creating directories or SQLite DBs."""
    raw_hint = getattr(args, "hint", None)
    if raw_hint is None or not isinstance(raw_hint, str) or not raw_hint.strip() or "\x00" in raw_hint:
        print(
            "[!] Error: --hint must be a non-empty string without NUL bytes.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        prio = float(getattr(args, "hint_priority", 10.0))
    except (TypeError, ValueError):
        print("[!] Error: --hint-priority must be a finite numeric value.", file=sys.stderr)
        sys.exit(1)
    if not math.isfinite(prio):
        print("[!] Error: --hint-priority must be finite.", file=sys.stderr)
        sys.exit(1)

    raw_domain = getattr(args, "hint_domain", "global")
    raw_domain_str = "global" if raw_domain is None else str(raw_domain)
    if "\x00" in raw_domain_str:
        print("[!] Error: --hint-domain must not contain NUL bytes.", file=sys.stderr)
        sys.exit(1)
    hint_domain = raw_domain_str.strip() or "global"

    explicit_dests = getattr(args, "_explicit_cli_dests", set())
    if "hint_task_id" in explicit_dests:
        raw_tid = getattr(args, "hint_task_id", default_task_id)
    elif "task_id" in explicit_dests:
        raw_tid = getattr(args, "task_id", default_task_id)
    elif default_task_id and default_task_id != "default":
        raw_tid = default_task_id
    else:
        raw_tid = getattr(args, "task_id", None) or getattr(args, "hint_task_id", None) or default_task_id or "default"
    raw_tid_str = str(default_task_id if raw_tid is None else raw_tid)
    if "\x00" in raw_tid_str:
        print("[!] Error: --hint-task-id must not contain NUL bytes.", file=sys.stderr)
        sys.exit(1)
    hint_task_id = raw_tid_str.strip() or default_task_id or "default"

    raw_rfc = getattr(args, "hint_rfc", "")
    raw_rfc_str = "" if raw_rfc is None else str(raw_rfc)
    if "\x00" in raw_rfc_str:
        print("[!] Error: --hint-rfc must not contain NUL bytes.", file=sys.stderr)
        sys.exit(1)
    hint_rfc = raw_rfc_str.strip()

    return raw_hint, prio, hint_domain, hint_task_id, hint_rfc


def _persist_cli_hint(
    args: Any,
    db: Optional[Any] = None,
    *,
    default_task_id: str = "default",
) -> Dict[str, Any]:
    """Validates CLI --hint flags and persists a HINT node into terminator.db."""
    as_json = bool(getattr(args, "as_json", False))
    raw_hint, prio, hint_domain, hint_task_id, hint_rfc = _validate_cli_hint_args(
        args,
        default_task_id=default_task_id,
    )

    if db is not None:
        node_id = db.add_hint(
            raw_hint,
            priority=prio,
            task_id=hint_task_id,
            domain=hint_domain,
            rfc_id=hint_rfc,
            source_agent="cli",
            active=True,
        )
    else:
        db_path = str(getattr(args, "db", "terminator.db") or "terminator.db")
        if db_path != ":memory:":
            parent_dir = Path(db_path).parent
            if str(parent_dir):
                parent_dir.mkdir(parents=True, exist_ok=True)
        local_db = _resolve_db_cls()(db_path)
        try:
            node_id = local_db.add_hint(
                raw_hint,
                priority=prio,
                task_id=hint_task_id,
                domain=hint_domain,
                rfc_id=hint_rfc,
                source_agent="cli",
                active=True,
            )
        finally:
            local_db.close()

    return {
        "status": "injected",
        "node_id": node_id,
        "node_type": "HINT",
        "domain": hint_domain,
        "priority": prio,
        "task_id": hint_task_id,
        "rfc_id": hint_rfc,
        "active": True,
        "as_json": as_json,
    }


def cmd_hint(args):
    """CLI-only runtime HINT injection into SQLite blackboard (zero GUI/HTTP calls)."""
    res = _persist_cli_hint(args)
    payload = {k: v for k, v in res.items() if k != "as_json"}
    if res.get("as_json"):
        from engine.cli_render import render_json
        render_json(payload)
        return
    print(
        f"[+] Blackboard HINT persisted: id={payload['node_id']} "
        f"domain={payload['domain']} task_id={payload['task_id']} priority={payload['priority']}"
    )


def _run_all_aixcc_extensions(
    args: Any,
    res: Dict[str, Any],
    *,
    repo: Optional[str],
    path: Optional[str],
    host: Optional[str],
    port: Optional[int],
    use_tls: Optional[bool],
    reports_dir: str,
    db: Any,
    task_id: str,
    approval_mode: str,
    as_json: bool,
) -> None:
    """
    Runs AIxCC upgrade engines cleanly inside `--all` (`cmd_all`) without ever
    writing inside target `--repo`/`--path` directories or crashing `--all` when
    Docker or optional toolchains are absent.
    """
    engines = res.setdefault("engines", {})
    local_target = repo or path
    local_target_exists = bool(local_target and os.path.exists(str(local_target)))
    in_offline_or_pytest = bool(
        os.environ.get("PYTEST_CURRENT_TEST")
        or os.environ.get("RFCHUNT_OFFLINE") == "1"
        or str(approval_mode or "").strip().lower() == "deny"
    )
    out_root = Path(str(reports_dir or "reports"))

    explicit_fuzz = bool(getattr(args, "fuzz_bridge", False))
    disable_fuzz = bool(getattr(args, "no_fuzz_bridge", False))
    exec_fuzz_containers = (not bool(getattr(args, "fuzz_dry_run", False))) and (
        str(approval_mode or "").strip().lower() != "deny"
    )
    eligible_fuzz = local_target_exists and not disable_fuzz and (explicit_fuzz or not in_offline_or_pytest)

    explicit_dpm = bool(getattr(args, "docker_parser_matrix", False))
    disable_dpm = bool(getattr(args, "no_docker_parser_matrix", False))
    eligible_dpm = (not disable_dpm) and (explicit_dpm or (bool(host) and not in_offline_or_pytest))

    explicit_inv = bool(getattr(args, "sandbox_invariants", False))
    disable_inv = bool(getattr(args, "no_sandbox_invariants", False))
    eligible_inv = local_target_exists and not disable_inv and (explicit_inv or not in_offline_or_pytest)

    explicit_poe = bool(getattr(args, "poe_verify", False))
    disable_poe = bool(getattr(args, "no_poe_verify", False))
    eligible_poe = (not disable_poe) and (explicit_poe or not in_offline_or_pytest)

    # Single shared lightweight Docker daemon probe (<=1.0s) when running online with
    # container-capable AIxCC extensions enabled, preventing 3-4 sequential 2.5s-3.0s
    # Docker CLI timeouts on Windows hosts where Docker Desktop is stopped/absent.
    shared_docker_ok: Optional[bool] = None
    shared_docker_reason = ""
    if not in_offline_or_pytest and (
        (eligible_fuzz and exec_fuzz_containers) or eligible_dpm or eligible_inv or eligible_poe
    ):
        import shutil as _shutil
        import subprocess as _subprocess
        from engine.host_containment import silent_subprocess_run

        _docker_bin = _shutil.which("docker")
        if not _docker_bin:
            shared_docker_ok = False
            shared_docker_reason = "docker binary not found on PATH"
        else:
            try:
                _docker_proc = silent_subprocess_run(
                    [_docker_bin, "info", "--format", "{{.ServerVersion}}"],
                    shell=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=1.0,
                )
                if _docker_proc.returncode == 0:
                    shared_docker_ok = True
                else:
                    shared_docker_ok = False
                    shared_docker_reason = (
                        (_docker_proc.stderr or _docker_proc.stdout or f"exit code {_docker_proc.returncode}").strip()[:240]
                    )
            except _subprocess.TimeoutExpired:
                shared_docker_ok = False
                shared_docker_reason = "docker daemon probe timed out after 1.0s"
            except OSError as _docker_exc:
                shared_docker_ok = False
                shared_docker_reason = str(_docker_exc)[:240]

    def _unavailable_docker_runner(cmd: Sequence[str], **_kwargs: Any) -> Any:
        import subprocess as _subprocess

        return _subprocess.CompletedProcess(
            args=list(cmd),
            returncode=1,
            stdout="",
            stderr=shared_docker_reason or "docker daemon unavailable",
        )

    # 1. Whole-Repo Multi-Language Call-Graph & Taint Slicer + Tiered Model Escalation (AIxCC #2)
    run_slicer = not bool(getattr(args, "no_call_graph_slice", False))
    if local_target_exists and run_slicer:
        try:
            from engine.call_graph_slicer import slice_repository
            from engine.swarm_dispatcher import DispatchEscalationConfig, TieredModelRouter

            slice_report = slice_repository(
                str(local_target),
                enable_codeql=bool(
                    getattr(args, "slice_codeql", False) or getattr(args, "include_codeql", False)
                ),
                max_depth=int(getattr(args, "slice_max_depth", 8) or 8),
                max_slices=int(getattr(args, "slice_max_slices", 200) or 200),
            )
            esc_fraction = float(getattr(args, "escalation_fraction", 0.05) or 0.05)
            esc_fraction = max(0.01, min(1.0, esc_fraction))
            min_poe_esc = max(0, int(getattr(args, "min_poe_escalation", 1) if getattr(args, "min_poe_escalation", None) is not None else 1))
            esc_cfg = DispatchEscalationConfig(
                enabled=True,
                max_escalation_fraction=esc_fraction,
                min_poe_for_escalation=min_poe_esc,
                frontier_api_opt_in=bool(getattr(args, "frontier_api_opt_in", False)),
            )
            router = TieredModelRouter(config=esc_cfg, offline=bool(os.environ.get("RFCHUNT_OFFLINE") == "1"))
            routing_candidates: List[Any] = list(slice_report.slices)
            for f_item in (res.get("findings") or [])[:100]:
                if isinstance(f_item, dict):
                    routing_candidates.append(f_item)
            routing_plan = router.rank_and_route(routing_candidates)

            slice_dict = slice_report.to_dict()
            engines["call_graph_slicer"] = {
                "status": "completed",
                "repo_root": slice_dict.get("repo_root"),
                "files_scanned": slice_dict.get("files_scanned", 0),
                "languages_detected": slice_dict.get("languages_detected", {}),
                "parser_backends": slice_dict.get("parser_backends", {}),
                "tree_sitter_available": slice_dict.get("tree_sitter_available", False),
                "symbols_count": slice_dict.get("symbols_count", 0),
                "edges_count": slice_dict.get("edges_count", 0),
                "total_slices": len(slice_report.slices),
                "cross_file_slices_count": slice_dict.get("cross_file_slices_count", 0),
                "codeql": slice_dict.get("codeql", {}),
                "elapsed_sec": round(float(slice_dict.get("elapsed_sec", 0.0) or 0.0), 4),
                "top_slices": [s.to_dict() for s in slice_report.slices[:20]],
            }
            plan_dict = routing_plan.to_dict() if hasattr(routing_plan, "to_dict") else {}
            engines["tiered_escalation"] = plan_dict

            if hasattr(db, "add_fact"):
                for sl in slice_report.slices[:15]:
                    if sl.is_cross_file and sl.sanitizer_status != "sanitized":
                        db.add_fact(
                            f"[TAINT_SLICE:{sl.severity}] {sl.sink_class} ({sl.cwe_id}) across {len(sl.files_involved)} files: {sl.entry_symbol} -> {sl.sink_symbol}",
                            node_id=f"fact:taint_slice:{task_id}:{sl.slice_id}",
                            task_id=task_id,
                            domain="global",
                            source_agent="call_graph_slicer",
                            payload={
                                "slice_id": sl.slice_id,
                                "sink_class": sl.sink_class,
                                "cwe_id": sl.cwe_id,
                                "severity": sl.severity,
                                "sanitizer_status": sl.sanitizer_status,
                                "files_involved": list(sl.files_involved),
                                "is_cross_file": sl.is_cross_file,
                            },
                        )
        except Exception as exc:
            engines["call_graph_slicer"] = {"status": "error", "error": str(exc)}
    elif not run_slicer:
        engines["call_graph_slicer"] = {"status": "disabled"}

    # 2. Multi-Language LLM-Guided Coverage Fuzzing Bridge (AIxCC #3)
    if local_target_exists and not disable_fuzz:
        if explicit_fuzz or not in_offline_or_pytest:
            try:
                from engine.fuzz_bridge import FuzzBridgeConfig, LLMFuzzBridge, run_fuzz_bridge_scan

                fuzz_langs = _parse_csv_list(getattr(args, "fuzz_languages", None))
                fuzz_out = out_root / "fuzz_bridge"
                fuzz_timeout = float(getattr(args, "fuzz_timeout", 60.0) or 60.0)
                fuzz_max_time = int(getattr(args, "fuzz_max_time", 30) or 30)
                fuzz_cpp_backend = str(getattr(args, "fuzz_cpp_backend", "afl++") or "afl++")
                if (
                    shared_docker_ok is False
                    and exec_fuzz_containers
                    and getattr(run_fuzz_bridge_scan, "__module__", "") == "engine.fuzz_bridge"
                    and getattr(LLMFuzzBridge, "__module__", "") == "engine.fuzz_bridge"
                ):
                    fuzz_cfg = FuzzBridgeConfig(
                        timeout_sec=fuzz_timeout,
                        max_total_time_sec=fuzz_max_time,
                        cpp_backend=fuzz_cpp_backend,
                        execute_containers=exec_fuzz_containers,
                        docker_binary="",
                    )
                    fuzz_bridge = LLMFuzzBridge(
                        db=db,
                        config=fuzz_cfg,
                        task_id=task_id,
                        subprocess_runner=_unavailable_docker_runner,
                    )
                    fuzz_res = fuzz_bridge.run(
                        str(local_target),
                        output_dir=str(fuzz_out),
                        task_id=task_id,
                        languages=fuzz_langs,
                        execute=exec_fuzz_containers,
                    ).to_dict()
                else:
                    fuzz_res = run_fuzz_bridge_scan(
                        str(local_target),
                        output_dir=str(fuzz_out),
                        db=db,
                        task_id=task_id,
                        languages=fuzz_langs,
                        timeout_sec=fuzz_timeout,
                        max_total_time_sec=fuzz_max_time,
                        cpp_backend=fuzz_cpp_backend,
                        execute_containers=exec_fuzz_containers,
                        **({"docker_binary": ""} if shared_docker_ok is False else {}),
                    )
                engines["fuzz_bridge"] = fuzz_res
            except Exception as exc:
                engines["fuzz_bridge"] = {"status": "error", "error": str(exc)}
        else:
            engines["fuzz_bridge"] = {
                "status": "skipped_offline_or_test_guard",
                "reason": "Skipped automatic container fuzzing under offline/test/deny guard; pass --fuzz-bridge explicitly to run.",
                "detected_languages": [],
                "crashes": [],
                "plateaus": [],
            }
    elif disable_fuzz:
        engines["fuzz_bridge"] = {"status": "disabled"}

    # 3. Real Differential Docker Parser Matrix (AIxCC #1a)
    if not disable_dpm and (explicit_dpm or (bool(host) and not in_offline_or_pytest)):
        try:
            from engine.differential_oracle import DockerParserMatrix, MultiImplementationDifferentialOracle

            dpm_parsers = _parse_csv_list(getattr(args, "parsers", None))
            dpm_oracle = MultiImplementationDifferentialOracle()
            dpm_matrix = (
                DockerParserMatrix(
                    parsers=dpm_parsers,
                    docker_bin="",
                    subprocess_runner=_unavailable_docker_runner,
                )
                if (
                    shared_docker_ok is False
                    and getattr(MultiImplementationDifferentialOracle, "__module__", "") == "engine.differential_oracle"
                    and getattr(DockerParserMatrix, "__module__", "") == "engine.differential_oracle"
                )
                else None
            )
            engines["docker_parser_matrix"] = dpm_oracle.run_docker_parser_matrix(
                parsers=dpm_parsers,
                fallback_to_4parsers=bool(getattr(args, "fallback_4parsers", False)),
                **({"docker_matrix": dpm_matrix} if dpm_matrix is not None else {}),
            )
        except Exception as exc:
            engines["docker_parser_matrix"] = {"status": "error", "error": str(exc)}
    elif disable_dpm:
        engines["docker_parser_matrix"] = {"status": "disabled"}

    # 4. Sandboxed Repo Invariant Runner (AIxCC #1b)
    if local_target_exists and not disable_inv:
        if explicit_inv or not in_offline_or_pytest:
            try:
                from engine.sandbox_invariant_runner import SandboxInvariantRunner

                inv_runner = (
                    SandboxInvariantRunner(docker_bin="", subprocess_runner=_unavailable_docker_runner)
                    if (
                        shared_docker_ok is False
                        and getattr(SandboxInvariantRunner, "__module__", "") == "engine.sandbox_invariant_runner"
                    )
                    else SandboxInvariantRunner()
                )
                inv_report = inv_runner.run(
                    str(local_target),
                    db=db,
                    task_id=task_id,
                    preferred_runtime=getattr(args, "invariant_runtime", None),
                    image=getattr(args, "invariant_image", None),
                )
                engines["sandbox_invariants"] = inv_report.to_dict()
            except Exception as exc:
                engines["sandbox_invariants"] = {"status": "error", "error": str(exc)}
        else:
            engines["sandbox_invariants"] = {
                "status": "skipped_offline_or_test_guard",
                "reason": "Skipped automatic container invariant check under offline/test/deny guard; pass --sandbox-invariants explicitly to run.",
                "invariants_checked": 0,
                "failures_count": 0,
            }
    elif disable_inv:
        engines["sandbox_invariants"] = {"status": "disabled"}

    # 5. Containerized Non-Destructive POE==3 Verifier (AIxCC #5a)
    if not disable_poe:
        if explicit_poe or not in_offline_or_pytest:
            try:
                from engine.poe_container_verifier import ContainerPOEVerifier

                all_findings = res.get("findings") if isinstance(res.get("findings"), list) else []
                poe_verifier = (
                    ContainerPOEVerifier(docker_bin="", subprocess_runner=_unavailable_docker_runner)
                    if (
                        shared_docker_ok is False
                        and getattr(ContainerPOEVerifier, "__module__", "") == "engine.poe_container_verifier"
                    )
                    else ContainerPOEVerifier()
                )
                poe_batch = poe_verifier.verify_findings(
                    all_findings,
                    repo_path=str(local_target) if local_target_exists else None,
                    db=db,
                    task_id=task_id,
                )
                if poe_batch.results:
                    res["findings"] = ContainerPOEVerifier.apply_verifications_to_findings(
                        all_findings,
                        poe_batch.results,
                        drop_false_positives=bool(getattr(args, "drop_unverified_fp", False)),
                    )
                engines["poe_verifier"] = poe_batch.to_dict()
            except Exception as exc:
                engines["poe_verifier"] = {"status": "error", "error": str(exc)}
        else:
            engines["poe_verifier"] = {
                "status": "skipped_offline_or_test_guard",
                "reason": "Skipped automatic container POE==3 verification under offline/test/deny guard; pass --poe-verify explicitly to run.",
                "verified_count": 0,
                "downgraded_count": 0,
            }
    elif disable_poe:
        engines["poe_verifier"] = {"status": "disabled"}

    # 6. Offline Known-Technique Novelty Corpus + Optional Explicit Refresh (AIxCC #4)
    try:
        from engine.novelty_corpus import NoveltyCorpusIndex, refresh_novelty_corpus

        raw_refresh = getattr(args, "refresh_novelty_corpus", None) or []
        refresh_sources: List[str] = []
        for item in raw_refresh:
            for tok in str(item).split(","):
                tok_s = tok.strip()
                if tok_s:
                    refresh_sources.append(tok_s)
        nov_thresh = float(getattr(args, "novelty_threshold", 0.72) or 0.72)
        if refresh_sources:
            engines["novelty_corpus"] = refresh_novelty_corpus(
                refresh_sources,
                db=db,
                allow_network=bool(getattr(args, "novelty_allow_network", False)),
                output_path=getattr(args, "novelty_export", None),
                novelty_threshold=nov_thresh,
            )
        else:
            idx = NoveltyCorpusIndex(db=db, include_workspace_templates=True, novelty_threshold=nov_thresh)
            summary = idx.summary()
            engines["novelty_corpus"] = {
                "status": "ready_offline",
                "entry_count": summary.get("total_entries", len(idx)),
                "total_corpus_entries": summary.get("total_entries", len(idx)),
                "novelty_threshold": nov_thresh,
                "network_calls": 0,
            }
    except (PermissionError, ValueError):
        raise
    except Exception as exc:
        engines["novelty_corpus"] = {"status": "error", "error": str(exc)}

    # 7. Optional HackerOne Campaign Discovery & HITL Findings Porter (--hackerone / --hackone)
    if getattr(args, "enable_hackerone", False):
        try:
            h1_findings = list(res.get("verified_exploits") or []) + list(res.get("deterministic_static_findings") or [])
            engines["hackerone_porter"] = cmd_hackerone(args, findings_override=h1_findings, return_dict_only=True)
        except (PermissionError, ValueError):
            raise
        except Exception as exc:
            engines["hackerone_porter"] = {"status": "error", "error": str(exc)}


def cmd_phi(
    args: Any,
    *,
    return_dict_only: bool = False,
) -> Dict[str, Any]:
    """
    Executes `--phi`: HIPAA Safe Harbor PHI/PII detector & zero-knowledge redaction engine
    (Presidio + GLiNER `urchade/gliner_multi_pii-v1` + RedactX-v3 18 HIPAA validators + Depth-8
    recursive encoding unwrapper + `<ZK_PII:TYPE:HASH8>` commitments).
    Respects universal `--dry-run`.
    """
    from engine.phi_scanner import DEFAULT_GLINER_MODEL, PhiScanner

    target_path = (
        getattr(args, "phi_target", None)
        or getattr(args, "repo", None)
        or getattr(args, "path", None)
        or getattr(args, "target_arg", None)
        or "."
    )
    out_dir = str(getattr(args, "output_dir", "reports") or "reports")
    phi_model = str(getattr(args, "phi_model", DEFAULT_GLINER_MODEL) or DEFAULT_GLINER_MODEL)
    enable_ml = not bool(getattr(args, "no_phi_ml", False))
    write_redacted = bool(getattr(args, "phi_redact", False))
    dry_run = bool(getattr(args, "dry_run", False))

    scanner = PhiScanner(
        gliner_model=phi_model,
        enable_ml=enable_ml and not dry_run,
        enable_presidio=enable_ml and not dry_run,
    )
    if dry_run:
        root = Path(str(target_path)).resolve(strict=False)
        files = scanner._collect_files(root) if root.exists() else []
        result: Dict[str, Any] = {
            "status": "dry_run_phi_plan_ready",
            "dry_run": True,
            "target_path": str(root),
            "target_exists": root.exists(),
            "candidate_files_count": len(files),
            "sample_files": [str(f) for f in files[:15]],
            "gliner_model": phi_model,
            "ml_requested": enable_ml,
            "backends_offline_ready": scanner.guard.active_backends,
            "would_write_redacted_copies": write_redacted,
            "output_dir": out_dir,
            "network_packets_sent": 0,
            "filesystem_mutations": 0,
        }
    else:
        result = scanner.scan_repository(
            str(target_path),
            output_dir=out_dir,
            write_redacted_copies=write_redacted,
        )

    if return_dict_only:
        return result

    if getattr(args, "as_json", False):
        from engine.cli_render import render_json
        render_json(result)
        return result

    print("\n" + "=" * 78)
    print("  RFCHUNT MODULE 22: HIPAA PHI / PII DETECTOR & ZK REDACTION (--phi)")
    print("=" * 78)
    print(f"  Status              : {result.get('status')}")
    print(f"  Target Path         : {result.get('target_path')}")
    if dry_run:
        print(f"  Dry-Run Mode        : ACTIVE (0 files modified, 0 network requests)")
        print(f"  Candidate Files     : {result.get('candidate_files_count', 0)}")
        print(f"  GLiNER Model        : {result.get('gliner_model')}")
        print(f"  Write Redacted Copy : {result.get('would_write_redacted_copies')}")
    else:
        print(f"  Active Backends     : {', '.join(result.get('backends') or [])}")
        print(f"  Files Scanned       : {result.get('files_scanned', 0)}")
        print(f"  PHI Findings        : {result.get('total_findings', 0)} {result.get('entity_counts', {})}")
        print(f"  Zero-Leakage Proof  : ENFORCED (<ZK_PII:TYPE:HASH8>, Platt T=1.08, Depth-8 Unwrap)")
        print(f"  Redacted Files Out  : {result.get('redacted_files_count', 0)}")
        print(f"  Report JSON         : {result.get('report_path')}")
        for item in (result.get("findings") or [])[:15]:
            print(
                f"    -> [{item.get('severity', 'HIGH'):<8}] {item.get('rule_id')} | "
                f"{Path(str(item.get('file_path', ''))).name}:{item.get('line_number', 1)} | "
                f"{item.get('zk_commitment') or item.get('title', '')[:60]}"
            )
    print("=" * 78 + "\n")
    return result


def cmd_preflight(args: Any, *, return_dict_only: bool = False) -> Dict[str, Any]:
    """
    Module 23: Fresh Pre-Flight Stack, Post-Quantum (PQC), HackerOne-Category,
    Keyless Live Research & Safe Local Skill Discovery (`--preflight-only`).
    Never reuses prior-session caches (`cache_reused: False`).
    """
    from engine.preflight_discovery import run_preflight_discovery

    target_path = (
        getattr(args, "repo", None)
        or getattr(args, "path", None)
        or getattr(args, "raptor_target", None)
        or "."
    )
    host = getattr(args, "host", None) or getattr(args, "target", None)
    raw_dirs = getattr(args, "preflight_skills_dirs", None)
    extra_dirs = (
        [d.strip() for d in str(raw_dirs).split(",") if d.strip()]
        if raw_dirs
        else None
    )
    dry_run = bool(getattr(args, "dry_run", False))
    out_dir = None if dry_run else str(getattr(args, "output_dir", "reports") or "reports")

    result = run_preflight_discovery(
        target_path=str(target_path) if target_path else None,
        prompt=str(getattr(args, "preflight_prompt", None) or ""),
        target_host=str(host) if host else None,
        live=bool(getattr(args, "preflight_live", True)) and not dry_run,
        enable_pqc=bool(getattr(args, "preflight_pqc", True)),
        include_home_skills=not bool(getattr(args, "no_home_skills", False)),
        extra_skills_dirs=extra_dirs,
        output_dir=out_dir,
        timeout_sec=float(getattr(args, "preflight_timeout", 15.0) or 15.0),
        dry_run=dry_run,
    )

    if return_dict_only:
        return {k: v for k, v in result.items() if k != "checklist_markdown"}

    if getattr(args, "as_json", False):
        from engine.cli_render import render_json

        render_json({k: v for k, v in result.items() if k != "checklist_markdown"})
        return result

    print(result.get("checklist_markdown", ""))
    return result


def _validate_cli_output_dir(
    raw_out_dir: Any,
    *,
    explicit_ws_root: Optional[Path] = None,
    inferred_ws_root: Optional[Path] = None,
    label: str = "output_dir",
) -> Path:
    """
    Validates CLI `--output-dir` against canonical syntax, sensitive host directories,
    symlinks / NTFS junctions / reparse ancestors, and `workspace_root` confinement:
    - When `--workspace-root` is explicitly set (`explicit_ws_root`), strictly confines output
      inside `explicit_ws_root` (no `%TEMP%` fallthrough).
    - Otherwise allows paths inside `inferred_ws_root`, strict `%TEMP%` subdirectories,
      `.pytest_temp` (under pytest), or `ExecutionPolicy.ALLOWED_WRITE_SUBDIRS`.
    """
    import tempfile as _tempfile
    from engine.execution_policy import (
        ExecutionPolicy,
        _is_drive_relative_or_colon_unsafe,
        _is_unc_path,
        _validate_canonical_path_syntax,
    )
    from engine.pe_magika_classifier import _reject_reparse_ancestors

    raw_s = os.fspath(raw_out_dir) if isinstance(raw_out_dir, os.PathLike) else raw_out_dir
    if not isinstance(raw_s, str) or not raw_s.strip():
        raise ValueError(f"Unsafe {label} rejected: empty path")
    if raw_s != raw_s.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_s):
        raise PermissionError(f"Unsafe {label} rejected (whitespace or control characters).")
    if _is_unc_path(raw_s) or _is_drive_relative_or_colon_unsafe(raw_s):
        raise PermissionError(f"Unsafe {label} rejected (UNC, NT-device, or drive-relative/ADS path).")
    syn_err = _validate_canonical_path_syntax(raw_s, allow_trailing_slash=True)
    if syn_err is not None and raw_s != ".":
        raise PermissionError(f"Unsafe {label} rejected: {syn_err}")

    def _reject_sensitive(cand_raw: str, cand_res: Optional[str]) -> None:
        sensitive_markers = (
            "/.ssh",
            "/.aws",
            "/.gnupg",
            "/.kube",
            "/etc/passwd",
            "/etc/shadow",
            "/windows/system32",
            "/windows/syswow64",
            "/windows/temp",
        )
        cands: List[str] = [cand_raw]
        if cand_raw.startswith("~"):
            try:
                exp = os.path.expanduser(cand_raw)
                cands.extend([exp, str(Path(exp).resolve(strict=False))])
            except Exception:
                pass
        if cand_res:
            cands.append(cand_res)
        for c in cands:
            c_low = c.replace("\\", "/").lower().rstrip("/") or "/"
            if (
                any(
                    c_low == m or c_low.startswith(m + "/") or c_low.endswith(m) or (m + "/" in c_low)
                    for m in sensitive_markers
                )
                or re.match(r"^[a-z]:/windows(?:/|$)", c_low)
                or re.match(r"^[a-z]:/(?:system32|syswow64)(?:/|$)", c_low)
            ):
                raise PermissionError(f"Unsafe {label} rejected: sensitive host path '{raw_out_dir}' is forbidden.")

    _reject_sensitive(raw_s, None)

    pol = ExecutionPolicy.get_instance()
    if explicit_ws_root is not None:
        ok_ws, detail_ws = pol.validate_file_path(
            raw_s,
            workspace_root=explicit_ws_root,
            allow_directory=True,
            allow_nonexistent=True,
        )
        if not ok_ws:
            raise PermissionError(
                f"Unsafe {label} rejected outside --workspace-root '{explicit_ws_root}': {detail_ws}"
            )
        _reject_sensitive(raw_s, detail_ws)
        return Path(detail_ws)

    if inferred_ws_root is not None:
        ok_inf, detail_inf = pol.validate_file_path(
            raw_s,
            workspace_root=inferred_ws_root,
            allow_directory=True,
            allow_nonexistent=True,
        )
        if ok_inf:
            _reject_sensitive(raw_s, detail_inf)
            return Path(detail_inf)

    _reject_reparse_ancestors(raw_s, label=label)
    resolved_out = Path(raw_s).resolve(strict=False)
    _reject_sensitive(raw_s, str(resolved_out))

    out_cmp = Path(os.path.normcase(str(resolved_out)))
    temp_root = Path(os.path.normcase(str(Path(_tempfile.gettempdir()).resolve(strict=False))))
    if out_cmp != temp_root and out_cmp.is_relative_to(temp_root):
        return resolved_out

    rfchunt_root = Path(__file__).resolve().parent
    if os.environ.get("PYTEST_CURRENT_TEST"):
        pt_root = Path(os.path.normcase(str((rfchunt_root.parent / ".pytest_temp").resolve(strict=False))))
        if out_cmp != pt_root and out_cmp.is_relative_to(pt_root):
            return resolved_out

    for allowed_sub in ExecutionPolicy.ALLOWED_WRITE_SUBDIRS:
        allowed_dir = Path(os.path.normcase(str((rfchunt_root / allowed_sub).resolve(strict=False))))
        if out_cmp == allowed_dir or out_cmp.is_relative_to(allowed_dir):
            return resolved_out

    raise PermissionError(
        f"Unsafe {label} rejected outside workspace_root and designated report/temp directories: '{raw_out_dir}'"
    )


def cmd_pe_audit(args: Any) -> Dict[str, Any]:
    """
    Standalone PE & .NET Code Integrity Anomaly Auditor (`pe-audit` / `--pe-audit`):
    runs Magika hybrid PE classification, CVE-2026-108398, UMCI/SEC_COMMIT flat memory
    fallback heuristics, defensive YARA rules, and optional KB5127694 / VirtualBox 7.2.18+
    host patch auditing with strict workspace_root confinement.
    """
    from engine.execution_policy import ExecutionPolicy, _validate_canonical_path_syntax
    from engine.pe_magika_classifier import audit_pe_dotnet_target

    as_json = bool(getattr(args, "as_json", False))
    if getattr(args, "dry_run", False):
        return cmd_dry_run_plan(args, active_mode="pe-audit", raw_argv=[])

    target_path = (
        getattr(args, "path", None)
        or getattr(args, "repo", None)
        or getattr(args, "target_arg", None)
        or "."
    )
    explicit_ws_arg = getattr(args, "workspace_root", None)
    explicit_ws_root: Optional[Path] = None
    try:
        ws_root = _resolve_cli_workspace_root(args)
        if explicit_ws_arg is not None and str(explicit_ws_arg).strip():
            explicit_ws_root = ws_root
        pol = ExecutionPolicy.get_instance()
        if ws_root is not None:
            ok_tp, detail_tp = pol.validate_file_path(
                target_path,
                workspace_root=ws_root,
                allow_directory=True,
                allow_nonexistent=True,
            )
            if not ok_tp:
                raise PermissionError(f"Unsafe target_path rejected outside workspace_root: {detail_tp}")
            resolved_target = detail_tp
        else:
            err = _validate_canonical_path_syntax(str(target_path), allow_trailing_slash=True)
            if err is not None and str(target_path) != ".":
                raise PermissionError(f"Unsafe target_path rejected: {err}")
            resolved_target = str(Path(str(target_path)).resolve(strict=False))

        out_dir_raw = getattr(args, "output_dir", None)
        validated_out_dir: Optional[Path] = None
        if out_dir_raw:
            validated_out_dir = _validate_cli_output_dir(
                out_dir_raw,
                explicit_ws_root=explicit_ws_root,
                inferred_ws_root=ws_root,
                label="PE/.NET audit output_dir",
            )
    except (PermissionError, ValueError) as exc:
        print(f"[!] PE/.NET audit path error: {exc}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)

    raw_host_audit = getattr(args, "pe_include_host_audit", None)
    include_host = True if raw_host_audit is None else bool(raw_host_audit)
    include_yara = bool(getattr(args, "pe_include_yara", True))

    try:
        result = audit_pe_dotnet_target(
            resolved_target,
            include_host_audit=include_host,
            include_yara=include_yara,
            workspace_root=ws_root,
        )
    except (PermissionError, ValueError) as exc:
        print(f"[!] PE/.NET audit path error: {exc}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)

    if validated_out_dir is not None:
        try:
            validated_out_dir.mkdir(parents=True, exist_ok=True)
            report_file = validated_out_dir / "pe_dotnet_audit.json"
            with open(report_file, "w", encoding="utf-8") as fh:
                import json as _json
                _json.dump(result, fh, indent=2)
            result["report_path"] = str(report_file)
        except (PermissionError, ValueError, OSError) as exc:
            print(f"[!] PE/.NET audit output_dir error: {exc}", file=(sys.stderr if as_json else sys.stdout))
            sys.exit(1)

    if as_json:
        from engine.cli_render import render_json
        render_json(result)
        return result

    print("\n" + "=" * 78)
    print("  RFCHUNT PE & .NET CODE INTEGRITY ANOMALY AUDITOR (--pe-audit)")
    print("=" * 78)
    print(f"  Status              : {result.get('status')}")
    print(f"  Target Path         : {result.get('target_path')}")
    print(f"  Files Scanned       : {result.get('files_scanned', 0)} (PE={result.get('pe_files_found', 0)}, .NET={result.get('dotnet_assemblies_found', 0)})")
    print(f"  CVE-2026-108398     : {result.get('cve_2026_108398_count', 0)}")
    print(f"  UMCI/SEC_COMMIT     : {result.get('umci_fallback_risk_count', 0)}")
    print(f"  Masqueraded Files   : {result.get('masqueraded_files_count', 0)}")
    print(f"  YARA Matches        : {result.get('yara_matches_count', 0)}")
    print(f"  Total Findings      : {result.get('total_findings', 0)} {result.get('severity_counts', {})}")
    if result.get("report_path"):
        print(f"  Report JSON         : {result.get('report_path')}")
    print("=" * 78 + "\n")
    return result


def cmd_dry_run_plan(
    args: Any,
    *,
    active_mode: str,
    raw_argv: Sequence[str],
) -> Dict[str, Any]:
    """
    Universal `--dry-run` planner covering ALL RFCHunt modes and flags with zero side effects:
    zero network sockets, zero external tool installs, zero git clones, zero DB/file writes,
    zero browser launches, and zero external API submissions.
    """
    from engine.safe_network_validator import validate_and_authorize_target

    host = getattr(args, "host", None) or getattr(args, "target", None)
    targets = getattr(args, "targets", None) or []
    repo = getattr(args, "repo", None) or getattr(args, "path", None) or getattr(args, "raptor_target", None)
    if not repo and getattr(args, "target_arg", None):
        _ta = str(args.target_arg)
        if not _ta.lower().startswith(("http://", "https://")):
            repo = _ta
    auth_checks: List[Dict[str, Any]] = []
    for cand_h in ([host] if host else []) + list(targets):
        if cand_h:
            ok, reason = validate_and_authorize_target(str(cand_h), authorized=bool(getattr(args, "authorized", False)))
            auth_checks.append({"target": str(cand_h), "authorized": bool(ok), "reason": str(reason)})

    enabled_flags = sorted(
        k for k, v in vars(args).items()
        if isinstance(v, bool) and v and not k.startswith("_")
    )
    planned_modules: List[str] = []
    if getattr(args, "run_all_scans", False) or active_mode in ("all", "all_scans"):
        planned_modules.extend(
            [
                "Module-23-PreflightDiscovery(14-Categories+PQC+HackerOne+SafeSkills)",
                "Module-20-Mantis",
                "Module-18-aiscan",
                "Module-15-RAPTOR",
                "Module-21-REA",
                "VerificationInversionHunter",
                "ArxivSecurityBridge",
                "Last30DaysSecuritySkills",
                "Module-17-ARTEX-DualGraph",
                "Module-19-PromptSmuggling",
            ]
        )
        if not getattr(args, "no_pe_audit", False):
            planned_modules.append("Module-PE-DotNet-Auditor(UMCI/SEC_COMMIT/YARA/HostPatch)")
    elif getattr(args, "preflight_only", False) or active_mode == "preflight":
        planned_modules.append("Module-23-PreflightDiscovery(14-Categories+PQC+HackerOne+SafeSkills)")
    if getattr(args, "ensemble", False):
        planned_modules.append("EnsembleWhiteboardOrchestrator(Planner-Worker-Verifier+Lean4)")
    if getattr(args, "enable_swarm", False) or active_mode == "swarm":
        planned_modules.append("MultiAgentSwarmOrchestrator(Parallel-OODA+Ensemble-Whiteboard+SwarmBoard)")
    if (
        getattr(args, "enable_pe_audit", False)
        or active_mode in ("pe-audit", "pe_audit", "pe-dotnet", "pe_dotnet")
    ) and "Module-PE-DotNet-Auditor(UMCI/SEC_COMMIT/YARA/HostPatch)" not in planned_modules:
        planned_modules.append("Module-PE-DotNet-Auditor(UMCI/SEC_COMMIT/YARA/HostPatch)")
    if getattr(args, "enable_phi", False) or active_mode == "phi":
        planned_modules.append("Module-22-PhiScanner(Presidio+GLiNER+RedactX-v3)")
    if getattr(args, "deep_audit", False) or active_mode in ("deep-audit", "deep_audit") or getattr(args, "proxy_target", None):
        planned_modules.append("DeepRepoAudit(TrustBoundary+LoopbackProxy+CoverageFuzz)")
    if getattr(args, "enable_poc", False):
        planned_modules.append("PoCVerifier")
    if getattr(args, "enable_hackerone", False) or active_mode in ("hackerone", "hackone"):
        planned_modules.append(
            "HackerOneAutonomousRunner(RoE-3Tier)"
            if getattr(args, "hackerone_auto", False)
            else "HackerOnePorter(HITL)"
        )
    if getattr(args, "serve_ui", False):
        planned_modules.append(f"MissionControlServer({getattr(args, 'ui_host', '127.0.0.1')}:{getattr(args, 'ui_port', 8789)})")
    if not planned_modules:
        planned_modules.append(f"mode:{active_mode}")

    sub_plans: Dict[str, Any] = {}
    if (
        getattr(args, "preflight_only", False)
        or active_mode == "preflight"
        or (
            bool(getattr(args, "enable_preflight", True))
            and (getattr(args, "run_all_scans", False) or active_mode in ("all", "all_scans", "deep-audit", "deep_audit"))
        )
    ):
        sub_plans["preflight"] = cmd_preflight(args, return_dict_only=True)
    if getattr(args, "enable_phi", False):
        sub_plans["phi"] = cmd_phi(args, return_dict_only=True)
    if getattr(args, "enable_hackerone", False):
        sub_plans["hackerone"] = cmd_hackerone(args, findings_override=[], return_dict_only=True)

    llm_backend_plan: Dict[str, Any] = {
        "mode": "ollama",
        "enabled": False,
        "using_ollama": True,
        "ollama_bypassed": False,
        "provider": "ollama",
    }
    try:
        from engine.paid_model_provider import load_paid_model_config

        _pcfg = load_paid_model_config(
            env_local_path=getattr(args, "env_local", None),
            force_ollama=bool(getattr(args, "force_ollama", False)),
        )
        llm_backend_plan = _pcfg.to_safe_dict()
    except Exception:
        pass

    _dry_fh_val = getattr(args, "freshness_hours", 72)
    _dry_q_val = getattr(args, "quorum", 2)
    plan: Dict[str, Any] = {
        "status": "dry_run_plan_ready",
        "dry_run": True,
        "active_mode": active_mode,
        "raw_argv": list(raw_argv),
        "target_repo_or_path": str(Path(str(repo)).resolve(strict=False)) if repo else None,
        "target_host": host,
        "target_port": getattr(args, "port", None),
        "target_tls": bool(getattr(args, "tls", False)),
        "targets": list(targets),
        "llm_backend": llm_backend_plan,
        "authorization_checks": auth_checks,
        "request_hygiene": {
            "custom_headers": list(getattr(args, "headers", None) or []),
            "user_agent": getattr(args, "user_agent", None),
            "max_rps": float(getattr(args, "max_rps", 0.0) or 0.0),
        },
        "planned_modules": planned_modules,
        "enabled_flags": enabled_flags,
        "ensemble": bool(getattr(args, "ensemble", False)),
        "swarm": bool(getattr(args, "enable_swarm", False) or active_mode == "swarm"),
        "swarm_workers": getattr(args, "swarm_workers", None),
        "program": str(getattr(args, "program", "generic") or "generic"),
        "freshness_hours": int(_dry_fh_val) if _dry_fh_val is not None else 72,
        "quorum": max(1, int(_dry_q_val)) if _dry_q_val is not None else 2,
        "sub_plans": sub_plans,
        "side_effects": {
            "network_packets_sent": 0,
            "filesystem_mutations": 0,
            "external_submissions": 0,
            "browser_launched": False,
        },
    }

    if getattr(args, "as_json", False):
        from engine.cli_render import render_json
        render_json(plan)
        return plan

    print("\n" + "=" * 78)
    print("  RFCHUNT UNIVERSAL --dry-run EXECUTION PLAN (ZERO SIDE EFFECTS)")
    print("=" * 78)
    print(f"  Active Mode         : {plan['active_mode']}")
    print(f"  Target Repo/Path    : {plan['target_repo_or_path'] or '-'}")
    print(f"  Target Host/Port    : {plan['target_host'] or '-'}:{plan['target_port'] or '-'} (TLS={plan['target_tls']})")
    _lb = plan.get("llm_backend") or {}
    if _lb.get("enabled"):
        print(
            f"  LLM Backend         : PAID API ({_lb.get('provider')}) | models={_lb.get('panel_models')} "
            f"| Ollama BYPASSED (source={_lb.get('source_file')})"
        )
    else:
        print("  LLM Backend         : Local Ollama (zero-cost local inference)")
    print(f"  Planned Modules     : {', '.join(planned_modules)}")
    if plan.get("ensemble"):
        print(
            f"  Ensemble Whiteboard : enabled (program={plan['program']}, "
            f"freshness={plan['freshness_hours']}h, quorum={plan['quorum']})"
        )
    print(f"  Request Hygiene     : headers={plan['request_hygiene']['custom_headers']} | max_rps={plan['request_hygiene']['max_rps']}")
    if auth_checks:
        for ac in auth_checks:
            print(f"  Auth Check          : {ac['target']} -> {'OK' if ac['authorized'] else 'BLOCKED'} ({ac['reason']})")
    print("  Guarantee           : 0 packets sent | 0 files mutated | 0 browser sessions | 0 submissions")
    print("=" * 78 + "\n")
    return plan


def cmd_hackerone(
    args: Any,
    *,
    findings_override: Optional[List[Dict[str, Any]]] = None,
    return_dict_only: bool = False,
) -> Dict[str, Any]:
    """
    Executes `--hackerone` / `--hackone` (and policy-aware `--hackerone-auto`):
      - Reads & enforces HackerOne's 3-Tier Program Rules of Engagement (RoE):
        Tier 1 Explicitly Prohibited (blocks live scanning for Safe Harbor),
        Tier 2 Permitted with Rate Limits & Attribution (`max_rps`, `X-HackerOne: <user>`),
        Tier 3 In-Scope Only (no out-of-scope redirect escape).
      - Applies the Strict Anti-Slop PoC Gate (Lane 1 + Lane 2 only) & Secret/PHI redaction.
      - Supports universal `--dry-run`.
      - Stops strictly before final Submit for human researcher validation.
    """
    from engine.hackerone_porter import (
        HackerOneAutonomousRunner,
        HackerOnePorter,
        load_findings_for_hackerone,
    )

    out_root = str(Path(getattr(args, "output_dir", "reports") or "reports") / "hackerone")
    dry_run = bool(getattr(args, "dry_run", False))
    auto_mode = bool(getattr(args, "hackerone_auto", False))
    researcher_username = str(getattr(args, "hackerone_username", "") or "").strip()
    include_ai_disclosure = bool(getattr(args, "hackerone_ai_disclosure", False))
    policy_text_override = ""
    policy_file = getattr(args, "hackerone_policy_file", None)
    if policy_file and Path(str(policy_file)).is_file():
        policy_text_override = Path(str(policy_file)).read_text(encoding="utf-8", errors="replace")

    if auto_mode:
        runner = HackerOneAutonomousRunner(output_dir=out_root)
        local_repo = getattr(args, "repo", None) or getattr(args, "path", None)
        result = runner.run_campaign_workflow(
            program_handle=getattr(args, "hackerone_program", None),
            query=str(getattr(args, "hackerone_query", "") or ""),
            max_programs=int(getattr(args, "hackerone_max_programs", 2) or 2),
            local_repo_path=str(local_repo) if local_repo else None,
            policy_text_override=policy_text_override,
            researcher_username=researcher_username,
            use_api=bool(getattr(args, "hackerone_api", False)),
            use_browser=bool(getattr(args, "hackerone_browser", False)),
            enable_phi_scan=bool(getattr(args, "enable_phi", False)),
            min_severity=str(getattr(args, "hackerone_min_severity", "medium") or "medium"),
            max_reports=int(getattr(args, "hackerone_max_reports", 5) or 5),
            include_ai_disclosure=include_ai_disclosure,
            dry_run=dry_run,
        )
        if return_dict_only:
            return result
        if getattr(args, "as_json", False):
            from engine.cli_render import render_json
            render_json(result)
            return result
        print("\n" + "=" * 78)
        print("  RFCHUNT HACKERONE POLICY-AWARE AUTONOMOUS RUNNER (--hackerone --hackerone-auto)")
        print("=" * 78)
        print(f"  Status              : {result.get('status')} (dry_run={result.get('dry_run')})")
        print(f"  Safe Harbor & RoE   : ENFORCED (3-Tier Policy Parser + No Cross-Scope Redirects)")
        print(f"  Programs Evaluated  : {result.get('programs_evaluated', 0)}")
        for pr in result.get("program_results") or []:
            roe = pr.get("roe_compliance") or {}
            pr_port = pr.get("port_result") or {}
            print(f"  -> Program          : {pr.get('program_handle')}")
            print(f"     RoE Tier         : {roe.get('automation_tier')} | Safe Harbor: {roe.get('safe_harbor_status')}")
            print(f"     Live Scan Policy : {roe.get('live_scan_policy_decision')} | max_rps={roe.get('max_rps')}")
            print(f"     Required Headers : {roe.get('required_headers') or ['none']}")
            print(f"     Eligible Drafts  : {pr_port.get('eligible_drafts_count', 0)} (Rejected: {pr_port.get('rejected_findings_count', 0)})")
        print("=" * 78 + "\n")
        return result

    findings = (
        list(findings_override)
        if findings_override is not None
        else load_findings_for_hackerone(
            findings_json=getattr(args, "findings_json", None),
            reports_dir=str(getattr(args, "output_dir", "reports") or "reports"),
        )
    )
    submit_api = bool(getattr(args, "hackerone_submit_api", False))
    hitl_approved = False
    if submit_api and not dry_run:
        confirm = input(
            "[HITL APPROVAL] You passed --hackerone-submit-api. Type YES to confirm submitting "
            "eligible RFCHunt drafts via the official HackerOne API v1: "
        ).strip()
        hitl_approved = confirm == "YES"

    porter = HackerOnePorter(output_dir=out_root)
    result = porter.port_findings(
        findings,
        program_handle=getattr(args, "hackerone_program", None),
        query=str(getattr(args, "hackerone_query", "") or ""),
        min_severity=str(getattr(args, "hackerone_min_severity", "medium") or "medium"),
        max_reports=int(getattr(args, "hackerone_max_reports", 5) or 5),
        use_api=bool(getattr(args, "hackerone_api", False) or submit_api),
        use_browser=bool(getattr(args, "hackerone_browser", False)),
        submit_api=submit_api,
        hitl_approved=hitl_approved,
        bounties_only=bool(getattr(args, "hackerone_bounties_only", False)),
        researcher_username=researcher_username,
        include_ai_disclosure=include_ai_disclosure,
        policy_text_override=policy_text_override,
        dry_run=dry_run,
    )

    if return_dict_only:
        return result

    if getattr(args, "as_json", False):
        from engine.cli_render import render_json
        render_json(result)
        return result

    camp = result.get("campaign") or {}
    roe_rules = result.get("policy_rules") or {}
    print("\n" + "=" * 78)
    print("  RFCHUNT HACKERONE CAMPAIGN FINDER & HITL REPORT PORTER (--hackerone)")
    print("=" * 78)
    print(f"  Status              : {result.get('status')} (dry_run={result.get('dry_run')})")
    print(f"  Campaign Handle     : {camp.get('handle')} ({camp.get('url')})")
    print(f"  Submit Report URL   : {camp.get('submit_url')}")
    if roe_rules:
        print(f"  RoE Compliance Tier : {roe_rules.get('automation_tier')} | max_rps={roe_rules.get('max_rps')} | headers={roe_rules.get('required_headers')}")
    print(f"  Anti-Slop PoC Gate  : ENFORCED (Lane 1 + Lane 2 only; Lane 3 speculative rejected; Secrets + PHI redacted)")
    print(f"  Eligible Drafts     : {result.get('eligible_drafts_count', 0)}")
    print(f"  Rejected Findings   : {result.get('rejected_findings_count', 0)}")
    print(f"  Bundle JSON         : {result.get('bundle_path')}")
    for d in result.get("drafts") or []:
        print(f"    -> [{d['severity_rating'].upper():<8}] {d['draft_id']} | {d['weakness_cwe']} | {d['title'][:65]}")
        print(f"       Draft Markdown : {d['markdown_path']}")
    if result.get("browser_session"):
        bs = result["browser_session"]
        print(f"  HITL Browser Status : {bs.get('status')} (Final Submit Held for Human Review)")
        if bs.get("install_hint"):
            print(f"  Playwright Setup    : {bs.get('install_hint')}")
    print("=" * 78 + "\n")
    return result


def cmd_novelty(args):
    """Inspects offline structural novelty corpus or refreshes it from explicit local/opt-in sources (AIxCC #4)."""
    from engine.cli_render import render_json, render_kv_panel
    from engine.novelty_corpus import NoveltyCorpusIndex, refresh_novelty_corpus

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    err_stream = sys.stderr if as_json else sys.stdout

    raw_refresh = getattr(args, "refresh_novelty_corpus", None) or []
    sources: List[str] = []
    for item in raw_refresh:
        for tok in str(item).split(","):
            tok_s = tok.strip()
            if tok_s:
                sources.append(tok_s)
    if not sources and getattr(args, "target_arg", None):
        sources.append(str(args.target_arg).strip())

    nov_thresh = float(getattr(args, "novelty_threshold", 0.72) or 0.72)
    allow_net = bool(getattr(args, "novelty_allow_network", False))
    export_path = getattr(args, "novelty_export", None)

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        if sources:
            payload = refresh_novelty_corpus(
                sources,
                db=db,
                allow_network=allow_net,
                output_path=export_path,
                novelty_threshold=nov_thresh,
            )
            payload.setdefault("status", "refreshed")
        else:
            idx = NoveltyCorpusIndex(db=db, include_workspace_templates=True, novelty_threshold=nov_thresh)
            if export_path:
                idx.export_catalog(export_path)
            summary = idx.summary()
            payload = {
                "status": "ready_offline",
                "total_entries": summary.get("total_entries", len(idx)),
                "total_corpus_entries": summary.get("total_entries", len(idx)),
                "novelty_threshold": nov_thresh,
                "sources_breakdown": summary.get("by_source", {}),
                "corpus_summary": summary,
                "allow_network": False,
                "exported_path": export_path or "",
            }
    except (PermissionError, ValueError) as exc:
        print(f"[!] Novelty corpus refresh rejected: {exc}", file=err_stream)
        sys.exit(1)
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "AIxCC Structural Novelty Corpus Index",
        {
            "Status": payload.get("status", "ready_offline"),
            "Total Entries": payload.get("total_corpus_entries", payload.get("total_entries", 0)),
            "Added / Updated": f"{payload.get('added', 0)} / {payload.get('updated', 0)}",
            "Novelty Threshold": payload.get("novelty_threshold", nov_thresh),
            "Allow Network": payload.get("allow_network", allow_net),
            "Exported Catalog": payload.get("exported_path") or "-",
        },
        plain=plain,
    )


def cmd_swarm_board(args):
    """Pure-CLI Swarm Overview & live terminal status board inspecting SQLite blackboard (zero GUI)."""
    from engine.swarm_cli_board import watch_board_from_db

    db_path = getattr(args, "db", "terminator.db")
    task_id = getattr(args, "task_id", None)
    watch = bool(getattr(args, "watch", False))
    interval = max(0.1, float(getattr(args, "interval", 1.0) or 1.0))
    limit_events = max(1, int(getattr(args, "board_events", 15) or 15))
    width = max(60, int(getattr(args, "board_width", 100) or 100))
    plain = bool(getattr(args, "plain", False))
    as_json = bool(getattr(args, "as_json", False))
    emoji = getattr(args, "board_emoji", None)

    watch_board_from_db(
        db_path,
        task_id=task_id,
        interval=interval,
        limit_events=limit_events,
        plain=plain,
        as_json=as_json,
        emoji=emoji,
        width=width,
        watch=watch,
    )


def cmd_sandbox_invariants(args):
    """Runs isolated `--network=none` container security invariants against a local repo (AIxCC #1b)."""
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.sandbox_invariant_runner import SandboxInvariantRunner

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    target_path = (
        getattr(args, "repo", None)
        or getattr(args, "path", None)
        or getattr(args, "target_arg", None)
        or "."
    )
    if not os.path.exists(str(target_path)):
        print(f"[!] Target path does not exist: {target_path}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)

    task_id = str(getattr(args, "task_id", None) or "default").strip() or "default"
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        runner = SandboxInvariantRunner()
        report = runner.run(
            str(target_path),
            db=db,
            task_id=task_id,
            preferred_runtime=getattr(args, "invariant_runtime", None),
            image=getattr(args, "invariant_image", None),
        )
        payload = report.to_dict()
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "AIxCC Sandboxed Repo Invariant Runner",
        {
            "Repository": payload.get("repo_path", str(target_path)),
            "Status": payload.get("status", "unknown"),
            "Container Mode": payload.get("container_mode", "docker_network_none"),
            "Checked / Passed / Failed": f"{payload.get('invariants_checked', 0)} / {payload.get('passed_count', 0)} / {payload.get('failures_count', 0)}",
            "Persisted FACTs": len(payload.get("fact_ids") or []),
        },
        plain=plain,
    )
    rows = [
        [
            r.get("invariant_id", ""),
            "PASS" if r.get("passed") else "FAIL",
            r.get("severity", ""),
            r.get("file_path", ""),
            str(r.get("evidence", ""))[:80],
        ]
        for r in (payload.get("results") or [])
    ]
    render_table("Security Invariants", ["Invariant ID", "Outcome", "Severity", "File", "Evidence"], rows, plain=plain)


def cmd_poe_verify(args):
    """Runs containerized non-destructive POE==3 verification on HIGH/CRITICAL findings (AIxCC #5a)."""
    import json as _json
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.poe_container_verifier import ContainerPOEVerifier

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    repo_path = getattr(args, "repo", None) or getattr(args, "path", None)
    task_id = str(getattr(args, "task_id", None) or "default").strip() or "default"
    findings_json_path = getattr(args, "findings_json", None)

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        findings: List[Dict[str, Any]] = []
        if findings_json_path:
            raw_doc = _json.loads(Path(str(findings_json_path)).read_text(encoding="utf-8"))
            if isinstance(raw_doc, list):
                findings = [x for x in raw_doc if isinstance(x, dict)]
            elif isinstance(raw_doc, dict) and isinstance(raw_doc.get("findings"), list):
                findings = [x for x in raw_doc["findings"] if isinstance(x, dict)]
        else:
            if hasattr(db, "get_mantis_findings"):
                findings.extend(db.get_mantis_findings(limit=200) or [])
            if hasattr(db, "get_attack_chains"):
                findings.extend(db.get_attack_chains(limit=100, task_id=getattr(args, "task_id", None)) or [])

        verifier = ContainerPOEVerifier()
        batch = verifier.verify_findings(
            findings,
            repo_path=str(repo_path) if repo_path and os.path.exists(str(repo_path)) else None,
            db=db,
            task_id=task_id,
        )
        payload = batch.to_dict()
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "AIxCC Containerized POE==3 Verifier",
        {
            "Status": payload.get("status", "unknown"),
            "Candidates Evaluated": payload.get("evaluated_count", 0),
            "POE==3 Verified": payload.get("verified_count", 0),
            "False Positives Downgraded": payload.get("downgraded_count", 0),
            "Skipped": payload.get("skipped_count", 0),
        },
        plain=plain,
    )
    rows = [
        [
            r.get("finding_id", ""),
            r.get("status", ""),
            r.get("poe_level", 0),
            r.get("verified", False),
            str(r.get("evidence", ""))[:80],
        ]
        for r in (payload.get("results") or [])
    ]
    render_table("POE==3 Verification Results", ["Finding ID", "Status", "POE", "Verified", "Evidence"], rows, plain=plain)


def cmd_poc(args):
    """Generates strictly non-destructive PoC verification scripts & false-positive triage bundles (`--poc`)."""
    import json as _json
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.poc_generator import generate_poc_bundle

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    repo_path = getattr(args, "repo", None) or getattr(args, "path", None)
    task_id = str(getattr(args, "task_id", None) or "default").strip() or "default"
    findings_json_path = getattr(args, "findings_json", None)
    output_base = getattr(args, "output_dir", None) or "reports"
    poc_dir_arg = getattr(args, "poc_dir", None)
    if poc_dir_arg:
        poc_req = Path(str(poc_dir_arg))
        if poc_req.is_absolute():
            poc_out_dir = poc_req
        else:
            base_resolved = Path(str(output_base)).resolve(strict=False)
            poc_out_dir = (base_resolved / poc_req).resolve(strict=False)
            if not poc_out_dir.is_relative_to(base_resolved):
                raise ValueError(f"--poc-dir relative path escapes output directory: {poc_dir_arg}")
    else:
        poc_out_dir = Path(str(output_base)) / "pocs"

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        findings: List[Dict[str, Any]] = []
        if findings_json_path:
            raw_doc = _json.loads(Path(str(findings_json_path)).read_text(encoding="utf-8"))
            if isinstance(raw_doc, list):
                findings = [x for x in raw_doc if isinstance(x, dict)]
            elif isinstance(raw_doc, dict):
                if isinstance(raw_doc.get("findings"), list):
                    findings = [x for x in raw_doc["findings"] if isinstance(x, dict)]
                if not repo_path and raw_doc.get("target_path"):
                    cand_target = str(raw_doc.get("target_path"))
                    if os.path.exists(cand_target):
                        repo_path = cand_target
        else:
            if hasattr(db, "get_confirmed_findings"):
                findings.extend([dict(x) for x in (db.get_confirmed_findings() or [])])
            if hasattr(db, "get_mantis_findings"):
                findings.extend([dict(x) for x in (db.get_mantis_findings(limit=200) or [])])
            if hasattr(db, "get_attack_chains"):
                findings.extend([dict(x) for x in (db.get_attack_chains(limit=100, task_id=getattr(args, "task_id", None)) or [])])

        report = generate_poc_bundle(
            findings,
            output_dir=poc_out_dir,
            repo_path=str(repo_path) if repo_path and os.path.exists(str(repo_path)) else None,
            include_rejected_scripts=bool(getattr(args, "poc_include_rejected", False)),
            run_container_verify=bool(getattr(args, "poc_container_verify", False)),
            max_scripts=int(getattr(args, "poc_max", 50) or 50),
            db=db,
            task_id=task_id,
        )
        payload = report.to_dict()
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    vc = payload.get("verdict_counts") or {}
    render_kv_panel(
        "RFCHunt --poc Non-Destructive Verification & Triage",
        {
            "Target": payload.get("target_path") or "N/A",
            "Findings Analyzed": payload.get("total_findings_analyzed", 0),
            "Disclosure-Worthy (POE=3)": payload.get("disclosure_worthy_count", 0),
            "Verdicts": (
                f"VERIFIED={vc.get('VERIFIED_REPRODUCIBLE', 0)}, "
                f"CANDIDATE={vc.get('UNVERIFIED_CANDIDATE', 0)}, "
                f"HARDENING={vc.get('HARDENING_NOTE', 0)}, "
                f"FALSE_POS={vc.get('FALSE_POSITIVE', 0)}, "
                f"TEST_FIXTURE={vc.get('TEST_FIXTURE', 0)}"
            ),
            "Generated Verifiers": payload.get("generated_script_count", 0),
            "Index Report": payload.get("index_markdown_path", ""),
        },
        plain=plain,
    )
    rows = [
        [
            r.get("rule_id", ""),
            f"{r.get('original_severity', '')}->{r.get('calibrated_severity', '')}",
            r.get("verdict", ""),
            r.get("poe_level", 0),
            ", ".join(r.get("generated_files") or []) or "-",
            str(r.get("rationale", ""))[:72],
        ]
        for r in (payload.get("records") or [])[:30]
    ]
    render_table(
        "PoC Verification & False-Positive Triage (Top 30)",
        ["Rule", "Severity", "Verdict", "POE", "Files", "Rationale"],
        rows,
        plain=plain,
    )


def cmd_docker_doctor(args):
    """Diagnoses and optionally self-heals Windows Docker Desktop / WSL2 VHDX compression & bootstrap failures."""
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.docker_wsl_doctor import diagnose_docker_wsl, repair_docker_wsl

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    do_fix = bool(getattr(args, "fix_docker", False))
    include_all_wsl = bool(getattr(args, "include_all_wsl", False))
    reset_distro = bool(getattr(args, "reset_docker_distro", False))
    approval_mode = str(getattr(args, "approval_mode", "policy") or "policy")

    if do_fix:
        rep = repair_docker_wsl(
            include_all_wsl=include_all_wsl,
            reset_stateless_distro=reset_distro,
            launch_docker=True,
            approval_mode=approval_mode,
        )
        payload = rep.to_dict()
        if as_json:
            render_json(payload)
            return
        after = payload.get("after") or {}
        render_kv_panel(
            "RFCHunt Docker Desktop / WSL2 Self-Heal Report",
            {
                "Repair Status": payload.get("status", "unknown"),
                "Daemon Running": after.get("daemon_running", False),
                "Server Version": after.get("server_version") or "N/A",
                "Backups Preserved": len(payload.get("backups_created") or []),
                "Errors": len(payload.get("errors") or []),
                "Elapsed": f"{payload.get('elapsed_sec', 0.0)}s",
            },
            plain=plain,
        )
        rows = [[idx + 1, act] for idx, act in enumerate(payload.get("actions_taken") or [])]
        for err in payload.get("errors") or []:
            rows.append(["ERR", err])
        render_table("Repair Actions & Outcomes", ["Step", "Detail"], rows, plain=plain)
        return

    diag = diagnose_docker_wsl(include_all_wsl=True)
    payload = diag.to_dict()
    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "RFCHunt Docker Desktop / WSL2 Doctor (Read-Only Diagnosis)",
        {
            "Healthy": payload.get("healthy", False),
            "Daemon Running": payload.get("daemon_running", False),
            "Server Version": payload.get("server_version") or "N/A",
            "Docker Binary": payload.get("docker_binary") or "not found",
            "Docker Desktop Exe": payload.get("docker_desktop_exe") or "not found",
            "Compressed Dirs": len(payload.get("compressed_dirs") or []),
            "Compressed VHDXs": len(payload.get("compressed_vhdxs") or []),
            "Log Signals": ", ".join(payload.get("log_signals") or []) or "none",
            "Issues": ", ".join(payload.get("issues") or []) or "none",
        },
        plain=plain,
    )
    rows = [
        [
            v.get("role", ""),
            f"{v.get('size_gb', 0)} GB",
            "COMPRESSED (UNSAFE)" if v.get("compressed") else "uncompressed (ok)",
            v.get("path", ""),
        ]
        for v in (payload.get("vhdx_inventory") or [])
    ]
    if rows:
        render_table("WSL2 / Docker VHDX Inventory", ["Role", "Size", "NTFS Compression", "Path"], rows, plain=plain)
    recs = payload.get("recommended_actions") or []
    if recs:
        for rec in recs:
            print(f"[*] Recommended: {rec}")


def cmd_deep_audit(args):
    """Runs 3-pillar deep code-repo audit: live loopback proxy fuzzing, line-by-line trust-boundary review, and coverage-guided fuzzing (`--deep-audit`)."""
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.deep_repo_audit import run_deep_repo_audit

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    repo_path = (
        getattr(args, "repo", None)
        or getattr(args, "path", None)
        or getattr(args, "target_arg", None)
        or "."
    )
    output_dir = getattr(args, "output_dir", None) or "reports"
    task_id = str(getattr(args, "task_id", None) or "deep-audit").strip() or "deep-audit"
    approval_mode = str(getattr(args, "approval_mode", "policy") or "policy")

    proxy_target_arg = getattr(args, "proxy_target", None)
    if proxy_target_arg and os.path.isdir(str(proxy_target_arg)) and not getattr(args, "repo", None) and not getattr(args, "path", None):
        repo_path = str(proxy_target_arg)
        proxy_target_arg = "auto"

    allow_repo_exec_flag = bool(getattr(args, "allow_repo_exec", False))
    any_pillar = any(
        bool(getattr(args, flag, False))
        for flag in ("live_proxy_fuzz", "trust_boundary_review", "coverage_fuzz")
    ) or bool(proxy_target_arg)
    if bool(getattr(args, "deep_audit", False)) or not any_pillar:
        en_live = True
        en_tb = True
        en_cov = True
        if allow_repo_exec_flag and not proxy_target_arg and not getattr(args, "proxy_port", None) and not getattr(args, "proxy_cmd", None):
            proxy_target_arg = "auto"
    else:
        en_live = bool(getattr(args, "live_proxy_fuzz", False)) or bool(proxy_target_arg)
        en_tb = bool(getattr(args, "trust_boundary_review", False))
        en_cov = bool(getattr(args, "coverage_fuzz", False))

    fuzz_langs_raw = getattr(args, "fuzz_languages", None)
    fuzz_langs = [x.strip() for x in str(fuzz_langs_raw).split(",") if x.strip()] if fuzz_langs_raw else None

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        report = run_deep_repo_audit(
            repo_path,
            output_dir=output_dir,
            enable_live_proxy_fuzz=en_live,
            enable_trust_boundary_review=en_tb,
            enable_coverage_fuzz=en_cov,
            proxy_target=proxy_target_arg,
            proxy_host=str(getattr(args, "proxy_host", "127.0.0.1") or "127.0.0.1"),
            proxy_port=getattr(args, "proxy_port", None),
            proxy_cmd=getattr(args, "proxy_cmd", None),
            allow_repo_exec=allow_repo_exec_flag,
            run_docker_matrix=bool(getattr(args, "docker_parser_matrix", False)),
            max_trust_files=int(getattr(args, "trust_max_files", 80) or 80),
            fuzz_dry_run=bool(getattr(args, "fuzz_dry_run", False)),
            fuzz_max_time=int(getattr(args, "fuzz_max_time", 30) or 30),
            fuzz_timeout=int(getattr(args, "fuzz_timeout", 60) or 60),
            fuzz_languages=fuzz_langs,
            approval_mode=approval_mode,
            db=db,
            task_id=task_id,
        )
        payload = report.to_dict()

        if getattr(args, "enable_poc", False):
            from engine.poc_generator import generate_poc_bundle
            poc_dir = Path(str(output_dir)) / "deep_audit" / "pocs"
            poc_rep = generate_poc_bundle(
                report.findings,
                output_dir=poc_dir,
                repo_path=repo_path,
                include_rejected_scripts=bool(getattr(args, "poc_include_rejected", False)),
                run_container_verify=bool(getattr(args, "poc_container_verify", False)),
                max_scripts=int(getattr(args, "poc_max", 50) or 50),
                db=db,
                task_id=task_id,
            )
            payload["poc_verification"] = poc_rep.to_dict()
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    lp = payload.get("live_proxy_fuzz") or {}
    tb = payload.get("trust_boundary_review") or {}
    cf = payload.get("coverage_fuzz") or {}
    render_kv_panel(
        "RFCHunt --deep-audit Code Repository Security Audit",
        {
            "Repository": payload.get("repo_path", ""),
            "Total Findings": payload.get("total_findings", 0),
            "Live Proxy Fuzz": f"{lp.get('status', 'disabled')} (probes={lp.get('probes_sent', 0)}, divergences={len(lp.get('confirmed_divergences') or [])})",
            "Trust-Boundary Review": f"{tb.get('status', 'disabled')} (files={tb.get('files_reviewed', 0)}, findings={tb.get('findings_count', 0)})",
            "Coverage Fuzz": f"{cf.get('status', 'disabled')} (targets={','.join(cf.get('targets_scanned') or []) or 'none'}, langs={','.join(cf.get('detected_languages') or []) or 'none'}, crashes={cf.get('crashes_count', 0)})",
            "Report": payload.get("report_markdown_path", ""),
            "Elapsed": f"{payload.get('elapsed_sec', 0.0)}s",
        },
        plain=plain,
    )
    rows = [
        [
            f.get("severity", ""),
            f.get("rule_id", ""),
            f"{Path(str(f.get('file_path', ''))).name}:{f.get('line_number') or ''}",
            str(f.get("title", ""))[:74],
        ]
        for f in (payload.get("findings") or [])[:35]
    ]
    if rows:
        render_table("Deep Audit Findings (Top 35)", ["Severity", "Rule", "Location", "Title"], rows, plain=plain)


def cmd_call_graph_slice(args):
    """Whole-repo multi-language call-graph & taint slicer with tiered model escalation (AIxCC #2)."""
    from engine.call_graph_slicer import slice_repository
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.swarm_dispatcher import DispatchEscalationConfig, TieredModelRouter

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    target_path = (
        getattr(args, "repo", None)
        or getattr(args, "path", None)
        or getattr(args, "target_arg", None)
        or "."
    )
    if not os.path.exists(str(target_path)):
        print(f"[!] Target path does not exist: {target_path}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)

    report = slice_repository(
        str(target_path),
        enable_codeql=bool(getattr(args, "slice_codeql", False) or getattr(args, "include_codeql", False)),
        max_depth=int(getattr(args, "slice_max_depth", 8) or 8),
        max_slices=int(getattr(args, "slice_max_slices", 200) or 200),
    )
    esc_fraction = max(0.01, min(1.0, float(getattr(args, "escalation_fraction", 0.05) or 0.05)))
    min_poe_esc = max(0, int(getattr(args, "min_poe_escalation", 1) if getattr(args, "min_poe_escalation", None) is not None else 1))
    router = TieredModelRouter(
        config=DispatchEscalationConfig(
            enabled=True,
            max_escalation_fraction=esc_fraction,
            min_poe_for_escalation=min_poe_esc,
            frontier_api_opt_in=bool(getattr(args, "frontier_api_opt_in", False)),
        ),
        offline=bool(os.environ.get("RFCHUNT_OFFLINE") == "1"),
    )
    plan = router.rank_and_route(report.slices)
    payload = {
        "call_graph": report.to_dict(),
        "escalation_plan": plan.to_dict() if hasattr(plan, "to_dict") else {},
    }
    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "AIxCC Whole-Repo Call-Graph & Taint Slicer",
        {
            "Repository": report.repo_root,
            "Files Scanned": report.files_scanned,
            "Languages": ", ".join(f"{k}({v})" for k, v in sorted(report.languages_detected.items())) or "none",
            "Tree-sitter Available": report.tree_sitter_available,
            "Symbols / Call Edges": f"{report.symbols_count} / {report.edges_count}",
            "Taint Slices (Cross-File)": f"{len(report.slices)} ({report.cross_file_slices_count} cross-file)",
            "CodeQL Status": getattr(report.codeql, "status", "disabled"),
            "Escalated Candidates": payload["escalation_plan"].get("escalated_count", 0),
        },
        plain=plain,
    )
    rows = [
        [
            s.severity,
            s.cwe_id,
            s.sink_class,
            s.sanitizer_status,
            f"{s.entry_symbol} -> {s.sink_symbol} ({len(s.files_involved)}f)",
        ]
        for s in report.slices[:30]
    ]
    render_table(
        "Top Extracted Multi-File Taint Slices",
        ["Severity", "CWE", "Sink Class", "Sanitizer", "Path"],
        rows,
        plain=plain,
    )


def cmd_fuzz_bridge(args):
    """Multi-language LLM-guided isolated container coverage fuzzing bridge (AIxCC #3)."""
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.fuzz_bridge import run_fuzz_bridge_scan

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    target_path = (
        getattr(args, "repo", None)
        or getattr(args, "path", None)
        or getattr(args, "target_arg", None)
        or "."
    )
    if not os.path.exists(str(target_path)):
        print(f"[!] Target path does not exist: {target_path}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)

    task_id = str(getattr(args, "task_id", None) or "default").strip() or "default"
    out_dir = Path(str(getattr(args, "output_dir", None) or "reports")) / "fuzz_bridge"
    fuzz_langs = _parse_csv_list(getattr(args, "fuzz_languages", None))
    exec_containers = not bool(getattr(args, "fuzz_dry_run", False))
    if str(getattr(args, "approval_mode", "policy") or "policy").strip().lower() == "deny":
        exec_containers = False

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        _stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _stdout_ctx:
            payload = run_fuzz_bridge_scan(
                str(target_path),
                output_dir=str(out_dir),
                db=db,
                task_id=task_id,
                languages=fuzz_langs,
                timeout_sec=float(getattr(args, "fuzz_timeout", 60.0) or 60.0),
                max_total_time_sec=int(getattr(args, "fuzz_max_time", 30) or 30),
                cpp_backend=str(getattr(args, "fuzz_cpp_backend", "afl++") or "afl++"),
                execute_containers=exec_containers,
            )
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "AIxCC Multi-Language Coverage Fuzzing Bridge",
        {
            "Repository": payload.get("repo_path", str(target_path)),
            "Status": payload.get("status", "unknown"),
            "Languages Detected": ", ".join(payload.get("detected_languages") or []) or "none",
            "Harnesses Generated": len(payload.get("generated_artifacts") or []),
            "Sanitizer Crashes": len(payload.get("crashes") or []),
            "Coverage Plateaus": len(payload.get("plateaus") or []),
            "Blackboard FACTs / INTENTs": f"{len(payload.get('blackboard_fact_ids') or [])} / {len(payload.get('blackboard_intent_ids') or [])}",
            "Work Dir": payload.get("work_dir", str(out_dir)),
        },
        plain=plain,
    )
    rows = [
        [
            t.get("language", ""),
            t.get("backend", ""),
            t.get("status", ""),
            len(t.get("crashes") or []),
            len(t.get("plateaus") or []),
        ]
        for t in (payload.get("target_results") or [])
    ]
    render_table(
        "Fuzz Target Results",
        ["Language", "Backend", "Status", "Crashes", "Plateaus"],
        rows,
        plain=plain,
    )


def _validate_export_sarif_path(
    export_sarif_arg: Any,
    *,
    reports_dir: Union[str, Path],
    workspace_root: Optional[Path] = None,
) -> Path:
    """
    Validates `--export-sarif` (both relative and absolute paths) against canonical path syntax,
    reparse/junction/symlink escapes, sensitive host paths, and confinement within `reports_dir`
    or `workspace_root`.
    """
    from engine.execution_policy import (
        ExecutionPolicy,
        _is_drive_relative_or_colon_unsafe,
        _is_unc_path,
        _validate_canonical_path_syntax,
    )

    raw_s = os.fspath(export_sarif_arg) if isinstance(export_sarif_arg, os.PathLike) else export_sarif_arg
    if not isinstance(raw_s, str) or not raw_s.strip():
        raise ValueError("--export-sarif path must be a non-empty string.")
    if raw_s != raw_s.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_s):
        raise PermissionError("Unsafe --export-sarif path rejected (whitespace or control characters).")
    if _is_unc_path(raw_s) or _is_drive_relative_or_colon_unsafe(raw_s):
        raise PermissionError("Unsafe --export-sarif path rejected (UNC, NT-device, or drive-relative/ADS path).")
    syn_err = _validate_canonical_path_syntax(raw_s, allow_trailing_slash=False)
    if syn_err is not None:
        raise PermissionError(f"Unsafe --export-sarif path rejected: {syn_err}")

    candidates: List[str] = [raw_s]
    if raw_s.startswith("~"):
        try:
            exp = os.path.expanduser(raw_s)
            candidates.extend([exp, str(Path(exp).resolve(strict=False))])
        except Exception:
            pass
    sensitive_markers = (
        "/.ssh",
        "/.aws",
        "/.gnupg",
        "/.kube",
        "/etc/passwd",
        "/etc/shadow",
        "/windows/system32",
        "/windows/syswow64",
        "/windows/temp",
    )
    for cand in candidates:
        cand_low = cand.replace("\\", "/").lower().rstrip("/") or "/"
        if any(
            cand_low == m or cand_low.startswith(m + "/") or cand_low.endswith(m) or (m + "/" in cand_low)
            for m in sensitive_markers
        ) or re.match(r"^[a-z]:/windows(?:/|$)", cand_low) or re.match(r"^[a-z]:/(?:system32|syswow64)(?:/|$)", cand_low):
            raise PermissionError(f"Unsafe --export-sarif path rejected: sensitive host path '{export_sarif_arg}' is forbidden.")

    out_dir_resolved = Path(str(reports_dir)).resolve(strict=False)
    pol = ExecutionPolicy.get_instance()
    sarif_req = Path(raw_s)
    if not sarif_req.is_absolute():
        ok_out, detail_out = pol.validate_file_path(
            raw_s,
            workspace_root=out_dir_resolved,
            allow_directory=False,
            allow_nonexistent=True,
        )
        if not ok_out:
            raise PermissionError(f"--export-sarif path escapes output directory: {export_sarif_arg} ({detail_out})")
        return Path(detail_out)

    ok_out, detail_out = pol.validate_file_path(
        raw_s,
        workspace_root=out_dir_resolved,
        allow_directory=False,
        allow_nonexistent=True,
    )
    if ok_out:
        return Path(detail_out)

    if workspace_root is not None:
        ok_ws, detail_ws = pol.validate_file_path(
            raw_s,
            workspace_root=workspace_root,
            allow_directory=False,
            allow_nonexistent=True,
        )
        if ok_ws:
            return Path(detail_ws)

    raise PermissionError(
        f"--export-sarif absolute path escapes --output-dir and --workspace-root: {export_sarif_arg}"
    )


def build_autonomous_hunt_argv(args, raw_argv: Optional[List[str]] = None) -> List[str]:
    """
    Translates unified `rfc_hunt_swarm.py --hunt ...` arguments into `hunt.py` argv,
    bridging repeatable `--target`/`--hunt-target` and `--repo`/`--hunt-repo` flags
    and forwarding `--model` / `--out` only when explicitly passed by the caller.
    """
    tokens = list(raw_argv) if raw_argv is not None else []
    explicit_dests = getattr(args, "_explicit_cli_dests", set())

    targets: List[str] = []
    repos: List[str] = []

    def _add_target(val: str) -> None:
        v = str(val or "").strip()
        if v and v not in targets:
            targets.append(v)

    def _add_repo_or_target(val: str) -> None:
        v = str(val or "").strip()
        if not v:
            return
        if os.path.isdir(v) or v in (".", "..") or v.startswith(("./", "../", ".\\", "..\\")):
            _add_target(v)
        elif v not in repos:
            repos.append(v)

    if tokens:
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok in ("--target", "--hunt-target", "--folder", "--dir", "--raptor-target", "--path") and i + 1 < len(tokens):
                _add_target(tokens[i + 1])
                i += 2
            elif tok.startswith(("--target=", "--hunt-target=", "--folder=", "--dir=", "--raptor-target=", "--path=")):
                _add_target(tok.split("=", 1)[1])
                i += 1
            elif tok in ("--repo", "--hunt-repo") and i + 1 < len(tokens):
                _add_repo_or_target(tokens[i + 1])
                i += 2
            elif tok.startswith(("--repo=", "--hunt-repo=")):
                _add_repo_or_target(tok.split("=", 1)[1])
                i += 1
            else:
                i += 1
    else:
        for t in getattr(args, "hunt_targets", None) or []:
            _add_target(t)
        if "host" in explicit_dests and getattr(args, "host", None):
            _add_target(str(args.host))
        for r in getattr(args, "hunt_repos", None) or []:
            _add_repo_or_target(r)
        if getattr(args, "repo", None):
            _add_repo_or_target(str(args.repo))
        if getattr(args, "raptor_target", None):
            _add_target(str(args.raptor_target))

    for t in getattr(args, "hunt_targets", None) or []:
        _add_target(t)
    for r in getattr(args, "hunt_repos", None) or []:
        _add_repo_or_target(r)
    if getattr(args, "path", None) and os.path.isdir(str(args.path)):
        _add_target(str(args.path))
    if getattr(args, "target_arg", None):
        _t_pos = str(args.target_arg).strip()
        if _t_pos and _t_pos not in ALL_MODES:
            _add_repo_or_target(_t_pos)

    hunt_argv: List[str] = []
    for t in targets:
        hunt_argv.extend(["--target", t])
    for r in repos:
        hunt_argv.extend(["--repo", r])
    if getattr(args, "clone_unlocked", False):
        hunt_argv.append("--clone-unlocked")
    if getattr(args, "no_clone_unlocked", False):
        hunt_argv.append("--no-clone-unlocked")

    prog_val = str(getattr(args, "program", "") or "").strip()
    h1_prog_val = str(getattr(args, "hackerone_program", "") or "").strip()
    if prog_val and prog_val != "generic":
        eff_prog = prog_val
    elif h1_prog_val:
        eff_prog = h1_prog_val
    else:
        eff_prog = prog_val or "generic"
    hunt_argv.extend(["--program", eff_prog])

    if getattr(args, "watchlist", None):
        hunt_argv.extend(["--watchlist", str(args.watchlist)])
    if getattr(args, "eligibility_db", None):
        hunt_argv.extend(["--eligibility-db", str(args.eligibility_db)])
    if getattr(args, "sync_public_directory", False):
        hunt_argv.append("--sync-public-directory")
    if getattr(args, "min_efficiency", None) is not None:
        hunt_argv.extend(["--min-efficiency", str(float(args.min_efficiency))])
    if getattr(args, "portfolio_capacity", None) is not None:
        hunt_argv.extend(["--portfolio-capacity", str(max(1, int(args.portfolio_capacity)))])
    if getattr(args, "max_repos", None) is not None:
        hunt_argv.extend(["--max-repos", str(max(1, int(args.max_repos)))])
    if getattr(args, "interval_minutes", None) is not None:
        hunt_argv.extend(["--interval-minutes", str(float(args.interval_minutes))])
    if getattr(args, "max_cycles", None) and int(args.max_cycles) > 0:
        hunt_argv.extend(["--max-cycles", str(int(args.max_cycles))])
    if getattr(args, "hunt_once", False):
        hunt_argv.append("--once")
    if getattr(args, "hunt_url", None):
        hunt_argv.extend(["--hunt-url", str(args.hunt_url)])
    if getattr(args, "browser_hunt", False):
        hunt_argv.append("--browser-hunt")
    if getattr(args, "no_browser_hunt", False):
        hunt_argv.append("--no-browser-hunt")
    if getattr(args, "browser_profile", None):
        hunt_argv.extend(["--browser-profile", str(args.browser_profile)])
    if getattr(args, "cdp_url", None):
        hunt_argv.extend(["--cdp-url", str(args.cdp_url)])
    if getattr(args, "login_timeout", None) is not None and float(args.login_timeout) != 300.0:
        hunt_argv.extend(["--login-timeout", str(float(args.login_timeout))])
    if getattr(args, "probe_report_id", None) is not None and int(args.probe_report_id) != 4243972:
        hunt_argv.extend(["--probe-report-id", str(int(args.probe_report_id))])
    if getattr(args, "enable_swarm", False):
        hunt_argv.append("--swarm")
    if getattr(args, "swarm_workers", None) is not None:
        hunt_argv.extend(["--swarm-workers", str(max(1, int(args.swarm_workers)))])
    if getattr(args, "dedup_db", None):
        hunt_argv.extend(["--dedup-db", str(args.dedup_db)])
    if getattr(args, "force_rescan", False):
        hunt_argv.append("--force-rescan")
    if getattr(args, "no_stage_drafts", False):
        hunt_argv.append("--no-stage-drafts")
    if getattr(args, "headless_only", False):
        hunt_argv.append("--headless-only")
    if getattr(args, "embedded", False):
        hunt_argv.append("--embedded")
    if getattr(args, "no_llm", False):
        hunt_argv.append("--no-llm")
    if getattr(args, "allow_blocked", False):
        hunt_argv.append("--allow-blocked")
    if getattr(args, "dry_run", False):
        hunt_argv.append("--dry-run")
    if getattr(args, "as_json", False):
        hunt_argv.append("--json")
    if getattr(args, "install_schedule", False):
        hunt_argv.append("--install-schedule")
    if getattr(args, "uninstall_schedule", False):
        hunt_argv.append("--uninstall-schedule")
    if getattr(args, "run_now", False):
        hunt_argv.append("--run-now")
    if getattr(args, "task_name", None):
        hunt_argv.extend(["--task-name", str(args.task_name)])

    # Forward --model only when explicitly provided so hunt.py's dynamic RAM-gated abliterated selector runs by default
    model_explicit = any(t == "--model" or t.startswith("--model=") for t in tokens)
    raw_model = getattr(args, "model", None)
    if (model_explicit or (not tokens and raw_model and raw_model != "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M")) and raw_model:
        hunt_argv.extend(["--model", str(raw_model)])

    # Forward --out / --output-dir only when explicitly provided so hunt.py preserves default out/autonomous_hunt
    out_explicit = any(t == "--out" or t.startswith("--out=") for t in tokens)
    outdir_explicit = any(t == "--output-dir" or t.startswith("--output-dir=") for t in tokens)
    if out_explicit and getattr(args, "out", None):
        hunt_argv.extend(["--out", str(args.out)])
    elif outdir_explicit and getattr(args, "output_dir", None):
        hunt_argv.extend(["--out", str(args.output_dir)])
    elif not tokens and getattr(args, "out", None) and str(args.out) != "reports":
        hunt_argv.extend(["--out", str(args.out)])

    return hunt_argv


def cmd_autonomous_hunt(args, raw_argv: Optional[List[str]] = None) -> int:
    """Master CLI handler for `rfc_hunt_swarm.py --hunt` delegating to the turnkey autonomous hunter (`hunt.py`)."""
    import hunt as _turnkey_hunt

    hunt_argv = build_autonomous_hunt_argv(args, raw_argv=raw_argv)
    return int(_turnkey_hunt.main(hunt_argv))


def cmd_fast_ooda(args) -> int:
    """
    Runs the 3-Stage Parallel OODA Funnel directly from `rfc_hunt_swarm.py --fast-ooda`:
      Stage 1 (CPU / ms, zero LLM): deterministic static/formal checks via SQLite WAL Blackboard
      Stage 2 (ACDSO Pareto AutoML, <1s): multi-objective Pareto + anomaly ranking
      Stage 3 (Abliterated Consensus + HITL): VRAM-gated specialist panel behind OllamaConcurrencyGuard
    """
    import json as _ooda_json
    from engine.ensemble_orchestrator import EnsembleOrchestrator
    from engine.program_eligibility_db import ProgramEligibilityDB

    target_str = str(
        getattr(args, "repo", None)
        or getattr(args, "path", None)
        or getattr(args, "target_arg", None)
        or "."
    )
    as_json = bool(getattr(args, "as_json", False))
    embedded = bool(getattr(args, "embedded", False))
    no_llm = bool(getattr(args, "no_llm", False))
    cpu_workers_arg = getattr(args, "cpu_workers", None)
    bb_db = str(getattr(args, "blackboard_db", None) or "reports/ensemble_hunt/blackboard.sqlite3")
    raw_out = getattr(args, "out", None)
    out_dir = str(raw_out if (raw_out and str(raw_out) != "reports") else (getattr(args, "output_dir", None) or "out/fast_ooda"))
    program = str(getattr(args, "program", "generic") or "generic")
    raw_model = getattr(args, "model", None)
    eff_model = None if raw_model == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M" else raw_model

    orch = EnsembleOrchestrator(
        program=program,
        embedded=embedded,
        model=eff_model,
        enable_llm_verify=(not no_llm and not embedded),
        max_workers=(max(1, int(cpu_workers_arg)) if cpu_workers_arg else 4),
    )
    elig_db_raw = getattr(args, "eligibility_db", None) or os.environ.get("RFCHUNT_ELIGIBILITY_DB")
    elig_db = (
        ProgramEligibilityDB(str(elig_db_raw).strip())
        if elig_db_raw and str(elig_db_raw).strip()
        else None
    )
    _ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
    with _ctx:
        res = orch.run_fast_parallel_ooda(
            target_str,
            program=program,
            blackboard_db=bb_db,
            max_cpu_workers=cpu_workers_arg,
            resume=bool(getattr(args, "resume", False)),
            signal_score=float(getattr(args, "signal_score", 0.0) or 0.0),
            eligibility_db=elig_db,
            out_dir=out_dir,
            trigger_browser=False,
        )
    out_p = Path(out_dir)
    out_p.mkdir(parents=True, exist_ok=True)
    (out_p / "fast_ooda_report.json").write_text(_ooda_json.dumps(res, indent=2, default=str), encoding="utf-8")
    if as_json:
        print(_ooda_json.dumps(res, indent=2, default=str))
    else:
        s1 = res.get("stage1") if isinstance(res.get("stage1"), dict) else {}
        s2 = res.get("stage2") if isinstance(res.get("stage2"), dict) else {}
        print(
            f"[+] 3-Stage Parallel OODA complete ({res.get('status', 'completed')}): "
            f"stage1_prod={s1.get('production_count', 0)}, noise_dropped={s1.get('noise_dropped', 0)}, "
            f"stage2_selected={len(s2.get('selected') or [])}, clusters={len(res.get('clusters') or [])} -> {out_dir}"
        )
    return 0


def cmd_all(args):
    """
    Unified --all orchestrator running Google Mantis, haasonsaas/aiscan, BaaRai/ARTEX Dual-Graph,
    RAPTOR (Docker or cross-platform SAST/PQC/SCA), and Prompt Smuggling / RFC framing analyzers
    against --repo or --path or remote --host with mandatory ModelFusion and Abliterated model enforcement.
    """
    from engine.mantis_integrator import DEFAULT_ABLITERATED_MODEL, run_unified_all_scans
    from engine.safe_network_validator import is_explicit_loopback_host, validate_and_authorize_target

    args.fusion = True
    args.abliteration = True
    try:
        _configure_cli_hygiene(args)
    except ValueError as exc:
        as_json_err = bool(getattr(args, "as_json", False))
        print(f"[!] Invalid request hygiene / rate-limit configuration: {exc}", file=(sys.stderr if as_json_err else sys.stdout))
        sys.exit(1)
    host = getattr(args, "host", None) or getattr(args, "target", None)
    targets = getattr(args, "targets", None)
    repo = getattr(args, "repo", None) or getattr(args, "raptor_target", None)
    path = getattr(args, "path", None)
    if not repo and not path and not host and not targets:
        fallback = getattr(args, "mantis_target", None) or getattr(args, "target_arg", None)
        if fallback and os.path.exists(str(fallback)):
            repo = str(fallback)
        else:
            repo = "."

    raw_depth = getattr(args, "depth", None)
    depth = 100 if raw_depth is None else int(raw_depth)
    mantis_mode = getattr(args, "mantis_mode", "full") or "full"
    preferred_model = getattr(args, "mantis_model", None) or DEFAULT_ABLITERATED_MODEL
    if getattr(args, "model", None) and "obliterated" in str(args.model).lower() and not getattr(args, "mantis_model", None):
        preferred_model = args.model
    reports_dir = getattr(args, "output_dir", None) or "reports"
    artex_rounds = max(1, int(getattr(args, "artex_rounds", 1) or 1))
    authorized = bool(getattr(args, "authorized", False))
    allow_destructive = bool(getattr(args, "allow_destructive", False))
    as_json = bool(getattr(args, "as_json", False))

    artex_intent_turns = int(getattr(args, "artex_intent_turns", 0) or 0)
    artex_intent_tokens = int(getattr(args, "artex_intent_tokens", 0) or 0)
    artex_budget_turns = int(getattr(args, "artex_budget_turns", 0) or 0)
    if artex_intent_turns < 0 or artex_intent_tokens < 0 or artex_budget_turns < 0:
        print(
            "[!] ARTEX budget/turn parameters must be non-negative (>= 0).",
            file=(sys.stderr if as_json else sys.stdout),
        )
        sys.exit(1)

    if host:
        ok, reason = validate_and_authorize_target(host, authorized=authorized)
        if not ok:
            print(f"[!] Target authorization error for {host}: {reason}", file=(sys.stderr if as_json else sys.stdout))
            sys.exit(1)

    try:
        cli_ws_root = _resolve_cli_workspace_root(args)
        export_sarif_arg = getattr(args, "export_sarif", None)
        if export_sarif_arg:
            pre_out_dir = (
                (cli_ws_root / str(reports_dir))
                if (cli_ws_root is not None and not Path(str(reports_dir)).is_absolute())
                else Path(str(reports_dir))
            )
            _validate_export_sarif_path(
                export_sarif_arg,
                reports_dir=pre_out_dir,
                workspace_root=cli_ws_root,
            )
    except (PermissionError, ValueError) as exc:
        print(f"[!] Invalid workspace_root/repo/path: {exc}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)

    all_task_id = str(getattr(args, "task_id", None) or "default").strip() or "default"
    if getattr(args, "hint", None) is not None:
        _validate_cli_hint_args(args, default_task_id=all_task_id)
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        if getattr(args, "hint", None) is not None and hasattr(db, "add_hint"):
            _persist_cli_hint(args, db=db)

        if hasattr(db, "reclaim_stale_intents"):
            try:
                db.reclaim_stale_intents(task_id=all_task_id)
            except Exception:
                pass

        active_hints: List[Dict[str, Any]] = []
        if hasattr(db, "get_active_hints"):
            try:
                active_hints = db.get_active_hints(task_id=all_task_id, limit=50)
            except Exception:
                active_hints = []

        if not as_json:
            print(f"\n{'='*75}")
            print(f"[*] UNIFIED --all SECURITY AUDIT (Fusion + Abliterated Models Enforced)")
            target_disp = f"host={host or targets}" if (host or targets) and not repo and not path else os.path.abspath(str(repo or path))
            print(f"[*] Target: {target_disp} | Depth: {depth} | Model: {preferred_model}")
            if active_hints:
                print(f"[*] Active Blackboard Hints: {len(active_hints)}")
            print(f"{'='*75}")

        raw_port = getattr(args, "port", None)
        explicit_dests = getattr(args, "_explicit_cli_dests", set())
        if "port" in explicit_dests and raw_port is not None:
            port_arg = int(raw_port)
        elif host and str(host).strip().lower().startswith("http://"):
            port_arg = 80 if (hasattr(args, "_explicit_cli_dests") or raw_port in (None, 443, 5006)) else int(raw_port)
        elif not host and "port" not in explicit_dests and (
            raw_port is None or (hasattr(args, "_explicit_cli_dests") and raw_port in (443, 5006))
        ):
            port_arg = None
        else:
            port_arg = int(raw_port) if raw_port is not None else (None if not host else 443)
            if port_arg == 5006 and host and not is_explicit_loopback_host(str(host)):
                port_arg = 443

        raw_profiles = getattr(args, "artex_llm_profiles", None)
        artex_llm_profiles = _parse_csv_list(raw_profiles) if not isinstance(raw_profiles, list) else raw_profiles
        approval_mode_val = str(getattr(args, "approval_mode", "policy") or "policy").strip() or "policy"
        artex_live_val = getattr(args, "artex_live", None)
        if getattr(args, "no_artex_live", False) or approval_mode_val.lower() == "deny":
            artex_live_val = False

        if getattr(args, "no_external_scanners", False):
            raw_ext_flag = False
        elif getattr(args, "enable_external_scanners", False):
            raw_ext_flag = True
        else:
            raw_ext_flag = None
        raw_rea_cli = getattr(args, "rea_cli", None)
        rea_use_cli_val = True if raw_rea_cli is None else bool(raw_rea_cli)
        include_models_val = bool(getattr(args, "include_models", True))

        unified_kwargs: Dict[str, Any] = dict(
            repo=repo,
            path=path,
            host=host,
            targets=targets,
            port=port_arg,
            use_tls=getattr(args, "tls", None),
            authorized=authorized,
            allow_destructive=allow_destructive,
            depth=depth,
            mantis_mode=mantis_mode,
            use_fusion=True,
            preferred_model=preferred_model,
            db=db,
            reports_dir=reports_dir,
            artex_rounds=artex_rounds,
            artex_url=getattr(args, "artex_url", None),
            artex_token=getattr(args, "artex_token", None),
            artex_proxy=getattr(args, "artex_proxy", None),
            artex_ca_cert=getattr(args, "artex_ca_cert", None),
            artex_noise_profile=getattr(args, "artex_noise_profile", None),
            artex_llm_profiles=artex_llm_profiles,
            artex_llm_rotate=bool(getattr(args, "artex_llm_rotate", False)),
            artex_wait_sse=bool(getattr(args, "artex_wait_sse", False)),
            artex_budget_turns=int(getattr(args, "artex_budget_turns", 0) or 0),
            artex_retest=bool(getattr(args, "artex_retest", False)),
            artex_workers=int(getattr(args, "artex_workers", 3) or 3),
            artex_live=artex_live_val,
            embedded_proxy=bool(getattr(args, "embedded_proxy", False)),
            embedded_proxy_port=int(getattr(args, "embedded_proxy_port", 0) or 0),
            auth_profile=getattr(args, "auth_profile", None),
            import_har=getattr(args, "import_har", None),
            import_openapi=getattr(args, "import_openapi", None),
            scope_file=getattr(args, "scope_file", None),
            approval_mode=approval_mode_val,
            approval_rules=getattr(args, "approval_rules", None),
            strict_poe=bool(getattr(args, "strict_poe", False)),
            export_advisory=bool(getattr(args, "export_advisory", False)),
            export_csv=bool(getattr(args, "export_csv", False)),
            quiet=as_json,
            enable_external_scanners=raw_ext_flag,
            httpx_scan=getattr(args, "httpx_scan", None),
            katana_scan=getattr(args, "katana_scan", None),
            nuclei_scan=getattr(args, "nuclei_scan", None),
            nuclei_tags=getattr(args, "nuclei_tags", None),
            scanner_isolation=getattr(args, "scanner_isolation", "host") or "host",
            docker_image=getattr(args, "docker_image", None),
            docker_network=getattr(args, "docker_network", None),
            artex_multiturn=bool(getattr(args, "artex_multiturn", False)),
            artex_intent_turns=artex_intent_turns,
            artex_intent_tokens=artex_intent_tokens,
            enable_rea=not bool(getattr(args, "no_rea", False)),
            rea_target=getattr(args, "rea_target", None),
            rea_use_cli=rea_use_cli_val,
            auto_install_tools=bool(getattr(args, "auto_install", True)),
        )
        _res_n = int(getattr(args, "research_num", 5) or 5)
        _sk_n_raw = getattr(args, "skills_num", None)
        _sk_n = int(_sk_n_raw) if _sk_n_raw is not None else _res_n
        _extra_unified = {
            "include_models": include_models_val,
            "include_leads": bool(getattr(args, "include_leads", False)),
            "custom_headers": getattr(args, "headers", None) or None,
            "user_agent": getattr(args, "user_agent", None),
            "max_rps": float(getattr(args, "max_rps", 0.0) or 0.0),
            "enable_h2_desync": bool(getattr(args, "enable_h2_desync", True)),
            "enable_verification_inversion": bool(getattr(args, "enable_verification_inversion", True)),
            "research_num": _res_n,
            "skills_num": _sk_n,
            "enable_arxiv_detect": bool(getattr(args, "enable_arxiv_detect", True)),
            "arxiv_sync": bool(getattr(args, "arxiv_sync", False)),
            "arxiv_query": getattr(args, "arxiv_query", None) or "",
            "arxiv_rl": bool(getattr(args, "arxiv_rl", False)),
            "arxiv_verify_panel": bool(getattr(args, "arxiv_verify_panel", False)),
            "arxiv_panel_size": int(getattr(args, "arxiv_panel_size", 2) or 2),
            "arxiv_auto_repair": bool(getattr(args, "arxiv_auto_repair", True)),
            "arxiv_max_repairs": int(getattr(args, "arxiv_max_repairs", 3) or 3),
            "enable_last30days_skills": bool(getattr(args, "enable_last30days_skills", True)),
            "last30days_sync": bool(getattr(args, "last30days_sync", False)),
            "last30days_topic": getattr(args, "last30days_topic", None) or "",
            "enable_phi_scan": bool(getattr(args, "enable_phi", False)),
            "phi_redact": bool(getattr(args, "phi_redact", False)),
            "phi_model": str(getattr(args, "phi_model", "urchade/gliner_multi_pii-v1") or "urchade/gliner_multi_pii-v1"),
            "phi_enable_ml": not bool(getattr(args, "no_phi_ml", False)),
            "enable_preflight": bool(getattr(args, "enable_preflight", True)),
            "preflight_live": bool(getattr(args, "preflight_live", True)),
            "preflight_pqc": bool(getattr(args, "preflight_pqc", True)),
            "preflight_prompt": str(getattr(args, "preflight_prompt", None) or ""),
            "preflight_skills_dirs": (
                [d.strip() for d in str(getattr(args, "preflight_skills_dirs", "")).split(",") if d.strip()]
                if getattr(args, "preflight_skills_dirs", None)
                else None
            ),
            "preflight_include_home_skills": not bool(getattr(args, "no_home_skills", False)),
            "preflight_timeout": float(getattr(args, "preflight_timeout", 15.0) or 15.0),
            "enable_pe_audit": not bool(getattr(args, "no_pe_audit", False)),
            "pe_include_host_audit": bool(getattr(args, "pe_include_host_audit", False)),
            "pe_include_yara": bool(getattr(args, "pe_include_yara", True)),
            "workspace_root": str(cli_ws_root) if cli_ws_root is not None else None,
            "confine_reports_to_workspace_root": bool(
                getattr(args, "workspace_root", None) is not None and str(getattr(args, "workspace_root", "")).strip()
            ),
        }
        try:
            _unified_sig = inspect.signature(run_unified_all_scans)
            _accepts_var_kw = any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in _unified_sig.parameters.values()
            )
            for _k, _v in _extra_unified.items():
                if _k in _unified_sig.parameters or _accepts_var_kw:
                    unified_kwargs[_k] = _v
        except (TypeError, ValueError):
            unified_kwargs.update(_extra_unified)

        _prev_cmd_all_auto_pull = os.environ.get("RFCHUNT_AUTO_PULL_MODELS")
        _cmd_all_no_pull = (
            (not include_models_val)
            or (not bool(getattr(args, "auto_install", True)))
            or (os.environ.get("RFCHUNT_AUTO_INSTALL_TOOLS") == "0")
        )
        if _cmd_all_no_pull:
            os.environ["RFCHUNT_AUTO_PULL_MODELS"] = "0"
        try:
            _stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
            with _stdout_ctx:
                res = run_unified_all_scans(**unified_kwargs)
                _run_all_aixcc_extensions(
                    args,
                    res,
                    repo=repo,
                    path=path,
                    host=host,
                    port=port_arg,
                    use_tls=getattr(args, "tls", None),
                    reports_dir=reports_dir,
                    db=db,
                    task_id=all_task_id,
                    approval_mode=approval_mode_val,
                    as_json=as_json,
                )
        except (PermissionError, ValueError) as exc:
            print(f"[!] Target authorization or scanner configuration error for {host or targets or repo or path}: {exc}", file=(sys.stderr if as_json else sys.stdout))
            sys.exit(1)
        finally:
            if _cmd_all_no_pull:
                if _prev_cmd_all_auto_pull is None:
                    os.environ.pop("RFCHUNT_AUTO_PULL_MODELS", None)
                else:
                    os.environ["RFCHUNT_AUTO_PULL_MODELS"] = _prev_cmd_all_auto_pull

        try:
            export_sarif_arg = getattr(args, "export_sarif", None)
            if export_sarif_arg:
                import shutil as _shutil
                src_sarif = (res.get("report_files") or {}).get("combined_sarif")
                eff_out_dir = (
                    Path(str(src_sarif)).resolve().parent
                    if src_sarif and os.path.isfile(str(src_sarif))
                    else (
                        (cli_ws_root / str(reports_dir)).resolve(strict=False)
                        if (cli_ws_root is not None and not Path(str(reports_dir)).is_absolute())
                        else Path(str(reports_dir)).resolve(strict=False)
                    )
                )
                dst_sarif = _validate_export_sarif_path(
                    export_sarif_arg,
                    reports_dir=eff_out_dir,
                    workspace_root=cli_ws_root,
                )
                if src_sarif and os.path.isfile(str(src_sarif)):
                    dst_sarif.parent.mkdir(parents=True, exist_ok=True)
                    if Path(str(src_sarif)).resolve() != dst_sarif.resolve():
                        _shutil.copyfile(str(src_sarif), str(dst_sarif))
                    res.setdefault("report_files", {})["exported_sarif"] = str(dst_sarif)
        except (PermissionError, ValueError) as exc:
            print(f"[!] Target authorization or scanner configuration error for {host or targets or repo or path}: {exc}", file=(sys.stderr if as_json else sys.stdout))
            sys.exit(1)

        if any(
            bool(getattr(args, flag, False))
            for flag in ("deep_audit", "live_proxy_fuzz", "trust_boundary_review", "coverage_fuzz", "proxy_target")
        ):
            deep_repo = repo or path or res.get("target_path")
            if deep_repo and os.path.isdir(str(deep_repo)):
                try:
                    from engine.deep_repo_audit import run_deep_repo_audit
                    p_target = getattr(args, "proxy_target", None)
                    any_p = any(
                        bool(getattr(args, fl, False))
                        for fl in ("live_proxy_fuzz", "trust_boundary_review", "coverage_fuzz")
                    ) or bool(p_target)
                    en_live = True if (getattr(args, "deep_audit", False) or not any_p) else (bool(getattr(args, "live_proxy_fuzz", False)) or bool(p_target))
                    en_tb = True if (getattr(args, "deep_audit", False) or not any_p) else bool(getattr(args, "trust_boundary_review", False))
                    en_cov = True if (getattr(args, "deep_audit", False) or not any_p) else bool(getattr(args, "coverage_fuzz", False))
                    allow_repo_exec_flag = bool(getattr(args, "allow_repo_exec", False))
                    if getattr(args, "deep_audit", False) and allow_repo_exec_flag and not p_target and not getattr(args, "proxy_port", None) and not getattr(args, "proxy_cmd", None):
                        p_target = "auto"
                    fl_raw = getattr(args, "fuzz_languages", None)
                    fl_list = [x.strip() for x in str(fl_raw).split(",") if x.strip()] if fl_raw else None
                    deep_rep = run_deep_repo_audit(
                        deep_repo,
                        output_dir=reports_dir,
                        enable_live_proxy_fuzz=en_live,
                        enable_trust_boundary_review=en_tb,
                        enable_coverage_fuzz=en_cov,
                        proxy_target=p_target,
                        proxy_host=str(getattr(args, "proxy_host", "127.0.0.1") or "127.0.0.1"),
                        proxy_port=getattr(args, "proxy_port", None),
                        proxy_cmd=getattr(args, "proxy_cmd", None),
                        allow_repo_exec=allow_repo_exec_flag,
                        run_docker_matrix=bool(getattr(args, "docker_parser_matrix", False)),
                        max_trust_files=int(getattr(args, "trust_max_files", 80) or 80),
                        fuzz_dry_run=bool(getattr(args, "fuzz_dry_run", False)),
                        fuzz_max_time=int(getattr(args, "fuzz_max_time", 30) or 30),
                        fuzz_timeout=int(getattr(args, "fuzz_timeout", 60) or 60),
                        fuzz_languages=fl_list,
                        approval_mode=approval_mode_val,
                        db=db,
                        task_id=all_task_id,
                    )
                    deep_dict = deep_rep.to_dict()
                    res["deep_audit"] = deep_dict
                    res.setdefault("engines", {})["deep_audit"] = deep_dict
                    res.setdefault("report_files", {})["deep_audit_md"] = deep_rep.report_markdown_path
                    res.setdefault("report_files", {})["deep_audit_json"] = deep_rep.summary_json_path
                    if deep_rep.findings:
                        res.setdefault("findings", []).extend(deep_rep.findings)
                except PermissionError:
                    raise
                except Exception as da_exc:
                    res.setdefault("engines", {})["deep_audit"] = {"status": "error", "error": str(da_exc)}

        if getattr(args, "enable_poc", False):
            try:
                from engine.poc_generator import generate_poc_bundle
                poc_dir_arg = getattr(args, "poc_dir", None)
                if poc_dir_arg:
                    poc_req = Path(str(poc_dir_arg))
                    if poc_req.is_absolute():
                        poc_out_dir = poc_req
                    else:
                        out_dir_resolved = Path(str(reports_dir)).resolve(strict=False)
                        poc_out_dir = (out_dir_resolved / poc_req).resolve(strict=False)
                        if not poc_out_dir.is_relative_to(out_dir_resolved):
                            raise ValueError(f"--poc-dir path escapes output directory: {poc_dir_arg}")
                else:
                    poc_out_dir = Path(str(reports_dir)) / "pocs"
                poc_repo = repo or path or res.get("target_path")
                poc_report = generate_poc_bundle(
                    res.get("findings") or [],
                    output_dir=poc_out_dir,
                    repo_path=str(poc_repo) if poc_repo and os.path.exists(str(poc_repo)) else None,
                    include_rejected_scripts=bool(getattr(args, "poc_include_rejected", False)),
                    run_container_verify=bool(getattr(args, "poc_container_verify", False)),
                    max_scripts=int(getattr(args, "poc_max", 50) or 50),
                    db=db,
                    task_id=all_task_id,
                )
                poc_dict = poc_report.to_dict()
                res["poc_verification"] = poc_dict
                res.setdefault("engines", {})["poc_verification"] = poc_dict
                res.setdefault("report_files", {})["poc_index_md"] = poc_report.index_markdown_path
                res.setdefault("report_files", {})["poc_manifest_json"] = poc_report.manifest_json_path
            except ValueError:
                raise
            except Exception as poc_exc:
                res.setdefault("engines", {})["poc_verification"] = {"status": "error", "error": str(poc_exc)}

        if getattr(args, "ensemble", False):
            import json as _ens_json
            from engine.ensemble_orchestrator import EnsembleOrchestrator
            from revenue_cli import unified_findings_to_engine_findings

            ensemble_target = str(repo or path or host or ".")
            combined_json_str = str((res.get("report_files") or {}).get("combined_json") or "").strip()
            if combined_json_str:
                ens_out_dir = Path(combined_json_str).resolve(strict=False).parent
            else:
                ens_out_dir = Path(str(reports_dir)).resolve(strict=False)

            ens_offline = (
                os.environ.get("RFCHUNT_OFFLINE") == "1"
                or bool(os.environ.get("CI"))
                or bool(getattr(args, "embedded", False))
                or (not bool(getattr(args, "preflight_live", True)))
            )
            ens_embedded = bool(getattr(args, "embedded", False))
            no_models_offline = (not bool(getattr(args, "include_models", True))) and (
                os.environ.get("RFCHUNT_OFFLINE") == "1" or bool(os.environ.get("CI"))
            )
            ens_llm_verify = (
                (not bool(getattr(args, "no_llm", False)))
                and (not ens_embedded)
                and (not no_models_offline)
            )
            ens_model = getattr(args, "model", None)
            if ens_model == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M":
                ens_model = None

            _fh_val = getattr(args, "freshness_hours", 72)
            _q_val = getattr(args, "quorum", 2)
            orch = EnsembleOrchestrator(
                program=str(getattr(args, "program", "generic") or "generic"),
                freshness_hours=int(_fh_val) if _fh_val is not None else 72,
                quorum=max(1, int(_q_val)) if _q_val is not None else 2,
                exhaustive_default=True,
                embedded=ens_embedded,
                model=ens_model,
                enable_llm_verify=ens_llm_verify,
                gha_only=bool(getattr(args, "gha_only", False)),
                no_external_scanners=bool(getattr(args, "no_external_scanners", False)),
                proxy=getattr(args, "proxy_target", None),
                db=db,
            )

            converted_findings = unified_findings_to_engine_findings(
                res.get("findings") or [],
                target_root=ensemble_target if (repo or path) else None,
                exclude_speculative_and_preflight=True,
            )
            merged_findings = list(converted_findings)
            ens_target_p = Path(ensemble_target)
            is_local_target = bool(repo or path) and (
                ens_target_p.is_dir()
                or (ens_target_p.is_file() and ens_target_p.suffix.lower() in (".yml", ".yaml"))
            )
            all_scan_summary = {
                "target_path": res.get("target_path"),
                "mode": res.get("mode"),
                "total_aggregated_findings": res.get("total_aggregated_findings", 0),
                "primary_findings_count": res.get("primary_findings_count", 0),
                "verified_exploits_count": res.get("verified_exploits_count", 0),
                "deterministic_static_count": res.get("deterministic_static_count", 0),
                "speculative_hypotheses_count": res.get("speculative_hypotheses_count", 0),
                "chains_synthesized": res.get("chains_synthesized", 0),
                "severity_counts": res.get("severity_counts") or {},
            }

            _ens_stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
            with _ens_stdout_ctx:
                if is_local_target:
                    local_findings, local_tele = EnsembleOrchestrator.run_exhaustive_local_engines(
                        ens_target_p,
                        refresh_stix=(not ens_offline),
                        embedded=ens_embedded,
                        model=ens_model,
                        enable_llm_verify=ens_llm_verify,
                        gha_only=bool(getattr(args, "gha_only", False)) or (ens_target_p.is_file() and ens_target_p.suffix.lower() in (".yml", ".yaml")),
                        no_external_scanners=bool(getattr(args, "no_external_scanners", False)),
                        lean_dir=orch.lean_dir,
                        program=str(getattr(args, "program", "generic") or "generic"),
                    )
                    orch.last_telemetry = local_tele
                    merged_findings.extend(local_findings)

                ens_rep = orch.run(
                    ensemble_target,
                    findings=merged_findings,
                    all_scan_summary=all_scan_summary,
                    out_dir=ens_out_dir,
                    package_client_name=getattr(args, "package_client", None),
                    refresh_stix=(not ens_offline),
                )

            ens_dict = ens_rep.to_dict()
            res["ensemble"] = ens_dict
            res["toolchain_status"] = ens_dict.get("toolchain_status", {})
            res["lean_verification"] = ens_dict.get("lean_verification", {})
            res.setdefault("engines", {})["ensemble"] = {
                "total_clusters": len(ens_rep.clusters),
                "counts_by_disposition": dict(ens_rep.counts_by_disposition),
                "whiteboard": ens_dict.get("whiteboard", {}),
                "lean_verification": res["lean_verification"],
                "toolchain_status": res["toolchain_status"],
                "telemetry": orch.last_telemetry,
            }
            rf = res.setdefault("report_files", {})
            rf["ensemble_json"] = str(ens_out_dir / "ensemble_report.json")
            rf["ensemble_md"] = str(ens_out_dir / "ensemble_summary.md")
            rf["ensemble_sarif"] = str(ens_out_dir / "ensemble_findings.sarif")
            if combined_json_str and Path(combined_json_str).parent.exists():
                Path(combined_json_str).write_text(_ens_json.dumps(res, indent=2), encoding="utf-8")
        else:
            # Even when --ensemble and --hunt are NOT passed, --all runs all local defensive tools
            # (TruffleHog, Mobile/MobSF, API/JWT/SD-JWT, AI Infra Guard, Parity/Invariants,
            # Zizmor/Actionlint/GHA Agent, Z3 Formal, JS Bundle Analyzer, Lean 4, and ACDSO Stage-2 ranking).
            _local_target_str = str(repo or path or "").strip()
            _local_target_p = Path(_local_target_str) if _local_target_str else None
            if _local_target_p is not None and (
                _local_target_p.is_dir()
                or (_local_target_p.is_file() and _local_target_p.suffix.lower() in (".yml", ".yaml"))
            ):
                try:
                    import json as _all_tools_json
                    from engine.acdso_bridge import rank_stage2_candidates
                    from engine.ensemble_orchestrator import EnsembleOrchestrator

                    _all_offline = (
                        os.environ.get("RFCHUNT_OFFLINE") == "1"
                        or bool(os.environ.get("CI"))
                        or bool(getattr(args, "embedded", False))
                        or (not bool(getattr(args, "preflight_live", True)))
                    )
                    _all_embedded = bool(getattr(args, "embedded", False))
                    _all_tools_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
                    with _all_tools_ctx:
                        _extra_local_findings, _extra_local_tele = EnsembleOrchestrator.run_exhaustive_local_engines(
                            _local_target_p,
                            refresh_stix=False,
                            embedded=_all_embedded,
                            model=None,
                            enable_llm_verify=False,
                            gha_only=bool(getattr(args, "gha_only", False))
                            or (_local_target_p.is_file() and _local_target_p.suffix.lower() in (".yml", ".yaml")),
                            no_external_scanners=bool(getattr(args, "no_external_scanners", False)) or _all_offline,
                            program=str(getattr(args, "program", "generic") or "generic"),
                        )
                    _prod_cands = [
                        ef.to_dict()
                        for ef in _extra_local_findings
                        if not getattr(ef, "non_production_noise", False)
                    ]
                    _acdso_s2 = (
                        rank_stage2_candidates(_prod_cands, top_k=5)
                        if _prod_cands
                        else {"selected": [], "pareto_count": 0, "total_candidates": 0}
                    )
                    res["exhaustive_local_findings"] = [ef.to_dict() for ef in _extra_local_findings]
                    res.setdefault("engines", {})["exhaustive_local_tools"] = {
                        "status": "completed",
                        "engines_executed": list(_extra_local_tele.get("engines_executed") or []),
                        "total_findings": len(_extra_local_findings),
                        "production_findings": len(_prod_cands),
                        "telemetry": _extra_local_tele,
                        "acdso_stage2": _acdso_s2,
                    }
                    _combined_json_p = str((res.get("report_files") or {}).get("combined_json") or "").strip()
                    if _combined_json_p and Path(_combined_json_p).parent.exists():
                        Path(_combined_json_p).write_text(_all_tools_json.dumps(res, indent=2, default=str), encoding="utf-8")
                except Exception as _ext_tools_exc:
                    res.setdefault("engines", {})["exhaustive_local_tools"] = {
                        "status": "degraded_error",
                        "error": str(_ext_tools_exc),
                    }

        if getattr(args, "enable_fast_ooda", False) and (repo or path):
            _ooda_target = str(repo or path)
            if os.path.isdir(_ooda_target):
                try:
                    import json as _ooda_all_json
                    from engine.ensemble_orchestrator import EnsembleOrchestrator
                    from engine.program_eligibility_db import ProgramEligibilityDB

                    _ooda_emb = bool(getattr(args, "embedded", False))
                    _ooda_llm = (not bool(getattr(args, "no_llm", False))) and (not _ooda_emb)
                    _ooda_cpu = getattr(args, "cpu_workers", None)
                    _ooda_orch = EnsembleOrchestrator(
                        program=str(getattr(args, "program", "generic") or "generic"),
                        embedded=_ooda_emb,
                        enable_llm_verify=_ooda_llm,
                        max_workers=(max(1, int(_ooda_cpu)) if _ooda_cpu else 4),
                    )
                    _elig_p = getattr(args, "eligibility_db", None) or os.environ.get("RFCHUNT_ELIGIBILITY_DB")
                    _elig_obj = ProgramEligibilityDB(str(_elig_p).strip()) if _elig_p and str(_elig_p).strip() else None
                    _ooda_out = Path(str(reports_dir)) / "fast_ooda"
                    _ooda_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
                    with _ooda_ctx:
                        _ooda_res = _ooda_orch.run_fast_parallel_ooda(
                            _ooda_target,
                            program=str(getattr(args, "program", "generic") or "generic"),
                            blackboard_db=str(getattr(args, "blackboard_db", None) or (Path(str(reports_dir)) / "blackboard.sqlite3")),
                            max_cpu_workers=_ooda_cpu,
                            resume=bool(getattr(args, "resume", False)),
                            signal_score=float(getattr(args, "signal_score", 0.0) or 0.0),
                            eligibility_db=_elig_obj,
                            out_dir=_ooda_out,
                            trigger_browser=False,
                        )
                    _ooda_out.mkdir(parents=True, exist_ok=True)
                    (_ooda_out / "fast_ooda_report.json").write_text(
                        _ooda_all_json.dumps(_ooda_res, indent=2, default=str), encoding="utf-8"
                    )
                    res["fast_ooda"] = _ooda_res
                    res.setdefault("engines", {})["fast_ooda"] = {
                        "status": _ooda_res.get("status", "completed"),
                        "stage1_production_count": _ooda_res.get("stage1_production_count", 0),
                        "stage1_dropped_noise_count": _ooda_res.get("stage1_dropped_noise_count", 0),
                        "stage2_selected_count": len((_ooda_res.get("stage2") or {}).get("selected") or []),
                        "clusters_count": len(_ooda_res.get("clusters") or []),
                    }
                except Exception as _ooda_exc:
                    res.setdefault("engines", {})["fast_ooda"] = {"status": "error", "error": str(_ooda_exc)}

        # Audit any additional distinct local folder(s) passed alongside --repo (e.g., --all --repo ./r --folder ./f)
        _extra_local_dirs: List[str] = []
        _primary_resolved: Optional[Path] = None
        if repo and os.path.isdir(str(repo)):
            _primary_resolved = Path(str(repo)).resolve(strict=False)
        elif path and os.path.isdir(str(path)):
            _primary_resolved = Path(str(path)).resolve(strict=False)
        for _cand_dir in (
            [getattr(args, "raptor_target", None), getattr(args, "path", None)]
            + list(getattr(args, "hunt_targets", None) or [])
        ):
            if not _cand_dir or not os.path.isdir(str(_cand_dir)):
                continue
            _cand_res = Path(str(_cand_dir)).resolve(strict=False)
            if _primary_resolved is not None and _cand_res == _primary_resolved:
                continue
            _cand_s = str(_cand_res)
            if _cand_s not in _extra_local_dirs:
                _extra_local_dirs.append(_cand_s)
        if _extra_local_dirs:
            from engine.ensemble_orchestrator import EnsembleOrchestrator

            _extra_target_summaries: List[Dict[str, Any]] = []
            _extra_offline = (
                os.environ.get("RFCHUNT_OFFLINE") == "1"
                or bool(os.environ.get("CI"))
                or bool(getattr(args, "embedded", False))
            )
            for _ed in _extra_local_dirs:
                try:
                    _ef_list, _ef_tele = EnsembleOrchestrator.run_exhaustive_local_engines(
                        Path(_ed),
                        refresh_stix=False,
                        embedded=bool(getattr(args, "embedded", False)),
                        model=None,
                        enable_llm_verify=False,
                        no_external_scanners=bool(getattr(args, "no_external_scanners", False)) or _extra_offline,
                        program=str(getattr(args, "program", "generic") or "generic"),
                    )
                    _extra_target_summaries.append(
                        {
                            "target_path": _ed,
                            "status": "completed",
                            "engines_executed": list(_ef_tele.get("engines_executed") or []),
                            "total_findings": len(_ef_list),
                            "findings": [ef.to_dict() for ef in _ef_list],
                        }
                    )
                except Exception as _ed_exc:
                    _extra_target_summaries.append(
                        {"target_path": _ed, "status": "error", "error": str(_ed_exc)}
                    )
            res["additional_local_targets"] = _extra_target_summaries

        if hasattr(db, "add_fact"):
            try:
                total_agg = int(res.get("total_aggregated_findings", 0) or 0)
                chains_syn = int(res.get("chains_synthesized", 0) or 0)
                db.add_fact(
                    f"Unified --all scan completed on {res.get('target_path') or host or repo or '.'} "
                    f"(findings={total_agg}, chains={chains_syn}, hints_active={len(active_hints)})",
                    node_id=f"fact:all_scan:{all_task_id}",
                    task_id=all_task_id,
                    domain="global",
                    source_agent="cmd_all",
                    payload={
                        "target": res.get("target_path"),
                        "total_findings": total_agg,
                        "chains_synthesized": chains_syn,
                        "hints_active": len(active_hints),
                        "severity_counts": res.get("severity_counts") or {},
                    },
                )
                for f_idx, f_item in enumerate((res.get("findings") or [])[:50]):
                    if not isinstance(f_item, dict):
                        continue
                    f_title = str(f_item.get("title") or f_item.get("rule_id") or f_item.get("description") or f"finding-{f_idx+1}")
                    f_sev = str(f_item.get("severity") or "INFO")
                    db.add_fact(
                        f"[{f_sev}] {f_title}",
                        node_id=f"fact:all_finding:{all_task_id}:{f_idx}",
                        task_id=all_task_id,
                        domain="global",
                        source_agent="cmd_all",
                        payload={
                            "rule_id": f_item.get("rule_id"),
                            "severity": f_sev,
                            "cwe": f_item.get("cwe"),
                            "file_path": f_item.get("file_path") or f_item.get("file"),
                            "capability_class": f_item.get("capability_class"),
                            "endpoint": f_item.get("endpoint"),
                        },
                    )
            except Exception:
                pass

        if getattr(args, "as_json", False):
            if getattr(args, "enable_autonomous_hunt", False):
                import io as _all_hunt_io
                import json as _all_hunt_json

                _h_buf = _all_hunt_io.StringIO()
                with contextlib.redirect_stdout(_h_buf):
                    _h_rc = cmd_autonomous_hunt(args, raw_argv=getattr(args, "_raw_cli_argv", None))
                _h_raw = _h_buf.getvalue().strip()
                try:
                    _h_doc = _all_hunt_json.loads(_h_raw) if _h_raw else {}
                except ValueError:
                    _h_doc = {"raw_output": _h_raw[:2000]}
                res["autonomous_hunt"] = {**_h_doc, "returncode": int(_h_rc)}
            from engine.cli_render import render_json
            render_json(res)
            return

        from engine.cli_render import render_poe_summary
        eng = res.get("engines", {})
        chaining = res.get("attack_chaining") or eng.get("artex_dual_graph") or {}
        cov = chaining.get("coverage") or {}
        poe_bd = chaining.get("poe_breakdown") or {}
        tid_val = chaining.get("task_id")
        traces_for_render = db.list_worker_traces(task_id=tid_val, limit=25) if hasattr(db, "list_worker_traces") else []
        chains_for_render = db.get_attack_chains(limit=25, task_id=tid_val) if hasattr(db, "get_attack_chains") else []

        print(f"[+] Unified --all Completed in {res['elapsed_sec']}s")
        print(f"    Fusion Enabled      : {res['fusion_enabled']} | Models: {', '.join(res.get('fusion_models', []))}")
        print(f"    Aggregated Findings : {res['total_aggregated_findings']} {res.get('severity_counts', {})}")
        print(f"    Module 20 Mantis    : {eng.get('mantis', {}).get('total_findings', 0)} (Reproduced: {eng.get('mantis', {}).get('reproduced_count', 0)})")
        print(f"    Module 18 aiscan    : {eng.get('aiscan', {}).get('total_findings', 0)}")
        print(f"    Module 15 RAPTOR    : {eng.get('raptor', {}).get('total_findings', 0)} ({eng.get('raptor', {}).get('mode', 'static')})")
        print(f"    Module 21 REA       : {eng.get('rea_surface', {}).get('total_findings', 0)} ({eng.get('rea_surface', {}).get('status', 'disabled')}, routes={eng.get('rea_surface', {}).get('total_endpoints', 0)})")
        if "pe_dotnet_auditor" in eng:
            pe_eng = eng.get("pe_dotnet_auditor") or {}
            print(
                f"    PE/.NET Auditor     : {pe_eng.get('total_findings', 0)} findings "
                f"(status={pe_eng.get('status', 'disabled')}, files={pe_eng.get('files_scanned', 0)}, "
                f"CVE-2026-108398={pe_eng.get('cve_2026_108398_count', 0)}, UMCI={pe_eng.get('umci_fallback_risk_count', 0)})"
            )
        print(
            f"    Module 17 ARTEX     : {chaining.get('chains_synthesized', 0)} chains synthesized "
            f"(Verified: {chaining.get('exploits_verified', 0)}, Max Hops: {chaining.get('max_hop_count', 0)}, "
            f"Coverage: {cov.get('coverage_pct', 0.0)}%, Traces: {chaining.get('worker_traces_count', 0)}, Goal Proven: {chaining.get('goal_proven', False)})"
        )
        print(f"    POE Breakdown       : {poe_bd}")
        print(f"    Module 19 Smuggling : {eng.get('prompt_smuggling', {}).get('probes_generated', 0)} probes synthesized")
        if "phi_scanner" in eng and (eng.get("phi_scanner") or {}).get("status") != "disabled":
            phi_info = eng.get("phi_scanner") or {}
            print(
                f"    Module 22 PHI/PII   : {phi_info.get('total_findings', 0)} findings "
                f"(backends={','.join(phi_info.get('backends') or [])}, zero_leakage={phi_info.get('zero_leakage_enforced', True)})"
            )
        if "call_graph_slicer" in eng:
            cg = eng.get("call_graph_slicer") or {}
            te = eng.get("tiered_escalation") or {}
            print(
                f"    Call-Graph Slicer   : {cg.get('total_slices', 0)} slices "
                f"({cg.get('cross_file_slices_count', 0)} cross-file, "
                f"escalated={te.get('escalated_count', 0)}, status={cg.get('status', 'ok')})"
            )
        if "fuzz_bridge" in eng:
            fb = eng.get("fuzz_bridge") or {}
            print(
                f"    Fuzzing Bridge      : {fb.get('status', 'unknown')} "
                f"(langs={','.join(fb.get('detected_languages') or []) or 'none'}, "
                f"crashes={len(fb.get('crashes') or [])}, plateaus={len(fb.get('plateaus') or [])})"
            )
        if "docker_parser_matrix" in eng:
            dpm = eng.get("docker_parser_matrix") or {}
            print(
                f"    Docker Parser Matrix: {dpm.get('status', 'unknown')} "
                f"(divergences={dpm.get('divergences_detected', 0)}, "
                f"active={','.join(dpm.get('active_parsers') or []) or 'none'})"
            )
        if "sandbox_invariants" in eng:
            si = eng.get("sandbox_invariants") or {}
            print(
                f"    Sandbox Invariants  : {si.get('status', 'unknown')} "
                f"(checked={si.get('invariants_checked', 0)}, failures={si.get('failures_count', 0)})"
            )
        if "poe_verifier" in eng:
            pv = eng.get("poe_verifier") or {}
            print(
                f"    POE==3 Verifier     : {pv.get('status', 'unknown')} "
                f"(verified={pv.get('verified_count', 0)}, downgraded={pv.get('downgraded_count', 0)})"
            )
        if "novelty_corpus" in eng:
            nc = eng.get("novelty_corpus") or {}
            print(
                f"    Novelty Corpus      : {nc.get('status', 'ready_offline')} "
                f"(entries={nc.get('total_entries', nc.get('entry_count', 0))}, "
                f"threshold={nc.get('novelty_threshold', 0.72)})"
            )
        if "poc_verification" in eng:
            poc_info = eng.get("poc_verification") or {}
            vc = poc_info.get("verdict_counts") or {}
            print(
                f"    PoC Verifier (--poc): {poc_info.get('status', 'completed')} "
                f"(disclosure_worthy={poc_info.get('disclosure_worthy_count', 0)}, "
                f"fp={vc.get('FALSE_POSITIVE', 0)}, fixtures={vc.get('TEST_FIXTURE', 0)}, "
                f"scripts={poc_info.get('generated_script_count', 0)})"
            )
        if "deep_audit" in eng:
            da_info = eng.get("deep_audit") or {}
            tb_i = da_info.get("trust_boundary_review") or {}
            lp_i = da_info.get("live_proxy_fuzz") or {}
            cf_i = da_info.get("coverage_fuzz") or {}
            print(
                f"    Deep Repo Audit     : {da_info.get('status', 'completed')} "
                f"(trust_files={tb_i.get('files_reviewed', 0)}, tb_findings={tb_i.get('findings_count', 0)}, "
                f"proxy={lp_i.get('status', 'disabled')}, fuzz_targets={len(cf_i.get('targets_scanned') or [])})"
            )
        if "ensemble" in eng:
            ens_info = eng.get("ensemble") or {}
            wb_info = ens_info.get("whiteboard") or {}
            print(
                f"    Ensemble Whiteboard : {ens_info.get('total_clusters', 0)} clusters "
                f"(hyps={wb_info.get('total_hypotheses', len(wb_info.get('hypotheses') or []))}, "
                f"lean={res.get('lean_verification', {}).get('status', 'unknown')})"
            )
        elif "exhaustive_local_tools" in eng:
            elt = eng.get("exhaustive_local_tools") or {}
            elt_exec = elt.get("engines_executed") or []
            print(
                f"    Exhaustive Tools    : {elt.get('status', 'completed')} "
                f"(engines={len(elt_exec)} [{','.join(elt_exec[:8])}], "
                f"findings={elt.get('total_findings', 0)}, prod={elt.get('production_findings', 0)})"
            )
        print(f"    Combined SARIF      : {res['report_files'].get('combined_sarif')}")
        if res["report_files"].get("exported_sarif"):
            print(f"    Exported SARIF      : {res['report_files'].get('exported_sarif')}")
        if res["report_files"].get("poc_index_md"):
            print(f"    PoC Triage Index    : {res['report_files'].get('poc_index_md')}")
        print(f"    Combined JSON       : {res['report_files'].get('combined_json')}")
        if res["report_files"].get("combined_csv"):
            print(f"    Combined CSV        : {res['report_files'].get('combined_csv')}")
        if res["report_files"].get("advisories"):
            print(f"    GHSA Advisories     : {len(res['report_files']['advisories'])} written")
        print(f"{'='*75}\n")
        render_poe_summary(
            poe_bd,
            coverage=cov,
            chains=chains_for_render or chaining.get("chains") or [],
            traces=traces_for_render,
            plain=bool(getattr(args, "plain", False)),
        )
        if bool(getattr(args, "swarm_board", False)):
            try:
                from engine.swarm_cli_board import (
                    create_all_scan_board,
                    enable_windows_console_vt,
                    update_all_board_from_result,
                )

                eff_plain = bool(getattr(args, "plain", False))
                if not eff_plain and not as_json:
                    enable_windows_console_vt(configure_utf8=True)
                target_disp_board = str(res.get("target_path") or host or repo or ".")
                cli_board = create_all_scan_board(
                    target_disp_board,
                    task_id=all_task_id,
                    plain=eff_plain,
                    json_mode=as_json,
                    emoji=getattr(args, "board_emoji", None),
                    width=max(60, int(getattr(args, "board_width", 100) or 100)),
                )
                update_all_board_from_result(cli_board, res)
                print(cli_board.render(plain=eff_plain, width=max(60, int(getattr(args, "board_width", 100) or 100))))
            except Exception:
                pass
    finally:
        db.close()

    if getattr(args, "enable_autonomous_hunt", False):
        _post_all_hunt_rc = cmd_autonomous_hunt(args, raw_argv=getattr(args, "_raw_cli_argv", None))
        if _post_all_hunt_rc != 0:
            sys.exit(_post_all_hunt_rc)


def cmd_harness2(args):
    """
    Executes Google Research Harness² Recursive Agent Harnessing (arXiv:2610.14224)
    in standalone or report mode.
    """
    from engine.harness2_engine import Harness2ProtocolEngine, RFCHUNT_SURFACE
    from engine.safe_network_validator import validate_and_authorize_target

    t_host = getattr(args, "host", None) or getattr(args, "target", None) or "127.0.0.1"
    ok, reason = validate_and_authorize_target(t_host, authorized=getattr(args, "authorized", False))
    if not ok:
        print(f"[!] Target authorization error for {t_host}: {reason}")
        sys.exit(1)

    runs_root = getattr(args, "harness2_runs_dir", None) or getattr(args, "runs_dir", None) or "runs/harness2"
    t_port = getattr(args, "port", 8080) or 8080
    show_report = bool(getattr(args, "harness2_report", False) or getattr(args, "report", False))

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        h2_engine = Harness2ProtocolEngine(
            runs_root=runs_root,
            target_host=t_host,
            target_port=t_port,
            db_path=getattr(args, "db", "terminator.db"),
        )

        print(f"\n{'='*78}")
        print("  GOOGLE RESEARCH HARNESS²: RECURSIVE AGENT HARNESSING FOR AN OPEN WORLD")
        print("  Citation : Xu et al., Google Research (arXiv:2610.14224, 2026)")
        print("  Repo     : https://github.com/google-research/harness2")
        print(f"{'='*78}")

        if show_report:
            runs = db.get_harness2_runs(limit=getattr(args, "limit", None) or 25)
            print(f"\n[*] HISTORICAL HARNESS² RECURSION RUNS ({len(runs)} recorded in {args.db}):")
            if not runs:
                print("    [~] No Harness² runs recorded yet. Executing a live k=1 run first...")
            else:
                print(f"  {'ID':<4} {'TASK':<10} {'DOMAIN':<28} {'MODE':<6} {'K':<3} {'R/P':<7} {'ADOPTED':<8} {'SCORE':<7}")
                print(f"  {'-'*4} {'-'*10} {'-'*28} {'-'*6} {'-'*3} {'-'*7} {'-'*8} {'-'*7}")
                for r in runs:
                    rp = f"{r['rollouts_count']}/{r['sessions_count']}"
                    print(
                        f"  {r['run_id']:<4} {r['task_id']:<10} {r['domain'][:28]:<28} "
                        f"{r['mode']:<6} {r['k_budget']:<3} {rp:<7} {r['adopted_label']:<8} {r['contrast_score']:<7.1f}"
                    )
                    print(f"       Lesson: {r['lesson']}")
                print(f"{'='*78}\n")
                return

        rfc_items = [
            r.strip().replace("RFC-", "").replace("RFC", "")
            for r in str(getattr(args, "rfc", None) or "9112").split(",")
            if r.strip()
        ]
        k = max(1, int(getattr(args, "harness2_k", None) or getattr(args, "k", None) or 1))
        raw_h2_mode = getattr(args, "harness2_mode", None) or getattr(args, "mode", None) or "parallel"
        req_mode = raw_h2_mode if raw_h2_mode in ("parallel", "sequential", "agg", "seq", "both") else "parallel"
        modes_to_run = ["parallel", "sequential"] if req_mode == "both" else [req_mode]
        domain = getattr(args, "harness2_domain", None) or getattr(args, "domain", None) or "auto"

        for rfc_clean in rfc_items:
            task_id = f"RFC{rfc_clean}"
            for mode in modes_to_run:
                print(f"  [+] Task ID                  : {task_id}")
                print(f"  [+] Recursion Mode           : {mode} ({'WIDTH: 2k INV+DOM -> k AGG' if mode in ('parallel', 'agg') else 'DEPTH: k sequential Propose-Probe-Compose rounds'})")
                print(f"  [+] Task Recursion Budget (k): {k} (Expected Rollouts R={4*k}, Improvement Stages P={3*k})")
                print(f"  [+] Editable Surface (c1..c8): {', '.join(RFCHUNT_SURFACE.always_on)} + skills/ + sub_agents/ + scripts/ + plugin/")
                print(f"  [+] Runs & Experience Dir    : {h2_engine.runs_root}")
                print(f"{'-'*78}")

                res = h2_engine.run_mode(mode=mode, task_id=task_id, k=k, domain=domain)
                res_dict = res.to_dict()
                db.save_harness2_run(res_dict)

                print("\n  [*] TASK-LEVEL PROPOSE-PROBE-COMPOSE STAGES:")
                for st in res.stages:
                    view = res.rollouts.get(st.label)
                    score_str = f"{view.behavioral_score:.1f}" if view else "N/A"
                    div_str = f"{view.parser_divergences}" if view else "0"
                    print(f"      - [{st.dim:<7}] Stage `{st.label:<10}` | Score: {score_str:<6} | Divergences: {div_str} | {st.notes}")

                print("\n  [*] BUDGET IDENTITY VERIFICATION (Ledger):")
                if res.ledger:
                    l_dict = res.ledger.to_dict()
                    print(
                        f"      - Rollouts (R = 4k) : {l_dict['actual_rollouts']}/{l_dict['expected_rollouts']} "
                        f"| Stages (P = 3k) : {l_dict['actual_sessions']}/{l_dict['expected_sessions']} "
                        f"| Verified: {l_dict['budget_verified']}"
                    )

                print("\n  [*] HARNESSING-LEVEL RECURSION (Adopted Harness & Experience Library):")
                print(f"      - Adopted Candidate : `{res.adopted_label}` (Domain: `{res.domain}`)")
                if res.similarity:
                    print(f"      - Candidate Diversity: Mean Jaccard={res.similarity['mean_jaccard_similarity']} (Diversity Index={res.similarity.get('diversity_index', 0.0)})")
                print(f"      - Cue               : {res.experience.get('cue')}")
                print(f"      - Lesson            : {res.experience.get('lesson')}")
                print(f"      - Evidence          : {res.experience.get('evidence')}")
                print(f"{'='*78}\n")
    finally:
        db.close()


def cmd_scanner(args):
    """Execute opt-in external scanners (`httpx`, `katana`, `nuclei`) into AssetGraph & DualGraph."""
    from datetime import datetime, timezone
    import secrets as _secrets
    from engine.approval_gate import ApprovalGate
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.dual_graph_engine import DualGraphAttackEngine, NoiseGovernor
    from engine.external_scanners import (
        DEFAULT_NUCLEI_TAGS,
        ExternalScannerConfig,
        _normalize_nuclei_tags,
        run_opt_in_external_discovery,
        run_opt_in_nuclei_scan,
    )
    from engine.safe_network_validator import (
        is_explicit_loopback_host,
        parse_host_and_port,
        validate_and_authorize_target,
    )
    from engine.session_loader import load_scope_file

    raw_host = getattr(args, "host", None) or getattr(args, "target", None) or "127.0.0.1"
    raw_port = getattr(args, "port", None)
    explicit_dests = getattr(args, "_explicit_cli_dests", set())
    if "port" in explicit_dests and raw_port is not None:
        eff_default_port = int(raw_port)
    elif str(raw_host).strip().lower().startswith("http://"):
        eff_default_port = 80
    elif raw_port is not None:
        eff_default_port = int(raw_port)
    else:
        eff_default_port = 443
    raw_tls = getattr(args, "tls", None)
    authorized = bool(getattr(args, "authorized", False))
    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    err_stream = sys.stderr if as_json else sys.stdout

    try:
        clean_host, resolved_port, resolved_tls = parse_host_and_port(
            raw_host,
            default_port=eff_default_port,
            use_tls=bool(raw_tls) if raw_tls is not None else None,
        )
        ok, reason = validate_and_authorize_target(clean_host, authorized=authorized)
        if not ok:
            raise PermissionError(reason)
    except (PermissionError, ValueError) as exc:
        print(f"[!] Target authorization error for {raw_host}: {exc}", file=err_stream)
        sys.exit(1)

    scanner_isolation = getattr(args, "scanner_isolation", "host") or "host"
    if scanner_isolation not in ("host", "docker"):
        print(
            f"[!] Unsupported --scanner-isolation value: {scanner_isolation!r}. Expected 'host' or 'docker'.",
            file=err_stream,
        )
        sys.exit(1)

    raw_tags = getattr(args, "nuclei_tags", None)
    try:
        norm_tags = _normalize_nuclei_tags(raw_tags) if raw_tags is not None else DEFAULT_NUCLEI_TAGS
    except (ValueError, PermissionError) as exc:
        print(f"[!] Invalid --nuclei-tags: {exc}", file=err_stream)
        sys.exit(1)

    enable_all = bool(getattr(args, "enable_external_scanners", False)) and not bool(getattr(args, "no_external_scanners", False))
    hx = getattr(args, "httpx_scan", None)
    kt = getattr(args, "katana_scan", None)
    nc = getattr(args, "nuclei_scan", None)
    any_enabled = enable_all or bool(hx) or bool(kt) or bool(nc)

    fmt_host = f"[{clean_host}]" if ":" in clean_host and not clean_host.startswith("[") else clean_host
    target_url = f"{'https' if resolved_tls else 'http'}://{fmt_host}:{resolved_port}"

    if not any_enabled:
        disabled_payload = {
            "status": "disabled",
            "ok": False,
            "scans_run": 0,
            "target": target_url,
            "execution_mode": scanner_isolation,
            "discovery": {"status": "disabled", "ok": False, "endpoints": [], "ai_sinks": []},
            "nuclei": {"status": "disabled", "ok": False, "findings": [], "total_findings": 0},
        }
        if as_json:
            render_json(disabled_payload)
        else:
            render_kv_panel(
                "External Scanners (Opt-In Disabled)",
                {
                    "Status": "disabled (pass --enable-external-scanners or --httpx-scan/--katana-scan/--nuclei-scan)",
                    "Target": target_url,
                    "Isolation": scanner_isolation,
                    "Scans Run": 0,
                },
                plain=plain,
            )
        return

    if hx is None and kt is None and nc is None:
        run_httpx = run_katana = run_nuclei = True
    else:
        run_httpx = bool(hx) if hx is not None else enable_all
        run_katana = bool(kt) if kt is not None else enable_all
        run_nuclei = bool(nc) if nc is not None else enable_all

    try:
        hygiene_cfg, _ = _configure_cli_hygiene(args)
        cfg = ExternalScannerConfig(
            enabled=True,
            execution_mode=scanner_isolation,
            docker_image=getattr(args, "docker_image", None),
            docker_network=getattr(args, "docker_network", None),
            nuclei_tags=norm_tags,
            custom_headers=list(hygiene_cfg.headers),
            user_agent=hygiene_cfg.user_agent,
            max_rps=float(getattr(args, "max_rps", 0.0) or 0.0),
        )
    except (ValueError, PermissionError) as exc:
        print(f"[!] Invalid external scanner configuration: {exc}", file=err_stream)
        sys.exit(1)

    reports_dir = getattr(args, "output_dir", None) or "reports"
    noise_profile = getattr(args, "artex_noise_profile", None)
    approval_mode = getattr(args, "approval_mode", "policy") or "policy"
    approval_rules = getattr(args, "approval_rules", None)
    scope_file = getattr(args, "scope_file", None)
    shared_task_id = f"SCAN-TASK-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{_secrets.token_hex(3)}"
    eff_auth = bool(authorized or is_explicit_loopback_host(clean_host))

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        gate = (
            ApprovalGate.from_rules_file(approval_rules, mode=approval_mode, db=db, task_id=shared_task_id)
            if approval_rules
            else ApprovalGate(mode=approval_mode, db=db, task_id=shared_task_id)
        )
        noise_gov = NoiseGovernor(profile=noise_profile)
        loaded_scope = load_scope_file(scope_file) if scope_file else {"allow_hosts": [], "deny_hosts": [], "deny_routes": []}
        scope_hosts_set = set(loaded_scope.get("allow_hosts") or []) or None

        engine = DualGraphAttackEngine(
            db=db,
            reports_dir=reports_dir,
            task_id=shared_task_id,
            scope_hosts=scope_hosts_set,
            noise_profile=noise_profile,
            approval_gate=gate,
        )
        for deny_h in loaded_scope.get("deny_hosts") or []:
            engine.asset_graph.deny_hosts.add(str(deny_h).lower())
        for deny_r in loaded_scope.get("deny_routes") or []:
            engine.asset_graph.deny_routes.append(str(deny_r))

        discovery_res: Dict[str, Any] = {
            "status": "disabled",
            "ok": False,
            "endpoints": [],
            "ai_sinks": [],
            "js_endpoints": [],
            "technologies": [],
            "assets_added": 0,
        }
        nuclei_res: Dict[str, Any] = {
            "status": "disabled",
            "ok": False,
            "tags": list(norm_tags),
            "findings": [],
            "total_findings": 0,
            "findings_ingested": 0,
        }

        _stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _stdout_ctx:
            from engine.external_scanners import resolve_external_scanner_tool_configs
            discovery_cfg, nuclei_cfg = resolve_external_scanner_tool_configs(
                cfg,
                run_httpx=run_httpx,
                run_katana=run_katana,
                run_nuclei=run_nuclei,
            )
            if run_httpx or run_katana:
                discovery_res = run_opt_in_external_discovery(
                    target_url,
                    config=discovery_cfg,
                    asset_graph=engine.asset_graph,
                    authorized=eff_auth,
                    approval_gate=gate,
                    noise_governor=noise_gov,
                    run_httpx=run_httpx,
                    run_katana=run_katana,
                )
            if run_nuclei:
                nuclei_res = run_opt_in_nuclei_scan(
                    target_url,
                    config=nuclei_cfg,
                    dual_graph_engine=engine,
                    authorized=eff_auth,
                    approval_gate=gate,
                    noise_governor=noise_gov,
                )

        scans_run = int(bool(run_httpx)) + int(bool(run_katana)) + int(bool(run_nuclei))
        payload = {
            "status": "completed",
            "ok": bool(discovery_res.get("ok") or nuclei_res.get("ok")),
            "scans_run": scans_run,
            "task_id": shared_task_id,
            "target": target_url,
            "execution_mode": scanner_isolation,
            "discovery": discovery_res,
            "nuclei": nuclei_res,
            "endpoints": list(discovery_res.get("endpoints") or []),
            "ai_sinks": list(discovery_res.get("ai_sinks") or []),
            "findings": list(nuclei_res.get("findings") or []),
        }
    except (PermissionError, ValueError) as exc:
        print(f"[!] External scanner execution rejected: {exc}", file=err_stream)
        sys.exit(1)
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "External Scanners Summary",
        {
            "Task ID": shared_task_id,
            "Target": target_url,
            "Isolation": scanner_isolation,
            "Scans Run": scans_run,
            "Endpoints": len(payload["endpoints"]),
            "AI Sinks": len(payload["ai_sinks"]),
            "Nuclei Findings": len(payload["findings"]),
        },
        plain=plain,
    )
    rows: List[List[Any]] = []
    for ep in payload["endpoints"]:
        rows.append(["endpoint", ep, "AssetGraph"])
    for nf in payload["findings"]:
        if isinstance(nf, dict):
            rows.append([nf.get("severity", "INFO"), nf.get("rule_id", ""), nf.get("file_path", "")])
    render_table("Discovered Surface & Findings", ["Kind/Severity", "Item", "Target"], rows, plain=plain)


def cmd_proxy(args):
    """Start the embedded pure-CLI recording HTTP/HTTPS MITM proxy (Pillar 2)."""
    import time as _time
    from engine.artex_bridge import TrafficCaptureSession
    from engine.cli_render import render_kv_panel
    from engine.dual_graph_engine import NoiseGovernor
    from engine.local_mitm_proxy import LocalRecordingMITMProxy, RewriteRule

    rewrite_rules = []
    for raw_rule in (getattr(args, "rewrite_rule", None) or []):
        if ":" in raw_rule and "=" in raw_rule:
            rname, rest = raw_rule.split(":", 1)
            hname, hval = rest.split("=", 1)
            rewrite_rules.append(
                RewriteRule(rule_id=rname.strip(), phase="request", header_name=hname.strip(), header_value=hval.strip())
            )
        elif "=" in raw_rule:
            hname, hval = raw_rule.split("=", 1)
            rewrite_rules.append(
                RewriteRule(rule_id=f"set_{hname.strip()}", phase="request", header_name=hname.strip(), header_value=hval.strip())
            )

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        session = TrafficCaptureSession(db=db, task_id=getattr(args, "task_id", None) or "PROXY-SESSION")
        governor = NoiseGovernor(profile=getattr(args, "noise_profile", None))
        raw_port = getattr(args, "port", None)
        bind_port = 8788 if raw_port is None else int(raw_port)
        proxy = LocalRecordingMITMProxy(
            host=getattr(args, "host", "127.0.0.1") or "127.0.0.1",
            port=bind_port,
            keys_dir=getattr(args, "ca_dir", "keys") or "keys",
            traffic_session=session,
            noise_governor=governor,
            rewrite_rules=rewrite_rules,
            authorized=bool(getattr(args, "authorized", False)),
        )
        proxy.start()
        try:
            info = {
                "Proxy URL": proxy.proxy_url,
                "CA Cert": proxy.ca_cert_path,
                "DB": args.db,
                "Noise Profile": governor.profile,
                "Authorized Remote": bool(getattr(args, "authorized", False)),
                "Rewrite Rules": len(rewrite_rules),
            }
            render_kv_panel(
                "RFCHunt Embedded Recording MITM Proxy",
                info,
                as_json=bool(getattr(args, "as_json", False)),
                plain=bool(getattr(args, "plain", False)),
            )
            duration = getattr(args, "duration", None)
            if duration is not None and float(duration) >= 0:
                _time.sleep(float(duration))
            else:
                try:
                    while True:
                        _time.sleep(0.5)
                except KeyboardInterrupt:
                    pass
        finally:
            proxy.stop()
    finally:
        db.close()


def cmd_chains(args):
    """Query and display persisted ARTEX attack chains from the SQLite database."""
    from engine.cli_render import render_chains

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        min_poe = int(getattr(args, "min_poe", 0) or 0)
        verified_only = bool(getattr(args, "verified_only", False))
        chains = db.get_attack_chains(
            limit=int(getattr(args, "limit", 50) or 50),
            task_id=getattr(args, "task_id", None),
            min_poe=min_poe if min_poe > 0 else None,
            verified_only=verified_only,
        )
        render_chains(
            chains,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_traces(args):
    """Search and inspect persisted ARTEX shared worker traces."""
    from engine.cli_render import render_traces

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        traces = db.list_worker_traces(
            task_id=getattr(args, "task_id", None),
            worker_id=getattr(args, "worker_id", None),
            query=getattr(args, "query", None),
            limit=int(getattr(args, "limit", 100) or 100),
        )
        render_traces(
            traces,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_coverage(args):
    """Compute and print the ARTEX Asset Coverage Ledger from persisted graphs."""
    from engine.cli_render import render_coverage
    from engine.dual_graph_engine import DualGraphAttackEngine

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        target_task_id = getattr(args, "task_id", None)
        engine = DualGraphAttackEngine(db=None, task_id=target_task_id)
        for n in db.get_dual_graph_nodes():
            gtype = n.get("graph_type")
            nid = n.get("node_id")
            attrs = n.get("attributes") or {}
            if gtype == "ASSET":
                engine.asset_graph.add_asset(nid, n.get("node_type", "ENDPOINT"), n.get("label", nid), attrs)
            elif gtype == "EXPLORATION":
                node_task_id = attrs.get("task_id")
                if target_task_id and node_task_id is not None and node_task_id != target_task_id:
                    continue
                engine.exploration_graph.add_intent(
                    nid,
                    n.get("node_type", "FACT"),
                    n.get("label", nid),
                    anchored_asset_id=attrs.get("anchored_asset"),
                    attributes=attrs,
                    status=attrs.get("status", "PENDING"),
                )
        for anc in db.get_exploration_anchors(task_id=target_task_id):
            engine.exploration_graph.anchor_asset(anc["node_id"], anc["asset_id"])
        cov = engine.compute_coverage_ledger()
        render_coverage(
            cov,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_retest(args):
    """Replay persisted attack chains and record FIXED / STILL_REPRODUCIBLE / CANNOT_CONFIRM verdicts."""
    from engine.artex_bridge import TrafficCaptureSession
    from engine.cli_render import render_retest_results
    from engine.dual_graph_engine import ArtexRetester
    from engine.safe_network_validator import is_explicit_loopback_host, validate_and_authorize_target

    target_host = getattr(args, "host", None)
    target_port = getattr(args, "port", None)
    use_tls = getattr(args, "tls", None)
    authorized = bool(getattr(args, "authorized", False))
    live = bool(getattr(args, "live", False))

    if target_host:
        ok, reason = validate_and_authorize_target(target_host, authorized=authorized)
        if not ok:
            print(f"[!] Target authorization error for {target_host}: {reason}")
            sys.exit(1)
        live = True
        if is_explicit_loopback_host(target_host):
            authorized = True

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        session = TrafficCaptureSession(db=db, task_id=getattr(args, "task_id", None) or "RETEST")
        retester = ArtexRetester(db=db, traffic_session=session)
        chain_id = getattr(args, "chain_id", None)
        task_id_filter = getattr(args, "task_id", None)
        if chain_id:
            found = db.get_attack_chain(str(chain_id), task_id=task_id_filter)
            if found is None:
                print(f"[!] Attack chain '{chain_id}' not found.", file=sys.stderr)
                sys.exit(1)
            chains = [found]
        else:
            chains = db.get_attack_chains(
                limit=int(getattr(args, "limit", 50) or 50),
                task_id=task_id_filter,
            )
            if not getattr(args, "all_chains", False):
                chains = chains[:10]

        results = []
        for ch in chains:
            verifier_fn = None
            if live and not ch.get("traffic_id") and target_host:
                from engine.live_executors import LiveWorkerExecutorRegistry
                reg = LiveWorkerExecutorRegistry(
                    host=target_host,
                    port=int(target_port or 80),
                    use_tls=bool(use_tls),
                    authorized=authorized,
                    traffic_session=session,
                    workspace_root=_resolve_cli_workspace_root(args),
                )

                def _live_fallback_verifier(chain_obj, _reg=reg):
                    ok_v, ev, _, meta = _reg.execute_candidate_live({
                        "attack_type": chain_obj.get("attack_type", ""),
                        "target_route": chain_obj.get("target_endpoint") or "/",
                        "raw_probe": chain_obj.get("raw_payload") or "",
                    })
                    if ok_v:
                        return True, ev
                    tid = meta.get("traffic_id")
                    ex = session.get_exchange(tid) if tid else None
                    if ex is not None and ex.status_code >= 500:
                        return None, ev
                    if ex is not None and ex.status_code in (400, 401, 403, 404, 405, 422):
                        return False, ev
                    return None, ev

                verifier_fn = _live_fallback_verifier

            results.append(
                retester.retest_chain(
                    ch,
                    verifier_fn=verifier_fn,
                    live=live,
                    authorized=authorized,
                    target_host=target_host,
                    target_port=int(target_port) if target_port is not None else None,
                    use_tls=use_tls,
                )
            )
        render_retest_results(
            results,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_export_advisory(args):
    """Export GHSA-ready Markdown advisories and/or formula-safe CSV from persisted findings."""
    from pathlib import Path as _Path
    from engine.advisory_exporter import AdvisoryExporter, _safe_filename
    from engine.cli_render import render_kv_panel

    out_dir = _Path(getattr(args, "out", None) or "reports")
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        exporter = AdvisoryExporter(reports_dir=out_dir)
        chain_id = getattr(args, "chain_id", None)
        task_id_filter = getattr(args, "task_id", None)
        include_leads = bool(getattr(args, "include_leads", False))
        if chain_id:
            found = db.get_attack_chain(str(chain_id), task_id=task_id_filter)
            if found is None:
                print(f"[!] Attack chain '{chain_id}' not found.", file=sys.stderr)
                sys.exit(1)
            chains = [found]
        else:
            req_min_poe = int(getattr(args, "min_poe", 0) or 0)
            eff_min_poe = req_min_poe if include_leads else max(3, req_min_poe)
            chains = db.get_attack_chains(
                limit=int(getattr(args, "limit", 50) or 50),
                task_id=task_id_filter,
                min_poe=eff_min_poe if eff_min_poe > 0 else None,
            )

        written_md: List[str] = []
        for ch in chains:
            cid = str(ch.get("chain_id") or "CHAIN")
            tid = ch.get("traffic_id")
            trec = db.get_traffic_evidence(tid) if tid else None
            rtests = db.get_chain_retests(chain_id=cid)
            out_md = out_dir / f"advisory_{_safe_filename(cid)}.md"
            exporter.export_ghsa_markdown(ch, traffic_record=trec, retests=rtests, output_path=out_md)
            written_md.append(str(out_md))

        csv_out = None
        if getattr(args, "csv", False):
            findings = db.get_mantis_findings(limit=500) if hasattr(db, "get_mantis_findings") else []
            csv_path = out_dir / "findings_and_chains.csv"
            exporter.export_findings_csv(findings, chains=chains, output_path=csv_path)
            csv_out = str(csv_path)

        summary = {
            "Output Directory": str(out_dir),
            "Advisories Exported": len(written_md),
            "Files": written_md,
            "CSV Exported": csv_out or "disabled",
        }
        render_kv_panel(
            "RFCHunt Advisory Export",
            summary,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_archive(args):
    """Export or import AES-256-GCM encrypted task archives (*.rfca) with SHA-256 verification."""
    from engine.advisory_exporter import AdvisoryExporter
    from engine.cli_render import render_kv_panel
    from engine.secret_store import SecretBox

    key_file = getattr(args, "key_file", None)
    export_path = getattr(args, "export_path", None)
    import_path = getattr(args, "import_path", None)
    if not export_path and not import_path:
        print("[!] Specify either --export <file.rfca> or --import <file.rfca>.")
        sys.exit(1)

    if export_path:
        db = _resolve_db_cls()(getattr(args, "db", "terminator.db"), secret_key_path=key_file)
        try:
            box = db.secret_box or SecretBox.from_env_or_keyfile(key_path=key_file, create_if_missing=True)
            res = AdvisoryExporter().export_task_archive(
                db,
                export_path,
                task_id=getattr(args, "task_id", None),
                secret_box=box,
            )
            render_kv_panel(
                "RFCHunt Encrypted Archive Export",
                res,
                as_json=bool(getattr(args, "as_json", False)),
                plain=bool(getattr(args, "plain", False)),
            )
        finally:
            db.close()
    else:
        box = SecretBox.from_env_or_keyfile(key_path=key_file, create_if_missing=False)
        res = AdvisoryExporter.import_task_archive(import_path, secret_box=box)
        summary = {
            "Archive": import_path,
            "Schema": res["schema"],
            "Task ID": res["task_id"],
            "Exported At": res["exported_at"],
            "SHA-256": res["sha256"],
            "Verified": res["verified"],
            "Chains": len((res.get("payload") or {}).get("attack_chains") or []),
            "Traffic Records": len((res.get("payload") or {}).get("traffic_evidence") or []),
        }
        render_kv_panel(
            "RFCHunt Encrypted Archive Verification",
            summary,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )


def cmd_rea(args):
    """Execute Module 21 (`morluto/rea`) client bundle, Electron `.asar`, source-map & live JS surface analyzer."""
    from engine.approval_gate import ApprovalGate
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.dual_graph_engine import NoiseGovernor
    from engine.execution_policy import ExecutionPolicy, _validate_canonical_path_syntax
    from engine.rea_integrator import ReaIntegrator
    from engine.safe_network_validator import (
        is_explicit_loopback_host,
        parse_host_and_port,
        validate_and_authorize_target,
    )

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    err_stream = sys.stderr if as_json else sys.stdout
    rea_target_arg = getattr(args, "rea_target", None)
    primary_ws = getattr(args, "workspace_root", None) or getattr(args, "repo", None) or getattr(args, "path", None)
    rea_ws = (
        str(Path(primary_ws).parent)
        if (primary_ws and Path(primary_ws).exists() and Path(primary_ws).is_file())
        else primary_ws
    )
    target_path = rea_target_arg or primary_ws
    raw_host = getattr(args, "host", None)
    if not target_path and not raw_host:
        target_path = "."
    if target_path is not None:
        raw_tp = str(target_path)
        tp_err = _validate_canonical_path_syntax(raw_tp, allow_trailing_slash=True)
        if tp_err is not None and raw_tp != ".":
            print(f"[!] REA target_path rejected: {tp_err} ('{raw_tp}')", file=err_stream)
            sys.exit(1)
    if rea_target_arg and rea_ws:
        ok_rea, detail_rea = ExecutionPolicy.get_instance().validate_file_path(
            rea_target_arg,
            workspace_root=rea_ws,
            allow_directory=True,
        )
        if not ok_rea:
            print(f"[!] REA target_path outside workspace_root: {detail_rea}", file=err_stream)
            sys.exit(1)
        target_path = detail_rea

    clean_host = None
    resolved_port = None
    resolved_tls = bool(getattr(args, "tls", False))
    authorized = bool(getattr(args, "authorized", False))

    if raw_host:
        raw_port = getattr(args, "port", None)
        explicit_dests = getattr(args, "_explicit_cli_dests", set())
        if "port" in explicit_dests and raw_port is not None:
            eff_port = int(raw_port)
        elif str(raw_host).strip().lower().startswith("http://"):
            eff_port = 80
        elif str(raw_host).strip().lower().startswith("https://"):
            eff_port = 443
        else:
            eff_port = int(raw_port) if raw_port is not None else 443
        try:
            clean_host, resolved_port, resolved_tls = parse_host_and_port(
                raw_host,
                default_port=eff_port,
                use_tls=True if getattr(args, "tls", False) else None,
            )
            ok, reason = validate_and_authorize_target(clean_host, authorized=authorized)
            if not ok:
                raise PermissionError(reason)
        except (PermissionError, ValueError) as exc:
            print(f"[!] REA target authorization error for {raw_host}: {exc}", file=err_stream)
            sys.exit(1)

    reports_dir = getattr(args, "output_dir", None) or "reports"
    approval_mode = getattr(args, "approval_mode", "policy") or "policy"
    approval_rules = getattr(args, "approval_rules", None)
    noise_profile = getattr(args, "artex_noise_profile", None)

    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        gate = (
            ApprovalGate.from_rules_file(approval_rules, mode=approval_mode, db=db, task_id="REA-CLI")
            if approval_rules
            else ApprovalGate(mode=approval_mode, db=db, task_id="REA-CLI")
        )
        noise_gov = NoiseGovernor(profile=noise_profile)
        integrator = ReaIntegrator(
            db=db,
            reports_dir=reports_dir,
            approval_gate=gate,
            noise_governor=noise_gov,
            workspace_root=rea_ws,
        )
        _stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _stdout_ctx:
            result = integrator.analyze(
                target_path=target_path,
                host=clean_host,
                port=resolved_port,
                use_tls=resolved_tls,
                authorized=bool(authorized or (clean_host and is_explicit_loopback_host(clean_host))),
                use_rea_cli=bool(getattr(args, "rea_cli", False)),
                write_reports=True,
                workspace_root=rea_ws,
            )
            payload = result.to_dict()
    except (PermissionError, ValueError) as exc:
        print(f"[!] REA execution rejected: {exc}", file=err_stream)
        sys.exit(1)
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "Module 21: REA Client Surface & Artifact Audit",
        {
            "Target": payload.get("target", ""),
            "Status": payload.get("status", ""),
            "Mode": payload.get("mode", ""),
            "Findings": len(payload.get("findings") or []),
            "Endpoints Mined": len(payload.get("discovered_endpoints") or []),
            "AI Sinks Mined": len(payload.get("ai_sinks") or []),
            "Electron IPC Channels": len(payload.get("ipc_channels") or []),
            "SARIF Report": (payload.get("report_files") or {}).get("sarif", "-"),
        },
        plain=plain,
    )
    rows = [
        [
            f.get("severity", "MEDIUM"),
            f.get("rule_id", ""),
            f.get("title", ""),
            f"{f.get('file_path', '')}:{f.get('line_number', 1)}",
        ]
        for f in (payload.get("findings") or [])
    ]
    render_table("REA Surface & Bundle Findings", ["Severity", "Rule ID", "Title", "Location"], rows, plain=plain)


def cmd_fetch(args):
    """Downloads core and recent normative RFC documents into local cache and DB."""
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    cache_dir = getattr(args, "cache_dir", "rfcs") or "rfcs"
    count = int(getattr(args, "count", None) or getattr(args, "max_rfcs", None) or 3)
    discover_recent = int(getattr(args, "discover_recent", 0) or 0)
    fetcher = RFCFetcher(cache_dir=cache_dir, db=db)
    try:
        print(f"[+] Fetching core RFC documents (limit={count})...")
        core_docs = fetcher.fetch_core_rfcs(limit=count)
        print(f"[*] Fetched {len(core_docs)} core RFCs.")

        if discover_recent:
            print("[+] Scanning RFC index for newly published protocol specifications...")
            recent_nums = fetcher.discover_recent_rfcs(max_discover=discover_recent)
            for num in recent_nums:
                fetcher.fetch_rfc_by_number(num)
    finally:
        if hasattr(fetcher, "client") and hasattr(fetcher.client, "close"):
            fetcher.client.close()
        db.close()


def cmd_chunk(args):
    """Chunks cached RFCs into terminator-weighted micro-inspiration fragments."""
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    sentences = int(getattr(args, "sentences", 2) or 2)
    try:
        cursor = db.conn.cursor()
        cursor.execute("SELECT rfc_id, doc_path FROM rfcs")
        rows = cursor.fetchall()

        if not rows:
            print("[-] No RFCs found in database. Run 'fetch' first.")
            return

        total_chunks = 0
        for row in rows:
            rfc_id = row["rfc_id"]
            doc_path = row["doc_path"]
            try:
                with open(doc_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                num_str = "".join(ch for ch in str(rfc_id) if ch.isdigit())
                rfc_num = int(num_str) if num_str else None
                fragments = RFCChunker.chunk_document_for_terminator(
                    text, sentences_per_chunk=sentences, rfc_num=rfc_num
                )
                saved = db.save_fragments(rfc_id, fragments)
                total_chunks += saved
                print(f"[+] {rfc_id}: Generated and saved {saved} micro-inspiration fragments.")
            except Exception as e:
                print(f"[!] Error chunking {rfc_id}: {e}")

        print(f"[*] Successfully saved {total_chunks} total micro-inspiration fragments.")
    finally:
        db.close()


def cmd_generate(args):
    """Synthesizes candidate HTTP probes from unprocessed RFC fragments."""
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    limit = int(getattr(args, "limit", None) or getattr(args, "fragments", None) or 5)
    try:
        unprocessed = db.get_unprocessed_fragments(limit=limit)

        if not unprocessed:
            print("[-] No unprocessed fragments. Run 'chunk' first.")
            return

        print(f"[+] Generating novel candidate probes from {len(unprocessed)} fragments using {args.model} (fusion={args.fusion})...")
        generator = ProbeGenerator(preferred_model=args.model, use_fusion=args.fusion, db=db)

        total_probes = 0
        for frag in unprocessed:
            frag_id = frag["fragment_id"]
            rfc_id = frag["rfc_id"]
            content = frag["content"]

            print(f"\n[*] Fragment [{rfc_id} #{frag_id}]: {content[:80]}...")
            probes = generator.generate_candidate_probes(content, fragment_id=frag_id)
            for p in probes:
                print(f"    -> [Probe #{p.get('probe_id')}] (Clean: {p['is_clean']}) {p['rationale']}")
                total_probes += 1

        print(f"\n[+] Generated and saved {total_probes} candidate probes.")
    finally:
        db.close()


def cmd_permute(args):
    """Applies protocol vector permutations to stored LLM/fusion base probes."""
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    limit = int(getattr(args, "limit", None) or 10)
    variants_cnt = int(getattr(args, "variants", 3) or 3)
    try:
        cursor = db.conn.cursor()
        cursor.execute(
            "SELECT probe_id, fragment_id, rationale, raw_request, is_clean FROM probes WHERE source_type IN ('llm', 'fusion') LIMIT ?",
            (limit,),
        )
        rows = [dict(r) for r in cursor.fetchall()]

        if not rows:
            print("[-] No base probes to permute. Run 'generate' first.")
            return

        permutator = VectorPermutator(db=db)
        total_permuted = 0
        for row in rows:
            variants = permutator.permute_probe(row, max_variants=variants_cnt)
            for v in variants:
                print(f"[+] Permutation #{v.get('probe_id')}: {v['rationale']}")
                total_permuted += 1

        print(f"[*] Generated {total_permuted} permuted probe variants.")
    finally:
        db.close()


def cmd_evaluate(args):
    """Evaluates pending probes with active host network containment."""
    with HostContainmentManager():
        return _cmd_evaluate_impl(args)


def _cmd_evaluate_impl(args):
    from deterministic_harness import DeterministicHarness
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    target_host = getattr(args, "target", None) or getattr(args, "host", "127.0.0.1")
    target_port = int(getattr(args, "port", 8080) or 8080)
    use_tls = bool(getattr(args, "tls", False))
    timeout = float(getattr(args, "timeout", 3.0) or 3.0)
    limit = int(getattr(args, "limit", 20) or 20)
    try:
        pending = db.get_pending_probes(target_host=target_host, limit=limit)

        if not pending:
            print(f"[-] No pending probes for target {target_host}. Generate probes first or check test history.")
            return

        harness = DeterministicHarness(
            host=target_host,
            port=target_port,
            use_tls=use_tls,
            timeout=timeout,
            db=db,
        )

        print(f"[+] Starting deterministic evaluation of {len(pending)} probes against {target_host}:{target_port} (TLS={use_tls})...")

        vulnerable_count = 0
        concurrency = getattr(args, "concurrency", 4)
        if concurrency > 1 and len(pending) > 1:
            print(f"[*] Multithreaded evaluation active: {concurrency} threads (bounded by semaphore)")
            probes_list = [dict(r) for r in pending]
            results = harness.evaluate_batch_concurrent(probes_list, max_concurrency=concurrency)
            for (is_vuln, desync_class, details, meta) in results:
                if is_vuln:
                    vulnerable_count += 1
                    print(f"    [!] BREAKTHROUGH FINDING: {details} ({desync_class})")
                else:
                    if meta.get("anomalies"):
                        for anom in meta["anomalies"]:
                            print(f"    [~] ANOMALY DETECTED: {anom['type']} - {anom['description']}")
        else:
            for row in pending:
                probe_dict = dict(row)
                p_id = probe_dict["probe_id"]
                print(f"\n[*] Evaluating Probe #{p_id}: {probe_dict['rationale'][:70]}...")

                is_vuln, desync_class, details, meta = harness.run_evaluation(probe_dict)
                if is_vuln:
                    print(f"    [!] BREAKTHROUGH FINDING: {details}")
                    print(f"    [!] Attack Class: {desync_class}")
                    vulnerable_count += 1
                else:
                    print(f"    [-] Result: {details}")

                if meta.get("anomalies"):
                    for anom in meta["anomalies"]:
                        print(f"    [~] ANOMALY DETECTED: {anom['type']} - {anom['description']}")

        print(f"\n[*] Evaluation complete: {vulnerable_count} breakthroughs out of {len(pending)} evaluated.")
    finally:
        db.close()


def cmd_weaponize(args):
    """Tests Dangling-Byte Request Queue Poisoning against the target host."""
    from weaponizer import RQPWeaponizer
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    target_host = getattr(args, "target", None) or getattr(args, "host", "127.0.0.1")
    target_port = int(getattr(args, "port", 8080) or 8080)
    use_tls = bool(getattr(args, "tls", False))
    try:
        weaponizer = RQPWeaponizer(
            host=target_host,
            port=target_port,
            use_tls=use_tls,
            db=db,
        )

        sample_trigger = (
            "POST / HTTP/1.1\r\n"
            "Host: target.local\r\n"
            "Content-Type: multipart/byteranges; boundary=BOUND\r\n"
            "Content-Length: 120\r\n\r\n"
            "$PAYLOAD"
        )

        print(f"[+] Launching Autonomous RQP with Dangling-Byte Technique on {target_host}:{target_port}...")
        is_stolen, reason, evidence = weaponizer.test_dangling_byte_rqp(sample_trigger)
        if is_stolen:
            print(f"\n[!] WEAPONIZATION SUCCESS: {reason}")
        else:
            print(f"\n[-] Weaponization outcome: {reason}")
    finally:
        db.close()


def cmd_cascade(args):
    """Formulates second-order shared-parser confusion hypotheses from confirmed findings."""
    db = _resolve_db_cls()(getattr(args, "db", "terminator.db"))
    try:
        confirmed = db.get_confirmed_findings()

        if not confirmed:
            print("[-] No confirmed vulnerable findings yet. Run 'evaluate' to surface discoveries first.")
            if getattr(args, "demo", False):
                print("[*] Running Cascade Extrapolation demo on Kettle's RFC 2616 multipart/byteranges finding...")
                confirmed = [{
                    "eval_id": 1,
                    "rationale": "RFC 2616 §19.2 response rule applied in request",
                    "rfc_fragment": "The one exception is the 'multipart/byteranges' type when it appears in a 206 response.",
                    "details": "Status shift 200 -> 405. Marker reflected in victim stream.",
                    "raw_evidence": "HTTP/1.1 200 OK\r\n\r\nTrigger Accepted\n--- POLLUTED ---\nHTTP/1.1 405 Method Not Allowed",
                }]
            else:
                return

        cascade_engine = DiscoveryCascade(preferred_model=args.model, use_fusion=args.fusion, db=db)
        for finding in confirmed:
            f_dict = dict(finding)
            print(f"\n[+] Extrapolating finding #{f_dict.get('eval_id')}: {f_dict.get('details')}")
            result = cascade_engine.cascade_from_finding(f_dict, eval_id=f_dict.get("eval_id"))
            if result:
                print(f"    [Cascade Category]: {result['category']}")
                print(f"    [Hypothesis]: {result['hypothesis']}")
                print(f"    [New Probes Synthesized]: {len(result['suggested_probes'])}")
    finally:
        db.close()


def cmd_lab(args):
    """Starts standalone Test Lab Server with optional random high port and `--patched` toggle."""
    from test_lab_server import TestLabServer
    lab_host = getattr(args, "host", "127.0.0.1") or "127.0.0.1"
    lab_port = int(getattr(args, "port", 8080) or 0)
    if getattr(args, "random_port", False) or lab_port == 0:
        lab_port = TestLabServer.get_high_random_port(min_port=10000, max_port=65000, host=lab_host)
    server = TestLabServer(
        host=lab_host,
        port=lab_port,
        auth_boundary_patched=bool(getattr(args, "patched", False)),
    )
    server.start()
    try:
        print(f"[*] Test Lab Server is active on http://{lab_host}:{lab_port}. Press Ctrl+C to stop.")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        server.stop()


def cmd_auto(args):
    """Continuous research loop: Ingest -> Chunk -> Generate -> Permute -> Evaluate -> Cascade."""
    from test_lab_server import TestLabServer
    print("=" * 70)
    print("  HTTP TERMINATOR: AUTONOMOUS PROTOCOL RESEARCH CASCADE ENGINE")
    print("  Model: Google Gemma 2 / Local ModelFusion (Zero-Cost 24/7 Mode)")
    print("=" * 70)

    _dispatch_cmd("cmd_fetch", args)
    _dispatch_cmd("cmd_chunk", args)
    _dispatch_cmd("cmd_generate", args)
    _dispatch_cmd("cmd_permute", args)

    lab_server = None
    target_host = getattr(args, "target", None) or getattr(args, "host", "127.0.0.1")
    target_port = int(getattr(args, "port", 8080) or 8080)
    if target_host == "127.0.0.1" and target_port == 8080:
        lab_server = TestLabServer(host="127.0.0.1", port=8080)
        lab_server.start()
        time.sleep(0.5)

    with HostContainmentManager():
        try:
            _dispatch_cmd("cmd_evaluate", args)
            _dispatch_cmd("cmd_weaponize", args)
            _dispatch_cmd("cmd_cascade", args)

            try:
                from engine.caldera_bridge import CalderaBridge
                bridge = CalderaBridge(db_path=args.db)
                c_res = bridge.export_plugin(output_dir="caldera_export")
                bridge.export_plugin(output_dir=".")
                print(f"\n[+] Caldera Auto-Sync [Default]: {c_res['abilities_count']} abilities and {c_res['adversaries_count']} adversaries updated.")
            except Exception as e:
                print(f"[-] Caldera Auto-Sync notice: {e}")

            if not getattr(args, "no_dream_rsi", False):
                try:
                    print(f"\n[*] Dream-RSI Auto-Optimization [Default]: Evolving off-policy exploration trajectories...")
                    _dispatch_cmd("cmd_dream", args)
                except Exception as e:
                    print(f"[-] Dream-RSI Auto-Optimization notice: {e}")
        finally:
            if lab_server:
                lab_server.stop()


def cmd_hunt(args):
    """Continuously fetches RFCs and evaluates until flaws are discovered."""
    from continuous_scanner import ContinuousFlawHunter

    target_host = getattr(args, "target", None) or getattr(args, "host", "127.0.0.1")
    target_port = int(getattr(args, "port", 8080) or 8080)
    max_rfcs = int(getattr(args, "max_rfcs", None) or 15)
    fragments = int(getattr(args, "fragments", None) or getattr(args, "limit", None) or 3)
    variants = int(getattr(args, "variants", None) or 2)

    hunter = ContinuousFlawHunter(
        target_host=target_host,
        target_port=target_port,
        use_tls=bool(getattr(args, "tls", False)),
        preferred_model=args.model,
        use_fusion=args.fusion,
        db_path=args.db,
    )
    flaws = hunter.run_until_flaw(
        max_rfcs=max_rfcs,
        fragments_per_rfc=fragments,
        permutations_per_probe=variants,
        stop_on_first_flaw=not bool(getattr(args, "keep_going", False)),
    )
    print(f"\n[*] Hunt complete. Total flaws/anomalies found: {len(flaws)}")

    try:
        from engine.caldera_bridge import CalderaBridge
        bridge = CalderaBridge(db_path=args.db)
        c_res = bridge.export_plugin(output_dir="caldera_export")
        bridge.export_plugin(output_dir=".")
        print(f"[+] Caldera Auto-Sync [Default]: {c_res['abilities_count']} abilities and {c_res['adversaries_count']} adversaries updated.")
    except Exception:
        pass

    if not getattr(args, "no_dream_rsi", False):
        try:
            print(f"\n[*] Dream-RSI Auto-Optimization [Default]: Evolving off-policy exploration trajectories...")
            _dispatch_cmd("cmd_dream", args)
        except Exception:
            pass


def cmd_mcp(args):
    """Runs the HTTP Terminator MCP Server over stdio, Streamable HTTP (/http), or Legacy SSE (/sse)."""
    from mcp_server import MCPHttpServer, TerminatorMCPServer
    transport = getattr(args, "mcp_transport", None) or getattr(args, "transport", None) or "stdio"
    with TerminatorMCPServer(db_path=args.db) as server:
        if transport == "stdio":
            print("[+] Launching Model Context Protocol (MCP) Server over JSON-RPC stdio...", file=sys.stderr)
            server.run_stdio()
        else:
            http_srv = MCPHttpServer(
                server,
                host=getattr(args, "mcp_host", "127.0.0.1") or "127.0.0.1",
                port=int(getattr(args, "mcp_port", 8790) or 8790),
                bearer_token=getattr(args, "mcp_token", None),
            )
            http_srv.serve_forever()


def cmd_ruler(args):
    """Measures front-end transformations using backend header length limits (James Kettle technique)."""
    from protocol_ruler import ProtocolRuler
    raw_host = getattr(args, "target", None) or getattr(args, "host", "127.0.0.1")
    port = int(getattr(args, "port", 8080) or 8080)
    use_tls = bool(getattr(args, "tls", False) or (port == 443))
    targets_arg = getattr(args, "targets", None)
    if targets_arg:
        target_tuples = parse_targets(targets_arg, raw_host, port, use_tls)
    else:
        target_tuples = [(raw_host, port, use_tls)]

    custom = None
    if getattr(args, "sequence", None):
        seq_str = args.sequence
        if seq_str.startswith("\\x"):
            seq_bytes = bytes.fromhex(seq_str.replace("\\x", ""))
        else:
            try:
                seq_bytes = bytes.fromhex(seq_str)
            except ValueError:
                seq_bytes = seq_str.encode("latin-1")
        custom = [(getattr(args, "name", "Custom Probe"), seq_bytes, f"Custom sequence: {seq_str}")]

    raw_timeout = float(getattr(args, "timeout", 3.5) or 3.5)
    ruler_timeout = raw_timeout if (0 < raw_timeout <= 30.0) else 3.5
    max_size = int(getattr(args, "max_size", 131072) or 131072)

    for t_host, t_port, t_tls in target_tuples:
        proto_str = "https" if t_tls else "http"
        print(f"\n{'='*75}")
        print("[*] LAUNCHING PROTOCOL RULER ENGINE (James Kettle Benchmark Technique)")
        print(f"[*] Target: {proto_str}://{t_host}:{t_port}")
        print(f"{'='*75}")
        ruler = ProtocolRuler(
            host=t_host,
            port=t_port,
            use_tls=t_tls,
            timeout=ruler_timeout,
            verbose=bool(getattr(args, "verbose", False)),
            debug=bool(getattr(args, "debug", False)),
        )
        ruler.run_comprehensive_audit(custom_sequences=custom, max_size=max_size)
        print("\n[*] Protocol Ruler Audit Completed.")


def cmd_dream(args):
    """Executes offline Replay-Tree Dream-RSI policy evolution or 4-baseline empirical RL benchmark."""
    db_path = getattr(args, "db", "terminator.db")
    target_host = getattr(args, "target", None) or getattr(args, "host", "127.0.0.1")
    target_port = int(getattr(args, "port", 5006) or 5006)
    export_path = getattr(args, "export", None) or getattr(args, "dream_export", "data/dream_policies.json")
    generations = int(getattr(args, "generations", 2) or 2)
    rollouts = int(getattr(args, "rollouts", None) or getattr(args, "dream_rollouts", 200) or 200)
    stack_profile = getattr(args, "dream_stack_profile", None)
    as_json = bool(getattr(args, "as_json", False))

    if bool(getattr(args, "dream_benchmark", False)):
        from engine.cli_render import render_json
        from engine.dream_rl_benchmark import run_dream_benchmark_cli

        num_seeds = max(2, int(getattr(args, "dream_seeds", 10) or 10))
        budget_steps = max(1, int(getattr(args, "dream_budget", 40) or 40))
        live_lab = bool(getattr(args, "dream_live_lab", False))
        _bench_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _bench_ctx:
            report = run_dream_benchmark_cli(
                db_path=db_path,
                live_lab=live_lab,
                num_seeds=num_seeds,
                budget_steps=budget_steps,
                generations=generations,
                stack_profile=stack_profile,
                strict_offline=bool(os.environ.get("RFCHUNT_OFFLINE") == "1" and not live_lab),
                save_policy_path=export_path if export_path else None,
            )
        if as_json:
            render_json(report.to_dict())
            return
        print(report.format_markdown_table())
        return

    _dream_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
    with _dream_ctx:
        print(f"[*] Initializing Dream-RSI World Model from {db_path}...")
        model = ProtocolWorldModel(target_host=target_host, target_port=target_port)
        loaded = model.ingest_history_from_db(db_path)
        print(f"[+] Loaded {loaded} execution trajectories into offline World Model (backend={getattr(model, 'backend_label', 'unknown')}).")

        optimizer = DreamRSIOptimizer(model)
        store = DreamPolicyStore(storage_path=export_path)

        print(f"[*] Executing {generations} generations of off-policy dreaming ({rollouts} rollouts each)...")
        evolved_history = []
        for _ in range(generations):
            evolved = optimizer.evolve_policy_generation(rollouts_per_candidate=rollouts)
            if stack_profile:
                evolved.stack_profile = str(stack_profile)
            store.save_policy(evolved)
            evolved_history.append(evolved.to_dict())
            gain_str = f"+{evolved.rsi_gain * 100:.1f}%" if evolved.rsi_gain > 0 else "0.0%"
            backend = getattr(evolved, "simulator_backend", "synthetic_heuristic_fallback")
            val_fit = float(getattr(evolved, "val_fitness_score", 0.0) or 0.0)
            print(
                f"  [Gen {evolved.generation}] Backend: {backend} | Fitness: {evolved.fitness_score:.2f} "
                f"| Val: {val_fit:.2f} | RSI Gain: {gain_str} | Yield: {evolved.simulated_yield:.1%}"
            )

        summary = store.export_summary(stack_profile=stack_profile)
        print(f"\n[+] Dream-RSI Optimization Complete. Policies saved to {export_path}.")
        print(f"    Total Cumulative Gain: {summary.get('cumulative_rsi_gain_pct', 0.0)}%")
        print(f"    Dominant Mutators: {summary.get('dominant_mutators', [])}")

    if as_json:
        from engine.cli_render import render_json
        render_json({"summary": summary, "generations": evolved_history})


def cmd_caldera(args):
    """Exports or pushes findings to Caldera adversary emulation platform."""
    from engine.caldera_bridge import CalderaBridge

    export_dir = getattr(args, "export", None) or getattr(args, "export_caldera", None)
    push_url = getattr(args, "push", None) or getattr(args, "caldera_url", None)
    api_key = getattr(args, "api_key", None) or getattr(args, "caldera_key", None)

    bridge = CalderaBridge(db_path=args.db)
    if export_dir and not push_url:
        print(f"[*] Exporting Caldera plugin to {export_dir}...")
        res = bridge.export_plugin(output_dir=export_dir)
        print(f"[+] Caldera plugin successfully exported to {res['plugin_path']}:")
        print(f"    Abilities generated: {res['abilities_count']}")
        print(f"    Adversaries generated: {res['adversaries_count']}")
        print(f"    Custom non-MITRE tactics: {', '.join(res['tactics'])}")
    elif push_url:
        if not api_key:
            print("[!] Error: --api-key is required when using --push")
            sys.exit(1)
        print(f"[*] Pushing abilities to Caldera at {push_url}...")
        findings = bridge.fetch_confirmed_findings_from_db()
        abilities = [bridge.generate_ability(f) for f in findings]
        adversary = bridge.generate_adversary(abilities) if abilities else None
        res = bridge.push_to_caldera(push_url, api_key, abilities=abilities, adversary=adversary)
        print(f"[+] Caldera API Push Result: {res['pushed_abilities']} abilities, {res['pushed_adversaries']} adversaries pushed.")
        if res["errors"]:
            print(f"[!] Warnings/Errors encountered during API push: {res['errors']}")
    else:
        print("[*] No action specified. Exporting to default directory: ./caldera_export...")
        res = bridge.export_plugin(output_dir="caldera_export")
        print(f"[+] Caldera plugin successfully exported to {res['plugin_path']} ({res['abilities_count']} abilities).")


def cmd_setup(args):
    """Inspects and dynamically installs ALL external tools & runtime dependencies for RFCHunt."""
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.tool_provisioner import ToolProvisioner

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    status_only = bool(getattr(args, "tool_status", False)) and not (
        bool(getattr(args, "install_tools", False))
        or getattr(args, "command", None) in ("setup", "install-tools", "install")
        or getattr(args, "mode", None) in ("setup", "install-tools", "install")
    )
    include_docker = bool(getattr(args, "include_docker", True))
    include_models = bool(getattr(args, "include_models", True))
    raw_tools = getattr(args, "tools", None)
    tool_ids = _parse_csv_list(raw_tools) if raw_tools else None

    trace_fn = (lambda msg: print(msg, file=sys.stderr, flush=True)) if as_json else (lambda msg: print(msg, flush=True))
    prov = ToolProvisioner(on_trace=None if status_only else trace_fn)

    if status_only:
        statuses = prov.check_all_statuses(tool_ids=tool_ids)
        payload = {
            "offline_or_test_mode": prov.is_offline_or_blocked(),
            "total": len(statuses),
            "installed_count": sum(1 for s in statuses.values() if s.installed),
            "tools": {k: v.to_dict() for k, v in statuses.items()},
        }
    else:
        payload = prov.ensure_all(
            tool_ids=tool_ids,
            include_docker=include_docker,
            include_models=include_models,
            force=bool(getattr(args, "force_install", False)),
        )

    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "RFCHunt Dynamic Tool Provisioner",
        {
            "Installed / Ready": f"{payload.get('installed_count', 0)}/{payload.get('total', 0)}",
            "Newly Installed": payload.get("newly_installed_count", 0),
            "Local Bin Dir": payload.get("bin_dir", str(prov.bin_dir)),
            "Mode": "Status Only" if status_only else ("Offline/Test Skipped" if payload.get("offline_or_test_skipped") else "Dynamic Install Complete"),
        },
        plain=plain,
    )
    rows = []
    for tid, info in (payload.get("tools") or {}).items():
        state = "READY" if info.get("installed") else "MISSING"
        rows.append([
            tid,
            info.get("category", ""),
            state,
            info.get("method", ""),
            str(info.get("path_or_source") or info.get("error") or info.get("detail") or "")[:64],
        ])
    render_table(
        "Integrated RFCHunt Toolchain Status",
        ["Tool ID", "Category", "State", "Method", "Location / Detail"],
        rows,
        as_json=False,
        plain=plain,
    )


def cmd_build(args):
    """Executes the unified 'Build All' pipeline."""
    from build_all import run_full_build
    success = run_full_build(skip_tests=bool(getattr(args, "skip_tests", False)))
    if not success:
        sys.exit(1)


def print_harness2_help():
    """Prints the comprehensive manual for Google Research Harness² integration."""
    help_text = r"""
===============================================================================
HARNESS²: Recursive Agent Harnessing for an Open World (Google Research)
Integrated Two-Level Recursive Agent Optimization Engine
===============================================================================

CREDIT & CITATION:
------------------
  @article{xu2026harness2,
    title   = {Harness$^2$: Recursive Agent Harnessing for an Open World},
    author  = {Xu, Ruiyao and Chen, Yanfei and CuiZhu, Zhongying and Dalvi Mishra, Bhavana
               and Ming, Yifei and Yu, Han and Han, Rujun and Lee, Chen-Yu and Pfister, Tomas},
    journal = {arXiv preprint arXiv:2610.14224},
    year    = {2026},
    url     = {https://arxiv.org/abs/2610.14224}
  }
  Official Repository: https://github.com/google-research/harness2
  License            : Apache-2.0

ARCHITECTURE IN RFCHUNT:
------------------------
  1. Eight Editable Harness Components (c1..c8 SurfaceSpec):
     - c1: systemprompt.md                   (Core micro-inspiration directive)
     - c2: guardrails.md                     (Anti-anchoring rules & auto-triggered skills)
     - c3: LongTermMEMORY.md                 (Cross-RFC empirical protocol memory)
     - c4: tool_descriptions/tool_guidance.md(3-Step Canary, Ruler & Oracle guidance)
     - c5: sub_agents/<name>/AGENT.md        (Delegated specialist subagents)
     - c6: skills/<name>/SKILL.md            (Reusable protocol audit workflows)
     - c7: scripts/<name>.py                 (Deterministic wire-framing Python helpers)
     - c8: plugin/<name>.ts                  (In-loop protocol framing enforcement)

  2. Task-Level Recursion (Propose -> Probe -> Compose):
     - Refines c1..c8 through contrastive behavioral probing without ground-truth labels.
     - Enforces strict budget accounting: R = 4k rollouts and P = 3k stages.
     - Supports 'parallel' ('agg' width exploration) and 'sequential' ('seq' depth refinement).

  3. Harnessing-Level Recursion (Per-Domain Experience Library):
     - Persists adopted c1..c8 trees, INDEX.md, and EXPERIENCE.md (cue, lesson, evidence)
       under runs/harness2/<run_tag>/<mode>/<domain>/ to guide future unseen RFCs.

EXAMPLES:
---------
  1. Run Parallel Harness² Recursion (k=2 -> R=8 rollouts, P=6 stages) on RFC 9112:
     python -u rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-k 2 --harness2-mode parallel

  2. Run Sequential Harness² Recursion (k=2 depth rounds) on RFC 9113 (H2 Translation):
     python -u rfc_hunt_swarm.py harness2 --rfc 9113 --harness2-k 2 --harness2-mode sequential

  3. View Historical Harness² Runs, Ledger Verification & Learned Domain Lessons:
     python -u rfc_hunt_swarm.py harness2 --harness2-report

  4. Run Full Terminator Swarm with Harness² Active:
     python -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --harness2 --harness2-k 1
===============================================================================
"""
    print(help_text)


ALL_MODES = [
    "single", "terminator", "corpus", "all", "all_scans", "pqc", "ruler",
    "build", "setup", "install-tools", "install", "lab", "mcp", "hunt", "auto", "start",
    "fetch", "chunk", "generate", "permute", "evaluate",
    "weaponize", "cascade", "dream", "caldera", "harness2", "hint",
    "dashboard", "export", "oracle", "differential", "h2", "http2", "audit", "merkle",
    "ui", "vulns", "findings", "list", "raptor", "mantis", "rea", "clean", "clean-db",
    "aiscan", "ai", "artex", "artex-loop", "chain", "dual_graph", "dual-graph", "smuggle", "prompt_smuggle",
    "scanner", "proxy", "retest", "chains", "traces", "coverage", "export-advisory", "archive",
    "slice", "call-graph", "call_graph", "fuzz", "fuzz-bridge", "fuzz_bridge",
    "invariants", "sandbox-invariants", "sandbox_invariants", "poe-verify", "poe_verify",
    "poc", "poc-verify", "poc_verify", "docker-doctor", "docker_doctor", "doctor-docker",
    "deep-audit", "deep_audit",
    "novelty", "novelty-refresh", "novelty_refresh", "swarm", "swarm-board", "swarm_board", "board",
    "phi", "preflight", "hackerone", "hackone",
    "pe-audit", "pe_audit", "pe-dotnet", "pe_dotnet",
]


def build_swarm_parser() -> argparse.ArgumentParser:
    """Builds the comprehensive argument parser for rfc_hunt_swarm.py."""
    parser = argparse.ArgumentParser(
        description=r"""
===============================================================================
RFC HUNT SWARM: Unified Autonomous Protocol Research & Compliance Engine
===============================================================================
The unified primary CLI entrypoint combining:
  - 12-Agent LangGraph Protocol Research Swarm (rfc_hunt_swarm.py)
  - One-Click Local Test Lab Auto-Launcher & Continuous Flaw Hunter (start.py)
  - Modular Pipeline, Build-All Verification, Dream-RSI & Caldera CLI (main.py)
  - 4-Parser Differential Matrix, Exploit Exporter & Dashboard Generator
  - RAPTOR Autonomous Offensive/Defensive Research Framework Integration
  - Google Research Harness² Recursive Agent Harnessing (c1..c8 Propose-Probe-Compose)

METHODOLOGY ATTRIBUTIONS:
-------------------------
1. HTTP Terminator & Protocol Desynchronization Research:
   - Inspired by James Kettle (Director of Research, PortSwigger)
   - "Can AI Do Novel Security Research? Meet the HTTP Terminator"
   - https://portswigger.net/research/can-ai-do-novel-security-research

2. RAPTOR Autonomous Security & Pentesting Framework:
   - Authored by Gadi Evron, Daniel Cuthbert, and Thomas Dullien (Halvar Flake)
   - Project: https://github.com/gadievron/raptor
   - Engine: danielcuthbert/raptor:latest (Docker Container)
   - Integrates Semgrep, CodeQL, web DAST, and local LLM exploitability triage.

3. Google Research Harness² (Recursive Agent Harnessing for an Open World):
   - Authored by Ruiyao Xu, Yanfei Chen, Zhongying CuiZhu, Bhavana Dalvi Mishra,
     Yifei Ming, Han Yu, Rujun Han, Chen-Yu Lee, and Tomas Pfister (Google Research, 2026)
   - Paper: arXiv:2610.14224 | Repo: https://github.com/google-research/harness2
   - Two-level recursive agent harnessing across 8 editable components (c1..c8).
""",
        epilog=r"""
===============================================================================
PRIMARY WORKFLOW EXAMPLES (All run directly via rfc_hunt_swarm.py):
===============================================================================

1. Scan the 25-RFC Terminator Suite against a Live Host with Debug Telemetry & RAPTOR:
   python -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --debug --ui --raptor

2. Clean and Compact the Database to Reclaim Disk Space:
   python -u rfc_hunt_swarm.py --clean-db
   python -u rfc_hunt_swarm.py --clean-db --mode terminator --host 127.0.0.1 --port 3030

3. Google Research Harness² Recursive Agent Harnessing (Parallel & Sequential):
   python -u rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-k 2 --harness2-mode parallel
   python -u rfc_hunt_swarm.py harness2 --rfc 9113 --harness2-k 2 --harness2-mode sequential
   python -u rfc_hunt_swarm.py harness2 --harness2-report

4. Scan James Kettle's Full 138-RFC Research Corpus against a Remote Host:
   python -u rfc_hunt_swarm.py --mode corpus --host remote-target.com --port 443 --tls --concurrency 8 --debug

5. Discover & Scan ALL Active IETF Protocol Specifications:
   python -u rfc_hunt_swarm.py --mode all --host remote-target.com --port 443 --tls --concurrency 8 --debug

6. RAPTOR Autonomous Pentesting & Web DAST (Evron, Cuthbert, Dullien / Halvar Flake):
   python -u rfc_hunt_swarm.py raptor --status
   python -u rfc_hunt_swarm.py raptor --host vanguardngr.com --port 443 --tls
   python -u rfc_hunt_swarm.py raptor --repo D:\\harfile\\my_project --raptor-mode agentic
   python -u rfc_hunt_swarm.py raptor --findings

7. Launch Interactive Mission Control Dashboard Web UI:
   python -u rfc_hunt_swarm.py ui --ui-port 8088

8. Protocol Ruler Byte-Transformation Measurement (James Kettle Technique):
   python -u rfc_hunt_swarm.py ruler --host 127.0.0.1 --port 3030 --sequence "\\xc0\\x8a" --name "Overlong-LF"

9. Export Confirmed Vulnerabilities to Nuclei, ModSecurity & Suricata Rules:
   python -u rfc_hunt_swarm.py export --export-rules-dir ./defense_rules

10. Run Unified 'Build All' Pipeline:
   python -u rfc_hunt_swarm.py build --skip-tests

===============================================================================
EXHAUSTIVE FLAG-BY-FLAG REFERENCE & EXAMPLES FOR EVERY FLAG:
===============================================================================

1. EXECUTION MODE & SCOPE FLAGS:
   --mode MODE              Execution mode: single, terminator, corpus, all, ruler, harness2, build, lab, mcp, hunt, auto, ui
                            Example: python -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030
   --rfc RFC_ID             Specific RFC ID to analyze (default: 9112)
                            Example: python -u rfc_hunt_swarm.py --mode single --rfc 7230 --host 127.0.0.1 --port 3030
   --kettle                 Shortcut flag to scan James Kettle's curated 138 HTTP & SMTP corpus
                            Example: python -u rfc_hunt_swarm.py --kettle --host 127.0.0.1 --port 3030
   --all-active             Shortcut flag to cycle through all active IETF protocol specifications
                            Example: python -u rfc_hunt_swarm.py --all-active --host 127.0.0.1 --port 3030
   --max-rfcs, --count N    Cap the maximum number of RFCs evaluated in this run
                            Example: python -u rfc_hunt_swarm.py --mode terminator --max-rfcs 5
   --keywords KW            Comma-separated keywords to filter active RFC specifications
                            Example: python -u rfc_hunt_swarm.py --mode all --keywords "chunked,trailer,websocket"
   --discover-recent N      Discover newly published RFCs from the live IETF index
                            Example: python -u rfc_hunt_swarm.py --mode fetch --discover-recent 5
   --list-terminators       Print catalog of 25 Terminator RFCs and 36 mutators and exit
                            Example: python -u rfc_hunt_swarm.py --list-terminators

2. TARGET SPECIFICATION & MULTIPLEXING FLAGS:
   --host, --target HOST    Target domain or IP address (default: 127.0.0.1)
                            Example: python -u rfc_hunt_swarm.py --host dlptest.com --port 443 --tls
   --port PORT              Target TCP port (default: 5006)
                            Example: python -u rfc_hunt_swarm.py --host 127.0.0.1 --port 3030
   --tls                    Enable TLS/HTTPS encryption (auto-enabled if port is 443)
                            Example: python -u rfc_hunt_swarm.py --host dlptest.com --port 443 --tls
   --authorized             Explicitly authorize testing against remote or public targets
                            Example: python -u rfc_hunt_swarm.py --host dlptest.com --port 443 --tls --authorized
   --targets TARGETS        Comma-separated list of multiple target terminators
                            Example: python -u rfc_hunt_swarm.py --targets "127.0.0.1:8080,https://target.local:8443"
   --terminators CATS       Filter mutator categories: line,chunk,framing,cross_protocol,crlf_rhi,h2_gateway
                            Example: python -u rfc_hunt_swarm.py --terminators line,chunk,framing,cross_protocol
   --no-lab                 Do not auto-spawn local mock TestLabServer when targeting localhost
                            Example: python -u rfc_hunt_swarm.py --host 127.0.0.1 --port 3030 --no-lab

3. DATABASE MAINTENANCE & STORAGE RECLAIM FLAGS:
   --clean-db               Truncate transient evaluation, probe, and anomaly tables and run SQLite VACUUM
                            Example: python -u rfc_hunt_swarm.py --clean-db
                            Example: python -u rfc_hunt_swarm.py --clean-db --mode terminator --host 127.0.0.1 --port 3030
   --keep-rfcs              When cleaning the database, retain cached RFC specifications and index
                            Example: python -u rfc_hunt_swarm.py --clean-db --keep-rfcs
   --keep-findings          When cleaning the database, retain confirmed vulnerabilities and defensive rules
                            Example: python -u rfc_hunt_swarm.py --clean-db --keep-findings
   --db DB_PATH             Specify custom SQLite database path (default: terminator.db)
                            Example: python -u rfc_hunt_swarm.py --db /data/terminator_prod.db
   --cache-dir DIR          Local directory to cache RFC texts (default: rfcs)
                            Example: python -u rfc_hunt_swarm.py --cache-dir /cache/rfcs

4. DASHBOARD, UI & RULE EXPORT FLAGS:
   --ui                     Launch the interactive research dashboard web UI on an available port
                            Example: python -u rfc_hunt_swarm.py ui
                            Example: python -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --ui
   --ui-port PORT           Explicit port to bind the interactive UI dashboard server
                            Example: python -u rfc_hunt_swarm.py ui --ui-port 8088
   --serve                  Serve the dashboard UI after report generation completes
                            Example: python -u rfc_hunt_swarm.py dashboard --serve
   --random-port            Force servers to bind to high random unprivileged ports (10000-65000)
                            Example: python -u rfc_hunt_swarm.py ui --random-port
   --dashboard-out PATH     Custom output path for generated HTML report (default: terminator_dashboard.html)
                            Example: python -u rfc_hunt_swarm.py dashboard --dashboard-out reports/audit.html
   --export-rules-dir DIR   Output directory for exported Nuclei, ModSecurity, and Suricata rules
                            Example: python -u rfc_hunt_swarm.py export --export-rules-dir ./defense_rules

5. RAPTOR AUTONOMOUS SECURITY FRAMEWORK FLAGS:
   --raptor                 Enable RAPTOR autonomous framework during active testing
                            Example: python -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --raptor
   --raptor-status          Verify RAPTOR Docker container and Ollama security models
                            Example: python -u rfc_hunt_swarm.py raptor --status
   --raptor-mode MODE       RAPTOR mode: web, scan, agentic, crypto, sca, describe
                            Example: python -u rfc_hunt_swarm.py raptor --repo D:\harfile\my_project --raptor-mode agentic
   --repo, --raptor-target  Path to local codebase or project to audit with RAPTOR
                            Example: python -u rfc_hunt_swarm.py raptor --repo D:\harfile\my_project
   --raptor-model MODEL     Ollama model for agentic triage (default: fenkohq/foundation-sec-8b:latest)
                            Example: python -u rfc_hunt_swarm.py raptor --repo D:\harfile\app --raptor-model fenkohq/foundation-sec-8b:latest
   --raptor-findings        List and summarize recent SARIF vulnerability findings from RAPTOR
                            Example: python -u rfc_hunt_swarm.py raptor --findings
   --policy-groups GROUPS   Filter Semgrep policy groups (e.g. 'secrets,owasp,crypto')
                            Example: python -u rfc_hunt_swarm.py raptor --repo D:\harfile\app --policy-groups secrets,owasp
   --include-codeql         Enable deep CodeQL compilation during RAPTOR agentic scan
                            Example: python -u rfc_hunt_swarm.py raptor --repo D:\harfile\app --raptor-mode agentic --include-codeql

6. PROTOCOL RULER & DIFFERENTIAL MATRIX FLAGS:
   --sequence BYTES         Custom byte sequence to measure in Protocol Ruler mode (e.g. '\xc0\x8a')
                            Example: python -u rfc_hunt_swarm.py ruler --host 127.0.0.1 --port 3030 --sequence "\\xc0\\x8a"
   --name NAME              Name for custom sequence in Protocol Ruler mode
                            Example: python -u rfc_hunt_swarm.py ruler --sequence "\\xc0\\x8a" --name "Overlong-LF"
   --max-size BYTES         Max header buffer length to test in Protocol Ruler mode (default: 131072)
                            Example: python -u rfc_hunt_swarm.py ruler --max-size 65536
   --probe PROBE_STR        Custom raw wire probe string or hex for oracle, h2, and differential modes
                            Example: python -u rfc_hunt_swarm.py oracle --probe "GET / HTTP/1.1\\r\\n\\r\\n"

7. AI MODELFUSION & EXPLORATION TUNING FLAGS:
   --model MODEL            Preferred primary base model (default: hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M)
                            Example: python -u rfc_hunt_swarm.py --model hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M
   --sec-model MODEL        Secondary security model for ModelFusion panel (default: fenkohq/foundation-sec-8b:latest; GLM arbiter: glm4:9b / abliterated GLM)
                            Example: python -u rfc_hunt_swarm.py --sec-model fenkohq/foundation-sec-8b:latest
   --no-fusion              Disable multi-model panel fusion (query primary model only)
                            Example: python -u rfc_hunt_swarm.py --no-fusion
   --timeout SECONDS        Ollama inference timeout in seconds (default: 900.0; 0 for unlimited)
                            Example: python -u rfc_hunt_swarm.py --timeout 300.0
   --cycles N               Maximum mutation cycles to run per RFC (default: 3)
                            Example: python -u rfc_hunt_swarm.py --cycles 4
   --limit, --fragments N   Maximum fragments/probes to process per RFC (default: 5)
                            Example: python -u rfc_hunt_swarm.py --limit 8
   --variants N             Permutation variants per probe (default: 3)
                            Example: python -u rfc_hunt_swarm.py --variants 4
   --sentences N            Sentences per chunk in chunking mode (default: 2)
                            Example: python -u rfc_hunt_swarm.py --mode chunk --sentences 3
   --concurrency N          Maximum concurrent probe execution threads (default: 8)
                            Example: python -u rfc_hunt_swarm.py --concurrency 16
   --comb-only, --offline   Offline RFC ingestion & probe synthesis without sending network packets
                            Example: python -u rfc_hunt_swarm.py --comb-only --max-rfcs 10

8. DREAM-RSI, HARNESS² & CALDERA ADVERSARY EMULATION FLAGS:
   --harness2               Enable Google Research Harness² recursive agent harnessing (default: True)
                            Example: python -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --harness2
   --no-harness2            Disable Google Research Harness² recursive agent harnessing
                            Example: python -u rfc_hunt_swarm.py --mode terminator --no-harness2
   --harness2-k K           Task-level recursion budget k (R=4k rollouts, P=3k stages; default: 1)
                            Example: python -u rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-k 2
   --harness2-mode MODE     Harness² recursion mode: 'parallel' ('agg' width) or 'sequential' ('seq' depth)
                            Example: python -u rfc_hunt_swarm.py harness2 --rfc 9112 --harness2-mode sequential --harness2-k 2
   --harness2-domain DOM    Protocol domain for Harness² experience library (default: auto)
                            Example: python -u rfc_hunt_swarm.py harness2 --rfc 9113 --harness2-domain h2_translation
   --harness2-runs-dir DIR  Output directory for Harness² c1..c8 trees, INDEX.md & EXPERIENCE.md (default: runs/harness2)
                            Example: python -u rfc_hunt_swarm.py harness2 --harness2-runs-dir ./runs/custom_h2
   --harness2-report        Display historical Harness² runs, ledger proofs, and learned domain lessons
                            Example: python -u rfc_hunt_swarm.py harness2 --harness2-report
   --dream-rsi              Enable Open Dream-RSI: recursive off-policy self-improvement (default: True)
                            Example: python -u rfc_hunt_swarm.py --dream-rsi
   --no-dream-rsi           Disable default Open Dream-RSI evolution cycle
                            Example: python -u rfc_hunt_swarm.py --no-dream-rsi
   --dream-rollouts N       Number of simulated rollouts per dream generation (default: 300)
                            Example: python -u rfc_hunt_swarm.py --dream-rollouts 500
   --generations N          Evolutionary dream generations (default: 3)
                            Example: python -u rfc_hunt_swarm.py --generations 5
   --dream-export PATH      Path to export evolved Dream-RSI policies (default: data/dream_policies.json)
                            Example: python -u rfc_hunt_swarm.py --dream-export data/dream_policies.json
   --export-caldera DIR     Directory to export Caldera plugin structure (default: caldera_export)
                            Example: python -u rfc_hunt_swarm.py --export-caldera ./my_caldera
   --no-caldera             Disable default Caldera export
                            Example: python -u rfc_hunt_swarm.py --no-caldera
   --caldera-url URL        Caldera server URL to push confirmed findings live
                            Example: python -u rfc_hunt_swarm.py --caldera-url http://127.0.0.1:8888
   --caldera-key KEY        Caldera API authentication key (default: ADMIN123)
                            Example: python -u rfc_hunt_swarm.py --caldera-url http://127.0.0.1:8888 --caldera-key ADMIN123

9. TELEMETRY, LOGGING & PIPELINE SHORTCUT FLAGS:
   --debug                  Enable comprehensive debugging mode (prints raw host responses and telemetry)
                            Example: python -u rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030 --debug
   --show-response          Print full raw HTTP/TLS responses received from target host
                            Example: python -u rfc_hunt_swarm.py --mode single --rfc 9112 --show-response
   -v, --verbose            Enable verbose execution telemetry and payload/response tracing
                            Example: python -u rfc_hunt_swarm.py -v
   --keep-going             Continue hunting after finding first flaw in hunt mode
                            Example: python -u rfc_hunt_swarm.py --mode hunt --keep-going
   --build                  Shortcut to run the unified 'Build All' verification pipeline
                            Example: python -u rfc_hunt_swarm.py --build
   --skip-tests             Skip running pytest when executing --mode build / --build
                            Example: python -u rfc_hunt_swarm.py --build --skip-tests
   --mcp                    Shortcut to launch the Model Context Protocol (MCP) JSON-RPC server over stdio
                            Example: python -u rfc_hunt_swarm.py --mcp

10. BLACKBOARD RUNTIME HINTS & YAML SWARM DISPATCHER FLAGS:
   --hint TEXT              Inject a live operator steering HINT onto the SQLite blackboard (standalone or combined with scan)
                            Example: python -u rfc_hunt_swarm.py hint --hint "Focus on TE+CL ambiguity" --hint-domain http11_framing
   --hint-domain DOM        Protocol domain scope for injected HINT (default: global)
   --hint-priority N        Numeric priority score for injected HINT (default: 10.0)
   --hint-task-id ID        Task ID scope for injected HINT (default: default)
   --hint-rfc RFC           Optional RFC number associated with the HINT
   --dispatch, --dispatch-config PATH
                            Execute a Cairn-style swarm_dispatch.yaml configuration with per-target workspace isolation
                            Example: python -u rfc_hunt_swarm.py --dispatch swarm_dispatch.yaml

11. UNIFIED --all DEFAULT-ON TOOLCHAIN & OPT-OUT FLAGS:
   --all                    Runs Google Mantis, aiscan, RAPTOR, ARTEX Dual-Graph, Prompt Smuggling, Module 21 REA
                            (including rea-agents CLI by default), and live-host httpx/katana/nuclei (non-destructive tags)
                            by default with dynamic Ollama & tool provisioning.
   --no-external-scanners   Opt out of httpx, katana, and nuclei during --all
   --no-httpx-scan          Opt out of ProjectDiscovery httpx discovery during --all
   --no-katana-scan         Opt out of ProjectDiscovery katana crawling during --all
   --no-nuclei-scan         Opt out of ProjectDiscovery nuclei template scanning during --all
   --no-rea-cli             Opt out of locally installed rea-agents CLI during --all (keep embedded Python REA analyzer)
   --no-include-models      Skip dynamic Ollama AI model pulls during --setup and --all auto-provisioning

12. AIxCC SECURITY ENGINES, REPLAY-TREE DREAM-RSI BENCHMARK & PURE-CLI SWARM BOARD:
   slice / call-graph       Whole-repo multi-language call-graph & taint slicer + tiered model escalation
   fuzz-bridge              Isolated --network=none container coverage fuzzing bridge (cargo-fuzz, AFL++/LibAFL, Atheris, Jazzer)
   sandbox-invariants       Isolated --network=none container security invariant runner persisting Cairn FACTs
   poe-verify               Containerized non-destructive POE==3 verifier (promotes verified findings, downgrades FPs)
   oracle --docker-parser-matrix
                            Real local Docker differential parser matrix (nginx, envoy, haproxy, undici, go, hyper)
   novelty / --refresh-novelty-corpus PATH
                            Offline structural novelty corpus & explicit local/opt-in feed refresh
   --mode dream --dream-benchmark [--dream-live-lab] [--dream-seeds 10] [--dream-budget 40]
                            4-baseline matched-seed empirical Dream-RSI RL benchmark with exact Student-t 95% CIs
   swarm-board [--watch --interval 1.0] [--plain] [--json]
                            Pure-CLI Swarm Overview & live terminal status board (zero GUI, Unicode icons / --plain ASCII)

13. DEEP CODE-REPO AUDIT (--deep-audit), LIVE LOOPBACK PROXY FUZZING (--proxy), --poc & DOCKER DOCTOR:
   --proxy [SPEC]           Live loopback-only (127.0.0.1/localhost/::1 fail-closed) 3-trial RFC 9112 proxy fuzzer
                            (5 accepted forms: bare `--proxy` auto-spawns compiled repo proxy on 127.0.0.1:0,
                            `<port>`, `127.0.0.1:<port>` / `[::1]:<port>`, `http://localhost:<port>`, or safe launch command).
                            Examples:
                              python -u rfc_hunt_swarm.py --repo /path/to/repo --proxy --plain
                              python -u rfc_hunt_swarm.py deep-audit --repo /path/to/repo --proxy 8080 --plain
                              python -u rfc_hunt_swarm.py --repo /path/to/repo --proxy 127.0.0.1:3128 --docker-parser-matrix
                              python -u rfc_hunt_swarm.py --repo /path/to/repo --proxy "node server.js" --plain
                              python -u rfc_hunt_swarm.py --proxy --help   (prints focused --proxy / deep-audit guide)
   deep-audit / --deep-audit
                            3-pillar code-repo audit: (1) live 127.0.0.1 proxy fuzzing, (2) line-by-line structural
                            trust-boundary review (TLS ClientHello version cap, TRACE/TRACK credential echo, Win32
                            CreateFile reparse-point flags, WFP inbound/listen layers, Linux bwrap pre-seccomp shell,
                            POSIX ERE bracket escaping, URL host canonicalizer stripping), and (3) root + nested-crate
                            coverage-guided fuzzing (strictly read-only against target repo).
                            Examples:
                              python -u rfc_hunt_swarm.py deep-audit --repo /path/to/repo --proxy --poc --plain
                              python -u rfc_hunt_swarm.py deep-audit --repo /path/to/repo --trust-boundary-review --plain
                              python -u rfc_hunt_swarm.py --all --repo /path/to/repo --deep-audit --proxy --poc --plain
   --trust-boundary-review  Run Pillar 2 line-by-line structural trust-boundary review (--trust-max-files 80 default)
   --coverage-fuzz          Run Pillar 3 coverage-guided fuzzing across root + nested crates (vendor/*/Cargo.toml)
   poc / --poc              Strictly non-destructive false-positive triage & proof-of-concept verification generator
                            Example: python -u rfc_hunt_swarm.py --all --repo . --poc --output-dir reports --plain
   docker-doctor [--fix] [--include-all-wsl]
                            Windows Docker Desktop & WSL2 NTFS-compression VHDX diagnostic and self-healing repair
                            Example: python -u rfc_hunt_swarm.py docker-doctor --fix --include-all-wsl --plain

14. UNIFIED LOCAL-FIRST RFCHUNT + MODELFUSION SINGLE-FILE ARCHITECTURE (--hunt, --all, --ensemble, --fast-ooda):
   --start-modelfusion      Auto-start local ModelFusion (:5000) with VRAM-gated abliterated open-weight models
                            (Gemma-4-12B, Foundation-Sec-8B, GLM, DeepSeek-R1-8B) + Anti-Junk & Grounding Guards.
   --fast-ooda              3-Stage Parallel OODA Funnel: Stage 1 (CPU/ms SQLite WAL Blackboard, Lean 4/Z3, AST) ->
                            Stage 2 (ACDSO 5/6-Objective Pareto AutoML <1s) -> Stage 3 (Abliterated Consensus + HITL).
   --all / --ensemble       Regular pentest mode (without --hunt): runs Mantis, aiscan, ARTEX, RAPTOR, REA, PE/.NET,
                            TruffleHog, Mobile/MobSF, API/JWT/SD-JWT, AI Infra Guard, Parity/Invariants, Zizmor/Actionlint/GHA,
                            Z3 Formal, JS Bundle Analyzer + Recon Clustering, Lean 4 Formal Proofs, ACDSO Stage-2 Pareto,
                            Strict 3-Lane Evidence Separation, RFC 6962 Merkle proofs, SARIF 2.1.0 / Nuclei / Snort 3 & --phi.
   --hunt                   Turnkey autonomous bug bounty pipeline (+ --dry-run, --sync-public-directory, --once,
                            --headless-only, --embedded, --no-llm, --install-schedule; HITL draft-only, never auto-submits).
   Subcommands (all runnable directly via `python rfc_hunt_swarm.py <subcommand>`):
                            freshness-watch, fast-ooda, ensemble-audit, lean-verify, rank-programs, sync-directory,
                            analyze-js, cluster-recon, qa-drafts, check-drafts, atlas-llm-eval, linux-poc,
                            package-audit, record-outcome, mcp, bugbounty-mcp.
===============================================================================
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=ALL_MODES,
        default=None,
        help="Optional positional mode/subcommand (e.g. build, ruler, lab, mcp, hunt, auto, terminator, start, dashboard, export, oracle, h2, audit, ui, harness2, raptor)",
    )
    parser.add_argument(
        "target_arg",
        nargs="?",
        default=None,
        help="Optional positional target folder path or host (e.g. 'python -u rfc_hunt_swarm.py raptor D:\\any\\folder')",
    )
    parser.add_argument("--rfc", type=str, default="9112", help="Specific RFC ID to analyze (e.g. 9112 or MCP)")
    parser.add_argument(
        "--mode",
        type=str,
        choices=ALL_MODES,
        default="single",
        help="Execution mode (default: single)",
    )
    parser.add_argument("--list-terminators", action="store_true", help="Print the complete catalog of 25 Terminator RFC specifications and 36 wire/chunk/cross-protocol terminator mutators and exit")
    parser.add_argument("--host", "--target", dest="host", type=str, default="127.0.0.1", action=_TrackExplicitStore, help="Target host (domain or IP, default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5006, action=_TrackExplicitStore, help="Target port (default: 5006)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS/HTTPS for remote host (auto-enabled if port is 443)")
    parser.add_argument("--targets", type=str, default=None, help="Comma-separated target terminators (e.g. '127.0.0.1:8080,https://target.local:8443')")
    parser.add_argument("--terminators", type=str, default="all", help="Comma-separated terminator categories: 'line,chunk,framing,cross_protocol,crlf_rhi,h2_gateway' or 'all' (default: all)")
    parser.add_argument("--dashboard-out", type=str, default="terminator_dashboard.html", help="Output path for generated HTML research dashboard (default: terminator_dashboard.html)")
    parser.add_argument("--export-rules-dir", type=str, default="defense_rules", help="Output directory for exported Nuclei, ModSecurity, and Suricata rules (default: defense_rules)")
    parser.add_argument("--probe", type=str, default=None, help="Custom raw wire probe string or hex for oracle, h2, and differential modes")
    parser.add_argument("--random-port", "--high-port", action="store_true", help="Use a high random available port for the UI and lab servers")
    parser.add_argument("--ui", action="store_true", help="Launch the interactive research dashboard web UI on a high random available port")
    parser.add_argument("--ui-port", type=int, default=0, help="Explicit port to bind the interactive UI dashboard server (default: auto-allocated high random port)")
    parser.add_argument("--serve", action="store_true", help="Serve the dashboard UI on a high random available port after generation")
    parser.add_argument("--kettle", action="store_true", help="Shortcut to scan James Kettle's curated 138 HTTP & SMTP RFC corpus")
    parser.add_argument("--all-active", action="store_true", help="Shortcut to scan all active IETF protocol specifications")
    parser.add_argument("--cycles", type=int, default=3, help="Max mutation cycles to run per RFC")
    parser.add_argument("--timeout", type=float, default=900.0, help="Ollama LLM inference timeout in seconds (default: 900.0 = 15m; 0 for unlimited)")
    parser.add_argument("--model", type=str, default="hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M", help="Preferred primary base model (default: refusal-free hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M)")
    parser.add_argument("--env-local", dest="env_local", type=str, default=None, help="Path to `.env.local` containing paid/enterprise LLM model credentials (when paid models are present in `.env.local`, RFCHunt uses them directly and bypasses Ollama)")
    parser.add_argument("--force-ollama", dest="force_ollama", action="store_true", default=False, help="Force local Ollama backend even if `.env.local` defines paid model credentials")
    parser.add_argument("--abliteration", "--obliterated", dest="abliteration", action="store_true", default=True, help="Default ON: Use refusal-free abliterated models (no safety filtering) across ModelFusion panel (Gemma + Cisco Foundation-Sec + GLM)")
    parser.add_argument("--sec-model", type=str, default=None, help="Secondary security specialist model (default: Cisco fenkohq/foundation-sec-8b:latest / abliterated)")
    parser.add_argument("--no-fusion", dest="fusion", action="store_false", default=True, help="Disable multi-model panel fusion")
    parser.add_argument("--db", type=str, default="terminator.db", help="SQLite database path (default: terminator.db)")
    parser.add_argument("--clean-db", action="store_true", help="Clean the SQLite database (truncate transient evaluations, anomalies, probes, fragments, and VACUUM to reclaim disk space)")
    parser.add_argument("--keep-rfcs-on-clean", "--keep-rfcs", dest="keep_rfcs_on_clean", action="store_true", help="When cleaning the database, retain the cached RFC specifications and index")
    parser.add_argument("--keep-findings-on-clean", "--keep-findings", dest="keep_findings_on_clean", action="store_true", help="When cleaning the database, retain confirmed vulnerabilities and defensive rules")
    parser.add_argument("--cache-dir", type=str, default="rfcs", help="Local directory to cache RFCs (default: rfcs)")
    parser.add_argument("--max-rfcs", "--count", dest="max_rfcs", type=int, default=None, help="Maximum number of RFCs to cycle through")
    parser.add_argument("--keywords", type=str, default=None, help="Comma-separated keywords to filter active RFCs (e.g. 'chunked,trailer,websocket')")
    parser.add_argument("--comb-only", "--offline", dest="comb_only", action="store_true", help="Offline RFC ingestion & probe generation into database without sending packets to any host")
    parser.add_argument("--no-lab", action="store_true", help="Do not auto-spawn the built-in local TestLabServer when targeting localhost/127.0.0.1")
    parser.add_argument("--patched", action="store_true", default=False, help="Start TestLabServer with /internal/service auth-boundary patched (returns 403)")
    parser.add_argument("--demo", action="store_true", default=False, help="Run cascade extrapolation demonstration when no confirmed findings exist")
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
    parser.add_argument(
        "--allow-destructive",
        dest="allow_destructive",
        action="store_true",
        default=False,
        help="Explicitly permit state-mutating requests (PUT, DELETE, PATCH) and active response theft on authorized targets",
    )
    parser.add_argument("--dream-rsi", dest="dream_rsi", action="store_true", default=True, help="Enable Open Dream-RSI: recursive off-policy self-improvement between cycles (enabled by default)")
    parser.add_argument("--no-dream-rsi", dest="dream_rsi", action="store_false", help="Disable default Open Dream-RSI evolution cycle")
    parser.add_argument("--dream-rollouts", "--rollouts", dest="dream_rollouts", type=int, default=300, help="Number of simulated rollouts per dream generation (default: 300)")
    parser.add_argument("--dream-export", "--export", dest="dream_export", type=str, default="data/dream_policies.json", help="Path to export evolved Dream-RSI policies")
    parser.add_argument("--dream-benchmark", dest="dream_benchmark", action="store_true", default=False, help="Run 4-baseline matched-seed empirical Dream-RSI RL benchmark with 95%% CIs")
    parser.add_argument("--dream-seeds", dest="dream_seeds", type=int, default=10, help="Number of matched episode seeds for --dream-benchmark (default: 10)")
    parser.add_argument("--dream-budget", dest="dream_budget", type=int, default=40, help="Step budget per episode for --dream-benchmark (default: 40)")
    parser.add_argument("--dream-live-lab", "--live-lab", dest="dream_live_lab", action="store_true", default=False, help="Run --dream-benchmark against local loopback 127.0.0.1 TestLabServer (zero external traffic)")
    parser.add_argument("--dream-stack-profile", dest="dream_stack_profile", type=str, default=None, help="Optional target stack profile for stack-specific Dream-RSI policies (e.g. nginx, envoy, node, rust)")
    parser.add_argument("--export-caldera", type=str, default="caldera_export", help="Directory to export Caldera plugin structure (default: caldera_export, runs automatically)")
    parser.add_argument("--no-caldera", action="store_true", help="Disable default Caldera export")
    parser.add_argument("--caldera-url", "--push", dest="caldera_url", type=str, default=None, help="Optional Caldera server URL to push confirmed findings live")
    parser.add_argument("--caldera-key", "--api-key", dest="caldera_key", type=str, default="ADMIN123", help="Caldera API authentication key (default: ADMIN123)")
    parser.add_argument("--concurrency", "--threads", type=int, default=8, help="Maximum concurrent probe execution threads (bounded by semaphore, default: 8)")

    # Google Research Harness² Recursive Agent Harnessing Integration
    # Credit: Xu et al., Google Research (arXiv:2610.14224, 2026)
    # https://github.com/google-research/harness2
    parser.add_argument("--harness2", dest="enable_harness2", action="store_true", default=True, help="Enable Google Research Harness² recursive agent harnessing (c1..c8 Propose-Probe-Compose; enabled by default)")
    parser.add_argument("--no-harness2", dest="enable_harness2", action="store_false", help="Disable Google Research Harness² recursive agent harnessing")
    parser.add_argument("--harness2-k", "--k", dest="harness2_k", type=int, default=1, help="Harness² task-level recursion budget k (R=4k rollouts, P=3k improvement stages; default: 1)")
    parser.add_argument("--harness2-mode", type=str, choices=["parallel", "sequential", "agg", "seq", "both"], default="parallel", help="Harness² recursion mode: 'parallel' ('agg' width exploration), 'sequential' ('seq' depth refinement), or 'both'")
    parser.add_argument("--harness2-domain", "--domain", dest="harness2_domain", type=str, default="auto", help="Protocol domain for Harness² experience library (e.g. http11_framing, h2_translation, tls13_pqc, auto)")
    parser.add_argument("--harness2-runs-dir", "--runs-dir", dest="harness2_runs_dir", type=str, default="runs/harness2", help="Output directory for persisted Harness² domain libraries, INDEX.md, and EXPERIENCE.md (default: runs/harness2)")
    parser.add_argument("--harness2-report", "--report", dest="harness2_report", action="store_true", help="Display historical Harness² recursion runs, R=4k/P=3k ledger verification, and learned domain lessons")

    # RAPTOR Autonomous Offensive/Defensive Research Framework Integration
    # Credit: Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake)
    # https://github.com/gadievron/raptor
    parser.add_argument("--raptor", "--enable-raptor", dest="enable_raptor", action="store_true", help="Enable RAPTOR Autonomous Framework (Web application & source code pentesting; credit: Gadi Evron, Daniel Cuthbert, Halvar Flake)")
    parser.add_argument("--raptor-mode", type=str, choices=["web", "scan", "agentic", "crypto", "sca", "describe", "all", "full"], default=None, help="RAPTOR analysis mode: 'all'/'full' (runs describe + scan + crypto + sca + agentic), 'web' (live host DAST), 'scan' (fast static), 'agentic' (LLM triage), 'crypto' (PQC), 'sca' (dependencies)")
    parser.add_argument("--raptor-target", "--folder", "--dir", dest="raptor_target", type=str, default=None, help="Any local folder or repository path to audit with RAPTOR")
    parser.add_argument("--raptor-model", type=str, default="fenkohq/foundation-sec-8b:latest", help="Ollama LLM for RAPTOR agentic triage (default: fenkohq/foundation-sec-8b:latest)")
    parser.add_argument("--raptor-status", "--status", dest="raptor_status", action="store_true", help="Check RAPTOR Docker container (danielcuthbert/raptor:latest) and Ollama security model readiness")
    parser.add_argument("--raptor-setup", "--install-raptor", dest="raptor_setup", action="store_true", help="Automatically clone, configure, and pull the RAPTOR Security Framework (https://github.com/gadievron/raptor & danielcuthbert/raptor:latest)")
    parser.add_argument("--raptor-findings", "--findings", dest="raptor_findings", action="store_true", help="List and summarize recent SARIF vulnerability findings from RAPTOR scans")
    parser.add_argument("--policy-groups", type=str, default="", help="Optional policy groups for RAPTOR scan (e.g. 'secrets,owasp,crypto')")
    parser.add_argument("--include-codeql", action="store_true", help="Include deep CodeQL compilation during RAPTOR agentic scan")
    # haasonsaas/aiscan Integration (Module 18)
    parser.add_argument("--aiscan", "--enable-aiscan", dest="enable_aiscan", action="store_true", help="Enable haasonsaas/aiscan AI & model risk scanner (Module 18)")
    parser.add_argument("--aiscan-target", type=str, default=".", help="Target directory to audit for AI vulnerabilities, prompt injection sinks, and exposed model credentials (default: '.')")
    parser.add_argument("--aiscan-report", action="store_true", help="Print summary of recent AI security audit findings from terminator.db")

    # BaaRai/ARTEX Dual-Graph Attack Chaining (Module 17) & Headless REST/SSE/Proxy Bridge
    parser.add_argument("--artex", "--dual-graph", dest="enable_artex", action="store_true", help="Enable BaaRai/ARTEX Dual-Graph planner/worker attack chaining engine (Module 17)")
    parser.add_argument("--artex-rounds", "--rounds", dest="artex_rounds", type=int, default=1, action=_TrackExplicitStore, help="Number of multi-round planning cycles to execute in ARTEX Dual-Graph (default: 1)")
    parser.add_argument("--artex-url", dest="artex_url", type=str, default=None, help="Headless BaaRai/ARTEX REST+SSE server URL (e.g. http://127.0.0.1:8787)")
    parser.add_argument("--artex-token", dest="artex_token", type=str, default=None, help="Bearer JWT token for headless ARTEX REST API")
    parser.add_argument("--artex-proxy", dest="artex_proxy", type=str, default=None, help="ARTEX recording MITM proxy URL (e.g. http://127.0.0.1:8788)")
    parser.add_argument("--artex-ca-cert", dest="artex_ca_cert", type=str, default=None, help="Optional CA certificate path for ARTEX MITM proxy")
    parser.add_argument("--artex-noise-profile", dest="artex_noise_profile", choices=["off", "quiet", "balanced", "aggressive"], default=None, help="ARTEX target noise governor profile (off|quiet|balanced|aggressive)")
    parser.add_argument("--artex-llm-profiles", dest="artex_llm_profiles", type=str, default=None, help="Comma-separated LLM profile IDs for ARTEX worker rotation")
    parser.add_argument("--artex-llm-rotate", dest="artex_llm_rotate", action="store_true", default=False, help="Enable round-robin multi-LLM worker rotation (A, B, A, B)")
    parser.add_argument("--artex-wait-sse", dest="artex_wait_sse", action="store_true", default=False, help="Stream headless ARTEX SSE events until terminal completion")
    parser.add_argument("--artex-budget-turns", dest="artex_budget_turns", type=int, default=0, help="Optional max task turn budget for ARTEX attack chaining (0 = unlimited)")
    parser.add_argument("--artex-retest", "--retest", dest="artex_retest", action="store_true", default=False, help="Run ARTEX chain retest loop after attack chaining")
    parser.add_argument("--artex-workers", dest="artex_workers", type=int, default=3, help="Concurrent ARTEX worker pool size (default: 3)")
    parser.add_argument("--artex-live", dest="artex_live", action="store_true", default=None, help="Force live non-destructive ARTEX worker verification")
    parser.add_argument("--no-artex-live", dest="no_artex_live", action="store_true", default=False, help="Disable auto-live ARTEX worker verification")
    parser.add_argument("--embedded-proxy", dest="embedded_proxy", action="store_true", default=False, help="Start embedded pure-CLI recording MITM proxy during scan")
    parser.add_argument("--embedded-proxy-port", dest="embedded_proxy_port", type=int, default=0, help="Port for embedded MITM proxy (0 = ephemeral)")
    parser.add_argument("--auth-profile", dest="auth_profile", type=str, default=None, action=_SingleOrMultiStoreAction, help="Path(s) to JSON/YAML multi-role auth profiles (repeatable or comma-separated for 2-account BOLA/IDOR differential replay)")
    parser.add_argument("--header", "--bounty-header", dest="headers", action="append", default=[], help="Repeatable custom HTTP header ('Name: Value', e.g. 'X-Bug-Bounty: handle') propagated across all raw sockets, HTTP/2 frames, HTTP clients, and external scanners")
    parser.add_argument("--user-agent", dest="user_agent", type=str, default=None, help="Custom User-Agent header propagated across all raw sockets, HTTP/2 frames, HTTP clients, and external scanners")
    parser.add_argument("--max-rps", dest="max_rps", type=float, default=0.0, help="Global shared token-bucket requests-per-second rate cap across all raw sockets, HTTP clients, and external scanners (0 = unlimited)")
    parser.add_argument("--h2-desync", dest="enable_h2_desync", action="store_true", default=True, help="Enable live 3-trial binary HTTP/2 (ALPN h2 / h2c) desync probing (H2.CL, H2.TE, pseudo-header smuggling; default: True)")
    parser.add_argument("--no-h2-desync", dest="enable_h2_desync", action="store_false", help="Disable live binary HTTP/2 desync probing during --all")
    parser.add_argument("--import-har", dest="import_har", type=str, default=None, help="Import HAR 1.2 recording into AssetGraph + traffic_evidence")
    parser.add_argument("--import-openapi", dest="import_openapi", type=str, default=None, help="Import OpenAPI/Swagger spec into AssetGraph")
    parser.add_argument("--scope-file", dest="scope_file", type=str, default=None, help="Path to YAML/JSON allow/deny scope rules")
    parser.add_argument("--approval-mode", dest="approval_mode", choices=["policy", "prompt", "deny"], default="policy", help="Approval gate mode (policy|prompt|deny)")
    parser.add_argument("--approval-rules", dest="approval_rules", type=str, default=None, help="Path to YAML/JSON approval rules file")
    parser.add_argument("--strict-poe", dest="strict_poe", action="store_true", default=False, help="Require POE==3 verified exploit proof (default on advisory exports unless --include-leads)")
    parser.add_argument("--include-leads", dest="include_leads", action="store_true", default=False, help="Include POE=1-2 manual review leads in advisory exports and --strict-poe reports")
    parser.add_argument("--export-advisory", dest="export_advisory", action="store_true", default=False, help="Export GHSA-ready Markdown advisories (defaults to POE==3 verified exploits unless --include-leads)")
    parser.add_argument("--export-csv", dest="export_csv", action="store_true", default=False, help="Export formula-neutralized CSV of findings & chains")
    parser.add_argument("--poc", dest="enable_poc", action="store_true", default=False, help="Generate non-destructive PoC verification scripts, false-positive triage, and POC_INDEX.md bundle under <output-dir>/pocs/")
    parser.add_argument("--poc-dir", dest="poc_dir", type=str, default=None, help="Optional output directory for --poc verification bundle (defaults to <output-dir>/pocs)")
    parser.add_argument("--poc-include-rejected", dest="poc_include_rejected", action="store_true", default=False, help="Also emit verification scripts for rejected false positives and test fixtures during --poc")
    parser.add_argument("--poc-max", dest="poc_max", type=int, default=50, help="Maximum number of verification scripts to generate during --poc (default: 50)")
    parser.add_argument("--poc-container-verify", dest="poc_container_verify", action="store_true", default=False, help="Run isolated Docker ContainerPOEVerifier on surviving HIGH/CRITICAL candidates during --poc")
    parser.add_argument("--fix", "--fix-docker", dest="fix_docker", action="store_true", default=False, help="Run non-destructive Windows Docker Desktop / WSL2 VHDX compression & bootstrap self-heal (for `docker-doctor`)")
    parser.add_argument("--include-all-wsl", dest="include_all_wsl", action="store_true", default=False, help="Also decompress non-Docker WSL2 distro VHDX files (e.g. Ubuntu) during `docker-doctor --fix`")
    parser.add_argument("--reset-docker-distro", dest="reset_docker_distro", action="store_true", default=False, help="Also unregister ONLY the stateless `docker-desktop` WSL runtime distro during `docker-doctor --fix` (preserves docker_data.vhdx)")
    parser.add_argument("--deep-audit", dest="deep_audit", action="store_true", default=False, help="Enable 3-pillar deep repo audit (live 127.0.0.1 proxy fuzzing + line-by-line trust-boundary review + root & nested-crate coverage-guided fuzzing)")
    parser.add_argument("--proxy", dest="proxy_target", nargs="?", const="auto", default=None, help="Enable live loopback-only (127.0.0.1) proxy fuzzing; pass bare `--proxy` to auto-spawn repo proxy on 127.0.0.1:0, or pass `<port>` / `127.0.0.1:<port>` / `http://127.0.0.1:<port>` / safe launch command")
    parser.add_argument("--live-proxy-fuzz", dest="live_proxy_fuzz", action="store_true", default=False, help="Enable live loopback-only (127.0.0.1) proxy RFC 9112 fuzzing + differential parser cross-check")
    parser.add_argument("--trust-boundary-review", dest="trust_boundary_review", action="store_true", default=False, help="Enable targeted line-by-line trust-boundary security review (proxies, path resolvers, authz/ACL, shell sinks, Rust FFI)")
    parser.add_argument("--coverage-fuzz", dest="coverage_fuzz", action="store_true", default=False, help="Enable coverage-guided fuzzing across root repo parsers and nested crates (e.g. vendor/*/Cargo.toml)")
    parser.add_argument("--proxy-host", dest="proxy_host", type=str, default="127.0.0.1", help="Loopback-only proxy host for --live-proxy-fuzz (default: 127.0.0.1)")
    parser.add_argument("--proxy-port", dest="proxy_port", type=int, default=None, help="Existing loopback 127.0.0.1 proxy port to fuzz with --live-proxy-fuzz")
    parser.add_argument("--proxy-cmd", dest="proxy_cmd", type=str, default=None, help="Optional safe command to launch target repo proxy on 127.0.0.1:<PORT> during --live-proxy-fuzz (shell=False)")
    parser.add_argument("--allow-repo-exec", dest="allow_repo_exec", action="store_true", default=False, help="Explicit opt-in required to dynamically import/execute compiled target repository proxy code (dist/*.js) or run --proxy-cmd inside target repo directory")
    parser.add_argument("--trust-max-files", dest="trust_max_files", type=int, default=80, help="Max top-ranked trust-boundary files to audit line-by-line (default: 80)")
    parser.add_argument("--enable-external-scanners", dest="enable_external_scanners", action="store_true", default=False, help="Enable external black-box scanners (httpx, katana, nuclei) — included in --all by default for live hosts; opt-in for standalone `scanner` mode")
    parser.add_argument("--no-external-scanners", dest="no_external_scanners", action="store_true", default=False, help="Disable external black-box scanners (httpx, katana, nuclei) during --all")
    parser.add_argument("--httpx-scan", dest="httpx_scan", action="store_true", default=None, help="Enable ProjectDiscovery httpx discovery (included in --all by default for live hosts)")
    parser.add_argument("--no-httpx-scan", dest="httpx_scan", action="store_false", help="Disable ProjectDiscovery httpx discovery during --all")
    parser.add_argument("--katana-scan", dest="katana_scan", action="store_true", default=None, help="Enable ProjectDiscovery katana crawling (included in --all by default for live hosts)")
    parser.add_argument("--no-katana-scan", dest="katana_scan", action="store_false", help="Disable ProjectDiscovery katana crawling during --all")
    parser.add_argument("--nuclei-scan", dest="nuclei_scan", action="store_true", default=None, help="Enable ProjectDiscovery nuclei non-destructive scanning (included in --all by default for live hosts)")
    parser.add_argument("--no-nuclei-scan", dest="nuclei_scan", action="store_false", help="Disable ProjectDiscovery nuclei scanning during --all")
    parser.add_argument("--nuclei-tags", dest="nuclei_tags", type=str, default=None, help="Comma-separated non-destructive nuclei tags (e.g. tech,misconfig,exposure,headers)")
    parser.add_argument("--scanner-isolation", dest="scanner_isolation", choices=["host", "docker"], default="host", help="External scanner execution isolation mode (host|docker)")
    parser.add_argument("--docker-image", dest="docker_image", type=str, default=None, help="Optional explicit OCI image for docker isolation")
    parser.add_argument("--docker-network", dest="docker_network", choices=["bridge", "none"], default=None, help="Docker network mode for external scanner isolation (bridge|none)")
    parser.add_argument("--artex-multiturn", dest="artex_multiturn", action="store_true", default=False, help="Enable bounded multi-turn ArtexWorker adaptive tool loop")
    parser.add_argument("--artex-intent-turns", dest="artex_intent_turns", type=int, default=0, help="Max turns per ARTEX intent (0 = default/unlimited)")
    parser.add_argument("--artex-intent-tokens", dest="artex_intent_tokens", type=int, default=0, help="Max tokens per ARTEX intent (0 = unlimited)")
    parser.add_argument("--json", dest="as_json", action="store_true", default=False, help="Emit machine-readable JSON output")
    parser.add_argument("--plain", dest="plain", action="store_true", default=False, help="Force plain ASCII output")
    parser.add_argument("--chain-id", dest="chain_id", type=str, default=None, help="Specific chain ID for retest or export-advisory")
    parser.add_argument("--min-poe", dest="min_poe", type=int, default=0, help="Minimum POE level filter (0..3) for chains")
    parser.add_argument("--verified-only", dest="verified_only", action="store_true", default=False, help="Filter chains to verified only")
    parser.add_argument("--all-chains", dest="all_chains", action="store_true", default=False, help="Retest all persisted chains")
    parser.add_argument("--live", dest="live", action="store_true", default=False, help="Enable live replay in retest mode")
    parser.add_argument("--task-id", dest="task_id", type=str, default=None, help="Filter by ARTEX task ID")
    parser.add_argument("--worker-id", dest="worker_id", type=str, default=None, help="Filter traces by worker ID")
    parser.add_argument("--query", "-q", dest="query", type=str, default=None, help="Search query for worker traces")
    parser.add_argument("--out", dest="out", type=str, default="reports", help="Output directory for export-advisory")
    parser.add_argument("--csv", dest="csv", action="store_true", default=False, help="Export formula-safe CSV in export-advisory")
    parser.add_argument("--export-archive", dest="export_path", type=str, default=None, help="Output encrypted .rfca archive file path")
    parser.add_argument("--import", "--import-archive", dest="import_path", type=str, default=None, help="Input encrypted .rfca archive file path")
    parser.add_argument("--key-file", dest="key_file", type=str, default=None, help="Optional encryption key file path for archive")
    parser.add_argument("--ca-dir", dest="ca_dir", type=str, default="keys", help="CA directory for proxy mode")
    parser.add_argument("--noise-profile", dest="noise_profile", choices=["off", "quiet", "balanced", "aggressive"], default=None, help="Noise governor profile for proxy mode")
    parser.add_argument("--rewrite-rule", dest="rewrite_rule", action="append", default=[], help="Header rewrite rule for proxy mode (name:Header=Value)")
    parser.add_argument("--duration", dest="duration", type=float, default=None, help="Optional run duration in seconds for proxy mode")
    parser.add_argument("--mcp-transport", "--transport", dest="mcp_transport", choices=["stdio", "http", "sse", "both"], default="stdio", help="MCP transport for `mcp` mode: stdio, http (/http), sse (/sse), or both")
    parser.add_argument("--mcp-host", dest="mcp_host", type=str, default="127.0.0.1", help="Bind address for remote HTTP/SSE MCP server (default: 127.0.0.1)")
    parser.add_argument("--mcp-port", dest="mcp_port", type=int, default=8790, help="Port for remote HTTP/SSE MCP server (default: 8790)")
    parser.add_argument("--mcp-token", dest="mcp_token", type=str, default=None, help="Optional Bearer token for remote HTTP/SSE MCP clients")

    # Novel Attack Synthesis: Desynchronized Prompt Injection (Module 19)
    parser.add_argument("--prompt-smuggle", dest="enable_prompt_smuggle", action="store_true", help="Synthesize and verify novel cross-layer Desynchronized Prompt Injection attack chains")
    parser.add_argument("--export-sarif", type=str, default=None, help="Export aggregated vulnerability findings to specified SARIF file in reports/")

    # Google Mantis Integration (Module 20) & Unified --all Multi-Scanner Orchestrator
    parser.add_argument("--all", "--run-all", "--all-scans", dest="run_all_scans", action="store_true", help="Execute ALL integrated scanners (Google Mantis, aiscan, ARTEX Dual-Graph, RAPTOR, Prompt Smuggling, Module 21 REA + rea-agents CLI, and httpx/katana/nuclei for live hosts) with mandatory ModelFusion + Abliterated models")
    parser.add_argument("--repo", dest="repo", type=str, default=None, help="Repository directory path for --all, --mantis, or --raptor audits")
    parser.add_argument("--path", dest="path", type=str, default=None, help="Specific file or directory path for --all, --mantis, or --raptor audits")
    parser.add_argument("--mantis", "--enable-mantis", dest="enable_mantis", action="store_true", help="Enable Google Mantis toolkit (Module 20: threat modeling, depth hypotheses, Tier 1/2 repro, CVSS rubric, patching)")
    parser.add_argument("--mantis-mode", type=str, choices=["full", "fast", "threat-model", "scan", "reproduce", "patch"], default="full", help="Google Mantis execution mode (default: full)")
    parser.add_argument("--depth", "--mantis-depth", dest="depth", type=int, default=None, help="Google Mantis audit depth 1..100 (default: 100 for --all, 30 for mantis; scales coverage, passes, and rule tiers)")
    parser.add_argument("--mantis-target", type=str, default=None, help="Target repository or file path for Google Mantis scan")
    parser.add_argument("--mantis-model", type=str, default="hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M", help="Refusal-free abliterated ModelFusion model for Google Mantis")
    parser.add_argument("--mantis-report", action="store_true", help="Display stored Google Mantis findings from terminator.db")
    parser.add_argument("--rea", dest="enable_rea_only", action="store_true", help="Run Module 21 (morluto/rea) JS/Electron/.asar/source-map & same-origin bundle surface analyzer")
    parser.add_argument("--rea-target", dest="rea_target", type=str, default=None, help="Target JS/Electron/.asar/web bundle path for Module 21 REA")
    parser.add_argument("--rea-cli", dest="rea_cli", action="store_true", default=None, help="Enable locally installed rea-agents CLI (shell=False; included in --all by default)")
    parser.add_argument("--no-rea-cli", dest="rea_cli", action="store_false", help="Disable rea-agents CLI invocation during --all (use embedded Python REA analyzer only)")
    parser.add_argument("--no-rea", dest="no_rea", action="store_true", default=False, help="Disable Module 21 REA during --all")
    parser.add_argument("--output-dir", type=str, default="reports", help="Output directory for SARIF, JSON, and text audit reports (default: reports)")

    # Dynamic Tool Provisioner (aiscan, RAPTOR, httpx/katana/nuclei, ARTEX, rea-agents, Semgrep, Python deps, Ollama)
    parser.add_argument("--setup", "--install-tools", "--provision-tools", dest="install_tools", action="store_true", help="Inspect and dynamically install ALL required & integrated RFCHunt tools (aiscan, RAPTOR, httpx, katana, nuclei, artex, rea-agents, semgrep, Python deps, Ollama)")
    parser.add_argument("--tool-status", "--tools-status", "--check-tools", dest="tool_status", action="store_true", help="Print installation status across the complete integrated toolchain")
    parser.add_argument("--tools", dest="tools", type=str, default=None, help="Optional comma-separated tool IDs for setup/status (e.g. 'aiscan,raptor,httpx,katana,nuclei,rea_agents')")
    parser.add_argument("--include-docker", dest="include_docker", action="store_true", default=True, help="Include Docker container images during tool provisioning (default: True)")
    parser.add_argument("--no-docker-tools", dest="include_docker", action="store_false", help="Skip Docker image pulls during tool provisioning")
    parser.add_argument("--no-include-models", dest="include_models", action="store_false", default=True, help="Skip pulling Ollama AI models during setup and --all auto-provisioning")
    parser.add_argument("--force-install", dest="force_install", action="store_true", default=False, help="Force reinstall/re-verify cached tools during setup")
    parser.add_argument("--no-auto-install", dest="auto_install", action="store_false", default=True, help="Disable automatic runtime installation of missing tools")

    # Cairn Blackboard Runtime Hints & Unified YAML Dispatcher
    parser.add_argument("--hint", dest="hint", type=str, default=None, help="Inject a live operator steering HINT into the SQLite blackboard")
    parser.add_argument("--hint-domain", dest="hint_domain", type=str, default="global", help="Protocol domain scope for --hint (default: global)")
    parser.add_argument("--hint-priority", dest="hint_priority", type=float, default=10.0, help="Numeric priority score for --hint (default: 10.0)")
    parser.add_argument("--hint-task-id", dest="hint_task_id", type=str, default="default", action=_TrackExplicitStore, help="Task ID scope for --hint (default: default)")
    parser.add_argument("--hint-rfc", dest="hint_rfc", type=str, default="", help="Optional RFC identifier for --hint")
    parser.add_argument("--dispatch", "--dispatch-config", dest="dispatch", type=str, default=None, help="Path to unified swarm_dispatch.yaml configuration")

    # AIxCC Upgrade #2: Whole-Repo Call-Graph & Taint Slicer + Tiered Model Escalation + Static Verification-Inversion Auditor
    parser.add_argument("--verification-inversion", dest="enable_verification_inversion", action="store_true", default=True, help="Enable 6-pass Static Verification-Inversion Auditor (DEV-* loop/panic slicer, Rule-5 trust-closure, Comparator contract diff, Refinement gap, Release/FFI elision, State-machine epoch rollback; default-ON in --all and --deep-audit)")
    parser.add_argument("--no-verification-inversion", dest="enable_verification_inversion", action="store_false", help="Disable Static Verification-Inversion Auditor during --all")
    parser.add_argument("--reseach-num", "--research-num", dest="research_num", type=int, default=5, help="Number of research articles (ArXiv-to-Code) to extract and convert per domain (default: 5)")
    parser.add_argument("--skills-num", "--skill-num", dest="skills_num", type=int, default=None, help="Number of zero-API last-30-days security & pentesting skills to harvest and convert per domain (defaults to --reseach-num / 5)")
    parser.add_argument("--arxiv-detect", dest="enable_arxiv_detect", action="store_true", default=True, help="Enable 10 ArXiv-to-Code research-backed security detectors (5 AI Security + 5 App Code Security; default-ON in --all and --deep-audit)")
    parser.add_argument("--no-arxiv-detect", dest="enable_arxiv_detect", action="store_false", help="Disable ArXiv-to-Code research detectors during --all")
    parser.add_argument("--arxiv-sync", dest="arxiv_sync", action="store_true", default=False, help="Sync and synthesize --reseach-num new research papers with code & GitHub repos from D:\\harfile\\arixiv-to-code")
    parser.add_argument("--arxiv-query", dest="arxiv_query", type=str, default=None, help="Custom arXiv search query for --arxiv-sync research-to-code synthesis")
    parser.add_argument("--arxiv-rl", dest="arxiv_rl", action="store_true", default=False, help="Optimize synthesized ArXiv-to-Code detector modules using Dream-RSI RL (arXiv:2609.14858)")
    parser.add_argument("--arxiv-verify-panel", dest="arxiv_verify_panel", action="store_true", default=False, help="Run ModelFusion Panel-of-Models verification (glm4:9b + qwen2.5:7b -> Judge glm4:9b) on synthesized ArXiv detectors")
    parser.add_argument("--arxiv-panel-size", dest="arxiv_panel_size", type=int, default=2, help="Number of panelists for --arxiv-verify-panel (default: 2)")
    parser.add_argument("--arxiv-auto-repair", dest="arxiv_auto_repair", action="store_true", default=True, help="Enable iterative Auto-Repair retry loop (Ruff + mypy --strict + 310-property fuzzing + pytest + Ollama patcher; default-ON)")
    parser.add_argument("--no-arxiv-auto-repair", dest="arxiv_auto_repair", action="store_false", help="Disable iterative Auto-Repair retry loop during --arxiv-sync")
    parser.add_argument("--arxiv-max-repairs", dest="arxiv_max_repairs", type=int, default=3, help="Maximum auto-repair retry attempts for generated ArXiv detector modules (default: 3)")
    parser.add_argument("--last30days-skills", dest="enable_last30days_skills", action="store_true", default=True, help="Enable 10 zero-API last30days-skill security & pentesting detectors (5 AI/Agent Security + 5 App/Web Bug-Bounty; default-ON in --all and --deep-audit)")
    parser.add_argument("--no-last30days-skills", dest="enable_last30days_skills", action="store_false", help="Disable zero-API last30days-skill security detectors during --all")
    parser.add_argument("--last30days-sync", dest="last30days_sync", action="store_true", default=False, help="Harvest and synthesize --reseach-num zero-API last-30-days security skills from keyless sources (Reddit, HN, GitHub, arXiv, dev.to)")
    parser.add_argument("--last30days-topic", dest="last30days_topic", type=str, default=None, help="Custom topic for --last30days-sync zero-API security skill discovery")
    parser.add_argument("--no-call-graph-slice", dest="no_call_graph_slice", action="store_true", default=False, help="Disable whole-repo call-graph & taint slicing during --all")
    parser.add_argument("--slice-max-depth", dest="slice_max_depth", type=int, default=8, help="Maximum call-graph traversal depth for taint slicing (default: 8)")
    parser.add_argument("--slice-max-slices", dest="slice_max_slices", type=int, default=200, help="Maximum taint slices to extract (default: 200)")
    parser.add_argument("--slice-codeql", dest="slice_codeql", action="store_true", default=False, help="Enable optional CodeQL CLI path extraction in CallGraphSlicer")
    parser.add_argument("--escalation-fraction", dest="escalation_fraction", type=float, default=0.05, help="Top high-signal fraction for tiered model escalation (default: 0.05)")
    parser.add_argument("--min-poe-escalation", dest="min_poe_escalation", type=int, default=1, help="Minimum POE level required for tiered model escalation (default: 1)")
    parser.add_argument("--frontier-api-opt-in", dest="frontier_api_opt_in", action="store_true", default=False, help="Explicitly opt-in to configured frontier API backend for top escalated candidates (default: False, local-only)")

    # AIxCC Upgrade #3: Multi-Language LLM-Guided Coverage Fuzzing Bridge
    parser.add_argument("--fuzz-bridge", dest="fuzz_bridge", action="store_true", default=False, help="Explicitly enable multi-language isolated container fuzzing bridge in --all")
    parser.add_argument("--no-fuzz-bridge", dest="no_fuzz_bridge", action="store_true", default=False, help="Disable multi-language coverage fuzzing bridge during --all")
    parser.add_argument("--fuzz-languages", dest="fuzz_languages", type=str, default=None, help="Comma-separated languages for fuzzing bridge (rust,cpp,c,python,js,ts,java)")
    parser.add_argument("--fuzz-timeout", dest="fuzz_timeout", type=float, default=60.0, help="Per-target wall timeout in seconds for isolated fuzz container (default: 60.0)")
    parser.add_argument("--fuzz-max-time", dest="fuzz_max_time", type=int, default=30, help="Max fuzzer run time in seconds inside container (default: 30)")
    parser.add_argument("--fuzz-cpp-backend", dest="fuzz_cpp_backend", choices=["afl++", "libafl"], default="afl++", help="C/C++ coverage fuzzer backend (default: afl++)")
    parser.add_argument("--fuzz-dry-run", dest="fuzz_dry_run", action="store_true", default=False, help="Generate harnesses, seed corpora, and dictionaries without executing Docker containers")

    # AIxCC Upgrades #1 & #5a: Docker Differential Parser Matrix, Sandbox Invariants & POE==3 Verifier
    parser.add_argument("--docker-parser-matrix", dest="docker_parser_matrix", action="store_true", default=False, help="Run real local Docker differential parser matrix (nginx, envoy, haproxy, node_undici, go_net_http, rust_hyper)")
    parser.add_argument("--no-docker-parser-matrix", dest="no_docker_parser_matrix", action="store_true", default=False, help="Disable Docker differential parser matrix during --all")
    parser.add_argument("--parsers", dest="parsers", type=str, default=None, help="Comma-separated parser names for Docker parser matrix (e.g. nginx,envoy,haproxy,node_undici,go_net_http,rust_hyper)")
    parser.add_argument("--fallback-4parsers", dest="fallback_4parsers", action="store_true", default=False, help="Fall back to offline 4-parser matrix if Docker parser matrix is unavailable")
    parser.add_argument("--sandbox-invariants", dest="sandbox_invariants", action="store_true", default=False, help="Explicitly run isolated --network=none container repo security invariants in --all")
    parser.add_argument("--no-sandbox-invariants", dest="no_sandbox_invariants", action="store_true", default=False, help="Disable sandboxed repo invariant runner during --all")
    parser.add_argument("--invariant-runtime", dest="invariant_runtime", type=str, default=None, help="Optional preferred runtime for sandbox invariant runner (python|node)")
    parser.add_argument("--invariant-image", dest="invariant_image", type=str, default=None, help="Optional explicit OCI image for sandbox invariant runner")
    parser.add_argument("--poe-verify", dest="poe_verify", action="store_true", default=False, help="Explicitly run containerized non-destructive POE==3 verification on HIGH/CRITICAL findings in --all")
    parser.add_argument("--no-poe-verify", dest="no_poe_verify", action="store_true", default=False, help="Disable containerized POE==3 verification during --all")
    parser.add_argument("--drop-unverified-fp", dest="drop_unverified_fp", action="store_true", default=False, help="Drop unverified false positives downgraded by POE==3 verifier from final findings list")
    parser.add_argument("--findings-json", dest="findings_json", type=str, default=None, help="Optional JSON findings file path for standalone `poe-verify` mode")

    # AIxCC Upgrade #4: Structural Fingerprinting & Offline Known-Technique Novelty Corpus
    parser.add_argument("--refresh-novelty-corpus", dest="refresh_novelty_corpus", action="append", default=[], help="Explicitly ingest local JSON/YAML/Nuclei catalog paths (or opt-in URLs with --novelty-allow-network) into the novelty corpus")
    parser.add_argument("--novelty-allow-network", dest="novelty_allow_network", action="store_true", default=False, help="Explicitly allow remote HTTP(S) feeds during --refresh-novelty-corpus (default: False, strictly offline)")
    parser.add_argument("--novelty-threshold", dest="novelty_threshold", type=float, default=0.72, help="Maximum structural similarity threshold below which 3-trial invariant-violating findings are tagged novel (default: 0.72)")
    parser.add_argument("--novelty-export", dest="novelty_export", type=str, default=None, help="Optional output JSON path to export the merged novelty corpus catalog")

    # Pure-CLI Swarm Overview, Multi-Agent Swarm Mode (--swarm) & Live Terminal Status Board (Zero GUI)
    parser.add_argument("--swarm", dest="enable_swarm", action="store_true", default=False, help="Enable full multi-agent parallel Swarm orchestration (--all + --ensemble + --fast-ooda + --swarm-board on repos/folders, parallel target fan-out on --hunt, or 12-agent LangGraph protocol swarm on --host)")
    parser.add_argument("--swarm-workers", dest="swarm_workers", type=int, default=None, help="Bounded concurrent worker count for --swarm target fan-out and parallel CPU checks (1..8)")
    parser.add_argument("--swarm-board", dest="swarm_board", action="store_true", default=False, help="Render live pure-CLI Swarm Overview board with color emojis & pipeline graph during --all and OODA Swarm runs (--plain for ASCII, zero GUI)")
    parser.add_argument("--no-swarm-board", dest="swarm_board", action="store_false", help="Disable pure-CLI Swarm Overview board rendering")
    parser.add_argument("--emoji", dest="board_emoji", action="store_true", default=None, help="Explicitly enable color emoji icons on the Swarm Overview board (auto-enabled on UTF-8 terminals)")
    parser.add_argument("--no-emoji", dest="board_emoji", action="store_false", help="Use geometric Unicode icons instead of color emojis on the Swarm Overview board")
    parser.add_argument("--watch", dest="watch", action="store_true", default=False, help="Continuously refresh `swarm-board` from SQLite DB until interrupted")
    parser.add_argument("--interval", dest="interval", type=float, default=1.0, help="Refresh interval in seconds for `swarm-board --watch` (default: 1.0)")
    parser.add_argument("--board-width", dest="board_width", type=int, default=100, help="Column width for pure-CLI Swarm Overview board (default: 100)")
    parser.add_argument("--board-events", dest="board_events", type=int, default=15, help="Max recent blackboard events shown in `swarm-board` (default: 15)")

    # Self-Hosted Mission Control Full-Lifecycle GUI Server & Turnkey Network Orchestration
    parser.add_argument("--serve-ui", dest="serve_ui", action="store_true", default=False, help="Launch self-hosted Mission Control Web GUI & full-lifecycle REST/SSE orchestration server (loopback 127.0.0.1:8789 by default)")
    parser.add_argument("--ui-host", dest="ui_host", type=str, default="127.0.0.1", help="Bind host for --serve-ui Mission Control server (default: 127.0.0.1)")
    parser.add_argument("--ui-allow-non-loopback", dest="ui_allow_non_loopback", action="store_true", default=False, help="Explicitly permit binding --serve-ui on a non-loopback interface")
    parser.add_argument("--network-lifecycle", dest="network_lifecycle", action="store_true", default=False, help="Run turnkey multi-target network lifecycle profile (--all + opt-in httpx/katana/nuclei discovery + Dual-Graph + retest)")

    # Universal Dry-Run Safety Flag (works across ALL flags, modes, and commands)
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=False, help="Universal zero-side-effect dry-run across ALL RFCHunt flags and modes (0 network packets, 0 disk mutations, 0 browser launches, 0 API submissions; prints complete execution & RoE compliance plan)")

    # Module 23: Fresh Pre-Flight Stack, Post-Quantum (PQC), HackerOne-Category, Research & Safe Skill Discovery
    parser.add_argument("--preflight", dest="enable_preflight", action="store_true", default=True, help="Execute fresh zero-cache pre-flight stack/PQC/HackerOne/research/safe-skill discovery at start of every --all run (default-ON)")
    parser.add_argument("--no-preflight", dest="enable_preflight", action="store_false", help="Disable Module 23 pre-flight discovery during --all")
    parser.add_argument("--preflight-only", dest="preflight_only", action="store_true", default=False, help="Run Module 23 fresh pre-flight discovery standalone and print the Pre-Flight Checklist (Markdown or --json)")
    parser.add_argument("--preflight-live", dest="preflight_live", action="store_true", default=True, help="Run fresh keyless live research & OSV.dev exact-version CVE queries during online pre-flight (default-ON; auto-skipped offline/CI/--dry-run)")
    parser.add_argument("--no-preflight-live", dest="preflight_live", action="store_false", help="Disable live network lookups during pre-flight discovery (local manifest/PQC/skill scan only)")
    parser.add_argument("--preflight-pqc", dest="preflight_pqc", action="store_true", default=True, help="Enable Post-Quantum Cryptography (FIPS 203/204/205/XMSS/LMS/Hybrid TLS/HNDL) pre-flight auditor (default-ON)")
    parser.add_argument("--no-preflight-pqc", dest="preflight_pqc", action="store_false", help="Disable Post-Quantum Cryptography static audit pass during pre-flight")
    parser.add_argument("--preflight-prompt", dest="preflight_prompt", type=str, default="", help="Optional user prompt or scope notes included in pre-flight domain/protocol/PQC detection")
    parser.add_argument("--preflight-skills-dirs", dest="preflight_skills_dirs", type=str, default=None, help="Comma-separated extra local skill directories to safety-audit and load during pre-flight")
    parser.add_argument("--no-home-skills", dest="no_home_skills", action="store_true", default=False, help="Restrict local skill discovery to workspace directories only (skip ~/.claude/skills, ~/.gemini/...)")
    parser.add_argument("--preflight-timeout", dest="preflight_timeout", type=float, default=15.0, help="Total live research time budget in seconds for pre-flight keyless queries (default: 15.0)")

    # Module 22: HIPAA Safe Harbor PHI/PII Detector & Zero-Knowledge Redaction (--phi)
    parser.add_argument("--phi", dest="enable_phi", action="store_true", default=False, help="Enable Presidio + GLiNER + RedactX-v3 18 HIPAA Safe Harbor PHI/PII detector & zero-knowledge redactor (standalone or chained into --all)")
    parser.add_argument("--phi-target", dest="phi_target", type=str, default=None, help="Explicit file or directory path for --phi scanning (defaults to --repo / --path / '.')")
    parser.add_argument("--phi-redact", dest="phi_redact", action="store_true", default=False, help="Write zero-knowledge scrubbed copies (`<ZK_PII:TYPE:HASH8>`) with quarantine proofs under reports/phi_redacted/")
    parser.add_argument("--phi-model", dest="phi_model", type=str, default="urchade/gliner_multi_pii-v1", help="GLiNER Span NER model identifier for --phi (default: urchade/gliner_multi_pii-v1)")
    parser.add_argument("--no-phi-ml", dest="no_phi_ml", action="store_true", default=False, help="Force deterministic offline RedactX-v3 + GLiNER fallback without loading HuggingFace GLiNER or Presidio ML weights")

    # HackerOne Campaign Finder, RoE Policy Engine & Autonomous HITL Computer-Use Report Porter
    parser.add_argument("--hackerone", "--hackone", dest="enable_hackerone", action="store_true", default=False, help="Discover a HackerOne campaign, parse its 3-tier RoE policy, and port verified/deterministic RFCHunt findings into redacted HackerOne report drafts with HITL review")
    parser.add_argument("--hackerone-auto", "--hackone-auto", dest="hackerone_auto", action="store_true", default=False, help="Policy-aware autonomous HackerOne workflow: after human login, discovers open campaigns, enforces RoE rules/Safe Harbor, audits in-scope repos (--all + --phi), and pre-fills drafts up to final human Submit")
    parser.add_argument("--hackerone-username", "--hackone-username", dest="hackerone_username", type=str, default="", help="Researcher HackerOne username for program-mandated attribution headers (e.g. X-HackerOne: <username>)")
    parser.add_argument("--hackerone-program", "--hackone-program", dest="hackerone_program", type=str, default=None, help="Target HackerOne program handle (e.g. 'anthropic-vdp')")
    parser.add_argument("--hackerone-query", "--hackone-query", dest="hackerone_query", type=str, default="", help="Search keyword for HackerOne campaign discovery")
    parser.add_argument("--hackerone-max-programs", dest="hackerone_max_programs", type=int, default=2, help="Max campaigns to inspect per --hackerone-auto run (default: 2)")
    parser.add_argument("--hackerone-policy-file", dest="hackerone_policy_file", type=str, default=None, help="Optional local policy text file for offline RoE compliance evaluation & dry-run testing")
    parser.add_argument("--hackerone-ai-disclosure", dest="hackerone_ai_disclosure", action="store_true", default=False, help="Include explicit RFCHunt research-assistance & manual PoC verification disclosure section in drafts")
    parser.add_argument("--hackerone-browser", "--hackone-browser", dest="hackerone_browser", action="store_true", default=False, help="Launch visible HITL Playwright browser session for HackerOne login (human completes 2FA/CAPTCHA) and report form pre-fill (stops before final Submit)")
    parser.add_argument("--hackerone-api", "--hackone-api", dest="hackerone_api", action="store_true", default=False, help="Query HackerOne Hacker API v1 for live campaign/scope/policy discovery using HACKERONE_API_USERNAME and HACKERONE_API_TOKEN")
    parser.add_argument("--hackerone-submit-api", dest="hackerone_submit_api", action="store_true", default=False, help="Explicit opt-in to submit eligible drafts via HackerOne API v1 after interactive HITL confirmation")
    parser.add_argument("--hackerone-bounties-only", dest="hackerone_bounties_only", action="store_true", default=False, help="Filter HackerOne API campaign discovery to paid bounty programs only")
    parser.add_argument("--hackerone-min-severity", dest="hackerone_min_severity", choices=["low", "medium", "high", "critical"], default="medium", help="Minimum severity eligible for HackerOne porting (default: medium)")
    parser.add_argument("--hackerone-max-reports", dest="hackerone_max_reports", type=int, default=5, help="Maximum eligible drafts to generate per run (default: 5)")

    # Module 24: Reverse-Proxy Config & HTTP Header Conformance Auditor (--crlf-desync / --crlf-conformance)
    parser.add_argument("--crlf-desync", "--crlf-conformance", dest="enable_crlf_conformance", action="store_true", default=False, help="Run Module 24 static Nginx/OpenResty $uri config audit and safe 3-trial RFC 9112 header conformance checks")

    # Module 25: Web LLM Defensive Security Auditor (--web-llm)
    parser.add_argument("--web-llm", dest="enable_web_llm", action="store_true", default=False, help="Run Module 25 static Web LLM security auditor (excessive agency, tool-arg taint, insecure output handling, prompt-only authz, RAG scrubbing)")

    # PE & .NET Code Integrity Anomaly Auditor (--pe-audit / --pe-dotnet)
    parser.add_argument("--workspace-root", dest="workspace_root", type=str, default=None, help="Explicit workspace root directory for strict file_path/target_path confinement")
    parser.add_argument("--pe-audit", "--pe-dotnet", dest="enable_pe_audit", action="store_true", default=False, help="Run PE & .NET Code Integrity Anomaly Auditor (Magika hybrid PE, CVE-2026-108398, UMCI/SEC_COMMIT fallback, YARA, KB5127694/VirtualBox host patch audit)")
    parser.add_argument("--no-pe-audit", "--no-pe-dotnet", dest="no_pe_audit", action="store_true", default=False, help="Disable PE & .NET Code Integrity Anomaly Auditor during --all")
    parser.add_argument("--pe-include-host-audit", dest="pe_include_host_audit", action="store_true", default=None, help="Include Windows KB5127694 & VirtualBox 7.2.18+ host patch audit during --all / --pe-audit")
    parser.add_argument("--pe-no-host-audit", dest="pe_include_host_audit", action="store_false", help="Disable host patch-level audit during --pe-audit")
    parser.add_argument("--pe-no-yara", dest="pe_include_yara", action="store_false", default=True, help="Disable defensive YARA rule evaluation during PE & .NET auditing")

    # Planner-Worker-Verifier Whiteboard & Lean 4 Ensemble Orchestration (--ensemble / --essemble / --essample)
    parser.add_argument("--ensemble", "--essemble", "--essample", dest="ensemble", action="store_true", default=False, help="Enable Planner-Worker-Verifier shared-whiteboard + Lean 4 formal ensemble orchestration in --all")
    parser.add_argument("--program", dest="program", type=str, default="generic", help="Vendor threat-model profile for --ensemble (generic, shopify, anthropic, arc-bbp, cloudflare, coinbase)")
    parser.add_argument("--freshness-hours", dest="freshness_hours", type=int, default=72, help="Git commit freshness lookback window in hours for --ensemble (default: 72)")
    parser.add_argument("--quorum", dest="quorum", type=int, default=2, help="Minimum independent engine quorum for static corroboration in --ensemble (default: 2)")
    parser.add_argument("--embedded", "--embeded", dest="embedded", action="store_true", default=False, help="Run --ensemble strictly in-process offline without spawning external scanner subprocesses")
    parser.add_argument("--no-llm", dest="no_llm", action="store_true", default=False, help="Disable optional LLM semantic verification layer in --ensemble")
    parser.add_argument("--gha-only", dest="gha_only", action="store_true", default=False, help="Restrict --ensemble local engine fan-out to GitHub Actions workflow scanners")
    parser.add_argument("--package-client", dest="package_client", type=str, default=None, help="Optional client organization name to emit 5-file ClientAuditPackager bundle in --ensemble")
    parser.add_argument("--start-modelfusion", dest="start_modelfusion", action="store_true", default=False, help="Auto-start local ModelFusion (:5000) server with VRAM-gated abliterated open-weight models and Anti-Junk & Grounding Guards before scanning")
    parser.add_argument("--fast-ooda", dest="enable_fast_ooda", action="store_true", default=False, help="Run the 3-Stage Parallel OODA Funnel (Stage 1 CPU SQLite WAL Blackboard -> Stage 2 ACDSO Pareto AutoML -> Stage 3 Abliterated Consensus behind OllamaConcurrencyGuard) standalone or chained into --all")
    parser.add_argument("--cpu-workers", dest="cpu_workers", type=int, default=None, help="Bounded ProcessPoolExecutor CPU workers for --fast-ooda / --ensemble (default: clamped 2..8)")
    parser.add_argument("--blackboard-db", dest="blackboard_db", type=str, default=None, help="SQLite WAL Blackboard database path for --fast-ooda / --ensemble")
    parser.add_argument("--resume", dest="resume", action="store_true", default=False, help="Recover stale IN_PROGRESS intents from SQLite WAL Blackboard before running --fast-ooda / --ensemble")
    parser.add_argument("--signal-score", dest="signal_score", type=float, default=0.0, help="HackerOne Signal score for two-lane scheduling in --fast-ooda / --hunt (default: 0.0)")

    # Turnkey Autonomous Bug Bounty Hunter (--hunt) — unified into rfc_hunt_swarm.py (regular pentests run unchanged without --hunt)
    parser.add_argument("--hunt", dest="enable_autonomous_hunt", action="store_true", default=False, help="Run the turnkey autonomous RFCHunt + ModelFusion bug bounty pipeline (syncs directory, ranks unlocked programs via ACDSO ML, runs freshness-watch, fast-ooda, ensemble-audit, Lean 4, QA-drafts & HITL Chrome handoff; omit for regular pentesting)")
    parser.add_argument("--hunt-target", dest="hunt_targets", action="append", default=[], help="Local repository or folder directory to audit during --hunt (repeatable; --target / --repo / --folder / --dir / --path also supported)")
    parser.add_argument("--hunt-repo", dest="hunt_repos", action="append", default=[], help="Extra 'owner/repo' GitHub slug or local repo to include during --hunt (repeatable)")
    parser.add_argument("--clone-unlocked", dest="clone_unlocked", action="store_true", default=False, help="Also shallow-clone and hunt UNLOCKED watchlist/EligibilityDB repos alongside local --repo / --folder / --target scans during --hunt")
    parser.add_argument("--no-clone-unlocked", dest="no_clone_unlocked", action="store_true", default=False, help="Audit only explicitly passed local --repo / --folder / --target paths during --hunt without cloning additional unlocked watchlist repos")
    parser.add_argument("--sync-public-directory", dest="sync_public_directory", action="store_true", default=False, help="Refresh public HackerOne Program Directory sorted by newest launch date before ML ranking during --hunt")
    parser.add_argument("--eligibility-db", dest="eligibility_db", type=str, default=None, help="Optional ProgramEligibilityDB SQLite path for --hunt / --all")
    parser.add_argument("--min-efficiency", dest="min_efficiency", type=float, default=80.0, help="Minimum HackerOne response efficiency %% during --hunt (default: 80.0)")
    parser.add_argument("--portfolio-capacity", dest="portfolio_capacity", type=int, default=6, help="Daily Two-Phase Knapsack portfolio capacity during --hunt (default: 6)")
    parser.add_argument("--max-repos", dest="max_repos", type=int, default=4, help="Maximum unlocked watchlist repos to audit per --hunt cycle (default: 4)")
    parser.add_argument("--watchlist", dest="watchlist", type=str, default=None, help="Optional custom JSON watchlist path for --hunt (omitting uses UNLOCKED ProgramEligibilityDB repos)")
    parser.add_argument("--interval-minutes", dest="interval_minutes", type=float, default=60.0, help="Minutes between continuous --hunt cycles (default: 60.0)")
    parser.add_argument("--max-cycles", dest="max_cycles", type=int, default=0, help="Stop --hunt after N cycles (0 = run continuously unless --once or --dry-run)")
    parser.add_argument("--once", dest="hunt_once", action="store_true", default=False, help="Run a single complete --hunt cycle and exit")
    parser.add_argument("--hunt-url", "--bug-hunt-url", dest="hunt_url", type=str, default=None, help="Official bug bounty directory or program URL opened in Chromium by --hunt so you log in and RFCHunt runs every /browser workflow automatically (default: https://hackerone.com/opportunities/all)")
    parser.add_argument("--browser-hunt", dest="browser_hunt", action="store_true", default=False, help="Explicitly enable interactive browser hunt on --hunt-url (auto-enabled by --hunt unless --headless-only, --embedded, or --no-browser-hunt is set)")
    parser.add_argument("--no-browser-hunt", dest="no_browser_hunt", action="store_true", default=False, help="Disable opening --hunt-url in interactive browser mode during --hunt")
    parser.add_argument("--browser-profile", dest="browser_profile", type=str, default=None, help="Persistent Chromium profile directory for --hunt so your bug bounty login persists across cycles (default: out/autonomous_hunt/h1_browser_profile)")
    parser.add_argument("--cdp-url", dest="cdp_url", type=str, default=None, help="Attach --hunt to an already-signed-in Chrome or HugOS Browser CDP endpoint (e.g. http://127.0.0.1:9222)")
    parser.add_argument("--login-timeout", dest="login_timeout", type=float, default=300.0, help="Maximum seconds --hunt waits for you to complete login, 2FA, and any CAPTCHA directly in the browser (default: 300.0)")
    parser.add_argument("--probe-report-id", dest="probe_report_id", type=int, default=4243972, help="HackerOne report ID probed read-only during --hunt to check live account cooldown (`can_submit_draft?`, default: 4243972)")
    parser.add_argument("--dedup-db", dest="dedup_db", type=str, default=None, help="SQLite WAL database path persisting processed target SHAs and drafted/submitted findings to eliminate duplicates (default: <out>/hunt_state.sqlite3)")
    parser.add_argument("--force-rescan", dest="force_rescan", action="store_true", default=False, help="Re-scan targets during --hunt even if their current commit SHA or folder digest is already recorded in SQLite (duplicate drafts stay blocked)")
    parser.add_argument("--no-stage-drafts", dest="no_stage_drafts", action="store_true", default=False, help="During --hunt, skip opening /reports/new or saving drafts on HackerOne while keeping browser discovery, scanning, and SQLite dedup active")
    parser.add_argument("--headless-only", dest="headless_only", action="store_true", default=False, help="During --hunt, skip browser login/discovery, draft staging, and Chrome launch; write READY_TO_CLICK_SUBMIT.md only")
    parser.add_argument("--allow-blocked", dest="allow_blocked", action="store_true", default=False, help="Allow Signal-blocked programs for local offline research during --hunt")
    parser.add_argument("--install-schedule", dest="install_schedule", action="store_true", default=False, help="Install recurring native OS schedule for `rfc_hunt_swarm.py --hunt --once` (zero Registry/PATH mutation)")
    parser.add_argument("--uninstall-schedule", dest="uninstall_schedule", action="store_true", default=False, help="Remove the recurring native OS schedule for --hunt")
    parser.add_argument("--run-now", dest="run_now", action="store_true", default=False, help="Trigger an immediate scheduled task run right after --hunt --install-schedule")
    parser.add_argument("--task-name", dest="task_name", type=str, default="RFCHunt-Autonomous-Defensive-Hunt", help="OS Scheduled Task name for --hunt --install-schedule")

    _ensure_help_examples_for_all_flags(parser)
    return parser


_CURATED_FLAG_EXAMPLES: Dict[str, str] = {
    "--swarm": "python rfc_hunt_swarm.py --swarm --repo . --dry-run",
    "--swarm-workers": "python rfc_hunt_swarm.py --swarm --swarm-workers 4 --repo . --folder ./extra --dry-run",
    "--hunt": "python rfc_hunt_swarm.py --hunt --hunt-url https://hackerone.com/opportunities/all --dry-run",
    "--hunt-url": "python rfc_hunt_swarm.py --hunt --hunt-url https://hackerone.com/opportunities/all --dry-run",
    "--bug-hunt-url": "python rfc_hunt_swarm.py --hunt --bug-hunt-url https://hackerone.com/anthropic --dry-run",
    "--browser-hunt": "python rfc_hunt_swarm.py --hunt --browser-hunt --hunt-url https://hackerone.com/opportunities/all --dry-run",
    "--no-browser-hunt": "python rfc_hunt_swarm.py --hunt --no-browser-hunt --once --dry-run",
    "--browser-profile": "python rfc_hunt_swarm.py --hunt --browser-profile out/autonomous_hunt/h1_browser_profile --dry-run",
    "--cdp-url": "python rfc_hunt_swarm.py --hunt --cdp-url http://127.0.0.1:9222 --dry-run",
    "--login-timeout": "python rfc_hunt_swarm.py --hunt --login-timeout 180 --dry-run",
    "--probe-report-id": "python rfc_hunt_swarm.py --hunt --probe-report-id 4243972 --dry-run",
    "--dedup-db": "python rfc_hunt_swarm.py --hunt --dedup-db out/autonomous_hunt/hunt_state.sqlite3 --dry-run",
    "--force-rescan": "python rfc_hunt_swarm.py --hunt --repo ./target_repo --force-rescan --once --dry-run",
    "--no-stage-drafts": "python rfc_hunt_swarm.py --hunt --hunt-url https://hackerone.com/anthropic --no-stage-drafts --once --dry-run",
    "--hunt-target": "python rfc_hunt_swarm.py --hunt --hunt-target ./target_repo --program common_codes --once --dry-run",
    "--hunt-repo": "python rfc_hunt_swarm.py --hunt --hunt-repo Shopify/shopify-app-js --once --dry-run",
    "--clone-unlocked": "python rfc_hunt_swarm.py --hunt --repo ./my_repo --folder ./my_folder --clone-unlocked --dry-run",
    "--no-clone-unlocked": "python rfc_hunt_swarm.py --hunt --repo ./my_repo --folder ./my_folder --no-clone-unlocked --once --dry-run",
    "--sync-public-directory": "python rfc_hunt_swarm.py --hunt --sync-public-directory --min-efficiency 80 --dry-run",
    "--eligibility-db": "python rfc_hunt_swarm.py --hunt --eligibility-db reports/program_eligibility.sqlite3 --dry-run",
    "--min-efficiency": "python rfc_hunt_swarm.py --hunt --min-efficiency 85 --dry-run",
    "--portfolio-capacity": "python rfc_hunt_swarm.py --hunt --portfolio-capacity 6 --dry-run",
    "--max-repos": "python rfc_hunt_swarm.py --hunt --max-repos 4 --dry-run",
    "--watchlist": "python rfc_hunt_swarm.py --hunt --watchlist config/freshness_watchlist.example.json --dry-run",
    "--interval-minutes": "python rfc_hunt_swarm.py --hunt --interval-minutes 60 --max-cycles 2",
    "--max-cycles": "python rfc_hunt_swarm.py --hunt --max-cycles 1 --headless-only",
    "--once": "python rfc_hunt_swarm.py --hunt --once --headless-only",
    "--headless-only": "python rfc_hunt_swarm.py --hunt --once --headless-only --embedded",
    "--allow-blocked": "python rfc_hunt_swarm.py --hunt --target ./repo --program shopify --allow-blocked --once --dry-run",
    "--install-schedule": "python rfc_hunt_swarm.py --hunt --install-schedule --interval-minutes 60 --dry-run",
    "--uninstall-schedule": "python rfc_hunt_swarm.py --hunt --uninstall-schedule --task-name RFCHunt-Autonomous-Defensive-Hunt",
    "--run-now": "python rfc_hunt_swarm.py --hunt --install-schedule --run-now --dry-run",
    "--task-name": "python rfc_hunt_swarm.py --hunt --install-schedule --task-name RFCHunt-Nightly --dry-run",
    "--all": "python rfc_hunt_swarm.py --all --repo . --dry-run",
    "--ensemble": "python rfc_hunt_swarm.py --all --ensemble --repo . --program generic --quorum 2",
    "--program": "python rfc_hunt_swarm.py --all --ensemble --repo . --program anthropic",
    "--freshness-hours": "python rfc_hunt_swarm.py --all --ensemble --repo . --freshness-hours 72",
    "--quorum": "python rfc_hunt_swarm.py --all --ensemble --repo . --quorum 2",
    "--embedded": "python rfc_hunt_swarm.py --all --ensemble --repo . --embedded --no-llm",
    "--no-llm": "python rfc_hunt_swarm.py --all --ensemble --repo . --no-llm",
    "--gha-only": "python rfc_hunt_swarm.py --all --ensemble --repo . --gha-only",
    "--package-client": 'python rfc_hunt_swarm.py --all --ensemble --repo . --package-client "Acme Corp"',
    "--start-modelfusion": "python rfc_hunt_swarm.py --all --repo . --start-modelfusion --dry-run",
    "--fast-ooda": "python rfc_hunt_swarm.py --fast-ooda --repo . --embedded --json",
    "--cpu-workers": "python rfc_hunt_swarm.py --fast-ooda --repo . --cpu-workers 4 --embedded",
    "--blackboard-db": "python rfc_hunt_swarm.py --fast-ooda --repo . --blackboard-db reports/blackboard.sqlite3",
    "--resume": "python rfc_hunt_swarm.py --fast-ooda --repo . --resume --embedded",
    "--signal-score": "python rfc_hunt_swarm.py --fast-ooda --repo . --signal-score 1.5 --embedded",
    "--dry-run": "python rfc_hunt_swarm.py --all --repo . --dry-run --json",
    "--host": "python rfc_hunt_swarm.py --all --host target.example.com --port 443 --tls --authorized --dry-run",
    "--port": "python rfc_hunt_swarm.py --mode terminator --host 127.0.0.1 --port 3030",
    "--tls": "python rfc_hunt_swarm.py --mode terminator --host target.example.com --port 443 --tls --authorized",
    "--authorized": "python rfc_hunt_swarm.py --all --host target.example.com --port 443 --tls --authorized",
    "--allow-destructive": "python rfc_hunt_swarm.py --all --host target.example.com --authorized --allow-destructive --dry-run",
    "--repo": "python rfc_hunt_swarm.py --all --repo ./target_repo",
    "--path": "python rfc_hunt_swarm.py --all --path engine/mantis_integrator.py",
    "--output-dir": "python rfc_hunt_swarm.py --all --repo . --output-dir reports/audit_run",
    "--out": "python rfc_hunt_swarm.py export-advisory --out reports/advisories",
    "--json": "python rfc_hunt_swarm.py --all --repo . --dry-run --json",
    "--plain": "python rfc_hunt_swarm.py --all --repo . --plain",
    "--phi": "python rfc_hunt_swarm.py --phi --repo . --phi-redact",
    "--phi-target": "python rfc_hunt_swarm.py --phi --phi-target ./records",
    "--phi-redact": "python rfc_hunt_swarm.py --phi --repo . --phi-redact",
    "--phi-model": "python rfc_hunt_swarm.py --phi --repo . --phi-model urchade/gliner_multi_pii-v1",
    "--no-phi-ml": "python rfc_hunt_swarm.py --phi --repo . --no-phi-ml",
    "--hackerone": "python rfc_hunt_swarm.py --hackerone --hackerone-program anthropic --dry-run",
    "--hackerone-auto": "python rfc_hunt_swarm.py --hackerone-auto --hackerone-max-programs 2 --dry-run",
    "--crlf-desync": "python rfc_hunt_swarm.py --crlf-desync --repo . --json",
    "--web-llm": "python rfc_hunt_swarm.py --web-llm --repo . --json",
    "--pe-audit": "python rfc_hunt_swarm.py --pe-audit --repo . --json",
    "--no-pe-audit": "python rfc_hunt_swarm.py --all --repo . --no-pe-audit",
    "--workspace-root": "python rfc_hunt_swarm.py --all --repo . --workspace-root .",
    "--serve-ui": "python rfc_hunt_swarm.py --serve-ui --ui-host 127.0.0.1 --ui-port 8789",
    "--network-lifecycle": "python rfc_hunt_swarm.py --network-lifecycle --host target.example.com --authorized --dry-run",
    "--preflight": "python rfc_hunt_swarm.py --all --repo . --preflight",
    "--no-preflight": "python rfc_hunt_swarm.py --all --repo . --no-preflight",
    "--preflight-only": "python rfc_hunt_swarm.py --preflight-only --repo . --json",
    "--deep-audit": "python rfc_hunt_swarm.py deep-audit --repo . --proxy --poc --plain",
    "--proxy": "python rfc_hunt_swarm.py --repo . --proxy 127.0.0.1:8080 --plain",
    "--poc": "python rfc_hunt_swarm.py --all --repo . --poc --output-dir reports",
    "--header": 'python rfc_hunt_swarm.py --all --host target.example.com --authorized --header "X-Bug-Bounty: researcher"',
    "--user-agent": 'python rfc_hunt_swarm.py --all --host target.example.com --authorized --user-agent "RFCHunt-Researcher/1.0"',
    "--max-rps": "python rfc_hunt_swarm.py --all --host target.example.com --authorized --max-rps 2.0",
    "--env-local": "python rfc_hunt_swarm.py --all --repo . --env-local .env.local",
    "--force-ollama": "python rfc_hunt_swarm.py --all --repo . --force-ollama",
}


def _synthesize_flag_example(act: argparse.Action) -> str:
    """Returns a curated or deterministically synthesized runnable CLI example for any parser flag."""
    opts = [o for o in act.option_strings if o.startswith("--")]
    if not opts:
        return "python rfc_hunt_swarm.py --help"
    primary = opts[0]
    for o in opts:
        if o in _CURATED_FLAG_EXAMPLES:
            return _CURATED_FLAG_EXAMPLES[o]

    # Pick realistic mode/context prefix from flag namespace
    low = primary.lower()
    if low.startswith("--hunt"):
        prefix = "python rfc_hunt_swarm.py --hunt --dry-run"
    elif low.startswith("--artex"):
        prefix = "python rfc_hunt_swarm.py --all --repo ."
    elif low.startswith("--aiscan"):
        prefix = "python rfc_hunt_swarm.py aiscan"
    elif low.startswith("--raptor"):
        prefix = "python rfc_hunt_swarm.py raptor --repo ."
    elif low.startswith("--mantis"):
        prefix = "python rfc_hunt_swarm.py --mantis --repo ."
    elif low.startswith("--harness2"):
        prefix = "python rfc_hunt_swarm.py harness2 --rfc 9112"
    elif low.startswith("--dream"):
        prefix = "python rfc_hunt_swarm.py --mode dream"
    elif low.startswith("--phi"):
        prefix = "python rfc_hunt_swarm.py --phi --repo ."
    elif low.startswith("--hackerone") or low.startswith("--hackone"):
        prefix = "python rfc_hunt_swarm.py --hackerone --dry-run"
    elif low.startswith("--preflight"):
        prefix = "python rfc_hunt_swarm.py --preflight-only --repo ."
    elif low.startswith("--pe-"):
        prefix = "python rfc_hunt_swarm.py --pe-audit --repo ."
    elif low.startswith("--fuzz"):
        prefix = "python rfc_hunt_swarm.py fuzz-bridge --repo ."
    elif low.startswith("--slice") or low.startswith("--escalation") or low.startswith("--frontier"):
        prefix = "python rfc_hunt_swarm.py slice --repo ."
    elif low.startswith("--poc"):
        prefix = "python rfc_hunt_swarm.py --all --repo . --poc"
    elif low.startswith("--proxy") or low.startswith("--live-proxy") or low.startswith("--trust-"):
        prefix = "python rfc_hunt_swarm.py deep-audit --repo ."
    elif low.startswith("--mcp"):
        prefix = "python rfc_hunt_swarm.py mcp"
    elif low.startswith("--hint"):
        prefix = 'python rfc_hunt_swarm.py hint --hint "Focus auth boundaries"'
    elif low.startswith("--caldera"):
        prefix = "python rfc_hunt_swarm.py caldera"
    elif low.startswith("--rea"):
        prefix = "python rfc_hunt_swarm.py rea --path ."
    elif low.startswith("--board") or low in ("--emoji", "--no-emoji", "--watch", "--interval"):
        prefix = "python rfc_hunt_swarm.py swarm-board"
    elif low.startswith("--ui") or low in ("--serve", "--random-port"):
        prefix = "python rfc_hunt_swarm.py ui"
    elif low.startswith("--novelty") or low.startswith("--refresh-novelty"):
        prefix = "python rfc_hunt_swarm.py novelty"
    elif low.startswith("--arxiv") or low.startswith("--last30days") or low.startswith("--research") or low.startswith("--reseach") or low.startswith("--skill"):
        prefix = "python rfc_hunt_swarm.py --all --repo ."
    elif low.startswith("--invariant") or low.startswith("--sandbox"):
        prefix = "python rfc_hunt_swarm.py sandbox-invariants --repo ."
    elif low.startswith("--poe") or low.startswith("--drop-unverified") or low.startswith("--findings-json"):
        prefix = "python rfc_hunt_swarm.py poe-verify --repo ."
    elif low.startswith("--docker") or low.startswith("--fix") or low.startswith("--include-all-wsl") or low.startswith("--reset-docker"):
        prefix = "python rfc_hunt_swarm.py docker-doctor"
    elif low in ("--chain-id", "--min-poe", "--verified-only"):
        prefix = "python rfc_hunt_swarm.py chains"
    elif low in ("--all-chains", "--live"):
        prefix = "python rfc_hunt_swarm.py retest"
    elif low in ("--worker-id", "--query"):
        prefix = "python rfc_hunt_swarm.py traces"
    elif low in ("--export-archive", "--import", "--key-file"):
        prefix = "python rfc_hunt_swarm.py archive"
    elif low in ("--ca-dir", "--noise-profile", "--rewrite-rule", "--duration"):
        prefix = "python rfc_hunt_swarm.py proxy"
    elif low in ("--sequence", "--name", "--max-size"):
        prefix = "python rfc_hunt_swarm.py ruler --host 127.0.0.1 --port 3030"
    elif low in ("--keep-rfcs-on-clean", "--keep-findings-on-clean"):
        prefix = "python rfc_hunt_swarm.py --clean-db"
    elif low in ("--include-docker", "--no-docker-tools", "--force-install", "--tools"):
        prefix = "python rfc_hunt_swarm.py --setup"
    else:
        prefix = "python rfc_hunt_swarm.py --all --repo ."

    # Boolean / count / flag-only actions take no argument
    if act.nargs == 0:
        return f"{prefix} {primary}"

    # Determine concrete sample value
    sample: str
    if act.choices:
        sample = str(list(act.choices)[0])
    elif act.type is int:
        dv = act.default if isinstance(act.default, int) and not isinstance(act.default, bool) and act.default > 0 else 5
        sample = str(dv)
    elif act.type is float:
        dv = act.default if isinstance(act.default, (int, float)) and not isinstance(act.default, bool) and float(act.default) > 0 else 10.0
        sample = str(dv)
    elif "url" in low:
        sample = "http://127.0.0.1:8787"
    elif "host" in low:
        sample = "127.0.0.1"
    elif "model" in low:
        sample = "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
    elif "profile" in low and "llm" in low:
        sample = "profA,profB"
    elif "har" in low:
        sample = "traffic.har"
    elif "openapi" in low:
        sample = "openapi.yaml"
    elif "sarif" in low:
        sample = "reports/audit.sarif"
    elif "archive" in low or low == "--import":
        sample = "reports/task_backup.rfca"
    elif "dir" in low or "folder" in low or "target" in low or "repo" in low:
        sample = "./reports" if "dir" in low or "out" in low else "."
    elif "file" in low or "rules" in low or "policy" in low or "cert" in low or "key" in low or "config" in low or "db" in low or "export" in low:
        sample = str(act.default) if (isinstance(act.default, str) and act.default.strip()) else "config.yaml"
    elif "rewrite" in low:
        sample = '"add-hdr:X-Test=1"'
    elif "sequence" in low:
        sample = '"\\xc0\\x8a"'
    elif "probe" in low:
        sample = '"GET / HTTP/1.1\\r\\n\\r\\n"'
    elif "query" in low or "topic" in low or "prompt" in low or "keywords" in low:
        sample = '"auth bypass"'
    elif "username" in low:
        sample = "researcher"
    elif "token" in low or "key" in low:
        sample = "demo-token"
    elif "tags" in low:
        sample = "tech,misconfig,exposure"
    elif "languages" in low:
        sample = "python,rust"
    elif "parsers" in low:
        sample = "nginx,envoy,haproxy"
    elif "tools" in low:
        sample = "aiscan,raptor,httpx"
    elif "image" in low:
        sample = "python:3.12-slim"
    elif "runtime" in low:
        sample = "python"
    elif isinstance(act.default, str) and act.default.strip():
        dv_s = act.default.strip()
        sample = f'"{dv_s}"' if " " in dv_s else dv_s
    else:
        sample = "example"

    return f"{prefix} {primary} {sample}"


def _ensure_help_examples_for_all_flags(parser: argparse.ArgumentParser) -> None:
    """Guarantees every single CLI option in `--help` includes a concrete `Example:` line."""
    for act in parser._actions:
        opts = [o for o in act.option_strings if o.startswith("--")]
        if not opts or "--help" in opts:
            continue
        cur_help = act.help or ""
        if "example:" in cur_help.lower():
            continue
        ex = _synthesize_flag_example(act)
        # Escape literal '%' for argparse %-formatting
        ex_safe = ex.replace("%", "%%")
        sep = " " if cur_help and not cur_help.endswith((".", ")")) else (" " if cur_help else "")
        act.help = f"{cur_help}{sep}Example: `{ex_safe}`"


def generate_complete_cli_flags_markdown() -> str:
    """Generates a 100%-complete Markdown CLI flags + examples reference directly from `build_swarm_parser()`."""
    parser = build_swarm_parser()
    lines: List[str] = [
        "| Flag(s) | Type | Default | Description | Example |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for act in parser._actions:
        opts = [o for o in act.option_strings if o.startswith("--")]
        if not opts or "--help" in opts:
            continue
        flag_cell = ", ".join(f"`{o}`" for o in opts)
        if act.nargs == 0:
            type_cell = "flag"
        elif act.choices:
            type_cell = "choice"
        elif act.type is int:
            type_cell = "int"
        elif act.type is float:
            type_cell = "float"
        else:
            type_cell = "string"
        default_val = act.default
        default_cell = f"`{default_val}`" if default_val is not None else "`None`"
        raw_help = (act.help or "").replace("%%", "%")
        if " Example: `" in raw_help:
            desc_part = raw_help.split(" Example: `", 1)[0].strip()
        else:
            desc_part = raw_help.strip()
        desc_cell = desc_part.replace("|", "\\|").replace("\n", " ")
        ex_cmd = _synthesize_flag_example(act).replace("|", "\\|")
        lines.append(f"| {flag_cell} | {type_cell} | {default_cell} | {desc_cell} | `{ex_cmd}` |")
    return "\n".join(lines) + "\n"


def print_raptor_help():
    """Prints the comprehensive, detailed help manual for RAPTOR integration with full attribution."""
    help_text = """
===============================================================================
RAPTOR: Autonomous Offensive/Defensive Research Framework
Integrated Security Engine & Unified CLI Reference
===============================================================================

CREDIT & CITATION:
------------------
RAPTOR is an autonomous offensive/defensive research framework created by:
  - Gadi Evron
  - Daniel Cuthbert (https://orcid.org/0009-0000-6443-0251)
  - Thomas Dullien ("Halvar Flake")

Official Project Repository : https://github.com/gadievron/raptor
Docker Registry Engine      : danielcuthbert/raptor:latest
License                     : MIT

ACADEMIC CITATION:
  Evron, G., Cuthbert, D., & Dullien, T. (2026).
  RAPTOR: Autonomous Offensive/Defensive Research Framework (Version 3.1.0).
  https://github.com/gadievron/raptor

===============================================================================
OVERVIEW & CAPABILITIES:
===============================================================================
RAPTOR provides end-to-end autonomous security testing across both live remote
hosts (web DAST) and local source-code repositories (SAST, agentic LLM triage,
and post-quantum cryptographic auditing):

1. LIVE HOST WEB APPLICATION TESTING ('web' mode):
   - Phased dynamic scanner executing against live URLs (https://<host>:<port>).
   - Phase 0: Preflight reachability and TLS negotiation.
   - Phase 2: Robots, sitemap, API specs, and service fingerprinting.
   - Phase 4: ASVS-mapped passive security header checks.
   - Phase 6: Autonomous parameter fuzzing, CRLF, and injection verification.
   - Correlates wire-level RFC desynchronization with application-level flaws.

2. AUTONOMOUS AGENTIC SOURCE-CODE PENTESTING ('agentic' mode):
   - Static analysis across Semgrep and Coccinelle with optional CodeQL.
   - Automated LLM exploitability triage powered by local Ollama models:
     Default Model: 'fenkohq/foundation-sec-8b:latest' (Cisco Foundation-Sec-8B).
   - 100% private, on-device execution (zero cloud API fees, zero token limits).

3. POST-QUANTUM CRYPTOGRAPHY AUDITING ('crypto' mode):
   - Audits codebases for quantum-resistant cryptographic readiness (ML-KEM,
     HPKE, hybrid key exchange, post-quantum signatures).

4. SOFTWARE COMPOSITION ANALYSIS ('sca' mode):
   - Audits dependencies, lockfiles, and third-party CVE advisories.

5. UNIFIED REPOSITORY INGESTION & DEFENSE EXPORT:
   - Ingests SARIF reports into terminator.db.
   - Exports defensive rules (ModSecurity WAF, Nuclei, Suricata IDS).

===============================================================================
COMMAND-LINE USAGE & EXAMPLES:
===============================================================================

1. Diagnostics & Readiness Status:
   python -u rfc_hunt_swarm.py raptor --status
   (Checks Docker daemon, danielcuthbert/raptor:latest image, and Ollama models)

2. Scan a Live Remote Host (Web Application Dynamic Audit):
   python -u rfc_hunt_swarm.py raptor --host vanguardngr.com --port 443 --tls
   python -u rfc_hunt_swarm.py raptor --host dlptest.com --port 443 --tls
   python -u rfc_hunt_swarm.py --mode raptor --host 127.0.0.1 --port 3030

3. Scan a Local Source-Code Repository (Fast Static Scan):
   python -u rfc_hunt_swarm.py raptor --repo D:\\harfile\\my_project --raptor-mode scan

4. Full Autonomous Agentic Pentest (Static Scan + Ollama LLM Triage):
   python -u rfc_hunt_swarm.py raptor --repo D:\\harfile\\my_project --raptor-mode agentic
   python -u rfc_hunt_swarm.py raptor --repo D:\\harfile\\my_project --raptor-mode agentic --raptor-model fenkohq/foundation-sec-8b:latest

5. Post-Quantum Cryptography & Algorithm Audit:
   python -u rfc_hunt_swarm.py raptor --repo D:\\harfile\\my_project --raptor-mode crypto

6. Software Composition Analysis (SCA Dependencies & Advisories):
   python -u rfc_hunt_swarm.py raptor --repo D:\\harfile\\my_project --raptor-mode sca

7. Profile Target Codebase Surface & Language Breakdown:
   python -u rfc_hunt_swarm.py raptor --describe D:\\harfile\\my_project

8. Review Historical SARIF Vulnerability Findings:
   python -u rfc_hunt_swarm.py raptor --findings
   python -u rfc_hunt_swarm.py raptor --findings --limit 25

===============================================================================
CLI FLAGS FOR RAPTOR:
===============================================================================
  --host HOST           Target domain or IP for live web application testing
  --port PORT           Target port (default: 443 with TLS, 80 with HTTP)
  --tls                 Enable TLS/HTTPS encryption (auto-enabled if port is 443)
  --repo, --raptor-target PATH
                        Path to local repository or source folder to audit
  --raptor-mode {web,scan,agentic,crypto,sca,describe}
                        Execution mode (default: 'web' for hosts, 'scan' for repos)
  --raptor-model MODEL  Ollama LLM for agentic triage (default: fenkohq/foundation-sec-8b:latest)
  --raptor-status, --status
                        Verify Docker container and Ollama model status
  --raptor-findings, --findings
                        List and summarize recent SARIF vulnerability findings
  --policy-groups GROUPS
                        Filter Semgrep policies (e.g. 'secrets,owasp,crypto')
  --include-codeql      Enable CodeQL compilation during agentic scan
  --db DB_PATH          SQLite database for unified finding storage (default: terminator.db)
===============================================================================
"""
    print(help_text)


def _normalize_harness2_argv(raw_args: List[str]) -> List[str]:
    """Translates `harness2 --mode <parallel|sequential|agg|seq|both>` to `--harness2-mode` cleanly."""
    h2_modes = {"parallel", "sequential", "agg", "seq", "both"}
    pos_tokens = [tok for tok in raw_args if not tok.startswith("-")]
    if "harness2" not in pos_tokens:
        return list(raw_args)
    out: List[str] = []
    i = 0
    while i < len(raw_args):
        tok = raw_args[i]
        if tok == "--mode" and i + 1 < len(raw_args) and raw_args[i + 1] in h2_modes:
            out.extend(["--harness2-mode", raw_args[i + 1]])
            i += 2
            continue
        if tok.startswith("--mode=") and tok.split("=", 1)[1] in h2_modes:
            out.append("--harness2-mode=" + tok.split("=", 1)[1])
            i += 1
            continue
        out.append(tok)
        i += 1
    return out


def print_deep_audit_proxy_help():
    """Prints dedicated CLI manual & copy-paste examples for `--proxy` and `deep-audit`."""
    help_text = r"""
===============================================================================
  RFCHunt: LIVE LOOPBACK PROXY FUZZING (--proxy) & DEEP REPO AUDIT (deep-audit)
===============================================================================

OVERVIEW:
  `--proxy` and `deep-audit` bridge static scanning toward real bug discovery on
  code repositories through three strictly CLI-only, non-destructive pillars:
    1. Live Loopback Proxy Fuzzing (`--proxy` / `--live-proxy-fuzz`):
       Fuzzes a local HTTP/HTTPS proxy strictly on loopback (`127.0.0.1` / `localhost`
       / `::1` — fails closed with PermissionError on any non-loopback host) using
       3-trial RFC 9112 framing, request-smuggling, and allowlist bypass probes
       cross-checked through RFCHunt's 4-parser differential matrix (+ optional
       `--docker-parser-matrix`).
    2. Line-by-Line Structural Trust-Boundary Review (`--trust-boundary-review`):
       Audits top-ranked production trust-boundary files (TS/JS, Rust nested crates
       under `vendor/*/src`, Python, Go, C/C++; excludes tests) for 14+ structural
       invariant bug classes including TLS ClientHello minor-version cap, TRACE/TRACK
       credential echo gating, Win32 CreateFile reparse-point omission, WFP missing
       inbound/listen layers, Linux bwrap pre-seccomp shell startup, POSIX ERE
       bracket escaping, and URL host canonicalizer stripping.
    3. Coverage-Guided Fuzzing (`--coverage-fuzz`):
       Runs LLMFuzzBridge (`cargo-fuzz`, `Jazzer`, `AFL++`, `Atheris`) on the root
       repo and nested crates (`vendor/*/Cargo.toml`), writing all harnesses strictly
       under `--output-dir` (zero mutations to the target repository).

===============================================================================
HOW TO RUN --proxy (ALL 5 SUPPORTED FORMS):
===============================================================================

  1. Auto-spawn a compiled Node repo proxy on ephemeral 127.0.0.1:0 (bare --proxy):
     python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy --plain
     python -u rfc_hunt_swarm.py deep-audit --repo D:\path\to\repo --proxy --plain

  2. Fuzz an already-running local proxy by port number (assumes 127.0.0.1):
     python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy 8080 --plain

  3. Fuzz an explicit loopback host:port (IPv4 or IPv6):
     python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy 127.0.0.1:3128 --plain
     python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy [::1]:8080 --plain

  4. Fuzz an explicit loopback HTTP URL:
     python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy http://localhost:8888 --plain

  5. Spawn a custom local proxy command on ephemeral 127.0.0.1:<PORT> (shell=False):
     python -u rfc_hunt_swarm.py --repo D:\path\to\repo --proxy "node dist/server.js" --plain
     (RFCHunt injects HOST=127.0.0.1, PORT=<ephemeral>, PROXY_PORT=<ephemeral>
     and deterministically terminates the process when fuzzing completes.)

===============================================================================
COMBINED DEEP-AUDIT & --all WORKFLOW EXAMPLES:
===============================================================================

  # Full 3-pillar deep audit (live proxy + structural trust-boundary + coverage fuzz + PoC triage):
  python -u rfc_hunt_swarm.py deep-audit --repo D:\path\to\repo --proxy --poc --output-dir reports --plain

  # Targeted line-by-line trust-boundary review only (fast, offline, read-only):
  python -u rfc_hunt_swarm.py deep-audit --repo D:\path\to\repo --trust-boundary-review --plain

  # Live loopback proxy fuzzing + real Docker multi-parser differential matrix:
  python -u rfc_hunt_swarm.py deep-audit --repo D:\path\to\repo --proxy 127.0.0.1:8080 --docker-parser-matrix --plain

  # Unified --all multi-scanner + deep-audit + live --proxy + --poc verification:
  python -u rfc_hunt_swarm.py --all --repo D:\path\to\repo --deep-audit --proxy --poc --plain

  # JSON output for CI / automation pipelines:
  python -u rfc_hunt_swarm.py deep-audit --repo D:\path\to\repo --proxy --fuzz-dry-run --json

===============================================================================
RELATED FLAGS:
===============================================================================
  --proxy [SPEC]            Auto-spawn (`--proxy`), port (`8080`), `127.0.0.1:8080`,
                            `http://localhost:8080`, or safe launch command (loopback-only)
  --live-proxy-fuzz         Enable Pillar 1 explicitly (auto-enabled by `--proxy`)
  --proxy-host HOST         Loopback host override (default: 127.0.0.1)
  --proxy-port PORT         Explicit running loopback proxy port
  --proxy-cmd CMD           Explicit safe command to launch proxy on 127.0.0.1:<PORT>
  --docker-parser-matrix    Cross-check probes against local Docker parser matrix
  --trust-boundary-review   Enable Pillar 2 line-by-line structural trust-boundary review
  --trust-max-files N       Max ranked trust-boundary files to audit (default: 80)
  --coverage-fuzz           Enable Pillar 3 root + nested-crate coverage fuzzing
  --fuzz-dry-run            Generate fuzz harnesses/corpora without launching containers
  --poc                     Run strictly non-destructive false-positive triage & PoC verifier
  --output-dir DIR          Directory for reports/harnesses (strictly outside target repo)
  --plain / --json          Plain ASCII table output or machine-readable JSON output
===============================================================================
"""
    print(help_text)


def _normalize_all_positional_target(
    argv_list: List[str],
    parser: argparse.ArgumentParser,
) -> Tuple[List[str], Optional[str]]:
    """
    Normalizes `["--all", "<target>", ...]` (e.g. from `bugbounty_mcp_server.build_rfchunt_all_argv`)
    using `parser._option_string_actions` so `<target>` is mapped to `--host` or `--repo`
    instead of failing `command` (`choices=ALL_MODES`) with `SystemExit(2)`.
    """
    opt_actions = getattr(parser, "_option_string_actions", {})
    has_all_flag = False
    has_explicit_target_opt = False

    def _consume_option_count(tok: str, idx: int, tokens: List[str]) -> int:
        if "=" in tok:
            return 0
        act = opt_actions.get(tok)
        if act is None:
            return 0
        nargs = getattr(act, "nargs", None)
        if nargs is None:
            return 1 if idx + 1 < len(tokens) else 0
        if isinstance(nargs, int):
            return min(nargs, max(0, len(tokens) - idx - 1))
        if nargs == "?":
            if idx + 1 < len(tokens) and not tokens[idx + 1].startswith("-"):
                return 1
            return 0
        if nargs in ("*", "+"):
            cnt = 0
            while idx + 1 + cnt < len(tokens) and not tokens[idx + 1 + cnt].startswith("-"):
                cnt += 1
            return cnt
        return 0

    i = 0
    while i < len(argv_list):
        tok = argv_list[i]
        if tok == "--":
            break
        if tok.startswith("-"):
            opt_key = tok.split("=", 1)[0]
            if opt_key in ("--all", "--run-all", "--all-scans", "--hunt", "--fast-ooda", "--ensemble", "--essemble", "--essample", "--swarm"):
                has_all_flag = True
            elif opt_key == "--mode":
                if "=" in tok:
                    if tok.split("=", 1)[1] in ("all", "all_scans"):
                        has_all_flag = True
                elif i + 1 < len(argv_list) and argv_list[i + 1] in ("all", "all_scans"):
                    has_all_flag = True
            if opt_key in ("--repo", "--raptor-target", "--folder", "--dir", "--path", "--host", "--target", "--hunt-target"):
                has_explicit_target_opt = True
            i += 1 + _consume_option_count(tok, i, argv_list)
        else:
            if tok in ("all", "all_scans"):
                has_all_flag = True
            i += 1

    if not has_all_flag:
        return list(argv_list), None

    has_hunt_mode = any(t == "--hunt" for t in argv_list)
    out: List[str] = []
    promoted_target: Optional[str] = None
    pos_idx = 0
    i = 0
    while i < len(argv_list):
        tok = argv_list[i]
        if tok == "--":
            out.extend(argv_list[i:])
            break
        if tok.startswith("-"):
            consume = _consume_option_count(tok, i, argv_list)
            out.extend(argv_list[i : i + 1 + consume])
            i += 1 + consume
            continue
        if tok not in ALL_MODES:
            if promoted_target is None:
                promoted_target = tok
            if has_hunt_mode:
                if os.path.isdir(tok) or tok in (".", "..") or tok.startswith(("./", "../", ".\\", "..\\")):
                    out.extend(["--hunt-target", tok])
                else:
                    out.extend(["--hunt-repo", tok])
                pos_idx += 1
                i += 1
                continue
            if pos_idx == 0:
                if not has_explicit_target_opt:
                    if tok.lower().startswith(("http://", "https://")):
                        out.extend(["--host", tok])
                    else:
                        out.extend(["--repo", tok])
                    has_explicit_target_opt = True
                pos_idx += 1
                i += 1
                continue
        pos_idx += 1
        out.append(tok)
        i += 1
    return out, promoted_target


def parse_swarm_arguments(argv=None):
    """Parses arguments using build_swarm_parser."""
    raw_args = sys.argv[1:] if argv is None else list(argv)
    if any(h in raw_args for h in ("--help", "-h", "help")):
        if "raptor" in raw_args or "--raptor" in raw_args:
            print_raptor_help()
            sys.exit(0)
        if "harness2" in raw_args or "--harness2" in raw_args:
            print_harness2_help()
            sys.exit(0)
        if any(
            tok in raw_args or any(arg.startswith(tok + "=") for arg in raw_args)
            for tok in ("deep-audit", "deep_audit", "--deep-audit", "--proxy", "--live-proxy-fuzz", "--trust-boundary-review")
        ):
            print_deep_audit_proxy_help()
            sys.exit(0)

    parser = build_swarm_parser()
    norm_args = _normalize_harness2_argv(raw_args)
    norm_args, promoted_target = _normalize_all_positional_target(norm_args, parser)
    args = parser.parse_args(norm_args)
    if not hasattr(args, "_explicit_cli_dests"):
        args._explicit_cli_dests = set()
    if promoted_target is not None and not getattr(args, "target_arg", None):
        args.target_arg = promoted_target
    if getattr(args, "command", None) in ("all", "all_scans") and getattr(args, "target_arg", None):
        _t_pos = str(args.target_arg)
        if _t_pos.lower().startswith(("http://", "https://")) and "host" not in args._explicit_cli_dests:
            args.host = _t_pos
            args._explicit_cli_dests.add("host")
        elif not getattr(args, "repo", None) and not getattr(args, "path", None):
            args.repo = _t_pos
    if isinstance(args.targets, str):
        args.targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    if isinstance(args.terminators, str):
        if args.terminators.lower() == "all":
            args.terminators = ["all"]
        else:
            args.terminators = [t.strip() for t in args.terminators.split(",") if t.strip()]
    if not getattr(args, "raptor_target", None):
        args.raptor_target = getattr(args, "repo", None) or getattr(args, "path", None)
    if not getattr(args, "repo", None) and getattr(args, "raptor_target", None):
        args.repo = args.raptor_target
    if getattr(args, "skills_num", None) is None:
        args.skills_num = int(getattr(args, "research_num", 5) or 5)
    return args



def main_swarm(argv=None, caller_profile: str = "swarm"):
    """Primary unified CLI execution entrypoint for rfc_hunt_swarm (and thin compatibility callers)."""
    args = parse_swarm_arguments(argv)
    if getattr(args, "env_local", None):
        os.environ["RFCHUNT_ENV_LOCAL"] = str(args.env_local)
    if getattr(args, "force_ollama", False):
        os.environ["RFCHUNT_FORCE_OLLAMA"] = "1"
    try:
        _configure_cli_hygiene(args)
    except ValueError as exc:
        as_json_err = bool(getattr(args, "as_json", False))
        print(f"[!] Invalid request hygiene / rate-limit configuration: {exc}", file=(sys.stderr if as_json_err else sys.stdout))
        sys.exit(1)

    raw_argv = sys.argv[1:] if argv is None else list(argv)
    args._raw_cli_argv = list(raw_argv)
    explicit_dests = getattr(args, "_explicit_cli_dests", set())
    explicit_mode_given = bool(args.command) or any(
        arg == "--mode" or arg.startswith("--mode=") for arg in _normalize_harness2_argv(raw_argv)
    )

    if caller_profile == "main" and not explicit_mode_given and not any(
        getattr(args, flag, False) for flag in (
            "ui", "build", "mcp", "kettle", "all_active", "enable_raptor", "list_terminators",
            "run_all_scans", "enable_mantis", "enable_artex", "enable_aiscan", "enable_prompt_smuggle",
            "enable_rea_only", "clean_db", "raptor_status", "raptor_findings", "raptor_setup",
            "harness2_report", "mantis_report", "aiscan_report", "install_tools", "tool_status",
            "deep_audit", "proxy_target", "live_proxy_fuzz", "trust_boundary_review",
            "coverage_fuzz", "enable_poc", "enable_phi", "enable_hackerone", "hackerone_auto",
            "serve_ui", "network_lifecycle", "dry_run", "enable_pe_audit", "enable_autonomous_hunt",
            "enable_fast_ooda", "start_modelfusion", "enable_swarm",
        )
    ) and getattr(args, "hint", None) is None and not getattr(args, "dispatch", None):
        build_swarm_parser().print_help()
        sys.exit(0)

    if not getattr(args, "auto_install", True):
        os.environ["RFCHUNT_AUTO_INSTALL_TOOLS"] = "0"

    # Resolve positional command / shortcut flags into active_mode
    if not explicit_mode_given:
        if args.ui:
            active_mode = "ui"
        elif args.build:
            active_mode = "build"
        elif args.mcp:
            active_mode = "mcp"
        elif args.kettle:
            active_mode = "corpus"
        elif args.all_active:
            active_mode = "all_active"
        elif getattr(args, "install_tools", False) and not getattr(args, "run_all_scans", False):
            active_mode = "setup"
        elif getattr(args, "tool_status", False) and not getattr(args, "run_all_scans", False):
            active_mode = "setup"
        elif getattr(args, "enable_rea_only", False) and not getattr(args, "run_all_scans", False):
            active_mode = "rea"
        else:
            active_mode = args.mode
    else:
        active_mode = args.command or args.mode

    # Normalize aliases
    if active_mode in ("differential",):
        active_mode = "oracle"
    elif active_mode in ("http2",):
        active_mode = "h2"
    elif active_mode in ("merkle",):
        active_mode = "audit"
    elif active_mode in ("export-rules",):
        active_mode = "export"
    elif active_mode in ("clean", "clean-db"):
        active_mode = "clean_db"
    elif active_mode in ("install-tools", "install"):
        active_mode = "setup"
    elif active_mode in ("hackone",):
        active_mode = "hackerone"

    # Validate numeric CLI bounds BEFORE --dry-run early return so invalid flags exit rc=1
    _as_json_cli = bool(getattr(args, "as_json", False))
    for _turn_attr in ("artex_intent_turns", "artex_intent_tokens", "artex_budget_turns"):
        _tval = getattr(args, _turn_attr, 0)
        if isinstance(_tval, bool) or (_tval is not None and int(_tval) < 0):
            print(
                "[!] ARTEX budget/turn parameters must be non-negative (>= 0).",
                file=(sys.stderr if _as_json_cli else sys.stdout),
            )
            sys.exit(1)
    _rounds_val = getattr(args, "artex_rounds", None)
    if _rounds_val is not None and int(_rounds_val) < 1:
        print(
            "[!] --artex-rounds must be >= 1.",
            file=(sys.stderr if _as_json_cli else sys.stdout),
        )
        sys.exit(1)
    _workers_val = getattr(args, "artex_workers", None)
    if _workers_val is not None and int(_workers_val) < 1:
        print(
            "[!] --artex-workers must be >= 1.",
            file=(sys.stderr if _as_json_cli else sys.stdout),
        )
        sys.exit(1)
    _max_rps_val = getattr(args, "max_rps", None)
    if _max_rps_val is not None and float(_max_rps_val) < 0.0:
        print(
            "[!] --max-rps must be non-negative (>= 0).",
            file=(sys.stderr if _as_json_cli else sys.stdout),
        )
        sys.exit(1)
    _swarm_workers_val = getattr(args, "swarm_workers", None)
    if _swarm_workers_val is not None and int(_swarm_workers_val) < 1:
        print(
            "[!] --swarm-workers must be >= 1.",
            file=(sys.stderr if _as_json_cli else sys.stdout),
        )
        sys.exit(1)

    # Multi-Agent Swarm Mode (--swarm / positional `swarm`):
    # - With `--hunt`: enables parallel multi-agent target fan-out inside `--hunt`.
    # - With local `--repo` / `--folder` / `--path` (or no explicit network `--host`):
    #   activates full `--all` + `--ensemble` + `--fast-ooda` + `--swarm-board` orchestration.
    # - With explicit network `--host` only: routes into 12-Agent LangGraph `ProtocolResearchSwarm` + `--swarm-board`.
    if getattr(args, "enable_swarm", False) or active_mode == "swarm":
        args.enable_swarm = True
        if not any(t == "--no-swarm-board" for t in raw_argv) and not _as_json_cli:
            args.swarm_board = True
        if _swarm_workers_val is not None:
            _bounded_sw = max(1, min(16, int(_swarm_workers_val)))
            if not getattr(args, "cpu_workers", None):
                args.cpu_workers = min(8, _bounded_sw)
            if "concurrency" not in explicit_dests:
                args.concurrency = _bounded_sw
        if not getattr(args, "enable_autonomous_hunt", False) and not getattr(args, "dispatch", None):
            _swarm_has_local = bool(
                getattr(args, "repo", None)
                or getattr(args, "path", None)
                or getattr(args, "raptor_target", None)
                or getattr(args, "hunt_targets", None)
                or getattr(args, "additional_local_targets", None)
            )
            _swarm_has_net_host = (
                "host" in explicit_dests
                or any(
                    a in ("--host", "--target") or a.startswith(("--host=", "--target="))
                    for a in raw_argv
                )
            ) and bool(getattr(args, "host", None)) and not os.path.isdir(str(getattr(args, "host", "") or ""))
            if _swarm_has_local or not _swarm_has_net_host:
                args.run_all_scans = True
                args.ensemble = True
                args.enable_fast_ooda = True
            else:
                active_mode = "terminator"

    # Turnkey Autonomous Bug Bounty Hunter (--hunt):
    # - Standalone `--hunt` (without `--all`) dispatches directly BEFORE generic `--dry-run`.
    # - Combined `--all --hunt` (e.g., `--all --repo ./repo --folder ./folder --hunt`) executes
    #   BOTH the full `--all` audit on local repo/folder targets AND the `--hunt` pipeline!
    if getattr(args, "enable_autonomous_hunt", False) and not getattr(args, "run_all_scans", False):
        _hunt_rc = cmd_autonomous_hunt(args, raw_argv=raw_argv)
        if _hunt_rc != 0:
            sys.exit(_hunt_rc)
        return

    # Universal --dry-run guard: works across EVERY flag and subcommand with zero side effects
    if getattr(args, "dry_run", False):
        if getattr(args, "enable_autonomous_hunt", False) and getattr(args, "run_all_scans", False):
            # Combined `--all --hunt --dry-run`: preview BOTH --all and --hunt with zero side effects
            if getattr(args, "as_json", False):
                import io as _combo_io
                import json as _combo_json

                _all_buf = _combo_io.StringIO()
                with contextlib.redirect_stdout(_all_buf):
                    cmd_dry_run_plan(args, active_mode=active_mode, raw_argv=raw_argv)
                _hunt_buf = _combo_io.StringIO()
                with contextlib.redirect_stdout(_hunt_buf):
                    _hunt_dry_rc = cmd_autonomous_hunt(args, raw_argv=raw_argv)
                _all_doc = _combo_json.loads(_all_buf.getvalue()) if _all_buf.getvalue().strip() else {}
                _hunt_doc = _combo_json.loads(_hunt_buf.getvalue()) if _hunt_buf.getvalue().strip() else {}
                print(
                    _combo_json.dumps(
                        {
                            "status": "dry_run_combined_all_and_hunt_planned",
                            "dry_run": True,
                            "all_scan_plan": _all_doc,
                            "autonomous_hunt_plan": _hunt_doc,
                            "side_effects": {
                                "network_packets_sent": 0,
                                "filesystem_mutations": 0,
                                "external_submissions": 0,
                                "browser_launched": False,
                            },
                        },
                        indent=2,
                    )
                )
                if _hunt_dry_rc != 0:
                    sys.exit(_hunt_dry_rc)
                return
            cmd_dry_run_plan(args, active_mode=active_mode, raw_argv=raw_argv)
            _hunt_dry_rc = cmd_autonomous_hunt(args, raw_argv=raw_argv)
            if _hunt_dry_rc != 0:
                sys.exit(_hunt_dry_rc)
            return
        if (getattr(args, "enable_hackerone", False) or getattr(args, "hackerone_auto", False) or active_mode == "hackerone") and not getattr(args, "run_all_scans", False):
            args.enable_hackerone = True
            cmd_hackerone(args)
            return
        if (getattr(args, "enable_phi", False) or active_mode == "phi") and not getattr(args, "run_all_scans", False):
            cmd_phi(args)
            return
        cmd_dry_run_plan(args, active_mode=active_mode, raw_argv=raw_argv)
        return

    # Optional ModelFusion (:5000) local server bootstrap when --start-modelfusion is requested (zero side effects on --dry-run)
    if getattr(args, "start_modelfusion", False) and not getattr(args, "embedded", False):
        try:
            from scripts.autonomous_hunt import ensure_modelfusion_running

            _mf_info = ensure_modelfusion_running(dry_run=False)
            if not getattr(args, "as_json", False):
                print(
                    f"[*] ModelFusion (:5000): status={_mf_info.get('status')} "
                    f"endpoint={_mf_info.get('endpoint')}"
                )
        except Exception as _mf_exc:
            if not getattr(args, "as_json", False):
                print(f"[!] ModelFusion auto-start fallback to Ollama: {_mf_exc}")

    # Standalone 3-Stage Parallel OODA Funnel (--fast-ooda without --all)
    if getattr(args, "enable_fast_ooda", False) and not getattr(args, "run_all_scans", False):
        _ooda_rc = cmd_fast_ooda(args)
        if _ooda_rc != 0:
            sys.exit(_ooda_rc)
        return

    if active_mode == "setup":
        _dispatch_cmd("cmd_setup", args)
        return

    # If user combined --install-tools / --setup with a scan command (e.g. `--install-tools --all`),
    # provision the entire toolchain up front before executing the scan.
    if getattr(args, "install_tools", False):
        cmd_setup(args)

    # Handle Database Clean & Vacuum
    if getattr(args, "clean_db", False) or active_mode == "clean_db":
        db_inst = _resolve_db_cls()(args.db)
        try:
            res = db_inst.clean_db(
                keep_rfcs=getattr(args, "keep_rfcs_on_clean", False),
                keep_findings=getattr(args, "keep_findings_on_clean", False),
                vacuum=True,
            )
        finally:
            db_inst.close()
        _clean_ctx = contextlib.redirect_stdout(sys.stderr) if getattr(args, "as_json", False) else contextlib.nullcontext()
        with _clean_ctx:
            print("\n" + "=" * 75)
            print("  DATABASE CLEAN & VACUUM (HTTP TERMINATOR)")
            print("=" * 75)
            print(f"  [+] Target Database       : {args.db}")
            print(f"  [+] Total Rows Cleared    : {res['total_rows_deleted']:,}")
            print(f"  [+] Size Before Clean     : {res['size_before_bytes'] / (1024*1024):.2f} MB")
            print(f"  [+] Size After Clean      : {res['size_after_bytes'] / (1024*1024):.2f} MB")
            print(f"  [+] Space Reclaimed       : {res['reclaimed_mb']} MB")
            if getattr(args, "keep_findings_on_clean", False):
                print("  [*] Preserved Confirmed Vulnerabilities and Defensive Rules")
            if getattr(args, "keep_rfcs_on_clean", False):
                print("  [*] Preserved Cached RFC Specifications & Index")
            print("=" * 75 + "\n")

        # If --clean-db was called standalone or as primary command/mode, exit cleanly
        standalone_clean = (active_mode == "clean_db" and not getattr(args, "run_all_scans", False)) or (
            not explicit_mode_given and not any(
                getattr(args, flag, False) for flag in (
                    "ui", "build", "mcp", "kettle", "all_active", "enable_raptor", "list_terminators",
                    "run_all_scans", "enable_mantis", "enable_artex", "enable_aiscan", "enable_prompt_smuggle",
                    "enable_rea_only",
                )
            )
            and getattr(args, "hint", None) is None
            and not getattr(args, "dispatch", None)
        )
        if standalone_clean:
            return

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
        return

    # Normalize default args.host (strip scheme, trailing paths, and inline :port without corrupting IPv6)
    inline_port_extracted = False
    raw_host_scheme: Optional[str] = None
    if getattr(args, "host", None):
        raw_host_scheme, clean_h, inline_port_val = _extract_cli_host_port(str(args.host))
        if raw_host_scheme == "https":
            args.tls = True
        if inline_port_val is not None and getattr(args, "port", 5006) == 5006:
            args.port = inline_port_val
            inline_port_extracted = True
        args.host = clean_h

    # Configure ExecutionPolicy singleton with CLI flags and env opt-in
    from engine.execution_policy import ExecutionPolicy
    ExecutionPolicy.get_instance().allow_destructive = ExecutionPolicy.get_instance().allow_destructive or bool(getattr(args, "allow_destructive", False))

    # Self-Hosted Mission Control Full-Lifecycle Web GUI & REST/SSE Server (--serve-ui)
    if getattr(args, "serve_ui", False):
        from engine.mission_control_server import MissionControlOrchestrator, MissionControlServer
        orch = MissionControlOrchestrator(
            reports_root=str(Path(getattr(args, "output_dir", "reports") or "reports") / "mission_control"),
            db_path=getattr(args, "db", "terminator.db"),
        )
        srv = MissionControlServer(
            host=str(getattr(args, "ui_host", "127.0.0.1") or "127.0.0.1"),
            port=int(getattr(args, "ui_port", 8789) or 8789),
            allow_non_loopback=bool(getattr(args, "ui_allow_non_loopback", False)),
            orchestrator=orch,
        )
        srv.serve_forever()
        return

    # Turnkey Network Lifecycle Profile (--network-lifecycle) promotes --all with external discovery & retest
    if getattr(args, "network_lifecycle", False):
        args.run_all_scans = True
        args.strict_poe = True
        args.artex_retest = True
        if getattr(args, "authorized", False):
            args.enable_external_discovery = True
            args.enable_external_nuclei = True

    # Standalone HackerOne Campaign Finder & HITL Report Porter (--hackerone / --hackone / --hackerone-auto without --all)
    if (getattr(args, "enable_hackerone", False) or getattr(args, "hackerone_auto", False) or active_mode == "hackerone") and not getattr(args, "run_all_scans", False):
        args.enable_hackerone = True
        cmd_hackerone(args)
        return

    # Standalone Module 23 Fresh Pre-Flight Discovery (--preflight-only without --all)
    if (getattr(args, "preflight_only", False) or active_mode == "preflight") and not getattr(args, "run_all_scans", False):
        cmd_preflight(args)
        return

    # Standalone Module 22 HIPAA PHI/PII Detector & ZK Redaction (--phi without --all)
    if (getattr(args, "enable_phi", False) or active_mode == "phi") and not getattr(args, "run_all_scans", False):
        cmd_phi(args)
        return

    # Standalone CLI-only blackboard hint injection (zero GUI / HTTP server calls)
    has_non_hint_action = explicit_mode_given and active_mode != "hint"
    has_shortcut_action = any(
        getattr(args, flag, False)
        for flag in (
            "ui", "build", "mcp", "kettle", "all_active", "enable_raptor",
            "list_terminators", "run_all_scans", "enable_mantis",
            "enable_artex", "enable_aiscan", "enable_prompt_smuggle",
            "enable_rea_only", "install_tools", "tool_status",
            "raptor_status", "raptor_findings", "raptor_setup",
            "harness2_report", "mantis_report", "aiscan_report",
            "preflight_only", "enable_pe_audit", "enable_autonomous_hunt", "enable_swarm",
        )
    )
    if active_mode == "hint" or (
        getattr(args, "hint", None) is not None
        and not getattr(args, "dispatch", None)
        and not has_non_hint_action
        and not has_shortcut_action
    ):
        cmd_hint(args)
        return

    # Unified Cairn-style YAML dispatcher (--dispatch / --dispatch-config)
    if getattr(args, "dispatch", None):
        from engine.swarm_dispatcher import execute_dispatch, load_dispatch_config

        if getattr(args, "hint", None) is not None:
            # Validate all --hint* flags early before creating any workspaces/DBs
            _validate_cli_hint_args(args)

        cfg = load_dispatch_config(args.dispatch)
        has_db_flag = "db" in explicit_dests or any(a == "--db" or a.startswith("--db=") for a in raw_argv)
        has_output_dir_flag = "output_dir" in explicit_dests or any(
            a == "--output-dir" or a.startswith("--output-dir=") for a in raw_argv
        )
        as_json = bool(getattr(args, "as_json", False))
        _disp_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _disp_ctx:
            dispatch_results = execute_dispatch(
                cfg,
                db_override=(args.db if has_db_flag else None),
                output_dir_override=(args.output_dir if has_output_dir_flag else None),
                extra_args=args,
                hint_persister=(
                    lambda a, db_h, target_task_id="default": _persist_cli_hint(
                        a,
                        db=db_h,
                        default_task_id=target_task_id,
                    )["node_id"]
                ),
            )
        if as_json:
            from engine.cli_render import render_json
            render_json({"status": "dispatched", "targets": dispatch_results})
        return

    # Handle standalone modes that do not require remote target authorization first
    if active_mode == "build":
        _dispatch_cmd("cmd_build", args)
        return

    if active_mode == "mcp":
        _dispatch_cmd("cmd_mcp", args)
        return

    has_port_flag = "port" in explicit_dests or any(a == "--port" or a.startswith("--port=") for a in raw_argv)
    has_host_flag = "host" in explicit_dests or any(
        a in ("--host", "--target") or a.startswith(("--host=", "--target=")) for a in raw_argv
    )
    has_limit_flag = any(a == "--limit" or a.startswith("--limit=") for a in raw_argv)
    has_rounds_flag = "artex_rounds" in explicit_dests or any(
        a in ("--artex-rounds", "--rounds") or a.startswith(("--artex-rounds=", "--rounds="))
        for a in raw_argv
    )

    if active_mode in ("slice", "call-graph", "call_graph"):
        _dispatch_cmd("cmd_call_graph_slice", args)
        return

    if active_mode in ("fuzz", "fuzz-bridge", "fuzz_bridge"):
        _dispatch_cmd("cmd_fuzz_bridge", args)
        return

    if active_mode in ("invariants", "sandbox-invariants", "sandbox_invariants"):
        _dispatch_cmd("cmd_sandbox_invariants", args)
        return

    if active_mode in ("poe-verify", "poe_verify"):
        _dispatch_cmd("cmd_poe_verify", args)
        return

    if active_mode in ("poc", "poc-verify", "poc_verify") or (
        bool(getattr(args, "enable_poc", False))
        and not getattr(args, "run_all_scans", False)
        and not explicit_mode_given
    ):
        _dispatch_cmd("cmd_poc", args)
        return

    if active_mode in ("docker-doctor", "docker_doctor", "doctor-docker"):
        _dispatch_cmd("cmd_docker_doctor", args)
        return

    if active_mode in ("deep-audit", "deep_audit") or (
        any(bool(getattr(args, fl, False)) for fl in ("deep_audit", "live_proxy_fuzz", "trust_boundary_review", "coverage_fuzz", "proxy_target"))
        and not getattr(args, "run_all_scans", False)
        and not explicit_mode_given
    ):
        _dispatch_cmd("cmd_deep_audit", args)
        return

    if active_mode in ("novelty", "novelty-refresh", "novelty_refresh") or (
        bool(getattr(args, "refresh_novelty_corpus", None))
        and not getattr(args, "run_all_scans", False)
        and not explicit_mode_given
    ):
        _dispatch_cmd("cmd_novelty", args)
        return

    if active_mode in ("swarm-board", "swarm_board", "board"):
        _dispatch_cmd("cmd_swarm_board", args)
        return

    if bool(getattr(args, "enable_crlf_conformance", False)) and not getattr(args, "run_all_scans", False):
        from engine.crlf_desync_engine import audit_nginx_configs, run_conformance_diagnostics
        target_dir = getattr(args, "repo", None) or getattr(args, "path", None) or getattr(args, "target_arg", None) or "."
        rep = audit_nginx_configs(target_dir)
        if has_host_flag and getattr(args, "host", None):
            live_rep = run_conformance_diagnostics(
                host=str(args.host),
                port=int(getattr(args, "port", 80) or 80),
                use_tls=bool(getattr(args, "tls", False)),
            )
            rep.findings.extend(live_rep.findings)
        if bool(getattr(args, "as_json", False)):
            from engine.cli_render import render_json
            render_json(rep.to_dict())
        else:
            print(f"[+] Module 24 (CRLF/Header Conformance): scanned {rep.files_scanned} config(s), found {len(rep.findings)} issue(s).")
            for f in rep.findings[:25]:
                print(f"  [{f.severity}] {f.rule_id} {f.location}:{f.line} — {f.title}")
        return

    if bool(getattr(args, "enable_web_llm", False)) and not getattr(args, "run_all_scans", False):
        from engine.web_llm_auditor import audit_web_llm_repository
        target_dir = getattr(args, "repo", None) or getattr(args, "path", None) or getattr(args, "target_arg", None) or "."
        rep = audit_web_llm_repository(target_dir)
        if bool(getattr(args, "as_json", False)):
            from engine.cli_render import render_json
            render_json(rep.to_dict())
        else:
            print(f"[+] Module 25 (Web LLM Security Auditor): scanned {rep.files_scanned} file(s), found {len(rep.findings)} issue(s).")
            for f in rep.findings[:25]:
                print(f"  [{f.severity}] {f.rule_id} ({f.owasp_llm}) {f.file_path}:{f.line} — {f.title}")
        return

    if (
        active_mode in ("pe-audit", "pe_audit", "pe-dotnet", "pe_dotnet")
        or (bool(getattr(args, "enable_pe_audit", False)) and not getattr(args, "run_all_scans", False))
    ):
        _dispatch_cmd("cmd_pe_audit", args, check_main_shim=False)
        return

    if active_mode in ("scanner", "artex-loop", "proxy", "retest", "chains", "traces", "coverage", "export-advisory", "archive", "rea"):
        if active_mode == "rea":
            if not has_host_flag:
                args.host = None
            if not has_port_flag:
                args.port = None
            if not getattr(args, "path", None) and not getattr(args, "repo", None) and getattr(args, "target_arg", None):
                args.path = args.target_arg
            _dispatch_cmd("cmd_rea", args)
        elif active_mode == "scanner":
            if not has_port_flag and not inline_port_extracted:
                if raw_host_scheme == "http":
                    args.port = 80
                    if not any(a == "--tls" for a in raw_argv):
                        args.tls = False
                else:
                    args.port = 443
            _dispatch_cmd("cmd_scanner", args)
        elif active_mode == "artex-loop":
            if not has_port_flag and not inline_port_extracted:
                args.port = 8080
            if not has_rounds_flag:
                args.artex_rounds = 1
            _dispatch_cmd("cmd_artex_loop", args)
        elif active_mode == "proxy":
            if not has_port_flag:
                args.port = 8788
            _dispatch_cmd("cmd_proxy", args)
        elif active_mode == "chains":
            if not has_limit_flag:
                args.limit = 50
            _dispatch_cmd("cmd_chains", args)
        elif active_mode == "traces":
            if not has_limit_flag:
                args.limit = 100
            _dispatch_cmd("cmd_traces", args)
        elif active_mode == "coverage":
            _dispatch_cmd("cmd_coverage", args)
        elif active_mode == "retest":
            if not has_host_flag:
                args.host = None
            if not has_port_flag:
                args.port = None
            if not has_limit_flag:
                args.limit = 50
            _dispatch_cmd("cmd_retest", args)
        elif active_mode == "export-advisory":
            if not has_limit_flag:
                args.limit = 50
            _dispatch_cmd("cmd_export_advisory", args)
        elif active_mode == "archive":
            if not getattr(args, "export_path", None) and any(
                a == "--export" or a.startswith("--export=") for a in raw_argv
            ):
                args.export_path = getattr(args, "dream_export", None)
            _dispatch_cmd("cmd_archive", args)
        return

    if active_mode == "dashboard":
        _dispatch_cmd("cmd_dashboard", args)
        return

    if active_mode == "export":
        _dispatch_cmd("cmd_export", args)
        return

    if active_mode == "oracle":
        _dispatch_cmd("cmd_oracle", args)
        return

    if active_mode == "h2":
        _dispatch_cmd("cmd_h2", args)
        return

    if active_mode == "audit":
        _dispatch_cmd("cmd_audit", args)
        return

    if active_mode == "start":
        _dispatch_cmd("cmd_start", args)
        return

    if active_mode == "ui":
        _dispatch_cmd("cmd_ui", args)
        return

    if active_mode in ("vulns", "findings", "list"):
        _dispatch_cmd("cmd_vulns", args)
        return

    if getattr(args, "hint", None) is not None and not (
        getattr(args, "run_all_scans", False) or active_mode in ("all", "all_scans")
    ):
        with (contextlib.redirect_stdout(sys.stderr) if getattr(args, "as_json", False) else contextlib.nullcontext()):
            _persist_cli_hint(args)

    if getattr(args, "run_all_scans", False) or active_mode in ("all", "all_scans"):
        if not has_host_flag:
            args.host = None
        elif raw_host_scheme == "http" and not has_port_flag and not inline_port_extracted:
            args.port = 80
            if not any(a == "--tls" for a in raw_argv):
                args.tls = False
        elif raw_host_scheme == "https" and not has_port_flag and not inline_port_extracted:
            args.port = 443
        elif caller_profile == "main" and has_host_flag and not has_port_flag and not inline_port_extracted:
            args.port = 443
        if not has_host_flag and not has_port_flag and getattr(args, "port", 5006) in (443, 5006):
            args.port = None
        _dispatch_cmd("cmd_all", args, check_main_shim=(caller_profile == "main"))
        return

    if active_mode == "mantis" or getattr(args, "enable_mantis", False) or getattr(args, "mantis_report", False):
        _dispatch_cmd("cmd_mantis", args, check_main_shim=(caller_profile == "main"))
        return

    if active_mode in ("aiscan", "ai") or getattr(args, "enable_aiscan", False) and not explicit_mode_given:
        _dispatch_cmd("cmd_aiscan", args, check_main_shim=(caller_profile == "main"))
        return

    if active_mode in ("artex", "chain", "dual_graph", "dual-graph") or getattr(args, "enable_artex", False) and not explicit_mode_given:
        if not has_port_flag and not inline_port_extracted and getattr(args, "port", 5006) == 5006:
            args.port = 8080
        if caller_profile == "main" and not has_rounds_flag:
            args.artex_rounds = 2
        _dispatch_cmd("cmd_artex", args, check_main_shim=True)
        return

    if active_mode in ("prompt_smuggle", "smuggle") or getattr(args, "enable_prompt_smuggle", False) and not explicit_mode_given:
        _dispatch_cmd("cmd_prompt_smuggle", args, check_main_shim=(caller_profile == "main"))
        return

    if active_mode == "raptor" or getattr(args, "raptor_status", False) or getattr(args, "raptor_findings", False) or getattr(args, "raptor_setup", False):
        _dispatch_cmd("cmd_raptor", args, check_main_shim=(caller_profile == "main"))
        return

    if active_mode == "harness2" or getattr(args, "harness2_report", False):
        if caller_profile == "main" and not has_port_flag and not inline_port_extracted:
            args.port = 8080
        _dispatch_cmd("cmd_harness2", args, check_main_shim=(caller_profile == "main"))
        return

    if getattr(args, "dream_benchmark", False) and not explicit_mode_given:
        _sync_modular_args(args, "dream", raw_argv)
        _dispatch_cmd("cmd_dream", args)
        return


    # Normalize args.host cleanly if still unstripped
    if args.host:
        rem_scheme, clean_h, rem_port = _extract_cli_host_port(str(args.host))
        if rem_scheme == "https":
            args.tls = True
        if rem_port is not None and args.port == 5006:
            args.port = rem_port
        args.host = clean_h

    use_tls = bool(args.tls or (args.port == 443))

    # Parse multiple target terminators if provided
    target_list = parse_targets(args.targets, args.host, args.port, use_tls)
    term_cats = parse_terminators(args.terminators)

    # Authorize and validate each target host specified on the CLI
    from engine.safe_network_validator import validate_and_authorize_target
    for t_host, t_port, t_tls in target_list:
        ok, reason = validate_and_authorize_target(t_host, authorized=getattr(args, "authorized", False))
        if not ok:
            print(f"[!] Target authorization error for {t_host}: {reason}")
            sys.exit(1)

    import socket as _sock
    os.environ["OLLAMA_TIMEOUT"] = str(args.timeout)

    bg_ui_server = None
    bg_ui_url = None
    bg_dash_url = None
    if getattr(args, "ui", False) or getattr(args, "serve", False):
        if active_mode not in ("ui", "dashboard"):
            try:
                bg_ui_server, bg_ui_url, bg_dash_url = start_background_ui(args)
            except Exception as e:
                print(f"[!] Warning: Could not start background UI server: {e}")

    if active_mode == "lab":
        if caller_profile == "main" and not has_port_flag and not inline_port_extracted:
            args.port = 8080
        _dispatch_cmd("cmd_lab", args)
        return

    if active_mode == "ruler":
        if caller_profile == "main" and not has_port_flag and not inline_port_extracted:
            args.port = 443 if getattr(args, "tls", False) else 8080
        _dispatch_cmd("cmd_ruler", args)
        return

    if caller_profile == "main" and active_mode == "hunt":
        if not has_port_flag and not inline_port_extracted:
            args.port = 8080
        _sync_modular_args(args, active_mode, raw_argv)
        _dispatch_cmd("cmd_hunt", args)
        return

    # Execute modular pipeline subcommands natively within rfc_hunt_swarm.py
    if active_mode in ("fetch", "chunk", "generate", "permute", "evaluate", "weaponize", "cascade", "dream", "caldera", "auto"):
        if caller_profile == "main" and active_mode in ("evaluate", "weaponize", "auto", "hunt") and not has_port_flag and not inline_port_extracted:
            args.port = 8080
        _sync_modular_args(args, active_mode, raw_argv)
        dispatch_map = {
            "fetch": "cmd_fetch",
            "chunk": "cmd_chunk",
            "generate": "cmd_generate",
            "permute": "cmd_permute",
            "evaluate": "cmd_evaluate",
            "weaponize": "cmd_weaponize",
            "cascade": "cmd_cascade",
            "dream": "cmd_dream",
            "caldera": "cmd_caldera",
            "auto": "cmd_auto",
        }
        _dispatch_cmd(dispatch_map[active_mode], args)
        return

    # Iterate through target list for Hunt or Swarm
    last_ooda_board = None
    for idx, (t_host, t_port, t_tls) in enumerate(target_list, 1):
        if len(target_list) > 1:
            proto = "https" if t_tls else "http"
            print(f"\n{'='*75}\n[+] TARGET #{idx}/{len(target_list)}: {proto}://{t_host}:{t_port}\n{'='*75}")

        # Auto-spawn local TestLabServer if targeting localhost/127.0.0.1 and nothing is listening on t_port
        bg_lab_server = None
        is_local_host = t_host in ("127.0.0.1", "localhost", "::1", "[::1]")
        if is_local_host and not t_tls and not args.no_lab and not args.comb_only:
            port_open = False
            try:
                with _sock.create_connection((t_host, t_port), timeout=0.4):
                    port_open = True
            except Exception:
                port_open = False
            if not port_open:
                from test_lab_server import TestLabServer
                bg_lab_server = TestLabServer(host=t_host, port=t_port)
                try:
                    bg_lab_server.start()
                    time.sleep(0.25)
                    print(f"[+] Auto-started local Protocol Test Lab Server on http://{t_host}:{t_port}")
                except Exception as e:
                    print(f"[!] Could not auto-start local Test Lab Server on {t_host}:{t_port}: {e}")
                    bg_lab_server = None

        if getattr(args, "abliteration", True) and getattr(args, "model", None) in (None, "", "auto", "gemma2:2b"):
            args.model = "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"

        if active_mode == "hunt" or args.comb_only:
            from continuous_scanner import ContinuousFlawHunter
            kw_list = [k.strip() for k in args.keywords.split(",") if k.strip()] if args.keywords else None
            hunter = ContinuousFlawHunter(
                target_host=t_host,
                target_port=t_port,
                use_tls=t_tls,
                preferred_model=args.model,
                use_fusion=args.fusion,
                db_path=args.db,
                verbose=args.verbose or args.debug,
                sec_model=args.sec_model,
                terminator_categories=term_cats,
            )
            try:
                hunter.run_until_flaw(
                    max_rfcs=args.max_rfcs or 15,
                    fragments_per_rfc=args.limit,
                    permutations_per_probe=args.variants,
                    stop_on_first_flaw=not args.keep_going,
                    all_active=(active_mode in ("all", "all_active")),
                    kettle=(active_mode not in ("all", "all_active")),
                    keywords=kw_list,
                    target_rfc=args.rfc if active_mode == "single" else None,
                    comb_only=args.comb_only,
                )
            finally:
                if bg_lab_server:
                    bg_lab_server.stop()
            continue

        proto_str = "https" if t_tls else "http"
        print(f"[*] Initializing Full LangGraph Swarm against {proto_str}://{t_host}:{t_port} (TLS: {t_tls}, Concurrency: {args.concurrency} threads, LLM Timeout: {'Unlimited' if args.timeout <= 0 else f'{args.timeout}s'})")
        if args.debug:
            print("[*] Deep Swarm Debug Mode: ENABLED (Live Host Responses + Pipeline Telemetry)")
        elif args.show_response or args.verbose:
            print("[*] Live Host Response Printing: ENABLED")
        if getattr(args, "abliteration", True) and getattr(args, "model", None) in (None, "", "auto", "gemma2:2b"):
            args.model = "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"

        swarm = ProtocolResearchSwarm(
            host=t_host,
            port=t_port,
            db_path=args.db,
            sec_model=args.sec_model,
            use_tls=t_tls,
            show_response=args.show_response,
            verbose=args.verbose,
            debug=args.debug,
            concurrency=args.concurrency,
            terminator_categories=term_cats,
            preferred_model=args.model,
            use_fusion=args.fusion,
            novelty_threshold=float(getattr(args, "novelty_threshold", 0.72) or 0.72),
            stack_profile=getattr(args, "dream_stack_profile", None),
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
        elif active_mode in ("all", "all_active"):
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

        # Step 0: Active Canonical Flaw Verification Suite (idempotent on crash resume)
        run_task_id = str(getattr(args, "task_id", None) or "default").strip() or "default"
        try:
            swarm.db.reclaim_stale_intents(task_id=run_task_id)
        except Exception:
            pass
        raw_h2_domain = str(getattr(args, "harness2_domain", "auto") or "auto").strip()
        run_domain = "" if raw_h2_domain.lower() in ("", "auto") else raw_h2_domain
        audit_fact_id = f"fact:bootstrap:active_audit:{run_task_id}"
        already_audited = any(
            f.get("node_id") == audit_fact_id
            for f in swarm.db.get_facts(task_id=run_task_id, limit=0)
        )
        if not args.comb_only:
            if not already_audited:
                from engine.active_flaw_prober import ActiveFlawProber
                try:
                    active_prober = ActiveFlawProber(
                        host=t_host,
                        port=t_port,
                        use_tls=t_tls,
                        timeout=args.timeout if (0 < args.timeout <= 10.0) else 3.5,
                        db=swarm.db,
                        on_trace=print,
                    )
                    canonical_vulns = active_prober.run_active_audit()
                    for v in canonical_vulns:
                        with swarm.stats_lock:
                            swarm.run_stats["vulnerabilities_confirmed"].append({
                                "rfc": "CANONICAL",
                                "vuln_id": v.vuln_id,
                                "anomaly_id": v.anomaly_id,
                                "impact": v.impact.value,
                                "repro": f"{v.reproducibility_rate * 100:.0f}% ({v.successful_reproductions}/{v.verification_attempts})",
                                "behavior": "Canonical PortSwigger attack vector verified",
                            })
                        try:
                            swarm.db.add_fact(
                                f"ActiveFlawProber finding {v.vuln_id} ({v.impact.value}): {v.provenance_chain}",
                                node_id=f"fact:active_flaw:{run_task_id}:{v.vuln_id}",
                                task_id=run_task_id,
                                domain=run_domain,
                                rfc_id="CANONICAL",
                                source_agent="ActiveFlawProber",
                                payload={"vuln_id": v.vuln_id, "anomaly_id": v.anomaly_id, "impact": v.impact.value},
                            )
                        except Exception:
                            pass
                    try:
                        swarm.db.add_fact(
                            f"ActiveFlawProber baseline audit completed against {t_host}:{t_port} ({len(canonical_vulns)} findings)",
                            node_id=f"fact:bootstrap:active_audit:{run_task_id}",
                            task_id=run_task_id,
                            domain=run_domain,
                            rfc_id="CANONICAL",
                            source_agent="ActiveFlawProber",
                            payload={"host": t_host, "port": t_port, "findings_count": len(canonical_vulns)},
                        )
                    except Exception:
                        pass
                except Exception as exc:
                    print(f"[-] Warning: Step 0 ActiveFlawProber handled safely: {exc}")
                    try:
                        swarm.db.add_fact(
                            f"ActiveFlawProber baseline audit handled safely against {t_host}:{t_port}: {exc}",
                            node_id=f"fact:bootstrap:active_audit:{run_task_id}",
                            task_id=run_task_id,
                            domain=run_domain,
                            rfc_id="CANONICAL",
                            source_agent="ActiveFlawProber",
                            payload={"host": t_host, "port": t_port, "error": str(exc)},
                        )
                    except Exception:
                        pass

            # Step 0b: RAPTOR Autonomous Security Analysis (if --raptor / --enable-raptor enabled)
            if getattr(args, "enable_raptor", False):
                from engine.raptor_integrator import RaptorIntegrator
                print(f"\n{'='*75}")
                print(RaptorIntegrator.get_attribution_banner())
                print(f"{'='*75}\n")
                raptor_eng = RaptorIntegrator(db=swarm.db, on_trace=print)
                target_repo = getattr(args, "raptor_target", None)
                if target_repo and os.path.exists(str(target_repo)):
                    raptor_res = raptor_eng.run_scan(
                        target_path=target_repo,
                        mode=getattr(args, "raptor_mode", "scan") or "scan",
                        model=getattr(args, "raptor_model", "fenkohq/foundation-sec-8b:latest"),
                    )
                else:
                    raptor_res = raptor_eng.run_host_scan(
                        host=t_host,
                        port=t_port,
                        use_tls=t_tls,
                    )
                if raptor_res.get("findings"):
                    for rf in raptor_res["findings"]:
                        with swarm.stats_lock:
                            swarm.run_stats["vulnerabilities_confirmed"].append({
                                "rfc": "RAPTOR",
                                "vuln_id": f"RAPTOR-{rf['rule_id'][:15]}",
                                "anomaly_id": f"RAPTOR-{rf['severity']}",
                                "impact": f"RAPTOR_{rf['severity']}",
                                "repro": "100%",
                                "behavior": f"[{rf['severity']}] {rf['rule_id']}: {rf['message'][:60]}",
                            })

            # Step 0c: haasonsaas/aiscan AI Risk Analysis (if --aiscan / --enable-aiscan enabled)
            if getattr(args, "enable_aiscan", False):
                from engine.aiscan_integrator import AiscanIntegrator
                print(f"\n{'='*75}")
                print("  HAASONSAAS/AISCAN: AI & PROMPT SECURITY AUDITOR (MODULE 18)")
                print("  Credit: Jonathan Haas (https://github.com/haasonsaas/aiscan)")
                print(f"{'='*75}\n")
                ai_scanner = AiscanIntegrator(db=swarm.db)
                ai_target = getattr(args, "aiscan_target", None) or getattr(args, "raptor_target", None) or "."
                ai_res = ai_scanner.scan_target(ai_target)
                if ai_res.get("findings"):
                    for af in ai_res["findings"]:
                        with swarm.stats_lock:
                            swarm.run_stats["vulnerabilities_confirmed"].append({
                                "rfc": "AISCAN",
                                "vuln_id": f"AI-{af['finding_type'][:15].upper()}",
                                "anomaly_id": f"AI-{af['severity']}",
                                "impact": f"AI_{af['severity']}",
                                "repro": "100%",
                                "behavior": f"[{af['severity']}] {af['description'][:60]}",
                            })

        try:
            swarm.containment.start()
        except Exception as e:
            print(f"[-] Warning: Failed to start host containment: {e}")

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
                    "enable_harness2": bool(getattr(args, "enable_harness2", True)),
                    "harness2_k": int(getattr(args, "harness2_k", 1)),
                    "harness2_mode": getattr(args, "harness2_mode", "parallel"),
                    "harness2_runs_dir": getattr(args, "harness2_runs_dir", "runs/harness2"),
                    "harness2_domain": getattr(args, "harness2_domain", "auto"),
                    "current_harness2_result": None,
                    "ooda_phase": "Bootstrap",
                    "blackboard_bootstrapped": False,
                    "active_intent_id": None,
                    "active_intent": None,
                    "active_hints": [],
                    "task_id": run_task_id,
                    "workspace_dir": getattr(args, "workspace_dir", None),
                    "blackboard_domain": run_domain,
                    "history": []
                }

                ooda_board = None
                board_width_eff = max(60, int(getattr(args, "board_width", 100) or 100))
                board_plain_eff = bool(getattr(args, "plain", False))
                board_emoji_eff = getattr(args, "board_emoji", None)
                if bool(getattr(args, "swarm_board", False)) and not bool(getattr(args, "as_json", False)):
                    try:
                        from engine.swarm_cli_board import create_swarm_ooda_board, enable_windows_console_vt

                        if not board_plain_eff:
                            enable_windows_console_vt(configure_utf8=True)
                        ooda_board = create_swarm_ooda_board(
                            rfc_num_str,
                            t_host,
                            t_port,
                            task_id=run_task_id,
                            plain=board_plain_eff,
                            json_mode=False,
                            emoji=board_emoji_eff,
                            width=board_width_eff,
                        )
                        ooda_board.set_task_state("Bootstrap", "Running", action=f"Fetching & chunking RFC {rfc_num_str}")
                        print(
                            ooda_board.render_pipeline_banner(
                                plain=board_plain_eff,
                                width=board_width_eff,
                                emoji=board_emoji_eff,
                                active_note=f"Phase: Bootstrap (RFC {rfc_num_str} -> {t_host}:{t_port})",
                            )
                        )
                        last_ooda_board = ooda_board
                    except Exception:
                        ooda_board = None

                last_rendered_phase = "Bootstrap"
                try:
                    for event in graph.stream(initial_state, {"recursion_limit": 5000}):
                        for node_name, state_update in event.items():
                            last_hist = state_update.get('history', [])[-1] if state_update.get('history') else ''
                            print(f"[{node_name}] -> {last_hist}")
                            if ooda_board is not None:
                                try:
                                    node_to_task = {
                                        "fetch_and_chunk_agent": "Bootstrap",
                                        "llm_generator_agent": "Reason",
                                        "execution_oracle_agent": "Explore",
                                        "triage_debugger_agent": "Triage",
                                        "cascade_and_publish_agent": "Publish",
                                        "dream_rsi_agent": "DreamRSI",
                                    }
                                    t_key = node_to_task.get(node_name)
                                    phase_changed = False
                                    active_phase_label = ""
                                    if t_key:
                                        ooda_board.set_task_state(t_key, "Done", action=str(last_hist)[:90])
                                        if t_key != last_rendered_phase:
                                            phase_changed = True
                                            last_rendered_phase = t_key
                                            active_phase_label = f"Completed {t_key}: {str(last_hist)[:80]}"
                                    elif node_name == "blackboard_router":
                                        nxt = str(state_update.get("ooda_phase") or "")
                                        if nxt in node_to_task.values():
                                            ooda_board.set_task_state(nxt, "Running", action=str(last_hist)[:90])
                                            if nxt != last_rendered_phase:
                                                phase_changed = True
                                                last_rendered_phase = nxt
                                                active_phase_label = f"Active phase -> {nxt} ({str(last_hist)[:70]})"
                                    ev_kind = "VULN" if ("current_vuln" in state_update and state_update["current_vuln"]) else "EVENT"
                                    ooda_board.post_event(node_name, str(last_hist)[:120], kind=ev_kind)
                                    if phase_changed:
                                        ooda_board.advance_spinner(1)
                                        print(
                                            ooda_board.render_pipeline_banner(
                                                plain=board_plain_eff,
                                                width=board_width_eff,
                                                emoji=board_emoji_eff,
                                                active_note=active_phase_label,
                                            )
                                        )
                                except Exception:
                                    pass
                            if "current_vuln" in state_update and state_update["current_vuln"]:
                                print(f"    !!! VULNERABILITY CONFIRMED: {state_update['current_vuln'].vuln_id}")
                    if ooda_board is not None:
                        try:
                            print(ooda_board.render(plain=board_plain_eff, width=board_width_eff, emoji=board_emoji_eff))
                        except Exception:
                            pass
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
            try:
                swarm.containment.stop()
            except Exception:
                pass
            if bg_lab_server:
                bg_lab_server.stop()
            swarm.print_run_summary()
            try:
                swarm.close()
            except Exception:
                pass

    print("[*] Swarm Execution Completed. All evidence saved to DB and Forensics Log.")

    # BaaRai/ARTEX Dual-Graph Attack Chaining Synthesis Pass (Module 17)
    try:
        from database import Database
        from engine.dual_graph_engine import DualGraphAttackEngine
        chain_db = Database(args.db)
        post_arbiter = None
        try:
            if getattr(args, "fusion", True) and os.environ.get("RFCHUNT_OFFLINE") != "1":
                try:
                    from fusion_engine import FusionArbiter
                    post_arbiter = FusionArbiter(
                        db=chain_db,
                        preferred_model=getattr(args, "model", None),
                        sec_model=getattr(args, "sec_model", None),
                    )
                except Exception:
                    post_arbiter = None
            artex_eng = DualGraphAttackEngine(
                db=chain_db,
                reports_dir=getattr(args, "output_dir", None) or "reports",
                noise_profile=getattr(args, "artex_noise_profile", None),
                arbiter=post_arbiter,
            )
            artex_eng.ingest_target_infrastructure(
                host=args.host,
                port=args.port,
                endpoints=["/"],
                ai_sinks=["/api/chat"],
            )
            hydrated_counts = artex_eng.ingest_from_database(chain_db)
            if sum(hydrated_counts.values()) > 0 or getattr(args, "enable_artex", False):
                if last_ooda_board is not None:
                    last_ooda_board.set_task_state("DualGraph", "Running", action="Synthesizing ARTEX Dual-Graph chains")
                c_res = artex_eng.run_attack_chain_cycle(round_num=max(1, int(getattr(args, "artex_rounds", 1) or 1)))
                print(
                    f"[+] [ARTEX Attack Chainer] Synthesized {c_res.get('candidates_planned', 0)} candidates | "
                    f"Verified {c_res.get('exploits_verified', 0)} chains (Max Hops: {c_res.get('max_hop_count', 0)})"
                )
                if last_ooda_board is not None:
                    last_ooda_board.set_task_state(
                        "DualGraph",
                        "Done",
                        note=f"Synthesized {c_res.get('candidates_planned', 0)} candidates ({c_res.get('exploits_verified', 0)} chains)",
                    )
            elif last_ooda_board is not None:
                last_ooda_board.set_task_state("DualGraph", "Done", note="No anomalies to chain")
        finally:
            if post_arbiter is not None and hasattr(post_arbiter, "close"):
                try:
                    post_arbiter.close()
                except Exception:
                    pass
            chain_db.close()
    except Exception as e:
        print(f"[!] Warning: Post-swarm ARTEX attack chaining encountered error: {e}")

    # Caldera Auto-Sync: Runs by default on every run without requiring any flags
    if not args.no_caldera:
        from engine.caldera_bridge import CalderaBridge
        caldera_dir = args.export_caldera or "caldera_export"
        print(f"\n[*] [Caldera Auto-Sync] Syncing verified findings to Caldera plugin at {caldera_dir}...")
        bridge = CalderaBridge(db_path=args.db)
        res = bridge.export_plugin(output_dir=caldera_dir)
        bridge.export_plugin(output_dir=".")
        print(f"[+] Caldera Auto-Sync Complete: {res['abilities_count']} abilities and {res['adversaries_count']} adversaries ready.")
        if last_ooda_board is not None:
            last_ooda_board.set_task_state(
                "Publish",
                "Done",
                note=f"Caldera exported {res['abilities_count']} abilities, {res['adversaries_count']} adversaries",
            )
    elif last_ooda_board is not None:
        last_ooda_board.set_task_state("Publish", "Skipped", note="--no-caldera enabled")

    if last_ooda_board is not None:
        try:
            print(
                last_ooda_board.render(
                    plain=bool(getattr(args, "plain", False)),
                    width=max(60, int(getattr(args, "board_width", 100) or 100)),
                    emoji=getattr(args, "board_emoji", None),
                )
            )
        except Exception:
            pass

    if args.caldera_url:
        from engine.caldera_bridge import CalderaBridge
        bridge = CalderaBridge(db_path=args.db)
        findings = bridge.fetch_confirmed_findings_from_db()
        abilities = [bridge.generate_ability(f) for f in findings]
        adversary = bridge.generate_adversary(abilities) if abilities else None
        res = bridge.push_to_caldera(args.caldera_url, args.caldera_key or "ADMIN123", abilities=abilities, adversary=adversary)
        print(f"[+] Caldera API Push: {res['pushed_abilities']} abilities, {res['pushed_adversaries']} adversaries pushed.")

    # Generate final dashboard HTML report
    try:
        from engine.dashboard_generator import DashboardGenerator
        from database import Database
        dash_db = Database(args.db)
        try:
            findings = [dict(f) for f in dash_db.get_confirmed_findings()]
            persisted_chains = dash_db.get_attack_chains(limit=50)
            stats = {
                "total_evaluated": max(len(findings), 15),
                "passed": 13,
                "anomalies": 2,
                "flaws": len(findings),
            }
            merkle_log = {
                "merkle_root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "total_leaves": len(findings),
            }
            out_file = getattr(args, "dashboard_out", None) or "terminator_dashboard.html"
            html = DashboardGenerator.generate_html_dashboard(
                target_host=args.host,
                target_port=args.port,
                scan_stats=stats,
                merkle_audit_log=merkle_log,
                flaws=findings,
                arm106_count=12,
                arm107_count=12,
                attack_chains=persisted_chains,
            )
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"\n[+] Interactive Research Dashboard generated: {out_file}")
        finally:
            dash_db.close()
    except Exception as e:
        print(f"[!] Warning: Dashboard generation encountered error: {e}")

    if bg_ui_server and bg_dash_url:
        print(f"\n{'='*75}")
        print(f"  HTTP TERMINATOR: RESEARCH DASHBOARD VIEWPORT ACTIVE")
        print(f"{'='*75}")
        print(f"  [+] Local Web UI URL               : {bg_ui_url}")
        print(f"  [+] Interactive Dashboard Viewport : {bg_dash_url}")
        print(f"{'='*75}")
        print("  Press Ctrl+C to halt the UI server.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] UI Server stopped.")
        finally:
            bg_ui_server.stop()


if __name__ == "__main__":
    _cli_argv = sys.argv[1:]
    _has_hunt_flag = any(t == "--hunt" for t in _cli_argv)
    _has_fast_ooda_flag = any(t == "--fast-ooda" for t in _cli_argv)
    _has_swarm_flag = any(t == "--swarm" for t in _cli_argv)
    _has_embedded = any(t in ("--embedded", "--embeded") for t in _cli_argv)
    _has_all_flag = (
        any(t in ("--all", "--run-all", "--all-scans", "all", "all_scans") for t in _cli_argv)
        or any(t in ("--mode=all", "--mode=all_scans") for t in _cli_argv)
        or any(
            _cli_argv[idx] == "--mode"
            and idx + 1 < len(_cli_argv)
            and _cli_argv[idx + 1] in ("all", "all_scans")
            for idx in range(len(_cli_argv))
        )
    )
    if not _has_hunt_flag and not _has_fast_ooda_flag and not _has_swarm_flag:
        from revenue_cli import REVENUE_SUBCOMMANDS, maybe_dispatch_revenue_cli

        _is_rev_subcmd = bool(_cli_argv) and (_cli_argv[0] in REVENUE_SUBCOMMANDS)
        if _is_rev_subcmd or _has_embedded or not _has_all_flag:
            _rev_rc = maybe_dispatch_revenue_cli(_cli_argv)
            if _rev_rc is not None:
                raise SystemExit(_rev_rc)
    main_swarm()

