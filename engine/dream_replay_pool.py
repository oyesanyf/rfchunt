"""
Module 13b: Dream-RSI Recorded Discovery Tree Replay Pool.

Clean-room replay-tree simulator inspired by Dream-RSI (Recursive Self-Improvement
through Evolving Worlds). Converts real recorded Cairn `blackboard_nodes` lineages
(`FACT` / `INTENT` / `HINT` connected via `parent_node_id`), SQLite outcome
telemetry (`evaluations`, `reproducible_vulnerabilities`, `implementation_anomalies`,
`attack_chains`), and ARTEX `ExplorationGraph` objects into deterministic,
zero-network, zero-LLM `DiscoveryTree` environments for off-policy meta-exploration
optimization and matched-seed RL benchmarking.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import sqlite3
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

BACKEND_RECORDED_REPLAY = "recorded_blackboard_replay"
BACKEND_LIVE_TESTLAB = "local_testlab_live"
BACKEND_SYNTHETIC_FALLBACK = "synthetic_heuristic_fallback"

REWARD_VULN = 15.0
REWARD_CHAIN = 4.0
REWARD_ANOMALY = 2.0
PENALTY_NOISE = 6.0
PENALTY_STEP = 0.15

_KNOWN_STACK_TOKENS: Tuple[Tuple[str, str], ...] = (
    ("nginx", "nginx"),
    ("envoy", "envoy"),
    ("haproxy", "haproxy"),
    ("apache", "apache"),
    ("httpd", "apache"),
    ("trafficserver", "ats"),
    ("ats", "ats"),
    ("varnish", "varnish"),
    ("cloudflare", "cloudflare"),
    ("caddy", "caddy"),
    ("gunicorn", "python"),
    ("uvicorn", "python"),
    ("werkzeug", "python"),
    ("node", "node"),
    ("express", "node"),
    ("hyper", "rust"),
    ("actix", "rust"),
    ("axum", "rust"),
    ("rust", "rust"),
    ("iis", "iis"),
    ("testlab", "testlab"),
)


def compute_replay_reward(
    vulns: int,
    chains: int,
    anomalies: int,
    noise_discards: int,
    steps_taken: int,
) -> float:
    """
    Explicit off-policy replay reward objective:
      J(pi; T, B) = +15.0 * N_vuln + 4.0 * N_chain + 2.0 * N_anom
                    - 6.0 * N_noise - 0.15 * N_steps
    """
    return (
        REWARD_VULN * float(vulns)
        + REWARD_CHAIN * float(chains)
        + REWARD_ANOMALY * float(anomalies)
        - PENALTY_NOISE * float(noise_discards)
        - PENALTY_STEP * float(steps_taken)
    )


def infer_stack_profile(hints: Sequence[str]) -> str:
    """Infers a normalized stack profile (e.g., nginx, envoy, rust, generic) from telemetry hints."""
    joined = " ".join(str(h or "").strip().lower() for h in hints if h)
    if not joined:
        return "generic"
    for token, profile in _KNOWN_STACK_TOKENS:
        if token in joined:
            return profile
    return "generic"


def infer_mutator_family(
    raw_text: str = "",
    category: str = "",
    payload: Optional[Dict[str, Any]] = None,
) -> str:
    """Extracts or infers the canonical protocol mutation family for a blackboard node."""
    p = payload if isinstance(payload, dict) else {}
    for key in ("mutator_family", "mutation_family", "arm", "arm_name"):
        val = p.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()

    combined = " ".join(
        str(x or "")
        for x in (
            category,
            p.get("category"),
            p.get("desync_class"),
            p.get("attack_type"),
            p.get("raw_request"),
            p.get("minimized_probe"),
            raw_text,
        )
    )
    low = combined.lower()

    if (
        "te_cl" in low
        or "cl_te" in low
        or "cl.te" in low
        or "te.cl" in low
        or "dual_header" in low
        or ("content-length" in low and "transfer-encoding" in low)
        or low.count("content-length:") >= 2
    ):
        return "TE_CL_DUAL_HEADER"
    if "multipart/byteranges" in low or "multipart" in low or "shared_parser" in low:
        return "MULTIPART_BYTERANGES_SHARED_PARSER"
    if "/nul" in low or "path_nul" in low or "early_response" in low:
        return "PATH_NUL_EARLY_RESPONSE"
    if "dangling" in low or "content-length: 1" in low or "stacked_response" in low:
        return "DANGLING_BYTE_STACKED_RESPONSE"
    if "obs_fold" in low or "\r\n " in combined or "\r\n\t" in combined or "line_join" in low:
        return "OBS_FOLD_LINE_JOIN"
    if "overlong" in low or "utf8" in low or "\\xc0\\x8a" in low or "\xc0\x8a" in combined:
        return "OVERLONG_UTF8_NORMALIZATION"
    if "tab_spacing" in low or "colon_whitespace" in low or ":\t" in combined or " :" in combined:
        return "HEADER_TAB_SPACING"
    if "crlf" in low or "delimiter_split" in low:
        return "CRLF_DELIMITER_SPLIT"
    if "chunk_extension" in low or "chunked" in low:
        return "CHUNK_EXTENSION_CORRUPTION"
    if "hop_by_hop" in low or "hop-by-hop" in low:
        return "HOP_BY_HOP_INVERSION"
    if "auth_boundary" in low or "/internal/service" in low or "authorization:" in low:
        return "AUTH_BOUNDARY_BYPASS"
    if "memory_leak" in low or "/leak" in low or "double_html" in low or "inline_headers" in low:
        return "SHARED_PARSER_REVERSAL"
    if "[requirement]" in low or "abnf" in low:
        return "ABNF_INVERSION"
    return "GENERIC_PROBE"


def infer_source_kind(
    node_type: str,
    source_agent: str,
    node_id: str,
    payload: Optional[Dict[str, Any]] = None,
) -> str:
    """Maps a Cairn/ARTEX node to a DreamPolicy `priority_weights` source key."""
    p = payload if isinstance(payload, dict) else {}
    explicit = p.get("source_kind")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    nt = str(node_type or "").strip().upper()
    sa = str(source_agent or "").strip().lower()
    nid = str(node_id or "").strip().lower()
    st = str(p.get("source_type") or "").strip().lower()

    if nt == "HINT" or nid.startswith("hint:"):
        return "hint_boost"
    if st == "cascade" or "cascade" in sa or ":cascade:" in nid:
        return "cascade_intent"
    if (
        st in ("dual_graph", "artex", "multihop")
        or "dual_graph" in sa
        or "artex" in sa
        or nt in ("ATTACK_CANDIDATE", "CONFIRMED_EXPLOIT", "WIRE_PRIMITIVE", "FINDING_PRIMITIVE")
    ):
        return "dual_graph_multihop"
    if st == "abnf" or "fetch_and_chunk" in sa or ":abnf:" in nid:
        return "abnf_seed"
    if nt == "FACT":
        return "cascade_intent" if p.get("vuln_id") or p.get("anomaly_id") else "llm_candidate"
    return "llm_candidate"


def _parse_json_dict(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            decoded = json.loads(raw)
            return decoded if isinstance(decoded, dict) else {"value": decoded}
        except (ValueError, TypeError):
            return {}
    return {}


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class ReplayNode:
    """Single node inside a recorded `DiscoveryTree` replay environment."""

    node_id: str
    parent_node_id: str = ""
    node_type: str = "INTENT"  # FACT, INTENT, HINT, GOAL, ATTACK_CANDIDATE, CONFIRMED_EXPLOIT
    source_agent: str = ""
    domain: str = ""
    rfc_id: str = ""
    mutator_family: str = "GENERIC_PROBE"
    depth: int = 0
    priority: float = 0.0
    step_cost: int = 1
    token_cost: int = 0
    is_anomaly: bool = False
    is_confirmed_vuln: bool = False
    is_attack_chain: bool = False
    is_noise_discard: bool = False
    poe_level: int = 0
    source_kind: str = "llm_candidate"
    status: str = ""
    content: str = ""
    children: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "parent_node_id": self.parent_node_id,
            "node_type": self.node_type,
            "source_agent": self.source_agent,
            "domain": self.domain,
            "rfc_id": self.rfc_id,
            "mutator_family": self.mutator_family,
            "depth": self.depth,
            "priority": float(self.priority),
            "step_cost": int(self.step_cost),
            "token_cost": int(self.token_cost),
            "is_anomaly": bool(self.is_anomaly),
            "is_confirmed_vuln": bool(self.is_confirmed_vuln),
            "is_attack_chain": bool(self.is_attack_chain),
            "is_noise_discard": bool(self.is_noise_discard),
            "poe_level": int(self.poe_level),
            "source_kind": self.source_kind,
            "status": self.status,
            "content": self.content,
            "children": list(self.children),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReplayNode":
        return cls(
            node_id=str(data.get("node_id", "")),
            parent_node_id=str(data.get("parent_node_id", "")),
            node_type=str(data.get("node_type", "INTENT")),
            source_agent=str(data.get("source_agent", "")),
            domain=str(data.get("domain", "")),
            rfc_id=str(data.get("rfc_id", "")),
            mutator_family=str(data.get("mutator_family", "GENERIC_PROBE")),
            depth=int(data.get("depth", 0) or 0),
            priority=float(data.get("priority", 0.0) or 0.0),
            step_cost=max(0, int(data.get("step_cost", 1) if data.get("step_cost") is not None else 1)),
            token_cost=max(0, int(data.get("token_cost", 0) or 0)),
            is_anomaly=bool(data.get("is_anomaly", False)),
            is_confirmed_vuln=bool(data.get("is_confirmed_vuln", False)),
            is_attack_chain=bool(data.get("is_attack_chain", False)),
            is_noise_discard=bool(data.get("is_noise_discard", False)),
            poe_level=int(data.get("poe_level", 0) or 0),
            source_kind=str(data.get("source_kind", "llm_candidate")),
            status=str(data.get("status", "")),
            content=str(data.get("content", "")),
            children=[str(c) for c in (data.get("children") or [])],
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class DiscoveryTree:
    """Rooted per-task discovery tree reconstructed from real recorded execution history."""

    tree_id: str
    task_id: str
    stack_profile: str = "generic"
    nodes: Dict[str, ReplayNode] = field(default_factory=dict)
    root_ids: List[str] = field(default_factory=list)
    source: str = "blackboard_nodes"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def finalize_topology(self) -> "DiscoveryTree":
        """Rebuilds deterministic child adjacency, identifies roots, and computes cycle-safe depths."""
        for node in self.nodes.values():
            node.children = []

        roots: List[str] = []
        for nid, node in self.nodes.items():
            parent = str(node.parent_node_id or "").strip()
            if parent and parent in self.nodes and parent != nid:
                self.nodes[parent].children.append(nid)
            else:
                roots.append(nid)

        # Ensure disconnected cycles still have deterministic entry roots
        visited: Set[str] = set()
        queue: deque[Tuple[str, int]] = deque()
        for r in roots:
            if r not in visited:
                visited.add(r)
                self.nodes[r].depth = 0
                queue.append((r, 0))

        def _drain_bfs() -> None:
            while queue:
                curr_id, d = queue.popleft()
                curr_node = self.nodes[curr_id]
                clean_children: List[str] = []
                for child_id in curr_node.children:
                    if child_id in visited:
                        continue
                    visited.add(child_id)
                    self.nodes[child_id].depth = d + 1
                    clean_children.append(child_id)
                    queue.append((child_id, d + 1))
                curr_node.children = clean_children

        _drain_bfs()

        # Any remaining nodes belong to pure cycles; break deterministically
        for nid in self.nodes:
            if nid not in visited:
                roots.append(nid)
                self.nodes[nid].parent_node_id = ""
                self.nodes[nid].depth = 0
                visited.add(nid)
                queue.append((nid, 0))
                _drain_bfs()

        self.root_ids = roots
        return self

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def max_depth(self) -> int:
        if not self.nodes:
            return 0
        return max(n.depth for n in self.nodes.values())

    def stats(self) -> Dict[str, Any]:
        nodes = list(self.nodes.values())
        return {
            "tree_id": self.tree_id,
            "task_id": self.task_id,
            "stack_profile": self.stack_profile,
            "node_count": len(nodes),
            "root_count": len(self.root_ids),
            "max_depth": self.max_depth,
            "confirmed_vulns": sum(1 for n in nodes if n.is_confirmed_vuln),
            "anomalies": sum(1 for n in nodes if n.is_anomaly and not n.is_confirmed_vuln),
            "attack_chains": sum(1 for n in nodes if n.is_attack_chain),
            "noise_discards": sum(1 for n in nodes if n.is_noise_discard),
            "mutator_families": sorted({n.mutator_family for n in nodes if n.mutator_family}),
            "domains": sorted({n.domain.lower() for n in nodes if n.domain}),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tree_id": self.tree_id,
            "task_id": self.task_id,
            "stack_profile": self.stack_profile,
            "root_ids": list(self.root_ids),
            "source": self.source,
            "metadata": dict(self.metadata),
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoveryTree":
        raw_nodes = data.get("nodes") or {}
        nodes = {nid: ReplayNode.from_dict(nd) for nid, nd in raw_nodes.items()}
        tree = cls(
            tree_id=str(data.get("tree_id", "")),
            task_id=str(data.get("task_id", "")),
            stack_profile=str(data.get("stack_profile", "generic")),
            nodes=nodes,
            root_ids=[str(r) for r in (data.get("root_ids") or [])],
            source=str(data.get("source", "blackboard_nodes")),
            metadata=dict(data.get("metadata") or {}),
        )
        return tree.finalize_topology()


@dataclass
class ReplayOutcome:
    """Result of replaying a single `DiscoveryTree` under a candidate exploration policy."""

    tree_id: str
    policy_name: str
    seed: int
    budget_steps: int
    steps_taken: int
    vulns_found: int
    chains_found: int
    anomalies_found: int
    noise_discards: int
    early_stopped_branches: int
    total_token_cost: int
    reward: float
    vuln_discovery_rate: float  # confirmed vulns per budget step
    vuln_hit_rate: float        # confirmed vulns per executed step
    noise_rate: float           # noise discards per executed step
    visited_node_ids: List[str] = field(default_factory=list)
    simulator_backend: str = BACKEND_RECORDED_REPLAY

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tree_id": self.tree_id,
            "policy_name": self.policy_name,
            "seed": self.seed,
            "budget_steps": self.budget_steps,
            "steps_taken": self.steps_taken,
            "vulns_found": self.vulns_found,
            "chains_found": self.chains_found,
            "anomalies_found": self.anomalies_found,
            "noise_discards": self.noise_discards,
            "early_stopped_branches": self.early_stopped_branches,
            "total_token_cost": self.total_token_cost,
            "reward": round(self.reward, 6),
            "vuln_discovery_rate": round(self.vuln_discovery_rate, 6),
            "vuln_hit_rate": round(self.vuln_hit_rate, 6),
            "noise_rate": round(self.noise_rate, 6),
            "visited_count": len(self.visited_node_ids),
            "simulator_backend": self.simulator_backend,
        }


def _score_node_with_policy(
    policy: Any,
    node: ReplayNode,
    *,
    max_depth: int,
    has_active_hint: bool,
    branch_noise_count: int,
) -> float:
    """Evaluates a frontier `ReplayNode` using `policy.score_intent_priority` or duck-typed attributes."""
    scorer = getattr(policy, "score_intent_priority", None)
    if callable(scorer):
        return float(
            scorer(
                base_priority=node.priority,
                source_kind=node.source_kind,
                domain=node.domain,
                mutator_family=node.mutator_family,
                depth=node.depth,
                max_depth=max_depth,
                has_active_hint=has_active_hint,
                branch_noise_count=branch_noise_count,
            )
        )

    priority_weights = getattr(policy, "priority_weights", None) or {}
    mutator_weights = getattr(policy, "mutator_weights", None) or {}
    domain_weights = getattr(policy, "domain_weights", None) or {}
    alpha = float(getattr(policy, "depth_vs_breadth_alpha", 0.5))
    normative_bias = float(getattr(policy, "normative_bias", 0.5))
    delta_agg = float(getattr(policy, "delta_aggressiveness", 0.5))

    src_w = float(priority_weights.get(node.source_kind, 1.0))
    if mutator_weights:
        n_arms = max(1, len(mutator_weights))
        raw_mw = float(mutator_weights.get(node.mutator_family, 1.0 / n_arms))
        mut_score = raw_mw * n_arms
    else:
        mut_score = 1.0

    dom_key = (node.domain or "").strip().lower()
    dom_w = float(domain_weights.get(dom_key, domain_weights.get(node.domain, 1.0))) if dom_key else 1.0

    depth_norm = min(1.0, max(0.0, float(node.depth)) / float(max(1, max_depth)))
    depth_bias = (2.0 * alpha - 1.0) * depth_norm * 2.5
    hint_bonus = float(priority_weights.get("hint_boost", 1.5)) if has_active_hint else 0.0

    norm_bonus = 0.0
    if node.source_kind == "abnf_seed":
        norm_bonus = (normative_bias - 0.5) * 1.5
    elif node.source_kind in ("llm_candidate", "dual_graph_multihop"):
        norm_bonus = (0.5 - normative_bias) * 1.5

    prio_term = math.tanh(float(node.priority) / 25.0) * 1.5
    noise_penalty = delta_agg * float(branch_noise_count) * 1.25

    return (
        2.5 * mut_score
        + 2.0 * src_w
        + 1.8 * dom_w
        + depth_bias
        + hint_bonus
        + norm_bonus
        + prio_term
        - noise_penalty
    )


class ReplayTreePool:
    """
    Zero-network, zero-LLM recorded discovery-tree simulator pool.

    Ingests historical Cairn `blackboard_nodes` + SQLite outcome tables and
    ARTEX `ExplorationGraph` structures, splits them deterministically into
    disjoint train/validation partitions, and replays alternative meta-exploration
    policies over the recorded trees.
    """

    def __init__(self) -> None:
        self.trees: Dict[str, DiscoveryTree] = {}

    def __len__(self) -> int:
        return len(self.trees)

    @property
    def total_nodes(self) -> int:
        return sum(t.node_count for t in self.trees.values())

    def add_tree(self, tree: DiscoveryTree) -> None:
        tree.finalize_topology()
        self.trees[tree.tree_id] = tree

    def get_tree(self, tree_id: str) -> Optional[DiscoveryTree]:
        return self.trees.get(tree_id)

    def list_trees(self, stack_profile: Optional[str] = None) -> List[DiscoveryTree]:
        ordered = [self.trees[k] for k in sorted(self.trees.keys())]
        if not stack_profile or str(stack_profile).strip().lower() in ("", "generic", "all"):
            return ordered
        target = str(stack_profile).strip().lower()
        return [t for t in ordered if t.stack_profile.lower() == target]

    @staticmethod
    def _existing_tables(conn: sqlite3.Connection) -> Set[str]:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return {str(r[0]) for r in cur.fetchall()}

    def ingest_from_db(
        self,
        db_path_or_db: Any,
        *,
        limit_tasks: int = 100,
        task_id: Optional[str] = None,
    ) -> int:
        """
        Ingests recorded Cairn `blackboard_nodes` lineages (plus outcome joins from
        `evaluations`, `reproducible_vulnerabilities`, `implementation_anomalies`,
        `attack_chains`, `probes`, and `llm_usage`) and persisted `dual_graph_nodes`
        exploration trees. Read-only; never mutates SQLite schema or data.

        Returns the number of `DiscoveryTree` objects ingested/updated.
        """
        conn: Optional[sqlite3.Connection] = None
        owns_conn = False
        db_lock = None

        if isinstance(db_path_or_db, (str, Path)):
            p = Path(db_path_or_db)
            if not p.exists():
                return 0
            conn = sqlite3.connect(str(p))
            conn.row_factory = sqlite3.Row
            owns_conn = True
        elif isinstance(db_path_or_db, sqlite3.Connection):
            conn = db_path_or_db
        elif hasattr(db_path_or_db, "conn") and getattr(db_path_or_db, "conn") is not None:
            conn = db_path_or_db.conn
            db_lock = getattr(db_path_or_db, "_lock", None)
        elif hasattr(db_path_or_db, "get_blackboard_nodes"):
            rows = db_path_or_db.get_blackboard_nodes(task_id=task_id, limit=0)
            return self._ingest_blackboard_rows(rows, limit_tasks=limit_tasks)
        else:
            return 0

        try:
            if db_lock is not None:
                with db_lock:
                    return self._ingest_from_connection(conn, limit_tasks=limit_tasks, task_id=task_id)
            return self._ingest_from_connection(conn, limit_tasks=limit_tasks, task_id=task_id)
        finally:
            if owns_conn and conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def _ingest_from_connection(
        self,
        conn: sqlite3.Connection,
        *,
        limit_tasks: int = 100,
        task_id: Optional[str] = None,
    ) -> int:
        tables = self._existing_tables(conn)
        prev_factory = conn.row_factory
        conn.row_factory = sqlite3.Row
        ingested_count = 0
        try:
            # 1. Load optional outcome telemetry tables for enrichment
            vuln_by_id: Dict[str, Dict[str, Any]] = {}
            vuln_by_anomaly: Dict[str, Dict[str, Any]] = {}
            vuln_by_probe_hash: Dict[str, Dict[str, Any]] = {}
            if "reproducible_vulnerabilities" in tables:
                for row in conn.execute("SELECT * FROM reproducible_vulnerabilities").fetchall():
                    d = dict(row)
                    vid = str(d.get("vuln_id") or "").strip()
                    aid = str(d.get("anomaly_id") or "").strip()
                    mp = str(d.get("minimized_probe") or "").strip()
                    if vid:
                        vuln_by_id[vid] = d
                    if aid:
                        vuln_by_anomaly[aid] = d
                    if mp:
                        vuln_by_probe_hash[_hash_text(mp)] = d

            anom_by_id: Dict[str, Dict[str, Any]] = {}
            if "implementation_anomalies" in tables:
                for row in conn.execute("SELECT * FROM implementation_anomalies").fetchall():
                    d = dict(row)
                    aid = str(d.get("anomaly_id") or "").strip()
                    if aid:
                        anom_by_id[aid] = d

            eval_by_id: Dict[int, Dict[str, Any]] = {}
            eval_by_probe_id: Dict[int, Dict[str, Any]] = {}
            eval_by_req_hash: Dict[str, Dict[str, Any]] = {}
            if "evaluations" in tables:
                if "probes" in tables:
                    sql = (
                        "SELECT e.*, p.raw_request AS probe_raw_request, p.source_type AS probe_source_type "
                        "FROM evaluations e LEFT JOIN probes p ON e.probe_id = p.probe_id"
                    )
                else:
                    sql = "SELECT e.*, NULL AS probe_raw_request, NULL AS probe_source_type FROM evaluations e"
                for row in conn.execute(sql).fetchall():
                    d = dict(row)
                    if d.get("eval_id") is not None:
                        eval_by_id[int(d["eval_id"])] = d
                    if d.get("probe_id") is not None:
                        eval_by_probe_id[int(d["probe_id"])] = d
                    raw_req = str(d.get("probe_raw_request") or "").strip()
                    if raw_req:
                        eval_by_req_hash[_hash_text(raw_req)] = d

            chains_by_id: Dict[str, Dict[str, Any]] = {}
            chains_by_anomaly: Dict[str, Dict[str, Any]] = {}
            chains_by_task: Dict[str, List[Dict[str, Any]]] = {}
            if "attack_chains" in tables:
                for row in conn.execute("SELECT * FROM attack_chains").fetchall():
                    d = dict(row)
                    cid = str(d.get("chain_id") or "").strip()
                    aid = str(d.get("framing_anomaly_id") or "").strip()
                    tid = str(d.get("task_id") or "default").strip()
                    if cid:
                        chains_by_id[cid] = d
                    if aid:
                        chains_by_anomaly[aid] = d
                    chains_by_task.setdefault(tid, []).append(d)

            tokens_by_task: Dict[str, int] = {}
            if "llm_usage" in tables:
                for row in conn.execute(
                    "SELECT task_id, SUM(COALESCE(total_tokens, 0)) AS tok FROM llm_usage GROUP BY task_id"
                ).fetchall():
                    tid = str(row["task_id"] or "default")
                    tokens_by_task[tid] = int(row["tok"] or 0)

            # 2. Ingest blackboard_nodes grouped by task_id
            ingested_task_ids: Set[str] = set()
            if "blackboard_nodes" in tables:
                if task_id:
                    cur = conn.execute(
                        "SELECT * FROM blackboard_nodes WHERE task_id = ? ORDER BY id ASC",
                        (str(task_id),),
                    )
                else:
                    cur = conn.execute("SELECT * FROM blackboard_nodes ORDER BY id ASC")
                bb_rows = [dict(r) for r in cur.fetchall()]
                ingested_count += self._ingest_blackboard_rows(
                    bb_rows,
                    limit_tasks=limit_tasks,
                    vuln_by_id=vuln_by_id,
                    vuln_by_anomaly=vuln_by_anomaly,
                    vuln_by_probe_hash=vuln_by_probe_hash,
                    anom_by_id=anom_by_id,
                    eval_by_id=eval_by_id,
                    eval_by_probe_id=eval_by_probe_id,
                    eval_by_req_hash=eval_by_req_hash,
                    chains_by_id=chains_by_id,
                    chains_by_anomaly=chains_by_anomaly,
                    chains_by_task=chains_by_task,
                    tokens_by_task=tokens_by_task,
                    ingested_task_ids=ingested_task_ids,
                )

            # 3. Also ingest persisted ARTEX dual_graph EXPLORATION trees for tasks not already covered
            if "dual_graph_nodes" in tables and len(ingested_task_ids) < limit_tasks:
                dg_rows = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM dual_graph_nodes WHERE UPPER(graph_type) = 'EXPLORATION'"
                    ).fetchall()
                ]
                if dg_rows:
                    dg_edges = []
                    if "dual_graph_edges" in tables:
                        dg_edges = [dict(r) for r in conn.execute("SELECT * FROM dual_graph_edges").fetchall()]
                    ingested_count += self._ingest_dual_graph_rows(
                        dg_rows,
                        dg_edges,
                        skip_tasks=ingested_task_ids,
                        limit_tasks=max(0, limit_tasks - len(ingested_task_ids)),
                        filter_task_id=task_id,
                    )

            return ingested_count
        finally:
            conn.row_factory = prev_factory

    def _ingest_blackboard_rows(
        self,
        rows: List[Dict[str, Any]],
        *,
        limit_tasks: int = 100,
        vuln_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
        vuln_by_anomaly: Optional[Dict[str, Dict[str, Any]]] = None,
        vuln_by_probe_hash: Optional[Dict[str, Dict[str, Any]]] = None,
        anom_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
        eval_by_id: Optional[Dict[int, Dict[str, Any]]] = None,
        eval_by_probe_id: Optional[Dict[int, Dict[str, Any]]] = None,
        eval_by_req_hash: Optional[Dict[str, Dict[str, Any]]] = None,
        chains_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
        chains_by_anomaly: Optional[Dict[str, Dict[str, Any]]] = None,
        chains_by_task: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        tokens_by_task: Optional[Dict[str, int]] = None,
        ingested_task_ids: Optional[Set[str]] = None,
    ) -> int:
        if not rows:
            return 0

        vuln_by_id = vuln_by_id or {}
        vuln_by_anomaly = vuln_by_anomaly or {}
        vuln_by_probe_hash = vuln_by_probe_hash or {}
        anom_by_id = anom_by_id or {}
        eval_by_id = eval_by_id or {}
        eval_by_probe_id = eval_by_probe_id or {}
        eval_by_req_hash = eval_by_req_hash or {}
        chains_by_id = chains_by_id or {}
        chains_by_anomaly = chains_by_anomaly or {}
        chains_by_task = chains_by_task or {}
        tokens_by_task = tokens_by_task or {}

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        task_order: List[str] = []
        for row in rows:
            tid = str(row.get("task_id") or "default").strip() or "default"
            if tid not in grouped:
                grouped[tid] = []
                task_order.append(tid)
            grouped[tid].append(row)

        ingested = 0
        for tid in task_order[:limit_tasks]:
            task_rows = grouped[tid]
            if not task_rows:
                continue

            # Pre-scan which vuln_ids / anomaly_ids / chain_ids already have dedicated nodes
            # so parent INTENT nodes don't double-count the same confirmed vulnerability or chain.
            dedicated_vuln_ids: Set[str] = set()
            dedicated_vuln_anomalies: Set[str] = set()
            dedicated_chain_ids: Set[str] = set()
            stack_hints: List[str] = []

            decoded_rows: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
            for r in task_rows:
                payload = r.get("payload") if isinstance(r.get("payload"), dict) else _parse_json_dict(r.get("payload_json"))
                decoded_rows.append((r, payload))
                nt = str(r.get("node_type") or "INTENT").strip().upper()
                cid_pre = str(payload.get("chain_id") or "").strip()
                if cid_pre:
                    dedicated_chain_ids.add(cid_pre)
                if nt == "FACT":
                    vid = str(payload.get("vuln_id") or "").strip()
                    aid = str(payload.get("anomaly_id") or "").strip()
                    if vid:
                        dedicated_vuln_ids.add(vid)
                        if aid:
                            dedicated_vuln_anomalies.add(aid)
                for sk in ("stack_profile", "target_engine", "server", "server_header"):
                    sv = payload.get(sk)
                    if isinstance(sv, str) and sv.strip():
                        stack_hints.append(sv.strip())
                if r.get("domain"):
                    stack_hints.append(str(r["domain"]))

            # Estimate average token cost per node if llm_usage recorded task tokens
            task_tokens = tokens_by_task.get(tid, 0)
            avg_node_tokens = int(task_tokens // max(1, len(decoded_rows))) if task_tokens > 0 else 0

            nodes: Dict[str, ReplayNode] = {}
            for r, payload in decoded_rows:
                nid = str(r.get("node_id") or "").strip()
                if not nid:
                    continue
                nt = str(r.get("node_type") or "INTENT").strip().upper()
                status = str(r.get("status") or "").strip().upper()
                parent_id = str(r.get("parent_node_id") or "").strip()
                source_agent = str(r.get("source_agent") or "").strip()
                domain = str(r.get("domain") or "").strip()
                rfc_id = str(r.get("rfc_id") or "").strip()
                content = str(r.get("content") or "")
                priority = float(r.get("priority") or 0.0)

                outcome_str = str(payload.get("outcome") or "").strip().upper()
                vid = str(payload.get("vuln_id") or "").strip()
                aid = str(payload.get("anomaly_id") or "").strip()
                cid = str(payload.get("chain_id") or "").strip()
                category = str(payload.get("category") or payload.get("desync_class") or "").strip()
                raw_req = str(payload.get("raw_request") or payload.get("minimized_probe") or content).strip()
                req_hash = _hash_text(raw_req) if raw_req else ""

                is_anomaly = bool(payload.get("is_anomaly", False))
                is_confirmed_vuln = bool(payload.get("is_confirmed_vuln", False))
                is_attack_chain = bool(payload.get("is_attack_chain", False))
                is_noise_discard = bool(
                    payload.get("is_noise_discard", False) or payload.get("is_environmental_noise", False)
                )
                poe_level = int(payload.get("poe_level", 0) or 0)

                # Explicit outcome labels from Cairn agents
                if outcome_str in ("ANOMALY", "DESYNC", "SUSPICIOUS"):
                    is_anomaly = True
                elif outcome_str in ("VULNERABLE", "CONFIRMED", "CONFIRMED_VULN"):
                    is_confirmed_vuln = True
                    is_anomaly = True
                elif outcome_str in ("NOISE", "DISCARDED", "FALSE_POSITIVE", "ARTIFACT", "FAILED"):
                    is_noise_discard = True
                    is_confirmed_vuln = False

                if status == "FAILED" or nid.startswith("fact:failed:"):
                    is_noise_discard = True

                # Direct FACT signals
                if nt == "FACT":
                    if nid.startswith("fact:vuln:") or nid.startswith("fact:active_flaw:") or bool(vid):
                        is_confirmed_vuln = True
                        is_anomaly = True
                        repro = float(payload.get("reproducibility_rate") or 0.0)
                        if repro >= 0.66:
                            poe_level = max(poe_level, 3)
                    elif nid.startswith("fact:anomaly:"):
                        is_anomaly = True
                    elif nid.startswith("fact:noise:") or nid.startswith("fact:discard:"):
                        is_noise_discard = True

                # Join reproducible_vulnerabilities
                vuln_row = None
                if vid and vid in vuln_by_id:
                    vuln_row = vuln_by_id[vid]
                elif aid and aid in vuln_by_anomaly:
                    if nt == "FACT" or aid not in dedicated_vuln_anomalies:
                        vuln_row = vuln_by_anomaly[aid]
                elif req_hash and req_hash in vuln_by_probe_hash:
                    v_cand = vuln_by_probe_hash[req_hash]
                    if nt == "FACT" or str(v_cand.get("vuln_id") or "") not in dedicated_vuln_ids:
                        vuln_row = v_cand

                if vuln_row is not None:
                    repro = float(vuln_row.get("reproducibility_rate") or 0.0)
                    if repro >= 0.66 or repro == 0.0:
                        is_confirmed_vuln = True
                        is_anomaly = True
                        poe_level = max(poe_level, 3 if repro >= 0.66 else 2)

                # Join implementation_anomalies
                if aid and aid in anom_by_id:
                    anom_row = anom_by_id[aid]
                    if anom_row.get("target_engine"):
                        stack_hints.append(str(anom_row["target_engine"]))
                    if anom_row.get("category") and not category:
                        category = str(anom_row["category"])
                    if bool(anom_row.get("is_environmental_noise")):
                        is_noise_discard = True
                        is_confirmed_vuln = False
                    else:
                        is_anomaly = True

                # Join evaluations
                eval_row = None
                if payload.get("eval_id") is not None:
                    try:
                        eval_row = eval_by_id.get(int(payload["eval_id"]))
                    except (ValueError, TypeError):
                        eval_row = None
                if eval_row is None and payload.get("probe_id") is not None:
                    try:
                        eval_row = eval_by_probe_id.get(int(payload["probe_id"]))
                    except (ValueError, TypeError):
                        eval_row = None
                if eval_row is None and req_hash and req_hash in eval_by_req_hash:
                    eval_row = eval_by_req_hash[req_hash]

                if eval_row is not None:
                    f_status = str(eval_row.get("finding_status") or "").strip().upper()
                    desync_cls = str(eval_row.get("desync_class") or "").strip()
                    if desync_cls and not category:
                        category = desync_cls
                    if f_status in ("FALSE_POSITIVE", "DISCARDED", "NOISE"):
                        is_noise_discard = True
                        is_confirmed_vuln = False
                    elif bool(eval_row.get("is_vulnerable")):
                        is_anomaly = True
                        # Avoid double-counting a confirmed vuln on a parent INTENT when a child FACT owns it
                        if nt == "FACT" or not (aid and aid in dedicated_vuln_anomalies):
                            is_confirmed_vuln = True
                            poe_level = max(poe_level, 3 if f_status == "CONFIRMED" else 2)
                    elif desync_cls:
                        is_anomaly = True

                # Join attack_chains
                chain_row = None
                if cid and cid in chains_by_id:
                    chain_row = chains_by_id[cid]
                elif aid and aid in chains_by_anomaly:
                    cand_chain = chains_by_anomaly[aid]
                    cand_cid = str(cand_chain.get("chain_id") or "").strip()
                    if not (cand_cid and cand_cid in dedicated_chain_ids):
                        chain_row = cand_chain

                if chain_row is not None:
                    is_attack_chain = True
                    chain_poe = int(chain_row.get("poe_level") or 0)
                    poe_level = max(poe_level, chain_poe)
                    if bool(chain_row.get("is_verified")) or chain_poe >= 3:
                        is_confirmed_vuln = True
                        is_anomaly = True

                # Ensure noise discard takes precedence if explicitly flagged without confirmation
                if is_noise_discard and not is_confirmed_vuln:
                    is_anomaly = False

                mutator = infer_mutator_family(raw_text=raw_req, category=category, payload=payload)
                source_kind = infer_source_kind(nt, source_agent, nid, payload)
                step_cost = int(payload.get("step_cost", 0 if nt == "HINT" else 1))
                token_cost = int(payload.get("token_cost", avg_node_tokens) or 0)

                nodes[nid] = ReplayNode(
                    node_id=nid,
                    parent_node_id=parent_id,
                    node_type=nt,
                    source_agent=source_agent,
                    domain=domain,
                    rfc_id=rfc_id,
                    mutator_family=mutator,
                    depth=0,
                    priority=priority,
                    step_cost=max(0, step_cost),
                    token_cost=max(0, token_cost),
                    is_anomaly=is_anomaly,
                    is_confirmed_vuln=is_confirmed_vuln,
                    is_attack_chain=is_attack_chain,
                    is_noise_discard=is_noise_discard,
                    poe_level=poe_level,
                    source_kind=source_kind,
                    status=status,
                    content=content[:500],
                    metadata={
                        "category": category,
                        "vuln_id": vid,
                        "anomaly_id": aid,
                        "chain_id": cid,
                    },
                )

            if not nodes:
                continue

            # Attach task-level attack_chains that were not linked via payload
            for ch in chains_by_task.get(tid, []):
                cid = str(ch.get("chain_id") or "").strip()
                if not cid:
                    continue
                ch_nid = f"chain:{cid}"
                if ch_nid in nodes or any(n.metadata.get("chain_id") == cid for n in nodes.values()):
                    continue
                parent_aid = str(ch.get("framing_anomaly_id") or "").strip()
                parent_nid = ""
                if parent_aid:
                    for existing in nodes.values():
                        if existing.metadata.get("anomaly_id") == parent_aid:
                            parent_nid = existing.node_id
                            break
                ch_poe = int(ch.get("poe_level") or 0)
                ch_verified = bool(ch.get("is_verified")) or ch_poe >= 3
                nodes[ch_nid] = ReplayNode(
                    node_id=ch_nid,
                    parent_node_id=parent_nid,
                    node_type="ATTACK_CANDIDATE" if not ch_verified else "CONFIRMED_EXPLOIT",
                    source_agent="DualGraphAttackEngine",
                    domain=str(ch.get("target_host") or ""),
                    rfc_id="",
                    mutator_family=infer_mutator_family(category=str(ch.get("attack_type") or "")),
                    depth=0,
                    priority=20.0 + float(ch_poe * 5),
                    step_cost=1,
                    token_cost=avg_node_tokens,
                    is_anomaly=True,
                    is_confirmed_vuln=ch_verified,
                    is_attack_chain=True,
                    is_noise_discard=False,
                    poe_level=ch_poe,
                    source_kind="dual_graph_multihop",
                    status=str(ch.get("verification_status") or ""),
                    content=str(ch.get("title") or "")[:300],
                    metadata={"chain_id": cid, "attack_type": str(ch.get("attack_type") or "")},
                )

            tree = DiscoveryTree(
                tree_id=f"bb:{tid}",
                task_id=tid,
                stack_profile=infer_stack_profile(stack_hints),
                nodes=nodes,
                source="blackboard_nodes",
                metadata={"row_count": len(task_rows)},
            ).finalize_topology()
            self.trees[tree.tree_id] = tree
            if ingested_task_ids is not None:
                ingested_task_ids.add(tid)
            ingested += 1

        return ingested

    def _ingest_dual_graph_rows(
        self,
        dg_rows: List[Dict[str, Any]],
        dg_edges: List[Dict[str, Any]],
        *,
        skip_tasks: Set[str],
        limit_tasks: int,
        filter_task_id: Optional[str] = None,
    ) -> int:
        if limit_tasks <= 0:
            return 0

        grouped_nodes: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for row in dg_rows:
            attrs = _parse_json_dict(row.get("attributes_json"))
            tid = str(attrs.get("task_id") or "default").strip() or "default"
            if filter_task_id and tid != filter_task_id:
                continue
            if tid in skip_tasks:
                continue
            nid = str(row.get("node_id") or "").strip()
            if not nid:
                continue
            grouped_nodes.setdefault(tid, {})[nid] = {
                "node_id": nid,
                "node_type": str(row.get("node_type") or "INTENT").upper(),
                "label": str(row.get("label") or ""),
                "status": str(attrs.get("status") or ""),
                "attributes": attrs,
            }

        parent_by_child: Dict[str, str] = {}
        for edge in dg_edges:
            rel = str(edge.get("relationship") or "").strip().lower()
            src = str(edge.get("source_id") or "").strip()
            dst = str(edge.get("target_id") or "").strip()
            if not src or not dst or src == dst:
                continue
            if rel in ("spawns", "yields", "proves", "contains", "dispatches_to"):
                parent_by_child.setdefault(dst, src)
            elif rel in ("derived_from", "chains_from"):
                parent_by_child.setdefault(src, dst)

        ingested = 0
        for tid in sorted(grouped_nodes.keys())[:limit_tasks]:
            task_map = grouped_nodes[tid]
            nodes: Dict[str, ReplayNode] = {}
            stack_hints: List[str] = []
            for nid, info in task_map.items():
                attrs = info["attributes"]
                nt = info["node_type"]
                st = info["status"].upper()
                parent_id = parent_by_child.get(nid, "")
                if parent_id not in task_map:
                    parent_id = ""

                poe = int(attrs.get("poe_level", 0) or 0)
                is_chain = nt in ("ATTACK_CANDIDATE", "CONFIRMED_EXPLOIT") or bool(attrs.get("is_attack_chain"))
                is_vuln = (
                    nt == "CONFIRMED_EXPLOIT"
                    or bool(attrs.get("is_confirmed_vuln"))
                    or poe >= 3
                    or (nt in ("FINDING", "FACT") and st == "PROVEN")
                )
                is_anom = (
                    is_vuln
                    or nt in ("WIRE_PRIMITIVE", "FINDING_PRIMITIVE", "FINDING")
                    or bool(attrs.get("is_anomaly"))
                )
                is_noise = (st == "FAILED" or bool(attrs.get("is_noise")) or bool(attrs.get("is_noise_discard"))) and not is_vuln
                if is_noise:
                    is_anom = False

                for sk in ("stack_profile", "target_engine", "server"):
                    if attrs.get(sk):
                        stack_hints.append(str(attrs[sk]))

                nodes[nid] = ReplayNode(
                    node_id=nid,
                    parent_node_id=parent_id,
                    node_type=nt,
                    source_agent=str(attrs.get("source_agent") or "DualGraphAttackEngine"),
                    domain=str(attrs.get("domain") or ""),
                    rfc_id=str(attrs.get("rfc_id") or ""),
                    mutator_family=infer_mutator_family(raw_text=info["label"], payload=attrs),
                    depth=0,
                    priority=float(attrs.get("priority", 10.0 if is_chain else 5.0) or 0.0),
                    step_cost=0 if nt in ("GOAL", "HINT") else 1,
                    token_cost=int(attrs.get("token_cost", 0) or 0),
                    is_anomaly=is_anom,
                    is_confirmed_vuln=is_vuln,
                    is_attack_chain=is_chain,
                    is_noise_discard=is_noise,
                    poe_level=poe,
                    source_kind=infer_source_kind(nt, "DualGraphAttackEngine", nid, attrs),
                    status=st,
                    content=info["label"][:500],
                    metadata=dict(attrs),
                )

            if not nodes:
                continue
            tree = DiscoveryTree(
                tree_id=f"eg:{tid}",
                task_id=tid,
                stack_profile=infer_stack_profile(stack_hints),
                nodes=nodes,
                source="exploration_graph",
            ).finalize_topology()
            self.trees[tree.tree_id] = tree
            ingested += 1

        return ingested

    def ingest_exploration_graph(
        self,
        exploration_graph: Any,
        task_id: Optional[str] = None,
        stack_profile: str = "generic",
    ) -> int:
        """
        Ingests an in-memory ARTEX `ExplorationGraph` object (`nodes` + `edges`)
        into a `DiscoveryTree`. Returns 1 if a non-empty tree was added, else 0.
        """
        raw_nodes = getattr(exploration_graph, "nodes", None)
        raw_edges = getattr(exploration_graph, "edges", None) or []
        if not raw_nodes or not isinstance(raw_nodes, dict):
            return 0

        resolved_task = str(task_id or getattr(exploration_graph, "task_id", "default") or "default").strip()

        # Build parent map avoiding derived_from/yields 2-cycles
        parent_by_child: Dict[str, str] = {}
        for edge in raw_edges:
            src = str(getattr(edge, "source_id", "") or "").strip()
            dst = str(getattr(edge, "target_id", "") or "").strip()
            rel = str(getattr(edge, "relationship", "") or "").strip().lower()
            if not src or not dst or src == dst:
                continue
            if rel in ("spawns", "yields", "proves", "contains", "dispatches_to"):
                if dst in raw_nodes and src in raw_nodes:
                    parent_by_child.setdefault(dst, src)
            elif rel in ("derived_from", "chains_from"):
                if src in raw_nodes and dst in raw_nodes:
                    parent_by_child.setdefault(src, dst)

        nodes: Dict[str, ReplayNode] = {}
        stack_hints: List[str] = [stack_profile] if stack_profile and stack_profile != "generic" else []

        for nid, enode in raw_nodes.items():
            nid_s = str(nid)
            nt = str(getattr(enode, "node_type", "INTENT") or "INTENT").strip().upper()
            st = str(getattr(enode, "status", "") or "").strip().upper()
            label = str(getattr(enode, "label", "") or "")
            attrs = dict(getattr(enode, "attributes", None) or {})
            parent_id = parent_by_child.get(nid_s, "")

            poe = int(attrs.get("poe_level", 0) or 0)
            is_chain = nt in ("ATTACK_CANDIDATE", "CONFIRMED_EXPLOIT") or bool(attrs.get("is_attack_chain"))
            is_vuln = (
                nt == "CONFIRMED_EXPLOIT"
                or bool(attrs.get("is_confirmed_vuln"))
                or poe >= 3
                or (nt in ("FINDING", "FACT") and st == "PROVEN")
            )
            is_anom = (
                is_vuln
                or nt in ("WIRE_PRIMITIVE", "FINDING_PRIMITIVE", "FINDING")
                or bool(attrs.get("is_anomaly"))
            )
            is_noise = (
                st == "FAILED"
                or bool(attrs.get("is_noise"))
                or bool(attrs.get("is_noise_discard"))
            ) and not is_vuln
            if is_noise:
                is_anom = False

            for sk in ("stack_profile", "target_engine", "server"):
                if attrs.get(sk):
                    stack_hints.append(str(attrs[sk]))

            nodes[nid_s] = ReplayNode(
                node_id=nid_s,
                parent_node_id=parent_id,
                node_type=nt,
                source_agent=str(attrs.get("source_agent") or "DualGraphAttackEngine"),
                domain=str(attrs.get("domain") or ""),
                rfc_id=str(attrs.get("rfc_id") or ""),
                mutator_family=infer_mutator_family(raw_text=label, payload=attrs),
                depth=0,
                priority=float(attrs.get("priority", 10.0 if is_chain else 5.0) or 0.0),
                step_cost=int(attrs.get("step_cost", 0 if nt in ("GOAL", "HINT") else 1)),
                token_cost=int(attrs.get("token_cost", 0) or 0),
                is_anomaly=is_anom,
                is_confirmed_vuln=is_vuln,
                is_attack_chain=is_chain,
                is_noise_discard=is_noise,
                poe_level=poe,
                source_kind=infer_source_kind(nt, "DualGraphAttackEngine", nid_s, attrs),
                status=st,
                content=label[:500],
                metadata=attrs,
            )

        resolved_stack = stack_profile if (stack_profile and stack_profile != "generic") else infer_stack_profile(stack_hints)
        tree = DiscoveryTree(
            tree_id=f"eg:{resolved_task}",
            task_id=resolved_task,
            stack_profile=resolved_stack,
            nodes=nodes,
            source="exploration_graph",
        ).finalize_topology()
        self.trees[tree.tree_id] = tree
        return 1

    def split_train_val(
        self,
        val_ratio: float = 0.25,
        seed: int = 42,
        *,
        stack_profile: Optional[str] = None,
    ) -> Tuple[List[DiscoveryTree], List[DiscoveryTree]]:
        """
        Deterministically partitions recorded trees into strictly disjoint
        `(train_trees, val_trees)` sets.
        """
        trees = self.list_trees(stack_profile=stack_profile)
        if not trees:
            return ([], [])
        if len(trees) == 1:
            return (list(trees), [])

        ordered = list(trees)
        rng = random.Random(int(seed))
        rng.shuffle(ordered)

        clamped_ratio = max(0.05, min(0.8, float(val_ratio)))
        n_val = max(1, min(len(ordered) - 1, int(round(len(ordered) * clamped_ratio))))
        return (ordered[:-n_val], ordered[-n_val:])

    @staticmethod
    def _compute_branch_keys(tree: DiscoveryTree) -> Dict[str, str]:
        """Assigns each node to a logical subtree branch key for early-stop tracking."""
        branch_keys: Dict[str, str] = {}
        single_root = len(tree.root_ids) == 1
        root_set = set(tree.root_ids)

        queue: deque[Tuple[str, str]] = deque()
        for rid in tree.root_ids:
            if single_root:
                branch_keys[rid] = f"root:{rid}"
            else:
                rnode = tree.nodes[rid]
                tag = rnode.rfc_id or rnode.domain or rid
                branch_keys[rid] = f"{rid}:{tag}"
            queue.append((rid, branch_keys[rid]))

        while queue:
            curr_id, curr_key = queue.popleft()
            curr_node = tree.nodes[curr_id]
            for child_id in curr_node.children:
                cnode = tree.nodes[child_id]
                if single_root and curr_id in root_set:
                    tag = cnode.rfc_id or cnode.domain or child_id
                    ckey = f"{child_id}:{tag}"
                else:
                    ckey = curr_key
                branch_keys[child_id] = ckey
                queue.append((child_id, ckey))

        return branch_keys

    def simulate_policy_traversal(
        self,
        tree: DiscoveryTree,
        policy: Any,
        budget_steps: int = 50,
        seed: int = 42,
        *,
        mode: str = "policy",
        policy_name: Optional[str] = None,
    ) -> ReplayOutcome:
        """
        Deterministically replays an existing `DiscoveryTree` under an alternative
        meta-exploration schedule. Performs zero network I/O and zero LLM calls.

        Supported `mode` values:
          - "policy": meta-exploration scheduling driven by `policy`
          - "nolearning": identical engine driven by a frozen Gen-0 `policy`
          - "disabled": unguided FIFO BFS traversal without pruning or early-stop
          - "random": uniform random frontier selection without early-stop
          - "heuristic": static priority + online per-episode UCB1 without learned priors
        """
        mode_norm = str(mode or "policy").strip().lower()
        p_name = policy_name or (
            f"DreamPolicy_gen{getattr(policy, 'generation', 0)}"
            if mode_norm in ("policy", "nolearning") and policy is not None
            else mode_norm
        )
        budget = max(1, int(budget_steps))

        if not tree.nodes:
            return ReplayOutcome(
                tree_id=tree.tree_id,
                policy_name=p_name,
                seed=int(seed),
                budget_steps=budget,
                steps_taken=0,
                vulns_found=0,
                chains_found=0,
                anomalies_found=0,
                noise_discards=0,
                early_stopped_branches=0,
                total_token_cost=0,
                reward=0.0,
                vuln_discovery_rate=0.0,
                vuln_hit_rate=0.0,
                noise_rate=0.0,
                visited_node_ids=[],
                simulator_backend=BACKEND_RECORDED_REPLAY,
            )

        if not tree.root_ids:
            tree.finalize_topology()

        rng = random.Random(int(seed))
        max_depth = max(1, tree.max_depth)
        branch_keys = self._compute_branch_keys(tree)
        single_root_id = tree.root_ids[0] if len(tree.root_ids) == 1 else None

        # Policy meta-controls
        if mode_norm in ("disabled", "random"):
            branch_width = 10**6
            parallel_group_size = 1
            early_stop_patience = 10**6
        elif mode_norm == "heuristic":
            branch_width = 4
            parallel_group_size = 4
            early_stop_patience = 5
        else:
            branch_width = max(1, int(getattr(policy, "branch_width", 3) or 3))
            parallel_group_size = max(1, int(getattr(policy, "parallel_group_size", 4) or 4))
            early_stop_patience = max(1, int(getattr(policy, "early_stop_patience", 4) or 4))

        frontier: List[str] = list(tree.root_ids)
        in_frontier: Set[str] = set(frontier)
        visited: Set[str] = set()
        visited_order: List[str] = []

        # Per-branch early-stop tracking
        branch_dead_streak: Dict[str, int] = {}
        branch_noise_count: Dict[str, int] = {}
        pruned_branches: Set[str] = set()
        active_hint_scopes: Set[Tuple[str, str]] = set()

        # Online per-episode UCB1 state for "heuristic" mode
        ucb_pulls: Dict[str, int] = {}
        ucb_rewards: Dict[str, float] = {}
        ucb_total_pulls = 0

        steps_taken = 0
        vulns_found = 0
        chains_found = 0
        anomalies_found = 0
        noise_discards = 0
        early_stopped_branches = 0
        total_token_cost = 0

        def _has_active_hint(nd: ReplayNode) -> bool:
            dom = nd.domain.lower()
            rfc = nd.rfc_id.lower()
            return (
                (dom, rfc) in active_hint_scopes
                or (dom, "") in active_hint_scopes
                or ("global", "") in active_hint_scopes
                or ("", rfc) in active_hint_scopes
            )

        def _score_candidate(nid: str) -> float:
            nd = tree.nodes[nid]
            bkey = branch_keys.get(nid, nid)
            if mode_norm == "heuristic":
                arm = nd.mutator_family or "GENERIC_PROBE"
                pulls = ucb_pulls.get(arm, 0)
                if pulls == 0:
                    ucb_term = 2.0
                else:
                    mean_r = ucb_rewards.get(arm, 0.0) / float(pulls)
                    ucb_term = mean_r + 1.414 * math.sqrt(math.log(max(2, ucb_total_pulls + 1)) / float(pulls))
                prio_term = math.tanh(float(nd.priority) / 25.0) * 1.5
                return ucb_term + prio_term + rng.uniform(0.0, 0.02)
            base = _score_node_with_policy(
                policy,
                nd,
                max_depth=max_depth,
                has_active_hint=_has_active_hint(nd),
                branch_noise_count=branch_noise_count.get(bkey, 0),
            )
            return base + rng.gauss(0.0, 0.03)

        while frontier and steps_taken < budget:
            remaining = budget - steps_taken
            batch_limit = min(parallel_group_size, len(frontier))
            batch_ids: List[str] = []

            if mode_norm == "disabled":
                batch_ids.append(frontier.pop(0))
                in_frontier.discard(batch_ids[0])
            elif mode_norm == "random":
                idx = rng.randrange(len(frontier))
                nid = frontier.pop(idx)
                in_frontier.discard(nid)
                batch_ids.append(nid)
            else:
                scored = [(_score_candidate(nid), idx, nid) for idx, nid in enumerate(frontier)]
                scored.sort(key=lambda item: (item[0], -item[1]), reverse=True)
                selected_nids: List[str] = []
                used_budget = 0
                for _, _, nid in scored:
                    if len(selected_nids) >= batch_limit:
                        break
                    cost = max(0, tree.nodes[nid].step_cost)
                    if used_budget > 0 and used_budget + cost > remaining:
                        continue
                    selected_nids.append(nid)
                    used_budget += cost
                if not selected_nids:
                    break
                selected_set = set(selected_nids)
                frontier = [nid for nid in frontier if nid not in selected_set]
                for nid in selected_nids:
                    in_frontier.discard(nid)
                batch_ids = selected_nids

            # Execute batch against recorded outcomes
            new_children_to_add: List[str] = []
            for nid in batch_ids:
                if nid in visited:
                    continue
                nd = tree.nodes[nid]
                cost = max(0, nd.step_cost)
                if steps_taken + cost > budget and steps_taken > 0:
                    continue

                visited.add(nid)
                visited_order.append(nid)
                steps_taken += cost
                total_token_cost += max(0, nd.token_cost)

                if nd.node_type == "HINT":
                    active_hint_scopes.add((nd.domain.lower() or "global", nd.rfc_id.lower()))

                bkey = branch_keys.get(nid, nid)
                positive_signal = False
                step_signal = 0.0

                if nd.is_confirmed_vuln:
                    vulns_found += 1
                    positive_signal = True
                    step_signal += 3.0
                elif nd.is_anomaly:
                    anomalies_found += 1
                    positive_signal = True
                    step_signal += 1.0

                if nd.is_attack_chain:
                    chains_found += 1
                    positive_signal = True
                    step_signal += 1.5

                if nd.is_noise_discard and not nd.is_confirmed_vuln:
                    noise_discards += 1
                    branch_noise_count[bkey] = branch_noise_count.get(bkey, 0) + 1
                    step_signal -= 1.5

                if mode_norm == "heuristic" and cost > 0:
                    arm = nd.mutator_family or "GENERIC_PROBE"
                    ucb_pulls[arm] = ucb_pulls.get(arm, 0) + 1
                    ucb_rewards[arm] = ucb_rewards.get(arm, 0.0) + step_signal
                    ucb_total_pulls += 1

                # Update per-branch early-stop streak (never prune the single global root)
                is_global_root = (nid == single_root_id)
                if cost > 0 and not is_global_root:
                    if positive_signal:
                        branch_dead_streak[bkey] = 0
                    else:
                        streak = branch_dead_streak.get(bkey, 0) + 1
                        branch_dead_streak[bkey] = streak
                        if (
                            mode_norm not in ("disabled", "random")
                            and streak >= early_stop_patience
                            and bkey not in pruned_branches
                        ):
                            pruned_branches.add(bkey)
                            early_stopped_branches += 1
                            # Prune remaining low-priority frontier nodes in the exhausted branch
                            kept: List[str] = []
                            for fnid in frontier:
                                fnode = tree.nodes[fnid]
                                is_high_prio_override = (
                                    fnode.source_kind in ("cascade_intent", "dual_graph_multihop")
                                    and fnode.priority >= 20.0
                                )
                                if branch_keys.get(fnid) == bkey and not is_high_prio_override:
                                    in_frontier.discard(fnid)
                                else:
                                    kept.append(fnid)
                            frontier = kept

                # Expand children up to branch_width (unless this branch was pruned)
                if bkey not in pruned_branches and nd.children:
                    candidate_children = [
                        cid for cid in nd.children
                        if cid not in visited and cid not in in_frontier
                    ]
                    if candidate_children:
                        if mode_norm in ("disabled", "random"):
                            chosen_children = candidate_children
                        else:
                            # Never throttle children of the single global root below total roots/sub-branches
                            # if the policy specifically wants to explore sub-branches, apply branch_width cleanly
                            scored_children = [
                                (_score_candidate(cid), idx, cid)
                                for idx, cid in enumerate(candidate_children)
                            ]
                            scored_children.sort(key=lambda item: (item[0], -item[1]), reverse=True)
                            chosen_children = [cid for _, _, cid in scored_children[:branch_width]]
                        new_children_to_add.extend(chosen_children)

            for cid in new_children_to_add:
                if cid not in visited and cid not in in_frontier:
                    cbkey = branch_keys.get(cid, cid)
                    cnode = tree.nodes[cid]
                    is_high_prio_override = (
                        cnode.source_kind in ("cascade_intent", "dual_graph_multihop")
                        and cnode.priority >= 20.0
                    )
                    if cbkey in pruned_branches and not is_high_prio_override:
                        continue
                    frontier.append(cid)
                    in_frontier.add(cid)

        reward = compute_replay_reward(
            vulns=vulns_found,
            chains=chains_found,
            anomalies=anomalies_found,
            noise_discards=noise_discards,
            steps_taken=steps_taken,
        )
        return ReplayOutcome(
            tree_id=tree.tree_id,
            policy_name=p_name,
            seed=int(seed),
            budget_steps=budget,
            steps_taken=steps_taken,
            vulns_found=vulns_found,
            chains_found=chains_found,
            anomalies_found=anomalies_found,
            noise_discards=noise_discards,
            early_stopped_branches=early_stopped_branches,
            total_token_cost=total_token_cost,
            reward=reward,
            vuln_discovery_rate=vulns_found / float(budget),
            vuln_hit_rate=vulns_found / float(max(1, steps_taken)),
            noise_rate=noise_discards / float(max(1, steps_taken)),
            visited_node_ids=visited_order,
            simulator_backend=BACKEND_RECORDED_REPLAY,
        )
