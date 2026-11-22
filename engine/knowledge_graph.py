"""
Module 11: Coverage and Research Knowledge Graph (P1).

Maintains a bipartite knowledge graph of RFC specifications, ABNF grammar tokens,
normative requirements, discovered anomalies, and novel techniques to uncover
untested specification blind spots.
"""

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    node_id: str
    node_type: str  # 'RFC', 'SECTION', 'GRAMMAR', 'REQUIREMENT', 'ANOMALY', 'VULNERABILITY', 'TECHNIQUE'
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relationship: str  # 'CONTAINS', 'DEFINES', 'TESTED_BY', 'PROVES_VULN', 'GENERALIZED_TO'


class ResearchKnowledgeGraph:
    """
    Maintains graph relationships and identifies coverage gaps across RFC specifications.
    Optionally mirrors FACT and INTENT nodes to a persistent Database blackboard.
    """

    FACT_NODE_TYPES: Set[str] = {"VULNERABILITY", "ANOMALY"}
    INTENT_NODE_TYPES: Set[str] = {"REQUIREMENT", "TECHNIQUE"}

    def __init__(
        self,
        db: Optional[Any] = None,
        *,
        task_id: str = "default",
        domain: str = "",
        source_agent: str = "knowledge_graph",
    ):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.db = db
        self.task_id = task_id
        self.domain = domain
        self.source_agent = source_agent
        self._mirrored_ids: Set[str] = set()
        self._lock = threading.RLock()

    def seed_mirrored_ids(self, node_ids: Iterable[str]) -> None:
        """Pre-seeds mirrored blackboard node IDs so resumed runs do not re-queue DONE intents."""
        with self._lock:
            for nid in node_ids or ():
                if nid:
                    self._mirrored_ids.add(str(nid))

    def _infer_rfc_parent(self, node_id: str) -> str:
        with self._lock:
            for parent_id in self.reverse_adjacency.get(node_id, set()):
                parent = self.nodes.get(parent_id)
                if parent is not None and str(parent.node_type).upper() == "RFC":
                    return parent.node_id
            return ""

    def _mirror_fact(
        self,
        *,
        bb_node_id: str,
        content: str,
        rfc_id: str = "",
        domain: str = "",
        task_id: Optional[str] = None,
        parent_node_id: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        with self._lock:
            if self.db is None or bb_node_id in self._mirrored_ids:
                return None
            eff_task_id = str(task_id or self.task_id)
            try:
                add_fact = getattr(self.db, "add_fact", None)
                if callable(add_fact):
                    res = add_fact(
                        content,
                        node_id=bb_node_id,
                        task_id=eff_task_id,
                        domain=domain or self.domain,
                        rfc_id=rfc_id,
                        source_agent=self.source_agent,
                        payload=payload or {},
                        parent_node_id=parent_node_id,
                    )
                else:
                    add_bb = getattr(self.db, "add_blackboard_node", None)
                    if not callable(add_bb):
                        return None
                    res = add_bb(
                        "FACT",
                        content,
                        node_id=bb_node_id,
                        status="ACTIVE",
                        task_id=eff_task_id,
                        domain=domain or self.domain,
                        rfc_id=rfc_id,
                        source_agent=self.source_agent,
                        payload=payload or {},
                        parent_node_id=parent_node_id,
                    )
                self._mirrored_ids.add(bb_node_id)
                return str(res) if res else bb_node_id
            except Exception as exc:
                logger.debug("ResearchKnowledgeGraph fact mirror failed for %s: %s", bb_node_id, exc)
                return None

    def _mirror_intent(
        self,
        *,
        bb_node_id: str,
        content: str,
        priority: float = 1.0,
        rfc_id: str = "",
        domain: str = "",
        task_id: Optional[str] = None,
        parent_node_id: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        with self._lock:
            if self.db is None or bb_node_id in self._mirrored_ids:
                return None
            eff_task_id = str(task_id or self.task_id)
            try:
                queue_intent = getattr(self.db, "queue_intent", None)
                if callable(queue_intent):
                    res = queue_intent(
                        content,
                        priority=priority,
                        node_id=bb_node_id,
                        task_id=eff_task_id,
                        domain=domain or self.domain,
                        rfc_id=rfc_id,
                        source_agent=self.source_agent,
                        payload=payload or {},
                        parent_node_id=parent_node_id,
                    )
                else:
                    add_bb = getattr(self.db, "add_blackboard_node", None)
                    if not callable(add_bb):
                        return None
                    res = add_bb(
                        "INTENT",
                        content,
                        node_id=bb_node_id,
                        status="PENDING",
                        priority=priority,
                        task_id=eff_task_id,
                        domain=domain or self.domain,
                        rfc_id=rfc_id,
                        source_agent=self.source_agent,
                        payload=payload or {},
                        parent_node_id=parent_node_id,
                    )
                self._mirrored_ids.add(bb_node_id)
                return str(res) if res else bb_node_id
            except Exception as exc:
                logger.debug("ResearchKnowledgeGraph intent mirror failed for %s: %s", bb_node_id, exc)
                return None

    def _complete_mirrored_intent(
        self,
        bb_node_id: str,
        result_payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            if self.db is None:
                return
            try:
                complete_fn = getattr(self.db, "complete_intent", None)
                if callable(complete_fn):
                    complete_fn(bb_node_id, status="DONE", result_payload=result_payload or {})
            except Exception as exc:
                logger.debug("ResearchKnowledgeGraph intent completion failed for %s: %s", bb_node_id, exc)

    def add_node(self, node_id: str, node_type: str, label: str, attributes: Optional[Dict[str, Any]] = None) -> GraphNode:
        attrs = dict(attributes) if attributes is not None else {}
        node = GraphNode(node_id=node_id, node_type=node_type, label=label, attributes=attrs)
        with self._lock:
            self.nodes[node_id] = node

            if self.db is not None:
                norm_type = str(node_type or "").strip().upper()
                bb_override = str(attrs.get("blackboard_type", "") or "").strip().upper()
                rfc_id = str(attrs.get("rfc_id", "") or self._infer_rfc_parent(node_id))
                domain = str(attrs.get("domain", "") or self.domain)
                task_id = str(attrs.get("task_id", "") or self.task_id)
                payload = {
                    "kg_node_id": node_id,
                    "kg_node_type": norm_type,
                    "label": label,
                    "attributes": attrs,
                }
                if bb_override == "FACT" or (not bb_override and norm_type in self.FACT_NODE_TYPES):
                    self._mirror_fact(
                        bb_node_id=f"kg:{node_id}",
                        content=f"[{norm_type}] {label}",
                        rfc_id=rfc_id,
                        domain=domain,
                        task_id=task_id,
                        payload=payload,
                    )
                elif bb_override == "INTENT" or (not bb_override and norm_type in self.INTENT_NODE_TYPES):
                    default_prio = 5.0 if norm_type == "TECHNIQUE" else 1.0
                    try:
                        prio = float(attrs.get("priority", default_prio))
                    except (TypeError, ValueError):
                        prio = default_prio
                    self._mirror_intent(
                        bb_node_id=f"kg:{node_id}",
                        content=f"[{norm_type}] {label}",
                        priority=prio,
                        rfc_id=rfc_id,
                        domain=domain,
                        task_id=task_id,
                        payload=payload,
                    )
            return node

    def add_edge(self, source_id: str, target_id: str, relationship: str) -> None:
        with self._lock:
            self.edges.append(GraphEdge(source_id=source_id, target_id=target_id, relationship=relationship))
            self.adjacency[source_id].add(target_id)
            self.reverse_adjacency[target_id].add(source_id)

    def record_testing_event(self, requirement_id: str, outcome_node_id: str, is_vulnerability: bool = False):
        """Connects a test outcome to an RFC requirement node."""
        rel = "PROVES_VULN" if is_vulnerability else "TESTED_BY"
        with self._lock:
            self.add_edge(requirement_id, outcome_node_id, rel)
            if self.db is not None:
                req_node = self.nodes.get(requirement_id)
                out_node = self.nodes.get(outcome_node_id)
                req_desc = f"{requirement_id} ({req_node.label})" if req_node else requirement_id
                out_desc = f"{outcome_node_id} ({out_node.label})" if out_node else outcome_node_id
                req_rfc = str(req_node.attributes.get("rfc_id", "")) if req_node else ""
                req_domain = str(req_node.attributes.get("domain", "")) if req_node else ""
                req_task = str(req_node.attributes.get("task_id", "")) if req_node else ""
                self._mirror_fact(
                    bb_node_id=f"kg:event:{requirement_id}:{outcome_node_id}",
                    content=f"[{rel}] {req_desc} -> {out_desc}",
                    rfc_id=req_rfc or self._infer_rfc_parent(requirement_id),
                    domain=req_domain,
                    task_id=req_task or self.task_id,
                    parent_node_id=f"kg:{requirement_id}",
                    payload={
                        "requirement_id": requirement_id,
                        "outcome_node_id": outcome_node_id,
                        "relationship": rel,
                        "is_vulnerability": bool(is_vulnerability),
                    },
                )
                self._complete_mirrored_intent(
                    f"kg:{requirement_id}",
                    result_payload={
                        "outcome_node_id": outcome_node_id,
                        "relationship": rel,
                        "is_vulnerability": bool(is_vulnerability),
                    },
                )

    def record_fact(
        self,
        node_id: str,
        label: str,
        node_type: str = "ANOMALY",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> GraphNode:
        """Records a node into the knowledge graph and forces FACT blackboard mirroring when db is set."""
        attrs = dict(attributes) if attributes is not None else {}
        if str(node_type or "").strip().upper() not in self.FACT_NODE_TYPES:
            attrs["blackboard_type"] = "FACT"
        return self.add_node(node_id, node_type, label, attributes=attrs)

    def record_intent(
        self,
        node_id: str,
        label: str,
        node_type: str = "REQUIREMENT",
        priority: float = 1.0,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> GraphNode:
        """Records a node into the knowledge graph and forces INTENT blackboard mirroring when db is set."""
        attrs = dict(attributes) if attributes is not None else {}
        attrs["priority"] = float(priority)
        attrs["blackboard_type"] = "INTENT"
        return self.add_node(node_id, node_type, label, attributes=attrs)

    def sync_blind_spots_to_intents(self, priority: float = 1.0) -> List[str]:
        """Mirrors all untested REQUIREMENT nodes (blind spots) as PENDING INTENTs on the blackboard."""
        with self._lock:
            if self.db is None:
                return []
            created: List[str] = []
            for node in list(self.nodes.values()):
                if node.node_type == "REQUIREMENT" and not self.adjacency.get(node.node_id):
                    rfc_id = str(node.attributes.get("rfc_id", "") or self._infer_rfc_parent(node.node_id))
                    domain = str(node.attributes.get("domain", "") or self.domain)
                    task_id = str(node.attributes.get("task_id", "") or self.task_id)
                    bb_id = self._mirror_intent(
                        bb_node_id=f"kg:{node.node_id}",
                        content=f"[REQUIREMENT] {node.label}",
                        priority=float(priority),
                        rfc_id=rfc_id,
                        domain=domain,
                        task_id=task_id,
                        payload={
                            "kg_node_id": node.node_id,
                            "kg_node_type": "REQUIREMENT",
                            "label": node.label,
                            "attributes": dict(node.attributes),
                        },
                    )
                    if bb_id:
                        created.append(bb_id)
            return created

    def calculate_specification_coverage(self) -> Dict[str, Any]:
        """
        Calculates test coverage across extracted specification requirements
        and returns unvisited 'blind spots'.
        """
        with self._lock:
            requirements = [n for n in list(self.nodes.values()) if n.node_type == "REQUIREMENT"]
            if not requirements:
                return {"coverage_percent": 0.0, "total_requirements": 0, "tested_count": 0, "blind_spots": []}

            tested = []
            untested = []

            for req in requirements:
                # Check if this node has outgoing edges to tests/anomalies/probes
                targets = self.adjacency.get(req.node_id, set())
                if targets:
                    tested.append(req.node_id)
                else:
                    untested.append(req.node_id)

            pct = (len(tested) / len(requirements)) * 100.0 if requirements else 0.0

            return {
                "coverage_percent": round(pct, 2),
                "total_requirements": len(requirements),
                "tested_count": len(tested),
                "untested_count": len(untested),
                "blind_spots": untested[:20],  # Return up to 20 immediate gaps
            }

    def get_lineage_trace(self, vuln_id: str) -> List[Dict[str, str]]:
        """Traces a confirmed vulnerability back to its originating RFC and section."""
        with self._lock:
            trace = []
            current = vuln_id

            # Trace backwards along reverse adjacency
            visited = set()
            while current and current not in visited:
                visited.add(current)
                node = self.nodes.get(current)
                if node:
                    trace.append({"node_id": node.node_id, "type": node.node_type, "label": node.label})
                parents = self.reverse_adjacency.get(current, set())
                current = next(iter(parents), None) if parents else None

            return trace
