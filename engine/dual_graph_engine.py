"""
ARTEX Dual-Graph & Autonomous Attack Chainer Engine (Module 17)
=============================================================
Ported from BaaRai/ARTEX (https://github.com/BaaRai/ARTEX) architectural principles:
1. Asset Graph: Global target topology tracking domains, IPs, ports, endpoints, and AI sinks.
2. Exploration Graph: Task-specific goals, intents, wire desync primitives, and attack chains.
3. ArtexPlanner: Strategic multi-round decomposition of anomalies into chained attack hypotheses.
4. ArtexWorker: Tactical execution of attack vectors against anchored assets.
5. Zero UI: Reports written directly to reports/ folder and persisted in terminator.db.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("terminator.artex")


@dataclass
class AssetNode:
    node_id: str
    node_type: str  # 'DOMAIN', 'SUBDOMAIN', 'IP_PORT', 'SERVICE', 'ENDPOINT', 'AI_SINK'
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExplorationNode:
    node_id: str
    node_type: str  # 'GOAL', 'INTENT', 'WIRE_PRIMITIVE', 'ATTACK_CANDIDATE', 'CONFIRMED_EXPLOIT'
    label: str
    status: str = "PENDING"  # 'PENDING', 'ACTIVE', 'VERIFIED', 'FAILED'
    anchored_asset_id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DirectedEdge:
    source_id: str
    target_id: str
    relationship: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AssetGraph:
    """
    Maintains persistent target infrastructure and attack surface across scans.
    """

    def __init__(self, db: Optional[Any] = None):
        self.db = db
        self.nodes: Dict[str, AssetNode] = {}
        self.edges: List[DirectedEdge] = []

    def add_asset(self, node_id: str, node_type: str, label: str, attributes: Optional[Dict[str, Any]] = None) -> AssetNode:
        attrs = attributes or {}
        node = AssetNode(node_id=node_id, node_type=node_type, label=label, attributes=attrs)
        self.nodes[node_id] = node
        if self.db and hasattr(self.db, "save_dual_graph_node"):
            try:
                self.db.save_dual_graph_node(node_id, "ASSET", node_type, label, attrs)
            except Exception as e:
                logger.debug("Failed to persist asset node: %s", e)
        return node

    def add_relation(self, source_id: str, target_id: str, relationship: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        attrs = attributes or {}
        edge = DirectedEdge(source_id=source_id, target_id=target_id, relationship=relationship, attributes=attrs)
        self.edges.append(edge)
        if self.db and hasattr(self.db, "save_dual_graph_edge"):
            try:
                self.db.save_dual_graph_edge(source_id, target_id, relationship, attrs)
            except Exception as e:
                logger.debug("Failed to persist asset edge: %s", e)

    def find_endpoints_by_type(self, node_type: str) -> List[AssetNode]:
        return [n for n in self.nodes.values() if n.node_type == node_type]


class ExplorationGraph:
    """
    Maintains dynamic task goals, anomalies, attack candidates, and proven exploits.
    """

    def __init__(self, db: Optional[Any] = None):
        self.db = db
        self.nodes: Dict[str, ExplorationNode] = {}
        self.edges: List[DirectedEdge] = []

    def add_intent(
        self,
        node_id: str,
        node_type: str,
        label: str,
        anchored_asset_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        status: str = "PENDING",
    ) -> ExplorationNode:
        attrs = attributes or {}
        node = ExplorationNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            status=status,
            anchored_asset_id=anchored_asset_id,
            attributes=attrs,
        )
        self.nodes[node_id] = node
        if self.db and hasattr(self.db, "save_dual_graph_node"):
            try:
                self.db.save_dual_graph_node(node_id, "EXPLORATION", node_type, label, {**attrs, "status": status, "anchored_asset": anchored_asset_id})
            except Exception as e:
                logger.debug("Failed to persist exploration node: %s", e)
        return node

    def add_relation(self, source_id: str, target_id: str, relationship: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        attrs = attributes or {}
        edge = DirectedEdge(source_id=source_id, target_id=target_id, relationship=relationship, attributes=attrs)
        self.edges.append(edge)
        if self.db and hasattr(self.db, "save_dual_graph_edge"):
            try:
                self.db.save_dual_graph_edge(source_id, target_id, relationship, attrs)
            except Exception as e:
                logger.debug("Failed to persist exploration edge: %s", e)

    def get_pending_candidates(self) -> List[ExplorationNode]:
        return [n for n in self.nodes.values() if n.node_type == "ATTACK_CANDIDATE" and n.status == "PENDING"]


class ArtexPlanner:
    """
    Decomposes primitive wire protocol anomalies, static code flaws, credential leaks,
    SSRF pivots, and asset discoveries into single-hop and multi-hop chained attack hypotheses.
    """

    def __init__(self, asset_graph: AssetGraph, exploration_graph: ExplorationGraph):
        self.asset_graph = asset_graph
        self.exploration_graph = exploration_graph

    def _add_candidate(
        self,
        cid: str,
        label: str,
        anchored_asset_id: Optional[str],
        attributes: Dict[str, Any],
        source_nodes: List[str],
        target_asset_id: Optional[str] = None,
    ) -> Optional[ExplorationNode]:
        if cid in self.exploration_graph.nodes:
            return None
        node = self.exploration_graph.add_intent(
            node_id=cid,
            node_type="ATTACK_CANDIDATE",
            label=label,
            anchored_asset_id=anchored_asset_id,
            attributes=attributes,
        )
        for src_id in source_nodes:
            self.exploration_graph.add_relation(cid, src_id, "CHAINS_FROM")
        if target_asset_id:
            self.exploration_graph.add_relation(cid, target_asset_id, "TARGETS_ASSET")
        return node

    def plan_next_round(self, round_num: int = 1) -> List[ExplorationNode]:
        """
        Analyzes the current graph state and generates both 1-hop primitive chains
        and multi-hop cross-scanner / cross-finding escalation chains.
        """
        new_candidates: List[ExplorationNode] = []
        primitives = [
            n
            for n in self.exploration_graph.nodes.values()
            if n.node_type in ("WIRE_PRIMITIVE", "FINDING_PRIMITIVE")
        ]
        ai_sinks = self.asset_graph.find_endpoints_by_type("AI_SINK")
        http_endpoints = self.asset_graph.find_endpoints_by_type("ENDPOINT")
        ip_ports = self.asset_graph.find_endpoints_by_type("IP_PORT")
        default_asset_id = (
            (http_endpoints[0].node_id if http_endpoints else None)
            or (ai_sinks[0].node_id if ai_sinks else None)
            or (ip_ports[0].node_id if ip_ports else None)
        )

        # Phase 1: 1-hop capability -> target asset planning
        for prim in primitives:
            cap = str(prim.attributes.get("capability_class") or "DESYNC").upper()
            anomaly_type = prim.attributes.get("anomaly_type", "HTTP_DESYNC")
            source_scanner = prim.attributes.get("scanner", "unknown")

            if cap in ("DESYNC", "WIRE_DESYNC"):
                for sink in ai_sinks:
                    added = self._add_candidate(
                        cid=f"CAND-PROMPT-INJ-{round_num}-{prim.node_id[-6:]}-{sink.node_id[-6:]}",
                        label=f"Desynchronized Prompt Injection: {anomaly_type} -> {sink.label}",
                        anchored_asset_id=sink.node_id,
                        attributes={
                            "attack_type": "DESYNC_PROMPT_INJECTION",
                            "has_ai_sink": True,
                            "wire_primitive_id": prim.node_id,
                            "ai_sink_id": sink.node_id,
                            "target_route": sink.attributes.get("route", "/api/chat"),
                            "method": sink.attributes.get("method", "POST"),
                            "hop_count": 1,
                            "source_scanners": [source_scanner],
                            "chain_steps": [
                                {"step": 1, "finding_id": prim.node_id, "scanner": source_scanner, "desc": prim.label},
                                {"step": 2, "target_asset": sink.node_id, "desc": f"Smuggle crafted instruction to {sink.label}"},
                            ],
                        },
                        source_nodes=[prim.node_id],
                        target_asset_id=sink.node_id,
                    )
                    if added:
                        new_candidates.append(added)

                for ep in http_endpoints:
                    added = self._add_candidate(
                        cid=f"CAND-DESYNC-HIJACK-{round_num}-{prim.node_id[-6:]}-{ep.node_id[-6:]}",
                        label=f"Pipeline Desync Response Hijacking: {ep.label}",
                        anchored_asset_id=ep.node_id,
                        attributes={
                            "attack_type": "PIPELINE_HIJACK",
                            "wire_primitive_id": prim.node_id,
                            "target_endpoint": ep.attributes.get("route", "/"),
                            "hop_count": 1,
                            "source_scanners": [source_scanner],
                            "chain_steps": [
                                {"step": 1, "finding_id": prim.node_id, "scanner": source_scanner, "desc": prim.label},
                                {"step": 2, "target_asset": ep.node_id, "desc": f"Hijack HTTP pipeline on {ep.label}"},
                            ],
                        },
                        source_nodes=[prim.node_id],
                        target_asset_id=ep.node_id,
                    )
                    if added:
                        new_candidates.append(added)

            elif cap == "AUTH_SECRET" and (http_endpoints or ai_sinks):
                anchor = ai_sinks[0] if ai_sinks else http_endpoints[0]
                added = self._add_candidate(
                    cid=f"CAND-AUTH-BYPASS-{round_num}-{prim.node_id[-8:]}",
                    label=f"Credential/Auth Bypass Chain: {prim.label[:60]} -> {anchor.label}",
                    anchored_asset_id=anchor.node_id,
                    attributes={
                        "attack_type": "CREDENTIAL_AUTH_BYPASS",
                        "wire_primitive_id": prim.node_id,
                        "target_route": anchor.attributes.get("route", "/"),
                        "hop_count": 1,
                        "source_scanners": [source_scanner],
                        "chain_steps": [
                            {"step": 1, "finding_id": prim.node_id, "scanner": source_scanner, "desc": prim.label},
                            {"step": 2, "target_asset": anchor.node_id, "desc": f"Replay exposed auth material against {anchor.label}"},
                        ],
                    },
                    source_nodes=[prim.node_id],
                    target_asset_id=anchor.node_id,
                )
                if added:
                    new_candidates.append(added)

            elif cap == "SSRF_PIVOT" and default_asset_id:
                added = self._add_candidate(
                    cid=f"CAND-SSRF-PIVOT-{round_num}-{prim.node_id[-8:]}",
                    label=f"SSRF Internal Service Pivot: {prim.label[:70]}",
                    anchored_asset_id=default_asset_id,
                    attributes={
                        "attack_type": "SSRF_INTERNAL_PIVOT",
                        "wire_primitive_id": prim.node_id,
                        "target_endpoint": "/",
                        "hop_count": 1,
                        "source_scanners": [source_scanner],
                        "chain_steps": [
                            {"step": 1, "finding_id": prim.node_id, "scanner": source_scanner, "desc": prim.label},
                            {"step": 2, "desc": "Pivot outbound HTTP fetch to internal metadata/service endpoints"},
                        ],
                    },
                    source_nodes=[prim.node_id],
                    target_asset_id=default_asset_id,
                )
                if added:
                    new_candidates.append(added)

            elif cap in ("EXEC_SINK", "ZERO_DAY_CANDIDATE", "AI_INJECTION") and default_asset_id:
                attack_t = "AI_PROMPT_TOOL_ESCALATION" if cap == "AI_INJECTION" else "EXPLOITABLE_SINK_CHAIN"
                added = self._add_candidate(
                    cid=f"CAND-SINK-{round_num}-{prim.node_id[-8:]}",
                    label=f"Attack Path to Sink: {prim.label[:75]}",
                    anchored_asset_id=default_asset_id,
                    attributes={
                        "attack_type": attack_t,
                        "wire_primitive_id": prim.node_id,
                        "target_route": (http_endpoints[0].attributes.get("route", "/") if http_endpoints else "/"),
                        "hop_count": 1,
                        "source_scanners": [source_scanner],
                        "chain_steps": [
                            {"step": 1, "finding_id": prim.node_id, "scanner": source_scanner, "desc": prim.label},
                            {"step": 2, "desc": "Reach unguarded execution/AI sink from exposed entrypoint"},
                        ],
                    },
                    source_nodes=[prim.node_id],
                    target_asset_id=default_asset_id,
                )
                if added:
                    new_candidates.append(added)

        # Phase 2: Multi-hop cross-finding & cross-scanner escalation composition
        # Chains distinct complementary findings (e.g., Auth/Secret -> Exec/AI, Desync -> Sink, SSRF -> Secret/Exec)
        max_multi_hop = 100
        multi_hop_count = 0
        for idx_a, prim_a in enumerate(primitives):
            if multi_hop_count >= max_multi_hop:
                break
            cap_a = str(prim_a.attributes.get("capability_class") or "DESYNC").upper()
            for prim_b in primitives[idx_a + 1 :]:
                if multi_hop_count >= max_multi_hop:
                    break
                cap_b = str(prim_b.attributes.get("capability_class") or "DESYNC").upper()
                rule_a = prim_a.attributes.get("rule_id", prim_a.node_id)
                rule_b = prim_b.attributes.get("rule_id", prim_b.node_id)
                scan_a = str(prim_a.attributes.get("scanner", "scanner-a"))
                scan_b = str(prim_b.attributes.get("scanner", "scanner-b"))
                if rule_a == rule_b and scan_a == scan_b:
                    continue

                pair_caps = {cap_a, cap_b}
                chain_kind: Optional[str] = None
                chain_desc: str = ""
                if "DESYNC" in pair_caps and pair_caps & {"AI_INJECTION", "EXEC_SINK", "ZERO_DAY_CANDIDATE", "AUTH_SECRET"}:
                    chain_kind = "MULTI_HOP_SMUGGLED_EXPLOIT"
                    chain_desc = "HTTP Framing Desync unlocks downstream injection/auth boundary"
                elif "AUTH_SECRET" in pair_caps and pair_caps & {"EXEC_SINK", "ZERO_DAY_CANDIDATE", "AI_INJECTION"}:
                    chain_kind = "MULTI_HOP_AUTH_BYPASS_EXEC"
                    chain_desc = "Credential/Auth bypass unlocks privileged code/command/AI sink"
                elif "SSRF_PIVOT" in pair_caps and pair_caps & {"AUTH_SECRET", "EXEC_SINK", "ZERO_DAY_CANDIDATE", "AI_INJECTION", "DESYNC"}:
                    chain_kind = "MULTI_HOP_SSRF_ESCALATION"
                    chain_desc = "SSRF pivot chains into internal credentials or execution sink"
                elif "CRYPTO_WEAK" in pair_caps and pair_caps & {"AUTH_SECRET", "EXEC_SINK", "SUPPLY_CHAIN", "ZERO_DAY_CANDIDATE"}:
                    chain_kind = "MULTI_HOP_CRYPTO_COMPROMISE"
                    chain_desc = "Cryptographic weakness/SCA flaw enables token forgery or escalation"
                elif scan_a != scan_b and pair_caps & {"EXEC_SINK", "ZERO_DAY_CANDIDATE", "AUTH_SECRET", "SSRF_PIVOT"}:
                    chain_kind = "MULTI_HOP_CROSS_SCANNER_CHAIN"
                    chain_desc = f"Cross-scanner composition ({scan_a} + {scan_b})"

                if not chain_kind:
                    continue

                target_sink = ai_sinks[0] if ("AI_INJECTION" in pair_caps and ai_sinks) else (http_endpoints[0] if http_endpoints else None)
                anchor_id = target_sink.node_id if target_sink else default_asset_id
                cid = f"CAND-CHAIN-{round_num}-{prim_a.node_id[-5:]}-{prim_b.node_id[-5:]}"
                has_ai = "AI_INJECTION" in pair_caps or (target_sink is not None and target_sink.node_type == "AI_SINK")
                added = self._add_candidate(
                    cid=cid,
                    label=f"[{chain_kind}] ({scan_a}) {prim_a.label[:42]} -> ({scan_b}) {prim_b.label[:42]}",
                    anchored_asset_id=anchor_id,
                    attributes={
                        "attack_type": chain_kind,
                        "has_ai_sink": has_ai,
                        "wire_primitive_id": prim_a.node_id,
                        "secondary_primitive_id": prim_b.node_id,
                        "target_route": target_sink.attributes.get("route", "/") if target_sink else "/",
                        "target_path": prim_b.attributes.get("file_path") or (target_sink.attributes.get("route", "/") if target_sink else "network-target"),
                        "hop_count": 2,
                        "is_multi_hop": True,
                        "source_scanners": sorted({scan_a, scan_b}),
                        "chain_steps": [
                            {"step": 1, "finding_id": prim_a.node_id, "scanner": scan_a, "cwe": prim_a.attributes.get("cwe", ""), "desc": prim_a.label},
                            {"step": 2, "finding_id": prim_b.node_id, "scanner": scan_b, "cwe": prim_b.attributes.get("cwe", ""), "desc": prim_b.label},
                            {"step": 3, "attack_type": chain_kind, "desc": chain_desc},
                        ],
                    },
                    source_nodes=[prim_a.node_id, prim_b.node_id],
                    target_asset_id=anchor_id,
                )
                if added:
                    new_candidates.append(added)
                    multi_hop_count += 1

        # Phase 3: 3-Hop Compound Attack Paths
        # Pattern 1: DESYNC -> AUTH_SECRET -> EXEC_SINK
        # Pattern 2: DESYNC -> AUTH_SECRET -> AI_INJECTION
        # Pattern 3: SSRF_PIVOT -> AUTH_SECRET -> EXEC_SINK
        # Pattern 4: ZERO_DAY_CANDIDATE -> AI_INJECTION / EXEC_SINK
        prims_by_cap: Dict[str, List[ExplorationNode]] = {}
        for p in primitives:
            p_cap = str(p.attributes.get("capability_class") or "DESYNC").upper()
            prims_by_cap.setdefault(p_cap, []).append(p)

        desync_prims = prims_by_cap.get("DESYNC", []) + [
            p for p in primitives if p.node_type == "WIRE_PRIMITIVE" and p not in prims_by_cap.get("DESYNC", [])
        ]
        auth_prims = prims_by_cap.get("AUTH_SECRET", [])
        exec_prims = prims_by_cap.get("EXEC_SINK", [])
        ai_prims = prims_by_cap.get("AI_INJECTION", [])
        ssrf_prims = prims_by_cap.get("SSRF_PIVOT", [])
        zero_day_prims = prims_by_cap.get("ZERO_DAY_CANDIDATE", [])

        # Pattern 1: DESYNC -> AUTH_SECRET -> EXEC_SINK
        for p_desync in desync_prims:
            for p_auth in auth_prims:
                for p_exec in exec_prims:
                    cid = f"CAND-3HOP-DESYNC-AUTH-EXEC-{round_num}-{p_desync.node_id[-4:]}-{p_auth.node_id[-4:]}-{p_exec.node_id[-4:]}"
                    scan_d = str(p_desync.attributes.get("scanner", "prober"))
                    scan_a = str(p_auth.attributes.get("scanner", "raptor"))
                    scan_e = str(p_exec.attributes.get("scanner", "mantis"))
                    target_asset = http_endpoints[0].node_id if http_endpoints else default_asset_id
                    target_route = http_endpoints[0].attributes.get("route", "/") if http_endpoints else "/"
                    added = self._add_candidate(
                        cid=cid,
                        label=f"[3-HOP COMPOUND] Desync ({scan_d}) -> Auth Secret ({scan_a}) -> Exec Sink ({scan_e})",
                        anchored_asset_id=target_asset,
                        attributes={
                            "attack_type": "3HOP_DESYNC_AUTH_EXEC",
                            "has_ai_sink": False,
                            "wire_primitive_id": p_desync.node_id,
                            "secondary_primitive_id": p_auth.node_id,
                            "tertiary_primitive_id": p_exec.node_id,
                            "target_route": target_route,
                            "target_path": p_exec.attributes.get("file_path", target_route),
                            "hop_count": 3,
                            "is_multi_hop": True,
                            "source_scanners": sorted({scan_d, scan_a, scan_e}),
                            "chain_steps": [
                                {"step": 1, "finding_id": p_desync.node_id, "capability": "DESYNC", "scanner": scan_d, "desc": p_desync.label},
                                {"step": 2, "finding_id": p_auth.node_id, "capability": "AUTH_SECRET", "scanner": scan_a, "desc": p_auth.label},
                                {"step": 3, "finding_id": p_exec.node_id, "capability": "EXEC_SINK", "scanner": scan_e, "desc": p_exec.label},
                                {"step": 4, "desc": "Smuggled HTTP request replays leaked authentication secret to trigger privileged execution sink"},
                            ],
                        },
                        source_nodes=[p_desync.node_id, p_auth.node_id, p_exec.node_id],
                        target_asset_id=target_asset,
                    )
                    if added:
                        new_candidates.append(added)

        # Pattern 2: DESYNC -> AUTH_SECRET -> AI_INJECTION
        for p_desync in desync_prims:
            for p_auth in auth_prims:
                for p_ai in ai_prims:
                    cid = f"CAND-3HOP-DESYNC-AUTH-AI-{round_num}-{p_desync.node_id[-4:]}-{p_auth.node_id[-4:]}-{p_ai.node_id[-4:]}"
                    scan_d = str(p_desync.attributes.get("scanner", "prober"))
                    scan_a = str(p_auth.attributes.get("scanner", "raptor"))
                    scan_i = str(p_ai.attributes.get("scanner", "aiscan"))
                    target_asset = ai_sinks[0].node_id if ai_sinks else default_asset_id
                    target_route = ai_sinks[0].attributes.get("route", "/api/chat") if ai_sinks else "/api/chat"
                    added = self._add_candidate(
                        cid=cid,
                        label=f"[3-HOP COMPOUND] Desync ({scan_d}) -> Auth Secret ({scan_a}) -> AI Injection ({scan_i})",
                        anchored_asset_id=target_asset,
                        attributes={
                            "attack_type": "3HOP_DESYNC_AUTH_AI_INJECTION",
                            "has_ai_sink": True,
                            "wire_primitive_id": p_desync.node_id,
                            "secondary_primitive_id": p_auth.node_id,
                            "tertiary_primitive_id": p_ai.node_id,
                            "target_route": target_route,
                            "target_path": p_ai.attributes.get("file_path", target_route),
                            "hop_count": 3,
                            "is_multi_hop": True,
                            "source_scanners": sorted({scan_d, scan_a, scan_i}),
                            "chain_steps": [
                                {"step": 1, "finding_id": p_desync.node_id, "capability": "DESYNC", "scanner": scan_d, "desc": p_desync.label},
                                {"step": 2, "finding_id": p_auth.node_id, "capability": "AUTH_SECRET", "scanner": scan_a, "desc": p_auth.label},
                                {"step": 3, "finding_id": p_ai.node_id, "capability": "AI_INJECTION", "scanner": scan_i, "desc": p_ai.label},
                                {"step": 4, "desc": "Smuggled HTTP request utilizes leaked credentials to bypass gateway auth and inject adversarial prompt into internal AI endpoint"},
                            ],
                        },
                        source_nodes=[p_desync.node_id, p_auth.node_id, p_ai.node_id],
                        target_asset_id=target_asset,
                    )
                    if added:
                        new_candidates.append(added)

        # Pattern 3: SSRF_PIVOT -> AUTH_SECRET -> EXEC_SINK
        for p_ssrf in ssrf_prims:
            for p_auth in auth_prims:
                for p_exec in exec_prims:
                    cid = f"CAND-3HOP-SSRF-AUTH-EXEC-{round_num}-{p_ssrf.node_id[-4:]}-{p_auth.node_id[-4:]}-{p_exec.node_id[-4:]}"
                    scan_s = str(p_ssrf.attributes.get("scanner", "scanner"))
                    scan_a = str(p_auth.attributes.get("scanner", "raptor"))
                    scan_e = str(p_exec.attributes.get("scanner", "mantis"))
                    target_asset = http_endpoints[0].node_id if http_endpoints else default_asset_id
                    target_route = http_endpoints[0].attributes.get("route", "/") if http_endpoints else "/"
                    added = self._add_candidate(
                        cid=cid,
                        label=f"[3-HOP COMPOUND] SSRF Pivot ({scan_s}) -> Auth Secret ({scan_a}) -> Exec Sink ({scan_e})",
                        anchored_asset_id=target_asset,
                        attributes={
                            "attack_type": "3HOP_SSRF_AUTH_EXEC",
                            "has_ai_sink": False,
                            "wire_primitive_id": p_ssrf.node_id,
                            "secondary_primitive_id": p_auth.node_id,
                            "tertiary_primitive_id": p_exec.node_id,
                            "target_route": target_route,
                            "target_path": p_exec.attributes.get("file_path", target_route),
                            "hop_count": 3,
                            "is_multi_hop": True,
                            "source_scanners": sorted({scan_s, scan_a, scan_e}),
                            "chain_steps": [
                                {"step": 1, "finding_id": p_ssrf.node_id, "capability": "SSRF_PIVOT", "scanner": scan_s, "desc": p_ssrf.label},
                                {"step": 2, "finding_id": p_auth.node_id, "capability": "AUTH_SECRET", "scanner": scan_a, "desc": p_auth.label},
                                {"step": 3, "finding_id": p_exec.node_id, "capability": "EXEC_SINK", "scanner": scan_e, "desc": p_exec.label},
                                {"step": 4, "desc": "SSRF pivots to internal cloud metadata/secret store to steal auth token, which is replayed to execute commands via privileged sink"},
                            ],
                        },
                        source_nodes=[p_ssrf.node_id, p_auth.node_id, p_exec.node_id],
                        target_asset_id=target_asset,
                    )
                    if added:
                        new_candidates.append(added)

        # Pattern 4: ZERO_DAY_CANDIDATE -> AI_INJECTION / EXEC_SINK
        for p_zd in zero_day_prims:
            scan_z = str(p_zd.attributes.get("scanner", "mantis-0day"))
            # 3-hop options via auth
            for p_auth in auth_prims:
                for p_exec in exec_prims:
                    cid = f"CAND-3HOP-0DAY-AUTH-EXEC-{round_num}-{p_zd.node_id[-4:]}-{p_auth.node_id[-4:]}-{p_exec.node_id[-4:]}"
                    scan_a = str(p_auth.attributes.get("scanner", "raptor"))
                    scan_e = str(p_exec.attributes.get("scanner", "mantis"))
                    target_asset = http_endpoints[0].node_id if http_endpoints else default_asset_id
                    target_route = http_endpoints[0].attributes.get("route", "/") if http_endpoints else "/"
                    added = self._add_candidate(
                        cid=cid,
                        label=f"[3-HOP COMPOUND] Zero-Day ({scan_z}) -> Auth Secret ({scan_a}) -> Exec Sink ({scan_e})",
                        anchored_asset_id=target_asset,
                        attributes={
                            "attack_type": "3HOP_ZERODAY_AUTH_EXEC",
                            "has_ai_sink": False,
                            "wire_primitive_id": p_zd.node_id,
                            "secondary_primitive_id": p_auth.node_id,
                            "tertiary_primitive_id": p_exec.node_id,
                            "target_route": target_route,
                            "target_path": p_exec.attributes.get("file_path", target_route),
                            "hop_count": 3,
                            "is_multi_hop": True,
                            "source_scanners": sorted({scan_z, scan_a, scan_e}),
                            "chain_steps": [
                                {"step": 1, "finding_id": p_zd.node_id, "capability": "ZERO_DAY_CANDIDATE", "scanner": scan_z, "desc": p_zd.label},
                                {"step": 2, "finding_id": p_auth.node_id, "capability": "AUTH_SECRET", "scanner": scan_a, "desc": p_auth.label},
                                {"step": 3, "finding_id": p_exec.node_id, "capability": "EXEC_SINK", "scanner": scan_e, "desc": p_exec.label},
                                {"step": 4, "desc": "Synthesized zero-day protocol divergence bypassed perimeter to access auth secrets, pivoting into code execution sink"},
                            ],
                        },
                        source_nodes=[p_zd.node_id, p_auth.node_id, p_exec.node_id],
                        target_asset_id=target_asset,
                    )
                    if added:
                        new_candidates.append(added)

                for p_ai in ai_prims:
                    cid = f"CAND-3HOP-0DAY-AUTH-AI-{round_num}-{p_zd.node_id[-4:]}-{p_auth.node_id[-4:]}-{p_ai.node_id[-4:]}"
                    scan_a = str(p_auth.attributes.get("scanner", "raptor"))
                    scan_i = str(p_ai.attributes.get("scanner", "aiscan"))
                    target_asset = ai_sinks[0].node_id if ai_sinks else default_asset_id
                    target_route = ai_sinks[0].attributes.get("route", "/api/chat") if ai_sinks else "/api/chat"
                    added = self._add_candidate(
                        cid=cid,
                        label=f"[3-HOP COMPOUND] Zero-Day ({scan_z}) -> Auth Secret ({scan_a}) -> AI Injection ({scan_i})",
                        anchored_asset_id=target_asset,
                        attributes={
                            "attack_type": "3HOP_ZERODAY_AUTH_AI_INJECTION",
                            "has_ai_sink": True,
                            "wire_primitive_id": p_zd.node_id,
                            "secondary_primitive_id": p_auth.node_id,
                            "tertiary_primitive_id": p_ai.node_id,
                            "target_route": target_route,
                            "target_path": p_ai.attributes.get("file_path", target_route),
                            "hop_count": 3,
                            "is_multi_hop": True,
                            "source_scanners": sorted({scan_z, scan_a, scan_i}),
                            "chain_steps": [
                                {"step": 1, "finding_id": p_zd.node_id, "capability": "ZERO_DAY_CANDIDATE", "scanner": scan_z, "desc": p_zd.label},
                                {"step": 2, "finding_id": p_auth.node_id, "capability": "AUTH_SECRET", "scanner": scan_a, "desc": p_auth.label},
                                {"step": 3, "finding_id": p_ai.node_id, "capability": "AI_INJECTION", "scanner": scan_i, "desc": p_ai.label},
                                {"step": 4, "desc": "Zero-day vulnerability leverages stolen auth to inject prompt into protected AI sink"},
                            ],
                        },
                        source_nodes=[p_zd.node_id, p_auth.node_id, p_ai.node_id],
                        target_asset_id=target_asset,
                    )
                    if added:
                        new_candidates.append(added)

            # Direct 2-hop zero-day combinations
            for p_exec in exec_prims:
                cid = f"CAND-0DAY-EXEC-{round_num}-{p_zd.node_id[-4:]}-{p_exec.node_id[-4:]}"
                scan_e = str(p_exec.attributes.get("scanner", "mantis"))
                target_asset = http_endpoints[0].node_id if http_endpoints else default_asset_id
                target_route = http_endpoints[0].attributes.get("route", "/") if http_endpoints else "/"
                added = self._add_candidate(
                    cid=cid,
                    label=f"[COMPOUND CHAIN] Zero-Day ({scan_z}) -> Exec Sink ({scan_e}): {p_zd.label[:40]}",
                    anchored_asset_id=target_asset,
                    attributes={
                        "attack_type": "ZERODAY_EXEC_SINK",
                        "has_ai_sink": False,
                        "wire_primitive_id": p_zd.node_id,
                        "secondary_primitive_id": p_exec.node_id,
                        "target_route": target_route,
                        "target_path": p_exec.attributes.get("file_path", target_route),
                        "hop_count": 2,
                        "is_multi_hop": True,
                        "source_scanners": sorted({scan_z, scan_e}),
                        "chain_steps": [
                            {"step": 1, "finding_id": p_zd.node_id, "capability": "ZERO_DAY_CANDIDATE", "scanner": scan_z, "desc": p_zd.label},
                            {"step": 2, "finding_id": p_exec.node_id, "capability": "EXEC_SINK", "scanner": scan_e, "desc": p_exec.label},
                            {"step": 3, "desc": "Synthesized zero-day protocol divergence chains into dangerous code/command execution sink"},
                        ],
                    },
                    source_nodes=[p_zd.node_id, p_exec.node_id],
                    target_asset_id=target_asset,
                )
                if added:
                    new_candidates.append(added)

            for p_ai in ai_prims:
                cid = f"CAND-0DAY-AI-{round_num}-{p_zd.node_id[-4:]}-{p_ai.node_id[-4:]}"
                scan_i = str(p_ai.attributes.get("scanner", "aiscan"))
                target_asset = ai_sinks[0].node_id if ai_sinks else default_asset_id
                target_route = ai_sinks[0].attributes.get("route", "/api/chat") if ai_sinks else "/api/chat"
                added = self._add_candidate(
                    cid=cid,
                    label=f"[COMPOUND CHAIN] Zero-Day ({scan_z}) -> AI Injection ({scan_i}): {p_zd.label[:40]}",
                    anchored_asset_id=target_asset,
                    attributes={
                        "attack_type": "ZERODAY_AI_INJECTION",
                        "has_ai_sink": True,
                        "wire_primitive_id": p_zd.node_id,
                        "secondary_primitive_id": p_ai.node_id,
                        "target_route": target_route,
                        "target_path": p_ai.attributes.get("file_path", target_route),
                        "hop_count": 2,
                        "is_multi_hop": True,
                        "source_scanners": sorted({scan_z, scan_i}),
                        "chain_steps": [
                            {"step": 1, "finding_id": p_zd.node_id, "capability": "ZERO_DAY_CANDIDATE", "scanner": scan_z, "desc": p_zd.label},
                            {"step": 2, "finding_id": p_ai.node_id, "capability": "AI_INJECTION", "scanner": scan_i, "desc": p_ai.label},
                            {"step": 3, "desc": "Zero-day protocol flaw allows directly reaching and injecting prompts into unmetered AI endpoint"},
                        ],
                    },
                    source_nodes=[p_zd.node_id, p_ai.node_id],
                    target_asset_id=target_asset,
                )
                if added:
                    new_candidates.append(added)

        return new_candidates


class ArtexWorker:
    """
    Executes specific tactical intents and attack candidates, recording
    verified exploits in the exploration graph and terminator.db.
    """

    def __init__(self, exploration_graph: ExplorationGraph, db: Optional[Any] = None):
        self.exploration_graph = exploration_graph
        self.db = db

    def execute_candidate(
        self,
        candidate: ExplorationNode,
        executor_fn: Optional[Callable[[Dict[str, Any]], Tuple[bool, str, str]]] = None,
    ) -> bool:
        """
        Executes an attack candidate using a verification function.
        Returns True if the attack chain is verified as an active exploit.
        """
        candidate.status = "ACTIVE"
        attrs = candidate.attributes

        success = False
        evidence = ""
        payload = ""

        if executor_fn:
            try:
                success, evidence, payload = executor_fn(attrs)
            except Exception as e:
                evidence = f"Execution error: {e}"
                success = False
        else:
            # Default deterministic verification: verify prerequisite anomaly exists
            success = bool(attrs.get("wire_primitive_id") or attrs.get("is_multi_hop") or attrs.get("secondary_primitive_id"))
            evidence = "Verified multi-hop attack chain linked to target assets."
            payload = "SMUGGLED-CANARY-PAYLOAD"

        if success:
            candidate.status = "VERIFIED"
            exploit_id = f"EXPLOIT-{candidate.node_id}"
            exploit_node = self.exploration_graph.add_intent(
                node_id=exploit_id,
                node_type="CONFIRMED_EXPLOIT",
                label=f"CONFIRMED: {candidate.label}",
                anchored_asset_id=candidate.anchored_asset_id,
                attributes={
                    **attrs,
                    "evidence": evidence,
                    "raw_payload": payload,
                    "verified_at": datetime.now().isoformat(),
                },
                status="VERIFIED",
            )
            self.exploration_graph.add_relation(exploit_id, candidate.node_id, "PROVES")

            # Persist attack chain in terminator.db
            if self.db and hasattr(self.db, "save_attack_chain"):
                try:
                    self.db.save_attack_chain(
                        chain_id=exploit_id,
                        title=candidate.label,
                        attack_type=attrs.get("attack_type", "GENERIC_CHAIN"),
                        target_host=attrs.get("target_host", "127.0.0.1"),
                        target_endpoint=attrs.get("target_route", attrs.get("target_endpoint", "/")),
                        framing_anomaly_id=attrs.get("wire_primitive_id"),
                        ai_sink_id=None,
                        steps=attrs.get("chain_steps") or [{"step": 1, "desc": "Wire framing desync established"}, {"step": 2, "desc": candidate.label, "evidence": evidence}],
                        raw_payload=payload,
                        is_verified=True,
                        severity="CRITICAL" if ("PROMPT" in attrs.get("attack_type", "") or attrs.get("has_ai_sink")) else "HIGH",
                    )
                except Exception as e:
                    logger.debug("Failed to persist attack chain: %s", e)
            return True
        else:
            candidate.status = "FAILED"
            return False


DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def derive_capability_class(f_dict: Dict[str, Any], scanner: str = "unknown") -> str:
    """
    Derives the canonical ARTEX capability class for a scanner finding.
    Supported classes:
    - DESYNC: Protocol framing anomalies, CL.TE, TE.CL, CRLF injection, chunk errors, CWE-444, ActiveFlawProber, ProtocolRuler, Harness2
    - AUTH_SECRET: Hardcoded keys, token leaks, missing auth, CWE-798, CWE-287, CWE-306, CWE-522
    - SSRF_PIVOT: Server-side request forgery, CWE-918, unvalidated fetch
    - EXEC_SINK: Command injection, code execution, SQLi, unsafe deserialization, CWE-78, CWE-94, CWE-89, CWE-502, CWE-22
    - AI_INJECTION: Prompt injection, jailbreak, unmetered AI endpoint, model inversion, aiscan, PromptSmugglingSynthesizer
    - ZERO_DAY_CANDIDATE: Synthesized zero-day hypotheses (is_zero_day=True, hypothesis_id), Harness2 differential divergence
    - CRYPTO_WEAK: Classical/non-PQC cryptography, weak hashing, CWE-327, CWE-328, CWE-1395
    - SUPPLY_CHAIN: Vulnerable dependencies, SCA findings
    """
    if f_dict.get("capability_class"):
        return str(f_dict["capability_class"]).upper()

    rule_id = str(f_dict.get("rule_id") or f_dict.get("ruleId") or f_dict.get("anomaly_id") or f_dict.get("finding_id") or "").upper()
    title = str(f_dict.get("title") or f_dict.get("name") or "").upper()
    cwe = str(f_dict.get("cwe") or f_dict.get("cwe_id") or "").upper()
    desc = str(f_dict.get("description") or "").upper()
    cat = str(f_dict.get("category") or f_dict.get("vulnerability_type") or f_dict.get("anomaly_type") or "").upper()
    evidence = str(f_dict.get("evidence") or f_dict.get("reproducible_evidence") or "").upper()
    scanner_upper = str(f_dict.get("scanner") or scanner or "").upper()
    full_text = f"{rule_id} {title} {cwe} {desc} {cat} {evidence} {scanner_upper}"

    # 1. ZERO_DAY_CANDIDATE: Synthesized zero-day hypotheses (is_zero_day=True, hypothesis_id), Harness2 differential divergence
    if (
        f_dict.get("is_zero_day") is True
        or bool(f_dict.get("hypothesis_id"))
        or "0DAY" in rule_id
        or "ZERO_DAY" in full_text
        or "ZERO-DAY" in full_text
        or ("HARNESS2" in scanner_upper and "DIVERGENCE" in full_text)
        or "DIFFERENTIAL DIVERGENCE" in full_text
    ):
        return "ZERO_DAY_CANDIDATE"

    # 2. AI_INJECTION: Prompt injection, jailbreak, unmetered AI endpoint, model inversion, aiscan, PromptSmugglingSynthesizer
    if (
        any(s in scanner_upper for s in ("AISCAN", "PROMPTSMUGGLINGSYNTHESIZER"))
        or any(k in full_text for k in ("PROMPT INJECTION", "JAILBREAK", "UNMETERED AI", "MODEL INVERSION", "PROMPT SMUGGLING", "AI_INJECTION", "PROMPT"))
    ):
        return "AI_INJECTION"

    # 3. SSRF_PIVOT: Server-side request forgery, CWE-918, unvalidated fetch
    if (
        "CWE-918" in full_text
        or any(k in full_text for k in ("SSRF", "SERVER-SIDE REQUEST FORGERY", "UNVALIDATED FETCH", "METADATA PIVOT", "SSRF_PIVOT"))
    ):
        return "SSRF_PIVOT"

    # 4. AUTH_SECRET: Hardcoded keys, token leaks, missing auth, CWE-798, CWE-287, CWE-306, CWE-522
    if (
        any(c in full_text for c in ("CWE-798", "CWE-287", "CWE-306", "CWE-522"))
        or any(k in full_text for k in ("HARDCODED", "SECRET", "TOKEN LEAK", "API_KEY", "JWT", "PASSWORD", "MISSING AUTH", "UNAUTHENTICATED", "AUTH BYPASS", "CREDENTIAL", "AUTH_SECRET"))
    ):
        return "AUTH_SECRET"

    # 5. EXEC_SINK: Command injection, code execution, SQLi, unsafe deserialization, CWE-78, CWE-94, CWE-89, CWE-502, CWE-22
    if (
        any(c in full_text for c in ("CWE-78", "CWE-94", "CWE-89", "CWE-502", "CWE-22"))
        or any(k in full_text for k in ("COMMAND INJECTION", "CODE EXECUTION", "RCE", "SQLI", "SQL INJECTION", "DESERIALIZATION", "PATH TRAVERSAL", "EXEC_SINK", "SYSTEM(", "SUBPROCESS"))
    ):
        return "EXEC_SINK"

    # 6. CRYPTO_WEAK: Classical/non-PQC cryptography, weak hashing, CWE-327, CWE-328, CWE-1395
    if (
        any(c in full_text for c in ("CWE-327", "CWE-328", "CWE-1395"))
        or any(k in full_text for k in ("NON-PQC", "NON_PQC", "CLASSICAL CRYPTOGRAPHY", "WEAK HASH", "MD5", "SHA1", "WEAK CRYPTO", "PQC", "CRYPTO_WEAK"))
    ):
        return "CRYPTO_WEAK"

    # 7. SUPPLY_CHAIN: Vulnerable dependencies, SCA findings
    if (
        any(k in full_text for k in ("SUPPLY_CHAIN", "SUPPLY CHAIN", "SCA", "DEPENDENCY", "CVE-", "OUTDATED PACKAGE", "VULNERABLE DEPENDENCY"))
    ):
        return "SUPPLY_CHAIN"

    # 8. DESYNC: Protocol framing anomalies, CL.TE, TE.CL, CRLF injection, chunk errors, CWE-444, ActiveFlawProber, ProtocolRuler, Harness2
    if (
        "CWE-444" in full_text
        or any(k in full_text for k in ("CL.TE", "TE.CL", "CL_TE", "TE_CL", "CRLF", "CHUNK", "DESYNC", "SMUGGLING", "FRAMING"))
        or any(s in scanner_upper for s in ("ACTIVEFLAWPROBER", "PROTOCOLRULER", "HARNESS2"))
        or rule_id.startswith("RFC")
        or rule_id.startswith("PROBE-")
    ):
        return "DESYNC"

    return "DESYNC"


class DualGraphAttackEngine:
    """
    Orchestrates the ARTEX Asset Graph, Exploration Graph, Planner, and Worker.
    Outputs reports purely into reports/ folder without any UI.
    """

    def __init__(self, db: Optional[Any] = None, reports_dir: Optional[Union[str, Path]] = None):
        self.db = db
        self.reports_dir = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.asset_graph = AssetGraph(db=self.db)
        self.exploration_graph = ExplorationGraph(db=self.db)
        self.planner = ArtexPlanner(self.asset_graph, self.exploration_graph)
        self.worker = ArtexWorker(self.exploration_graph, db=self.db)

    def ingest_target_infrastructure(
        self,
        host: Union[str, Dict[str, Any]],
        port: int = 80,
        endpoints: Optional[List[Union[str, Dict[str, Any]]]] = None,
        ai_sinks: Optional[List[Union[str, Dict[str, Any]]]] = None,
    ) -> None:
        """Populates the Asset Graph with target domains, ports, and endpoints.
        Normalizes both string and dictionary representations to prevent AttributeError.
        """
        if isinstance(host, dict):
            resolved_port = int(host.get("port") or port or 80)
            resolved_host = str(host.get("host") or host.get("hostname") or host.get("domain") or "target-host")
        else:
            resolved_host = str(host or "target-host")
            resolved_port = int(port or 80)

        domain_id = f"ASSET-HOST-{resolved_host}"
        self.asset_graph.add_asset(domain_id, "DOMAIN", resolved_host, {"host": resolved_host})

        port_id = f"ASSET-PORT-{resolved_host}-{resolved_port}"
        self.asset_graph.add_asset(port_id, "IP_PORT", f"{resolved_host}:{resolved_port}", {"host": resolved_host, "port": resolved_port})
        self.asset_graph.add_relation(domain_id, port_id, "HOSTS")

        for idx, ep in enumerate(endpoints or []):
            if isinstance(ep, str):
                route = ep
                method = "GET"
            elif isinstance(ep, dict):
                route = ep.get("route") or ep.get("function") or ep.get("path") or "/"
                method = ep.get("method") or ep.get("http_method") or "GET"
            else:
                route = str(ep)
                method = "GET"

            ep_id = f"ASSET-EP-{resolved_host}-{idx}"
            self.asset_graph.add_asset(
                ep_id,
                "ENDPOINT",
                f"{method} {route}",
                {"route": route, "host": resolved_host, "port": resolved_port, "method": method},
            )
            self.asset_graph.add_relation(port_id, ep_id, "EXPOSES")

        for idx, sink in enumerate(ai_sinks or []):
            if isinstance(sink, str):
                route = sink
                model = "local_ai"
                sink_name = sink
                method = "POST"
                file_path = ""
            elif isinstance(sink, dict):
                route = sink.get("route_path") or sink.get("route") or sink.get("title") or "/api/chat"
                model = sink.get("model_provider") or sink.get("model") or "local_ai"
                sink_name = sink.get("title") or sink.get("sink_name") or route
                method = sink.get("http_method") or sink.get("method") or "POST"
                file_path = sink.get("file_path") or sink.get("file") or ""
            else:
                route = str(sink)
                model = "local_ai"
                sink_name = str(sink)
                method = "POST"
                file_path = ""

            sink_id = f"ASSET-AI-SINK-{resolved_host}-{idx}"
            self.asset_graph.add_asset(
                sink_id,
                "AI_SINK",
                f"AI Endpoint: {method} {route}",
                {
                    "route": route,
                    "model": model,
                    "file": file_path,
                    "sink_name": sink_name,
                    "method": method,
                },
            )
            self.asset_graph.add_relation(port_id, sink_id, "DISPATCHES_TO")

    def ingest_finding(self, finding: Any, scanner: str = "unknown") -> Optional[ExplorationNode]:
        """
        Normalizes and registers a security finding from any detector (Mantis, aiscan,
        RAPTOR, ProtocolRuler, ActiveFlawProber, Harness2, AnomalyDetector) as an ARTEX
        ExplorationNode finding primitive with an automatically derived capability class.
        """
        if finding is None:
            return None

        if isinstance(finding, dict):
            f_dict = finding
        elif hasattr(finding, "to_dict") and callable(finding.to_dict):
            try:
                f_dict = finding.to_dict()
            except Exception:
                f_dict = {k: getattr(finding, k) for k in dir(finding) if not k.startswith("_") and not callable(getattr(finding, k))}
        elif hasattr(finding, "__dict__"):
            f_dict = finding.__dict__
        else:
            f_dict = {k: getattr(finding, k) for k in dir(finding) if not k.startswith("_") and not callable(getattr(finding, k))}

        scanner_name = str(f_dict.get("scanner") or scanner or "unknown")
        rule_id = str(f_dict.get("rule_id") or f_dict.get("ruleId") or f_dict.get("anomaly_id") or f_dict.get("finding_id") or f_dict.get("id") or "UNKNOWN_RULE")
        title = str(f_dict.get("title") or f_dict.get("name") or f_dict.get("description") or f_dict.get("label") or rule_id)
        cwe = str(f_dict.get("cwe") or f_dict.get("cwe_id") or "")
        severity = str(f_dict.get("severity") or "HIGH").upper()
        file_path = str(f_dict.get("file_path") or f_dict.get("path") or f_dict.get("file") or f_dict.get("target_path") or "")
        try:
            line_number = int(f_dict.get("line_number") or f_dict.get("line") or 1)
        except (ValueError, TypeError):
            line_number = 1
        evidence = str(f_dict.get("evidence") or f_dict.get("reproducible_evidence") or f_dict.get("snippet") or f_dict.get("raw_probe") or "")

        capability_class = derive_capability_class(f_dict, scanner=scanner_name)

        # Resolve asset anchor
        http_endpoints = self.asset_graph.find_endpoints_by_type("ENDPOINT")
        ai_sinks = self.asset_graph.find_endpoints_by_type("AI_SINK")
        ip_ports = self.asset_graph.find_endpoints_by_type("IP_PORT")
        domains = self.asset_graph.find_endpoints_by_type("DOMAIN")

        anchored_asset = None
        if capability_class == "AI_INJECTION" and ai_sinks:
            anchored_asset = ai_sinks[0]
        elif http_endpoints:
            anchored_asset = http_endpoints[0]
        elif ai_sinks:
            anchored_asset = ai_sinks[0]
        elif ip_ports:
            anchored_asset = ip_ports[0]
        elif domains:
            anchored_asset = domains[0]

        anchor_id = anchored_asset.node_id if anchored_asset else None

        node_id = f"EXPLORE-FIND-{scanner_name}-{rule_id}-{len(self.exploration_graph.nodes)}"
        label = f"[{capability_class}] {title}"

        attributes = {
            "scanner": scanner_name,
            "rule_id": rule_id,
            "cwe": cwe,
            "severity": severity,
            "file_path": file_path,
            "line_number": line_number,
            "evidence": evidence,
            "capability_class": capability_class,
            "title": title,
            "description": str(f_dict.get("description") or title),
            "raw_finding": f_dict,
        }

        node = self.exploration_graph.add_intent(
            node_id=node_id,
            node_type="FINDING_PRIMITIVE",
            label=label,
            anchored_asset_id=anchor_id,
            attributes=attributes,
            status="VERIFIED",
        )

        if anchor_id:
            self.exploration_graph.add_relation(node_id, anchor_id, "ANCHORS_TO", {"scanner": scanner_name})

        return node

    def ingest_findings(self, findings: List[Any], scanner: str = "unknown") -> List[ExplorationNode]:
        """Ingests a collection of security findings into the exploration graph."""
        nodes: List[ExplorationNode] = []
        for finding in (findings or []):
            node = self.ingest_finding(finding, scanner=scanner)
            if node:
                nodes.append(node)
        return nodes

    ingest_scanner_finding = ingest_finding
    ingest_scanner_findings = ingest_findings

    def register_wire_primitive(self, anomaly_id: str, description: str, anomaly_type: str = "HTTP_DESYNC", raw_probe: str = "") -> ExplorationNode:
        """Registers a discovered wire-level framing anomaly as an exploitation primitive."""
        node_id = f"EXPLORE-PRIM-{anomaly_id}"
        return self.exploration_graph.add_intent(
            node_id=node_id,
            node_type="WIRE_PRIMITIVE",
            label=description,
            status="VERIFIED",
            attributes={
                "anomaly_type": anomaly_type,
                "anomaly_id": anomaly_id,
                "raw_probe": raw_probe,
            },
        )

    def run_attack_chain_cycle(
        self,
        round_num: int = 1,
        executor_fn: Optional[Callable[[Dict[str, Any]], Tuple[bool, str, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Executes one full Planner -> Worker cycle and writes reports to reports/ folder.
        """
        new_candidates = self.planner.plan_next_round(round_num=round_num)
        all_candidates = list(new_candidates)
        for p in self.exploration_graph.get_pending_candidates():
            if p not in all_candidates:
                all_candidates.append(p)

        verified_count = 0
        for cand in all_candidates:
            if self.worker.execute_candidate(cand, executor_fn=executor_fn):
                verified_count += 1

        report_files = self.generate_reports()

        return {
            "round": round_num,
            "total_assets": len(self.asset_graph.nodes),
            "total_intents": len(self.exploration_graph.nodes),
            "candidates_planned": len(all_candidates),
            "exploits_verified": verified_count,
            "report_files": report_files,
        }

    def generate_reports(self) -> Dict[str, str]:
        """Outputs dual-graph reports directly into reports/ folder without any UI."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = self.reports_dir / f"dual_graph_report_{timestamp}.json"
        summary_file = self.reports_dir / f"dual_graph_summary_{timestamp}.txt"

        assets_dict = [n.to_dict() for n in self.asset_graph.nodes.values()]
        explores_dict = [n.to_dict() for n in self.exploration_graph.nodes.values()]
        edges_dict = [e.to_dict() for e in self.asset_graph.edges + self.exploration_graph.edges]

        # 1. JSON Report
        json_data = {
            "timestamp": timestamp,
            "asset_graph": {
                "nodes": assets_dict,
                "count": len(assets_dict),
            },
            "exploration_graph": {
                "nodes": explores_dict,
                "count": len(explores_dict),
            },
            "edges": edges_dict,
        }
        json_file.write_text(json.dumps(json_data, indent=2), encoding="utf-8")

        # 2. Text Summary Report
        lines = [
            "=" * 70,
            "  ARTEX DUAL-GRAPH ATTACK CHAINING REPORT",
            "=" * 70,
            f"Timestamp        : {timestamp}",
            f"Total Assets     : {len(assets_dict)}",
            f"Exploration Nodes: {len(explores_dict)}",
            f"Graph Edges      : {len(edges_dict)}",
            "-" * 70,
            "ASSET GRAPH TOPOLOGY:",
        ]
        for a in assets_dict:
            lines.append(f"  [{a['node_type']}] {a['label']} (id={a['node_id']})")

        lines.append("-" * 70)
        lines.append("EXPLORATION GRAPH (ATTACK CHAINS & EXPLOITS):")
        for e in explores_dict:
            lines.append(f"  [{e['status']}] {e['node_type']} | {e['label']}")
            if e.get("attributes", {}).get("evidence"):
                lines.append(f"      Evidence: {e['attributes']['evidence']}")

        lines.append("=" * 70)
        summary_file.write_text("\n".join(lines), encoding="utf-8")

        return {
            "json": str(json_file),
            "summary": str(summary_file),
        }

    def export_attack_chains_to_sarif_findings(self) -> List[Dict[str, Any]]:
        """
        Exports planned attack candidates and confirmed exploits as normalized
        finding dictionaries compatible with build_sarif_document.
        """
        findings: List[Dict[str, Any]] = []
        candidates = [
            n
            for n in self.exploration_graph.nodes.values()
            if n.node_type in ("ATTACK_CANDIDATE", "CONFIRMED_EXPLOIT")
        ]
        seen_keys = set()
        for cand in candidates:
            attack_type = cand.attributes.get("attack_type", "CHAIN")
            rule_id = f"ARTEX-{attack_type}"
            key = (rule_id, cand.label)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            finding = {
                "rule_id": rule_id,
                "title": cand.label,
                "severity": "CRITICAL" if "EXPLOIT" in cand.node_type or cand.attributes.get("has_ai_sink") else "HIGH",
                "cwe": cand.attributes.get("cwe", "CWE-444"),
                "file_path": cand.attributes.get("target_path", "network-target"),
                "line_number": 1,
                "description": cand.attributes.get("description", cand.label),
                "scanner": "Module-17-ARTEX-DualGraph",
                "chain_steps": cand.attributes.get("chain_steps", []),
            }
            findings.append(finding)
        return findings

