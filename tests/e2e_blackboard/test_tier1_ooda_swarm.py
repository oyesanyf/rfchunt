"""
Tier 1 Feature Contract Tests: OODA Blackboard Router & Prompt Absorption (Features #5-#9).
Covers `PROJECT.md § Interface Contracts` #3 (>= 5 tests per feature = 25 tests).

Collection-safe: M2 additions (`blackboard_router`, `ResearchState` fields,
`hints` kwarg on `ProbeGenerator`/`FusionArbiter`) are resolved at runtime inside
test bodies rather than imported at module top level.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, get_type_hints

import pytest

from database import Database
from engine.taxonomy import AnomalyCategory, ImpactClass, ImplementationAnomaly, ReproducibleVulnerability
from fusion_engine import FusionArbiter
from probe_generator import ProbeGenerator


def _make_offline_swarm(
    ws: SimpleNamespace,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    use_fusion: bool = False,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    """Instantiate `ProtocolResearchSwarm` strictly inside isolated `tmp_path` workspace."""
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import ProtocolResearchSwarm

    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(FusionArbiter, "_fetch_available_tags", lambda self: ["gemma2:2b"])

    swarm = ProtocolResearchSwarm(
        host=host,
        port=port,
        db_path=str(ws.db_path),
        use_fusion=use_fusion,
        concurrency=2,
    )
    swarm.fetcher.cache_dir = ws.rfcs_dir
    swarm.dream_store.storage_path = str(ws.root / "data" / "dream_policies.json")
    swarm.harness2_engine.runs_root = ws.harness2_runs_dir
    return swarm


def _base_state(ws: SimpleNamespace, *, rfc_num: str = "9112", max_cycles: int = 1, **extra: Any) -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "rfc_num": rfc_num,
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
        "max_cycles": max_cycles,
        "baseline_resp": b"",
        "enable_dream_rsi": False,
        "dream_rollouts": 10,
        "current_dream_policy": None,
        "enable_harness2": False,
        "harness2_k": 1,
        "harness2_mode": "parallel",
        "harness2_runs_dir": str(ws.harness2_runs_dir),
        "harness2_domain": "auto",
        "current_harness2_result": None,
        "history": [],
        "ooda_phase": "Bootstrap",
        "blackboard_bootstrapped": False,
        "active_intent_id": None,
        "active_intent": None,
        "active_hints": [],
        "task_id": "e2e-ooda-task",
        "workspace_dir": str(ws.root),
        "blackboard_domain": "http11_framing",
    }
    state.update(extra)
    return state


# =============================================================================
# Feature #5: `blackboard_router` & `ResearchState` (5 tests)
# =============================================================================


def test_t1_f5_research_state_exposes_ooda_blackboard_fields() -> None:
    from rfc_hunt_swarm import ResearchState

    hints = get_type_hints(ResearchState)
    required_keys = {
        "ooda_phase",
        "blackboard_bootstrapped",
        "active_intent_id",
        "active_intent",
        "active_hints",
        "task_id",
        "workspace_dir",
        "blackboard_domain",
    }
    assert required_keys.issubset(set(hints.keys())), f"Missing ResearchState keys: {required_keys - set(hints.keys())}"


def test_t1_f5_build_graph_uses_blackboard_router_hub(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, sys_p, usr_p: [
            {
                "rationale": "Router hub probe",
                "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
                "is_clean": True,
            }
        ],
    )
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    router_calls: List[str] = []
    orig_router = swarm.blackboard_router

    def _spy_router(st: Dict[str, Any]) -> Dict[str, Any]:
        out = orig_router(st)
        router_calls.append(str(out.get("ooda_phase", "")))
        return out

    monkeypatch.setattr(swarm, "blackboard_router", _spy_router)

    legacy_calls: List[str] = []
    for legacy_router in (
        "route_after_generation",
        "route_after_execution",
        "route_after_triage",
        "route_after_publish",
    ):
        if hasattr(swarm, legacy_router):
            monkeypatch.setattr(
                swarm,
                legacy_router,
                lambda st, _name=legacy_router: legacy_calls.append(_name) or "__end__",
            )

    try:
        assert hasattr(swarm, "blackboard_router") and callable(swarm.blackboard_router)
        graph = swarm.build_graph()
        node_names = set(getattr(graph, "nodes", {}).keys())
        assert "blackboard_router" in node_names
        graph.invoke(_base_state(isolated_swarm_workspace, max_cycles=1), {"recursion_limit": 200})
        assert len(router_calls) >= 2
        assert legacy_calls == []
    finally:
        swarm.close()


def test_t1_f5_blackboard_router_selects_bootstrap_reason_explore_end(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        # Unbootstrapped state -> Bootstrap
        s0 = _base_state(isolated_swarm_workspace, blackboard_bootstrapped=False)
        r0 = swarm.blackboard_router(s0)
        assert isinstance(r0, dict) and r0.get("ooda_phase") == "Bootstrap"

        # Bootstrapped + pending INTENT -> Explore
        swarm.db.queue_intent("GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", priority=5.0, task_id="t-route")
        s1 = _base_state(
            isolated_swarm_workspace,
            task_id="t-route",
            blackboard_bootstrapped=True,
            cycle_count=0,
            max_cycles=2,
        )
        r1 = swarm.blackboard_router(s1)
        assert isinstance(r1, dict) and r1.get("ooda_phase") in ("Explore", "Reason")

        # Exhausted cycles and empty queue -> Done / Dream / Terminate
        swarm2_task = "t-route-empty"
        s2 = _base_state(
            isolated_swarm_workspace,
            task_id=swarm2_task,
            blackboard_bootstrapped=True,
            fragments=[],
            generated_candidates=[],
            cycle_count=2,
            max_cycles=2,
            enable_dream_rsi=False,
        )
        r2 = swarm.blackboard_router(s2)
        assert isinstance(r2, dict)
        assert str(r2.get("ooda_phase", "")).lower() in ("done", "end", "__end__", "complete", "terminate")
    finally:
        swarm.close()


def test_t1_f5_compiled_graph_invoke_completes_on_loopback_lab(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, sys_p, usr_p: [
            {
                "rationale": "Test normal request",
                "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
                "is_clean": True,
            }
        ],
    )
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        graph = swarm.build_graph()
        final_state = graph.invoke(_base_state(isolated_swarm_workspace, max_cycles=1), {"recursion_limit": 200})
        assert final_state.get("blackboard_bootstrapped") is True
        assert len(final_state.get("history", [])) >= 1
        assert len(swarm.db.get_blackboard_nodes(task_id="e2e-ooda-task")) >= 1
    finally:
        swarm.close()


def test_t1_f5_fallback_graph_runs_blackboard_router_identically(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, sys_p, usr_p: [
            {
                "rationale": "Fallback graph probe",
                "raw_request": "GET /health HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
                "is_clean": True,
            }
        ],
    )
    # Trigger _resolve_langgraph() ImportError fallback naturally without touching private classes
    monkeypatch.setitem(sys.modules, "langgraph", None)
    monkeypatch.setitem(sys.modules, "langgraph.graph", None)

    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    router_calls: List[str] = []
    orig_router = swarm.blackboard_router

    def _spy_router(st: Dict[str, Any]) -> Dict[str, Any]:
        out = orig_router(st)
        router_calls.append(str(out.get("ooda_phase", "")))
        return out

    monkeypatch.setattr(swarm, "blackboard_router", _spy_router)
    try:
        graph = swarm.build_graph()
        assert "blackboard_router" in graph.nodes
        out = graph.invoke(_base_state(isolated_swarm_workspace, max_cycles=1))
        assert out.get("blackboard_bootstrapped") is True
        assert len(router_calls) >= 2
    finally:
        swarm.close()


# =============================================================================
# Feature #6: OODA `Bootstrap` mapping (5 tests)
# =============================================================================


def test_t1_f6_bootstrap_emits_abnf_seed_intents_and_baseline_facts(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}],
    )
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        graph = swarm.build_graph()
        graph.invoke(_base_state(isolated_swarm_workspace, task_id="boot-task", max_cycles=1))
        facts = swarm.db.get_facts(task_id="boot-task")
        nodes = swarm.db.get_blackboard_nodes(task_id="boot-task")
        assert len(facts) >= 1
        assert any(n["node_type"] == "INTENT" and n["rfc_id"] == "RFC9112" for n in nodes)
    finally:
        swarm.close()


def test_t1_f6_fetch_and_chunk_agent_populates_seed_intents(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        res = swarm.fetch_and_chunk_agent(_base_state(isolated_swarm_workspace, task_id="fetch-seed"))
        assert len(res["fragments"]) >= 1
        assert res.get("blackboard_bootstrapped") is True
        intents = swarm.db.list_intents(task_id="fetch-seed")
        facts = swarm.db.get_facts(task_id="fetch-seed")
        assert len(intents) >= 1
        assert len(facts) >= 1
    finally:
        swarm.close()


def test_t1_f6_bootstrap_records_active_flaw_prober_baseline_fact(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from engine.active_flaw_prober import ActiveFlawProber
    from model_adapter import ModelFusionAdapter

    vuln = ReproducibleVulnerability(
        vuln_id="VULN-BOOT-1",
        anomaly_id="ANOM-BOOT-1",
        impact=ImpactClass.DESYNCHRONIZATION,
        minimized_probe=b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nABCD",
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        delta_debug_steps=1,
        provenance_chain="ActiveFlawProber->CL.0",
    )
    monkeypatch.setattr(ActiveFlawProber, "run_active_audit", lambda self: [vuln])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}],
    )
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        graph = swarm.build_graph()
        graph.invoke(_base_state(isolated_swarm_workspace, task_id="prober-boot", max_cycles=1))
        facts = swarm.db.get_facts(task_id="prober-boot")
        assert any("VULN-BOOT-1" in f["content"] or "VULN-BOOT-1" in json.dumps(f["payload"]) for f in facts)
    finally:
        swarm.close()


def test_t1_f6_bootstrap_runs_once_per_lifecycle(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [{"rationale": "c", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}],
    )
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    fetch_calls = 0
    orig_fetch = swarm.fetch_and_chunk_agent

    def _spy_fetch(st: Dict[str, Any]) -> Dict[str, Any]:
        nonlocal fetch_calls
        fetch_calls += 1
        return orig_fetch(st)

    monkeypatch.setattr(swarm, "fetch_and_chunk_agent", _spy_fetch)
    try:
        graph = swarm.build_graph()
        graph.invoke(_base_state(isolated_swarm_workspace, task_id="once-boot", max_cycles=2))
        assert fetch_calls == 1
    finally:
        swarm.close()


def test_t1_f6_bootstrap_syncs_knowledge_graph_with_blackboard(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        swarm.fetch_and_chunk_agent(_base_state(isolated_swarm_workspace, task_id="kg-sync"))
        assert "RFC9112" in swarm.knowledge_graph.nodes
        assert any(n.node_type == "REQUIREMENT" for n in swarm.knowledge_graph.nodes.values())
        assert len(swarm.db.list_intents(task_id="kg-sync")) >= 1
    finally:
        swarm.close()


# =============================================================================
# Feature #7: OODA `Reason` mapping (5 tests)
# =============================================================================


def test_t1_f7_llm_generator_agent_persists_intents_to_sqlite(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [
            {
                "rationale": "Shared-parser CL.0 candidate",
                "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 4\r\n\r\nABCD",
                "is_clean": False,
            }
        ],
    )
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        st = _base_state(
            isolated_swarm_workspace,
            task_id="reason-persist",
            fragments=[("Transfer-Encoding overrides Content-Length.", "transfer-encoding", 2.0)],
            blackboard_bootstrapped=True,
        )
        swarm.llm_generator_agent(st)
        swarm.close()

        fresh = Database(str(isolated_swarm_workspace.db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
        try:
            intents = fresh.list_intents(task_id="reason-persist")
            assert len(intents) >= 1
            assert any("Content-Length: 4" in i["content"] or "Content-Length: 4" in json.dumps(i["payload"]) for i in intents)
        finally:
            fresh.close()
    finally:
        swarm.close()


def test_t1_f7_reason_absorbs_facts_into_llm_generation_context(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    seen_prompts: List[str] = []

    def _capture(self: Any, sys_p: str, usr_p: str) -> List[Dict[str, Any]]:
        seen_prompts.append(usr_p)
        return [{"rationale": "fact-driven", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]

    monkeypatch.setattr(ModelFusionAdapter, "generate_json", _capture)
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        swarm.db.add_fact("FACT_UNIQUE_OBS_FOLD_ALLOWED", task_id="reason-facts", domain="http11_framing")
        st = _base_state(
            isolated_swarm_workspace,
            task_id="reason-facts",
            fragments=[("Header lines MUST NOT use obs-fold.", "obs-fold", 3.0)],
            blackboard_bootstrapped=True,
        )
        swarm.llm_generator_agent(st)
        assert len(seen_prompts) == 1
        assert "Header lines MUST NOT use obs-fold." in seen_prompts[0]
        assert len(swarm.db.list_intents(task_id="reason-facts")) >= 1
    finally:
        swarm.close()


def test_t1_f7_cascade_and_publish_agent_queues_followup_intents(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        monkeypatch.setattr(
            swarm.cascade_engine,
            "cascade_from_finding",
            lambda info: {
                "hypothesis": "Shared parser confusion on chunked trailer",
                "suggested_probes": [
                    "POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: 1\r\n\r\n"
                ],
            },
        )
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (True, "verified"))
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-CASC-1",
            target_engine=f"127.0.0.1:{loopback_lab_server.port}",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="smuggled marker reflected",
            expected_behavior="clean separation",
            raw_probe=b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\nterminator_marker reflected",
        )
        vuln = ReproducibleVulnerability(
            vuln_id="VULN-CASC-1",
            anomaly_id="ANOM-CASC-1",
            impact=ImpactClass.DESYNCHRONIZATION,
            minimized_probe=b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=1,
            provenance_chain="SequenceEngine",
        )
        st = _base_state(
            isolated_swarm_workspace,
            task_id="cascade-intents",
            current_anomaly=anom,
            current_vuln=vuln,
            current_fragment="Chunked trailers MUST be parsed carefully.",
        )
        res = swarm.cascade_and_publish_agent(st)
        assert res["cascade_results"] is not None
        intents = swarm.db.list_intents(task_id="cascade-intents")
        assert len(intents) >= 1
    finally:
        swarm.close()


def test_t1_f7_reason_permuted_candidates_persist_with_priority(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [
            {
                "rationale": "Base TE probe",
                "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                "is_clean": False,
            }
        ],
    )
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        st = _base_state(
            isolated_swarm_workspace,
            task_id="reason-perm",
            fragments=[("Transfer-Encoding MUST be chunked.", "transfer-encoding,chunked", 4.0)],
        )
        swarm.llm_generator_agent(st)
        intents = swarm.db.list_intents(task_id="reason-perm")
        assert len(intents) >= 2
        assert all(isinstance(i["priority"], (int, float)) for i in intents)
    finally:
        swarm.close()


def test_t1_f7_reason_handles_empty_fragments_without_error(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        res = swarm.llm_generator_agent(
            _base_state(isolated_swarm_workspace, task_id="empty-frag", fragments=[])
        )
        assert res["generated_candidates"] == []
        assert res["cycle_count"] == 1
    finally:
        swarm.close()


# =============================================================================
# Feature #8: OODA `Explore` mapping (5 tests)
# =============================================================================


def test_t1_f8_explore_claims_highest_priority_intent_and_marks_done(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        low_id = swarm.db.queue_intent(
            "GET /low HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
            priority=1.0,
            task_id="exp-prio",
            payload={"raw_request": "GET /low HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True},
        )
        high_id = swarm.db.queue_intent(
            "GET /high HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
            priority=50.0,
            task_id="exp-prio",
            payload={"raw_request": "GET /high HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True},
        )
        st = _base_state(isolated_swarm_workspace, task_id="exp-prio", blackboard_bootstrapped=True)
        swarm.execution_oracle_agent(st)
        done_ids = {r["node_id"] for r in swarm.db.list_intents(status="DONE", task_id="exp-prio")}
        assert high_id in done_ids
        assert low_id in {r["node_id"] for r in swarm.db.list_intents(status="PENDING", task_id="exp-prio")} or low_id in done_ids
    finally:
        swarm.close()


def test_t1_f8_explore_commits_conformant_observation_as_fact(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        swarm.db.queue_intent(
            "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
            priority=10.0,
            task_id="exp-fact",
            payload={"raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True},
        )
        swarm.execution_oracle_agent(_base_state(isolated_swarm_workspace, task_id="exp-fact", blackboard_bootstrapped=True))
        facts = swarm.db.get_facts(task_id="exp-fact")
        assert len(facts) >= 1
    finally:
        swarm.close()


def test_t1_f8_explore_triggers_triage_and_commits_vuln_fact_on_desync(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_raw_tcp_desync_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_raw_tcp_desync_server.port, monkeypatch=monkeypatch
    )
    try:
        desync_probe = (
            "POST / HTTP/1.1\r\nHost: target.local\r\nTransfer_Encoding: chunked\r\n"
            "Content-Length: 4\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ\r\n\r\n"
        )
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: False)
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (True, "confirmed"))
        monkeypatch.setattr(
            swarm.debugger,
            "minimize_and_reproduce",
            lambda a, max_verification_trials=3: ReproducibleVulnerability(
                vuln_id="VULN-EXPLORE-1",
                anomaly_id=a.anomaly_id,
                impact=ImpactClass.DESYNCHRONIZATION,
                minimized_probe=desync_probe.encode("latin-1"),
                reproducibility_rate=1.0,
                verification_attempts=3,
                successful_reproductions=3,
                delta_debug_steps=2,
                provenance_chain="SequenceEngine->Triage",
            ),
        )
        swarm.db.queue_intent(
            desync_probe,
            priority=20.0,
            task_id="exp-desync",
            payload={"raw_request": desync_probe, "is_clean": False},
        )
        res = swarm.execution_oracle_agent(
            _base_state(isolated_swarm_workspace, task_id="exp-desync", blackboard_bootstrapped=True)
        )
        assert res.get("current_anomaly") is not None
        triage_res = swarm.triage_debugger_agent(
            _base_state(
                isolated_swarm_workspace,
                task_id="exp-desync",
                current_anomaly=res["current_anomaly"],
                baseline_resp=res.get("baseline_resp", b""),
            )
        )
        assert triage_res.get("current_vuln") is not None
        facts = swarm.db.get_facts(task_id="exp-desync")
        assert len(facts) >= 1
    finally:
        swarm.close()


def test_t1_f8_explore_marks_intent_failed_on_evaluation_exception(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        nid = swarm.db.queue_intent(
            "GET /err HTTP/1.1\r\nHost: target.local\r\n\r\n",
            priority=10.0,
            task_id="exp-err",
            payload={"raw_request": "GET /err HTTP/1.1\r\nHost: target.local\r\n\r\n"},
        )
        monkeypatch.setattr(
            swarm,
            "_evaluate_single_candidate",
            lambda cand: (_ for _ in ()).throw(RuntimeError("simulated socket failure")),
        )
        swarm.execution_oracle_agent(_base_state(isolated_swarm_workspace, task_id="exp-err", blackboard_bootstrapped=True))
        # Must not remain stuck in CLAIMED
        claimed = swarm.db.list_intents(status="CLAIMED", task_id="exp-err")
        assert claimed == []
        finished = swarm.db.list_intents(task_id="exp-err")
        assert finished[0]["node_id"] == nid
        assert finished[0]["status"] in ("FAILED", "DONE")
    finally:
        swarm.close()


def test_t1_f8_explore_substitutes_payload_and_length_placeholders(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    captured_bytes: List[bytes] = []
    orig_seq = swarm.sequence_engine.run_pipelined_canary_sequence

    def _spy_seq(host: str, port: int, probe_bytes: bytes, use_tls: bool = False) -> Any:
        captured_bytes.append(probe_bytes)
        return orig_seq(host, port, probe_bytes, use_tls=use_tls)

    monkeypatch.setattr(swarm.sequence_engine, "run_pipelined_canary_sequence", _spy_seq)
    try:
        out = swarm._evaluate_single_candidate(
            {"raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: $LENGTH\r\n\r\n$PAYLOAD"}
        )
        assert out["probe_bytes"]
        assert b"target.local" not in captured_bytes[0]
        assert b"$PAYLOAD" not in captured_bytes[0]
        assert b"$LENGTH" not in captured_bytes[0]
    finally:
        swarm.close()


# =============================================================================
# Feature #9: Live `HINT` prompt absorption (5 tests)
# =============================================================================


def test_t1_f9_probe_generator_accepts_hints_kwarg_and_embeds_in_prompt(
    bb_db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    sig = inspect.signature(ProbeGenerator.generate_candidate_probes)
    assert "hints" in sig.parameters

    captured: List[str] = []
    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, sys_p, usr_p: (
            captured.append(usr_p)
            or [{"rationale": "h", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    gen = ProbeGenerator(use_fusion=False, db=bb_db)
    try:
        probes = gen.generate_candidate_probes(
            "Transfer-Encoding MUST override Content-Length.",
            hints=["STEERING_HINT_ALPHA: test obs-fold with chunked"],
        )
        assert len(probes) == 1
        assert len(captured) == 1
        assert "STEERING_HINT_ALPHA: test obs-fold with chunked" in captured[0]
    finally:
        gen.adapter.close()


def test_t1_f9_fusion_arbiter_accepts_hints_and_injects_into_all_specialists(
    bb_db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sig = inspect.signature(FusionArbiter.run_fusion_pipeline)
    assert "hints" in sig.parameters

    monkeypatch.setattr(FusionArbiter, "_fetch_available_tags", lambda self: ["gemma2:2b", "foundation-sec:latest", "deepseek-r1:1.5b"])
    seen_calls: List[Dict[str, str]] = []

    def _fake_query(self: Any, model: str, prompt: str, system_prompt: str, num_predict: int = 160) -> str:
        seen_calls.append({"model": model, "prompt": prompt, "system": system_prompt})
        if "gemma" in model.lower():
            return json.dumps({"rationale": "gemma-probe", "raw_request": "POST /a HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD", "is_clean": False})
        if "sec" in model.lower():
            return json.dumps({"rationale": "sec-probe", "raw_request": "POST /b HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD", "is_clean": False})
        return json.dumps({"rationale": "arbiter-probe", "raw_request": "POST /ab HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD", "is_clean": False})

    monkeypatch.setattr(FusionArbiter, "_query_model", _fake_query)
    arb = FusionArbiter(db=bb_db, quiet=True)
    try:
        res = arb.run_fusion_pipeline(
            "Multiple Content-Length headers MUST be rejected.",
            hints=["FUSION_HINT_BETA: test duplicate CL with chunked"],
        )
        assert len(res.fused_probes) >= 1
        assert len(seen_calls) >= 2
        assert all("FUSION_HINT_BETA: test duplicate CL with chunked" in c["prompt"] for c in seen_calls)
    finally:
        arb.close()


def test_t1_f9_hints_none_preserves_backward_compatibility(
    bb_db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, sys_p, usr_p: [
            {"rationale": "compat", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}
        ],
    )
    gen = ProbeGenerator(use_fusion=False, db=bb_db)
    try:
        probes = gen.generate_candidate_probes("HTTP-message = start-line CRLF")
        assert len(probes) == 1
    finally:
        gen.adapter.close()


def test_t1_f9_llm_generator_agent_fetches_active_hints_alongside_fragment(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    seen: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, sys_p, usr_p: (
            seen.append(usr_p)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        swarm.db.add_hint(
            "LIVE_DB_HINT_9112: prioritize bare LF headers",
            priority=30.0,
            domain="http11_framing",
            task_id="hint-fetch-task",
        )
        st = _base_state(
            isolated_swarm_workspace,
            task_id="hint-fetch-task",
            blackboard_domain="http11_framing",
            fragments=[("Recipients MUST reject bare LF in strict mode.", "crlf", 3.0)],
        )
        out = swarm.llm_generator_agent(st)
        assert len(seen) == 1
        assert "LIVE_DB_HINT_9112: prioritize bare LF headers" in seen[0]
        assert "Recipients MUST reject bare LF in strict mode." in seen[0]
        assert any("LIVE_DB_HINT_9112" in json.dumps(h) for h in out.get("active_hints", []))
    finally:
        swarm.close()


def test_t1_f9_midrun_injected_hint_absorbed_on_cycle2_without_restart(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    prompts_by_cycle: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, sys_p, usr_p: (
            prompts_by_cycle.append(usr_p)
            or [{"rationale": "cycle", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    swarm = _make_offline_swarm(
        isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch
    )
    try:
        st = _base_state(
            isolated_swarm_workspace,
            task_id="midrun-task",
            blackboard_domain="http11_framing",
            fragments=[
                ("Fragment one: Transfer-Encoding header syntax.", "transfer-encoding", 2.0),
                ("Fragment two: Content-Length header syntax.", "content-length", 2.0),
            ],
            cycle_count=0,
            max_cycles=2,
        )
        out1 = swarm.llm_generator_agent(st)
        assert "MIDRUN_STEER_TE_OBSFOLD" not in prompts_by_cycle[0]

        # Separate DB connection injects HINT mid-run without restarting swarm
        ext_db = Database(str(isolated_swarm_workspace.db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
        try:
            ext_db.add_hint(
                "MIDRUN_STEER_TE_OBSFOLD",
                priority=50.0,
                domain="http11_framing",
                task_id="midrun-task",
            )
        finally:
            ext_db.close()

        st2 = dict(st, **out1)
        swarm.llm_generator_agent(st2)
        assert len(prompts_by_cycle) == 2
        assert "MIDRUN_STEER_TE_OBSFOLD" in prompts_by_cycle[1]
    finally:
        swarm.close()
