"""
Hermetic Unit & Integration Tests for Milestone M2:
- OODA Blackboard Router (`blackboard_router`) & `ResearchState` fields
- Cairn Bootstrap / Reason / Explore / Triage / Publish lifecycle on SQLite `blackboard_nodes`
- Live mid-run HINT absorption in `llm_generator_agent`, `ProbeGenerator`, and `FusionArbiter`
- `_FallbackStateGraph` vs `langgraph` parity & `ResearchKnowledgeGraph(db=...)` thread safety
"""

from __future__ import annotations

import concurrent.futures
import inspect
import json
from pathlib import Path
import socket
import sys
import threading
from typing import Any, Dict, List, get_type_hints

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from database import Database
from engine.active_flaw_prober import ActiveFlawProber
from engine.execution_policy import ExecutionPolicy
from engine.knowledge_graph import ResearchKnowledgeGraph
from engine.sequence_engine import SequenceExecutionReport, SequenceStepResult
from engine.taxonomy import (
    AnomalyCategory,
    ImpactClass,
    ImplementationAnomaly,
    ReproducibleVulnerability,
)
from fusion_engine import FusionArbiter
from mcp_server import TargetAuthorizationGate
from model_adapter import ModelFusionAdapter
from probe_generator import ProbeGenerator
from rfc_hunt_swarm import ProtocolResearchSwarm, ResearchState


SAMPLE_RFC_9112 = (
    "RFC 9112 HTTP/1.1 Message Syntax and Framing\n\n"
    "1. Transfer-Encoding and Content-Length\n"
    "A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding header field.\n"
    "If both are received, Transfer-Encoding overrides Content-Length.\n\n"
    "ABNF:\n"
    "obs-fold = OWS CRLF RWS\n"
    "chunk-ext = *( \";\" chunk-ext-name )\n"
)


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolates CWD, DB, encryption, offline flags, and security singletons inside tmp_path."""
    ws = tmp_path / "m2_ws"
    ws.mkdir(parents=True, exist_ok=True)
    rfcs_dir = ws / "rfcs"
    rfcs_dir.mkdir(parents=True, exist_ok=True)
    (rfcs_dir / "rfc9112.txt").write_text(SAMPLE_RFC_9112, encoding="utf-8")
    (ws / "data").mkdir(parents=True, exist_ok=True)

    orig_targets = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    orig_hist = {k: list(v) for k, v in TargetAuthorizationGate._request_history.items()}
    ExecutionPolicy.reset_instance()
    TargetAuthorizationGate.ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}
    TargetAuthorizationGate._request_history.clear()

    monkeypatch.chdir(ws)
    monkeypatch.setenv("RFCHUNT_DISABLE_AT_REST_ENCRYPTION", "1")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(FusionArbiter, "_fetch_available_tags", lambda self: ["gemma2:2b", "foundation-sec:latest"])

    try:
        yield ws
    finally:
        ExecutionPolicy.reset_instance()
        TargetAuthorizationGate.ALLOWED_TARGETS = orig_targets
        TargetAuthorizationGate._request_history.clear()
        for k, v in orig_hist.items():
            TargetAuthorizationGate._request_history[k] = v


def _make_swarm(ws: Path, port: int = 18080, use_fusion: bool = False) -> ProtocolResearchSwarm:
    swarm = ProtocolResearchSwarm(
        host="127.0.0.1",
        port=port,
        db_path=str(ws / "ooda.db"),
        use_fusion=use_fusion,
        concurrency=1,
    )
    swarm.fetcher.cache_dir = ws / "rfcs"
    swarm.dream_store.storage_path = str(ws / "data" / "dream_policies.json")
    swarm.harness2_engine.runs_root = ws / "runs" / "harness2"
    return swarm


def _base_state(ws: Path, **overrides: Any) -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "rfc_num": "9112",
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
        "max_cycles": 1,
        "baseline_resp": b"",
        "enable_dream_rsi": False,
        "dream_rollouts": 5,
        "current_dream_policy": None,
        "enable_harness2": False,
        "harness2_k": 1,
        "harness2_mode": "parallel",
        "harness2_runs_dir": str(ws / "runs" / "harness2"),
        "harness2_domain": "auto",
        "current_harness2_result": None,
        "ooda_phase": "Bootstrap",
        "blackboard_bootstrapped": False,
        "active_intent_id": None,
        "active_intent": None,
        "active_hints": [],
        "task_id": "m2-task",
        "workspace_dir": str(ws),
        "blackboard_domain": "http11_framing",
        "history": [],
    }
    state.update(overrides)
    return state


def _stub_clean_sequence(probe_bytes: bytes) -> SequenceExecutionReport:
    return SequenceExecutionReport(
        sequence_type="PIPELINED_CANARY",
        target="127.0.0.1:18080",
        steps=[
            SequenceStepResult(
                step_name="Step 1: Baseline",
                sent_bytes=b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                received_bytes=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
                status_code=200,
                latency=0.002,
            ),
            SequenceStepResult(
                step_name="Step 2: Candidate Probe",
                sent_bytes=probe_bytes,
                received_bytes=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
                status_code=200,
                latency=0.002,
            ),
        ],
        has_desynchronization=False,
        has_pipeline_leak=False,
        details="Clean separation",
    )


def test_research_state_and_build_graph_uses_blackboard_router_not_legacy(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hints = get_type_hints(ResearchState)
    for key in (
        "ooda_phase",
        "blackboard_bootstrapped",
        "active_intent_id",
        "active_intent",
        "active_hints",
        "task_id",
        "workspace_dir",
        "blackboard_domain",
    ):
        assert key in hints

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [
            {
                "rationale": "Router verification probe",
                "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
                "is_clean": True,
            }
        ],
    )
    monkeypatch.setattr(ActiveFlawProber, "run_active_audit", lambda self: [])

    swarm = _make_swarm(isolated_env)
    monkeypatch.setattr(
        swarm.sequence_engine,
        "run_pipelined_canary_sequence",
        lambda host, port, probe_bytes, use_tls=False: _stub_clean_sequence(probe_bytes),
    )
    monkeypatch.setattr(
        swarm.metamorphic,
        "test_metamorphic_invariance",
        lambda host, port, probe_bytes, use_tls=False: [],
    )

    legacy_invocations: List[str] = []
    for legacy_name in (
        "route_after_generation",
        "route_after_execution",
        "route_after_triage",
        "route_after_publish",
    ):
        assert hasattr(swarm, legacy_name)
        monkeypatch.setattr(
            swarm,
            legacy_name,
            lambda st, _name=legacy_name: legacy_invocations.append(_name) or "__end__",
        )

    router_phases: List[str] = []
    orig_router = swarm.blackboard_router

    def _spy_router(st: Dict[str, Any]) -> Dict[str, Any]:
        out = orig_router(st)
        router_phases.append(str(out.get("ooda_phase")))
        return out

    monkeypatch.setattr(swarm, "blackboard_router", _spy_router)

    try:
        graph = swarm.build_graph()
        expected_nodes = {
            "blackboard_router",
            "fetch_and_chunk_agent",
            "llm_generator_agent",
            "execution_oracle_agent",
            "triage_debugger_agent",
            "cascade_and_publish_agent",
            "dream_rsi_agent",
        }
        assert expected_nodes.issubset(set(graph.nodes.keys()))

        if hasattr(graph, "get_graph"):
            edges = [(e.source, e.target, e.conditional) for e in graph.get_graph().edges]
            assert ("__start__", "blackboard_router", False) in edges
            for worker in (
                "fetch_and_chunk_agent",
                "llm_generator_agent",
                "execution_oracle_agent",
                "triage_debugger_agent",
                "cascade_and_publish_agent",
            ):
                assert (worker, "blackboard_router", False) in edges
                assert ("blackboard_router", worker, True) in edges
                assert not any(src == worker and cond for (src, _, cond) in edges)

        final_state = graph.invoke(_base_state(isolated_env, max_cycles=1), {"recursion_limit": 200})
        assert final_state.get("blackboard_bootstrapped") is True
        assert "Bootstrap" in router_phases
        assert "Reason" in router_phases
        assert "Explore" in router_phases
        assert router_phases[-1] == "Done"
        assert legacy_invocations == []
    finally:
        swarm.close()


def test_full_ooda_bootstrap_reason_explore_triage_publish_and_no_requeue(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boot_vuln = ReproducibleVulnerability(
        vuln_id="VULN-ACT-1",
        anomaly_id="ANOM-ACT-1",
        impact=ImpactClass.DESYNCHRONIZATION,
        minimized_probe=b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nABCD",
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        delta_debug_steps=1,
        provenance_chain="ActiveFlawProber->CL.0",
    )
    monkeypatch.setattr(ActiveFlawProber, "run_active_audit", lambda self: [boot_vuln])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [
            {
                "rationale": "Trigger CL.TE desync probe",
                "raw_request": "POST /desync HTTP/1.1\r\nHost: target.local\r\nTransfer_Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n",
                "is_clean": False,
            }
        ],
    )

    swarm = _make_swarm(isolated_env)
    # Keep permutations compact (1 variant) so graph finishes quickly and deterministically
    monkeypatch.setattr(
        swarm.permutator,
        "permute_probe",
        lambda base, max_variants=5, categories=None: [],
    )

    def _seq_side_effect(host: str, port: int, probe_bytes: bytes, use_tls: bool = False) -> SequenceExecutionReport:
        if b"/desync" in probe_bytes:
            return SequenceExecutionReport(
                sequence_type="PIPELINED_CANARY",
                target=f"{host}:{port}",
                steps=[
                    SequenceStepResult("Step 1: Baseline", b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\nOK", 200, 0.002),
                    SequenceStepResult("Step 2: Candidate Probe", probe_bytes, b"HTTP/1.1 404 Not Found\r\n\r\nterminator_marker", 404, 0.002),
                ],
                has_desynchronization=True,
                has_pipeline_leak=True,
                details="Simulated pipeline leak on /desync",
            )
        return _stub_clean_sequence(probe_bytes)

    monkeypatch.setattr(swarm.sequence_engine, "run_pipelined_canary_sequence", _seq_side_effect)
    monkeypatch.setattr(swarm.metamorphic, "test_metamorphic_invariance", lambda *a, **kw: [])
    monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
    monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: False)
    monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (True, "verified"))
    monkeypatch.setattr(
        swarm.debugger,
        "minimize_and_reproduce",
        lambda a, max_verification_trials=3: ReproducibleVulnerability(
            vuln_id="VULN-OODA-99",
            anomaly_id=a.anomaly_id,
            impact=ImpactClass.DESYNCHRONIZATION,
            minimized_probe=a.raw_probe,
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=1,
            provenance_chain="SequenceEngine->Triage",
        ),
    )
    monkeypatch.setattr(
        swarm.cascade_engine,
        "cascade_from_finding",
        lambda info: {
            "category": "shared_parser_confusion",
            "hypothesis": "Follow-up cascade probe",
            "suggested_probes": [
                {
                    "rationale": "Cascade follow-up GET",
                    "raw_request": "GET /cascade-followup HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
                    "is_clean": True,
                }
            ],
        },
    )

    try:
        graph = swarm.build_graph()
        events = list(graph.stream(_base_state(isolated_env, task_id="full-ooda", max_cycles=1), {"recursion_limit": 200}))
        visited_nodes = [next(iter(ev.keys())) for ev in events]
        assert "fetch_and_chunk_agent" in visited_nodes
        assert "llm_generator_agent" in visited_nodes
        assert "execution_oracle_agent" in visited_nodes
        assert "triage_debugger_agent" in visited_nodes
        assert "cascade_and_publish_agent" in visited_nodes

        # Verify SQLite persistence: no PENDING or orphaned CLAIMED intents remain
        assert swarm.db.list_intents(status="PENDING", task_id="full-ooda") == []
        assert swarm.db.list_intents(status="CLAIMED", task_id="full-ooda") == []
        done_intents = swarm.db.list_intents(status="DONE", task_id="full-ooda")
        assert len(done_intents) >= 4  # 2 ABNF + 1 LLM + 1 cascade follow-up
        assert all(str(r["claimed_by"]).startswith("oracle:") for r in done_intents)

        # Verify FACTs committed by Bootstrap, Explore, Triage, and Publish
        facts = swarm.db.get_facts(task_id="full-ooda", limit=0)
        fact_ids = {f["node_id"] for f in facts}
        assert "fact:active_flaw:full-ooda:VULN-ACT-1" in fact_ids
        assert "fact:bootstrap:active_audit:full-ooda" in fact_ids
        assert "fact:bootstrap:rfc:full-ooda:RFC9112" in fact_ids
        assert "fact:vuln:VULN-OODA-99:full-ooda" in fact_ids

        # Verify KnowledgeGraph nodes carry rfc_id
        req_nodes = [n for n in swarm.knowledge_graph.nodes.values() if n.node_type == "REQUIREMENT"]
        assert len(req_nodes) >= 2
        assert all(n.attributes.get("rfc_id") == "RFC9112" for n in req_nodes)

        # Re-running Bootstrap against same DB/task_id must NOT reset DONE deterministic node_ids to PENDING
        swarm.fetch_and_chunk_agent(_base_state(isolated_env, task_id="full-ooda"))
        assert swarm.db.list_intents(status="PENDING", task_id="full-ooda") == []
        assert len(swarm.db.list_intents(status="DONE", task_id="full-ooda")) == len(done_intents)
    finally:
        swarm.close()


def test_explore_marks_intent_failed_on_exception_and_triage_discard_no_loop(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_env)
    try:
        nid = swarm.db.queue_intent(
            "GET /err HTTP/1.1\r\nHost: target.local\r\n\r\n",
            priority=10.0,
            task_id="err-task",
            domain="",
            payload={"raw_request": "GET /err HTTP/1.1\r\nHost: target.local\r\n\r\n"},
        )
        route_check = swarm.blackboard_router(
            _base_state(isolated_env, task_id="err-task", blackboard_bootstrapped=True, blackboard_domain="http11_framing")
        )
        assert route_check["ooda_phase"] == "Explore"
        monkeypatch.setattr(
            swarm,
            "_evaluate_single_candidate",
            lambda cand: (_ for _ in ()).throw(RuntimeError("simulated socket crash")),
        )
        res = swarm.execution_oracle_agent(
            _base_state(isolated_env, task_id="err-task", blackboard_bootstrapped=True)
        )
        assert res["current_anomaly"] is None
        assert swarm.db.list_intents(status="CLAIMED", task_id="err-task") == []
        failed = swarm.db.list_intents(status="FAILED", task_id="err-task")
        assert [r["node_id"] for r in failed] == [nid]

        # Triage discard (low reproducibility) must clear current_anomaly + active_intent_id so router does not loop
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-FLAKY-1",
            target_engine="127.0.0.1:18080",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="flaky",
            expected_behavior="clean",
            raw_probe=b"GET / HTTP/1.1\r\n\r\n",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
        )
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: False)
        monkeypatch.setattr(
            swarm.debugger,
            "minimize_and_reproduce",
            lambda a, max_verification_trials=3: ReproducibleVulnerability(
                vuln_id="VULN-FLAKY",
                anomaly_id=a.anomaly_id,
                impact=ImpactClass.DESYNCHRONIZATION,
                minimized_probe=b"GET / HTTP/1.1\r\n\r\n",
                reproducibility_rate=0.33,
                verification_attempts=3,
                successful_reproductions=1,
                delta_debug_steps=1,
                provenance_chain="flaky",
            ),
        )
        triage_out = swarm.triage_debugger_agent(
            _base_state(
                isolated_env,
                task_id="flaky-triage",
                current_anomaly=anom,
                active_intent_id="intent-x",
                active_intent={"node_id": "intent-x"},
            )
        )
        assert triage_out["current_anomaly"] is None
        assert triage_out["current_vuln"] is None
        assert triage_out["active_intent_id"] is None
        assert triage_out["active_intent"] is None
        assert swarm.db.get_facts(task_id="flaky-triage") == []
    finally:
        swarm.close()


def test_live_midrun_hint_absorption_and_fusion_and_braces_safety(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    single_prompts: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            single_prompts.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )

    swarm = _make_swarm(isolated_env, use_fusion=False)
    try:
        raw_frag_1 = "Fragment 1: Transfer-Encoding MUST override Content-Length."
        raw_frag_2 = "Fragment 2: Header fields MUST NOT use obs-fold."
        st = _base_state(
            isolated_env,
            task_id="live-hint-task",
            blackboard_domain="http11_framing",
            blackboard_bootstrapped=True,
            fragments=[(raw_frag_1, "te", 2.0), (raw_frag_2, "obs-fold", 2.0)],
            max_cycles=2,
        )

        # Cycle 1: no hints yet
        out1 = swarm.llm_generator_agent(st)
        assert out1["current_fragment"] == raw_frag_1
        assert "MIDRUN_HINT_WITH_{BRACES}" not in single_prompts[0]

        # Inject HINT mid-run via a separate Database connection (simulating CLI/MCP injection)
        ext_db = Database(str(isolated_env / "ooda.db"))
        try:
            ext_db.add_hint(
                "MIDRUN_HINT_WITH_{BRACES}_AND_UNICODE_\u2603",
                priority=40.0,
                task_id="live-hint-task",
                domain="http11_framing",
            )
            ext_db.add_hint(
                "DEFAULT_GLOBAL_HINT",
                priority=15.0,
                task_id="default",
                domain="global",
            )
            ext_db.add_hint(
                "UNRELATED_DOMAIN_DNS_HINT",
                priority=99.0,
                task_id="live-hint-task",
                domain="dns_framing",
            )
            ext_db.add_hint(
                "OTHER_TASK_SECRET_HINT",
                priority=99.0,
                task_id="completely-different-task",
                domain="http11_framing",
            )
        finally:
            ext_db.close()

        # Cycle 2: absorbs active matching hints without restart, leaving current_fragment unpolluted
        st2 = dict(st, **out1)
        out2 = swarm.llm_generator_agent(st2)
        assert out2["current_fragment"] == raw_frag_2
        assert "MIDRUN_HINT_WITH_{BRACES}_AND_UNICODE_\u2603" in single_prompts[1]
        assert "DEFAULT_GLOBAL_HINT" in single_prompts[1]
        assert "UNRELATED_DOMAIN_DNS_HINT" not in single_prompts[1]
        assert "OTHER_TASK_SECRET_HINT" not in single_prompts[1]
        assert any("MIDRUN_HINT_WITH_{BRACES}" in h["content"] for h in out2["active_hints"])
    finally:
        swarm.close()

    # Verify FusionArbiter injects hints into all 4 prompt sites (gemma, sec, abliteration rescue, arbiter)
    fusion_calls: List[Dict[str, str]] = []
    monkeypatch.setattr(
        FusionArbiter,
        "_fetch_available_tags",
        lambda self: ["gemma2:2b", "foundation-sec:latest", "gemma-abliterated:4b", "deepseek-r1:1.5b"],
    )

    def _fake_query(self: Any, model: str, prompt: str, system_prompt: str, num_predict: int = 160) -> str:
        fusion_calls.append({"model": model, "prompt": prompt})
        if "gemma2" in model.lower():
            return "I cannot assist with that request."  # triggers abliteration rescue!
        if "sec" in model.lower():
            return json.dumps({"rationale": "sec-ok", "raw_request": "POST /s HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD", "is_clean": False})
        if "abliterat" in model.lower():
            return json.dumps({"rationale": "abl-ok", "raw_request": "POST /a HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD", "is_clean": False})
        return json.dumps({"rationale": "arb-ok", "raw_request": "POST /arb HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD", "is_clean": False})

    monkeypatch.setattr(FusionArbiter, "_query_model", _fake_query)
    db = Database(str(isolated_env / "fusion.db"))
    try:
        gen = ProbeGenerator(use_fusion=True, db=db)
        assert gen.arbiter is not None
        gen.arbiter.gemma_model = "gemma2:2b"
        gen.arbiter.sec_model = "foundation-sec:latest"
        gen.arbiter.arbiter_model = "deepseek-r1:1.5b"
        try:
            probes = gen.generate_candidate_probes(
                "Chunked trailers MUST be parsed strictly.",
                hints=["FUSION_STEER_{TRAILER}_HINT"],
                facts=["FACT_BACKEND_ACCEPTS_OBS_FOLD"],
            )
            assert len(probes) >= 1
            assert len(fusion_calls) == 4  # gemma, sec, abliterated rescue, arbiter
            assert all("FUSION_STEER_{TRAILER}_HINT" in c["prompt"] for c in fusion_calls)
            assert all("FACT_BACKEND_ACCEPTS_OBS_FOLD" in c["prompt"] for c in fusion_calls)
        finally:
            gen.adapter.close()
            if gen.arbiter:
                gen.arbiter.close()
    finally:
        db.close()


def test_fallback_graph_parity_and_knowledge_graph_thread_safety(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ActiveFlawProber, "run_active_audit", lambda self: [])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [
            {
                "rationale": "Parity probe",
                "raw_request": "GET /parity HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
                "is_clean": True,
            }
        ],
    )

    def _run_with_graph_backend(force_fallback: bool, db_name: str) -> Dict[str, Any]:
        if force_fallback:
            monkeypatch.setitem(sys.modules, "langgraph", None)
            monkeypatch.setitem(sys.modules, "langgraph.graph", None)

        swarm = ProtocolResearchSwarm(
            host="127.0.0.1",
            port=18080,
            db_path=str(isolated_env / db_name),
            use_fusion=False,
            concurrency=1,
        )
        swarm.fetcher.cache_dir = isolated_env / "rfcs"
        swarm.dream_store.storage_path = str(isolated_env / "data" / "dream_policies.json")
        swarm.harness2_engine.runs_root = isolated_env / "runs" / "harness2"
        monkeypatch.setattr(
            swarm.permutator,
            "permute_probe",
            lambda base, max_variants=5, categories=None: [],
        )
        monkeypatch.setattr(
            swarm.sequence_engine,
            "run_pipelined_canary_sequence",
            lambda host, port, probe_bytes, use_tls=False: _stub_clean_sequence(probe_bytes),
        )
        monkeypatch.setattr(swarm.metamorphic, "test_metamorphic_invariance", lambda *a, **kw: [])
        try:
            graph = swarm.build_graph()
            assert "blackboard_router" in graph.nodes
            # Omit history from initial_state to verify _FallbackStateGraph history merge parity
            init = _base_state(isolated_env, task_id="parity-task")
            init.pop("history", None)
            out = graph.invoke(init, {"recursion_limit": 200})
            done_count = len(swarm.db.list_intents(status="DONE", task_id="parity-task"))
            fact_count = len(swarm.db.get_facts(task_id="parity-task"))
            return {
                "bootstrapped": out.get("blackboard_bootstrapped"),
                "history_len": len(out.get("history", [])),
                "done_count": done_count,
                "fact_count": fact_count,
            }
        finally:
            swarm.close()

    lg_summary = _run_with_graph_backend(False, "parity_lg.db")
    fb_summary = _run_with_graph_backend(True, "parity_fb.db")
    assert lg_summary == fb_summary
    assert lg_summary["bootstrapped"] is True
    assert lg_summary["done_count"] >= 3
    assert lg_summary["fact_count"] >= 4

    # Concurrent ResearchKnowledgeGraph(db=...) thread-safety smoke check
    kg_db = Database(str(isolated_env / "kg_threads.db"))
    try:
        kg = ResearchKnowledgeGraph(db=kg_db, task_id="kg-thread-task", domain="http11_framing")
        kg.add_node("RFC9112", "RFC", "HTTP/1.1", attributes={"rfc_id": "RFC9112"})

        def _worker(tid: int) -> None:
            for i in range(15):
                req_id = f"REQ-T{tid}-{i}"
                kg.add_node(
                    req_id,
                    "REQUIREMENT",
                    f"Rule {tid}-{i}",
                    attributes={"rfc_id": "RFC9112", "domain": "http11_framing"},
                )
                kg.add_edge("RFC9112", req_id, "DEFINES")
                if i % 3 == 0:
                    kg.sync_blind_spots_to_intents()
                    cov = kg.calculate_specification_coverage()
                    assert cov["total_requirements"] >= 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futs = [pool.submit(_worker, t) for t in range(4)]
            for fut in futs:
                fut.result()

        cov = kg.calculate_specification_coverage()
        assert cov["total_requirements"] == 60
        assert len(kg_db.list_intents(task_id="kg-thread-task", limit=0)) == 60
    finally:
        kg_db.close()


def test_cross_domain_isolation_and_window_loop_freedom(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_env)
    monkeypatch.setattr(
        swarm.sequence_engine,
        "run_pipelined_canary_sequence",
        lambda host, port, probe_bytes, use_tls=False: _stub_clean_sequence(probe_bytes),
    )
    monkeypatch.setattr(swarm.metamorphic, "test_metamorphic_invariance", lambda *a, **kw: [])
    try:
        # Queue 26 higher-priority intents in an unrelated domain plus 1 global & 1 empty-domain intent
        other_ids = [
            swarm.db.queue_intent(
                f"GET /quic-{i} HTTP/1.1\r\nHost: target.local\r\n\r\n",
                priority=100.0 + i,
                node_id=f"intent:quic:{i}",
                task_id="iso-loop-task",
                domain="quic_transport",
                payload={"raw_request": f"GET /quic-{i} HTTP/1.1\r\nHost: target.local\r\n\r\n"},
            )
            for i in range(26)
        ]
        global_id = swarm.db.queue_intent(
            "GET /global-probe HTTP/1.1\r\nHost: target.local\r\n\r\n",
            priority=2.0,
            node_id="intent:global:1",
            task_id="iso-loop-task",
            domain="global",
            payload={"raw_request": "GET /global-probe HTTP/1.1\r\nHost: target.local\r\n\r\n"},
        )
        empty_id = swarm.db.queue_intent(
            "GET /empty-probe HTTP/1.1\r\nHost: target.local\r\n\r\n",
            priority=1.0,
            node_id="intent:empty:1",
            task_id="iso-loop-task",
            domain="",
            payload={"raw_request": "GET /empty-probe HTTP/1.1\r\nHost: target.local\r\n\r\n"},
        )

        # Backward compatibility: include_global=False does NOT match 'global'/'' when domain is set
        assert (
            swarm.db.claim_next_intent(
                "compat-check",
                task_id="iso-loop-task",
                domain="http11_framing",
                include_global=False,
            )
            is None
        )

        graph = swarm.build_graph()
        out = graph.invoke(
            _base_state(
                isolated_env,
                task_id="iso-loop-task",
                blackboard_domain="http11_framing",
                blackboard_bootstrapped=True,
                fragments=[],
                max_cycles=1,
            ),
            {"recursion_limit": 25},
        )
        assert out.get("ooda_phase") == "Done"
        done_ids = {r["node_id"] for r in swarm.db.list_intents(status="DONE", task_id="iso-loop-task", limit=0)}
        assert done_ids == {global_id, empty_id}
        pending_ids = {r["node_id"] for r in swarm.db.list_intents(status="PENDING", task_id="iso-loop-task", limit=0)}
        assert pending_ids == set(other_ids)
    finally:
        swarm.close()


def test_mixed_case_domain_claiming_no_loop(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_env)
    monkeypatch.setattr(
        swarm.sequence_engine,
        "run_pipelined_canary_sequence",
        lambda host, port, probe_bytes, use_tls=False: _stub_clean_sequence(probe_bytes),
    )
    monkeypatch.setattr(swarm.metamorphic, "test_metamorphic_invariance", lambda *a, **kw: [])
    try:
        other_id = swarm.db.queue_intent(
            "GET /quic HTTP/1.1\r\nHost: target.local\r\n\r\n",
            priority=99.0,
            node_id="intent:quic:case",
            task_id="case-task",
            domain="quic_transport",
            payload={"raw_request": "GET /quic HTTP/1.1\r\nHost: target.local\r\n\r\n"},
        )
        target_id = swarm.db.queue_intent(
            "GET /http-case HTTP/1.1\r\nHost: target.local\r\n\r\n",
            priority=5.0,
            node_id="intent:http:case",
            task_id="case-task",
            domain="http11_framing",
            payload={"raw_request": "GET /http-case HTTP/1.1\r\nHost: target.local\r\n\r\n"},
        )

        graph = swarm.build_graph()
        out = graph.invoke(
            _base_state(
                isolated_env,
                task_id="case-task",
                blackboard_domain="HTTP11_FRAMING",
                blackboard_bootstrapped=True,
                fragments=[],
                max_cycles=1,
            ),
            {"recursion_limit": 20},
        )
        assert out.get("ooda_phase") == "Done"
        done_ids = {r["node_id"] for r in swarm.db.list_intents(status="DONE", task_id="case-task")}
        pending_ids = {r["node_id"] for r in swarm.db.list_intents(status="PENDING", task_id="case-task")}
        assert done_ids == {target_id}
        assert pending_ids == {other_id}
    finally:
        swarm.close()


def test_history_none_parity_between_langgraph_and_fallback(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ActiveFlawProber, "run_active_audit", lambda self: [])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [
            {
                "rationale": "History None parity probe",
                "raw_request": "GET /hist-none HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
                "is_clean": True,
            }
        ],
    )

    def _run_history_none(force_fallback: bool, db_name: str) -> Dict[str, Any]:
        if force_fallback:
            monkeypatch.setitem(sys.modules, "langgraph", None)
            monkeypatch.setitem(sys.modules, "langgraph.graph", None)

        swarm = ProtocolResearchSwarm(
            host="127.0.0.1",
            port=18080,
            db_path=str(isolated_env / db_name),
            use_fusion=False,
            concurrency=1,
        )
        swarm.fetcher.cache_dir = isolated_env / "rfcs"
        swarm.dream_store.storage_path = str(isolated_env / "data" / "dream_policies.json")
        swarm.harness2_engine.runs_root = isolated_env / "runs" / "harness2"
        monkeypatch.setattr(
            swarm.permutator,
            "permute_probe",
            lambda base, max_variants=5, categories=None: [],
        )
        monkeypatch.setattr(
            swarm.sequence_engine,
            "run_pipelined_canary_sequence",
            lambda host, port, probe_bytes, use_tls=False: _stub_clean_sequence(probe_bytes),
        )
        monkeypatch.setattr(swarm.metamorphic, "test_metamorphic_invariance", lambda *a, **kw: [])
        try:
            graph = swarm.build_graph()
            out = graph.invoke({"rfc_num": "9112", "history": None}, {"recursion_limit": 200})
            return {
                "ooda_phase": out.get("ooda_phase"),
                "bootstrapped": out.get("blackboard_bootstrapped"),
                "history_len": len(out.get("history", [])),
                "done_count": len(swarm.db.list_intents(status="DONE", task_id="default", limit=0)),
                "fact_count": len(swarm.db.get_facts(task_id="default", limit=0)),
            }
        finally:
            swarm.close()

    lg_out = _run_history_none(False, "hist_none_lg.db")
    fb_out = _run_history_none(True, "hist_none_fb.db")
    assert lg_out == fb_out
    assert lg_out["ooda_phase"] == "Done"
    assert lg_out["bootstrapped"] is True
    assert lg_out["history_len"] >= 3
    assert lg_out["done_count"] >= 3


def test_hardening_hints_limit_bytes_cascade_and_candidate_exception(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_env)
    try:
        # 1. >50 other-RFC hints must not truncate matching rfc_label hints
        for i in range(55):
            swarm.db.add_hint(
                f"OTHER_RFC9110_HINT_{i}",
                priority=100.0 + i,
                task_id="hardening-task",
                domain="http11_framing",
                rfc_id="RFC9110",
            )
        target_hint_id = swarm.db.add_hint(
            "TARGET_RFC9112_HINT",
            priority=1.0,
            task_id="hardening-task",
            domain="http11_framing",
            rfc_id="RFC9112",
        )
        fetched = swarm._fetch_active_hints(
            task_id="hardening-task",
            domain="http11_framing",
            rfc_label="RFC9112",
            limit=50,
        )
        assert [h["node_id"] for h in fetched] == [target_hint_id]

        # 2. bytes raw_request in cascade_and_publish_agent suggested_probes must decode cleanly
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-BYTES-1",
            target_engine="127.0.0.1:18080",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="bytes probe divergence",
            expected_behavior="clean",
            raw_probe=b"GET / HTTP/1.1\r\n\r\n",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
        )
        vuln = ReproducibleVulnerability(
            vuln_id="VULN-BYTES-1",
            anomaly_id=anom.anomaly_id,
            impact=ImpactClass.DESYNCHRONIZATION,
            minimized_probe=b"GET / HTTP/1.1\r\n\r\n",
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=1,
            provenance_chain="SequenceEngine->Triage",
        )
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (True, "ok"))
        monkeypatch.setattr(
            swarm.cascade_engine,
            "cascade_from_finding",
            lambda info: {
                "hypothesis": "bytes cascade",
                "suggested_probes": [
                    {
                        "raw_request": b"GET /bytes-dict HTTP/1.1\r\nHost: target.local\r\n\r\n",
                        "rationale": "dict bytes",
                        "is_clean": False,
                    },
                    b"GET /bytes-raw HTTP/1.1\r\nHost: target.local\r\n\r\n",
                ],
            },
        )
        swarm.cascade_and_publish_agent(
            _base_state(
                isolated_env,
                task_id="hardening-task",
                current_anomaly=anom,
                current_vuln=vuln,
            )
        )
        queued_contents = {r["content"] for r in swarm.db.list_intents(status="PENDING", task_id="hardening-task", limit=0)}
        assert "GET /bytes-dict HTTP/1.1\r\nHost: target.local" in queued_contents
        assert "GET /bytes-raw HTTP/1.1\r\nHost: target.local" in queued_contents
        assert all(not c.startswith("b'") for c in queued_contents)

        # 3. Exception inside _candidate_from_intent must mark claimed intent FAILED (not leave CLAIMED)
        bad_id = swarm.db.queue_intent(
            "bad-candidate-trigger",
            priority=999.0,
            task_id="cand-err-task",
            domain="http11_framing",
        )
        monkeypatch.setattr(
            swarm,
            "_candidate_from_intent",
            lambda intent: (_ for _ in ()).throw(ValueError("malformed intent payload")),
        )
        out_err = swarm.execution_oracle_agent(
            _base_state(
                isolated_env,
                task_id="cand-err-task",
                blackboard_domain="http11_framing",
            )
        )
        assert out_err["active_intent_id"] is None
        assert swarm.db.list_intents(status="CLAIMED", task_id="cand-err-task") == []
        failed = swarm.db.list_intents(status="FAILED", task_id="cand-err-task")
        assert [r["node_id"] for r in failed] == [bad_id]
        err_facts = swarm.db.get_facts(task_id="cand-err-task")
        assert any(f["node_id"] == f"fact:failed:{bad_id}" for f in err_facts)
    finally:
        swarm.close()
