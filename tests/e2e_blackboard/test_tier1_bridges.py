"""
Tier 1 Feature Contract Tests: Harness² & ARTEX Dual-Graph Bridges (Features #14-#15).
Covers `PROJECT.md § Interface Contracts` #6 (>= 5 tests per feature = 10 tests).

Collection-safe: M4 methods (`DualGraphAttackEngine.reason_from_blackboard_facts`)
and M4 agent behaviors are resolved inside test bodies.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from database import Database
from engine.dual_graph_engine import DualGraphAttackEngine
from engine.taxonomy import AnomalyCategory, ImpactClass, ImplementationAnomaly, ReproducibleVulnerability


def _make_swarm(
    ws: SimpleNamespace,
    *,
    port: int,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import ProtocolResearchSwarm

    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    swarm = ProtocolResearchSwarm(
        host="127.0.0.1",
        port=port,
        db_path=str(ws.db_path),
        use_fusion=False,
        concurrency=1,
    )
    swarm.fetcher.cache_dir = ws.rfcs_dir
    swarm.dream_store.storage_path = str(ws.root / "data" / "dream_policies.json")
    swarm.harness2_engine.runs_root = ws.harness2_runs_dir
    return swarm


# =============================================================================
# Feature #14: Harness² `HINT` promotion bridge (5 tests)
# =============================================================================


def test_t1_f14_dream_rsi_agent_promotes_harness2_lesson_to_hint(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        state = {
            "rfc_num": "9112",
            "dream_rollouts": 10,
            "enable_harness2": True,
            "harness2_k": 1,
            "harness2_mode": "parallel",
            "harness2_runs_dir": str(isolated_swarm_workspace.harness2_runs_dir),
            "harness2_domain": "auto",
            "task_id": "h2-promote-1",
            "history": [],
        }
        out = swarm.dream_rsi_agent(state)
        h2_res = out.get("current_harness2_result")
        assert h2_res is not None
        assert len(swarm.db.get_harness2_runs()) == 1

        hints = swarm.db.get_active_hints(domain=h2_res["domain"])
        promoted = [h for h in hints if h["source_agent"] == "dream_rsi_agent"]
        assert len(promoted) >= 1
        assert promoted[0]["rfc_id"] == "RFC9112"
    finally:
        swarm.close()


def test_t1_f14_promoted_hint_contains_cue_lesson_and_evidence(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        fake_res = SimpleNamespace(
            mode="parallel",
            task_id="RFC9112",
            domain="http11_framing",
            k=1,
            adopted_label="c3",
            rollouts={"c3": SimpleNamespace(behavioral_score=91.5)},
            experience={
                "cue": "obs-fold in Transfer-Encoding header",
                "lesson": "Always pair obs-fold with chunked trailer smuggling",
                "evidence": "3/3 backend parser divergences",
            },
            to_dict=lambda: {
                "mode": "parallel",
                "task_id": "RFC9112",
                "domain": "http11_framing",
                "k": 1,
                "adopted_label": "c3",
                "rollouts": {"c3": {"behavioral_score": 91.5}},
                "experience": {
                    "cue": "obs-fold in Transfer-Encoding header",
                    "lesson": "Always pair obs-fold with chunked trailer smuggling",
                    "evidence": "3/3 backend parser divergences",
                },
            },
        )
        monkeypatch.setattr(swarm.harness2_engine, "run_mode", lambda **kwargs: fake_res)
        swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 10,
                "enable_harness2": True,
                "harness2_k": 1,
                "harness2_mode": "parallel",
                "harness2_runs_dir": str(isolated_swarm_workspace.harness2_runs_dir),
                "task_id": "h2-fields",
                "history": [],
            }
        )
        hints = swarm.db.get_active_hints(domain="http11_framing")
        promoted = [h for h in hints if h["source_agent"] == "dream_rsi_agent"]
        assert len(promoted) == 1
        content = promoted[0]["content"]
        assert "Always pair obs-fold with chunked trailer smuggling" in content
        assert "obs-fold in Transfer-Encoding header" in content
    finally:
        swarm.close()


def test_t1_f14_promoted_rfc9112_hint_steers_subsequent_rfc7230_generation(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    seen_prompts: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            seen_prompts.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 10,
                "enable_harness2": True,
                "harness2_k": 1,
                "harness2_mode": "parallel",
                "harness2_runs_dir": str(isolated_swarm_workspace.harness2_runs_dir),
                "task_id": "campaign-http11",
                "history": [],
            }
        )
        promoted = [
            h
            for h in swarm.db.get_active_hints(task_id="campaign-http11", domain="http11_framing")
            if h["source_agent"] == "dream_rsi_agent"
        ]
        assert len(promoted) >= 1
        assert promoted[0]["rfc_id"] == "RFC9112"
        lesson_snippet = promoted[0]["content"][:40]

        swarm.llm_generator_agent(
            {
                "rfc_num": "7230",
                "fragments": [("RFC7230 chunked transfer coding rule.", "transfer-encoding", 2.0)],
                "blackboard_domain": "http11_framing",
                "task_id": "campaign-http11",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert len(seen_prompts) == 1
        assert lesson_snippet in seen_prompts[0]
    finally:
        swarm.close()


def test_t1_f14_promoted_http11_hint_does_not_leak_to_h2_translation_domain(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    seen_prompts: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            seen_prompts.append(u)
            or [{"rationale": "h2", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        swarm.db.add_hint(
            "HTTP11_ONLY_PROMOTED_LESSON",
            domain="http11_framing",
            rfc_id="RFC9112",
            source_agent="dream_rsi_agent",
            priority=30.0,
        )
        swarm.llm_generator_agent(
            {
                "rfc_num": "9113",
                "fragments": [("HTTP/2 MUST NOT include Transfer-Encoding.", "transfer-encoding", 2.0)],
                "blackboard_domain": "h2_translation",
                "task_id": "h2-isolated",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert len(seen_prompts) == 1
        assert "HTTP11_ONLY_PROMOTED_LESSON" not in seen_prompts[0]
    finally:
        swarm.close()


def test_t1_f14_disable_harness2_skips_run_and_hint_promotion(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        out = swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 10,
                "enable_harness2": False,
                "task_id": "no-h2",
                "history": [],
            }
        )
        assert out["current_harness2_result"] is None
        assert swarm.db.get_harness2_runs() == []
        assert [h for h in swarm.db.get_active_hints() if h["source_agent"] == "dream_rsi_agent"] == []
    finally:
        swarm.close()


# =============================================================================
# Feature #15: ARTEX Dual-Graph `Reason` bridge (5 tests)
# =============================================================================


def test_t1_f15_triage_debugger_agent_commits_confirmed_vuln_fact(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-TRIAGE-1",
            target_engine=f"127.0.0.1:{loopback_lab_server.port}",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="CL.0 smuggled request reached /internal/service",
            expected_behavior="Request isolation",
            raw_probe=b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nABCD",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\nterminator_marker reflected",
        )
        vuln = ReproducibleVulnerability(
            vuln_id="VULN-TRIAGE-1",
            anomaly_id="ANOM-TRIAGE-1",
            impact=ImpactClass.DESYNCHRONIZATION,
            minimized_probe=b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nABCD",
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=1,
            provenance_chain="DeltaDebugger",
        )
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: False)
        monkeypatch.setattr(swarm.debugger, "minimize_and_reproduce", lambda a, max_verification_trials=3: vuln)
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (True, "confirmed"))
        monkeypatch.setattr(swarm.classifier, "classify_novelty", lambda v: (False, None))

        out = swarm.triage_debugger_agent(
            {
                "rfc_num": "9112",
                "current_anomaly": anom,
                "baseline_resp": b"HTTP/1.1 200 OK\r\n\r\nHello",
                "task_id": "triage-fact-task",
                "blackboard_domain": "http11_framing",
            }
        )
        assert out["current_vuln"] is not None
        facts = swarm.db.get_facts(task_id="triage-fact-task")
        assert len(facts) >= 1
        assert any(
            f["source_agent"] in ("triage_debugger_agent", "triage_debugger")
            and "VULN-TRIAGE-1" in (f["content"] + json.dumps(f["payload"]))
            for f in facts
        )
    finally:
        swarm.close()


def test_t1_f15_dual_graph_reason_from_blackboard_facts_emits_multihop_intents(
    bb_db: Database,
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
) -> None:
    eng = DualGraphAttackEngine(
        db=bb_db,
        reports_dir=isolated_swarm_workspace.reports_dir / "dg1",
        task_id="dg-task-1",
    )
    eng.ingest_target_infrastructure(
        host="127.0.0.1",
        port=loopback_lab_server.port,
        endpoints=["/", "/internal/service", "/api/chat"],
        ai_sinks=["/api/chat"],
    )
    bb_db.add_fact(
        "Confirmed HTTP/1.1 CL.0 desync on /",
        task_id="dg-task-1",
        domain="http11_framing",
        rfc_id="RFC9112",
        source_agent="triage_debugger_agent",
        payload={"rule_id": "desync-cl0-1", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
    )
    bb_db.add_fact(
        "Confirmed OIDC auth-boundary bypass on /internal/service",
        task_id="dg-task-1",
        domain="http_semantics_intermediaries",
        rfc_id="RFC9110",
        source_agent="triage_debugger_agent",
        payload={"rule_id": "auth-boundary-1", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
    )
    bb_db.add_fact(
        "Confirmed command execution sink in admin handler",
        task_id="dg-task-1",
        domain="exec",
        source_agent="mantis",
        payload={"rule_id": "exec-sink-1", "cwe": "CWE-78", "capability_class": "EXEC_SINK", "endpoint": "/internal/service"},
    )

    created_ids = eng.reason_from_blackboard_facts(db=bb_db, task_id="dg-task-1", round_num=1)
    assert isinstance(created_ids, list) and len(created_ids) >= 1
    intents = bb_db.list_intents(status="PENDING", task_id="dg-task-1")
    assert any(i["node_id"] in created_ids for i in intents)
    assert any(int(i["payload"].get("hop_count", 0)) >= 2 for i in intents)


def test_t1_f15_dual_graph_reason_is_idempotent_without_new_facts(
    bb_db: Database,
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
) -> None:
    eng = DualGraphAttackEngine(
        db=bb_db,
        reports_dir=isolated_swarm_workspace.reports_dir / "dg2",
        task_id="dg-idem",
    )
    eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_lab_server.port, endpoints=["/", "/internal/service"])
    bb_db.add_fact(
        "Confirmed CL.TE desync",
        task_id="dg-idem",
        source_agent="triage_debugger_agent",
        payload={"rule_id": "r-desync", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
    )
    bb_db.add_fact(
        "Confirmed Auth boundary bypass",
        task_id="dg-idem",
        source_agent="triage_debugger_agent",
        payload={"rule_id": "r-auth", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
    )
    round1 = eng.reason_from_blackboard_facts(db=bb_db, task_id="dg-idem", round_num=1)
    assert len(round1) >= 1
    count_after_r1 = len(bb_db.list_intents(task_id="dg-idem"))
    round2 = eng.reason_from_blackboard_facts(db=bb_db, task_id="dg-idem", round_num=2)
    assert round2 == []
    assert len(bb_db.list_intents(task_id="dg-idem")) == count_after_r1


def test_t1_f15_dual_graph_multihop_intent_retains_provenance_and_source_facts(
    bb_db: Database,
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
) -> None:
    eng = DualGraphAttackEngine(
        db=bb_db,
        reports_dir=isolated_swarm_workspace.reports_dir / "dg3",
        task_id="dg-prov",
    )
    eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_lab_server.port, endpoints=["/", "/internal/service"])
    f1 = bb_db.add_fact(
        "Desync primitive",
        task_id="dg-prov",
        source_agent="triage_debugger_agent",
        payload={"rule_id": "desync-p", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
    )
    f2 = bb_db.add_fact(
        "Auth boundary primitive",
        task_id="dg-prov",
        source_agent="triage_debugger_agent",
        payload={"rule_id": "auth-p", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
    )
    created = eng.reason_from_blackboard_facts(db=bb_db, task_id="dg-prov", round_num=1)
    assert created
    multihop_intents = [i for i in bb_db.list_intents(task_id="dg-prov") if int(i["payload"].get("hop_count", 0)) >= 2]
    assert len(multihop_intents) >= 1
    payload_str = json.dumps(multihop_intents[0]["payload"])
    assert any(tok in payload_str for tok in ("MULTI_HOP", "AUTH_BOUNDARY", "DESYNC", f1, f2))


def test_t1_f15_swarm_reason_phase_invokes_dual_graph_continuous_hook(
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
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        swarm.db.add_fact(
            "Desync confirmed",
            task_id="swarm-dg",
            source_agent="triage_debugger_agent",
            payload={"rule_id": "d-1", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
        )
        swarm.db.add_fact(
            "Auth boundary confirmed",
            task_id="swarm-dg",
            source_agent="triage_debugger_agent",
            payload={"rule_id": "a-1", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
        )
        called: List[str] = []
        orig_reason = DualGraphAttackEngine.reason_from_blackboard_facts

        def _spy_reason(self: Any, db: Any = None, *, task_id: Any = None, round_num: int = 1) -> List[str]:
            called.append(str(task_id))
            return orig_reason(self, db=db, task_id=task_id, round_num=round_num)

        monkeypatch.setattr(DualGraphAttackEngine, "reason_from_blackboard_facts", _spy_reason)
        swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [("Transfer-Encoding MUST override Content-Length.", "transfer-encoding", 2.0)],
                "task_id": "swarm-dg",
                "blackboard_domain": "http11_framing",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert len(called) >= 1
    finally:
        swarm.close()
