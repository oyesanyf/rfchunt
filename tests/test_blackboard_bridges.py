"""
Hermetic Unit & Integration Tests for Milestone M4 (Requirement R2):
- Harness2 `dream_rsi_agent` -> domain-scoped `HINT` promotion & cross-RFC domain transfer
- `triage_debugger_agent` -> confirmed vulnerability `FACT` persistence & artifact/noise suppression
- `DualGraphAttackEngine.reason_from_blackboard_facts` -> multi-hop chaining, provenance, idempotency
- Continuous `DualGraphAttackEngine` `Reason` hook inside `ProtocolResearchSwarm.llm_generator_agent`
"""

from __future__ import annotations

from pathlib import Path
import sys
import threading
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from database import Database
from engine.dual_graph_engine import DualGraphAttackEngine
from engine.execution_policy import ExecutionPolicy
from engine.taxonomy import (
    AnomalyCategory,
    ImpactClass,
    ImplementationAnomaly,
    ReproducibleVulnerability,
)
from fusion_engine import FusionArbiter
from mcp_server import TargetAuthorizationGate
from model_adapter import ModelFusionAdapter
from rfc_hunt_swarm import ProtocolResearchSwarm


SAMPLE_RFC_9112 = (
    "RFC 9112 HTTP/1.1 Message Syntax and Framing\n\n"
    "1. Transfer-Encoding and Content-Length\n"
    "A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding header field.\n"
)


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolates CWD, DB, encryption, offline flags, and security singletons inside tmp_path."""
    ws = tmp_path / "m4_ws"
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
    monkeypatch.setattr(
        FusionArbiter, "_fetch_available_tags", lambda self: ["gemma2:2b", "foundation-sec:latest"]
    )

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
        db_path=str(ws / "m4_bridges.db"),
        use_fusion=use_fusion,
        concurrency=1,
    )
    swarm.fetcher.cache_dir = ws / "rfcs"
    swarm.dream_store.storage_path = str(ws / "data" / "dream_policies.json")
    swarm.harness2_engine.runs_root = ws / "runs" / "harness2"
    return swarm


def _fake_h2_result(
    *,
    task_id: str = "RFC9112",
    domain: str = "http11_framing",
    adopted_label: str = "agg1",
    experience: Any = None,
) -> SimpleNamespace:
    exp_dict = experience if isinstance(experience, dict) else {}
    return SimpleNamespace(
        mode="parallel",
        task_id=task_id,
        domain=domain,
        k=1,
        adopted_label=adopted_label,
        rollouts={adopted_label: SimpleNamespace(behavioral_score=94.0)},
        experience=experience,
        to_dict=lambda: {
            "mode": "parallel",
            "task_id": task_id,
            "domain": domain,
            "k": 1,
            "adopted_label": adopted_label,
            "rollouts": {adopted_label: {"behavioral_score": 94.0}},
            "experience": exp_dict,
        },
    )


def test_dream_rsi_agent_promotes_lesson_cue_evidence_to_domain_hint(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_env)
    try:
        fake_res = _fake_h2_result(
            task_id="RFC9112",
            domain="http11_framing",
            adopted_label="agg1",
            experience={
                "cue": "obs-fold before Transfer-Encoding",
                "lesson": "Test duplicate TE headers paired with chunk extensions",
                "evidence": "3/3 differential parser divergences",
            },
        )
        monkeypatch.setattr(swarm.harness2_engine, "run_mode", lambda **kwargs: fake_res)

        out = swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 5,
                "enable_harness2": True,
                "harness2_k": 1,
                "harness2_mode": "parallel",
                "harness2_runs_dir": str(isolated_env / "runs" / "harness2"),
                "task_id": "campaign-1",
                "workspace_dir": str(isolated_env),
                "history": [],
            }
        )
        assert out["current_harness2_result"] is not None
        assert len(swarm.db.get_harness2_runs()) == 1

        hints = swarm.db.get_active_hints(task_id="campaign-1", domain="http11_framing")
        promoted = [h for h in hints if h["source_agent"] == "dream_rsi_agent"]
        assert len(promoted) == 1
        h = promoted[0]
        assert h["task_id"] == "campaign-1"
        assert h["domain"] == "http11_framing"
        assert h["rfc_id"] == "RFC9112"
        assert "obs-fold before Transfer-Encoding" in h["content"]
        assert "Test duplicate TE headers paired with chunk extensions" in h["content"]
        assert "3/3 differential parser divergences" in h["content"]
        assert h["payload"]["cue"] == "obs-fold before Transfer-Encoding"
        assert h["payload"]["lesson"] == "Test duplicate TE headers paired with chunk extensions"
        assert h["payload"]["evidence"] == "3/3 differential parser divergences"
    finally:
        swarm.close()


def test_dream_rsi_agent_cross_rfc_same_domain_steering_and_cross_domain_isolation(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen_prompts: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            seen_prompts.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )

    swarm = _make_swarm(isolated_env)
    try:
        fake_res = _fake_h2_result(
            task_id="RFC9112",
            domain="http11_framing",
            experience={
                "cue": "Content-Length vs Transfer-Encoding conflict",
                "lesson": "CROSS_RFC_DOMAIN_MARKER_9112_TO_7230",
                "evidence": "2/2 proxy desync",
            },
        )
        monkeypatch.setattr(swarm.harness2_engine, "run_mode", lambda **kwargs: fake_res)

        swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 5,
                "enable_harness2": True,
                "harness2_runs_dir": str(isolated_env / "runs" / "harness2"),
                "task_id": "camp-iso",
                "workspace_dir": str(isolated_env),
                "history": [],
            }
        )

        # Same domain, different RFC (RFC9112 -> RFC7230) must absorb dream_rsi_agent hint
        swarm.llm_generator_agent(
            {
                "rfc_num": "7230",
                "fragments": [("RFC 7230 chunked transfer coding rule.", "transfer-encoding", 2.0)],
                "blackboard_domain": "http11_framing",
                "task_id": "camp-iso",
                "workspace_dir": str(isolated_env),
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert len(seen_prompts) == 1
        assert "CROSS_RFC_DOMAIN_MARKER_9112_TO_7230" in seen_prompts[0]

        # Different domain (h2_translation) must remain isolated
        swarm.llm_generator_agent(
            {
                "rfc_num": "9113",
                "fragments": [("HTTP/2 streams MUST NOT include Transfer-Encoding.", "transfer-encoding", 2.0)],
                "blackboard_domain": "h2_translation",
                "task_id": "camp-iso",
                "workspace_dir": str(isolated_env),
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert len(seen_prompts) == 2
        assert "CROSS_RFC_DOMAIN_MARKER_9112_TO_7230" not in seen_prompts[1]

        # Regular non-dream_rsi_agent RFC-scoped hints remain strictly scoped to their rfc_id
        swarm.db.add_hint(
            "OTHER_RFC9110_CLI_HINT",
            task_id="camp-iso",
            domain="http11_framing",
            rfc_id="RFC9110",
            source_agent="cli",
            priority=50.0,
        )
        fetched = swarm._fetch_active_hints(
            task_id="camp-iso", domain="http11_framing", rfc_label="RFC9112", limit=50
        )
        assert all("OTHER_RFC9110_CLI_HINT" not in r["content"] for r in fetched)
        assert any("CROSS_RFC_DOMAIN_MARKER_9112_TO_7230" in r["content"] for r in fetched)
    finally:
        swarm.close()


@pytest.mark.parametrize(
    "bad_experience",
    [
        {"cue": "c", "lesson": "", "evidence": "e"},
        {"cue": "c", "lesson": "  \t\n ", "evidence": "e"},
        {"cue": "c", "evidence": "e"},
        None,
    ],
)
def test_dream_rsi_agent_skips_blank_or_missing_lesson(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
    bad_experience: Any,
) -> None:
    swarm = _make_swarm(isolated_env)
    try:
        fake_res = _fake_h2_result(experience=bad_experience)
        monkeypatch.setattr(swarm.harness2_engine, "run_mode", lambda **kwargs: fake_res)
        swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 5,
                "enable_harness2": True,
                "harness2_runs_dir": str(isolated_env / "runs" / "harness2"),
                "task_id": "blank-exp",
                "workspace_dir": str(isolated_env),
                "history": [],
            }
        )
        promoted = [h for h in swarm.db.get_active_hints() if h["source_agent"] == "dream_rsi_agent"]
        assert promoted == []
    finally:
        swarm.close()


def test_dream_rsi_agent_disabled_harness2_and_special_characters(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_env)
    try:
        called = False

        def _fail_run_mode(**kwargs: Any) -> Any:
            nonlocal called
            called = True
            raise AssertionError("run_mode must not be called when enable_harness2=False")

        monkeypatch.setattr(swarm.harness2_engine, "run_mode", _fail_run_mode)
        out = swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 5,
                "enable_harness2": False,
                "task_id": "disabled-h2",
                "workspace_dir": str(isolated_env),
                "history": [],
            }
        )
        assert not called
        assert out["current_harness2_result"] is None
        assert swarm.db.get_harness2_runs() == []
        assert [h for h in swarm.db.get_active_hints() if h["source_agent"] == "dream_rsi_agent"] == []

        special_lesson = "Quotes 'single' and \"double\"\r\nLine2 with lambda \u03bb"
        fake_res = _fake_h2_result(
            experience={"cue": "cue-\u03bb", "lesson": special_lesson, "evidence": "ev-1"}
        )
        monkeypatch.setattr(swarm.harness2_engine, "run_mode", lambda **kwargs: fake_res)
        swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 5,
                "enable_harness2": True,
                "harness2_runs_dir": str(isolated_env / "runs" / "harness2"),
                "task_id": "special-chars",
                "workspace_dir": str(isolated_env),
                "history": [],
            }
        )
        promoted = [
            h
            for h in swarm.db.get_active_hints(task_id="special-chars", domain="http11_framing")
            if h["source_agent"] == "dream_rsi_agent"
        ]
        assert len(promoted) == 1
        assert special_lesson in promoted[0]["content"]
        assert promoted[0]["payload"]["lesson"] == special_lesson
    finally:
        swarm.close()


def test_triage_debugger_agent_commits_fact_on_confirmed_vuln_and_suppresses_noise(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_env)
    try:
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-M4-1",
            target_engine="127.0.0.1:18080",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="CL.0 request smuggling into /internal/service",
            expected_behavior="clean isolation",
            raw_probe=b"GET / HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\nleaked",
        )
        confirmed_vuln = ReproducibleVulnerability(
            vuln_id="VULN-M4-1",
            anomaly_id="ANOM-M4-1",
            impact=ImpactClass.DESYNCHRONIZATION,
            minimized_probe=b"GET / HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD",
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=1,
            provenance_chain="DeltaDebugger",
        )

        # 1. Framing artifact -> 0 FACTs
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (True, "artifact"))
        swarm.triage_debugger_agent(
            {"rfc_num": "9112", "current_anomaly": anom, "task_id": "t-art", "blackboard_domain": "http11_framing"}
        )
        assert swarm.db.get_facts(task_id="t-art") == []

        # 2. Environmental noise -> 0 FACTs
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: True)
        swarm.triage_debugger_agent(
            {"rfc_num": "9112", "current_anomaly": anom, "task_id": "t-noise", "blackboard_domain": "http11_framing"}
        )
        assert swarm.db.get_facts(task_id="t-noise") == []

        # 3. Low reproducibility (0.33) -> 0 FACTs
        low_repro = ReproducibleVulnerability(
            vuln_id="VULN-LOW",
            anomaly_id="ANOM-M4-1",
            impact=ImpactClass.DESYNCHRONIZATION,
            minimized_probe=b"GET / HTTP/1.1\r\n\r\n",
            reproducibility_rate=0.33,
            verification_attempts=3,
            successful_reproductions=1,
            delta_debug_steps=1,
            provenance_chain="DeltaDebugger",
        )
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: False)
        monkeypatch.setattr(swarm.debugger, "minimize_and_reproduce", lambda a, max_verification_trials=3: low_repro)
        swarm.triage_debugger_agent(
            {"rfc_num": "9112", "current_anomaly": anom, "task_id": "t-low", "blackboard_domain": "http11_framing"}
        )
        assert swarm.db.get_facts(task_id="t-low") == []

        # 4. Invalid evidence -> 0 FACTs
        monkeypatch.setattr(swarm.debugger, "minimize_and_reproduce", lambda a, max_verification_trials=3: confirmed_vuln)
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (False, "no-evidence"))
        swarm.triage_debugger_agent(
            {"rfc_num": "9112", "current_anomaly": anom, "task_id": "t-inval", "blackboard_domain": "http11_framing"}
        )
        assert swarm.db.get_facts(task_id="t-inval") == []

        # 5. Confirmed vulnerability -> FACT committed immediately
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (True, "ok"))
        monkeypatch.setattr(swarm.classifier, "classify_novelty", lambda v: (False, None))
        out = swarm.triage_debugger_agent(
            {
                "rfc_num": "9112",
                "current_anomaly": anom,
                "task_id": "t-ok",
                "blackboard_domain": "http11_framing",
                "active_intent_id": "intent:seed:1",
            }
        )
        assert out["current_vuln"] is not None
        facts = swarm.db.get_facts(task_id="t-ok")
        assert len(facts) == 1
        f = facts[0]
        assert f["node_id"] == "fact:vuln:VULN-M4-1:t-ok"
        assert f["source_agent"] == "triage_debugger_agent"
        assert f["domain"] == "http11_framing"
        assert f["rfc_id"] == "RFC9112"
        assert f["parent_node_id"] == "intent:seed:1"
        assert f["payload"]["vuln_id"] == "VULN-M4-1"
        assert f["payload"]["anomaly_id"] == "ANOM-M4-1"
        assert f["payload"]["impact"] == ImpactClass.DESYNCHRONIZATION.value
        assert f["payload"]["reproducibility_rate"] == 1.0
        assert "minimized_probe" in f["payload"]
        assert f["payload"]["observed_behavior"] == anom.observed_behavior
    finally:
        swarm.close()


def test_dual_graph_reason_from_blackboard_facts_chains_multihop_with_provenance(
    isolated_env: Path,
) -> None:
    db_path = isolated_env / "dg_chain.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        eng = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "dg1", task_id="dg-1"
        )
        eng.ingest_target_infrastructure(
            host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"]
        )

        # Single-fact DB must not fabricate multi-hop intents
        f1 = db.add_fact(
            "Confirmed DESYNC via triage",
            node_id="fact:vuln:VULN-1:dg-1",
            task_id="dg-1",
            domain="http11_framing",
            rfc_id="RFC9112",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-1",
                "anomaly_id": "ANOM-1",
                "impact": "DESYNCHRONIZATION",
                "reproducibility_rate": 1.0,
                "minimized_probe": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nABCD",
                "observed_behavior": "CL.0 desync",
            },
        )
        assert eng.reason_from_blackboard_facts(db=db, task_id="dg-1", round_num=1) == []

        # Lifecycle facts, corrupt JSON, and other-task facts must not chain or crash
        db.add_fact("Bootstrap RFC", node_id="fact:bootstrap:rfc:9112", task_id="dg-1", payload={"findings_count": 0})
        db.add_fact("Conformant probe", node_id="fact:conformant:i1", task_id="dg-1", payload={"resp_summary": "200"})
        db.add_fact("Other task auth", task_id="dg-other", payload={"rule_id": "auth-other", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"})
        db.add_fact("Corrupt JSON row", node_id="fact:corrupt:1", task_id="dg-1")
        with db.conn:
            db.conn.execute(
                "UPDATE blackboard_nodes SET payload_json = '{bad-json' WHERE node_id = ?",
                ("fact:corrupt:1",),
            )
        assert eng.reason_from_blackboard_facts(db=db, task_id="dg-1", round_num=1) == []

        # Add complementary AUTH_BOUNDARY fact -> multi-hop INTENT created with provenance
        f2 = db.add_fact(
            "Confirmed auth boundary bypass on /internal/service",
            task_id="dg-1",
            domain="http_semantics_intermediaries",
            rfc_id="RFC9110",
            source_agent="triage_debugger_agent",
            payload={
                "rule_id": "auth-b-1",
                "cwe": "CWE-287",
                "capability_class": "AUTH_BOUNDARY",
                "endpoint": "/internal/service",
            },
        )
        created = eng.reason_from_blackboard_facts(db=db, task_id="dg-1", round_num=2)
        assert len(created) >= 1
        assert db.list_intents(task_id="dg-other") == []

        intents = db.list_intents(status="PENDING", task_id="dg-1", limit=0)
        created_rows = [i for i in intents if i["node_id"] in created]
        assert len(created_rows) == len(created)
        assert any(set(row["payload"]["source_facts"]) >= {f1, f2} for row in created_rows)
        for row in created_rows:
            p = row["payload"]
            assert int(p["hop_count"]) >= 2
            assert "fact:corrupt:1" not in p["source_facts"]
            assert isinstance(p["provenance"], list) and len(p["provenance"]) >= 2
            assert str(p["raw_request"]).strip()
            assert "HTTP/" in p["raw_request"]


def test_dual_graph_reason_from_blackboard_facts_idempotent_same_and_fresh_engine(
    isolated_env: Path,
) -> None:
    db_path = isolated_env / "dg_idem.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        eng1 = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "idem1", task_id="dg-idem"
        )
        eng1.ingest_target_infrastructure(
            host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"]
        )
        db.add_fact(
            "Desync",
            task_id="dg-idem",
            source_agent="triage_debugger_agent",
            payload={"rule_id": "r-d", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
        )
        db.add_fact(
            "Auth boundary",
            task_id="dg-idem",
            source_agent="triage_debugger_agent",
            payload={"rule_id": "r-a", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
        )

        round1 = eng1.reason_from_blackboard_facts(db=db, task_id="dg-idem", round_num=1)
        assert len(round1) >= 1
        db.complete_intent(round1[0], status="DONE")

        # Repeat on same instance -> [] and DONE status preserved
        assert eng1.reason_from_blackboard_facts(db=db, task_id="dg-idem", round_num=2) == []
        done_rows = db.list_intents(status="DONE", task_id="dg-idem", limit=0)
        assert any(r["node_id"] == round1[0] for r in done_rows)

        # Fresh instance against same DB -> []
        eng2 = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "idem2", task_id="dg-idem"
        )
        eng2.ingest_target_infrastructure(
            host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"]
        )
        assert eng2.reason_from_blackboard_facts(db=db, task_id="dg-idem", round_num=3) == []

        # New complementary EXEC_SINK fact -> plans new chain(s)
        db.add_fact(
            "Command injection sink",
            task_id="dg-idem",
            source_agent="mantis",
            payload={"rule_id": "r-e", "cwe": "CWE-78", "capability_class": "EXEC_SINK", "endpoint": "/internal/service"},
        )
        round4 = eng2.reason_from_blackboard_facts(db=db, task_id="dg-idem", round_num=4)
        assert len(round4) >= 1
        assert set(round4).isdisjoint(set(round1))


def test_swarm_reason_phase_continuous_dual_graph_hook_and_localized_reports(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [
            {"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}
        ],
    )
    swarm = _make_swarm(isolated_env)
    try:
        # Empty fragments + no finding facts -> 0 phantom intents
        empty_out = swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [],
                "task_id": "swarm-empty",
                "workspace_dir": str(isolated_env),
                "blackboard_domain": "http11_framing",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert empty_out["generated_candidates"] == []
        assert swarm.db.list_intents(task_id="swarm-empty") == []

        # Seed complementary facts and spy on class-level DualGraphAttackEngine.reason_from_blackboard_facts
        swarm.db.add_fact(
            "Desync confirmed",
            task_id="swarm-dg",
            source_agent="triage_debugger_agent",
            payload={"rule_id": "sd-1", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
        )
        swarm.db.add_fact(
            "Auth boundary confirmed",
            task_id="swarm-dg",
            source_agent="triage_debugger_agent",
            payload={"rule_id": "sa-1", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
        )

        spy_calls: List[Dict[str, Any]] = []
        orig_reason = DualGraphAttackEngine.reason_from_blackboard_facts

        def _spy_reason(
            self: DualGraphAttackEngine,
            db: Any = None,
            *,
            task_id: Any = None,
            round_num: int = 1,
        ) -> List[str]:
            spy_calls.append(
                {
                    "task_id": task_id,
                    "round_num": round_num,
                    "reports_dir": Path(self.reports_dir),
                }
            )
            return orig_reason(self, db=db, task_id=task_id, round_num=round_num)

        monkeypatch.setattr(DualGraphAttackEngine, "reason_from_blackboard_facts", _spy_reason)

        swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [("Transfer-Encoding MUST override Content-Length.", "transfer-encoding", 2.0)],
                "task_id": "swarm-dg",
                "workspace_dir": str(isolated_env),
                "blackboard_domain": "http11_framing",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )

        assert len(spy_calls) == 1
        assert spy_calls[0]["task_id"] == "swarm-dg"
        assert spy_calls[0]["round_num"] == 1
        assert isolated_env.resolve() in spy_calls[0]["reports_dir"].resolve().parents

        pending = swarm.db.list_intents(status="PENDING", task_id="swarm-dg", limit=0)
        assert any(int(i["payload"].get("hop_count", 0)) >= 2 for i in pending)
        assert any(i["source_agent"] == "llm_generator_agent" for i in pending)
    finally:
        swarm.close()


def test_dual_graph_toctou_two_engines_wal_never_resets_done(
    isolated_env: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = isolated_env / "dg_toctou_wal.db"
    with (
        Database(str(db_path), encrypt_at_rest=False) as db_a,
        Database(str(db_path), encrypt_at_rest=False) as db_b,
        Database(str(db_path), encrypt_at_rest=False) as db_worker,
    ):
        db_a.add_fact(
            "Desync finding",
            node_id="fact:vuln:VULN-T1:toctou",
            task_id="toctou",
            source_agent="triage_debugger_agent",
            payload={"vuln_id": "VULN-T1", "rule_id": "r-d", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
        )
        db_a.add_fact(
            "Auth boundary finding",
            node_id="fact:vuln:VULN-T2:toctou",
            task_id="toctou",
            source_agent="triage_debugger_agent",
            payload={"vuln_id": "VULN-T2", "rule_id": "r-a", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
        )

        eng_a = DualGraphAttackEngine(
            db=db_a, reports_dir=isolated_env / "reports" / "toctou_a", task_id="toctou"
        )
        eng_b = DualGraphAttackEngine(
            db=db_b, reports_dir=isolated_env / "reports" / "toctou_b", task_id="toctou"
        )
        eng_a.ingest_target_infrastructure(host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"])
        eng_b.ingest_target_infrastructure(host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"])

        interleaved_created: List[str] = []
        interleaved_errors: List[BaseException] = []
        orig_list_intents = db_a.list_intents

        def _interleave_after_list_intents(*args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
            # Engine A observes empty intents first (pre-insert TOCTOU snapshot)
            snapshot = orig_list_intents(*args, **kwargs)
            assert snapshot == []

            # While Engine A is paused before inserting, Engine B queues and Worker claims+completes DONE
            def _run_b_and_worker() -> None:
                try:
                    created_b = eng_b.reason_from_blackboard_facts(db=db_b, task_id="toctou", round_num=1)
                    interleaved_created.extend(created_b)
                    for nid in created_b:
                        claimed = db_worker.claim_next_intent("worker-toctou", task_id="toctou")
                        assert claimed is not None and claimed["node_id"] == nid
                        assert db_worker.complete_intent(nid, status="DONE") is True
                except BaseException as exc:  # pragma: no cover - surfaced below
                    interleaved_errors.append(exc)

            t = threading.Thread(target=_run_b_and_worker, daemon=True)
            t.start()
            t.join(timeout=10.0)
            assert not t.is_alive()
            return snapshot

        monkeypatch.setattr(db_a, "list_intents", _interleave_after_list_intents)

        created_a = eng_a.reason_from_blackboard_facts(db=db_a, task_id="toctou", round_num=1)
        assert not interleaved_errors
        assert len(interleaved_created) >= 1
        assert created_a == []

        all_intents = db_worker.list_intents(task_id="toctou", limit=0)
        assert len(all_intents) == len(interleaved_created)
        assert all(row["status"] == "DONE" for row in all_intents)
        assert all(row["claimed_by"] == "worker-toctou" for row in all_intents)
        assert all(row["completed_at"] is not None for row in all_intents)


def test_dual_graph_nonnumeric_findings_count_safe(
    isolated_env: Path,
) -> None:
    db_path = isolated_env / "dg_nonnumeric_fc.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        db.add_fact(
            "Audit N/A count",
            node_id="fact:audit:na",
            task_id="dg-fc",
            payload={"findings_count": "N/A"},
        )
        db.add_fact(
            "Audit abc count",
            node_id="fact:audit:abc",
            task_id="dg-fc",
            payload={"findings_count": "abc"},
        )
        eng = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "dg_fc", task_id="dg-fc"
        )
        assert eng.reason_from_blackboard_facts(db=db, task_id="dg-fc", round_num=1) == []
        assert db.list_intents(task_id="dg-fc", limit=0) == []


def test_dual_graph_empty_info_fact_no_phantom_desync_and_kg_vuln_canonical_dedup(
    isolated_env: Path,
) -> None:
    db_path = isolated_env / "dg_info_kg_dedup.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        # 1. Empty-payload informational FACT alongside 1 real AUTH_BOUNDARY finding must NOT fabricate DESYNC chain
        db.add_fact(
            "Target listens on port 18080",
            node_id="fact:info:port",
            task_id="dg-info",
            payload={},
        )
        db.add_fact(
            "Confirmed auth boundary bypass",
            node_id="fact:vuln:VULN-AUTH-1:dg-info",
            task_id="dg-info",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-AUTH-1",
                "rule_id": "auth-1",
                "cwe": "CWE-287",
                "capability_class": "AUTH_BOUNDARY",
                "endpoint": "/internal/service",
            },
        )
        eng = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "dg_info", task_id="dg-info"
        )
        eng.ingest_target_infrastructure(host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"])
        assert eng.reason_from_blackboard_facts(db=db, task_id="dg-info", round_num=1) == []
        assert db.list_intents(task_id="dg-info", limit=0) == []

        # 2. kg:VULN-X in Round 1 followed by fact:vuln:VULN-X in Round 2 must NOT emit duplicate intents
        db.add_fact(
            "KG Desync vulnerability VULN-X",
            node_id="kg:VULN-X",
            task_id="dg-kg-dedup",
            domain="http11_framing",
            source_agent="ResearchKnowledgeGraph",
            payload={
                "kg_node_type": "VULNERABILITY",
                "kg_node_id": "VULN-X",
                "capability_class": "DESYNC",
                "cwe": "CWE-444",
                "endpoint": "/",
            },
        )
        db.add_fact(
            "Auth boundary for kg dedup",
            node_id="fact:vuln:VULN-AUTH-KG:dg-kg-dedup",
            task_id="dg-kg-dedup",
            domain="http_semantics_intermediaries",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-AUTH-KG",
                "rule_id": "auth-kg",
                "cwe": "CWE-287",
                "capability_class": "AUTH_BOUNDARY",
                "endpoint": "/internal/service",
            },
        )
        eng_kg = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "dg_kg", task_id="dg-kg-dedup"
        )
        eng_kg.ingest_target_infrastructure(host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"])
        r1 = eng_kg.reason_from_blackboard_facts(db=db, task_id="dg-kg-dedup", round_num=1)
        assert len(r1) == 1

        # Now fact:vuln:VULN-X:dg-kg-dedup arrives in Round 2 -> canonical vuln_id "VULN-X" already ingested -> []
        db.add_fact(
            "Triage Desync vulnerability VULN-X",
            node_id="fact:vuln:VULN-X:dg-kg-dedup",
            task_id="dg-kg-dedup",
            domain="http11_framing",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-X",
                "impact": "DESYNCHRONIZATION",
                "capability_class": "DESYNC",
                "cwe": "CWE-444",
                "endpoint": "/",
            },
        )
        r2 = eng_kg.reason_from_blackboard_facts(db=db, task_id="dg-kg-dedup", round_num=2)
        assert r2 == []
        assert len(db.list_intents(task_id="dg-kg-dedup", limit=0)) == 1


def test_dual_graph_kg_then_fact_fresh_engine_canonical_dedup(
    isolated_env: Path,
) -> None:
    db_path = isolated_env / "dg_kg_fresh_dedup.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        db.add_fact(
            "Confirmed auth boundary bypass",
            node_id="fact:vuln:VULN-AUTH:p3d",
            task_id="p3d",
            domain="http_semantics_intermediaries",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-AUTH",
                "rule_id": "auth-p3d",
                "cwe": "CWE-287",
                "capability_class": "AUTH_BOUNDARY",
                "endpoint": "/internal/service",
            },
        )
        db.add_fact(
            "KG Desync vulnerability VULN-Z",
            node_id="kg:VULN-Z",
            task_id="p3d",
            domain="http11_framing",
            source_agent="ResearchKnowledgeGraph",
            payload={
                "kg_node_type": "VULNERABILITY",
                "kg_node_id": "VULN-Z",
                "capability_class": "DESYNC",
                "cwe": "CWE-444",
                "endpoint": "/",
            },
        )

        eng1 = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "p3d_1", task_id="p3d"
        )
        eng1.ingest_target_infrastructure(
            host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"]
        )
        r1 = eng1.reason_from_blackboard_facts(db=db, task_id="p3d", round_num=1)
        assert len(r1) == 1

        # fact:vuln:VULN-Z:p3d arrives later, and a fresh engine runs Round 2
        db.add_fact(
            "Triage Desync vulnerability VULN-Z",
            node_id="fact:vuln:VULN-Z:p3d",
            task_id="p3d",
            domain="http11_framing",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-Z",
                "impact": "DESYNCHRONIZATION",
                "capability_class": "DESYNC",
                "cwe": "CWE-444",
                "endpoint": "/",
            },
        )
        eng2 = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "p3d_2", task_id="p3d"
        )
        eng2.ingest_target_infrastructure(
            host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"]
        )
        r2 = eng2.reason_from_blackboard_facts(db=db, task_id="p3d", round_num=2)
        assert r2 == []
        intents = db.list_intents(task_id="p3d", limit=0)
        assert len(intents) == 1
        assert set(intents[0]["payload"]["source_facts"]) == {
            "fact:vuln:VULN-AUTH:p3d",
            "kg:VULN-Z",
        }


def test_dual_graph_existing_intent_nonfinite_hop_count_safe(
    isolated_env: Path,
) -> None:
    db_path = isolated_env / "dg_nonfinite_hop.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        with db.conn:
            db.conn.execute(
                """
                INSERT INTO blackboard_nodes (
                    node_id, task_id, node_type, status, priority, content, payload_json
                )
                VALUES (?, ?, 'INTENT', 'PENDING', 10.0, ?, ?)
                """,
                (
                    "intent:artex:p2d:inf-hop",
                    "p2d",
                    "Existing intent with Infinity hop_count",
                    '{"attack_type": "MULTI_HOP_SMUGGLED_EXPLOIT", "source_facts": ["a", "b"], "hop_count": Infinity}',
                ),
            )

        db.add_fact(
            "Desync finding",
            node_id="fact:vuln:VULN-INF-1:p2d",
            task_id="p2d",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-INF-1",
                "capability_class": "DESYNC",
                "cwe": "CWE-444",
                "endpoint": "/",
            },
        )
        db.add_fact(
            "Auth boundary finding",
            node_id="fact:vuln:VULN-INF-2:p2d",
            task_id="p2d",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-INF-2",
                "capability_class": "AUTH_BOUNDARY",
                "cwe": "CWE-287",
                "endpoint": "/internal/service",
            },
        )

        eng = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "p2d", task_id="p2d"
        )
        eng.ingest_target_infrastructure(
            host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"]
        )
        created = eng.reason_from_blackboard_facts(db=db, task_id="p2d", round_num=1)
        assert len(created) == 1


def test_dual_graph_inactive_fact_vuln_does_not_suppress_active_kg_vuln(
    isolated_env: Path,
) -> None:
    db_path = isolated_env / "dg_inactive_fact_kg.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        db.add_fact(
            "Inactive triage fact for VULN-Z",
            node_id="fact:vuln:VULN-Z:p2d-inact",
            task_id="p2d-inact",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-Z",
                "capability_class": "DESYNC",
                "cwe": "CWE-444",
                "endpoint": "/",
            },
        )
        with db.conn:
            db.conn.execute(
                "UPDATE blackboard_nodes SET status = 'INACTIVE' WHERE node_id = ?",
                ("fact:vuln:VULN-Z:p2d-inact",),
            )
        db.add_fact(
            "Active KG VULN-Z",
            node_id="kg:VULN-Z",
            task_id="p2d-inact",
            source_agent="ResearchKnowledgeGraph",
            payload={
                "kg_node_type": "VULNERABILITY",
                "kg_node_id": "VULN-Z",
                "capability_class": "DESYNC",
                "cwe": "CWE-444",
                "endpoint": "/",
            },
        )
        db.add_fact(
            "Active Auth boundary",
            node_id="fact:vuln:VULN-AUTH-Z:p2d-inact",
            task_id="p2d-inact",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-AUTH-Z",
                "capability_class": "AUTH_BOUNDARY",
                "cwe": "CWE-287",
                "endpoint": "/internal/service",
            },
        )

        eng = DualGraphAttackEngine(
            db=db, reports_dir=isolated_env / "reports" / "p2d_inact", task_id="p2d-inact"
        )
        eng.ingest_target_infrastructure(
            host="127.0.0.1", port=18080, endpoints=["/", "/internal/service"]
        )
        created = eng.reason_from_blackboard_facts(db=db, task_id="p2d-inact", round_num=1)
        assert len(created) == 1
        intents = db.list_intents(task_id="p2d-inact", limit=0)
        assert len(intents) == 1
        assert set(intents[0]["payload"]["source_facts"]) == {
            "fact:vuln:VULN-AUTH-Z:p2d-inact",
            "kg:VULN-Z",
        }
