"""
Tier 3 Pairwise Cross-Feature Combination Tests (>= 16 tests: 18 tests).
Verifies interactions across Blackboard SQLite, Concurrency, SecretBox,
ResearchKnowledgeGraph, OODA Swarm, CLI/MCP Hints, YAML Dispatch, Harness², and DualGraph.

Collection-safe: M2-M4 symbols/modules are resolved inside test bodies/helpers.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import multiprocessing
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
from typing import Any, Callable, Dict, List

import pytest
import yaml

from database import Database
from engine.dual_graph_engine import DualGraphAttackEngine
from engine.knowledge_graph import ResearchKnowledgeGraph
from engine.taxonomy import AnomalyCategory, ImpactClass, ImplementationAnomaly, ReproducibleVulnerability
from fusion_engine import FusionArbiter
from mcp_server import TerminatorMCPServer
from tests.e2e_blackboard.conftest import REPO_ROOT, TEST_HEX_KEY, _mp_claim_worker


def _make_swarm(ws: SimpleNamespace, *, port: int, use_fusion: bool = False, monkeypatch: pytest.MonkeyPatch) -> Any:
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import ProtocolResearchSwarm

    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(FusionArbiter, "_fetch_available_tags", lambda self: ["gemma2:2b", "foundation-sec:latest"])
    swarm = ProtocolResearchSwarm(
        host="127.0.0.1",
        port=port,
        db_path=str(ws.db_path),
        use_fusion=use_fusion,
        concurrency=2,
    )
    swarm.fetcher.cache_dir = ws.rfcs_dir
    swarm.dream_store.storage_path = str(ws.root / "data" / "dream_policies.json")
    swarm.harness2_engine.runs_root = ws.harness2_runs_dir
    return swarm


# 1. Multithread contention on shared Database (12 threads, 60 INTENTs)
def test_t3_01_multithread_shared_db_atomic_intent_claiming(bb_db: Database) -> None:
    expected = {bb_db.queue_intent(f"mt-shared-{i}", priority=float(i % 7), task_id="mt-shared") for i in range(60)}
    barrier = threading.Barrier(12)

    def _worker(wid: int) -> List[str]:
        barrier.wait(timeout=10.0)
        claimed: List[str] = []
        while True:
            item = bb_db.claim_next_intent(f"thread-{wid}", task_id="mt-shared")
            if item is None:
                break
            claimed.append(item["node_id"])
        return claimed

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(_worker, range(12)))

    flat = [nid for sub in results for nid in sub]
    assert len(flat) == 60
    assert set(flat) == expected
    assert bb_db.claim_next_intent("after", task_id="mt-shared") is None


# 2. Multithread contention across 12 separate Database connections to same WAL DB
def test_t3_02_multithread_separate_connections_atomic_intent_claiming(
    bb_db_factory: Callable[..., Database],
    tmp_path: Path,
) -> None:
    seed_db = bb_db_factory("mt_wal_race.db")
    expected = {seed_db.queue_intent(f"mt-conn-{i}", priority=float(i), task_id="mt-conns") for i in range(48)}
    seed_db.close()

    db_file = str(tmp_path / "mt_wal_race.db")
    key_file = str(tmp_path / "keys" / "secret.key")
    barrier = threading.Barrier(12)

    def _worker(wid: int) -> List[str]:
        conn_db = Database(db_file, timeout=30.0, secret_key_path=key_file)
        claimed: List[str] = []
        try:
            barrier.wait(timeout=10.0)
            while True:
                item = conn_db.claim_next_intent(f"conn-worker-{wid}", task_id="mt-conns")
                if item is None:
                    break
                claimed.append(item["node_id"])
        finally:
            conn_db.close()
        return claimed

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(_worker, range(12)))

    flat = [nid for sub in results for nid in sub]
    assert len(flat) == 48
    assert set(flat) == expected


# 3. Multiprocess (Windows spawn) atomic INTENT claiming across 4 OS processes
def test_t3_03_multiprocess_spawn_atomic_intent_claiming(tmp_path: Path) -> None:
    db_file = tmp_path / "mp_race.db"
    key_file = tmp_path / "keys" / "secret.key"
    seed = Database(str(db_file), timeout=30.0, secret_key_path=str(key_file))
    expected = {seed.queue_intent(f"mp-item-{i}", priority=float(i % 5), task_id="mp-t") for i in range(40)}
    seed.close()

    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(4)
    out_q = ctx.Queue()
    procs = [
        ctx.Process(
            target=_mp_claim_worker,
            args=(str(db_file), str(key_file), f"mp-w-{i}", "mp-t", barrier, out_q),
        )
        for i in range(4)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30.0)
        assert p.exitcode == 0

    all_claimed: List[str] = []
    for _ in range(4):
        msg = out_q.get(timeout=5.0)
        assert msg["errors"] == []
        all_claimed.extend(msg["claimed"])

    assert len(all_claimed) == 40
    assert set(all_claimed) == expected


# 4. Pre-migration v003 + SecretBox + ResearchKnowledgeGraph(db=db)
def test_t3_04_premigration_v003_plus_secret_box_plus_kg_mirroring(
    pre_migration_db_builder: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARTEX_SECRET_KEY", TEST_HEX_KEY)
    legacy_path = pre_migration_db_builder("v003")
    db = Database(str(legacy_path), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        kg = ResearchKnowledgeGraph(db=db, task_id="v003-kg", domain="http11_framing")
        kg.add_node("RFC9112", "RFC", "HTTP/1.1 Framing")
        kg.add_node("REQ-1", "REQUIREMENT", "Reject obs-fold")
        kg.add_edge("RFC9112", "REQ-1", "DEFINES")
        kg.add_node("VULN-1", "VULNERABILITY", "Confirmed obs-fold desync")
        kg.record_testing_event("REQ-1", "VULN-1", is_vulnerability=True)

        assert len(db.get_facts(task_id="v003-kg")) >= 1
        assert len(db.list_intents(task_id="v003-kg")) >= 1
        assert db.conn.execute("SELECT chain_id FROM attack_chains").fetchone()[0] == "legacy-chain-1"
    finally:
        db.close()


# 5. Pre-001 upgrade + reclaim_stale_intents + add_hint + get_active_hints
def test_t3_05_pre001_upgrade_plus_reclaim_plus_hints(
    pre_migration_db_builder: Callable[..., Path],
    bb_db_factory: Callable[..., Database],
) -> None:
    legacy = pre_migration_db_builder("pre_001")
    db1 = bb_db_factory(str(legacy))
    nid = db1.queue_intent("after-pre001", priority=9.0, task_id="pre-t")
    db1.claim_next_intent("dead-worker", task_id="pre-t")
    db1.add_hint("pre001 hint", domain="http11_framing", task_id="pre-t", priority=15.0)
    db1.close()

    db2 = bb_db_factory(str(legacy))
    assert db2.reclaim_stale_intents(task_id="pre-t") == 1
    assert db2.claim_next_intent("live-worker", task_id="pre-t")["node_id"] == nid
    assert len(db2.get_active_hints(task_id="pre-t", domain="http11_framing")) == 1


# 6. CLI hint + llm_generator_agent + ProbeGenerator(use_fusion=False)
def test_t3_06_cli_hint_plus_llm_generator_plus_probe_generator_nonfusion(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    offline_subprocess_env: Dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    proc = subprocess.run(
        [
            sys.executable,
            "-u",
            str(REPO_ROOT / "rfc_hunt_swarm.py"),
            "hint",
            "--hint",
            "CLI_PAIRWISE_HINT_NONFUSION",
            "--hint-domain",
            "http11_framing",
            "--hint-task-id",
            "pw-nf",
            "--db",
            str(isolated_swarm_workspace.db_path),
        ],
        cwd=str(isolated_swarm_workspace.root),
        env=offline_subprocess_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=25,
    )
    assert proc.returncode == 0

    seen: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            seen.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, use_fusion=False, monkeypatch=monkeypatch)
    try:
        swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [("Transfer-Encoding MUST override Content-Length.", "transfer-encoding", 2.0)],
                "task_id": "pw-nf",
                "blackboard_domain": "http11_framing",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert len(seen) == 1
        assert "CLI_PAIRWISE_HINT_NONFUSION" in seen[0]
    finally:
        swarm.close()


# 7. MCP inject_blackboard_hint + llm_generator_agent + FusionArbiter
def test_t3_07_mcp_hint_plus_llm_generator_plus_fusion_arbiter(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TerminatorMCPServer(db_path=str(isolated_swarm_workspace.db_path)) as srv:
        resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "inject_blackboard_hint",
                    "arguments": {
                        "hint_text": "MCP_PAIRWISE_FUSION_HINT",
                        "domain": "http11_framing",
                        "priority": 60.0,
                        "task_id": "pw-fusion",
                    },
                },
            }
        )
        assert "result" in resp

    fusion_prompts: List[str] = []

    def _fake_query(self: Any, model: str, prompt: str, system_prompt: str, num_predict: int = 160) -> str:
        fusion_prompts.append(prompt)
        return json.dumps(
            {
                "rationale": f"from-{model}",
                "raw_request": f"POST /{len(fusion_prompts)} HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD",
                "is_clean": False,
            }
        )

    monkeypatch.setattr(FusionArbiter, "_query_model", _fake_query)
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, use_fusion=True, monkeypatch=monkeypatch)
    try:
        swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [("A server MUST reject whitespace before header colon.", "header", 2.0)],
                "task_id": "pw-fusion",
                "blackboard_domain": "http11_framing",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert len(fusion_prompts) >= 2
        assert all("MCP_PAIRWISE_FUSION_HINT" in p for p in fusion_prompts)
    finally:
        swarm.close()


# 8. CLI + MCP hints priority arbitration + deactivate_hint mid-run
def test_t3_08_cli_plus_mcp_priority_ordering_and_deactivate(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rfc_hunt_swarm import main_swarm

    main_swarm(
        [
            "hint",
            "--hint",
            "CLI_LOW_HINT",
            "--hint-domain",
            "http11_framing",
            "--hint-priority",
            "10",
            "--hint-task-id",
            "pw-prio",
            "--db",
            str(isolated_swarm_workspace.db_path),
        ]
    )
    with TerminatorMCPServer(db_path=str(isolated_swarm_workspace.db_path)) as srv:
        r = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "inject_blackboard_hint",
                    "arguments": {
                        "hint_text": "MCP_HIGH_HINT",
                        "domain": "http11_framing",
                        "priority": 90,
                        "task_id": "pw-prio",
                    },
                },
            }
        )
        mcp_nid = json.loads(r["result"]["content"][0]["text"])["node_id"]

    db = Database(str(isolated_swarm_workspace.db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
    try:
        active = db.get_active_hints(task_id="pw-prio", domain="http11_framing")
        assert [h["content"] for h in active] == ["MCP_HIGH_HINT", "CLI_LOW_HINT"]
        assert db.deactivate_hint(mcp_nid) is True
        active_after = db.get_active_hints(task_id="pw-prio", domain="http11_framing")
        assert [h["content"] for h in active_after] == ["CLI_LOW_HINT"]
    finally:
        db.close()


# 9. OODA Bootstrap -> Reason -> Explore full loopback cycle
def test_t3_09_ooda_bootstrap_reason_explore_full_cycle(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [
            {"rationale": "clean baseline", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True}
        ],
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, use_fusion=False, monkeypatch=monkeypatch)
    try:
        graph = swarm.build_graph()
        out = graph.invoke(
            {
                "rfc_num": "9112",
                "fragments": [],
                "generated_candidates": [],
                "cycle_count": 0,
                "max_cycles": 1,
                "enable_dream_rsi": False,
                "enable_harness2": False,
                "blackboard_bootstrapped": False,
                "task_id": "pw-ooda-9",
                "blackboard_domain": "http11_framing",
                "history": [],
            },
            {"recursion_limit": 150},
        )
        assert out["blackboard_bootstrapped"] is True
        assert len(swarm.db.get_facts(task_id="pw-ooda-9")) >= 1
        assert len(swarm.db.list_intents(status="DONE", task_id="pw-ooda-9")) >= 1
    finally:
        swarm.close()


# 10. Explore anomaly -> triage_debugger_agent (FACT) -> cascade_and_publish_agent (INTENT + KG)
def test_t3_10_explore_triage_fact_plus_cascade_intent_and_kg(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, use_fusion=False, monkeypatch=monkeypatch)
    try:
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-PW-10",
            target_engine=f"127.0.0.1:{loopback_lab_server.port}",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="desync marker reflected",
            expected_behavior="clean",
            raw_probe=b"GET / HTTP/1.1\r\n\r\n",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\nterminator_marker reflected",
        )
        vuln = ReproducibleVulnerability(
            vuln_id="VULN-PW-10",
            anomaly_id="ANOM-PW-10",
            impact=ImpactClass.DESYNCHRONIZATION,
            minimized_probe=b"GET / HTTP/1.1\r\n\r\n",
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=1,
            provenance_chain="DeltaDebugger",
        )
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: False)
        monkeypatch.setattr(swarm.debugger, "minimize_and_reproduce", lambda a, max_verification_trials=3: vuln)
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (True, "ok"))
        monkeypatch.setattr(swarm.classifier, "classify_novelty", lambda v: (False, None))
        monkeypatch.setattr(
            swarm.cascade_engine,
            "cascade_from_finding",
            lambda info: {
                "hypothesis": "Cascade follow-up",
                "suggested_probes": ["POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"],
            },
        )

        t_out = swarm.triage_debugger_agent({"rfc_num": "9112", "current_anomaly": anom, "task_id": "pw-10", "blackboard_domain": "http11_framing"})
        assert t_out["current_vuln"] is not None
        assert len(swarm.db.get_facts(task_id="pw-10")) >= 1

        c_out = swarm.cascade_and_publish_agent(
            {
                "rfc_num": "9112",
                "current_anomaly": anom,
                "current_vuln": vuln,
                "current_fragment": "Transfer-Encoding framing",
                "task_id": "pw-10",
            }
        )
        assert c_out["cascade_results"] is not None
        assert len(swarm.db.list_intents(task_id="pw-10")) >= 1
        assert "VULN-PW-10" in swarm.knowledge_graph.nodes
    finally:
        swarm.close()


# 11. Harness² RFC9112 lesson HINT -> same-domain RFC7230 absorption
def test_t3_11_harness2_rfc9112_hint_steers_rfc7230_generation(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    seen: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            seen.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, use_fusion=False, monkeypatch=monkeypatch)
    try:
        swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 5,
                "enable_harness2": True,
                "harness2_runs_dir": str(isolated_swarm_workspace.harness2_runs_dir),
                "task_id": "pw-h2-rfc",
                "history": [],
            }
        )
        promoted = [
            h
            for h in swarm.db.get_active_hints(task_id="pw-h2-rfc", domain="http11_framing")
            if h["source_agent"] == "dream_rsi_agent"
        ]
        assert len(promoted) >= 1
        swarm.llm_generator_agent(
            {
                "rfc_num": "7230",
                "fragments": [("RFC 7230 Content-Length framing rule.", "content-length", 2.0)],
                "blackboard_domain": "http11_framing",
                "task_id": "pw-h2-rfc",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert promoted[0]["content"][:30] in seen[0]
    finally:
        swarm.close()


# 12. Harness² domain isolation + global CLI hint combination
def test_t3_12_harness2_domain_isolation_with_global_cli_hint(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    seen: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            seen.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, use_fusion=False, monkeypatch=monkeypatch)
    try:
        swarm.db.add_hint("GLOBAL_APPLIES_TO_ALL_RFCS", domain="global", priority=20.0)
        swarm.db.add_hint("HTTP11_SCOPED_LESSON", domain="http11_framing", source_agent="dream_rsi_agent", priority=50.0)
        swarm.llm_generator_agent(
            {
                "rfc_num": "9113",
                "fragments": [("HTTP/2 pseudo-header validation MUST be strict.", "header", 2.0)],
                "blackboard_domain": "h2_translation",
                "task_id": "pw-iso-glob",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert "GLOBAL_APPLIES_TO_ALL_RFCS" in seen[0]
        assert "HTTP11_SCOPED_LESSON" not in seen[0]
    finally:
        swarm.close()


# 13. triage_debugger_agent FACT + DualGraphAttackEngine.reason_from_blackboard_facts + idempotency
def test_t3_13_triage_fact_plus_dual_graph_multihop_and_idempotency(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, use_fusion=False, monkeypatch=monkeypatch)
    try:
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-PW-13",
            target_engine=f"127.0.0.1:{loopback_lab_server.port}",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="CL.0 desync",
            expected_behavior="clean",
            raw_probe=b"GET / HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\nmarker",
        )
        vuln = ReproducibleVulnerability(
            vuln_id="VULN-PW-13",
            anomaly_id="ANOM-PW-13",
            impact=ImpactClass.DESYNCHRONIZATION,
            minimized_probe=b"GET / HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD",
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=1,
            provenance_chain="DeltaDebugger",
        )
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: False)
        monkeypatch.setattr(swarm.debugger, "minimize_and_reproduce", lambda a, max_verification_trials=3: vuln)
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (True, "ok"))
        monkeypatch.setattr(swarm.classifier, "classify_novelty", lambda v: (False, None))

        swarm.triage_debugger_agent({"rfc_num": "9112", "current_anomaly": anom, "task_id": "pw-13", "blackboard_domain": "http11_framing"})
        swarm.db.add_fact(
            "OIDC auth boundary bypass on /internal/service",
            task_id="pw-13",
            domain="http_semantics_intermediaries",
            source_agent="triage_debugger_agent",
            payload={"rule_id": "auth-pw13", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
        )

        eng = DualGraphAttackEngine(db=swarm.db, reports_dir=isolated_swarm_workspace.reports_dir / "pw13", task_id="pw-13")
        eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_lab_server.port, endpoints=["/", "/internal/service"])
        r1 = eng.reason_from_blackboard_facts(db=swarm.db, task_id="pw-13", round_num=1)
        assert len(r1) >= 1
        r2 = eng.reason_from_blackboard_facts(db=swarm.db, task_id="pw-13", round_num=2)
        assert r2 == []
    finally:
        swarm.close()


# 14. DualGraph multi-hop INTENT -> claim_next_intent -> Explore -> complete_intent("DONE")
def test_t3_14_dual_graph_intent_claimed_and_completed_by_explore(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, use_fusion=False, monkeypatch=monkeypatch)
    seq_calls: List[bytes] = []
    orig_seq = swarm.sequence_engine.run_pipelined_canary_sequence

    def _safe_seq_wrapper(host: str, port: int, candidate_probe: bytes, rule_id: Any = None, use_tls: bool = False) -> Any:
        effective_probe = (
            candidate_probe
            if candidate_probe and candidate_probe.strip()
            else b"GET /internal/service HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        seq_calls.append(effective_probe)
        return orig_seq(host, port, effective_probe, rule_id=rule_id, use_tls=use_tls)

    monkeypatch.setattr(swarm.sequence_engine, "run_pipelined_canary_sequence", _safe_seq_wrapper)
    try:
        swarm.db.add_fact(
            "CL.0 desync on /",
            task_id="pw-14",
            payload={
                "rule_id": "d14",
                "cwe": "CWE-444",
                "capability_class": "DESYNC",
                "endpoint": "/",
                "target_route": "/internal/service",
                "raw_probe": "GET /internal/service HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            },
        )
        swarm.db.add_fact(
            "Auth boundary bypass on /internal/service",
            task_id="pw-14",
            payload={
                "rule_id": "a14",
                "cwe": "CWE-287",
                "capability_class": "AUTH_BOUNDARY",
                "endpoint": "/internal/service",
                "target_route": "/internal/service",
                "raw_probe": "GET /internal/service HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            },
        )
        eng = DualGraphAttackEngine(db=swarm.db, reports_dir=isolated_swarm_workspace.reports_dir / "pw14", task_id="pw-14")
        eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_lab_server.port, endpoints=["/", "/internal/service"])
        created = eng.reason_from_blackboard_facts(db=swarm.db, task_id="pw-14", round_num=1)
        assert len(created) >= 1

        # Execute explore loop until created multihop intent is DONE
        for _ in range(len(created) + 1):
            if not swarm.db.list_intents(status="PENDING", task_id="pw-14"):
                break
            swarm.execution_oracle_agent({"task_id": "pw-14", "blackboard_bootstrapped": True})

        assert len(seq_calls) >= 1
        done_ids = {i["node_id"] for i in swarm.db.list_intents(status="DONE", task_id="pw-14")}
        assert set(created).issubset(done_ids)
    finally:
        swarm.close()


# 15. swarm_dispatch.yaml (local) + --all + per_target_isolation across 2 loopback servers
def test_t3_15_swarm_dispatch_local_plus_all_per_target_isolation(
    tmp_path: Path,
    loopback_http_server: Any,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rfc_hunt_swarm import main_swarm

    ws_root = tmp_path / "ws_pw15"
    cfg = tmp_path / "dispatch15.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workers": {"backend": "all", "concurrency": 1, "use_fusion": False},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {"name": "t_http", "host": "127.0.0.1", "port": loopback_http_server.port, "tls": False, "authorized": True, "modes": ["all"], "rfcs": ["9112"]},
                    {"name": "t_lab", "host": "127.0.0.1", "port": loopback_lab_server.port, "tls": False, "authorized": True, "modes": ["all"], "rfcs": ["7230"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    main_swarm(["--dispatch", str(cfg)])
    db_files = sorted(ws_root.rglob("*.db"))
    assert len(db_files) == 2
    assert db_files[0].resolve() != db_files[1].resolve()
    assert db_files[0].parent.resolve() != db_files[1].parent.resolve()
    for dbf in db_files:
        assert dbf.resolve().is_relative_to(ws_root.resolve())
        db = Database(str(dbf), secret_key_path=str(tmp_path / "keys" / "secret.key"))
        try:
            assert db.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blackboard_nodes'").fetchone() is not None
        finally:
            db.close()


# 16. swarm_dispatch.yaml (docker) + --scanner-isolation docker + subprocess_recorder
def test_t3_16_swarm_dispatch_docker_plus_scanner_isolation_subprocess_recorder(
    tmp_path: Path,
    loopback_http_server: Any,
    subprocess_recorder: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.mantis_integrator as mi
    from rfc_hunt_swarm import main_swarm

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_http_server.url}/health", "status_code": 200}) + "\n",
    )
    recorded_kwargs: List[Dict[str, Any]] = []
    orig_unified = mi.run_unified_all_scans

    def _spy_unified(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        recorded_kwargs.append(dict(kwargs))
        call_kw = dict(kwargs)
        call_kw["enable_external_scanners"] = True
        call_kw["httpx_scan"] = True
        call_kw["katana_scan"] = False
        call_kw["nuclei_scan"] = False
        return orig_unified(*args, **call_kw)

    monkeypatch.setattr(mi, "run_unified_all_scans", _spy_unified)
    ws_root = tmp_path / "ws_docker16"
    cfg = tmp_path / "docker_pw16.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {
                    "execution": "docker",
                    "docker_image": "projectdiscovery/httpx:latest",
                    "docker_network": "bridge",
                    "offline": True,
                },
                "workers": {"backend": "all", "concurrency": 1, "use_fusion": False},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {"name": "docker_t", "host": "127.0.0.1", "port": loopback_http_server.port, "tls": False, "authorized": True, "modes": ["all"], "rfcs": ["9112"]}
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    main_swarm(["--dispatch", str(cfg)])
    assert len(recorded_kwargs) == 1
    assert recorded_kwargs[0].get("scanner_isolation") == "docker"
    assert recorded_kwargs[0].get("docker_network") == "bridge"
    assert recorded_kwargs[0].get("docker_image") == "projectdiscovery/httpx:latest"

    docker_calls = [c for c in subprocess_recorder.calls if Path(c["argv"][0]).name.lower().startswith("docker")]
    assert len(docker_calls) >= 1
    for dc in docker_calls:
        assert dc["shell"] is False
        assert "run" in dc["argv"] and "--rm" in dc["argv"]
        assert "--network=host" not in dc["argv"]


# 17. swarm_dispatch.yaml + crash-resume in per-target terminator.db
def test_t3_17_swarm_dispatch_plus_crash_resume_in_per_target_db(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import main_swarm

    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True}],
    )

    ws_root = isolated_swarm_workspace.root / "ws_res17"
    cfg = isolated_swarm_workspace.root / "resume_dispatch.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workers": {"backend": "swarm", "concurrency": 1, "use_fusion": False},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {"name": "res_target", "host": "127.0.0.1", "port": loopback_lab_server.port, "tls": False, "authorized": True, "modes": ["single"], "rfcs": ["9112"]}
                ],
            }
        ),
        encoding="utf-8",
    )

    # Initial dispatch creates per-target isolated DB
    main_swarm(["--dispatch", str(cfg)])
    db_files = list(ws_root.rglob("*.db"))
    assert len(db_files) == 1
    target_db_path = db_files[0]

    # Seed pre-crash FACT + stale CLAIMED INTENT in the isolated DB
    db1 = Database(str(target_db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
    try:
        fact_id = db1.add_fact("pre-crash dispatch fact", task_id="default", domain="http11_framing")
        stale_id = db1.queue_intent(
            "GET /resumed-dispatch HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            priority=500.0,
            task_id="default",
            payload={"raw_request": "GET /resumed-dispatch HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", "is_clean": True},
        )
        claimed = db1.claim_next_intent("dead-pid", task_id="default")
        assert claimed is not None and claimed["node_id"] == stale_id
    finally:
        db1.close()

    # Resume by re-invoking --dispatch against the same workspace.root
    main_swarm(["--dispatch", str(cfg)])
    assert len(list(ws_root.rglob("*.db"))) == 1
    db2 = Database(str(target_db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
    try:
        assert any(f["node_id"] == fact_id for f in db2.get_facts(task_id="default"))
        assert db2.list_intents(status="CLAIMED") == []
        stale_rows = [r for r in db2.get_blackboard_nodes(node_type="INTENT") if r["node_id"] == stale_id]
        assert len(stale_rows) == 1
        assert stale_rows[0]["status"] in ("PENDING", "DONE")
    finally:
        db2.close()


# 18. MCP hint + --all + DualGraph.reason_from_blackboard_facts + zero GUI/TestLabServer mutation
def test_t3_18_mcp_hint_plus_all_plus_dual_graph_plus_zero_gui_mutation(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_http_server: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rfc_hunt_swarm import main_swarm

    lab_bytes_before = (REPO_ROOT / "test_lab_server.py").read_bytes()
    with TerminatorMCPServer(db_path=str(isolated_swarm_workspace.db_path)) as srv:
        srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "inject_blackboard_hint",
                    "arguments": {"hint_text": "MCP_ALL_DG_HINT", "domain": "http11_framing", "task_id": "pw-18"},
                },
            }
        )

    mini_repo = isolated_swarm_workspace.root / "repo_18"
    mini_repo.mkdir()
    (mini_repo / "app.py").write_text("def f(): return True\n", encoding="utf-8")

    main_swarm(
        [
            "--all",
            "--repo",
            str(mini_repo),
            "--host",
            "127.0.0.1",
            "--port",
            str(loopback_http_server.port),
            "--authorized",
            "--no-rea",
            "--db",
            str(isolated_swarm_workspace.db_path),
            "--output-dir",
            str(isolated_swarm_workspace.reports_dir / "pw18"),
            "--json",
        ]
    )
    _ = json.loads(capsys.readouterr().out)

    db = Database(str(isolated_swarm_workspace.db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
    try:
        db.add_fact("Desync", task_id="pw-18", payload={"rule_id": "d18", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"})
        db.add_fact("Auth", task_id="pw-18", payload={"rule_id": "a18", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"})
        eng = DualGraphAttackEngine(db=db, reports_dir=isolated_swarm_workspace.reports_dir / "dg18", task_id="pw-18")
        eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_http_server.port, endpoints=["/", "/internal/service"])
        created = eng.reason_from_blackboard_facts(db=db, task_id="pw-18", round_num=1)
        assert len(created) >= 1
        assert len(db.get_active_hints(task_id="pw-18", domain="http11_framing")) == 1
    finally:
        db.close()

    assert (REPO_ROOT / "test_lab_server.py").read_bytes() == lab_bytes_before
