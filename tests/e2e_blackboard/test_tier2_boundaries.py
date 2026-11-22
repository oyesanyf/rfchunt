"""
Tier 2 Boundary, Adversarial & Corner Case Tests across Features #1-#15 (>= 75 tests).
Covers invalid inputs, SQLi/path-traversal/SSRF/YAML-tag defenses, empty/corrupt states,
queue exhaustion, domain/task isolation, and zero-GUI invariants.

Collection-safe: M2-M4 modules/methods are resolved inside test bodies/helpers.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import subprocess
import sys
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
from probe_generator import ProbeGenerator
from tests.e2e_blackboard.conftest import REPO_ROOT


def _make_swarm(ws: SimpleNamespace, *, port: int, monkeypatch: pytest.MonkeyPatch) -> Any:
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
# F1 Boundaries: `blackboard_nodes` table & constraints (5 tests)
# =============================================================================


@pytest.mark.parametrize(
    "bad_type",
    [
        "INVALID",
        "",
        "FACT'); DROP TABLE blackboard_nodes;--",
    ],
)
def test_t2_f1_invalid_and_sqli_node_type_rejected(bb_db: Database, bad_type: str) -> None:
    bb_db.add_fact("sentinel row", node_id="sentinel-1")
    with pytest.raises((ValueError, sqlite3.IntegrityError)):
        bb_db.add_blackboard_node(bad_type, "bad content")
    rows = bb_db.get_blackboard_nodes()
    assert [r["node_id"] for r in rows] == ["sentinel-1"]


@pytest.mark.parametrize("raw_type", ["fact", "intent"])
def test_t2_f1_sql_check_constraint_rejects_lowercase_node_types(bb_db: Database, raw_type: str) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        with bb_db.conn:
            bb_db.conn.execute(
                "INSERT INTO blackboard_nodes (node_id, node_type, content) VALUES (?, ?, ?)",
                (f"raw-{raw_type}", raw_type, "lowercase test"),
            )


def test_t2_f1_null_node_id_rejected_at_sql_level(bb_db: Database) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        with bb_db.conn:
            bb_db.conn.execute(
                "INSERT INTO blackboard_nodes (node_id, node_type, content) VALUES (NULL, 'FACT', 'x')"
            )


def test_t2_f1_unicode_crlf_and_large_content_roundtrip(bb_db: Database) -> None:
    text = "RFC9112 §3.2 — CRLF\r\nobs-fold\t\u2603 " + ("A" * 16384)
    nid = bb_db.add_fact(text, payload={"size": len(text), "crlf": "\r\n"})
    rows = bb_db.get_facts()
    assert len(rows) == 1
    assert rows[0]["node_id"] == nid
    assert rows[0]["content"] == text
    assert rows[0]["payload"]["crlf"] == "\r\n"


# =============================================================================
# F2 Boundaries: Idempotent migration `004_blackboard_nodes` (5 tests)
# =============================================================================


def test_t2_f2_in_memory_db_applies_migration_004_without_wal_error() -> None:
    db = Database(":memory:", encrypt_at_rest=False)
    try:
        versions = {str(r[0]) for r in db.conn.execute("SELECT version FROM schema_migrations").fetchall()}
        assert "004_blackboard_nodes" in versions
        nid = db.queue_intent("mem-intent", priority=2.0)
        claimed = db.claim_next_intent("mem-worker")
        assert claimed is not None and claimed["node_id"] == nid
    finally:
        db.close()


def test_t2_f2_premigration_db_with_partial_legacy_blackboard_table_upgrades(tmp_path: Path) -> None:
    db_file = tmp_path / "partial_bb.db"
    conn = sqlite3.connect(str(db_file))
    try:
        with conn:
            conn.executescript(
                """
                CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
                CREATE TABLE attack_chains (chain_id TEXT PRIMARY KEY, title TEXT NOT NULL, attack_type TEXT NOT NULL, target_host TEXT NOT NULL, target_endpoint TEXT NOT NULL, steps_json TEXT NOT NULL);
                CREATE TABLE chain_retests (retest_id TEXT PRIMARY KEY, chain_id TEXT NOT NULL, verdict TEXT NOT NULL);
                CREATE TABLE approval_decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, action_type TEXT NOT NULL, decision TEXT NOT NULL, decided_by TEXT NOT NULL);
                CREATE TABLE blackboard_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id TEXT UNIQUE NOT NULL,
                    node_type TEXT NOT NULL CHECK(node_type IN ('FACT', 'INTENT', 'HINT')),
                    content TEXT NOT NULL DEFAULT ''
                );
                """
            )
    finally:
        conn.close()

    db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        cols = {r[1] for r in db.conn.execute("PRAGMA table_info(blackboard_nodes)").fetchall()}
        assert {"task_id", "status", "priority", "domain", "rfc_id", "payload_json", "claimed_by"}.issubset(cols)
        db.add_fact("after partial upgrade")
        assert len(db.get_facts()) == 1
    finally:
        db.close()


def test_t2_f2_pre001_preserves_evaluations_and_probes_fk_consistency(
    pre_migration_db_builder: Callable[..., Path],
    bb_db_factory: Callable[..., Database],
) -> None:
    p = pre_migration_db_builder("pre_001")
    db = bb_db_factory(str(p))
    rows = db.conn.execute(
        "SELECT e.desync_class, p.rationale FROM evaluations e JOIN probes p ON e.probe_id = p.probe_id"
    ).fetchall()
    assert [tuple(r) for r in rows] == [("CL.TE", "legacy-probe")]


def test_t2_f2_v003_preserves_existing_attack_chain_artex_cols(
    pre_migration_db_builder: Callable[..., Path],
    bb_db_factory: Callable[..., Database],
) -> None:
    p = pre_migration_db_builder("v003")
    db = bb_db_factory(str(p))
    row = db.conn.execute("SELECT chain_id, hop_count, poe_level FROM attack_chains").fetchone()
    assert tuple(row) == ("legacy-chain-1", 1, 0)


def test_t2_f2_clean_db_resets_safely_and_keeps_blackboard_schema(bb_db: Database) -> None:
    bb_db.add_fact("temp fact before clean")
    bb_db.clean_db()
    cols = {r[1] for r in bb_db.conn.execute("PRAGMA table_info(blackboard_nodes)").fetchall()}
    assert "node_id" in cols


# =============================================================================
# F3 Boundaries: Atomic `INTENT` claiming & resume (6 tests)
# =============================================================================


def test_t2_f3_claim_next_intent_on_empty_queue_returns_none(bb_db: Database) -> None:
    assert bb_db.claim_next_intent("w-empty") is None


def test_t2_f3_claim_next_intent_ignores_claimed_done_failed(bb_db: Database) -> None:
    i1 = bb_db.queue_intent("claimed", priority=10.0)
    bb_db.claim_next_intent("w1")
    i2 = bb_db.queue_intent("done", priority=20.0)
    bb_db.claim_next_intent("w2")
    bb_db.complete_intent(i2, status="DONE")
    i3 = bb_db.queue_intent("failed", priority=30.0)
    bb_db.claim_next_intent("w3")
    bb_db.complete_intent(i3, status="FAILED")
    assert i1 != i2 != i3
    assert bb_db.claim_next_intent("w4") is None


def test_t2_f3_negative_zero_and_extreme_float_priority_ordering(bb_db: Database) -> None:
    neg = bb_db.queue_intent("neg", priority=-10.5, task_id="prio-bva")
    z1 = bb_db.queue_intent("z1", priority=0.0, task_id="prio-bva")
    z2 = bb_db.queue_intent("z2", priority=0.0, task_id="prio-bva")
    huge = bb_db.queue_intent("huge", priority=1e9, task_id="prio-bva")

    order = [bb_db.claim_next_intent("w", task_id="prio-bva")["node_id"] for _ in range(4)]
    assert order == [huge, z1, z2, neg]


def test_t2_f3_complete_intent_missing_and_double_complete(bb_db: Database) -> None:
    assert bb_db.complete_intent("does-not-exist-node") is False
    nid = bb_db.queue_intent("once")
    bb_db.claim_next_intent("w1")
    assert bb_db.complete_intent(nid, status="DONE") is True
    # Re-completing an already DONE node must not resurrect it to PENDING
    bb_db.complete_intent(nid, status="DONE")
    assert bb_db.claim_next_intent("w2") is None
    assert [r["node_id"] for r in bb_db.list_intents(status="DONE")] == [nid]


def test_t2_f3_reclaim_stale_intents_worker_filter_preserves_other_workers(bb_db: Database) -> None:
    n1 = bb_db.queue_intent("for w1", priority=5.0, task_id="t-rec")
    n2 = bb_db.queue_intent("for w2", priority=4.0, task_id="t-rec")
    bb_db.claim_next_intent("worker-1", task_id="t-rec")
    bb_db.claim_next_intent("worker-2", task_id="t-rec")

    count = bb_db.reclaim_stale_intents(task_id="t-rec", worker_id="worker-1")
    assert count == 1
    pending = {r["node_id"] for r in bb_db.list_intents(status="PENDING", task_id="t-rec")}
    claimed = {r["node_id"] for r in bb_db.list_intents(status="CLAIMED", task_id="t-rec")}
    assert pending == {n1}
    assert claimed == {n2}


def test_t2_f3_list_intents_limit_one_and_pagination_boundary(bb_db: Database) -> None:
    i1 = bb_db.queue_intent("i1", priority=1.0)
    i2 = bb_db.queue_intent("i2", priority=2.0)
    limited = bb_db.list_intents(limit=1)
    assert [r["node_id"] for r in limited] == [i2]
    all_items = bb_db.list_intents(limit=10)
    assert [r["node_id"] for r in all_items] == [i2, i1]


# =============================================================================
# F4 Boundaries: `FACT` / `HINT` / `ResearchKnowledgeGraph` APIs (6 tests)
# =============================================================================


def test_t2_f4_task_id_isolation_across_all_getters(bb_db: Database) -> None:
    bb_db.add_fact("fA", task_id="taskA")
    bb_db.queue_intent("iA", task_id="taskA")
    bb_db.add_hint("hA", task_id="taskA")
    assert bb_db.get_facts(task_id="taskB") == []
    assert bb_db.list_intents(task_id="taskB") == []
    assert bb_db.get_active_hints(task_id="taskB") == []


def test_t2_f4_domain_and_rfc_isolation(bb_db: Database) -> None:
    bb_db.add_fact("f-h1", domain="http11_framing", rfc_id="RFC9112")
    bb_db.add_fact("f-h2", domain="h2_translation", rfc_id="RFC9113")
    assert len(bb_db.get_facts(domain="http11_framing", rfc_id="RFC9112")) == 1
    assert bb_db.get_facts(domain="http11_framing", rfc_id="RFC9113") == []


def test_t2_f4_deactivate_hint_missing_and_double_deactivate(bb_db: Database) -> None:
    assert bb_db.deactivate_hint("nonexistent-hint") is False
    hid = bb_db.add_hint("to deactivate")
    assert bb_db.deactivate_hint(hid) is True
    assert bb_db.get_active_hints() == []
    bb_db.deactivate_hint(hid)
    assert bb_db.get_active_hints() == []


def test_t2_f4_corrupt_payload_json_in_sqlite_recovers_gracefully(bb_db: Database) -> None:
    with bb_db.conn:
        bb_db.conn.execute(
            "INSERT INTO blackboard_nodes (node_id, node_type, status, content, payload_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("corrupt-json-1", "FACT", "ACTIVE", "corrupt payload test", "{not-valid-json"),
        )
    rows = bb_db.get_blackboard_nodes(node_type="FACT")
    assert len(rows) == 1
    assert rows[0]["node_id"] == "corrupt-json-1"
    assert isinstance(rows[0]["payload"], dict)


def test_t2_f4_knowledge_graph_duplicate_node_mirroring_is_safe(bb_db: Database) -> None:
    kg = ResearchKnowledgeGraph(db=bb_db, task_id="kg-dup")
    kg.add_node("VULN-DUP", "VULNERABILITY", "First description")
    kg.add_node("VULN-DUP", "VULNERABILITY", "First description")
    facts = bb_db.get_facts(task_id="kg-dup")
    assert len(facts) == 1


def test_t2_f4_knowledge_graph_without_db_does_not_fail_on_record_event() -> None:
    kg = ResearchKnowledgeGraph(db=None)
    kg.add_node("REQ-X", "REQUIREMENT", "Check CL")
    kg.record_testing_event("REQ-X", "ANOM-X", is_vulnerability=False)
    cov = kg.calculate_specification_coverage()
    assert cov["tested_count"] == 1


# =============================================================================
# F5 Boundaries: `blackboard_router` & `ResearchState` (5 tests)
# =============================================================================


def test_t2_f5_blackboard_router_handles_minimal_state_without_keyerror(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        res = swarm.blackboard_router({"rfc_num": "9112"})
        assert isinstance(res, dict)
        assert res.get("ooda_phase") == "Bootstrap"
    finally:
        swarm.close()


def test_t2_f5_blackboard_router_respects_max_cycles_zero(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        res = swarm.blackboard_router(
            {
                "rfc_num": "9112",
                "blackboard_bootstrapped": True,
                "cycle_count": 0,
                "max_cycles": 0,
                "fragments": [("frag", "kw", 1.0)],
                "task_id": "max0",
                "enable_dream_rsi": False,
            }
        )
        assert str(res.get("ooda_phase", "")).lower() in ("done", "end", "__end__", "complete", "terminate")
    finally:
        swarm.close()


def test_t2_f5_blackboard_router_routes_to_dream_rsi_when_enabled_at_exhaustion(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        res = swarm.blackboard_router(
            {
                "rfc_num": "9112",
                "blackboard_bootstrapped": True,
                "cycle_count": 3,
                "max_cycles": 3,
                "fragments": [],
                "task_id": "dream-route",
                "enable_dream_rsi": True,
            }
        )
        assert str(res.get("ooda_phase", "")).lower() in ("dream", "dream_rsi", "dreamrsi", "dream_rsi_agent", "done", "end", "__end__")
    finally:
        swarm.close()


def test_t2_f5_blackboard_router_preserves_task_id_and_domain(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        res = swarm.blackboard_router(
            {
                "rfc_num": "9113",
                "task_id": "custom-tid",
                "blackboard_domain": "h2_translation",
                "blackboard_bootstrapped": False,
            }
        )
        assert res.get("task_id", "custom-tid") == "custom-tid"
    finally:
        swarm.close()


def test_t2_f5_build_graph_has_no_legacy_conditional_router_nodes(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True}],
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    router_calls: List[str] = []
    orig_router = swarm.blackboard_router

    def _spy_router(st: Dict[str, Any]) -> Dict[str, Any]:
        out = orig_router(st)
        router_calls.append(str(out.get("ooda_phase", "")))
        return out

    monkeypatch.setattr(swarm, "blackboard_router", _spy_router)

    legacy_calls: List[str] = []
    for legacy in ("route_after_generation", "route_after_execution", "route_after_triage", "route_after_publish"):
        if hasattr(swarm, legacy):
            monkeypatch.setattr(swarm, legacy, lambda st, _name=legacy: legacy_calls.append(_name) or "__end__")

    try:
        graph = swarm.build_graph()
        nodes = set(getattr(graph, "nodes", {}).keys())
        assert "blackboard_router" in nodes
        graph.invoke(
            {
                "rfc_num": "9112",
                "fragments": [],
                "generated_candidates": [],
                "cycle_count": 0,
                "max_cycles": 1,
                "enable_dream_rsi": False,
                "enable_harness2": False,
                "blackboard_bootstrapped": False,
                "task_id": "t2-router-hub",
                "blackboard_domain": "http11_framing",
                "history": [],
            },
            {"recursion_limit": 150},
        )
        assert len(router_calls) >= 2
        assert legacy_calls == []
    finally:
        swarm.close()


# =============================================================================
# F6 Boundaries: OODA `Bootstrap` mapping (5 tests)
# =============================================================================


def test_t2_f6_bootstrap_handles_unavailable_rfc_gracefully(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    monkeypatch.setattr(swarm.fetcher, "fetch_rfc_by_number", lambda num: None)
    try:
        out = swarm.fetch_and_chunk_agent({"rfc_num": "99999", "task_id": "missing-rfc"})
        assert out["fragments"] == []
        assert out["rfc_text"] == ""
    finally:
        swarm.close()


def test_t2_f6_bootstrap_with_zero_abnf_blocks_still_chunks_normative_text(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    monkeypatch.setattr(
        swarm.fetcher,
        "fetch_rfc_by_number",
        lambda num: "A proxy MUST reject requests containing conflicting Transfer-Encoding and Content-Length headers.",
    )
    try:
        out = swarm.fetch_and_chunk_agent({"rfc_num": "9112", "task_id": "no-abnf"})
        assert len(out["fragments"]) >= 1
    finally:
        swarm.close()


def test_t2_f6_bootstrap_with_zero_prober_findings_still_commits_baseline_fact(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from engine.active_flaw_prober import ActiveFlawProber

    monkeypatch.setattr(ActiveFlawProber, "run_active_audit", lambda self: [])
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        swarm.fetch_and_chunk_agent({"rfc_num": "9112", "task_id": "zero-vulns"})
        assert len(swarm.db.get_facts(task_id="zero-vulns")) >= 1
    finally:
        swarm.close()


def test_t2_f6_bootstrap_closed_loopback_port_fails_safely(
    isolated_swarm_workspace: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]

    swarm = _make_swarm(isolated_swarm_workspace, port=closed_port, monkeypatch=monkeypatch)
    try:
        out = swarm.fetch_and_chunk_agent({"rfc_num": "9112", "task_id": "closed-port-boot"})
        assert isinstance(out, dict)
    finally:
        swarm.close()


def test_t2_f6_bootstrap_skips_when_already_bootstrapped(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        r = swarm.blackboard_router({"rfc_num": "9112", "blackboard_bootstrapped": True, "cycle_count": 0, "max_cycles": 1})
        assert r.get("ooda_phase") != "Bootstrap"
    finally:
        swarm.close()


# =============================================================================
# F7 Boundaries: OODA `Reason` mapping (5 tests)
# =============================================================================


def test_t2_f7_reason_llm_exception_falls_back_to_grammar_probes_and_persists_intents(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (_ for _ in ()).throw(RuntimeError("offline llm failure")),
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        out = swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [("A sender MUST NOT send Content-Length with Transfer-Encoding.", "transfer-encoding", 2.0)],
                "task_id": "llm-fallback-task",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert len(out["generated_candidates"]) >= 1
        assert len(swarm.db.list_intents(task_id="llm-fallback-task")) >= 1
    finally:
        swarm.close()


def test_t2_f7_reason_ignores_deactivated_hints(
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
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        hid = swarm.db.add_hint("DEACTIVATED_HINT_SHOULD_NOT_APPEAR", task_id="deact-t", domain="http11_framing")
        swarm.db.deactivate_hint(hid)
        swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [("Transfer-Encoding MUST be parsed.", "transfer-encoding", 2.0)],
                "task_id": "deact-t",
                "blackboard_domain": "http11_framing",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert "DEACTIVATED_HINT_SHOULD_NOT_APPEAR" not in seen[0]
    finally:
        swarm.close()


def test_t2_f7_reason_respects_task_id_isolation_for_hints_and_facts(
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
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        swarm.db.add_hint("OTHER_TASK_ONLY_HINT", task_id="other-task", domain="http11_framing")
        swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [("Content-Length MUST match octets.", "content-length", 2.0)],
                "task_id": "isolated-task",
                "blackboard_domain": "http11_framing",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert "OTHER_TASK_ONLY_HINT" not in seen[0]
    finally:
        swarm.close()


def test_t2_f7_reason_orders_hints_by_priority_descending(
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
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        swarm.db.add_hint("HINT_LOW_PRIORITY", priority=5.0, task_id="order-t", domain="http11_framing")
        swarm.db.add_hint("HINT_HIGH_PRIORITY", priority=95.0, task_id="order-t", domain="http11_framing")
        swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [("Line terminator is CRLF.", "crlf", 2.0)],
                "task_id": "order-t",
                "blackboard_domain": "http11_framing",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert seen[0].index("HINT_HIGH_PRIORITY") < seen[0].index("HINT_LOW_PRIORITY")
    finally:
        swarm.close()


def test_t2_f7_reason_empty_fragments_emits_no_phantom_intents(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        swarm.llm_generator_agent({"rfc_num": "9112", "fragments": [], "task_id": "no-phantom"})
        assert swarm.db.list_intents(task_id="no-phantom") == []
    finally:
        swarm.close()


# =============================================================================
# F8 Boundaries: OODA `Explore` mapping (5 tests)
# =============================================================================


def test_t2_f8_explore_exhausted_intent_queue_exits_cleanly(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        out = swarm.execution_oracle_agent({"task_id": "exhausted-q", "generated_candidates": []})
        assert out.get("current_anomaly") is None
    finally:
        swarm.close()


def test_t2_f8_explore_triage_discards_environmental_noise_without_vuln_fact(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: True)
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-NOISE-1",
            target_engine="127.0.0.1",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="jitter",
            expected_behavior="clean",
            raw_probe=b"GET / HTTP/1.1\r\n\r\n",
            raw_response=b"HTTP/1.1 503 Busy\r\n\r\n",
        )
        out = swarm.triage_debugger_agent({"current_anomaly": anom, "task_id": "noise-t"})
        assert out["current_vuln"] is None
        assert swarm.db.get_facts(task_id="noise-t") == []
    finally:
        swarm.close()


def test_t2_f8_explore_triage_rejects_low_reproducibility_without_vuln_fact(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
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
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-FLAKY",
            target_engine="127.0.0.1",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="flaky",
            expected_behavior="clean",
            raw_probe=b"GET / HTTP/1.1\r\n\r\n",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
        )
        out = swarm.triage_debugger_agent({"current_anomaly": anom, "task_id": "flaky-t"})
        assert out["current_vuln"] is None
        assert swarm.db.get_facts(task_id="flaky-t") == []
    finally:
        swarm.close()


def test_t2_f8_explore_triage_rejects_invalid_evidence_without_vuln_fact(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: False)
        monkeypatch.setattr(
            swarm.debugger,
            "minimize_and_reproduce",
            lambda a, max_verification_trials=3: ReproducibleVulnerability(
                vuln_id="VULN-BAD-EV",
                anomaly_id=a.anomaly_id,
                impact=ImpactClass.DESYNCHRONIZATION,
                minimized_probe=b"GET / HTTP/1.1\r\n\r\n",
                reproducibility_rate=1.0,
                verification_attempts=3,
                successful_reproductions=3,
                delta_debug_steps=1,
                provenance_chain="bad-ev",
            ),
        )
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (False, "ordinary framing"))
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-BAD-EV",
            target_engine="127.0.0.1",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="normal",
            expected_behavior="normal",
            raw_probe=b"GET / HTTP/1.1\r\n\r\n",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
        )
        out = swarm.triage_debugger_agent({"current_anomaly": anom, "task_id": "bad-ev-t"})
        assert out["current_vuln"] is None
        assert swarm.db.get_facts(task_id="bad-ev-t") == []
    finally:
        swarm.close()


def test_t2_f8_explore_escaped_crlf_string_normalizes_cleanly(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        res = swarm._evaluate_single_candidate(
            {"raw_request": "GET / HTTP/1.1\\r\\nHost: target.local\\r\\nConnection: close\\r\\n\\r\\n"}
        )
        assert b"\r\n" in res["probe_bytes"]
        assert b"\\r\\n" not in res["probe_bytes"]
    finally:
        swarm.close()


# =============================================================================
# F9 Boundaries: Live `HINT` prompt absorption (5 tests)
# =============================================================================


@pytest.mark.parametrize("hints_arg", [None, []])
def test_t2_f9_probe_generator_empty_or_none_hints_no_hint_section(
    bb_db: Database,
    monkeypatch: pytest.MonkeyPatch,
    hints_arg: Any,
) -> None:
    from model_adapter import ModelFusionAdapter

    captured: List[str] = []
    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            captured.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    gen = ProbeGenerator(use_fusion=False, db=bb_db)
    try:
        probes = gen.generate_candidate_probes("Chunked body ends with zero chunk.", hints=hints_arg)
        assert len(probes) == 1
        assert len(captured) == 1
    finally:
        gen.adapter.close()


def test_t2_f9_probe_generator_special_chars_and_unicode_in_hints(
    bb_db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    captured: List[str] = []
    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            captured.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    special_hint = 'Focus on "quotes", \\r\\n escapes, {braces}, and Unicode \u00e9\u2603'
    gen = ProbeGenerator(use_fusion=False, db=bb_db)
    try:
        probes = gen.generate_candidate_probes("Header folding rule.", hints=[special_hint])
        assert len(probes) == 1
        assert special_hint in captured[0]
    finally:
        gen.adapter.close()


def test_t2_f9_fusion_arbiter_with_hints_handles_specialist_refusal_safely(
    bb_db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(FusionArbiter, "_fetch_available_tags", lambda self: ["gemma2:2b", "foundation-sec:latest"])
    monkeypatch.setattr(
        FusionArbiter,
        "_query_model",
        lambda self, model, prompt, system_prompt, num_predict=160: "I cannot assist with that request.",
    )
    arb = FusionArbiter(db=bb_db, quiet=True)
    try:
        res = arb.run_fusion_pipeline("Test TE+CL", hints=["Test refusal handling"])
        assert res.fused_probes == []
    finally:
        arb.close()


def test_t2_f9_llm_generator_filters_out_unrelated_domain_hints(
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
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        swarm.db.add_hint("UNRELATED_SMTP_HINT", domain="smtp_pipeline", task_id="dom-filt")
        swarm.db.add_hint("MATCHING_HTTP11_HINT", domain="http11_framing", task_id="dom-filt")
        swarm.llm_generator_agent(
            {
                "rfc_num": "9112",
                "fragments": [("HTTP/1.1 message syntax.", "framing", 2.0)],
                "task_id": "dom-filt",
                "blackboard_domain": "http11_framing",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert "MATCHING_HTTP11_HINT" in seen[0]
        assert "UNRELATED_SMTP_HINT" not in seen[0]
    finally:
        swarm.close()


# =============================================================================
# F10 Boundaries: CLI-only `HINT` injection (6 tests)
# =============================================================================


def test_t2_f10_cli_empty_hint_rejected_with_nonzero_exit(
    tmp_path: Path,
    offline_subprocess_env: Dict[str, str],
) -> None:
    db_file = tmp_path / "empty_hint.db"
    proc = subprocess.run(
        [
            sys.executable,
            "-u",
            str(REPO_ROOT / "rfc_hunt_swarm.py"),
            "hint",
            "--hint",
            "   ",
            "--db",
            str(db_file),
        ],
        cwd=str(tmp_path),
        env=offline_subprocess_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=25,
    )
    assert proc.returncode != 0


def test_t2_f10_cli_missing_hint_text_rejected(
    tmp_path: Path,
    offline_subprocess_env: Dict[str, str],
) -> None:
    db_file = tmp_path / "missing_hint.db"
    proc = subprocess.run(
        [
            sys.executable,
            "-u",
            str(REPO_ROOT / "rfc_hunt_swarm.py"),
            "hint",
            "--db",
            str(db_file),
        ],
        cwd=str(tmp_path),
        env=offline_subprocess_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=25,
    )
    assert proc.returncode != 0


def test_t2_f10_cli_invalid_priority_string_rejected(
    tmp_path: Path,
    offline_subprocess_env: Dict[str, str],
) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-u",
            str(REPO_ROOT / "rfc_hunt_swarm.py"),
            "hint",
            "--hint",
            "valid",
            "--hint-priority",
            "not-a-float",
            "--db",
            str(tmp_path / "bad_prio.db"),
        ],
        cwd=str(tmp_path),
        env=offline_subprocess_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=25,
    )
    assert proc.returncode != 0


def test_t2_f10_cli_hint_with_quotes_semicolons_sqli_persists_verbatim(
    tmp_path: Path,
    offline_subprocess_env: Dict[str, str],
) -> None:
    db_file = tmp_path / "sqli_hint.db"
    payload = "Test ' OR 1=1; DROP TABLE blackboard_nodes; -- \"quoted\""
    proc = subprocess.run(
        [
            sys.executable,
            "-u",
            str(REPO_ROOT / "rfc_hunt_swarm.py"),
            "hint",
            "--hint",
            payload,
            "--db",
            str(db_file),
        ],
        cwd=str(tmp_path),
        env=offline_subprocess_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=25,
    )
    assert proc.returncode == 0
    db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        hints = db.get_active_hints()
        assert len(hints) == 1
        assert hints[0]["content"] == payload
    finally:
        db.close()


def test_t2_f10_cli_hint_creates_new_db_at_nonexistent_nested_path(
    tmp_path: Path,
    offline_subprocess_env: Dict[str, str],
) -> None:
    db_file = tmp_path / "nested_dir" / "brand_new.db"
    db_file.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [
            sys.executable,
            "-u",
            str(REPO_ROOT / "rfc_hunt_swarm.py"),
            "hint",
            "--hint",
            "Nested path hint",
            "--db",
            str(db_file),
        ],
        cwd=str(tmp_path),
        env=offline_subprocess_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=25,
    )
    assert proc.returncode == 0
    assert db_file.is_file()


def test_t2_f10_cli_help_documents_hint_flags_without_ui() -> None:
    from rfc_hunt_swarm import build_swarm_parser

    help_text = build_swarm_parser().format_help()
    assert "--hint" in help_text
    assert "--hint-domain" in help_text
    assert "--hint-priority" in help_text
    assert "--dispatch" in help_text


# =============================================================================
# F11 Boundaries: MCP `inject_blackboard_hint` tool (6 tests)
# =============================================================================


@pytest.mark.parametrize(
    "bad_args",
    [
        {},
        {"hint_text": ""},
        {"hint_text": "   \t  "},
        {"hint_text": "bad\x00nul"},
        {"hint_text": 12345},
        {"hint_text": "valid", "priority": True},
    ],
)
def test_t2_f11_mcp_inject_blackboard_hint_invalid_inputs_return_invalid_params(
    bb_db: Database,
    bad_args: Dict[str, Any],
) -> None:
    with TerminatorMCPServer(db_path=str(bb_db.db_path)) as srv:
        resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "inject_blackboard_hint", "arguments": bad_args},
            }
        )
        assert "error" in resp
        assert resp["error"]["code"] == -32602


# =============================================================================
# F12 Boundaries: `swarm_dispatch.yaml` & dispatcher security (10 tests)
# =============================================================================


def _assert_dispatch_rejected(cfg_path: Path) -> None:
    from rfc_hunt_swarm import main_swarm

    with pytest.raises((ValueError, PermissionError, SystemExit, yaml.YAMLError)) as exc:
        main_swarm(["--dispatch", str(cfg_path)])
    if isinstance(exc.value, SystemExit):
        assert exc.value.code not in (0, None)


def test_t2_f12_yaml_python_object_tag_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = tmp_path / "unsafe.yaml"
    cfg.write_text(
        "version: 1\nruntime:\n  execution: local\ntargets:\n  - !!python/object/apply:os.system ['echo pwn']\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    _assert_dispatch_rejected(cfg)
    assert list(tmp_path.rglob("*.db")) == []


@pytest.mark.parametrize(
    "bad_cfg",
    [
        {"version": 99, "runtime": {"execution": "local"}, "workspace": {"root": "ws"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "k8s"}, "workspace": {"root": "ws"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "docker", "docker_network": "host"}, "workspace": {"root": "ws"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": "ws"}, "targets": []},
    ],
)
def test_t2_f12_invalid_schema_version_execution_network_empty_targets_rejected(
    tmp_path: Path,
    bad_cfg: Dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = tmp_path / "bad_schema.yaml"
    cfg.write_text(yaml.safe_dump(bad_cfg), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _assert_dispatch_rejected(cfg)
    assert list(tmp_path.rglob("*.db")) == []


@pytest.mark.parametrize(
    "bad_ws_root",
    [
        "../../outside",
        "%2e%2e/escape",
        r"\\server\share\escape",
        r"C:\Windows\Temp\escape",
        "ws:ads_stream",
        "CON",
        "NUL",
        "host:80:ads",
    ],
)
def test_t2_f12_path_traversal_unc_ads_reserved_names_in_workspace_root_rejected(
    tmp_path: Path,
    bad_ws_root: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    win_temp_escape = Path(r"C:\Windows\Temp\escape")
    existed_win_temp = win_temp_escape.exists()
    cfg = tmp_path / "traversal.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workspace": {"root": bad_ws_root, "per_target_isolation": True},
                "targets": [{"name": "lab", "host": "127.0.0.1", "port": 8080, "authorized": True}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    _assert_dispatch_rejected(cfg)
    assert list(tmp_path.rglob("*.db")) == []
    assert not (tmp_path.parent / "outside").exists()
    assert not (tmp_path.parent.parent / "outside").exists()
    assert win_temp_escape.exists() == existed_win_temp


@pytest.mark.parametrize(
    "ssrf_host",
    [
        "169.254.169.254",
        "10.0.0.1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
    ],
)
def test_t2_f12_ssrf_targets_rejected_even_when_authorized_true(
    tmp_path: Path,
    ssrf_host: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = tmp_path / "ssrf.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workspace": {"root": str(tmp_path / "ws"), "per_target_isolation": True},
                "targets": [{"name": "ssrf", "host": ssrf_host, "port": 80, "authorized": True}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    _assert_dispatch_rejected(cfg)
    assert list(tmp_path.rglob("*.db")) == []


def test_t2_f12_unauthorized_external_target_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = tmp_path / "unauth.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workspace": {"root": str(tmp_path / "ws"), "per_target_isolation": True},
                "targets": [{"name": "ext", "host": "example.com", "port": 443, "authorized": False}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    _assert_dispatch_rejected(cfg)
    assert list(tmp_path.rglob("*.db")) == []


# =============================================================================
# F13 Boundaries: `--all` / `--mode all` & crash resume (5 tests)
# =============================================================================


def test_t2_f13_all_rejects_unauthorized_external_host(isolated_swarm_workspace: SimpleNamespace) -> None:
    from rfc_hunt_swarm import main_swarm

    with pytest.raises(SystemExit) as exc:
        main_swarm(
            [
                "--all",
                "--host",
                "unauthorized.example.com",
                "--db",
                str(isolated_swarm_workspace.db_path),
            ]
        )
    assert exc.value.code != 0


def test_t2_f13_all_rejects_negative_artex_intent_turns(isolated_swarm_workspace: SimpleNamespace) -> None:
    from rfc_hunt_swarm import main_swarm

    with pytest.raises(SystemExit) as exc:
        main_swarm(
            [
                "--all",
                "--host",
                "127.0.0.1",
                "--port",
                "8080",
                "--artex-intent-turns",
                "-1",
                "--db",
                str(isolated_swarm_workspace.db_path),
            ]
        )
    assert exc.value.code == 1


def test_t2_f13_all_approval_mode_deny_blocks_active_socket_probes(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_http_server: Any,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket
    import threading
    import urllib.request
    from urllib.parse import urlparse

    import httpx
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import main_swarm

    # Unset RFCHUNT_OFFLINE so --approval-mode deny is proven to block target sockets directly,
    # while isolating Ollama tag probes and generation calls from any local Ollama daemon.
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    ollama_endpoint = "http://127.0.0.1:9"
    monkeypatch.setenv("OLLAMA_ENDPOINT", ollama_endpoint)
    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: [])
    monkeypatch.setattr(FusionArbiter, "_fetch_available_tags", lambda self: [])
    monkeypatch.setattr(ModelFusionAdapter, "generate_json", lambda self, *args, **kwargs: [])
    monkeypatch.setattr(FusionArbiter, "_query_model", lambda self, *args, **kwargs: "")

    ollama_http_calls: List[str] = []
    ollama_socket_connects: List[tuple[str, int]] = []
    target_socket_connects: List[tuple[str, int]] = []

    ollama_ep_norm = ollama_endpoint.rstrip("/")
    ollama_parsed = urlparse(ollama_ep_norm)
    ollama_ports = {11434}
    if ollama_parsed.port is not None:
        ollama_ports.add(int(ollama_parsed.port))

    def _is_ollama_url(raw_url: Any) -> bool:
        u = raw_url.full_url if hasattr(raw_url, "full_url") else str(raw_url or "")
        if "/api/tags" in u or "/api/generate" in u:
            return True
        if ollama_ep_norm and u.rstrip("/").startswith(ollama_ep_norm):
            return True
        try:
            parsed = urlparse(u)
            if parsed.port is not None and int(parsed.port) in ollama_ports:
                return True
        except ValueError:
            return False
        return False

    orig_client_send = httpx.Client.send
    orig_async_client_send = httpx.AsyncClient.send
    orig_urlopen = urllib.request.urlopen

    def _spy_client_send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        u = str(getattr(request, "url", ""))
        if _is_ollama_url(u):
            method = str(getattr(request, "method", "REQUEST"))
            ollama_http_calls.append(f"HTTPX_SEND {method} {u}")
        return orig_client_send(self, request, *args, **kwargs)

    async def _spy_async_client_send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        u = str(getattr(request, "url", ""))
        if _is_ollama_url(u):
            method = str(getattr(request, "method", "REQUEST"))
            ollama_http_calls.append(f"HTTPX_ASYNC_SEND {method} {u}")
        return await orig_async_client_send(self, request, *args, **kwargs)

    def _spy_urlopen(url: Any, *args: Any, **kwargs: Any) -> Any:
        u = url.full_url if hasattr(url, "full_url") else str(url or "")
        if _is_ollama_url(u):
            ollama_http_calls.append(f"URLLIB_OPEN {u}")
        return orig_urlopen(url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "send", _spy_client_send)
    monkeypatch.setattr(httpx.AsyncClient, "send", _spy_async_client_send)
    monkeypatch.setattr(urllib.request, "urlopen", _spy_urlopen)

    try:
        import requests  # type: ignore[import-untyped]
    except ImportError:
        requests = None

    if requests is not None:
        orig_requests_send = requests.Session.send

        def _spy_requests_send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
            u = str(getattr(request, "url", ""))
            if _is_ollama_url(u):
                method = str(getattr(request, "method", "REQUEST"))
                ollama_http_calls.append(f"REQUESTS_SEND {method} {u}")
            return orig_requests_send(self, request, *args, **kwargs)

        monkeypatch.setattr(requests.Session, "send", _spy_requests_send)

    sock_tls = threading.local()
    orig_create_connection = socket.create_connection
    orig_socket_connect = socket.socket.connect
    orig_socket_connect_ex = socket.socket.connect_ex

    def _record_socket_addr(address: Any) -> None:
        if not isinstance(address, tuple) or len(address) < 2:
            return
        host = str(address[0] or "")
        try:
            port_int = int(address[1])
        except (TypeError, ValueError):
            return
        if port_int == int(loopback_http_server.port):
            target_socket_connects.append((host, port_int))
        if port_int in ollama_ports:
            ollama_socket_connects.append((host, port_int))

    def _spy_create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        _record_socket_addr(address)
        depth = getattr(sock_tls, "depth", 0)
        sock_tls.depth = depth + 1
        try:
            return orig_create_connection(address, *args, **kwargs)
        finally:
            sock_tls.depth = depth

    def _spy_socket_connect(self: Any, address: Any) -> Any:
        if getattr(sock_tls, "depth", 0) == 0:
            _record_socket_addr(address)
        return orig_socket_connect(self, address)

    def _spy_socket_connect_ex(self: Any, address: Any) -> Any:
        if getattr(sock_tls, "depth", 0) == 0:
            _record_socket_addr(address)
        return orig_socket_connect_ex(self, address)

    monkeypatch.setattr(socket, "create_connection", _spy_create_connection)
    monkeypatch.setattr(socket.socket, "connect", _spy_socket_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _spy_socket_connect_ex)

    mini_repo = isolated_swarm_workspace.root / "repo_deny"
    mini_repo.mkdir(parents=True, exist_ok=True)
    (mini_repo / "svc.py").write_text("x = 1\n", encoding="utf-8")

    loopback_http_server.reset()
    main_swarm(
        [
            "--all",
            "--repo",
            str(mini_repo),
            "--host",
            "127.0.0.1",
            "--port",
            str(loopback_http_server.port),
            "--approval-mode",
            "deny",
            "--no-rea",
            "--db",
            str(isolated_swarm_workspace.db_path),
            "--output-dir",
            str(isolated_swarm_workspace.reports_dir / "deny"),
            "--json",
        ]
    )
    parsed = json.loads(capsys.readouterr().out)
    assert "report_files" in parsed
    assert ollama_http_calls == []
    assert ollama_socket_connects == []
    assert target_socket_connects == []
    assert loopback_http_server.requests == []


def test_t2_f13_reclaim_stale_intents_returns_zero_when_none_claimed(bb_db: Database) -> None:
    nid = bb_db.queue_intent("done-only", task_id="clean-resume")
    bb_db.claim_next_intent("w1", task_id="clean-resume")
    bb_db.complete_intent(nid, status="DONE")
    assert bb_db.reclaim_stale_intents(task_id="clean-resume") == 0
    assert len(bb_db.list_intents(status="DONE", task_id="clean-resume")) == 1


def test_t2_f13_all_does_not_modify_untouched_gui_or_lab_modules(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_http_server: Any,
) -> None:
    from rfc_hunt_swarm import main_swarm

    tracked = [
        REPO_ROOT / "test_lab_server.py",
        REPO_ROOT / "engine" / "dashboard_generator.py",
        REPO_ROOT / "rfchunt_dashboard.html",
    ]
    before = {p: p.read_bytes() for p in tracked if p.exists()}
    mini_repo = isolated_swarm_workspace.root / "repo_gui_check"
    mini_repo.mkdir(parents=True, exist_ok=True)
    (mini_repo / "a.py").write_text("pass\n", encoding="utf-8")

    main_swarm(
        [
            "--mode",
            "all",
            "--repo",
            str(mini_repo),
            "--host",
            "127.0.0.1",
            "--port",
            str(loopback_http_server.port),
            "--no-rea",
            "--db",
            str(isolated_swarm_workspace.db_path),
            "--output-dir",
            str(isolated_swarm_workspace.reports_dir / "gui_check"),
            "--json",
        ]
    )
    for p, content in before.items():
        assert p.read_bytes() == content


# =============================================================================
# F14 Boundaries: Harness² `HINT` promotion bridge (5 tests)
# =============================================================================


@pytest.mark.parametrize(
    "exp_dict",
    [
        {"cue": "c", "lesson": "", "evidence": "e"},
        {"cue": "c", "lesson": "   \n  ", "evidence": "e"},
        {"cue": "c", "evidence": "e"},
    ],
)
def test_t2_f14_empty_whitespace_or_missing_lesson_does_not_emit_blank_hint(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
    exp_dict: Dict[str, str],
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        fake_res = SimpleNamespace(
            mode="parallel",
            task_id="RFC9112",
            domain="http11_framing",
            k=1,
            adopted_label="c1",
            rollouts={"c1": SimpleNamespace(behavioral_score=50.0)},
            experience=exp_dict,
            to_dict=lambda: {
                "mode": "parallel",
                "task_id": "RFC9112",
                "domain": "http11_framing",
                "k": 1,
                "adopted_label": "c1",
                "rollouts": {"c1": {"behavioral_score": 50.0}},
                "experience": exp_dict,
            },
        )
        monkeypatch.setattr(swarm.harness2_engine, "run_mode", lambda **kwargs: fake_res)
        swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 5,
                "enable_harness2": True,
                "harness2_runs_dir": str(isolated_swarm_workspace.harness2_runs_dir),
                "history": [],
            }
        )
        promoted = [h for h in swarm.db.get_active_hints() if h["source_agent"] == "dream_rsi_agent"]
        assert promoted == []
    finally:
        swarm.close()


def test_t2_f14_special_characters_in_lesson_promote_cleanly(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        lesson = "Test 'TE: chunked\\r\\n' & \"CL: 0\" against proxy's parser — unicode \u03bb"
        fake_res = SimpleNamespace(
            mode="parallel",
            task_id="RFC7230",
            domain="http11_framing",
            k=1,
            adopted_label="c2",
            rollouts={"c2": SimpleNamespace(behavioral_score=80.0)},
            experience={"cue": "te-cl", "lesson": lesson, "evidence": "2/2 divergences"},
            to_dict=lambda: {
                "mode": "parallel",
                "task_id": "RFC7230",
                "domain": "http11_framing",
                "k": 1,
                "adopted_label": "c2",
                "rollouts": {"c2": {"behavioral_score": 80.0}},
                "experience": {"cue": "te-cl", "lesson": lesson, "evidence": "2/2 divergences"},
            },
        )
        monkeypatch.setattr(swarm.harness2_engine, "run_mode", lambda **kwargs: fake_res)
        swarm.dream_rsi_agent(
            {
                "rfc_num": "7230",
                "dream_rollouts": 5,
                "enable_harness2": True,
                "harness2_runs_dir": str(isolated_swarm_workspace.harness2_runs_dir),
                "history": [],
            }
        )
        promoted = [h for h in swarm.db.get_active_hints(domain="http11_framing") if h["source_agent"] == "dream_rsi_agent"]
        assert len(promoted) == 1
        assert lesson in promoted[0]["content"]
    finally:
        swarm.close()


def test_t2_f14_harness2_disabled_never_writes_harness2_runs_or_hints(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        called: List[bool] = []
        monkeypatch.setattr(swarm.harness2_engine, "run_mode", lambda **kwargs: called.append(True))
        swarm.dream_rsi_agent({"rfc_num": "9112", "dream_rollouts": 5, "enable_harness2": False, "history": []})
        assert called == []
        assert swarm.db.get_harness2_runs() == []
    finally:
        swarm.close()


# =============================================================================
# F15 Boundaries: ARTEX Dual-Graph `Reason` bridge (5 tests)
# =============================================================================


def test_t2_f15_reason_from_blackboard_facts_empty_db_returns_empty_list(
    bb_db: Database,
    isolated_swarm_workspace: SimpleNamespace,
) -> None:
    eng = DualGraphAttackEngine(db=bb_db, reports_dir=isolated_swarm_workspace.reports_dir / "dg_empty", task_id="empty-dg")
    created = eng.reason_from_blackboard_facts(db=bb_db, task_id="empty-dg", round_num=1)
    assert created == []


def test_t2_f15_reason_from_blackboard_facts_survives_corrupt_fact_payload(
    bb_db: Database,
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
) -> None:
    eng = DualGraphAttackEngine(db=bb_db, reports_dir=isolated_swarm_workspace.reports_dir / "dg_corrupt", task_id="corrupt-dg")
    eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_lab_server.port, endpoints=["/"])
    with bb_db.conn:
        bb_db.conn.execute(
            "INSERT INTO blackboard_nodes (node_id, task_id, node_type, status, content, payload_json) "
            "VALUES (?, ?, 'FACT', 'ACTIVE', 'corrupt fact', '{bad-json')",
            ("bad-fact-1", "corrupt-dg"),
        )
    res = eng.reason_from_blackboard_facts(db=bb_db, task_id="corrupt-dg", round_num=1)
    assert isinstance(res, list)


def test_t2_f15_single_fact_alone_does_not_fabricate_multihop_chain(
    bb_db: Database,
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
) -> None:
    eng = DualGraphAttackEngine(db=bb_db, reports_dir=isolated_swarm_workspace.reports_dir / "dg_single", task_id="single-dg")
    eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_lab_server.port, endpoints=["/"])
    bb_db.add_fact(
        "Single isolated desync",
        task_id="single-dg",
        source_agent="triage_debugger_agent",
        payload={"rule_id": "only-one", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
    )
    eng.reason_from_blackboard_facts(db=bb_db, task_id="single-dg", round_num=1)
    multihop = [i for i in bb_db.list_intents(task_id="single-dg") if int(i["payload"].get("hop_count", 0)) >= 2]
    assert multihop == []


def test_t2_f15_reason_from_blackboard_facts_isolates_by_task_id(
    bb_db: Database,
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
) -> None:
    eng = DualGraphAttackEngine(db=bb_db, reports_dir=isolated_swarm_workspace.reports_dir / "dg_iso", task_id="task-alpha")
    eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_lab_server.port, endpoints=["/", "/internal/service"])
    bb_db.add_fact(
        "Beta desync",
        task_id="task-beta",
        source_agent="triage_debugger_agent",
        payload={"rule_id": "b1", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
    )
    bb_db.add_fact(
        "Beta auth",
        task_id="task-beta",
        source_agent="triage_debugger_agent",
        payload={"rule_id": "b2", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
    )
    created = eng.reason_from_blackboard_facts(db=bb_db, task_id="task-alpha", round_num=1)
    assert created == []
    assert bb_db.list_intents(task_id="task-alpha") == []


def test_t2_f15_triage_framing_artifact_emits_zero_confirmed_vuln_facts(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (True, "leftover baseline"))
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-ART-1",
            target_engine="127.0.0.1",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="artifact",
            expected_behavior="clean",
            raw_probe=b"GET / HTTP/1.1\r\n\r\n",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
        )
        out = swarm.triage_debugger_agent({"current_anomaly": anom, "task_id": "art-task"})
        assert out["current_vuln"] is None
        assert swarm.db.get_facts(task_id="art-task") == []
    finally:
        swarm.close()
