"""
Tier 1 Feature Contract Tests: Blackboard Store & Schema Migration (Features #1-#4).
Covers `PROJECT.md § Interface Contracts` #1 and #2 (>= 5 tests per feature = 24 tests).
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any, Callable

import pytest

from database import Database
from engine.knowledge_graph import ResearchKnowledgeGraph


# =============================================================================
# Feature #1: `blackboard_nodes` table & indexes (6 tests)
# =============================================================================


def test_t1_f1_blackboard_nodes_table_columns_and_types(bb_db: Database) -> None:
    cur = bb_db.conn.execute("PRAGMA table_info(blackboard_nodes)")
    cols = {row[1]: {"type": row[2], "notnull": row[3], "dflt": row[4], "pk": row[5]} for row in cur.fetchall()}
    expected_cols = {
        "id",
        "node_id",
        "task_id",
        "node_type",
        "status",
        "priority",
        "domain",
        "rfc_id",
        "source_agent",
        "claimed_by",
        "claimed_at",
        "completed_at",
        "content",
        "payload_json",
        "parent_node_id",
        "created_at",
        "updated_at",
    }
    assert expected_cols.issubset(set(cols.keys()))
    assert cols["id"]["pk"] == 1
    assert cols["node_id"]["notnull"] == 1
    assert cols["node_type"]["notnull"] == 1


def test_t1_f1_blackboard_nodes_column_defaults(bb_db: Database) -> None:
    with bb_db.conn:
        bb_db.conn.execute(
            "INSERT INTO blackboard_nodes (node_id, node_type, content) VALUES (?, ?, ?)",
            ("raw-default-1", "FACT", "baseline default check"),
        )
    row = bb_db.conn.execute(
        "SELECT task_id, status, priority, domain, rfc_id, source_agent, claimed_by, payload_json, parent_node_id "
        "FROM blackboard_nodes WHERE node_id = ?",
        ("raw-default-1",),
    ).fetchone()
    assert row is not None
    assert row[0] == "default"
    assert row[1] == "ACTIVE"
    assert float(row[2]) == 0.0
    assert row[3] == ""
    assert row[4] == ""
    assert row[5] == ""
    assert row[6] == ""
    assert row[7] == "{}"
    assert row[8] == ""


def test_t1_f1_blackboard_nodes_indexes_exist(bb_db: Database) -> None:
    rows = bb_db.conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='blackboard_nodes'"
    ).fetchall()
    index_names = {r[0] for r in rows}
    assert "idx_blackboard_type_status_prio" in index_names
    assert "idx_blackboard_task_type" in index_names
    assert "idx_blackboard_domain_rfc" in index_names


def test_t1_f1_blackboard_nodes_unique_node_id_and_autoincrement(bb_db: Database) -> None:
    id1 = bb_db.add_blackboard_node("FACT", "first fact", node_id="uniq-node-1")
    id2 = bb_db.add_blackboard_node("FACT", "second fact", node_id="uniq-node-2")
    assert id1 == "uniq-node-1"
    assert id2 == "uniq-node-2"
    rows = bb_db.conn.execute(
        "SELECT id, node_id FROM blackboard_nodes WHERE node_id IN (?, ?) ORDER BY id ASC",
        ("uniq-node-1", "uniq-node-2"),
    ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] < rows[1][0]
    with pytest.raises(sqlite3.IntegrityError):
        with bb_db.conn:
            bb_db.conn.execute(
                "INSERT INTO blackboard_nodes (node_id, node_type, content) VALUES (?, ?, ?)",
                ("uniq-node-1", "FACT", "duplicate"),
            )


def test_t1_f1_blackboard_nodes_supports_all_three_node_types_and_statuses(bb_db: Database) -> None:
    f_id = bb_db.add_fact("confirmed CL.0 behavior", domain="http11_framing", rfc_id="RFC9112")
    i_id = bb_db.queue_intent("probe TE obs-fold", priority=7.5, domain="http11_framing", rfc_id="RFC9112")
    h_id = bb_db.add_hint("focus on header folding", priority=12.0, domain="http11_framing")
    assert f_id and i_id and h_id
    all_nodes = bb_db.get_blackboard_nodes(limit=20)
    by_id = {n["node_id"]: n for n in all_nodes}
    assert by_id[f_id]["node_type"] == "FACT"
    assert by_id[i_id]["node_type"] == "INTENT"
    assert by_id[i_id]["status"] == "PENDING"
    assert by_id[h_id]["node_type"] == "HINT"
    assert by_id[h_id]["status"] == "ACTIVE"


def test_t1_f1_wal_mode_and_storage_stats_compatibility(bb_db: Database) -> None:
    mode = bb_db.conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert str(mode).lower() == "wal"
    bb_db.add_fact("wal-fact", domain="http11_framing")
    bb_db.queue_intent("wal-intent", priority=3.0)
    stats = bb_db.get_storage_stats()
    assert isinstance(stats, dict)
    assert len(bb_db.get_blackboard_nodes()) == 2


# =============================================================================
# Feature #2: Idempotent migration `004_blackboard_nodes` (6 tests)
# =============================================================================


def test_t1_f2_fresh_db_records_migration_004(bb_db: Database) -> None:
    rows = bb_db.conn.execute("SELECT version FROM schema_migrations").fetchall()
    versions = {str(r[0]) for r in rows}
    assert "004_blackboard_nodes" in versions
    assert {"001_attack_chains_artex_cols", "002_chain_retests_original_traffic_id", "003_approval_decisions_action_summary"}.issubset(versions)


def test_t1_f2_upgrade_v003_premigration_db_preserves_legacy_rows(
    pre_migration_db_builder: Callable[..., Path],
    bb_db_factory: Callable[..., Database],
) -> None:
    legacy_path = pre_migration_db_builder("v003")
    raw = sqlite3.connect(str(legacy_path))
    try:
        tables_before = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "blackboard_nodes" not in tables_before
    finally:
        raw.close()

    upgraded = bb_db_factory(str(legacy_path))
    versions = {str(r[0]) for r in upgraded.conn.execute("SELECT version FROM schema_migrations").fetchall()}
    assert "004_blackboard_nodes" in versions

    rfcs = upgraded.conn.execute("SELECT rfc_id FROM rfcs").fetchall()
    evals = upgraded.conn.execute("SELECT desync_class FROM evaluations").fetchall()
    chains = upgraded.conn.execute("SELECT chain_id FROM attack_chains").fetchall()
    assert [r[0] for r in rfcs] == ["RFC9112"]
    assert [e[0] for e in evals] == ["CL.TE"]
    assert [c[0] for c in chains] == ["legacy-chain-1"]


def test_t1_f2_upgrade_pre001_legacy_db_applies_001_through_004(
    pre_migration_db_builder: Callable[..., Path],
    bb_db_factory: Callable[..., Database],
) -> None:
    legacy_path = pre_migration_db_builder("pre_001")
    upgraded = bb_db_factory(str(legacy_path))
    versions = {str(r[0]) for r in upgraded.conn.execute("SELECT version FROM schema_migrations").fetchall()}
    assert {"001_attack_chains_artex_cols", "002_chain_retests_original_traffic_id", "003_approval_decisions_action_summary", "004_blackboard_nodes"}.issubset(versions)
    upgraded.add_fact("post-upgrade fact", rfc_id="RFC9112")
    assert len(upgraded.get_facts(rfc_id="RFC9112")) == 1


def test_t1_f2_repeated_reopen_idempotency(
    pre_migration_db_builder: Callable[..., Path],
    bb_db_factory: Callable[..., Database],
) -> None:
    legacy_path = pre_migration_db_builder("v003")
    for idx in range(3):
        db = bb_db_factory(str(legacy_path))
        db.add_fact(f"fact-{idx}", node_id=f"reopen-fact-{idx}")
        db.close()

    final_db = bb_db_factory(str(legacy_path))
    facts = final_db.get_facts()
    assert {f["node_id"] for f in facts} == {"reopen-fact-0", "reopen-fact-1", "reopen-fact-2"}
    count_004 = final_db.conn.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = '004_blackboard_nodes'"
    ).fetchone()[0]
    assert count_004 == 1


def test_t1_f2_migrate_wrapper_backward_compatibility(bb_db: Database) -> None:
    bb_db._migrate_attack_chains_columns()
    bb_db._run_migrations()
    versions = {str(r[0]) for r in bb_db.conn.execute("SELECT version FROM schema_migrations").fetchall()}
    assert "004_blackboard_nodes" in versions


def test_t1_f2_existing_blackboard_nodes_preserved_if_migration_retriggered(bb_db: Database) -> None:
    nid = bb_db.queue_intent("survive re-migration", priority=9.0, domain="h2_translation")
    with bb_db.conn:
        bb_db.conn.execute("DELETE FROM schema_migrations WHERE version = '004_blackboard_nodes'")
    bb_db._run_migrations()
    intents = bb_db.list_intents(domain="h2_translation")
    assert len(intents) == 1
    assert intents[0]["node_id"] == nid


# =============================================================================
# Feature #3: Atomic `INTENT` claiming & resume (6 tests)
# =============================================================================


def test_t1_f3_queue_intent_priority_ordering_and_fifo_tiebreak(bb_db: Database) -> None:
    id_low = bb_db.queue_intent("low prio", priority=1.0, task_id="t-prio")
    id_high_1 = bb_db.queue_intent("high first", priority=10.0, task_id="t-prio")
    id_high_2 = bb_db.queue_intent("high second", priority=10.0, task_id="t-prio")
    id_mid = bb_db.queue_intent("mid prio", priority=5.0, task_id="t-prio")

    c1 = bb_db.claim_next_intent("w1", task_id="t-prio")
    c2 = bb_db.claim_next_intent("w1", task_id="t-prio")
    c3 = bb_db.claim_next_intent("w1", task_id="t-prio")
    c4 = bb_db.claim_next_intent("w1", task_id="t-prio")
    c5 = bb_db.claim_next_intent("w1", task_id="t-prio")

    assert [c["node_id"] for c in (c1, c2, c3, c4)] == [id_high_1, id_high_2, id_mid, id_low]
    assert c5 is None


def test_t1_f3_claim_next_intent_sets_claimed_fields(bb_db: Database) -> None:
    nid = bb_db.queue_intent("test cl0", priority=5.0, domain="http11_framing", payload={"probe": "GET /"})
    claimed = bb_db.claim_next_intent("worker-alpha", domain="http11_framing")
    assert claimed is not None
    assert claimed["node_id"] == nid
    assert claimed["status"] == "CLAIMED"
    assert claimed["claimed_by"] == "worker-alpha"
    assert claimed["claimed_at"] is not None
    assert claimed["payload"]["probe"] == "GET /"


def test_t1_f3_complete_intent_done_merges_result_payload(bb_db: Database) -> None:
    nid = bb_db.queue_intent("verify probe", priority=4.0, payload={"target": "127.0.0.1", "step": 1})
    claimed = bb_db.claim_next_intent("worker-beta")
    assert claimed is not None
    ok = bb_db.complete_intent(nid, status="DONE", result_payload={"verdict": "CONFORMANT", "latency_ms": 4.2})
    assert ok is True
    done_rows = bb_db.list_intents(status="DONE")
    assert len(done_rows) == 1
    row = done_rows[0]
    assert row["node_id"] == nid
    assert row["completed_at"] is not None
    assert row["payload"]["verdict"] == "CONFORMANT"


def test_t1_f3_complete_intent_failed_status(bb_db: Database) -> None:
    nid = bb_db.queue_intent("failing probe", priority=2.0)
    bb_db.claim_next_intent("worker-gamma")
    ok = bb_db.complete_intent(nid, status="FAILED", result_payload={"error": "connection_reset"})
    assert ok is True
    failed = bb_db.list_intents(status="FAILED")
    assert len(failed) == 1
    assert failed[0]["node_id"] == nid
    assert failed[0]["payload"]["error"] == "connection_reset"
    assert bb_db.claim_next_intent("worker-gamma") is None


def test_t1_f3_reclaim_stale_intents_resets_claimed_across_connections(
    bb_db_factory: Callable[..., Database],
) -> None:
    db1 = bb_db_factory("resume_shared.db")
    nid1 = db1.queue_intent("crash-target-1", priority=10.0, task_id="task-r")
    nid2 = db1.queue_intent("crash-target-2", priority=5.0, task_id="task-r")
    c1 = db1.claim_next_intent("worker-crashed", task_id="task-r")
    assert c1 is not None and c1["node_id"] == nid1
    db1.close()

    db2 = bb_db_factory("resume_shared.db")
    reclaimed = db2.reclaim_stale_intents(task_id="task-r", worker_id="worker-crashed")
    assert reclaimed == 1
    pending = db2.list_intents(status="PENDING", task_id="task-r")
    assert [p["node_id"] for p in pending] == [nid1, nid2]
    assert pending[0]["claimed_by"] == ""

    reclaimed_item = db2.claim_next_intent("worker-healthy", task_id="task-r")
    assert reclaimed_item is not None
    assert reclaimed_item["node_id"] == nid1
    assert reclaimed_item["claimed_by"] == "worker-healthy"


def test_t1_f3_list_intents_filters_by_status_task_and_domain(bb_db: Database) -> None:
    a1 = bb_db.queue_intent("a1", task_id="tA", domain="http11_framing", priority=5.0)
    a2 = bb_db.queue_intent("a2", task_id="tA", domain="h2_translation", priority=3.0)
    b1 = bb_db.queue_intent("b1", task_id="tB", domain="http11_framing", priority=9.0)
    bb_db.claim_next_intent("w", task_id="tA", domain="http11_framing")

    assert [r["node_id"] for r in bb_db.list_intents(status="CLAIMED", task_id="tA")] == [a1]
    assert [r["node_id"] for r in bb_db.list_intents(status="PENDING", task_id="tA", domain="h2_translation")] == [a2]
    assert [r["node_id"] for r in bb_db.list_intents(task_id="tB", domain="http11_framing")] == [b1]


# =============================================================================
# Feature #4: `FACT` / `HINT` / `ResearchKnowledgeGraph` APIs (6 tests)
# =============================================================================


def test_t1_f4_add_and_get_blackboard_nodes_payload_roundtrip(bb_db: Database) -> None:
    payload = {"cwe": "CWE-444", "hop_count": 2, "nested": {"ok": True}}
    nid = bb_db.add_blackboard_node(
        "FACT",
        "Confirmed framing discrepancy",
        task_id="task-payload",
        domain="http11_framing",
        rfc_id="RFC9112",
        source_agent="execution_oracle",
        payload=payload,
        parent_node_id="intent-parent-1",
    )
    rows = bb_db.get_blackboard_nodes(node_type="FACT", task_id="task-payload")
    assert len(rows) == 1
    row = rows[0]
    assert row["node_id"] == nid
    assert row["payload"] == payload
    assert json.loads(row["payload_json"]) == payload
    assert row["parent_node_id"] == "intent-parent-1"


def test_t1_f4_add_and_get_facts_filters(bb_db: Database) -> None:
    f1 = bb_db.add_fact("fact 9112", task_id="t1", domain="http11_framing", rfc_id="RFC9112", source_agent="triage")
    f2 = bb_db.add_fact("fact 9113", task_id="t1", domain="h2_translation", rfc_id="RFC9113", source_agent="oracle")
    f3 = bb_db.add_fact("fact t2", task_id="t2", domain="http11_framing", rfc_id="RFC9112", source_agent="triage")

    assert [f["node_id"] for f in bb_db.get_facts(task_id="t1", domain="http11_framing")] == [f1]
    assert [f["node_id"] for f in bb_db.get_facts(task_id="t1", rfc_id="RFC9113")] == [f2]
    assert [f["node_id"] for f in bb_db.get_facts(task_id="t2")] == [f3]


def test_t1_f4_add_and_get_active_hints_domain_global_and_priority(bb_db: Database) -> None:
    h_global = bb_db.add_hint("always test TE+CL", priority=15.0, domain="global", task_id="t1")
    h_empty_dom = bb_db.add_hint("wildcard domain hint", priority=5.0, domain="", task_id="t1")
    h_http = bb_db.add_hint("focus on obs-fold", priority=25.0, domain="http11_framing", task_id="t1")
    h_pqc = bb_db.add_hint("check ml-kem downgrade", priority=99.0, domain="tls13_pqc", task_id="t1")

    http_hints = bb_db.get_active_hints(task_id="t1", domain="http11_framing")
    ids = [h["node_id"] for h in http_hints]
    assert ids == [h_http, h_global, h_empty_dom]
    assert h_pqc not in ids


def test_t1_f4_deactivate_hint_hides_from_active_hints(bb_db: Database) -> None:
    h1 = bb_db.add_hint("active hint", priority=10.0, domain="http11_framing")
    h2 = bb_db.add_hint("obsolete hint", priority=20.0, domain="http11_framing")
    assert bb_db.deactivate_hint(h2) is True
    active = bb_db.get_active_hints(domain="http11_framing")
    assert [h["node_id"] for h in active] == [h1]


def test_t1_f4_knowledge_graph_zero_arg_backward_compat() -> None:
    kg = ResearchKnowledgeGraph()
    kg.add_node("RFC9112", "RFC", "HTTP/1.1 Framing")
    kg.add_node("REQ-1", "REQUIREMENT", "MUST reject obs-fold")
    kg.add_node("VULN-1", "VULNERABILITY", "Confirmed obs-fold desync")
    kg.add_edge("RFC9112", "REQ-1", "DEFINES")
    kg.record_testing_event("REQ-1", "VULN-1", is_vulnerability=True)
    cov = kg.calculate_specification_coverage()
    assert cov["total_requirements"] == 1
    assert cov["tested_count"] == 1
    assert cov["coverage_percent"] == 100.0
    trace = kg.get_lineage_trace("VULN-1")
    assert [t["node_id"] for t in trace] == ["VULN-1", "REQ-1", "RFC9112"]


def test_t1_f4_knowledge_graph_with_db_mirrors_facts_and_intents(bb_db: Database) -> None:
    kg = ResearchKnowledgeGraph(db=bb_db, task_id="kg-task", domain="http11_framing")
    kg.add_node("RFC9112", "RFC", "HTTP/1.1 Framing")
    kg.add_node("REQ-TE", "REQUIREMENT", "Reject conflicting Transfer-Encoding and Content-Length")
    kg.add_edge("RFC9112", "REQ-TE", "DEFINES")
    kg.add_node("VULN-99", "VULNERABILITY", "Confirmed CL.TE desync on /internal/service")
    kg.record_testing_event("REQ-TE", "VULN-99", is_vulnerability=True)

    facts = bb_db.get_facts(task_id="kg-task")
    intents = bb_db.list_intents(task_id="kg-task")
    assert len(facts) >= 1
    assert len(intents) >= 1
    assert any("CL.TE" in f["content"] or "VULN-99" in f["node_id"] for f in facts)
