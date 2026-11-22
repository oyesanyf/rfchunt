"""
Milestone M1 Unit, Migration, Concurrency & KnowledgeGraph Bridge Tests
for the Cairn-style SQLite Blackboard (`blackboard_nodes`).

All tests run exclusively against `:memory:` or pytest `tmp_path` databases
with isolated `encrypt_at_rest=False` or `secret_key_path=tmp_path / "secret.key"`
so `terminator.db` and `keys/secret.key` are never touched.
"""

import json
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from database import Database
from engine.knowledge_graph import ResearchKnowledgeGraph


# ---------------------------------------------------------------------------
# Group A: Schema, Migrations & Idempotency
# ---------------------------------------------------------------------------


def test_fresh_db_migration_and_schema_migrations(tmp_path: Path):
    db_path = tmp_path / "fresh.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        cur = db.conn.cursor()

        # Verify schema_migrations contains 001..004
        cur.execute("SELECT version FROM schema_migrations")
        versions = {str(r[0]) for r in cur.fetchall()}
        assert {
            "001_attack_chains_artex_cols",
            "002_chain_retests_original_traffic_id",
            "003_approval_decisions_action_summary",
            "004_blackboard_nodes",
        }.issubset(versions)

        # Verify exact 17 contracted columns on blackboard_nodes
        cur.execute("PRAGMA table_info(blackboard_nodes)")
        cols = {str(r[1]) for r in cur.fetchall()}
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
        assert cols == expected_cols

        # Verify indexes on blackboard_nodes
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='blackboard_nodes'"
        )
        index_names = {str(r[0]) for r in cur.fetchall()}
        assert {
            "idx_blackboard_type_status_prio",
            "idx_blackboard_task_type",
            "idx_blackboard_domain_rfc",
        }.issubset(index_names)

        # Verify CHECK constraint and API validation reject invalid node_type
        with pytest.raises(ValueError):
            db.add_blackboard_node("BOGUS", "bad type")
        with pytest.raises(sqlite3.IntegrityError):
            db.conn.execute(
                "INSERT INTO blackboard_nodes (node_id, node_type, content) VALUES (?, ?, ?)",
                ("bad-1", "BOGUS", "bad"),
            )


def test_premigration_db_upgrade_preserves_existing_data(tmp_path: Path):
    db_path = tmp_path / "legacy.db"
    raw = sqlite3.connect(str(db_path))
    try:
        raw.executescript(
            """
            CREATE TABLE rfcs (
                rfc_id TEXT PRIMARY KEY,
                title TEXT,
                source_url TEXT,
                doc_path TEXT,
                fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE fragments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rfc_id TEXT,
                content TEXT,
                keywords TEXT
            );
            CREATE TABLE attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id TEXT UNIQUE NOT NULL,
                goal TEXT,
                steps_json TEXT,
                raw_payload TEXT,
                severity TEXT,
                is_verified BOOLEAN DEFAULT 0,
                evidence TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE chain_retests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id TEXT NOT NULL,
                retest_status TEXT DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE approval_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL DEFAULT 'default',
                action_type TEXT NOT NULL,
                decision TEXT NOT NULL,
                decided_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO schema_migrations (version) VALUES
                ('001_attack_chains_artex_cols'),
                ('002_chain_retests_original_traffic_id'),
                ('003_approval_decisions_action_summary');
            INSERT INTO rfcs (rfc_id, title, source_url, doc_path)
            VALUES ('RFC9112', 'HTTP/1.1', 'https://example.invalid/rfc9112', 'rfc9112.txt');
            INSERT INTO attack_chains (chain_id, goal, steps_json, raw_payload, severity, is_verified, evidence)
            VALUES ('CHAIN-LEGACY-1', 'Smuggling', '[{"step":1}]', 'GET / HTTP/1.1', 'HIGH', 1, 'legacy-proof');
            """
        )
        raw.commit()
    finally:
        raw.close()

    with Database(str(db_path), encrypt_at_rest=False) as db:
        cur = db.conn.cursor()
        cur.execute("SELECT version FROM schema_migrations WHERE version = '004_blackboard_nodes'")
        assert cur.fetchone() is not None

        # Legacy rows remain intact
        cur.execute("SELECT title FROM rfcs WHERE rfc_id = 'RFC9112'")
        rfc_row = cur.fetchone()
        assert rfc_row is not None and rfc_row["title"] == "HTTP/1.1"

        chains = db.get_attack_chains(chain_id="CHAIN-LEGACY-1")
        assert len(chains) == 1
        assert chains[0]["goal"] == "Smuggling"

        # Blackboard table is now operational
        fid = db.add_fact("Legacy upgrade fact", rfc_id="RFC9112", source_agent="test")
        facts = db.get_facts(rfc_id="RFC9112")
        assert len(facts) == 1
        assert facts[0]["node_id"] == fid


def test_reopen_idempotency_and_default_secret_box_isolation(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("ARTEX_SECRET_KEY", raising=False)
    monkeypatch.delenv("RFCHUNT_DISABLE_AT_REST_ENCRYPTION", raising=False)

    db_path = tmp_path / "reopen.db"
    key_path = tmp_path / "secret.key"

    with Database(str(db_path), secret_key_path=key_path) as db1:
        f_id = db1.add_fact("Observed header folding", domain="http", rfc_id="RFC9112")
        i_id = db1.queue_intent("Probe chunk ext", priority=7.0, domain="http", rfc_id="RFC9112")
        h_id = db1.add_hint("Prioritize TE/CL", priority=15.0, domain="http")

    assert key_path.exists()

    for _ in range(2):
        with Database(str(db_path), secret_key_path=key_path) as db_reopen:
            cur = db_reopen.conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = '004_blackboard_nodes'"
            )
            assert cur.fetchone()[0] == 1

            facts = db_reopen.get_facts()
            intents = db_reopen.list_intents()
            hints = db_reopen.get_active_hints(domain="http")
            assert [f["node_id"] for f in facts] == [f_id]
            assert [i["node_id"] for i in intents] == [i_id]
            assert [h["node_id"] for h in hints] == [h_id]


def test_partial_blackboard_nodes_table_upgrade(tmp_path: Path):
    db_path = tmp_path / "partial.db"
    raw = sqlite3.connect(str(db_path))
    try:
        raw.executescript(
            """
            CREATE TABLE schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO schema_migrations (version) VALUES
                ('001_attack_chains_artex_cols'),
                ('002_chain_retests_original_traffic_id'),
                ('003_approval_decisions_action_summary');
            CREATE TABLE blackboard_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT UNIQUE NOT NULL,
                node_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                content TEXT NOT NULL DEFAULT ''
            );
            INSERT INTO blackboard_nodes (node_id, node_type, status, content)
            VALUES ('FACT-PRE-1', 'FACT', 'ACTIVE', 'Pre-existing fact');
            """
        )
        raw.commit()
    finally:
        raw.close()

    with Database(str(db_path), encrypt_at_rest=False) as db:
        cur = db.conn.cursor()
        cur.execute("PRAGMA table_info(blackboard_nodes)")
        cols = {str(r[1]) for r in cur.fetchall()}
        for expected in (
            "task_id",
            "priority",
            "domain",
            "rfc_id",
            "source_agent",
            "claimed_by",
            "claimed_at",
            "completed_at",
            "payload_json",
            "parent_node_id",
            "created_at",
            "updated_at",
        ):
            assert expected in cols

        cur.execute("SELECT version FROM schema_migrations WHERE version = '004_blackboard_nodes'")
        assert cur.fetchone() is not None

        facts = db.get_facts()
        assert any(f["node_id"] == "FACT-PRE-1" and f["content"] == "Pre-existing fact" for f in facts)

        iid = db.queue_intent("Post-upgrade intent", priority=3.0)
        claimed = db.claim_next_intent("worker-partial")
        assert claimed is not None
        assert claimed["node_id"] == iid
        assert claimed["status"] == "CLAIMED"


# ---------------------------------------------------------------------------
# Group B: FACT, INTENT, HINT CRUD & Filtering
# ---------------------------------------------------------------------------


def test_fact_crud_and_payload_json_roundtrip():
    with Database(":memory:") as db:
        fid1 = db.add_fact(
            "Observed 400 vs 200 discrepancy",
            task_id="task-alpha",
            domain="http",
            rfc_id="RFC9112",
            source_agent="execution_oracle_agent",
            payload={"nested": [1, 2], "ok": True},
            parent_node_id="",
        )
        fid2 = db.add_fact(
            "Confirmed smuggling chain",
            task_id="task-alpha",
            domain="http",
            rfc_id="RFC9110",
            source_agent="triage_debugger_agent",
            payload={"poe": 3},
            parent_node_id=fid1,
        )
        fid3 = db.add_blackboard_node(
            "FACT",
            "DNS NXDOMAIN reflection",
            task_id="task-beta",
            domain="dns",
            rfc_id="RFC1035",
            source_agent="oracle",
            payload={"rcode": 3},
        )
        assert fid1 and fid2 and fid3

        http_facts = db.get_facts(task_id="task-alpha", domain="http")
        assert len(http_facts) == 2
        f1_row = next(r for r in http_facts if r["node_id"] == fid1)
        f2_row = next(r for r in http_facts if r["node_id"] == fid2)
        assert f1_row["payload"] == {"nested": [1, 2], "ok": True}
        assert '"nested": [1, 2]' in f1_row["payload_json"]
        assert f2_row["parent_node_id"] == fid1

        rfc9110_facts = db.get_facts(rfc_id="RFC9110")
        assert [r["node_id"] for r in rfc9110_facts] == [fid2]

        limited = db.get_blackboard_nodes(node_type="FACT", limit=2)
        assert len(limited) == 2


def test_hint_crud_domain_global_filtering_and_deactivate():
    with Database(":memory:") as db:
        h_global = db.add_hint("Global hint", priority=5.0, domain="global", task_id="t1")
        h_empty = db.add_hint("Empty domain hint", priority=8.0, domain="", task_id="t1")
        h_http = db.add_hint("HTTP hint", priority=20.0, domain="http", task_id="t1", rfc_id="RFC9112")
        db.add_hint("DNS hint", priority=50.0, domain="dns", task_id="t1")
        db.add_hint("Inactive HTTP hint", priority=100.0, domain="http", task_id="t1", active=False)

        active_http = db.get_active_hints(domain="http", task_id="t1")
        assert [h["node_id"] for h in active_http] == [h_http, h_empty, h_global]
        assert [h["priority"] for h in active_http] == [20.0, 8.0, 5.0]

        scoped_rfc = db.get_active_hints(domain="http", task_id="t1", rfc_id="RFC9112")
        assert [h["node_id"] for h in scoped_rfc] == [h_http]

        assert db.deactivate_hint(h_http) is True
        assert db.deactivate_hint("NONEXISTENT-HINT") is False

        after_deact = db.get_active_hints(domain="http", task_id="t1")
        assert [h["node_id"] for h in after_deact] == [h_empty, h_global]


def test_intent_priority_and_fifo_tiebreak_ordering(tmp_path: Path):
    with Database(str(tmp_path / "prio.db"), encrypt_at_rest=False) as db:
        id_low = db.queue_intent("low", priority=1.0, domain="http")
        id_high1 = db.queue_intent("high-1", priority=10.0, domain="http")
        id_high2 = db.queue_intent("high-2", priority=10.0, domain="http")
        id_mid = db.queue_intent("mid", priority=5.0, domain="http")
        id_tls = db.queue_intent("tls-other", priority=99.0, domain="tls")

        claimed_order: List[str] = []
        for _ in range(4):
            item = db.claim_next_intent("w1", domain="http")
            assert item is not None
            assert item["status"] == "CLAIMED"
            assert item["claimed_by"] == "w1"
            assert item["claimed_at"]
            claimed_order.append(item["node_id"])

        assert claimed_order == [id_high1, id_high2, id_mid, id_low]
        assert db.claim_next_intent("w1", domain="http") is None

        pending = db.list_intents(status="PENDING")
        assert [p["node_id"] for p in pending] == [id_tls]
        claimed_list = db.list_intents(status="CLAIMED", domain="http")
        assert len(claimed_list) == 4


# ---------------------------------------------------------------------------
# Group C: Concurrency, batch_writes(), Lifecycle & Crash Recovery
# ---------------------------------------------------------------------------


def test_claim_next_intent_inside_batch_writes(tmp_path: Path):
    db_path = tmp_path / "batch_claim.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        i1 = db.queue_intent("first", priority=10.0, task_id="t-batch")
        i2 = db.queue_intent("second", priority=5.0, task_id="t-batch")

        with db.batch_writes():
            c1 = db.claim_next_intent("worker-batch", task_id="t-batch")
            assert c1 is not None and c1["node_id"] == i1
            assert c1["status"] == "CLAIMED"

        # Verify committed after batch_writes exited
        claimed = db.list_intents(status="CLAIMED", task_id="t-batch")
        assert [c["node_id"] for c in claimed] == [i1]

        # Verify exception inside batch_writes rolls back nested claim cleanly
        with pytest.raises(RuntimeError):
            with db.batch_writes():
                c2 = db.claim_next_intent("worker-batch", task_id="t-batch")
                assert c2 is not None and c2["node_id"] == i2
                raise RuntimeError("abort batch")

        pending = db.list_intents(status="PENDING", task_id="t-batch")
        assert [p["node_id"] for p in pending] == [i2]


def test_concurrent_claim_same_connection_multithread(tmp_path: Path):
    db_path = tmp_path / "shared_mt.db"
    total_intents = 40
    num_workers = 8

    with Database(str(db_path), encrypt_at_rest=False) as db:
        for idx in range(total_intents):
            db.queue_intent(f"intent-{idx}", priority=float(idx % 5), task_id="mt-shared")

        barrier = threading.Barrier(num_workers)
        claimed_by_thread: List[List[str]] = [[] for _ in range(num_workers)]
        errors: List[BaseException] = []
        err_lock = threading.Lock()

        def worker(tid: int) -> None:
            try:
                barrier.wait(timeout=10.0)
                while True:
                    row = db.claim_next_intent(f"worker-{tid}", task_id="mt-shared")
                    if row is None:
                        break
                    claimed_by_thread[tid].append(row["node_id"])
            except BaseException as exc:
                with err_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        assert not errors, f"Unexpected thread errors: {errors}"
        all_claimed = [nid for batch in claimed_by_thread for nid in batch]
        assert len(all_claimed) == total_intents
        assert len(set(all_claimed)) == total_intents
        assert db.list_intents(status="PENDING", task_id="mt-shared") == []


def test_concurrent_claim_multi_connection_multithread(tmp_path: Path):
    db_path = tmp_path / "multiconn_mt.db"
    total_intents = 50
    num_workers = 10

    with Database(str(db_path), encrypt_at_rest=False) as init_db:
        for idx in range(total_intents):
            init_db.queue_intent(f"mc-intent-{idx}", priority=float(idx % 7), task_id="mt-mc")

    barrier = threading.Barrier(num_workers)
    claimed_by_thread: List[List[str]] = [[] for _ in range(num_workers)]
    errors: List[BaseException] = []
    err_lock = threading.Lock()

    def worker(tid: int) -> None:
        conn_db = None
        try:
            conn_db = Database(str(db_path), timeout=30.0, encrypt_at_rest=False)
            barrier.wait(timeout=10.0)
            while True:
                row = conn_db.claim_next_intent(f"conn-worker-{tid}", task_id="mt-mc")
                if row is None:
                    break
                claimed_by_thread[tid].append(row["node_id"])
        except BaseException as exc:
            with err_lock:
                errors.append(exc)
        finally:
            if conn_db is not None:
                conn_db.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30.0)

    assert not errors, f"Unexpected multi-connection errors: {errors}"
    all_claimed = [nid for batch in claimed_by_thread for nid in batch]
    assert len(all_claimed) == total_intents
    assert len(set(all_claimed)) == total_intents

    with Database(str(db_path), encrypt_at_rest=False) as verify_db:
        assert verify_db.list_intents(status="PENDING", task_id="mt-mc") == []
        assert len(verify_db.list_intents(status="CLAIMED", task_id="mt-mc")) == total_intents


def test_complete_intent_done_and_failed_across_connections(tmp_path: Path):
    db_path = tmp_path / "complete.db"
    with Database(str(db_path), encrypt_at_rest=False) as db_a:
        i1 = db_a.queue_intent("intent-1", priority=10.0, payload={"seed": "A"})
        i2 = db_a.queue_intent("intent-2", priority=5.0, payload={"seed": "B"})
        c1 = db_a.claim_next_intent("worker-A")
        assert c1 is not None and c1["node_id"] == i1

        with Database(str(db_path), encrypt_at_rest=False) as db_b:
            c2 = db_b.claim_next_intent("worker-B")
            assert c2 is not None and c2["node_id"] == i2
            assert db_b.complete_intent(i2, status="FAILED", result_payload={"error": "timeout"}) is True

        assert db_a.complete_intent(i1, status="DONE", result_payload={"finding": "confirmed"}) is True
        assert db_a.complete_intent("MISSING-INTENT", status="DONE") is False

    with Database(str(db_path), encrypt_at_rest=False) as db_c:
        done = db_c.list_intents(status="DONE")
        failed = db_c.list_intents(status="FAILED")
        assert len(done) == 1 and done[0]["node_id"] == i1
        assert done[0]["completed_at"]
        assert done[0]["payload"] == {"seed": "A", "finding": "confirmed"}

        assert len(failed) == 1 and failed[0]["node_id"] == i2
        assert failed[0]["completed_at"]
        assert failed[0]["payload"] == {"seed": "B", "error": "timeout"}


def test_reclaim_stale_intents_across_separate_connections(tmp_path: Path):
    db_path = tmp_path / "reclaim.db"
    with Database(str(db_path), encrypt_at_rest=False) as db1:
        i1 = db1.queue_intent("crash-target", priority=10.0, task_id="t-rec")
        i2 = db1.queue_intent("alive-target", priority=5.0, task_id="t-rec")
        i3 = db1.queue_intent("done-target", priority=1.0, task_id="t-rec")

        c1 = db1.claim_next_intent("w-crash", task_id="t-rec")
        c2 = db1.claim_next_intent("w-alive", task_id="t-rec")
        c3 = db1.claim_next_intent("w-done", task_id="t-rec")
        assert c1 and c1["node_id"] == i1
        assert c2 and c2["node_id"] == i2
        assert c3 and c3["node_id"] == i3
        assert db1.complete_intent(i3, status="DONE") is True

    with Database(str(db_path), encrypt_at_rest=False) as db2:
        reclaimed = db2.reclaim_stale_intents(worker_id="w-crash")
        assert reclaimed == 1

        pending = db2.list_intents(status="PENDING", task_id="t-rec")
        assert [p["node_id"] for p in pending] == [i1]
        assert pending[0]["claimed_by"] == ""

        still_claimed = db2.list_intents(status="CLAIMED", task_id="t-rec")
        assert [c["node_id"] for c in still_claimed] == [i2]

    with Database(str(db_path), encrypt_at_rest=False) as db3:
        resumed = db3.claim_next_intent("w-resume", task_id="t-rec")
        assert resumed is not None and resumed["node_id"] == i1

        reclaimed_all = db3.reclaim_stale_intents(task_id="t-rec")
        assert reclaimed_all == 2  # i1 and i2; i3 remains DONE
        done_rows = db3.list_intents(status="DONE", task_id="t-rec")
        assert [d["node_id"] for d in done_rows] == [i3]


# ---------------------------------------------------------------------------
# Group D: Storage Stats, Cleanup & ResearchKnowledgeGraph Compatibility
# ---------------------------------------------------------------------------


def test_storage_stats_and_clean_db_with_blackboard_nodes(tmp_path: Path):
    db_path = tmp_path / "stats.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        db.add_fact("fact-1")
        db.add_fact("fact-2")
        db.queue_intent("intent-1")
        db.queue_intent("intent-2")
        db.add_hint("hint-1")

        stats = db.get_storage_stats()
        assert stats["table_counts"]["blackboard_nodes"] == 5
        assert stats["total_rows"] >= 5

        # keep_findings=True must preserve blackboard_nodes
        db.clean_db(keep_rfcs=True, keep_findings=True, vacuum=True)
        assert db.get_storage_stats()["table_counts"]["blackboard_nodes"] == 5

        # keep_findings=False clears blackboard_nodes and vacuums cleanly
        res = db.clean_db(keep_rfcs=False, keep_findings=False, vacuum=True)
        assert res["tables_cleared"]["blackboard_nodes"] == 5
        assert db.get_storage_stats()["table_counts"]["blackboard_nodes"] == 0


def test_research_knowledge_graph_zero_arg_backward_compatibility():
    kg = ResearchKnowledgeGraph()
    kg.add_node("RFC9112", "RFC", "HTTP/1.1")
    kg.add_node("REQ-01", "REQUIREMENT", "Must reject invalid Content-Length")
    kg.add_node("REQ-02", "REQUIREMENT", "Must reject bare LF")
    kg.add_edge("RFC9112", "REQ-01", "DEFINES")
    kg.add_edge("RFC9112", "REQ-02", "DEFINES")
    kg.add_node("VULN-101", "VULNERABILITY", "CL.TE Smuggling")
    kg.record_testing_event("REQ-01", "VULN-101", is_vulnerability=True)

    cov = kg.calculate_specification_coverage()
    assert cov["total_requirements"] == 2
    assert cov["tested_count"] == 1
    assert cov["untested_count"] == 1
    assert cov["coverage_percent"] == 50.0
    assert "REQ-02" in cov["blind_spots"]

    trace = kg.get_lineage_trace("VULN-101")
    assert [step["node_id"] for step in trace] == ["VULN-101", "REQ-01", "RFC9112"]


def test_research_knowledge_graph_with_db_mirroring(tmp_path: Path):
    db_path = tmp_path / "kg.db"
    with Database(str(db_path), encrypt_at_rest=False) as db:
        kg = ResearchKnowledgeGraph(db=db, task_id="kg-task", domain="http")
        kg.add_node("RFC9112", "RFC", "HTTP/1.1")
        kg.add_node("SEC-6", "SECTION", "Message Body")
        kg.add_node("REQ-01", "REQUIREMENT", "Reject conflicting CL", attributes={"rfc_id": "RFC9112"})
        kg.add_node("REQ-02", "REQUIREMENT", "Reject obs-fold", attributes={"rfc_id": "RFC9112"})
        kg.add_node("TECH-01", "TECHNIQUE", "Chunk extension smuggling", attributes={"rfc_id": "RFC9112"})
        kg.add_node("ANOM-01", "ANOMALY", "Backend returned 200 on duplicate CL")
        kg.add_node("VULN-01", "VULNERABILITY", "Confirmed CL.CL smuggling")

        # Structural nodes are not mirrored; REQUIREMENT/TECHNIQUE -> PENDING INTENT; ANOMALY/VULNERABILITY -> FACT
        intents = db.list_intents(status="PENDING", task_id="kg-task")
        intent_ids = {i["node_id"] for i in intents}
        assert intent_ids == {"kg:REQ-01", "kg:REQ-02", "kg:TECH-01"}
        tech = next(i for i in intents if i["node_id"] == "kg:TECH-01")
        assert tech["priority"] == 5.0
        assert tech["rfc_id"] == "RFC9112"

        facts = db.get_facts(task_id="kg-task")
        assert {f["node_id"] for f in facts} == {"kg:ANOM-01", "kg:VULN-01"}

        # record_testing_event mirrors an event FACT and completes kg:REQ-01 INTENT
        kg.record_testing_event("REQ-01", "VULN-01", is_vulnerability=True)
        done_intents = db.list_intents(status="DONE", task_id="kg-task")
        assert [d["node_id"] for d in done_intents] == ["kg:REQ-01"]

        facts_after = db.get_facts(task_id="kg-task")
        assert "kg:event:REQ-01:VULN-01" in {f["node_id"] for f in facts_after}

        # Explicit helper methods
        kg.record_fact("OBS-CUSTOM", "Observed custom parser quirk", node_type="CUSTOM_OBS")
        kg.record_intent("HYP-CUSTOM", "Test custom quirk", priority=9.0)
        assert "kg:OBS-CUSTOM" in {f["node_id"] for f in db.get_facts(task_id="kg-task")}
        assert "kg:HYP-CUSTOM" in {i["node_id"] for i in db.list_intents(status="PENDING", task_id="kg-task")}

    # Reopen and verify persistence + blind-spot sync helper
    with Database(str(db_path), encrypt_at_rest=False) as db_reopen:
        assert len(db_reopen.get_facts(task_id="kg-task")) == 4
        assert len(db_reopen.list_intents(status="DONE", task_id="kg-task")) == 1

        kg2 = ResearchKnowledgeGraph(db=None)
        kg2.add_node("REQ-BLIND", "REQUIREMENT", "Untested requirement", attributes={"rfc_id": "RFC9110"})
        kg2.db = db_reopen
        kg2.task_id = "kg-task"
        created = kg2.sync_blind_spots_to_intents(priority=4.0)
        assert created == ["kg:REQ-BLIND"]
        assert any(i["node_id"] == "kg:REQ-BLIND" for i in db_reopen.list_intents(status="PENDING", task_id="kg-task"))


def test_research_knowledge_graph_duck_typed_and_failing_db_resilience():
    class GenericBlackboardOnly:
        def __init__(self):
            self.calls: List[Dict[str, Any]] = []

        def add_blackboard_node(self, node_type: str, content: str, **kwargs):
            self.calls.append({"node_type": node_type, "content": content, **kwargs})
            return kwargs.get("node_id", "gen-1")

    generic_db = GenericBlackboardOnly()
    kg_gen = ResearchKnowledgeGraph(db=generic_db)
    kg_gen.add_node("REQ-G1", "REQUIREMENT", "Generic req")
    kg_gen.add_node("VULN-G1", "VULNERABILITY", "Generic vuln")
    kg_gen.record_testing_event("REQ-G1", "VULN-G1", is_vulnerability=True)
    assert len(generic_db.calls) == 3
    assert generic_db.calls[0]["node_type"] == "INTENT"
    assert generic_db.calls[1]["node_type"] == "FACT"
    assert generic_db.calls[2]["node_type"] == "FACT"

    class FailingDB:
        def add_fact(self, *args, **kwargs):
            raise RuntimeError("disk full")

        def queue_intent(self, *args, **kwargs):
            raise RuntimeError("disk full")

        def complete_intent(self, *args, **kwargs):
            raise RuntimeError("disk full")

    kg_fail = ResearchKnowledgeGraph(db=FailingDB())
    kg_fail.add_node("REQ-F1", "REQUIREMENT", "Failing DB req")
    kg_fail.add_node("VULN-F1", "VULNERABILITY", "Failing DB vuln")
    kg_fail.record_testing_event("REQ-F1", "VULN-F1", is_vulnerability=True)
    cov = kg_fail.calculate_specification_coverage()
    assert cov["total_requirements"] == 1
    assert cov["tested_count"] == 1
    assert cov["coverage_percent"] == 100.0


# ---------------------------------------------------------------------------
# Group E: Multi-Process Cold-Start, Pre-WAL Upgrade & batch_writes() Contention
# ---------------------------------------------------------------------------


def _run_synchronized_subprocesses(
    repo_root: Path,
    gate_dir: Path,
    num_workers: int,
    worker_script: str,
    extra_args_per_worker: List[List[str]],
    timeout: float = 45.0,
) -> List[Dict[str, Any]]:
    """Spawns `num_workers` OS Python processes synchronized on a ready/go file barrier."""
    go_flag = gate_dir / "go.flag"
    procs: List[subprocess.Popen] = []
    for idx in range(num_workers):
        ready_flag = gate_dir / f"ready_{idx}.flag"
        cmd = [
            sys.executable,
            "-c",
            worker_script,
            str(repo_root),
            str(ready_flag),
            str(go_flag),
            str(idx),
            *extra_args_per_worker[idx],
        ]
        procs.append(
            subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
        )

    deadline = time.monotonic() + timeout
    for idx in range(num_workers):
        ready_flag = gate_dir / f"ready_{idx}.flag"
        while not ready_flag.exists():
            if time.monotonic() > deadline:
                for p in procs:
                    p.kill()
                raise TimeoutError(f"Worker {idx} failed to reach ready barrier within {timeout}s")
            time.sleep(0.01)

    go_flag.write_text("GO", encoding="utf-8")

    results: List[Dict[str, Any]] = []
    for idx, proc in enumerate(procs):
        remaining = max(1.0, deadline - time.monotonic())
        stdout, stderr = proc.communicate(timeout=remaining)
        assert proc.returncode == 0, f"Worker {idx} exited with {proc.returncode}: stderr={stderr!r}, stdout={stdout!r}"
        results.append(json.loads(stdout.strip()))
    return results


def test_batch_writes_read_then_claim_with_concurrent_writer(tmp_path: Path):
    db_path = tmp_path / "batch_snap.db"
    with Database(str(db_path), encrypt_at_rest=False) as init_db:
        init_db.add_fact("seed-fact", task_id="snap")
        i1 = init_db.queue_intent("snap-intent-1", priority=10.0, task_id="snap")

    db_a = Database(str(db_path), timeout=30.0, encrypt_at_rest=False)
    db_b = Database(str(db_path), timeout=30.0, encrypt_at_rest=False)
    a_entered_batch = threading.Event()
    writer_errors: List[BaseException] = []

    def concurrent_writer() -> None:
        try:
            assert a_entered_batch.wait(timeout=10.0)
            db_b.add_fact("concurrent-writer-fact", task_id="snap", source_agent="db_b")
        except BaseException as exc:
            writer_errors.append(exc)

    writer_thread = threading.Thread(target=concurrent_writer)
    writer_thread.start()
    try:
        with db_a.batch_writes():
            a_entered_batch.set()
            facts = db_a.get_facts(task_id="snap")
            assert len(facts) >= 1
            # Give db_b time to hit the lock while db_a is mid-batch before claim_next_intent()
            time.sleep(0.05)
            claimed = db_a.claim_next_intent("worker-snap-a", task_id="snap")
            assert claimed is not None
            assert claimed["node_id"] == i1
            assert claimed["status"] == "CLAIMED"
            db_a.add_fact("batch-claimed-fact", task_id="snap", parent_node_id=i1)

        writer_thread.join(timeout=15.0)
        assert not writer_thread.is_alive()
        assert not writer_errors, f"Concurrent writer failed: {writer_errors}"

        all_facts = db_a.get_facts(task_id="snap")
        contents = {f["content"] for f in all_facts}
        assert {"seed-fact", "concurrent-writer-fact", "batch-claimed-fact"} == contents
        claimed_list = db_a.list_intents(status="CLAIMED", task_id="snap")
        assert [c["node_id"] for c in claimed_list] == [i1]
    finally:
        db_b.close()
        db_a.close()


def test_batch_writes_claim_contention_multithread_and_multiprocess(tmp_path: Path):
    # Part 1: Multi-thread across independent connections inside batch_writes()
    mt_db_path = tmp_path / "batch_mt.db"
    total_intents = 40
    num_threads = 6
    with Database(str(mt_db_path), encrypt_at_rest=False) as init_db:
        for idx in range(total_intents):
            init_db.queue_intent(f"mt-bw-{idx}", priority=float(idx % 5), task_id="bw-mt")

    barrier = threading.Barrier(num_threads)
    claimed_by_thread: List[List[str]] = [[] for _ in range(num_threads)]
    mt_errors: List[BaseException] = []
    err_lock = threading.Lock()

    def mt_worker(tid: int) -> None:
        conn_db = None
        try:
            conn_db = Database(str(mt_db_path), timeout=30.0, encrypt_at_rest=False)
            barrier.wait(timeout=10.0)
            while True:
                with conn_db.batch_writes():
                    conn_db.get_facts(task_id="bw-mt", limit=5)
                    row = conn_db.claim_next_intent(f"mt-bw-{tid}", task_id="bw-mt")
                    if row is None:
                        break
                    conn_db.add_fact(
                        f"done-{row['node_id']}",
                        task_id="bw-mt",
                        parent_node_id=row["node_id"],
                    )
                    claimed_by_thread[tid].append(row["node_id"])
        except BaseException as exc:
            with err_lock:
                mt_errors.append(exc)
        finally:
            if conn_db is not None:
                conn_db.close()

    threads = [threading.Thread(target=mt_worker, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30.0)

    assert not mt_errors, f"Multi-thread batch_writes errors: {mt_errors}"
    mt_claimed = [nid for batch in claimed_by_thread for nid in batch]
    assert len(mt_claimed) == total_intents
    assert len(set(mt_claimed)) == total_intents
    with Database(str(mt_db_path), encrypt_at_rest=False) as verify_mt:
        assert verify_mt.list_intents(status="PENDING", task_id="bw-mt") == []
        assert len(verify_mt.get_facts(task_id="bw-mt", limit=100)) == total_intents

    # Part 2: Multi-process contention across 6 OS processes inside batch_writes()
    mp_db_path = tmp_path / "batch_mp.db"
    with Database(str(mp_db_path), encrypt_at_rest=False) as init_mp:
        for idx in range(total_intents):
            init_mp.queue_intent(f"mp-bw-{idx}", priority=float(idx % 6), task_id="bw-mp")

    worker_script = """
import json, sys, time
from pathlib import Path
repo_root, ready_path, go_path, idx, db_path = sys.argv[1:6]
sys.path.insert(0, repo_root)
from database import Database

Path(ready_path).write_text("1", encoding="utf-8")
while not Path(go_path).exists():
    time.sleep(0.002)

claimed = []
with Database(db_path, timeout=30.0, encrypt_at_rest=False) as db:
    while True:
        with db.batch_writes():
            db.get_facts(task_id="bw-mp", limit=5)
            row = db.claim_next_intent(f"mp-worker-{idx}", task_id="bw-mp")
            if row is None:
                break
            db.add_fact(f"mp-fact-{row['node_id']}", task_id="bw-mp", parent_node_id=row["node_id"])
            claimed.append(row["node_id"])
print(json.dumps({"worker": int(idx), "claimed": claimed}))
"""
    repo_root = Path(__file__).resolve().parent.parent
    gate_dir = tmp_path / "mp_batch_gate"
    gate_dir.mkdir()
    num_procs = 6
    results = _run_synchronized_subprocesses(
        repo_root=repo_root,
        gate_dir=gate_dir,
        num_workers=num_procs,
        worker_script=worker_script,
        extra_args_per_worker=[[str(mp_db_path)] for _ in range(num_procs)],
    )
    mp_claimed = [nid for res in results for nid in res["claimed"]]
    assert len(mp_claimed) == total_intents
    assert len(set(mp_claimed)) == total_intents
    with Database(str(mp_db_path), encrypt_at_rest=False) as verify_mp:
        assert verify_mp.list_intents(status="PENDING", task_id="bw-mp") == []
        assert len(verify_mp.list_intents(status="CLAIMED", task_id="bw-mp")) == total_intents
        assert len(verify_mp.get_facts(task_id="bw-mp", limit=100)) == total_intents


def test_multiprocess_cold_start_and_pre_wal_upgrade(tmp_path: Path):
    repo_root = Path(__file__).resolve().parent.parent
    num_procs = 8

    # 1. Simultaneous cold-start on a non-existent DB across 8 OS processes
    cold_db = tmp_path / "cold_start_mp.db"
    assert not cold_db.exists()
    cold_script = """
import json, sys, time
from pathlib import Path
repo_root, ready_path, go_path, idx, db_path = sys.argv[1:6]
sys.path.insert(0, repo_root)
from database import Database

Path(ready_path).write_text("1", encoding="utf-8")
while not Path(go_path).exists():
    time.sleep(0.002)

with Database(db_path, timeout=30.0, encrypt_at_rest=False) as db:
    fid = db.add_fact(f"cold-fact-{idx}", task_id="cold", source_agent=f"proc-{idx}")
print(json.dumps({"worker": int(idx), "fact_id": fid}))
"""
    cold_gate = tmp_path / "cold_gate"
    cold_gate.mkdir()
    cold_results = _run_synchronized_subprocesses(
        repo_root=repo_root,
        gate_dir=cold_gate,
        num_workers=num_procs,
        worker_script=cold_script,
        extra_args_per_worker=[[str(cold_db)] for _ in range(num_procs)],
    )
    assert len(cold_results) == num_procs

    with Database(str(cold_db), encrypt_at_rest=False) as verify_cold:
        mode = verify_cold.conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(mode).strip().lower() == "wal"
        mig = verify_cold.conn.execute(
            "SELECT version FROM schema_migrations WHERE version = '004_blackboard_nodes'"
        ).fetchone()
        assert mig is not None
        facts = verify_cold.get_facts(task_id="cold", limit=50)
        assert len(facts) == num_procs

    # 2. Simultaneous pre-WAL (DELETE-mode) legacy DB upgrade across 8 OS processes
    legacy_db = tmp_path / "legacy_delete_mp.db"
    raw = sqlite3.connect(str(legacy_db))
    try:
        raw.execute("PRAGMA journal_mode = DELETE;")
        raw.executescript(
            """
            CREATE TABLE rfcs (
                rfc_id TEXT PRIMARY KEY,
                title TEXT,
                source_url TEXT,
                doc_path TEXT,
                fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE fragments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rfc_id TEXT,
                content TEXT,
                keywords TEXT
            );
            CREATE TABLE attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id TEXT UNIQUE NOT NULL,
                goal TEXT,
                steps_json TEXT,
                raw_payload TEXT,
                severity TEXT,
                is_verified BOOLEAN DEFAULT 0,
                evidence TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE chain_retests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id TEXT NOT NULL,
                retest_status TEXT DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE approval_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL DEFAULT 'default',
                action_type TEXT NOT NULL,
                decision TEXT NOT NULL,
                decided_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO schema_migrations (version) VALUES
                ('001_attack_chains_artex_cols'),
                ('002_chain_retests_original_traffic_id'),
                ('003_approval_decisions_action_summary');
            INSERT INTO rfcs (rfc_id, title, source_url, doc_path)
            VALUES ('RFC9112', 'HTTP/1.1', 'https://example.invalid/rfc9112', 'rfc9112.txt');
            """
        )
        raw.commit()
        pre_mode = raw.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(pre_mode).strip().lower() == "delete"
    finally:
        raw.close()

    legacy_script = """
import json, sys, time
from pathlib import Path
repo_root, ready_path, go_path, idx, db_path = sys.argv[1:6]
sys.path.insert(0, repo_root)
from database import Database

Path(ready_path).write_text("1", encoding="utf-8")
while not Path(go_path).exists():
    time.sleep(0.002)

with Database(db_path, timeout=30.0, encrypt_at_rest=False) as db:
    fid = db.add_fact(f"legacy-fact-{idx}", task_id="legacy-up", source_agent=f"proc-{idx}")
print(json.dumps({"worker": int(idx), "fact_id": fid}))
"""
    legacy_gate = tmp_path / "legacy_gate"
    legacy_gate.mkdir()
    legacy_results = _run_synchronized_subprocesses(
        repo_root=repo_root,
        gate_dir=legacy_gate,
        num_workers=num_procs,
        worker_script=legacy_script,
        extra_args_per_worker=[[str(legacy_db)] for _ in range(num_procs)],
    )
    assert len(legacy_results) == num_procs

    with Database(str(legacy_db), encrypt_at_rest=False) as verify_leg:
        mode = verify_leg.conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(mode).strip().lower() == "wal"
        mig = verify_leg.conn.execute(
            "SELECT version FROM schema_migrations WHERE version = '004_blackboard_nodes'"
        ).fetchone()
        assert mig is not None
        rfc_row = verify_leg.conn.execute("SELECT title FROM rfcs WHERE rfc_id = 'RFC9112'").fetchone()
        assert rfc_row is not None and rfc_row["title"] == "HTTP/1.1"
        facts = verify_leg.get_facts(task_id="legacy-up", limit=50)
        assert len(facts) == num_procs
