"""
Comprehensive Tests for Dream-RSI Replay-Tree Meta-Exploration RL & 4-Baseline Benchmark.

Covers:
1. SQLite `blackboard_nodes` (`parent_node_id` lineage) + `evaluations` +
   `reproducible_vulnerabilities` + `attack_chains` + ARTEX `ExplorationGraph` ingestion.
2. Deterministic, zero-network, zero-LLM `simulate_policy_traversal` including
   `branch_width`, `depth_vs_breadth_alpha`, `early_stop_patience`, and `HINT` boosting.
3. Strictly disjoint `split_train_val` and held-out validation promotion gate.
4. Explicit `simulator_backend` provenance labels (`recorded_blackboard_replay`,
   `local_testlab_live`, `synthetic_heuristic_fallback`).
5. `DreamPolicyStore` stack-profile lookup, legacy JSON backward-compatibility, and
   `AdaptiveBanditScheduler` bounded prior injection + `active_meta_controls`.
6. Exact Student-t 95% Confidence Intervals and standardized 5-policy matched-seed
   empirical benchmark (offline `"recorded_blackboard_replay"` + loopback
   `TestLabServer` `"local_testlab_live"` + CLI `--live-lab --json`).
"""

from __future__ import annotations

import json
import math
import socket
import subprocess
import sys
from pathlib import Path
from typing import List

import pytest

from database import Database
from engine.bandit_scheduler import AdaptiveBanditScheduler
from engine.dream_policy_store import DreamPolicyStore
from engine.dream_replay_pool import (
    BACKEND_LIVE_TESTLAB,
    BACKEND_RECORDED_REPLAY,
    BACKEND_SYNTHETIC_FALLBACK,
    DiscoveryTree,
    ReplayNode,
    ReplayTreePool,
    compute_replay_reward,
)
from engine.dream_rl_benchmark import (
    POLICY_ORDER,
    compute_confidence_interval,
    run_dream_benchmark_cli,
    run_live_lab_benchmark,
    run_replay_benchmark,
    student_t_critical,
)
from engine.dream_rsi_optimizer import DreamPolicy, DreamRSIOptimizer
from engine.dream_world_model import ProtocolWorldModel
from engine.dual_graph_engine import ExplorationGraph


def _populate_realistic_blackboard_db(db_path: Path, num_tasks: int = 8) -> Database:
    """
    Populates a real SQLite `Database` with `num_tasks` Cairn `blackboard_nodes`
    discovery trees plus `probes`, `evaluations`, `implementation_anomalies`,
    `reproducible_vulnerabilities`, and `attack_chains`.

    Tree structure across tasks (consistent underlying signal across nginx targets):
      - Branch A (queued first, FIFO trap): `HEADER_TAB_SPACING` / `abnf_seed` / `static_noise`
        -> mostly noise discards & conformant dead ends.
      - Branch B: `OBS_FOLD_LINE_JOIN` / `llm_candidate` / `legacy_headers`
        -> conformant dead ends & environmental noise.
      - Branch C: `TE_CL_DUAL_HEADER` / `cascade_intent` / `http_framing`
        -> anomaly -> confirmed reproducible vulnerability -> cascade follow-up -> verified attack chain.
      - Branch D: `MULTIPART_BYTERANGES_SHARED_PARSER` / `dual_graph_multihop` / `http_framing`
        -> anomaly -> confirmed vulnerability.
    """
    db = Database(str(db_path), encrypt_at_rest=False)
    for t_idx in range(num_tasks):
        tid = f"task-nginx-{t_idx:02d}"
        # Branch A: Noisy ABNF branch queued first (FIFO baseline gets trapped here)
        a_root = f"{tid}:a_root"
        db.queue_intent(
            "GET / HTTP/1.1\r\nHost: nginx.local\r\nX-Tab :\t1\r\n\r\n",
            priority=12.0,
            node_id=a_root,
            task_id=tid,
            domain="static_noise",
            rfc_id="RFC9112-5.1",
            source_agent="fetch_and_chunk_agent",
            payload={
                "mutator_family": "HEADER_TAB_SPACING",
                "outcome": "NOISE",
                "is_noise_discard": True,
                "stack_profile": "nginx",
            },
        )
        prev_a = a_root
        for k in range(5):
            nid = f"{tid}:a_noise_{k}"
            db.queue_intent(
                f"GET /static/{k} HTTP/1.1\r\nHost: nginx.local\r\nX-Tab :\t{k}\r\n\r\n",
                priority=10.0 - k * 0.5,
                node_id=nid,
                task_id=tid,
                domain="static_noise",
                rfc_id="RFC9112-5.1",
                source_agent="fetch_and_chunk_agent",
                parent_node_id=prev_a if k < 3 else a_root,
                payload={
                    "mutator_family": "HEADER_TAB_SPACING",
                    "outcome": "NOISE" if k % 2 == 0 else "CONFORMANT",
                    "is_noise_discard": (k % 2 == 0),
                    "stack_profile": "nginx",
                },
            )
            prev_a = nid

        # Branch B: Legacy OBS_FOLD dead-ends
        b_root = f"{tid}:b_root"
        db.queue_intent(
            "GET /status HTTP/1.1\r\nHost: nginx.local\r\nX-Fold: a\r\n b\r\n\r\n",
            priority=11.0,
            node_id=b_root,
            task_id=tid,
            domain="legacy_headers",
            rfc_id="RFC9112-5.2",
            source_agent="llm_generator_agent",
            payload={
                "mutator_family": "OBS_FOLD_LINE_JOIN",
                "outcome": "NOISE",
                "is_noise_discard": True,
                "stack_profile": "nginx",
            },
        )
        for k in range(4):
            nid = f"{tid}:b_dead_{k}"
            db.queue_intent(
                f"GET /legacy/{k} HTTP/1.1\r\nHost: nginx.local\r\nX-Fold: a\r\n {k}\r\n\r\n",
                priority=9.0 - k * 0.5,
                node_id=nid,
                task_id=tid,
                domain="legacy_headers",
                rfc_id="RFC9112-5.2",
                source_agent="llm_generator_agent",
                parent_node_id=b_root,
                payload={
                    "mutator_family": "OBS_FOLD_LINE_JOIN",
                    "outcome": "NOISE" if k < 2 else "CONFORMANT",
                    "is_noise_discard": (k < 2),
                    "stack_profile": "nginx",
                },
            )

        # Branch C: High-yield TE_CL_DUAL_HEADER cascade lineage joined with SQLite tables
        anom_id = f"ANOM-{tid}-CLTE"
        vuln_id = f"VULN-{tid}-CLTE"
        chain_id = f"CHAIN-{tid}-CLTE"
        probe_text = (
            f"POST /t/{t_idx} HTTP/1.1\r\nHost: nginx.local\r\n"
            "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )

        with db._lock:
            with db._tx():
                cur = db.conn.execute(
                    "INSERT INTO probes (rationale, raw_request, source_type) VALUES (?, ?, ?)",
                    ("CL.TE desync hypothesis", probe_text, "cascade"),
                )
                probe_id = int(cur.lastrowid)
                db.conn.execute(
                    "INSERT INTO evaluations (finding_status, probe_id, target_host, target_port, is_vulnerable, desync_class, details) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    ("CONFIRMED", probe_id, "nginx.local", 8080, 1, "CL_TE_DESYNCHRONIZATION", "Confirmed desync"),
                )
                db.conn.execute(
                    "INSERT INTO implementation_anomalies (anomaly_id, target_engine, category, observed_behavior, is_environmental_noise) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (anom_id, "nginx/1.25", "CL_TE_DESYNCHRONIZATION", "Pipeline boundary split", 0),
                )
                db.conn.execute(
                    "INSERT INTO reproducible_vulnerabilities (vuln_id, anomaly_id, impact, minimized_probe, reproducibility_rate, verification_attempts, successful_reproductions) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (vuln_id, anom_id, "REQUEST_SMUGGLING", probe_text, 1.0, 3, 3),
                )
                db.conn.execute(
                    "INSERT INTO attack_chains (chain_id, title, attack_type, target_host, target_endpoint, framing_anomaly_id, steps_json, is_verified, task_id, poe_level, verification_status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (chain_id, "Smuggling -> Cache Poison", "CL_TE_CHAIN", "nginx.local", "/", anom_id, "[]", 1, tid, 3, "CONFIRMED"),
                )

        c_root = f"{tid}:c_clte_intent"
        db.queue_intent(
            probe_text,
            priority=10.0,
            node_id=c_root,
            task_id=tid,
            domain="http_framing",
            rfc_id="RFC9112-6.3",
            source_agent="cascade_and_publish_agent",
            payload={
                "mutator_family": "TE_CL_DUAL_HEADER",
                "source_type": "cascade",
                "outcome": "ANOMALY",
                "anomaly_id": anom_id,
                "stack_profile": "nginx",
            },
        )
        c_vuln_fact = f"fact:vuln:{vuln_id}:{tid}"
        db.add_fact(
            f"Confirmed REQUEST_SMUGGLING {vuln_id}",
            node_id=c_vuln_fact,
            task_id=tid,
            domain="http_framing",
            rfc_id="RFC9112-6.3",
            source_agent="triage_debugger_agent",
            parent_node_id=c_root,
            payload={
                "mutator_family": "TE_CL_DUAL_HEADER",
                "vuln_id": vuln_id,
                "anomaly_id": anom_id,
                "reproducibility_rate": 1.0,
                "stack_profile": "nginx",
            },
        )
        c_cascade_2 = f"intent:cascade:{tid}:followup"
        db.queue_intent(
            "POST /admin HTTP/1.1\r\nHost: nginx.local\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            priority=15.0,
            node_id=c_cascade_2,
            task_id=tid,
            domain="http_framing",
            rfc_id="RFC9112-6.3",
            source_agent="cascade_and_publish_agent",
            parent_node_id=c_vuln_fact,
            payload={
                "mutator_family": "TE_CL_DUAL_HEADER",
                "source_type": "cascade",
                "chain_id": chain_id,
                "stack_profile": "nginx",
            },
        )

        # Branch D: High-yield MULTIPART shared-parser branch
        d_root = f"{tid}:d_mp_root"
        db.queue_intent(
            "POST /range HTTP/1.1\r\nHost: nginx.local\r\nContent-Type: multipart/byteranges; boundary=B\r\n\r\n",
            priority=10.5,
            node_id=d_root,
            task_id=tid,
            domain="http_framing",
            rfc_id="RFC9110-14",
            source_agent="DualGraphAttackEngine",
            payload={
                "mutator_family": "MULTIPART_BYTERANGES_SHARED_PARSER",
                "source_type": "dual_graph",
                "outcome": "ANOMALY",
                "stack_profile": "nginx",
            },
        )
        d_vuln = f"{tid}:d_mp_vuln"
        db.add_fact(
            f"Confirmed shared parser confusion on {tid}",
            node_id=d_vuln,
            task_id=tid,
            domain="http_framing",
            rfc_id="RFC9110-14",
            source_agent="DualGraphAttackEngine",
            parent_node_id=d_root,
            payload={
                "mutator_family": "MULTIPART_BYTERANGES_SHARED_PARSER",
                "source_type": "dual_graph",
                "is_confirmed_vuln": True,
                "poe_level": 3,
                "stack_profile": "nginx",
            },
        )

    return db


def test_replay_tree_ingestion_from_sqlite_and_exploration_graph(tmp_path):
    """Verifies SQLite blackboard_nodes lineage + outcome table joins + ARTEX ExplorationGraph ingestion."""
    db_file = tmp_path / "replay_ingest.db"
    db = _populate_realistic_blackboard_db(db_file, num_tasks=4)
    try:
        pool = ReplayTreePool()
        count = pool.ingest_from_db(db)
        assert count == 4
        assert len(pool) == 4

        tree = pool.get_tree("bb:task-nginx-00")
        assert tree is not None
        assert tree.stack_profile == "nginx"
        assert tree.max_depth >= 2

        # Verify parent -> child topological lineage and non-duplication of confirmed vuln across INTENT + FACT
        c_root = tree.nodes["task-nginx-00:c_clte_intent"]
        c_fact = tree.nodes["fact:vuln:VULN-task-nginx-00-CLTE:task-nginx-00"]
        c_casc = tree.nodes["intent:cascade:task-nginx-00:followup"]
        assert c_fact.node_id in c_root.children
        assert c_casc.node_id in c_fact.children
        assert c_root.depth == 0
        assert c_fact.depth == 1
        assert c_casc.depth == 2
        assert c_fact.is_confirmed_vuln is True
        assert c_fact.poe_level == 3
        assert c_casc.is_attack_chain is True
        assert c_casc.is_confirmed_vuln is True
        # Dedicated vuln FACT exists -> parent INTENT remains anomaly (not double-counted as vuln)
        assert c_root.is_anomaly is True
        assert c_root.is_confirmed_vuln is False

        # Verify path-based ingestion produces identical pool size
        pool_from_path = ReplayTreePool()
        assert pool_from_path.ingest_from_db(str(db_file)) == 4

        # Verify ARTEX ExplorationGraph ingestion handles reciprocal yields/derived_from edges cleanly
        eg = ExplorationGraph(db=None, task_id="artex-task-1")
        eg.add_goal("goal-1", "Verify HTTP desync to admin pivot", attributes={"domain": "http_framing", "stack_profile": "envoy"})
        eg.add_fact("fact-1", "CL.TE boundary split observed", source_node_id="goal-1", attributes={"domain": "http_framing", "is_anomaly": True})
        eg.add_intent("cand-1", "ATTACK_CANDIDATE", "Multi-hop cache poison", status="PROVEN", attributes={"domain": "http_framing", "poe_level": 3})
        eg.add_relation("fact-1", "cand-1", "spawns")
        eg.add_relation("cand-1", "fact-1", "derived_from")

        eg_added = pool.ingest_exploration_graph(eg, task_id="artex-task-1")
        assert eg_added == 1
        eg_tree = pool.get_tree("eg:artex-task-1")
        assert eg_tree is not None
        assert eg_tree.stack_profile == "envoy"
        assert eg_tree.nodes["goal-1"].depth == 0
        assert eg_tree.nodes["fact-1"].depth == 1
        assert eg_tree.nodes["cand-1"].depth == 2
        assert eg_tree.nodes["cand-1"].is_confirmed_vuln is True
        assert eg_tree.nodes["cand-1"].is_attack_chain is True

        # Verify ProtocolWorldModel auto-populates replay_pool and updates backend_label
        wm = ProtocolWorldModel(target_host="127.0.0.1", target_port=8080)
        assert wm.backend_label == BACKEND_SYNTHETIC_FALLBACK
        loaded_probes = wm.ingest_history_from_db(str(db_file))
        assert loaded_probes == 4
        assert len(wm.replay_pool) == 4
        assert wm.backend_label == BACKEND_RECORDED_REPLAY
        assert wm.server_signature == "nginx"
    finally:
        db.close()


def test_zero_network_deterministic_replay_and_meta_controls(tmp_path, monkeypatch):
    """Verifies zero socket calls, bit-for-bit determinism, early-stop pruning, and BFS/DFS bias."""
    db_file = tmp_path / "det_replay.db"
    db = _populate_realistic_blackboard_db(db_file, num_tasks=3)
    try:
        pool = ReplayTreePool()
        pool.ingest_from_db(db)
    finally:
        db.close()

    def _forbid_network(*args, **kwargs):
        raise AssertionError("Network socket I/O is strictly forbidden during offline replay!")

    monkeypatch.setattr(socket, "create_connection", _forbid_network)
    monkeypatch.setattr(socket, "socket", _forbid_network)

    tree = pool.get_tree("bb:task-nginx-00")
    assert tree is not None

    pol = DreamPolicy(
        generation=1,
        mutator_weights={
            "TE_CL_DUAL_HEADER": 0.55,
            "MULTIPART_BYTERANGES_SHARED_PARSER": 0.35,
            "HEADER_TAB_SPACING": 0.05,
            "OBS_FOLD_LINE_JOIN": 0.05,
        },
        branch_width=3,
        depth_vs_breadth_alpha=0.8,
        early_stop_patience=2,
        parallel_group_size=2,
        domain_weights={"http_framing": 3.0, "static_noise": 0.2, "legacy_headers": 0.2},
    )

    out1 = pool.simulate_policy_traversal(tree, pol, budget_steps=5, seed=123)
    out2 = pool.simulate_policy_traversal(tree, pol, budget_steps=5, seed=123)
    assert out1 == out2
    assert out1.simulator_backend == BACKEND_RECORDED_REPLAY
    assert out1.vulns_found >= 2
    assert out1.noise_discards == 0
    assert out1.reward == pytest.approx(
        compute_replay_reward(
            out1.vulns_found, out1.chains_found, out1.anomalies_found, out1.noise_discards, out1.steps_taken
        )
    )

    # Verify early-stop prunes dead branches when policy starts on noisy branch with patience=1
    noisy_first_pol = DreamPolicy(
        generation=1,
        mutator_weights={
            "HEADER_TAB_SPACING": 0.70,
            "OBS_FOLD_LINE_JOIN": 0.20,
            "TE_CL_DUAL_HEADER": 0.05,
            "MULTIPART_BYTERANGES_SHARED_PARSER": 0.05,
        },
        early_stop_patience=1,
        parallel_group_size=1,
        branch_width=4,
    )
    pruned_out = pool.simulate_policy_traversal(tree, noisy_first_pol, budget_steps=8, seed=7)
    assert pruned_out.early_stopped_branches >= 1

    # Verify BFS (alpha=0.0) vs DFS (alpha=1.0) depth bias on a symmetric 2-branch tree
    sym_nodes = {
        "r1": ReplayNode("r1", "", priority=1.0, mutator_family="GENERIC_PROBE"),
        "r1_c1": ReplayNode("r1_c1", "r1", priority=1.0, mutator_family="GENERIC_PROBE"),
        "r1_c1_g1": ReplayNode("r1_c1_g1", "r1_c1", priority=1.0, mutator_family="GENERIC_PROBE", is_confirmed_vuln=True),
        "r2": ReplayNode("r2", "", priority=1.0, mutator_family="GENERIC_PROBE", is_confirmed_vuln=True),
        "r3": ReplayNode("r3", "", priority=1.0, mutator_family="GENERIC_PROBE", is_confirmed_vuln=True),
    }
    sym_tree = DiscoveryTree(tree_id="sym", task_id="sym", nodes=sym_nodes).finalize_topology()
    bfs_pol = DreamPolicy(generation=0, depth_vs_breadth_alpha=0.0, parallel_group_size=1, early_stop_patience=10)
    dfs_pol = DreamPolicy(generation=0, depth_vs_breadth_alpha=1.0, parallel_group_size=1, early_stop_patience=10)
    bfs_out = pool.simulate_policy_traversal(sym_tree, bfs_pol, budget_steps=3, seed=42)
    dfs_out = pool.simulate_policy_traversal(sym_tree, dfs_pol, budget_steps=3, seed=42)
    assert set(bfs_out.visited_node_ids) == {"r1", "r2", "r3"}
    assert any(sym_tree.nodes[nid].depth >= 1 for nid in dfs_out.visited_node_ids)


def test_train_val_split_and_held_out_validation_promotion_gate():
    """Verifies disjoint train/val split and that candidates degrading held-out validation are rejected."""
    pool = ReplayTreePool()

    # Create anti-correlated train vs val trees to stress-test the validation gate:
    # Train trees reward HEADER_TAB_SPACING and penalize TE_CL_DUAL_HEADER;
    # Val trees reward TE_CL_DUAL_HEADER and penalize HEADER_TAB_SPACING!
    train_trees: List[DiscoveryTree] = []
    val_trees: List[DiscoveryTree] = []

    for i in range(4):
        tr = DiscoveryTree(
            tree_id=f"tr_{i}",
            task_id=f"tr_{i}",
            nodes={
                "tab_1": ReplayNode("tab_1", "", mutator_family="HEADER_TAB_SPACING", domain="d_tab", is_confirmed_vuln=True),
                "tab_2": ReplayNode("tab_2", "tab_1", mutator_family="HEADER_TAB_SPACING", domain="d_tab", is_confirmed_vuln=True),
                "clte_1": ReplayNode("clte_1", "", mutator_family="TE_CL_DUAL_HEADER", domain="d_clte", is_noise_discard=True),
                "clte_2": ReplayNode("clte_2", "clte_1", mutator_family="TE_CL_DUAL_HEADER", domain="d_clte", is_noise_discard=True),
            },
        ).finalize_topology()
        train_trees.append(tr)
        pool.add_tree(tr)

    for j in range(2):
        vl = DiscoveryTree(
            tree_id=f"vl_{j}",
            task_id=f"vl_{j}",
            nodes={
                "tab_1": ReplayNode("tab_1", "", mutator_family="HEADER_TAB_SPACING", domain="d_tab", is_noise_discard=True),
                "tab_2": ReplayNode("tab_2", "tab_1", mutator_family="HEADER_TAB_SPACING", domain="d_tab", is_noise_discard=True),
                "clte_1": ReplayNode("clte_1", "", mutator_family="TE_CL_DUAL_HEADER", domain="d_clte", is_confirmed_vuln=True),
                "clte_2": ReplayNode("clte_2", "clte_1", mutator_family="TE_CL_DUAL_HEADER", domain="d_clte", is_confirmed_vuln=True),
            },
        ).finalize_topology()
        val_trees.append(vl)
        pool.add_tree(vl)

    # Disjointness & determinism of split_train_val
    s_tr_1, s_vl_1 = pool.split_train_val(val_ratio=0.33, seed=42)
    s_tr_2, s_vl_2 = pool.split_train_val(val_ratio=0.33, seed=42)
    assert [t.tree_id for t in s_tr_1] == [t.tree_id for t in s_tr_2]
    assert [t.tree_id for t in s_vl_1] == [t.tree_id for t in s_vl_2]
    assert set(t.tree_id for t in s_tr_1).isdisjoint(set(t.tree_id for t in s_vl_1))
    assert len(s_vl_1) == 2

    wm = ProtocolWorldModel()
    wm.replay_pool = pool
    opt = DreamRSIOptimizer(wm)

    # Start incumbent favoring TE_CL_DUAL_HEADER (already strong on val_trees!)
    opt.active_policy = DreamPolicy(
        generation=0,
        mutator_weights={"TE_CL_DUAL_HEADER": 0.90, "HEADER_TAB_SPACING": 0.10},
        domain_weights={"d_clte": 3.0, "d_tab": 0.2},
        parallel_group_size=1,
        early_stop_patience=1,
    )
    baseline_val = opt.evaluate_policy_on_trees(opt.active_policy, val_trees, budget_steps=2, seed=5045)["mean_reward"]

    # Direct gate check: overfitted train candidate MUST be rejected on val_trees
    overfit_cand = DreamPolicy(
        generation=1,
        mutator_weights={"HEADER_TAB_SPACING": 0.95, "TE_CL_DUAL_HEADER": 0.05},
        domain_weights={"d_tab": 3.5, "d_clte": 0.1},
        parallel_group_size=1,
        early_stop_patience=1,
    )
    should_promote, cand_v, inc_v = opt.validate_policy_promotion(
        overfit_cand, opt.active_policy, val_trees, budget_steps=2, seed=42
    )
    assert should_promote is False
    assert cand_v < inc_v

    # Full CEM evolution on anti-correlated train vs val MUST reject overfitted promotions
    result = opt.evolve_meta_policy_from_replay(
        pool,
        generations=4,
        population_size=8,
        budget_steps=2,
        seed=42,
        train_trees=train_trees,
        val_trees=val_trees,
    )
    assert result.val_fitness_score >= baseline_val - 1e-6
    assert opt.last_evolution_report["promotions_rejected"] >= 1


def test_backend_labels_policy_store_and_bounded_bandit_priors(tmp_path):
    """Verifies explicit backend provenance labels, DreamPolicyStore stack profiles, and bounded bandit priors."""
    # 1. Cold-start synthetic fallback provenance
    cold_wm = ProtocolWorldModel()
    probe = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    sim_cold = cold_wm.simulate_probe(probe)
    assert sim_cold.backend_label == BACKEND_SYNTHETIC_FALLBACK

    cold_opt = DreamRSIOptimizer(cold_wm)
    cold_pol = cold_opt.evolve_policy_generation(rollouts_per_candidate=30, population_size=4, seed=7)
    assert cold_pol.simulator_backend == BACKEND_SYNTHETIC_FALLBACK

    # Recording a live step switches exact_cache replay provenance to recorded_blackboard_replay
    cold_wm.record_step(probe, 200, is_anomaly=True, is_vulnerability=True)
    sim_cached = cold_wm.simulate_probe(probe)
    assert sim_cached.backend_label == BACKEND_RECORDED_REPLAY

    # 2. DreamPolicyStore legacy backward-compatibility + stack_profile + require_replay
    store_path = tmp_path / "dream_policies.json"
    legacy_payload = {
        "total_generations": 1,
        "latest_generation": 1,
        "policies": [
            {
                "generation": 1,
                "mutator_weights": {"TE_CL_DUAL_HEADER": 0.7, "HEADER_TAB_SPACING": 0.3},
                "normative_bias": 0.4,
                "delta_aggressiveness": 0.6,
                "fitness_score": 42.0,
                "rsi_gain": 0.15,
            }
        ],
    }
    store_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

    store = DreamPolicyStore(storage_path=str(store_path))
    legacy_loaded = store.get_latest_policy()
    assert legacy_loaded is not None
    assert legacy_loaded.generation == 1
    assert legacy_loaded.branch_width == 3
    assert legacy_loaded.stack_profile == "generic"

    nginx_pol = DreamPolicy(
        generation=2,
        mutator_weights={"TE_CL_DUAL_HEADER": 0.85, "HEADER_TAB_SPACING": 0.15},
        branch_width=2,
        depth_vs_breadth_alpha=0.85,
        early_stop_patience=2,
        parallel_group_size=2,
        stack_profile="nginx",
        simulator_backend=BACKEND_RECORDED_REPLAY,
        fitness_score=80.0,
        val_fitness_score=74.5,
    )
    store.save_policy(nginx_pol)
    store.save_policy(cold_pol)  # synthetic_heuristic_fallback generic policy saved last

    reloaded = DreamPolicyStore(storage_path=str(store_path))
    assert reloaded.get_latest_policy(stack_profile="nginx").generation == 2
    assert reloaded.get_latest_policy(stack_profile="nginx").val_fitness_score == pytest.approx(74.5)
    assert reloaded.get_latest_policy(stack_profile="unknown", fallback_generic=False) is None
    assert reloaded.get_latest_policy(stack_profile="unknown", fallback_generic=True).stack_profile == "generic"
    # require_replay skips the synthetic fallback policy saved last
    replay_only = reloaded.get_latest_policy(require_replay=True)
    assert replay_only is not None
    assert replay_only.simulator_backend == BACKEND_RECORDED_REPLAY
    assert replay_only.stack_profile == "nginx"

    summary = reloaded.export_summary(stack_profile="nginx")
    assert summary["simulator_backend"] == BACKEND_RECORDED_REPLAY
    assert summary["latest_val_fitness"] == pytest.approx(74.5)
    assert summary["meta_controls"]["early_stop_patience"] == 2

    # 3. AdaptiveBanditScheduler bounded prior injection (no cumulative drift across 25 cycles)
    sched = AdaptiveBanditScheduler()
    sched.record_feedback("TE_CL_DUAL_HEADER", reward=3.0, is_anomaly=True, is_vulnerability=True)
    for _ in range(25):
        sched.apply_dream_policy(nginx_pol)

    arm = sched.arms["TE_CL_DUAL_HEADER"]
    # 1 empirical pull + 2 bounded prior pulls = 3 (never 1 + 25*2 = 51!)
    assert arm.pulls == 3
    assert arm.total_reward <= 3.0 + AdaptiveBanditScheduler.MAX_PRIOR_REWARD_PER_ARM + 1e-6
    assert arm.vulnerabilities_confirmed == 1
    meta = sched.get_meta_controls()
    assert meta["branch_width"] == 2
    assert meta["early_stop_patience"] == 2
    assert meta["depth_vs_breadth_alpha"] == pytest.approx(0.85)
    assert meta["stack_profile"] == "nginx"
    assert meta["simulator_backend"] == BACKEND_RECORDED_REPLAY


def test_student_t_critical_and_confidence_interval_math():
    """Verifies exact pure-stdlib Student-t critical values and 95% CI computation."""
    assert student_t_critical(1) == pytest.approx(12.706205, rel=1e-5)
    assert student_t_critical(5) == pytest.approx(2.570582, rel=1e-5)
    assert student_t_critical(9) == pytest.approx(2.262157, rel=1e-5)
    assert student_t_critical(19) == pytest.approx(2.093024, rel=1e-5)
    assert student_t_critical(29) == pytest.approx(2.045230, rel=1e-5)
    assert student_t_critical(100) == pytest.approx(1.983972, rel=1e-5)

    samples = [10.0, 12.0, 14.0, 16.0, 18.0]
    ci = compute_confidence_interval(samples, confidence=0.95)
    expected_mean = 14.0
    expected_std = math.sqrt(40.0 / 4.0)
    expected_hw = student_t_critical(4) * expected_std / math.sqrt(5.0)
    assert ci.mean == pytest.approx(expected_mean)
    assert ci.std == pytest.approx(expected_std)
    assert ci.half_width == pytest.approx(expected_hw)
    assert ci.ci_low == pytest.approx(expected_mean - expected_hw)
    assert ci.ci_high == pytest.approx(expected_mean + expected_hw)


def test_offline_4_baseline_matched_seed_benchmark_zero_network(tmp_path, monkeypatch):
    """Verifies standardized 5-policy offline replay benchmark over matched seeds with zero sockets."""
    db_file = tmp_path / "bench_replay.db"
    db = _populate_realistic_blackboard_db(db_file, num_tasks=8)
    try:
        pool = ReplayTreePool()
        assert pool.ingest_from_db(db) == 8
    finally:
        db.close()

    def _forbid_network(*args, **kwargs):
        raise AssertionError("Network socket I/O is strictly forbidden during offline replay benchmark!")

    monkeypatch.setattr(socket, "create_connection", _forbid_network)
    monkeypatch.setattr(socket, "socket", _forbid_network)

    report = run_replay_benchmark(
        pool,
        num_seeds=10,
        budget_steps=6,
        base_seed=42,
        generations=5,
        population_size=12,
        val_ratio=0.25,
        stack_profile="nginx",
    )

    assert report.simulator_backend == BACKEND_RECORDED_REPLAY
    assert len(report.matched_seeds) == 10
    assert report.train_tree_count == 6
    assert report.val_tree_count == 2
    assert set(report.policies.keys()) == set(POLICY_ORDER)

    for pname in POLICY_ORDER:
        m = report.policies[pname]
        assert m.cumulative_reward.n == 10
        assert m.cumulative_reward.ci_low <= m.cumulative_reward.mean <= m.cumulative_reward.ci_high
        assert m.vuln_discovery_rate.ci_low <= m.vuln_discovery_rate.mean <= m.vuln_discovery_rate.ci_high
        assert m.noise_rate.ci_low <= m.noise_rate.mean <= m.noise_rate.ci_high

    learned = report.policies["DreamRSI_Learned"]
    disabled = report.policies["Disabled"]
    rand_base = report.policies["Random"]
    nolearn = report.policies["NoLearning"]

    # Empirical learning superiority on blind held-out trees
    assert learned.cumulative_reward.mean > disabled.cumulative_reward.mean
    assert learned.cumulative_reward.mean > rand_base.cumulative_reward.mean
    assert learned.cumulative_reward.mean > nolearn.cumulative_reward.mean
    assert report.paired_comparisons["Disabled"]["statistically_significant"] is True
    assert report.paired_comparisons["Random"]["statistically_significant"] is True
    assert report.paired_comparisons["NoLearning"]["beats_baseline"] is True

    md = report.format_markdown_table()
    assert BACKEND_RECORDED_REPLAY in md
    assert "DreamRSI_Learned" in md
    assert "\ufffd" not in md

    as_json = json.dumps(report.to_dict())
    decoded = json.loads(as_json)
    assert decoded["simulator_backend"] == BACKEND_RECORDED_REPLAY
    assert decoded["num_seeds"] == 10


def test_live_testlab_benchmark_loopback_only_and_cli_json(tmp_path):
    """Verifies fail-closed loopback guard, live TestLabServer 5-policy benchmark, and clean CLI --json output."""
    # Fail-closed: non-loopback host MUST be rejected
    with pytest.raises(ValueError, match="loopback"):
        run_live_lab_benchmark(host="example.com", num_seeds=2)
    with pytest.raises(ValueError, match="loopback"):
        run_live_lab_benchmark(host="192.168.1.10", num_seeds=2)

    # Real loopback TestLabServer execution on 127.0.0.1 ephemeral port
    policy_out = tmp_path / "live_learned_policy.json"
    report = run_dream_benchmark_cli(
        live_lab=True,
        num_seeds=4,
        budget_steps=7,
        base_seed=42,
        generations=4,
        population_size=10,
        save_policy_path=str(policy_out),
    )

    assert report.simulator_backend == BACKEND_LIVE_TESTLAB
    assert len(report.matched_seeds) == 4
    assert set(report.policies.keys()) == set(POLICY_ORDER)
    assert policy_out.exists()

    learned = report.policies["DreamRSI_Learned"]
    disabled = report.policies["Disabled"]
    rand_base = report.policies["Random"]
    assert learned.cumulative_reward.mean > disabled.cumulative_reward.mean
    assert learned.cumulative_reward.mean > rand_base.cumulative_reward.mean
    assert learned.mean_vulns_found >= 4.0
    assert report.paired_comparisons["Disabled"]["statistically_significant"] is True

    # Verify `python -m engine.dream_rl_benchmark --live-lab --json` outputs pure valid JSON
    repo_root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "engine.dream_rl_benchmark",
            "--live-lab",
            "--seeds",
            "3",
            "--budget",
            "6",
            "--generations",
            "3",
            "--population",
            "8",
            "--json",
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=True,
    )
    parsed = json.loads(proc.stdout)
    assert parsed["simulator_backend"] == BACKEND_LIVE_TESTLAB
    assert parsed["num_seeds"] == 3
    assert set(parsed["policies"].keys()) == set(POLICY_ORDER)
