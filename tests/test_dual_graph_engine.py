"""
Unit tests for BaaRai/ARTEX Dual-Graph Attack Chaining Engine (Module 17)
========================================================================
Verifies:
1. AssetGraph node and relationship tracking (Domains, Ports, AI Sinks)
2. ExplorationGraph task goals, wire primitives, and intent anchors
3. ArtexPlanner strategic decomposition of anomalies into chained candidates
4. ArtexWorker tactical execution and exploit confirmation
5. Persistence into terminator.db tables (dual_graph_nodes, dual_graph_edges, attack_chains)
6. Zero UI reports generation in reports/ folder
"""

import json
from pathlib import Path
from database import Database
from engine.dual_graph_engine import (
    AssetGraph,
    ExplorationGraph,
    ArtexPlanner,
    ArtexWorker,
    DualGraphAttackEngine,
)


def test_asset_and_exploration_graphs_in_memory():
    db = Database(":memory:")
    engine = DualGraphAttackEngine(db=db)

    # Ingest assets
    engine.ingest_target_infrastructure(
        host="staging.corp.internal",
        port=8443,
        endpoints=[{"route": "/admin/dashboard", "method": "GET"}],
        ai_sinks=[{"route_path": "/api/v1/chat", "http_method": "POST", "model_provider": "local_llm"}],
    )

    assert len(engine.asset_graph.nodes) >= 3
    ai_sinks = engine.asset_graph.find_endpoints_by_type("AI_SINK")
    assert len(ai_sinks) == 1
    assert ai_sinks[0].attributes["route"] == "/api/v1/chat"

    # Register a wire desync primitive
    prim = engine.register_wire_primitive(
        anomaly_id="RFC9112-CHUNK-01",
        description="Chunk boundary disagreement via Kettle obsolete extension",
        anomaly_type="CL.TE_DESYNC",
    )
    assert prim.node_type == "WIRE_PRIMITIVE"
    assert prim.status == "VERIFIED"

    # Run planning round
    candidates = engine.planner.plan_next_round(round_num=1)
    assert len(candidates) >= 1

    # Candidate should chain from primitive to AI sink
    candidate_types = [c.attributes.get("attack_type") for c in candidates]
    assert "DESYNC_PROMPT_INJECTION" in candidate_types or "PIPELINE_HIJACK" in candidate_types

    # Execute worker
    def mock_executor(attrs):
        return True, "Mock attack verification succeeded", "RAW_SMUGGLED_CANARY"

    res = engine.run_attack_chain_cycle(round_num=1, executor_fn=mock_executor)
    assert res["exploits_verified"] >= 1

    # Verify DB persistence
    saved_nodes = db.get_dual_graph_nodes()
    assert len(saved_nodes) >= 4
    saved_edges = db.get_dual_graph_edges()
    assert len(saved_edges) >= 2
    chains = db.get_attack_chains()
    assert len(chains) >= 1
    assert chains[0]["is_verified"] == 1

    db.close()


def test_artex_reports_generation(tmp_path):
    reports_dir = tmp_path / "reports"
    engine = DualGraphAttackEngine(db=None, reports_dir=reports_dir)

    engine.ingest_target_infrastructure(
        host="10.0.0.50",
        port=80,
        ai_sinks=[{"route_path": "/agent/run", "http_method": "POST"}],
    )
    engine.register_wire_primitive("ANOM-9112", "TE.CL desync")
    res = engine.run_attack_chain_cycle(round_num=1)

    assert Path(res["report_files"]["json"]).exists()
    assert Path(res["report_files"]["summary"]).exists()

    report_content = json.loads(Path(res["report_files"]["json"]).read_text(encoding="utf-8"))
    assert report_content["asset_graph"]["count"] >= 2
