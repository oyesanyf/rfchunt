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

    # Execute worker (POE=2 active indicator without live traffic receipt -> recorded as lead)
    def mock_executor(attrs):
        return True, "Mock attack verification succeeded", "RAW_SMUGGLED_CANARY"

    res = engine.run_attack_chain_cycle(round_num=1, executor_fn=mock_executor)
    assert res["leads_recorded"] >= 1
    assert res["exploits_verified"] == 0

    # Verify DB persistence (truthful POE=2 lead status)
    saved_nodes = db.get_dual_graph_nodes()
    assert len(saved_nodes) >= 4
    saved_edges = db.get_dual_graph_edges()
    assert len(saved_edges) >= 2
    chains = db.get_attack_chains()
    assert len(chains) >= 1
    assert chains[0]["poe_level"] == 2
    assert chains[0]["is_verified"] == 0
    assert chains[0]["verification_status"] == "LEAD_ACTIVE_INDICATOR"

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


def test_ingest_target_infrastructure_strings_and_dicts():
    engine = DualGraphAttackEngine(db=None)

    # 1. Pure string ingestion (as passed by mantis_integrator run_remote_all_scans and run_all_scans)
    engine.ingest_target_infrastructure(
        host="remote-target.example.com",
        port=443,
        endpoints=["/api/chat", "/api/v1", "/status", "/login"],
        ai_sinks=["llm_prompt_sink", "rag_retrieval_sink"],
    )

    # Asset nodes: 1 domain, 1 port, 4 endpoints, 2 ai_sinks = 8 assets
    assert len(engine.asset_graph.nodes) == 8
    endpoints = engine.asset_graph.find_endpoints_by_type("ENDPOINT")
    assert len(endpoints) == 4
    assert any(ep.attributes["route"] == "/api/chat" for ep in endpoints)
    assert any(ep.attributes["method"] == "GET" for ep in endpoints)

    ai_sinks = engine.asset_graph.find_endpoints_by_type("AI_SINK")
    assert len(ai_sinks) == 2
    assert any(s.attributes["route"] == "llm_prompt_sink" for s in ai_sinks)
    assert any(s.attributes["model"] == "local_ai" for s in ai_sinks)

    # 2. Dict-based target ingestion
    engine2 = DualGraphAttackEngine(db=None)
    engine2.ingest_target_infrastructure(
        host={"host": "api.corp.internal", "port": 8443},
        endpoints=[{"route": "/v2/auth", "method": "POST"}],
        ai_sinks=[{"route_path": "/v2/generate", "http_method": "POST", "model_provider": "gemma", "title": "Generator"}],
    )

    assert len(engine2.asset_graph.nodes) == 4
    ai_sinks2 = engine2.asset_graph.find_endpoints_by_type("AI_SINK")
    assert len(ai_sinks2) == 1
    assert ai_sinks2[0].attributes["model"] == "gemma"
    assert ai_sinks2[0].attributes["route"] == "/v2/generate"


def test_ingest_finding_capability_classes():
    from dataclasses import dataclass

    @dataclass
    class CustomFinding:
        rule_id: str
        title: str
        severity: str
        cwe: str
        file_path: str
        line_number: int
        evidence: str
        scanner: str = "TestScanner"
        is_zero_day: bool = False

    engine = DualGraphAttackEngine(db=None)
    engine.ingest_target_infrastructure("target.com", 443, endpoints=["/api"], ai_sinks=["/ai"])

    # Test all 8 capability classes
    # 1. DESYNC
    n1 = engine.ingest_finding(
        {"rule_id": "PROBE-CLTE-01", "title": "CL.TE Framing Desync", "cwe": "CWE-444", "category": "DESYNC"},
        scanner="ActiveFlawProber",
    )
    assert n1 is not None
    assert n1.node_type == "FINDING_PRIMITIVE"
    assert n1.attributes["capability_class"] == "DESYNC"

    # 2. AUTH_SECRET
    n2 = engine.ingest_finding(
        {"rule_id": "MANTIS-AUTH-001", "title": "Hardcoded JWT Secret", "cwe": "CWE-798"},
        scanner="Mantis",
    )
    assert n2 is not None
    assert n2.attributes["capability_class"] == "AUTH_SECRET"

    # 3. SSRF_PIVOT
    n3 = engine.ingest_finding(
        {"rule_id": "RAPTOR-SSRF-01", "title": "Server-side request forgery in webhook", "cwe": "CWE-918"},
        scanner="RAPTOR",
    )
    assert n3 is not None
    assert n3.attributes["capability_class"] == "SSRF_PIVOT"

    # 4. EXEC_SINK
    n4 = engine.ingest_finding(
        {"rule_id": "MANTIS-CMD-01", "title": "OS Command Injection in subprocess", "cwe": "CWE-78"},
        scanner="Mantis",
    )
    assert n4 is not None
    assert n4.attributes["capability_class"] == "EXEC_SINK"

    # 5. AI_INJECTION
    n5 = engine.ingest_finding(
        {"rule_id": "AISCAN-PROMPT-01", "title": "Prompt Injection via Chat API", "cwe": "CWE-20"},
        scanner="aiscan",
    )
    assert n5 is not None
    assert n5.attributes["capability_class"] == "AI_INJECTION"

    # 6. ZERO_DAY_CANDIDATE (using dataclass)
    dc_finding = CustomFinding(
        rule_id="MANTIS-0DAY-AST-01",
        title="Synthesized Zero-Day Hypothesis: Oblique Framing Smuggle",
        severity="CRITICAL",
        cwe="CWE-444",
        file_path="server/handler.py",
        line_number=42,
        evidence="Observed grammar cliff",
        scanner="MantisZeroDay",
        is_zero_day=True,
    )
    n6 = engine.ingest_finding(dc_finding, scanner="MantisZeroDay")
    assert n6 is not None
    assert n6.attributes["capability_class"] == "ZERO_DAY_CANDIDATE"

    # 7. CRYPTO_WEAK
    n7 = engine.ingest_finding(
        {"rule_id": "RAPTOR-PQC-01", "title": "Classical RSA Non-PQC Crypto", "cwe": "CWE-327"},
        scanner="RAPTOR",
    )
    assert n7 is not None
    assert n7.attributes["capability_class"] == "CRYPTO_WEAK"

    # 8. SUPPLY_CHAIN
    n8 = engine.ingest_finding(
        {"rule_id": "RAPTOR-SCA-01", "title": "Vulnerable Dependency CVE-2024-1234", "category": "SCA"},
        scanner="RAPTOR",
    )
    assert n8 is not None
    assert n8.attributes["capability_class"] == "SUPPLY_CHAIN"


def test_multihop_3hop_compound_chain_generation():
    engine = DualGraphAttackEngine(db=None)
    engine.ingest_target_infrastructure(
        host="staging-cluster.internal",
        port=443,
        endpoints=["/api/v1/resource", "/api/v1/execute"],
        ai_sinks=["/api/v1/prompt_agent"],
    )

    findings = [
        # Desync primitive (Hop 1 for Patterns 1 & 2)
        {"rule_id": "DESYNC-01", "title": "CL.TE Desync Anomaly", "cwe": "CWE-444", "scanner": "ActiveFlawProber"},
        # Auth secret primitive (Hop 2 for Patterns 1, 2, 3)
        {"rule_id": "AUTH-01", "title": "Exposed Admin API Key", "cwe": "CWE-798", "scanner": "Mantis"},
        # Exec sink primitive (Hop 3 for Patterns 1 & 3)
        {"rule_id": "EXEC-01", "title": "Command Injection in Runner", "cwe": "CWE-78", "scanner": "RAPTOR"},
        # AI sink primitive (Hop 3 for Pattern 2, Hop 2/3 for Pattern 4)
        {"rule_id": "AI-01", "title": "Unmetered Agent Prompt Injection", "cwe": "CWE-20", "scanner": "aiscan"},
        # SSRF primitive (Hop 1 for Pattern 3)
        {"rule_id": "SSRF-01", "title": "SSRF in Webhook Callback", "cwe": "CWE-918", "scanner": "ActiveFlawProber"},
        # Zero-Day candidate (Hop 1 for Pattern 4)
        {"rule_id": "MANTIS-0DAY-01", "title": "Zero-Day Synthesized Parser Divergence", "is_zero_day": True, "scanner": "Mantis"},
    ]
    engine.ingest_findings(findings)

    candidates = engine.planner.plan_next_round(round_num=1)
    attack_types = {c.attributes.get("attack_type") for c in candidates}

    # Verify all 4 required compound chaining patterns are synthesized
    # Pattern 1: DESYNC -> AUTH_SECRET -> EXEC_SINK
    assert "3HOP_DESYNC_AUTH_EXEC" in attack_types

    # Pattern 2: DESYNC -> AUTH_SECRET -> AI_INJECTION
    assert "3HOP_DESYNC_AUTH_AI_INJECTION" in attack_types

    # Pattern 3: SSRF_PIVOT -> AUTH_SECRET -> EXEC_SINK
    assert "3HOP_SSRF_AUTH_EXEC" in attack_types

    # Pattern 4: ZERO_DAY_CANDIDATE -> AI_INJECTION / EXEC_SINK
    assert any("ZERODAY" in at or "0DAY" in at for at in attack_types)

    # Verify 3-hop candidates contain full chain_steps and multi-hop attributes
    p1_cand = next(c for c in candidates if c.attributes.get("attack_type") == "3HOP_DESYNC_AUTH_EXEC")
    assert p1_cand.attributes["hop_count"] == 3
    assert p1_cand.attributes["is_multi_hop"] is True
    assert len(p1_cand.attributes["chain_steps"]) >= 3
    assert len(p1_cand.attributes["source_scanners"]) >= 2

    # Verify execution cycle records passive correlation leads truthfully (POE=1 -> leads_recorded, not exploits_verified)
    res = engine.run_attack_chain_cycle(round_num=1)
    assert res["candidates_planned"] >= 4
    assert res["leads_recorded"] >= 4
    assert res["exploits_verified"] == 0


def test_export_attack_chains_to_sarif_findings():
    engine = DualGraphAttackEngine(db=None)
    engine.ingest_target_infrastructure("corp.target", 80, endpoints=["/run"], ai_sinks=["/chat"])
    engine.ingest_findings([
        {"rule_id": "DESYNC-CHUNK", "title": "Chunk Oblique Desync", "cwe": "CWE-444", "scanner": "ActiveFlawProber"},
        {"rule_id": "AUTH-LEAK", "title": "Stolen JWT", "cwe": "CWE-798", "scanner": "Mantis"},
        {"rule_id": "RCE-SINK", "title": "Exec RCE", "cwe": "CWE-78", "scanner": "RAPTOR"},
    ])
    engine.run_attack_chain_cycle(round_num=1)

    sarif_findings = engine.export_attack_chains_to_sarif_findings()
    assert len(sarif_findings) >= 1

    first = sarif_findings[0]
    assert first["rule_id"].startswith("ARTEX-")
    assert "title" in first
    assert first["severity"] in ("CRITICAL", "HIGH")
    assert first["cwe"] == "CWE-444"
    assert "file_path" in first
    assert first["line_number"] == 1
    assert first["scanner"] == "Module-17-ARTEX-DualGraph"
    assert isinstance(first["chain_steps"], list)

