"""
Unit test for LangGraph Protocol Research Swarm Agent (rfc_hunt_swarm.py).
Verifies:
1. Swarm graph construction, compilation, and state schema.
2. Node definitions (fetch, generate, execute, triage, cascade/publish).
3. Conditional routing decisions.
"""

import pytest
from pathlib import Path
import sys

# Ensure vendor/rfchunt is in python path
rfchunt_dir = Path(__file__).resolve().parent.parent
if str(rfchunt_dir) not in sys.path:
    sys.path.insert(0, str(rfchunt_dir))

from rfc_hunt_swarm import ProtocolResearchSwarm, ResearchState


def test_swarm_agent_graph_build(tmp_path):
    test_db = str(tmp_path / "test_swarm.db")
    swarm = ProtocolResearchSwarm(host="127.0.0.1", port=5006, db_path=test_db)
    graph = swarm.build_graph()

    assert graph is not None
    # Verify graph nodes exist
    nodes = graph.nodes
    assert "fetch_and_chunk_agent" in nodes
    assert "llm_generator_agent" in nodes
    assert "execution_oracle_agent" in nodes
    assert "triage_debugger_agent" in nodes
    assert "cascade_and_publish_agent" in nodes


def test_swarm_agent_routing_logic(tmp_path):
    test_db = str(tmp_path / "test_swarm.db")
    swarm = ProtocolResearchSwarm(host="127.0.0.1", port=5006, db_path=test_db)

    # Test route_after_generation
    empty_state = {"generated_candidates": [], "fragments": []}
    assert swarm.route_after_generation(empty_state) == "__end__"

    state_with_frags = {"generated_candidates": [], "fragments": ["some fragment"]}
    assert swarm.route_after_generation(state_with_frags) == "llm_generator_agent"

    state_with_cands = {"generated_candidates": [{"raw_request": b"GET / HTTP/1.1\r\n\r\n"}]}
    assert swarm.route_after_generation(state_with_cands) == "execution_oracle_agent"

    # Test route_after_execution
    from engine.taxonomy import ImplementationAnomaly, AnomalyCategory
    anom = ImplementationAnomaly(
        anomaly_id="ANOM-TEST",
        target_engine="127.0.0.1:5006",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="divergence",
        expected_behavior="standard",
        raw_probe=b"TEST",
        raw_response=b"RESP",
    )
    assert swarm.route_after_execution({"current_anomaly": anom}) == "triage_debugger_agent"
    assert swarm.route_after_execution({"current_anomaly": None, "generated_candidates": [1]}) == "execution_oracle_agent"
    assert swarm.route_after_execution({"current_anomaly": None, "generated_candidates": [], "cycle_count": 5, "max_cycles": 3}) == "__end__"
    assert swarm.route_after_execution({"current_anomaly": None, "generated_candidates": [], "cycle_count": 5, "max_cycles": 3, "enable_dream_rsi": True}) == "dream_rsi_agent"


def test_swarm_run_summary_pass_fail_telemetry(tmp_path):
    test_db = str(tmp_path / "test_summary.db")
    swarm = ProtocolResearchSwarm(host="nrs.gov.ng", port=443, db_path=test_db, use_tls=True)
    swarm.run_stats["rfcs_scheduled"] = 2
    swarm.run_stats["rfcs_completed"] = 2
    swarm.run_stats["fragments_processed"] = 4
    swarm.run_stats["base_probes_generated"] = 6
    swarm.run_stats["total_candidates_executed"] = 20
    swarm.run_stats["probes_passed"] = 18
    swarm.run_stats["probes_failed_anomaly"] = 2
    swarm.run_stats["triage_discarded"] = 1
    r9112 = swarm._ensure_rfc_stat("RFC9112")
    r9112.update({"fragments": 2, "executed": 10, "passed": 10, "failed_anomalies": 0, "confirmed_vulns": 0, "status": "COMPLETED"})
    r9110 = swarm._ensure_rfc_stat("RFC9110")
    r9110.update({"fragments": 2, "executed": 10, "passed": 8, "failed_anomalies": 2, "confirmed_vulns": 1, "status": "COMPLETED"})
    swarm.run_stats["vulnerabilities_confirmed"].append({
        "rfc": "RFC9110",
        "vuln_id": "VULN-REPRO-1001",
        "anomaly_id": "ANOM-META-1001",
        "impact": "PARSER_CONFUSION",
        "repro": "100% (3/3)",
        "behavior": "Metamorphic Violation: Base request returned 302, but transformed request returned 501",
    })

    summary = swarm.print_run_summary()
    assert "SWARM RUN TELEMETRY & PASS / FAIL SUMMARY" in summary
    assert "PASSED (Target Conformant): 18 (90.0%)" in summary
    assert "FAILED (Anomaly Triggered): 2 (10.0%)" in summary
    assert "RFC9112" in summary and "PASS (100% CONFORMANT)" in summary
    assert "RFC9110" in summary and "FAIL (VULNERABILITY CONFIRMED)" in summary
    assert "VULN-REPRO-1001" in summary


def test_swarm_all_wired_commands(tmp_path):
    """Verifies that all commands, arguments, targets, and modes are cleanly wired into rfc_hunt_swarm.py."""
    import os
    from rfc_hunt_swarm import (
        ALL_MODES,
        build_swarm_parser,
        parse_swarm_arguments,
        cmd_oracle,
        cmd_h2,
        cmd_audit,
        cmd_dashboard,
        cmd_export,
    )

    # 1. Verify ALL_MODES coverage
    for mode in [
        "single", "terminator", "corpus", "all", "pqc", "ruler",
        "build", "lab", "mcp", "hunt", "auto", "start",
        "fetch", "chunk", "generate", "permute", "evaluate",
        "weaponize", "cascade", "dream", "caldera",
        "dashboard", "export", "oracle", "differential", "h2", "http2", "audit", "merkle",
    ]:
        assert mode in ALL_MODES

    # 2. Test CLI argument parser with newly wired options
    args = parse_swarm_arguments([
        "oracle",
        "--targets", "127.0.0.1:8080,https://internal.proxy:8443",
        "--terminators", "chunk,h2_gateway",
        "--dashboard-out", str(tmp_path / "dash.html"),
        "--export-rules-dir", str(tmp_path / "rules"),
        "--probe", "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    ])
    assert args.command == "oracle"
    assert args.targets == ["127.0.0.1:8080", "https://internal.proxy:8443"]
    assert args.terminators == ["chunk", "h2_gateway"]

    # 3. Test execution of newly wired standalone commands
    cmd_oracle(args)
    cmd_h2(args)
    cmd_audit(args)
    cmd_dashboard(args)
    assert os.path.exists(str(tmp_path / "dash.html"))

    cmd_export(args)
    assert os.path.exists(str(tmp_path / "rules"))
    rule_files = os.listdir(str(tmp_path / "rules"))
    assert len(rule_files) >= 3


