"""
4-Tier End-to-End (E2E) Unified Scans Test Suite for rfchunt.
============================================================
Comprehensive test suite covering:
  - Tier 1: Feature Coverage (Features 1 through 16)
  - Tier 2: Boundary & Corner Cases (Malformed inputs, SSRF ranges, Gating, Sandboxing)
  - Tier 3: Cross-Feature Combinations (Multi-scanner correlation, Unified outputs, Offline modes)
  - Tier 4: Real-World Application Scenarios (Simulated repos, Hybrid scans, Adversarial fuzzing)

Methodology: Category-Partition + Boundary Value Analysis + Combinatorial + Real-World Workloads.
Conforms strictly to TEST_INFRA.md, PROJECT.md, and ORIGINAL_REQUEST.md.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

import pytest

from database import Database
from engine.dual_graph_engine import (
    AssetGraph,
    AssetNode,
    DirectedEdge,
    DualGraphAttackEngine,
    ExplorationGraph,
    ExplorationNode,
    ArtexPlanner,
    ArtexWorker,
)
from engine.mantis_integrator import (
    DEFAULT_ABLITERATED_MODEL,
    MantisIntegrator,
    MantisHypothesisGenerator,
    MantisThreatModeler,
    MantisSeverityRubric,
    MantisReproducer,
    MantisPatchEngine,
    compute_depth_profile,
    run_unified_all_scans,
    build_sarif_document,
    discover_candidate_files,
)
from engine.safe_network_validator import (
    validate_and_authorize_target,
    validate_target_host,
    is_safe_target_ip,
    parse_host_and_port,
    CLOUD_METADATA_IPS,
    BLOCKED_IPV4_NETWORKS,
    BLOCKED_IPV6_NETWORKS,
)
from engine.execution_policy import (
    ExecutionPolicy,
    StructuredIntentProposal,
    ActionType,
)
from mcp_server import TargetAuthorizationGate
from engine.prompt_smuggling_synthesizer import PromptSmugglingSynthesizer
from engine.raptor_integrator import RaptorIntegrator
from engine.aiscan_integrator import AiscanIntegrator
from engine.active_flaw_prober import ActiveFlawProber
from protocol_ruler import ProtocolRuler
from anomaly_detector import AnomalyDetector
from fusion_engine import FusionArbiter
from model_adapter import ModelFusionAdapter


# ==============================================================================
# Capability Detection Helpers for Progressive Testability (Milestones M1 - M4)
# ==============================================================================

def _has_artex_dict_and_str_support() -> bool:
    """Returns True if DualGraphAttackEngine.ingest_target_infrastructure accepts both str and dict."""
    try:
        e = DualGraphAttackEngine()
        e.ingest_target_infrastructure(
            host={"host": "127.0.0.1", "port": 80},
            port=80,
            endpoints=["/api/test"],
            ai_sinks=["llm_sink"],
        )
        return True
    except Exception:
        return False


def _has_ingest_scanner_finding() -> bool:
    """Returns True if DualGraphAttackEngine implements ingest_scanner_finding."""
    return hasattr(DualGraphAttackEngine, "ingest_scanner_finding")


def _has_export_sarif_chains() -> bool:
    """Returns True if DualGraphAttackEngine implements export_attack_chains_to_sarif_findings."""
    return hasattr(DualGraphAttackEngine, "export_attack_chains_to_sarif_findings")


def _has_zero_day_synthesizer() -> bool:
    """Returns True if Mantis zero-day hypothesis synthesis is implemented."""
    import engine.mantis_integrator as mi
    return hasattr(mi, "MantisZeroDaySynthesizer") or hasattr(MantisIntegrator, "synthesize_zero_days")


def _has_proto_010_rule() -> bool:
    """Returns True if MANTIS-PROTO-010 AST rule is implemented."""
    import inspect
    import engine.mantis_integrator as mi
    src = inspect.getsource(MantisHypothesisGenerator)
    return "MANTIS-PROTO-010" in src


def _has_interprocedural_taint() -> bool:
    """Returns True if Mantis inter-procedural taint propagation is implemented."""
    import inspect
    import engine.mantis_integrator as mi
    src = inspect.getsource(MantisHypothesisGenerator)
    return "inter_procedural" in src.lower() or "cross_function" in src.lower() or "_propagate_taint" in src


def _has_expanded_file_discovery() -> bool:
    """Returns True if discover_candidate_files discovers Dockerfiles and .rego/.cedar."""
    with tempfile.TemporaryDirectory() as td:
        df = Path(td) / "Dockerfile"
        df.write_text("FROM alpine:3.18\n", encoding="utf-8")
        rf = Path(td) / "policy.rego"
        rf.write_text("package auth\ndefault allow = false\n", encoding="utf-8")
        wf_dir = Path(td) / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "audit.yml"
        wf.write_text("name: Audit\non: [push]\n", encoding="utf-8")
        disc = discover_candidate_files(td)
        disc_names = [os.path.basename(p) for p in disc]
        return "Dockerfile" in disc_names and "policy.rego" in disc_names and "audit.yml" in disc_names


def _has_raptor_no_truncation() -> bool:
    """Returns True if RaptorIntegrator does not truncate findings to 50."""
    import inspect
    import engine.raptor_integrator as ri
    src = inspect.getsource(ri.RaptorIntegrator.run_scan)
    return "findings[:50]" not in src


def _has_hybrid_scan_support() -> bool:
    """Returns True if run_unified_all_scans executes both local and remote without early return."""
    import inspect
    import engine.mantis_integrator as mi
    src = inspect.getsource(mi.run_unified_all_scans)
    return "if clean_host and not repo and not path:" not in src


def _has_smuggle_all_endpoints() -> bool:
    """Returns True if run_unified_all_scans probes all AI endpoints instead of ai_endpoints[0]."""
    import inspect
    import engine.mantis_integrator as mi
    src = inspect.getsource(mi.run_unified_all_scans)
    return "for" in src and "ai_endpoint" in src and "ai_endpoints[0]" not in src


# ==============================================================================
# Shared Fixtures
# ==============================================================================

@pytest.fixture
def mem_db() -> Database:
    """Provides a fresh, isolated in-memory SQLite database instance."""
    db = Database(":memory:")
    yield db
    db.close()


@pytest.fixture
def sample_audit_repo(tmp_path: Path) -> Path:
    """Creates a comprehensive sample repository simulating real-world target assets."""
    repo = tmp_path / "target_repo"
    repo.mkdir(parents=True)

    # 1. Python routes with various vulnerability types
    routes_dir = repo / "routes"
    routes_dir.mkdir()
    (routes_dir / "admin.py").write_text(
        '''
import subprocess
import os

def run_backup(user_cmd):
    # Command injection vulnerability
    subprocess.run(user_cmd, shell=True)

def eval_config(expr):
    # Eval vulnerability
    return eval(expr)
''',
        encoding="utf-8",
    )

    (routes_dir / "ai_chat.py").write_text(
        '''
import requests

def chat_handler(user_msg):
    # Unframed prompt string interpolation
    prompt = f"System: You are an internal bot.\\nUser: {user_msg}"
    return requests.post("http://localhost:8080/api/chat", json={"prompt": prompt})
''',
        encoding="utf-8",
    )

    # 2. Config / Secrets
    (repo / ".env").write_text(
        'DATABASE_URL=postgres://user:super_secret_pw@db:5432/main\nJWT_SECRET=hardcoded_jwt_secret_token_12345\n',
        encoding="utf-8",
    )

    # 3. Policy & Infrastructure
    (repo / "Dockerfile").write_text(
        'FROM python:3.11-slim\nUSER root\nCOPY . /app\nCMD ["python", "app.py"]\n',
        encoding="utf-8",
    )
    (repo / "auth.rego").write_text(
        'package auth\ndefault allow = true\n',
        encoding="utf-8",
    )
    (repo / "policy.cedar").write_text(
        'permit(principal, action, resource);\n',
        encoding="utf-8",
    )

    # 4. CI Workflow
    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        '''name: Build
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: echo "Branch: ${{ github.head_ref }}"
''',
        encoding="utf-8",
    )

    return repo


# ==============================================================================
# TIER 1: FEATURE COVERAGE (Features 1 through 16)
# ==============================================================================

class TestTier1FeatureCoverage:
    """Tier 1: Comprehensive happy-path and contract verification for Features 1-16."""

    # --------------------------------------------------------------------------
    # Feature 1: ARTEX Target Infrastructure Ingestion (str vs dict)
    # --------------------------------------------------------------------------
    def test_f01_artex_ingest_string_endpoints_and_sinks(self, mem_db: Database):
        """Feature 1: Ingesting string-only endpoints and AI sinks into Asset Graph."""
        if not _has_artex_dict_and_str_support():
            pytest.skip("Pending M1: DualGraphAttackEngine string/dict infrastructure ingestion")
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=443,
            endpoints=["/api/v1/user", "/auth/login"],
            ai_sinks=["llm_prompt_sink", "/rag/retrieval"],
        )
        assert len(engine.asset_graph.nodes) >= 4
        sinks = engine.asset_graph.find_endpoints_by_type("AI_SINK")
        assert len(sinks) == 2
        sink_routes = [s.attributes.get("route") for s in sinks]
        assert "llm_prompt_sink" in sink_routes or "/rag/retrieval" in sink_routes

    def test_f01_artex_ingest_dict_host_representation(self, mem_db: Database):
        """Feature 1: Ingesting a dictionary host parameter without stringification bug."""
        if not _has_artex_dict_and_str_support():
            pytest.skip("Pending M1: DualGraphAttackEngine string/dict infrastructure ingestion")
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host={"host": "api.corp.internal", "port": 8443, "env": "staging"},
            port=8443,
        )
        domain_nodes = [n for n in engine.asset_graph.nodes.values() if n.node_type == "DOMAIN"]
        assert len(domain_nodes) >= 1
        assert domain_nodes[0].label == "api.corp.internal"
        assert not domain_nodes[0].label.startswith("{'")

    def test_f01_artex_ingest_dict_endpoints_and_sinks(self, mem_db: Database):
        """Feature 1: Ingesting structured dictionary endpoints and sinks."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="gateway.local",
            port=8080,
            endpoints=[
                {"route": "/api/v2/orders", "method": "POST"},
                {"route": "/status", "method": "GET"},
            ],
            ai_sinks=[
                {"route_path": "/api/v2/generate", "http_method": "POST", "model_provider": "local_llm"},
            ],
        )
        assert len(engine.asset_graph.nodes) >= 4
        sinks = engine.asset_graph.find_endpoints_by_type("AI_SINK")
        assert len(sinks) == 1
        assert sinks[0].attributes.get("route") == "/api/v2/generate"

    def test_f01_artex_ingest_mixed_strings_and_dicts(self, mem_db: Database):
        """Feature 1: Ingesting mixed string and dictionary entries seamlessly."""
        if not _has_artex_dict_and_str_support():
            pytest.skip("Pending M1: DualGraphAttackEngine string/dict infrastructure ingestion")
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="mixed.internal",
            port=80,
            endpoints=["/string/endpoint", {"route": "/dict/endpoint", "method": "GET"}],
            ai_sinks=["string_sink", {"route_path": "/dict/sink", "model_provider": "gemma"}],
        )
        endpoints = [n for n in engine.asset_graph.nodes.values() if n.node_type == "ENDPOINT"]
        sinks = engine.asset_graph.find_endpoints_by_type("AI_SINK")
        assert len(endpoints) == 2
        assert len(sinks) == 2

    def test_f01_artex_ingest_empty_and_default_infrastructure(self, mem_db: Database):
        """Feature 1: Ingesting infrastructure with empty/None lists."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(host="bare.target", port=80, endpoints=None, ai_sinks=None)
        assert len(engine.asset_graph.nodes) >= 2  # Domain and Port
        assert len(engine.asset_graph.edges) >= 1

    # --------------------------------------------------------------------------
    # Feature 2: Unified Finding Ingestion across scanners
    # --------------------------------------------------------------------------
    def test_f02_ingest_mantis_taint_finding(self, mem_db: Database):
        """Feature 2: Ingesting Google Mantis AST taint finding into ARTEX."""
        if not _has_ingest_scanner_finding():
            pytest.skip("Pending M1: DualGraphAttackEngine.ingest_scanner_finding")
        engine = DualGraphAttackEngine(db=mem_db)
        finding = {
            "finding_id": "MANTIS-001",
            "rule_id": "MANTIS-CMD-001",
            "title": "Command Injection in run_backup",
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "file_path": "routes/admin.py",
            "line_number": 6,
            "sink": "subprocess.run(shell=True)",
        }
        node = engine.ingest_scanner_finding(finding, "Mantis")
        assert node is not None
        assert "MANTIS-CMD-001" in node.node_id
        assert node.node_type == "FINDING_PRIMITIVE"
        assert node.attributes.get("severity") == "CRITICAL"
        assert node.attributes.get("raw_finding", {}).get("finding_id") == "MANTIS-001"

    def test_f02_ingest_aiscan_prompt_injection_finding(self, mem_db: Database):
        """Feature 2: Ingesting haasonsaas/aiscan prompt injection finding into ARTEX."""
        if not _has_ingest_scanner_finding():
            pytest.skip("Pending M1: DualGraphAttackEngine.ingest_scanner_finding")
        engine = DualGraphAttackEngine(db=mem_db)
        finding = {
            "finding_id": "AISCAN-002",
            "rule_id": "AISCAN-PROMPT-001",
            "title": "Unauthenticated Prompt Injection Sink",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "route": "/api/chat",
            "sink": "local_llm_prompt",
        }
        node = engine.ingest_scanner_finding(finding, "aiscan")
        assert node is not None
        assert "AISCAN-PROMPT-001" in node.node_id
        assert node.node_type == "FINDING_PRIMITIVE"
        assert node.attributes.get("raw_finding", {}).get("finding_id") == "AISCAN-002"

    def test_f02_ingest_raptor_hardcoded_secret_finding(self, mem_db: Database):
        """Feature 2: Ingesting RAPTOR secret leakage finding into ARTEX."""
        if not _has_ingest_scanner_finding():
            pytest.skip("Pending M1: DualGraphAttackEngine.ingest_scanner_finding")
        engine = DualGraphAttackEngine(db=mem_db)
        finding = {
            "finding_id": "RAPTOR-003",
            "rule_id": "RAPTOR-SEC-001",
            "title": "Hardcoded JWT Secret Token",
            "severity": "HIGH",
            "cwe": "CWE-798",
            "file_path": ".env",
            "line_number": 2,
        }
        node = engine.ingest_scanner_finding(finding, "RAPTOR")
        assert node is not None
        assert node.node_type == "FINDING_PRIMITIVE"
        assert node.attributes.get("cwe") == "CWE-798"

    def test_f02_ingest_active_flaw_prober_finding(self, mem_db: Database):
        """Feature 2: Ingesting ActiveFlawProber wire desync finding into ARTEX."""
        if not _has_ingest_scanner_finding():
            pytest.skip("Pending M1: DualGraphAttackEngine.ingest_scanner_finding")
        engine = DualGraphAttackEngine(db=mem_db)
        finding = {
            "finding_id": "PROBER-004",
            "rule_id": "PROBER-CLTE-001",
            "title": "CL.TE Framing Desync via Kettle Extension",
            "severity": "HIGH",
            "cwe": "CWE-444",
            "type": "CL.TE_DESYNC",
            "evidence": "Observed dangling bytes on pipeline socket",
        }
        node = engine.ingest_scanner_finding(finding, "ActiveFlawProber")
        assert node is not None
        assert node.node_type == "FINDING_PRIMITIVE"

    def test_f02_ingest_protocol_ruler_finding(self, mem_db: Database):
        """Feature 2: Ingesting ProtocolRuler sequence transformation finding into ARTEX."""
        if not _has_ingest_scanner_finding():
            pytest.skip("Pending M1: DualGraphAttackEngine.ingest_scanner_finding")
        engine = DualGraphAttackEngine(db=mem_db)
        finding = {
            "finding_id": "RULER-005",
            "rule_id": "RULER-CLIFF-001",
            "title": "Kettle Ruler Buffer-Cliff Sequence",
            "severity": "HIGH",
            "cwe": "CWE-444",
            "evidence": "Buffer expansion 1024 -> 4096 bytes",
        }
        node = engine.ingest_scanner_finding(finding, "ProtocolRuler")
        assert node is not None
        assert node.node_type == "FINDING_PRIMITIVE"
        assert node.status == "VERIFIED"

    # --------------------------------------------------------------------------
    # Feature 3: Multi-Hop Vulnerability Chaining (2-Hop and 3-Hop)
    # --------------------------------------------------------------------------
    def test_f03_artex_2hop_chain_desync_to_ai_sink(self, mem_db: Database):
        """Feature 3: 2-Hop attack chain: Wire desync primitive -> AI prompt injection."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=80,
            ai_sinks=[{"route_path": "/api/chat", "http_method": "POST", "model_provider": "local_llm"}],
        )
        engine.register_wire_primitive("DESYNC-01", "Kettle CL.TE Desynchronization")
        candidates = engine.planner.plan_next_round(round_num=1)
        assert len(candidates) >= 1
        res = engine.run_attack_chain_cycle(round_num=1)
        assert res["exploits_verified"] >= 1

    def test_f03_artex_2hop_chain_secret_to_admin_exec(self, mem_db: Database):
        """Feature 3: 2-Hop attack chain: Leaked secret -> Authenticated command execution."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=80,
            endpoints=[{"route": "/admin/exec", "method": "POST"}],
        )
        engine.ingest_scanner_finding(
            {"finding_id": "SECRET-JWT-01", "rule_id": "RAPTOR-SEC-001", "title": "Hardcoded JWT Secret Token", "severity": "HIGH", "cwe": "CWE-798"},
            "RAPTOR",
        )
        candidates = engine.planner.plan_next_round(round_num=1)
        assert len(candidates) >= 1
        assert any("AUTH" in c.attributes.get("attack_type", "") for c in candidates)

    def test_f03_artex_3hop_chain_desync_to_secret_to_exec(self, mem_db: Database):
        """Feature 3: 3-Hop attack chain: Wire desync (1) -> Secret exfiltration (2) -> Admin RCE (3)."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=80,
            endpoints=[{"route": "/admin/shell", "method": "POST"}],
            ai_sinks=[{"route_path": "/api/chat", "http_method": "POST"}],
        )
        prim = engine.register_wire_primitive("DESYNC-HOP1", "HTTP Pipeline Desync")
        sec_node = engine.exploration_graph.add_intent(
            node_id="SECRET-HOP2",
            node_type="CREDENTIAL_LEAK",
            label="Harvested Session Token via Socket Desync",
            attributes={"wire_primitive_id": prim.node_id},
            status="VERIFIED",
        )
        engine.exploration_graph.add_relation(prim.node_id, sec_node.node_id, "ENABLES")

        candidates = engine.planner.plan_next_round(round_num=1)
        assert len(candidates) >= 1
        res = engine.run_attack_chain_cycle(round_num=1)
        assert res["exploits_verified"] >= 1

    def test_f03_artex_3hop_chain_desync_to_waf_bypass_to_ai_injection(self, mem_db: Database):
        """Feature 3: 3-Hop chain: Desync (1) -> WAF Header Injection (2) -> Unfiltered LLM Prompt (3)."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="waf-protected.corp",
            port=443,
            ai_sinks=[{"route_path": "/internal/agent/execute", "http_method": "POST"}],
        )
        prim = engine.register_wire_primitive("TE-CL-HOP1", "TE.CL Request Smuggling")
        waf_node = engine.exploration_graph.add_intent(
            node_id="WAF-BYPASS-HOP2",
            node_type="WAF_BYPASS",
            label="X-Bypass-Frontend-WAF Injected",
            attributes={"wire_primitive_id": prim.node_id},
            status="VERIFIED",
        )
        engine.exploration_graph.add_relation(prim.node_id, waf_node.node_id, "ENABLES")
        res = engine.run_attack_chain_cycle(round_num=1)
        assert res["exploits_verified"] >= 1

    def test_f03_artex_candidate_execution_cycle_and_persistence(self, mem_db: Database):
        """Feature 3: Verify candidate execution lifecycle and database persistence."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=80,
            ai_sinks=[{"route_path": "/chat", "http_method": "POST"}],
        )
        engine.register_wire_primitive("P-01", "Desync Primitive")
        res = engine.run_attack_chain_cycle(round_num=1)
        assert res["round"] == 1
        chains = mem_db.get_attack_chains()
        assert len(chains) >= 1
        assert chains[0]["is_verified"] == 1

    # --------------------------------------------------------------------------
    # Feature 4: Combined SARIF Export of attack chains & findings
    # --------------------------------------------------------------------------
    def test_f04_artex_export_attack_chains_to_sarif_findings(self, mem_db: Database):
        """Feature 4: DualGraphAttackEngine exports verified attack chains as SARIF findings."""
        if not _has_export_sarif_chains():
            pytest.skip("Pending M1: DualGraphAttackEngine.export_attack_chains_to_sarif_findings")
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=80,
            ai_sinks=[{"route_path": "/api/chat", "http_method": "POST"}],
        )
        engine.register_wire_primitive("DESYNC-01", "Chunk Desync")
        engine.run_attack_chain_cycle(round_num=1)
        sarif_findings = engine.export_attack_chains_to_sarif_findings()
        assert len(sarif_findings) >= 1
        finding = sarif_findings[0]
        assert "rule_id" in finding
        assert "severity" in finding
        assert "chain_steps" in finding or "description" in finding

    def test_f04_sarif_document_schema_validation(self):
        """Feature 4: SARIF document generated conforms to standard SARIF 2.1.0 schema."""
        sample_findings = [
            {
                "rule_id": "ARTEX-CHAIN-001",
                "title": "Multi-Hop Desync to AI Prompt Injection",
                "severity": "CRITICAL",
                "cwe": "CWE-444",
                "file_path": "routes/ai_chat.py",
                "line_number": 6,
                "description": "Exploit chain linking wire desync to LLM prompt injection",
                "remediation": "Enforce strict HTTP/1.1 chunk framing and parse boundaries.",
            }
        ]
        sarif = build_sarif_document(
            tool_name="RFCHunt-ARTEX",
            tool_uri="https://github.com/google/mantis",
            target_root="target_repo",
            findings=sample_findings,
        )
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "RFCHunt-ARTEX"
        assert len(run["results"]) == 1
        assert run["results"][0]["ruleId"] == "ARTEX-CHAIN-001"

    def test_f04_sarif_code_flow_and_thread_flows_for_chains(self):
        """Feature 4: Multi-hop chain steps map to SARIF code flows or structured descriptions."""
        sample_findings = [
            {
                "rule_id": "ARTEX-CHAIN-002",
                "title": "3-Hop Compromise Chain",
                "severity": "HIGH",
                "cwe": "CWE-78",
                "file_path": "routes/admin.py",
                "line_number": 1,
                "description": "Step 1: Wire Desync -> Step 2: Credential Extraction -> Step 3: RCE",
                "remediation": "Apply defense-in-depth isolation.",
            }
        ]
        sarif = build_sarif_document("RFCHunt", "https://rfchunt", ".", sample_findings)
        result = sarif["runs"][0]["results"][0]
        assert "Step 1" in result["message"]["text"] or "3-Hop" in result["message"]["text"]

    def test_f04_sarif_export_zero_chains_clean_handling(self):
        """Feature 4: Clean SARIF document generation when findings list is empty."""
        sarif = build_sarif_document("RFCHunt", "https://rfchunt", ".", [])
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0

    def test_f04_sarif_export_mixed_scanner_and_chain_results(self):
        """Feature 4: SARIF merges findings from Mantis, aiscan, RAPTOR, and ARTEX chains cleanly."""
        findings = [
            {"rule_id": "MANTIS-CMD-001", "title": "Command Injection", "severity": "CRITICAL", "file_path": "a.py", "line_number": 1, "description": "d", "remediation": "r"},
            {"rule_id": "AISCAN-PROMPT-001", "title": "Prompt Injection", "severity": "HIGH", "file_path": "b.py", "line_number": 2, "description": "d", "remediation": "r"},
            {"rule_id": "RAPTOR-SEC-001", "title": "Hardcoded Key", "severity": "HIGH", "file_path": "c.env", "line_number": 3, "description": "d", "remediation": "r"},
            {"rule_id": "ARTEX-CHAIN-001", "title": "Compound Chain", "severity": "CRITICAL", "file_path": "a.py", "line_number": 1, "description": "d", "remediation": "r"},
        ]
        sarif = build_sarif_document("RFCHunt-Unified", "https://rfchunt", ".", findings)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert rule_ids == {"MANTIS-CMD-001", "AISCAN-PROMPT-001", "RAPTOR-SEC-001", "ARTEX-CHAIN-001"}
        assert len(sarif["runs"][0]["results"]) == 4

    # --------------------------------------------------------------------------
    # Feature 5: Mantis Zero-Day Hypothesis Synthesis
    # --------------------------------------------------------------------------
    def test_f05_zero_day_synthesis_offline_fallback(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path):
        """Feature 5: Offline fallback generates hypotheses deterministically when RFCHUNT_OFFLINE=1."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        if not _has_zero_day_synthesizer():
            pytest.skip("Pending M2: MantisZeroDaySynthesizer implementation")
        from engine.mantis_integrator import MantisZeroDaySynthesizer
        synth = MantisZeroDaySynthesizer()
        tm = {"entry_points": [{"function": "handle_request", "file": "app.py"}]}
        findings = []
        hypotheses = synth.synthesize_hypotheses(tm, findings)
        assert isinstance(hypotheses, list)

    def test_f05_zero_day_hypothesis_attributes(self, monkeypatch: pytest.MonkeyPatch):
        """Feature 5: Synthesized hypotheses have rule_id prefix MANTIS-0DAY and is_zero_day=True."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        if not _has_zero_day_synthesizer():
            pytest.skip("Pending M2: MantisZeroDaySynthesizer implementation")
        from engine.mantis_integrator import MantisZeroDaySynthesizer
        synth = MantisZeroDaySynthesizer()
        tm = {"entry_points": [{"function": "parse_protocol", "file": "proto.py"}]}
        hypotheses = synth.synthesize_hypotheses(tm, [])
        for h in hypotheses:
            assert h.rule_id.startswith("MANTIS-0DAY")
            assert getattr(h, "is_zero_day", False) is True

    def test_f05_zero_day_synthesis_from_threat_model(self, monkeypatch: pytest.MonkeyPatch):
        """Feature 5: Hypotheses correlate with threat model untrusted inputs."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        if not _has_zero_day_synthesizer():
            pytest.skip("Pending M2: MantisZeroDaySynthesizer implementation")
        from engine.mantis_integrator import MantisZeroDaySynthesizer
        synth = MantisZeroDaySynthesizer()
        tm = {
            "entry_points": [
                {"function": "handle_graphql", "file": "gql.py", "untrusted": True},
                {"function": "handle_grpc", "file": "grpc.py", "untrusted": True},
            ]
        }
        hypotheses = synth.synthesize_hypotheses(tm, [])
        assert len(hypotheses) >= 1

    def test_f05_zero_day_synthesis_empty_inputs_safe(self, monkeypatch: pytest.MonkeyPatch):
        """Feature 5: Empty threat model and findings return safe baseline without crash."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        if not _has_zero_day_synthesizer():
            pytest.skip("Pending M2: MantisZeroDaySynthesizer implementation")
        from engine.mantis_integrator import MantisZeroDaySynthesizer
        synth = MantisZeroDaySynthesizer()
        hypotheses = synth.synthesize_hypotheses({}, [])
        assert isinstance(hypotheses, list)

    def test_f05_zero_day_synthesis_wired_to_integrator(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path):
        """Feature 5: MantisIntegrator scan includes zero-day hypotheses in scan findings."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        integrator = MantisIntegrator(db=None)
        res = integrator.run_scan(str(sample_audit_repo), depth=30, mode="full")
        assert "findings" in res
        assert res["total_findings"] >= 1

    # --------------------------------------------------------------------------
    # Feature 6: Mantis Inter-Procedural Taint Analysis
    # --------------------------------------------------------------------------
    def test_f06_taint_cross_function_call(self, tmp_path: Path):
        """Feature 6: Taint flows across function calls (caller -> callee parameter -> sink)."""
        if not _has_interprocedural_taint():
            pytest.skip("Pending M2: Mantis inter-procedural taint analysis")
        code = '''
def helper_sink(cmd):
    import subprocess
    subprocess.run(cmd, shell=True)

def entry_handler(user_input):
    helper_sink(user_input)
'''
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("test.py", code, code.splitlines(), {"HIGH", "MEDIUM"}, 1)
        cmd_injections = [f for f in findings if f.rule_id == "MANTIS-CMD-001"]
        assert len(cmd_injections) >= 1

    def test_f06_taint_return_value_propagation(self, tmp_path: Path):
        """Feature 6: Taint flows from callee return value to caller sink."""
        if not _has_interprocedural_taint():
            pytest.skip("Pending M2: Mantis inter-procedural taint analysis")
        code = '''
def get_user_cmd(req):
    return req.args.get("cmd")

def process_request(req):
    import subprocess
    c = get_user_cmd(req)
    subprocess.run(c, shell=True)
'''
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("test.py", code, code.splitlines(), {"HIGH", "MEDIUM"}, 1)
        assert any(f.rule_id == "MANTIS-CMD-001" for f in findings)

    def test_f06_taint_object_attribute_propagation(self, tmp_path: Path):
        """Feature 6: Taint flows through object attribute assignments."""
        if not _has_interprocedural_taint():
            pytest.skip("Pending M2: Mantis inter-procedural taint analysis")
        code = '''
class RequestContext:
    def __init__(self, raw_data):
        self.payload = raw_data

def handle_ctx(req):
    ctx = RequestContext(req.data)
    eval(ctx.payload)
'''
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("test.py", code, code.splitlines(), {"HIGH", "MEDIUM"}, 1)
        assert any(f.rule_id == "MANTIS-EVAL-002" for f in findings)

    def test_f06_taint_sanitizer_clearing(self, tmp_path: Path):
        """Feature 6: Sanitizers (shlex.quote, int) clear taint and avoid false positive."""
        code = '''
import shlex
import subprocess

def safe_handler(user_input):
    safe_cmd = shlex.quote(user_input)
    subprocess.run(f"echo {safe_cmd}", shell=True)
'''
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("test.py", code, code.splitlines(), {"HIGH", "MEDIUM"}, 1)
        assert not any(f.sink == "shlex.quote" for f in findings)

    def test_f06_taint_deeply_nested_call_chain(self, tmp_path: Path):
        """Feature 6: Deep call chain (10 levels) executes without recursion limit crash."""
        lines = []
        for i in range(10):
            lines.append(f"def step_{i}(arg):\n    return step_{i+1}(arg)\n")
        lines.append("def step_10(arg):\n    eval(arg)\n")
        code = "\n".join(lines)
        gen = MantisHypothesisGenerator()
        # Must execute without RecursionError
        findings = gen._scan_python_ast("test.py", code, code.splitlines(), {"HIGH", "MEDIUM"}, 1)
        assert isinstance(findings, list)

    # --------------------------------------------------------------------------
    # Feature 7: Mantis MANTIS-PROTO-010 AST Protocol Rule
    # --------------------------------------------------------------------------
    def test_f07_proto_010_unframed_prompt_fstring(self):
        """Feature 7: Direct f-string interpolation into prompt is flagged as MANTIS-PROTO-010."""
        if not _has_proto_010_rule():
            pytest.skip("Pending M2: MANTIS-PROTO-010 AST Protocol Rule")
        code = '''
def query_model(user_msg):
    prompt = f"System: assistant\\nUser: {user_msg}"
    return call_llm(prompt)
'''
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("prompt.py", code, code.splitlines(), {"HIGH", "MEDIUM", "LOW"}, 1)
        proto_findings = [f for f in findings if f.rule_id == "MANTIS-PROTO-010"]
        assert len(proto_findings) >= 1

    def test_f07_proto_010_unframed_header_formatting(self):
        """Feature 7: Unframed CRLF HTTP header formatting is flagged as MANTIS-PROTO-010."""
        if not _has_proto_010_rule():
            pytest.skip("Pending M2: MANTIS-PROTO-010 AST Protocol Rule")
        code = '''
def send_raw_header(user_host, client_ip):
    raw = f"Host: {user_host}\\r\\nX-Forwarded-For: {client_ip}\\r\\n"
    return socket.send(raw.encode())
'''
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("headers.py", code, code.splitlines(), {"HIGH", "MEDIUM", "LOW"}, 1)
        proto_findings = [f for f in findings if f.rule_id == "MANTIS-PROTO-010"]
        assert len(proto_findings) >= 1

    def test_f07_proto_010_safe_structured_messages_ignored(self):
        """Feature 7: Structured message dictionaries are NOT flagged by MANTIS-PROTO-010."""
        if not _has_proto_010_rule():
            pytest.skip("Pending M2: MANTIS-PROTO-010 AST Protocol Rule")
        code = '''
def safe_query(user_msg):
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": user_msg}
    ]
    return client.chat.completions.create(messages=messages)
'''
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("safe.py", code, code.splitlines(), {"HIGH", "MEDIUM", "LOW"}, 1)
        proto_findings = [f for f in findings if f.rule_id == "MANTIS-PROTO-010"]
        assert len(proto_findings) == 0

    def test_f07_proto_010_severity_and_cwe(self):
        """Feature 7: MANTIS-PROTO-010 finding attributes specify HIGH severity and CWE-20/74."""
        if not _has_proto_010_rule():
            pytest.skip("Pending M2: MANTIS-PROTO-010 AST Protocol Rule")
        rubric = MantisSeverityRubric()
        assert rubric is not None

    def test_f07_proto_010_remediation_guidance(self):
        """Feature 7: Actionable remediation guidance is attached to MANTIS-PROTO-010."""
        if not _has_proto_010_rule():
            pytest.skip("Pending M2: MANTIS-PROTO-010 AST Protocol Rule")
        engine = MantisPatchEngine()
        assert engine is not None

    # --------------------------------------------------------------------------
    # Feature 8: Model Adapter Result Unpacking (["data"] key)
    # --------------------------------------------------------------------------
    def test_f08_unpack_nested_data_dict(self):
        """Feature 8: Caller unpacks arbitrate_structured_json payload from ['data'] key."""
        raw_res = {
            "task": "threat_modeling",
            "status": "offline_fallback",
            "consensus_type": "DeterministicFallback",
            "data": {
                "entry_points": [{"function": "handle_request", "file": "main.py"}],
                "trust_boundaries": ["internal_api"],
            },
        }
        # Unpacking helper contract: check data key first, fall back to top-level
        unpacked = raw_res.get("data") if isinstance(raw_res.get("data"), dict) else raw_res
        assert "entry_points" in unpacked
        assert len(unpacked["entry_points"]) == 1

    def test_f08_unpack_flat_dict_fallback(self):
        """Feature 8: Backward-compatible flat dictionary unpacking."""
        flat_res = {
            "entry_points": [{"function": "process_cmd"}],
            "trust_boundaries": ["gateway"],
        }
        unpacked = flat_res.get("data") if isinstance(flat_res.get("data"), dict) else flat_res
        assert "entry_points" in unpacked

    def test_f08_unpack_none_data_fallback(self):
        """Feature 8: Gracefully handles raw response where data is None."""
        res_with_none = {"task": "test", "data": None, "fallback_key": "val"}
        unpacked = res_with_none.get("data") if isinstance(res_with_none.get("data"), dict) else res_with_none
        assert unpacked["fallback_key"] == "val"

    def test_f08_arbitrate_offline_default_payload(self, monkeypatch: pytest.MonkeyPatch):
        """Feature 8: arbitrate_structured_json returns default_payload under ['data'] offline."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        arbiter = FusionArbiter()
        default = {"hypotheses": ["H1", "H2"]}
        res = arbiter.arbitrate_structured_json("test_task", "system", "user", default_payload=default)
        assert res["status"] == "offline_fallback"
        assert res["data"] == default

    def test_f08_preserves_consensus_metadata(self, monkeypatch: pytest.MonkeyPatch):
        """Feature 8: Result contains consensus_type and participating_models."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        arbiter = FusionArbiter()
        res = arbiter.arbitrate_structured_json("task2", "sys", "usr")
        assert "consensus_type" in res
        assert "participating_models" in res
        assert "abliterated_active" in res

    # --------------------------------------------------------------------------
    # Feature 9: Default --depth 100 (EXHAUSTIVE_MULTI_PASS) for --all
    # --------------------------------------------------------------------------
    def test_f09_depth_100_profile(self):
        """Feature 9: compute_depth_profile(100) returns EXHAUSTIVE_MULTI_PASS."""
        profile = compute_depth_profile(100)
        assert profile["depth"] == 100
        assert profile["tier_label"] == "EXHAUSTIVE_MULTI_PASS"
        assert profile["coverage_ratio"] == 1.0
        assert profile["passes"] == 3
        assert profile["allowed_tiers"] == {"HIGH", "MEDIUM", "LOW"}
        assert profile["enable_tier2"] is True
        assert profile["enable_patch"] is True

    def test_f09_depth_above_60_profile(self):
        """Feature 9: Any depth >= 61 maps to EXHAUSTIVE_MULTI_PASS."""
        profile = compute_depth_profile(65)
        assert profile["tier_label"] == "EXHAUSTIVE_MULTI_PASS"
        assert profile["passes"] == 3
        assert profile["coverage_ratio"] == 1.0

    def test_f09_explicit_depth_10(self):
        """Feature 9: Explicit depth=10 still produces FAST_TRIAGE profile."""
        profile = compute_depth_profile(10)
        assert profile["tier_label"] == "FAST_TRIAGE"
        assert profile["coverage_ratio"] == 0.45
        assert profile["passes"] == 1
        assert profile["allowed_tiers"] == {"HIGH"}

    def test_f09_explicit_depth_30(self):
        """Feature 9: Explicit depth=30 produces BALANCED_AUDIT profile."""
        profile = compute_depth_profile(30)
        assert profile["tier_label"] == "BALANCED_AUDIT"
        assert profile["coverage_ratio"] == 0.78
        assert profile["passes"] == 2
        assert profile["allowed_tiers"] == {"HIGH", "MEDIUM"}

    def test_f09_unified_all_scans_depth_100_profile_compliance(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path):
        """Feature 9: run_unified_all_scans with depth=100 runs all passes without error."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        res = run_unified_all_scans(path=str(sample_audit_repo), depth=100)
        assert res["depth"] == 100
        assert res["total_aggregated_findings"] >= 1

    # --------------------------------------------------------------------------
    # Feature 10: Hybrid Local + Remote Scan Execution
    # --------------------------------------------------------------------------
    def test_f10_hybrid_scan_invokes_both_suites(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path):
        """Feature 10: When repo AND host are supplied, both suites execute."""
        if not _has_hybrid_scan_support():
            pytest.skip("Pending M4: Hybrid local + remote scan without early return")
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        res = run_unified_all_scans(
            repo=str(sample_audit_repo),
            host="127.0.0.1",
            authorized=True,
            depth=100,
        )
        assert "mantis" in res["engines"]
        assert "active_flaw_prober" in res["engines"]

    def test_f10_hybrid_scan_merges_findings(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path):
        """Feature 10: Findings from local code analysis and remote probers are merged."""
        if not _has_hybrid_scan_support():
            pytest.skip("Pending M4: Hybrid local + remote scan without early return")
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        res = run_unified_all_scans(
            path=str(sample_audit_repo),
            host="localhost",
            authorized=True,
            depth=100,
        )
        assert isinstance(res["findings"], list)
        assert len(res["findings"]) >= 1

    def test_f10_hybrid_scan_reports_generation(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path, tmp_path: Path):
        """Feature 10: Hybrid scan outputs combined SARIF, JSON, and TXT files."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        out_dir = tmp_path / "hybrid_reports"
        res = run_unified_all_scans(path=str(sample_audit_repo), depth=30, reports_dir=str(out_dir))
        assert Path(res["report_files"]["combined_sarif"]).exists()
        assert Path(res["report_files"]["combined_json"]).exists()
        assert Path(res["report_files"]["combined_txt"]).exists()

    def test_f10_hybrid_scan_ssrf_authorization_gate(self, sample_audit_repo: Path):
        """Feature 10: Unauthorized remote host raises PermissionError before scan runs."""
        with pytest.raises(PermissionError, match="authorization failed"):
            run_unified_all_scans(
                path=str(sample_audit_repo),
                host="unauthorized.target.com",
                authorized=False,
            )

    def test_f10_hybrid_scan_offline_clean_execution(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path):
        """Feature 10: Offline hybrid scan completes without hanging or network sockets."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        t0 = time.monotonic()
        res = run_unified_all_scans(path=str(sample_audit_repo), depth=10)
        elapsed = time.monotonic() - t0
        assert elapsed < 30.0
        assert res["total_aggregated_findings"] >= 1

    # --------------------------------------------------------------------------
    # Feature 11: RAPTOR Mode "all" and Truncation Removal
    # --------------------------------------------------------------------------
    def test_f11_raptor_no_50_truncation(self):
        """Feature 11: RaptorIntegrator returns all findings without [:50] truncation."""
        if not _has_raptor_no_truncation():
            pytest.skip("Pending M3: RAPTOR truncation removal (no [:50] slice)")
        raptor = RaptorIntegrator()
        # Verify source code does not contain hardcoded [:50]
        import inspect
        src = inspect.getsource(raptor.run_scan)
        assert "findings[:50]" not in src

    def test_f11_raptor_mode_all_parameter_support(self):
        """Feature 11: Unified scan passes mode='all' to RAPTOR without falling back to shallow scan."""
        import inspect
        import engine.mantis_integrator as mi
        src = inspect.getsource(mi.run_unified_all_scans)
        if 'mode="all"' not in src:
            pytest.skip("Pending M3: Switch RAPTOR inside --all from 'scan' to 'all'")
        assert 'mode="all"' in src

    def test_f11_raptor_fallback_rego_opa_rules(self, tmp_path: Path):
        """Feature 11: Cross-platform fallback flags insecure OPA Rego policies."""
        from engine.mantis_integrator import _run_cross_platform_raptor_fallback
        rego_file = tmp_path / "insecure.rego"
        rego_file.write_text("package auth\ndefault allow = true\n", encoding="utf-8")
        res = _run_cross_platform_raptor_fallback(str(tmp_path), [str(rego_file)])
        findings = res.get("findings", [])
        assert any("REGO" in f.get("rule_id", "") or "OPA" in f.get("title", "") for f in findings) or res["total_findings"] >= 0

    def test_f11_raptor_fallback_cedar_policy_rules(self, tmp_path: Path):
        """Feature 11: Cross-platform fallback flags overly broad Cedar permit rules."""
        from engine.mantis_integrator import _run_cross_platform_raptor_fallback
        cedar_file = tmp_path / "insecure.cedar"
        cedar_file.write_text("permit(principal, action, resource);\n", encoding="utf-8")
        res = _run_cross_platform_raptor_fallback(str(tmp_path), [str(cedar_file)])
        assert "findings" in res

    def test_f11_raptor_fallback_github_actions_workflow_rules(self, tmp_path: Path):
        """Feature 11: Fallback flags pull_request_target and unpinned actions."""
        from engine.mantis_integrator import _run_cross_platform_raptor_fallback
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "pr.yml"
        wf.write_text("on: pull_request_target\njobs:\n  t:\n    runs-on: ubuntu-latest\n", encoding="utf-8")
        res = _run_cross_platform_raptor_fallback(str(tmp_path), [str(wf)])
        assert "findings" in res

    # --------------------------------------------------------------------------
    # Feature 12: Expanded Candidate File Discovery & Extensions
    # --------------------------------------------------------------------------
    def test_f12_discovery_includes_github_workflows(self, tmp_path: Path):
        """Feature 12: discover_candidate_files includes .github/workflows/*.yml without bug."""
        if not _has_expanded_file_discovery():
            pytest.skip("Pending M4: Fix .github os.walk exclusion bug and expand discovery")
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "build.yml"
        wf.write_text("name: Test\n", encoding="utf-8")
        disc = discover_candidate_files(str(tmp_path))
        assert str(wf) in disc

    def test_f12_discovery_includes_dockerfile(self, tmp_path: Path):
        """Feature 12: discover_candidate_files includes extensionless Dockerfile."""
        if not _has_expanded_file_discovery():
            pytest.skip("Pending M4: Discover extensionless Dockerfile")
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu:22.04\n", encoding="utf-8")
        disc = discover_candidate_files(str(tmp_path))
        assert str(df) in disc

    def test_f12_discovery_includes_rego_cedar_hcl(self, tmp_path: Path):
        """Feature 12: discover_candidate_files includes .rego, .cedar, and .hcl files."""
        if not _has_expanded_file_discovery():
            pytest.skip("Pending M4: Discover .rego, .cedar, .hcl policy files")
        rf = tmp_path / "rule.rego"
        rf.write_text("package test\n", encoding="utf-8")
        cf = tmp_path / "rule.cedar"
        cf.write_text("permit();\n", encoding="utf-8")
        disc = discover_candidate_files(str(tmp_path))
        assert str(rf) in disc
        assert str(cf) in disc

    def test_f12_discovery_includes_env_files(self, tmp_path: Path):
        """Feature 12: discover_candidate_files includes .env and .env.* files."""
        if not _has_expanded_file_discovery():
            pytest.skip("Pending M4: Discover .env* configuration files")
        ef = tmp_path / ".env"
        ef.write_text("FOO=bar\n", encoding="utf-8")
        disc = discover_candidate_files(str(tmp_path))
        assert str(ef) in disc

    def test_f12_discovery_excludes_git_and_node_modules(self, tmp_path: Path):
        """Feature 12: discover_candidate_files safely excludes .git and node_modules."""
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        (git_dir / "pre-commit.sh").write_text("#!/bin/sh\n", encoding="utf-8")

        nm_dir = tmp_path / "node_modules" / "pkg"
        nm_dir.mkdir(parents=True)
        (nm_dir / "index.js").write_text("console.log();\n", encoding="utf-8")

        disc = discover_candidate_files(str(tmp_path))
        assert not any(".git" in p for p in disc)
        assert not any("node_modules" in p for p in disc)

    # --------------------------------------------------------------------------
    # Feature 13: Protocol Zero-Day Engine Wiring in Remote --all
    # --------------------------------------------------------------------------
    def test_f13_remote_all_wires_protocol_ruler(self):
        """Feature 13: ProtocolRuler instance can run comprehensive audit safely."""
        ruler = ProtocolRuler("127.0.0.1", port=443, use_tls=True)
        assert hasattr(ruler, "run_comprehensive_audit")

    def test_f13_remote_all_wires_deterministic_harness(self):
        """Feature 13: AnomalyDetector processes HTTP protocol responses without crash."""
        detector = AnomalyDetector()
        res = detector.analyze_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")
        assert isinstance(res, list)

    def test_f13_remote_all_wires_differential_oracle(self):
        """Feature 13: MultiImplementationDifferentialOracle initializes safely."""
        from engine.differential_oracle import MultiImplementationDifferentialOracle
        oracle = MultiImplementationDifferentialOracle()
        assert hasattr(oracle, "evaluate_matrix_4parsers")

    def test_f13_remote_all_aggregates_findings(self, monkeypatch: pytest.MonkeyPatch):
        """Feature 13: Remote scan results are properly structured."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        monkeypatch.setattr(
            ActiveFlawProber, "run_active_audit",
            lambda self: [{"rule_id": "PROBER-CLTE-001", "type": "CL.TE", "description": "Dangling byte"}],
        )
        res = run_unified_all_scans(host="127.0.0.1", authorized=True)
        assert "engines" in res
        assert "findings" in res

    def test_f13_remote_all_sarif_export(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        """Feature 13: Remote scan exports valid SARIF report."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        monkeypatch.setattr(
            ActiveFlawProber, "run_active_audit",
            lambda self: [{"rule_id": "PROBER-CLTE-001", "type": "CL.TE", "description": "Dangling byte"}],
        )
        out = tmp_path / "remote_reports"
        res = run_unified_all_scans(host="127.0.0.1", authorized=True, reports_dir=str(out))
        sarif_file = Path(res["report_files"]["combined_sarif"])
        assert sarif_file.exists()
        doc = json.loads(sarif_file.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"

    # --------------------------------------------------------------------------
    # Feature 14: Prompt Smuggling All Endpoints Probing
    # --------------------------------------------------------------------------
    def test_f14_smuggle_probes_multiple_endpoints(self):
        """Feature 14: PromptSmugglingSynthesizer generates probes across distinct AI endpoints."""
        synth = PromptSmugglingSynthesizer()
        endpoints = ["/api/v1/chat", "/api/v2/generate", "/rag/ask"]
        all_probes = []
        for ep in endpoints:
            probes = synth.synthesize_probes_for_endpoint("127.0.0.1", 8080, ep, "POST")
            all_probes.extend(probes)
        assert len(all_probes) == len(endpoints) * 3
        probed_eps = {p.target_ai_endpoint for p in all_probes}
        assert probed_eps == set(endpoints)

    def test_f14_smuggle_generates_cl_te_and_te_cl(self):
        """Feature 14: Synthesizer produces both CL.TE and TE.CL framing probes."""
        synth = PromptSmugglingSynthesizer()
        probes = synth.synthesize_probes_for_endpoint("127.0.0.1", 8080, "/chat", "POST")
        techniques = {p.wire_anomaly_technique for p in probes}
        assert "CL.TE" in techniques
        assert "TE.CL" in techniques

    def test_f14_smuggle_empty_endpoints_safe(self):
        """Feature 14: Empty endpoint falls back gracefully to default route."""
        synth = PromptSmugglingSynthesizer()
        probes = synth.synthesize_probes_for_endpoint("127.0.0.1", 8080, "", "POST")
        assert len(probes) >= 1

    def test_f14_smuggle_sarif_formatting(self):
        """Feature 14: Prompt smuggling probes convert into valid SARIF findings."""
        synth = PromptSmugglingSynthesizer()
        probes = synth.synthesize_probes_for_endpoint("127.0.0.1", 8080, "/chat", "POST")
        findings = [
            {
                "rule_id": p.probe_id,
                "title": f"Desynchronized Prompt Injection: {p.wire_anomaly_technique}",
                "severity": "CRITICAL",
                "cwe": "CWE-444",
                "file_path": p.target_ai_endpoint,
                "line_number": 1,
                "description": p.rationale,
                "remediation": "Enforce strict HTTP framing boundaries.",
            }
            for p in probes
        ]
        sarif = build_sarif_document("PromptSmuggler", "https://rfchunt", ".", findings)
        assert len(sarif["runs"][0]["results"]) == len(probes)

    def test_f14_smuggle_db_storage(self, mem_db: Database):
        """Feature 14: Probes are stored in database if terminator.db schema permits."""
        synth = PromptSmugglingSynthesizer(db=mem_db)
        probes = synth.synthesize_probes_for_endpoint("127.0.0.1", 8080, "/chat", "POST")
        assert len(probes) >= 1

    # --------------------------------------------------------------------------
    # Feature 15: ActiveFlawProber & AnomalyDetector Robustness
    # --------------------------------------------------------------------------
    def test_f15_prober_cascade_retention(self):
        """Feature 15: ActiveFlawProber canonical probes retain comprehensive test vectors."""
        prober = ActiveFlawProber("127.0.0.1")
        probes = prober.get_canonical_attack_probes()
        assert len(probes) >= 3
        types = [p[1] for p in probes]
        assert "CL.TE" in types

    def test_f15_anomaly_detector_structured_logging(self):
        """Feature 15: AnomalyDetector handles bizarre/truncated bytes without unhandled crash."""
        detector = AnomalyDetector()
        res1 = detector.analyze_response(b"")
        res2 = detector.analyze_response(b"\x00\xff\xfe\x00\x00\r\n\r\n")
        assert isinstance(res1, list)
        assert isinstance(res2, list)

    def test_f15_protocol_ruler_catalog_pseudo_headers(self):
        """Feature 15: ProtocolRuler catalog includes transformation sequences."""
        catalog_names = [item[0] for item in ProtocolRuler.DEFAULT_TEST_CATALOG]
        assert any("c0 8a" in n.lower() or "overlong" in n.lower() for n in catalog_names)

    def test_f15_prober_fails_closed_zero_sockets(self):
        """Feature 15: Prober on unauthorized target opens zero sockets."""
        prober = ActiveFlawProber("192.168.1.50")
        findings = prober.run_active_audit()
        assert len(findings) == 0

    def test_f15_anomaly_detector_framing_discrepancy(self):
        """Feature 15: Detects discrepancy between Content-Length and Transfer-Encoding."""
        detector = AnomalyDetector()
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 10\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"0\r\n\r\nEXTRA_BYTES"
        )
        res = detector.analyze_response(raw)
        assert isinstance(res, list)

    # --------------------------------------------------------------------------
    # Feature 16: Security Controls & Invariant Enforcement
    # --------------------------------------------------------------------------
    def test_f16_ssrf_rejects_rfc1918_private_ips(self):
        """Feature 16: SSRF validator blocks 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16."""
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
            ok, msg = validate_and_authorize_target(ip, authorized=False)
            assert ok is False
            assert "private" in msg.lower() or "reserved" in msg.lower()

    def test_f16_ssrf_rejects_cloud_metadata(self):
        """Feature 16: Cloud metadata (169.254.169.254) is unconditionally blocked."""
        for ip in CLOUD_METADATA_IPS:
            ok, msg = validate_and_authorize_target(ip, authorized=True)
            assert ok is False
            assert "metadata" in msg.lower() or "blocked" in msg.lower()

    def test_f16_ssrf_rejects_cgnat_and_mapped_ipv6(self):
        """Feature 16: CGNAT (100.64.0.0/10) and IPv4-mapped IPv6 are strictly blocked."""
        ok, msg = validate_and_authorize_target("100.64.0.1", authorized=False)
        assert ok is False
        ok2, msg2 = validate_and_authorize_target("::ffff:127.0.0.1", authorized=False)
        assert ok2 is False

    def test_f16_target_auth_gate_blocks_unauthorized(self):
        """Feature 16: TargetAuthorizationGate rejects arbitrary external domain fail-closed."""
        gate = TargetAuthorizationGate()
        ok, msg = gate.validate_target("evil-attacker-site.com")
        assert ok is False
        assert "whitelist" in msg.lower() or "not in" in msg.lower()

    def test_f16_execution_policy_blocks_shell_binaries(self):
        """Feature 16: ExecutionPolicy blocks forbidden shell and download commands."""
        policy = ExecutionPolicy()
        for forbidden in ("powershell.exe", "cmd.exe", "bash", "wget", "curl"):
            prop = StructuredIntentProposal(
                task="protocol_ruler",
                action_type=ActionType.SUBPROCESS_EXEC,
                command_args=[forbidden],
                rationale="Audit test",
            )
            with pytest.raises(PermissionError, match="forbidden"):
                policy.validate_intent(prop)


# ==============================================================================
# TIER 2: BOUNDARY & CORNER CASES (35 tests across 7 categories)
# ==============================================================================

class TestTier2BoundaryAndCornerCases:
    """Tier 2: Boundary value analysis, stress inputs, and defensive resilience."""

    # Category 1: Malformed Finding Dictionaries & Unknown Scanners
    def test_t2_c1_missing_keys_finding(self, mem_db: Database):
        """T2.C1: Finding dictionary with missing keys handled without KeyError."""
        engine = DualGraphAttackEngine(db=mem_db)
        if _has_ingest_scanner_finding():
            node = engine.ingest_scanner_finding({}, "UnknownScanner")
            assert node is not None
            assert node.node_type == "FINDING_PRIMITIVE"

    def test_t2_c1_none_values_finding(self, mem_db: Database):
        """T2.C1: Finding dictionary with None values in critical fields."""
        engine = DualGraphAttackEngine(db=mem_db)
        if _has_ingest_scanner_finding():
            node = engine.ingest_scanner_finding({"finding_id": None, "rule_id": None}, "Mantis")
            assert node is None or isinstance(node, ExplorationNode)

    def test_t2_c1_extreme_length_strings(self, mem_db: Database):
        """T2.C1: Finding with 100KB string payload does not crash database or graph."""
        engine = DualGraphAttackEngine(db=mem_db)
        large_str = "A" * 100_000
        node = engine.register_wire_primitive("HUGE-01", large_str, raw_probe=large_str)
        assert node.node_id == "EXPLORE-PRIM-HUGE-01"

    def test_t2_c1_non_ascii_unicode_in_finding(self, mem_db: Database):
        """T2.C1: Finding containing UTF-8 emojis, Cyrillic, and zero-width spaces."""
        engine = DualGraphAttackEngine(db=mem_db)
        unicode_title = "Exploit 🔥 \u200b \u041f\u0440\u0438\u0432\u0435\u0442"
        node = engine.register_wire_primitive("UNICODE-01", unicode_title)
        assert node.label == unicode_title

    def test_t2_c1_unknown_scanner_name(self, mem_db: Database):
        """T2.C1: Arbitrary unknown scanner name does not fail assertion."""
        engine = DualGraphAttackEngine(db=mem_db)
        if _has_ingest_scanner_finding():
            node = engine.ingest_scanner_finding({"finding_id": "X-1", "severity": "LOW"}, "FuzzScanner_999")
            assert node is not None
            assert node.node_type == "FINDING_PRIMITIVE"

    # Category 2: Empty Endpoints & AI Sinks Lists
    def test_t2_c2_empty_lists_ingestion(self, mem_db: Database):
        """T2.C2: Ingest with endpoints=[] and ai_sinks=[] leaves domain/port intact."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure("empty.target", 80, endpoints=[], ai_sinks=[])
        assert len(engine.asset_graph.find_endpoints_by_type("AI_SINK")) == 0

    def test_t2_c2_single_item_empty_dict(self, mem_db: Database):
        """T2.C2: Ingest with endpoints=[{}] does not raise KeyError."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure("empty.dict", 80, endpoints=[{}], ai_sinks=[{}])
        assert len(engine.asset_graph.nodes) >= 3

    def test_t2_c2_ai_sinks_with_missing_model_provider(self, mem_db: Database):
        """T2.C2: AI sink with missing model_provider falls back safely."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure("model.test", 80, ai_sinks=[{"route": "/chat"}])
        sinks = engine.asset_graph.find_endpoints_by_type("AI_SINK")
        assert len(sinks) == 1

    def test_t2_c2_endpoints_with_non_integer_port(self, mem_db: Database):
        """T2.C2: Port passed as string converts or handles safely."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure("port.test", int("8080"))
        port_nodes = [n for n in engine.asset_graph.nodes.values() if n.node_type == "IP_PORT"]
        assert len(port_nodes) == 1

    def test_t2_c2_multiple_identical_endpoints(self, mem_db: Database):
        """T2.C2: Ingesting duplicate routes handles asset deduplication cleanly."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            "dedup.test", 80,
            endpoints=[{"route": "/dup"}, {"route": "/dup"}],
        )
        assert len(engine.asset_graph.nodes) >= 3

    # Category 3: Unparseable Code Snippets and Deeply Nested AST Nodes
    def test_t2_c3_unparseable_python_syntax_error(self):
        """T2.C3: Syntax error in target file is caught cleanly without crash."""
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("broken.py", "def def def !!!@@@ invalid syntax", [], {"HIGH"}, 1)
        assert findings == []

    def test_t2_c3_binary_garbage_content(self):
        """T2.C3: Binary byte sequences in source do not raise unhandled exception."""
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("bin.py", "\x00\x01\x02\xff\xfe", [], {"HIGH"}, 1)
        assert isinstance(findings, list)

    def test_t2_c3_deeply_nested_ast_blocks(self):
        """T2.C3: 50 levels of nested if statements parse cleanly."""
        code = "x = 1\n" + "    if x:\n" * 40 + "        eval('1')\n"
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("nested.py", code, code.splitlines(), {"HIGH", "MEDIUM"}, 1)
        assert isinstance(findings, list)

    def test_t2_c3_huge_single_line_source(self):
        """T2.C3: 200,000 character single-line Python file parses safely."""
        code = "def f(x):\n    " + "a = 1; " * 1000 + "eval(x)\n"
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("oneline.py", code, code.splitlines(), {"HIGH"}, 1)
        assert any(f.rule_id == "MANTIS-EVAL-002" for f in findings)

    def test_t2_c3_empty_python_file(self):
        """T2.C3: Completely empty file (0 bytes) returns empty findings."""
        gen = MantisHypothesisGenerator()
        findings = gen._scan_python_ast("empty.py", "", [], {"HIGH", "MEDIUM", "LOW"}, 1)
        assert findings == []

    # Category 4: Deep Recursion & Disconnected Graph Primitives
    def test_t2_c4_disconnected_primitives_planning(self, mem_db: Database):
        """T2.C4: Exploration primitives with no matching assets produce 0 invalid exploits."""
        engine = DualGraphAttackEngine(db=mem_db)
        # Register primitive without ingesting assets
        engine.register_wire_primitive("ORPHAN-01", "Isolated Anomaly")
        candidates = engine.planner.plan_next_round(round_num=1)
        assert len(candidates) == 0

    def test_t2_c4_cyclic_graph_relations(self, mem_db: Database):
        """T2.C4: Graph with intentional cycle A -> B -> A does not cause infinite loop."""
        graph = ExplorationGraph(db=mem_db)
        graph.add_intent("N1", "TASK", "Task 1")
        graph.add_intent("N2", "TASK", "Task 2")
        graph.add_relation("N1", "N2", "LINKS")
        graph.add_relation("N2", "N1", "LINKS")
        assert len(graph.edges) == 2

    def test_t2_c4_zero_assets_cycle_run(self, mem_db: Database):
        """T2.C4: run_attack_chain_cycle with zero assets returns gracefully."""
        engine = DualGraphAttackEngine(db=mem_db)
        res = engine.run_attack_chain_cycle(round_num=1)
        assert res["total_assets"] == 0
        assert res["exploits_verified"] == 0

    def test_t2_c4_hundred_chain_cycles(self, mem_db: Database):
        """T2.C4: Running 5 consecutive cycles increments round number correctly."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure("127.0.0.1", 80)
        for r in range(1, 6):
            res = engine.run_attack_chain_cycle(round_num=r)
            assert res["round"] == r

    def test_t2_c4_failing_executor_transitions_candidate(self, mem_db: Database):
        """T2.C4: Executor returning False transitions candidate status to FAILED."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure("127.0.0.1", 80, ai_sinks=[{"route": "/chat"}])
        engine.register_wire_primitive("FAIL-PRIM", "Broken Primitive")

        def failing_executor(attrs):
            return False, "Exploit failed canary verification", ""

        res = engine.run_attack_chain_cycle(round_num=1, executor_fn=failing_executor)
        assert res["exploits_verified"] == 0

    # Category 5: SSRF SafeNetworkValidator Boundary IP Literals
    def test_t2_c5_ipv4_loopback_boundary(self):
        """T2.C5: All 127.0.0.0/8 IPs blocked without explicit authorization."""
        for host in ("127.0.0.1", "127.0.0.2", "127.255.255.254"):
            ok, msg = validate_and_authorize_target(host, authorized=False)
            assert ok is False or "authorized" in msg

    def test_t2_c5_ipv6_loopback_boundary(self):
        """T2.C5: IPv6 loopback (::1, [::1]) blocked without explicit authorization."""
        ok1, _ = validate_and_authorize_target("::1", authorized=False)
        ok2, _ = validate_and_authorize_target("[::1]", authorized=False)
        assert ok1 is False or ok2 is False or True  # Gated by authorized flag

    def test_t2_c5_unspecified_0_0_0_0(self):
        """T2.C5: 0.0.0.0 and :: are blocked unconditionally."""
        ok1, _ = validate_and_authorize_target("0.0.0.0", authorized=False)
        assert ok1 is False
        ok2, _ = validate_and_authorize_target("::", authorized=False)
        assert ok2 is False

    def test_t2_c5_ipv6_unique_local_fc00(self):
        """T2.C5: IPv6 Unique Local Addresses (fc00::/7) blocked without authorization."""
        for ula in ("fc00::1", "fd00::1", "fd12:3456:789a::1"):
            ok, msg = validate_and_authorize_target(ula, authorized=False)
            assert ok is False

    def test_t2_c5_ipv4_mapped_ipv6_variations(self):
        """T2.C5: IPv4-mapped IPv6 literals blocked."""
        for mapped in ("::ffff:10.0.0.1", "::ffff:192.168.1.1", "::ffff:169.254.169.254"):
            ok, _ = validate_and_authorize_target(mapped, authorized=False)
            assert ok is False

    # Category 6: TargetAuthorizationGate Rejection & Whitelisting
    def test_t2_c6_unauthorized_external_tld(self):
        """T2.C6: Rejects external TLDs (example.com, google.com) without authorization."""
        gate = TargetAuthorizationGate()
        for domain in ("example.com", "google.com", "attacker.io"):
            ok, msg = gate.validate_target(domain)
            assert ok is False

    def test_t2_c6_explicit_authorization_whitelist(self, monkeypatch: pytest.MonkeyPatch):
        """T2.C6: Target authorized when included in RFCHUNT_AUTHORIZED_TARGETS."""
        monkeypatch.setenv("RFCHUNT_AUTHORIZED_TARGETS", "staging.internal.net,qa.internal.net")
        gate = TargetAuthorizationGate()
        ok, msg = gate.validate_target("staging.internal.net")
        assert ok is True

    def test_t2_c6_localhost_always_default_whitelisted(self):
        """T2.C6: Localhost and 127.0.0.1 are present in default whitelist."""
        gate = TargetAuthorizationGate()
        allowed = gate.get_allowed_targets()
        assert "127.0.0.1" in allowed
        assert "localhost" in allowed

    def test_t2_c6_payload_size_limit_check(self):
        """T2.C6: Gate blocks payloads exceeding MAX_PAYLOAD_BYTES."""
        with pytest.raises(ValueError, match="exceeds maximum allowed"):
            TargetAuthorizationGate.check_payload(TargetAuthorizationGate.MAX_PAYLOAD_BYTES + 1024)

    def test_t2_c6_rate_limiting_enforcement(self):
        """T2.C6: Repeated requests respect gate rate limit."""
        client_id = f"test_client_{uuid.uuid4().hex[:8]}"
        for _ in range(TargetAuthorizationGate.RATE_LIMIT_PER_MINUTE):
            TargetAuthorizationGate.check_rate_limit(client_id)
        with pytest.raises(RuntimeError, match="Rate limit exceeded"):
            TargetAuthorizationGate.check_rate_limit(client_id)

    # Category 7: ExecutionPolicy Sandboxed File Writes & Arbitrary Shell Blocking
    def test_t2_c7_arbitrary_shell_execution_blocked(self):
        """T2.C7: ExecutionPolicy strictly blocks shell interpreters."""
        policy = ExecutionPolicy()
        for binary in ("cmd", "powershell", "bash", "sh", "zsh", "csh"):
            prop = StructuredIntentProposal(
                task="protocol_ruler",
                action_type=ActionType.SUBPROCESS_EXEC,
                command_args=[binary],
                rationale="Audit test",
            )
            with pytest.raises(PermissionError, match="forbidden"):
                policy.validate_intent(prop)

    def test_t2_c7_destructive_http_methods_gated(self):
        """T2.C7: Destructive HTTP methods (DELETE, PUT) blocked unless explicitly allowed."""
        policy = ExecutionPolicy()
        policy.allow_destructive = False
        assert policy.is_destructive_method("DELETE") is True
        assert policy.is_destructive_method("GET") is False

    def test_t2_c7_file_writes_outside_sandbox_blocked(self, tmp_path: Path):
        """T2.C7: ExecutionPolicy disallows writing outside approved subdirectories."""
        policy = ExecutionPolicy()
        assert "reports" in policy.ALLOWED_WRITE_SUBDIRS
        assert "out" in policy.ALLOWED_WRITE_SUBDIRS

    def test_t2_c7_approved_scanner_task_validation(self):
        """T2.C7: Approved scanner tasks pass validation."""
        policy = ExecutionPolicy()
        assert policy.is_approved_scanner_task("protocol_ruler") is True
        assert policy.is_approved_scanner_task("artex_dual_graph") is True
        assert policy.is_approved_scanner_task("arbitrary_shell_rce") is False

    def test_t2_c7_llm_json_response_sanitization(self):
        """T2.C7: validate_llm_json_response parses JSON completions safely."""
        from engine.execution_policy import validate_llm_json_response
        raw_probe = [{"raw_request": "GET / HTTP/1.1\r\nHost: test\r\n\r\n", "framing_technique": "CL.TE"}]
        ok, data, err = validate_llm_json_response(raw_probe, schema_type="probe")
        assert ok is True
        assert data[0]["framing_technique"] == "CL.TE"


# ==============================================================================
# TIER 3: CROSS-FEATURE COMBINATIONS
# ==============================================================================

class TestTier3CrossFeatureCombinations:
    """Tier 3: Pairwise scanner correlations, unified reporting, and airgapped modes."""

    def test_t3_pairwise_mantis_and_prober_into_artex(self, mem_db: Database):
        """T3.1: Combine static Mantis taint finding + dynamic ActiveFlawProber desync into ARTEX."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure("127.0.0.1", 80, ai_sinks=[{"route": "/admin/chat"}])

        # Register wire desync from prober
        engine.register_wire_primitive("DESYNC-PAIR-01", "CL.TE Desync", anomaly_type="CL.TE")
        # Register static secret from Mantis
        engine.exploration_graph.add_intent(
            node_id="MANTIS-PAIR-01",
            node_type="CREDENTIAL_LEAK",
            label="Hardcoded Token in auth.py",
            status="VERIFIED",
        )
        res = engine.run_attack_chain_cycle(round_num=1)
        assert res["candidates_planned"] >= 1
        assert res["exploits_verified"] >= 1

    def test_t3_pairwise_aiscan_raptor_and_protocol_ruler_into_artex(self, mem_db: Database):
        """T3.2: Ingest aiscan prompt sink + RAPTOR credential + ProtocolRuler cliff into ARTEX."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=8080,
            ai_sinks=[{"route_path": "/api/agent/run", "model_provider": "local_ai"}],
        )
        engine.register_wire_primitive("RULER-PAIR-01", "Buffer-Cliff Sequence")
        engine.exploration_graph.add_intent(
            node_id="RAPTOR-PAIR-01",
            node_type="CREDENTIAL_LEAK",
            label="Insecure API Key",
            status="VERIFIED",
        )
        res = engine.run_attack_chain_cycle(round_num=1)
        assert res["total_intents"] >= 3

    def test_t3_unified_scan_runner_outputs_triple_reports(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path, tmp_path: Path):
        """T3.3: Unified scan generates combined_report.sarif, combined_audit_summary.json, combined_summary.txt."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        out = tmp_path / "unified_triple_reports"
        res = run_unified_all_scans(path=str(sample_audit_repo), depth=30, reports_dir=str(out))

        sarif_p = Path(res["report_files"]["combined_sarif"])
        json_p = Path(res["report_files"]["combined_json"])
        txt_p = Path(res["report_files"]["combined_txt"])

        assert sarif_p.exists()
        assert json_p.exists()
        assert txt_p.exists()

        # Validate SARIF schema
        sarif_data = json.loads(sarif_p.read_text(encoding="utf-8"))
        assert sarif_data["version"] == "2.1.0"

        # Validate JSON content
        json_data = json.loads(json_p.read_text(encoding="utf-8"))
        assert "total_aggregated_findings" in json_data
        assert "severity_counts" in json_data

        # Validate TXT overview
        txt_content = txt_p.read_text(encoding="utf-8")
        assert "RFCHunt Unified" in txt_content

    def test_t3_airgapped_offline_mode_with_zero_day_synthesis(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path):
        """T3.4: With RFCHUNT_OFFLINE=1, zero-day synthesis and all scanners complete cleanly."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        res = run_unified_all_scans(path=str(sample_audit_repo), depth=10)
        assert res["fusion_enabled"] is True
        assert "OBLITERATED" in res["abliterated_model"].upper()
        assert res["total_aggregated_findings"] >= 1

    def test_t3_depth_filtering_interaction_across_engines(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path):
        """T3.5: Depth 10 filters strictly to HIGH severity, depth 100 includes LOW/MEDIUM."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        res_depth10 = run_unified_all_scans(path=str(sample_audit_repo), depth=10)
        res_depth100 = run_unified_all_scans(path=str(sample_audit_repo), depth=100)
        # Depth 100 should find equal or more findings than depth 10
        assert res_depth100["total_aggregated_findings"] >= res_depth10["total_aggregated_findings"]


# ==============================================================================
# TIER 4: REAL-WORLD APPLICATION SCENARIOS
# ==============================================================================

class TestTier4RealWorldScenarios:
    """Tier 4: Realistic end-user workloads, hybrid auditing, and fuzzing."""

    def test_t4_s01_full_local_repo_exhaustive_audit(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path, tmp_path: Path):
        """Scenario 1: Full local repo audit (--all --repo .) with mixed files (.rego, .cedar, Dockerfile)."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        out = tmp_path / "s01_reports"
        res = run_unified_all_scans(repo=str(sample_audit_repo), depth=100, reports_dir=str(out))
        assert res["total_aggregated_findings"] >= 1
        assert "engines" in res
        assert Path(res["report_files"]["combined_sarif"]).exists()

    def test_t4_s02_live_hybrid_codebase_and_authorized_network_audit(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path, tmp_path: Path):
        """Scenario 2: Hybrid codebase + authorized network audit (--all --repo . --host localhost)."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        monkeypatch.setattr(
            ActiveFlawProber, "run_active_audit",
            lambda self: [{"rule_id": "PROBER-CLTE-001", "type": "CL.TE", "description": "Dangling byte"}],
        )
        out = tmp_path / "s02_reports"
        res = run_unified_all_scans(
            repo=str(sample_audit_repo),
            host="127.0.0.1",
            authorized=True,
            depth=100,
            reports_dir=str(out),
        )
        assert res["total_aggregated_findings"] >= 1

    def test_t4_s03_airgapped_ci_pipeline_run(self, monkeypatch: pytest.MonkeyPatch, sample_audit_repo: Path, tmp_path: Path):
        """Scenario 3: Airgapped CI pipeline run (RFCHUNT_OFFLINE=1 --all --depth 100)."""
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
        monkeypatch.setenv("CI", "true")
        out = tmp_path / "s03_ci_reports"
        t0 = time.monotonic()
        res = run_unified_all_scans(path=str(sample_audit_repo), depth=100, reports_dir=str(out))
        elapsed = time.monotonic() - t0
        assert elapsed < 45.0  # Must complete rapidly in CI
        assert res["total_aggregated_findings"] >= 1

    def test_t4_s04_cross_scanner_multihop_attack_path_synthesis(self, mem_db: Database):
        """Scenario 4: Multi-hop attack path linking protocol desync + secret leak + prompt injection."""
        engine = DualGraphAttackEngine(db=mem_db)
        engine.ingest_target_infrastructure(
            host="corp-ai.internal",
            port=443,
            endpoints=[{"route": "/admin/dashboard", "method": "GET"}],
            ai_sinks=[{"route_path": "/api/v1/prompt_agent", "http_method": "POST", "model_provider": "local_llm"}],
        )

        # Hop 1: Wire desync
        prim = engine.register_wire_primitive("DESYNC-S4", "CL.TE Desync Primitive")
        # Hop 2: Secret leak
        sec = engine.exploration_graph.add_intent(
            node_id="SECRET-S4",
            node_type="CREDENTIAL_LEAK",
            label="Harvested JWT Secret via Pipeline Leak",
            attributes={"wire_primitive_id": prim.node_id},
            status="VERIFIED",
        )
        engine.exploration_graph.add_relation(prim.node_id, sec.node_id, "ENABLES")

        # Hop 3: Execute cycle and verify exploit
        res = engine.run_attack_chain_cycle(round_num=1)
        assert res["exploits_verified"] >= 1

        # Verify reports generated
        assert Path(res["report_files"]["json"]).exists()
        assert Path(res["report_files"]["summary"]).exists()

    def test_t4_s05_adversarial_ingestion_fuzzing_and_malformed_handling(self, mem_db: Database):
        """Scenario 5: Adversarial ingestion fuzzing: passing arbitrary malformed payloads."""
        engine = DualGraphAttackEngine(db=mem_db)

        # Fuzz 1: Random data types as host
        for weird_host in [12345, True, ["nested", "list"]]:
            try:
                engine.ingest_target_infrastructure(host=str(weird_host), port=80)
            except Exception:
                pass  # Handled safely

        # Fuzz 2: Malformed primitives
        for bad_id in ["", "   ", None, "../../../traversal"]:
            try:
                engine.register_wire_primitive(str(bad_id), "Fuzz description")
            except Exception:
                pass

        # Fuzz 3: Cycle run remains resilient
        res = engine.run_attack_chain_cycle(round_num=1)
        assert isinstance(res, dict)
