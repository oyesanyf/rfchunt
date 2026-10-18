"""
Unit & Integration Tests for RAPTOR Framework Integration:
1. Verifies proper attribution to Gadi Evron, Daniel Cuthbert, and Thomas Dullien (Halvar Flake).
2. Verifies RaptorIntegrator status checking and Docker/Ollama diagnostics.
3. Verifies SARIF file parsing and normalized finding extraction.
4. Verifies database ingestion into terminator.db.
5. Verifies MCP tool exposure in mcp_server.py.
6. Verifies CLI execution across --host and --target paths in rfc_hunt_swarm.py.
"""

import json
from pathlib import Path
import pytest

from engine.raptor_integrator import (
    RaptorIntegrator,
    RAPTOR_PROJECT_TITLE,
    RAPTOR_AUTHORS,
    RAPTOR_REPO_URL,
    RAPTOR_DOCKER_IMAGE,
)
from database import Database
from mcp_server import TerminatorMCPServer
from rfc_hunt_swarm import parse_swarm_arguments, cmd_raptor, ALL_MODES


def test_raptor_attribution_metadata():
    """Ensures mandatory credit and attribution to the RAPTOR authors."""
    assert "RAPTOR" in RAPTOR_PROJECT_TITLE
    assert "Gadi Evron" in RAPTOR_AUTHORS
    assert "Daniel Cuthbert" in RAPTOR_AUTHORS
    assert "Halvar Flake" in RAPTOR_AUTHORS or "Thomas Dullien" in RAPTOR_AUTHORS
    assert "https://github.com/gadievron/raptor" in RAPTOR_REPO_URL

    banner = RaptorIntegrator.get_attribution_banner()
    assert "Gadi Evron" in banner
    assert "Daniel Cuthbert" in banner
    assert "Halvar Flake" in banner
    assert "danielcuthbert/raptor:latest" in banner


def test_raptor_status_check():
    """Verifies that RaptorIntegrator checks Docker image readiness and Ollama models."""
    integrator = RaptorIntegrator()
    status = integrator.check_status()

    assert "docker_ready" in status
    assert "ollama_ready" in status
    assert "attribution" in status
    assert status["attribution"]["title"] == RAPTOR_PROJECT_TITLE
    assert status["attribution"]["authors"] == RAPTOR_AUTHORS


def test_sarif_parsing_and_db_ingestion(tmp_path):
    """Verifies that SARIF vulnerability findings are parsed and ingested into terminator.db."""
    # 1. Create a synthetic valid SARIF report
    sarif_data = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RAPTOR-Semgrep",
                        "version": "3.1.0",
                    }
                },
                "results": [
                    {
                        "ruleId": "raptor.http.crlf-header-injection",
                        "level": "error",
                        "message": {"text": "Unsanitized user input forwarded into HTTP response header."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/proxy/handler.py"},
                                    "region": {
                                        "startLine": 42,
                                        "snippet": {"text": "response.headers['X-Custom'] = user_input"},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    sarif_file = tmp_path / "test_report.sarif"
    sarif_file.write_text(json.dumps(sarif_data), encoding="utf-8")

    # 2. Parse SARIF
    findings = RaptorIntegrator.parse_sarif_file(sarif_file)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "raptor.http.crlf-header-injection"
    assert f["severity"] == "ERROR"
    assert f["file"] == "src/proxy/handler.py"
    assert f["line"] == 42
    assert "Unsanitized" in f["message"]

    # 3. Ingest into test DB
    test_db_path = str(tmp_path / "test_terminator.db")
    db = Database(test_db_path)
    try:
        integrator = RaptorIntegrator(db=db)

        count = integrator.ingest_findings_to_db(findings, target_engine="target.example.com:443")
        assert count == 1

        # Verify presence in database
        cur = db.conn.cursor()
        cur.execute("SELECT anomaly_id, target_engine, observed_behavior FROM implementation_anomalies WHERE target_engine = 'target.example.com:443'")
        rows = cur.fetchall()
        assert len(rows) == 1
        assert "crlf-header-injection" in rows[0]["observed_behavior"]
    finally:
        db.close()


def test_mcp_server_raptor_tool_exposure(tmp_path):
    """Verifies that TerminatorMCPServer exposes RAPTOR security tools over JSON-RPC."""
    test_db = str(tmp_path / "mcp_test.db")
    with TerminatorMCPServer(db_path=test_db) as server:
        tool_defs = server._get_tool_definitions()
        tool_names = [t["name"] for t in tool_defs]

        assert "raptor_status" in tool_names
        assert "raptor_describe_target" in tool_names
        assert "raptor_scan_project" in tool_names
        assert "raptor_list_findings" in tool_names

        # Check that tool descriptions explicitly give credit to RAPTOR authors
        raptor_desc = next(t["description"] for t in tool_defs if t["name"] == "raptor_status")
        assert "Gadi Evron" in raptor_desc
        assert "Daniel Cuthbert" in raptor_desc
        assert "Halvar Flake" in raptor_desc

        # Test raptor_status tool call
        res = server._execute_tool("raptor_status", {})
        assert "attribution" in res
        assert "docker_ready" in res


def test_rfc_hunt_swarm_raptor_cli_modes(tmp_path):
    """Verifies that rfc_hunt_swarm.py parses RAPTOR commands and executes status checks."""
    assert "raptor" in ALL_MODES

    # 1. Parse positional subcommand: raptor --status
    args1 = parse_swarm_arguments(["raptor", "--status"])
    assert args1.command == "raptor"
    assert args1.raptor_status is True

    # 2. Parse flag-based execution against a remote host: --mode raptor --host target.com
    args2 = parse_swarm_arguments(["--mode", "raptor", "--host", "target.com", "--port", "443", "--tls"])
    assert args2.mode == "raptor"
    assert args2.host == "target.com"
    assert args2.port == 443
    assert args2.tls is True

    # 3. Parse target repo audit: raptor --repo D:\some\path --raptor-mode agentic
    args3 = parse_swarm_arguments(["raptor", "--repo", str(tmp_path), "--raptor-mode", "agentic"])
    assert args3.command == "raptor"
    assert args3.raptor_target == str(tmp_path)
    assert args3.raptor_mode == "agentic"


def test_raptor_help_manual(capsys):
    """Verifies that raptor --help prints dedicated help with full attribution."""
    from rfc_hunt_swarm import print_raptor_help
    print_raptor_help()
    captured = capsys.readouterr()
    assert "RAPTOR: Autonomous Offensive/Defensive Research Framework" in captured.out
    assert "Gadi Evron" in captured.out
    assert "Daniel Cuthbert" in captured.out
    assert "Halvar Flake" in captured.out
    assert "https://github.com/gadievron/raptor" in captured.out
    assert "--host HOST" in captured.out
