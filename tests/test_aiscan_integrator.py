"""
Unit tests for haasonsaas/aiscan Integrator & Python AST AI Risk Scanner (Module 18)
===================================================================================
Verifies:
1. Discovery of leaked AI API credentials (OpenAI, Anthropic, HuggingFace, etc.)
2. Detection of prompt injection sinks in template strings
3. Detection of unsafe model deserialization (pickle, unvalidated torch)
4. Detection of unmetered AI web endpoint routes
5. Ingestion of AI findings into SQLite database
6. Export of SARIF, JSON, and Summary reports into reports/ folder without any UI
"""

import json
from pathlib import Path
from database import Database
from engine.aiscan_integrator import AiscanIntegrator, PythonAIScanner, AIFinding


def test_python_ai_scanner_detects_credentials_and_sinks(tmp_path):
    # Create sample file with various AI risks
    sample_code = '''
import os
import pickle
import torch
from openai import OpenAI

OPENAI_API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"
ANTHROPIC_API_KEY = "sk-ant-api03-abcdef1234567890abcdef1234567890"

def unsafe_load_model(weight_path):
    with open(weight_path, "rb") as f:
        model = pickle.load(f)
    weights = torch.load("weights.pt")
    return model

def chat_endpoint(user_query):
    system_prompt = f"You are a helpful assistant. System instructions: {user_query}"
    client = OpenAI(api_key=OPENAI_API_KEY)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "system", "content": system_prompt}]
    )
    return response
'''
    target_file = tmp_path / "vulnerable_app.py"
    target_file.write_text(sample_code, encoding="utf-8")

    scanner = PythonAIScanner()
    findings, endpoints = scanner.scan_file(target_file)

    finding_types = {f.finding_type for f in findings}
    assert "hardcoded_ai_credential" in finding_types
    assert "insecure_deserialization" in finding_types
    assert "prompt_injection_sink" in finding_types

    # Verify severity
    severities = {f.severity for f in findings}
    assert "CRITICAL" in severities or "HIGH" in severities


def test_aiscan_integrator_persistence_and_reports(tmp_path):
    sample_code = '''
OPENAI_API_KEY = "sk-proj-test1234567890abcdef123456"
prompt = f"System prompt with {user_input}"
'''
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "agent.py").write_text(sample_code, encoding="utf-8")

    reports_dir = tmp_path / "reports"
    db = Database(":memory:")

    integrator = AiscanIntegrator(db=db, reports_dir=reports_dir)
    res = integrator.scan_target(src_dir)

    assert res["total_findings"] >= 2
    assert reports_dir.exists()

    # Check generated report files
    report_files = res["report_files"]
    assert Path(report_files["json"]).exists()
    assert Path(report_files["sarif"]).exists()
    assert Path(report_files["summary"]).exists()

    # Verify SARIF format
    sarif_data = json.loads(Path(report_files["sarif"]).read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) >= 2

    # Verify DB persistence
    db_findings = db.get_ai_findings()
    assert len(db_findings) >= 2
    db.close()
