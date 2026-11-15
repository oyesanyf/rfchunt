"""Tests enforcing codebase-wide refusal-free abliterated trio panel defaults:
Abliterated Gemma + Cisco Foundation-Sec + GLM-4 (with abliterated priority).
"""

import inspect
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from continuous_scanner import ContinuousFlawHunter  # noqa: E402
from engine.mantis_integrator import (  # noqa: E402
    DEFAULT_ABLITERATED_MODEL,
    DEFAULT_ARBITER_MODEL,
    DEFAULT_SEC_MODEL,
    MantisIntegrator,
)
from fusion_engine import FusionArbiter  # noqa: E402
from mcp_server import TerminatorMCPServer  # noqa: E402
from model_adapter import ModelFusionAdapter  # noqa: E402
import rfc_hunt_swarm  # noqa: E402
import start  # noqa: E402


def test_fusion_arbiter_defaults_to_abliterated_gemma_cisco_and_glm():
    installed = [
        "gemma2:2b",
        "deepseek-r1:1.5b",
        "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
        "fenkohq/foundation-sec-8b:latest",
        "glm4:9b",
        "glm-4.7-flash:latest",
    ]
    with patch.object(FusionArbiter, "_fetch_available_tags", return_value=installed):
        arb = FusionArbiter()
    assert arb.gemma_model == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
    assert arb.sec_model == "fenkohq/foundation-sec-8b:latest"
    assert arb.arbiter_model == "glm4:9b"


def test_fusion_arbiter_upgrades_to_abliterated_cisco_and_glm_when_pulled():
    installed = [
        "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
        "huihui_ai/foundation-sec-abliterated:8b",
        "fenkohq/foundation-sec-8b:latest",
        "huihui_ai/glm-4.7-abliterated",
        "glm4:9b",
    ]
    with patch.object(FusionArbiter, "_fetch_available_tags", return_value=installed):
        arb = FusionArbiter()
    assert arb.gemma_model == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
    assert arb.sec_model == "huihui_ai/foundation-sec-abliterated:8b"
    assert arb.arbiter_model == "huihui_ai/glm-4.7-abliterated"


def test_model_adapter_panel_queries_all_three_specialists(monkeypatch):
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    installed = [
        "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
        "fenkohq/foundation-sec-8b:latest",
        "glm4:9b",
    ]
    queried = []

    def fake_query(self, model, system_instruction, user_prompt, schema_hint=None, num_predict=160):
        queried.append(model)
        return [{"rationale": f"probe from {model}", "raw_request": f"GET /{len(queried)} HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": False}]

    with patch.object(ModelFusionAdapter, "_fetch_available_tags", return_value=installed):
        adapter = ModelFusionAdapter(use_fusion=True)
        assert adapter.preferred_model == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
        with patch.object(ModelFusionAdapter, "_query_ollama", fake_query):
            res = adapter.generate_json("sys", "prompt")

    assert len(res) == 3
    assert queried == [
        "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
        "fenkohq/foundation-sec-8b:latest",
        "glm4:9b",
    ]


def test_codebase_wide_defaults_enable_abliterated_trio(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")

    # 1. Mantis constants and integrator
    assert DEFAULT_ABLITERATED_MODEL == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
    assert DEFAULT_SEC_MODEL == "fenkohq/foundation-sec-8b:latest"
    assert DEFAULT_ARBITER_MODEL == "glm4:9b"

    integrator = MantisIntegrator(reports_dir=str(tmp_path / "reports"))
    assert integrator.preferred_model == DEFAULT_ABLITERATED_MODEL
    assert integrator.sec_model == DEFAULT_SEC_MODEL

    # 2. CLI parser defaults
    swarm_args = rfc_hunt_swarm.build_swarm_parser().parse_args([])
    assert swarm_args.abliteration is True
    assert swarm_args.model == DEFAULT_ABLITERATED_MODEL

    start_args = start.build_parser().parse_args([])
    assert start_args.model == DEFAULT_ABLITERATED_MODEL
    assert start_args.cisco is True
    assert start_args.fusion is True

    # 3. ContinuousFlawHunter signature default
    sig = inspect.signature(ContinuousFlawHunter.__init__)
    assert sig.parameters["preferred_model"].default == DEFAULT_ABLITERATED_MODEL
    assert sig.parameters["use_fusion"].default is True

    # 4. MCP tool schemas
    server = TerminatorMCPServer(db_path=str(tmp_path / "mcp_defaults.db"))
    try:
        tools = {t["name"]: t for t in server._get_tool_definitions()}
        for tname in ("run_continuous_hunt", "generate_probes"):
            props = tools[tname]["inputSchema"]["properties"]
            assert props["model"]["default"] == DEFAULT_ABLITERATED_MODEL
            assert props["use_fusion"]["default"] is True
        assert tools["cascade_extrapolate"]["inputSchema"]["properties"]["model"]["default"] == DEFAULT_ABLITERATED_MODEL
    finally:
        server.db.close()

    # 5. main.py help check
    proc = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert proc.returncode == 0
    assert "Default ON" in proc.stdout
    assert "Gemma-4-12B-OBLITERATED" in proc.stdout
