"""Unit tests for ModelFusion upgrades:
- Memory-aware Ollama concurrency limits (1/1 on <=8 GB RAM, 2/2 medium, 3/3 high RAM/VRAM)
- Low-RAM Single-Model Collapse fast path (avoids 2-3x redundant CPU calls on single model)
- Arbitrary N-model specialist voting & Gate 3 QuorumConsensus
- Model-grouped batch scheduling (`run_fusion_batch`) to eliminate disk model-swap thrashing
- Hybrid local Ollama + `.env.local` cloud per-slot routing
- Resilient JSON repair, 1-shot Arbiter JSON retry, and configurable fallback timeout
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from engine.paid_model_provider import (
    PaidModelConfig,
    is_explicit_ollama_spec,
    load_paid_model_config,
    strip_ollama_prefix,
)
from fusion_engine import FusionArbiter, _repair_json_string
from ollama_manager import compute_ollama_concurrency_limits


def test_compute_ollama_concurrency_limits_scales_by_free_memory():
    assert compute_ollama_concurrency_limits(free_ram_gb=2.2, free_vram_mb=0.0) == (1, 1)
    assert compute_ollama_concurrency_limits(free_ram_gb=7.9, free_vram_mb=0.0) == (1, 1)
    assert compute_ollama_concurrency_limits(free_ram_gb=10.0, free_vram_mb=0.0) == (2, 2)
    assert compute_ollama_concurrency_limits(free_ram_gb=4.0, free_vram_mb=8192.0) == (2, 2)
    assert compute_ollama_concurrency_limits(free_ram_gb=24.0, free_vram_mb=0.0) == (3, 3)
    assert compute_ollama_concurrency_limits(free_ram_gb=8.0, free_vram_mb=16384.0) == (3, 3)


def test_single_model_collapse_fast_path_eliminates_redundant_calls():
    with (
        patch.object(FusionArbiter, "_fetch_available_tags", return_value=["qwen2.5:1.5b"]),
        patch.object(FusionArbiter, "_get_free_memory_gb", return_value=2.2),
        patch.object(FusionArbiter, "_get_free_vram_mb", return_value=0.0),
    ):
        arb = FusionArbiter(quiet=True, force_ollama=True)

    assert arb.gemma_model == "qwen2.5:1.5b"
    assert arb.sec_model == "qwen2.5:1.5b"
    assert arb.arbiter_model == "qwen2.5:1.5b"
    assert arb.max_concurrent_queries == 1

    calls = []

    def fake_query(model, prompt, system_prompt, num_predict=160):
        calls.append(model)
        return json.dumps({
            "rationale": "Single-pass combined boundary test",
            "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 0\r\n\r\n$PAYLOAD",
            "is_clean": False,
        })

    with patch.object(arb, "_query_model", side_effect=fake_query):
        res = arb.run_fusion_pipeline("A sender MUST NOT send Content-Length with Transfer-Encoding.")

    assert len(calls) == 1, f"Expected 1 collapsed call, got {len(calls)}: {calls}"
    assert res.consensus_type == "SingleModelCollapsed"
    assert res.metadata.get("unique_models") == 1
    assert res.metadata.get("redundant_calls_saved", 0) >= 2
    assert len(res.fused_probes) == 1


def test_n_model_quorum_voting_gate_3():
    installed = ["qwen2.5:1.5b", "deepseek-r1:1.5b", "gemma2:2b", "glm4:9b"]
    with (
        patch.object(FusionArbiter, "_fetch_available_tags", return_value=installed),
        patch.object(FusionArbiter, "_get_free_memory_gb", return_value=24.0),
        patch.object(FusionArbiter, "_get_free_vram_mb", return_value=0.0),
    ):
        arb = FusionArbiter(
            quiet=True,
            force_ollama=True,
            panel_models=["qwen2.5:1.5b", "deepseek-r1:1.5b", "gemma2:2b", "glm4:9b"],
            voting_quorum=0.6,
        )

    assert arb.specialist_models == ["qwen2.5:1.5b", "deepseek-r1:1.5b", "gemma2:2b"]
    assert arb.arbiter_model == "glm4:9b"

    shared_req = "POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n$PAYLOAD"
    alt_req = "GET /alt HTTP/1.1\r\nHost: target.local\r\n\r\n"
    queried = []

    def fake_query(model, prompt, system_prompt, num_predict=160):
        queried.append(model)
        req = shared_req if model in ("qwen2.5:1.5b", "gemma2:2b") else alt_req
        return json.dumps({"rationale": f"from {model}", "raw_request": req, "is_clean": False})

    with patch.object(arb, "_query_model", side_effect=fake_query):
        res = arb.run_fusion_pipeline("Chunked framing ambiguity")

    assert res.consensus_type == "QuorumConsensus"
    assert "glm4:9b" not in queried  # Arbiter bypassed because 2/3 quorum reached
    assert res.fused_probes[0]["vote_count"] == 2
    assert set(res.fused_probes[0]["corroborated_by_models"]) == {"qwen2.5:1.5b", "gemma2:2b"}


def test_run_fusion_batch_groups_by_model_to_avoid_swaps():
    installed = ["qwen2.5:1.5b", "deepseek-r1:1.5b", "gemma2:2b"]
    with (
        patch.object(FusionArbiter, "_fetch_available_tags", return_value=installed),
        patch.object(FusionArbiter, "_get_free_memory_gb", return_value=4.0),
    ):
        arb = FusionArbiter(
            quiet=True,
            force_ollama=True,
            panel_models=["qwen2.5:1.5b", "deepseek-r1:1.5b", "gemma2:2b"],
        )

    call_order = []

    def fake_query(model, prompt, system_prompt, num_predict=160):
        call_order.append(model)
        return json.dumps({
            "rationale": f"{model}",
            "raw_request": f"GET /{model.replace(':', '_')} HTTP/1.1\r\nHost: target.local\r\n\r\n",
            "is_clean": False,
        })

    with patch.object(arb, "_query_model", side_effect=fake_query):
        results = arb.run_fusion_batch(["frag A", "frag B", "frag C"])

    assert len(results) == 3
    # Model-outer grouping: all 3 calls for specialist 1, then all 3 for specialist 2, then all 3 for arbiter
    assert call_order[:3] == ["qwen2.5:1.5b", "qwen2.5:1.5b", "qwen2.5:1.5b"]
    assert call_order[3:6] == ["deepseek-r1:1.5b", "deepseek-r1:1.5b", "deepseek-r1:1.5b"]
    assert call_order[6:9] == ["gemma2:2b", "gemma2:2b", "gemma2:2b"]


def test_hybrid_local_ollama_plus_cloud_panel_routing(tmp_path: Path):
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "\n".join([
            "RFCHUNT_HYBRID_PANEL=1",
            "ANTHROPIC_API_KEY=sk-ant-test-1234567890abcdef",
            "RFCHUNT_PAID_MODELS=ollama/qwen2.5:1.5b,anthropic/claude-sonnet-4-20250514",
            "RFCHUNT_PAID_PRIMARY_MODEL=ollama/qwen2.5:1.5b",
            "RFCHUNT_PAID_ARBITER_MODEL=anthropic/claude-sonnet-4-20250514",
        ]),
        encoding="utf-8",
    )
    cfg = load_paid_model_config(env_local_path=env_file)
    assert cfg.enabled is True
    assert cfg.hybrid_mode is True
    assert cfg.ollama_bypassed is False
    assert cfg.is_local_ollama_slot("ollama/qwen2.5:1.5b") is True
    assert cfg.is_local_ollama_slot("anthropic/claude-sonnet-4-20250514") is False
    assert is_explicit_ollama_spec("ollama/qwen2.5:1.5b") is True
    assert strip_ollama_prefix("ollama/qwen2.5:1.5b") == "qwen2.5:1.5b"

    with patch.object(FusionArbiter, "_fetch_available_tags", return_value=["qwen2.5:1.5b"]):
        arb = FusionArbiter(quiet=True, env_local_path=str(env_file))
    assert arb.backend_mode == "hybrid"
    assert arb.using_ollama is True
    assert arb._is_cloud_slot("ollama/qwen2.5:1.5b") is False
    assert arb._is_cloud_slot("anthropic/claude-sonnet-4-20250514") is True


def test_resilient_json_repair_and_configurable_fallback_timeout():
    malformed_trailing_and_newlines = (
        '```json\n'
        '{\n'
        '  "rationale": "Literal newline inside raw_request",\n'
        '  "raw_request": "POST / HTTP/1.1\nHost: target.local\n\n$PAYLOAD",\n'
        '  "is_clean": false,\n'
        '}\n'
        '```'
    )
    arb = FusionArbiter.__new__(FusionArbiter)
    parsed = arb._parse_json(malformed_trailing_and_newlines)
    assert len(parsed) == 1
    assert "POST / HTTP/1.1" in parsed[0]["raw_request"]

    single_quoted = "{'rationale': 'python dict style', 'raw_request': 'GET / HTTP/1.1\\r\\nHost: target.local\\r\\n\\r\\n', 'is_clean': False}"
    parsed_sq = arb._parse_json(single_quoted)
    assert len(parsed_sq) == 1
    assert parsed_sq[0]["rationale"] == "python dict style"

    raw_prose_http = "Here is a test request:\nPOST /admin HTTP/1.1\r\nHost: target.local\r\nContent-Length: 0\r\n\r\n"
    parsed_http = arb._parse_json(raw_prose_http)
    assert len(parsed_http) == 1
    assert parsed_http[0]["raw_request"].startswith("POST /admin HTTP/1.1")

    with patch.object(FusionArbiter, "_fetch_available_tags", return_value=["qwen2.5:1.5b"]):
        arb_to = FusionArbiter(quiet=True, force_ollama=True, fallback_timeout=95.0)
    assert arb_to.fallback_timeout == 95.0
