"""
Unit tests for OllamaLifecycleManager, zero-API-key local inference,
and deterministic RFC grammar fallback in ProbeGenerator.
"""

import os
from ollama_manager import OllamaLifecycleManager
from model_adapter import ModelFusionAdapter
from probe_generator import ProbeGenerator


def test_ollama_binary_detection():
    """Verifies OllamaLifecycleManager can locate or check for ollama binary without mutating registry."""
    bin_path = OllamaLifecycleManager.find_ollama_binary()
    assert bin_path is None or isinstance(bin_path, str)


def test_no_gemini_api_key_used_by_default(monkeypatch):
    """Ensures an invalid GEMINI_API_KEY in environment never triggers Gemini cloud client unless USE_GEMINI_CLOUD=1."""
    monkeypatch.setenv("GEMINI_API_KEY", "INVALID_DUMMY_KEY_12345")
    monkeypatch.delenv("USE_GEMINI_CLOUD", raising=False)
    adapter = ModelFusionAdapter(use_fusion=False)
    assert adapter.gemini_client is None


def test_deterministic_rfc_grammar_fallback():
    """Ensures ProbeGenerator always produces non-empty RFC-anchored HTTP/1.1 probes via _synthesize_rfc_grammar_probes."""
    gen = ProbeGenerator(use_fusion=False)
    probes = gen._synthesize_rfc_grammar_probes(
        "Any 2xx (Successful) response to a CONNECT request implies that the connection becomes a tunnel."
    )
    assert len(probes) >= 1
    for p in probes:
        assert "HTTP/1.1" in p["raw_request"]
        assert "target.local" in p["raw_request"]
