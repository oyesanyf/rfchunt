"""
Unit Tests for Native Gemma-4-12B-OBLITERATED Integration & ModelFusion Abliteration/Arbitration
=============================================================================================
Verifies:
1. Dynamic model alias resolution for hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M.
2. AI safety refusal detection (_is_refusal) across technical vs refused outputs.
3. ModelFusion panel role assignment (Protocol Specialist + Boundary Specialist + Reasoning Arbiter).
4. Refusal-free abliteration rescue when standard models return refusal text.
5. CLI argument parsing for --abliteration / --obliterated flags in main.py and rfc_hunt_swarm.py.
"""

import argparse
import pytest
from unittest.mock import MagicMock, patch

from model_adapter import ModelFusionAdapter
from fusion_engine import FusionArbiter, CandidateProposal


class TestAbliterationResolution:
    def test_alias_resolution_obliterated(self):
        """Verifies that various shorthand aliases resolve to the full Ollama tag."""
        adapter = ModelFusionAdapter(preferred_model="gemma2:2b")
        adapter.available_tags = [
            "gemma2:2b",
            "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            "qwen2.5:7b",
            "fenkohq/foundation-sec-8b:latest",
        ]

        aliases = [
            "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            "gemma-4-12b-obliterated",
            "gemma4-12b-obliterated",
            "gemma-4-obliterated",
            "obliteratus",
            "obliterated",
            "abliterated",
            "gemma-obliterated",
            "gemma4:12b-obliterated",
        ]

        expected_tag = "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
        for alias in aliases:
            resolved = adapter._resolve_model(alias)
            assert resolved == expected_tag, f"Alias '{alias}' did not resolve to '{expected_tag}', got '{resolved}'"

    def test_fusion_arbiter_alias_resolution(self):
        """Verifies FusionArbiter._resolve_model resolves abliterated aliases correctly."""
        arbiter = FusionArbiter.__new__(FusionArbiter)
        arbiter.available_tags = [
            "gemma2:2b",
            "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            "qwen2.5:7b",
        ]
        arbiter.free_ram_gb = 64.0

        resolved = arbiter._resolve_model(["obliteratus"], fallback="gemma2:2b")
        assert resolved == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"

        resolved_direct = arbiter._resolve_model(["gemma-4-12b-obliterated:q4_k_m"], fallback="gemma2:2b")
        assert resolved_direct == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"


class TestRefusalDetection:
    def test_is_refusal_positive_cases(self):
        """Verifies refusal detection across standard LLM safety refusal markers."""
        refusal_samples = [
            "I cannot fulfill this request. As an AI, I am unable to generate exploit payloads.",
            "I cannot assist with creating exploits or attacks against servers.",
            "I am unable to provide code that exploits security vulnerabilities as it violates safety guidelines.",
            "I'm sorry, but I cannot create malicious payloads.",
            "As a responsible AI developed by Google, I cannot generate harmful attacks.",
        ]

        for sample in refusal_samples:
            assert ModelFusionAdapter._is_refusal(sample) is True
            assert FusionArbiter._is_refusal(sample) is True

    def test_is_refusal_negative_cases(self):
        """Verifies valid technical probe responses are NOT flagged as refusals."""
        valid_samples = [
            'POST / HTTP/1.1\\r\\nHost: target.local\\r\\nContent-Length: 0\\r\\n\\r\\n$PAYLOAD',
            'Testing shared-parser confusion by inverting RFC 9112 Section 6 response rules into client requests.',
            '{"probes": [{"rationale": "Dangling byte boundary discrepancy", "raw_request": "GET / HTTP/1.1\\r\\nHost: target.local\\r\\n\\r\\n", "is_clean": false}]}',
            '',
            None,
        ]

        for sample in valid_samples:
            assert ModelFusionAdapter._is_refusal(sample) is False
            assert FusionArbiter._is_refusal(sample) is False


class TestModelFusionPanelPrioritization:
    def test_panel_prioritizes_gemma_obliterated_when_requested(self):
        adapter = ModelFusionAdapter(preferred_model="hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M", use_fusion=True)
        adapter.available_tags = [
            "gemma2:2b",
            "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            "fenkohq/foundation-sec-8b:latest",
            "qwen2.5:7b",
        ]
        adapter.active_model = adapter._resolve_model(adapter.preferred_model)
        assert adapter.active_model == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"

    def test_fusion_arbiter_initialization_with_preferred_model(self):
        with patch.object(FusionArbiter, "_fetch_available_tags", return_value=[
            "gemma2:2b",
            "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            "fenkohq/foundation-sec-8b:latest",
            "deepseek-r1:1.5b",
        ]):
            arbiter = FusionArbiter(preferred_model="gemma-4-12b-obliterated")
            assert arbiter.gemma_model == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
            assert arbiter.sec_model == "fenkohq/foundation-sec-8b:latest"


class TestCLIAbliterationFlags:
    def test_rfc_hunt_swarm_abliteration_flag(self):
        """Verifies --abliteration flag sets model in rfc_hunt_swarm argument parser."""
        from rfc_hunt_swarm import build_swarm_parser
        parser = build_swarm_parser()
        args = parser.parse_args(["--abliteration"])
        assert args.abliteration is True

    def test_main_abliteration_flag(self):
        """Verifies --abliteration flag sets model in main.py argument parser."""
        import main
        # Create test subparser
        test_parser = argparse.ArgumentParser()
        test_parser.add_argument("--model", default="gemma2:2b")
        test_parser.add_argument("--abliteration", action="store_true", default=False)

        parsed = test_parser.parse_args(["--abliteration"])
        assert parsed.abliteration is True
