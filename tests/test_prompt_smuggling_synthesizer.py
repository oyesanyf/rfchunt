"""
Unit tests for Desynchronized Prompt Injection Synthesizer (Module 19)
=====================================================================
Verifies:
1. Synthesis of CL.TE, TE.CL, and Chunk Extension prompt injection probes
2. Correct framing and delivery of injected system prompt payload to AI endpoint
3. Canary token generation and tracking
4. Zero UI report generation in reports/ folder
"""

import json
from pathlib import Path
from engine.prompt_smuggling_synthesizer import PromptSmugglingSynthesizer, SmuggledPromptProbe


def test_synthesizer_generates_all_framing_variants(tmp_path):
    reports_dir = tmp_path / "reports"
    synthesizer = PromptSmugglingSynthesizer(db=None, reports_dir=reports_dir)

    probes = synthesizer.synthesize_probes_for_endpoint(
        target_host="ai-proxy.corp.internal",
        target_port=443,
        ai_endpoint="/internal/chat",
        http_method="POST",
    )

    assert len(probes) == 3
    attack_classes = {p.attack_class for p in probes}
    assert "CL.TE_PROMPT_INJECTION" in attack_classes
    assert "TE.CL_PROMPT_INJECTION" in attack_classes
    assert "CHUNK_EXTENSION_OBLIQUE_PROMPT_INJECTION" in attack_classes

    for p in probes:
        assert p.canary_token.startswith(PromptSmugglingSynthesizer.CANARY_PREFIX)
        assert "/internal/chat" in p.raw_smuggled_stream
        assert "EMIT_VERIFICATION_TOKEN" in p.raw_smuggled_stream
        assert "\r\n" in p.raw_smuggled_stream

    # Verify report files in tmp_path/reports
    report_files = synthesizer.generate_reports("ai-proxy.corp.internal", probes)
    assert Path(report_files["json"]).exists()
    assert Path(report_files["summary"]).exists()

    report_json = json.loads(Path(report_files["json"]).read_text(encoding="utf-8"))
    assert report_json["total_probes"] == 3
