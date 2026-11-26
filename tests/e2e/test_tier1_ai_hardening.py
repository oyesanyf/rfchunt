"""
Tier 1 E2E Tests: AI-Powered Scanner Self-Hardening (Features #1-#11).

Covers 5 distinct opaque-box test cases per feature F1-F10 and 6 for F11 (56 total tests):
- F1: Centralized XML nonce fencer (`sanitize_for_llm_prompt`, `UntrustedOutputBoundary`)
- F2: `fusion_engine.py` prompt fencing (6 prompt sites)
- F3: `probe_generator.py` & `cascade.py` prompt fencing (3 sites)
- F4: `engine/mantis_integrator.py` prompt fencing (5 sites)
- F5: `engine/dual_graph_engine.py` & `engine/live_executors.py` prompt fencing
- F6: `engine/code_verification_repair.py` prompt fencing (2+ sites)
- F7: `engine/fuzz_bridge.py` & `engine/call_graph_slicer.py` prompt fencing
- F8: Ollama `/api/chat` structured role isolation (5 POST sites + `model_adapter.py`)
- F9: `surface_mining` workspace root confinement
- F10: `file_path` workspace root confinement
- F11: Deterministic override immunity
"""

from __future__ import annotations

import dataclasses
import inspect
import json
from pathlib import Path
import re
from typing import Any, Dict, List

import pytest

from cascade import DiscoveryCascade
from database import Database
from engine.approval_gate import ApprovalGate
from engine.call_graph_slicer import CallGraphSlicer, SliceStep, TaintSlice
from engine.code_verification_repair import (
    _build_native_verify_prompt,
    _invoke_ollama_json_judge,
    auto_repair_generated_code,
    request_ollama_code_patch,
    run_deterministic_code_verification,
    verify_python_code_native,
)
from engine.dual_graph_engine import (
    ArtexPlanner,
    ArtexWorker,
    AssetGraph,
    ExplorationGraph,
    RunBudgetLedger,
    TrafficCaptureSession,
    UntrustedOutputBoundary,
    WorkerTraceStore,
)
from engine.execution_policy import (
    ActionType,
    ExecutionPolicy,
    ScannerTask,
    StructuredIntentProposal,
    sanitize_for_llm_prompt,
)
from engine.fuzz_bridge import DetectedTarget, LLMFuzzBridge
from engine.live_executors import LiveWorkerExecutorRegistry
from engine.mantis_integrator import (
    MantisHypothesis,
    MantisHypothesisGenerator,
    MantisPatchEngine,
    MantisReproducer,
    MantisThreatModeler,
    MantisZeroDaySynthesizer,
    run_unified_all_scans,
)
from engine.rea_integrator import ReaIntegrator
from engine.session_loader import AuthProfile
from engine.swarm_dispatcher import ModelRoutingDecision, TieredModelRouter
from fusion_engine import FusionArbiter
from mcp_server import TerminatorMCPServer
from model_adapter import ModelFusionAdapter
from probe_generator import ProbeGenerator

pytestmark = pytest.mark.tier1

_FENCE_RE = re.compile(
    r'<untrusted_data nonce="([a-fA-F0-9_-]{12,})">\n(.*?)\n</untrusted_data>',
    re.DOTALL,
)

_CLEAN_VERIFY_PY = '''"""Clean deterministic Python module for E2E verification."""

from typing import List


def detect_anomaly(payload: str) -> List[str]:
    """Detects dual framing headers deterministically."""
    if not payload:
        return []
    lowered = payload.lower()
    hits: List[str] = []
    if "transfer-encoding:" in lowered and "content-length:" in lowered:
        hits.append("cl_te_conflict")
    return hits
'''


def _assert_fenced_blocks(text: str, *, min_blocks: int = 1) -> List[str]:
    matches = list(_FENCE_RE.finditer(text or ""))
    assert len(matches) >= min_blocks, (
        f"Expected at least {min_blocks} <untrusted_data nonce=...>...</untrusted_data> block(s) in:\n{text}"
    )
    assert "untrusted_remote_response_data" not in text
    assert "<<<ARTEX_UNTRUSTED_DATA" not in text
    assert "<<<RFCHUNT_FUZZ_CONTEXT>>>" not in text
    assert text.count("</untrusted_data>") == len(matches), (
        f"Mismatched closing tags ({text.count('</untrusted_data>')} != {len(matches)}) in:\n{text}"
    )
    return [m.group(1) for m in matches]


def _extract_roles(req_entry: Dict[str, Any]) -> Dict[str, str]:
    body = req_entry.get("json") or {}
    msgs = body.get("messages") or []
    roles: Dict[str, str] = {}
    for m in msgs:
        role = str(m.get("role") or "")
        roles[role] = roles.get(role, "") + str(m.get("content") or "")
    return roles


def _make_multiturn_chat_handler(
    tool_call_payload: Dict[str, Any],
    finish_payload: Dict[str, Any],
):
    def _handler(path: str, parsed_json: Dict[str, Any], headers: Dict[str, str]):
        model_name = str(parsed_json.get("model") or "qwen2.5:14b")
        msgs = parsed_json.get("messages") or []
        user_txt = "\n".join(str(m.get("content") or "") for m in msgs if m.get("role") == "user")
        if "Tool Observations (untrusted data):" in user_txt:
            chosen = finish_payload
        elif "[source: specialist_proposals]" in user_txt:
            chosen = finish_payload if '"action": "finish"' in user_txt else tool_call_payload
        else:
            chosen = tool_call_payload
        return 200, {
            "model": model_name,
            "message": {"role": "assistant", "content": json.dumps(chosen)},
            "done": True,
        }

    return _handler


# =============================================================================
# F1: Centralized XML Nonce Fencer (5 tests)
# =============================================================================


def test_f1_sanitize_emits_canonical_xml_nonce_tag() -> None:
    out = sanitize_for_llm_prompt("HTTP/1.1 200 OK\r\nX-Test: alpha", max_chars=500)
    nonces = _assert_fenced_blocks(out, min_blocks=1)
    assert len(nonces[0]) >= 16
    assert out.startswith(f'<untrusted_data nonce="{nonces[0]}">\n')
    assert out.endswith("\n</untrusted_data>")


def test_f1_sanitize_distinct_per_call_csprng_nonces() -> None:
    nonces = set()
    for _ in range(5):
        out = sanitize_for_llm_prompt("repeated payload", max_chars=200)
        found = _assert_fenced_blocks(out, min_blocks=1)
        nonces.add(found[0])
    assert len(nonces) == 5, "Every sanitize_for_llm_prompt call must emit a fresh CSPRNG nonce"


def test_f1_sanitize_preserves_legitimate_content_and_source_label() -> None:
    payload = "GET /api/v1/items?limit=10 HTTP/1.1\nHost: target.local\nX-Custom: valid-value"
    out = sanitize_for_llm_prompt(payload, max_chars=1000, source="http_probe")
    _assert_fenced_blocks(out, min_blocks=1)
    assert "[source: http_probe]\n" in out
    assert "GET /api/v1/items?limit=10 HTTP/1.1" in out
    assert "X-Custom: valid-value" in out


def test_f1_untrusted_output_boundary_frame_canonical_format_and_nonces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARTEX_UNTRUSTED_BOUNDARY", raising=False)
    boundary = UntrustedOutputBoundary()
    f1 = boundary.frame("first tool observation", source_label="tool_http")
    n1 = boundary.nonce
    f2 = boundary.frame("second tool observation", source_label="tool_http")
    n2 = boundary.nonce

    assert n1 != n2
    assert f'<untrusted_data nonce="{n1}">' in f1
    assert f'<untrusted_data nonce="{n2}">' in f2
    assert "[source: tool_http]\n" in f1
    assert "first tool observation" in f1
    _assert_fenced_blocks(f1, min_blocks=1)
    _assert_fenced_blocks(f2, min_blocks=1)
    assert "<untrusted_data" in boundary.system_note()


def test_f1_sanitize_bytes_input_and_explicit_nonce() -> None:
    out = sanitize_for_llm_prompt(
        b"RAW_BYTES_MARKER\r\nHeader: ok",
        max_chars=200,
        nonce="deadbeef0123456789abcdef",
        source="wire_bytes",
    )
    assert out.startswith('<untrusted_data nonce="deadbeef0123456789abcdef">\n')
    assert "[source: wire_bytes]\n" in out
    assert "RAW_BYTES_MARKER" in out
    assert out.endswith("\n</untrusted_data>")


# =============================================================================
# F2: `fusion_engine.py` Prompt Fencing (5 tests)
# =============================================================================


def test_f2_fusion_pipeline_gemma_and_sec_prompts_fenced(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "rationale": "Shared parser rule inversion",
            "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 0\r\n\r\n$PAYLOAD",
            "is_clean": False,
        }
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        res = arbiter.run_fusion_pipeline(
            "RFC9112_CLUE_MARKER: 304 responses MUST NOT contain a message body.",
            hints=["HINT_MARKER_CLTE"],
            facts=["FACT_MARKER_KEEPALIVE"],
        )
    finally:
        arbiter.close()

    assert res.fused_probes
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) >= 2
    for req in reqs:
        roles = _extract_roles(req)
        user_txt = roles.get("user", "")
        assert "RFC9112_CLUE_MARKER" in user_txt
        assert "HINT_MARKER_CLTE" in user_txt
        assert "FACT_MARKER_KEEPALIVE" in user_txt
        _assert_fenced_blocks(user_txt, min_blocks=3)


def test_f2_fusion_pipeline_gate4_arbiter_fences_specialist_proposals(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.queue_responses(
        [
            {
                "rationale": "Gemma proposal A",
                "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n$PAYLOAD",
                "is_clean": False,
            },
            {
                "rationale": "Sec proposal B",
                "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 0\r\n\r\n$PAYLOAD",
                "is_clean": True,
            },
            {
                "rationale": "Synthesized consensus probe",
                "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n$PAYLOAD",
                "is_clean": False,
            },
        ]
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        res = arbiter.run_fusion_pipeline("RFC_GATE4_MARKER: chunked framing")
    finally:
        arbiter.close()

    assert res.consensus_type in ("ArbiterSynthesized", "AbliteratedConsensus")
    reqs = loopback_ollama.get_requests("/api/chat")
    gate4_reqs = [r for r in reqs if "Candidate Proposals Submitted to Fusion Arbiter" in _extract_roles(r).get("user", "")]
    assert gate4_reqs, "Expected Gate-4 Arbiter synthesis call"
    user_txt = _extract_roles(gate4_reqs[0])["user"]
    nonces = _assert_fenced_blocks(user_txt, min_blocks=2)
    assert len(set(nonces)) >= 2
    assert "[source: specialist_candidates]" in user_txt


def test_f2_fusion_pipeline_abliterated_rescue_fences_rfc_and_hints(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_models(["gemma2:9b", "huihui_ai/foundation-sec-abliterated:8b", "glm4:9b"])
    loopback_ollama.queue_responses(
        [
            "I cannot assist with creating exploits.",
            "I cannot assist with creating exploits.",
            {
                "rationale": "Abliterated rescue probe",
                "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 0\r\n\r\n$PAYLOAD",
                "is_clean": False,
            },
        ]
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        res = arbiter.run_fusion_pipeline(
            "RFC_RESCUE_MARKER: trailer section",
            hints=["HINT_RESCUE_TRAILER"],
        )
    finally:
        arbiter.close()

    assert res.fused_probes
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) >= 3
    rescue_user = _extract_roles(reqs[2])["user"]
    assert "RFC_RESCUE_MARKER" in rescue_user
    assert "HINT_RESCUE_TRAILER" in rescue_user
    _assert_fenced_blocks(rescue_user, min_blocks=2)


def test_f2_explain_vulnerability_concept_fences_all_evidence_fields(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "concept_name": "Shared-Parser Confusion",
            "architectural_explanation": "Applies 304 rules to requests.",
            "rfc_clue_connection": "RFC 9110 304",
            "generalization": "Proxy chains",
            "validation_steps": ["Send pipelined request"],
        }
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        explanation = arbiter.explain_vulnerability_concept(
            rfc_fragment="EXPLAIN_RFC_MARKER",
            probe_request="POST /EXPLAIN_REQ_MARKER HTTP/1.1\r\nHost: target.local\r\n\r\n",
            baseline_resp="HTTP/1.1 200 OK\r\n\r\nok",
            probe_resp="HTTP/1.1 304 Not Modified\r\n\r\nEXPLAIN_PROBE_RESP",
            retest_resp="HTTP/1.1 400 Bad Request\r\n\r\nEXPLAIN_RETEST_RESP",
            anomalies=[{"type": "DESYNC", "description": "EXPLAIN_ANOM_MARKER"}],
            desync_class="CL.TE",
            details="EXPLAIN_DETAILS_MARKER",
        )
    finally:
        arbiter.close()

    assert explanation["concept_name"] == "Shared-Parser Confusion"
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) >= 1
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=9)
    for marker in (
        "EXPLAIN_RFC_MARKER",
        "EXPLAIN_REQ_MARKER",
        "EXPLAIN_DETAILS_MARKER",
        "EXPLAIN_ANOM_MARKER",
        "EXPLAIN_PROBE_RESP",
        "EXPLAIN_RETEST_RESP",
    ):
        assert marker in user_txt


def test_f2_arbitrate_structured_json_fences_specialist_proposals_in_arbiter(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.queue_responses(
        [
            {"summary": "SPEC1_SUMMARY", "items": ["a"]},
            {"summary": "SPEC2_SUMMARY", "items": ["b"]},
            {"summary": "MERGED_SUMMARY", "items": ["a", "b"]},
        ]
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        safe_user = sanitize_for_llm_prompt("UNTRUSTED_TARGET_DATA", max_chars=500, source="target")
        out = arbiter.arbitrate_structured_json(
            task_name="E2E Arbitration",
            system_prompt="Return strict JSON.",
            user_prompt=f"Analyze:\n{safe_user}",
            default_payload={"summary": "fallback"},
        )
    finally:
        arbiter.close()

    assert out["status"] == "fused"
    reqs = loopback_ollama.get_requests("/api/chat")
    merge_reqs = [r for r in reqs if "[source: specialist_proposals]" in _extract_roles(r).get("user", "")]
    assert merge_reqs
    merge_user = _extract_roles(merge_reqs[0])["user"]
    _assert_fenced_blocks(merge_user, min_blocks=1)
    assert "SPEC1_SUMMARY" in merge_user and "SPEC2_SUMMARY" in merge_user


# =============================================================================
# F3: `probe_generator.py` & `cascade.py` Prompt Fencing (5 tests)
# =============================================================================


def test_f3_probe_generator_non_fusion_fences_rfc_hints_facts(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "probes": [
                {
                    "rationale": "Trailer confusion",
                    "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD",
                    "is_clean": False,
                }
            ]
        }
    )
    pg = ProbeGenerator(preferred_model="qwen2.5:14b", use_fusion=False)
    probes = pg.generate_candidate_probes(
        "PG_RFC_MARKER: Trailer headers follow chunked body.",
        hints=["PG_HINT_MARKER"],
        facts=["PG_FACT_MARKER"],
    )
    assert probes
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) >= 1
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=3)
    assert "PG_RFC_MARKER" in user_txt
    assert "PG_HINT_MARKER" in user_txt
    assert "PG_FACT_MARKER" in user_txt


def test_f3_probe_generator_fusion_mode_fences_rfc_fragment(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "rationale": "Fusion probe",
            "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 0\r\n\r\n$PAYLOAD",
            "is_clean": False,
        }
    )
    pg = ProbeGenerator(preferred_model="gemma2:9b", use_fusion=True)
    probes = pg.generate_candidate_probes("PG_FUSION_RFC_MARKER: CONNECT 200")
    assert probes
    reqs = loopback_ollama.get_requests("/api/chat")
    assert reqs
    for req in reqs:
        user_txt = _extract_roles(req)["user"]
        _assert_fenced_blocks(user_txt, min_blocks=1)
        assert "PG_FUSION_RFC_MARKER" in user_txt


def test_f3_probe_generator_grammar_fallback_when_ollama_empty(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content("not valid json")
    pg = ProbeGenerator(preferred_model="qwen2.5:14b", use_fusion=False)
    probes = pg.generate_candidate_probes("Transfer-Encoding: chunked trailer boundary")
    assert len(probes) >= 1
    assert probes[0]["source_type"] == "grammar"
    assert "Transfer-Encoding: chunked" in probes[0]["raw_request"]


def test_f3_cascade_step1_fences_finding_fields(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.queue_responses(
        [
            {
                "category": "shared_parser_confusion",
                "hypothesis": "Step 1 clean hypothesis",
                "rationale": "Step 1 clean hypothesis",
            },
            {
                "probes": [
                    {
                        "rationale": "Radical probe",
                        "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\n\r\n",
                        "is_clean": False,
                    }
                ]
            },
        ]
    )
    cascade = DiscoveryCascade(preferred_model="qwen2.5:14b", use_fusion=False)
    out = cascade.cascade_from_finding(
        {
            "details": "CASCADE_DETAILS_MARKER",
            "rationale": "CASCADE_RATIONALE_MARKER",
            "rfc_fragment": "CASCADE_RFC_MARKER",
            "raw_evidence": "CASCADE_EVIDENCE_MARKER",
        }
    )
    assert out is not None
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) >= 2
    step1_user = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(step1_user, min_blocks=4)
    for m in (
        "CASCADE_DETAILS_MARKER",
        "CASCADE_RATIONALE_MARKER",
        "CASCADE_RFC_MARKER",
        "CASCADE_EVIDENCE_MARKER",
    ):
        assert m in step1_user
    step2_user = _extract_roles(reqs[1])["user"]
    assert "Step 1 clean hypothesis" in step2_user


def test_f3_cascade_step2_fences_step1_hypothesis_text(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.queue_responses(
        [
            {
                "category": "shared_parser_confusion",
                "hypothesis": "STEP1_HYPOTHESIS_MARKER",
                "rationale": "STEP1_HYPOTHESIS_MARKER",
            },
            {
                "probes": [
                    {
                        "rationale": "Step 2 probe",
                        "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\n\r\n",
                        "is_clean": False,
                    }
                ]
            },
        ]
    )
    cascade = DiscoveryCascade(preferred_model="qwen2.5:14b", use_fusion=False)
    out = cascade.cascade_from_finding(
        {
            "details": "d1",
            "rationale": "r1",
            "rfc_fragment": "rfc1",
            "raw_evidence": "ev1",
        }
    )
    assert out is not None
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) >= 2
    step2_user = _extract_roles(reqs[1])["user"]
    _assert_fenced_blocks(step2_user, min_blocks=5)
    assert "[source: step1_hypothesis]\n" in step2_user
    assert "STEP1_HYPOTHESIS_MARKER" in step2_user


# =============================================================================
# F4: `engine/mantis_integrator.py` Prompt Fencing (5 tests)
# =============================================================================


def test_f4_mantis_threat_modeler_fences_repo_telemetry(
    loopback_ollama, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "summary": "Threat model generated",
            "threat_actors": ["Remote Attacker"],
        }
    )
    f = e2e_workspace.write_repo_file(
        "app_surface.py",
        "def run_cmd(user_in):\n    return eval(user_in)\n",
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        tm = MantisThreatModeler(fusion_arbiter=arbiter).build_threat_model(
            str(e2e_workspace.repo), [str(f)]
        )
    finally:
        arbiter.close()

    assert tm.target_repo == str(e2e_workspace.repo.resolve())
    reqs = loopback_ollama.get_requests("/api/chat")
    assert reqs
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=1)
    assert "[source: mantis_threat_model]" in user_txt
    assert "app_surface.py" in user_txt


def test_f4_mantis_hypothesis_generator_fences_hypotheses_sample(
    loopback_ollama, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content([{"id": "HYP-1", "priority": "HIGH"}])
    f = e2e_workspace.write_repo_file(
        "eval_sink.py",
        "def handle(x):\n    return eval(x)\n",
    )
    tm = MantisThreatModeler().build_threat_model(str(e2e_workspace.repo), [str(f)])
    adapter = ModelFusionAdapter(
        preferred_model="qwen2.5:14b",
        ollama_endpoint=loopback_ollama.url,
        use_fusion=False,
        force_ollama=True,
    )
    try:
        hyps = MantisHypothesisGenerator(model_adapter=adapter).generate_hypotheses(
            [str(f)], tm, depth=100
        )
    finally:
        adapter.close()

    assert any(h.rule_id == "MANTIS-EVAL-002" for h in hyps)
    reqs = loopback_ollama.get_requests("/api/chat")
    assert reqs
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=1)
    assert "[source: mantis_hypotheses]" in user_txt
    assert "eval_sink.py" in user_txt


def test_f4_mantis_zeroday_synthesizer_fences_context(
    loopback_ollama, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "hypotheses": [
                {
                    "rule_id": "MANTIS-0DAY-TEST",
                    "title": "Synthesized multi-vector flaw",
                    "cwe": "CWE-94",
                    "category": "Injection",
                    "file_path": "zeroday_target.py",
                    "line_number": 2,
                    "function_name": "run",
                    "sink": "eval",
                    "source_hint": "user_input",
                    "code_snippet": "eval(x)",
                    "raw_severity": "HIGH",
                    "confidence": 0.9,
                    "description": "Test",
                    "remediation": "Fix",
                }
            ]
        }
    )
    f = e2e_workspace.write_repo_file("zeroday_target.py", "def run(x):\n    return eval(x)\n")
    tm = MantisThreatModeler().build_threat_model(str(e2e_workspace.repo), [str(f)])
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        hyps = MantisZeroDaySynthesizer(fusion_arbiter=arbiter).synthesize_hypotheses(tm, [], {})
    finally:
        arbiter.close()

    assert hyps
    reqs = loopback_ollama.get_requests("/api/chat")
    assert reqs
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=1)
    assert "[source: mantis_zeroday_context]" in user_txt
    assert "zeroday_target.py" in user_txt


def test_f4_mantis_patch_engine_fences_patch_diff(
    loopback_ollama, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content({"verified": True, "notes": "Clean patch"})
    f = e2e_workspace.write_repo_file(
        "patchable.py",
        "import ast\n\ndef parse_user(raw):\n    return eval(raw)\n",
    )
    hyp = MantisHypothesis(
        hypothesis_id="HYP-PATCH-1",
        rule_id="MANTIS-EVAL-002",
        title="eval sink",
        cwe="CWE-95",
        category="Code Injection",
        file_path=str(f),
        line_number=4,
        function_name="parse_user",
        sink="eval",
        source_hint="raw",
        code_snippet="return eval(raw)",
        raw_severity="CRITICAL",
        confidence=0.95,
        description="eval",
        remediation="ast.literal_eval",
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        res = MantisPatchEngine(fusion_arbiter=arbiter).generate_and_verify_patch(
            hyp, MantisReproducer()
        )
    finally:
        arbiter.close()

    assert res.patch_generated is True
    assert res.patch_verified is True
    reqs = loopback_ollama.get_requests("/api/chat")
    assert reqs
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=1)
    assert "[source: mantis_patch_diff]" in user_txt


def test_f4_run_unified_all_scans_fences_final_summary_telemetry(
    loopback_ollama, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content({"executive_summary": "Audit completed cleanly."})
    e2e_workspace.write_repo_file(
        "service.py",
        "def run_it(cmd):\n    return eval(cmd)\n",
    )
    db = Database(db_path=str(e2e_workspace.db_path))
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        result = run_unified_all_scans(
            repo=str(e2e_workspace.repo),
            depth=20,
            mantis_mode="fast",
            db=db,
            reports_dir=str(e2e_workspace.output_dir),
            arbiter=arbiter,
            artex_rounds=0,
            enable_external_scanners=False,
            enable_rea=False,
            enable_h2_desync=False,
            enable_verification_inversion=False,
            enable_arxiv_detect=False,
            enable_last30days_skills=False,
            enable_preflight=False,
            quiet=True,
        )
    finally:
        arbiter.close()
        db.close()

    assert (
        result["total_aggregated_findings"] >= 0
        and "primary_findings_count" in result
        and "executive_summary" in result
    )
    reqs = loopback_ollama.get_requests("/api/chat")
    unified_reqs = [
        r for r in reqs if "[source: unified_scan_summary]" in _extract_roles(r).get("user", "")
    ]
    assert unified_reqs, "Expected run_unified_all_scans final summary call to fence unified_scan_summary"
    _assert_fenced_blocks(_extract_roles(unified_reqs[0])["user"], min_blocks=1)


# =============================================================================
# F5: `engine/dual_graph_engine.py` & `engine/live_executors.py` Fencing (5 tests)
# =============================================================================


def test_f5_untrusted_output_boundary_frame_replaces_legacy_artex_marker() -> None:
    boundary = UntrustedOutputBoundary(enabled=True)
    framed = boundary.frame("HTTP/1.1 200 OK\r\nServer: test", source_label="live_http")
    _assert_fenced_blocks(framed, min_blocks=1)
    assert "<<<ARTEX_UNTRUSTED_DATA" not in framed
    assert "<<<END_ARTEX_UNTRUSTED_DATA>>>" not in framed


def test_f5_artex_planner_plan_llm_intents_fences_dual_graph_snapshot(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    loopback_ollama.set_default_content(
        {
            "intents": [
                {
                    "title": "Test admin endpoint",
                    "attack_type": "AUTH_BOUNDARY",
                    "target_route": "/internal/admin",
                    "method": "GET",
                    "source_finding_ids": ["PRIM-1"],
                    "chain_steps": [{"step": 1, "capability": "AUTH_BOUNDARY", "desc": "Check /internal/admin"}],
                }
            ]
        }
    )
    ag = AssetGraph()
    ep = ag.add_asset("ep-f5-planner", "ENDPOINT", "/internal/admin", attributes={"host": "127.0.0.1", "route": "/internal/admin"})
    eg = ExplorationGraph(task_id="e2e-f5-planner")
    eg.add_intent("PRIM-1", "FINDING_PRIMITIVE", "Admin route", anchored_asset_id=ep.node_id)
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        planner = ArtexPlanner(asset_graph=ag, exploration_graph=eg, arbiter=arbiter)
        created = planner.plan_next_round(round_num=1)
    finally:
        arbiter.close()

    assert created
    reqs = loopback_ollama.get_requests("/api/chat")
    assert reqs
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=1)
    assert "[source: dual_graph_snapshot]" in user_txt


def test_f5_live_executors_multiturn_fences_candidate_and_reused_traces(
    loopback_ollama, loopback_target_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {"action": "finish", "confirmed": False, "evidence": "No issue"}
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    registry = LiveWorkerExecutorRegistry(
        host="127.0.0.1",
        port=loopback_target_app.port,
        authorized=True,
        approval_gate=ApprovalGate(mode="policy"),
        arbiter=arbiter,
    )
    try:
        ok, _, _, meta = registry.execute_candidate_multiturn(
            {
                "attack_type": "AI_INJECTION",
                "target_route": "/api/chat",
                "reused_worker_traces": [{"summary": "REUSED_TRACE_MARKER", "route": "/api/chat"}],
            },
            max_turns=1,
        )
    finally:
        arbiter.close()

    assert ok is False
    assert meta["turns_executed"] == 1
    reqs = loopback_ollama.get_requests("/api/chat")
    assert reqs
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=2)
    assert "REUSED_TRACE_MARKER" in user_txt


def test_f5_live_executors_multiturn_fences_tool_observations_across_turns(
    loopback_ollama, loopback_target_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_handler(
        _make_multiturn_chat_handler(
            {
                "action": "tool_call",
                "tool": "safe_http_probe",
                "args": {"method": "POST", "route": "/api/chat", "body": "RFCHUNT_CANARY_PROBE"},
                "hypothesis": "Check canary reflection",
            },
            {
                "action": "finish",
                "confirmed": True,
                "evidence": "Canary reflected",
            },
        )
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    registry = LiveWorkerExecutorRegistry(
        host="127.0.0.1",
        port=loopback_target_app.port,
        authorized=True,
        approval_gate=ApprovalGate(mode="policy"),
        arbiter=arbiter,
    )
    try:
        ok, evidence, _, meta = registry.execute_candidate_multiturn(
            {"attack_type": "AI_INJECTION", "target_route": "/api/chat", "has_ai_sink": True},
            max_turns=3,
        )
    finally:
        arbiter.close()

    assert ok is True
    assert meta["turns_executed"] == 2
    reqs = loopback_ollama.get_requests("/api/chat")
    turn2_reqs = [
        r for r in reqs if "[source: tool_safe_http_probe]" in _extract_roles(r).get("user", "")
    ]
    assert turn2_reqs, f"Expected Turn-2 /api/chat request with fenced tool observation; got {len(reqs)} requests"
    turn2_user = _extract_roles(turn2_reqs[0])["user"]
    _assert_fenced_blocks(turn2_user, min_blocks=2)
    assert "[source: tool_safe_http_probe]" in turn2_user
    assert evidence


def test_f5_artex_worker_execute_candidate_frames_trace_observation(
    loopback_target_app,
) -> None:
    ag = AssetGraph()
    ep = ag.add_asset("ep-f5-worker", "ENDPOINT", "/internal/admin", attributes={"host": "127.0.0.1", "route": "/internal/admin"})
    eg = ExplorationGraph(task_id="e2e-f5-worker")
    cand = eg.add_intent(
        "CAND-F5-1",
        "ATTACK_CANDIDATE",
        "Check admin boundary",
        anchored_asset_id=ep.node_id,
        attributes={
            "attack_type": "AUTH_BOUNDARY",
            "target_host": "127.0.0.1",
            "target_route": "/internal/admin",
            "wire_primitive_id": "PRIM-1",
            "raw_probe": "GET /internal/admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        },
    )
    ts = WorkerTraceStore(task_id="e2e-f5-worker")
    worker = ArtexWorker(exploration_graph=eg, trace_store=ts, asset_graph=ag)
    worker.execute_candidate(cand, executor_fn=lambda attrs: (True, "EVIDENCE_BOUNDARY_MARKER", "GET /internal/admin", {}))
    traces = ts.list_worker_traces()
    assert traces
    _assert_fenced_blocks(traces[0]["raw_observation"], min_blocks=1)
    assert "EVIDENCE_BOUNDARY_MARKER" in traces[0]["raw_observation"]


# =============================================================================
# F6: `engine/code_verification_repair.py` Prompt Fencing (5 tests)
# =============================================================================


def test_f6_build_native_verify_prompt_fences_target_and_source() -> None:
    det = run_deterministic_code_verification(_CLEAN_VERIFY_PY, arxiv_id="2601.00001")
    prompt = _build_native_verify_prompt(
        "2601.00001",
        "VERIFY_TITLE_MARKER",
        _CLEAN_VERIFY_PY,
        det,
    )
    nonces = _assert_fenced_blocks(prompt, min_blocks=2)
    assert len(set(nonces)) == 2
    assert "[source: paper_metadata]" in prompt
    assert "[source: python_source_code]" in prompt
    assert "VERIFY_TITLE_MARKER" in prompt
    assert "detect_anomaly" in prompt


def test_f6_verify_python_code_native_sends_fenced_prompt_to_ollama(
    loopback_ollama,
) -> None:
    loopback_ollama.set_default_content(
        {
            "verdict": "PASS",
            "paper_fidelity_score": 95,
            "correctness_score": 95,
            "security_score": 95,
            "summary": "Clean module",
            "findings": [],
        }
    )
    res = verify_python_code_native(
        _CLEAN_VERIFY_PY,
        arxiv_id="2601.00002",
        title="NATIVE_VERIFY_MARKER",
        ollama_endpoint=loopback_ollama.url,
        enable_llm=True,
    )
    assert res.verdict == "PASS"
    assert res.llm_verified is True
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) == 1
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=2)
    assert "NATIVE_VERIFY_MARKER" in user_txt


def test_f6_request_ollama_code_patch_fences_metadata_defects_source(
    loopback_ollama,
) -> None:
    loopback_ollama.set_default_content(
        f"```python\n{_CLEAN_VERIFY_PY}\n```"
    )
    patched, status = request_ollama_code_patch(
        source_code=_CLEAN_VERIFY_PY,
        defect_block="DEFECT_BLOCK_MARKER: none",
        arxiv_id="2601.00003",
        title="PATCH_TITLE_MARKER",
        endpoint=loopback_ollama.url,
        model_tag="qwen2.5:14b",
    )
    assert patched is not None
    assert status == "ollama_patch_synthesized"
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) == 1
    user_txt = _extract_roles(reqs[0])["user"]
    nonces = _assert_fenced_blocks(user_txt, min_blocks=3)
    assert len(set(nonces)) == 3
    assert "[source: paper_metadata]" in user_txt
    assert "[source: defect_diagnostics]" in user_txt
    assert "[source: python_source_code]" in user_txt
    assert "PATCH_TITLE_MARKER" in user_txt
    assert "DEFECT_BLOCK_MARKER" in user_txt


def test_f6_auto_repair_generated_code_with_llm_fences_defects(
    loopback_ollama,
) -> None:
    buggy = '''"""Module with bare except defect."""


def check_val(x: str) -> bool:
    try:
        return int(x) > 0
    except:
        return False
'''
    fixed = '''"""Module with bare except defect fixed."""


def check_val(x: str) -> bool:
    """Checks positive integer input."""
    try:
        return int(x) > 0
    except ValueError:
        return False
'''
    def _repair_handler(path: str, parsed_json: Dict[str, Any], headers: Dict[str, str]):
        model_name = str(parsed_json.get("model") or "qwen2.5:14b")
        msgs = parsed_json.get("messages") or []
        user_txt = "\n".join(str(m.get("content") or "") for m in msgs if m.get("role") == "user")
        if "[source: defect_diagnostics]" in user_txt:
            content = f"```python\n{fixed}\n```"
        elif "except:" in user_txt:
            content = json.dumps(
                {"verdict": "FAIL", "paper_fidelity_score": 40, "correctness_score": 40, "security_score": 40, "summary": "bare except", "findings": []}
            )
        else:
            content = json.dumps(
                {"verdict": "PASS", "paper_fidelity_score": 95, "correctness_score": 95, "security_score": 95, "summary": "repaired", "findings": []}
            )
        return 200, {"model": model_name, "message": {"role": "assistant", "content": content}, "done": True}

    loopback_ollama.set_handler(_repair_handler)
    res = auto_repair_generated_code(
        source_code=buggy,
        arxiv_id="2601.00004",
        title="REPAIR_TITLE_MARKER",
        max_repair_attempts=1,
        ollama_endpoint=loopback_ollama.url,
        enable_llm=True,
    )
    assert res.final_verdict == "PASS"
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) >= 2
    for req in reqs:
        _assert_fenced_blocks(_extract_roles(req)["user"], min_blocks=2)


def test_f6_invoke_ollama_json_judge_preserves_fenced_user_content(
    loopback_ollama,
) -> None:
    loopback_ollama.set_default_content(
        {
            "verdict": "PASS",
            "paper_fidelity_score": 92,
            "correctness_score": 90,
            "security_score": 94,
            "summary": "Verified",
            "findings": [],
        }
    )
    fenced_prompt = sanitize_for_llm_prompt("JUDGE_PAYLOAD_MARKER", max_chars=500, source="python_source_code")
    parsed, status = _invoke_ollama_json_judge(
        loopback_ollama.url,
        "qwen2.5:14b",
        fenced_prompt,
    )
    assert status == "llm_verified"
    assert parsed is not None and parsed["verdict"] == "PASS"
    reqs = loopback_ollama.get_requests("/api/chat")
    assert len(reqs) == 1
    _assert_fenced_blocks(_extract_roles(reqs[0])["user"], min_blocks=1)


# =============================================================================
# F7: `engine/fuzz_bridge.py` & `engine/call_graph_slicer.py` Fencing (5 tests)
# =============================================================================


def test_f7_fuzz_bridge_replaces_static_context_delimiter_with_xml_nonce(
    loopback_ollama, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "harness_code": "import atheris\ndef TestOneInput(data): pass\n",
            "seeds": ["seed1"],
            "dictionary_tokens": ["GET"],
        }
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    bridge = LLMFuzzBridge(arbiter=arbiter)
    target = DetectedTarget(
        language="python",
        backend="atheris",
        engine="libfuzzer",
        build_system="pip",
        root_dir=str(e2e_workspace.repo),
        package_name="fuzz_pkg_marker",
        entry_symbols=["parse_frame"],
        extracted_tokens=["CHUNKED"],
    )
    try:
        out = bridge._invoke_llm_for_synthesis(target, {"raw_hints": []})
    finally:
        arbiter.close()

    assert out is not None
    reqs = loopback_ollama.get_requests("/api/chat")
    assert reqs
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=1)
    assert "[source: fuzz_context]" in user_txt
    assert "<<<RFCHUNT_FUZZ_CONTEXT>>>" not in user_txt


def test_f7_fuzz_bridge_fences_cairn_hints_and_entry_symbols(
    loopback_ollama, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "harness_code": "import atheris\ndef TestOneInput(data): pass\n",
            "seeds": ["alpha"],
            "dictionary_tokens": ["POST"],
        }
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    bridge = LLMFuzzBridge(arbiter=arbiter)
    target = DetectedTarget(
        language="python",
        backend="atheris",
        engine="libfuzzer",
        build_system="pip",
        root_dir=str(e2e_workspace.repo),
        package_name="pkg_hints_test",
        entry_symbols=["ENTRY_SYM_MARKER"],
        extracted_tokens=["TOK_MARKER"],
    )
    hint_bundle = {
        "raw_hints": [
            {"node_id": "H-1", "domain": "http", "content": "CAIRN_HINT_MARKER"}
        ]
    }
    try:
        bridge._invoke_llm_for_synthesis(target, hint_bundle)
    finally:
        arbiter.close()

    reqs = loopback_ollama.get_requests("/api/chat")
    assert reqs
    user_txt = _extract_roles(reqs[0])["user"]
    _assert_fenced_blocks(user_txt, min_blocks=1)
    assert "ENTRY_SYM_MARKER" in user_txt
    assert "CAIRN_HINT_MARKER" in user_txt


def test_f7_taint_slice_to_prompt_block_wraps_in_xml_nonce() -> None:
    sl = TaintSlice(
        slice_id="SLICE-F7-1",
        vulnerability_class="Command Injection",
        cwe="CWE-78",
        severity="CRITICAL",
        entry_point="handler",
        sink="subprocess.run",
        sink_call="subprocess.run(cmd, shell=True)",
        sink_file="routes.py",
        sink_line=12,
        steps=[
            SliceStep(
                step_index=0,
                role="source",
                symbol_id="sym1",
                symbol_name="handler",
                file_path="routes.py",
                start_line=1,
                end_line=15,
                call_line=12,
                language="python",
                snippet="def handler(user_cmd):\n    subprocess.run(user_cmd, shell=True)\n",
            )
        ],
        files_involved=["routes.py"],
        is_cross_file=False,
        sanitizers=[],
        sanitizer_status="unsanitized",
        taint_confidence=0.95,
        poe_hint=2,
        source_backend="ast",
    )
    block = sl.to_prompt_block()
    _assert_fenced_blocks(block, min_blocks=1)
    assert "[source: taint_slice]" in block
    assert "subprocess.run(user_cmd, shell=True)" in block


def test_f7_taint_slice_to_escalation_candidate_produces_fenced_prompt_context() -> None:
    sl = TaintSlice(
        slice_id="SLICE-F7-2",
        vulnerability_class="Code Execution",
        cwe="CWE-95",
        severity="HIGH",
        entry_point="api_eval",
        sink="eval",
        sink_call="eval(body)",
        sink_file="api.py",
        sink_line=8,
        steps=[
            SliceStep(
                step_index=0,
                role="sink",
                symbol_id="sym2",
                symbol_name="api_eval",
                file_path="api.py",
                start_line=5,
                end_line=10,
                call_line=8,
                language="python",
                snippet="def api_eval(body):\n    return eval(body)\n",
            )
        ],
        files_involved=["api.py"],
        is_cross_file=False,
        sanitizers=[],
        sanitizer_status="unsanitized",
        taint_confidence=0.9,
        poe_hint=2,
        source_backend="ast",
    )
    cand = sl.to_escalation_candidate()
    _assert_fenced_blocks(cand["prompt_context"], min_blocks=1)
    assert "api_eval" in cand["prompt_context"]


def test_f7_call_graph_slicer_analyze_repo_fences_extracted_slices(
    e2e_workspace,
) -> None:
    e2e_workspace.write_repo_file(
        "app.py",
        (
            "import subprocess\n"
            "from flask import request\n\n"
            "def run_helper(cmd):\n"
            "    return subprocess.run(cmd, shell=True)\n\n"
            "def route_handler():\n"
            "    q = request.args.get('q')\n"
            "    return run_helper(q)\n"
        ),
    )
    report = CallGraphSlicer().analyze_repo(e2e_workspace.repo)
    assert report.files_scanned >= 1
    assert report.slices, "Expected at least one extracted taint slice"
    for sl in report.slices:
        _assert_fenced_blocks(sl.to_prompt_block(), min_blocks=1)


# =============================================================================
# F8: Ollama `/api/chat` Structured Role Isolation (5 tests)
# =============================================================================


def test_f8_fusion_engine_posts_only_to_api_chat_with_role_isolation(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "rationale": "Test",
            "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD",
            "is_clean": True,
        }
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        arbiter.run_fusion_pipeline("UNTRUSTED_ROLE_CANARY_F8_1")
    finally:
        arbiter.close()

    all_reqs = loopback_ollama.get_requests()
    assert all_reqs
    assert all(r["path"] == "/api/chat" for r in all_reqs)
    for r in all_reqs:
        msgs = (r["json"] or {}).get("messages") or []
        assert [m.get("role") for m in msgs] == ["system", "user"]
        assert "UNTRUSTED_ROLE_CANARY_F8_1" not in msgs[0]["content"]
        assert "UNTRUSTED_ROLE_CANARY_F8_1" in msgs[1]["content"]


def test_f8_model_adapter_posts_only_to_api_chat_with_role_isolation(
    loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "probes": [
                {
                    "rationale": "Adapter probe",
                    "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n",
                    "is_clean": True,
                }
            ]
        }
    )
    adapter = ModelFusionAdapter(
        preferred_model="qwen2.5:14b",
        ollama_endpoint=loopback_ollama.url,
        use_fusion=False,
        force_ollama=True,
    )
    try:
        safe_user = sanitize_for_llm_prompt("UNTRUSTED_ROLE_CANARY_F8_2", max_chars=400)
        res = adapter.generate_json("SYSTEM_DIRECTIVE_ONLY", f"Analyze:\n{safe_user}")
    finally:
        adapter.close()

    assert res
    all_reqs = loopback_ollama.get_requests()
    assert len(all_reqs) == 1
    assert all_reqs[0]["path"] == "/api/chat"
    msgs = all_reqs[0]["json"]["messages"]
    assert [m.get("role") for m in msgs] == ["system", "user"]
    assert msgs[0]["content"] == "SYSTEM_DIRECTIVE_ONLY"
    assert "UNTRUSTED_ROLE_CANARY_F8_2" in msgs[1]["content"]


def test_f8_code_verification_repair_verify_site_uses_api_chat(
    loopback_ollama,
) -> None:
    loopback_ollama.set_default_content(
        {
            "verdict": "PASS",
            "paper_fidelity_score": 90,
            "correctness_score": 90,
            "security_score": 90,
            "summary": "ok",
            "findings": [],
        }
    )
    verify_python_code_native(
        _CLEAN_VERIFY_PY + "\n# UNTRUSTED_ROLE_CANARY_F8_3\n",
        arxiv_id="2601.00005",
        title="Title",
        ollama_endpoint=loopback_ollama.url,
        enable_llm=True,
    )
    all_reqs = loopback_ollama.get_requests()
    assert len(all_reqs) == 1
    assert all_reqs[0]["path"] == "/api/chat"
    msgs = all_reqs[0]["json"]["messages"]
    assert [m.get("role") for m in msgs] == ["system", "user"]
    assert "UNTRUSTED_ROLE_CANARY_F8_3" not in msgs[0]["content"]
    assert "UNTRUSTED_ROLE_CANARY_F8_3" in msgs[1]["content"]


def test_f8_code_verification_repair_patch_site_uses_api_chat(
    loopback_ollama,
) -> None:
    loopback_ollama.set_default_content(f"```python\n{_CLEAN_VERIFY_PY}\n```")
    request_ollama_code_patch(
        source_code=_CLEAN_VERIFY_PY + "\n# UNTRUSTED_ROLE_CANARY_F8_4\n",
        defect_block="DEFECT_CANARY",
        arxiv_id="2601.00006",
        title="Patch",
        endpoint=loopback_ollama.url,
        model_tag="qwen2.5:14b",
    )
    all_reqs = loopback_ollama.get_requests()
    assert len(all_reqs) == 1
    assert all_reqs[0]["path"] == "/api/chat"
    msgs = all_reqs[0]["json"]["messages"]
    assert [m.get("role") for m in msgs] == ["system", "user"]
    assert "UNTRUSTED_ROLE_CANARY_F8_4" not in msgs[0]["content"]
    assert "UNTRUSTED_ROLE_CANARY_F8_4" in msgs[1]["content"]


def test_f8_swarm_dispatcher_tiered_model_router_uses_api_chat(
    loopback_ollama,
) -> None:
    loopback_ollama.set_default_content({"verdict": "confirmed"})
    router = TieredModelRouter()
    decision = ModelRoutingDecision(
        candidate_id="CAND-F8",
        tier="fast_local",
        model="qwen2.5:14b",
        provider="ollama",
        escalated=False,
        rank_score=0.9,
        poe_level=2,
        reason="test",
        free_ram_gb=16.0,
        free_vram_mb=0.0,
    )
    fenced_slice = sanitize_for_llm_prompt("UNTRUSTED_ROLE_CANARY_F8_5", max_chars=400)
    out = router.invoke_decision(
        decision,
        system_prompt="ROUTER_SYSTEM_ONLY",
        user_prompt=f"Triage slice:\n{fenced_slice}",
        ollama_endpoint=loopback_ollama.url,
    )
    assert "confirmed" in out["response"]
    all_reqs = loopback_ollama.get_requests()
    assert len(all_reqs) == 1
    assert all_reqs[0]["path"] == "/api/chat"
    msgs = all_reqs[0]["json"]["messages"]
    assert [m.get("role") for m in msgs] == ["system", "user"]
    assert msgs[0]["content"] == "ROUTER_SYSTEM_ONLY"
    assert "UNTRUSTED_ROLE_CANARY_F8_5" in msgs[1]["content"]


# =============================================================================
# F9: `surface_mining` Workspace Root Confinement (5 tests)
# =============================================================================


def _create_registry_with_workspace_root(workspace_root: Path, port: int) -> LiveWorkerExecutorRegistry:
    sig = inspect.signature(LiveWorkerExecutorRegistry.__init__)
    assert "workspace_root" in sig.parameters, (
        "M2: LiveWorkerExecutorRegistry.__init__ missing required 'workspace_root' parameter"
    )
    return LiveWorkerExecutorRegistry(
        host="127.0.0.1",
        port=port,
        authorized=True,
        approval_gate=ApprovalGate(mode="policy"),
        workspace_root=workspace_root,
    )


def test_f9_surface_mining_registry_accepts_workspace_root_param(
    e2e_workspace, loopback_target_app
) -> None:
    registry = _create_registry_with_workspace_root(e2e_workspace.repo, loopback_target_app.port)
    ws_attr = getattr(registry, "workspace_root", None)
    assert ws_attr is not None
    assert Path(ws_attr).resolve() == e2e_workspace.repo.resolve()


def test_f9_surface_mining_allows_in_root_directory_and_discovers_routes(
    e2e_workspace, loopback_target_app
) -> None:
    e2e_workspace.write_repo_file(
        "frontend/app.js",
        "fetch('/api/inroot_route');\n",
    )
    registry = _create_registry_with_workspace_root(e2e_workspace.repo, loopback_target_app.port)
    res = registry.surface_mining(target_path=str(e2e_workspace.repo))
    assert res["ok"] is True
    assert res["source"] != "blocked"
    assert any("/api/inroot_route" in str(ep) for ep in (res.get("endpoints") or []))


def test_f9_surface_mining_allows_in_root_nested_file(
    e2e_workspace, loopback_target_app
) -> None:
    js_file = e2e_workspace.write_repo_file(
        "src/nested/routes.js",
        "axios.get('/api/nested_endpoint');\n",
    )
    registry = _create_registry_with_workspace_root(e2e_workspace.repo, loopback_target_app.port)
    res = registry.surface_mining(target_path=str(js_file))
    assert res["ok"] is True
    assert res["source"] != "blocked"
    assert any("/api/nested_endpoint" in str(ep) for ep in (res.get("endpoints") or []))


def test_f9_surface_mining_blocks_outside_absolute_path(
    e2e_workspace, loopback_target_app
) -> None:
    outside_js = e2e_workspace.write_outside_file(
        "secret.js",
        "fetch('/api/leaked_outside_secret');\n",
    )
    registry = _create_registry_with_workspace_root(e2e_workspace.repo, loopback_target_app.port)
    res = registry.surface_mining(target_path=str(outside_js))
    assert res["ok"] is False
    assert res["source"] == "blocked"
    assert "leaked_outside_secret" not in json.dumps(res)


def test_f9_surface_mining_blocks_traversal_path(
    e2e_workspace, loopback_target_app
) -> None:
    e2e_workspace.write_outside_file(
        "secret_trav.js",
        "fetch('/api/leaked_traversal_secret');\n",
    )
    registry = _create_registry_with_workspace_root(e2e_workspace.repo, loopback_target_app.port)
    res = registry.surface_mining(target_path=str(e2e_workspace.repo / ".." / "outside" / "secret_trav.js"))
    assert res["ok"] is False
    assert res["source"] == "blocked"
    assert "leaked_traversal_secret" not in json.dumps(res)


# =============================================================================
# F10: `file_path` Workspace Root Confinement (5 tests)
# =============================================================================


def test_f10_execution_policy_exposes_file_read_action_and_validate_file_path(
    e2e_workspace,
) -> None:
    file_read = getattr(ActionType, "FILE_READ", None)
    assert file_read is not None, "M2: ActionType.FILE_READ not implemented yet"
    validate_fn = getattr(ExecutionPolicy, "validate_file_path", None)
    assert callable(validate_fn), "M2: ExecutionPolicy.validate_file_path not implemented yet"

    target_file = e2e_workspace.write_repo_file("module.py", "print('ok')\n")
    policy = ExecutionPolicy()
    result = validate_fn(policy, str(target_file), e2e_workspace.repo)
    assert result is not None
    if isinstance(result, tuple):
        assert result[0] is True
    else:
        assert Path(result).resolve() == target_file.resolve()


def test_f10_execution_policy_validate_intent_file_read_allows_in_root(
    e2e_workspace,
) -> None:
    file_read = getattr(ActionType, "FILE_READ", None)
    assert file_read is not None, "M2: ActionType.FILE_READ not implemented yet"

    target_file = e2e_workspace.write_repo_file("in_root.py", "x = 1\n")
    field_names = {f.name for f in dataclasses.fields(StructuredIntentProposal)}
    kwargs: Dict[str, Any] = {
        "task": ScannerTask.REA_SURFACE,
        "action_type": file_read,
        "file_path": str(target_file),
        "rationale": "Inspect in-root file",
        "metadata": {"workspace_root": str(e2e_workspace.repo)},
    }
    if "workspace_root" in field_names:
        kwargs["workspace_root"] = str(e2e_workspace.repo)
    proposal = StructuredIntentProposal(**kwargs)
    assert ExecutionPolicy().validate_intent(proposal) is True


def test_f10_execution_policy_validate_intent_blocks_out_of_root_file_read(
    e2e_workspace,
) -> None:
    file_read = getattr(ActionType, "FILE_READ", None)
    assert file_read is not None, "M2: ActionType.FILE_READ not implemented yet"

    outside_file = e2e_workspace.write_outside_file("secret.txt", "TOP_SECRET\n")
    field_names = {f.name for f in dataclasses.fields(StructuredIntentProposal)}
    kwargs: Dict[str, Any] = {
        "task": ScannerTask.REA_SURFACE,
        "action_type": file_read,
        "file_path": str(outside_file),
        "rationale": "Prompt-injected out-of-root read",
        "metadata": {"workspace_root": str(e2e_workspace.repo)},
    }
    if "workspace_root" in field_names:
        kwargs["workspace_root"] = str(e2e_workspace.repo)
    proposal = StructuredIntentProposal(**kwargs)
    with pytest.raises((PermissionError, ValueError)):
        ExecutionPolicy().validate_intent(proposal)


def test_f10_rea_integrator_analyze_allows_in_root_js_file(
    e2e_workspace,
) -> None:
    init_sig = inspect.signature(ReaIntegrator.__init__)
    analyze_sig = inspect.signature(ReaIntegrator.analyze)
    has_ws = ("workspace_root" in init_sig.parameters) or ("workspace_root" in analyze_sig.parameters)
    assert has_ws, "M2: ReaIntegrator missing workspace_root confinement parameter"

    e2e_workspace.write_repo_file("client.js", "fetch('/api/rea_inroot');\n")
    init_kwargs: Dict[str, Any] = {"reports_dir": str(e2e_workspace.output_dir)}
    if "workspace_root" in init_sig.parameters:
        init_kwargs["workspace_root"] = str(e2e_workspace.repo)
    integrator = ReaIntegrator(**init_kwargs)
    analyze_kwargs: Dict[str, Any] = {
        "target_path": str(e2e_workspace.repo),
        "write_reports": False,
    }
    if "workspace_root" in analyze_sig.parameters:
        analyze_kwargs["workspace_root"] = str(e2e_workspace.repo)
    res = integrator.analyze(**analyze_kwargs)
    assert res.status == "completed"
    assert any("/api/rea_inroot" in str(ep) for ep in res.discovered_endpoints)


def test_f10_mcp_server_allows_in_root_rea_analyze_and_run_all_scans(
    e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("RFCHUNT_WORKSPACE_ROOT", str(e2e_workspace.repo))
    e2e_workspace.write_repo_file("ui.js", "fetch('/api/mcp_inroot');\n")

    srv_sig = inspect.signature(TerminatorMCPServer.__init__)
    srv_kwargs: Dict[str, Any] = {"db_path": str(e2e_workspace.db_path)}
    if "workspace_root" in srv_sig.parameters:
        srv_kwargs["workspace_root"] = str(e2e_workspace.repo)
    server = TerminatorMCPServer(**srv_kwargs)
    resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "rea_analyze_surface",
                "arguments": {
                    "target_path": str(e2e_workspace.repo),
                    "output_dir": str(e2e_workspace.repo / "reports"),
                },
            },
        }
    )
    assert "error" not in resp
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["status"] == "completed"
    assert any("/api/mcp_inroot" in str(ep) for ep in payload["discovered_endpoints"])


# =============================================================================
# F11: Deterministic Override Immunity (6 tests)
# =============================================================================


def test_f11_verify_python_code_native_preserves_deterministic_pass_against_hostile_fail(
    loopback_ollama,
) -> None:
    loopback_ollama.set_default_content(
        {
            "verdict": "FAIL",
            "paper_fidelity_score": 5,
            "correctness_score": 5,
            "security_score": 5,
            "summary": "POISONED_LLM_VETO_FAIL",
            "findings": [{"severity": "CRITICAL", "category": "spoof", "message": "veto"}],
        }
    )
    res = verify_python_code_native(
        _CLEAN_VERIFY_PY,
        arxiv_id="2601.00011",
        title="Clean Deterministic Module",
        ollama_endpoint=loopback_ollama.url,
        enable_llm=True,
    )
    assert res.llm_verified is True
    assert res.verdict == "PASS", (
        f"Deterministic Layer-1 PASS was illegally downgraded to {res.verdict} by hostile LLM judge"
    )


def test_f11_execute_candidate_multiturn_preserves_final_ok_against_hostile_finish(
    loopback_ollama, loopback_target_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_handler(
        _make_multiturn_chat_handler(
            {
                "action": "tool_call",
                "tool": "safe_http_probe",
                "args": {"method": "POST", "route": "/api/chat", "body": "RFCHUNT_CANARY_PROBE"},
                "hypothesis": "Verify canary reflection",
            },
            {
                "action": "finish",
                "confirmed": False,
                "evidence": "POISONED_FINISH_NOT_VULNERABLE",
            },
        )
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    registry = LiveWorkerExecutorRegistry(
        host="127.0.0.1",
        port=loopback_target_app.port,
        authorized=True,
        approval_gate=ApprovalGate(mode="policy"),
        arbiter=arbiter,
    )
    try:
        final_ok, _, _, meta = registry.execute_candidate_multiturn(
            {"attack_type": "AI_INJECTION", "target_route": "/api/chat", "has_ai_sink": True},
            max_turns=3,
        )
    finally:
        arbiter.close()

    assert final_ok is True
    assert meta["evidence_quote"] == "RFCHUNT_CANARY_PROBE"


def test_f11_execute_candidate_multiturn_preserves_best_evidence_against_hostile_finish(
    loopback_ollama, loopback_target_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_handler(
        _make_multiturn_chat_handler(
            {
                "action": "tool_call",
                "tool": "safe_http_probe",
                "args": {"method": "POST", "route": "/api/chat", "body": "RFCHUNT_CANARY_PROBE"},
                "hypothesis": "Verify canary reflection",
            },
            {
                "action": "finish",
                "confirmed": False,
                "evidence": "POISONED_LLM_CLAIM_EVERYTHING_SAFE",
            },
        )
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    registry = LiveWorkerExecutorRegistry(
        host="127.0.0.1",
        port=loopback_target_app.port,
        authorized=True,
        approval_gate=ApprovalGate(mode="policy"),
        arbiter=arbiter,
    )
    try:
        final_ok, final_evidence, _, _ = registry.execute_candidate_multiturn(
            {"attack_type": "AI_INJECTION", "target_route": "/api/chat", "has_ai_sink": True},
            max_turns=3,
        )
    finally:
        arbiter.close()

    assert final_ok is True
    assert "POISONED_LLM_CLAIM_EVERYTHING_SAFE" not in final_evidence, (
        f"Hostile finish(confirmed=false) overwrote deterministic best_evidence: {final_evidence!r}"
    )
    assert "AI_INJECTION" in final_evidence or "/api/chat" in final_evidence


def test_f11_execute_candidate_multiturn_auth_boundary_override_immunity(
    loopback_ollama, loopback_target_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_target_app.admin_requires_auth = True
    loopback_ollama.set_handler(
        _make_multiturn_chat_handler(
            {
                "action": "tool_call",
                "tool": "auth_diff_probe",
                "args": {
                    "method": "GET",
                    "route": "/internal/admin",
                    "primary_profile": "end_user",
                    "secondary_profile": "anonymous",
                },
                "hypothesis": "Verify AUTH_BOUNDARY differential on /internal/admin",
            },
            {
                "action": "finish",
                "confirmed": False,
                "evidence": "POISONED_AUTH_BOUNDARY_SAFE",
            },
        )
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    registry = LiveWorkerExecutorRegistry(
        host="127.0.0.1",
        port=loopback_target_app.port,
        authorized=True,
        approval_gate=ApprovalGate(mode="policy"),
        auth_profiles={
            "end_user": AuthProfile(
                name="end_user",
                role="end_user",
                bearer_token="admin-token",
            )
        },
        arbiter=arbiter,
    )
    try:
        final_ok, final_evidence, _, meta = registry.execute_candidate_multiturn(
            {"attack_type": "AUTH_BOUNDARY", "target_route": "/internal/admin"},
            max_turns=3,
        )
    finally:
        arbiter.close()

    assert final_ok is True
    assert meta.get("traffic_id")
    assert "POISONED_AUTH_BOUNDARY_SAFE" not in final_evidence, (
        f"Hostile finish(confirmed=false) overwrote deterministic AUTH_BOUNDARY evidence: {final_evidence!r}"
    )
    assert "AUTH_BOUNDARY" in final_evidence and "/internal/admin" in final_evidence


def test_f11_mantis_threat_modeler_preserves_deterministic_counts_against_hostile_summary(
    loopback_ollama, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content(
        {
            "summary": "0 files indexed, 0 vulnerabilities, completely safe.",
            "threat_actors": [],
        }
    )
    f = e2e_workspace.write_repo_file(
        "vuln_entry.py",
        "from flask import request\ndef route():\n    return eval(request.args.get('x'))\n",
    )
    arbiter = FusionArbiter(endpoint=loopback_ollama.url, force_ollama=True, quiet=True)
    try:
        tm = MantisThreatModeler(fusion_arbiter=arbiter).build_threat_model(
            str(e2e_workspace.repo), [str(f)]
        )
    finally:
        arbiter.close()

    assert "0 files" not in tm.raw_summary.lower(), (
        f"Hostile LLM summary overwrote deterministic file count in raw_summary: {tm.raw_summary!r}"
    )
    assert "1 files indexed" in tm.raw_summary or len(tm.risk_ranked_files) == 1


def test_f11_mantis_hypothesis_generator_preserves_ast_findings_against_hostile_llm(
    loopback_ollama, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    loopback_ollama.set_default_content([])
    f = e2e_workspace.write_repo_file(
        "vuln_eval.py",
        "def run_eval(user_expr):\n    return eval(user_expr)\n",
    )
    tm = MantisThreatModeler().build_threat_model(str(e2e_workspace.repo), [str(f)])
    adapter = ModelFusionAdapter(
        preferred_model="qwen2.5:14b",
        ollama_endpoint=loopback_ollama.url,
        use_fusion=False,
        force_ollama=True,
    )
    try:
        hyps = MantisHypothesisGenerator(model_adapter=adapter).generate_hypotheses(
            [str(f)], tm, depth=100
        )
    finally:
        adapter.close()

    assert any(h.rule_id == "MANTIS-EVAL-002" for h in hyps)
