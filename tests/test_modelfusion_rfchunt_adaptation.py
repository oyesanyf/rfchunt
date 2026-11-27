"""
Zero-Mock Integration & Unit Tests for ModelFusion <-> RFCHunt Adaptation
and Abliterated Anti-Junk / Grounding Guards.

Uses real loopback `ThreadingHTTPServer` endpoints on ephemeral `127.0.0.1:0` ports
and real temporary workspace directories (ZERO `unittest.mock`, `MagicMock`, or `monkeypatch`).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from engine.ensemble_orchestrator import EngineFinding
from engine.gha_llm_verifier import (
    ABLITERATED_GLM_FUSION_CATALOG,
    resolve_gha_llm_backend,
    verify_gha_findings_with_llm,
)
from engine.hackerone_porter import (
    HackerOneCampaign,
    HackerOneComputerUsePorter,
    HackerOneReportDraft,
)
from engine.ollama_concurrency_guard import OllamaConcurrencyGuard
from model_adapter import (
    ModelFusionAdapter,
    detect_meta_slop,
    detect_repetition_loop,
    strip_think_blocks,
    validate_abliterated_output,
)


def _start_loopback_server(routes: Dict[Tuple[str, str], Any]) -> Tuple[ThreadingHTTPServer, str]:
    """Starts a real loopback HTTP server with deterministic route handlers."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(length) if length > 0 else b""
            body_json = None
            if raw_body:
                try:
                    body_json = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    body_json = raw_body.decode("utf-8", errors="ignore")
            handler = routes.get((method, self.path))
            if handler is None:
                self.send_response(404)
                self.end_headers()
                return
            status, resp_obj = handler(body_json)
            encoded = (
                json.dumps(resp_obj).encode("utf-8")
                if isinstance(resp_obj, (dict, list))
                else str(resp_obj).encode("utf-8")
            )
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def test_anti_junk_guard_rejects_loops_slop_refusals_and_hallucinated_paths() -> None:
    assert strip_think_blocks("<think>chain of thought</think>\n{\"ok\": true}") == '{"ok": true}'
    assert strip_think_blocks("<think>unclosed reasoning loop") == ""

    assert detect_repetition_loop("The file is vulnerable at line 42.\n" * 4) is not None
    assert detect_repetition_loop("validate every single input parameter before use " * 5) is not None
    assert detect_repetition_loop("z" * 30) is not None
    assert detect_meta_slop("In summary, the key steps to continue aligns with best practices.") is not None

    bad_hallucination = json.dumps(
        {
            "verdicts": [
                {
                    "file_path": "src/nonexistent/fabricated_handler.ts",
                    "line": 12,
                    "confirmed": True,
                }
            ]
        }
    )
    v_bad = validate_abliterated_output(
        bad_hallucination,
        allowed_file_paths=["packages/shopify-app-remix/src/sanitize.ts"],
        require_json=True,
    )
    assert not v_bad["accepted"]
    assert any(r.startswith("hallucinated_file_paths") for r in v_bad["rejection_reasons"])

    good_grounded = (
        "<think>Checking sanitize.ts...</think>\n"
        + json.dumps(
            {
                "verdicts": [
                    {
                        "file_path": "packages/shopify-app-remix/src/sanitize.ts",
                        "line": 42,
                        "confirmed": True,
                        "cwe": "CWE-601",
                    }
                ]
            }
        )
    )
    v_good = validate_abliterated_output(
        good_grounded,
        allowed_file_paths=["packages/shopify-app-remix/src/sanitize.ts"],
        require_json=True,
    )
    assert v_good["accepted"]
    assert v_good["cleaned_text"].startswith("{")


def test_modelfusion_http_server_routing_and_anti_junk_fallback(tmp_path: Path) -> None:
    mf_calls: List[Dict[str, Any]] = []

    def _mf_health(_body: Any) -> Tuple[int, Dict[str, Any]]:
        return 200, {"status": "ok"}

    def _mf_orchestrate(body: Any) -> Tuple[int, Dict[str, Any]]:
        mf_calls.append(body if isinstance(body, dict) else {})
        return 200, {
            "content": "<think>Analyzing src/filestore.ts</think>\n"
            + json.dumps(
                {
                    "verdicts": [
                        {
                            "file_path": "src/filestore.ts",
                            "line": 48,
                            "confirmed": True,
                            "severity": "HIGH",
                            "recommended_fix": "Verify canonical realpath on every intermediate directory.",
                        },
                        {
                            "file_path": "src/totally_fake_hallucination.ts",
                            "line": 99,
                            "confirmed": True,
                            "severity": "CRITICAL",
                        },
                    ]
                }
            )
        }

    server, mf_url = _start_loopback_server(
        {
            ("GET", "/health"): _mf_health,
            ("POST", "/api/orchestrate"): _mf_orchestrate,
        }
    )
    try:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        (wf_dir / "ci.yml").write_text("name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n", encoding="utf-8")

        guard = OllamaConcurrencyGuard(lock_path=tmp_path / "slot.lock")
        res = resolve_gha_llm_backend(
            modelfusion_endpoint=mf_url,
            use_modelfusion=True,
            guard=guard,
        )
        assert res.backend == "modelfusion"
        assert res.status == "ready"

        static_finding = EngineFinding(
            engine="parity_auditor",
            title="Missing intermediate symlink resolution",
            file_path="src/filestore.ts",
            line=48,
            cwe="CWE-59",
            severity="HIGH",
            confidence=0.9,
            summary="FileStore checks final path only.",
            rule_id="PARITY-SYMLINK-01",
            deterministic=True,
            confirmed=True,
        )
        findings, telemetry = verify_gha_findings_with_llm(
            tmp_path,
            [static_finding],
            modelfusion_endpoint=mf_url,
            use_modelfusion=True,
            guard=guard,
        )
        assert len(mf_calls) == 1
        assert mf_calls[0].get("fusion") is True
        assert telemetry["status"] == "completed"
        assert telemetry["dropped_hallucinated_verdicts"] == 1
        assert len(findings) == 1
        assert findings[0].file_path == "src/filestore.ts"
        assert findings[0].deterministic is False
    finally:
        server.shutdown()
        server.server_close()


def test_ollama_abliterated_junk_rolls_over_to_next_specialist(tmp_path: Path) -> None:
    calls_by_model: List[str] = []

    def _tags(_body: Any) -> Tuple[int, Dict[str, Any]]:
        return 200, {
            "models": [
                {"name": "huihui_ai/foundation-sec-abliterated:8b"},
                {"name": "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"},
            ]
        }

    def _chat(body: Any) -> Tuple[int, Dict[str, Any]]:
        m = str((body or {}).get("model") or "")
        calls_by_model.append(m)
        if "foundation-sec" in m:
            # First abliterated model emits degenerate repetition loop junk -> MUST be rejected
            return 200, {"message": {"content": "Check the input validation now.\n" * 6}}
        return 200, {
            "message": {
                "content": json.dumps(
                    {
                        "verdicts": [
                            {
                                "gha_class": "template_script_injection",
                                "file_path": ".github/workflows/ci.yml",
                                "line": 10,
                                "confirmed": True,
                                "severity": "HIGH",
                                "recommended_fix": "Pass untrusted expression through env variable.",
                            }
                        ]
                    }
                )
            }
        }

    server, ollama_url = _start_loopback_server(
        {
            ("GET", "/api/tags"): _tags,
            ("POST", "/api/chat"): _chat,
        }
    )
    try:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        (wf_dir / "ci.yml").write_text("name: CI\non: [pull_request_target]\n", encoding="utf-8")

        guard = OllamaConcurrencyGuard(lock_path=tmp_path / "slot2.lock")
        findings, telemetry = verify_gha_findings_with_llm(
            tmp_path,
            [],
            ollama_endpoint=ollama_url,
            use_modelfusion=False,
            force_ollama=True,
            guard=guard,
        )
        assert len(calls_by_model) == 2
        assert telemetry["status"] == "completed"
        assert telemetry["model"] == "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
        assert len(telemetry.get("anti_junk_rejections") or []) == 1
        assert len(findings) == 1
        assert findings[0].file_path == ".github/workflows/ci.yml"
        assert findings[0].deterministic is False
    finally:
        server.shutdown()
        server.server_close()


def test_hugos_browser_cdp_draft_spec_enforces_hitl_draft_only() -> None:
    campaign = HackerOneCampaign(
        handle="common_codes",
        name="Common Codes",
        url="https://hackerone.com/common_codes",
        submit_url="https://hackerone.com/common_codes/reports/new",
    )
    draft = HackerOneReportDraft(
        draft_id="draft-001",
        fingerprint="abcd1234",
        program_handle="common_codes",
        submit_url="https://hackerone.com/common_codes/reports/new",
        title="Intermediate symlink traversal in FileStore",
        vulnerability_information="Reproducible PoC details",
        impact="Arbitrary file write outside store root",
        severity_rating="high",
        weakness_cwe="CWE-59",
        asset_identifier="github.com/example/repo",
        source_rule_id="PARITY-SYMLINK-01",
        source_scanner="RFCHunt-Parity",
        evidence_lane="VERIFIED_EXPLOIT",
        poe_level=3,
        scope_match_status="in_scope",
    )
    porter = HackerOneComputerUsePorter()
    res = porter.stage_draft_via_hugos_cdp(campaign, [draft], dry_run=True)
    assert res["status"] == "dry_run_hugos_cdp_draft_planned"
    assert res["auto_submit_forbidden"] is True
    assert res["captcha_bypass_forbidden"] is True
    assert res["final_submit_blocked_for_hitl"] is True
    spec = res["spec"]
    assert spec["action_boundary"] == "create_draft_only"
    assert spec["target_url"] == "https://hackerone.com/common_codes/reports/new"
    assert any(s.get("action") == "click_create_draft_only" for s in spec["steps"])


def test_modelfusion_rust_catalog_has_100_percent_rfchunt_abliterated_parity() -> None:
    mf_memory_rs = Path(r"d:\harfile\ModelFusion\crates\model_selection\src\memory.rs")
    if not mf_memory_rs.is_file():
        pytest.skip("Sibling ModelFusion checkout not present on this host")
    content = mf_memory_rs.read_text(encoding="utf-8")
    for entry in ABLITERATED_GLM_FUSION_CATALOG:
        repo = str(entry.get("repo") or "")
        assert repo and repo in content, f"Missing RFCHunt abliterated model in ModelFusion catalog: {repo}"
    for core_tag in (
        "huihui_ai/foundation-sec-abliterated:8b",
        "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
        "huihui_ai/deepseek-r1-abliterated:8b",
        "fenkohq/foundation-sec-8b:latest",
    ):
        assert core_tag in content, f"Missing RFCHunt core specialist in ModelFusion catalog: {core_tag}"
