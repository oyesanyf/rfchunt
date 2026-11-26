#!/usr/bin/env python3
"""
tests/test_code_verification_repair.py
================================================================================
End-to-end verification tests for RFCHunt's migrated ArXiv-to-Code engines:
  - Layer-1 Concurrent Deterministic Verification (AST + Ruff + `mypy --strict` +
    310-Property Process-Isolated Fuzzing + Subprocess `pytest` + 7 Invariants)
  - Scale-Accurate VRAM-Resident Official Model Ranking (`glm4:9b` > `qwen2.5:7b` > `deepseek-r1:7b`)
  - Iterative Two-Tier Monotonic Auto-Repair Retry Loop (Tier A Ollama + Tier B AST Patcher)
  - ArxivSecurityBridge (`use_rl`, `auto_repair`, standalone CI synthesis + mounted integration)
  - CLI flags (`--arxiv-rl`, `--arxiv-verify-panel`, `--arxiv-auto-repair`, `--arxiv-max-repairs`)
  - MCP Tool (`verify_and_auto_repair_python_code`)
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Callable, List, Tuple

from engine.arxiv_security_bridge import ArxivSecurityBridge
from engine.code_verification_repair import (
    auto_repair_generated_code,
    is_verification_clean_pass,
    rank_repair_and_verifier_models,
    run_deterministic_code_verification,
    run_mypy_type_checker,
    run_property_based_fuzzing,
    run_static_code_linters,
    synthesize_verified_detector_module,
    verify_python_code_native,
)
from mcp_server import TerminatorMCPServer
from rfc_hunt_swarm import parse_swarm_arguments


def _start_loopback_ollama(
    models: List[str],
    responder: Callable[[str, str], str],
) -> Tuple[HTTPServer, str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/api/tags":
                payload = json.dumps({"models": [{"name": m} for m in models]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            body = json.loads(raw) if raw else {}
            model_name = str(body.get("model", models[0] if models else "glm4:9b"))
            if self.path == "/api/chat":
                messages = body.get("messages")
                if not isinstance(messages, list) or not any(
                    isinstance(m, dict) and m.get("role") == "system" and m.get("content")
                    for m in messages
                ) or not any(
                    isinstance(m, dict) and m.get("role") == "user" and m.get("content")
                    for m in messages
                ):
                    err = json.dumps({"error": "missing system/user messages"}).encode("utf-8")
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                    return
                prompt = "\n".join(str(m.get("content", "")) for m in messages if isinstance(m, dict))
                reply = responder(model_name, prompt)
                resp_obj = {
                    "model": model_name,
                    "message": {"role": "assistant", "content": reply},
                    "done": True,
                }
            else:
                prompt = str(body.get("prompt", ""))
                reply = responder(model_name, prompt)
                resp_obj = {"model": model_name, "response": reply, "done": True}
            payload = json.dumps(resp_obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}"


def test_native_synthesized_module_passes_lint_mypy_strict_310_fuzz_and_pytest() -> None:
    src = synthesize_verified_detector_module(
        arxiv_id="2608.15888",
        title="Bounded Agents: Delegation Security for Multi-Agent AI Systems",
        code_repo_url="https://github.com/xmuruaga/bounded-agents",
    )
    det = run_deterministic_code_verification(src, arxiv_id="2608.15888")
    assert det["ast_syntax_valid"] is True
    assert det["linter_passed"] is True, det["linter_issues"]
    assert det["mypy_executed"] is True
    assert det["mypy_passed"] is True, det["mypy_issues"]
    assert det["mypy_issue_count"] == 0
    assert det["fuzz_executed"] is True
    assert det["fuzz_passed"] is True, det["fuzz_failures"]
    assert det["fuzz_properties_checked"] >= 250
    assert det["pytest_executed"] is True
    assert det["pytest_passed"] is True
    assert det["runtime_tests_passed"] == det["runtime_tests_total"] == 7
    assert det["deterministic_score"] == 100.0


def test_mypy_strict_and_property_fuzzing_fail_closed_on_real_defects() -> None:
    clean = synthesize_verified_detector_module(
        arxiv_id="2608.15888",
        title="Bounded Agents",
        code_repo_url="https://github.com/xmuruaga/bounded-agents",
    )

    # 1. mypy --strict failure on untyped / mismatched code
    bad_type = clean + "\n\ndef untyped_fn(a, b):\n    x: int = 'wrong'\n    return a + b + x\n"
    mypy_res = run_mypy_type_checker(bad_type)
    assert mypy_res["mypy_executed"] is True
    assert mypy_res["mypy_passed"] is False
    ver_type = verify_python_code_native(bad_type, arxiv_id="2608.15888", enable_llm=False)
    assert ver_type.verdict == "FAIL"

    # 2. Broken wildcard top-element semilattice (`*` & S != S)
    bad_lattice = clean.replace(
        "self._meet_set(self.resources, narrower.resources)",
        "self.resources & narrower.resources",
    )
    fuzz_lat = run_property_based_fuzzing(bad_lattice)
    assert fuzz_lat["fuzz_passed"] is False
    assert any(f["property"] == "semilattice_top_identity" for f in fuzz_lat["failures"])
    assert verify_python_code_native(bad_lattice, enable_llm=False).verdict == "FAIL"

    # 3. Stale cache key `(payload_corpus, len(indicators))` + `1.0 / alpha` ZeroDivisionError
    bad_kernel = (
        "_BAD_CACHE: Dict[Tuple[str, int], Tuple[str, ...]] = {}\n\n"
        "def scan_and_score_payload(\n"
        "    payload_corpus: str,\n"
        "    indicators: Sequence[str],\n"
        "    prior_wealth: float = 1.0,\n"
        "    alpha: float = 0.01,\n"
        ") -> Tuple[Tuple[str, ...], float, float, bool]:\n"
        "    cache_key = (payload_corpus, len(indicators))\n"
        "    cached = _BAD_CACHE.get(cache_key)\n"
        "    if cached is None:\n"
        "        corpus_lc = payload_corpus.lower()\n"
        "        cached = tuple(pat for pat in indicators if pat.lower() in corpus_lc)\n"
        "        _BAD_CACHE[cache_key] = cached\n"
        "    nc = min(1.0, 0.05 + 0.35 * len(cached))\n"
        "    w = prior_wealth * (1.0 + 3.0 * len(cached)) if cached else max(0.05, prior_wealth * 0.9)\n"
        "    return cached, round(nc, 4), round(w, 4), (bool(cached) or w >= (1.0 / alpha))\n"
    )
    s = clean.index("# EVOLVE-BLOCK-START") + len("# EVOLVE-BLOCK-START")
    e = clean.index("# EVOLVE-BLOCK-END")
    bad_cache_code = clean[:s] + "\n" + bad_kernel + "\n" + clean[e:]
    lint_res = run_static_code_linters(bad_cache_code)
    assert lint_res["linter_passed"] is False
    assert any(i["code"] == "AST-BUG001" for i in lint_res["issues"])
    fuzz_zero = run_property_based_fuzzing(bad_cache_code)
    assert fuzz_zero["fuzz_passed"] is False


def test_scale_accurate_vram_model_ranking_9b_over_7b_and_abliterated() -> None:
    installed = [
        "hf.co/ggml-org/Bespoke-Nimble-9B-v3-GGUF:Q4_K_M",
        "nomic-embed-text:latest",
        "huihui_ai/foundation-sec-abliterated:8b",
        "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
        "deepseek-r1:7b",
        "qwen2.5:7b",
        "glm4:9b",
    ]
    ranked = rank_repair_and_verifier_models(installed, gpu_vram_gb=8.0)
    assert all("nimble" not in m.lower() and "embed" not in m.lower() for m in ranked)
    assert ranked[:3] == ["glm4:9b", "qwen2.5:7b", "deepseek-r1:7b"]


def test_auto_repair_deterministic_patcher_heals_5_simultaneous_bugs_to_100_pass() -> None:
    clean = synthesize_verified_detector_module(
        arxiv_id="2608.15888",
        title="Bounded Agents",
        code_repo_url="https://github.com/xmuruaga/bounded-agents",
    )
    buggy = clean.replace("import hashlib\n", "import hashlib\nimport math\n", 1)
    buggy = buggy.replace(
        "self._meet_set(self.resources, narrower.resources)",
        "self.resources & narrower.resources",
    )
    broken_kernel = (
        "_BAD_CACHE: Dict[Tuple[str, int], Tuple[str, ...]] = {}\n\n"
        "def scan_and_score_payload(\n"
        "    payload_corpus: str,\n"
        "    indicators: Sequence[str],\n"
        "    prior_wealth: float = 1.0,\n"
        "    alpha: float = 0.01,\n"
        ") -> Tuple[Tuple[str, ...], float, float, bool]:\n"
        "    try:\n"
        "        cache_key = (payload_corpus, len(indicators))\n"
        "    except:\n"
        "        cache_key = (payload_corpus, len(indicators))\n"
        "    cached = _BAD_CACHE.get(cache_key)\n"
        "    if cached is None:\n"
        "        corpus_lc = payload_corpus.lower()\n"
        "        cached = tuple(pat for pat in indicators if pat.lower() in corpus_lc)\n"
        "        _BAD_CACHE[cache_key] = cached\n"
        "    nc = min(1.0, 0.05 + 0.35 * len(cached))\n"
        "    w = prior_wealth * (1.0 + 3.0 * len(cached)) if cached else max(0.05, prior_wealth * 0.9)\n"
        "    return cached, round(nc, 4), round(w, 4), (bool(cached) or w >= (1.0 / alpha))\n"
    )
    s = buggy.index("# EVOLVE-BLOCK-START") + len("# EVOLVE-BLOCK-START")
    e = buggy.index("# EVOLVE-BLOCK-END")
    buggy = buggy[:s] + "\n" + broken_kernel + "\n" + buggy[e:]

    before = verify_python_code_native(buggy, arxiv_id="2608.15888", enable_llm=False)
    assert before.verdict == "FAIL"
    assert before.deterministic_checks["linter_passed"] is False
    assert before.deterministic_checks["fuzz_passed"] is False

    rep = auto_repair_generated_code(
        source_code=buggy,
        arxiv_id="2608.15888",
        initial_report=before,
        max_repair_attempts=3,
        enable_llm=False,
    )
    assert rep.repaired is True
    assert rep.converged_clean is True
    assert rep.final_verdict == "PASS"
    assert rep.final_score == 100.0
    assert is_verification_clean_pass(rep.final_verification_report) is True


def test_auto_repair_live_loopback_ollama_heals_mypy_error_and_rejects_regression() -> None:
    clean = synthesize_verified_detector_module(
        arxiv_id="2608.15888",
        title="Bounded Agents",
        code_repo_url="https://github.com/xmuruaga/bounded-agents",
    )
    buggy = clean + "\n\ndef helper_metric(n: int) -> int:\n    bad: int = 'wrong_type'\n    return n + len(bad)\n"
    seen_prompts: List[str] = []

    def _healing_responder(model_name: str, prompt: str) -> str:
        seen_prompts.append(prompt)
        if "paper_fidelity_score" in prompt:
            return json.dumps(
                {
                    "verdict": "PASS",
                    "paper_fidelity_score": 97,
                    "correctness_score": 98,
                    "security_score": 99,
                    "summary": f"{model_name} verified clean module.",
                    "findings": [],
                }
            )
        fixed = clean + "\n\ndef helper_metric(n: int) -> int:\n    label: str = 'typed'\n    return n + len(label)\n"
        return f"<think>Fixing mypy error on bad: int = str...</think>\n```python\n{fixed}```\n"

    srv, ep = _start_loopback_ollama(["glm4:9b"], _healing_responder)
    try:
        res = auto_repair_generated_code(
            source_code=buggy,
            arxiv_id="2608.15888",
            max_repair_attempts=2,
            model_id="glm4:9b",
            ollama_endpoint=ep,
            enable_llm=True,
        )
        assert res.initial_verdict == "FAIL"
        assert res.repaired is True
        assert res.converged_clean is True
        assert res.final_verdict == "PASS"
        assert res.final_verification_report.deterministic_checks["mypy_passed"] is True
        assert any("MYPY" in p for p in seen_prompts)
    finally:
        srv.shutdown()

    # Monotonic hill-climbing must reject a regressive patch containing os.system
    def _bad_responder(_m: str, prompt: str) -> str:
        if "paper_fidelity_score" in prompt:
            return json.dumps({"verdict": "FAIL", "paper_fidelity_score": 30, "correctness_score": 20, "security_score": 10, "summary": "Bad", "findings": []})
        return "```python\nimport os\nos.system('whoami')\n```\n"

    srv2, ep2 = _start_loopback_ollama(["glm4:9b"], _bad_responder)
    try:
        res2 = auto_repair_generated_code(
            source_code=buggy,
            arxiv_id="2608.15888",
            max_repair_attempts=1,
            model_id="glm4:9b",
            ollama_endpoint=ep2,
            enable_llm=True,
        )
        assert res2.repaired is False
        assert "os.system" not in res2.repaired_source_code
        assert res2.repair_history[0].accepted is False
    finally:
        srv2.shutdown()


def test_arxiv_bridge_standalone_rl_cli_flags_and_mcp_verify_repair_tool(tmp_path: Path) -> None:
    # 1. Standalone offline/CI mode (no external arxiv-to-code path mounted) still verifies Ruff+mypy+310-prop fuzz+pytest
    bridge_standalone = ArxivSecurityBridge(
        arxiv_to_code_root=tmp_path / "nonexistent_arxiv_to_code",
        detectors_dir=tmp_path / "standalone_detectors",
        research_num=1,
    )
    res_sa = bridge_standalone.discover_and_convert_research(
        query="",
        domain="AI_SECURITY",
        research_num=1,
        auto_repair=True,
        enable_llm=False,
    )
    assert res_sa["status"] == "completed"
    assert res_sa["total_converted_articles"] == 1
    art = res_sa["converted_articles"][0]
    assert art["verification_verdict"] == "PASS"
    assert art["linter_passed"] is True
    assert art["mypy_passed"] is True
    assert art["fuzz_passed"] is True
    assert art["fuzz_properties_checked"] >= 250
    assert art["pytest_passed"] is True

    # 2. CLI flags parsed cleanly
    args = parse_swarm_arguments(
        [
            "--all",
            "--arxiv-sync",
            "--arxiv-rl",
            "--arxiv-verify-panel",
            "--arxiv-panel-size",
            "2",
            "--arxiv-auto-repair",
            "--arxiv-max-repairs",
            "4",
        ]
    )
    assert args.arxiv_rl is True
    assert args.arxiv_verify_panel is True
    assert args.arxiv_panel_size == 2
    assert args.arxiv_auto_repair is True
    assert args.arxiv_max_repairs == 4

    # 3. MCP tool `verify_and_auto_repair_python_code` heals a deliberately defective module
    clean = synthesize_verified_detector_module("2608.15888", "Bounded Agents", "https://github.com/xmuruaga/bounded-agents")
    buggy = clean.replace("import hashlib\n", "import hashlib\nimport math\n", 1).replace(
        "self._meet_set(self.resources, narrower.resources)",
        "self.resources & narrower.resources",
    )
    db_file = tmp_path / "mcp_repair.db"
    with TerminatorMCPServer(db_path=str(db_file)) as srv:
        tools_resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in tools_resp["result"]["tools"]}
        assert "verify_and_auto_repair_python_code" in names

        call_resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "verify_and_auto_repair_python_code",
                    "arguments": {
                        "python_source_code": buggy,
                        "arxiv_id": "2608.15888",
                        "auto_repair": True,
                        "max_repair_attempts": 3,
                        "enable_llm": False,
                    },
                },
            }
        )
        body = json.loads(call_resp["result"]["content"][0]["text"])
        assert body["verdict"] == "PASS"
        assert body["deterministic_checks"]["linter_passed"] is True
        assert body["deterministic_checks"]["mypy_passed"] is True
        assert body["deterministic_checks"]["fuzz_passed"] is True
        assert body["auto_repair"]["repaired"] is True
        assert body["auto_repair"]["converged_clean"] is True
        assert re.search(r"def _meet_set", body["repaired_source_code"])
