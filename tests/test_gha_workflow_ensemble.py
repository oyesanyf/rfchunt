"""
Zero-Mock Integration Tests for RFCHunt GHA Security Ensemble (R1, R2, R3)
==========================================================================
Covers:
  - R1: All 7 GitHub Actions vulnerability classes + Actionlint parity + clean/mitigated YAML (0 high-sev FPs)
  - R1: Binary-present (`zizmor --format sarif`, `actionlint -format '{{json .}}'`) & binary-absent pure-Python parity
  - R2: `EnsembleConsensusVoter` cross-engine corroboration, multi-step attack chains, `--all --ensemble` (`--essemble`),
        `--embedded` (`--embeded`) offline in-process execution, CLI (`revenue_cli.py`), & MCP (`bugbounty_mcp_server.py`)
  - R3: Loopback Ollama `/api/tags` (<=400ms probe, abliterated security model selection, refusal fallback),
        `--model` / `RFCHUNT_LLM_MODEL`, `.env.local` `PaidModelClient`, graceful offline skip, and deterministic override immunity
  - OASIS SARIF 2.1.0 schema verification + self-audit of `D:\\harfile\\rfchunt\\.github\\workflows`
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bugbounty_mcp_server import BugBountyMCPServer
from engine.ensemble_orchestrator import (
    ENGINE_WEIGHTS,
    EngineFinding,
    EnsembleConsensusVoter,
    EnsembleOrchestrator,
)
from engine.gha_llm_verifier import (
    resolve_gha_llm_backend,
    select_preferred_ollama_security_model,
    verify_gha_findings_with_llm,
)
from engine.gha_workflow_scanners import (
    GHA_CLASS_AI_AGENT_BOUNDARY,
    GHA_CLASS_ARTIFACT_CACHE_POISONING,
    GHA_CLASS_ENV_PATH_INJECTION,
    GHA_CLASS_EXCESSIVE_PERMISSIONS,
    GHA_CLASS_PWN_REQUEST,
    GHA_CLASS_TEMPLATE_INJECTION,
    GHA_CLASS_UNPINNED_USES,
    discover_workflow_files,
    gha_findings_to_sarif,
    resolve_gha_scanner_binary,
    run_actionlint_scan,
    run_zizmor_scan,
)
from engine.ollama_concurrency_guard import OllamaConcurrencyGuard
from revenue_cli import maybe_dispatch_revenue_cli, run_revenue_cli


@pytest.fixture(autouse=True)
def _isolate_gha_ollama_guard(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    import engine.ollama_concurrency_guard as ocg

    monkeypatch.setenv("RFCHUNT_OLLAMA_LOCK_PATH", str(tmp_path / "gha_ollama_slot.lock"))
    ocg._SHARED_GUARD = None
    try:
        yield
    finally:
        ocg._SHARED_GUARD = None


def _assert_valid_sarif_210(sarif: Dict[str, Any], *, require_results: bool = False) -> None:
    assert sarif.get("version") == "2.1.0"
    assert "$schema" in sarif and "sarif-2.1.0" in sarif["$schema"]
    runs = sarif.get("runs")
    assert isinstance(runs, list) and len(runs) >= 1
    run0 = runs[0]
    driver = (run0.get("tool") or {}).get("driver") or {}
    assert driver.get("name")
    rules = driver.get("rules")
    assert isinstance(rules, list)
    results = run0.get("results")
    assert isinstance(results, list)
    if require_results:
        assert len(results) >= 1
        assert len(rules) >= 1
    rule_ids = {r.get("id") for r in rules}
    for res in results:
        assert res.get("ruleId") in rule_ids
        assert res.get("level") in ("error", "warning", "note", "none")
        locs = res.get("locations") or []
        assert len(locs) >= 1
        phys = locs[0].get("physicalLocation") or {}
        assert (phys.get("artifactLocation") or {}).get("uri")
        assert int((phys.get("region") or {}).get("startLine") or 0) >= 1


def _write_vulnerable_gha_repo(root: Path) -> Path:
    wf_dir = root / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)

    # Workflow 1: Multi-step pwn-request + script/template injection + unpinned/impostor uses + write-all + GITHUB_ENV + AI agent
    (wf_dir / "pr_agent_pipeline.yml").write_text(
        "name: Vulnerable PR Agent\n"
        "on:\n"
        "  pull_request_target:\n"
        "    types: [opened, synchronize]\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  triage:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - uses: some-org/impostor-action@1234567\n"
        "      - uses: other-org/pinned-mismatch@b4ffde65f46336ab88eb53be808477a3936bae11 # main\n"
        "      - name: Direct template injection\n"
        "        run: |\n"
        '          echo "Title: ${{ github.event.pull_request.title }}"\n'
        '          echo "DYLD=${{ github.event.pull_request.head.ref }}" >> "$GITHUB_ENV"\n'
        "          npm ci && npm test\n"
        "      - uses: actions/github-script@main\n"
        "        with:\n"
        "          script: |\n"
        '            const msg = "${{ github.event.pull_request.body }}";\n'
        "            console.log(msg);\n"
        "      - uses: actions/cache@v4\n"
        "        with:\n"
        "          path: ~/.npm\n"
        "          key: cache-${{ github.event.pull_request.title }}\n"
        "      - uses: anthropics/claude-code-action@v1\n"
        "        with:\n"
        "          prompt: ${{ github.event.pull_request.body }}\n"
        "        env:\n"
        "          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n"
        "      - uses: actions/upload-artifact@v4\n"
        "        with:\n"
        "          name: debug-out\n"
        "          path: .\n",
        encoding="utf-8",
    )

    # Workflow 2 & 3: Cross-workflow artifact poisoning (PR upload -> workflow_run download + exec) + structural needs error
    (wf_dir / "pr_build.yml").write_text(
        "name: PR Build\n"
        "on: [pull_request]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1\n"
        "      - uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3 # v4.3.1\n"
        "        with:\n"
        "          name: build-artifact\n"
        "          path: dist/\n",
        encoding="utf-8",
    )
    (wf_dir / "post_build.yml").write_text(
        "name: Post Build\n"
        "on:\n"
        "  workflow_run:\n"
        "    workflows: [PR Build]\n"
        "    types: [completed]\n"
        "jobs:\n"
        "  publish:\n"
        "    needs: nonexistent_job\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/download-artifact@v4\n"
        "        with:\n"
        "          name: build-artifact\n"
        "      - run: bash ./dist/deploy.sh\n",
        encoding="utf-8",
    )
    return wf_dir


# ---------------------------------------------------------------------------
# R1: All 7 Vulnerability Classes, Mitigated Clean YAML, & Binary/Fallback Parity
# ---------------------------------------------------------------------------


def test_r1_zizmor_and_actionlint_parity_cover_all_7_classes_and_line_numbers(tmp_path: Path) -> None:
    _write_vulnerable_gha_repo(tmp_path)

    z_res = run_zizmor_scan(tmp_path, embedded=True)
    a_res = run_actionlint_scan(tmp_path, embedded=True)

    assert z_res.execution_mode == "python_parity"
    assert a_res.execution_mode == "python_parity"
    assert z_res.files_scanned == 3
    assert a_res.files_scanned == 3

    z_classes = {f.gha_class for f in z_res.findings}
    assert {
        GHA_CLASS_PWN_REQUEST,
        GHA_CLASS_TEMPLATE_INJECTION,
        GHA_CLASS_UNPINNED_USES,
        GHA_CLASS_EXCESSIVE_PERMISSIONS,
        GHA_CLASS_ENV_PATH_INJECTION,
        GHA_CLASS_ARTIFACT_CACHE_POISONING,
        GHA_CLASS_AI_AGENT_BOUNDARY,
    }.issubset(z_classes)

    a_rules = {f.rule_id for f in a_res.findings}
    assert "ACTIONLINT-INVALID-NEEDS" in a_rules
    assert "ACTIONLINT-UNTRUSTED-CHECKOUT" in a_rules
    assert "ACTIONLINT-SHELL-INJECTION" in a_rules
    assert "ACTIONLINT-SCRIPT-INJECTION" in a_rules
    assert "ACTIONLINT-GITHUB-ENV-WRITE" in a_rules

    # Exact line number check (not stuck on line 1)
    assert any(f.line > 10 for f in z_res.findings)
    assert any(f.line > 10 for f in a_res.findings)

    sarif = gha_findings_to_sarif([*z_res.findings, *a_res.findings])
    _assert_valid_sarif_210(sarif, require_results=True)


def test_r1_clean_mitigated_workflow_has_zero_high_severity_false_positives(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "hardened.yml").write_text(
        "name: Hardened Production Workflow\n"
        "on:\n"
        "  pull_request:\n"
        "    branches: [main]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  verify:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - name: Safe env-bound PR title and output\n"
        "        env:\n"
        "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
        "          ISSUE_BODY: ${{ github.event.issue.body }}\n"
        "        run: |\n"
        '          printf "%s\\n" "$PR_TITLE"\n'
        '          echo "BUILD_STATUS=ok" >> "$GITHUB_OUTPUT"\n'
        "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1\n"
        "        env:\n"
        "          SAFE_TITLE: ${{ github.event.pull_request.title }}\n"
        "        with:\n"
        "          script: |\n"
        "            console.log(process.env.SAFE_TITLE);\n"
        "      - uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3 # v4.3.1\n"
        "        with:\n"
        "          name: test-results\n"
        "          path: reports/\n",
        encoding="utf-8",
    )

    z_res = run_zizmor_scan(tmp_path, embedded=True)
    a_res = run_actionlint_scan(tmp_path, embedded=True)

    high_crit = [f for f in [*z_res.findings, *a_res.findings] if f.severity.upper() in ("CRITICAL", "HIGH")]
    assert high_crit == [], f"Unexpected high-sev FP(s) on mitigated workflow: {high_crit}"
    # Also ensure zero unpinned/artipacked/template injection FPs even at MEDIUM
    assert not [f for f in z_res.findings if f.gha_class in (
        GHA_CLASS_PWN_REQUEST,
        GHA_CLASS_TEMPLATE_INJECTION,
        GHA_CLASS_UNPINNED_USES,
        GHA_CLASS_EXCESSIVE_PERMISSIONS,
        GHA_CLASS_ENV_PATH_INJECTION,
        GHA_CLASS_ARTIFACT_CACHE_POISONING,
    )]


def test_r1_binary_available_execution_and_fail_closed_shim_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_file.write_text(
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        '      - run: echo "${{ github.event.pull_request.title }}"\n',
        encoding="utf-8",
    )

    # 1. Fail-closed validation rejects script shims & cross-tool binaries
    shim_bat = tmp_path / "zizmor.bat"
    shim_bat.write_text("@echo off\n", encoding="utf-8")
    with pytest.raises(PermissionError):
        resolve_gha_scanner_binary("zizmor", binary_path=str(shim_bat))
    with pytest.raises(PermissionError):
        resolve_gha_scanner_binary("actionlint", binary_path="zizmor.exe")

    # 2. Simulate binaries present on PATH (like tests/test_external_scanners.py subprocess_recorder)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    z_bin = bin_dir / ("zizmor.exe" if os.name == "nt" else "zizmor")
    a_bin = bin_dir / ("actionlint.exe" if os.name == "nt" else "actionlint")
    z_bin.write_bytes(b"MZ")
    a_bin.write_bytes(b"MZ")

    monkeypatch.setenv("PATH", str(bin_dir))
    calls: List[List[str]] = []

    z_sarif_stdout = json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "zizmor",
                            "rules": [
                                {
                                    "id": "template-injection",
                                    "shortDescription": {"text": "Template injection in run block"},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "template-injection",
                            "level": "error",
                            "message": {"text": "untrusted github.event.pull_request.title"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": ".github/workflows/ci.yml"},
                                        "region": {"startLine": 9, "startColumn": 14},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )
    a_json_stdout = json.dumps(
        [
            {
                "kind": "expression",
                "message": "untrusted expression github.event.pull_request.title in shell",
                "filepath": ".github/workflows/ci.yml",
                "line": 9,
                "column": 14,
                "snippet": 'echo "${{ github.event.pull_request.title }}"',
            }
        ]
    )

    def _recorder(argv: Any, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        assert kwargs.get("shell", False) is False
        calls.append(list(argv))
        exe_name = Path(argv[0]).name.lower()
        if exe_name.startswith("zizmor"):
            return subprocess.CompletedProcess(argv, 12, stdout=z_sarif_stdout, stderr="")
        if exe_name.startswith("actionlint"):
            return subprocess.CompletedProcess(argv, 1, stdout=a_json_stdout, stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _recorder)

    z_bin_res = run_zizmor_scan(tmp_path, embedded=False)
    a_bin_res = run_actionlint_scan(tmp_path, embedded=False)

    assert z_bin_res.execution_mode == "binary"
    assert a_bin_res.execution_mode == "binary"
    assert len(calls) == 2
    assert any(f.gha_class == GHA_CLASS_TEMPLATE_INJECTION and f.line == 9 for f in z_bin_res.findings)
    assert any(f.gha_class == GHA_CLASS_TEMPLATE_INJECTION and f.line == 9 for f in a_bin_res.findings)

    # 3. With embedded=True, binary execution MUST be bypassed in favor of pure-Python parity
    calls.clear()
    z_emb = run_zizmor_scan(tmp_path, embedded=True)
    a_emb = run_actionlint_scan(tmp_path, embedded=True)
    assert len(calls) == 0
    assert z_emb.execution_mode == "python_parity"
    assert a_emb.execution_mode == "python_parity"
    assert any(f.gha_class == GHA_CLASS_TEMPLATE_INJECTION for f in z_emb.findings)
    assert any(f.gha_class == GHA_CLASS_TEMPLATE_INJECTION for f in a_emb.findings)


# ---------------------------------------------------------------------------
# R2: Ensemble Registration, Corroboration, Multi-Step Chains, --embedded / --embeded
# ---------------------------------------------------------------------------


def test_r2_ensemble_corroboration_attack_chains_and_embedded_cli_mcp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for eng in ("zizmor", "actionlint", "gha_agent", "gha_llm"):
        assert eng in ENGINE_WEIGHTS

    repo = tmp_path / "vuln_repo"
    _write_vulnerable_gha_repo(repo)
    # Remove external binaries from PATH to verify pure-Python embedded path
    monkeypatch.setenv("PATH", "")

    out_dir = tmp_path / "ens_out"
    sarif_explicit = tmp_path / "explicit.sarif"
    rc = run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(repo),
            "--all",
            "--essemble",
            "--embeded",
            "--gha-only",
            "--out",
            str(out_dir),
            "--sarif-out",
            str(sarif_explicit),
        ]
    )
    assert rc == 0
    assert sarif_explicit.is_file()
    sarif = json.loads(sarif_explicit.read_text(encoding="utf-8"))
    _assert_valid_sarif_210(sarif, require_results=True)

    rep_json = json.loads((out_dir / "ensemble_report.json").read_text(encoding="utf-8"))
    clusters = rep_json["clusters"]
    assert len(clusters) >= 3

    # Verify cross-engine corroboration (zizmor + actionlint + gha_agent) on template injection
    inj_clusters = [c for c in clusters if c.get("gha_class") == GHA_CLASS_TEMPLATE_INJECTION]
    assert len(inj_clusters) >= 1
    assert any(c["engine_count"] >= 2 and c["disposition"] == "ENSEMBLE_CORROBORATED_STATIC" for c in inj_clusters)

    # Verify multi-step attack chain correlation across pr_agent_pipeline.yml
    chained = [c for c in clusters if c.get("attack_chain_id")]
    assert len(chained) >= 2
    assert any(len(c.get("attack_chain_steps") or []) >= 2 for c in chained)

    # Verify `maybe_dispatch_revenue_cli` handles `rfc_hunt_swarm.py` flags (--all, --essemble, --embeded) without touching rfc_hunt_swarm.py
    capsys.readouterr()  # clear prior stdout from non-JSON CLI call
    out_dispatch = tmp_path / "dispatch_out"
    d_rc = maybe_dispatch_revenue_cli(
        [
            "--all",
            str(repo),
            "--essemble",
            "--embeded",
            "--gha-only",
            "--output-dir",
            str(out_dispatch),
            "--json",
        ]
    )
    assert d_rc == 0
    dispatch_payload = json.loads(capsys.readouterr().out)
    assert dispatch_payload["telemetry"]["embedded"] is True
    assert dispatch_payload["telemetry"]["gha_llm"]["status"] == "skipped_embedded"

    # Verify BugBountyMCPServer `bb_run_all_scan(embedded=True)` and `bb_gha_workflow_audit`
    mcp = BugBountyMCPServer()
    tools = {t["name"] for t in mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
    assert "bb_gha_workflow_audit" in tools

    mcp_all = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "bb_run_all_scan",
                "arguments": {
                    "target": str(repo),
                    "output_dir": str(tmp_path / "mcp_all_out"),
                    "ensemble": True,
                    "embedded": True,
                    "include_lean_verify": False,
                },
            },
        }
    )
    all_res = json.loads(mcp_all["result"]["content"][0]["text"])
    assert all_res["status"] == "completed"
    assert all_res["embedded"] is True
    assert all_res["total_clusters"] >= 3
    assert Path(all_res["sarif_path"]).is_file()

    mcp_gha = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "bb_gha_workflow_audit",
                "arguments": {
                    "target": str(repo),
                    "embedded": True,
                },
            },
        }
    )
    gha_res = json.loads(mcp_gha["result"]["content"][0]["text"])
    _assert_valid_sarif_210(gha_res["sarif"], require_results=True)


# ---------------------------------------------------------------------------
# R3: Loopback Ollama / Paid Model Selection, 400ms Probe, Offline Skip & Override Immunity
# ---------------------------------------------------------------------------


def _start_loopback_ollama_server(
    *,
    models: List[str],
    refuse_first_model: Optional[str] = None,
    sleep_on_tags_sec: float = 0.0,
) -> Tuple[ThreadingHTTPServer, str, List[Dict[str, Any]]]:
    requests_log: List[Dict[str, Any]] = []
    lock = threading.Lock()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if sleep_on_tags_sec > 0:
                time.sleep(sleep_on_tags_sec)
            if self.path.startswith("/api/tags"):
                body = json.dumps({"models": [{"name": m} for m in models]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
            req_json = json.loads(raw)
            with lock:
                requests_log.append({"path": self.path, "body": req_json})

            req_model = str(req_json.get("model") or "")
            if refuse_first_model and req_model == refuse_first_model:
                content = "I'm sorry, but I cannot assist with creating exploits."
            else:
                verdict_json = json.dumps(
                    {
                        "verdicts": [
                            {
                                "gha_class": "pwn_request",
                                "file_path": ".github/workflows/ci.yml",
                                "line": 7,
                                "confirmed": True,
                                "confidence": 0.91,
                                "severity": "CRITICAL",
                                "attack_chain_steps": [
                                    "pull_request_target trigger",
                                    "actions/checkout untrusted head sha",
                                    "npm test code execution",
                                ],
                                "recommended_fix": "Remove head ref checkout from pull_request_target.",
                            }
                        ],
                        "attack_chains": [
                            {
                                "title": "Pwn-request to secret exfiltration",
                                "gha_class": "pwn_request",
                                "file_path": ".github/workflows/ci.yml",
                                "line": 7,
                                "severity": "CRITICAL",
                                "steps": ["pull_request_target", "checkout head.sha", "npm test"],
                            }
                        ],
                    }
                )
                content = verdict_json

            if self.path.endswith("/v1/chat/completions"):
                resp_obj = {"choices": [{"message": {"role": "assistant", "content": content}}]}
            else:
                resp_obj = {"message": {"role": "assistant", "content": content}}
            out = json.dumps(resp_obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}", requests_log


def test_r3_ollama_abliterated_selection_override_and_400ms_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  t:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm test\n",
        encoding="utf-8",
    )

    # Isolate away from any local .env.local
    monkeypatch.setenv("RFCHUNT_ENV_LOCAL", str(tmp_path / "none.env.local"))
    monkeypatch.delenv("RFCHUNT_LLM_MODEL", raising=False)

    # 1. Model selection prioritizes security/abliterated model and excludes embedding models
    primary, fallbacks = select_preferred_ollama_security_model(
        [
            "nomic-embed-text:latest",
            "qwen2.5:7b",
            "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            "huihui_ai/foundation-sec-abliterated:8b",
        ],
        free_ram_gb=32.0,
    )
    assert primary == "huihui_ai/foundation-sec-abliterated:8b"
    assert "nomic-embed-text:latest" not in [primary, *fallbacks]

    from engine.ollama_concurrency_guard import OllamaConcurrencyGuard

    r3_guard = OllamaConcurrencyGuard(lock_path=tmp_path / "r3_guard.lock")

    # 2. Loopback Ollama server with refusal fallback -> rescues via abliterated model
    srv, url, reqs = _start_loopback_ollama_server(
        models=[
            "nomic-embed-text:latest",
            "qwen2.5:7b",
            "huihui_ai/foundation-sec-abliterated:8b",
        ],
        refuse_first_model="qwen2.5:7b",
    )
    try:
        # Auto-selection picks foundation-sec-abliterated directly
        llm_findings, tele = verify_gha_findings_with_llm(
            tmp_path, [], ollama_endpoint=url, guard=r3_guard
        )
        assert tele["status"] == "completed"
        assert tele["model"] == "huihui_ai/foundation-sec-abliterated:8b"
        assert len(llm_findings) >= 1
        assert all(f.engine == "gha_llm" and f.deterministic is False for f in llm_findings)

        # Verify nonce-fenced prompt sanitization was used
        user_msg = reqs[-1]["body"]["messages"][1]["content"]
        assert '<untrusted_data nonce="' in user_msg

        # Explicit RFCHUNT_LLM_MODEL="qwen2.5:7b" triggers refusal -> falls back to abliterated model
        monkeypatch.setenv("RFCHUNT_LLM_MODEL", "qwen2.5:7b")
        llm_fb, tele_fb = verify_gha_findings_with_llm(
            tmp_path, [], ollama_endpoint=url, guard=r3_guard
        )
        assert tele_fb["status"] == "completed"
        assert tele_fb["model"] == "huihui_ai/foundation-sec-abliterated:8b"
        assert len(llm_fb) >= 1

        # Explicit `--model` parameter overrides `RFCHUNT_LLM_MODEL`
        llm_ov, tele_ov = verify_gha_findings_with_llm(
            tmp_path,
            [],
            model="huihui_ai/foundation-sec-abliterated:8b",
            ollama_endpoint=url,
            guard=r3_guard,
        )
        assert tele_ov["model"] == "huihui_ai/foundation-sec-abliterated:8b"
        assert len(llm_ov) >= 1
    finally:
        srv.shutdown()
        srv.server_close()

    # 3. 400ms strict timeout on slow Ollama probe skips gracefully without blocking
    srv_slow, url_slow, _ = _start_loopback_ollama_server(models=["qwen2.5:7b"], sleep_on_tags_sec=1.2)
    try:
        t0 = time.monotonic()
        res_slow = resolve_gha_llm_backend(
            ollama_endpoint=url_slow, probe_timeout_sec=0.4, guard=r3_guard
        )
        elapsed = time.monotonic() - t0
        assert res_slow.status == "skipped_unreachable"
        assert elapsed < 1.0
    finally:
        srv_slow.shutdown()
        srv_slow.server_close()

    # 4. Unreachable closed loopback port skips gracefully with 0 findings
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    closed_port = sock.getsockname()[1]
    sock.close()
    res_dead, tele_dead = verify_gha_findings_with_llm(
        tmp_path, [], ollama_endpoint=f"http://127.0.0.1:{closed_port}", guard=r3_guard
    )
    assert res_dead == []
    assert tele_dead["status"] == "skipped_unreachable"


def test_r3_paid_model_env_local_and_deterministic_override_immunity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  t:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm test\n",
        encoding="utf-8",
    )

    srv, url, reqs = _start_loopback_ollama_server(models=["gpt-4o-mini"])
    try:
        env_local = tmp_path / ".env.local"
        env_local.write_text(
            f"OPENAI_API_KEY=loopback-secret-token-123456\n"
            f"OPENAI_MODEL=gpt-4o-mini\n"
            f"OPENAI_BASE_URL={url}/v1\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("RFCHUNT_ENV_LOCAL", str(env_local))
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")  # Loopback paid endpoint remains permitted

        paid_guard = OllamaConcurrencyGuard(lock_path=tmp_path / "r3_paid_guard.lock")
        llm_findings, tele = verify_gha_findings_with_llm(
            tmp_path, [], env_local_path=env_local, guard=paid_guard
        )
        assert tele["backend"] == "paid_api"
        assert tele["status"] == "completed"
        assert len(reqs) >= 1
        assert len(llm_findings) >= 1
    finally:
        srv.shutdown()
        srv.server_close()

    # Deterministic Override Immunity: LLM dissent (`confirmed=False`, `severity="LOW"`)
    # MUST NOT override or downgrade deterministic scanner confirmations (`zizmor`, `actionlint`, `gha_agent`)
    findings = [
        EngineFinding(
            engine="zizmor",
            title="Pwn Request in CI",
            file_path=".github/workflows/ci.yml",
            line=7,
            cwe="CWE-829",
            severity="CRITICAL",
            confidence=0.92,
            deterministic=True,
            confirmed=True,
            metadata={"gha_class": GHA_CLASS_PWN_REQUEST},
        ),
        EngineFinding(
            engine="actionlint",
            title="Untrusted Head Checkout",
            file_path=".github/workflows/ci.yml",
            line=8,
            cwe="CWE-829",
            severity="CRITICAL",
            confidence=0.88,
            deterministic=True,
            confirmed=True,
            metadata={"gha_class": GHA_CLASS_PWN_REQUEST},
        ),
        EngineFinding(
            engine="gha_llm",
            title="LLM Dissenting Claim",
            file_path=".github/workflows/ci.yml",
            line=7,
            cwe="CWE-829",
            severity="LOW",
            confidence=0.95,
            deterministic=False,
            confirmed=False,
            metadata={"gha_class": GHA_CLASS_PWN_REQUEST, "false_positive_reason": "Looks benign"},
        ),
    ]
    voter = EnsembleConsensusVoter(program="generic", quorum=2)
    clusters = voter.fuse(findings)
    assert len(clusters) == 1
    c = clusters[0]
    assert c.deterministic_override_protected is True
    assert c.llm_dissent_ignored is True
    assert c.severity == "CRITICAL"
    assert c.disposition == "ENSEMBLE_CORROBORATED_STATIC"
    assert c.engine_count == 2


def test_self_audit_rfchunt_github_workflows_embedded_sarif(tmp_path: Path) -> None:
    orch = EnsembleOrchestrator(
        program="generic",
        quorum=2,
        exhaustive_default=True,
        embedded=True,
        gha_only=True,
    )
    out_dir = tmp_path / "rfchunt_self_audit"
    rep = orch.run(REPO_ROOT, out_dir=out_dir)
    sarif = rep.to_sarif()
    _assert_valid_sarif_210(sarif, require_results=False)
    assert orch.last_telemetry["embedded"] is True
    assert orch.last_telemetry["gha_llm"]["status"] == "skipped_embedded"
    assert (out_dir / "ensemble_findings.sarif").is_file()


# ---------------------------------------------------------------------------
# Iteration 2 Regression Tests: Adversarial Bypasses, Zero-Subprocess Embedded,
# Explicit Ollama Override vs .env.local, & Non-Workflow Root YAML Filtering
# ---------------------------------------------------------------------------


def test_iter2_remediated_bypasses_and_fp_resistance(tmp_path: Path) -> None:
    from engine.gha_agent_auditor import audit_gha_workflows

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)

    # 1. Heredoc GITHUB_ENV injection with tainted env var + safe static heredoc
    (wf_dir / "heredoc.yml").write_text(
        "name: Heredoc Env\n"
        "on: [pull_request]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  env_job:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: heredoc_multiline_bypass\n"
        "        env:\n"
        "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
        "        run: |\n"
        '          cat << EOF >> "$GITHUB_ENV"\n'
        "          PR_VAR=$PR_TITLE\n"
        "          EOF\n"
        "      - name: safe_static_heredoc\n"
        "        run: |\n"
        "          cat << 'EOF' >> \"$GITHUB_ENV\"\n"
        "          FOO=bar\n"
        "          EOF\n",
        encoding="utf-8",
    )

    # 2. Wrapped ${{ format(...) / toJSON(...) / || }} expressions + safe env-bound wrapped expr
    (wf_dir / "wrappers.yml").write_text(
        "name: Wrapper Expressions\n"
        "on: [issue_comment]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  wrap:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ format(\'{0}\', github.event.comment.body) }}"\n'
        '      - run: echo "${{ github.event.comment.body || \'fallback\' }}"\n'
        "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1\n"
        "        with:\n"
        "          script: |\n"
        '            const x = "${{ toJSON(github.event.comment.body) }}";\n'
        "            console.log(x);\n"
        "      - name: Safe wrapped env binding\n"
        "        env:\n"
        "          SAFE_BODY: ${{ format('{0}', github.event.comment.body) }}\n"
        "        run: |\n"
        '          printf "%s\\n" "$SAFE_BODY"\n',
        encoding="utf-8",
    )

    # 3. Fork checkout via `with.repository` without `with.ref` under pull_request_target
    (wf_dir / "fork_repo.yml").write_text(
        "name: Fork Repo No Ref\n"
        "on: pull_request_target\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1\n"
        "        with:\n"
        "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
        "          persist-credentials: false\n"
        "      - run: npm test\n",
        encoding="utf-8",
    )

    # 4. Impostor commit comments (# vercel/checkout, # tag: main) vs clean (# v4.1.1, # v4)
    (wf_dir / "impostor.yml").write_text(
        "name: Impostor Comments\n"
        "on: [push]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  pins:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # vercel/checkout\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # tag: main\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4\n"
        "        with:\n"
        "          persist-credentials: false\n",
        encoding="utf-8",
    )

    # 5. Multiline restore-keys broad prefix + benign download-artifact echo + CodeQL permissions
    (wf_dir / "cache_and_benign.yml").write_text(
        "name: Multiline Cache And Benign Artifact\n"
        "on:\n"
        "  workflow_run:\n"
        "    workflows: [CI]\n"
        "    types: [completed]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  check:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8\n"
        "        with:\n"
        "          name: metadata\n"
        '      - run: echo "done"\n',
        encoding="utf-8",
    )
    (wf_dir / "cache_only.yml").write_text(
        "name: Multiline Cache\n"
        "on: [push]\n"
        "permissions:\n"
        "  contents: read\n"
        "  security-events: write\n"
        "jobs:\n"
        "  cache:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf96b4f5e # v4.0.2\n"
        "        with:\n"
        "          path: ~/.cache/pip\n"
        "          key: ${{ runner.os }}-py-${{ hashFiles('requirements.txt') }}\n"
        "          restore-keys: |\n"
        "            python-cache-v1-\n"
        "            py-\n",
        encoding="utf-8",
    )

    z_heredoc = run_zizmor_scan(wf_dir / "heredoc.yml", embedded=True).findings
    a_heredoc = run_actionlint_scan(wf_dir / "heredoc.yml", embedded=True).findings
    g_heredoc = audit_gha_workflows(wf_dir / "heredoc.yml")
    assert any(f.gha_class == GHA_CLASS_ENV_PATH_INJECTION and f.line == 12 for f in z_heredoc)
    assert any(f.gha_class == GHA_CLASS_ENV_PATH_INJECTION and f.line == 12 for f in a_heredoc)
    assert any(f.gha_class == GHA_CLASS_ENV_PATH_INJECTION and f.line == 12 for f in g_heredoc)
    assert not any(f.line >= 16 for f in z_heredoc)

    z_wrap = run_zizmor_scan(wf_dir / "wrappers.yml", embedded=True).findings
    a_wrap = run_actionlint_scan(wf_dir / "wrappers.yml", embedded=True).findings
    g_wrap = audit_gha_workflows(wf_dir / "wrappers.yml")
    for list_f in (z_wrap, a_wrap, g_wrap):
        lines_hit = {f.line for f in list_f if f.gha_class == GHA_CLASS_TEMPLATE_INJECTION}
        assert {8, 9, 13}.issubset(lines_hit), f"Expected lines {{8, 9, 13}}, got {lines_hit}"
        assert not any(f.line >= 15 for f in list_f)

    z_fork = run_zizmor_scan(wf_dir / "fork_repo.yml", embedded=True).findings
    a_fork = run_actionlint_scan(wf_dir / "fork_repo.yml", embedded=True).findings
    g_fork = audit_gha_workflows(wf_dir / "fork_repo.yml")
    assert any(f.gha_class == GHA_CLASS_PWN_REQUEST for f in z_fork)
    assert any(f.gha_class == GHA_CLASS_PWN_REQUEST for f in a_fork)
    assert any(f.gha_class == GHA_CLASS_PWN_REQUEST for f in g_fork)

    z_imp = run_zizmor_scan(wf_dir / "impostor.yml", embedded=True).findings
    a_imp = run_actionlint_scan(wf_dir / "impostor.yml", embedded=True).findings
    g_imp = audit_gha_workflows(wf_dir / "impostor.yml")
    for list_f in (z_imp, a_imp, g_imp):
        imp_lines = sorted(f.line for f in list_f if f.gha_class == GHA_CLASS_UNPINNED_USES)
        assert imp_lines == [8, 11], f"Expected only impostor lines [8, 11], got {imp_lines}"

    z_cache = run_zizmor_scan(wf_dir / "cache_only.yml", embedded=True).findings
    assert any(f.rule_id == "ZIZMOR-PY-CACHE-BROAD-RESTORE" and "py-" in f.snippet for f in z_cache)
    assert not any(f.gha_class == GHA_CLASS_EXCESSIVE_PERMISSIONS for f in z_cache)

    z_benign_art = run_zizmor_scan(wf_dir / "cache_and_benign.yml", embedded=True).findings
    assert not any(f.rule_id == "ZIZMOR-PY-ARTIFACT-POISONING" for f in z_benign_art)


def test_iter2_root_non_workflow_yaml_filtered_from_discovery(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_file.write_text(
        "on: [push]\npermissions: read-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        encoding="utf-8",
    )
    # Non-workflow root YAML files must NOT be returned by discover_workflow_files()
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  api:\n    image: python:3.12-slim\n    ports:\n      - '8000:8000'\n",
        encoding="utf-8",
    )
    (tmp_path / "config.yaml").write_text("version: 1\nfeatures:\n  enabled: true\n", encoding="utf-8")

    _root, files = discover_workflow_files(tmp_path)
    names = [p.name for p in files]
    assert names == ["ci.yml"]


def test_iter2_embedded_mode_spawns_zero_subprocesses_with_normal_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Initialize a real git repo on disk with normal PATH intact
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm test\n",
        encoding="utf-8",
    )

    spawned: List[List[str]] = []
    orig_popen = subprocess.Popen

    def _fail_popen(args: Any, *a: Any, **kw: Any) -> Any:
        spawned.append(list(args) if isinstance(args, (list, tuple)) else [str(args)])
        raise AssertionError(f"Unexpected subprocess in embedded=True mode: {args!r}")

    monkeypatch.setattr(subprocess, "Popen", _fail_popen)
    try:
        orch = EnsembleOrchestrator(program="generic", quorum=2, embedded=True, gha_only=False)
        rep = orch.run(tmp_path, out_dir=tmp_path / "emb_out")
    finally:
        monkeypatch.setattr(subprocess, "Popen", orig_popen)

    assert spawned == []
    assert rep.freshness.freshness_status == "EMBEDDED_OFFLINE"
    assert rep.freshness.is_git_repo is False
    assert len(rep.clusters) >= 1
    assert orch.last_telemetry["embedded"] is True


def test_iter2_explicit_ollama_model_bypasses_paid_env_local(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  t:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm test\n",
        encoding="utf-8",
    )

    paid_srv, paid_url, paid_reqs = _start_loopback_ollama_server(models=["gpt-4o-mini"])
    ollama_srv, ollama_url, ollama_reqs = _start_loopback_ollama_server(
        models=["huihui_ai/foundation-sec-abliterated:8b", "llama3:8b"]
    )
    try:
        env_local = tmp_path / ".env.local"
        env_local.write_text(
            f"OPENAI_API_KEY=loopback-secret-token-123456\n"
            f"OPENAI_MODEL=gpt-4o-mini\n"
            f"OPENAI_BASE_URL={paid_url}/v1\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("RFCHUNT_ENV_LOCAL", str(env_local))
        monkeypatch.setenv("RFCHUNT_OFFLINE", "1")

        iter2_guard = OllamaConcurrencyGuard(lock_path=tmp_path / "iter2_guard.lock")

        # 1. Explicit Ollama tag bypasses `.env.local` paid config and uses Ollama
        findings_ov, tele_ov = verify_gha_findings_with_llm(
            tmp_path,
            [],
            model="huihui_ai/foundation-sec-abliterated:8b",
            ollama_endpoint=ollama_url,
            env_local_path=env_local,
            guard=iter2_guard,
        )
        assert tele_ov["backend"] == "ollama"
        assert tele_ov["status"] == "completed"
        assert tele_ov["model"] == "huihui_ai/foundation-sec-abliterated:8b"
        assert len(ollama_reqs) >= 1
        assert len(paid_reqs) == 0
        assert len(findings_ov) >= 1

        # 2. Generic `name:tag` Ollama model via RFCHUNT_LLM_MODEL also bypasses `.env.local`
        monkeypatch.setenv("RFCHUNT_LLM_MODEL", "llama3:8b")
        findings_env, tele_env = verify_gha_findings_with_llm(
            tmp_path,
            [],
            ollama_endpoint=ollama_url,
            env_local_path=env_local,
            guard=iter2_guard,
        )
        assert tele_env["backend"] == "ollama"
        assert tele_env["model"] == "llama3:8b"
        assert len(paid_reqs) == 0
        assert len(findings_env) >= 1

        # 3. Explicit paid model still routes to paid_api
        monkeypatch.delenv("RFCHUNT_LLM_MODEL", raising=False)
        findings_paid, tele_paid = verify_gha_findings_with_llm(
            tmp_path,
            [],
            model="gpt-4o-mini",
            ollama_endpoint=ollama_url,
            env_local_path=env_local,
            guard=iter2_guard,
        )
        assert tele_paid["backend"] == "paid_api"
        assert tele_paid["model"] == "gpt-4o-mini"
        assert len(paid_reqs) >= 1
        assert len(findings_paid) >= 1
    finally:
        paid_srv.shutdown()
        paid_srv.server_close()
        ollama_srv.shutdown()
        ollama_srv.server_close()


def test_iter2_revenue_cli_swarm_dry_run_and_no_external_scanners(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = maybe_dispatch_revenue_cli(
        [
            "--all",
            "--db",
            str(tmp_path / "swarm.db"),
            "--repo",
            str(tmp_path),
            "--essemble",
            "--no-external-scanners",
            "--no-preflight-live",
            "--no-include-models",
            "--no-auto-install",
            "--dry-run",
            "--json",
        ]
    )
    assert rc == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["status"] == "dry_run_plan_ready"
    assert plan["dry_run"] is True
    assert plan["side_effects"]["network_packets_sent"] == 0
    assert plan["side_effects"]["filesystem_mutations"] == 0
    assert plan["side_effects"]["browser_launched"] is False
    assert "--no-external-scanners" in plan["argv"]
    assert plan["argv"][plan["argv"].index("--target") + 1] == str(tmp_path)
