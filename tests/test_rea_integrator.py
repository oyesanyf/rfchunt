"""
Verification Suite for Module 21 (`morluto/rea` Surface, Bundle & Electron Analyzer)
and Codebase-Wide Logic/Security Regression Fixes.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import struct
import subprocess
import threading
from typing import Dict, Tuple

import httpx
import pytest

from database import Database
from engine.advisory_exporter import AdvisoryExporter, neutralize_csv_cell
from engine.approval_gate import ApprovalGate
from engine.artex_bridge import TrafficCaptureSession
from engine.caldera_bridge import CalderaBridge
from engine.dual_graph_engine import DualGraphAttackEngine, NoiseGovernor
from engine.execution_policy import (
    ActionType,
    ExecutionPolicy,
    ScannerTask,
    StructuredIntentProposal,
)
from engine.live_executors import LiveWorkerExecutorRegistry
from engine.mantis_integrator import run_unified_all_scans
from engine.rea_integrator import ReaIntegrator, parse_asar_archive
from engine.secret_store import SecretBox
from engine.session_loader import AuthProfile, load_scope_file
from fusion_engine import FusionArbiter
from mcp_server import MCPHttpServer, TerminatorMCPServer
import ollama_manager


def _build_synthetic_asar(files_map: Dict[str, bytes]) -> bytes:
    """Constructs a valid Chromium Pickle `.asar` archive in memory."""
    tree: Dict[str, dict] = {"files": {}}
    chunks = []
    offset = 0
    for rel_path, content in files_map.items():
        parts = [p for p in rel_path.strip("/").split("/") if p]
        cur = tree["files"]
        for d in parts[:-1]:
            cur = cur.setdefault(d, {"files": {}})["files"]
        cur[parts[-1]] = {"size": len(content), "offset": str(offset)}
        chunks.append(content)
        offset += len(content)

    json_bytes = json.dumps(tree, separators=(",", ":")).encode("utf-8")
    json_len = len(json_bytes)
    aligned_json_len = (json_len + 3) & ~3
    padding = b"\x00" * (aligned_json_len - json_len)
    json_pickle_size = 4 + aligned_json_len
    header_total_size = 4 + json_pickle_size
    preamble = struct.pack("<IIII", 4, header_total_size, json_pickle_size, json_len)
    return preamble + json_bytes + padding + b"".join(chunks)


def test_asar_parser_electron_prefs_ipc_routes_and_header_cap(tmp_path: Path) -> None:
    asar_bytes = _build_synthetic_asar(
        {
            "package.json": json.dumps({"name": "demo-electron", "main": "src/main.js"}).encode("utf-8"),
            "src/main.js": (
                "const { app, BrowserWindow, ipcMain } = require('electron');\n"
                "const { execSync } = require('child_process');\n"
                "function createWin() {\n"
                "  new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\n"
                "}\n"
                "ipcMain.handle('sys:exec', async (event, cmd) => { return execSync(cmd); });\n"
            ).encode("utf-8"),
            "src/renderer.js": (
                "const cfg = { audience: 'api://end-user-spa', client_id: 'spa-1234', issuer: 'https://login.example.org' };\n"
                "fetch('/internal/service/dispatch', { method: 'POST' });\n"
                "axios.post('/api/v1/chat/completions', { prompt: 'hi' });\n"
            ).encode("utf-8"),
        }
    )
    asar_file = tmp_path / "app.asar"
    asar_file.write_bytes(asar_bytes)

    db = Database(":memory:")
    try:
        integrator = ReaIntegrator(db=db, reports_dir=tmp_path / "reports")
        res = integrator.analyze(target_path=asar_file, write_reports=True)
        assert res.status == "completed"
        rule_ids = {f.rule_id for f in res.findings}
        assert "REA-ELECTRON-003" in rule_ids
        assert "REA-IPC-002" in rule_ids
        assert "REA-ROUTE-001" in rule_ids
        assert "REA-AI-ENDPOINT-007" in rule_ids
        assert "REA-OIDC-005" in rule_ids

        routes = {ep["route"] for ep in res.discovered_endpoints}
        assert "/internal/service/dispatch" in routes
        assert "/api/v1/chat/completions" in routes
        assert len(res.ipc_channels) >= 1
        assert Path(res.report_files["sarif"]).is_file()

        persisted = db.get_rea_findings(limit=50)
        assert len(persisted) == len(res.findings)
    finally:
        db.close()

    # Oversized .asar header must fail closed without allocating huge memory
    bad_asar = tmp_path / "bomb.asar"
    bad_asar.write_bytes(struct.pack("<IIII", 4, 64 * 1024 * 1024, 64 * 1024 * 1024 - 4, 64 * 1024 * 1024 - 8) + b"{}")
    with pytest.raises(ValueError, match="exceeds safety cap"):
        parse_asar_archive(bad_asar)


def test_minified_bundle_noise_filtering_caps_and_dual_graph_chaining(tmp_path: Path) -> None:
    bundle_dir = tmp_path / "web"
    bundle_dir.mkdir()
    noisy_lines = [
        "const mimeA = '/application/json'; const assetA = '/static/css/main.css'; const img = '/logo.svg';",
        "const chunk = '/__webpack_hmr'; const font = '/fonts/inter.woff2';",
        "const openAiKey = 'sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';",
    ]
    for i in range(20):
        noisy_lines.append(f"fetch('/api/v1/item-{i}');")
    noisy_lines.append("axios.post('/internal/admin/override');")
    noisy_lines.append("axios.post('/api/chat');")
    (bundle_dir / "app.bundle.js").write_text("\n".join(noisy_lines), encoding="utf-8")

    smap = {
        "version": 3,
        "sources": ["src/auth.ts", "src/api.ts"],
        "sourcesContent": ["export const r = () => fetch('/service/worker/sync');"],
    }
    (bundle_dir / "app.bundle.js.map").write_text(json.dumps(smap), encoding="utf-8")

    integrator = ReaIntegrator(
        reports_dir=tmp_path / "reports",
        max_endpoints_per_bundle=8,
        max_findings_per_bundle=6,
    )
    res = integrator.analyze(target_path=bundle_dir, write_reports=False)
    routes = [ep["route"] for ep in res.discovered_endpoints]
    for noisy in ("/application/json", "/static/css/main.css", "/logo.svg", "/__webpack_hmr", "/fonts/inter.woff2"):
        assert noisy not in routes
    # Per-bundle cap enforced on app.bundle.js (8) + 1 from .map <= 9
    assert len(routes) <= 9
    assert any("Capped extracted routes" in lim for lim in res.limitations)

    # Hydrate into DualGraphAttackEngine and verify multi-hop correlation with a wire desync finding
    db = Database(":memory:")
    try:
        engine = DualGraphAttackEngine(db=db, reports_dir=str(tmp_path / "reports"))
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=8080,
            endpoints=[ep["route"] for ep in res.discovered_endpoints],
            ai_sinks=[s["route"] for s in res.ai_sinks] or ["/api/chat"],
        )
        for f in res.findings:
            engine.ingest_finding(f.to_dict(), scanner="Module-21-REA")
        engine.register_wire_primitive(
            anomaly_id="RULER-DESYNC-1",
            description="HTTP/1.1 CL.TE framing desync",
            anomaly_type="CL.TE",
            scanner="ProtocolRuler",
        )
        cycle = engine.run_attack_chain_cycle(round_num=1)
        assert cycle["candidates_planned"] >= 1
    finally:
        db.close()


def test_non_js_repo_fast_short_circuit(tmp_path: Path) -> None:
    py_repo = tmp_path / "pure_python"
    py_repo.mkdir()
    (py_repo / "server.py").write_text("def health():\n    return {'ok': True}\n", encoding="utf-8")
    (py_repo / "README.md").write_text("# Pure Python Service\n", encoding="utf-8")

    integrator = ReaIntegrator(reports_dir=tmp_path / "reports")
    res = integrator.analyze(target_path=py_repo, write_reports=True)
    assert res.status == "skipped_no_js_artifacts"
    assert res.findings == []
    assert res.report_files == {}


def test_live_same_origin_js_mining_and_ssrf_fail_closed(tmp_path: Path) -> None:
    class _SpaHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/":
                body = (
                    b'<html><head>'
                    b'<script src="/static/app.js"></script>'
                    b'<script src="https://cdn.evil.example/tracker.js"></script>'
                    b'</head><body>SPA</body></html>'
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/static/app.js":
                body = (
                    b"fetch('/internal/service/token-exchange', {method: 'POST'});\n"
                    b"axios.post('/api/v1/llm/generate', {prompt: 'test'});\n"
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SpaHandler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        db = Database(":memory:")
        try:
            session = TrafficCaptureSession(db=db, task_id="test-live-rea")
            integrator = ReaIntegrator(
                db=db,
                reports_dir=tmp_path / "reports",
                approval_gate=ApprovalGate(mode="policy", db=db),
                noise_governor=NoiseGovernor(profile="off"),
            )
            res = integrator.analyze(
                target_path=None,
                host="127.0.0.1",
                port=port,
                use_tls=False,
                authorized=True,
                traffic_session=session,
                write_reports=False,
            )
            assert res.status == "completed"
            routes = {ep["route"] for ep in res.discovered_endpoints}
            assert "/internal/service/token-exchange" in routes
            assert "/api/v1/llm/generate" in routes
            assert any("Skipped cross-origin script" in lim for lim in res.limitations)

            # Cloud metadata & unauthorized external hosts MUST fail closed
            with pytest.raises(PermissionError):
                integrator.analyze(target_path=None, host="169.254.169.254", port=80, authorized=True, write_reports=False)
            with pytest.raises(PermissionError):
                integrator.analyze(target_path=None, host="example.com", port=443, authorized=False, write_reports=False)
        finally:
            db.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_rea_execution_policy_confinement_and_cli_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = ExecutionPolicy.get_instance()
    # Native binary decompilers and disallowed rea subcommands MUST be blocked
    with pytest.raises(PermissionError):
        policy.validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.REA_SURFACE,
                action_type=ActionType.SUBPROCESS_EXEC,
                command_args=["ghidraRun", "target.exe"],
                rationale="Attempt binary decompiler",
            )
        )
    with pytest.raises(PermissionError):
        policy.validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.REA_SURFACE,
                action_type=ActionType.SUBPROCESS_EXEC,
                command_args=["rea", "analyze-binary", "app.exe"],
                rationale="Attempt disallowed binary subcommand",
            )
        )

    # Native PE/ELF binaries must be skipped safely by static collector
    bin_dir = tmp_path / "bins"
    bin_dir.mkdir()
    (bin_dir / "native.exe").write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    (bin_dir / "bundle.js").write_text("fetch('/internal/admin/audit');\n", encoding="utf-8")

    integrator = ReaIntegrator(reports_dir=tmp_path / "reports")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "0")
    fake_stdout = json.dumps(
        {
            "endpoints": [{"route": "/service/rea-cli-discovered", "method": "POST"}],
            "findings": [
                {
                    "rule_id": "REA-ROUTE-001",
                    "title": "CLI Discovered Route",
                    "severity": "MEDIUM",
                    "file_path": str(bin_dir / "bundle.js"),
                    "line_number": 1,
                }
            ],
        }
    )
    run_calls = []

    def _fake_silent_run(argv, **kwargs):
        run_calls.append((list(argv), dict(kwargs)))
        return subprocess.CompletedProcess(argv, 0, stdout=fake_stdout, stderr="")

    import engine.rea_integrator as rea_mod

    with monkeypatch.context() as mp:
        mp.setattr(integrator, "check_rea_cli_status", lambda: {"installed": True, "binary_path": "/usr/local/bin/rea"})
        mp.setattr(rea_mod, "silent_subprocess_run", _fake_silent_run)
        res = integrator.analyze(target_path=bin_dir, use_rea_cli=True, write_reports=False)
        assert res.mode == "hybrid"
        routes = {ep["route"] for ep in res.discovered_endpoints}
        assert "/internal/admin/audit" in routes
        assert "/service/rea-cli-discovered" in routes
        assert len(run_calls) == 1
        called_argv, called_kw = run_calls[0]
        assert called_argv[1] == "analyze-javascript-application"
        assert called_kw["shell"] is False


def test_unified_all_scans_and_mcp_rea_integration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    repo_dir = tmp_path / "fullstack_app"
    repo_dir.mkdir()
    (repo_dir / "frontend.js").write_text(
        "const k = 'sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';\n"
        "fetch('/internal/service/billing');\n",
        encoding="utf-8",
    )
    (repo_dir / "backend.py").write_text(
        "def run_route(token):\n"
        "    '/internal/service/billing'\n"
        "    claims = verify_oidc(token)\n"
        "    return claims\n",
        encoding="utf-8",
    )

    db = Database(":memory:")
    try:
        out = run_unified_all_scans(
            repo=str(repo_dir),
            depth=20,
            db=db,
            reports_dir=str(tmp_path / "reports"),
            quiet=True,
        )
        assert "rea_surface" in out["engines"]
        rea_summary = out["engines"]["rea_surface"]
        assert rea_summary["status"] == "completed"
        assert rea_summary["total_findings"] >= 2
        assert any(f.get("scanner") == "Module-21-REA" for f in out["findings"])

        # Verify MCP HTTP transport exposes rea_analyze_surface + enforces Origin & SSE session guards
        with TerminatorMCPServer(db_path=":memory:") as mcp_srv:
            http_srv = MCPHttpServer(mcp_srv, host="127.0.0.1", port=0, bearer_token="test-tok-123")
            host, port = http_srv.start()
            try:
                base = f"http://{host}:{port}"
                hdrs = {"Authorization": "Bearer test-tok-123"}

                # Cross-origin browser Origin header must be blocked (403)
                bad_origin = httpx.post(
                    f"{base}/http",
                    headers={**hdrs, "Origin": "https://evil.attacker.example"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )
                assert bad_origin.status_code == 403

                # Unknown SSE sessionId on /message must 404 BEFORE executing tool
                bad_sse = httpx.post(
                    f"{base}/message?sessionId=nonexistent",
                    headers=hdrs,
                    json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "rea_analyze_surface", "arguments": {"target_path": str(repo_dir)}}},
                )
                assert bad_sse.status_code == 404

                # Valid Streamable HTTP call to rea_analyze_surface
                ok_resp = httpx.post(
                    f"{base}/http",
                    headers=hdrs,
                    json={
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "rea_analyze_surface",
                            "arguments": {"target_path": str(repo_dir), "output_dir": str(tmp_path / "mcp_reports")},
                        },
                    },
                )
                assert ok_resp.status_code == 200
                rpc_data = json.loads(ok_resp.json()["result"]["content"][0]["text"])
                assert rpc_data["status"] == "completed"
                assert rpc_data["total_findings"] >= 2
            finally:
                http_srv.stop()
    finally:
        db.close()


def test_codebase_logic_bug_regressions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Embedding model exclusion + dynamic ensure_model_installed
    assert ollama_manager.is_embedding_model("embeddinggemma:latest") is True
    assert ollama_manager.is_embedding_model("nomic-embed-text:latest") is True
    assert ollama_manager.is_embedding_model("hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M") is False
    filtered = ollama_manager.filter_generative_tags(
        ["embeddinggemma:latest", "qwen2.5:7b", "fenkohq/foundation-sec-8b:latest"]
    )
    assert "embeddinggemma:latest" not in filtered
    assert "qwen2.5:7b" in filtered

    monkeypatch.setenv("RFCHUNT_OFFLINE", "0")
    monkeypatch.setenv("CI", "")
    with ollama_manager.OllamaLifecycleManager._lock:
        ollama_manager.OllamaLifecycleManager._failed_pulls.clear()
        ollama_manager.OllamaLifecycleManager._cached_by_endpoint.clear()
        ollama_manager.OllamaLifecycleManager._cached_tags.clear()
    pull_calls = []

    def _fake_pull_run(argv, **kwargs):
        pull_calls.append((list(argv), dict(kwargs)))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    with monkeypatch.context() as mp:
        mp.setattr(ollama_manager.OllamaLifecycleManager, "find_ollama_binary", staticmethod(lambda: "/usr/bin/ollama"))
        mp.setattr(ollama_manager.OllamaLifecycleManager, "probe_ollama", staticmethod(lambda *a, **kw: ["huihui_ai/foundation-sec-abliterated:8b"]))
        mp.setattr(ollama_manager.subprocess, "run", _fake_pull_run)
        pulled = ollama_manager.ensure_model_installed(
            "huihui_ai/foundation-sec-abliterated:8b",
            allow_in_tests=True,
        )
        assert pulled is True
        assert len(pull_calls) == 1
        called_cmd, called_kw = pull_calls[0]
        assert called_cmd == ["/usr/bin/ollama", "pull", "huihui_ai/foundation-sec-abliterated:8b"]
        assert called_kw.get("shell", False) is False

    # 2. FusionArbiter._parse_json(unwrap_lists=False) preserves {"intents": [...]} envelope
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    arbiter = FusionArbiter(quiet=True)
    try:
        parsed_env = arbiter._parse_json(
            '{"intents": [{"capability": "AUTH_BOUNDARY"}, {"capability": "DESYNC"}]}',
            unwrap_lists=False,
        )
        assert isinstance(parsed_env, list) and len(parsed_env) == 1
        assert len(parsed_env[0]["intents"]) == 2
    finally:
        arbiter.close()

    # 3. Database._seed_baseline_defensive_intelligence FK integrity on fresh DB
    db = Database(":memory:")
    try:
        db._seed_baseline_defensive_intelligence()
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM evaluations WHERE probe_id = 1")
        assert cur.fetchone()[0] >= 1
    finally:
        db.close()

    # 4. load_scope_file IPv6 handling & AuthProfile double-Bearer prevention
    scope_txt = tmp_path / "scope.txt"
    scope_txt.write_text("::1\n[2001:db8::1]:8443\napi.example.com.\n", encoding="utf-8")
    scope = load_scope_file(scope_txt)
    assert "::1" in scope["allow_hosts"]
    assert "2001:db8::1" in scope["allow_hosts"]
    assert "api.example.com" in scope["allow_hosts"]

    prof = AuthProfile(name="u", bearer_token="Bearer eyJhbGciOiJIUzI1NiJ9.test.sig")
    assert prof.build_headers()["Authorization"] == "Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"

    # 5. SecretBox 32-byte raw key ending with whitespace byte (0x0a)
    key_file = tmp_path / "raw32.key"
    raw_32 = b"A" * 31 + b"\n"
    key_file.write_bytes(raw_32)
    monkeypatch.delenv("ARTEX_SECRET_KEY", raising=False)
    box = SecretBox.from_env_or_keyfile(key_path=key_file)
    assert box is not None
    ct = box.encrypt_str("secret-payload")
    assert box.decrypt_str(ct) == "secret-payload"

    # 6. CSV formula neutralization (`|`, `\n`, leading tab) & GHSA Bearer redaction + backtick fence
    assert neutralize_csv_cell("|cmd").startswith("'")
    assert neutralize_csv_cell("\n=1+1").startswith("'")
    assert neutralize_csv_cell("\t=SUM(A1:A2)").startswith("'")
    md = AdvisoryExporter(reports_dir=tmp_path).export_ghsa_markdown(
        {
            "chain_id": "CH-1",
            "evidence_quote": "```injected```\nAuthorization: Bearer supersecret123456",
        }
    )
    assert "supersecret123456" not in md
    assert "Bearer <REDACTED>" in md
    assert "````text" in md

    # 7. CalderaBridge SecretBox decryption + SSRF URL guard
    import base64 as _b64

    monkeypatch.setenv("ARTEX_SECRET_KEY", _b64.b64encode(raw_32).decode("ascii"))
    disk_db_path = tmp_path / "caldera_test.db"
    disk_db = Database(str(disk_db_path))
    try:
        disk_db.save_attack_chain(
            chain_id="CHAIN-ENC-1",
            title="Encrypted Chain",
            attack_type="CL.TE_DESYNC",
            target_host="127.0.0.1:8080",
            target_endpoint="/smuggle",
            steps=[{"step": 1}],
            raw_payload="POST /smuggle HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            poe_level=3,
            is_verified=True,
        )
    finally:
        disk_db.close()

    bridge = CalderaBridge(db_path=str(disk_db_path))
    loaded_chains = bridge.fetch_attack_chains_from_db()
    assert len(loaded_chains) == 1
    assert loaded_chains[0]["raw_payload"].startswith("POST /smuggle")
    push_res = bridge.push_to_caldera("file:///etc/passwd", "KEY", abilities=[])
    assert push_res["errors"]

    # 8. Multi-turn string "confirmed": "false" & conjunctive multi-hop sink fail-closed
    class _StubArbiter:
        def arbitrate_structured_json(self, **kwargs):
            return {"action": "finish", "confirmed": "false", "evidence": "Not reproducible"}

    reg = LiveWorkerExecutorRegistry(host="127.0.0.1", port=9, authorized=True, arbiter=_StubArbiter())
    reg._check_confirmed_evidence = lambda *a, **kw: True  # type: ignore[method-assign]
    ok_mt, _, _, meta_mt = reg.execute_candidate_multiturn(
        {"capability_class": "AUTH_BOUNDARY", "target_route": "/internal"},
        max_turns=2,
    )
    assert ok_mt is False
    assert meta_mt["stop_reason"] == "finish_not_confirmed"
