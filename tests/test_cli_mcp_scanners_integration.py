"""
Offline M4 Unit & Integration Tests: CLI, `--all`, & MCP Integration
====================================================================
Covers Features F11 (`--all` pipeline integration), F12 (standalone CLI
subcommands, flags, and pure-CLI rendering), and F13 (MCP server tools,
handlers, target authorization, approval gates, and JSON-RPC error mapping),
plus minimal M3 §3 DualGraph caveat fixes.

Runs strictly offline (`CI=true`, `RFCHUNT_OFFLINE=1`) using ephemeral loopback
servers, isolated SQLite databases, and `subprocess.run` interception.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
from typing import Any, Dict, Iterator, List
import uuid

import pytest

from database import Database
from engine.approval_gate import ApprovalGate
from engine.dual_graph_engine import DualGraphAttackEngine, derive_capability_class
from engine.execution_policy import ExecutionPolicy
from engine.mantis_integrator import run_unified_all_scans
from mcp_server import MCPHttpServer, TargetAuthorizationGate, TerminatorMCPServer


_TEST_HEX_KEY = "0123456789abcdef" * 4


@pytest.fixture(autouse=True)
def _reset_env_and_singletons(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    orig_targets = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    orig_history = {k: list(v) for k, v in TargetAuthorizationGate._request_history.items()}
    ExecutionPolicy.reset_instance()
    TargetAuthorizationGate.ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}
    TargetAuthorizationGate._request_history.clear()
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    monkeypatch.delenv("RFCHUNT_ALLOW_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("RFCHUNT_AUTHORIZED_TARGETS", raising=False)
    try:
        yield
    finally:
        ExecutionPolicy.reset_instance()
        TargetAuthorizationGate.ALLOWED_TARGETS = orig_targets
        TargetAuthorizationGate._request_history.clear()
        for k, hist in orig_history.items():
            TargetAuthorizationGate._request_history[k] = hist


@pytest.fixture
def isolated_db(tmp_path: Path) -> Iterator[Database]:
    db_path = tmp_path / f"m4_{uuid.uuid4().hex[:8]}.db"
    db = Database(str(db_path), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def loopback_server() -> Iterator[SimpleNamespace]:
    req_lock = threading.Lock()
    requests_log: List[Dict[str, Any]] = []

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self, method: str) -> None:
            raw_len = self.headers.get("Content-Length") or "0"
            body = self.rfile.read(int(raw_len)).decode("utf-8", errors="replace") if int(raw_len) > 0 else ""
            with req_lock:
                requests_log.append({"method": method, "path": self.path, "body": body})
            clean_path = self.path.split("?", 1)[0]
            if clean_path in ("/", "/health", "/api/public"):
                self._send(200, json.dumps({"ok": True, "path": clean_path}).encode("utf-8"))
                return
            if clean_path == "/api/admin":
                auth_h = self.headers.get("Authorization", "")
                if not auth_h.startswith("Bearer ") or not auth_h[7:].strip():
                    self._send(401, json.dumps({"error": "unauthorized"}).encode("utf-8"))
                    return
                self._send(200, json.dumps({"admin": True}).encode("utf-8"))
                return
            if clean_path == "/api/ai/chat":
                self._send(200, json.dumps({"reply": "ok"}).encode("utf-8"))
                return
            self._send(404, json.dumps({"error": "not_found"}).encode("utf-8"))

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    ns = SimpleNamespace(
        host=str(host),
        port=int(port),
        url=f"http://{host}:{port}",
        requests=requests_log,
        reset=lambda: requests_log.clear(),
    )
    try:
        yield ns
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def subprocess_recorder(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    calls: List[Dict[str, Any]] = []
    responses: Dict[str, Any] = {}

    def _norm(tok: str) -> str:
        name = Path(str(tok).replace("\\", "/")).name.lower()
        return name[:-4] if name.endswith(".exe") else name

    def set_response(binary: str, *, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        responses[_norm(binary)] = {"returncode": returncode, "stdout": stdout, "stderr": stderr}

    def _fake_run(args: Any, *pos: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        assert kwargs.get("shell", False) is False
        assert isinstance(args, list) and len(args) >= 1
        calls.append({"argv": list(args), "shell": kwargs.get("shell", False), "kwargs": dict(kwargs)})
        key = _norm(args[0])
        resp = responses.get(key)
        if resp is None and key == "docker":
            for tok in args[1:]:
                t_norm = _norm(str(tok).split(":")[0])
                if t_norm in responses:
                    resp = responses[t_norm]
                    break
        if resp is None:
            resp = {"returncode": 0, "stdout": "", "stderr": ""}
        return subprocess.CompletedProcess(args=list(args), returncode=resp["returncode"], stdout=resp["stdout"], stderr=resp["stderr"])

    monkeypatch.setattr(subprocess, "run", _fake_run)
    return SimpleNamespace(calls=calls, set_response=set_response)


# =============================================================================
# DualGraph M3 §3 Caveat Fixes
# =============================================================================


def test_derive_capability_class_sca_word_boundary_does_not_match_scan() -> None:
    assert derive_capability_class(
        {"rule_id": "exposed-admin-docker", "title": "Exposed Admin Docker Scan", "category": "exposure"},
        scanner="nuclei",
    ) != "SUPPLY_CHAIN"
    assert derive_capability_class(
        {"rule_id": "SCA-001", "title": "SCA Dependency Issue", "category": "sca"},
        scanner="raptor",
    ) == "SUPPLY_CHAIN"


def test_dual_graph_ingest_finding_handles_non_numeric_port_attribute(isolated_db: Database, tmp_path: Path) -> None:
    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=str(tmp_path / "rep"))
    eng.asset_graph.add_asset(
        "ASSET-EP-NONNUM",
        "ENDPOINT",
        "GET /api/public",
        {"route": "/api/public", "host": "127.0.0.1", "port": "unknown", "method": "GET"},
    )
    node = eng.ingest_finding(
        {
            "rule_id": "MANTIS-AUTH-011",
            "title": "Service route audience bypass",
            "cwe": "CWE-285",
            "route": "/api/admin",
            "capability_class": "AUTH_BOUNDARY",
        },
        scanner="nuclei",
    )
    assert node is not None


# =============================================================================
# Feature F11: --all Pipeline Integration
# =============================================================================


def test_run_unified_all_scans_default_skips_external_scanners(
    isolated_db: Database, subprocess_recorder: SimpleNamespace, tmp_path: Path
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    res = run_unified_all_scans(
        repo=str(repo_dir),
        db=isolated_db,
        reports_dir=str(tmp_path / "rep_def"),
        quiet=True,
    )
    assert res["engines"]["external_discovery"]["status"] == "disabled"
    assert res["engines"]["external_nuclei"]["status"] == "disabled"
    assert len(subprocess_recorder.calls) == 0


def test_run_unified_all_scans_opt_in_scanners_and_asset_preservation(
    isolated_db: Database,
    subprocess_recorder: SimpleNamespace,
    loopback_server: SimpleNamespace,
    tmp_path: Path,
) -> None:
    subprocess_recorder.set_response(
        "httpx",
        stdout=json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200, "tech": ["FastAPI"]}) + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        stdout=json.dumps({"request": {"method": "POST", "endpoint": f"{loopback_server.url}/api/ai/chat"}}) + "\n",
    )
    subprocess_recorder.set_response(
        "nuclei",
        stdout=json.dumps(
            {
                "template-id": "exposed-admin-route",
                "info": {"name": "Exposed Admin Route", "severity": "high", "tags": ["exposure"]},
                "matched-at": f"{loopback_server.url}/api/admin",
                "host": loopback_server.host,
            }
        )
        + "\n",
    )

    res = run_unified_all_scans(
        host=loopback_server.host,
        port=loopback_server.port,
        use_tls=False,
        authorized=True,
        db=isolated_db,
        reports_dir=str(tmp_path / "rep_opt"),
        enable_external_scanners=True,
        nuclei_tags="exposure,tech",
        scanner_isolation="host",
        artex_live=True,
        artex_multiturn=True,
        artex_intent_turns=2,
        artex_intent_tokens=3000,
        quiet=True,
    )
    assert res["engines"]["external_discovery"]["status"] == "completed"
    assert res["engines"]["external_nuclei"]["total_findings"] == 1
    assert res["engines"]["artex_dual_graph"]["multiturn_enabled"] is True
    assert len(subprocess_recorder.calls) == 3
    assert all(c["shell"] is False and "-rl" in c["argv"] for c in subprocess_recorder.calls)

    sarif_txt = Path(res["report_files"]["combined_sarif"]).read_text(encoding="utf-8")
    assert "exposed-admin-route" in sarif_txt
    asset_nodes = isolated_db.get_dual_graph_nodes(graph_type="ASSET")
    ai_sinks = [n for n in asset_nodes if n.get("node_type") == "AI_SINK"]
    assert any("/api/ai/chat" in json.dumps(n) for n in ai_sinks)
    assert not any("llm_prompt_sink" in json.dumps(n) for n in ai_sinks)


def test_run_unified_all_scans_per_scanner_toggles_and_fail_closed_validation(
    isolated_db: Database,
    subprocess_recorder: SimpleNamespace,
    loopback_server: SimpleNamespace,
    tmp_path: Path,
) -> None:
    subprocess_recorder.set_response(
        "httpx",
        stdout=json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200}) + "\n",
    )
    res = run_unified_all_scans(
        host=loopback_server.host,
        port=loopback_server.port,
        use_tls=False,
        authorized=True,
        db=isolated_db,
        reports_dir=str(tmp_path / "rep_hx"),
        enable_external_scanners=True,
        httpx_scan=True,
        katana_scan=False,
        nuclei_scan=False,
        quiet=True,
    )
    invoked = [Path(c["argv"][0]).name.lower() for c in subprocess_recorder.calls]
    assert any(b.startswith("httpx") for b in invoked)
    assert not any(b.startswith(("katana", "nuclei")) for b in invoked)
    assert res["engines"]["external_nuclei"]["status"] == "disabled"

    subprocess_recorder.calls.clear()
    with pytest.raises(ValueError):
        run_unified_all_scans(
            host=loopback_server.host,
            port=loopback_server.port,
            use_tls=False,
            authorized=True,
            db=isolated_db,
            reports_dir=str(tmp_path / "rep_neg_turns"),
            artex_intent_turns=-1,
            quiet=True,
        )
    with pytest.raises(ValueError):
        run_unified_all_scans(
            host=loopback_server.host,
            port=loopback_server.port,
            use_tls=False,
            authorized=True,
            db=isolated_db,
            reports_dir=str(tmp_path / "rep_bad_tags"),
            enable_external_scanners=True,
            nuclei_tags="rce",
            quiet=True,
        )
    with pytest.raises(ValueError):
        run_unified_all_scans(
            host=loopback_server.host,
            port=loopback_server.port,
            use_tls=False,
            authorized=True,
            db=isolated_db,
            reports_dir=str(tmp_path / "rep_bad_iso"),
            enable_external_scanners=True,
            scanner_isolation="podman",
            quiet=True,
        )
    with pytest.raises(PermissionError):
        run_unified_all_scans(
            host=loopback_server.host,
            port=loopback_server.port,
            use_tls=False,
            authorized=True,
            db=isolated_db,
            reports_dir=str(tmp_path / "rep_deny"),
            enable_external_scanners=True,
            approval_mode="deny",
            quiet=True,
        )
    assert len(subprocess_recorder.calls) == 0


# =============================================================================
# Feature F12: Standalone CLI Subcommands & Rendering
# =============================================================================


def test_cli_scanner_disabled_enabled_plain_and_approval_deny(
    monkeypatch: pytest.MonkeyPatch,
    subprocess_recorder: SimpleNamespace,
    loopback_server: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import main as main_mod

    db_file = tmp_path / "cli_scan.db"
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--db", str(db_file), "scanner", "--host", loopback_server.host, "--port", str(loopback_server.port), "--authorized", "--json"],
    )
    main_mod.main()
    dis_out = json.loads(capsys.readouterr().out)
    assert dis_out["status"] == "disabled"
    assert dis_out["scans_run"] == 0
    assert len(subprocess_recorder.calls) == 0

    subprocess_recorder.set_response(
        "httpx",
        stdout=json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200}) + "\n",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--db",
            str(db_file),
            "scanner",
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
            "--httpx-scan",
            "--json",
        ],
    )
    main_mod.main()
    en_out = json.loads(capsys.readouterr().out)
    assert en_out["status"] == "completed"
    assert en_out["scans_run"] == 1
    assert any("/api/public" in ep for ep in en_out["endpoints"])

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--db",
            str(db_file),
            "scanner",
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
            "--httpx-scan",
            "--plain",
        ],
    )
    main_mod.main()
    plain_out = capsys.readouterr().out
    assert "\x1b[" not in plain_out
    assert "External Scanners Summary" in plain_out
    assert "tkinter" not in sys.modules

    before = len(subprocess_recorder.calls)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--db",
            str(db_file),
            "scanner",
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
            "--enable-external-scanners",
            "--approval-mode",
            "deny",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code != 0
    assert len(subprocess_recorder.calls) == before
    check_db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        assert any(d.get("decision") == "DENY" for d in check_db.get_approval_decisions())
    finally:
        check_db.close()


def test_cli_artex_loop_and_swarm_delegation_parity(
    monkeypatch: pytest.MonkeyPatch,
    subprocess_recorder: SimpleNamespace,
    loopback_server: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import main as main_mod
    import rfc_hunt_swarm as swarm_mod

    db_file = tmp_path / "swarm_del.db"
    subprocess_recorder.set_response(
        "httpx",
        stdout=json.dumps({"url": f"{loopback_server.url}/health", "status_code": 200}) + "\n",
    )
    swarm_mod.main_swarm(
        [
            "scanner",
            "--db",
            str(db_file),
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
            "--httpx-scan",
            "--json",
        ]
    )
    scan_json = json.loads(capsys.readouterr().out)
    assert scan_json["status"] == "completed"

    loopback_server.reset()
    swarm_mod.main_swarm(
        [
            "artex-loop",
            "--db",
            str(db_file),
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
            "--artex-intent-turns",
            "0",
            "--output-dir",
            str(tmp_path / "rep_loop"),
            "--json",
        ]
    )
    loop_json = json.loads(capsys.readouterr().out)
    assert loop_json["result"]["task_id"]
    assert len(loopback_server.requests) >= 1

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--db",
            str(db_file),
            "artex-loop",
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
            "--artex-intent-turns",
            "-2",
        ],
    )
    with pytest.raises(SystemExit) as neg_exc:
        main_mod.main()
    assert neg_exc.value.code != 0


# =============================================================================
# Feature F13: MCP Server Tools & Handlers
# =============================================================================


def test_mcp_tools_list_and_excluded_scanners_blocked(
    subprocess_recorder: SimpleNamespace, tmp_path: Path
) -> None:
    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_tools.db")) as srv:
        resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        for expected in (
            "external_httpx_discover",
            "external_katana_crawl",
            "external_nuclei_scan",
            "artex_run_multiturn_worker",
        ):
            assert expected in tools
        assert "artex_multiturn" in tools["run_all_scans"]["inputSchema"]["properties"]
        assert "multiturn" in tools["artex_run_attack_chain"]["inputSchema"]["properties"]

        for excluded in ("nmap", "ffuf", "dalfox", "sqlmap"):
            r_ex = srv.handle_request(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": excluded, "arguments": {}}}
            )
            assert r_ex["error"]["code"] == -32602
    assert len(subprocess_recorder.calls) == 0


def test_mcp_validation_errors_and_shell_rejection(
    subprocess_recorder: SimpleNamespace, loopback_server: SimpleNamespace, tmp_path: Path
) -> None:
    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_val.db")) as srv:
        bad_requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "not-a-dict"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "external_httpx_discover", "arguments": "bad"}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "external_httpx_discover", "arguments": {"host": loopback_server.host, "port": "80", "enabled": True}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "external_httpx_discover", "arguments": {"host": loopback_server.host, "enabled": "yes"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "external_httpx_discover", "arguments": {"host": loopback_server.host, "enabled": True, "approval_mode": "prompt"}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "external_httpx_discover", "arguments": {"host": loopback_server.host, "enabled": True, "extra_flags": ["-exec", "id"]}}},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "external_nuclei_scan", "arguments": {"host": loopback_server.host, "enabled": True, "tags": ["XSS"]}}},
        ]
        for req in bad_requests:
            resp = srv.handle_request(req)
            assert resp["error"]["code"] == -32602, f"Expected -32602 for {req!r}, got {resp!r}"

        shell_resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "external_httpx_discover", "arguments": {"host": loopback_server.host, "enabled": True, "shell": True}},
            }
        )
        assert shell_resp["error"]["code"] == -32001
    assert len(subprocess_recorder.calls) == 0


def test_mcp_docker_scanner_and_multiturn_worker_end_to_end(
    subprocess_recorder: SimpleNamespace, loopback_server: SimpleNamespace, tmp_path: Path
) -> None:
    subprocess_recorder.set_response(
        "nuclei",
        stdout=json.dumps(
            {
                "template-id": "tech-fastapi",
                "info": {"name": "FastAPI Detected", "severity": "info", "tags": ["tech"]},
                "matched-at": f"{loopback_server.url}/health",
                "host": loopback_server.host,
            }
        )
        + "\n",
    )

    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_e2e.db")) as srv:
        r_nuc = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "external_nuclei_scan",
                    "arguments": {
                        "host": loopback_server.host,
                        "port": loopback_server.port,
                        "use_tls": False,
                        "authorized": True,
                        "enabled": True,
                        "execution_mode": "docker",
                        "tags": ["tech"],
                    },
                },
            }
        )
        nuc_payload = json.loads(r_nuc["result"]["content"][0]["text"])
        assert nuc_payload["execution_mode"] == "docker"
        assert nuc_payload["total_findings"] == 1
        assert Path(subprocess_recorder.calls[0]["argv"][0]).name.lower().startswith("docker")
        assert subprocess_recorder.calls[0]["shell"] is False

        loopback_server.reset()
        r_mt = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "artex_run_multiturn_worker",
                    "arguments": {
                        "host": loopback_server.host,
                        "port": loopback_server.port,
                        "use_tls": False,
                        "authorized": True,
                        "target_route": "/api/admin",
                        "attack_type": "AUTH_BOUNDARY",
                        "max_intent_turns": 1,
                        "reports_dir": str(tmp_path / "rep_mcp_mt"),
                    },
                },
            }
        )
        mt_payload = json.loads(r_mt["result"]["content"][0]["text"])
        assert mt_payload["turns_executed"] <= 1
        assert mt_payload["worker_traces_count"] >= 1
        assert len(loopback_server.requests) >= 1

        loopback_server.reset()
        r_deny = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "artex_run_multiturn_worker",
                    "arguments": {
                        "host": loopback_server.host,
                        "port": loopback_server.port,
                        "use_tls": False,
                        "authorized": True,
                        "target_route": "/api/admin",
                        "approval_mode": "deny",
                    },
                },
            }
        )
        assert r_deny["error"]["code"] == -32001
        assert len(loopback_server.requests) == 0


# =============================================================================
# Iteration 2 Remediation Regression Tests (CLI, Swarm, & MCP)
# =============================================================================


def test_main_global_port_and_artex_rounds_before_subcommands_preserved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import main as main_mod

    captured: List[Dict[str, Any]] = []

    def _spy_cmd_artex(args: Any) -> None:
        captured.append(
            {
                "fn": "artex",
                "command": args.command,
                "port": getattr(args, "port", None),
                "artex_rounds": getattr(args, "artex_rounds", None),
                "artex_multiturn": getattr(args, "artex_multiturn", False),
            }
        )

    def _spy_cmd_all(args: Any) -> None:
        captured.append(
            {
                "fn": "all",
                "command": args.command,
                "port": getattr(args, "port", None),
                "artex_rounds": getattr(args, "artex_rounds", None),
            }
        )

    def _spy_cmd_scanner(args: Any) -> None:
        captured.append(
            {
                "fn": "scanner",
                "command": args.command,
                "port": getattr(args, "port", None),
            }
        )

    monkeypatch.setattr(main_mod, "cmd_artex", _spy_cmd_artex)
    monkeypatch.setattr(main_mod, "cmd_all", _spy_cmd_all)
    monkeypatch.setattr(main_mod, "cmd_scanner", _spy_cmd_scanner)

    db_file = str(tmp_path / "cli_flags.db")

    # 1. Global --port and --artex-rounds before artex-loop must not be clobbered
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--db", db_file, "--host", "127.0.0.1", "--port", "60975", "--artex-rounds", "3", "artex-loop"],
    )
    main_mod.main()
    assert captured[-1]["port"] == 60975
    assert captured[-1]["artex_rounds"] == 3
    assert captured[-1]["artex_multiturn"] is True

    # 2. Global --port and --artex-rounds before artex and chain must not be clobbered
    for sub in ("artex", "chain"):
        monkeypatch.setattr(
            sys,
            "argv",
            ["main.py", "--db", db_file, "--host", "127.0.0.1", "--port", "60975", "--artex-rounds", "4", sub],
        )
        main_mod.main()
        assert captured[-1]["command"] == sub
        assert captured[-1]["port"] == 60975
        assert captured[-1]["artex_rounds"] == 4

    # 3. Omitting --port and --artex-rounds preserves per-subcommand defaults
    monkeypatch.setattr(sys, "argv", ["main.py", "--db", db_file, "--host", "127.0.0.1", "artex"])
    main_mod.main()
    assert captured[-1]["port"] == 8080
    assert captured[-1]["artex_rounds"] == 2

    monkeypatch.setattr(sys, "argv", ["main.py", "--db", db_file, "--host", "127.0.0.1", "artex-loop"])
    main_mod.main()
    assert captured[-1]["port"] == 8080
    assert captured[-1]["artex_rounds"] == 1

    monkeypatch.setattr(sys, "argv", ["main.py", "--db", db_file, "--host", "127.0.0.1", "all"])
    main_mod.main()
    assert captured[-1]["port"] == 443
    assert captured[-1]["artex_rounds"] == 1

    monkeypatch.setattr(sys, "argv", ["main.py", "--db", db_file, "--host", "127.0.0.1", "scanner"])
    main_mod.main()
    assert captured[-1]["port"] == 443


def test_main_artex_loop_normalizes_url_host(
    monkeypatch: pytest.MonkeyPatch,
    loopback_server: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import main as main_mod

    db_file = tmp_path / "url_host.db"
    loopback_server.reset()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--db",
            str(db_file),
            "artex-loop",
            "--host",
            loopback_server.url,
            "--authorized",
            "--artex-intent-turns",
            "1",
            "--output-dir",
            str(tmp_path / "rep_url"),
            "--json",
        ],
    )
    main_mod.main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["result"]["task_id"]
    assert len(loopback_server.requests) >= 1


def test_swarm_inline_host_port_preserved_and_cmd_all_closes_db_on_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import main as main_mod
    import rfc_hunt_swarm as swarm_mod

    seen_calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(
        main_mod,
        "cmd_scanner",
        lambda a: seen_calls.append({"mode": "scanner", "host": a.host, "port": a.port}),
    )
    monkeypatch.setattr(
        main_mod,
        "cmd_artex_loop",
        lambda a: seen_calls.append({"mode": "artex-loop", "host": a.host, "port": a.port}),
    )

    swarm_mod.main_swarm(["scanner", "--host", "http://127.0.0.1:60975", "--authorized"])
    assert seen_calls[-1] == {"mode": "scanner", "host": "127.0.0.1", "port": 60975}

    swarm_mod.main_swarm(["artex-loop", "--host", "http://127.0.0.1:60976", "--authorized"])
    assert seen_calls[-1] == {"mode": "artex-loop", "host": "127.0.0.1", "port": 60976}

    swarm_mod.main_swarm(["scanner", "--host", "127.0.0.1", "--authorized"])
    assert seen_calls[-1] == {"mode": "scanner", "host": "127.0.0.1", "port": 443}

    swarm_mod.main_swarm(["artex-loop", "--host", "127.0.0.1", "--authorized"])
    assert seen_calls[-1] == {"mode": "artex-loop", "host": "127.0.0.1", "port": 8080}

    # Verify cmd_all closes Database deterministically via finally even on unexpected RuntimeError
    close_events: List[str] = []
    opened_dbs: List[Database] = []
    orig_db_cls = Database

    class _TrackingDatabase(orig_db_cls):
        def __init__(self, *a: Any, **kw: Any) -> None:
            super().__init__(*a, **kw)
            opened_dbs.append(self)

        def close(self) -> None:
            close_events.append("closed")
            super().close()

    monkeypatch.setattr(swarm_mod, "Database", _TrackingDatabase, raising=False)
    import database as db_mod
    monkeypatch.setattr(db_mod, "Database", _TrackingDatabase)
    import engine.mantis_integrator as mi_mod
    monkeypatch.setattr(
        mi_mod,
        "run_unified_all_scans",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(RuntimeError, match="boom"):
        swarm_mod.main_swarm(
            ["--all", "--repo", str(tmp_path), "--db", str(tmp_path / "err.db"), "--json"]
        )
    assert len(opened_dbs) == 1
    assert close_events == ["closed"]


def test_mcp_run_all_scans_hardening_stdio_purity_and_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import time

    monkeypatch.setattr("builtins.input", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("stdin prompt called")))

    repo_dir = tmp_path / "mcp_repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_all_hard.db")) as srv:
        # 1. Input schema declares approval_mode enum=[policy, deny]
        tl = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        tools = {t["name"]: t for t in tl["result"]["tools"]}
        for tname in ("run_all_scans", "mantis_scan_all"):
            am_prop = tools[tname]["inputSchema"]["properties"]["approval_mode"]
            assert am_prop["enum"] == ["policy", "deny"]
            assert am_prop["default"] == "policy"

        # 2. approval_mode="prompt" or invalid returns -32602 without blocking or printing to stdout
        for bad_mode in ("prompt", "bogus"):
            resp_bad = srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "run_all_scans",
                        "arguments": {
                            "host": "127.0.0.1",
                            "enable_external_scanners": True,
                            "approval_mode": bad_mode,
                        },
                    },
                }
            )
            assert resp_bad["error"]["code"] == -32602
            assert capsys.readouterr().out == ""

        # 3. Invalid nuclei_tags / scanner_isolation rejected even when enable_external_scanners=False
        for bad_args in (
            {"repo": str(repo_dir), "enable_external_scanners": False, "nuclei_tags": [123]},
            {"repo": str(repo_dir), "enable_external_scanners": False, "nuclei_tags": ["rce"]},
            {"repo": str(repo_dir), "enable_external_scanners": False, "scanner_isolation": "podman"},
        ):
            r_inv = srv.handle_request(
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "run_all_scans", "arguments": bad_args}}
            )
            assert r_inv["error"]["code"] == -32602
            assert capsys.readouterr().out == ""

        # 4. Valid nuclei_tags=["tech"] + scanner_isolation="docker" with enabled=False completes cleanly with 0 stdout bytes
        r_ok = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "run_all_scans",
                    "arguments": {
                        "repo": str(repo_dir),
                        "enable_external_scanners": False,
                        "nuclei_tags": ["tech"],
                        "scanner_isolation": "docker",
                        "reports_dir": str(tmp_path / "rep_mcp_ok"),
                        "output_dir": str(tmp_path / "rep_mcp_ok"),
                    },
                },
            }
        )
        assert "result" in r_ok
        assert capsys.readouterr().out == ""

        # 5. Rate limit enforcement on run_all_scans & mantis_scan_all -> -32029
        now = time.time()
        TargetAuthorizationGate._request_history["default"] = [now] * TargetAuthorizationGate.RATE_LIMIT_PER_MINUTE
        for tname in ("run_all_scans", "mantis_scan_all"):
            r_rl = srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": tname, "arguments": {"repo": str(repo_dir)}},
                }
            )
            assert r_rl["error"]["code"] == -32029
            assert capsys.readouterr().out == ""

    # 6. End-to-end stdio subprocess check: approval_mode="prompt" returns -32602 JSON-RPC & second request succeeds
    root_dir = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root_dir)
    env["CI"] = "true"
    env["RFCHUNT_OFFLINE"] = "1"
    stdio_db = tmp_path / "stdio_mcp.db"
    reqs = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 101,
                "method": "tools/call",
                "params": {
                    "name": "run_all_scans",
                    "arguments": {"host": "127.0.0.1", "enable_external_scanners": True, "approval_mode": "prompt"},
                },
            }
        )
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 102, "method": "tools/list", "params": {}})
        + "\n"
    )
    proc = subprocess.run(
        [sys.executable, "mcp_server.py", "--transport", "stdio", "--db", str(stdio_db)],
        cwd=str(root_dir),
        input=reqs,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert proc.returncode == 0
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) == 2
    parsed = [json.loads(ln) for ln in lines]
    assert parsed[0]["id"] == 101 and parsed[0]["error"]["code"] == -32602
    assert parsed[1]["id"] == 102 and "tools" in parsed[1]["result"]


def test_mcp_concurrent_stats_crlf_max_turns_shell_and_nuclei_tags_shadowing(
    subprocess_recorder: SimpleNamespace,
    loopback_server: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import concurrent.futures

    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_conc.db")) as srv:
        # 1. CRLF / control-char rejection on artex_run_multiturn_worker target_route & method
        for bad_arg in (
            {"host": loopback_server.host, "port": loopback_server.port, "target_route": "/api\r\nX-Inject: 1"},
            {"host": loopback_server.host, "port": loopback_server.port, "method": "GET\r\n"},
        ):
            r_ctrl = srv.handle_request(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "artex_run_multiturn_worker", "arguments": bad_arg}}
            )
            assert r_ctrl["error"]["code"] == -32602

        # 2. max_turns honored when max_intent_turns is explicitly None
        r_mt = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "artex_run_multiturn_worker",
                    "arguments": {
                        "host": loopback_server.host,
                        "port": loopback_server.port,
                        "use_tls": False,
                        "authorized": True,
                        "target_route": "/api/admin",
                        "max_intent_turns": None,
                        "max_turns": 1,
                        "reports_dir": str(tmp_path / "rep_mt_none"),
                    },
                },
            }
        )
        mt_data = json.loads(r_mt["result"]["content"][0]["text"])
        assert mt_data["turns_executed"] <= 1

        # 3. Truthy non-bool shell values rejected with -32001
        for bad_shell in ("true", 1):
            r_sh = srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "external_httpx_discover",
                        "arguments": {"host": loopback_server.host, "enabled": False, "shell": bad_shell},
                    },
                }
            )
            assert r_sh["error"]["code"] == -32001

        # 4. external_nuclei_scan validates nuclei_tags even when tags is None or non-None
        for tag_args in (
            {"host": loopback_server.host, "enabled": True, "tags": None, "nuclei_tags": ["rce"]},
            {"host": loopback_server.host, "enabled": True, "tags": ["tech"], "nuclei_tags": ["rce"]},
        ):
            r_nt = srv.handle_request(
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "external_nuclei_scan", "arguments": tag_args}}
            )
            assert r_nt["error"]["code"] == -32602
        assert len(subprocess_recorder.calls) == 0

        # 5. Concurrent handle_request mixing get_database_stats and artex_run_multiturn_worker
        def _worker_call(idx: int) -> Dict[str, Any]:
            if idx % 2 == 0:
                return srv.handle_request(
                    {"jsonrpc": "2.0", "id": idx, "method": "tools/call", "params": {"name": "get_database_stats", "arguments": {}}}
                )
            return srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "tools/call",
                    "params": {
                        "name": "artex_run_multiturn_worker",
                        "arguments": {
                            "host": loopback_server.host,
                            "port": loopback_server.port,
                            "use_tls": False,
                            "authorized": True,
                            "target_route": "/api/public",
                            "max_intent_turns": 1,
                            "reports_dir": str(tmp_path / f"rep_conc_{idx}"),
                        },
                    },
                }
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(_worker_call, range(16)))
        errors = [r for r in results if "error" in r]
        assert errors == []
        assert capsys.readouterr().out == ""


def test_mcp_cross_request_target_authorization_isolation(tmp_path: Path) -> None:
    import concurrent.futures

    TargetAuthorizationGate.ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}
    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_auth_iso.db")) as srv:
        # 1. Request with authorized=True must succeed (disabled no-op) without leaking into ALLOWED_TARGETS
        r1 = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "external_httpx_discover",
                    "arguments": {"host": "93.184.216.34", "authorized": True, "enabled": False},
                },
            }
        )
        assert "result" in r1
        assert "93.184.216.34" not in TargetAuthorizationGate.ALLOWED_TARGETS

        # 2. Subsequent request with authorized=False on the same host MUST fail with -32001
        r2 = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "external_httpx_discover",
                    "arguments": {"host": "93.184.216.34", "authorized": False, "enabled": False},
                },
            }
        )
        assert r2.get("error", {}).get("code") == -32001

        # 3. Same isolation for run_all_scans multi-target loop
        r3 = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_all_scans",
                    "arguments": {
                        "host": "93.184.216.34",
                        "targets": "93.184.216.34,93.184.216.35",
                        "authorized": False,
                        "enable_external_scanners": False,
                    },
                },
            }
        )
        assert r3.get("error", {}).get("code") == -32001

        # 4. Concurrent in-flight authorized=True must NOT authorize concurrent authorized=False request
        entered = threading.Event()
        release = threading.Event()
        orig_exec = srv._execute_tool

        def _holding_exec(name: str, args: Dict[str, Any]) -> Any:
            if args.get("authorized") is True:
                res = orig_exec(name, args)
                entered.set()
                release.wait(timeout=5)
                return res
            return orig_exec(name, args)

        srv._execute_tool = _holding_exec  # type: ignore[method-assign]
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                fut_auth = pool.submit(
                    srv.handle_request,
                    {
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/call",
                        "params": {
                            "name": "external_httpx_discover",
                            "arguments": {"host": "93.184.216.34", "authorized": True, "enabled": False},
                        },
                    },
                )
                assert entered.wait(timeout=5)
                r_unauth = srv.handle_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "tools/call",
                        "params": {
                            "name": "external_httpx_discover",
                            "arguments": {"host": "93.184.216.34", "authorized": False, "enabled": False},
                        },
                    }
                )
                release.set()
                r_auth = fut_auth.result(timeout=5)
        finally:
            srv._execute_tool = orig_exec  # type: ignore[method-assign]

        assert "result" in r_auth
        assert r_unauth.get("error", {}).get("code") == -32001
        assert "93.184.216.34" not in TargetAuthorizationGate.ALLOWED_TARGETS


def test_cli_mcp_db_flag(tmp_path: Path) -> None:
    # `main.py mcp --db <path> --help` succeeds with exit 0 (real subprocess, no recorder)
    proc = subprocess.run(
        [sys.executable, "main.py", "mcp", "--db", str(tmp_path / "m.db"), "--help"],
        cwd=str(Path(__file__).resolve().parent.parent),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "--db" in proc.stdout


def test_cli_scanner_no_double_print(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    subprocess_recorder: SimpleNamespace,
    loopback_server: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import main as main_mod

    # `cmd_scanner` disabled and enabled plain outputs print panels/tables exactly once
    db_file = tmp_path / "cli_noprint.db"
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--db", str(db_file), "scanner", "--host", loopback_server.host, "--port", str(loopback_server.port), "--plain"],
    )
    main_mod.main()
    dis_out = capsys.readouterr().out
    assert dis_out.count("=== External Scanners (Opt-In Disabled) ===") == 1

    subprocess_recorder.set_response(
        "httpx",
        stdout=json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200}) + "\n",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--db",
            str(db_file),
            "scanner",
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
            "--enable-external-scanners",
            "--httpx-scan",
            "--plain",
        ],
    )
    main_mod.main()
    en_out = capsys.readouterr().out
    assert en_out.count("=== External Scanners Summary ===") == 1
    assert en_out.count("=== Discovered Surface & Findings ===") == 1


def test_mcp_clean_db_httpx_nuclei_hydrate_db_dedup_and_sequential_nuclei_node_ids(
    tmp_path: Path,
    subprocess_recorder: SimpleNamespace,
    loopback_server: SimpleNamespace,
) -> None:
    def _call(srv: TerminatorMCPServer, rid: int, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        resp = srv.handle_request({"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
        assert "result" in resp, f"Expected JSON-RPC result for {name}, got {resp}"
        return json.loads(resp["result"]["content"][0]["text"])

    db_file = tmp_path / "clean_mcp.db"
    subprocess_recorder.set_response(
        "httpx",
        stdout="\n".join([
            json.dumps({"url": f"{loopback_server.url}/api/v1/users", "status_code": 200, "method": "GET"}),
            json.dumps({"url": f"{loopback_server.url}/internal/admin", "status_code": 403, "method": "GET"}),
        ]) + "\n",
    )
    subprocess_recorder.set_response(
        "nuclei",
        stdout=json.dumps({
            "template-id": "exposed-admin-panel",
            "info": {"name": "Exposed Internal Admin Panel", "severity": "high", "tags": ["exposure", "panel"], "classification": {"cwe-id": ["CWE-284"]}},
            "matched-at": f"{loopback_server.url}/internal/admin",
            "host": loopback_server.host,
            "matcher-status": True,
        }) + "\n",
    )

    with TerminatorMCPServer(db_path=str(db_file)) as srv:
        r_hx = _call(srv, 1, "external_httpx_discover", {"host": loopback_server.host, "port": loopback_server.port, "use_tls": False, "enabled": True})
        assert r_hx["status"] == "completed"
        r_nuc = _call(srv, 2, "external_nuclei_scan", {"host": loopback_server.host, "port": loopback_server.port, "use_tls": False, "enabled": True, "tags": ["exposure"]})
        assert r_nuc["findings_ingested"] == 1

        asset_rows = srv.db.get_dual_graph_nodes(graph_type="ASSET")
        admin_eps = [r for r in asset_rows if r["node_type"] == "ENDPOINT" and "/internal/admin" in r["label"]]
        assert len(admin_eps) == 1

        r_chain = _call(
            srv,
            3,
            "artex_run_attack_chain",
            {"host": loopback_server.host, "port": loopback_server.port, "use_tls": False, "hydrate_db": True, "rounds": 1, "reports_dir": str(tmp_path / "rep")},
        )
        assert r_chain["candidates_planned"] >= 1
        assert r_chain["chains_synthesized"] >= 1

        # Sequential nuclei scans with identical template-id must not overwrite each other
        subprocess_recorder.set_response(
            "nuclei",
            stdout=json.dumps({
                "template-id": "exposed-admin-panel",
                "info": {"name": "Second Panel", "severity": "medium", "tags": ["misconfig"]},
                "matched-at": f"{loopback_server.url}/panel-2",
                "host": loopback_server.host,
                "matcher-status": True,
            }) + "\n",
        )
        _call(srv, 4, "external_nuclei_scan", {"host": loopback_server.host, "port": loopback_server.port, "use_tls": False, "enabled": True, "tags": ["misconfig"]})
        prim_rows = [r for r in srv.db.get_dual_graph_nodes(graph_type="EXPLORATION") if r["node_type"] == "FINDING_PRIMITIVE"]
        assert len(prim_rows) == 2


def test_run_unified_all_scans_deduplicates_overlapping_repo_openapi_and_httpx_endpoints(
    tmp_path: Path,
    subprocess_recorder: SimpleNamespace,
    loopback_server: SimpleNamespace,
) -> None:
    from database import Database
    from engine.mantis_integrator import run_unified_all_scans

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n'
        '@app.route("/api/v1/health")\ndef h(): return "ok"\n'
        '@app.route("/internal/admin")\ndef a(): return "admin"\n',
        encoding="utf-8",
    )
    oa = tmp_path / "openapi.json"
    oa.write_text(
        json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/api/v1/health": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/internal/admin": {"get": {"responses": {"200": {"description": "ok"}}}},
            },
        }),
        encoding="utf-8",
    )
    subprocess_recorder.set_response(
        "httpx",
        stdout="\n".join([
            json.dumps({"url": f"{loopback_server.url}/api/v1/health", "status_code": 200, "method": "GET"}),
            json.dumps({"url": f"{loopback_server.url}/internal/admin", "status_code": 403, "method": "GET"}),
        ]) + "\n",
    )
    db = Database(str(tmp_path / "all_dedup.db"))
    try:
        run_unified_all_scans(
            str(repo),
            host=loopback_server.host,
            port=loopback_server.port,
            use_tls=False,
            authorized=True,
            import_openapi=str(oa),
            enable_external_scanners=True,
            httpx_scan=True,
            reports_dir=str(tmp_path / "all_rep"),
            db=db,
        )
        dg_report = sorted((tmp_path / "all_rep").glob("dual_graph_report_*.json"))[-1]
        rep_data = json.loads(dg_report.read_text(encoding="utf-8"))
        ep_nodes = [n for n in rep_data["asset_graph"]["nodes"] if n["node_type"] in ("ENDPOINT", "AI_SINK")]
        health_eps = [n for n in ep_nodes if "/api/v1/health" in n["label"]]
        admin_eps = [n for n in ep_nodes if "/internal/admin" in n["label"]]
        assert len(health_eps) == 1
        assert len(admin_eps) == 1
    finally:
        db.close()


def test_mcp_artex_run_attack_chain_hydrate_db_no_duplicate_discovered_assets(
    tmp_path: Path,
    subprocess_recorder: SimpleNamespace,
    loopback_server: SimpleNamespace,
) -> None:
    def _call(srv: TerminatorMCPServer, rid: int, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        resp = srv.handle_request(
            {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
        )
        assert "result" in resp, f"Expected JSON-RPC result for {name}, got {resp}"
        return json.loads(resp["result"]["content"][0]["text"])

    subprocess_recorder.set_response(
        "httpx",
        stdout="\n".join(
            [
                json.dumps({"url": f"{loopback_server.url}/api/v1", "status_code": 200, "method": "GET"}),
                json.dumps({"url": f"{loopback_server.url}/internal/service", "status_code": 403, "method": "GET"}),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        stdout="\n".join(
            [
                json.dumps(
                    {
                        "request": {"method": "POST", "endpoint": f"{loopback_server.url}/api/chat"},
                        "response": {"status_code": 200},
                    }
                ),
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": f"{loopback_server.url}/static/bundle.js"},
                        "response": {"status_code": 200},
                    }
                ),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "nuclei",
        stdout=json.dumps(
            {
                "template-id": "tech-fastapi",
                "info": {"name": "FastAPI Detected", "severity": "info", "tags": ["tech"]},
                "matched-at": f"{loopback_server.url}/api/v1",
                "host": loopback_server.host,
                "matcher-status": True,
            }
        )
        + "\n",
    )

    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_hydrate_dedup.db")) as srv:
        _call(
            srv,
            1,
            "external_httpx_discover",
            {"host": loopback_server.host, "port": loopback_server.port, "use_tls": False, "authorized": True, "enabled": True},
        )
        _call(
            srv,
            2,
            "external_katana_crawl",
            {"host": loopback_server.host, "port": loopback_server.port, "use_tls": False, "authorized": True, "enabled": True},
        )
        _call(
            srv,
            3,
            "external_nuclei_scan",
            {"host": loopback_server.host, "port": loopback_server.port, "use_tls": False, "authorized": True, "enabled": True, "tags": ["tech"]},
        )

        pre_assets = [
            (r["node_id"], r["node_type"], r["label"])
            for r in srv.db.get_dual_graph_nodes(graph_type="ASSET")
            if r["node_type"] in ("ENDPOINT", "AI_SINK")
        ]
        assert len(pre_assets) == 4

        _call(
            srv,
            4,
            "artex_run_attack_chain",
            {
                "host": loopback_server.host,
                "port": loopback_server.port,
                "use_tls": False,
                "authorized": True,
                "hydrate_db": True,
                "multiturn": True,
                "rounds": 1,
                "reports_dir": str(tmp_path / "rep1"),
            },
        )
        post_assets = [
            (r["node_id"], r["node_type"], r["label"])
            for r in srv.db.get_dual_graph_nodes(graph_type="ASSET")
            if r["node_type"] in ("ENDPOINT", "AI_SINK")
        ]
        assert post_assets == pre_assets
        assert not any("ASSET-EP-127.0.0.1-0" in nid or "ASSET-AI-SINK-127.0.0.1-0" in nid for nid, _, _ in post_assets)

        # Even when overlapping endpoints/ai_sinks are passed explicitly, hydrated assets are reused without duplication
        _call(
            srv,
            5,
            "artex_run_attack_chain",
            {
                "host": loopback_server.host,
                "port": loopback_server.port,
                "use_tls": False,
                "authorized": True,
                "hydrate_db": True,
                "endpoints": ["/api/v1"],
                "ai_sinks": ["/api/chat"],
                "rounds": 1,
                "reports_dir": str(tmp_path / "rep2"),
            },
        )
        post_explicit_assets = [
            (r["node_id"], r["node_type"], r["label"])
            for r in srv.db.get_dual_graph_nodes(graph_type="ASSET")
            if r["node_type"] in ("ENDPOINT", "AI_SINK")
        ]
        assert post_explicit_assets == pre_assets


def test_dual_graph_ingest_from_database_idempotent_across_same_and_fresh_engines(
    isolated_db: Database,
    tmp_path: Path,
) -> None:
    isolated_db.save_mantis_finding(
        {
            "finding_id": "MF-IDEM-1",
            "target_path": "/app",
            "file_path": "/api/v1",
            "rule_id": "MANTIS-IDEM-01",
            "title": "Mantis SSRF",
            "severity": "HIGH",
            "calibrated_severity": "HIGH",
        }
    )
    isolated_db.save_ai_finding(
        target_path="/app",
        finding_type="PROMPT_INJECTION",
        severity="HIGH",
        file_path="/api/chat",
        line_number=10,
        model_or_api="openai",
        description="Prompt injection sink",
        snippet="chat()",
    )

    seed_eng = DualGraphAttackEngine(db=isolated_db, reports_dir=str(tmp_path / "rep_seed"))
    seed_eng.ingest_finding({"rule_id": "NUC-IDEM-1", "title": "Exposed Health", "file_path": "/health"}, scanner="nuclei")

    # 1. Same-engine repeated ingest_from_database must return 0 on Cycle 2
    eng_same = DualGraphAttackEngine(db=isolated_db, reports_dir=str(tmp_path / "rep_same"))
    c1 = eng_same.ingest_from_database(isolated_db)
    assert c1["dual_graph_primitives"] == 1
    assert c1["mantis_findings"] == 1
    assert c1["ai_security_findings"] == 1
    assert len(isolated_db.get_dual_graph_nodes(graph_type="EXPLORATION")) == 3

    c2 = eng_same.ingest_from_database(isolated_db)
    assert all(v == 0 for v in c2.values()), f"Expected all 0 on repeated ingest, got {c2}"
    in_mem_same = [
        n for n in eng_same.exploration_graph.nodes.values() if n.node_type in ("FINDING_PRIMITIVE", "WIRE_PRIMITIVE")
    ]
    assert len(in_mem_same) == 3
    assert len(isolated_db.get_dual_graph_nodes(graph_type="EXPLORATION")) == 3

    # 2. Three consecutive fresh engines against the same DB must keep DB rows & in-memory nodes constant
    for idx in range(3):
        eng_fresh = DualGraphAttackEngine(db=isolated_db, reports_dir=str(tmp_path / f"rep_fresh_{idx}"))
        cf = eng_fresh.ingest_from_database(isolated_db)
        assert cf["mantis_findings"] == 0
        assert cf["ai_security_findings"] == 0
        assert cf["dual_graph_primitives"] == 3
        in_mem_fresh = [
            n for n in eng_fresh.exploration_graph.nodes.values() if n.node_type in ("FINDING_PRIMITIVE", "WIRE_PRIMITIVE")
        ]
        assert len(in_mem_fresh) == 3
        db_rows = isolated_db.get_dual_graph_nodes(graph_type="EXPLORATION")
        assert len(db_rows) == 3
        by_scanner: Dict[str, int] = {}
        for r in db_rows:
            sc = str((r.get("attributes") or {}).get("scanner") or "")
            by_scanner[sc] = by_scanner.get(sc, 0) + 1
        assert by_scanner == {"nuclei": 1, "mantis": 1, "aiscan": 1}
