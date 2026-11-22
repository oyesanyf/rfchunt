"""
Tier 1 Feature Contract Tests: CLI Hint Injection, MCP Tool, YAML Dispatcher,
and `--all` / Crash Resume (Features #10-#13).
Covers `PROJECT.md § Interface Contracts` #4 and #5 (>= 5 tests per feature = 21 tests).

Collection-safe: M3 modules (`engine.swarm_dispatcher`) and M3 parser modes/flags
are resolved dynamically inside test bodies.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Callable, Dict, List

import pytest
import yaml

from database import Database
from mcp_server import TerminatorMCPServer
from tests.e2e_blackboard.conftest import REPO_ROOT, _build_offline_subprocess_env


def _make_mini_repo(root: Path) -> Path:
    repo = root / "mini_repo"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "app.py").write_text(
        "def health():\n    return {'status': 'ok'}\n",
        encoding="utf-8",
    )
    return repo


# =============================================================================
# Feature #10: CLI-only `HINT` injection (6 tests)
# =============================================================================


def test_t1_f10_parser_exposes_hint_mode_and_cli_flags() -> None:
    from rfc_hunt_swarm import ALL_MODES, build_swarm_parser

    assert "hint" in ALL_MODES
    parser = build_swarm_parser()
    args = parser.parse_args(
        [
            "hint",
            "--hint",
            "Focus on obs-fold",
            "--hint-domain",
            "http11_framing",
            "--hint-priority",
            "42.5",
            "--hint-task-id",
            "task-cli-1",
            "--db",
            "custom.db",
        ]
    )
    assert args.hint == "Focus on obs-fold"
    assert args.hint_domain == "http11_framing"
    assert float(args.hint_priority) == 42.5
    assert args.hint_task_id == "task-cli-1"

    args_dispatch = parser.parse_args(["--dispatch", "swarm_dispatch.yaml"])
    assert args_dispatch.dispatch == "swarm_dispatch.yaml" or getattr(args_dispatch, "dispatch_config", None) == "swarm_dispatch.yaml"


def test_t1_f10_cli_subcommand_hint_persists_via_subprocess(
    tmp_path: Path,
    offline_subprocess_env: Dict[str, str],
) -> None:
    db_file = tmp_path / "cli_hint.db"
    proc = subprocess.run(
        [
            sys.executable,
            "-u",
            str(REPO_ROOT / "rfc_hunt_swarm.py"),
            "hint",
            "--hint",
            "Reject TE+CL ambiguity",
            "--hint-domain",
            "http11_framing",
            "--hint-priority",
            "33.0",
            "--hint-task-id",
            "cli-t1",
            "--db",
            str(db_file),
        ],
        cwd=str(tmp_path),
        env=offline_subprocess_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"
    db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        hints = db.get_active_hints(task_id="cli-t1", domain="http11_framing")
        assert len(hints) == 1
        assert hints[0]["content"] == "Reject TE+CL ambiguity"
        assert float(hints[0]["priority"]) == 33.0
    finally:
        db.close()


def test_t1_f10_cli_flag_mode_hint_persists_in_process(
    isolated_swarm_workspace: SimpleNamespace,
) -> None:
    from rfc_hunt_swarm import main_swarm

    db_file = isolated_swarm_workspace.db_path
    main_swarm(
        [
            "--mode",
            "hint",
            "--hint",
            "Test chunk extension semicolon",
            "--hint-domain",
            "http11_framing",
            "--hint-priority",
            "18",
            "--hint-task-id",
            "cli-flag-t",
            "--db",
            str(db_file),
        ]
    )
    db = Database(str(db_file), secret_key_path=str(isolated_swarm_workspace.key_path))
    try:
        hints = db.get_active_hints(task_id="cli-flag-t", domain="http11_framing")
        assert any(h["content"] == "Test chunk extension semicolon" for h in hints)
    finally:
        db.close()


def test_t1_f10_cli_combined_hint_with_single_scan_persists_before_run(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import main_swarm

    seen_prompts: List[str] = []
    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            seen_prompts.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )

    main_swarm(
        [
            "--mode",
            "single",
            "--rfc",
            "9112",
            "--host",
            "127.0.0.1",
            "--port",
            str(loopback_lab_server.port),
            "--db",
            str(isolated_swarm_workspace.db_path),
            "--cycles",
            "1",
            "--no-fusion",
            "--no-dream-rsi",
            "--no-harness2",
            "--no-caldera",
            "--hint",
            "CLI_COMBINED_HINT_MARKER",
            "--hint-domain",
            "global",
            "--hint-priority",
            "40",
        ]
    )
    assert len(seen_prompts) >= 1
    assert any("CLI_COMBINED_HINT_MARKER" in p for p in seen_prompts)
    db = Database(str(isolated_swarm_workspace.db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
    try:
        hints = db.get_active_hints(domain="global")
        assert any("CLI_COMBINED_HINT_MARKER" in h["content"] for h in hints)
    finally:
        db.close()


def test_t1_f10_cli_hint_starts_zero_gui_or_http_servers(
    isolated_swarm_workspace: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rfc_hunt_swarm

    called_ui: List[str] = []
    monkeypatch.setattr(rfc_hunt_swarm, "start_background_ui", lambda args: called_ui.append("bg"))
    monkeypatch.setattr(rfc_hunt_swarm, "cmd_ui", lambda args: called_ui.append("ui"))
    monkeypatch.setattr(rfc_hunt_swarm, "cmd_dashboard", lambda args: called_ui.append("dash"))

    rfc_hunt_swarm.main_swarm(
        [
            "hint",
            "--hint",
            "Zero GUI check",
            "--db",
            str(isolated_swarm_workspace.db_path),
        ]
    )
    assert called_ui == []
    assert "tkinter" not in sys.modules


def test_t1_f10_gui_and_test_lab_files_remain_strictly_cli_only() -> None:
    for rel in ("test_lab_server.py", "engine/dashboard_generator.py", "rfchunt_dashboard.html"):
        p = REPO_ROOT / rel
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="replace")
            assert "blackboard_nodes" not in txt
            assert "inject_blackboard_hint" not in txt
            assert "swarm_dispatcher" not in txt


# =============================================================================
# Feature #11: MCP `inject_blackboard_hint` tool (5 tests)
# =============================================================================


def test_t1_f11_mcp_tools_list_advertises_inject_blackboard_hint(bb_db: Database) -> None:
    with TerminatorMCPServer(db_path=str(bb_db.db_path)) as srv:
        resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        assert "inject_blackboard_hint" in tools
        schema = tools["inject_blackboard_hint"]["inputSchema"]
        assert "hint_text" in schema.get("properties", {})
        assert "hint_text" in schema.get("required", [])


def test_t1_f11_mcp_inject_blackboard_hint_defaults_and_json_contract(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "mcp_defaults.db"
    with TerminatorMCPServer(db_path=str(db_path)) as srv:
        resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "inject_blackboard_hint",
                    "arguments": {"hint_text": "Probe Transfer-Encoding comma lists"},
                },
            }
        )
        assert "result" in resp
        payload = json.loads(resp["result"]["content"][0]["text"])
        assert payload["status"] == "injected"
        assert payload["node_type"] == "HINT"
        assert payload["domain"] == "global"
        assert float(payload["priority"]) == 10.0
        assert payload["active"] is True
        assert payload["node_id"]

    check = Database(str(db_path), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        hints = check.get_active_hints(task_id="default", domain="global")
        assert len(hints) == 1
        assert hints[0]["content"] == "Probe Transfer-Encoding comma lists"
    finally:
        check.close()


def test_t1_f11_mcp_inject_blackboard_hint_custom_fields_and_inactive(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "mcp_custom.db"
    with TerminatorMCPServer(db_path=str(db_path)) as srv:
        r1 = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "inject_blackboard_hint",
                    "arguments": {
                        "hint_text": "Custom H2 pseudo-header hint",
                        "domain": "h2_translation",
                        "priority": 75.5,
                        "task_id": "mcp-t2",
                        "rfc_num": "9113",
                        "source": "claude-mcp",
                        "active": True,
                    },
                },
            }
        )
        p1 = json.loads(r1["result"]["content"][0]["text"])
        assert p1["domain"] == "h2_translation"
        assert float(p1["priority"]) == 75.5
        assert p1["active"] is True

        r2 = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "inject_blackboard_hint",
                    "arguments": {
                        "hint_text": "Inactive hint seed",
                        "domain": "h2_translation",
                        "task_id": "mcp-t2",
                        "active": False,
                    },
                },
            }
        )
        p2 = json.loads(r2["result"]["content"][0]["text"])
        assert p2["active"] is False

    check = Database(str(db_path), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        active_hints = check.get_active_hints(task_id="mcp-t2", domain="h2_translation")
        assert len(active_hints) == 1
        assert active_hints[0]["content"] == "Custom H2 pseudo-header hint"
        assert active_hints[0]["source_agent"] == "claude-mcp"
        assert "9113" in active_hints[0]["rfc_id"]
    finally:
        check.close()


def test_t1_f11_mcp_stdio_subprocess_roundtrip_stdout_purity(
    tmp_path: Path,
    offline_subprocess_env: Dict[str, str],
) -> None:
    db_path = tmp_path / "mcp_stdio.db"
    requests_jsonl = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "inject_blackboard_hint",
                        "arguments": {
                            "hint_text": "STDIO_HINT_PERSISTED",
                            "domain": "http11_framing",
                            "priority": 88,
                            "task_id": "stdio-t",
                        },
                    },
                }
            ),
        ]
    ) + "\n"

    proc = subprocess.run(
        [
            sys.executable,
            "-u",
            str(REPO_ROOT / "mcp_server.py"),
            "--db",
            str(db_path),
            "--transport",
            "stdio",
        ],
        input=requests_jsonl,
        cwd=str(tmp_path),
        env=offline_subprocess_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) == 3
    parsed = [json.loads(ln) for ln in lines]
    assert parsed[0]["result"]["protocolVersion"] == "2024-11-05"
    assert any(t["name"] == "inject_blackboard_hint" for t in parsed[1]["result"]["tools"])
    call_body = json.loads(parsed[2]["result"]["content"][0]["text"])
    assert call_body["status"] == "injected"

    check = Database(str(db_path), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        hints = check.get_active_hints(task_id="stdio-t", domain="http11_framing")
        assert len(hints) == 1
        assert hints[0]["content"] == "STDIO_HINT_PERSISTED"
    finally:
        check.close()


def test_t1_f11_mcp_does_not_expose_gui_dashboard_tools(bb_db: Database) -> None:
    with TerminatorMCPServer(db_path=str(bb_db.db_path)) as srv:
        resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        names = {t["name"].lower() for t in resp["result"]["tools"]}
        assert not any("dashboard" in n or "gui" in n or "browser" in n for n in names)


# =============================================================================
# Feature #12: `swarm_dispatch.yaml` & dispatcher (5 tests)
# =============================================================================


def test_t1_f12_repo_reference_swarm_dispatch_yaml_validates() -> None:
    from rfc_hunt_swarm import build_swarm_parser

    cfg_path = REPO_ROOT / "swarm_dispatch.yaml"
    assert cfg_path.is_file()
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    assert raw["version"] == 1
    assert raw["runtime"]["execution"] in ("local", "docker")
    assert isinstance(raw["workers"], dict)
    assert raw["workers"]["backend"] in ("swarm", "all", "mantis", "artex")
    assert isinstance(raw["workspace"], dict) and "root" in raw["workspace"]
    assert isinstance(raw["targets"], list) and len(raw["targets"]) >= 1
    for tgt in raw["targets"]:
        assert {"name", "host", "port", "tls", "authorized", "modes", "rfcs"}.issubset(set(tgt.keys()))

    parser = build_swarm_parser()
    assert parser.parse_args(["--dispatch", str(cfg_path)]).dispatch == str(cfg_path)
    args_cfg = parser.parse_args(["--dispatch-config", str(cfg_path)])
    assert getattr(args_cfg, "dispatch_config", None) == str(cfg_path) or getattr(args_cfg, "dispatch", None) == str(cfg_path)


def test_t1_f12_local_execution_maps_to_host_scanner_isolation(
    tmp_path: Path,
    loopback_http_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.mantis_integrator as mi
    from rfc_hunt_swarm import main_swarm

    recorded: List[Dict[str, Any]] = []
    orig_unified = mi.run_unified_all_scans

    def _spy_unified(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        recorded.append({"kwargs": dict(kwargs), "offline": os.environ.get("RFCHUNT_OFFLINE")})
        return orig_unified(*args, **kwargs)

    monkeypatch.setattr(mi, "run_unified_all_scans", _spy_unified)
    ws_root = tmp_path / "ws_local"
    cfg_path = tmp_path / "local_dispatch.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workers": {"backend": "all", "concurrency": 2, "use_fusion": False},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {
                        "name": "lab1",
                        "host": "127.0.0.1",
                        "port": loopback_http_server.port,
                        "tls": False,
                        "authorized": True,
                        "modes": ["all"],
                        "rfcs": ["9112"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    main_swarm(["--dispatch", str(cfg_path)])
    assert len(recorded) == 1
    assert recorded[0]["kwargs"].get("scanner_isolation", "host") == "host"
    assert recorded[0]["offline"] == "1"
    assert len(list(ws_root.rglob("*.db"))) >= 1


def test_t1_f12_docker_execution_maps_to_docker_scanner_isolation(
    tmp_path: Path,
    loopback_http_server: Any,
    subprocess_recorder: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.mantis_integrator as mi
    from rfc_hunt_swarm import main_swarm

    subprocess_recorder.set_response(
        "nuclei",
        returncode=0,
        stdout="",
    )
    recorded: List[Dict[str, Any]] = []
    orig_unified = mi.run_unified_all_scans

    def _spy_unified(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        recorded.append(dict(kwargs))
        call_kw = dict(kwargs)
        call_kw["enable_external_scanners"] = True
        call_kw["httpx_scan"] = False
        call_kw["katana_scan"] = False
        call_kw["nuclei_scan"] = True
        return orig_unified(*args, **call_kw)

    monkeypatch.setattr(mi, "run_unified_all_scans", _spy_unified)
    ws_root = tmp_path / "ws_docker"
    cfg_path = tmp_path / "docker_dispatch.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {
                    "execution": "docker",
                    "docker_image": "projectdiscovery/nuclei:latest",
                    "docker_network": "bridge",
                    "offline": True,
                },
                "workers": {"backend": "all", "concurrency": 2, "artex_workers": 2},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {
                        "name": "lab_docker",
                        "host": "127.0.0.1",
                        "port": loopback_http_server.port,
                        "tls": False,
                        "authorized": True,
                        "modes": ["all"],
                        "rfcs": ["9112"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    main_swarm(["--dispatch", str(cfg_path)])
    assert len(recorded) == 1
    assert recorded[0].get("scanner_isolation") == "docker"
    assert recorded[0].get("docker_image") == "projectdiscovery/nuclei:latest"
    assert recorded[0].get("docker_network") == "bridge"
    docker_calls = [c for c in subprocess_recorder.calls if Path(c["argv"][0]).name.lower().startswith("docker")]
    assert len(docker_calls) >= 1
    for dc in docker_calls:
        assert dc["shell"] is False
        assert "--network=host" not in dc["argv"]
        assert "bridge" in dc["argv"]
        assert "projectdiscovery/nuclei:latest" in dc["argv"]


def test_t1_f12_per_target_workspace_isolation_creates_distinct_paths(
    tmp_path: Path,
    loopback_http_server: Any,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rfc_hunt_swarm import main_swarm

    ws_root = tmp_path / "isolated_ws"
    cfg_path = tmp_path / "multi_target.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workers": {"backend": "all", "concurrency": 2, "use_fusion": False},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {
                        "name": "svc_a",
                        "host": "127.0.0.1",
                        "port": loopback_http_server.port,
                        "tls": False,
                        "authorized": True,
                        "modes": ["all"],
                        "rfcs": ["9112"],
                    },
                    {
                        "name": "svc_b",
                        "host": "127.0.0.1",
                        "port": loopback_lab_server.port,
                        "tls": False,
                        "authorized": True,
                        "modes": ["all"],
                        "rfcs": ["7230"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    main_swarm(["--dispatch", str(cfg_path)])
    db_files = sorted(ws_root.rglob("*.db"))
    assert len(db_files) == 2
    assert db_files[0].resolve() != db_files[1].resolve()
    assert db_files[0].parent.resolve() != db_files[1].parent.resolve()
    for dbf in db_files:
        assert dbf.resolve().is_relative_to(ws_root.resolve())
        db = Database(str(dbf), secret_key_path=str(tmp_path / "keys" / "secret.key"))
        try:
            tbl = db.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blackboard_nodes'").fetchone()
            assert tbl is not None
        finally:
            db.close()


def test_t1_f12_dispatcher_enforces_worker_backend_and_offline_flag(
    tmp_path: Path,
    loopback_http_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.mantis_integrator as mi
    from rfc_hunt_swarm import main_swarm

    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    observed: List[Dict[str, Any]] = []
    orig_unified = mi.run_unified_all_scans

    def _spy_unified(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        observed.append({"offline": os.environ.get("RFCHUNT_OFFLINE"), "host": kwargs.get("host"), "port": kwargs.get("port")})
        return orig_unified(*args, **kwargs)

    monkeypatch.setattr(mi, "run_unified_all_scans", _spy_unified)
    ws_root = tmp_path / "dispatch_exec_ws"
    cfg_path = tmp_path / "exec_dispatch.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workers": {"backend": "all", "concurrency": 1, "use_fusion": False},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {
                        "name": "loopback_api",
                        "host": "127.0.0.1",
                        "port": loopback_http_server.port,
                        "tls": False,
                        "authorized": True,
                        "modes": ["all"],
                        "rfcs": ["9112"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    main_swarm(["--dispatch-config", str(cfg_path)])
    assert len(observed) == 1
    assert observed[0]["offline"] == "1"
    db_files = list(ws_root.rglob("*.db"))
    assert len(db_files) == 1
    assert db_files[0].is_file()


# =============================================================================
# Feature #13: `--all` / `--mode all` & crash resume (5 tests)
# =============================================================================


def test_t1_f13_cli_all_flag_runs_local_smoke_and_outputs_json_and_sarif(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_http_server: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rfc_hunt_swarm import main_swarm

    mini_repo = _make_mini_repo(isolated_swarm_workspace.root)
    out_dir = isolated_swarm_workspace.reports_dir / "all_flag"
    main_swarm(
        [
            "--all",
            "--repo",
            str(mini_repo),
            "--host",
            "127.0.0.1",
            "--port",
            str(loopback_http_server.port),
            "--authorized",
            "--db",
            str(isolated_swarm_workspace.db_path),
            "--output-dir",
            str(out_dir),
            "--no-rea",
            "--json",
        ]
    )
    stdout_text = capsys.readouterr().out
    parsed = json.loads(stdout_text)
    assert "report_files" in parsed
    assert Path(parsed["report_files"]["combined_sarif"]).is_file()
    assert Path(parsed["report_files"]["combined_json"]).is_file()


def test_t1_f13_cli_mode_all_populates_blackboard_nodes_and_reports(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_http_server: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rfc_hunt_swarm import main_swarm

    mini_repo = _make_mini_repo(isolated_swarm_workspace.root)
    out_dir = isolated_swarm_workspace.reports_dir / "mode_all"
    main_swarm(
        [
            "--mode",
            "all",
            "--repo",
            str(mini_repo),
            "--host",
            "127.0.0.1",
            "--port",
            str(loopback_http_server.port),
            "--authorized",
            "--db",
            str(isolated_swarm_workspace.db_path),
            "--output-dir",
            str(out_dir),
            "--no-rea",
            "--json",
        ]
    )
    parsed = json.loads(capsys.readouterr().out)
    assert Path(parsed["report_files"]["combined_sarif"]).is_file()
    db = Database(str(isolated_swarm_workspace.db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
    try:
        nodes = db.get_blackboard_nodes()
        assert len(nodes) >= 1
    finally:
        db.close()


def test_t1_f13_crash_resume_reclaims_claimed_and_skips_done(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import ProtocolResearchSwarm

    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}],
    )

    db1 = Database(str(isolated_swarm_workspace.db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
    done_id = db1.queue_intent("GET /already-done HTTP/1.1\r\nHost: target.local\r\n\r\n", priority=100.0, task_id="resume-t")
    db1.claim_next_intent("worker-dead", task_id="resume-t")
    db1.complete_intent(done_id, status="DONE", result_payload={"verdict": "CONFORMANT"})

    stale_id = db1.queue_intent(
        "GET /stale-claimed HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
        priority=50.0,
        task_id="resume-t",
        payload={"raw_request": "GET /stale-claimed HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True},
    )
    db1.claim_next_intent("worker-dead", task_id="resume-t")
    pending_id = db1.queue_intent(
        "GET /still-pending HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
        priority=10.0,
        task_id="resume-t",
        payload={"raw_request": "GET /still-pending HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True},
    )
    db1.close()

    executed_probes: List[bytes] = []
    swarm = ProtocolResearchSwarm(
        host="127.0.0.1",
        port=loopback_lab_server.port,
        db_path=str(isolated_swarm_workspace.db_path),
        use_fusion=False,
        concurrency=1,
    )
    swarm.fetcher.cache_dir = isolated_swarm_workspace.rfcs_dir
    orig_eval = swarm._evaluate_single_candidate

    def _spy_eval(cand: Dict[str, Any]) -> Dict[str, Any]:
        out = orig_eval(cand)
        executed_probes.append(out["probe_bytes"])
        return out

    monkeypatch.setattr(swarm, "_evaluate_single_candidate", _spy_eval)
    try:
        graph = swarm.build_graph()
        graph.invoke(
            {
                "rfc_num": "9112",
                "fragments": [],
                "generated_candidates": [],
                "cycle_count": 0,
                "max_cycles": 3,
                "enable_dream_rsi": False,
                "enable_harness2": False,
                "blackboard_bootstrapped": True,
                "task_id": "resume-t",
                "blackboard_domain": "http11_framing",
                "history": [],
            },
            {"recursion_limit": 100},
        )
        assert not any(b"/already-done" in p for p in executed_probes)
        done_ids = {r["node_id"] for r in swarm.db.list_intents(status="DONE", task_id="resume-t")}
        assert {done_id, stale_id, pending_id}.issubset(done_ids)
    finally:
        swarm.close()


def test_t1_f13_crash_resume_preserves_prior_facts_and_hints(
    bb_db_factory: Callable[..., Database],
) -> None:
    db1 = bb_db_factory("crash_facts.db")
    fact_id = db1.add_fact("pre-crash CL.TE confirmed", task_id="cr-task", domain="http11_framing")
    hint_id = db1.add_hint("pre-crash hint", task_id="cr-task", domain="http11_framing", priority=25.0)
    stale_id = db1.queue_intent("pre-crash intent", task_id="cr-task", priority=15.0)
    db1.claim_next_intent("crashed-worker", task_id="cr-task")
    db1.close()

    db2 = bb_db_factory("crash_facts.db")
    assert db2.reclaim_stale_intents(task_id="cr-task") == 1
    assert [f["node_id"] for f in db2.get_facts(task_id="cr-task")] == [fact_id]
    assert [h["node_id"] for h in db2.get_active_hints(task_id="cr-task", domain="http11_framing")] == [hint_id]
    reclaimed = db2.claim_next_intent("resumed-worker", task_id="cr-task")
    assert reclaimed is not None and reclaimed["node_id"] == stale_id


def test_t1_f13_main_swarm_dispatch_flag_executes_against_loopback(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_http_server: Any,
) -> None:
    from rfc_hunt_swarm import main_swarm

    ws_root = isolated_swarm_workspace.root / "dispatched_ws"
    cfg_path = isolated_swarm_workspace.root / "cli_dispatch.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workers": {"backend": "all", "concurrency": 1, "use_fusion": False},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {
                        "name": "loop_cli",
                        "host": "127.0.0.1",
                        "port": loopback_http_server.port,
                        "tls": False,
                        "authorized": True,
                        "modes": ["all"],
                        "rfcs": ["9112"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    main_swarm(["--dispatch", str(cfg_path)])
    db_files = list(ws_root.rglob("*.db"))
    assert len(db_files) >= 1
