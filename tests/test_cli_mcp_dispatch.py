"""
Unit and integration tests for Milestone M3:
- CLI-only `hint` mode & `--hint` / `--dispatch` flags (`rfc_hunt_swarm.py`)
- MCP `inject_blackboard_hint` tool (`mcp_server.py`)
- Unified `swarm_dispatch.yaml` & `engine/swarm_dispatcher.py`
- Crash-resilient resume & `--all` / `--mode all` blackboard integration (local/mocked only)
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
from typing import Any, Dict, List

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from database import Database
from engine.swarm_dispatcher import (
    execute_dispatch,
    load_dispatch_config,
    resolve_target_workspace,
)
from mcp_server import TerminatorMCPServer


class _LocalLabHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b'{"status":"ok","service":"m3-local-lab"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 0:
            self.rfile.read(length)
        self.do_GET()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


@pytest.fixture()
def local_http_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LocalLabHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield port
    finally:
        srv.shutdown()
        srv.server_close()


# =============================================================================
# 1. CLI Hint Injection (`rfc_hunt_swarm.py`)
# =============================================================================


def test_cli_hint_standalone_json_and_zero_gui(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rfc_hunt_swarm

    assert "hint" in rfc_hunt_swarm.ALL_MODES
    ui_calls: List[str] = []
    monkeypatch.setattr(rfc_hunt_swarm, "start_background_ui", lambda a: ui_calls.append("bg"))
    monkeypatch.setattr(rfc_hunt_swarm, "cmd_ui", lambda a: ui_calls.append("ui"))
    monkeypatch.setattr(rfc_hunt_swarm, "cmd_dashboard", lambda a: ui_calls.append("dash"))

    db_file = tmp_path / "cli_hint.db"
    rfc_hunt_swarm.main_swarm(
        [
            "hint",
            "--hint",
            "Check chunk extension whitespace",
            "--hint-domain",
            "http11_framing",
            "--hint-priority",
            "45.5",
            "--hint-task-id",
            "m3-task-1",
            "--hint-rfc",
            "9112",
            "--db",
            str(db_file),
            "--json",
        ]
    )
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["status"] == "injected"
    assert payload["node_type"] == "HINT"
    assert payload["domain"] == "http11_framing"
    assert float(payload["priority"]) == 45.5
    assert payload["task_id"] == "m3-task-1"
    assert payload["active"] is True
    assert ui_calls == []

    db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        hints = db.get_active_hints(task_id="m3-task-1", domain="http11_framing")
        assert len(hints) == 1
        assert hints[0]["content"] == "Check chunk extension whitespace"
        assert hints[0]["rfc_id"] == "9112"
    finally:
        db.close()


@pytest.mark.parametrize(
    "argv",
    [
        ["hint"],
        ["hint", "--hint", "   "],
        ["hint", "--hint", ""],
        ["hint", "--hint", "bad\x00nul"],
        ["hint", "--hint", "ok", "--hint-priority", "nan"],
        ["--hint", "   "],
    ],
)
def test_cli_hint_invalid_inputs_exit_nonzero_without_creating_db(
    tmp_path: Path,
    argv: List[str],
) -> None:
    from rfc_hunt_swarm import main_swarm

    db_file = tmp_path / "should_not_exist.db"
    with pytest.raises(SystemExit) as exc:
        main_swarm([*argv, "--db", str(db_file)])
    assert exc.value.code not in (0, None)
    assert not db_file.exists()


def test_cli_hint_combined_with_single_scan_persists_before_generation(
    tmp_path: Path,
    local_http_server: int,
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
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "is_clean": True}]
        ),
    )

    # Seed RFC 9112 text in local cache dir so test stays 100% offline
    rfc_dir = tmp_path / "rfcs"
    rfc_dir.mkdir(parents=True, exist_ok=True)
    (rfc_dir / "rfc9112.txt").write_text(
        "6.1. Transfer-Encoding\nA server MUST reject ambiguous Content-Length and Transfer-Encoding headers.\n",
        encoding="utf-8",
    )

    db_file = tmp_path / "combined_hint.db"
    monkeypatch.chdir(tmp_path)
    main_swarm(
        [
            "--mode",
            "single",
            "--rfc",
            "9112",
            "--host",
            "127.0.0.1",
            "--port",
            str(local_http_server),
            "--cache-dir",
            str(rfc_dir),
            "--db",
            str(db_file),
            "--cycles",
            "1",
            "--no-fusion",
            "--no-dream-rsi",
            "--no-harness2",
            "--no-caldera",
            "--no-lab",
            "--hint",
            "UNIT_COMBINED_HINT_MARKER",
        ]
    )
    assert any("UNIT_COMBINED_HINT_MARKER" in p for p in seen_prompts)


# =============================================================================
# 2. MCP `inject_blackboard_hint` Tool (`mcp_server.py`)
# =============================================================================


def test_mcp_inject_blackboard_hint_list_call_and_validation(tmp_path: Path) -> None:
    db_file = tmp_path / "mcp_hint.db"
    with TerminatorMCPServer(db_path=str(db_file)) as srv:
        list_resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        tools = {t["name"]: t for t in list_resp["result"]["tools"]}
        assert "inject_blackboard_hint" in tools
        assert "hint_text" in tools["inject_blackboard_hint"]["inputSchema"]["required"]

        call_resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "inject_blackboard_hint",
                    "arguments": {
                        "hint_text": "Prioritize TE-TE duplicate headers",
                        "domain": "http11_framing",
                        "priority": 65.5,
                        "task_id": "mcp-u1",
                        "rfc_num": "9112",
                        "source": "unit-mcp",
                        "active": True,
                    },
                },
            }
        )
        body = json.loads(call_resp["result"]["content"][0]["text"])
        assert body["status"] == "injected"
        assert body["node_type"] == "HINT"
        assert body["domain"] == "http11_framing"
        assert float(body["priority"]) == 65.5
        assert body["active"] is True

        # Strict validation errors (-32602)
        for bad_args in (
            {},
            {"hint_text": None},
            {"hint_text": ""},
            {"hint_text": "   \t  "},
            {"hint_text": "bad\x00hint"},
            {"hint_text": 42},
            {"hint_text": "ok", "priority": True},
            {"hint_text": "ok", "priority": float("nan")},
            {"hint_text": "ok", "active": "true"},
        ):
            err_resp = srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "inject_blackboard_hint", "arguments": bad_args},
                }
            )
            assert err_resp["error"]["code"] == -32602

        # ExecutionPolicy shell/command rejection (-32001)
        for shell_args in (
            {"hint_text": "ok", "shell": True},
            {"hint_text": "ok", "command": "whoami"},
        ):
            auth_resp = srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "inject_blackboard_hint", "arguments": shell_args},
                }
            )
            assert auth_resp["error"]["code"] == -32001

    check_db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        hints = check_db.get_active_hints(task_id="mcp-u1", domain="http11_framing")
        assert len(hints) == 1
        assert hints[0]["content"] == "Prioritize TE-TE duplicate headers"
        assert hints[0]["source_agent"] == "unit-mcp"
        assert hints[0]["rfc_id"] == "9112"
    finally:
        check_db.close()


# =============================================================================
# 3. `swarm_dispatch.yaml` & `engine/swarm_dispatcher.py`
# =============================================================================


def test_reference_swarm_dispatch_yaml_loads_and_maps_runtime() -> None:
    cfg = load_dispatch_config(REPO_ROOT / "swarm_dispatch.yaml")
    assert cfg.version == 1
    assert cfg.runtime.execution == "local"
    assert cfg.runtime.scanner_isolation == "host"
    assert cfg.workers.backend == "all"
    assert cfg.workspace.per_target_isolation is True
    assert len(cfg.targets) >= 1
    assert cfg.targets[0].host == "127.0.0.1"


def test_dispatcher_docker_mapping_and_cli_overrides(
    tmp_path: Path,
    local_http_server: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.mantis_integrator as mi

    captured: List[Dict[str, Any]] = []

    def _fake_unified(**kwargs: Any) -> Dict[str, Any]:
        captured.append({"kwargs": dict(kwargs), "offline": os.environ.get("RFCHUNT_OFFLINE")})
        return {
            "target_path": kwargs.get("host"),
            "total_aggregated_findings": 1,
            "severity_counts": {"LOW": 1},
            "chains_synthesized": 0,
            "findings": [{"title": "Local probe check", "rule_id": "R1", "severity": "LOW"}],
            "report_files": {},
        }

    monkeypatch.setattr(mi, "run_unified_all_scans", _fake_unified)
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)

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
                "workers": {"backend": "all", "concurrency": 2, "use_fusion": False},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {
                        "name": "local_docker_tgt",
                        "host": "127.0.0.1",
                        "port": local_http_server,
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
    cfg = load_dispatch_config(cfg_path)
    assert cfg.runtime.scanner_isolation == "docker"

    custom_db = tmp_path / "cli_override" / "custom.db"
    custom_out = tmp_path / "cli_override" / "reports"
    res = execute_dispatch(cfg, db_override=str(custom_db), output_dir_override=str(custom_out))
    assert len(res) == 1
    assert captured[0]["kwargs"]["scanner_isolation"] == "docker"
    assert captured[0]["kwargs"]["docker_image"] == "projectdiscovery/nuclei:latest"
    assert captured[0]["kwargs"]["docker_network"] == "bridge"
    assert captured[0]["offline"] == "1"
    assert os.environ.get("RFCHUNT_OFFLINE") is None
    assert custom_db.is_file()
    assert custom_out.is_dir()

    db = Database(str(custom_db), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        facts = db.get_facts()
        assert len(facts) >= 2
    finally:
        db.close()


@pytest.mark.parametrize(
    "bad_cfg",
    [
        {"version": 2, "runtime": {"execution": "local"}, "workspace": {"root": "ws"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": True, "runtime": {"execution": "local"}, "workspace": {"root": "ws"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "k8s"}, "workspace": {"root": "ws"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "docker", "docker_network": "host"}, "workspace": {"root": "ws"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workers": {"backend": "unknown"}, "workspace": {"root": "ws"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": "../../escape"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": "%2e%2e/escape"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": r"\\server\share\ws"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": "ws:stream"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": "CON"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": r"C:\Windows\Temp\escape"}, "targets": [{"name": "a", "host": "127.0.0.1", "port": 8080, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": "ws"}, "targets": [{"name": "ssrf", "host": "169.254.169.254", "port": 80, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": "ws"}, "targets": [{"name": "ssrf6", "host": "::ffff:127.0.0.1", "port": 80, "authorized": True}]},
        {"version": 1, "runtime": {"execution": "local"}, "workspace": {"root": "ws"}, "targets": [{"name": "unauth", "host": "example.com", "port": 443, "authorized": False}]},
    ],
)
def test_dispatcher_rejects_invalid_and_unsafe_configs_before_creating_db(
    tmp_path: Path,
    bad_cfg: Dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_path = tmp_path / "bad.yaml"
    cfg_path.write_text(yaml.safe_dump(bad_cfg), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with pytest.raises((ValueError, PermissionError, yaml.YAMLError)):
        load_dispatch_config(cfg_path)
    assert list(tmp_path.rglob("*.db")) == []


def test_dispatcher_per_target_workspace_isolation(tmp_path: Path) -> None:
    ws_root = tmp_path / "multi_ws"
    cfg_path = tmp_path / "multi.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {"execution": "local", "offline": True},
                "workers": {"backend": "all"},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {"name": "svc_one", "host": "127.0.0.1", "port": 8081, "authorized": True},
                    {"name": "svc_two", "host": "127.0.0.1", "port": 8082, "authorized": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    cfg = load_dispatch_config(cfg_path)
    p1 = resolve_target_workspace(cfg.workspace, cfg.targets[0], create=True)
    p2 = resolve_target_workspace(cfg.workspace, cfg.targets[1], create=True)
    assert p1.workspace_dir != p2.workspace_dir
    assert p1.db_path != p2.db_path
    assert p1.workspace_dir.is_relative_to(ws_root.resolve())
    assert p2.workspace_dir.is_relative_to(ws_root.resolve())


# =============================================================================
# 4. Crash-Resume & `--all` / `--mode all` Smoke Execution
# =============================================================================


def test_crash_resume_reclaims_claimed_preserves_done_and_facts_and_dedups_bootstrap(
    tmp_path: Path,
    local_http_server: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import ProtocolResearchSwarm

    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "is_clean": True}],
    )

    rfc_dir = tmp_path / "rfcs"
    rfc_dir.mkdir(parents=True, exist_ok=True)
    (rfc_dir / "rfc9112.txt").write_text(
        "6.1. Transfer-Encoding\nA sender MUST NOT send Content-Length with Transfer-Encoding.\n",
        encoding="utf-8",
    )

    db_file = tmp_path / "resume_swarm.db"
    db1 = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    fact_id = db1.add_fact("prior confirmed finding", task_id="res-u1", domain="http11_framing")
    done_id = db1.queue_intent("GET /done HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", priority=90.0, task_id="res-u1")
    db1.claim_next_intent("dead-worker", task_id="res-u1")
    db1.complete_intent(done_id, status="DONE")

    stale_id = db1.queue_intent(
        "GET /reclaimed HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        priority=80.0,
        task_id="res-u1",
        payload={"raw_request": "GET /reclaimed HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", "is_clean": True},
    )
    claimed = db1.claim_next_intent("dead-worker", task_id="res-u1")
    assert claimed is not None and claimed["node_id"] == stale_id
    db1.close()

    executed: List[bytes] = []
    swarm = ProtocolResearchSwarm(
        host="127.0.0.1",
        port=local_http_server,
        db_path=str(db_file),
        use_fusion=False,
        concurrency=1,
    )
    swarm.fetcher.cache_dir = rfc_dir
    orig_eval = swarm._evaluate_single_candidate

    def _spy_eval(cand: Dict[str, Any]) -> Dict[str, Any]:
        out = orig_eval(cand)
        executed.append(out["probe_bytes"])
        return out

    monkeypatch.setattr(swarm, "_evaluate_single_candidate", _spy_eval)
    try:
        graph = swarm.build_graph()
        base_state = {
            "rfc_num": "9112",
            "fragments": [],
            "generated_candidates": [],
            "cycle_count": 0,
            "max_cycles": 1,
            "enable_dream_rsi": False,
            "enable_harness2": False,
            "blackboard_bootstrapped": False,
            "task_id": "res-u1",
            "workspace_dir": str(tmp_path),
            "blackboard_domain": "http11_framing",
            "history": [],
        }
        graph.invoke(base_state, {"recursion_limit": 100})
        frag_count_1 = swarm.db.conn.execute("SELECT COUNT(*) FROM fragments").fetchone()[0]

        # Resume a second time with blackboard_bootstrapped=False: save_fragments must not duplicate rows
        graph.invoke(dict(base_state, history=[]), {"recursion_limit": 100})
        frag_count_2 = swarm.db.conn.execute("SELECT COUNT(*) FROM fragments").fetchone()[0]
        assert frag_count_2 == frag_count_1

        assert not any(b"/done" in p for p in executed)
        assert any(b"/reclaimed" in p for p in executed)
        assert swarm.db.list_intents(status="CLAIMED", task_id="res-u1") == []
        done_ids = {r["node_id"] for r in swarm.db.list_intents(status="DONE", task_id="res-u1")}
        assert {done_id, stale_id}.issubset(done_ids)
        fact_ids = {f["node_id"] for f in swarm.db.get_facts(task_id="res-u1")}
        assert fact_id in fact_ids
    finally:
        swarm.close()


def test_cli_all_and_mode_all_smoke_persists_facts_and_hints(
    tmp_path: Path,
    local_http_server: int,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.mantis_integrator as mi
    from rfc_hunt_swarm import main_swarm

    def _fake_unified(**kwargs: Any) -> Dict[str, Any]:
        return {
            "target_path": kwargs.get("repo") or kwargs.get("host") or ".",
            "depth": kwargs.get("depth"),
            "fusion_enabled": kwargs.get("use_fusion"),
            "abliterated_model": kwargs.get("preferred_model"),
            "fusion_models": [kwargs.get("preferred_model")],
            "total_aggregated_findings": 1,
            "severity_counts": {"MEDIUM": 1},
            "elapsed_sec": 0.01,
            "chains_synthesized": 1,
            "findings": [{"title": "Sample local finding", "rule_id": "M3-01", "severity": "MEDIUM"}],
            "engines": {"mantis": {}, "aiscan": {}, "raptor": {}, "prompt_smuggling": {}},
            "report_files": {"combined_sarif": str(tmp_path / "r.sarif"), "combined_json": str(tmp_path / "r.json")},
        }

    monkeypatch.setattr(mi, "run_unified_all_scans", _fake_unified)
    mini_repo = tmp_path / "repo"
    mini_repo.mkdir()
    (mini_repo / "app.py").write_text("def ok(): return True\n", encoding="utf-8")

    db_file = tmp_path / "all_smoke.db"
    main_swarm(
        [
            "--mode",
            "all",
            "--repo",
            str(mini_repo),
            "--host",
            "127.0.0.1",
            "--port",
            str(local_http_server),
            "--authorized",
            "--hint",
            "ALL_SCAN_HINT_MARKER",
            "--db",
            str(db_file),
            "--output-dir",
            str(tmp_path / "reports"),
            "--no-rea",
            "--json",
        ]
    )
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["total_aggregated_findings"] == 1

    db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        facts = db.get_facts()
        hints = db.get_active_hints()
        assert len(facts) >= 2
        assert any("ALL_SCAN_HINT_MARKER" in h["content"] for h in hints)
    finally:
        db.close()


# =============================================================================
# 5. Phase-1 Additions: `export_blackboard_trees` & `--all` Default-ON / Opt-Out
# =============================================================================


def test_database_export_blackboard_trees_groups_lineage_and_outcomes(tmp_path: Path) -> None:
    db_file = tmp_path / "trees.db"
    db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        # Confirm migration 004_blackboard_nodes is untouched
        migs = {r[0] for r in db.conn.execute("SELECT version FROM schema_migrations").fetchall()}
        assert "004_blackboard_nodes" in migs

        probe_id = db.save_probe(None, "TE+CL probe", "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        db.record_evaluation(probe_id, "127.0.0.1", 8080, True, "CL.TE", "Confirmed desync", "HTTP/1.1 200 OK")
        db.save_implementation_anomaly(
            anomaly_id="ANOM-T1",
            target_engine="127.0.0.1:8080",
            category="PARSER_DIVERGENCE",
            observed_behavior="CL.TE split",
            expected_behavior="400",
            raw_probe="POST / HTTP/1.1",
            raw_response="HTTP/1.1 200 OK",
        )
        db.save_reproducible_vulnerability(
            vuln_id="VULN-T1",
            anomaly_id="ANOM-T1",
            impact="DESYNCHRONIZATION",
            minimized_probe="POST / HTTP/1.1",
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=1,
            provenance_chain=["seq", "delta"],
        )

        root_id = db.add_fact("Bootstrap RFC9112", node_id="fact:boot:t1", task_id="task-alpha", domain="http11_framing", rfc_id="RFC9112")
        intent_id = db.queue_intent(
            "POST / HTTP/1.1",
            priority=50.0,
            node_id="intent:probe:t1",
            task_id="task-alpha",
            domain="http11_framing",
            rfc_id="RFC9112",
            parent_node_id=root_id,
            payload={"probe_id": probe_id, "anomaly_id": "ANOM-T1", "outcome": "ANOMALY"},
        )
        vuln_fact_id = db.add_fact(
            "Confirmed vuln VULN-T1",
            node_id="fact:vuln:VULN-T1:task-alpha",
            task_id="task-alpha",
            domain="http11_framing",
            rfc_id="RFC9112",
            parent_node_id=intent_id,
            payload={"vuln_id": "VULN-T1", "anomaly_id": "ANOM-T1"},
        )
        db.add_fact("Second task root", node_id="fact:boot:t2", task_id="task-beta", domain="h2_translation", rfc_id="RFC9113")

        all_trees = db.export_blackboard_trees(limit_tasks=10)
        assert len(all_trees) == 2
        assert {t["task_id"] for t in all_trees} == {"task-alpha", "task-beta"}

        limited = db.export_blackboard_trees(limit_tasks=1)
        assert len(limited) == 1
        assert limited[0]["task_id"] == "task-beta"

        alpha_trees = db.export_blackboard_trees(task_id="task-alpha")
        assert len(alpha_trees) == 1
        alpha = alpha_trees[0]
        assert alpha["node_count"] == 3
        assert alpha["root_node_ids"] == [root_id]
        assert alpha["children_by_parent"][root_id] == [intent_id]
        assert alpha["children_by_parent"][intent_id] == [vuln_fact_id]
        assert alpha["summary"]["confirmed_vuln_count"] >= 2
        assert len(alpha["outcomes"]["evaluations"]) == 1
        assert len(alpha["outcomes"]["anomalies"]) == 1
        assert len(alpha["outcomes"]["reproducible_vulnerabilities"]) == 1

        node_map = {n["node_id"]: n for n in alpha["nodes"]}
        assert node_map[intent_id]["outcomes"]["evaluation"]["probe_id"] == probe_id
        assert node_map[vuln_fact_id]["outcomes"]["vulnerability"]["vuln_id"] == "VULN-T1"
        assert node_map[vuln_fact_id]["outcomes"]["is_confirmed_vuln"] is True

        assert db.export_blackboard_trees(task_id="nonexistent-task") == []
    finally:
        db.close()


def test_cli_all_default_on_scanners_rea_models_and_opt_out_flags(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.mantis_integrator as mi
    from rfc_hunt_swarm import main_swarm, parse_swarm_arguments

    captured: List[Dict[str, Any]] = []

    def _fake_unified(**kwargs: Any) -> Dict[str, Any]:
        captured.append(dict(kwargs))
        return {
            "target_path": kwargs.get("repo") or kwargs.get("host") or ".",
            "depth": kwargs.get("depth"),
            "fusion_enabled": True,
            "fusion_models": [kwargs.get("preferred_model")],
            "total_aggregated_findings": 0,
            "severity_counts": {},
            "elapsed_sec": 0.01,
            "chains_synthesized": 0,
            "findings": [],
            "engines": {},
            "report_files": {},
        }

    monkeypatch.setattr(mi, "run_unified_all_scans", _fake_unified)
    mini_repo = tmp_path / "repo_flags"
    mini_repo.mkdir()
    (mini_repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    db_file = tmp_path / "flags.db"

    # 1. Default --all passes enable_external_scanners=None (default-ON in run_unified_all_scans),
    #    rea_use_cli=True, and include_models=True
    main_swarm(["--all", "--repo", str(mini_repo), "--db", str(db_file), "--output-dir", str(tmp_path / "r1"), "--json"])
    _ = json.loads(capsys.readouterr().out)
    assert captured[-1]["enable_external_scanners"] is None
    assert captured[-1]["httpx_scan"] is None
    assert captured[-1]["katana_scan"] is None
    assert captured[-1]["nuclei_scan"] is None
    assert captured[-1]["rea_use_cli"] is True
    assert captured[-1]["include_models"] is True

    # 2. Explicit opt-out flags disable each component cleanly
    main_swarm(
        [
            "--all",
            "--repo",
            str(mini_repo),
            "--db",
            str(db_file),
            "--output-dir",
            str(tmp_path / "r2"),
            "--no-external-scanners",
            "--no-httpx-scan",
            "--no-katana-scan",
            "--no-nuclei-scan",
            "--no-rea-cli",
            "--no-include-models",
            "--json",
        ]
    )
    _ = json.loads(capsys.readouterr().out)
    assert captured[-1]["enable_external_scanners"] is False
    assert captured[-1]["httpx_scan"] is False
    assert captured[-1]["katana_scan"] is False
    assert captured[-1]["nuclei_scan"] is False
    assert captured[-1]["rea_use_cli"] is False
    assert captured[-1]["include_models"] is False

    # 3. Standalone scanner mode remains opt-in disabled when no scanner flags are provided
    parsed_scanner = parse_swarm_arguments(["scanner", "--host", "127.0.0.1", "--port", "8080"])
    assert parsed_scanner.enable_external_scanners is False
    assert parsed_scanner.no_external_scanners is False


# =============================================================================
# 6. Phase-2 CLI Integration Tests (Slicer, Fuzz Bridge, Diff/Invariants/POE)
# =============================================================================


def test_cli_call_graph_slice_and_fuzz_bridge_dry_run_keep_repo_clean(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rfc_hunt_swarm import main_swarm

    repo = tmp_path / "sample_repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from service import run_cmd\n"
        "def handle_request(request):\n"
        "    user_input = request.args.get('q')\n"
        "    return run_cmd(user_input)\n",
        encoding="utf-8",
    )
    (repo / "service.py").write_text(
        "import subprocess\n"
        "def run_cmd(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    before_files = sorted(str(p.relative_to(repo)) for p in repo.rglob("*"))

    # 1. `slice` subcommand JSON
    main_swarm(["slice", "--repo", str(repo), "--json"])
    slice_out = json.loads(capsys.readouterr().out)
    assert slice_out["call_graph"]["files_scanned"] == 2
    assert slice_out["escalation_plan"]["frontier_enabled"] is False

    # 2. `fuzz-bridge --fuzz-dry-run` keeps target repo untouched and writes artifacts to --output-dir
    out_dir = tmp_path / "fuzz_out"
    db_file = tmp_path / "fuzz_cli.db"
    main_swarm(
        [
            "fuzz-bridge",
            "--repo",
            str(repo),
            "--output-dir",
            str(out_dir),
            "--db",
            str(db_file),
            "--task-id",
            "cli-fuzz-1",
            "--fuzz-dry-run",
            "--json",
        ]
    )
    fuzz_out = json.loads(capsys.readouterr().out)
    assert fuzz_out["status"] == "prepared_only"
    assert "python" in fuzz_out["detected_languages"]
    assert len(fuzz_out["generated_artifacts"]) >= 1
    assert sorted(str(p.relative_to(repo)) for p in repo.rglob("*")) == before_files


def test_cli_docker_matrix_invariants_and_poe_verify_skip_cleanly_without_docker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.differential_oracle as diff_mod
    import engine.poe_container_verifier as poe_mod
    import engine.sandbox_invariant_runner as inv_mod
    from rfc_hunt_swarm import main_swarm

    # Force Docker unavailable cleanly across all three modules
    monkeypatch.setattr(diff_mod.DockerParserMatrix, "check_docker_available", lambda self: (False, "mock_no_docker"))
    monkeypatch.setattr(inv_mod.SandboxInvariantRunner, "check_docker_available", lambda self: (False, "mock_no_docker"))
    monkeypatch.setattr(poe_mod.ContainerPOEVerifier, "check_docker_available", lambda self: (False, "mock_no_docker"))

    repo = tmp_path / "inv_repo"
    repo.mkdir()
    (repo / "app.py").write_text("def ok():\n    return True\n", encoding="utf-8")
    db_file = tmp_path / "diff_cli.db"

    main_swarm(["oracle", "--docker-parser-matrix", "--json"])
    dpm_out = json.loads(capsys.readouterr().out)
    assert dpm_out["status"] == "skipped_docker_unavailable"

    main_swarm(["sandbox-invariants", "--repo", str(repo), "--db", str(db_file), "--json"])
    inv_out = json.loads(capsys.readouterr().out)
    assert inv_out["status"] == "skipped_docker_unavailable"

    findings_file = tmp_path / "findings.json"
    findings_file.write_text(
        json.dumps([{"finding_id": "F-1", "severity": "HIGH", "title": "Test finding", "file_path": "app.py"}]),
        encoding="utf-8",
    )
    main_swarm(
        [
            "poe-verify",
            "--repo",
            str(repo),
            "--findings-json",
            str(findings_file),
            "--db",
            str(db_file),
            "--json",
        ]
    )
    poe_out = json.loads(capsys.readouterr().out)
    assert poe_out["status"] == "skipped_docker_unavailable"


def test_cli_all_attaches_aixcc_extensions_and_honors_export_sarif(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.mantis_integrator as mi
    from rfc_hunt_swarm import main_swarm

    out_dir = tmp_path / "all_rep"
    out_dir.mkdir(parents=True, exist_ok=True)
    base_sarif = out_dir / "combined_report.sarif"
    base_sarif.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")

    def _fake_unified(**kwargs: Any) -> Dict[str, Any]:
        return {
            "target_path": kwargs.get("repo") or ".",
            "depth": kwargs.get("depth"),
            "fusion_enabled": True,
            "fusion_models": ["gemma"],
            "total_aggregated_findings": 0,
            "severity_counts": {},
            "elapsed_sec": 0.01,
            "chains_synthesized": 0,
            "findings": [],
            "engines": {},
            "report_files": {"combined_sarif": str(base_sarif)},
        }

    monkeypatch.setattr(mi, "run_unified_all_scans", _fake_unified)
    repo = tmp_path / "mini_all"
    repo.mkdir()
    (repo / "main.py").write_text("def hello():\n    return 'ok'\n", encoding="utf-8")
    db_file = tmp_path / "all_ext.db"

    main_swarm(
        [
            "--all",
            "--repo",
            str(repo),
            "--output-dir",
            str(out_dir),
            "--db",
            str(db_file),
            "--export-sarif",
            "custom_combined.sarif",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["engines"]["call_graph_slicer"]["status"] == "completed"
    assert "tiered_escalation" in payload["engines"]
    assert payload["engines"]["fuzz_bridge"]["status"] == "skipped_offline_or_test_guard"
    assert payload["engines"]["sandbox_invariants"]["status"] == "skipped_offline_or_test_guard"
    assert payload["engines"]["poe_verifier"]["status"] == "skipped_offline_or_test_guard"
    exported = out_dir / "custom_combined.sarif"
    assert exported.is_file()
    assert json.loads(exported.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert payload["engines"]["novelty_corpus"]["status"] == "ready_offline"
    assert payload["engines"]["novelty_corpus"]["entry_count"] >= 20


def test_cli_novelty_corpus_offline_refresh_and_fail_closed_network(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rfc_hunt_swarm import main_swarm

    db_file = tmp_path / "nov.db"
    # 1. Offline status (0 network calls)
    main_swarm(["novelty", "--db", str(db_file), "--json"])
    info = json.loads(capsys.readouterr().out)
    assert info["status"] == "ready_offline"
    assert info["total_entries"] >= 20
    assert info["allow_network"] is False

    # 2. Local JSON catalog refresh
    custom_cat = tmp_path / "custom_techniques.json"
    custom_cat.write_text(
        json.dumps(
            [
                {
                    "technique_id": "CUSTOM-H3-999",
                    "title": "Custom H3 QPACK Dynamic Table Smuggling",
                    "probe": "POST / HTTP/3\r\n:authority: example.com\r\ncontent-length: 0\r\n\r\n",
                    "tags": ["http3", "qpack"],
                }
            ]
        ),
        encoding="utf-8",
    )
    export_file = tmp_path / "merged_catalog.json"
    main_swarm(
        [
            "novelty-refresh",
            "--refresh-novelty-corpus",
            str(custom_cat),
            "--novelty-export",
            str(export_file),
            "--db",
            str(db_file),
            "--json",
        ]
    )
    ref = json.loads(capsys.readouterr().out)
    assert ref["added"] >= 1
    assert export_file.is_file()

    # 3. Remote URL without --novelty-allow-network fails closed
    with pytest.raises(SystemExit) as exc:
        main_swarm(
            [
                "novelty-refresh",
                "--refresh-novelty-corpus",
                "https://example.com/feed.json",
                "--db",
                str(db_file),
                "--json",
            ]
        )
    assert exc.value.code != 0


def test_cli_dream_benchmark_offline_and_live_lab_plus_router_early_stop(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from engine.dream_rsi_optimizer import DreamPolicy
    from rfc_hunt_swarm import ProtocolResearchSwarm, main_swarm

    db_file = tmp_path / "dream_cli.db"
    pol_file = tmp_path / "dream_policies.json"
    # Seed a recorded tree in SQLite
    db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        root = db.add_fact("Boot RFC9112", node_id="fact:boot:d1", task_id="dream-t1", domain="http11_framing", rfc_id="RFC9112")
        i1 = db.queue_intent("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", priority=20.0, node_id="intent:d1:1", task_id="dream-t1", domain="http11_framing", rfc_id="RFC9112", parent_node_id=root, payload={"outcome": "ANOMALY"})
        db.add_fact("Confirmed vuln", node_id="fact:vuln:V-D1:dream-t1", task_id="dream-t1", domain="http11_framing", rfc_id="RFC9112", parent_node_id=i1, payload={"vuln_id": "V-D1", "is_confirmed_vuln": True})
    finally:
        db.close()

    # 1. Offline replay benchmark CLI
    main_swarm(
        [
            "--mode",
            "dream",
            "--dream-benchmark",
            "--dream-seeds",
            "3",
            "--dream-budget",
            "15",
            "--generations",
            "2",
            "--db",
            str(db_file),
            "--dream-export",
            str(pol_file),
            "--json",
        ]
    )
    bench_out = json.loads(capsys.readouterr().out)
    assert bench_out["simulator_backend"] == "recorded_blackboard_replay"
    assert set(bench_out["policies"].keys()) >= {"Disabled", "Random", "Heuristic", "NoLearning", "DreamRSI_Learned"}

    # 2. Loopback TestLabServer live-lab benchmark CLI
    main_swarm(
        [
            "--mode",
            "dream",
            "--dream-benchmark",
            "--dream-live-lab",
            "--dream-seeds",
            "2",
            "--dream-budget",
            "8",
            "--generations",
            "1",
            "--db",
            str(db_file),
            "--dream-export",
            str(pol_file),
            "--json",
        ]
    )
    live_out = json.loads(capsys.readouterr().out)
    assert live_out["simulator_backend"] == "local_testlab_live"

    # 3. ProtocolResearchSwarm blackboard_router early-stop pruning & dream_rsi_agent replay refresh
    swarm = ProtocolResearchSwarm(
        host="127.0.0.1",
        port=18089,
        db_path=str(db_file),
        use_fusion=False,
        concurrency=1,
    )
    swarm.dream_store.storage_path = str(pol_file)
    try:
        swarm.active_meta_policy = DreamPolicy(generation=1, early_stop_patience=2)
        route = swarm.blackboard_router(
            {
                "rfc_num": "9112",
                "blackboard_bootstrapped": True,
                "fragments": [("remaining frag", "kw", 1.0)],
                "cycle_count": 1,
                "max_cycles": 3,
                "zero_anomaly_streak": 3,
                "enable_dream_rsi": True,
                "task_id": "early-stop-task",
                "blackboard_domain": "http11_framing",
                "history": [],
            }
        )
        assert route["ooda_phase"] == "DreamRSI"
        assert route["early_stop_triggered"] is True

        d_out = swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 10,
                "enable_harness2": False,
                "task_id": "early-stop-task",
                "blackboard_domain": "http11_framing",
                "history": [],
            }
        )
        assert d_out["current_dream_policy"] is not None
        assert swarm.active_meta_policy is not None
        facts = swarm.db.get_facts(task_id="early-stop-task")
        assert any(f.get("source_agent") == "dream_rsi_agent" for f in facts)
    finally:
        swarm.close()


def test_cli_swarm_board_plain_json_and_zero_gui(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rfc_hunt_swarm

    ui_calls: List[str] = []
    monkeypatch.setattr(rfc_hunt_swarm, "start_background_ui", lambda a: ui_calls.append("bg"))
    monkeypatch.setattr(rfc_hunt_swarm, "cmd_ui", lambda a: ui_calls.append("ui"))
    monkeypatch.setattr(rfc_hunt_swarm, "cmd_dashboard", lambda a: ui_calls.append("dash"))

    db_file = tmp_path / "board_cli.db"
    db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        db.add_fact("Bootstrapped RFC9112", task_id="board-t1", domain="http11_framing", source_agent="fetch_and_chunk_agent")
        iid = db.queue_intent("POST / HTTP/1.1", priority=40.0, task_id="board-t1", domain="http11_framing", source_agent="llm_generator_agent")
        db.claim_next_intent("oracle-1", task_id="board-t1")
        db.complete_intent(iid, status="DONE")
        db.add_hint("Focus on TE+CL", task_id="board-t1", domain="http11_framing")
    finally:
        db.close()

    rfc_hunt_swarm.main_swarm(["swarm-board", "--db", str(db_file), "--task-id", "board-t1", "--plain"])
    plain_out = capsys.readouterr().out
    assert "\x1b[" not in plain_out
    assert "tasks done" in plain_out
    assert "tkinter" not in sys.modules
    assert ui_calls == []

    rfc_hunt_swarm.main_swarm(["swarm-board", "--db", str(db_file), "--task-id", "board-t1", "--json"])
    json_out = json.loads(capsys.readouterr().out)
    assert "goal" in json_out
    assert "threads" in json_out
    assert "counters" in json_out
    assert ui_calls == []
