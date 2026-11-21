"""
Tier 1 E2E Tests: CLI, --all Pipeline, Pure-CLI Rendering, & MCP Surface
Covers Features F11, F12, and F13 (18 tests total; >=5 per feature).

Collection safety: All M1-M4 symbols and dynamic CLI/MCP attributes are
resolved inside test bodies or local helpers so `pytest --collect-only`
succeeds cleanly before M1-M4 land.
"""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from engine import cli_render
from engine.approval_gate import ApprovalGate
from engine.mantis_integrator import run_unified_all_scans
from mcp_server import MCPHttpServer, TargetAuthorizationGate, TerminatorMCPServer


_TEST_HEX_KEY = "0123456789abcdef" * 4  # 64-char hex 32-byte key avoiding workspace secret.key creation
_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent)


def _offline_env(**extra: str) -> Dict[str, str]:
    env = dict(os.environ)
    env["CI"] = "true"
    env["RFCHUNT_OFFLINE"] = "1"
    env["PYTHONPATH"] = _REPO_ROOT
    env["ARTEX_SECRET_KEY"] = _TEST_HEX_KEY
    env.update(extra)
    return env


def _get_main_help(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], *subargs: str
) -> str:
    import main as main_mod

    monkeypatch.setattr(sys, "argv", ["main.py", *subargs, "--help"])
    with pytest.raises(SystemExit) as exc_info:
        main_mod.main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    return captured.out + captured.err


def _find_scanner_subcommand(help_text: str) -> Optional[str]:
    import re

    m = re.search(r"\{([a-zA-Z0-9_,-]+)\}", help_text)
    choices = set(m.group(1).split(",")) if m else set()
    for candidate in ("scanner", "external-scan", "discover", "nuclei-scan"):
        if candidate in choices:
            return candidate
    return None


def _find_artex_loop_subcommand(help_text: str) -> Optional[str]:
    for candidate in ("artex-loop", "artex_loop"):
        if candidate in help_text:
            return candidate
    if "artex" in help_text and "--artex-multiturn" in help_text:
        return "artex"
    return None


def _mcp_tools_by_name(server: TerminatorMCPServer) -> Dict[str, Dict[str, Any]]:
    resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    tools = resp["result"]["tools"]
    return {t["name"]: t for t in tools}


# =============================================================================
# Feature F11: --all Pipeline Integration (6 tests)
# =============================================================================


def test_f11_all_cli_parses_opt_in_scanner_and_multiturn_flags_parity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import main as main_mod
    import rfc_hunt_swarm as swarm_mod

    main_help = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert main_help.returncode == 0
    all_help = subprocess.run(
        [sys.executable, "main.py", "all", "--help"],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert all_help.returncode == 0
    combined_main_help = main_help.stdout + "\n" + all_help.stdout

    swarm_parser = swarm_mod.build_swarm_parser()
    swarm_help = swarm_parser.format_help()

    expected_flags = (
        "--enable-external-scanners",
        "--nuclei-tags",
        "--scanner-isolation",
        "--artex-multiturn",
        "--artex-intent-turns",
        "--artex-intent-tokens",
    )
    for flag in expected_flags:
        assert flag in combined_main_help, f"M4 flag {flag} missing from main.py CLI"
        assert flag in swarm_help, f"M4 flag {flag} missing from rfc_hunt_swarm.py CLI"

    swarm_defaults = swarm_parser.parse_args(["--all", "--repo", "."])
    assert getattr(swarm_defaults, "enable_external_scanners", None) is False
    assert getattr(swarm_defaults, "artex_multiturn", None) is False
    assert hasattr(main_mod, "cmd_all")


def test_f11_run_unified_all_scans_default_unchanged_without_opt_in(
    isolated_db: Any, subprocess_recorder: Any, tmp_path: Path
) -> None:
    sample_repo = tmp_path / "repo"
    sample_repo.mkdir()
    (sample_repo / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef h(): return {'ok': True}\n",
        encoding="utf-8",
    )
    res = run_unified_all_scans(
        repo=str(sample_repo),
        db=isolated_db,
        reports_dir=str(tmp_path / "reports"),
        quiet=True,
    )
    assert Path(res["report_files"]["combined_sarif"]).is_file()
    invoked_bins = [Path(c["argv"][0]).name.lower() for c in subprocess_recorder.calls]
    for ext_bin in ("httpx", "katana", "nuclei"):
        assert not any(b.startswith(ext_bin) for b in invoked_bins)


def test_f11_run_unified_all_scans_opt_in_blackbox_scanners_populate_graphs(
    isolated_db: Any, subprocess_recorder: Any, loopback_server: Any, tmp_path: Path
) -> None:
    sig = inspect.signature(run_unified_all_scans)
    params = set(sig.parameters.keys())
    opt_in_param = next(
        (p for p in ("enable_external_scanners", "external_scanners", "httpx_scan") if p in params),
        None,
    )
    assert opt_in_param is not None, (
        "M4 contract missing: run_unified_all_scans must accept opt-in external scanner parameter"
    )

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200, "tech": ["FastAPI"]}) + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout=json.dumps({"request": {"method": "POST", "endpoint": f"{loopback_server.url}/api/ai/chat"}}) + "\n",
    )
    subprocess_recorder.set_response(
        "nuclei",
        returncode=0,
        stdout=json.dumps(
            {
                "template-id": "exposed-admin-route",
                "info": {"name": "Exposed Admin Route", "severity": "medium", "tags": ["exposure"]},
                "matched-at": f"{loopback_server.url}/api/admin",
                "host": loopback_server.host,
            }
        )
        + "\n",
    )

    kwargs: Dict[str, Any] = {
        "host": loopback_server.host,
        "port": loopback_server.port,
        "use_tls": False,
        "authorized": True,
        "db": isolated_db,
        "reports_dir": str(tmp_path / "reports"),
        "quiet": True,
        opt_in_param: True,
    }
    for extra_flag in ("httpx_scan", "katana_scan", "nuclei_scan"):
        if extra_flag in params:
            kwargs[extra_flag] = True

    res = run_unified_all_scans(**kwargs)
    invoked = [Path(c["argv"][0]).name.lower() for c in subprocess_recorder.calls]
    assert any(b.startswith("httpx") for b in invoked)
    assert any(b.startswith("katana") for b in invoked)
    assert any(b.startswith("nuclei") for b in invoked)
    for call in subprocess_recorder.calls:
        assert call["shell"] is False

    sarif_path = Path(res["report_files"]["combined_sarif"])
    assert sarif_path.is_file()
    sarif_text = sarif_path.read_text(encoding="utf-8")
    assert "exposed-admin-route" in sarif_text or "Exposed Admin Route" in sarif_text


def test_f11_run_unified_all_scans_wires_multiturn_artex_worker(
    monkeypatch: pytest.MonkeyPatch, isolated_db: Any, loopback_server: Any, tmp_path: Path
) -> None:
    sig = inspect.signature(run_unified_all_scans)
    params = set(sig.parameters.keys())
    assert "artex_multiturn" in params, (
        "M4 contract missing: run_unified_all_scans(artex_multiturn=...)"
    )

    from engine.live_executors import LiveWorkerExecutorRegistry

    assert hasattr(LiveWorkerExecutorRegistry, "execute_candidate_multiturn"), (
        "M2 contract missing: LiveWorkerExecutorRegistry.execute_candidate_multiturn"
    )

    multiturn_calls = {"execute": 0, "as_fn": 0}
    orig_exec_mt = LiveWorkerExecutorRegistry.execute_candidate_multiturn

    def _spy_exec_mt(self: Any, *args: Any, **kwargs: Any) -> Any:
        multiturn_calls["execute"] += 1
        return orig_exec_mt(self, *args, **kwargs)

    monkeypatch.setattr(LiveWorkerExecutorRegistry, "execute_candidate_multiturn", _spy_exec_mt)
    if hasattr(LiveWorkerExecutorRegistry, "as_multiturn_executor_fn"):
        orig_as_mt_fn = LiveWorkerExecutorRegistry.as_multiturn_executor_fn

        def _spy_as_mt_fn(self: Any, *args: Any, **kwargs: Any) -> Any:
            multiturn_calls["as_fn"] += 1
            return orig_as_mt_fn(self, *args, **kwargs)

        monkeypatch.setattr(LiveWorkerExecutorRegistry, "as_multiturn_executor_fn", _spy_as_mt_fn)

    sample_repo = tmp_path / "repo"
    sample_repo.mkdir()
    (sample_repo / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "import subprocess\n"
        "app = FastAPI()\n"
        "@app.get('/api/admin')\n"
        "def admin(cmd: str):\n"
        "    return subprocess.check_output(cmd, shell=True)\n",
        encoding="utf-8",
    )

    kwargs: Dict[str, Any] = {
        "repo": str(sample_repo),
        "host": loopback_server.host,
        "port": loopback_server.port,
        "use_tls": False,
        "authorized": True,
        "db": isolated_db,
        "reports_dir": str(tmp_path / "reports"),
        "artex_live": True,
        "artex_multiturn": True,
        "quiet": True,
    }
    if "artex_intent_turns" in params:
        kwargs["artex_intent_turns"] = 2
    if "artex_intent_tokens" in params:
        kwargs["artex_intent_tokens"] = 5000

    loopback_server.reset()
    res = run_unified_all_scans(**kwargs)
    chaining = res.get("attack_chaining") or {}
    assert chaining.get("task_id")
    assert Path(res["report_files"]["combined_json"]).is_file()
    assert len(loopback_server.requests) >= 1, (
        "run_unified_all_scans(artex_multiturn=True) must execute live probes against loopback_server"
    )
    assert multiturn_calls["execute"] >= 1 or multiturn_calls["as_fn"] >= 1, (
        "run_unified_all_scans(artex_multiturn=True) must invoke LiveWorkerExecutorRegistry multi-turn path"
    )
    assert chaining.get("worker_traces_count", 0) >= 1
    assert len(isolated_db.list_worker_traces(task_id=chaining["task_id"])) >= 1


def test_f11_cmd_all_main_and_swarm_forward_opt_in_args_and_emit_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import main as main_mod
    import rfc_hunt_swarm as swarm_mod

    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    recorded_calls: List[Dict[str, Any]] = []

    def _spy_run_all(**kwargs: Any) -> Dict[str, Any]:
        recorded_calls.append(kwargs)
        return {
            "target_path": kwargs.get("host") or kwargs.get("repo") or ".",
            "fusion_enabled": True,
            "abliterated_model": "mock-model",
            "total_aggregated_findings": 0,
            "severity_counts": {},
            "attack_chaining": {"task_id": "T-SPY", "chains_synthesized": 0, "exploits_verified": 0},
            "report_files": {"combined_sarif": str(tmp_path / "c.sarif"), "combined_json": str(tmp_path / "c.json")},
        }

    monkeypatch.setattr("engine.mantis_integrator.run_unified_all_scans", _spy_run_all)

    ns = SimpleNamespace(
        db=str(tmp_path / "spy.db"),
        host="127.0.0.1",
        target=None,
        targets=None,
        repo=None,
        path=None,
        port=8080,
        tls=False,
        authorized=True,
        allow_destructive=False,
        depth=100,
        mantis_mode="full",
        output_dir=str(tmp_path / "rep"),
        artex_rounds=1,
        artex_url=None,
        artex_token=None,
        artex_proxy=None,
        artex_ca_cert=None,
        artex_noise_profile="quiet",
        artex_llm_profiles=None,
        artex_llm_rotate=False,
        artex_wait_sse=False,
        artex_budget_turns=0,
        artex_retest=False,
        artex_workers=1,
        artex_live=False,
        no_artex_live=True,
        embedded_proxy=False,
        embedded_proxy_port=0,
        auth_profile=None,
        import_har=None,
        import_openapi=None,
        scope_file=None,
        approval_mode="policy",
        approval_rules=None,
        strict_poe=False,
        export_advisory=False,
        export_csv=False,
        as_json=True,
        plain=True,
        model=None,
        enable_external_scanners=True,
        httpx_scan=True,
        katana_scan=True,
        nuclei_scan=True,
        nuclei_tags="tech,headers",
        scanner_isolation="host",
        artex_multiturn=True,
        artex_intent_turns=3,
        artex_intent_tokens=4000,
    )

    main_mod.cmd_all(ns)
    out_main = json.loads(capsys.readouterr().out)
    assert out_main["attack_chaining"]["task_id"] == "T-SPY"

    swarm_mod.cmd_all(ns)
    out_swarm = json.loads(capsys.readouterr().out)
    assert out_swarm["attack_chaining"]["task_id"] == "T-SPY"

    assert len(recorded_calls) == 2
    for call_kwargs in recorded_calls:
        assert call_kwargs.get("artex_multiturn") is True, (
            "M4 contract missing: cmd_all must forward artex_multiturn to run_unified_all_scans"
        )
        assert any(
            call_kwargs.get(k) is True
            for k in ("enable_external_scanners", "external_scanners", "httpx_scan")
        ), "M4 contract missing: cmd_all must forward opt-in external scanner flags"
        ntags = call_kwargs.get("nuclei_tags")
        assert ntags == "tech,headers" or list(ntags or []) == ["tech", "headers"], (
            f"M4 contract missing: cmd_all must forward nuclei_tags, got {ntags!r}"
        )
        assert call_kwargs.get("scanner_isolation") == "host", (
            f"M4 contract missing: cmd_all must forward scanner_isolation, got {call_kwargs.get('scanner_isolation')!r}"
        )
        assert call_kwargs.get("artex_intent_turns") == 3, (
            f"M4 contract missing: cmd_all must forward artex_intent_turns, got {call_kwargs.get('artex_intent_turns')!r}"
        )
        assert call_kwargs.get("artex_intent_tokens") == 4000, (
            f"M4 contract missing: cmd_all must forward artex_intent_tokens, got {call_kwargs.get('artex_intent_tokens')!r}"
        )


def test_f11_all_unauthorized_host_fails_closed_before_external_scanners(
    isolated_db: Any, subprocess_recorder: Any, tmp_path: Path
) -> None:
    sig = inspect.signature(run_unified_all_scans)
    params = set(sig.parameters.keys())
    opt_kwargs: Dict[str, Any] = {}
    for p in ("enable_external_scanners", "httpx_scan", "katana_scan", "nuclei_scan"):
        if p in params:
            opt_kwargs[p] = True

    with pytest.raises(PermissionError):
        run_unified_all_scans(
            host="10.0.0.1",
            port=80,
            authorized=True,
            db=isolated_db,
            reports_dir=str(tmp_path / "r1"),
            quiet=True,
            **opt_kwargs,
        )

    with pytest.raises(PermissionError):
        run_unified_all_scans(
            host="target.example.com",
            port=443,
            authorized=False,
            db=isolated_db,
            reports_dir=str(tmp_path / "r2"),
            quiet=True,
            **opt_kwargs,
        )

    assert len(subprocess_recorder.calls) == 0


# =============================================================================
# Feature F12: Standalone CLI Subcommands & Pure-CLI Rendering (6 tests)
# =============================================================================


def test_f12_main_exposes_standalone_scanner_and_artex_loop_subcommands() -> None:
    help_proc = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert help_proc.returncode == 0
    scanner_cmd = _find_scanner_subcommand(help_proc.stdout)
    assert scanner_cmd is not None, (
        "M4 contract missing: main.py must expose a standalone external scanner subcommand (e.g. scanner/discover/nuclei-scan)"
    )

    sub_help = subprocess.run(
        [sys.executable, "main.py", scanner_cmd, "--help"],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert sub_help.returncode == 0
    assert "--json" in sub_help.stdout
    assert "--plain" in sub_help.stdout

    artex_help = subprocess.run(
        [sys.executable, "main.py", "artex", "--help"],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    combined = help_proc.stdout + "\n" + artex_help.stdout
    loop_cmd = _find_artex_loop_subcommand(combined)
    assert loop_cmd is not None, (
        "M4 contract missing: main.py must expose artex-loop subcommand or --artex-multiturn on artex"
    )


def test_f12_standalone_scanner_subcommand_json_output_offline(
    monkeypatch: pytest.MonkeyPatch,
    subprocess_recorder: Any,
    loopback_server: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import main as main_mod

    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    help_text = _get_main_help(monkeypatch, capsys)
    scanner_cmd = _find_scanner_subcommand(help_text)
    assert scanner_cmd is not None, "M4 standalone scanner subcommand not implemented"

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_server.url}/health", "status_code": 200}) + "\n",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--db",
            str(tmp_path / "cli_scanner.db"),
            scanner_cmd,
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
            "--enable-external-scanners",
            "--json",
        ],
    )
    main_mod.main()
    out = capsys.readouterr().out
    assert "\x1b[" not in out
    parsed = json.loads(out)
    assert isinstance(parsed, (dict, list))


def test_f12_standalone_scanner_subcommand_plain_ascii_output(
    monkeypatch: pytest.MonkeyPatch,
    subprocess_recorder: Any,
    loopback_server: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import main as main_mod

    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    help_text = _get_main_help(monkeypatch, capsys)
    scanner_cmd = _find_scanner_subcommand(help_text)
    assert scanner_cmd is not None, "M4 standalone scanner subcommand not implemented"

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200}) + "\n",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--db",
            str(tmp_path / "cli_plain.db"),
            scanner_cmd,
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
            "--enable-external-scanners",
            "--plain",
        ],
    )
    main_mod.main()
    out = capsys.readouterr().out
    assert "\x1b[" not in out
    assert len(out.strip()) > 0
    assert "tkinter" not in sys.modules


def test_f12_standalone_artex_multiturn_cli_json_and_plain_modes(
    monkeypatch: pytest.MonkeyPatch,
    loopback_server: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import main as main_mod
    from database import Database

    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    main_help = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    artex_help = subprocess.run(
        [sys.executable, "main.py", "artex", "--help"],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    combined_help = (main_help.stdout or "") + "\n" + (artex_help.stdout or "")
    loop_cmd = _find_artex_loop_subcommand(combined_help)
    assert loop_cmd is not None, (
        "M4 contract missing: main.py must expose --artex-multiturn on artex or artex-loop subcommand"
    )

    def _build_argv(db_file: Path, out_dir: Path, mode_flag: str) -> List[str]:
        if loop_cmd == "artex":
            return [
                "main.py",
                "--db",
                str(db_file),
                "artex",
                "--host",
                loopback_server.host,
                "--port",
                str(loopback_server.port),
                "--authorized",
                "--artex-live",
                "--artex-multiturn",
                "--artex-intent-turns",
                "2",
                "--output-dir",
                str(out_dir),
                mode_flag,
            ]
        sub_help_proc = subprocess.run(
            [sys.executable, "main.py", loop_cmd, "--help"],
            cwd=_REPO_ROOT,
            env=_offline_env(),
            capture_output=True,
            text=True,
            timeout=30,
        )
        sub_help_txt = sub_help_proc.stdout or ""
        argv = [
            "main.py",
            "--db",
            str(db_file),
            loop_cmd,
            "--host",
            loopback_server.host,
            "--port",
            str(loopback_server.port),
            "--authorized",
        ]
        if "--artex-live" in sub_help_txt:
            argv.append("--artex-live")
        if "--artex-multiturn" in sub_help_txt:
            argv.append("--artex-multiturn")
        if "--artex-intent-turns" in sub_help_txt:
            argv.extend(["--artex-intent-turns", "2"])
        elif "--max-turns" in sub_help_txt:
            argv.extend(["--max-turns", "2"])
        if "--output-dir" in sub_help_txt:
            argv.extend(["--output-dir", str(out_dir)])
        argv.append(mode_flag)
        return argv

    db_file = tmp_path / "cli_mt.db"
    loopback_server.reset()
    monkeypatch.setattr(sys, "argv", _build_argv(db_file, tmp_path / "rep_json", "--json"))
    main_mod.main()
    json_out = capsys.readouterr().out
    parsed = json.loads(json_out)
    res_obj = parsed.get("result") if isinstance(parsed.get("result"), dict) else {}
    task_id = parsed.get("task_id") or res_obj.get("task_id")
    assert task_id, f"Expected task_id in top-level or result dict, got {parsed!r}"
    assert len(loopback_server.requests) >= 1, (
        "Standalone multi-turn CLI run must probe loopback_server"
    )
    traces_count = parsed.get("worker_traces_count")
    if traces_count is None:
        traces_count = res_obj.get("worker_traces_count")
    check_db = Database(str(db_file), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        db_traces = check_db.list_worker_traces(task_id=task_id)
    finally:
        check_db.close()
    assert (traces_count or 0) >= 1 or len(db_traces) >= 1, (
        f"Expected >=1 worker trace from multi-turn CLI run, got count={traces_count!r}, db={len(db_traces)}"
    )

    loopback_server.reset()
    monkeypatch.setattr(sys, "argv", _build_argv(db_file, tmp_path / "rep_plain", "--plain"))
    main_mod.main()
    plain_out = capsys.readouterr().out
    assert "\x1b[" not in plain_out
    assert len(loopback_server.requests) >= 1
    if loop_cmd == "artex":
        assert "POE" in plain_out
    else:
        assert "POE" in plain_out or "trace" in plain_out.lower() or "turn" in plain_out.lower()


def test_f12_cli_render_tty_vs_ci_plain_and_json_contract(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli_render._use_rich(plain=True) is False
    assert cli_render._use_rich(plain=False) is False  # CI=true active

    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    if cli_render._RICH_AVAILABLE:
        assert cli_render._use_rich(plain=False) is True
    assert cli_render._use_rich(plain=True) is False

    tbl_json = cli_render.render_table(
        "Scanners",
        ["Name", "Status"],
        [["httpx", "ok"]],
        as_json=True,
    )
    assert json.loads(tbl_json) == [{"Name": "httpx", "Status": "ok"}]

    with cli_render.LiveScanProgress(plain=True) as prog:
        prog.update("httpx", "DONE", "2 endpoints")
    captured = capsys.readouterr().out
    assert "[httpx] DONE - 2 endpoints" in captured


def test_f12_standalone_cli_rejects_unauthorized_target_and_invalid_tags_exit_nonzero(
    tmp_path: Path,
) -> None:
    help_proc = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    scanner_cmd = _find_scanner_subcommand(help_proc.stdout)
    assert scanner_cmd is not None, "M4 standalone scanner subcommand not implemented"

    db_file = str(tmp_path / "cli_reject.db")
    ssrf_proc = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--db",
            db_file,
            scanner_cmd,
            "--host",
            "169.254.169.254",
            "--authorized",
            "--enable-external-scanners",
        ],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    ssrf_out = (ssrf_proc.stdout + "\n" + ssrf_proc.stderr).lower()
    assert ssrf_proc.returncode != 0
    assert "unrecognized arguments" not in ssrf_out, (
        f"Argparse failure masked SSRF validation: {ssrf_proc.stderr!r}"
    )
    assert any(
        tok in ssrf_out
        for tok in ("ssrf", "target", "authoriz", "link-local", "private", "blocked", "denied", "169.254.169.254")
    ), f"Expected SSRF/target rejection message, got stdout={ssrf_proc.stdout!r} stderr={ssrf_proc.stderr!r}"

    bad_tag_proc = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--db",
            db_file,
            scanner_cmd,
            "--host",
            "127.0.0.1",
            "--authorized",
            "--enable-external-scanners",
            "--nuclei-tags",
            "exploit",
        ],
        cwd=_REPO_ROOT,
        env=_offline_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    tag_out = (bad_tag_proc.stdout + "\n" + bad_tag_proc.stderr).lower()
    assert bad_tag_proc.returncode != 0
    assert "unrecognized arguments" not in tag_out, (
        f"Argparse failure masked nuclei tag validation: {bad_tag_proc.stderr!r}"
    )
    assert any(
        tok in tag_out
        for tok in ("tag", "nuclei", "invalid", "destructive", "allowlist", "rejected", "exploit")
    ), f"Expected invalid tag rejection message, got stdout={bad_tag_proc.stdout!r} stderr={bad_tag_proc.stderr!r}"


# =============================================================================
# Feature F13: MCP Server Tools & Handlers (6 tests)
# =============================================================================


def test_f13_mcp_tools_list_exposes_multiturn_and_external_scanner_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_list.db")) as srv:
        tools = _mcp_tools_by_name(srv)
        for name in ("external_httpx_discover", "external_katana_crawl", "external_nuclei_scan"):
            assert name in tools, f"M4 MCP tool {name} missing from tools/list"
            assert isinstance(tools[name].get("inputSchema"), dict)

        has_multiturn_tool = "artex_run_multiturn_worker" in tools
        chain_props = tools.get("artex_run_attack_chain", {}).get("inputSchema", {}).get("properties", {})
        has_multiturn_props = any(
            k in chain_props for k in ("multiturn", "artex_multiturn", "max_intent_turns", "max_turns")
        )
        assert has_multiturn_tool or has_multiturn_props, (
            "M4 MCP contract missing: artex_run_multiturn_worker or multi-turn params on artex_run_attack_chain"
        )


def test_f13_mcp_external_httpx_and_katana_discover_populate_asset_graph(
    monkeypatch: pytest.MonkeyPatch,
    subprocess_recorder: Any,
    loopback_server: Any,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200, "tech": ["FastAPI"]}) + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout=json.dumps({"request": {"method": "GET", "endpoint": f"{loopback_server.url}/app.js"}}) + "\n",
    )

    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_disc.db")) as srv:
        r_httpx = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "external_httpx_discover",
                    "arguments": {
                        "host": loopback_server.host,
                        "port": loopback_server.port,
                        "use_tls": False,
                        "authorized": True,
                        "enabled": True,
                    },
                },
            }
        )
        assert "result" in r_httpx
        p_httpx = json.loads(r_httpx["result"]["content"][0]["text"])
        assert "/api/public" in json.dumps(p_httpx)

        r_katana = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "external_katana_crawl",
                    "arguments": {
                        "host": loopback_server.host,
                        "port": loopback_server.port,
                        "use_tls": False,
                        "authorized": True,
                        "enabled": True,
                    },
                },
            }
        )
        assert "result" in r_katana
        p_katana = json.loads(r_katana["result"]["content"][0]["text"])
        assert "/app.js" in json.dumps(p_katana)

    assert len(subprocess_recorder.calls) == 2
    for call in subprocess_recorder.calls:
        assert call["shell"] is False
        assert "-rl" in call["argv"]


def test_f13_mcp_external_nuclei_scan_ingests_findings_and_blocks_destructive_tags(
    monkeypatch: pytest.MonkeyPatch,
    subprocess_recorder: Any,
    loopback_server: Any,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    subprocess_recorder.set_response(
        "nuclei",
        returncode=0,
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

    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_nuclei.db")) as srv:
        bad_resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {
                    "name": "external_nuclei_scan",
                    "arguments": {
                        "host": loopback_server.host,
                        "port": loopback_server.port,
                        "authorized": True,
                        "enabled": True,
                        "tags": ["exploit"],
                    },
                },
            }
        )
        assert "error" in bad_resp
        assert bad_resp["error"]["code"] in (-32602, -32001)
        assert len(subprocess_recorder.calls) == 0

        ok_resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {
                    "name": "external_nuclei_scan",
                    "arguments": {
                        "host": loopback_server.host,
                        "port": loopback_server.port,
                        "use_tls": False,
                        "authorized": True,
                        "enabled": True,
                        "tags": ["tech", "misconfig"],
                    },
                },
            }
        )
        assert "result" in ok_resp
        parsed = json.loads(ok_resp["result"]["content"][0]["text"])
        assert "tech-fastapi" in json.dumps(parsed) or "FastAPI Detected" in json.dumps(parsed)


def test_f13_mcp_multiturn_artex_worker_executes_bounded_loop(
    monkeypatch: pytest.MonkeyPatch, loopback_server: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_mt.db")) as srv:
        tools = _mcp_tools_by_name(srv)
        if "artex_run_multiturn_worker" in tools:
            tool_name = "artex_run_multiturn_worker"
            args = {
                "host": loopback_server.host,
                "port": loopback_server.port,
                "use_tls": False,
                "authorized": True,
                "target_route": "/api/admin",
                "attack_type": "AUTH_BOUNDARY",
                "max_intent_turns": 2,
                "reports_dir": str(tmp_path / "rep"),
            }
        else:
            chain_props = tools.get("artex_run_attack_chain", {}).get("inputSchema", {}).get("properties", {})
            assert any(
                k in chain_props for k in ("multiturn", "artex_multiturn", "max_intent_turns", "max_turns")
            ), (
                "M4 MCP contract missing: artex_run_multiturn_worker or multi-turn params on artex_run_attack_chain"
            )
            tool_name = "artex_run_attack_chain"
            args = {
                "host": loopback_server.host,
                "port": loopback_server.port,
                "use_tls": False,
                "authorized": True,
                "multiturn": True,
                "artex_multiturn": True,
                "max_intent_turns": 2,
                "findings": [
                    {
                        "rule_id": "MANTIS-AUTH-001",
                        "title": "Admin Auth Boundary",
                        "cwe": "CWE-287",
                        "file_path": "/api/admin",
                    }
                ],
                "reports_dir": str(tmp_path / "rep"),
            }

        loopback_server.reset()
        resp = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": args},
            }
        )
        assert "result" in resp, f"Expected result for {tool_name}, got {resp!r}"
        data = json.loads(resp["result"]["content"][0]["text"])
        assert isinstance(data, dict)
        assert "task_id" in data or "traces" in data or "worker_traces_count" in data
        assert len(loopback_server.requests) >= 1, (
            "MCP multi-turn worker execution must probe loopback_server (hollow no-op rejected)"
        )
        task_id = data.get("task_id")
        db_traces = srv.db.list_worker_traces(task_id=task_id) if task_id else srv.db.list_worker_traces()
        traces_field = data.get("traces")
        traces_count = data.get("worker_traces_count", 0)
        assert (
            len(db_traces) >= 1
            or (isinstance(traces_field, list) and len(traces_field) >= 1)
            or (isinstance(traces_count, int) and traces_count >= 1)
        ), f"Expected >=1 worker trace from MCP multi-turn execution, got data={data!r}, db_traces={len(db_traces)}"


def test_f13_mcp_target_authorization_and_disabled_opt_in_gating(
    monkeypatch: pytest.MonkeyPatch,
    subprocess_recorder: Any,
    loopback_server: Any,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_auth.db")) as srv:
        r_unauth = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 40,
                "method": "tools/call",
                "params": {
                    "name": "external_httpx_discover",
                    "arguments": {
                        "host": "unauthorized.example.com",
                        "authorized": False,
                        "enabled": True,
                    },
                },
            }
        )
        assert "error" in r_unauth
        assert r_unauth["error"]["code"] == -32001

        r_ssrf = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "external_nuclei_scan",
                    "arguments": {
                        "host": "10.0.0.1",
                        "authorized": True,
                        "enabled": True,
                    },
                },
            }
        )
        assert "error" in r_ssrf
        assert r_ssrf["error"]["code"] == -32001

        r_disabled = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": "external_httpx_discover",
                    "arguments": {
                        "host": loopback_server.host,
                        "port": loopback_server.port,
                        "authorized": True,
                        "enabled": False,
                    },
                },
            }
        )
        assert "result" in r_disabled
        disabled_payload = json.loads(r_disabled["result"]["content"][0]["text"])
        assert disabled_payload.get("status") == "disabled"
        assert len(subprocess_recorder.calls) == 0


def test_f13_mcp_http_and_stdio_jsonrpc_error_mapping_and_approval_gate(
    monkeypatch: pytest.MonkeyPatch,
    subprocess_recorder: Any,
    loopback_server: Any,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ARTEX_SECRET_KEY", _TEST_HEX_KEY)
    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_err.db")) as srv:
        # Unknown tool -> -32602
        unk = srv.handle_request(
            {"jsonrpc": "2.0", "id": 50, "method": "tools/call", "params": {"name": "nonexistent_tool", "arguments": {}}}
        )
        assert unk["error"]["code"] == -32602

        # Rate-limit/runtime -> -32029
        def _raise_runtime(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("Rate limit simulated")

        monkeypatch.setattr(srv, "_execute_tool", _raise_runtime)
        rt = srv.handle_request(
            {"jsonrpc": "2.0", "id": 51, "method": "tools/call", "params": {"name": "get_database_stats", "arguments": {}}}
        )
        assert rt["error"]["code"] == -32029

        # Internal exception -> sanitized -32000
        def _raise_key(*args: Any, **kwargs: Any) -> Any:
            raise KeyError("secret-internal-key")

        monkeypatch.setattr(srv, "_execute_tool", _raise_key)
        internal = srv.handle_request(
            {"jsonrpc": "2.0", "id": 52, "method": "tools/call", "params": {"name": "get_database_stats", "arguments": {}}}
        )
        assert internal["error"]["code"] == -32000
        assert "secret-internal-key" not in internal["error"]["message"]

    # HTTP Bearer auth check + ApprovalGate deny on external scanner tool
    with TerminatorMCPServer(db_path=str(tmp_path / "mcp_http.db")) as srv2:
        http_srv = MCPHttpServer(srv2, host="127.0.0.1", port=0, bearer_token="test-mcp-token")
        http_srv.start()
        try:
            req_unauth = urllib.request.Request(
                f"http://127.0.0.1:{http_srv.port}/http",
                data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_unauth, timeout=5)
            assert exc_info.value.code == 401

            # Verify ApprovalGate deny mode blocks external_httpx_discover fail-closed
            resp_denied = srv2.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 53,
                    "method": "tools/call",
                    "params": {
                        "name": "external_httpx_discover",
                        "arguments": {
                            "host": loopback_server.host,
                            "port": loopback_server.port,
                            "authorized": True,
                            "enabled": True,
                            "approval_mode": "deny",
                        },
                    },
                }
            )
            assert "error" in resp_denied
            assert "Unknown tool" not in resp_denied["error"]["message"]
            assert resp_denied["error"]["code"] in (-32001, -32000)
            assert len(subprocess_recorder.calls) == 0
        finally:
            http_srv.stop()
