"""
Offline unit & integration tests for M3 `engine/external_scanners.py`
(Features F8, F9, F10).

Runs strictly offline (`CI=true`, `RFCHUNT_OFFLINE=1`) using isolated SQLite
databases, clean singleton/env teardown, and `subprocess.run` interception
over `silent_subprocess_run`.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterator, List

import pytest

from database import Database
from engine.approval_gate import ApprovalGate, ApprovalRule
from engine.dual_graph_engine import (
    AssetGraph,
    DualGraphAttackEngine,
    NoiseGovernor,
)
from engine.execution_policy import ExecutionPolicy
from engine.external_scanners import (
    DEFAULT_NUCLEI_TAGS,
    ExternalScannerConfig,
    HttpxScannerAdapter,
    KatanaScannerAdapter,
    NucleiScannerAdapter,
    ScannerExecutionResult,
    run_opt_in_external_discovery,
    run_opt_in_nuclei_scan,
)
from engine.host_containment import CREATE_NO_WINDOW
from engine.session_loader import import_openapi_spec
from mcp_server import TargetAuthorizationGate


@pytest.fixture(autouse=True)
def _reset_singletons_and_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    orig_targets = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    orig_history = {
        k: list(v) for k, v in TargetAuthorizationGate._request_history.items()
    }
    ExecutionPolicy.reset_instance()
    TargetAuthorizationGate.ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}
    TargetAuthorizationGate._request_history.clear()
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
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
    db_path = tmp_path / "ext_scanner_test.db"
    key_path = tmp_path / "keys" / "secret.key"
    db = Database(str(db_path), secret_key_path=str(key_path))
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def subprocess_recorder(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    calls: List[Dict[str, Any]] = []
    responses: Dict[str, Any] = {}

    def _norm(tok: str) -> str:
        name = Path(str(tok).replace("\\", "/")).name.lower()
        return name[:-4] if name.endswith(".exe") else name

    def set_response(
        binary: str,
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        exc: Exception | None = None,
    ) -> None:
        responses[_norm(binary)] = {
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr,
            "exc": exc,
        }

    def _fake_run(args: Any, *pos: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        assert kwargs.get("shell", False) is False
        assert isinstance(args, list) and len(args) >= 1
        calls.append(
            {
                "argv": list(args),
                "shell": kwargs.get("shell", False),
                "kwargs": dict(kwargs),
            }
        )
        key = _norm(args[0])
        resp = responses.get(key)
        if resp is None and key == "docker":
            for tok in args[1:]:
                t_norm = _norm(str(tok).split(":")[0])
                if t_norm in responses:
                    resp = responses[t_norm]
                    break
        if resp is None:
            resp = {"returncode": 0, "stdout": "", "stderr": "", "exc": None}
        if resp.get("exc") is not None:
            raise resp["exc"]
        return subprocess.CompletedProcess(
            args=list(args),
            returncode=resp["returncode"],
            stdout=resp["stdout"],
            stderr=resp["stderr"],
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    return SimpleNamespace(calls=calls, set_response=set_response)


# =============================================================================
# Feature F8: Opt-In, Binary Allowlist, Flags, Tags, Auth, Gate, NoiseGovernor
# =============================================================================


def test_disabled_by_default_noop(subprocess_recorder: Any) -> None:
    default_cfg = ExternalScannerConfig()
    assert default_cfg.enabled is False

    bad_disabled_cfg = ExternalScannerConfig(
        enabled=False,
        binary_path="/tmp/evil/sqlmap",
        nuclei_tags=("rce",),
    )

    for res in (
        HttpxScannerAdapter(config=bad_disabled_cfg).run("http://127.0.0.1:8080", authorized=True),
        KatanaScannerAdapter(config=bad_disabled_cfg).run("http://127.0.0.1:8080", authorized=True),
        NucleiScannerAdapter(config=bad_disabled_cfg).run("http://127.0.0.1:8080", authorized=True),
    ):
        assert isinstance(res, ScannerExecutionResult)
        assert res.status == "disabled"
        assert res.ok is False
        assert res.to_dict()["status"] == "disabled"

    disc = run_opt_in_external_discovery(
        "http://127.0.0.1:8080", config=bad_disabled_cfg, authorized=True
    )
    nuc = run_opt_in_nuclei_scan(
        "http://127.0.0.1:8080", config=bad_disabled_cfg, authorized=True
    )
    assert disc["status"] == "disabled" and disc["ok"] is False
    assert nuc["status"] == "disabled" and nuc["ok"] is False
    assert len(subprocess_recorder.calls) == 0


@pytest.mark.parametrize(
    "bad_bin",
    [
        "nmap",
        "ffuf",
        "dalfox",
        "sqlmap",
        "/usr/bin/nmap",
        "/tmp/evil/sqlmap",
        "bash",
        "sh",
        "cmd.exe",
        "powershell.exe",
        "python3",
        "curl",
        "../httpx",
        " httpx",
        "httpx.bat",
        "httpx.cmd",
        "httpx.ps1",
        "httpx.py",
        "katana",
    ],
)
def test_rejects_non_allowlisted_excluded_and_cross_tool_binaries(
    bad_bin: str, subprocess_recorder: Any
) -> None:
    cfg = ExternalScannerConfig(enabled=True, binary_path=bad_bin)
    with pytest.raises((PermissionError, ValueError)):
        adapter = HttpxScannerAdapter(config=cfg)
        adapter.run("http://127.0.0.1:8080", authorized=True)
    assert len(subprocess_recorder.calls) == 0


def test_rejects_symlink_spoofed_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, subprocess_recorder: Any
) -> None:
    fake_bin = tmp_path / "httpx.exe"
    fake_bin.write_text("", encoding="utf-8")

    orig_resolve = Path.resolve

    def _spoofed_resolve(self: Path, strict: bool = False) -> Path:
        if self == fake_bin:
            return tmp_path / "sqlmap.exe"
        return orig_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _spoofed_resolve)

    cfg = ExternalScannerConfig(enabled=True, binary_path=str(fake_bin))
    with pytest.raises((PermissionError, ValueError)):
        HttpxScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)
    assert len(subprocess_recorder.calls) == 0


@pytest.mark.parametrize(
    "bad_flags",
    [
        ["-exec", "whoami"],
        ["-o", "/etc/passwd"],
        ["--arbitrary"],
        ["-u;whoami"],
        ["-H", "X: $(id)"],
        ["-H", "X: a|cat"],
        ["-timeout", "999999"],
        ["-proxy", "http://127.0.0.1:8081"],
        "not-a-list",
    ],
)
def test_rejects_invalid_and_injected_extra_flags(
    bad_flags: Any, subprocess_recorder: Any
) -> None:
    adapter = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True))
    with pytest.raises((PermissionError, ValueError, TypeError)):
        adapter.run("http://127.0.0.1:8080", authorized=True, extra_flags=bad_flags)
    assert len(subprocess_recorder.calls) == 0


def test_extra_flags_cannot_bypass_noise_governor_rl(subprocess_recorder: Any) -> None:
    adapter = HttpxScannerAdapter(
        config=ExternalScannerConfig(enabled=True),
        noise_governor=NoiseGovernor(profile="quiet"),  # rps=2.0
    )
    with pytest.raises(ValueError):
        adapter.run(
            "http://127.0.0.1:8080",
            authorized=True,
            extra_flags=["-rl", "50"],
        )
    assert len(subprocess_recorder.calls) == 0


@pytest.mark.parametrize(
    "bad_tags",
    [
        ("dos",),
        ("DoS",),
        ("fuzz",),
        ("exploit",),
        ("rce",),
        ("RCE",),
        ("sqli",),
        ("xss",),
        ("ssti",),
        ("ssrf",),
        ("lfi",),
        ("xxe",),
        ("bruteforce",),
        ("intrusive",),
        ("interactsh",),
        ("takeover",),
        ("tech,exploit",),
        ("Headers,FUZZ",),
        ("unknown-custom-tag",),
        ("",),
    ],
)
def test_nuclei_tag_allowlist_blocks_destructive_tags(
    bad_tags: tuple[str, ...], subprocess_recorder: Any
) -> None:
    with pytest.raises((PermissionError, ValueError)):
        cfg = ExternalScannerConfig(enabled=True, nuclei_tags=bad_tags)
        NucleiScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)
    assert len(subprocess_recorder.calls) == 0


def test_nuclei_empty_tuple_falls_back_to_safe_defaults(subprocess_recorder: Any) -> None:
    subprocess_recorder.set_response("nuclei", returncode=0, stdout="")
    cfg = ExternalScannerConfig(enabled=True, nuclei_tags=())
    res = NucleiScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)
    assert res.ok is True
    argv = subprocess_recorder.calls[0]["argv"]
    assert "-tags" in argv
    assert argv[argv.index("-tags") + 1] == ",".join(DEFAULT_NUCLEI_TAGS)


@pytest.mark.parametrize(
    ("bad_target", "auth_flag"),
    [
        ("http://169.254.169.254/latest/meta-data", True),
        ("http://10.0.0.1:8080", True),
        ("http://192.168.1.1:8080", True),
        ("http://0.0.0.0:8080", True),
        ("http://[::]:8080", True),
        ("http://[::ffff:169.254.169.254]/", True),
        ("http://[fe80::1]/", True),
        ("http://0x7f000001/", True),
        ("http://2130706433/", True),
        ("http://169.254.169.254\\@example.com/", True),
        ("file://127.0.0.1/etc/passwd", True),
        ("http://user:pass@127.0.0.1:8080/", True),
        ("https://unauthorized.example.com", False),
    ],
)
def test_target_authorization_and_ssrf_enforcement(
    bad_target: str, auth_flag: bool, subprocess_recorder: Any
) -> None:
    adapter = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True))
    with pytest.raises((PermissionError, ValueError)):
        adapter.run(bad_target, authorized=auth_flag)
    assert len(subprocess_recorder.calls) == 0


def test_approval_gate_deny_prompt_and_argv_prefix_rules(
    isolated_db: Database, subprocess_recorder: Any
) -> None:
    cfg = ExternalScannerConfig(enabled=True)

    with pytest.raises(PermissionError):
        HttpxScannerAdapter(
            config=cfg, approval_gate=ApprovalGate(mode="deny", db=isolated_db)
        ).run("http://127.0.0.1:8080", authorized=True)

    with pytest.raises(PermissionError):
        HttpxScannerAdapter(
            config=cfg,
            approval_gate=ApprovalGate(
                mode="prompt",
                db=isolated_db,
                input_fn=lambda _: "d",
                output_fn=lambda _: None,
            ),
        ).run("http://127.0.0.1:8080", authorized=True)

    deny_nuclei_gate = ApprovalGate(
        mode="policy",
        db=isolated_db,
        rules=[
            ApprovalRule(
                rule_id="DENY-NUCLEI",
                rule_type="argv_prefix",
                action="DENY",
                pattern=["nuclei"],
            )
        ],
    )
    with pytest.raises(PermissionError):
        NucleiScannerAdapter(config=cfg, approval_gate=deny_nuclei_gate).run(
            "http://127.0.0.1:8080", authorized=True
        )

    assert len(subprocess_recorder.calls) == 0


@pytest.mark.parametrize(
    ("profile", "expected_rl"),
    [("quiet", 2), ("balanced", 5), ("aggressive", 20), ("off", 5)],
)
def test_noise_governor_rl_derivation_and_bounds(
    profile: str, expected_rl: int, subprocess_recorder: Any
) -> None:
    subprocess_recorder.set_response("httpx", returncode=0, stdout="")
    gov = NoiseGovernor(profile=profile)
    res = HttpxScannerAdapter(
        config=ExternalScannerConfig(enabled=True),
        noise_governor=gov,
    ).run("http://127.0.0.1:8080", authorized=True)
    assert res.ok is True
    argv = subprocess_recorder.calls[0]["argv"]
    assert "-rl" in argv
    assert int(argv[argv.index("-rl") + 1]) == expected_rl

    # Non-positive explicit rate_limit rejected
    with pytest.raises(ValueError):
        ExternalScannerConfig(enabled=True, rate_limit=0)
    with pytest.raises(ValueError):
        ExternalScannerConfig(enabled=True, rate_limit=-5)


# =============================================================================
# Feature F9: Host shell=False & Docker shell=False Execution + Non-Shadowing
# =============================================================================


def test_host_mode_list_argv_shell_false_and_containment_kwargs(
    subprocess_recorder: Any,
) -> None:
    subprocess_recorder.set_response("httpx", returncode=0, stdout="")
    subprocess_recorder.set_response("katana", returncode=0, stdout="")
    subprocess_recorder.set_response("nuclei", returncode=0, stdout="")

    cfg = ExternalScannerConfig(enabled=True, execution_mode="host", rate_limit=4)
    HttpxScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)
    KatanaScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)
    NucleiScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)

    assert len(subprocess_recorder.calls) == 3
    for call in subprocess_recorder.calls:
        assert call["shell"] is False
        assert isinstance(call["argv"], list)
        assert "-jsonl" in call["argv"]
        assert "-rl" in call["argv"] and call["argv"][call["argv"].index("-rl") + 1] == "4"
        assert call["kwargs"].get("stdin") == subprocess.DEVNULL
        if sys.platform == "win32" or os.name == "nt":
            assert call["kwargs"].get("creationflags", 0) & CREATE_NO_WINDOW

    nuclei_argv = subprocess_recorder.calls[2]["argv"]
    assert "-no-interactsh" in nuclei_argv
    assert "-tags" in nuclei_argv


def test_docker_mode_list_argv_shell_false_rm_no_mounts_no_host_rewrite(
    subprocess_recorder: Any,
) -> None:
    subprocess_recorder.set_response("httpx", returncode=0, stdout="")
    subprocess_recorder.set_response("katana", returncode=0, stdout="")
    subprocess_recorder.set_response("nuclei", returncode=0, stdout="")

    cfg = ExternalScannerConfig(enabled=True, execution_mode="docker", rate_limit=3)
    HttpxScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)
    KatanaScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)
    NucleiScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)

    assert len(subprocess_recorder.calls) == 3
    for idx, expected_img in enumerate(
        (
            "projectdiscovery/httpx:latest",
            "projectdiscovery/katana:latest",
            "projectdiscovery/nuclei:latest",
        )
    ):
        call = subprocess_recorder.calls[idx]
        argv = call["argv"]
        assert call["shell"] is False
        assert Path(argv[0]).name.lower().startswith("docker")
        assert "run" in argv and "--rm" in argv
        assert expected_img in argv
        assert "-jsonl" in argv and "-rl" in argv
        assert "--privileged" not in argv
        assert "-v" not in argv and "--mount" not in argv
        assert "--network=host" not in argv
        assert "http://127.0.0.1:8080" in argv
        assert "host.docker.internal" not in " ".join(argv)


def test_docker_mode_rejects_invalid_mode_network_and_unsafe_images(
    subprocess_recorder: Any,
) -> None:
    for bad_mode in ("ssh", "podman", ""):
        with pytest.raises((ValueError, PermissionError)):
            cfg = ExternalScannerConfig(enabled=True, execution_mode=bad_mode)  # type: ignore[arg-type]
            HttpxScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)

    with pytest.raises(PermissionError):
        cfg = ExternalScannerConfig(
            enabled=True, execution_mode="docker", docker_network="host"
        )
        HttpxScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)

    for bad_img in (
        "",
        "   ",
        "alpine;id",
        "instrumentisto/nmap:latest",
        "projectdiscovery/httpx:latest --privileged",
        "secsi/sqlmap",
        "$(whoami)",
        "ubuntu:22.04",
        "projectdiscovery/katana:latest",
    ):
        with pytest.raises((PermissionError, ValueError)):
            cfg = ExternalScannerConfig(
                enabled=True, execution_mode="docker", docker_image=bad_img
            )
            HttpxScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)

    assert len(subprocess_recorder.calls) == 0


def test_error_handling_nonzero_exit_missing_binary_and_timeout(
    subprocess_recorder: Any,
) -> None:
    cfg = ExternalScannerConfig(enabled=True)

    subprocess_recorder.set_response(
        "httpx", returncode=2, stdout="", stderr="dial error"
    )
    err_res = HttpxScannerAdapter(config=cfg).run(
        "http://127.0.0.1:8080", authorized=True
    )
    assert err_res.ok is False
    assert err_res.status == "error"
    assert err_res.returncode == 2
    assert "dial error" in err_res.stderr

    subprocess_recorder.set_response(
        "katana", exc=FileNotFoundError("katana not on PATH")
    )
    nf_res = KatanaScannerAdapter(config=cfg).run(
        "http://127.0.0.1:8080", authorized=True
    )
    assert nf_res.ok is False
    assert nf_res.status == "binary_not_found"

    subprocess_recorder.set_response(
        "nuclei", exc=subprocess.TimeoutExpired(cmd=["nuclei"], timeout=5)
    )
    to_res = NucleiScannerAdapter(config=cfg).run(
        "http://127.0.0.1:8080", authorized=True
    )
    assert to_res.ok is False
    assert to_res.status == "timeout"


def test_python_httpx_package_not_shadowed() -> None:
    import httpx
    from engine import external_scanners

    assert hasattr(httpx, "Client")
    assert hasattr(httpx, "MockTransport")
    assert not hasattr(external_scanners, "httpx")
    assert hasattr(external_scanners, "HttpxScannerAdapter")


# =============================================================================
# Feature F10: JSONL Parsing -> AssetGraph & DualGraphAttackEngine
# =============================================================================


def test_httpx_jsonl_populates_asset_graph(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps(
                    {
                        "url": "http://127.0.0.1:8080/health",
                        "host": "127.0.0.1",
                        "port": "8080",
                        "status_code": 200,
                        "title": "Health",
                        "tech": ["FastAPI", "Uvicorn"],
                    }
                ),
                json.dumps(
                    {
                        "url": "http://127.0.0.1:8080/api/v1/chat",
                        "method": "POST",
                        "status-code": 200,
                        "technologies": ["OpenAI-Compat"],
                    }
                ),
            ]
        )
        + "\n",
    )

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    disc = run_opt_in_external_discovery(
        "http://127.0.0.1:8080",
        config=ExternalScannerConfig(enabled=True),
        asset_graph=eng.asset_graph,
        authorized=True,
        run_katana=False,
    )
    assert disc["status"] == "completed"
    assert "FastAPI" in disc["technologies"]
    assert len(eng.asset_graph.find_endpoints_by_type("DOMAIN")) == 1
    assert len(eng.asset_graph.find_endpoints_by_type("IP_PORT")) == 1
    assert len(eng.asset_graph.find_endpoints_by_type("ENDPOINT")) == 1
    assert len(eng.asset_graph.find_endpoints_by_type("AI_SINK")) == 1


def test_katana_jsonl_discovers_endpoints_js_and_ai_sinks(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"request": {"method": "GET", "endpoint": "http://127.0.0.1:8080/api/public"}}),
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": "http://127.0.0.1:8080/app.js", "tag": "script"},
                        "js_endpoints": ["/api/internal/metrics"],
                    }
                ),
                json.dumps({"request": {"method": "POST", "endpoint": "http://127.0.0.1:8080/api/ai/chat"}}),
            ]
        )
        + "\n",
    )

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    disc = run_opt_in_external_discovery(
        "http://127.0.0.1:8080",
        config=ExternalScannerConfig(enabled=True),
        asset_graph=eng.asset_graph,
        authorized=True,
        run_httpx=False,
    )
    assert "/app.js" in disc["js_endpoints"]
    assert "/api/internal/metrics" in disc["js_endpoints"]
    eps = eng.asset_graph.find_endpoints_by_type("ENDPOINT")
    sinks = eng.asset_graph.find_endpoints_by_type("AI_SINK")
    assert any(n.attributes.get("route") == "/api/internal/metrics" and n.attributes.get("is_service_route") for n in eps)
    assert any(n.attributes.get("route") == "/api/ai/chat" for n in sinks)


def test_asset_graph_deduplication_against_openapi_and_repeats(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "Lab", "version": "1.0"},
                "servers": [{"url": "http://127.0.0.1:8080"}],
                "paths": {
                    "/api/public": {"get": {"responses": {"200": {"description": "ok"}}}},
                    "/api/ai/chat": {"post": {"responses": {"200": {"description": "ok"}}}},
                },
            }
        ),
        encoding="utf-8",
    )
    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    import_openapi_spec(spec_file, asset_graph=eng.asset_graph)

    before_nodes = len(eng.asset_graph.nodes)
    before_edges = len(eng.asset_graph.edges)

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": "http://127.0.0.1:8080/api/public", "status_code": 200}) + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"request": {"method": "GET", "endpoint": "http://127.0.0.1:8080/api/public"}}),
                json.dumps({"request": {"method": "POST", "endpoint": "http://127.0.0.1:8080/api/ai/chat"}}),
            ]
        )
        + "\n",
    )

    run_opt_in_external_discovery(
        "http://127.0.0.1:8080",
        config=ExternalScannerConfig(enabled=True),
        asset_graph=eng.asset_graph,
        authorized=True,
    )
    assert len(eng.asset_graph.nodes) == before_nodes
    assert len(eng.asset_graph.edges) == before_edges


def test_asset_graph_scope_and_deny_routes_filtering(
    isolated_db: Database, subprocess_recorder: Any
) -> None:
    ag = AssetGraph(
        db=isolated_db,
        scope_hosts={"127.0.0.1"},
        deny_hosts={"evil.example.com"},
        deny_routes=["/internal", "/logout"],
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"request": {"method": "GET", "endpoint": "http://evil.example.com/admin"}}),
                json.dumps({"request": {"method": "GET", "endpoint": "http://other.example.com/v1"}}),
                json.dumps({"request": {"method": "GET", "endpoint": "http://127.0.0.1:8080/internal/secret"}}),
                json.dumps({"request": {"method": "GET", "endpoint": "http://127.0.0.1:8080/logout"}}),
                json.dumps({"request": {"method": "GET", "endpoint": "http://127.0.0.1:8080/api/public"}}),
            ]
        )
        + "\n",
    )

    run_opt_in_external_discovery(
        "http://127.0.0.1:8080",
        config=ExternalScannerConfig(enabled=True),
        asset_graph=ag,
        authorized=True,
        run_httpx=False,
    )
    labels = [n.label for n in ag.in_scope_assets()]
    assert labels == ["127.0.0.1", "127.0.0.1:8080", "GET /api/public"]


def test_nuclei_jsonl_ingests_into_dual_graph_and_avoids_false_desync(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    subprocess_recorder.set_response(
        "nuclei",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps(
                    {
                        "template-id": "tech-fastapi",
                        "info": {
                            "name": "FastAPI Detected",
                            "severity": "info",
                            "tags": ["tech"],
                        },
                        "matched-at": "http://127.0.0.1:8080/health",
                        "host": "127.0.0.1",
                    }
                ),
                json.dumps(
                    {
                        "template-id": "ssrf-pivot-check",
                        "info": {
                            "name": "SSRF Metadata Pivot",
                            "severity": "critical",
                            "tags": ["exposure", "misconfig"],
                            "classification": {"cwe-id": ["CWE-918"]},
                        },
                        "matched-at": "http://127.0.0.1:8080/api/fetch",
                        "host": "127.0.0.1",
                        "extracted-results": ["http://169.254.169.254"],
                        "curl-command": "curl -s http://127.0.0.1:8080/api/fetch",
                    }
                ),
            ]
        )
        + "\n",
    )

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    eng.ingest_target_infrastructure(
        host="127.0.0.1", port=8080, endpoints=["/health", "/api/fetch"]
    )
    res = run_opt_in_nuclei_scan(
        "http://127.0.0.1:8080",
        config=ExternalScannerConfig(enabled=True, nuclei_tags=("tech", "exposure", "misconfig")),
        dual_graph_engine=eng,
        authorized=True,
    )
    assert res["ok"] is True
    assert res["total_findings"] == 2
    assert res["findings_ingested"] == 2

    primitives = [
        n
        for n in eng.exploration_graph.nodes.values()
        if n.node_type == "FINDING_PRIMITIVE"
    ]
    by_rule = {p.attributes["rule_id"]: p for p in primitives}
    assert by_rule["tech-fastapi"].attributes["capability_class"] == "RECON_TECH"
    assert by_rule["ssrf-pivot-check"].attributes["capability_class"] == "SSRF_PIVOT"
    assert by_rule["ssrf-pivot-check"].attributes["severity"] == "CRITICAL"
    assert len(eng.trace_store.traces) == 2


def test_malformed_empty_whitespace_and_partial_jsonl_resilience(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    mixed = "\n".join(
        [
            "",
            "   \t  ",
            "[INF] banner line",
            "{corrupt json",
            "[1, 2, 3]",
            "null",
            '"plain-string"',
            json.dumps({"status_code": 200}),
            json.dumps({"url": "http://127.0.0.1:8080/api/public", "status_code": 200}),
        ]
    )
    subprocess_recorder.set_response("httpx", returncode=0, stdout=mixed + "\n")

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    res = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
    )
    assert res.ok is True
    assert res.malformed_lines >= 6
    assert res.endpoints_discovered == ["GET /api/public"]


# =============================================================================
# Iteration 2 Remediation Regression Tests (Challengers 1 & 2, Reviewers 1 & 2)
# =============================================================================


def test_rejects_poisoned_shutil_which_shim_and_symlink_for_host_and_docker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, subprocess_recorder: Any
) -> None:
    # 1. Host mode: shutil.which returns a .bat shim
    bat_shim = tmp_path / "httpx.bat"
    bat_shim.write_text("@echo off\r\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda name: str(bat_shim))
    with pytest.raises(PermissionError):
        HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True, binary_path=None)).run(
            "http://127.0.0.1:8080", authorized=True
        )

    # 2. Host mode: shutil.which returns a cross-tool symlink (httpx -> nmap)
    fake_httpx = tmp_path / "httpx.exe"
    fake_httpx.write_text("", encoding="utf-8")
    orig_resolve = Path.resolve

    def _spoof_nmap(self: Path, strict: bool = False) -> Path:
        if self == fake_httpx:
            return tmp_path / "nmap.exe"
        return orig_resolve(self, strict=strict)

    monkeypatch.setattr(shutil, "which", lambda name: str(fake_httpx))
    monkeypatch.setattr(Path, "resolve", _spoof_nmap)
    with pytest.raises(PermissionError):
        HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True, binary_path=None)).run(
            "http://127.0.0.1:8080", authorized=True
        )

    # 3. Docker mode: shutil.which("docker") returns a .bat shim
    docker_bat = tmp_path / "docker.bat"
    docker_bat.write_text("@echo off\r\n", encoding="utf-8")
    monkeypatch.setattr(Path, "resolve", orig_resolve)
    monkeypatch.setattr(shutil, "which", lambda name: str(docker_bat))
    with pytest.raises(PermissionError):
        HttpxScannerAdapter(
            config=ExternalScannerConfig(enabled=True, execution_mode="docker")
        ).run("http://127.0.0.1:8080", authorized=True)

    # 4. Docker mode: shutil.which("docker") resolves to a non-docker binary
    fake_docker = tmp_path / "docker.exe"
    fake_docker.write_text("", encoding="utf-8")

    def _spoof_docker_sqlmap(self: Path, strict: bool = False) -> Path:
        if self == fake_docker:
            return tmp_path / "sqlmap.exe"
        return orig_resolve(self, strict=strict)

    monkeypatch.setattr(shutil, "which", lambda name: str(fake_docker))
    monkeypatch.setattr(Path, "resolve", _spoof_docker_sqlmap)
    with pytest.raises(PermissionError):
        KatanaScannerAdapter(
            config=ExternalScannerConfig(enabled=True, execution_mode="docker")
        ).run("http://127.0.0.1:8080", authorized=True)

    assert len(subprocess_recorder.calls) == 0


@pytest.mark.parametrize("bad_timeout", [float("nan"), float("inf"), float("-inf")])
def test_rejects_non_finite_timeout_sec(
    bad_timeout: float, subprocess_recorder: Any
) -> None:
    with pytest.raises(ValueError):
        ExternalScannerConfig(enabled=True, timeout_sec=bad_timeout)

    cfg = ExternalScannerConfig(enabled=False, timeout_sec=bad_timeout)
    cfg.enabled = True
    with pytest.raises(ValueError):
        HttpxScannerAdapter(config=cfg).run("http://127.0.0.1:8080", authorized=True)
    assert len(subprocess_recorder.calls) == 0


def test_rejects_delayed_enablement_and_post_init_config_mutation(
    subprocess_recorder: Any,
) -> None:
    # Delayed enablement bypass attempts
    cfg1 = ExternalScannerConfig(
        enabled=False, max_depth=999999, crawl_duration_sec=999999, threads=999999
    )
    cfg1.enabled = True
    with pytest.raises(ValueError):
        KatanaScannerAdapter(config=cfg1).run("http://127.0.0.1:8080", authorized=True)

    cfg2 = ExternalScannerConfig(enabled=False, threads=999999)
    cfg2.enabled = True
    with pytest.raises(ValueError):
        HttpxScannerAdapter(config=cfg2).run("http://127.0.0.1:8080", authorized=True)

    # Post-init mutation bypass attempts
    cfg3 = ExternalScannerConfig(enabled=True)
    cfg3.max_depth = "-exec"  # type: ignore[assignment]
    with pytest.raises(ValueError):
        KatanaScannerAdapter(config=cfg3).run("http://127.0.0.1:8080", authorized=True)

    cfg4 = ExternalScannerConfig(enabled=True)
    cfg4.crawl_duration_sec = "-o"  # type: ignore[assignment]
    with pytest.raises(ValueError):
        KatanaScannerAdapter(config=cfg4).run("http://127.0.0.1:8080", authorized=True)

    cfg5 = ExternalScannerConfig(enabled=True)
    cfg5.threads = "-exec"  # type: ignore[assignment]
    with pytest.raises(ValueError):
        NucleiScannerAdapter(config=cfg5).run("http://127.0.0.1:8080", authorized=True)

    cfg6 = ExternalScannerConfig(enabled=True)
    cfg6.timeout_sec = math.nan
    with pytest.raises(ValueError):
        NucleiScannerAdapter(config=cfg6).run("http://127.0.0.1:8080", authorized=True)

    assert len(subprocess_recorder.calls) == 0


def test_concurrent_asset_graph_deduplication_race_500_endpoints(
    isolated_db: Database, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    httpx_lines = "\n".join(
        json.dumps({"url": f"http://127.0.0.1:8080/ep/{i}", "status_code": 200})
        for i in range(500)
    )
    katana_lines = "\n".join(
        json.dumps({"request": {"method": "GET", "endpoint": f"http://127.0.0.1:8080/ep/{i}/"}})
        for i in range(500)
    )

    barrier = threading.Barrier(2)

    def _concurrent_fake_run(args: Any, *pos: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        tool = Path(str(args[0]).replace("\\", "/")).name.lower()
        barrier.wait(timeout=10.0)
        out = httpx_lines if "httpx" in tool else katana_lines
        return subprocess.CompletedProcess(args=list(args), returncode=0, stdout=out + "\n", stderr="")

    monkeypatch.setattr(subprocess, "run", _concurrent_fake_run)

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    errors: List[BaseException] = []

    def _run_httpx() -> None:
        try:
            HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
                "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
            )
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    def _run_katana() -> None:
        try:
            KatanaScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
                "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
            )
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    t1 = threading.Thread(target=_run_httpx)
    t2 = threading.Thread(target=_run_katana)
    t1.start()
    t2.start()
    t1.join(timeout=15.0)
    t2.join(timeout=15.0)

    assert not errors
    ep_nodes = eng.asset_graph.find_endpoints_by_type("ENDPOINT")
    domain_nodes = eng.asset_graph.find_endpoints_by_type("DOMAIN")
    port_nodes = eng.asset_graph.find_endpoints_by_type("IP_PORT")
    assert len(ep_nodes) == 500
    assert len(domain_nodes) == 1
    assert len(port_nodes) == 1
    edge_tuples = [(e.source_id, e.target_id, e.relationship) for e in eng.asset_graph.edges]
    assert len(edge_tuples) == len(set(edge_tuples))
    assert len(edge_tuples) == 501


def test_uppercase_preexisting_host_dedup_and_nonint_port_resilience(
    isolated_db: Database, monkeypatch: pytest.MonkeyPatch, subprocess_recorder: Any, tmp_path: Path
) -> None:
    TargetAuthorizationGate.ALLOWED_TARGETS.add("case.example.com")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    eng.ingest_target_infrastructure("CASE.EXAMPLE.COM", 443, endpoints=["/existing"])
    eng.asset_graph.add_asset(
        "ASSET-EP-BADPORT",
        "ENDPOINT",
        "GET /legacy",
        {"host": "case.example.com", "port": "unknown", "route": "/legacy", "method": "GET"},
    )

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": "https://case.example.com/discovered", "status_code": 200}) + "\n",
    )
    res = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://case.example.com", authorized=True, asset_graph=eng.asset_graph
    )
    assert res.ok is True
    assert len(eng.asset_graph.find_endpoints_by_type("DOMAIN")) == 1
    assert len(eng.asset_graph.find_endpoints_by_type("IP_PORT")) == 1


def test_malformed_ipv6_urls_do_not_crash_adapters(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"url": "http://[invalid/api", "status_code": 200}),
                json.dumps({"url": "http://127.0.0.1:8080/ok", "status_code": 200}),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"request": {"method": "GET", "endpoint": "http://[bad/root"}}),
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": "http://127.0.0.1:8080/app.js"},
                        "js_endpoints": ["http://[bad/js", "/good_js_ep"],
                    }
                ),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "nuclei",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"template-id": "bad-ipv6", "matched-at": "http://[bad/c"}),
                json.dumps(
                    {
                        "template-id": "tech-ok",
                        "info": {"name": "OK", "severity": "info", "tags": ["tech"]},
                        "matched-at": "http://127.0.0.1:8080/ok",
                    }
                ),
            ]
        )
        + "\n",
    )

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    h_res = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
    )
    k_res = KatanaScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
    )
    n_res = NucleiScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, dual_graph_engine=eng
    )

    assert h_res.ok is True and h_res.malformed_lines == 1 and h_res.endpoints_discovered == ["GET /ok"]
    assert k_res.ok is True and k_res.malformed_lines == 2 and "/good_js_ep" in k_res.js_endpoints
    assert n_res.ok is True and n_res.malformed_lines == 1 and len(n_res.findings) == 1


def test_scheme_switch_port_accuracy_and_rec_port_precedence(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"url": "http://127.0.0.1/health", "status_code": 200}),
                json.dumps({"url": "http://127.0.0.1:80/health", "status_code": 200}),
                json.dumps({"url": "https://127.0.0.1/api", "port": 80, "status_code": 200}),
            ]
        )
        + "\n",
    )
    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    res = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://127.0.0.1", authorized=True, asset_graph=eng.asset_graph
    )
    assert res.ok is True
    assert [(r["route"], r["port"]) for r in res.records] == [
        ("/health", 80),
        ("/health", 80),
        ("/api", 443),
    ]
    assert len(eng.asset_graph.find_endpoints_by_type("ENDPOINT")) == 2


def test_non_string_url_fields_rejected_as_malformed_and_katana_scope_gates_tech(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"url": ["http://127.0.0.1:8080/a"], "status_code": 200}),
                json.dumps({"url": {"href": "http://127.0.0.1:8080/b"}, "status_code": 200}),
                json.dumps({"url": "http://127.0.0.1:8080/valid", "status_code": 200}),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"request": {"endpoint": ["http://127.0.0.1:8080/bad"]}}),
                json.dumps(
                    {
                        "request": {
                            "endpoint": "http://127.0.0.1:8080/ok",
                            "source": ["bad_source"],
                        }
                    }
                ),
                json.dumps(
                    {
                        "request": {"endpoint": "https://cdn.thirdparty.example/widget.js"},
                        "response": {"technologies": ["ThirdPartyCDNTech"]},
                    }
                ),
                json.dumps(
                    {
                        "request": {"endpoint": "http://127.0.0.1:8080/app.js"},
                        "response": {"technologies": ["InScopeReact"]},
                        "js_endpoints": [123, {"path": "/nope"}, "/api/ok"],
                    }
                ),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "nuclei",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"template-id": ["bad"], "matched-at": "http://127.0.0.1:8080/a"}),
                json.dumps({"template-id": "ok-id", "matched-at": ["http://127.0.0.1:8080/a"]}),
                json.dumps(
                    {
                        "template-id": "ok-id",
                        "matched-at": "http://127.0.0.1:8080/a",
                        "host": {"h": "127.0.0.1"},
                    }
                ),
            ]
        )
        + "\n",
    )

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    h_res = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
    )
    k_res = KatanaScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
    )
    n_res = NucleiScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, dual_graph_engine=eng
    )

    assert h_res.malformed_lines == 2 and h_res.endpoints_discovered == ["GET /valid"]
    assert k_res.malformed_lines == 4
    assert k_res.technologies == ["InScopeReact"]
    assert "ThirdPartyCDNTech" not in k_res.technologies
    assert "/api/ok" in k_res.js_endpoints
    assert n_res.malformed_lines == 3 and len(n_res.findings) == 0


# =============================================================================
# Iteration 3 Remediation Regression Tests (Challengers 1 & 2 Iter2)
# =============================================================================


def test_bare_binary_path_enforces_shutil_which_and_cwd_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, subprocess_recorder: Any
) -> None:
    # 1. Bare binary_path="httpx" when shutil.which returns a .bat shim
    bat_shim = tmp_path / "httpx.bat"
    bat_shim.write_text("@echo off\r\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda name: str(bat_shim))
    with pytest.raises(PermissionError):
        HttpxScannerAdapter(
            config=ExternalScannerConfig(enabled=True, binary_path="httpx")
        ).run("http://127.0.0.1:8080", authorized=True)

    # 2. Bare binary_path="httpx" & "httpx.exe" when shutil.which resolves to nmap.exe
    fake_httpx = tmp_path / "httpx.exe"
    fake_httpx.write_text("", encoding="utf-8")
    orig_resolve = Path.resolve

    def _spoof_nmap(self: Path, strict: bool = False) -> Path:
        if self == fake_httpx:
            return tmp_path / "nmap.exe"
        return orig_resolve(self, strict=strict)

    monkeypatch.setattr(shutil, "which", lambda name: str(fake_httpx))
    monkeypatch.setattr(Path, "resolve", _spoof_nmap)
    for bare_name in ("httpx", "httpx.exe"):
        with pytest.raises(PermissionError):
            HttpxScannerAdapter(
                config=ExternalScannerConfig(enabled=True, binary_path=bare_name)
            ).run("http://127.0.0.1:8080", authorized=True)

    # 3. Bare binary_path="httpx" with valid PATH binary returns validated concrete path
    monkeypatch.setattr(Path, "resolve", orig_resolve)
    subprocess_recorder.set_response("httpx", returncode=0, stdout="")
    res = HttpxScannerAdapter(
        config=ExternalScannerConfig(enabled=True, binary_path="httpx")
    ).run("http://127.0.0.1:8080", authorized=True)
    assert res.ok is True
    assert subprocess_recorder.calls[-1]["argv"][0] == str(fake_httpx)

    # 4. CWD poisoned httpx.exe -> nmap.exe blocked even when shutil.which returns None
    cwd_dir = tmp_path / "cwd_poison"
    cwd_dir.mkdir()
    cwd_httpx = cwd_dir / "httpx.exe"
    cwd_httpx.write_text("", encoding="utf-8")
    monkeypatch.chdir(cwd_dir)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    def _spoof_cwd_nmap(self: Path, strict: bool = False) -> Path:
        if self.name.lower() == "httpx.exe":
            return cwd_dir / "nmap.exe"
        return orig_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _spoof_cwd_nmap)
    calls_before = len(subprocess_recorder.calls)
    for cfg_bin in ("httpx", "httpx.exe", None):
        with pytest.raises(PermissionError):
            HttpxScannerAdapter(
                config=ExternalScannerConfig(enabled=True, binary_path=cfg_bin)
            ).run("http://127.0.0.1:8080", authorized=True)
    assert len(subprocess_recorder.calls) == calls_before


def test_windows_extensionless_binary_path_probes_exe_and_runtime_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, subprocess_recorder: Any
) -> None:
    extless_dir = tmp_path / "extless"
    extless_dir.mkdir()
    extless_path = extless_dir / "httpx"
    exe_sibling = extless_dir / "httpx.exe"
    exe_sibling.write_text("", encoding="utf-8")
    orig_resolve = Path.resolve

    # 1. Extensionless <dir>\httpx when <dir>\httpx.exe resolves to nmap.exe
    def _spoof_exe_to_nmap(self: Path, strict: bool = False) -> Path:
        if self == exe_sibling:
            return extless_dir / "nmap.exe"
        return orig_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _spoof_exe_to_nmap)
    with pytest.raises(PermissionError):
        HttpxScannerAdapter(
            config=ExternalScannerConfig(enabled=True, binary_path=str(extless_path))
        ).run("http://127.0.0.1:8080", authorized=True)
    assert len(subprocess_recorder.calls) == 0

    # 2. RuntimeError (e.g. symlink loop) during resolve() fails closed with PermissionError
    def _raise_runtime_err(self: Path, strict: bool = False) -> Path:
        if self == exe_sibling:
            raise RuntimeError("Symlink loop detected")
        return orig_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _raise_runtime_err)
    with pytest.raises(PermissionError):
        HttpxScannerAdapter(
            config=ExternalScannerConfig(enabled=True, binary_path=str(extless_path))
        ).run("http://127.0.0.1:8080", authorized=True)
    assert len(subprocess_recorder.calls) == 0

    # 3. Valid <dir>\httpx.exe resolves to concrete .exe path in argv[0]
    monkeypatch.setattr(Path, "resolve", orig_resolve)
    subprocess_recorder.set_response("httpx", returncode=0, stdout="")
    res = HttpxScannerAdapter(
        config=ExternalScannerConfig(enabled=True, binary_path=str(extless_path))
    ).run("http://127.0.0.1:8080", authorized=True)
    assert res.ok is True
    assert subprocess_recorder.calls[0]["argv"][0] == str(exe_sibling)


def test_parse_endpoint_url_protocol_relative_non_http_userinfo_and_rel_paths() -> None:
    from engine.external_scanners import _parse_endpoint_url

    # Protocol-relative extracts real third-party host for scope filtering
    assert _parse_endpoint_url(
        "//evil.thirdparty.example/steal.js",
        fallback_host="example.com",
        fallback_port=443,
        fallback_scheme="https",
    ) == ("evil.thirdparty.example", 443, "/steal.js", "https")
    assert _parse_endpoint_url(
        "//example.com:8443/inscope.js",
        fallback_host="example.com",
        fallback_port=443,
        fallback_scheme="https",
    ) == ("example.com", 8443, "/inscope.js", "https")

    # Non-HTTP(S) schemes & userinfo rejected
    for bad_url in (
        "mailto:admin@example.com",
        "javascript:alert(1)",
        "javascript:123",
        "data:text/html,<script>alert(1)</script>",
        "tel:+15550199",
        "tel:8080",
        "file:///etc/passwd",
        "vbscript:msgbox(1)",
        "ftp://example.com/archive.tar.gz",
        "http://evil.com@example.com/admin",
        "https://user:pass@example.com/admin",
        "//evil.com@example.com/steal.js",
        "evil.com@example.com/admin",
        "http:///missing-host",
        "///missing-host",
    ):
        assert _parse_endpoint_url(
            bad_url,
            fallback_host="example.com",
            fallback_port=443,
            fallback_scheme="https",
        ) is None, f"Expected {bad_url!r} to be rejected"

    # Relative path without leading slash resolves onto fallback_host
    assert _parse_endpoint_url(
        "api/users?page=2#top",
        fallback_host="example.com",
        fallback_port=8443,
        fallback_scheme="https",
    ) == ("example.com", 8443, "/api/users", "https")
    assert _parse_endpoint_url("api/users", fallback_host="") is None

    # Schemeless host/authority still parses cleanly
    assert _parse_endpoint_url(
        "localhost:8080/health",
        fallback_host="example.com",
        fallback_port=443,
        fallback_scheme="https",
    ) == ("localhost", 8080, "/health", "https")


def test_katana_filters_protocol_relative_mailto_and_oos_parent_js_endpoints(
    isolated_db: Database, monkeypatch: pytest.MonkeyPatch, subprocess_recorder: Any, tmp_path: Path
) -> None:
    TargetAuthorizationGate.ALLOWED_TARGETS.add("example.com")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": "https://example.com/index.html"},
                        "js_endpoints": [
                            "//evil.thirdparty.example/steal.js",
                            "mailto:admin@example.com",
                            "javascript:123",
                            "http://evil.com@example.com/admin",
                            "api/users",
                        ],
                    }
                ),
                json.dumps(
                    {
                        "request": {
                            "method": "GET",
                            "endpoint": "https://cdn.thirdparty.example/widget.js",
                        },
                        "response": {"technologies": ["ThirdPartyTech"]},
                        "js_endpoints": ["/cdn-internal-secret"],
                    }
                ),
                json.dumps(
                    {
                        "request": {
                            "method": "GET",
                            "endpoint": "https://api.example.com:8443/app.js",
                        },
                        "js_endpoints": ["/v2/items"],
                    }
                ),
            ]
        )
        + "\n",
    )

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    res = KatanaScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, asset_graph=eng.asset_graph
    )
    assert res.ok is True
    assert res.malformed_lines == 3  # mailto:, javascript:123, userinfo@
    ep_nodes = eng.asset_graph.find_endpoints_by_type("ENDPOINT")
    routes = [n.attributes.get("route") for n in ep_nodes]
    assert "/index.html" in routes
    assert "/api/users" in routes
    assert "/app.js" in routes
    assert "/v2/items" in routes
    assert "//evil.thirdparty.example/steal.js" not in routes
    assert "/steal.js" not in routes
    assert "/admin" not in routes
    assert "/cdn-internal-secret" not in routes
    assert "/cdn-internal-secret" not in res.js_endpoints
    assert "ThirdPartyTech" not in res.technologies

    v2_node = next(n for n in ep_nodes if n.attributes.get("route") == "/v2/items")
    assert v2_node.attributes.get("host") == "api.example.com"
    assert v2_node.attributes.get("port") == 8443


def test_sync_graph_index_handles_inplace_node_replacement_and_ipv6_brackets(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")

    # 1. Same-count in-place overwrite (/first -> /second) must not miss /first later
    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": "http://127.0.0.1:8080/first", "status_code": 200}) + "\n",
    )
    res1 = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
    )
    assert res1.ok is True
    first_node = eng.asset_graph.find_endpoints_by_type("ENDPOINT")[0]
    eng.asset_graph.add_asset(
        first_node.node_id,
        "ENDPOINT",
        "GET /second",
        {"host": "127.0.0.1", "port": 8080, "route": "/second", "method": "GET"},
    )
    res2 = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
    )
    assert res2.assets_added == 1
    routes = sorted(
        str(n.attributes.get("route"))
        for n in eng.asset_graph.find_endpoints_by_type("ENDPOINT")
    )
    assert routes == ["/first", "/second"]

    # 2. Trailing-slash in-place replacement (/old/ -> /new/) deduplicates /new
    eng2 = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep2")
    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": "http://127.0.0.1:8080/old/", "status_code": 200}) + "\n",
    )
    HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng2.asset_graph
    )
    old_node = eng2.asset_graph.find_endpoints_by_type("ENDPOINT")[0]
    eng2.asset_graph.add_asset(
        old_node.node_id,
        "ENDPOINT",
        "GET /new/",
        {"host": "127.0.0.1", "port": 8080, "route": "/new/", "method": "GET"},
    )
    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": "http://127.0.0.1:8080/new", "status_code": 200}) + "\n",
    )
    res_slash = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng2.asset_graph
    )
    assert res_slash.assets_added == 0
    ep2 = eng2.asset_graph.find_endpoints_by_type("ENDPOINT")
    assert len(ep2) == 1
    assert ep2[0].attributes.get("route") == "/new/"

    # 3. Pre-existing bracketed IPv6 IP_PORT label "[::1]:8080" deduplicates cleanly
    eng3 = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep3")
    eng3.asset_graph.add_asset("ASSET-PORT-CUSTOM", "IP_PORT", "[::1]:8080", {})
    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": "http://[::1]:8080/api", "status_code": 200}) + "\n",
    )
    res_v6 = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://[::1]:8080", authorized=True, asset_graph=eng3.asset_graph
    )
    assert res_v6.ok is True
    assert len(eng3.asset_graph.find_endpoints_by_type("IP_PORT")) == 1


# =============================================================================
# Iteration 4 Remediation Regression Tests (Challengers 1 & 2 Iter3, Auditor, Rev1)
# =============================================================================


def test_bare_command_cwd_directory_and_extensionless_windows_shadowing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, subprocess_recorder: Any
) -> None:
    orig_resolve = Path.resolve

    # 1. CWD directory named httpx/ must NOT short-circuit shutil.which validation
    cwd_case = tmp_path / "cwd_dir_case"
    (cwd_case / "httpx").mkdir(parents=True)
    (cwd_case / "docker").mkdir(parents=True)
    bat_httpx = tmp_path / "path_dir" / "httpx.bat"
    bat_httpx.parent.mkdir(parents=True)
    bat_httpx.write_text("@echo off\r\n", encoding="utf-8")
    bat_docker = tmp_path / "path_dir" / "docker.bat"
    bat_docker.write_text("@echo off\r\n", encoding="utf-8")

    monkeypatch.chdir(cwd_case)
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: str(bat_docker if "docker" in name.lower() else bat_httpx),
    )
    for bp in (None, "httpx"):
        with pytest.raises(PermissionError):
            HttpxScannerAdapter(
                config=ExternalScannerConfig(enabled=True, binary_path=bp)
            ).run("http://127.0.0.1:8080", authorized=True)
    with pytest.raises(PermissionError):
        HttpxScannerAdapter(
            config=ExternalScannerConfig(enabled=True, execution_mode="docker")
        ).run("http://127.0.0.1:8080", authorized=True)

    # 2. CWD directory docker/ with VALID docker.exe on PATH resolves cleanly to docker.exe
    valid_docker = tmp_path / "path_dir" / "docker.exe"
    valid_docker.write_text("", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda name: str(valid_docker))
    subprocess_recorder.set_response("docker", returncode=0, stdout="")
    res_docker = HttpxScannerAdapter(
        config=ExternalScannerConfig(enabled=True, execution_mode="docker")
    ).run("http://127.0.0.1:8080", authorized=True)
    assert res_docker.ok is True
    assert subprocess_recorder.calls[-1]["argv"][0] == str(valid_docker)

    # 3. CWD directory httpx/ + poisoned CWD\httpx.exe -> nmap.exe blocked
    if os.name == "nt":
        poison_cwd_exe = cwd_case / "httpx.exe"
        poison_cwd_exe.write_text("", encoding="utf-8")
        monkeypatch.setattr(shutil, "which", lambda name: None)

        def _spoof_cwd_exe_nmap(self: Path, strict: bool = False) -> Path:
            if self.name.lower() == "httpx.exe":
                return cwd_case / "nmap.exe"
            return orig_resolve(self, strict=strict)

        monkeypatch.setattr(Path, "resolve", _spoof_cwd_exe_nmap)
        with pytest.raises(PermissionError):
            HttpxScannerAdapter(
                config=ExternalScannerConfig(enabled=True, binary_path="httpx")
            ).run("http://127.0.0.1:8080", authorized=True)
        monkeypatch.setattr(Path, "resolve", orig_resolve)
        poison_cwd_exe.unlink()

    # 4. CWD 0-byte extensionless httpx + httpx.bat on Windows delegates to shutil.which and rejects .bat
    if os.name == "nt":
        cwd_extless = cwd_case / "extless_bat"
        cwd_extless.mkdir()
        (cwd_extless / "httpx").write_text("", encoding="utf-8")
        cwd_bat = cwd_extless / "httpx.bat"
        cwd_bat.write_text("@echo off\r\n", encoding="utf-8")
        monkeypatch.chdir(cwd_extless)
        monkeypatch.setattr(shutil, "which", lambda name: str(cwd_bat))
        with pytest.raises(PermissionError):
            HttpxScannerAdapter(
                config=ExternalScannerConfig(enabled=True, binary_path="httpx")
            ).run("http://127.0.0.1:8080", authorized=True)

    # 5. Co-located explicit <dir>\httpx (0-byte) + poisoned <dir>\httpx.exe -> nmap.exe blocked;
    #    valid <dir>\httpx.exe resolves to .exe; explicit directory <dir>\httpx is always rejected
    if os.name == "nt":
        coloc = tmp_path / "coloc"
        coloc.mkdir()
        coloc_extless = coloc / "httpx"
        coloc_extless.write_text("", encoding="utf-8")
        coloc_exe = coloc / "httpx.exe"
        coloc_exe.write_text("", encoding="utf-8")

        def _spoof_coloc(self: Path, strict: bool = False) -> Path:
            if self == coloc_exe:
                return coloc / "nmap.exe"
            return orig_resolve(self, strict=strict)

        monkeypatch.setattr(Path, "resolve", _spoof_coloc)
        with pytest.raises(PermissionError):
            HttpxScannerAdapter(
                config=ExternalScannerConfig(enabled=True, binary_path=str(coloc_extless))
            ).run("http://127.0.0.1:8080", authorized=True)

        monkeypatch.setattr(Path, "resolve", orig_resolve)
        subprocess_recorder.set_response("httpx", returncode=0, stdout="")
        res_coloc = HttpxScannerAdapter(
            config=ExternalScannerConfig(enabled=True, binary_path=str(coloc_extless))
        ).run("http://127.0.0.1:8080", authorized=True)
        assert res_coloc.ok is True
        assert subprocess_recorder.calls[-1]["argv"][0] == str(coloc_exe)

        dir_clash = tmp_path / "dir_clash"
        (dir_clash / "httpx").mkdir(parents=True)
        (dir_clash / "httpx.exe").write_text("", encoding="utf-8")
        with pytest.raises(PermissionError):
            HttpxScannerAdapter(
                config=ExternalScannerConfig(
                    enabled=True, binary_path=str(dir_clash / "httpx")
                )
            ).run("http://127.0.0.1:8080", authorized=True)


def test_parse_endpoint_url_control_chars_dotted_paths_query_scheme_and_ipv6() -> None:
    from engine.external_scanners import _parse_endpoint_url

    fb = {"fallback_host": "example.com", "fallback_port": 443, "fallback_scheme": "https"}

    # Control chars and internal whitespace rejected
    for bad in (
        "ja\tvascript:123",
        "java\nscript:alert(1)",
        "data\n:text/html,<h1>x</h1>",
        "https://example.com\n/evil",
        "http://example.com\r\n/admin",
        "http://evil .com/x",
        "api/\x00users",
        "api/\x7fusers",
    ):
        assert _parse_endpoint_url(bad, **fb) is None, f"Expected control-char/ws {bad!r} -> None"

    # Unbracketed IPv6 literals rejected consistently
    for v6 in ("2001:db8::1", "::1", "fe80::1", "2001:db8::1/api"):
        assert _parse_endpoint_url(v6, **fb) is None, f"Expected unbracketed IPv6 {v6!r} -> None"

    # Dotted relative paths and query-param `://` resolve onto fallback_host
    expected_rel = {
        "index.html": ("example.com", 443, "/index.html", "https"),
        "app.js": ("example.com", 443, "/app.js", "https"),
        "./rel": ("example.com", 443, "/./rel", "https"),
        "../up": ("example.com", 443, "/../up", "https"),
        "v1.0/users": ("example.com", 443, "/v1.0/users", "https"),
        ".env": ("example.com", 443, "/.env", "https"),
        ".well-known/security.txt": ("example.com", 443, "/.well-known/security.txt", "https"),
        "config.yaml": ("example.com", 443, "/config.yaml", "https"),
        "login?next=http://evil.com": ("example.com", 443, "/login", "https"),
    }
    for raw, exp in expected_rel.items():
        assert _parse_endpoint_url(raw, **fb) == exp, f"Mismatch for relative {raw!r}"

    # Real domain/IP/bracketed-IPv6 authorities continue to parse as hosts
    expected_hosts = {
        "api.example.com/v1": ("api.example.com", 443, "/v1", "https"),
        "sub.localhost/api": ("sub.localhost", 443, "/api", "https"),
        "example.com:8443/x": ("example.com", 8443, "/x", "https"),
        "[::1]:8080/x": ("::1", 8080, "/x", "https"),
        "localhost:3000/api": ("localhost", 3000, "/api", "https"),
        "93.184.216.34/api": ("93.184.216.34", 443, "/api", "https"),
    }
    for raw, exp in expected_hosts.items():
        assert _parse_endpoint_url(raw, **fb) == exp, f"Mismatch for host {raw!r}"


def test_sync_graph_index_ip_port_label_port_fallback(
    isolated_db: Database, subprocess_recorder: Any, tmp_path: Path
) -> None:
    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    eng.asset_graph.add_asset("P-V6", "IP_PORT", "[::1]:8080", {"host": "[::1]"})
    eng.asset_graph.add_asset("P-V4", "IP_PORT", "127.0.0.1:8080", {"host": "127.0.0.1"})

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"url": "http://[::1]:8080/v6", "status_code": 200}),
                json.dumps({"url": "http://127.0.0.1:8080/v4", "status_code": 200}),
            ]
        )
        + "\n",
    )
    res_v6 = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://[::1]:8080", authorized=True, asset_graph=eng.asset_graph
    )
    res_v4 = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True, asset_graph=eng.asset_graph
    )
    assert res_v6.ok is True and res_v4.ok is True
    ip_ports = eng.asset_graph.find_endpoints_by_type("IP_PORT")
    assert sorted(n.node_id for n in ip_ports) == ["P-V4", "P-V6"]


def test_httpx_katana_without_asset_graph_enforce_target_scope(
    monkeypatch: pytest.MonkeyPatch, subprocess_recorder: Any
) -> None:
    TargetAuthorizationGate.ALLOWED_TARGETS.add("example.com")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"url": "https://evil.attacker.com/steal", "status_code": 200, "tech": ["EvilTech"]}),
                json.dumps({"url": "http://169.254.169.254/latest/meta-data/", "status_code": 200, "tech": ["IMDS"]}),
                json.dumps({"url": "https://sub.example.com/health", "status_code": 200, "tech": ["GoodTech"]}),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": "https://evil.attacker.com/exfil.js"},
                        "response": {"technologies": ["EvilTech"]},
                        "js_endpoints": ["/steal"],
                    }
                ),
                json.dumps({"request": {"method": "GET", "endpoint": "http://169.254.169.254/latest/meta-data/"}}),
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": "https://example.com/"},
                        "response": {"technologies": ["InScopeTech"]},
                        "js_endpoints": ["app.js", "login?next=http://evil.com", "//evil.attacker.com/x.js"],
                    }
                ),
            ]
        )
        + "\n",
    )

    h_res = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, asset_graph=None
    )
    k_res = KatanaScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, asset_graph=None
    )

    assert h_res.endpoints_discovered == ["GET /health"]
    assert h_res.technologies == ["GoodTech"]
    assert "EvilTech" not in h_res.technologies and "IMDS" not in h_res.technologies

    assert k_res.endpoints_discovered == ["GET /", "GET /app.js", "GET /login"]
    assert k_res.js_endpoints == ["/app.js", "/login"]
    assert k_res.technologies == ["InScopeTech"]
    assert "/steal" not in k_res.js_endpoints
    assert "/latest/meta-data/" not in " ".join(k_res.endpoints_discovered)


def test_nuclei_enforces_scope_deny_routes_and_ssrf_filtering(
    isolated_db: Database, monkeypatch: pytest.MonkeyPatch, subprocess_recorder: Any, tmp_path: Path
) -> None:
    TargetAuthorizationGate.ALLOWED_TARGETS.add("example.com")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    nuclei_out = "\n".join(
        [
            json.dumps({"template-id": "imds-ssrf", "matched-at": "http://169.254.169.254/latest/meta-data/"}),
            json.dumps({"template-id": "oos-leak", "matched-at": "https://evil.attacker.com/leak"}),
            json.dumps({"template-id": "denied-host", "matched-at": "https://denied.example.com/a"}),
            json.dumps({"template-id": "denied-route", "matched-at": "https://example.com/internal/secret"}),
            json.dumps({"template-id": "smuggled", "matched-at": "ja\tvascript:123"}),
            json.dumps(
                {
                    "template-id": "valid-sub",
                    "info": {"name": "Valid Sub Finding", "severity": "low", "tags": ["misconfig"]},
                    "matched-at": "https://sub.example.com/public",
                }
            ),
        ]
    ) + "\n"
    subprocess_recorder.set_response("nuclei", returncode=0, stdout=nuclei_out)

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    eng.asset_graph.scope_hosts.add("example.com")
    eng.asset_graph.deny_hosts.add("denied.example.com")
    eng.asset_graph.deny_routes.append("/internal")

    res = NucleiScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, dual_graph_engine=eng
    )
    assert res.ok is True
    assert res.malformed_lines == 1  # smuggled ja\tvascript:123
    assert [f["rule_id"] for f in res.findings] == ["valid-sub"]
    assert res.findings_ingested == 1

    # Also verify dual_graph_engine=None enforces target_host scope
    res_no_eng = NucleiScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, dual_graph_engine=None
    )
    assert [f["rule_id"] for f in res_no_eng.findings] == [
        "denied-host",
        "denied-route",
        "valid-sub",
    ]

    # Bracketed IPv6 scope_hosts in AssetGraph still allows ::1 findings
    eng_v6 = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep_v6")
    eng_v6.asset_graph.scope_hosts.add("[::1]")
    subprocess_recorder.set_response(
        "nuclei",
        returncode=0,
        stdout=json.dumps(
            {
                "template-id": "v6-ok",
                "info": {"name": "V6", "severity": "info", "tags": ["tech"]},
                "matched-at": "http://[::1]:8080/ok",
            }
        )
        + "\n",
    )
    res_v6 = NucleiScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://[::1]:8080", authorized=True, dual_graph_engine=eng_v6
    )
    assert res_v6.findings_ingested == 1


# =============================================================================
# Iteration 5 Remediation Regression Tests (Challengers 1 & 2 Iter4, Auditor)
# =============================================================================


def test_deny_routes_dot_segment_normalization_across_all_adapters(
    isolated_db: Database, monkeypatch: pytest.MonkeyPatch, subprocess_recorder: Any, tmp_path: Path
) -> None:
    from engine.external_scanners import _parse_endpoint_url

    # _parse_endpoint_url must continue preserving /./rel and /../up
    fb = {"fallback_host": "example.com", "fallback_port": 443, "fallback_scheme": "https"}
    assert _parse_endpoint_url("./rel", **fb) == ("example.com", 443, "/./rel", "https")
    assert _parse_endpoint_url("../up", **fb) == ("example.com", 443, "/../up", "https")

    TargetAuthorizationGate.ALLOWED_TARGETS.add("example.com")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"url": "https://example.com/internal/secret", "status_code": 200}),
                json.dumps({"url": "https://example.com/./internal/secret", "status_code": 200}),
                json.dumps({"url": "https://example.com/public/../internal/secret", "status_code": 200}),
                json.dumps({"url": "https://example.com/a/b/../../internal/secret", "status_code": 200}),
                json.dumps({"url": "https://example.com/./logout/", "status_code": 200}),
                json.dumps({"url": "https://example.com/ok", "status_code": 200}),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"request": {"method": "GET", "endpoint": "https://example.com/./internal/secret"}}),
                json.dumps({"request": {"method": "GET", "endpoint": "https://example.com/public/../internal/secret"}}),
                json.dumps({"request": {"method": "GET", "endpoint": "https://example.com/a/b/../../internal/secret"}}),
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": "https://example.com/app.js"},
                        "js_endpoints": [
                            "/./internal/secret",
                            "/public/../internal/secret",
                            "/a/b/../../internal/secret",
                            "/ok2",
                        ],
                    }
                ),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "nuclei",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"template-id": "deny-lit", "matched-at": "https://example.com/internal/secret"}),
                json.dumps({"template-id": "deny-dot", "matched-at": "https://example.com/./internal/secret"}),
                json.dumps({"template-id": "deny-dotdot", "matched-at": "https://example.com/public/../internal/secret"}),
                json.dumps({"template-id": "deny-multi-dotdot", "matched-at": "https://example.com/a/b/../../internal/secret"}),
                json.dumps({"template-id": "deny-logout", "matched-at": "https://example.com/./logout/"}),
                json.dumps(
                    {
                        "template-id": "ok-sub",
                        "info": {"name": "OK", "severity": "info", "tags": ["tech"]},
                        "matched-at": "https://sub.example.com/ok",
                    }
                ),
            ]
        )
        + "\n",
    )

    eng = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "rep")
    eng.asset_graph.scope_hosts.add("example.com")
    eng.asset_graph.deny_routes.extend(["/internal", "/logout/"])

    h_res = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, asset_graph=eng.asset_graph
    )
    k_res = KatanaScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, asset_graph=eng.asset_graph
    )
    n_res = NucleiScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, dual_graph_engine=eng
    )

    assert h_res.endpoints_discovered == ["GET /ok"]
    assert [r["route"] for r in h_res.records] == ["/ok"]

    assert k_res.endpoints_discovered == ["GET /app.js", "GET /ok2"]
    assert k_res.js_endpoints == ["/app.js", "/ok2"]
    assert [r["route"] for r in k_res.records] == ["/app.js", "/ok2"]

    assert [f["rule_id"] for f in n_res.findings] == ["ok-sub"]
    assert [r["template-id"] for r in n_res.records] == ["ok-sub"]
    assert n_res.findings_ingested == 1

    graph_routes = sorted(
        str(n.attributes.get("route"))
        for n in eng.asset_graph.find_endpoints_by_type("ENDPOINT")
    )
    assert graph_routes == ["/app.js", "/ok", "/ok2"]


def test_scanner_execution_result_records_excludes_oos_ssrf_and_denied_routes(
    isolated_db: Database, monkeypatch: pytest.MonkeyPatch, subprocess_recorder: Any, tmp_path: Path
) -> None:
    TargetAuthorizationGate.ALLOWED_TARGETS.add("example.com")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"url": "https://evil.attacker.com/a", "status_code": 200}),
                json.dumps({"url": "http://169.254.169.254/latest/meta-data/", "status_code": 200}),
                json.dumps({"url": "http://[::ffff:169.254.169.254]/", "status_code": 200}),
                json.dumps({"url": "https://notexample.com/a", "status_code": 200}),
                json.dumps({"url": "https://example.com.evil.com/a", "status_code": 200}),
                json.dumps({"url": "https://denied.example.com/a", "status_code": 200}),
                json.dumps({"url": "https://example.com/internal/secret", "status_code": 200}),
                json.dumps({"url": "https://example.com/./internal/secret", "status_code": 200}),
                json.dumps({"url": "https://sub.example.com/ok", "status_code": 200}),
            ]
        )
        + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"request": {"method": "GET", "endpoint": "https://evil.attacker.com/a"}, "js_endpoints": ["/steal"]}),
                json.dumps({"request": {"method": "GET", "endpoint": "http://169.254.169.254/latest/meta-data/"}}),
                json.dumps({"request": {"method": "GET", "endpoint": "https://denied.example.com/a"}}),
                json.dumps({"request": {"method": "GET", "endpoint": "https://example.com/public/../internal/secret"}}),
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": "https://sub.example.com/app.js"},
                        "js_endpoints": ["https://evil.attacker.com/x.js", "/./internal/secret", "/ok2"],
                    }
                ),
            ]
        )
        + "\n",
    )

    # 1. With AssetGraph (enforces deny_hosts + deny_routes + scope_hosts)
    ag = AssetGraph(
        db=isolated_db,
        scope_hosts={"example.com"},
        deny_hosts={"denied.example.com"},
        deny_routes=["/internal"],
    )
    h_ag = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, asset_graph=ag
    )
    k_ag = KatanaScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, asset_graph=ag
    )
    assert [(r["host"], r["route"]) for r in h_ag.records] == [("sub.example.com", "/ok")]
    assert [(r["host"], r["route"]) for r in k_ag.records] == [
        ("sub.example.com", "/app.js"),
        ("sub.example.com", "/ok2"),
    ]

    # 2. Without AssetGraph (asset_graph=None still excludes evil.attacker.com / SSRF / suffix spoof)
    h_no = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, asset_graph=None
    )
    k_no = KatanaScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "https://example.com", authorized=True, asset_graph=None
    )
    assert all(
        r["host"] == "example.com" or r["host"].endswith(".example.com")
        for r in h_no.records
    )
    assert "evil.attacker.com" not in str(h_no.records)
    assert "169.254.169.254" not in str(h_no.records)
    assert "notexample.com" not in str(h_no.records)
    assert "example.com.evil.com" not in str(h_no.records)

    assert all(
        r["host"] == "example.com" or r["host"].endswith(".example.com")
        for r in k_no.records
    )
    assert "evil.attacker.com" not in str(k_no.records)
    assert "169.254.169.254" not in str(k_no.records)
    assert "/steal" not in str(k_no.records)


def test_jsonl_utf8_bom_line1_and_target_control_char_rejection(
    subprocess_recorder: Any,
) -> None:
    from engine.external_scanners import _iter_jsonl_records

    bom_out = '\ufeff{"url": "https://example.com/a"}\n{"url": "https://example.com/b"}\n'
    recs, mal = _iter_jsonl_records(bom_out)
    assert len(recs) == 2
    assert mal == 0

    # BOM on line 2 is still treated as malformed
    bom_line2 = '{"url": "https://example.com/a"}\n\ufeff{"url": "https://example.com/b"}\n'
    recs2, mal2 = _iter_jsonl_records(bom_line2)
    assert len(recs2) == 1
    assert mal2 == 1

    # Control characters & internal spaces in target URL are rejected fail-closed
    adapter = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True))
    for bad_target in (
        "http://127.0.0.1\t:8080/",
        "http\t://127.0.0.1:8080/",
        "http://127.0.0.1:8080\x0b/admin",
        "http://127.0.0.1\x7f:8080/",
        "http://127.0.0.1:8080/a b",
        "https://127.0.0.1\x01:8080/x",
    ):
        with pytest.raises(PermissionError):
            adapter.run(bad_target, authorized=True)
    assert len(subprocess_recorder.calls) == 0


def test_host_httpx_skips_python_httpx_cli_and_returns_binary_not_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from engine.external_scanners import _is_python_httpx_cli_binary, _resolve_host_binary

    py_dir = tmp_path / "py_scripts"
    py_dir.mkdir()
    py_httpx = py_dir / ("httpx.EXE" if os.name == "nt" else "httpx")
    if os.name == "nt":
        # Mimic pip console_scripts PE launcher + zip payload
        py_httpx.write_bytes(
            b"MZ"
            + b"\x00" * 20480
            + b"#!C:\\python313\\python.exe\nPK\x03\x04__main__.py"
            + b"import sys\nfrom httpx import main\nif __name__ == '__main__':\n    sys.exit(main())\n"
        )
    else:
        py_httpx.write_bytes(
            b"#!/usr/bin/python3\nimport sys\nfrom httpx import main\nif __name__ == '__main__':\n    sys.exit(main())\n"
        )
        py_httpx.chmod(0o755)

    assert _is_python_httpx_cli_binary(str(py_httpx)) is True

    # 1. When a real ProjectDiscovery httpx exists later on PATH, _resolve_host_binary skips Python's httpx CLI
    pd_dir = tmp_path / "pd_bin"
    pd_dir.mkdir()
    pd_httpx = pd_dir / ("httpx.exe" if os.name == "nt" else "httpx")
    pd_httpx.write_bytes(b"MZ\x90\x00ProjectDiscovery Go httpx binary stub" + b"\x00" * 4096)
    if os.name != "nt":
        pd_httpx.chmod(0o755)
    assert _is_python_httpx_cli_binary(str(pd_httpx)) is False

    monkeypatch.setenv("PATH", f"{py_dir}{os.pathsep}{pd_dir}")
    monkeypatch.setattr(shutil, "which", lambda name: str(py_httpx) if name == "httpx" else None)
    resolved = _resolve_host_binary(None, "httpx")
    assert Path(resolved).resolve() == pd_httpx.resolve()

    # 2. When ONLY Python's httpx CLI is on PATH and subprocess.run is NOT mocked, return binary_not_found cleanly
    monkeypatch.setenv("PATH", str(py_dir))
    res = HttpxScannerAdapter(config=ExternalScannerConfig(enabled=True)).run(
        "http://127.0.0.1:8080", authorized=True
    )
    assert res.ok is False
    assert res.status == "binary_not_found"
    assert "No such option" not in (res.error or "")
    assert "python" in (res.error or "").lower()


