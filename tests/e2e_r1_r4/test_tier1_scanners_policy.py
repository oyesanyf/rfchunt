"""
Tier 1 E2E Tests: Shell-Free ExecutionPolicy & Opt-In External Scanner Adapters
Covers Features F1, F8, F9, and F10 (22 tests total; >=5 per feature).

Collection safety: All M1/M3 symbols (`engine.external_scanners`,
`ExecutionPolicy.validate_subprocess_command`, etc.) are imported inside test
bodies or local helpers so `pytest --collect-only` succeeds before M1-M3 land.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from engine.approval_gate import ApprovalGate, ApprovalRule
from engine.dual_graph_engine import AssetGraph, DualGraphAttackEngine, NoiseGovernor
from engine.execution_policy import (
    ActionType,
    ExecutionPolicy,
    ScannerTask,
    StructuredIntentProposal,
)


def _check_subprocess_policy(
    policy: ExecutionPolicy, cmd: Any, *, shell: bool = False
) -> Tuple[bool, str]:
    """Invoke `ExecutionPolicy.validate_subprocess_command` per PROJECT.md contract."""
    assert hasattr(policy, "validate_subprocess_command"), (
        "M1 contract missing: ExecutionPolicy.validate_subprocess_command"
    )
    res = policy.validate_subprocess_command(cmd, shell=shell)
    assert isinstance(res, tuple) and len(res) == 2, (
        f"validate_subprocess_command must return (bool, str), got {res!r}"
    )
    return bool(res[0]), str(res[1])


def _invoke_adapter(adapter: Any, *args: Any, **kwargs: Any) -> Any:
    """Invoke standard adapter entrypoint (`run`, `scan`, or `discover`)."""
    for meth in ("run", "scan", "discover"):
        fn = getattr(adapter, meth, None)
        if callable(fn):
            return fn(*args, **kwargs)
    raise AssertionError(
        f"Scanner adapter {type(adapter).__name__} exposes none of run/scan/discover"
    )


# =============================================================================
# Feature F1: Shell-Free ExecutionPolicy Hardening (6 tests)
# =============================================================================


def test_f01_execution_policy_rejects_shell_true() -> None:
    policy = ExecutionPolicy.get_instance()
    allowed_false, _ = _check_subprocess_policy(
        policy, ["httpx", "-u", "http://127.0.0.1:8080", "-jsonl"], shell=False
    )
    assert allowed_false is True

    allowed_true, reason = _check_subprocess_policy(
        policy, ["httpx", "-u", "http://127.0.0.1:8080", "-jsonl"], shell=True
    )
    assert allowed_true is False
    assert "shell" in reason.lower()


def test_f01_execution_policy_rejects_raw_shell_string() -> None:
    policy = ExecutionPolicy.get_instance()
    allowed, reason = _check_subprocess_policy(
        policy, "httpx -u http://127.0.0.1:8080 | cat", shell=False
    )
    assert allowed is False
    assert reason.strip() != ""


@pytest.mark.parametrize(
    "shell_bin",
    ["sh", "bash", "cmd.exe", "powershell.exe", "pwsh", "env", "sudo", "xargs"],
)
def test_f01_execution_policy_rejects_shell_interpreters_and_wrappers(shell_bin: str) -> None:
    policy = ExecutionPolicy.get_instance()
    cmd = [shell_bin, "-c", "id"] if shell_bin in ("sh", "bash") else [shell_bin, "id"]

    allowed, reason = _check_subprocess_policy(policy, cmd, shell=False)
    assert allowed is False, f"Expected {shell_bin} to be rejected by validate_subprocess_command"
    assert reason.strip() != ""

    with pytest.raises(PermissionError):
        policy.validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.ARTEX_DUAL_GRAPH,
                action_type=ActionType.SUBPROCESS_EXEC,
                command_args=cmd,
                rationale=f"Attempt forbidden shell/wrapper {shell_bin}",
            )
        )


@pytest.mark.parametrize(
    "bad_arg",
    [
        "http://127.0.0.1;whoami",
        "http://127.0.0.1&&id",
        "http://127.0.0.1||cat",
        "http://127.0.0.1|nc",
        "`id`",
        "$(whoami)",
    ],
)
def test_f01_execution_policy_rejects_shell_metacharacters_in_args(bad_arg: str) -> None:
    policy = ExecutionPolicy.get_instance()
    allowed, reason = _check_subprocess_policy(
        policy, ["httpx", "-u", bad_arg], shell=False
    )
    assert allowed is False, f"Expected metacharacter arg {bad_arg!r} to be rejected"
    assert reason.strip() != ""


@pytest.mark.parametrize(
    "excluded_bin",
    ["nmap", "ffuf", "dalfox", "sqlmap", "nmap.exe", "sqlmap.exe"],
)
def test_f01_execution_policy_blocks_excluded_native_scanners(excluded_bin: str) -> None:
    policy = ExecutionPolicy.get_instance()
    cmd = [excluded_bin, "-h"]

    allowed, reason = _check_subprocess_policy(policy, cmd, shell=False)
    assert allowed is False, f"Excluded scanner {excluded_bin} must be rejected"
    assert reason.strip() != ""

    with pytest.raises(PermissionError):
        policy.validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.ARTEX_DUAL_GRAPH,
                action_type=ActionType.SUBPROCESS_EXEC,
                command_args=cmd,
                rationale=f"Attempt excluded native scanner {excluded_bin}",
            )
        )


@pytest.mark.parametrize(
    "allowed_cmd",
    [
        ["httpx", "-u", "http://127.0.0.1:8080", "-jsonl", "-rl", "2"],
        ["httpx.exe", "-u", "http://127.0.0.1:8080", "-jsonl"],
        ["katana", "-u", "http://127.0.0.1:8080", "-jsonl", "-rl", "2"],
        ["nuclei", "-u", "http://127.0.0.1:8080", "-jsonl", "-tags", "tech,headers"],
        ["docker", "run", "--rm", "projectdiscovery/httpx:latest", "-u", "http://127.0.0.1:8080"],
    ],
)
def test_f01_execution_policy_allowlists_external_scanners_and_docker(
    allowed_cmd: list[str],
) -> None:
    policy = ExecutionPolicy.get_instance()
    allowed, reason = _check_subprocess_policy(policy, allowed_cmd, shell=False)
    assert allowed is True, f"Expected {allowed_cmd!r} to be allowlisted, got: {reason}"

    # ApprovalGate must still honor hard ExecutionPolicy denies over permissive APPROVE rules
    gate = ApprovalGate(
        mode="policy",
        rules=[
            ApprovalRule(
                rule_id="ALLOW-ALL-REGEX",
                rule_type="regex",
                action="APPROVE",
                pattern=".*",
            )
        ],
    )
    deny_dec = gate.check(action_type="subprocess", command=["sqlmap", "-u", "http://127.0.0.1"])
    assert deny_dec.approved is False
    assert deny_dec.rule_id == "EXECUTION_POLICY_HARD_DENY"


# =============================================================================
# Feature F8: Opt-In Typed httpx, katana, nuclei Adapters (6 tests)
# =============================================================================


def test_f08_external_scanners_disabled_by_default(
    subprocess_recorder: Any, loopback_server: Any
) -> None:
    from engine.external_scanners import (
        ExternalScannerConfig,
        HttpxScannerAdapter,
        KatanaScannerAdapter,
        NucleiScannerAdapter,
        run_opt_in_external_discovery,
    )

    cfg = ExternalScannerConfig()
    assert cfg.enabled is False

    res_httpx = _invoke_adapter(
        HttpxScannerAdapter(config=cfg),
        target=loopback_server.url,
        authorized=True,
    )
    res_katana = _invoke_adapter(
        KatanaScannerAdapter(config=cfg),
        target=loopback_server.url,
        authorized=True,
    )
    res_nuclei = _invoke_adapter(
        NucleiScannerAdapter(config=cfg),
        target=loopback_server.url,
        authorized=True,
    )
    res_orch = run_opt_in_external_discovery(
        target=loopback_server.url,
        config=cfg,
        authorized=True,
    )

    for res in (res_httpx, res_katana, res_nuclei, res_orch):
        status = res.get("status") if isinstance(res, dict) else getattr(res, "status", None)
        assert status == "disabled"
    assert len(subprocess_recorder.calls) == 0


def test_f08_adapters_reject_non_allowlisted_binary_path(
    subprocess_recorder: Any, loopback_server: Any
) -> None:
    from engine.external_scanners import ExternalScannerConfig, HttpxScannerAdapter

    for bad_bin in ("/tmp/evil/sqlmap", "bash", "cmd.exe", "nmap"):
        cfg = ExternalScannerConfig(enabled=True, binary_path=bad_bin)
        with pytest.raises((PermissionError, ValueError)):
            adapter = HttpxScannerAdapter(config=cfg)
            _invoke_adapter(adapter, target=loopback_server.url, authorized=True)
    assert len(subprocess_recorder.calls) == 0


def test_f08_adapters_reject_invalid_or_injected_flags(
    subprocess_recorder: Any, loopback_server: Any
) -> None:
    from engine.external_scanners import ExternalScannerConfig, HttpxScannerAdapter

    cfg = ExternalScannerConfig(enabled=True)
    adapter = HttpxScannerAdapter(config=cfg)
    with pytest.raises((PermissionError, ValueError, TypeError)):
        _invoke_adapter(
            adapter,
            target=loopback_server.url,
            authorized=True,
            extra_flags=["-exec", "whoami", ";id"],
        )
    assert len(subprocess_recorder.calls) == 0


@pytest.mark.parametrize(
    "bad_tag",
    ["exploit", "dos", "rce", "sqli", "xss", "fuzz", "bruteforce", "intrusive"],
)
def test_f08_nuclei_rejects_destructive_or_intrusive_tags(
    bad_tag: str, subprocess_recorder: Any, loopback_server: Any
) -> None:
    from engine.external_scanners import ExternalScannerConfig, NucleiScannerAdapter

    with pytest.raises((PermissionError, ValueError)):
        cfg = ExternalScannerConfig(enabled=True, nuclei_tags=(bad_tag,))
        adapter = NucleiScannerAdapter(config=cfg)
        _invoke_adapter(adapter, target=loopback_server.url, authorized=True)
    assert len(subprocess_recorder.calls) == 0


def test_f08_adapters_enforce_target_authorization_and_ssrf(
    subprocess_recorder: Any, loopback_server: Any
) -> None:
    from engine.external_scanners import ExternalScannerConfig, HttpxScannerAdapter

    cfg = ExternalScannerConfig(enabled=True)
    adapter = HttpxScannerAdapter(config=cfg)

    for bad_target, auth_flag in (
        ("http://169.254.169.254/latest/meta-data", True),
        ("http://10.0.0.5:8080", True),
        ("https://evil.example.com", False),
    ):
        with pytest.raises((PermissionError, ValueError)):
            _invoke_adapter(adapter, target=bad_target, authorized=auth_flag)
    assert len(subprocess_recorder.calls) == 0

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_server.url}/health", "status_code": 200}) + "\n",
    )
    ok_res = _invoke_adapter(adapter, target=loopback_server.url, authorized=True)
    assert len(subprocess_recorder.calls) == 1
    assert ok_res is not None


def test_f08_adapters_enforce_approval_gate_and_noise_governor_rl(
    subprocess_recorder: Any, loopback_server: Any, isolated_db: Any
) -> None:
    from engine.external_scanners import ExternalScannerConfig, HttpxScannerAdapter

    cfg = ExternalScannerConfig(enabled=True)
    deny_gate = ApprovalGate(mode="deny", db=isolated_db)
    with pytest.raises(PermissionError):
        _invoke_adapter(
            HttpxScannerAdapter(config=cfg, approval_gate=deny_gate),
            target=loopback_server.url,
            authorized=True,
        )
    assert len(subprocess_recorder.calls) == 0

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200}) + "\n",
    )
    policy_gate = ApprovalGate(mode="policy", db=isolated_db)
    governor = NoiseGovernor(profile="quiet")  # rps=2.0
    _invoke_adapter(
        HttpxScannerAdapter(config=cfg, approval_gate=policy_gate, noise_governor=governor),
        target=loopback_server.url,
        authorized=True,
    )
    assert len(subprocess_recorder.calls) == 1
    argv = subprocess_recorder.calls[0]["argv"]
    assert "-rl" in argv
    rl_idx = argv.index("-rl")
    assert argv[rl_idx + 1] == "2"


# =============================================================================
# Feature F9: Host shell=False & Docker shell=False Scanner Execution (5 tests)
# =============================================================================


def test_f09_host_mode_invokes_shell_false_list_argv_with_containment_kwargs(
    subprocess_recorder: Any, loopback_server: Any
) -> None:
    from engine.external_scanners import ExternalScannerConfig, HttpxScannerAdapter
    from engine.host_containment import CREATE_NO_WINDOW

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_server.url}/health", "status_code": 200}) + "\n",
    )
    cfg = ExternalScannerConfig(enabled=True, execution_mode="host")
    _invoke_adapter(
        HttpxScannerAdapter(config=cfg),
        target=loopback_server.url,
        authorized=True,
    )

    assert len(subprocess_recorder.calls) == 1
    call = subprocess_recorder.calls[0]
    assert call["shell"] is False
    assert isinstance(call["argv"], list)
    assert Path(call["argv"][0]).name.lower().startswith("httpx")
    assert "-jsonl" in call["argv"] or "-json" in call["argv"]
    assert call["kwargs"].get("stdin") == subprocess.DEVNULL
    if sys.platform == "win32" or os.name == "nt":
        assert call["kwargs"].get("creationflags", 0) & CREATE_NO_WINDOW


def test_f09_katana_host_mode_jsonl_flags_and_shell_false(
    subprocess_recorder: Any, loopback_server: Any
) -> None:
    from engine.external_scanners import ExternalScannerConfig, KatanaScannerAdapter

    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout=json.dumps({"request": {"endpoint": f"{loopback_server.url}/api/public"}}) + "\n",
    )
    cfg = ExternalScannerConfig(enabled=True, execution_mode="host", rate_limit=3)
    _invoke_adapter(
        KatanaScannerAdapter(config=cfg),
        target=loopback_server.url,
        authorized=True,
    )

    assert len(subprocess_recorder.calls) == 1
    call = subprocess_recorder.calls[0]
    assert call["shell"] is False
    assert isinstance(call["argv"], list)
    assert Path(call["argv"][0]).name.lower().startswith("katana")
    assert "-jsonl" in call["argv"]
    assert "-rl" in call["argv"]


def test_f09_nuclei_host_mode_jsonl_and_nondestructive_tags(
    subprocess_recorder: Any, loopback_server: Any
) -> None:
    from engine.external_scanners import ExternalScannerConfig, NucleiScannerAdapter

    subprocess_recorder.set_response(
        "nuclei",
        returncode=0,
        stdout="",
    )
    cfg = ExternalScannerConfig(
        enabled=True,
        execution_mode="host",
        nuclei_tags=("tech", "misconfig", "exposure", "headers"),
        rate_limit=2,
    )
    _invoke_adapter(
        NucleiScannerAdapter(config=cfg),
        target=loopback_server.url,
        authorized=True,
    )

    assert len(subprocess_recorder.calls) == 1
    call = subprocess_recorder.calls[0]
    assert call["shell"] is False
    argv = call["argv"]
    assert isinstance(argv, list)
    assert Path(argv[0]).name.lower().startswith("nuclei")
    assert "-jsonl" in argv
    assert "-tags" in argv
    tags_val = argv[argv.index("-tags") + 1]
    assert "tech" in tags_val
    assert "-rl" in argv


def test_f09_docker_isolation_mode_invokes_docker_run_shell_false(
    subprocess_recorder: Any, loopback_server: Any
) -> None:
    from engine.external_scanners import ExternalScannerConfig, HttpxScannerAdapter

    subprocess_recorder.set_response(
        "docker",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_server.url}/health", "status_code": 200}) + "\n",
    )
    cfg = ExternalScannerConfig(
        enabled=True,
        execution_mode="docker",
        docker_image="projectdiscovery/httpx:latest",
    )
    _invoke_adapter(
        HttpxScannerAdapter(config=cfg),
        target=loopback_server.url,
        authorized=True,
    )

    assert len(subprocess_recorder.calls) == 1
    call = subprocess_recorder.calls[0]
    assert call["shell"] is False
    argv = call["argv"]
    assert isinstance(argv, list)
    assert Path(argv[0]).name.lower().startswith("docker")
    assert "run" in argv
    assert "--rm" in argv
    assert "projectdiscovery/httpx:latest" in argv


def test_f09_python_httpx_package_not_shadowed_by_adapter() -> None:
    import httpx
    from engine import external_scanners

    assert hasattr(httpx, "Client")
    assert hasattr(httpx, "MockTransport")
    assert hasattr(external_scanners, "HttpxScannerAdapter")


# =============================================================================
# Feature F10: Scanner JSONL -> AssetGraph & DualGraphAttackEngine (5 tests)
# =============================================================================


def test_f10_httpx_jsonl_populates_asset_graph_without_openapi(
    subprocess_recorder: Any, isolated_db: Any, loopback_server: Any, tmp_path: Path
) -> None:
    from engine.external_scanners import ExternalScannerConfig, run_opt_in_external_discovery

    httpx_jsonl = "\n".join(
        [
            json.dumps(
                {
                    "url": f"{loopback_server.url}/health",
                    "host": loopback_server.host,
                    "port": str(loopback_server.port),
                    "status_code": 200,
                    "tech": ["FastAPI", "Uvicorn"],
                }
            ),
            json.dumps(
                {
                    "url": f"{loopback_server.url}/api/public",
                    "host": loopback_server.host,
                    "port": str(loopback_server.port),
                    "status_code": 200,
                    "tech": ["FastAPI"],
                }
            ),
        ]
    )
    subprocess_recorder.set_response("httpx", returncode=0, stdout=httpx_jsonl + "\n")

    engine = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "reports")
    cfg = ExternalScannerConfig(enabled=True)
    run_opt_in_external_discovery(
        target=loopback_server.url,
        config=cfg,
        asset_graph=engine.asset_graph,
        authorized=True,
        run_katana=False,
    )

    domains = engine.asset_graph.find_endpoints_by_type("DOMAIN")
    ip_ports = engine.asset_graph.find_endpoints_by_type("IP_PORT")
    endpoints = engine.asset_graph.find_endpoints_by_type("ENDPOINT")
    assert len(domains) >= 1
    assert len(ip_ports) >= 1
    ep_labels = " ".join(e.label for e in endpoints)
    assert "/health" in ep_labels and "/api/public" in ep_labels


def test_f10_katana_jsonl_discovers_endpoints_js_and_ai_sinks(
    subprocess_recorder: Any, isolated_db: Any, loopback_server: Any, tmp_path: Path
) -> None:
    from engine.external_scanners import ExternalScannerConfig, run_opt_in_external_discovery

    katana_jsonl = "\n".join(
        [
            json.dumps({"request": {"method": "GET", "endpoint": f"{loopback_server.url}/api/public"}}),
            json.dumps({"request": {"method": "GET", "endpoint": f"{loopback_server.url}/app.js"}}),
            json.dumps({"request": {"method": "POST", "endpoint": f"{loopback_server.url}/api/ai/chat"}}),
        ]
    )
    subprocess_recorder.set_response("katana", returncode=0, stdout=katana_jsonl + "\n")

    engine = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "reports")
    cfg = ExternalScannerConfig(enabled=True)
    run_opt_in_external_discovery(
        target=loopback_server.url,
        config=cfg,
        asset_graph=engine.asset_graph,
        authorized=True,
        run_httpx=False,
        run_katana=True,
    )

    endpoints = engine.asset_graph.find_endpoints_by_type("ENDPOINT")
    ai_sinks = engine.asset_graph.find_endpoints_by_type("AI_SINK")
    all_labels = " ".join(n.label for n in endpoints + ai_sinks)
    assert "/api/public" in all_labels
    assert "/app.js" in all_labels
    assert "/api/ai/chat" in all_labels
    assert len(ai_sinks) >= 1


def test_f10_asset_graph_deduplicates_discovered_endpoints(
    subprocess_recorder: Any, isolated_db: Any, loopback_server: Any, tmp_path: Path
) -> None:
    from engine.external_scanners import ExternalScannerConfig, run_opt_in_external_discovery

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200}) + "\n",
    )
    subprocess_recorder.set_response(
        "katana",
        returncode=0,
        stdout="\n".join(
            [
                json.dumps({"request": {"method": "GET", "endpoint": f"{loopback_server.url}/api/public"}}),
                json.dumps({"request": {"method": "GET", "endpoint": f"{loopback_server.url}/api/public"}}),
            ]
        )
        + "\n",
    )

    engine = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "reports")
    engine.ingest_target_infrastructure(
        host=loopback_server.host,
        port=loopback_server.port,
        endpoints=["/api/public"],
    )
    before_count = len(
        [n for n in engine.asset_graph.find_endpoints_by_type("ENDPOINT") if "/api/public" in n.label]
    )

    cfg = ExternalScannerConfig(enabled=True)
    run_opt_in_external_discovery(
        target=loopback_server.url,
        config=cfg,
        asset_graph=engine.asset_graph,
        authorized=True,
    )
    after_count = len(
        [n for n in engine.asset_graph.find_endpoints_by_type("ENDPOINT") if "/api/public" in n.label]
    )
    assert after_count == before_count


def test_f10_nuclei_jsonl_ingests_into_dual_graph_engine(
    subprocess_recorder: Any, isolated_db: Any, loopback_server: Any, tmp_path: Path
) -> None:
    from engine.external_scanners import ExternalScannerConfig, run_opt_in_nuclei_scan

    nuclei_jsonl = json.dumps(
        {
            "template-id": "exposed-admin-panel",
            "info": {
                "name": "Exposed Admin Endpoint",
                "severity": "medium",
                "tags": ["exposure", "misconfig"],
                "classification": {"cwe-id": ["CWE-284"]},
            },
            "matched-at": f"{loopback_server.url}/api/admin",
            "host": loopback_server.host,
        }
    )
    subprocess_recorder.set_response("nuclei", returncode=0, stdout=nuclei_jsonl + "\n")

    engine = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "reports")
    engine.ingest_target_infrastructure(
        host=loopback_server.host,
        port=loopback_server.port,
        endpoints=["/api/admin"],
    )
    cfg = ExternalScannerConfig(enabled=True, nuclei_tags=("exposure", "misconfig"))
    run_opt_in_nuclei_scan(
        target=loopback_server.url,
        config=cfg,
        dual_graph_engine=engine,
        authorized=True,
    )

    primitives = [
        n
        for n in engine.exploration_graph.nodes.values()
        if n.node_type == "FINDING_PRIMITIVE"
    ]
    assert len(primitives) >= 1
    assert any(
        "nuclei" in str(p.attributes.get("scanner", "")).lower()
        or "exposed-admin-panel" in str(p.attributes.get("rule_id", "")).lower()
        or "exposed-admin-panel" in p.label.lower()
        for p in primitives
    )


def test_f10_malformed_jsonl_lines_handled_gracefully(
    subprocess_recorder: Any, isolated_db: Any, loopback_server: Any, tmp_path: Path
) -> None:
    from engine.external_scanners import ExternalScannerConfig, run_opt_in_external_discovery

    mixed_output = "\n".join(
        [
            "",
            "{not valid json!!!",
            json.dumps({"url": f"{loopback_server.url}/api/public", "status_code": 200}),
            "corrupt trailing line",
        ]
    )
    subprocess_recorder.set_response("httpx", returncode=0, stdout=mixed_output + "\n")

    engine = DualGraphAttackEngine(db=isolated_db, reports_dir=tmp_path / "reports")
    cfg = ExternalScannerConfig(enabled=True)
    run_opt_in_external_discovery(
        target=loopback_server.url,
        config=cfg,
        asset_graph=engine.asset_graph,
        authorized=True,
        run_katana=False,
    )

    endpoints = engine.asset_graph.find_endpoints_by_type("ENDPOINT")
    assert any("/api/public" in e.label for e in endpoints)
