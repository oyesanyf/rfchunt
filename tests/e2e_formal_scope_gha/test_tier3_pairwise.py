"""
Tier 3 — Cross-Feature Pairwise Integration Tests (13 tests: T3-01 .. T3-13).

Zero mocks, zero fake stubs, zero pytest.skip, strictly defensive-only.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict

import pytest

from tests.e2e_formal_scope_gha.conftest import (
    REPO_ROOT,
    assert_defensive_only_report,
    assert_protected_files_unmodified,
    assert_valid_sarif_210,
    extract_field,
    extract_findings,
    iam_escalation_policy_dict,
    iam_hardened_policy_dict,
    import_contract,
    make_scope_request,
    openapi_auth_bypass_yaml,
    openapi_hardened_yaml,
    resolve_scope_gatekeeper_bin,
    run_revenue_cli_subprocess,
    run_scope_gatekeeper_cli,
    sample_scope_intent,
    sample_scope_policy,
    start_loopback_ollama_server,
    state_machine_safe_dict,
    state_machine_vuln_dict,
    unpack_translation_result,
)

pytestmark = pytest.mark.tier3


def _call_bridge_authorize(bridge: Any, request_payload: Dict[str, Any]) -> Any:
    sig = inspect.signature(bridge.authorize_intent)
    params = list(sig.parameters.keys())
    if "policy" in params and "intent" in params:
        return bridge.authorize_intent(policy=request_payload["policy"], intent=request_payload["intent"])
    return bridge.authorize_intent(request_payload)


def _call_run_z3(
    run_fn: Any,
    *,
    openapi_source: Any = None,
    iam_source: Any = None,
    state_machine_source: Any = None,
    target_description: str | None = None,
    scope_policy: Dict[str, Any] | None = None,
    scope_intent: Dict[str, Any] | None = None,
    offline: bool = True,
) -> Any:
    sig = inspect.signature(run_fn)
    kwargs: Dict[str, Any] = {}
    if openapi_source is not None:
        for k in ("openapi_source", "openapi_spec", "openapi"):
            if k in sig.parameters:
                kwargs[k] = openapi_source
                break
    if iam_source is not None:
        for k in ("iam_source", "iam_policy", "iam"):
            if k in sig.parameters:
                kwargs[k] = iam_source
                break
    if state_machine_source is not None:
        for k in ("state_machine_source", "state_machine", "fsm"):
            if k in sig.parameters:
                kwargs[k] = state_machine_source
                break
    if target_description is not None and "target_description" in sig.parameters:
        kwargs["target_description"] = target_description
    if scope_policy is not None and "scope_policy" in sig.parameters:
        kwargs["scope_policy"] = scope_policy
    if scope_intent is not None:
        for k in ("target_intent", "scope_intent", "intent"):
            if k in sig.parameters:
                kwargs[k] = scope_intent
                break
    if "offline" in sig.parameters:
        kwargs["offline"] = offline
    return run_fn(**kwargs)


def test_t3_01_openapi_parser_into_z3_verifier() -> None:
    parse_openapi = import_contract("engine.z3_formal_verifier", "parse_openapi_spec")
    verify_openapi = import_contract("engine.z3_formal_verifier", "verify_openapi_invariants")

    vuln_rep = verify_openapi(parse_openapi(openapi_auth_bypass_yaml()))
    vuln_findings = extract_findings(vuln_rep)
    assert any(extract_field(f, "status") == "SAT_VIOLATION" for f in vuln_findings)

    safe_rep = verify_openapi(parse_openapi(openapi_hardened_yaml()))
    safe_findings = extract_findings(safe_rep)
    assert all(extract_field(f, "status") == "UNSAT_PROVEN" for f in safe_findings)


def test_t3_02_iam_parser_into_z3_verifier() -> None:
    parse_iam = import_contract("engine.z3_formal_verifier", "parse_iam_policy")
    verify_iam = import_contract("engine.z3_formal_verifier", "verify_iam_invariants")

    esc_rep = verify_iam(parse_iam(iam_escalation_policy_dict()))
    assert any(extract_field(f, "status") == "SAT_VIOLATION" for f in extract_findings(esc_rep))

    hardened = iam_escalation_policy_dict()
    hardened["Statement"].append(
        {"Sid": "ExplicitDenyAllIam", "Effect": "Deny", "Principal": "*", "Action": ["iam:*"], "Resource": "*"}
    )
    safe_rep = verify_iam(parse_iam(hardened))
    assert any(extract_field(f, "status") == "UNSAT_PROVEN" for f in extract_findings(safe_rep))


def test_t3_03_state_machine_parser_into_z3_verifier() -> None:
    parse_fsm = import_contract("engine.z3_formal_verifier", "parse_state_machine")
    verify_fsm = import_contract("engine.z3_formal_verifier", "verify_state_machine_invariants")

    vuln_rep = verify_fsm(parse_fsm(state_machine_vuln_dict()))
    assert any(extract_field(f, "status") == "SAT_VIOLATION" for f in extract_findings(vuln_rep))

    safe_rep = verify_fsm(parse_fsm(state_machine_safe_dict()))
    assert all(extract_field(f, "status") == "UNSAT_PROVEN" for f in extract_findings(safe_rep))


def test_t3_04_model_assisted_translation_into_z3_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    translate = import_contract("engine.z3_formal_verifier", "translate_target_to_formal_model")
    verify_fsm = import_contract("engine.z3_formal_verifier", "verify_state_machine_invariants")

    off_res = translate("Unauthenticated user reaches admin state.", offline=True)
    off_model, off_tele = unpack_translation_result(off_res)
    assert isinstance(off_tele, dict)
    assert off_tele.get("prompt_sanitized") is True
    if off_model is not None:
        rep_off = verify_fsm(off_model)
        assert_defensive_only_report(
            rep_off.to_dict() if hasattr(rep_off, "to_dict") else [getattr(f, "__dict__", f) for f in extract_findings(rep_off)]
        )
    else:
        assert off_tele.get("status") in {"skipped_offline", "skipped_air_gapped", "skipped_embedded"}

    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    monkeypatch.delenv("RFCHUNT_AIR_GAPPED", raising=False)
    formal_json = state_machine_vuln_dict()
    with start_loopback_ollama_server(["qwen2.5:7b"], chat_responder=lambda _r: formal_json) as srv:
        monkeypatch.setenv("OLLAMA_HOST", srv["url"])
        sig = inspect.signature(translate)
        kwargs: Dict[str, Any] = {"model": "qwen2.5:7b", "offline": False}
        for ep_key in ("ollama_endpoint", "endpoint", "base_url"):
            if ep_key in sig.parameters:
                kwargs[ep_key] = srv["url"]
                break
        online_res = translate("Debug promotion path from anon to admin.", **kwargs)
        online_model, online_tele = unpack_translation_result(online_res)
        assert online_model is not None, f"Expected StateMachineIR from loopback Ollama, got telemetry={online_tele}"
        rep_on = verify_fsm(online_model)
        assert any(extract_field(f, "status") == "SAT_VIOLATION" for f in extract_findings(rep_on))


def test_t3_05_rust_gatekeeper_binary_with_python_bridge() -> None:
    RustScopeBridge = import_contract("engine.rust_scope_bridge", "RustScopeBridge")
    ScopeGateDeniedError = import_contract("engine.rust_scope_bridge", "ScopeGateDeniedError")

    bin_path = resolve_scope_gatekeeper_bin()
    bridge = RustScopeBridge()
    policy = sample_scope_policy(allowed_cidrs=["192.0.2.0/24", "2001:db8::/32"], allowed_ports=[443, 8443])

    for ok_intent in (
        sample_scope_intent(target_url="https://192.0.2.10:443/api", host="192.0.2.10", port=443, method="GET"),
        sample_scope_intent(target_url="https://[2001:db8::1]:8443/api", host="2001:db8::1", port=8443, method="GET"),
    ):
        req = make_scope_request(policy=policy, intent=ok_intent)
        _rc, _o, _e, bin_dec = run_scope_gatekeeper_cli(req, bin_path=bin_path)
        br_dec = _call_bridge_authorize(bridge, req)
        assert bin_dec is not None and bin_dec["allowed"] is True and br_dec.allowed is True

    for bad_intent in (
        sample_scope_intent(target_url="https://203.0.113.9:443/api", host="203.0.113.9", port=443, method="GET"),
        sample_scope_intent(target_url="https://192.0.2.10:22/api", host="192.0.2.10", port=22, method="GET"),
        sample_scope_intent(target_url="https://192.0.2.10:443/%252e%252e/admin", host="192.0.2.10", port=443, method="GET"),
    ):
        req = make_scope_request(policy=policy, intent=bad_intent)
        _rc, _o, _e, bin_dec = run_scope_gatekeeper_cli(req, bin_path=bin_path)
        assert bin_dec is not None and bin_dec["allowed"] is False
        try:
            br_dec = _call_bridge_authorize(bridge, req)
            assert br_dec.allowed is False
        except ScopeGateDeniedError:
            pass


def test_t3_06_scope_bridge_gates_z3_formal_verification() -> None:
    run_z3 = import_contract("engine.z3_formal_verifier", "run_z3_formal_verification")
    ScopeGateDeniedError = import_contract("engine.rust_scope_bridge", "ScopeGateDeniedError")

    policy = sample_scope_policy(allowed_cidrs=["192.0.2.0/24"], allowed_ports=[443])
    bad_intent = sample_scope_intent(target_url="https://127.0.0.1:443/admin", host="127.0.0.1", port=443, method="DELETE")

    with pytest.raises((ScopeGateDeniedError, PermissionError, ValueError)):
        _call_run_z3(
            run_z3,
            openapi_source=openapi_auth_bypass_yaml(),
            scope_policy=policy,
            scope_intent=bad_intent,
            offline=True,
        )

    good_intent = sample_scope_intent(target_url="https://192.0.2.10:443/api", host="192.0.2.10", port=443, method="GET")
    rep = _call_run_z3(
        run_z3,
        openapi_source=openapi_auth_bypass_yaml(),
        scope_policy=policy,
        scope_intent=good_intent,
        offline=True,
    )
    assert len(extract_field(rep, "findings")) >= 1


def test_t3_07_z3_findings_into_ensemble_orchestrator_sarif(tmp_path: Path) -> None:
    run_z3 = import_contract("engine.z3_formal_verifier", "run_z3_formal_verification")
    ENGINE_WEIGHTS = import_contract("engine.ensemble_orchestrator", "ENGINE_WEIGHTS")
    EnsembleOrchestrator = import_contract("engine.ensemble_orchestrator", "EnsembleOrchestrator")

    assert ENGINE_WEIGHTS["z3_formal"] == pytest.approx(0.94, abs=1e-6)
    z3_rep = _call_run_z3(run_z3, openapi_source=openapi_auth_bypass_yaml(), offline=True)
    eng_findings = z3_rep.to_engine_findings()
    assert len(eng_findings) >= 1

    orch = EnsembleOrchestrator(embedded=True, enable_llm_verify=False, exhaustive_default=False, quorum=2)
    ens_rep = orch.run(tmp_path, findings=eng_findings, out_dir=tmp_path / "ens_out")
    assert any(c.deterministic_override_protected for c in ens_rep.clusters)
    assert_valid_sarif_210(ens_rep.to_sarif(), require_results=True)


def test_t3_08_revenue_cli_z3_verify_with_scope_policy_and_z3(tmp_path: Path) -> None:
    openapi_f = tmp_path / "openapi.yaml"
    iam_f = tmp_path / "iam.json"
    fsm_f = tmp_path / "fsm.json"
    pol_f = tmp_path / "scope_policy.json"
    sarif_f = tmp_path / "out.sarif"
    out_dir = tmp_path / "cli_out"

    openapi_f.write_text(openapi_auth_bypass_yaml(), encoding="utf-8")
    iam_f.write_text(json.dumps(iam_escalation_policy_dict()), encoding="utf-8")
    fsm_f.write_text(json.dumps(state_machine_vuln_dict()), encoding="utf-8")
    pol_f.write_text(json.dumps(sample_scope_policy(allowed_cidrs=["192.0.2.0/24"], allowed_ports=[443])), encoding="utf-8")

    ok_proc = run_revenue_cli_subprocess(
        [
            "z3-verify",
            "--openapi",
            str(openapi_f),
            "--iam",
            str(iam_f),
            "--state-machine",
            str(fsm_f),
            "--target",
            "https://192.0.2.10:443/api",
            "--scope-policy",
            str(pol_f),
            "--out",
            str(out_dir),
            "--sarif-out",
            str(sarif_f),
            "--json",
        ]
    )
    assert ok_proc.returncode == 0, f"STDOUT:\n{ok_proc.stdout}\nSTDERR:\n{ok_proc.stderr}"
    assert isinstance(json.loads(ok_proc.stdout), dict)
    assert_valid_sarif_210(json.loads(sarif_f.read_text(encoding="utf-8")), require_results=True)

    deny_proc = run_revenue_cli_subprocess(
        [
            "z3-verify",
            "--openapi",
            str(openapi_f),
            "--target",
            "https://10.0.0.5:443/api",
            "--scope-policy",
            str(pol_f),
        ]
    )
    assert deny_proc.returncode != 0


def test_t3_09_bugbounty_mcp_bb_z3_formal_verify_with_scope_and_z3(tmp_path: Path) -> None:
    BugBountyMCPServer = import_contract("bugbounty_mcp_server", "BugBountyMCPServer")
    openapi_f = tmp_path / "openapi.yaml"
    iam_f = tmp_path / "iam.json"
    openapi_f.write_text(openapi_auth_bypass_yaml(), encoding="utf-8")
    iam_f.write_text(json.dumps(iam_escalation_policy_dict()), encoding="utf-8")

    srv = BugBountyMCPServer()
    ok_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "bb_z3_formal_verify",
                "arguments": {
                    "openapi_path": str(openapi_f),
                    "iam_path": str(iam_f),
                    "target_url": "https://192.0.2.10:443/api",
                    "scope_policy": sample_scope_policy(allowed_cidrs=["192.0.2.0/24"], allowed_ports=[443]),
                },
            },
        }
    )
    assert ok_resp["result"]["isError"] is False
    ok_payload = json.loads(ok_resp["result"]["content"][0]["text"])
    assert isinstance(ok_payload, dict)

    deny_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "bb_z3_formal_verify",
                "arguments": {
                    "openapi_path": str(openapi_f),
                    "target_url": "https://10.0.0.9:443/api",
                    "scope_policy": sample_scope_policy(allowed_cidrs=["192.0.2.0/24"], allowed_ports=[443]),
                },
            },
        }
    )
    deny_payload = json.loads(deny_resp["result"]["content"][0]["text"])
    assert deny_resp["result"]["isError"] is True or deny_payload.get("allowed") is False or "denied" in json.dumps(deny_payload).lower()


def test_t3_10_linux_kani_ci_workflow_passes_gha_scanners_raptor_atlas(monkeypatch: pytest.MonkeyPatch) -> None:
    run_zizmor = import_contract("engine.gha_workflow_scanners", "run_zizmor_scan")
    run_actionlint = import_contract("engine.gha_workflow_scanners", "run_actionlint_scan")
    audit_repo = import_contract("engine.gha_agent_auditor", "audit_gha_agent_repository")
    resolve_llm = import_contract("engine.gha_llm_verifier", "resolve_gha_llm_backend")
    verify_llm = import_contract("engine.gha_llm_verifier", "verify_gha_findings_with_llm")
    EnsembleOrchestrator = import_contract("engine.ensemble_orchestrator", "EnsembleOrchestrator")

    wf = REPO_ROOT / ".github" / "workflows" / "rust-kani-z3-ci.yml"
    assert wf.is_file(), f"Missing {wf}"

    ziz = run_zizmor(wf, embedded=True)
    act = run_actionlint(wf, embedded=True)
    agent_f = audit_repo(wf)
    bad = [f for f in [*ziz.findings, *act.findings, *agent_f] if f.severity in ("CRITICAL", "HIGH") and not getattr(f, "hygiene_only", False)]
    assert bad == [], f"Unexpected CRITICAL/HIGH on rust-kani-z3-ci.yml: {bad}"

    assert resolve_llm(offline=True, ollama_endpoint="https://example.invalid").status == "skipped_offline"

    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    monkeypatch.delenv("RFCHUNT_AIR_GAPPED", raising=False)
    with start_loopback_ollama_server(["qwen2.5:7b"], chat_responder=lambda _r: {"verdicts": []}) as srv:
        _lf, tele = verify_llm(wf, ziz.findings, ollama_endpoint=srv["url"], force_ollama=True, offline=False)
        assert tele["status"] in ("completed", "skipped_no_workflows")

    orch = EnsembleOrchestrator(embedded=True, enable_llm_verify=False, gha_only=True)
    rep = orch.run(wf)
    assert_valid_sarif_210(rep.to_sarif(), require_results=False)


def test_t3_11_kani_proof_harnesses_align_with_gatekeeper_and_ci() -> None:
    wf = REPO_ROOT / ".github" / "workflows" / "rust-kani-z3-ci.yml"
    assert wf.is_file(), f"Missing {wf}"
    wf_txt = wf.read_text(encoding="utf-8")
    assert "cargo kani" in wf_txt and "cargo test" in wf_txt and "rust_scope_gatekeeper" in wf_txt

    cargo_exe = shutil.which("cargo")
    assert cargo_exe
    manifest = REPO_ROOT / "rust_scope_gatekeeper" / "Cargo.toml"
    proc = subprocess.run(
        [cargo_exe, "test", "--manifest-path", str(manifest)],
        shell=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    bin_path = resolve_scope_gatekeeper_bin()
    _rc, _o, _e, dec = run_scope_gatekeeper_cli(
        make_scope_request(
            policy=sample_scope_policy(allowed_cidrs=["192.0.2.0/24"], allowed_ports=[443]),
            intent=sample_scope_intent(target_url="https://192.0.2.10:22/", host="192.0.2.10", port=22, method="GET"),
        ),
        bin_path=bin_path,
    )
    assert dec is not None and dec["allowed"] is False


def test_t3_12_scope_bridge_gates_gha_and_atlas_audits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    RustScopeBridge = import_contract("engine.rust_scope_bridge", "RustScopeBridge")
    ScopeGateDeniedError = import_contract("engine.rust_scope_bridge", "ScopeGateDeniedError")
    LLMTargetAdapter = import_contract("engine.atlas_llm_evaluator", "LLMTargetAdapter")
    AtlasLLMEvaluator = import_contract("engine.atlas_llm_evaluator", "AtlasLLMEvaluator")
    AtlasStixSyncManager = import_contract("engine.mitre_atlas_stix", "AtlasStixSyncManager")

    bridge = RustScopeBridge()
    unapproved = make_scope_request(
        policy=sample_scope_policy(allowed_cidrs=["127.0.0.1/32"], allowed_ports=[11434]),
        intent=sample_scope_intent(target_url="https://203.0.113.99:443/v1/chat/completions", host="203.0.113.99", port=443, method="POST"),
    )
    try:
        dec = _call_bridge_authorize(bridge, unapproved)
        assert dec.allowed is False
    except ScopeGateDeniedError:
        pass

    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    monkeypatch.delenv("RFCHUNT_AIR_GAPPED", raising=False)
    with start_loopback_ollama_server(["qwen2.5:7b"], openai_responder=lambda _r: "I cannot comply with unauthorized requests.") as srv:
        loopback_port = int(srv["port"])
        ok_req = make_scope_request(
            policy=sample_scope_policy(allowed_cidrs=["127.0.0.1/32"], allowed_ports=[loopback_port]),
            intent=sample_scope_intent(target_url=f"http://127.0.0.1:{loopback_port}/v1/chat/completions", host="127.0.0.1", port=loopback_port, method="POST"),
        )
        ok_dec = _call_bridge_authorize(bridge, ok_req)
        assert ok_dec.allowed is True

        adapter = LLMTargetAdapter(target=srv["url"], model="qwen2.5:7b", timeout_sec=5.0)
        evaluator = AtlasLLMEvaluator(adapter=adapter, sync_manager=AtlasStixSyncManager(cache_dir=tmp_path / "stix"), concurrency=2)
        rep = evaluator.evaluate(suites=("canary",), refresh_stix=False)
        assert rep.canary_leaks == 0


def test_t3_13_full_pipeline_preserves_protected_files(tmp_path: Path) -> None:
    run_z3 = import_contract("engine.z3_formal_verifier", "run_z3_formal_verification")
    RustScopeBridge = import_contract("engine.rust_scope_bridge", "RustScopeBridge")
    EnsembleOrchestrator = import_contract("engine.ensemble_orchestrator", "EnsembleOrchestrator")
    BugBountyMCPServer = import_contract("bugbounty_mcp_server", "BugBountyMCPServer")

    _call_bridge_authorize(RustScopeBridge(), make_scope_request())
    z3_rep = _call_run_z3(run_z3, openapi_source=openapi_auth_bypass_yaml(), offline=True)
    orch = EnsembleOrchestrator(embedded=True, enable_llm_verify=False, exhaustive_default=False)
    orch.run(tmp_path, findings=z3_rep.to_engine_findings(), out_dir=tmp_path / "ens")
    spec_path = tmp_path / "openapi.yaml"
    spec_path.write_text(openapi_auth_bypass_yaml(), encoding="utf-8")
    BugBountyMCPServer().handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "bb_z3_formal_verify", "arguments": {"openapi_path": str(spec_path)}}}
    )
    assert_protected_files_unmodified()
