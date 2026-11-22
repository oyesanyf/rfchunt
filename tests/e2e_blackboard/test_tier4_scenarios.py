"""
Tier 4 Real-World End-to-End Application Scenarios (8 scenarios matching `TEST_INFRA.md`).
All scenarios execute exclusively against local `127.0.0.1` loopback servers,
`tmp_path` SQLite WAL databases, `RFCHUNT_OFFLINE=1`, and LLM transport-boundary stubs.

Collection-safe: M2-M4 symbols/modules are resolved inside test bodies/helpers.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import urllib.request
from typing import Any, Callable, Dict, List

import pytest
import yaml

from database import Database
from engine.dual_graph_engine import DualGraphAttackEngine
from engine.knowledge_graph import ResearchKnowledgeGraph
from engine.taxonomy import AnomalyCategory, ImpactClass, ImplementationAnomaly, ReproducibleVulnerability
from mcp_server import TerminatorMCPServer
from tests.e2e_blackboard.conftest import REPO_ROOT


def _make_swarm(ws: SimpleNamespace, *, port: int, monkeypatch: pytest.MonkeyPatch) -> Any:
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import ProtocolResearchSwarm

    monkeypatch.setattr(ModelFusionAdapter, "_fetch_available_tags", lambda self: ["gemma2:2b"])
    swarm = ProtocolResearchSwarm(
        host="127.0.0.1",
        port=port,
        db_path=str(ws.db_path),
        use_fusion=False,
        concurrency=2,
    )
    swarm.fetcher.cache_dir = ws.rfcs_dir
    swarm.dream_store.storage_path = str(ws.root / "data" / "dream_policies.json")
    swarm.harness2_engine.runs_root = ws.harness2_runs_dir
    return swarm


# =============================================================================
# Scenario 1: Full Bootstrap -> Reason -> Explore -> DualGraph -> Harness² Lifecycle
# =============================================================================


def test_t4_s01_full_ooda_dual_graph_harness2_lifecycle_on_test_lab_server(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [
            {
                "rationale": "Test CL.0 desync probe",
                "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
                "is_clean": True,
            }
        ],
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        graph = swarm.build_graph()
        assert "blackboard_router" in graph.nodes

        final_state = graph.invoke(
            {
                "rfc_num": "9112",
                "fragments": [],
                "generated_candidates": [],
                "cycle_count": 0,
                "max_cycles": 1,
                "enable_dream_rsi": True,
                "dream_rollouts": 5,
                "enable_harness2": True,
                "harness2_k": 1,
                "harness2_mode": "parallel",
                "harness2_runs_dir": str(isolated_swarm_workspace.harness2_runs_dir),
                "blackboard_bootstrapped": False,
                "task_id": "s01-full",
                "blackboard_domain": "http11_framing",
                "history": [],
            },
            {"recursion_limit": 200},
        )
        assert final_state["blackboard_bootstrapped"] is True
        assert len(swarm.db.get_facts(task_id="s01-full")) >= 1
        assert len(swarm.db.list_intents(status="DONE", task_id="s01-full")) >= 1
        assert len(swarm.db.get_harness2_runs()) == 1
        promoted = [h for h in swarm.db.get_active_hints(domain="http11_framing") if h["source_agent"] == "dream_rsi_agent"]
        assert len(promoted) >= 1

        # Add complementary AUTH_BOUNDARY fact & verify DualGraphAttackEngine chains them
        swarm.db.add_fact(
            "OIDC bypass on /internal/service",
            task_id="s01-full",
            domain="http_semantics_intermediaries",
            payload={"rule_id": "s01-auth", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
        )
        swarm.db.add_fact(
            "CL.0 desync on /",
            task_id="s01-full",
            domain="http11_framing",
            payload={"rule_id": "s01-desync", "cwe": "CWE-444", "capability_class": "DESYNC", "endpoint": "/"},
        )
        eng = DualGraphAttackEngine(db=swarm.db, reports_dir=isolated_swarm_workspace.reports_dir / "s01_dg", task_id="s01-full")
        eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_lab_server.port, endpoints=["/", "/internal/service"])
        created = eng.reason_from_blackboard_facts(db=swarm.db, task_id="s01-full", round_num=1)
        assert len(created) >= 1
    finally:
        swarm.close()


# =============================================================================
# Scenario 2: Crash-and-Resume Across Separate DB Connections
# =============================================================================


def test_t4_s02_crash_and_resume_reclaims_stale_claimed_and_preserves_done_facts(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}],
    )

    # Phase 1: Worker 1 seeds intents, finishes 1, commits FACT, claims 1, and crashes
    db1 = Database(str(isolated_swarm_workspace.db_path), secret_key_path=str(isolated_swarm_workspace.key_path))
    done_id = db1.queue_intent("GET /done HTTP/1.1\r\nHost: target.local\r\n\r\n", priority=30.0, task_id="s02-crash")
    db1.claim_next_intent("worker-1", task_id="s02-crash")
    db1.complete_intent(done_id, status="DONE", result_payload={"verdict": "CONFORMANT"})
    fact_id = db1.add_fact("Confirmed baseline before crash", task_id="s02-crash", domain="http11_framing")

    crashed_id = db1.queue_intent(
        "GET /crashed HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
        priority=20.0,
        task_id="s02-crash",
        payload={"raw_request": "GET /crashed HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True},
    )
    pending_id = db1.queue_intent(
        "GET /pending HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n",
        priority=10.0,
        task_id="s02-crash",
        payload={"raw_request": "GET /pending HTTP/1.1\r\nHost: target.local\r\nConnection: close\r\n\r\n", "is_clean": True},
    )
    claimed = db1.claim_next_intent("worker-1", task_id="s02-crash")
    assert claimed is not None and claimed["node_id"] == crashed_id
    db1.close()

    # Phase 2: Worker 2 resumes on same DB
    executed_urls: List[bytes] = []
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    orig_eval = swarm._evaluate_single_candidate

    def _spy(c: Dict[str, Any]) -> Dict[str, Any]:
        out = orig_eval(c)
        executed_urls.append(out["probe_bytes"])
        return out

    monkeypatch.setattr(swarm, "_evaluate_single_candidate", _spy)
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
                "task_id": "s02-crash",
                "blackboard_domain": "http11_framing",
                "history": [],
            },
            {"recursion_limit": 100},
        )
        assert not any(b"/done" in p for p in executed_urls)
        assert any(b"/crashed" in p for p in executed_urls)
        assert any(b"/pending" in p for p in executed_urls)
        done_ids = {r["node_id"] for r in swarm.db.list_intents(status="DONE", task_id="s02-crash")}
        assert {done_id, crashed_id, pending_id}.issubset(done_ids)
        assert any(f["node_id"] == fact_id for f in swarm.db.get_facts(task_id="s02-crash"))
    finally:
        swarm.close()


# =============================================================================
# Scenario 3: Live Mid-Run CLI + MCP HINT Steering Absorbed on Cycle 2
# =============================================================================


def test_t4_s03_live_midrun_cli_and_mcp_hint_absorbed_on_cycle2_without_restart(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    offline_subprocess_env: Dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    prompts: List[str] = []
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            prompts.append(u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )

    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        st1 = {
            "rfc_num": "9112",
            "fragments": [
                ("Fragment 1: Transfer-Encoding MUST override Content-Length.", "transfer-encoding", 2.0),
                ("Fragment 2: Obsolete line folding obs-fold MUST be rejected.", "obs-fold", 2.0),
            ],
            "task_id": "s03-live",
            "blackboard_domain": "http11_framing",
            "cycle_count": 0,
            "max_cycles": 2,
        }
        out1 = swarm.llm_generator_agent(st1)
        assert "CLI_LIVE_MIDRUN_STEER" not in prompts[0]
        assert "MCP_LIVE_MIDRUN_STEER" not in prompts[0]

        # Inject 1 HINT via CLI subprocess + 1 HINT via MCP server while swarm remains alive
        proc = subprocess.run(
            [
                sys.executable,
                "-u",
                str(REPO_ROOT / "rfc_hunt_swarm.py"),
                "hint",
                "--hint",
                "CLI_LIVE_MIDRUN_STEER",
                "--hint-domain",
                "http11_framing",
                "--hint-priority",
                "40",
                "--hint-task-id",
                "s03-live",
                "--db",
                str(isolated_swarm_workspace.db_path),
            ],
            cwd=str(isolated_swarm_workspace.root),
            env=offline_subprocess_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=25,
        )
        assert proc.returncode == 0

        with TerminatorMCPServer(db_path=str(isolated_swarm_workspace.db_path)) as srv:
            r = srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "inject_blackboard_hint",
                        "arguments": {
                            "hint_text": "MCP_LIVE_MIDRUN_STEER",
                            "domain": "http11_framing",
                            "priority": 60.0,
                            "task_id": "s03-live",
                        },
                    },
                }
            )
            assert "result" in r

        # Cycle 2 on the exact same swarm instance absorbs both live HINTs
        swarm.llm_generator_agent(dict(st1, **out1))
        assert len(prompts) == 2
        assert "CLI_LIVE_MIDRUN_STEER" in prompts[1]
        assert "MCP_LIVE_MIDRUN_STEER" in prompts[1]
    finally:
        swarm.close()


# =============================================================================
# Scenario 4: Cross-RFC Harness² Domain Learning (9112 -> 7230, isolated from 9113)
# =============================================================================


def test_t4_s04_cross_rfc_harness2_domain_learning_and_isolation(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter

    seen_by_rfc: Dict[str, str] = {}
    current_rfc = {"val": "7230"}
    monkeypatch.setattr(
        ModelFusionAdapter,
        "generate_json",
        lambda self, s, u: (
            seen_by_rfc.__setitem__(current_rfc["val"], u)
            or [{"rationale": "ok", "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n", "is_clean": True}]
        ),
    )
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        swarm.dream_rsi_agent(
            {
                "rfc_num": "9112",
                "dream_rollouts": 5,
                "enable_harness2": True,
                "harness2_k": 1,
                "harness2_mode": "parallel",
                "harness2_runs_dir": str(isolated_swarm_workspace.harness2_runs_dir),
                "task_id": "s04-campaign",
                "history": [],
            }
        )
        promoted = [
            h
            for h in swarm.db.get_active_hints(task_id="s04-campaign", domain="http11_framing")
            if h["source_agent"] == "dream_rsi_agent"
        ]
        assert len(promoted) >= 1
        assert promoted[0]["rfc_id"] == "RFC9112"
        marker = promoted[0]["content"][:35]

        current_rfc["val"] = "7230"
        swarm.llm_generator_agent(
            {
                "rfc_num": "7230",
                "fragments": [("RFC 7230 multiple Content-Length MUST be rejected.", "content-length", 2.0)],
                "blackboard_domain": "http11_framing",
                "task_id": "s04-campaign",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert marker in seen_by_rfc["7230"]

        current_rfc["val"] = "9113"
        swarm.llm_generator_agent(
            {
                "rfc_num": "9113",
                "fragments": [("HTTP/2 streams MUST NOT carry Transfer-Encoding.", "transfer-encoding", 2.0)],
                "blackboard_domain": "h2_translation",
                "task_id": "s04-campaign",
                "cycle_count": 0,
                "max_cycles": 1,
            }
        )
        assert marker not in seen_by_rfc["9113"]
    finally:
        swarm.close()


# =============================================================================
# Scenario 5: Desync + Auth-Boundary Multi-Hop Kill Chain & /__lab/patch Retest
# =============================================================================


def test_t4_s05_desync_plus_auth_boundary_multihop_kill_chain_and_lab_patch_retest(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    swarm = _make_swarm(isolated_swarm_workspace, port=loopback_lab_server.port, monkeypatch=monkeypatch)
    try:
        # 1. Verify /internal/service unpatched Bearer returns 200 before patch
        req1 = urllib.request.Request(
            f"http://127.0.0.1:{loopback_lab_server.port}/internal/service",
            headers={"Authorization": "Bearer e2e-user-token"},
        )
        with urllib.request.urlopen(req1, timeout=5) as resp1:
            assert resp1.status == 200

        # 2. triage_debugger_agent confirms desync vulnerability -> writes FACT
        anom = ImplementationAnomaly(
            anomaly_id="ANOM-S05",
            target_engine=f"127.0.0.1:{loopback_lab_server.port}",
            category=AnomalyCategory.PARSER_DIVERGENCE,
            observed_behavior="CL.0 queue poisoning into /internal/service",
            expected_behavior="clean",
            raw_probe=b"GET / HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD",
            raw_response=b"HTTP/1.1 200 OK\r\n\r\nmarker",
        )
        vuln = ReproducibleVulnerability(
            vuln_id="VULN-S05",
            anomaly_id="ANOM-S05",
            impact=ImpactClass.DESYNCHRONIZATION,
            minimized_probe=b"GET / HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD",
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=1,
            provenance_chain="DeltaDebugger",
        )
        monkeypatch.setattr(swarm.classifier, "is_framing_artifact", lambda a, baseline_resp=None: (False, "ok"))
        monkeypatch.setattr(swarm.classifier, "filter_environmental_noise", lambda a, baseline_is_healthy=True, baseline_resp=None: False)
        monkeypatch.setattr(swarm.debugger, "minimize_and_reproduce", lambda a, max_verification_trials=3: vuln)
        monkeypatch.setattr(swarm.classifier, "validate_evidence", lambda v, a, baseline_resp=None: (True, "ok"))
        monkeypatch.setattr(swarm.classifier, "classify_novelty", lambda v: (False, None))

        swarm.triage_debugger_agent(
            {"rfc_num": "9112", "current_anomaly": anom, "task_id": "s05-chain", "blackboard_domain": "http11_framing"}
        )
        swarm.db.add_fact(
            "Confirmed OIDC auth boundary bypass on /internal/service",
            task_id="s05-chain",
            domain="http_semantics_intermediaries",
            payload={"rule_id": "s05-auth", "cwe": "CWE-287", "capability_class": "AUTH_BOUNDARY", "endpoint": "/internal/service"},
        )

        # 3. DualGraphAttackEngine chains DESYNC + AUTH_BOUNDARY -> multi-hop INTENT
        eng = DualGraphAttackEngine(db=swarm.db, reports_dir=isolated_swarm_workspace.reports_dir / "s05", task_id="s05-chain")
        eng.ingest_target_infrastructure(host="127.0.0.1", port=loopback_lab_server.port, endpoints=["/", "/internal/service"])
        created = eng.reason_from_blackboard_facts(db=swarm.db, task_id="s05-chain", round_num=1)
        assert len(created) >= 1
        assert any(int(i["payload"].get("hop_count", 0)) >= 2 for i in swarm.db.list_intents(task_id="s05-chain"))

        # 4. Runtime patch toggle via /__lab/patch?patched=1 -> retest sees HTTP 403
        with urllib.request.urlopen(f"http://127.0.0.1:{loopback_lab_server.port}/__lab/patch?patched=1", timeout=5) as patch_resp:
            assert json.loads(patch_resp.read().decode("utf-8"))["auth_boundary_patched"] is True

        req2 = urllib.request.Request(
            f"http://127.0.0.1:{loopback_lab_server.port}/internal/service",
            headers={"Authorization": "Bearer e2e-user-token"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_403:
            urllib.request.urlopen(req2, timeout=5)
        assert exc_403.value.code == 403
    finally:
        swarm.close()


# =============================================================================
# Scenario 6: `--all` and `--mode all` Multi-Scanner Local Smoke Run
# =============================================================================


def test_t4_s06_all_and_mode_all_local_smoke_against_repo_and_loopback_http(
    isolated_swarm_workspace: SimpleNamespace,
    loopback_http_server: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rfc_hunt_swarm import main_swarm

    mini_repo = isolated_swarm_workspace.root / "s06_repo"
    mini_repo.mkdir()
    (mini_repo / "server.py").write_text(
        "def run_cmd(user_val):\n    return eval(user_val)\n",
        encoding="utf-8",
    )

    for idx, flag_args in enumerate((["--all"], ["--mode", "all"]), start=1):
        out_dir = isolated_swarm_workspace.reports_dir / f"s06_run_{idx}"
        main_swarm(
            [
                *flag_args,
                "--repo",
                str(mini_repo),
                "--host",
                "127.0.0.1",
                "--port",
                str(loopback_http_server.port),
                "--authorized",
                "--no-rea",
                "--db",
                str(isolated_swarm_workspace.db_path),
                "--output-dir",
                str(out_dir),
                "--json",
            ]
        )
        res = json.loads(capsys.readouterr().out)
        assert Path(res["report_files"]["combined_sarif"]).is_file()
        assert Path(res["report_files"]["combined_json"]).is_file()


# =============================================================================
# Scenario 7: Multi-Target `swarm_dispatch.yaml` (Docker + Per-Target Isolation)
# =============================================================================


def test_t4_s07_multi_target_swarm_dispatch_docker_and_isolation(
    tmp_path: Path,
    loopback_http_server: Any,
    loopback_lab_server: Any,
    subprocess_recorder: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.mantis_integrator as mi
    from rfc_hunt_swarm import main_swarm

    subprocess_recorder.set_response(
        "httpx",
        returncode=0,
        stdout=json.dumps({"url": f"{loopback_http_server.url}/health", "status_code": 200}) + "\n",
    )

    recorded_calls: List[Dict[str, Any]] = []
    orig_unified = mi.run_unified_all_scans

    def _spy_unified(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        recorded_calls.append(dict(kwargs))
        call_kw = dict(kwargs)
        call_kw["enable_external_scanners"] = True
        call_kw["httpx_scan"] = True
        call_kw["katana_scan"] = False
        call_kw["nuclei_scan"] = False
        return orig_unified(*args, **call_kw)

    monkeypatch.setattr(mi, "run_unified_all_scans", _spy_unified)

    ws_root = tmp_path / "s07_workspaces"
    cfg_path = tmp_path / "s07_dispatch.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "runtime": {
                    "execution": "docker",
                    "docker_image": "projectdiscovery/httpx:latest",
                    "docker_network": "bridge",
                    "offline": True,
                },
                "workers": {"backend": "all", "concurrency": 1, "use_fusion": False},
                "workspace": {"root": str(ws_root), "per_target_isolation": True},
                "targets": [
                    {"name": "target_http", "host": "127.0.0.1", "port": loopback_http_server.port, "tls": False, "authorized": True, "modes": ["all"], "rfcs": ["9112"]},
                    {"name": "target_lab", "host": "127.0.0.1", "port": loopback_lab_server.port, "tls": False, "authorized": True, "modes": ["all"], "rfcs": ["7230"]},
                ],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    main_swarm(["--dispatch", str(cfg_path)])

    assert len(recorded_calls) == 2
    assert {int(c["port"]) for c in recorded_calls} == {loopback_http_server.port, loopback_lab_server.port}
    for c in recorded_calls:
        assert c.get("scanner_isolation") == "docker"
        assert c.get("docker_image") == "projectdiscovery/httpx:latest"
        assert c.get("docker_network") == "bridge"

    db_files = sorted(ws_root.rglob("*.db"))
    assert len(db_files) == 2
    assert db_files[0].resolve() != db_files[1].resolve()
    assert db_files[0].parent.resolve() != db_files[1].parent.resolve()
    assert all(p.resolve().is_relative_to(ws_root.resolve()) for p in db_files)

    # Verify zero cross-target leakage across per-target isolated SQLite DBs
    db0 = Database(str(db_files[0]), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    db1 = Database(str(db_files[1]), secret_key_path=str(tmp_path / "keys" / "secret.key"))
    try:
        db0.add_fact("isolated-fact-0", task_id="s07-0")
        db1.add_fact("isolated-fact-1", task_id="s07-1")
        assert [f["content"] for f in db0.get_facts(task_id="s07-0")] == ["isolated-fact-0"]
        assert db0.get_facts(task_id="s07-1") == []
        assert [f["content"] for f in db1.get_facts(task_id="s07-1")] == ["isolated-fact-1"]
        assert db1.get_facts(task_id="s07-0") == []
    finally:
        db0.close()
        db1.close()

    docker_calls = [c for c in subprocess_recorder.calls if Path(c["argv"][0]).name.lower().startswith("docker")]
    assert len(docker_calls) >= 2
    assert all(c["shell"] is False and "--network=host" not in c["argv"] and "bridge" in c["argv"] for c in docker_calls)


# =============================================================================
# Scenario 8: Pre-Migration v003 Upgrade -> CLI/MCP Hint -> OODA -> GUI Hygiene
# =============================================================================


def test_t4_s08_premigration_v003_upgrade_cli_mcp_ooda_and_repo_hygiene(
    pre_migration_db_builder: Callable[..., Path],
    isolated_swarm_workspace: SimpleNamespace,
    loopback_lab_server: Any,
    offline_subprocess_env: Dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from model_adapter import ModelFusionAdapter
    from rfc_hunt_swarm import ProtocolResearchSwarm

    untouched_paths = [
        REPO_ROOT / "test_lab_server.py",
        REPO_ROOT / "engine" / "dashboard_generator.py",
        REPO_ROOT / "rfchunt_dashboard.html",
    ]
    snapshots = {p: p.read_bytes() for p in untouched_paths if p.exists()}

    v003_db_path = pre_migration_db_builder("v003", filename="s08_v003.db")

    # 1. CLI hint injection triggers migration 004_blackboard_nodes cleanly
    proc = subprocess.run(
        [
            sys.executable,
            "-u",
            str(REPO_ROOT / "rfc_hunt_swarm.py"),
            "hint",
            "--hint",
            "S08_CLI_UPGRADE_HINT",
            "--hint-domain",
            "http11_framing",
            "--hint-task-id",
            "s08-task",
            "--db",
            str(v003_db_path),
        ],
        cwd=str(isolated_swarm_workspace.root),
        env=offline_subprocess_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=25,
    )
    assert proc.returncode == 0

    # 2. MCP inject_blackboard_hint writes second HINT into upgraded DB
    with TerminatorMCPServer(db_path=str(v003_db_path)) as srv:
        r = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "inject_blackboard_hint",
                    "arguments": {
                        "hint_text": "S08_MCP_UPGRADE_HINT",
                        "domain": "http11_framing",
                        "priority": 45.0,
                        "task_id": "s08-task",
                    },
                },
            }
        )
        assert "result" in r

    # 3. OODA swarm runs on upgraded DB and preserves legacy rows
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
    swarm = ProtocolResearchSwarm(
        host="127.0.0.1",
        port=loopback_lab_server.port,
        db_path=str(v003_db_path),
        use_fusion=False,
        concurrency=1,
    )
    swarm.fetcher.cache_dir = isolated_swarm_workspace.rfcs_dir
    try:
        graph = swarm.build_graph()
        graph.invoke(
            {
                "rfc_num": "9112",
                "fragments": [],
                "generated_candidates": [],
                "cycle_count": 0,
                "max_cycles": 1,
                "enable_dream_rsi": False,
                "enable_harness2": False,
                "blackboard_bootstrapped": False,
                "task_id": "s08-task",
                "blackboard_domain": "http11_framing",
                "history": [],
            },
            {"recursion_limit": 150},
        )
        assert any("S08_CLI_UPGRADE_HINT" in p and "S08_MCP_UPGRADE_HINT" in p for p in seen_prompts)
        assert swarm.db.conn.execute("SELECT rfc_id FROM rfcs").fetchone()[0] == "RFC9112"
        assert swarm.db.conn.execute("SELECT chain_id FROM attack_chains").fetchone()[0] == "legacy-chain-1"
    finally:
        swarm.close()

    for p, content in snapshots.items():
        assert p.read_bytes() == content
