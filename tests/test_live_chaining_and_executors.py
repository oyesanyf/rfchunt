"""
Tests for Pillar 1: Live Tool-Backed ARTEX Worker Executors, Concurrent Workers,
GraphEventBus, ModelFusion LLM Dynamic Planning, Strict POE, and Live Retesting.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from database import Database
from engine.approval_gate import ApprovalGate
from engine.artex_bridge import TrafficCaptureSession
from engine.dual_graph_engine import DualGraphAttackEngine, POELevel
from engine.live_executors import LiveWorkerExecutorRegistry
from engine.session_loader import AuthProfile


class _MockServiceBoundaryServer:
    """
    Local HTTP server simulating GHSA-797p-rrgm-4p56:
    - Anonymous callers on `/internal/service` get 401.
    - Before patching (`patched=False`), an `end_user_oidc` Bearer token wrongly receives 200 OK.
    - After patching (`patched=True`), an `end_user_oidc` Bearer token receives 403 Forbidden.
    """

    def __init__(self) -> None:
        self.patched = False
        self.requests_seen = []
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                parent.requests_seen.append((self.path, auth))
                if self.path.startswith("/internal/service"):
                    if not auth:
                        body = json.dumps({"error": "missing_credentials"}).encode("utf-8")
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    if "end-user-oidc-token" in auth:
                        if parent.patched:
                            body = json.dumps({"error": "service_principal_required"}).encode("utf-8")
                            self.send_response(403)
                        else:
                            body = json.dumps(
                                {"status": "granted", "route": "/internal/service", "scope": "governance-admin"}
                            ).encode("utf-8")
                            self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def test_graph_event_bus_and_concurrent_worker_pool_no_duplicate_claims(tmp_path):
    db = Database(":memory:")
    try:
        engine = DualGraphAttackEngine(db=db, reports_dir=tmp_path / "reports", workers=4)
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=8080,
            endpoints=["/api/v1", "/internal/service", "/admin/exec"],
            ai_sinks=["/api/chat"],
        )
        # Seed multiple capabilities to produce several candidates
        engine.ingest_finding(
            {"rule_id": "MANTIS-PROTO-010", "title": "CL.TE Framing Desync", "cwe": "CWE-444", "file_path": "/api/v1"},
            scanner="prober",
        )
        engine.ingest_finding(
            {"rule_id": "MANTIS-AUTH-011", "title": "OIDC Token on Service Route", "cwe": "CWE-287", "file_path": "/internal/service"},
            scanner="mantis",
        )
        engine.ingest_finding(
            {"rule_id": "MANTIS-CMD-001", "title": "Command Exec Sink", "cwe": "CWE-78", "file_path": "/admin/exec"},
            scanner="mantis",
        )
        engine.ingest_finding(
            {"rule_id": "AISCAN-PROMPT-001", "title": "Unframed LLM Sink", "cwe": "CWE-77", "file_path": "/api/chat"},
            scanner="aiscan",
        )

        claimed_lock = threading.Lock()
        claimed_ids = []
        worker_threads = set()

        def _concurrent_exec(attrs):
            time.sleep(0.02)
            with claimed_lock:
                claimed_ids.append(attrs.get("attack_type"))
                worker_threads.add(threading.get_ident())
            return True, "Concurrent check passed", "GET /api/v1"

        res = engine.run_attack_chain_cycle(round_num=1, executor_fn=_concurrent_exec)
        assert res["candidates_planned"] >= 3
        assert res["exploits_verified"] == res["candidates_planned"]
        # Ensure zero duplicate execution of the exact same todolist step
        step_ids = [s.step_id for s in engine.todolist.steps.values()]
        assert len(step_ids) == len(set(step_ids))
        assert all(s.status == "COMPLETED" for s in engine.todolist.steps.values())
        assert len(worker_threads) >= 2
    finally:
        db.close()


def test_llm_guided_dynamic_planner_valid_and_malformed_fallback(tmp_path):
    class _ValidArbiter:
        def arbitrate_structured_json(self, task_name, system_prompt, user_prompt, default_payload, num_predict=512):
            return {
                "data": {
                    "intents": [
                        {
                            "attack_type": "LLM_AUTH_BOUNDARY_PIVOT",
                            "label": "Cross-role OIDC pivot into internal service endpoint",
                            "target_route": "/internal/service",
                            "method": "GET",
                            "rationale": "Correlate OIDC validation flaw with internal admin endpoint",
                            "steps": [
                                {"capability": "AUTH_BOUNDARY", "desc": "Present end-user OIDC token to /internal/service"},
                                {"capability": "EXEC_SINK", "desc": "Reach privileged governance handler"},
                            ],
                        }
                    ]
                },
                "tokens_used": 420,
                "model": "mock-fusion",
            }

    class _MalformedArbiter:
        def arbitrate_structured_json(self, task_name, system_prompt, user_prompt, default_payload, num_predict=512):
            return {
                "data": "INVALID NOT JSON <<< rm -rf / >>>",
                "intents": "not-a-list",
            }

    db = Database(":memory:")
    try:
        eng = DualGraphAttackEngine(
            db=db,
            reports_dir=tmp_path / "r1",
            task_id="TASK-LLM-PLAN-1",
            arbiter=_ValidArbiter(),
            workers=1,
        )
        eng.ingest_target_infrastructure(host="127.0.0.1", port=8080, endpoints=["/internal/service"])
        eng.ingest_finding(
            {"rule_id": "MANTIS-AUTH-011", "title": "OIDC Service Route Confusion", "cwe": "CWE-287", "file_path": "/internal/service"},
            scanner="mantis",
        )
        res = eng.run_attack_chain_cycle(round_num=1)
        assert res["candidates_planned"] >= 2
        labels = [n.label for n in eng.exploration_graph.nodes.values()]
        assert any("LLM-PLANNED" in lbl or "Cross-role OIDC pivot" in lbl for lbl in labels)
        usage = db.get_task_llm_usage("TASK-LLM-PLAN-1")
        assert usage["total_tokens"] >= 420
        assert usage["total_turns"] >= 1

        # Malformed LLM output must fail-closed to deterministic plan without crashing
        eng_bad = DualGraphAttackEngine(
            db=db,
            reports_dir=tmp_path / "r2",
            task_id="TASK-LLM-PLAN-BAD",
            arbiter=_MalformedArbiter(),
            workers=1,
        )
        eng_bad.ingest_target_infrastructure(host="127.0.0.1", port=8080, endpoints=["/internal/service"])
        eng_bad.ingest_finding(
            {"rule_id": "MANTIS-AUTH-011", "title": "OIDC Service Route Confusion", "cwe": "CWE-287", "file_path": "/internal/service"},
            scanner="mantis",
        )
        res_bad = eng_bad.run_attack_chain_cycle(round_num=1)
        assert res_bad["candidates_planned"] >= 1
    finally:
        db.close()


def test_live_auth_boundary_ghsa_797p_end_to_end_and_live_retest_fix(tmp_path):
    srv = _MockServiceBoundaryServer().start()
    db = Database(":memory:")
    try:
        task_id = "TASK-GHSA-797P"
        traffic_session = TrafficCaptureSession(db=db, task_id=task_id)
        gate = ApprovalGate(mode="policy", db=db)
        profiles = {
            "end_user_oidc": AuthProfile(
                name="end_user_oidc",
                role="end_user_oidc",
                bearer_token="end-user-oidc-token-12345",
            )
        }
        registry = LiveWorkerExecutorRegistry(
            host="127.0.0.1",
            port=srv.port,
            use_tls=False,
            authorized=True,
            traffic_session=traffic_session,
            approval_gate=gate,
            auth_profiles=profiles,
        )
        engine = DualGraphAttackEngine(
            db=db,
            reports_dir=tmp_path / "reports",
            task_id=task_id,
            traffic_session=traffic_session,
            strict_poe=True,
            workers=2,
            approval_gate=gate,
            default_executor_fn=registry.as_executor_fn(),
        )
        engine.ingest_target_infrastructure(
            host="127.0.0.1",
            port=srv.port,
            endpoints=["/internal/service"],
            ai_sinks=[],
        )
        engine.ingest_finding(
            {
                "rule_id": "MANTIS-AUTH-011",
                "title": "OIDC End-User Token Accepted on Service-Only Route",
                "cwe": "CWE-287",
                "file_path": "/internal/service",
            },
            scanner="mantis",
        )

        # Phase 1: Live verification against vulnerable server -> POE=3 VERIFIED_EXPLOIT
        res = engine.run_attack_chain_cycle(round_num=1)
        assert res["exploits_verified"] >= 1
        assert res["poe_breakdown"].get("VERIFIED_EXPLOIT", 0) >= 1

        chains = db.get_attack_chains(task_id=task_id)
        assert len(chains) >= 1
        chain = chains[0]
        assert chain["poe_level"] == int(POELevel.VERIFIED_EXPLOIT)
        assert bool(chain["is_verified"]) is True
        assert chain["traffic_id"]
        assert "governance-admin" in chain["evidence_quote"]
        original_payload = chain["raw_payload"]
        original_traffic_id = chain["traffic_id"]

        # Verify live replay BEFORE patch -> STILL_REPRODUCIBLE
        rt_before = engine.retester.retest_chain(chain, live=True, authorized=True)
        assert rt_before["verdict"] == "STILL_REPRODUCIBLE"
        assert rt_before["replay_traffic_id"]

        # Phase 2: Deploy patch on server -> /internal/service now returns 403 to end-user OIDC token
        srv.patched = True
        rt_after = engine.retester.retest_chain(chain, live=True, authorized=True)
        assert rt_after["verdict"] == "FIXED"
        assert rt_after["replay_traffic_id"] != original_traffic_id

        # Phase 3: Ensure original chain evidence & traffic_id were NEVER overwritten
        chains_after = db.get_attack_chains(task_id=task_id)
        updated = next(c for c in chains_after if c["chain_id"] == chain["chain_id"])
        assert updated["raw_payload"] == original_payload
        assert updated["traffic_id"] == original_traffic_id
        assert updated["verification_status"] == "FIXED"
    finally:
        srv.stop()
        db.close()


def test_strict_poe_rejects_static_poe1_and_preserves_default_compat(tmp_path):
    db = Database(":memory:")
    try:
        # 1. Default strict_poe=False keeps static correlated chains verified (backward compat)
        eng_default = DualGraphAttackEngine(db=db, reports_dir=tmp_path / "r_def", strict_poe=False, workers=1)
        eng_default.ingest_target_infrastructure(host="127.0.0.1", port=8080, endpoints=["/internal/service"])
        eng_default.ingest_finding(
            {"rule_id": "MANTIS-AUTH-011", "title": "OIDC Service Route Flaw", "cwe": "CWE-287", "file_path": "/internal/service"},
            scanner="mantis",
        )
        res_def = eng_default.run_attack_chain_cycle(round_num=1)
        assert res_def["exploits_verified"] >= 1
        # Verify honest static correlation payload (never fake smuggled canary string)
        def_chains = db.get_attack_chains(task_id=eng_default.task_id)
        assert def_chains
        assert "SMUGGLED-CANARY-PAYLOAD" not in def_chains[0]["raw_payload"]
        assert "STRUCTURAL_CORRELATION" in def_chains[0]["raw_payload"]

        # 2. strict_poe=True rejects POE=1 static correlation without live receipt
        eng_strict = DualGraphAttackEngine(db=db, reports_dir=tmp_path / "r_strict", strict_poe=True, workers=1)
        eng_strict.ingest_target_infrastructure(host="127.0.0.1", port=8080, endpoints=["/internal/service"])
        eng_strict.ingest_finding(
            {"rule_id": "MANTIS-AUTH-011", "title": "OIDC Service Route Flaw", "cwe": "CWE-287", "file_path": "/internal/service"},
            scanner="mantis",
        )
        res_strict = eng_strict.run_attack_chain_cycle(round_num=1)
        assert res_strict["exploits_verified"] == 0
    finally:
        db.close()


def test_desync_tool_backed_executor_rejects_plain_200_and_confirms_real_desync():
    plain_srv = _MockServiceBoundaryServer().start()
    db = Database(":memory:")
    try:
        sess = TrafficCaptureSession(db=db, task_id="DESYNC-LIVE")
        reg_plain = LiveWorkerExecutorRegistry(
            host="127.0.0.1",
            port=plain_srv.port,
            authorized=True,
            traffic_session=sess,
        )
        # Plain 200 OK server must NOT confirm DESYNC
        ok_plain, msg_plain, _, _ = reg_plain.execute_candidate_live({
            "capability_class": "DESYNC",
            "attack_type": "PIPELINE_HIJACK",
            "target_route": "/",
        })
        assert ok_plain is False
        assert "not confirmed" in msg_plain.lower()
    finally:
        plain_srv.stop()

    # Real TestLabServer with multipart/byteranges desync trigger MUST confirm DESYNC
    from test_lab_server import TestLabServer
    lab = TestLabServer(host="127.0.0.1", port=0)
    lab.start()
    try:
        reg_lab = LiveWorkerExecutorRegistry(
            host="127.0.0.1",
            port=lab.port,
            authorized=True,
            traffic_session=sess,
        )
        desync_probe = (
            "POST / HTTP/1.1\r\n"
            "Host: target.local\r\n"
            "Content-Type: multipart/byteranges; boundary=abc\r\n"
            "Content-Length: $LENGTH\r\n"
            "Connection: keep-alive\r\n\r\n$PAYLOAD"
        )
        ok_lab, msg_lab, _, meta_lab = reg_lab.execute_candidate_live({
            "capability_class": "DESYNC",
            "attack_type": "PIPELINE_HIJACK",
            "target_route": "/",
            "raw_probe": desync_probe,
        })
        assert ok_lab is True
        assert "DeterministicHarness" in msg_lab
        assert meta_lab["traffic_id"]
        assert meta_lab["evidence_quote"]
    finally:
        lab.stop()
        db.close()


def test_main_retest_cli_host_port_against_test_lab_server(tmp_path):
    import os
    import subprocess
    import sys
    import httpx
    from engine.secret_store import SecretBox
    from test_lab_server import TestLabServer

    lab = TestLabServer(host="127.0.0.1", port=0)
    lab.start()
    db_path = tmp_path / "retest_lab.db"
    os.environ["ARTEX_SECRET_KEY"] = SecretBox.generate_key().hex()
    try:
        db = Database(str(db_path))
        try:
            db.save_traffic_evidence(
                traffic_id="TRF-LAB-1",
                task_id="TASK-LAB-RT",
                method="GET",
                url=f"http://127.0.0.1:{lab.port}/internal/service",
                host="127.0.0.1",
                port=lab.port,
                request_headers={"Authorization": "Bearer end-user-oidc-token"},
                status_code=200,
                response_headers={"Content-Type": "application/json"},
                response_body_b64="eyJzdGF0dXMiOiAiZ3JhbnRlZCIsICJzY29wZSI6ICJnb3Zlcm5hbmNlLWFkbWluIn0=",
            )
            db.save_attack_chain(
                chain_id="CHAIN-LAB-RT-1",
                title="Auth Boundary on /internal/service",
                attack_type="AUTH_BOUNDARY_VIOLATION",
                target_host="127.0.0.1",
                target_endpoint="/internal/service",
                steps=[{"step": 1, "capability": "AUTH_BOUNDARY", "desc": "End-user token accepted"}],
                raw_payload="GET /internal/service",
                is_verified=True,
                task_id="TASK-LAB-RT",
                poe_level=3,
                evidence_quote="governance-admin",
                traffic_id="TRF-LAB-1",
            )
        finally:
            db.close()

        root = str(tmp_path.parent) if False else str(__import__("pathlib").Path(__file__).resolve().parent.parent)
        env = {**os.environ, "RFCHUNT_OFFLINE": "1", "CI": "true"}

        p1 = subprocess.run(
            [sys.executable, "main.py", "retest", "--db", str(db_path), "--chain-id", "CHAIN-LAB-RT-1", "--host", "127.0.0.1", "--port", str(lab.port), "--json"],
            cwd=root, env=env, capture_output=True, text=True, timeout=30,
        )
        assert p1.returncode == 0, p1.stderr + p1.stdout
        out1 = json.loads(p1.stdout)
        assert out1[0]["verdict"] == "STILL_REPRODUCIBLE"

        # Patch lab via /__lab/patch
        patch_resp = httpx.post(f"http://127.0.0.1:{lab.port}/__lab/patch", json={"patched": True}, timeout=5.0)
        assert patch_resp.status_code == 200
        assert patch_resp.json()["auth_boundary_patched"] is True

        p2 = subprocess.run(
            [sys.executable, "main.py", "retest", "--db", str(db_path), "--chain-id", "CHAIN-LAB-RT-1", "--host", "127.0.0.1", "--port", str(lab.port), "--json"],
            cwd=root, env=env, capture_output=True, text=True, timeout=30,
        )
        assert p2.returncode == 0, p2.stderr + p2.stdout
        out2 = json.loads(p2.stdout)
        assert out2[0]["verdict"] == "FIXED"

        # Original evidence & original_traffic_id preserved
        db_check = Database(str(db_path))
        try:
            ch = db_check.get_attack_chains(task_id="TASK-LAB-RT")[0]
            assert ch["raw_payload"] == "GET /internal/service"
            assert ch["traffic_id"] == "TRF-LAB-1"
            assert ch["verification_status"] == "FIXED"
            rtests = db_check.get_chain_retests(chain_id="CHAIN-LAB-RT-1")
            assert any(r.get("original_traffic_id") == "TRF-LAB-1" for r in rtests)
        finally:
            db_check.close()
    finally:
        os.environ.pop("ARTEX_SECRET_KEY", None)
        lab.stop()


def test_asset_graph_deny_hosts_event_bus_and_offline_no_token_charge(tmp_path, monkeypatch):
    from engine.dual_graph_engine import (
        ArtexRetester,
        AssetCoverageLedger,
        AssetGraph,
        GraphEventBus,
        derive_capability_class,
    )

    bus = GraphEventBus()
    ag = AssetGraph(scope_hosts={"example.com"}, deny_hosts={"bad.example.com"}, event_bus=bus)
    assert ag.is_in_scope("api.example.com") is True
    assert ag.is_in_scope("bad.example.com") is False
    ag.add_asset("ASSET-1", "DOMAIN", "api.example.com", {"host": "api.example.com"})
    events = bus.drain()
    assert any(e["event_type"] == "asset_added" for e in events)

    assert derive_capability_class({"title": "JWT audience and issuer confusion on service route"}) == "AUTH_BOUNDARY"
    assert derive_capability_class({"description": "Privilege boundary bypass"}) == "AUTH_BOUNDARY"

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    class _OfflineArbiter:
        def arbitrate_structured_json(self, *a, **kw):
            return {"status": "offline_fallback", "data": {"intents": []}}

    db = Database(":memory:")
    try:
        eng = DualGraphAttackEngine(db=db, reports_dir=tmp_path / "r_off", task_id="TASK-OFF-0", arbiter=_OfflineArbiter(), workers=1)
        eng.ingest_target_infrastructure(host="127.0.0.1", port=8080, endpoints=["/internal/service"])
        eng.ingest_finding({"rule_id": "MANTIS-AUTH-011", "title": "OIDC Service Route", "file_path": "/internal/service"}, scanner="mantis")
        eng.run_attack_chain_cycle(round_num=1)
        # Offline fallback must NOT charge planner tokens or planner turns
        planner_rows = db.conn.execute("SELECT * FROM llm_usage WHERE task_id='TASK-OFF-0' AND role='planner'").fetchall()
        assert len(planner_rows) == 0

        # AssetCoverageLedger class works directly
        ledger = AssetCoverageLedger(eng.asset_graph, eng.exploration_graph).compute()
        assert "coverage_pct" in ledger

        # ArtexRetester 5xx -> CANNOT_CONFIRM
        class _FakeSession:
            def replay_exchange(self, traffic_id, **kwargs):
                from engine.artex_bridge import CapturedExchange
                return CapturedExchange(
                    traffic_id="TRF-500",
                    method="GET",
                    url="http://127.0.0.1/x",
                    host="127.0.0.1",
                    port=80,
                    status_code=503,
                    response_body_b64="U2VydmljZSBVbmF2YWlsYWJsZQ==",
                )
        rt = ArtexRetester(db=db, traffic_session=_FakeSession()).retest_chain(
            {"chain_id": "C-500", "traffic_id": "TRF-ORIG", "evidence_quote": "secret"},
            live=True,
            authorized=True,
        )
        assert rt["verdict"] == "CANNOT_CONFIRM"
    finally:
        db.close()


def test_live_executors_reject_plain_200_ok_for_auth_exec_ssrf_ai_and_3hop():
    import socket as _socket
    from test_lab_server import TestLabServer

    class _Plain200Server:
        def __init__(self) -> None:
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, format, *args):
                    return

                def _reply(self, body: bytes, ctype: str = "text/plain") -> None:
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def do_GET(self):
                    if self.path.startswith("/api/chat"):
                        self._reply(json.dumps({"reply": "ok", "model": "lab-mock", "canary_echo": ""}).encode("utf-8"), "application/json")
                        return
                    self._reply(b"Hello, world!")

                def do_POST(self):
                    if self.path.startswith("/api/chat"):
                        self._reply(json.dumps({"reply": "ok", "model": "lab-mock", "canary_echo": ""}).encode("utf-8"), "application/json")
                        return
                    self._reply(b"Hello, world!")

            self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            self.port = self.server.server_address[1]
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

        def start(self):
            self._thread.start()
            return self

        def stop(self):
            self.server.shutdown()
            self.server.server_close()

    plain_srv = _Plain200Server().start()
    db = Database(":memory:")
    try:
        sess = TrafficCaptureSession(db=db, task_id="PLAIN-200-TEST")
        reg = LiveWorkerExecutorRegistry(
            host="127.0.0.1",
            port=plain_srv.port,
            authorized=True,
            traffic_session=sess,
            auth_profiles={"end_user_oidc": AuthProfile(name="end_user_oidc", role="end_user_oidc", bearer_token="user-tok")},
        )
        cases = [
            {"capability_class": "AUTH_BOUNDARY", "attack_type": "AUTH_BOUNDARY_VIOLATION", "target_route": "/api/public"},
            {"capability_class": "EXEC_SINK", "attack_type": "EXPLOITABLE_SINK_CHAIN", "target_route": "/api/users"},
            {"capability_class": "SSRF_PIVOT", "attack_type": "SSRF_INTERNAL_PIVOT", "target_route": "/api/fetch"},
            {"capability_class": "AI_INJECTION", "attack_type": "AI_PROMPT_TOOL_ESCALATION", "target_route": "/api/chat", "method": "GET"},
            {"capability_class": "MCP_TOOL", "attack_type": "MCP_TOOL", "target_route": "/http"},
            {"capability_class": "DESYNC", "attack_type": "PIPELINE_HIJACK", "target_route": "/"},
            {
                "attack_type": "3HOP_DESYNC_AUTH_BOUNDARY_EXEC",
                "is_multi_hop": True,
                "target_route": "/api/users",
                "auth_route": "/api/public",
                "chain_steps": [
                    {"step": 1, "capability": "DESYNC"},
                    {"step": 2, "capability": "AUTH_BOUNDARY"},
                    {"step": 3, "capability": "EXEC_SINK"},
                ],
            },
            {
                "attack_type": "3HOP_DESYNC_AUTH_BOUNDARY_AI_INJECTION",
                "is_multi_hop": True,
                "has_ai_sink": True,
                "target_route": "/api/chat",
                "auth_route": "/api/public",
                "ai_route": "/api/chat",
                "chain_steps": [
                    {"step": 1, "capability": "DESYNC"},
                    {"step": 2, "capability": "AUTH_BOUNDARY"},
                    {"step": 3, "capability": "AI_INJECTION"},
                ],
            },
        ]
        for attrs in cases:
            ok, _, _, meta = reg.execute_candidate_live(attrs)
            assert ok is False, f"Expected False for {attrs}, got True with meta={meta}"
            assert meta.get("evidence_quote", "") == ""
    finally:
        plain_srv.stop()

    # Positive AI_INJECTION + 3HOP rejection without DESYNC + full TestLabServer verification
    lab = TestLabServer(host="127.0.0.1", port=0)
    lab.start()
    try:
        reg_lab = LiveWorkerExecutorRegistry(
            host="127.0.0.1",
            port=lab.port,
            authorized=True,
            traffic_session=TrafficCaptureSession(db=db, task_id="LAB-AI"),
            auth_profiles={"end_user_oidc": AuthProfile(name="end_user_oidc", role="end_user_oidc", bearer_token="end-user-oidc-token")},
        )
        ok_ai, _, _, meta_ai = reg_lab.execute_candidate_live({
            "capability_class": "AI_INJECTION",
            "attack_type": "AI_PROMPT_TOOL_ESCALATION",
            "target_route": "/api/chat",
            "method": "GET",
            "has_ai_sink": True,
        })
        assert ok_ai is True
        assert "RFCHUNT_CANARY_PROBE" in meta_ai["evidence_quote"]

        # Without a desync-capable probe on plain /internal/service server, 3HOP_DESYNC_AUTH_BOUNDARY_AI_INJECTION must fail
        srv_auth = _MockServiceBoundaryServer().start()
        try:
            reg_no_desync = LiveWorkerExecutorRegistry(
                host="127.0.0.1",
                port=srv_auth.port,
                authorized=True,
                traffic_session=TrafficCaptureSession(db=db, task_id="NO-DESYNC"),
                auth_profiles={"end_user_oidc": AuthProfile(name="end_user_oidc", role="end_user_oidc", bearer_token="end-user-oidc-token")},
            )
            ok_3hop_no, msg_3hop_no, _, _ = reg_no_desync.execute_candidate_live({
                "attack_type": "3HOP_DESYNC_AUTH_BOUNDARY_AI_INJECTION",
                "is_multi_hop": True,
                "has_ai_sink": True,
                "target_route": "/api/chat",
                "auth_route": "/internal/service",
                "ai_route": "/api/chat",
                "chain_steps": [
                    {"step": 1, "capability": "DESYNC"},
                    {"step": 2, "capability": "AUTH_BOUNDARY"},
                    {"step": 3, "capability": "AI_INJECTION"},
                ],
            })
            assert ok_3hop_no is False
            assert "DESYNC" in msg_3hop_no
        finally:
            srv_auth.stop()
    finally:
        lab.stop()
        db.close()


def test_six_worker_concurrent_traffic_session_exchanges(tmp_path):
    db = Database(":memory:")
    try:
        sess = TrafficCaptureSession(db=db, task_id="CONC-6W")
        eng = DualGraphAttackEngine(db=db, reports_dir=tmp_path / "r_conc", workers=6, traffic_session=sess)
        endpoints = [f"/api/v1/item{i}" for i in range(10)]
        eng.ingest_target_infrastructure(host="127.0.0.1", port=8080, endpoints=endpoints)
        for i in range(10):
            eng.ingest_finding(
                {
                    "rule_id": f"MANTIS-AUTH-{i:03d}",
                    "title": f"OIDC Boundary Flaw {i}",
                    "cwe": "CWE-287",
                    "file_path": f"/api/v1/item{i}",
                },
                scanner="mantis",
            )

        errors = []
        stop_bg = threading.Event()

        def _bg_writer():
            idx = 0
            while not stop_bg.is_set() and idx < 200:
                try:
                    sess.record_exchange(
                        method="GET",
                        url=f"http://127.0.0.1:8080/api/v1/item{idx % 10}",
                        status_code=200,
                        response_body=f"ok-{idx}",
                    )
                except Exception as exc:
                    errors.append(exc)
                idx += 1

        def _exec_3tuple(attrs):
            route = attrs.get("target_route") or "/api/v1/item0"
            sess.record_exchange(method="GET", url=f"http://127.0.0.1:8080{route}", status_code=200, response_body="ok")
            return (True, "ok", f"GET {route}")

        bg = threading.Thread(target=_bg_writer, daemon=True)
        bg.start()
        try:
            res = eng.run_attack_chain_cycle(round_num=1, executor_fn=_exec_3tuple)
        finally:
            stop_bg.set()
            bg.join(timeout=5.0)
        assert not errors, f"Concurrency errors: {errors}"
        assert res["exploits_verified"] == res["candidates_planned"]
        assert res["exploits_verified"] >= 10
    finally:
        db.close()


def test_test_lab_server_patch_split_tcp_body():
    import socket as _socket
    from test_lab_server import TestLabServer

    lab = TestLabServer(host="127.0.0.1", port=0)
    lab.start()
    try:
        for desired in (True, False):
            body_bytes = json.dumps({"patched": desired}).encode("utf-8")
            with _socket.create_connection(("127.0.0.1", lab.port), timeout=5.0) as sock:
                hdrs = (
                    f"POST /__lab/patch HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{lab.port}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body_bytes)}\r\n\r\n"
                ).encode("ascii")
                sock.sendall(hdrs)
                time.sleep(0.05)
                sock.sendall(body_bytes)
                raw = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
            text = raw.decode("utf-8", errors="replace")
            assert "200 OK" in text
            payload = json.loads(text.split("\r\n\r\n", 1)[1])
            assert payload["auth_boundary_patched"] is desired
    finally:
        lab.stop()


def test_dual_graph_end_to_end_raw_probe_scanner_propagation_strict_poe(tmp_path):
    from test_lab_server import TestLabServer

    desync_probe = (
        "POST / HTTP/1.1\r\n"
        "Host: target.local\r\n"
        "Content-Type: multipart/byteranges; boundary=abc\r\n"
        "Content-Length: $LENGTH\r\n"
        "Connection: keep-alive\r\n\r\n$PAYLOAD"
    )
    lab = TestLabServer(host="127.0.0.1", port=0)
    lab.start()
    db = Database(":memory:")
    try:
        task_id = "TASK-E2E-PROP"
        sess = TrafficCaptureSession(db=db, task_id=task_id)
        gate = ApprovalGate(mode="policy", db=db)
        reg = LiveWorkerExecutorRegistry(
            host="127.0.0.1",
            port=lab.port,
            authorized=True,
            traffic_session=sess,
            approval_gate=gate,
            auth_profiles={
                "end_user": AuthProfile(
                    name="end_user",
                    role="end_user_oidc",
                    headers={"Authorization": "Bearer end-user-oidc-token"},
                )
            },
        )
        eng = DualGraphAttackEngine(
            db=db,
            reports_dir=tmp_path / "prop_reports",
            task_id=task_id,
            traffic_session=sess,
            strict_poe=True,
            workers=2,
            approval_gate=gate,
        )
        eng.ingest_target_infrastructure(
            host="127.0.0.1",
            port=lab.port,
            endpoints=["/internal/service"],
            ai_sinks=["/api/chat"],
        )
        eng.register_wire_primitive(
            anomaly_id="AFP-1",
            description="multipart/byteranges pipeline desync",
            anomaly_type="CL.TE",
            raw_probe=desync_probe,
            scanner="ActiveFlawProber",
        )
        eng.ingest_finding(
            {
                "rule_id": "MANTIS-AUTH-011",
                "title": "OIDC Service Route Confusion",
                "cwe": "CWE-287",
                "file_path": "/internal/service",
            },
            scanner="mantis",
        )
        eng.ingest_finding(
            {
                "rule_id": "AISCAN-001",
                "title": "Prompt Injection Sink",
                "cwe": "CWE-77",
                "file_path": "/api/chat",
            },
            scanner="aiscan",
        )

        res = eng.run_attack_chain_cycle(round_num=1, executor_fn=reg.as_executor_fn())
        assert res["exploits_verified"] >= 2

        candidates = [
            n for n in eng.exploration_graph.nodes.values()
            if n.node_type == "ATTACK_CANDIDATE"
        ]
        by_type = {c.attributes.get("attack_type"): c for c in candidates}
        for req_type in ("PIPELINE_HIJACK", "3HOP_DESYNC_AUTH_BOUNDARY_AI_INJECTION"):
            assert req_type in by_type, f"Missing planned candidate {req_type}"
            cand = by_type[req_type]
            assert cand.attributes.get("raw_probe") == desync_probe
            assert cand.attributes.get("scanner") == "ActiveFlawProber"
            assert cand.status == "VERIFIED"

        chains = db.get_attack_chains(task_id=task_id)
        chain_by_type = {c["attack_type"]: c for c in chains}
        for req_type in ("PIPELINE_HIJACK", "3HOP_DESYNC_AUTH_BOUNDARY_AI_INJECTION"):
            assert req_type in chain_by_type
            assert chain_by_type[req_type]["poe_level"] == int(POELevel.VERIFIED_EXPLOIT)
            assert bool(chain_by_type[req_type]["is_verified"]) is True
    finally:
        lab.stop()
        db.close()

    # Plain 200 OK server must still fail honestly (ok=False, no POE=3) even with strict_poe=True and propagated raw_probe
    class _Plain200Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            body = b"Hello, world!"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or "0")
            if length:
                self.rfile.read(length)
            body = b"Hello, world!"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    plain_srv = ThreadingHTTPServer(("127.0.0.1", 0), _Plain200Handler)
    plain_port = plain_srv.server_address[1]
    t = threading.Thread(target=plain_srv.serve_forever, daemon=True)
    t.start()
    db_plain = Database(":memory:")
    try:
        sess_p = TrafficCaptureSession(db=db_plain, task_id="TASK-E2E-PLAIN")
        reg_p = LiveWorkerExecutorRegistry(
            host="127.0.0.1",
            port=plain_port,
            authorized=True,
            traffic_session=sess_p,
            auth_profiles={"end_user": AuthProfile(name="end_user", role="end_user_oidc", headers={"Authorization": "Bearer tok"})},
        )
        eng_p = DualGraphAttackEngine(
            db=db_plain,
            reports_dir=tmp_path / "plain_reports",
            task_id="TASK-E2E-PLAIN",
            traffic_session=sess_p,
            strict_poe=True,
            workers=1,
        )
        eng_p.ingest_target_infrastructure(host="127.0.0.1", port=plain_port, endpoints=["/internal/service"], ai_sinks=["/api/chat"])
        eng_p.register_wire_primitive("AFP-P", "probe", anomaly_type="CL.TE", raw_probe=desync_probe, scanner="ActiveFlawProber")
        eng_p.ingest_finding({"rule_id": "MANTIS-AUTH-011", "title": "Auth boundary", "file_path": "/internal/service"}, scanner="mantis")
        eng_p.ingest_finding({"rule_id": "AISCAN-001", "title": "AI", "file_path": "/api/chat"}, scanner="aiscan")

        res_p = eng_p.run_attack_chain_cycle(round_num=1, executor_fn=reg_p.as_executor_fn())
        assert res_p["exploits_verified"] == 0
        assert db_plain.get_attack_chains(task_id="TASK-E2E-PLAIN") == []
    finally:
        plain_srv.shutdown()
        plain_srv.server_close()
        db_plain.close()


def test_verify_auth_boundary_memoization_and_desync_cache_key_separation(tmp_path):
    from unittest.mock import patch

    srv = _MockServiceBoundaryServer().start()
    db = Database(":memory:")
    try:
        sess = TrafficCaptureSession(db=db, task_id="AUTH-CACHE-TEST")
        reg = LiveWorkerExecutorRegistry(
            host="127.0.0.1",
            port=srv.port,
            authorized=True,
            traffic_session=sess,
            auth_profiles={
                "end_user_oidc": AuthProfile(
                    name="end_user_oidc",
                    role="end_user_oidc",
                    bearer_token="end-user-oidc-token-12345",
                )
            },
        )
        first = reg._verify_auth_boundary({"target_route": "/internal/service", "method": "GET"})
        assert first[0] is True
        reqs_after_first = len(srv.requests_seen)
        assert reqs_after_first == 2  # 1 anonymous + 1 end-user

        for _ in range(5):
            cached = reg._verify_auth_boundary({"target_route": "/internal/service", "method": "GET"})
            assert cached == first
        # Memoization must prevent duplicate HTTP probes for identical (host, port, method, route, profile)
        assert len(srv.requests_seen) == reqs_after_first

        # Distinct route must NOT hit the previous route's cache entry
        other = reg._verify_auth_boundary({"target_route": "/other/route", "method": "GET"})
        assert other[0] is False
        assert len(srv.requests_seen) == reqs_after_first + 2

        # _desync_cache must separate entries by (anomaly_type, use_active_prober) when raw_probe is empty
        with (
            patch("protocol_ruler.ProtocolRuler.run_comprehensive_audit", return_value={"expansions": [], "contractions": []}) as mock_ruler,
            patch("engine.active_flaw_prober.ActiveFlawProber.run_active_audit", return_value=[]) as mock_prober,
            patch("deterministic_harness.DeterministicHarness.run_evaluation", return_value=(False, "", "ok", {})),
        ):
            reg._verify_desync({"target_route": "/", "anomaly_type": "RULER"})
            assert mock_ruler.call_count == 1
            assert mock_prober.call_count == 0

            reg._verify_desync({"target_route": "/", "use_active_prober": True})
            assert mock_prober.call_count == 1

            reg._verify_desync({"target_route": "/"})
            assert len(reg._desync_cache) == 3

        # ArtexPlanner must safely tolerate non-dict raw_finding in primitive attributes
        eng = DualGraphAttackEngine(db=db, reports_dir=tmp_path / "non_dict_rf", workers=1)
        eng.ingest_target_infrastructure(host="127.0.0.1", port=srv.port, endpoints=["/internal/service"])
        p = eng.exploration_graph.add_intent(
            node_id="PRIM-NON-DICT",
            node_type="FINDING_PRIMITIVE",
            label="Non-dict raw_finding test",
            attributes={"capability_class": "DESYNC", "raw_finding": "not-a-dict", "scanner": "test"},
            status="VERIFIED",
        )
        assert eng.planner._extract_node_raw_probe(p) == ""
        cands = eng.planner.plan_next_round(round_num=1)
        assert len(cands) >= 1
    finally:
        srv.stop()
        db.close()


def test_cmd_coverage_read_only_hydration_no_db_writeback(tmp_path):
    import argparse
    import main as main_cli

    db_path = tmp_path / "cov_readonly.db"
    db = Database(str(db_path))
    try:
        for i in range(50):
            aid = f"ASSET-{i:03d}"
            eid = f"EXP-{i:03d}"
            db.save_dual_graph_node(aid, "ASSET", "ENDPOINT", f"GET /api/{i}", {"host": "127.0.0.1", "route": f"/api/{i}"})
            db.save_dual_graph_node(eid, "EXPLORATION", "CONFIRMED_EXPLOIT", f"Chain {i}", {"status": "VERIFIED", "anchored_asset": aid})
            if i < 25:
                db.save_exploration_anchor(eid, aid, task_id="TASK-COV")
    finally:
        db.close()

    # Spy on save_dual_graph_node / save_exploration_anchor to prove cmd_coverage does zero DB writes
    orig_save_node = Database.save_dual_graph_node
    orig_save_anchor = Database.save_exploration_anchor
    writes = []

    def _fail_if_called(*args, **kwargs):
        writes.append((args, kwargs))
        return orig_save_node(*args, **kwargs)

    Database.save_dual_graph_node = _fail_if_called  # type: ignore[method-assign]
    Database.save_exploration_anchor = _fail_if_called  # type: ignore[method-assign]
    try:
        main_cli.cmd_coverage(
            argparse.Namespace(db=str(db_path), task_id=None, as_json=True, plain=True)
        )
        assert writes == [], f"cmd_coverage must not write back to SQLite, saw {len(writes)} writes"
    finally:
        Database.save_dual_graph_node = orig_save_node  # type: ignore[method-assign]
        Database.save_exploration_anchor = orig_save_anchor  # type: ignore[method-assign]


def test_verify_desync_concurrent_serialization_no_collision():
    from concurrent.futures import ThreadPoolExecutor
    from test_lab_server import TestLabServer

    lab = TestLabServer(host="127.0.0.1", port=0)
    lab.start()
    db = Database(":memory:")
    try:
        sess = TrafficCaptureSession(db=db, task_id="TASK-DESYNC-RACE")
        reg = LiveWorkerExecutorRegistry(
            host="127.0.0.1",
            port=lab.port,
            authorized=True,
            traffic_session=sess,
            approval_gate=ApprovalGate(mode="policy", db=db),
        )
        collisions = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            for i in range(25):
                with reg._cache_lock:
                    reg._desync_cache.clear()
                f1 = pool.submit(reg._verify_desync, {"target_route": "/", "anomaly_type": "CL.TE"})
                f2 = pool.submit(reg._verify_desync, {"target_route": "/", "anomaly_type": "TE.CL"})
                r1 = f1.result(timeout=15)
                r2 = f2.result(timeout=15)
                if not (r1[0] and r2[0]):
                    collisions.append((i, r1[0], r1[1], r2[0], r2[1]))
        assert collisions == [], f"Concurrent _verify_desync collisions observed: {collisions}"
    finally:
        lab.stop()
        db.close()


def test_database_batch_savepoint_tx_and_coverage_task_isolation(tmp_path, capsys):
    import argparse
    import main as main_cli

    db = Database(":memory:")
    try:
        # 1. Nested batch_writes() must isolate caught inner exception via SAVEPOINT
        with db.batch_writes():
            db.save_dual_graph_node("N_OUTER", "ASSET", "HOST", "outer")
            try:
                with db.batch_writes():
                    db.save_dual_graph_node("N_INNER", "ASSET", "HOST", "inner")
                    raise RuntimeError("inner rollback")
            except RuntimeError:
                pass
            # Legacy methods converted to _tx() must not commit early inside batch_writes()
            db.save_ai_finding("repo", "PROMPT_INJ", "HIGH", "a.py", 1, "gpt", "desc")
        nodes = {n["node_id"] for n in db.get_dual_graph_nodes()}
        assert nodes == {"N_OUTER"}
        assert len(db.get_ai_findings()) == 1

        # Outer rollback must also roll back save_ai_finding inside batch_writes()
        try:
            with db.batch_writes():
                db.save_ai_finding("repo", "PROMPT_INJ", "HIGH", "b.py", 2, "gpt", "rolled back")
                raise RuntimeError("outer rollback")
        except RuntimeError:
            pass
        assert len(db.get_ai_findings()) == 1
    finally:
        db.close()

    # 2. cmd_coverage with explicit --task-id skips EXPLORATION nodes from other tasks
    db_path = tmp_path / "cov_task_iso.db"
    db2 = Database(str(db_path))
    try:
        db2.save_dual_graph_node("A1", "ASSET", "ENDPOINT", "GET /t1", {"host": "127.0.0.1", "route": "/t1"})
        db2.save_dual_graph_node("A2", "ASSET", "ENDPOINT", "GET /t2", {"host": "127.0.0.1", "route": "/t2"})
        db2.save_dual_graph_node(
            "E1", "EXPLORATION", "CONFIRMED_EXPLOIT", "T1 chain",
            {"status": "VERIFIED", "anchored_asset": "A1", "task_id": "T1"},
        )
        db2.save_dual_graph_node(
            "E2", "EXPLORATION", "CONFIRMED_EXPLOIT", "T2 chain",
            {"status": "VERIFIED", "anchored_asset": "A2", "task_id": "T2"},
        )
        db2.save_exploration_anchor("E1", "A1", task_id="T1")
        db2.save_exploration_anchor("E2", "A2", task_id="T2")
    finally:
        db2.close()

    capsys.readouterr()
    main_cli.cmd_coverage(argparse.Namespace(db=str(db_path), task_id="T1", as_json=True, plain=True))
    out = json.loads(capsys.readouterr().out)
    assert out["tested_assets"] == 1
    assert out["coverage_pct"] == 50.0


def test_mantis_auth_011_http_handlefunc_boundary(tmp_path, monkeypatch):
    from engine.mantis_integrator import MantisIntegrator

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    repo = tmp_path / "go_http_handlefunc"
    repo.mkdir()
    (repo / "srv.go").write_text(
        '''package server
import "net/http"
func Register() {
    http.HandleFunc("/internal/unguarded", func(w http.ResponseWriter, r *http.Request) {
        claims, err := verifyOIDC(r.Header.Get("Authorization"))
        if err != nil { w.WriteHeader(401); return }
        _ = claims
        w.WriteHeader(200)
    })
    http.HandleFunc("/public/ping", func(w http.ResponseWriter, r *http.Request) {
        claims, _ := verifyOIDC(r.Header.Get("Authorization"))
        if claims.Aud != "public" { w.WriteHeader(403); return }
        w.WriteHeader(200)
    })
}
''',
        encoding="utf-8",
    )
    db = Database(":memory:")
    try:
        res = MantisIntegrator(db=db, reports_dir=str(tmp_path / "reports"), use_fusion=True).run_scan(
            target_path=str(repo), depth=100, mode="scan"
        )
        auth011 = [f for f in res["findings"] if f["rule_id"] == "MANTIS-AUTH-011"]
        assert len(auth011) == 1
    finally:
        db.close()


def test_mantis_auth_011_upward_guarded_4line_and_5line_handlefunc_no_bleed(tmp_path, monkeypatch):
    from engine.mantis_integrator import MantisIntegrator

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    cases = {
        "guarded_4line": '''package server
import "net/http"
func Register() {
    http.HandleFunc("/public/ping", func(w http.ResponseWriter, r *http.Request) {
        claims, _ := verifyOIDC(r.Header.Get("Authorization"))
        if claims.Aud != "public" { w.WriteHeader(403); return }
    })
    http.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
        claims, err := verifyOIDC(r.Header.Get("Authorization"))
        if err != nil { w.WriteHeader(401); return }
        _ = claims
        w.WriteHeader(200)
    })
}
''',
        "guarded_5line": '''package server
import "net/http"
func Register() {
    http.HandleFunc("/public/ping", func(w http.ResponseWriter, r *http.Request) {
        claims, err := verifyOIDC(r.Header.Get("Authorization"))
        if claims.Aud != "public" { w.WriteHeader(403); return }
        _ = err
    })
    http.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
        claims, err := verifyOIDC(r.Header.Get("Authorization"))
        if err != nil { w.WriteHeader(401); return }
        _ = claims
        w.WriteHeader(200)
    })
}
''',
        "guarded_inline_close": '''package server
import "net/http"
func Register() {
    http.HandleFunc("/public/ping", func(w http.ResponseWriter, r *http.Request) {
        claims, _ := verifyOIDC(r.Header.Get("Authorization"))
        if claims.Aud != "public" { w.WriteHeader(403); return } })
    http.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
        claims, err := verifyOIDC(r.Header.Get("Authorization"))
        if err != nil { w.WriteHeader(401); return }
        _ = claims
        w.WriteHeader(200)
    })
}
''',
    }

    for name, src in cases.items():
        repo = tmp_path / name
        repo.mkdir()
        (repo / "srv.go").write_text(src, encoding="utf-8")
        db = Database(":memory:")
        try:
            res = MantisIntegrator(db=db, reports_dir=str(repo / "reports"), use_fusion=True).run_scan(
                target_path=str(repo), depth=100, mode="scan"
            )
            auth011 = [f for f in res["findings"] if f["rule_id"] == "MANTIS-AUTH-011"]
            assert len(auth011) == 1, f"{name}: expected 1 finding, got {auth011}"
            assert auth011[0]["reproduced"] is True, f"{name}: expected reproduced=True"
            assert auth011[0]["reproduction_tier"] == "TIER_1_STATIC_TAINT", f"{name}: {auth011[0]}"
            assert auth011[0]["cvss_score"] == 7.5, f"{name}: {auth011[0]}"
        finally:
            db.close()
