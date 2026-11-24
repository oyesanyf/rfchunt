"""
Tests for Self-Hosted Mission Control Full-Lifecycle GUI & REST/SSE Server (`--serve-ui`).
"""

from __future__ import annotations

import json
from pathlib import Path
import time
import urllib.error
import urllib.request

import pytest

from engine.mission_control_server import MissionControlOrchestrator, MissionControlServer
from rfc_hunt_swarm import parse_swarm_arguments


def _http_json(url: str, *, method: str = "GET", headers: dict | None = None, payload: dict | None = None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req_headers = dict(headers or {})
    if data is not None:
        req_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, json.loads(body) if body.startswith("{") else {"raw": body}


def test_mission_control_refuses_non_loopback_bind_by_default() -> None:
    with pytest.raises(PermissionError):
        MissionControlServer(host="0.0.0.0", port=0)


def test_mission_control_cli_flags_parsed() -> None:
    args = parse_swarm_arguments(["--serve-ui", "--ui-port", "8799", "--network-lifecycle"])
    assert args.serve_ui is True
    assert args.ui_port == 8799
    assert args.ui_host == "127.0.0.1"
    assert args.network_lifecycle is True


def test_mission_control_server_end_to_end_auth_ssrf_3lane_findings_and_approvals(tmp_path: Path) -> None:
    def _runner(**kwargs):
        return {
            "verified_exploits": [
                {
                    "rule_id": "H2-DESYNC-001",
                    "severity": "CRITICAL",
                    "evidence_lane": "VERIFIED_EXPLOIT",
                    "scanner": "LiveH2DesyncProber",
                    "file_path": "127.0.0.1:8080",
                    "line_number": 1,
                    "title": "Verified HTTP/2 Framing Desync",
                    "poe_level": 3,
                }
            ],
            "deterministic_static_findings": [
                {
                    "rule_id": "INV-COMP-ECHO-METHOD-CRED-LEAK",
                    "severity": "HIGH",
                    "evidence_lane": "DETERMINISTIC_STATIC",
                    "scanner": "VerificationInversionHunter",
                    "file_path": "src/http-proxy.ts",
                    "line_number": 42,
                    "title": "TRACE credential echo",
                    "poe_level": 1,
                }
            ],
            "speculative_hypotheses": [
                {
                    "rule_id": "ARTEX-CHAIN-001",
                    "severity": "LOW",
                    "potential_impact": "CRITICAL",
                    "evidence_lane": "SPECULATIVE_HYPOTHESIS",
                    "scanner": "Module-17-ARTEX",
                    "file_path": "network-target",
                    "line_number": 1,
                    "title": "LEAD [POE=1]: Speculative multi-hop path",
                    "poe_level": 1,
                }
            ],
            "severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "speculative_severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 0},
            "merkle_audit": {
                "status": "no_live_differential_wire_findings",
                "total_leaves": 0,
                "confirmed_leaves": 0,
            },
            "defensive_intelligence": {"status": "skipped_no_verified_wire_exploits", "rules_published": 0},
            "report_files": {},
        }

    orch = MissionControlOrchestrator(
        reports_root=str(tmp_path / "mc_reports"),
        db_path=str(tmp_path / "mc.db"),
        scan_runner=_runner,
    )
    srv = MissionControlServer(host="127.0.0.1", port=0, orchestrator=orch)
    host, port = srv.start_background()
    base = f"http://{host}:{port}"
    tok_hdr = {"X-RFCHunt-Token": srv.session_token}
    try:
        # 1. Interactive SPA HTML with CSP header
        with urllib.request.urlopen(f"{base}/", timeout=5.0) as resp:
            assert resp.status == 200
            assert "default-src 'self'" in (resp.headers.get("Content-Security-Policy") or "")
            html_body = resp.read().decode("utf-8")
            assert "RFCHunt Mission Control" in html_body
            assert "3-Lane Evidence Explorer" in html_body

        # 2. Health endpoint
        st, health = _http_json(f"{base}/api/health")
        assert st == 200 and health["strict_evidence_separation"] is True

        # 3. Missing token rejected on mutating POST
        st_unauth, _ = _http_json(f"{base}/api/tasks", method="POST", payload={"target": str(tmp_path)})
        assert st_unauth == 401

        # 4. Unauthorized external host blocked by SSRF/authorization guard
        st_ssrf, err_body = _http_json(
            f"{base}/api/tasks",
            method="POST",
            headers=tok_hdr,
            payload={"target": "169.254.169.254", "mode": "network_lifecycle", "authorized": False},
        )
        assert st_ssrf == 403
        assert "guard" in err_body.get("error", "").lower()

        # 5. Launch real local repo audit task and verify 3-lane separated findings
        st_ok, task_resp = _http_json(
            f"{base}/api/tasks",
            method="POST",
            headers=tok_hdr,
            payload={"target": str(tmp_path), "mode": "repo_all", "strict_poe": True},
        )
        assert st_ok == 202
        tid = task_resp["task"]["task_id"]

        for _ in range(40):
            _, t_cur = _http_json(f"{base}/api/tasks/{tid}")
            if t_cur["task"]["status"] == "completed":
                break
            time.sleep(0.05)
        assert t_cur["task"]["status"] == "completed"

        _, f_primary = _http_json(f"{base}/api/findings?lane=primary")
        assert len(f_primary["items"]) == 2
        assert all(i["evidence_lane"] != "SPECULATIVE_HYPOTHESIS" for i in f_primary["items"])

        _, f_spec = _http_json(f"{base}/api/findings?lane=speculative")
        assert len(f_spec["items"]) == 1
        assert f_spec["items"][0]["severity"] == "LOW"
        assert f_spec["items"][0]["potential_impact"] == "CRITICAL"

        # 6. Approvals lifecycle
        apr = orch.create_approval_request(
            task_id=tid,
            action_type="live_proxy_fuzz",
            target="127.0.0.1:8080",
            reason="Confirm live loopback proxy fuzzing",
        )
        st_apr, dec_body = _http_json(
            f"{base}/api/approvals/{apr.approval_id}",
            method="POST",
            headers=tok_hdr,
            payload={"decision": "approved"},
        )
        assert st_apr == 200 and dec_body["approval"]["status"] == "approved"

        # 7. SSE one-shot connectivity check
        with urllib.request.urlopen(f"{base}/api/events?once=1", timeout=5.0) as sse_resp:
            assert sse_resp.status == 200
            assert b"connected" in sse_resp.read(512)
    finally:
        srv.stop()
