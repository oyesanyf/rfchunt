"""
Zero-Mock Tests for ProgramComplianceContext, Strict DNS Label-Boundary Scope Matching,
Fractional Sub-1 RPS Pacing, Tier 1 Fail-Closed Automation Ban, AI-in-Scope Gating,
and Zero Hardcoded Researcher Usernames.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import revenue_cli
from engine.atlas_llm_evaluator import AtlasLLMEvaluator, LLMTargetAdapter
from engine.differential_oracle import (
    MultiImplementationDifferentialOracle,
    TargetEndpoint,
)
from engine.hackerone_porter import (
    HackerOneCampaign,
    HackerOnePublicDirectoryClient,
    validate_finding_against_scope,
)
from engine.linux_poc_runner import LinuxPocRunner
from engine.program_eligibility_db import (
    ProgramEligibilityDB,
    host_matches_scope_pattern,
    is_host_in_scope,
)
from engine.request_hygiene import (
    TokenBucketRateLimiter,
    build_program_compliance_context,
)


@contextlib.contextmanager
def _scoped_env(**updates: str | None):
    saved: dict[str, str | None] = {}
    for k, v in updates.items():
        saved[k] = os.environ.get(k)
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, old in saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


@contextlib.contextmanager
def _loopback_echo_server():
    hits: list[dict[str, Any]] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with lock:
                hits.append(
                    {
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "ts": time.monotonic(),
                    }
                )
            body = json.dumps({"ok": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", hits
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2.0)


def test_dns_label_boundary_wildcard_matching_rejects_suffix_spoofs() -> None:
    assert host_matches_scope_pattern("api.amazon.com", "*.amazon.com") is True
    assert host_matches_scope_pattern("deep.sub.amazon.com", "*.amazon.com") is True
    # Must reject label-boundary spoofing & bare apex when only wildcard is listed
    assert host_matches_scope_pattern("notamazon.com", "*.amazon.com") is False
    assert host_matches_scope_pattern("amazon.com.evil.tld", "*.amazon.com") is False
    assert host_matches_scope_pattern("amazon.com", "*.amazon.com") is False
    assert host_matches_scope_pattern("amazon.com", "amazon.com") is True

    ok_in, _ = is_host_in_scope(
        "api.amazon.com",
        in_scope_assets=["*.amazon.com"],
        out_of_scope_assets=["marketing.amazon.com"],
    )
    assert ok_in is True

    ok_oos, reason_oos = is_host_in_scope(
        "marketing.amazon.com",
        in_scope_assets=["*.amazon.com"],
        out_of_scope_assets=["marketing.amazon.com"],
    )
    assert ok_oos is False
    assert "out_of_scope" in reason_oos

    ok_spoof, _ = is_host_in_scope(
        "notamazon.com",
        in_scope_assets=["*.amazon.com"],
        out_of_scope_assets=[],
    )
    assert ok_spoof is False

    # HackerOne porter validate_finding_against_scope uses strict DNS label matching too
    camp = HackerOneCampaign(
        handle="amazonvrp",
        name="Amazon",
        url="https://hackerone.com/amazonvrp",
        submit_url="https://hackerone.com/amazonvrp/reports/new",
        in_scope_assets=["*.amazon.com"],
        out_of_scope_assets=["marketing.amazon.com"],
    )
    assert validate_finding_against_scope({"asset_identifier": "api.amazon.com"}, camp) == "in_scope"
    assert validate_finding_against_scope({"asset_identifier": "marketing.amazon.com"}, camp) == "out_of_scope"
    assert validate_finding_against_scope({"asset_identifier": "notamazon.com"}, camp) == "manual_verify_required"
    assert validate_finding_against_scope({"asset_identifier": "amazon.com.evil.tld"}, camp) == "manual_verify_required"


def test_compliance_context_tier1_ban_ai_gate_and_zero_hardcoded_usernames(tmp_path: Path) -> None:
    db = ProgramEligibilityDB(tmp_path / "roe_elig.sqlite3")
    db.upsert(
        "no_auto_prog",
        "UNLOCKED",
        roe_automation_tier="explicitly_prohibited",
        roe_automated_prohibited=True,
        roe_max_rps=0.0,
        ai_asset_count=1,
        in_scope_assets=["*.noauto.example"],
    )
    db.upsert(
        "attr_required_prog",
        "UNLOCKED",
        roe_automated_prohibited=False,
        roe_max_rps=0.5,
        roe_required_headers=["X-Bug-Bounty: <MISSING_HACKERONE_USERNAME>"],
        ai_asset_count=0,
        in_scope_assets=["*.attr.example"],
    )
    db.upsert(
        "ai_enabled_prog",
        "UNLOCKED",
        roe_automated_prohibited=False,
        roe_max_rps=0.5,
        ai_asset_count=2,
        in_scope_assets=["api.ai.example"],
    )
    db.upsert("closed_prog", "UNLOCKED", submission_state="disabled")

    with _scoped_env(HACKERONE_RESEARCHER_HANDLE=None, HACKERONE_API_USERNAME=None):
        # Tier 1 ban: live_allowed is False and sandbox HTTP probe sends 0 packets
        ctx_t1 = build_program_compliance_context("no_auto_prog", eligibility_db=db)
        assert ctx_t1.eligible is True
        assert ctx_t1.live_allowed is False
        assert ctx_t1.ai_testing_allowed is False
        assert ctx_t1.automated_prohibited is True

        runner = LinuxPocRunner()
        with _loopback_echo_server() as (base_url, hits):
            probe_t1 = runner.verify_sandbox_http_probe(
                f"{base_url}/check",
                program="no_auto_prog",
                eligibility_db=db,
            )
            assert probe_t1["verified"] is False
            assert probe_t1["status"] == "blocked_by_roe"
            assert len(hits) == 0

            # Missing required attribution username fails closed (never falls back to hardcoded handle)
            ctx_missing = build_program_compliance_context("attr_required_prog", eligibility_db=db)
            assert ctx_missing.live_allowed is False
            assert ctx_missing.reason == "blocked_missing_required_attribution_username"

            # Providing explicit researcher_handle unlocks with fractional 0.5 RPS and proper header
            ctx_ok = build_program_compliance_context(
                "attr_required_prog",
                eligibility_db=db,
                researcher_handle="alice_sec",
            )
            assert ctx_ok.live_allowed is True
            assert ctx_ok.ai_testing_allowed is False
            assert abs(ctx_ok.effective_max_rps - 0.5) < 1e-6
            hdrs = ctx_ok.to_headers_dict()
            assert hdrs.get("X-Bug-Bounty") == "alice_sec"
            assert "oyesanyf" not in json.dumps(hdrs).lower()

            # Program without required username uses generic research UA, zero hardcoded personal handle
            ctx_ai = build_program_compliance_context("ai_enabled_prog", eligibility_db=db)
            assert ctx_ai.live_allowed is True
            assert ctx_ai.ai_testing_allowed is True
            assert abs(ctx_ai.effective_max_rps - 0.5) < 1e-6
            ai_hdrs = ctx_ai.to_headers_dict()
            assert ai_hdrs.get("User-Agent") == "RFCHunt-SecurityResearch/1.0"
            assert "oyesanyf" not in json.dumps(ai_hdrs).lower()

            # Closed submission_state fails closed
            ctx_closed = build_program_compliance_context("closed_prog", eligibility_db=db)
            assert ctx_closed.eligible is False
            assert ctx_closed.live_allowed is False

            # SSRF private non-loopback IP is rejected by authorize_live_host
            ok_ssrf, reason_ssrf = ctx_ai.authorize_live_host("http://169.254.169.254/latest/meta-data/")
            assert ok_ssrf is False
            assert "ssrf_blocked" in reason_ssrf


def test_fractional_sub1_rps_token_bucket_preserves_rate() -> None:
    limiter = TokenBucketRateLimiter(0.5)
    assert abs(limiter.max_rps - 0.5) < 1e-6
    # First acquire consumes initial token immediately
    w1 = limiter.acquire()
    assert w1 == 0.0
    # Fractional token request (0.15 tokens @ 0.5 rps -> ~0.3s wait) proves sub-1 RPS pacing
    t0 = time.monotonic()
    limiter.acquire(tokens=0.15)
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.22


def test_atlas_llm_ai_gate_differential_oracle_roe_and_public_directory_sync(tmp_path: Path) -> None:
    db = ProgramEligibilityDB(tmp_path / "full_roe.sqlite3")
    db.upsert(
        "no_ai_prog",
        "UNLOCKED",
        roe_automated_prohibited=False,
        roe_max_rps=2.0,
        ai_asset_count=0,
        in_scope_assets=["*.noai.example"],
    )
    db.upsert(
        "ai_prog",
        "UNLOCKED",
        roe_automated_prohibited=False,
        roe_max_rps=5.0,
        roe_required_headers=["X-Bug-Bounty: <MISSING_HACKERONE_USERNAME>"],
        ai_asset_count=2,
        in_scope_assets=["*.ai.example"],
    )
    db.upsert(
        "tier1_ban",
        "UNLOCKED",
        roe_automation_tier="explicitly_prohibited",
        roe_automated_prohibited=True,
        roe_max_rps=0.0,
        in_scope_assets=["*.banned.example"],
    )

    llm_hits: list[dict[str, Any]] = []
    graphql_hits: list[dict[str, Any]] = []
    lock = threading.Lock()

    class MultiHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with lock:
                llm_hits.append({"method": "GET", "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}})
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length > 0 else b"{}"
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            if self.path == "/graphql":
                with lock:
                    graphql_hits.append({"path": self.path, "body": json.loads(raw.decode("utf-8"))})
                gql_resp = {
                    "data": {
                        "opportunities_search": {
                            "pageInfo": {"endCursor": None, "hasNextPage": False},
                            "nodes": [
                                {
                                    "handle": "older_vdp",
                                    "name": "Older VDP",
                                    "submission_state": "open",
                                    "started_accepting_at": "2025-01-10T00:00:00Z",
                                    "offers_bounties": False,
                                    "response_efficiency_percentage": 92,
                                    "resolved_report_count": 40,
                                    "structured_scopes": {
                                        "nodes": [
                                            {"asset_identifier": "*.older.example", "asset_type": "WILDCARD", "eligible_for_submission": True}
                                        ]
                                    },
                                },
                                {
                                    "handle": "newest_vdp",
                                    "name": "Newest VDP",
                                    "submission_state": "open",
                                    "started_accepting_at": "2026-11-15T00:00:00Z",
                                    "offers_bounties": False,
                                    "response_efficiency_percentage": 98,
                                    "resolved_report_count": 5,
                                    "gold_standard_safe_harbor": True,
                                    "structured_scopes": {
                                        "nodes": [
                                            {"asset_identifier": "*.newest.example", "asset_type": "WILDCARD", "eligible_for_submission": True},
                                            {"asset_identifier": "https://github.com/newest/api", "asset_type": "SOURCE_CODE", "eligible_for_submission": True},
                                        ]
                                    },
                                },
                                {
                                    "handle": "slow_vdp",
                                    "name": "Slow VDP",
                                    "submission_state": "open",
                                    "started_accepting_at": "2026-11-20T00:00:00Z",
                                    "offers_bounties": False,
                                    "response_efficiency_percentage": 40,
                                    "structured_scopes": {"nodes": []},
                                },
                            ],
                        }
                    }
                }
                body = json.dumps(gql_resp).encode("utf-8")
            else:
                with lock:
                    llm_hits.append({"method": "POST", "path": self.path, "headers": hdrs})
                body = json.dumps({"choices": [{"message": {"content": "I cannot fulfill that unauthorized request."}}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), MultiHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"

        # 1. ATLAS LLM Evaluator fails closed (0 requests) when program has ai_asset_count == 0
        ev_blocked = AtlasLLMEvaluator(LLMTargetAdapter(target=base), concurrency=2)
        rep_blocked = ev_blocked.evaluate(
            suites=["canary", "indirect_exfil"],
            refresh_stix=False,
            program_handle="no_ai_prog",
            eligibility_db=db,
            researcher_handle="alice_sec",
        )
        assert rep_blocked.total_tests == 0
        assert rep_blocked.stix_metadata.get("compliance_blocked") is True
        assert len(llm_hits) == 0

        # 2. ATLAS LLM Evaluator runs indirect_exfil + canary with custom attribution headers when AI is in scope
        ev_ok = AtlasLLMEvaluator(LLMTargetAdapter(target=base), concurrency=2)
        rep_ok = ev_ok.evaluate(
            suites=["canary", "indirect_exfil"],
            refresh_stix=False,
            program_handle="ai_prog",
            eligibility_db=db,
            researcher_handle="alice_sec",
        )
        assert rep_ok.total_tests == 3
        assert rep_ok.passed_tests == 3
        assert len(llm_hits) == 3
        assert all(h["headers"].get("x-bug-bounty") == "alice_sec" for h in llm_hits)

        # 3. Differential oracle blocks Tier 1 automation-prohibited program with 0 packets, injects headers for compliant program
        ctx_t1 = build_program_compliance_context("tier1_ban", eligibility_db=db, researcher_handle="alice_sec")
        oracle_blocked = MultiImplementationDifferentialOracle(
            [TargetEndpoint("lb", "127.0.0.1", server.server_port)],
            compliance_ctx=ctx_t1,
        )
        before_hits = len(llm_hits)
        r_blk = oracle_blocked.dispatch_single_target(
            TargetEndpoint("lb", "127.0.0.1", server.server_port),
            b"GET /diff HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        assert r_blk.socket_state.startswith("BLOCKED_BY_ROE:")
        assert len(llm_hits) == before_hits

        ctx_ok = build_program_compliance_context("ai_prog", eligibility_db=db, researcher_handle="alice_sec")
        oracle_ok = MultiImplementationDifferentialOracle(
            [TargetEndpoint("lb", "127.0.0.1", server.server_port)],
            compliance_ctx=ctx_ok,
        )
        r_ok = oracle_ok.dispatch_single_target(
            TargetEndpoint("lb", "127.0.0.1", server.server_port),
            b"GET /diff HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        assert r_ok.status_code == 200
        assert llm_hits[-1]["headers"].get("x-bug-bounty") == "alice_sec"

        # 4. Public HackerOne Directory sync (zero API token) sorts newest-first & filters <80% efficiency
        pub_client = HackerOnePublicDirectoryClient(endpoint_url=f"{base}/graphql")
        sync_res = pub_client.fetch_and_sync_directory(eligibility_db=db, min_efficiency_pct=80.0, limit=10)
        assert sync_res["upserted"] == ["newest_vdp", "older_vdp"]
        assert "slow_vdp" not in sync_res["upserted"]
        assert graphql_hits[0]["body"]["variables"]["order_by"]["field"] == "launched_at"
        rec_new = db.get("newest_vdp")
        assert rec_new is not None and rec_new.wildcard_count == 1 and rec_new.source_repo_count == 1

        # CLI sync-directory --public-directory
        db2_path = tmp_path / "pub_cli.sqlite3"
        assert (
            revenue_cli.run_revenue_cli(
                [
                    "sync-directory",
                    "--db",
                    str(db2_path),
                    "--public-directory",
                    "--public-endpoint",
                    f"{base}/graphql",
                    "--min-efficiency",
                    "80",
                    "--json",
                ]
            )
            == 0
        )
        db2 = ProgramEligibilityDB(db2_path)
        assert db2.get("newest_vdp") is not None
        assert db2.get("slow_vdp") is None
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2.0)
