"""
Zero-Mock Unit & Integration Tests for ACDSO-Adapted ML HackerOne Program Selector,
Generalized Pareto Frontier, Two-Phase Portfolio Knapsack, Pure-Python PolicyLearner,
BoostDecisionAdapter, CLI (`rank-programs`, `sync-directory`, `record-outcome`), and MCP tools.

Strictly uses real SQLite WAL files, real loopback ThreadingHTTPServer endpoints,
and zero `unittest.mock` / `MagicMock` / `monkeypatch`.
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import threading
from typing import Any, Dict, List

import pytest

from bugbounty_mcp_server import BugBountyMCPServer, TOOLS_SCHEMA
from engine.acdso_bridge import (
    ContextualBanditEnv,
    MultiObjectiveCandidate,
    PolicyLearner,
    generalized_pareto_front,
    select_pareto_knee,
)
from engine.boost_decision_adapter import (
    BoostDecisionAdapter,
    probe_modelfusion_decision_api,
)
from engine.ml_program_selector import (
    DailyHuntPortfolioOptimizer,
    OnlineProgramBandit,
    PortfolioItem,
    ProgramFeatureExtractor,
    ProgramRanker,
    ProgramSurvivalModel,
    classify_program_lane,
    compute_unlock_distance,
    concordance_index,
    ndcg_at_k,
    rank_hackerone_programs,
)
from engine.program_eligibility_db import (
    AccountSignalState,
    ProgramEligibilityDB,
    parse_scope_prose_metadata,
)
import revenue_cli


@contextlib.contextmanager
def _scoped_env(**updates: str | None):
    saved: Dict[str, str | None] = {}
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
def _modelfusion_loopback_server(decision_winner: str, reject_slop: bool = False):
    calls: List[Dict[str, Any]] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                body = json.dumps({"status": "ok", "engine": "modelfusion"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/api/decision":
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(length) if length > 0 else b"{}"
                payload = json.loads(raw.decode("utf-8"))
                with lock:
                    calls.append(payload)
                resp = {
                    "selected_id": decision_winner,
                    "reject_as_slop": bool(reject_slop),
                    "reason": "critic_rejected_low_evidence" if reject_slop else "ok",
                }
                body = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", calls
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2.0)


def test_schema_v2_migration_scope_backfill_and_unlock_distance(tmp_path: Path) -> None:
    db = ProgramEligibilityDB(tmp_path / "elig_v2.sqlite3")
    counts = db.seed_observed_hackerone_baseline()
    assert counts["UNLOCKED"] >= 10
    assert counts["BLOCKED_SIGNAL"] >= 10

    meta = parse_scope_prose_metadata(
        "acme_prog",
        "*.example.com, api.example.com, https://github.com/acme/core, Android APK, LLM prompt endpoint",
    )
    assert meta["wildcard_count"] >= 1
    assert meta["api_asset_count"] >= 1
    assert meta["source_repo_count"] >= 1
    assert meta["mobile_asset_count"] >= 1
    assert meta["ai_asset_count"] >= 1

    # D4 fix: unestablished Signal (None) yields finite non-zero unlock distance & VDP count
    shopify = db.get("shopify")
    assert shopify is not None
    unest = AccountSignalState(signal_established=False, signal_score=None)
    ud_unest = compute_unlock_distance(shopify, unest)
    assert ud_unest["distance"] > 0.0
    assert ud_unest["estimated_vdp_reports_needed"] >= 1

    est_low = AccountSignalState(signal_established=True, signal_score=0.2)
    est_high = AccountSignalState(signal_established=True, signal_score=5.0)
    ud_low = compute_unlock_distance(shopify, est_low)
    ud_high = compute_unlock_distance(shopify, est_high)
    assert ud_low["distance"] > ud_high["distance"]
    assert ud_high["distance"] == 0.0


def test_classify_program_lane_and_efficiency_deferral(tmp_path: Path) -> None:
    db = ProgramEligibilityDB(tmp_path / "lanes.sqlite3")
    now = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)
    db.upsert(
        "fresh_vdp",
        "UNLOCKED",
        is_vdp=True,
        offers_bounties=False,
        bounty_max_usd=0,
        response_efficiency_pct=96.0,
        launched_at_utc=(now - timedelta(days=20)).isoformat(),
        now=now,
    )
    db.upsert(
        "fresh_bbp",
        "UNLOCKED",
        is_vdp=False,
        offers_bounties=True,
        bounty_max_usd=25000,
        response_efficiency_pct=94.0,
        launched_at_utc=(now - timedelta(days=30)).isoformat(),
        now=now,
    )
    db.upsert(
        "slow_bbp",
        "UNLOCKED",
        is_vdp=False,
        offers_bounties=True,
        bounty_max_usd=15000,
        response_efficiency_pct=45.0,
        now=now,
    )
    db.upsert("locked_bbp", "BLOCKED_SIGNAL", signal_required=3.0, now=now)

    assert classify_program_lane(db.get("fresh_vdp"), min_efficiency_pct=80.0)[0] == "LANE_1_VDP_FAST_SIGNAL"
    assert classify_program_lane(db.get("fresh_bbp"), min_efficiency_pct=80.0)[0] == "LANE_2_BBP_HIGH_EV"
    assert classify_program_lane(db.get("slow_bbp"), min_efficiency_pct=80.0)[0] == "DEFERRED_LOW_EFFICIENCY"
    assert classify_program_lane(db.get("locked_bbp"), min_efficiency_pct=80.0)[0] == "BLOCKED"


def test_fenwick_concordance_index_and_breslow_cox_survival() -> None:
    # Exact concordance check: higher risk corresponds to shorter time-to-duplicate
    c_perf = concordance_index([10.0, 20.0, 30.0, 40.0], [1, 1, 1, 1], [4.0, 3.0, 2.0, 1.0])
    c_inv = concordance_index([10.0, 20.0, 30.0, 40.0], [1, 1, 1, 1], [1.0, 2.0, 3.0, 4.0])
    c_ties = concordance_index([10.0, 20.0, 30.0], [1, 1, 0], [2.0, 2.0, 1.0])
    assert c_perf == 1.0
    assert c_inv == 0.0
    assert 0.5 <= c_ties <= 1.0

    # Overflow-free Breslow Cox PH model (stays on cold prior below n=20; refits cleanly at n>=20)
    base_X = [
        [0.1, 0.2, 8.0, 0.9],
        [0.15, 0.2, 7.5, 0.8],
        [0.9, 0.9, 1.0, 0.2],
        [0.95, 0.85, 0.5, 0.1],
        [0.2, 0.3, 6.0, 0.85],
        [0.85, 0.9, 1.2, 0.15],
        [0.12, 0.25, 7.2, 0.9],
        [0.92, 0.88, 0.8, 0.12],
    ]
    base_times = [6.0, 10.0, 120.0, 150.0, 14.0, 110.0, 8.0, 140.0]
    base_events = [1, 1, 0, 0, 1, 0, 1, 0]

    cold_model = ProgramSurvivalModel(l2=0.5).fit(base_X, base_times, base_events)
    assert cold_model.fitted_on_outcomes is False

    X = base_X * 7
    times = [t + 0.1 * rep for rep in range(7) for t in base_times]
    events = base_events * 7
    model = ProgramSurvivalModel(l2=0.5)
    model.fit(X, times, events)
    assert model.fitted_on_outcomes is True
    s_saturated = model.predict_fresh_survival([0.1, 0.2, 8.0, 0.9], window_hours=72.0)
    s_fresh = model.predict_fresh_survival([0.95, 0.9, 0.5, 0.1], window_hours=72.0)
    assert 0.0 <= s_saturated <= 1.0
    assert 0.0 <= s_fresh <= 1.0
    assert s_fresh >= s_saturated

    # Extreme values must never raise OverflowError or produce NaN
    s_extreme = model.predict_fresh_survival([1e6, -1e6, 1e6, 1e6], window_hours=72.0)
    assert math.isfinite(s_extreme) and 0.0 <= s_extreme <= 1.0


def test_ltr_3tier_curriculum_ndcg_tie_awareness_and_generalized_pareto(tmp_path: Path) -> None:
    # D3 tie-aware NDCG must not depend on arbitrary tie order
    n1 = ndcg_at_k([1.0, 0.0, 0.0], [0.5, 0.5, 0.5], k=3)
    n2 = ndcg_at_k([0.0, 0.0, 1.0], [0.5, 0.5, 0.5], k=3)
    assert abs(n1 - n2) < 1e-6

    # D2 generalized Pareto front with mixed directions (MAX obj0, MIN obj1..5) and zero double-log
    dirs = (True, False, False)
    cands = [
        MultiObjectiveCandidate("winner", (0.95, 0.10, 0.10), directions=dirs),
        MultiObjectiveCandidate("dominated", (0.50, 0.80, 0.80), directions=dirs),
        MultiObjectiveCandidate("tradeoff", (0.80, 0.02, 0.05), directions=dirs),
    ]
    front = generalized_pareto_front(cands, directions=dirs)
    front_names = {c.name for c in front}
    assert "winner" in front_names
    assert "tradeoff" in front_names
    assert "dominated" not in front_names
    knee_c, scores = select_pareto_knee(front, directions=dirs)
    assert knee_c.name in front_names
    assert all(math.isfinite(v) for v in scores.values())

    # 3-tier sample-size curriculum: <15 outcomes stays Tier 0 cold prior
    db = ProgramEligibilityDB(tmp_path / "ltr.sqlite3")
    db.seed_observed_hackerone_baseline()
    recs = db.list_unlocked()
    ext = ProgramFeatureExtractor([])
    extracted = {r.handle.lower(): ext.extract(r) for r in recs}
    ranker_cold = ProgramRanker(preset="signal_fast").fit_from_outcomes(extracted, [])
    assert ranker_cold.tier_active == 0

    # With 20 outcomes across >=3 programs, GroupKFold runs cleanly without crashing
    for i in range(20):
        rec = recs[i % len(recs)]
        db.record_hunt_outcome(
            handle=rec.handle,
            outcome="TRIAGED" if i % 2 == 0 else "DUPLICATE",
            lane=1 if rec.is_vdp else 2,
            target_age_hours=float(2 + i),
            signal_delta=7.0 if i % 2 == 0 else 0.0,
        )
    outcomes = db.list_hunt_outcomes(limit=100)
    ranker_warm = ProgramRanker(preset="signal_fast").fit_from_outcomes(extracted, outcomes)
    assert ranker_warm.tier_active in (0, 1)


def test_two_phase_knapsack_lane1_floor_and_online_bandit_and_policy_learner(tmp_path: Path) -> None:
    # D1 fix: Two-Phase Reserved-Quota Knapsack guarantees Lane 1 >= 50% when Signal is low
    items = [
        PortfolioItem("vdp_a", "LANE_1_VDP_FAST_SIGNAL", 0.72, 15.0, 0.70, 0.85, 0, 96.0, False),
        PortfolioItem("vdp_b", "LANE_1_VDP_FAST_SIGNAL", 0.68, 15.0, 0.65, 0.82, 0, 95.0, False),
        PortfolioItem("vdp_c", "LANE_1_VDP_FAST_SIGNAL", 0.65, 15.0, 0.62, 0.80, 0, 92.0, False),
        PortfolioItem("bbp_a", "LANE_2_BBP_HIGH_EV", 0.99, 15.0, 0.98, 0.90, 50000, 98.0, True),
        PortfolioItem("bbp_b", "LANE_2_BBP_HIGH_EV", 0.97, 15.0, 0.95, 0.88, 30000, 95.0, True),
        PortfolioItem("bbp_c", "LANE_2_BBP_HIGH_EV", 0.95, 15.0, 0.93, 0.86, 20000, 93.0, False),
    ]
    opt = DailyHuntPortfolioOptimizer()
    low_state = AccountSignalState(signal_established=False, signal_score=None)
    for cap in (0, 1, 5, 6):
        res = opt.optimize(items, capacity=cap, budget_minutes=120.0, account_state=low_state)
        if cap == 0:
            assert res["selected"] == []
        else:
            expected_floor = min(math.ceil(cap * 0.5), 3)
            assert res["lane1_count"] >= expected_floor
            assert len(res["selected"]) == cap

    # High-signal regime drops Lane 1 forced floor -> picks highest-EV BBPs first
    high_state = AccountSignalState(signal_established=True, signal_score=3.5)
    res_hi = opt.optimize(items, capacity=3, budget_minutes=120.0, account_state=high_state)
    assert res_hi["lane1_reserved_floor"] == 0
    assert res_hi["lane2_count"] == 3

    # OnlineProgramBandit rewards TRIAGED > DUPLICATE
    db = ProgramEligibilityDB(tmp_path / "bandit.sqlite3")
    for _ in range(5):
        db.record_hunt_outcome(handle="winner_prog", outcome="TRIAGED", lane=1, signal_delta=7.0)
        db.record_hunt_outcome(handle="dupe_prog", outcome="DUPLICATE", lane=2, signal_delta=0.0)
    bandit = OnlineProgramBandit().fit_outcomes(db.list_hunt_outcomes())
    assert bandit.program_thompson_bonus("winner_prog", deterministic=True) > bandit.program_thompson_bonus(
        "dupe_prog", deterministic=True
    )

    # B5 fix: pure-Python PolicyLearner produces context-dependent predictions (not constant)
    env = ContextualBanditEnv(
        X=[[1.0, 0.0, 0.0], [1.0, 0.1, 0.0], [0.0, 0.0, 1.0], [0.0, 0.1, 1.0]] * 6,
        rewards=[[1.0, 0.0], [0.95, 0.05], [0.0, 1.0], [0.05, 0.95]] * 6,
    )
    learner = PolicyLearner(env, seed=42, prefer_sklearn=False)
    policy_res = learner.train(n_iterations=30)
    assert policy_res.config["backend"] == "python_contextual_logreg"
    pred_a = policy_res.policy.predict([[1.0, 0.0, 0.0]])[0]
    pred_b = policy_res.policy.predict([[0.0, 0.0, 1.0]])[0]
    assert pred_a == 0 and pred_b == 1


def test_boost_adapter_tie_break_and_deterministic_proof_preservation() -> None:
    with _modelfusion_loopback_server(decision_winner="prog_b", reject_slop=True) as (mf_url, calls):
        with _scoped_env(RFCHUNT_OFFLINE=None, CI=None):
            probe = probe_modelfusion_decision_api(mf_url, timeout_sec=0.4)
            assert probe["available"] is True

            adapter = BoostDecisionAdapter(modelfusion_url=mf_url, embedded=False)
            tied = [
                {"handle": "prog_a", "score": 0.850, "program_age_days": 400, "response_efficiency_pct": 85},
                {"handle": "prog_b", "score": 0.842, "program_age_days": 30, "response_efficiency_pct": 98},
            ]
            tb = adapter.tie_break_pareto_knee(tied, margin=0.02)
            assert tb["tie_broken"] is True
            assert tb["backend"] == "modelfusion"
            assert tb["winner"] == "prog_b"
            assert tb["ordered"][0]["handle"] == "prog_b"
            assert len(calls) >= 1

            # Deterministic proof (poc_verified=True & lean4) MUST NEVER be demoted even when critic rejects slop
            stress = adapter.stress_test_stage3_candidates(
                [
                    {"title": "Verified PoC bypass", "file_path": "src/auth.py", "line": 42, "poc_verified": True, "engine": "api_jwt_sdjwt"},
                    {"title": "Lean4 RFC 9112 counterexample", "file_path": "src/http.rs", "line": 12, "poc_verified": False, "engine": "lean4", "confirmed": True},
                    {"title": "Potentially vulnerable header", "file_path": "tests/test_a.py", "line": 1, "poc_verified": False, "engine": "heuristic", "confidence": 0.2},
                ],
                top_k=3,
                program="common_codes",
            )
            assert stress["deterministic_preserved"] == 2
            assert stress["kept_count"] == 2
            assert stress["demoted_count"] == 1


def test_end_to_end_rank_programs_cli_sync_outcome_and_mcp(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db_path = tmp_path / "cli_elig.sqlite3"
    snap_path = tmp_path / "h1_snapshot.json"
    now = datetime.now(timezone.utc)
    snap_path.write_text(
        json.dumps(
            {
                "programs": [
                    {
                        "handle": "brand_new_vdp",
                        "status": "UNLOCKED",
                        "is_vdp": True,
                        "offers_bounties": False,
                        "bounty_max_usd": 0,
                        "response_efficiency_pct": 98.0,
                        "first_response_hours": 6.0,
                        "launched_at_utc": (now - timedelta(days=10)).isoformat(),
                        "in_scope_assets": ["*.brandnew.example", "api.brandnew.example"],
                        "in_scope_repos": ["https://github.com/brandnew/core"],
                    },
                    {
                        "handle": "brand_new_bbp",
                        "status": "UNLOCKED",
                        "is_vdp": False,
                        "offers_bounties": True,
                        "bounty_max_usd": 25000,
                        "response_efficiency_pct": 95.0,
                        "first_response_hours": 10.0,
                        "launched_at_utc": (now - timedelta(days=15)).isoformat(),
                        "in_scope_assets": ["*.bbpnew.example", "api.bbpnew.example"],
                        "in_scope_repos": ["https://github.com/bbpnew/api"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    assert {"rank-programs", "sync-directory", "cluster-recon", "record-outcome"}.issubset(
        revenue_cli.REVENUE_SUBCOMMANDS
    )
    assert revenue_cli.run_revenue_cli(["sync-directory", "--db", str(db_path), "--snapshot-json", str(snap_path), "--json"]) == 0
    sync_out = json.loads(capsys.readouterr().out)
    assert sync_out["upserted_count"] == 2

    assert (
        revenue_cli.run_revenue_cli(
            [
                "record-outcome",
                "--db",
                str(db_path),
                "--handle",
                "brand_new_vdp",
                "--outcome",
                "TRIAGED",
                "--lane",
                "1",
                "--signal-delta",
                "7.0",
                "--json",
            ]
        )
        == 0
    )
    outc_out = json.loads(capsys.readouterr().out)
    assert outc_out["status"] == "recorded"

    assert revenue_cli.run_revenue_cli(["rank-programs", "--db", str(db_path), "--capacity", "2", "--json"]) == 0
    rank_out = json.loads(capsys.readouterr().out)
    assert rank_out["schema"] == "rfchunt.ml_program_selection.v1"
    assert len(rank_out["ranked_programs"]) >= 2
    assert rank_out["daily_hunt_portfolio"]["lane1_count"] >= 1

    # Direct Python API parity check
    direct_res = rank_hackerone_programs(db_path=str(db_path), capacity=2)
    assert direct_res["pareto_knee_winner"] == rank_out["pareto_knee_winner"]

    # MCP server exposure check
    srv = BugBountyMCPServer()
    tool_names = {t["name"] for t in TOOLS_SCHEMA}
    assert {"bb_rank_programs", "bb_score_fresh_commits", "bb_cluster_recon_assets", "bb_record_hunt_outcome"}.issubset(
        tool_names
    )
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "bb_rank_programs",
                "arguments": {"eligibility_db_path": str(db_path), "capacity": 2},
            },
        }
    )
    assert resp["result"]["isError"] is False
    mcp_payload = json.loads(resp["result"]["content"][0]["text"])
    assert mcp_payload["schema"] == "rfchunt.ml_program_selection.v1"
