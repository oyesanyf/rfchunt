"""
Zero-Mock Tests for ACDSO-Adapted ML Commit/Diff Ranker, Surface-to-Scanner Router,
Dynamic Unlocked DB Watchlist Builder, Recon Asset & JS Bundle Clusterer, CLI, and MCP tools.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugbounty_mcp_server import BugBountyMCPServer
from engine.ml_diff_and_recon_ranker import (
    CommitDiffRanker,
    CommitVelocityBurstDetector,
    HTTPResponseAnomalyClassifier,
    JavaScriptBundleAnalyzer,
    ReconAssetClusterer,
    SurfaceToScannerRouter,
    WelfordOnlineScaler,
    build_unlocked_watchlist_from_db,
)
from engine.program_eligibility_db import ProgramEligibilityDB
from engine.request_hygiene import build_program_compliance_context
import revenue_cli


def test_welford_scaler_and_commit_velocity_burst_detector() -> None:
    scaler = WelfordOnlineScaler(2)
    scaler.partial_fit([[10.0, 100.0], [12.0, 102.0], [11.0, 99.0], [10.5, 101.0]])
    z_norm = scaler.transform_one([11.0, 100.5])
    z_out = scaler.transform_one([50.0, 100.5])
    assert abs(z_out[0]) > abs(z_norm[0]) + 5.0

    det = CommitVelocityBurstDetector(z_threshold=2.0)
    for rate in (2.0, 2.2, 1.9, 2.1, 2.0):
        _, burst = det.observe_and_score("acme/core", rate)
        assert burst is False
    z_burst, is_burst = det.observe_and_score("acme/core", 18.0)
    assert is_burst is True
    assert z_burst >= 2.0


def test_surface_to_scanner_router_and_commit_diff_ranker() -> None:
    router = SurfaceToScannerRouter()
    jwt_route = router.route_scanners(
        changed_files=["src/auth/jwt_verifier.py"],
        text_context="fix RS256 HS256 alg none verification",
    )
    assert "api_jwt_sdjwt" in jwt_route["recommended_scanners"]
    assert "mobile_mobsf" not in jwt_route["recommended_scanners"]

    mobile_route = router.route_scanners(
        changed_files=["android/app/src/main/AndroidManifest.xml", "android/DeepLink.kt"],
        text_context="exported activity openid4vci deeplink",
    )
    assert "mobile_mobsf" in mobile_route["recommended_scanners"]

    ranker = CommitDiffRanker()
    ranked = ranker.rank_candidates(
        [
            {
                "program": "anthropic",
                "repo": "anthropics/sandbox-runtime",
                "event_type": "commit",
                "age_hours": 60.0,
                "surface_score": 10,
                "title": "docs: fix typo in README",
                "changed_files": ["README.md"],
            },
            {
                "program": "anthropic",
                "repo": "anthropics/sandbox-runtime",
                "event_type": "merged_pr",
                "age_hours": 2.0,
                "surface_score": 85,
                "title": "fix: enforce O_NOFOLLOW symlink guard and SSRF allowFrom authz",
                "changed_files": ["packages/core/src/fs_guard.ts", "packages/core/src/proxy.ts"],
            },
        ],
        program_scores={"anthropic": 0.90},
    )
    assert len(ranked) == 2
    assert ranked[0]["ml_rank"] == 1
    assert ranked[0]["event_type"] == "merged_pr"
    assert ranked[0]["triggers_sibling_parity"] is True
    assert ranked[0]["ml_priority_score"] > ranked[1]["ml_priority_score"]


def test_build_unlocked_watchlist_from_db_excludes_blocked_programs(tmp_path: Path) -> None:
    db = ProgramEligibilityDB(tmp_path / "watchlist_elig.sqlite3")
    db.seed_observed_hackerone_baseline()
    targets = build_unlocked_watchlist_from_db(eligibility_db=db, min_efficiency_pct=80.0)
    assert len(targets) >= 3
    programs = {t["program"] for t in targets}
    assert "shopify" not in programs
    assert "vercel" not in programs
    assert any("/" in t["repo"] for t in targets)


def test_recon_asset_clusterer_suppresses_bulk_and_enforces_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = ProgramEligibilityDB(tmp_path / "recon_elig.sqlite3")
    db.upsert(
        "acme_scope",
        "UNLOCKED",
        in_scope_assets=["*.acme.example"],
        out_of_scope_assets=["marketing.acme.example"],
        roe_automated_prohibited=False,
        roe_max_rps=2.0,
    )
    ctx = build_program_compliance_context("acme_scope", eligibility_db=db, researcher_handle="tester")

    # 12 homogeneous static CDN pages + 2 rare high-value API/JS outliers + 2 out-of-scope hosts
    assets = [
        {
            "url": f"https://cdn{i}.acme.example/index.html",
            "status_code": 200,
            "content_length": 4200,
            "words": 310,
            "title": "Acme Static Landing",
            "tech": ["Cloudflare", "HTML"],
        }
        for i in range(12)
    ] + [
        {
            "url": "https://api.acme.example/v2/graphql?introspection=1",
            "status_code": 403,
            "content_length": 18400,
            "words": 950,
            "title": "GraphQL Admin Gateway",
            "tech": ["GraphQL", "Node"],
            "js_tokens": ["openid", "jwks", "admin"],
        },
        {
            "url": "https://app.acme.example/static/main.bundle.js.map",
            "status_code": 200,
            "content_length": 250000,
            "words": 15000,
            "title": "",
            "tech": ["Webpack"],
            "js_tokens": ["postMessage", "api_key", "sourcemap"],
        },
        {
            "url": "https://marketing.acme.example/promo",
            "status_code": 200,
            "content_length": 4200,
        },
        {
            "url": "https://evil-acme.example/leak",
            "status_code": 200,
            "content_length": 4200,
        },
    ]

    clusterer = ReconAssetClusterer(max_clusters=6)
    res = clusterer.cluster_and_prioritize(assets, compliance_ctx=ctx)
    assert res["skipped_out_of_scope"] == 2
    assert res["total_assets"] == 14
    assert res["suppressed_homogeneous_count"] >= 8
    top_two_urls = {r["url"] for r in res["prioritized_assets"][:2]}
    assert "https://api.acme.example/v2/graphql?introspection=1" in top_two_urls
    assert "https://app.acme.example/static/main.bundle.js.map" in top_two_urls

    # CLI cluster-recon + MCP bb_cluster_recon_assets / bb_score_fresh_commits
    in_file = tmp_path / "recon.json"
    in_file.write_text(json.dumps({"assets": assets}), encoding="utf-8")
    assert (
        revenue_cli.run_revenue_cli(
            [
                "cluster-recon",
                "--input",
                str(in_file),
                "--program",
                "acme_scope",
                "--db",
                str(db.db_path),
                "--json",
            ]
        )
        == 0
    )
    cli_res = json.loads(capsys.readouterr().out)
    assert cli_res["skipped_out_of_scope"] == 2
    assert cli_res["total_assets"] == 14

    srv = BugBountyMCPServer()
    mcp_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "bb_cluster_recon_assets",
                "arguments": {
                    "assets": assets,
                    "program_handle": "acme_scope",
                    "eligibility_db_path": str(db.db_path),
                },
            },
        }
    )
    assert mcp_resp["result"]["isError"] is False
    mcp_data = json.loads(mcp_resp["result"]["content"][0]["text"])
    assert mcp_data["skipped_out_of_scope"] == 2

    score_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {
                "name": "bb_score_fresh_commits",
                "arguments": {
                    "candidates": [
                        {
                            "program": "anthropic",
                            "repo": "anthropics/sandbox-runtime",
                            "event_type": "commit",
                            "age_hours": 1.5,
                            "surface_score": 80,
                            "title": "fix: sanitize ssrf proxy",
                            "changed_files": ["src/proxy.ts"],
                        }
                    ]
                },
            },
        }
    )
    assert score_resp["result"]["isError"] is False
    score_data = json.loads(score_resp["result"]["content"][0]["text"])
    assert score_data["total_candidates"] == 1
    assert score_data["ranked_candidates"][0]["triggers_sibling_parity"] is True


def test_javascript_bundle_analyzer_and_http_response_anomaly_classifier(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = ProgramEligibilityDB(tmp_path / "js_elig.sqlite3")
    db.upsert(
        "acme_js",
        "UNLOCKED",
        in_scope_assets=["*.acme.example"],
        out_of_scope_assets=["marketing.acme.example"],
        roe_automated_prohibited=False,
        roe_max_rps=2.0,
    )
    ctx = build_program_compliance_context("acme_js", eligibility_db=db, researcher_handle="tester")

    js_dir = tmp_path / "bundles"
    js_dir.mkdir(parents=True)
    (js_dir / "app.bundle.js").write_text(
        (
            'const ep = "/api/v2/admin/users";\n'
            'const gql = "https://api.acme.example/graphql";\n'
            'const oos = "https://evil-outside.example/beacon";\n'
            'window.addEventListener("message", (e) => { el.innerHTML = e.data; });\n'
            "//# sourceMappingURL=app.bundle.js.map\n"
        ),
        encoding="utf-8",
    )
    (js_dir / "static.js").write_text("console.log('hello');\n", encoding="utf-8")

    analyzer = JavaScriptBundleAnalyzer()
    js_res = analyzer.analyze_bundles(
        [
            {"url": "https://app.acme.example/app.bundle.js", "path": str(js_dir / "app.bundle.js")},
            {"url": "https://app.acme.example/static.js", "path": str(js_dir / "static.js")},
            {"url": "https://marketing.acme.example/promo.js", "content": "console.log(1);"},
        ],
        compliance_ctx=ctx,
    )
    assert js_res["total_bundles"] == 2
    assert js_res["skipped_out_of_scope_bundles"] == 1
    assert js_res["total_endpoints_discovered"] >= 1
    assert js_res["total_dom_sinks"] >= 2
    assert js_res["total_sourcemap_leaks"] == 1
    top_b = js_res["bundles"][0]
    assert "/api/v2/admin/users" in top_b["discovered_endpoints"]
    assert "https://api.acme.example/graphql" in top_b["in_scope_urls"]
    assert "https://evil-outside.example/beacon" not in top_b["in_scope_urls"]
    assert top_b["skipped_out_of_scope_urls"] == 1

    # CLI analyze-js
    assert (
        revenue_cli.run_revenue_cli(
            [
                "analyze-js",
                "--input",
                str(js_dir),
                "--program",
                "acme_js",
                "--db",
                str(db.db_path),
                "--json",
            ]
        )
        == 0
    )
    cli_js = json.loads(capsys.readouterr().out)
    assert cli_js["total_bundles"] == 2
    assert cli_js["total_sourcemap_leaks"] == 1

    # HTTPResponseAnomalyClassifier (baseline diff + stacktrace + sensitive leak + auth shift)
    clf = HTTPResponseAnomalyClassifier()
    classified = clf.classify_responses(
        [
            {"url": "https://app.acme.example/health", "status_code": 200, "content_length": 100, "body_preview": "ok"},
            {
                "url": "https://api.acme.example/v1/crash",
                "status_code": 500,
                "content_length": 2400,
                "body_preview": "Traceback (most recent call last): SQLSTATE[42601]",
            },
            {
                "url": "https://api.acme.example/openapi.json",
                "status_code": 200,
                "content_length": 9000,
                "body_preview": '{"openapi": "3.1.0", "jwks_uri": "/.well-known/jwks.json"}',
            },
            {
                "url": "https://api.acme.example/admin/panel",
                "status_code": 200,
                "content_length": 4500,
                "body_preview": "Admin Dashboard",
            },
            {"url": "https://marketing.acme.example/blocked", "status_code": 500, "content_length": 100},
        ],
        baseline={"status_code": 403, "content_length": 100},
        compliance_ctx=ctx,
    )
    assert len(classified) == 4  # marketing.acme.example filtered out-of-scope
    by_url = {c["url"]: c for c in classified}
    assert by_url["https://api.acme.example/v1/crash"]["anomaly_class"] == "SERVER_ERROR_OR_STACKTRACE"
    assert by_url["https://api.acme.example/openapi.json"]["anomaly_class"] == "SENSITIVE_CONTENT_LEAK"
    assert by_url["https://api.acme.example/admin/panel"]["anomaly_class"] == "AUTH_BOUNDARY_ANOMALY"

    # MCP bb_analyze_js_bundles & bb_classify_http_responses
    srv = BugBountyMCPServer()
    mcp_js = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {
                "name": "bb_analyze_js_bundles",
                "arguments": {
                    "bundles": [{"url": "https://app.acme.example/app.js", "content": 'fetch("/api/v1/secret"); //# sourceMappingURL=app.js.map'}],
                    "program_handle": "acme_js",
                    "eligibility_db_path": str(db.db_path),
                },
            },
        }
    )
    assert mcp_js["result"]["isError"] is False
    assert json.loads(mcp_js["result"]["content"][0]["text"])["total_sourcemap_leaks"] == 1

    mcp_http = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 24,
            "method": "tools/call",
            "params": {
                "name": "bb_classify_http_responses",
                "arguments": {
                    "responses": [
                        {"url": "https://api.acme.example/err", "status_code": 500, "content_length": 500, "body_preview": "panic: runtime error"}
                    ],
                    "program_handle": "acme_js",
                    "eligibility_db_path": str(db.db_path),
                },
            },
        }
    )
    assert mcp_http["result"]["isError"] is False
    http_data = json.loads(mcp_http["result"]["content"][0]["text"])
    assert http_data["anomalous_count"] == 1
    assert http_data["classified_responses"][0]["anomaly_class"] == "SERVER_ERROR_OR_STACKTRACE"
