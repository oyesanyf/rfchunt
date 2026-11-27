"""
Zero-Mock Tests for RFCHunt M2: ACDSO Bridge, Async SQLite WAL Blackboard,
Windows-Spawn ProcessPoolExecutor, and Bounty Loops 1, 2, & 5.

All tests use real SQLite WAL files, real `multiprocessing.get_context("spawn")`
workers, real `http.server.HTTPServer` loopback servers, real temporary
repositories, and real `ProgramEligibilityDB` instances.
"""

from __future__ import annotations

import asyncio
import json
import math
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from engine.acdso_bridge import (
    ACDSOAnomalyScorer,
    CandidateResult,
    ContextualBanditEnv,
    PolicyLearner,
    TwoLanePolicyScheduler,
    knee_point_selection,
    pareto_front,
    rank_stage2_candidates,
)
from engine.async_blackboard_runtime import (
    LANE1_DEFAULT_PROGRAMS,
    LANE2_DEFAULT_PROGRAMS,
    SECURITY_FIX_KEYWORDS,
    SIBLING_SDK_LANGUAGES,
    SqliteBlackboard,
    TwoLaneBountyQueue,
    detect_security_fix_signal,
    emit_sibling_parity_intents,
    run_local_rfchunt_async,
    run_stage1_cpu_check,
    sync_eligibility_and_stage_unlocks,
)
from engine.freshness_watcher import (
    AsyncFreshnessPoller,
    WatchTarget,
    resolve_changed_sibling_paths,
    score_diff_surface,
)
from engine.program_eligibility_db import ProgramEligibilityDB


def _start_loop1_loopback_server(now_utc: datetime) -> HTTPServer:
    fresh_ts = (now_utc - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    older_ts = (now_utc - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

    routes: dict[str, Any] = {
        "/repos/anthropics/sandbox-runtime/releases?per_page=5": (
            '"etag-anth-rel"',
            [
                {
                    "tag_name": "v1.1.0",
                    "name": "Enforce O_NOFOLLOW symlink guard",
                    "target_commitish": "rel110sha",
                    "published_at": fresh_ts,
                    "html_url": "https://github.com/anthropics/sandbox-runtime/releases/tag/v1.1.0",
                    "body": "Fixes symlink traversal and SSRF proxy allowFrom check.",
                },
                {
                    "tag_name": "v1.0.0",
                    "name": "Initial baseline",
                    "target_commitish": "rel100sha",
                    "published_at": older_ts,
                    "html_url": "https://github.com/anthropics/sandbox-runtime/releases/tag/v1.0.0",
                    "body": "Baseline",
                },
            ],
        ),
        "/repos/anthropics/sandbox-runtime/compare/v1.0.0...v1.1.0": (
            '"etag-anth-cmp"',
            {
                "files": [
                    {"filename": "packages/core/src/fs_guard.ts"},
                ]
            },
        ),
        "/repos/anthropics/sandbox-runtime/pulls?state=closed&sort=updated&direction=desc&per_page=10": (
            '"etag-anth-pr"',
            [
                {
                    "number": 7,
                    "title": "Sanitize proxy header and JWT authz verifier",
                    "merged_at": fresh_ts,
                    "merge_commit_sha": "pr7sha123456",
                    "html_url": "https://github.com/anthropics/sandbox-runtime/pull/7",
                    "body": "Hardens SSRF and CSP verification.",
                }
            ],
        ),
        "/repos/anthropics/sandbox-runtime/pulls/7/files?per_page=30": (
            '"etag-anth-pr7-files"',
            [
                {"filename": "packages/core/src/proxy_guard.ts"},
            ],
        ),
        "/repos/anthropics/sandbox-runtime/commits?per_page=10": (
            '"etag-anth-commits"',
            [],
        ),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            entry = routes.get(self.path)
            if entry is None:
                self.send_response(404)
                self.end_headers()
                return
            etag, payload = entry
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.end_headers()
                return
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def test_sqlite_wal_blackboard_crash_recovery_and_zero_lost_facts(tmp_path: Path) -> None:
    db_path = tmp_path / "blackboard.sqlite3"
    bb = SqliteBlackboard(db_path)
    try:
        # Confirm WAL mode enabled on file-backed DB
        conn = sqlite3.connect(str(db_path))
        try:
            mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            assert str(mode).lower() == "wal"
        finally:
            conn.close()

        # Persist facts and hints
        f1 = bb.add_fact("Confirmed unauthenticated admin route", domain="z3", severity="HIGH", poc_verified=False)
        f2 = bb.add_fact("Confirmed CL+TE parser divergence", domain="diff4", severity="HIGH", poc_verified=True)
        h1 = bb.add_hint("Prioritize sandbox/proxy paths", domain="triage", priority=0.9)
        assert f1 and f2 and h1

        # Enqueue intents across Lane 1 & Lane 2 + dedup verification
        i1 = bb.enqueue_intent("stage1_cpu", {"a": 1}, lane=1, priority=0.9, dedup_key="k1")
        i1_dup = bb.enqueue_intent("stage1_cpu", {"a": 1}, lane=1, priority=0.9, dedup_key="k1")
        assert i1 == i1_dup
        i2 = bb.enqueue_intent("stage1_cpu", {"a": 2}, lane=2, priority=0.8, max_retries=1)
        _ = bb.enqueue_intent("stage1_cpu", {"a": 3}, lane=2, priority=0.5)

        # Claim 2 intents and simulate sudden crash before completion
        c1 = bb.claim_intent("dead-worker-1", lane=1, lease_sec=60.0)
        c2 = bb.claim_intent("dead-worker-2", lane=2, lease_sec=60.0)
        assert c1 is not None and c1["intent_id"] == i1
        assert c2 is not None and c2["intent_id"] == i2
        assert bb.heartbeat_intent(c1["intent_id"], "dead-worker-1", extend_sec=120.0)
    finally:
        bb.close()

    # Reopen blackboard and recover stale IN_PROGRESS intents
    bb2 = SqliteBlackboard(db_path)
    try:
        rec = bb2.recover_stale_intents(force_all_in_progress=True)
        assert rec["recovered_to_pending"] == 2
        assert set(rec["intent_ids"]) == {i1, i2}

        # Zero lost facts and hints
        facts = bb2.list_facts()
        assert len(facts) == 2
        assert len(bb2.list_hints()) == 1

        # Verify retry_count incremented and re-claimed cleanly
        pending = {item["intent_id"]: item for item in bb2.list_intents(status="PENDING")}
        assert pending[i1]["retry_count"] == 1
        assert pending[i2]["retry_count"] == 1

        # Exhaust max_retries=1 on i2: claim -> recover again -> FAILED
        reclaimed_i1 = bb2.claim_intent("live-worker", lane=1)
        assert reclaimed_i1 is not None and reclaimed_i1["intent_id"] == i1
        assert bb2.complete_intent(i1, {"ok": True})

        reclaimed_i2 = bb2.claim_intent("live-worker", lane=2)
        assert reclaimed_i2 is not None and reclaimed_i2["intent_id"] == i2
        rec2 = bb2.recover_stale_intents(force_all_in_progress=True)
        assert rec2["exhausted_to_failed"] == 1
        assert i2 in rec2["failed_ids"]
        failed_list = bb2.list_intents(status="FAILED")
        assert any(item["intent_id"] == i2 for item in failed_list)
    finally:
        bb2.close()

    # Also ensure :memory: DB works without WAL error
    mem_bb = SqliteBlackboard(":memory:")
    try:
        mem_bb.add_fact("in-memory check")
        assert len(mem_bb.list_facts()) == 1
    finally:
        mem_bb.close()


def test_windows_spawn_process_pool_multi_pid_formal_and_differential(tmp_path: Path) -> None:
    db_path = tmp_path / "spawn_bb.sqlite3"
    openapi_spec = {
        "openapi": "3.0.3",
        "paths": {
            "/admin/users": {
                "delete": {
                    "summary": "Unauthenticated admin user deletion",
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    cl_te_probe = (
        "POST / HTTP/1.1\r\n"
        "Host: target.example\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n\r\n"
    )

    seeds: list[dict[str, Any]] = []
    for idx in range(8):
        payload: dict[str, Any] = {
            "cpu_work_iters": 120000,
            "propagate_siblings": False,
        }
        if idx == 0:
            payload["openapi_spec"] = openapi_spec
        elif idx == 1:
            payload["raw_probe"] = cl_te_probe
            payload["rule_id"] = "HTTP-CL-TE-001"
        elif idx == 2:
            payload["http_framing"] = {
                "content_lengths": [42],
                "has_transfer_encoding_chunked": True,
                "has_bare_lf": False,
                "proxy_verdict": ["acceptContentLength", 42],
            }
        seeds.append(
            {
                "intent_type": "formal_and_differential",
                "lane": 2,
                "priority": 0.9,
                "payload": payload,
                "dedup_key": f"spawn_seed_{idx}",
            }
        )

    res = asyncio.run(
        run_local_rfchunt_async(
            seeds,
            repo_path=tmp_path,
            db_path=db_path,
            max_cpu_workers=2,
            max_net_concurrency=4,
            signal_score=0.5,
        )
    )
    assert res["status"] == "completed"
    assert res["intents_completed"] == 8
    assert res["intents_failed"] == 0
    assert len(res["worker_pids"]) >= 2
    assert res["stage1_production_count"] >= 2
    assert len(res["facts"]) >= 2
    assert res["lane_allocation"]["lane1_slots"] >= 5


def test_stage1_cpu_check_filters_noise_gracefully(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_secret.py").write_text("TOKEN = 'dummy'\n", encoding="utf-8")
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "demo.js").write_text("console.log('demo');\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "handler.ts").write_text("export function handle(req: any) { return req; }\n", encoding="utf-8")
    (tmp_path / "openapi.json").write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "paths": {
                    "/internal/admin": {
                        "post": {"responses": {"200": {"description": "admin action"}}}
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    out = run_stage1_cpu_check(
        {
            "repo_path": str(tmp_path),
            "target_files": [
                "tests/test_secret.py",
                "examples/demo.js",
                "README.md",
                "src/handler.ts",
            ],
            "candidate_findings": [
                {
                    "engine": "trufflehog",
                    "rule_id": "TH-TEST-NOISE",
                    "title": "Test fixture token",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "file_path": "tests/test_secret.py",
                    "line": 1,
                    "summary": "Fixture secret",
                },
                {
                    "engine": "parity_auditor",
                    "rule_id": "DOCSTRING-ONLY",
                    "title": "Docstring note",
                    "severity": "LOW",
                    "confidence": 0.2,
                    "file_path": "src/handler.ts",
                    "line": 2,
                    "summary": "Docstring only note",
                },
                {
                    "engine": "parity_auditor",
                    "rule_id": "HYGIENE-DOCSTRING-01",
                    "title": "M1 hygiene docstring note",
                    "severity": "LOW",
                    "confidence": 0.2,
                    "file_path": "src/handler.ts",
                    "line": 3,
                    "summary": "Hygiene note in docstring",
                    "metadata": {"in_docstring": True},
                },
                {
                    "engine": "parity_auditor",
                    "rule_id": "PARITY-GUARD-01",
                    "title": "Missing authz guard in production handler",
                    "severity": "HIGH",
                    "confidence": 0.88,
                    "file_path": "src/handler.ts",
                    "line": 1,
                    "summary": "Production handler lacks allowFrom check",
                },
            ],
            "no_external_scanners": True,
        }
    )

    assert out["ok"] is True
    assert out["worker_pid"] > 0
    assert out["dropped_noise_count"] >= 6
    assert "src/handler.ts" in out["scanned_files"]
    assert "tests/test_secret.py" in out["dropped_files"]
    assert all(f["non_production_noise"] is False for f in out["production_findings"])
    prod_rules = {f["rule_id"] for f in out["production_findings"]}
    noise_rules = {f["rule_id"] for f in out["noise_findings"]}
    assert "DOCSTRING-ONLY" in noise_rules and "DOCSTRING-ONLY" not in prod_rules
    assert "HYGIENE-DOCSTRING-01" in noise_rules and "HYGIENE-DOCSTRING-01" not in prod_rules
    assert any(f["rule_id"] == "PARITY-GUARD-01" for f in out["production_findings"])
    assert any(f["engine"] == "z3_formal" for f in out["production_findings"])


def test_loop2_security_fix_signal_and_sibling_parity_propagation(tmp_path: Path) -> None:
    # Build real multi-package, multi-handler, 6-language-SDK monorepo
    (tmp_path / "packages" / "pkg-a" / "src").mkdir(parents=True)
    (tmp_path / "packages" / "pkg-b" / "src").mkdir(parents=True)
    (tmp_path / "packages" / "pkg-a" / "src" / "handler.ts").write_text("export const a = 1;\n", encoding="utf-8")
    (tmp_path / "packages" / "pkg-b" / "src" / "handler.ts").write_text("export const b = 1;\n", encoding="utf-8")

    (tmp_path / "src" / "handlers").mkdir(parents=True)
    (tmp_path / "src" / "handlers" / "text_handler.ts").write_text("export function textH() {}\n", encoding="utf-8")
    (tmp_path / "src" / "handlers" / "button_handler.ts").write_text("export function btnH() {}\n", encoding="utf-8")

    sdk_exts = {
        "ts": "ts",
        "python": "py",
        "go": "go",
        "java": "java",
        "ruby": "rb",
        "rust": "rs",
    }
    for folder, ext in sdk_exts.items():
        sdir = tmp_path / "sdks" / folder
        sdir.mkdir(parents=True)
        (sdir / f"client.{ext}").write_text("// sdk\n", encoding="utf-8")

    signals = detect_security_fix_signal(
        "fix: enforce O_NOFOLLOW and sanitize symlink SSRF",
        "+ verify allowFrom CSP authz boundary",
    )
    assert set(signals) == set(SECURITY_FIX_KEYWORDS)

    bb = SqliteBlackboard(tmp_path / "loop2_bb.sqlite3")
    try:
        emitted = emit_sibling_parity_intents(
            bb,
            repo_path=tmp_path,
            changed_files=["packages/pkg-a/src/handler.ts", "src/handlers/text_handler.ts"],
            trigger_reason="security_fix:o_nofollow,symlink",
            depth=0,
            max_depth=2,
        )
        assert len(emitted) >= 8

        intents = bb.list_intents()
        scopes = {item["payload"]["scope_label"] for item in intents}
        assert "packages/pkg-b" in scopes
        assert "sibling_handlers" in scopes
        for lang in SIBLING_SDK_LANGUAGES:
            assert f"sdk_{lang}" in scopes

        handler_intent = next(i for i in intents if i["payload"]["scope_label"] == "sibling_handlers")
        assert "src/handlers/button_handler.ts" in handler_intent["payload"]["target_files"]

        # Empty changed_files returns [] without emitting any intents
        assert emit_sibling_parity_intents(
            bb,
            repo_path=tmp_path,
            changed_files=[],
            trigger_reason="empty_guard",
            depth=0,
            max_depth=2,
        ) == []

        # Depth limit stops infinite recursion
        stopped = emit_sibling_parity_intents(
            bb,
            repo_path=tmp_path,
            changed_files=["packages/pkg-a/src/handler.ts"],
            trigger_reason="depth_cap",
            depth=2,
            max_depth=2,
        )
        assert stopped == []

        # Distinct PR fixes touching different files on same persistent blackboard must NOT collide
        pr2_emitted = emit_sibling_parity_intents(
            bb,
            repo_path=tmp_path,
            changed_files=["packages/pkg-b/src/handler.ts"],
            trigger_reason="security_fix:ssrf",
            parent_intent_id="pr_2",
            depth=0,
            max_depth=2,
        )
        assert len(pr2_emitted) >= 8
        assert set(pr2_emitted).isdisjoint(set(emitted))
    finally:
        bb.close()

    # Repo with ONLY sdk/ts and sdk/rust on disk must emit ONLY sibling sdk_Rust (never Python)
    sdk_only_repo = tmp_path / "sdk_only_repo"
    (sdk_only_repo / "sdk" / "ts").mkdir(parents=True)
    (sdk_only_repo / "sdk" / "rust").mkdir(parents=True)
    (sdk_only_repo / "sdk" / "ts" / "client.ts").write_text("export const c = 1;\n", encoding="utf-8")
    (sdk_only_repo / "sdk" / "rust" / "client.rs").write_text("pub fn c() {}\n", encoding="utf-8")
    bb_sdk = SqliteBlackboard(tmp_path / "sdk_only_bb.sqlite3")
    try:
        sdk_emitted = emit_sibling_parity_intents(
            bb_sdk,
            repo_path=sdk_only_repo,
            changed_files=["sdk/ts/client.ts"],
            trigger_reason="security_fix:verify",
            depth=0,
            max_depth=2,
        )
        assert len(sdk_emitted) == 1
        sdk_intents = bb_sdk.list_intents()
        assert len(sdk_intents) == 1
        assert sdk_intents[0]["payload"]["scope_label"] == "sdk_Rust"
        assert sdk_intents[0]["payload"]["sibling_sdk_languages"] == ["Rust"]
        assert "Python" not in sdk_intents[0]["payload"]["sibling_sdk_languages"]
    finally:
        bb_sdk.close()


def test_sibling_discovery_rejects_path_traversal_and_external_paths(tmp_path: Path) -> None:
    repo_root = tmp_path / "safe_repo"
    (repo_root / "packages" / "pkg-a" / "src").mkdir(parents=True)
    (repo_root / "packages" / "pkg-b" / "src").mkdir(parents=True)
    (repo_root / "packages" / "pkg-a" / "src" / "handler.ts").write_text("export const a = 1;\n", encoding="utf-8")
    (repo_root / "packages" / "pkg-b" / "src" / "handler.ts").write_text("export const b = 2;\n", encoding="utf-8")
    outside_file = tmp_path / "outside.ts"
    outside_file.write_text("export const secret = 'leak';\n", encoding="utf-8")

    malicious_only = [
        "../../outside.ts",
        "/etc/passwd",
        "C:/Windows/System32/cmd.exe",
        "%2e%2e/x.py",
        "\\\\host\\share\\x",
        "C:drive_rel.py",
        "bad\x00path.ts",
    ]
    assert resolve_changed_sibling_paths(malicious_only, repo_path=repo_root) == []
    assert resolve_changed_sibling_paths(malicious_only, repo_path=None) == []

    mixed = malicious_only + ["packages/pkg-a/src/handler.ts"]
    sibs = resolve_changed_sibling_paths(mixed, repo_path=repo_root)
    assert "packages/pkg-b/src/handler.ts" in sibs
    assert all("outside" not in s and "passwd" not in s and "System32" not in s for s in sibs)

    bb = SqliteBlackboard(tmp_path / "traversal_bb.sqlite3")
    try:
        assert emit_sibling_parity_intents(
            bb,
            repo_path=repo_root,
            changed_files=malicious_only,
            trigger_reason="security_fix:symlink",
        ) == []
        emitted = emit_sibling_parity_intents(
            bb,
            repo_path=repo_root,
            changed_files=mixed,
            trigger_reason="security_fix:symlink",
        )
        assert len(emitted) >= 1
        for item in bb.list_intents():
            tfiles = item["payload"].get("target_files") or []
            cfiles = item["payload"].get("changed_files") or []
            assert cfiles == ["packages/pkg-a/src/handler.ts"]
            assert all("outside" not in tf and "passwd" not in tf and "System32" not in tf for tf in tfiles)
    finally:
        bb.close()


def test_loop1_async_etag_poller_skips_blocked_and_304(tmp_path: Path) -> None:
    now_utc = datetime(2026, 11, 27, 4, 0, 0, tzinfo=UTC)
    server = _start_loop1_loopback_server(now_utc)
    elig_db = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    elig_db.seed_observed_hackerone_baseline(now=now_utc)

    repo_root = tmp_path / "anth_repo"
    (repo_root / "packages" / "core" / "src").mkdir(parents=True)
    (repo_root / "packages" / "sibling" / "src").mkdir(parents=True)
    (repo_root / "packages" / "core" / "src" / "fs_guard.ts").write_text("export const x = 1;\n", encoding="utf-8")
    (repo_root / "packages" / "sibling" / "src" / "fs_guard.ts").write_text("export const y = 2;\n", encoding="utf-8")

    bb = SqliteBlackboard(tmp_path / "loop1_bb.sqlite3")
    poller = AsyncFreshnessPoller(
        api_base=f"http://127.0.0.1:{server.server_port}",
        token="",
        state_db=tmp_path / "poller_state.sqlite3",
        now_utc=now_utc,
    )
    try:
        targets = [
            WatchTarget(program="shopify", repo="Shopify/shopify-app-js", bounty_tier="High"),
            WatchTarget(program="anthropic", repo="anthropics/sandbox-runtime", bounty_tier="High"),
        ]

        # Poll 1: skips BLOCKED_SIGNAL shopify, extracts release tag compare diff + PR files for anthropic
        rep1 = asyncio.run(
            poller.poll_once(
                targets,
                eligibility_db=elig_db,
                blackboard=bb,
                freshness_hours=72,
                min_score=20,
                repo_paths={"anthropics/sandbox-runtime": repo_root},
            )
        )
        assert rep1["errors"] == []
        assert rep1["targets_checked"] == 1
        assert "shopify" in rep1["skipped_ineligible"]
        assert rep1["total_candidates"] >= 2
        assert len(rep1["enqueued_intent_ids"]) >= 2
        rel_cand = next(c for c in rep1["candidates"] if c["event_type"] == "release")
        assert "packages/core/src/fs_guard.ts" in rel_cand["changed_files"]

        # Poll 2: all endpoints return 304 Not Modified -> 0 candidates, 0 new intents
        rep2 = asyncio.run(
            poller.poll_once(
                targets,
                eligibility_db=elig_db,
                blackboard=bb,
                freshness_hours=72,
                min_score=20,
                repo_paths={"anthropics/sandbox-runtime": repo_root},
            )
        )
        assert rep2["etag_cache_hits"] >= 3
        assert rep2["total_candidates"] == 0
        assert rep2["enqueued_intent_ids"] == []

        # SSRF validator & URL/slug hardening
        with pytest.raises(ValueError):
            AsyncFreshnessPoller(api_base="http://169.254.169.254", state_db=tmp_path / "ssrf.sqlite3")
        with pytest.raises(ValueError):
            AsyncFreshnessPoller(api_base="file:///etc/passwd", state_db=tmp_path / "scheme.sqlite3")
        with pytest.raises(ValueError):
            WatchTarget.from_dict({"program": "anthropic", "repo": "bad/../slug"})
    finally:
        poller.close()
        bb.close()
        server.shutdown()
        server.server_close()


def test_loop1_40char_sha_non304_dedup_and_security_fix_surface_scores(tmp_path: Path) -> None:
    # Verify every SECURITY_FIX_KEYWORD scores >= 20 in SURFACE_RULES
    for kw in SECURITY_FIX_KEYWORDS:
        sc, _ = score_diff_surface(["src/core/module.ts"], title=f"Fix {kw} boundary", event_type="commit")
        assert sc >= 20, f"Keyword {kw} scored {sc} < 20"

    full_sha_pr = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    full_sha_commit = "fedcba9876543210fedcba9876543210fedcba98"
    now_utc = datetime(2026, 11, 27, 4, 0, 0, tzinfo=UTC)
    fresh_ts = (now_utc - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    poll_count = {"pulls": 0}

    class Non304Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.startswith("/repos/anthropics/sandbox-runtime/releases"):
                payload: Any = []
                etag = f'"rel-{poll_count["pulls"]}"'
            elif self.path.startswith("/repos/anthropics/sandbox-runtime/pulls?"):
                poll_count["pulls"] += 1
                payload = [
                    {
                        "number": 99,
                        "title": "Fix SSRF proxy check",
                        "merged_at": fresh_ts,
                        "merge_commit_sha": full_sha_pr,
                        "html_url": "https://github.com/anthropics/sandbox-runtime/pull/99",
                        "body": "Hardens ssrf validation.",
                    }
                ]
                etag = f'"pr-{poll_count["pulls"]}"'
            elif self.path.startswith("/repos/anthropics/sandbox-runtime/pulls/99/files"):
                payload = [{"filename": "src/proxy.ts"}]
                etag = '"pr99-files"'
            elif self.path.startswith("/repos/anthropics/sandbox-runtime/commits?"):
                payload = [
                    {
                        "sha": full_sha_commit,
                        "html_url": f"https://github.com/anthropics/sandbox-runtime/commit/{full_sha_commit}",
                        "commit": {"message": "Enforce O_NOFOLLOW symlink check", "committer": {"date": fresh_ts}},
                        "files": [{"filename": "src/fs.ts"}],
                    }
                ]
                etag = f'"commits-{poll_count["pulls"]}"'
            else:
                self.send_response(404)
                self.end_headers()
                return

            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Non304Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    bb = SqliteBlackboard(tmp_path / "sha40_bb.sqlite3")
    poller = AsyncFreshnessPoller(
        api_base=f"http://127.0.0.1:{server.server_port}",
        token="",
        state_db=tmp_path / "sha40_state.sqlite3",
        now_utc=now_utc,
    )
    try:
        target = WatchTarget(program="anthropic", repo="anthropics/sandbox-runtime", bounty_tier="High")
        rep1 = asyncio.run(poller.poll_once([target], blackboard=bb, freshness_hours=72, min_score=20))
        assert rep1["total_candidates"] == 2
        assert len(rep1["enqueued_intent_ids"]) == 2
        assert poller.store.is_seen("anthropics/sandbox-runtime", full_sha_pr)
        assert poller.store.is_seen("anthropics/sandbox-runtime", full_sha_commit)

        # Second poll receives 200 OK (never 304) and must deduplicate both 40-char SHAs
        rep2 = asyncio.run(poller.poll_once([target], blackboard=bb, freshness_hours=72, min_score=20))
        assert rep2["etag_cache_hits"] == 0
        assert rep2["total_candidates"] == 0
        assert rep2["enqueued_intent_ids"] == []
    finally:
        poller.close()
        bb.close()
        server.shutdown()
        server.server_close()


def test_loop5_two_lane_queue_and_shopify_unlock_staging(tmp_path: Path) -> None:
    elig_db = ProgramEligibilityDB(tmp_path / "elig_loop5.sqlite3")
    elig_db.seed_observed_hackerone_baseline()
    bb = SqliteBlackboard(tmp_path / "loop5_bb.sqlite3")
    drafts_dir = tmp_path / "drafts"
    drafts_dir.mkdir()

    # Save verified and unverified Shopify drafts
    (drafts_dir / "shopify_app_remix_verified.json").write_text(
        json.dumps(
            {
                "program_handle": "shopify",
                "asset": "@shopify/shopify-app-remix",
                "package": "@shopify/shopify-app-remix",
                "title": "OAuth redirect validation bypass in @shopify/shopify-app-remix",
                "severity_rating": "High",
                "weakness_cwe": "CWE-601",
                "poc_verified": True,
                "report_id": "991234",
            }
        ),
        encoding="utf-8",
    )
    (drafts_dir / "shopify_unverified.json").write_text(
        json.dumps(
            {
                "program_handle": "shopify",
                "asset": "@shopify/shopify-app-remix",
                "title": "Unverified speculative draft",
                "poc_verified": False,
            }
        ),
        encoding="utf-8",
    )

    try:
        queue = TwoLaneBountyQueue(elig_db, bb, signal_score=0.4)
        assert queue.LANE1_DEFAULT_PROGRAMS == LANE1_DEFAULT_PROGRAMS
        assert queue.LANE2_DEFAULT_PROGRAMS == LANE2_DEFAULT_PROGRAMS

        # Low-signal regime (< 1.0): Lane 1 reserves >= 50% capacity
        low_plan = queue.plan_cycle(queue_capacity=10, signal_score=0.4, cycle_id="low")
        assert low_plan["lane1_slots"] >= math.ceil(10 * 0.5)
        assert low_plan["lane1_slots"] + low_plan["lane2_slots"] == 10
        assert set(low_plan["lane1_programs_queued"]).issubset(set(LANE1_DEFAULT_PROGRAMS))

        # High-signal regime (>= 1.0): shifts dynamically toward Lane 2
        high_plan = queue.plan_cycle(queue_capacity=10, signal_score=1.5, cycle_id="high")
        assert high_plan["lane2_slots"] > high_plan["lane1_slots"]

        # While shopify is BLOCKED_SIGNAL, sync_eligibility_and_stage_unlocks stays fail-closed
        pre_sync = sync_eligibility_and_stage_unlocks(elig_db, bb, drafts_dir, out_dir=tmp_path / "out")
        assert pre_sync["staged_drafts"] == []
        assert len(pre_sync["blocked_drafts"]) == 2
        assert not (tmp_path / "out" / "READY_TO_SUBMIT.json").exists()

        # Flip shopify to UNLOCKED -> auto-queues shopify & stages verified @shopify/shopify-app-remix draft
        elig_db.upsert("shopify", "UNLOCKED", bounty_min_usd=500, bounty_max_usd=50000)
        post_sync = sync_eligibility_and_stage_unlocks(elig_db, bb, drafts_dir, out_dir=tmp_path / "out")
        assert "shopify" in post_sync["newly_unlocked"]
        assert len(post_sync["queued_intents"]) >= 1
        assert len(post_sync["staged_drafts"]) == 1
        staged = post_sync["staged_drafts"][0]
        assert staged["package"] == "@shopify/shopify-app-remix"
        assert staged["draft_url"] == "https://hackerone.com/reports/991234"
        assert (tmp_path / "out" / "READY_TO_SUBMIT.json").is_file()
        # Unverified draft remains blocked fail-closed
        assert len(post_sync["blocked_drafts"]) == 1
        assert "poc_verified_false" in post_sync["blocked_drafts"][0]["reasons"]

        # Repeated poll must NOT insert duplicate facts
        facts_before = len(bb.list_facts(domain="loop5_unlock_stage"))
        _ = sync_eligibility_and_stage_unlocks(elig_db, bb, drafts_dir, out_dir=tmp_path / "out")
        facts_after = len(bb.list_facts(domain="loop5_unlock_stage"))
        assert facts_before == 1 and facts_after == 1
    finally:
        bb.close()


def test_single_seed_loop2_concurrent_workers_and_eligibility_sync(tmp_path: Path) -> None:
    (tmp_path / "packages" / "pkg-a" / "src").mkdir(parents=True)
    (tmp_path / "packages" / "pkg-b" / "src").mkdir(parents=True)
    (tmp_path / "packages" / "pkg-c" / "src").mkdir(parents=True)
    (tmp_path / "packages" / "pkg-a" / "src" / "handler.ts").write_text("export const a = 1;\n", encoding="utf-8")
    (tmp_path / "packages" / "pkg-b" / "src" / "handler.ts").write_text("export const b = 2;\n", encoding="utf-8")
    (tmp_path / "packages" / "pkg-c" / "src" / "handler.ts").write_text("export const c = 3;\n", encoding="utf-8")

    elig_db_path = tmp_path / "elig_runtime.sqlite3"
    elig_db = ProgramEligibilityDB(elig_db_path)
    elig_db.seed_observed_hackerone_baseline()

    seed = [
        {
            "intent_type": "stage1_cpu",
            "lane": 2,
            "priority": 0.9,
            "payload": {
                "repo_path": str(tmp_path),
                "changed_files": ["packages/pkg-a/src/handler.ts"],
                "commit_message": "Fix SSRF allowFrom check",
                "propagate_siblings": True,
                "max_depth": 1,
                "no_external_scanners": True,
            },
        }
    ]
    res = asyncio.run(
        run_local_rfchunt_async(
            seed,
            repo_path=tmp_path,
            db_path=tmp_path / "single_seed_bb.sqlite3",
            max_cpu_workers=2,
            eligibility_db_path=elig_db_path,
        )
    )
    assert res["status"] == "completed"
    assert len(res["loop2_emitted_intents"]) >= 2
    assert res["intents_completed"] == 1 + len(res["loop2_emitted_intents"])
    assert isinstance(res["eligibility_sync"], dict)
    assert "unlocked_programs" in res["eligibility_sync"]


def test_async_runtime_enforces_stage3_single_slot_and_net_concurrency(tmp_path: Path) -> None:
    db_path = tmp_path / "conc_bb.sqlite3"
    active_calls = 0
    peak_active = 0
    evaluated_titles: list[str] = []

    async def real_async_evaluator(cand: dict[str, Any]) -> dict[str, Any]:
        nonlocal active_calls, peak_active
        active_calls += 1
        peak_active = max(peak_active, active_calls)
        await asyncio.sleep(0.04)
        evaluated_titles.append(str(cand.get("title", "")))
        active_calls -= 1
        return {"status": "evaluated", "title": cand.get("title", "")}

    seeds = []
    for i in range(4):
        seeds.append(
            {
                "intent_type": "stage1_cpu",
                "lane": 2,
                "payload": {
                    "repo_path": str(tmp_path),
                    "propagate_siblings": False,
                    "candidate_findings": [
                        {
                            "engine": "parity_auditor",
                            "rule_id": f"PARITY-{i}",
                            "title": f"Production parity gap {i}",
                            "severity": "HIGH",
                            "confidence": 0.75 + 0.05 * i,
                            "file_path": f"src/handler_{i}.ts",
                            "line": 10 + i,
                            "summary": f"Handler {i} missing authz check",
                        }
                    ],
                },
            }
        )

    res = asyncio.run(
        run_local_rfchunt_async(
            seeds,
            repo_path=tmp_path,
            db_path=db_path,
            max_cpu_workers=2,
            max_net_concurrency=2,
            ollama_evaluator=real_async_evaluator,
        )
    )
    assert res["intents_completed"] == 4
    assert peak_active == 1
    assert 1 <= len(evaluated_titles) <= 5


def test_acdso_bridge_edge_cases_and_parity_fallbacks() -> None:
    # 1. Anomaly scorer edge cases (0, 1, constant, NaN/Inf, pure-Python parity)
    scorer = ACDSOAnomalyScorer(prefer_sklearn=False)
    assert scorer.fit_score([]) == []
    one = scorer.fit_score([{"severity": "HIGH", "confidence": 0.9, "engine": "trufflehog"}])
    assert len(one) == 1 and 0.0 <= one[0] <= 1.0

    const_scores = scorer.fit_score(
        [
            {"severity": "MEDIUM", "confidence": 0.5, "x": float("nan")},
            {"severity": "MEDIUM", "confidence": 0.5, "x": float("inf")},
            {"severity": "MEDIUM", "confidence": 0.5, "x": 1.0},
        ]
    )
    assert len(const_scores) == 3
    assert all(math.isfinite(s) and 0.0 <= s <= 1.0 for s in const_scores)

    large_rows = [
        {"severity": "MEDIUM", "confidence": 0.1 + (i % 9) * 0.1, "x": float(i)}
        for i in range(320)
    ]
    large_scores = scorer.fit_score(large_rows)
    assert len(large_scores) == 320
    assert all(math.isfinite(s) and 0.0 <= s <= 1.0 for s in large_scores)

    # 2. Stage 2 ranking cap (3..5 when >=3 candidates) and <1s target
    many = [
        {
            "engine": "parity_auditor",
            "rule_id": f"R-{i}",
            "title": f"Candidate {i}",
            "severity": "CRITICAL" if i < 2 else "MEDIUM",
            "confidence": 0.4 + 0.05 * i,
            "deterministic": i % 2 == 0,
            "summary": "Check authz and proxy header handling " * (1 + i),
        }
        for i in range(10)
    ]
    ranked = rank_stage2_candidates(many, top_k=5)
    assert 3 <= len(ranked["selected"]) <= 5
    assert ranked["pareto_count"] >= 1
    assert ranked["elapsed_ms"] < 1000.0

    # 3. Pareto front & knee point selection
    with pytest.raises(ValueError):
        knee_point_selection([])
    c1 = CandidateResult("a", None, 0.9, 1.0, 32.0, 10.0, 0.1, (0.9, 0.7, 3.5, 2.4, 0.1, 0.1))
    c2 = CandidateResult("b", None, 0.8, 0.5, 16.0, 5.0, 0.2, (0.8, 0.4, 2.8, 1.8, 0.2, 0.2))
    c3 = CandidateResult("c", None, 0.5, 2.0, 64.0, 20.0, 0.5, (0.5, 1.1, 4.1, 3.0, 0.5, 0.5))
    front = pareto_front([c1, c2, c3])
    assert c3 not in front
    assert knee_point_selection(front, preference="balanced") in front
    assert knee_point_selection(front, preference="speed") in front

    # 4. PolicyLearner single-action, constant-reward & extreme-reward overflow guards
    env1 = ContextualBanditEnv(X=[[1.0, 1.0], [1.0, 1.0]], rewards=[[5.0], [5.0]])
    pol1 = PolicyLearner(env1, prefer_sklearn=False).train(n_iterations=10)
    assert pol1.get_action([1.0, 1.0]) == 0
    assert pol1.get_action_probs([1.0, 1.0]) == [1.0]

    env_ext = ContextualBanditEnv(X=[[0.1], [0.9]], rewards=[[1e9, -1e9], [-1e9, 1e9]])
    pol_ext = PolicyLearner(env_ext, prefer_sklearn=False).train(n_iterations=10)
    probs_ext = pol_ext.get_action_probs([0.5])
    assert len(probs_ext) == 2 and all(math.isfinite(p) for p in probs_ext)

    # 5. TwoLanePolicyScheduler R4 50% reserve invariant across odd & even capacities
    sched = TwoLanePolicyScheduler()
    for cap in (1, 3, 5, 10):
        alloc = sched.allocate_slots(cap, signal_score=0.0)
        assert alloc["lane1_slots"] >= math.ceil(cap * 0.5)
        assert alloc["lane1_slots"] + alloc["lane2_slots"] == cap
