"""
Zero-Mock Tests for Bottleneck Fixes B1 (Invariant Commits ETag 304 on Advancing Clock
+ Commit Detail Patch Extraction), B2 (Diff-Scoped `target_files` Across All 4 Stage 1
Scanners + SurfaceToScannerRouter), and B4 (Async Blackboard `remote_dispatcher`).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from typing import Any, Dict, List

from engine.ai_infra_guard_auditor import audit_ai_infra
from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt
from engine.async_blackboard_runtime import run_local_rfchunt_async, run_stage1_cpu_check
from engine.freshness_watcher import AsyncFreshnessPoller, FreshnessWatcher, WatchTarget
from engine.mobile_app_auditor import audit_mobile_app
from engine.trufflehog_scanner import scan_secrets_with_trufflehog


def _start_advancing_clock_github_server(commit_ts: str):
    requests_seen: List[Dict[str, Any]] = []
    lock = threading.Lock()
    sha_val = "abcdef1234567890abcdef1234567890abcdef12"

    routes: Dict[str, Any] = {
        "/repos/acme/core/releases?per_page=5": ('"rel-etag-1"', []),
        "/repos/acme/core/pulls?state=closed&sort=updated&direction=desc&per_page=10": ('"pr-etag-1"', []),
        "/repos/acme/core/commits?per_page=10": (
            '"commits-etag-1"',
            [
                {
                    "sha": sha_val,
                    "html_url": f"https://github.com/acme/core/commit/{sha_val}",
                    "commit": {
                        "message": "chore: internal handler refactor",
                        "committer": {"date": commit_ts},
                    },
                    # Intentionally omit `files` like real GitHub /commits list endpoint
                }
            ],
        ),
        f"/repos/acme/core/commits/{sha_val}": (
            '"commit-detail-1"',
            {
                "sha": sha_val,
                "files": [
                    {
                        "filename": "src/proxy/auth_router.rs",
                        "patch": "@@ -1,3 +1,5 @@\n+enforce O_NOFOLLOW symlink and jwt verify guard\n",
                    }
                ],
            },
        ),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            inm = self.headers.get("If-None-Match")
            with lock:
                requests_seen.append({"path": self.path, "if_none_match": inm})
            entry = routes.get(self.path)
            if entry is None:
                self.send_response(404)
                self.end_headers()
                return
            etag, payload = entry
            if inm == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.end_headers()
                return
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, requests_seen


def test_b1_invariant_commits_url_hits_304_on_advancing_clock_and_extracts_patch(
    tmp_path: Path,
) -> None:
    t1 = datetime(2026, 11, 27, 10, 0, 0, tzinfo=timezone.utc)
    commit_ts = (t1 - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    server, reqs = _start_advancing_clock_github_server(commit_ts)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        target = WatchTarget(program="anthropic", repo="acme/core", bounty_tier="High")

        # Sync FreshnessWatcher with clock advancing by +5 minutes between polls
        watcher1 = FreshnessWatcher(
            api_base=base_url,
            token="",
            state_db=tmp_path / "sync_fresh.db",
            now_utc=t1,
        )
        rep1 = watcher1.poll_watchlist([target], freshness_hours=72, min_score=20, mark_returned_seen=True, ml_rank=True)
        watcher1.close()
        assert rep1.errors == []
        assert len(rep1.candidates) == 1
        assert "src/proxy/auth_router.rs" in rep1.candidates[0].changed_files
        assert not any("since=" in r["path"] for r in reqs)

        watcher2 = FreshnessWatcher(
            api_base=base_url,
            token="",
            state_db=tmp_path / "sync_fresh.db",
            now_utc=t1 + timedelta(minutes=5),
        )
        rep2 = watcher2.poll_watchlist([target], freshness_hours=72, min_score=20)
        watcher2.close()
        assert rep2.errors == []
        assert rep2.etag_cache_hits >= 3
        assert rep2.candidates == []

        # AsyncFreshnessPoller also hits 304 on advancing clock
        poller1 = AsyncFreshnessPoller(
            api_base=base_url,
            token="",
            state_db=tmp_path / "async_fresh.db",
            now_utc=t1,
        )
        arep1 = asyncio.run(poller1.poll_once([target], freshness_hours=72, min_score=20))
        poller1.close()
        assert arep1["errors"] == []
        assert arep1["total_candidates"] == 1

        poller2 = AsyncFreshnessPoller(
            api_base=base_url,
            token="",
            state_db=tmp_path / "async_fresh.db",
            now_utc=t1 + timedelta(minutes=10),
        )
        arep2 = asyncio.run(poller2.poll_once([target], freshness_hours=72, min_score=20))
        poller2.close()
        assert arep2["errors"] == []
        assert arep2["etag_cache_hits"] >= 3
        assert arep2["total_candidates"] == 0
    finally:
        server.shutdown()
        server.server_close()


def test_b2_diff_scoped_target_files_across_all_4_stage1_scanners(tmp_path: Path) -> None:
    pat_a = "ghp_" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8"
    pat_b = "ghp_" + "Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2"
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "touched").mkdir(parents=True)
    (tmp_path / "untouched").mkdir(parents=True)

    # Secrets: touched vs untouched
    (tmp_path / "src" / "touched_secret.py").write_text(f'TOK = "{pat_a}"\n', encoding="utf-8")
    (tmp_path / "src" / "untouched_secret.py").write_text(f'TOK = "{pat_b}"\n', encoding="utf-8")

    # JWT: touched vs untouched
    jwt_bug = 'import jwt\ndef p(t):\n    return jwt.decode(t, options={"verify_signature": False}, algorithms=["none"])\n'
    (tmp_path / "src" / "touched_jwt.py").write_text(jwt_bug, encoding="utf-8")
    (tmp_path / "src" / "untouched_jwt.py").write_text(jwt_bug, encoding="utf-8")

    # AI infra: touched vs untouched
    ai_bug = "import pickle\ndef load_m(b):\n    return pickle.loads(b)\n"
    (tmp_path / "src" / "touched_ai.py").write_text(ai_bug, encoding="utf-8")
    (tmp_path / "src" / "untouched_ai.py").write_text(ai_bug, encoding="utf-8")

    # Mobile: touched vs untouched
    mob_xml = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">\n'
        '  <application><activity android:name=".Auth" android:exported="true"/></application>\n'
        "</manifest>\n"
    )
    (tmp_path / "touched" / "AndroidManifest.xml").write_text(mob_xml, encoding="utf-8")
    (tmp_path / "untouched" / "AndroidManifest.xml").write_text(mob_xml, encoding="utf-8")

    th_f = scan_secrets_with_trufflehog(
        tmp_path, embedded=True, no_external_scanners=True, target_files=["src/touched_secret.py"]
    )
    assert len(th_f) >= 1
    assert all(
        "touched_secret.py" in str(f["file_path"]) and "untouched_secret.py" not in str(f["file_path"])
        for f in th_f
    )

    jwt_f = audit_api_and_jwt(
        tmp_path, embedded=True, no_external_scanners=True, allow_live=False, target_files=["src/touched_jwt.py"]
    )
    assert len(jwt_f) >= 1
    assert all(
        "touched_jwt.py" in str(f["file_path"]) and "untouched_jwt.py" not in str(f["file_path"])
        for f in jwt_f
    )

    ai_f = audit_ai_infra(tmp_path, target_files=["src/touched_ai.py"])
    assert len(ai_f) >= 1
    assert all(
        "touched_ai.py" in str(f["file_path"]) and "untouched_ai.py" not in str(f["file_path"])
        for f in ai_f
    )

    mob_f = audit_mobile_app(
        tmp_path, embedded=True, no_external_scanners=True, target_files=["touched/AndroidManifest.xml"]
    )
    assert len(mob_f) >= 1
    assert all("touched/AndroidManifest.xml" in str(f["file_path"]).replace("\\", "/") for f in mob_f)

    # Stage 1 worker with explicit target_files + SurfaceToScannerRouter ignores untouched files
    s1 = run_stage1_cpu_check(
        {
            "repo_path": str(tmp_path),
            "target_files": ["src/touched_jwt.py"],
            "commit_message": "fix jwt verify",
            "embedded": True,
            "no_external_scanners": True,
            "use_surface_router": True,
        }
    )
    assert s1["ok"] is True
    assert "api_jwt_sdjwt" in s1["scanners_run"]
    assert "mobile_mobsf" not in s1["scanners_run"]
    for item in s1["production_findings"]:
        fp = str(item.get("file_path") or "").replace("\\", "/")
        assert "untouched" not in fp


def test_b4_async_blackboard_remote_dispatcher_executes_remote_intents(tmp_path: Path) -> None:
    dispatched: List[str] = []

    async def _dispatcher(intent: Dict[str, Any]) -> Dict[str, Any]:
        dispatched.append(str(intent.get("program") or ""))
        return {
            "status": "dispatched_remote",
            "findings": [
                {
                    "engine": "freshness_remote",
                    "rule_id": "REMOTE-DIFF-001",
                    "title": "Remote diff security regression",
                    "file_path": "src/auth.ts",
                    "line": 22,
                    "severity": "HIGH",
                    "confidence": 0.85,
                    "deterministic": True,
                    "confirmed": True,
                }
            ],
        }

    seeds = [
        {
            "intent_type": "vdp_signal_lift",
            "program": "henkel_vdp",
            "repo": "acme/remote-repo",
            "lane": 1,
            "priority": 0.95,
            "payload": {"program": "henkel_vdp", "repo": "acme/remote-repo", "repo_path": ""},
        }
    ]
    res = asyncio.run(
        run_local_rfchunt_async(
            seeds,
            repo_path=tmp_path,
            db_path=tmp_path / "b4_bb.sqlite3",
            max_cpu_workers=2,
            signal_score=0.2,
            remote_dispatcher=_dispatcher,
        )
    )
    assert res["status"] == "completed"
    assert res["intents_completed"] >= 1
    assert "henkel_vdp" in dispatched
    assert any(f.get("title") == "Remote diff security regression" for f in res["facts"])
