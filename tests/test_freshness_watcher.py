"""
Loopback HTTP tests for FreshnessWatcher (zero mocks — real local HTTP server).
"""

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import threading
import pytest

from engine.freshness_watcher import (
    FreshnessWatcher,
    WatchTarget,
    load_watchlist,
    render_fresh_hunt_queue_markdown,
    score_diff_surface,
)


def _start_github_loopback_server(now_utc: datetime):
    fresh_ts = (now_utc - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stale_ts = (now_utc - timedelta(hours=200)).strftime("%Y-%m-%dT%H:%M:%SZ")

    routes = {
        "/repos/acme/wasm-runner/releases?per_page=5": (
            '"etag-rel-1"',
            [
                {
                    "tag_name": "v2.4.0",
                    "name": "Wasmtime sandbox & unsafe FFI update",
                    "target_commitish": "relsha240",
                    "published_at": fresh_ts,
                    "html_url": "https://github.com/acme/wasm-runner/releases/tag/v2.4.0",
                    "body": "Refactors WASI memory limiter and unsafe ptr handling.",
                },
                {
                    "tag_name": "v2.0.0",
                    "name": "Old release",
                    "target_commitish": "oldsha200",
                    "published_at": stale_ts,
                    "html_url": "https://github.com/acme/wasm-runner/releases/tag/v2.0.0",
                    "body": "Stale release outside 72h window.",
                },
            ],
        ),
        "/repos/acme/wasm-runner/pulls?state=closed&sort=updated&direction=desc&per_page=10": (
            '"etag-pr-1"',
            [
                {
                    "number": 42,
                    "title": "Add OAuth JWT session verifier and proxy header parser",
                    "merged_at": fresh_ts,
                    "merge_commit_sha": "pr42mergedsha1234",
                    "html_url": "https://github.com/acme/wasm-runner/pull/42",
                    "body": "Validates HMAC and bearer tokens.",
                },
                {
                    "number": 10,
                    "title": "Update README docs only",
                    "merged_at": stale_ts,
                    "merge_commit_sha": "stalepr10sha",
                    "html_url": "https://github.com/acme/wasm-runner/pull/10",
                    "body": "Old PR",
                },
            ],
        ),
        "/repos/acme/wasm-runner/pulls/42/files?per_page=30": (
            '"etag-pr42-files"',
            [
                {"filename": "src/auth/jwt_verify.rs"},
                {"filename": "src/proxy/header_parser.rs"},
            ],
        ),
        "/repos/acme/wasm-runner/commits?per_page=10": (
            '"etag-commits-1"',
            [
                {
                    "sha": "commitfresh999999",
                    "html_url": "https://github.com/acme/wasm-runner/commit/commitfresh999999",
                    "commit": {
                        "message": "Update docs typo",
                        "committer": {"date": fresh_ts},
                    },
                    "files": [{"filename": "README.md"}],
                }
            ],
        ),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
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

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_surface_scoring_prioritizes_security_surfaces_over_docs():
    high_score, high_surfaces = score_diff_surface(
        ["src/wasm/sandbox.rs", "src/auth/oauth.ts"],
        title="Refactor WASI memory limiter and JWT verification",
        event_type="merged_pr",
    )
    doc_score, doc_surfaces = score_diff_surface(
        ["README.md", "docs/guide.md"],
        title="Fix typo in readme",
        event_type="commit",
    )
    assert high_score >= 70
    assert "wasm_sandbox_ffi" in high_surfaces
    assert "auth_session_crypto" in high_surfaces
    assert doc_score == 0
    assert doc_surfaces == []


def test_freshness_watcher_filters_window_caches_etags_and_deduplicates(tmp_path: Path):
    now_utc = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
    server = _start_github_loopback_server(now_utc)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        watcher = FreshnessWatcher(
            api_base=base_url,
            token="",
            state_db=tmp_path / "freshness.db",
            now_utc=now_utc,
        )
        target = WatchTarget(program="acme-bbp", repo="acme/wasm-runner", bounty_tier="High")

        # First poll: fetches fresh release + merged PR, skips stale (>72h) and low-score README commit
        report1 = watcher.poll_watchlist(
            [target], freshness_hours=72, min_score=20, skip_seen=True, mark_returned_seen=True
        )
        assert report1.errors == []
        assert report1.etag_cache_hits == 0
        assert len(report1.candidates) == 2
        # PR #42 has both auth_session_crypto + http_proxy_parser + merged_pr + 2 code files -> ranked #1
        assert report1.candidates[0].ref_id == "#42"
        assert report1.candidates[1].ref_id == "v2.4.0"

        md = render_fresh_hunt_queue_markdown(report1)
        assert "RFCHunt Daily Fresh Hunt Queue" in md
        assert "acme/wasm-runner" in md
        assert "git clone --depth 1" in md

        # Second poll: all 3 endpoints hit 304 Not Modified ETag cache!
        report2 = watcher.poll_watchlist(
            [target], freshness_hours=72, min_score=20, skip_seen=True
        )
        assert report2.etag_cache_hits >= 3
        assert report2.candidates == []
        watcher.close()
    finally:
        server.shutdown()


def test_example_watchlist_parses_cleanly():
    watchlist_path = Path("config/freshness_watchlist.example.json")
    if not watchlist_path.is_file():
        watchlist_path = Path("D:/harfile/rfchunt/config/freshness_watchlist.example.json")
    targets = load_watchlist(watchlist_path)
    assert len(targets) >= 6
    assert any(t.program == "shopify" for t in targets)
    assert any(t.program == "anthropic" for t in targets)
