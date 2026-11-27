"""Zero-mock tests for HackerOne Draft Submit-Readiness & Cooldown-Clear Checker."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import threading
from typing import Any, Dict

import pytest

from engine.draft_submit_checker import (
    DraftSubmitChecker,
    DraftSubmitTrackerDB,
    parse_hackerone_report_json,
)
from revenue_cli import run_revenue_cli


def _start_local_h1_server(state_by_id: Dict[int, tuple[int, Dict[str, Any]]]):
    """Spin up a real local HTTP server serving HackerOne-shaped `/reports/<id>.json` responses."""
    hit_log: list[int] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path.startswith("/reports/") and path.endswith(".json"):
                rid = int(path[len("/reports/") : -len(".json")])
                hit_log.append(rid)
                code, payload = state_by_id.get(rid, (404, {}))
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}", hit_log


def test_parse_hackerone_report_json_states() -> None:
    locked = parse_hackerone_report_json(
        4243972,
        {
            "id": 4243972,
            "state": "Draft",
            "substate": "editing",
            "title": "SDK HTTPS bypass",
            "team": {"handle": "anthropic"},
            "abilities": {
                "can_submit_draft?": False,
                "can_delete_draft?": True,
                "can_add_comment?": True,
            },
        },
        http_status=200,
    )
    assert locked.readiness == "COOLDOWN_LOCKED"
    assert locked.can_submit_draft is False
    assert locked.can_delete_draft is True
    assert locked.program == "anthropic"

    ready = parse_hackerone_report_json(
        4243972,
        {
            "id": 4243972,
            "state": "Draft",
            "substate": "editing",
            "title": "SDK HTTPS bypass",
            "team": {"handle": "anthropic"},
            "abilities": {
                "can_submit_draft?": True,
                "can_delete_draft?": True,
                "can_add_comment?": True,
            },
        },
        http_status=200,
    )
    assert ready.readiness == "READY_TO_SUBMIT"
    assert ready.can_submit_draft is True

    submitted = parse_hackerone_report_json(
        4244509,
        {
            "id": 4244509,
            "state": "Open",
            "substate": "triaged",
            "title": "claude-code-action gitattributes",
            "team": {"handle": "anthropic"},
            "abilities": {"can_submit_draft?": False},
        },
        http_status=200,
    )
    assert submitted.readiness == "ALREADY_SUBMITTED"


def test_probe_first_short_circuits_on_cooldown_then_clears_and_paces(tmp_path: Path) -> None:
    db = DraftSubmitTrackerDB(tmp_path / "tracker.sqlite3")
    db.seed_default_queue()
    out_md = tmp_path / "ready.md"

    # Phase 1: Cooldown active (`can_submit_draft? == False`) -> probe_first sends ONLY 1 request
    payloads: Dict[int, tuple[int, Dict[str, Any]]] = {
        4243972: (
            200,
            {
                "id": 4243972,
                "state": "Draft",
                "substate": "editing",
                "team": {"handle": "anthropic"},
                "abilities": {"can_submit_draft?": False, "can_delete_draft?": True, "can_add_comment?": True},
            },
        ),
        4243977: (
            200,
            {
                "id": 4243977,
                "state": "Draft",
                "substate": "editing",
                "team": {"handle": "anthropic"},
                "abilities": {"can_submit_draft?": False, "can_delete_draft?": True},
            },
        ),
        4244055: (
            200,
            {
                "id": 4244055,
                "state": "Draft",
                "substate": "editing",
                "team": {"handle": "oppo_bbp"},
                "abilities": {"can_submit_draft?": False, "can_delete_draft?": True},
            },
        ),
    }
    server, base_url, hit_log = _start_local_h1_server(payloads)
    try:
        checker = DraftSubmitChecker(db=db, base_url=base_url, max_rps=50.0, max_concurrency=4)
        s1 = checker.check(
            report_ids=[4243972, 4243977, 4244055],
            probe_report_id=4243972,
            probe_first=True,
            max_per_day=2,
            out_md=out_md,
        )
        assert s1.account_status == "COOLDOWN_ACTIVE"
        assert hit_log == [4243972]  # Polite 1-request short-circuit!
        assert s1.recommended_next_batch == []
        assert "Cooldown Active" in out_md.read_text(encoding="utf-8")

        # Phase 2: Cooldown clears (`can_submit_draft? == True`) -> fans out & emits top 2 pacing batch
        for rid in (4243972, 4243977, 4244055):
            payloads[rid][1]["abilities"]["can_submit_draft?"] = True
        hit_log.clear()

        s2 = checker.check(
            report_ids=[4243972, 4243977, 4244055],
            probe_report_id=4243972,
            probe_first=True,
            max_per_day=2,
            out_md=out_md,
        )
        assert s2.account_status == "CLEARED"
        assert set(hit_log) == {4243972, 4243977, 4244055}
        assert set(s2.newly_cleared_ids) == {4243972, 4243977, 4244055}
        assert len(s2.recommended_next_batch) == 2
        assert [x["report_id"] for x in s2.recommended_next_batch] == [4243972, 4243977]
        md_text = out_md.read_text(encoding="utf-8")
        assert "https://hackerone.com/reports/4243972" in md_text
        assert "https://hackerone.com/reports/4243977" in md_text

        # Phase 3: Mark 1 submitted -> remaining daily quota drops from 2 to 1
        db.mark_submitted(4243972)
        assert db.get_submitted_today() == 1
        s3 = checker.check(
            report_ids=[4243977, 4244055],
            probe_report_id=4243977,
            probe_first=True,
            max_per_day=2,
            out_md=out_md,
        )
        assert s3.account_status == "CLEARED"
        assert s3.remaining_today == 1
        assert [x["report_id"] for x in s3.recommended_next_batch] == [4243977]
    finally:
        server.shutdown()


def test_cli_check_drafts_snapshot_ingestion(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap_path = tmp_path / "browser_snaps.json"
    snap_path.write_text(
        json.dumps(
            [
                {
                    "id": 4243972,
                    "state": "Draft",
                    "substate": "editing",
                    "team": {"handle": "anthropic"},
                    "abilities": {"can_submit_draft?": True, "can_delete_draft?": True},
                },
                {
                    "id": 4244055,
                    "state": "Draft",
                    "substate": "editing",
                    "team": {"handle": "oppo_bbp"},
                    "abilities": {"can_submit_draft?": True, "can_delete_draft?": True},
                },
            ]
        ),
        encoding="utf-8",
    )
    db_path = tmp_path / "cli_tracker.sqlite3"
    out_md = tmp_path / "cli_ready.md"
    rc = run_revenue_cli(
        [
            "check-drafts",
            "--db",
            str(db_path),
            "--snapshot-json",
            str(snap_path),
            "--max-per-day",
            "2",
            "--out-md",
            str(out_md),
            "--json",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["account_status"] == "CLEARED"
    assert [x["report_id"] for x in data["recommended_next_batch"]] == [4243972, 4244055]
    assert out_md.exists()
