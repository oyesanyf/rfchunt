"""
Unit & Integration Tests for Pure-CLI Swarm Overview Board
(`engine/swarm_cli_board.py`).
"""

from __future__ import annotations

import ast
import io
import json
import sys
import threading
from pathlib import Path
from typing import Any, List

import pytest

from database import Database
from engine.swarm_cli_board import (
    ASCII_STATUS_ICONS,
    SPINNER_FRAMES_UNICODE,
    UNICODE_STATUS_ICONS,
    BoardSnapshot,
    SwarmCLIBoard,
    SwarmCLIBoardTracker,
    create_all_scan_board,
    create_swarm_ooda_board,
    load_board_snapshot_from_db,
    normalize_task_state,
    render_swarm_cli_board,
    update_all_board_from_result,
    watch_board_from_db,
)


class _EncodingStringIO(io.StringIO):
    """In-memory stream simulating a specific terminal encoding and TTY capability."""

    def __init__(self, *, encoding: str = "utf-8", tty: bool = False) -> None:
        super().__init__()
        self._encoding = encoding
        self._tty = tty

    @property
    def encoding(self) -> str:
        return self._encoding

    def isatty(self) -> bool:
        return self._tty


def _build_full_state_board() -> SwarmCLIBoard:
    board = SwarmCLIBoard(
        title="Protocol & Repo Swarm",
        line="Verify parser framing boundaries and sandbox invariants across workers.",
        task_id="task-alpha",
    )
    board.add_thread("t_done", "Toolchain Setup", "Prepare local models and binaries.")
    board.add_thread("t_moving", "Active Audits", "Run static, differential, and POE-3 checks.")
    board.add_thread("t_pending", "Dream-RSI Optimization", "Evolve replay policy from recorded traces.")

    board.add_task("prov", "Provision Ollama & tools", worker="provisioner", thread_id="t_done", state="Done", note="All tools ready")
    board.add_task("diff", "Run differential parser matrix", worker="diff-oracle", thread_id="t_moving", state="Running", action="Probing nginx vs envoy CL.TE")
    board.add_task("poe", "Verify POE-3 exploit chain", worker="poe-verifier", thread_id="t_moving", state="In review", action="Replaying minimized payload")
    board.add_task("fuzz", "Run container fuzzer", worker="fuzzer", thread_id="t_moving", state="Skipped", note="skipped_docker_unavailable")
    board.add_task("inv", "Run sandbox invariant suite", worker="invariant-runner", thread_id="t_moving", state="Failed", note="Authz bypass detected")
    board.add_task("dream", "Evolve Dream-RSI policy", worker="dream-rsi", thread_id="t_pending", state="Waiting")

    board.post_event("diff-oracle", "Observed CL.TE divergence across nginx and haproxy", kind="FACT")
    board.post_event("reasoner", "Probe TE.CL chunk extension framing", kind="INTENT")
    board.post_event("cli", "Focus on chunk trailer parsing", kind="HINT")
    return board


def test_zero_gui_imports_and_alias():
    assert SwarmCLIBoardTracker is SwarmCLIBoard
    assert "tkinter" not in sys.modules
    assert "webbrowser" not in sys.modules

    src_path = Path(__file__).resolve().parent.parent / "engine" / "swarm_cli_board.py"
    source = src_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {"tkinter", "webbrowser", "PyQt5", "PyQt6", "PySide2", "PySide6", "http"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported.isdisjoint(forbidden), f"Forbidden GUI/HTTP imports found: {imported & forbidden}"


def test_render_goal_running_states_counters_threads_team_and_events():
    board = _build_full_state_board()
    out = board.render(plain=True, width=110)

    # Goal block
    assert "GOAL: Protocol & Repo Swarm" in out
    assert "Verify parser framing boundaries and sandbox invariants across workers." in out

    # Running (N) count & all 6 canonical status badges
    assert "Running (1)" in out
    assert "[Running]" in out
    assert "[In review]" in out
    assert "[Done]" in out
    assert "[Waiting]" in out
    assert "[Skipped]" in out
    assert "[Failed]" in out

    # Exact counter math:
    # 6 tasks total: 1 Done (prov), 1 In review (poe), 1 Running (diff), 1 Skipped (fuzz), 1 Failed (inv), 1 Waiting (dream)
    # 3 threads: t_done -> Done (1/1), t_moving -> Moving (0/4), t_pending -> Not started (0/1) => 2 threads open
    assert "1 of 6 tasks done | 1 in review | 2 threads open" in out

    # Threads statuses, fractions, goals, and Now line on Moving thread
    assert "Toolchain Setup" in out and "[Done]" in out and "1/1" in out
    assert "Active Audits" in out and "[Moving]" in out and "0/4" in out
    assert "Dream-RSI Optimization" in out and "[Not started]" in out and "0/1" in out
    assert "> Now Probing nginx vs envoy CL.TE" in out

    # Team roster & board events
    assert "The team & board" in out
    assert "Coordinator" in out
    assert "@provisioner" in out
    assert "@diff-oracle" in out
    assert "[FACT]" in out
    assert "[INTENT]" in out
    assert "[HINT]" in out
    assert "Observed CL.TE divergence across nginx and haproxy" in out


def test_unicode_live_icons_and_spinner_tick_progression():
    board = _build_full_state_board()

    # Check every spinner frame across ticks 0..9
    seen_frames = []
    for tick, expected_frame in enumerate(SPINNER_FRAMES_UNICODE):
        rendered = board.render(plain=False, width=110, unicode_icons=True, ansi=True, spinner_tick=tick)
        assert expected_frame in rendered
        seen_frames.append(expected_frame)
    assert len(set(seen_frames)) == len(SPINNER_FRAMES_UNICODE) == 10

    # Verify advance_spinner() mutates live tick deterministically
    t0 = board.render(plain=False, unicode_icons=True, ansi=False)
    assert SPINNER_FRAMES_UNICODE[0] in t0
    board.advance_spinner(1)
    t1 = board.render(plain=False, unicode_icons=True, ansi=False)
    assert SPINNER_FRAMES_UNICODE[1] in t1

    # Verify every distinct Unicode status icon is present
    out_uni = board.render(plain=False, width=110, unicode_icons=True, ansi=True, spinner_tick=2)
    assert SPINNER_FRAMES_UNICODE[2] in out_uni
    assert UNICODE_STATUS_ICONS["Running"] in out_uni     # ●
    assert UNICODE_STATUS_ICONS["In review"] in out_uni   # ◐
    assert UNICODE_STATUS_ICONS["Done"] in out_uni        # ✓
    assert UNICODE_STATUS_ICONS["Waiting"] in out_uni     # ○
    assert UNICODE_STATUS_ICONS["Skipped"] in out_uni     # ⊘
    assert UNICODE_STATUS_ICONS["Failed"] in out_uni      # ✗
    assert UNICODE_STATUS_ICONS["Now"] in out_uni         # ▸
    assert "\x1b[" in out_uni


def test_plain_mode_ascii_icons_zero_ansi_and_non_utf8_fallback():
    board = _build_full_state_board()
    out_plain = board.render(plain=True, width=110)

    # Zero ANSI SGR codes and strictly pure ASCII
    assert "\x1b[" not in out_plain
    assert out_plain.isascii()

    # Exact pure-ASCII icon equivalents
    assert ASCII_STATUS_ICONS["Running"] in out_plain     # [*]
    assert ASCII_STATUS_ICONS["In review"] in out_plain   # [~]
    assert ASCII_STATUS_ICONS["Done"] in out_plain        # [+]
    assert ASCII_STATUS_ICONS["Waiting"] in out_plain     # [ ]
    assert ASCII_STATUS_ICONS["Skipped"] in out_plain     # [-]
    assert ASCII_STATUS_ICONS["Failed"] in out_plain      # [!]
    assert "> Now " in out_plain

    # Non-UTF8 terminal fallback (e.g. legacy cp1252 or ascii console) even when plain=False
    cp1252_stream = _EncodingStringIO(encoding="cp1252", tty=True)
    out_cp1252 = render_swarm_cli_board(board, plain=False, ansi=False, width=100, stream=cp1252_stream)
    assert ASCII_STATUS_ICONS["Running"] in out_cp1252
    assert ASCII_STATUS_ICONS["In review"] in out_cp1252
    assert ASCII_STATUS_ICONS["Done"] in out_cp1252
    assert ASCII_STATUS_ICONS["Waiting"] in out_cp1252
    assert ASCII_STATUS_ICONS["Skipped"] in out_cp1252
    assert ASCII_STATUS_ICONS["Failed"] in out_cp1252
    assert UNICODE_STATUS_ICONS["Running"] not in out_cp1252
    # Must encode cleanly to cp1252 without error
    out_cp1252.encode("cp1252")

    assert "tkinter" not in sys.modules


def test_team_roster_compact_overflow_narrow_vs_wide():
    board = SwarmCLIBoard(
        title="Large Team Swarm",
        goal="Check +N overflow formatting on narrow vs wide terminals.",
        team=["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"],
    )
    wide = board.render(plain=True, width=140)
    narrow = board.render(plain=True, width=52)

    assert "Team: Coordinator, @alpha, @beta, @gamma, @delta, @epsilon, @zeta, @eta, @theta" in wide
    team_narrow_lines = [ln for ln in narrow.splitlines() if ln.strip().startswith("Team:")]
    assert len(team_narrow_lines) == 1
    assert "Coordinator" in team_narrow_lines[0]
    assert " +" in team_narrow_lines[0]
    assert len(team_narrow_lines[0]) <= 52


def test_json_mode_zero_stdout_and_dict_roundtrip(capsys):
    board = _build_full_state_board()
    board.json_mode = True

    with board:
        board.set_task_state("diff", "Running", action="Checking HTTP/2 pseudo-header desync")
        board.post_event("diff-oracle", "Confirmed divergence", kind="FACT")
        board.flush_live(force=True)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""

    payload = board.to_dict()
    encoded = json.dumps(payload)
    decoded = json.loads(encoded)
    assert decoded["title"] == "Protocol & Repo Swarm"
    assert decoded["counters"]["done"] == 1
    assert decoded["counters"]["total"] == 6
    assert decoded["counters"]["in_review"] == 1
    assert decoded["counters"]["open_threads"] == 2
    assert decoded["progress_line"] == "1 of 6 tasks done | 1 in review | 2 threads open"

    # Stateless renderer also accepts deserialized dict directly
    rerendered = render_swarm_cli_board(decoded, plain=True, width=100)
    assert "1 of 6 tasks done | 1 in review | 2 threads open" in rerendered
    assert "GOAL: Protocol & Repo Swarm" in rerendered


def test_live_printer_non_tty_zero_ansi_and_exception_cleanup():
    buf = _EncodingStringIO(encoding="utf-8", tty=False)
    board = SwarmCLIBoard(
        title="Live Non-TTY Test",
        goal="Ensure non-TTY live printing emits pure ASCII with zero ANSI escapes.",
        plain=False,
        refresh_interval=0.05,
        stream=buf,
    )
    board.add_thread("t1", "Execution", "Execute target probes.")
    board.add_task("probe", "Run canary probe", worker="explorer", thread_id="t1")

    with pytest.raises(RuntimeError, match="boom"):
        with board:
            board.set_task_state("probe", "Running", action="Sending pipelined request")
            board.set_task_state("probe", "Done", note="Clean 200 OK")
            raise RuntimeError("boom")

    output = buf.getvalue()
    assert "\x1b[" not in output
    assert "Live Non-TTY Test" in output
    assert "1 of 1 tasks done | 0 in review | 0 threads open" in output
    assert board._live_active is False


def test_prebuilt_all_scan_and_ooda_templates():
    all_board = create_all_scan_board("d:/harfile/sandbox-runtime", task_id="sr-all")
    all_snap = all_board.snapshot()
    thread_titles = [th.title for th in all_snap.threads]
    assert "Toolchain & Provisioning" in thread_titles
    assert "Static & AI Surface Analysis" in thread_titles
    assert "Differential Matrix, Invariants & Fuzzing" in thread_titles
    assert "ARTEX Chaining & POE-3 Verification" in thread_titles
    assert "Blackboard OODA & Dream-RSI" in thread_titles

    update_all_board_from_result(
        all_board,
        {
            "provisioning": {"status": "ok"},
            "mantis": {"status": "completed", "findings_count": 3},
            "raptor": {"status": "completed", "findings_count": 1},
            "differential_matrix": {"status": "skipped_docker_unavailable"},
            "sandbox_invariants": {"status": "skipped_docker_unavailable"},
            "fuzz_bridge": {"status": "skipped_docker_unavailable"},
        },
    )
    all_dict = all_board.to_dict()
    assert all_dict["counters"]["done"] >= 3
    assert all_dict["counters"]["skipped"] == 3
    # Thread with all tasks Skipped resolves to Done (0 open work remaining in that thread)
    diff_th = next(th for th in all_dict["threads"] if th["thread_id"] == "diff_inv_fuzz")
    assert diff_th["status"] == "Done"
    assert diff_th["fraction"] == "0/3"

    ooda_board = create_swarm_ooda_board("RFC 9110", "127.0.0.1", 5006, task_id="ooda-9110")
    ooda_names = {t.name for t in ooda_board.snapshot().tasks}
    assert {"Bootstrap", "Reason", "Explore", "Triage", "Publish", "DreamRSI", "DualGraph"}.issubset(ooda_names)
    ooda_board.set_task_state("Bootstrap", "Done", note="Chunked 12 RFC fragments")
    ooda_board.set_task_state("Reason", "Done", note="Generated 8 candidates")
    ooda_board.set_task_state("Explore", "Running", action="Sending stateful canary pipeline")
    rendered = ooda_board.render(plain=True, width=100)
    assert "Running (1)" in rendered
    assert "2 of 7 tasks done | 0 in review | 2 threads open" in rendered
    assert "> Now Sending stateful canary pipeline" in rendered


def test_load_board_snapshot_from_db_and_watch_cli(tmp_path):
    db_file = tmp_path / "terminator_board.db"
    db = Database(str(db_file), encrypt_at_rest=False)
    try:
        # Populate FACT, INTENT (PENDING / CLAIMED / DONE), and HINT rows
        db.add_fact(
            "Observed differential CL.TE acceptance on /api/proxy",
            task_id="scan-42",
            domain="http_desync",
            rfc_id="RFC9112",
            source_agent="explorer",
        )
        db.add_hint(
            "Prioritize chunk-extension whitespace fuzzing",
            task_id="scan-42",
            domain="http_desync",
            source_agent="operator",
        )
        i_pending = db.queue_intent(
            "Probe trailer header smuggling",
            priority=5.0,
            task_id="scan-42",
            domain="http_desync",
            source_agent="reasoner",
        )
        i_claimed = db.queue_intent(
            "Test TE.CL boundary on /upload",
            priority=9.0,
            task_id="scan-42",
            domain="http_desync",
            source_agent="reasoner",
        )
        claimed_row = db.claim_next_intent("worker-alpha", task_id="scan-42", domain="http_desync")
        assert claimed_row is not None and claimed_row["node_id"] == i_claimed

        i_done = db.queue_intent(
            "Verify TLS ALPN downgrade framing",
            priority=8.0,
            task_id="scan-42",
            domain="tls_pqc",
            source_agent="reasoner",
        )
        db.complete_intent(i_done, status="DONE", result_payload={"summary": "No downgrade observed"})

        # Add an unrelated task to confirm task_id filtering
        db.queue_intent("Other task intent", task_id="other-task", domain="other", source_agent="other-agent")

        # Populate an attack_chain row for metadata verification
        db.conn.execute(
            """
            INSERT INTO attack_chains (
                chain_id, title, attack_type, target_host, target_endpoint,
                steps_json, is_verified, severity, task_id, poe_level, verification_status, hop_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "chain-1",
                "CL.TE Cache Poisoning Chain",
                "http_desync",
                "127.0.0.1",
                "/api/proxy",
                "[]",
                1,
                "HIGH",
                "scan-42",
                3,
                "VERIFIED",
                2,
            ),
        )
        # Populate a probe + vulnerable evaluation row for metadata verification
        db.conn.execute(
            "INSERT INTO probes (rationale, raw_request) VALUES (?, ?)",
            ("CL.TE desync probe", "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        )
        probe_id = int(db.conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        db.conn.execute(
            """
            INSERT INTO evaluations (
                probe_id, target_host, target_port, is_vulnerable, desync_class, finding_status, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (probe_id, "127.0.0.1", 5006, 1, "CL.TE", "CONFIRMED", "Differential response split"),
        )
        db.conn.commit()
        assert i_pending and i_claimed and i_done
    finally:
        db.close()

    snap = load_board_snapshot_from_db(db_file, task_id="scan-42", limit_events=15)
    assert isinstance(snap, BoardSnapshot)
    ctr = snap.counters()
    assert ctr["total"] == 3
    assert ctr["running"] == 1
    assert ctr["waiting"] == 1
    assert ctr["done"] == 1
    assert ctr["in_review"] == 0
    # 2 domain threads: http_desync (Moving: 1 Running, 1 Waiting), tls_pqc (Done: 1 Done) => 1 open thread
    assert ctr["total_threads"] == 2
    assert ctr["open_threads"] == 1

    # Verify events contain FACT, INTENT, HINT
    kinds = {e.kind for e in snap.events}
    assert {"FACT", "INTENT", "HINT"}.issubset(kinds)
    assert snap.metadata["attack_chains"]["total"] == 1
    assert snap.metadata["attack_chains"]["verified"] == 1
    assert snap.metadata["attack_chains"]["max_poe_level"] == 3
    assert snap.metadata["evaluations"]["total"] == 1
    assert snap.metadata["evaluations"]["vulnerable"] == 1
    assert "worker-alpha" in snap.ordered_team()
    assert "other-agent" not in snap.ordered_team()

    rendered = render_swarm_cli_board(snap, plain=True, width=120)
    assert "Running (1)" in rendered
    assert "1 of 3 tasks done | 0 in review | 1 threads open" in rendered
    assert "Chains=1 (1 verified, max POE=3)" in rendered
    assert "  Team: Coordinator," in rendered

    # Test watch_board_from_db single-shot JSON & multi-iteration plain watch
    json_buf = _EncodingStringIO(encoding="utf-8", tty=False)
    watch_board_from_db(db_file, task_id="scan-42", as_json=True, watch=False, stream=json_buf)
    parsed_json = json.loads(json_buf.getvalue())
    assert parsed_json["counters"]["done"] == 1
    assert parsed_json["task_id"] == "scan-42"

    watch_buf = _EncodingStringIO(encoding="utf-8", tty=False)
    watch_board_from_db(
        db_file,
        task_id="scan-42",
        plain=True,
        watch=True,
        interval=0.1,
        max_iterations=2,
        stream=watch_buf,
    )
    watch_out = watch_buf.getvalue()
    assert "\x1b[" not in watch_out
    assert watch_out.count("1 of 3 tasks done | 0 in review | 1 threads open") == 2

    with pytest.raises(FileNotFoundError):
        load_board_snapshot_from_db(tmp_path / "does_not_exist.db")


def test_thread_safety_under_concurrent_updates():
    board = SwarmCLIBoard(
        title="Concurrent Swarm Stress",
        goal="Verify lock integrity across simultaneous worker threads.",
        max_events=30,
        json_mode=True,
    )
    for idx in range(4):
        board.add_thread(f"th-{idx}", f"Thread {idx}", f"Goal {idx}")
    for idx in range(16):
        board.add_task(f"task-{idx}", f"Worker task {idx}", worker=f"w{idx % 4}", thread_id=f"th-{idx % 4}")

    errors: List[Exception] = []
    states_cycle = ["Running", "In review", "Done", "Waiting", "Skipped", "Failed"]

    def _worker(worker_idx: int) -> None:
        try:
            for step in range(40):
                t_name = f"task-{(worker_idx * 4 + step) % 16}"
                st = states_cycle[(worker_idx + step) % len(states_cycle)]
                board.set_task_state(t_name, st, action=f"step-{step}", note=f"note-{step}")
                board.post_event(f"w{worker_idx}", f"event {step} on {t_name}", kind="FACT" if step % 2 == 0 else "EVENT")
                board.advance_spinner(1)
                if step % 10 == 0:
                    _ = board.render(plain=(step % 20 == 0), width=90)
                    _ = board.to_dict()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(6)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=10.0)
        assert not th.is_alive()

    assert not errors, f"Concurrent errors occurred: {errors}"
    snap = board.snapshot()
    ctr = snap.counters()
    assert ctr["total"] == 16
    assert ctr["running"] + ctr["in_review"] + ctr["done"] + ctr["waiting"] + ctr["skipped"] + ctr["failed"] == 16
    # Bounded event deque honored
    assert len(snap.events) <= 30


def test_control_char_and_ansi_injection_sanitization():
    board = SwarmCLIBoard(
        title="Sanitize \x1b[31mInjected\x1b[0m\x07\ufffd Title",
        goal="Line with \x00null and\nnewline",
    )
    board.add_thread("t1", "Thread \x08Bad", "Outcome \x1b[2Jclear")
    board.add_task(
        "t_evil",
        "Check \x07bell \ufffd replacement",
        worker="w\x1b[32m1",
        thread_id="t1",
        state="Running",
        action="Probing \x00payload\r\nnext",
    )
    board.post_event("a\x07gent", "FACT \x1b[31mred\x1b[0m\ufffd text", kind="FACT")

    out_plain = board.render(plain=True, width=100)
    assert "\x1b[" not in out_plain
    assert "\ufffd" not in out_plain
    for ch in out_plain:
        code = ord(ch)
        assert ch == "\n" or (0x20 <= code <= 0x7E), f"Unexpected char U+{code:04X} in plain output"

    assert normalize_task_state("CLAIMED") == "Running"
    assert normalize_task_state("skipped_docker_unavailable") == "Skipped"
    assert normalize_task_state("PENDING") == "Waiting"
    assert normalize_task_state("IN_REVIEW") == "In review"
    assert normalize_task_state("FAILED") == "Failed"
    assert normalize_task_state("DONE") == "Done"


def test_live_tty_stdlib_fallback_and_spinner_advancement(monkeypatch):
    import engine.swarm_cli_board as mod

    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(mod, "_RICH_AVAILABLE", False)

    tty_buf = _EncodingStringIO(encoding="utf-8", tty=True)
    board = SwarmCLIBoard(
        title="Live TTY Fallback",
        goal="Verify stdlib TTY live rendering advances spinner frames and cleans up.",
        plain=False,
        refresh_interval=0.05,
        stream=tty_buf,
    )
    board.add_thread("t1", "Exploration", "Probe RFC boundaries.")
    board.add_task("explore", "Run canary sequence", worker="explorer", thread_id="t1", state="Running", action="Sending probes")

    with board:
        board.advance_spinner(1)
        board.flush_live(force=True)
        board.advance_spinner(1)
        board.flush_live(force=True)
        board.set_task_state("explore", "Done", note="Verified 0 regressions")

    assert board._live_active is False
    assert board._live_thread is None
    out = tty_buf.getvalue()
    assert "\x1b[" in out
    assert UNICODE_STATUS_ICONS["Done"] in out
    assert any(frame in out for frame in SPINNER_FRAMES_UNICODE)


def test_emoji_swarm_graphics_pipeline_graph_and_windows_vt_guard(monkeypatch):
    import engine.swarm_cli_board as mod

    board = create_swarm_ooda_board("RFC 9112", "127.0.0.1", 8080, task_id="emoji-test")
    board.set_task_state("Bootstrap", "Done", note="Chunked 214 fragments")
    board.set_task_state("Reason", "Done", note="Synthesized 11 candidates")
    board.set_task_state("Explore", "Running", action="Probing CL.TE framing")
    board.set_task_state("Triage", "In review", action="Running 3-trial check")
    board.set_task_state("Publish", "Skipped", note="Skipped")
    board.set_task_state("DreamRSI", "Failed", note="Timeout")
    board.post_event("explorer", "Anomaly observed", kind="FACT")

    # 1. Default UTF-8 mode renders rich color emojis + visual Swarm Pipeline Graph
    utf8_stream = _EncodingStringIO(encoding="utf-8", tty=True)
    rendered_emoji = render_swarm_cli_board(board, plain=False, width=110, ansi=False, stream=utf8_stream)
    assert "\U0001f41d GOAL:" in rendered_emoji          # 🐝
    assert "\U0001f5fa\ufe0f" in rendered_emoji          # 🗺️ pipeline graph
    assert "\u2500\u2500\u25b6" in rendered_emoji        # ──▶ pipeline arrows
    assert "\U0001f4ca" in rendered_emoji                # 📊 progress
    assert "\u26a1" in rendered_emoji                    # ⚡ running
    assert "\u2705" in rendered_emoji                    # ✅ done
    assert "\U0001f50d" in rendered_emoji                # 🔍 in review
    assert "\u23f3" in rendered_emoji                    # ⏳ waiting
    assert "\u23ed\ufe0f" in rendered_emoji              # ⏭️ skipped
    assert "\u274c" in rendered_emoji                    # ❌ failed
    assert "\U0001f9f5" in rendered_emoji                # 🧵 threads
    assert "\U0001f465" in rendered_emoji                # 👥 team
    assert "\U0001f9ed Coordinator" in rendered_emoji    # 🧭 Coordinator
    assert "\U0001f4cc" in rendered_emoji                # 📌 FACT event

    # 2. Compact live pipeline banner works in both emoji and pure-ASCII plain modes
    banner_emoji = board.render_pipeline_banner(plain=False, width=100, ansi=False, emoji=True, active_note="Active phase -> Explore")
    assert "\U0001f41d" in banner_emoji
    assert "\u26a1" in banner_emoji
    assert "Active phase -> Explore" in banner_emoji

    banner_plain = board.render_pipeline_banner(plain=True, width=100, active_note="Active phase -> Explore")
    assert banner_plain.isascii()
    assert "\x1b[" not in banner_plain
    assert "Pipeline:" in banner_plain
    assert " -> " in banner_plain

    # 3. --no-emoji disables color emojis while preserving geometric Unicode icons
    rendered_no_emoji = render_swarm_cli_board(board, plain=False, width=110, ansi=False, emoji=False, stream=utf8_stream)
    assert "\U0001f41d" not in rendered_no_emoji
    assert "\u2705" not in rendered_no_emoji
    assert UNICODE_STATUS_ICONS["Done"] in rendered_no_emoji

    # 4. Windows VT100 guard: if VT enabling fails on real sys.stdout with ansi=None, never emit raw \x1b[
    monkeypatch.setattr(mod.os, "name", "nt")
    monkeypatch.setattr(mod, "enable_windows_console_vt", lambda **kw: False)
    rendered_no_vt = render_swarm_cli_board(board, plain=False, width=100, ansi=None, stream=sys.stdout)
    assert "\x1b[" not in rendered_no_vt


