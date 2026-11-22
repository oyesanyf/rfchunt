"""
Pure-CLI Swarm Overview & Live Terminal Board
=============================================
Zero-GUI, terminal-native Swarm Overview board for RFCHunt.

Mirrors the structured Swarm Overview layout purely in the CLI:
  - Goal block (`title` + concise goal `line`)
  - Progress counters (`<done> of <total> tasks done | <in_review> in review | <open_threads> threads open`)
  - Running (`N`) task list with status badges, live icons/spinner, worker handles, and `Now ...` activity
  - Threads section grouped by outcome (`Moving`, `Not started`, `Done`, `<done>/<total>`, goal, `Now ...`)
  - The team (`Coordinator` + `@<worker>` handles with compact `+N` overflow) & recent board messages

Design invariants:
  - Strictly ZERO GUI imports (no tkinter, webbrowser, PyQt, or HTTP servers).
  - Pure Python standard library by default (uses `rich` optionally if installed,
    with full graceful stdlib fallback and zero new required pip dependencies).
  - Explicit UTF-8 handling, zero control characters / U+FFFD in sanitized output.
  - Strict pure-ASCII mode (zero ANSI SGR codes, ASCII status icons) when `plain=True`
    or when attached to a non-TTY / non-UTF8 terminal.
  - Strictly zero stdout output when `json_mode=True`.
"""

from __future__ import annotations

import collections
import contextlib
import json
import locale
import os
import re
import sqlite3
import sys
import textwrap
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    from rich.console import Console as _RichConsole
    from rich.live import Live as _RichLive
    from rich.text import Text as _RichText

    _RICH_AVAILABLE = True
except Exception:
    _RichConsole = None
    _RichLive = None
    _RichText = None
    _RICH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Canonical states, icons, ANSI palette, and text sanitization
# ---------------------------------------------------------------------------

TASK_STATES: Tuple[str, ...] = (
    "Running",
    "In review",
    "Done",
    "Waiting",
    "Skipped",
    "Failed",
)

THREAD_STATES: Tuple[str, ...] = (
    "Moving",
    "Not started",
    "Done",
)

_TASK_STATE_ALIASES: Dict[str, str] = {
    # Running
    "running": "Running",
    "active": "Running",
    "in_progress": "Running",
    "in progress": "Running",
    "working": "Running",
    "claimed": "Running",
    "moving": "Running",
    "started": "Running",
    "executing": "Running",
    # In review
    "in review": "In review",
    "in_review": "In review",
    "review": "In review",
    "reviewing": "In review",
    "verifying": "In review",
    "triage": "In review",
    "triaging": "In review",
    "pending_review": "In review",
    # Done
    "done": "Done",
    "completed": "Done",
    "complete": "Done",
    "passed": "Done",
    "verified": "Done",
    "ok": "Done",
    "success": "Done",
    "succeeded": "Done",
    "finished": "Done",
    # Waiting
    "waiting": "Waiting",
    "pending": "Waiting",
    "queued": "Waiting",
    "idle": "Waiting",
    "not_started": "Waiting",
    "not started": "Waiting",
    "ready": "Waiting",
    # Skipped
    "skipped": "Skipped",
    "skip": "Skipped",
    "disabled": "Skipped",
    "bypassed": "Skipped",
    "unavailable": "Skipped",
    "cancelled": "Skipped",
    "canceled": "Skipped",
    "skipped_docker_unavailable": "Skipped",
    "skipped_toolchain_unavailable": "Skipped",
    # Failed
    "failed": "Failed",
    "fail": "Failed",
    "error": "Failed",
    "crashed": "Failed",
    "blocked": "Failed",
    "timeout": "Failed",
}

_TASK_SORT_RANK: Dict[str, int] = {
    "Running": 0,
    "In review": 1,
    "Failed": 2,
    "Waiting": 3,
    "Done": 4,
    "Skipped": 5,
}

# Braille rotating spinner frames (U+280B .. U+280F)
SPINNER_FRAMES_UNICODE: Tuple[str, ...] = (
    "\u280b",
    "\u2819",
    "\u2839",
    "\u2838",
    "\u283c",
    "\u2834",
    "\u2826",
    "\u2827",
    "\u2807",
    "\u280f",
)

UNICODE_STATUS_ICONS: Dict[str, str] = {
    "Running": "\u25cf",      # ●
    "Moving": "\u25cf",       # ●
    "In review": "\u25d0",    # ◐
    "Done": "\u2713",         # ✓
    "Waiting": "\u25cb",      # ○
    "Not started": "\u25cb",  # ○
    "Skipped": "\u2298",      # ⊘
    "Failed": "\u2717",       # ✗
    "Now": "\u25b8",          # ▸
}

ASCII_STATUS_ICONS: Dict[str, str] = {
    "Running": "[*]",
    "Moving": "[*]",
    "In review": "[~]",
    "Done": "[+]",
    "Waiting": "[ ]",
    "Not started": "[ ]",
    "Skipped": "[-]",
    "Failed": "[!]",
    "Now": ">",
}

_UNICODE_PROBE_SAMPLE = "".join(SPINNER_FRAMES_UNICODE) + "".join(UNICODE_STATUS_ICONS.values()) + "\u2500\u2502\u256d\u256e\u2570\u256f"

# ANSI SGR escape sequences (emitted at runtime ONLY when ansi=True and plain=False)
_SGR_RESET = "\x1b[0m"
_SGR_BOLD = "\x1b[1m"
_SGR_DIM = "\x1b[2m"
_SGR_CYAN = "\x1b[36m"
_SGR_BOLD_CYAN = "\x1b[1;36m"
_SGR_GREEN = "\x1b[32m"
_SGR_BOLD_GREEN = "\x1b[1;32m"
_SGR_YELLOW = "\x1b[33m"
_SGR_BOLD_YELLOW = "\x1b[1;33m"
_SGR_RED = "\x1b[31m"
_SGR_BOLD_RED = "\x1b[1;31m"
_SGR_MAGENTA = "\x1b[35m"
_SGR_BLUE = "\x1b[34m"
_SGR_WHITE = "\x1b[37m"

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffd]")


def normalize_task_state(state: Optional[str]) -> str:
    """Normalizes arbitrary engine/DB status strings to one of the 6 canonical states."""
    raw = str(state or "").strip()
    if not raw:
        return "Waiting"
    if raw in TASK_STATES:
        return raw
    low = raw.lower()
    if low in _TASK_STATE_ALIASES:
        return _TASK_STATE_ALIASES[low]
    if low.startswith("skip") or "unavailable" in low:
        return "Skipped"
    if "review" in low or "triage" in low or "verif" in low:
        return "In review"
    if "fail" in low or "err" in low or "crash" in low:
        return "Failed"
    if "done" in low or "complet" in low or "pass" in low or "ok" == low:
        return "Done"
    if "run" in low or "claim" in low or "active" in low or "work" in low:
        return "Running"
    return "Waiting"


def _sanitize_text(text: Any, *, max_len: Optional[int] = None, ascii_only: bool = False) -> str:
    """
    Flattens newlines, strips embedded ANSI escapes, control chars, and U+FFFD.
    When `ascii_only=True`, encodes down to clean printable ASCII.
    """
    if text is None:
        return ""
    s = str(text)
    s = _ANSI_ESCAPE_RE.sub("", s)
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    s = _CTRL_CHARS_RE.sub("", s)
    s = " ".join(s.split())
    if ascii_only:
        s = s.encode("ascii", errors="ignore").decode("ascii")
    if max_len is not None and max_len > 3 and len(s) > max_len:
        cut = s[: max_len - 3]
        if " " in cut and len(cut) > 16:
            ws_cut = cut.rsplit(" ", 1)[0].rstrip(" ,;:-")
            if len(ws_cut) >= (max_len - 3) // 2:
                cut = ws_cut
        s = cut.rstrip() + "..."
    return s


def _normalize_handle(name: Optional[str]) -> str:
    """Normalizes worker/agent handle (without leading '@')."""
    cleaned = _sanitize_text(name or "", max_len=48).strip()
    while cleaned.startswith("@"):
        cleaned = cleaned[1:].strip()
    return cleaned


def _format_now_activity(action: str) -> str:
    """Formats activity text so it cleanly begins with `Now ` without duplicating."""
    cleaned = _sanitize_text(action)
    if not cleaned:
        return ""
    if cleaned.lower().startswith("now "):
        return "Now " + cleaned[4:].strip()
    return f"Now {cleaned}"


def _utc_hms() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _supports_unicode(stream: Optional[Any] = None, *, plain: bool = False) -> bool:
    """Returns True iff target stream encoding can cleanly encode Unicode CLI icons."""
    if plain:
        return False
    target = stream if stream is not None else sys.stdout
    encoding = getattr(target, "encoding", None) or locale.getpreferredencoding(False) or "utf-8"
    try:
        _UNICODE_PROBE_SAMPLE.encode(encoding, errors="strict")
        return True
    except (UnicodeEncodeError, LookupError, TypeError, AttributeError):
        return False


def _is_interactive_tty(stream: Optional[Any] = None, *, plain: bool = False) -> bool:
    """Returns True only for interactive non-CI, non-NO_COLOR TTY streams."""
    if plain:
        return False
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        return False
    target = stream if stream is not None else sys.stdout
    try:
        return bool(target.isatty())
    except Exception:
        return False


def _style(text: str, sgr: str, *, use_ansi: bool) -> str:
    if not use_ansi or not sgr or not text:
        return text
    return f"{sgr}{text}{_SGR_RESET}"


def _spinner_frame(tick: int, *, use_unicode: bool) -> str:
    if not use_unicode:
        return ASCII_STATUS_ICONS["Running"]
    idx = int(tick) % len(SPINNER_FRAMES_UNICODE)
    return SPINNER_FRAMES_UNICODE[idx]


def _task_icon(state: str, *, tick: int, use_unicode: bool) -> str:
    norm = normalize_task_state(state)
    if not use_unicode:
        return ASCII_STATUS_ICONS.get(norm, "[ ]")
    if norm == "Running":
        return _spinner_frame(tick, use_unicode=True)
    return UNICODE_STATUS_ICONS.get(norm, "\u25cb")


def _thread_icon(status: str, *, tick: int, use_unicode: bool) -> str:
    if not use_unicode:
        return ASCII_STATUS_ICONS.get(status, "[ ]")
    if status == "Moving":
        return _spinner_frame(tick, use_unicode=True)
    return UNICODE_STATUS_ICONS.get(status, "\u25cb")


def _state_sgr(state: str) -> str:
    mapping = {
        "Running": _SGR_BOLD_CYAN,
        "Moving": _SGR_BOLD_CYAN,
        "In review": _SGR_BOLD_YELLOW,
        "Done": _SGR_BOLD_GREEN,
        "Waiting": _SGR_DIM,
        "Not started": _SGR_DIM,
        "Skipped": _SGR_MAGENTA,
        "Failed": _SGR_BOLD_RED,
    }
    return mapping.get(state, _SGR_WHITE)


def _event_kind_sgr(kind: str) -> str:
    up = str(kind or "").upper()
    if up == "FACT":
        return _SGR_BOLD_GREEN
    if up == "INTENT":
        return _SGR_BOLD_CYAN
    if up == "HINT":
        return _SGR_BOLD_YELLOW
    if up in ("CHAIN", "VULN", "ERROR", "FAIL"):
        return _SGR_BOLD_RED
    return _SGR_BLUE


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class BoardTask:
    name: str
    description: str
    worker: str = ""
    thread_id: str = "general"
    state: str = "Waiting"
    action: str = ""
    note: str = ""
    updated_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.name = _sanitize_text(self.name, max_len=120) or "task"
        self.description = _sanitize_text(self.description, max_len=200) or self.name
        self.worker = _normalize_handle(self.worker)
        self.thread_id = _sanitize_text(self.thread_id, max_len=80) or "general"
        self.state = normalize_task_state(self.state)
        self.action = _sanitize_text(self.action, max_len=240)
        self.note = _sanitize_text(self.note, max_len=240)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "worker": self.worker,
            "thread_id": self.thread_id,
            "state": self.state,
            "action": self.action,
            "note": self.note,
            "updated_at": round(float(self.updated_at), 3),
        }


@dataclass
class BoardThread:
    thread_id: str
    title: str
    goal: str = ""
    explicit_status: Optional[str] = None

    def __post_init__(self) -> None:
        self.thread_id = _sanitize_text(self.thread_id, max_len=80) or "general"
        self.title = _sanitize_text(self.title, max_len=120) or self.thread_id
        self.goal = _sanitize_text(self.goal, max_len=240)

    def compute_summary(self, tasks: Sequence[BoardTask]) -> Dict[str, Any]:
        member_tasks = [t for t in tasks if t.thread_id == self.thread_id]
        total = len(member_tasks)
        done = sum(1 for t in member_tasks if t.state == "Done")
        skipped = sum(1 for t in member_tasks if t.state == "Skipped")
        running = sum(1 for t in member_tasks if t.state == "Running")
        in_review = sum(1 for t in member_tasks if t.state == "In review")
        failed = sum(1 for t in member_tasks if t.state == "Failed")
        waiting = sum(1 for t in member_tasks if t.state == "Waiting")

        if total == 0:
            status = self.explicit_status if self.explicit_status in THREAD_STATES else "Not started"
        elif running > 0 or in_review > 0 or failed > 0:
            status = "Moving"
        elif waiting == total:
            status = "Not started"
        elif (done + skipped) == total:
            status = "Done"
        elif done > 0 or skipped > 0:
            status = "Moving"
        else:
            status = "Not started"

        now_action = ""
        if status == "Moving":
            # Pick highest-priority active task for `Now ...`
            for preferred_state in ("Running", "In review", "Failed"):
                candidates = [t for t in member_tasks if t.state == preferred_state]
                if candidates:
                    # Prefer task with explicit action, most recently updated first
                    candidates.sort(key=lambda item: (bool(item.action or item.note), item.updated_at), reverse=True)
                    chosen = candidates[0]
                    now_action = chosen.action or chosen.note or chosen.description
                    break
            if not now_action:
                # Thread has partial progress (some Done, some Waiting)
                waiting_tasks = [t for t in member_tasks if t.state == "Waiting"]
                if waiting_tasks:
                    now_action = f"Next: {waiting_tasks[0].description}"

        return {
            "thread_id": self.thread_id,
            "title": self.title,
            "goal": self.goal,
            "status": status,
            "done": done,
            "total": total,
            "running": running,
            "in_review": in_review,
            "waiting": waiting,
            "skipped": skipped,
            "failed": failed,
            "fraction": f"{done}/{total}",
            "now_action": now_action,
            "task_names": [t.name for t in member_tasks],
        }


@dataclass
class BoardEvent:
    seq: int
    agent: str
    text: str
    kind: str = "EVENT"
    timestamp: str = field(default_factory=_utc_hms)
    node_id: str = ""
    status: str = ""

    def __post_init__(self) -> None:
        self.seq = int(self.seq)
        self.agent = _normalize_handle(self.agent) or "coordinator"
        self.text = _sanitize_text(self.text, max_len=280)
        self.kind = (_sanitize_text(self.kind, max_len=24) or "EVENT").upper()
        self.timestamp = _sanitize_text(self.timestamp, max_len=32) or _utc_hms()
        self.node_id = _sanitize_text(self.node_id, max_len=120)
        self.status = _sanitize_text(self.status, max_len=32).upper()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "agent": self.agent,
            "text": self.text,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "node_id": self.node_id,
            "status": self.status,
        }


@dataclass
class BoardSnapshot:
    title: str
    goal: str
    task_id: str = "default"
    coordinator: str = "Coordinator"
    team: List[str] = field(default_factory=list)
    tasks: List[BoardTask] = field(default_factory=list)
    threads: List[BoardThread] = field(default_factory=list)
    events: List[BoardEvent] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    spinner_tick: int = 0
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def line(self) -> str:
        return self.goal

    def thread_summaries(self) -> List[Dict[str, Any]]:
        summaries = [th.compute_summary(self.tasks) for th in self.threads]
        known_thread_ids = {th.thread_id for th in self.threads}
        orphan_ids: List[str] = []
        for task in self.tasks:
            if task.thread_id not in known_thread_ids and task.thread_id not in orphan_ids:
                orphan_ids.append(task.thread_id)
        for tid in orphan_ids:
            auto_th = BoardThread(
                thread_id=tid,
                title=_humanize_identifier(tid),
                goal=f"Track tasks grouped under {_humanize_identifier(tid)}.",
            )
            summaries.append(auto_th.compute_summary(self.tasks))
        return summaries

    def counters(self) -> Dict[str, int]:
        th_summaries = self.thread_summaries()
        running = sum(1 for t in self.tasks if t.state == "Running")
        in_review = sum(1 for t in self.tasks if t.state == "In review")
        done = sum(1 for t in self.tasks if t.state == "Done")
        waiting = sum(1 for t in self.tasks if t.state == "Waiting")
        skipped = sum(1 for t in self.tasks if t.state == "Skipped")
        failed = sum(1 for t in self.tasks if t.state == "Failed")
        open_threads = sum(1 for th in th_summaries if th["status"] != "Done")
        return {
            "running": running,
            "in_review": in_review,
            "done": done,
            "waiting": waiting,
            "skipped": skipped,
            "failed": failed,
            "total": len(self.tasks),
            "open_threads": open_threads,
            "total_threads": len(th_summaries),
        }

    def ordered_team(self) -> List[str]:
        seen = set()
        handles: List[str] = []
        coord_low = _normalize_handle(self.coordinator).lower()
        for raw in list(self.team) + [t.worker for t in self.tasks if t.worker] + [e.agent for e in self.events if e.agent]:
            h = _normalize_handle(raw)
            if not h:
                continue
            low = h.lower()
            if low == coord_low or low == "coordinator":
                continue
            if low not in seen:
                seen.add(low)
                handles.append(h)
        return handles

    def to_dict(self) -> Dict[str, Any]:
        th_summaries = self.thread_summaries()
        ctr = self.counters()
        return {
            "title": self.title,
            "goal": self.goal,
            "line": self.goal,
            "task_id": self.task_id,
            "coordinator": self.coordinator,
            "team": self.ordered_team(),
            "counters": ctr,
            "progress_line": (
                f"{ctr['done']} of {ctr['total']} tasks done | "
                f"{ctr['in_review']} in review | "
                f"{ctr['open_threads']} threads open"
            ),
            "tasks": [t.to_dict() for t in self.tasks],
            "threads": th_summaries,
            "events": [e.to_dict() for e in self.events],
            "metadata": dict(self.metadata),
            "spinner_tick": int(self.spinner_tick),
            "generated_at": self.generated_at,
        }


def _humanize_identifier(raw: str) -> str:
    cleaned = _sanitize_text(raw, max_len=80).replace("_", " ").replace("-", " ").strip()
    if not cleaned:
        return "General Execution"
    words = cleaned.split()
    acronyms = {"http", "https", "tls", "pqc", "rfc", "ai", "llm", "poe", "artex", "sast", "sca", "ooda", "rsi", "cli", "db"}
    out = []
    for w in words:
        if w.lower() in acronyms:
            out.append(w.upper())
        else:
            out.append(w.capitalize())
    return " ".join(out)


def _snapshot_from_mapping(data: Dict[str, Any]) -> BoardSnapshot:
    tasks: List[BoardTask] = []
    for raw_t in data.get("tasks") or []:
        if isinstance(raw_t, BoardTask):
            tasks.append(raw_t)
        elif isinstance(raw_t, dict):
            tasks.append(
                BoardTask(
                    name=str(raw_t.get("name") or "task"),
                    description=str(raw_t.get("description") or raw_t.get("name") or "task"),
                    worker=str(raw_t.get("worker") or ""),
                    thread_id=str(raw_t.get("thread_id") or "general"),
                    state=str(raw_t.get("state") or "Waiting"),
                    action=str(raw_t.get("action") or ""),
                    note=str(raw_t.get("note") or ""),
                    updated_at=float(raw_t.get("updated_at") or time.time()),
                )
            )
    threads: List[BoardThread] = []
    for raw_th in data.get("threads") or []:
        if isinstance(raw_th, BoardThread):
            threads.append(raw_th)
        elif isinstance(raw_th, dict):
            threads.append(
                BoardThread(
                    thread_id=str(raw_th.get("thread_id") or raw_th.get("title") or "general"),
                    title=str(raw_th.get("title") or raw_th.get("thread_id") or "General"),
                    goal=str(raw_th.get("goal") or ""),
                    explicit_status=raw_th.get("status") if raw_th.get("status") in THREAD_STATES else None,
                )
            )
    events: List[BoardEvent] = []
    for idx, raw_ev in enumerate(data.get("events") or [], start=1):
        if isinstance(raw_ev, BoardEvent):
            events.append(raw_ev)
        elif isinstance(raw_ev, dict):
            events.append(
                BoardEvent(
                    seq=int(raw_ev.get("seq") or idx),
                    agent=str(raw_ev.get("agent") or "coordinator"),
                    text=str(raw_ev.get("text") or ""),
                    kind=str(raw_ev.get("kind") or "EVENT"),
                    timestamp=str(raw_ev.get("timestamp") or _utc_hms()),
                    node_id=str(raw_ev.get("node_id") or ""),
                    status=str(raw_ev.get("status") or ""),
                )
            )
    return BoardSnapshot(
        title=str(data.get("title") or "RFCHunt Swarm Overview"),
        goal=str(data.get("goal") or data.get("line") or ""),
        task_id=str(data.get("task_id") or "default"),
        coordinator=str(data.get("coordinator") or "Coordinator"),
        team=[str(m) for m in (data.get("team") or [])],
        tasks=tasks,
        threads=threads,
        events=events,
        metadata=dict(data.get("metadata") or {}),
        spinner_tick=int(data.get("spinner_tick") or 0),
        generated_at=str(data.get("generated_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )


# ---------------------------------------------------------------------------
# Stateless Renderer
# ---------------------------------------------------------------------------

def _format_team_line(
    coordinator: str,
    handles: Sequence[str],
    *,
    width: int,
    prefix: str = "  Team: ",
    max_handles: Optional[int] = None,
) -> str:
    coord_label = _sanitize_text(coordinator or "Coordinator", max_len=32) or "Coordinator"
    tokens = [coord_label] + [f"@{_normalize_handle(h)}" for h in handles if _normalize_handle(h)]
    if not tokens:
        return f"{prefix}Coordinator"

    avail = max(24, int(width) - len(prefix))
    cap = len(tokens) if max_handles is None else min(len(tokens), max(1, int(max_handles) + 1))

    # Try fitting all tokens up to cap
    if cap == len(tokens):
        full = ", ".join(tokens)
        if len(full) <= avail:
            return f"{prefix}{full}"

    # Greedily add tokens while preserving room for ` +N` overflow badge
    shown: List[str] = [tokens[0]]
    for idx in range(1, cap):
        remaining = len(tokens) - (idx + 1)
        candidate = ", ".join(shown + [tokens[idx]])
        suffix = f" +{remaining}" if remaining > 0 else ""
        if len(candidate) + len(suffix) <= avail:
            shown.append(tokens[idx])
        else:
            break

    overflow = len(tokens) - len(shown)
    if overflow > 0:
        return f"{prefix}{', '.join(shown)} +{overflow}"
    return f"{prefix}{', '.join(shown)}"


def render_swarm_cli_board(
    board_or_snapshot: Union["SwarmCLIBoard", BoardSnapshot, Dict[str, Any]],
    *,
    plain: bool = False,
    width: int = 100,
    ansi: Optional[bool] = None,
    unicode_icons: Optional[bool] = None,
    spinner_tick: Optional[int] = None,
    limit_events: int = 10,
    max_tasks: int = 50,
    max_team_handles: Optional[int] = None,
    stream: Optional[Any] = None,
) -> str:
    """
    Stateless CLI renderer producing the structured Swarm Overview layout.

    - When `plain=True`: strictly pure ASCII borders and ASCII status icons
      (`[*]`, `[~]`, `[+]`, `[ ]`, `[-]`, `[!]`, `>`), and ZERO `\\x1b[` ANSI codes.
    - When `plain=False`: crisp Unicode live status icons + rotating braille spinner
      (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`, `●`, `◐`, `✓`, `○`, `⊘`, `✗`, `▸`) with automatic
      pure-ASCII icon fallback on non-UTF8 terminals.
    """
    if isinstance(board_or_snapshot, SwarmCLIBoard):
        snap = board_or_snapshot.snapshot()
    elif isinstance(board_or_snapshot, BoardSnapshot):
        snap = board_or_snapshot
    elif isinstance(board_or_snapshot, dict):
        snap = _snapshot_from_mapping(board_or_snapshot)
    else:
        raise TypeError("board_or_snapshot must be a SwarmCLIBoard, BoardSnapshot, or dict")

    w = max(48, min(200, int(width or 100)))
    use_unicode = False if plain else (
        bool(unicode_icons) if unicode_icons is not None else _supports_unicode(stream=stream, plain=False)
    )
    if plain:
        use_ansi = False
    elif ansi is not None:
        use_ansi = bool(ansi)
    else:
        use_ansi = not bool(os.environ.get("NO_COLOR"))

    tick = snap.spinner_tick if spinner_tick is None else int(spinner_tick)
    ascii_sanitize = bool(plain or not use_unicode)

    ctr = snap.counters()
    th_summaries = snap.thread_summaries()
    team_handles = snap.ordered_team()
    now_icon = UNICODE_STATUS_ICONS["Now"] if use_unicode else ASCII_STATUS_ICONS["Now"]
    h_rule = ("\u2500" * w) if use_unicode else ("-" * w)
    top_rule = ("\u2550" * w) if use_unicode else ("=" * w)

    lines: List[str] = []

    # 1. GOAL BLOCK
    title_clean = _sanitize_text(snap.title or "RFCHunt Swarm Overview", ascii_only=ascii_sanitize)
    goal_clean = _sanitize_text(snap.goal, ascii_only=ascii_sanitize)
    task_id_clean = _sanitize_text(snap.task_id or "default", ascii_only=ascii_sanitize)

    lines.append(_style(top_rule, _SGR_CYAN, use_ansi=use_ansi))
    goal_hdr = f"GOAL: {title_clean}  [task:{task_id_clean}]"
    lines.append(_style(goal_hdr, _SGR_BOLD_CYAN, use_ansi=use_ansi))
    if goal_clean:
        for wrapped in textwrap.wrap(goal_clean, width=max(32, w - 2)):
            lines.append(f"  {wrapped}")

    # Progress summary counters
    progress_line = (
        f"{ctr['done']} of {ctr['total']} tasks done | "
        f"{ctr['in_review']} in review | "
        f"{ctr['open_threads']} threads open"
    )
    pct = int(round((100.0 * ctr["done"] / ctr["total"]))) if ctr["total"] > 0 else 0
    bar_w = 16
    filled = int(round((bar_w * pct) / 100.0))
    if use_unicode:
        bar = "\u2588" * filled + "\u2591" * (bar_w - filled)
    else:
        bar = "#" * filled + "-" * (bar_w - filled)
    lines.append(
        "  "
        + _style(progress_line, _SGR_BOLD, use_ansi=use_ansi)
        + f"  [{bar}] {pct}%"
    )
    lines.append(_style(h_rule, _SGR_DIM, use_ansi=use_ansi))

    # 2. RUNNING (N) TASK LIST
    run_icon = (
        UNICODE_STATUS_ICONS["Running"] if ctr["running"] > 0 else UNICODE_STATUS_ICONS["Waiting"]
    ) if use_unicode else (
        ASCII_STATUS_ICONS["Running"] if ctr["running"] > 0 else ASCII_STATUS_ICONS["Waiting"]
    )
    run_spin_suffix = f" {_spinner_frame(tick, use_unicode=True)}" if (use_unicode and ctr["running"] > 0) else ""
    running_header = f"{run_icon} Running ({ctr['running']}){run_spin_suffix}"
    lines.append(_style(running_header, _SGR_BOLD_CYAN if ctr["running"] > 0 else _SGR_BOLD, use_ansi=use_ansi))

    if not snap.tasks:
        lines.append("  (no tracked tasks yet)")
    else:
        ordered_tasks = sorted(
            enumerate(snap.tasks),
            key=lambda pair: (_TASK_SORT_RANK.get(pair[1].state, 99), pair[0]),
        )
        visible_tasks = [t for _, t in ordered_tasks[: max(1, int(max_tasks))]]
        hidden_tasks = max(0, len(ordered_tasks) - len(visible_tasks))

        for task in visible_tasks:
            t_icon = _task_icon(task.state, tick=tick, use_unicode=use_unicode)
            desc = _sanitize_text(task.description, ascii_only=ascii_sanitize)
            worker_str = f"@{_sanitize_text(task.worker, ascii_only=ascii_sanitize)}" if task.worker else ""
            if use_unicode and task.state == "Running":
                badge_text = f"[{UNICODE_STATUS_ICONS['Running']} {task.state}]"
            else:
                badge_text = f"[{task.state}]"

            sgr = _state_sgr(task.state)
            icon_styled = _style(t_icon, sgr, use_ansi=use_ansi)
            badge_styled = _style(badge_text, sgr, use_ansi=use_ansi)
            worker_styled = _style(worker_str, _SGR_DIM, use_ansi=use_ansi) if worker_str else ""

            row_parts = [f"  {icon_styled}", desc, badge_styled]
            if worker_styled:
                row_parts.append(worker_styled)
            lines.append("  ".join(row_parts))

            # Activity / note line
            if task.state in ("Running", "In review") and (task.action or task.note):
                now_str = _format_now_activity(task.action or task.note)
                now_clean = _sanitize_text(now_str, max_len=max(24, w - 8), ascii_only=ascii_sanitize)
                lines.append("    " + _style(f"{now_icon} {now_clean}", _SGR_CYAN if task.state == "Running" else _SGR_YELLOW, use_ansi=use_ansi))
            elif task.note or task.action:
                summary_clean = _sanitize_text(task.note or task.action, max_len=max(24, w - 8), ascii_only=ascii_sanitize)
                lines.append("    " + _style(f"{now_icon} {summary_clean}", _SGR_DIM, use_ansi=use_ansi))

        if hidden_tasks > 0:
            lines.append(f"  ... +{hidden_tasks} more tasks")

    lines.append(_style(h_rule, _SGR_DIM, use_ansi=use_ansi))

    # 3. THREADS SECTION (GROUPED BY OUTCOME)
    threads_header = f"Threads ({ctr['open_threads']} open / {ctr['total_threads']} total)"
    lines.append(_style(threads_header, _SGR_BOLD, use_ansi=use_ansi))

    if not th_summaries:
        lines.append("  (no threads configured)")
    else:
        for th in th_summaries:
            th_status = th["status"]
            th_icon = _thread_icon(th_status, tick=tick, use_unicode=use_unicode)
            th_title = _sanitize_text(th["title"], ascii_only=ascii_sanitize)
            th_frac = th["fraction"]
            if use_unicode and th_status == "Moving":
                th_badge = f"[{UNICODE_STATUS_ICONS['Moving']} {th_status}]"
            else:
                th_badge = f"[{th_status}]"

            sgr = _state_sgr(th_status)
            lines.append(
                f"  {_style(th_icon, sgr, use_ansi=use_ansi)}  "
                f"{_style(th_title, _SGR_BOLD, use_ansi=use_ansi)}  "
                f"{_style(th_badge, sgr, use_ansi=use_ansi)}  "
                f"{th_frac}"
            )
            th_goal = _sanitize_text(th["goal"], max_len=max(32, w - 6), ascii_only=ascii_sanitize)
            if th_goal:
                lines.append(f"    {th_goal}")
            if th_status == "Moving" and th["now_action"]:
                now_str = _format_now_activity(th["now_action"])
                now_clean = _sanitize_text(now_str, max_len=max(24, w - 8), ascii_only=ascii_sanitize)
                lines.append("    " + _style(f"{now_icon} {now_clean}", _SGR_CYAN, use_ansi=use_ansi))

    lines.append(_style(h_rule, _SGR_DIM, use_ansi=use_ansi))

    # 4. THE TEAM & BOARD
    lines.append(_style("The team & board", _SGR_BOLD, use_ansi=use_ansi))
    team_line = _format_team_line(
        snap.coordinator,
        team_handles,
        width=w,
        prefix="  Team: ",
        max_handles=max_team_handles,
    )
    lines.append("  " + _sanitize_text(team_line.lstrip(), ascii_only=ascii_sanitize))

    ev_limit = max(0, int(limit_events))
    recent_events = snap.events[-ev_limit:] if ev_limit > 0 else []
    if not recent_events:
        lines.append("  Board: (no messages yet)")
    else:
        lines.append("  Board:")
        for ev in recent_events:
            ts = _sanitize_text(ev.timestamp, ascii_only=ascii_sanitize)
            kind_badge = f"[{_sanitize_text(ev.kind, ascii_only=ascii_sanitize)}]"
            agent_handle = f"@{_sanitize_text(ev.agent, ascii_only=ascii_sanitize)}"
            status_tag = f" ({_sanitize_text(ev.status, ascii_only=ascii_sanitize)})" if ev.status else ""
            prefix_plain = f"    #{ev.seq} {ts} {kind_badge} {agent_handle}{status_tag}: "
            msg_budget = max(20, w - len(prefix_plain))
            msg_text = _sanitize_text(ev.text, max_len=msg_budget, ascii_only=ascii_sanitize)
            lines.append(
                f"    #{ev.seq} {_style(ts, _SGR_DIM, use_ansi=use_ansi)} "
                f"{_style(kind_badge, _event_kind_sgr(ev.kind), use_ansi=use_ansi)} "
                f"{_style(agent_handle, _SGR_BOLD, use_ansi=use_ansi)}{status_tag}: {msg_text}"
            )

    lines.append(_style(top_rule, _SGR_CYAN, use_ansi=use_ansi))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Thread-safe Live Tracker (`SwarmCLIBoard` / `SwarmCLIBoardTracker`)
# ---------------------------------------------------------------------------

class SwarmCLIBoard:
    """
    Thread-safe live CLI board state tracker and non-blocking terminal printer.

    - Supports context-manager usage (`with board: ...`) and explicit
      `start_live()` / `stop_live()`.
    - Strictly writes ZERO bytes to `sys.stdout` when `json_mode=True`.
    - Strictly emits pure ASCII (zero `\\x1b[` escapes) when `plain=True` or non-TTY.
    - Uses bounded event history (`deque(maxlen=max_events)`) to keep memory constant.
    """

    def __init__(
        self,
        title: str = "RFCHunt Swarm Overview",
        goal: str = "",
        *,
        line: Optional[str] = None,
        task_id: str = "default",
        coordinator: str = "Coordinator",
        team: Optional[Sequence[str]] = None,
        max_events: int = 50,
        plain: bool = False,
        json_mode: bool = False,
        width: int = 100,
        refresh_interval: float = 0.25,
        stream: Optional[Any] = None,
    ) -> None:
        self._lock = threading.RLock()
        self.title = _sanitize_text(title or "RFCHunt Swarm Overview", max_len=140)
        self.goal = _sanitize_text(line if line is not None else goal, max_len=320)
        self.task_id = _sanitize_text(task_id or "default", max_len=80) or "default"
        self.coordinator = _sanitize_text(coordinator or "Coordinator", max_len=40) or "Coordinator"
        self.plain = bool(plain)
        self.json_mode = bool(json_mode)
        self.width = max(48, min(200, int(width or 100)))
        self.refresh_interval = max(0.05, float(refresh_interval))
        self._stream = stream

        self._team: List[str] = []
        for member in (team or []):
            h = _normalize_handle(member)
            if h and h.lower() != self.coordinator.lower() and h.lower() not in {x.lower() for x in self._team}:
                self._team.append(h)

        self._threads: Dict[str, BoardThread] = {}
        self._tasks: Dict[str, BoardTask] = {}
        self._events: Deque[BoardEvent] = collections.deque(maxlen=max(1, int(max_events)))
        self._metadata: Dict[str, Any] = {}
        self._event_seq: int = 0
        self._spinner_tick: int = 0

        # Live printer state
        self._render_lock = threading.Lock()
        self._live_active: bool = False
        self._live_tty: bool = False
        self._live_plain: bool = bool(plain)
        self._live_width: int = self.width
        self._live_interval: float = self.refresh_interval
        self._rich_live: Optional[Any] = None
        self._stop_event: Optional[threading.Event] = None
        self._live_thread: Optional[threading.Thread] = None
        self._last_emit_ts: float = 0.0
        self._dirty: bool = False

    def _out_stream(self) -> Any:
        return self._stream if self._stream is not None else sys.stdout

    def set_goal(self, title: Optional[str] = None, line: Optional[str] = None) -> None:
        with self._lock:
            if title is not None:
                self.title = _sanitize_text(title, max_len=140)
            if line is not None:
                self.goal = _sanitize_text(line, max_len=320)
            self._dirty = True

    def set_metadata(self, key: str, value: Any) -> None:
        with self._lock:
            self._metadata[str(key)] = value

    def add_team_member(self, member: str) -> None:
        h = _normalize_handle(member)
        if not h:
            return
        with self._lock:
            if h.lower() != self.coordinator.lower() and h.lower() not in {x.lower() for x in self._team}:
                self._team.append(h)

    def add_thread(
        self,
        thread_id: str,
        title: str,
        goal: str = "",
        *,
        explicit_status: Optional[str] = None,
    ) -> BoardThread:
        th = BoardThread(
            thread_id=thread_id,
            title=title,
            goal=goal,
            explicit_status=explicit_status,
        )
        with self._lock:
            self._threads[th.thread_id] = th
            self._dirty = True
            return th

    def add_task(
        self,
        name: str,
        description: str,
        *,
        worker: str = "",
        thread_id: str = "general",
        state: str = "Waiting",
        action: str = "",
        note: str = "",
    ) -> BoardTask:
        task = BoardTask(
            name=name,
            description=description,
            worker=worker,
            thread_id=thread_id,
            state=state,
            action=action,
            note=note,
        )
        with self._lock:
            if task.thread_id not in self._threads:
                self._threads[task.thread_id] = BoardThread(
                    thread_id=task.thread_id,
                    title=_humanize_identifier(task.thread_id),
                    goal=f"Complete tasks in {_humanize_identifier(task.thread_id)}.",
                )
            self._tasks[task.name] = task
            if task.worker:
                self.add_team_member(task.worker)
            self._dirty = True
            return task

    def set_task_state(
        self,
        name: str,
        state: str,
        action: str = "",
        note: str = "",
        *,
        worker: Optional[str] = None,
        description: Optional[str] = None,
        thread_id: Optional[str] = None,
    ) -> BoardTask:
        """Thread-safely updates (or auto-registers) a task's status and live activity."""
        norm_state = normalize_task_state(state)
        clean_action = _sanitize_text(action, max_len=240)
        clean_note = _sanitize_text(note, max_len=240)
        should_emit_plain = False
        plain_line = ""

        with self._lock:
            task = self._tasks.get(name)
            if task is None:
                resolved_thread = thread_id or "general"
                if resolved_thread not in self._threads:
                    self._threads[resolved_thread] = BoardThread(
                        thread_id=resolved_thread,
                        title=_humanize_identifier(resolved_thread),
                        goal=f"Track tasks grouped under {_humanize_identifier(resolved_thread)}.",
                    )
                task = BoardTask(
                    name=name,
                    description=description or _humanize_identifier(name),
                    worker=worker or name,
                    thread_id=resolved_thread,
                    state=norm_state,
                    action=clean_action,
                    note=clean_note,
                )
                self._tasks[task.name] = task
            else:
                task.state = norm_state
                if worker is not None:
                    task.worker = _normalize_handle(worker)
                if description is not None:
                    task.description = _sanitize_text(description, max_len=200) or task.description
                if thread_id is not None:
                    task.thread_id = _sanitize_text(thread_id, max_len=80) or task.thread_id
                if norm_state in ("Done", "Skipped", "Failed"):
                    if clean_note:
                        task.note = clean_note
                    elif clean_action:
                        task.note = clean_action
                    task.action = ""
                else:
                    if clean_action:
                        task.action = clean_action
                    elif norm_state == "Waiting":
                        task.action = ""
                    if clean_note:
                        task.note = clean_note
                task.updated_at = time.time()

            if task.worker:
                self.add_team_member(task.worker)
            self._dirty = True

            if self._live_active and not self.json_mode and not self._live_tty:
                now_mono = time.monotonic()
                if (now_mono - self._last_emit_ts) >= self._live_interval or norm_state in ("Done", "Failed", "Skipped"):
                    self._last_emit_ts = now_mono
                    icon = ASCII_STATUS_ICONS.get(norm_state, "[ ]")
                    detail = task.action or task.note
                    suffix = f" > {detail}" if detail else ""
                    worker_disp = f" @{task.worker}" if task.worker else ""
                    plain_line = _sanitize_text(
                        f"{icon} [{norm_state}] {task.description}{worker_disp}{suffix}",
                        ascii_only=True,
                    )
                    should_emit_plain = True

        if should_emit_plain and plain_line:
            self._write_stream_line(plain_line)
        elif self._live_active and self._live_tty and not self.json_mode:
            self.flush_live(force=False)
        return task

    def post_event(
        self,
        agent: str,
        text: str,
        kind: str = "EVENT",
        *,
        node_id: str = "",
        status: str = "",
    ) -> BoardEvent:
        """Thread-safely appends a board/blackboard event to the bounded feed."""
        with self._lock:
            self._event_seq += 1
            ev = BoardEvent(
                seq=self._event_seq,
                agent=agent,
                text=text,
                kind=kind,
                node_id=node_id,
                status=status,
            )
            self._events.append(ev)
            self.add_team_member(ev.agent)
            self._dirty = True
        if self._live_active and self._live_tty and not self.json_mode:
            self.flush_live(force=False)
        return ev

    def advance_spinner(self, steps: int = 1) -> int:
        with self._lock:
            self._spinner_tick = (self._spinner_tick + int(steps)) % len(SPINNER_FRAMES_UNICODE)
            return self._spinner_tick

    def snapshot(self) -> BoardSnapshot:
        with self._lock:
            return BoardSnapshot(
                title=self.title,
                goal=self.goal,
                task_id=self.task_id,
                coordinator=self.coordinator,
                team=list(self._team),
                tasks=[
                    BoardTask(
                        name=t.name,
                        description=t.description,
                        worker=t.worker,
                        thread_id=t.thread_id,
                        state=t.state,
                        action=t.action,
                        note=t.note,
                        updated_at=t.updated_at,
                    )
                    for t in self._tasks.values()
                ],
                threads=[
                    BoardThread(
                        thread_id=th.thread_id,
                        title=th.title,
                        goal=th.goal,
                        explicit_status=th.explicit_status,
                    )
                    for th in self._threads.values()
                ],
                events=[
                    BoardEvent(
                        seq=e.seq,
                        agent=e.agent,
                        text=e.text,
                        kind=e.kind,
                        timestamp=e.timestamp,
                        node_id=e.node_id,
                        status=e.status,
                    )
                    for e in self._events
                ],
                metadata=dict(self._metadata),
                spinner_tick=self._spinner_tick,
            )

    def to_dict(self) -> Dict[str, Any]:
        return self.snapshot().to_dict()

    def render(
        self,
        plain: Optional[bool] = None,
        width: Optional[int] = None,
        *,
        ansi: Optional[bool] = None,
        unicode_icons: Optional[bool] = None,
        spinner_tick: Optional[int] = None,
        limit_events: int = 10,
        max_tasks: int = 50,
        max_team_handles: Optional[int] = None,
    ) -> str:
        eff_plain = self.plain if plain is None else bool(plain)
        eff_width = self.width if width is None else int(width)
        return render_swarm_cli_board(
            self.snapshot(),
            plain=eff_plain,
            width=eff_width,
            ansi=ansi,
            unicode_icons=unicode_icons,
            spinner_tick=spinner_tick,
            limit_events=limit_events,
            max_tasks=max_tasks,
            max_team_handles=max_team_handles,
            stream=self._out_stream(),
        )

    def _write_stream_line(self, text: str) -> None:
        if self.json_mode:
            return
        target = self._out_stream()
        with self._render_lock:
            try:
                target.write(text + "\n")
                target.flush()
            except Exception:
                pass

    def _build_rich_renderable(self) -> Any:
        rendered = self.render(
            plain=self._live_plain,
            width=self._live_width,
            ansi=not self._live_plain,
        )
        if _RichText is not None:
            return _RichText.from_ansi(rendered)
        return rendered

    def _live_loop(self) -> None:
        stop_ev = self._stop_event
        if stop_ev is None:
            return
        while not stop_ev.wait(self._live_interval):
            if self.json_mode:
                break
            self.advance_spinner(1)
            self.flush_live(force=True)

    def start_live(
        self,
        *,
        refresh_interval: Optional[float] = None,
        plain: Optional[bool] = None,
        width: Optional[int] = None,
    ) -> "SwarmCLIBoard":
        """
        Starts non-blocking throttled live terminal rendering.
        Strictly a no-op (zero stdout writes) when `json_mode=True`.
        """
        with self._lock:
            if self.json_mode or self._live_active:
                return self

            self._live_interval = max(0.05, float(refresh_interval if refresh_interval is not None else self.refresh_interval))
            self._live_width = max(48, min(200, int(width if width is not None else self.width)))
            requested_plain = self.plain if plain is None else bool(plain)
            target = self._out_stream()
            is_tty = _is_interactive_tty(target, plain=requested_plain)
            self._live_tty = is_tty
            self._live_plain = True if (requested_plain or not is_tty) else False
            self._live_active = True
            self._last_emit_ts = 0.0

            if self._live_tty and _RICH_AVAILABLE and _RichConsole is not None and _RichLive is not None:
                try:
                    console = _RichConsole(file=target, force_terminal=True, width=self._live_width)
                    live = _RichLive(
                        self._build_rich_renderable(),
                        console=console,
                        refresh_per_second=max(1, min(10, int(round(1.0 / self._live_interval)))),
                        transient=False,
                    )
                    live.__enter__()
                    self._rich_live = live
                except Exception:
                    self._rich_live = None

            if self._live_tty:
                self._stop_event = threading.Event()
                self._live_thread = threading.Thread(
                    target=self._live_loop,
                    name="rfchunt-cli-board-live",
                    daemon=True,
                )
                self._live_thread.start()
        return self

    def flush_live(self, *, force: bool = False) -> None:
        """Flushes a throttled live frame to the terminal when live mode is active."""
        if self.json_mode:
            return
        with self._lock:
            if not self._live_active:
                return
            now_mono = time.monotonic()
            if not force and (now_mono - self._last_emit_ts) < self._live_interval:
                return
            self._last_emit_ts = now_mono
            self._dirty = False
            rich_live = self._rich_live
            live_tty = self._live_tty
            live_plain = self._live_plain
            live_width = self._live_width

        if live_tty:
            with self._render_lock:
                if rich_live is not None:
                    try:
                        rich_live.update(self._build_rich_renderable())
                        return
                    except Exception:
                        pass
                # Stdlib TTY fallback when rich is unavailable
                rendered = self.render(plain=live_plain, width=live_width, ansi=not live_plain)
                target = self._out_stream()
                try:
                    if not live_plain:
                        target.write("\x1b[2J\x1b[H" + rendered + "\n")
                    else:
                        target.write(rendered + "\n")
                    target.flush()
                except Exception:
                    pass

    def stop_live(self, *, print_final: bool = True) -> None:
        """Stops background live updates and prints final snapshot cleanly (unless json_mode=True)."""
        thread_to_join: Optional[threading.Thread] = None
        rich_live_to_close: Optional[Any] = None
        should_print_plain_final = False
        final_plain = True
        final_width = self.width

        with self._lock:
            if not self._live_active:
                return
            self._live_active = False
            if self._stop_event is not None:
                self._stop_event.set()
            thread_to_join = self._live_thread
            self._live_thread = None
            self._stop_event = None
            rich_live_to_close = self._rich_live
            self._rich_live = None
            final_plain = self._live_plain
            final_width = self._live_width
            should_print_plain_final = bool(print_final and not self.json_mode and rich_live_to_close is None)

        if thread_to_join is not None and thread_to_join.is_alive():
            thread_to_join.join(timeout=1.5)

        if rich_live_to_close is not None:
            with self._render_lock:
                try:
                    if print_final and not self.json_mode:
                        rich_live_to_close.update(self._build_rich_renderable())
                except Exception:
                    pass
                try:
                    rich_live_to_close.__exit__(None, None, None)
                except Exception:
                    pass
        elif should_print_plain_final:
            final_frame = self.render(plain=final_plain, width=final_width, ansi=not final_plain)
            self._write_stream_line(final_frame)

    def __enter__(self) -> "SwarmCLIBoard":
        self.start_live()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop_live(print_final=True)


# Alias requested by contract
SwarmCLIBoardTracker = SwarmCLIBoard


# ---------------------------------------------------------------------------
# Pre-built RFCHunt Board Templates
# ---------------------------------------------------------------------------

def create_all_scan_board(
    target_label: str,
    task_id: str = "default",
    *,
    plain: bool = False,
    json_mode: bool = False,
    width: int = 100,
    stream: Optional[Any] = None,
) -> SwarmCLIBoard:
    """
    Creates a SwarmCLIBoard pre-populated with outcome threads and tasks for
    `rfc_hunt_swarm.py --all` / `run_unified_all_scans`.
    """
    target_clean = _sanitize_text(target_label or "target", max_len=120) or "target"
    board = SwarmCLIBoard(
        title="RFCHunt --all Security Audit",
        goal=f"Audit {target_clean} across toolchain, static/AI surface, differential/invariant/fuzzing, ARTEX POE-3, and Blackboard Dream-RSI pipelines.",
        task_id=task_id,
        plain=plain,
        json_mode=json_mode,
        width=width,
        stream=stream,
    )

    board.add_thread(
        "toolchain",
        "Toolchain & Provisioning",
        "Prepare memory-safe local AI models, ModelFusion arbiter, and scanner binaries.",
    )
    board.add_thread(
        "static_ai",
        "Static & AI Surface Analysis",
        "Run Mantis, RAPTOR SAST/PQC/SCA, aiscan, REA, call-graph slicing, and scanners.",
    )
    board.add_thread(
        "diff_inv_fuzz",
        "Differential Matrix, Invariants & Fuzzing",
        "Detect cross-parser divergences, enforce repo invariants, and fuzz coverage.",
    )
    board.add_thread(
        "artex_poe",
        "ARTEX Chaining & POE-3 Verification",
        "Build ARTEX attack chains, verify POE=3 evidence, and triage novelty corpus.",
    )
    board.add_thread(
        "blackboard_dream",
        "Blackboard OODA & Dream-RSI",
        "Sync Cairn blackboard FACT/INTENT/HINT state, evolve Dream-RSI, and export.",
    )

    # Thread 1: Toolchain & Provisioning
    board.add_task("provisioner", "Provision local Ollama models & scanner toolchain", worker="provisioner", thread_id="toolchain")
    board.add_task("fusion_arbiter", "Initialize ModelFusion & abliterated model arbiter", worker="fusion-arbiter", thread_id="toolchain")

    # Thread 2: Static & AI Surface Analysis
    board.add_task("mantis", "Mantis threat model, hypotheses & patch verification", worker="mantis", thread_id="static_ai")
    board.add_task("raptor", "RAPTOR SAST, Post-Quantum Crypto & SCA scan", worker="raptor", thread_id="static_ai")
    board.add_task("aiscan", "AI/LLM security surface audit (aiscan)", worker="aiscan", thread_id="static_ai")
    board.add_task("rea_agents", "REA capability & boundary static/CLI analysis", worker="rea-agents", thread_id="static_ai")
    board.add_task("call_graph", "Whole-repo call-graph & taint slicing", worker="slicer", thread_id="static_ai")
    board.add_task("external_scanners", "External discovery & safe Nuclei scan (httpx/katana/nuclei)", worker="scanners", thread_id="static_ai")

    # Thread 3: Differential Matrix / Invariants / Fuzzing
    board.add_task("differential_matrix", "Differential multi-implementation parser matrix", worker="diff-oracle", thread_id="diff_inv_fuzz")
    board.add_task("sandbox_invariants", "Sandboxed container security invariant checks", worker="invariant-runner", thread_id="diff_inv_fuzz")
    board.add_task("fuzz_bridge", "LLM-guided isolated coverage fuzzing bridge", worker="fuzzer", thread_id="diff_inv_fuzz")

    # Thread 4: ARTEX Chaining & POE-3 Verification
    board.add_task("artex_dual_graph", "ARTEX Dual-Graph attack chaining & asset coverage", worker="artex", thread_id="artex_poe")
    board.add_task("poe_verifier", "Containerized non-destructive POE=3 verification", worker="poe-verifier", thread_id="artex_poe")
    board.add_task("novelty_corpus", "Structural fingerprinting & novelty corpus triage", worker="novelty-triage", thread_id="artex_poe")

    # Thread 5: Blackboard OODA & Dream-RSI
    board.add_task("blackboard_sync", "Cairn blackboard FACT/INTENT/HINT sync & exports", worker="blackboard", thread_id="blackboard_dream")
    board.add_task("dream_rsi", "Dream-RSI replay policy evolution & tiered routing", worker="dream-rsi", thread_id="blackboard_dream")

    return board


def create_swarm_ooda_board(
    rfc_num: str,
    host: str,
    port: int,
    task_id: str = "default",
    *,
    plain: bool = False,
    json_mode: bool = False,
    width: int = 100,
    stream: Optional[Any] = None,
) -> SwarmCLIBoard:
    """
    Creates a SwarmCLIBoard pre-populated for `ProtocolResearchSwarm` OODA execution
    tracking Bootstrap, Reason, Explore, Triage, Publish, DreamRSI, and DualGraph.
    """
    rfc_label = _sanitize_text(str(rfc_num or "RFC"), max_len=40)
    host_label = _sanitize_text(str(host or "127.0.0.1"), max_len=80)
    port_num = int(port or 80)

    board = SwarmCLIBoard(
        title=f"RFCHunt OODA Swarm ({rfc_label})",
        goal=f"Autonomously research {rfc_label} against {host_label}:{port_num} via Cairn Blackboard OODA, DualGraph chaining, and Dream-RSI.",
        task_id=task_id,
        plain=plain,
        json_mode=json_mode,
        width=width,
        stream=stream,
    )

    board.add_thread(
        "ooda_intake",
        "Bootstrap & Hypothesis Reasoning",
        "Ingest RFC normative rules, active blackboard hints, and synthesize boundary probes.",
    )
    board.add_thread(
        "ooda_exec",
        "Stateful Exploration & Reproducibility Triage",
        "Execute pipelined canary probes, run differential oracles, and delta-debug anomalies.",
    )
    board.add_thread(
        "ooda_publish",
        "DualGraph Chaining, Defensive Publish & Dream-RSI",
        "Link multi-hop DualGraph paths, publish defensive rules, and evolve Dream-RSI policies.",
    )

    board.add_task("Bootstrap", f"Fetch {rfc_label}, chunk fragments & seed blackboard", worker="bootstrap", thread_id="ooda_intake")
    board.add_task("Reason", "Synthesize protocol & boundary candidates via ModelFusion", worker="reasoner", thread_id="ooda_intake")
    board.add_task("Explore", f"Execute stateful canary probes against {host_label}:{port_num}", worker="explorer", thread_id="ooda_exec")
    board.add_task("Triage", "Delta-debug anomalies, 3-trial confirmation & novelty check", worker="triager", thread_id="ooda_exec")
    board.add_task("DualGraph", "Synthesize ARTEX Dual-Graph chains & asset coverage", worker="dual-graph", thread_id="ooda_publish")
    board.add_task("Publish", "Publish defensive rules, regression tests & advisories", worker="publisher", thread_id="ooda_publish")
    board.add_task("DreamRSI", "Evolve Dream-RSI replay-tree exploration policy", worker="dream-rsi", thread_id="ooda_publish")

    return board


def update_all_board_from_result(board: SwarmCLIBoard, result: Dict[str, Any]) -> None:
    """
    Convenience hook for CLI callers to synchronize `--all` result statuses
    onto an existing `create_all_scan_board(...)` instance.
    """
    if not isinstance(result, dict):
        return

    def _status_to_state(raw_val: Any) -> Tuple[str, str]:
        if isinstance(raw_val, dict):
            st = str(raw_val.get("status") or "").strip().lower()
            if st in ("disabled", "skipped", "skipped_docker_unavailable", "skipped_toolchain_unavailable"):
                return "Skipped", st
            if st in ("error", "failed"):
                return "Failed", str(raw_val.get("error") or st)
            if st in ("ok", "completed", "done", "verified", "success"):
                cnt = raw_val.get("findings_count") or raw_val.get("chains_count") or raw_val.get("total_findings")
                return "Done", f"{st} (count={cnt})" if cnt is not None else st
            if raw_val.get("findings") is not None:
                return "Done", f"{len(raw_val.get('findings') or [])} findings"
            return "Done", st or "completed"
        if isinstance(raw_val, list):
            return "Done", f"{len(raw_val)} items"
        if raw_val:
            return normalize_task_state(str(raw_val)), str(raw_val)
        return "Skipped", "not executed"

    mapping = (
        ("provisioner", "provisioning"),
        ("mantis", "mantis"),
        ("raptor", "raptor"),
        ("aiscan", "aiscan"),
        ("rea_agents", "rea_agents"),
        ("call_graph", "call_graph"),
        ("external_scanners", "external_discovery"),
        ("differential_matrix", "differential_matrix"),
        ("sandbox_invariants", "sandbox_invariants"),
        ("fuzz_bridge", "fuzz_bridge"),
        ("artex_dual_graph", "artex"),
        ("poe_verifier", "poe_verification"),
        ("novelty_corpus", "novelty"),
        ("dream_rsi", "dream_rsi"),
    )
    for task_name, key in mapping:
        if key in result:
            st, note = _status_to_state(result.get(key))
            board.set_task_state(task_name, st, note=note)


# ---------------------------------------------------------------------------
# SQLite Live Board Snapshot Loader & CLI Watch Helper
# ---------------------------------------------------------------------------

def _existing_tables(cur: sqlite3.Cursor) -> set:
    cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    return {str(r[0]) for r in cur.fetchall() if r and r[0]}


def _format_db_timestamp(raw_ts: Any) -> str:
    text = _sanitize_text(raw_ts)
    if not text:
        return _utc_hms()
    if " " in text:
        tail = text.split(" ")[-1]
        if len(tail) >= 8:
            return tail[:8]
    if "T" in text:
        tail = text.split("T")[-1]
        if len(tail) >= 8:
            return tail[:8]
    return text[:16]


def load_board_snapshot_from_db(
    db_path: Union[str, Path],
    *,
    task_id: Optional[str] = None,
    limit_events: int = 15,
) -> BoardSnapshot:
    """
    Reads live swarm progress directly from SQLite (`blackboard_nodes`, plus
    `attack_chains`, `evaluations`, and `worker_execution_traces` when present)
    without mutating the database.
    """
    path_str = str(db_path)
    if path_str not in (":memory:", "") and not path_str.startswith("file:"):
        p = Path(path_str)
        if not p.exists():
            raise FileNotFoundError(f"RFCHunt SQLite database not found: {p}")

    conn = sqlite3.connect(path_str, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        tables = _existing_tables(cur)

        bb_rows: List[Dict[str, Any]] = []
        if "blackboard_nodes" in tables:
            if task_id is not None and str(task_id).strip():
                cur.execute(
                    "SELECT * FROM blackboard_nodes WHERE task_id = ? ORDER BY id ASC",
                    (str(task_id).strip(),),
                )
            else:
                cur.execute("SELECT * FROM blackboard_nodes ORDER BY id ASC")
            bb_rows = [dict(r) for r in cur.fetchall()]

        # Read attack_chains metadata safely (never reads encrypted raw_payload)
        chain_rows: List[Dict[str, Any]] = []
        if "attack_chains" in tables:
            try:
                cur.execute("PRAGMA table_info(attack_chains)")
                chain_cols = {str(r[1]) for r in cur.fetchall()}
                select_cols = [
                    c for c in (
                        "chain_id", "title", "attack_type", "target_host", "target_endpoint",
                        "is_verified", "severity", "task_id", "poe_level", "verification_status",
                        "hop_count", "created_at",
                    )
                    if c in chain_cols
                ]
                if select_cols:
                    col_sql = ", ".join(select_cols)
                    if task_id is not None and str(task_id).strip() and "task_id" in chain_cols:
                        cur.execute(
                            f"SELECT {col_sql} FROM attack_chains WHERE task_id = ? ORDER BY created_at ASC",
                            (str(task_id).strip(),),
                        )
                    else:
                        cur.execute(f"SELECT {col_sql} FROM attack_chains ORDER BY created_at ASC")
                    chain_rows = [dict(r) for r in cur.fetchall()]
            except sqlite3.OperationalError:
                chain_rows = []

        # Read evaluations summary safely (never reads raw_evidence)
        eval_rows: List[Dict[str, Any]] = []
        if "evaluations" in tables:
            try:
                cur.execute(
                    "SELECT eval_id, probe_id, target_host, target_port, is_vulnerable, "
                    "desync_class, finding_status, details, tested_at "
                    "FROM evaluations ORDER BY eval_id DESC LIMIT 50"
                )
                eval_rows = [dict(r) for r in cur.fetchall()]
            except sqlite3.OperationalError:
                eval_rows = []

        # Read worker traces handles when present
        trace_workers: List[str] = []
        trace_total = 0
        if "worker_execution_traces" in tables:
            try:
                if task_id is not None and str(task_id).strip():
                    cur.execute(
                        "SELECT DISTINCT worker_id FROM worker_execution_traces WHERE task_id = ?",
                        (str(task_id).strip(),),
                    )
                    trace_workers = [str(r[0]) for r in cur.fetchall() if r and r[0]]
                    cur.execute(
                        "SELECT COUNT(*) FROM worker_execution_traces WHERE task_id = ?",
                        (str(task_id).strip(),),
                    )
                    trace_total = int(cur.fetchone()[0] or 0)
                else:
                    cur.execute("SELECT DISTINCT worker_id FROM worker_execution_traces")
                    trace_workers = [str(r[0]) for r in cur.fetchall() if r and r[0]]
                    cur.execute("SELECT COUNT(*) FROM worker_execution_traces")
                    trace_total = int(cur.fetchone()[0] or 0)
            except sqlite3.OperationalError:
                pass
    finally:
        conn.close()

    # Build snapshot from loaded records
    observed_task_ids = sorted({str(r.get("task_id") or "default") for r in bb_rows if r.get("task_id")})
    resolved_task_id = (
        str(task_id).strip()
        if (task_id is not None and str(task_id).strip())
        else (observed_task_ids[-1] if len(observed_task_ids) == 1 else (observed_task_ids[-1] if observed_task_ids else "default"))
    )

    threads_map: Dict[str, BoardThread] = {}
    tasks: List[BoardTask] = []
    team_set: List[str] = []
    seen_team: set = set()

    def _add_team(raw_agent: Any) -> None:
        h = _normalize_handle(str(raw_agent or ""))
        if h and h.lower() != "coordinator" and h.lower() not in seen_team:
            seen_team.add(h.lower())
            team_set.append(h)

    for w_id in trace_workers:
        _add_team(w_id)

    fact_count = 0
    intent_count = 0
    hint_count = 0
    all_events: List[BoardEvent] = []

    for row in bb_rows:
        ntype = str(row.get("node_type") or "").upper()
        status_raw = str(row.get("status") or "").upper()
        domain = _sanitize_text(row.get("domain") or "", max_len=64)
        rfc_id = _sanitize_text(row.get("rfc_id") or "", max_len=40)
        source_agent = _normalize_handle(row.get("source_agent") or "")
        claimed_by = _normalize_handle(row.get("claimed_by") or "")
        content = _sanitize_text(row.get("content") or "", max_len=240)
        node_id = _sanitize_text(row.get("node_id") or "", max_len=120)
        seq_num = int(row.get("id") or (len(all_events) + 1))

        payload: Dict[str, Any] = {}
        raw_payload = row.get("payload_json")
        if isinstance(raw_payload, str) and raw_payload.strip():
            try:
                parsed = json.loads(raw_payload)
                if isinstance(parsed, dict):
                    payload = parsed
            except (ValueError, TypeError):
                payload = {}

        if source_agent:
            _add_team(source_agent)
        if claimed_by:
            _add_team(claimed_by)

        if ntype == "FACT":
            fact_count += 1
        elif ntype == "HINT":
            hint_count += 1
        elif ntype == "INTENT":
            intent_count += 1
            th_id = domain.lower() if domain else (rfc_id.lower() if rfc_id else "blackboard")
            if th_id not in threads_map:
                th_title = _humanize_identifier(domain or rfc_id or "Blackboard Execution")
                threads_map[th_id] = BoardThread(
                    thread_id=th_id,
                    title=th_title,
                    goal=f"Execute queued and claimed {th_title} hypotheses and confirm facts.",
                )

            task_state = normalize_task_state(status_raw)
            worker_name = claimed_by or source_agent or "worker"
            action_text = ""
            note_text = ""
            if task_state in ("Running", "In review"):
                action_text = _sanitize_text(payload.get("action") or payload.get("current_step") or content, max_len=200)
            elif task_state in ("Done", "Skipped", "Failed"):
                note_text = _sanitize_text(payload.get("summary") or payload.get("outcome") or payload.get("reason") or "", max_len=200)

            tasks.append(
                BoardTask(
                    name=node_id or f"intent-{seq_num}",
                    description=content or node_id or f"Intent #{seq_num}",
                    worker=worker_name,
                    thread_id=th_id,
                    state=task_state,
                    action=action_text,
                    note=note_text,
                )
            )

        ev_agent = claimed_by or source_agent or "blackboard"
        all_events.append(
            BoardEvent(
                seq=seq_num,
                agent=ev_agent,
                text=content or node_id,
                kind=ntype or "EVENT",
                timestamp=_format_db_timestamp(row.get("updated_at") or row.get("created_at")),
                node_id=node_id,
                status=status_raw,
            )
        )

    # Aggregate attack_chains & evaluations telemetry
    verified_chains = sum(
        1 for ch in chain_rows
        if bool(ch.get("is_verified")) or str(ch.get("verification_status") or "").upper() == "VERIFIED"
    )
    max_poe = max((int(ch.get("poe_level") or 0) for ch in chain_rows), default=0)
    vuln_evals = sum(1 for ev in eval_rows if bool(ev.get("is_vulnerable")))

    # If DB has attack_chains / evaluations but zero INTENTs, surface them as tracked tasks
    if not tasks and chain_rows:
        threads_map["attack_chains"] = BoardThread(
            thread_id="attack_chains",
            title="ARTEX Attack Chains",
            goal="Verify synthesized attack chains to POE=3 evidence.",
        )
        for ch in chain_rows:
            cid = str(ch.get("chain_id") or "chain")
            ch_verified = bool(ch.get("is_verified")) or str(ch.get("verification_status") or "").upper() == "VERIFIED"
            poe_lvl = int(ch.get("poe_level") or 0)
            tasks.append(
                BoardTask(
                    name=cid,
                    description=str(ch.get("title") or ch.get("attack_type") or cid),
                    worker="artex",
                    thread_id="attack_chains",
                    state="Done" if ch_verified else "In review",
                    action="" if ch_verified else f"Verifying {ch.get('attack_type') or cid} (POE={poe_lvl})",
                    note=f"POE={poe_lvl} ({ch.get('severity') or 'HIGH'})",
                )
            )
            _add_team("artex")

    # Add recent verified chains / vulnerable evaluations as board events if space allows
    ev_limit = max(1, int(limit_events))
    selected_events = all_events[-ev_limit:]
    next_seq = (all_events[-1].seq if all_events else 0) + 1
    if len(selected_events) < ev_limit:
        for ch in chain_rows[-(ev_limit - len(selected_events)) :]:
            selected_events.append(
                BoardEvent(
                    seq=next_seq,
                    agent="artex",
                    text=f"{ch.get('title') or ch.get('attack_type') or ch.get('chain_id')} (POE={int(ch.get('poe_level') or 0)})",
                    kind="CHAIN",
                    timestamp=_format_db_timestamp(ch.get("created_at")),
                    node_id=str(ch.get("chain_id") or ""),
                    status=str(ch.get("verification_status") or ("VERIFIED" if ch.get("is_verified") else "UNVERIFIED")),
                )
            )
            next_seq += 1
    if len(selected_events) < ev_limit:
        for ev in [r for r in eval_rows if bool(r.get("is_vulnerable"))][: (ev_limit - len(selected_events))]:
            selected_events.append(
                BoardEvent(
                    seq=next_seq,
                    agent="explorer",
                    text=f"{ev.get('desync_class') or 'anomaly'} on {ev.get('target_host')}:{ev.get('target_port')}",
                    kind="EVAL",
                    timestamp=_format_db_timestamp(ev.get("tested_at")),
                    status=str(ev.get("finding_status") or "UNVERIFIED"),
                )
            )
            next_seq += 1

    db_name = Path(path_str).name if path_str not in (":memory:", "") else ":memory:"
    goal_parts = [
        f"Live blackboard snapshot from {db_name}",
        f"FACT={fact_count}",
        f"INTENT={intent_count}",
        f"HINT={hint_count}",
    ]
    if chain_rows:
        goal_parts.append(f"Chains={len(chain_rows)} ({verified_chains} verified, max POE={max_poe})")
    if eval_rows:
        goal_parts.append(f"Evals={len(eval_rows)} ({vuln_evals} vulnerable)")

    return BoardSnapshot(
        title=f"RFCHunt Blackboard Swarm ({resolved_task_id})",
        goal=" | ".join(goal_parts),
        task_id=resolved_task_id,
        coordinator="Coordinator",
        team=team_set,
        tasks=tasks,
        threads=list(threads_map.values()),
        events=selected_events,
        metadata={
            "db_path": path_str,
            "task_ids": observed_task_ids,
            "blackboard_counts": {
                "FACT": fact_count,
                "INTENT": intent_count,
                "HINT": hint_count,
                "total": len(bb_rows),
            },
            "attack_chains": {
                "total": len(chain_rows),
                "verified": verified_chains,
                "max_poe_level": max_poe,
            },
            "evaluations": {
                "total": len(eval_rows),
                "vulnerable": vuln_evals,
            },
            "worker_traces_total": trace_total,
        },
    )


def watch_board_from_db(
    db_path: Union[str, Path],
    *,
    task_id: Optional[str] = None,
    interval: float = 1.0,
    limit_events: int = 15,
    plain: bool = False,
    as_json: bool = False,
    width: int = 100,
    watch: bool = False,
    max_iterations: Optional[int] = None,
    stream: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    CLI entry helper powering:
      `rfc_hunt_swarm.py swarm-board --db <path> [--task-id ...] [--watch --interval 1.0] [--plain] [--json]`

    - Single-shot when `watch=False`.
    - Live refreshing terminal loop when `watch=True` (Ctrl+C exits cleanly).
    - Emits clean JSON when `as_json=True`, pure ASCII when `plain=True` or non-TTY.
    """
    target = stream if stream is not None else sys.stdout
    poll_interval = max(0.1, float(interval or 1.0))
    is_tty = _is_interactive_tty(target, plain=plain)
    eff_plain = True if (plain or not is_tty) else False

    def _emit_line(payload_str: str) -> None:
        target.write(payload_str + "\n")
        target.flush()

    if not watch:
        snap = load_board_snapshot_from_db(db_path, task_id=task_id, limit_events=limit_events)
        data = snap.to_dict()
        if as_json:
            _emit_line(json.dumps(data, indent=2, default=str))
        else:
            _emit_line(
                render_swarm_cli_board(
                    snap,
                    plain=eff_plain,
                    width=width,
                    ansi=not eff_plain,
                    limit_events=limit_events,
                    stream=target,
                )
            )
        return data

    # Watch loop
    iteration = 0
    last_data: Dict[str, Any] = {}
    use_rich_live = (
        not as_json
        and not eff_plain
        and is_tty
        and _RICH_AVAILABLE
        and _RichConsole is not None
        and _RichLive is not None
        and _RichText is not None
    )

    try:
        if use_rich_live:
            console = _RichConsole(file=target, force_terminal=True, width=max(48, int(width)))
            with _RichLive(console=console, refresh_per_second=max(1, min(8, int(round(1.0 / poll_interval)))), transient=False) as live:
                while max_iterations is None or iteration < int(max_iterations):
                    snap = load_board_snapshot_from_db(db_path, task_id=task_id, limit_events=limit_events)
                    snap.spinner_tick = iteration % len(SPINNER_FRAMES_UNICODE)
                    last_data = snap.to_dict()
                    rendered = render_swarm_cli_board(
                        snap,
                        plain=False,
                        width=width,
                        ansi=True,
                        spinner_tick=snap.spinner_tick,
                        limit_events=limit_events,
                        stream=target,
                    )
                    live.update(_RichText.from_ansi(rendered))
                    iteration += 1
                    if max_iterations is not None and iteration >= int(max_iterations):
                        break
                    time.sleep(poll_interval)
        else:
            while max_iterations is None or iteration < int(max_iterations):
                snap = load_board_snapshot_from_db(db_path, task_id=task_id, limit_events=limit_events)
                snap.spinner_tick = iteration % len(SPINNER_FRAMES_UNICODE)
                last_data = snap.to_dict()
                if as_json:
                    _emit_line(json.dumps(last_data, default=str))
                else:
                    rendered = render_swarm_cli_board(
                        snap,
                        plain=eff_plain,
                        width=width,
                        ansi=not eff_plain,
                        spinner_tick=snap.spinner_tick,
                        limit_events=limit_events,
                        stream=target,
                    )
                    if is_tty and not eff_plain:
                        target.write("\x1b[2J\x1b[H" + rendered + "\n")
                        target.flush()
                    else:
                        _emit_line(rendered)
                iteration += 1
                if max_iterations is not None and iteration >= int(max_iterations):
                    break
                time.sleep(poll_interval)
    except KeyboardInterrupt:
        pass
    return last_data


__all__ = [
    "TASK_STATES",
    "THREAD_STATES",
    "SPINNER_FRAMES_UNICODE",
    "UNICODE_STATUS_ICONS",
    "ASCII_STATUS_ICONS",
    "normalize_task_state",
    "BoardTask",
    "BoardThread",
    "BoardEvent",
    "BoardSnapshot",
    "SwarmCLIBoard",
    "SwarmCLIBoardTracker",
    "render_swarm_cli_board",
    "create_all_scan_board",
    "create_swarm_ooda_board",
    "update_all_board_from_result",
    "load_board_snapshot_from_db",
    "watch_board_from_db",
]
