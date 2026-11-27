#!/usr/bin/env python3
"""
RFCHunt + ModelFusion Turnkey Python Autonomous Hunter (`hunt.py`)
==================================================================
Single pure-Python command that runs everything automatically up to your
final manual "Submit report" click in Google Chrome:

    python hunt.py

Default behavior (no flags required):
  1. Auto-starts local ModelFusion server (:5000) with abliterated security models
     and deterministic Anti-Junk & Grounding Guards (falls back to Ollama if :5000 is absent).
  2. Polls & shallow-clones UNLOCKED in-scope watchlist repos (`ProgramEligibilityDB`).
  3. Runs ALL checks:
       - `freshness-watch` (<72h PRs/releases)
       - `fast-ooda` (3-stage parallel SQLite Blackboard + ACDSO + Auto-PoC Gate)
       - `ensemble-audit --all --ensemble --quorum 2` (SARIF 2.1.0)
       - `lean-verify` (Lean 4 formal proof check)
       - Safety & violation checks (blocks secret leaks, `&lt;` HTML entities, control chars)
       - `qa-drafts --write-repaired --strict` + `check-drafts`
  4. Stages ONLY verified, zero-violation, QA-PASS drafts (never clicks Submit,
     never bypasses login/2FA/CAPTCHA), prints every clickable URL, writes
     `out/autonomous_hunt/READY_TO_CLICK_SUBMIT.md`, and opens Google Chrome
     directly to those URLs so you only review and click Submit.
  5. Repeats every 60 minutes (or pass `--once` for a single pass, or
     `--install-schedule` to register an automatic OS scheduled task).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

RFCHUNT_ROOT = Path(__file__).resolve().parent
if str(RFCHUNT_ROOT) not in sys.path:
    sys.path.insert(0, str(RFCHUNT_ROOT))

from scripts.autonomous_hunt import main as autonomous_hunt_main

DEFAULT_TASK_NAME = "RFCHunt-Autonomous-Defensive-Hunt"


def build_hunt_argv(ns: argparse.Namespace) -> list[str]:
    """Translates simple `hunt.py` flags into full `scripts/autonomous_hunt.py` argv."""
    argv: list[str] = ["--start-modelfusion"]

    if getattr(ns, "sync_public_directory", False):
        argv.append("--sync-public-directory")
    if getattr(ns, "eligibility_db", None):
        argv.extend(["--eligibility-db", str(ns.eligibility_db)])
    if getattr(ns, "min_efficiency", None) is not None:
        argv.extend(["--min-efficiency", str(float(ns.min_efficiency))])
    if getattr(ns, "portfolio_capacity", None) is not None:
        argv.extend(["--portfolio-capacity", str(max(1, int(ns.portfolio_capacity)))])

    if ns.targets:
        for t in ns.targets:
            argv.extend(["--target", str(t)])
        argv.extend(["--program", str(ns.program)])
    else:
        argv.extend(["--clone-unlocked", "--max-repos", str(max(1, int(ns.max_repos)))])
        if not ns.watchlist:
            argv.append("--from-eligibility-db")

    for r in ns.repos or []:
        argv.extend(["--repo", str(r)])

    if ns.watchlist:
        argv.extend(["--watchlist", str(ns.watchlist)])
    if ns.model:
        argv.extend(["--model", str(ns.model)])
    if ns.out:
        argv.extend(["--out", str(ns.out)])
    if ns.embedded:
        argv.append("--embedded")
    if ns.no_llm:
        argv.append("--no-llm")
    if ns.allow_blocked:
        argv.append("--allow-blocked")
    if not ns.headless_only:
        argv.extend(["--stage-drafts", "--open-chrome"])
    if not ns.once and not ns.dry_run:
        argv.extend(["--watch", "--interval-minutes", str(float(ns.interval_minutes))])
    if ns.max_cycles and int(ns.max_cycles) > 0:
        argv.extend(["--max-cycles", str(int(ns.max_cycles))])
    if ns.dry_run:
        argv.append("--dry-run")
    if ns.json_out:
        argv.append("--json")
    return argv


def manage_os_schedule(ns: argparse.Namespace) -> int:
    """Installs or removes a native OS background schedule without touching Registry PATH."""
    task_name = str(ns.task_name or DEFAULT_TASK_NAME).strip()
    if os.name == "nt":
        if ns.uninstall_schedule:
            proc = subprocess.run(
                ["schtasks", "/Delete", "/TN", task_name, "/F"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if proc.returncode == 0:
                print(f"[OK] Removed Windows Scheduled Task '{task_name}'.")
            else:
                print(f"[INFO] Task '{task_name}' not removed: {(proc.stderr or proc.stdout).strip()}")
            return 0 if proc.returncode == 0 else 1

        interval = max(5, round(float(ns.interval_minutes)))
        run_flags = ["--hunt", "--once"]
        if ns.targets:
            for t in ns.targets:
                run_flags.extend(["--target", f'"{t}"'])
            run_flags.extend(["--program", str(ns.program)])
        if ns.headless_only:
            run_flags.append("--headless-only")
        if ns.embedded:
            run_flags.append("--embedded")
        task_cmd = f'"{sys.executable}" "{RFCHUNT_ROOT / "rfc_hunt_swarm.py"}" ' + " ".join(run_flags)

        create_cmd = [
            "schtasks",
            "/Create",
            "/F",
            "/SC",
            "MINUTE",
            "/MO",
            str(interval),
            "/TN",
            task_name,
            "/TR",
            task_cmd,
        ]
        if ns.dry_run:
            print(f"[DRY-RUN] Would run: {create_cmd}")
            return 0

        proc = subprocess.run(
            create_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if proc.returncode != 0:
            print(f"[ERROR] Failed to register schedule: {(proc.stderr or proc.stdout).strip()}", file=sys.stderr)
            return int(proc.returncode)
        print(f"[OK] Scheduled '{task_name}' every {interval} minutes -> {task_cmd}")
        if ns.run_now:
            subprocess.run(["schtasks", "/Run", "/TN", task_name], check=False)
            print(f"[OK] Triggered immediate run of '{task_name}'.")
        return 0

    # POSIX / Linux / macOS crontab line
    interval = max(5, round(float(ns.interval_minutes)))
    cron_line = (
        f"*/{interval} * * * * cd {RFCHUNT_ROOT} && "
        f"{sys.executable} {RFCHUNT_ROOT / 'rfc_hunt_swarm.py'} --hunt --once"
    )
    if ns.uninstall_schedule:
        print(f"[INFO] Remove this line from `crontab -e`:\n  {cron_line}")
    else:
        print(f"[INFO] Add this line to `crontab -e`:\n  {cron_line}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hunt.py",
        description="Turnkey pure-Python RFCHunt + ModelFusion autonomous hunter (lists ready URLs & opens Chrome for manual Submit).",
    )
    p.add_argument("--target", dest="targets", action="append", default=[], help="Local repo directory to audit (repeatable).")
    p.add_argument("--program", default="generic", help="HackerOne program handle (default: generic).")
    p.add_argument("--repo", dest="repos", action="append", default=[], help="Extra 'owner/repo' slug to include.")
    p.add_argument("--watchlist", default=None, help="Optional custom watchlist JSON path (omitting uses UNLOCKED ProgramEligibilityDB repos).")
    p.add_argument("--eligibility-db", default=None, help="Optional ProgramEligibilityDB SQLite path.")
    p.add_argument("--sync-public-directory", action="store_true", default=False, help="Refresh public HackerOne Program Directory sorted by newest launch date before ML ranking.")
    p.add_argument("--min-efficiency", type=float, default=80.0, help="Minimum HackerOne response efficiency %% (default: 80).")
    p.add_argument("--portfolio-capacity", type=int, default=6, help="Daily Two-Phase Knapsack portfolio capacity (default: 6).")
    p.add_argument("--max-repos", type=int, default=4, help="Max unlocked watchlist repos per cycle (default: 4).")
    p.add_argument("--interval-minutes", type=float, default=60.0, help="Minutes between cycles (default: 60).")
    p.add_argument("--max-cycles", type=int, default=0, help="Stop after N cycles (0 = run continuously).")
    p.add_argument("--once", action="store_true", default=False, help="Run one complete cycle and exit.")
    p.add_argument("--headless-only", action="store_true", default=False, help="Do not stage drafts or open Chrome; write READY_TO_CLICK_SUBMIT.md only.")
    p.add_argument("--model", default=None, help="Explicit abliterated Ollama model override.")
    p.add_argument("--out", default="out/autonomous_hunt", help="Output directory (default: out/autonomous_hunt).")
    p.add_argument("--embedded", action="store_true", default=False, help="Offline deterministic checks only.")
    p.add_argument("--no-llm", action="store_true", default=False, help="Disable Stage-3 LLM triage.")
    p.add_argument("--allow-blocked", action="store_true", default=False, help="Allow Signal-blocked programs for local research.")
    p.add_argument("--dry-run", action="store_true", default=False, help="Preview full execution plan with zero side effects.")
    p.add_argument("--json", dest="json_out", action="store_true", default=False, help="Print full JSON summary to stdout.")
    p.add_argument("--install-schedule", action="store_true", default=False, help="Install automatic background OS schedule (Windows Task Scheduler via schtasks).")
    p.add_argument("--uninstall-schedule", action="store_true", default=False, help="Remove the background OS scheduled task.")
    p.add_argument("--run-now", action="store_true", default=False, help="Trigger immediate run right after --install-schedule.")
    p.add_argument("--task-name", default=DEFAULT_TASK_NAME, help="Scheduled task name.")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)

    if ns.install_schedule or ns.uninstall_schedule:
        return manage_os_schedule(ns)

    if not ns.json_out:
        print("=" * 72)
        print(" RFCHunt + ModelFusion Autonomous Hunter (Pure Python, Draft-Only HITL)")
        print(" -> Auto-Submit: FORBIDDEN | CAPTCHA Bypass: FORBIDDEN")
        print(f" -> Ready URLs: {RFCHUNT_ROOT / ns.out / 'READY_TO_CLICK_SUBMIT.md'}")
        print("=" * 72)

    forwarded = build_hunt_argv(ns)
    return int(autonomous_hunt_main(forwarded))


if __name__ == "__main__":
    raise SystemExit(main())
