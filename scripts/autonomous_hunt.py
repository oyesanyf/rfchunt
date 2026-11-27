#!/usr/bin/env python3
"""
RFCHunt Standalone All-In-One Autonomous Defensive Hunting & Audit Runner
=========================================================================
Runs 100% independently from the CLI with ZERO `/browser` and ZERO cloud-LLM
dependencies (powered by ModelFusion + local abliterated Ollama models with
deterministic Anti-Junk & Grounding Guards).

Full Pipeline (Single Run or Scheduled Continuous Loop):
  Stage 0: Pre-flight & Safety Gate
           - <=400ms health probes for ModelFusion (:5000) & Ollama (:11434)
           - Process-scoped environment only (zero Registry / PATH mutation)
           - ProgramEligibilityDB gate (skips BLOCKED_SIGNAL / PAUSED programs)
           - Strict RoE safety invariants (read-only code auditing, no auto-submit,
             no browser launch, no CAPTCHA bypass)
  Stage 1: Freshness Watch (`revenue_cli.py freshness-watch`)
           - Polls in-scope GitHub repos for fresh <72h PRs/releases/commits
           - Optional shallow local mirror (`--clone-unlocked`) for watchlist repos
  Stage 2: Fast 3-Stage Parallel OODA Funnel (`revenue_cli.py fast-ooda`)
           - Async SQLite WAL Blackboard + ProcessPoolExecutor + ACDSO Pareto
             ranking + abliterated Stage-3 verification + Auto-PoC Gate
  Stage 3: Exhaustive Multi-Engine Audit (`revenue_cli.py ensemble-audit`)
           - `--all --ensemble --quorum 2` + SARIF 2.1.0 output
  Stage 4: Formal Verification & Safety Violation Checks
           - `revenue_cli.py lean-verify` (Lean 4 kernel proof audit)
           - Hard violation scanner across generated drafts & bundles:
             blocks unredacted secrets/keys, HTML entity corruption (`&lt;`),
             control characters, and ungrounded boilerplate
  Stage 5: Draft QA, Auto-Repair & Cooldown Check
           - `revenue_cli.py qa-drafts --strict` (verifies & auto-repairs drafts)
           - `revenue_cli.py check-drafts` (updates clickable ready-to-submit list)
  Stage 6: Summary Report + Optional Continuous Scheduling (`--watch`)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RFCHUNT_ROOT = Path(__file__).resolve().parent.parent
if str(RFCHUNT_ROOT) not in sys.path:
    sys.path.insert(0, str(RFCHUNT_ROOT))

import shutil
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed

from engine.hackerone_porter import (
    DEFAULT_BUG_HUNT_URL,
    HackerOneComputerUsePorter,
    HackerOnePorter,
    validate_bug_hunt_url,
    validate_hackerone_url,
)
from engine.program_eligibility_db import ProgramEligibilityDB

_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_HANDLE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")

# Safety & Hygiene Violation Patterns checked on every generated draft/artifact
_SECRET_LEAK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{24,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("openai_or_anthropic_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{24,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b")),
)
_HTML_ENTITY_LEAK_RE = re.compile(r"&(?:lt|gt|amp|quot);")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffd]")

# Operational Markdown files (queues, summaries, QA dashboards, PoC transcripts, client bundles)
# that are NOT HackerOne vulnerability report drafts and must be excluded from `qa-drafts`.
NON_DRAFT_MD_NAMES: frozenset[str] = frozenset(
    {
        "latest_summary.md",
        "drafts_ready_to_submit.md",
        "qa_draft_audit.md",
        "cycle_qa_audit.md",
        "ready_to_click_submit.md",
        "fresh_hunt_queue.md",
        "ensemble_audit_report.md",
        "ensemble_summary.md",
        "executive_summary.md",
        "01_executive_summary.md",
        "02_technical_findings.md",
        "poc_transcript.md",
        "remediation_roadmap.md",
        "validation_checklist.md",
        "readme.md",
    }
)
NON_DRAFT_MD_PREFIXES: tuple[str, ...] = (
    "fresh_hunt_queue",
    "poc_transcript",
    "cycle_qa_",
    "qa_draft_",
)
NON_DRAFT_PARENT_DIRS: frozenset[str] = frozenset(
    {
        "client_audit_bundle",
        "repos_cache",
        "h1_browser_profile",
        ".git",
    }
)
NON_DRAFT_HEADING_PREFIXES: tuple[str, ...] = (
    "# rfchunt daily fresh hunt queue",
    "# rfchunt autonomous hunt summary",
    "# rfchunt ensemble security audit summary",
    "# hackerone draft quality assurance",
    "# ready to review & click submit",
    "# security audit executive summary",
    "# technical security findings",
)


def is_non_draft_markdown(
    md_path: Path,
    markdown_text: str | None = None,
    *,
    base_dir: Path | None = None,
) -> bool:
    """
    Returns True when a Markdown file is an operational queue, cycle summary, QA report,
    client bundle document, or PoC transcript rather than a HackerOne vulnerability draft.
    Prevents Stage 5 `qa-drafts --strict` from flagging `fresh_hunt_queue.md` (and variants)
    for missing HackerOne report headings.
    """
    name_low = md_path.name.lower()
    if name_low in NON_DRAFT_MD_NAMES:
        return True
    if any(name_low.startswith(prefix) for prefix in NON_DRAFT_MD_PREFIXES):
        return True

    parent_parts: tuple[str, ...]
    if base_dir is not None:
        try:
            parent_parts = md_path.relative_to(base_dir).parts[:-1]
        except ValueError:
            parent_parts = md_path.parts[:-1]
    else:
        parent_parts = md_path.parts[:-1]
    if any(part.lower() in NON_DRAFT_PARENT_DIRS for part in parent_parts):
        return True

    if markdown_text is not None:
        for raw_line in markdown_text.splitlines():
            stripped = raw_line.strip().lower()
            if not stripped:
                continue
            if any(stripped.startswith(h) for h in NON_DRAFT_HEADING_PREFIXES):
                return True
            break
    return False


def utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def probe_http_fast(url: str, timeout_sec: float = 0.4) -> bool:
    """Strict <=400ms health probe so offline daemons never stall the hunter."""
    eff = min(max(float(timeout_sec), 0.05), 0.4)
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=eff) as resp:
            return 200 <= int(resp.status) < 500
    except Exception:  # noqa: BLE001
        return False


def discover_ollama_models(ollama_endpoint: str, timeout_sec: float = 0.4) -> list[str]:
    eff = min(max(float(timeout_sec), 0.05), 0.4)
    url = f"{ollama_endpoint.rstrip('/')}/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=eff) as resp:
            if int(resp.status) == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                return [
                    str(m.get("name"))
                    for m in (data.get("models") or [])
                    if isinstance(m, dict) and m.get("name")
                ]
    except Exception:  # noqa: BLE001, S110
        pass
    return []


def validate_repo_slug(slug: str) -> str:
    cleaned = str(slug or "").strip()
    if not _REPO_SLUG_RE.match(cleaned) or ".." in cleaned:
        raise ValueError(f"Invalid GitHub repository slug: {slug!r}")
    return cleaned


def validate_program_handle(handle: str) -> str:
    cleaned = str(handle or "").strip().lower()
    if not _HANDLE_RE.match(cleaned):
        raise ValueError(f"Invalid program handle: {handle!r}")
    return cleaned


def scan_draft_safety_violations(markdown_text: str) -> list[dict[str, str]]:
    """
    Audits a generated Markdown draft for hard safety & formatting violations:
      - Unredacted credentials / private keys
      - Corrupted HTML entities (`&lt;`, `&gt;`)
      - Illegal ASCII control characters / `U+FFFD` replacement glyphs
    """
    violations: list[dict[str, str]] = []
    text = markdown_text or ""

    for name, pat in _SECRET_LEAK_PATTERNS:
        if pat.search(text):
            violations.append(
                {
                    "code": f"SECRET_LEAK:{name}",
                    "severity": "CRITICAL",
                    "message": f"Potential unredacted secret ({name}) detected in draft.",
                }
            )

    if _HTML_ENTITY_LEAK_RE.search(text):
        violations.append(
            {
                "code": "HTML_ENTITY_CORRUPTION",
                "severity": "HIGH",
                "message": "Literal HTML entity (&lt;/&gt;/&amp;) detected; must be repaired before staging.",
            }
        )

    if _CONTROL_CHAR_RE.search(text):
        violations.append(
            {
                "code": "CONTROL_CHAR_OR_MOJIBAKE",
                "severity": "HIGH",
                "message": "Control character or U+FFFD replacement glyph detected in draft.",
            }
        )

    return violations


def build_process_env(
    *,
    modelfusion_endpoint: str,
    ollama_endpoint: str,
    use_modelfusion: bool,
    model_override: str | None = None,
    offline: bool = False,
) -> dict[str, str]:
    """Process-scoped environment only — never touches Windows Registry or user/system PATH."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["MODELFUSION_ENDPOINT"] = modelfusion_endpoint.rstrip("/")
    env["RFCHUNT_USE_MODELFUSION"] = "1" if use_modelfusion else "0"
    env["OLLAMA_ENDPOINT"] = ollama_endpoint.rstrip("/")
    env["LOCAL_OLLAMA_ENDPOINT"] = ollama_endpoint.rstrip("/")
    env["RFCHUNT_ENABLE_ANTI_JUNK_GUARD"] = "1"
    if offline:
        env["RFCHUNT_OFFLINE"] = "1"
    if model_override and model_override.strip():
        env["RFCHUNT_LLM_MODEL"] = model_override.strip()
        env["LOCAL_MODEL"] = model_override.strip()
    return env


def run_step(
    label: str,
    cmd: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_sec: float = 600.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Executes one CLI stage with `shell=False`, deterministic timeout, and structured telemetry."""
    started = time.monotonic()
    if dry_run:
        return {
            "label": label,
            "status": "dry_run_planned",
            "exit_code": 0,
            "duration_sec": 0.0,
            "command": list(cmd),
            "stdout_tail": "",
            "stderr_tail": "",
        }
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(5.0, float(timeout_sec)),
            check=False,
        )
        return {
            "label": label,
            "status": "ok" if proc.returncode == 0 else "failed",
            "exit_code": int(proc.returncode),
            "duration_sec": round(time.monotonic() - started, 2),
            "command": list(cmd),
            "stdout_tail": (proc.stdout or "")[-2000:],
            "stderr_tail": (proc.stderr or "")[-2000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "label": label,
            "status": "timeout",
            "exit_code": 124,
            "duration_sec": round(time.monotonic() - started, 2),
            "command": list(cmd),
            "stdout_tail": "",
            "stderr_tail": f"Timed out after {timeout_sec}s: {exc}",
        }
    except OSError as exc:
        return {
            "label": label,
            "status": "exec_error",
            "exit_code": 127,
            "duration_sec": round(time.monotonic() - started, 2),
            "command": list(cmd),
            "stdout_tail": "",
            "stderr_tail": str(exc),
        }


def sync_watchlist_repo(
    repo_slug: str,
    repos_cache_dir: Path,
    *,
    env: dict[str, str],
    dry_run: bool = False,
) -> tuple[Path | None, dict[str, Any]]:
    """Shallow-clones or fast-forward-pulls an in-scope GitHub repo using `shell=False`."""
    clean_slug = validate_repo_slug(repo_slug)
    safe_dir = repos_cache_dir / clean_slug.replace("/", "__")
    clone_url = f"https://github.com/{clean_slug}.git"

    if dry_run:
        return safe_dir, {
            "label": f"git_sync:{clean_slug}",
            "status": "dry_run_planned",
            "repo_dir": str(safe_dir),
            "exit_code": 0,
        }

    repos_cache_dir.mkdir(parents=True, exist_ok=True)
    if (safe_dir / ".git").is_dir():
        res = run_step(
            f"git_pull:{clean_slug}",
            ["git", "-C", str(safe_dir), "pull", "--ff-only", "--depth", "1"],
            cwd=RFCHUNT_ROOT,
            env=env,
            timeout_sec=120.0,
        )
    else:
        res = run_step(
            f"git_clone:{clean_slug}",
            ["git", "clone", "--depth", "1", clone_url, str(safe_dir)],
            cwd=RFCHUNT_ROOT,
            env=env,
            timeout_sec=180.0,
        )
    return (safe_dir if safe_dir.is_dir() else None), res


def load_watchlist_targets(watchlist_path: Path) -> list[dict[str, str]]:
    if not watchlist_path.is_file():
        return []
    try:
        data = json.loads(watchlist_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    out: list[dict[str, str]] = []
    for item in data.get("targets") or []:
        if not isinstance(item, dict):
            continue
        repo = str(item.get("repo") or "").strip()
        prog = str(item.get("program") or "generic").strip().lower()
        if repo and _REPO_SLUG_RE.match(repo):
            out.append({"program": prog, "repo": repo})
    return out


def check_program_eligibility(
    program_handle: str,
    *,
    eligibility_db_path: str | None = None,
    allow_blocked: bool = False,
) -> tuple[bool, str]:
    """
    Fail-safe Program Eligibility & Signal Gate:
      - If a program is recorded as `BLOCKED_SIGNAL`, `PAUSED`, or `NOT_FOUND`,
        skip it unless `--allow-blocked` is explicitly set.
      - Unknown / `generic` programs are allowed for local white-box auditing.
    """
    handle = str(program_handle or "generic").strip().lower()
    if handle == "generic" or allow_blocked:
        return True, "allowed"
    try:
        db = ProgramEligibilityDB(db_path=eligibility_db_path)
        rec = db.get(handle)
        if rec is None:
            return True, "untracked_default_allowed"
        status = str(getattr(rec, "status", "UNLOCKED")).upper()
        if status == "UNLOCKED":
            return True, "unlocked"
        return False, f"blocked_by_eligibility_db:{status}"
    except Exception as exc:  # noqa: BLE001
        return True, f"eligibility_db_unavailable:{exc}"


def extract_verified_findings_from_cycle(target_out_dir: Path) -> list[dict[str, Any]]:
    """
    Collects verified, PoC-backed or corroborated findings from `fast_ooda_report.json`,
    `READY_TO_SUBMIT.json`, and `ensemble_audit` JSON outputs inside `target_out_dir`.
    Strictly drops speculative/unverified items so only high-signal findings reach draft staging.
    """
    collected: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    def _add_candidate(item: dict[str, Any]) -> None:
        if not isinstance(item, dict):
            return
        disp = str(item.get("disposition") or "").upper()
        lane = str(item.get("evidence_lane") or "").upper()
        poc_ok = bool(item.get("poc_verified", False))
        confirmed = bool(item.get("confirmed", False))
        poe_lvl = int(item.get("poe_level", 0) or 0)
        if not (poc_ok or confirmed or disp in ("CONFIRMED", "LIKELY_VALID") or lane in ("LANE_1_POC", "LANE_2_CORROBORATED") or poe_lvl >= 2):
            return
        fp = str(item.get("file_path") or item.get("file") or "")
        ln = int(item.get("line") or 1)
        rid = str(item.get("rule_id") or item.get("cwe") or item.get("title") or "finding")
        dedup_k = f"{fp}:{ln}:{rid}".lower()
        if dedup_k in seen_keys:
            return
        seen_keys.add(dedup_k)
        # Normalize shape for HackerOnePorter.port_findings
        norm = dict(item)
        norm.setdefault("file_path", fp)
        norm.setdefault("line", ln)
        norm.setdefault("rule_id", rid)
        norm.setdefault("severity", str(item.get("severity") or "MEDIUM").upper())
        if poc_ok and not norm.get("evidence_lane"):
            norm["evidence_lane"] = "LANE_1_POC"
            norm["poe_level"] = max(poe_lvl, 3)
        elif not norm.get("evidence_lane"):
            norm["evidence_lane"] = "LANE_2_CORROBORATED"
            norm["poe_level"] = max(poe_lvl, 2)
        collected.append(norm)

    if not target_out_dir.is_dir():
        return collected

    for json_path in sorted(target_out_dir.rglob("*.json")):
        if json_path.name in ("summary.json", "latest_summary.json", "submission_ledger.json"):
            continue
        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:  # noqa: BLE001, S112
            continue
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    _add_candidate(entry)
        elif isinstance(data, dict):
            for key in ("ready_findings", "verified_findings", "findings", "clusters", "staged_submissions"):
                arr = data.get(key)
                if isinstance(arr, list):
                    for entry in arr:
                        if isinstance(entry, dict):
                            _add_candidate(entry)
            if data.get("poc_verified") or data.get("disposition") in ("CONFIRMED", "LIKELY_VALID"):
                _add_candidate(data)
    return collected


def find_chrome_executable() -> str | None:
    """Locates Google Chrome (`chrome.exe`) across standard Windows/Linux/macOS install paths."""
    candidates: list[str] = []
    if os.name == "nt":
        for base in (
            os.environ.get("PROGRAMFILES", r"C:\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", ""),
        ):
            if base:
                candidates.append(str(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe"))
        for name in ("chrome.exe", "chrome"):
            found = shutil.which(name)
            if found:
                candidates.append(found)
    else:
        for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
            found = shutil.which(name)
            if found:
                candidates.append(found)
        mac_chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        if Path(mac_chrome).is_file():
            candidates.append(mac_chrome)

    for cand in candidates:
        if cand and Path(cand).is_file():
            return str(Path(cand))
    return None


def open_urls_in_chrome(urls: Sequence[str], *, dry_run: bool = False) -> dict[str, Any]:
    """
    Validates every URL strictly against `https://hackerone.com/...` and opens them
    in Google Chrome (`shell=False`) so the user can review and manually click Submit.
    """
    validated: list[str] = []
    seen: set[str] = set()
    for raw in urls:
        clean = validate_hackerone_url(str(raw or "").strip())
        if clean not in seen:
            seen.add(clean)
            validated.append(clean)

    chrome_exe = find_chrome_executable()
    if not validated:
        return {"status": "skipped_no_urls", "chrome_exe": chrome_exe, "opened_urls": []}
    if dry_run:
        return {"status": "dry_run_chrome_planned", "chrome_exe": chrome_exe, "opened_urls": validated}

    if chrome_exe:
        try:
            subprocess.Popen(
                [chrome_exe, "--new-tab", *validated],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return {"status": "opened_in_chrome", "chrome_exe": chrome_exe, "opened_urls": validated}
        except OSError:
            pass

    for u in validated:
        webbrowser.open_new_tab(u)
    return {"status": "opened_in_default_browser", "chrome_exe": chrome_exe, "opened_urls": validated}


def maybe_start_modelfusion_server(
    cli_path: Path,
    db_path: Path,
    port: int,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Optionally starts ModelFusion's local HTTP server (`--server --port 5000`) detached."""
    endpoint = f"http://127.0.0.1:{port}"
    if probe_http_fast(f"{endpoint}/health") or probe_http_fast(f"{endpoint}/api/health"):
        return {"started": False, "reachable": True, "endpoint": endpoint, "note": "already_running"}
    if dry_run:
        return {"started": False, "reachable": False, "endpoint": endpoint, "note": "dry_run_skipped"}
    if not cli_path.is_file():
        return {"started": False, "reachable": False, "endpoint": endpoint, "note": f"cli_not_found:{cli_path}"}

    cmd = [str(cli_path), "--server", "--port", str(port)]
    if db_path.is_file():
        cmd.extend(["--db-path", str(db_path)])

    creationflags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW on Windows
    try:
        subprocess.Popen(
            cmd,
            cwd=str(cli_path.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
    except OSError as exc:
        return {"started": False, "reachable": False, "endpoint": endpoint, "note": f"spawn_failed:{exc}"}

    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        if probe_http_fast(f"{endpoint}/health") or probe_http_fast(f"{endpoint}/api/health"):
            return {"started": True, "reachable": True, "endpoint": endpoint, "note": "started_and_healthy"}
        time.sleep(0.4)
    return {"started": True, "reachable": False, "endpoint": endpoint, "note": "spawned_warming_up"}


def execute_hunt_cycle(args: argparse.Namespace, cycle_num: int) -> dict[str, Any]:
    """Executes one complete end-to-end defensive hunting + violation + QA cycle."""
    cycle_started = utc_now_iso()
    out_root = Path(args.out).resolve()
    cycle_id = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    cycle_dir = out_root / f"cycle_{cycle_id}_n{cycle_num}"
    if not args.dry_run:
        cycle_dir.mkdir(parents=True, exist_ok=True)

    # Stage 0: Fast <=400ms Pre-Flight Probes
    mf_endpoint = args.modelfusion_endpoint.rstrip("/")
    ollama_endpoint = args.ollama_endpoint.rstrip("/")
    mf_start_info: dict[str, Any] = {"started": False, "reachable": False, "endpoint": mf_endpoint}
    if args.start_modelfusion and not args.embedded:
        mf_start_info = maybe_start_modelfusion_server(
            Path(args.modelfusion_cli),
            Path(args.modelfusion_db),
            args.modelfusion_port,
            dry_run=args.dry_run,
        )

    mf_reachable = (
        False
        if args.embedded or args.dry_run
        else (
            bool(mf_start_info.get("reachable"))
            or probe_http_fast(f"{mf_endpoint}/health")
            or probe_http_fast(f"{mf_endpoint}/api/health")
        )
    )
    ollama_tags = [] if (args.embedded or args.dry_run) else discover_ollama_models(ollama_endpoint)
    abliterated_tags = [
        t for t in ollama_tags
        if any(k in t.lower() for k in ("abliterat", "obliterat", "foundation-sec"))
    ]

    env = build_process_env(
        modelfusion_endpoint=mf_endpoint,
        ollama_endpoint=ollama_endpoint,
        use_modelfusion=mf_reachable and not args.no_modelfusion,
        model_override=args.model,
        offline=args.embedded,
    )

    steps: list[dict[str, Any]] = []
    targets_to_audit: list[tuple[str, Path]] = []

    # Stage 0A: Interactive Browser Hunt Session (opens --hunt-url, waits for human login/2FA/CAPTCHA,
    # syncs inbox/cooldown `can_submit_draft?`/Signal, discovers unlocked programs & GitHub repos)
    raw_hunt_url = str(getattr(args, "hunt_url", None) or DEFAULT_BUG_HUNT_URL).strip()
    browser_hunt_active = (
        bool(getattr(args, "browser_hunt", False))
        and not bool(getattr(args, "no_browser_hunt", False))
        and not args.embedded
    )
    if browser_hunt_active or raw_hunt_url != DEFAULT_BUG_HUNT_URL:
        # Fail closed on untrusted/non-bounty URLs even in --dry-run
        validate_bug_hunt_url(raw_hunt_url)

    browser_hunt_session: dict[str, Any] = {
        "status": "disabled",
        "browser_launched": False,
        "hunt_url": raw_hunt_url,
        "auto_submit_forbidden": True,
        "captcha_bypass_forbidden": True,
        "final_submit_blocked_for_hitl": True,
        "discovered_repos": [],
        "unlocked_programs": [],
    }
    if browser_hunt_active:
        browser_hunt_session = HackerOneComputerUsePorter().run_interactive_browser_hunt_session(
            hunt_url=raw_hunt_url,
            cdp_url=getattr(args, "cdp_url", None),
            profile_dir=getattr(args, "browser_profile", None),
            login_timeout_sec=float(getattr(args, "login_timeout", 300.0) or 300.0),
            max_programs=max(4, int(getattr(args, "portfolio_capacity", 6) or 6) * 2),
            probe_report_id=int(getattr(args, "probe_report_id", 4243972) or 4243972),
            eligibility_db_path=args.eligibility_db,
            draft_tracker_db_path=(out_root / "draft_submit_tracker.sqlite3" if not args.dry_run else None),
            dry_run=args.dry_run,
        )
        b_status = str(browser_hunt_session.get("status") or "")
        steps.append(
            {
                "label": "stage0_interactive_browser_hunt",
                "status": "dry_run_planned"
                if args.dry_run
                else (
                    "ok"
                    if b_status
                    in (
                        "browser_hunt_session_completed",
                        "playwright_not_installed_manual_ready",
                        "login_timeout_hitl_required",
                    )
                    else "error"
                ),
                "exit_code": 0,
                "hunt_url": browser_hunt_session.get("hunt_url", raw_hunt_url),
                "browser_status": b_status,
                "discovered_repos_count": int(browser_hunt_session.get("discovered_repos_count") or 0),
                "unlocked_programs_count": int(browser_hunt_session.get("unlocked_programs_count") or 0),
            }
        )
        live_sig = browser_hunt_session.get("signal_score")
        if live_sig is not None and not isinstance(live_sig, bool):
            try:
                args.signal_score = float(live_sig)
            except (TypeError, ValueError):
                pass

    # Stage 0.2: Optional Public HackerOne Program Directory Sync (newest launches, >=min_efficiency%)
    if getattr(args, "sync_public_directory", False) and not args.embedded:
        sync_cmd = [
            sys.executable,
            str(RFCHUNT_ROOT / "rfc_hunt_swarm.py"),
            "sync-directory",
            "--public-directory",
            "--min-efficiency",
            str(getattr(args, "min_efficiency", 80.0)),
            "--limit",
            "25",
            "--json",
        ]
        if args.eligibility_db:
            sync_cmd.extend(["--db", args.eligibility_db])
        steps.append(
            run_step(
                "stage0_sync_public_directory",
                sync_cmd,
                cwd=RFCHUNT_ROOT,
                env=env,
                timeout_sec=120.0,
                dry_run=args.dry_run,
            )
        )

    # Stage 0.5: ACDSO-Adapted ML Public HackerOne Program Selection & Two-Lane Portfolio
    ml_program_selection: dict[str, Any] = {"status": "skipped"}
    if not getattr(args, "skip_ml_ranking", False):
        if args.dry_run:
            rank_cmd = [
                sys.executable,
                str(RFCHUNT_ROOT / "rfc_hunt_swarm.py"),
                "rank-programs",
                "--min-efficiency",
                str(getattr(args, "min_efficiency", 80.0)),
                "--capacity",
                str(max(1, int(getattr(args, "portfolio_capacity", 6)))),
                "--json",
            ]
            if args.eligibility_db:
                rank_cmd.extend(["--db", args.eligibility_db])
            steps.append(
                run_step(
                    "stage0_ml_program_ranking",
                    rank_cmd,
                    cwd=RFCHUNT_ROOT,
                    env=env,
                    timeout_sec=60.0,
                    dry_run=True,
                )
            )
            ml_program_selection = {"status": "dry_run_planned", "min_efficiency_pct": float(getattr(args, "min_efficiency", 80.0))}
        else:
            try:
                from engine.ml_program_selector import rank_hackerone_programs

                ml_program_selection = rank_hackerone_programs(
                    db_path=args.eligibility_db,
                    min_efficiency_pct=float(getattr(args, "min_efficiency", 80.0)),
                    capacity=max(1, int(getattr(args, "portfolio_capacity", 6))),
                )
            except Exception as exc:  # noqa: BLE001
                ml_program_selection = {"status": "error", "error": str(exc)}

    # Collect explicit local targets (`--target PATH[:PROGRAM]`)
    for raw_t in args.targets or []:
        t_path = Path(raw_t).resolve()
        prog = validate_program_handle(args.program)
        targets_to_audit.append((prog, t_path))

    # Stage 1: Freshness Watch across watchlist (or dynamically from UNLOCKED Eligibility DB)
    watchlist_path = Path(args.watchlist)
    if not watchlist_path.is_absolute():
        watchlist_path = (RFCHUNT_ROOT / watchlist_path).resolve()

    if not args.skip_freshness and not args.embedded:
        fresh_cmd = [
            sys.executable,
            str(RFCHUNT_ROOT / "rfc_hunt_swarm.py"),
            "freshness-watch",
            "--hours",
            str(args.freshness_hours),
            "--min-score",
            str(args.min_score),
            "--out",
            str(cycle_dir / "fresh_hunt_queue"),
            "--ml-rank",
        ]
        if getattr(args, "from_eligibility_db", False):
            fresh_cmd.extend(
                [
                    "--from-eligibility-db",
                    "--min-efficiency",
                    str(getattr(args, "min_efficiency", 80.0)),
                ]
            )
            if args.eligibility_db:
                fresh_cmd.extend(["--eligibility-db", args.eligibility_db])
        else:
            fresh_cmd.extend(["--watchlist", str(watchlist_path)])
        for r in args.repos or []:
            fresh_cmd.extend(["--repo", validate_repo_slug(r)])
        if args.mark_seen:
            fresh_cmd.append("--mark-seen")
        steps.append(
            run_step(
                "stage1_freshness_watch",
                fresh_cmd,
                cwd=RFCHUNT_ROOT,
                env=env,
                timeout_sec=180.0,
                dry_run=args.dry_run,
            )
        )

    # Shallow-clone explicit `--repo owner/repo` slugs, browser-discovered unlocked repos,
    # and (when `--clone-unlocked`) unlocked watchlist repos
    explicit_repo_items = [
        {"program": validate_program_handle(args.program), "repo": validate_repo_slug(r)}
        for r in (args.repos or [])
    ]
    for disc in browser_hunt_session.get("discovered_repos") or []:
        if not isinstance(disc, dict):
            continue
        d_repo = str(disc.get("repo") or "").strip()
        d_prog = str(disc.get("program") or args.program or "generic").strip()
        if not d_repo:
            continue
        try:
            explicit_repo_items.append(
                {"program": validate_program_handle(d_prog), "repo": validate_repo_slug(d_repo)}
            )
        except ValueError:
            continue
    if (args.clone_unlocked or explicit_repo_items) and not args.embedded:
        repos_cache = out_root / "repos_cache"
        wl_items: list[dict[str, str]] = []
        if args.clone_unlocked:
            if getattr(args, "from_eligibility_db", False) and (
                not args.dry_run
                or args.eligibility_db is None
                or Path(args.eligibility_db).exists()
            ):
                from engine.ml_diff_and_recon_ranker import (
                    build_unlocked_watchlist_from_db,
                )

                wl_items = [
                    {"program": t["program"], "repo": t["repo"]}
                    for t in build_unlocked_watchlist_from_db(
                        db_path=args.eligibility_db,
                        min_efficiency_pct=float(getattr(args, "min_efficiency", 80.0)),
                    )
                ]
            else:
                wl_items = load_watchlist_targets(watchlist_path)

        # Prioritize explicit `--repo owner/repo` slugs first so they are never truncated by max_repos
        seen_slugs: set[str] = set()
        combined_clone_items: list[dict[str, str]] = []
        for item in explicit_repo_items:
            slug_low = item["repo"].lower()
            if slug_low not in seen_slugs:
                seen_slugs.add(slug_low)
                combined_clone_items.append(item)
        wl_budget = max(1, int(args.max_repos))
        wl_added = 0
        for item in wl_items:
            if wl_added >= wl_budget:
                break
            slug_low = item["repo"].lower()
            if slug_low not in seen_slugs:
                seen_slugs.add(slug_low)
                combined_clone_items.append(item)
                wl_added += 1

        seen_target_paths = {t_path.resolve() for _, t_path in targets_to_audit}
        for item in combined_clone_items:
            eligible, reason = check_program_eligibility(
                item["program"],
                eligibility_db_path=args.eligibility_db,
                allow_blocked=args.allow_blocked,
            )
            if not eligible:
                steps.append(
                    {
                        "label": f"eligibility_skip:{item['program']}:{item['repo']}",
                        "status": "skipped_ineligible",
                        "exit_code": 0,
                        "reason": reason,
                    }
                )
                continue
            repo_dir, sync_res = sync_watchlist_repo(item["repo"], repos_cache, env=env, dry_run=args.dry_run)
            steps.append(sync_res)
            if repo_dir is not None and repo_dir.resolve() not in seen_target_paths:
                seen_target_paths.add(repo_dir.resolve())
                targets_to_audit.append((item["program"], repo_dir))

    # Stage 2 & Stage 3: Fast 3-Stage OODA + Exhaustive Multi-Engine Ensemble Audit per eligible target
    per_target_results: list[dict[str, Any]] = []
    blackboard_db = str(Path(args.blackboard_db).resolve()) if args.blackboard_db else str(out_root / "blackboard.sqlite3")
    swarm_enabled = bool(getattr(args, "swarm", False))
    raw_sw = getattr(args, "swarm_workers", None)
    eff_swarm_workers = (
        max(1, min(8, int(raw_sw)))
        if raw_sw is not None
        else min(4, max(2, (os.cpu_count() or 2) // 2))
    )

    def _audit_single_target(idx: int, prog: str, target_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        local_steps: list[dict[str, Any]] = []
        eligible, elig_reason = check_program_eligibility(
            prog,
            eligibility_db_path=args.eligibility_db,
            allow_blocked=args.allow_blocked,
        )
        if not eligible:
            return local_steps, {
                "program": prog,
                "target": str(target_dir),
                "status": "skipped_ineligible",
                "reason": elig_reason,
            }

        t_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{idx}_{prog}_{target_dir.name}")[:64]
        t_out = cycle_dir / t_slug

        # Stage 2: Fast 3-Stage OODA Funnel (Loop 3 + Loop 4 Auto-PoC Gate)
        ooda_cmd = [
            sys.executable,
            str(RFCHUNT_ROOT / "rfc_hunt_swarm.py"),
            "fast-ooda",
            "--target",
            str(target_dir),
            "--program",
            prog,
            "--blackboard-db",
            blackboard_db,
            "--resume",
            "--signal-score",
            str(args.signal_score),
            "--out",
            str(t_out / "fast_ooda"),
            "--json",
        ]
        if args.cpu_workers:
            ooda_cmd.extend(["--cpu-workers", str(args.cpu_workers)])
        if args.eligibility_db:
            ooda_cmd.extend(["--eligibility-db", args.eligibility_db])
        if args.embedded:
            ooda_cmd.append("--embedded")
        if args.no_llm:
            ooda_cmd.append("--no-llm")
        if args.model:
            ooda_cmd.extend(["--model", args.model])

        ooda_res = run_step(
            f"stage2_fast_ooda:{t_slug}",
            ooda_cmd,
            cwd=RFCHUNT_ROOT,
            env=env,
            timeout_sec=args.step_timeout_sec,
            dry_run=args.dry_run,
        )
        local_steps.append(ooda_res)

        # Stage 3: Exhaustive Multi-Engine Violation & Security Audit (`--all --ensemble` + SARIF)
        ens_res: dict[str, Any] | None = None
        if not args.skip_ensemble:
            sarif_path = t_out / "ensemble_audit" / "results.sarif"
            ens_cmd = [
                sys.executable,
                str(RFCHUNT_ROOT / "rfc_hunt_swarm.py"),
                "ensemble-audit",
                "--target",
                str(target_dir),
                "--program",
                prog,
                "--all",
                "--ensemble",
                "--quorum",
                str(args.quorum),
                "--freshness-hours",
                str(args.freshness_hours),
                "--blackboard-db",
                blackboard_db,
                "--resume",
                "--out",
                str(t_out / "ensemble_audit"),
                "--sarif-out",
                str(sarif_path),
                "--json",
            ]
            if args.cpu_workers:
                ens_cmd.extend(["--cpu-workers", str(args.cpu_workers)])
            if args.embedded:
                ens_cmd.append("--embedded")
            if args.no_llm:
                ens_cmd.append("--no-llm")
            if args.no_external_scanners:
                ens_cmd.append("--no-external-scanners")
            if args.model:
                ens_cmd.extend(["--model", args.model])

            ens_res = run_step(
                f"stage3_ensemble_audit:{t_slug}",
                ens_cmd,
                cwd=RFCHUNT_ROOT,
                env=env,
                timeout_sec=args.step_timeout_sec,
                dry_run=args.dry_run,
            )
            local_steps.append(ens_res)

        t_res: dict[str, Any] = {
            "program": prog,
            "target": str(target_dir),
            "eligibility": elig_reason,
            "fast_ooda_status": ooda_res["status"],
            "ensemble_audit_status": ens_res["status"] if ens_res else "skipped",
            "output_dir": str(t_out),
            "swarm_parallel": swarm_enabled,
        }

        # Stage 3.5: Auto-Port verified findings into QA-checked, secret/PHI-redacted HackerOne drafts
        if not args.dry_run:
            verified_findings = extract_verified_findings_from_cycle(t_out)
            if verified_findings:
                porter = HackerOnePorter(output_dir=str(t_out / "hackerone_drafts"), workspace_root=RFCHUNT_ROOT)
                port_res = porter.port_findings(
                    verified_findings,
                    program_handle=prog,
                    use_api=False,
                    use_browser=False,
                    submit_api=False,
                    dry_run=False,
                    enforce_eligibility=(not args.allow_blocked and prog != "generic"),
                )
                t_res["ported_drafts_count"] = int(port_res.get("eligible_drafts_count") or 0)
                t_res["ported_drafts"] = list(port_res.get("drafts") or [])

        return local_steps, t_res

    if swarm_enabled and len(targets_to_audit) > 1 and not args.dry_run:
        indexed_out: dict[int, tuple[list[dict[str, Any]], dict[str, Any]]] = {}
        max_w = min(eff_swarm_workers, len(targets_to_audit))
        with ThreadPoolExecutor(max_workers=max_w) as pool:
            futs = {
                pool.submit(_audit_single_target, idx, prog, target_dir): idx
                for idx, (prog, target_dir) in enumerate(targets_to_audit, start=1)
            }
            for fut in as_completed(futs):
                orig_idx = futs[fut]
                indexed_out[orig_idx] = fut.result()
        for orig_idx in sorted(indexed_out):
            l_steps, t_res = indexed_out[orig_idx]
            steps.extend(l_steps)
            per_target_results.append(t_res)
    else:
        for idx, (prog, target_dir) in enumerate(targets_to_audit, start=1):
            l_steps, t_res = _audit_single_target(idx, prog, target_dir)
            steps.extend(l_steps)
            per_target_results.append(t_res)

    # Stage 4: Lean 4 Formal Proof Kernel Verification
    if not args.skip_lean:
        lean_cmd = [sys.executable, str(RFCHUNT_ROOT / "rfc_hunt_swarm.py"), "lean-verify"]
        steps.append(
            run_step(
                "stage4_lean_verify",
                lean_cmd,
                cwd=RFCHUNT_ROOT,
                env=env,
                timeout_sec=180.0,
                dry_run=args.dry_run,
            )
        )

    # Stage 5: Hard Safety Violation Check + Strict QA Audit (`qa-drafts --strict`) + Optional Draft-Only Staging
    draft_violations: list[dict[str, Any]] = []
    ready_to_click_submit: list[dict[str, Any]] = []
    staged_browser_drafts: list[dict[str, Any]] = []

    draft_dirs = [cycle_dir, RFCHUNT_ROOT / "reports" / "hackerone"]
    program_by_draft_path: dict[str, str] = {}
    for tr in per_target_results:
        prog_h = str(tr.get("program") or "").strip()
        for d_item in tr.get("ported_drafts") or []:
            if isinstance(d_item, dict):
                mp = str(d_item.get("markdown_path") or "").strip()
                if mp and not mp.startswith("[dry-run]") and prog_h:
                    program_by_draft_path[str(Path(mp).resolve())] = prog_h

    seen_md: set[Path] = set()
    qa_status_by_path: dict[str, str] = {}
    for d_root in draft_dirs:
        if not d_root.is_dir():
            continue
        for md_path in sorted(d_root.rglob("*.md")):
            if is_non_draft_markdown(md_path, base_dir=d_root):
                continue
            if md_path in seen_md:
                continue
            seen_md.add(md_path)
            if args.dry_run:
                continue
            try:
                md_text = md_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if is_non_draft_markdown(md_path, md_text, base_dir=d_root):
                continue
            v_list = scan_draft_safety_violations(md_text)
            if v_list:
                draft_violations.append({"file": str(md_path), "violations": v_list})

            qa_passed = len(v_list) == 0
            if not args.skip_qa_drafts:
                eff_prog = validate_program_handle(
                    program_by_draft_path.get(str(md_path.resolve()), args.program)
                )
                qa_cmd = [
                    sys.executable,
                    str(RFCHUNT_ROOT / "rfc_hunt_swarm.py"),
                    "qa-drafts",
                    "--markdown-file",
                    str(md_path),
                    "--program",
                    eff_prog,
                    "--db",
                    str(cycle_dir / "cycle_qa_tracker.sqlite3"),
                    "--submit-db",
                    "",
                    "--out-md",
                    str(cycle_dir / "cycle_qa_audit.md"),
                    "--out-edit-queue",
                    str(cycle_dir / "cycle_qa_edit_queue.json"),
                    "--write-repaired",
                    str(md_path),
                    "--strict",
                ]
                if args.embedded:
                    qa_cmd.append("--no-verify-sources")
                qa_step = run_step(
                    f"stage5_qa_draft:{md_path.name}",
                    qa_cmd,
                    cwd=RFCHUNT_ROOT,
                    env=env,
                    timeout_sec=60.0,
                    dry_run=args.dry_run,
                )
                steps.append(qa_step)
                # Re-scan after auto-repair so repaired HTML entities are cleared
                try:
                    repaired_text = md_path.read_text(encoding="utf-8", errors="replace")
                    v_after = scan_draft_safety_violations(repaired_text)
                except OSError:
                    v_after = v_list
                qa_passed = (qa_step["exit_code"] == 0) and (len(v_after) == 0)
            qa_status_by_path[str(md_path.resolve())] = "PASS" if qa_passed else "FAIL"

    # Stage 5C: Stage ONLY zero-violation, QA-PASS ported drafts ready for the human's final Submit click
    browser_stager = HackerOneComputerUsePorter()
    for tr in per_target_results:
        prog_handle = str(tr.get("program") or "generic")
        for d_item in tr.get("ported_drafts") or []:
            if not isinstance(d_item, dict):
                continue
            md_p = str(d_item.get("markdown_path") or "")
            resolved_md = str(Path(md_p).resolve()) if md_p and not md_p.startswith("[dry-run]") else ""
            if resolved_md and qa_status_by_path.get(resolved_md) == "FAIL":
                continue
            entry = {
                "program": prog_handle,
                "draft_id": str(d_item.get("draft_id") or ""),
                "title": str(d_item.get("title") or ""),
                "severity": str(d_item.get("severity_rating") or "medium"),
                "submit_url": str(d_item.get("submit_url") or f"https://hackerone.com/{prog_handle}/reports/new"),
                "draft_url": str(d_item.get("submit_url") or f"https://hackerone.com/{prog_handle}/reports/new"),
                "markdown_path": md_p,
                "qa_status": qa_status_by_path.get(resolved_md, "PASS"),
                "auto_submitted": False,
            }
            if args.stage_drafts and prog_handle != "generic":
                porter = HackerOnePorter(output_dir=str(cycle_dir / "hackerone_drafts"), workspace_root=RFCHUNT_ROOT)
                camp, _ = porter.resolve_campaign(program_handle=prog_handle, dry_run=args.dry_run)
                from engine.hackerone_porter import HackerOneReportDraft

                draft_obj = HackerOneReportDraft(
                    draft_id=entry["draft_id"],
                    fingerprint=str(d_item.get("fingerprint") or ""),
                    program_handle=prog_handle,
                    submit_url=entry["submit_url"],
                    title=entry["title"],
                    weakness_cwe=str(d_item.get("weakness_cwe") or "CWE-20"),
                    severity_rating=entry["severity"],
                    asset_identifier=str(d_item.get("asset_identifier") or ""),
                    evidence_lane=str(d_item.get("evidence_lane") or "LANE_1_POC"),
                    poe_level=int(d_item.get("poe_level") or 2),
                    vulnerability_information=str(d_item.get("vulnerability_information") or ""),
                    impact=str(d_item.get("impact") or ""),
                    source_rule_id=str(d_item.get("source_rule_id") or ""),
                    source_scanner=str(d_item.get("source_scanner") or ""),
                    scope_match_status=str(d_item.get("scope_match_status") or "in_scope"),
                    markdown_path=md_p,
                )
                stage_res = browser_stager.stage_draft_ready_to_submit(
                    camp,
                    draft_obj,
                    cdp_url=args.cdp_url,
                    profile_dir=args.browser_profile,
                    dry_run=args.dry_run,
                )
                staged_browser_drafts.append(stage_res)
                entry["draft_url"] = str(stage_res.get("draft_url") or entry["submit_url"])
                entry["stage_status"] = str(stage_res.get("status") or "")
            ready_to_click_submit.append(entry)

    # Stage 5B: Headless Cooldown / Draft Submission Readiness Check (`check-drafts`)
    if not args.skip_check_drafts:
        chk_cmd = [
            sys.executable,
            str(RFCHUNT_ROOT / "rfc_hunt_swarm.py"),
            "check-drafts",
            "--out-md",
            str(out_root / "drafts_ready_to_submit.md"),
        ]
        if args.embedded or not os.environ.get("HACKERONE_SESSION_COOKIE"):
            chk_cmd.append("--seed-only")
        steps.append(
            run_step(
                "stage5_check_drafts",
                chk_cmd,
                cwd=RFCHUNT_ROOT,
                env=env,
                timeout_sec=60.0,
                dry_run=args.dry_run,
            )
        )

    # Stage 5D: Open every verified ready-to-submit HackerOne URL in Google Chrome for manual Submit click
    urls_to_submit: list[str] = [
        str(item["draft_url"])
        for item in ready_to_click_submit
        if str(item.get("draft_url") or "").startswith("https://hackerone.com/")
    ]
    chrome_launch: dict[str, Any] = {"status": "disabled", "opened_urls": []}
    if args.open_chrome and urls_to_submit:
        chrome_launch = open_urls_in_chrome(urls_to_submit, dry_run=args.dry_run)

    critical_violations = [
        v for item in draft_violations for v in item["violations"] if v.get("severity") == "CRITICAL"
    ]
    failed_steps = [s["label"] for s in steps if s.get("status") not in ("ok", "dry_run_planned", "skipped_ineligible")]

    summary: dict[str, Any] = {
        "schema": "rfchunt.autonomous_hunt_cycle.v1",
        "cycle_number": cycle_num,
        "started_utc": cycle_started,
        "finished_utc": utc_now_iso(),
        "dry_run": bool(args.dry_run),
        "browser_used": bool(staged_browser_drafts) or bool(browser_hunt_session.get("browser_launched")),
        "browser_hunt_enabled": bool(browser_hunt_active),
        "browser_hunt_session": browser_hunt_session,
        "swarm_enabled": swarm_enabled,
        "swarm_workers": eff_swarm_workers,
        "auto_submit_forbidden": True,
        "captcha_bypass_forbidden": True,
        "anti_junk_guard_enabled": True,
        "modelfusion_endpoint": mf_endpoint,
        "modelfusion_reachable": mf_reachable,
        "ollama_endpoint": ollama_endpoint,
        "ollama_models_count": len(ollama_tags),
        "installed_abliterated_models": abliterated_tags,
        "ml_program_selection": {
            "pareto_knee_winner": ml_program_selection.get("pareto_knee_winner"),
            "preset": ml_program_selection.get("preset"),
            "ranked_count": len(ml_program_selection.get("ranked_programs") or []),
            "daily_hunt_portfolio": ml_program_selection.get("daily_hunt_portfolio"),
            "ai_in_scope_programs": ml_program_selection.get("ai_in_scope_programs") or [],
            "status": ml_program_selection.get("status", "ok"),
        },
        "targets_audited": per_target_results,
        "ready_to_click_submit_count": len(ready_to_click_submit),
        "ready_to_click_submit": ready_to_click_submit,
        "ready_urls": urls_to_submit,
        "staged_browser_drafts": staged_browser_drafts,
        "chrome_launch": chrome_launch,
        "safety_violations_count": len(draft_violations),
        "critical_safety_violations": critical_violations,
        "draft_violations": draft_violations,
        "failed_steps": failed_steps,
        "steps": steps,
    }

    if not args.dry_run:
        out_root.mkdir(parents=True, exist_ok=True)
        (cycle_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (out_root / "latest_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

        ready_lines = [
            f"# Ready To Review & Click Submit (Cycle #{cycle_num} — {summary['finished_utc']})",
            "",
            "> Every item below passed PoC/corroboration gating, secret/PHI redaction, and strict QA checks.",
            "> Final submission is **always manual** — open each link, review, and click **Submit report**.",
            "",
        ]
        if ready_to_click_submit:
            for item in ready_to_click_submit:
                ready_lines.append(
                    f"- **[{item['program']} | {item['severity'].upper()} | QA={item['qa_status']}]** "
                    f"[{item['title']}]({item['draft_url']})  "
                    f"(`{item.get('stage_status', 'local_md_ready')}` | draft: `{item['markdown_path']}`)"
                )
        else:
            ready_lines.append("- *(No new QA-verified findings ready to submit in this cycle.)*")
        (out_root / "READY_TO_CLICK_SUBMIT.md").write_text("\n".join(ready_lines) + "\n", encoding="utf-8")

        md_lines = [
            f"# RFCHunt Autonomous Hunt Summary (Cycle #{cycle_num})",
            "",
            f"- **Started (UTC)**: `{summary['started_utc']}`",
            f"- **Finished (UTC)**: `{summary['finished_utc']}`",
            "- **Headless / Zero `/browser`**: `True` (`auto_submit_forbidden=True`)",
            f"- **ModelFusion HTTP (`:5000`)**: `{'ONLINE' if mf_reachable else 'FALLBACK_TO_OLLAMA'}`",
            f"- **Ollama Abliterated Models**: `{', '.join(abliterated_tags) or 'none detected'}`",
            "- **Anti-Junk & Grounding Guard**: `ENABLED`",
            f"- **Safety Violations Detected**: `{len(draft_violations)}` (critical: `{len(critical_violations)}`)",
            f"- **Failed Steps**: `{', '.join(failed_steps) or 'none'}`",
            "",
            "## Targets Audited",
        ]
        if per_target_results:
            for tr in per_target_results:
                md_lines.append(
                    f"- `{tr['program']}` | `{tr['target']}` | fast-ooda=`{tr.get('fast_ooda_status', tr.get('status'))}` | ensemble=`{tr.get('ensemble_audit_status', 'n/a')}`"
                )
        else:
            md_lines.append("- *(No local repo targets passed; pass `--target <dir>` or `--clone-unlocked`)*")
        (out_root / "latest_summary.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    return summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autonomous_hunt.py",
        description="Standalone headless RFCHunt + ModelFusion all-checks defensive hunting & scheduling runner.",
    )
    p.add_argument(
        "--target",
        dest="targets",
        action="append",
        default=[],
        help="Local target repository directory to audit (repeatable).",
    )
    p.add_argument(
        "--program",
        default="generic",
        help="HackerOne program handle for eligibility/RoE gating (default: generic).",
    )
    p.add_argument(
        "--watchlist",
        default="config/freshness_watchlist.example.json",
        help="Watchlist JSON path for freshness-watch & optional --clone-unlocked.",
    )
    p.add_argument(
        "--repo",
        dest="repos",
        action="append",
        default=[],
        help="Additional 'owner/repo' slug to include in freshness-watch / --clone-unlocked.",
    )
    p.add_argument(
        "--clone-unlocked",
        action="store_true",
        default=False,
        help="Shallow-clone/pull unlocked watchlist repos locally and audit them automatically.",
    )
    p.add_argument("--max-repos", type=int, default=4, help="Max watchlist repos per cycle when --clone-unlocked is set.")
    p.add_argument("--freshness-hours", type=int, default=72, help="Freshness lookback window in hours (default: 72).")
    p.add_argument("--min-score", type=int, default=20, help="Minimum attack-surface risk score (default: 20).")
    p.add_argument("--mark-seen", action="store_true", default=False, help="Mark polled commit SHAs as seen in SQLite.")
    p.add_argument("--quorum", type=int, default=2, help="Minimum corroborating engines for ensemble-audit (default: 2).")
    p.add_argument("--cpu-workers", type=int, default=None, help="Bounded ProcessPoolExecutor worker count (2..8).")
    p.add_argument("--signal-score", type=float, default=0.0, help="Current HackerOne Signal score for two-lane scheduling.")
    p.add_argument("--eligibility-db", default=None, help="Optional ProgramEligibilityDB SQLite path.")
    p.add_argument("--sync-public-directory", action="store_true", default=False, help="Sync public HackerOne Directory (sorted newest-first) before ML ranking.")
    p.add_argument("--from-eligibility-db", action="store_true", default=False, help="Derive freshness-watch & clone targets dynamically from UNLOCKED programs in ProgramEligibilityDB.")
    p.add_argument("--min-efficiency", type=float, default=80.0, help="Minimum HackerOne response efficiency %% for ML program ranking & watchlist filtering (default: 80).")
    p.add_argument("--portfolio-capacity", type=int, default=6, help="Daily Two-Phase Knapsack portfolio capacity (default: 6).")
    p.add_argument("--skip-ml-ranking", action="store_true", default=False, help="Skip Stage 0.5 ML HackerOne program ranking.")
    p.add_argument("--allow-blocked", action="store_true", default=False, help="Override eligibility DB skip for local research.")
    p.add_argument("--blackboard-db", default=None, help="SQLite WAL Blackboard DB path for crash-safe resume.")
    p.add_argument("--out", default="out/autonomous_hunt", help="Output directory for summaries, SARIF, and logs.")
    p.add_argument("--model", default=None, help="Explicit abliterated Ollama model override.")
    p.add_argument("--modelfusion-endpoint", default=os.environ.get("MODELFUSION_ENDPOINT", "http://127.0.0.1:5000"))
    p.add_argument("--ollama-endpoint", default=os.environ.get("LOCAL_OLLAMA_ENDPOINT", "http://127.0.0.1:11434"))
    p.add_argument("--no-modelfusion", action="store_true", default=False, help="Bypass ModelFusion :5000 and call local Ollama directly.")
    p.add_argument("--start-modelfusion", action="store_true", default=False, help="Auto-start ModelFusion cli.exe --server if not running.")
    p.add_argument("--modelfusion-cli", default=r"d:\harfile\ModelFusion\target\release\cli.exe")
    p.add_argument("--modelfusion-db", default=r"d:\harfile\ModelFusion\IDE\db\hf_models.db")
    p.add_argument("--modelfusion-port", type=int, default=5000)
    p.add_argument("--embedded", action="store_true", default=False, help="100%% offline in-process deterministic mode (zero network/LLM).")
    p.add_argument("--no-llm", action="store_true", default=False, help="Skip Stage-3 LLM triage.")
    p.add_argument("--no-external-scanners", action="store_true", default=False, help="Use in-process engines only in ensemble-audit.")
    p.add_argument("--skip-freshness", action="store_true", default=False)
    p.add_argument("--skip-ensemble", action="store_true", default=False)
    p.add_argument("--skip-lean", action="store_true", default=False)
    p.add_argument("--skip-qa-drafts", action="store_true", default=False)
    p.add_argument("--skip-check-drafts", action="store_true", default=False)
    p.add_argument(
        "--browser-hunt",
        action="store_true",
        default=False,
        help="Open --hunt-url in visible Chromium, wait for human login/2FA/CAPTCHA, sync inbox/cooldown/Signal, discover unlocked scopes & GitHub repos, and stage verified drafts (NEVER clicks Submit).",
    )
    p.add_argument(
        "--no-browser-hunt",
        action="store_true",
        default=False,
        help="Disable opening --hunt-url in interactive browser mode.",
    )
    p.add_argument(
        "--hunt-url",
        "--bug-hunt-url",
        dest="hunt_url",
        default=DEFAULT_BUG_HUNT_URL,
        help=f"Official bug bounty directory or program URL opened by --browser-hunt (default: {DEFAULT_BUG_HUNT_URL}).",
    )
    p.add_argument(
        "--login-timeout",
        type=float,
        default=300.0,
        help="Seconds to wait for human login/2FA/CAPTCHA during --browser-hunt (default: 300).",
    )
    p.add_argument(
        "--probe-report-id",
        type=int,
        default=4243972,
        help="HackerOne draft report ID probed read-only for cooldown `can_submit_draft?` status (default: 4243972).",
    )
    p.add_argument(
        "--swarm",
        action="store_true",
        default=False,
        help="Enable parallel multi-agent swarm auditing across discovered and local targets.",
    )
    p.add_argument(
        "--swarm-workers",
        type=int,
        default=None,
        help="Bounded concurrent target swarm workers when --swarm is active (1..8).",
    )
    p.add_argument(
        "--stage-drafts",
        action="store_true",
        default=False,
        help="Prefill & save QA-verified drafts in HugOS Browser CDP (:9222) or persistent Chromium profile (NEVER clicks Submit).",
    )
    p.add_argument(
        "--cdp-url",
        default=os.environ.get("RFCHUNT_HUGOS_CDP_URL", "http://127.0.0.1:9222"),
        help="Chromium / HugOS Browser CDP endpoint used when --stage-drafts is set (default: http://127.0.0.1:9222).",
    )
    p.add_argument(
        "--browser-profile",
        default="out/autonomous_hunt/h1_browser_profile",
        help="Persistent local browser profile directory so you only sign into HackerOne once.",
    )
    p.add_argument(
        "--open-chrome",
        action="store_true",
        default=False,
        help="Automatically open every verified ready-to-submit HackerOne URL in Google Chrome for your manual Submit click.",
    )
    p.add_argument("--step-timeout-sec", type=float, default=600.0, help="Per-stage timeout in seconds (default: 600).")
    p.add_argument("--dry-run", action="store_true", default=False, help="Print full execution plan with zero disk/network side effects.")
    p.add_argument("--watch", action="store_true", default=False, help="Run continuously on a repeating schedule.")
    p.add_argument("--interval-minutes", type=float, default=60.0, help="Minutes between scheduled cycles in --watch mode (default: 60).")
    p.add_argument("--max-cycles", type=int, default=0, help="Max cycles in --watch mode (0 = run until Ctrl+C).")
    p.add_argument("--json", dest="json_out", action="store_true", default=False, help="Print full JSON summary to stdout.")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    stop_requested = False

    def _handle_sig(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    for sig_name in ("SIGINT", "SIGTERM"):
        sig_val = getattr(signal, sig_name, None)
        if sig_val is not None:
            try:
                signal.signal(sig_val, _handle_sig)
            except Exception:  # noqa: BLE001, S110
                pass

    cycle_num = 0
    last_exit = 0
    while True:
        cycle_num += 1
        try:
            summary = execute_hunt_cycle(args, cycle_num)
        except (PermissionError, ValueError) as exc:
            print(f"[SAFETY BLOCK] {exc}", file=sys.stderr)
            return 1
        if args.json_out:
            print(json.dumps(summary, indent=2))
        else:
            mode_tag = " [DRY-RUN]" if summary.get("dry_run") else ""
            print(
                f"[RFCHunt] Cycle #{cycle_num}{mode_tag} complete | targets={len(summary['targets_audited'])} "
                f"| steps_planned={len(summary['steps'])} "
                f"| ready_to_click_submit={summary['ready_to_click_submit_count']} "
                f"| safety_violations={summary['safety_violations_count']} "
                f"| failed_steps={len(summary['failed_steps'])} "
                f"| modelfusion={'UP' if summary['modelfusion_reachable'] else 'OLLAMA_DIRECT'}"
            )
            if summary.get("dry_run"):
                for st in summary.get("steps") or []:
                    cmd_preview = " ".join(str(x) for x in (st.get("command") or []))
                    print(f"  [DRY-RUN STEP] {st.get('label')}: {cmd_preview or st.get('status')}")
            for item in summary.get("ready_to_click_submit") or []:
                print(
                    f"  [READY FOR YOUR SUBMIT CLICK] {item['draft_url']} "
                    f"({item['program']} | {item['severity'].upper()}) — {item['title']}"
                )
            if (summary.get("chrome_launch") or {}).get("opened_urls"):
                print(
                    f"  [CHROME OPENED] {summary['chrome_launch']['status']}: "
                    + ", ".join(summary["chrome_launch"]["opened_urls"])
                )
            if summary["critical_safety_violations"]:
                print(
                    f"[SAFETY BLOCK] Critical secret leak(s) detected: {summary['critical_safety_violations']}",
                    file=sys.stderr,
                )

        if summary["critical_safety_violations"]:
            last_exit = 2
        elif summary["failed_steps"]:
            last_exit = 1
        else:
            last_exit = 0

        if not args.watch or stop_requested:
            break
        if args.max_cycles > 0 and cycle_num >= args.max_cycles:
            break

        sleep_sec = max(5.0, float(args.interval_minutes) * 60.0)
        deadline = time.monotonic() + sleep_sec
        while time.monotonic() < deadline and not stop_requested:
            time.sleep(min(2.0, max(0.1, deadline - time.monotonic())))
        if stop_requested:
            break

    return last_exit


if __name__ == "__main__":
    raise SystemExit(main())
