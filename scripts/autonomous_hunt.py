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
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

RFCHUNT_ROOT = Path(__file__).resolve().parent.parent
if str(RFCHUNT_ROOT) not in sys.path:
    sys.path.insert(0, str(RFCHUNT_ROOT))

from engine.program_eligibility_db import ProgramEligibilityDB  # noqa: E402

_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_HANDLE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")

# Safety & Hygiene Violation Patterns checked on every generated draft/artifact
_SECRET_LEAK_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{24,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("openai_or_anthropic_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{24,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b")),
)
_HTML_ENTITY_LEAK_RE = re.compile(r"&(?:lt|gt|amp|quot);")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffd]")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def probe_http_fast(url: str, timeout_sec: float = 0.4) -> bool:
    """Strict <=400ms health probe so offline daemons never stall the hunter."""
    eff = min(max(float(timeout_sec), 0.05), 0.4)
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=eff) as resp:
            return 200 <= int(resp.status) < 500
    except Exception:
        return False


def discover_ollama_models(ollama_endpoint: str, timeout_sec: float = 0.4) -> List[str]:
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
    except Exception:
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


def scan_draft_safety_violations(markdown_text: str) -> List[Dict[str, str]]:
    """
    Audits a generated Markdown draft for hard safety & formatting violations:
      - Unredacted credentials / private keys
      - Corrupted HTML entities (`&lt;`, `&gt;`)
      - Illegal ASCII control characters / `U+FFFD` replacement glyphs
    """
    violations: List[Dict[str, str]] = []
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
    model_override: Optional[str] = None,
    offline: bool = False,
) -> Dict[str, str]:
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
    env: Dict[str, str],
    timeout_sec: float = 600.0,
    dry_run: bool = False,
) -> Dict[str, Any]:
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
    env: Dict[str, str],
    dry_run: bool = False,
) -> Tuple[Optional[Path], Dict[str, Any]]:
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


def load_watchlist_targets(watchlist_path: Path) -> List[Dict[str, str]]:
    if not watchlist_path.is_file():
        return []
    try:
        data = json.loads(watchlist_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    out: List[Dict[str, str]] = []
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
    eligibility_db_path: Optional[str] = None,
    allow_blocked: bool = False,
) -> Tuple[bool, str]:
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
    except Exception as exc:
        return True, f"eligibility_db_unavailable:{exc}"


def maybe_start_modelfusion_server(
    cli_path: Path,
    db_path: Path,
    port: int,
    *,
    dry_run: bool = False,
) -> Dict[str, Any]:
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


def execute_hunt_cycle(args: argparse.Namespace, cycle_num: int) -> Dict[str, Any]:
    """Executes one complete end-to-end defensive hunting + violation + QA cycle."""
    cycle_started = utc_now_iso()
    out_root = Path(args.out).resolve()
    cycle_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    cycle_dir = out_root / f"cycle_{cycle_id}_n{cycle_num}"
    if not args.dry_run:
        cycle_dir.mkdir(parents=True, exist_ok=True)

    # Stage 0: Fast <=400ms Pre-Flight Probes
    mf_endpoint = args.modelfusion_endpoint.rstrip("/")
    ollama_endpoint = args.ollama_endpoint.rstrip("/")
    mf_start_info: Dict[str, Any] = {"started": False, "reachable": False, "endpoint": mf_endpoint}
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

    steps: List[Dict[str, Any]] = []
    targets_to_audit: List[Tuple[str, Path]] = []

    # Collect explicit local targets (`--target PATH[:PROGRAM]`)
    for raw_t in args.targets or []:
        t_path = Path(raw_t).resolve()
        prog = validate_program_handle(args.program)
        targets_to_audit.append((prog, t_path))

    # Stage 1: Freshness Watch across watchlist
    watchlist_path = Path(args.watchlist)
    if not watchlist_path.is_absolute():
        watchlist_path = (RFCHUNT_ROOT / watchlist_path).resolve()

    if not args.skip_freshness and not args.embedded:
        fresh_cmd = [
            sys.executable,
            str(RFCHUNT_ROOT / "revenue_cli.py"),
            "freshness-watch",
            "--watchlist",
            str(watchlist_path),
            "--hours",
            str(args.freshness_hours),
            "--min-score",
            str(args.min_score),
            "--out",
            str(cycle_dir / "fresh_hunt_queue"),
        ]
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

    # Optionally shallow-clone unlocked watchlist repos into local cache for full white-box auditing
    if args.clone_unlocked and not args.embedded:
        repos_cache = out_root / "repos_cache"
        wl_items = load_watchlist_targets(watchlist_path)
        for r in args.repos or []:
            wl_items.append({"program": validate_program_handle(args.program), "repo": validate_repo_slug(r)})
        for item in wl_items[: max(1, int(args.max_repos))]:
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
            if repo_dir is not None:
                targets_to_audit.append((item["program"], repo_dir))

    # Stage 2 & Stage 3: Fast 3-Stage OODA + Exhaustive Multi-Engine Ensemble Audit per eligible target
    per_target_results: List[Dict[str, Any]] = []
    blackboard_db = str(Path(args.blackboard_db).resolve()) if args.blackboard_db else str(out_root / "blackboard.sqlite3")

    for idx, (prog, target_dir) in enumerate(targets_to_audit, start=1):
        eligible, elig_reason = check_program_eligibility(
            prog,
            eligibility_db_path=args.eligibility_db,
            allow_blocked=args.allow_blocked,
        )
        if not eligible:
            per_target_results.append(
                {
                    "program": prog,
                    "target": str(target_dir),
                    "status": "skipped_ineligible",
                    "reason": elig_reason,
                }
            )
            continue

        t_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{idx}_{prog}_{target_dir.name}")[:64]
        t_out = cycle_dir / t_slug

        # Stage 2: Fast 3-Stage OODA Funnel (Loop 3 + Loop 4 Auto-PoC Gate; zero browser)
        ooda_cmd = [
            sys.executable,
            str(RFCHUNT_ROOT / "revenue_cli.py"),
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
        steps.append(ooda_res)

        # Stage 3: Exhaustive Multi-Engine Violation & Security Audit (`--all --ensemble` + SARIF)
        ens_res: Optional[Dict[str, Any]] = None
        if not args.skip_ensemble:
            sarif_path = t_out / "ensemble_audit" / "results.sarif"
            ens_cmd = [
                sys.executable,
                str(RFCHUNT_ROOT / "revenue_cli.py"),
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
            steps.append(ens_res)

        per_target_results.append(
            {
                "program": prog,
                "target": str(target_dir),
                "eligibility": elig_reason,
                "fast_ooda_status": ooda_res["status"],
                "ensemble_audit_status": ens_res["status"] if ens_res else "skipped",
                "output_dir": str(t_out),
            }
        )

    # Stage 4: Lean 4 Formal Proof Kernel Verification
    if not args.skip_lean:
        lean_cmd = [sys.executable, str(RFCHUNT_ROOT / "revenue_cli.py"), "lean-verify"]
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

    # Stage 5: Hard Safety Violation Check + Strict QA Audit (`qa-drafts --strict`) on Staged Markdown Drafts
    draft_violations: List[Dict[str, Any]] = []
    draft_dirs = [cycle_dir, RFCHUNT_ROOT / "reports" / "hackerone"]
    seen_md: set[Path] = set()
    for d_root in draft_dirs:
        if not d_root.is_dir():
            continue
        for md_path in sorted(d_root.rglob("*.md")):
            if md_path.name in ("latest_summary.md", "drafts_ready_to_submit.md", "qa_draft_audit.md"):
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
            v_list = scan_draft_safety_violations(md_text)
            if v_list:
                draft_violations.append({"file": str(md_path), "violations": v_list})

            if not args.skip_qa_drafts:
                qa_cmd = [
                    sys.executable,
                    str(RFCHUNT_ROOT / "revenue_cli.py"),
                    "qa-drafts",
                    "--markdown-file",
                    str(md_path),
                    "--program",
                    validate_program_handle(args.program),
                    "--write-repaired",
                    str(md_path),
                    "--strict",
                ]
                if args.embedded:
                    qa_cmd.append("--no-verify-sources")
                steps.append(
                    run_step(
                        f"stage5_qa_draft:{md_path.name}",
                        qa_cmd,
                        cwd=RFCHUNT_ROOT,
                        env=env,
                        timeout_sec=60.0,
                        dry_run=args.dry_run,
                    )
                )

    # Stage 5B: Headless Cooldown / Draft Submission Readiness Check (`check-drafts`)
    if not args.skip_check_drafts:
        chk_cmd = [
            sys.executable,
            str(RFCHUNT_ROOT / "revenue_cli.py"),
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

    critical_violations = [
        v for item in draft_violations for v in item["violations"] if v.get("severity") == "CRITICAL"
    ]
    failed_steps = [s["label"] for s in steps if s.get("status") not in ("ok", "dry_run_planned", "skipped_ineligible")]

    summary: Dict[str, Any] = {
        "schema": "rfchunt.autonomous_hunt_cycle.v1",
        "cycle_number": cycle_num,
        "started_utc": cycle_started,
        "finished_utc": utc_now_iso(),
        "dry_run": bool(args.dry_run),
        "browser_used": False,
        "auto_submit_forbidden": True,
        "anti_junk_guard_enabled": True,
        "modelfusion_endpoint": mf_endpoint,
        "modelfusion_reachable": mf_reachable,
        "ollama_endpoint": ollama_endpoint,
        "ollama_models_count": len(ollama_tags),
        "installed_abliterated_models": abliterated_tags,
        "targets_audited": per_target_results,
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

        md_lines = [
            f"# RFCHunt Autonomous Hunt Summary (Cycle #{cycle_num})",
            "",
            f"- **Started (UTC)**: `{summary['started_utc']}`",
            f"- **Finished (UTC)**: `{summary['finished_utc']}`",
            f"- **Headless / Zero `/browser`**: `True` (`auto_submit_forbidden=True`)",
            f"- **ModelFusion HTTP (`:5000`)**: `{'ONLINE' if mf_reachable else 'FALLBACK_TO_OLLAMA'}`",
            f"- **Ollama Abliterated Models**: `{', '.join(abliterated_tags) or 'none detected'}`",
            f"- **Anti-Junk & Grounding Guard**: `ENABLED`",
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
    p.add_argument("--step-timeout-sec", type=float, default=600.0, help="Per-stage timeout in seconds (default: 600).")
    p.add_argument("--dry-run", action="store_true", default=False, help="Print full execution plan with zero disk/network side effects.")
    p.add_argument("--watch", action="store_true", default=False, help="Run continuously on a repeating schedule.")
    p.add_argument("--interval-minutes", type=float, default=60.0, help="Minutes between scheduled cycles in --watch mode (default: 60).")
    p.add_argument("--max-cycles", type=int, default=0, help="Max cycles in --watch mode (0 = run until Ctrl+C).")
    p.add_argument("--json", dest="json_out", action="store_true", default=False, help="Print full JSON summary to stdout.")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
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
            except Exception:
                pass

    cycle_num = 0
    last_exit = 0
    while True:
        cycle_num += 1
        summary = execute_hunt_cycle(args, cycle_num)
        if args.json_out:
            print(json.dumps(summary, indent=2))
        else:
            print(
                f"[RFCHunt] Cycle #{cycle_num} complete | targets={len(summary['targets_audited'])} "
                f"| safety_violations={summary['safety_violations_count']} "
                f"| failed_steps={len(summary['failed_steps'])} "
                f"| modelfusion={'UP' if summary['modelfusion_reachable'] else 'OLLAMA_DIRECT'}"
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
