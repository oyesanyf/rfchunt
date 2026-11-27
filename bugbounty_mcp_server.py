"""
Bug Bounty & Revenue Operations MCP Server (`bugbounty_mcp_server.py`).
=======================================================================
Standalone JSON-RPC 2.0 stdio MCP server exposing RFCHunt's revenue-ready bug bounty
and consulting workflows:
  1. `bb_freshness_watch`       — Poll GitHub watchlist for <72h releases/PRs/commits
  2. `bb_run_linux_poc`         — Execute polyglot PoCs in hardened Linux Docker/WSL2
  3. `bb_package_client_audit`  — Generate 5-file client security audit deliverable bundle
  4. `bb_stage_hackerone_draft` — Validate & stage a HackerOne-ready report payload JSON
  5. `bb_browser_handoff_spec`  — Produce a structured `/browser` action spec for
                                  HackerOne / Bugcrowd / Immunefi (respecting HITL/CAPTCHA)
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

from engine.client_audit_packager import ClientAuditPackager
from engine.freshness_watcher import (
    FreshnessWatcher,
    WatchTarget,
    load_watchlist,
    render_fresh_hunt_queue_markdown,
)
from engine.host_containment import silent_subprocess_run
from engine.linux_poc_runner import (
    LinuxPocRunner,
    save_transcript_bundle,
    validate_command_tokens,
)


def build_rfchunt_all_argv(
    *,
    target: str,
    output_dir: str = "reports",
    dry_run: bool = False,
    ensemble: bool = False,
    program: str = "generic",
    freshness_hours: int = 72,
    ensemble_quorum: int = 2,
    embedded: bool = False,
    model: str | None = None,
    extra_flags: list[str] | None = None,
    swarm_script: Path | None = None,
) -> list[str]:
    """Builds a fail-closed argv invoking `rfc_hunt_swarm.py --all [--ensemble] [--embedded] <target>` (`shell=False`)."""
    t = str(target or "").strip()
    if not t:
        raise ValueError("target is required for bb_run_all_scan.")
    if t.startswith("-"):
        raise ValueError(
            f"Invalid target {t!r}: target must not start with '-' (argument injection blocked)."
        )
    if isinstance(freshness_hours, bool) or isinstance(ensemble_quorum, bool):
        raise TypeError("freshness_hours and ensemble_quorum must be integers, not bool.")
    script = swarm_script or (Path(__file__).resolve().parent / "rfc_hunt_swarm.py")
    argv = [sys.executable, str(script), "--all", t, "--output-dir", str(output_dir)]
    if ensemble:
        argv.extend(
            [
                "--ensemble",
                "--program",
                str(program).strip() or "generic",
                "--freshness-hours",
                str(int(freshness_hours)),
                "--quorum",
                str(max(1, int(ensemble_quorum))),
            ]
        )
    if embedded:
        argv.append("--embedded")
    if model and str(model).strip():
        argv.extend(["--model", str(model).strip()])
    if dry_run:
        argv.append("--dry-run")
    for flag in (extra_flags or []):
        f_s = str(flag).strip()
        if f_s:
            argv.append(f_s)
    ok, err = validate_command_tokens(argv)
    if not ok:
        raise ValueError(err)
    return argv


_ALL_TOOLCHAIN_KEYS = (
    "docker",
    "wsl2",
    "lean4",
    "rfchunt_lean_oracle",
    "angr",
    "klee",
    "semgrep",
    "rea",
    "trufflehog",
    "jadx",
    "subfinder",
    "httpx",
    "katana",
    "schemathesis",
)


def _probe_toolchain_status_safe(lean_dir: Path | None, embedded: bool) -> dict[str, Any]:
    """Return non-destructive backend availability status, degrading gracefully on probe errors."""
    if embedded:
        try:
            from engine.ensemble_orchestrator import _embedded_toolchain_status

            return _embedded_toolchain_status()
        except Exception:  # noqa: BLE001
            return {
                name: {
                    "available": False,
                    "status": "skipped_embedded",
                    "reason": "Subprocess toolchain probes skipped in embedded=True mode.",
                    "path_or_module": None,
                }
                for name in _ALL_TOOLCHAIN_KEYS
            }
    try:
        from engine.linux_poc_runner import probe_optional_backends

        eff_lean = lean_dir if (lean_dir is not None and lean_dir.is_dir()) else None
        return probe_optional_backends(lean_dir=eff_lean, timeout_sec=2.5)
    except Exception as exc:  # noqa: BLE001
        return {
            name: {
                "available": False,
                "status": "unavailable",
                "reason": str(exc),
                "path_or_module": None,
            }
            for name in _ALL_TOOLCHAIN_KEYS
        }


def _merge_lean_domain_enrichment(
    base_lean: dict[str, Any] | None,
    ens_lean: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Merge counterexamples/domain_checks into base Lean workspace report without overwriting base fields."""
    if not isinstance(ens_lean, dict):
        return base_lean
    if base_lean is None:
        return dict(ens_lean)
    enriched = dict(base_lean)
    for key in ("counterexamples", "domain_checks", "oracle_backend", "degradation_reason"):
        if key in ens_lean:
            enriched[key] = ens_lean[key]
    return enriched


def run_rfchunt_all_scan(
    *,
    target: str,
    output_dir: str = "reports",
    dry_run: bool = False,
    ensemble: bool = False,
    program: str = "generic",
    freshness_hours: int = 72,
    ensemble_quorum: int = 2,
    embedded: bool = False,
    model: str | None = None,
    include_lean_verify: bool = True,
    timeout_sec: float = 300.0,
    extra_flags: list[str] | None = None,
) -> dict[str, Any]:
    """Executes RFCHunt `--all` (optionally `--ensemble` / `--embedded`) safely (`shell=False`) plus Lean 4 check."""
    try:
        if (
            isinstance(freshness_hours, bool)
            or isinstance(ensemble_quorum, bool)
            or isinstance(timeout_sec, bool)
        ):
            raise TypeError("freshness_hours, ensemble_quorum, and timeout_sec must be numeric, not bool.")
        eff_freshness_hours = int(freshness_hours)
        eff_quorum = max(1, int(ensemble_quorum))
        eff_timeout_sec = float(timeout_sec)
    except (TypeError, ValueError) as exc:
        return {
            "ok": False,
            "status": "error",
            "error": f"Invalid numeric parameter for bb_run_all_scan: {exc}",
            "target": str(target or ""),
            "output_dir": str(output_dir),
        }

    argv = build_rfchunt_all_argv(
        target=target,
        output_dir=output_dir,
        dry_run=dry_run,
        ensemble=ensemble,
        program=program,
        freshness_hours=eff_freshness_hours,
        ensemble_quorum=eff_quorum,
        embedded=embedded,
        model=model,
        extra_flags=extra_flags,
    )
    lean_dir = Path(__file__).resolve().parent / "formal" / "lean4"
    lean_summary: dict[str, Any] | None = None
    if include_lean_verify:
        from engine.lean_formal_verifier import verify_lean_workspace
        if lean_dir.is_dir():
            lean_summary = verify_lean_workspace(lean_dir).to_dict()

    mode = "--all --ensemble" if ensemble else "--all"
    if embedded:
        mode = f"{mode} --embedded"
    if dry_run:
        tc_status = _probe_toolchain_status_safe(lean_dir, bool(embedded))
        dry_payload: dict[str, Any] = {
            "status": "dry_run_ready",
            "mode": mode,
            "argv": argv,
            "target": target,
            "output_dir": output_dir,
            "program": program,
            "freshness_hours": eff_freshness_hours,
            "embedded": bool(embedded),
            "model": model,
            "lean_verification": lean_summary,
            "toolchain_status": tc_status,
        }
        if ensemble:
            dry_payload["ensemble"] = {
                "target": target,
                "program": str(program).strip() or "generic",
                "freshness_hours": eff_freshness_hours,
                "quorum": eff_quorum,
                "whiteboard": {
                    "enabled": True,
                    "dry_run": True,
                    "hypotheses": [],
                    "facts": [],
                    "backend_status": tc_status,
                },
                "clusters": [],
                "counts_by_disposition": {},
                "toolchain_status": tc_status,
            }
        return dry_payload

    if embedded:
        from engine.ensemble_orchestrator import EnsembleOrchestrator

        orch = EnsembleOrchestrator(
            program=program,
            freshness_hours=eff_freshness_hours,
            quorum=eff_quorum,
            exhaustive_default=True,
            embedded=True,
            model=model,
            enable_llm_verify=False,
        )
        rep = orch.run(target, out_dir=output_dir)
        rep_dict = rep.to_dict()
        merged_lean = _merge_lean_domain_enrichment(lean_summary, rep_dict.get("lean_verification"))
        return {
            "status": "completed",
            "mode": mode,
            "exit_code": 0,
            "embedded": True,
            "target": target,
            "output_dir": output_dir,
            "total_clusters": len(rep.clusters),
            "counts_by_disposition": rep.counts_by_disposition,
            "sarif_path": str(Path(output_dir) / "ensemble_findings.sarif"),
            "telemetry": orch.last_telemetry,
            "lean_verification": merged_lean,
            "toolchain_status": rep.toolchain_status,
            "ensemble": rep_dict,
        }

    proc = silent_subprocess_run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=eff_timeout_sec,
    )
    payload: dict[str, Any] = {
        "status": "completed" if proc.returncode == 0 else "failed",
        "mode": mode,
        "exit_code": proc.returncode,
        "argv": argv,
        "target": target,
        "output_dir": output_dir,
        "stdout_tail": (proc.stdout or "")[-4000:],
        "stderr_tail": (proc.stderr or "")[-2000:],
        "lean_verification": lean_summary,
    }
    ens_data: dict[str, Any] | None = None
    if ensemble and proc.returncode == 0:
        out_path = Path(output_dir)
        ens_report_path = out_path / "ensemble_report.json"
        combined_json_path = out_path / "combined_audit_summary.json"
        if ens_report_path.is_file():
            try:
                loaded = json.loads(ens_report_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    ens_data = loaded
            except (json.JSONDecodeError, TypeError, ValueError):
                ens_data = None
        if ens_data is None and combined_json_path.is_file():
            try:
                comb = json.loads(combined_json_path.read_text(encoding="utf-8"))
                if isinstance(comb, dict) and isinstance(comb.get("ensemble"), dict):
                    ens_data = comb["ensemble"]
            except (json.JSONDecodeError, TypeError, ValueError):
                ens_data = None
        if ens_data is None and (proc.stdout or "").strip():
            try:
                parsed_stdout = json.loads((proc.stdout or "").strip())
                if isinstance(parsed_stdout, dict) and isinstance(parsed_stdout.get("ensemble"), dict):
                    ens_data = parsed_stdout["ensemble"]
            except (json.JSONDecodeError, TypeError, ValueError):
                ens_data = None

    if isinstance(ens_data, dict):
        payload["ensemble"] = ens_data
        tc_from_ens = ens_data.get("toolchain_status")
        payload["toolchain_status"] = (
            tc_from_ens if isinstance(tc_from_ens, dict) else _probe_toolchain_status_safe(lean_dir, False)
        )
        payload["lean_verification"] = _merge_lean_domain_enrichment(
            lean_summary, ens_data.get("lean_verification")
        )
    else:
        tc_fallback = _probe_toolchain_status_safe(lean_dir, False)
        payload["toolchain_status"] = tc_fallback
        if ensemble:
            payload["ensemble"] = {
                "target": target,
                "program": str(program).strip() or "generic",
                "freshness_hours": eff_freshness_hours,
                "quorum": eff_quorum,
                "whiteboard": {
                    "enabled": True,
                    "status": "completed" if proc.returncode == 0 else "failed",
                    "hypotheses": [],
                    "facts": [],
                    "backend_status": tc_fallback,
                },
                "clusters": [],
                "counts_by_disposition": {},
                "toolchain_status": tc_fallback,
            }
    return payload


SERVER_INFO = {
    "name": "rfchunt-bugbounty-mcp",
    "version": "1.0.0",
}

HACKERONE_MAX_TITLE_LEN = 150
SUPPORTED_PLATFORMS = {
    "hackerone": "https://hackerone.com/{handle}/reports/new?type=team&report_type=vulnerability",
    "bugcrowd": "https://bugcrowd.com/engagements/{handle}",
    "immunefi": "https://immunefi.com/bug-bounty/{handle}/information/",
}


def _coerce_strict_bool(val: Any) -> bool:
    """Strictly coerce booleans without fail-open bool('false') / bool('0')."""
    if isinstance(val, bool):
        return val
    if isinstance(val, int) and not isinstance(val, bool):
        return val == 1
    if isinstance(val, str):
        return val.strip().lower() in {"true", "1", "yes", "on"}
    return False


def _parse_strict_bool_arg(val: Any, *, field_name: str = "value") -> bool:
    """Strictly parse MCP boolean arguments, raising ValueError/TypeError on invalid inputs."""
    if isinstance(val, bool):
        return val
    if isinstance(val, int) and not isinstance(val, bool):
        if val in (0, 1):
            return val == 1
        raise ValueError(f"Invalid integer boolean for {field_name}: {val!r}")
    if isinstance(val, str):
        norm = val.strip().lower()
        if norm in ("true", "1", "yes", "on"):
            return True
        if norm in ("false", "0", "no", "off"):
            return False
        raise ValueError(f"Invalid boolean string for {field_name}: {val!r}")
    raise TypeError(f"Invalid boolean value for {field_name}: {val!r}")


def _redact_draft_text(text: str) -> str:
    raw = str(text or "")
    try:
        from engine.advisory_exporter import _redact_inline_tokens

        raw = _redact_inline_tokens(raw)
    except Exception:  # noqa: BLE001, S110
        pass
    try:
        from engine.hackerone_porter import _scrub_secrets_and_phi

        raw = _scrub_secrets_and_phi(raw)
    except Exception:  # noqa: BLE001, S110
        pass
    return raw


def validate_and_stage_hackerone_draft(
    *,
    program_handle: str,
    asset: str,
    weakness_cwe: str,
    severity_rating: str,
    title: str,
    vulnerability_information: str,
    impact: str,
    poc_verified: Any,
    out_path: str,
    require_verified_poc: bool = True,
    eligibility_db: Any | None = None,
    eligibility_db_path: str | None = None,
    poc_transcript: str = "",
    report_id: str | None = None,
) -> dict[str, Any]:
    """
    Validates a bug bounty draft against strict signal-protection and ProgramEligibilityDB
    fail-closed gates before staging it for browser review/submission.
    """
    handle_clean = str(program_handle or "").strip()
    asset_clean = str(asset or "").strip()
    weakness_clean = str(weakness_cwe or "").strip()
    title_clean = _redact_draft_text(str(title or "")).strip()
    vuln_clean = _redact_draft_text(str(vulnerability_information or ""))
    impact_clean = _redact_draft_text(str(impact or ""))
    transcript_clean = _redact_draft_text(str(poc_transcript or ""))

    issues: list[str] = []
    elig_blocked = False
    is_valid_handle = bool(
        handle_clean
        and "\x00" not in handle_clean
        and ".." not in handle_clean
        and "/" not in handle_clean
        and "\\" not in handle_clean
    )
    if not is_valid_handle:
        elig_blocked = True
        issues.append("program_handle is required and must not contain path traversal or control characters.")
    else:
        from engine.program_eligibility_db import ProgramEligibilityDB

        if eligibility_db is not None:
            elig_store = eligibility_db
        elif eligibility_db_path and str(eligibility_db_path).strip():
            elig_store = ProgramEligibilityDB(str(eligibility_db_path).strip())
        elif os.environ.get("RFCHUNT_ELIGIBILITY_DB", "").strip():
            elig_store = ProgramEligibilityDB(os.environ["RFCHUNT_ELIGIBILITY_DB"].strip())
        else:
            elig_store = ProgramEligibilityDB()
        try:
            if not elig_store.is_eligible(handle_clean):
                elig_blocked = True
                issues.append(
                    f"Program {handle_clean!r} is not UNLOCKED in ProgramEligibilityDB (blocked by signal/eligibility gate)."
                )
        except Exception as exc:  # noqa: BLE001
            elig_blocked = True
            issues.append(f"ProgramEligibilityDB fail-closed block for {handle_clean!r}: {exc}")

    if not asset_clean:
        issues.append("in-scope asset is required.")
    if not title_clean:
        issues.append("title is required.")
    elif len(title_clean) >= HACKERONE_MAX_TITLE_LEN:
        issues.append(
            f"title length ({len(title_clean)}) must be < {HACKERONE_MAX_TITLE_LEN} characters."
        )
    if len(vuln_clean.strip()) < 100:
        issues.append("vulnerability_information is too short (< 100 chars).")
    if not impact_clean.strip():
        issues.append("impact section is required.")
    if severity_rating not in ("None", "Low", "Medium", "High", "Critical"):
        issues.append(
            f"severity_rating {severity_rating!r} must be one of None/Low/Medium/High/Critical."
        )
    eff_poc_verified = _coerce_strict_bool(poc_verified)
    if require_verified_poc and not eff_poc_verified:
        issues.append(
            "poc_verified is False — run `bb_run_linux_poc` first to attach verbatim Linux runtime output before submission."
        )

    from engine.ensemble_orchestrator import evaluate_vendor_threat_model

    tm = evaluate_vendor_threat_model(
        title=title_clean,
        summary=f"{vuln_clean}\n{impact_clean}",
        file_path=asset_clean,
        program=handle_clean,
        poc_verified=eff_poc_verified,
    )
    if not tm.passed:
        issues.extend(tm.reasons)

    if not issues:
        status = "staged_ready"
    elif elig_blocked and len(issues) == 1:
        status = "blocked_eligibility_gate"
    else:
        status = "blocked_quality_gate"

    eff_report_id: str | None = None
    report_url: str | None = None
    if status == "staged_ready":
        if report_id and str(report_id).strip():
            eff_report_id = str(report_id).strip()
        else:
            digest = hashlib.sha256(
                f"{handle_clean}|{asset_clean}|{title_clean}".encode()
            ).hexdigest()[:10]
            eff_report_id = f"draft-{digest}"
        report_url = f"https://hackerone.com/reports/{eff_report_id}"

    payload = {
        "status": status,
        "quality_gate_issues": issues,
        "program_handle": handle_clean,
        "submit_url": SUPPORTED_PLATFORMS["hackerone"].format(handle=handle_clean) if is_valid_handle else None,
        "report_id": eff_report_id,
        "report_url": report_url,
        "asset": asset_clean,
        "weakness_cwe": weakness_clean,
        "severity_rating": severity_rating,
        "title": title_clean,
        "title_length": len(title_clean),
        "vulnerability_information": vuln_clean,
        "impact": impact_clean,
        "poc_verified": eff_poc_verified,
        "poc_transcript": transcript_clean,
    }

    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {
        "status": status,
        "staged_file": str(dest),
        "quality_gate_issues": issues,
        "submit_url": payload["submit_url"],
        "report_id": eff_report_id,
        "report_url": report_url,
    }


def build_browser_handoff_spec(
    *,
    platform: str,
    program_handle: str,
    action: str,
    staged_draft_path: str | None = None,
    existing_draft_url: str | None = None,
) -> dict[str, Any]:
    """
    Emits a structured `/browser` subagent handoff specification for authorized bug bounty
    UI workflows (scope reading, inbox triage check, or draft staging).
    Always enforces human-in-the-loop for CAPTCHA/Turnstile and explicit confirmation before final submit.
    """
    plat = platform.strip().lower()
    if plat not in SUPPORTED_PLATFORMS:
        raise ValueError(f"Unsupported platform {platform!r}; choose from {sorted(SUPPORTED_PLATFORMS)}")
    valid_actions = ("inspect_scope", "check_inbox", "stage_draft", "submit_approved_draft")
    if action not in valid_actions:
        raise ValueError(f"Unsupported action {action!r}; choose from {valid_actions}")

    target_url = existing_draft_url or SUPPORTED_PLATFORMS[plat].format(handle=program_handle.strip())
    steps = [
        f"Open {target_url} in the authenticated built-in `/browser` session.",
        "If Cloudflare Turnstile, CAPTCHA, or login prompt appears, pause immediately and ask the user to complete it in the visible browser pane (never bypass).",
    ]
    if action == "inspect_scope":
        steps.append("Extract in-scope assets, max severities, Signal requirements, and out-of-scope rules.")
    elif action == "check_inbox":
        steps.append("Inspect report statuses (New/Triaged/Resolved/Duplicate/Informative) and confirm whether Submit is enabled.")
    elif action == "stage_draft":
        steps.append(f"Read staged JSON payload from `{staged_draft_path}` and populate Asset, Weakness, Severity, Title, Description, and Impact.")
        steps.append("Click `Create Draft` ONLY (do NOT click final Submit until user confirms).")
    elif action == "submit_approved_draft":
        steps.append("Confirm all required fields, Severity, and verbatim PoC output are present.")
        steps.append("Click `Submit` / `Submit Report`, capture the confirmed Report ID/URL + screenshot, and respect 1-2 reports/day pacing.")

    return {
        "platform": plat,
        "program_handle": program_handle.strip(),
        "action": action,
        "target_url": target_url,
        "staged_draft_path": staged_draft_path,
        "hitl_invariants": [
            "Never bypass CAPTCHA/Turnstile or login gates.",
            "Pace live submissions to 1-2 verified reports/day on new accounts.",
            "Verify `poc_verified == true` before submitting.",
        ],
        "browser_steps": steps,
    }


TOOLS_SCHEMA: list[dict[str, Any]] = [
    {
        "name": "bb_freshness_watch",
        "description": "Poll in-scope GitHub repositories for fresh releases, merged PRs, and commits landed within the last 24-72 hours, ranked by high-bounty attack surface.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "watchlist_path": {"type": "string", "description": "Path to JSON watchlist file"},
                "repos": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional ad-hoc list of 'owner/repo' slugs",
                },
                "freshness_hours": {"type": "integer", "default": 72},
                "min_score": {"type": "integer", "default": 20},
                "out_markdown": {"type": "string"},
            },
        },
    },
    {
        "name": "bb_run_linux_poc",
        "description": "Execute a non-destructive Rust/Node/Python/Ruby/Go verification command inside a hardened ephemeral Linux Docker container (--network=none --cap-drop=ALL) or WSL2 fallback and return a verbatim transcript.",
        "inputSchema": {
            "type": "object",
            "required": ["language", "repo_path", "cmd"],
            "properties": {
                "language": {"type": "string", "enum": ["rust", "node", "python", "ruby", "go"]},
                "repo_path": {"type": "string"},
                "cmd": {"type": "array", "items": {"type": "string"}},
                "timeout_sec": {"type": "number", "default": 120},
                "out_dir": {"type": "string"},
            },
        },
    },
    {
        "name": "bb_package_client_audit",
        "description": "Package verified security findings into a 5-file paid client audit deliverable bundle (Executive Summary, Technical Findings, formula-safe CSV, SARIF 2.1.0, HTML Dashboard).",
        "inputSchema": {
            "type": "object",
            "required": ["client_name", "scope_description", "findings", "out_dir"],
            "properties": {
                "client_name": {"type": "string"},
                "scope_description": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "object"}},
                "out_dir": {"type": "string"},
            },
        },
    },
    {
        "name": "bb_stage_hackerone_draft",
        "description": "Validate a HackerOne report against signal-protection quality gates (<150 char title, poc_verified, CWE/severity) and stage it to disk for /browser submission.",
        "inputSchema": {
            "type": "object",
            "required": [
                "program_handle",
                "asset",
                "weakness_cwe",
                "severity_rating",
                "title",
                "vulnerability_information",
                "impact",
                "poc_verified",
                "out_path",
            ],
            "properties": {
                "program_handle": {"type": "string"},
                "asset": {"type": "string"},
                "weakness_cwe": {"type": "string"},
                "severity_rating": {"type": "string"},
                "title": {"type": "string"},
                "vulnerability_information": {"type": "string"},
                "impact": {"type": "string"},
                "poc_verified": {"type": "boolean"},
                "out_path": {"type": "string"},
                "require_verified_poc": {"type": "boolean", "default": True},
                "eligibility_db_path": {
                    "type": "string",
                    "description": "Optional path to ProgramEligibilityDB SQLite file",
                },
                "poc_transcript": {"type": "string"},
                "report_id": {"type": "string"},
            },
        },
    },
    {
        "name": "bb_browser_handoff_spec",
        "description": "Generate a structured /browser automation handoff spec for HackerOne, Bugcrowd, or Immunefi scope inspection, inbox checking, or draft staging.",
        "inputSchema": {
            "type": "object",
            "required": ["platform", "program_handle", "action"],
            "properties": {
                "platform": {"type": "string", "enum": ["hackerone", "bugcrowd", "immunefi"]},
                "program_handle": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["inspect_scope", "check_inbox", "stage_draft", "submit_approved_draft"],
                },
                "staged_draft_path": {"type": "string"},
                "existing_draft_url": {"type": "string"},
            },
        },
    },
    {
        "name": "bb_lean_formal_verify",
        "description": "Audit and (when Lean 4 / lake is installed) kernel-check RFCHunt's Lean 4 formal security proofs (PolicyGuard, HttpFramingOracle, DotNetPeIntegrity).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lean_dir": {"type": "string", "default": "formal/lean4"},
            },
        },
    },
    {
        "name": "bb_run_all_scan",
        "description": "Invoke RFCHunt's full `--all` (optionally `--all --ensemble --embedded`) unified security audit pipeline on an authorized local repository or target (shell=False, optional in-process embedded mode, dry-run, and Lean 4 formal verification).",
        "inputSchema": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Local repository path or authorized target URL"},
                "output_dir": {"type": "string", "default": "reports"},
                "dry_run": {"type": "boolean", "default": False},
                "ensemble": {"type": "boolean", "default": False},
                "embedded": {"type": "boolean", "default": False},
                "model": {"type": "string", "description": "Optional LLM model override"},
                "program": {"type": "string", "default": "generic"},
                "freshness_hours": {"type": "integer", "default": 72},
                "ensemble_quorum": {"type": "integer", "default": 2},
                "include_lean_verify": {"type": "boolean", "default": True},
                "timeout_sec": {"type": "number", "default": 300},
                "extra_flags": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "bb_gha_workflow_audit",
        "description": "Audit GitHub Actions workflows via Zizmor, Actionlint, gha_agent_auditor, and optional LLM semantic verification inside EnsembleConsensusVoter with SARIF 2.1.0 output.",
        "inputSchema": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Repository root, .github/workflows dir, or workflow YAML path"},
                "embedded": {"type": "boolean", "default": False},
                "model": {"type": "string"},
                "enable_llm_verify": {"type": "boolean", "default": True},
                "program": {"type": "string", "default": "generic"},
                "quorum": {"type": "integer", "default": 2},
                "out_dir": {"type": "string"},
            },
        },
    },
    {
        "name": "bb_atlas_llm_eval",
        "description": "Sync live MITRE ATLAS STIX 2.1 (with ETag cache & golden fallback), synthesize stack-adaptive skills, and evaluate an LLM target across 74-language / low-resource, canary, indirect_exfil, SSRF/tool, and dynamic ATLAS probes (enforces fail-closed AI-in-scope ProgramComplianceContext when program_handle is specified).",
        "inputSchema": {
            "type": "object",
            "required": ["llm_target"],
            "properties": {
                "llm_target": {"type": "string", "description": "'ollama', 'paid', or OpenAI-compatible HTTP(S) URL"},
                "model": {"type": "string"},
                "repo_path": {"type": "string", "description": "Optional repo path for stack-adaptive ATLAS skills"},
                "suites": {"type": "array", "items": {"type": "string"}},
                "refresh_stix": {"type": "boolean", "default": True},
                "concurrency": {"type": "integer", "default": 8},
                "program_handle": {"type": "string", "description": "Optional HackerOne program handle (fails closed unless AI assets are in scope)"},
                "eligibility_db_path": {"type": "string"},
                "researcher_handle": {"type": "string"},
            },
        },
    },
    {
        "name": "bb_run_fast_ooda",
        "description": "Run Loop 3 3-stage parallel OODA triage funnel (ProcessPoolExecutor CPU checks -> ACDSO Pareto/Anomaly top 3-5 -> single-slot OllamaConcurrencyGuard) and optional Loop 4 auto-PoC submission staging.",
        "inputSchema": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Local repository path"},
                "program": {"type": "string", "default": "generic"},
                "cpu_workers": {"type": "integer"},
                "blackboard_db": {
                    "type": "string",
                    "default": "reports/ensemble_hunt/blackboard.sqlite3",
                },
                "out_dir": {"type": "string", "default": "out/fast_ooda"},
                "embedded": {"type": "boolean", "default": False},
                "resume": {"type": "boolean", "default": False},
                "signal_score": {"type": "number", "default": 0.0},
                "eligibility_db_path": {"type": "string"},
                "model": {"type": "string"},
                "trigger_browser": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "bb_rank_programs",
        "description": "Rank UNLOCKED public HackerOne programs via ACDSO-adapted survival, LTR, 6-objective Pareto knee, online bandit & Two-Phase Lane 1/2 knapsack.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "eligibility_db_path": {"type": "string"},
                "min_efficiency_pct": {"type": "number", "default": 80.0},
                "preset": {"type": "string", "enum": ["signal_fast", "balanced", "max_ev"]},
                "capacity": {"type": "integer", "default": 6},
                "budget_minutes": {"type": "number", "default": 120.0},
                "include_deferred": {"type": "boolean", "default": False},
                "use_boost_tie_break": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "bb_score_fresh_commits",
        "description": "Score and prioritize <72h commits/PRs/releases with ACDSO CommitDiffRanker, velocity burst detection, and diff-scoped SurfaceToScannerRouter.",
        "inputSchema": {
            "type": "object",
            "required": ["candidates"],
            "properties": {
                "candidates": {"type": "array", "items": {"type": "object"}},
                "program_scores": {"type": "object"},
                "repo_stars_map": {"type": "object"},
            },
        },
    },
    {
        "name": "bb_cluster_recon_assets",
        "description": "Cluster HTTP recon endpoints and JS bundles via K-Means++ + inductive p95 noise threshold and classify anomalous HTTP responses.",
        "inputSchema": {
            "type": "object",
            "required": ["assets"],
            "properties": {
                "assets": {"type": "array", "items": {"type": "object"}},
                "program_handle": {"type": "string"},
                "eligibility_db_path": {"type": "string"},
                "max_clusters": {"type": "integer", "default": 8},
            },
        },
    },
    {
        "name": "bb_analyze_js_bundles",
        "description": "Analyze JavaScript bundles for hidden API/GraphQL/OIDC endpoints, DOM/postMessage sinks, source map leaks, and scoped recon clustering.",
        "inputSchema": {
            "type": "object",
            "required": ["bundles"],
            "properties": {
                "bundles": {"type": "array", "items": {"type": "object"}},
                "program_handle": {"type": "string"},
                "eligibility_db_path": {"type": "string"},
                "cluster": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "bb_classify_http_responses",
        "description": "Classify anomalous HTTP responses via Welford streaming outlier scoring and optional baseline-vs-probe differential comparison (enforcing program scope allowlist when specified).",
        "inputSchema": {
            "type": "object",
            "required": ["responses"],
            "properties": {
                "responses": {"type": "array", "items": {"type": "object"}},
                "baseline": {"type": "object"},
                "program_handle": {"type": "string"},
                "eligibility_db_path": {"type": "string"},
            },
        },
    },
    {
        "name": "bb_record_hunt_outcome",
        "description": "Record a HackerOne submission triage outcome (TRIAGED, RESOLVED, DUPLICATE, INFORMATIVE, etc.) to update ProgramEligibilityDB ML survival, LTR & bandit models.",
        "inputSchema": {
            "type": "object",
            "required": ["handle", "outcome"],
            "properties": {
                "handle": {"type": "string"},
                "outcome": {"type": "string"},
                "repo": {"type": "string", "default": ""},
                "commit_sha": {"type": "string", "default": ""},
                "lane": {"type": "integer", "default": 1},
                "target_age_hours": {"type": "number", "default": 0.0},
                "signal_delta": {"type": "number", "default": 0.0},
                "bounty_usd": {"type": "number", "default": 0.0},
                "triage_hours_observed": {"type": "number"},
                "cycle_id": {"type": "string", "default": ""},
                "eligibility_db_path": {"type": "string"},
                "update_signal_score": {"type": "number"},
            },
        },
    },
    {
        "name": "bb_run_autonomous_hunt",
        "description": "Invoke RFCHunt's unified master autonomous hunt pipeline (`rfc_hunt_swarm.py --hunt --once --headless-only`) for dry-run planning or a single bounded headless hunt cycle (auto-submit and CAPTCHA bypass strictly forbidden).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "Optional local repository directories to audit"},
                "repos": {"type": "array", "items": {"type": "string"}, "description": "Optional extra 'owner/repo' slugs"},
                "program": {"type": "string", "default": "generic"},
                "sync_public_directory": {"type": "boolean", "default": False},
                "eligibility_db": {"type": "string"},
                "watchlist": {"type": "string"},
                "min_efficiency": {"type": "number", "default": 80.0},
                "portfolio_capacity": {"type": "integer", "default": 6},
                "max_repos": {"type": "integer", "default": 4},
                "out_dir": {"type": "string", "default": "out/autonomous_hunt"},
                "embedded": {"type": "boolean", "default": False},
                "no_llm": {"type": "boolean", "default": False},
                "allow_blocked": {"type": "boolean", "default": False},
                "browser_hunt": {"type": "boolean", "default": False, "description": "Opt-in interactive browser hunt on hunt_url (opens browser for human login/2FA/CAPTCHA; auto-submit strictly forbidden)"},
                "hunt_url": {"type": "string", "description": "Official bug bounty URL (hackerone.com, bugcrowd.com, immunefi.com, intigriti.com)"},
                "cdp_url": {"type": "string", "description": "Optional Chrome/HugOS CDP endpoint (e.g. http://127.0.0.1:9222)"},
                "browser_profile": {"type": "string", "description": "Persistent Chromium profile directory"},
                "login_timeout": {"type": "number", "default": 300.0},
                "swarm": {"type": "boolean", "default": False, "description": "Enable parallel multi-agent swarm auditing across targets"},
                "swarm_workers": {"type": "integer"},
                "dedup_db": {"type": "string", "description": "SQLite WAL database path for processed target SHAs and drafted findings dedup"},
                "force_rescan": {"type": "boolean", "default": False},
                "no_stage_drafts": {"type": "boolean", "default": False},
                "dry_run": {"type": "boolean", "default": True},
                "model": {"type": "string"},
            },
        },
    },
    {
        "name": "bb_sync_public_directory",
        "description": "Sync HackerOne programs (offline JSON snapshot or Public Directory newest-first >=80% efficiency) into ProgramEligibilityDB v2.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "eligibility_db_path": {"type": "string"},
                "snapshot_json": {"type": "string", "description": "Optional offline JSON snapshot file path"},
                "programs": {"type": "array", "items": {"type": "object"}, "description": "Optional inline list of program dicts to upsert offline"},
                "public_directory": {"type": "boolean", "default": False},
                "public_endpoint": {"type": "string"},
                "query": {"type": "string", "default": ""},
                "limit": {"type": "integer", "default": 25},
                "min_efficiency_pct": {"type": "number", "default": 80.0},
                "bounties_only": {"type": "boolean", "default": False},
                "vdp_only": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "bb_qa_drafts",
        "description": "Run RFCHunt's 14-check HackerOne Draft QA Phase checker & deterministic auto-fixer (HTML entities, control chars, code fences, citations, Netlink checks) on a Markdown draft or exported draft snapshots.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "markdown_body": {"type": "string", "description": "Inline Markdown draft body to QA-check and auto-repair"},
                "markdown_file": {"type": "string", "description": "Path to a local Markdown draft file"},
                "snapshots": {"type": "array", "items": {"type": "object"}, "description": "List of HackerOne draft snapshot objects"},
                "title": {"type": "string", "default": ""},
                "report_id": {"type": "integer", "default": 1},
                "program": {"type": "string", "default": ""},
                "verify_sources": {"type": "boolean", "default": False},
                "qa_db_path": {"type": "string"},
                "out_md": {"type": "string"},
                "out_edit_queue": {"type": "string"},
                "include_repaired_body": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "bb_check_drafts",
        "description": "Inspect HackerOne saved drafts and cooldown readiness (`can_submit_draft?`) strictly read-only via seeded queue, offline JSON snapshots, or single-anchor probe (never clicks Submit or Delete).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_path": {"type": "string", "default": "reports/ensemble_hunt/draft_submit_tracker.sqlite3"},
                "qa_db_path": {"type": "string"},
                "probe_id": {"type": "integer", "default": 4243972},
                "probe_only": {"type": "boolean", "default": True},
                "seed_only": {"type": "boolean", "default": True},
                "snapshots": {"type": "array", "items": {"type": "object"}},
                "max_per_day": {"type": "integer", "default": 2},
                "mark_submitted": {"type": "integer"},
                "out_md": {"type": "string"},
            },
        },
    },
]


class BugBountyMCPServer:
    """In-process & stdio JSON-RPC 2.0 MCP server for RFCHunt bug bounty workflows."""

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any]:
        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": SERVER_INFO,
                    "capabilities": {"tools": {}},
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOLS_SCHEMA},
            }

        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments") or {}
            try:
                result_obj = self._dispatch_tool(name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result_obj, indent=2)}],
                        "isError": False,
                    },
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def _dispatch_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "bb_freshness_watch":
            targets: list[WatchTarget] = []
            if args.get("watchlist_path"):
                targets.extend(load_watchlist(args["watchlist_path"]))
            for slug in args.get("repos") or []:
                targets.append(WatchTarget(program="adhoc", repo=str(slug)))
            watcher = FreshnessWatcher(
                api_base=args.get("api_base", "https://api.github.com"),
                state_db=args.get("state_db", "out/freshness_state.db"),
            )
            try:
                report = watcher.poll_watchlist(
                    targets,
                    freshness_hours=int(args.get("freshness_hours", 72)),
                    min_score=int(args.get("min_score", 20)),
                )
            finally:
                watcher.close()
            if args.get("out_markdown"):
                Path(args["out_markdown"]).parent.mkdir(parents=True, exist_ok=True)
                Path(args["out_markdown"]).write_text(
                    render_fresh_hunt_queue_markdown(report), encoding="utf-8"
                )
            return report.to_dict()

        if name == "bb_run_linux_poc":
            runner = LinuxPocRunner(timeout_sec=float(args.get("timeout_sec", 120.0)))
            transcript = runner.run_poc(
                language=str(args["language"]),
                repo_path=str(args["repo_path"]),
                cmd=args["cmd"],
                image_override=args.get("image_override"),
            )
            out = transcript.to_dict()
            if args.get("out_dir"):
                j_path, m_path = save_transcript_bundle(transcript, args["out_dir"])
                out["saved_json"] = str(j_path)
                out["saved_md"] = str(m_path)
            return out

        if name == "bb_package_client_audit":
            packager = ClientAuditPackager()
            bundle = packager.package(
                client_name=str(args["client_name"]),
                scope_description=str(args["scope_description"]),
                findings=list(args["findings"]),
                out_dir=str(args["out_dir"]),
            )
            return bundle.to_dict()

        if name == "bb_stage_hackerone_draft":
            return validate_and_stage_hackerone_draft(
                program_handle=str(args["program_handle"]),
                asset=str(args["asset"]),
                weakness_cwe=str(args["weakness_cwe"]),
                severity_rating=str(args["severity_rating"]),
                title=str(args["title"]),
                vulnerability_information=str(args["vulnerability_information"]),
                impact=str(args["impact"]),
                poc_verified=_coerce_strict_bool(args["poc_verified"]),
                out_path=str(args["out_path"]),
                require_verified_poc=_parse_strict_bool_arg(
                    args.get("require_verified_poc", True),
                    field_name="require_verified_poc",
                ),
                eligibility_db_path=args.get("eligibility_db_path"),
                poc_transcript=str(args.get("poc_transcript") or ""),
                report_id=args.get("report_id"),
            )

        if name == "bb_browser_handoff_spec":
            return build_browser_handoff_spec(
                platform=str(args["platform"]),
                program_handle=str(args["program_handle"]),
                action=str(args["action"]),
                staged_draft_path=args.get("staged_draft_path"),
                existing_draft_url=args.get("existing_draft_url"),
            )

        if name == "bb_lean_formal_verify":
            from engine.lean_formal_verifier import verify_lean_workspace
            return verify_lean_workspace(str(args.get("lean_dir", "formal/lean4"))).to_dict()

        if name == "bb_run_all_scan":
            extra_flags_raw = args.get("extra_flags")
            if extra_flags_raw is not None and (
                isinstance(extra_flags_raw, (str, bytes, bytearray, dict))
                or not isinstance(extra_flags_raw, (list, tuple))
            ):
                raise TypeError("extra_flags must be a list of flag strings, not str/bytes/dict.")
            return run_rfchunt_all_scan(
                target=str(args["target"]),
                output_dir=str(args.get("output_dir", "reports")),
                dry_run=_parse_strict_bool_arg(args.get("dry_run", False), field_name="dry_run"),
                ensemble=_parse_strict_bool_arg(args.get("ensemble", False), field_name="ensemble"),
                program=str(args.get("program", "generic")),
                freshness_hours=args.get("freshness_hours", 72),
                ensemble_quorum=args.get("ensemble_quorum", 2),
                embedded=_parse_strict_bool_arg(args.get("embedded", False), field_name="embedded"),
                model=args.get("model"),
                include_lean_verify=_parse_strict_bool_arg(
                    args.get("include_lean_verify", True),
                    field_name="include_lean_verify",
                ),
                timeout_sec=args.get("timeout_sec", 300.0),
                extra_flags=list(extra_flags_raw or []),
            )

        if name == "bb_gha_workflow_audit":
            from engine.ensemble_orchestrator import EnsembleOrchestrator

            embedded_flag = _parse_strict_bool_arg(args.get("embedded", False), field_name="embedded")
            quorum_raw = args.get("quorum", 2)
            if isinstance(quorum_raw, bool):
                raise TypeError("quorum must be an integer, not bool.")
            enable_llm_raw = _parse_strict_bool_arg(
                args.get("enable_llm_verify", True),
                field_name="enable_llm_verify",
            )
            orch = EnsembleOrchestrator(
                program=str(args.get("program", "generic")),
                quorum=int(quorum_raw),
                exhaustive_default=True,
                embedded=embedded_flag,
                model=args.get("model"),
                enable_llm_verify=(not embedded_flag and enable_llm_raw),
                gha_only=True,
            )
            rep = orch.run(
                str(args["target"]),
                out_dir=args.get("out_dir"),
            )
            payload = rep.to_dict()
            payload["sarif"] = rep.to_sarif()
            payload["telemetry"] = orch.last_telemetry
            return payload

        if name == "bb_atlas_llm_eval":
            from engine.atlas_llm_evaluator import AtlasLLMEvaluator, LLMTargetAdapter

            elig_db = None
            prog_h = str(args.get("program_handle") or "").strip() or None
            if prog_h:
                from engine.program_eligibility_db import ProgramEligibilityDB

                elig_db = ProgramEligibilityDB(db_path=args.get("eligibility_db_path"))
            adapter = LLMTargetAdapter(
                target=str(args["llm_target"]),
                model=args.get("model"),
            )
            evaluator = AtlasLLMEvaluator(
                adapter=adapter,
                concurrency=int(args.get("concurrency", 8)),
            )
            suites = list(args.get("suites") or ["low_resource", "canary", "indirect_exfil", "ssrf_tool", "atlas_dynamic"])
            return evaluator.evaluate(
                suites=suites,
                repo_path=args.get("repo_path"),
                refresh_stix=bool(args.get("refresh_stix", True)),
                program_handle=prog_h,
                eligibility_db=elig_db,
                researcher_handle=args.get("researcher_handle"),
            ).to_dict()

        if name == "bb_run_fast_ooda":
            target = str(args.get("target") or "").strip()
            if not target:
                raise ValueError("target is required for bb_run_fast_ooda.")
            from engine.ensemble_orchestrator import EnsembleOrchestrator
            from engine.program_eligibility_db import ProgramEligibilityDB

            program = str(args.get("program") or "generic").strip() or "generic"
            embedded_flag = _coerce_strict_bool(args.get("embedded", False))
            cpu_workers_val = args.get("cpu_workers")
            cpu_workers_int = int(cpu_workers_val) if cpu_workers_val is not None else None
            orch = EnsembleOrchestrator(
                program=program,
                embedded=embedded_flag,
                model=args.get("model"),
                max_workers=(max(1, cpu_workers_int) if cpu_workers_int else 4),
            )
            elig_path = args.get("eligibility_db_path") or os.environ.get("RFCHUNT_ELIGIBILITY_DB")
            elig_db = (
                ProgramEligibilityDB(str(elig_path).strip())
                if elig_path and str(elig_path).strip()
                else None
            )
            eff_out_dir = str(args.get("out_dir") or "out/fast_ooda").strip() or "out/fast_ooda"
            ooda_res = orch.run_fast_parallel_ooda(
                target,
                program=program,
                blackboard_db=str(args.get("blackboard_db") or "reports/ensemble_hunt/blackboard.sqlite3"),
                max_cpu_workers=cpu_workers_int,
                resume=_coerce_strict_bool(args.get("resume", False)),
                signal_score=float(args.get("signal_score", 0.0) or 0.0),
                eligibility_db=elig_db,
                out_dir=eff_out_dir,
                trigger_browser=_coerce_strict_bool(args.get("trigger_browser", False)),
            )
            out_dir_path = Path(eff_out_dir)
            out_dir_path.mkdir(parents=True, exist_ok=True)
            report_path = out_dir_path / "fast_ooda_report.json"
            report_path.write_text(json.dumps(ooda_res, indent=2, default=str), encoding="utf-8")
            ooda_res["out_dir"] = str(out_dir_path)
            ooda_res["report_path"] = str(report_path)
            return ooda_res

        if name == "bb_rank_programs":
            from engine.ml_program_selector import rank_hackerone_programs

            res = rank_hackerone_programs(
                db_path=args.get("eligibility_db_path"),
                min_efficiency_pct=float(args.get("min_efficiency_pct", 80.0)),
                preset=args.get("preset"),
                capacity=int(args.get("capacity", 6)),
                budget_minutes=float(args.get("budget_minutes", 120.0)),
                include_deferred=_coerce_strict_bool(args.get("include_deferred", False)),
            )
            if _coerce_strict_bool(args.get("use_boost_tie_break", False)) and res.get("tie_break_needed"):
                from engine.boost_decision_adapter import BoostDecisionAdapter

                tb = BoostDecisionAdapter().tie_break_pareto_knee(res.get("ranked_programs") or [])
                res["boost_tie_break"] = {k: v for k, v in tb.items() if k != "ordered"}
                if tb.get("tie_broken") and tb.get("ordered"):
                    res["ranked_programs"] = tb["ordered"]
            return res

        if name == "bb_score_fresh_commits":
            from engine.ml_diff_and_recon_ranker import CommitDiffRanker

            cands = list(args.get("candidates") or [])
            ranker = CommitDiffRanker()
            ranked = ranker.rank_candidates(
                cands,
                program_scores=args.get("program_scores"),
                repo_stars_map=args.get("repo_stars_map"),
            )
            return {
                "total_candidates": len(ranked),
                "ranked_candidates": ranked,
            }

        if name == "bb_cluster_recon_assets":
            from engine.ml_diff_and_recon_ranker import ReconAssetClusterer

            assets = list(args.get("assets") or [])
            compliance_ctx = None
            prog_h = str(args.get("program_handle") or "").strip()
            if prog_h:
                from engine.program_eligibility_db import ProgramEligibilityDB
                from engine.request_hygiene import build_program_compliance_context

                elig_db = ProgramEligibilityDB(db_path=args.get("eligibility_db_path"))
                compliance_ctx = build_program_compliance_context(prog_h, eligibility_db=elig_db)

            clusterer = ReconAssetClusterer(max_clusters=int(args.get("max_clusters", 8)))
            return clusterer.cluster_and_prioritize(assets, compliance_ctx=compliance_ctx)

        if name == "bb_analyze_js_bundles":
            from engine.ml_diff_and_recon_ranker import JavaScriptBundleAnalyzer

            bundles = list(args.get("bundles") or [])
            compliance_ctx = None
            prog_h = str(args.get("program_handle") or "").strip()
            if prog_h:
                from engine.program_eligibility_db import ProgramEligibilityDB
                from engine.request_hygiene import build_program_compliance_context

                elig_db = ProgramEligibilityDB(db_path=args.get("eligibility_db_path"))
                compliance_ctx = build_program_compliance_context(prog_h, eligibility_db=elig_db)

            return JavaScriptBundleAnalyzer().analyze_bundles(
                bundles,
                compliance_ctx=compliance_ctx,
                cluster=_coerce_strict_bool(args.get("cluster", True)),
            )

        if name == "bb_classify_http_responses":
            from engine.ml_diff_and_recon_ranker import HTTPResponseAnomalyClassifier

            responses = list(args.get("responses") or [])
            compliance_ctx = None
            prog_h = str(args.get("program_handle") or "").strip()
            if prog_h:
                from engine.program_eligibility_db import ProgramEligibilityDB
                from engine.request_hygiene import build_program_compliance_context

                elig_db = ProgramEligibilityDB(db_path=args.get("eligibility_db_path"))
                compliance_ctx = build_program_compliance_context(prog_h, eligibility_db=elig_db)

            classified = HTTPResponseAnomalyClassifier().classify_responses(
                responses,
                baseline=args.get("baseline") if isinstance(args.get("baseline"), dict) else None,
                compliance_ctx=compliance_ctx,
            )
            return {
                "total_responses": len(classified),
                "anomalous_count": sum(1 for r in classified if r["is_anomalous"]),
                "classified_responses": classified,
            }

        if name == "bb_record_hunt_outcome":
            from engine.program_eligibility_db import ProgramEligibilityDB

            db = ProgramEligibilityDB(db_path=args.get("eligibility_db_path"))
            rec = db.record_hunt_outcome(
                handle=str(args["handle"]),
                outcome=str(args["outcome"]),
                repo=str(args.get("repo") or ""),
                commit_sha=str(args.get("commit_sha") or ""),
                lane=int(args.get("lane", 1)),
                target_age_hours=float(args.get("target_age_hours", 0.0)),
                signal_delta=float(args.get("signal_delta", 0.0)),
                bounty_usd=float(args.get("bounty_usd", 0.0)),
                triage_hours_observed=args.get("triage_hours_observed"),
                cycle_id=str(args.get("cycle_id") or ""),
            )
            acct = None
            if args.get("update_signal_score") is not None:
                acct = db.update_account_state(
                    signal_established=True,
                    signal_score=float(args["update_signal_score"]),
                ).to_dict()
            return {"status": "recorded", "outcome": rec.to_dict(), "account_state": acct}

        if name == "bb_run_autonomous_hunt":
            import rfc_hunt_swarm
            from engine.hackerone_porter import validate_bug_hunt_url

            use_browser_hunt = _coerce_strict_bool(args.get("browser_hunt", False))
            swarm_argv: list[str] = ["--hunt", "--once", "--json"]
            if use_browser_hunt:
                swarm_argv.append("--browser-hunt")
            else:
                swarm_argv.append("--headless-only")
            if args.get("hunt_url"):
                validated_h_url = validate_bug_hunt_url(str(args["hunt_url"]).strip())
                swarm_argv.extend(["--hunt-url", validated_h_url])
            if args.get("cdp_url"):
                swarm_argv.extend(["--cdp-url", str(args["cdp_url"]).strip()])
            if args.get("browser_profile"):
                swarm_argv.extend(["--browser-profile", str(args["browser_profile"]).strip()])
            if args.get("login_timeout") is not None:
                swarm_argv.extend(["--login-timeout", str(float(args["login_timeout"]))])
            if _coerce_strict_bool(args.get("swarm", False)):
                swarm_argv.append("--swarm")
            if args.get("swarm_workers") is not None:
                swarm_argv.extend(["--swarm-workers", str(max(1, int(args["swarm_workers"])))])
            if args.get("dedup_db"):
                swarm_argv.extend(["--dedup-db", str(args["dedup_db"]).strip()])
            if _coerce_strict_bool(args.get("force_rescan", False)):
                swarm_argv.append("--force-rescan")
            if _coerce_strict_bool(args.get("no_stage_drafts", False)):
                swarm_argv.append("--no-stage-drafts")
            for t in args.get("targets") or []:
                t_s = str(t).strip()
                if t_s:
                    if t_s.startswith("-"):
                        raise ValueError(f"Invalid target {t_s!r}: must not start with '-'.")
                    swarm_argv.extend(["--hunt-target", t_s])
            for r in args.get("repos") or []:
                r_s = str(r).strip()
                if r_s:
                    if r_s.startswith("-"):
                        raise ValueError(f"Invalid repo slug {r_s!r}: must not start with '-'.")
                    swarm_argv.extend(["--hunt-repo", r_s])
            if args.get("program"):
                swarm_argv.extend(["--program", str(args["program"]).strip()])
            if _coerce_strict_bool(args.get("sync_public_directory", False)):
                swarm_argv.append("--sync-public-directory")
            if args.get("eligibility_db"):
                swarm_argv.extend(["--eligibility-db", str(args["eligibility_db"])])
            if args.get("watchlist"):
                swarm_argv.extend(["--watchlist", str(args["watchlist"])])
            if args.get("min_efficiency") is not None:
                swarm_argv.extend(["--min-efficiency", str(float(args["min_efficiency"]))])
            if args.get("portfolio_capacity") is not None:
                swarm_argv.extend(["--portfolio-capacity", str(max(1, int(args["portfolio_capacity"])))])
            if args.get("max_repos") is not None:
                swarm_argv.extend(["--max-repos", str(max(1, int(args["max_repos"])))])
            if args.get("out_dir"):
                swarm_argv.extend(["--out", str(args["out_dir"])])
            if _coerce_strict_bool(args.get("embedded", False)):
                swarm_argv.append("--embedded")
            if _coerce_strict_bool(args.get("no_llm", False)):
                swarm_argv.append("--no-llm")
            if _coerce_strict_bool(args.get("allow_blocked", False)):
                swarm_argv.append("--allow-blocked")
            if _coerce_strict_bool(args.get("dry_run", True)):
                swarm_argv.append("--dry-run")
            if args.get("model"):
                swarm_argv.extend(["--model", str(args["model"]).strip()])

            parsed_ns = rfc_hunt_swarm.parse_swarm_arguments(swarm_argv)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = rfc_hunt_swarm.cmd_autonomous_hunt(parsed_ns, raw_argv=swarm_argv)
            raw_out = buf.getvalue().strip()
            parsed_payload: dict[str, Any] = {}
            if raw_out:
                try:
                    loaded = json.loads(raw_out)
                    if isinstance(loaded, dict):
                        parsed_payload = loaded
                except ValueError:
                    start_idx = raw_out.find("{")
                    end_idx = raw_out.rfind("}")
                    if start_idx != -1 and end_idx > start_idx:
                        try:
                            loaded = json.loads(raw_out[start_idx : end_idx + 1])
                            if isinstance(loaded, dict):
                                parsed_payload = loaded
                        except ValueError:
                            parsed_payload = {"raw_output": raw_out[:2000]}
                    else:
                        parsed_payload = {"raw_output": raw_out[:2000]}
            return {
                **parsed_payload,
                "status": parsed_payload.get("status") or ("completed" if rc == 0 else "error"),
                "returncode": int(rc),
                "invoked_via": "rfc_hunt_swarm.py --hunt",
                "swarm_argv": swarm_argv,
                "auto_submit_forbidden": True,
                "captcha_bypass_forbidden": True,
            }

        if name == "bb_sync_public_directory":
            from engine.program_eligibility_db import ProgramEligibilityDB

            db = ProgramEligibilityDB(db_path=args.get("eligibility_db_path"))
            upserted: list[str] = []
            items: list[dict[str, Any]] = []
            if args.get("snapshot_json"):
                raw_data = json.loads(Path(str(args["snapshot_json"])).read_text(encoding="utf-8"))
                raw_items = raw_data.get("programs", raw_data) if isinstance(raw_data, dict) else raw_data
                if isinstance(raw_items, list):
                    items.extend(x for x in raw_items if isinstance(x, dict))
            if isinstance(args.get("programs"), list):
                items.extend(x for x in args["programs"] if isinstance(x, dict))

            for item in items:
                handle = str(item.get("handle") or "").strip().lower()
                if not handle:
                    continue
                status = str(item.get("status") or "UNLOCKED").strip().upper()
                db.upsert(
                    handle,
                    status,
                    signal_required=item.get("signal_required"),
                    bounty_min_usd=item.get("bounty_min_usd"),
                    bounty_max_usd=item.get("bounty_max_usd"),
                    submit_url=str(item.get("submit_url") or ""),
                    scope_summary=str(item.get("scope_summary") or ""),
                    notes=str(item.get("notes") or ""),
                    launched_at_utc=str(item.get("launched_at_utc") or ""),
                    response_efficiency_pct=item.get("response_efficiency_pct"),
                    first_response_hours=item.get("first_response_hours"),
                    triage_hours=item.get("triage_hours"),
                    bounty_hours=item.get("bounty_hours"),
                    resolved_count=int(item.get("resolved_count") or 0),
                    offers_bounties=item.get("offers_bounties"),
                    is_vdp=item.get("is_vdp"),
                    gold_standard=bool(item.get("gold_standard", False)),
                    fast_payments=bool(item.get("fast_payments", False)),
                    submission_state=str(item.get("submission_state") or "open"),
                    in_scope_assets=item.get("in_scope_assets") or (),
                    in_scope_repos=item.get("in_scope_repos") or (),
                    out_of_scope_assets=item.get("out_of_scope_assets") or (),
                    roe_automated_prohibited=item.get("roe_automated_prohibited"),
                    roe_max_rps=item.get("roe_max_rps"),
                )
                upserted.append(handle)

            if _coerce_strict_bool(args.get("public_directory", False)):
                from engine.hackerone_porter import HackerOnePublicDirectoryClient

                pub_client = HackerOnePublicDirectoryClient(endpoint_url=args.get("public_endpoint"))
                pub_res = pub_client.fetch_and_sync_directory(
                    eligibility_db=db,
                    query=str(args.get("query") or ""),
                    limit=max(1, int(args.get("limit", 25))),
                    min_efficiency_pct=float(args.get("min_efficiency_pct", 80.0)),
                    bounties_only=_coerce_strict_bool(args.get("bounties_only", False)),
                    vdp_only=_coerce_strict_bool(args.get("vdp_only", False)),
                )
                upserted.extend(pub_res.get("upserted") or [])

            return {
                "status": "completed",
                "upserted_count": len(upserted),
                "upserted": upserted,
                "summary_counts": db.summary_counts(),
                "db_path": str(db.db_path),
            }

        if name == "bb_qa_drafts":
            from engine.draft_qa_checker import DraftQAChecker, DraftQATrackerDB

            qa_db = DraftQATrackerDB(args.get("qa_db_path") or "reports/ensemble_hunt/draft_qa_tracker.sqlite3")
            qa_checker = DraftQAChecker(db=qa_db)
            snapshots: list[dict[str, Any]] = []
            if isinstance(args.get("snapshots"), list) and args["snapshots"]:
                snapshots = [s for s in args["snapshots"] if isinstance(s, dict)]
            elif args.get("markdown_file"):
                md_path = Path(str(args["markdown_file"]))
                snapshots = [
                    {
                        "id": int(args.get("report_id", 1)),
                        "title": str(args.get("title") or md_path.stem),
                        "team_handle": str(args.get("program") or ""),
                        "state": "Draft",
                        "vulnerability_information": md_path.read_text(encoding="utf-8"),
                    }
                ]
            elif args.get("markdown_body") is not None:
                snapshots = [
                    {
                        "id": int(args.get("report_id", 1)),
                        "title": str(args.get("title") or "Draft Audit"),
                        "team_handle": str(args.get("program") or ""),
                        "state": "Draft",
                        "vulnerability_information": str(args["markdown_body"]),
                    }
                ]
            else:
                raise ValueError("Provide markdown_body, markdown_file, or snapshots for bb_qa_drafts.")

            summary = qa_checker.audit_snapshots(
                snapshots,
                verify_sources=_coerce_strict_bool(args.get("verify_sources", False)),
                out_md=args.get("out_md"),
                out_edit_queue=args.get("out_edit_queue"),
            )
            return summary.to_dict(
                include_bodies=_coerce_strict_bool(args.get("include_repaired_body", True))
            )

        if name == "bb_check_drafts":
            from engine.draft_qa_checker import DraftQATrackerDB
            from engine.draft_submit_checker import (
                DraftSubmitChecker,
                DraftSubmitTrackerDB,
            )

            db_path = str(args.get("db_path") or "reports/ensemble_hunt/draft_submit_tracker.sqlite3")
            db = DraftSubmitTrackerDB(db_path)
            db.seed_default_queue()
            qa_db_arg = args.get("qa_db_path")
            if qa_db_arg and Path(str(qa_db_arg)).exists():
                qa_map = DraftQATrackerDB(str(qa_db_arg)).get_qa_status_map()
                if qa_map:
                    db.sync_qa_statuses(qa_map)

            if args.get("mark_submitted") is not None:
                rid = int(args["mark_submitted"])
                db.mark_submitted(rid)
                return {
                    "status": "marked_submitted",
                    "report_id": rid,
                    "submitted_today": db.get_submitted_today(),
                    "auto_submit_forbidden": True,
                }

            if isinstance(args.get("snapshots"), list) and args["snapshots"]:
                checker = DraftSubmitChecker(db=db, session_cookie="")
                summary = checker.ingest_snapshots(
                    [s for s in args["snapshots"] if isinstance(s, dict)],
                    probe_report_id=int(args.get("probe_id", 4243972)),
                    max_per_day=int(args.get("max_per_day", 2)),
                    out_md=args.get("out_md"),
                )
                return {**summary.to_dict(), "auto_submit_forbidden": True, "auto_delete_forbidden": True}

            if _coerce_strict_bool(args.get("seed_only", True)):
                drafts = db.list_drafts(only_drafts=True)
                return {
                    "status": "seeded_queue",
                    "total_drafts": len(drafts),
                    "drafts": [d.__dict__ for d in drafts],
                    "auto_submit_forbidden": True,
                    "auto_delete_forbidden": True,
                }

            cookie_val = os.environ.get("HACKERONE_SESSION_COOKIE", "").strip()
            checker = DraftSubmitChecker(db=db, session_cookie=cookie_val)
            summary = checker.check(
                probe_report_id=int(args.get("probe_id", 4243972)),
                probe_first=True,
                probe_only=_coerce_strict_bool(args.get("probe_only", True)),
                max_per_day=int(args.get("max_per_day", 2)),
                out_md=args.get("out_md"),
            )
            return {**summary.to_dict(), "auto_submit_forbidden": True, "auto_delete_forbidden": True}

        raise ValueError(f"Unknown tool: {name}")


def serve_stdio() -> None:
    """Runs the Bug Bounty MCP Server over line-delimited JSON-RPC 2.0 stdio."""
    server = BugBountyMCPServer()
    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            req = json.loads(stripped)
            resp = server.handle_request(req)
        except Exception as exc:  # noqa: BLE001
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    serve_stdio()
