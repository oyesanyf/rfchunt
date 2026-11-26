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

import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from engine.client_audit_packager import ClientAuditPackager
from engine.freshness_watcher import (
    FreshnessWatcher,
    WatchTarget,
    load_watchlist,
    render_fresh_hunt_queue_markdown,
)
from engine.host_containment import silent_subprocess_run
from engine.linux_poc_runner import LinuxPocRunner, save_transcript_bundle, validate_command_tokens


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
    model: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
    swarm_script: Optional[Path] = None,
) -> List[str]:
    """Builds a fail-closed argv invoking `rfc_hunt_swarm.py --all [--ensemble] [--embedded] <target>` (`shell=False`)."""
    t = str(target).strip()
    if not t:
        raise ValueError("target is required for bb_run_all_scan.")
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


def _probe_toolchain_status_safe(lean_dir: Optional[Path], embedded: bool) -> Dict[str, Any]:
    """Return non-destructive backend availability status, degrading gracefully on probe errors."""
    if embedded:
        try:
            from engine.ensemble_orchestrator import _embedded_toolchain_status

            return _embedded_toolchain_status()
        except Exception:
            return {}
    try:
        from engine.linux_poc_runner import probe_optional_backends

        eff_lean = lean_dir if (lean_dir is not None and lean_dir.is_dir()) else None
        return probe_optional_backends(lean_dir=eff_lean, timeout_sec=2.5)
    except Exception as exc:
        return {
            "docker": {"available": False, "status": "unavailable", "reason": str(exc), "path_or_module": None},
            "wsl2": {"available": False, "status": "unavailable", "reason": str(exc), "path_or_module": None},
            "lean4": {"available": False, "status": "unavailable", "reason": str(exc), "path_or_module": None},
            "rfchunt_lean_oracle": {"available": False, "status": "unavailable", "reason": str(exc), "path_or_module": None},
            "angr": {"available": False, "status": "unavailable", "reason": str(exc), "path_or_module": None},
            "klee": {"available": False, "status": "unavailable", "reason": str(exc), "path_or_module": None},
            "semgrep": {"available": False, "status": "unavailable", "reason": str(exc), "path_or_module": None},
        }


def _merge_lean_domain_enrichment(
    base_lean: Optional[Dict[str, Any]],
    ens_lean: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
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
    model: Optional[str] = None,
    include_lean_verify: bool = True,
    timeout_sec: float = 300.0,
    extra_flags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Executes RFCHunt `--all` (optionally `--ensemble` / `--embedded`) safely (`shell=False`) plus Lean 4 check."""
    argv = build_rfchunt_all_argv(
        target=target,
        output_dir=output_dir,
        dry_run=dry_run,
        ensemble=ensemble,
        program=program,
        freshness_hours=freshness_hours,
        ensemble_quorum=ensemble_quorum,
        embedded=embedded,
        model=model,
        extra_flags=extra_flags,
    )
    lean_dir = Path(__file__).resolve().parent / "formal" / "lean4"
    lean_summary: Optional[Dict[str, Any]] = None
    if include_lean_verify:
        from engine.lean_formal_verifier import verify_lean_workspace
        if lean_dir.is_dir():
            lean_summary = verify_lean_workspace(lean_dir).to_dict()

    mode = "--all --ensemble" if ensemble else "--all"
    if embedded:
        mode = f"{mode} --embedded"
    if dry_run:
        tc_status = _probe_toolchain_status_safe(lean_dir, bool(embedded))
        dry_payload: Dict[str, Any] = {
            "status": "dry_run_ready",
            "mode": mode,
            "argv": argv,
            "target": target,
            "output_dir": output_dir,
            "program": program,
            "freshness_hours": freshness_hours,
            "embedded": bool(embedded),
            "model": model,
            "lean_verification": lean_summary,
            "toolchain_status": tc_status,
        }
        if ensemble:
            dry_payload["ensemble"] = {
                "target": target,
                "program": str(program).strip() or "generic",
                "freshness_hours": int(freshness_hours),
                "quorum": max(1, int(ensemble_quorum)),
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
            freshness_hours=freshness_hours,
            quorum=ensemble_quorum,
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
        timeout=timeout_sec,
    )
    payload: Dict[str, Any] = {
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
    ens_data: Optional[Dict[str, Any]] = None
    if ensemble and proc.returncode == 0:
        out_path = Path(output_dir)
        ens_report_path = out_path / "ensemble_report.json"
        combined_json_path = out_path / "combined_audit_summary.json"
        if ens_report_path.is_file():
            try:
                loaded = json.loads(ens_report_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    ens_data = loaded
            except Exception:
                ens_data = None
        if ens_data is None and combined_json_path.is_file():
            try:
                comb = json.loads(combined_json_path.read_text(encoding="utf-8"))
                if isinstance(comb, dict) and isinstance(comb.get("ensemble"), dict):
                    ens_data = comb["ensemble"]
            except Exception:
                ens_data = None
        if ens_data is None and (proc.stdout or "").strip():
            try:
                parsed_stdout = json.loads((proc.stdout or "").strip())
                if isinstance(parsed_stdout, dict) and isinstance(parsed_stdout.get("ensemble"), dict):
                    ens_data = parsed_stdout["ensemble"]
            except Exception:
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
                "freshness_hours": int(freshness_hours),
                "quorum": max(1, int(ensemble_quorum)),
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


def validate_and_stage_hackerone_draft(
    *,
    program_handle: str,
    asset: str,
    weakness_cwe: str,
    severity_rating: str,
    title: str,
    vulnerability_information: str,
    impact: str,
    poc_verified: bool,
    out_path: str,
    require_verified_poc: bool = True,
) -> Dict[str, Any]:
    """
    Validates a bug bounty draft against strict signal-protection gates before staging
    it for browser review/submission.
    """
    issues: List[str] = []
    if not program_handle.strip():
        issues.append("program_handle is required.")
    if not asset.strip():
        issues.append("in-scope asset is required.")
    if not title.strip():
        issues.append("title is required.")
    elif len(title.strip()) >= HACKERONE_MAX_TITLE_LEN:
        issues.append(
            f"title length ({len(title.strip())}) must be < {HACKERONE_MAX_TITLE_LEN} characters."
        )
    if len(vulnerability_information.strip()) < 100:
        issues.append("vulnerability_information is too short (< 100 chars).")
    if not impact.strip():
        issues.append("impact section is required.")
    if severity_rating not in ("None", "Low", "Medium", "High", "Critical"):
        issues.append(
            f"severity_rating {severity_rating!r} must be one of None/Low/Medium/High/Critical."
        )
    if require_verified_poc and not poc_verified:
        issues.append(
            "poc_verified is False — run `bb_run_linux_poc` first to attach verbatim Linux runtime output before submission."
        )

    from engine.ensemble_orchestrator import evaluate_vendor_threat_model

    tm = evaluate_vendor_threat_model(
        title=title,
        summary=f"{vulnerability_information}\n{impact}",
        file_path=asset,
        program=program_handle,
        poc_verified=bool(poc_verified),
    )
    if not tm.passed:
        issues.extend(tm.reasons)

    status = "staged_ready" if not issues else "blocked_quality_gate"
    payload = {
        "status": status,
        "quality_gate_issues": issues,
        "program_handle": program_handle.strip(),
        "submit_url": SUPPORTED_PLATFORMS["hackerone"].format(handle=program_handle.strip()),
        "asset": asset.strip(),
        "weakness_cwe": weakness_cwe.strip(),
        "severity_rating": severity_rating,
        "title": title.strip(),
        "title_length": len(title.strip()),
        "vulnerability_information": vulnerability_information,
        "impact": impact,
        "poc_verified": bool(poc_verified),
    }

    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {
        "status": status,
        "staged_file": str(dest),
        "quality_gate_issues": issues,
        "submit_url": payload["submit_url"],
    }


def build_browser_handoff_spec(
    *,
    platform: str,
    program_handle: str,
    action: str,
    staged_draft_path: Optional[str] = None,
    existing_draft_url: Optional[str] = None,
) -> Dict[str, Any]:
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


TOOLS_SCHEMA: List[Dict[str, Any]] = [
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
        "description": "Sync live MITRE ATLAS STIX 2.1 (with ETag cache & golden fallback), synthesize stack-adaptive skills, and evaluate an LLM target across 74-language / low-resource, canary, SSRF/tool, and dynamic ATLAS probes.",
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
            },
        },
    },
]


class BugBountyMCPServer:
    """In-process & stdio JSON-RPC 2.0 MCP server for RFCHunt bug bounty workflows."""

    def handle_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
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
            except Exception as exc:
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

    def _dispatch_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name == "bb_freshness_watch":
            targets: List[WatchTarget] = []
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
                cmd=list(args["cmd"]),
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
                poc_verified=bool(args["poc_verified"]),
                out_path=str(args["out_path"]),
                require_verified_poc=bool(args.get("require_verified_poc", True)),
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
            return run_rfchunt_all_scan(
                target=str(args["target"]),
                output_dir=str(args.get("output_dir", "reports")),
                dry_run=bool(args.get("dry_run", False)),
                ensemble=bool(args.get("ensemble", False)),
                program=str(args.get("program", "generic")),
                freshness_hours=int(args.get("freshness_hours", 72)),
                ensemble_quorum=int(args.get("ensemble_quorum", 2)),
                embedded=bool(args.get("embedded", False)),
                model=args.get("model"),
                include_lean_verify=bool(args.get("include_lean_verify", True)),
                timeout_sec=float(args.get("timeout_sec", 300.0)),
                extra_flags=list(args.get("extra_flags") or []),
            )

        if name == "bb_gha_workflow_audit":
            from engine.ensemble_orchestrator import EnsembleOrchestrator

            embedded_flag = bool(args.get("embedded", False))
            orch = EnsembleOrchestrator(
                program=str(args.get("program", "generic")),
                quorum=int(args.get("quorum", 2)),
                exhaustive_default=True,
                embedded=embedded_flag,
                model=args.get("model"),
                enable_llm_verify=(not embedded_flag and bool(args.get("enable_llm_verify", True))),
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

            adapter = LLMTargetAdapter(
                target=str(args["llm_target"]),
                model=args.get("model"),
            )
            evaluator = AtlasLLMEvaluator(
                adapter=adapter,
                concurrency=int(args.get("concurrency", 8)),
            )
            suites = list(args.get("suites") or ["low_resource", "canary", "ssrf_tool", "atlas_dynamic"])
            return evaluator.evaluate(
                suites=suites,
                repo_path=args.get("repo_path"),
                refresh_stix=bool(args.get("refresh_stix", True)),
            ).to_dict()

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
        except Exception as exc:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    serve_stdio()
