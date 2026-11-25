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
from engine.linux_poc_runner import LinuxPocRunner, save_transcript_bundle


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
