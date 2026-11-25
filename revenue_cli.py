"""
RFCHunt Revenue Operations CLI (`revenue_cli.py`).
==================================================
Provides three focused, revenue-unblocking CLI commands:
  - `freshness-watch` : Poll in-scope GitHub repos for <72h releases/PRs/commits
  - `linux-poc`       : Execute Rust/Node/Python/Ruby/Go PoCs inside hardened Linux Docker/WSL2
  - `package-audit`   : Generate 5-file paid client security audit deliverable bundle
  - `bugbounty-mcp`   : Launch the Bug Bounty MCP stdio server (`bugbounty_mcp_server.py`)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional, Sequence

from engine.client_audit_packager import ClientAuditPackager
from engine.freshness_watcher import (
    FreshnessWatcher,
    WatchTarget,
    load_watchlist,
    render_fresh_hunt_queue_markdown,
)
from engine.linux_poc_runner import LinuxPocRunner, save_transcript_bundle


REVENUE_SUBCOMMANDS = {"freshness-watch", "linux-poc", "package-audit", "bugbounty-mcp", "lean-verify"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rfchunt-revenue",
        description="RFCHunt Revenue Engine CLI (Freshness Watcher, Linux PoC Runner, Client Audit Packager, Bug Bounty MCP).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_fresh = sub.add_parser("freshness-watch", help="Poll GitHub watchlist for fresh <72h code changes.")
    p_fresh.add_argument(
        "--watchlist",
        default="config/freshness_watchlist.example.json",
        help="Path to JSON watchlist file.",
    )
    p_fresh.add_argument("--repo", action="append", default=[], help="Ad-hoc 'owner/repo' slug (repeatable).")
    p_fresh.add_argument("--hours", type=int, default=72, help="Freshness lookback window in hours (default: 72).")
    p_fresh.add_argument("--min-score", type=int, default=20, help="Minimum attack-surface risk score (0-100).")
    p_fresh.add_argument("--out", default="out/fresh_hunt_queue", help="Output path stem (writes .json and .md).")
    p_fresh.add_argument("--mark-seen", action="store_true", help="Record returned SHAs as seen in SQLite.")

    p_poc = sub.add_parser("linux-poc", help="Run a PoC command inside a hardened Linux Docker container or WSL2.")
    p_poc.add_argument("--lang", required=True, choices=["rust", "node", "python", "ruby", "go"])
    p_poc.add_argument("--repo", required=True, help="Local repository directory to mount read-only.")
    p_poc.add_argument("--timeout", type=float, default=120.0, help="Execution timeout in seconds.")
    p_poc.add_argument("--image", default=None, help="Optional Docker image override.")
    p_poc.add_argument("--out", default="out/poc_transcripts", help="Directory to save JSON + Markdown transcript.")
    p_poc.add_argument("--stem", default="poc_transcript", help="Output filename stem.")
    p_poc.add_argument("cmd", nargs=argparse.REMAINDER, help="Command tokens after `--` (e.g., -- cargo test).")

    p_pkg = sub.add_parser("package-audit", help="Package verified findings into a 5-file client audit bundle.")
    p_pkg.add_argument("--client", required=True, help="Client organization name.")
    p_pkg.add_argument("--scope", default="Authorized Security Assessment", help="Audit scope description.")
    p_pkg.add_argument("--findings-json", required=True, help="JSON file containing findings list or {'findings': [...]}.")
    p_pkg.add_argument("--out", required=True, help="Output directory for client deliverable bundle.")

    sub.add_parser("bugbounty-mcp", help="Start the standalone Bug Bounty MCP stdio server.")

    p_lean = sub.add_parser("lean-verify", help="Audit and kernel-check RFCHunt's Lean 4 formal proofs.")
    p_lean.add_argument("--lean-dir", default="formal/lean4", help="Path to Lean 4 project directory.")
    return parser


def run_revenue_cli(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "freshness-watch":
        targets: List[WatchTarget] = []
        wl = Path(args.watchlist)
        if wl.is_file():
            targets.extend(load_watchlist(wl))
        for slug in args.repo:
            targets.append(WatchTarget(program="adhoc", repo=slug))
        watcher = FreshnessWatcher()
        try:
            report = watcher.poll_watchlist(
                targets,
                freshness_hours=args.hours,
                min_score=args.min_score,
                mark_returned_seen=args.mark_seen,
            )
        finally:
            watcher.close()
        out_stem = Path(args.out)
        out_stem.parent.mkdir(parents=True, exist_ok=True)
        json_path = out_stem.with_suffix(".json")
        md_path = out_stem.with_suffix(".md")
        json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        md_path.write_text(render_fresh_hunt_queue_markdown(report), encoding="utf-8")
        print(f"[+] Freshness Watch complete: {len(report.candidates)} candidates -> {md_path}")
        return 0

    if args.command == "linux-poc":
        cmd_tokens = list(args.cmd)
        if cmd_tokens and cmd_tokens[0] == "--":
            cmd_tokens = cmd_tokens[1:]
        if not cmd_tokens:
            print("[!] Error: provide a command after `--` (e.g., -- node poc.mjs)", file=sys.stderr)
            return 2
        runner = LinuxPocRunner(timeout_sec=args.timeout)
        tr = runner.run_poc(
            language=args.lang,
            repo_path=args.repo,
            cmd=cmd_tokens,
            image_override=args.image,
        )
        j_path, m_path = save_transcript_bundle(tr, args.out, stem=args.stem)
        print(f"[+] Linux PoC [{tr.status}] ({tr.backend}) -> {m_path} ({j_path})")
        return 0 if tr.verified else 1

    if args.command == "package-audit":
        raw = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
        findings = raw.get("findings", raw) if isinstance(raw, dict) else raw
        packager = ClientAuditPackager()
        bundle = packager.package(
            client_name=args.client,
            scope_description=args.scope,
            findings=findings,
            out_dir=args.out,
        )
        print(f"[+] Client Audit Bundle generated in {bundle.out_dir} ({bundle.finding_counts})")
        return 0

    if args.command == "bugbounty-mcp":
        from bugbounty_mcp_server import serve_stdio
        serve_stdio()
        return 0

    if args.command == "lean-verify":
        from engine.lean_formal_verifier import verify_lean_workspace
        rep = verify_lean_workspace(args.lean_dir)
        print(json.dumps(rep.to_dict(), indent=2))
        return 0 if rep.status in ("machine_checked", "static_audited_lean_not_installed") else 1

    return 2


def maybe_dispatch_revenue_cli(argv: Sequence[str]) -> Optional[int]:
    """Early non-invasive hook for `rfc_hunt_swarm.py` when invoked with a revenue subcommand."""
    if argv and argv[0] in REVENUE_SUBCOMMANDS:
        return run_revenue_cli(argv)
    return None


if __name__ == "__main__":
    raise SystemExit(run_revenue_cli())
