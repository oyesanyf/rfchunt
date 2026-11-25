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


REVENUE_SUBCOMMANDS = {
    "freshness-watch",
    "linux-poc",
    "package-audit",
    "bugbounty-mcp",
    "lean-verify",
    "ensemble-audit",
    "atlas-llm-eval",
}


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

    p_ens = sub.add_parser("ensemble-audit", help="Run exhaustive Stage 0-5 --all --ensemble audit (exhaustive multi-engine fan-out by default).")
    p_ens.add_argument("--target", required=True, help="Target repository directory.")
    p_ens.add_argument("--findings-json", default=None, help="Optional pre-computed JSON file of findings (omitting runs exhaustive multi-engine scan by default).")
    p_ens.add_argument("--program", default="generic", help="Vendor threat-model profile (shopify, anthropic, arc-bbp, cloudflare, coinbase, generic).")
    p_ens.add_argument("--freshness-hours", type=int, default=72, help="Freshness lookback window in hours (default: 72).")
    p_ens.add_argument("--quorum", type=int, default=2, help="Minimum independent engines for static corroboration.")
    p_ens.add_argument("--out", default="out/ensemble_audit", help="Output directory for JSON/MD/SARIF.")
    p_ens.add_argument("--package-client", default=None, help="Optional client name to also emit 5-file ClientAuditPackager bundle.")

    p_atlas = sub.add_parser("atlas-llm-eval", help="Sync live MITRE ATLAS STIX 2.1 and evaluate LLM guardrails + 74-language/low-resource parity.")
    p_atlas.add_argument("--llm-target", default="ollama", help="Target LLM: 'ollama', 'paid' (.env.local), or OpenAI-compatible HTTP(S) URL.")
    p_atlas.add_argument("--model", default=None, help="Optional model name override.")
    p_atlas.add_argument("--repo", default=None, help="Optional repository path for stack-adaptive ATLAS skill synthesis.")
    p_atlas.add_argument("--suites", default="low_resource,canary,ssrf_tool,atlas_dynamic", help="Comma-separated suites (all, multilingual, low_resource, canary, ssrf_tool, atlas_dynamic).")
    p_atlas.add_argument("--offline-stix", action="store_true", help="Skip live STIX download and use bundled golden snapshot.")
    p_atlas.add_argument("--concurrency", type=int, default=8, help="Max concurrent LLM requests.")
    p_atlas.add_argument("--out", default="out/atlas_llm_eval", help="Output directory for JSON + SARIF 2.1.0 report.")
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

    if args.command == "ensemble-audit":
        from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

        findings = None
        if args.findings_json:
            raw = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
            items = raw.get("findings", raw) if isinstance(raw, dict) else raw
            findings = [EngineFinding(**item) for item in items if isinstance(item, dict)]
        orch = EnsembleOrchestrator(
            program=args.program,
            freshness_hours=args.freshness_hours,
            quorum=args.quorum,
            exhaustive_default=True,
        )
        rep = orch.run(
            args.target,
            findings,
            out_dir=args.out,
            package_client_name=args.package_client,
        )
        print(f"[+] Exhaustive Ensemble Audit complete: {len(rep.clusters)} clusters ({rep.counts_by_disposition}) -> {args.out}")
        return 0

    if args.command == "atlas-llm-eval":
        from engine.atlas_llm_evaluator import AtlasLLMEvaluator, LLMTargetAdapter

        adapter = LLMTargetAdapter(target=args.llm_target, model=args.model)
        evaluator = AtlasLLMEvaluator(adapter=adapter, concurrency=args.concurrency)
        suites = [s.strip() for s in str(args.suites).split(",") if s.strip()]
        rep = evaluator.evaluate(
            suites=suites,
            repo_path=args.repo,
            refresh_stix=not args.offline_stix,
        )
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "atlas_llm_report.json").write_text(json.dumps(rep.to_dict(), indent=2), encoding="utf-8")
        (out_dir / "atlas_llm_findings.sarif").write_text(json.dumps(rep.to_sarif(), indent=2), encoding="utf-8")
        print(
            f"[+] ATLAS LLM Eval complete: {rep.passed_tests}/{rep.total_tests} passed "
            f"(parity={rep.cross_lingual_parity:.2f}, canary_leaks={rep.canary_leaks}) -> {out_dir}"
        )
        return 0 if rep.failed_tests == 0 else 1

    return 2


def maybe_dispatch_revenue_cli(argv: Sequence[str]) -> Optional[int]:
    """Early non-invasive hook for `rfc_hunt_swarm.py` when invoked with a revenue subcommand."""
    if argv and argv[0] in REVENUE_SUBCOMMANDS:
        return run_revenue_cli(argv)
    return None


if __name__ == "__main__":
    raise SystemExit(run_revenue_cli())
