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
import contextlib
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

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
    "fast-ooda",
    "atlas-llm-eval",
    "check-drafts",
    "qa-drafts",
    "rank-programs",
    "sync-directory",
    "cluster-recon",
    "analyze-js",
    "record-outcome",
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
    p_fresh.add_argument(
        "--from-eligibility-db",
        action="store_true",
        help="Build watchlist dynamically from UNLOCKED in_scope_repos in ProgramEligibilityDB.",
    )
    p_fresh.add_argument("--eligibility-db", default=None, help="Optional ProgramEligibilityDB SQLite path.")
    p_fresh.add_argument("--min-efficiency", type=float, default=80.0, help="Min response efficiency %% when using --from-eligibility-db.")
    p_fresh.add_argument("--ml-rank", action="store_true", help="Rank candidates via ACDSO-adapted CommitDiffRanker.")
    p_fresh.add_argument("--json", dest="json_out", action="store_true", help="Print JSON report to stdout.")

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

    p_ens = sub.add_parser("ensemble-audit", help="Run exhaustive Stage 0-5 --all --ensemble --proxy audit (exhaustive multi-engine fan-out by default).")
    p_ens.add_argument("--target", "--repo", dest="target", required=True, help="Target repository directory or workflow YAML file.")
    p_ens.add_argument("--findings-json", default=None, help="Optional pre-computed JSON file of findings (omitting runs exhaustive multi-engine scan by default).")
    p_ens.add_argument("--program", default="generic", help="Vendor threat-model profile (shopify, anthropic, arc-bbp, cloudflare, coinbase, generic).")
    p_ens.add_argument("--freshness-hours", type=int, default=72, help="Freshness lookback window in hours (default: 72).")
    p_ens.add_argument("--quorum", type=int, default=2, help="Minimum independent engines for static corroboration.")
    p_ens.add_argument("--proxy", nargs="?", const="auto", default="auto", help="Optional local/authorized proxy URL for traffic inspection (default: auto).")
    p_ens.add_argument("--all", action="store_true", default=True, help="Enable full exhaustive multi-engine `--all` scan (default: enabled).")
    p_ens.add_argument("--ensemble", "--essemble", "--essample", action="store_true", default=True, help="Enable exhaustive multi-engine ensemble fusion (default: enabled).")
    p_ens.add_argument("--embedded", "--embeded", dest="embedded", action="store_true", default=False, help="Run purely in-process offline (zero external binaries, zero network calls).")
    p_ens.add_argument("--model", default=None, help="Optional LLM model override (e.g., Ollama security/abliterated tag or paid model).")
    p_ens.add_argument("--no-llm", dest="no_llm", action="store_true", default=False, help="Disable optional LLM semantic verification layer.")
    p_ens.add_argument("--gha-only", dest="gha_only", action="store_true", default=False, help="Run only GitHub Actions engines (zizmor, actionlint, gha_agent, gha_llm).")
    p_ens.add_argument("--no-external-scanners", dest="no_external_scanners", action="store_true", default=False, help="Skip external scanner binaries (e.g., semgrep) and run local in-process engines only.")
    p_ens.add_argument("--out", default="out/ensemble_audit", help="Output directory for JSON/MD/SARIF.")
    p_ens.add_argument("--sarif-out", default=None, help="Optional explicit file path for SARIF 2.1.0 output.")
    p_ens.add_argument("--json", dest="json_out", action="store_true", default=False, help="Print full JSON report summary to stdout.")
    p_ens.add_argument("--package-client", default=None, help="Optional client name to also emit 5-file ClientAuditPackager bundle.")
    p_ens.add_argument("--cpu-workers", type=int, default=None, help="Bounded ProcessPoolExecutor CPU workers (default: clamped 2..8).")
    p_ens.add_argument("--blackboard-db", default=None, help="Optional Async SQLite WAL Blackboard database path.")
    p_ens.add_argument("--resume", action="store_true", default=False, help="Recover stale IN_PROGRESS intents from blackboard DB before running.")
    p_ens.add_argument("--stride", dest="enable_stride", action="store_true", default=False, help="Force generation of an advanced Fusion-powered STRIDE + MITRE ATT&CK + Zero Trust threat model and attack-tree diagrams (auto-runs when codebase lacks a threat model).")
    p_ens.add_argument("--no-stride", dest="no_stride", action="store_true", default=False, help="Disable automatic STRIDE threat model generation during ensemble-audit.")
    p_ens.add_argument("--stride-diagram", dest="stride_diagrams", action="append", default=[], help="Architecture diagram file to ingest into STRIDE analysis (repeatable).")
    p_ens.add_argument("--stride-out", dest="stride_out", default=None, help="Custom output directory for STRIDE report and downloadable SVG/PNG diagrams.")
    p_ens.add_argument("--stride-write-repo", dest="stride_write_repo", action="store_true", default=False, help="Also write generated THREAT_MODEL.md into the target repository root.")

    p_ooda = sub.add_parser("fast-ooda", help="Run Loop 3 3-stage parallel OODA funnel + Loop 4 auto-PoC submission gate.")
    p_ooda.add_argument("--target", "--repo", dest="target", required=True, help="Target repository directory.")
    p_ooda.add_argument("--program", default="generic", help="Vendor threat-model / eligibility program handle.")
    p_ooda.add_argument("--cpu-workers", type=int, default=None, help="Bounded ProcessPoolExecutor CPU workers (default: clamped 2..8).")
    p_ooda.add_argument("--blackboard-db", default="reports/ensemble_hunt/blackboard.sqlite3", help="Async SQLite WAL Blackboard database path.")
    p_ooda.add_argument("--resume", action="store_true", default=False, help="Recover stale IN_PROGRESS intents from blackboard DB before running.")
    p_ooda.add_argument("--signal-score", type=float, default=0.0, help="Current HackerOne Signal score for two-lane scheduling.")
    p_ooda.add_argument("--eligibility-db", default=None, help="Optional ProgramEligibilityDB SQLite path.")
    p_ooda.add_argument("--out", default="out/fast_ooda", help="Output directory for fast_ooda_report.json and staged drafts.")
    p_ooda.add_argument("--embedded", action="store_true", default=False, help="Run purely in-process offline (zero external binaries, zero Ollama calls).")
    p_ooda.add_argument("--model", default=None, help="Optional Ollama model override for Stage 3 verification.")
    p_ooda.add_argument("--no-llm", dest="no_llm", action="store_true", default=False, help="Disable Stage 3 LLM verification layer.")
    p_ooda.add_argument("--trigger-browser", dest="trigger_browser", action="store_true", default=False, help="Emit /browser stage-draft handoff spec for Loop 4 verified findings.")
    p_ooda.add_argument("--json", dest="json_out", action="store_true", default=False, help="Print full JSON OODA report to stdout.")

    p_atlas = sub.add_parser("atlas-llm-eval", help="Sync live MITRE ATLAS STIX 2.1 and evaluate LLM guardrails + 74-language/low-resource parity.")
    p_atlas.add_argument("--llm-target", default="ollama", help="Target LLM: 'ollama', 'paid' (.env.local), or OpenAI-compatible HTTP(S) URL.")
    p_atlas.add_argument("--model", default=None, help="Optional model name override.")
    p_atlas.add_argument("--repo", default=None, help="Optional repository path for stack-adaptive ATLAS skill synthesis.")
    p_atlas.add_argument("--suites", default="low_resource,canary,indirect_exfil,ssrf_tool,atlas_dynamic", help="Comma-separated suites (all, multilingual, low_resource, canary, indirect_exfil, ssrf_tool, atlas_dynamic).")
    p_atlas.add_argument("--program", default=None, help="Optional HackerOne program handle (fails closed unless AI/LLM assets are explicitly in scope).")
    p_atlas.add_argument("--eligibility-db", default=None, help="Optional ProgramEligibilityDB SQLite path for program RoE & AI-in-scope gating.")
    p_atlas.add_argument("--researcher-handle", default=None, help="Optional HackerOne researcher attribution handle for required policy headers/User-Agent.")
    p_atlas.add_argument("--offline-stix", action="store_true", help="Skip live STIX download and use bundled golden snapshot.")
    p_atlas.add_argument("--concurrency", type=int, default=8, help="Max concurrent LLM requests.")
    p_atlas.add_argument("--out", default="out/atlas_llm_eval", help="Output directory for JSON + SARIF 2.1.0 report.")

    p_drafts = sub.add_parser(
        "check-drafts",
        help="Check HackerOne saved drafts for cooldown clearance (`can_submit_draft? == true`) and print next 1-2 clickable URLs to submit.",
    )
    p_drafts.add_argument("--db", default="reports/ensemble_hunt/draft_submit_tracker.sqlite3", help="SQLite WAL tracker database path.")
    p_drafts.add_argument("--probe-id", type=int, default=4243972, help="Anchor draft report ID to probe first (default: 4243972).")
    p_drafts.add_argument("--probe-only", action="store_true", help="Only probe the single anchor draft ID (1 HTTP request).")
    p_drafts.add_argument("--all", dest="check_all", action="store_true", help="Check all tracked drafts even if anchor probe is still locked.")
    p_drafts.add_argument("--id", dest="report_ids", action="append", type=int, default=[], help="Specific HackerOne report ID(s) to check (repeatable).")
    p_drafts.add_argument("--max-per-day", type=int, default=2, help="Safe daily submission pacing cap (default: 2).")
    p_drafts.add_argument("--cookie-env", default="HACKERONE_SESSION_COOKIE", help="Env var holding HackerOne Cookie header.")
    p_drafts.add_argument("--snapshot-json", default=None, help="Optional JSON file of browser-exported HackerOne report objects to ingest offline.")
    p_drafts.add_argument("--mark-submitted", type=int, default=None, help="Record a report ID as submitted today (updates daily pacing).")
    p_drafts.add_argument("--seed-only", action="store_true", help="Seed/list tracked drafts locally without making network requests.")
    p_drafts.add_argument("--watch", action="store_true", help="Poll periodically until `can_submit_draft?` clears to true.")
    p_drafts.add_argument("--interval-minutes", type=float, default=30.0, help="Polling interval in minutes when --watch is set (default: 30).")
    p_drafts.add_argument("--out-md", default="reports/ensemble_hunt/drafts_ready_to_submit.md", help="Clickable Markdown checklist output path.")
    p_drafts.add_argument("--qa-db", default="reports/ensemble_hunt/draft_qa_tracker.sqlite3", help="Optional QA Phase SQLite DB to sync QA pass/fail gating before recommending drafts.")
    p_drafts.add_argument("--json", dest="json_out", action="store_true", help="Print structured JSON output.")

    p_qa = sub.add_parser(
        "qa-drafts",
        help="Run Quality Assurance (QA Phase) checks, upstream source verification, and auto-repair across HackerOne drafts.",
    )
    p_qa.add_argument("--snapshot-json", default=None, help="JSON file containing a HackerOne draft object or list of draft objects.")
    p_qa.add_argument("--markdown-file", default=None, help="Single local Markdown draft file to QA-check and optionally auto-repair before staging.")
    p_qa.add_argument("--title", default="", help="Draft title when using --markdown-file.")
    p_qa.add_argument("--report-id", type=int, default=0, help="HackerOne report ID when using --markdown-file.")
    p_qa.add_argument("--program", default="", help="Program handle when using --markdown-file.")
    p_qa.add_argument("--db", default="reports/ensemble_hunt/draft_qa_tracker.sqlite3", help="SQLite WAL QA tracker DB path.")
    p_qa.add_argument("--submit-db", default="reports/ensemble_hunt/draft_submit_tracker.sqlite3", help="Submit tracker DB to sync QA pass/fail status into.")
    p_qa.add_argument("--no-verify-sources", dest="no_verify_sources", action="store_true", help="Skip live raw.githubusercontent.com source-line and #define verification.")
    p_qa.add_argument("--out-md", default="reports/ensemble_hunt/qa_draft_audit.md", help="Clickable Markdown QA report output path.")
    p_qa.add_argument("--out-edit-queue", default="reports/ensemble_hunt/qa_edit_queue.json", help="Machine-readable edit queue JSON output path.")
    p_qa.add_argument("--write-repaired", default=None, help="When using --markdown-file, write the auto-repaired markdown body to this path.")
    p_qa.add_argument("--strict", action="store_true", help="Return non-zero exit code if any audited draft is not PASS.")
    p_qa.add_argument("--json", dest="json_out", action="store_true", help="Print structured JSON output.")

    p_rank = sub.add_parser(
        "rank-programs",
        help="Rank UNLOCKED public HackerOne programs using ACDSO-adapted survival, LTR, Pareto knee, bandit & Two-Phase knapsack.",
    )
    p_rank.add_argument("--db", default=None, help="Optional ProgramEligibilityDB SQLite path.")
    p_rank.add_argument("--min-efficiency", type=float, default=80.0, help="Minimum response efficiency %% (default: 80).")
    p_rank.add_argument("--preset", default=None, choices=["signal_fast", "balanced", "max_ev"], help="Optional preference preset.")
    p_rank.add_argument("--capacity", type=int, default=6, help="Daily portfolio program slot capacity (default: 6).")
    p_rank.add_argument("--budget-minutes", type=float, default=120.0, help="Daily compute budget in minutes (default: 120).")
    p_rank.add_argument("--include-deferred", action="store_true", help="Include <min-efficiency unlocked programs in ranking.")
    p_rank.add_argument("--use-boost", action="store_true", help="Apply ModelFusion /boost tie-breaker when top scores are within 0.02.")
    p_rank.add_argument("--json", dest="json_out", action="store_true", help="Print structured JSON output.")

    p_sync = sub.add_parser(
        "sync-directory",
        help="Sync HackerOne directory metadata & structured scopes (offline JSON snapshot, Public Directory newest-first, or HackerOne API v1) into ProgramEligibilityDB v2.",
    )
    p_sync.add_argument("--db", default=None, help="Optional ProgramEligibilityDB SQLite path.")
    p_sync.add_argument("--snapshot-json", default=None, help="Offline JSON file containing HackerOne program records to upsert.")
    p_sync.add_argument("--public-directory", action="store_true", help="Fetch public HackerOne Directory sorted by newest launch date (no API token required).")
    p_sync.add_argument("--public-endpoint", default=None, help="Optional public directory GraphQL URL override (default: https://hackerone.com/graphql).")
    p_sync.add_argument("--min-efficiency", type=float, default=80.0, help="Minimum response efficiency %% for public directory filtering (default: 80).")
    p_sync.add_argument("--query", default="", help="Optional HackerOne directory search query.")
    p_sync.add_argument("--limit", type=int, default=25, help="Max programs to fetch (default: 25).")
    p_sync.add_argument("--bounties-only", action="store_true", help="Filter directory sync to bounty-paying programs only.")
    p_sync.add_argument("--vdp-only", action="store_true", help="Filter directory sync to non-monetary VDPs only (fast Signal building).")
    p_sync.add_argument("--json", dest="json_out", action="store_true", help="Print structured JSON output.")

    p_recon = sub.add_parser(
        "cluster-recon",
        help="Cluster HTTP recon endpoints & JS bundles via K-Means++ + inductive p95 noise threshold and classify anomalous HTTP responses.",
    )
    p_recon.add_argument("--input", required=True, help="JSON file (list or {'assets': [...]}) or JSONL of recon assets/endpoints.")
    p_recon.add_argument("--program", default=None, help="Optional HackerOne program handle to filter strictly by in-scope allowlist.")
    p_recon.add_argument("--db", default=None, help="Optional ProgramEligibilityDB SQLite path.")
    p_recon.add_argument("--max-clusters", type=int, default=8, help="Maximum clusters (default: 8).")
    p_recon.add_argument("--out", default=None, help="Optional output JSON file path.")
    p_recon.add_argument("--json", dest="json_out", action="store_true", help="Print structured JSON output.")

    p_js = sub.add_parser(
        "analyze-js",
        help="Analyze JavaScript bundles (.js/.mjs/.js.map or JSON bundle list) for hidden API/GraphQL endpoints, DOM sinks, source maps & recon clustering.",
    )
    p_js.add_argument("--input", required=True, help="Directory of .js/.mjs files, single .js file, or JSON bundle list.")
    p_js.add_argument("--program", default=None, help="Optional HackerOne program handle to enforce strict DNS-boundary scope allowlist.")
    p_js.add_argument("--db", default=None, help="Optional ProgramEligibilityDB SQLite path.")
    p_js.add_argument("--out", default=None, help="Optional output JSON file path.")
    p_js.add_argument("--json", dest="json_out", action="store_true", help="Print structured JSON output.")

    p_outc = sub.add_parser(
        "record-outcome",
        help="Record a real HackerOne submission triage outcome into ProgramEligibilityDB to train survival, LTR & bandit models.",
    )
    p_outc.add_argument("--db", default=None, help="Optional ProgramEligibilityDB SQLite path.")
    p_outc.add_argument("--handle", required=True, help="HackerOne program handle (e.g., henkel_vdp, common_codes).")
    p_outc.add_argument(
        "--outcome",
        required=True,
        choices=["BOUNTY", "RESOLVED", "TRIAGED", "DUPLICATE", "INFORMATIVE", "NA", "NO_FINDING"],
        help="Observed report outcome.",
    )
    p_outc.add_argument("--repo", default="", help="Optional GitHub repo slug.")
    p_outc.add_argument("--sha", default="", help="Optional commit SHA.")
    p_outc.add_argument("--lane", type=int, default=1, choices=[1, 2], help="Hunt lane (1=VDP Signal, 2=Paid BBP).")
    p_outc.add_argument("--age-hours", type=float, default=0.0, help="Target commit/PR age in hours at discovery.")
    p_outc.add_argument("--signal-delta", type=float, default=0.0, help="Observed Signal point delta (e.g., +7.0).")
    p_outc.add_argument("--bounty-usd", type=float, default=0.0, help="Awarded bounty in USD (default: 0).")
    p_outc.add_argument("--triage-hours", type=float, default=None, help="Observed hours to triage.")
    p_outc.add_argument("--cycle-id", default="", help="Optional hunt cycle ID.")
    p_outc.add_argument("--update-signal", type=float, default=None, help="Optional updated account Signal score.")
    p_outc.add_argument("--json", dest="json_out", action="store_true", help="Print structured JSON output.")
    return parser


def _map_scanner_to_ensemble_engine(scanner: str) -> str:
    s = (scanner or "").strip().lower()
    if "mantis" in s:
        return "mantis"
    if "aiscan" in s:
        return "aiscan"
    if "raptor" in s or "semgrep" in s:
        return "raptor"
    if "artex" in s:
        return "artex"
    if any(k in s for k in ("smuggl", "h2desync", "h2_desync", "prober", "ruler", "oracle", "harness")):
        return "smuggling"
    if "rea" in s:
        return "rea"
    if "pe-dotnet" in s or "pe_dotnet" in s or "pe_magika" in s or "magika" in s:
        return "pe_magika"
    if "slicer" in s or "verificationinversion" in s:
        return "slicer"
    if "web_llm" in s or "webllm" in s:
        return "web_llm"
    if "atlas" in s:
        return "atlas_llm"
    if "zizmor" in s:
        return "zizmor"
    if "actionlint" in s:
        return "actionlint"
    if "gha_agent" in s:
        return "gha_agent"
    if "gha_llm" in s:
        return "gha_llm"
    if "lean" in s:
        return "lean4"
    if "linux_poc" in s:
        return "linux_poc"
    return "raptor"


def unified_findings_to_engine_findings(
    raw_findings: Sequence[Any],
    *,
    target_root: str | None = None,
    exclude_speculative_and_preflight: bool = False,
) -> list[Any]:
    """Convert `run_unified_all_scans` finding dicts into `EngineFinding` instances."""
    from engine.ensemble_orchestrator import EngineFinding

    resolved_root: Path | None = None
    if target_root:
        try:
            cand = Path(str(target_root)).resolve(strict=False)
            if cand.is_dir():
                resolved_root = cand
        except Exception:  # noqa: BLE001
            resolved_root = None

    converted: list[EngineFinding] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        scanner_raw = str(item.get("scanner") or "")
        scanner_low = scanner_raw.strip().lower()
        lane = str(item.get("evidence_lane") or "").strip().upper()
        ver_status = str(item.get("verification_status") or "").strip().upper()
        sev = str(item.get("severity") or "MEDIUM").strip().upper()
        try:
            poe_level = int(item.get("poe_level", 1) or 1)
        except (TypeError, ValueError):
            poe_level = 1

        if exclude_speculative_and_preflight:
            if lane == "SPECULATIVE_HYPOTHESIS":
                continue
            if "preflight" in scanner_low:
                continue
            if sev == "INFO" and poe_level < 3:
                continue
            if ver_status == "LEAD_PASSIVE_CORRELATION" and lane != "DETERMINISTIC_STATIC":
                continue

        raw_fp = str(item.get("file_path") or item.get("file") or "").strip()
        rel_fp = raw_fp
        if resolved_root is not None and raw_fp:
            try:
                p_fp = Path(raw_fp)
                if p_fp.is_absolute():
                    rel_fp = p_fp.resolve(strict=False).relative_to(resolved_root).as_posix()
                else:
                    rel_fp = raw_fp.replace("\\", "/")
            except Exception:  # noqa: BLE001
                rel_fp = raw_fp.replace("\\", "/")

        if lane == "VERIFIED_EXPLOIT":
            is_det = True
            is_conf = True
            conf = float(item.get("confidence", 0.85) or 0.85)
        elif lane == "SPECULATIVE_HYPOTHESIS":
            is_det = False
            is_conf = False
            conf = float(item.get("confidence", 0.35) or 0.35)
        else:
            is_det = (lane == "DETERMINISTIC_STATIC")
            is_conf = True
            conf = float(item.get("confidence", 0.68) or 0.68)

        try:
            line_num = int(item.get("line_number") or item.get("line") or 0)
        except (TypeError, ValueError):
            line_num = 0

        meta: dict[str, Any] = {}
        if isinstance(item.get("metadata"), dict):
            meta.update(item["metadata"])
        meta.setdefault("raw_scanner", scanner_raw)
        if lane:
            meta.setdefault("evidence_lane", lane)
        meta.setdefault("poe_level", poe_level)
        if ver_status:
            meta.setdefault("verification_status", ver_status)

        converted.append(
            EngineFinding(
                engine=_map_scanner_to_ensemble_engine(scanner_raw),
                title=str(item.get("title") or item.get("rule_id") or "Finding"),
                file_path=rel_fp,
                line=line_num,
                cwe=str(item.get("cwe") or ""),
                severity=sev or "MEDIUM",
                confidence=conf,
                summary=str(item.get("description") or item.get("summary") or item.get("evidence") or ""),
                rule_id=str(item.get("rule_id") or ""),
                atlas_technique=str(item.get("atlas_technique") or ""),
                deterministic=is_det,
                confirmed=is_conf,
                metadata=meta,
            )
        )
    return converted


def run_revenue_cli(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "freshness-watch":
        from engine.program_eligibility_db import ProgramEligibilityDB

        elig_db = None
        elig_path = getattr(args, "eligibility_db", None) or os.environ.get("RFCHUNT_ELIGIBILITY_DB")
        if bool(getattr(args, "from_eligibility_db", False)) or (elig_path and str(elig_path).strip()):
            elig_db = ProgramEligibilityDB(str(elig_path).strip() if elig_path else None)

        targets: list[WatchTarget] = []
        if bool(getattr(args, "from_eligibility_db", False)):
            from engine.ml_diff_and_recon_ranker import build_unlocked_watchlist_from_db

            raw_targets = build_unlocked_watchlist_from_db(
                eligibility_db=elig_db,
                min_efficiency_pct=float(getattr(args, "min_efficiency", 80.0)),
            )
            for row in raw_targets:
                targets.append(WatchTarget.from_dict(row))
        else:
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
                eligibility_db=elig_db if bool(getattr(args, "from_eligibility_db", False)) else None,
                ml_rank=bool(getattr(args, "ml_rank", False)),
            )
        finally:
            watcher.close()
        out_stem = Path(args.out)
        out_stem.parent.mkdir(parents=True, exist_ok=True)
        json_path = out_stem.with_suffix(".json")
        md_path = out_stem.with_suffix(".md")
        json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        md_path.write_text(render_fresh_hunt_queue_markdown(report), encoding="utf-8")
        if bool(getattr(args, "json_out", False)):
            print(json.dumps(report.to_dict(), indent=2))
        else:
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
        if not isinstance(raw, (list, dict)):
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error": (
                            f"Invalid --findings-json top-level type {type(raw).__name__}: "
                            "expected JSON array (list) or object (dict)."
                        ),
                    }
                ),
                file=sys.stderr,
            )
            return 2
        findings_raw = raw.get("findings", []) if isinstance(raw, dict) else raw
        findings = findings_raw if isinstance(findings_raw, list) else []
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
        from engine.ensemble_orchestrator import (
            EnsembleOrchestrator,
            _finding_from_dict,
        )

        findings = None
        all_scan_summary: dict[str, Any] | None = None
        offline_mode = (
            os.environ.get("RFCHUNT_OFFLINE") == "1"
            or bool(os.environ.get("CI"))
            or bool(args.embedded)
        )
        if args.findings_json:
            raw = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
            if not isinstance(raw, (list, dict)):
                err_payload = {
                    "status": "error",
                    "error": (
                        f"Invalid --findings-json top-level type {type(raw).__name__}: "
                        "expected JSON array (list) or object (dict)."
                    ),
                }
                if args.json_out:
                    print(json.dumps(err_payload, indent=2))
                else:
                    print(json.dumps(err_payload), file=sys.stderr)
                return 2
            items_raw = raw.get("findings", []) if isinstance(raw, dict) else raw
            items = items_raw if isinstance(items_raw, list) else []
            findings = [_finding_from_dict(item) for item in items if isinstance(item, dict)]

        cpu_workers_arg = getattr(args, "cpu_workers", None)
        bb_db_arg = getattr(args, "blackboard_db", None)
        resume_flag = bool(getattr(args, "resume", False))
        bb_recovery: dict[str, Any] | None = None
        if bb_db_arg or resume_flag:
            from engine.async_blackboard_runtime import SqliteBlackboard

            bb_path = str(bb_db_arg or "reports/ensemble_hunt/blackboard.sqlite3")
            bb = SqliteBlackboard(bb_path)
            try:
                if resume_flag:
                    bb_recovery = bb.recover_stale_intents(force_all_in_progress=True)
            finally:
                bb.close()

        orch = EnsembleOrchestrator(
            program=args.program,
            freshness_hours=args.freshness_hours,
            quorum=args.quorum,
            exhaustive_default=bool(getattr(args, "ensemble", True)),
            embedded=bool(args.embedded),
            model=args.model,
            enable_llm_verify=(not args.no_llm and not args.embedded),
            gha_only=bool(args.gha_only),
            no_external_scanners=bool(getattr(args, "no_external_scanners", False)),
            proxy=getattr(args, "proxy", None),
            max_workers=(max(1, int(cpu_workers_arg)) if cpu_workers_arg else 4),
            enable_stride=(
                False
                if bool(getattr(args, "no_stride", False))
                else (True if bool(getattr(args, "enable_stride", False)) else None)
            ),
            stride_diagrams=list(getattr(args, "stride_diagrams", None) or []),
            stride_out=getattr(args, "stride_out", None),
            stride_write_repo=bool(getattr(args, "stride_write_repo", False)),
        )

        target_path = Path(args.target)
        if (
            bool(getattr(args, "all", False))
            and findings is None
            and not bool(args.embedded)
            and not bool(args.gha_only)
        ):
            if target_path.is_dir():
                try:
                    from engine.mantis_integrator import run_unified_all_scans

                    ext_flag = (
                        False
                        if (bool(getattr(args, "no_external_scanners", False)) or offline_mode)
                        else None
                    )
                    with (
                        tempfile.TemporaryDirectory(prefix="rfchunt_unified_") as unified_reports_dir,
                        contextlib.redirect_stdout(sys.stderr) if args.json_out else contextlib.nullcontext(),
                    ):
                        all_res = run_unified_all_scans(
                            repo=str(target_path),
                            reports_dir=unified_reports_dir,
                            quiet=True,
                            enable_external_scanners=ext_flag,
                            include_models=False,
                            auto_install_tools=False,
                            preflight_live=False,
                            enable_h2_desync=False,
                            confine_reports_to_workspace_root=False,
                        )
                    all_scan_summary = {
                        "status": "completed",
                        "target_path": all_res.get("target_path"),
                        "mode": all_res.get("mode"),
                        "total_aggregated_findings": all_res.get("total_aggregated_findings", 0),
                        "primary_findings_count": all_res.get("primary_findings_count", 0),
                        "verified_exploits_count": all_res.get("verified_exploits_count", 0),
                        "deterministic_static_count": all_res.get("deterministic_static_count", 0),
                        "speculative_hypotheses_count": all_res.get("speculative_hypotheses_count", 0),
                        "chains_synthesized": all_res.get("chains_synthesized", 0),
                    }
                    converted = unified_findings_to_engine_findings(
                        all_res.get("findings") or [],
                        target_root=str(target_path),
                        exclude_speculative_and_preflight=True,
                    )
                    auto_findings, tele = orch.run_exhaustive_local_engines(
                        target_path,
                        refresh_stix=not offline_mode,
                        embedded=bool(args.embedded),
                        model=args.model,
                        enable_llm_verify=orch.enable_llm_verify,
                        gha_only=bool(args.gha_only),
                        no_external_scanners=bool(getattr(args, "no_external_scanners", False)),
                        lean_dir=orch.lean_dir,
                        program=args.program,
                    )
                    orch.last_telemetry = tele
                    findings = [*converted, *auto_findings]
                except Exception as exc:  # noqa: BLE001
                    all_scan_summary = {
                        "status": "degraded_unavailable",
                        "reason": str(exc),
                        "target": str(args.target),
                    }
                    findings = None
            else:
                all_scan_summary = {
                    "status": "skipped_non_directory_target",
                    "target": str(args.target),
                }

        rep = orch.run(
            args.target,
            findings,
            all_scan_summary=all_scan_summary,
            out_dir=args.out,
            package_client_name=args.package_client,
            refresh_stix=not offline_mode,
        )
        if bb_recovery is not None:
            orch.last_telemetry["blackboard_recovery"] = bb_recovery
        if bb_db_arg:
            orch.last_telemetry["blackboard_db"] = str(bb_db_arg)
        if cpu_workers_arg is not None:
            orch.last_telemetry["cpu_workers"] = int(cpu_workers_arg)
        if args.sarif_out:
            sarif_dest = Path(args.sarif_out)
            sarif_dest.parent.mkdir(parents=True, exist_ok=True)
            sarif_dest.write_text(json.dumps(rep.to_sarif(), indent=2), encoding="utf-8")
        if args.json_out:
            payload = rep.to_dict()
            payload["telemetry"] = orch.last_telemetry
            print(json.dumps(payload, indent=2))
        else:
            mode_tag = "embedded" if args.embedded else "standard"
            wb = rep.whiteboard or {}
            lv = rep.lean_verification or {}
            tc = rep.toolchain_status or {}
            avail_tc = [k for k, v in tc.items() if isinstance(v, dict) and v.get("available")]
            stm = rep.stride_threat_model if isinstance(rep.stride_threat_model, dict) else {}
            stride_tag = (
                f" | stride={stm.get('status', 'disabled')}({stm.get('threat_scenarios_count', 0)} threats, {stm.get('attack_trees_count', 0)} trees)"
                if stm
                else ""
            )
            print(
                f"[+] Exhaustive Ensemble Audit ({mode_tag}) complete: {len(rep.clusters)} clusters "
                f"({rep.counts_by_disposition}) | whiteboard_hyps={wb.get('total_hypotheses', len(wb.get('hypotheses') or []))} "
                f"| lean={lv.get('status', 'unknown')} | available_toolchains={avail_tc or 'none'}"
                f"{stride_tag} | proxy={rep.proxy or 'none'} -> {args.out}"
            )
        return 0

    if args.command == "fast-ooda":
        from engine.ensemble_orchestrator import EnsembleOrchestrator
        from engine.program_eligibility_db import ProgramEligibilityDB

        cpu_workers_arg = getattr(args, "cpu_workers", None)
        orch = EnsembleOrchestrator(
            program=args.program,
            embedded=bool(args.embedded),
            model=args.model,
            enable_llm_verify=(not args.no_llm and not args.embedded),
            max_workers=(max(1, int(cpu_workers_arg)) if cpu_workers_arg else 4),
        )
        elig_db_raw = getattr(args, "eligibility_db", None) or os.environ.get("RFCHUNT_ELIGIBILITY_DB")
        elig_db = (
            ProgramEligibilityDB(str(elig_db_raw).strip())
            if elig_db_raw and str(elig_db_raw).strip()
            else None
        )
        res = orch.run_fast_parallel_ooda(
            args.target,
            program=args.program,
            blackboard_db=args.blackboard_db,
            max_cpu_workers=cpu_workers_arg,
            resume=bool(args.resume),
            signal_score=float(args.signal_score),
            eligibility_db=elig_db,
            out_dir=args.out,
            trigger_browser=bool(args.trigger_browser),
        )
        if args.out:
            out_dir = Path(args.out)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "fast_ooda_report.json").write_text(
                json.dumps(res, indent=2, default=str),
                encoding="utf-8",
            )
        if args.json_out:
            print(json.dumps(res, indent=2, default=str))
        else:
            s1 = res.get("stage1") if isinstance(res.get("stage1"), dict) else {}
            s2 = res.get("stage2") if isinstance(res.get("stage2"), dict) else {}
            prod_cnt = s1.get("production_count", res.get("stage1_production_count", 0))
            noise_cnt = s1.get("noise_dropped", res.get("stage1_dropped_noise_count", 0))
            sel_cnt = len(s2.get("selected") or [])
            print(
                f"[+] Fast OODA ({res.get('status', 'completed')}) complete: "
                f"prod={prod_cnt}, noise_dropped={noise_cnt}, stage2_selected={sel_cnt}, "
                f"clusters={len(res.get('clusters') or [])} -> {args.out}"
            )
            ready_paths: list[str] = []
            report_urls: list[str] = []
            candidates: list[dict[str, Any]] = [res]
            if isinstance(res.get("submission"), dict):
                candidates.append(res["submission"])
            if isinstance(res.get("loop4"), dict):
                candidates.append(res["loop4"])
            for item in res.get("staged_submissions") or []:
                if isinstance(item, dict):
                    candidates.append(item)
            for cand in candidates:
                rp = cand.get("ready_to_submit_path")
                if rp and str(rp) not in ready_paths:
                    ready_paths.append(str(rp))
                for key in ("report_url", "submit_url"):
                    u = str(cand.get(key) or "").strip()
                    if u.startswith("https://hackerone.com/reports/") and u not in report_urls:
                        report_urls.append(u)
            for rp in ready_paths:
                print(f"[+] READY_TO_SUBMIT.json: {rp}")
            for url in report_urls:
                print(f"[+] HackerOne Draft URL: {url}")
        return 0

    if args.command == "atlas-llm-eval":
        from engine.atlas_llm_evaluator import AtlasLLMEvaluator, LLMTargetAdapter

        elig_db = None
        if args.program:
            from engine.program_eligibility_db import ProgramEligibilityDB

            elig_db = ProgramEligibilityDB(db_path=args.eligibility_db)
        adapter = LLMTargetAdapter(target=args.llm_target, model=args.model)
        evaluator = AtlasLLMEvaluator(adapter=adapter, concurrency=args.concurrency)
        suites = [s.strip() for s in str(args.suites).split(",") if s.strip()]
        rep = evaluator.evaluate(
            suites=suites,
            repo_path=args.repo,
            refresh_stix=not args.offline_stix,
            program_handle=args.program,
            eligibility_db=elig_db,
            researcher_handle=args.researcher_handle,
        )
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "atlas_llm_report.json").write_text(json.dumps(rep.to_dict(), indent=2), encoding="utf-8")
        (out_dir / "atlas_llm_findings.sarif").write_text(json.dumps(rep.to_sarif(), indent=2), encoding="utf-8")
        if rep.stix_metadata.get("compliance_blocked"):
            print(f"[!] ATLAS LLM Eval blocked by ProgramComplianceContext: {rep.stix_metadata.get('reason')}")
            return 1
        print(
            f"[+] ATLAS LLM Eval complete: {rep.passed_tests}/{rep.total_tests} passed "
            f"(parity={rep.cross_lingual_parity:.2f}, canary_leaks={rep.canary_leaks}) -> {out_dir}"
        )
        return 0 if rep.failed_tests == 0 else 1

    if args.command == "check-drafts":
        import time as _time

        from engine.draft_qa_checker import DraftQATrackerDB
        from engine.draft_submit_checker import DraftSubmitChecker, DraftSubmitTrackerDB

        db = DraftSubmitTrackerDB(args.db)
        db.seed_default_queue()
        if args.qa_db and Path(args.qa_db).exists():
            qa_map = DraftQATrackerDB(args.qa_db).get_qa_status_map()
            if qa_map:
                db.sync_qa_statuses(qa_map)

        if args.mark_submitted is not None:
            db.mark_submitted(int(args.mark_submitted))
            if args.json_out:
                print(
                    json.dumps(
                        {
                            "status": "marked_submitted",
                            "report_id": int(args.mark_submitted),
                            "submitted_today": db.get_submitted_today(),
                        },
                        indent=2,
                    )
                )
            else:
                print(
                    f"[+] Marked report #{args.mark_submitted} as submitted "
                    f"(submitted today: {db.get_submitted_today()}/{args.max_per_day})."
                )
            return 0

        if args.seed_only:
            drafts = db.list_drafts(only_drafts=True)
            if args.json_out:
                print(json.dumps({"total_drafts": len(drafts), "drafts": [d.__dict__ for d in drafts]}, indent=2))
            else:
                print(f"[+] Tracked HackerOne Drafts: {len(drafts)} (db={args.db})")
                for d in drafts[:10]:
                    print(f"  - [{d.payout_tier} {d.severity}] {d.url} ({d.program}) — {d.title}")
            return 0

        cookie_val = os.environ.get(str(args.cookie_env), "").strip()
        checker = DraftSubmitChecker(db=db, session_cookie=cookie_val)

        if args.snapshot_json:
            raw_snap = json.loads(Path(args.snapshot_json).read_text(encoding="utf-8"))
            snaps = raw_snap if isinstance(raw_snap, list) else [raw_snap]
            summary = checker.ingest_snapshots(
                snaps,
                probe_report_id=int(args.probe_id),
                max_per_day=int(args.max_per_day),
                out_md=args.out_md,
            )
        else:
            while True:
                summary = checker.check(
                    report_ids=args.report_ids or None,
                    probe_report_id=int(args.probe_id),
                    probe_first=not bool(args.check_all),
                    probe_only=bool(args.probe_only),
                    max_per_day=int(args.max_per_day),
                    out_md=args.out_md,
                )
                if not args.watch or summary.account_status in ("CLEARED", "AUTH_REQUIRED"):
                    break
                sleep_s = max(60.0, float(args.interval_minutes) * 60.0)
                print(
                    f"[~] Status={summary.account_status} (probe #{summary.probe_report_id}) "
                    f"— sleeping {args.interval_minutes:.1f}m before next polite check..."
                )
                _time.sleep(sleep_s)

        if args.json_out:
            print(json.dumps(summary.to_dict(), indent=2))
        else:
            print(
                f"[+] HackerOne Draft Readiness: {summary.account_status} | "
                f"ready={summary.ready_to_submit_count}, locked={summary.cooldown_locked_count}, "
                f"open={summary.already_submitted_count} | "
                f"daily_quota={summary.submitted_today}/{summary.daily_limit} "
                f"-> {summary.ready_markdown_path}"
            )
            if summary.account_status == "CLEARED":
                print("[+] SUBMIT READY NOW (Next Safe Batch):")
                for item in summary.recommended_next_batch:
                    print(
                        f"    -> {item['url']}  [{item['program']} | {item['payout_tier']} | {item['severity']}] "
                        f"{item['title']}"
                    )
            elif summary.account_status == "COOLDOWN_ACTIVE":
                print(
                    "[!] Cooldown still active (`can_submit_draft? == false`). "
                    "Do NOT click Delete; re-run later or use --watch."
                )
            elif summary.account_status == "AUTH_REQUIRED":
                print(
                    f"[!] Auth required: export {args.cookie_env} or pass --snapshot-json from an authenticated browser session."
                )
        return 0 if summary.account_status == "CLEARED" else 1

    if args.command == "qa-drafts":
        from engine.draft_qa_checker import DraftQAChecker, DraftQATrackerDB
        from engine.draft_submit_checker import DraftSubmitTrackerDB

        qa_db = DraftQATrackerDB(args.db)
        qa_checker = DraftQAChecker(db=qa_db)
        snapshots: list[dict[str, Any]] = []

        if args.snapshot_json:
            raw_snap = json.loads(Path(args.snapshot_json).read_text(encoding="utf-8"))
            snapshots = raw_snap if isinstance(raw_snap, list) else [raw_snap]
        elif args.markdown_file:
            md_path = Path(args.markdown_file)
            body = md_path.read_text(encoding="utf-8")
            snapshots = [
                {
                    "id": int(args.report_id or 1),
                    "title": str(args.title or md_path.stem),
                    "team_handle": str(args.program or ""),
                    "state": "Draft",
                    "vulnerability_information": body,
                }
            ]
        else:
            print("[!] Provide either --snapshot-json <file> or --markdown-file <file>.", file=sys.stderr)
            return 2

        summary = qa_checker.audit_snapshots(
            snapshots,
            verify_sources=not bool(args.no_verify_sources),
            out_md=args.out_md,
            out_edit_queue=args.out_edit_queue,
        )

        if args.write_repaired and summary.results:
            Path(args.write_repaired).write_text(summary.results[0].repaired_body, encoding="utf-8")

        if args.submit_db:
            submit_db = DraftSubmitTrackerDB(args.submit_db)
            submit_db.seed_default_queue()
            submit_db.sync_qa_statuses(qa_db.get_qa_status_map())

        if args.json_out:
            print(json.dumps(summary.to_dict(include_bodies=False), indent=2))
        else:
            print(
                f"[+] QA Phase Complete: audited={summary.total_audited} | "
                f"pass={summary.passed_count}, auto_fixed={summary.auto_fixed_pending_push_count}, "
                f"needs_source_edit={summary.needs_source_edit_count}, fail={summary.failed_count} "
                f"| defects={summary.total_defects}"
            )
            print(f"[+] Clickable QA Report: {summary.audit_markdown_path}")
            print(f"[+] Auto-Edit Queue:    {summary.edit_queue_json_path}")
            for r in summary.results:
                if r.qa_status != "PASS":
                    codes = ", ".join(sorted({d.code for d in r.defects}))
                    print(f"    -> [{r.qa_status}] {r.url} ({r.program}) :: {codes}")

        if args.strict and summary.passed_count != summary.total_audited:
            return 1
        return 0

    if args.command == "rank-programs":
        from engine.ml_program_selector import rank_hackerone_programs

        res = rank_hackerone_programs(
            db_path=args.db,
            min_efficiency_pct=float(args.min_efficiency),
            preset=args.preset,
            capacity=int(args.capacity),
            budget_minutes=float(args.budget_minutes),
            include_deferred=bool(args.include_deferred),
        )
        if bool(args.use_boost) and res.get("tie_break_needed") and res.get("ranked_programs"):
            from engine.boost_decision_adapter import BoostDecisionAdapter

            tb = BoostDecisionAdapter().tie_break_pareto_knee(res["ranked_programs"])
            res["boost_tie_break"] = {k: v for k, v in tb.items() if k != "ordered"}
            if tb.get("tie_broken") and tb.get("ordered"):
                res["ranked_programs"] = tb["ordered"]
                for idx, row in enumerate(res["ranked_programs"], start=1):
                    row["rank"] = idx
        if args.json_out:
            print(json.dumps(res, indent=2, default=str))
        else:
            port = res.get("daily_hunt_portfolio") or {}
            print(
                f"[+] ML Program Ranking (preset={res['preset']}, LTR tier={res['ltr_curriculum_tier']}, "
                f"Pareto winner={res['pareto_knee_winner']}): "
                f"ranked={len(res['ranked_programs'])}, portfolio={len(port.get('selected') or [])} "
                f"(Lane1={port.get('lane1_count', 0)}, Lane2={port.get('lane2_count', 0)})"
            )
            for row in (res.get("ranked_programs") or [])[:10]:
                print(
                    f"  #{row['rank']:2d} {row['handle']:<28} [{row['lane']}] "
                    f"score={row['combined_rank_score']:.4f} eff={row.get('response_efficiency_pct')}% "
                    f"max=${row.get('bounty_max_usd', 0)}"
                )
        return 0

    if args.command == "sync-directory":
        from engine.program_eligibility_db import ProgramEligibilityDB

        db = ProgramEligibilityDB(db_path=args.db)
        upserted: list[str] = []
        errors_list: list[str] = []
        if args.snapshot_json:
            raw_data = json.loads(Path(args.snapshot_json).read_text(encoding="utf-8"))
            items = raw_data.get("programs", raw_data) if isinstance(raw_data, dict) else raw_data
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
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
        elif bool(getattr(args, "public_directory", False)):
            from engine.hackerone_porter import HackerOnePublicDirectoryClient

            pub_client = HackerOnePublicDirectoryClient(endpoint_url=getattr(args, "public_endpoint", None))
            pub_res = pub_client.fetch_and_sync_directory(
                eligibility_db=db,
                query=str(args.query or ""),
                limit=max(1, int(args.limit)),
                min_efficiency_pct=float(getattr(args, "min_efficiency", 80.0)),
                bounties_only=bool(args.bounties_only),
                vdp_only=bool(getattr(args, "vdp_only", False)),
            )
            upserted.extend(pub_res.get("upserted") or [])
        else:
            from engine.hackerone_porter import HackerOneApiClient

            client = HackerOneApiClient()
            if not client.has_credentials:
                payload = {
                    "status": "auth_required",
                    "upserted": [],
                    "message": "Set HACKERONE_API_USERNAME & HACKERONE_API_TOKEN, pass --public-directory, or pass --snapshot-json.",
                }
                if args.json_out:
                    print(json.dumps(payload, indent=2))
                else:
                    print(f"[!] {payload['message']}")
                return 1
            campaigns = client.list_campaigns(
                query=str(args.query or ""),
                bounties_only=bool(args.bounties_only),
                limit=max(1, int(args.limit)),
            )
            for camp in campaigns:
                try:
                    client.fetch_campaign_scope(camp.handle, eligibility_db=db)
                    upserted.append(camp.handle)
                except Exception as exc:  # noqa: BLE001
                    errors_list.append(f"{camp.handle}: {exc}")

        out_payload = {
            "status": "completed",
            "upserted_count": len(upserted),
            "upserted": upserted,
            "summary_counts": db.summary_counts(),
            "errors": errors_list,
        }
        if args.json_out:
            print(json.dumps(out_payload, indent=2))
        else:
            print(f"[+] Synced {len(upserted)} program(s) into {db.db_path} ({out_payload['summary_counts']})")
        return 0

    if args.command == "cluster-recon":
        from engine.ml_diff_and_recon_ranker import ReconAssetClusterer

        raw_txt = Path(args.input).read_text(encoding="utf-8").strip()
        assets_in: list[dict[str, Any]] = []
        if raw_txt.startswith(("[", "{")):
            parsed = json.loads(raw_txt)
            if isinstance(parsed, dict):
                parsed = parsed.get("assets") or parsed.get("endpoints") or parsed.get("items") or []
            if isinstance(parsed, list):
                assets_in = [x for x in parsed if isinstance(x, dict)]
        else:
            for line in raw_txt.splitlines():
                s = line.strip()
                if not s:
                    continue
                obj = json.loads(s)
                if isinstance(obj, dict):
                    assets_in.append(obj)

        compliance_ctx = None
        if args.program:
            from engine.program_eligibility_db import ProgramEligibilityDB
            from engine.request_hygiene import build_program_compliance_context

            db = ProgramEligibilityDB(db_path=args.db)
            compliance_ctx = build_program_compliance_context(args.program, eligibility_db=db)

        clusterer = ReconAssetClusterer(max_clusters=int(args.max_clusters))
        result = clusterer.cluster_and_prioritize(assets_in, compliance_ctx=compliance_ctx)
        if args.out:
            out_p = Path(args.out)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(result, indent=2), encoding="utf-8")
        if args.json_out:
            print(json.dumps(result, indent=2))
        else:
            print(
                f"[+] Recon Clustering complete: total={result['total_assets']}, "
                f"clusters={result['clusters_count']}, outliers={result['outliers_count']}, "
                f"suppressed_bulk={result['suppressed_homogeneous_count']}, "
                f"skipped_oos={result['skipped_out_of_scope']}"
            )
            for row in (result.get("prioritized_assets") or [])[:10]:
                print(
                    f"  - [{row['priority_score']:.3f} | {row.get('anomaly_class', 'NORMAL')}] {row['url']} "
                    f"(cluster={row['cluster_id']}, outlier={row['is_outlier_noise']}, tokens={row['matched_high_value_tokens']})"
                )
        return 0

    if args.command == "analyze-js":
        from engine.ml_diff_and_recon_ranker import JavaScriptBundleAnalyzer

        in_path = Path(args.input)
        bundles_in: list[dict[str, Any]] = []
        if in_path.is_dir():
            for p_js in sorted(in_path.rglob("*")):
                if p_js.is_file() and (
                    p_js.suffix.lower() in (".js", ".mjs", ".cjs") or p_js.name.lower().endswith(".js.map")
                ):
                    bundles_in.append({"path": str(p_js), "url": p_js.relative_to(in_path).as_posix()})
        elif in_path.is_file() and in_path.suffix.lower() == ".json":
            parsed = json.loads(in_path.read_text(encoding="utf-8"))
            items = parsed.get("bundles", parsed) if isinstance(parsed, dict) else parsed
            if isinstance(items, list):
                bundles_in = [x for x in items if isinstance(x, dict)]
        elif in_path.is_file():
            bundles_in.append({"path": str(in_path), "url": in_path.name})

        compliance_ctx = None
        if args.program:
            from engine.program_eligibility_db import ProgramEligibilityDB
            from engine.request_hygiene import build_program_compliance_context

            db = ProgramEligibilityDB(db_path=args.db)
            compliance_ctx = build_program_compliance_context(args.program, eligibility_db=db)

        result = JavaScriptBundleAnalyzer().analyze_bundles(bundles_in, compliance_ctx=compliance_ctx)
        if args.out:
            out_p = Path(args.out)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(result, indent=2), encoding="utf-8")
        if args.json_out:
            print(json.dumps(result, indent=2))
        else:
            print(
                f"[+] JS Bundle Analysis complete: bundles={result['total_bundles']}, "
                f"endpoints={result['total_endpoints_discovered']}, dom_sinks={result['total_dom_sinks']}, "
                f"sourcemaps={result['total_sourcemap_leaks']}"
            )
            for b in (result.get("bundles") or [])[:10]:
                print(
                    f"  - [{b['js_risk_score']:.3f}] {b['source']} "
                    f"(endpoints={len(b['discovered_endpoints'])}, sinks={b['dom_sinks']}, maps={len(b['sourcemap_urls'])})"
                )
        return 0

    if args.command == "record-outcome":
        from engine.program_eligibility_db import ProgramEligibilityDB

        db = ProgramEligibilityDB(db_path=args.db)
        rec = db.record_hunt_outcome(
            handle=args.handle,
            outcome=args.outcome,
            repo=args.repo,
            commit_sha=args.sha,
            lane=int(args.lane),
            target_age_hours=float(args.age_hours),
            signal_delta=float(args.signal_delta),
            bounty_usd=float(args.bounty_usd),
            triage_hours_observed=args.triage_hours,
            cycle_id=args.cycle_id,
        )
        acct = None
        if args.update_signal is not None:
            acct = db.update_account_state(
                signal_established=True,
                signal_score=float(args.update_signal),
            ).to_dict()
        payload = {"status": "recorded", "outcome": rec.to_dict(), "account_state": acct}
        if args.json_out:
            print(json.dumps(payload, indent=2))
        else:
            print(
                f"[+] Recorded outcome {rec.outcome} for {rec.handle} (lane={rec.lane}, "
                f"signal_delta={rec.signal_delta:+.2f}, bounty=${rec.bounty_usd:.2f})"
            )
        return 0

    return 2


_ENSEMBLE_TRIGGER_FLAGS = {"--ensemble", "--essemble", "--essample", "--embedded", "--embeded"}


def _translate_swarm_argv_to_ensemble(argv: Sequence[str]) -> tuple[list[str], bool]:
    """Translates `rfc_hunt_swarm.py --all [--ensemble|--essemble|--essample] [--embedded|--embeded]` into `ensemble-audit` args."""
    tokens = list(argv)
    target: str | None = None
    out_dir: str = "out/ensemble_audit"
    sarif_out: str | None = None
    program: str = "generic"
    freshness_hours: str = "72"
    quorum: str = "2"
    model: str | None = None
    findings_json: str | None = None
    package_client: str | None = None
    cpu_workers: str | None = None
    blackboard_db: str | None = None
    resume = False
    proxy: str | None = "auto"
    embedded = False
    no_llm = False
    gha_only = False
    no_external_scanners = False
    json_out = False
    dry_run = False
    enable_stride = False
    no_stride = False
    stride_diagrams: list[str] = []
    stride_out: str | None = None
    stride_write_repo = False

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("--ensemble", "--essemble", "--essample"):
            i += 1
        elif tok in ("--embedded", "--embeded"):
            embedded = True
            i += 1
        elif tok == "--stride":
            enable_stride = True
            i += 1
        elif tok == "--no-stride":
            no_stride = True
            i += 1
        elif tok == "--stride-write-repo":
            stride_write_repo = True
            i += 1
        elif tok == "--stride-diagram" and i + 1 < len(tokens):
            stride_diagrams.append(tokens[i + 1])
            i += 2
        elif tok.startswith("--stride-diagram="):
            val_sd = tok.split("=", 1)[1].strip()
            if val_sd:
                stride_diagrams.append(val_sd)
            i += 1
        elif tok == "--stride-out" and i + 1 < len(tokens):
            stride_out = tokens[i + 1]
            i += 2
        elif tok.startswith("--stride-out="):
            stride_out = tok.split("=", 1)[1].strip() or None
            i += 1
        elif tok == "--no-llm":
            no_llm = True
            i += 1
        elif tok == "--gha-only":
            gha_only = True
            i += 1
        elif tok == "--no-external-scanners":
            no_external_scanners = True
            i += 1
        elif tok in ("--no-preflight-live", "--no-include-models", "--no-auto-install"):
            i += 1
        elif tok == "--json":
            json_out = True
            i += 1
        elif tok == "--dry-run":
            dry_run = True
            i += 1
        elif tok == "--all":
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                target = tokens[i + 1]
                i += 2
            else:
                i += 1
        elif tok in ("--target", "--repo", "--path"):
            if i + 1 < len(tokens):
                target = tokens[i + 1]
                i += 2
            else:
                i += 1
        elif tok in ("--out", "--output-dir"):
            if i + 1 < len(tokens):
                out_dir = tokens[i + 1]
                i += 2
            else:
                i += 1
        elif tok == "--db":
            if i + 1 < len(tokens):
                i += 2
            else:
                i += 1
        elif tok.startswith("--db="):
            i += 1
        elif tok == "--sarif-out" and i + 1 < len(tokens):
            sarif_out = tokens[i + 1]
            i += 2
        elif tok == "--program" and i + 1 < len(tokens):
            program = tokens[i + 1]
            i += 2
        elif tok == "--freshness-hours" and i + 1 < len(tokens):
            freshness_hours = tokens[i + 1]
            i += 2
        elif tok == "--quorum" and i + 1 < len(tokens):
            quorum = tokens[i + 1]
            i += 2
        elif tok == "--model" and i + 1 < len(tokens):
            model = tokens[i + 1]
            i += 2
        elif tok == "--findings-json" and i + 1 < len(tokens):
            findings_json = tokens[i + 1]
            i += 2
        elif tok == "--package-client" and i + 1 < len(tokens):
            package_client = tokens[i + 1]
            i += 2
        elif tok == "--cpu-workers" and i + 1 < len(tokens):
            cpu_workers = tokens[i + 1]
            i += 2
        elif tok.startswith("--cpu-workers="):
            cpu_workers = tok.split("=", 1)[1] or None
            i += 1
        elif tok == "--blackboard-db" and i + 1 < len(tokens):
            blackboard_db = tokens[i + 1]
            i += 2
        elif tok.startswith("--blackboard-db="):
            blackboard_db = tok.split("=", 1)[1] or None
            i += 1
        elif tok == "--resume":
            resume = True
            i += 1
        elif tok == "--proxy":
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                proxy = tokens[i + 1]
                i += 2
            else:
                proxy = "auto"
                i += 1
        elif tok.startswith("--proxy="):
            proxy = tok.split("=", 1)[1] or "auto"
            i += 1
        elif not tok.startswith("-") and target is None:
            target = tok
            i += 1
        else:
            i += 1

    mapped: list[str] = [
        "ensemble-audit",
        "--target",
        target or ".",
        "--program",
        program,
        "--freshness-hours",
        freshness_hours,
        "--quorum",
        quorum,
        "--out",
        out_dir,
        "--all",
        "--ensemble",
    ]
    if embedded:
        mapped.append("--embedded")
    if no_llm:
        mapped.append("--no-llm")
    if gha_only:
        mapped.append("--gha-only")
    if no_external_scanners:
        mapped.append("--no-external-scanners")
    if json_out:
        mapped.append("--json")
    if model:
        mapped.extend(["--model", model])
    if sarif_out:
        mapped.extend(["--sarif-out", sarif_out])
    if findings_json:
        mapped.extend(["--findings-json", findings_json])
    if package_client:
        mapped.extend(["--package-client", package_client])
    if cpu_workers:
        mapped.extend(["--cpu-workers", cpu_workers])
    if blackboard_db:
        mapped.extend(["--blackboard-db", blackboard_db])
    if resume:
        mapped.append("--resume")
    if proxy:
        mapped.extend(["--proxy", proxy])
    if enable_stride:
        mapped.append("--stride")
    if no_stride:
        mapped.append("--no-stride")
    for dpath in stride_diagrams:
        mapped.extend(["--stride-diagram", dpath])
    if stride_out:
        mapped.extend(["--stride-out", stride_out])
    if stride_write_repo:
        mapped.append("--stride-write-repo")
    return mapped, dry_run


def maybe_dispatch_revenue_cli(argv: Sequence[str]) -> int | None:
    """Early non-invasive hook for `rfc_hunt_swarm.py` when invoked with a revenue subcommand or ensemble/embedded flags."""
    if not argv:
        return None
    if argv[0] in REVENUE_SUBCOMMANDS:
        return run_revenue_cli(argv)
    if any(tok in _ENSEMBLE_TRIGGER_FLAGS for tok in argv):
        mapped, dry_run = _translate_swarm_argv_to_ensemble(argv)
        if dry_run:
            print(
                json.dumps(
                    {
                        "status": "dry_run_plan_ready",
                        "dry_run": True,
                        "command": mapped[0],
                        "argv": mapped,
                        "side_effects": {
                            "network_packets_sent": 0,
                            "filesystem_mutations": 0,
                            "browser_launched": False,
                        },
                    },
                    indent=2,
                )
            )
            return 0
        return run_revenue_cli(mapped)
    return None


if __name__ == "__main__":
    raise SystemExit(run_revenue_cli())
