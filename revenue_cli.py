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
from pathlib import Path
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence

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

    p_atlas = sub.add_parser("atlas-llm-eval", help="Sync live MITRE ATLAS STIX 2.1 and evaluate LLM guardrails + 74-language/low-resource parity.")
    p_atlas.add_argument("--llm-target", default="ollama", help="Target LLM: 'ollama', 'paid' (.env.local), or OpenAI-compatible HTTP(S) URL.")
    p_atlas.add_argument("--model", default=None, help="Optional model name override.")
    p_atlas.add_argument("--repo", default=None, help="Optional repository path for stack-adaptive ATLAS skill synthesis.")
    p_atlas.add_argument("--suites", default="low_resource,canary,ssrf_tool,atlas_dynamic", help="Comma-separated suites (all, multilingual, low_resource, canary, ssrf_tool, atlas_dynamic).")
    p_atlas.add_argument("--offline-stix", action="store_true", help="Skip live STIX download and use bundled golden snapshot.")
    p_atlas.add_argument("--concurrency", type=int, default=8, help="Max concurrent LLM requests.")
    p_atlas.add_argument("--out", default="out/atlas_llm_eval", help="Output directory for JSON + SARIF 2.1.0 report.")
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
    target_root: Optional[str] = None,
    exclude_speculative_and_preflight: bool = False,
) -> List[Any]:
    """Convert `run_unified_all_scans` finding dicts into `EngineFinding` instances."""
    from engine.ensemble_orchestrator import EngineFinding

    resolved_root: Optional[Path] = None
    if target_root:
        try:
            cand = Path(str(target_root)).resolve(strict=False)
            if cand.is_dir():
                resolved_root = cand
        except Exception:
            resolved_root = None

    converted: List[EngineFinding] = []
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
            except Exception:
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

        meta: Dict[str, Any] = {}
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
        all_scan_summary: Optional[Dict[str, Any]] = None
        offline_mode = (
            os.environ.get("RFCHUNT_OFFLINE") == "1"
            or bool(os.environ.get("CI"))
            or bool(args.embedded)
        )
        if args.findings_json:
            raw = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
            items = raw.get("findings", raw) if isinstance(raw, dict) else raw
            findings = [EngineFinding(**item) for item in items if isinstance(item, dict)]

        orch = EnsembleOrchestrator(
            program=args.program,
            freshness_hours=args.freshness_hours,
            quorum=args.quorum,
            exhaustive_default=True,
            embedded=bool(args.embedded),
            model=args.model,
            enable_llm_verify=(not args.no_llm and not args.embedded),
            gha_only=bool(args.gha_only),
            no_external_scanners=bool(getattr(args, "no_external_scanners", False)),
            proxy=getattr(args, "proxy", None),
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
                    with tempfile.TemporaryDirectory(prefix="rfchunt_unified_") as unified_reports_dir:
                        with (contextlib.redirect_stdout(sys.stderr) if args.json_out else contextlib.nullcontext()):
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
                    )
                    orch.last_telemetry = tele
                    findings = [*converted, *auto_findings]
                except Exception as exc:
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
            print(
                f"[+] Exhaustive Ensemble Audit ({mode_tag}) complete: {len(rep.clusters)} clusters "
                f"({rep.counts_by_disposition}) | whiteboard_hyps={wb.get('total_hypotheses', len(wb.get('hypotheses') or []))} "
                f"| lean={lv.get('status', 'unknown')} | available_toolchains={avail_tc or 'none'} "
                f"| proxy={rep.proxy or 'none'} -> {args.out}"
            )
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


_ENSEMBLE_TRIGGER_FLAGS = {"--ensemble", "--essemble", "--essample", "--embedded", "--embeded"}


def _translate_swarm_argv_to_ensemble(argv: Sequence[str]) -> tuple[List[str], bool]:
    """Translates `rfc_hunt_swarm.py --all [--ensemble|--essemble|--essample] [--embedded|--embeded]` into `ensemble-audit` args."""
    tokens = list(argv)
    target: Optional[str] = None
    out_dir: str = "out/ensemble_audit"
    sarif_out: Optional[str] = None
    program: str = "generic"
    freshness_hours: str = "72"
    quorum: str = "2"
    model: Optional[str] = None
    findings_json: Optional[str] = None
    package_client: Optional[str] = None
    proxy: Optional[str] = "auto"
    embedded = False
    no_llm = False
    gha_only = False
    no_external_scanners = False
    json_out = False
    dry_run = False

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("--ensemble", "--essemble", "--essample"):
            i += 1
        elif tok in ("--embedded", "--embeded"):
            embedded = True
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

    mapped: List[str] = [
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
    if proxy:
        mapped.extend(["--proxy", proxy])
    return mapped, dry_run


def maybe_dispatch_revenue_cli(argv: Sequence[str]) -> Optional[int]:
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
