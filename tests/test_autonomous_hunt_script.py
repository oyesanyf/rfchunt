"""
Zero-Mock Tests for `scripts/autonomous_hunt.py` (Standalone Headless Hunting Runner).
Verifies safety violation checks, ProgramEligibilityDB gating, repo-slug validation,
dry-run planning, and real end-to-end single-cycle embedded execution with zero mocks.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import hunt as root_hunt
import rfc_hunt_swarm
from bugbounty_mcp_server import BugBountyMCPServer
from engine.ensemble_orchestrator import EnsembleOrchestrator
from engine.hackerone_porter import (
    HackerOneCampaign,
    HackerOneComputerUsePorter,
    HackerOneReportDraft,
)
from engine.program_eligibility_db import ProgramEligibilityDB
from mcp_server import TerminatorMCPServer
from scripts.autonomous_hunt import (
    build_parser,
    check_program_eligibility,
    execute_hunt_cycle,
    extract_verified_findings_from_cycle,
    open_urls_in_chrome,
    scan_draft_safety_violations,
    validate_repo_slug,
)
from scripts.autonomous_hunt import (
    main as hunt_main,
)


def test_safety_violation_scanner_catches_secrets_entities_and_control_chars() -> None:
    clean_draft = "# Valid Draft\n\nConfirmed CWE-22 at `src/store.ts:48` (`len < 64`).\n"
    assert scan_draft_safety_violations(clean_draft) == []

    # Synthetic fake token format + HTML entity leak + BEL control char
    dirty_draft = (
        "Title: `test` with &lt; comparison\n"
        "Leaked: AKIAIOSFODNN7EXAMPLE\n"
        "Control: bad\x07char\n"
    )
    violations = scan_draft_safety_violations(dirty_draft)
    codes = {v["code"] for v in violations}
    assert "SECRET_LEAK:aws_access_key" in codes
    assert "HTML_ENTITY_CORRUPTION" in codes
    assert "CONTROL_CHAR_OR_MOJIBAKE" in codes


def test_repo_slug_validation_blocks_traversal_and_shell_chars() -> None:
    assert validate_repo_slug("Shopify/shopify-app-js") == "Shopify/shopify-app-js"
    for bad in ("../etc/passwd", "owner/repo;rm -rf /", "owner/repo$(id)", "just_one_part"):
        with pytest.raises(ValueError):
            validate_repo_slug(bad)


def test_program_eligibility_gate_blocks_signal_locked_and_allows_unlocked(tmp_path: Path) -> None:
    db_path = tmp_path / "elig.sqlite3"
    db = ProgramEligibilityDB(db_path=db_path)
    db.upsert(
        "locked_prog",
        "BLOCKED_SIGNAL",
        signal_required=1.0,
        submit_url="https://hackerone.com/locked_prog/reports/new",
    )
    db.upsert(
        "open_prog",
        "UNLOCKED",
        signal_required=0.0,
        submit_url="https://hackerone.com/open_prog/reports/new",
    )

    ok_locked, reason_locked = check_program_eligibility("locked_prog", eligibility_db_path=str(db_path))
    assert not ok_locked
    assert "BLOCKED_SIGNAL" in reason_locked

    ok_open, reason_open = check_program_eligibility("open_prog", eligibility_db_path=str(db_path))
    assert ok_open
    assert reason_open == "unlocked"


def test_autonomous_hunt_dry_run_and_embedded_cycle(tmp_path: Path) -> None:
    repo_dir = tmp_path / "sample_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    out_dir = tmp_path / "hunt_out"
    parser = build_parser()
    dry_args = parser.parse_args(
        [
            "--target",
            str(repo_dir),
            "--program",
            "generic",
            "--out",
            str(out_dir),
            "--dry-run",
            "--skip-freshness",
            "--skip-lean",
        ]
    )
    dry_summary = execute_hunt_cycle(dry_args, 1)
    assert dry_summary["dry_run"] is True
    assert dry_summary["browser_used"] is False
    assert dry_summary["auto_submit_forbidden"] is True
    assert not out_dir.exists()

    # Real headless embedded cycle on the temporary workspace (zero mocks, zero network)
    rc = hunt_main(
        [
            "--target",
            str(repo_dir),
            "--program",
            "generic",
            "--out",
            str(out_dir),
            "--embedded",
            "--no-llm",
            "--no-external-scanners",
            "--skip-freshness",
            "--skip-lean",
            "--skip-qa-drafts",
            "--skip-check-drafts",
        ]
    )
    assert rc == 0
    latest_json = out_dir / "latest_summary.json"
    latest_md = out_dir / "latest_summary.md"
    ready_md = out_dir / "READY_TO_CLICK_SUBMIT.md"
    assert latest_json.is_file()
    assert latest_md.is_file()
    assert ready_md.is_file()
    parsed = json.loads(latest_json.read_text(encoding="utf-8"))
    assert parsed["browser_used"] is False
    assert parsed["anti_junk_guard_enabled"] is True
    assert parsed["safety_violations_count"] == 0
    assert len(parsed["targets_audited"]) == 1


def test_extract_verified_findings_filters_noise_and_stage_draft_blocks_submit(tmp_path: Path) -> None:
    report_path = tmp_path / "fast_ooda_report.json"
    report_path.write_text(
        json.dumps(
            {
                "clusters": [
                    {
                        "title": "Unverified speculative alert",
                        "file_path": "src/a.py",
                        "line": 10,
                        "disposition": "SPECULATIVE",
                        "poc_verified": False,
                    },
                    {
                        "title": "Verified symlink escape",
                        "file_path": "src/store.ts",
                        "line": 48,
                        "cwe": "CWE-59",
                        "severity": "HIGH",
                        "disposition": "CONFIRMED",
                        "poc_verified": True,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    verified = extract_verified_findings_from_cycle(tmp_path)
    assert len(verified) == 1
    assert verified[0]["file_path"] == "src/store.ts"
    assert verified[0]["evidence_lane"] == "LANE_1_POC"

    camp = HackerOneCampaign(
        handle="common_codes",
        name="Common Codes",
        url="https://hackerone.com/common_codes",
        submit_url="https://hackerone.com/common_codes/reports/new",
    )
    draft = HackerOneReportDraft(
        draft_id="H1-COMMON-1234",
        fingerprint="1234abcd",
        program_handle="common_codes",
        submit_url="https://hackerone.com/common_codes/reports/new",
        title="Verified symlink escape",
        weakness_cwe="CWE-59",
        severity_rating="high",
        asset_identifier="github.com/common-codes/app",
        evidence_lane="LANE_1_POC",
        poe_level=3,
        vulnerability_information="Reproducible PoC",
        impact="Arbitrary write",
        source_rule_id="PARITY-SYMLINK",
        source_scanner="parity_auditor",
        scope_match_status="in_scope",
    )
    res = HackerOneComputerUsePorter().stage_draft_ready_to_submit(camp, draft, dry_run=True)
    assert res["status"] == "dry_run_draft_stage_planned"
    assert res["auto_submit_forbidden"] is True
    assert res["captcha_bypass_forbidden"] is True
    assert res["final_submit_blocked_for_hitl"] is True
    assert res["auto_submitted"] is False

    # Chrome launcher validates strictly pinned https://hackerone.com/... URLs and rejects external domains
    chrome_plan = open_urls_in_chrome(
        ["https://hackerone.com/reports/4244042", "https://hackerone.com/reports/4244042"],
        dry_run=True,
    )
    assert chrome_plan["status"] == "dry_run_chrome_planned"
    assert chrome_plan["opened_urls"] == ["https://hackerone.com/reports/4244042"]
    with pytest.raises((ValueError, PermissionError)):
        open_urls_in_chrome(["https://evil.example.com/phish"], dry_run=True)


def test_python_hunt_entrypoint_builds_full_turnkey_argv(tmp_path: Path) -> None:
    ns_default = root_hunt.build_parser().parse_args([])
    argv_default = root_hunt.build_hunt_argv(ns_default)
    assert "--start-modelfusion" in argv_default
    assert "--clone-unlocked" in argv_default
    assert "--from-eligibility-db" in argv_default
    assert "--stage-drafts" in argv_default
    assert "--open-chrome" in argv_default
    assert "--watch" in argv_default

    ns_once = root_hunt.build_parser().parse_args(["--target", "repo_x", "--program", "common_codes", "--once", "--dry-run"])
    argv_once = root_hunt.build_hunt_argv(ns_once)
    assert "--target" in argv_once
    assert "common_codes" in argv_once
    assert "--watch" not in argv_once
    assert "--dry-run" in argv_once
    assert "--open-chrome" in argv_once

    # Bare `python hunt.py --dry-run` MUST NOT enter infinite --watch loop and MUST execute cleanly with 0 side effects
    ns_dry = root_hunt.build_parser().parse_args(["--dry-run"])
    argv_dry = root_hunt.build_hunt_argv(ns_dry)
    assert "--dry-run" in argv_dry
    assert "--watch" not in argv_dry
    dry_out = tmp_path / "hunt_dry_test"
    rc = root_hunt.main(["--dry-run", "--sync-public-directory", "--out", str(dry_out), "--json"])
    assert rc == 0
    assert not dry_out.exists()


def test_rfc_hunt_swarm_master_cli_hunt_dry_run_and_embedded_cycle(tmp_path: Path) -> None:
    repo_dir = tmp_path / "swarm_hunt_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "app.py").write_text("def greet(name: str) -> str:\n    return f'hi {name}'\n", encoding="utf-8")

    # 1. Verify argument translation from master CLI (`rfc_hunt_swarm.py --hunt ...`)
    raw_argv = [
        "--hunt",
        "--target",
        str(repo_dir),
        "--repo",
        "Shopify/shopify-app-js",
        "--program",
        "common_codes",
        "--sync-public-directory",
        "--min-efficiency",
        "85",
        "--portfolio-capacity",
        "4",
        "--once",
        "--headless-only",
        "--dry-run",
        "--json",
    ]
    parsed = rfc_hunt_swarm.parse_swarm_arguments(raw_argv)
    assert parsed.enable_autonomous_hunt is True
    forwarded = rfc_hunt_swarm.build_autonomous_hunt_argv(parsed, raw_argv=raw_argv)
    assert "--target" in forwarded and str(repo_dir) in forwarded
    assert "--repo" in forwarded and "Shopify/shopify-app-js" in forwarded
    assert "--program" in forwarded and "common_codes" in forwarded
    assert "--sync-public-directory" in forwarded
    assert "--once" in forwarded
    assert "--headless-only" in forwarded
    assert "--dry-run" in forwarded
    assert "--model" not in forwarded  # Preserves dynamic RAM-gated abliterated selector by default
    assert "--out" not in forwarded  # Preserves hunt.py default out/autonomous_hunt

    # 2. Live subprocess dry-run via master CLI (`rfc_hunt_swarm.py --hunt --sync-public-directory --dry-run`)
    dry_out = tmp_path / "swarm_hunt_dry"
    swarm_script = Path(__file__).resolve().parents[1] / "rfc_hunt_swarm.py"
    proc = subprocess.run(
        [
            sys.executable,
            str(swarm_script),
            "--hunt",
            "--sync-public-directory",
            "--dry-run",
            "--out",
            str(dry_out),
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=90,
        check=False,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    assert not dry_out.exists()
    dry_payload = json.loads(proc.stdout)
    assert dry_payload["dry_run"] is True
    assert dry_payload["auto_submit_forbidden"] is True
    planned_cmds = [s.get("command") or [] for s in (dry_payload.get("steps") or []) if s.get("command")]
    assert planned_cmds and all("rfc_hunt_swarm.py" in str(cmd[1]) for cmd in planned_cmds if len(cmd) > 1)

    # 2b. Live standalone 3-Stage Parallel OODA Funnel via master CLI (`--fast-ooda`) and `--all --fast-ooda --start-modelfusion --dry-run`
    ooda_out = tmp_path / "swarm_fast_ooda_out"
    proc_ooda = subprocess.run(
        [
            sys.executable,
            str(swarm_script),
            "--fast-ooda",
            "--repo",
            str(repo_dir),
            "--program",
            "generic",
            "--embedded",
            "--no-llm",
            "--blackboard-db",
            str(tmp_path / "ooda_bb.sqlite3"),
            "--out",
            str(ooda_out),
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    assert proc_ooda.returncode == 0, f"stderr={proc_ooda.stderr}\nstdout={proc_ooda.stdout}"
    ooda_doc = json.loads(proc_ooda.stdout)
    assert ooda_doc["status"] == "completed"
    assert "stage1" in ooda_doc and "stage2" in ooda_doc and "stage3" in ooda_doc
    assert (ooda_out / "fast_ooda_report.json").is_file()

    proc_combo_dry = subprocess.run(
        [
            sys.executable,
            str(swarm_script),
            "--all",
            "--fast-ooda",
            "--start-modelfusion",
            "--repo",
            str(repo_dir),
            "--dry-run",
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=90,
        check=False,
    )
    assert proc_combo_dry.returncode == 0, f"stderr={proc_combo_dry.stderr}\nstdout={proc_combo_dry.stdout}"
    assert json.loads(proc_combo_dry.stdout).get("dry_run") is True

    # 3. Live embedded single cycle via `rfc_hunt_swarm.py --hunt --once --embedded --headless-only`
    emb_out = tmp_path / "swarm_hunt_emb"
    proc_emb = subprocess.run(
        [
            sys.executable,
            str(swarm_script),
            "--hunt",
            "--target",
            str(repo_dir),
            "--program",
            "generic",
            "--once",
            "--headless-only",
            "--embedded",
            "--no-llm",
            "--out",
            str(emb_out),
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    assert proc_emb.returncode == 0, f"stderr={proc_emb.stderr}\nstdout={proc_emb.stdout}"
    assert (emb_out / "latest_summary.json").is_file()
    assert (emb_out / "READY_TO_CLICK_SUBMIT.md").is_file()


def test_regular_pentest_all_and_ensemble_use_all_tools_without_hunt(tmp_path: Path) -> None:
    repo_dir = tmp_path / "pentest_polyglot_repo"
    (repo_dir / "src").mkdir(parents=True, exist_ok=True)
    (repo_dir / "web").mkdir(parents=True, exist_ok=True)

    # Real JS bundle with DOM sinks, sourceMappingURL, and hidden admin endpoint
    (repo_dir / "web" / "app.bundle.js").write_text(
        'const ep = "/api/admin/export";\n'
        "function render(u) { document.body.innerHTML = u; eval(u); }\n"
        "//# sourceMappingURL=app.bundle.js.map\n",
        encoding="utf-8",
    )
    # Real JWT signature verification disabled bug
    (repo_dir / "src" / "auth.py").write_text(
        'import jwt\ndef decode_tok(t):\n    return jwt.decode(t, options={"verify_signature": False})\n',
        encoding="utf-8",
    )

    # 1. Regular pentest dry-run WITHOUT --hunt routes to regular pentest planner (NOT --hunt)
    swarm_script = Path(__file__).resolve().parents[1] / "rfc_hunt_swarm.py"
    dry_pentest = subprocess.run(
        [sys.executable, str(swarm_script), "--all", "--repo", str(repo_dir), "--dry-run", "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=90,
        check=False,
    )
    assert dry_pentest.returncode == 0, f"stderr={dry_pentest.stderr}\nstdout={dry_pentest.stdout}"
    dry_doc = json.loads(dry_pentest.stdout)
    assert dry_doc.get("dry_run") is True

    # 2. --ensemble (without --hunt) executes js_bundle + api_jwt_sdjwt + ACDSO Stage-2 ranking
    ens_out = tmp_path / "ens_out"
    orch = EnsembleOrchestrator(program="generic", embedded=True, enable_llm_verify=False)
    rep = orch.run(repo_dir, out_dir=ens_out)
    executed = set(orch.last_telemetry.get("engines_executed") or [])
    assert {"js_bundle", "api_jwt_sdjwt", "trufflehog", "parity_auditor", "lean4"}.issubset(executed)
    assert any("js_bundle" in c.engines for c in rep.clusters)
    assert "acdso_stage2" in orch.last_telemetry

    # 3. Regular --all (WITHOUT --hunt AND WITHOUT --ensemble) STILL invokes exhaustive local tools + JS + ACDSO
    all_out = tmp_path / "all_out"
    env_off = os.environ.copy()
    env_off["RFCHUNT_OFFLINE"] = "1"
    all_proc = subprocess.run(
        [
            sys.executable,
            str(swarm_script),
            "--all",
            "--repo",
            str(repo_dir),
            "--output-dir",
            str(all_out),
            "--no-preflight-live",
            "--no-include-models",
            "--no-auto-install",
            "--no-external-scanners",
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env_off,
        timeout=180,
        check=False,
    )
    assert all_proc.returncode == 0, f"stderr={all_proc.stderr}\nstdout={all_proc.stdout}"
    all_doc = json.loads(all_proc.stdout)
    elt = (all_doc.get("engines") or {}).get("exhaustive_local_tools") or {}
    assert elt.get("status") == "completed"
    elt_engines = set(elt.get("engines_executed") or [])
    assert {"js_bundle", "api_jwt_sdjwt", "trufflehog", "parity_auditor", "lean4"}.issubset(elt_engines)
    assert "acdso_stage2" in elt


def test_mcp_agent_tools_expose_hunt_and_bounty_engines_in_both_servers(tmp_path: Path) -> None:
    # 1. BugBountyMCPServer exposes bb_run_autonomous_hunt, bb_sync_public_directory, bb_qa_drafts, bb_check_drafts
    bb = BugBountyMCPServer()
    bb_list = bb.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    bb_names = {t["name"] for t in bb_list["result"]["tools"]}
    assert {
        "bb_run_autonomous_hunt",
        "bb_sync_public_directory",
        "bb_qa_drafts",
        "bb_check_drafts",
    }.issubset(bb_names)

    hunt_dry_resp = bb.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "bb_run_autonomous_hunt",
                "arguments": {
                    "sync_public_directory": True,
                    "dry_run": True,
                    "out_dir": str(tmp_path / "mcp_hunt_dry"),
                },
            },
        }
    )
    assert hunt_dry_resp["result"]["isError"] is False
    hunt_dry_data = json.loads(hunt_dry_resp["result"]["content"][0]["text"])
    assert hunt_dry_data["returncode"] == 0
    assert hunt_dry_data["auto_submit_forbidden"] is True
    assert hunt_dry_data["invoked_via"] == "rfc_hunt_swarm.py --hunt"
    assert not (tmp_path / "mcp_hunt_dry").exists()

    snap_file = tmp_path / "h1_snap.json"
    snap_file.write_text(
        json.dumps(
            {
                "programs": [
                    {
                        "handle": "acme_vdp",
                        "status": "UNLOCKED",
                        "response_efficiency_pct": 95.0,
                        "is_vdp": True,
                        "offers_bounties": False,
                        "in_scope_repos": ["acme/webapp"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    elig_db_p = tmp_path / "mcp_elig.sqlite3"
    sync_resp = bb.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "bb_sync_public_directory",
                "arguments": {
                    "eligibility_db_path": str(elig_db_p),
                    "snapshot_json": str(snap_file),
                },
            },
        }
    )
    assert sync_resp["result"]["isError"] is False
    sync_data = json.loads(sync_resp["result"]["content"][0]["text"])
    assert sync_data["upserted"] == ["acme_vdp"]

    qa_resp = bb.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "bb_qa_drafts",
                "arguments": {
                    "title": "Test Draft",
                    "program": "acme_vdp",
                    "markdown_body": "# Summary\nCheck `len &lt; 10`.\n",
                    "verify_sources": False,
                    "qa_db_path": str(tmp_path / "qa.sqlite3"),
                },
            },
        }
    )
    assert qa_resp["result"]["isError"] is False
    qa_data = json.loads(qa_resp["result"]["content"][0]["text"])
    assert qa_data["total_audited"] == 1
    assert "len < 10" in qa_data["results"][0]["repaired_body"]

    chk_resp = bb.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "bb_check_drafts",
                "arguments": {
                    "db_path": str(tmp_path / "chk.sqlite3"),
                    "seed_only": True,
                },
            },
        }
    )
    assert chk_resp["result"]["isError"] is False
    chk_data = json.loads(chk_resp["result"]["content"][0]["text"])
    assert chk_data["auto_submit_forbidden"] is True
    assert chk_data["total_drafts"] >= 1

    # 2. Primary TerminatorMCPServer (`mcp_server.py`) exposes run_autonomous_hunt + bounty/ML/QA tools
    with TerminatorMCPServer(db_path=str(tmp_path / "term.db")) as srv:
        t_list_resp = srv.handle_request({"jsonrpc": "2.0", "id": 10, "method": "tools/list"})
        t_names = {t["name"] for t in t_list_resp["result"]["tools"]}
        assert {
            "run_autonomous_hunt",
            "run_fast_ooda",
            "rank_bounty_programs",
            "sync_hackerone_directory",
            "score_fresh_commits",
            "cluster_recon_assets",
            "analyze_js_bundles",
            "classify_http_responses",
            "qa_bounty_drafts",
            "check_bounty_drafts",
        }.issubset(t_names)

        res_hunt_rpc = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "run_autonomous_hunt",
                    "arguments": {
                        "dry_run": True,
                        "sync_public_directory": True,
                        "out_dir": str(tmp_path / "term_hunt_dry"),
                    },
                },
            }
        )
        res_hunt = json.loads(res_hunt_rpc["result"]["content"][0]["text"])
        assert res_hunt["returncode"] == 0
        assert res_hunt["auto_submit_forbidden"] is True

        res_rank_rpc = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "rank_bounty_programs",
                    "arguments": {"eligibility_db_path": str(elig_db_p)},
                },
            }
        )
        res_rank = json.loads(res_rank_rpc["result"]["content"][0]["text"])
        assert "ranked_programs" in res_rank

        res_js_rpc = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "analyze_js_bundles",
                    "arguments": {
                        "bundles": [
                            {
                                "url": "app.js",
                                "content": 'fetch("/api/admin/users"); document.body.innerHTML = x;',
                            }
                        ]
                    },
                },
            }
        )
        res_js = json.loads(res_js_rpc["result"]["content"][0]["text"])
        assert res_js["total_endpoints_discovered"] >= 1
        assert res_js["total_dom_sinks"] >= 1


def test_help_and_docs_include_examples_for_all_flags() -> None:
    parser = rfc_hunt_swarm.build_swarm_parser()
    help_text = parser.format_help()
    cli_doc = (Path(__file__).resolve().parents[1] / "docs" / "CLI_REFERENCE.md").read_text(encoding="utf-8")

    missing_help_examples: list[str] = []
    missing_doc_flags: list[str] = []
    for act in parser._actions:
        opts = [o for o in act.option_strings if o.startswith("--")]
        if not opts or "--help" in opts:
            continue
        if "example:" not in (act.help or "").lower():
            missing_help_examples.append(opts[0])
        if not any(o in cli_doc for o in opts):
            missing_doc_flags.append(opts[0])

    assert missing_help_examples == [], f"Flags missing Example: in --help: {missing_help_examples[:15]}"
    assert missing_doc_flags == [], f"Flags missing from docs/CLI_REFERENCE.md: {missing_doc_flags[:15]}"
    assert "Example:" in help_text
    assert "--hunt" in help_text and "--fast-ooda" in help_text and "--start-modelfusion" in help_text
