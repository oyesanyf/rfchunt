"""
Offline tests for Precision STRIDE (`engine/stride_engine.py`), Cash-Tuned Bounty ROI
(`engine/cash_bounty_tuner.py`), and Persistent SQLite Ticket State (`HackerOneTicketStore`).

Directly validates all empirical lessons from the 39-finding RFCHunt security ledger:
  - Anthropic #4235888 (OpenProcess working as designed per threat model) -> DOCUMENTED_AS_DESIGNED
  - Shopify #24 (ucp-cli local CLI self-execution) -> BOUNDARY_NOT_CROSSED -> do_not_submit
  - Anthropic #4235866 (TLS 0x0304 opaque tunnel fallback) -> HARDENING_CANDIDATE_NOT_BOUNTY -> hardening_pr_only
  - Anthropic #4235906 / Shopify #19-#23 (unexecuted OS/runtime PoC) -> needs_live_poc
  - Shopify #4236500 / Google GHSA-797p (PROVEN_RUNTIME cross-boundary) -> top of Cash EV queue
  - Persistent SQLite ticket states, transition audit history, dry-run zero-DB creation, and 39-finding seeder.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.cash_bounty_tuner import (
    assess_runtime_poc_readiness,
    rank_submission_queue,
    score_finding_cash_ev,
    seed_historical_findings_inventory,
)
from engine.hackerone_porter import HackerOnePorter, HackerOneTicketStore
from engine.stride_engine import DynamicStrideThreatEngine


def test_precision_stride_blocks_as_designed_local_cli_and_hardening_candidates(tmp_path: Path) -> None:
    repo = tmp_path / "sandbox_proj"
    repo.mkdir()
    (repo / "SECURITY.md").write_text(
        "# Threat Model\n"
        "- Trust boundary: isolates untrusted guest workloads from host filesystem and network.\n"
        "- Out of threat model: Windows cross-session OpenProcess access by same-user processes is working as designed.\n",
        encoding="utf-8",
    )
    (repo / "proxy.ts").write_text("export function handleClientHello(buf: Uint8Array) { return buf[0] === 0x16; }\n", encoding="utf-8")

    stride_model = DynamicStrideThreatEngine.analyze_repository(str(repo))
    spec = stride_model["target_threat_model_spec"]
    assert "SECURITY.md" in spec["source_docs"]
    assert len(spec["explicit_non_goals"]) >= 1
    assert len(spec["explicit_trust_boundaries"]) >= 1

    # 1. Anthropic #4235888 pattern -> DOCUMENTED_AS_DESIGNED -> informative_prevented
    ev_designed = score_finding_cash_ev(
        {
            "rule_id": "WIN-OPENPROC-01",
            "title": "Windows Cross-Session OpenProcess(PROCESS_ALL_ACCESS) by same-user process",
            "severity": "HIGH",
            "cwe": "CWE-269",
            "file_path": "src/win/broker.rs",
            "poe_level": 3,
            "epistemic_status": "PROVEN_RUNTIME",
            "runtime_poe_verified": True,
        },
        stride_model=stride_model,
    )
    assert ev_designed.stride_verdict["verdict"] == "DOCUMENTED_AS_DESIGNED"
    assert ev_designed.target_ticket_state == "informative_prevented"
    assert ev_designed.recommended_route == "HOLD_DO_NOT_SUBMIT"

    # 2. Shopify #24 ucp-cli pattern -> BOUNDARY_NOT_CROSSED -> do_not_submit
    ev_cli = score_finding_cash_ev(
        {
            "rule_id": "CLI-PP-01",
            "title": "Prototype Pollution via RFC 6901 --set JSON Pointer in local CLI buildOperationInput",
            "severity": "MEDIUM",
            "cwe": "CWE-1321",
            "file_path": "ucp-cli/src/input.ts",
            "poe_level": 2,
            "epistemic_status": "PROVEN_STATIC_INVARIANT",
        },
        stride_model=stride_model,
    )
    assert ev_cli.stride_verdict["verdict"] == "BOUNDARY_NOT_CROSSED"
    assert ev_cli.target_ticket_state == "do_not_submit"

    # 3. Anthropic #4235866 pattern -> HARDENING_CANDIDATE_NOT_BOUNTY -> hardening_pr_only
    ev_hardening = score_finding_cash_ev(
        {
            "rule_id": "TLS-OPAQUE-01",
            "title": "TLS ClientHello 0x0304..0x03ff Opaque Tunnel fallback",
            "severity": "HIGH",
            "cwe": "CWE-436",
            "file_path": "src/tls-proxy.ts",
            "poe_level": 2,
            "epistemic_status": "PROVEN_STATIC_INVARIANT",
        },
        stride_model=stride_model,
    )
    assert ev_hardening.stride_verdict["verdict"] == "HARDENING_CANDIDATE_NOT_BOUNTY"
    assert ev_hardening.target_ticket_state == "hardening_pr_only"
    assert ev_hardening.recommended_route == "GITHUB_HARDENING_PR"


def test_runtime_poc_gate_holds_unexecuted_pocs_and_promotes_proven_runtime() -> None:
    # Anthropic #4235906 macOS APFS audited on Windows without macOS repro -> OS_MISMATCH_UNVERIFIED -> needs_live_poc
    poc_mac = assess_runtime_poc_readiness(
        {
            "title": "macOS Case-Insensitive APFS Seatbelt Bypass",
            "file_path": "src/sandbox/macos-seatbelt.ts",
            "poe_level": 2,
            "epistemic_status": "PROVEN_STATIC_INVARIANT",
        },
        current_os="windows",
    )
    assert poc_mac.required_runtime == "macos_apfs"
    assert poc_mac.poc_gate_status == "OS_MISMATCH_UNVERIFIED"
    assert poc_mac.poc_verified_runtime is False

    # Shopify #19 OAuth HMAC pending Node PoC -> NEEDS_LIVE_POC
    ev_node = score_finding_cash_ev(
        {
            "rule_id": "SHOP-OAUTH-01",
            "title": "OAuth Callback HMAC, Timestamp & state CSRF Bypass via Duplicate Query Parameter Differential",
            "severity": "HIGH",
            "cwe": "CWE-345",
            "file_path": "packages/shopify-app-js/src/oauth.ts",
            "poe_level": 2,
            "epistemic_status": "PROVEN_STATIC_INVARIANT",
        },
        program_meta={"handle": "shopify", "offers_bounties": True, "avg_bounty_low_usd": 1000, "avg_bounty_high_usd": 2500, "resolved_count": 200},
    )
    assert ev_node.stride_verdict["verdict"] == "CASH_GRADE_BOUNDARY_VIOLATION"
    assert ev_node.target_ticket_state == "needs_live_poc"
    assert ev_node.recommended_route == "RUN_LIVE_POC_FIRST"
    assert ev_node.runtime_poc["required_runtime"] == "node_js"

    # Verified PROVEN_RUNTIME cross-tenant JWT confusion -> SUBMIT_NEXT_SLOT (or QUEUE_COOL_OFF under cool-off)
    ev_proven = score_finding_cash_ev(
        {
            "rule_id": "JWT-TENANT-01",
            "title": "Missing iss/dest Validation Allows Storefront Buyer JWTs to Authenticate as Merchant Admin",
            "severity": "HIGH",
            "cwe": "CWE-287",
            "file_path": "src/auth/jwt_verify.py",
            "poe_level": 3,
            "epistemic_status": "PROVEN_RUNTIME",
            "runtime_poe_verified": True,
        },
        program_meta={"handle": "common_codes", "offers_bounties": True, "avg_bounty_low_usd": 2000, "avg_bounty_high_usd": 3000, "resolved_count": 5},
        cool_off_active=True,
    )
    assert ev_proven.stride_verdict["verdict"] == "CASH_GRADE_BOUNDARY_VIOLATION"
    assert ev_proven.recommended_route == "QUEUE_COOL_OFF"
    assert ev_proven.target_ticket_state == "held_cool_off"
    assert ev_proven.cash_ev_usd > 3000.0


def test_sqlite_ticket_store_lifecycle_dry_run_and_39_finding_inventory_seeder(tmp_path: Path) -> None:
    # 1. Dry-run MUST NOT create SQLite DB file on disk
    porter = HackerOnePorter(output_dir=str(tmp_path / "h1_dry"))
    dry_res = porter.port_findings(
        [
            {
                "rule_id": "INV-JWT-01",
                "title": "Missing iss validation allows cross-tenant admin bypass",
                "severity": "HIGH",
                "evidence_lane": "VERIFIED_EXPLOIT",
                "epistemic_status": "PROVEN_RUNTIME",
                "independent_oracles": ["runtime_poe_container"],
                "scanner": "PoEContainerVerifier",
                "cwe": "CWE-287",
                "file_path": "src/auth/jwt.py",
                "line_number": 42,
                "poe_level": 3,
                "runtime_poe_verified": True,
                "evidence": "Buyer token accepted by /admin/export",
            }
        ],
        program_handle="common_codes",
        cool_off_mode=True,
        dry_run=True,
    )
    assert dry_res["dry_run"] is True
    assert not (tmp_path / "h1_dry" / "hackerone_tickets.db").exists()

    # 2. Live port persists ticket into SQLite with full state transition audit trail
    live_res = porter.port_findings(
        [
            {
                "rule_id": "INV-JWT-01",
                "title": "Missing iss validation allows cross-tenant admin bypass",
                "severity": "HIGH",
                "evidence_lane": "VERIFIED_EXPLOIT",
                "epistemic_status": "PROVEN_RUNTIME",
                "independent_oracles": ["runtime_poe_container"],
                "scanner": "PoEContainerVerifier",
                "cwe": "CWE-287",
                "file_path": "src/auth/jwt.py",
                "line_number": 42,
                "poe_level": 3,
                "runtime_poe_verified": True,
                "evidence": "Buyer token accepted by /admin/export",
            }
        ],
        program_handle="common_codes",
        cool_off_mode=True,
        dry_run=False,
    )
    assert Path(live_res["ticket_db_path"]).is_file()
    draft_id = live_res["drafts"][0]["draft_id"]
    tk = porter.ticket_store.get_ticket(draft_id)
    assert tk is not None
    assert tk["state"] == "held_cool_off"
    assert tk["poc_verified_runtime"] == 1
    assert len(tk["history"]) == 1

    # Transition held_cool_off -> submitted -> bounty_awarded ($2,500)
    porter.ticket_store.transition_state(draft_id, "submitted", remote_report_id="#9990001", reason="manual_submit")
    paid = porter.ticket_store.transition_state(draft_id, "bounty_awarded", bounty_amount_usd=2500.0, reason="paid")
    assert paid["state"] == "bounty_awarded"
    assert paid["bounty_amount_usd"] == 2500.0
    tk_full = porter.ticket_store.get_ticket(draft_id)
    assert tk_full is not None and len(tk_full["history"]) == 3
    assert porter.ticket_store.get_state_summary()["total_bounty_usd"] == 2500.0

    # 3. 39-finding historical inventory seeder is idempotent and accurately tracks all 39 rows + paid programs
    inv_store = HackerOneTicketStore(tmp_path / "inventory.db")
    seed1 = seed_historical_findings_inventory(inv_store)
    seed2 = seed_historical_findings_inventory(inv_store)
    assert seed1["tickets_seeded"] == 39
    assert seed2["summary"]["total_tickets"] == 39
    assert seed2["summary"]["tracked_bounty_programs"] >= 12
    assert seed2["summary"]["by_state"]["duplicate"] == 4  # 3 Anthropic + Circle Arc #4234132
    assert seed2["summary"]["by_state"]["submitted"] == 1  # Shopify #4234525
    assert seed2["summary"]["by_state"]["queued_cooldown"] == 1  # Shopify #4236500
    assert seed2["summary"]["by_state"]["needs_live_poc"] == 5  # Shopify #19-#23
    assert seed2["summary"]["by_state"]["do_not_submit"] == 1  # Shopify #24 ucp-cli

    # Ranked paid programs put common_codes ($2k-$3k, 5 resolved) at top
    progs = inv_store.list_bounty_programs(bounties_only=True, limit=10)
    assert progs[0]["handle"] == "common_codes"

    # Ranked submission queue puts verified queued/held tickets ahead of unexecuted needs_live_poc
    q = rank_submission_queue(inv_store.list_tickets(limit=100))
    assert q[0]["draft_id"] == "H1-SHOPIFY-INV-18"  # #4236500 queued_cooldown verified Rust PoC
