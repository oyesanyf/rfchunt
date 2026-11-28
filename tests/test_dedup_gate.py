"""
Offline tests for `engine/dedup_gate.py`:
  1. Local cross-report structural vector collision (`#4234132` -> `#4035475` in `started_round.rs`).
  2. Real temporary git repository history inspection + fresh `< 72h` diff-scoped hunk slicing.
  3. Mocked GitHub commits / PRs / issues / advisories upstream gate + offline/dry-run zero-network guarantee.
  4. Surface congestion & deep cross-boundary ranking of remaining Circle Arc drafts
     (AWS Nitro Enclave KMS + PQC Precompile outranking congested top-level consensus core).
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import urllib.request

import pytest

from engine.cash_bounty_tuner import seed_historical_findings_inventory
from engine.dedup_gate import (
    build_structural_signature,
    evaluate_dedup_gate,
    inspect_local_git_history,
    query_github_upstream_dedup,
    score_cross_report_similarity,
    score_draft_batch,
    score_surface_congestion,
    slice_changed_hunks,
)
from engine.hackerone_porter import HackerOneTicketStore


def _run_git(repo: Path, *args: str) -> None:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=True,
    )
    assert proc.returncode == 0


def test_cross_report_vector_blocks_overlapping_variant_of_duplicate_4234132(tmp_path: Path) -> None:
    store = HackerOneTicketStore(tmp_path / "tickets.db")
    seed_historical_findings_inventory(store)

    # Confirm #4234132 (INV-25) is now accurately tracked as duplicate of #4035475
    t25 = store.get_ticket("H1-ARC-BBP-INV-25")
    assert t25 is not None
    assert t25["state"] == "duplicate"
    assert "#4035475" in t25["remote_report_id"]

    prior_sigs = store.list_report_signatures(program_handle="arc-bbp")
    assert any(s["draft_id"] == "H1-ARC-BBP-INV-25" for s in prior_sigs)

    # A new variant targeting the exact same started_round.rs / Byzantine block-hash validation MUST hit HOLD_CROSS_REPORT_DUPLICATE
    overlapping_variant = {
        "rule_id": "ARC-VAR-999",
        "file_path": "consensus/src/started_round.rs",
        "title": "Unverified Byzantine proposer block hash bypasses may_be_stored_as_undecided() guard",
        "cwe": "CWE-841",
        "evidence": "started_round.rs accepts undecided proposal without may_be_stored_as_undecided() check",
    }
    gate = evaluate_dedup_gate(
        overlapping_variant,
        program_handle="arc-bbp",
        resolved_count=4,
        prior_signatures=prior_sigs,
    )
    assert gate.gate_verdict == "HOLD_CROSS_REPORT_DUPLICATE"
    assert gate.cross_report_similarity >= 0.72
    assert "H1-ARC-BBP-INV-25" in gate.closest_prior_report
    assert gate.adjusted_p_duplicate >= 0.90

    # Meanwhile a genuinely distinct AWS Nitro Enclave KMS attestation bug stays novel & low-congestion
    distinct_enclave = {
        "rule_id": "ARC-NITRO-NEW",
        "file_path": "crates/remote-signer/src/nitro_kms.rs",
        "title": "AWS Nitro Enclave PCR0 attestation nonce replay in KMS decrypt envelope",
        "cwe": "CWE-294",
        "evidence": "kms_decrypt_envelope() omits attestation nonce freshness verification",
    }
    gate_ok = evaluate_dedup_gate(
        distinct_enclave,
        program_handle="arc-bbp",
        resolved_count=4,
        prior_signatures=prior_sigs,
    )
    assert gate_ok.gate_verdict == "PASS_LOW_CONGESTION"
    assert gate_ok.congestion_tier == "LOW_CONGESTION_DEEP_BOUNDARY"


def test_local_git_history_patch_detection_and_fresh_code_hunk_slicing(tmp_path: Path) -> None:
    repo = tmp_path / "mini_repo"
    repo.mkdir()
    _run_git(repo, "init")
    _run_git(repo, "config", "user.name", "Test Dev")
    _run_git(repo, "config", "user.email", "dev@example.com")

    src = repo / "src"
    src.mkdir()
    target_file = src / "validator.rs"
    target_file.write_text("pub fn verify_round(hash: &[u8]) -> bool {\n    !hash.is_empty()\n}\n", encoding="utf-8")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "initial commit")

    # Land a fresh commit mentioning security guard + validation on validator.rs
    target_file.write_text(
        "pub fn verify_round(hash: &[u8]) -> bool {\n    if hash.len() != 32 { return false; }\n    !hash.is_empty()\n}\n",
        encoding="utf-8",
    )
    enclave_file = src / "nitro_attest.rs"
    enclave_file.write_text("pub fn check_pcr(doc: &[u8]) -> bool {\n    doc.len() > 0\n}\n", encoding="utf-8")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "fix: add Byzantine block hash validation guard in validator.rs")

    # 1. Local git log detects recent security commit -> likely_patched_in_git=True
    hist = inspect_local_git_history(str(repo), "src/validator.rs")
    assert hist.git_available is True
    assert hist.code_age_hours is not None and hist.code_age_hours < 2.0
    assert hist.likely_patched_in_git is True
    assert len(hist.recent_security_commits) >= 1

    # 2. Fresh-code diff slicer extracts exact changed files & line ranges landed within 72h
    slices = slice_changed_hunks(str(repo), since_hours=72)
    by_path = {s.file_path: s for s in slices}
    assert "src/validator.rs" in by_path
    assert "src/nitro_attest.rs" in by_path
    assert len(by_path["src/validator.rs"].changed_line_ranges) >= 1

    # 3. evaluate_dedup_gate on recently patched file triggers HOLD_LIKELY_PATCHED_UPSTREAM
    gate = evaluate_dedup_gate(
        {
            "file_path": "src/validator.rs",
            "title": "Missing hash length check in verify_round()",
            "cwe": "CWE-841",
        },
        program_handle="arc-bbp",
        local_repo_path=str(repo),
    )
    assert gate.gate_verdict == "HOLD_LIKELY_PATCHED_UPSTREAM"
    assert len(gate.upstream_hits) >= 1


def test_github_upstream_gate_mocked_and_offline_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    finding = {
        "file_path": "consensus/src/started_round.rs",
        "title": "Missing may_be_stored_as_undecided() guard in started_round.rs",
        "cwe": "CWE-841",
    }

    # Offline mode (RFCHUNT_OFFLINE=1) MUST never touch network
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    off_res = query_github_upstream_dedup(
        finding,
        repo_url="https://github.com/circlefin/arc-malachite",
        allow_network=True,
    )
    assert off_res.verdict == "OFFLINE_SKIPPED"

    # Mocked live GitHub API detects open PR + security advisory
    monkeypatch.setenv("RFCHUNT_OFFLINE", "0")

    class _FakeResp:
        def __init__(self, payload: object) -> None:
            self._buf = io.BytesIO(json.dumps(payload).encode("utf-8"))

        def read(self) -> bytes:
            return self._buf.read()

        def __enter__(self) -> "_FakeResp":
            return self

        def __exit__(self, *args) -> bool:
            return False

    def _fake_urlopen(req, timeout=5.0):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        assert url.startswith("https://api.github.com/")
        if "/commits?" in url:
            return _FakeResp([{"sha": "abcdef123456", "commit": {"message": "fix: add guard for Byzantine proposer"}}])
        if "/pulls?" in url:
            return _FakeResp([{"number": 412, "state": "open", "title": "Fix started_round.rs guard validation", "body": "Adds may_be_stored_as_undecided()"}])
        if "/search/issues?" in url:
            return _FakeResp({"items": [{"number": 411, "state": "closed", "title": "Byzantine hash bug"}]})
        if "/security-advisories?" in url:
            return _FakeResp([{"ghsa_id": "GHSA-test-1234-5678", "summary": "Validator deadlock in started_round.rs", "description": "CWE-841"}])
        return _FakeResp([])

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    live_res = query_github_upstream_dedup(
        finding,
        repo_url="https://github.com/circlefin/arc-malachite",
        allow_network=True,
        dry_run=False,
    )
    assert live_res.verdict == "LIKELY_PATCHED_OR_IN_REVIEW"
    assert len(live_res.matched_commits) == 1
    assert len(live_res.matched_prs) == 1
    assert len(live_res.matched_issues) == 1
    assert len(live_res.matched_advisories) == 1
    assert live_res.dup_risk_delta >= 0.50


def test_surface_congestion_ranks_nitro_kms_and_pqc_above_congested_consensus_core(tmp_path: Path) -> None:
    # Direct congestion comparison
    cong_started = score_surface_congestion(
        {"file_path": "consensus/src/started_round.rs", "title": "Byzantine block_hash guard"},
        code_age_hours=24.0 * 240.0,
        resolved_count=150,
    )
    cong_nitro = score_surface_congestion(
        {"file_path": "crates/remote-signer/src/nitro.rs", "title": "AWS Nitro Enclave KMS attestation binding"},
        code_age_hours=36.0,
        resolved_count=4,
    )
    assert cong_started.congestion_tier == "HIGH_CONGESTION_CROWDED"
    assert cong_nitro.congestion_tier == "LOW_CONGESTION_DEEP_BOUNDARY"
    assert cong_nitro.freshness_tier == "FRESH_72H"
    assert cong_nitro.congestion_score < cong_started.congestion_score

    # Batch scoring of seeded remaining 14 Circle Arc drafts: Nitro KMS & PQC Precompile MUST outrank congested INV-26 consensus core
    store = HackerOneTicketStore(tmp_path / "arc_rank.db")
    seed_historical_findings_inventory(store)
    arc_tickets = store.list_tickets(program_handle="arc-bbp", limit=50)
    arc_sigs = store.list_report_signatures(program_handle="arc-bbp")
    ranked = score_draft_batch(
        arc_tickets,
        prior_signatures=arc_sigs,
        program_resolved_counts={"arc-bbp": 4},
    )
    # Closed duplicate INV-25 is excluded from actionable queue
    ranked_ids = [r["draft_id"] for r in ranked]
    assert "H1-ARC-BBP-INV-25" not in ranked_ids
    assert len(ranked) == 14
    # Top ranks go to deep low-congestion boundaries (Nitro KMS INV-29 / PQC Precompile INV-28) ahead of congested INV-26
    idx_nitro = ranked_ids.index("H1-ARC-BBP-INV-29")
    idx_pqc = ranked_ids.index("H1-ARC-BBP-INV-28")
    idx_core = ranked_ids.index("H1-ARC-BBP-INV-26")
    assert idx_nitro < idx_core
    assert idx_pqc < idx_core
