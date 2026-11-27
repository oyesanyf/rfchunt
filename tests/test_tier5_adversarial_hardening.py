"""
Tier 5 Adversarial Hardening & Regression Test Suite (Zero Mocks).
=================================================================

Validates all M4 security, concurrency, lifecycle, and pipeline invariants using
real SQLite WAL stores, real ThreadingHTTPServer loopback endpoints, real file
locks, real multiprocessing/asyncio execution, and real Z3 scope gates.

Strict Engineering Invariants:
  - ZERO mocks (`unittest.mock`, `MagicMock`, `AsyncMock`, `patch`, `monkeypatch`).
  - Zero Registry or system PATH mutations.
  - All synthetic secret strings constructed programmatically so static scanners
    never confuse test fixtures for live credentials.
"""

from __future__ import annotations

import ast
import asyncio
import gc
import json
import sys
import threading
import time
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import revenue_cli
from bugbounty_mcp_server import (
    BugBountyMCPServer,
    validate_and_stage_hackerone_draft,
)
from engine.advisory_exporter import (
    AdvisoryExporter,
    _redact_inline_tokens,
    neutralize_csv_cell,
)
from engine.async_blackboard_runtime import (
    SqliteBlackboard,
    run_local_rfchunt_async,
    run_stage1_cpu_check,
    sync_eligibility_and_stage_unlocks,
)
from engine.ensemble_orchestrator import (
    EngineFinding,
    EnsembleConsensusVoter,
    EnsembleOrchestrator,
    _finding_from_dict,
    evaluate_and_stage_submission,
)
from engine.freshness_watcher import (
    AsyncFreshnessPoller,
    FreshnessStateStore,
    FreshnessWatcher,
)
from engine.gha_llm_verifier import verify_gha_findings_with_llm
from engine.linux_poc_runner import LinuxPocRunner
from engine.ollama_concurrency_guard import OllamaConcurrencyGuard
from engine.parity_invariant_auditor import filter_production_candidates
from engine.program_eligibility_db import ProgramEligibilityDB
from engine.z3_formal_verifier import (
    ScopeGateDeniedError,
    run_z3_formal_verification,
)


def _make_fake_openai_proj_key() -> str:
    return "sk-" + "proj-" + ("AbCdEf123456_" * 2) + "XyZ987"


def _make_fake_openai_classic_key() -> str:
    return "sk-" + ("A1b2C3d4" * 6)


def _make_fake_google_key() -> str:
    return "AIza" + ("SyD1234567890abcdefghij" + "klmnopqrstuv")[:35]


def _seed_unlocked_db(db_path: Path, handles: tuple[str, ...] = ("anthropic", "shopify")) -> ProgramEligibilityDB:
    db = ProgramEligibilityDB(db_path)
    for handle in handles:
        db.upsert(handle, "UNLOCKED", bounty_min_usd=500, bounty_max_usd=25000)
    return db


# ---------------------------------------------------------------------------
# 1. Strict boolean poc_verified fail-closed rejection across all gates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("falsy_val", ["false", "FALSE", "0", "no", "off", "", None, False, 0])
def test_tier5_strict_poc_verified_fail_closed_across_gates(tmp_path: Path, falsy_val: object) -> None:
    elig_db = _seed_unlocked_db(tmp_path / "elig.sqlite3", handles=("anthropic",))

    # 1a. evaluate_and_stage_submission must reject falsy strings / None
    sub_res = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/auth/verify.py",
        title="Missing authorization signature check in webhook verification",
        summary="Deterministic verification reveals unverified signature bypass in src/auth/verify.py.",
        impact="Allows forging signed webhook calls on production tenant.",
        poc_verified=falsy_val,
        eligibility_db=elig_db,
        output_dir=tmp_path / f"out_sub_{type(falsy_val).__name__}",
        trigger_browser=False,
    )
    assert sub_res["eligible"] is False
    assert sub_res["status"] != "staged_ready"
    assert sub_res["report_url"] is None

    # 1b. bb_stage_hackerone_draft MCP tool must reject falsy strings / None
    mcp = BugBountyMCPServer()
    draft_path = tmp_path / f"draft_{type(falsy_val).__name__}.json"
    mcp_res = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "bb_stage_hackerone_draft",
                "arguments": {
                    "program_handle": "anthropic",
                    "asset": "src/auth/verify.py",
                    "weakness_cwe": "CWE-345",
                    "severity_rating": "High",
                    "title": "Missing authorization signature check in webhook handler",
                    "vulnerability_information": (
                        "Detailed reproduction showing webhook handler skips HMAC validation "
                        "when header X-Sig-Mode is omitted on POST /hooks/receive in src/auth/verify.py."
                    ),
                    "impact": "Attackers can spoof tenant webhook events without holding signing secret.",
                    "poc_verified": falsy_val,
                    "out_path": str(draft_path),
                    "eligibility_db_path": str(elig_db.db_path),
                },
            },
        }
    )
    stage_payload = json.loads(mcp_res["result"]["content"][0]["text"])
    assert stage_payload["status"] != "staged_ready"
    staged_data = json.loads(Path(stage_payload["staged_file"]).read_text(encoding="utf-8"))
    assert staged_data["poc_verified"] is False
    assert stage_payload["report_url"] is None

    # 1c. _finding_from_dict & EnsembleConsensusVoter.fuse must coerce strictly
    ef = _finding_from_dict(
        {
            "engine": "trufflehog",
            "rule_id": "RULE-1",
            "title": "Leak check",
            "file_path": "src/app.py",
            "line": 12,
            "severity": "HIGH",
            "confidence": 0.9,
            "deterministic": True,
            "confirmed": True,
            "poc_verified": falsy_val,
        }
    )
    assert ef.poc_verified is False
    clusters = EnsembleConsensusVoter(program="anthropic", quorum=1).fuse([ef])
    assert len(clusters) == 1
    assert clusters[0].poc_verified is False
    assert clusters[0].disposition != "SUBMISSION_READY"

    # 1d. filter_production_candidates must reject falsy string poc_verified values
    prod_list, noise_list = filter_production_candidates(
        [
            {
                "engine": "parity_auditor",
                "rule_id": "PARITY-1",
                "file_path": "tests/test_sample.py",
                "summary": "test fixture",
                "poc_verified": falsy_val,
                "metadata": {"poc_verified": falsy_val},
            }
        ]
    )
    assert prod_list == []
    assert len(noise_list) == 1


def test_tier5_strict_poc_verified_async_runtime_and_loop5_unlocks(tmp_path: Path) -> None:
    elig_db = _seed_unlocked_db(tmp_path / "elig.sqlite3", handles=("shopify",))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    # Seed a blackboard fact with string "false" poc_verified and verify strict DB storage
    bb_path = tmp_path / "bb.sqlite3"
    with SqliteBlackboard(bb_path) as bb:
        fact_id = bb.add_fact(
            source_engine="api_jwt_sdjwt",
            title="Unsigned JWT accepted",
            file_path="src/jwt.py",
            line=8,
            severity="HIGH",
            poc_verified="false",  # type: ignore[arg-type]
        )
        assert isinstance(fact_id, str) and fact_id.startswith("fact_")
        stored = bb.list_facts()
        assert len(stored) == 1
        assert stored[0]["poc_verified"] is False

    # Loop 5 unlock staging must block drafts whose poc_verified is string "false" or "0"
    drafts_dir = tmp_path / "drafts"
    drafts_dir.mkdir()
    (drafts_dir / "shopify_false_string.json").write_text(
        json.dumps(
            {
                "program_handle": "shopify",
                "asset": "@shopify/shopify-app-remix",
                "package": "@shopify/shopify-app-remix",
                "title": "OAuth state bypass in @shopify/shopify-app-remix",
                "summary": "Reproduction verified in @shopify/shopify-app-remix callback route.",
                "poc_verified": "false",
            }
        ),
        encoding="utf-8",
    )
    (drafts_dir / "shopify_zero_string.json").write_text(
        json.dumps(
            {
                "program_handle": "shopify",
                "asset": "@shopify/shopify-app-remix",
                "package": "@shopify/shopify-app-remix",
                "title": "CSRF issue in @shopify/shopify-app-remix",
                "summary": "Verified check.",
                "poc_verified": "0",
            }
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "unlock_out"
    with SqliteBlackboard(bb_path) as bb:
        sync_res = sync_eligibility_and_stage_unlocks(elig_db, bb, drafts_dir, out_dir=out_dir)
    assert len(sync_res["staged_drafts"]) == 0
    assert len(sync_res["blocked_drafts"]) == 2
    assert not (out_dir / "READY_TO_SUBMIT.json").exists()

    # Verify run_local_rfchunt_async handles strict boolean on embedded planning intent
    async_res = asyncio.run(
        run_local_rfchunt_async(
            [{"intent_type": "diff_scan", "payload": {"program": "shopify"}}],
            repo_path=repo,
            db_path=tmp_path / "bb2.sqlite3",
            max_cpu_workers=1,
            eligibility_db_path=elig_db.db_path,
        )
    )
    assert async_res["intents_completed"] >= 1


# ---------------------------------------------------------------------------
# 2. Complete OpenAI & Google API key redaction + Loop 5 scrubbing/threat gate
# ---------------------------------------------------------------------------


def test_tier5_openai_and_google_key_redaction_end_to_end(tmp_path: Path) -> None:
    key_proj = _make_fake_openai_proj_key()
    key_classic = _make_fake_openai_classic_key()
    key_google = _make_fake_google_key()

    sample_blob = (
        f"Leaked OpenAI proj={key_proj} and classic={key_classic} and GCP={key_google} in logs."
    )
    redacted = _redact_inline_tokens(sample_blob)
    assert key_proj not in redacted
    assert key_classic not in redacted
    assert key_google not in redacted
    assert "<REDACTED" in redacted

    elig_db = _seed_unlocked_db(tmp_path / "elig.sqlite3", handles=("anthropic", "shopify"))

    # 2a. evaluate_and_stage_submission redacts keys in output artifacts
    sub_out = tmp_path / "sub_out"
    sub_res = evaluate_and_stage_submission(
        program="anthropic",
        asset="src/config/keys.py",
        title=f"Hardcoded provider token {key_proj} in client bundle",
        summary=f"Exposed credentials {key_classic} and {key_google} in shipped config.",
        impact=f"Allows unauthorized API usage with {key_google}.",
        poc_verified=True,
        poc_transcript=f"curl returned token {key_proj}",
        eligibility_db=elig_db,
        output_dir=sub_out,
        trigger_browser=False,
    )
    assert sub_res["eligible"] is True
    ready_file = Path(sub_res["ready_to_submit_path"])
    ready_text = ready_file.read_text(encoding="utf-8")
    for secret in (key_proj, key_classic, key_google):
        assert secret not in ready_text

    # 2b. bb_stage_hackerone_draft redacts keys in JSON output
    draft_out = tmp_path / "staged_draft.json"
    draft_res = validate_and_stage_hackerone_draft(
        program_handle="anthropic",
        asset="src/config/keys.py",
        weakness_cwe="CWE-798",
        severity_rating="High",
        title=f"Exposed credentials {key_proj} in bundle",
        vulnerability_information=(
            f"Detailed reproduction proving secret {key_classic} and API token {key_google} "
            "are embedded in the compiled client distribution without server-side isolation."
        ),
        impact=f"Any user can extract {key_google} and bill quota against vendor account.",
        poc_verified=True,
        poc_transcript=f"Extracted {key_proj} cleanly",
        out_path=str(draft_out),
        eligibility_db=elig_db,
    )
    assert draft_res["status"] == "staged_ready"
    draft_disk_text = draft_out.read_text(encoding="utf-8")
    for secret in (key_proj, key_classic, key_google):
        assert secret not in draft_disk_text
        assert secret not in json.dumps(draft_res)

    # 2c. sync_eligibility_and_stage_unlocks scrubs keys AND enforces evaluate_vendor_threat_model
    drafts_dir = tmp_path / "loop5_drafts"
    drafts_dir.mkdir()
    # Out-of-scope Shopify draft (local CLI self-execution) should be blocked by threat model
    (drafts_dir / "shopify_local_dev_noise.json").write_text(
        json.dumps(
            {
                "program_handle": "shopify",
                "asset": "packages/ucp-cli/src/index.ts",
                "title": "Local CLI self-execution via user-supplied --exec flag in ucp-cli",
                "summary": f"Local-only CLI runs caller-supplied command with {key_proj}",
                "poc_verified": True,
            }
        ),
        encoding="utf-8",
    )
    # In-scope @shopify/shopify-app-remix verified draft containing keys should pass threat model AND be scrubbed
    (drafts_dir / "shopify_valid_app_remix.json").write_text(
        json.dumps(
            {
                "program_handle": "shopify",
                "asset": "@shopify/shopify-app-remix/src/auth.ts",
                "package": "@shopify/shopify-app-remix",
                "title": f"Session token leak in @shopify/shopify-app-remix ({key_proj})",
                "summary": f"Auth handler leaks {key_classic} and {key_google} across tenant boundary.",
                "poc": f"PoC output captured {key_google}",
                "poc_verified": True,
            }
        ),
        encoding="utf-8",
    )
    unlock_out = tmp_path / "loop5_out"
    with SqliteBlackboard(tmp_path / "loop5_bb.sqlite3") as bb:
        sync_res = sync_eligibility_and_stage_unlocks(elig_db, bb, drafts_dir, out_dir=unlock_out)
    assert len(sync_res["staged_drafts"]) == 1
    assert len(sync_res["blocked_drafts"]) == 1
    assert "blocked_threat_model" in sync_res["blocked_drafts"][0]["reasons"]
    unlock_disk = (unlock_out / "READY_TO_SUBMIT.json").read_text(encoding="utf-8")
    for secret in (key_proj, key_classic, key_google):
        assert secret not in unlock_disk


# ---------------------------------------------------------------------------
# 3. Malformed / traversal / empty program handles fail closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_handle", ["", "   ", "../shopify", "anthropic\x00", "org/sub\\pkg"])
def test_tier5_malformed_and_traversal_program_handles_fail_closed(
    tmp_path: Path, bad_handle: str
) -> None:
    elig_db = _seed_unlocked_db(tmp_path / "elig.sqlite3", handles=("anthropic", "shopify"))

    # ProgramEligibilityDB.is_eligible must never unlock bad/traversal handles
    assert elig_db.is_eligible(bad_handle) is False
    if not bad_handle.strip():
        with pytest.raises(ValueError):
            elig_db.upsert(bad_handle, "UNLOCKED")

    # evaluate_and_stage_submission must block
    sub_res = evaluate_and_stage_submission(
        program=bad_handle,
        asset="src/auth.py",
        title="Valid vulnerability title for test",
        summary="Detailed security issue description.",
        poc_verified=True,
        eligibility_db=elig_db,
        output_dir=tmp_path / "sub_bad",
        trigger_browser=False,
    )
    assert sub_res["eligible"] is False
    assert sub_res["status"] == "blocked_ineligible"
    assert sub_res["report_url"] is None

    # validate_and_stage_hackerone_draft must block and emit report_url=None, submit_url=None
    draft_res = validate_and_stage_hackerone_draft(
        program_handle=bad_handle,
        asset="src/auth.py",
        weakness_cwe="CWE-287",
        severity_rating="High",
        title="Missing authentication enforcement on admin action",
        vulnerability_information=(
            "Complete reproduction demonstrating unauthenticated access to protected "
            "administrative endpoint without session cookie or bearer signature."
        ),
        impact="Unauthorized state mutation across tenant accounts.",
        poc_verified=True,
        out_path=str(tmp_path / "bad_draft.json"),
        eligibility_db=elig_db,
    )
    assert draft_res["status"] != "staged_ready"
    assert draft_res["report_url"] is None
    assert draft_res["submit_url"] is None


# ---------------------------------------------------------------------------
# 4. OllamaConcurrencyGuard cooldown half-open recovery & thread timeout
# ---------------------------------------------------------------------------


def test_tier5_ollama_concurrency_guard_half_open_and_timeout(tmp_path: Path) -> None:
    guard = OllamaConcurrencyGuard(
        lock_path=tmp_path / "ollama_slot.lock",
        acquire_timeout_sec=0.05,
        failure_threshold=2,
        cooldown_sec=0.06,
    )

    assert guard.is_circuit_open() is False
    guard.record_failure()
    assert guard.is_circuit_open() is False
    guard.record_failure()
    assert guard.is_circuit_open() is True

    # Wait past cooldown -> transitions to half-open (allows 1 probe)
    time.sleep(0.09)
    assert guard.is_circuit_open() is False

    # A single failure in half-open immediately re-opens the circuit
    guard.record_failure()
    assert guard.is_circuit_open() is True

    # Wait past cooldown again -> single success resets breaker cleanly
    time.sleep(0.09)
    assert guard.is_circuit_open() is False
    guard.record_success()
    assert guard.is_circuit_open() is False

    # Multi-thread lock contention timeout rejection
    acquired_event = threading.Event()
    release_event = threading.Event()
    holder_results: list[bool] = []
    contender_results: list[bool] = []

    def _holder() -> None:
        with guard.acquire(timeout_sec=1.0) as got:
            holder_results.append(got)
            acquired_event.set()
            release_event.wait(timeout=1.0)

    t_hold = threading.Thread(target=_holder, daemon=True)
    t_hold.start()
    assert acquired_event.wait(timeout=1.0)

    def _contender() -> None:
        with guard.acquire(timeout_sec=0.05) as got:
            contender_results.append(got)

    t_wait = threading.Thread(target=_contender, daemon=True)
    t_wait.start()
    t_wait.join(timeout=2.0)
    release_event.set()
    t_hold.join(timeout=2.0)

    assert holder_results == [True]
    assert contender_results == [False]


# ---------------------------------------------------------------------------
# 5. SqliteBlackboard + FreshnessStateStore lifecycle, WAL checkpoint & warnings
# ---------------------------------------------------------------------------


def test_tier5_sqlite_context_manager_wal_checkpoint_no_resource_warnings(tmp_path: Path) -> None:
    bb_db = tmp_path / "bb_lifecycle.sqlite3"
    fresh_db = tmp_path / "fresh_lifecycle.sqlite3"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)

        # Normal context manager lifecycle
        with SqliteBlackboard(bb_db) as bb:
            bb.add_fact(
                source_engine="trufflehog",
                title="Token test",
                file_path="src/a.py",
                line=5,
                severity="MEDIUM",
            )
            assert len(bb.list_facts()) == 1

        # Exception path still closes cleanly and checkpoints WAL
        with pytest.raises(RuntimeError, match="boom"), SqliteBlackboard(bb_db) as bb:
            bb.add_fact(
                source_engine="parity_auditor",
                title="Exception path fact",
                file_path="src/b.py",
                line=9,
                severity="HIGH",
            )
            raise RuntimeError("boom")

        # FreshnessStateStore normal + exception lifecycle
        with FreshnessStateStore(fresh_db) as store:
            assert store.is_seen("github:org/repo", "sha-1") is False
            store.mark_seen("github:org/repo", "sha-1")
            assert store.is_seen("github:org/repo", "sha-1") is True

        with pytest.raises(ValueError, match="abort"), FreshnessStateStore(fresh_db) as store:
            store.mark_seen("github:org/repo", "sha-2")
            raise ValueError("abort")

        # FreshnessWatcher & AsyncFreshnessPoller context manager lifecycle
        with FreshnessWatcher(state_db=fresh_db) as watcher:
            assert watcher.store.is_seen("github:org/repo", "sha-2") is True

        with AsyncFreshnessPoller(api_base="http://127.0.0.1", state_db=fresh_db) as poller:
            assert poller.store.is_seen("github:org/repo", "sha-1") is True

        gc.collect()

    resource_warnings = [w for w in caught if issubclass(w.category, ResourceWarning)]
    assert resource_warnings == []

    # Re-open verifies both writes survived WAL checkpoint cleanly
    with SqliteBlackboard(bb_db) as bb_check:
        assert len(bb_check.list_facts()) == 2


# ---------------------------------------------------------------------------
# 6. CLI --findings-json extra fields, MCP bb_run_fast_ooda out_dir & CSV cells
# ---------------------------------------------------------------------------


def test_tier5_cli_findings_json_mcp_fast_ooda_out_dir_and_csv_cells(tmp_path: Path) -> None:
    findings_json = tmp_path / "extra_findings.json"
    findings_json.write_text(
        json.dumps(
            [
                {
                    "engine": "trufflehog",
                    "rule_id": "CUSTOM-KEY",
                    "title": "Secret in server config",
                    "file_path": "src/server.py",
                    "line": 14,
                    "line_number": 14,
                    "raw_scanner": "custom-extra-field",
                    "severity": "HIGH",
                    "confidence": 0.92,
                    "deterministic": True,
                    "confirmed": True,
                    "poc_verified": "false",
                }
            ]
        ),
        encoding="utf-8",
    )
    cli_target = tmp_path / "cli_repo"
    cli_target.mkdir()
    (cli_target / "server.py").write_text("print('ok')\n", encoding="utf-8")
    cli_out = tmp_path / "cli_out"
    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(cli_target),
            "--findings-json",
            str(findings_json),
            "--program",
            "anthropic",
            "--embedded",
            "--out",
            str(cli_out),
        ]
    )
    assert rc == 0
    cli_report_path = cli_out / "ensemble_report.json"
    assert cli_report_path.exists()
    cli_report = json.loads(cli_report_path.read_text(encoding="utf-8"))
    assert cli_report["clusters"][0]["poc_verified"] is False

    # MCP bb_run_fast_ooda must honor out_dir and persist fast_ooda_report.json
    repo = tmp_path / "mcp_repo"
    repo.mkdir()
    (repo / "service.py").write_text("def health():\n    return {'ok': True}\n", encoding="utf-8")
    ooda_out = tmp_path / "mcp_fast_ooda_out"
    mcp = BugBountyMCPServer()
    mcp_resp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 202,
            "method": "tools/call",
            "params": {
                "name": "bb_run_fast_ooda",
                "arguments": {
                    "target": str(repo),
                    "program": "anthropic",
                    "embedded": True,
                    "cpu_workers": 1,
                    "blackboard_db": str(tmp_path / "mcp_ooda_bb.sqlite3"),
                    "out_dir": str(ooda_out),
                },
            },
        }
    )
    ooda_payload = json.loads(mcp_resp["result"]["content"][0]["text"])
    expected_report = ooda_out / "fast_ooda_report.json"
    assert expected_report.exists()
    assert ooda_payload["report_path"] == str(expected_report)

    # CSV formula injection edge cases (\t=, \r+)
    assert neutralize_csv_cell("\t=CMD()") == "'\t=CMD()"
    assert neutralize_csv_cell("\r+1+1") == "'\r+1+1"
    exporter = AdvisoryExporter(tmp_path / "adv_reports")
    csv_out = tmp_path / "adv_reports" / "findings.csv"
    csv_text = exporter.export_findings_csv(
        [
            {
                "id": "C-1",
                "title": "\t=1+1",
                "severity": "HIGH",
                "cwe": "CWE-79",
                "file": "\r+evil.py",
                "line": 1,
                "description": "=HYPERLINK(\"http://x\")",
            }
        ],
        output_path=csv_out,
    )
    assert csv_out.exists()
    assert "'\t=1+1" in csv_text
    assert "'\r+evil.py" in csv_text


# ---------------------------------------------------------------------------
# 7. Z3 fail-closed ScopeGateDeniedError & Findings #3/#4/#5 regressions
# ---------------------------------------------------------------------------


def test_tier5_z3_scope_gate_denied_error_fail_closed() -> None:
    with pytest.raises(ScopeGateDeniedError):
        run_z3_formal_verification(
            target_name="http://169.254.169.254/latest/meta-data",
            scope_policy={"allowed_domains": ["example.com"]},
            target_intent={
                "target_url": "http://169.254.169.254/latest/meta-data",
                "action": "formal_verify",
                "method": "GET",
            },
        )


def test_tier5_loop2_sibling_parity_scoped_and_gha_non_gha_prompt(tmp_path: Path) -> None:
    # Finding #3: sibling_parity with explicit target_files avoids unrelated files
    repo = tmp_path / "scoped_repo"
    (repo / "sdk" / "ts").mkdir(parents=True)
    (repo / "unrelated").mkdir(parents=True)
    (repo / "sdk" / "ts" / "auth.ts").write_text("export const ok = 1;\n", encoding="utf-8")
    (repo / "unrelated" / "secret.py").write_text(
        f'KEY = "{_make_fake_openai_proj_key()}"\n', encoding="utf-8"
    )
    res = run_stage1_cpu_check(
        {
            "intent_type": "sibling_parity",
            "repo_path": str(repo),
            "target_files": ["sdk/ts/auth.ts"],
            "embedded": True,
            "no_external_scanners": True,
        }
    )
    assert res["ok"] is True
    assert "parity_auditor" in res["scanners_run"]
    assert "trufflehog" not in res["scanners_run"]
    assert res["scanned_files"] == ["sdk/ts/auth.ts"]
    emitted_files = [str(f.get("file_path") or "") for f in res["production_findings"]]
    assert not any("unrelated" in p for p in emitted_files)

    # Finding #4: poc_runner in run_fast_parallel_ooda stays fail-closed when no explicit target exists
    orch = EnsembleOrchestrator(program="anthropic", embedded=True, max_workers=1)
    ooda_res = orch.run_fast_parallel_ooda(
        repo,
        program="anthropic",
        blackboard_db=tmp_path / "fail_closed_poc_bb.sqlite3",
        max_cpu_workers=1,
        poc_runner=LinuxPocRunner(),
    )
    for cl in ooda_res["clusters"]:
        assert cl["poc_verified"] is False

    # Finding #4: gha_llm_verifier passes summary and uses non-GHA prompt for production code
    captured_requests: list[dict] = []

    class _LoopbackOllama(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/api/tags":
                body = json.dumps({"models": [{"name": "qwen2.5:1.5b"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            captured_requests.append(json.loads(raw))
            resp = {
                "message": {
                    "content": json.dumps(
                        {
                            "verdicts": [
                                {
                                    "file_path": "src/payments/webhook.py",
                                    "line": 22,
                                    "severity": "HIGH",
                                    "confirmed": True,
                                    "confidence": 0.9,
                                    "recommended_fix": "Verify HMAC signature on POST /hooks/receive.",
                                }
                            ],
                            "attack_chains": [],
                        }
                    )
                }
            }
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            _ = (format, args)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackOllama)
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()
    try:
        port = srv.server_address[1]
        prod_finding = EngineFinding(
            engine="api_jwt_sdjwt",
            rule_id="JWT-001",
            title="Unsigned webhook token",
            file_path="src/payments/webhook.py",
            line=22,
            severity="HIGH",
            summary="UNIQUE_SUMMARY_MARKER_PROD_CONTEXT",
            deterministic=True,
            confirmed=True,
        )
        guard = OllamaConcurrencyGuard(lock_path=tmp_path / "llm_guard.lock")
        llm_findings, tele = verify_gha_findings_with_llm(
            repo,
            [prod_finding],
            model="qwen2.5:1.5b",
            embedded=False,
            offline=False,
            ollama_endpoint=f"http://127.0.0.1:{port}",
            force_ollama=True,
            guard=guard,
        )
        assert tele["status"] == "completed"
        assert len(llm_findings) == 1
        assert llm_findings[0].confirmed is True
        assert llm_findings[0].file_path == "src/payments/webhook.py"
        assert len(captured_requests) == 1
        msgs = captured_requests[0]["messages"]
        assert "application and infrastructure security" in msgs[0]["content"].lower()
        assert "UNIQUE_SUMMARY_MARKER_PROD_CONTEXT" in msgs[1]["content"]
    finally:
        srv.shutdown()
        srv.server_close()
        srv_thread.join(timeout=2.0)


def test_tier5_loop5_worker_short_circuit_remote_and_no_local_repo(tmp_path: Path) -> None:
    elig_db = _seed_unlocked_db(
        tmp_path / "elig_loop5_shortcircuit.sqlite3",
        handles=("henkel_vdp", "anthropic"),
    )
    repo = tmp_path / "loop5_repo"
    repo.mkdir()
    (repo / "app.py").write_text("def health():\n    return True\n", encoding="utf-8")
    bb_path = tmp_path / "loop5_shortcircuit_bb.sqlite3"

    res = asyncio.run(
        run_local_rfchunt_async(
            None,
            repo_path=repo,
            db_path=bb_path,
            max_cpu_workers=1,
            signal_score=0.0,
            eligibility_db_path=elig_db.db_path,
        )
    )
    assert res["status"] == "completed"
    assert res["intents_failed"] == 0
    assert res["intents_completed"] >= 3

    with SqliteBlackboard(bb_path) as bb_after:
        done_intents = bb_after.list_intents(status="DONE", limit=100)
    statuses = {
        str((it.get("result") or {}).get("status") or "")
        for it in done_intents
        if it.get("intent_type") in ("vdp_signal_lift", "diff_scan", "unlock_queued")
    }
    assert "queued_remote" in statuses
    assert "skipped_no_local_repo" in statuses


def test_tier5_zero_mocks_in_this_suite() -> None:
    src = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden = {"unittest.mock", "MagicMock", "AsyncMock", "monkeypatch"}
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden or alias.name.startswith("unittest.mock"):
                    found.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith("unittest.mock") or mod in forbidden:
                found.append(mod)
            for alias in node.names:
                if alias.name in forbidden:
                    found.append(alias.name)
    assert found == []
