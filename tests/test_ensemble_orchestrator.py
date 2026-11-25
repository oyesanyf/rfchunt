"""Zero-mock tests for `engine/ensemble_orchestrator.py` (`--all --ensemble`)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from engine.ensemble_orchestrator import (
    EngineFinding,
    EnsembleConsensusVoter,
    EnsembleOrchestrator,
    evaluate_vendor_threat_model,
    inspect_repo_freshness,
)
from engine.linux_poc_runner import VerifiableTranscript


def _git(repo: Path, *args: str, env_extra: dict | None = None) -> None:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=True,
    )
    assert proc.returncode == 0


def test_stage0_freshness_ranks_fresh_commit_above_stale_duplicate_risk(tmp_path: Path) -> None:
    repo = tmp_path / "sample_repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@rfchunt.local")
    _git(repo, "config", "user.name", "RFCHunt Tester")

    # 1. Backdated 90-day-old commit on stale_file.py
    stale_file = repo / "stale_file.py"
    stale_file.write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "stale_file.py")
    old_date = "2020-01-01T00:00:00Z"
    _git(
        repo,
        "commit",
        "-m",
        "old commit",
        env_extra={"GIT_AUTHOR_DATE": old_date, "GIT_COMMITTER_DATE": old_date},
    )

    # 2. Brand-new commit (<72h) on fresh_file.py
    fresh_file = repo / "fresh_file.py"
    fresh_file.write_text("y = 2\n", encoding="utf-8")
    _git(repo, "add", "fresh_file.py")
    _git(repo, "commit", "-m", "fresh commit")

    snap = inspect_repo_freshness(repo, freshness_hours=72)
    assert snap.is_git_repo is True
    assert snap.freshness_status == "FRESH_UNDER_72H"
    assert "fresh_file.py" in snap.fresh_files
    assert "stale_file.py" not in snap.fresh_files

    # Fuse two identical-severity multi-engine clusters: fresh_file.py must rank first
    findings = [
        EngineFinding(engine="mantis", title="Stale bug", file_path="stale_file.py", line=10, cwe="CWE-89", severity="HIGH"),
        EngineFinding(engine="raptor", title="Stale bug", file_path="stale_file.py", line=12, cwe="CWE-89", severity="HIGH"),
        EngineFinding(engine="mantis", title="Fresh bug", file_path="fresh_file.py", line=10, cwe="CWE-89", severity="HIGH"),
        EngineFinding(engine="raptor", title="Fresh bug", file_path="fresh_file.py", line=12, cwe="CWE-89", severity="HIGH"),
    ]
    voter = EnsembleConsensusVoter(program="generic", quorum=2)
    clusters = voter.fuse(findings, freshness=snap)
    assert len(clusters) == 2
    assert clusters[0].file_path == "fresh_file.py"
    assert clusters[0].changed_in_fresh_diff is True
    assert clusters[0].freshness_status == "FRESH_UNDER_72H"


def test_stage4_hard_live_poc_gate_caps_static_only_consensus() -> None:
    findings = [
        EngineFinding(engine="mantis", title="SSRF in proxy", file_path="src/proxy.py", line=42, cwe="CWE-918", severity="HIGH"),
        EngineFinding(engine="raptor", title="SSRF in proxy", file_path="src/proxy.py", line=45, cwe="CWE-918", severity="HIGH"),
        EngineFinding(engine="aiscan", title="SSRF in proxy", file_path="src/proxy.py", line=44, cwe="CWE-918", severity="HIGH"),
    ]
    voter = EnsembleConsensusVoter(program="generic", quorum=2)

    # Without live PoC: even 3 agreeing static engines MUST stay capped at ENSEMBLE_CORROBORATED_STATIC
    static_clusters = voter.fuse(findings)
    assert len(static_clusters) == 1
    assert static_clusters[0].engine_count == 3
    assert static_clusters[0].disposition == "ENSEMBLE_CORROBORATED_STATIC"
    assert static_clusters[0].poc_verified is False

    # With verified LinuxPocRunner transcript: promotes to SUBMISSION_READY
    tr = VerifiableTranscript(
        language="python",
        backend="docker",
        status="passed",
        exit_code=0,
        command=["python3", "poc.py"],
        image="python:3.12-slim",
        repo_path="/tmp/repo",
        started_at_utc="2026-11-25T00:00:00Z",
        elapsed_ms=125.0,
        stdout="EXPLOIT_CONFIRMED",
        stderr="",
    )
    live_clusters = voter.fuse(findings, poc_transcripts={"src/proxy.py": tr})
    assert live_clusters[0].disposition == "SUBMISSION_READY"
    assert live_clusters[0].poc_verified is True


def test_stage3_vendor_threat_model_gates_anthropic_macos_and_shopify() -> None:
    # 1. Anthropic shared srt-sandbox cross-session (#4235888)
    v_anth = evaluate_vendor_threat_model(
        title="Cross-session OpenProcess inside srt-sandbox",
        summary="Two processes inside srt-sandbox can inspect each other.",
        file_path="src/sandbox.rs",
        program="anthropic",
    )
    assert v_anth.passed is False
    assert "ANTHROPIC_SHARED_SANDBOX_NON_BOUNDARY" in v_anth.matched_rules

    # 2. macOS APFS Seatbelt without live macOS runtime output (#4235906)
    v_mac = evaluate_vendor_threat_model(
        title="macOS APFS case-sensitivity Seatbelt bypass",
        summary="Static analysis of sandbox-exec SBPL profile.",
        file_path="src/seatbelt.rs",
        program="anthropic",
        poc_verified=True,
        poc_target_os="linux",
    )
    assert v_mac.passed is False
    assert "OS_RUNTIME_MISMATCH" in v_mac.matched_rules

    # 3. Shopify local CLI self-execution (#06 ucp-cli)
    v_shop = evaluate_vendor_threat_model(
        title="ucp-cli local CLI self-execution via user-supplied --exec",
        summary="Local user invokes ucp-cli with shell flag.",
        file_path="cmd/ucp-cli/main.go",
        program="shopify",
    )
    assert v_shop.passed is False
    assert "SHOPIFY_LOCAL_CLI_SELF_EXEC_OUT_OF_SCOPE" in v_shop.matched_rules


def test_deterministic_override_immunity_and_artifact_export(tmp_path: Path) -> None:
    findings = [
        EngineFinding(
            engine="lean4",
            title="RFC 9112 CL/TE Framing Differential",
            file_path="src/http_parser.rs",
            line=100,
            cwe="CWE-444",
            severity="CRITICAL",
            deterministic=True,
            confirmed=True,
        ),
        EngineFinding(
            engine="mantis",
            title="RFC 9112 CL/TE Framing Differential",
            file_path="src/http_parser.rs",
            line=102,
            cwe="CWE-444",
            severity="CRITICAL",
            deterministic=False,
            confirmed=False,  # LLM dissent MUST NOT override Lean 4 + live PoC
        ),
    ]
    tr = VerifiableTranscript(
        language="rust",
        backend="docker",
        status="passed",
        exit_code=0,
        command=["cargo", "test"],
        image="rust:1.85-slim",
        repo_path=str(tmp_path),
        started_at_utc="2026-11-25T00:00:00Z",
        elapsed_ms=420.0,
        stdout="test framing_desync ... ok",
        stderr="",
    )
    orch = EnsembleOrchestrator(program="generic", quorum=2)
    out_dir = tmp_path / "ensemble_out"
    report = orch.run(
        tmp_path,
        findings,
        poc_transcripts={"*": tr},
        out_dir=out_dir,
        package_client_name="Acme Corp",
    )

    assert len(report.clusters) == 1
    c = report.clusters[0]
    assert c.disposition == "SUBMISSION_READY"
    assert c.lean_verified is True
    assert c.deterministic_override_protected is True
    assert c.llm_dissent_ignored is True

    sarif = json.loads((out_dir / "ensemble_findings.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert (out_dir / "ensemble_report.json").is_file()
    assert (out_dir / "ensemble_summary.md").is_file()
    assert (out_dir / "client_audit_bundle").is_dir()
