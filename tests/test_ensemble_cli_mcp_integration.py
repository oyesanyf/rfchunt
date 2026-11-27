"""
Integration tests for RFCHunt Milestone 3 CLI & MCP Entry Points:
  - `revenue_cli.py` (`ensemble-audit --all --ensemble/--essemble --proxy`, graceful degradation,
    clean-repo non-fabrication, `maybe_dispatch_revenue_cli` compatibility)
  - `rfc_hunt_swarm.py` (`parse_swarm_arguments` positional `--all <target>`, `--dry-run --json`,
    live offline `--all --ensemble` / `--essemble` writing JSON/MD/SARIF + updating `combined_audit_summary.json`)
  - `bugbounty_mcp_server.py` (`build_rfchunt_all_argv`, `bb_run_all_scan` in `dry_run=True`,
    `embedded=True`, `dry_run=False`, and degraded/failed error paths)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Iterator, List, Optional, Sequence

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import bugbounty_mcp_server
import revenue_cli
import rfc_hunt_swarm


def _offline_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "CI": "true",
            "RFCHUNT_OFFLINE": "1",
            "RFCHUNT_AIR_GAPPED": "1",
            "RFCHUNT_AUTO_INSTALL_TOOLS": "0",
            "RFCHUNT_AUTO_PULL_MODELS": "0",
            "RFCHUNT_NO_EMOJI": "1",
            "NO_COLOR": "1",
            "PYTHONIOENCODING": "utf-8",
            "SEMGREP_SEND_METRICS": "off",
        }
    )
    if extra:
        env.update(extra)
    return env


def _run_cli(script_name: str, args: Sequence[str], *, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-u", str(REPO_ROOT / script_name), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        env=_offline_env(),
        timeout=timeout,
    )


def _create_git_repo(root: Path, files: Dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        fp = root / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "init"], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "qa@rfchunt.local"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "RFCHunt QA"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", "initial fixture"], check=True, capture_output=True)
    return root


@pytest.fixture(autouse=True)
def _force_offline_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    import engine.ollama_concurrency_guard as ocg

    for k, v in (
        ("CI", "true"),
        ("RFCHUNT_OFFLINE", "1"),
        ("RFCHUNT_AIR_GAPPED", "1"),
        ("RFCHUNT_AUTO_INSTALL_TOOLS", "0"),
        ("RFCHUNT_AUTO_PULL_MODELS", "0"),
        ("SEMGREP_SEND_METRICS", "off"),
    ):
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("RFCHUNT_OLLAMA_LOCK_PATH", str(tmp_path / "ollama_slot.lock"))
    ocg._SHARED_GUARD = None
    try:
        yield
    finally:
        ocg._SHARED_GUARD = None


@pytest.fixture
def vulnerable_repo(tmp_path: Path) -> Path:
    return _create_git_repo(
        tmp_path / "vuln_repo",
        {
            ".github/workflows/pr_triage.yml": (
                "name: PR Triage\n"
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  triage:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo \"${{ github.event.pull_request.title }}\"\n"
            ),
            "src/http_gateway.py": (
                "# CL+TE HTTP framing mismatch (CWE-444)\n"
                "def parse_req(cl_val: int) -> tuple[str, int]:\n"
                "    return ('acceptContentLength', cl_val)\n"
            ),
            "src/agent_guard.py": (
                "import subprocess\n"
                "@tool\n"
                "def exec_tool(tool_args: dict) -> str:\n"
                "    subprocess.run(['echo', str(tool_args)], check=False)\n"
                "    return 'done'\n"
            ),
        },
    )


@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    return _create_git_repo(
        tmp_path / "clean_repo",
        {
            "src/utils.py": (
                "def safe_add(a: int, b: int) -> int:\n"
                "    return a + b\n"
            ),
        },
    )


def test_revenue_cli_ensemble_audit_all_proxy_and_clean_non_fabrication(
    vulnerable_repo: Path,
    clean_repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "semgrep" else orig_which(name))

    out_vuln = tmp_path / "out_vuln"
    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(vulnerable_repo),
            "--all",
            "--essemble",
            "--proxy",
            "http://127.0.0.1:8080",
            "--quorum",
            "1",
            "--out",
            str(out_vuln),
        ]
    )
    assert rc == 0
    stdout_summary = capsys.readouterr().out
    assert "whiteboard_hyps=" in stdout_summary
    assert "proxy=http://127.0.0.1:8080" in stdout_summary

    rep_path = out_vuln / "ensemble_report.json"
    md_path = out_vuln / "ensemble_summary.md"
    sarif_path = out_vuln / "ensemble_findings.sarif"
    assert rep_path.is_file()
    assert md_path.is_file()
    assert sarif_path.is_file()

    rep = json.loads(rep_path.read_text(encoding="utf-8"))
    assert rep["proxy"] == "http://127.0.0.1:8080"
    assert "whiteboard" in rep
    assert "lean_verification" in rep
    assert "toolchain_status" in rep
    assert rep["all_scan_summary"]["status"] == "completed"
    assert len(rep["clusters"]) >= 1

    # Clean repo must never fabricate findings
    out_clean = tmp_path / "out_clean"
    rc_clean = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(clean_repo),
            "--all",
            "--ensemble",
            "--out",
            str(out_clean),
        ]
    )
    assert rc_clean == 0
    clean_rep = json.loads((out_clean / "ensemble_report.json").read_text(encoding="utf-8"))
    assert clean_rep["clusters"] == []
    assert clean_rep["counts_by_disposition"].get("SUBMISSION_READY", 0) == 0

    # Non-existent target degrades gracefully without crashing
    out_missing = tmp_path / "out_missing"
    rc_missing = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(tmp_path / "does_not_exist"),
            "--all",
            "--ensemble",
            "--out",
            str(out_missing),
        ]
    )
    assert rc_missing == 0
    missing_rep = json.loads((out_missing / "ensemble_report.json").read_text(encoding="utf-8"))
    assert missing_rep["freshness"]["is_git_repo"] is False
    assert missing_rep["clusters"] == []
    assert missing_rep["all_scan_summary"]["status"] == "skipped_non_directory_target"


def test_revenue_cli_translate_preserves_proxy_and_maybe_dispatch_compat(
    vulnerable_repo: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mapped, dry_run = revenue_cli._translate_swarm_argv_to_ensemble(
        [
            "--all",
            str(vulnerable_repo),
            "--essemble",
            "--proxy",
            "http://127.0.0.1:9090",
            "--output-dir",
            str(tmp_path / "out_trans"),
            "--dry-run",
        ]
    )
    assert dry_run is True
    assert "--proxy" in mapped
    assert mapped[mapped.index("--proxy") + 1] == "http://127.0.0.1:9090"
    assert mapped[mapped.index("--target") + 1] == str(vulnerable_repo)

    # Direct caller compatibility required by tests/test_gha_workflow_ensemble.py
    rc = revenue_cli.maybe_dispatch_revenue_cli(
        [
            "--all",
            str(vulnerable_repo),
            "--essemble",
            "--embeded",
            "--gha-only",
            "--output-dir",
            str(tmp_path / "out_dispatch"),
            "--json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["telemetry"]["embedded"] is True
    assert payload["telemetry"]["gha_llm"]["status"] == "skipped_embedded"


def test_swarm_parse_arguments_and_dry_run_flags(
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    out_dir = tmp_path / "swarm_dry_out"
    argv_repo = bugbounty_mcp_server.build_rfchunt_all_argv(
        target=str(vulnerable_repo),
        output_dir=str(out_dir),
        ensemble=True,
        program="shopify",
        freshness_hours=48,
        ensemble_quorum=3,
        dry_run=True,
    )
    parsed_repo = rfc_hunt_swarm.parse_swarm_arguments(argv_repo[2:])
    assert parsed_repo.run_all_scans is True
    assert parsed_repo.ensemble is True
    assert parsed_repo.program == "shopify"
    assert parsed_repo.freshness_hours == 48
    assert parsed_repo.quorum == 3
    assert parsed_repo.dry_run is True
    assert parsed_repo.repo == str(vulnerable_repo)

    argv_url = bugbounty_mcp_server.build_rfchunt_all_argv(
        target="https://127.0.0.1:8443",
        output_dir=str(out_dir),
        ensemble=True,
        dry_run=True,
    )
    parsed_url = rfc_hunt_swarm.parse_swarm_arguments(argv_url[2:])
    assert parsed_url.run_all_scans is True
    assert parsed_url.host == "https://127.0.0.1:8443"
    assert parsed_url.ensemble is True

    # Verify rfc_hunt_swarm.py --all --ensemble and --essemble route to cmd_dry_run_plan natively
    for flag in ("--ensemble", "--essemble"):
        proc = _run_cli(
            "rfc_hunt_swarm.py",
            [
                "--all",
                "--repo",
                str(vulnerable_repo),
                flag,
                "--program",
                "anthropic",
                "--freshness-hours",
                "24",
                "--quorum",
                "1",
                "--dry-run",
                "--json",
                "--output-dir",
                str(out_dir),
                "--db",
                str(tmp_path / "dry.db"),
            ],
        )
        assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
        plan = json.loads(proc.stdout)
        assert plan["status"] == "dry_run_plan_ready"
        assert plan["ensemble"] is True
        assert plan["program"] == "anthropic"
        assert plan["freshness_hours"] == 24
        assert plan["quorum"] == 1
        assert "EnsembleWhiteboardOrchestrator(Planner-Worker-Verifier+Lean4)" in plan["planned_modules"]
        assert plan["side_effects"]["network_packets_sent"] == 0


def test_swarm_live_all_essemble_writes_ensemble_artifacts_and_combined_json(
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    out_dir = tmp_path / "swarm_live_out"
    db_path = tmp_path / "swarm_live.db"
    proc = _run_cli(
        "rfc_hunt_swarm.py",
        [
            "--all",
            "--repo",
            str(vulnerable_repo),
            "--essemble",
            "--program",
            "generic",
            "--freshness-hours",
            "72",
            "--quorum",
            "1",
            "--output-dir",
            str(out_dir),
            "--db",
            str(db_path),
            "--no-external-scanners",
            "--no-preflight-live",
            "--no-include-models",
            "--no-auto-install",
            "--json",
        ],
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    data = json.loads(proc.stdout)
    assert "ensemble" in data
    assert "whiteboard" in data["ensemble"]
    assert "clusters" in data["ensemble"]
    assert "toolchain_status" in data["ensemble"]
    assert "toolchain_status" in data
    assert "lean_verification" in data
    assert "ensemble" in data["engines"]

    for fname in ("ensemble_report.json", "ensemble_summary.md", "ensemble_findings.sarif", "combined_audit_summary.json"):
        assert (out_dir / fname).is_file(), f"Missing expected artifact {fname} in {out_dir}"

    combined = json.loads((out_dir / "combined_audit_summary.json").read_text(encoding="utf-8"))
    assert "ensemble" in combined
    assert combined["report_files"]["ensemble_json"].endswith("ensemble_report.json")
    assert combined["report_files"]["ensemble_md"].endswith("ensemble_summary.md")
    assert combined["report_files"]["ensemble_sarif"].endswith("ensemble_findings.sarif")

    # Target repository working tree remains strictly untouched
    git_clean = subprocess.run(
        ["git", "-C", str(vulnerable_repo), "status", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    assert git_clean.stdout.strip() == ""


def test_mcp_bb_run_all_scan_dry_run_embedded_live_and_degraded(
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    srv = bugbounty_mcp_server.BugBountyMCPServer()

    # 1. dry_run=True
    dry_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "bb_run_all_scan",
                "arguments": {
                    "target": str(vulnerable_repo),
                    "output_dir": str(tmp_path / "mcp_dry"),
                    "ensemble": True,
                    "program": "cloudflare",
                    "freshness_hours": 48,
                    "ensemble_quorum": 2,
                    "dry_run": True,
                    "include_lean_verify": True,
                },
            },
        }
    )
    assert dry_resp["result"]["isError"] is False
    dry_data = json.loads(dry_resp["result"]["content"][0]["text"])
    assert dry_data["status"] == "dry_run_ready"
    assert "toolchain_status" in dry_data
    assert "ensemble" in dry_data
    assert dry_data["ensemble"]["program"] == "cloudflare"
    assert dry_data["ensemble"]["quorum"] == 2
    assert dry_data["lean_verification"]["total_theorems"] == 11
    assert isinstance(dry_data["lean_verification"]["diagnostics"], list)

    # 2. embedded=True
    emb_out = tmp_path / "mcp_emb"
    emb_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "bb_run_all_scan",
                "arguments": {
                    "target": str(vulnerable_repo),
                    "output_dir": str(emb_out),
                    "ensemble": True,
                    "embedded": True,
                    "ensemble_quorum": 1,
                    "include_lean_verify": True,
                },
            },
        }
    )
    assert emb_resp["result"]["isError"] is False
    emb_data = json.loads(emb_resp["result"]["content"][0]["text"])
    assert emb_data["status"] == "completed"
    assert emb_data["embedded"] is True
    assert emb_data["toolchain_status"]["docker"]["status"] == "skipped_embedded"
    assert "ensemble" in emb_data and "whiteboard" in emb_data["ensemble"]
    assert emb_data["lean_verification"]["total_theorems"] == 11
    assert Path(emb_data["sarif_path"]).is_file()

    # 3. dry_run=False, embedded=False end-to-end subprocess + artifact ingestion
    live_out = tmp_path / "mcp_live"
    live_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "bb_run_all_scan",
                "arguments": {
                    "target": str(vulnerable_repo),
                    "output_dir": str(live_out),
                    "ensemble": True,
                    "program": "generic",
                    "freshness_hours": 72,
                    "ensemble_quorum": 1,
                    "dry_run": False,
                    "include_lean_verify": True,
                    "extra_flags": [
                        "--db",
                        str(tmp_path / "mcp_live.db"),
                        "--no-external-scanners",
                        "--no-preflight-live",
                        "--no-include-models",
                        "--no-auto-install",
                    ],
                },
            },
        }
    )
    assert live_resp["result"]["isError"] is False
    live_data = json.loads(live_resp["result"]["content"][0]["text"])
    assert live_data["status"] == "completed"
    assert live_data["exit_code"] == 0
    assert "ensemble" in live_data
    assert "whiteboard" in live_data["ensemble"]
    assert "clusters" in live_data["ensemble"]
    assert "toolchain_status" in live_data["ensemble"]
    assert "toolchain_status" in live_data
    assert live_data["lean_verification"]["total_theorems"] == 11
    assert "counterexamples" in live_data["lean_verification"]

    # 4. Failed subprocess degrades gracefully with toolchain_status
    fail_data = bugbounty_mcp_server.run_rfchunt_all_scan(
        target=str(vulnerable_repo),
        output_dir=str(tmp_path / "mcp_fail"),
        ensemble=True,
        dry_run=False,
        include_lean_verify=True,
        extra_flags=["--artex-rounds", "0", "--db", str(tmp_path / "mcp_fail.db")],
    )
    assert fail_data["status"] == "failed"
    assert fail_data["exit_code"] != 0
    assert "toolchain_status" in fail_data
    assert "ensemble" in fail_data


def test_swarm_live_all_ensemble_clean_hardened_repo_no_fabrication(tmp_path: Path) -> None:
    """Clean hardened repo (src/utils.py + hardened GHA workflow) yields clusters == [] at quorum 2 and quorum 1."""
    clean_hardened = _create_git_repo(
        tmp_path / "clean_hardened_repo",
        {
            "src/utils.py": (
                "def safe_add(a: int, b: int) -> int:\n"
                "    return a + b\n"
            ),
            ".github/workflows/hardened.yml": (
                "name: Hardened CI\n"
                "on: [push]\n"
                "permissions: read-all\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n"
                "        with:\n"
                "          persist-credentials: false\n"
                "      - run: echo ok\n"
            ),
        },
    )

    for label, extra_quorum_args in (("default_q2", []), ("q1", ["--quorum", "1"])):
        out_dir = tmp_path / f"swarm_clean_{label}"
        db_path = tmp_path / f"swarm_clean_{label}.db"
        proc = _run_cli(
            "rfc_hunt_swarm.py",
            [
                "--all",
                "--repo",
                str(clean_hardened),
                "--ensemble",
                *extra_quorum_args,
                "--output-dir",
                str(out_dir),
                "--db",
                str(db_path),
                "--no-external-scanners",
                "--no-preflight-live",
                "--no-include-models",
                "--no-auto-install",
                "--json",
            ],
        )
        assert proc.returncode == 0, f"[{label}] stderr={proc.stderr}\nstdout={proc.stdout}"
        data = json.loads(proc.stdout)
        assert data["ensemble"]["clusters"] == [], f"[{label}] fabricated clusters: {data['ensemble']['clusters']}"
        assert data["ensemble"]["counts_by_disposition"].get("SUBMISSION_READY", 0) == 0

    git_clean = subprocess.run(
        ["git", "-C", str(clean_hardened), "status", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    assert git_clean.stdout.strip() == ""


def test_swarm_essample_alias_and_zero_quorum_freshness_dry_run(
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    """`--essample` alias parity + `is not None` handling for `--freshness-hours 0` and `--quorum 0`."""
    proc = _run_cli(
        "rfc_hunt_swarm.py",
        [
            "--all",
            "--repo",
            str(vulnerable_repo),
            "--essample",
            "--freshness-hours",
            "0",
            "--quorum",
            "0",
            "--dry-run",
            "--json",
            "--output-dir",
            str(tmp_path / "essample_dry_out"),
            "--db",
            str(tmp_path / "essample_dry.db"),
        ],
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    plan = json.loads(proc.stdout)
    assert plan["status"] == "dry_run_plan_ready"
    assert plan["ensemble"] is True
    assert plan["freshness_hours"] == 0
    assert plan["quorum"] == 1
    assert "EnsembleWhiteboardOrchestrator(Planner-Worker-Verifier+Lean4)" in plan["planned_modules"]


def test_revenue_cli_external_out_dir_stages_unified_reports_in_temp(
    clean_repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arbitrary `--out` outside %TEMP% and rfchunt/ still runs `run_unified_all_scans` cleanly via temp staging."""
    isolated_sys_tmp = tmp_path / "isolated_sys_tmp"
    isolated_sys_tmp.mkdir(parents=True, exist_ok=True)
    ext_out = tmp_path / "external_out_dir"

    monkeypatch.setenv("TMP", str(isolated_sys_tmp))
    monkeypatch.setenv("TEMP", str(isolated_sys_tmp))
    monkeypatch.setenv("TMPDIR", str(isolated_sys_tmp))
    monkeypatch.setattr(tempfile, "tempdir", None)

    rc = revenue_cli.run_revenue_cli(
        [
            "ensemble-audit",
            "--target",
            str(clean_repo),
            "--all",
            "--ensemble",
            "--out",
            str(ext_out),
        ]
    )
    assert rc == 0
    rep = json.loads((ext_out / "ensemble_report.json").read_text(encoding="utf-8"))
    assert rep["all_scan_summary"]["status"] == "completed"
    assert rep["clusters"] == []
    assert not (ext_out / "_unified_all").exists()
    assert list(isolated_sys_tmp.glob("rfchunt_unified_*")) == []

