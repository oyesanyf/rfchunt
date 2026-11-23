"""Automated tests for engine/poc_generator.py and `--poc` / `poc` CLI integration."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from database import Database
from engine.poc_generator import (
    VERDICT_FALSE_POSITIVE,
    VERDICT_HARDENING_NOTE,
    VERDICT_TEST_FIXTURE,
    VERDICT_UNVERIFIED_CANDIDATE,
    VERDICT_VERIFIED_REPRODUCIBLE,
    generate_poc_bundle,
    generate_protocol_conformance_script,
    PoCTriageRecord,
)
import rfc_hunt_swarm


def _write_sample_repo(root: Path) -> Path:
    (root / "src" / "sandbox").mkdir(parents=True, exist_ok=True)
    (root / "test" / "sandbox").mkdir(parents=True, exist_ok=True)
    (root / "vendor" / "win" / "src").mkdir(parents=True, exist_ok=True)

    # 1. Regex PEM matcher (false positive)
    (root / "src" / "sandbox" / "proxy-only.ts").write_text(
        "\n".join(
            [
                "export function parseCa(caPem: string) {",
                "  const key =",
                "    /-----BEGIN (?:RSA )?PRIVATE KEY-----[\\s\\S]+?-----END (?:RSA )?PRIVATE KEY-----/.exec(",
                "      caPem,",
                "    )",
                "  return key",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 2. Hardcoded constant execSync (hardening note, not exploitable RCE)
    (root / "src" / "sandbox" / "generate-seccomp-filter.ts").write_text(
        "\n".join(
            [
                "import { execSync } from 'child_process'",
                "const NPM_ROOT_COMMAND = 'npm root -g'",
                "export function getGlobalNpmPaths() {",
                "  return execSync(NPM_ROOT_COMMAND, { encoding: 'utf8' })",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 3. Documented DACL trade-off doc comment
    (root / "vendor" / "win" / "src" / "install.rs").write_text(
        "\n".join(
            [
                "/// Guard the install state on the",
                "/// FILESYSTEM: `%ProgramData%\\sandbox-runtime\\ca\\`.",
                "/// Accepted trade-off (decided): any real local user can read or replace",
                "/// the CA key material, while the sandbox group has an explicit DENY DACL.",
                "pub fn install_ca() {}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 4. Test fixture secret
    (root / "test" / "sandbox" / "mitm-ca.test.ts").write_text(
        "const TEST_KEY = 'AKIA1234567890ABCDEF'\n",
        encoding="utf-8",
    )

    # 5. Genuine dynamic shell sink candidate in production source
    (root / "src" / "sandbox" / "dynamic-handler.ts").write_text(
        "\n".join(
            [
                "import { execSync } from 'child_process'",
                "export function runTool(req: any) {",
                "  return execSync(req.query.cmd)",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 6. Genuine hardcoded non-regex secret literal in production source (synthetic test value)
    (root / "src" / "sandbox" / "leaked-config.ts").write_text(
        "export const PROD_AWS_KEY = 'AKIA9988776655443322'\n",
        encoding="utf-8",
    )
    return root


def test_poc_module_has_zero_gui_imports():
    repo_root = Path(__file__).resolve().parent.parent
    src = (repo_root / "engine" / "poc_generator.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden = {"tkinter", "PyQt5", "PyQt6", "PySide6", "wx", "webbrowser", "http.server"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in forbidden
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden


def test_source_aware_triage_rejects_false_positives_and_downgrades_passive_chains(tmp_path):
    repo = _write_sample_repo(tmp_path / "repo")
    out_dir = tmp_path / "pocs"
    findings = [
        {
            "rule_id": "RAPTOR-SECRET-EXPOSED",
            "title": "Hardcoded Private Key block exposed",
            "severity": "CRITICAL",
            "file_path": str(repo / "src" / "sandbox" / "proxy-only.ts"),
            "line_number": 3,
        },
        {
            "rule_id": "RAPTOR-SECRET-EXPOSED",
            "title": "Hardcoded AWS Access Key ID exposed",
            "severity": "CRITICAL",
            "file_path": str(repo / "test" / "sandbox" / "mitm-ca.test.ts"),
            "line_number": 1,
        },
        {
            "rule_id": "MANTIS-CMD-001",
            "title": "OS Command Injection via Unvalidated Sink",
            "severity": "HIGH",
            "file_path": str(repo / "src" / "sandbox" / "generate-seccomp-filter.ts"),
            "line_number": 4,
        },
        {
            "rule_id": "AISCAN-001",
            "title": "AI Risk Finding",
            "severity": "HIGH",
            "file_path": str(repo / "vendor" / "win" / "src" / "install.rs"),
            "line_number": 2,
        },
        {
            "rule_id": "ARTEX-EXPLOITABLE_SINK_CHAIN",
            "title": "CONFIRMED: Attack Path to Sink",
            "severity": "CRITICAL",
            "file_path": "network-target",
            "poe_level": 1,
        },
    ]

    report = generate_poc_bundle(findings, output_dir=out_dir, repo_path=repo)
    by_rule = {(r.rule_id, Path(r.file_path).name): r for r in report.records}

    assert report.disclosure_worthy_count == 0
    assert by_rule[("RAPTOR-SECRET-EXPOSED", "proxy-only.ts")].verdict == VERDICT_FALSE_POSITIVE
    assert by_rule[("RAPTOR-SECRET-EXPOSED", "mitm-ca.test.ts")].verdict == VERDICT_TEST_FIXTURE
    assert by_rule[("MANTIS-CMD-001", "generate-seccomp-filter.ts")].verdict == VERDICT_HARDENING_NOTE
    assert by_rule[("AISCAN-001", "install.rs")].verdict == VERDICT_HARDENING_NOTE
    assert by_rule[("ARTEX-EXPLOITABLE_SINK_CHAIN", "network-target")].verdict == VERDICT_FALSE_POSITIVE

    # Generated read-only verifier for constant command executes cleanly and confirms invariant holds (exit 0)
    cmd_rec = by_rule[("MANTIS-CMD-001", "generate-seccomp-filter.ts")]
    assert len(cmd_rec.generated_files) == 1
    script_path = out_dir / cmd_rec.generated_files[0]
    proc = subprocess.run(
        [sys.executable, str(script_path), "--repo", str(repo)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0
    verdict_json = json.loads(proc.stdout)
    assert verdict_json["violated"] is False
    assert (out_dir / "POC_INDEX.md").is_file()
    assert (out_dir / "poc_manifest.json").is_file()


def test_real_dynamic_sink_and_literal_secret_are_flagged_and_secret_is_redacted(tmp_path):
    repo = _write_sample_repo(tmp_path / "repo")
    out_dir = tmp_path / "pocs"
    db = Database(str(tmp_path / "poc.db"))
    try:
        findings = [
            {
                "rule_id": "MANTIS-CMD-001",
                "title": "OS Command Injection via Unvalidated Sink",
                "severity": "HIGH",
                "file_path": str(repo / "src" / "sandbox" / "dynamic-handler.ts"),
                "line_number": 3,
            },
            {
                "rule_id": "RAPTOR-SECRET-EXPOSED",
                "title": "Hardcoded AWS Access Key ID exposed",
                "severity": "CRITICAL",
                "file_path": str(repo / "src" / "sandbox" / "leaked-config.ts"),
                "line_number": 1,
            },
        ]
        report = generate_poc_bundle(findings, output_dir=out_dir, repo_path=repo, db=db, task_id="poc-test")
    finally:
        db.close()

    by_file = {Path(r.file_path).name: r for r in report.records}
    dyn_rec = by_file["dynamic-handler.ts"]
    sec_rec = by_file["leaked-config.ts"]

    assert dyn_rec.verdict == VERDICT_UNVERIFIED_CANDIDATE
    assert sec_rec.verdict == VERDICT_VERIFIED_REPRODUCIBLE
    assert sec_rec.poe_level == 3
    assert sec_rec.disclosure_worthy is True
    assert report.disclosure_worthy_count == 1

    # Secret must NEVER appear unredacted in manifest or index
    index_text = (out_dir / "POC_INDEX.md").read_text(encoding="utf-8")
    manifest_text = (out_dir / "poc_manifest.json").read_text(encoding="utf-8")
    assert "AKIA9988776655443322" not in index_text
    assert "AKIA9988776655443322" not in manifest_text

    # Running both read-only verifier scripts must detect the violations (exit 1) without executing shell commands
    for rec in (dyn_rec, sec_rec):
        script_path = out_dir / rec.generated_files[0]
        proc = subprocess.run(
            [sys.executable, str(script_path), "--repo", str(repo)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
            check=False,
        )
        assert proc.returncode == 1
        data = json.loads(proc.stdout)
        assert data["violated"] is True


def test_protocol_conformance_verifier_enforces_loopback_and_blocks_destructive_verbs(tmp_path):
    out_dir = tmp_path / "pocs_proto"
    findings = [
        {
            "vuln_id": "VULN-RFC9112-01",
            "rule_id": "RFC-9112-TE-CL",
            "title": "Conflicting Transfer-Encoding and Content-Length",
            "severity": "HIGH",
            "rfc_num": 9112,
            "verification_attempts": 3,
            "reproducibility_rate": 1.0,
            "raw_probe": "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        }
    ]
    report = generate_poc_bundle(findings, output_dir=out_dir)
    assert report.disclosure_worthy_count == 1
    rec = report.records[0]
    assert rec.verdict == VERDICT_VERIFIED_REPRODUCIBLE
    assert any(f.endswith(".py") for f in rec.generated_files)
    assert any(f.endswith("_modsecurity.conf") for f in rec.generated_files)
    assert any(f.endswith("_suricata.rules") for f in rec.generated_files)

    # Loopback-only script MUST fail closed on non-loopback host
    py_file = out_dir / [f for f in rec.generated_files if f.endswith(".py")][0]
    proc = subprocess.run(
        [sys.executable, str(py_file), "--host", "example.com", "--port", "80"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )
    assert proc.returncode != 0
    assert "non-loopback" in (proc.stderr + proc.stdout).lower()

    # Destructive HTTP verb MUST raise PermissionError
    with pytest.raises(PermissionError):
        generate_protocol_conformance_script(
            rec,
            {"raw_probe": "DELETE /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"},
        )


def test_cli_poc_subcommand_json_and_parser_flags(tmp_path, capsys):
    repo = _write_sample_repo(tmp_path / "repo")
    findings_json = tmp_path / "audit.json"
    findings_json.write_text(
        json.dumps(
            {
                "target_path": str(repo),
                "findings": [
                    {
                        "rule_id": "RAPTOR-SECRET-EXPOSED",
                        "title": "Hardcoded Private Key block exposed",
                        "severity": "CRITICAL",
                        "file_path": str(repo / "src" / "sandbox" / "proxy-only.ts"),
                        "line_number": 3,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    parser = rfc_hunt_swarm.build_swarm_parser()
    args = parser.parse_args(
        [
            "poc",
            "--findings-json",
            str(findings_json),
            "--output-dir",
            str(tmp_path / "out"),
            "--db",
            str(tmp_path / "cli_poc.db"),
            "--json",
        ]
    )
    rfc_hunt_swarm.cmd_poc(args)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "completed"
    assert payload["total_findings_analyzed"] == 1
    assert payload["disclosure_worthy_count"] == 0
    assert payload["verdict_counts"][VERDICT_FALSE_POSITIVE] == 1

    # Verify --all --poc flag parsing
    all_args = parser.parse_args(["--all", "--repo", str(repo), "--poc", "--poc-max", "10"])
    assert all_args.run_all_scans is True
    assert all_args.enable_poc is True
    assert all_args.poc_max == 10

    # Verify path-traversal guard on --poc-dir
    bad_args = parser.parse_args(
        [
            "poc",
            "--findings-json",
            str(findings_json),
            "--output-dir",
            str(tmp_path / "out"),
            "--poc-dir",
            "../../escape_dir",
            "--db",
            str(tmp_path / "cli_poc2.db"),
        ]
    )
    with pytest.raises(ValueError):
        rfc_hunt_swarm.cmd_poc(bad_args)
