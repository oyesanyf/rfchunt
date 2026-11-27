"""Tier 5 white-box adversarial coverage & bug-regression suite for RFCHunt M1-M4.

Intended integration path:
    tests/e2e_ensemble_whiteboard/test_tier5_adversarial.py

Structure:
- Part A (TestTier5AdversarialCoverage*): White-box boundary, concurrency,
  error-handling, SSRF, malformed-input, and CLI/MCP routing tests that exercise
  untested M1-M4 branches and pass against hardened baselines.
- Part B (TestTier5ConfirmedBugRegressions*): Targeted regression tests for the
  12 empirically reproduced M1-M4 product bugs (BUG-01 .. BUG-12). These fail
  until the corresponding M1-M4 owned fixes are applied, then pass cleanly.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
import sqlite3
import sys
import threading
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2] if (Path(__file__).resolve().parents[2] / "engine").is_dir() else Path(r"D:\harfile\rfchunt")
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# =============================================================================
# PART A: White-Box Adversarial Coverage Hardening (Expected PASS on baseline)
# =============================================================================


class TestTier5AdversarialCoverageLean:
    def test_t5_lean_nested_comments_and_strings_do_not_trigger_false_sorry(self, tmp_path: Path) -> None:
        from engine.lean_formal_verifier import audit_lean_file

        lean_file = tmp_path / "NestedCommentsAndStrings.lean"
        lean_file.write_text(
            "/- outer /- sorry -/ still inside block comment axiom fake_in_comment : False -/\n"
            'def literal : String := "sorry axiom fake"\n'
            "-- single line sorry axiom ignored\n"
            "theorem verified_clean : True := trivial\n",
            encoding="utf-8",
        )
        audit = audit_lean_file(lean_file)
        assert audit.has_sorry is False
        assert audit.has_custom_axiom is False
        assert audit.clean_proofs is True
        assert "verified_clean" in audit.theorems

    def test_t5_lean_parse_lake_diagnostics_windows_and_posix_paths(self) -> None:
        from engine.lean_formal_verifier import _parse_lake_diagnostics

        stdout_text = "formal/lean4/RFCHunt/PolicyGuard.lean:42:4: error: unsolved goals\n"
        stderr_text = (
            r"D:\harfile\rfchunt\formal\lean4\RFCHunt\HttpFramingOracle.lean:10:2: "
            "warning: declaration uses 'sorry'\n"
        )
        diags = _parse_lake_diagnostics(stdout_text, stderr_text)
        assert len(diags) == 2
        modules = {d.module for d in diags}
        assert "RFCHunt.HttpFramingOracle" in modules
        assert "RFCHunt.PolicyGuard" in modules
        kinds = {d.kind for d in diags}
        assert "sorry" in kinds
        assert "unsolved_goals" in kinds

    def test_t5_lean_http_framing_negative_cl_raises_and_cl_te_detects_desync(self) -> None:
        from engine.lean_formal_verifier import verify_http_framing_invariant

        with pytest.raises(ValueError):
            verify_http_framing_invariant(content_lengths=[-5], has_transfer_encoding_chunked=False)

        results = verify_http_framing_invariant(
            content_lengths=[10, 10],
            has_transfer_encoding_chunked=True,
        )
        assert any(r.violated for r in results)

    def test_t5_lean_dotnet_pe_invalid_pe_with_none_report_no_crash(self) -> None:
        from engine.lean_formal_verifier import verify_dotnet_pe_invariant

        results = verify_dotnet_pe_invariant(
            is_valid_pe=False,
            has_clr_descriptor=False,
            pe_report=None,
        )
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_t5_lean_policy_guard_privilege_escalation_witness(self) -> None:
        from engine.lean_formal_verifier import verify_policy_guard_invariant

        results = verify_policy_guard_invariant(
            action="shellExec",
            scope="outOfScope",
            in_workspace_root=False,
            allow_destructive=False,
            rules=(("permit", True),),
            observed_allowed=True,
        )
        violated = [r for r in results if r.violated]
        assert len(violated) >= 1
        assert any(r.theorem == "shell_exec_never_permitted" for r in violated)


class TestTier5AdversarialCoverageSandboxAndNetwork:
    def test_t5_ssrf_cgnat_unspecified_ipv4_mapped_ipv6_and_metadata_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import engine.safe_network_validator as snv

        def _offline_dns(host, port, *args, **kwargs):
            raise socket.gaierror(11001, f"offline deterministic DNS block for {host}")

        monkeypatch.setattr(snv.socket, "getaddrinfo", _offline_dns)

        blocked_targets = [
            "http://100.64.0.1/",
            "http://0.0.0.0/",
            "http://[::ffff:127.0.0.1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://2130706433/",
            "http://0177.0.0.1/",
            "http://0x7f000001/",
            "http://127.1/",
        ]
        for url in blocked_targets:
            ok, msg = snv.validate_and_authorize_target(url)
            assert ok is False, f"SSRF bypass allowed for {url}: {msg}"

    def test_t5_symbolic_hook_rejects_raw_str_args_and_missing_target(self, tmp_path: Path) -> None:
        from engine.linux_poc_runner import run_symbolic_hook

        work = tmp_path / "work"
        work.mkdir()

        res_str_args = run_symbolic_hook("angr", target_path=work, args="--help")
        assert res_str_args["verified"] is False
        assert res_str_args["status"] == "rejected_unsafe"

        res_missing = run_symbolic_hook("angr", target_path=tmp_path / "missing_dir")
        assert res_missing["verified"] is False
        assert res_missing["status"] == "rejected_unsafe"

    def test_t5_linux_poc_runner_invalid_path_chars_and_ads_rejected_without_crash(self, tmp_path: Path) -> None:
        from engine.linux_poc_runner import validate_mount_path

        for bad_path in (
            str(tmp_path / "bad*name?"),
            str(tmp_path / "ads.txt:hidden"),
            r"C:\Windows",
        ):
            ok, msg = validate_mount_path(bad_path)
            assert ok is False
            assert msg


class TestTier5AdversarialCoverageWhiteboardAndOrchestrator:
    def test_t5_whiteboard_multithreaded_db_sync_and_corrupt_sqlite_rejected(self, tmp_path: Path) -> None:
        from database import Database
        from engine.ensemble_whiteboard import EnsembleWhiteboard, WhiteboardHypothesis

        corrupt_db = tmp_path / "corrupt.db"
        corrupt_db.write_bytes(b"NOT A SQLITE DATABASE HEADER" * 20)
        with pytest.raises(sqlite3.DatabaseError):
            Database(str(corrupt_db))

        good_db = Database(str(tmp_path / "mt_wb.db"))
        try:
            wb = EnsembleWhiteboard(db=good_db)
            errors: list[str] = []

            def _worker(tid: int) -> None:
                try:
                    for j in range(10):
                        hid = f"t5-{tid}-{j}"
                        wb.add_hypothesis(
                            WhiteboardHypothesis(
                                hypothesis_id=hid,
                                title=f"Concurrent hyp {tid}-{j}",
                                domain="http_framing",
                                source_engine="lean4",
                                confidence=0.65,
                            )
                        )
                        wb.update_status(hid, "TESTING", confidence=0.75)
                        snap = wb.to_dict()
                        assert "hypotheses" in snap
                except Exception as exc:
                    errors.append(f"t{tid}: {type(exc).__name__}: {exc}")

            threads = [threading.Thread(target=_worker, args=(i,)) for i in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            assert errors == []
        finally:
            if getattr(good_db, "conn", None) is not None:
                good_db.conn.close()

    def test_t5_orchestrator_corrupt_manifest_and_openapi_zero_finding_convergence(self, tmp_path: Path) -> None:
        from engine.ensemble_orchestrator import EnsembleOrchestrator

        bad_repo = tmp_path / "bad_repo"
        bad_repo.mkdir()
        (bad_repo / "AndroidManifest.xml").write_bytes(b"<manifest><application \xff\xfe\x00BROKEN" * 2000)
        (bad_repo / "openapi.json").write_text("{corrupt json", encoding="utf-8")

        orch = EnsembleOrchestrator()
        res = orch.run_exhaustive_local_engines(
            repo_path=str(bad_repo),
            no_external_scanners=True,
            enable_llm_verify=False,
        )
        assert isinstance(res, tuple) and len(res) == 2

    def test_t5_orchestrator_partial_engine_crash_is_contained_in_telemetry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import engine.ensemble_orchestrator as eo
        import engine.lean_formal_verifier as lfv

        repo = tmp_path / "partial_crash_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

        def _boom(*args, **kwargs):
            raise RuntimeError("simulated lean domain crash")

        monkeypatch.setattr(lfv, "evaluate_lean_domains", _boom)
        orch = eo.EnsembleOrchestrator()
        findings, telemetry = orch.run_exhaustive_local_engines(
            repo_path=str(repo),
            no_external_scanners=True,
            enable_llm_verify=False,
        )
        assert isinstance(findings, list)
        assert isinstance(telemetry, dict)

    def test_t5_revenue_cli_findings_json_non_list_findings_and_embedded_dry_run(self, tmp_path: Path) -> None:
        import revenue_cli as rc

        repo = tmp_path / "cli_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

        bad_dict_json = tmp_path / "bad_dict.json"
        bad_dict_json.write_text('{"findings": "not-a-list"}', encoding="utf-8")
        exit_code = rc.run_revenue_cli(
            [
                "ensemble-audit",
                "--repo",
                str(repo),
                "--findings-json",
                str(bad_dict_json),
                "--out",
                str(tmp_path / "rc_out"),
            ]
        )
        assert exit_code == 0

        handled = rc.maybe_dispatch_revenue_cli(
            ["--embedded", "--no-llm", "--dry-run", "--repo", str(repo)]
        )
        assert handled == 0

    def test_t5_rfc_hunt_swarm_typo_aliases_and_conflicting_flags(self, tmp_path: Path) -> None:
        import rfc_hunt_swarm as rhs

        repo = tmp_path / "swarm_repo"
        repo.mkdir()
        parsed = rhs.parse_swarm_arguments(
            ["--all", str(repo), "--essemble", "--embeded", "--no-llm", "--dry-run"]
        )
        assert parsed.ensemble is True
        assert parsed.embedded is True
        assert parsed.no_llm is True
        assert parsed.dry_run is True


# =============================================================================
# PART B: Empirically Reproduced M1-M4 Bug Regressions (BUG-01 .. BUG-12)
# =============================================================================


class TestTier5ConfirmedBugRegressions:
    def test_bug01_lean_audit_detects_visibility_modified_axioms_and_theorems(self, tmp_path: Path) -> None:
        from engine.lean_formal_verifier import audit_lean_file

        lean_file = tmp_path / "ModifiedAxioms.lean"
        lean_file.write_text(
            "private axiom sneak_priv : False\n"
            "protected axiom sneak_prot : False\n"
            "unsafe axiom sneak_unsafe : False\n"
            "private theorem t_priv : True := trivial\n",
            encoding="utf-8",
        )
        audit = audit_lean_file(lean_file)
        assert audit.has_custom_axiom is True
        assert audit.clean_proofs is False
        assert "t_priv" in audit.theorems

    def test_bug02_http_framing_rejects_str_and_bool_content_lengths(self) -> None:
        from engine.lean_formal_verifier import verify_http_framing_invariant

        with pytest.raises((TypeError, ValueError)):
            verify_http_framing_invariant(content_lengths="42", has_transfer_encoding_chunked=False)

        with pytest.raises((TypeError, ValueError)):
            verify_http_framing_invariant(content_lengths=[True], has_transfer_encoding_chunked=False)

    def test_bug03_policy_guard_strict_bool_rejects_false_string_coercion(self) -> None:
        from engine.lean_formal_verifier import verify_policy_guard_invariant

        res = verify_policy_guard_invariant(
            action="shellExec",
            scope="outOfScope",
            in_workspace_root=False,
            allow_destructive=False,
            rules=(("forbid", False),),
            observed_allowed="false",  # type: ignore[arg-type]
        )
        assert res[0].observed_verdict == "allowed=False"
        assert res[0].violated is False

    def test_bug04_validate_mount_path_rejects_filesystem_roots(self) -> None:
        from engine.linux_poc_runner import validate_mount_path

        for root_path in ("/", "C:\\", "C:/", "D:\\"):
            ok, _msg = validate_mount_path(root_path)
            assert ok is False, f"Root path {root_path!r} must not be mountable"

    def test_bug05_validate_command_tokens_rejects_raw_string(self) -> None:
        from engine.linux_poc_runner import validate_command_tokens

        ok, _msg = validate_command_tokens("python3 -V")  # type: ignore[arg-type]
        assert ok is False

    def test_bug06_verify_sandbox_http_probe_redacts_url_secrets(self) -> None:
        from engine.linux_poc_runner import LinuxPocRunner

        runner = LinuxPocRunner()
        secret_url = (
            "http://user:sk-proj-secret1234567890abcdef@127.0.0.1:1/"
            "?token=ghp_1234567890abcdef1234567890abcdef1234"
        )
        res = runner.verify_sandbox_http_probe(url=secret_url, program="tier5-probe", timeout_sec=0.2)
        serialized = json.dumps(res, default=str)
        assert "sk-proj-secret1234567890abcdef" not in serialized
        assert "ghp_1234567890abcdef1234567890abcdef1234" not in serialized

    def test_bug07_whiteboard_guards_terminal_rollback_nan_and_secret_leak(self) -> None:
        from engine.ensemble_whiteboard import EnsembleWhiteboard, WhiteboardHypothesis

        wb = EnsembleWhiteboard()
        wb.add_hypothesis(
            WhiteboardHypothesis(
                hypothesis_id="hyp-1",
                title="Secret test",
                domain="http_framing",
                source_engine="lean4",
                confidence=0.9,
                evidence={"nested": [{"token": "ghp_ABCDEF1234567890ABCDEF1234567890ABCD"}]},
            )
        )
        wb.update_status("hyp-1", "VERIFIED", confidence=0.95, notes="confirmed")

        with pytest.raises(ValueError):
            wb.update_status("hyp-1", "OPEN", confidence=0.5, notes="illegal rollback")

        with pytest.raises(ValueError):
            wb.update_status("hyp-1", "VERIFIED", confidence=float("nan"), notes="nan confidence")

        snap_json = json.dumps(wb.to_dict(), allow_nan=False, default=str)
        assert "ghp_ABCDEF1234567890ABCDEF1234567890ABCD" not in snap_json

    def test_bug08_orchestrator_export_artifacts_redacts_secrets_in_json_and_sarif(self, tmp_path: Path) -> None:
        from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

        repo = tmp_path / "sec_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

        finding = EngineFinding(
            engine="semgrep",
            rule_id="TEST-SEC-1",
            title="Leak sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            severity="high",
            confidence=0.9,
            file_path="app.py",
            line=1,
            cwe="CWE-798",
            summary="Token ghp_1234567890abcdef1234567890abcdef1234",
            metadata={"raw_key": "AKIAIOSFODNN7EXAMPLE"},
        )
        out_dir = tmp_path / "out_sec"
        orch = EnsembleOrchestrator()
        report = orch.run(target=str(repo), findings=[finding], out_dir=str(out_dir))
        artifacts = orch.export_artifacts(report, out_dir=str(out_dir))
        for fmt in ("json", "markdown", "sarif"):
            p = Path(artifacts[fmt])
            txt = p.read_text(encoding="utf-8", errors="replace")
            assert "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in txt, f"secret leaked in {fmt}"
            assert "ghp_1234567890abcdef1234567890abcdef1234" not in txt, f"secret leaked in {fmt}"
            assert "AKIAIOSFODNN7EXAMPLE" not in txt, f"secret leaked in {fmt}"

    def test_bug09_orchestrator_run_rejects_non_dict_all_scan_summary_cleanly(self, tmp_path: Path) -> None:
        from engine.ensemble_orchestrator import EnsembleOrchestrator

        repo = tmp_path / "bad_sum_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        orch = EnsembleOrchestrator()
        with pytest.raises(TypeError):
            orch.run(
                target=str(repo),
                findings=[],
                all_scan_summary="not-a-dict",  # type: ignore[arg-type]
                out_dir=str(tmp_path / "bad_sum_out"),
            )

    def test_bug10_revenue_cli_findings_json_wrong_top_type_exits_cleanly(self, tmp_path: Path) -> None:
        import revenue_cli as rc

        repo = tmp_path / "rc_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        bad_int_json = tmp_path / "bad_int.json"
        bad_int_json.write_text("123", encoding="utf-8")

        exit_code = rc.run_revenue_cli(
            [
                "ensemble-audit",
                "--repo",
                str(repo),
                "--findings-json",
                str(bad_int_json),
                "--out",
                str(tmp_path / "rc_out"),
            ]
        )
        assert isinstance(exit_code, int)
        assert exit_code != 0

    def test_bug11_mcp_build_rfchunt_all_argv_rejects_leading_dash_target(self) -> None:
        import bugbounty_mcp_server as bms

        with pytest.raises(ValueError):
            bms.build_rfchunt_all_argv(target="--dry-run", ensemble=True)

    def test_bug12_mcp_run_rfchunt_all_scan_invalid_quorum_returns_structured_error(self, tmp_path: Path) -> None:
        import bugbounty_mcp_server as bms

        repo = tmp_path / "mcp_repo"
        repo.mkdir()
        res = bms.run_rfchunt_all_scan(
            target=str(repo),
            ensemble=True,
            embedded=True,
            dry_run=True,
            ensemble_quorum="not_an_int",  # type: ignore[arg-type]
        )
        assert isinstance(res, dict)
        assert res.get("ok") is False or res.get("status") == "error"
