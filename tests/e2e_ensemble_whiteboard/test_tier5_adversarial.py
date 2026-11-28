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


# =============================================================================
# PART C: Tier 5 Re-Challenge Gap Regressions (GAP-01 .. GAP-05)
# =============================================================================


class TestTier5RechallengeGapRegressions:
    def test_gap01_orchestrator_and_lean_strict_bool_no_false_positive_fabrication(self, tmp_path: Path) -> None:
        from engine.ensemble_orchestrator import (
            EngineFinding,
            EnsembleOrchestrator,
            _finding_from_dict,
        )
        from engine.lean_formal_verifier import evaluate_lean_domains

        repo = tmp_path / "gap01_repo"
        repo.mkdir()
        (repo / "proxy.py").write_text("x = 1\n", encoding="utf-8")

        f_http = EngineFinding(
            engine="smuggling",
            rule_id="HTTP-TEST",
            title="Clean framing check",
            file_path="proxy.py",
            line=1,
            cwe="CWE-444",
            severity="INFO",
            confidence=0.6,
            metadata={
                "http_framing": {
                    "content_lengths": [42],
                    "has_transfer_encoding_chunked": "false",
                    "has_bare_lf": "false",
                }
            },
        )
        dom_direct = evaluate_lean_domains([f_http])
        assert dom_direct.violations_count == 0

        rep_emb = EnsembleOrchestrator(embedded=True).run(
            str(repo),
            findings=[f_http],
            out_dir=str(tmp_path / "gap01_emb_out"),
        )
        assert rep_emb.lean_verification.get("violations_count") == 0
        assert all("lean4" not in c.engines for c in rep_emb.clusters)

        rep_std = EnsembleOrchestrator(embedded=False).run(
            str(repo),
            findings=[f_http],
            out_dir=str(tmp_path / "gap01_std_out"),
        )
        assert rep_std.lean_verification.get("violations_count") == 0
        assert all("lean4" not in c.engines for c in rep_std.clusters)

        ef = _finding_from_dict(
            {
                "engine": "web_llm",
                "title": "JSON finding",
                "confirmed": "false",
                "deterministic": "false",
                "poc_verified": "false",
            }
        )
        assert ef.confirmed is False
        assert ef.deterministic is False
        assert ef.poc_verified is False

        f_pe = EngineFinding(
            engine="pe_magika",
            rule_id="PE-DOTNET-01",
            title="Clean PE check",
            file_path="bin/sample.dll",
            line=1,
            cwe="CWE-345",
            severity="INFO",
            confidence=0.6,
            metadata={"has_forshaw_cve_2026_108398_anomaly": "false"},
        )
        dom_pe = evaluate_lean_domains([f_pe])
        assert dom_pe.violations_count == 0
        rep_pe = EnsembleOrchestrator(embedded=True).run(
            str(repo),
            findings=[f_pe],
            out_dir=str(tmp_path / "gap01_pe_out"),
        )
        assert rep_pe.lean_verification.get("violations_count") == 0

    def test_gap02_direct_report_to_dict_to_sarif_and_cli_sarif_json_redact_secrets(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import revenue_cli as rc
        from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

        repo = tmp_path / "gap02_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

        sec1 = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        sec2 = "ghp_1234567890abcdef1234567890abcdef1234"
        sec3 = "AKIAIOSFODNN7EXAMPLE"

        finding = EngineFinding(
            engine="semgrep",
            rule_id="TEST-SEC-GAP02",
            title=f"Leak {sec1}",
            severity="high",
            confidence=0.9,
            file_path="app.py",
            line=1,
            cwe="CWE-798",
            summary=f"Token {sec2}",
            metadata={"raw": sec3},
        )
        rep = EnsembleOrchestrator(embedded=True).run(
            str(repo),
            findings=[finding],
            out_dir=str(tmp_path / "gap02_out"),
        )
        direct_dict_s = json.dumps(rep.to_dict(), default=str)
        direct_sarif_s = json.dumps(rep.to_sarif(), default=str)
        for sec in (sec1, sec2, sec3):
            assert sec not in direct_dict_s
            assert sec not in direct_sarif_s

        findings_file = tmp_path / "gap02_findings.json"
        findings_file.write_text(
            json.dumps(
                [
                    {
                        "engine": "semgrep",
                        "rule_id": "TEST-SEC-GAP02",
                        "title": f"Leak {sec1}",
                        "severity": "high",
                        "confidence": 0.9,
                        "file_path": "app.py",
                        "line": 1,
                        "cwe": "CWE-798",
                        "summary": f"Token {sec2}",
                        "metadata": {"raw": sec3},
                    }
                ]
            ),
            encoding="utf-8",
        )
        custom_sarif = tmp_path / "gap02_custom.sarif"
        cli_rc = rc.run_revenue_cli(
            [
                "ensemble-audit",
                "--repo",
                str(repo),
                "--findings-json",
                str(findings_file),
                "--out",
                str(tmp_path / "gap02_cli_out"),
                "--sarif-out",
                str(custom_sarif),
                "--json",
                "--embedded",
            ]
        )
        assert cli_rc == 0
        stdout_txt = capsys.readouterr().out
        custom_sarif_txt = custom_sarif.read_text(encoding="utf-8")
        for sec in (sec1, sec2, sec3):
            assert sec not in custom_sarif_txt
            assert sec not in stdout_txt

    def test_gap03_verify_sandbox_http_probe_redacts_normalized_sensitive_query_keys(self) -> None:
        from engine.linux_poc_runner import LinuxPocRunner

        runner = LinuxPocRunner()
        u = (
            "http://127.0.0.1:1/"
            "?authorization=RawAuthSecret999"
            "&x-api-key=RawXApiKey999"
            "&sessionid=RawSessionId999"
            "&private_key=RawPrivKey999"
            "&token=RawTok999"
            "&safe=1"
            "&author=alice"
        )
        res = runner.verify_sandbox_http_probe(url=u, program="tier5-probe", timeout_sec=0.2)
        serialized = json.dumps(res, default=str)
        for secret_val in (
            "RawAuthSecret999",
            "RawXApiKey999",
            "RawSessionId999",
            "RawPrivKey999",
            "RawTok999",
        ):
            assert secret_val not in serialized
        assert "safe=1" in str(res.get("url", ""))
        assert "author=alice" in str(res.get("url", ""))

    def test_gap04_linux_poc_runner_safe_command_coercion_on_non_iterable_and_bytes(self, tmp_path: Path) -> None:
        from engine.linux_poc_runner import LinuxPocRunner

        valid_dir = tmp_path / "gap04_valid"
        valid_dir.mkdir()
        runner = LinuxPocRunner()

        tr_int = runner.run_poc(language="python", repo_path=valid_dir, cmd=123)  # type: ignore[arg-type]
        assert tr_int.status == "rejected_unsafe"
        assert isinstance(tr_int.command, list)
        assert all(isinstance(tok, str) for tok in tr_int.command)
        assert "rejected_unsafe" in tr_int.to_markdown()

        tr_bytes = runner.run_poc(language="python", repo_path=valid_dir, cmd=b"python3 -V")  # type: ignore[arg-type]
        assert tr_bytes.status == "rejected_unsafe"
        assert tr_bytes.command == ["python3 -V"]
        assert "python3 -V" in tr_bytes.to_markdown()

    def test_gap05_mcp_dispatch_strict_bool_and_raw_numeric_validation(self, tmp_path: Path) -> None:
        import bugbounty_mcp_server as bms

        repo = tmp_path / "gap05_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        srv = bms.BugBountyMCPServer()

        resp_dry = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "bb_run_all_scan",
                    "arguments": {
                        "target": str(repo),
                        "dry_run": "true",
                        "ensemble": "false",
                        "embedded": "false",
                        "include_lean_verify": "false",
                    },
                },
            }
        )
        assert resp_dry["result"]["isError"] is False
        parsed_dry = json.loads(resp_dry["result"]["content"][0]["text"])
        assert parsed_dry["status"] == "dry_run_ready"
        assert parsed_dry["mode"] == "--all"
        assert parsed_dry["embedded"] is False

        resp_bool_quorum = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "bb_run_all_scan",
                    "arguments": {
                        "target": str(repo),
                        "dry_run": "false",
                        "ensemble": "false",
                        "embedded": "false",
                        "include_lean_verify": "false",
                        "ensemble_quorum": True,
                    },
                },
            }
        )
        parsed_bool_quorum = json.loads(resp_bool_quorum["result"]["content"][0]["text"])
        assert parsed_bool_quorum.get("ok") is False
        assert parsed_bool_quorum.get("status") == "error"

        resp_bad_bool = srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "bb_run_all_scan",
                    "arguments": {
                        "target": str(repo),
                        "dry_run": "maybe",
                    },
                },
            }
        )
        assert resp_bad_bool["result"]["isError"] is True


class TestTier5Gap06Gap07Regressions:
    def test_gap06_dotnet_pe_strict_bool_coercion_and_invalid_witness_handling(self, tmp_path: Path) -> None:
        from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator
        from engine.lean_formal_verifier import (
            evaluate_lean_domains,
            verify_dotnet_pe_invariant,
        )

        # 1. String "false" in pe_report must NOT coerce to True and fabricate CVE-2026-108398
        rep_clean = verify_dotnet_pe_invariant(
            pe_report={
                "is_pe": True,
                "is_dot_net": True,
                "is_executable_image": True,
                "has_forshaw_cve_2026_108398_anomaly": "false",
            },
            is_signed_by_trusted_publisher=True,
        )
        assert sum(1 for c in rep_clean if c.violated) == 0
        assert rep_clean[0].input_witness["has_executable_image_bit"] is True

        # 2. String "false" direct parameters must all coerce strictly to False
        str_false_res = verify_dotnet_pe_invariant(
            is_valid_pe="false",  # type: ignore[arg-type]
            has_clr_descriptor="false",  # type: ignore[arg-type]
            has_executable_image_bit="false",  # type: ignore[arg-type]
            is_umci_enforced="false",  # type: ignore[arg-type]
            is_signed_by_trusted_publisher="false",  # type: ignore[arg-type]
        )
        assert sum(1 for c in str_false_res if c.violated) == 0
        assert all(v is False for v in str_false_res[0].input_witness.values())

        # 3. Invalid boolean strings raise ValueError; clr_header_rva preserves integer checks
        with pytest.raises(ValueError):
            verify_dotnet_pe_invariant(is_valid_pe="maybe")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            verify_dotnet_pe_invariant(
                pe_report={
                    "is_pe": True,
                    "is_dot_net": True,
                    "is_executable_image": True,
                    "has_forshaw_cve_2026_108398_anomaly": "maybe",
                }
            )
        with pytest.raises(TypeError):
            verify_dotnet_pe_invariant(
                pe_report={
                    "is_pe": True,
                    "dot_net": {"clr_header_rva": True},
                    "is_executable_image": False,
                }
            )
        rva_vuln = verify_dotnet_pe_invariant(
            pe_report={"is_pe": True, "dot_net": {"clr_header_rva": 0x2008}, "is_executable_image": False}
        )
        assert any(c.violated for c in rva_vuln)
        rva_zero = verify_dotnet_pe_invariant(
            pe_report={"is_pe": True, "dot_net": {"clr_header_rva": 0}, "is_executable_image": False}
        )
        assert sum(1 for c in rva_zero if c.violated) == 0

        # 4. End-to-end evaluate_lean_domains and EnsembleOrchestrator(embedded=True/False)
        f_pe_false = EngineFinding(
            engine="pe_magika",
            rule_id="PE-DOTNET-02",
            title="Clean PE report with string false anomaly",
            file_path="bin/clean.dll",
            line=1,
            cwe="CWE-345",
            severity="INFO",
            confidence=0.6,
            metadata={
                "pe_report": {
                    "is_pe": True,
                    "is_dot_net": True,
                    "is_executable_image": True,
                    "has_forshaw_cve_2026_108398_anomaly": "false",
                }
            },
        )
        dom_rep = evaluate_lean_domains([f_pe_false])
        assert dom_rep.violations_count == 0

        repo = tmp_path / "gap06_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

        rep_emb = EnsembleOrchestrator(embedded=True).run(
            str(repo),
            findings=[f_pe_false],
            out_dir=str(tmp_path / "gap06_emb_out"),
        )
        assert rep_emb.lean_verification.get("violations_count") == 0
        assert rep_emb.whiteboard.get("counts_by_status", {}).get("COUNTEREXAMPLE_FOUND", 0) == 0

        rep_std = EnsembleOrchestrator(embedded=False).run(
            str(repo),
            findings=[f_pe_false],
            out_dir=str(tmp_path / "gap06_std_out"),
        )
        assert rep_std.lean_verification.get("violations_count") == 0
        assert rep_std.whiteboard.get("counts_by_status", {}).get("COUNTEREXAMPLE_FOUND", 0) == 0

        # Invalid pe_report boolean in finding metadata records invalid_witness cleanly without crashing
        f_pe_bad = EngineFinding(
            engine="pe_magika",
            rule_id="PE-DOTNET-BAD",
            title="Malformed PE report",
            file_path="bin/bad.dll",
            line=1,
            cwe="CWE-345",
            severity="INFO",
            confidence=0.5,
            metadata={
                "pe_report": {
                    "is_pe": True,
                    "is_dot_net": True,
                    "is_executable_image": True,
                    "has_forshaw_cve_2026_108398_anomaly": "maybe",
                }
            },
        )
        dom_bad = evaluate_lean_domains([f_pe_bad])
        assert dom_bad.violations_count == 0
        assert any(
            d.kind == "invalid_witness" and d.module == "RFCHunt.DotNetPeIntegrity"
            for d in dom_bad.diagnostics
        )
        rep_bad_emb = EnsembleOrchestrator(embedded=True).run(
            str(repo),
            findings=[f_pe_bad],
            out_dir=str(tmp_path / "gap06_bad_emb_out"),
        )
        assert rep_bad_emb.lean_verification.get("violations_count") == 0
        assert rep_bad_emb.whiteboard.get("counts_by_status", {}).get("COUNTEREXAMPLE_FOUND", 0) == 0

    def test_gap07_embedded_lean_domains_detects_cve_2026_108398_in_summary_matching_whiteboard(
        self, tmp_path: Path
    ) -> None:
        from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator

        repo = tmp_path / "gap07_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

        finding = EngineFinding(
            engine="pe_magika",
            rule_id="PE-DOTNET-03",
            title="PE summary test",
            file_path="bin/sample.dll",
            line=1,
            cwe="CWE-347",
            severity="HIGH",
            confidence=0.85,
            summary="Detected CVE-2026-108398 anomaly in CLR header",
            metadata={},
        )
        rep = EnsembleOrchestrator(embedded=True).run(
            str(repo),
            findings=[finding],
            out_dir=str(tmp_path / "gap07_emb_out"),
        )
        assert rep.whiteboard.get("counts_by_status", {}).get("COUNTEREXAMPLE_FOUND", 0) == 1
        assert any(c.lean_verified for c in rep.clusters)
        assert int(rep.lean_verification.get("violations_count") or 0) >= 1
        dotnet_check = rep.lean_verification.get("domain_checks", {}).get("dotnet_pe", {})
        assert dotnet_check.get("status") != "passed"
        assert dotnet_check.get("status") == "counterexample_found"
        assert int(dotnet_check.get("violations") or 0) >= 1


class TestTier5Gap08Gap09Regressions:
    def test_gap08_policy_guard_info_and_passed_status_do_not_fabricate_counterexamples(
        self, tmp_path: Path
    ) -> None:
        from engine.ensemble_orchestrator import EngineFinding, EnsembleOrchestrator
        from engine.lean_formal_verifier import evaluate_lean_domains

        repo = tmp_path / "gap08_repo"
        repo.mkdir()
        (repo / "policy.yaml").write_text("shellExec: deny\n", encoding="utf-8")

        f_pol_info = EngineFinding(
            engine="policy_checker",
            rule_id="POL-INFO-01",
            title="PolicyGuard shellExec check passed",
            file_path="policy.yaml",
            line=1,
            cwe="CWE-862",
            severity="INFO",
            confidence=0.5,
            summary="Verified shellExec is blocked by policy",
            confirmed=True,
            metadata={"status": "passed"},
        )

        # 1. evaluate_lean_domains and all 4 EnsembleOrchestrator combinations yield 0 violations
        dom_rep = evaluate_lean_domains([f_pol_info])
        assert dom_rep.violations_count == 0

        for idx, (emb, en_wb) in enumerate(
            ((False, False), (True, False), (False, True), (True, True)),
            start=1,
        ):
            rep = EnsembleOrchestrator(embedded=emb, enable_whiteboard=en_wb).run(
                str(repo),
                findings=[f_pol_info],
                out_dir=str(tmp_path / f"gap08_out_{idx}"),
            )
            assert rep.lean_verification.get("violations_count") == 0
            assert rep.whiteboard.get("counts_by_status", {}).get("COUNTEREXAMPLE_FOUND", 0) == 0
            assert all("lean4" not in c.engines for c in rep.clusters)
            if en_wb:
                assert rep.whiteboard.get("counts_by_status", {}).get("REFUTED", 0) == 1

        # 2. metadata={"status": "passed"} also prevents fabrication even with MEDIUM/HIGH severity
        f_pol_status_passed = EngineFinding(
            engine="policy_checker",
            rule_id="POL-PASS-02",
            title="PolicyGuard out_of_scope denied",
            file_path="policy.yaml",
            line=2,
            cwe="CWE-862",
            severity="MEDIUM",
            confidence=0.5,
            summary="Blocked out_of_scope probe",
            confirmed=True,
            metadata={"status": "passed"},
        )
        for emb in (True, False):
            rep_pass = EnsembleOrchestrator(embedded=emb, enable_whiteboard=True).run(
                str(repo),
                findings=[f_pol_status_passed],
                out_dir=str(tmp_path / f"gap08_pass_{emb}"),
            )
            assert rep_pass.lean_verification.get("violations_count") == 0
            assert rep_pass.whiteboard.get("counts_by_status", {}).get("COUNTEREXAMPLE_FOUND", 0) == 0

        # 3. Invalid/non-bool confirmed triggers invalid-witness handling cleanly without crashing
        f_pol_bad_conf = EngineFinding(
            engine="policy_checker",
            rule_id="POL-BAD-03",
            title="Malformed PolicyGuard shellExec witness",
            file_path="policy.yaml",
            line=3,
            cwe="CWE-862",
            severity="HIGH",
            confidence=0.6,
            summary="shellExec policy witness",
            confirmed="maybe",  # type: ignore[arg-type]
            metadata={},
        )
        rep_bad = EnsembleOrchestrator(embedded=True, enable_whiteboard=True).run(
            str(repo),
            findings=[f_pol_bad_conf],
            out_dir=str(tmp_path / "gap08_bad_conf"),
        )
        assert rep_bad.lean_verification.get("violations_count") == 0
        assert rep_bad.whiteboard.get("counts_by_status", {}).get("COUNTEREXAMPLE_FOUND", 0) == 0
        assert rep_bad.whiteboard.get("counts_by_status", {}).get("UNVERIFIED_UNAVAILABLE", 0) == 1
        assert any(
            d.get("kind") == "invalid_witness" and d.get("module") == "RFCHunt.PolicyGuard"
            for d in (rep_bad.lean_verification.get("diagnostics") or [])
        )

        # 4. Genuine active HIGH policy violation still triggers COUNTEREXAMPLE_FOUND == 1 & violations_count >= 1
        f_pol_vuln = EngineFinding(
            engine="policy_checker",
            rule_id="POL-HIGH-04",
            title="PolicyGuard shellExec bypass",
            file_path="policy.yaml",
            line=4,
            cwe="CWE-862",
            severity="HIGH",
            confidence=0.9,
            summary="Active shellExec violation",
            confirmed=True,
            metadata={},
        )
        dom_vuln = evaluate_lean_domains([f_pol_vuln])
        assert dom_vuln.violations_count >= 1
        for emb in (True, False):
            rep_vuln = EnsembleOrchestrator(embedded=emb, enable_whiteboard=True).run(
                str(repo),
                findings=[f_pol_vuln],
                out_dir=str(tmp_path / f"gap08_vuln_{emb}"),
            )
            assert rep_vuln.whiteboard.get("counts_by_status", {}).get("COUNTEREXAMPLE_FOUND", 0) == 1
            assert int(rep_vuln.lean_verification.get("violations_count") or 0) >= 1
            assert any("lean4" in c.engines and c.lean_verified for c in rep_vuln.clusters)

    def test_gap09_proxy_userinfo_credentials_redacted_across_all_outputs_preserving_non_secret_urls(
        self, tmp_path: Path
    ) -> None:
        from engine.advisory_exporter import _redact_inline_tokens
        from engine.ensemble_orchestrator import (
            EnsembleOrchestrator,
            EnsembleReport,
            RepoFreshnessSnapshot,
            render_ensemble_markdown,
        )
        from engine.ensemble_whiteboard import EnsembleWhiteboard

        secret_pw = "ProxyUserInfoPass98765"
        secret_proxy = f"http://alice:{secret_pw}@127.0.0.1:8080"
        socks_pw = "SocksSecret54321"
        socks_proxy = f"socks5h://svc:{socks_pw}@127.0.0.1:1080"

        # 1. Direct _redact_inline_tokens checks (positive redaction + negative non-corruption)
        red_http = _redact_inline_tokens(secret_proxy)
        assert secret_pw not in red_http
        assert "<REDACTED>" in red_http
        assert red_http == "http://alice:<REDACTED>@127.0.0.1:8080"

        red_socks = _redact_inline_tokens(socks_proxy)
        assert socks_pw not in red_socks
        assert red_socks == "socks5h://svc:<REDACTED>@127.0.0.1:1080"

        for intact in (
            "http://127.0.0.1:8080",
            "https://example.com/user@corp",
            "https://example.com:8443/user@corp",
            "https://example.com:8443?email=alice@corp.com",
            '{"url":"https://example.com:8443","email":"alice@corp.com"}',
        ):
            assert _redact_inline_tokens(intact) == intact

        # 2. EnsembleWhiteboard.to_dict() redacts proxy and facts
        wb = EnsembleWhiteboard(proxy=secret_proxy)
        wb.add_fact("proxy_note", f"Using {socks_proxy}", payload={"proxy": secret_proxy})
        wb_json = json.dumps(wb.to_dict(), default=str)
        assert secret_pw not in wb_json
        assert socks_pw not in wb_json
        assert "<REDACTED>" in wb_json

        # 3. Full EnsembleOrchestrator run + exported artifacts + direct render_ensemble_markdown
        repo = tmp_path / "gap09_repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        out_dir = tmp_path / "gap09_out"

        orch = EnsembleOrchestrator(embedded=True, proxy=secret_proxy)
        rep = orch.run(str(repo), findings=[], out_dir=str(out_dir))

        rep_dict_s = json.dumps(rep.to_dict(), default=str)
        rep_sarif_s = json.dumps(rep.to_sarif(), default=str)
        telemetry_s = json.dumps(orch.last_telemetry, default=str)
        direct_md = render_ensemble_markdown(rep)
        json_file_s = (out_dir / "ensemble_report.json").read_text(encoding="utf-8")
        sarif_file_s = (out_dir / "ensemble_findings.sarif").read_text(encoding="utf-8")
        md_file_s = (out_dir / "ensemble_summary.md").read_text(encoding="utf-8")

        for label, blob in (
            ("rep.to_dict", rep_dict_s),
            ("rep.to_sarif", rep_sarif_s),
            ("last_telemetry", telemetry_s),
            ("direct_render_md", direct_md),
            ("ensemble_report.json", json_file_s),
            ("ensemble_findings.sarif", sarif_file_s),
            ("ensemble_summary.md", md_file_s),
        ):
            assert secret_pw not in blob, f"proxy password leaked in {label}"
            assert "<REDACTED>" in blob, f"missing redaction marker in {label}"

        # Also verify manually constructed EnsembleReport passed directly to render_ensemble_markdown
        manual_rep = EnsembleReport(
            target=str(repo),
            program="generic",
            quorum=2,
            freshness=RepoFreshnessSnapshot(repo_path=str(repo), is_git_repo=False),
            proxy=secret_proxy,
        )
        manual_md = render_ensemble_markdown(manual_rep)
        assert secret_pw not in manual_md
        assert "<REDACTED>" in manual_md

        # Non-userinfo proxy stays intact
        rep_plain = EnsembleOrchestrator(embedded=True, proxy="http://127.0.0.1:8080").run(
            str(repo), findings=[], out_dir=str(tmp_path / "gap09_plain_out")
        )
        assert rep_plain.to_dict()["proxy"] == "http://127.0.0.1:8080"
        assert "http://127.0.0.1:8080" in render_ensemble_markdown(rep_plain)


