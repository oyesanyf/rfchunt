"""Automated real-file and live-loopback tests for engine/deep_repo_audit.py and `--deep-audit` CLI."""

from __future__ import annotations

import ast
import json
import socket
import threading
from pathlib import Path

import pytest

from database import Database
from engine.deep_repo_audit import (
    discover_nested_fuzz_crates,
    discover_trust_boundary_files,
    parse_proxy_target,
    run_coverage_fuzz_orchestration,
    run_deep_repo_audit,
    run_live_proxy_fuzz,
    run_trust_boundary_review,
)
import rfc_hunt_swarm


def _create_sample_repo(root: Path) -> Path:
    (root / "src" / "sandbox").mkdir(parents=True, exist_ok=True)
    (root / "test" / "sandbox").mkdir(parents=True, exist_ok=True)
    (root / "vendor" / "srt-win-src" / "src").mkdir(parents=True, exist_ok=True)

    # 1. Vulnerable proxy & authz policy + safe constant execSync
    (root / "src" / "sandbox" / "http-proxy.ts").write_text(
        "\n".join(
            [
                "import { execSync } from 'child_process'",
                "const SAFE_CMD = 'npm root -g'",
                "export function getNpmRoot() { return execSync(SAFE_CMD) }",
                "export function parseHeaders(raw: string) {",
                "  return raw.split('\\n')",
                "}",
                "export function runDynamic(req: any) {",
                "  return execSync(req.query.cmd)",
                "}",
                "export const tlsOpts = { rejectUnauthorized: false }",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 2. Fail-open policy filter + unbounded path.join
    (root / "src" / "sandbox" / "authz-policy.ts").write_text(
        "\n".join(
            [
                "export function checkPolicy(req: any): boolean {",
                "  try {",
                "    return req.role === 'admin'",
                "  } catch (e) {",
                "    return true",
                "  }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "src" / "sandbox" / "sandbox-path.ts").write_text(
        "\n".join(
            [
                "import path from 'path'",
                "export function openTarget(rootDir: string, userPath: string) {",
                "  return path.join(rootDir, userPath)",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 3. Nested first-party Rust crate with unsafe FFI and executable WinBuiltinUsersSid
    (root / "vendor" / "srt-win-src" / "Cargo.toml").write_text(
        '[package]\nname = "srt-win"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (root / "vendor" / "srt-win-src" / "src" / "install.rs").write_text(
        "\n".join(
            [
                "/// Doc comment mentioning WinBuiltinUsersSid must NOT trigger executable rule",
                "pub fn setup_dacl() {",
                "    let sid = WELL_KNOWN_SID_TYPE::WinBuiltinUsersSid;",
                "    unsafe {",
                "        SetNamedSecurityInfoW(sid);",
                "    }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 4. Test file that must be excluded from production trust-boundary review
    (root / "test" / "sandbox" / "http-proxy.test.ts").write_text(
        "const tlsOpts = { rejectUnauthorized: false }\n",
        encoding="utf-8",
    )
    (root / "package.json").write_text(
        json.dumps({"name": "sample-sandbox", "version": "1.0.0"}), encoding="utf-8"
    )
    return root


def _start_loopback_http_stub(response_bytes: bytes) -> tuple[int, threading.Event, threading.Thread]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = int(srv.getsockname()[1])
    srv.listen(32)
    srv.settimeout(0.2)
    stop_evt = threading.Event()

    def _serve() -> None:
        try:
            while not stop_evt.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    conn.settimeout(0.5)
                    try:
                        conn.recv(4096)
                        conn.sendall(response_bytes)
                    except OSError:
                        pass
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return port, stop_evt, t


def test_deep_repo_audit_has_zero_gui_imports_and_no_shell_true():
    src = Path(r"d:\harfile\rfchunt\engine\deep_repo_audit.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden = {"tkinter", "PyQt5", "PyQt6", "PySide6", "wx", "webbrowser"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in forbidden
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden
        elif isinstance(node, ast.keyword) and node.arg == "shell":
            assert not (isinstance(node.value, ast.Constant) and node.value.value is True)


def test_trust_boundary_review_detects_real_defects_and_ignores_tests_and_constants(tmp_path):
    repo = _create_sample_repo(tmp_path / "repo")
    ranked = discover_trust_boundary_files(repo)
    rel_names = [fp.relative_to(repo).as_posix() for fp, _, _ in ranked]
    assert "src/sandbox/http-proxy.ts" in rel_names
    assert "vendor/srt-win-src/src/install.rs" in rel_names
    assert not any(n.startswith("test/") for n in rel_names)

    db = Database(str(tmp_path / "tb.db"))
    try:
        res = run_trust_boundary_review(repo, db=db, task_id="tb-unit")
    finally:
        db.close()

    rules = {f["rule_id"] for f in res["findings"]}
    assert "TB-FAIL-OPEN-CATCH" in rules
    assert "TB-HTTP-FRAMING-SMUGGLE" in rules
    assert "TB-PATH-CONFINEMENT" in rules
    assert "TB-DYNAMIC-SHELL-EXEC" in rules
    assert "TB-TLS-VERIFY-DISABLED" in rules
    assert "TB-PERMISSIVE-ACL-MODE" in rules
    assert "TB-RUST-UNSAFE-FFI" in rules

    # Ensure SAFE_CMD constant execSync at line 3 was NOT flagged as dynamic shell exec
    dyn_lines = [f["line_number"] for f in res["findings"] if f["rule_id"] == "TB-DYNAMIC-SHELL-EXEC"]
    assert 3 not in dyn_lines
    assert 8 in dyn_lines
    # Ensure doc comment at install.rs:1 was NOT flagged
    acl_lines = [f["line_number"] for f in res["findings"] if f["rule_id"] == "TB-PERMISSIVE-ACL-MODE"]
    assert 1 not in acl_lines
    assert 3 in acl_lines


def test_live_loopback_proxy_fuzz_reproduces_permissive_vs_strict_and_fails_closed(tmp_path):
    repo = _create_sample_repo(tmp_path / "repo")

    # 1. Fail-closed on non-loopback host
    with pytest.raises(PermissionError):
        run_live_proxy_fuzz(repo, proxy_host="example.com", proxy_port=80)

    # 2. Fail-closed on forbidden metacharacters in --proxy-cmd
    with pytest.raises(PermissionError):
        run_live_proxy_fuzz(repo, proxy_cmd="node server.js; echo pwn")

    # 3. Permissive loopback server (returns 200 OK to malformed probes) -> confirmed POE=3 divergences
    p_perm, stop_perm, t_perm = _start_loopback_http_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    try:
        db = Database(str(tmp_path / "live.db"))
        try:
            res_perm = run_live_proxy_fuzz(repo, proxy_host="127.0.0.1", proxy_port=p_perm, db=db, task_id="live-perm")
        finally:
            db.close()
    finally:
        stop_perm.set()
        t_perm.join(timeout=2.0)

    assert res_perm["status"] == "completed"
    assert res_perm["probes_sent"] == 18  # 6 probes x 3 trials
    assert len(res_perm["confirmed_divergences"]) == 6
    assert all(f["poe_level"] == 3 and f["verification_attempts"] == 3 for f in res_perm["confirmed_divergences"])

    # 4. Strict loopback server (returns 400 Bad Request) -> 0 confirmed divergences
    p_strict, stop_strict, t_strict = _start_loopback_http_stub(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    try:
        res_strict = run_live_proxy_fuzz(repo, proxy_host="127.0.0.1", proxy_port=p_strict)
    finally:
        stop_strict.set()
        t_strict.join(timeout=2.0)

    assert res_strict["status"] == "completed"
    assert res_strict["confirmed_divergences"] == []


def test_coverage_fuzz_discovers_nested_rust_crates_and_writes_strictly_outside_repo(tmp_path):
    repo = _create_sample_repo(tmp_path / "repo")
    nested = discover_nested_fuzz_crates(repo)
    assert any(p.name == "srt-win-src" for p in nested)

    before_repo_files = sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*"))
    out_dir = tmp_path / "out"
    res = run_coverage_fuzz_orchestration(repo, output_dir=out_dir, dry_run=True)
    after_repo_files = sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*"))

    assert before_repo_files == after_repo_files
    assert "root" in res["targets_scanned"]
    assert "vendor_srt-win-src" in res["targets_scanned"]
    assert "rust" in res["detected_languages"]
    assert "js_ts" in res["detected_languages"]


def test_cli_deep_audit_subcommand_json_poc_and_all_flags(tmp_path, capsys):
    repo = _create_sample_repo(tmp_path / "repo")
    out_dir = tmp_path / "reports"
    parser = rfc_hunt_swarm.build_swarm_parser()

    args = parser.parse_args(
        [
            "deep-audit",
            "--repo",
            str(repo),
            "--output-dir",
            str(out_dir),
            "--db",
            str(tmp_path / "da.db"),
            "--fuzz-dry-run",
            "--poc",
            "--json",
        ]
    )
    rfc_hunt_swarm.cmd_deep_audit(args)
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "completed"
    assert payload["trust_boundary_review"]["files_reviewed"] >= 3
    assert payload["coverage_fuzz"]["dry_run"] is True
    assert "vendor_srt-win-src" in payload["coverage_fuzz"]["targets_scanned"]
    assert "poc_verification" in payload
    assert Path(payload["report_markdown_path"]).is_file()
    assert Path(payload["summary_json_path"]).is_file()

    all_args = parser.parse_args(
        ["--all", "--repo", str(repo), "--deep-audit", "--proxy", "--live-proxy-fuzz", "--trust-boundary-review", "--coverage-fuzz", "--poc"]
    )
    assert all_args.run_all_scans is True
    assert all_args.deep_audit is True
    assert all_args.proxy_target == "auto"
    assert all_args.live_proxy_fuzz is True
    assert all_args.trust_boundary_review is True
    assert all_args.coverage_fuzz is True
    assert all_args.enable_poc is True


def test_proxy_flag_parsing_loopback_guards_and_live_execution(tmp_path, capsys):
    assert parse_proxy_target("auto") == ("127.0.0.1", None, None, True)
    assert parse_proxy_target("8080") == ("127.0.0.1", 8080, None, False)
    assert parse_proxy_target("127.0.0.1:3128") == ("127.0.0.1", 3128, None, False)
    assert parse_proxy_target("http://localhost:8888") == ("localhost", 8888, None, False)
    assert parse_proxy_target("[::1]:9090") == ("::1", 9090, None, False)

    with pytest.raises(PermissionError):
        parse_proxy_target("example.com:80")
    with pytest.raises(PermissionError):
        parse_proxy_target("http://169.254.169.254:80")

    repo = _create_sample_repo(tmp_path / "repo")
    port, stop_evt, th = _start_loopback_http_stub(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    try:
        parser = rfc_hunt_swarm.build_swarm_parser()
        args = parser.parse_args(
            [
                "--repo",
                str(repo),
                "--proxy",
                f"127.0.0.1:{port}",
                "--output-dir",
                str(tmp_path / "out_proxy"),
                "--db",
                str(tmp_path / "proxy_cli.db"),
                "--json",
            ]
        )
        assert args.proxy_target == f"127.0.0.1:{port}"
        rfc_hunt_swarm.cmd_deep_audit(args)
        payload = json.loads(capsys.readouterr().out)
        assert payload["live_proxy_fuzz"]["status"] == "completed"
        assert payload["live_proxy_fuzz"]["probes_sent"] == 18
        assert payload["live_proxy_fuzz"]["confirmed_divergences"] == []
    finally:
        stop_evt.set()
        th.join(timeout=2.0)


def test_structural_trust_boundary_detectors_catch_real_bug_classes_with_zero_fp_on_fixes(tmp_path):
    """
    Verifies all 7 structural multi-token trust-boundary detectors fire on genuine
    vulnerable patterns (even when comments mention mitigations) and emit ZERO
    findings on remediated equivalents.
    """
    vuln_repo = tmp_path / "vuln_repo"
    (vuln_repo / "src" / "proxy").mkdir(parents=True, exist_ok=True)
    (vuln_repo / "src" / "sandbox").mkdir(parents=True, exist_ok=True)
    (vuln_repo / "vendor" / "win-iso" / "src").mkdir(parents=True, exist_ok=True)

    # 1. TB-TLS-CLIENTHELLO-VERSION-CAP + 2. TB-HTTP-ECHO-METHOD-GATED
    (vuln_repo / "src" / "proxy" / "tls-terminate-proxy.ts").write_text(
        "\n".join(
            [
                "export function looksLikeClientHello(buf: Buffer): boolean {",
                "  return buf.length >= 3 && buf[0] === 0x16 && buf[1] === 0x03 && buf[2]! <= 0x03",
                "}",
                "export async function forwardUpstream(req: any, res: any, opts: any) {",
                "  if (opts.filterRequest) { await opts.filterRequest(req) }",
                "  const fwdHeaders: Record<string, string> = { host: 'api.example' }",
                "  const plan = opts.planSigv4?.(req.method ?? 'GET', '/', fwdHeaders, 'api.example')",
                "  opts.mutateHeaders?.(fwdHeaders, 'api.example')",
                "  return plan",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 3. TB-WIN-REPARSE-NO-FLAG (doc comment mentions FILE_FLAG_OPEN_REPARSE_POINT, call omits it)
    (vuln_repo / "vendor" / "win-iso" / "src" / "path_id.rs").write_text(
        "\n".join(
            [
                "/// Future work: pass FILE_FLAG_OPEN_REPARSE_POINT here",
                "fn open_meta(path: *const u16) -> isize {",
                "    unsafe {",
                "        CreateFileW(",
                "            path,",
                "            0,",
                "            FILE_SHARE_READ,",
                "            None,",
                "            OPEN_EXISTING,",
                "            FILE_FLAG_BACKUP_SEMANTICS,",
                "            None,",
                "        )",
                "    }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 4. TB-WIN-WFP-MISSING-INBOUND
    (vuln_repo / "vendor" / "win-iso" / "src" / "wfp.rs").write_text(
        "\n".join(
            [
                "// TODO: consider FWPM_LAYER_ALE_AUTH_LISTEN_V4 later",
                "const OUTBOUND: [GUID; 2] = [",
                "    FWPM_LAYER_ALE_AUTH_CONNECT_V4,",
                "    FWPM_LAYER_ALE_AUTH_CONNECT_V6,",
                "];",
                "pub fn install(engine: HANDLE) -> u32 {",
                "    let mut f = FWPM_FILTER0::default();",
                "    unsafe { FwpmFilterAdd0(engine, &f, None, None) }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 5. TB-LINUX-BWRAP-PRESECCOMP-SHELL (comment mentions BASH_ENV, code does not unset it)
    (vuln_repo / "src" / "sandbox" / "linux-sandbox-utils.ts").write_text(
        "\n".join(
            [
                "// Startup files like BASH_ENV or ZDOTDIR could run before seccomp",
                "export function wrapLinux(shell: string, command: string, applySeccompPrefix: string) {",
                "  const bwrapArgs: string[] = ['--unshare-net']",
                "  bwrapArgs.push('--', shell, '-c')",
                "  bwrapArgs.push(applySeccompPrefix + command)",
                "  return bwrapArgs",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 6. TB-POSIX-ERE-BRACKET-ESCAPE
    (vuln_repo / "src" / "sandbox" / "glob-pattern.ts").write_text(
        "\n".join(
            [
                "export function setToRegex(members: string): string {",
                "  return `[${members.replace(/[.^$+{}()|\\\\]/g, '\\\\$&')}]`",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # 7. TB-URL-CANONICALIZE-STRIP
    (vuln_repo / "src" / "proxy" / "host-url.ts").write_text(
        "\n".join(
            [
                "export function canonicalizeHost(raw: string): string | undefined {",
                "  try {",
                "    const out = new URL(`http://${raw}/`).hostname",
                "    return out.replace(/\\.$/, '')",
                "  } catch { return undefined }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    vuln_res = run_trust_boundary_review(vuln_repo, max_files=60)
    vuln_rules = {f["rule_id"] for f in vuln_res["findings"]}
    expected_new_rules = {
        "TB-TLS-CLIENTHELLO-VERSION-CAP",
        "TB-HTTP-ECHO-METHOD-GATED",
        "TB-WIN-REPARSE-NO-FLAG",
        "TB-WIN-WFP-MISSING-INBOUND",
        "TB-LINUX-BWRAP-PRESECCOMP-SHELL",
        "TB-POSIX-ERE-BRACKET-ESCAPE",
        "TB-URL-CANONICALIZE-STRIP",
    }
    assert expected_new_rules.issubset(vuln_rules), f"Missing rules: {expected_new_rules - vuln_rules}"

    # Now build a remediated repo fixing every single one of the 7 bug classes -> ZERO of those 7 rules may fire
    fixed_repo = tmp_path / "fixed_repo"
    (fixed_repo / "src" / "proxy").mkdir(parents=True, exist_ok=True)
    (fixed_repo / "src" / "sandbox").mkdir(parents=True, exist_ok=True)
    (fixed_repo / "vendor" / "win-iso" / "src").mkdir(parents=True, exist_ok=True)

    (fixed_repo / "src" / "proxy" / "tls-terminate-proxy.ts").write_text(
        "\n".join(
            [
                "const ECHO_METHODS = new Set(['TRACE', 'TRACK'])",
                "export function looksLikeClientHello(buf: Buffer): boolean {",
                "  return buf.length >= 3 && buf[0] === 0x16 && buf[1] === 0x03",
                "}",
                "export async function forwardUpstream(req: any, res: any, opts: any) {",
                "  if (ECHO_METHODS.has(String(req.method || '').toUpperCase())) { res.writeHead(405); res.end(); return }",
                "  const fwdHeaders: Record<string, string> = { host: 'api.example' }",
                "  opts.mutateHeaders?.(fwdHeaders, 'api.example')",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (fixed_repo / "vendor" / "win-iso" / "src" / "path_id.rs").write_text(
        "\n".join(
            [
                "fn open_meta(path: *const u16) -> Result<isize, i32> {",
                "    let h = unsafe {",
                "        CreateFileW(",
                "            path, 0, FILE_SHARE_READ, None, OPEN_EXISTING,",
                "            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,",
                "            None,",
                "        )",
                "    };",
                "    if h == -1 { return Err(-1); }",
                "    Ok(h)",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (fixed_repo / "vendor" / "win-iso" / "src" / "wfp.rs").write_text(
        "\n".join(
            [
                "const LAYERS: [GUID; 4] = [",
                "    FWPM_LAYER_ALE_AUTH_CONNECT_V4,",
                "    FWPM_LAYER_ALE_AUTH_CONNECT_V6,",
                "    FWPM_LAYER_ALE_AUTH_LISTEN_V4,",
                "    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,",
                "];",
                "pub fn install(engine: HANDLE) -> u32 {",
                "    let f = FWPM_FILTER0::default();",
                "    unsafe { FwpmFilterAdd0(engine, &f, None, None) }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (fixed_repo / "src" / "sandbox" / "linux-sandbox-utils.ts").write_text(
        "\n".join(
            [
                "export function wrapLinux(shell: string, command: string, applySeccompPrefix: string) {",
                "  const bwrapArgs: string[] = ['--unshare-net', '--unsetenv', 'BASH_ENV', '--unsetenv', 'ZDOTDIR']",
                "  bwrapArgs.push('--', shell, '-c')",
                "  bwrapArgs.push(applySeccompPrefix + command)",
                "  return bwrapArgs",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (fixed_repo / "src" / "sandbox" / "glob-pattern.ts").write_text(
        "\n".join(
            [
                "export function setToRegex(members: string): string {",
                "  const clean = members.replace(/]/g, '')",
                "  return `[${clean}]`",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (fixed_repo / "src" / "proxy" / "host-url.ts").write_text(
        "\n".join(
            [
                "export function canonicalizeHost(raw: string): string | undefined {",
                "  try {",
                "    const u = new URL(`http://${raw}/`)",
                "    if (u.username || u.password || u.port || u.pathname !== '/' || u.search || u.hash) {",
                "      return undefined",
                "    }",
                "    return u.hostname.replace(/\\.+$/, '')",
                "  } catch { return undefined }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    fixed_res = run_trust_boundary_review(fixed_repo, max_files=60)
    fixed_rules = {f["rule_id"] for f in fixed_res["findings"]}
    unexpected = expected_new_rules.intersection(fixed_rules)
    assert not unexpected, f"False positives on fixed repo: {unexpected}"


def test_cli_help_includes_proxy_and_deep_audit_examples(capsys):
    for argv in (["--proxy", "--help"], ["deep-audit", "--help"], ["--deep-audit", "-h"]):
        with pytest.raises(SystemExit) as exc:
            rfc_hunt_swarm.parse_swarm_arguments(argv)
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "HOW TO RUN --proxy" in out
        assert "127.0.0.1:3128" in out
        assert "http://localhost:8888" in out
        assert "--trust-boundary-review" in out

    with pytest.raises(SystemExit) as exc_main:
        rfc_hunt_swarm.parse_swarm_arguments(["--help"])
    assert exc_main.value.code == 0
    main_help = capsys.readouterr().out
    assert "13. DEEP CODE-REPO AUDIT" in main_help
    assert "--proxy [SPEC]" in main_help


def test_reusable_ci_audit_runner_emits_valid_sarif_and_respects_gates(tmp_path, monkeypatch):
    import scripts.ci_run_reusable_audit as ci_mod

    repo = _create_sample_repo(tmp_path / "target_repo")
    out_dir = tmp_path / "ci_reports"
    summary_file = tmp_path / "step_summary.md"

    argv_auto = ci_mod.build_rfchunt_cli_argv(
        Path(r"d:\harfile\rfchunt"),
        repo,
        out_dir,
        tmp_path / "ci.db",
        mode="deep-audit",
        proxy="auto",
        enable_poc=True,
    )
    assert "deep-audit" in argv_auto
    assert "--proxy" in argv_auto
    assert "--poc" in argv_auto

    monkeypatch.setenv("RFCHUNT_ROOT", r"d:\harfile\rfchunt")
    monkeypatch.setenv("TARGET_REPO", str(repo))
    monkeypatch.setenv("REPORT_DIR", str(out_dir))
    monkeypatch.setenv("RFCHUNT_MODE", "trust-boundary")
    monkeypatch.setenv("RFCHUNT_PROXY", "")
    monkeypatch.setenv("RFCHUNT_ENABLE_POC", "true")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("FAIL_ON_SEV", "none")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    rc = ci_mod.main()
    assert rc == 0

    sarif_path = out_dir / "rfchunt_ci.sarif"
    assert sarif_path.is_file()
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) >= 1
    results = sarif["runs"][-1]["results"]
    assert len(results) >= 5
    # Verify all SARIF URIs are clean repo-relative POSIX paths (no drive letters or leading slashes)
    for r in results:
        uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/")
        assert ":" not in uri

    assert summary_file.is_file()
    assert "## RFCHunt Security Audit Summary" in summary_file.read_text(encoding="utf-8")

    # Severity gate should fail when HIGH findings exist and gate is HIGH
    deep_sum = json.loads((out_dir / "deep_audit" / "deep_audit_summary.json").read_text(encoding="utf-8"))
    ok_none, _ = ci_mod.evaluate_severity_gate(deep_sum, "none")
    ok_high, _ = ci_mod.evaluate_severity_gate(deep_sum, "HIGH")
    assert ok_none is True
    assert ok_high is False



