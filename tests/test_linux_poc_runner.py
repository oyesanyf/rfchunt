"""
Unit tests for LinuxPocRunner (security hardening invariants, path conversion, and transcript output).
"""

from pathlib import Path
import subprocess
from types import SimpleNamespace
import pytest

import engine.linux_poc_runner as lpr
from engine.linux_poc_runner import (
    LANGUAGE_PROFILES,
    LinuxPocRunner,
    VerifiableTranscript,
    build_hardened_docker_argv,
    probe_optional_backends,
    probe_toolchain_availability,
    run_symbolic_hook,
    save_transcript_bundle,
    validate_command_tokens,
    validate_mount_path,
    windows_to_wsl_path,
)


def test_build_hardened_docker_argv_enforces_sandbox_invariants(tmp_path: Path):
    argv = build_hardened_docker_argv(
        docker_bin="docker",
        image="rust:1.85-slim",
        repo_dir=tmp_path,
        cmd=["cargo", "test", "--release"],
    )
    assert "--rm" in argv
    assert "--network=none" in argv
    assert "--cap-drop=ALL" in argv
    assert "no-new-privileges:true" in argv
    assert "--read-only" in argv
    assert any(tok.endswith(":/workspace:ro") for tok in argv)
    assert argv[-3:] == ["cargo", "test", "--release"]


def test_rejects_shell_metacharacters_and_unsafe_images(tmp_path: Path):
    ok, err = validate_command_tokens(["node", "poc.mjs; rm -rf /"])
    assert ok is False
    assert "metacharacter" in err.lower()

    with pytest.raises(ValueError):
        build_hardened_docker_argv(
            docker_bin="docker",
            image="bad image; whoami",
            repo_dir=tmp_path,
            cmd=["node", "-v"],
        )


def test_rejects_critical_host_mounts_and_unc_paths(monkeypatch: pytest.MonkeyPatch):
    ok_unc, _ = validate_mount_path(r"\\attacker\share\repo")
    assert ok_unc is False

    ok_fwd_unc, _ = validate_mount_path("//attacker/share/repo")
    assert ok_fwd_unc is False

    # Even if Path.exists / Path.is_dir claim a SMB share is reachable, UNC paths must fail closed
    monkeypatch.setattr(lpr.Path, "exists", lambda _self: True)
    monkeypatch.setattr(lpr.Path, "is_dir", lambda _self: True)
    ok_reachable_fwd_unc, _ = validate_mount_path("//server/share/bin")
    assert ok_reachable_fwd_unc is False
    ok_reachable_back_unc, _ = validate_mount_path(r"\\server\share\bin")
    assert ok_reachable_back_unc is False

    ok_win, _ = validate_mount_path(r"C:\Windows\System32")
    assert ok_win is False


def test_windows_to_wsl_path_conversion():
    assert windows_to_wsl_path("D:/harfile/rfchunt") == "/mnt/d/harfile/rfchunt"


def test_transcript_serialization_and_bundle_write(tmp_path: Path):
    tr = VerifiableTranscript(
        language="rust",
        backend="docker",
        status="passed",
        exit_code=0,
        command=["cargo", "test", "--release"],
        image="rust:1.85-slim",
        repo_path=str(tmp_path),
        started_at_utc="2026-11-25T00:00:00+00:00",
        elapsed_ms=412.5,
        stdout="test result: ok. 1 passed; 0 failed",
        stderr="",
    )
    assert tr.verified is True
    j_path, m_path = save_transcript_bundle(tr, tmp_path / "out", stem="finding_01")
    assert j_path.is_file()
    assert m_path.is_file()
    md = m_path.read_text(encoding="utf-8")
    assert "test result: ok. 1 passed" in md
    assert "--network=none" in md


def test_runner_rejects_unsupported_language(tmp_path: Path):
    runner = LinuxPocRunner()
    with pytest.raises(ValueError):
        runner.run_poc(language="cobol", repo_path=tmp_path, cmd=["echo", "hi"])
    assert {"rust", "node", "python", "ruby", "go"}.issubset(LANGUAGE_PROFILES.keys())


# ---------------------------------------------------------------------------
# M1 Extended Unit Tests: Optional Backend Probes & Bounded Symbolic Hooks
# ---------------------------------------------------------------------------


def test_probe_optional_backends_all_unavailable_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    assert probe_toolchain_availability is probe_optional_backends
    monkeypatch.setattr(lpr, "find_docker_binary", lambda: None)
    monkeypatch.setattr(lpr, "probe_docker_daemon", lambda *a, **kw: (False, None))
    monkeypatch.setattr(lpr.shutil, "which", lambda _name: None)
    monkeypatch.setattr(lpr, "_safe_find_spec", lambda _mod: None)

    res = probe_optional_backends(lean_dir=tmp_path)
    expected_keys = {
        "docker",
        "wsl2",
        "lean4",
        "rfchunt_lean_oracle",
        "angr",
        "klee",
        "semgrep",
    }
    assert set(res.keys()) == expected_keys
    for key in expected_keys:
        entry = res[key]
        assert set(entry.keys()) == {"available", "status", "reason", "path_or_module"}
        assert entry["available"] is False
        assert entry["status"] == "unavailable"
        assert isinstance(entry["reason"], str) and entry["reason"]


def test_probe_optional_backends_available_tools_and_oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    oracle_exe = tmp_path / ".lake" / "build" / "bin" / "rfchunt-lean-oracle.exe"
    oracle_exe.parent.mkdir(parents=True, exist_ok=True)
    oracle_exe.write_text("stub", encoding="utf-8")
    (tmp_path / "lakefile.lean").write_text("package rfchunt_formal\n", encoding="utf-8")

    monkeypatch.setattr(
        lpr,
        "find_docker_binary",
        lambda: r"C:\Program Files\Docker\docker.exe",
    )
    monkeypatch.setattr(
        lpr,
        "probe_docker_daemon",
        lambda _bin, timeout=2.5: (True, "27.1.1"),
    )
    monkeypatch.setattr(
        lpr.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in ("wsl.exe", "lean", "lake", "klee", "semgrep") else None,
    )
    monkeypatch.setattr(
        lpr,
        "_safe_find_spec",
        lambda mod: SimpleNamespace(origin=f"/site-packages/{mod}/__init__.py") if mod == "angr" else None,
    )
    monkeypatch.setattr(
        lpr,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout="Default Distribution: Ubuntu", stderr=""),
    )

    res = probe_optional_backends(lean_dir=tmp_path)
    for key in res:
        assert res[key]["available"] is True
        assert res[key]["status"] == "available"
        assert res[key]["path_or_module"]

    # Also verify UTF-16LE NUL-byte stripping when WSL2 returns non-zero
    monkeypatch.setattr(
        lpr,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="W\x00S\x00L\x00 \x00n\x00o\x00t\x00 \x00c\x00o\x00n\x00f\x00i\x00g\x00u\x00r\x00e\x00d\x00",
        ),
    )
    res_wsl_fail = probe_optional_backends(lean_dir=tmp_path)
    assert res_wsl_fail["wsl2"]["available"] is False
    assert "\x00" not in res_wsl_fail["wsl2"]["reason"]
    assert "WSL not configured" in res_wsl_fail["wsl2"]["reason"]


def test_probe_optional_backends_wsl_and_docker_timeout_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import threading
    import time as _time

    docker_timeouts = []
    wsl_timeouts = []
    release_hang = threading.Event()

    monkeypatch.setattr(lpr, "find_docker_binary", lambda: r"C:\Program Files\Docker\docker.exe")

    def _hanging_docker_probe(_bin, timeout=2.5):
        docker_timeouts.append(timeout)
        release_hang.wait(timeout=5.0)
        return (False, None)

    monkeypatch.setattr(lpr, "probe_docker_daemon", _hanging_docker_probe)
    monkeypatch.setattr(
        lpr.shutil,
        "which",
        lambda name: r"C:\Windows\System32\wsl.exe" if name == "wsl.exe" else None,
    )
    monkeypatch.setattr(lpr, "_safe_find_spec", lambda _mod: None)

    def _timeout_run(*_a, **kw):
        wsl_timeouts.append(kw.get("timeout"))
        raise subprocess.TimeoutExpired(cmd=["wsl.exe", "--status"], timeout=kw.get("timeout", 2.5))

    monkeypatch.setattr(lpr, "silent_subprocess_run", _timeout_run)

    t0 = _time.monotonic()
    try:
        res = probe_optional_backends(lean_dir=tmp_path, timeout_sec=0.4)
    finally:
        release_hang.set()
    dt = _time.monotonic() - t0

    assert docker_timeouts and docker_timeouts[0] == pytest.approx(0.4, abs=0.05)
    assert wsl_timeouts and wsl_timeouts[0] == pytest.approx(0.4, abs=0.05)
    assert dt < 1.5
    assert res["docker"]["available"] is False
    assert res["docker"]["status"] == "timeout"
    assert res["wsl2"]["available"] is False
    assert res["wsl2"]["status"] == "timeout"

    # Clamp upper bound <= 3.0s even if caller passes timeout_sec=99.0
    recorded_upper = []
    monkeypatch.setattr(
        lpr,
        "probe_docker_daemon",
        lambda _bin, timeout=2.5: (recorded_upper.append(timeout) or False, None),
    )
    res_clamped = probe_optional_backends(lean_dir=tmp_path, timeout_sec=99.0)
    assert recorded_upper and recorded_upper[0] <= 3.0
    assert wsl_timeouts[-1] <= 3.0
    assert res_clamped["docker"]["status"] == "unavailable"


def test_probe_optional_backends_live_unmocked_bounded_latency():
    import time as _time

    t0 = _time.monotonic()
    res = probe_optional_backends(timeout_sec=1.5)
    dt = _time.monotonic() - t0
    assert dt <= 3.0, f"Live unmocked probe_optional_backends(timeout_sec=1.5) took {dt:.3f}s (> 3.0s)"
    assert set(res.keys()) == {
        "docker",
        "wsl2",
        "lean4",
        "rfchunt_lean_oracle",
        "angr",
        "klee",
        "semgrep",
    }


def test_run_symbolic_hook_unsupported_backend(tmp_path: Path):
    res = run_symbolic_hook("ghidra", tmp_path)
    assert res["backend"] == "ghidra"
    assert res["available"] is False
    assert res["status"] == "unsupported_backend"
    assert res["verified"] is False
    assert res["findings"] == []


def test_run_symbolic_hook_rejects_unsafe_paths_and_args(tmp_path: Path):
    sample_bin = tmp_path / "sample.bin"
    sample_bin.write_bytes(b"\x7fELF")

    unsafe_paths = [
        "",
        r"\\attacker\share\bin",
        "//attacker/share/bin",
        r"C:\Windows\System32",
        r"C:\Windows\System32\cmd.exe",
        str(tmp_path / "does_not_exist.bin"),
    ]
    for bad_path in unsafe_paths:
        res = run_symbolic_hook("angr", bad_path)
        assert res["status"] == "rejected_unsafe"
        assert res["verified"] is False
        assert res["findings"] == []

    # Unsafe args: empty token, shell metacharacters, raw string/bytes/bytearray, dict, non-sequence
    for bad_args in (
        [""],
        ["--flag;rm -rf /"],
        "--raw-string",
        b"--raw-bytes",
        bytearray(b"--raw-bytearray"),
        123,
        {"--flag": "; rm"},
        {"--safe"},
    ):
        res = run_symbolic_hook("angr", sample_bin, args=bad_args)  # type: ignore[arg-type]
        assert res["available"] is False
        assert res["status"] == "rejected_unsafe"
        assert res["verified"] is False
        assert res["findings"] == []


def test_run_symbolic_hook_empty_args_equivalent_to_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    sample_bin = tmp_path / "sample.bin"
    sample_bin.write_bytes(b"\x7fELF")

    # 1. Unavailable backend: args=[] matches args=None ("unavailable")
    monkeypatch.setattr(lpr, "_safe_find_spec", lambda _mod: None)
    monkeypatch.setattr(lpr.shutil, "which", lambda _name: None)
    res_none = run_symbolic_hook("angr", sample_bin, args=None)
    res_empty = run_symbolic_hook("angr", sample_bin, args=[])
    assert res_none["status"] == "unavailable"
    assert res_empty["status"] == "unavailable"
    assert res_empty["verified"] is False
    assert res_empty["findings"] == []

    # 2. Mocked available angr: args=[] matches args=None ("passed", verified=False, identical command)
    monkeypatch.setattr(
        lpr,
        "_safe_find_spec",
        lambda mod: SimpleNamespace(origin="/site-packages/angr/__init__.py") if mod == "angr" else None,
    )
    monkeypatch.setattr(
        lpr,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout='{"findings": [], "verified": false}', stderr=""),
    )
    ok_none = run_symbolic_hook("angr", sample_bin, args=None)
    ok_empty = run_symbolic_hook("angr", sample_bin, args=[])
    assert ok_none["status"] == "passed"
    assert ok_empty["status"] == "passed"
    assert ok_empty["verified"] is False
    assert ok_empty["command"] == ok_none["command"]


def test_run_symbolic_hook_unavailable_graceful_degradation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    sample_bin = tmp_path / "sample.bin"
    sample_bin.write_bytes(b"\x7fELF")

    monkeypatch.setattr(lpr, "_safe_find_spec", lambda _mod: None)
    monkeypatch.setattr(lpr.shutil, "which", lambda _name: None)

    for backend in ("angr", "klee"):
        res = run_symbolic_hook(backend, sample_bin)
        assert res["backend"] == backend
        assert res["available"] is False
        assert res["status"] == "unavailable"
        assert res["verified"] is False
        assert res["findings"] == []
        assert res["remediation_hint"]


def test_run_symbolic_hook_bounded_execution_and_no_fabricated_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    sample_bin = tmp_path / "sample.bin"
    sample_bin.write_bytes(b"\x7fELF")

    monkeypatch.setattr(
        lpr,
        "_safe_find_spec",
        lambda mod: SimpleNamespace(origin="/site-packages/angr/__init__.py") if mod == "angr" else None,
    )
    monkeypatch.setattr(
        lpr.shutil,
        "which",
        lambda name: "/usr/bin/klee" if name == "klee" else None,
    )

    seen_kwargs = []

    def _run_unverified(*args, **kwargs):
        seen_kwargs.append(kwargs)
        return SimpleNamespace(returncode=0, stdout='{"findings": [], "verified": false}', stderr="")

    monkeypatch.setattr(lpr, "silent_subprocess_run", _run_unverified)
    res_unverified = run_symbolic_hook("angr", sample_bin, args=["--max-steps=5"], timeout_sec=10.0)
    assert res_unverified["available"] is True
    assert res_unverified["status"] == "passed"
    assert res_unverified["verified"] is False
    assert res_unverified["command"][-2:] == [str(sample_bin.resolve()), "--max-steps=5"]
    assert "bounded_metadata_probe" in res_unverified["command"][2]
    assert "args_received" in res_unverified["command"][2]
    assert all(kw.get("shell") is not True for kw in seen_kwargs)

    # Empty stdout on rc=0 must never fabricate verified=True
    monkeypatch.setattr(
        lpr,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    res_empty = run_symbolic_hook("klee", sample_bin)
    assert res_empty["status"] == "passed"
    assert res_empty["verified"] is False

    # Explicit verified=True JSON with rc=0 sets verified=True
    monkeypatch.setattr(
        lpr,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0,
            stdout='{"verified": true, "findings": [{"title": "reach"}]}',
            stderr="",
        ),
    )
    res_ok = run_symbolic_hook("klee", sample_bin)
    assert res_ok["status"] == "passed"
    assert res_ok["verified"] is True
    assert res_ok["findings"] == [{"title": "reach"}]

    # Non-zero exit must keep verified=False even if stdout claims verified=true
    monkeypatch.setattr(
        lpr,
        "silent_subprocess_run",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout='{"verified": true}', stderr="err"),
    )
    res_fail = run_symbolic_hook("angr", sample_bin)
    assert res_fail["status"] == "failed"
    assert res_fail["verified"] is False

    # Timeout degrades cleanly
    def _run_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd=["klee"], timeout=1.0)

    monkeypatch.setattr(lpr, "silent_subprocess_run", _run_timeout)
    res_to = run_symbolic_hook("klee", sample_bin, timeout_sec=1.0)
    assert res_to["status"] == "timeout"
    assert res_to["verified"] is False
    assert res_to["findings"] == []
