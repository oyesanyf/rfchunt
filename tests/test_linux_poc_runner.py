"""
Unit tests for LinuxPocRunner (security hardening invariants, path conversion, and transcript output).
"""

from pathlib import Path
import pytest

from engine.linux_poc_runner import (
    LANGUAGE_PROFILES,
    LinuxPocRunner,
    VerifiableTranscript,
    build_hardened_docker_argv,
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


def test_rejects_critical_host_mounts_and_unc_paths():
    ok_unc, _ = validate_mount_path(r"\\attacker\share\repo")
    assert ok_unc is False

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
