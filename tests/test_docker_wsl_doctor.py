"""Automated tests for engine/docker_wsl_doctor.py and `docker-doctor` CLI integration."""

from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path
from typing import Any, List, Sequence

import pytest

from engine.docker_wsl_doctor import (
    diagnose_docker_wsl,
    is_guard_active,
    probe_docker_daemon,
    repair_docker_wsl,
    stream_copy_to_uncompressed_vhdx,
)
import rfc_hunt_swarm


def _fake_completed(rc: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["cmd"], returncode=rc, stdout=stdout, stderr=stderr)


def _setup_fake_docker_tree(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    local = tmp_path / "LocalAppData"
    roaming = tmp_path / "RoamingAppData"
    disk_dir = local / "Docker" / "wsl" / "disk"
    main_dir = local / "Docker" / "wsl" / "main"
    wsl_ubuntu = local / "wsl" / "{0e2d9ebd-b8cc-4639-aae7-f03724bafd36}"
    log_dir = local / "Docker" / "log" / "host"
    dd_dir = local / "Programs" / "DockerDesktop"
    bin_dir = dd_dir / "resources" / "bin"

    for d in (disk_dir, main_dir, wsl_ubuntu, log_dir, bin_dir, roaming / "Docker"):
        d.mkdir(parents=True, exist_ok=True)

    docker_data = disk_dir / "docker_data.vhdx"
    docker_data.write_bytes(b"VHDX_DATA_PAYLOAD_" * 4096)
    main_vhdx = main_dir / "ext4.vhdx"
    main_vhdx.write_bytes(b"MAIN_VHDX_" * 512)
    ubuntu_vhdx = wsl_ubuntu / "ext4.vhdx"
    ubuntu_vhdx.write_bytes(b"UBUNTU_VHDX_" * 1024)

    (dd_dir / "Docker Desktop.exe").write_bytes(b"MZ")
    (bin_dir / "docker.exe").write_bytes(b"MZ")
    (roaming / "Docker" / "settings-store.json").write_text(
        json.dumps({"EngineTypeWindows": "wsl2"}), encoding="utf-8"
    )
    (log_dir / "monitor.log").write_text(
        "[wsl-bootstrap] detected existing ext4 file system\n"
        "Error: preparing environment: provisioning data: preparing block device /dev/sdd: "
        "mounting disk: input/output error\n"
        "wslErrorCode: DockerDesktop/Wsl/ExecError\n",
        encoding="utf-8",
    )
    return local, roaming, docker_data, ubuntu_vhdx


def test_docker_doctor_module_has_zero_gui_imports_and_no_shell_true():
    src = Path(r"d:\harfile\rfchunt\engine\docker_wsl_doctor.py").read_text(encoding="utf-8")
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


def test_guard_blocks_repair_in_tests_ci_offline_and_deny(monkeypatch):
    # PYTEST_CURRENT_TEST is active during pytest -> fail closed by default
    guarded, reason = is_guard_active()
    assert guarded is True
    assert "PYTEST_CURRENT_TEST" in reason

    rep = repair_docker_wsl(platform_override="win32")
    assert rep.status == "skipped_guard"

    # Explicit deny blocks even when allow_in_tests=True
    guarded_deny, reason_deny = is_guard_active(approval_mode="deny", allow_in_tests=True)
    assert guarded_deny is True
    assert "deny" in reason_deny

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    guarded_off, _ = is_guard_active(allow_in_tests=True)
    assert guarded_off is True


def test_probe_docker_daemon_rejects_empty_server_version():
    up_empty, ver_empty = probe_docker_daemon(
        "docker",
        run_cmd=lambda argv, timeout=3.0: _fake_completed(0, stdout="   \n"),
    )
    assert up_empty is False
    assert ver_empty is None

    up_ok, ver_ok = probe_docker_daemon(
        "docker",
        run_cmd=lambda argv, timeout=3.0: _fake_completed(0, stdout="29.9.2\n"),
    )
    assert up_ok is True
    assert ver_ok == "29.9.2"


def test_diagnose_detects_ntfs_compression_and_wsl_bootstrap_io_errors(tmp_path):
    local, roaming, docker_data, ubuntu_vhdx = _setup_fake_docker_tree(tmp_path)
    compressed_set = {str(docker_data.parent).lower(), str(docker_data).lower(), str(ubuntu_vhdx).lower()}

    diag = diagnose_docker_wsl(
        local_appdata=local,
        roaming_appdata=roaming,
        include_all_wsl=True,
        compression_checker=lambda p: str(p).lower() in compressed_set,
        run_cmd=lambda argv, timeout=3.0: _fake_completed(1, stderr="pipe not found"),
        platform_override="win32",
    )
    assert diag.healthy is False
    assert diag.daemon_running is False
    assert "docker_daemon_not_running" in diag.issues
    assert "ntfs_compressed_vhdx_detected" in diag.issues
    assert "vhdx_ext4_mount_io_error" in diag.issues
    assert "wsl_bootstrap_failed" in diag.issues
    assert len(diag.compressed_vhdxs) == 2
    assert len(diag.compressed_dirs) == 1


def test_repair_handles_compact_file_system_limitation_via_verified_uncompressed_swap(tmp_path, monkeypatch):
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    local, roaming, docker_data, ubuntu_vhdx = _setup_fake_docker_tree(tmp_path)
    orig_bytes = docker_data.read_bytes()

    compressed_paths = {
        str(docker_data.parent).lower(),
        str(docker_data).lower(),
    }
    commands_seen: List[List[str]] = []
    launched = {"done": False}
    acls_copied: List[tuple[Path, Path]] = []

    def fake_run(argv: Sequence[str], timeout: float = 30.0) -> subprocess.CompletedProcess:
        cmd = [str(x) for x in argv]
        commands_seen.append(cmd)
        if cmd[0] == "compact" and cmd[1] == "/u":
            target = cmd[2].lower()
            if target == str(docker_data.parent).lower():
                compressed_paths.discard(target)
                return _fake_completed(0, stdout="1 files within 1 directories were uncompressed.")
            # Simulate STATUS_FILE_SYSTEM_LIMITATION on large compressed docker_data.vhdx
            return _fake_completed(1, stderr="The requested operation could not be completed due to a file system limitation")
        if cmd[0] == "explorer.exe":
            launched["done"] = True
            return _fake_completed(0)
        if len(cmd) >= 2 and cmd[1] == "version":
            return _fake_completed(0, stdout="29.9.2\n") if launched["done"] else _fake_completed(1, stderr="down")
        return _fake_completed(0)

    def fake_acl(src: Path, dst: Path) -> tuple[bool, str]:
        acls_copied.append((src, dst))
        return True, "acl_copied"

    def fake_is_compressed(p: Any) -> bool:
        return str(p).lower() in compressed_paths

    # When swap renames src -> .compressed_bak and .uncompressed -> src, remove src from compressed_paths after swap
    def fake_acl_and_clear(src: Path, dst: Path) -> tuple[bool, str]:
        acls_copied.append((src, dst))
        # Destination was created inside uncompressed dir; after swap src points to uncompressed file
        compressed_paths.discard(str(src).lower())
        return True, "acl_copied"

    rep = repair_docker_wsl(
        local_appdata=local,
        roaming_appdata=roaming,
        include_all_wsl=False,
        reset_stateless_distro=True,
        launch_docker=True,
        wait_timeout_sec=5.0,
        allow_in_tests=True,
        compression_checker=fake_is_compressed,
        run_cmd=fake_run,
        acl_copier=fake_acl_and_clear,
        platform_override="win32",
    )

    assert rep.status == "repaired"
    assert rep.errors == []
    assert rep.after is not None and rep.after.healthy is True and rep.after.server_version == "29.9.2"
    assert len(rep.backups_created) == 1
    bak_file = Path(rep.backups_created[0])
    assert bak_file.is_file()
    assert bak_file.name.startswith("docker_data.vhdx.compressed_bak")
    # Byte-exact preservation of original VHDX contents
    assert docker_data.read_bytes() == orig_bytes
    assert len(acls_copied) == 1
    # Verify wsl --shutdown and stateless docker-desktop unregister ran (and NEVER deleted data)
    assert ["wsl", "--shutdown"] in commands_seen
    assert ["wsl", "--unregister", "docker-desktop"] in commands_seen


def test_stream_copy_fails_closed_on_insufficient_disk_space(tmp_path, monkeypatch):
    vhdx = tmp_path / "docker_data.vhdx"
    vhdx.write_bytes(b"A" * 1024)
    monkeypatch.setattr(
        "engine.docker_wsl_doctor.shutil.disk_usage",
        lambda _: type("Usage", (), {"total": 2048, "used": 1500, "free": 500})(),
    )
    ok, msg, bak = stream_copy_to_uncompressed_vhdx(vhdx, compression_checker=lambda _: False)
    assert ok is False
    assert "Insufficient free space" in msg
    assert bak is None
    assert vhdx.is_file()


def test_cli_docker_doctor_read_only_json_and_parser_flags(monkeypatch, capsys):
    parser = rfc_hunt_swarm.build_swarm_parser()
    args = parser.parse_args(["docker-doctor", "--json"])
    monkeypatch.setattr(
        "engine.docker_wsl_doctor.diagnose_docker_wsl",
        lambda **kwargs: type(
            "FakeDiag",
            (),
            {"to_dict": lambda self: {"healthy": True, "daemon_running": True, "server_version": "29.9.2"}},
        )(),
    )
    rfc_hunt_swarm.cmd_docker_doctor(args)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["healthy"] is True
    assert data["server_version"] == "29.9.2"

    fix_args = parser.parse_args(["docker-doctor", "--fix", "--include-all-wsl", "--reset-docker-distro"])
    assert fix_args.fix_docker is True
    assert fix_args.include_all_wsl is True
    assert fix_args.reset_docker_distro is True
