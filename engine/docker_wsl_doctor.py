"""
Windows Docker Desktop & WSL2 Self-Healing Diagnostic and Non-Destructive Repair Engine.

Automatically detects and repairs the most common Windows Docker Desktop / WSL2 bootstrap
failures for users running RFCHunt (`--all`, `poe-verify`, `sandbox-invariants`,
`fuzz-bridge`, `oracle --docker-parser-matrix`, `docker-doctor`):
  1. NTFS Compression (`FILE_ATTRIBUTE_COMPRESSED`, 0x0800) on WSL2 / Docker `.vhdx` disks
     and parent directories, which triggers `Ntfs Event ID 141 ({Delayed Write Failed})`,
     `STATUS_FILE_SYSTEM_LIMITATION`, and `wsl-bootstrap` `mounting disk: input/output error`.
  2. Stopped Docker Desktop daemon when Docker Desktop is installed locally.
  3. Wedged stateless `docker-desktop` WSL runtime distro (rebuilt from `docker-desktop.iso`
     without touching user images/volumes in `docker_data.vhdx`).

Safety invariants:
  - Strictly CLI-only (zero GUI imports), zero `shell=True`, zero PATH or registry edits.
  - Strictly non-destructive: NEVER deletes `docker_data.vhdx` or user WSL distros; any
    decompressed replacement preserves the original file as `*.compressed_bak` and copies
    exact NTFS + Hyper-V VM SID ACLs.
  - Fail-closed under `PYTEST_CURRENT_TEST`, `CI`, `GITHUB_ACTIONS`, `RFCHUNT_OFFLINE=1`,
    or `approval_mode="deny"` unless explicitly overridden for isolated unit tests.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

FILE_ATTRIBUTE_COMPRESSED = 0x0800
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
STREAM_COPY_CHUNK_BYTES = 64 * 1024 * 1024  # 64 MB streaming chunks
MIN_FREE_SPACE_SAFETY_RATIO = 1.15
DOCKER_PROBE_TIMEOUT_SEC = 3.0

_DOCKER_STOP_PROCESS_NAMES = (
    "Docker Desktop.exe",
    "com.docker.backend.exe",
    "com.docker.build.exe",
    "com.docker.proxy.exe",
    "vpnkit.exe",
)


@dataclass
class VhdxInspectRecord:
    """Inspection result for a single WSL2 / Docker VHDX file or directory."""

    path: str
    kind: str  # "file" | "dir"
    size_bytes: int
    compressed: bool
    free_bytes_on_volume: int
    role: str  # "docker_data" | "docker_main" | "wsl_distro" | "parent_dir"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "size_gb": round(self.size_bytes / 1e9, 2),
            "compressed": self.compressed,
            "free_bytes_on_volume": self.free_bytes_on_volume,
            "role": self.role,
        }


@dataclass
class DockerWSLDiagnosis:
    """Read-only diagnostic snapshot of Windows Docker Desktop and WSL2 health."""

    platform: str
    docker_binary: Optional[str]
    docker_desktop_exe: Optional[str]
    daemon_running: bool
    server_version: Optional[str]
    issues: List[str] = field(default_factory=list)
    compressed_dirs: List[VhdxInspectRecord] = field(default_factory=list)
    compressed_vhdxs: List[VhdxInspectRecord] = field(default_factory=list)
    vhdx_inventory: List[VhdxInspectRecord] = field(default_factory=list)
    log_signals: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    healthy: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "healthy": self.healthy,
            "docker_binary": self.docker_binary,
            "docker_desktop_exe": self.docker_desktop_exe,
            "daemon_running": self.daemon_running,
            "server_version": self.server_version,
            "issues": list(self.issues),
            "compressed_dirs": [r.to_dict() for r in self.compressed_dirs],
            "compressed_vhdxs": [r.to_dict() for r in self.compressed_vhdxs],
            "vhdx_inventory": [r.to_dict() for r in self.vhdx_inventory],
            "log_signals": list(self.log_signals),
            "recommended_actions": list(self.recommended_actions),
        }


@dataclass
class DockerWSLRepairReport:
    """Structured report of a non-destructive Docker Desktop / WSL2 repair pass."""

    status: str  # "healthy" | "repaired" | "skipped_guard" | "skipped_non_windows" | "not_installed" | "partial_or_failed"
    actions_taken: List[str] = field(default_factory=list)
    backups_created: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    before: Optional[DockerWSLDiagnosis] = None
    after: Optional[DockerWSLDiagnosis] = None
    elapsed_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "actions_taken": list(self.actions_taken),
            "backups_created": list(self.backups_created),
            "errors": list(self.errors),
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "elapsed_sec": round(self.elapsed_sec, 3),
        }


def is_guard_active(*, approval_mode: str = "policy", allow_in_tests: bool = False) -> Tuple[bool, str]:
    """Fail-closed guard preventing host mutations during tests, CI, offline, or deny mode."""
    if str(approval_mode or "policy").strip().lower() == "deny":
        return True, "approval_mode=deny"
    if os.environ.get("RFCHUNT_OFFLINE", "").strip() in ("1", "true", "TRUE", "yes"):
        return True, "RFCHUNT_OFFLINE=1"
    if not allow_in_tests:
        for env_key in ("PYTEST_CURRENT_TEST", "CI", "GITHUB_ACTIONS"):
            if os.environ.get(env_key):
                return True, f"{env_key} active"
    return False, ""


def _creationflags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _default_run_cmd(
    argv: Sequence[str],
    *,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False,
        creationflags=_creationflags(),
        check=False,
    )


def is_ntfs_compressed(path: Union[str, Path]) -> bool:
    """Returns True iff Windows FILE_ATTRIBUTE_COMPRESSED (0x0800) is set on `path`."""
    if os.name != "nt":
        return False
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == INVALID_FILE_ATTRIBUTES:
            return False
        return bool(attrs & FILE_ATTRIBUTE_COMPRESSED)
    except Exception:
        return False


def find_docker_binary(local_appdata: Optional[Path] = None) -> Optional[str]:
    """Locates `docker` / `docker.exe` via PATH or standard user-space/program-files installs."""
    found = shutil.which("docker")
    if found:
        return found
    if os.name != "nt":
        return None
    local = local_appdata or (Path(os.environ["LOCALAPPDATA"]) if os.environ.get("LOCALAPPDATA") else None)
    candidates: List[Path] = []
    if local:
        candidates.append(local / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe")
    pf = os.environ.get("ProgramFiles")
    if pf:
        candidates.append(Path(pf) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe")
    for cand in candidates:
        if cand.is_file():
            return str(cand)
    return None


def find_docker_desktop_exe(local_appdata: Optional[Path] = None) -> Optional[str]:
    """Locates Docker Desktop.exe on Windows (both user-space and Program Files installs)."""
    if os.name != "nt":
        return None
    local = local_appdata or (Path(os.environ["LOCALAPPDATA"]) if os.environ.get("LOCALAPPDATA") else None)
    candidates: List[Path] = []
    if local:
        candidates.append(local / "Programs" / "DockerDesktop" / "Docker Desktop.exe")
    pf = os.environ.get("ProgramFiles")
    if pf:
        candidates.append(Path(pf) / "Docker" / "Docker" / "Docker Desktop.exe")
    for cand in candidates:
        if cand.is_file():
            return str(cand)
    return None


def probe_docker_daemon(
    docker_binary: Optional[str] = None,
    *,
    timeout: float = DOCKER_PROBE_TIMEOUT_SEC,
    run_cmd: Callable[..., subprocess.CompletedProcess] = _default_run_cmd,
) -> Tuple[bool, Optional[str]]:
    """
    Checks whether Docker Engine Server is genuinely responding (non-empty `Server.Version`).
    Never treats an empty `docker info` output as ready.
    """
    exe = docker_binary or find_docker_binary()
    if not exe:
        return False, None
    try:
        proc = run_cmd([exe, "version", "--format", "{{.Server.Version}}"], timeout=timeout)
        ver = (proc.stdout or "").strip()
        if proc.returncode == 0 and ver and "error" not in ver.lower() and "failed" not in ver.lower():
            return True, ver
    except Exception:
        pass
    return False, None


def _discover_vhdx_and_dirs(
    local_appdata: Path,
    roaming_appdata: Optional[Path] = None,
    *,
    include_all_wsl: bool = True,
) -> Tuple[List[Tuple[Path, str]], List[Tuple[Path, str]]]:
    """Discovers Docker Desktop and WSL2 parent directories and `.vhdx` files."""
    dirs: List[Tuple[Path, str]] = []
    files: List[Tuple[Path, str]] = []
    seen_dirs = set()
    seen_files = set()

    def _add_dir(p: Path, role: str) -> None:
        key = str(p).lower()
        if p.is_dir() and key not in seen_dirs:
            seen_dirs.add(key)
            dirs.append((p, role))

    def _add_file(p: Path, role: str) -> None:
        key = str(p).lower()
        if p.is_file() and key not in seen_files:
            seen_files.add(key)
            files.append((p, role))

    docker_root = local_appdata / "Docker"
    for d in (
        docker_root,
        docker_root / "wsl",
        docker_root / "wsl" / "disk",
        docker_root / "wsl" / "data",
        docker_root / "wsl" / "main",
    ):
        _add_dir(d, "parent_dir")

    for cand, role in (
        (docker_root / "wsl" / "disk" / "docker_data.vhdx", "docker_data"),
        (docker_root / "wsl" / "data" / "ext4.vhdx", "docker_data"),
        (docker_root / "wsl" / "main" / "ext4.vhdx", "docker_main"),
    ):
        _add_file(cand, role)

    # Check custom dataFolder in settings-store.json
    if roaming_appdata:
        ss = roaming_appdata / "Docker" / "settings-store.json"
        if ss.is_file():
            try:
                cfg = json.loads(ss.read_text(encoding="utf-8", errors="replace"))
                custom_folder = cfg.get("DataFolder") or cfg.get("dataFolder")
                if isinstance(custom_folder, str) and custom_folder.strip():
                    cf = Path(custom_folder.strip())
                    _add_dir(cf, "parent_dir")
                    for sub in (cf / "disk" / "docker_data.vhdx", cf / "docker_data.vhdx", cf / "data" / "ext4.vhdx"):
                        _add_dir(sub.parent, "parent_dir")
                        _add_file(sub, "docker_data")
            except Exception:
                pass

    if include_all_wsl:
        wsl_root = local_appdata / "wsl"
        _add_dir(wsl_root, "parent_dir")
        if wsl_root.is_dir():
            try:
                for child in sorted(wsl_root.iterdir()):
                    if child.is_dir():
                        _add_dir(child, "parent_dir")
                        ext4 = child / "ext4.vhdx"
                        _add_file(ext4, "wsl_distro")
            except Exception:
                pass

    return dirs, files


def _scan_docker_logs_for_wsl_errors(local_appdata: Path) -> List[str]:
    """Reads bounded tails of Docker host logs looking for known wsl-bootstrap / VHDX failures."""
    signals: List[str] = []
    log_dir = local_appdata / "Docker" / "log" / "host"
    if not log_dir.is_dir():
        return signals

    patterns = (
        ("vhdx_ext4_io_error", re.compile(r"mounting disk:\s*input/output error", re.IGNORECASE)),
        ("wsl_bootstrap_exec_error", re.compile(r"wsl-bootstrap.*exit status 1|DockerDesktop/Wsl/ExecError", re.IGNORECASE)),
        ("wsl_unmount_invalid_arg", re.compile(r"unprovisioning data:\s*unmounting disk:\s*invalid argument", re.IGNORECASE)),
        ("wsl_create_instance_fail", re.compile(r"Wsl/Service/CreateInstance/E_FAIL", re.IGNORECASE)),
    )
    seen = set()
    for name in ("monitor.log", "com.docker.backend.exe.log"):
        p = log_dir / name
        if not p.is_file():
            continue
        try:
            raw = p.read_bytes()
            tail_txt = raw[-262144:].decode("utf-8", errors="replace")
            for tag, rx in patterns:
                if tag not in seen and rx.search(tail_txt):
                    seen.add(tag)
                    signals.append(tag)
        except Exception:
            continue
    return signals


def diagnose_docker_wsl(
    *,
    local_appdata: Optional[Union[str, Path]] = None,
    roaming_appdata: Optional[Union[str, Path]] = None,
    include_all_wsl: bool = True,
    probe_timeout: float = DOCKER_PROBE_TIMEOUT_SEC,
    compression_checker: Callable[[Union[str, Path]], bool] = is_ntfs_compressed,
    run_cmd: Callable[..., subprocess.CompletedProcess] = _default_run_cmd,
    platform_override: Optional[str] = None,
) -> DockerWSLDiagnosis:
    """Performs a strictly read-only diagnosis of Docker Desktop and WSL2 VHDX health."""
    plat = platform_override or sys.platform
    local_p = Path(local_appdata) if local_appdata else (
        Path(os.environ["LOCALAPPDATA"]) if os.environ.get("LOCALAPPDATA") else Path.home()
    )
    roaming_p = Path(roaming_appdata) if roaming_appdata else (
        Path(os.environ["APPDATA"]) if os.environ.get("APPDATA") else None
    )

    docker_bin = find_docker_binary(local_p)
    dd_exe = find_docker_desktop_exe(local_p) if plat.startswith("win") else None
    daemon_up, server_ver = probe_docker_daemon(docker_bin, timeout=probe_timeout, run_cmd=run_cmd)

    diag = DockerWSLDiagnosis(
        platform=plat,
        docker_binary=docker_bin,
        docker_desktop_exe=dd_exe,
        daemon_running=daemon_up,
        server_version=server_ver,
    )

    if plat.startswith("win"):
        dirs, files = _discover_vhdx_and_dirs(local_p, roaming_p, include_all_wsl=include_all_wsl)
        for d, role in dirs:
            comp = bool(compression_checker(d))
            try:
                free_b = shutil.disk_usage(str(d)).free
            except Exception:
                free_b = 0
            rec = VhdxInspectRecord(
                path=str(d),
                kind="dir",
                size_bytes=0,
                compressed=comp,
                free_bytes_on_volume=free_b,
                role=role,
            )
            if comp:
                diag.compressed_dirs.append(rec)

        for f, role in files:
            comp = bool(compression_checker(f))
            try:
                sz = f.stat().st_size
                free_b = shutil.disk_usage(str(f.parent)).free
            except Exception:
                sz, free_b = 0, 0
            rec = VhdxInspectRecord(
                path=str(f),
                kind="file",
                size_bytes=sz,
                compressed=comp,
                free_bytes_on_volume=free_b,
                role=role,
            )
            diag.vhdx_inventory.append(rec)
            if comp:
                diag.compressed_vhdxs.append(rec)

        diag.log_signals = _scan_docker_logs_for_wsl_errors(local_p)

    # Synthesize actionable findings
    if not docker_bin and not dd_exe:
        diag.issues.append("docker_not_installed")
        diag.recommended_actions.append("Install Docker Desktop (or Colima/Docker Engine) to enable container isolation engines.")
    elif not daemon_up:
        diag.issues.append("docker_daemon_not_running")
        if diag.compressed_vhdxs or diag.compressed_dirs:
            diag.issues.append("ntfs_compressed_vhdx_detected")
            diag.recommended_actions.append(
                "Run `rfc_hunt_swarm.py docker-doctor --fix` to remove NTFS compression from WSL/Docker directories "
                "and safely copy compressed `.vhdx` disks to uncompressed files (preserving `.compressed_bak` backups)."
            )
        if "vhdx_ext4_io_error" in diag.log_signals:
            diag.issues.append("vhdx_ext4_mount_io_error")
        if "wsl_bootstrap_exec_error" in diag.log_signals:
            diag.issues.append("wsl_bootstrap_failed")
            diag.recommended_actions.append(
                "If decompression alone does not recover bootstrap, unregister ONLY the stateless `docker-desktop` "
                "system distro (`wsl --unregister docker-desktop`) and relaunch Docker Desktop."
            )
        if not diag.compressed_vhdxs and dd_exe:
            diag.recommended_actions.append(f"Launch Docker Desktop (`{dd_exe}`) and wait for `docker version` to report Server.Version.")
    else:
        if diag.compressed_vhdxs or diag.compressed_dirs:
            diag.issues.append("ntfs_compressed_vhdx_at_risk")
            extra_flag = " --include-all-wsl" if any(r.role == "wsl_distro" for r in diag.compressed_vhdxs) else ""
            diag.recommended_actions.append(
                "Docker is running, but NTFS compression is still set on WSL/Docker VHDX path(s) — "
                f"run `rfc_hunt_swarm.py docker-doctor --fix{extra_flag}` to prevent future Event ID 141 I/O corruption."
            )

    diag.healthy = bool(daemon_up and not diag.compressed_vhdxs)
    return diag


def _copy_ntfs_acl(
    src: Path,
    dst: Path,
    *,
    run_cmd: Callable[..., subprocess.CompletedProcess] = _default_run_cmd,
) -> Tuple[bool, str]:
    """Copies exact Windows NTFS ACL (including Hyper-V VM SIDs) from `src` to `dst`."""
    if os.name != "nt":
        return True, "non_windows_noop"
    ps_script = (
        "$s = $env:RFCHUNT_ACL_SRC; $d = $env:RFCHUNT_ACL_DST; "
        "$acl = Get-Acl -LiteralPath $s; Set-Acl -LiteralPath $d -AclObject $acl"
    )
    env = dict(os.environ)
    env["RFCHUNT_ACL_SRC"] = str(src)
    env["RFCHUNT_ACL_DST"] = str(dst)
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30.0,
            env=env,
            shell=False,
            creationflags=_creationflags(),
            check=False,
        )
        if proc.returncode == 0:
            return True, "acl_copied"
        return False, (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()[:200]
    except Exception as exc:
        return False, str(exc)


def stream_copy_to_uncompressed_vhdx(
    vhdx_path: Union[str, Path],
    *,
    chunk_bytes: int = STREAM_COPY_CHUNK_BYTES,
    compression_checker: Callable[[Union[str, Path]], bool] = is_ntfs_compressed,
    acl_copier: Callable[[Path, Path], Tuple[bool, str]] = _copy_ntfs_acl,
    min_free_ratio: float = MIN_FREE_SPACE_SAFETY_RATIO,
) -> Tuple[bool, str, Optional[str]]:
    """
    Safely replaces an NTFS-compressed `.vhdx` that hit `STATUS_FILE_SYSTEM_LIMITATION`
    by streaming a byte-exact copy into a newly created uncompressed file inside the
    already-uncompressed parent directory, copying ACLs, and renaming the original to
    `<name>.compressed_bak`. Never deletes the original user data!
    """
    src = Path(vhdx_path)
    if not src.is_file():
        return False, f"VHDX not found: {src}", None

    total_size = src.stat().st_size
    try:
        free_bytes = shutil.disk_usage(str(src.parent)).free
    except Exception:
        free_bytes = 0

    required_bytes = int(total_size * min_free_ratio)
    if free_bytes < required_bytes:
        return (
            False,
            (
                f"Insufficient free space to safely copy {src.name}: "
                f"need {required_bytes / 1e9:.1f} GB, only {free_bytes / 1e9:.1f} GB free"
            ),
            None,
        )

    tmp_path = src.with_name(src.name + ".uncompressed")
    bak_path = src.with_name(src.name + ".compressed_bak")
    if tmp_path.exists():
        tmp_path.unlink()

    copied = 0
    try:
        with open(src, "rb") as f_in, open(tmp_path, "wb") as f_out:
            while True:
                buf = f_in.read(chunk_bytes)
                if not buf:
                    break
                f_out.write(buf)
                copied += len(buf)
        if copied != total_size:
            tmp_path.unlink(missing_ok=True)
            return False, f"Copied byte mismatch for {src.name}: {copied} != {total_size}", None
        if compression_checker(tmp_path):
            tmp_path.unlink(missing_ok=True)
            return False, f"Parent directory of {src.name} is still NTFS-compressed; aborting swap", None

        acl_ok, acl_msg = acl_copier(src, tmp_path)
        if not acl_ok:
            tmp_path.unlink(missing_ok=True)
            return False, f"Failed to copy NTFS ACL onto {tmp_path.name}: {acl_msg}", None

        if bak_path.exists():
            ts = int(time.time())
            bak_path = src.with_name(f"{src.name}.compressed_bak_{ts}")
        src.rename(bak_path)
        try:
            tmp_path.rename(src)
        except Exception as swap_exc:
            # Roll back original file if final rename fails
            if not src.exists() and bak_path.exists():
                bak_path.rename(src)
            return False, f"Atomic swap failed (rolled back): {swap_exc}", None
        return True, f"Uncompressed copy swapped cleanly ({copied:,} bytes)", str(bak_path)
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        return False, f"Streaming uncompressed copy failed: {exc}", None


def repair_docker_wsl(
    *,
    local_appdata: Optional[Union[str, Path]] = None,
    roaming_appdata: Optional[Union[str, Path]] = None,
    include_all_wsl: bool = False,
    reset_stateless_distro: bool = False,
    launch_docker: bool = True,
    wait_timeout_sec: float = 60.0,
    approval_mode: str = "policy",
    allow_in_tests: bool = False,
    compression_checker: Callable[[Union[str, Path]], bool] = is_ntfs_compressed,
    run_cmd: Callable[..., subprocess.CompletedProcess] = _default_run_cmd,
    acl_copier: Callable[[Path, Path], Tuple[bool, str]] = _copy_ntfs_acl,
    platform_override: Optional[str] = None,
) -> DockerWSLRepairReport:
    """
    Performs safe, non-destructive Windows Docker Desktop & WSL2 auto-repair:
      1. Stops Docker processes and shuts down WSL when VHDX/distro repair is needed.
      2. Removes NTFS compression from Docker/WSL directories and VHDX files (`compact /u`
         with verified streaming uncompressed copy fallback on `STATUS_FILE_SYSTEM_LIMITATION`).
      3. Optionally resets ONLY stateless `docker-desktop` distro (preserving `docker_data.vhdx`).
      4. Relaunches Docker Desktop detached and verifies live `Server.Version`.
    """
    t0 = time.perf_counter()
    plat = platform_override or sys.platform
    if not plat.startswith("win"):
        return DockerWSLRepairReport(status="skipped_non_windows", elapsed_sec=time.perf_counter() - t0)

    guarded, reason = is_guard_active(approval_mode=approval_mode, allow_in_tests=allow_in_tests)
    if guarded:
        return DockerWSLRepairReport(
            status="skipped_guard",
            actions_taken=[f"Skipped host Docker/WSL repair under safety guard ({reason})"],
            elapsed_sec=time.perf_counter() - t0,
        )

    before = diagnose_docker_wsl(
        local_appdata=local_appdata,
        roaming_appdata=roaming_appdata,
        include_all_wsl=include_all_wsl,
        compression_checker=compression_checker,
        run_cmd=run_cmd,
        platform_override=plat,
    )
    if before.healthy:
        return DockerWSLRepairReport(
            status="healthy",
            actions_taken=["Docker Desktop Engine is already healthy and VHDX disks are uncompressed."],
            before=before,
            after=before,
            elapsed_sec=time.perf_counter() - t0,
        )

    if not before.docker_binary and not before.docker_desktop_exe:
        return DockerWSLRepairReport(
            status="not_installed",
            errors=["Docker Desktop is not installed on this host."],
            before=before,
            after=before,
            elapsed_sec=time.perf_counter() - t0,
        )

    actions: List[str] = []
    backups: List[str] = []
    errors: List[str] = []

    needs_wsl_stop = bool(before.compressed_dirs or before.compressed_vhdxs or reset_stateless_distro)
    if needs_wsl_stop:
        for proc_name in _DOCKER_STOP_PROCESS_NAMES:
            try:
                run_cmd(["taskkill", "/F", "/IM", proc_name], timeout=10.0)
            except Exception:
                pass
        actions.append("Stopped Docker Desktop host processes cleanly.")
        try:
            run_cmd(["wsl", "--shutdown"], timeout=30.0)
            actions.append("Executed `wsl --shutdown` to release VHDX file handles.")
        except Exception as exc:
            errors.append(f"wsl --shutdown failed: {exc}")

    # Remove NTFS compression from parent directories first
    for drec in before.compressed_dirs:
        try:
            res = run_cmd(["compact", "/u", drec.path], timeout=30.0)
            if res.returncode == 0:
                actions.append(f"Removed NTFS compression from directory: {drec.path}")
            else:
                errors.append(f"compact /u failed on directory {drec.path}: {(res.stderr or res.stdout).strip()[:160]}")
        except Exception as exc:
            errors.append(f"compact /u error on {drec.path}: {exc}")

    # Decompress VHDX files (compact /u first, streaming copy fallback on STATUS_FILE_SYSTEM_LIMITATION)
    for frec in before.compressed_vhdxs:
        try:
            res = run_cmd(["compact", "/u", frec.path], timeout=300.0)
            if res.returncode == 0 and not compression_checker(frec.path):
                actions.append(f"Decompressed VHDX in-place via compact /u: {frec.path}")
                continue
        except Exception as exc:
            actions.append(f"compact /u failed on {frec.path} ({exc}); falling back to streaming uncompressed copy.")

        ok_copy, msg, bak_path = stream_copy_to_uncompressed_vhdx(
            frec.path,
            compression_checker=compression_checker,
            acl_copier=acl_copier,
        )
        if ok_copy:
            actions.append(f"{frec.path}: {msg}")
            if bak_path:
                backups.append(bak_path)
        else:
            errors.append(f"{frec.path}: {msg}")

    # Optional stateless `docker-desktop` distro reset (NEVER touches docker_data.vhdx)
    if reset_stateless_distro:
        try:
            res = run_cmd(["wsl", "--unregister", "docker-desktop"], timeout=60.0)
            if res.returncode == 0:
                actions.append("Unregistered stateless `docker-desktop` runtime distro (data disk preserved).")
            else:
                errors.append(f"wsl --unregister docker-desktop failed: {(res.stderr or res.stdout).strip()[:160]}")
        except Exception as exc:
            errors.append(f"wsl --unregister docker-desktop error: {exc}")

    # Relaunch Docker Desktop detached so parent job cleanup does not terminate it
    if launch_docker and before.docker_desktop_exe:
        try:
            if os.name == "nt" and not allow_in_tests:
                subprocess.Popen(
                    ["explorer.exe", before.docker_desktop_exe],
                    shell=False,
                    creationflags=_creationflags(),
                )
            else:
                run_cmd(["explorer.exe", before.docker_desktop_exe], timeout=10.0)
            actions.append(f"Launched Docker Desktop detached: {before.docker_desktop_exe}")
        except Exception as exc:
            errors.append(f"Failed to launch Docker Desktop: {exc}")

        deadline = time.monotonic() + max(0.0, float(wait_timeout_sec))
        while time.monotonic() < deadline:
            up, ver = probe_docker_daemon(before.docker_binary, timeout=DOCKER_PROBE_TIMEOUT_SEC, run_cmd=run_cmd)
            if up and ver:
                actions.append(f"Docker Engine Server verified ready (version {ver}).")
                break
            time.sleep(min(3.0, max(0.1, deadline - time.monotonic())))

    after = diagnose_docker_wsl(
        local_appdata=local_appdata,
        roaming_appdata=roaming_appdata,
        include_all_wsl=include_all_wsl,
        compression_checker=compression_checker,
        run_cmd=run_cmd,
        platform_override=plat,
    )
    final_status = "repaired" if after.healthy else "partial_or_failed"
    return DockerWSLRepairReport(
        status=final_status,
        actions_taken=actions,
        backups_created=backups,
        errors=errors,
        before=before,
        after=after,
        elapsed_sec=time.perf_counter() - t0,
    )
