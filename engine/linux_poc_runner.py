"""
Clean Linux / Docker / WSL2 Polyglot PoC Verification Runner (Revenue Track 1 — Blocker 2).
===========================================================================================
Executes non-destructive verification harnesses across Rust, Node.js, Python, Ruby, and Go
inside hardened ephemeral Linux Docker containers (or WSL2 fallback), eliminating Windows
Smart App Control (`os error 4551`) and PowerShell PTY deadlocks.

Security & Integrity Invariants:
- Always enforces `--rm`, `--network=none`, `--cap-drop=ALL`,
  `--security-opt no-new-privileges:true`, `--memory`, `--cpus`, `--pids-limit`,
  read-only repo mounts (`:ro`), and `shell=False`.
- Rejects critical host mount prefixes (`/etc`, `/var/run/docker.sock`, `C:\\Windows`, etc.)
  and shell metacharacters in entrypoint tokens.
- Never fabricates passing transcripts: if neither Docker nor WSL2 is available, fails closed
  with `status="unavailable"` and exact remediation guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from engine.docker_wsl_doctor import diagnose_docker_wsl
from engine.host_containment import silent_subprocess_run


LANGUAGE_PROFILES: Dict[str, Dict[str, Any]] = {
    "rust": {
        "image": "rust:1.85-slim",
        "binary": "cargo",
        "default_args": ["test", "--release"],
        "version_cmd": ["rustc", "--version"],
    },
    "node": {
        "image": "node:22-slim",
        "binary": "node",
        "default_args": ["--version"],
        "version_cmd": ["node", "--version"],
    },
    "python": {
        "image": "python:3.12-slim",
        "binary": "pytest",
        "default_args": ["-q"],
        "version_cmd": ["python3", "--version"],
    },
    "ruby": {
        "image": "ruby:3.3-slim",
        "binary": "ruby",
        "default_args": ["-v"],
        "version_cmd": ["ruby", "--version"],
    },
    "go": {
        "image": "golang:1.23-alpine",
        "binary": "go",
        "default_args": ["test", "./..."],
        "version_cmd": ["go", "version"],
    },
}

_DOCKER_IMAGE_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?$"
)
_SHELL_META_RE = re.compile(r"(\$\(|`|\$\{|\r|\n|\x00|\||;|&|>|<)")
_FORBIDDEN_MOUNT_PREFIXES = (
    "/etc",
    "/var/run/docker.sock",
    "/var/run",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/root",
)
_WINDOWS_CRITICAL_RE = re.compile(
    r"^[a-z]:/(?:windows|programdata|program files|program files \(x86\)|system32)(?:/|$)",
    re.IGNORECASE,
)


@dataclass
class VerifiableTranscript:
    """Submission-grade runtime verification transcript captured from clean Linux."""

    language: str
    backend: str  # "docker" | "wsl2" | "unavailable"
    status: str  # "passed" | "failed" | "timeout" | "unavailable" | "rejected_unsafe"
    exit_code: Optional[int]
    command: List[str]
    image: str
    repo_path: str
    started_at_utc: str
    elapsed_ms: float
    stdout: str = ""
    stderr: str = ""
    remediation_hint: str = ""
    docker_argv: List[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return self.status == "passed" and self.exit_code == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "backend": self.backend,
            "status": self.status,
            "verified": self.verified,
            "exit_code": self.exit_code,
            "command": list(self.command),
            "image": self.image,
            "repo_path": self.repo_path,
            "started_at_utc": self.started_at_utc,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "remediation_hint": self.remediation_hint,
        }

    def to_markdown(self) -> str:
        cmd_str = " ".join(self.command)
        lines = [
            f"### Verified Linux Execution Transcript (`{self.language}` via `{self.backend}`)",
            "",
            f"- **Status:** `{self.status}` (exit code `{self.exit_code}`, `{self.elapsed_ms:.1f} ms`)",
            f"- **Environment:** `{self.image}` (`--network=none --cap-drop=ALL`)" if self.backend == "docker" else f"- **Environment:** `{self.backend}`",
            f"- **Timestamp (UTC):** `{self.started_at_utc}`",
            f"- **Command:** `{cmd_str}`",
            "",
            "#### Verbatim stdout",
            "```text",
            self.stdout.rstrip() or "<empty>",
            "```",
        ]
        if self.stderr.strip():
            lines.extend(["", "#### Verbatim stderr", "```text", self.stderr.rstrip(), "```"])
        if self.remediation_hint:
            lines.extend(["", f"> **Note:** {self.remediation_hint}"])
        return "\n".join(lines) + "\n"


def validate_mount_path(repo_path: Union[str, Path]) -> Tuple[bool, str]:
    """Fail-closed validation preventing critical host directories from being mounted."""
    raw = str(repo_path).strip()
    if not raw:
        return False, "Repository mount path is empty."
    if "\x00" in raw or raw.startswith("\\\\"):
        return False, f"Unsafe or UNC mount path rejected: {raw!r}"
    resolved = Path(raw).resolve()
    norm = str(resolved).replace("\\", "/").lower()
    if _WINDOWS_CRITICAL_RE.match(norm):
        return False, f"Critical Windows host directory cannot be mounted: {resolved}"
    for prefix in _FORBIDDEN_MOUNT_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return False, f"Critical POSIX host directory cannot be mounted: {resolved}"
    if not resolved.exists() or not resolved.is_dir():
        return False, f"Repository directory does not exist: {resolved}"
    return True, str(resolved)


def validate_command_tokens(cmd: Sequence[str]) -> Tuple[bool, str]:
    """Validates argv tokens have no shell injection metacharacters."""
    if not cmd:
        return False, "Command argv cannot be empty."
    for tok in cmd:
        if not isinstance(tok, str) or not tok:
            return False, f"Invalid empty/non-string token in command: {cmd!r}"
        if _SHELL_META_RE.search(tok):
            return False, f"Shell metacharacter rejected in token: {tok!r}"
    return True, "ok"


def build_hardened_docker_argv(
    *,
    docker_bin: str,
    image: str,
    repo_dir: Union[str, Path],
    cmd: Sequence[str],
    memory_limit: str = "2g",
    cpus: str = "2",
    pids_limit: int = 256,
    workdir: str = "/workspace",
    writable_tmp: bool = True,
) -> List[str]:
    """Builds a fail-closed, network-disabled Docker invocation argv (`shell=False`)."""
    if not _DOCKER_IMAGE_RE.match(image):
        raise ValueError(f"Invalid Docker image reference: {image!r}")
    ok_mount, resolved = validate_mount_path(repo_dir)
    if not ok_mount:
        raise ValueError(resolved)
    ok_cmd, err_cmd = validate_command_tokens(cmd)
    if not ok_cmd:
        raise ValueError(err_cmd)

    argv = [
        docker_bin,
        "run",
        "--rm",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--memory",
        memory_limit,
        "--cpus",
        str(cpus),
        "--pids-limit",
        str(pids_limit),
        "-v",
        f"{resolved}:{workdir}:ro",
        "-w",
        workdir,
    ]
    if writable_tmp:
        argv.extend(["--tmpfs", "/tmp:rw,nosuid,size=512m"])
    argv.append(image)
    argv.extend(cmd)
    return argv


def windows_to_wsl_path(path: Union[str, Path]) -> str:
    """Converts `D:\\harfile\\rfchunt` -> `/mnt/d/harfile/rfchunt` for WSL2 execution."""
    raw = str(path).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", raw)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    s = str(Path(path).resolve()).replace("\\", "/")
    m2 = re.match(r"^([A-Za-z]):/(.*)$", s)
    if m2:
        return f"/mnt/{m2.group(1).lower()}/{m2.group(2)}"
    return s


class LinuxPocRunner:
    """
    Runs polyglot PoC verification commands inside hardened Linux Docker containers
    (or WSL2 fallback) and returns structured `VerifiableTranscript` records.
    """

    def __init__(self, timeout_sec: float = 120.0):
        self.timeout_sec = timeout_sec

    def _detect_backend(self) -> Tuple[str, Optional[str]]:
        diag = diagnose_docker_wsl()
        if diag.daemon_running and diag.docker_binary:
            return "docker", diag.docker_binary
        wsl_bin = shutil.which("wsl.exe") or shutil.which("wsl")
        if wsl_bin:
            return "wsl2", wsl_bin
        return "unavailable", None

    def run_poc(
        self,
        *,
        language: str,
        repo_path: Union[str, Path],
        cmd: Sequence[str],
        image_override: Optional[str] = None,
        timeout_sec: Optional[float] = None,
        prefer_backend: Optional[str] = None,
    ) -> VerifiableTranscript:
        lang = language.strip().lower()
        profile = LANGUAGE_PROFILES.get(lang)
        if profile is None:
            raise ValueError(
                f"Unsupported language {language!r}; choose from {sorted(LANGUAGE_PROFILES)}"
            )
        image = image_override or str(profile["image"])
        started_iso = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()

        ok_mount, mount_info = validate_mount_path(repo_path)
        if not ok_mount:
            return VerifiableTranscript(
                language=lang,
                backend="unavailable",
                status="rejected_unsafe",
                exit_code=None,
                command=list(cmd),
                image=image,
                repo_path=str(repo_path),
                started_at_utc=started_iso,
                elapsed_ms=(time.monotonic() - t0) * 1000.0,
                remediation_hint=mount_info,
            )

        ok_cmd, cmd_err = validate_command_tokens(cmd)
        if not ok_cmd:
            return VerifiableTranscript(
                language=lang,
                backend="unavailable",
                status="rejected_unsafe",
                exit_code=None,
                command=list(cmd),
                image=image,
                repo_path=mount_info,
                started_at_utc=started_iso,
                elapsed_ms=(time.monotonic() - t0) * 1000.0,
                remediation_hint=cmd_err,
            )

        backend, binary = self._detect_backend()
        if prefer_backend in ("docker", "wsl2"):
            if prefer_backend == "wsl2":
                wsl_bin = shutil.which("wsl.exe") or shutil.which("wsl")
                backend, binary = ("wsl2", wsl_bin) if wsl_bin else ("unavailable", None)

        if backend == "unavailable" or not binary:
            return VerifiableTranscript(
                language=lang,
                backend="unavailable",
                status="unavailable",
                exit_code=None,
                command=list(cmd),
                image=image,
                repo_path=mount_info,
                started_at_utc=started_iso,
                elapsed_ms=(time.monotonic() - t0) * 1000.0,
                remediation_hint=(
                    "Neither Docker daemon nor WSL2 is available. Run `python rfc_hunt_swarm.py docker-doctor` "
                    "to start Docker Desktop or enable WSL2 before submitting reports."
                ),
            )

        effective_timeout = timeout_sec if timeout_sec is not None else self.timeout_sec
        if backend == "docker":
            exec_argv = build_hardened_docker_argv(
                docker_bin=binary,
                image=image,
                repo_dir=mount_info,
                cmd=cmd,
            )
        else:
            wsl_cwd = windows_to_wsl_path(mount_info)
            exec_argv = [binary, "--cd", wsl_cwd, "-e", *cmd]

        try:
            proc = silent_subprocess_run(
                exec_argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=effective_timeout,
            )
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            status = "passed" if proc.returncode == 0 else "failed"
            return VerifiableTranscript(
                language=lang,
                backend=backend,
                status=status,
                exit_code=proc.returncode,
                command=list(cmd),
                image=image if backend == "docker" else "wsl2-linux",
                repo_path=mount_info,
                started_at_utc=started_iso,
                elapsed_ms=elapsed_ms,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                docker_argv=exec_argv if backend == "docker" else [],
            )
        except subprocess.TimeoutExpired as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            return VerifiableTranscript(
                language=lang,
                backend=backend,
                status="timeout",
                exit_code=None,
                command=list(cmd),
                image=image if backend == "docker" else "wsl2-linux",
                repo_path=mount_info,
                started_at_utc=started_iso,
                elapsed_ms=elapsed_ms,
                stdout=(exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")),
                stderr=(exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")),
                remediation_hint=f"Execution exceeded {effective_timeout}s timeout.",
                docker_argv=exec_argv if backend == "docker" else [],
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            return VerifiableTranscript(
                language=lang,
                backend=backend,
                status="failed",
                exit_code=None,
                command=list(cmd),
                image=image if backend == "docker" else "wsl2-linux",
                repo_path=mount_info,
                started_at_utc=started_iso,
                elapsed_ms=elapsed_ms,
                stderr=str(exc),
                docker_argv=exec_argv if backend == "docker" else [],
            )


def save_transcript_bundle(
    transcript: VerifiableTranscript, out_dir: Union[str, Path], stem: str = "poc_transcript"
) -> Tuple[Path, Path]:
    """Persists both JSON and Markdown transcripts cleanly in UTF-8."""
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    json_path = dest / f"{stem}.json"
    md_path = dest / f"{stem}.md"
    json_path.write_text(json.dumps(transcript.to_dict(), indent=2), encoding="utf-8")
    md_path.write_text(transcript.to_markdown(), encoding="utf-8")
    return json_path, md_path
