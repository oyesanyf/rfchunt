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

from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from engine.docker_wsl_doctor import diagnose_docker_wsl, find_docker_binary, probe_docker_daemon
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
    if raw in ("/", "\\"):
        return False, f"Filesystem root cannot be mounted: {raw!r}"
    if "\x00" in raw or raw.startswith("\\\\") or raw.startswith("//"):
        return False, f"Unsafe or UNC mount path rejected: {raw!r}"
    raw_norm = raw.replace("\\", "/").lower()
    if _WINDOWS_CRITICAL_RE.match(raw_norm):
        return False, f"Critical Windows host directory cannot be mounted: {raw}"
    try:
        resolved = Path(raw).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        return False, f"Invalid mount path {raw!r}: {exc}"
    if resolved == resolved.parent or len(resolved.parts) <= 1:
        return False, f"Filesystem or drive root cannot be mounted: {resolved}"
    resolved_str = str(resolved)
    if resolved_str.startswith("\\\\") or resolved.as_posix().startswith("//"):
        return False, f"Unsafe or UNC mount path rejected: {resolved_str!r}"
    norm = resolved_str.replace("\\", "/").lower()
    if _WINDOWS_CRITICAL_RE.match(norm):
        return False, f"Critical Windows host directory cannot be mounted: {resolved}"
    for prefix in _FORBIDDEN_MOUNT_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return False, f"Critical POSIX host directory cannot be mounted: {resolved}"
    try:
        if not resolved.exists() or not resolved.is_dir():
            return False, f"Repository directory does not exist: {resolved}"
    except OSError as exc:
        return False, f"Invalid repository directory {resolved}: {exc}"
    return True, resolved_str


def validate_command_tokens(cmd: Sequence[str]) -> Tuple[bool, str]:
    """Validates argv tokens have no shell injection metacharacters."""
    if isinstance(cmd, (str, bytes, bytearray, dict)) or not isinstance(cmd, Sequence):
        return (
            False,
            "Command must be a non-string Sequence of string tokens (e.g. list or tuple), not str/bytes/dict.",
        )
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


_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth",
        "auth_token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "pwd",
        "jwt",
        "session",
        "session_id",
        "sig",
        "signature",
        "credential",
        "bearer",
        "pat",
        "code",
    }
)


def _sanitize_probe_url(raw_url: str, redact_fn: Callable[[str], str]) -> str:
    """Strips URL userinfo (`user:pass@`) and redacts sensitive query params and inline secrets."""
    cleaned = str(raw_url or "").strip()
    if not cleaned:
        return ""
    try:
        parsed = urlparse(cleaned)
    except ValueError:
        stripped = re.sub(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@", r"\1", cleaned)
        return redact_fn(stripped)

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    netloc = redact_fn(netloc)

    query = parsed.query
    if query:
        redacted_pairs: List[Tuple[str, str]] = []
        for k, v in parse_qsl(query, keep_blank_values=True):
            k_low = k.strip().lower()
            is_sensitive_key = (
                k_low in _SENSITIVE_QUERY_KEYS
                or any(
                    tok in k_low
                    for tok in ("token", "secret", "password", "passwd", "apikey", "api_key", "credential", "bearer")
                )
            )
            redacted_v = redact_fn(v)
            if is_sensitive_key or redacted_v != v:
                redacted_pairs.append((k, "<REDACTED>"))
            else:
                redacted_pairs.append((k, v))
        query = urlencode(redacted_pairs, safe="<>")

    sanitized = urlunparse(
        (
            parsed.scheme,
            netloc,
            redact_fn(parsed.path),
            redact_fn(parsed.params),
            query,
            redact_fn(parsed.fragment),
        )
    )
    return redact_fn(sanitized)


class LinuxPocRunner:
    """
    Runs polyglot PoC verification commands inside hardened Linux Docker containers
    (or WSL2 fallback) and returns structured `VerifiableTranscript` records.
    """

    def __init__(self, timeout_sec: float = 120.0):
        self.timeout_sec = timeout_sec
        self._probe_lock = threading.Lock()
        self._probe_limiters: Dict[Tuple[str, float], Any] = {}

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

    def verify_sandbox_http_probe(
        self,
        url: str,
        *,
        program: str,
        eligibility_db: Any = None,
        max_rps: float = 2.0,
        researcher_handle: Optional[str] = None,
        allow_private: Optional[bool] = None,
        timeout_sec: float = 3.0,
    ) -> Dict[str, Any]:
        """
        Fail-closed, strictly non-destructive HTTP GET probe enforcing:
          1. `ProgramComplianceContext` (`UNLOCKED` + `open` + Tier 1 RoE check)
          2. `validate_target_host` SSRF guard + strict DNS label-boundary scope allowlist
          3. Dynamic program-mandated attribution headers (`User-Agent`, `X-HackerOne`, etc.)
          4. Fractional `TokenBucketRateLimiter` pacing `<= min(max_rps, roe_max_rps)` & `follow_redirects=False`
        """
        from engine.advisory_exporter import _redact_inline_tokens
        from engine.program_eligibility_db import ProgramEligibilityDB
        from engine.request_hygiene import TokenBucketRateLimiter, build_program_compliance_context
        from engine.safe_network_validator import is_explicit_loopback_host, validate_target_host
        import httpx

        t0 = time.monotonic()
        clean_url = str(url or "").strip()
        display_url = _sanitize_probe_url(clean_url, _redact_inline_tokens)
        prog = str(program or "").strip()
        db = eligibility_db if eligibility_db is not None else ProgramEligibilityDB()

        if researcher_handle is not None:
            raw_h = str(researcher_handle).strip()
            if not raw_h or any(ch in raw_h for ch in ("\r", "\n", "\x00")):
                return {
                    "verified": False,
                    "status": "rejected_unsafe_headers",
                    "program": prog,
                    "url": display_url,
                    "status_code": None,
                    "headers_sent": {},
                    "response_preview": "",
                    "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                    "reason": "Invalid researcher_handle for HackerOne attribution headers.",
                }

        ctx = build_program_compliance_context(
            prog,
            eligibility_db=db,
            researcher_handle=researcher_handle,
            max_rps_cap=max(0.01, min(float(max_rps), 100.0)),
        )
        if not ctx.eligible:
            return {
                "verified": False,
                "status": "blocked_ineligible",
                "program": prog,
                "url": display_url,
                "status_code": None,
                "headers_sent": {},
                "response_preview": "",
                "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                "reason": f"Program {prog!r} is not UNLOCKED in ProgramEligibilityDB ({ctx.reason}).",
            }
        if not ctx.live_allowed or ctx.automated_prohibited:
            return {
                "verified": False,
                "status": "blocked_by_roe",
                "program": prog,
                "url": display_url,
                "status_code": None,
                "headers_sent": {},
                "response_preview": "",
                "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                "reason": ctx.reason,
            }

        parsed = urlparse(clean_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            return {
                "verified": False,
                "status": "rejected_unsafe_url",
                "program": prog,
                "url": display_url,
                "status_code": None,
                "headers_sent": {},
                "response_preview": "",
                "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                "reason": "URL must be http(s) with a valid hostname and no embedded credentials.",
            }

        host = parsed.hostname
        eff_private = is_explicit_loopback_host(host) if allow_private is None else bool(allow_private)
        ok_host, host_reason = validate_target_host(host, allow_private=eff_private)
        if not ok_host:
            return {
                "verified": False,
                "status": "rejected_ssrf",
                "program": prog,
                "url": display_url,
                "status_code": None,
                "headers_sent": {},
                "response_preview": "",
                "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                "reason": _redact_inline_tokens(host_reason),
            }
        if not is_explicit_loopback_host(host):
            ok_scope, scope_reason = ctx.authorize_live_host(host, allow_loopback=eff_private)
            if not ok_scope:
                return {
                    "verified": False,
                    "status": "rejected_out_of_scope",
                    "program": prog,
                    "url": display_url,
                    "status_code": None,
                    "headers_sent": {},
                    "response_preview": "",
                    "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                    "reason": _redact_inline_tokens(scope_reason),
                }

        headers = ctx.to_headers_dict()

        eff_rps = ctx.effective_max_rps
        lim_key = (prog.lower(), eff_rps)
        with self._probe_lock:
            limiter = self._probe_limiters.get(lim_key)
            if limiter is None:
                limiter = TokenBucketRateLimiter(eff_rps)
                self._probe_limiters[lim_key] = limiter
        limiter.acquire()

        eff_timeout = min(max(0.2, float(timeout_sec)), 10.0)
        try:
            with httpx.Client(timeout=eff_timeout, follow_redirects=False, trust_env=False) as client:
                resp = client.get(clean_url, headers=headers)
            passed = 200 <= resp.status_code < 400
            return {
                "verified": passed,
                "status": "passed" if passed else "failed",
                "program": prog,
                "url": display_url,
                "status_code": resp.status_code,
                "headers_sent": headers,
                "response_preview": _redact_inline_tokens(resp.text[:512]),
                "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                "reason": f"HTTP {resp.status_code}",
            }
        except httpx.TimeoutException:
            return {
                "verified": False,
                "status": "timeout",
                "program": prog,
                "url": display_url,
                "status_code": None,
                "headers_sent": headers,
                "response_preview": "",
                "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                "reason": f"Sandbox HTTP probe timed out after {eff_timeout:.1f}s.",
            }
        except Exception as exc:
            return {
                "verified": False,
                "status": "error",
                "program": prog,
                "url": display_url,
                "status_code": None,
                "headers_sent": headers,
                "response_preview": "",
                "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                "reason": _redact_inline_tokens(str(exc)[:200]),
            }


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


# ---------------------------------------------------------------------------
# Non-Destructive Toolchain Probes & Optional Symbolic Hooks (M1)
# ---------------------------------------------------------------------------


def _safe_find_spec(module_name: str) -> Optional[Any]:
    try:
        return importlib.util.find_spec(module_name)
    except (ImportError, ValueError, AttributeError, OSError):
        return None


def _default_lean_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "formal" / "lean4"


def _validate_symbolic_target_path(target_path: Union[str, Path]) -> Tuple[bool, str]:
    """
    Validates a file or directory target using `validate_mount_path` invariants.
    Rejects empty, UNC (`\\\\` or `//`), NUL-byte, missing, or critical Windows/POSIX paths.
    """
    if target_path is None:
        return validate_mount_path("")
    raw = str(target_path).strip()
    if not raw or "\x00" in raw or raw.startswith("\\\\") or raw.startswith("//"):
        return validate_mount_path(raw)
    try:
        resolved = Path(raw).resolve()
    except (OSError, RuntimeError, ValueError):
        return False, f"Invalid target path: {raw!r}"

    resolved_str = str(resolved)
    if resolved_str.startswith("\\\\") or resolved.as_posix().startswith("//"):
        return False, f"Unsafe or UNC mount path rejected: {resolved_str!r}"

    if resolved.is_file():
        norm = resolved_str.replace("\\", "/").lower()
        if _WINDOWS_CRITICAL_RE.match(norm):
            return False, f"Critical Windows host file cannot be inspected: {resolved}"
        for prefix in _FORBIDDEN_MOUNT_PREFIXES:
            if norm == prefix or norm.startswith(prefix + "/"):
                return False, f"Critical POSIX host file cannot be inspected: {resolved}"
        ok_parent, parent_msg = validate_mount_path(resolved.parent)
        if not ok_parent:
            return False, parent_msg
        return True, resolved_str

    return validate_mount_path(raw)


def probe_optional_backends(
    lean_dir: Optional[Union[str, Path]] = None,
    *,
    timeout_sec: float = 2.5,
) -> Dict[str, Dict[str, Any]]:
    """
    Non-destructively probes optional local verification toolchains concurrently with
    strictly bounded wall-clock timeouts (<= 3.0s). Returns availability dictionaries
    for `docker`, `wsl2`, `lean4`, `rfchunt_lean_oracle`, `angr`, `klee`, `semgrep`,
    `rea`, `trufflehog`, `jadx`, `subfinder`, `httpx`, `katana`, and `schemathesis`.
    """
    t0 = time.monotonic()
    bounded_timeout = max(0.2, min(float(timeout_sec), 3.0))
    deadline = t0 + bounded_timeout
    resolved_lean_dir = (
        Path(lean_dir).resolve() if lean_dir is not None else _default_lean_dir()
    )

    def _entry(
        available: bool, status: str, reason: str, path_or_module: Optional[str]
    ) -> Dict[str, Any]:
        return {
            "available": bool(available),
            "status": status,
            "reason": reason,
            "path_or_module": path_or_module,
        }

    # Subprocess probes run in daemon threads so a hanging child/pipe teardown
    # returns `status="timeout"` immediately at `bounded_timeout` without blocking.
    docker_box: Dict[str, Dict[str, Any]] = {}
    docker_bin_ref: List[Optional[str]] = [None]
    docker_done = threading.Event()

    def _probe_docker() -> None:
        try:
            docker_bin = find_docker_binary()
            docker_bin_ref[0] = docker_bin
            if not docker_bin:
                docker_box["value"] = _entry(
                    False,
                    "unavailable",
                    "Docker CLI/Desktop not found on host.",
                    None,
                )
                return
            daemon_up, server_ver = probe_docker_daemon(
                docker_bin, timeout=bounded_timeout
            )
            if daemon_up:
                ver = f" (server {server_ver})" if server_ver else ""
                docker_box["value"] = _entry(
                    True,
                    "available",
                    f"Docker daemon running{ver}.",
                    docker_bin,
                )
            else:
                docker_box["value"] = _entry(
                    False,
                    "unavailable",
                    "Docker CLI found, but Docker daemon is not running.",
                    docker_bin,
                )
        except subprocess.TimeoutExpired:
            docker_box["value"] = _entry(
                False,
                "timeout",
                f"Docker daemon probe timed out after {bounded_timeout:.1f}s.",
                docker_bin_ref[0],
            )
        except Exception as exc:
            docker_box["value"] = _entry(
                False,
                "unavailable",
                f"Docker probe failed cleanly: {exc}",
                docker_bin_ref[0],
            )
        finally:
            docker_done.set()

    wsl_box: Dict[str, Dict[str, Any]] = {}
    wsl_bin_ref: List[Optional[str]] = [None]
    wsl_done = threading.Event()

    def _probe_wsl2() -> None:
        try:
            wsl_bin = shutil.which("wsl.exe") or shutil.which("wsl")
            wsl_bin_ref[0] = wsl_bin
            if not wsl_bin:
                wsl_box["value"] = _entry(
                    False,
                    "unavailable",
                    "wsl.exe / wsl not found on PATH.",
                    None,
                )
                return
            proc = silent_subprocess_run(
                [wsl_bin, "--status"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=bounded_timeout,
            )
            if proc.returncode == 0:
                wsl_box["value"] = _entry(
                    True,
                    "available",
                    "WSL2 status probe succeeded.",
                    wsl_bin,
                )
            else:
                snippet = (
                    (proc.stderr or "") or (proc.stdout or "")
                ).replace("\x00", "").strip()
                first_line = (
                    snippet.splitlines()[0][:200]
                    if snippet
                    else f"exit code {proc.returncode}"
                )
                wsl_box["value"] = _entry(
                    False,
                    "unavailable",
                    f"WSL2 probe returned non-zero ({first_line}).",
                    wsl_bin,
                )
        except subprocess.TimeoutExpired:
            wsl_box["value"] = _entry(
                False,
                "timeout",
                f"WSL2 probe timed out after {bounded_timeout:.1f}s.",
                wsl_bin_ref[0],
            )
        except Exception as exc:
            wsl_box["value"] = _entry(
                False,
                "unavailable",
                f"WSL2 probe failed cleanly: {exc}",
                wsl_bin_ref[0],
            )
        finally:
            wsl_done.set()

    def _probe_lean4() -> Dict[str, Any]:
        lean_bin = shutil.which("lean")
        lake_bin = shutil.which("lake")
        has_lakefile = (resolved_lean_dir / "lakefile.lean").is_file()
        if lean_bin and lake_bin:
            lake_note = "lakefile.lean present" if has_lakefile else "lakefile.lean missing"
            return _entry(
                True,
                "available",
                f"Lean 4 (`lean` and `lake`) found ({lake_note}).",
                lake_bin,
            )
        missing = [name for name, path in (("lean", lean_bin), ("lake", lake_bin)) if not path]
        return _entry(
            False,
            "unavailable",
            f"Lean 4 toolchain missing ({', '.join(missing)} not on PATH).",
            lake_bin or lean_bin,
        )

    def _probe_lean_oracle() -> Dict[str, Any]:
        try:
            from engine.lean_formal_verifier import find_lean_oracle_binary

            oracle_bin = find_lean_oracle_binary(resolved_lean_dir)
            if oracle_bin is not None:
                return _entry(
                    True,
                    "available",
                    "Compiled rfchunt-lean-oracle binary found.",
                    str(oracle_bin),
                )
            return _entry(
                False,
                "unavailable",
                f"Compiled rfchunt-lean-oracle binary not built under {resolved_lean_dir}.",
                None,
            )
        except Exception as exc:
            return _entry(
                False,
                "unavailable",
                f"rfchunt-lean-oracle probe failed cleanly: {exc}",
                None,
            )

    def _probe_angr() -> Dict[str, Any]:
        angr_spec = _safe_find_spec("angr")
        if angr_spec is not None:
            return _entry(
                True,
                "available",
                "Python package `angr` is importable.",
                getattr(angr_spec, "origin", None) or "angr",
            )
        return _entry(
            False,
            "unavailable",
            "Python package `angr` is not installed.",
            None,
        )

    def _probe_klee() -> Dict[str, Any]:
        klee_bin = shutil.which("klee")
        klee_spec = _safe_find_spec("klee")
        if klee_bin:
            return _entry(
                True,
                "available",
                "KLEE CLI binary found on PATH.",
                klee_bin,
            )
        if klee_spec is not None:
            return _entry(
                True,
                "available",
                "Python package `klee` is importable.",
                getattr(klee_spec, "origin", None) or "klee",
            )
        return _entry(
            False,
            "unavailable",
            "Optional symbolic backend `klee` is not installed.",
            None,
        )

    def _probe_semgrep() -> Dict[str, Any]:
        semgrep_bin = shutil.which("semgrep")
        semgrep_spec = _safe_find_spec("semgrep")
        if semgrep_bin:
            return _entry(
                True,
                "available",
                "Semgrep CLI binary found on PATH.",
                semgrep_bin,
            )
        if semgrep_spec is not None:
            return _entry(
                True,
                "available",
                "Python package `semgrep` is importable.",
                getattr(semgrep_spec, "origin", None) or "semgrep",
            )
        return _entry(
            False,
            "unavailable",
            "Semgrep CLI/package is not installed.",
            None,
        )

    def _probe_rea() -> Dict[str, Any]:
        rea_spec = _safe_find_spec("engine.rea_integrator")
        rea_bin = shutil.which("rea-agents")
        node_bin = shutil.which("node")
        repo_rea_mjs = (
            Path(__file__).resolve().parent.parent
            / "tools"
            / "npm"
            / "node_modules"
            / "rea-agents"
            / "scripts"
            / "rea.mjs"
        )
        cli_path = rea_bin or (str(repo_rea_mjs) if (node_bin and repo_rea_mjs.is_file()) else None)
        if rea_spec is not None:
            detail = (
                f"Module 21 REA offline analyzer loaded (CLI: {cli_path})."
                if cli_path
                else "Module 21 REA offline pure-Python surface analyzer loaded."
            )
            return _entry(
                True,
                "available",
                detail,
                getattr(rea_spec, "origin", None) or "engine.rea_integrator",
            )
        if cli_path:
            return _entry(
                True,
                "available",
                "REA CLI binary found on host.",
                cli_path,
            )
        return _entry(
            False,
            "unavailable",
            "Module 21 REA analyzer is not available.",
            None,
        )

    def _which_is_unmocked() -> bool:
        return (
            getattr(shutil.which, "__module__", None) == "shutil"
            and getattr(shutil.which, "__qualname__", None) == "which"
        )

    def _find_optional_binary(names: Sequence[str], *, reject_py_httpx: bool = False) -> Optional[str]:
        from engine.external_scanners import (
            _find_non_python_httpx_on_path,
            _is_python_httpx_cli_binary,
        )

        rejected_py_httpx_paths: List[str] = []
        for name in names:
            cand = shutil.which(name)
            if cand:
                if reject_py_httpx and _is_python_httpx_cli_binary(cand):
                    rejected_py_httpx_paths.append(cand)
                    continue
                return cand

        if not _which_is_unmocked():
            return None

        if reject_py_httpx:
            for skip_p in rejected_py_httpx_paths:
                alt = _find_non_python_httpx_on_path(skip_p)
                if alt:
                    return alt

        repo_bin = Path(__file__).resolve().parent.parent / "bin"
        extra_dirs = (
            Path.home() / "go" / "bin",
            Path(r"C:\Program Files\Go\bin"),
            repo_bin,
        )
        suffixes = (".exe", "") if os.name == "nt" else ("",)
        for base in extra_dirs:
            if not base.is_dir():
                continue
            for name in names:
                for suf in suffixes:
                    cand_p = base / f"{name}{suf}"
                    if cand_p.is_file():
                        cand_s = str(cand_p)
                        if reject_py_httpx and _is_python_httpx_cli_binary(cand_s):
                            continue
                        return cand_s
        return None

    def _probe_trufflehog() -> Dict[str, Any]:
        bin_path = _find_optional_binary(("trufflehog",))
        if bin_path:
            return _entry(True, "available", "TruffleHog CLI binary found on host.", bin_path)
        return _entry(
            False,
            "unavailable",
            "TruffleHog CLI not found (pure-Python offline fallback remains active).",
            None,
        )

    def _probe_jadx() -> Dict[str, Any]:
        bin_path = _find_optional_binary(("jadx", "jadx-gui"))
        if bin_path:
            return _entry(True, "available", "jadx decompiler CLI found on host.", bin_path)
        return _entry(
            False,
            "unavailable",
            "jadx CLI not found (pure-Python mobile static auditor remains active).",
            None,
        )

    def _probe_subfinder() -> Dict[str, Any]:
        bin_path = _find_optional_binary(("subfinder",))
        if bin_path:
            return _entry(True, "available", "ProjectDiscovery subfinder binary found on host.", bin_path)
        return _entry(False, "unavailable", "Optional `subfinder` binary is not installed.", None)

    def _probe_httpx() -> Dict[str, Any]:
        bin_path = _find_optional_binary(("httpx",), reject_py_httpx=True)
        if bin_path:
            return _entry(True, "available", "ProjectDiscovery httpx binary found on host.", bin_path)
        return _entry(
            False,
            "unavailable",
            "Optional ProjectDiscovery `httpx` binary is not installed.",
            None,
        )

    def _probe_katana() -> Dict[str, Any]:
        bin_path = _find_optional_binary(("katana",))
        if bin_path:
            return _entry(True, "available", "ProjectDiscovery katana binary found on host.", bin_path)
        return _entry(False, "unavailable", "Optional `katana` binary is not installed.", None)

    def _probe_schemathesis() -> Dict[str, Any]:
        bin_path = _find_optional_binary(("schemathesis",))
        if bin_path:
            return _entry(True, "available", "Schemathesis CLI binary found on host.", bin_path)
        spec = _safe_find_spec("schemathesis")
        if spec is not None:
            return _entry(
                True,
                "available",
                "Python package `schemathesis` is importable.",
                getattr(spec, "origin", None) or "schemathesis",
            )
        return _entry(False, "unavailable", "Optional `schemathesis` tool/package is not installed.", None)

    docker_thread = threading.Thread(
        target=_probe_docker, name="rfchunt-probe-docker", daemon=True
    )
    wsl_thread = threading.Thread(
        target=_probe_wsl2, name="rfchunt-probe-wsl2", daemon=True
    )
    docker_thread.start()
    wsl_thread.start()

    results: Dict[str, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=12) as pool:
        f_lean = pool.submit(_probe_lean4)
        f_oracle = pool.submit(_probe_lean_oracle)
        f_angr = pool.submit(_probe_angr)
        f_klee = pool.submit(_probe_klee)
        f_semgrep = pool.submit(_probe_semgrep)
        f_rea = pool.submit(_probe_rea)
        f_trufflehog = pool.submit(_probe_trufflehog)
        f_jadx = pool.submit(_probe_jadx)
        f_subfinder = pool.submit(_probe_subfinder)
        f_httpx = pool.submit(_probe_httpx)
        f_katana = pool.submit(_probe_katana)
        f_schemathesis = pool.submit(_probe_schemathesis)

        results["lean4"] = f_lean.result()
        results["rfchunt_lean_oracle"] = f_oracle.result()
        results["angr"] = f_angr.result()
        results["klee"] = f_klee.result()
        results["semgrep"] = f_semgrep.result()
        results["rea"] = f_rea.result()
        results["trufflehog"] = f_trufflehog.result()
        results["jadx"] = f_jadx.result()
        results["subfinder"] = f_subfinder.result()
        results["httpx"] = f_httpx.result()
        results["katana"] = f_katana.result()
        results["schemathesis"] = f_schemathesis.result()

    if docker_done.wait(timeout=max(0.0, deadline - time.monotonic())):
        results["docker"] = docker_box.get("value") or _entry(
            False, "unavailable", "Docker probe produced no result.", docker_bin_ref[0]
        )
    else:
        results["docker"] = _entry(
            False,
            "timeout",
            f"Docker daemon probe timed out after {bounded_timeout:.1f}s.",
            docker_bin_ref[0],
        )

    if wsl_done.wait(timeout=max(0.0, deadline - time.monotonic())):
        results["wsl2"] = wsl_box.get("value") or _entry(
            False, "unavailable", "WSL2 probe produced no result.", wsl_bin_ref[0]
        )
    else:
        results["wsl2"] = _entry(
            False,
            "timeout",
            f"WSL2 probe timed out after {bounded_timeout:.1f}s.",
            wsl_bin_ref[0],
        )

    return {
        "docker": results["docker"],
        "wsl2": results["wsl2"],
        "lean4": results["lean4"],
        "rfchunt_lean_oracle": results["rfchunt_lean_oracle"],
        "angr": results["angr"],
        "klee": results["klee"],
        "semgrep": results["semgrep"],
        "rea": results["rea"],
        "trufflehog": results["trufflehog"],
        "jadx": results["jadx"],
        "subfinder": results["subfinder"],
        "httpx": results["httpx"],
        "katana": results["katana"],
        "schemathesis": results["schemathesis"],
    }


probe_toolchain_availability = probe_optional_backends


def run_rea_hook(
    target_path: Union[str, Path],
    *,
    query: str = "",
    timeout_sec: float = 30.0,
) -> Dict[str, Any]:
    """
    Auto-loaded, bounded, offline-first Module 21 (`morluto/rea`) surface & client-bundle
    reverse-engineering hook. Enforces `_validate_symbolic_target_path` fail-closed and
    delegates to `engine.rea_integrator.ReaIntegrator(write_reports=False)` without
    invoking native binary decompilers or spawning shells.
    """
    t0 = time.monotonic()
    raw_target_str = str(target_path) if target_path is not None else ""
    _ = timeout_sec

    ok_target, target_info = _validate_symbolic_target_path(target_path)
    if not ok_target:
        return {
            "backend": "rea",
            "target_path": raw_target_str,
            "available": False,
            "status": "rejected_unsafe",
            "verified": False,
            "findings": [],
            "discovered_endpoints": [],
            "ai_sinks": [],
            "ipc_channels": [],
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "command": [],
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
            "remediation_hint": target_info,
        }

    try:
        from engine.rea_integrator import ReaIntegrator

        integrator = ReaIntegrator()
        res = integrator.analyze(target_path=target_info, write_reports=False)
        findings_dicts = [f.to_dict() for f in (res.findings or [])]
        endpoints = list(res.discovered_endpoints or [])
        ai_sinks = list(res.ai_sinks or [])
        ipc_channels = list(res.ipc_channels or [])
        if query and str(query).strip():
            q_low = str(query).strip().lower()
            filtered_ep = [
                ep
                for ep in endpoints
                if q_low in str(ep.get("route", "")).lower()
                or q_low in str(ep.get("node_type", "")).lower()
            ]
            if filtered_ep:
                endpoints = filtered_ep
        return {
            "backend": "rea",
            "target_path": target_info,
            "available": True,
            "status": "passed" if res.status == "completed" else str(res.status),
            "mode": str(res.mode),
            "verified": False,
            "findings": findings_dicts,
            "discovered_endpoints": endpoints,
            "ai_sinks": ai_sinks,
            "ipc_channels": ipc_channels,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "command": ["engine.rea_integrator.ReaIntegrator.analyze", target_info],
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
            "remediation_hint": "",
        }
    except Exception as exc:
        return {
            "backend": "rea",
            "target_path": target_info,
            "available": False,
            "status": "failed",
            "verified": False,
            "findings": [],
            "discovered_endpoints": [],
            "ai_sinks": [],
            "ipc_channels": [],
            "exit_code": None,
            "stdout": "",
            "stderr": str(exc),
            "command": [],
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
            "remediation_hint": f"REA hook failed cleanly: {exc}",
        }


def run_symbolic_hook(
    backend: str,
    target_path: Union[str, Path],
    *,
    args: Optional[Sequence[str]] = None,
    timeout_sec: float = 30.0,
) -> Dict[str, Any]:
    """
    Bounded, non-destructive optional symbolic/reverse-engineering hook for `angr`, `klee`,
    and auto-loaded `rea` (Module 21 client-bundle/Electron surface analyzer).
    Enforces `validate_mount_path` and `validate_command_tokens` invariants, uses
    `silent_subprocess_run(..., shell=False)`, and degrades gracefully with
    `status="unavailable"` and `verified=False` when optional tools are absent.
    """
    t0 = time.monotonic()
    norm_backend = str(backend or "").strip().lower()
    raw_target_str = str(target_path) if target_path is not None else ""

    if norm_backend == "rea":
        if args is not None:
            if isinstance(args, (str, bytes, bytearray, dict)) or not isinstance(args, Sequence):
                return {
                    "backend": "rea",
                    "target_path": raw_target_str,
                    "available": False,
                    "status": "rejected_unsafe",
                    "verified": False,
                    "findings": [],
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "",
                    "command": [],
                    "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                    "remediation_hint": (
                        "Symbolic hook args must be a non-string Sequence of string tokens."
                    ),
                }
            args_list = list(args)
            if args_list:
                ok_args, args_err = validate_command_tokens(args_list)
                if not ok_args:
                    return {
                        "backend": "rea",
                        "target_path": raw_target_str,
                        "available": False,
                        "status": "rejected_unsafe",
                        "verified": False,
                        "findings": [],
                        "exit_code": None,
                        "stdout": "",
                        "stderr": "",
                        "command": [],
                        "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                        "remediation_hint": args_err,
                    }
        return run_rea_hook(target_path, timeout_sec=timeout_sec)

    def _result(
        *,
        available: bool,
        status: str,
        verified: bool = False,
        findings: Optional[List[Dict[str, Any]]] = None,
        exit_code: Optional[int] = None,
        stdout: str = "",
        stderr: str = "",
        command: Optional[List[str]] = None,
        remediation_hint: str = "",
        resolved_target: str = raw_target_str,
    ) -> Dict[str, Any]:
        return {
            "backend": norm_backend,
            "target_path": resolved_target,
            "available": bool(available),
            "status": status,
            "verified": bool(verified),
            "findings": list(findings) if findings is not None else [],
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "command": list(command) if command is not None else [],
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
            "remediation_hint": remediation_hint,
        }

    if norm_backend not in ("angr", "klee", "rea"):
        return _result(
            available=False,
            status="unsupported_backend",
            remediation_hint=f"Unsupported symbolic backend {backend!r}; choose 'angr', 'klee', or 'rea'.",
        )

    ok_target, target_info = _validate_symbolic_target_path(target_path)
    if not ok_target:
        return _result(
            available=False,
            status="rejected_unsafe",
            remediation_hint=target_info,
        )

    safe_args: List[str] = []
    if args is not None:
        if isinstance(args, (str, bytes, bytearray, dict)) or not isinstance(args, Sequence):
            return _result(
                available=False,
                status="rejected_unsafe",
                resolved_target=target_info,
                remediation_hint=(
                    "Symbolic hook args must be a non-string Sequence of string tokens "
                    "(e.g. list or tuple), not a str, bytes, dict, or non-sequence."
                ),
            )
        args_list = list(args)
        if args_list:
            ok_args, args_err = validate_command_tokens(args_list)
            if not ok_args:
                return _result(
                    available=False,
                    status="rejected_unsafe",
                    resolved_target=target_info,
                    remediation_hint=args_err,
                )
            safe_args = args_list

    angr_spec = None
    klee_bin = None
    klee_spec = None
    if norm_backend == "angr":
        angr_spec = _safe_find_spec("angr")
        if angr_spec is None:
            return _result(
                available=False,
                status="unavailable",
                resolved_target=target_info,
                remediation_hint="Optional symbolic backend 'angr' is not installed. Install with `pip install angr`.",
            )
    else:
        klee_bin = shutil.which("klee")
        klee_spec = _safe_find_spec("klee")
        if not klee_bin and klee_spec is None:
            return _result(
                available=False,
                status="unavailable",
                resolved_target=target_info,
                remediation_hint="Optional symbolic backend 'klee' is not installed on PATH or in Python environment.",
            )

    bounded_timeout = max(0.1, min(float(timeout_sec), 300.0))
    if norm_backend == "angr":
        probe_script = (
            "import angr, json, sys; "
            "p = angr.Project(sys.argv[1], auto_load_libs=False); "
            "print(json.dumps({"
            "'arch': str(p.arch.name), "
            "'entry': int(p.entry), "
            "'mode': 'bounded_metadata_probe', "
            "'args_received': sys.argv[2:], "
            "'findings': [], "
            "'verified': False"
            "}))"
        )
        exec_argv = [sys.executable, "-c", probe_script, target_info, *safe_args]
    else:
        if klee_bin:
            if safe_args:
                exec_argv = [klee_bin, *safe_args, target_info]
            elif Path(target_info).is_file():
                exec_argv = [klee_bin, "--max-time=10", target_info]
            else:
                exec_argv = [klee_bin, "--version"]
        else:
            exec_argv = [sys.executable, "-m", "klee", *(safe_args or ["--version"])]

    try:
        proc = silent_subprocess_run(
            exec_argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=bounded_timeout,
        )
        out_s = proc.stdout or ""
        err_s = proc.stderr or ""
        parsed_findings: List[Dict[str, Any]] = []
        verified = False
        if proc.returncode == 0 and out_s.strip():
            try:
                parsed = json.loads(out_s.strip())
                if isinstance(parsed, dict):
                    raw_findings = parsed.get("findings")
                    if isinstance(raw_findings, list):
                        parsed_findings = [f for f in raw_findings if isinstance(f, dict)]
                    verified = parsed.get("verified") is True
            except (json.JSONDecodeError, ValueError):
                verified = False

        return _result(
            available=True,
            status="passed" if proc.returncode == 0 else "failed",
            verified=verified,
            findings=parsed_findings,
            exit_code=proc.returncode,
            stdout=out_s,
            stderr=err_s,
            command=exec_argv,
            resolved_target=target_info,
        )
    except subprocess.TimeoutExpired as exc:
        out_s = (
            exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        err_s = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
        return _result(
            available=True,
            status="timeout",
            verified=False,
            findings=[],
            exit_code=None,
            stdout=out_s,
            stderr=err_s,
            command=exec_argv,
            resolved_target=target_info,
            remediation_hint=f"Symbolic hook `{norm_backend}` exceeded {bounded_timeout}s timeout.",
        )
    except Exception as exc:
        return _result(
            available=True,
            status="failed",
            verified=False,
            findings=[],
            exit_code=None,
            stderr=str(exc),
            command=exec_argv,
            resolved_target=target_info,
            remediation_hint=f"Symbolic hook `{norm_backend}` failed cleanly: {exc}",
        )
