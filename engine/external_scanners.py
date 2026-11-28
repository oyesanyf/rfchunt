"""
Opt-In Typed External Scanner Adapters (`httpx`, `katana`, `nuclei`).

Wraps ProjectDiscovery CLI tools behind fail-closed guardrails:
- Opt-in only (`ExternalScannerConfig.enabled = False` by default).
- Strict binary allowlisting (`httpx`, `katana`, `nuclei`, `docker` only; rejects
  excluded tools `nmap`/`ffuf`/`dalfox`/`sqlmap`, script shims, traversal, and
  cross-tool symlinks).
- Strict flag allowlisting (no free-form LLM shell strings or unknown flags).
- Non-destructive `nuclei` tag allowlist only (with mandatory `-jsonl`).
- `validate_and_authorize_target` SSRF + authorization checks.
- `ExecutionPolicy.validate_subprocess_command` / `validate_intent` (`shell=False`).
- `ApprovalGate.require(action_type="subprocess_exec", is_high_risk=False)`.
- `NoiseGovernor` rate-limit derivation (`-rl <int>`, bounded positive fallback).
- Dual `shell=False` execution modes: host `silent_subprocess_run` and mountless
  Docker `docker run --rm ...` (retaining canonical target URLs).
- Resilient JSONL parsing into `AssetGraph` (deduplicated against OpenAPI/HAR/repo)
  and `DualGraphAttackEngine.ingest_finding(..., scanner="nuclei")`.

NOTE: Never `import httpx` or define a module-level `httpx` symbol here so the
Python `httpx` HTTP client package is never shadowed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, replace
import hashlib
import ipaddress
import json
import logging
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
from typing import Any, Dict, FrozenSet, List, Literal, Optional, Set, Tuple
from urllib.parse import urlparse

from engine.approval_gate import ApprovalGate
from engine.dual_graph_engine import (
    AssetGraph,
    AssetNode,
    DualGraphAttackEngine,
    NoiseGovernor,
    derive_capability_class,
)
from engine.execution_policy import (
    ActionType,
    ExecutionPolicy,
    ScannerTask,
    StructuredIntentProposal,
    _extract_basename_lower,
    _is_drive_relative_or_colon_unsafe,
    _is_non_canonical_ipv4_host,
    _is_unc_path,
    _validate_canonical_path_syntax,
)
from engine.host_containment import silent_subprocess_run
from engine.safe_network_validator import (
    parse_host_and_port,
    validate_and_authorize_target,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_SAFE_RATE_LIMIT",
    "MAX_RATE_LIMIT",
    "DEFAULT_TIMEOUT_SEC",
    "DEFAULT_NUCLEI_TAGS",
    "ALLOWED_NUCLEI_TAGS",
    "FORBIDDEN_NUCLEI_TAGS",
    "ALLOWED_NUCLEI_SEVERITIES",
    "EXCLUDED_SCANNER_STEMS",
    "DEFAULT_DOCKER_IMAGES",
    "ExternalScannerConfig",
    "ScannerExecutionResult",
    "HttpxScannerAdapter",
    "KatanaScannerAdapter",
    "NucleiScannerAdapter",
    "run_opt_in_external_discovery",
    "run_opt_in_nuclei_scan",
]

DEFAULT_SAFE_RATE_LIMIT: int = 5
MAX_RATE_LIMIT: int = 150
DEFAULT_TIMEOUT_SEC: float = 120.0
MAX_TIMEOUT_SEC: float = 1800.0

DEFAULT_NUCLEI_TAGS: Tuple[str, ...] = ("tech", "misconfig", "exposure", "headers")
ALLOWED_NUCLEI_TAGS: FrozenSet[str] = frozenset(
    {
        "tech",
        "misconfig",
        "exposure",
        "headers",
        "ssl",
        "tls",
        "dns",
        "cve-detect",
        "http",
        "panel",
        "detect",
        "info",
        "config",
    }
)
FORBIDDEN_NUCLEI_TAGS: FrozenSet[str] = frozenset(
    {
        "dos",
        "ddos",
        "fuzz",
        "fuzzing",
        "exploit",
        "rce",
        "sqli",
        "xss",
        "ssti",
        "ssrf",
        "lfi",
        "rfi",
        "xxe",
        "cmdi",
        "bruteforce",
        "brute",
        "intrusive",
        "oob",
        "oast",
        "interactsh",
        "takeover",
        "injection",
    }
)
ALLOWED_NUCLEI_SEVERITIES: FrozenSet[str] = frozenset(
    {"info", "low", "medium", "high", "critical"}
)
EXCLUDED_SCANNER_STEMS: FrozenSet[str] = frozenset(
    {"nmap", "ffuf", "dalfox", "sqlmap"}
)
DEFAULT_DOCKER_IMAGES: Dict[str, str] = {
    "httpx": "projectdiscovery/httpx:latest",
    "katana": "projectdiscovery/katana:latest",
    "nuclei": "projectdiscovery/nuclei:latest",
}

_ALLOWED_SCRIPT_SHIMS: FrozenSet[str] = frozenset(
    {".bat", ".cmd", ".ps1", ".sh", ".py", ".vbs", ".js"}
)
_TAG_TOKEN_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_DOCKER_IMAGE_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?$"
)
_SHELL_IMAGE_NAMES: FrozenSet[str] = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "csh",
        "ash",
        "fish",
        "alpine",
        "ubuntu",
        "debian",
        "busybox",
        "python",
        "python3",
        "powershell",
        "pwsh",
        "cmd",
    }
)
_FORBIDDEN_META_CHARS: Tuple[str, ...] = (
    ";",
    "|",
    "&",
    "$(",
    "`",
    "\n",
    "\r",
    "\x00",
    ">",
    "<",
)

_AI_ROUTE_TOKENS: Tuple[str, ...] = (
    "/chat",
    "/completions",
    "/generate",
    "/prompt",
    "/llm",
    "/agent",
)
_SERVICE_ROUTE_TOKENS: Tuple[str, ...] = (
    "/internal",
    "/service",
    "/admin",
    "/worker",
    "/system",
    "/rpc",
    "/agent",
)

# Strict per-tool allowlists for optional extra_flags.
_TOOL_BOOL_FLAGS: Dict[str, FrozenSet[str]] = {
    "httpx": frozenset(
        {
            "-silent",
            "-nc",
            "-no-color",
            "-status-code",
            "-title",
            "-tech-detect",
            "-method",
            "-ip",
            "-content-type",
            "-content-length",
            "-web-server",
            "-server",
            "-follow-redirects",
            "-follow-host-redirects",
            "-jsonl",
            "-json",
        }
    ),
    "katana": frozenset(
        {
            "-silent",
            "-nc",
            "-no-color",
            "-jc",
            "-js-crawl",
            "-jsluice",
            "-kf",
            "-known-files",
            "-automatic-form-fill",
            "-aff",
            "-jsonl",
            "-json",
        }
    ),
    "nuclei": frozenset(
        {
            "-silent",
            "-nc",
            "-no-color",
            "-no-interactsh",
            "-ni",
            "-jsonl",
            "-json",
            "-include-rr",
            "-irr",
            "-no-mhe",
        }
    ),
}

_TOOL_INT_VALUE_FLAGS: Dict[str, Dict[str, Tuple[int, int]]] = {
    "httpx": {
        "-rl": (1, MAX_RATE_LIMIT),
        "-rate-limit": (1, MAX_RATE_LIMIT),
        "-timeout": (1, 120),
        "-retries": (0, 5),
        "-threads": (1, 50),
        "-max-host-error": (1, 10000),
        "-body-read-limit": (1024, 10485760),
        "-max-redirects": (0, 20),
    },
    "katana": {
        "-rl": (1, MAX_RATE_LIMIT),
        "-rate-limit": (1, MAX_RATE_LIMIT),
        "-timeout": (1, 120),
        "-depth": (1, 5),
        "-crawl-duration": (1, 600),
        "-retries": (0, 5),
        "-threads": (1, 50),
        "-max-host-error": (1, 10000),
        "-body-read-limit": (1024, 10485760),
    },
    "nuclei": {
        "-rl": (1, MAX_RATE_LIMIT),
        "-rate-limit": (1, MAX_RATE_LIMIT),
        "-timeout": (1, 120),
        "-retries": (0, 5),
        "-threads": (1, 50),
        "-c": (1, 50),
        "-concurrency": (1, 50),
        "-max-host-error": (1, 10000),
    },
}

_DESYNC_EVIDENCE_MARKERS: Tuple[str, ...] = (
    "CWE-444",
    "CL.TE",
    "TE.CL",
    "CL_TE",
    "TE_CL",
    "CRLF",
    "SMUGGLING",
    "DESYNC",
    "REQUEST SMUGGLING",
    "HTTP FRAMING",
)


def _normalize_nuclei_tags(raw_tags: Any) -> Tuple[str, ...]:
    """Normalize and validate nuclei template tags against the non-destructive allowlist."""
    if raw_tags is None:
        return DEFAULT_NUCLEI_TAGS
    if isinstance(raw_tags, (bytes, bytearray)):
        raise ValueError("nuclei_tags must be a sequence of tag strings, not bytes.")
    if isinstance(raw_tags, str):
        items: Sequence[str] = [raw_tags]
    elif isinstance(raw_tags, Sequence):
        items = raw_tags
    else:
        raise ValueError(f"Invalid nuclei_tags type: {type(raw_tags).__name__}")

    if len(items) == 0:
        return DEFAULT_NUCLEI_TAGS

    normalized: List[str] = []
    seen: Set[str] = set()
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"Nuclei tag must be a string, got {type(item).__name__}.")
        for part in item.split(","):
            tag = part.strip().lower()
            if not tag:
                raise ValueError("Empty nuclei tag is not permitted.")
            if not _TAG_TOKEN_RE.fullmatch(tag):
                raise ValueError(f"Invalid nuclei tag format: {part!r}")
            if tag in FORBIDDEN_NUCLEI_TAGS:
                raise ValueError(
                    f"Destructive/intrusive nuclei tag {tag!r} is forbidden."
                )
            if tag not in ALLOWED_NUCLEI_TAGS:
                raise ValueError(
                    f"Nuclei tag {tag!r} is not in the non-destructive allowlist."
                )
            if tag not in seen:
                seen.add(tag)
                normalized.append(tag)

    if not normalized:
        return DEFAULT_NUCLEI_TAGS
    return tuple(normalized)


def _normalize_nuclei_severities(raw_sevs: Any) -> Tuple[str, ...]:
    if raw_sevs is None:
        return ("info", "low", "medium")
    if isinstance(raw_sevs, str):
        items: Sequence[str] = [raw_sevs]
    elif isinstance(raw_sevs, Sequence) and not isinstance(raw_sevs, (bytes, bytearray)):
        items = raw_sevs
    else:
        raise ValueError(f"Invalid nuclei_severity type: {type(raw_sevs).__name__}")
    if len(items) == 0:
        return ("info", "low", "medium")
    out: List[str] = []
    seen: Set[str] = set()
    for item in items:
        if not isinstance(item, str):
            raise ValueError("nuclei_severity values must be strings.")
        for part in item.split(","):
            sev = part.strip().lower()
            if not sev or sev not in ALLOWED_NUCLEI_SEVERITIES:
                raise ValueError(f"Invalid nuclei severity: {part!r}")
            if sev not in seen:
                seen.add(sev)
                out.append(sev)
    return tuple(out) if out else ("info", "low", "medium")


def _validate_docker_image(image: Optional[str], tool_name: str) -> str:
    """Validate an explicit or default Docker image reference for a scanner tool."""
    if image is None:
        return DEFAULT_DOCKER_IMAGES[tool_name]
    if not isinstance(image, str):
        raise ValueError("docker_image must be a string.")
    if image != image.strip() or not image.strip():
        raise ValueError("docker_image must be non-empty without leading/trailing whitespace.")
    img = image.strip()
    if any(ch.isspace() for ch in img):
        raise ValueError(f"Invalid docker_image containing whitespace: {image!r}")
    if any(meta in img for meta in _FORBIDDEN_META_CHARS) or ".." in img:
        raise PermissionError(f"Unsafe docker_image blocked: {image!r}")
    if not _DOCKER_IMAGE_RE.fullmatch(img):
        raise ValueError(f"Invalid OCI docker_image reference: {image!r}")

    repo_no_digest = img.split("@", 1)[0]
    repo_last = repo_no_digest.rsplit("/", 1)[-1]
    repo_stem = repo_last.split(":", 1)[0].lower()
    if repo_stem in EXCLUDED_SCANNER_STEMS or any(ex in img.lower() for ex in EXCLUDED_SCANNER_STEMS):
        raise PermissionError(f"Excluded scanner docker_image blocked: {image!r}")
    if repo_stem in _SHELL_IMAGE_NAMES:
        raise PermissionError(f"Generic shell/OS docker_image blocked: {image!r}")
    if repo_stem != tool_name:
        raise ValueError(
            f"docker_image repository {repo_stem!r} does not match adapter tool {tool_name!r}."
        )
    return img


def _validate_execution_mode(mode: Any) -> str:
    if not isinstance(mode, str) or mode not in ("host", "docker"):
        raise ValueError(
            f"Unsupported execution_mode {mode!r}; expected 'host' or 'docker'."
        )
    return mode


def _validate_docker_network(network: Optional[str]) -> Optional[str]:
    if network is None:
        return None
    if not isinstance(network, str):
        raise ValueError("docker_network must be a string or None.")
    net = network.strip().lower()
    if not net:
        return None
    if net == "host":
        raise PermissionError("docker_network='host' (--network=host) is forbidden.")
    if net not in ("bridge", "none"):
        raise ValueError(
            f"Unsupported docker_network {network!r}; allowed values: None, 'bridge', 'none'."
        )
    return net


def _validate_rate_limit_field(rate_limit: Optional[int]) -> Optional[int]:
    if rate_limit is None:
        return None
    if isinstance(rate_limit, bool) or not isinstance(rate_limit, int):
        raise ValueError(f"rate_limit must be a positive integer, got {rate_limit!r}.")
    if rate_limit <= 0:
        raise ValueError(f"rate_limit must be >= 1, got {rate_limit}.")
    if rate_limit > MAX_RATE_LIMIT:
        raise ValueError(f"rate_limit {rate_limit} exceeds maximum {MAX_RATE_LIMIT}.")
    return rate_limit


def _validate_timeout_field(timeout_sec: Any) -> float:
    if isinstance(timeout_sec, bool) or not isinstance(timeout_sec, (int, float)):
        raise ValueError(f"timeout_sec must be numeric, got {timeout_sec!r}.")
    val = float(timeout_sec)
    if not math.isfinite(val) or val <= 0 or val > MAX_TIMEOUT_SEC:
        raise ValueError(
            f"timeout_sec must be a finite number in (0, {MAX_TIMEOUT_SEC}], got {timeout_sec!r}."
        )
    return val


def _validate_max_depth(max_depth: Any) -> int:
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not (1 <= max_depth <= 5):
        raise ValueError(f"max_depth must be an integer in [1, 5], got {max_depth!r}.")
    return max_depth


def _validate_crawl_duration_sec(crawl_duration_sec: Any) -> int:
    if (
        isinstance(crawl_duration_sec, bool)
        or not isinstance(crawl_duration_sec, int)
        or not (1 <= crawl_duration_sec <= 600)
    ):
        raise ValueError(
            f"crawl_duration_sec must be an integer in [1, 600], got {crawl_duration_sec!r}."
        )
    return crawl_duration_sec


def _validate_threads_field(threads: Any) -> Optional[int]:
    if threads is None:
        return None
    if isinstance(threads, bool) or not isinstance(threads, int) or not (1 <= threads <= 50):
        raise ValueError(f"threads must be an integer in [1, 50], got {threads!r}.")
    return threads


@dataclass
class ExternalScannerConfig:
    """
    Configuration for opt-in external ProjectDiscovery scanner adapters.

    `enabled` defaults to `False` so external scanners never run automatically.
    """

    enabled: bool = False
    execution_mode: Literal["host", "docker"] = "host"
    docker_image: Optional[str] = None
    docker_network: Optional[str] = None
    binary_path: Optional[str] = None
    rate_limit: Optional[int] = None
    timeout_sec: float = DEFAULT_TIMEOUT_SEC
    max_depth: int = 2
    crawl_duration_sec: int = 30
    js_crawl: bool = True
    nuclei_tags: Tuple[str, ...] = DEFAULT_NUCLEI_TAGS
    nuclei_severity: Tuple[str, ...] = ("info", "low", "medium")
    threads: Optional[int] = None
    custom_headers: Tuple[Tuple[str, str], ...] = ()
    user_agent: Optional[str] = None
    max_rps: float = 0.0

    def __post_init__(self) -> None:
        if self.custom_headers or self.user_agent or self.max_rps:
            from engine.request_hygiene import RequestHygieneConfig
            hyg = RequestHygieneConfig.from_raw(
                headers=list(self.custom_headers),
                user_agent=self.user_agent,
                max_rps=self.max_rps,
            )
            self.custom_headers = hyg.headers
            self.user_agent = hyg.user_agent
            self.max_rps = hyg.max_rps
        if not self.enabled:
            return
        _validate_execution_mode(self.execution_mode)
        _validate_docker_network(self.docker_network)
        _validate_rate_limit_field(self.rate_limit)
        _validate_timeout_field(self.timeout_sec)
        self.nuclei_tags = _normalize_nuclei_tags(self.nuclei_tags)
        self.nuclei_severity = _normalize_nuclei_severities(self.nuclei_severity)
        _validate_max_depth(self.max_depth)
        _validate_crawl_duration_sec(self.crawl_duration_sec)
        _validate_threads_field(self.threads)
        if self.execution_mode == "docker" and self.docker_image is not None:
            # Validate syntactic image safety early (tool match checked in adapter).
            if (
                not isinstance(self.docker_image, str)
                or self.docker_image != self.docker_image.strip()
                or not self.docker_image.strip()
                or any(ch.isspace() for ch in self.docker_image)
                or any(m in self.docker_image for m in _FORBIDDEN_META_CHARS)
                or ".." in self.docker_image
                or not _DOCKER_IMAGE_RE.fullmatch(self.docker_image.strip())
                or any(ex in self.docker_image.lower() for ex in EXCLUDED_SCANNER_STEMS)
            ):
                raise ValueError(f"Invalid or unsafe docker_image: {self.docker_image!r}")


@dataclass
class ScannerExecutionResult:
    """Structured JSON-serializable execution result for an external scanner run."""

    scanner: str
    status: str  # "disabled" | "completed" | "error" | "binary_not_found" | "timeout"
    ok: bool
    target: str
    execution_mode: str = "host"
    returncode: Optional[int] = None
    command: List[str] = field(default_factory=list)
    rate_limit: int = DEFAULT_SAFE_RATE_LIMIT
    records: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    endpoints_discovered: List[str] = field(default_factory=list)
    ai_sinks_discovered: List[str] = field(default_factory=list)
    js_endpoints: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    assets_added: int = 0
    findings_ingested: int = 0
    malformed_lines: int = 0
    stderr: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _is_bare_command(raw: str) -> bool:
    """Return True if `raw` is a bare command name without directory separators or drive prefix."""
    return "/" not in raw and "\\" not in raw and ":" not in raw


def _is_windows_platform() -> bool:
    """Return True when running on Windows (isolated helper for deterministic cross-OS testing)."""
    return os.name == "nt"


def _validate_binary_candidate(raw_path: str, tool_name: str) -> str:
    """Strictly validate an explicit or PATH-discovered binary path (fail closed)."""
    if not isinstance(raw_path, str):
        raise ValueError("binary_path must be a string.")
    if raw_path != raw_path.strip() or not raw_path.strip():
        raise PermissionError(
            f"Invalid binary_path (whitespace obfuscation or empty): {raw_path!r}"
        )
    raw = raw_path.strip()
    if any(meta in raw for meta in _FORBIDDEN_META_CHARS):
        raise PermissionError(f"Unsafe metacharacter in binary_path: {raw_path!r}")
    if "=" in raw and not raw.startswith("-"):
        raise PermissionError(f"Env prefix assignment forbidden in binary_path: {raw_path!r}")
    path_err = _validate_canonical_path_syntax(raw)
    if path_err is not None:
        raise PermissionError(f"Unsafe binary_path ({path_err}): {raw_path!r}")

    name = _extract_basename_lower(raw)
    if not name:
        raise ValueError(f"Empty executable basename in binary_path: {raw_path!r}")
    for ext in _ALLOWED_SCRIPT_SHIMS:
        if name.endswith(ext):
            raise PermissionError(
                f"Script wrapper binary {name!r} is forbidden for {tool_name}."
            )
    stem = name[:-4] if name.endswith(".exe") else name
    if stem in EXCLUDED_SCANNER_STEMS:
        raise PermissionError(f"Excluded scanner binary {name!r} is forbidden.")
    if stem != tool_name:
        raise PermissionError(
            f"Binary {name!r} is not allowlisted for {tool_name} adapter."
        )

    p = Path(raw)
    target_p = p
    resolved_paths: List[Path] = []
    try:
        if p.is_dir():
            if not _is_bare_command(raw) or p.is_symlink():
                raise PermissionError(
                    f"Binary path {raw!r} is a directory, not an executable."
                )
        elif p.is_file() or p.is_symlink():
            resolved_paths.append(p.resolve())

        if _is_windows_platform() and not p.name.lower().endswith(".exe"):
            exe_p = Path(str(p) + ".exe")
            if exe_p.is_dir():
                raise PermissionError(
                    f"Binary path {str(exe_p)!r} is a directory, not an executable."
                )
            if exe_p.is_file() or exe_p.is_symlink():
                target_p = exe_p
                resolved_paths.append(exe_p.resolve())
    except PermissionError:
        raise
    except (OSError, RuntimeError) as exc:
        raise PermissionError(
            f"Unable to safely resolve binary path {raw!r} for {tool_name}: {exc}"
        ) from exc

    for resolved_path in resolved_paths:
        resolved_s = str(resolved_path)
        if _is_unc_path(resolved_s) or _is_drive_relative_or_colon_unsafe(resolved_s):
            raise PermissionError(
                f"Resolved binary path {resolved_s!r} is an unsafe NT/UNC/drive-relative path."
            )
        res_name = resolved_path.name.lower()
        for ext in _ALLOWED_SCRIPT_SHIMS:
            if res_name.endswith(ext):
                raise PermissionError(
                    f"Resolved binary {res_name!r} is a forbidden script wrapper."
                )
        res_stem = res_name[:-4] if res_name.endswith(".exe") else res_name
        if res_stem in EXCLUDED_SCANNER_STEMS:
            raise PermissionError(
                f"Resolved binary {res_name!r} is an excluded scanner."
            )
        if res_stem != tool_name:
            raise PermissionError(
                f"Cross-tool symlink {name!r} -> {res_name!r} is forbidden."
            )
    return str(target_p) if target_p is not p else raw


def _is_subprocess_run_mocked() -> bool:
    """Return True when `subprocess.run` has been monkeypatched (e.g. offline test recorders)."""
    return not (
        getattr(subprocess.run, "__module__", None) == "subprocess"
        and getattr(subprocess.run, "__qualname__", None) == "run"
    )


def _is_python_httpx_cli_binary(path_str: str) -> bool:
    """
    Detect Python's `httpx[cli]` console script wrapper (e.g. `Scripts/httpx.EXE`
    or POSIX `bin/httpx`) by inspecting header/tail bytes without executing it.
    """
    try:
        p = Path(path_str)
        if not p.is_file():
            return False
        size = p.stat().st_size
        if size <= 0 or size > 2 * 1024 * 1024:
            return False
        with p.open("rb") as fh:
            if size <= 16384:
                chunk = fh.read(size)
            else:
                head = fh.read(256)
                if not head.startswith(b"MZ"):
                    return False
                fh.seek(max(0, size - 8192))
                chunk = fh.read(8192)
        chunk_l = chunk.lower()
        is_py_shebang = b"#!" in chunk_l and b"python" in chunk_l
        has_httpx_ep = (
            b"from httpx import main" in chunk_l
            or b"from httpx._main import main" in chunk_l
            or b"load_entry_point('httpx'" in chunk_l
            or b'load_entry_point("httpx"' in chunk_l
            or (b"__main__.py" in chunk_l and b"httpx" in chunk_l and b"sys.exit" in chunk_l)
        )
        return bool(is_py_shebang and has_httpx_ep)
    except OSError:
        return False


def _find_non_python_httpx_on_path(skip_path: str) -> Optional[str]:
    """Scan PATH entries for a ProjectDiscovery `httpx` binary other than Python's `httpx` CLI."""
    try:
        skip_resolved = Path(skip_path).resolve()
    except OSError:
        skip_resolved = None
    path_env = os.environ.get("PATH", "")
    if not path_env:
        return None
    cand_names = ("httpx.exe", "httpx") if os.name == "nt" else ("httpx",)
    for raw_dir in path_env.split(os.pathsep):
        d = raw_dir.strip().strip('"')
        if not d:
            continue
        dir_p = Path(d)
        try:
            if not dir_p.is_dir():
                continue
        except OSError:
            continue
        for cname in cand_names:
            cand = dir_p / cname
            try:
                if not cand.is_file():
                    continue
                if os.name != "nt" and not os.access(str(cand), os.X_OK):
                    continue
                if skip_resolved is not None and cand.resolve() == skip_resolved:
                    continue
                validated_cand = _validate_binary_candidate(str(cand), "httpx")
                if not _is_python_httpx_cli_binary(validated_cand):
                    return validated_cand
            except (OSError, PermissionError, ValueError):
                continue
    return None


def _try_auto_install_external_scanner(tool_name: str) -> bool:
    """Dynamically provisions a missing ProjectDiscovery scanner when live online."""
    if tool_name not in ("httpx", "katana", "nuclei"):
        return False
    if _is_subprocess_run_mocked():
        return False
    try:
        from engine.tool_provisioner import ToolProvisioner

        prov = ToolProvisioner()
        if prov.is_offline_or_blocked():
            return False
        res = prov.ensure_tool(tool_name)
        return bool(res.installed)
    except Exception:
        return False


def _resolve_host_binary(binary_path: Optional[str], tool_name: str) -> str:
    """Validate and resolve a host scanner binary path against strict allowlists."""
    candidate_in = tool_name if binary_path is None else binary_path
    validated = _validate_binary_candidate(candidate_in, tool_name)
    if _is_bare_command(validated):
        try:
            vp = Path(validated)
            if _is_windows_platform():
                if validated.lower().endswith(".exe"):
                    in_cwd = vp.is_file() or vp.is_symlink()
                else:
                    vp_exe = Path(validated + ".exe")
                    if vp_exe.is_file() or vp_exe.is_symlink():
                        return _validate_binary_candidate(str(vp_exe), tool_name)
                    # An extensionless file or directory in CWD is not executed directly by CreateProcessW;
                    # fall through to shutil.which so CWD *.bat/*.cmd or PATH binaries are validated.
                    in_cwd = False
            else:
                in_cwd = vp.is_file() or vp.is_symlink()
        except (OSError, RuntimeError) as exc:
            raise PermissionError(
                f"Unable to safely inspect binary path {validated!r} for {tool_name}: {exc}"
            ) from exc
        if not in_cwd:
            found = shutil.which(validated)
            if found:
                found_valid = _validate_binary_candidate(found, tool_name)
                if tool_name == "httpx" and binary_path is None and _is_python_httpx_cli_binary(found_valid):
                    alt = _find_non_python_httpx_on_path(found_valid)
                    if alt:
                        return alt
                    if _try_auto_install_external_scanner("httpx"):
                        alt_installed = _find_non_python_httpx_on_path(found_valid)
                        if alt_installed:
                            return alt_installed
                return found_valid
            if binary_path is None and _try_auto_install_external_scanner(tool_name):
                found_after = shutil.which(validated)
                if found_after:
                    return _validate_binary_candidate(found_after, tool_name)
    return validated


def _resolve_docker_binary() -> str:
    return _resolve_host_binary(None, "docker")


def _validate_target_and_normalize(
    raw_target: str, *, authorized: bool = False
) -> Tuple[str, str, int, bool]:
    """
    Validate URL/target syntax, reject SSRF obfuscations, enforce
    `validate_and_authorize_target`, and return `(canonical_url, host, port, use_tls)`.
    Never imports Python `httpx`.
    """
    if not isinstance(raw_target, str) or not raw_target.strip():
        raise ValueError("Target URL/host must be a non-empty string.")
    raw = raw_target.strip()
    if any(meta in raw for meta in _FORBIDDEN_META_CHARS):
        raise PermissionError(f"Unsafe character in target URL: {raw_target!r}")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise PermissionError(
            f"Whitespace or control character forbidden in target URL: {raw_target!r}"
        )

    if "://" in raw:
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError(
                f"Unsupported target URL scheme {scheme!r}; only http/https are permitted."
            )
        if parsed.username is not None or parsed.password is not None:
            raise PermissionError("Userinfo credentials in target URL are forbidden.")
        if "\\" in (parsed.netloc or ""):
            raise PermissionError(
                f"Backslash authority parser differential rejected in target URL: {raw_target!r}"
            )
        host_raw = (parsed.hostname or "").strip()
        if not host_raw:
            raise ValueError(f"Missing hostname in target URL: {raw_target!r}")
        if _is_non_canonical_ipv4_host(host_raw):
            raise PermissionError(
                f"Non-canonical IPv4 target host rejected: {host_raw!r}"
            )
        use_tls = scheme == "https"
        try:
            port = int(parsed.port) if parsed.port is not None else (443 if use_tls else 80)
        except ValueError as exc:
            raise ValueError(f"Invalid port in target URL: {raw_target!r}") from exc
        if not (1 <= port <= 65535):
            raise ValueError(f"Port out of range in target URL: {port}")
        clean_host = host_raw.lower()
        host_fmt = f"[{clean_host}]" if ":" in clean_host else clean_host
        path_part = parsed.path or ""
        query_part = f"?{parsed.query}" if parsed.query else ""
        if parsed.port is not None or (use_tls and port != 443) or (not use_tls and port != 80):
            canonical_url = f"{scheme}://{host_fmt}:{port}{path_part}{query_part}"
        else:
            canonical_url = f"{scheme}://{host_fmt}{path_part}{query_part}"
    else:
        host_raw, port, use_tls = parse_host_and_port(raw)
        clean_host = host_raw.strip().lower()
        if not clean_host:
            raise ValueError(f"Missing hostname in target: {raw_target!r}")
        if _is_non_canonical_ipv4_host(clean_host):
            raise PermissionError(
                f"Non-canonical IPv4 target host rejected: {clean_host!r}"
            )
        scheme = "https" if use_tls else "http"
        host_fmt = f"[{clean_host}]" if ":" in clean_host else clean_host
        canonical_url = f"{scheme}://{host_fmt}:{port}"

    ok_auth, auth_reason = validate_and_authorize_target(
        clean_host, authorized=authorized
    )
    if not ok_auth:
        raise PermissionError(auth_reason)

    return canonical_url, clean_host, port, use_tls


def _resolve_rate_limit(
    config: ExternalScannerConfig, noise_governor: Optional[NoiseGovernor]
) -> int:
    from engine.request_hygiene import get_active_hygiene
    active_hyg, _ = get_active_hygiene()
    eff_max_rps = float(getattr(config, "max_rps", 0.0) or 0.0) or float(active_hyg.max_rps or 0.0)

    gov_rps = 0.0
    if noise_governor is not None:
        try:
            gov_rps = float(noise_governor.config().get("rps", 0.0) or 0.0)
        except Exception:
            gov_rps = 0.0

    resolved = DEFAULT_SAFE_RATE_LIMIT
    if gov_rps > 0:
        gov_cap = max(1, min(MAX_RATE_LIMIT, int(gov_rps)))
        if config.rate_limit is not None:
            resolved = max(1, min(int(config.rate_limit), gov_cap))
        else:
            resolved = gov_cap
    elif config.rate_limit is not None:
        resolved = max(1, min(MAX_RATE_LIMIT, int(config.rate_limit)))

    if eff_max_rps > 0.0:
        rps_cap = max(1, min(MAX_RATE_LIMIT, int(eff_max_rps)))
        if config.rate_limit is not None or gov_rps > 0:
            return max(1, min(resolved, rps_cap))
        return rps_cap
    return resolved


def _validate_extra_flags(
    extra_flags: Optional[Sequence[str]], tool_name: str
) -> List[str]:
    """Validate optional extra CLI flags strictly against per-tool allowlists."""
    if extra_flags is None:
        return []
    if isinstance(extra_flags, (str, bytes, bytearray)) or not isinstance(
        extra_flags, Sequence
    ):
        raise TypeError("extra_flags must be a sequence of CLI flag strings.")

    bool_flags = _TOOL_BOOL_FLAGS[tool_name]
    int_flags = _TOOL_INT_VALUE_FLAGS[tool_name]
    out: List[str] = []
    i = 0
    items = list(extra_flags)
    while i < len(items):
        raw_tok = items[i]
        if not isinstance(raw_tok, str):
            raise TypeError(
                f"extra_flags elements must be str, got {type(raw_tok).__name__}."
            )
        if any(meta in raw_tok for meta in _FORBIDDEN_META_CHARS):
            raise PermissionError(
                f"Shell metacharacter forbidden in extra_flags: {raw_tok!r}"
            )
        tok = raw_tok.strip()
        if not tok or tok != raw_tok:
            raise ValueError(f"Empty or whitespace-padded flag token: {raw_tok!r}")
        if not tok.startswith("-"):
            raise ValueError(
                f"Unexpected positional/bare argument in extra_flags: {tok!r}"
            )

        flag_name = tok.split("=", 1)[0].lower() if "=" in tok else tok.lower()
        inline_val = tok.split("=", 1)[1] if "=" in tok else None

        if flag_name in bool_flags:
            if inline_val is not None:
                raise ValueError(f"Boolean flag {flag_name} does not accept a value.")
            out.append(flag_name)
            i += 1
            continue

        if flag_name in int_flags:
            min_v, max_v = int_flags[flag_name]
            if inline_val is not None:
                val_str = inline_val
                step = 1
            else:
                if i + 1 >= len(items):
                    raise ValueError(f"Flag {flag_name} requires an integer value.")
                val_raw = items[i + 1]
                if not isinstance(val_raw, str):
                    raise TypeError("Flag value must be a string.")
                if any(meta in val_raw for meta in _FORBIDDEN_META_CHARS):
                    raise PermissionError(
                        f"Shell metacharacter forbidden in flag value: {val_raw!r}"
                    )
                val_str = val_raw.strip()
                step = 2
            if not re.fullmatch(r"\d+", val_str):
                raise ValueError(
                    f"Flag {flag_name} requires a non-negative integer, got {val_str!r}."
                )
            int_val = int(val_str)
            if not (min_v <= int_val <= max_v):
                raise ValueError(
                    f"Flag {flag_name} value {int_val} outside allowed range [{min_v}, {max_v}]."
                )
            out.extend([flag_name, str(int_val)])
            i += step
            continue

        if tool_name == "nuclei" and flag_name in ("-tags", "-severity", "-s"):
            if inline_val is not None:
                val_str = inline_val
                step = 1
            else:
                if i + 1 >= len(items):
                    raise ValueError(f"Flag {flag_name} requires a value.")
                val_raw = items[i + 1]
                if not isinstance(val_raw, str):
                    raise TypeError("Flag value must be a string.")
                if any(meta in val_raw for meta in _FORBIDDEN_META_CHARS):
                    raise PermissionError(
                        f"Shell metacharacter forbidden in flag value: {val_raw!r}"
                    )
                val_str = val_raw.strip()
                step = 2
            if flag_name == "-tags":
                norm_val = ",".join(_normalize_nuclei_tags([val_str]))
            else:
                norm_val = ",".join(_normalize_nuclei_severities([val_str]))
            out.extend([flag_name, norm_val])
            i += step
            continue

        raise ValueError(
            f"Flag {tok!r} is not in the allowlist for {tool_name} adapter."
        )

    return out


def _iter_jsonl_records(raw_output: Optional[str]) -> Tuple[List[Dict[str, Any]], int]:
    """Parse JSONL lines resiliently, skipping blank, corrupt, or non-dict lines."""
    if not raw_output:
        return [], 0
    records: List[Dict[str, Any]] = []
    malformed = 0
    for idx, raw_line in enumerate(str(raw_output).splitlines()):
        line = raw_line.strip()
        if idx == 0 and line.startswith("\ufeff"):
            line = line.lstrip("\ufeff").strip()
        if not line:
            continue
        if not line.startswith("{"):
            malformed += 1
            logger.debug("Skipping non-JSON object line from scanner output.")
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError, TypeError):
            malformed += 1
            logger.debug("Skipping malformed JSONL line from scanner output.")
            continue
        if not isinstance(obj, dict):
            malformed += 1
            continue
        records.append(obj)
    return records, malformed


def _is_ip_literal(val: Any) -> bool:
    if not isinstance(val, str) or not val.strip():
        return False
    try:
        ipaddress.ip_address(val.strip("[] "))
        return True
    except ValueError:
        return False


def _safe_int_port(val: Any, default: int = 0) -> int:
    if val is None or isinstance(val, bool):
        return default
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return default
        try:
            return int(s)
        except ValueError:
            return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _extract_str_from_candidates(candidates: Sequence[Any]) -> Tuple[str, bool]:
    """
    Return `(first_non_empty_str, had_invalid_non_str_type)`.
    Rejects non-string non-None field values (e.g. list/dict/int) instead of
    coercing them with `str(...)`.
    """
    for val in candidates:
        if val is None:
            continue
        if not isinstance(val, str):
            return "", True
        stripped = val.strip()
        if stripped:
            return stripped, False
    return "", False


def _normalize_str_list(val: Any) -> List[str]:
    if not val:
        return []
    if isinstance(val, str):
        return [p.strip() for p in val.split(",") if p.strip()]
    if isinstance(val, Sequence) and not isinstance(val, (bytes, bytearray)):
        out: List[str] = []
        for elem in val:
            if isinstance(elem, str) and elem.strip():
                out.append(elem.strip())
            elif elem is not None and not isinstance(elem, (dict, list)):
                s = str(elem).strip()
                if s:
                    out.append(s)
        return out
    if isinstance(val, dict):
        return [str(k).strip() for k in val.keys() if str(k).strip()]
    return []


_NON_HTTP_SCHEMES: FrozenSet[str] = frozenset(
    {
        "mailto",
        "javascript",
        "data",
        "tel",
        "file",
        "vbscript",
        "ftp",
        "ftps",
        "ws",
        "wss",
        "about",
        "blob",
        "chrome",
        "cid",
        "geo",
        "imap",
        "irc",
        "ldap",
        "ldaps",
        "magnet",
        "mid",
        "mms",
        "news",
        "nntp",
        "pop",
        "rtsp",
        "sftp",
        "sip",
        "sips",
        "sms",
        "smsto",
        "ssh",
        "svn",
        "telnet",
        "urn",
        "view-source",
        "webcal",
        "xmpp",
    }
)
_LEADING_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$")
_EXPLICIT_SCHEME_SLASH_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_STATIC_FILE_EXTENSIONS: FrozenSet[str] = frozenset(
    {
        ".html",
        ".htm",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".css",
        ".scss",
        ".json",
        ".xml",
        ".txt",
        ".md",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".py",
        ".rb",
        ".go",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".conf",
        ".env",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
        ".pdf",
        ".zip",
        ".bak",
        ".sql",
        ".log",
    }
)


def _is_host_in_target_scope(host: str, target_host: str) -> bool:
    """Return True if normalized `host` matches `target_host` or one of its subdomains."""
    h = str(host or "").strip("[] ").rstrip(".").lower()
    t = str(target_host or "").strip("[] ").rstrip(".").lower()
    if not h:
        return False
    if not t:
        return True
    return h == t or h.endswith(f".{t}")


def _normalize_route_for_deny_check(route: str) -> str:
    """Normalize dot segments and slashes on a route copy for AssetGraph.deny_routes matching."""
    raw_path = str(route or "").split("?", 1)[0].split("#", 1)[0].strip()
    if not raw_path:
        return "/"
    had_trailing_slash = raw_path.endswith("/")
    collapsed = re.sub(r"/{2,}", "/", raw_path)
    if not collapsed.startswith("/"):
        collapsed = "/" + collapsed
    norm_route = posixpath.normpath(collapsed)
    norm_route = re.sub(r"/{2,}", "/", norm_route)
    if not norm_route.startswith("/"):
        norm_route = "/" + norm_route
    if had_trailing_slash and norm_route != "/" and not norm_route.endswith("/"):
        norm_route += "/"
    return norm_route


def _is_asset_graph_target_allowed(
    ag: AssetGraph, host: str, route: str, target_host: str
) -> bool:
    """Enforce AssetGraph scope_hosts/deny_hosts/deny_routes with IPv6 bracket normalization."""
    norm_host = str(host or "").strip("[] ").rstrip(".").lower()
    if not norm_host:
        return False
    norm_route = _normalize_route_for_deny_check(route)
    if ag.is_route_denied(route) or ag.is_route_denied(norm_route):
        return False
    with ag._lock:
        raw_deny = set(ag.deny_hosts)
        raw_scope = set(ag.scope_hosts)
    norm_fn = getattr(AssetGraph, "_normalize_host_entry", None)
    norm_deny = set()
    for d in raw_deny:
        if not str(d).strip():
            continue
        if callable(norm_fn):
            nd_res = norm_fn(str(d))
            nd = "" if (isinstance(nd_res, tuple) and nd_res[1]) else (nd_res[0] if isinstance(nd_res, tuple) else str(nd_res or ""))
        else:
            nd = str(d)
        if nd:
            norm_deny.add(str(nd).strip("[] ").rstrip(".").lower())
    if any(norm_host == d or norm_host.endswith(f".{d}") for d in norm_deny):
        return False
    if raw_scope:
        if ag.is_in_scope(norm_host):
            return True
        if any("[" in s or "]" in s or str(s).rstrip().endswith(".") or "://" in str(s) or ":" in str(s) for s in raw_scope):
            norm_scope = set()
            for s in raw_scope:
                if not str(s).strip():
                    continue
                if callable(norm_fn):
                    ns_res = norm_fn(str(s))
                    ns = "" if (isinstance(ns_res, tuple) and ns_res[1]) else (ns_res[0] if isinstance(ns_res, tuple) else str(ns_res or ""))
                else:
                    ns = str(s)
                if ns:
                    norm_scope.add(str(ns).strip("[] ").rstrip(".").lower())
            return any(norm_host == s or norm_host.endswith(f".{s}") for s in norm_scope)
        return False
    if not ag.is_in_scope(norm_host):
        return False
    if target_host:
        return _is_host_in_target_scope(norm_host, target_host)
    return True


def _looks_like_host_segment(first_seg: str) -> bool:
    """Return True if `first_seg` looks like a host[:port] authority rather than a relative path."""
    if not first_seg:
        return False
    if first_seg.startswith("["):
        return True
    if ":" in first_seg:
        h_cand, p_cand = first_seg.rsplit(":", 1)
        if not p_cand.isdigit():
            return False
        host_no_port = h_cand.lower()
        has_port = True
    else:
        host_no_port = first_seg.lower()
        has_port = False

    if not host_no_port or host_no_port in (".", ".."):
        return False
    if host_no_port.startswith(".") or host_no_port.endswith(".") or ".." in host_no_port:
        return False
    if host_no_port == "localhost":
        return True
    if "." not in host_no_port:
        return has_port and ":" not in host_no_port

    try:
        ipaddress.IPv4Address(host_no_port)
        return True
    except ValueError:
        pass

    tld = host_no_port.rsplit(".", 1)[-1]
    if not tld or tld.isdigit():
        return False
    if f".{tld}" in _STATIC_FILE_EXTENSIONS:
        return False
    return True


def _parse_endpoint_url(
    raw_url: str,
    *,
    fallback_host: str = "",
    fallback_port: Optional[int] = None,
    fallback_scheme: str = "http",
) -> Optional[Tuple[str, int, str, str]]:
    """
    Parse a discovered URL or relative path into `(host, port, route, scheme)`.
    Returns None if invalid, non-HTTP(S), carrying userinfo, or lacking a valid host.
    """
    if not isinstance(raw_url, str):
        return None
    text = raw_url.strip()
    if not text:
        return None
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None

    fb_host = fallback_host.strip("[] ").rstrip(".").lower()
    fb_scheme = (fallback_scheme or "http").strip().lower()
    if fb_scheme not in ("http", "https"):
        return None

    def _relative_result(raw_path: str) -> Optional[Tuple[str, int, str, str]]:
        if not fb_host:
            return None
        try:
            port_val = (
                int(fallback_port)
                if fallback_port is not None
                else (443 if fb_scheme == "https" else 80)
            )
        except (ValueError, TypeError):
            return None
        if not (1 <= port_val <= 65535):
            return None
        path = raw_path.split("?", 1)[0].split("#", 1)[0] or "/"
        path = re.sub(r"/{2,}", "/", path)
        if not path.startswith("/"):
            path = "/" + path
        return fb_host, port_val, path, fb_scheme

    if text.startswith("//"):
        candidate = f"{fb_scheme}:{text}"
        has_explicit_scheme = True
    elif text.startswith("/"):
        return _relative_result(text)
    elif _EXPLICIT_SCHEME_SLASH_RE.match(text):
        candidate = text
        has_explicit_scheme = True
    else:
        first_seg = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in first_seg:
            return None
        if not first_seg.startswith("[") and ":" in first_seg:
            try:
                if isinstance(ipaddress.ip_address(first_seg), ipaddress.IPv6Address):
                    return None
            except ValueError:
                pass

        m_scheme = _LEADING_SCHEME_RE.match(text)
        if m_scheme:
            sch_prefix = m_scheme.group(1).lower()
            rest = m_scheme.group(2)
            if sch_prefix in _NON_HTTP_SCHEMES or sch_prefix in ("http", "https"):
                return None
            if not re.match(r"^\d+(?:[/?#].*)?$", rest):
                return None

        if not _looks_like_host_segment(first_seg):
            return _relative_result(text)
        candidate = f"{fb_scheme}://{text}"
        has_explicit_scheme = False

    try:
        parsed = urlparse(candidate)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return None
        if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
            return None
        if "\\" in (parsed.netloc or ""):
            return None
        host = (parsed.hostname or "").strip("[] ").lower()
        parsed_port = parsed.port
    except (ValueError, TypeError):
        return None
    if not host:
        return None
    try:
        if parsed_port is not None:
            port = int(parsed_port)
        elif has_explicit_scheme:
            # Explicit scheme (or protocol-relative //host) URLs without an explicit port use scheme defaults.
            port = 443 if scheme == "https" else 80
        else:
            port = int(fallback_port or (443 if scheme == "https" else 80))
    except (ValueError, TypeError):
        return None
    if not (1 <= port <= 65535):
        return None
    route = parsed.path or "/"
    route = re.sub(r"/{2,}", "/", route)
    if not route.startswith("/"):
        route = "/" + route
    return host, port, route, scheme


def _canon_route(route: str) -> str:
    r = str(route or "/").strip()
    if not r.startswith("/"):
        r = "/" + r
    return r.rstrip("/") or "/"


def _classify_endpoint_node_type(route: str) -> Tuple[str, str]:
    r_low = route.lower()
    if any(tok in r_low for tok in _AI_ROUTE_TOKENS):
        return "AI_SINK", "DISPATCHES_TO"
    return "ENDPOINT", "EXPOSES"


class _AssetGraphPopulator:
    """Thread-safe, deduplicating, scope-aware AssetGraph helper for discovery adapters."""

    def __init__(self, asset_graph: AssetGraph, target_host: str) -> None:
        self.asset_graph = asset_graph
        self.target_host = target_host.strip("[] ").lower()
        self.added_count = 0
        self.endpoints_added = 0
        self.ai_sinks_added = 0
        with asset_graph._lock:
            self._sync_graph_index_locked()

    @staticmethod
    def _node_sig_entry(node: AssetNode) -> Tuple[Any, ...]:
        attrs = node.attributes or {}
        return (
            id(node),
            node.node_type,
            node.label,
            str(attrs.get("host") or ""),
            str(attrs.get("port") or ""),
            str(attrs.get("method") or ""),
            str(attrs.get("route") or ""),
        )

    def _sync_graph_index_locked(self) -> Dict[str, Any]:
        """Synchronize canonical lookup indices against live AssetGraph under `_lock`."""
        idx = getattr(self.asset_graph, "_ext_populator_idx", None)
        if idx is None:
            idx = {
                "node_sig": None,
                "edge_sig": None,
                "domains": {},
                "ports": {},
                "endpoints": {},
                "edges": set(),
            }
            setattr(self.asset_graph, "_ext_populator_idx", idx)

        node_sig = {
            nid: self._node_sig_entry(node)
            for nid, node in self.asset_graph.nodes.items()
        }
        if idx.get("node_sig") != node_sig:
            domains: Dict[str, str] = {}
            ports: Dict[Tuple[str, int], str] = {}
            endpoints: Dict[Tuple[str, int, str, str], AssetNode] = {}
            for node in self.asset_graph.nodes.values():
                if node.node_type == "DOMAIN":
                    h = str(node.attributes.get("host") or node.label or "").strip("[] ").lower()
                    if h and h not in domains:
                        domains[h] = node.node_id
                elif node.node_type == "IP_PORT":
                    h = str(node.attributes.get("host") or "").strip("[] ").lower()
                    p = _safe_int_port(node.attributes.get("port"), 0)
                    if (not h or p <= 0) and ":" in str(node.label or ""):
                        h_part, p_part = str(node.label).rsplit(":", 1)
                        if not h:
                            h = h_part.strip("[] ").lower()
                        if p <= 0:
                            p = _safe_int_port(p_part, 0)
                    if h and p > 0 and (h, p) not in ports:
                        ports[(h, p)] = node.node_id
                elif node.node_type in ("ENDPOINT", "AI_SINK"):
                    key = (
                        str(node.attributes.get("host") or "").strip("[] ").lower(),
                        _safe_int_port(node.attributes.get("port"), 0),
                        str(node.attributes.get("method") or "GET").strip().upper() or "GET",
                        _canon_route(str(node.attributes.get("route") or "/")),
                    )
                    if key not in endpoints:
                        endpoints[key] = node
            idx["domains"] = domains
            idx["ports"] = ports
            idx["endpoints"] = endpoints
            idx["node_sig"] = node_sig

        edge_sig = [id(e) for e in self.asset_graph.edges]
        if idx.get("edge_sig") != edge_sig:
            idx["edges"] = {
                (e.source_id, e.target_id, e.relationship)
                for e in self.asset_graph.edges
            }
            idx["edge_sig"] = edge_sig

        return idx

    def is_allowed_in_graph(self, host: str, route: str) -> bool:
        return _is_asset_graph_target_allowed(
            self.asset_graph, host, route, self.target_host
        )

    def ensure_host_and_port(
        self,
        host: str,
        port: int,
        source_tag: str,
        *,
        ip_addr: str = "",
    ) -> Tuple[str, str]:
        norm_host = host.strip("[] ").lower()
        norm_port = _safe_int_port(port, 0)
        with self.asset_graph._lock:
            idx = self._sync_graph_index_locked()
            domain_id = idx["domains"].get(norm_host)
            if domain_id is None or domain_id not in self.asset_graph.nodes:
                domain_id = f"ASSET-HOST-{norm_host}"
                if domain_id not in self.asset_graph.nodes:
                    d_node = self.asset_graph.add_asset(
                        domain_id,
                        "DOMAIN",
                        norm_host,
                        {"host": norm_host, "source": source_tag},
                    )
                    self.added_count += 1
                    if idx.get("node_sig") is not None:
                        idx["node_sig"][domain_id] = self._node_sig_entry(d_node)
                idx["domains"][norm_host] = domain_id

            port_id = idx["ports"].get((norm_host, norm_port))
            if port_id is None or port_id not in self.asset_graph.nodes:
                port_id = f"ASSET-PORT-{norm_host}-{norm_port}"
                if port_id not in self.asset_graph.nodes:
                    port_attrs: Dict[str, Any] = {
                        "host": norm_host,
                        "port": norm_port,
                        "source": source_tag,
                    }
                    if ip_addr:
                        port_attrs["ip"] = ip_addr
                    p_node = self.asset_graph.add_asset(
                        port_id,
                        "IP_PORT",
                        f"{norm_host}:{norm_port}",
                        port_attrs,
                    )
                    self.added_count += 1
                    if idx.get("node_sig") is not None:
                        idx["node_sig"][port_id] = self._node_sig_entry(p_node)
                idx["ports"][(norm_host, norm_port)] = port_id

            edge_key = (domain_id, port_id, "HOSTS")
            if edge_key not in idx["edges"]:
                self.asset_graph.add_relation(domain_id, port_id, "HOSTS")
                idx["edges"].add(edge_key)
                if idx.get("edge_sig") is not None and self.asset_graph.edges:
                    idx["edge_sig"].append(id(self.asset_graph.edges[-1]))
        return domain_id, port_id

    def add_endpoint_if_new(
        self,
        *,
        host: str,
        port: int,
        method: str,
        route: str,
        source_tag: str,
        attributes: Dict[str, Any],
    ) -> Tuple[Optional[AssetNode], bool]:
        if not self.is_allowed_in_graph(host, route):
            return None, False

        norm_host = host.strip("[] ").lower()
        norm_port = _safe_int_port(port, 0)
        norm_method = method.strip().upper() or "GET"
        canon_route = _canon_route(route)
        canon_key = (norm_host, norm_port, norm_method, canon_route)
        node_type, edge_rel = _classify_endpoint_node_type(route)
        label = f"{norm_method} {route}"

        with self.asset_graph._lock:
            idx = self._sync_graph_index_locked()
            existing_ep = idx["endpoints"].get(canon_key)
            if existing_ep is not None and existing_ep.node_id in self.asset_graph.nodes:
                return existing_ep, False
            dedup_key = self.asset_graph.compute_dedup_key(node_type, label, attributes)
            if dedup_key in self.asset_graph._dedup_index:
                existing_id = self.asset_graph._dedup_index[dedup_key]
                existing_node = self.asset_graph.nodes.get(existing_id)
                if existing_node is not None:
                    live_key = self.asset_graph.compute_dedup_key(
                        existing_node.node_type,
                        existing_node.label,
                        existing_node.attributes,
                    )
                    if live_key == dedup_key:
                        return existing_node, False

            _, port_id = self.ensure_host_and_port(
                norm_host, norm_port, source_tag, ip_addr=str(attributes.get("ip") or "")
            )
            ep_hash = hashlib.sha256(
                f"{norm_host}|{norm_port}|{norm_method}|{canon_route}".encode("utf-8")
            ).hexdigest()[:10]
            ep_id = f"ASSET-EP-{ep_hash}"
            if ep_id in self.asset_graph.nodes:
                suffix = len(self.asset_graph.nodes)
                while f"ASSET-EP-{ep_hash}-{suffix}" in self.asset_graph.nodes:
                    suffix += 1
                ep_id = f"ASSET-EP-{ep_hash}-{suffix}"

            node = self.asset_graph.add_asset(ep_id, node_type, label, attributes)
            edge_key = (port_id, ep_id, edge_rel)
            if edge_key not in idx["edges"]:
                self.asset_graph.add_relation(port_id, ep_id, edge_rel)
                idx["edges"].add(edge_key)
                if idx.get("edge_sig") is not None and self.asset_graph.edges:
                    idx["edge_sig"].append(id(self.asset_graph.edges[-1]))

            idx["endpoints"][canon_key] = node
            if idx.get("node_sig") is not None:
                idx["node_sig"][ep_id] = self._node_sig_entry(node)
            self.added_count += 1
            if node_type == "AI_SINK":
                self.ai_sinks_added += 1
            else:
                self.endpoints_added += 1
            return node, True


class _BaseExternalScannerAdapter:
    """Shared fail-closed validation and execution pipeline for ProjectDiscovery adapters."""

    tool_name: str = ""
    scanner_task: ScannerTask = ScannerTask.DISCOVERY_CASCADE

    def __init__(
        self,
        config: Optional[ExternalScannerConfig] = None,
        *,
        approval_gate: Optional[ApprovalGate] = None,
        noise_governor: Optional[NoiseGovernor] = None,
        execution_policy: Optional[ExecutionPolicy] = None,
        rate_limiter: Optional[Any] = None,
    ) -> None:
        self.config = config if config is not None else ExternalScannerConfig()
        self.approval_gate = approval_gate
        self.noise_governor = noise_governor
        self.execution_policy = execution_policy
        self.rate_limiter = rate_limiter
        if self.config.enabled:
            self._validate_config_for_tool()

    def _build_hygiene_header_flags(self) -> List[str]:
        from engine.request_hygiene import RequestHygieneConfig, get_active_hygiene
        active_hyg, _ = get_active_hygiene()
        cfg_headers = getattr(self.config, "custom_headers", ()) or active_hyg.headers
        cfg_ua = getattr(self.config, "user_agent", None) or active_hyg.user_agent
        if not cfg_headers and not cfg_ua:
            return []
        hyg = RequestHygieneConfig.from_raw(headers=list(cfg_headers), user_agent=cfg_ua)
        flags: List[str] = []
        for k, v in hyg.to_cli_header_pairs():
            flags.extend(["-H", f"{k}: {v}"])
        return flags

    def _validate_config_for_tool(self) -> Tuple[str, Optional[str], Optional[int]]:
        mode = _validate_execution_mode(self.config.execution_mode)
        net = _validate_docker_network(self.config.docker_network)
        rl_cfg = _validate_rate_limit_field(self.config.rate_limit)
        _validate_timeout_field(self.config.timeout_sec)
        _validate_max_depth(self.config.max_depth)
        _validate_crawl_duration_sec(self.config.crawl_duration_sec)
        _validate_threads_field(self.config.threads)
        if mode == "host":
            if self.config.binary_path is not None:
                _resolve_host_binary(self.config.binary_path, self.tool_name)
        else:
            _validate_docker_image(self.config.docker_image, self.tool_name)
        return mode, net, rl_cfg

    def _build_tool_flags(
        self,
        target_url: str,
        rate_limit: int,
        extra_flags: List[str],
    ) -> List[str]:
        raise NotImplementedError

    def _build_argv(
        self,
        target_url: str,
        rate_limit: Optional[int] = None,
        extra_flags: Optional[List[str]] = None,
    ) -> List[str]:
        eff_rl = _resolve_rate_limit(self.config, self.noise_governor) if rate_limit is None else int(rate_limit)
        eff_extra = list(extra_flags or [])
        tool_flags = self._build_tool_flags(target_url, eff_rl, eff_extra)
        hdr_flags = self._build_hygiene_header_flags()
        if hdr_flags:
            tool_flags = [*tool_flags, *hdr_flags]
        if self.config.execution_mode == "docker":
            docker_bin = _resolve_docker_binary()
            image = _validate_docker_image(self.config.docker_image, self.tool_name)
            net = _validate_docker_network(self.config.docker_network)
            net_args = ["--network", net] if net else []
            return [
                docker_bin,
                "run",
                "--rm",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=128",
                "--memory=512m",
                "--cpus=1.0",
                *net_args,
                image,
                *tool_flags,
            ]
        bin_path = _resolve_host_binary(self.config.binary_path, self.tool_name)
        return [bin_path, *tool_flags]

    def _execute_subprocess(
        self,
        target: str,
        *,
        authorized: bool,
        extra_flags: Optional[Sequence[str]],
    ) -> Tuple[Optional[ScannerExecutionResult], Optional[subprocess.CompletedProcess], str, int, bool, List[str], int]:
        if not self.config.enabled:
            res = ScannerExecutionResult(
                scanner=self.tool_name,
                status="disabled",
                ok=False,
                target=str(target or ""),
                execution_mode=str(getattr(self.config, "execution_mode", "host") or "host"),
            )
            return res, None, "", 0, False, [], DEFAULT_SAFE_RATE_LIMIT

        self._validate_config_for_tool()
        validated_extra = _validate_extra_flags(extra_flags, self.tool_name)
        canonical_url, host, port, use_tls = _validate_target_and_normalize(
            target, authorized=authorized
        )
        rate_limit = _resolve_rate_limit(self.config, self.noise_governor)
        # Never allow extra_flags `-rl`/`-rate-limit` to exceed the resolved NoiseGovernor/config cap.
        for idx, tok in enumerate(validated_extra):
            if tok in ("-rl", "-rate-limit") and idx + 1 < len(validated_extra):
                if int(validated_extra[idx + 1]) > rate_limit:
                    raise ValueError(
                        f"extra_flags {tok} {validated_extra[idx + 1]} exceeds rate_limit={rate_limit}."
                    )
            elif tok.startswith(("-rl=", "-rate-limit=")):
                k_eq, v_eq = tok.split("=", 1)
                if int(v_eq) > rate_limit:
                    raise ValueError(
                        f"extra_flags {k_eq} {v_eq} exceeds rate_limit={rate_limit}."
                    )
        argv = self._build_argv(canonical_url, rate_limit, validated_extra)

        policy = self.execution_policy or ExecutionPolicy.get_instance()
        ok_cmd, cmd_reason = policy.validate_subprocess_command(argv, shell=False)
        if not ok_cmd:
            raise PermissionError(cmd_reason)

        policy.validate_intent(
            StructuredIntentProposal(
                task=self.scanner_task,
                action_type=ActionType.SUBPROCESS_EXEC,
                target_host=host,
                target_port=port,
                command_args=argv,
                rationale=(
                    f"Opt-in external {self.tool_name} scan on {canonical_url} "
                    f"(mode={self.config.execution_mode})"
                ),
                metadata={
                    "shell": False,
                    "execution_mode": self.config.execution_mode,
                    "scanner": self.tool_name,
                },
            )
        )

        gate = self.approval_gate or ApprovalGate(mode="policy")
        gate.require(
            action_type="subprocess_exec",
            target=canonical_url,
            method="GET",
            rationale=(
                f"Opt-in external {self.tool_name} scan "
                f"(mode={self.config.execution_mode}, rl={rate_limit})"
            ),
            command=argv,
            is_high_risk=False,
            shell=False,
        )

        if self.noise_governor is not None:
            sleep_flag = getattr(self.noise_governor, "profile", "off") != "off"
            self.noise_governor.acquire_slot(host, sleep_enabled=sleep_flag)

        from engine.request_hygiene import acquire_rate_limit
        acquire_rate_limit(self.rate_limiter)

        if (
            self.config.execution_mode == "host"
            and self.tool_name == "httpx"
            and not _is_subprocess_run_mocked()
            and _is_python_httpx_cli_binary(argv[0])
        ):
            return (
                ScannerExecutionResult(
                    scanner=self.tool_name,
                    status="binary_not_found",
                    ok=False,
                    target=canonical_url,
                    execution_mode=self.config.execution_mode,
                    command=list(argv),
                    rate_limit=rate_limit,
                    error=(
                        f"ProjectDiscovery 'httpx' binary not found on PATH "
                        f"(resolved {argv[0]!r} is Python's httpx CLI wrapper, not ProjectDiscovery httpx)."
                    ),
                ),
                None,
                host,
                port,
                use_tls,
                argv,
                rate_limit,
            )

        try:
            proc = silent_subprocess_run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=float(self.config.timeout_sec),
                check=False,
            )
        except FileNotFoundError as exc:
            return (
                ScannerExecutionResult(
                    scanner=self.tool_name,
                    status="binary_not_found",
                    ok=False,
                    target=canonical_url,
                    execution_mode=self.config.execution_mode,
                    command=list(argv),
                    rate_limit=rate_limit,
                    error=str(exc),
                ),
                None,
                host,
                port,
                use_tls,
                argv,
                rate_limit,
            )
        except subprocess.TimeoutExpired as exc:
            return (
                ScannerExecutionResult(
                    scanner=self.tool_name,
                    status="timeout",
                    ok=False,
                    target=canonical_url,
                    execution_mode=self.config.execution_mode,
                    command=list(argv),
                    rate_limit=rate_limit,
                    stderr=str(getattr(exc, "stderr", "") or ""),
                    error=f"{self.tool_name} timed out after {self.config.timeout_sec}s",
                ),
                None,
                host,
                port,
                use_tls,
                argv,
                rate_limit,
            )
        except OSError as exc:
            return (
                ScannerExecutionResult(
                    scanner=self.tool_name,
                    status="error",
                    ok=False,
                    target=canonical_url,
                    execution_mode=self.config.execution_mode,
                    command=list(argv),
                    rate_limit=rate_limit,
                    error=str(exc),
                ),
                None,
                host,
                port,
                use_tls,
                argv,
                rate_limit,
            )

        return None, proc, host, port, use_tls, argv, rate_limit


def _extract_extra_flag_keys(extra_flags: Sequence[str]) -> Set[str]:
    keys: Set[str] = set()
    for tok in extra_flags:
        if isinstance(tok, str):
            t = tok.strip()
            if t.startswith("-"):
                keys.add(t.split("=", 1)[0].lower())
    return keys


class HttpxScannerAdapter(_BaseExternalScannerAdapter):
    """Opt-in typed adapter for ProjectDiscovery `httpx` JSONL endpoint & tech probing."""

    tool_name = "httpx"
    scanner_task = ScannerTask.DISCOVERY_CASCADE

    def _build_tool_flags(
        self,
        target_url: str,
        rate_limit: int,
        extra_flags: List[str],
    ) -> List[str]:
        timeout_val = _validate_timeout_field(self.config.timeout_sec)
        threads_val = _validate_threads_field(self.config.threads)
        req_timeout = max(1, min(30, int(timeout_val)))
        extra_keys = _extract_extra_flag_keys(extra_flags)
        flags = [
            "-u",
            target_url,
            "-jsonl",
            "-silent",
            "-nc",
            "-status-code",
            "-title",
            "-tech-detect",
            "-method",
        ]
        if not (extra_keys & {"-rl", "-rate-limit"}):
            flags.extend(["-rl", str(rate_limit)])
        if "-timeout" not in extra_keys:
            flags.extend(["-timeout", str(req_timeout)])
        if "-retries" not in extra_keys:
            flags.extend(["-retries", "1"])
        if threads_val is not None and "-threads" not in extra_keys:
            flags.extend(["-threads", str(threads_val)])
        flags.extend(extra_flags)
        return flags

    def run(
        self,
        target: str,
        *,
        authorized: bool = False,
        asset_graph: Optional[AssetGraph] = None,
        extra_flags: Optional[Sequence[str]] = None,
    ) -> ScannerExecutionResult:
        early, proc, target_host, target_port, target_tls, argv, rate_limit = (
            self._execute_subprocess(
                target, authorized=authorized, extra_flags=extra_flags
            )
        )
        if early is not None:
            return early
        assert proc is not None

        records, malformed = _iter_jsonl_records(proc.stdout)
        endpoints_discovered: List[str] = []
        ai_sinks_discovered: List[str] = []
        technologies: List[str] = []
        seen_eps: Set[str] = set()
        seen_ai: Set[str] = set()
        seen_tech: Set[str] = set()
        valid_records: List[Dict[str, Any]] = []

        populator = (
            _AssetGraphPopulator(asset_graph, target_host)
            if asset_graph is not None
            else None
        )
        fallback_scheme = "https" if target_tls else "http"

        for rec in records:
            if rec.get("failed") is True and not rec.get("status_code") and not rec.get("status-code"):
                continue
            raw_url, bad_url_type = _extract_str_from_candidates(
                [rec.get("url"), rec.get("final_url"), rec.get("input")]
            )
            if bad_url_type or not raw_url:
                malformed += 1
                continue

            raw_port_val = rec.get("port")
            parsed_rec_port = _safe_int_port(raw_port_val, 0)
            rec_port_fb: Optional[int] = (
                parsed_rec_port
                if 1 <= parsed_rec_port <= 65535
                else target_port
            )
            parsed = _parse_endpoint_url(
                raw_url,
                fallback_host=target_host,
                fallback_port=rec_port_fb,
                fallback_scheme=fallback_scheme,
            )
            if parsed is None:
                malformed += 1
                continue
            host, port, route, scheme = parsed
            raw_method = rec.get("method")
            method = (
                raw_method.strip().upper()
                if isinstance(raw_method, str) and raw_method.strip()
                else "GET"
            )

            raw_status = rec.get("status_code")
            if raw_status is None:
                raw_status = rec.get("status-code")
            status_code: Optional[int] = None
            if isinstance(raw_status, int) and not isinstance(raw_status, bool):
                status_code = raw_status
            elif isinstance(raw_status, str) and raw_status.strip().isdigit():
                status_code = int(raw_status.strip())

            tech_list = _normalize_str_list(rec.get("tech") or rec.get("technologies"))

            raw_ip = rec.get("ip")
            ip_addr = raw_ip.strip() if isinstance(raw_ip, str) else ""
            if not ip_addr and isinstance(rec.get("a"), list) and rec["a"]:
                first_a = rec["a"][0]
                if isinstance(first_a, str):
                    ip_addr = first_a.strip()
            if not ip_addr and _is_ip_literal(rec.get("host")):
                ip_addr = str(rec.get("host")).strip()

            raw_title = rec.get("title")
            title = raw_title.strip() if isinstance(raw_title, str) else ""
            raw_ws = rec.get("webserver")
            webserver = raw_ws.strip() if isinstance(raw_ws, str) else ""
            raw_ct = rec.get("content_type") if rec.get("content_type") is not None else rec.get("content-type")
            content_type = raw_ct.strip() if isinstance(raw_ct, str) else ""
            is_service_route = any(tok in route.lower() for tok in _SERVICE_ROUTE_TOKENS)

            attrs = {
                "host": host,
                "port": port,
                "route": route,
                "method": method,
                "url": raw_url,
                "scheme": scheme,
                "ip": ip_addr,
                "status_code": status_code,
                "title": title,
                "technologies": tech_list,
                "webserver": webserver,
                "content_type": content_type,
                "is_service_route": is_service_route,
                "source": "httpx",
            }

            node_type, _ = _classify_endpoint_node_type(route)
            if populator is not None:
                in_scope_ok = populator.is_allowed_in_graph(host, route)
                if in_scope_ok:
                    populator.add_endpoint_if_new(
                        host=host,
                        port=port,
                        method=method,
                        route=route,
                        source_tag="httpx",
                        attributes=attrs,
                    )
            else:
                in_scope_ok = _is_host_in_target_scope(host, target_host)

            if in_scope_ok:
                valid_records.append(attrs)
                for t in tech_list:
                    if t not in seen_tech:
                        seen_tech.add(t)
                        technologies.append(t)
                ep_label = f"{method} {route}"
                if node_type == "AI_SINK":
                    if ep_label not in seen_ai:
                        seen_ai.add(ep_label)
                        ai_sinks_discovered.append(ep_label)
                else:
                    if ep_label not in seen_eps:
                        seen_eps.add(ep_label)
                        endpoints_discovered.append(ep_label)

        ok = proc.returncode == 0
        return ScannerExecutionResult(
            scanner="httpx",
            status="completed" if ok else "error",
            ok=ok,
            target=target,
            execution_mode=self.config.execution_mode,
            returncode=proc.returncode,
            command=list(argv),
            rate_limit=rate_limit,
            records=valid_records,
            endpoints_discovered=endpoints_discovered,
            ai_sinks_discovered=ai_sinks_discovered,
            technologies=technologies,
            assets_added=populator.added_count if populator is not None else 0,
            malformed_lines=malformed,
            stderr=str(proc.stderr or ""),
            error="" if ok else (str(proc.stderr or "").strip() or f"httpx exited with {proc.returncode}"),
        )

    scan = run
    discover = run


class KatanaScannerAdapter(_BaseExternalScannerAdapter):
    """Opt-in typed adapter for ProjectDiscovery `katana` JSONL crawling & JS discovery."""

    tool_name = "katana"
    scanner_task = ScannerTask.DISCOVERY_CASCADE

    def _build_tool_flags(
        self,
        target_url: str,
        rate_limit: int,
        extra_flags: List[str],
    ) -> List[str]:
        timeout_val = _validate_timeout_field(self.config.timeout_sec)
        max_depth_val = _validate_max_depth(self.config.max_depth)
        crawl_dur_val = _validate_crawl_duration_sec(self.config.crawl_duration_sec)
        threads_val = _validate_threads_field(self.config.threads)
        req_timeout = max(1, min(60, int(timeout_val)))
        extra_keys = _extract_extra_flag_keys(extra_flags)
        flags = [
            "-u",
            target_url,
            "-jsonl",
            "-silent",
            "-nc",
        ]
        if "-depth" not in extra_keys:
            flags.extend(["-depth", str(max_depth_val)])
        if "-crawl-duration" not in extra_keys:
            flags.extend(["-crawl-duration", str(crawl_dur_val)])
        if not (extra_keys & {"-rl", "-rate-limit"}):
            flags.extend(["-rl", str(rate_limit)])
        if "-timeout" not in extra_keys:
            flags.extend(["-timeout", str(req_timeout)])
        if self.config.js_crawl and not (extra_keys & {"-jc", "-js-crawl"}):
            flags.append("-jc")
        if threads_val is not None and "-threads" not in extra_keys:
            flags.extend(["-threads", str(threads_val)])
        flags.extend(extra_flags)
        return flags

    def run(
        self,
        target: str,
        *,
        authorized: bool = False,
        asset_graph: Optional[AssetGraph] = None,
        extra_flags: Optional[Sequence[str]] = None,
    ) -> ScannerExecutionResult:
        early, proc, target_host, target_port, target_tls, argv, rate_limit = (
            self._execute_subprocess(
                target, authorized=authorized, extra_flags=extra_flags
            )
        )
        if early is not None:
            return early
        assert proc is not None

        records, malformed = _iter_jsonl_records(proc.stdout)
        endpoints_discovered: List[str] = []
        ai_sinks_discovered: List[str] = []
        js_endpoints: List[str] = []
        technologies: List[str] = []
        seen_eps: Set[str] = set()
        seen_ai: Set[str] = set()
        seen_js: Set[str] = set()
        seen_tech: Set[str] = set()
        valid_records: List[Dict[str, Any]] = []

        populator = (
            _AssetGraphPopulator(asset_graph, target_host)
            if asset_graph is not None
            else None
        )
        fallback_scheme = "https" if target_tls else "http"

        def _ingest_endpoint(
            raw_ep: str,
            method: str,
            *,
            status_code: Optional[int],
            tech_list: List[str],
            discovered_from: str,
            tag: str,
            attribute: str,
            fb_host: str = target_host,
            fb_port: int = target_port,
            fb_scheme: str = fallback_scheme,
        ) -> Tuple[bool, bool, str, int, str]:
            parsed = _parse_endpoint_url(
                raw_ep,
                fallback_host=fb_host,
                fallback_port=fb_port,
                fallback_scheme=fb_scheme,
            )
            if parsed is None:
                return False, False, fb_host, fb_port, fb_scheme
            host, port, route, scheme = parsed
            is_js_asset = route.lower().endswith((".js", ".mjs")) or tag == "script"
            discovered_from_js = discovered_from.lower().split("?", 1)[0].endswith(
                (".js", ".mjs")
            )
            is_service_route = any(tok in route.lower() for tok in _SERVICE_ROUTE_TOKENS)

            attrs = {
                "host": host,
                "port": port,
                "route": route,
                "method": method,
                "url": raw_ep,
                "scheme": scheme,
                "status_code": status_code,
                "technologies": tech_list,
                "discovered_from": discovered_from,
                "tag": tag,
                "attribute": attribute,
                "is_js_asset": is_js_asset,
                "discovered_from_js": discovered_from_js,
                "is_service_route": is_service_route,
                "source": "katana",
            }

            node_type, _ = _classify_endpoint_node_type(route)
            if populator is not None:
                in_scope_ok = populator.is_allowed_in_graph(host, route)
                if in_scope_ok:
                    populator.add_endpoint_if_new(
                        host=host,
                        port=port,
                        method=method,
                        route=route,
                        source_tag="katana",
                        attributes=attrs,
                    )
            else:
                in_scope_ok = _is_host_in_target_scope(host, target_host)

            if in_scope_ok:
                valid_records.append(attrs)
                ep_label = f"{method} {route}"
                if is_js_asset or discovered_from_js:
                    if route not in seen_js:
                        seen_js.add(route)
                        js_endpoints.append(route)
                if node_type == "AI_SINK":
                    if ep_label not in seen_ai:
                        seen_ai.add(ep_label)
                        ai_sinks_discovered.append(ep_label)
                else:
                    if ep_label not in seen_eps:
                        seen_eps.add(ep_label)
                        endpoints_discovered.append(ep_label)
            return True, in_scope_ok, host, port, scheme

        for rec in records:
            req = rec.get("request") if isinstance(rec.get("request"), dict) else {}
            resp = rec.get("response") if isinstance(rec.get("response"), dict) else {}

            raw_url, bad_url_type = _extract_str_from_candidates(
                [req.get("endpoint"), req.get("url"), rec.get("endpoint"), rec.get("url")]
            )
            if bad_url_type or not raw_url:
                malformed += 1
                continue

            discovered_from, bad_src_type = _extract_str_from_candidates(
                [req.get("source"), rec.get("source")]
            )
            if bad_src_type:
                malformed += 1
                continue

            raw_method = req.get("method") if req.get("method") is not None else rec.get("method")
            method = (
                raw_method.strip().upper()
                if isinstance(raw_method, str) and raw_method.strip()
                else "GET"
            )
            raw_tag = req.get("tag") if req.get("tag") is not None else rec.get("tag")
            tag = raw_tag.strip().lower() if isinstance(raw_tag, str) else ""
            raw_attr = req.get("attribute") if req.get("attribute") is not None else rec.get("attribute")
            attribute = raw_attr.strip().lower() if isinstance(raw_attr, str) else ""

            raw_status = (
                resp.get("status_code")
                if resp.get("status_code") is not None
                else resp.get("status-code")
            )
            if raw_status is None:
                raw_status = rec.get("status_code")
            status_code: Optional[int] = None
            if isinstance(raw_status, int) and not isinstance(raw_status, bool):
                status_code = raw_status
            elif isinstance(raw_status, str) and raw_status.strip().isdigit():
                status_code = int(raw_status.strip())

            tech_list = _normalize_str_list(
                resp.get("technologies")
                or resp.get("tech")
                or rec.get("technologies")
                or rec.get("tech")
            )

            parsed_ok, in_scope_ok, parent_host, parent_port, parent_scheme = _ingest_endpoint(
                raw_url,
                method,
                status_code=status_code,
                tech_list=tech_list,
                discovered_from=discovered_from,
                tag=tag,
                attribute=attribute,
            )
            if not parsed_ok:
                malformed += 1
                continue

            if in_scope_ok:
                for t in tech_list:
                    if t not in seen_tech:
                        seen_tech.add(t)
                        technologies.append(t)

            raw_extra_js = (
                rec.get("js_endpoints")
                if rec.get("js_endpoints") is not None
                else resp.get("js_endpoints")
            )
            if raw_extra_js is not None and in_scope_ok:
                if isinstance(raw_extra_js, (str, bytes, bytearray)) or not isinstance(
                    raw_extra_js, Sequence
                ):
                    malformed += 1
                else:
                    for js_ep in raw_extra_js:
                        if not isinstance(js_ep, str):
                            if js_ep is not None:
                                malformed += 1
                            continue
                        js_text = js_ep.strip()
                        if not js_text:
                            continue
                        js_parsed_ok, _, _, _, _ = _ingest_endpoint(
                            js_text,
                            "GET",
                            status_code=None,
                            tech_list=[],
                            discovered_from=raw_url,
                            tag="script",
                            attribute="js_endpoint",
                            fb_host=parent_host,
                            fb_port=parent_port,
                            fb_scheme=parent_scheme,
                        )
                        if not js_parsed_ok:
                            malformed += 1

        ok = proc.returncode == 0
        return ScannerExecutionResult(
            scanner="katana",
            status="completed" if ok else "error",
            ok=ok,
            target=target,
            execution_mode=self.config.execution_mode,
            returncode=proc.returncode,
            command=list(argv),
            rate_limit=rate_limit,
            records=valid_records,
            endpoints_discovered=endpoints_discovered,
            ai_sinks_discovered=ai_sinks_discovered,
            js_endpoints=js_endpoints,
            technologies=technologies,
            assets_added=populator.added_count if populator is not None else 0,
            malformed_lines=malformed,
            stderr=str(proc.stderr or ""),
            error="" if ok else (str(proc.stderr or "").strip() or f"katana exited with {proc.returncode}"),
        )

    scan = run
    discover = run


def _classify_nuclei_capability(
    *,
    probe_dict: Dict[str, Any],
    tags: List[str],
    cwe_str: str,
    cve_str: str,
    severity: str,
) -> str:
    """
    Determine explicit `capability_class` for a flattened Nuclei finding so
    non-desync informational/misconfig findings are NOT defaulted to `"DESYNC"`.
    """
    derived = derive_capability_class(probe_dict, scanner="nuclei")
    if derived != "DESYNC":
        return derived

    upper_blob = (
        f"{probe_dict.get('rule_id', '')} {probe_dict.get('title', '')} "
        f"{cwe_str} {cve_str} {probe_dict.get('description', '')} "
        f"{probe_dict.get('evidence', '')} {' '.join(tags)}"
    ).upper()

    if any(m in upper_blob for m in _DESYNC_EVIDENCE_MARKERS):
        return "DESYNC"

    if any(c in upper_blob for c in ("CWE-284", "CWE-862")) or (
        "ADMIN" in upper_blob and any(t in tags for t in ("exposure", "panel", "misconfig"))
    ):
        return "AUTH_BOUNDARY"

    if cve_str or "cve" in tags or "cve-detect" in tags:
        return "SUPPLY_CHAIN"

    if "ssl" in tags or "tls" in tags:
        return "CRYPTO_WEAK"

    if "tech" in tags or "detect" in tags or severity == "INFO":
        return "RECON_TECH"

    return "MISCONFIG"


class NucleiScannerAdapter(_BaseExternalScannerAdapter):
    """Opt-in typed adapter for ProjectDiscovery `nuclei -jsonl` non-destructive scanning."""

    tool_name = "nuclei"
    scanner_task = ScannerTask.ARTEX_DUAL_GRAPH

    def _validate_config_for_tool(self) -> Tuple[str, Optional[str], Optional[int]]:
        res = super()._validate_config_for_tool()
        _normalize_nuclei_tags(self.config.nuclei_tags)
        _normalize_nuclei_severities(self.config.nuclei_severity)
        return res

    def _build_tool_flags(
        self,
        target_url: str,
        rate_limit: int,
        extra_flags: List[str],
    ) -> List[str]:
        tags = _normalize_nuclei_tags(self.config.nuclei_tags)
        severities = _normalize_nuclei_severities(self.config.nuclei_severity)
        timeout_val = _validate_timeout_field(self.config.timeout_sec)
        threads_val = _validate_threads_field(self.config.threads)
        req_timeout = max(1, min(60, int(timeout_val)))

        # Avoid duplicating -tags/-severity/-rl/-timeout/-retries if caller passed validated overrides in extra_flags.
        extra_keys = _extract_extra_flag_keys(extra_flags)
        extra_has_tags = "-tags" in extra_keys
        extra_has_sev = bool(extra_keys & {"-severity", "-s"})

        flags = [
            "-u",
            target_url,
            "-jsonl",
            "-silent",
            "-nc",
            "-no-interactsh",
        ]
        if not extra_has_tags:
            flags.extend(["-tags", ",".join(tags)])
        if not extra_has_sev:
            flags.extend(["-severity", ",".join(severities)])
        if not (extra_keys & {"-rl", "-rate-limit"}):
            flags.extend(["-rl", str(rate_limit)])
        if "-timeout" not in extra_keys:
            flags.extend(["-timeout", str(req_timeout)])
        if "-retries" not in extra_keys:
            flags.extend(["-retries", "1"])
        if threads_val is not None and "-threads" not in extra_keys:
            flags.extend(["-threads", str(threads_val)])
        flags.extend(extra_flags)
        return flags

    def run(
        self,
        target: str,
        *,
        authorized: bool = False,
        dual_graph_engine: Optional[DualGraphAttackEngine] = None,
        extra_flags: Optional[Sequence[str]] = None,
    ) -> ScannerExecutionResult:
        early, proc, target_host, target_port, target_tls, argv, rate_limit = (
            self._execute_subprocess(
                target, authorized=authorized, extra_flags=extra_flags
            )
        )
        if early is not None:
            return early
        assert proc is not None

        records, malformed = _iter_jsonl_records(proc.stdout)
        fallback_scheme = "https" if target_tls else "http"

        normalized_findings: List[Dict[str, Any]] = []
        valid_records: List[Dict[str, Any]] = []
        seen_batch: Set[Tuple[str, str, str]] = set()
        findings_ingested = 0

        for rec in records:
            template_id, bad_tid = _extract_str_from_candidates(
                [rec.get("template-id"), rec.get("template_id"), rec.get("id")]
            )
            info = rec.get("info") if isinstance(rec.get("info"), dict) else {}
            matched_at, bad_matched = _extract_str_from_candidates(
                [
                    rec.get("matched-at"),
                    rec.get("matched_at"),
                    rec.get("url"),
                    rec.get("host"),
                ]
            )
            host_field, bad_host = _extract_str_from_candidates([rec.get("host")])

            if (
                bad_tid
                or bad_matched
                or bad_host
                or not template_id
                or not matched_at
            ):
                malformed += 1
                continue

            parsed_ep = _parse_endpoint_url(
                matched_at or host_field,
                fallback_host=target_host,
                fallback_port=target_port,
                fallback_scheme=fallback_scheme,
            )
            if parsed_ep is None:
                malformed += 1
                continue
            p_host, p_port, p_route, _ = parsed_ep

            ag = (
                getattr(dual_graph_engine, "asset_graph", None)
                if dual_graph_engine is not None
                else None
            )
            if ag is not None:
                in_scope_ok = _is_asset_graph_target_allowed(
                    ag, p_host, p_route, target_host
                )
            elif target_host:
                in_scope_ok = _is_host_in_target_scope(p_host, target_host)
            else:
                in_scope_ok = True
            if not in_scope_ok:
                continue
            valid_records.append(rec)

            raw_matcher = rec.get("matcher-name") if rec.get("matcher-name") is not None else rec.get("matcher_name")
            matcher_name = raw_matcher.strip() if isinstance(raw_matcher, str) else ""
            batch_key = (template_id, matched_at, matcher_name)
            if batch_key in seen_batch:
                continue
            seen_batch.add(batch_key)

            raw_name = info.get("name") if info.get("name") is not None else rec.get("name")
            name = (
                raw_name.strip()
                if isinstance(raw_name, str) and raw_name.strip()
                else template_id
            )
            raw_sev_val = info.get("severity") if info.get("severity") is not None else rec.get("severity")
            raw_sev = (
                raw_sev_val.strip().upper()
                if isinstance(raw_sev_val, str) and raw_sev_val.strip()
                else "INFO"
            )
            severity = (
                raw_sev
                if raw_sev in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
                else "INFO"
            )
            tags = [t.lower() for t in _normalize_str_list(info.get("tags"))]
            raw_desc = info.get("description")
            description = raw_desc.strip() if isinstance(raw_desc, str) else ""
            references = _normalize_str_list(info.get("reference"))

            classification = (
                info.get("classification")
                if isinstance(info.get("classification"), dict)
                else {}
            )
            cwe_list = _normalize_str_list(
                classification.get("cwe-id") or classification.get("cwe_id")
            )
            cve_list = _normalize_str_list(
                classification.get("cve-id") or classification.get("cve_id")
            )
            cwe_str = ",".join(cwe_list)
            cve_str = ",".join(cve_list)

            raw_type = rec.get("type")
            scan_type = (
                raw_type.strip().lower()
                if isinstance(raw_type, str) and raw_type.strip()
                else "http"
            )
            extracted_list = _normalize_str_list(
                rec.get("extracted-results") or rec.get("extracted_results")
            )
            raw_curl = rec.get("curl-command") if rec.get("curl-command") is not None else rec.get("curl_command")
            curl_cmd = raw_curl.strip() if isinstance(raw_curl, str) else ""

            confidence = (
                "HIGH"
                if (extracted_list or rec.get("matcher-status") is True or curl_cmd)
                else ("MEDIUM" if severity in ("MEDIUM", "HIGH", "CRITICAL") else "LOW")
            )

            ev_parts: List[str] = [f"matched_at={matched_at}"]
            if matcher_name:
                ev_parts.append(f"matcher={matcher_name}")
            if extracted_list:
                ev_parts.append(f"extracted={','.join(extracted_list)[:240]}")
            if curl_cmd:
                ev_parts.append(f"curl={curl_cmd[:240]}")
            evidence_str = " | ".join(ev_parts)

            probe_dict: Dict[str, Any] = {
                "scanner": "nuclei",
                "rule_id": template_id,
                "title": name,
                "severity": severity,
                "cwe": cwe_str,
                "cve": cve_str,
                "category": ",".join(tags) if tags else scan_type,
                "description": description or name,
                "evidence": evidence_str,
            }
            explicit_cap = _classify_nuclei_capability(
                probe_dict=probe_dict,
                tags=tags,
                cwe_str=cwe_str,
                cve_str=cve_str,
                severity=severity,
            )

            normalized = {
                "scanner": "nuclei",
                "rule_id": template_id,
                "title": name,
                "severity": severity,
                "confidence": confidence,
                "cwe": cwe_str,
                "cve": cve_str,
                "category": ",".join(tags) if tags else scan_type,
                "description": description or name,
                "file_path": matched_at or host_field,
                "route": p_route,
                "target_route": p_route,
                "host": p_host,
                "port": p_port,
                "evidence": evidence_str,
                "raw_probe": curl_cmd,
                "tags": tags,
                "reference": references,
                "matcher_name": matcher_name,
                "extracted_results": extracted_list,
                "scan_type": scan_type,
                "capability_class": explicit_cap,
            }
            normalized_findings.append(normalized)

            if dual_graph_engine is not None:
                node = dual_graph_engine.ingest_finding(normalized, scanner="nuclei")
                if node is not None:
                    findings_ingested += 1

        ok = proc.returncode == 0
        return ScannerExecutionResult(
            scanner="nuclei",
            status="completed" if ok else "error",
            ok=ok,
            target=target,
            execution_mode=self.config.execution_mode,
            returncode=proc.returncode,
            command=list(argv),
            rate_limit=rate_limit,
            records=valid_records,
            findings=normalized_findings,
            findings_ingested=findings_ingested,
            malformed_lines=malformed,
            stderr=str(proc.stderr or ""),
            error="" if ok else (str(proc.stderr or "").strip() or f"nuclei exited with {proc.returncode}"),
        )

    scan = run


def run_opt_in_external_discovery(
    target: str,
    config: Optional[ExternalScannerConfig] = None,
    *,
    asset_graph: Optional[AssetGraph] = None,
    authorized: bool = False,
    approval_gate: Optional[ApprovalGate] = None,
    noise_governor: Optional[NoiseGovernor] = None,
    execution_policy: Optional[ExecutionPolicy] = None,
    run_httpx: bool = True,
    run_katana: bool = True,
    extra_flags: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """
    Run opt-in black-box discovery (`httpx` + `katana`) into `AssetGraph`.
    No-ops safely returning `status="disabled"` when `config.enabled` is False.
    """
    cfg = config if config is not None else ExternalScannerConfig()
    if not cfg.enabled:
        return {
            "status": "disabled",
            "ok": False,
            "target": str(target or ""),
            "execution_mode": str(getattr(cfg, "execution_mode", "host") or "host"),
            "httpx": None,
            "katana": None,
            "endpoints": [],
            "ai_sinks": [],
            "js_endpoints": [],
            "technologies": [],
            "assets_added": 0,
            "endpoints_added": 0,
            "ai_sinks_added": 0,
        }

    httpx_cfg = cfg
    katana_cfg = cfg
    if run_httpx and run_katana and cfg.execution_mode == "docker" and cfg.docker_image is not None:
        matched_httpx = False
        matched_katana = False
        try:
            _validate_docker_image(cfg.docker_image, "httpx")
            matched_httpx = True
        except ValueError:
            pass
        try:
            _validate_docker_image(cfg.docker_image, "katana")
            matched_katana = True
        except ValueError:
            pass
        if matched_httpx and not matched_katana:
            katana_cfg = replace(cfg, docker_image=None)
        elif matched_katana and not matched_httpx:
            httpx_cfg = replace(cfg, docker_image=None)
        elif not matched_httpx and not matched_katana:
            _validate_docker_image(cfg.docker_image, "httpx")

    httpx_res: Optional[ScannerExecutionResult] = None
    katana_res: Optional[ScannerExecutionResult] = None

    if run_httpx:
        httpx_res = HttpxScannerAdapter(
            config=httpx_cfg,
            approval_gate=approval_gate,
            noise_governor=noise_governor,
            execution_policy=execution_policy,
        ).run(
            target,
            authorized=authorized,
            asset_graph=asset_graph,
            extra_flags=extra_flags,
        )

    if run_katana:
        katana_res = KatanaScannerAdapter(
            config=katana_cfg,
            approval_gate=approval_gate,
            noise_governor=noise_governor,
            execution_policy=execution_policy,
        ).run(
            target,
            authorized=authorized,
            asset_graph=asset_graph,
            extra_flags=extra_flags,
        )

    results = [r for r in (httpx_res, katana_res) if r is not None]
    endpoints: List[str] = []
    ai_sinks: List[str] = []
    js_endpoints: List[str] = []
    technologies: List[str] = []
    assets_added = 0

    for res in results:
        assets_added += res.assets_added
        for ep in res.endpoints_discovered:
            if ep not in endpoints:
                endpoints.append(ep)
        for ai in res.ai_sinks_discovered:
            if ai not in ai_sinks:
                ai_sinks.append(ai)
        for js in res.js_endpoints:
            if js not in js_endpoints:
                js_endpoints.append(js)
        for tech in res.technologies:
            if tech not in technologies:
                technologies.append(tech)

    if not results:
        status = "completed"
        overall_ok = True
    elif all(r.ok for r in results):
        status = "completed"
        overall_ok = True
    elif any(r.ok for r in results):
        status = "partial"
        overall_ok = True
    else:
        status = results[0].status if len(results) == 1 else "error"
        overall_ok = False

    return {
        "status": status,
        "ok": overall_ok,
        "target": str(target or ""),
        "execution_mode": cfg.execution_mode,
        "httpx": httpx_res.to_dict() if httpx_res is not None else None,
        "katana": katana_res.to_dict() if katana_res is not None else None,
        "endpoints": endpoints,
        "ai_sinks": ai_sinks,
        "js_endpoints": js_endpoints,
        "technologies": technologies,
        "assets_added": assets_added,
        "endpoints_added": len(endpoints),
        "ai_sinks_added": len(ai_sinks),
    }


def resolve_external_scanner_tool_configs(
    cfg: ExternalScannerConfig,
    *,
    run_httpx: bool = True,
    run_katana: bool = True,
    run_nuclei: bool = True,
) -> Tuple[ExternalScannerConfig, ExternalScannerConfig]:
    """
    Resolve per-pipeline `(discovery_cfg, nuclei_cfg)` when multiple external tools
    share one `ExternalScannerConfig` under `execution_mode="docker"` with an explicit
    `docker_image`. Preserves `PermissionError` for shell/excluded images, `ValueError`
    for unrelated images or single-tool mismatches, and clears `docker_image` for
    non-matching enabled tools when >=2 tools are active and one matches.
    """
    enabled_tools = [
        tool_name
        for tool_name, is_on in (
            ("httpx", bool(run_httpx)),
            ("katana", bool(run_katana)),
            ("nuclei", bool(run_nuclei)),
        )
        if is_on
    ]
    if (
        cfg.execution_mode != "docker"
        or cfg.docker_image is None
        or len(enabled_tools) < 2
    ):
        return cfg, cfg

    matched: Set[str] = set()
    last_val_err: Optional[ValueError] = None
    for tool_name in enabled_tools:
        try:
            _validate_docker_image(cfg.docker_image, tool_name)
            matched.add(tool_name)
        except ValueError as exc:
            last_val_err = exc

    if not matched:
        if last_val_err is not None:
            raise last_val_err
        _validate_docker_image(cfg.docker_image, enabled_tools[0])

    discovery_cfg = (
        cfg
        if ("httpx" in matched or "katana" in matched)
        else replace(cfg, docker_image=None)
    )
    nuclei_cfg = (
        cfg
        if "nuclei" in matched
        else replace(cfg, docker_image=None)
    )
    return discovery_cfg, nuclei_cfg


def run_opt_in_nuclei_scan(
    target: str,
    config: Optional[ExternalScannerConfig] = None,
    *,
    dual_graph_engine: Optional[DualGraphAttackEngine] = None,
    authorized: bool = False,
    approval_gate: Optional[ApprovalGate] = None,
    noise_governor: Optional[NoiseGovernor] = None,
    execution_policy: Optional[ExecutionPolicy] = None,
    extra_flags: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """
    Run opt-in non-destructive `nuclei -jsonl` scan and ingest findings into
    `DualGraphAttackEngine`. No-ops safely returning `status="disabled"` when disabled.
    """
    cfg = config if config is not None else ExternalScannerConfig()
    if not cfg.enabled:
        return {
            "status": "disabled",
            "ok": False,
            "target": str(target or ""),
            "execution_mode": str(getattr(cfg, "execution_mode", "host") or "host"),
            "tags": list(DEFAULT_NUCLEI_TAGS),
            "findings": [],
            "total_findings": 0,
            "findings_ingested": 0,
            "returncode": None,
            "stderr": "",
            "command": [],
            "rate_limit": DEFAULT_SAFE_RATE_LIMIT,
            "error": "",
        }

    tags = _normalize_nuclei_tags(cfg.nuclei_tags)
    res = NucleiScannerAdapter(
        config=cfg,
        approval_gate=approval_gate,
        noise_governor=noise_governor,
        execution_policy=execution_policy,
    ).run(
        target,
        authorized=authorized,
        dual_graph_engine=dual_graph_engine,
        extra_flags=extra_flags,
    )

    return {
        "status": res.status,
        "ok": res.ok,
        "target": res.target,
        "execution_mode": res.execution_mode,
        "tags": list(tags),
        "findings": list(res.findings),
        "total_findings": len(res.findings),
        "findings_ingested": res.findings_ingested,
        "returncode": res.returncode,
        "stderr": res.stderr,
        "command": list(res.command),
        "rate_limit": res.rate_limit,
        "error": res.error,
    }
