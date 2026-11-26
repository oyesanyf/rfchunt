"""
Clean-room Cairn-style YAML swarm dispatcher and workspace isolation validator.

Loads and strictly validates `swarm_dispatch.yaml` via `yaml.safe_load()`,
enforcing fail-closed schema, SSRF, target authorization, Docker network,
and filesystem containment checks BEFORE creating any workspace directory
or SQLite database.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import inspect
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import subprocess
import sys
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Tuple, Union
from urllib.parse import unquote

import yaml

from database import Database
from engine.external_scanners import (
    EXCLUDED_SCANNER_STEMS,
    _DOCKER_IMAGE_RE,
    _FORBIDDEN_META_CHARS,
    _SHELL_IMAGE_NAMES,
    _validate_docker_network,
)
from engine.safe_network_validator import validate_and_authorize_target

_WIN_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)
_PERCENT_ESCAPE_RE = re.compile(r"%(?:2e|2f|5c|00|3a)", re.IGNORECASE)
_WINDOWS_DRIVE_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")
_VALID_BACKENDS = frozenset({"swarm", "all", "mantis", "artex"})
_VALID_APPROVAL_MODES = frozenset({"policy", "prompt", "deny"})
_VALID_NOISE_PROFILES = frozenset({"off", "quiet", "balanced", "aggressive"})
_VALID_TARGET_MODES = frozenset(
    {
        "all",
        "all_scans",
        "swarm",
        "single",
        "terminator",
        "corpus",
        "pqc",
        "all_active",
        "mantis",
        "artex",
    }
)


_VALID_FRONTIER_PROVIDERS = frozenset({"openai", "anthropic", "google", "gemini", "openrouter"})
_ALLOWED_ESCALATION_KEYS = frozenset(
    {
        "enabled",
        "fast_local_model",
        "max_escalation_fraction",
        "min_poe_for_escalation",
        "strong_local_model",
        "frontier_api_opt_in",
        "frontier_provider",
        "frontier_model",
        "frontier_api_env_var",
    }
)
_FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "frontier_api_key",
        "secret",
        "secret_key",
        "token",
        "access_token",
        "bearer_token",
        "auth_token",
        "password",
        "credentials",
        "private_key",
        "key",
    }
)
_ENV_VAR_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_RAW_SECRET_VALUE_RE = re.compile(
    r"(?:^|\b)(?:sk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[0-9A-Z]{16}|Bearer\s+\S{10,}|hf_[A-Za-z0-9]{16,})",
)
_CODER_SUFFIX_RE = re.compile(r"-coder(?:$|[:\-/])", re.IGNORECASE)
_MODEL_PARAM_SIZE_RE = re.compile(r"(?:^|[:\-_])(\d+(?:\.\d+)?)\s*b(?:$|[^a-z0-9])", re.IGNORECASE)
_SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.25,
    "INFO": 0.1,
}


@dataclass
class DispatchEscalationConfig:
    enabled: bool = True
    fast_local_model: Optional[str] = None
    max_escalation_fraction: float = 0.05
    min_poe_for_escalation: int = 1
    strong_local_model: Optional[str] = None
    frontier_api_opt_in: bool = False
    frontier_provider: Optional[str] = None
    frontier_model: Optional[str] = None
    frontier_api_env_var: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeMemorySnapshot:
    free_ram_gb: float
    free_vram_mb: float = 0.0
    ram_source: str = "fallback"
    vram_source: str = "none"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ModelRoutingDecision:
    candidate_id: str
    tier: Literal["fast_local", "strong_local", "frontier_api"]
    model: str
    provider: str
    escalated: bool
    rank_score: float
    poe_level: int
    reason: str
    free_ram_gb: float
    free_vram_mb: float
    downgraded_for_memory: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RoutingPlan:
    decisions: List[ModelRoutingDecision]
    total_candidates: int
    eligible_candidates: int
    escalation_budget: int
    escalated_count: int
    fast_local_model: str
    strong_local_model: str
    frontier_enabled: bool
    free_ram_gb: float
    free_vram_mb: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decisions": [d.to_dict() for d in self.decisions],
            "total_candidates": self.total_candidates,
            "eligible_candidates": self.eligible_candidates,
            "escalation_budget": self.escalation_budget,
            "escalated_count": self.escalated_count,
            "fast_local_model": self.fast_local_model,
            "strong_local_model": self.strong_local_model,
            "frontier_enabled": self.frontier_enabled,
            "free_ram_gb": round(self.free_ram_gb, 3),
            "free_vram_mb": round(self.free_vram_mb, 1),
        }


@dataclass
class DispatchRuntimeConfig:
    execution: Literal["local", "docker"] = "local"
    scanner_isolation: Literal["host", "docker"] = "host"
    docker_image: Optional[str] = None
    docker_network: Optional[str] = None
    offline: bool = False


@dataclass
class DispatchWorkersConfig:
    backend: Literal["swarm", "all", "mantis", "artex"] = "all"
    concurrency: int = 8
    artex_workers: int = 3
    preferred_model: Optional[str] = None
    sec_model: Optional[str] = None
    use_fusion: bool = True
    approval_mode: Literal["policy", "prompt", "deny"] = "policy"
    noise_profile: Optional[str] = None
    escalation: DispatchEscalationConfig = field(default_factory=DispatchEscalationConfig)


@dataclass
class DispatchWorkspaceConfig:
    root: str
    resolved_root: Path
    per_target_isolation: bool = True


@dataclass
class DispatchTargetConfig:
    name: str
    host: str
    port: int = 8080
    tls: bool = False
    authorized: bool = False
    modes: List[str] = field(default_factory=lambda: ["all"])
    rfcs: List[str] = field(default_factory=lambda: ["9112"])
    repo: Optional[str] = None
    path: Optional[str] = None
    task_id: Optional[str] = None
    modes_explicit: bool = False


@dataclass
class TargetWorkspacePaths:
    slug: str
    workspace_dir: Path
    db_path: Path
    reports_dir: Path
    harness2_runs_dir: Path
    dream_export_path: Path
    dashboard_out: Path
    caldera_export_dir: Path


@dataclass
class SwarmDispatchConfig:
    version: int
    runtime: DispatchRuntimeConfig
    workers: DispatchWorkersConfig
    workspace: DispatchWorkspaceConfig
    targets: List[DispatchTargetConfig]
    source_path: Optional[Path] = None
    escalation: DispatchEscalationConfig = field(default_factory=DispatchEscalationConfig)


def _check_safe_path_tokens(raw_path: str, *, label: str) -> None:
    """Rejects NUL, percent-encoded traversal, UNC/device paths, '..' segments, ADS colons, and Windows reserved names."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError(f"{label} must be a non-empty path string.")
    if "\x00" in raw_path:
        raise ValueError(f"{label} contains NUL byte.")
    if _PERCENT_ESCAPE_RE.search(raw_path):
        raise ValueError(f"{label} contains forbidden percent-encoded path sequence: {raw_path!r}")

    decoded = unquote(raw_path)
    if "\x00" in decoded:
        raise ValueError(f"{label} contains decoded NUL byte.")

    for candidate in (raw_path, decoded):
        if candidate.startswith("\\\\") or candidate.startswith("//"):
            raise ValueError(f"{label} UNC/network paths are forbidden: {raw_path!r}")

        # Allow a single ':' only as a leading Windows drive-letter root (e.g., C:\...)
        colon_count = candidate.count(":")
        if colon_count > 1:
            raise ValueError(f"{label} contains forbidden ':' / NTFS ADS sequence: {raw_path!r}")
        if colon_count == 1 and not _WINDOWS_DRIVE_ABS_RE.match(candidate):
            raise ValueError(f"{label} contains forbidden ':' / NTFS ADS sequence: {raw_path!r}")

        for parts in (PureWindowsPath(candidate).parts, PurePosixPath(candidate).parts):
            for part in parts:
                if part == "..":
                    raise ValueError(f"{label} path traversal '..' is forbidden: {raw_path!r}")
                cleaned_part = part.rstrip(" .")
                if cleaned_part:
                    stem = cleaned_part.split(".", 1)[0].upper()
                    if stem in _WIN_RESERVED_NAMES:
                        raise ValueError(f"{label} contains forbidden Windows device name {part!r}: {raw_path!r}")


def _is_system_root_path(resolved_path: Path) -> bool:
    """Returns True if resolved_path points to or inside a protected OS system directory or drive root."""
    if resolved_path == Path(resolved_path.anchor):
        return True

    norm = str(resolved_path).replace("/", "\\").rstrip("\\").lower()
    sys_prefixes: List[str] = []
    for env_key in ("WINDIR", "SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        val = os.environ.get(env_key)
        if val:
            sys_prefixes.append(str(Path(val).resolve()).replace("/", "\\").rstrip("\\").lower())
    sys_prefixes.extend(
        [
            "c:\\windows",
            "c:\\program files",
            "c:\\program files (x86)",
            "\\etc",
            "\\usr",
            "\\bin",
            "\\sbin",
            "\\var",
            "\\system",
            "\\library",
        ]
    )
    for prefix in sys_prefixes:
        if prefix and (norm == prefix or norm.startswith(prefix + "\\")):
            return True
    return False


def _validate_workspace_root(raw_root: Any, *, base_dir: Path) -> Path:
    if not isinstance(raw_root, str):
        raise ValueError("workspace.root must be a string.")
    _check_safe_path_tokens(raw_root, label="workspace.root")

    is_abs = bool(
        _WINDOWS_DRIVE_ABS_RE.match(raw_root)
        or PureWindowsPath(raw_root).is_absolute()
        or PurePosixPath(raw_root).is_absolute()
    )
    base_resolved = base_dir.resolve()
    cwd_resolved = Path.cwd().resolve()

    if is_abs:
        candidate = Path(raw_root).resolve()
        if _is_system_root_path(candidate):
            raise PermissionError(f"workspace.root targets protected system directory: {raw_root!r}")
        if not (candidate.is_relative_to(base_resolved) or candidate.is_relative_to(cwd_resolved)):
            raise PermissionError(
                f"Absolute workspace.root {raw_root!r} must stay within {base_resolved} or {cwd_resolved}."
            )
    else:
        candidate = (base_resolved / raw_root).resolve()
        if _is_system_root_path(candidate):
            raise PermissionError(f"workspace.root targets protected system directory: {raw_root!r}")
        if not candidate.is_relative_to(base_resolved):
            raise PermissionError(f"Relative workspace.root {raw_root!r} escapes base directory {base_resolved}.")

    return candidate


def _validate_runtime(raw_runtime: Any) -> DispatchRuntimeConfig:
    if raw_runtime is None:
        raw_runtime = {}
    if not isinstance(raw_runtime, dict):
        raise ValueError("runtime section must be a mapping.")

    execution = raw_runtime.get("execution", "local")
    if not isinstance(execution, str) or execution not in ("local", "docker"):
        raise ValueError(f"Unsupported runtime.execution {execution!r}; expected 'local' or 'docker'.")
    scanner_isolation: Literal["host", "docker"] = "host" if execution == "local" else "docker"

    docker_network = _validate_docker_network(raw_runtime.get("docker_network"))

    raw_image = raw_runtime.get("docker_image")
    docker_image: Optional[str] = None
    if raw_image is not None:
        if (
            not isinstance(raw_image, str)
            or raw_image != raw_image.strip()
            or not raw_image.strip()
            or any(ch.isspace() for ch in raw_image)
            or any(m in raw_image for m in _FORBIDDEN_META_CHARS)
            or ".." in raw_image
            or not _DOCKER_IMAGE_RE.fullmatch(raw_image.strip())
            or any(ex in raw_image.lower() for ex in EXCLUDED_SCANNER_STEMS)
        ):
            raise ValueError(f"Invalid or unsafe runtime.docker_image: {raw_image!r}")
        repo_stem = raw_image.strip().split(":", 1)[0].split("@", 1)[0].rsplit("/", 1)[-1].lower()
        if repo_stem in _SHELL_IMAGE_NAMES:
            raise PermissionError(f"Generic shell/OS docker_image blocked: {raw_image!r}")
        docker_image = raw_image.strip()

    raw_offline = raw_runtime.get("offline", False)
    if not isinstance(raw_offline, bool):
        raise ValueError(f"runtime.offline must be a boolean, got {raw_offline!r}.")

    return DispatchRuntimeConfig(
        execution=execution,  # type: ignore[arg-type]
        scanner_isolation=scanner_isolation,
        docker_image=docker_image,
        docker_network=docker_network,
        offline=raw_offline,
    )


def _assert_no_control_or_secret(val: str, *, label: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 0xFFFD for ch in val):
        raise ValueError(f"{label} contains forbidden control or replacement characters.")
    if _RAW_SECRET_VALUE_RE.search(val):
        raise ValueError(f"{label} appears to contain a hardcoded secret/API key; use an environment variable name instead.")
    return val


def _validate_escalation(raw_escalation: Any, *, label: str = "escalation") -> DispatchEscalationConfig:
    """
    Strictly validates optional `escalation` / `workers.escalation` configuration.
    Enforces local-only default (`frontier_api_opt_in=False`), rejects raw API keys
    in YAML, rejects `-coder` model suffixes, and validates budget fraction & POE gate.
    """
    if raw_escalation is None:
        return DispatchEscalationConfig()
    if not isinstance(raw_escalation, dict):
        raise ValueError(f"{label} section must be a mapping.")

    for raw_key in raw_escalation.keys():
        if not isinstance(raw_key, str):
            raise ValueError(f"{label} keys must be strings, got {raw_key!r}.")
        low_key = raw_key.strip().lower()
        if low_key in _FORBIDDEN_SECRET_KEYS or ("secret" in low_key or "password" in low_key or "api_key" in low_key or "apikey" in low_key):
            raise ValueError(
                f"{label}.{raw_key} is forbidden: raw API keys/secrets must never be stored in swarm_dispatch.yaml; "
                "use frontier_api_env_var with an environment variable name instead."
            )
        if raw_key not in _ALLOWED_ESCALATION_KEYS:
            raise ValueError(
                f"Unsupported key {label}.{raw_key!r}; allowed keys: {sorted(_ALLOWED_ESCALATION_KEYS)}."
            )

    enabled = raw_escalation.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError(f"{label}.enabled must be a boolean, got {enabled!r}.")

    raw_frac = raw_escalation.get("max_escalation_fraction", 0.05)
    if isinstance(raw_frac, bool) or not isinstance(raw_frac, (int, float)):
        raise ValueError(f"{label}.max_escalation_fraction must be a float in (0.0, 1.0], got {raw_frac!r}.")
    max_frac = float(raw_frac)
    if not math.isfinite(max_frac) or max_frac <= 0.0 or max_frac > 1.0:
        raise ValueError(f"{label}.max_escalation_fraction must be finite and in (0.0, 1.0], got {raw_frac!r}.")

    raw_min_poe = raw_escalation.get("min_poe_for_escalation", 1)
    if isinstance(raw_min_poe, bool) or not isinstance(raw_min_poe, int) or not (1 <= raw_min_poe <= 3):
        raise ValueError(f"{label}.min_poe_for_escalation must be an integer in [1, 3], got {raw_min_poe!r}.")

    def _validate_local_model(raw_val: Any, field_name: str) -> Optional[str]:
        if raw_val is None:
            return None
        if not isinstance(raw_val, str) or not raw_val.strip():
            raise ValueError(f"{label}.{field_name} must be a non-empty string or null.")
        cleaned = _assert_no_control_or_secret(raw_val.strip(), label=f"{label}.{field_name}")
        if _CODER_SUFFIX_RE.search(cleaned):
            raise ValueError(
                f"{label}.{field_name} must not use '-coder' model suffixes (causes silent Ollama 404 aborts): {cleaned!r}"
            )
        return cleaned

    fast_local_model = _validate_local_model(raw_escalation.get("fast_local_model"), "fast_local_model")
    strong_local_model = _validate_local_model(raw_escalation.get("strong_local_model"), "strong_local_model")

    frontier_opt_in = raw_escalation.get("frontier_api_opt_in", False)
    if not isinstance(frontier_opt_in, bool):
        raise ValueError(f"{label}.frontier_api_opt_in must be a boolean, got {frontier_opt_in!r}.")

    raw_provider = raw_escalation.get("frontier_provider")
    raw_fmodel = raw_escalation.get("frontier_model")
    raw_env_var = raw_escalation.get("frontier_api_env_var")

    if not frontier_opt_in:
        if any(v is not None for v in (raw_provider, raw_fmodel, raw_env_var)):
            raise PermissionError(
                f"{label}: frontier_provider, frontier_model, and frontier_api_env_var are strictly rejected "
                "when frontier_api_opt_in is false (local-only default)."
            )
        return DispatchEscalationConfig(
            enabled=enabled,
            fast_local_model=fast_local_model,
            max_escalation_fraction=max_frac,
            min_poe_for_escalation=raw_min_poe,
            strong_local_model=strong_local_model,
            frontier_api_opt_in=False,
            frontier_provider=None,
            frontier_model=None,
            frontier_api_env_var=None,
        )

    # frontier_api_opt_in == True: all three frontier settings are mandatory and strictly validated
    if not isinstance(raw_provider, str) or not raw_provider.strip():
        raise ValueError(f"{label}.frontier_provider is required when frontier_api_opt_in is true.")
    frontier_provider = _assert_no_control_or_secret(raw_provider.strip().lower(), label=f"{label}.frontier_provider")
    if frontier_provider not in _VALID_FRONTIER_PROVIDERS:
        raise ValueError(
            f"Unsupported {label}.frontier_provider {raw_provider!r}; expected one of {sorted(_VALID_FRONTIER_PROVIDERS)}."
        )

    if not isinstance(raw_fmodel, str) or not raw_fmodel.strip():
        raise ValueError(f"{label}.frontier_model is required when frontier_api_opt_in is true.")
    frontier_model = _assert_no_control_or_secret(raw_fmodel.strip(), label=f"{label}.frontier_model")

    if not isinstance(raw_env_var, str) or not raw_env_var.strip():
        raise ValueError(f"{label}.frontier_api_env_var is required when frontier_api_opt_in is true.")
    frontier_env_var = _assert_no_control_or_secret(raw_env_var.strip(), label=f"{label}.frontier_api_env_var")
    if not _ENV_VAR_NAME_RE.fullmatch(frontier_env_var):
        raise ValueError(
            f"{label}.frontier_api_env_var must be an uppercase environment variable name (e.g. 'ANTHROPIC_API_KEY'), "
            f"never a raw API key: {frontier_env_var!r}"
        )

    return DispatchEscalationConfig(
        enabled=enabled,
        fast_local_model=fast_local_model,
        max_escalation_fraction=max_frac,
        min_poe_for_escalation=raw_min_poe,
        strong_local_model=strong_local_model,
        frontier_api_opt_in=True,
        frontier_provider=frontier_provider,
        frontier_model=frontier_model,
        frontier_api_env_var=frontier_env_var,
    )


def _validate_workers(raw_workers: Any) -> DispatchWorkersConfig:
    if raw_workers is None:
        raw_workers = {}
    if not isinstance(raw_workers, dict):
        raise ValueError("workers section must be a mapping.")

    backend = raw_workers.get("backend", "all")
    if not isinstance(backend, str) or backend not in _VALID_BACKENDS:
        raise ValueError(f"Unsupported workers.backend {backend!r}; expected one of {sorted(_VALID_BACKENDS)}.")

    concurrency = raw_workers.get("concurrency", 8)
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency < 1:
        raise ValueError(f"workers.concurrency must be an integer >= 1, got {concurrency!r}.")

    artex_workers = raw_workers.get("artex_workers", 3)
    if isinstance(artex_workers, bool) or not isinstance(artex_workers, int) or artex_workers < 1:
        raise ValueError(f"workers.artex_workers must be an integer >= 1, got {artex_workers!r}.")

    use_fusion = raw_workers.get("use_fusion", True)
    if not isinstance(use_fusion, bool):
        raise ValueError(f"workers.use_fusion must be a boolean, got {use_fusion!r}.")

    approval_mode = raw_workers.get("approval_mode", "policy")
    if not isinstance(approval_mode, str) or approval_mode not in _VALID_APPROVAL_MODES:
        raise ValueError(
            f"Unsupported workers.approval_mode {approval_mode!r}; expected one of {sorted(_VALID_APPROVAL_MODES)}."
        )

    noise_profile = raw_workers.get("noise_profile")
    if noise_profile is not None:
        if not isinstance(noise_profile, str) or noise_profile not in _VALID_NOISE_PROFILES:
            raise ValueError(
                f"Unsupported workers.noise_profile {noise_profile!r}; expected one of {sorted(_VALID_NOISE_PROFILES)}."
            )

    preferred_model = raw_workers.get("preferred_model")
    if preferred_model is not None:
        if not isinstance(preferred_model, str) or "\x00" in preferred_model or not preferred_model.strip():
            raise ValueError("workers.preferred_model must be a non-empty string or null.")
        preferred_model = preferred_model.strip()

    sec_model = raw_workers.get("sec_model")
    if sec_model is not None:
        if not isinstance(sec_model, str) or "\x00" in sec_model or not sec_model.strip():
            raise ValueError("workers.sec_model must be a non-empty string or null.")
        sec_model = sec_model.strip()

    escalation_cfg = _validate_escalation(raw_workers.get("escalation"), label="workers.escalation")

    return DispatchWorkersConfig(
        backend=backend,  # type: ignore[arg-type]
        concurrency=concurrency,
        artex_workers=artex_workers,
        preferred_model=preferred_model,
        sec_model=sec_model,
        use_fusion=use_fusion,
        approval_mode=approval_mode,  # type: ignore[arg-type]
        noise_profile=noise_profile,
        escalation=escalation_cfg,
    )


def _validate_targets(raw_targets: Any) -> List[DispatchTargetConfig]:
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ValueError("targets must be a non-empty list of target entries.")

    validated: List[DispatchTargetConfig] = []
    for idx, item in enumerate(raw_targets):
        if not isinstance(item, dict):
            raise ValueError(f"targets[{idx}] must be a mapping.")

        raw_name = item.get("name")
        if not isinstance(raw_name, str) or not raw_name.strip() or "\x00" in raw_name:
            raise ValueError(f"targets[{idx}].name must be a non-empty string.")
        name = raw_name.strip()

        raw_host = item.get("host")
        if not isinstance(raw_host, str) or not raw_host.strip() or "\x00" in raw_host:
            raise ValueError(f"targets[{idx}].host must be a non-empty string.")
        host = raw_host.strip()

        raw_port = item.get("port", 8080)
        if isinstance(raw_port, bool) or not isinstance(raw_port, int) or not (1 <= raw_port <= 65535):
            raise ValueError(f"targets[{idx}].port must be an integer in [1, 65535], got {raw_port!r}.")

        raw_tls = item.get("tls", False)
        if not isinstance(raw_tls, bool):
            raise ValueError(f"targets[{idx}].tls must be a boolean, got {raw_tls!r}.")

        raw_auth = item.get("authorized", False)
        if not isinstance(raw_auth, bool):
            raise ValueError(f"targets[{idx}].authorized must be a boolean, got {raw_auth!r}.")

        # Fail-closed SSRF + TargetAuthorizationGate check BEFORE any directory or DB creation.
        ok, reason = validate_and_authorize_target(host, authorized=raw_auth)
        if not ok:
            raise PermissionError(f"targets[{idx}] ({name}) rejected: {reason}")

        has_explicit_modes = "modes" in item and item.get("modes") is not None
        raw_modes = item.get("modes", ["all"])
        if raw_modes is None:
            raw_modes = ["all"]
        if not isinstance(raw_modes, list) or not raw_modes:
            raise ValueError(f"targets[{idx}].modes must be a non-empty list of mode strings.")
        modes: List[str] = []
        for m in raw_modes:
            if not isinstance(m, str) or m.strip() not in _VALID_TARGET_MODES:
                raise ValueError(
                    f"targets[{idx}].modes contains unsupported mode {m!r}; allowed: {sorted(_VALID_TARGET_MODES)}."
                )
            modes.append(m.strip())

        raw_rfcs = item.get("rfcs", ["9112"])
        if raw_rfcs is None:
            raw_rfcs = ["9112"]
        if not isinstance(raw_rfcs, list) or not raw_rfcs:
            raise ValueError(f"targets[{idx}].rfcs must be a non-empty list of RFC IDs.")
        rfcs: List[str] = []
        for r in raw_rfcs:
            if isinstance(r, bool) or not isinstance(r, (str, int)):
                raise ValueError(f"targets[{idx}].rfcs contains invalid RFC entry {r!r}.")
            r_str = str(r).strip().replace("RFC-", "").replace("RFC", "")
            if not r_str or "\x00" in r_str:
                raise ValueError(f"targets[{idx}].rfcs contains empty/invalid RFC entry {r!r}.")
            rfcs.append(r_str)

        repo = item.get("repo")
        if repo is not None:
            if not isinstance(repo, str) or "\x00" in repo:
                raise ValueError(f"targets[{idx}].repo must be a valid string or null.")

        path_val = item.get("path")
        if path_val is not None:
            if not isinstance(path_val, str) or "\x00" in path_val:
                raise ValueError(f"targets[{idx}].path must be a valid string or null.")

        task_id = item.get("task_id")
        if task_id is not None:
            if not isinstance(task_id, str) or not task_id.strip() or "\x00" in task_id:
                raise ValueError(f"targets[{idx}].task_id must be a non-empty string or null.")
            task_id = task_id.strip()

        validated.append(
            DispatchTargetConfig(
                name=name,
                host=host,
                port=raw_port,
                tls=raw_tls,
                authorized=raw_auth,
                modes=modes,
                rfcs=rfcs,
                repo=repo,
                path=path_val,
                task_id=task_id,
                modes_explicit=has_explicit_modes,
            )
        )
    return validated


def load_dispatch_config(
    config_path: Union[str, Path],
    *,
    base_dir: Optional[Path] = None,
) -> SwarmDispatchConfig:
    """
    Loads and strictly validates a Cairn-style `swarm_dispatch.yaml` file using `yaml.safe_load()`.
    Raises ValueError, PermissionError, FileNotFoundError, or yaml.YAMLError before creating any dirs or DBs.
    """
    p = Path(config_path)
    if not p.is_file():
        raise FileNotFoundError(f"Dispatch config file not found: {p}")

    raw_text = p.read_text(encoding="utf-8-sig")
    doc = yaml.safe_load(raw_text)
    if not isinstance(doc, dict):
        raise ValueError("Dispatch config root must be a YAML mapping.")

    version = doc.get("version")
    if type(version) is not int or version != 1:
        raise ValueError(f"Unsupported dispatch config version {version!r}; expected integer 1.")

    runtime_cfg = _validate_runtime(doc.get("runtime"))
    raw_workers = doc.get("workers")
    has_workers_esc = isinstance(raw_workers, dict) and raw_workers.get("escalation") is not None
    has_top_esc = doc.get("escalation") is not None
    if has_workers_esc and has_top_esc:
        raise ValueError(
            "Ambiguous escalation config: specify either top-level 'escalation' or 'workers.escalation', not both."
        )
    workers_cfg = _validate_workers(raw_workers)
    if has_top_esc:
        escalation_cfg = _validate_escalation(doc.get("escalation"), label="escalation")
        workers_cfg.escalation = escalation_cfg
    else:
        escalation_cfg = workers_cfg.escalation

    raw_ws = doc.get("workspace")
    if raw_ws is None:
        raw_ws = {}
    if not isinstance(raw_ws, dict):
        raise ValueError("workspace section must be a mapping.")

    raw_root = raw_ws.get("root", ".swarm_workspaces")
    effective_base = base_dir.resolve() if base_dir is not None else p.resolve().parent
    resolved_root = _validate_workspace_root(raw_root, base_dir=effective_base)

    per_target_iso = raw_ws.get("per_target_isolation", True)
    if not isinstance(per_target_iso, bool):
        raise ValueError(f"workspace.per_target_isolation must be a boolean, got {per_target_iso!r}.")

    workspace_cfg = DispatchWorkspaceConfig(
        root=raw_root,
        resolved_root=resolved_root,
        per_target_isolation=per_target_iso,
    )
    targets_cfg = _validate_targets(doc.get("targets"))

    return SwarmDispatchConfig(
        version=1,
        runtime=runtime_cfg,
        workers=workers_cfg,
        workspace=workspace_cfg,
        targets=targets_cfg,
        source_path=p.resolve(),
        escalation=escalation_cfg,
    )


# =============================================================================
# Runtime Free RAM / VRAM Sizing & TieredModelRouter (AIxCC Upgrade #2)
# =============================================================================


def probe_runtime_free_memory(*, check_gpu: Optional[bool] = None) -> RuntimeMemorySnapshot:
    """
    Measures **runtime free/available** RAM (GB) and free VRAM (MB) — NEVER total physical RAM.
    Uses `psutil.virtual_memory().available` when available, falling back to OS-native free-memory APIs,
    and queries `nvidia-smi` for `memory.free` (`shell=False`, <=400ms timeout) when GPU probing is enabled.
    """
    free_ram_gb: Optional[float] = None
    ram_source = "fallback"

    try:
        import psutil  # type: ignore[import-untyped]

        vm = psutil.virtual_memory()
        avail = getattr(vm, "available", None)
        if avail is not None and float(avail) > 0:
            free_ram_gb = float(avail) / (1024 ** 3)
            ram_source = "psutil.virtual_memory.available"
    except Exception:
        pass

    if free_ram_gb is None:
        try:
            if os.name == "nt":
                import ctypes

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                    free_ram_gb = float(stat.ullAvailPhys) / (1024 ** 3)
                    ram_source = "win32.GlobalMemoryStatusEx.ullAvailPhys"
            elif os.path.isfile("/proc/meminfo"):
                with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("MemAvailable:"):
                            kb = int(line.split()[1])
                            free_ram_gb = kb / (1024 ** 2)
                            ram_source = "proc.meminfo.MemAvailable"
                            break
            elif sys.platform == "darwin":
                proc = subprocess.run(
                    ["vm_stat"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=0.4,
                    check=False,
                    shell=False,
                )
                if proc.returncode == 0 and proc.stdout:
                    page_size = 4096
                    m_ps = re.search(r"page size of (\d+) bytes", proc.stdout)
                    if m_ps:
                        page_size = int(m_ps.group(1))
                    free_pages = 0
                    for key in ("Pages free", "Pages inactive", "Pages speculative"):
                        m_pg = re.search(rf"{key}:\s+(\d+)", proc.stdout)
                        if m_pg:
                            free_pages += int(m_pg.group(1))
                    if free_pages > 0:
                        free_ram_gb = (free_pages * page_size) / (1024 ** 3)
                        ram_source = "darwin.vm_stat"
        except Exception:
            pass

    if free_ram_gb is None or not math.isfinite(free_ram_gb) or free_ram_gb < 0.0:
        free_ram_gb = 4.0
        ram_source = "conservative_fallback"

    if check_gpu is None:
        in_test_or_offline = (
            os.environ.get("RFCHUNT_OFFLINE") == "1"
            or "PYTEST_CURRENT_TEST" in os.environ
            or bool(os.environ.get("CI"))
        )
        check_gpu = not in_test_or_offline

    free_vram_mb = 0.0
    vram_source = "none"
    if check_gpu:
        nv_smi = shutil.which("nvidia-smi")
        if nv_smi:
            try:
                creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
                proc = subprocess.run(
                    [nv_smi, "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=0.4,
                    check=False,
                    shell=False,
                    creationflags=creation_flags,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    vals: List[float] = []
                    for ln in proc.stdout.splitlines():
                        tok = ln.strip().split(",")[0].strip()
                        try:
                            v = float(tok)
                            if math.isfinite(v) and v >= 0.0:
                                vals.append(v)
                        except ValueError:
                            continue
                    if vals:
                        free_vram_mb = max(vals)
                        vram_source = "nvidia-smi.memory.free"
            except Exception:
                pass

    return RuntimeMemorySnapshot(
        free_ram_gb=free_ram_gb,
        free_vram_mb=free_vram_mb,
        ram_source=ram_source,
        vram_source=vram_source,
    )


def size_model_for_free_memory(free_ram_gb: float, free_vram_mb: float = 0.0) -> str:
    """
    Sizes local Ollama model strictly by **runtime free/available memory**
    (NEVER total physical RAM, NEVER appends `-coder` suffixes).
    """
    ram = max(0.0, float(free_ram_gb))
    vram = max(0.0, float(free_vram_mb))
    if ram >= 48.0 or vram >= 24576.0:
        return "qwen2.5:32b"
    if ram >= 24.0 or vram >= 14336.0:
        return "qwen2.5:14b"
    if ram >= 12.0 or vram >= 4608.0:
        return "qwen2.5:7b"
    if ram >= 6.0 or vram >= 2048.0:
        return "qwen2.5:3b"
    return "qwen2.5:1.5b"


def size_fast_local_model_for_free_memory(free_ram_gb: float, free_vram_mb: float = 0.0) -> str:
    """
    Sizes fast triage local Ollama model strictly by runtime free/available memory,
    capped at 14B so bulk triage remains responsive (NEVER `-coder` suffixes).
    """
    ram = max(0.0, float(free_ram_gb))
    vram = max(0.0, float(free_vram_mb))
    if ram >= 24.0 or vram >= 14336.0:
        return "qwen2.5:14b"
    if ram >= 12.0 or vram >= 4608.0:
        return "qwen2.5:7b"
    if ram >= 6.0 or vram >= 2048.0:
        return "qwen2.5:3b"
    return "qwen2.5:1.5b"


def model_fits_free_memory(model_name: str, free_ram_gb: float, free_vram_mb: float = 0.0) -> bool:
    """
    Checks whether a configured local model's parameter scale fits safely inside
    runtime free RAM (GB) or free VRAM (MB).
    """
    m = _MODEL_PARAM_SIZE_RE.search(model_name or "")
    if not m:
        return True
    try:
        params_b = float(m.group(1))
    except ValueError:
        return True

    ram = max(0.0, float(free_ram_gb))
    vram = max(0.0, float(free_vram_mb))
    if params_b >= 65.0:
        return ram >= 64.0 or vram >= 40960.0
    if params_b >= 26.0:
        return ram >= 48.0 or vram >= 24576.0
    if params_b >= 12.0:
        return ram >= 24.0 or vram >= 14336.0
    if params_b >= 7.0:
        return ram >= 12.0 or vram >= 4608.0
    if params_b >= 3.0:
        return ram >= 6.0 or vram >= 2048.0
    return True


class TieredModelRouter:
    """
    Ranks candidate anomalies / multi-file taint slices and routes them across:
      1. Tier 1 (`fast_local`): default runtime-free-memory-safe local Ollama model for bulk triage.
      2. Tier 2 (`strong_local`): stronger local Ollama model (when runtime free RAM/VRAM allows)
         for the top `max_escalation_fraction` (default 5%) high-signal candidates satisfying
         `POE >= min_poe_for_escalation` (default `POE >= 1`).
      3. Tier 3 (`frontier_api`): strictly opt-in (`frontier_api_opt_in=True`), online-only,
         env-var authenticated frontier provider when explicitly configured.
    """

    def __init__(
        self,
        config: Optional[DispatchEscalationConfig] = None,
        *,
        offline: bool = False,
        memory_probe: Optional[Callable[[], RuntimeMemorySnapshot]] = None,
        frontier_invoker: Optional[Callable[..., str]] = None,
        local_invoker: Optional[Callable[..., str]] = None,
    ) -> None:
        self.config = config or DispatchEscalationConfig()
        self.offline = bool(offline or os.environ.get("RFCHUNT_OFFLINE") == "1")
        self._memory_probe = memory_probe or probe_runtime_free_memory
        self._frontier_invoker = frontier_invoker
        self._local_invoker = local_invoker

    def _get_memory_snapshot(
        self,
        free_ram_gb: Optional[float] = None,
        free_vram_mb: Optional[float] = None,
    ) -> RuntimeMemorySnapshot:
        if free_ram_gb is not None:
            return RuntimeMemorySnapshot(
                free_ram_gb=max(0.0, float(free_ram_gb)),
                free_vram_mb=max(0.0, float(free_vram_mb or 0.0)),
                ram_source="override",
                vram_source="override" if free_vram_mb is not None else "none",
            )
        return self._memory_probe()

    def resolve_models(
        self,
        mem: Optional[RuntimeMemorySnapshot] = None,
    ) -> Dict[str, Any]:
        """Resolves memory-safe fast and strong local models from runtime free RAM/VRAM."""
        snap = mem or self._get_memory_snapshot()
        safe_fast = size_fast_local_model_for_free_memory(snap.free_ram_gb, snap.free_vram_mb)
        safe_strong = size_model_for_free_memory(snap.free_ram_gb, snap.free_vram_mb)

        fast_model = safe_fast
        fast_downgraded = False
        if self.config.fast_local_model and self.config.fast_local_model.lower() != "auto":
            if _CODER_SUFFIX_RE.search(self.config.fast_local_model):
                fast_downgraded = True
            elif model_fits_free_memory(self.config.fast_local_model, snap.free_ram_gb, snap.free_vram_mb):
                fast_model = self.config.fast_local_model
            else:
                fast_downgraded = True

        strong_model = safe_strong
        strong_downgraded = False
        if self.config.strong_local_model and self.config.strong_local_model.lower() != "auto":
            if _CODER_SUFFIX_RE.search(self.config.strong_local_model):
                strong_downgraded = True
            elif model_fits_free_memory(self.config.strong_local_model, snap.free_ram_gb, snap.free_vram_mb):
                strong_model = self.config.strong_local_model
            else:
                strong_downgraded = True

        return {
            "fast_local_model": fast_model,
            "strong_local_model": strong_model,
            "fast_downgraded_for_memory": fast_downgraded,
            "strong_downgraded_for_memory": strong_downgraded,
            "free_ram_gb": snap.free_ram_gb,
            "free_vram_mb": snap.free_vram_mb,
        }

    @staticmethod
    def _normalize_candidate(item: Any, idx: int) -> Dict[str, Any]:
        if hasattr(item, "to_escalation_candidate") and callable(item.to_escalation_candidate):
            raw = item.to_escalation_candidate()
        elif isinstance(item, dict):
            raw = dict(item)
        else:
            raw = {"candidate_id": f"cand-{idx}", "title": str(item)}

        cid = str(
            raw.get("candidate_id")
            or raw.get("slice_id")
            or raw.get("chain_id")
            or raw.get("anomaly_id")
            or raw.get("id")
            or raw.get("rule_id")
            or f"cand-{idx + 1}"
        )
        raw_poe = raw.get("poe_level", raw.get("poe_hint", raw.get("poe", 0)))
        try:
            poe_level = max(0, int(raw_poe))
        except (TypeError, ValueError):
            poe_level = 0

        sev = str(raw.get("severity") or "MEDIUM").strip().upper()
        if sev not in _SEVERITY_WEIGHTS:
            sev = "MEDIUM"

        files = raw.get("files_involved") or []
        if not isinstance(files, list):
            files = []
        is_multi_file = bool(raw.get("is_multi_file_chain") or raw.get("is_cross_file") or len(files) >= 2)
        if not is_multi_file and int(raw.get("hop_count", 0) or 0) >= 2:
            is_multi_file = True

        san_status = str(raw.get("sanitizer_status") or "unsanitized").strip().lower()
        try:
            sig_score = float(raw.get("signal_score", raw.get("taint_confidence", raw.get("confidence", 0.5))))
            if not math.isfinite(sig_score):
                sig_score = 0.5
        except (TypeError, ValueError):
            sig_score = 0.5
        sig_score = max(0.0, min(1.0, sig_score))

        # Composite ranking score for selecting top 1-5% escalation candidates
        poe_bonus = {0: 0.0, 1: 0.15, 2: 0.30}.get(poe_level, 0.45)
        san_adj = 0.15 if san_status == "unsanitized" else (0.10 if san_status == "weak_sanitizer" else -0.10)
        chain_bonus = 0.20 if is_multi_file else 0.0
        rank_score = round(_SEVERITY_WEIGHTS[sev] + poe_bonus + chain_bonus + san_adj + (0.35 * sig_score), 4)

        return {
            "candidate_id": cid,
            "poe_level": poe_level,
            "severity": sev,
            "is_multi_file_chain": is_multi_file,
            "sanitizer_status": san_status,
            "signal_score": sig_score,
            "rank_score": rank_score,
            "orig_index": idx,
        }

    def _frontier_ready(self) -> Tuple[bool, str]:
        if not self.config.frontier_api_opt_in:
            return False, "local_only_default"
        if self.offline:
            return False, "offline_mode_fallback_local"
        if not (self.config.frontier_provider and self.config.frontier_model and self.config.frontier_api_env_var):
            return False, "frontier_incomplete_config_fallback_local"
        if not os.environ.get(self.config.frontier_api_env_var, "").strip():
            return False, "frontier_env_var_unset_fallback_local"
        return True, "frontier_opt_in_active"

    def rank_and_route(
        self,
        candidates: Sequence[Any],
        *,
        free_ram_gb: Optional[float] = None,
        free_vram_mb: Optional[float] = None,
    ) -> RoutingPlan:
        """
        Ranks candidates and enforces the top `max_escalation_fraction` (default 5%)
        budget cap plus `POE >= min_poe_for_escalation` (default 1) gate.
        """
        snap = self._get_memory_snapshot(free_ram_gb=free_ram_gb, free_vram_mb=free_vram_mb)
        resolved = self.resolve_models(snap)
        fast_model = str(resolved["fast_local_model"])
        strong_model = str(resolved["strong_local_model"])
        strong_downgraded = bool(resolved["strong_downgraded_for_memory"])
        fast_downgraded = bool(resolved["fast_downgraded_for_memory"])

        normalized = [self._normalize_candidate(c, i) for i, c in enumerate(candidates)]
        total = len(normalized)
        eligible = [
            c for c in normalized if self.config.enabled and c["poe_level"] >= self.config.min_poe_for_escalation
        ]

        if not self.config.enabled or total == 0 or not eligible:
            budget = 0
        else:
            raw_cap = math.floor(total * self.config.max_escalation_fraction)
            # For small batches (< 1/fraction, e.g. <20 items at 5%), allow at most 1 top POE>=1 item
            budget = min(len(eligible), max(1, raw_cap))

        ranked_eligible = sorted(
            eligible,
            key=lambda c: (-c["rank_score"], -c["poe_level"], c["orig_index"]),
        )
        escalated_ids = {c["candidate_id"] for c in ranked_eligible[:budget]}

        frontier_ok, frontier_status = self._frontier_ready()
        paid_cfg = None
        try:
            from engine.paid_model_provider import load_paid_model_config

            _pcfg = load_paid_model_config()
            if _pcfg.enabled:
                paid_cfg = _pcfg
        except Exception:
            paid_cfg = None

        decisions: List[ModelRoutingDecision] = []

        for c in normalized:
            cid = c["candidate_id"]
            if cid in escalated_ids:
                if paid_cfg is not None:
                    decisions.append(
                        ModelRoutingDecision(
                            candidate_id=cid,
                            tier="frontier_api",
                            model=paid_cfg.arbiter_model or paid_cfg.primary_model,
                            provider=paid_cfg.provider,
                            escalated=True,
                            rank_score=c["rank_score"],
                            poe_level=c["poe_level"],
                            reason="top_signal_poe_gate_passed:env_local_paid_models_active",
                            free_ram_gb=snap.free_ram_gb,
                            free_vram_mb=snap.free_vram_mb,
                            downgraded_for_memory=False,
                        )
                    )
                elif frontier_ok:
                    decisions.append(
                        ModelRoutingDecision(
                            candidate_id=cid,
                            tier="frontier_api",
                            model=str(self.config.frontier_model),
                            provider=str(self.config.frontier_provider),
                            escalated=True,
                            rank_score=c["rank_score"],
                            poe_level=c["poe_level"],
                            reason=f"top_signal_poe_gate_passed:{frontier_status}",
                            free_ram_gb=snap.free_ram_gb,
                            free_vram_mb=snap.free_vram_mb,
                            downgraded_for_memory=False,
                        )
                    )
                else:
                    reason = (
                        f"top_signal_poe_gate_passed:{frontier_status}"
                        if not strong_downgraded
                        else f"top_signal_poe_gate_passed:{frontier_status}:downgraded_for_free_memory"
                    )
                    decisions.append(
                        ModelRoutingDecision(
                            candidate_id=cid,
                            tier="strong_local",
                            model=strong_model,
                            provider="ollama",
                            escalated=True,
                            rank_score=c["rank_score"],
                            poe_level=c["poe_level"],
                            reason=reason,
                            free_ram_gb=snap.free_ram_gb,
                            free_vram_mb=snap.free_vram_mb,
                            downgraded_for_memory=strong_downgraded,
                        )
                    )
            else:
                if not self.config.enabled:
                    reason = "escalation_disabled"
                elif c["poe_level"] < self.config.min_poe_for_escalation:
                    reason = f"below_min_poe_gate(poe={c['poe_level']}<{self.config.min_poe_for_escalation})"
                else:
                    reason = "outside_escalation_budget"
                if paid_cfg is not None:
                    decisions.append(
                        ModelRoutingDecision(
                            candidate_id=cid,
                            tier="frontier_api",
                            model=paid_cfg.primary_model,
                            provider=paid_cfg.provider,
                            escalated=False,
                            rank_score=c["rank_score"],
                            poe_level=c["poe_level"],
                            reason=f"{reason}:env_local_paid_models_active",
                            free_ram_gb=snap.free_ram_gb,
                            free_vram_mb=snap.free_vram_mb,
                            downgraded_for_memory=False,
                        )
                    )
                else:
                    decisions.append(
                        ModelRoutingDecision(
                            candidate_id=cid,
                            tier="fast_local",
                            model=fast_model,
                            provider="ollama",
                            escalated=False,
                            rank_score=c["rank_score"],
                            poe_level=c["poe_level"],
                            reason=reason,
                            free_ram_gb=snap.free_ram_gb,
                            free_vram_mb=snap.free_vram_mb,
                            downgraded_for_memory=fast_downgraded,
                        )
                    )

        return RoutingPlan(
            decisions=decisions,
            total_candidates=total,
            eligible_candidates=len(eligible),
            escalation_budget=budget,
            escalated_count=len(escalated_ids),
            fast_local_model=fast_model,
            strong_local_model=strong_model,
            frontier_enabled=frontier_ok,
            free_ram_gb=snap.free_ram_gb,
            free_vram_mb=snap.free_vram_mb,
        )

    route_candidates = rank_and_route

    def invoke_decision(
        self,
        decision: ModelRoutingDecision,
        system_prompt: str,
        user_prompt: str,
        *,
        ollama_endpoint: str = "http://127.0.0.1:11434",
        timeout: float = 60.0,
    ) -> Dict[str, Any]:
        """
        Executes a routed model decision. Strictly enforces `frontier_api_opt_in`
        before any external frontier API call and keeps default execution 100% local.
        """
        if decision.tier == "frontier_api":
            if not self.config.frontier_api_opt_in:
                raise PermissionError(
                    "Refused frontier API invocation: frontier_api_opt_in is false (local-only default)."
                )
            if self.offline:
                raise PermissionError("Refused frontier API invocation while runtime offline mode is enabled.")
            env_var = self.config.frontier_api_env_var or ""
            api_key = os.environ.get(env_var, "").strip()
            if not api_key:
                raise PermissionError(
                    f"Refused frontier API invocation: environment variable {env_var!r} is not set."
                )

            if self._frontier_invoker is not None:
                text = self._frontier_invoker(
                    provider=decision.provider,
                    model=decision.model,
                    api_key=api_key,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
                return {
                    "tier": decision.tier,
                    "provider": decision.provider,
                    "model": decision.model,
                    "response": text,
                }

            import httpx

            provider = decision.provider.lower()
            with httpx.Client(timeout=httpx.Timeout(float(timeout), connect=10.0)) as client:
                if provider == "anthropic":
                    resp = client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": api_key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={
                            "model": decision.model,
                            "max_tokens": 2048,
                            "system": system_prompt,
                            "messages": [{"role": "user", "content": user_prompt}],
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    blocks = data.get("content") or []
                    text = "".join(str(b.get("text", "")) for b in blocks if isinstance(b, dict))
                elif provider in ("google", "gemini"):
                    resp = client.post(
                        f"https://generativelanguage.googleapis.com/v1beta/models/{decision.model}:generateContent",
                        headers={"x-goog-api-key": api_key, "content-type": "application/json"},
                        json={
                            "system_instruction": {"parts": [{"text": system_prompt}]},
                            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    cands = data.get("candidates") or []
                    parts = (((cands[0].get("content") or {}).get("parts")) or []) if cands else []
                    text = "".join(str(p.get("text", "")) for p in parts if isinstance(p, dict))
                else:
                    base_url = (
                        "https://openrouter.ai/api/v1/chat/completions"
                        if provider == "openrouter"
                        else "https://api.openai.com/v1/chat/completions"
                    )
                    resp = client.post(
                        base_url,
                        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                        json={
                            "model": decision.model,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt},
                            ],
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    choices = data.get("choices") or []
                    text = str(((choices[0].get("message") or {}).get("content")) or "") if choices else ""

            return {
                "tier": decision.tier,
                "provider": decision.provider,
                "model": decision.model,
                "response": text,
            }

        # Local Ollama tier (`fast_local` or `strong_local`)
        if self._local_invoker is not None:
            text = self._local_invoker(
                model=decision.model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                endpoint=ollama_endpoint,
            )
            return {
                "tier": decision.tier,
                "provider": "ollama",
                "model": decision.model,
                "response": text,
            }

        import httpx

        norm_ep = (ollama_endpoint or "http://127.0.0.1:11434").rstrip("/")
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        with httpx.Client(timeout=httpx.Timeout(float(timeout), connect=5.0)) as client:
            resp = client.post(
                f"{norm_ep}/api/chat",
                json={
                    "model": decision.model,
                    "messages": messages,
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()
        msg = data.get("message") if isinstance(data, dict) else None
        msg_content = str(msg.get("content") or "").strip() if isinstance(msg, dict) else ""
        content = msg_content or str((data.get("response") if isinstance(data, dict) else "") or "").strip()
        return {
            "tier": decision.tier,
            "provider": "ollama",
            "model": decision.model,
            "response": content,
        }


def _sanitize_target_slug(target: DispatchTargetConfig) -> str:
    raw = f"{target.name}_{target.host}_{target.port}"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")
    if not slug:
        slug = "target"
    stem = slug.split(".", 1)[0].upper()
    if stem in _WIN_RESERVED_NAMES:
        slug = f"target_{slug}"
    return slug


def _validate_cli_override_path(raw_override: str, *, label: str) -> Path:
    _check_safe_path_tokens(raw_override, label=label)
    candidate = Path(raw_override).resolve()
    if _is_system_root_path(candidate):
        raise PermissionError(f"{label} override targets protected system directory: {raw_override!r}")
    return candidate


def resolve_target_workspace(
    workspace_cfg: DispatchWorkspaceConfig,
    target: DispatchTargetConfig,
    *,
    db_override: Optional[str] = None,
    output_dir_override: Optional[str] = None,
    create: bool = True,
    target_count: int = 1,
) -> TargetWorkspacePaths:
    """Resolves isolated per-target workspace paths safely inside `workspace_cfg.resolved_root`."""
    slug = _sanitize_target_slug(target)
    root_resolved = workspace_cfg.resolved_root.resolve()

    if workspace_cfg.per_target_isolation:
        ws_dir = (root_resolved / slug).resolve()
        if not ws_dir.is_relative_to(root_resolved):
            raise PermissionError(f"Target workspace {ws_dir} escapes workspace root {root_resolved}.")
    else:
        ws_dir = root_resolved

    scope_multi_overrides = bool(workspace_cfg.per_target_isolation and int(target_count or 1) > 1)
    if db_override:
        base_db = _validate_cli_override_path(db_override, label="--db")
        if scope_multi_overrides:
            db_suffix = base_db.suffix or ".db"
            db_path = base_db.with_name(f"{base_db.stem}_{slug}{db_suffix}")
        else:
            db_path = base_db
    else:
        db_path = ws_dir / "terminator.db"

    if output_dir_override:
        base_out = _validate_cli_override_path(output_dir_override, label="--output-dir")
        reports_dir = (base_out / slug) if scope_multi_overrides else base_out
    else:
        reports_dir = ws_dir / "reports"
    harness2_runs_dir = ws_dir / "runs" / "harness2"
    dream_export_path = ws_dir / "dream_policies.json"
    dashboard_out = ws_dir / "terminator_dashboard.html"
    caldera_export_dir = ws_dir / "caldera_export"

    if create:
        ws_dir.mkdir(parents=True, exist_ok=True)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

    return TargetWorkspacePaths(
        slug=slug,
        workspace_dir=ws_dir,
        db_path=db_path,
        reports_dir=reports_dir,
        harness2_runs_dir=harness2_runs_dir,
        dream_export_path=dream_export_path,
        dashboard_out=dashboard_out,
        caldera_export_dir=caldera_export_dir,
    )


def _persist_dispatch_all_facts(
    db: Database,
    *,
    task_id: str,
    target: DispatchTargetConfig,
    res: Dict[str, Any],
) -> None:
    """Writes run summary and top findings as FACT rows onto the target's blackboard."""
    total_findings = int(res.get("total_aggregated_findings", 0) or 0)
    chains_count = int(res.get("chains_synthesized", 0) or 0)
    db.add_fact(
        f"Unified --all scan completed for {target.host}:{target.port} "
        f"(findings={total_findings}, chains={chains_count})",
        node_id=f"fact:all_scan:{task_id}:{target.name}",
        task_id=task_id,
        domain="global",
        source_agent="swarm_dispatcher",
        payload={
            "target": res.get("target_path") or f"{target.host}:{target.port}",
            "host": target.host,
            "port": target.port,
            "total_findings": total_findings,
            "chains_synthesized": chains_count,
            "severity_counts": res.get("severity_counts") or {},
        },
    )
    findings = res.get("findings") or []
    for idx, finding in enumerate(findings[:50]):
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or finding.get("rule_id") or finding.get("description") or f"finding-{idx+1}")
        severity = str(finding.get("severity") or "INFO")
        db.add_fact(
            f"[{severity}] {title}",
            node_id=f"fact:all_finding:{task_id}:{target.name}:{idx}",
            task_id=task_id,
            domain="global",
            source_agent="swarm_dispatcher",
            payload={
                "rule_id": finding.get("rule_id"),
                "severity": severity,
                "cwe": finding.get("cwe"),
                "file_path": finding.get("file_path") or finding.get("file"),
                "capability_class": finding.get("capability_class"),
                "endpoint": finding.get("endpoint"),
            },
        )


def _resolve_target_backend(
    backend: str,
    target: DispatchTargetConfig,
) -> str:
    target_modes = set(target.modes) if target.modes_explicit else {backend}
    if (
        (backend == "all" and (not target.modes_explicit or "all" in target_modes or "all_scans" in target_modes))
        or (("all" in target_modes or "all_scans" in target_modes) and backend != "swarm")
    ):
        return "all"
    if backend == "mantis" or "mantis" in target_modes:
        return "mantis"
    if backend == "artex" or "artex" in target_modes:
        return "artex"
    return "swarm"


def _validate_dispatch_extra_hints(extra_args: Optional[Any]) -> None:
    if extra_args is None or getattr(extra_args, "hint", None) is None:
        return
    raw_h = getattr(extra_args, "hint", None)
    if not isinstance(raw_h, str) or not raw_h.strip() or "\x00" in raw_h:
        raise ValueError("--hint must be a non-empty string without NUL bytes.")
    try:
        prio_val = float(getattr(extra_args, "hint_priority", 10.0))
    except (TypeError, ValueError) as exc:
        raise ValueError("--hint-priority must be a finite numeric value.") from exc
    if not math.isfinite(prio_val):
        raise ValueError("--hint-priority must be finite.")
    for fld_name in ("hint_domain", "hint_task_id", "hint_rfc"):
        raw_fld = getattr(extra_args, fld_name, None)
        if raw_fld is not None and "\x00" in str(raw_fld):
            raise ValueError(f"--{fld_name.replace('_', '-')} must not contain NUL bytes.")


def _call_hint_persister(
    hint_persister: Callable[..., str],
    extra_args: Any,
    db: Database,
    *,
    target_task_id: str,
) -> str:
    try:
        sig = inspect.signature(hint_persister)
        accepts_tid = "target_task_id" in sig.parameters or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )
    except (TypeError, ValueError):
        accepts_tid = False
    if accepts_tid:
        return hint_persister(extra_args, db, target_task_id=target_task_id)
    return hint_persister(extra_args, db)


def execute_dispatch(
    config: SwarmDispatchConfig,
    *,
    db_override: Optional[str] = None,
    output_dir_override: Optional[str] = None,
    extra_args: Optional[Any] = None,
    hint_persister: Optional[Callable[..., str]] = None,
) -> List[Dict[str, Any]]:
    """
    Executes validated dispatch targets with per-target workspace isolation,
    runtime isolation mapping (`local`->`host`, `docker`->`docker`), and
    crash-resilient `reclaim_stale_intents()` recovery on resume.
    """
    _validate_dispatch_extra_hints(extra_args)

    _approval_deny = str(config.workers.approval_mode or "policy").strip().lower() == "deny"
    if _approval_deny and not config.runtime.offline:
        for _t in config.targets:
            if _resolve_target_backend(config.workers.backend, _t) == "swarm":
                raise PermissionError(
                    f"Target '{_t.name}' cannot run live 'swarm' probing under approval_mode='deny' "
                    "unless runtime.offline is true."
                )

    prev_offline = os.environ.get("RFCHUNT_OFFLINE")
    if config.runtime.offline:
        os.environ["RFCHUNT_OFFLINE"] = "1"

    results: List[Dict[str, Any]] = []
    target_count = len(config.targets)
    try:
        for target in config.targets:
            ws = resolve_target_workspace(
                config.workspace,
                target,
                db_override=db_override,
                output_dir_override=output_dir_override,
                create=True,
                target_count=target_count,
            )
            target_task_id = str(
                target.task_id or getattr(extra_args, "task_id", None) or "default"
            ).strip() or "default"

            db = Database(str(ws.db_path))
            reclaimed_count = 0
            try:
                reclaimed_count = db.reclaim_stale_intents(task_id=target_task_id)
                if getattr(extra_args, "hint", None) is not None:
                    if hint_persister is not None:
                        _call_hint_persister(hint_persister, extra_args, db, target_task_id=target_task_id)
                    else:
                        explicit_dests = getattr(extra_args, "_explicit_cli_dests", None)
                        if isinstance(explicit_dests, (set, frozenset)):
                            if "hint_task_id" in explicit_dests:
                                hint_tid = str(getattr(extra_args, "hint_task_id", None) or target_task_id).strip() or target_task_id
                            elif "task_id" in explicit_dests:
                                hint_tid = str(getattr(extra_args, "task_id", None) or target_task_id).strip() or target_task_id
                            else:
                                hint_tid = target_task_id
                        else:
                            hint_tid = str(getattr(extra_args, "hint_task_id", None) or target_task_id).strip() or target_task_id
                        db.add_hint(
                            str(getattr(extra_args, "hint")),
                            priority=float(getattr(extra_args, "hint_priority", 10.0)),
                            task_id=hint_tid,
                            domain=str(getattr(extra_args, "hint_domain", "global") or "global"),
                            rfc_id=str(getattr(extra_args, "hint_rfc", "") or ""),
                            source_agent="cli",
                            active=True,
                        )
            finally:
                db.close()

            backend = config.workers.backend
            target_modes = set(target.modes) if target.modes_explicit else {backend}
            resolved_backend = _resolve_target_backend(backend, target)
            if resolved_backend == "all":
                from engine.mantis_integrator import DEFAULT_ABLITERATED_MODEL, run_unified_all_scans

                db_all = Database(str(ws.db_path))
                try:
                    preferred_model = (
                        config.workers.preferred_model
                        or getattr(extra_args, "mantis_model", None)
                        or DEFAULT_ABLITERATED_MODEL
                    )
                    artex_live_arg = (
                        False
                        if (_approval_deny or bool(getattr(extra_args, "no_artex_live", False)))
                        else getattr(extra_args, "artex_live", None)
                    )
                    res = run_unified_all_scans(
                        repo=target.repo or getattr(extra_args, "repo", None),
                        path=target.path or getattr(extra_args, "path", None),
                        host=target.host,
                        port=int(target.port),
                        use_tls=bool(target.tls),
                        authorized=bool(target.authorized),
                        allow_destructive=bool(getattr(extra_args, "allow_destructive", False)),
                        depth=int(getattr(extra_args, "depth", None) or 100),
                        mantis_mode=getattr(extra_args, "mantis_mode", "full") or "full",
                        use_fusion=bool(config.workers.use_fusion),
                        preferred_model=preferred_model,
                        db=db_all,
                        reports_dir=str(ws.reports_dir),
                        artex_rounds=max(1, int(getattr(extra_args, "artex_rounds", 1) or 1)),
                        artex_noise_profile=config.workers.noise_profile,
                        artex_workers=config.workers.artex_workers,
                        artex_live=artex_live_arg,
                        approval_mode=config.workers.approval_mode,
                        quiet=bool(getattr(extra_args, "as_json", False)),
                        enable_external_scanners=bool(getattr(extra_args, "enable_external_scanners", False)),
                        httpx_scan=getattr(extra_args, "httpx_scan", None),
                        katana_scan=getattr(extra_args, "katana_scan", None),
                        nuclei_scan=getattr(extra_args, "nuclei_scan", None),
                        nuclei_tags=getattr(extra_args, "nuclei_tags", None),
                        scanner_isolation=config.runtime.scanner_isolation,
                        docker_image=config.runtime.docker_image,
                        docker_network=config.runtime.docker_network,
                        enable_rea=not bool(getattr(extra_args, "no_rea", False)),
                        auto_install_tools=bool(getattr(extra_args, "auto_install", True)),
                    )
                    _persist_dispatch_all_facts(db_all, task_id=target_task_id, target=target, res=res)
                finally:
                    db_all.close()

                esc_router = TieredModelRouter(
                    config.escalation,
                    offline=config.runtime.offline,
                    memory_probe=lambda: probe_runtime_free_memory(check_gpu=False),
                )
                esc_plan = esc_router.rank_and_route(res.get("findings") or [])

                results.append(
                    {
                        "target": target.name,
                        "host": target.host,
                        "port": target.port,
                        "backend": "all",
                        "scanner_isolation": config.runtime.scanner_isolation,
                        "workspace_dir": str(ws.workspace_dir),
                        "db_path": str(ws.db_path),
                        "reports_dir": str(ws.reports_dir),
                        "reclaimed_intents": reclaimed_count,
                        "escalation_plan": esc_plan.to_dict(),
                        "result": res,
                    }
                )
            elif resolved_backend == "mantis":
                from engine.mantis_integrator import DEFAULT_ABLITERATED_MODEL, MantisIntegrator

                db_m = Database(str(ws.db_path))
                try:
                    integrator = MantisIntegrator(
                        db=db_m,
                        reports_dir=str(ws.reports_dir),
                        use_fusion=bool(config.workers.use_fusion),
                        preferred_model=config.workers.preferred_model or DEFAULT_ABLITERATED_MODEL,
                        sec_model=config.workers.sec_model,
                    )
                    m_target = target.repo or target.path or "."
                    res = integrator.run_scan(
                        target_path=str(m_target),
                        depth=int(getattr(extra_args, "depth", None) or 30),
                        mode=getattr(extra_args, "mantis_mode", "full") or "full",
                    )
                    db_m.add_fact(
                        f"Mantis scan completed for {target.name} (findings={res.get('total_findings', 0)})",
                        node_id=f"fact:dispatch:mantis:{target_task_id}:{target.name}",
                        task_id=target_task_id,
                        domain="global",
                        source_agent="swarm_dispatcher",
                        payload={"total_findings": res.get("total_findings", 0)},
                    )
                finally:
                    db_m.close()

                results.append(
                    {
                        "target": target.name,
                        "host": target.host,
                        "port": target.port,
                        "backend": "mantis",
                        "scanner_isolation": config.runtime.scanner_isolation,
                        "workspace_dir": str(ws.workspace_dir),
                        "db_path": str(ws.db_path),
                        "reports_dir": str(ws.reports_dir),
                        "reclaimed_intents": reclaimed_count,
                        "result": res,
                    }
                )
            elif backend == "artex" or "artex" in target_modes:
                from engine.dual_graph_engine import DualGraphAttackEngine

                db_a = Database(str(ws.db_path))
                try:
                    eng = DualGraphAttackEngine(
                        db=db_a,
                        reports_dir=str(ws.reports_dir),
                        task_id=target_task_id,
                        noise_profile=config.workers.noise_profile,
                        workers=config.workers.artex_workers,
                    )
                    eng.ingest_target_infrastructure(host=target.host, port=target.port, endpoints=["/"])
                    eng.ingest_from_database(db_a)
                    res = eng.run_attack_chain_cycle(round_num=max(1, int(getattr(extra_args, "artex_rounds", 1) or 1)))
                    db_a.add_fact(
                        f"ARTEX cycle completed for {target.host}:{target.port} (chains={res.get('chains_synthesized', 0)})",
                        node_id=f"fact:dispatch:artex:{target_task_id}:{target.name}",
                        task_id=target_task_id,
                        domain="global",
                        source_agent="swarm_dispatcher",
                        payload={"chains_synthesized": res.get("chains_synthesized", 0)},
                    )
                finally:
                    db_a.close()

                results.append(
                    {
                        "target": target.name,
                        "host": target.host,
                        "port": target.port,
                        "backend": "artex",
                        "scanner_isolation": config.runtime.scanner_isolation,
                        "workspace_dir": str(ws.workspace_dir),
                        "db_path": str(ws.db_path),
                        "reports_dir": str(ws.reports_dir),
                        "reclaimed_intents": reclaimed_count,
                        "result": res,
                    }
                )
            else:
                from rfc_hunt_swarm import ProtocolResearchSwarm

                preferred_model = config.workers.preferred_model or getattr(
                    extra_args, "model", "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
                )
                sec_model = config.workers.sec_model or getattr(extra_args, "sec_model", None)
                swarm = ProtocolResearchSwarm(
                    host=target.host,
                    port=target.port,
                    db_path=str(ws.db_path),
                    sec_model=sec_model,
                    use_tls=target.tls,
                    concurrency=config.workers.concurrency,
                    preferred_model=preferred_model,
                    use_fusion=config.workers.use_fusion,
                )
                if getattr(extra_args, "cache_dir", None):
                    swarm.fetcher.cache_dir = Path(str(extra_args.cache_dir))

                rfc_outputs: List[Dict[str, Any]] = []
                try:
                    swarm.db.reclaim_stale_intents(task_id=target_task_id)
                    graph = swarm.build_graph()
                    rfcs_to_run = list(target.rfcs)
                    if "terminator" in target_modes:
                        rfcs_to_run = swarm.fetcher.get_terminator_corpus(
                            max_rfcs=getattr(extra_args, "max_rfcs", None)
                        )
                    elif "corpus" in target_modes:
                        rfcs_to_run = swarm.fetcher.get_kettle_corpus(
                            max_rfcs=getattr(extra_args, "max_rfcs", None) or 138
                        )
                    elif "pqc" in target_modes:
                        rfcs_to_run = swarm.fetcher.get_pqc_corpus()

                    max_cycles = int(getattr(extra_args, "cycles", 1) or 1)
                    enable_dream_rsi = bool(getattr(extra_args, "dream_rsi", False)) if extra_args is not None else False
                    enable_harness2 = bool(getattr(extra_args, "enable_harness2", False)) if extra_args is not None else False
                    raw_h2_domain = str(getattr(extra_args, "harness2_domain", "auto") or "auto").strip()
                    run_domain = "" if raw_h2_domain.lower() in ("", "auto") else raw_h2_domain

                    for rfc_item in rfcs_to_run:
                        rfc_num_str = str(rfc_item).replace("RFC-", "").replace("RFC", "")
                        state_in = {
                            "rfc_num": rfc_num_str,
                            "rfc_text": "",
                            "fragments": [],
                            "current_fragment": "",
                            "generated_candidates": [],
                            "current_probe": b"",
                            "reward": 0.0,
                            "current_anomaly": None,
                            "current_vuln": None,
                            "novel_technique_found": None,
                            "cascade_results": None,
                            "cycle_count": 0,
                            "max_cycles": max_cycles,
                            "baseline_resp": b"",
                            "enable_dream_rsi": enable_dream_rsi,
                            "dream_rollouts": int(getattr(extra_args, "dream_rollouts", 50) or 50),
                            "current_dream_policy": None,
                            "enable_harness2": enable_harness2,
                            "harness2_k": int(getattr(extra_args, "harness2_k", 1) or 1),
                            "harness2_mode": getattr(extra_args, "harness2_mode", "parallel") or "parallel",
                            "harness2_runs_dir": str(ws.harness2_runs_dir),
                            "harness2_domain": raw_h2_domain,
                            "current_harness2_result": None,
                            "ooda_phase": "Bootstrap",
                            "blackboard_bootstrapped": False,
                            "active_intent_id": None,
                            "active_intent": None,
                            "active_hints": [],
                            "task_id": target_task_id,
                            "workspace_dir": str(ws.workspace_dir),
                            "blackboard_domain": run_domain,
                            "history": [],
                        }
                        out_state = graph.invoke(state_in, {"recursion_limit": 5000})
                        rfc_outputs.append(
                            {
                                "rfc": rfc_num_str,
                                "blackboard_bootstrapped": bool(out_state.get("blackboard_bootstrapped", False)),
                                "ooda_phase": out_state.get("ooda_phase"),
                            }
                        )
                finally:
                    swarm.close()

                results.append(
                    {
                        "target": target.name,
                        "host": target.host,
                        "port": target.port,
                        "backend": "swarm",
                        "scanner_isolation": config.runtime.scanner_isolation,
                        "workspace_dir": str(ws.workspace_dir),
                        "db_path": str(ws.db_path),
                        "reports_dir": str(ws.reports_dir),
                        "reclaimed_intents": reclaimed_count,
                        "rfcs": rfc_outputs,
                    }
                )
    finally:
        if config.runtime.offline:
            if prev_offline is None:
                os.environ.pop("RFCHUNT_OFFLINE", None)
            else:
                os.environ["RFCHUNT_OFFLINE"] = prev_offline

    return results
