"""
Paid / Enterprise LLM Provider & `.env.local` Auto-Router for RFCHunt
======================================================================
Automatically detects paid/enterprise model credentials defined in `.env.local`
and routes RFCHunt inference directly to those paid APIs while completely
bypassing local Ollama health probes, daemon startup, and model pulls.

Design & Security Invariants:
-----------------------------
1. Zero OS / Registry / Global Environment Mutation (`environment_safety.md`):
   - Strictly reads `.env.local` into process-local dataclasses; never mutates
     Windows Registry, system/user `PATH`, or even ambient `os.environ`.
2. Strict `.env.local` Opt-In (Preserves Local Ollama Default):
   - When `.env.local` contains configured paid model credentials, RFCHunt
     activates paid API mode (`enabled=True`, `ollama_bypassed=True`).
   - When `.env.local` is absent or defines no paid credentials (and
     `RFCHUNT_USE_PAID_MODELS` is not explicitly set to `1`), RFCHunt keeps its
     default zero-cost local Ollama backend even if ambient shell variables
     exist (preserving CI and local-only invariants).
   - Passing `--force-ollama` or setting `RFCHUNT_FORCE_OLLAMA=1` (or
     `RFCHUNT_USE_PAID_MODELS=0`) explicitly disables paid routing.
3. Multi-Provider & Heterogeneous Paid Panel Support:
   - Supports Anthropic Claude, OpenAI / OpenAI-compatible enterprise gateways,
     Azure OpenAI, Google Gemini, and OpenRouter.
   - Supports single-provider or heterogeneous multi-provider ModelFusion panels
     (`primary_model`, `sec_model`, `arbiter_model`, `panel_models`).
4. Zero Secret Leakage:
   - Never prints, logs, returns, or serializes raw API keys.
   - Passes Gemini keys via `x-goog-api-key` header (never query string URLs).
   - Scrubs any secret material from error messages before logging/returning.
5. Offline Guard with Safe Loopback Testing:
   - Under `RFCHUNT_OFFLINE=1`, refuses outbound calls to non-loopback hosts,
     while still permitting verified loopback test servers (`127.0.0.1`,
     `localhost`, `::1`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse
import httpx

UnionPath = Union[Path, str]

logger = logging.getLogger("terminator.paid_models")

REPO_ROOT: Path = Path(__file__).resolve().parent.parent

DEFAULT_ANTHROPIC_BASE_URL = "https://api.anthropic.com"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"

DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_OPENAI_MODEL = "gpt-4o"

DEFAULT_AZURE_API_VERSION = "2024-10-21"

DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com"
DEFAULT_GEMINI_MODEL = "gemini-2.5-pro"

DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = "anthropic/claude-3.7-sonnet"

_PLACEHOLDER_VALUES = {
    "",
    "none",
    "null",
    "replace_me",
    "your_api_key",
    "your-api-key",
    "your-api-key-here",
    "your_key_here",
    "changeme",
    "change_me",
    "todo",
    "placeholder",
    "<your_key>",
    "<api_key>",
    "sk-...",
    "sk-ant-...",
    "sk-proj-...",
}

_OLLAMA_DEFAULT_MODEL_MARKERS = (
    "obliterat",
    "abliterat",
    "gemma2:",
    "gemma4:",
    "qwen2.5:",
    "foundation-sec",
    "glm4:",
    "glm-4.7-flash",
    "deepseek-r1:",
    "strix-",
    "hf.co/",
    "huihui_ai/",
    "fenkohq/",
)

_ENV_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _truthy(val: Optional[str]) -> bool:
    return (val or "").strip().lower() in ("1", "true", "yes", "on", "enabled")


def _falsy(val: Optional[str]) -> bool:
    return (val or "").strip().lower() in ("0", "false", "no", "off", "disabled")


def _is_usable_secret(val: Optional[str]) -> bool:
    s = (val or "").strip()
    if not s:
        return False
    low = s.lower()
    if low in _PLACEHOLDER_VALUES:
        return False
    if "replace_me" in low or "your-api-key" in low or "your_api_key" in low:
        return False
    if s.startswith("<") and s.endswith(">"):
        return False
    return True


def mask_api_key(secret: str) -> str:
    """Returns a non-reversible or heavily masked fingerprint suitable for telemetry."""
    s = (secret or "").strip()
    if not s:
        return ""
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]
    if len(s) >= 12:
        return f"{s[:4]}...{s[-4:]} (sha256:{digest})"
    return f"*** (sha256:{digest})"


def sanitize_url_for_log(url: str) -> str:
    """Strips query strings and userinfo from base URLs before logging/serializing."""
    raw = (url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port_part = f":{parsed.port}" if parsed.port else ""
        scheme = parsed.scheme or "https"
        path = parsed.path or ""
        return f"{scheme}://{host}{port_part}{path}"
    except Exception:
        return raw.split("?", 1)[0]


def is_loopback_url(url: str) -> bool:
    """Returns True iff `url` resolves syntactically to a loopback host."""
    try:
        parsed = urlparse((url or "").strip())
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            return False
        if host in ("localhost", "ip6-localhost"):
            return True
        ip = ipaddress.ip_address(host)
        return bool(ip.is_loopback)
    except Exception:
        return False


def is_ollama_model_tag(model: Optional[str]) -> bool:
    """Heuristically identifies default local Ollama model tags vs paid cloud model IDs."""
    m = (model or "").strip().lower()
    if not m or m == "auto":
        return True
    return any(marker in m for marker in _OLLAMA_DEFAULT_MODEL_MARKERS)


def _strip_inline_comment(raw_val: str) -> str:
    """Strips unquoted `# ...` trailing comments while preserving `#` inside quotes."""
    val = raw_val.strip()
    if not val:
        return ""
    if val[0] in ("'", '"'):
        quote = val[0]
        escaped = False
        chars: List[str] = []
        for idx in range(1, len(val)):
            ch = val[idx]
            if escaped:
                if quote == '"':
                    esc_map = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
                    chars.append(esc_map.get(ch, ch))
                else:
                    chars.append("\\" + ch)
                escaped = False
                continue
            if ch == "\\" and quote == '"':
                escaped = True
                continue
            if ch == quote:
                return "".join(chars)
            chars.append(ch)
        return "".join(chars)

    # Unquoted value: strip trailing `# comment` preceded by whitespace
    for idx, ch in enumerate(val):
        if ch == "#" and (idx == 0 or val[idx - 1].isspace()):
            return val[:idx].strip()
    return val


def parse_env_local_file(path: Path) -> Dict[str, str]:
    """Parses a `.env.local` file cleanly into a dict without mutating `os.environ`."""
    values: Dict[str, str] = {}
    if not path or not path.is_file():
        return values
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip()
        val = _strip_inline_comment(m.group(2))
        values[key] = val
    return values


def find_env_local_path(
    env_local_path: Optional[UnionPath] = None,
    *,
    search_dirs: Optional[Sequence[Path]] = None,
) -> Optional[Path]:
    """
    Locates `.env.local` in deterministic priority order:
      1. Explicit `env_local_path` argument
      2. `RFCHUNT_ENV_LOCAL` environment variable (unless set to `none`/`disabled`)
      3. `search_dirs` if explicitly supplied (used in tests)
      4. `Path.cwd() / ".env.local"` and `REPO_ROOT / ".env.local"`
    """
    if env_local_path is not None:
        raw_arg = str(env_local_path).strip()
        if not raw_arg or raw_arg.lower() in ("none", "disabled", "off"):
            return None
        p = Path(raw_arg).expanduser()
        return p.resolve() if p.is_file() else None

    env_override = os.environ.get("RFCHUNT_ENV_LOCAL")
    if env_override is not None:
        clean_ov = env_override.strip()
        if not clean_ov or clean_ov.lower() in ("none", "disabled", "off"):
            return None
        p = Path(clean_ov).expanduser()
        return p.resolve() if p.is_file() else None

    if search_dirs is not None:
        dirs: List[Path] = [Path(d) for d in search_dirs]
    else:
        dirs = [Path.cwd(), REPO_ROOT]

    seen: set = set()
    for d in dirs:
        try:
            cand = (d / ".env.local").resolve()
        except Exception:
            cand = d / ".env.local"
        key = os.path.normcase(str(cand))
        if key in seen:
            continue
        seen.add(key)
        if cand.is_file():
            return cand
    return None


@dataclass(frozen=True)
class PaidProviderEndpoint:
    """Single configured paid model provider loaded from `.env.local`."""

    provider: str  # anthropic | openai | azure_openai | gemini | openrouter | openai_compatible
    api_key: str
    default_model: str
    base_url: str
    api_version: str = ""
    deployment: str = ""
    extra_headers: Dict[str, str] = field(default_factory=dict)

    def to_safe_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "default_model": self.default_model,
            "base_url": sanitize_url_for_log(self.base_url),
            "deployment": self.deployment or None,
            "key_fingerprint": mask_api_key(self.api_key),
        }


@dataclass(frozen=True)
class PaidModelConfig:
    """Resolved paid-model configuration governing Ollama bypass and API routing."""

    enabled: bool = False
    provider: str = "ollama"
    primary_model: str = ""
    sec_model: str = ""
    arbiter_model: str = ""
    panel_models: Tuple[str, ...] = ()
    source_file: Optional[str] = None
    timeout_sec: float = 120.0
    providers: Dict[str, PaidProviderEndpoint] = field(default_factory=dict)
    reason: str = "no_env_local_paid_models"

    @property
    def ollama_bypassed(self) -> bool:
        return bool(self.enabled)

    def all_secrets(self) -> Tuple[str, ...]:
        return tuple(ep.api_key for ep in self.providers.values() if ep.api_key)

    def resolve_provider_for_model(self, model_name: Optional[str]) -> Tuple[PaidProviderEndpoint, str]:
        """
        Maps a model string (optionally provider-prefixed like `anthropic/claude-sonnet-4-20250514`
        or `openai/gpt-4o`) to the right configured `PaidProviderEndpoint` and clean wire model ID.
        """
        if not self.enabled or not self.providers:
            raise RuntimeError("PaidModelConfig is not enabled.")

        raw = (model_name or "").strip()
        default_ep = self.providers.get(self.provider) or next(iter(self.providers.values()))
        if not raw or is_ollama_model_tag(raw):
            return default_ep, (self.primary_model or default_ep.default_model)

        # 1. Explicit provider prefix (`anthropic/...`, `openai/...`, `gemini/...`, `azure/...`, `openrouter/...`)
        if "/" in raw:
            prefix, rest = raw.split("/", 1)
            pl = prefix.strip().lower()
            alias_map = {
                "anthropic": "anthropic",
                "claude": "anthropic",
                "openai": "openai",
                "azure": "azure_openai",
                "azure_openai": "azure_openai",
                "gemini": "gemini",
                "google": "gemini",
                "openrouter": "openrouter",
                "openai_compatible": "openai_compatible",
            }
            target_prov = alias_map.get(pl)
            if target_prov and target_prov in self.providers:
                if target_prov == "openrouter":
                    # OpenRouter expects vendor/model IDs like `anthropic/claude-3.7-sonnet`
                    return self.providers[target_prov], (rest if pl == "openrouter" else raw)
                return self.providers[target_prov], rest.strip() or self.providers[target_prov].default_model

        # 2. Infer provider by well-known model family when multiple providers are configured
        low = raw.lower()
        if low.startswith("claude-") and "anthropic" in self.providers:
            return self.providers["anthropic"], raw
        if (low.startswith(("gpt-", "o1", "o3", "o4", "chatgpt-")) or low in ("o1", "o3", "o4")) and "openai" in self.providers:
            return self.providers["openai"], raw
        if low.startswith("gemini-") and "gemini" in self.providers:
            return self.providers["gemini"], raw
        if "/" in raw and "openrouter" in self.providers:
            return self.providers["openrouter"], raw
        if "azure_openai" in self.providers and raw == self.providers["azure_openai"].deployment:
            return self.providers["azure_openai"], raw

        return default_ep, raw

    def to_safe_dict(self) -> Dict[str, Any]:
        """Returns a secret-free summary safe for JSON reports, CLI banners, and `--dry-run`."""
        return {
            "mode": "paid_api" if self.enabled else "ollama",
            "enabled": bool(self.enabled),
            "using_ollama": not bool(self.enabled),
            "ollama_bypassed": bool(self.enabled),
            "provider": self.provider if self.enabled else "ollama",
            "primary_model": self.primary_model or None,
            "sec_model": self.sec_model or None,
            "arbiter_model": self.arbiter_model or None,
            "panel_models": list(self.panel_models),
            "source_file": self.source_file,
            "providers_configured": {k: v.to_safe_dict() for k, v in self.providers.items()},
            "reason": self.reason,
        }


def _extract_providers(env_map: Dict[str, str]) -> Dict[str, PaidProviderEndpoint]:
    """Extracts all validly configured paid providers from parsed `.env.local` values."""
    providers: Dict[str, PaidProviderEndpoint] = {}

    def _get(*keys: str) -> str:
        for k in keys:
            v = env_map.get(k)
            if v is not None and str(v).strip():
                return str(v).strip()
        return ""

    # 1. Anthropic Claude
    ant_key = _get("ANTHROPIC_API_KEY", "CLAUDE_API_KEY")
    if _is_usable_secret(ant_key):
        providers["anthropic"] = PaidProviderEndpoint(
            provider="anthropic",
            api_key=ant_key,
            default_model=_get("ANTHROPIC_MODEL", "CLAUDE_MODEL") or DEFAULT_ANTHROPIC_MODEL,
            base_url=(_get("ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL") or DEFAULT_ANTHROPIC_BASE_URL).rstrip("/"),
            api_version=_get("ANTHROPIC_VERSION") or DEFAULT_ANTHROPIC_VERSION,
        )

    # 2. OpenAI / OpenAI-Compatible Enterprise Gateway
    oai_key = _get("OPENAI_API_KEY", "PAID_MODEL_API_KEY", "RFCHUNT_PAID_API_KEY", "LLM_API_KEY")
    if _is_usable_secret(oai_key):
        oai_base = (_get("OPENAI_BASE_URL", "OPENAI_API_BASE", "PAID_MODEL_BASE_URL", "RFCHUNT_PAID_BASE_URL", "LLM_BASE_URL") or DEFAULT_OPENAI_BASE_URL).rstrip("/")
        oai_model = _get("OPENAI_MODEL", "PAID_MODEL", "RFCHUNT_PAID_MODEL", "LLM_MODEL") or DEFAULT_OPENAI_MODEL
        prov_key = "openai"
        if _get("OPENAI_API_KEY") == "" and oai_base != DEFAULT_OPENAI_BASE_URL:
            prov_key = "openai_compatible"
        providers[prov_key] = PaidProviderEndpoint(
            provider=prov_key,
            api_key=oai_key,
            default_model=oai_model,
            base_url=oai_base,
        )

    # 3. Azure OpenAI
    az_key = _get("AZURE_OPENAI_API_KEY")
    az_ep = _get("AZURE_OPENAI_ENDPOINT").rstrip("/")
    az_dep = _get("AZURE_OPENAI_DEPLOYMENT", "AZURE_OPENAI_MODEL")
    if _is_usable_secret(az_key) and az_ep and az_dep:
        providers["azure_openai"] = PaidProviderEndpoint(
            provider="azure_openai",
            api_key=az_key,
            default_model=az_dep,
            base_url=az_ep,
            api_version=_get("AZURE_OPENAI_API_VERSION") or DEFAULT_AZURE_API_VERSION,
            deployment=az_dep,
        )

    # 4. Google Gemini
    gem_key = _get("GEMINI_API_KEY", "GOOGLE_API_KEY")
    if _is_usable_secret(gem_key):
        providers["gemini"] = PaidProviderEndpoint(
            provider="gemini",
            api_key=gem_key,
            default_model=_get("GEMINI_MODEL", "GOOGLE_MODEL") or DEFAULT_GEMINI_MODEL,
            base_url=(_get("GEMINI_BASE_URL", "GEMINI_API_BASE") or DEFAULT_GEMINI_BASE_URL).rstrip("/"),
        )

    # 5. OpenRouter
    or_key = _get("OPENROUTER_API_KEY")
    if _is_usable_secret(or_key):
        extra_hdrs: Dict[str, str] = {}
        ref = _get("OPENROUTER_SITE_URL", "OPENROUTER_HTTP_REFERER")
        title = _get("OPENROUTER_APP_NAME", "OPENROUTER_X_TITLE")
        if ref:
            extra_hdrs["HTTP-Referer"] = ref
        if title:
            extra_hdrs["X-Title"] = title
        providers["openrouter"] = PaidProviderEndpoint(
            provider="openrouter",
            api_key=or_key,
            default_model=_get("OPENROUTER_MODEL") or DEFAULT_OPENROUTER_MODEL,
            base_url=(_get("OPENROUTER_BASE_URL") or DEFAULT_OPENROUTER_BASE_URL).rstrip("/"),
            extra_headers=extra_hdrs,
        )

    return providers


def _parse_csv_models(raw: str) -> List[str]:
    out: List[str] = []
    for tok in (raw or "").split(","):
        s = tok.strip()
        if s and s not in out:
            out.append(s)
    return out


def load_paid_model_config(
    *,
    env_local_path: Optional[UnionPath] = None,
    search_dirs: Optional[Sequence[Path]] = None,
    force_ollama: bool = False,
) -> PaidModelConfig:
    """
    Loads `.env.local` and returns a `PaidModelConfig`.
    If `.env.local` configures one or more paid providers (and neither `--force-ollama`
    nor `RFCHUNT_USE_PAID_MODELS=0` is set), returns `PaidModelConfig(enabled=True, ...)`
    so all RFCHunt LLM components bypass Ollama and invoke paid models directly.
    """
    if force_ollama or _truthy(os.environ.get("RFCHUNT_FORCE_OLLAMA")):
        return PaidModelConfig(enabled=False, reason="forced_ollama")

    if _falsy(os.environ.get("RFCHUNT_USE_PAID_MODELS")):
        return PaidModelConfig(enabled=False, reason="disabled_by_env_toggle")

    resolved_path = find_env_local_path(env_local_path=env_local_path, search_dirs=search_dirs)
    env_map: Dict[str, str] = {}
    source_file: Optional[str] = None

    if resolved_path is not None:
        env_map = parse_env_local_file(resolved_path)
        source_file = str(resolved_path)
    elif _truthy(os.environ.get("RFCHUNT_USE_PAID_MODELS")):
        # Explicit opt-in via environment variable when no `.env.local` file exists
        env_map = dict(os.environ)
        source_file = "process_env(RFCHUNT_USE_PAID_MODELS=1)"
    else:
        return PaidModelConfig(enabled=False, reason="no_env_local_file")

    if _falsy(env_map.get("RFCHUNT_USE_PAID_MODELS")):
        return PaidModelConfig(enabled=False, source_file=source_file, reason="disabled_in_env_local")

    providers = _extract_providers(env_map)
    if not providers:
        return PaidModelConfig(enabled=False, source_file=source_file, reason="no_paid_models_in_env_local")

    # Select primary provider
    explicit_prov = (
        env_map.get("RFCHUNT_PAID_PROVIDER")
        or env_map.get("PAID_MODEL_PROVIDER")
        or env_map.get("LLM_PROVIDER")
        or ""
    ).strip().lower()
    prov_alias = {
        "claude": "anthropic",
        "google": "gemini",
        "azure": "azure_openai",
    }
    explicit_prov = prov_alias.get(explicit_prov, explicit_prov)

    priority_order = ("anthropic", "openai", "azure_openai", "gemini", "openrouter", "openai_compatible")
    if explicit_prov and explicit_prov in providers:
        primary_provider = explicit_prov
    else:
        primary_provider = next((p for p in priority_order if p in providers), next(iter(providers.keys())))

    # Build panel models from explicit overrides or configured providers
    explicit_panel = _parse_csv_models(
        env_map.get("RFCHUNT_PAID_MODELS")
        or env_map.get("PAID_MODELS")
        or ""
    )
    explicit_primary = (
        env_map.get("RFCHUNT_PAID_PRIMARY_MODEL")
        or env_map.get("PAID_PRIMARY_MODEL")
        or env_map.get("RFCHUNT_PAID_MODEL")
        or env_map.get("PAID_MODEL")
        or ""
    ).strip()
    explicit_sec = (
        env_map.get("RFCHUNT_PAID_SEC_MODEL")
        or env_map.get("PAID_SEC_MODEL")
        or ""
    ).strip()
    explicit_arbiter = (
        env_map.get("RFCHUNT_PAID_ARBITER_MODEL")
        or env_map.get("PAID_ARBITER_MODEL")
        or ""
    ).strip()

    provider_defaults: List[str] = []
    ordered_prov_keys = [primary_provider] + [p for p in priority_order if p in providers and p != primary_provider]
    for pkey in ordered_prov_keys:
        m = providers[pkey].default_model
        if m and m not in provider_defaults:
            provider_defaults.append(m)

    panel: List[str] = []
    for cand in [explicit_primary, *explicit_panel, explicit_sec, explicit_arbiter, *provider_defaults]:
        if cand and cand not in panel:
            panel.append(cand)

    primary_model = explicit_primary or (explicit_panel[0] if explicit_panel else providers[primary_provider].default_model)
    if explicit_sec:
        sec_model = explicit_sec
    elif len(panel) >= 2:
        sec_model = panel[1]
    else:
        sec_model = primary_model

    if explicit_arbiter:
        arbiter_model = explicit_arbiter
    elif len(panel) >= 3:
        arbiter_model = panel[2]
    elif len(panel) >= 2:
        arbiter_model = panel[1]
    else:
        arbiter_model = primary_model

    # Ensure primary provider aligns with primary_model if primary_model explicitly names another configured provider
    if "/" in primary_model:
        pref = primary_model.split("/", 1)[0].strip().lower()
        pref = prov_alias.get(pref, pref)
        if pref in providers:
            primary_provider = pref
    elif primary_model.lower().startswith("claude-") and "anthropic" in providers:
        primary_provider = "anthropic"
    elif primary_model.lower().startswith(("gpt-", "o1", "o3", "o4")) and "openai" in providers:
        primary_provider = "openai"
    elif primary_model.lower().startswith("gemini-") and "gemini" in providers:
        primary_provider = "gemini"

    timeout_raw = env_map.get("RFCHUNT_PAID_TIMEOUT") or env_map.get("PAID_MODEL_TIMEOUT") or os.environ.get("OLLAMA_TIMEOUT") or "120.0"
    try:
        timeout_sec = float(timeout_raw)
        if timeout_sec <= 0:
            timeout_sec = 120.0
    except ValueError:
        timeout_sec = 120.0

    return PaidModelConfig(
        enabled=True,
        provider=primary_provider,
        primary_model=primary_model,
        sec_model=sec_model,
        arbiter_model=arbiter_model,
        panel_models=tuple(panel),
        source_file=source_file,
        timeout_sec=timeout_sec,
        providers=providers,
        reason="env_local_paid_models_active",
    )


def is_paid_model_active(
    *,
    env_local_path: Optional[UnionPath] = None,
    search_dirs: Optional[Sequence[Path]] = None,
    force_ollama: bool = False,
) -> bool:
    """Convenience predicate returning True whenever `.env.local` paid models supersede Ollama."""
    return load_paid_model_config(
        env_local_path=env_local_path,
        search_dirs=search_dirs,
        force_ollama=force_ollama,
    ).enabled


class PaidModelClient:
    """
    Real HTTP client executing text/JSON completions against configured paid LLM APIs
    (Anthropic, OpenAI / OpenAI-compatible gateways, Azure OpenAI, Google Gemini, OpenRouter).
    """

    def __init__(
        self,
        config: PaidModelConfig,
        *,
        timeout: Optional[float] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.config = config
        self.timeout = float(timeout if (timeout is not None and timeout > 0) else (config.timeout_sec or 120.0))
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=httpx.Timeout(self.timeout, connect=10.0))

    def close(self) -> None:
        if self._owns_client and getattr(self, "client", None) is not None:
            try:
                self.client.close()
            except Exception:
                pass

    def __enter__(self) -> "PaidModelClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _scrub_error(self, exc: Exception) -> str:
        msg = str(exc)
        for secret in self.config.all_secrets():
            if secret and secret in msg:
                msg = msg.replace(secret, "[REDACTED_API_KEY]")
        return msg

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        max_tokens: int = 512,
        temperature: float = 0.2,
        expect_json: bool = True,
    ) -> str:
        """
        Sends a completion request to the paid provider corresponding to `model`.
        Returns the generated text content or `""` on offline block / API error.
        """
        if not self.config.enabled:
            return ""

        endpoint, wire_model = self.config.resolve_provider_for_model(model)

        # Enforce offline guard against external internet hosts while allowing local loopback test servers
        if os.environ.get("RFCHUNT_OFFLINE") == "1" and not is_loopback_url(endpoint.base_url):
            logger.info(
                "[PaidModels] RFCHUNT_OFFLINE=1 set; skipping external paid API call to %s",
                sanitize_url_for_log(endpoint.base_url),
            )
            return ""

        eff_tokens = max(64, int(max_tokens or 512))
        try:
            if endpoint.provider == "anthropic":
                return self._call_anthropic(
                    endpoint,
                    wire_model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=eff_tokens,
                    temperature=temperature,
                )
            if endpoint.provider == "gemini":
                return self._call_gemini(
                    endpoint,
                    wire_model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=eff_tokens,
                    temperature=temperature,
                    expect_json=expect_json,
                )
            if endpoint.provider == "azure_openai":
                return self._call_azure_openai(
                    endpoint,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=eff_tokens,
                    temperature=temperature,
                    expect_json=expect_json,
                )
            return self._call_openai_compatible(
                endpoint,
                wire_model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=eff_tokens,
                temperature=temperature,
                expect_json=expect_json,
            )
        except Exception as exc:
            logger.warning(
                "[PaidModels] Provider '%s' model '%s' call failed: %s",
                endpoint.provider,
                wire_model,
                self._scrub_error(exc),
            )
            return ""

    def _call_openai_compatible(
        self,
        endpoint: PaidProviderEndpoint,
        wire_model: str,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        temperature: float,
        expect_json: bool,
    ) -> str:
        base = endpoint.base_url.rstrip("/")
        url = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
        headers = {
            "Authorization": f"Bearer {endpoint.api_key}",
            "Content-Type": "application/json",
            **endpoint.extra_headers,
        }
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        is_reasoning_o = bool(re.match(r"^o[134](?:-|$)", wire_model.lower()))
        payload: Dict[str, Any] = {
            "model": wire_model,
            "messages": messages,
        }
        if is_reasoning_o:
            payload["max_completion_tokens"] = max_tokens
        else:
            payload["max_tokens"] = max_tokens
            payload["temperature"] = temperature
        if expect_json and not is_reasoning_o:
            payload["response_format"] = {"type": "json_object"}

        resp = self.client.post(url, headers=headers, json=payload)
        if resp.status_code == 400 and "response_format" in payload:
            retry_payload = dict(payload)
            retry_payload.pop("response_format", None)
            resp = self.client.post(url, headers=headers, json=retry_payload)
        if resp.status_code != 200:
            logger.warning(
                "[PaidModels] %s returned HTTP %s for %s",
                endpoint.provider,
                resp.status_code,
                wire_model,
            )
            return ""
        data = resp.json()
        choices = data.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            return ""
        msg = choices[0].get("message") or {}
        content = msg.get("content", "")
        if isinstance(content, list):
            parts = [str(p.get("text", "")) for p in content if isinstance(p, dict) and p.get("text")]
            return "\n".join(parts).strip()
        return str(content or "").strip()

    def _call_azure_openai(
        self,
        endpoint: PaidProviderEndpoint,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        temperature: float,
        expect_json: bool,
    ) -> str:
        base = endpoint.base_url.rstrip("/")
        api_ver = endpoint.api_version or DEFAULT_AZURE_API_VERSION
        url = f"{base}/openai/deployments/{endpoint.deployment}/chat/completions?api-version={api_ver}"
        headers = {
            "api-key": endpoint.api_key,
            "Content-Type": "application/json",
            **endpoint.extra_headers,
        }
        payload: Dict[str, Any] = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if expect_json:
            payload["response_format"] = {"type": "json_object"}
        resp = self.client.post(url, headers=headers, json=payload)
        if resp.status_code == 400 and "response_format" in payload:
            retry_payload = dict(payload)
            retry_payload.pop("response_format", None)
            resp = self.client.post(url, headers=headers, json=retry_payload)
        if resp.status_code != 200:
            logger.warning("[PaidModels] azure_openai returned HTTP %s for %s", resp.status_code, endpoint.deployment)
            return ""
        data = resp.json()
        choices = data.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            return ""
        return str((choices[0].get("message") or {}).get("content", "") or "").strip()

    def _call_anthropic(
        self,
        endpoint: PaidProviderEndpoint,
        wire_model: str,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        base = endpoint.base_url.rstrip("/")
        url = base if base.endswith("/v1/messages") else f"{base}/v1/messages"
        headers = {
            "x-api-key": endpoint.api_key,
            "anthropic-version": endpoint.api_version or DEFAULT_ANTHROPIC_VERSION,
            "content-type": "application/json",
            **endpoint.extra_headers,
        }
        payload: Dict[str, Any] = {
            "model": wire_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        resp = self.client.post(url, headers=headers, json=payload)
        if resp.status_code != 200:
            logger.warning("[PaidModels] anthropic returned HTTP %s for %s", resp.status_code, wire_model)
            return ""
        data = resp.json()
        blocks = data.get("content") or []
        text_parts: List[str] = []
        for blk in blocks:
            if isinstance(blk, dict) and blk.get("type") == "text" and blk.get("text"):
                text_parts.append(str(blk["text"]))
        return "\n".join(text_parts).strip()

    def _call_gemini(
        self,
        endpoint: PaidProviderEndpoint,
        wire_model: str,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        temperature: float,
        expect_json: bool,
    ) -> str:
        base = endpoint.base_url.rstrip("/")
        clean_model = wire_model[len("models/") :] if wire_model.startswith("models/") else wire_model
        url = f"{base}/v1beta/models/{clean_model}:generateContent"
        # Pass API key strictly in header (never in URL query string)
        headers = {
            "x-goog-api-key": endpoint.api_key,
            "Content-Type": "application/json",
            **endpoint.extra_headers,
        }
        gen_cfg: Dict[str, Any] = {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        }
        if expect_json:
            gen_cfg["responseMimeType"] = "application/json"
        payload: Dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": gen_cfg,
        }
        resp = self.client.post(url, headers=headers, json=payload)
        if resp.status_code != 200:
            logger.warning("[PaidModels] gemini returned HTTP %s for %s", resp.status_code, clean_model)
            return ""
        data = resp.json()
        candidates = data.get("candidates") or []
        if not candidates or not isinstance(candidates[0], dict):
            return ""
        parts = ((candidates[0].get("content") or {}).get("parts")) or []
        text_parts = [str(p.get("text", "")) for p in parts if isinstance(p, dict) and p.get("text")]
        return "\n".join(text_parts).strip()
