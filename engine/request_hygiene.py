"""
Global Bounty & Pentest Request Hygiene & Shared Token-Bucket Rate Limiter (R2).

Provides:
  - Repeatable `--header` / `--bounty-header` parsing and CRLF/NUL sanitization.
  - Global `--user-agent` override across raw HTTP/1.1 sockets, HTTP/2 HPACK frames,
    `httpx.Client` sessions, and ProjectDiscovery external scanners (`httpx`, `katana`, `nuclei`).
  - Shared thread-safe `TokenBucketRateLimiter` (`--max-rps`, default `0.0` = unlimited)
    enforcing aggregate request pacing across concurrent threads and subprocess invocations.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_FORBIDDEN_HEADER_CHARS = ("\r", "\n", "\x00")
_PROTECTED_FRAMING_HEADERS = frozenset({"host", "content-length", "transfer-encoding"})


def parse_header_spec(raw: str) -> Tuple[str, str]:
    """
    Parses a single `'Name: Value'` header specification and validates against
    CRLF / NUL injection and RFC 9110 token syntax.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Header specification must be a non-empty 'Name: Value' string.")
    if any(ch in raw for ch in _FORBIDDEN_HEADER_CHARS):
        raise ValueError("Header specification contains forbidden CR/LF/NUL control characters.")
    if ":" not in raw:
        raise ValueError(f"Header specification missing ':' delimiter: {raw!r}")
    name, val = raw.split(":", 1)
    name_s = name.strip()
    val_s = val.strip()
    if not name_s or not _HEADER_NAME_RE.match(name_s):
        raise ValueError(f"Invalid HTTP header name: {name_s!r}")
    return name_s, val_s


def validate_user_agent(user_agent: Optional[str]) -> Optional[str]:
    if user_agent is None:
        return None
    ua = str(user_agent).strip()
    if not ua:
        return None
    if any(ch in ua for ch in _FORBIDDEN_HEADER_CHARS):
        raise ValueError("User-Agent contains forbidden CR/LF/NUL control characters.")
    return ua


class TokenBucketRateLimiter:
    """
    Thread-safe token-bucket rate limiter shared across all concurrent RFCHunt
    senders and external scanner invocations.

    When `max_rps <= 0`, `acquire()` is an immediate zero-overhead no-op returning `0.0`.
    When `max_rps > 0`, the first token is available immediately (`_next_free_time = now`)
    and subsequent acquisitions reserve slots spaced by `1.0 / max_rps` seconds.
    """

    def __init__(self, max_rps: float = 0.0, burst: float = 1.0) -> None:
        rps = float(max_rps or 0.0)
        if math.isnan(rps) or math.isinf(rps) or rps < 0.0:
            raise ValueError(f"--max-rps must be a finite number >= 0, got: {max_rps!r}")
        self.max_rps: float = rps
        self.burst: float = max(1.0, float(burst or 1.0))
        self._lock = threading.Lock()
        self._next_free_time: float = 0.0
        self._acquisitions: int = 0
        self._total_wait_sec: float = 0.0

    @property
    def enabled(self) -> bool:
        return self.max_rps > 0.0

    @property
    def acquisitions(self) -> int:
        with self._lock:
            return self._acquisitions

    @property
    def total_wait_sec(self) -> float:
        with self._lock:
            return self._total_wait_sec

    def acquire(self, tokens: float = 1.0) -> float:
        """
        Reserves `tokens` from the shared bucket and sleeps outside the lock if needed.
        Returns the number of seconds slept (`0.0` when unlimited or immediately available).
        """
        if self.max_rps <= 0.0:
            with self._lock:
                self._acquisitions += 1
            return 0.0

        interval = max(0.0, float(tokens)) / self.max_rps
        with self._lock:
            now = time.monotonic()
            if self._next_free_time <= now:
                wait_sec = 0.0
                self._next_free_time = now + interval
            else:
                wait_sec = self._next_free_time - now
                self._next_free_time += interval
            self._acquisitions += 1
            self._total_wait_sec += wait_sec

        if wait_sec > 0.0:
            time.sleep(wait_sec)
        return wait_sec


@dataclass(frozen=True)
class RequestHygieneConfig:
    """
    Immutable configuration holding custom HTTP headers, User-Agent override,
    and target `--max-rps` rate limit.
    """

    headers: Tuple[Tuple[str, str], ...] = ()
    user_agent: Optional[str] = None
    max_rps: float = 0.0

    @classmethod
    def from_raw(
        cls,
        headers: Optional[Sequence[Union[str, Tuple[str, str]]]] = None,
        bounty_headers: Optional[Sequence[Union[str, Tuple[str, str]]]] = None,
        user_agent: Optional[str] = None,
        max_rps: float = 0.0,
    ) -> "RequestHygieneConfig":
        parsed_pairs: List[Tuple[str, str]] = []
        extracted_ua: Optional[str] = None

        for seq in (headers or (), bounty_headers or ()):
            for item in seq:
                if isinstance(item, tuple) and len(item) == 2:
                    k, v = parse_header_spec(f"{item[0]}: {item[1]}")
                else:
                    k, v = parse_header_spec(str(item))
                if k.lower() == "user-agent":
                    extracted_ua = v
                else:
                    parsed_pairs.append((k, v))

        ua_clean = validate_user_agent(user_agent)
        final_ua = ua_clean if ua_clean is not None else extracted_ua
        rps = float(max_rps or 0.0)
        if math.isnan(rps) or math.isinf(rps) or rps < 0.0:
            raise ValueError(f"--max-rps must be >= 0, got: {max_rps!r}")
        return cls(headers=tuple(parsed_pairs), user_agent=final_ua, max_rps=rps)

    @classmethod
    def from_cli(
        cls,
        headers: Optional[Sequence[Union[str, Tuple[str, str]]]] = None,
        bounty_headers: Optional[Sequence[Union[str, Tuple[str, str]]]] = None,
        user_agent: Optional[str] = None,
        max_rps: float = 0.0,
    ) -> "RequestHygieneConfig":
        return cls.from_raw(
            headers=headers,
            bounty_headers=bounty_headers,
            user_agent=user_agent,
            max_rps=max_rps,
        )

    @property
    def is_active(self) -> bool:
        return bool(self.headers or self.user_agent or self.max_rps > 0.0)

    def to_headers_dict(
        self,
        base: Optional[Dict[str, str]] = None,
        *,
        default_ua: Optional[str] = None,
    ) -> Dict[str, str]:
        """Merges `base` headers with configured custom headers and `User-Agent`."""
        out: Dict[str, str] = dict(base or {})
        for k, v in self.headers:
            # Replace existing case-insensitive match if present
            existing_key = next((ek for ek in out if ek.lower() == k.lower()), None)
            if existing_key is not None and existing_key != k:
                del out[existing_key]
            out[k] = v

        effective_ua = self.user_agent or default_ua
        if effective_ua:
            existing_ua = next((ek for ek in out if ek.lower() == "user-agent"), None)
            if self.user_agent is not None or existing_ua is None:
                if existing_ua is not None and existing_ua != "User-Agent":
                    del out[existing_ua]
                out["User-Agent"] = effective_ua
        return out

    def to_cli_header_pairs(self) -> List[Tuple[str, str]]:
        """Returns `(name, value)` pairs for `-H 'Name: Value'` external scanner flags."""
        pairs = list(self.headers)
        if self.user_agent:
            pairs.append(("User-Agent", self.user_agent))
        return pairs

    def inject_raw_http1(
        self,
        raw_bytes: bytes,
        *,
        default_ua: Optional[str] = None,
    ) -> bytes:
        """
        Non-destructively injects custom headers and `User-Agent` into raw HTTP/1.1
        wire bytes before the `\r\n\r\n` terminator while preserving request line,
        `Host`, `Content-Length`, `Transfer-Encoding`, and body bytes verbatim.
        """
        if not raw_bytes or (not self.headers and not self.user_agent and not default_ua):
            return raw_bytes

        sep = b"\r\n\r\n"
        line_sep = b"\r\n"
        idx = raw_bytes.find(sep)
        if idx == -1:
            sep = b"\n\n"
            line_sep = b"\n"
            idx = raw_bytes.find(sep)
            if idx == -1:
                return raw_bytes

        head_block = raw_bytes[:idx]
        body_block = raw_bytes[idx + len(sep) :]
        raw_lines = head_block.split(line_sep)
        if not raw_lines:
            return raw_bytes

        req_line = raw_lines[0]
        # Only inject into plausible HTTP/1.x request lines
        if b"HTTP/" not in req_line:
            return raw_bytes

        header_lines = list(raw_lines[1:])
        effective_ua = self.user_agent or default_ua

        # Filter or replace User-Agent if an explicit User-Agent override is configured
        filtered_lines: List[bytes] = []
        custom_names_lower = {
            k.lower().encode("latin-1", errors="ignore")
            for k, _ in self.headers
            if k.lower() not in _PROTECTED_FRAMING_HEADERS
        }
        saw_ua = False
        for hline in header_lines:
            colon = hline.find(b":")
            if colon != -1:
                hname_low = hline[:colon].strip().lower()
                if hname_low == b"user-agent":
                    if self.user_agent is not None:
                        filtered_lines.append(
                            f"User-Agent: {self.user_agent}".encode("latin-1", errors="replace")
                        )
                        saw_ua = True
                        continue
                    saw_ua = True
                elif hname_low in custom_names_lower:
                    continue
            filtered_lines.append(hline)

        if effective_ua and not saw_ua:
            filtered_lines.append(f"User-Agent: {effective_ua}".encode("latin-1", errors="replace"))

        for k, v in self.headers:
            if k.lower() in _PROTECTED_FRAMING_HEADERS:
                continue
            filtered_lines.append(f"{k}: {v}".encode("latin-1", errors="replace"))

        rebuilt_head = line_sep.join([req_line, *filtered_lines])
        return rebuilt_head + sep + body_block


_ACTIVE_LOCK = threading.Lock()
_ACTIVE_HYGIENE: RequestHygieneConfig = RequestHygieneConfig()
_ACTIVE_LIMITER: Optional[TokenBucketRateLimiter] = None


def set_active_hygiene(
    config: Optional[RequestHygieneConfig],
    limiter: Optional[TokenBucketRateLimiter] = None,
) -> None:
    """Sets process-wide active hygiene config and shared token-bucket rate limiter."""
    global _ACTIVE_HYGIENE, _ACTIVE_LIMITER
    with _ACTIVE_LOCK:
        _ACTIVE_HYGIENE = config if config is not None else RequestHygieneConfig()
        if limiter is not None:
            _ACTIVE_LIMITER = limiter
        elif _ACTIVE_HYGIENE.max_rps > 0.0:
            _ACTIVE_LIMITER = TokenBucketRateLimiter(_ACTIVE_HYGIENE.max_rps)
        else:
            _ACTIVE_LIMITER = None


def get_active_hygiene() -> Tuple[RequestHygieneConfig, Optional[TokenBucketRateLimiter]]:
    """Returns `(active_hygiene_config, active_rate_limiter)`."""
    with _ACTIVE_LOCK:
        return _ACTIVE_HYGIENE, _ACTIVE_LIMITER


def set_active_rate_limiter(limiter: Optional[TokenBucketRateLimiter]) -> None:
    """Sets process-wide active shared token-bucket rate limiter."""
    global _ACTIVE_LIMITER
    with _ACTIVE_LOCK:
        _ACTIVE_LIMITER = limiter


def get_active_rate_limiter() -> Optional[TokenBucketRateLimiter]:
    """Returns process-wide active shared token-bucket rate limiter."""
    with _ACTIVE_LOCK:
        return _ACTIVE_LIMITER


def resolve_rate_limiter(rate_limiter: Optional[TokenBucketRateLimiter] = None) -> Optional[TokenBucketRateLimiter]:
    """Resolves explicit `rate_limiter` or falls back to process-wide active limiter."""
    _, lim = resolve_hygiene(None, rate_limiter)
    return lim


def resolve_hygiene(
    hygiene_config: Optional[RequestHygieneConfig] = None,
    rate_limiter: Optional[TokenBucketRateLimiter] = None,
) -> Tuple[RequestHygieneConfig, Optional[TokenBucketRateLimiter]]:
    """Resolves explicit `hygiene_config` / `rate_limiter` or falls back to active process state."""
    if isinstance(hygiene_config, tuple) and len(hygiene_config) == 2:
        hygiene_config, rate_limiter = hygiene_config[0], (rate_limiter or hygiene_config[1])
    active_cfg, active_lim = get_active_hygiene()
    cfg = hygiene_config if hygiene_config is not None else active_cfg
    lim = rate_limiter if rate_limiter is not None else active_lim
    if lim is None and cfg.max_rps > 0.0:
        lim = TokenBucketRateLimiter(cfg.max_rps)
    return cfg, lim


def acquire_rate_limit(
    rate_limiter: Optional[TokenBucketRateLimiter] = None,
    tokens: float = 1.0,
) -> float:
    """Null-safe rate limit acquisition using explicit or active `TokenBucketRateLimiter`."""
    _, lim = resolve_hygiene(None, rate_limiter)
    if lim is not None:
        return lim.acquire(tokens=tokens)
    return 0.0


@dataclass(frozen=True)
class ProgramComplianceContext:
    """
    Single fail-closed per-program HackerOne Rules-of-Engagement (RoE) compliance contract.
    Enforces:
      1. `ProgramEligibilityDB.is_eligible(handle)` (`UNLOCKED` and `submission_state == 'open'`)
      2. Tier 1 `roe_automated_prohibited` hard block (static OSS review only; zero live traffic)
      3. Strict DNS label-boundary in-scope/out-of-scope host allowlist + SSRF validation
      4. Fractional sub-1 RPS `TokenBucketRateLimiter` (never rounding 0.5 RPS up to 1 RPS)
      5. Exact program-mandated custom headers & `User-Agent` (zero hardcoded usernames)
      6. `follow_redirects = False` (`no_out_of_scope_redirects = True`)
      7. Explicit in-scope AI/LLM adversarial testing gate (`ai_testing_allowed`)
    """

    program_handle: str
    eligible: bool
    live_allowed: bool
    ai_testing_allowed: bool
    reason: str
    automation_tier: str
    automated_prohibited: bool
    effective_max_rps: float
    hygiene: RequestHygieneConfig
    rate_limiter: Optional[TokenBucketRateLimiter]
    in_scope_assets: Tuple[str, ...] = ()
    in_scope_repos: Tuple[str, ...] = ()
    out_of_scope_assets: Tuple[str, ...] = ()
    no_out_of_scope_redirects: bool = True
    ai_disclosure_required: bool = False

    def authorize_scope_host(
        self,
        host_or_url: str,
        *,
        allow_loopback: bool = True,
        require_declared_scope: bool = False,
    ) -> Tuple[bool, str]:
        """
        Fail-closed offline scope & IP-SSRF check for already-collected recon assets,
        JS bundles, and HTTP response logs (performs zero live DNS lookups or network I/O):
          - Verifies program eligibility (`UNLOCKED` and `open`)
          - Blocks unsafe IP literals (cloud metadata, RFC1918, unspecified, IPv4-mapped IPv6)
          - Enforces strict DNS label-boundary in-scope / out-of-scope rules
        """
        if not self.eligible:
            return False, self.reason

        import ipaddress
        from engine.program_eligibility_db import _normalize_hostname, is_host_in_scope
        from engine.safe_network_validator import is_explicit_loopback_host, is_safe_target_ip

        host = _normalize_hostname(host_or_url)
        if not host:
            return False, "invalid_hostname"

        is_lb = is_explicit_loopback_host(host)
        try:
            ipaddress.ip_address(host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

        if is_ip_literal:
            if not is_safe_target_ip(host, allow_private=(allow_loopback and is_lb)):
                return False, "ssrf_blocked:unsafe_ip_literal"
            if is_lb and allow_loopback:
                return True, "loopback_sandbox_allowed"
        elif is_lb and allow_loopback:
            return True, "loopback_sandbox_allowed"

        if self.out_of_scope_assets or self.in_scope_assets or require_declared_scope:
            in_ok, scope_reason = is_host_in_scope(host, self.in_scope_assets, self.out_of_scope_assets)
            if not in_ok:
                return False, scope_reason
            return True, scope_reason
        return True, "eligible_no_host_scope_restriction"

    def authorize_live_host(
        self,
        host_or_url: str,
        *,
        allow_loopback: bool = True,
        require_declared_scope: bool = False,
    ) -> Tuple[bool, str]:
        """
        Fail-closed check before sending ANY live packet to `host_or_url`:
          - Verifies program eligibility & Tier 1 automation allowance
          - Validates DNS host via `safe_network_validator.validate_target_host`
          - Enforces strict DNS label-boundary scope matching (always rejects out-of-scope;
            enforces in-scope match whenever `in_scope_assets` are declared or `require_declared_scope=True`)
        """
        if not self.eligible:
            return False, self.reason
        if not self.live_allowed or self.automated_prohibited:
            return False, self.reason

        from engine.program_eligibility_db import _normalize_hostname, is_host_in_scope
        from engine.safe_network_validator import is_explicit_loopback_host, validate_target_host

        host = _normalize_hostname(host_or_url)
        if not host:
            return False, "invalid_hostname"

        is_lb = is_explicit_loopback_host(host)
        ok_net, net_reason = validate_target_host(host, allow_private=(allow_loopback and is_lb))
        if not ok_net:
            return False, f"ssrf_blocked:{net_reason}"

        if is_lb and allow_loopback:
            return True, "loopback_sandbox_allowed"

        if self.out_of_scope_assets or self.in_scope_assets or require_declared_scope:
            in_ok, scope_reason = is_host_in_scope(host, self.in_scope_assets, self.out_of_scope_assets)
            if not in_ok:
                return False, scope_reason
            return True, scope_reason
        return True, "eligible_no_host_scope_restriction"

    def to_headers_dict(self, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        return self.hygiene.to_headers_dict(base)

    def to_cli_header_pairs(self) -> List[Tuple[str, str]]:
        return self.hygiene.to_cli_header_pairs()


def build_program_compliance_context(
    program_handle: str,
    *,
    eligibility_db: Any = None,
    researcher_handle: Optional[str] = None,
    max_rps_cap: Optional[float] = None,
    extra_headers: Optional[Sequence[Union[str, Tuple[str, str]]]] = None,
    user_agent_override: Optional[str] = None,
) -> ProgramComplianceContext:
    """
    Constructs a fail-closed `ProgramComplianceContext` from `ProgramEligibilityDB`
    without relying on any hardcoded personal usernames.
    """
    import os
    from engine.program_eligibility_db import ProgramEligibilityDB

    prog = str(program_handle or "").strip().lower()
    if not prog:
        return ProgramComplianceContext(
            program_handle="",
            eligible=False,
            live_allowed=False,
            ai_testing_allowed=False,
            reason="missing_program_handle",
            automation_tier="explicitly_prohibited",
            automated_prohibited=True,
            effective_max_rps=0.0,
            hygiene=RequestHygieneConfig(),
            rate_limiter=None,
        )

    db = eligibility_db if eligibility_db is not None else ProgramEligibilityDB()
    rec = db.get(prog)
    if rec is None or rec.status != "UNLOCKED" or (rec.submission_state or "open").strip().lower() != "open":
        status_label = rec.status if rec is not None else "UNTRACKED"
        return ProgramComplianceContext(
            program_handle=prog,
            eligible=False,
            live_allowed=False,
            ai_testing_allowed=False,
            reason=f"blocked_ineligible:{status_label}",
            automation_tier="explicitly_prohibited",
            automated_prohibited=True,
            effective_max_rps=0.0,
            hygiene=RequestHygieneConfig(),
            rate_limiter=None,
        )

    prohibited = bool(rec.roe_automated_prohibited or rec.roe_automation_tier == "explicitly_prohibited")
    raw_handle = (
        researcher_handle
        if researcher_handle is not None
        else (
            os.environ.get("HACKERONE_RESEARCHER_HANDLE")
            or os.environ.get("HACKERONE_API_USERNAME")
            or ""
        )
    )
    clean_researcher = str(raw_handle or "").strip()
    if any(ch in clean_researcher for ch in _FORBIDDEN_HEADER_CHARS):
        return ProgramComplianceContext(
            program_handle=prog,
            eligible=True,
            live_allowed=False,
            ai_testing_allowed=False,
            reason="rejected_unsafe_researcher_handle",
            automation_tier=rec.roe_automation_tier,
            automated_prohibited=prohibited,
            effective_max_rps=0.0,
            hygiene=RequestHygieneConfig(),
            rate_limiter=None,
        )

    # Assemble program-mandated headers + dynamic researcher attribution
    hdr_specs: List[Union[str, Tuple[str, str]]] = []
    missing_placeholder = False
    for raw_h in rec.roe_required_headers:
        h_str = str(raw_h or "").strip()
        if not h_str:
            continue
        if "<MISSING_HACKERONE_USERNAME>" in h_str:
            if clean_researcher:
                h_str = h_str.replace("<MISSING_HACKERONE_USERNAME>", clean_researcher)
            else:
                missing_placeholder = True
                continue
        hdr_specs.append(h_str)

    if not hdr_specs and clean_researcher:
        hdr_specs.append(("X-HackerOne", clean_researcher))

    for eh in extra_headers or ():
        hdr_specs.append(eh)

    eff_ua = validate_user_agent(
        user_agent_override
        or rec.roe_user_agent
        or (f"HackerOne/{clean_researcher}" if clean_researcher else "RFCHunt-SecurityResearch/1.0")
    )

    if prohibited:
        eff_rps = 0.0
        live_ok = False
        reason = "blocked_tier1_automated_scanning_prohibited"
    elif missing_placeholder:
        eff_rps = 0.0
        live_ok = False
        reason = "blocked_missing_required_attribution_username"
    else:
        prog_rps = max(0.05, float(rec.roe_max_rps if rec.roe_max_rps > 0.0 else 2.0))
        if max_rps_cap is not None and float(max_rps_cap) > 0.0:
            eff_rps = min(prog_rps, float(max_rps_cap))
        else:
            eff_rps = prog_rps
        eff_rps = max(0.05, min(100.0, eff_rps))
        live_ok = True
        reason = "authorized_compliant"

    hygiene = RequestHygieneConfig.from_raw(
        headers=hdr_specs,
        user_agent=eff_ua,
        max_rps=eff_rps,
    )
    limiter = TokenBucketRateLimiter(eff_rps) if eff_rps > 0.0 else None

    return ProgramComplianceContext(
        program_handle=prog,
        eligible=True,
        live_allowed=live_ok,
        ai_testing_allowed=bool(live_ok and rec.ai_asset_count > 0),
        reason=reason,
        automation_tier=rec.roe_automation_tier,
        automated_prohibited=prohibited,
        effective_max_rps=eff_rps,
        hygiene=hygiene,
        rate_limiter=limiter,
        in_scope_assets=rec.in_scope_assets,
        in_scope_repos=rec.in_scope_repos,
        out_of_scope_assets=rec.out_of_scope_assets,
        no_out_of_scope_redirects=bool(rec.roe_no_oos_redirects),
        ai_disclosure_required=bool(rec.roe_ai_disclosure_required),
    )
