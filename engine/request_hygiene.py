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

from dataclasses import dataclass, field
import math
import re
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


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
