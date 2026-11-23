"""
BaaRai/ARTEX Headless Integration Bridge (REST API + SSE + MITM Proxy :8788)
=============================================================================
Enables headless programmatic orchestration of BaaRai/ARTEX from RFCHunt
without touching the ARTEX web UI:

1. Headless REST API & SSE Client (`ArtexRestClient`, default :8787):
   - Auth via Bearer JWT, `artex_token` cookie, `POST /api/auth/login`, or `/api/setup`.
   - Task lifecycle: `POST /api/tasks`, `GET /api/tasks/{id}`, `PUT /api/tasks/{id}/llm`
     (including `llm_rotate` & `llm_profile_ids`), `POST /api/llm/models`.
   - Evidence ingestion: `POST /api/traffic/ingest` for pushing captured HTTP
     request/response batches into ARTEX's evidence store.
   - Real-time SSE consumer (`GET /api/tasks/{id}/events`) for monitoring graph
     updates, findings, approval gates, and terminal completion.
   - Findings, exploration graph, asset coverage, archive download, noise profile
     configuration, and remote MCP server registration (`POST /api/mcp/servers`).

2. Recording MITM Proxy Router (`ArtexProxyConfig`, default :8788):
   - Configures `httpx`, `requests`, and subprocess proxy env vars to route
     RFCHunt HTTP traffic through ARTEX's recording MITM proxy with optional
     custom CA verification and SSRF-safe validation.

3. Local + Remote Traffic Capture (`TrafficCaptureSession`, `CapturedExchange`):
   - Persists captured exchanges to `terminator.db` (`traffic_evidence`),
     decodes gzip/deflate response bodies for verbatim POE quote verification,
     and flushes batches to ARTEX via `POST /api/traffic/ingest`.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import gzip
import hashlib
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union
from urllib.parse import urlparse
import zlib

import httpx

logger = logging.getLogger("terminator.artex.bridge")

DEFAULT_ARTEX_API_URL = "http://127.0.0.1:8787"
DEFAULT_ARTEX_PROXY_URL = "http://127.0.0.1:8788"

TERMINAL_SSE_EVENTS = frozenset({
    "done",
    "completed",
    "task_done",
    "task_completed",
    "goal_proven",
    "timeout",
    "failed",
    "cancelled",
    "canceled",
    "error",
})


def decode_http_body(raw_bytes: bytes, content_encoding: str = "") -> bytes:
    """
    Decodes HTTP response payloads compressed with gzip or deflate before
    verbatim evidence quote verification (matching ARTEX's evidence verifier).
    Returns original bytes safely if decoding fails or encoding is identity.
    """
    if not raw_bytes:
        return b""
    enc = (content_encoding or "").strip().lower()
    if not enc or enc == "identity":
        # Auto-detect gzip magic bytes if header omitted
        if len(raw_bytes) >= 2 and raw_bytes[:2] == b"\x1f\x8b":
            try:
                return gzip.decompress(raw_bytes)
            except Exception:
                return raw_bytes
        return raw_bytes

    encodings = [e.strip() for e in enc.split(",") if e.strip()]
    data = raw_bytes
    for layer in reversed(encodings):
        if layer in ("gzip", "x-gzip"):
            try:
                data = gzip.decompress(data)
            except Exception:
                return data
        elif layer == "deflate":
            try:
                data = zlib.decompress(data)
            except zlib.error:
                try:
                    # Raw RFC 1951 deflate stream (no zlib header)
                    data = zlib.decompress(data, -zlib.MAX_WBITS)
                except Exception:
                    return data
    return data


def _validate_endpoint_url(url: str, *, authorized: bool = False, label: str = "ARTEX endpoint") -> str:
    """
    Validates an ARTEX API or MITM proxy URL fail-closed against SSRF invariants.
    Loopback endpoints (127.0.0.1 / localhost / ::1) are permitted by default;
    non-loopback hosts require `authorized=True` and pass `validate_target_host`.
    Cloud metadata, unspecified (0.0.0.0 / ::), and IPv4-mapped IPv6 are always blocked.
    """
    raw = str(url or "").strip()
    if not raw:
        raise ValueError(f"{label} URL cannot be empty.")
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{label} URL must use http or https scheme, got '{parsed.scheme}'.")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError(f"{label} URL is missing a valid hostname: {url}")

    from engine.safe_network_validator import is_explicit_loopback_host, validate_and_authorize_target

    is_loopback = is_explicit_loopback_host(host)
    ok, reason = validate_and_authorize_target(host, authorized=authorized or is_loopback)
    if not ok:
        raise PermissionError(f"{label} '{url}' rejected by SSRF/authorization gate: {reason}")
    return raw.rstrip("/")


@dataclass
class ArtexProxyConfig:
    """
    Configuration for routing RFCHunt HTTP clients through ARTEX's recording
    MITM proxy (default http://127.0.0.1:8788).
    """

    proxy_url: Optional[str] = None
    ca_cert_path: Optional[str] = None
    authorized: bool = False
    enabled: bool = False

    def __post_init__(self) -> None:
        if self.proxy_url:
            self.proxy_url = _validate_endpoint_url(
                self.proxy_url,
                authorized=self.authorized,
                label="ARTEX MITM proxy",
            )
            self.enabled = True
        elif self.enabled:
            self.proxy_url = DEFAULT_ARTEX_PROXY_URL

        if self.ca_cert_path:
            self.ca_cert_path = str(Path(self.ca_cert_path))

    @classmethod
    def from_env_or_args(
        cls,
        proxy_url: Optional[str] = None,
        ca_cert_path: Optional[str] = None,
        authorized: bool = False,
    ) -> "ArtexProxyConfig":
        resolved_url = proxy_url or os.environ.get("ARTEX_PROXY_URL") or os.environ.get("ARTEX_MITM_PROXY")
        resolved_ca = ca_cert_path or os.environ.get("ARTEX_CA_CERT")
        if not resolved_url:
            return cls(proxy_url=None, ca_cert_path=resolved_ca, authorized=authorized, enabled=False)
        return cls(
            proxy_url=resolved_url,
            ca_cert_path=resolved_ca,
            authorized=authorized,
            enabled=True,
        )

    def verify_option(self) -> Union[bool, str]:
        if self.ca_cert_path and os.path.isfile(self.ca_cert_path):
            return self.ca_cert_path
        return True

    def httpx_client_kwargs(self, timeout: float = 15.0) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "timeout": timeout,
            "verify": self.verify_option(),
            "trust_env": bool(self.enabled),
        }
        if self.enabled and self.proxy_url:
            kwargs["proxy"] = self.proxy_url
        return kwargs

    def requests_proxies(self) -> Dict[str, str]:
        if not (self.enabled and self.proxy_url):
            return {}
        return {"http": self.proxy_url, "https": self.proxy_url}

    def subprocess_env(self, base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = dict(base_env if base_env is not None else os.environ)
        if self.enabled and self.proxy_url:
            env["HTTP_PROXY"] = self.proxy_url
            env["HTTPS_PROXY"] = self.proxy_url
            env["ARTEX_PROXY_URL"] = self.proxy_url
            if self.ca_cert_path and os.path.isfile(self.ca_cert_path):
                env["REQUESTS_CA_BUNDLE"] = self.ca_cert_path
                env["SSL_CERT_FILE"] = self.ca_cert_path
        return env

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "proxy_url": self.proxy_url,
            "ca_cert_path": self.ca_cert_path,
        }


@dataclass
class CapturedExchange:
    """Single captured HTTP request/response exchange bound to findings/chains."""

    traffic_id: str
    method: str
    url: str
    host: str
    port: int = 80
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status_code: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body_bytes: bytes = b""
    content_encoding: str = ""
    is_preview_only: bool = False
    source: str = "local"
    task_id: str = "default"
    captured_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def response_body_b64(self) -> str:
        return base64.b64encode(self.response_body_bytes or b"").decode("ascii")

    def decoded_response_bytes(self) -> bytes:
        enc = self.content_encoding
        if not enc:
            for k, v in self.response_headers.items():
                if k.lower() == "content-encoding":
                    enc = str(v)
                    break
        return decode_http_body(self.response_body_bytes, enc)

    def decoded_response_text(self) -> str:
        return self.decoded_response_bytes().decode("utf-8", errors="replace")

    def verify_verbatim_quote(self, quote: str) -> Tuple[bool, str]:
        """
        Verifies whether `quote` appears verbatim in the decoded response body
        or formatted response headers (decoding gzip/deflate first).
        """
        q = str(quote or "").strip()
        if not q:
            return False, ""
        decoded_text = self.decoded_response_text()
        if q in decoded_text:
            idx = decoded_text.find(q)
            start = max(0, idx - 60)
            end = min(len(decoded_text), idx + len(q) + 60)
            return True, decoded_text[start:end]
        header_blob = "\r\n".join(f"{k}: {v}" for k, v in self.response_headers.items())
        if q in header_blob:
            return True, header_blob[:240]
        return False, ""

    def to_artex_ingest_item(self) -> Dict[str, Any]:
        """Formats the exchange for BaaRai/ARTEX `POST /api/traffic/ingest`."""
        return {
            "id": self.traffic_id,
            "task_id": self.task_id,
            "method": self.method.upper(),
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "request_headers": dict(self.request_headers),
            "request_body": self.request_body,
            "status_code": self.status_code,
            "response_headers": dict(self.response_headers),
            "response_body": self.decoded_response_text(),
            "response_body_b64": self.response_body_b64,
            "content_encoding": self.content_encoding,
            "source": self.source,
            "captured_at": self.captured_at,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "traffic_id": self.traffic_id,
            "task_id": self.task_id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "response_body_b64": self.response_body_b64,
            "content_encoding": self.content_encoding,
            "is_preview_only": self.is_preview_only,
            "source": self.source,
            "captured_at": self.captured_at,
        }


class TrafficCaptureSession:
    """
    Captures HTTP exchanges locally (and optionally via ARTEX MITM proxy :8788),
    persists them in `terminator.db`, and pushes batches to ARTEX `POST /api/traffic/ingest`.
    """

    def __init__(
        self,
        db: Optional[Any] = None,
        task_id: str = "default",
        proxy_config: Optional[ArtexProxyConfig] = None,
        hygiene_config: Optional[Any] = None,
        rate_limiter: Optional[Any] = None,
    ):
        self.db = db
        self.task_id = task_id
        self.proxy_config = proxy_config or ArtexProxyConfig()
        self.hygiene_config = hygiene_config
        self.rate_limiter = rate_limiter
        self._lock = threading.RLock()
        self.exchanges: Dict[str, CapturedExchange] = {}

    def record_exchange(
        self,
        method: str,
        url: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
        request_headers: Optional[Dict[str, str]] = None,
        request_body: str = "",
        status_code: int = 0,
        response_headers: Optional[Dict[str, str]] = None,
        response_body: Union[bytes, str] = b"",
        content_encoding: Optional[str] = None,
        is_preview_only: bool = False,
        source: Optional[str] = None,
        traffic_id: Optional[str] = None,
    ) -> CapturedExchange:
        fallback_host = host or "localhost"
        if ":" in fallback_host and not fallback_host.startswith("["):
            fallback_host = f"[{fallback_host}]"
        parsed = urlparse(url if "://" in url else f"http://{fallback_host}{url if url.startswith('/') else '/' + url}")
        resolved_host = host or parsed.hostname or "localhost"
        resolved_port = int(port if port is not None else (parsed.port or (443 if parsed.scheme == "https" else 80)))

        raw_bytes = response_body.encode("utf-8", errors="replace") if isinstance(response_body, str) else bytes(response_body or b"")
        resp_hdrs = {str(k): str(v) for k, v in (response_headers or {}).items()}
        req_hdrs = {str(k): str(v) for k, v in (request_headers or {}).items()}
        resolved_enc = content_encoding
        if resolved_enc is None:
            for k, v in resp_hdrs.items():
                if k.lower() == "content-encoding":
                    resolved_enc = v
                    break
            resolved_enc = resolved_enc or ""

        resolved_source = source or ("mitm_proxy" if self.proxy_config.enabled else "local")
        with self._lock:
            if not traffic_id:
                digest = hashlib.sha256(
                    f"{self.task_id}:{method}:{url}:{status_code}:{time.time_ns()}:{len(self.exchanges)}".encode("utf-8")
                ).hexdigest()[:12]
                traffic_id = f"TRAF-{digest}"

            ex = CapturedExchange(
                traffic_id=traffic_id,
                method=method.upper(),
                url=url,
                host=resolved_host,
                port=resolved_port,
                request_headers=req_hdrs,
                request_body=request_body or "",
                status_code=int(status_code),
                response_headers=resp_hdrs,
                response_body_bytes=raw_bytes,
                content_encoding=resolved_enc,
                is_preview_only=bool(is_preview_only),
                source=resolved_source,
                task_id=self.task_id,
            )
            self.exchanges[traffic_id] = ex
        if self.db and hasattr(self.db, "save_traffic_evidence"):
            try:
                self.db.save_traffic_evidence(
                    traffic_id=ex.traffic_id,
                    method=ex.method,
                    url=ex.url,
                    host=ex.host,
                    port=ex.port,
                    request_headers=ex.request_headers,
                    request_body=ex.request_body,
                    status_code=ex.status_code,
                    response_headers=ex.response_headers,
                    response_body_b64=ex.response_body_b64,
                    content_encoding=ex.content_encoding,
                    is_preview_only=ex.is_preview_only,
                    source=ex.source,
                    task_id=ex.task_id,
                )
            except Exception as exc:
                logger.debug("Failed persisting traffic_evidence %s: %s", traffic_id, exc)
        return ex

    def get_exchange(self, traffic_id: str) -> Optional[CapturedExchange]:
        with self._lock:
            existing = self.exchanges.get(traffic_id)
            if existing is not None:
                return existing
        if self.db and hasattr(self.db, "get_traffic_evidence"):
            row = self.db.get_traffic_evidence(traffic_id)
            if row:
                raw_b = base64.b64decode(row.get("response_body_b64") or "") if row.get("response_body_b64") else b""
                ex = CapturedExchange(
                    traffic_id=row["traffic_id"],
                    method=row["method"],
                    url=row["url"],
                    host=row["host"],
                    port=int(row.get("port") or 80),
                    request_headers=row.get("request_headers") or {},
                    request_body=row.get("request_body") or "",
                    status_code=int(row.get("status_code") or 0),
                    response_headers=row.get("response_headers") or {},
                    response_body_bytes=raw_b,
                    content_encoding=row.get("content_encoding") or "",
                    is_preview_only=bool(row.get("is_preview_only", False)),
                    source=row.get("source") or "local",
                    task_id=row.get("task_id") or self.task_id,
                )
                with self._lock:
                    return self.exchanges.setdefault(traffic_id, ex)
        return None

    def send_and_capture(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        authorized: bool = False,
        timeout: float = 10.0,
    ) -> CapturedExchange:
        """
        Executes a safe, policy-validated HTTP request (automatically routed through
        ARTEX MITM proxy :8788 when configured) and records the full exchange.
        """
        parsed = urlparse(url)
        if (parsed.scheme or "").lower() not in ("http", "https"):
            raise ValueError(f"TrafficCaptureSession requires http/https URL, got '{url}'")
        if "\\" in url or parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
            raise ValueError(f"TrafficCaptureSession rejected ambiguous URL authority in '{url}'")
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        from engine.execution_policy import ActionType, ExecutionPolicy, ScannerTask, StructuredIntentProposal
        from engine.safe_network_validator import validate_and_authorize_target

        ok, reason = validate_and_authorize_target(host, authorized=authorized)
        if not ok:
            raise PermissionError(f"TrafficCaptureSession blocked destination '{host}': {reason}")

        ExecutionPolicy.get_instance().validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.ARTEX_DUAL_GRAPH,
                action_type=ActionType.NETWORK_SOCKET,
                target_host=host,
                target_port=port,
                http_method=method.upper(),
                raw_payload=body,
                rationale="ARTEX traffic capture / replay verification",
            )
        )

        from engine.request_hygiene import acquire_rate_limit, resolve_hygiene
        hyg, lim = resolve_hygiene(getattr(self, "hygiene_config", None), getattr(self, "rate_limiter", None))
        acquire_rate_limit(lim)
        effective_headers = hyg.to_headers_dict(headers)

        client_kwargs = self.proxy_config.httpx_client_kwargs(timeout=timeout)
        with httpx.Client(**client_kwargs) as client:
            resp = client.request(method.upper(), url, headers=effective_headers, content=body.encode("utf-8") if body else None)
            resp_headers = dict(resp.headers)
            # httpx decodes Content-Encoding into resp.content automatically;
            # mark content_encoding="identity" so decoded_response_bytes() does not double-decompress.
            raw_content = resp.content
            enc = "identity"
            return self.record_exchange(
                method=method.upper(),
                url=url,
                host=host,
                port=port,
                request_headers=effective_headers,
                request_body=body,
                status_code=resp.status_code,
                response_headers=resp_headers,
                response_body=raw_content,
                content_encoding=enc,
                is_preview_only=False,
            )

    def replay_exchange(
        self,
        traffic_id: str,
        authorized: bool = False,
        timeout: float = 10.0,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        use_tls: Optional[bool] = None,
    ) -> CapturedExchange:
        """
        Replays a previously captured HTTP exchange (method, URL, headers, stored body).
        Refuses replay when the stored exchange only holds a body preview (`is_preview_only=True`),
        matching ARTEX's replay safety rule.
        """
        orig = self.get_exchange(traffic_id)
        if orig is None:
            raise KeyError(f"Traffic record '{traffic_id}' not found.")
        if orig.is_preview_only:
            raise ValueError(f"Replay disabled for '{traffic_id}': only body preview is loaded.")
        replay_url = orig.url
        if target_host or target_port is not None or use_tls is not None:
            parsed = urlparse(orig.url)
            scheme = "https" if use_tls is True else ("http" if use_tls is False else (parsed.scheme or "http"))
            h = target_host or parsed.hostname or orig.host
            p = int(target_port) if target_port is not None else (parsed.port or orig.port or (443 if scheme == "https" else 80))
            path_q = parsed.path or "/"
            if parsed.query:
                path_q = f"{path_q}?{parsed.query}"
            host_fmt = f"[{h}]" if (":" in h and not h.startswith("[")) else h
            replay_url = f"{scheme}://{host_fmt}:{p}{path_q}"
        return self.send_and_capture(
            method=orig.method,
            url=replay_url,
            headers=orig.request_headers,
            body=orig.request_body,
            authorized=authorized,
            timeout=timeout,
        )

    def list_exchanges(self) -> List[CapturedExchange]:
        with self._lock:
            return list(self.exchanges.values())

    def find_matching_exchange(self, target_route: str) -> Optional[CapturedExchange]:
        if not target_route or target_route == "/":
            return None
        for ex in self.list_exchanges():
            parsed_path = urlparse(ex.url).path or "/"
            if parsed_path == target_route or target_route in parsed_path:
                return ex
        return None

    def to_ingest_batch(self) -> List[Dict[str, Any]]:
        return [ex.to_artex_ingest_item() for ex in self.list_exchanges()]


@dataclass
class ArtexSSEEvent:
    """Single parsed Server-Sent Event frame from ARTEX's activity stream."""

    event: str = "message"
    data: Any = None
    raw_data: str = ""
    event_id: str = ""
    received_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event,
            "data": self.data,
            "event_id": self.event_id,
            "received_at": self.received_at,
        }


class ArtexRestClient:
    """
    Headless REST API & SSE client for driving a running BaaRai/ARTEX Go server
    (default http://127.0.0.1:8787) programmatically from RFCHunt without any browser UI.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        authorized: bool = False,
        timeout: float = 15.0,
        verify: Union[bool, str] = True,
        http_client: Optional[httpx.Client] = None,
    ):
        resolved_url = base_url or os.environ.get("ARTEX_API_URL") or DEFAULT_ARTEX_API_URL
        self.base_url = _validate_endpoint_url(
            resolved_url,
            authorized=authorized,
            label="ARTEX API server",
        )
        self.token: Optional[str] = token or os.environ.get("ARTEX_API_TOKEN")
        self.timeout = float(timeout)
        self.verify = verify
        self._external_client = http_client

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        hdrs: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "RFCHunt-ARTEX-Bridge/1.0",
        }
        if self.token:
            hdrs["Authorization"] = f"Bearer {self.token}"
            hdrs["Cookie"] = f"artex_token={self.token}"
        if extra:
            hdrs.update(extra)
        return hdrs

    def _get_client(self, timeout: Optional[float] = None) -> Tuple[httpx.Client, bool]:
        if self._external_client is not None:
            return self._external_client, False
        return httpx.Client(timeout=timeout or self.timeout, verify=self.verify), True

    def _request_json(
        self,
        method: str,
        path: str,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        client, should_close = self._get_client(timeout=timeout)
        try:
            resp = client.request(
                method.upper(),
                url,
                headers=self._headers({"Content-Type": "application/json"} if json_body is not None else None),
                json=json_body,
                params=params,
            )
            resp.raise_for_status()
            if not resp.content:
                return {"status": "ok", "http_status": resp.status_code}
            try:
                data = resp.json()
                return data if isinstance(data, dict) else {"items": data}
            except Exception:
                return {"raw": resp.text, "http_status": resp.status_code}
        finally:
            if should_close:
                client.close()

    def health_check(self) -> Dict[str, Any]:
        """Checks whether the headless ARTEX server is reachable."""
        for route in ("/api/health", "/api/status"):
            try:
                data = self._request_json("GET", route, timeout=5.0)
                return {"reachable": True, "endpoint": f"{self.base_url}{route}", "details": data}
            except Exception as exc:
                last_err = str(exc)
        return {"reachable": False, "endpoint": self.base_url, "error": last_err}

    def login(self, username: str, password: str) -> str:
        """Authenticates against `POST /api/auth/login` and stores the JWT / `artex_token`."""
        url = f"{self.base_url}/api/auth/login"
        client, should_close = self._get_client()
        try:
            resp = client.post(
                url,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json={"username": username, "password": password},
            )
            resp.raise_for_status()
            token = resp.cookies.get("artex_token")
            if not token:
                payload = resp.json() if resp.content else {}
                token = payload.get("token") or payload.get("access_token") or (payload.get("data") or {}).get("token")
            if not token:
                raise RuntimeError("ARTEX login succeeded but no JWT token or artex_token cookie was returned.")
            self.token = str(token)
            return self.token
        finally:
            if should_close:
                client.close()

    def claim_setup(self, setup_token: str, password: str, username: str = "admin") -> Dict[str, Any]:
        """Claims first-run setup via `POST /api/setup` using the startup one-time token."""
        return self._request_json(
            "POST",
            "/api/setup",
            json_body={"setup_token": setup_token, "username": username, "password": password},
        )

    def create_task(
        self,
        name: str,
        goal: str,
        targets: Optional[List[str]] = None,
        scope: Optional[List[str]] = None,
        llm_profile_ids: Optional[List[str]] = None,
        llm_rotate: Optional[bool] = None,
        noise_profile: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Creates an autonomous attack-chaining assessment task via `POST /api/tasks`."""
        payload: Dict[str, Any] = {
            "name": name,
            "goal": goal,
            "targets": list(targets or []),
            "scope": list(scope if scope is not None else (targets or [])),
        }
        if llm_profile_ids:
            payload["llm_profile_ids"] = list(llm_profile_ids)
        if llm_rotate is not None:
            payload["llm_rotate"] = bool(llm_rotate)
        if noise_profile:
            payload["noise_profile"] = noise_profile
        if metadata:
            payload["metadata"] = dict(metadata)
        return self._request_json("POST", "/api/tasks", json_body=payload)

    def get_task(self, task_id: str) -> Dict[str, Any]:
        return self._request_json("GET", f"/api/tasks/{task_id}")

    def list_tasks(self) -> Dict[str, Any]:
        return self._request_json("GET", "/api/tasks")

    def update_task_llm(
        self,
        task_id: str,
        llm_profile_ids: List[str],
        llm_rotate: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Updates task LLM failover/rotation chain via `PUT /api/tasks/{id}/llm`.
        Per ARTEX API contract, omitting `llm_rotate` preserves its existing value.
        """
        payload: Dict[str, Any] = {"llm_profile_ids": list(llm_profile_ids)}
        if llm_rotate is not None:
            payload["llm_rotate"] = bool(llm_rotate)
        return self._request_json("PUT", f"/api/tasks/{task_id}/llm", json_body=payload)

    def discover_llm_models(
        self,
        provider: str,
        base_url: str,
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries provider model catalog via `POST /api/llm/models`."""
        payload: Dict[str, Any] = {"provider": provider, "base_url": base_url}
        if api_key:
            payload["api_key"] = api_key
        return self._request_json("POST", "/api/llm/models", json_body=payload)

    def ingest_traffic_batch(
        self,
        exchanges: List[Union[CapturedExchange, Dict[str, Any]]],
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Pushes captured HTTP request/response batches into ARTEX's evidence store
        via `POST /api/traffic/ingest`.
        """
        items: List[Dict[str, Any]] = []
        for ex in exchanges:
            if isinstance(ex, CapturedExchange):
                item = ex.to_artex_ingest_item()
            elif isinstance(ex, dict):
                item = dict(ex)
            else:
                continue
            if task_id and not item.get("task_id"):
                item["task_id"] = task_id
            items.append(item)

        payload: Dict[str, Any] = {"items": items, "count": len(items)}
        if task_id:
            payload["task_id"] = task_id
        return self._request_json("POST", "/api/traffic/ingest", json_body=payload)

    def get_task_findings(self, task_id: str) -> List[Dict[str, Any]]:
        data = self._request_json("GET", f"/api/tasks/{task_id}/findings")
        if isinstance(data.get("findings"), list):
            return data["findings"]
        if isinstance(data.get("items"), list):
            return data["items"]
        return []

    def get_exploration_graph(self, task_id: str) -> Dict[str, Any]:
        return self._request_json("GET", f"/api/tasks/{task_id}/graph")

    def get_asset_coverage(self, task_id: str) -> Dict[str, Any]:
        return self._request_json("GET", f"/api/tasks/{task_id}/coverage")

    def download_task_archive(self, task_id: str, dest_path: Union[str, Path]) -> str:
        """Downloads a task archive from `GET /api/tasks/{id}/archive` into confined reports/out path."""
        clean_task_id = str(task_id or "").strip()
        if not clean_task_id or any(c in clean_task_id for c in ("/", "\\", "..")) or any(ord(c) < 32 for c in clean_task_id):
            raise ValueError(f"Invalid ARTEX task_id for archive download: {task_id!r}")
        raw_dest = os.fspath(dest_path)
        if not isinstance(raw_dest, str) or not raw_dest.strip():
            raise ValueError("Archive destination path must be a non-empty path string.")
        from engine.execution_policy import (
            ActionType,
            ExecutionPolicy,
            ScannerTask,
            StructuredIntentProposal,
        )

        ExecutionPolicy.get_instance().validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.ARTEX_DUAL_GRAPH,
                action_type=ActionType.FILE_WRITE,
                file_path=raw_dest,
                rationale=f"Download ARTEX archive for task {clean_task_id}",
            )
        )
        out_path = Path(raw_dest)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        url = f"{self.base_url}/api/tasks/{clean_task_id}/archive"
        client, should_close = self._get_client(timeout=60.0)
        try:
            resp = client.get(url, headers=self._headers({"Accept": "application/octet-stream"}))
            resp.raise_for_status()
            out_path.write_bytes(resp.content)
            return str(out_path)
        finally:
            if should_close:
                client.close()

    def set_noise_profile(self, profile: str) -> Dict[str, Any]:
        """Updates runtime target noise profile (`off`, `quiet`, `balanced`, `aggressive`)."""
        return self._request_json("PUT", "/api/settings/noise", json_body={"profile": profile})

    def get_noise_stats(self) -> Dict[str, Any]:
        return self._request_json("GET", "/api/settings/noise")

    def register_mcp_server(
        self,
        name: str,
        url: str,
        transport: str = "http",
        bearer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Registers RFCHunt's remote MCP server (`/http` or `/sse`) inside ARTEX."""
        payload: Dict[str, Any] = {
            "name": name,
            "url": url,
            "transport": transport,
        }
        if bearer_token:
            payload["headers"] = {"Authorization": f"Bearer {bearer_token}"}
        return self._request_json("POST", "/api/mcp/servers", json_body=payload)

    def iter_sse_events(
        self,
        path: str,
        timeout_sec: float = 30.0,
        max_events: int = 500,
    ) -> Iterator[ArtexSSEEvent]:
        """
        Streams and parses Server-Sent Events (`text/event-stream`) from ARTEX on :8787.
        Yields `ArtexSSEEvent` instances as each blank-line-delimited SSE frame completes.
        """
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        headers = self._headers({"Accept": "text/event-stream", "Cache-Control": "no-cache"})
        client, should_close = self._get_client(timeout=timeout_sec)
        emitted = 0
        deadline = time.monotonic() + max(0.5, float(timeout_sec))
        try:
            with client.stream("GET", url, headers=headers) as resp:
                resp.raise_for_status()
                cur_event = "message"
                cur_id = ""
                cur_data_lines: List[str] = []

                for raw_line in resp.iter_lines():
                    if time.monotonic() > deadline:
                        break
                    line = raw_line if isinstance(raw_line, str) else raw_line.decode("utf-8", errors="replace")
                    if line == "":
                        if cur_data_lines:
                            raw_payload = "\n".join(cur_data_lines)
                            try:
                                parsed_payload: Any = json.loads(raw_payload)
                            except Exception:
                                parsed_payload = raw_payload
                            yield ArtexSSEEvent(
                                event=cur_event or "message",
                                data=parsed_payload,
                                raw_data=raw_payload,
                                event_id=cur_id,
                            )
                            emitted += 1
                            cur_event = "message"
                            cur_id = ""
                            cur_data_lines = []
                            if emitted >= max_events:
                                break
                        continue
                    if line.startswith(":"):
                        continue
                    if ":" in line:
                        field_name, field_val = line.split(":", 1)
                        if field_val.startswith(" "):
                            field_val = field_val[1:]
                    else:
                        field_name, field_val = line, ""

                    if field_name == "event":
                        cur_event = field_val.strip()
                    elif field_name == "id":
                        cur_id = field_val.strip()
                    elif field_name == "data":
                        cur_data_lines.append(field_val)

                # Flush trailing frame if stream closed without final blank line
                if cur_data_lines and emitted < max_events:
                    raw_payload = "\n".join(cur_data_lines)
                    try:
                        parsed_payload = json.loads(raw_payload)
                    except Exception:
                        parsed_payload = raw_payload
                    yield ArtexSSEEvent(
                        event=cur_event or "message",
                        data=parsed_payload,
                        raw_data=raw_payload,
                        event_id=cur_id,
                    )
        finally:
            if should_close:
                client.close()

    def stream_task_events(
        self,
        task_id: str,
        on_event: Optional[Callable[[ArtexSSEEvent], None]] = None,
        timeout_sec: float = 30.0,
        max_events: int = 500,
        stop_on_terminal: bool = True,
    ) -> List[ArtexSSEEvent]:
        """
        Consumes ARTEX's real-time SSE activity stream for a task (`GET /api/tasks/{id}/events`),
        invoking `on_event` on each frame and stopping cleanly on terminal events.
        """
        collected: List[ArtexSSEEvent] = []
        for ev in self.iter_sse_events(
            f"/api/tasks/{task_id}/events",
            timeout_sec=timeout_sec,
            max_events=max_events,
        ):
            collected.append(ev)
            if on_event:
                try:
                    on_event(ev)
                except Exception as exc:
                    logger.debug("SSE callback error: %s", exc)
            if stop_on_terminal:
                ev_name = (ev.event or "").lower()
                status_val = ""
                if isinstance(ev.data, dict):
                    status_val = str(ev.data.get("status") or ev.data.get("type") or "").lower()
                if ev_name in TERMINAL_SSE_EVENTS or status_val in TERMINAL_SSE_EVENTS:
                    break
        return collected

    def orchestrate_headless_chain(
        self,
        task_name: str,
        goal: str,
        targets: List[str],
        traffic_batches: Optional[List[Union[CapturedExchange, Dict[str, Any]]]] = None,
        llm_profile_ids: Optional[List[str]] = None,
        llm_rotate: Optional[bool] = None,
        noise_profile: Optional[str] = None,
        wait_sse: bool = False,
        sse_timeout_sec: float = 15.0,
        on_event: Optional[Callable[[ArtexSSEEvent], None]] = None,
    ) -> Dict[str, Any]:
        """
        High-level headless orchestration pipeline used by `--all` and `cmd_artex`:
        health check -> noise profile -> create task -> configure LLM rotation ->
        ingest captured traffic -> optionally consume SSE -> pull findings & coverage.
        Never raises on unreachable server; returns structured telemetry cleanly.
        """
        summary: Dict[str, Any] = {
            "base_url": self.base_url,
            "connected": False,
            "task_id": None,
            "traffic_ingested": 0,
            "sse_events": [],
            "remote_findings": [],
            "coverage": {},
            "status": "uninitialized",
        }
        try:
            health = self.health_check()
            if not health.get("reachable"):
                summary["status"] = "unreachable"
                summary["error"] = health.get("error", "ARTEX API unreachable")
                return summary
            summary["connected"] = True

            if noise_profile:
                try:
                    self.set_noise_profile(noise_profile)
                except Exception as exc:
                    summary["noise_warning"] = str(exc)

            created = self.create_task(
                name=task_name,
                goal=goal,
                targets=targets,
                llm_profile_ids=llm_profile_ids,
                llm_rotate=llm_rotate,
                noise_profile=noise_profile,
                metadata={"source": "rfchunt_unified_all"},
            )
            task_id = str(
                created.get("id")
                or created.get("task_id")
                or (created.get("task") or {}).get("id")
                or ""
            )
            summary["task_id"] = task_id or None

            if task_id and llm_profile_ids:
                try:
                    self.update_task_llm(task_id, llm_profile_ids, llm_rotate=llm_rotate)
                except Exception as exc:
                    summary["llm_update_warning"] = str(exc)

            if traffic_batches:
                ingest_res = self.ingest_traffic_batch(traffic_batches, task_id=task_id or None)
                summary["traffic_ingested"] = int(ingest_res.get("ingested", len(traffic_batches)))

            if task_id and wait_sse:
                try:
                    events = self.stream_task_events(
                        task_id,
                        on_event=on_event,
                        timeout_sec=sse_timeout_sec,
                    )
                    summary["sse_events"] = [e.to_dict() for e in events]
                except Exception as exc:
                    summary["sse_warning"] = str(exc)

            if task_id:
                try:
                    summary["remote_findings"] = self.get_task_findings(task_id)
                except Exception:
                    pass
                try:
                    summary["coverage"] = self.get_asset_coverage(task_id)
                except Exception:
                    pass

            summary["status"] = "synced"
            return summary
        except Exception as exc:
            summary["status"] = "error"
            summary["error"] = str(exc)
            return summary
