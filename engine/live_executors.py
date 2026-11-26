"""
Live Tool-Backed ARTEX Worker Executors (Pillar 1)
==================================================
Binds real, policy-confined RFCHunt assessment executors to `ArtexWorker` and
`ArtexRetester` for authorized targets:
- `AUTH_BOUNDARY` / `AUTH_SECRET`: Safe read-only cross-role HTTP differential
  probing (e.g., verifying whether an end-user OIDC token is accepted on a
  service-only route that rejects anonymous callers with 401/403).
- `DESYNC`: Live HTTP framing verification via `DeterministicHarness` /
  `ActiveFlawProber` (or captured HTTP exchange) on authorized targets.
- `AI_INJECTION` / `SSRF_PIVOT` / `EXEC_SINK`: Safe non-destructive endpoint
  reachability & canary/response verification via `TrafficCaptureSession`.

Every live request passes fail-closed through:
1. `validate_and_authorize_target` (SSRF + authorization boundary)
2. `ExecutionPolicy.validate_intent` (scanner confinement + destructive verb gate)
3. `ApprovalGate.check` (rule / policy / interactive CLI approval)
4. `NoiseGovernor` (per-host pacing & Retry-After backoff)
"""

from __future__ import annotations

import collections
import collections.abc as collections_abc
import contextlib
from dataclasses import dataclass
import importlib
import inspect
import ipaddress
import itertools
import json
import logging
import os
from pathlib import Path
import posixpath
import re
import secrets
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import httpx

from engine.approval_gate import (
    EXCLUDED_SCANNER_BINARIES,
    ApprovalGate,
    _EXCLUDED_SCANNER_STEMS,
)
from engine.artex_bridge import CapturedExchange, TrafficCaptureSession
from engine.safe_network_validator import validate_and_authorize_target
from engine.session_loader import AuthProfile

logger = logging.getLogger("terminator.artex.executors")

_EXCLUDED_TOOL_EXTS: Tuple[str, ...] = (".exe", ".py", ".sh", ".bat", ".cmd", ".ps1")
_VALID_SURFACE_EXTS: Set[str] = {".py", ".go", ".ts", ".tsx", ".js", ".jsx"}
_LIVE_EXEC_STATIC_EXTS: Set[str] = {
    ".html", ".htm", ".js", ".mjs", ".cjs", ".ts", ".css", ".scss",
    ".json", ".xml", ".txt", ".md", ".php", ".asp", ".aspx", ".jsp",
    ".py", ".rb", ".go", ".yaml", ".yml", ".toml", ".ini", ".conf",
    ".env", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip", ".bak", ".sql",
    ".log",
}


def _is_excluded_tool_name(raw_name: Any) -> bool:
    if not isinstance(raw_name, str):
        return True
    cleaned = raw_name.strip()
    if not cleaned:
        return True
    base = cleaned.replace("\\", "/").split("/")[-1].strip().lower()
    if base in EXCLUDED_SCANNER_BINARIES:
        return True
    stem = base
    for ext in _EXCLUDED_TOOL_EXTS:
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    return stem in _EXCLUDED_SCANNER_STEMS


def _safe_nonneg_int(val: Any, default: int = 0) -> int:
    if isinstance(val, bool) or val is None:
        return default
    try:
        return max(0, int(val))
    except (TypeError, ValueError, OverflowError):
        return default


def _format_host_for_url(host: str) -> str:
    h = str(host or "").strip()
    if ":" in h and not h.startswith("["):
        return f"[{h}]"
    return h


def _normalize_host_cmp(host: str) -> str:
    h = str(host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1].strip()
    return h.rstrip(".")


class _CompositeApprovalGate:
    """
    Fail-closed composite ApprovalGate enforcing every configured gate in order.
    If any gate denies an action, the denial is returned/raised immediately.
    """

    def __init__(self, gates: List[Any]):
        self.gates: List[Any] = []
        seen: Set[int] = set()
        for g in gates:
            if g is not None and id(g) not in seen:
                seen.add(id(g))
                self.gates.append(g)

    def check(self, **kwargs: Any) -> Any:
        last_dec = None
        for g in self.gates:
            dec = g.check(**kwargs)
            last_dec = dec
            if not getattr(dec, "approved", False):
                return dec
        if last_dec is not None:
            return last_dec
        return ApprovalGate(mode="policy").check(**kwargs)

    def require(self, **kwargs: Any) -> Any:
        last_dec = None
        for g in self.gates:
            last_dec = g.require(**kwargs)
        if last_dec is not None:
            return last_dec
        return ApprovalGate(mode="policy").require(**kwargs)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[..., Dict[str, Any]]


class ArtexToolBox:
    """
    Explicit typed JSON tool registry for the bounded ArtexWorker loop.
    Dispatches strictly through a fixed 6-tool dictionary (never `getattr`),
    rejects dunder/private names and excluded native scanners
    (`nmap`, `ffuf`, `dalfox`, `sqlmap`), and converts direct tool exceptions
    into structured JSON error dicts for safe loop continuation.
    """

    def __init__(self, registry: "LiveWorkerExecutorRegistry"):
        self._registry = registry
        self._tools: Dict[str, ToolSpec] = {
            "safe_http_probe": ToolSpec(
                name="safe_http_probe",
                description="Execute a policy-validated, approval-gated non-destructive HTTP probe against the authorized target.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "default": "GET"},
                        "route": {"type": "string", "default": "/"},
                        "headers": {"type": "object"},
                        "body": {"type": "string", "default": ""},
                        "rationale": {"type": "string", "default": ""},
                    },
                    "required": ["route"],
                },
                handler=self._handle_safe_http_probe,
            ),
            "auth_diff_probe": ToolSpec(
                name="auth_diff_probe",
                description="Perform a differential HTTP probe comparing primary_profile vs secondary_profile (default anonymous).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "default": "GET"},
                        "route": {"type": "string", "default": "/"},
                        "primary_profile": {"type": ["string", "null"], "default": None},
                        "secondary_profile": {"type": "string", "default": "anonymous"},
                        "headers": {"type": "object"},
                        "body": {"type": "string", "default": ""},
                    },
                    "required": ["route"],
                },
                handler=self._handle_auth_diff_probe,
            ),
            "protocol_ruler": ToolSpec(
                name="protocol_ruler",
                description="Run ProtocolRuler HTTP framing boundary audit against the authorized target.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "route": {"type": "string", "default": "/"},
                        "max_size": {"type": "integer", "default": 16384},
                    },
                },
                handler=self._handle_protocol_ruler,
            ),
            "deterministic_harness": ToolSpec(
                name="deterministic_harness",
                description="Run DeterministicHarness 3-phase HTTP desync/contamination evaluation on the target.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "raw_request": {"type": ["string", "null"], "default": None},
                        "probe_type": {"type": "string", "default": "Candidate Probe"},
                        "route": {"type": "string", "default": "/"},
                    },
                },
                handler=self._handle_deterministic_harness,
            ),
            "search_all_worker_traces": ToolSpec(
                name="search_all_worker_traces",
                description="Search shared worker execution memory for prior observations, headers, and routes.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "default": ""},
                        "limit": {"type": "integer", "default": 10},
                    },
                },
                handler=self._handle_search_all_worker_traces,
            ),
            "surface_mining": ToolSpec(
                name="surface_mining",
                description="Discover target endpoints and AI sinks via Module 21 (morluto/rea) or native AssetGraph/Mantis/AIScan fallback.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target_path": {"type": ["string", "null"], "default": None},
                        "query": {"type": "string", "default": ""},
                    },
                },
                handler=self._handle_surface_mining,
            ),
        }

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "input_schema": dict(spec.input_schema),
            }
            for spec in self._tools.values()
        ]

    def is_allowed(self, tool_name: Any) -> bool:
        if not isinstance(tool_name, str):
            return False
        name = tool_name.strip()
        if not name or name.startswith("_") or _is_excluded_tool_name(name):
            return False
        return name in self._tools

    def invoke(
        self,
        tool_name: Any,
        args: Optional[Dict[str, Any]] = None,
        *,
        _context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not isinstance(tool_name, str) or not tool_name.strip():
            return {
                "ok": False,
                "approved": False,
                "tool": str(tool_name),
                "error": "Tool name must be a non-empty string.",
            }
        clean_name = tool_name.strip()
        if _is_excluded_tool_name(clean_name):
            return {
                "ok": False,
                "approved": False,
                "tool": clean_name,
                "error": f"Excluded native scanner '{clean_name}' is prohibited in the autonomous loop.",
            }
        if clean_name.startswith("_") or clean_name not in self._tools:
            return {
                "ok": False,
                "approved": False,
                "tool": clean_name,
                "error": f"Tool '{clean_name}' is not registered in ArtexToolBox.",
            }
        if args is not None and not isinstance(args, dict):
            return {
                "ok": False,
                "approved": False,
                "tool": clean_name,
                "error": "Tool args must be a JSON object (dict).",
            }
        spec = self._tools[clean_name]
        safe_args = dict(args or {})
        try:
            res = spec.handler(safe_args, _context or {})
            if not isinstance(res, dict):
                return {"ok": False, "tool": clean_name, "error": "Tool returned non-dict output."}
            return res
        except (PermissionError, ValueError, TypeError) as exc:
            return {
                "ok": False,
                "approved": False,
                "confirmed": False,
                "tool": clean_name,
                "error": str(exc),
            }
        except Exception as exc:
            return {
                "ok": False,
                "approved": False,
                "confirmed": False,
                "tool": clean_name,
                "error": f"{type(exc).__name__}: {exc}",
            }

    def _handle_safe_http_probe(self, args: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        return self._registry._safe_http_probe_tool(
            method=args.get("method", "GET"),
            route=args.get("route", "/"),
            headers=args.get("headers"),
            body=args.get("body", ""),
            rationale=args.get("rationale", ""),
            approval_gate=ctx.get("approval_gate"),
            noise_governor=ctx.get("noise_governor"),
        )

    def _handle_auth_diff_probe(self, args: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        return self._registry._auth_diff_probe_impl(
            method=args.get("method", "GET"),
            route=args.get("route", "/"),
            primary_profile=args.get("primary_profile"),
            secondary_profile=args.get("secondary_profile", "anonymous"),
            headers=args.get("headers"),
            body=args.get("body", ""),
            approval_gate=ctx.get("approval_gate"),
            noise_governor=ctx.get("noise_governor"),
        )

    def _handle_protocol_ruler(self, args: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        return self._registry._protocol_ruler_impl(
            route=args.get("route", "/"),
            max_size=args.get("max_size", 16384),
            custom_sequences=args.get("custom_sequences"),
            approval_gate=ctx.get("approval_gate"),
            noise_governor=ctx.get("noise_governor"),
        )

    def _handle_deterministic_harness(self, args: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        return self._registry._deterministic_harness_impl(
            raw_request=args.get("raw_request"),
            probe_type=args.get("probe_type", "Candidate Probe"),
            route=args.get("route", "/"),
            approval_gate=ctx.get("approval_gate"),
            noise_governor=ctx.get("noise_governor"),
        )

    def _handle_search_all_worker_traces(self, args: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        return self._registry._search_traces_impl(
            query=args.get("query", ""),
            limit=args.get("limit", 10),
            trace_store=ctx.get("trace_store"),
        )

    def _handle_surface_mining(self, args: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        return self._registry._surface_mining_impl(
            target_path=args.get("target_path"),
            query=args.get("query", ""),
            asset_graph=ctx.get("asset_graph"),
        )


class LiveWorkerExecutorRegistry:
    """
    Executes live non-destructive verification checks for planned ARTEX attack
    candidates against authorized hosts and returns verbatim traffic receipts
    for `POE=3 (VERIFIED_EXPLOIT)` promotion.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int = 80,
        use_tls: bool = False,
        authorized: bool = False,
        traffic_session: Optional[TrafficCaptureSession] = None,
        approval_gate: Optional[ApprovalGate] = None,
        noise_governor: Optional[Any] = None,
        auth_profiles: Optional[Dict[str, AuthProfile]] = None,
        timeout: float = 8.0,
        budget_ledger: Optional[Any] = None,
        trace_store: Optional[Any] = None,
        boundary: Optional[Any] = None,
        asset_graph: Optional[Any] = None,
        arbiter: Optional[Any] = None,
        surface_provider: Optional[Callable[..., Any]] = None,
        hygiene_config: Optional[Any] = None,
        rate_limiter: Optional[Any] = None,
        workspace_root: Optional[Union[str, Path]] = None,
    ):
        self.host = host
        self.port = int(port)
        self.use_tls = bool(use_tls)
        self.authorized = bool(authorized)
        self.hygiene_config = hygiene_config
        self.rate_limiter = rate_limiter
        self._workspace_root: Optional[Path] = None
        self.workspace_root = workspace_root
        self.traffic_session = traffic_session or TrafficCaptureSession(
            hygiene_config=hygiene_config,
            rate_limiter=rate_limiter,
        )
        self._has_custom_approval_gate = approval_gate is not None
        self.approval_gate = approval_gate or ApprovalGate(mode="policy")
        self.noise_governor = noise_governor
        self.auth_profiles: Dict[str, AuthProfile] = dict(auth_profiles or {})
        self.timeout = float(timeout)
        self.budget_ledger = budget_ledger
        self.trace_store = trace_store
        self.boundary = boundary
        self.asset_graph = asset_graph
        self.arbiter = arbiter
        self.surface_provider = surface_provider
        self._cache_lock = threading.Lock()
        self._desync_exec_lock = threading.Lock()
        self._desync_cache: Dict[Tuple[Any, ...], Tuple[bool, str, str, Dict[str, Any]]] = {}
        self._boundary_cache: Dict[Tuple[Any, ...], Tuple[bool, str, str, Dict[str, Any]]] = {}
        self.toolbox = ArtexToolBox(self)

    @property
    def workspace_root(self) -> Optional[Path]:
        return self._workspace_root

    @workspace_root.setter
    def workspace_root(self, value: Optional[Union[str, Path]]) -> None:
        if value is None:
            self._workspace_root = None
            return
        ws_raw = os.fspath(value) if isinstance(value, os.PathLike) else value
        if not isinstance(ws_raw, str):
            raise ValueError("workspace_root must be a string or Path.")
        ws_stripped = ws_raw.strip()
        if not ws_stripped:
            self._workspace_root = None
            return
        from engine.execution_policy import (
            _is_drive_relative_or_colon_unsafe,
            _is_unc_path,
            _validate_canonical_path_syntax,
        )

        if ws_raw != ws_stripped or any(ord(ch) < 32 or ord(ch) == 127 for ch in ws_raw):
            raise PermissionError("Unsafe workspace_root rejected (whitespace or control characters).")
        if _is_unc_path(ws_stripped) or _is_drive_relative_or_colon_unsafe(ws_stripped):
            raise PermissionError("Unsafe workspace_root rejected (UNC, NT-device, or drive-relative/ADS path).")
        ws_err = _validate_canonical_path_syntax(ws_stripped, allow_trailing_slash=True)
        if ws_err is not None and ws_stripped != ".":
            raise PermissionError(f"Unsafe workspace_root rejected: {ws_err}")
        ws_resolved = Path(ws_stripped).resolve(strict=False)
        if _is_unc_path(str(ws_resolved)) or _is_drive_relative_or_colon_unsafe(str(ws_resolved)):
            raise PermissionError("Unsafe resolved workspace_root rejected.")
        self._workspace_root = ws_resolved

    def register_surface_provider(self, provider: Optional[Callable[..., Any]]) -> None:
        self.surface_provider = provider

    def list_tools(self) -> List[Dict[str, Any]]:
        return self.toolbox.list_tools()

    def invoke_tool(self, tool_name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.toolbox.invoke(tool_name, args)

    def _build_url(self, route: str) -> str:
        scheme = "https" if self.use_tls else "http"
        clean_route = str(route or "/").strip() or "/"
        lower_route = clean_route.lower()
        if lower_route.startswith("https://"):
            return "https://" + clean_route[8:]
        if lower_route.startswith("http://"):
            return "http://" + clean_route[7:]
        if not clean_route.startswith("/"):
            clean_route = "/" + clean_route
        return f"{scheme}://{_format_host_for_url(self.host)}:{self.port}{clean_route}"

    def _authorize_url_or_host(self, url_or_route: str) -> Tuple[str, str, int]:
        url = self._build_url(url_or_route)
        if "://" in url:
            after_scheme = url.split("://", 1)[1]
            authority = re.split(r"[/?#]", after_scheme, maxsplit=1)[0]
            if "\\" in authority:
                raise PermissionError(f"Rejected malformed URL authority containing backslash: {url!r}")
        try:
            parsed = urlparse(url)
            if parsed.username is not None or parsed.password is not None:
                raise PermissionError(f"Rejected URL containing userinfo credentials: {url!r}")
            parsed_port = parsed.port
        except ValueError as exc:
            raise PermissionError(f"Malformed target URL {url!r}: {exc}") from exc
        target_host = (parsed.hostname or "").strip()
        if not target_host:
            raise PermissionError(f"Unable to extract target host from URL: {url!r}")
        default_port = 443 if (parsed.scheme or "").lower() == "https" else 80
        target_port = int(parsed_port) if parsed_port is not None else default_port
        norm_target_host = _normalize_host_cmp(target_host)
        norm_self_host = _normalize_host_cmp(self.host)
        if (norm_target_host, target_port) != (norm_self_host, int(self.port)):
            raise PermissionError(
                f"Target URL {url!r} escapes bound target {self.host}:{self.port}"
            )
        is_ok, reason = validate_and_authorize_target(target_host, authorized=self.authorized)
        if not is_ok:
            raise PermissionError(reason)
        return url, target_host, target_port

    def _resolve_worker_gates(self, worker_ctx: Optional[Dict[str, Any]] = None) -> Tuple[Any, Optional[Any]]:
        ctx = worker_ctx if isinstance(worker_ctx, dict) else {}
        worker_gate = ctx.get("approval_gate")
        registry_gate_customized = (
            self._has_custom_approval_gate
            or getattr(self.approval_gate, "mode", "policy") != "policy"
            or bool(getattr(self.approval_gate, "rules", None))
        )
        if worker_gate is not None and registry_gate_customized and worker_gate is not self.approval_gate:
            active_approval_gate: Any = _CompositeApprovalGate([worker_gate, self.approval_gate])
        elif worker_gate is not None and not registry_gate_customized:
            active_approval_gate = worker_gate
        else:
            active_approval_gate = self.approval_gate
        active_noise_governor = (
            self.noise_governor
            if self.noise_governor is not None
            else ctx.get("noise_governor")
        )
        return active_approval_gate, active_noise_governor

    _VOLATILE_SNAPSHOT_SEQ = itertools.count()

    @classmethod
    def _volatile_sentinel(cls, obj: Any) -> Tuple[str, str, int, int]:
        return (
            "volatile_snapshot",
            type(obj).__qualname__,
            time.monotonic_ns(),
            next(cls._VOLATILE_SNAPSHOT_SEQ),
        )

    @staticmethod
    def _snapshot_sequence(
        iterable_fn: Callable[[], Any],
        max_attempts: int = 16,
    ) -> Tuple[bool, List[Any]]:
        for _ in range(max_attempts):
            try:
                return True, list(iterable_fn())
            except RuntimeError:
                continue
        return False, []

    @staticmethod
    def _safe_repr(obj: Any) -> str:
        try:
            return repr(obj)
        except Exception:
            if isinstance(obj, tuple):
                try:
                    return "(" + ", ".join(LiveWorkerExecutorRegistry._safe_repr(x) for x in obj) + ")"
                except Exception:
                    pass
            return f"<unrepr:{type(obj).__qualname__}:{id(obj)}>"

    @staticmethod
    def _freeze_cache_val(val: Any, _seen: Optional[Set[int]] = None) -> Any:
        """
        Recursively converts arbitrary values (including list, tuple, deque, set,
        frozenset, dict/Mapping, custom Iterable containers, bytearray/memoryview,
        cyclic containers, and custom unhashable objects) into deterministic,
        hashable cache-key tuples. Uses bounded snapshot-retry on mutable
        containers so concurrent mutations never raise RuntimeError or cause
        stale cache hits.
        """
        if val is None or isinstance(val, (bool, int, float, str, bytes)):
            return val
        if isinstance(val, (bytearray, memoryview)):
            return ("bytes", type(val).__qualname__, bytes(val))
        if _seen is None:
            _seen = set()
        obj_id = id(val)
        if obj_id in _seen:
            return ("cycle", type(val).__qualname__, obj_id)
        if isinstance(val, (list, tuple, collections.deque)):
            _seen.add(obj_id)
            try:
                if isinstance(val, tuple):
                    snap: Any = val
                else:
                    ok, snap = LiveWorkerExecutorRegistry._snapshot_sequence(lambda: val)
                    if not ok:
                        return LiveWorkerExecutorRegistry._volatile_sentinel(val)
                return (
                    type(val).__name__,
                    tuple(LiveWorkerExecutorRegistry._freeze_cache_val(x, _seen) for x in snap),
                )
            finally:
                _seen.discard(obj_id)
        if isinstance(val, (set, frozenset, collections_abc.Set)):
            _seen.add(obj_id)
            try:
                if isinstance(val, frozenset):
                    snap_set: Any = val
                else:
                    ok, snap_set = LiveWorkerExecutorRegistry._snapshot_sequence(lambda: val)
                    if not ok:
                        return LiveWorkerExecutorRegistry._volatile_sentinel(val)
                frozen_items = [LiveWorkerExecutorRegistry._freeze_cache_val(x, _seen) for x in snap_set]
                return (
                    type(val).__name__,
                    tuple(sorted(frozen_items, key=LiveWorkerExecutorRegistry._safe_repr)),
                )
            finally:
                _seen.discard(obj_id)
        if isinstance(val, collections_abc.Mapping):
            _seen.add(obj_id)
            try:
                ok, snap_pairs = LiveWorkerExecutorRegistry._snapshot_sequence(val.items)
                if not ok:
                    return LiveWorkerExecutorRegistry._volatile_sentinel(val)
                frozen_pairs = [
                    (
                        LiveWorkerExecutorRegistry._freeze_cache_val(k, _seen),
                        LiveWorkerExecutorRegistry._freeze_cache_val(v, _seen),
                    )
                    for k, v in snap_pairs
                ]
                tag = "dict" if isinstance(val, dict) else type(val).__name__
                return (tag, tuple(sorted(frozen_pairs, key=LiveWorkerExecutorRegistry._safe_repr)))
            finally:
                _seen.discard(obj_id)
        if isinstance(val, collections_abc.Iterable) and not isinstance(
            val, (str, bytes, bytearray, memoryview)
        ):
            _seen.add(obj_id)
            try:
                ok, snap_iter = LiveWorkerExecutorRegistry._snapshot_sequence(lambda: val)
                if not ok:
                    return LiveWorkerExecutorRegistry._volatile_sentinel(val)
                return (
                    type(val).__qualname__,
                    tuple(LiveWorkerExecutorRegistry._freeze_cache_val(x, _seen) for x in snap_iter),
                )
            finally:
                _seen.discard(obj_id)
        try:
            hash(val)
            return val
        except TypeError:
            rep = LiveWorkerExecutorRegistry._safe_repr(val)
            return ("unhashable", type(val).__qualname__, obj_id, rep)

    @classmethod
    def _freeze_rule_key(cls, rule: Any) -> Any:
        if isinstance(rule, collections_abc.Mapping):
            return cls._freeze_cache_val(rule)
        return (
            cls._freeze_cache_val(getattr(rule, "rule_id", None)),
            cls._freeze_cache_val(getattr(rule, "rule_type", None)),
            cls._freeze_cache_val(getattr(rule, "action", None)),
            cls._freeze_cache_val(getattr(rule, "pattern", None)),
            cls._freeze_cache_val(getattr(rule, "method_scope", None)),
        )

    @classmethod
    def _gate_cache_key(
        cls,
        approval_gate: Optional[Any],
        _seen_gates: Optional[Set[int]] = None,
    ) -> Any:
        if approval_gate is None:
            return 0
        if isinstance(approval_gate, _CompositeApprovalGate):
            gate_id = id(approval_gate)
            if _seen_gates is None:
                _seen_gates = set()
            if gate_id in _seen_gates:
                return ("composite_cycle", gate_id)
            _seen_gates.add(gate_id)
            try:
                gate_lock = getattr(approval_gate, "_lock", None)
                ctx_mgr = gate_lock if gate_lock is not None else contextlib.nullcontext()
                with ctx_mgr:
                    ok, snap_gates = cls._snapshot_sequence(lambda: approval_gate.gates)
                if not ok:
                    return cls._volatile_sentinel(approval_gate)
                return (
                    "composite",
                    tuple(cls._gate_cache_key(g, _seen_gates) for g in snap_gates),
                )
            finally:
                _seen_gates.discard(gate_id)
        gate_lock = getattr(approval_gate, "_lock", None)
        ctx_mgr = gate_lock if gate_lock is not None else contextlib.nullcontext()
        with ctx_mgr:
            mode_val = getattr(approval_gate, "mode", None)
            raw_rules = getattr(approval_gate, "rules", ())
            if raw_rules is None:
                rules_kind = "none"
                snap_rules: Any = ()
                rules_type_name = ""
            elif isinstance(raw_rules, (set, frozenset, collections_abc.Set)):
                rules_kind = "set"
                rules_type_name = type(raw_rules).__qualname__
                if isinstance(raw_rules, frozenset):
                    snap_rules = list(raw_rules)
                else:
                    ok, snap_rules = cls._snapshot_sequence(lambda: raw_rules)
                    if not ok:
                        return cls._volatile_sentinel(raw_rules)
            elif isinstance(raw_rules, collections_abc.Mapping):
                rules_kind = "mapping"
                rules_type_name = type(raw_rules).__qualname__
                ok, snap_rules = cls._snapshot_sequence(raw_rules.items)
                if not ok:
                    return cls._volatile_sentinel(raw_rules)
            elif isinstance(raw_rules, collections_abc.Iterable) and not isinstance(
                raw_rules, (str, bytes, bytearray, memoryview)
            ):
                rules_kind = "iterable"
                rules_type_name = type(raw_rules).__qualname__
                ok, snap_rules = cls._snapshot_sequence(lambda: raw_rules)
                if not ok:
                    return cls._volatile_sentinel(raw_rules)
            else:
                rules_kind = "other"
                rules_type_name = ""
                snap_rules = raw_rules

        if rules_kind == "none":
            rules_key: Any = ()
        elif rules_kind == "set":
            rules_key = (
                rules_type_name,
                tuple(sorted((cls._freeze_rule_key(r) for r in snap_rules), key=cls._safe_repr)),
            )
        elif rules_kind == "mapping":
            rules_key = (
                rules_type_name,
                tuple(
                    sorted(
                        (
                            (cls._freeze_cache_val(k), cls._freeze_rule_key(v))
                            for k, v in snap_rules
                        ),
                        key=cls._safe_repr,
                    )
                ),
            )
        elif rules_kind == "iterable":
            rules_key = (
                rules_type_name,
                tuple(cls._freeze_rule_key(r) for r in snap_rules),
            )
        else:
            rules_key = cls._freeze_cache_val(snap_rules)
        return (
            id(approval_gate),
            cls._freeze_cache_val(mode_val),
            rules_key,
        )

    @classmethod
    def _gate_has_prompt_mode(
        cls,
        approval_gate: Optional[Any],
        _seen_gates: Optional[Set[int]] = None,
    ) -> bool:
        if approval_gate is None:
            return False
        if isinstance(approval_gate, _CompositeApprovalGate):
            gid = id(approval_gate)
            if _seen_gates is None:
                _seen_gates = set()
            if gid in _seen_gates:
                return False
            _seen_gates.add(gid)
            try:
                gate_lock = getattr(approval_gate, "_lock", None)
                ctx_mgr = gate_lock if gate_lock is not None else contextlib.nullcontext()
                with ctx_mgr:
                    ok, snap_gates = cls._snapshot_sequence(lambda: approval_gate.gates)
                if not ok:
                    return True
                return any(cls._gate_has_prompt_mode(g, _seen_gates) for g in snap_gates)
            finally:
                _seen_gates.discard(gid)
        gate_lock = getattr(approval_gate, "_lock", None)
        ctx_mgr = gate_lock if gate_lock is not None else contextlib.nullcontext()
        with ctx_mgr:
            mode_val = getattr(approval_gate, "mode", None)
        return str(mode_val or "").strip().lower() == "prompt"

    def _pick_end_user_profile(self) -> Optional[AuthProfile]:
        for key in ("end_user_oidc", "end_user", "user", "oidc_user"):
            if key in self.auth_profiles:
                return self.auth_profiles[key]
        for prof in self.auth_profiles.values():
            if prof.role.lower() in ("end_user_oidc", "end_user", "user"):
                return prof
        for prof in self.auth_profiles.values():
            if prof.role.lower() not in ("admin", "service", "service_account", "system", "anonymous"):
                return prof
        return None

    def _safe_http_probe(
        self,
        method: str,
        route: str,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        rationale: str = "",
        *,
        approval_gate: Optional[ApprovalGate] = None,
        noise_governor: Optional[Any] = None,
    ) -> CapturedExchange:
        if headers is not None and not isinstance(headers, dict):
            raise ValueError("headers must be a dict or None")
        url, target_host, target_port = self._authorize_url_or_host(route)
        m = str(method or "GET").strip().upper() or "GET"

        from engine.execution_policy import (
            ActionType,
            ExecutionPolicy,
            ScannerTask,
            StructuredIntentProposal,
        )

        policy = ExecutionPolicy.get_instance()
        is_high_risk = policy.is_destructive_method(m)
        policy.validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.ARTEX_DUAL_GRAPH,
                action_type=ActionType.NETWORK_SOCKET,
                target_host=target_host,
                target_port=target_port,
                http_method=m,
                is_destructive=is_high_risk,
                rationale=rationale or f"Live ARTEX verification probe {m} {url}",
            )
        )

        active_gate = approval_gate or self.approval_gate
        active_gov = noise_governor if noise_governor is not None else self.noise_governor

        # Gate through ApprovalGate before sending any live traffic
        active_gate.require(
            action_type="network_socket",
            target=url,
            method=m,
            rationale=rationale or f"Live ARTEX verification probe {m} {url}",
            is_high_risk=is_high_risk,
        )
        if active_gov is not None:
            sleep_on = getattr(active_gov, "profile", "off") != "off"
            active_gov.acquire_slot(target_host, sleep_enabled=sleep_on)

        ex = self.traffic_session.send_and_capture(
            method=m,
            url=url,
            headers=dict(headers or {}),
            body=str(body or ""),
            authorized=self.authorized,
            timeout=self.timeout,
        )
        if active_gov is not None and ex.status_code in (429, 503):
            retry_after = None
            for hk, hv in (ex.response_headers or {}).items():
                if hk.lower() == "retry-after":
                    retry_after = hv
                    break
            active_gov.record_backoff(target_host, ex.status_code, retry_after_header=retry_after)
        return ex

    def _verify_auth_boundary(
        self,
        attrs: Dict[str, Any],
        *,
        approval_gate: Optional[Any] = None,
        noise_governor: Optional[Any] = None,
    ) -> Tuple[bool, str, str, Dict[str, Any]]:
        """
        Tests whether a restricted/service-only route improperly accepts an
        end-user OIDC / lower-privilege token (the GHSA-797p-rrgm-4p56 pattern).
        """
        route = str(attrs.get("target_route") or attrs.get("target_endpoint") or "/")
        method = str(attrs.get("method") or "GET").upper()
        if method in ("PUT", "DELETE", "PATCH"):
            method = "GET"

        user_prof = self._pick_end_user_profile()
        prof_name = user_prof.name if user_prof is not None else "__ANON__"
        active_gate = approval_gate or self.approval_gate
        gate_key = self._gate_cache_key(active_gate)
        b_key = (self.host, self.port, "AUTH_BOUNDARY", method, route, prof_name, gate_key)
        if not self._gate_has_prompt_mode(active_gate):
            with self._cache_lock:
                if b_key in self._boundary_cache:
                    return self._boundary_cache[b_key]

        # 1. Anonymous baseline request
        anon_ex = self._safe_http_probe(
            method,
            route,
            headers={"Accept": "application/json"},
            rationale=f"Auth-boundary anonymous baseline on {route}",
            approval_gate=approval_gate,
            noise_governor=noise_governor,
        )

        # 2. End-user / OIDC caller request (required for cross-role differential proof)
        if user_prof is None:
            res_tuple: Tuple[bool, str, str, Dict[str, Any]] = (
                False,
                f"No end-user auth profile configured to verify cross-role auth boundary on {route} (anonymous got HTTP {anon_ex.status_code}).",
                f"{method} {route} [anonymous]",
                {"traffic_id": anon_ex.traffic_id, "evidence_quote": ""},
            )
            with self._cache_lock:
                self._boundary_cache[b_key] = res_tuple
            return res_tuple

        user_hdrs = {"Accept": "application/json", **user_prof.build_headers()}
        user_ex = self._safe_http_probe(
            method,
            route,
            headers=user_hdrs,
            rationale=f"Auth-boundary cross-role probe ({user_prof.name}) on {route}",
            approval_gate=approval_gate,
            noise_governor=noise_governor,
        )
        decoded = user_ex.decoded_response_text().strip()
        # Genuine boundary violation requires anonymous rejection (401/403) AND end-user acceptance (2xx)
        if 200 <= user_ex.status_code < 300 and anon_ex.status_code in (401, 403):
            quote = decoded[:120] if decoded else f"HTTP {user_ex.status_code}"
            res_tuple = (
                True,
                f"AUTH_BOUNDARY confirmed: caller '{user_prof.name}' received HTTP {user_ex.status_code} on {route} (anonymous got HTTP {anon_ex.status_code}).",
                f"{method} {route} [profile={user_prof.name}]",
                {"traffic_id": user_ex.traffic_id, "evidence_quote": quote},
            )
        else:
            res_tuple = (
                False,
                f"Auth boundary not confirmed on {route}: caller '{user_prof.name}' got HTTP {user_ex.status_code} (anonymous HTTP {anon_ex.status_code}).",
                f"{method} {route} [profile={user_prof.name}]",
                {"traffic_id": user_ex.traffic_id, "evidence_quote": ""},
            )
        with self._cache_lock:
            self._boundary_cache[b_key] = res_tuple
        return res_tuple

    @staticmethod
    def _parse_raw_http_response(raw_text: str) -> Tuple[int, Dict[str, str], str]:
        """Splits a raw HTTP/1.x response into (status_code, headers_dict, body_text)."""
        if not raw_text:
            return 0, {}, ""
        sep = "\r\n\r\n" if "\r\n\r\n" in raw_text else ("\n\n" if "\n\n" in raw_text else None)
        if sep is None:
            return 0, {}, raw_text
        head, body = raw_text.split(sep, 1)
        lines = head.splitlines()
        status_code = 0
        if lines:
            m = re.match(r"HTTP/\S+\s+(\d{3})", lines[0].strip(), re.IGNORECASE)
            if m:
                status_code = int(m.group(1))
        hdrs: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                hdrs[k.strip()] = v.strip()
        return status_code, hdrs, body

    @staticmethod
    def _parse_raw_http_method(raw_req: Optional[str], default: str = "POST") -> str:
        if raw_req:
            for line in str(raw_req).splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                first_tok = stripped.split()[0].upper()
                if re.fullmatch(r"[A-Z][A-Z0-9_-]{0,15}", first_tok):
                    return first_tok
                break
        return default

    def _verify_desync(
        self,
        attrs: Dict[str, Any],
        *,
        approval_gate: Optional[Any] = None,
        noise_governor: Optional[Any] = None,
    ) -> Tuple[bool, str, str, Dict[str, Any]]:
        """
        Executes real framing/desync verification via DeterministicHarness,
        ActiveFlawProber, or ProtocolRuler against the authorized target.
        Returns True ONLY when desync, contamination, or structural anomaly is
        empirically confirmed (never on a plain 200 OK).
        """
        route = str(attrs.get("target_route") or attrs.get("target_endpoint") or "/")
        url, _, _ = self._authorize_url_or_host(route)
        raw_probe_attr = str(attrs.get("raw_probe") or "").strip()
        if raw_probe_attr:
            parsed_method = self._parse_raw_http_method(raw_probe_attr, default="POST")
        else:
            parsed_method = str(attrs.get("method") or "POST").strip().upper() or "POST"

        from engine.execution_policy import (
            ActionType,
            ExecutionPolicy,
            ScannerTask,
            StructuredIntentProposal,
        )

        policy = ExecutionPolicy.get_instance()
        policy.validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.ARTEX_DUAL_GRAPH,
                action_type=ActionType.NETWORK_SOCKET,
                target_host=self.host,
                target_port=self.port,
                http_method=parsed_method,
                rationale=f"Live DESYNC verification against {self.host}:{self.port}",
            )
        )

        active_gate = approval_gate or self.approval_gate
        active_gov = noise_governor if noise_governor is not None else self.noise_governor
        active_gate.require(
            action_type="network_socket",
            target=url,
            method=parsed_method,
            rationale=f"Live DESYNC verification against {self.host}:{self.port}",
            is_high_risk=policy.is_destructive_method(parsed_method),
        )

        scanner_parts: List[str] = []
        if attrs.get("scanner"):
            scanner_parts.append(str(attrs["scanner"]))
        raw_sources = attrs.get("source_scanners")
        if isinstance(raw_sources, (list, tuple, set)):
            scanner_parts.extend(str(s) for s in raw_sources if s)
        elif raw_sources:
            scanner_parts.append(str(raw_sources))
        scanner = " ".join(scanner_parts).lower()
        anomaly_type = str(attrs.get("anomaly_type") or "").upper()

        gate_key = self._gate_cache_key(active_gate)
        if raw_probe_attr:
            cache_key: Tuple[Any, ...] = (self.host, self.port, raw_probe_attr, gate_key)
        else:
            cache_key = (
                self.host,
                self.port,
                scanner or "__DEFAULT_DESYNC__",
                anomaly_type,
                bool(attrs.get("use_active_prober")),
                gate_key,
            )
        with self._cache_lock:
            if cache_key in self._desync_cache:
                return self._desync_cache[cache_key]

        # Single-flight serialization per target prevents concurrent workers from
        # colliding on stateful HTTP/1.1 connection queues during desync probing.
        with self._desync_exec_lock:
            with self._cache_lock:
                if cache_key in self._desync_cache:
                    return self._desync_cache[cache_key]

            if active_gov is not None:
                sleep_on = getattr(active_gov, "profile", "off") != "off"
                active_gov.acquire_slot(self.host, sleep_enabled=sleep_on)

            # Optional ProtocolRuler verification path (when no explicit raw_probe is supplied)
            if not raw_probe_attr and ("ruler" in scanner or "RULER" in anomaly_type):
                from protocol_ruler import ProtocolRuler

                ruler = ProtocolRuler(
                    host=self.host,
                    port=self.port,
                    use_tls=self.use_tls,
                    timeout=min(self.timeout, 3.0),
                    on_trace=lambda _: None,
                )
                ruler_res = ruler.run_comprehensive_audit(max_size=16384)
                expansions = ruler_res.get("expansions") or []
                contractions = ruler_res.get("contractions") or []
                if expansions or contractions:
                    first = (expansions or contractions)[0]
                    evidence_line = (
                        f"ProtocolRuler confirmed {first['classification']}: "
                        f"{first['name']} delta={first['delta_bytes']} bytes"
                    )
                    ex = self.traffic_session.record_exchange(
                        method="GET",
                        url=url,
                        host=self.host,
                        port=self.port,
                        request_headers={"Host": self.host},
                        request_body=str(first.get("sequence_repr") or ""),
                        status_code=200,
                        response_headers={"X-RFCHunt-Tool": "ProtocolRuler"},
                        response_body=evidence_line,
                        source="protocol_ruler",
                    )
                    ruler_tuple = (
                        True,
                        evidence_line,
                        str(first.get("sequence_repr") or ""),
                        {"traffic_id": ex.traffic_id, "evidence_quote": evidence_line[:120]},
                    )
                    with self._cache_lock:
                        self._desync_cache[cache_key] = ruler_tuple
                    return ruler_tuple

            # Optional ActiveFlawProber canonical framing path (when no explicit raw_probe is supplied)
            if not raw_probe_attr and ("activeflawprober" in scanner or attrs.get("use_active_prober")):
                from engine.active_flaw_prober import ActiveFlawProber

                prober = ActiveFlawProber(
                    host=self.host,
                    port=self.port,
                    use_tls=self.use_tls,
                    timeout=min(self.timeout, 2.5),
                    on_trace=lambda _: None,
                )
                vulns = prober.run_active_audit()
                if vulns:
                    v = vulns[0]
                    probe_txt = v.minimized_probe.decode("latin-1", errors="replace")
                    evidence_txt = f"ActiveFlawProber confirmed {v.impact.value}: {v.provenance_chain}"
                    ex = self.traffic_session.record_exchange(
                        method="POST",
                        url=url,
                        host=self.host,
                        port=self.port,
                        request_headers={"Host": self.host},
                        request_body=probe_txt,
                        status_code=200,
                        response_headers={"X-RFCHunt-Tool": "ActiveFlawProber"},
                        response_body=evidence_txt,
                        source="active_flaw_prober",
                    )
                    prober_tuple = (
                        True,
                        evidence_txt,
                        probe_txt,
                        {"traffic_id": ex.traffic_id, "evidence_quote": v.impact.value},
                    )
                    with self._cache_lock:
                        self._desync_cache[cache_key] = prober_tuple
                    return prober_tuple

            # Default tool-backed path: DeterministicHarness 3-phase desync/contamination evaluation
            from deterministic_harness import DeterministicHarness

            harness = DeterministicHarness(
                host=self.host,
                port=self.port,
                use_tls=self.use_tls,
                timeout=min(self.timeout, 1.5),
            )
            candidate_probes: List[Tuple[str, str]] = []
            if raw_probe_attr:
                candidate_probes.append(("Candidate Probe", raw_probe_attr))
            candidate_probes.extend([
                (
                    "CL.0",
                    "GET / HTTP/1.1\r\nHost: target.local\r\nContent-Length: $LENGTH\r\nConnection: keep-alive\r\n\r\n$PAYLOAD",
                ),
                (
                    "CL.TE",
                    "POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ\r\n\r\n",
                ),
                (
                    "TE.CL",
                    "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nX",
                ),
            ])
            if not raw_probe_attr:
                candidate_probes.append((
                    "multipart/byteranges",
                    "POST / HTTP/1.1\r\nHost: target.local\r\nContent-Type: multipart/byteranges; boundary=abc\r\nContent-Length: $LENGTH\r\nConnection: keep-alive\r\n\r\n$PAYLOAD",
                ))

            last_details = "No cross-request contamination observed"
            last_probe = candidate_probes[0][1]
            last_resp_raw = ""

            for probe_name, probe_tmpl in candidate_probes:
                is_vuln, desync_class, details, meta = harness.run_evaluation(
                    {"raw_request": probe_tmpl, "is_clean": False}
                )
                last_details = details
                last_probe = probe_tmpl
                raw_anomalies = list((meta or {}).get("anomalies") or [])
                # Do not treat HTTP 501 Unsupported Method from a non-CRLF probe as CRLF RHI desync
                anomalies = [
                    a for a in raw_anomalies
                    if a.get("type") != "crlf_rhi_discovery" or "crlf" in probe_name.lower()
                ]
                raw_resp = str(
                    (meta or {}).get("polluted_resp")
                    or (meta or {}).get("attacker_resp")
                    or (meta or {}).get("baseline_resp")
                    or ""
                )
                last_resp_raw = raw_resp

                if is_vuln or anomalies:
                    status_code, resp_hdrs, resp_body = self._parse_raw_http_response(raw_resp)
                    if not resp_body and raw_resp:
                        resp_body = raw_resp
                    quote = ""
                    if "terminator_marker_8821" in resp_body:
                        quote = "terminator_marker_8821"
                    elif anomalies and resp_body:
                        quote = resp_body.strip()[:120]
                    elif resp_body:
                        quote = resp_body.strip()[:120]
                    elif resp_hdrs:
                        first_k = next(iter(resp_hdrs))
                        quote = f"{first_k}: {resp_hdrs[first_k]}"[:120]

                    ex = self.traffic_session.record_exchange(
                        method=self._parse_raw_http_method(probe_tmpl, default="GET"),
                        url=url,
                        host=self.host,
                        port=self.port,
                        request_headers={"Host": self.host},
                        request_body=probe_tmpl,
                        status_code=status_code or 200,
                        response_headers=resp_hdrs,
                        response_body=resp_body,
                        source="deterministic_harness",
                    )
                    anom_tag = f" [anomalies: {', '.join(a.get('type', '') for a in anomalies)}]" if anomalies else ""
                    res_tuple = (
                        True,
                        f"DESYNC empirically confirmed via DeterministicHarness ({probe_name}/{desync_class or 'ANOMALY'}): {details}{anom_tag}",
                        probe_tmpl,
                        {"traffic_id": ex.traffic_id, "evidence_quote": quote},
                    )
                    with self._cache_lock:
                        self._desync_cache[cache_key] = res_tuple
                    return res_tuple

            # Negative result: never confirm DESYNC on a plain 200 OK
            status_code, resp_hdrs, resp_body = self._parse_raw_http_response(last_resp_raw)
            if not resp_body:
                resp_body = last_resp_raw or last_details
            ex = self.traffic_session.record_exchange(
                method=self._parse_raw_http_method(last_probe, default="GET"),
                url=url,
                host=self.host,
                port=self.port,
                request_headers={"Host": self.host},
                request_body=last_probe,
                status_code=status_code,
                response_headers=resp_hdrs,
                response_body=resp_body,
                source="deterministic_harness",
            )
            neg_tuple = (
                False,
                f"DESYNC not confirmed on {self.host}:{self.port}: {last_details}",
                last_probe,
                {"traffic_id": ex.traffic_id, "evidence_quote": ""},
            )
            with self._cache_lock:
                self._desync_cache[cache_key] = neg_tuple
            return neg_tuple

    def _verify_safe_boundary(
        self,
        attrs: Dict[str, Any],
        *,
        approval_gate: Optional[Any] = None,
        noise_governor: Optional[Any] = None,
    ) -> Tuple[bool, str, str, Dict[str, Any]]:
        """
        Safe non-destructive verification for SSRF_PIVOT / EXEC_SINK / AI_INJECTION /
        other capabilities: performs authorized boundary/canary checks
        and NEVER promotes generic 2xx reachability to POE=3 without exploit proof.
        """
        cap = str(attrs.get("capability_class") or "").upper()
        attack_type = str(attrs.get("attack_type") or "").upper()
        route = str(attrs.get("target_route") or attrs.get("target_endpoint") or "/")
        is_ai = cap == "AI_INJECTION" or "AI_" in attack_type or "PROMPT" in attack_type or bool(attrs.get("has_ai_sink"))

        if is_ai:
            req_method = "POST"
        else:
            req_method = str(attrs.get("method") or "GET").upper()
            if req_method in ("PUT", "DELETE", "PATCH"):
                req_method = "GET"

        active_gate = approval_gate or self.approval_gate
        gate_key = self._gate_cache_key(active_gate)
        b_key = (self.host, self.port, cap or ("AI_INJECTION" if is_ai else attack_type), req_method, route, gate_key)
        if not self._gate_has_prompt_mode(active_gate):
            with self._cache_lock:
                if b_key in self._boundary_cache:
                    return self._boundary_cache[b_key]

        user_prof = self._pick_end_user_profile()
        hdrs: Dict[str, str] = {"Accept": "application/json"}
        if user_prof is not None:
            hdrs.update(user_prof.build_headers())

        body = ""
        canary_token = "RFCHUNT_CANARY_PROBE"
        if is_ai and req_method == "POST":
            hdrs["Content-Type"] = "application/json"
            body = json.dumps({"prompt": canary_token, "message": canary_token})

        ex = self._safe_http_probe(
            req_method,
            route,
            headers=hdrs,
            body=body,
            rationale=f"Safe boundary/canary verification for {attack_type or cap or 'CHAIN'} on {route}",
            approval_gate=approval_gate,
            noise_governor=noise_governor,
        )
        decoded = ex.decoded_response_text().strip()
        if is_ai:
            if 200 <= ex.status_code < 300 and canary_token in decoded:
                res_tuple = (
                    True,
                    f"AI_INJECTION canary reflected on {route} (HTTP {ex.status_code}); captured traffic {ex.traffic_id}.",
                    f"{req_method} {route}",
                    {"traffic_id": ex.traffic_id, "evidence_quote": canary_token},
                )
            else:
                res_tuple = (
                    False,
                    f"AI_INJECTION canary probe not reflected on {route} (HTTP {ex.status_code}).",
                    f"{req_method} {route}",
                    {"traffic_id": ex.traffic_id, "evidence_quote": ""},
                )
            with self._cache_lock:
                self._boundary_cache[b_key] = res_tuple
            return res_tuple

        # Non-AI capabilities (EXEC_SINK, SSRF_PIVOT, CRYPTO_WEAK, ZERO_DAY_CANDIDATE, etc.)
        # must NEVER promote generic 2xx reachability ("Hello, world!") to POE=3.
        neg_tuple = (
            False,
            f"No live exploit proof confirmed for {cap or attack_type or 'CHAIN'} on {route} (HTTP {ex.status_code}); generic 2xx reachability is not promoted to POE=3.",
            f"{req_method} {route}",
            {"traffic_id": ex.traffic_id, "evidence_quote": ""},
        )
        with self._cache_lock:
            self._boundary_cache[b_key] = neg_tuple
        return neg_tuple

    def _verify_mcp_tool(
        self,
        attrs: Dict[str, Any],
        *,
        approval_gate: Optional[Any] = None,
        noise_governor: Optional[Any] = None,
    ) -> Tuple[bool, str, str, Dict[str, Any]]:
        """
        Optional adapter invoking a registered remote MCP tool over `/http` or `/sse`
        guarded by TargetAuthorizationGate, ApprovalGate, and NoiseGovernor.
        """
        raw_ep = attrs.get("mcp_endpoint")
        raw_target = (
            str(raw_ep).strip()
            if (raw_ep is not None and str(raw_ep).strip())
            else (str(attrs.get("target_route") or "/http").strip() or "/http")
        )
        if raw_target.startswith(("//", "/\\", "\\/", "\\\\")):
            raise PermissionError(f"Rejected scheme-relative MCP endpoint URL: {raw_target!r}")
        if "://" in raw_target:
            raw_scheme = raw_target.split("://", 1)[0].strip().lower()
            if raw_scheme not in ("http", "https"):
                raise PermissionError(
                    f"Rejected unsupported MCP URL scheme {raw_scheme!r}: {raw_target!r}"
                )
        mcp_url, mcp_host, mcp_port = self._authorize_url_or_host(raw_target)
        parsed = urlparse(mcp_url)

        from engine.execution_policy import (
            ActionType,
            ExecutionPolicy,
            ScannerTask,
            StructuredIntentProposal,
        )

        ExecutionPolicy.get_instance().validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.ARTEX_DUAL_GRAPH,
                action_type=ActionType.NETWORK_SOCKET,
                target_host=mcp_host,
                target_port=mcp_port,
                http_method="POST",
                is_destructive=False,
                rationale=f"Invoke remote MCP tool on {mcp_url}",
            )
        )

        active_gate = approval_gate or self.approval_gate
        active_gov = noise_governor if noise_governor is not None else self.noise_governor
        active_gate.require(
            action_type="mcp_tool",
            target=mcp_url,
            method="POST",
            rationale=f"Invoke remote MCP tool on {mcp_url}",
            is_high_risk=False,
        )
        if active_gov is not None:
            sleep_on = getattr(active_gov, "profile", "off") != "off"
            active_gov.acquire_slot(mcp_host, sleep_enabled=sleep_on)

        tool_name = str(attrs.get("mcp_tool_name") or "artex_budget_status")
        tool_args = attrs.get("mcp_tool_args") if isinstance(attrs.get("mcp_tool_args"), dict) else {}
        rpc_body = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": tool_args},
        })
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if attrs.get("mcp_bearer_token"):
            hdrs["Authorization"] = f"Bearer {attrs['mcp_bearer_token']}"

        transport = str(attrs.get("mcp_transport") or ("sse" if mcp_url.rstrip("/").endswith("/sse") else "http")).lower()
        if transport == "sse" and mcp_url.rstrip("/").endswith("/sse"):
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            sse_deadline = time.monotonic() + max(0.5, float(self.timeout))
            with httpx.Client(timeout=self.timeout, trust_env=False, follow_redirects=False) as client:
                with client.stream("GET", mcp_url, headers=hdrs) as stream_resp:
                    msg_path = "/message"
                    for line_idx, line in enumerate(stream_resp.iter_lines()):
                        if line_idx >= 64 or time.monotonic() >= sse_deadline:
                            break
                        if line.startswith("data:"):
                            candidate = line.split("data:", 1)[1].strip()
                            if (
                                candidate.startswith("/message")
                                and not candidate.startswith("//")
                                and "\\" not in candidate
                            ):
                                msg_path = candidate
                                break
                    post_url, _, _ = self._authorize_url_or_host(f"{base_url}{msg_path}")
                    ex = self.traffic_session.send_and_capture(
                        method="POST",
                        url=post_url,
                        headers=hdrs,
                        body=rpc_body,
                        authorized=self.authorized,
                        timeout=self.timeout,
                    )
        else:
            ex = self.traffic_session.send_and_capture(
                method="POST",
                url=mcp_url,
                headers=hdrs,
                body=rpc_body,
                authorized=self.authorized,
                timeout=self.timeout,
            )

        if active_gov is not None and ex.status_code in (429, 503):
            retry_after = None
            for hk, hv in (ex.response_headers or {}).items():
                if hk.lower() == "retry-after":
                    retry_after = hv
                    break
            active_gov.record_backoff(mcp_host, ex.status_code, retry_after_header=retry_after)

        decoded = ex.decoded_response_text().strip()
        is_valid_rpc = False
        if 200 <= ex.status_code < 300 and decoded:
            try:
                rpc_obj = json.loads(decoded)
                is_valid_rpc = (
                    isinstance(rpc_obj, dict)
                    and (rpc_obj.get("jsonrpc") == "2.0" or "result" in rpc_obj)
                    and "error" not in rpc_obj
                )
            except Exception:
                is_valid_rpc = ('"jsonrpc"' in decoded or '"result"' in decoded) and '"error"' not in decoded.lower()

        if is_valid_rpc:
            quote = decoded[:120] if decoded else f"HTTP {ex.status_code}"
            return (
                True,
                f"MCP tool '{tool_name}' verified over {transport.upper()} ({mcp_url}, HTTP {ex.status_code}).",
                rpc_body,
                {"traffic_id": ex.traffic_id, "evidence_quote": quote},
            )
        return (
            False,
            f"MCP tool '{tool_name}' call failed on {mcp_url} (HTTP {ex.status_code}).",
            rpc_body,
            {"traffic_id": ex.traffic_id, "evidence_quote": ""},
        )

    def execute_candidate_live(self, attrs: Dict[str, Any]) -> Tuple[bool, str, str, Dict[str, Any]]:
        """Primary executor callable compatible with `ArtexWorker.execute_candidate`."""
        raw_attrs = dict(attrs or {})
        worker_ctx = raw_attrs.pop("_worker_context", None)
        active_approval_gate, active_noise_governor = self._resolve_worker_gates(worker_ctx)

        cap = str(raw_attrs.get("capability_class") or "").upper()
        attack_type = str(raw_attrs.get("attack_type") or "").upper()
        step_caps = {
            str(s.get("capability") or "").upper()
            for s in (raw_attrs.get("chain_steps") or [])
            if isinstance(s, dict)
        }

        if cap == "MCP_TOOL" or "MCP_TOOL" in attack_type or raw_attrs.get("mcp_endpoint"):
            return self._verify_mcp_tool(
                raw_attrs,
                approval_gate=active_approval_gate,
                noise_governor=active_noise_governor,
            )

        is_multi = (
            bool(raw_attrs.get("is_multi_hop"))
            or len(step_caps) >= 2
            or any(tag in attack_type for tag in ("3HOP_", "4HOP_", "MULTI_HOP_", "DESYNC_PROMPT_INJECTION", "ZERODAY_AI_INJECTION"))
        )

        if is_multi:
            needs_desync = (
                "DESYNC" in step_caps
                or any(k in attack_type for k in ("DESYNC", "PIPELINE_HIJACK", "SMUGGL", "CRLF", "CL.TE", "TE.CL", "RULER"))
            )
            needs_auth = (
                bool(step_caps & {"AUTH_BOUNDARY", "AUTH_SECRET"})
                or any(k in attack_type for k in ("AUTH_BOUNDARY", "CREDENTIAL_AUTH", "AUTH_BYPASS", "AUTH_SECRET"))
            )
            needs_ai = (
                "AI_INJECTION" in step_caps
                or bool(raw_attrs.get("has_ai_sink"))
                or any(k in attack_type for k in ("AI_INJECTION", "PROMPT"))
            )
            needs_sink = (
                bool(step_caps & {"EXEC_SINK", "SSRF_PIVOT"})
                or any(k in attack_type for k in ("_EXEC", "EXEC_SINK", "SSRF"))
            ) and not needs_ai

            step_traffic_ids: List[str] = []
            last_verified: Optional[Tuple[bool, str, str, Dict[str, Any]]] = None

            if needs_desync:
                ok, msg, probe, meta = self._verify_desync(
                    raw_attrs,
                    approval_gate=active_approval_gate,
                    noise_governor=active_noise_governor,
                )
                if meta.get("traffic_id"):
                    step_traffic_ids.append(str(meta["traffic_id"]))
                if not ok:
                    return (False, f"Multi-hop DESYNC prerequisite not confirmed: {msg}", probe, meta)
                last_verified = (ok, msg, probe, meta)

            if needs_auth:
                auth_route = raw_attrs.get("auth_route") or raw_attrs.get("target_route") or raw_attrs.get("target_endpoint") or "/"
                auth_attrs = {**raw_attrs, "capability_class": "AUTH_BOUNDARY", "target_route": auth_route}
                ok, msg, probe, meta = self._verify_auth_boundary(
                    auth_attrs,
                    approval_gate=active_approval_gate,
                    noise_governor=active_noise_governor,
                )
                if meta.get("traffic_id"):
                    step_traffic_ids.append(str(meta["traffic_id"]))
                if not ok:
                    return (False, f"Multi-hop auth boundary step not confirmed: {msg}", probe, meta)
                last_verified = (ok, msg, probe, meta)

            if needs_ai:
                ai_route = raw_attrs.get("ai_route") or raw_attrs.get("target_route") or "/api/chat"
                ai_attrs = {
                    **raw_attrs,
                    "capability_class": "AI_INJECTION",
                    "has_ai_sink": True,
                    "method": "POST",
                    "target_route": ai_route,
                }
                ok, msg, probe, meta = self._verify_safe_boundary(
                    ai_attrs,
                    approval_gate=active_approval_gate,
                    noise_governor=active_noise_governor,
                )
                if meta.get("traffic_id"):
                    step_traffic_ids.append(str(meta["traffic_id"]))
                if not ok:
                    return (False, f"Multi-hop AI_INJECTION step not confirmed: {msg}", probe, meta)
                last_verified = (ok, msg, probe, meta)

            if needs_sink:
                ok, msg, probe, meta = self._verify_safe_boundary(
                    raw_attrs,
                    approval_gate=active_approval_gate,
                    noise_governor=active_noise_governor,
                )
                if meta.get("traffic_id"):
                    step_traffic_ids.append(str(meta["traffic_id"]))
                if not ok:
                    return (False, f"Multi-hop sink step not confirmed: {msg}", probe, meta)
                last_verified = (ok, msg, probe, meta)

            if last_verified is not None:
                ok, msg, probe, meta = last_verified
                out_meta = dict(meta or {})
                if step_traffic_ids:
                    out_meta["step_traffic_ids"] = step_traffic_ids
                return (ok, msg, probe, out_meta)
            return self._verify_safe_boundary(
                raw_attrs,
                approval_gate=active_approval_gate,
                noise_governor=active_noise_governor,
            )

        if (
            cap in ("AUTH_BOUNDARY", "AUTH_SECRET")
            or any(k in attack_type for k in ("AUTH_BOUNDARY", "CREDENTIAL_AUTH", "AUTH_BYPASS", "AUTH_SECRET"))
        ):
            return self._verify_auth_boundary(
                raw_attrs,
                approval_gate=active_approval_gate,
                noise_governor=active_noise_governor,
            )
        if (
            cap == "DESYNC"
            or any(k in attack_type for k in ("DESYNC", "PIPELINE_HIJACK", "SMUGGL", "CRLF", "CL.TE", "TE.CL", "RULER"))
        ):
            return self._verify_desync(
                raw_attrs,
                approval_gate=active_approval_gate,
                noise_governor=active_noise_governor,
            )
        return self._verify_safe_boundary(
            raw_attrs,
            approval_gate=active_approval_gate,
            noise_governor=active_noise_governor,
        )

    execute_candidate_live._accepts_worker_context = True  # type: ignore[attr-defined]

    def as_executor_fn(self) -> Callable[[Dict[str, Any]], Tuple[bool, str, str, Dict[str, Any]]]:
        def _live_exec(exec_attrs: Dict[str, Any]) -> Tuple[bool, str, str, Dict[str, Any]]:
            return self.execute_candidate_live(exec_attrs)

        _live_exec._accepts_worker_context = True  # type: ignore[attr-defined]
        return _live_exec

    # ------------------------------------------------------------------
    # Typed JSON Tool Methods (F4 & F6)
    # ------------------------------------------------------------------

    def _resolve_profile(self, profile_name: Optional[str]) -> Optional[AuthProfile]:
        if profile_name is None:
            return self._pick_end_user_profile()
        key = str(profile_name).strip()
        if not key:
            return None
        if key in self.auth_profiles:
            return self.auth_profiles[key]
        for prof in self.auth_profiles.values():
            if prof.name == key:
                return prof
        return None

    def _safe_http_probe_tool(
        self,
        *,
        method: str = "GET",
        route: str = "/",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        rationale: str = "",
        approval_gate: Optional[ApprovalGate] = None,
        noise_governor: Optional[Any] = None,
    ) -> Dict[str, Any]:
        ex = self._safe_http_probe(
            method=str(method or "GET"),
            route=str(route if route is not None else "/"),
            headers=headers,
            body=str(body or ""),
            rationale=str(rationale or ""),
            approval_gate=approval_gate,
            noise_governor=noise_governor,
        )
        decoded = ex.decoded_response_text()
        return {
            "ok": True,
            "approved": True,
            "traffic_id": ex.traffic_id,
            "method": ex.method,
            "url": ex.url,
            "status_code": int(ex.status_code),
            "response_headers": dict(ex.response_headers or {}),
            "response_body": decoded[:4096],
            "body_length": len(ex.decoded_response_bytes()),
        }

    def safe_http_probe(
        self,
        method: str = "GET",
        route: str = "/",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        rationale: str = "",
    ) -> Dict[str, Any]:
        return self._safe_http_probe_tool(
            method=method,
            route=route,
            headers=headers,
            body=body,
            rationale=rationale,
        )

    def _auth_diff_probe_impl(
        self,
        *,
        method: str = "GET",
        route: str = "/",
        primary_profile: Optional[str] = None,
        secondary_profile: str = "anonymous",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        approval_gate: Optional[ApprovalGate] = None,
        noise_governor: Optional[Any] = None,
    ) -> Dict[str, Any]:
        if headers is not None and not isinstance(headers, dict):
            raise ValueError("headers must be a dict or None")
        clean_route = str(route if route is not None else "/")
        m = str(method or "GET").strip().upper() or "GET"
        self._authorize_url_or_host(clean_route)

        prim_prof = self._resolve_profile(primary_profile)
        if prim_prof is None:
            return {
                "ok": False,
                "confirmed": False,
                "exposed": False,
                "method": m,
                "route": clean_route,
                "primary_profile": primary_profile,
                "secondary_profile": secondary_profile,
                "error": (
                    f"Unknown primary_profile: {primary_profile!r}"
                    if primary_profile is not None
                    else "No primary end-user auth profile configured"
                ),
            }

        sec_label = str(secondary_profile if secondary_profile is not None else "anonymous").strip() or "anonymous"
        sec_prof: Optional[AuthProfile] = None
        if sec_label.lower() not in ("anonymous", "anon", "none"):
            sec_prof = self._resolve_profile(sec_label)
            if sec_prof is None:
                return {
                    "ok": False,
                    "confirmed": False,
                    "exposed": False,
                    "method": m,
                    "route": clean_route,
                    "primary_profile": prim_prof.name,
                    "secondary_profile": sec_label,
                    "error": f"Unknown secondary_profile: {sec_label!r}",
                }

        base_hdrs: Dict[str, str] = {"Accept": "application/json"}
        if headers:
            base_hdrs.update({str(k): str(v) for k, v in headers.items()})

        sec_hdrs = dict(base_hdrs)
        if sec_prof is not None:
            sec_hdrs.update(sec_prof.build_headers())
        sec_ex = self._safe_http_probe(
            m,
            clean_route,
            headers=sec_hdrs,
            body=str(body or ""),
            rationale=f"Auth-diff secondary ({sec_label}) probe on {clean_route}",
            approval_gate=approval_gate,
            noise_governor=noise_governor,
        )

        prim_hdrs = dict(base_hdrs)
        prim_hdrs.update(prim_prof.build_headers())
        prim_ex = self._safe_http_probe(
            m,
            clean_route,
            headers=prim_hdrs,
            body=str(body or ""),
            rationale=f"Auth-diff primary ({prim_prof.name}) probe on {clean_route}",
            approval_gate=approval_gate,
            noise_governor=noise_governor,
        )

        prim_decoded = prim_ex.decoded_response_text().strip()
        sec_decoded = sec_ex.decoded_response_text().strip()
        confirmed = (200 <= prim_ex.status_code < 300) and (sec_ex.status_code in (401, 403))
        quote = (prim_decoded[:120] if prim_decoded else f"HTTP {prim_ex.status_code}") if confirmed else ""
        return {
            "ok": True,
            "confirmed": confirmed,
            "exposed": confirmed,
            "method": m,
            "route": clean_route,
            "primary_profile": prim_prof.name,
            "secondary_profile": sec_prof.name if sec_prof is not None else "anonymous",
            "primary_status": int(prim_ex.status_code),
            "secondary_status": int(sec_ex.status_code),
            "status_code": int(prim_ex.status_code),
            "anon_status": int(sec_ex.status_code),
            "traffic_id": prim_ex.traffic_id,
            "secondary_traffic_id": sec_ex.traffic_id,
            "evidence_quote": quote,
            "primary_excerpt": prim_decoded[:512],
            "secondary_excerpt": sec_decoded[:512],
        }

    def auth_diff_probe(
        self,
        method: str = "GET",
        route: str = "/",
        primary_profile: Optional[str] = None,
        secondary_profile: str = "anonymous",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> Dict[str, Any]:
        return self._auth_diff_probe_impl(
            method=method,
            route=route,
            primary_profile=primary_profile,
            secondary_profile=secondary_profile,
            headers=headers,
            body=body,
        )

    def _protocol_ruler_impl(
        self,
        *,
        route: str = "/",
        max_size: int = 16384,
        custom_sequences: Optional[List[Tuple[str, bytes, str]]] = None,
        approval_gate: Optional[ApprovalGate] = None,
        noise_governor: Optional[Any] = None,
    ) -> Dict[str, Any]:
        clean_route = str(route if route is not None else "/")
        url, target_host, target_port = self._authorize_url_or_host(clean_route)

        from engine.execution_policy import (
            ActionType,
            ExecutionPolicy,
            ScannerTask,
            StructuredIntentProposal,
        )

        ExecutionPolicy.get_instance().validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.ARTEX_DUAL_GRAPH,
                action_type=ActionType.NETWORK_SOCKET,
                target_host=target_host,
                target_port=target_port,
                http_method="GET",
                rationale=f"ProtocolRuler framing audit on {url}",
            )
        )
        active_gate = approval_gate or self.approval_gate
        active_gov = noise_governor if noise_governor is not None else self.noise_governor
        active_gate.require(
            action_type="network_socket",
            target=url,
            method="GET",
            rationale=f"ProtocolRuler framing audit on {url}",
            is_high_risk=False,
        )
        if isinstance(max_size, bool):
            m_size = 0
        else:
            try:
                m_size = int(max_size)
            except (TypeError, ValueError, OverflowError):
                m_size = 0
        if m_size <= 0:
            return {
                "ok": False,
                "confirmed": False,
                "vulnerable": False,
                "route": clean_route,
                "max_size": m_size,
                "baseline_limit": None,
                "expansions": [],
                "contractions": [],
                "findings": [],
                "traffic_id": "",
                "evidence_quote": "",
                "error": "max_size must be positive",
            }
        if active_gov is not None:
            sleep_on = getattr(active_gov, "profile", "off") != "off"
            active_gov.acquire_slot(target_host, sleep_enabled=sleep_on)

        try:
            from protocol_ruler import ProtocolRuler

            with self._desync_exec_lock:
                ruler = ProtocolRuler(
                    host=target_host,
                    port=target_port,
                    use_tls=self.use_tls,
                    timeout=min(self.timeout, 3.0),
                    on_trace=lambda _: None,
                )
                ruler_res = ruler.run_comprehensive_audit(
                    custom_sequences=custom_sequences,
                    max_size=min(m_size, 131072),
                )
        except (PermissionError, ValueError):
            raise
        except Exception as exc:
            return {
                "ok": False,
                "confirmed": False,
                "vulnerable": False,
                "route": clean_route,
                "max_size": m_size,
                "baseline_limit": None,
                "expansions": [],
                "contractions": [],
                "findings": [],
                "traffic_id": "",
                "evidence_quote": "",
                "error": f"{type(exc).__name__}: {exc}",
            }

        expansions = list((ruler_res or {}).get("expansions") or [])
        contractions = list((ruler_res or {}).get("contractions") or [])
        findings = list((ruler_res or {}).get("findings") or [])
        confirmed = bool(expansions or contractions)
        traffic_id = ""
        evidence_quote = ""
        if confirmed:
            first = (expansions or contractions)[0]
            evidence_line = (
                f"ProtocolRuler confirmed {first.get('classification', 'ANOMALY')}: "
                f"{first.get('name', 'probe')} delta={first.get('delta_bytes', 0)} bytes"
            )
            ex = self.traffic_session.record_exchange(
                method="GET",
                url=url,
                host=target_host,
                port=target_port,
                request_headers={"Host": target_host},
                request_body=str(first.get("sequence_repr") or ""),
                status_code=200,
                response_headers={"X-RFCHunt-Tool": "ProtocolRuler"},
                response_body=evidence_line,
                source="protocol_ruler",
            )
            traffic_id = ex.traffic_id
            evidence_quote = evidence_line[:120]

        return {
            "ok": bool((ruler_res or {}).get("success", True)),
            "confirmed": confirmed,
            "vulnerable": confirmed,
            "route": clean_route,
            "max_size": m_size,
            "baseline_limit": (ruler_res or {}).get("baseline_limit"),
            "expansions": expansions,
            "contractions": contractions,
            "findings": findings,
            "traffic_id": traffic_id,
            "evidence_quote": evidence_quote,
            "error": str((ruler_res or {}).get("error") or ""),
        }

    def protocol_ruler(
        self,
        route: str = "/",
        max_size: int = 16384,
        custom_sequences: Optional[List[Tuple[str, bytes, str]]] = None,
    ) -> Dict[str, Any]:
        return self._protocol_ruler_impl(
            route=route,
            max_size=max_size,
            custom_sequences=custom_sequences,
        )

    def _deterministic_harness_impl(
        self,
        *,
        raw_request: Optional[str] = None,
        probe_type: str = "Candidate Probe",
        route: str = "/",
        approval_gate: Optional[ApprovalGate] = None,
        noise_governor: Optional[Any] = None,
    ) -> Dict[str, Any]:
        clean_route = str(route if route is not None else "/")
        url, target_host, target_port = self._authorize_url_or_host(clean_route)
        p_type = str(probe_type or "Candidate Probe")

        from engine.execution_policy import (
            ActionType,
            ExecutionPolicy,
            ScannerTask,
            StructuredIntentProposal,
        )

        parsed_method = (
            self._parse_raw_http_method(raw_request, default="POST")
            if raw_request is not None
            else "GET"
        )
        policy = ExecutionPolicy.get_instance()
        policy.validate_intent(
            StructuredIntentProposal(
                task=ScannerTask.ARTEX_DUAL_GRAPH,
                action_type=ActionType.NETWORK_SOCKET,
                target_host=target_host,
                target_port=target_port,
                http_method=parsed_method,
                rationale=f"DeterministicHarness probe ({p_type}) on {url}",
            )
        )
        active_gate = approval_gate or self.approval_gate
        active_gov = noise_governor if noise_governor is not None else self.noise_governor
        active_gate.require(
            action_type="network_socket",
            target=url,
            method=parsed_method,
            rationale=f"DeterministicHarness probe ({p_type}) on {url}",
            is_high_risk=policy.is_destructive_method(parsed_method),
        )

        if raw_request is not None and not str(raw_request).strip():
            return {
                "ok": False,
                "confirmed": False,
                "vulnerable": False,
                "probe_type": p_type,
                "route": clean_route,
                "desync_class": None,
                "details": "",
                "anomalies": [],
                "traffic_id": "",
                "evidence_quote": "",
                "error": "Empty raw_request",
            }

        if active_gov is not None:
            sleep_on = getattr(active_gov, "profile", "off") != "off"
            active_gov.acquire_slot(target_host, sleep_enabled=sleep_on)

        norm_route = clean_route if clean_route.startswith("/") else "/" + clean_route
        probe_str = (
            str(raw_request)
            if raw_request is not None
            else f"GET {norm_route} HTTP/1.1\r\nHost: {_format_host_for_url(target_host)}:{target_port}\r\nConnection: keep-alive\r\n\r\n"
        )

        try:
            from deterministic_harness import DeterministicHarness

            with self._desync_exec_lock:
                harness = DeterministicHarness(
                    host=target_host,
                    port=target_port,
                    use_tls=self.use_tls,
                    timeout=min(self.timeout, 1.5),
                )
                is_vuln, desync_class, details, meta = harness.run_evaluation(
                    {"raw_request": probe_str, "is_clean": False}
                )
        except (PermissionError, ValueError):
            raise
        except Exception as exc:
            return {
                "ok": False,
                "confirmed": False,
                "vulnerable": False,
                "probe_type": p_type,
                "route": clean_route,
                "desync_class": None,
                "details": "",
                "anomalies": [],
                "traffic_id": "",
                "evidence_quote": "",
                "error": f"{type(exc).__name__}: {exc}",
            }

        raw_anomalies = list((meta or {}).get("anomalies") or [])
        anomalies = [
            a for a in raw_anomalies
            if a.get("type") != "crlf_rhi_discovery" or "crlf" in p_type.lower()
        ]
        confirmed = bool(is_vuln or anomalies)
        raw_resp = str(
            (meta or {}).get("polluted_resp")
            or (meta or {}).get("attacker_resp")
            or (meta or {}).get("baseline_resp")
            or ""
        )
        status_code, resp_hdrs, resp_body = self._parse_raw_http_response(raw_resp)
        if not resp_body:
            resp_body = raw_resp or str(details or "")

        quote = ""
        if confirmed:
            if "terminator_marker_8821" in resp_body:
                quote = "terminator_marker_8821"
            elif resp_body:
                quote = resp_body.strip()[:120]
            elif resp_hdrs:
                fk = next(iter(resp_hdrs))
                quote = f"{fk}: {resp_hdrs[fk]}"[:120]

        ex = self.traffic_session.record_exchange(
            method=parsed_method,
            url=url,
            host=target_host,
            port=target_port,
            request_headers={"Host": target_host},
            request_body=probe_str,
            status_code=status_code or (200 if confirmed else 0),
            response_headers=resp_hdrs,
            response_body=resp_body,
            source="deterministic_harness",
        )
        return {
            "ok": True,
            "confirmed": confirmed,
            "vulnerable": confirmed,
            "desync_class": desync_class,
            "probe_type": p_type,
            "route": clean_route,
            "details": str(details or ""),
            "anomalies": anomalies,
            "traffic_id": ex.traffic_id,
            "evidence_quote": quote,
            "response_excerpt": raw_resp[:512],
        }

    def deterministic_harness(
        self,
        raw_request: Optional[str] = None,
        probe_type: str = "Candidate Probe",
        route: str = "/",
    ) -> Dict[str, Any]:
        return self._deterministic_harness_impl(
            raw_request=raw_request,
            probe_type=probe_type,
            route=route,
        )

    def _search_traces_impl(
        self,
        *,
        query: str = "",
        limit: int = 10,
        trace_store: Optional[Any] = None,
    ) -> Dict[str, Any]:
        q = str(query or "")
        if isinstance(limit, bool):
            lim = 0
        else:
            try:
                lim = int(limit)
            except (TypeError, ValueError):
                lim = 0
        if lim <= 0:
            return {"ok": True, "query": q, "count": 0, "traces": []}

        store = trace_store if trace_store is not None else self.trace_store
        if store is None:
            return {
                "ok": True,
                "query": q,
                "count": 0,
                "traces": [],
                "note": "No trace_store configured",
            }
        hits = list(store.search_all_worker_traces(query=q, limit=lim) or [])[:lim]
        return {
            "ok": True,
            "query": q,
            "count": len(hits),
            "traces": hits,
        }

    def search_all_worker_traces(self, query: str = "", limit: int = 10) -> Dict[str, Any]:
        return self._search_traces_impl(query=query, limit=limit)

    @staticmethod
    def _invoke_surface_callable(fn: Callable[..., Any], target_path: Optional[str], query: str) -> Any:
        try:
            sig = inspect.signature(fn)
            params = sig.parameters
            accepts_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
            kw: Dict[str, Any] = {}
            if accepts_varkw or "target_path" in params:
                kw["target_path"] = target_path
            if accepts_varkw or "query" in params:
                kw["query"] = query
            if kw or accepts_varkw:
                return fn(**kw)
            pos_params = [
                p for p in params.values()
                if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            ]
            if len(pos_params) >= 2:
                return fn(target_path, query)
            if len(pos_params) == 1:
                return fn(target_path if "path" in pos_params[0].name else query)
            return fn()
        except TypeError:
            return fn(target_path, query)

    @staticmethod
    def _normalize_module21_items(raw: Any) -> List[Dict[str, Any]]:
        tagged_items: List[Tuple[Optional[str], Any]] = []
        if isinstance(raw, list):
            tagged_items = [(None, item) for item in raw]
        elif isinstance(raw, dict):
            for key in ("endpoints", "ai_sinks", "surfaces", "assets", "routes", "items", "results"):
                val = raw.get(key)
                if isinstance(val, list) and len(val) > 0:
                    for item in val:
                        tagged_items.append((key, item))
        if not tagged_items:
            return []

        normalized: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str, str, str, str]] = set()
        for src_key, item in tagged_items:
            default_ntype = "AI_SINK" if src_key == "ai_sinks" else "ENDPOINT"
            if isinstance(item, dict):
                route = item.get("route") or item.get("path") or item.get("endpoint") or item.get("url")
                if not route and not item.get("label"):
                    continue
                rec = dict(item)
                if route is not None:
                    rec["route"] = str(route)
                rec["method"] = str(item.get("method") or "GET").upper()
                rec["source"] = str(item.get("source") or "module21")
                raw_nt = item.get("node_type")
                rec["node_type"] = str(raw_nt) if raw_nt else default_ntype
                dedup_k = (
                    rec["node_type"].upper(),
                    rec["method"],
                    str(rec.get("route") or ""),
                    str(rec.get("label") or ""),
                    str(rec.get("host") or ""),
                )
                if dedup_k in seen:
                    continue
                seen.add(dedup_k)
                normalized.append(rec)
            elif isinstance(item, str) and item.strip():
                r_str = item.strip()
                dedup_k = (default_ntype, "GET", r_str, "", "")
                if dedup_k in seen:
                    continue
                seen.add(dedup_k)
                normalized.append({
                    "route": r_str,
                    "method": "GET",
                    "node_type": default_ntype,
                    "source": "module21",
                })
        return normalized

    @staticmethod
    def _filter_surface_by_query(items: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
        q = str(query or "").strip().lower()
        if not q:
            return list(items)
        return [it for it in items if q in json.dumps(it, default=str).lower()]

    @staticmethod
    def _normalize_host_token(raw_host: Any) -> Tuple[Optional[str], bool]:
        if raw_host is None:
            return None, False
        s = str(raw_host).strip()
        if not s:
            return None, False
        if s.startswith("//"):
            return None, True
        if "://" in s:
            scheme = s.split("://", 1)[0].strip().lower()
            if scheme not in ("http", "https"):
                return None, True
            after_scheme = s.split("://", 1)[1]
            authority = re.split(r"[/?#]", after_scheme, maxsplit=1)[0]
            if "\\" in authority:
                return None, True
            try:
                parsed = urlparse(s)
                _ = parsed.port
            except ValueError:
                return None, True
            host_clean = _normalize_host_cmp(parsed.hostname or "")
            if not host_clean:
                return None, True
            return host_clean, False
        if "\\" in s:
            return None, True
        s = re.split(r"[/?#]", s, maxsplit=1)[0].strip()
        if "@" in s:
            s = s.rsplit("@", 1)[-1].strip()
        if s.startswith("["):
            if "]" not in s:
                return None, True
            end_idx = s.index("]")
            host_part = s[1:end_idx]
            rest = s[end_idx + 1:].strip()
            if rest and (not rest.startswith(":") or (len(rest) > 1 and not rest[1:].isdigit())):
                return None, True
            s = host_part
        elif s.count(":") == 1:
            h_part, p_part = s.split(":", 1)
            if p_part and not p_part.isdigit():
                return None, True
            s = h_part
        clean = _normalize_host_cmp(s)
        if not clean:
            return None, True
        return clean, False

    @staticmethod
    def _is_scheme_relative_authority(
        tok: str,
        known_hosts: Optional[Set[str]] = None,
    ) -> Tuple[Optional[str], bool]:
        if not tok or not tok.startswith("//") or tok.startswith("///"):
            return None, False
        authority = re.split(r"[/?#]", tok[2:], maxsplit=1)[0].strip()
        if not authority:
            return None, False
        if "\\" in authority:
            return tok, True
        has_userinfo = "@" in authority
        if has_userinfo:
            host_port = authority.rsplit("@", 1)[-1].strip()
            if not host_port:
                return tok, True
        else:
            host_port = authority
        if host_port.startswith("["):
            if "]" not in host_port:
                return tok, True
            end_idx = host_port.index("]")
            inner = host_port[1:end_idx].strip()
            tail = host_port[end_idx + 1:].strip()
            if not inner:
                return tok, True
            if tail and (not tail.startswith(":") or len(tail) <= 1 or not tail[1:].isdigit()):
                return tok, True
            try:
                ipaddress.IPv6Address(inner)
            except ValueError:
                return tok, True
            return tok, False
        has_port = False
        host_no_port = host_port
        if ":" in host_port:
            if host_port.count(":") > 1:
                return (tok, True) if has_userinfo else (None, False)
            h_cand, p_cand = host_port.split(":", 1)
            if not p_cand or not p_cand.isdigit():
                return (tok, True) if has_userinfo else (None, False)
            host_no_port = h_cand
            has_port = True
        host_no_port_clean = host_no_port.strip().lower().rstrip(".")
        if (
            not host_no_port_clean
            or host_no_port_clean in (".", "..")
            or host_no_port_clean.startswith(".")
            or ".." in host_no_port_clean
        ):
            return (tok, True) if has_userinfo else (None, False)
        if has_userinfo:
            return tok, False
        if host_no_port_clean == "localhost" or has_port:
            return tok, False
        if known_hosts and host_no_port_clean in known_hosts:
            return tok, False
        if "." not in host_no_port_clean:
            return None, False
        try:
            ipaddress.IPv4Address(host_no_port_clean)
            return tok, False
        except ValueError:
            pass
        tld = host_no_port_clean.rsplit(".", 1)[-1]
        if not tld or tld.isdigit():
            return None, False
        if f".{tld}" in _LIVE_EXEC_STATIC_EXTS:
            return None, False
        return tok, False

    @classmethod
    def _infer_host_from_record(
        cls,
        rec: Dict[str, Any],
        known_hosts: Optional[Set[str]] = None,
    ) -> Optional[str]:
        for h_key in ("host", "domain"):
            hv = rec.get(h_key)
            if hv is not None and str(hv).strip():
                norm_h, mal = cls._normalize_host_token(hv)
                if not mal and norm_h:
                    return norm_h
        ntype = str(rec.get("node_type") or "").upper()
        lbl = str(rec.get("label") or "").strip()
        if ntype in ("DOMAIN", "ROOT_DOMAIN", "SUBDOMAIN", "IP_PORT") and lbl:
            norm_h, mal = cls._normalize_host_token(lbl)
            if not mal and norm_h:
                return norm_h
        for url_key in ("url", "endpoint", "route", "path", "label"):
            u_val = str(rec.get(url_key) or "").strip()
            if not u_val:
                continue
            for tok in u_val.split():
                if tok.lower().startswith(("http://", "https://")):
                    norm_h, mal = cls._normalize_host_token(tok)
                    if not mal and norm_h:
                        return norm_h
                else:
                    cand_sr = ("//" + tok[2:]) if tok.startswith(("/\\", "\\/", "\\\\")) else tok
                    sr_tok, sr_mal = cls._is_scheme_relative_authority(cand_sr, known_hosts=known_hosts)
                    if not sr_mal and sr_tok is not None:
                        norm_h, mal = cls._normalize_host_token(f"http:{sr_tok}")
                        if not mal and norm_h:
                            return norm_h
        return None

    @classmethod
    def _extract_record_hosts_and_routes(
        cls,
        rec: Dict[str, Any],
        known_hosts: Optional[Set[str]] = None,
    ) -> Tuple[List[str], List[str], bool]:
        hosts: List[str] = []
        routes: List[str] = []
        malformed = False
        ntype = str(rec.get("node_type") or "").upper()
        lbl = str(rec.get("label") or "").strip()

        def _inspect_token_host(tok: str) -> Tuple[Optional[str], Optional[str], bool]:
            tok_l = tok.lower()
            if tok_l.startswith(("http://", "https://")):
                norm_h, is_mal = cls._normalize_host_token(tok)
                if is_mal:
                    return None, None, True
                return norm_h, tok, False
            tok_no_q = tok.split("?", 1)[0].split("#", 1)[0]
            if "://" in tok_no_q:
                return None, None, True
            cand_sr = ("//" + tok[2:]) if tok.startswith(("/\\", "\\/", "\\\\")) else tok
            sr_tok, sr_mal = cls._is_scheme_relative_authority(cand_sr, known_hosts=known_hosts)
            if sr_mal:
                return None, None, True
            if sr_tok is not None:
                norm_h, is_mal = cls._normalize_host_token(f"http:{sr_tok}")
                if is_mal:
                    return None, None, True
                return norm_h, sr_tok, False
            return None, None, False

        for h_key in ("host", "domain"):
            hv = rec.get(h_key)
            if hv is not None and str(hv).strip():
                norm_h, is_mal = cls._normalize_host_token(hv)
                if is_mal:
                    malformed = True
                elif norm_h:
                    hosts.append(norm_h)

        if ntype in ("DOMAIN", "ROOT_DOMAIN", "SUBDOMAIN", "IP_PORT") and lbl:
            norm_h, is_mal = cls._normalize_host_token(lbl)
            if is_mal:
                malformed = True
            elif norm_h:
                hosts.append(norm_h)

        has_explicit_route = False
        for r_key in ("url", "endpoint", "route", "path"):
            rv = rec.get(r_key)
            if rv is not None and str(rv).strip():
                has_explicit_route = True
                r_str = str(rv).strip()
                routes.append(r_str)
                for tok in r_str.split():
                    norm_h, _, tok_mal = _inspect_token_host(tok)
                    if tok_mal:
                        malformed = True
                    elif norm_h:
                        hosts.append(norm_h)

        if lbl:
            lbl_routes_found = False
            is_host_only_type = ntype in ("DOMAIN", "ROOT_DOMAIN", "SUBDOMAIN", "IP_PORT")
            is_route_type = not is_host_only_type
            for tok in lbl.split():
                norm_h, sr_route, tok_mal = _inspect_token_host(tok)
                if tok_mal:
                    malformed = True
                    continue
                if norm_h:
                    hosts.append(norm_h)
                    if sr_route and (is_route_type or not has_explicit_route):
                        routes.append(sr_route)
                        lbl_routes_found = True
                elif (tok.startswith("/") or tok.startswith("\\")) and (
                    is_route_type or not has_explicit_route
                ):
                    routes.append(tok)
                    lbl_routes_found = True
                elif ("/" in tok or "\\" in tok) and (
                    is_route_type or not has_explicit_route
                ):
                    routes.append(tok)
                    lbl_routes_found = True
            if not is_host_only_type and not lbl_routes_found:
                parts = lbl.split()
                if (
                    len(parts) >= 2
                    and parts[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
                ):
                    routes.append(parts[1])
                elif not has_explicit_route and (
                    is_route_type
                    or "/" in lbl
                    or "\\" in lbl
                    or "://" in lbl
                ):
                    routes.append(lbl)
                elif not has_explicit_route:
                    routes.append(lbl)

        return hosts, routes, malformed

    def _surface_mining_impl(
        self,
        *,
        target_path: Optional[str] = None,
        query: str = "",
        asset_graph: Optional[Any] = None,
    ) -> Dict[str, Any]:
        q_str = str(query or "")
        tp_str: Optional[str] = None
        if target_path is not None:
            from engine.execution_policy import ExecutionPolicy

            ok_tp, detail_tp = ExecutionPolicy.get_instance().validate_file_path(
                target_path,
                workspace_root=self.workspace_root,
                allow_directory=True,
            )
            if not ok_tp:
                return {
                    "ok": False,
                    "source": "blocked",
                    "provider": "rfchunt_native",
                    "module21_available": False,
                    "target_path": str(target_path),
                    "query": q_str,
                    "endpoints": [],
                    "ai_sinks": [],
                    "assets": [],
                    "count": 0,
                    "error": f"Unsafe target_path rejected by workspace_root containment: {detail_tp}",
                }
            _sensitive_seg = {
                ".ssh", ".aws", ".gnupg", ".kube", ".netrc",
                "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys",
            }
            _tp_parts = {p.lower() for p in Path(detail_tp).parts}
            if _tp_parts.intersection(_sensitive_seg):
                return {
                    "ok": False,
                    "source": "blocked",
                    "provider": "rfchunt_native",
                    "module21_available": False,
                    "target_path": str(target_path),
                    "query": q_str,
                    "endpoints": [],
                    "ai_sinks": [],
                    "assets": [],
                    "count": 0,
                    "error": f"Unsafe target_path rejected: sensitive credential/key path '{detail_tp}' is forbidden",
                }
            tp_str = detail_tp
        fallback_reason = "module21_absent"
        ag = asset_graph if asset_graph is not None else self.asset_graph

        known_ag_hosts: Set[str] = set()
        if ag is not None:
            ag_lock = getattr(ag, "_lock", None)
            ctx_mgr = ag_lock if ag_lock is not None else contextlib.nullcontext()
            with ctx_mgr:
                raw_deny = list(getattr(ag, "deny_hosts", ()) or ())
                raw_scope = list(getattr(ag, "scope_hosts", ()) or ())
            for dh in raw_deny + raw_scope:
                norm_dh, dh_mal = self._normalize_host_token(dh)
                if not dh_mal and norm_dh:
                    known_ag_hosts.add(norm_dh)

        def _is_record_denied_by_ag(rec: Dict[str, Any]) -> bool:
            if ag is None:
                return False
            hosts, routes, malformed = self._extract_record_hosts_and_routes(
                rec,
                known_hosts=known_ag_hosts,
            )
            if malformed:
                return True
            if hasattr(ag, "is_in_scope"):
                for h_val in hosts:
                    if not ag.is_in_scope(h_val):
                        return True
            if hasattr(ag, "is_route_denied"):
                for r_val in routes:
                    if ag.is_route_denied(r_val):
                        return True
                    # Fallback normalization for duck-typed mock AssetGraphs
                    r_str = str(r_val).strip()
                    parts = r_str.split()
                    if (
                        len(parts) >= 2
                        and parts[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
                    ):
                        r_str = parts[1]
                    if r_str.lower().startswith(("http://", "https://")):
                        after_scheme = r_str.split("://", 1)[1]
                        authority = re.split(r"[/?#]", after_scheme, maxsplit=1)[0]
                        if "\\" in authority:
                            return True
                        try:
                            r_str = urlparse(r_str).path or "/"
                        except ValueError:
                            return True
                    elif "://" in r_str.split("?", 1)[0].split("#", 1)[0]:
                        return True
                    else:
                        cand_sr = ("//" + r_str[2:]) if r_str.startswith(("/\\", "\\/", "\\\\")) else r_str
                        sr_tok, sr_mal = self._is_scheme_relative_authority(
                            cand_sr,
                            known_hosts=known_ag_hosts,
                        )
                        if sr_mal:
                            return True
                        if sr_tok is not None:
                            try:
                                r_str = urlparse(f"http:{sr_tok}").path or "/"
                            except ValueError:
                                return True
                    r_str = r_str.split("#", 1)[0].split("?", 1)[0].strip().replace("\\", "/")
                    if r_str:
                        r_str = re.sub(r"^/+", "/", r_str) if r_str.startswith("/") else f"/{r_str}"
                        if ag.is_route_denied(r_str):
                            return True
                        r_norm = re.sub(r"^/+", "/", posixpath.normpath(r_str))
                        if r_norm != r_str and ag.is_route_denied(r_norm):
                            return True
            return False

        # 1. Per-call dynamic resolution of Module 21 (morluto/rea) — never cached
        candidates: List[Tuple[str, Any]] = []
        if callable(self.surface_provider):
            candidates.append(("surface_provider", self.surface_provider))
        else:
            for mod_name in ("morluto.rea", "engine.morluto_rea", "morluto_rea"):
                try:
                    mod = importlib.import_module(mod_name)
                    if mod is not None:
                        candidates.append((mod_name, mod))
                except Exception:
                    continue
            try:
                m_pkg = importlib.import_module("morluto")
                rea_attr = getattr(m_pkg, "rea", None)
                if rea_attr is not None:
                    candidates.append(("morluto.rea", rea_attr))
            except Exception:
                pass

        for prov_name, prov_obj in candidates:
            fn = prov_obj if callable(prov_obj) else None
            if fn is None:
                for fn_name in ("mine_surface", "discover_surface", "surface_mining", "analyze_surface", "run"):
                    cand_fn = getattr(prov_obj, fn_name, None)
                    if callable(cand_fn):
                        fn = cand_fn
                        break
            if fn is None:
                continue
            try:
                raw = self._invoke_surface_callable(fn, tp_str, q_str)
                norm = self._normalize_module21_items(raw)
                if norm:
                    scoped_norm: List[Dict[str, Any]] = []
                    for it in norm:
                        if _is_record_denied_by_ag(it):
                            continue
                        scoped_norm.append(it)
                    filtered = self._filter_surface_by_query(scoped_norm, q_str)
                    ai_sinks = [it for it in filtered if str(it.get("node_type", "")).upper() == "AI_SINK"]
                    assets = [it for it in filtered if str(it.get("node_type", "")).upper() not in ("ENDPOINT", "AI_SINK")]
                    endpoints = [it for it in filtered if str(it.get("node_type", "")).upper() in ("ENDPOINT", "AI_SINK")]
                    if not endpoints:
                        endpoints = filtered
                    return {
                        "ok": True,
                        "source": "module21",
                        "provider": prov_name,
                        "module21_available": True,
                        "target_path": tp_str,
                        "query": q_str,
                        "endpoints": endpoints,
                        "ai_sinks": ai_sinks,
                        "assets": assets,
                        "count": len(filtered),
                    }
                fallback_reason = "module21_empty_or_malformed"
            except Exception as exc:
                fallback_reason = f"module21_error: {type(exc).__name__}: {exc}"
                continue

        # 2. Native RFCHunt Fallback: AssetGraph + session_loader + Mantis + PythonAIScanner + traffic_session
        seen_keys: Set[Tuple[str, str, str]] = set()
        endpoints: List[Dict[str, Any]] = []
        ai_sinks: List[Dict[str, Any]] = []
        assets: List[Dict[str, Any]] = []

        def _add_record(rec: Dict[str, Any]) -> None:
            ntype = str(rec.get("node_type") or "ENDPOINT").upper()
            method_v = str(rec.get("method") or "GET").upper()
            route_v = str(rec.get("route") or rec.get("label") or "")
            if _is_record_denied_by_ag(rec):
                return
            dkey = (method_v, route_v, ntype)
            if dkey in seen_keys:
                return
            seen_keys.add(dkey)
            if ntype == "AI_SINK":
                ai_sinks.append(rec)
                endpoints.append(rec)
            elif ntype == "ENDPOINT":
                endpoints.append(rec)
            else:
                assets.append(rec)

        if ag is not None and hasattr(ag, "in_scope_assets"):
            for node in ag.in_scope_assets():
                attrs = dict(getattr(node, "attributes", None) or {})
                ntype = str(getattr(node, "node_type", "ENDPOINT") or "ENDPOINT").upper()
                label = str(getattr(node, "label", "") or "")
                route_v = attrs.get("route")
                if not route_v and ntype in ("ENDPOINT", "AI_SINK"):
                    for tok in label.split():
                        if tok.startswith("/") or tok.lower().startswith(("http://", "https://")):
                            route_v = tok
                            break
                    if not route_v:
                        route_v = label
                inferred_host = self._infer_host_from_record(
                    {
                        "node_type": ntype,
                        "label": label,
                        "host": attrs.get("host"),
                        "domain": attrs.get("domain"),
                        "url": attrs.get("url"),
                        "endpoint": attrs.get("endpoint"),
                        "route": route_v,
                    },
                    known_hosts=known_ag_hosts,
                )
                _add_record({
                    "asset_id": getattr(node, "node_id", ""),
                    "node_type": ntype,
                    "label": label,
                    "route": route_v or (label if ntype in ("ENDPOINT", "AI_SINK") else ""),
                    "url": attrs.get("url"),
                    "endpoint": attrs.get("endpoint"),
                    "method": str(attrs.get("method") or "GET").upper(),
                    "host": attrs.get("host") if attrs.get("host") is not None else inferred_host,
                    "port": attrs.get("port"),
                    "source": str(attrs.get("source") or "asset_graph"),
                })

        if tp_str:
            tp = Path(tp_str)
            ws_root_resolved = Path(self.workspace_root).resolve() if self.workspace_root else None
            ws_cmp_root = Path(os.path.normcase(str(ws_root_resolved))) if ws_root_resolved else None

            def _is_confined_child(cand_file: Union[str, Path]) -> bool:
                if ws_cmp_root is None:
                    return False
                try:
                    from engine.execution_policy import (
                        _collect_intermediate_reparse_hops,
                        _is_drive_relative_or_colon_unsafe,
                        _is_symlink_or_reparse,
                        _is_unc_path,
                        _normalize_win_readlink_target,
                    )

                    cand_p = Path(cand_file)
                    if not cand_p.is_absolute():
                        cand_p = (ws_root_resolved / cand_p) if ws_root_resolved is not None else cand_p.resolve(strict=False)
                    ws_cmp_str = os.path.normcase(str(ws_cmp_root))
                    cur_anc: Optional[Path] = cand_p
                    visited_anc: Set[str] = set()
                    while cur_anc is not None:
                        cur_key = os.path.normcase(str(cur_anc))
                        if cur_key == ws_cmp_str or cur_key in visited_anc:
                            break
                        visited_anc.add(cur_key)
                        if not _is_symlink_or_reparse(cur_anc):
                            try:
                                anc_res_str = os.path.normcase(str(cur_anc.resolve(strict=False)))
                                if anc_res_str == ws_cmp_str:
                                    break
                            except OSError:
                                pass
                        pending_hops: List[Path] = [cur_anc]
                        seen_hops: Set[str] = {cur_key}
                        for _ in range(16):
                            if not pending_hops:
                                break
                            hop_p = pending_hops.pop(0)
                            if not _is_symlink_or_reparse(hop_p):
                                continue
                            norm_link = _normalize_win_readlink_target(os.readlink(hop_p))
                            if _is_unc_path(norm_link) or _is_drive_relative_or_colon_unsafe(norm_link):
                                return False
                            link_t = Path(norm_link)
                            if not link_t.is_absolute():
                                link_t = hop_p.parent / link_t
                            link_res = link_t.resolve(strict=False)
                            if _is_unc_path(str(link_res)) or _is_drive_relative_or_colon_unsafe(str(link_res)):
                                return False
                            lt_cmp = Path(os.path.normcase(str(link_res)))
                            if lt_cmp != ws_cmp_root and not lt_cmp.is_relative_to(ws_cmp_root):
                                return False
                            cand_hops = _collect_intermediate_reparse_hops(link_t, ws_cmp_root, seen_hops)
                            if link_res != link_t:
                                cand_hops.extend(_collect_intermediate_reparse_hops(link_res, ws_cmp_root, seen_hops))
                            for ch_p in cand_hops:
                                ch_key = os.path.normcase(str(ch_p))
                                if ch_key not in seen_hops:
                                    seen_hops.add(ch_key)
                                    pending_hops.append(ch_p)
                        if pending_hops:
                            return False
                        if cur_anc.parent == cur_anc:
                            break
                        cur_anc = cur_anc.parent
                    cand_cmp = Path(os.path.normcase(str(cand_p.resolve(strict=False))))
                    return cand_cmp == ws_cmp_root or cand_cmp.is_relative_to(ws_cmp_root)
                except Exception:
                    return False

            if tp.exists() and _is_confined_child(tp):
                # Optional OpenAPI / HAR file surface parsing via session_loader
                if tp.is_file() and tp.suffix.lower() in (".json", ".yaml", ".yml", ".har"):
                    try:
                        from engine.dual_graph_engine import AssetGraph as _EphemeralAG
                        from engine.session_loader import import_har_file, import_openapi_spec

                        if ag is not None:
                            ag_lock = getattr(ag, "_lock", None)
                            ephem_ctx = ag_lock if ag_lock is not None else contextlib.nullcontext()
                            with ephem_ctx:
                                ephem_scope = set(getattr(ag, "scope_hosts", set()) or set())
                                ephem_deny_hosts = set(getattr(ag, "deny_hosts", set()) or set())
                                ephem_deny_routes = list(getattr(ag, "deny_routes", []) or [])
                        else:
                            ephem_scope = None
                            ephem_deny_hosts = None
                            ephem_deny_routes = None
                        tmp_ag = _EphemeralAG(
                            scope_hosts=ephem_scope,
                            deny_hosts=ephem_deny_hosts,
                            deny_routes=ephem_deny_routes,
                        )
                        if tp.suffix.lower() == ".har":
                            import_har_file(tp, asset_graph=tmp_ag)
                        else:
                            import_openapi_spec(tp, asset_graph=tmp_ag, host=self.host, port=self.port)
                        for node in tmp_ag.in_scope_assets():
                            attrs = dict(node.attributes or {})
                            _add_record({
                                "asset_id": node.node_id,
                                "node_type": node.node_type,
                                "label": node.label,
                                "route": attrs.get("route") or node.label,
                                "method": str(attrs.get("method") or "GET").upper(),
                                "host": attrs.get("host"),
                                "port": attrs.get("port"),
                                "source": str(attrs.get("source") or "session_loader"),
                            })
                    except Exception:
                        pass

                # Pure-Python Mantis AST/regex route extraction (fusion_arbiter=None -> zero LLM calls)
                try:
                    from engine.mantis_integrator import MantisThreatModeler, discover_candidate_files

                    files = [f for f in discover_candidate_files(str(tp)) if _is_confined_child(f)]
                    if files:
                        tm = MantisThreatModeler(fusion_arbiter=None).build_threat_model(str(tp), files)
                        tp_base = tp.parent if tp.is_file() else tp
                        for ep in (tm.entry_points or []):
                            r_path = ep.get("route")
                            if not r_path:
                                continue
                            ep_file = ep.get("file")
                            if ep_file:
                                ep_cand = Path(ep_file) if Path(ep_file).is_absolute() else (tp_base / ep_file)
                                if not _is_confined_child(ep_cand):
                                    continue
                            _add_record({
                                "node_type": "ENDPOINT",
                                "route": str(r_path),
                                "method": str(ep.get("method") or "GET").upper(),
                                "file": ep_file,
                                "function": ep.get("function"),
                                "line": ep.get("line"),
                                "source": "mantis_ast",
                            })
                except Exception:
                    pass

                # Pure-Python AI sink extraction (PythonAIScanner -> zero subprocesses, zero report files)
                try:
                    from engine.aiscan_integrator import PythonAIScanner

                    py_scanner = PythonAIScanner()
                    ai_eps = []
                    if tp.is_file():
                        if _is_confined_child(tp):
                            _, ai_eps = py_scanner.scan_file(tp)
                    else:
                        skip_ai_dirs = {
                            ".git", "node_modules", "target", "venv", ".venv", "__pycache__",
                            "out", "reports", "runs", "caldera_export", "caldera_plugin",
                            "yara", "rules", "coverage", ".pytest_cache", ".mypy_cache",
                        }
                        valid_ai_exts = {
                            ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".json", ".yaml", ".yml", ".env",
                            ".rego", ".cedar", ".tf", ".hcl", ".sh", ".ps1", ".toml", ".md",
                        }
                        data_ai_exts = {".json", ".yaml", ".yml", ".toml"}
                        data_scanned = 0
                        for ai_root, ai_dirs, ai_files in os.walk(tp, followlinks=False):
                            ai_dirs[:] = [
                                d for d in ai_dirs
                                if d not in skip_ai_dirs and _is_confined_child(Path(ai_root) / d)
                            ]
                            for ai_fname in ai_files:
                                cand_ai_p = Path(ai_root) / ai_fname
                                if not _is_confined_child(cand_ai_p):
                                    continue
                                ext_ai = cand_ai_p.suffix.lower()
                                is_df = ai_fname.lower() in ("dockerfile", "containerfile") or ai_fname.lower().startswith("dockerfile.")
                                if ext_ai in valid_ai_exts or is_df:
                                    if ext_ai in data_ai_exts:
                                        data_scanned += 1
                                        if data_scanned > 150:
                                            continue
                                    _, f_eps = py_scanner.scan_file(cand_ai_p)
                                    ai_eps.extend(f_eps)
                    tp_base = tp.parent if tp.is_file() else tp
                    for aep in ai_eps:
                        if aep.file_path:
                            aep_cand = Path(aep.file_path) if Path(aep.file_path).is_absolute() else (tp_base / aep.file_path)
                            if not _is_confined_child(aep_cand):
                                continue
                        _add_record({
                            "node_type": "AI_SINK",
                            "route": str(aep.route_path),
                            "method": str(aep.http_method or "POST").upper(),
                            "file": aep.file_path,
                            "line": aep.line_number,
                            "model_provider": aep.model_provider,
                            "source": "python_aiscan",
                        })
                except Exception:
                    pass

        if self.traffic_session is not None and hasattr(self.traffic_session, "list_exchanges"):
            try:
                for ex in self.traffic_session.list_exchanges():
                    parsed_ex = urlparse(ex.url)
                    ex_route = parsed_ex.path or "/"
                    _add_record({
                        "node_type": "ENDPOINT",
                        "route": ex_route,
                        "method": str(ex.method or "GET").upper(),
                        "host": ex.host,
                        "port": ex.port,
                        "source": "traffic_session",
                    })
            except Exception:
                pass

        f_endpoints = self._filter_surface_by_query(endpoints, q_str)
        f_ai_sinks = self._filter_surface_by_query(ai_sinks, q_str)
        f_assets = self._filter_surface_by_query(assets, q_str)
        return {
            "ok": True,
            "source": "fallback",
            "provider": "rfchunt_native",
            "module21_available": False,
            "fallback_reason": fallback_reason,
            "target_path": tp_str,
            "query": q_str,
            "endpoints": f_endpoints,
            "ai_sinks": f_ai_sinks,
            "assets": f_assets,
            "count": len(f_endpoints),
        }

    def surface_mining(
        self,
        target_path: Optional[str] = None,
        query: str = "",
    ) -> Dict[str, Any]:
        return self._surface_mining_impl(target_path=target_path, query=query)

    # ------------------------------------------------------------------
    # Bounded Multi-Turn Loop (F5)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_turn_tokens(raw_out: Any, sys_prompt: str, user_prompt: str) -> int:
        if isinstance(raw_out, dict):
            for k in ("tokens_used", "total_tokens", "tokens"):
                val = raw_out.get(k)
                if val is not None and not isinstance(val, bool):
                    try:
                        return max(1, int(val))
                    except (TypeError, ValueError):
                        pass
            usage = raw_out.get("usage")
            if isinstance(usage, dict):
                tot = usage.get("total_tokens")
                if tot is not None and not isinstance(tot, bool):
                    try:
                        return max(1, int(tot))
                    except (TypeError, ValueError):
                        pass
        approx = (len(sys_prompt) + len(user_prompt) + len(json.dumps(raw_out, default=str))) // 16
        return max(1, min(128, approx))

    @staticmethod
    def _parse_arbiter_action(raw_out: Any) -> Tuple[bool, Dict[str, Any], str]:
        if not isinstance(raw_out, dict):
            return False, {}, "Arbiter returned non-dict response."
        payload = raw_out.get("data", raw_out)
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception as exc:
                return False, {}, f"Arbiter returned malformed JSON string: {exc}"
        if isinstance(payload, list):
            if len(payload) == 1 and isinstance(payload[0], dict):
                payload = payload[0]
            else:
                return False, {}, "Arbiter returned non-object list payload."
        if not isinstance(payload, dict):
            return False, {}, "Arbiter payload must be a JSON object."
        action = str(payload.get("action") or "").strip().lower()
        if action not in ("tool_call", "finish"):
            return False, {}, f"Missing or invalid arbiter action: {payload.get('action')!r}"
        return True, payload, ""

    @staticmethod
    def _check_ledger_turn(
        ledger: Any,
        intent_id: str,
        slot_ctx: Optional[Dict[str, int]],
        tokens_used: int,
        turns_used: int,
        *,
        reserve_tokens_hint: Optional[int] = None,
    ) -> Tuple[bool, str]:
        if ledger is None:
            return True, ""
        if hasattr(ledger, "acquire_turn_from_slot"):
            try:
                return ledger.acquire_turn_from_slot(
                    intent_id=intent_id or None,
                    slot_ctx=slot_ctx,
                    reserve_tokens_hint=reserve_tokens_hint,
                )
            except TypeError:
                return ledger.acquire_turn_from_slot(
                    intent_id=intent_id or None,
                    slot_ctx=slot_ctx,
                )
        if hasattr(ledger, "check_turn_budget"):
            held_tok = _safe_nonneg_int(slot_ctx.get("reserved_tokens"), 0) if isinstance(slot_ctx, dict) else 0
            held_trn = _safe_nonneg_int(slot_ctx.get("reserved_turns"), 0) if isinstance(slot_ctx, dict) else 0
            return ledger.check_turn_budget(
                intent_id=intent_id or None,
                held_reserved_tokens=held_tok,
                held_reserved_turns=held_trn,
            )
        if hasattr(ledger, "check_intent_budget"):
            return ledger.check_intent_budget(
                tokens_used=tokens_used,
                turns_used=turns_used,
                intent_id=intent_id or None,
            )
        return True, ""

    @staticmethod
    def _charge_ledger_turn(
        ledger: Any,
        *,
        tokens: int,
        turns: int,
        intent_id: str,
        slot_ctx: Optional[Dict[str, int]],
    ) -> None:
        if ledger is None:
            return
        if hasattr(ledger, "record_turn_from_slot"):
            ledger.record_turn_from_slot(
                tokens=tokens,
                turns=turns,
                intent_id=intent_id or None,
                slot_ctx=slot_ctx,
            )
        elif hasattr(ledger, "record_worker_run"):
            ledger.record_worker_run(
                tokens=tokens,
                turns=turns,
                intent_id=intent_id or None,
            )

    def _build_offline_plan(self, attrs: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        cap = str(attrs.get("capability_class") or "").upper()
        attack_type = str(attrs.get("attack_type") or "").upper()
        route = str(attrs.get("target_route") or attrs.get("target_endpoint") or "/")
        method = str(attrs.get("method") or "GET").upper()
        step_caps = {
            str(s.get("capability") or "").upper()
            for s in (attrs.get("chain_steps") or [])
            if isinstance(s, dict)
        }
        is_multi = (
            bool(attrs.get("is_multi_hop"))
            or len(step_caps) >= 2
            or any(tag in attack_type for tag in ("3HOP_", "4HOP_", "MULTI_HOP_", "DESYNC_PROMPT_INJECTION", "ZERODAY_AI_INJECTION"))
        )
        is_desync = (
            cap == "DESYNC"
            or "DESYNC" in step_caps
            or any(k in attack_type for k in ("DESYNC", "PIPELINE_HIJACK", "SMUGGL", "CRLF", "CL.TE", "TE.CL", "RULER"))
        )
        is_auth = (
            cap in ("AUTH_BOUNDARY", "AUTH_SECRET")
            or bool(step_caps & {"AUTH_BOUNDARY", "AUTH_SECRET"})
            or any(k in attack_type for k in ("AUTH_BOUNDARY", "CREDENTIAL_AUTH", "AUTH_BYPASS", "AUTH_SECRET"))
        )
        is_ai = (
            cap == "AI_INJECTION"
            or "AI_INJECTION" in step_caps
            or bool(attrs.get("has_ai_sink"))
            or any(k in attack_type for k in ("AI_INJECTION", "PROMPT"))
        )
        needs_sink = (
            bool(step_caps & {"EXEC_SINK", "SSRF_PIVOT"})
            or any(k in attack_type for k in ("_EXEC", "EXEC_SINK", "SSRF"))
        ) and not is_ai

        plan: List[Tuple[str, Dict[str, Any]]] = []
        if is_multi:
            if is_desync:
                plan.append(("deterministic_harness", {"raw_request": attrs.get("raw_probe"), "probe_type": "Candidate Probe", "route": route}))
            if is_auth:
                auth_route = str(attrs.get("auth_route") or route)
                plan.append(("auth_diff_probe", {"method": "GET" if method in ("PUT", "DELETE", "PATCH") else method, "route": auth_route, "primary_profile": None, "secondary_profile": "anonymous"}))
            if is_ai:
                ai_route = str(attrs.get("ai_route") or route or "/api/chat")
                canary_body = json.dumps({"prompt": "RFCHUNT_CANARY_PROBE", "message": "RFCHUNT_CANARY_PROBE"})
                plan.append(("safe_http_probe", {"method": "POST", "route": ai_route, "headers": {"Content-Type": "application/json", "Accept": "application/json"}, "body": canary_body, "rationale": "Offline AI canary probe"}))
            if needs_sink:
                safe_m = "GET" if method in ("PUT", "DELETE", "PATCH") else method
                plan.append(("safe_http_probe", {"method": safe_m, "route": route, "rationale": "Offline multi-hop sink boundary check"}))
            if not plan:
                safe_m = "GET" if method in ("PUT", "DELETE", "PATCH") else method
                plan.append(("safe_http_probe", {"method": safe_m, "route": route, "rationale": "Offline safe boundary probe"}))
            return plan

        if is_auth:
            safe_m = "GET" if method in ("PUT", "DELETE", "PATCH") else method
            plan.append(("auth_diff_probe", {"method": safe_m, "route": route, "primary_profile": None, "secondary_profile": "anonymous"}))
            plan.append(("surface_mining", {"query": route.strip("/")}))
            return plan

        if is_desync:
            scanner_hint = f"{attrs.get('scanner', '')} {attrs.get('anomaly_type', '')}".upper()
            if "RULER" in scanner_hint and not attrs.get("raw_probe"):
                plan.append(("protocol_ruler", {"route": route, "max_size": 16384}))
                plan.append(("deterministic_harness", {"raw_request": None, "probe_type": "Candidate Probe", "route": route}))
            else:
                plan.append(("deterministic_harness", {"raw_request": attrs.get("raw_probe"), "probe_type": "Candidate Probe", "route": route}))
                plan.append(("protocol_ruler", {"route": route, "max_size": 16384}))
            return plan

        if is_ai:
            canary_body = json.dumps({"prompt": "RFCHUNT_CANARY_PROBE", "message": "RFCHUNT_CANARY_PROBE"})
            plan.append(("safe_http_probe", {"method": "POST", "route": route, "headers": {"Content-Type": "application/json", "Accept": "application/json"}, "body": canary_body, "rationale": "Offline AI canary probe"}))
            plan.append(("search_all_worker_traces", {"query": route, "limit": 5}))
            return plan

        safe_m = "GET" if method in ("PUT", "DELETE", "PATCH") else method
        plan.append(("safe_http_probe", {"method": safe_m, "route": route, "rationale": f"Offline safe probe on {route}"}))
        plan.append(("search_all_worker_traces", {"query": route, "limit": 5}))
        return plan

    def execute_candidate_multiturn(
        self,
        candidate_attrs: Dict[str, Any],
        *,
        max_turns: Optional[int] = None,
        budget_ledger: Optional[Any] = None,
        trace_store: Optional[Any] = None,
        boundary: Optional[Any] = None,
        arbiter: Optional[Any] = None,
        asset_graph: Optional[Any] = None,
        worker_id: str = "artex-worker-1",
        intent_id: str = "",
    ) -> Tuple[bool, str, str, Dict[str, Any]]:
        """
        Bounded multi-turn adaptive tool loop (`hypothesis -> probe -> read trace -> refine`)
        with `RunBudgetLedger` inner-turn enforcement, `ApprovalGate` + `ExecutionPolicy`
        gating, and `UntrustedOutputBoundary` framing on all tool outputs and reused traces.
        """
        raw_attrs = dict(candidate_attrs or {})
        worker_ctx = raw_attrs.pop("_worker_context", None)
        if not isinstance(worker_ctx, dict):
            worker_ctx = {}

        active_ledger = (
            budget_ledger
            if budget_ledger is not None
            else (worker_ctx.get("budget_ledger") if worker_ctx.get("budget_ledger") is not None else self.budget_ledger)
        )
        active_trace_store = (
            trace_store
            if trace_store is not None
            else (worker_ctx.get("trace_store") if worker_ctx.get("trace_store") is not None else self.trace_store)
        )
        active_boundary = (
            boundary
            if boundary is not None
            else (worker_ctx.get("boundary") if worker_ctx.get("boundary") is not None else self.boundary)
        )
        if active_boundary is None:
            from engine.dual_graph_engine import UntrustedOutputBoundary

            active_boundary = UntrustedOutputBoundary()

        active_arbiter = (
            arbiter
            if arbiter is not None
            else (worker_ctx.get("arbiter") if worker_ctx.get("arbiter") is not None else self.arbiter)
        )
        active_asset_graph = (
            asset_graph
            if asset_graph is not None
            else (worker_ctx.get("asset_graph") if worker_ctx.get("asset_graph") is not None else self.asset_graph)
        )
        active_approval_gate, active_noise_governor = self._resolve_worker_gates(worker_ctx)
        active_worker_id = str(worker_ctx.get("worker_id") or worker_id or "artex-worker-1")
        active_intent_id = str(
            intent_id
            or raw_attrs.get("intent_id")
            or raw_attrs.get("node_id")
            or f"candidate:{secrets.token_hex(6)}"
        )
        parent_slot_ctx = worker_ctx.get("slot_ctx") if isinstance(worker_ctx.get("slot_ctx"), dict) else None
        owns_local_slot = parent_slot_ctx is None and active_ledger is not None
        slot_ctx: Optional[Dict[str, int]] = (
            parent_slot_ctx
            if parent_slot_ctx is not None
            else (
                {
                    "reserved_tokens": 0,
                    "reserved_intent_tokens": 0,
                    "reserved_turns": 0,
                    "turn_reserved_tokens": 0,
                    "turn_reserved_intent_tokens": 0,
                    "recorded_tokens": 0,
                    "recorded_turns": 0,
                }
                if owns_local_slot
                else None
            )
        )

        cap_turns = 6 if max_turns is None else _safe_nonneg_int(max_turns, 0)
        if active_ledger is not None:
            ledger_intent_turns = _safe_nonneg_int(getattr(active_ledger, "max_intent_turns", 0), 0)
            if ledger_intent_turns > 0:
                cap_turns = min(cap_turns, ledger_intent_turns)

        tool_ctx = {
            "approval_gate": active_approval_gate,
            "noise_governor": active_noise_governor,
            "trace_store": active_trace_store,
            "asset_graph": active_asset_graph,
        }

        if cap_turns == 0:
            return (
                False,
                "Multi-turn loop stopped: max_turns=0.",
                "",
                {
                    "traffic_id": "",
                    "evidence_quote": "",
                    "tokens_used": 0,
                    "turns_used": 0,
                    "turns_executed": 0,
                    "step_traffic_ids": [],
                    "tool_history": [],
                    "stop_reason": "max_turns_zero",
                    "offline_fallback": False,
                },
            )

        cap = str(raw_attrs.get("capability_class") or "").upper()
        attack_type = str(raw_attrs.get("attack_type") or "").upper()
        route = str(raw_attrs.get("target_route") or raw_attrs.get("target_endpoint") or "/")
        step_caps_mt = {
            str(s.get("capability") or "").upper()
            for s in (raw_attrs.get("chain_steps") or [])
            if isinstance(s, dict)
        }
        is_multi_candidate = (
            bool(raw_attrs.get("is_multi_hop"))
            or len(step_caps_mt) >= 2
            or any(tag in attack_type for tag in ("3HOP_", "4HOP_", "MULTI_HOP_", "DESYNC_PROMPT_INJECTION", "ZERODAY_AI_INJECTION"))
        )
        is_ai_candidate = (
            cap == "AI_INJECTION"
            or "AI_INJECTION" in step_caps_mt
            or "AI_" in attack_type
            or "PROMPT" in attack_type
            or bool(raw_attrs.get("has_ai_sink"))
        )

        # Frame any reused prior worker traces with UntrustedOutputBoundary
        framed_reused_traces: List[str] = []
        for idx, tr in enumerate(raw_attrs.get("reused_worker_traces") or []):
            tr_txt = json.dumps(tr, default=str) if isinstance(tr, dict) else str(tr)
            framed_reused_traces.append(
                active_boundary.frame(tr_txt[:2000], source_label=f"reused_trace_{idx}")
            )

        is_offline = (
            active_arbiter is None
            or not hasattr(active_arbiter, "arbitrate_structured_json")
            or (
                os.environ.get("RFCHUNT_OFFLINE", "").strip() == "1"
                and type(active_arbiter).__name__ == "FusionArbiter"
            )
        )

        observations_history: List[str] = []
        tool_history: List[Dict[str, Any]] = []
        step_traffic_ids: List[str] = []
        confirmed_by_tool = False
        explicit_finish_confirmed = False
        explicit_finish_denied = False
        llm_finish_override_blocked = False
        best_traffic_id = ""
        last_traffic_id = ""
        best_evidence_quote = ""
        best_payload = ""
        best_evidence = ""
        finish_evidence = ""
        total_tokens = 0
        turns_executed = 0
        stop_reason = "max_turns_reached"
        used_offline_fallback = is_offline

        def _evaluate_and_record_tool(
            tool_name: str, tool_args: Optional[Dict[str, Any]], hypothesis: str = ""
        ) -> Dict[str, Any]:
            nonlocal confirmed_by_tool, best_traffic_id, last_traffic_id
            nonlocal best_evidence_quote, best_payload, best_evidence

            safe_tool_args = dict(tool_args) if isinstance(tool_args, dict) else {}
            res = self.toolbox.invoke(tool_name, tool_args, _context=tool_ctx)
            obs_json = json.dumps(res, default=str)
            safe_lbl = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(tool_name))[:32] or "tool"
            framed_obs = active_boundary.frame(obs_json[:12000], source_label=f"tool_{safe_lbl}")
            observations_history.append(framed_obs)

            t_tid = str(res.get("traffic_id") or "")
            if t_tid:
                last_traffic_id = t_tid
                if t_tid not in step_traffic_ids:
                    step_traffic_ids.append(t_tid)

            tool_confirmed = False
            if tool_name == "auth_diff_probe" and res.get("ok") and res.get("confirmed") and t_tid:
                tool_confirmed = True
                best_traffic_id = t_tid
                best_evidence_quote = str(res.get("evidence_quote") or f"HTTP {res.get('primary_status', 200)}")
                best_payload = f"{res.get('method', 'GET')} {res.get('route', route)}"
                best_evidence = (
                    f"AUTH_BOUNDARY confirmed on {res.get('route', route)} "
                    f"(primary HTTP {res.get('primary_status')}, secondary HTTP {res.get('secondary_status')})."
                )
            elif tool_name == "protocol_ruler" and res.get("ok") and res.get("confirmed") and t_tid:
                tool_confirmed = True
                best_traffic_id = t_tid
                best_evidence_quote = str(res.get("evidence_quote") or "")
                best_payload = str(res.get("route", route))
                best_evidence = f"ProtocolRuler confirmed framing anomaly on {res.get('route', route)}."
            elif tool_name == "deterministic_harness" and res.get("ok") and res.get("confirmed") and t_tid:
                tool_confirmed = True
                best_traffic_id = t_tid
                best_evidence_quote = str(res.get("evidence_quote") or "")
                best_payload = str(safe_tool_args.get("raw_request") or res.get("route", route))
                best_evidence = (
                    f"DeterministicHarness confirmed desync ({res.get('desync_class') or 'ANOMALY'}): "
                    f"{res.get('details', '')}"
                )
            elif (
                tool_name == "safe_http_probe"
                and is_ai_candidate
                and res.get("ok")
                and 200 <= int(res.get("status_code") or 0) < 300
                and "RFCHUNT_CANARY_PROBE" in str(res.get("response_body") or "")
                and t_tid
            ):
                tool_confirmed = True
                best_traffic_id = t_tid
                best_evidence_quote = "RFCHUNT_CANARY_PROBE"
                best_payload = f"{res.get('method', 'POST')} {res.get('url', route)}"
                best_evidence = f"AI_INJECTION canary reflected on {route} (HTTP {res.get('status_code')})."

            if tool_confirmed:
                confirmed_by_tool = True

            tool_history.append({
                "turn": turns_executed + 1,
                "tool": tool_name,
                "ok": bool(res.get("ok")),
                "confirmed": tool_confirmed,
                "traffic_id": t_tid,
                "hypothesis": hypothesis,
            })

            if active_trace_store is not None and hasattr(active_trace_store, "record_trace"):
                try:
                    active_trace_store.record_trace(
                        worker_id=active_worker_id,
                        intent_id=active_intent_id or "multiturn",
                        tool_name=tool_name,
                        summary=f"turn={turns_executed + 1} tool={tool_name} ok={res.get('ok')} confirmed={tool_confirmed}",
                        raw_observation=framed_obs,
                        target_asset_id=raw_attrs.get("anchored_asset_id"),
                        status="COMPLETED" if res.get("ok") else "FAILED",
                        traffic_id=t_tid or None,
                    )
                except Exception:
                    pass
            return res

        offline_plan: Optional[List[Tuple[str, Dict[str, Any]]]] = None
        offline_step_idx = 0

        try:
            for turn_idx in range(cap_turns):
                ok_budget, budget_reason = self._check_ledger_turn(
                    active_ledger,
                    active_intent_id,
                    slot_ctx,
                    total_tokens,
                    turns_executed,
                    reserve_tokens_hint=0 if is_offline else None,
                )
                if not ok_budget:
                    stop_reason = budget_reason or "budget_exhausted"
                    break

                if not is_offline:
                    tools_desc = json.dumps(self.toolbox.list_tools())
                    boundary_note = active_boundary.system_note() if hasattr(active_boundary, "system_note") else ""
                    system_prompt = (
                        "You are an autonomous defensive security verification worker. "
                        "Select exactly one JSON action per turn: "
                        '{"action": "tool_call", "tool": "<name>", "args": {...}, "hypothesis": "..."} '
                        'or {"action": "finish", "confirmed": true|false, "evidence": "..."}. '
                        f"Allowed tools: {tools_desc}\n{boundary_note}"
                    )
                    cand_summary = {
                        k: v
                        for k, v in raw_attrs.items()
                        if k != "reused_worker_traces"
                    }
                    framed_cand = active_boundary.frame(
                        json.dumps(cand_summary, default=str),
                        source_label="candidate_attrs",
                    )
                    prompt_parts = [f"Candidate (untrusted data):\n{framed_cand}"]
                    if framed_reused_traces:
                        prompt_parts.append("Prior Reused Worker Traces (untrusted data):\n" + "\n".join(framed_reused_traces))
                    if observations_history:
                        prompt_parts.append("Tool Observations (untrusted data):\n" + "\n".join(observations_history))
                    user_prompt = "\n\n".join(prompt_parts)

                    try:
                        raw_out = active_arbiter.arbitrate_structured_json(
                            task_name=f"ARTEX Worker Turn {turn_idx + 1}",
                            system_prompt=system_prompt,
                            user_prompt=user_prompt,
                            default_payload={"action": "finish", "confirmed": False, "evidence": ""},
                            num_predict=512,
                        )
                    except Exception as exc:
                        err_obs = active_boundary.frame(
                            json.dumps({"ok": False, "error": f"Arbiter error: {exc}"}),
                            source_label="arbiter_error",
                        )
                        observations_history.append(err_obs)
                        self._charge_ledger_turn(
                            active_ledger,
                            tokens=0,
                            turns=1,
                            intent_id=active_intent_id,
                            slot_ctx=slot_ctx,
                        )
                        turns_executed += 1
                        stop_reason = f"arbiter_error: {exc}"
                        break

                    if isinstance(raw_out, dict) and raw_out.get("status") == "offline_fallback":
                        is_offline = True
                        used_offline_fallback = True
                    else:
                        turn_tokens = self._extract_turn_tokens(raw_out, system_prompt, user_prompt)
                        valid_action, action_obj, parse_err = self._parse_arbiter_action(raw_out)
                        if not valid_action:
                            mal_obs = active_boundary.frame(
                                json.dumps({"ok": False, "error": parse_err}),
                                source_label="arbiter_malformed",
                            )
                            observations_history.append(mal_obs)
                            self._charge_ledger_turn(
                                active_ledger,
                                tokens=turn_tokens,
                                turns=1,
                                intent_id=active_intent_id,
                                slot_ctx=slot_ctx,
                            )
                            total_tokens += turn_tokens
                            turns_executed += 1
                            stop_reason = parse_err or "malformed_arbiter_response"
                            break

                        action_kind = str(action_obj.get("action") or "").strip().lower()
                        if action_kind == "finish":
                            raw_confirmed = action_obj.get("confirmed", False)
                            if isinstance(raw_confirmed, str):
                                req_confirmed = raw_confirmed.strip().lower() in ("true", "1", "yes")
                            else:
                                req_confirmed = bool(raw_confirmed)
                            finish_evidence = str(action_obj.get("evidence") or "")
                            if req_confirmed and confirmed_by_tool:
                                explicit_finish_confirmed = True
                                stop_reason = "finish_confirmed"
                            elif req_confirmed and not confirmed_by_tool:
                                explicit_finish_denied = True
                                finish_evidence = (
                                    finish_evidence
                                    or "Finish claimed confirmed=True without confirming tool evidence; failing closed."
                                )
                                stop_reason = "finish_uncorroborated"
                            elif not req_confirmed and confirmed_by_tool:
                                llm_finish_override_blocked = True
                                stop_reason = "finish_override_blocked"
                            else:
                                explicit_finish_denied = True
                                stop_reason = "finish_not_confirmed"

                            self._charge_ledger_turn(
                                active_ledger,
                                tokens=turn_tokens,
                                turns=1,
                                intent_id=active_intent_id,
                                slot_ctx=slot_ctx,
                            )
                            total_tokens += turn_tokens
                            turns_executed += 1
                            break

                        # action_kind == "tool_call"
                        raw_tool = action_obj.get("tool")
                        raw_args = action_obj.get("args")
                        hyp = str(action_obj.get("hypothesis") or "")
                        _evaluate_and_record_tool(str(raw_tool or ""), raw_args, hypothesis=hyp)
                        self._charge_ledger_turn(
                            active_ledger,
                            tokens=turn_tokens,
                            turns=1,
                            intent_id=active_intent_id,
                            slot_ctx=slot_ctx,
                        )
                        total_tokens += turn_tokens
                        turns_executed += 1
                        continue

                # Deterministic offline fallback (0 LLM tokens billed, 1 turn charged per step)
                if offline_plan is None:
                    if cap == "MCP_TOOL" or "MCP_TOOL" in attack_type or raw_attrs.get("mcp_endpoint"):
                        try:
                            mcp_ok, mcp_msg, mcp_payload, mcp_meta = self._verify_mcp_tool(
                                raw_attrs,
                                approval_gate=active_approval_gate,
                                noise_governor=active_noise_governor,
                            )
                        except Exception as exc:
                            mcp_ok, mcp_msg, mcp_payload, mcp_meta = False, f"MCP error: {exc}", "", {}
                        mcp_obs = active_boundary.frame(
                            json.dumps({"ok": mcp_ok, "evidence": mcp_msg, **dict(mcp_meta or {})}, default=str),
                            source_label="tool_mcp",
                        )
                        observations_history.append(mcp_obs)
                        if mcp_meta.get("traffic_id"):
                            last_traffic_id = str(mcp_meta["traffic_id"])
                            step_traffic_ids.append(last_traffic_id)
                        if mcp_ok:
                            confirmed_by_tool = True
                            best_traffic_id = str(mcp_meta.get("traffic_id") or "")
                            best_evidence_quote = str(mcp_meta.get("evidence_quote") or "")
                            best_payload = mcp_payload
                            best_evidence = mcp_msg
                        self._charge_ledger_turn(
                            active_ledger,
                            tokens=0,
                            turns=1,
                            intent_id=active_intent_id,
                            slot_ctx=slot_ctx,
                        )
                        turns_executed += 1
                        stop_reason = "offline_mcp_complete"
                        break
                    offline_plan = self._build_offline_plan(raw_attrs)

                if offline_step_idx >= len(offline_plan):
                    stop_reason = "offline_plan_complete"
                    break

                step_tool, step_args = offline_plan[offline_step_idx]
                offline_step_idx += 1
                _evaluate_and_record_tool(step_tool, step_args, hypothesis="deterministic_offline_fallback")
                self._charge_ledger_turn(
                    active_ledger,
                    tokens=0,
                    turns=1,
                    intent_id=active_intent_id,
                    slot_ctx=slot_ctx,
                )
                turns_executed += 1
                if is_multi_candidate:
                    step_confirmed = bool(tool_history and tool_history[-1].get("confirmed"))
                    if not step_confirmed:
                        confirmed_by_tool = False
                        stop_reason = "offline_prerequisite_failed"
                        break
                    if offline_step_idx < len(offline_plan):
                        confirmed_by_tool = False
                    else:
                        confirmed_by_tool = True
                        stop_reason = "offline_confirmed"
                        break
                elif confirmed_by_tool:
                    stop_reason = "offline_confirmed"
                    break
        finally:
            if (
                active_ledger is not None
                and isinstance(slot_ctx, dict)
                and hasattr(active_ledger, "abort_turn_from_slot")
            ):
                active_ledger.abort_turn_from_slot(
                    slot_ctx=slot_ctx,
                    intent_id=active_intent_id or None,
                )
            if (
                owns_local_slot
                and active_ledger is not None
                and isinstance(slot_ctx, dict)
                and (
                    slot_ctx.get("reserved_tokens", 0) > 0
                    or slot_ctx.get("reserved_intent_tokens", 0) > 0
                    or slot_ctx.get("reserved_turns", 0) > 0
                )
                and hasattr(active_ledger, "release_worker_slot")
            ):
                try:
                    active_ledger.release_worker_slot(
                        reserved_tokens=slot_ctx["reserved_tokens"],
                        reserved_turns=slot_ctx["reserved_turns"],
                        intent_id=active_intent_id or None,
                        reserved_intent_tokens=slot_ctx.get("reserved_intent_tokens"),
                        slot_ctx=slot_ctx,
                    )
                except TypeError:
                    active_ledger.release_worker_slot(
                        reserved_tokens=slot_ctx["reserved_tokens"],
                        reserved_turns=slot_ctx["reserved_turns"],
                        intent_id=active_intent_id or None,
                    )
                slot_ctx["reserved_tokens"] = 0
                slot_ctx["reserved_intent_tokens"] = 0
                slot_ctx["reserved_turns"] = 0
                slot_ctx["turn_reserved_tokens"] = 0
                slot_ctx["turn_reserved_intent_tokens"] = 0

        if (
            active_ledger is not None
            and owns_local_slot
            and turns_executed > 0
            and hasattr(active_ledger, "finalize_slot_samples")
        ):
            try:
                active_ledger.finalize_slot_samples(
                    reserved_tokens=0,
                    reserved_turns=0,
                    total_tokens=total_tokens,
                    total_turns=turns_executed,
                    intent_id=active_intent_id or None,
                    slot_ctx=slot_ctx,
                )
            except TypeError:
                try:
                    active_ledger.finalize_slot_samples(
                        reserved_tokens=0,
                        reserved_turns=0,
                        total_tokens=total_tokens,
                        total_turns=turns_executed,
                        intent_id=active_intent_id or None,
                    )
                except TypeError:
                    active_ledger.finalize_slot_samples(
                        reserved_tokens=0,
                        reserved_turns=0,
                        total_tokens=total_tokens,
                        total_turns=turns_executed,
                    )

        # Deterministic tool confirmation is authoritative and cannot be suppressed
        # or have its deterministic evidence overwritten by an injected LLM finish(...) call.
        if confirmed_by_tool:
            final_ok = True
            final_evidence = (
                best_evidence
                or finish_evidence
                or f"Multi-turn loop confirmed by tool ({stop_reason})."
            )
        elif explicit_finish_denied:
            final_ok = False
            final_evidence = (
                finish_evidence
                if finish_evidence
                else (best_evidence or f"Multi-turn loop finished ({stop_reason}).")
            )
        else:
            final_ok = False
            final_evidence = best_evidence or finish_evidence or f"Multi-turn loop finished ({stop_reason})."

        final_traffic_id = best_traffic_id or last_traffic_id
        return (
            final_ok,
            final_evidence,
            best_payload,
            {
                "traffic_id": final_traffic_id,
                "evidence_quote": best_evidence_quote if final_ok else "",
                "tokens_used": total_tokens,
                "turns_used": turns_executed,
                "turns_executed": turns_executed,
                "step_traffic_ids": step_traffic_ids,
                "tool_history": tool_history,
                "stop_reason": stop_reason,
                "offline_fallback": used_offline_fallback,
                "confirmed_by_tool": confirmed_by_tool,
                "llm_override_blocked": llm_finish_override_blocked,
            },
        )

    def as_multiturn_executor_fn(
        self,
        *,
        max_turns: Optional[int] = None,
        budget_ledger: Optional[Any] = None,
        trace_store: Optional[Any] = None,
        boundary: Optional[Any] = None,
        arbiter: Optional[Any] = None,
        asset_graph: Optional[Any] = None,
        worker_id: Optional[str] = None,
    ) -> Callable[[Dict[str, Any]], Tuple[bool, str, str, Dict[str, Any]]]:
        def _multiturn_exec(exec_attrs: Dict[str, Any]) -> Tuple[bool, str, str, Dict[str, Any]]:
            attrs = dict(exec_attrs or {})
            w_ctx = attrs.get("_worker_context") if isinstance(attrs.get("_worker_context"), dict) else {}
            eff_ledger = budget_ledger if budget_ledger is not None else w_ctx.get("budget_ledger")
            eff_trace_store = trace_store if trace_store is not None else w_ctx.get("trace_store")
            eff_boundary = boundary if boundary is not None else w_ctx.get("boundary")
            eff_arbiter = arbiter if arbiter is not None else w_ctx.get("arbiter")
            eff_asset_graph = asset_graph if asset_graph is not None else w_ctx.get("asset_graph")
            eff_worker_id = worker_id or str(w_ctx.get("worker_id") or "artex-worker-1")
            eff_intent_id = str(attrs.get("intent_id") or "")
            return self.execute_candidate_multiturn(
                attrs,
                max_turns=max_turns,
                budget_ledger=eff_ledger,
                trace_store=eff_trace_store,
                boundary=eff_boundary,
                arbiter=eff_arbiter,
                asset_graph=eff_asset_graph,
                worker_id=eff_worker_id,
                intent_id=eff_intent_id,
            )

        _multiturn_exec._accepts_worker_context = True  # type: ignore[attr-defined]
        return _multiturn_exec
