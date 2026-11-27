"""
HTTP Terminator MCP (Model Context Protocol) Server:
Exposes autonomous protocol research tools over standard JSON-RPC 2.0 stdio.
Allows AI coding harnesses and agents (Antigravity, Claude, Cursor) to orchestrate
continuous RFC fetching, micro-inspiration generation with local Google Gemma,
deterministic evaluation, anomaly cascades, and dangling-byte weaponization.
"""

import contextlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import queue
import re
import secrets
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qs, urlparse


_STDOUT_REDIRECT_LOCK = threading.Lock()
_STDOUT_REDIRECT_DEPTH = 0
_STDOUT_ORIG = None


@contextlib.contextmanager
def _suppress_stdout_to_stderr():
    """Thread-safe stdout->stderr redirection so MCP JSON-RPC stdio never receives stray banners."""
    global _STDOUT_REDIRECT_DEPTH, _STDOUT_ORIG
    with _STDOUT_REDIRECT_LOCK:
        if _STDOUT_REDIRECT_DEPTH == 0:
            _STDOUT_ORIG = sys.stdout
            sys.stdout = sys.stderr
        _STDOUT_REDIRECT_DEPTH += 1
    try:
        yield
    finally:
        with _STDOUT_REDIRECT_LOCK:
            _STDOUT_REDIRECT_DEPTH -= 1
            if _STDOUT_REDIRECT_DEPTH == 0 and _STDOUT_ORIG is not None:
                sys.stdout = _STDOUT_ORIG
                _STDOUT_ORIG = None


class TargetAuthorizationGate:
    """
    Decoupled Security Gate:
    Enforces independent, non-bypassable controls for destination target validation,
    payload size boundaries, durable per-identity sliding-window rate limiting,
    and mandatory supervisor approvals for high-risk actions.
    """
    ALLOWED_TARGETS: Set[str] = {"127.0.0.1", "localhost", "::1", "[::1]"}
    MAX_PAYLOAD_BYTES: int = 64 * 1024  # 64 KB strict upper limit
    RATE_LIMIT_PER_MINUTE: int = 60

    _request_history: Dict[str, List[float]] = {}
    _lock = threading.RLock()
    _tls = threading.local()

    @classmethod
    def _tls_scope_depth(cls) -> int:
        return int(getattr(cls._tls, "scope_depth", 0) or 0)

    @classmethod
    def _tls_transient_targets(cls) -> Dict[str, int]:
        bag = getattr(cls._tls, "transient_targets", None)
        if bag is None:
            bag = {}
            cls._tls.transient_targets = bag
        return bag

    @classmethod
    @contextlib.contextmanager
    def mcp_request_scope(cls, *, authorized_request: bool = True):
        """
        Isolate per-request `authorized=True` target grants per thread so they never
        permanently mutate `ALLOWED_TARGETS` or leak into subsequent/concurrent requests.
        """
        prev_depth = cls._tls_scope_depth()
        prev_ignore = getattr(cls._tls, "ignore_transient", False)
        prev_bag = getattr(cls._tls, "scope_bag", None)
        my_bag: List[str] = []
        cls._tls.scope_depth = prev_depth + 1
        cls._tls.scope_bag = my_bag
        cls._tls.ignore_transient = not bool(authorized_request)
        transient = cls._tls_transient_targets()
        try:
            yield
        finally:
            cls._tls.ignore_transient = prev_ignore
            cls._tls.scope_bag = prev_bag
            for host in my_bag:
                cnt = transient.get(host, 0) - 1
                if cnt <= 0:
                    transient.pop(host, None)
                else:
                    transient[host] = cnt
            new_depth = max(0, prev_depth)
            cls._tls.scope_depth = new_depth
            if new_depth == 0:
                transient.clear()

    @classmethod
    def get_allowed_targets(cls, *, include_transient: Optional[bool] = None) -> Set[str]:
        if include_transient is None:
            include_transient = (
                cls._tls_scope_depth() > 0
                and not bool(getattr(cls._tls, "ignore_transient", False))
            )
        with cls._lock:
            targets = set(cls.ALLOWED_TARGETS)
        if include_transient:
            transient = getattr(cls._tls, "transient_targets", None) or {}
            targets.update(h for h, cnt in transient.items() if cnt > 0)
        extra = os.environ.get("RFCHUNT_AUTHORIZED_TARGETS", "")
        if extra:
            for t in extra.split(","):
                t_clean = t.strip().lower()
                # Disallow wildcards from bypassing target controls
                if t_clean and t_clean not in ("*", "all"):
                    try:
                        from engine.safe_network_validator import validate_target_host, is_explicit_loopback_host
                        is_safe, _ = validate_target_host(t_clean, allow_private=is_explicit_loopback_host(t_clean))
                        if is_safe:
                            targets.add(t_clean)
                    except ImportError:
                        targets.add(t_clean)
        return targets

    @classmethod
    def authorize_target(cls, host: str) -> None:
        cleaned = host.strip().lower()
        if cleaned in ("0.0.0.0", "::"):
            raise ValueError("Cannot authorize 0.0.0.0 or :: (INADDR_ANY listening address). Specify a valid host or loopback.")
        if cleaned in ("*", "all"):
            raise ValueError("Wildcard authorization is disallowed. Specify explicit target hostnames or IPs.")
        try:
            from engine.safe_network_validator import validate_target_host, is_explicit_loopback_host
            is_safe, reason = validate_target_host(cleaned, allow_private=is_explicit_loopback_host(cleaned))
            if not is_safe:
                is_dns_offline = "DNS resolution failed for target hostname" in reason
                has_domain_label = any(c.isalpha() for c in cleaned) and "." in cleaned and not cleaned.startswith("0x")
                if is_dns_offline and has_domain_label:
                    pass
                else:
                    raise ValueError(f"Cannot authorize target '{host}': {reason}")
        except ImportError:
            pass
        if cls._tls_scope_depth() > 0:
            transient = cls._tls_transient_targets()
            transient[cleaned] = transient.get(cleaned, 0) + 1
            scope_bag = getattr(cls._tls, "scope_bag", None)
            if scope_bag is not None:
                scope_bag.append(cleaned)
        else:
            with cls._lock:
                cls.ALLOWED_TARGETS.add(cleaned)

    @classmethod
    def check_target(cls, host: str) -> None:
        cleaned = host.strip().lower()
        if cleaned in ("0.0.0.0", "::"):
            raise ValueError(f"Target '{host}' is an invalid destination address (INADDR_ANY bind address). Specify 127.0.0.1 or localhost.")
        allowed = cls.get_allowed_targets()
        if cleaned not in allowed:
            raise PermissionError(
                f"Target '{host}' is not in the authorized targets whitelist ({sorted(list(allowed))}). "
                f"Active protocol research against external services requires explicit authorization "
                f"(set RFCHUNT_AUTHORIZED_TARGETS={host})."
            )
        try:
            from engine.safe_network_validator import validate_target_host
            is_local = cleaned in ("127.0.0.1", "localhost", "::1", "[::1]") or cleaned.startswith("127.")
            is_safe, reason = validate_target_host(cleaned, allow_private=is_local)
            if not is_safe:
                if "DNS resolution failed for target hostname" in reason:
                    pass
                else:
                    raise PermissionError(f"Target '{host}' failed security boundary validation: {reason}")
        except ImportError:
            pass

    @classmethod
    def validate_target(cls, host: str) -> Tuple[bool, str]:
        try:
            cls.check_target(host)
            return True, f"Target '{host}' is authorized."
        except (ValueError, PermissionError) as e:
            return False, str(e)

    @classmethod
    def check_payload(cls, payload_len: int) -> None:
        if payload_len > cls.MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload size {payload_len} bytes exceeds maximum allowed boundary of {cls.MAX_PAYLOAD_BYTES} bytes (64 KB)."
            )

    @classmethod
    def check_rate_limit(cls, client_id: str = "default") -> None:
        now = time.time()
        with cls._lock:
            history = cls._request_history.setdefault(client_id, [])
            cls._request_history[client_id] = [t for t in history if now - t < 60.0]
            if len(cls._request_history[client_id]) >= cls.RATE_LIMIT_PER_MINUTE:
                raise RuntimeError(
                    f"Rate limit exceeded: maximum {cls.RATE_LIMIT_PER_MINUTE} requests/minute allowed for client '{client_id}'."
                )
            cls._request_history[client_id].append(now)

    @classmethod
    def check_supervisor_approval(cls, supervisor_token: Optional[str], action_name: str) -> None:
        expected_token = os.environ.get("RFCHUNT_SUPERVISOR_TOKEN")
        if not expected_token:
            raise PermissionError(
                f"Autonomous {action_name} is suspended: RFCHUNT_SUPERVISOR_TOKEN is not configured in the host environment. "
                f"Human supervisor authorization is mandatory."
            )
        if not supervisor_token or supervisor_token.strip() != expected_token.strip():
            raise PermissionError(
                f"Invalid or missing supervisor approval token for high-risk action '{action_name}'. Operation rejected."
            )

    @classmethod
    def check_auth(
        cls,
        host: str,
        payload_len: int = 0,
        is_weaponization: bool = False,
        is_heavy_hunt: bool = False,
        supervisor_token: Optional[str] = None,
        client_id: str = "default",
    ) -> None:
        """
        Executes decoupled security checks in strict non-bypassable sequence:
        1. Destination Target Validation (Rejects 0.0.0.0 & unlisted targets)
        2. Payload Size Enforcement (Strict 64KB boundary)
        3. Durable Sliding-Window Rate Limiting
        4. Cryptographic/Configured Supervisor Approval Verification
        """
        cls.check_target(host)
        cls.check_payload(payload_len)
        cls.check_rate_limit(client_id)
        if is_weaponization:
            cls.check_supervisor_approval(supervisor_token, "weaponization")
        elif is_heavy_hunt:
            cls.check_supervisor_approval(supervisor_token, "heavy_continuous_hunt")


from cascade import DiscoveryCascade
from continuous_scanner import ContinuousFlawHunter
from database import Database
from deterministic_harness import DeterministicHarness
from permutator import VectorPermutator
from probe_generator import ProbeGenerator
from rfc_chunker import RFCChunker
from rfc_fetcher import RFCFetcher
from weaponizer import RQPWeaponizer
from engine.raptor_integrator import (
    RaptorIntegrator,
    RAPTOR_PROJECT_TITLE,
    RAPTOR_AUTHORS,
    RAPTOR_REPO_URL,
    RAPTOR_DOCKER_IMAGE,
)


class TerminatorMCPServer:
    def __init__(self, db_path: str = "terminator.db", workspace_root: Optional[Union[str, Path]] = None):
        self._explicit_init_workspace_root: bool = workspace_root is not None
        raw_ws = (
            workspace_root
            if workspace_root is not None
            else (os.environ.get("RFCHUNT_MCP_WORKSPACE_ROOT") or os.environ.get("RFCHUNT_WORKSPACE_ROOT"))
        )
        self.workspace_root: Optional[Path] = self._normalize_mcp_workspace_root(raw_ws)
        self.db_path = db_path
        self.db = Database(db_path)
        self.fetcher = RFCFetcher(db=self.db)
        self.permutator = VectorPermutator(db=self.db)
        self.raptor = RaptorIntegrator(db=self.db)

    @staticmethod
    def _normalize_mcp_workspace_root(workspace_root: Optional[Union[str, Path]]) -> Optional[Path]:
        if workspace_root is None:
            return None
        ws_raw = os.fspath(workspace_root) if isinstance(workspace_root, os.PathLike) else workspace_root
        if not isinstance(ws_raw, str):
            raise ValueError("MCP workspace_root must be a string or Path.")
        ws_stripped = ws_raw.strip()
        if not ws_stripped:
            raise PermissionError("Unsafe MCP workspace_root rejected (empty or whitespace-only).")
        from engine.execution_policy import (
            _is_drive_relative_or_colon_unsafe,
            _is_unc_path,
            _validate_canonical_path_syntax,
        )

        if ws_raw != ws_stripped or any(ord(ch) < 32 or ord(ch) == 127 for ch in ws_raw):
            raise PermissionError("Unsafe MCP workspace_root rejected (whitespace or control characters).")
        if _is_unc_path(ws_stripped) or _is_drive_relative_or_colon_unsafe(ws_stripped):
            raise PermissionError("Unsafe MCP workspace_root rejected (UNC, NT-device, or drive-relative/ADS path).")
        ws_err = _validate_canonical_path_syntax(ws_stripped, allow_trailing_slash=True)
        if ws_err is not None and ws_stripped != ".":
            raise PermissionError(f"Unsafe MCP workspace_root rejected: {ws_err}")
        ws_resolved = Path(ws_stripped).resolve(strict=False)
        if _is_unc_path(str(ws_resolved)) or _is_drive_relative_or_colon_unsafe(str(ws_resolved)):
            raise PermissionError("Unsafe resolved MCP workspace_root rejected.")
        if ws_resolved.exists() and not ws_resolved.is_dir():
            raise PermissionError("MCP workspace_root must be a directory.")
        TerminatorMCPServer._check_sensitive_host_path(ws_raw, str(ws_resolved), label="MCP workspace_root")
        return ws_resolved

    def _resolve_mcp_workspace_root(self, args: Optional[Dict[str, Any]] = None) -> Optional[Path]:
        if self.workspace_root is None:
            if isinstance(args, dict) and args.get("workspace_root") is not None:
                norm_ws = self._normalize_mcp_workspace_root(args.get("workspace_root"))
                if norm_ws is not None and norm_ws.exists() and not norm_ws.is_dir():
                    raise PermissionError("MCP workspace_root must be a directory.")
                return norm_ws
            return None
        if isinstance(args, dict) and args.get("workspace_root") is not None:
            from engine.execution_policy import ExecutionPolicy

            raw_arg_ws = args.get("workspace_root")
            if isinstance(raw_arg_ws, str) and not raw_arg_ws.strip():
                raise PermissionError("Unsafe MCP workspace_root rejected (empty or whitespace-only).")
            if isinstance(raw_arg_ws, (str, os.PathLike)):
                self._check_sensitive_host_path(os.fspath(raw_arg_ws), None, label="MCP workspace_root")
            ok, detail = ExecutionPolicy.get_instance().validate_file_path(
                raw_arg_ws,
                workspace_root=self.workspace_root,
                allow_directory=True,
            )
            if not ok:
                raise PermissionError(f"MCP workspace_root cannot exceed configured server root: {detail}")
            narrowed_ws = Path(detail).resolve(strict=False)
            if narrowed_ws.exists() and not narrowed_ws.is_dir():
                raise PermissionError("MCP workspace_root must be a directory.")
            self._check_sensitive_host_path(os.fspath(raw_arg_ws) if isinstance(raw_arg_ws, (str, os.PathLike)) else str(raw_arg_ws), str(narrowed_ws), label="MCP workspace_root")
            return narrowed_ws
        return self.workspace_root

    def _has_explicit_output_confinement(self, args: Optional[Dict[str, Any]] = None) -> bool:
        """
        True when workspace_root was explicitly configured on TerminatorMCPServer(...)
        or explicitly provided in per-call tool args['workspace_root'] (as opposed to
        ambient RFCHUNT_WORKSPACE_ROOT env fallback or repo-inferred root).
        """
        return bool(
            getattr(self, "_explicit_init_workspace_root", False)
            or (isinstance(args, dict) and args.get("workspace_root") is not None)
        )

    @staticmethod
    def _check_sensitive_host_path(
        raw_str: str,
        resolved_str: Optional[str] = None,
        *,
        label: str = "MCP path",
    ) -> None:
        candidates: List[str] = []
        if raw_str:
            candidates.append(raw_str)
            if raw_str.startswith("~"):
                try:
                    expanded = os.path.expanduser(raw_str)
                    candidates.append(expanded)
                    candidates.append(str(Path(expanded).resolve(strict=False)))
                except Exception:
                    pass
        if resolved_str:
            candidates.append(resolved_str)

        sensitive_markers = (
            "/.ssh",
            "/.aws",
            "/.gnupg",
            "/.kube",
            "/etc/passwd",
            "/etc/shadow",
            "/windows/system32",
            "/windows/syswow64",
            "/windows/temp",
        )
        win_roots: List[str] = []
        for env_k in ("SystemRoot", "WINDIR"):
            val = os.environ.get(env_k)
            if val:
                try:
                    win_roots.append(str(Path(val).resolve(strict=False)).replace("\\", "/").lower().rstrip("/"))
                except Exception:
                    win_roots.append(val.replace("\\", "/").lower().rstrip("/"))
        home_cred_dirs: List[str] = []
        try:
            home_base = Path.home().resolve(strict=False)
            for cred_sub in (".ssh", ".aws", ".gnupg", ".kube"):
                home_cred_dirs.append(str(home_base / cred_sub).replace("\\", "/").lower().rstrip("/"))
        except Exception:
            pass

        for cand in candidates:
            cand_low = cand.replace("\\", "/").lower()
            cand_trimmed = cand_low.rstrip("/") or "/"
            if any(
                cand_trimmed == m
                or cand_trimmed.startswith(m + "/")
                or cand_trimmed.endswith(m)
                or (m + "/" in cand_trimmed)
                for m in sensitive_markers
            ):
                raise PermissionError(f"Unsafe {label} rejected: sensitive host path '{raw_str}' is forbidden.")
            if re.match(r"^[a-z]:/windows(?:/|$)", cand_trimmed) or re.match(
                r"^[a-z]:/(?:system32|syswow64)(?:/|$)", cand_trimmed
            ):
                raise PermissionError(f"Unsafe {label} rejected: Windows system directory '{raw_str}' is forbidden.")
            for wr in win_roots:
                if wr and (cand_trimmed == wr or cand_trimmed.startswith(wr + "/")):
                    raise PermissionError(f"Unsafe {label} rejected: Windows system directory '{raw_str}' is forbidden.")
            for hc in home_cred_dirs:
                if hc and (cand_trimmed == hc or cand_trimmed.startswith(hc + "/")):
                    raise PermissionError(f"Unsafe {label} rejected: user credential directory '{raw_str}' is forbidden.")

    def _validate_mcp_scan_path(
        self,
        raw_path: Any,
        *,
        workspace_root: Optional[Union[str, Path]] = None,
        allow_directory: bool = True,
        allow_nonexistent: bool = True,
        enforce_workspace_root: bool = True,
    ) -> str:
        from engine.execution_policy import (
            ExecutionPolicy,
            _collect_intermediate_reparse_hops,
            _is_drive_relative_or_colon_unsafe,
            _is_symlink_or_reparse,
            _is_unc_path,
            _normalize_win_readlink_target,
            _validate_canonical_path_syntax,
        )

        eff_ws = (self.workspace_root if self.workspace_root is not None else workspace_root) if enforce_workspace_root else None
        if isinstance(raw_path, (str, os.PathLike)):
            self._check_sensitive_host_path(os.fspath(raw_path), None, label="MCP path")
        if eff_ws is not None:
            ok, detail = ExecutionPolicy.get_instance().validate_file_path(
                raw_path,
                workspace_root=eff_ws,
                allow_directory=allow_directory,
                allow_nonexistent=allow_nonexistent,
            )
            if not ok:
                raise PermissionError(f"MCP path rejected outside workspace_root: {detail}")
            self._check_sensitive_host_path(
                os.fspath(raw_path) if isinstance(raw_path, (str, os.PathLike)) else str(raw_path),
                detail,
                label="MCP path",
            )
            return detail

        if raw_path is None:
            raise ValueError("Path parameter is required.")
        raw_str = os.fspath(raw_path) if isinstance(raw_path, os.PathLike) else raw_path
        if not isinstance(raw_str, str) or not raw_str.strip():
            raise ValueError("Path parameter must be a non-empty string.")
        if raw_str != raw_str.strip():
            raise PermissionError("Unsafe MCP path rejected: leading/trailing whitespace obfuscation forbidden.")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_str):
            raise PermissionError("Unsafe MCP path rejected: control/NUL character forbidden.")
        if _is_unc_path(raw_str) or _is_drive_relative_or_colon_unsafe(raw_str):
            raise PermissionError("Unsafe MCP path rejected: UNC, NT-device, or drive-relative/ADS path forbidden.")
        p_err = _validate_canonical_path_syntax(raw_str, allow_trailing_slash=allow_directory)
        if p_err is not None and not (allow_directory and raw_str == "."):
            raise PermissionError(f"Unsafe MCP path rejected: {p_err}")
        norm = raw_str.replace("\\", "/")
        if os.name == "nt" and norm.startswith("/") and not (len(norm) >= 2 and norm[1] == ":"):
            raise PermissionError(f"Unsafe MCP path rejected: single-slash POSIX path '{raw_str}' forbidden on Windows.")
        cand_raw = Path(raw_str)
        raw_abs = Path(os.path.abspath(raw_str))
        cur_anc: Optional[Path] = raw_abs
        seen_anc: set = set()
        while cur_anc is not None:
            cur_key = os.path.normcase(str(cur_anc))
            if cur_key in seen_anc or cur_anc.parent == cur_anc:
                break
            seen_anc.add(cur_key)
            try:
                if cur_anc.exists():
                    anc_real = Path(os.path.normcase(os.path.realpath(str(cur_anc))))
                    parent_real = Path(os.path.normcase(os.path.realpath(str(cur_anc.parent))))
                    if anc_real != parent_real and not anc_real.is_relative_to(parent_real):
                        raise PermissionError(
                            f"Unsafe MCP path rejected: path '{raw_str}' escapes parent directory."
                        )
                pending_hops: List[Path] = [cur_anc]
                seen_hops: set = {cur_key}
                for _ in range(16):
                    if not pending_hops:
                        break
                    hop_p = pending_hops.pop(0)
                    if not _is_symlink_or_reparse(hop_p):
                        continue
                    raw_parent_cmp = Path(os.path.normcase(str(hop_p.parent)))
                    raw_parent = hop_p.parent.resolve(strict=False)
                    parent_cmp = Path(os.path.normcase(str(raw_parent)))
                    try:
                        norm_link = _normalize_win_readlink_target(os.readlink(hop_p))
                    except OSError as exc:
                        raise PermissionError(
                            f"Unsafe MCP path rejected: cannot inspect symlink/reparse point '{hop_p}': {exc}"
                        ) from exc
                    if _is_unc_path(norm_link) or _is_drive_relative_or_colon_unsafe(norm_link):
                        raise PermissionError(f"Unsafe MCP path rejected: symlink target '{norm_link}' is unsafe.")
                    link_t = Path(norm_link)
                    if not link_t.is_absolute():
                        link_t = hop_p.parent / link_t
                    link_res = link_t.resolve(strict=False)
                    if _is_unc_path(str(link_res)) or _is_drive_relative_or_colon_unsafe(str(link_res)):
                        raise PermissionError(f"Unsafe MCP path rejected: symlink target '{link_res}' is unsafe.")
                    res_cmp = Path(os.path.normcase(str(link_res)))
                    if res_cmp != parent_cmp and not res_cmp.is_relative_to(parent_cmp):
                        raise PermissionError(f"Unsafe MCP path rejected: symlink '{raw_str}' escapes parent directory.")
                    cand_hops = _collect_intermediate_reparse_hops(link_t, raw_parent_cmp, seen_hops)
                    if link_res != link_t:
                        cand_hops.extend(_collect_intermediate_reparse_hops(link_res, parent_cmp, seen_hops))
                    for ch_p in cand_hops:
                        ch_key = os.path.normcase(str(ch_p))
                        if ch_key not in seen_hops:
                            seen_hops.add(ch_key)
                            pending_hops.append(ch_p)
                if pending_hops:
                    raise PermissionError(
                        f"Unsafe MCP path rejected: symlink chain '{raw_str}' exceeded max resolution depth."
                    )
            except PermissionError:
                raise
            except OSError as exc:
                raise PermissionError(
                    f"Unsafe MCP path rejected: symlink/reparse inspection failed for '{raw_str}': {exc}"
                ) from exc
            cur_anc = cur_anc.parent
        resolved = cand_raw.resolve(strict=False)
        res_str = str(resolved)
        if _is_unc_path(res_str) or _is_drive_relative_or_colon_unsafe(res_str):
            raise PermissionError(f"Unsafe resolved MCP path rejected: '{res_str}'.")
        self._check_sensitive_host_path(raw_str, res_str, label="MCP path")
        if not allow_directory and resolved.exists() and resolved.is_dir():
            raise PermissionError(f"Directory target '{raw_str}' forbidden.")
        if not allow_nonexistent and not resolved.exists():
            raise ValueError(f"Target path does not exist: {resolved}")
        return res_str

    def _validate_mcp_output_dir(
        self,
        raw_path: Any,
        *,
        workspace_root: Optional[Union[str, Path]] = None,
        enforce_explicit_ws: Optional[bool] = None,
        allow_directory: bool = True,
    ) -> str:
        """
        Validates report output_dir / archive_path:
        - When workspace_root was explicitly supplied (`TerminatorMCPServer(..., workspace_root=...)`
          or `args["workspace_root"]`), fails closed with `PermissionError` for any path outside it.
        - Otherwise (when workspace_root is None, env-inherited, or repo-inferred), allows paths inside
          `workspace_root` as well as designated report subdirectories (`reports`, `out`, `runs`, ...)
          and strict `%TEMP%` subdirectories, while always rejecting traversal, UNC/ADS/NUL,
          symlink/junction escapes, and sensitive host directories.
        """
        from engine.execution_policy import ExecutionPolicy

        eff_ws = workspace_root if workspace_root is not None else self.workspace_root
        explicit_ws = (
            bool(enforce_explicit_ws)
            if enforce_explicit_ws is not None
            else bool(getattr(self, "_explicit_init_workspace_root", False))
        )
        if isinstance(raw_path, (str, os.PathLike)):
            self._check_sensitive_host_path(os.fspath(raw_path), None, label="MCP output_dir")
        if eff_ws is not None:
            ok_ws, detail_ws = ExecutionPolicy.get_instance().validate_file_path(
                raw_path,
                workspace_root=eff_ws,
                allow_directory=allow_directory,
                allow_nonexistent=True,
            )
            if ok_ws:
                self._check_sensitive_host_path(
                    os.fspath(raw_path) if isinstance(raw_path, (str, os.PathLike)) else str(raw_path),
                    detail_ws,
                    label="MCP output_dir",
                )
                return detail_ws
            if explicit_ws:
                raise PermissionError(
                    f"Unsafe MCP output path rejected outside workspace_root '{eff_ws}': {detail_ws}"
                )

        safe_res = self._validate_mcp_scan_path(
            raw_path,
            workspace_root=None,
            allow_directory=allow_directory,
            allow_nonexistent=True,
            enforce_workspace_root=False,
        )

        resolved_out = Path(safe_res).resolve(strict=False)
        self._check_sensitive_host_path(
            os.fspath(raw_path) if isinstance(raw_path, (str, os.PathLike)) else str(raw_path),
            str(resolved_out),
            label="MCP output_dir",
        )
        out_cmp = Path(os.path.normcase(str(resolved_out)))
        temp_root = Path(os.path.normcase(str(Path(tempfile.gettempdir()).resolve(strict=False))))
        if out_cmp != temp_root and out_cmp.is_relative_to(temp_root):
            return safe_res

        rfchunt_root = Path(__file__).resolve().parent
        if os.environ.get("PYTEST_CURRENT_TEST"):
            pytest_temp_root = Path(os.path.normcase(str((rfchunt_root.parent / ".pytest_temp").resolve(strict=False))))
            if out_cmp != pytest_temp_root and out_cmp.is_relative_to(pytest_temp_root):
                return safe_res

        for allowed_sub in ExecutionPolicy.ALLOWED_WRITE_SUBDIRS:
            allowed_dir = Path(os.path.normcase(str((rfchunt_root / allowed_sub).resolve(strict=False))))
            if out_cmp == allowed_dir or out_cmp.is_relative_to(allowed_dir):
                return safe_res

        raise PermissionError(
            f"MCP output_dir rejected outside workspace_root and designated report/temp directories: '{raw_path}'"
        )

    def close(self) -> None:
        """Closes internal HTTP client and database handle cleanly."""
        if hasattr(self, "fetcher") and self.fetcher is not None and hasattr(self.fetcher, "client"):
            try:
                self.fetcher.client.close()
            except Exception:
                pass
        if hasattr(self, "db") and self.db is not None:
            self.db.close()

    def __enter__(self) -> "TerminatorMCPServer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(request, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: expected JSON object"},
            }
        method = request.get("method")
        msg_id = request.get("id")
        raw_params = request.get("params")
        if raw_params is None:
            params: Dict[str, Any] = {}
        elif isinstance(raw_params, dict):
            params = raw_params
        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": "Invalid params: expected JSON object"},
            }

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "http-terminator-mcp",
                        "version": "1.0.0",
                    },
                    "capabilities": {
                        "tools": {},
                    },
                },
            }

        elif method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {},
            }

        elif method == "notifications/initialized" or (isinstance(method, str) and method.startswith("notifications/")):
            return {}

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": self._get_tool_definitions(),
                },
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments")
            if arguments is None:
                arguments = {}
            try:
                if not isinstance(tool_name, str) or not tool_name.strip():
                    raise ValueError("Tool 'name' must be a non-empty string.")
                if not isinstance(arguments, dict):
                    raise ValueError("Tool 'arguments' must be a JSON object.")
                with _suppress_stdout_to_stderr():
                    with TargetAuthorizationGate.mcp_request_scope(
                        authorized_request=(arguments.get("authorized") is True)
                    ):
                        res = self._execute_tool(tool_name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(res, indent=2)}],
                    },
                }
            except PermissionError as pe:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32001,
                        "message": f"Authorization error: {pe}",
                    },
                }
            except ValueError as ve:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32602,
                        "message": f"Invalid parameter: {ve}",
                    },
                }
            except RuntimeError as re:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32029,
                        "message": f"Rate limit or runtime constraint: {re}",
                    },
                }
            except Exception as e:
                # Sanitize technical traceback and prevent leaking internal implementation
                sys.stderr.write(f"[MCP-ERROR] Internal exception in {tool_name}: {e}\n")
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32000,
                        "message": "Internal request processing error. Diagnostics logged to secure server console.",
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method {method} not found"},
        }

    def _get_tool_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "run_continuous_hunt",
                "description": "Continuously fetches successive RFCs from the RFC Editor index, chunks into micro-inspiration fragments, generates probes using local Google Gemma / ModelFusion (at zero cost 24/7), permutes, and evaluates until a breakthrough desync flaw or anomaly is discovered.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_host": {"type": "string", "default": "127.0.0.1"},
                        "target_port": {"type": "integer", "default": 8080},
                        "use_tls": {"type": "boolean", "default": False},
                        "model": {"type": "string", "default": "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"},
                        "use_fusion": {"type": "boolean", "default": True},
                        "max_rfcs": {"type": "integer", "default": 10},
                        "stop_on_first_flaw": {"type": "boolean", "default": True},
                        "supervisor_token": {"type": "string", "description": "Mandatory supervisor approval token for heavy research hunts"},
                    },
                },
            },
            {
                "name": "fetch_rfc",
                "description": "Fetches a protocol RFC by number or scans the RFC Editor index for the most recent specifications.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rfc_number": {"type": "integer", "description": "e.g. 9112 or 8446"},
                        "discover_recent": {"type": "integer", "description": "Number of recent RFCs to discover"},
                    },
                },
            },
            {
                "name": "chunk_and_inspire",
                "description": "Slices an RFC document or text into 1-2 sentence micro-inspiration fragments, stripping headers and filtering for operative keywords.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rfc_text": {"type": "string"},
                        "sentences_per_chunk": {"type": "integer", "default": 2},
                    },
                    "required": ["rfc_text"],
                },
            },
            {
                "name": "generate_probes",
                "description": "Generates novel raw HTTP candidate probes from a micro-inspiration fragment using 100% local refusal-free abliterated ModelFusion models (Abliterated Gemma-4-12B, Cisco Foundation-Sec-8B, GLM-4; no safety filtering) without buzzword contamination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rfc_fragment": {"type": "string"},
                        "model": {"type": "string", "default": "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"},
                        "use_fusion": {"type": "boolean", "default": True},
                    },
                    "required": ["rfc_fragment"],
                },
            },
            {
                "name": "evaluate_probe",
                "description": "Evaluates a raw HTTP probe using Connection A/B state contamination testing and scans for anomalies (text/binary blend, double HTML, inline headers).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "raw_request": {"type": "string"},
                        "target_host": {"type": "string", "default": "127.0.0.1"},
                        "target_port": {"type": "integer", "default": 8080},
                        "use_tls": {"type": "boolean", "default": False},
                    },
                    "required": ["raw_request"],
                },
            },
            {
                "name": "weaponize_dangling_byte",
                "description": "Executes autonomous Response Queue Poisoning (RQP) using the Dangling-Byte Technique (withholding 1 byte to eliminate front-end stacked response race conditions).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base_trigger": {"type": "string"},
                        "target_host": {"type": "string", "default": "127.0.0.1"},
                        "target_port": {"type": "integer", "default": 8080},
                        "use_tls": {"type": "boolean", "default": False},
                        "supervisor_token": {"type": "string", "description": "Mandatory supervisor approval token for RQP weaponization"},
                    },
                    "required": ["base_trigger"],
                },
            },
            {
                "name": "cascade_extrapolate",
                "description": "Feeds an observed flaw into the Discovery Cascade loop ('You are not thinking big enough') to extrapolate Shared-Parser Confusion, Range Cache Poisoning, and Status-Line Injection.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "details": {"type": "string"},
                        "rationale": {"type": "string"},
                        "rfc_fragment": {"type": "string"},
                        "raw_evidence": {"type": "string"},
                        "model": {"type": "string", "default": "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"},
                    },
                    "required": ["details", "rationale"],
                },
            },
            {
                "name": "get_database_stats",
                "description": "Retrieves real-time counts of ingested RFCs, micro-fragments, generated probes, confirmed vulnerabilities, and anomaly detections.",
                "inputSchema": {"type": "object"},
            },
            {
                "name": "raptor_status",
                "description": "[RAPTOR Framework Integration by Gadi Evron, Daniel Cuthbert & Halvar Flake] Verifies Docker container readiness (danielcuthbert/raptor:latest), RAPTOR status, and local Ollama security models.",
                "inputSchema": {"type": "object"},
            },
            {
                "name": "raptor_describe_target",
                "description": "[RAPTOR Framework Integration by Gadi Evron, Daniel Cuthbert & Halvar Flake] Profiles a local codebase repository: language distribution, lines of code, build systems, and attack surface.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "description": "Absolute path to repository on host"},
                    },
                    "required": ["target_path"],
                },
            },
            {
                "name": "raptor_scan_project",
                "description": "[RAPTOR Framework Integration by Gadi Evron, Daniel Cuthbert & Halvar Flake] Executes autonomous source code security analysis (Semgrep, Coccinelle, CodeQL, LLM exploitability triage, crypto/PQC readiness, and SCA). Automatically ingests SARIF findings into terminator.db.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "description": "Absolute path to repository on host"},
                        "mode": {"type": "string", "enum": ["scan", "agentic", "crypto", "sca"], "default": "scan"},
                        "model": {"type": "string", "default": "fenkohq/foundation-sec-8b:latest"},
                        "policy_groups": {"type": "string", "default": ""},
                        "include_codeql": {"type": "boolean", "default": False},
                    },
                    "required": ["target_path"],
                },
            },
            {
                "name": "raptor_list_findings",
                "description": "[RAPTOR Framework Integration by Gadi Evron, Daniel Cuthbert & Halvar Flake] Lists and summarizes SARIF vulnerability findings from previous RAPTOR scans in out/.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "max_items": {"type": "integer", "default": 50},
                    },
                },
            },
            {
                "name": "run_all_scans",
                "description": "[Unified --all Multi-Scanner + Google Mantis] Runs ALL integrated security scanners (Google Mantis, haasonsaas/aiscan, ARTEX Dual-Graph, RAPTOR SAST/PQC/SCA + web DAST, Prompt Smuggling, Protocol Ruler & TLS/HTTP framing) against --repo/--path and/or remote --host with mandatory ModelFusion and Abliterated models.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string", "description": "Repository directory path to audit"},
                        "path": {"type": "string", "description": "Specific file or folder path to audit"},
                        "host": {"type": "string", "description": "Optional remote hostname or URL to review (e.g. target.example.com)"},
                        "port": {"type": "integer", "description": "Target port for remote --host audit (defaults to 443 for HTTPS / 80 for HTTP)"},
                        "tls": {"type": "boolean", "description": "Enable TLS/HTTPS inspection for remote --host"},
                        "authorized": {"type": "boolean", "default": False, "description": "Explicit authorization flag for public/remote host (SSRF checks always enforced)"},
                        "depth": {"type": "integer", "default": 30, "description": "Mantis audit depth (1..100)"},
                        "mantis_mode": {
                            "type": "string",
                            "enum": ["full", "fast", "threat-model", "scan", "reproduce", "patch"],
                            "default": "full",
                        },
                        "artex_rounds": {"type": "integer", "default": 1},
                        "artex_url": {"type": "string", "description": "Optional headless BaaRai/ARTEX REST+SSE server URL (e.g. http://127.0.0.1:8787)"},
                        "artex_token": {"type": "string", "description": "Optional Bearer JWT token for headless ARTEX REST API"},
                        "artex_proxy": {"type": "string", "description": "Optional ARTEX recording MITM proxy URL (e.g. http://127.0.0.1:8788)"},
                        "artex_noise_profile": {"type": "string", "enum": ["off", "quiet", "balanced", "aggressive"], "default": "off"},
                        "artex_llm_profiles": {"type": "array", "items": {"type": "string"}, "description": "Ordered LLM profile IDs for ARTEX worker rotation"},
                        "artex_llm_rotate": {"type": "boolean", "default": False},
                        "artex_wait_sse": {"type": "boolean", "default": False},
                        "artex_budget_turns": {"type": "integer", "default": 0},
                        "artex_retest": {"type": "boolean", "default": False},
                        "output_dir": {"type": "string", "default": "reports"},
                        "enable_external_scanners": {"type": "boolean", "default": False},
                        "httpx_scan": {"type": "boolean"},
                        "katana_scan": {"type": "boolean"},
                        "nuclei_scan": {"type": "boolean"},
                        "nuclei_tags": {"type": "array", "items": {"type": "string"}},
                        "scanner_isolation": {"type": "string", "enum": ["host", "docker"], "default": "host"},
                        "docker_image": {"type": "string"},
                        "docker_network": {"type": "string", "enum": ["bridge", "none"]},
                        "artex_live": {"type": "boolean"},
                        "artex_multiturn": {"type": "boolean", "default": False},
                        "artex_intent_turns": {"type": "integer", "default": 0},
                        "artex_intent_tokens": {"type": "integer", "default": 0},
                        "approval_mode": {"type": "string", "enum": ["policy", "deny"], "default": "policy"},
                        "enable_pe_audit": {"type": "boolean", "default": True, "description": "Run PE & .NET Code Integrity Anomaly Auditor during --all"},
                        "pe_include_host_audit": {"type": "boolean", "default": False, "description": "Include Windows KB5127694 and VirtualBox 7.2.18+ host patch audit during --all"},
                        "pe_include_yara": {"type": "boolean", "default": True, "description": "Evaluate defensive PE/.NET YARA rules during --all"},
                    },
                },
            },
            {
                "name": "mantis_scan_all",
                "description": "[Alias for run_all_scans] Runs all RFCHunt + Google Mantis scanners against repo/path and/or remote host with mandatory ModelFusion + Abliterated models.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "path": {"type": "string"},
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "tls": {"type": "boolean"},
                        "authorized": {"type": "boolean", "default": False},
                        "depth": {"type": "integer", "default": 30},
                        "mantis_mode": {
                            "type": "string",
                            "enum": ["full", "fast", "threat-model", "scan", "reproduce", "patch"],
                            "default": "full",
                        },
                        "artex_rounds": {"type": "integer", "default": 1},
                        "artex_url": {"type": "string"},
                        "artex_token": {"type": "string"},
                        "artex_proxy": {"type": "string"},
                        "artex_noise_profile": {"type": "string", "enum": ["off", "quiet", "balanced", "aggressive"], "default": "off"},
                        "artex_llm_profiles": {"type": "array", "items": {"type": "string"}},
                        "artex_llm_rotate": {"type": "boolean", "default": False},
                        "artex_wait_sse": {"type": "boolean", "default": False},
                        "artex_budget_turns": {"type": "integer", "default": 0},
                        "artex_retest": {"type": "boolean", "default": False},
                        "output_dir": {"type": "string", "default": "reports"},
                        "enable_external_scanners": {"type": "boolean", "default": False},
                        "httpx_scan": {"type": "boolean"},
                        "katana_scan": {"type": "boolean"},
                        "nuclei_scan": {"type": "boolean"},
                        "nuclei_tags": {"type": "array", "items": {"type": "string"}},
                        "scanner_isolation": {"type": "string", "enum": ["host", "docker"], "default": "host"},
                        "docker_image": {"type": "string"},
                        "docker_network": {"type": "string", "enum": ["bridge", "none"]},
                        "artex_live": {"type": "boolean"},
                        "artex_multiturn": {"type": "boolean", "default": False},
                        "artex_intent_turns": {"type": "integer", "default": 0},
                        "artex_intent_tokens": {"type": "integer", "default": 0},
                        "approval_mode": {"type": "string", "enum": ["policy", "deny"], "default": "policy"},
                        "enable_pe_audit": {"type": "boolean", "default": True},
                        "pe_include_host_audit": {"type": "boolean", "default": False},
                        "pe_include_yara": {"type": "boolean", "default": True},
                    },
                },
            },
            {
                "name": "artex_run_attack_chain",
                "description": "[Module 17: BaaRai/ARTEX Dual-Graph Attack Chainer] Runs durable multi-step attack chaining (1-hop to 4-hop) with PlannerTodolist prerequisite gating, shared worker execution traces, POE verification, and optional headless ARTEX REST+SSE sync.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "default": "127.0.0.1"},
                        "port": {"type": "integer", "default": 8080},
                        "use_tls": {"type": "boolean", "default": False},
                        "authorized": {"type": "boolean", "default": False},
                        "endpoints": {"type": "array", "items": {"type": "string"}},
                        "ai_sinks": {"type": "array", "items": {"type": "string"}},
                        "findings": {"type": "array", "items": {"type": "object"}},
                        "hydrate_db": {"type": "boolean", "default": True},
                        "rounds": {"type": "integer", "default": 2},
                        "noise_profile": {"type": "string", "enum": ["off", "quiet", "balanced", "aggressive"], "default": "off"},
                        "budget_turns": {"type": "integer", "default": 0},
                        "artex_url": {"type": "string"},
                        "artex_token": {"type": "string"},
                        "artex_proxy": {"type": "string"},
                        "artex_wait_sse": {"type": "boolean", "default": False},
                        "retest": {"type": "boolean", "default": False},
                        "multiturn": {"type": "boolean", "default": False},
                        "artex_multiturn": {"type": "boolean", "default": False},
                        "max_intent_turns": {"type": "integer", "default": 0},
                        "max_intent_tokens": {"type": "integer", "default": 0},
                        "approval_mode": {"type": "string", "enum": ["policy", "deny"], "default": "policy"},
                    },
                },
            },
            {
                "name": "artex_run_multiturn_worker",
                "description": "[Module 17: Bounded Multi-Turn ArtexWorker] Executes a bounded adaptive multi-turn tool loop (hypothesis -> probe -> trace -> refine) over typed JSON tools with RunBudgetLedger, ApprovalGate, and UntrustedOutputBoundary.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "default": "127.0.0.1"},
                        "port": {"type": "integer", "default": 8080},
                        "use_tls": {"type": "boolean", "default": False},
                        "authorized": {"type": "boolean", "default": False},
                        "target_route": {"type": "string", "default": "/"},
                        "attack_type": {"type": "string", "default": "AUTH_BOUNDARY"},
                        "method": {"type": "string", "default": "GET"},
                        "max_intent_turns": {"type": "integer", "default": 4},
                        "max_turns": {"type": "integer"},
                        "max_intent_tokens": {"type": "integer", "default": 0},
                        "max_task_turns": {"type": "integer", "default": 0},
                        "max_task_tokens": {"type": "integer", "default": 0},
                        "noise_profile": {"type": "string", "enum": ["off", "quiet", "balanced", "aggressive"], "default": "off"},
                        "approval_mode": {"type": "string", "enum": ["policy", "deny"], "default": "policy"},
                        "approval_rules": {"type": "string"},
                        "strict_poe": {"type": "boolean", "default": False},
                        "auth_profile": {"type": "string"},
                        "endpoints": {"type": "array", "items": {"type": "string"}},
                        "ai_sinks": {"type": "array", "items": {"type": "string"}},
                        "findings": {"type": "array", "items": {"type": "object"}},
                        "task_id": {"type": "string"},
                        "worker_id": {"type": "string", "default": "artex-mcp-worker-1"},
                        "reports_dir": {"type": "string", "default": "reports"},
                        "artex_proxy": {"type": "string"},
                    },
                },
            },
            {
                "name": "external_httpx_discover",
                "description": "[Opt-In External Scanner] Runs ProjectDiscovery httpx probe discovery (disabled by default; enabled=True required) and populates AssetGraph.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "default": "127.0.0.1"},
                        "port": {"type": "integer"},
                        "use_tls": {"type": "boolean", "default": False},
                        "authorized": {"type": "boolean", "default": False},
                        "enabled": {"type": "boolean", "default": False},
                        "execution_mode": {"type": "string", "enum": ["host", "docker"], "default": "host"},
                        "docker_image": {"type": "string"},
                        "docker_network": {"type": "string", "enum": ["bridge", "none"]},
                        "binary_path": {"type": "string"},
                        "rate_limit": {"type": "integer"},
                        "timeout_sec": {"type": "number", "default": 120.0},
                        "threads": {"type": "integer"},
                        "noise_profile": {"type": "string", "enum": ["off", "quiet", "balanced", "aggressive"], "default": "off"},
                        "approval_mode": {"type": "string", "enum": ["policy", "deny"], "default": "policy"},
                        "approval_rules": {"type": "string"},
                        "extra_flags": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            {
                "name": "external_katana_crawl",
                "description": "[Opt-In External Scanner] Runs ProjectDiscovery katana crawl (disabled by default; enabled=True required) to discover endpoints and JS routes into AssetGraph.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "default": "127.0.0.1"},
                        "port": {"type": "integer"},
                        "use_tls": {"type": "boolean", "default": False},
                        "authorized": {"type": "boolean", "default": False},
                        "enabled": {"type": "boolean", "default": False},
                        "execution_mode": {"type": "string", "enum": ["host", "docker"], "default": "host"},
                        "docker_image": {"type": "string"},
                        "docker_network": {"type": "string", "enum": ["bridge", "none"]},
                        "binary_path": {"type": "string"},
                        "rate_limit": {"type": "integer"},
                        "timeout_sec": {"type": "number", "default": 120.0},
                        "threads": {"type": "integer"},
                        "max_depth": {"type": "integer", "default": 2},
                        "crawl_duration_sec": {"type": "integer", "default": 30},
                        "js_crawl": {"type": "boolean", "default": True},
                        "noise_profile": {"type": "string", "enum": ["off", "quiet", "balanced", "aggressive"], "default": "off"},
                        "approval_mode": {"type": "string", "enum": ["policy", "deny"], "default": "policy"},
                        "approval_rules": {"type": "string"},
                        "extra_flags": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            {
                "name": "external_nuclei_scan",
                "description": "[Opt-In External Scanner] Runs ProjectDiscovery nuclei -jsonl with strictly non-destructive tags (disabled by default; enabled=True required) and ingests findings into DualGraphAttackEngine.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "default": "127.0.0.1"},
                        "port": {"type": "integer"},
                        "use_tls": {"type": "boolean", "default": False},
                        "authorized": {"type": "boolean", "default": False},
                        "enabled": {"type": "boolean", "default": False},
                        "execution_mode": {"type": "string", "enum": ["host", "docker"], "default": "host"},
                        "docker_image": {"type": "string"},
                        "docker_network": {"type": "string", "enum": ["bridge", "none"]},
                        "binary_path": {"type": "string"},
                        "rate_limit": {"type": "integer"},
                        "timeout_sec": {"type": "number", "default": 120.0},
                        "threads": {"type": "integer"},
                        "tags": {"type": "array", "items": {"type": "string"}, "default": ["tech", "misconfig", "exposure", "headers"]},
                        "nuclei_tags": {"type": "array", "items": {"type": "string"}},
                        "severity": {"type": "array", "items": {"type": "string"}, "default": ["info", "low", "medium"]},
                        "task_id": {"type": "string"},
                        "noise_profile": {"type": "string", "enum": ["off", "quiet", "balanced", "aggressive"], "default": "off"},
                        "approval_mode": {"type": "string", "enum": ["policy", "deny"], "default": "policy"},
                        "approval_rules": {"type": "string"},
                        "extra_flags": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            {
                "name": "artex_list_worker_traces",
                "description": "[ARTEX Shared Worker Memory] Lists recorded worker execution traces (`list_worker_traces`) for a task or across all tasks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {"type": "string"},
                        "worker_id": {"type": "string"},
                        "intent_id": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
            {
                "name": "artex_get_worker_trace",
                "description": "[ARTEX Shared Worker Memory] Retrieves a single worker execution trace by trace_id (`get_worker_trace`).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "trace_id": {"type": "string"},
                    },
                    "required": ["trace_id"],
                },
            },
            {
                "name": "artex_search_worker_traces",
                "description": "[ARTEX Shared Worker Memory] Searches across all workers' raw observations, error snippets, and headers (`search_all_worker_traces`).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "task_id": {"type": "string"},
                        "limit": {"type": "integer", "default": 25},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "artex_get_attack_chains",
                "description": "[ARTEX Dual-Graph] Lists persisted multi-step attack chains, POE levels, verification status, and step plans from terminator.db.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
            {
                "name": "artex_retest_chain",
                "description": "[ARTEX Retester] Re-evaluates a confirmed attack chain against bound traffic evidence (or live HTTP replay) and records STILL_REPRODUCIBLE / FIXED / CANNOT_CONFIRM.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "chain_id": {"type": "string"},
                        "conditions": {"type": "string", "default": ""},
                        "auto_mark_fixed": {"type": "boolean", "default": True},
                        "live": {"type": "boolean", "default": False},
                        "authorized": {"type": "boolean", "default": False},
                    },
                    "required": ["chain_id"],
                },
            },
            {
                "name": "artex_import_surface",
                "description": "[Pillar 2: Surface & Session Importer] Imports an OpenAPI 3.x/Swagger 2.0 spec, HAR 1.2 traffic capture, or YAML/JSON scope file directly into the persistent ARTEX AssetGraph & traffic_evidence store.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "openapi_path": {"type": "string"},
                        "har_path": {"type": "string"},
                        "scope_path": {"type": "string"},
                        "host": {"type": "string", "default": "127.0.0.1"},
                        "port": {"type": "integer", "default": 443},
                        "task_id": {"type": "string"},
                    },
                },
            },
            {
                "name": "artex_export_advisory",
                "description": "[Pillar 5: Advisory & Archive Exporter] Exports GHSA-ready Markdown advisories, formula-neutralized CSV, and/or AES-256-GCM encrypted task archives (.rfca) with SHA-256 verification.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "chain_id": {"type": "string"},
                        "task_id": {"type": "string"},
                        "output_dir": {"type": "string", "default": "reports/advisories"},
                        "export_csv": {"type": "boolean", "default": False},
                        "archive_path": {"type": "string"},
                    },
                },
            },
            {
                "name": "artex_approval_history",
                "description": "[Pillar 3: Approval Gate Audit Trail] Returns persisted approval gate decisions (ALLOW / DENY / PROMPT) from terminator.db.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "default": 100},
                    },
                },
            },
            {
                "name": "artex_budget_status",
                "description": "[Pillar 4: Durable LLM Budget Ledger] Returns persisted token/turn consumption for a task from the `llm_usage` table.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {"type": "string"},
                    },
                    "required": ["task_id"],
                },
            },
            {
                "name": "artex_coverage_report",
                "description": "[ARTEX Asset Coverage Ledger] Returns tested vs untested assets and exploration_anchors links from terminator.db.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {"type": "string"},
                    },
                },
            },
            {
                "name": "artex_headless_task",
                "description": "[Headless BaaRai/ARTEX REST+SSE Bridge] Drives a running ARTEX Go backend (:8787) programmatically via REST API & SSE without opening a browser.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["health", "create_task", "get_task", "list_tasks", "update_llm", "ingest_traffic", "get_findings", "stream_events", "register_mcp"],
                            "default": "health",
                        },
                        "artex_url": {"type": "string", "default": "http://127.0.0.1:8787"},
                        "artex_token": {"type": "string"},
                        "authorized": {"type": "boolean", "default": False},
                        "task_id": {"type": "string"},
                        "name": {"type": "string"},
                        "goal": {"type": "string"},
                        "targets": {"type": "array", "items": {"type": "string"}},
                        "llm_profile_ids": {"type": "array", "items": {"type": "string"}},
                        "llm_rotate": {"type": "boolean"},
                        "exchanges": {"type": "array", "items": {"type": "object"}},
                        "mcp_name": {"type": "string"},
                        "mcp_url": {"type": "string"},
                        "mcp_transport": {"type": "string", "enum": ["http", "sse"], "default": "http"},
                        "mcp_token": {"type": "string"},
                        "timeout_sec": {"type": "number", "default": 15.0},
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "mantis_scan",
                "description": "[Module 20: Google Mantis] Executes automated STRIDE threat modeling, depth-scaled AST/rule hypothesis synthesis, Tier 1/2 sandbox canary reproduction, calibrated CVSS v3.1 scoring, and verified adversarial patching using ModelFusion + Abliterated models.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "description": "Target file or directory path"},
                        "repo": {"type": "string", "description": "Alternative repository directory path"},
                        "path": {"type": "string", "description": "Alternative file or directory path"},
                        "depth": {"type": "integer", "default": 30, "description": "Audit depth 1..100"},
                        "mode": {
                            "type": "string",
                            "enum": ["full", "fast", "threat-model", "scan", "reproduce", "patch"],
                            "default": "full",
                        },
                        "output_dir": {"type": "string", "default": "reports"},
                    },
                },
            },
            {
                "name": "rea_analyze_surface",
                "description": "[Module 21: morluto/rea] Analyzes JavaScript/TypeScript bundles, source maps (.map), HTML scripts, Electron .asar archives, and bounded same-origin live JS bundles to discover hidden /internal and /service routes, AI sinks, OIDC audience configs, embedded client secrets, and Electron IPC/webPreferences risks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "description": "Local JS/TS/Electron/.asar/.map/HTML file or directory path"},
                        "host": {"type": "string", "description": "Optional authorized host for bounded same-origin JS bundle mining"},
                        "port": {"type": "integer", "description": "Optional target port"},
                        "use_tls": {"type": "boolean", "default": False},
                        "authorized": {"type": "boolean", "default": False},
                        "use_rea_cli": {"type": "boolean", "default": False, "description": "Opt-in to locally installed rea-agents CLI (shell=False)"},
                        "approval_mode": {"type": "string", "enum": ["policy", "deny"], "default": "policy"},
                        "approval_rules": {"type": "string"},
                        "output_dir": {"type": "string", "default": "reports"},
                    },
                },
            },
            {
                "name": "rfchunt_provision_tools",
                "description": "[Dynamic Tool Provisioner] Checks installation status or dynamically installs all external RFCHunt dependencies (aiscan, RAPTOR, ProjectDiscovery httpx/katana/nuclei, BaaRai/ARTEX, morluto/rea rea-agents CLI, Semgrep, Python deps, Ollama runtime & abliterated models, RFC corpus cache).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "install_missing": {"type": "boolean", "default": False, "description": "If true (and online/allowed), dynamically install missing tools; if false, report status only"},
                        "tools": {"type": "array", "items": {"type": "string"}, "description": "Optional subset of tool IDs (e.g. aiscan, raptor, httpx, katana, nuclei, artex, rea_agents, semgrep, python_deps, ollama, ollama_models, rfc_cache)"},
                        "include_docker": {"type": "boolean", "default": True, "description": "Include Docker container images (danielcuthbert/raptor:latest, projectdiscovery/*)"},
                        "include_models": {"type": "boolean", "default": True, "description": "Include Ollama abliterated ModelFusion models"},
                        "force": {"type": "boolean", "default": False, "description": "Re-install even if already cached"},
                    },
                },
            },
            {
                "name": "inject_blackboard_hint",
                "description": (
                    "[Cairn Blackboard] Persists a live operator or agent steering HINT "
                    "into terminator.db so active OODA Reason passes absorb it without restarting."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "hint_text": {
                            "type": "string",
                            "description": "Non-empty steering rule or guardrail text to inject onto the blackboard.",
                        },
                        "domain": {
                            "type": "string",
                            "default": "global",
                            "description": "Protocol domain scope (e.g. 'global', 'http11_framing', 'h2_translation').",
                        },
                        "priority": {
                            "type": "number",
                            "default": 10.0,
                            "description": "Finite numeric priority score (higher values are retrieved first).",
                        },
                        "task_id": {
                            "type": "string",
                            "default": "default",
                            "description": "Swarm task identifier scope.",
                        },
                        "rfc_num": {
                            "type": "string",
                            "description": "Optional RFC number or identifier (e.g. '9112', 'RFC9112').",
                        },
                        "source": {
                            "type": "string",
                            "default": "mcp",
                            "description": "Source agent identifier stored on the HINT node.",
                        },
                        "active": {
                            "type": "boolean",
                            "default": True,
                            "description": "Whether the injected HINT starts ACTIVE (true) or INACTIVE (false).",
                        },
                    },
                    "required": ["hint_text"],
                },
            },
            {
                "name": "arxiv_discover_and_convert_security_research",
                "description": (
                    "[ArXiv-to-Code Security Bridge] Uses D:\\harfile\\arixiv-to-code to discover, extract 3-class "
                    "Google LangExtract character-interval spans, synthesize # EVOLVE-BLOCK Python detector modules, "
                    "evolve via ShinkaEvolve + OpenEvolve, verify 7/7 tests, and register --reseach-num / --research-num "
                    "new AI Security and Application Code Security research articles with verified code & GitHub repositories."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "default": "LLM agent sandbox escape prompt injection static taint analysis",
                        },
                        "domain": {
                            "type": "string",
                            "enum": ["both", "AI_SECURITY", "APP_CODE_SECURITY"],
                            "default": "both",
                        },
                        "research_num": {
                            "type": "integer",
                            "default": 5,
                            "description": "Number of research articles with code & GitHub repos to extract and convert per domain (--reseach-num / --research-num).",
                        },
                        "require_code_repo": {"type": "boolean", "default": True},
                        "evolve": {"type": "boolean", "default": True},
                        "use_rl": {"type": "boolean", "default": False, "description": "Optimize synthesized detectors with Dream-RSI RL (arXiv:2609.14858)."},
                        "verify_panel": {"type": "boolean", "default": False, "description": "Run ModelFusion Panel-of-Models verification (glm4:9b + qwen2.5:7b -> Judge glm4:9b)."},
                        "panel_size": {"type": "integer", "default": 2},
                        "auto_repair": {"type": "boolean", "default": True, "description": "Run iterative Auto-Repair retry loop (Ruff + mypy --strict + 310-property fuzzing + pytest + Ollama patcher)."},
                        "max_repair_attempts": {"type": "integer", "default": 3},
                    },
                },
            },
            {
                "name": "verify_and_auto_repair_python_code",
                "description": (
                    "[ArXiv-to-Code Verification & Auto-Repair Gate] Verifies generated or custom Python code "
                    "using concurrent Layer-1 gates (AST security + Ruff/AST lint + mypy --strict + 310-property "
                    "randomized fuzzing + isolated subprocess pytest + 7 runtime invariants) plus optional ModelFusion "
                    "Panel-of-Models (glm4:9b + qwen2.5:7b -> Judge glm4:9b) and iterative monotonic Auto-Repair retry loop."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "python_source_code": {"type": "string", "description": "Complete Python source code to verify and optionally auto-repair."},
                        "arxiv_id": {"type": "string", "default": "custom"},
                        "title": {"type": "string", "default": "Generated Security Detector Module"},
                        "use_panel": {"type": "boolean", "default": False},
                        "panel_size": {"type": "integer", "default": 2},
                        "auto_repair": {"type": "boolean", "default": True},
                        "max_repair_attempts": {"type": "integer", "default": 3},
                        "enable_llm": {"type": "boolean", "default": False},
                    },
                    "required": ["python_source_code"],
                },
            },
            {
                "name": "run_arxiv_ai_security_detectors",
                "description": (
                    "[ArXiv-to-Code AI Security Detectors] Runs the 5 research-derived AI Security detectors "
                    "(ARXIV-AI-01..05: Bounded Agents APC delegation, SandboxEscapeBench container breakout, "
                    "Adaptive IPI tool hijack, PISanitizer long-context splitting, GuardReasoner drift) "
                    "plus any newly ingested AI security detectors on a target repository or path."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "default": "."},
                        "research_num": {"type": "integer", "default": 5},
                    },
                },
            },
            {
                "name": "run_arxiv_appsec_code_detectors",
                "description": (
                    "[ArXiv-to-Code Application Code Security Detectors] Runs the 5 research-derived Application "
                    "Code Security detectors (ARXIV-APPSEC-01..05: IRIS neuro-symbolic taint, ACFix RBAC/BOLA "
                    "sibling-route consistency, Rudra unsafe Rust panic/Send/Sync, LLMSan unchecked allocation "
                    "dataflow, H2-to-H1 reverse-proxy downgrade desync) on a target repository or path."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "default": "."},
                        "research_num": {"type": "integer", "default": 5},
                    },
                },
            },
            {
                "name": "run_all_arxiv_research_detectors",
                "description": (
                    "[ArXiv-to-Code Unified Scanner] Runs all 10 built-in + dynamically ingested arXiv security "
                    "research detectors (5 AI Security + 5 App Code Security) and optionally syncs new papers "
                    "from D:\\harfile\\arixiv-to-code."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "default": "."},
                        "sync_new_query": {"type": "string", "default": ""},
                        "research_num": {"type": "integer", "default": 5},
                    },
                },
            },
            {
                "name": "list_active_arxiv_research_detectors",
                "description": (
                    "[ArXiv-to-Code Catalog] Lists all active research-backed security detectors with their "
                    "arXiv IDs, verified GitHub repository URLs, CWEs, mathematical formulations, and evolved fitness scores."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "default": "all"},
                    },
                },
            },
            {
                "name": "last30days_discover_security_skills",
                "description": (
                    "[Zero-API Last30Days Security Skills Discovery] Adapts mvanhorn/last30days-skill using "
                    "STRICTLY ZERO-API-KEY public sources (Reddit public JSON, Hacker News Algolia keyless API, "
                    "GitHub keyless public search, arXiv keyless Atom API, dev.to keyless API, local corpus) "
                    "to harvest, engagement-score, and build --reseach-num / --research-num security & pentesting "
                    "skills (SKILL.md + executable Python detectors)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {
                            "type": "string",
                            "default": "AI security prompt injection bug bounty pentesting",
                        },
                        "domain": {
                            "type": "string",
                            "enum": ["both", "AI_SECURITY", "APP_CODE_SECURITY"],
                            "default": "both",
                        },
                        "research_num": {"type": "integer", "default": 5},
                        "skills_num": {"type": "integer", "default": 5},
                        "days": {"type": "integer", "default": 30},
                        "emit_skill_md": {"type": "boolean", "default": True},
                    },
                },
            },
            {
                "name": "run_last30days_security_skills",
                "description": (
                    "[Zero-API Last30Days Security Skill Scanner] Executes all 10 zero-API last-30-days security "
                    "& hacking detection skills (5 AI/Agent Security + 5 App/Web Bug-Bounty Skills) against a repository."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "default": "."},
                        "domain": {"type": "string", "default": "both"},
                        "sync_online": {"type": "boolean", "default": False},
                        "topic": {"type": "string", "default": ""},
                        "research_num": {"type": "integer", "default": 5},
                        "skills_num": {"type": "integer", "default": 5},
                    },
                },
            },
            {
                "name": "audit_agent_skill_package",
                "description": (
                    "[Hermes & Cookie-Consent Skill Package Auditor] Audits a SKILL.md, .claude-plugin, "
                    ".codex-plugin, .grok-plugin, or agent repository for remote piped shell backdoors, "
                    "unconsented browser cookie sidecar/keychain reads (PR #1440), and MCP tool rug-pulls."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "skill_or_repo_path": {"type": "string", "default": "."},
                    },
                    "required": ["skill_or_repo_path"],
                },
            },
            {
                "name": "list_active_last30days_security_skills",
                "description": (
                    "[Zero-API Last30Days Skills Catalog] Lists all active zero-API security & pentesting "
                    "skills with their keyless source lanes, engagement scores, CWEs, and SKILL.md paths."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "default": "all"},
                    },
                },
            },
            {
                "name": "run_preflight_discovery",
                "description": (
                    "[Module 23 Fresh Pre-Flight Discovery + Post-Quantum + Safe Skills] Executes a fresh, "
                    "zero-cache pre-flight pass inspecting manifests, schemas, file extensions, and prompts "
                    "across all 14 domains/protocols/HackerOne categories including Post-Quantum Cryptography "
                    "(FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, XMSS/LMS, Hybrid TLS, HNDL), "
                    "conditional keyless live research (OSV.dev exact-version CVEs, IETF RFCs, arXiv, HN), "
                    "and fail-closed local skill safety auditing."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "default": "."},
                        "prompt": {"type": "string", "default": ""},
                        "policy_text": {"type": "string", "default": ""},
                        "target_host": {"type": "string", "default": ""},
                        "live": {"type": "boolean", "default": False},
                        "enable_pqc": {"type": "boolean", "default": True},
                        "include_home_skills": {"type": "boolean", "default": True},
                        "dry_run": {"type": "boolean", "default": False},
                    },
                },
            },
            {
                "name": "run_crlf_conformance_audit",
                "description": (
                    "[Module 24 Reverse-Proxy Config & RFC 9112 Header Conformance Auditor] Audits Nginx/OpenResty/Tengine "
                    "configs for unsafe normalized $uri/$document_uri interpolation and optionally runs safe, read-only "
                    "3-trial RFC 9112 header-rejection conformance diagnostics against an authorized host."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "default": "."},
                        "host": {"type": "string", "default": ""},
                        "port": {"type": "integer", "default": 80},
                        "use_tls": {"type": "boolean", "default": False},
                        "trials": {"type": "integer", "default": 3},
                    },
                },
            },
            {
                "name": "run_web_llm_security_audit",
                "description": (
                    "[Module 25 Web LLM Defensive Security Auditor] Scans a repository for OWASP LLM & PortSwigger "
                    "Web LLM flaws: excessive agency, unvalidated tool-argument sinks, insecure output handling, "
                    "unfenced untrusted prompt data, prompt-only access control, and missing RAG tenant/PII scrubbing."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "default": "."},
                    },
                },
            },
            {
                "name": "run_pe_dotnet_audit",
                "description": (
                    "[PE & .NET Code Integrity Anomaly Auditor] Scans PE/.NET binaries and workspaces for "
                    "Google Magika hybrid PE classification, extension masquerading, CVE-2026-108398 "
                    "(IMAGE_FILE_EXECUTABLE_IMAGE 0x0002 cleared), UMCI / SEC_COMMIT flat memory fallback "
                    "anomalies, defensive YARA rules, and Windows KB5127694 / VirtualBox 7.2.18+ host patch audit."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "default": "."},
                        "workspace_root": {"type": "string", "description": "Optional workspace root directory for strict path confinement"},
                        "include_host_audit": {"type": "boolean", "default": False, "description": "Include Windows KB5127694 and VirtualBox 7.2.18+ host patch audit"},
                        "include_yara": {"type": "boolean", "default": True, "description": "Evaluate defensive PE/.NET YARA rules"},
                    },
                },
            },
            {
                "name": "run_autonomous_hunt",
                "description": (
                    "[Unified Master CLI --hunt Agent Tool] Runs RFCHunt's turnkey autonomous hunt "
                    "pipeline (`rfc_hunt_swarm.py --hunt --once --headless-only`) for zero-side-effect "
                    "dry-run planning or a single bounded headless cycle (auto-submit & CAPTCHA bypass forbidden)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "targets": {"type": "array", "items": {"type": "string"}},
                        "repos": {"type": "array", "items": {"type": "string"}},
                        "program": {"type": "string", "default": "generic"},
                        "sync_public_directory": {"type": "boolean", "default": False},
                        "eligibility_db": {"type": "string"},
                        "watchlist": {"type": "string"},
                        "min_efficiency": {"type": "number", "default": 80.0},
                        "portfolio_capacity": {"type": "integer", "default": 6},
                        "max_repos": {"type": "integer", "default": 4},
                        "out_dir": {"type": "string", "default": "out/autonomous_hunt"},
                        "embedded": {"type": "boolean", "default": False},
                        "no_llm": {"type": "boolean", "default": False},
                        "allow_blocked": {"type": "boolean", "default": False},
                        "dry_run": {"type": "boolean", "default": True},
                        "model": {"type": "string"},
                        "workspace_root": {"type": "string"},
                    },
                },
            },
            {
                "name": "run_fast_ooda",
                "description": (
                    "[3-Stage Parallel OODA Triage Funnel] Runs Stage 1 parallel deterministic CPU checks, "
                    "Stage 2 ACDSO Pareto/Anomaly top-5 ranking, and Stage 3 bounded LLM verification."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["target"],
                    "properties": {
                        "target": {"type": "string"},
                        "program": {"type": "string", "default": "generic"},
                        "cpu_workers": {"type": "integer"},
                        "blackboard_db": {"type": "string"},
                        "out_dir": {"type": "string"},
                        "embedded": {"type": "boolean", "default": False},
                        "resume": {"type": "boolean", "default": False},
                        "signal_score": {"type": "number", "default": 0.0},
                        "eligibility_db_path": {"type": "string"},
                        "model": {"type": "string"},
                        "workspace_root": {"type": "string"},
                    },
                },
            },
            {
                "name": "rank_bounty_programs",
                "description": (
                    "[ACDSO ML Program Selector] Ranks UNLOCKED public HackerOne programs using "
                    "survival anti-saturation, GroupKFold LTR, 6-objective Pareto knee, bandit & Two-Phase knapsack."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "eligibility_db_path": {"type": "string"},
                        "min_efficiency_pct": {"type": "number", "default": 80.0},
                        "preset": {"type": "string", "enum": ["signal_fast", "balanced", "max_ev"]},
                        "capacity": {"type": "integer", "default": 6},
                        "budget_minutes": {"type": "number", "default": 120.0},
                        "include_deferred": {"type": "boolean", "default": False},
                        "use_boost_tie_break": {"type": "boolean", "default": False},
                    },
                },
            },
            {
                "name": "sync_hackerone_directory",
                "description": (
                    "[HackerOne Public Directory Sync] Syncs public HackerOne programs (newest launch first, "
                    ">=80% efficiency) or offline JSON snapshots into ProgramEligibilityDB v2."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "eligibility_db_path": {"type": "string"},
                        "snapshot_json": {"type": "string"},
                        "programs": {"type": "array", "items": {"type": "object"}},
                        "public_directory": {"type": "boolean", "default": False},
                        "public_endpoint": {"type": "string"},
                        "query": {"type": "string", "default": ""},
                        "limit": {"type": "integer", "default": 25},
                        "min_efficiency_pct": {"type": "number", "default": 80.0},
                        "bounties_only": {"type": "boolean", "default": False},
                        "vdp_only": {"type": "boolean", "default": False},
                    },
                },
            },
            {
                "name": "score_fresh_commits",
                "description": "[ACDSO CommitDiffRanker] Scores and prioritizes <72h commits/PRs/releases with velocity burst detection and diff-scoped scanner routing.",
                "inputSchema": {
                    "type": "object",
                    "required": ["candidates"],
                    "properties": {
                        "candidates": {"type": "array", "items": {"type": "object"}},
                        "program_scores": {"type": "object"},
                        "repo_stars_map": {"type": "object"},
                    },
                },
            },
            {
                "name": "cluster_recon_assets",
                "description": "[ReconAssetClusterer] Clusters HTTP recon endpoints via K-Means++ + p95 noise threshold and classifies anomalous HTTP responses.",
                "inputSchema": {
                    "type": "object",
                    "required": ["assets"],
                    "properties": {
                        "assets": {"type": "array", "items": {"type": "object"}},
                        "program_handle": {"type": "string"},
                        "eligibility_db_path": {"type": "string"},
                        "max_clusters": {"type": "integer", "default": 8},
                    },
                },
            },
            {
                "name": "analyze_js_bundles",
                "description": "[JavaScriptBundleAnalyzer] Extracts hidden API/GraphQL/OIDC endpoints, DOM/postMessage sinks, source map leaks, and scoped recon clusters from JS bundles.",
                "inputSchema": {
                    "type": "object",
                    "required": ["bundles"],
                    "properties": {
                        "bundles": {"type": "array", "items": {"type": "object"}},
                        "program_handle": {"type": "string"},
                        "eligibility_db_path": {"type": "string"},
                        "cluster": {"type": "boolean", "default": True},
                    },
                },
            },
            {
                "name": "classify_http_responses",
                "description": "[HTTPResponseAnomalyClassifier] Classifies anomalous HTTP responses via Welford streaming outlier scoring and baseline differential checks.",
                "inputSchema": {
                    "type": "object",
                    "required": ["responses"],
                    "properties": {
                        "responses": {"type": "array", "items": {"type": "object"}},
                        "baseline": {"type": "object"},
                        "program_handle": {"type": "string"},
                        "eligibility_db_path": {"type": "string"},
                    },
                },
            },
            {
                "name": "qa_bounty_drafts",
                "description": "[HackerOne Draft QA Phase] Runs 14 automated QA checks & lossless auto-repairs on Markdown drafts or exported draft JSON snapshots.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "markdown_body": {"type": "string"},
                        "markdown_file": {"type": "string"},
                        "snapshots": {"type": "array", "items": {"type": "object"}},
                        "title": {"type": "string", "default": ""},
                        "report_id": {"type": "integer", "default": 1},
                        "program": {"type": "string", "default": ""},
                        "verify_sources": {"type": "boolean", "default": False},
                        "qa_db_path": {"type": "string"},
                        "include_repaired_body": {"type": "boolean", "default": True},
                    },
                },
            },
            {
                "name": "check_bounty_drafts",
                "description": "[HackerOne Cooldown Monitor] Strictly read-only inspection of tracked HackerOne drafts and cooldown readiness (never clicks Submit or Delete).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "db_path": {"type": "string"},
                        "qa_db_path": {"type": "string"},
                        "probe_id": {"type": "integer", "default": 4243972},
                        "probe_only": {"type": "boolean", "default": True},
                        "seed_only": {"type": "boolean", "default": True},
                        "snapshots": {"type": "array", "items": {"type": "object"}},
                        "max_per_day": {"type": "integer", "default": 2},
                        "mark_submitted": {"type": "integer"},
                    },
                },
            },
        ]

    @staticmethod
    def _reject_shell_execution(args: Dict[str, Any]) -> None:
        if args.get("shell") not in (None, False):
            raise PermissionError("shell=True is forbidden by ExecutionPolicy.")
        raw_cmd = args.get("command")
        if isinstance(raw_cmd, str):
            raise PermissionError("Raw shell command strings are forbidden by ExecutionPolicy.")

    @staticmethod
    def _parse_strict_bool(args: Dict[str, Any], key: str, default: Optional[bool]) -> Optional[bool]:
        if key not in args or args[key] is None:
            return default
        val = args[key]
        if not isinstance(val, bool):
            raise ValueError(f"Parameter '{key}' must be a boolean.")
        return val

    @staticmethod
    def _parse_strict_int(
        args: Dict[str, Any],
        key: str,
        default: Optional[int],
        *,
        min_val: Optional[int] = None,
        max_val: Optional[int] = None,
        allow_none: bool = True,
    ) -> Optional[int]:
        if key not in args:
            return default
        val = args[key]
        if val is None:
            if allow_none:
                return default
            raise ValueError(f"Parameter '{key}' must be an integer.")
        if isinstance(val, bool) or not isinstance(val, int):
            raise ValueError(f"Parameter '{key}' must be an integer.")
        if min_val is not None and val < min_val:
            raise ValueError(f"Parameter '{key}' must be >= {min_val}, got {val}.")
        if max_val is not None and val > max_val:
            raise ValueError(f"Parameter '{key}' must be <= {max_val}, got {val}.")
        return val

    @staticmethod
    def _parse_strict_float(
        args: Dict[str, Any],
        key: str,
        default: Optional[float],
        *,
        min_val: Optional[float] = None,
        max_val: Optional[float] = None,
    ) -> Optional[float]:
        if key not in args or args[key] is None:
            return default
        val = args[key]
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise ValueError(f"Parameter '{key}' must be numeric.")
        fval = float(val)
        if not math.isfinite(fval):
            raise ValueError(f"Parameter '{key}' must be finite.")
        if min_val is not None and fval < min_val:
            raise ValueError(f"Parameter '{key}' must be >= {min_val}, got {fval}.")
        if max_val is not None and fval > max_val:
            raise ValueError(f"Parameter '{key}' must be <= {max_val}, got {fval}.")
        return fval

    @staticmethod
    def _parse_strict_str(
        args: Dict[str, Any],
        key: str,
        default: Optional[str] = None,
        *,
        allow_empty: bool = False,
    ) -> Optional[str]:
        if key not in args or args[key] is None:
            return default
        val = args[key]
        if not isinstance(val, str):
            raise ValueError(f"Parameter '{key}' must be a string.")
        if "\x00" in val:
            raise ValueError(f"Parameter '{key}' contains invalid NUL byte.")
        if not allow_empty and not val.strip():
            raise ValueError(f"Parameter '{key}' must be a non-empty string.")
        return val

    @staticmethod
    def _parse_str_list(
        args: Dict[str, Any],
        key: str,
        default: Optional[List[str]] = None,
    ) -> Optional[List[str]]:
        if key not in args or args[key] is None:
            return default
        val = args[key]
        if not isinstance(val, list):
            raise ValueError(f"Parameter '{key}' must be an array of strings.")
        out: List[str] = []
        for item in val:
            if not isinstance(item, str) or "\x00" in item:
                raise ValueError(f"Parameter '{key}' items must be valid strings.")
            out.append(item)
        return out

    @staticmethod
    def _authorize_mcp_target(
        raw_host: Any,
        *,
        port: Optional[int] = None,
        use_tls: Optional[bool] = None,
        authorized: bool = False,
    ) -> Tuple[str, int, bool]:
        if not isinstance(raw_host, str) or not raw_host.strip():
            raise ValueError("Parameter 'host' must be a non-empty string.")
        if "\x00" in raw_host or any(ord(ch) < 32 for ch in raw_host) or any(ch.isspace() for ch in raw_host):
            raise PermissionError("Target host contains forbidden control or whitespace characters.")

        from engine.safe_network_validator import parse_host_and_port, validate_and_authorize_target

        clean_host, resolved_port, resolved_tls = parse_host_and_port(
            raw_host.strip(),
            default_port=port,
            use_tls=use_tls,
        )
        if clean_host in ("0.0.0.0", "::"):
            TargetAuthorizationGate.check_target(clean_host)
        ok, reason = validate_and_authorize_target(clean_host, authorized=authorized)
        if not ok:
            raise PermissionError(f"Target authorization failed for {clean_host}: {reason}")
        TargetAuthorizationGate.check_auth(host=clean_host, payload_len=0)
        return clean_host, resolved_port, resolved_tls

    def _build_mcp_approval_gate(
        self,
        args: Dict[str, Any],
        task_id: str,
        workspace_root: Optional[Union[str, Path]] = None,
    ):
        from engine.approval_gate import ApprovalGate

        mode_raw = self._parse_strict_str(args, "approval_mode", "policy")
        approval_mode = (mode_raw or "policy").strip().lower()
        if approval_mode not in ("policy", "deny"):
            raise ValueError(
                f"Unsupported MCP approval_mode {approval_mode!r}; allowed values: 'policy', 'deny'."
            )
        rules_path = self._parse_strict_str(args, "approval_rules", None)
        if rules_path:
            rules_path = self._validate_mcp_scan_path(
                rules_path,
                workspace_root=workspace_root,
                allow_directory=False,
            )
            return ApprovalGate.from_rules_file(
                rules_path,
                mode=approval_mode,
                db=self.db,
                task_id=task_id,
            )
        return ApprovalGate(mode=approval_mode, db=self.db, task_id=task_id)

    def _execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        if name == "run_continuous_hunt":
            token = args.get("supervisor_token") or os.environ.get("RFCHUNT_SUPERVISOR_TOKEN")
            TargetAuthorizationGate.check_auth(
                host=args.get('target_host', '127.0.0.1'),
                payload_len=0,
                is_heavy_hunt=True,
                supervisor_token=token,
            )
            hunter = ContinuousFlawHunter(
                target_host=args.get("target_host", "127.0.0.1"),
                target_port=args.get("target_port", 8080),
                use_tls=args.get("use_tls", False),
                preferred_model=args.get("model", "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"),
                use_fusion=args.get("use_fusion", True),
                db_path=self.db_path,
                on_progress=lambda msg: sys.stderr.write(f"{msg}\n"),
            )
            flaws = hunter.run_until_flaw(
                max_rfcs=args.get("max_rfcs", 10),
                stop_on_first_flaw=args.get("stop_on_first_flaw", True),
            )
            return {"status": "success", "flaws_found": len(flaws), "flaws": flaws}

        elif name == "fetch_rfc":
            if args.get("discover_recent"):
                nums = self.fetcher.discover_recent_rfcs(max_discover=int(args["discover_recent"]))
                return {"discovered_recent_rfcs": nums}
            num = args.get("rfc_number", 9112)
            text = self.fetcher.fetch_rfc_by_number(num)
            return {"rfc_number": num, "length": len(text) if text else 0, "status": "fetched" if text else "failed"}

        elif name == "chunk_and_inspire":
            if "rfc_text" not in args or args["rfc_text"] is None:
                raise ValueError("Missing required parameter 'rfc_text'.")
            text = str(args["rfc_text"])
            sentences = args.get("sentences_per_chunk", 2)
            fragments = RFCChunker.chunk_document(text, sentences_per_chunk=sentences)
            return {"fragment_count": len(fragments), "fragments": fragments[:10]}

        elif name == "generate_probes":
            if "rfc_fragment" not in args or args["rfc_fragment"] is None:
                raise ValueError("Missing required parameter 'rfc_fragment'.")
            generator = ProbeGenerator(
                preferred_model=args.get("model", "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"),
                use_fusion=args.get("use_fusion", True),
                db=self.db,
            )
            probes = generator.generate_candidate_probes(str(args["rfc_fragment"]))
            return {"probe_count": len(probes), "probes": probes}

        elif name == "evaluate_probe":
            raw_req = args.get("raw_request") or ""
            req_len = len(raw_req.encode("utf-8") if isinstance(raw_req, str) else raw_req)
            TargetAuthorizationGate.check_auth(
                host=args.get('target_host', '127.0.0.1'),
                payload_len=req_len,
            )
            if "raw_request" not in args or args["raw_request"] is None:
                raise ValueError("Missing required parameter 'raw_request'.")
            harness = DeterministicHarness(
                host=args.get("target_host", "127.0.0.1"),
                port=args.get("target_port", 8080),
                use_tls=args.get("use_tls", False),
                db=self.db,
            )
            probe_dict = {
                "raw_request": args["raw_request"],
                "rationale": "MCP triggered evaluation",
                "is_clean": False,
            }
            is_vuln, desync_class, details, meta = harness.run_evaluation(probe_dict)
            return {
                "is_vulnerable": is_vuln,
                "desync_class": desync_class,
                "details": details,
                "anomalies": meta.get("anomalies", []),
            }

        elif name == "weaponize_dangling_byte":
            base_trig = args.get("base_trigger") or ""
            trig_len = len(base_trig.encode("utf-8") if isinstance(base_trig, str) else base_trig)
            token = args.get("supervisor_token") or os.environ.get("RFCHUNT_SUPERVISOR_TOKEN")
            TargetAuthorizationGate.check_auth(
                host=args.get('target_host', '127.0.0.1'),
                payload_len=trig_len,
                is_weaponization=True,
                supervisor_token=token,
            )
            if "base_trigger" not in args or args["base_trigger"] is None:
                raise ValueError("Missing required parameter 'base_trigger'.")
            weaponizer = RQPWeaponizer(
                host=args.get("target_host", "127.0.0.1"),
                port=args.get("target_port", 8080),
                use_tls=args.get("use_tls", False),
                db=self.db,
            )
            is_stolen, reason, evidence = weaponizer.test_dangling_byte_rqp(args["base_trigger"])
            return {"is_weaponized": is_stolen, "reason": reason, "evidence": evidence}

        elif name == "cascade_extrapolate":
            cascade = DiscoveryCascade(
                preferred_model=args.get("model", "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"),
                db=self.db,
            )
            res = cascade.cascade_from_finding(args)
            return res or {"status": "no_extrapolation_generated"}

        elif name == "get_database_stats":
            with self.db._lock:
                c = self.db.conn.cursor()
                try:
                    c.execute("SELECT COUNT(*) FROM rfcs")
                    rfcs_count = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM fragments")
                    fragments_count = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM probes")
                    probes_count = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM evaluations WHERE is_vulnerable = 1")
                    vulns_count = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM anomalies")
                    anomalies_count = c.fetchone()[0]
                finally:
                    c.close()
            return {
                "rfcs_ingested": rfcs_count,
                "fragments_stored": fragments_count,
                "probes_generated": probes_count,
                "confirmed_vulnerabilities": vulns_count,
                "anomalies_detected": anomalies_count,
            }

        elif name == "raptor_status":
            return self.raptor.check_status()

        elif name == "raptor_describe_target":
            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            t_path = self._validate_mcp_scan_path(
                args.get("target_path", "."),
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            return self.raptor.describe_target(t_path)

        elif name == "raptor_scan_project":
            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            t_path = str(args.get("target_path", "."))
            mode = args.get("mode", "scan")
            model = args.get("model", "fenkohq/foundation-sec-8b:latest")
            pg = args.get("policy_groups", "")
            codeql = args.get("include_codeql", False)
            if mode == "web" or t_path.startswith("http://") or t_path.startswith("https://"):
                from engine.safe_network_validator import parse_host_and_port, validate_and_authorize_target
                host, port, tls = parse_host_and_port(t_path, use_tls=None)
                authorized = bool(args.get("authorized", False))
                ok, reason = validate_and_authorize_target(host, authorized=authorized)
                if not ok:
                    raise PermissionError(reason)
                return self.raptor.run_host_scan(host=host, port=port, use_tls=tls, authorized=authorized)
            validated_t_path = self._validate_mcp_scan_path(
                t_path,
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            return self.raptor.run_scan(
                target_path=validated_t_path,
                mode=mode,
                model=model,
                policy_groups=pg,
                include_codeql=codeql,
            )

        elif name == "raptor_list_findings":
            max_i = args.get("max_items", 50)
            findings = self.raptor.list_all_findings(max_items=max_i)
            return {
                "total_findings": len(findings),
                "findings": findings,
                "credit": {
                    "framework": RAPTOR_PROJECT_TITLE,
                    "authors": RAPTOR_AUTHORS,
                    "url": RAPTOR_REPO_URL,
                },
            }

        elif name in ("run_all_scans", "mantis_scan_all"):
            self._reject_shell_execution(args)
            from engine.external_scanners import _normalize_nuclei_tags
            from engine.mantis_integrator import DEFAULT_ABLITERATED_MODEL, run_unified_all_scans

            repo = self._parse_strict_str(args, "repo", None)
            path = self._parse_strict_str(args, "path", None)
            remote_host = self._parse_strict_str(args, "host", None)
            targets_arg = self._parse_strict_str(args, "targets", None)
            remote_port = self._parse_strict_int(args, "port", None, min_val=1, max_val=65535)
            remote_tls = self._parse_strict_bool(args, "tls", None)
            authorized = bool(self._parse_strict_bool(args, "authorized", False))
            approval_mode_raw = self._parse_strict_str(args, "approval_mode", "policy")
            approval_mode = (approval_mode_raw or "policy").strip().lower()
            if approval_mode not in ("policy", "deny"):
                raise ValueError(
                    f"Unsupported MCP approval_mode {approval_mode!r}; allowed values: 'policy', 'deny'."
                )
            approval_rules = self._parse_strict_str(args, "approval_rules", None)
            enable_ext = bool(self._parse_strict_bool(args, "enable_external_scanners", False))
            httpx_scan = self._parse_strict_bool(args, "httpx_scan", None)
            katana_scan = self._parse_strict_bool(args, "katana_scan", None)
            nuclei_scan = self._parse_strict_bool(args, "nuclei_scan", None)
            raw_ntags = args.get("nuclei_tags")
            if raw_ntags is not None:
                try:
                    _normalize_nuclei_tags(raw_ntags)
                except TypeError as te:
                    raise ValueError(str(te)) from te
            scanner_iso = (self._parse_strict_str(args, "scanner_isolation", "host") or "host").strip().lower()
            if scanner_iso not in ("host", "docker"):
                raise ValueError(
                    f"Unsupported scanner_isolation {scanner_iso!r}; expected 'host' or 'docker'."
                )
            docker_image = self._parse_strict_str(args, "docker_image", None)
            docker_network = self._parse_strict_str(args, "docker_network", None)
            artex_live = self._parse_strict_bool(args, "artex_live", None)
            artex_multiturn = bool(self._parse_strict_bool(args, "artex_multiturn", False))
            artex_intent_turns = int(self._parse_strict_int(args, "artex_intent_turns", 0, min_val=0) or 0)
            artex_intent_tokens = int(self._parse_strict_int(args, "artex_intent_tokens", 0, min_val=0) or 0)
            depth = int(self._parse_strict_int(args, "depth", 30, min_val=1, max_val=100) or 30)
            mantis_mode = str(self._parse_strict_str(args, "mantis_mode", "full") or "full")
            reports_dir = self._parse_strict_str(args, "output_dir", "reports") or "reports"
            artex_rounds = int(self._parse_strict_int(args, "artex_rounds", 1, min_val=1) or 1)
            artex_url = self._parse_strict_str(args, "artex_url", None)
            artex_token = self._parse_strict_str(args, "artex_token", None)
            artex_proxy = self._parse_strict_str(args, "artex_proxy", None)
            artex_noise_profile = self._parse_strict_str(args, "artex_noise_profile", None)
            artex_llm_profiles = self._parse_str_list(args, "artex_llm_profiles", None)
            artex_llm_rotate = bool(self._parse_strict_bool(args, "artex_llm_rotate", False))
            artex_wait_sse = bool(self._parse_strict_bool(args, "artex_wait_sse", False))
            artex_budget_turns = int(self._parse_strict_int(args, "artex_budget_turns", 0, min_val=0) or 0)
            artex_retest = bool(self._parse_strict_bool(args, "artex_retest", False))
            artex_workers = int(self._parse_strict_int(args, "artex_workers", 3, min_val=1) or 3)
            embedded_proxy = bool(self._parse_strict_bool(args, "embedded_proxy", False))
            auth_profile = self._parse_strict_str(args, "auth_profile", None)
            import_har = self._parse_strict_str(args, "import_har", None)
            import_openapi = self._parse_strict_str(args, "import_openapi", None)
            scope_file = self._parse_strict_str(args, "scope_file", None)
            strict_poe = bool(self._parse_strict_bool(args, "strict_poe", False))
            export_advisory = bool(self._parse_strict_bool(args, "export_advisory", False))
            export_csv = bool(self._parse_strict_bool(args, "export_csv", False))
            enable_rea = bool(self._parse_strict_bool(args, "enable_rea", True))
            if self._parse_strict_bool(args, "no_rea", False):
                enable_rea = False
            rea_target = self._parse_strict_str(args, "rea_target", None)
            rea_use_cli = bool(
                self._parse_strict_bool(args, "rea_use_cli", False)
                or self._parse_strict_bool(args, "rea_cli", False)
            )
            enable_pe_audit = bool(self._parse_strict_bool(args, "enable_pe_audit", True))
            pe_include_host_audit = bool(self._parse_strict_bool(args, "pe_include_host_audit", False))
            pe_include_yara = bool(self._parse_strict_bool(args, "pe_include_yara", True))

            if remote_host is not None:
                self._authorize_mcp_target(
                    remote_host,
                    port=remote_port,
                    use_tls=remote_tls,
                    authorized=authorized,
                )
            if targets_arg is not None:
                raw_targets_list = [t.strip() for t in targets_arg.split(",") if t.strip()]
                if not raw_targets_list:
                    if remote_host is None:
                        TargetAuthorizationGate.check_rate_limit()
                    raise ValueError("Parameter 'targets' must contain at least one non-empty target host.")
                for idx, t_item in enumerate(raw_targets_list):
                    if remote_host is None and idx == 0:
                        self._authorize_mcp_target(
                            t_item,
                            port=remote_port,
                            use_tls=remote_tls,
                            authorized=authorized,
                        )
                    else:
                        if "\x00" in t_item or any(ord(ch) < 32 for ch in t_item) or any(ch.isspace() for ch in t_item):
                            raise PermissionError("Target host contains forbidden control or whitespace characters.")
                        from engine.safe_network_validator import parse_host_and_port, validate_and_authorize_target
                        t_clean, _, _ = parse_host_and_port(t_item, default_port=remote_port, use_tls=remote_tls)
                        if t_clean in ("0.0.0.0", "::"):
                            TargetAuthorizationGate.check_target(t_clean)
                        ok, reason = validate_and_authorize_target(t_clean, authorized=authorized)
                        if not ok:
                            raise PermissionError(f"Target authorization failed for {t_clean}: {reason}")
                        TargetAuthorizationGate.check_target(t_clean)
            if remote_host is None and targets_arg is None:
                TargetAuthorizationGate.check_rate_limit()

            resolved_repo = None
            resolved_path = None
            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            primary_ws: Optional[Union[str, Path]] = explicit_ws_root
            if repo or path or (not remote_host and not targets_arg):
                if repo is not None:
                    resolved_repo = self._validate_mcp_scan_path(
                        repo, workspace_root=explicit_ws_root, allow_directory=True
                    )
                    if not os.path.exists(resolved_repo):
                        return {"error": f"Target path does not exist: {resolved_repo}"}
                if path is not None:
                    resolved_path = self._validate_mcp_scan_path(
                        path, workspace_root=explicit_ws_root, allow_directory=True
                    )
                    if not os.path.exists(resolved_path):
                        return {"error": f"Target path does not exist: {resolved_path}"}
                if repo is None and path is None:
                    resolved_repo = self._validate_mcp_scan_path(
                        ".", workspace_root=explicit_ws_root, allow_directory=True
                    )
                    if not os.path.exists(resolved_repo):
                        return {"error": f"Target path does not exist: {resolved_repo}"}
                primary_candidate = resolved_repo or resolved_path
                if primary_ws is None and primary_candidate:
                    primary_ws = (
                        primary_candidate
                        if os.path.isdir(primary_candidate)
                        else os.path.dirname(primary_candidate)
                    )
            if rea_target is not None:
                rea_target = self._validate_mcp_scan_path(
                    rea_target, workspace_root=primary_ws, allow_directory=True
                )
            if import_har is not None:
                import_har = self._validate_mcp_scan_path(
                    import_har, workspace_root=primary_ws, allow_directory=False
                )
            if import_openapi is not None:
                import_openapi = self._validate_mcp_scan_path(
                    import_openapi, workspace_root=primary_ws, allow_directory=False
                )
            if scope_file is not None:
                scope_file = self._validate_mcp_scan_path(
                    scope_file, workspace_root=primary_ws, allow_directory=False
                )
            if auth_profile is not None:
                ap_parts = [p.strip() for p in auth_profile.split(",")]
                if not ap_parts or any(not p for p in ap_parts):
                    raise PermissionError("Unsafe MCP auth_profile rejected: empty profile path entry.")
                validated_ap_parts: List[str] = [
                    self._validate_mcp_scan_path(
                        ap_item, workspace_root=primary_ws, allow_directory=False
                    )
                    for ap_item in ap_parts
                ]
                auth_profile = ",".join(validated_ap_parts)
            if approval_rules is not None:
                approval_rules = self._validate_mcp_scan_path(
                    approval_rules, workspace_root=primary_ws, allow_directory=False
                )
            explicit_out_ws = self._has_explicit_output_confinement(args)
            reports_dir = self._validate_mcp_output_dir(
                reports_dir,
                workspace_root=(explicit_ws_root or primary_ws),
                enforce_explicit_ws=explicit_out_ws,
            )

            with _suppress_stdout_to_stderr():
                return run_unified_all_scans(
                    repo=resolved_repo,
                    path=resolved_path,
                    depth=depth,
                    mantis_mode=mantis_mode,
                    use_fusion=True,
                    preferred_model=DEFAULT_ABLITERATED_MODEL,
                    db=self.db,
                    reports_dir=reports_dir,
                    artex_rounds=artex_rounds,
                    host=remote_host,
                    targets=targets_arg,
                    port=remote_port,
                    use_tls=remote_tls,
                    authorized=authorized,
                    artex_url=artex_url,
                    artex_token=artex_token,
                    artex_proxy=artex_proxy,
                    artex_noise_profile=artex_noise_profile,
                    artex_llm_profiles=artex_llm_profiles,
                    artex_llm_rotate=artex_llm_rotate,
                    artex_wait_sse=artex_wait_sse,
                    artex_budget_turns=artex_budget_turns,
                    artex_retest=artex_retest,
                    artex_workers=artex_workers,
                    artex_live=artex_live,
                    embedded_proxy=embedded_proxy,
                    auth_profile=auth_profile,
                    import_har=import_har,
                    import_openapi=import_openapi,
                    scope_file=scope_file,
                    approval_mode=approval_mode,
                    approval_rules=approval_rules,
                    strict_poe=strict_poe,
                    export_advisory=export_advisory,
                    export_csv=export_csv,
                    quiet=True,
                    enable_external_scanners=enable_ext,
                    httpx_scan=httpx_scan,
                    katana_scan=katana_scan,
                    nuclei_scan=nuclei_scan,
                    nuclei_tags=raw_ntags,
                    scanner_isolation=scanner_iso,
                    docker_image=docker_image,
                    docker_network=docker_network,
                    artex_multiturn=artex_multiturn,
                    artex_intent_turns=artex_intent_turns,
                    artex_intent_tokens=artex_intent_tokens,
                    enable_rea=enable_rea,
                    rea_target=rea_target,
                    rea_use_cli=rea_use_cli,
                    enable_pe_audit=enable_pe_audit,
                    pe_include_host_audit=pe_include_host_audit,
                    pe_include_yara=pe_include_yara,
                    workspace_root=explicit_ws_root,
                    confine_reports_to_workspace_root=explicit_out_ws,
                )

        elif name == "artex_run_attack_chain":
            self._reject_shell_execution(args)
            from engine.artex_bridge import ArtexProxyConfig
            from engine.dual_graph_engine import DualGraphAttackEngine
            from engine.safe_network_validator import is_explicit_loopback_host

            raw_host = self._parse_strict_str(args, "host", "127.0.0.1") or "127.0.0.1"
            t_port = self._parse_strict_int(args, "port", 8080, min_val=1, max_val=65535)
            use_tls = bool(self._parse_strict_bool(args, "use_tls", False))
            authorized = bool(self._parse_strict_bool(args, "authorized", False))
            rounds = int(self._parse_strict_int(args, "rounds", 2, min_val=1) or 2)
            budget_turns = int(self._parse_strict_int(args, "budget_turns", 0, min_val=0) or 0)
            multiturn = bool(
                self._parse_strict_bool(args, "multiturn", False)
                or self._parse_strict_bool(args, "artex_multiturn", False)
            )
            max_intent_turns = int(
                self._parse_strict_int(
                    args,
                    "max_intent_turns",
                    self._parse_strict_int(args, "max_turns", 0, min_val=0) or 0,
                    min_val=0,
                )
                or 0
            )
            max_intent_tokens = int(self._parse_strict_int(args, "max_intent_tokens", 0, min_val=0) or 0)

            clean_host, resolved_port, resolved_tls = self._authorize_mcp_target(
                raw_host,
                port=t_port,
                use_tls=use_tls,
                authorized=authorized,
            )
            resolved_ws_root = self._resolve_mcp_workspace_root(args)
            gate = self._build_mcp_approval_gate(args, "MCP-ARTEX-CHAIN", workspace_root=resolved_ws_root)
            if multiturn and gate.mode == "deny":
                fmt_host = f"[{clean_host}]" if ":" in clean_host and not clean_host.startswith("[") else clean_host
                gate.require(
                    action_type="network_socket",
                    target=f"{'https' if resolved_tls else 'http'}://{fmt_host}:{resolved_port}/",
                    method="GET",
                    rationale="MCP artex_run_attack_chain multi-turn execution",
                )

            raw_reports_dir = self._parse_strict_str(args, "reports_dir", None)
            if raw_reports_dir is not None:
                raw_reports_dir = self._validate_mcp_output_dir(
                    raw_reports_dir,
                    workspace_root=resolved_ws_root,
                    enforce_explicit_ws=self._has_explicit_output_confinement(args),
                )

            proxy_cfg = ArtexProxyConfig.from_env_or_args(
                proxy_url=self._parse_strict_str(args, "artex_proxy", None),
                authorized=authorized,
            )
            mcp_arbiter = None
            if os.environ.get("RFCHUNT_OFFLINE") != "1":
                try:
                    from fusion_engine import FusionArbiter
                    mcp_arbiter = FusionArbiter(db=self.db, quiet=True)
                except Exception:
                    mcp_arbiter = None
            try:
                engine = DualGraphAttackEngine(
                    db=self.db,
                    reports_dir=raw_reports_dir,
                    noise_profile=self._parse_strict_str(args, "noise_profile", None),
                    max_task_turns=budget_turns,
                    max_intent_turns=max_intent_turns,
                    max_intent_tokens=max_intent_tokens,
                    arbiter=mcp_arbiter,
                    approval_gate=gate,
                    proxy_config=proxy_cfg,
                )
                if self._parse_strict_bool(args, "hydrate_db", True):
                    engine.ingest_from_database(self.db)
                explicit_endpoints = self._parse_str_list(args, "endpoints", None)
                explicit_ai_sinks = self._parse_str_list(args, "ai_sinks", None)
                existing_eps = engine.asset_graph.find_endpoints_by_type("ENDPOINT", host=clean_host, port=resolved_port)
                existing_sinks = engine.asset_graph.find_endpoints_by_type("AI_SINK", host=clean_host, port=resolved_port)
                eff_endpoints = explicit_endpoints if explicit_endpoints is not None else ([] if existing_eps else ["/api/v1"])
                eff_ai_sinks = explicit_ai_sinks if explicit_ai_sinks is not None else ([] if existing_sinks else ["/api/chat"])
                engine.ingest_target_infrastructure(
                    host=clean_host,
                    port=resolved_port,
                    endpoints=eff_endpoints,
                    ai_sinks=eff_ai_sinks,
                )
                if args.get("findings") is not None:
                    if not isinstance(args["findings"], list):
                        raise ValueError("Parameter 'findings' must be a list of finding objects.")
                    engine.ingest_findings(args["findings"], scanner="mcp_input")

                executor_fn = None
                if multiturn:
                    from engine.live_executors import LiveWorkerExecutorRegistry
                    registry = LiveWorkerExecutorRegistry(
                        host=clean_host,
                        port=resolved_port,
                        use_tls=resolved_tls,
                        authorized=bool(authorized or is_explicit_loopback_host(clean_host)),
                        traffic_session=engine.traffic_session,
                        approval_gate=gate,
                        noise_governor=engine.noise_governor,
                        arbiter=mcp_arbiter,
                        budget_ledger=engine.budget_ledger,
                        trace_store=engine.trace_store,
                        boundary=engine.boundary,
                        asset_graph=engine.asset_graph,
                        workspace_root=self._resolve_mcp_workspace_root(args),
                    )
                    executor_fn = registry.as_multiturn_executor_fn(
                        max_turns=(max_intent_turns if max_intent_turns > 0 else None),
                        budget_ledger=engine.budget_ledger,
                        trace_store=engine.trace_store,
                        boundary=engine.boundary,
                        asset_graph=engine.asset_graph,
                    )

                with _suppress_stdout_to_stderr():
                    cycle_res = engine.run_attack_chain_cycle(
                        round_num=rounds,
                        executor_fn=executor_fn,
                        retest_existing=bool(self._parse_strict_bool(args, "retest", False)),
                    )
                    chains = engine.export_attack_chains_to_sarif_findings()
                    cycle_res["chains"] = chains
                    cycle_res["chains_synthesized"] = len(chains)

                    if args.get("artex_url"):
                        cycle_res["remote_artex"] = engine.sync_with_headless_artex(
                            artex_url=str(self._parse_strict_str(args, "artex_url")),
                            token=self._parse_strict_str(args, "artex_token", None),
                            authorized=authorized,
                            wait_sse=bool(self._parse_strict_bool(args, "artex_wait_sse", False)),
                        )
                return cycle_res
            finally:
                if mcp_arbiter is not None and hasattr(mcp_arbiter, "close"):
                    try:
                        mcp_arbiter.close()
                    except Exception:
                        pass

        elif name == "artex_run_multiturn_worker":
            self._reject_shell_execution(args)
            from engine.artex_bridge import ArtexProxyConfig
            from engine.dual_graph_engine import DualGraphAttackEngine
            from engine.live_executors import LiveWorkerExecutorRegistry
            from engine.safe_network_validator import is_explicit_loopback_host
            from engine.session_loader import AuthProfile as _MCPAuthProfile, load_auth_profiles

            raw_host = self._parse_strict_str(args, "host", "127.0.0.1") or "127.0.0.1"
            port = self._parse_strict_int(args, "port", 8080, min_val=1, max_val=65535)
            use_tls = bool(self._parse_strict_bool(args, "use_tls", False))
            authorized = bool(self._parse_strict_bool(args, "authorized", False))
            target_route = self._parse_strict_str(args, "target_route", "/") or "/"
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in target_route):
                raise ValueError("Parameter 'target_route' contains forbidden control characters.")
            attack_type = (self._parse_strict_str(args, "attack_type", "AUTH_BOUNDARY") or "AUTH_BOUNDARY").upper()
            method = (self._parse_strict_str(args, "method", "GET") or "GET").upper()
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in method):
                raise ValueError("Parameter 'method' contains forbidden control characters.")
            if args.get("max_intent_turns") is not None:
                raw_turns_arg = args.get("max_intent_turns")
            elif args.get("max_turns") is not None:
                raw_turns_arg = args.get("max_turns")
            else:
                raw_turns_arg = None
            if raw_turns_arg is None:
                eff_intent_turns = 4
            else:
                eff_intent_turns = int(
                    self._parse_strict_int(
                        {"v": raw_turns_arg},
                        "v",
                        4,
                        min_val=0,
                    )
                    or 0
                )
            max_intent_tokens = int(self._parse_strict_int(args, "max_intent_tokens", 0, min_val=0) or 0)
            max_task_turns = int(self._parse_strict_int(args, "max_task_turns", 0, min_val=0) or 0)
            max_task_tokens = int(self._parse_strict_int(args, "max_task_tokens", 0, min_val=0) or 0)
            noise_profile = (self._parse_strict_str(args, "noise_profile", "off") or "off").strip().lower()
            if noise_profile not in ("off", "quiet", "balanced", "aggressive"):
                raise ValueError(f"Unsupported noise_profile: {noise_profile!r}")
            strict_poe = bool(self._parse_strict_bool(args, "strict_poe", False))
            resolved_ws_root = self._resolve_mcp_workspace_root(args)
            reports_dir = self._validate_mcp_output_dir(
                self._parse_strict_str(args, "reports_dir", "reports") or "reports",
                workspace_root=resolved_ws_root,
                enforce_explicit_ws=self._has_explicit_output_confinement(args),
            )
            task_id = self._parse_strict_str(args, "task_id", None)
            worker_id = self._parse_strict_str(args, "worker_id", "artex-mcp-worker-1") or "artex-mcp-worker-1"
            auth_profile_path = self._parse_strict_str(args, "auth_profile", None)
            artex_proxy_url = self._parse_strict_str(args, "artex_proxy", None)
            endpoints = self._parse_str_list(args, "endpoints", None)
            ai_sinks = self._parse_str_list(args, "ai_sinks", None)

            clean_host, resolved_port, resolved_tls = self._authorize_mcp_target(
                raw_host,
                port=port,
                use_tls=use_tls,
                authorized=authorized,
            )
            fmt_host = f"[{clean_host}]" if ":" in clean_host and not clean_host.startswith("[") else clean_host
            target_url = f"{'https' if resolved_tls else 'http'}://{fmt_host}:{resolved_port}"

            gate = self._build_mcp_approval_gate(args, task_id or "MCP-MULTITURN", workspace_root=resolved_ws_root)
            if gate.mode == "deny":
                gate.require(
                    action_type="network_socket",
                    target=f"{target_url}{target_route if target_route.startswith('/') else '/' + target_route}",
                    method=method,
                    rationale="MCP bounded multi-turn ArtexWorker execution",
                )

            if auth_profile_path is not None:
                ap_parts = [p.strip() for p in auth_profile_path.split(",")]
                if not ap_parts or any(not p for p in ap_parts):
                    raise PermissionError("Unsafe MCP auth_profile rejected: empty profile path entry.")
                auth_profile_path = ",".join(
                    self._validate_mcp_scan_path(p, workspace_root=resolved_ws_root, allow_directory=False)
                    for p in ap_parts
                )
            if auth_profile_path and "," in auth_profile_path:
                from engine.h2_live_authz import resolve_auth_profiles_from_cli
                loaded_profiles = resolve_auth_profiles_from_cli(auth_profile_path)
            else:
                loaded_profiles = load_auth_profiles(auth_profile_path) if auth_profile_path else {}
            if not loaded_profiles:
                loaded_profiles = {
                    "anonymous_probe": _MCPAuthProfile(
                        name="anonymous_probe",
                        role="end_user",
                        headers={},
                    )
                }
            proxy_cfg = ArtexProxyConfig.from_env_or_args(proxy_url=artex_proxy_url, authorized=authorized)
            mt_arbiter = None
            if os.environ.get("RFCHUNT_OFFLINE") != "1":
                try:
                    from fusion_engine import FusionArbiter
                    mt_arbiter = FusionArbiter(db=self.db, quiet=True)
                except Exception:
                    mt_arbiter = None

            try:
                engine = DualGraphAttackEngine(
                    db=self.db,
                    reports_dir=reports_dir,
                    task_id=task_id,
                    noise_profile=noise_profile,
                    max_task_tokens=max_task_tokens,
                    max_task_turns=max_task_turns,
                    max_intent_tokens=max_intent_tokens,
                    max_intent_turns=eff_intent_turns,
                    arbiter=mt_arbiter,
                    approval_gate=gate,
                    strict_poe=strict_poe,
                    proxy_config=proxy_cfg,
                    workers=1,
                )

                ep_list = list(endpoints or [])
                if target_route not in ep_list:
                    ep_list.insert(0, target_route)
                engine.ingest_target_infrastructure(
                    host=clean_host,
                    port=resolved_port,
                    endpoints=ep_list,
                    ai_sinks=list(ai_sinks or ["/api/chat"]),
                )
                if args.get("findings") is not None:
                    if not isinstance(args["findings"], list):
                        raise ValueError("Parameter 'findings' must be a list of finding objects.")
                    engine.ingest_findings(args["findings"], scanner="mcp_input")

                registry = LiveWorkerExecutorRegistry(
                    host=clean_host,
                    port=resolved_port,
                    use_tls=resolved_tls,
                    authorized=bool(authorized or is_explicit_loopback_host(clean_host)),
                    traffic_session=engine.traffic_session,
                    approval_gate=gate,
                    noise_governor=engine.noise_governor,
                    auth_profiles=loaded_profiles,
                    arbiter=mt_arbiter,
                    budget_ledger=engine.budget_ledger,
                    trace_store=engine.trace_store,
                    boundary=engine.boundary,
                    asset_graph=engine.asset_graph,
                    workspace_root=self._resolve_mcp_workspace_root(args),
                )
                mt_fn = registry.as_multiturn_executor_fn(
                    max_turns=(eff_intent_turns if eff_intent_turns > 0 else None),
                    budget_ledger=engine.budget_ledger,
                    trace_store=engine.trace_store,
                    boundary=engine.boundary,
                    asset_graph=engine.asset_graph,
                    worker_id=worker_id,
                )

                verified = False
                with _suppress_stdout_to_stderr():
                    if args.get("findings"):
                        cycle_res = engine.run_attack_chain_cycle(round_num=1, executor_fn=mt_fn)
                        verified = bool(cycle_res.get("exploits_verified", 0) > 0)
                    else:
                        ep_nodes = engine.asset_graph.find_endpoints_by_type("ENDPOINT")
                        anchor = next(
                            (n for n in ep_nodes if n.attributes.get("route") == target_route),
                            ep_nodes[0] if ep_nodes else None,
                        )
                        cand_id = f"CAND-MCP-{secrets.token_hex(4)}"
                        cand = engine.exploration_graph.add_intent(
                            node_id=cand_id,
                            node_type="CANDIDATE_INTENT",
                            label=f"MCP Multi-Turn {attack_type} on {method} {target_route}",
                            anchored_asset_id=anchor.node_id if anchor else None,
                            status="PENDING",
                            attributes={
                                "target_host": clean_host,
                                "target_port": resolved_port,
                                "target_route": target_route,
                                "route": target_route,
                                "attack_type": attack_type,
                                "method": method,
                                "hop_count": 1,
                                "source_scanners": ["mcp_multiturn"],
                            },
                        )
                        verified = bool(engine.worker.execute_candidate(cand, executor_fn=mt_fn, worker_id=worker_id))
                        engine.prove_goal()

                traces = self.db.list_worker_traces(task_id=engine.task_id, limit=50)
                chains = engine.export_attack_chains_to_sarif_findings()
                intent_turns = (
                    sum(int(v.get("turns", 0)) for v in engine.budget_ledger._intent_usage.values())
                    or int(engine.budget_ledger.used_turns)
                )
                return {
                    "status": "completed",
                    "task_id": engine.task_id,
                    "target": target_url,
                    "target_route": target_route,
                    "attack_type": attack_type,
                    "verified": verified,
                    "turns_executed": int(intent_turns),
                    "used_turns": int(intent_turns),
                    "intent_turns_used": int(intent_turns),
                    "used_tokens": int(engine.budget_ledger.used_tokens),
                    "worker_traces_count": len(traces),
                    "traces": traces,
                    "chains_synthesized": len(chains),
                    "chains": chains,
                }
            finally:
                if mt_arbiter is not None and hasattr(mt_arbiter, "close"):
                    try:
                        mt_arbiter.close()
                    except Exception:
                        pass

        elif name in ("external_httpx_discover", "external_katana_crawl", "external_nuclei_scan"):
            self._reject_shell_execution(args)
            from engine.dual_graph_engine import AssetGraph, DualGraphAttackEngine, NoiseGovernor
            from engine.external_scanners import (
                DEFAULT_NUCLEI_TAGS,
                ExternalScannerConfig,
                _normalize_nuclei_severities,
                _normalize_nuclei_tags,
                _validate_extra_flags,
                run_opt_in_external_discovery,
                run_opt_in_nuclei_scan,
            )
            from engine.safe_network_validator import is_explicit_loopback_host

            raw_host = self._parse_strict_str(args, "host", "127.0.0.1") or "127.0.0.1"
            port = self._parse_strict_int(args, "port", None, min_val=1, max_val=65535)
            use_tls = self._parse_strict_bool(args, "use_tls", None)
            if use_tls is None and "tls" in args:
                use_tls = self._parse_strict_bool(args, "tls", None)
            authorized = bool(self._parse_strict_bool(args, "authorized", False))
            enabled = bool(self._parse_strict_bool(args, "enabled", False))
            execution_mode = self._parse_strict_str(args, "execution_mode", "host") or "host"
            if execution_mode not in ("host", "docker"):
                raise ValueError(f"Unsupported execution_mode {execution_mode!r}; expected 'host' or 'docker'.")
            docker_image = self._parse_strict_str(args, "docker_image", None)
            docker_network = self._parse_strict_str(args, "docker_network", None)
            binary_path = self._parse_strict_str(args, "binary_path", None)
            rate_limit = self._parse_strict_int(args, "rate_limit", None, min_val=1, max_val=150)
            timeout_sec = float(self._parse_strict_float(args, "timeout_sec", 120.0, min_val=0.1, max_val=1800.0) or 120.0)
            threads = self._parse_strict_int(args, "threads", None, min_val=1, max_val=50)
            noise_profile = (self._parse_strict_str(args, "noise_profile", "off") or "off").strip().lower()
            if noise_profile not in ("off", "quiet", "balanced", "aggressive"):
                raise ValueError(f"Unsupported noise_profile: {noise_profile!r}")
            extra_flags = self._parse_str_list(args, "extra_flags", None)

            max_depth = int(self._parse_strict_int(args, "max_depth", 2, min_val=1, max_val=5) or 2)
            crawl_duration_sec = int(self._parse_strict_int(args, "crawl_duration_sec", 30, min_val=1, max_val=600) or 30)
            js_crawl = bool(self._parse_strict_bool(args, "js_crawl", True))

            raw_tags_param = args.get("tags")
            raw_nuclei_tags_param = args.get("nuclei_tags")
            if raw_tags_param is not None and raw_nuclei_tags_param is not None:
                try:
                    _normalize_nuclei_tags(raw_nuclei_tags_param)
                except TypeError as te:
                    raise ValueError(str(te)) from te
            raw_tags = raw_tags_param if raw_tags_param is not None else raw_nuclei_tags_param
            try:
                norm_tags = _normalize_nuclei_tags(raw_tags) if raw_tags is not None else DEFAULT_NUCLEI_TAGS
            except TypeError as te:
                raise ValueError(str(te)) from te
            raw_sev = args.get("severity")
            try:
                norm_sevs = _normalize_nuclei_severities(raw_sev) if raw_sev is not None else ("info", "low", "medium")
            except TypeError as te:
                raise ValueError(str(te)) from te
            task_id = self._parse_strict_str(args, "task_id", None)

            clean_host, resolved_port, resolved_tls = self._authorize_mcp_target(
                raw_host,
                port=port,
                use_tls=use_tls,
                authorized=authorized,
            )
            fmt_host = f"[{clean_host}]" if ":" in clean_host and not clean_host.startswith("[") else clean_host
            if "://" in raw_host:
                parsed_raw = urlparse(raw_host.strip())
                path_part = parsed_raw.path or ""
                query_part = f"?{parsed_raw.query}" if parsed_raw.query else ""
                scheme = "https" if resolved_tls else "http"
                try:
                    has_inline_port = parsed_raw.port is not None
                except ValueError:
                    has_inline_port = False
                include_port = (
                    has_inline_port
                    or port is not None
                    or (resolved_tls and resolved_port != 443)
                    or (not resolved_tls and resolved_port != 80)
                )
                authority = f"{fmt_host}:{resolved_port}" if include_port else fmt_host
                target_url = f"{scheme}://{authority}{path_part}{query_part}"
            else:
                target_url = f"{'https' if resolved_tls else 'http'}://{fmt_host}:{resolved_port}"

            cfg = ExternalScannerConfig(
                enabled=enabled,
                execution_mode=execution_mode,
                docker_image=docker_image,
                docker_network=docker_network,
                binary_path=binary_path,
                rate_limit=rate_limit,
                timeout_sec=timeout_sec,
                max_depth=max_depth,
                crawl_duration_sec=crawl_duration_sec,
                js_crawl=js_crawl,
                nuclei_tags=norm_tags,
                nuclei_severity=norm_sevs,
                threads=threads,
            )

            if not enabled:
                with _suppress_stdout_to_stderr():
                    if name == "external_nuclei_scan":
                        return run_opt_in_nuclei_scan(target_url, config=cfg)
                    return run_opt_in_external_discovery(
                        target_url,
                        config=cfg,
                        run_httpx=(name == "external_httpx_discover"),
                        run_katana=(name == "external_katana_crawl"),
                    )

            tool_key = (
                "httpx"
                if name == "external_httpx_discover"
                else ("katana" if name == "external_katana_crawl" else "nuclei")
            )
            if extra_flags is not None:
                try:
                    _validate_extra_flags(extra_flags, tool_name=tool_key)
                except TypeError as te:
                    raise ValueError(str(te)) from te

            gate = self._build_mcp_approval_gate(
                args,
                task_id or f"MCP-{tool_key.upper()}",
                workspace_root=self._resolve_mcp_workspace_root(args),
            )
            governor = NoiseGovernor(profile=noise_profile)
            eff_auth = bool(authorized or is_explicit_loopback_host(clean_host))

            with _suppress_stdout_to_stderr():
                if name == "external_nuclei_scan":
                    eng = DualGraphAttackEngine(
                        db=self.db,
                        task_id=task_id,
                        noise_profile=noise_profile,
                        approval_gate=gate,
                    )
                    eng.asset_graph.hydrate_from_database(self.db)
                    return run_opt_in_nuclei_scan(
                        target_url,
                        config=cfg,
                        dual_graph_engine=eng,
                        authorized=eff_auth,
                        approval_gate=gate,
                        noise_governor=governor,
                        extra_flags=extra_flags,
                    )

                ag = AssetGraph(db=self.db)
                ag.hydrate_from_database(self.db)
                return run_opt_in_external_discovery(
                    target_url,
                    config=cfg,
                    asset_graph=ag,
                    authorized=eff_auth,
                    approval_gate=gate,
                    noise_governor=governor,
                    run_httpx=(name == "external_httpx_discover"),
                    run_katana=(name == "external_katana_crawl"),
                    extra_flags=extra_flags,
                )

        elif name == "artex_list_worker_traces":
            limit = int(self._parse_strict_int(args, "limit", 50, min_val=1, allow_none=False) or 50)
            return {
                "traces": self.db.list_worker_traces(
                    task_id=args.get("task_id"),
                    worker_id=args.get("worker_id"),
                    intent_id=args.get("intent_id"),
                    limit=limit,
                )
            }

        elif name == "artex_get_worker_trace":
            trace_id = self._parse_strict_str(args, "trace_id", None)
            if not trace_id:
                raise ValueError("Parameter 'trace_id' is required and must be a non-empty string.")
            tr = self.db.get_worker_trace(trace_id)
            return tr or {"error": f"Worker trace '{trace_id}' not found."}

        elif name == "artex_search_worker_traces":
            limit = int(self._parse_strict_int(args, "limit", 25, min_val=1, allow_none=False) or 25)
            hits = self.db.search_all_worker_traces(
                query=str(args.get("query", "")),
                task_id=args.get("task_id"),
                limit=limit,
            )
            return {"query": args.get("query", ""), "matches": len(hits), "traces": hits}

        elif name == "artex_get_attack_chains":
            limit = int(self._parse_strict_int(args, "limit", 50, min_val=1, allow_none=False) or 50)
            chains = self.db.get_attack_chains(
                limit=limit,
                task_id=args.get("task_id"),
            )
            return {"count": len(chains), "chains": chains}

        elif name == "artex_retest_chain":
            from engine.artex_bridge import TrafficCaptureSession
            from engine.dual_graph_engine import ArtexRetester

            chain_id = self._parse_strict_str(args, "chain_id", None)
            if not chain_id:
                raise ValueError("Parameter 'chain_id' is required and must be a non-empty string.")
            target_chain = self.db.get_attack_chain(chain_id)
            if target_chain is None:
                return {"error": f"Attack chain '{chain_id}' not found."}
            retester = ArtexRetester(db=self.db, traffic_session=TrafficCaptureSession(db=self.db))
            return retester.retest_chain(
                target_chain,
                conditions=str(args.get("conditions", "")),
                auto_mark_fixed=bool(args.get("auto_mark_fixed", True)),
                live=bool(args.get("live", False)),
                authorized=bool(args.get("authorized", False)),
            )

        elif name == "artex_import_surface":
            from engine.artex_bridge import TrafficCaptureSession
            from engine.dual_graph_engine import AssetGraph
            from engine.session_loader import (
                import_har_file,
                import_openapi_spec,
                load_scope_file,
            )

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            loaded_scope = None
            if args.get("scope_path"):
                validated_scope_path = self._validate_mcp_scan_path(
                    args["scope_path"],
                    workspace_root=explicit_ws_root,
                    allow_directory=False,
                )
                loaded_scope = load_scope_file(validated_scope_path)
            ag = AssetGraph(
                db=self.db,
                scope_hosts=set(loaded_scope.get("allow_hosts") or []) or None if loaded_scope else None,
                deny_hosts=set(loaded_scope.get("deny_hosts") or []) if loaded_scope else None,
                deny_routes=list(loaded_scope.get("deny_routes") or []) if loaded_scope else None,
            )
            ts = TrafficCaptureSession(db=self.db, task_id=args.get("task_id") or "MCP-SURFACE")
            out: Dict[str, Any] = {}
            if loaded_scope is not None:
                out["scope"] = loaded_scope
            if args.get("openapi_path"):
                validated_openapi_path = self._validate_mcp_scan_path(
                    args["openapi_path"],
                    workspace_root=explicit_ws_root,
                    allow_directory=False,
                )
                out["openapi"] = import_openapi_spec(
                    validated_openapi_path,
                    asset_graph=ag,
                    default_host=str(args.get("host") or "127.0.0.1"),
                    default_port=int(args.get("port") or 443),
                )
            if args.get("har_path"):
                validated_har_path = self._validate_mcp_scan_path(
                    args["har_path"],
                    workspace_root=explicit_ws_root,
                    allow_directory=False,
                )
                har_res = import_har_file(validated_har_path, asset_graph=ag, traffic_session=ts)
                out["har"] = {k: v for k, v in har_res.items() if k != "extracted_auth_headers"}
                out["har"]["auth_headers_found"] = har_res.get("auth_headers_found", [])
            out["total_assets_ingested"] = len(ag.nodes)
            return out

        elif name == "artex_export_advisory":
            from pathlib import Path as _Path
            from engine.advisory_exporter import AdvisoryExporter, _safe_filename

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            explicit_out_ws = self._has_explicit_output_confinement(args)
            raw_out_dir = self._parse_strict_str(args, "output_dir", "reports/advisories") or "reports/advisories"
            out_dir = _Path(
                self._validate_mcp_output_dir(
                    raw_out_dir,
                    workspace_root=explicit_ws_root,
                    enforce_explicit_ws=explicit_out_ws,
                )
            )
            raw_archive_path = self._parse_strict_str(args, "archive_path", None)
            validated_archive_path = (
                self._validate_mcp_output_dir(
                    raw_archive_path,
                    workspace_root=explicit_ws_root,
                    enforce_explicit_ws=explicit_out_ws,
                    allow_directory=False,
                )
                if raw_archive_path is not None
                else None
            )
            exporter = AdvisoryExporter(reports_dir=out_dir)
            if args.get("chain_id"):
                ch = self.db.get_attack_chain(str(args["chain_id"]), task_id=args.get("task_id"))
                chains = [ch] if ch is not None else []
            else:
                chains = self.db.get_attack_chains(limit=100, task_id=args.get("task_id"))
            advisories: List[str] = []
            for ch in chains:
                cid = str(ch.get("chain_id") or "CHAIN")
                trec = self.db.get_traffic_evidence(ch["traffic_id"]) if ch.get("traffic_id") else None
                rtests = self.db.get_chain_retests(chain_id=cid)
                out_md = out_dir / f"advisory_{_safe_filename(cid)}.md"
                exporter.export_ghsa_markdown(ch, traffic_record=trec, retests=rtests, output_path=out_md)
                advisories.append(str(out_md))
            resp: Dict[str, Any] = {"advisories_exported": len(advisories), "files": advisories}
            if args.get("export_csv"):
                findings = self.db.get_mantis_findings(limit=500) if hasattr(self.db, "get_mantis_findings") else []
                csv_path = out_dir / "findings_and_chains.csv"
                exporter.export_findings_csv(findings, chains=chains, output_path=csv_path)
                resp["csv_path"] = str(csv_path)
            if validated_archive_path is not None:
                resp["archive"] = exporter.export_task_archive(
                    self.db,
                    validated_archive_path,
                    task_id=args.get("task_id"),
                    secret_box=getattr(self.db, "secret_box", None),
                )
            return resp

        elif name == "artex_approval_history":
            limit = int(self._parse_strict_int(args, "limit", 100, min_val=1, allow_none=False) or 100)
            decisions = self.db.get_approval_decisions(limit=limit)
            return {"count": len(decisions), "decisions": decisions}

        elif name == "artex_budget_status":
            task_id = self._parse_strict_str(args, "task_id", None)
            if not task_id:
                raise ValueError("Parameter 'task_id' is required and must be a non-empty string.")
            usage = self.db.get_task_llm_usage(task_id)
            return {"task_id": task_id, "usage": usage}

        elif name == "artex_coverage_report":
            task_id = args.get("task_id")
            assets = self.db.get_dual_graph_nodes(graph_type="ASSET")
            anchors = self.db.get_exploration_anchors(task_id=task_id)
            anchored_assets = {a["asset_id"] for a in anchors}
            tested = [a for a in assets if a["node_id"] in anchored_assets]
            total = len(assets)
            return {
                "task_id": task_id or "all",
                "total_assets": total,
                "tested_assets": len(tested),
                "untested_assets": max(0, total - len(tested)),
                "coverage_pct": round((len(tested) / total) * 100.0, 1) if total > 0 else 0.0,
                "anchors_count": len(anchors),
                "anchors": anchors[:200],
            }

        elif name == "artex_headless_task":
            from engine.artex_bridge import ArtexRestClient

            action = str(args.get("action", "health")).lower()
            client = ArtexRestClient(
                base_url=args.get("artex_url"),
                token=args.get("artex_token"),
                authorized=bool(args.get("authorized", False)),
            )
            if action == "health":
                return client.health_check()
            elif action == "create_task":
                return client.create_task(
                    name=str(args.get("name") or "RFCHunt-MCP-Task"),
                    goal=str(args.get("goal") or "Autonomous attack chain assessment"),
                    targets=list(args.get("targets") or []),
                    llm_profile_ids=args.get("llm_profile_ids"),
                    llm_rotate=args.get("llm_rotate"),
                )
            elif action == "get_task":
                return client.get_task(str(args["task_id"]))
            elif action == "list_tasks":
                return client.list_tasks()
            elif action == "update_llm":
                return client.update_task_llm(
                    str(args["task_id"]),
                    llm_profile_ids=list(args.get("llm_profile_ids") or []),
                    llm_rotate=args.get("llm_rotate"),
                )
            elif action == "ingest_traffic":
                return client.ingest_traffic_batch(
                    exchanges=list(args.get("exchanges") or []),
                    task_id=args.get("task_id"),
                )
            elif action == "get_findings":
                return {"findings": client.get_task_findings(str(args["task_id"]))}
            elif action == "stream_events":
                events = client.stream_task_events(
                    str(args["task_id"]),
                    timeout_sec=float(args.get("timeout_sec", 15.0)),
                )
                return {"count": len(events), "events": [e.to_dict() for e in events]}
            elif action == "register_mcp":
                return client.register_mcp_server(
                    name=str(args.get("mcp_name") or "rfchunt-mcp"),
                    url=str(args.get("mcp_url") or "http://127.0.0.1:8790/http"),
                    transport=str(args.get("mcp_transport") or "http"),
                    bearer_token=args.get("mcp_token"),
                )
            raise ValueError(f"Unsupported artex_headless_task action: {action}")

        elif name == "mantis_scan":
            from engine.mantis_integrator import DEFAULT_ABLITERATED_MODEL, MantisIntegrator

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            raw_target = str(args.get("target_path") or args.get("repo") or args.get("path") or ".")
            resolved = self._validate_mcp_scan_path(
                raw_target, workspace_root=explicit_ws_root, allow_directory=True
            )
            if not os.path.exists(resolved):
                return {"error": f"Target path does not exist: {resolved}"}
            raw_out_dir = self._parse_strict_str(args, "output_dir", "reports") or "reports"
            validated_out_dir = self._validate_mcp_output_dir(
                raw_out_dir,
                workspace_root=explicit_ws_root,
                enforce_explicit_ws=self._has_explicit_output_confinement(args),
            )

            integrator = MantisIntegrator(
                db=self.db,
                reports_dir=validated_out_dir,
                use_fusion=True,
                preferred_model=DEFAULT_ABLITERATED_MODEL,
            )
            return integrator.run_scan(
                target_path=resolved,
                depth=int(args.get("depth", 30)),
                mode=str(args.get("mode", "full")),
            )

        elif name == "rea_analyze_surface":
            self._reject_shell_execution(args)
            from engine.dual_graph_engine import NoiseGovernor
            from engine.rea_integrator import ReaIntegrator
            from engine.safe_network_validator import is_explicit_loopback_host

            target_path = self._parse_strict_str(args, "target_path", None)
            if target_path is None:
                target_path = self._parse_strict_str(args, "path", None) or self._parse_strict_str(args, "repo", None)
            raw_host = self._parse_strict_str(args, "host", None)
            port = self._parse_strict_int(args, "port", None, min_val=1, max_val=65535)
            use_tls = bool(self._parse_strict_bool(args, "use_tls", False))
            authorized = bool(self._parse_strict_bool(args, "authorized", False))
            use_rea_cli = bool(
                self._parse_strict_bool(args, "use_rea_cli", False)
                or self._parse_strict_bool(args, "rea_cli", False)
            )
            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            reports_dir = self._validate_mcp_output_dir(
                self._parse_strict_str(args, "output_dir", "reports") or "reports",
                workspace_root=explicit_ws_root,
                enforce_explicit_ws=self._has_explicit_output_confinement(args),
            )
            noise_profile = self._parse_strict_str(args, "noise_profile", "off") or "off"

            if not target_path and not raw_host:
                target_path = "."
            if target_path is not None:
                target_path = self._validate_mcp_scan_path(
                    target_path,
                    workspace_root=explicit_ws_root,
                    allow_directory=True,
                )

            clean_host = None
            resolved_port = None
            resolved_tls = use_tls
            if raw_host is not None:
                clean_host, resolved_port, resolved_tls = self._authorize_mcp_target(
                    raw_host,
                    port=port,
                    use_tls=use_tls,
                    authorized=authorized,
                )
            else:
                TargetAuthorizationGate.check_rate_limit()

            eff_rea_ws = explicit_ws_root
            if eff_rea_ws is None and target_path is not None:
                eff_rea_ws = Path(target_path) if os.path.isdir(target_path) else Path(target_path).parent
            gate = self._build_mcp_approval_gate(args, "MCP-REA-SURFACE", workspace_root=eff_rea_ws)
            integrator = ReaIntegrator(
                db=self.db,
                reports_dir=reports_dir,
                approval_gate=gate,
                noise_governor=NoiseGovernor(profile=noise_profile),
                workspace_root=explicit_ws_root,
            )
            res_obj = integrator.analyze(
                target_path=target_path,
                host=clean_host,
                port=resolved_port,
                use_tls=resolved_tls,
                authorized=bool(authorized or (clean_host and is_explicit_loopback_host(clean_host))),
                use_rea_cli=use_rea_cli,
                write_reports=True,
                workspace_root=explicit_ws_root,
            )
            out = res_obj.to_dict()
            out["total_findings"] = len(out.get("findings") or [])
            out["total_endpoints"] = len(out.get("discovered_endpoints") or [])
            return out

        elif name == "rfchunt_provision_tools":
            self._reject_shell_execution(args)
            from engine.tool_provisioner import ToolProvisioner

            install_missing = bool(self._parse_strict_bool(args, "install_missing", False))
            include_docker = bool(self._parse_strict_bool(args, "include_docker", True))
            include_models = bool(self._parse_strict_bool(args, "include_models", True))
            force = bool(self._parse_strict_bool(args, "force", False))
            raw_tools = args.get("tools")
            tool_ids: Optional[List[str]] = None
            if raw_tools is not None:
                if not isinstance(raw_tools, list) or not all(isinstance(x, str) for x in raw_tools):
                    raise ValueError("'tools' must be a list of tool ID strings.")
                tool_ids = [str(x).strip() for x in raw_tools if str(x).strip()]

            prov = ToolProvisioner()
            if install_missing and not prov.is_offline_or_blocked():
                return prov.ensure_all(
                    tool_ids=tool_ids,
                    include_docker=include_docker,
                    include_models=include_models,
                    force=force,
                )
            statuses = prov.check_all_statuses(tool_ids=tool_ids)
            return {
                "offline_or_test_mode": prov.is_offline_or_blocked(),
                "total": len(statuses),
                "installed_count": sum(1 for s in statuses.values() if s.installed),
                "tools": {k: v.to_dict() for k, v in statuses.items()},
            }

        elif name == "inject_blackboard_hint":
            self._reject_shell_execution(args)
            hint_text = self._parse_strict_str(args, "hint_text", None, allow_empty=False)
            if hint_text is None:
                raise ValueError("Parameter 'hint_text' is required and must be a non-empty string.")
            domain_raw = self._parse_strict_str(args, "domain", "global", allow_empty=False)
            domain = (domain_raw or "global").strip()
            priority = float(self._parse_strict_float(args, "priority", 10.0))
            task_id_raw = self._parse_strict_str(args, "task_id", "default", allow_empty=False)
            task_id = (task_id_raw or "default").strip()
            rfc_num = (self._parse_strict_str(args, "rfc_num", "", allow_empty=True) or "").strip()
            source_raw = self._parse_strict_str(args, "source", "mcp", allow_empty=False)
            source = (source_raw or "mcp").strip()
            active = bool(self._parse_strict_bool(args, "active", True))

            node_id = self.db.add_hint(
                hint_text,
                priority=priority,
                task_id=task_id,
                domain=domain,
                rfc_id=rfc_num,
                source_agent=source,
                active=active,
            )
            return {
                "status": "injected",
                "node_id": node_id,
                "node_type": "HINT",
                "domain": domain,
                "priority": priority,
                "active": active,
            }

        elif name == "arxiv_discover_and_convert_security_research":
            self._reject_shell_execution(args)
            from engine.arxiv_security_bridge import ArxivSecurityBridge

            query = self._parse_strict_str(
                args,
                "query",
                "LLM agent sandbox escape prompt injection static taint analysis",
                allow_empty=True,
            ) or "LLM agent sandbox escape prompt injection static taint analysis"
            domain = self._parse_strict_str(args, "domain", "both", allow_empty=False) or "both"
            research_num = int(
                self._parse_strict_int(args, "research_num", 5, min_val=1, max_val=25) or 5
            )
            require_code_repo = bool(self._parse_strict_bool(args, "require_code_repo", True))
            evolve = bool(self._parse_strict_bool(args, "evolve", True))
            use_rl = bool(self._parse_strict_bool(args, "use_rl", False))
            verify_panel = bool(self._parse_strict_bool(args, "verify_panel", False))
            panel_size = int(self._parse_strict_int(args, "panel_size", 2, min_val=2, max_val=7) or 2)
            auto_repair = bool(self._parse_strict_bool(args, "auto_repair", True))
            max_repair_attempts = int(
                self._parse_strict_int(args, "max_repair_attempts", 3, min_val=1, max_val=10) or 3
            )
            bridge = ArxivSecurityBridge(research_num=research_num)
            return bridge.discover_and_convert_research(
                query=query,
                domain=domain,
                research_num=research_num,
                require_code_repo=require_code_repo,
                evolve=evolve,
                use_rl=use_rl,
                verify_panel=verify_panel,
                panel_size=panel_size,
                auto_repair=auto_repair,
                max_repair_attempts=max_repair_attempts,
                enable_llm=verify_panel,
            )

        elif name == "verify_and_auto_repair_python_code":
            self._reject_shell_execution(args)
            from engine.arxiv_security_bridge import ArxivSecurityBridge

            src_code = self._parse_strict_str(args, "python_source_code", "", allow_empty=False) or ""
            arxiv_id = self._parse_strict_str(args, "arxiv_id", "custom", allow_empty=True) or "custom"
            title = (
                self._parse_strict_str(args, "title", "Generated Security Detector Module", allow_empty=True)
                or "Generated Security Detector Module"
            )
            use_panel = bool(self._parse_strict_bool(args, "use_panel", False))
            panel_size = int(self._parse_strict_int(args, "panel_size", 2, min_val=2, max_val=7) or 2)
            auto_repair = bool(self._parse_strict_bool(args, "auto_repair", True))
            max_repair_attempts = int(
                self._parse_strict_int(args, "max_repair_attempts", 3, min_val=1, max_val=10) or 3
            )
            enable_llm = bool(self._parse_strict_bool(args, "enable_llm", False))
            bridge = ArxivSecurityBridge()
            return bridge.verify_and_repair_code(
                source_code=src_code,
                arxiv_id=arxiv_id,
                title=title,
                use_panel=use_panel,
                panel_size=panel_size,
                auto_repair=auto_repair,
                max_repair_attempts=max_repair_attempts,
                enable_llm=enable_llm,
            )

        elif name == "run_arxiv_ai_security_detectors":
            self._reject_shell_execution(args)
            from engine.arxiv_security_bridge import ArxivSecurityBridge

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            repo_path = self._validate_mcp_scan_path(
                self._parse_strict_str(args, "repo_path", ".", allow_empty=False) or ".",
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            research_num = int(
                self._parse_strict_int(args, "research_num", 5, min_val=1, max_val=25) or 5
            )
            bridge = ArxivSecurityBridge(research_num=research_num)
            return bridge.scan_repository(
                repo_path=repo_path,
                domain="AI_SECURITY",
                research_num=research_num,
            )

        elif name == "run_arxiv_appsec_code_detectors":
            self._reject_shell_execution(args)
            from engine.arxiv_security_bridge import ArxivSecurityBridge

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            repo_path = self._validate_mcp_scan_path(
                self._parse_strict_str(args, "repo_path", ".", allow_empty=False) or ".",
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            research_num = int(
                self._parse_strict_int(args, "research_num", 5, min_val=1, max_val=25) or 5
            )
            bridge = ArxivSecurityBridge(research_num=research_num)
            return bridge.scan_repository(
                repo_path=repo_path,
                domain="APP_CODE_SECURITY",
                research_num=research_num,
            )

        elif name == "run_all_arxiv_research_detectors":
            self._reject_shell_execution(args)
            from engine.arxiv_security_bridge import ArxivSecurityBridge

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            repo_path = self._validate_mcp_scan_path(
                self._parse_strict_str(args, "repo_path", ".", allow_empty=False) or ".",
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            sync_new_query = self._parse_strict_str(args, "sync_new_query", "", allow_empty=True) or ""
            research_num = int(
                self._parse_strict_int(args, "research_num", 5, min_val=1, max_val=25) or 5
            )
            bridge = ArxivSecurityBridge(research_num=research_num)
            return bridge.scan_repository(
                repo_path=repo_path,
                domain="both",
                sync_new_research=bool(sync_new_query.strip()),
                arxiv_query=sync_new_query,
                research_num=research_num,
            )

        elif name == "list_active_arxiv_research_detectors":
            self._reject_shell_execution(args)
            from engine.arxiv_security_bridge import ArxivSecurityBridge

            domain = self._parse_strict_str(args, "domain", "all", allow_empty=True) or "all"
            bridge = ArxivSecurityBridge()
            detectors = bridge.list_active_detectors(domain=domain)
            return {
                "status": "completed",
                "domain": domain,
                "total_detectors": len(detectors),
                "detectors": detectors,
            }

        elif name == "last30days_discover_security_skills":
            self._reject_shell_execution(args)
            from engine.last30days_security_skills import Last30DaysSecuritySkillsEngine

            topic = self._parse_strict_str(
                args,
                "topic",
                "AI security prompt injection bug bounty pentesting",
                allow_empty=True,
            ) or "AI security prompt injection bug bounty pentesting"
            domain = self._parse_strict_str(args, "domain", "both", allow_empty=False) or "both"
            research_num = int(
                self._parse_strict_int(args, "research_num", 5, min_val=1, max_val=25) or 5
            )
            skills_num_arg = self._parse_strict_int(args, "skills_num", None, min_val=1, max_val=25)
            eff_sk_num = int(skills_num_arg) if skills_num_arg is not None else research_num
            days = int(self._parse_strict_int(args, "days", 30, min_val=1, max_val=365) or 30)
            emit_skill_md = bool(self._parse_strict_bool(args, "emit_skill_md", True))
            engine = Last30DaysSecuritySkillsEngine(research_num=eff_sk_num, skills_num=eff_sk_num)
            return engine.discover_and_build_security_skills(
                topic=topic,
                domain=domain,
                research_num=eff_sk_num,
                skills_num=eff_sk_num,
                days=days,
                emit_skill_md=emit_skill_md,
            )

        elif name == "run_last30days_security_skills":
            self._reject_shell_execution(args)
            from engine.last30days_security_skills import Last30DaysSecuritySkillsEngine

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            repo_path = self._validate_mcp_scan_path(
                self._parse_strict_str(args, "repo_path", ".", allow_empty=False) or ".",
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            domain = self._parse_strict_str(args, "domain", "both", allow_empty=False) or "both"
            sync_online = bool(self._parse_strict_bool(args, "sync_online", False))
            topic = self._parse_strict_str(args, "topic", "", allow_empty=True) or ""
            research_num = int(
                self._parse_strict_int(args, "research_num", 5, min_val=1, max_val=25) or 5
            )
            skills_num_arg = self._parse_strict_int(args, "skills_num", None, min_val=1, max_val=25)
            eff_sk_num = int(skills_num_arg) if skills_num_arg is not None else research_num
            engine = Last30DaysSecuritySkillsEngine(research_num=eff_sk_num, skills_num=eff_sk_num)
            return engine.scan_repository(
                repo_path=repo_path,
                domain=domain,
                sync_online=sync_online,
                topic=topic,
                research_num=eff_sk_num,
                skills_num=eff_sk_num,
            )

        elif name == "audit_agent_skill_package":
            self._reject_shell_execution(args)
            from engine.last30days_security_skills import Last30DaysSecuritySkillsEngine

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            skill_path = self._validate_mcp_scan_path(
                self._parse_strict_str(args, "skill_or_repo_path", ".", allow_empty=False) or ".",
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            engine = Last30DaysSecuritySkillsEngine()
            return engine.audit_agent_skill_package(skill_path)

        elif name == "list_active_last30days_security_skills":
            self._reject_shell_execution(args)
            from engine.last30days_security_skills import Last30DaysSecuritySkillsEngine

            domain = self._parse_strict_str(args, "domain", "all", allow_empty=True) or "all"
            engine = Last30DaysSecuritySkillsEngine()
            skills = engine.list_active_skills(domain=domain)
            return {
                "status": "completed",
                "zero_api_key_invariant_enforced": True,
                "domain": domain,
                "total_skills": len(skills),
                "skills": skills,
            }

        elif name == "run_preflight_discovery":
            self._reject_shell_execution(args)
            from engine.preflight_discovery import run_preflight_discovery

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            target_path = self._parse_strict_str(args, "target_path", ".", allow_empty=True) or None
            if target_path is not None:
                target_path = self._validate_mcp_scan_path(
                    target_path,
                    workspace_root=explicit_ws_root,
                    allow_directory=True,
                )
            prompt = self._parse_strict_str(args, "prompt", "", allow_empty=True) or ""
            policy_text = self._parse_strict_str(args, "policy_text", "", allow_empty=True) or ""
            target_host = self._parse_strict_str(args, "target_host", "", allow_empty=True) or None
            live = bool(self._parse_strict_bool(args, "live", False))
            enable_pqc = bool(self._parse_strict_bool(args, "enable_pqc", True))
            include_home_skills = bool(self._parse_strict_bool(args, "include_home_skills", True))
            dry_run = bool(self._parse_strict_bool(args, "dry_run", False))
            res = run_preflight_discovery(
                target_path=target_path,
                prompt=prompt,
                policy_text=policy_text,
                target_host=target_host,
                live=live,
                enable_pqc=enable_pqc,
                include_home_skills=include_home_skills,
                dry_run=dry_run,
            )
            return {k: v for k, v in res.items() if k != "checklist_markdown"}

        elif name == "run_crlf_conformance_audit":
            self._reject_shell_execution(args)
            from engine.crlf_desync_engine import audit_nginx_configs, run_conformance_diagnostics

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            target_path = self._validate_mcp_scan_path(
                self._parse_strict_str(args, "target_path", ".", allow_empty=True) or ".",
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            host = self._parse_strict_str(args, "host", "", allow_empty=True) or ""
            port = int(self._parse_strict_int(args, "port", 80, min_val=1, max_val=65535) or 80)
            use_tls = bool(self._parse_strict_bool(args, "use_tls", False))
            trials = int(self._parse_strict_int(args, "trials", 3, min_val=3, max_val=10) or 3)
            rep = audit_nginx_configs(target_path)
            if host.strip():
                live_rep = run_conformance_diagnostics(
                    host=host.strip(),
                    port=port,
                    use_tls=use_tls,
                    trials=trials,
                )
                rep.findings.extend(live_rep.findings)
            return rep.to_dict()

        elif name == "run_web_llm_security_audit":
            self._reject_shell_execution(args)
            from engine.web_llm_auditor import audit_web_llm_repository

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            target_path = self._validate_mcp_scan_path(
                self._parse_strict_str(args, "target_path", ".", allow_empty=False) or ".",
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            return audit_web_llm_repository(target_path).to_dict()

        elif name == "run_pe_dotnet_audit":
            self._reject_shell_execution(args)
            from engine.pe_magika_classifier import audit_pe_dotnet_target

            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            raw_target = (
                self._parse_strict_str(args, "target_path", None, allow_empty=False)
                or self._parse_strict_str(args, "path", None, allow_empty=False)
                or self._parse_strict_str(args, "repo", None, allow_empty=False)
                or "."
            )
            target_path = self._validate_mcp_scan_path(
                raw_target,
                workspace_root=explicit_ws_root,
                allow_directory=True,
            )
            include_host_audit = bool(self._parse_strict_bool(args, "include_host_audit", False))
            include_yara = bool(self._parse_strict_bool(args, "include_yara", True))
            return audit_pe_dotnet_target(
                target_path,
                include_host_audit=include_host_audit,
                include_yara=include_yara,
                workspace_root=explicit_ws_root,
            )

        elif name in (
            "run_autonomous_hunt",
            "run_fast_ooda",
            "rank_bounty_programs",
            "sync_hackerone_directory",
            "score_fresh_commits",
            "cluster_recon_assets",
            "analyze_js_bundles",
            "classify_http_responses",
            "qa_bounty_drafts",
            "check_bounty_drafts",
        ):
            self._reject_shell_execution(args)
            from bugbounty_mcp_server import BugBountyMCPServer

            bridge_map = {
                "run_autonomous_hunt": "bb_run_autonomous_hunt",
                "run_fast_ooda": "bb_run_fast_ooda",
                "rank_bounty_programs": "bb_rank_programs",
                "sync_hackerone_directory": "bb_sync_public_directory",
                "score_fresh_commits": "bb_score_fresh_commits",
                "cluster_recon_assets": "bb_cluster_recon_assets",
                "analyze_js_bundles": "bb_analyze_js_bundles",
                "classify_http_responses": "bb_classify_http_responses",
                "qa_bounty_drafts": "bb_qa_drafts",
                "check_bounty_drafts": "bb_check_drafts",
            }
            forwarded_args = dict(args)
            explicit_ws_root = self._resolve_mcp_workspace_root(args)
            if name == "run_autonomous_hunt" and forwarded_args.get("targets"):
                validated_targets: List[str] = []
                for raw_t in forwarded_args["targets"]:
                    validated_targets.append(
                        self._validate_mcp_scan_path(
                            str(raw_t),
                            workspace_root=explicit_ws_root,
                            allow_directory=True,
                        )
                    )
                forwarded_args["targets"] = validated_targets
            elif name == "run_fast_ooda":
                raw_t = self._parse_strict_str(args, "target", ".", allow_empty=False) or "."
                forwarded_args["target"] = self._validate_mcp_scan_path(
                    raw_t,
                    workspace_root=explicit_ws_root,
                    allow_directory=True,
                )
            elif name == "qa_bounty_drafts" and forwarded_args.get("markdown_file"):
                forwarded_args["markdown_file"] = self._validate_mcp_scan_path(
                    str(forwarded_args["markdown_file"]),
                    workspace_root=explicit_ws_root,
                    allow_directory=False,
                )
            elif name == "sync_hackerone_directory" and forwarded_args.get("snapshot_json"):
                forwarded_args["snapshot_json"] = self._validate_mcp_scan_path(
                    str(forwarded_args["snapshot_json"]),
                    workspace_root=explicit_ws_root,
                    allow_directory=False,
                )
            return BugBountyMCPServer()._dispatch_tool(bridge_map[name], forwarded_args)

        raise ValueError(f"Unknown tool: {name}")

    def run_stdio(self) -> None:
        """Runs the JSON-RPC stdio event loop."""
        real_stdout = sys.stdout
        sys.stderr.write("[+] HTTP Terminator MCP Server listening on stdio...\n")
        sys.stderr.flush()

        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                request = json.loads(line_str)
                response = self.handle_request(request)
                if response:
                    real_stdout.write(json.dumps(response) + "\n")
                    real_stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
                real_stdout.write(json.dumps(err_resp) + "\n")
                real_stdout.flush()


class MCPHttpServer:
    """
    Remote MCP Server exposing `TerminatorMCPServer` over BOTH transports supported
    by BaaRai/ARTEX's remote MCP client (`mcphttp`):
    1. Streamable HTTP: `POST /http` (JSON-RPC 2.0 request/response or batch) & `DELETE /http`
    2. Legacy SSE: `GET /sse` (establishes SSE stream and announces `/message?sessionId=<sid>`
       pinned strictly to the configured origin) + `POST /message?sessionId=<sid>`
    3. Health probe: `GET /health`

    Binds to `127.0.0.1` by default and optionally enforces `Authorization: Bearer <token>`.
    """

    def __init__(
        self,
        mcp_server: TerminatorMCPServer,
        host: str = "127.0.0.1",
        port: int = 8790,
        bearer_token: Optional[str] = None,
    ):
        self.mcp_server = mcp_server
        self.host = host or "127.0.0.1"
        self.port = int(port)
        self.bearer_token = bearer_token if bearer_token is not None else os.environ.get("RFCHUNT_MCP_TOKEN")
        self._sessions: Dict[str, "queue.Queue[Optional[str]]"] = {}
        self._sessions_lock = threading.Lock()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _check_auth(self, auth_header: Optional[str]) -> bool:
        if self.bearer_token is None:
            return True
        if not self.bearer_token:
            return False
        if not auth_header or not auth_header.startswith("Bearer "):
            return False
        provided = auth_header[7:].strip()
        return hmac.compare_digest(provided, self.bearer_token)

    def _check_origin(self, origin_header: Optional[str]) -> bool:
        if not origin_header:
            return True
        try:
            parsed = urlparse(origin_header)
            ohost = (parsed.hostname or "").strip("[] ").lower()
        except Exception:
            return False
        if not ohost:
            return False
        allowed = {"127.0.0.1", "localhost", "::1", self.host.strip("[] ").lower()}
        return ohost in allowed

    def _create_session(self) -> Tuple[str, "queue.Queue[Optional[str]]"]:
        sid = secrets.token_hex(16)
        q: "queue.Queue[Optional[str]]" = queue.Queue()
        with self._sessions_lock:
            self._sessions[sid] = q
        return sid, q

    def _remove_session(self, sid: str) -> None:
        with self._sessions_lock:
            self._sessions.pop(sid, None)

    def _push_session_event(self, sid: str, event_name: str, payload: Any) -> bool:
        with self._sessions_lock:
            q = self._sessions.get(sid)
        if q is None:
            return False
        data_str = payload if isinstance(payload, str) else json.dumps(payload)
        q.put(f"event: {event_name}\ndata: {data_str}\n\n")
        return True

    def _build_handler(self):
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send_json(self, status: int, body: Any, extra_headers: Optional[Dict[str, str]] = None) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                has_conn_hdr = False
                if extra_headers:
                    for k, v in extra_headers.items():
                        if str(k).lower() == "connection":
                            has_conn_hdr = True
                        self.send_header(k, v)
                if self.close_connection and not has_conn_hdr:
                    self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

            def _drain_request_body(self, max_bytes: int = 10 * 1024 * 1024) -> bool:
                te_vals = self.headers.get_all("Transfer-Encoding", [])
                if te_vals:
                    return False
                cl_vals = self.headers.get_all("Content-Length", [])
                if not cl_vals:
                    return True
                if len(cl_vals) > 1:
                    return False
                raw_s = str(cl_vals[0]).strip()
                if not (raw_s.isascii() and raw_s.isdigit()):
                    return False
                length = int(raw_s)
                if length < 0 or length > max_bytes:
                    return False
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, 65536))
                    if not chunk:
                        return False
                    remaining -= len(chunk)
                return True

            def _send_error_drained(self, status: int, body: Any) -> None:
                drained = self._drain_request_body()
                extra = None
                if not drained:
                    self.close_connection = True
                    extra = {"Connection": "close"}
                self._send_json(status, body, extra_headers=extra)

            def _require_auth(self) -> bool:
                if not parent._check_origin(self.headers.get("Origin")):
                    self._send_error_drained(403, {"error": "Forbidden Origin header (MCP DNS-rebinding / CSRF guard)"})
                    return False
                if not parent._check_auth(self.headers.get("Authorization")):
                    self._send_error_drained(401, {"error": "Unauthorized: invalid or missing Bearer token"})
                    return False
                return True

            def _read_chunked_body(self, max_bytes: int = 2 * 1024 * 1024) -> Tuple[Optional[bytes], Optional[str]]:
                buf = bytearray()
                max_line = 4096
                max_chunks = 4096
                for _ in range(max_chunks):
                    line = self.rfile.readline(max_line + 1)
                    if not line or len(line) > max_line or not line.endswith(b"\r\n"):
                        self.close_connection = True
                        return None, "Malformed chunked header"
                    size_tok = line[:-2].split(b";", 1)[0]
                    if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", size_tok):
                        self.close_connection = True
                        return None, "Malformed chunked size"
                    chunk_size = int(size_tok, 16)
                    if chunk_size == 0:
                        for _ in range(64):
                            tline = self.rfile.readline(max_line + 1)
                            if not tline or len(tline) > max_line or not tline.endswith(b"\r\n"):
                                self.close_connection = True
                                return None, "Malformed chunked trailer"
                            if tline == b"\r\n":
                                return bytes(buf), None
                        self.close_connection = True
                        return None, "Too many chunked trailers"
                    if len(buf) + chunk_size > max_bytes:
                        self.close_connection = True
                        return None, "Payload exceeds 2 MiB limit"
                    rem = chunk_size
                    while rem > 0:
                        part = self.rfile.read(rem)
                        if not part:
                            self.close_connection = True
                            return None, "Truncated chunked body"
                        buf.extend(part)
                        rem -= len(part)
                    crlf = self.rfile.read(2)
                    if crlf != b"\r\n":
                        self.close_connection = True
                        return None, "Malformed chunk terminator"
                self.close_connection = True
                return None, "Too many chunks"

            def _read_json_body(self) -> Tuple[Optional[Any], Optional[str]]:
                te_vals = self.headers.get_all("Transfer-Encoding", [])
                cl_vals = self.headers.get_all("Content-Length", [])
                if te_vals:
                    if cl_vals:
                        self.close_connection = True
                        return None, "Conflicting Content-Length and Transfer-Encoding headers"
                    te_tokens = [tok.strip().lower() for hdr in te_vals for tok in str(hdr).split(",") if tok.strip()]
                    if te_tokens != ["chunked"]:
                        self.close_connection = True
                        return None, "Unsupported Transfer-Encoding"
                    raw, c_err = self._read_chunked_body(max_bytes=2 * 1024 * 1024)
                    if c_err is not None or raw is None:
                        return None, c_err or "Malformed chunked body"
                else:
                    if len(cl_vals) > 1:
                        self.close_connection = True
                        return None, "Duplicate Content-Length"
                    length = 0
                    if cl_vals:
                        raw_s = str(cl_vals[0]).strip()
                        if not (raw_s.isascii() and raw_s.isdigit()):
                            self.close_connection = True
                            return None, "Invalid Content-Length"
                        length = int(raw_s)
                    if length > 2 * 1024 * 1024:
                        self.close_connection = True
                        return None, "Payload exceeds 2 MiB limit"
                    raw = b""
                    if length > 0:
                        chunks = bytearray()
                        rem = length
                        while rem > 0:
                            part = self.rfile.read(rem)
                            if not part:
                                self.close_connection = True
                                return None, "Truncated JSON body"
                            chunks.extend(part)
                            rem -= len(part)
                        raw = bytes(chunks)
                if not raw:
                    return None, "Empty JSON body"
                try:
                    return json.loads(raw.decode("utf-8")), None
                except Exception as exc:
                    return None, f"Invalid JSON: {exc}"

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    self._send_json(
                        200,
                        {
                            "status": "ok",
                            "server": "http-terminator-mcp",
                            "transports": ["http", "sse"],
                            "endpoints": {"streamable_http": "/http", "legacy_sse": "/sse", "legacy_message": "/message"},
                        },
                    )
                    return

                if not self._require_auth():
                    return

                if parsed.path == "/sse":
                    sid, q = parent._create_session()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.send_header("X-Accel-Buffering", "no")
                    self.end_headers()
                    # Pin legacy SSE message endpoint strictly to relative path on configured origin
                    endpoint_frame = f"event: endpoint\ndata: /message?sessionId={sid}\n\n".encode("utf-8")
                    try:
                        self.wfile.write(endpoint_frame)
                        self.wfile.flush()
                        while not parent._stop_event.is_set():
                            try:
                                msg = q.get(timeout=0.5)
                            except queue.Empty:
                                continue
                            if msg is None:
                                break
                            self.wfile.write(msg.encode("utf-8"))
                            self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass
                    finally:
                        parent._remove_session(sid)
                    return

                self._send_json(404, {"error": f"Not found: {parsed.path}"})

            def do_POST(self) -> None:
                if not self._require_auth():
                    return
                parsed = urlparse(self.path)

                # Streamable HTTP MCP transport (`POST /http` or `POST /mcp`)
                if parsed.path in ("/http", "/mcp"):
                    payload, err = self._read_json_body()
                    if err:
                        extra = {"Connection": "close"} if self.close_connection else None
                        self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": err}}, extra_headers=extra)
                        return

                    if isinstance(payload, list):
                        if len(payload) == 0:
                            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
                            return
                        responses = []
                        for req in payload:
                            if isinstance(req, dict):
                                r = parent.mcp_server.handle_request(req)
                                if r:
                                    responses.append(r)
                            else:
                                responses.append({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
                        result_obj: Any = responses
                    elif isinstance(payload, dict):
                        result_obj = parent.mcp_server.handle_request(payload)
                    else:
                        self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
                        return

                    accept = (self.headers.get("Accept") or "").lower()
                    if "text/event-stream" in accept and "application/json" not in accept:
                        frame = f"event: message\ndata: {json.dumps(result_obj)}\n\n".encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.send_header("Content-Length", str(len(frame)))
                        if self.close_connection:
                            self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(frame)
                        return

                    if not result_obj:
                        self.send_response(202)
                        self.send_header("Content-Length", "0")
                        if self.close_connection:
                            self.send_header("Connection", "close")
                        self.end_headers()
                        return

                    self._send_json(200, result_obj, extra_headers={"Mcp-Session-Id": self.headers.get("Mcp-Session-Id") or secrets.token_hex(8)})
                    return

                # Legacy SSE message endpoint (`POST /message?sessionId=...`)
                if parsed.path == "/message":
                    qs = parse_qs(parsed.query)
                    sid = (qs.get("sessionId") or [""])[0].strip()
                    if not sid:
                        self._send_error_drained(400, {"error": "Missing sessionId query parameter"})
                        return
                    with parent._sessions_lock:
                        has_session = sid in parent._sessions
                    if not has_session:
                        self._send_error_drained(404, {"error": f"Unknown or closed SSE session: {sid}"})
                        return
                    payload, err = self._read_json_body()
                    if err or not isinstance(payload, dict):
                        extra = {"Connection": "close"} if self.close_connection else None
                        self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": err or "Invalid request"}}, extra_headers=extra)
                        return
                    resp = parent.mcp_server.handle_request(payload)
                    if resp:
                        delivered = parent._push_session_event(sid, "message", resp)
                        if not delivered:
                            self._send_json(404, {"error": f"Unknown or closed SSE session: {sid}"})
                            return
                    self._send_json(202, {"status": "accepted", "sessionId": sid})
                    return

                self._send_error_drained(404, {"error": f"Not found: {parsed.path}"})

            def do_DELETE(self) -> None:
                if not self._require_auth():
                    return
                parsed = urlparse(self.path)
                if parsed.path in ("/http", "/mcp"):
                    self.send_response(204)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._send_json(404, {"error": f"Not found: {parsed.path}"})

        return _Handler

    def start(self) -> Tuple[str, int]:
        """Starts the HTTP/SSE MCP server in a background daemon thread."""
        self._stop_event.clear()
        self._httpd = ThreadingHTTPServer((self.host, self.port), self._build_handler())
        self._httpd.daemon_threads = True
        actual_host, actual_port = self._httpd.server_address[:2]
        self.port = int(actual_port)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return str(actual_host), self.port

    def serve_forever(self) -> None:
        host, port = self.start()
        sys.stderr.write(
            f"[+] HTTP Terminator Remote MCP Server listening on http://{host}:{port}\n"
            f"    - Streamable HTTP : http://{host}:{port}/http\n"
            f"    - Legacy SSE      : http://{host}:{port}/sse  (+ /message?sessionId=...)\n"
            f"    - Bearer Auth     : {'ENABLED' if self.bearer_token else 'DISABLED'}\n"
        )
        sys.stderr.flush()
        try:
            while not self._stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop_event.set()
        with self._sessions_lock:
            for q in self._sessions.values():
                q.put(None)
            self._sessions.clear()
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HTTP Terminator MCP Server (stdio / Streamable HTTP / Legacy SSE)")
    parser.add_argument("--db", default="terminator.db", help="SQLite database path")
    parser.add_argument("--transport", choices=["stdio", "http", "sse", "both"], default="stdio", help="MCP transport (default: stdio; 'http'/'sse'/'both' serves /http and /sse for ARTEX)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address for HTTP/SSE MCP server (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8790, help="Port for HTTP/SSE MCP server (default: 8790)")
    parser.add_argument("--token", default=None, help="Optional Bearer token for HTTP/SSE authentication")
    cli_args = parser.parse_args()

    with TerminatorMCPServer(db_path=cli_args.db) as server:
        if cli_args.transport == "stdio":
            server.run_stdio()
        else:
            http_srv = MCPHttpServer(server, host=cli_args.host, port=cli_args.port, bearer_token=cli_args.token)
            http_srv.serve_forever()
