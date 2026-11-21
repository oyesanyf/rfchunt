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
import queue
import secrets
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
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
    def __init__(self, db_path: str = "terminator.db"):
        self.db_path = db_path
        self.db = Database(db_path)
        self.fetcher = RFCFetcher(db=self.db)
        self.permutator = VectorPermutator(db=self.db)
        self.raptor = RaptorIntegrator(db=self.db)

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

    def _build_mcp_approval_gate(self, args: Dict[str, Any], task_id: str):
        from engine.approval_gate import ApprovalGate

        mode_raw = self._parse_strict_str(args, "approval_mode", "policy")
        approval_mode = (mode_raw or "policy").strip().lower()
        if approval_mode not in ("policy", "deny"):
            raise ValueError(
                f"Unsupported MCP approval_mode {approval_mode!r}; allowed values: 'policy', 'deny'."
            )
        rules_path = self._parse_strict_str(args, "approval_rules", None)
        if rules_path:
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
            t_path = args.get("target_path", ".")
            return self.raptor.describe_target(t_path)

        elif name == "raptor_scan_project":
            t_path = args.get("target_path", ".")
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
            return self.raptor.run_scan(
                target_path=t_path,
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
            resolved_path = path
            if repo or path or (not remote_host and not targets_arg):
                raw_target = str(repo or path or ".")
                if "\x00" in raw_target:
                    raise ValueError("Invalid target path containing NUL byte.")
                resolved = os.path.abspath(raw_target)
                if not os.path.exists(resolved):
                    return {"error": f"Target path does not exist: {resolved}"}
                resolved_repo = resolved if repo or not path else None
                resolved_path = resolved if path and not repo else path

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
            gate = self._build_mcp_approval_gate(args, "MCP-ARTEX-CHAIN")
            if multiturn and gate.mode == "deny":
                fmt_host = f"[{clean_host}]" if ":" in clean_host and not clean_host.startswith("[") else clean_host
                gate.require(
                    action_type="network_socket",
                    target=f"{'https' if resolved_tls else 'http'}://{fmt_host}:{resolved_port}/",
                    method="GET",
                    rationale="MCP artex_run_attack_chain multi-turn execution",
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
                    reports_dir=self._parse_strict_str(args, "reports_dir", None),
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
            reports_dir = self._parse_strict_str(args, "reports_dir", "reports") or "reports"
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

            gate = self._build_mcp_approval_gate(args, task_id or "MCP-MULTITURN")
            if gate.mode == "deny":
                gate.require(
                    action_type="network_socket",
                    target=f"{target_url}{target_route if target_route.startswith('/') else '/' + target_route}",
                    method=method,
                    rationale="MCP bounded multi-turn ArtexWorker execution",
                )

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

            gate = self._build_mcp_approval_gate(args, task_id or f"MCP-{tool_key.upper()}")
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

            loaded_scope = None
            if args.get("scope_path"):
                loaded_scope = load_scope_file(str(args["scope_path"]))
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
                out["openapi"] = import_openapi_spec(
                    str(args["openapi_path"]),
                    asset_graph=ag,
                    default_host=str(args.get("host") or "127.0.0.1"),
                    default_port=int(args.get("port") or 443),
                )
            if args.get("har_path"):
                har_res = import_har_file(str(args["har_path"]), asset_graph=ag, traffic_session=ts)
                out["har"] = {k: v for k, v in har_res.items() if k != "extracted_auth_headers"}
                out["har"]["auth_headers_found"] = har_res.get("auth_headers_found", [])
            out["total_assets_ingested"] = len(ag.nodes)
            return out

        elif name == "artex_export_advisory":
            from pathlib import Path as _Path
            from engine.advisory_exporter import AdvisoryExporter, _safe_filename

            out_dir = _Path(str(args.get("output_dir") or "reports/advisories"))
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
            if args.get("archive_path"):
                resp["archive"] = exporter.export_task_archive(
                    self.db,
                    str(args["archive_path"]),
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

            raw_target = str(args.get("target_path") or args.get("repo") or args.get("path") or ".")
            if "\x00" in raw_target:
                raise ValueError("Invalid target path containing NUL byte.")
            resolved = os.path.abspath(raw_target)
            if not os.path.exists(resolved):
                return {"error": f"Target path does not exist: {resolved}"}

            integrator = MantisIntegrator(
                db=self.db,
                reports_dir=args.get("output_dir") or "reports",
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
            reports_dir = self._parse_strict_str(args, "output_dir", "reports") or "reports"
            noise_profile = self._parse_strict_str(args, "noise_profile", "off") or "off"

            if not target_path and not raw_host:
                target_path = "."

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

            gate = self._build_mcp_approval_gate(args, "MCP-REA-SURFACE")
            integrator = ReaIntegrator(
                db=self.db,
                reports_dir=reports_dir,
                approval_gate=gate,
                noise_governor=NoiseGovernor(profile=noise_profile),
            )
            res_obj = integrator.analyze(
                target_path=target_path,
                host=clean_host,
                port=resolved_port,
                use_tls=resolved_tls,
                authorized=bool(authorized or (clean_host and is_explicit_loopback_host(clean_host))),
                use_rea_cli=use_rea_cli,
                write_reports=True,
            )
            out = res_obj.to_dict()
            out["total_findings"] = len(out.get("findings") or [])
            out["total_endpoints"] = len(out.get("discovered_endpoints") or [])
            return out

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
                if extra_headers:
                    for k, v in extra_headers.items():
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def _require_auth(self) -> bool:
                if not parent._check_origin(self.headers.get("Origin")):
                    self._send_json(403, {"error": "Forbidden Origin header (MCP DNS-rebinding / CSRF guard)"})
                    return False
                if not parent._check_auth(self.headers.get("Authorization")):
                    self._send_json(401, {"error": "Unauthorized: invalid or missing Bearer token"})
                    return False
                return True

            def _read_json_body(self) -> Tuple[Optional[Any], Optional[str]]:
                try:
                    length = int(self.headers.get("Content-Length") or "0")
                except ValueError:
                    return None, "Invalid Content-Length"
                if length > 2 * 1024 * 1024:
                    return None, "Payload exceeds 2 MiB limit"
                raw = self.rfile.read(length) if length > 0 else b""
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
                        self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": err}})
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
                        self.end_headers()
                        self.wfile.write(frame)
                        return

                    if not result_obj:
                        self.send_response(202)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return

                    self._send_json(200, result_obj, extra_headers={"Mcp-Session-Id": self.headers.get("Mcp-Session-Id") or secrets.token_hex(8)})
                    return

                # Legacy SSE message endpoint (`POST /message?sessionId=...`)
                if parsed.path == "/message":
                    qs = parse_qs(parsed.query)
                    sid = (qs.get("sessionId") or [""])[0].strip()
                    if not sid:
                        self._send_json(400, {"error": "Missing sessionId query parameter"})
                        return
                    with parent._sessions_lock:
                        has_session = sid in parent._sessions
                    if not has_session:
                        self._send_json(404, {"error": f"Unknown or closed SSE session: {sid}"})
                        return
                    payload, err = self._read_json_body()
                    if err or not isinstance(payload, dict):
                        self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": err or "Invalid request"}})
                        return
                    resp = parent.mcp_server.handle_request(payload)
                    if resp:
                        delivered = parent._push_session_event(sid, "message", resp)
                        if not delivered:
                            self._send_json(404, {"error": f"Unknown or closed SSE session: {sid}"})
                            return
                    self._send_json(202, {"status": "accepted", "sessionId": sid})
                    return

                self._send_json(404, {"error": f"Not found: {parsed.path}"})

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
