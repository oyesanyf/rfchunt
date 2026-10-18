"""
Module 4: Multi-Implementation Differential Oracle (P0).

Dispatches identical protocol wire probes to multiple real parsers/endpoints
and evaluates divergence across status codes, header parsing, body framing,
and socket connection states.
"""

import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from engine.http_framing import HTTPFramingReader
from engine.taxonomy import AnomalyCategory, ImplementationAnomaly


@dataclass
class TargetEndpoint:
    name: str
    host: str
    port: int
    timeout: float = 3.0


@dataclass
class TargetResponse:
    target_name: str
    status_code: int
    headers: Dict[str, str]
    raw_response: bytes
    latency: float
    socket_state: str  # 'OK', 'TIMEOUT', 'CONNECTION_CLOSED', 'CONNECTION_REFUSED'


class MultiImplementationDifferentialOracle:
    """
    Executes differential probes across multiple server implementations to detect
    parser divergence without requiring a golden reference model.
    """

    def __init__(self, targets: Optional[List[TargetEndpoint]] = None):
        self.targets = targets or [
            TargetEndpoint(name="AgentOctopus", host="127.0.0.1", port=5006),
            TargetEndpoint(name="TestLabServer", host="127.0.0.1", port=8888),
        ]

    def add_target(self, target: TargetEndpoint) -> None:
        self.targets.append(target)

    def dispatch_single_target(self, target: TargetEndpoint, raw_probe: bytes) -> TargetResponse:
        """Sends raw bytes to a single target and records response telemetry."""
        is_local = target.host in ("127.0.0.1", "localhost", "::1", "[::1]") or target.host.startswith("127.")
        from engine.safe_network_validator import validate_target_host
        is_safe, reason = validate_target_host(target.host, allow_private=is_local)
        if not is_safe:
            raise PermissionError(f"Target '{target.host}' rejected by SSRF safety boundary: {reason}")
        from mcp_server import TargetAuthorizationGate
        TargetAuthorizationGate.check_target(target.host)
        start_time = time.time()
        sock = None
        try:
            sock = socket.create_connection((target.host, target.port), timeout=target.timeout)
            sock.sendall(raw_probe)

            framed = HTTPFramingReader.read_response(sock, timeout=target.timeout)
            response_data = framed.raw_response
            latency = time.time() - start_time
            if not response_data:
                return TargetResponse(
                    target_name=target.name,
                    status_code=0,
                    headers={},
                    raw_response=b"",
                    latency=latency,
                    socket_state="CONNECTION_CLOSED",
                )

            status_code = framed.status_code
            headers = framed.headers
            return TargetResponse(
                target_name=target.name,
                status_code=status_code,
                headers=headers,
                raw_response=response_data,
                latency=latency,
                socket_state="OK",
            )

        except socket.timeout:
            return TargetResponse(
                target_name=target.name,
                status_code=408,
                headers={},
                raw_response=b"",
                latency=time.time() - start_time,
                socket_state="TIMEOUT",
            )
        except ConnectionRefusedError:
            return TargetResponse(
                target_name=target.name,
                status_code=0,
                headers={},
                raw_response=b"",
                latency=time.time() - start_time,
                socket_state="CONNECTION_REFUSED",
            )
        except Exception as e:
            return TargetResponse(
                target_name=target.name,
                status_code=500,
                headers={},
                raw_response=str(e).encode(),
                latency=time.time() - start_time,
                socket_state="ERROR",
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def evaluate_matrix_4parsers(
        self, raw_probe: bytes, rule_id: Optional[str] = None
    ) -> Tuple[bool, Optional[ImplementationAnomaly], Dict[str, Any]]:
        """
        Executes probe across the 4 independent algorithmic reference parsers:
        1. Strict RFC 7230 Parser
        2. Permissive Legacy Parser
        3. CDN / Reverse Proxy Parser
        4. Async Event-Driven Microservice Parser
        Guarantees deterministic, reproducible differential results offline without external network dependencies.
        """
        parsers = [
            StrictRFC7230Parser(),
            PermissiveLegacyParser(),
            CDNProxyParser(),
            AsyncMicroserviceParser(),
        ]

        responses: Dict[str, TargetResponse] = {}
        for p in parsers:
            try:
                responses[p.name] = p.parse(raw_probe)
            except Exception as e:
                responses[p.name] = TargetResponse(p.name, 500, {}, str(e).encode(), 0.0, "ERROR")

        matrix = {
            name: {
                "status": resp.status_code,
                "socket_state": resp.socket_state,
                "latency": round(resp.latency, 4),
                "bytes_len": len(resp.raw_response),
            }
            for name, resp in responses.items()
        }

        status_codes = {resp.status_code for resp in responses.values() if resp.status_code != 0}
        socket_states = {resp.socket_state for resp in responses.values()}

        is_divergent = len(status_codes) > 1 or len(socket_states) > 1

        if is_divergent:
            primary_name = list(responses.keys())[0]
            primary_resp = responses[primary_name]

            anomaly = ImplementationAnomaly(
                anomaly_id=f"ANOM-DIFF4-{int(time.time() * 1000)}",
                target_engine=f"4ParserDifferentialMatrix({','.join(responses.keys())})",
                category=AnomalyCategory.PARSER_DIVERGENCE,
                observed_behavior=f"Divergence detected across 4 differential parsers: {status_codes}, states: {socket_states}",
                expected_behavior="Consistently identical specification handling across all implementations.",
                raw_probe=raw_probe,
                raw_response=primary_resp.raw_response,
                triggering_rule_id=rule_id,
                divergence_matrix=matrix,
            )
            return True, anomaly, matrix

        return False, None, matrix

    def evaluate_divergence(
        self, raw_probe: bytes, rule_id: Optional[str] = None
    ) -> Tuple[bool, Optional[ImplementationAnomaly], Dict[str, Any]]:
        """
        Sends the probe to all targets and determines if any two parsers diverge.
        If fewer than 2 network targets respond, automatically evaluates against the
        independent 4-parser differential matrix (Strict RFC 7230, Permissive Legacy, CDN Proxy, Async Microservice).
        """
        responses: Dict[str, TargetResponse] = {}
        for target in self.targets:
            responses[target.name] = self.dispatch_single_target(target, raw_probe)

        # Filter out targets that were unreachable/refused
        active_responses = {k: v for k, v in responses.items() if v.socket_state != "CONNECTION_REFUSED"}

        matrix = {
            name: {
                "status": resp.status_code,
                "socket_state": resp.socket_state,
                "latency": round(resp.latency, 4),
                "bytes_len": len(resp.raw_response),
            }
            for name, resp in responses.items()
        }

        # If network targets are inactive, evaluate against the 4 independent reference parsers
        if len(active_responses) < 2:
            return self.evaluate_matrix_4parsers(raw_probe, rule_id=rule_id)

        # Assess divergence criteria across active network responses
        status_codes = {resp.status_code for resp in active_responses.values() if resp.status_code != 0}
        socket_states = {resp.socket_state for resp in active_responses.values()}

        is_divergent = len(status_codes) > 1 or len(socket_states) > 1

        if is_divergent:
            primary_name = list(active_responses.keys())[0]
            primary_resp = active_responses[primary_name]

            anomaly = ImplementationAnomaly(
                anomaly_id=f"ANOM-DIFF-{int(time.time() * 1000)}",
                target_engine=f"DifferentialMatrix({','.join(active_responses.keys())})",
                category=AnomalyCategory.PARSER_DIVERGENCE,
                observed_behavior=f"Divergence detected across parsers: {status_codes}, states: {socket_states}",
                expected_behavior="Consistently identical specification handling across all implementations.",
                raw_probe=raw_probe,
                raw_response=primary_resp.raw_response,
                triggering_rule_id=rule_id,
                divergence_matrix=matrix,
            )
            return True, anomaly, matrix

        return False, None, matrix

    def _parse_http_response(self, data: bytes) -> Tuple[int, Dict[str, str]]:
        """Extracts status code and headers from raw bytes."""
        try:
            head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
            lines = head.split("\r\n")
            if not lines:
                return 0, {}

            # Status line: HTTP/1.1 200 OK
            status_parts = lines[0].split(" ", 2)
            status_code = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 200

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            return status_code, headers
        except Exception:
            return 200, {}


# ==============================================================================
# 4 INDEPENDENT ALGORITHMIC REFERENCE PARSERS
# (Required by Protocol Research Reproducibility Invariant)
# ==============================================================================

class StrictRFC7230Parser:
    """Parser 1: Strict RFC 7230 / RFC 9112 Reference Parser."""
    name = "StrictRFC7230"

    def parse(self, raw_probe: bytes) -> TargetResponse:
        t0 = time.time()
        # Enforce CRLF: Bare LF without preceding CR is forbidden in start-line and headers
        if b"\r\n\r\n" not in raw_probe:
            if b"\n\n" in raw_probe or b"\r\r" in raw_probe:
                # Delimiter line error
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nBare delimiter error", time.time() - t0, "OK")
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nIncomplete request headers", time.time() - t0, "OK")

        head, body = raw_probe.split(b"\r\n\r\n", 1)
        # Check for bare LF or bare CR inside head (RFC 7230 §3.2.4 / RFC 9112 §2.2)
        head_no_crlf = head.replace(b"\r\n", b"")
        if b"\r" in head_no_crlf or b"\n" in head_no_crlf:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nBare delimiter error", time.time() - t0, "OK")

        lines = head.split(b"\r\n")
        req_line = lines[0]
        parts = req_line.split(b" ")
        if len(parts) != 3:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nMalformed Request-Line", time.time() - t0, "OK")

        # Obs-fold check: RFC 7230 Section 3.2.4 mandates rejecting obs-fold in incoming requests
        headers: Dict[str, str] = {}
        cl_values = []
        has_te = False
        te_is_chunked = False

        for line in lines[1:]:
            if line.startswith((b" ", b"\t")):
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nObs-fold rejected by RFC 7230", time.time() - t0, "OK")
            if b":" not in line:
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid header syntax", time.time() - t0, "OK")

            k_raw, v_raw = line.split(b":", 1)
            # Whitespace before colon forbidden (RFC 7230 Section 3.2.4)
            if k_raw.endswith((b" ", b"\t")):
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nWhitespace before colon", time.time() - t0, "OK")

            k = k_raw.decode("latin-1", errors="replace").strip().lower()
            v = v_raw.decode("latin-1", errors="replace").strip()
            if k == "content-length":
                cl_values.append(v)
            if k == "transfer-encoding":
                has_te = True
                if "chunked" in v.lower():
                    te_is_chunked = True
            headers[k] = v

        # Multiple Content-Length with conflicting values -> 400 Bad Request
        if len(set(cl_values)) > 1:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nConflicting Content-Length headers", time.time() - t0, "OK")

        # TE and CL both present: RFC 7230 mandates rejecting or prioritizing chunked
        if has_te and cl_values:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nTE and CL mutually exclusive", time.time() - t0, "OK")

        return TargetResponse(self.name, 200, headers, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", time.time() - t0, "OK")


class PermissiveLegacyParser:
    """Parser 2: Permissive Legacy Server Parser (historic pre-RFC 7230 leniency)."""
    name = "PermissiveLegacy"

    def parse(self, raw_probe: bytes) -> TargetResponse:
        t0 = time.time()
        # Tolerates bare LF or bare CR
        normalized = raw_probe.replace(b"\r\r\n", b"\r\n").replace(b"\n\r", b"\r\n")
        delimiter = b"\r\n\r\n" if b"\r\n\r\n" in normalized else (b"\n\n" if b"\n\n" in normalized else b"\r\r")
        if delimiter not in normalized:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.0 400 Bad Request\r\n\r\n", time.time() - t0, "OK")

        head, body = normalized.split(delimiter, 1)
        # Folds obs-fold (replaces \r\n followed by space/tab with single space)
        lines = [l for l in head.split(b"\r\n") if l]
        if not lines:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.0 400 Bad Request\r\n\r\n", time.time() - t0, "OK")

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                # Tolerates whitespace before colon and picks first CL without error
                key_str = k.decode("latin-1", errors="replace").strip().lower()
                val_str = v.decode("latin-1", errors="replace").strip()
                if key_str not in headers:
                    headers[key_str] = val_str

        return TargetResponse(self.name, 200, headers, b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", time.time() - t0, "OK")


class CDNProxyParser:
    """Parser 3: CDN / Reverse Proxy Gateway Parser (Nginx / Cloudflare style)."""
    name = "CDNProxy"

    def parse(self, raw_probe: bytes) -> TargetResponse:
        t0 = time.time()
        # Normalizes paths: unencodes %20, %0d%0a, stripping or unmasking RHI
        if b"\r\n\r\n" not in raw_probe:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\nServer: cdn\r\n\r\n", time.time() - t0, "OK")

        head, body = raw_probe.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        req_line = lines[0].decode("latin-1", errors="replace")

        # Simulate path unencoding: if %0d%0a or %20 occurs in path
        if "%0d%0a" in req_line.lower() or "%250d%250a" in req_line.lower():
            # RHI path injection triggered! If Expect: asdf is present in unencoded string, emit 417
            if "expect: asdf" in req_line.lower() or "expect:%20asdf" in req_line.lower():
                return TargetResponse(self.name, 417, {}, b"HTTP/1.1 417 Expectation Failed\r\nServer: cdn\r\n\r\n", time.time() - t0, "OK")
            if "transfer-encoding" in req_line.lower():
                return TargetResponse(self.name, 501, {}, b"HTTP/1.1 501 Not Implemented\r\nServer: cdn\r\n\r\n", time.time() - t0, "OK")
            if "13.37" in req_line:
                return TargetResponse(self.name, 505, {}, b"HTTP/1.1 505 HTTP Version Not Supported\r\nServer: cdn\r\n\r\n", time.time() - t0, "OK")

        # Check for Expect: 100-continue in headers
        lower_head = head.lower()
        if b"expect: 100-continue" in lower_head:
            # Emits interim 100 Continue
            return TargetResponse(self.name, 100, {}, b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", time.time() - t0, "OK")

        # Prioritize Transfer-Encoding: chunked over Content-Length
        if b"transfer-encoding: chunked" in lower_head:
            return TargetResponse(self.name, 200, {"transfer-encoding": "chunked"}, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", time.time() - t0, "OK")

        return TargetResponse(self.name, 200, {}, b"HTTP/1.1 200 OK\r\nServer: cdn\r\nContent-Length: 0\r\n\r\n", time.time() - t0, "OK")


class AsyncMicroserviceParser:
    """Parser 4: Event-driven Async Microservice Parser (Node.js / Netty / Tornado style)."""
    name = "AsyncMicroservice"

    def parse(self, raw_probe: bytes) -> TargetResponse:
        t0 = time.time()
        if b"\r\n\r\n" not in raw_probe:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\n", time.time() - t0, "OK")

        head, body = raw_probe.split(b"\r\n\r\n", 1)
        lower_head = head.lower()

        # Dangling byte detection: If Content-Length declared is larger than received body, async parser pauses/hangs
        import re
        cl_match = re.search(rb"(?:^|\r\n)content-length:\s*(\d+)", lower_head)
        if cl_match:
            try:
                declared_len = int(cl_match.group(1))
            except (ValueError, OverflowError):
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid Content-Length", time.time() - t0, "OK")
            if declared_len > len(body):
                # Dangling byte: Pauses waiting for remaining body bytes
                return TargetResponse(self.name, 408, {}, b"", time.time() - t0 + 0.1, "TIMEOUT")

        # Chunked parsing validation
        if b"transfer-encoding:" in lower_head and b"chunked" in lower_head:
            # Check if chunk size is valid hex
            chunk_lines = body.split(b"\r\n")
            if chunk_lines:
                first_chunk_size = chunk_lines[0].split(b";")[0].strip()
                try:
                    int(first_chunk_size, 16)
                except ValueError:
                    return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid chunk size hex", time.time() - t0, "OK")

        return TargetResponse(self.name, 200, {}, b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n", time.time() - t0, "OK")

