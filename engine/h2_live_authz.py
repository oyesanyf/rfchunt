"""
Live Binary HTTP/2 (`h2`) Desync Prober & Two-Account Authz/IDOR Differential Replay (R3).

Provides:
  1. `LiveH2DesyncProber`:
     Real binary HTTP/2 (ALPN `h2` over TLS or cleartext `h2c` prior-knowledge) 3-trial
     prober testing `H2.CL`, `H2.TE`, and pseudo-header CRLF/space smuggling with a
     same-connection Stream 3 canary, 4-parser differential matrix cross-check,
     `MerkleAuditTrail` registration, global `RequestHygieneConfig` headers/User-Agent,
     and shared `TokenBucketRateLimiter` pacing.
  2. `TwoAccountAuthzDiffer`:
     Cross-session two-account (`Role A` vs. `Role B` + unauthenticated public-route
     control) 3-trial BOLA / IDOR / BFLA differential replay engine integrated with
     repeatable `--auth-profile` and `--all`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import httpx

from engine.differential_oracle import MultiImplementationDifferentialOracle
from engine.h2_framing import (
    H2Flag,
    H2Frame,
    H2FrameType,
    H2GatewayDesyncBuilder,
    HPACKLite,
)
from engine.merkle_audit import MerkleAuditTrail
from engine.request_hygiene import (
    RequestHygieneConfig,
    TokenBucketRateLimiter,
    acquire_rate_limit,
    resolve_hygiene,
)
from engine.safe_network_validator import validate_and_authorize_target
from engine.session_loader import AuthProfile, load_auth_profiles


LIVE_H2_TRIALS = 3
AUTHZ_DIFF_TRIALS = 3


def resolve_auth_profiles_from_cli(
    auth_profile_arg: Optional[Union[str, Path, Sequence[Union[str, Path]]]],
) -> Dict[str, AuthProfile]:
    """
    Loads one or more `--auth-profile` files (supporting repeatable `--auth-profile a.json --auth-profile b.json`,
    comma-separated paths, or a single JSON/YAML containing multiple profiles).
    """
    if not auth_profile_arg:
        return {}
    raw_items: List[str] = []
    if isinstance(auth_profile_arg, (list, tuple, set)):
        for item in auth_profile_arg:
            if item:
                for sub in str(item).split(","):
                    if sub.strip():
                        raw_items.append(sub.strip())
    else:
        for sub in str(auth_profile_arg).split(","):
            if sub.strip():
                raw_items.append(sub.strip())

    merged: Dict[str, AuthProfile] = {}
    for file_idx, path_str in enumerate(raw_items, 1):
        loaded = load_auth_profiles(path_str)
        for name, prof in loaded.items():
            key = name
            if key in merged:
                key = f"{name}_{file_idx}"
                prof = AuthProfile(
                    name=key,
                    role=prof.role,
                    headers=dict(prof.headers),
                    cookies=dict(prof.cookies),
                    bearer_token=prof.bearer_token,
                )
            merged[key] = prof
    return merged


def _build_h2_stream_with_hygiene(
    headers: List[Tuple[str, str]],
    body: bytes,
    stream_id: int,
    hygiene: RequestHygieneConfig,
) -> bytes:
    """Encodes an HTTP/2 HEADERS (+ optional DATA) stream including custom hygiene headers & User-Agent."""
    final_headers = list(headers)
    existing_lower = {k.lower() for k, _ in final_headers}
    if hygiene.user_agent and "user-agent" not in existing_lower:
        final_headers.append(("user-agent", hygiene.user_agent))
        existing_lower.add("user-agent")
    for k, v in hygiene.headers:
        kl = k.lower()
        if kl not in (":method", ":scheme", ":authority", ":path", "content-length", "transfer-encoding"):
            final_headers.append((kl, v))

    hdr_payload = HPACKLite.encode_headers_block(final_headers)
    if body:
        h_frame = H2Frame(
            frame_type=H2FrameType.HEADERS,
            flags=H2Flag.END_HEADERS,
            stream_id=stream_id,
            payload=hdr_payload,
        )
        d_frame = H2Frame(
            frame_type=H2FrameType.DATA,
            flags=H2Flag.END_STREAM,
            stream_id=stream_id,
            payload=body,
        )
        return h_frame.serialize() + d_frame.serialize()
    h_frame = H2Frame(
        frame_type=H2FrameType.HEADERS,
        flags=H2Flag.END_HEADERS | H2Flag.END_STREAM,
        stream_id=stream_id,
        payload=hdr_payload,
    )
    return h_frame.serialize()


def _parse_h2_response_frames(raw: bytes) -> Dict[str, Any]:
    """Parses binary HTTP/2 response frames into per-stream status codes, data bodies, and control signals."""
    buf = raw
    # Strip server preface if peer echoed one
    if buf.startswith(H2Frame.CONNECTION_PREFACE):
        buf = buf[len(H2Frame.CONNECTION_PREFACE) :]

    saw_settings = False
    saw_rst_or_goaway = False
    stream_statuses: Dict[int, int] = {}
    stream_headers: Dict[int, List[Tuple[str, str]]] = {}
    stream_bodies: Dict[int, bytearray] = {}
    frames_parsed = 0

    while len(buf) >= 9:
        try:
            frame, buf = H2Frame.parse(buf)
        except ValueError:
            break
        frames_parsed += 1
        if frame.frame_type == int(H2FrameType.SETTINGS):
            saw_settings = True
        elif frame.frame_type in (int(H2FrameType.RST_STREAM), int(H2FrameType.GOAWAY)):
            saw_rst_or_goaway = True
        elif frame.frame_type == int(H2FrameType.HEADERS):
            hdrs = HPACKLite.decode_literal_headers(frame.payload)
            stream_headers.setdefault(frame.stream_id, []).extend(hdrs)
            for k, v in hdrs:
                if k == ":status" and v.isdigit():
                    stream_statuses[frame.stream_id] = int(v)
        elif frame.frame_type == int(H2FrameType.DATA):
            stream_bodies.setdefault(frame.stream_id, bytearray()).extend(frame.payload)

    return {
        "frames_parsed": frames_parsed,
        "saw_settings": saw_settings,
        "saw_rst_or_goaway": saw_rst_or_goaway,
        "headers": stream_headers,
        "stream_statuses": stream_statuses,
        "stream_bodies": {sid: bytes(b).decode("latin-1", errors="replace") for sid, b in stream_bodies.items()},
    }


parse_h2_response_frames = _parse_h2_response_frames


class LiveH2DesyncProber:
    """
    Executes 3-trial binary HTTP/2 (`H2.CL`, `H2.TE`, and pseudo-header CRLF smuggling)
    probes against an authorized target with Stream 3 canary verification.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        use_tls: bool = False,
        timeout: float = 3.0,
        *,
        authorized: bool = False,
        hygiene_config: Optional[RequestHygieneConfig] = None,
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        traffic_session: Optional[Any] = None,
        merkle_trail: Optional[MerkleAuditTrail] = None,
        on_trace: Optional[Any] = None,
    ) -> None:
        self.host = str(host or "127.0.0.1").strip()
        self.port = int(port or (443 if use_tls else 8080))
        self.use_tls = bool(use_tls or self.port == 443)
        self.timeout = float(timeout or 3.0)
        self.authorized = bool(authorized)
        self.hygiene_config, self.rate_limiter = resolve_hygiene(hygiene_config, rate_limiter)
        self.traffic_session = traffic_session
        self.merkle_trail = merkle_trail if merkle_trail is not None else MerkleAuditTrail()
        self.oracle = MultiImplementationDifferentialOracle()
        self.on_trace = on_trace

    def _open_h2_socket(self) -> Tuple[socket.socket, str]:
        ok, reason = validate_and_authorize_target(self.host, authorized=self.authorized)
        if not ok:
            raise PermissionError(f"LiveH2DesyncProber target blocked: {reason}")
        acquire_rate_limit(self.rate_limiter)
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw_sock.settimeout(self.timeout)
        if not self.use_tls:
            return raw_sock, "h2c"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
        tls_sock.settimeout(self.timeout)
        negotiated = tls_sock.selected_alpn_protocol() or "h2-tls"
        return tls_sock, negotiated

    def _send_h2_exchange(self, wire_bytes: bytes) -> Tuple[bytes, str]:
        sock, proto = self._open_h2_socket()
        try:
            sock.sendall(wire_bytes)
            chunks: List[bytes] = []
            while True:
                try:
                    data = sock.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
                    if sum(len(c) for c in chunks) >= 32768:
                        break
                except socket.timeout:
                    break
            return b"".join(chunks), proto
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _build_vectors(self) -> List[Dict[str, Any]]:
        scheme = "https" if self.use_tls else "http"
        authority = f"{self.host}:{self.port}"
        preface = H2GatewayDesyncBuilder.build_client_init_stream()
        canary_stream = _build_h2_stream_with_hygiene(
            [
                (":method", "GET"),
                (":scheme", scheme),
                (":authority", authority),
                (":path", "/"),
            ],
            b"",
            3,
            self.hygiene_config,
        )

        # 1. H2.CL desync (declared CL=0, actual body smuggles prefix for next request)
        smuggled_prefix = f"GET /__rfchunt_h2_smuggled HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("latin-1")
        h2_cl_s1 = _build_h2_stream_with_hygiene(
            [
                (":method", "POST"),
                (":scheme", scheme),
                (":authority", authority),
                (":path", "/"),
                ("content-length", "0"),
            ],
            smuggled_prefix,
            1,
            self.hygiene_config,
        )

        # 2. H2.TE desync (illegal transfer-encoding: chunked in H2)
        h2_te_s1 = _build_h2_stream_with_hygiene(
            [
                (":method", "POST"),
                (":scheme", scheme),
                (":authority", authority),
                (":path", "/"),
                ("transfer-encoding", "chunked"),
            ],
            b"0\r\n\r\n" + smuggled_prefix,
            1,
            self.hygiene_config,
        )

        # 3. H2 pseudo-header smuggling (:path containing CRLF + injected header/request)
        h2_pseudo_s1 = _build_h2_stream_with_hygiene(
            [
                (":method", "GET"),
                (":scheme", scheme),
                (":authority", authority),
                (":path", f"/ HTTP/1.1\r\nHost: {authority}\r\nX-RFCHunt-Smuggled: 1\r\n\r\nGET /__rfchunt_h2_smuggled"),
            ],
            b"",
            1,
            self.hygiene_config,
        )

        return [
            {
                "rule_id": "H2-CL-DESYNC-001",
                "desync_class": "H2.CL_DESYNC",
                "title": "HTTP/2 H2.CL Content-Length vs DATA Frame Desynchronization",
                "cwe": "CWE-444",
                "rfc_num": 9113,
                "wire_bytes": preface + h2_cl_s1 + canary_stream,
                "http1_equiv": (
                    f"POST / HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 0\r\nContent-Length: {len(smuggled_prefix)}\r\n\r\n".encode("latin-1")
                    + smuggled_prefix
                ),
            },
            {
                "rule_id": "H2-TE-DESYNC-002",
                "desync_class": "H2.TE_DESYNC",
                "title": "HTTP/2 H2.TE Forbidden Transfer-Encoding Gateway Desynchronization",
                "cwe": "CWE-444",
                "rfc_num": 9113,
                "wire_bytes": preface + h2_te_s1 + canary_stream,
                "http1_equiv": (
                    f"POST / HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX".encode(
                        "latin-1"
                    )
                ),
            },
            {
                "rule_id": "H2-PSEUDO-SMUGGLE-003",
                "desync_class": "H2.PSEUDO_HEADER_SMUGGLE",
                "title": "HTTP/2 Pseudo-Header CRLF Request Splitting / Smuggling",
                "cwe": "CWE-444",
                "rfc_num": 9113,
                "wire_bytes": preface + h2_pseudo_s1 + canary_stream,
                "http1_equiv": f"GET / HTTP/1.1\nHost: {authority}\nX-Smuggled: 1\n\n".encode("latin-1"),
            },
        ]

    def run_live_h2_audit(self, trials: int = LIVE_H2_TRIALS) -> Dict[str, Any]:
        """Executes 3-trial binary HTTP/2 probing across all H2 desync vectors."""
        t0 = time.perf_counter()
        ok, reason = validate_and_authorize_target(self.host, authorized=self.authorized)
        if not ok:
            raise PermissionError(f"LiveH2DesyncProber target blocked: {reason}")

        n_trials = max(3, int(trials or LIVE_H2_TRIALS))
        scheme = "https" if self.use_tls else "http"
        authority = f"{self.host}:{self.port}"
        preface = H2GatewayDesyncBuilder.build_client_init_stream()
        baseline_s1 = _build_h2_stream_with_hygiene(
            [(":method", "GET"), (":scheme", scheme), (":authority", authority), (":path", "/")],
            b"",
            1,
            self.hygiene_config,
        )
        baseline_s3 = _build_h2_stream_with_hygiene(
            [(":method", "GET"), (":scheme", scheme), (":authority", authority), (":path", "/")],
            b"",
            3,
            self.hygiene_config,
        )

        # Measure baseline Stream 3 status
        base_s3_statuses: List[int] = []
        negotiated_proto = "unknown"
        for _ in range(n_trials):
            try:
                raw_b, negotiated_proto = self._send_h2_exchange(preface + baseline_s1 + baseline_s3)
                parsed_b = _parse_h2_response_frames(raw_b)
                if 3 in parsed_b["stream_statuses"]:
                    base_s3_statuses.append(parsed_b["stream_statuses"][3])
            except OSError:
                break

        vector_results: List[Dict[str, Any]] = []
        verified_findings: List[Dict[str, Any]] = []
        lead_findings: List[Dict[str, Any]] = []

        for vec in self._build_vectors():
            has_div, _, diff_matrix = self.oracle.evaluate_matrix_4parsers(vec["http1_equiv"], rule_id=vec["rule_id"])
            repro_count = 0
            last_raw_resp = b""
            last_quote = ""
            trial_details: List[Dict[str, Any]] = []

            for _ in range(n_trials):
                try:
                    raw_resp, negotiated_proto = self._send_h2_exchange(vec["wire_bytes"])
                except OSError as exc:
                    trial_details.append({"error": str(exc), "desync_observed": False})
                    continue

                last_raw_resp = raw_resp
                parsed = _parse_h2_response_frames(raw_resp)
                s1_status = parsed["stream_statuses"].get(1, 0)
                s3_status = parsed["stream_statuses"].get(3, 0)
                s3_body = parsed["stream_bodies"].get(3, "")
                s1_body = parsed["stream_bodies"].get(1, "")

                base_ok = (not base_s3_statuses) or (base_s3_statuses[0] == 200)
                canary_poisoned = (
                    not parsed["saw_rst_or_goaway"]
                    and 200 <= s1_status < 400
                    and (
                        (base_ok and s3_status in (400, 404, 500, 502))
                        or "SMUGGLED" in s3_body.upper()
                        or "SMUGGLED" in s1_body.upper()
                        or "__rfchunt_h2_smuggled" in s3_body
                    )
                )
                if canary_poisoned:
                    repro_count += 1
                    last_quote = (s3_body or s1_body or f"stream1={s1_status} stream3={s3_status}")[:180]
                trial_details.append(
                    {
                        "s1_status": s1_status,
                        "s3_status": s3_status,
                        "saw_rst_or_goaway": parsed["saw_rst_or_goaway"],
                        "desync_observed": canary_poisoned,
                    }
                )

            repro_rate = round(repro_count / float(n_trials), 3)
            leaf = self.merkle_trail.record_finding(
                entry_id=vec["rule_id"],
                target_engine=f"{self.host}:{self.port}",
                raw_probe=vec["wire_bytes"],
                raw_response=last_raw_resp,
                reproducibility_rate=repro_rate,
                verification_attempts=n_trials,
                successful_reproductions=repro_count,
                four_parser_differential={"divergence": bool(has_div), "matrix": diff_matrix},
                status="CONFIRMED_VULNERABILITY" if (repro_rate >= 0.67 and has_div) else "NON_REPRODUCIBLE_TRANSIENT",
            )

            traffic_id = None
            if self.traffic_session is not None and hasattr(self.traffic_session, "record_exchange") and repro_count > 0:
                try:
                    rec = self.traffic_session.record_exchange(
                        method="POST",
                        url=f"{scheme}://{authority}/",
                        request_headers=self.hygiene_config.to_headers_dict({"X-H2-Vector": vec["rule_id"]}),
                        request_body=vec["wire_bytes"].decode("latin-1", errors="replace"),
                        status_code=200,
                        response_headers={"x-h2-negotiated": negotiated_proto},
                        response_body=(last_quote or "H2_DESYNC_VERIFIED").encode("utf-8"),
                    )
                    traffic_id = getattr(rec, "traffic_id", None)
                except Exception:
                    traffic_id = None

            is_poe3 = bool(repro_rate >= 0.67 and n_trials >= 3 and has_div and leaf.status == "CONFIRMED_VULNERABILITY")
            entry_summary = {
                "rule_id": vec["rule_id"],
                "desync_class": vec["desync_class"],
                "title": vec["title"],
                "cwe": vec["cwe"],
                "rfc_num": vec["rfc_num"],
                "target": f"{self.host}:{self.port}",
                "negotiated_protocol": negotiated_proto,
                "verification_attempts": n_trials,
                "successful_reproductions": repro_count,
                "reproducibility_rate": repro_rate,
                "oracle_diverged": bool(has_div),
                "merkle_status": leaf.status,
                "merkle_leaf_hash": leaf.compute_leaf_hash(),
                "traffic_id": traffic_id,
                "evidence_quote": last_quote,
                "trials": trial_details,
            }
            vector_results.append(entry_summary)

            if is_poe3:
                finding = {
                    "rule_id": vec["rule_id"],
                    "title": vec["title"],
                    "severity": "CRITICAL",
                    "cwe": vec["cwe"],
                    "rfc_num": vec["rfc_num"],
                    "file_path": f"{self.host}:{self.port}",
                    "line_number": 1,
                    "poe_level": 3,
                    "verification_status": "VERIFIED",
                    "finding_tier": "VERIFIED_EXPLOIT",
                    "verified": True,
                    "verification_attempts": n_trials,
                    "successful_reproductions": repro_count,
                    "reproducibility_rate": repro_rate,
                    "traffic_id": traffic_id,
                    "evidence_quote": last_quote,
                    "scanner": "LiveH2DesyncProber",
                    "description": (
                        f"3-trial binary HTTP/2 ({negotiated_proto}) probing confirmed `{vec['desync_class']}` "
                        f"on {self.host}:{self.port} ({repro_count}/{n_trials} trials, 4-parser divergence={has_div})."
                    ),
                }
                verified_findings.append(finding)
            elif repro_count > 0:
                lead_findings.append(
                    {
                        "rule_id": vec["rule_id"],
                        "title": f"Transient HTTP/2 Anomaly Lead: {vec['title']}",
                        "severity": "MEDIUM",
                        "cwe": vec["cwe"],
                        "rfc_num": vec["rfc_num"],
                        "file_path": f"{self.host}:{self.port}",
                        "line_number": 1,
                        "poe_level": 1,
                        "verification_status": "LEAD_PASSIVE_CORRELATION",
                        "finding_tier": "MANUAL_REVIEW_LEAD",
                        "verified": False,
                        "verification_attempts": n_trials,
                        "successful_reproductions": repro_count,
                        "reproducibility_rate": repro_rate,
                        "merkle_status": "NON_REPRODUCIBLE_TRANSIENT",
                        "scanner": "LiveH2DesyncProber",
                        "description": (
                            f"Transient HTTP/2 response variance ({repro_count}/{n_trials} trials) downgraded "
                            f"to NON_REPRODUCIBLE_TRANSIENT."
                        ),
                    }
                )

        return {
            "status": "completed",
            "target": f"{self.host}:{self.port}",
            "use_tls": self.use_tls,
            "negotiated_protocol": negotiated_proto,
            "vectors_tested": len(vector_results),
            "trials_per_vector": n_trials,
            "total_findings": len(verified_findings),
            "verified_count": len(verified_findings),
            "transient_count": len(lead_findings),
            "leads_count": len(lead_findings),
            "verified_findings": verified_findings,
            "lead_findings": lead_findings,
            "findings": verified_findings,
            "all_findings": verified_findings + lead_findings,
            "vectors": vector_results,
            "merkle_root": self.merkle_trail.get_merkle_root(),
            "elapsed_sec": round(time.perf_counter() - t0, 3),
        }

    def run_live_h2_desync_audit(self, trials: int = LIVE_H2_TRIALS) -> Dict[str, Any]:
        return self.run_live_h2_audit(trials=trials)


class TwoAccountAuthzDiffer:
    """
    Executes 3-trial cross-session two-account (`Role A` vs. `Role B` + unauthenticated control)
    BOLA / IDOR / BFLA differential replay across target endpoints.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        use_tls: bool = False,
        *,
        auth_profiles: Dict[str, AuthProfile],
        endpoints: Optional[Sequence[str]] = None,
        authorized: bool = False,
        timeout: float = 3.5,
        hygiene_config: Optional[RequestHygieneConfig] = None,
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        traffic_session: Optional[Any] = None,
        approval_gate: Optional[Any] = None,
        noise_governor: Optional[Any] = None,
    ) -> None:
        self.host = str(host or "127.0.0.1").strip()
        self.port = int(port or (443 if use_tls else 8080))
        self.use_tls = bool(use_tls or self.port == 443)
        self.auth_profiles = dict(auth_profiles or {})
        self.endpoints = list(endpoints or ["/api/v1/users/1", "/api/account", "/internal/service"])
        self.authorized = bool(authorized)
        self.timeout = float(timeout or 3.5)
        self.hygiene_config, self.rate_limiter = resolve_hygiene(hygiene_config, rate_limiter)
        self.traffic_session = traffic_session
        self.approval_gate = approval_gate
        self.noise_governor = noise_governor

    def _send_get(self, client: httpx.Client, url: str, extra_headers: Optional[Dict[str, str]] = None) -> Tuple[int, str, Dict[str, str]]:
        acquire_rate_limit(self.rate_limiter)
        merged_headers = self.hygiene_config.to_headers_dict(extra_headers)
        resp = client.get(url, headers=merged_headers)
        body_text = resp.text or ""
        if self.traffic_session is not None and hasattr(self.traffic_session, "record_exchange"):
            try:
                rec = self.traffic_session.record_exchange(
                    method="GET",
                    url=url,
                    request_headers=merged_headers,
                    request_body="",
                    status_code=int(resp.status_code),
                    response_headers={str(k): str(v) for k, v in resp.headers.items()},
                    response_body=resp.content,
                )
                return int(resp.status_code), body_text, {"traffic_id": getattr(rec, "traffic_id", ""), "headers": merged_headers}
            except Exception:
                pass
        return int(resp.status_code), body_text, {"traffic_id": "", "headers": merged_headers}

    def run_differential_replay(self, trials: int = AUTHZ_DIFF_TRIALS) -> Dict[str, Any]:
        """Runs 3-trial cross-account differential replay when 2+ auth profiles are provided."""
        t0 = time.perf_counter()
        if len(self.auth_profiles) < 2:
            return {
                "status": "skipped_insufficient_profiles",
                "profiles_loaded": len(self.auth_profiles),
                "verified_findings": [],
                "lead_findings": [],
                "findings": [],
                "elapsed_sec": 0.0,
            }

        ok, reason = validate_and_authorize_target(self.host, authorized=self.authorized)
        if not ok:
            raise PermissionError(f"TwoAccountAuthzDiffer target blocked: {reason}")

        profile_list = list(self.auth_profiles.values())
        role_a = profile_list[0]
        role_b = profile_list[1]
        scheme = "https" if self.use_tls else "http"
        base_url = f"{scheme}://{self.host}:{self.port}"
        n_trials = max(3, int(trials or AUTHZ_DIFF_TRIALS))

        verified_findings: List[Dict[str, Any]] = []
        lead_findings: List[Dict[str, Any]] = []
        endpoint_results: List[Dict[str, Any]] = []

        with httpx.Client(verify=False, timeout=self.timeout, follow_redirects=False) as client:
            for raw_ep in self.endpoints:
                route = "/" + str(raw_ep or "/").split()[-1].lstrip("/")
                url = f"{base_url}{route}"
                idor_confirmations = 0
                last_b_body = ""
                last_b_traffic_id = ""
                trial_rows: List[Dict[str, Any]] = []

                for _ in range(n_trials):
                    try:
                        st_a, body_a, _ = self._send_get(client, url, role_a.build_headers())
                        st_b, body_b, meta_b = self._send_get(client, url, role_b.build_headers())
                        st_u, body_u, _ = self._send_get(client, url, {})
                    except Exception as exc:
                        trial_rows.append({"error": str(exc), "idor_detected": False})
                        continue

                    sim_ab = SequenceMatcher(None, body_a[:2000], body_b[:2000]).ratio() if (body_a and body_b) else 0.0
                    sim_au = SequenceMatcher(None, body_a[:2000], body_u[:2000]).ratio() if (body_a and body_u) else 0.0
                    unauth_blocked = (st_u in (401, 403, 404)) or (sim_au < 0.35)
                    is_idor = (
                        200 <= st_a < 300
                        and 200 <= st_b < 300
                        and len(body_a.strip()) >= 8
                        and unauth_blocked
                        and sim_ab >= 0.70
                    )
                    if is_idor:
                        idor_confirmations += 1
                        last_b_body = body_b.strip()
                        last_b_traffic_id = str(meta_b.get("traffic_id") or "")
                    trial_rows.append(
                        {
                            "role_a_status": st_a,
                            "role_b_status": st_b,
                            "unauth_status": st_u,
                            "similarity_ab": round(sim_ab, 3),
                            "unauth_blocked": unauth_blocked,
                            "idor_detected": is_idor,
                        }
                    )

                repro_rate = round(idor_confirmations / float(n_trials), 3)
                ep_summary = {
                    "route": route,
                    "role_a": role_a.name,
                    "role_b": role_b.name,
                    "verification_attempts": n_trials,
                    "successful_reproductions": idor_confirmations,
                    "reproducibility_rate": repro_rate,
                    "traffic_id": last_b_traffic_id,
                    "trials": trial_rows,
                }
                endpoint_results.append(ep_summary)

                if repro_rate >= 0.67 and idor_confirmations >= 2:
                    quote = last_b_body[:160]
                    verified_findings.append(
                        {
                            "rule_id": f"AUTHZ-IDOR-{hashlib.sha256(route.encode('utf-8')).hexdigest()[:8].upper()}",
                            "title": f"Cross-Account BOLA/IDOR Verified on `{route}` (`{role_b.name}` accessed `{role_a.name}` resource)",
                            "severity": "HIGH",
                            "cwe": "CWE-639",
                            "route": route,
                            "file_path": route,
                            "line_number": 1,
                            "poe_level": 3,
                            "verification_status": "VERIFIED",
                            "finding_tier": "VERIFIED_EXPLOIT",
                            "verified": True,
                            "reproduced": True,
                            "verification_attempts": n_trials,
                            "successful_reproductions": idor_confirmations,
                            "reproducibility_rate": repro_rate,
                            "traffic_id": last_b_traffic_id,
                            "evidence_quote": quote,
                            "scanner": "TwoAccountAuthzDiffer",
                            "description": (
                                f"3-trial cross-session authz replay confirmed `{role_b.name}` (`{role_b.role}`) "
                                f"received `{role_a.name}`'s protected resource on `{route}` ({idor_confirmations}/{n_trials} trials) "
                                f"while unauthenticated requests were denied."
                            ),
                        }
                    )
                elif idor_confirmations == 1:
                    lead_findings.append(
                        {
                            "rule_id": f"AUTHZ-LEAD-{hashlib.sha256(route.encode('utf-8')).hexdigest()[:8].upper()}",
                            "title": f"Transient Cross-Account Authz Anomaly Lead on `{route}`",
                            "severity": "MEDIUM",
                            "cwe": "CWE-639",
                            "route": route,
                            "file_path": route,
                            "line_number": 1,
                            "poe_level": 2,
                            "verification_status": "LEAD_ACTIVE_INDICATOR",
                            "finding_tier": "MANUAL_REVIEW_LEAD",
                            "verified": False,
                            "reproduced": False,
                            "verification_attempts": n_trials,
                            "successful_reproductions": idor_confirmations,
                            "reproducibility_rate": repro_rate,
                            "scanner": "TwoAccountAuthzDiffer",
                            "description": f"Single-trial cross-account 200 OK observed on `{route}`; manual review recommended.",
                        }
                    )

        return {
            "status": "completed",
            "target": f"{self.host}:{self.port}",
            "role_a": role_a.name,
            "role_b": role_b.name,
            "endpoints_tested": len(endpoint_results),
            "trials_per_endpoint": n_trials,
            "total_findings": len(verified_findings),
            "verified_count": len(verified_findings),
            "leads_count": len(lead_findings),
            "verified_findings": verified_findings,
            "lead_findings": lead_findings,
            "findings": verified_findings,
            "all_findings": verified_findings + lead_findings,
            "endpoints": endpoint_results,
            "elapsed_sec": round(time.perf_counter() - t0, 3),
        }

    def run_differential_audit(
        self,
        routes: Optional[Sequence[str]] = None,
        trials: int = AUTHZ_DIFF_TRIALS,
    ) -> Dict[str, Any]:
        if routes is not None:
            self.endpoints = list(routes)
        return self.run_differential_replay(trials=trials)
