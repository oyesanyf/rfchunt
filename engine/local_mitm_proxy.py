"""
Embedded CLI Recording MITM Proxy (Pillar 2, default :8788)
===========================================================
Pure-CLI local HTTP/1.1 + HTTPS CONNECT recording proxy built with Python stdlib
and `cryptography` (zero external proxy daemon or GUI required):
- Generates a local Root CA (`keys/rfchunt_ca.crt` + `keys/rfchunt_ca.key`, mode 0600)
  and mints per-host leaf TLS certificates dynamically for HTTPS interception.
- Enforces fail-closed SSRF / target-authorization validation on every proxied host.
- Applies `NoiseGovernor` per-host rate limits, jitter, and 429/503 Retry-After tracking.
- Supports request/response header rewrite rules with provenance metadata recorded
  directly alongside every captured exchange in `TrafficCaptureSession` / `traffic_evidence`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import ipaddress
import logging
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import httpx

from engine.artex_bridge import ArtexProxyConfig, TrafficCaptureSession

logger = logging.getLogger("terminator.artex.mitm")

DEFAULT_KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"


@dataclass
class RewriteRule:
    """Header rewrite rule applied by the capture proxy with provenance tracking."""

    rule_id: str
    phase: str = "request"  # 'request' or 'response'
    header_name: str = ""
    header_value: str = ""
    host_pattern: str = ""  # substring match or empty for all hosts
    enabled: bool = True

    def matches_host(self, host: str) -> bool:
        if not self.enabled or not self.header_name:
            return False
        if not self.host_pattern:
            return True
        return self.host_pattern.lower() in str(host or "").lower()


class LocalCA:
    """Manages the local recording MITM Root CA and dynamic per-host leaf certs."""

    def __init__(self, keys_dir: Optional[Union[str, Path]] = None):
        self.keys_dir = Path(keys_dir) if keys_dir else DEFAULT_KEYS_DIR
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = self.keys_dir / "rfchunt_ca.crt"
        self.ca_key_path = self.keys_dir / "rfchunt_ca.key"
        self._lock = threading.Lock()
        self._leaf_dir = Path(tempfile.mkdtemp(prefix="rfchunt_mitm_certs_"))
        self._leaf_cache: Dict[str, Tuple[Path, Path]] = {}
        self.ca_cert, self.ca_key = self._load_or_create_ca()

    def _load_or_create_ca(self) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        if self.ca_cert_path.is_file() and self.ca_key_path.is_file():
            try:
                cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
                key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
                # Python 3.13 / OpenSSL 3.x VERIFY_X509_STRICT requires SubjectKeyIdentifier on CA certs
                cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
                if cert.public_key().public_numbers() != key.public_key().public_numbers():
                    raise ValueError("MITM Root CA certificate/key pair mismatch.")
                now_utc = datetime.now(timezone.utc)
                not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
                if not_after > now_utc:
                    return cert, key
            except Exception as exc:
                logger.info("Regenerating legacy/invalid MITM Root CA (%s): %s", self.ca_cert_path, exc)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RFCHunt Local Recording CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "RFCHunt ARTEX MITM Root CA"),
        ])
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(ski, critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
            .sign(key, hashes.SHA256())
        )
        self.ca_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        try:
            os.chmod(self.ca_key_path, 0o600)
        except OSError:
            pass
        return cert, key

    def get_leaf_cert(self, host: str) -> Tuple[Path, Path]:
        clean = str(host or "localhost").strip().lower()
        if clean.startswith("[") and clean.endswith("]"):
            clean = clean[1:-1]
        with self._lock:
            if clean in self._leaf_cache:
                return self._leaf_cache[clean]
            leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            now = datetime.now(timezone.utc)
            san_entries: List[x509.GeneralName] = []
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(clean)))
            except ValueError:
                san_entries.append(x509.DNSName(clean))
            try:
                ca_ski = self.ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski)
            except x509.ExtensionNotFound:
                aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key())
            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, clean[:64])]))
                .issuer_name(self.ca_cert.subject)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(hours=1))
                .not_valid_after(now + timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
                .add_extension(aki, critical=False)
                .sign(self.ca_key, hashes.SHA256())
            )
            safe_prefix = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in clean)[:40]
            host_digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()[:8]
            safe_name = f"{safe_prefix}_{host_digest}"
            cert_file = self._leaf_dir / f"{safe_name}.crt"
            key_file = self._leaf_dir / f"{safe_name}.key"
            cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_file.write_bytes(
                leaf_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            self._leaf_cache[clean] = (cert_file, key_file)
            return cert_file, key_file

    def cleanup(self) -> None:
        import shutil
        shutil.rmtree(self._leaf_dir, ignore_errors=True)


class LocalRecordingMITMProxy:
    """
    Embedded CLI Recording MITM Proxy (default 127.0.0.1:8788).
    Records HTTP/1.1 & HTTPS CONNECT exchanges straight into `TrafficCaptureSession`
    and `terminator.db` (`traffic_evidence`), enforcing SSRF checks & `NoiseGovernor`.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8788,
        db: Optional[Any] = None,
        task_id: str = "default",
        traffic_session: Optional[TrafficCaptureSession] = None,
        noise_governor: Optional[Any] = None,
        authorized: bool = False,
        keys_dir: Optional[Union[str, Path]] = None,
        rewrite_rules: Optional[List[RewriteRule]] = None,
        upstream_verify: Union[bool, str] = True,
    ):
        self.host = host or "127.0.0.1"
        self.port = int(port)
        self.db = db
        self.task_id = task_id
        self.traffic_session = traffic_session or TrafficCaptureSession(db=db, task_id=task_id)
        self.noise_governor = noise_governor
        self.authorized = bool(authorized)
        self.ca = LocalCA(keys_dir=keys_dir)
        self.rewrite_rules: List[RewriteRule] = list(rewrite_rules or [])
        self.upstream_verify = upstream_verify
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.stats: Dict[str, Any] = {
            "requests_recorded": 0,
            "requests_blocked": 0,
            "rewrites_applied": 0,
            "connect_tunnels": 0,
        }

    @property
    def proxy_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def ca_cert_path(self) -> str:
        return str(self.ca.ca_cert_path)

    def to_proxy_config(self) -> ArtexProxyConfig:
        return ArtexProxyConfig(
            proxy_url=self.proxy_url,
            ca_cert_path=self.ca_cert_path,
            authorized=self.authorized,
            enabled=True,
        )

    def _validate_target(self, target_host: str) -> Tuple[bool, str]:
        from engine.safe_network_validator import is_explicit_loopback_host, validate_target_host
        from mcp_server import TargetAuthorizationGate

        clean = str(target_host or "").strip("[] ").lower()
        if not clean:
            return False, "Empty target host."
        is_loopback = is_explicit_loopback_host(clean)
        is_safe, reason = validate_target_host(clean, allow_private=is_loopback)
        if not is_safe:
            return False, reason
        if not self.authorized and not is_loopback:
            is_valid, auth_reason = TargetAuthorizationGate.validate_target(clean)
            if not is_valid:
                return False, f"Remote target '{clean}' requires explicit authorization: {auth_reason}"
        return True, "Validated safe target"

    def _apply_rewrites(self, phase: str, host: str, headers: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
        out = dict(headers)
        lower_map = {k.lower(): k for k in out}
        applied: List[str] = []
        for rule in self.rewrite_rules:
            if rule.phase == phase and rule.matches_host(host):
                existing_key = lower_map.get(rule.header_name.lower())
                if existing_key is not None and existing_key != rule.header_name:
                    out.pop(existing_key, None)
                out[rule.header_name] = rule.header_value
                lower_map[rule.header_name.lower()] = rule.header_name
                applied.append(rule.rule_id)
        if applied:
            with self._lock:
                self.stats["rewrites_applied"] += len(applied)
        return out, applied

    def _forward_http(
        self,
        method: str,
        url: str,
        req_headers: Dict[str, str],
        req_body: bytes,
    ) -> Tuple[int, Dict[str, str], bytes]:
        parsed = urlparse(url)
        if (parsed.scheme or "").lower() not in ("http", "https") or "\\" in url or "@" in (parsed.netloc or ""):
            with self._lock:
                self.stats["requests_blocked"] += 1
            raise PermissionError(f"MITM proxy rejected invalid/ambiguous URL '{url}'")
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        ok, reason = self._validate_target(host)
        if not ok:
            with self._lock:
                self.stats["requests_blocked"] += 1
            raise PermissionError(f"MITM proxy blocked destination '{host}': {reason}")

        if self.noise_governor is not None:
            sleep_on = getattr(self.noise_governor, "profile", "off") != "off"
            self.noise_governor.acquire_slot(host, sleep_enabled=sleep_on)

        # Strip hop-by-hop proxy headers
        clean_req_headers = {
            k: v for k, v in req_headers.items()
            if k.lower() not in ("proxy-connection", "proxy-authorization", "connection", "keep-alive", "transfer-encoding", "host", "content-length")
        }
        clean_req_headers, req_rewrites = self._apply_rewrites("request", host, clean_req_headers)

        with httpx.Client(timeout=15.0, verify=self.upstream_verify, follow_redirects=False, trust_env=False) as client:
            resp = client.request(method.upper(), url, headers=clean_req_headers, content=req_body or None)
            resp_headers = {
                k: v for k, v in resp.headers.items()
                if k.lower() not in ("transfer-encoding", "connection", "keep-alive", "content-encoding", "content-length")
            }
            resp_headers, resp_rewrites = self._apply_rewrites("response", host, resp_headers)
            if req_rewrites or resp_rewrites:
                resp_headers["X-RFCHunt-Rewrite-Provenance"] = ",".join(req_rewrites + resp_rewrites)

            backoff_sec = 0.0
            if self.noise_governor is not None and resp.status_code in (429, 503):
                backoff_sec = float(
                    self.noise_governor.record_backoff(host, resp.status_code, resp.headers.get("Retry-After")) or 0.0
                )

            raw_resp_body = resp.content
            self.traffic_session.record_exchange(
                method=method.upper(),
                url=url,
                host=host,
                port=port,
                request_headers=clean_req_headers,
                request_body=req_body.decode("utf-8", errors="replace") if req_body else "",
                status_code=resp.status_code,
                response_headers=resp_headers,
                response_body=raw_resp_body,
                content_encoding="identity",
                is_preview_only=False,
                source="mitm_proxy",
            )
            with self._lock:
                self.stats["requests_recorded"] += 1
            if (
                backoff_sec > 0.0
                and self.noise_governor is not None
                and getattr(self.noise_governor, "profile", "off") != "off"
            ):
                time.sleep(min(backoff_sec, 2.0))
            return resp.status_code, resp_headers, raw_resp_body

    def _build_handler(self):
        parent = self

        class _ProxyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _read_chunked_rfile(self) -> bytes:
                chunks: List[bytes] = []
                while True:
                    line = self.rfile.readline(65536)
                    if not line:
                        break
                    size_token = line.decode("latin-1", errors="replace").split(";", 1)[0].strip()
                    if not size_token:
                        continue
                    if size_token.startswith(("+", "-")):
                        break
                    try:
                        chunk_size = int(size_token, 16)
                    except ValueError:
                        break
                    if chunk_size < 0:
                        break
                    if chunk_size == 0:
                        while True:
                            trailer = self.rfile.readline(65536)
                            if not trailer or trailer in (b"\r\n", b"\n"):
                                break
                        break
                    data = self.rfile.read(chunk_size)
                    if data:
                        chunks.append(data)
                    self.rfile.readline(64)
                return b"".join(chunks)

            def _handle_http_request(self) -> None:
                target_url = self.path
                if not target_url.startswith(("http://", "https://")):
                    host_hdr = self.headers.get("Host") or ""
                    target_url = f"http://{host_hdr}{target_url}"

                te_hdr = self.headers.get("Transfer-Encoding") or ""
                if "chunked" in te_hdr.lower():
                    body = self._read_chunked_rfile()
                else:
                    try:
                        length = int(self.headers.get("Content-Length") or "0")
                    except ValueError:
                        length = 0
                    body = self.rfile.read(length) if length > 0 else b""
                req_hdrs = {k: v for k, v in self.headers.items()}

                try:
                    status, resp_hdrs, resp_body = parent._forward_http(self.command, target_url, req_hdrs, body)
                except PermissionError as pe:
                    err = str(pe).encode("utf-8")
                    self.send_response(403)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                    return
                except Exception as exc:
                    err = f"Proxy upstream error: {exc}".encode("utf-8")
                    self.send_response(502)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                    return

                self.send_response(status)
                for k, v in resp_hdrs.items():
                    self.send_header(k, v)
                if not (100 <= status < 200) and status not in (204, 304):
                    self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                if self.command != "HEAD" and not (100 <= status < 200) and status not in (204, 304):
                    self.wfile.write(resp_body)

            def do_CONNECT(self) -> None:
                host_port = self.path.strip()
                if host_port.startswith("[") and "]" in host_port:
                    rb_idx = host_port.index("]")
                    target_host = host_port[1:rb_idx]
                    rest_port = host_port[rb_idx + 1:]
                    if rest_port.startswith(":") and rest_port[1:].isdigit():
                        target_port = int(rest_port[1:])
                    else:
                        target_port = 443
                elif ":" in host_port:
                    target_host, raw_port = host_port.rsplit(":", 1)
                    target_port = int(raw_port) if raw_port.isdigit() else 443
                else:
                    target_host, target_port = host_port, 443

                ok, reason = parent._validate_target(target_host)
                if not ok:
                    with parent._lock:
                        parent.stats["requests_blocked"] += 1
                    err = f"MITM CONNECT blocked: {reason}".encode("utf-8")
                    self.send_response(403)
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                    return

                with parent._lock:
                    parent.stats["connect_tunnels"] += 1

                # Establish TLS MITM tunnel using dynamically minted leaf certificate
                self.send_response(200, "Connection Established")
                self.end_headers()
                self.close_connection = True

                try:
                    cert_file, key_file = parent.ca.get_leaf_cert(target_host)
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
                    tls_sock = ctx.wrap_socket(self.connection, server_side=True)
                    tls_sock.settimeout(10.0)
                    recv_buf = bytearray()
                    url_host = f"[{target_host}]" if ":" in target_host and not target_host.startswith("[") else target_host
                    try:
                        while True:
                            raw_req = self._read_single_http1_request(tls_sock, recv_buf)
                            if not raw_req:
                                break
                            method, req_path, req_hdrs, req_body = raw_req
                            full_url = f"https://{url_host}:{target_port}{req_path if req_path.startswith('/') else '/' + req_path}"
                            try:
                                status, resp_hdrs, resp_body = parent._forward_http(method, full_url, req_hdrs, req_body)
                            except PermissionError as pe:
                                err_b = str(pe).encode("utf-8")
                                tls_sock.sendall(
                                    f"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {len(err_b)}\r\nConnection: close\r\n\r\n".encode("latin-1")
                                    + (b"" if method == "HEAD" else err_b)
                                )
                                break
                            except Exception as u_exc:
                                err_b = f"Proxy upstream error: {u_exc}".encode("utf-8")
                                tls_sock.sendall(
                                    f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {len(err_b)}\r\nConnection: close\r\n\r\n".encode("latin-1")
                                    + (b"" if method == "HEAD" else err_b)
                                )
                                break
                            try:
                                reason_phrase = HTTPStatus(status).phrase
                            except ValueError:
                                reason_phrase = "OK"
                            conn_hdr = ""
                            for hk, hv in req_hdrs.items():
                                if hk.lower() == "connection":
                                    conn_hdr = hv.strip().lower()
                                    break
                            keep_alive = conn_hdr != "close"
                            resp_head = [f"HTTP/1.1 {status} {reason_phrase}"]
                            for k, v in resp_hdrs.items():
                                resp_head.append(f"{k}: {v}")
                            if not (100 <= status < 200) and status not in (204, 304):
                                resp_head.append(f"Content-Length: {len(resp_body)}")
                            resp_head.append(f"Connection: {'keep-alive' if keep_alive else 'close'}")
                            send_body = b"" if (method == "HEAD" or (100 <= status < 200) or status in (204, 304)) else resp_body
                            raw_out = ("\r\n".join(resp_head) + "\r\n\r\n").encode("latin-1", errors="replace") + send_body
                            tls_sock.sendall(raw_out)
                            if not keep_alive:
                                break
                    finally:
                        tls_sock.close()
                except Exception as exc:
                    logger.debug("MITM CONNECT session ended (%s:%s): %s", target_host, target_port, exc)

            @staticmethod
            def _decode_chunked_body(sock: socket.socket, initial: bytearray) -> Tuple[bytes, bytearray]:
                buf = bytearray(initial)
                out = bytearray()
                while True:
                    while b"\r\n" not in buf:
                        more = sock.recv(4096)
                        if not more:
                            return bytes(out), bytearray()
                        buf.extend(more)
                    nl_idx = buf.index(b"\r\n")
                    size_line = bytes(buf[:nl_idx]).decode("latin-1", errors="replace").split(";", 1)[0].strip()
                    del buf[: nl_idx + 2]
                    if size_line.startswith(("+", "-")):
                        return bytes(out), buf
                    try:
                        chunk_size = int(size_line, 16)
                    except ValueError:
                        return bytes(out), buf
                    if chunk_size < 0:
                        return bytes(out), buf
                    if chunk_size == 0:
                        # Consume trailing CRLF after last-chunk (and optional trailers)
                        while not buf.startswith(b"\r\n") and b"\r\n\r\n" not in buf:
                            more = sock.recv(4096)
                            if not more:
                                break
                            buf.extend(more)
                        if buf.startswith(b"\r\n"):
                            del buf[:2]
                        elif b"\r\n\r\n" in buf:
                            _, rest_after = bytes(buf).split(b"\r\n\r\n", 1)
                            buf = bytearray(rest_after)
                        return bytes(out), buf
                    while len(buf) < chunk_size + 2:
                        more = sock.recv(4096)
                        if not more:
                            out.extend(buf[:chunk_size])
                            return bytes(out), bytearray()
                        buf.extend(more)
                    out.extend(buf[:chunk_size])
                    del buf[: chunk_size + 2]

            @classmethod
            def _read_single_http1_request(
                cls,
                sock: socket.socket,
                buf: Optional[bytearray] = None,
            ) -> Optional[Tuple[str, str, Dict[str, str], bytes]]:
                work_buf = buf if buf is not None else bytearray()
                while b"\r\n\r\n" not in work_buf and len(work_buf) < 65536:
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    work_buf.extend(chunk)
                if b"\r\n\r\n" not in work_buf:
                    return None
                head_bytes, rest = bytes(work_buf).split(b"\r\n\r\n", 1)
                work_buf.clear()
                work_buf.extend(rest)
                lines = head_bytes.decode("latin-1", errors="replace").split("\r\n")
                if not lines:
                    return None
                parts = lines[0].split(" ", 2)
                if len(parts) < 2:
                    return None
                method, req_path = parts[0].upper(), parts[1]
                hdrs: Dict[str, str] = {}
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        hdrs[k.strip()] = v.strip()

                is_chunked = any(
                    k.lower() == "transfer-encoding" and "chunked" in v.lower()
                    for k, v in hdrs.items()
                )
                if is_chunked:
                    body_bytes, leftover = cls._decode_chunked_body(sock, work_buf)
                    work_buf.clear()
                    work_buf.extend(leftover)
                    return method, req_path, hdrs, body_bytes

                content_len = 0
                for k, v in hdrs.items():
                    if k.lower() == "content-length" and v.isdigit():
                        content_len = int(v)
                while len(work_buf) < content_len:
                    chunk = sock.recv(min(4096, content_len - len(work_buf)))
                    if not chunk:
                        break
                    work_buf.extend(chunk)
                if content_len:
                    body_bytes = bytes(work_buf[:content_len])
                    del work_buf[:content_len]
                else:
                    body_bytes = b""
                return method, req_path, hdrs, body_bytes

            do_GET = _handle_http_request
            do_POST = _handle_http_request
            do_PUT = _handle_http_request
            do_DELETE = _handle_http_request
            do_PATCH = _handle_http_request
            do_HEAD = _handle_http_request
            do_OPTIONS = _handle_http_request

        return _ProxyHandler

    def start(self) -> Tuple[str, int]:
        self._httpd = ThreadingHTTPServer((self.host, self.port), self._build_handler())
        self._httpd.daemon_threads = True
        actual_host, actual_port = self._httpd.server_address[:2]
        self.port = int(actual_port)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return str(actual_host), self.port

    def serve_forever(self) -> None:
        host, port = self.start()
        print(
            f"[+] RFCHunt CLI Recording MITM Proxy active on http://{host}:{port}\n"
            f"    - Local Root CA : {self.ca_cert_path}\n"
            f"    - Noise Profile : {self.noise_governor.profile if self.noise_governor else 'off'}\n"
            f"    - Authorized    : {self.authorized} (SSRF invariants enforced)\n"
            f"    Press Ctrl+C to stop."
        )
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        self.ca.cleanup()
