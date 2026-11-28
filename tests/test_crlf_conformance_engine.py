"""
Unit and Real Loopback HTTP Server Tests for Module 24 (CRLF / Header Conformance Auditor).
"""

import socket
import threading
from pathlib import Path
import pytest

from engine.crlf_desync_engine import (
    audit_nginx_configs,
    run_conformance_diagnostics,
    validate_canary_safety,
)


def _start_loopback_http_server(mode: str):
    """Spins up a real TCP loopback HTTP server (zero mocks) in a daemon thread."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(32)
    stop_evt = threading.Event()
    counter = {"n": 0}

    def _serve():
        srv.settimeout(0.2)
        while not stop_evt.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(1.0)
                data = conn.recv(4096).decode("latin-1", errors="replace")
                counter["n"] += 1
                first_line = data.splitlines()[0] if data else ""
                low = data.lower()

                if mode == "strict":
                    if "%0d" in low or "%0a" in low:
                        resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    elif "expect: rfchunt-invalid-expectation" in low:
                        resp = b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    elif "transfer-encoding: rfchunt-unknown-coding" in low:
                        resp = b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    elif "content-length: invalid_len" in low:
                        resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    else:
                        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                elif mode == "permissive":
                    # Accepts everything with 200 OK (fails RFC 9112 strict rejection)
                    if "%0d%0a" in low:
                        resp = (
                            b"HTTP/1.1 200 OK\r\nX-RFCHunt-Canary: 1\r\n"
                            b"Content-Length: 2\r\nConnection: close\r\n\r\nok"
                        )
                    else:
                        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                else:  # transient
                    if counter["n"] <= 3:
                        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    elif counter["n"] % 2 == 0:
                        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    else:
                        resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                conn.sendall(resp)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        try:
            srv.close()
        except OSError:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return port, stop_evt, t


def test_static_nginx_config_audit_detects_unsafe_uri_and_allows_safe(tmp_path: Path):
    unsafe_conf = tmp_path / "nginx.conf"
    unsafe_conf.write_text(
        """
        server {
            location /api/ {
                proxy_pass http://backend$uri;
                proxy_set_header X-Original-URI $document_uri;
            }
            location /redir/ {
                return 302 https://example.com$uri;
            }
            location /hdr/ {
                add_header X-Debug $arg_debug;
            }
        }
        """,
        encoding="utf-8",
    )
    rep = audit_nginx_configs(tmp_path)
    assert rep.files_scanned == 1
    rule_ids = {f.rule_id for f in rep.findings}
    assert "CRLF-NGINX-001" in rule_ids
    assert "CRLF-NGINX-002" in rule_ids
    assert "CRLF-NGINX-003" in rule_ids
    assert "CRLF-NGINX-004" in rule_ids
    assert "nginx_hardening" in rep.defensive_rules

    safe_dir = tmp_path / "safe"
    safe_dir.mkdir()
    (safe_dir / "nginx.conf").write_text(
        """
        server {
            location /api/ {
                proxy_pass http://backend;
                return 301 https://example.com$request_uri;
            }
        }
        """,
        encoding="utf-8",
    )
    safe_rep = audit_nginx_configs(safe_dir)
    assert safe_rep.files_scanned == 1
    assert len(safe_rep.findings) == 0


def test_canary_safety_guard_blocks_mutations_and_cookies():
    ok, _ = validate_canary_safety("GET", {"Host": "127.0.0.1"}, "/canary")
    assert ok is True

    ok_post, _ = validate_canary_safety("POST", {"Host": "127.0.0.1"}, "/canary")
    assert ok_post is False

    ok_cookie, _ = validate_canary_safety("GET", {"Cookie": "sid=abc"}, "/canary")
    assert ok_cookie is False


def test_loopback_strict_rfc9112_server_zero_findings():
    port, stop_evt, th = _start_loopback_http_server("strict")
    try:
        rep = run_conformance_diagnostics("127.0.0.1", port, trials=3)
        assert len(rep.findings) == 0
    finally:
        stop_evt.set()
        th.join(timeout=2.0)


def test_loopback_permissive_server_confirmed_multi_trial():
    port, stop_evt, th = _start_loopback_http_server("permissive")
    try:
        rep = run_conformance_diagnostics("127.0.0.1", port, trials=3)
        rule_ids = {f.rule_id for f in rep.findings}
        assert "CRLF-CONF-001" in rule_ids
        assert "CRLF-CONF-004" in rule_ids
        assert all(f.reproducibility == "ConfirmedMultiTrial" for f in rep.findings)
        assert all(f.trials_passed == 3 for f in rep.findings)
    finally:
        stop_evt.set()
        th.join(timeout=2.0)


def test_loopback_transient_server_downgraded():
    port, stop_evt, th = _start_loopback_http_server("transient")
    try:
        rep = run_conformance_diagnostics("127.0.0.1", port, trials=3)
        assert any(f.reproducibility == "NonReproducibleTransient" for f in rep.findings)
    finally:
        stop_evt.set()
        th.join(timeout=2.0)
