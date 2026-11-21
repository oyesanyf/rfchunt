"""
Tests for Pillar 2: Embedded Pure-CLI Recording MITM Proxy (`LocalRecordingMITMProxy`,
`LocalCA`, `RewriteRule`, SSRF fail-closed) and Surface/Session Importers
(`import_openapi_spec`, `import_har_file`, `load_scope_file`, `load_auth_profiles`).
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
import yaml

from database import Database
from engine.artex_bridge import TrafficCaptureSession
from engine.dual_graph_engine import DualGraphAttackEngine, NoiseGovernor
from engine.local_mitm_proxy import LocalCA, LocalRecordingMITMProxy, RewriteRule
from engine.session_loader import (
    import_har_file,
    import_openapi_spec,
    load_auth_profiles,
    load_scope_file,
)


class _EchoTargetServer:
    def __init__(self) -> None:
        self.received_headers = []
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                hdrs = {k.lower(): v for k, v in self.headers.items()}
                parent.received_headers.append(hdrs)
                body = json.dumps({"echo_path": self.path, "headers": hdrs}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def test_local_ca_generates_root_and_leaf_certs(tmp_path):
    ca_dir = tmp_path / "keys"
    ca = LocalCA(keys_dir=ca_dir)
    assert Path(ca.ca_cert_path).is_file()
    assert Path(ca.ca_key_path).is_file()
    assert "BEGIN CERTIFICATE" in Path(ca.ca_cert_path).read_text(encoding="utf-8")

    cert_p, key_p = ca.get_leaf_cert("localhost")
    assert Path(cert_p).is_file()
    assert Path(key_p).is_file()
    # Second call reuses cached cert
    cert_p2, key_p2 = ca.get_leaf_cert("localhost")
    assert cert_p == cert_p2 and key_p == key_p2
    ca.cleanup()


def test_local_recording_mitm_proxy_http_rewrite_noise_and_ssrf_block(tmp_path):
    target = _EchoTargetServer().start()
    db = Database(":memory:")
    session = TrafficCaptureSession(db=db, task_id="MITM-TEST-1")
    governor = NoiseGovernor(profile="quiet")
    proxy = LocalRecordingMITMProxy(
        host="127.0.0.1",
        port=0,
        keys_dir=tmp_path / "keys",
        traffic_session=session,
        noise_governor=governor,
        rewrite_rules=[
            RewriteRule(rule_id="add_marker", phase="request", header_name="X-RFCHunt-Marker", header_value="verified-42")
        ],
        authorized=True,
    )
    proxy.start()
    try:
        assert Path(proxy.ca_cert_path).is_file()
        assert proxy.port > 0

        # 1. Proxied HTTP request to loopback target succeeds, rewrites headers, and records to DB
        with httpx.Client(proxy=proxy.proxy_url, timeout=8.0) as client:
            resp = client.get(f"http://127.0.0.1:{target.port}/api/check")
            assert resp.status_code == 200
            data = resp.json()
            assert data["echo_path"] == "/api/check"
            assert data["headers"].get("x-rfchunt-marker") == "verified-42"
            assert "add_marker" in resp.headers.get("X-RFCHunt-Rewrite-Provenance", "")

            # 2. SSRF fail-closed block against cloud metadata IP (169.254.169.254)
            blocked = client.get("http://169.254.169.254/latest/meta-data/")
            assert blocked.status_code == 403

        # 3. Raw CONNECT tunnel to 169.254.169.254:443 must also fail-closed with 403
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=5.0) as sock:
            sock.sendall(b"CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: 169.254.169.254:443\r\n\r\n")
            raw_reply = sock.recv(1024).decode("latin-1", errors="replace")
            assert "403" in raw_reply

        # 4. Verify recorded exchange persisted in traffic_evidence
        recorded = db.list_traffic_evidence(task_id="MITM-TEST-1")
        assert len(recorded) >= 1
        rec = recorded[0]
        assert rec["status_code"] == 200
        assert "/api/check" in rec["url"]
        assert "add_marker" in rec["response_headers"].get("X-RFCHunt-Rewrite-Provenance", "")
    finally:
        proxy.stop()
        target.stop()
        db.close()


def test_import_openapi_har_scope_and_auth_profiles(tmp_path):
    # 1. OpenAPI 3.0 YAML spec
    openapi_file = tmp_path / "openapi.yaml"
    openapi_doc = {
        "openapi": "3.0.3",
        "info": {"title": "Governance Service", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.local:8443"}],
        "paths": {
            "/internal/service": {
                "get": {"summary": "Service governance route"},
                "post": {"summary": "Execute service action"},
            },
            "/api/chat": {
                "post": {"summary": "AI chat completion sink"},
            },
        },
    }
    openapi_file.write_text(yaml.safe_dump(openapi_doc), encoding="utf-8")

    # 2. HAR 1.2 JSON file
    har_file = tmp_path / "capture.har"
    har_doc = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.local:8443/v1/profile",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer har-captured-token-999"},
                            {"name": "Accept", "value": "application/json"},
                        ],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"text": '{"user":"alice"}'},
                    },
                }
            ],
        }
    }
    har_file.write_text(json.dumps(har_doc), encoding="utf-8")

    # 3. Scope YAML file
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        yaml.safe_dump(
            {
                "allow_hosts": ["api.example.local"],
                "deny_hosts": ["billing.internal.local"],
                "deny_routes": ["/logout", "/delete-account"],
            }
        ),
        encoding="utf-8",
    )

    # 4. Multi-role Auth Profiles YAML file
    auth_file = tmp_path / "auth.yaml"
    auth_file.write_text(
        yaml.safe_dump(
            {
                "profiles": {
                    "end_user_oidc": {
                        "role": "end_user_oidc",
                        "auth_type": "bearer",
                        "token": "eyJ.user.token",
                    },
                    "service_account": {
                        "role": "service",
                        "auth_type": "header",
                        "header_name": "X-Service-Token",
                        "token": "svc-secret-123",
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    db = Database(":memory:")
    try:
        scope = load_scope_file(scope_file)
        assert "api.example.local" in scope["allow_hosts"]
        assert "billing.internal.local" in scope["deny_hosts"]
        assert "/logout" in scope["deny_routes"]

        profiles = load_auth_profiles(auth_file)
        assert "end_user_oidc" in profiles and "service_account" in profiles
        assert profiles["end_user_oidc"].build_headers()["Authorization"] == "Bearer eyJ.user.token"
        assert profiles["service_account"].build_headers()["X-Service-Token"] == "svc-secret-123"

        eng = DualGraphAttackEngine(
            db=db,
            reports_dir=tmp_path / "reports",
            scope_hosts=set(scope["allow_hosts"]),
        )
        oa_res = import_openapi_spec(openapi_file, asset_graph=eng.asset_graph)
        assert oa_res["endpoints_imported"] >= 3
        assert oa_res["ai_sinks_imported"] >= 1

        har_res = import_har_file(har_file, asset_graph=eng.asset_graph, traffic_session=eng.traffic_session)
        assert har_res["entries_processed"] == 1
        assert har_res["extracted_auth_headers"].get("Authorization") == "Bearer har-captured-token-999"
        assert len(db.list_traffic_evidence(task_id=eng.task_id)) == 1

        # Verify coverage ledger starts at 0% tested and rises after anchoring
        cov_before = eng.compute_coverage_ledger()
        assert cov_before["total_in_scope_assets"] >= 4
        assert cov_before["tested_assets"] == 0

        first_asset_id = cov_before["assets"][0]["asset_id"]
        eng.exploration_graph.add_fact("FACT-1", "Verified endpoint", anchored_asset_id=first_asset_id)
        cov_after = eng.compute_coverage_ledger()
        assert cov_after["tested_assets"] == 1
        assert cov_after["coverage_pct"] > 0.0
    finally:
        db.close()


def test_session_loader_openapi_explicit_host_har_cookies_and_base64(tmp_path):
    import base64
    from engine.dual_graph_engine import AssetGraph

    oa = tmp_path / "oa.json"
    oa.write_text(
        json.dumps({
            "openapi": "3.0.3",
            "servers": [{"url": "https://remote.example.com:9443"}],
            "paths": {"/internal/check": {"get": {"summary": "Check"}}},
        }),
        encoding="utf-8",
    )
    ag = AssetGraph()
    oa_res = import_openapi_spec(oa, asset_graph=ag, host="127.0.0.1", port=8181)
    assert oa_res["host"] == "127.0.0.1"
    assert oa_res["port"] == 8181

    har = tmp_path / "cookies.har"
    b64_body = base64.b64encode(b'{"secret":"decoded_b64_ok"}').decode("ascii")
    har.write_text(
        json.dumps({
            "log": {
                "version": "1.2",
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": "http://127.0.0.1:8181/internal/check",
                        "headers": [],
                        "cookies": [{"name": "sid", "value": "cookieval-42"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {"text": b64_body, "encoding": "base64"},
                    },
                }],
            }
        }),
        encoding="utf-8",
    )
    db = Database(":memory:")
    try:
        sess = TrafficCaptureSession(db=db, task_id="HAR-B64")
        h_res = import_har_file(har, asset_graph=ag, traffic_session=sess)
        assert "Cookie" in h_res["extracted_auth_headers"]
        assert "cookieval-42" in h_res["extracted_auth_headers"]["Cookie"]
        recs = db.list_traffic_evidence(task_id="HAR-B64")
        assert len(recs) == 1
        assert "decoded_b64_ok" in base64.b64decode(recs[0]["response_body_b64"]).decode("utf-8")
    finally:
        db.close()


def test_mcp_artex_import_surface_over_http_and_sse_with_scope(tmp_path):
    from mcp_server import MCPHttpServer, TerminatorMCPServer

    db_path = tmp_path / "mcp_surface.db"
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(yaml.safe_dump({"allow_hosts": ["127.0.0.1"], "deny_hosts": ["blocked.local"]}), encoding="utf-8")
    oa_file = tmp_path / "spec.json"
    oa_file.write_text(
        json.dumps({
            "openapi": "3.0.3",
            "servers": [{"url": "http://blocked.local:8080"}],
            "paths": {"/admin/op": {"get": {"summary": "Admin op"}}},
        }),
        encoding="utf-8",
    )

    with TerminatorMCPServer(db_path=str(db_path)) as srv:
        http_srv = MCPHttpServer(srv, host="127.0.0.1", port=0)
        http_srv.start()
        try:
            base = f"http://127.0.0.1:{http_srv.port}"
            # 1. Streamable HTTP (/http)
            r_http = httpx.post(
                f"{base}/http",
                json={
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "artex_import_surface",
                        "arguments": {
                            "scope_path": str(scope_file),
                            "openapi_path": str(oa_file),
                            "host": "blocked.local",
                            "port": 8080,
                        },
                    },
                },
                timeout=10.0,
            )
            assert r_http.status_code == 200
            body_http = json.loads(r_http.json()["result"]["content"][0]["text"])
            assert body_http["total_assets_ingested"] >= 3

            # Verify scope_hosts / deny_hosts applied to persisted AssetGraph nodes
            nodes = srv.db.get_dual_graph_nodes(graph_type="ASSET")
            ep_nodes = [n for n in nodes if n["node_type"] == "ENDPOINT"]
            assert ep_nodes and ep_nodes[0]["attributes"]["in_scope"] is False

            # 2. Legacy SSE (/sse + /message)
            with httpx.Client(timeout=10.0) as client:
                with client.stream("GET", f"{base}/sse") as sse_stream:
                    msg_ep = None
                    for line in sse_stream.iter_lines():
                        if line.startswith("data:"):
                            msg_ep = line.split("data:", 1)[1].strip()
                            break
                    assert msg_ep and msg_ep.startswith("/message?sessionId=")
                    r_msg = client.post(
                        f"{base}{msg_ep}",
                        json={"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "artex_approval_history", "arguments": {"limit": 5}}},
                    )
                    assert r_msg.status_code in (200, 202)
        finally:
            http_srv.stop()


def test_local_ca_strict_python313_tls_connect_keepalive_and_plain_chunked(tmp_path):
    import datetime as _dt
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    keys_dir = tmp_path / "keys_strict"
    keys_dir.mkdir(parents=True, exist_ok=True)

    # 1. Pre-seed a legacy CA cert lacking SubjectKeyIdentifier and verify LocalCA regenerates it
    legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Legacy-No-SKI")])
    legacy_cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(legacy_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(legacy_key, hashes.SHA256())
    )
    (keys_dir / "rfchunt_ca.key").write_bytes(
        legacy_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    )
    (keys_dir / "rfchunt_ca.crt").write_bytes(legacy_cert.public_bytes(serialization.Encoding.PEM))

    ca = LocalCA(keys_dir=keys_dir)
    try:
        ca_cert = x509.load_pem_x509_certificate(Path(ca.ca_cert_path).read_bytes())
        assert ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier) is not None
        assert ca_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier) is not None
        leaf_crt_p, leaf_key_p = ca.get_leaf_cert("127.0.0.1")
        leaf_cert = x509.load_pem_x509_certificate(Path(leaf_crt_p).read_bytes())
        assert leaf_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier) is not None
        assert leaf_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier) is not None
        assert leaf_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
        assert ExtendedKeyUsageOID.SERVER_AUTH in leaf_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    finally:
        ca.cleanup()

    # 2. Local HTTPS server + plain HTTP server behind LocalRecordingMITMProxy
    received_bodies = []

    class _UpstreamHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def _handle(self):
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length) if length > 0 else b""
            received_bodies.append((self.command, self.path, body.decode("utf-8", errors="replace")))
            out = json.dumps({"method": self.command, "path": self.path, "body": body.decode("utf-8", errors="replace")}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_GET = _handle
        do_POST = _handle

    https_srv = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    https_port = https_srv.server_address[1]
    srv_cert, srv_key = LocalCA(keys_dir=tmp_path / "srv_keys").get_leaf_cert("127.0.0.1")
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(certfile=str(srv_cert), keyfile=str(srv_key))
    https_srv.socket = srv_ctx.wrap_socket(https_srv.socket, server_side=True)
    https_t = threading.Thread(target=https_srv.serve_forever, daemon=True)
    https_t.start()

    plain_srv = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    plain_port = plain_srv.server_address[1]
    plain_t = threading.Thread(target=plain_srv.serve_forever, daemon=True)
    plain_t.start()

    db = Database(":memory:")
    session = TrafficCaptureSession(db=db, task_id="MITM-STRICT-TLS")
    proxy = LocalRecordingMITMProxy(
        host="127.0.0.1",
        port=0,
        keys_dir=keys_dir,
        traffic_session=session,
        authorized=True,
        upstream_verify=False,
    )
    proxy.start()
    try:
        # Strict default Python 3.13 SSL verification (VERIFY_X509_STRICT) + keep-alive GET & POST
        with httpx.Client(proxy=proxy.proxy_url, verify=proxy.ca_cert_path, timeout=10.0) as client:
            r1 = client.get(f"https://127.0.0.1:{https_port}/tls-keepalive-1")
            assert r1.status_code == 200
            r2 = client.post(f"https://127.0.0.1:{https_port}/tls-keepalive-2", json={"ok": True})
            assert r2.status_code == 200

        # Raw plain HTTP Transfer-Encoding: chunked request through proxy
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=5.0) as sock:
            chunked_req = (
                f"POST http://127.0.0.1:{plain_port}/plain-chunked HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{plain_port}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n\r\n"
                f"4\r\ntest\r\n5\r\n-body\r\n0\r\n\r\n"
            ).encode("ascii")
            sock.sendall(chunked_req)
            raw_resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw_resp += chunk
        assert "200 OK" in raw_resp.decode("latin-1", errors="replace")
        assert any(path == "/plain-chunked" and body == "test-body" for _, path, body in received_bodies)

        ev = db.list_traffic_evidence(task_id="MITM-STRICT-TLS")
        assert len(ev) >= 3
        assert any("/tls-keepalive-1" in r["url"] for r in ev)
        assert any("/plain-chunked" in r["url"] and r["request_body"] == "test-body" for r in ev)
    finally:
        proxy.stop()
        https_srv.shutdown()
        https_srv.server_close()
        plain_srv.shutdown()
        plain_srv.server_close()
        db.close()


def test_har_session_auth_profile_visibility_in_unified_scan(tmp_path, monkeypatch):
    from engine.mantis_integrator import run_unified_all_scans

    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    seen_auth_headers = []

    class _HarTargetHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            seen_auth_headers.append((self.path, auth))
            if self.path.startswith("/internal/service"):
                if not auth:
                    body = b'{"error":"unauthorized"}'
                    self.send_response(401)
                else:
                    body = b'{"status":"granted","scope":"governance-admin"}'
                    self.send_response(200)
            else:
                body = b"Hello, world!"
                self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _HarTargetHandler)
    srv_t = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_t.start()
    srv_port = srv.server_address[1]

    repo = tmp_path / "har_repo"
    repo.mkdir()
    (repo / "service.py").write_text(
        "@app.get('/internal/service')\ndef svc(authorization: str):\n    return verify_oidc_token(authorization)\n",
        encoding="utf-8",
    )
    har_file = tmp_path / "session.har"
    har_file.write_text(
        json.dumps({
            "log": {
                "version": "1.2",
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": f"http://127.0.0.1:{srv_port}/internal/service",
                        "headers": [{"name": "Authorization", "value": "Bearer har-live-token-777"}],
                    },
                    "response": {"status": 200, "headers": [], "content": {"text": "{}"}},
                }],
            }
        }),
        encoding="utf-8",
    )
    db = Database(":memory:")
    try:
        res = run_unified_all_scans(
            repo=str(repo),
            host="127.0.0.1",
            port=srv_port,
            use_tls=False,
            authorized=True,
            depth=30,
            db=db,
            reports_dir=str(tmp_path / "reports"),
            import_har=str(har_file),
            artex_live=True,
            artex_workers=2,
            quiet=True,
        )
        assert any(auth == "Bearer har-live-token-777" for _, auth in seen_auth_headers)
        assert res["attack_chaining"]["poe_breakdown"].get("VERIFIED_EXPLOIT", 0) >= 1
    finally:
        srv.shutdown()
        srv.server_close()
        db.close()
