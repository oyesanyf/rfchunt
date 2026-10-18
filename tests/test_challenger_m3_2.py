"""
Empirical Adversarial Challenge Suite: Protocol Ruler Stress & Socket Verification
Agent: Challenger M3-2

Empirically challenges Protocol Ruler (protocol_ruler.py):
1. Stress-test socket cleanup: simulate server connection drops, resets (RST), FIN aborts,
   partial response disconnects, TLS aborts, and timeouts; verify zero open socket descriptors leaked.
2. Stress-test bracket calibration with custom small min_size (100, 300, 500) and verify accurate limit detection.
3. Stress-test sequence measurement with universally rejected sequences (HTTP 400, 413, 500, 0 at all sizes)
   and verify classification is REJECTED_OR_OVERSIZED (zero false expansions).
"""

import os
import re
import socket
import struct
import sys
import threading
import time
import unittest
from typing import Optional, List, Tuple
import psutil

from protocol_ruler import ProtocolRuler
from test_lab_server import TestLabServer


class EphemeralResetServer:
    """TCP Server that drops or resets incoming connections under controlled patterns."""

    def __init__(self, mode: str = "rst"):
        self.mode = mode  # "rst", "fin", "partial", "hang"
        self.sock: Optional[socket.socket] = None
        self.port: int = 0
        self.is_running: bool = False
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(64)
        self.is_running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

    def _run(self):
        while self.is_running:
            try:
                client, _ = self.sock.accept()
            except Exception:
                break
            t = threading.Thread(target=self._handle_conn, args=(client,), daemon=True)
            t.start()

    def _handle_conn(self, client: socket.socket):
        try:
            if self.mode == "rst":
                # TCP RST via SO_LINGER (l_onoff=1, l_linger=0)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                client.close()
            elif self.mode == "fin":
                # Drain incoming bytes then clean FIN
                client.settimeout(0.5)
                try:
                    client.recv(4096)
                except Exception:
                    pass
                client.close()
            elif self.mode == "partial":
                # Send truncated HTTP headers and immediately close
                try:
                    client.recv(4096)
                    client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npart")
                except Exception:
                    pass
                client.close()
            elif self.mode == "hang":
                # Keep socket open and silent until client times out
                time.sleep(2.0)
                client.close()
        except Exception:
            pass


class CustomLimitServer:
    """Socket server with configurable header limit and rejection triggers."""

    def __init__(self, limit: int, rejected_token: Optional[bytes] = None, reject_code: int = 400):
        self.limit = limit
        self.rejected_token = rejected_token
        self.reject_code = reject_code
        self.sock: Optional[socket.socket] = None
        self.port: int = 0
        self.is_running: bool = False
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(64)
        self.is_running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

    def _run(self):
        while self.is_running:
            try:
                client, _ = self.sock.accept()
            except Exception:
                break
            t = threading.Thread(target=self._handle_conn, args=(client,), daemon=True)
            t.start()

    def _handle_conn(self, client: socket.socket):
        client.settimeout(2.0)
        buffer = bytearray()
        try:
            while self.is_running:
                chunk = client.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)
                if b"\r\n\r\n" in buffer:
                    header_bytes = bytes(buffer).split(b"\r\n\r\n", 1)[0]
                    # Check for universally rejected token
                    if self.rejected_token and self.rejected_token in header_bytes:
                        if self.reject_code == 0:
                            # Drop connection
                            client.close()
                            return
                        resp = (
                            f"HTTP/1.1 {self.reject_code} Error\r\n"
                            f"Content-Type: text/plain\r\n"
                            f"Connection: close\r\n"
                            f"Content-Length: 15\r\n\r\n"
                            f"Universal Reject\n"
                        ).encode("latin-1")
                        client.sendall(resp)
                        break

                    # Check header length limit on "A" header
                    a_match = re.search(rb"(?i)\r\nA:\s*([^\r\n]*)", b"\r\n" + header_bytes)
                    if a_match:
                        a_payload = a_match.group(1)
                        if len(a_payload) > self.limit:
                            resp = (
                                b"HTTP/1.1 400 Bad Request\r\n"
                                b"Content-Type: text/plain\r\n"
                                b"Connection: close\r\n"
                                b"Content-Length: 17\r\n\r\n"
                                b"Header Too Large\n"
                            )
                            client.sendall(resp)
                            break
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 2\r\n\r\n"
                        b"OK"
                    )
                    client.sendall(resp)
                    break
        except Exception:
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass


class TestProtocolRulerEmpiricalChallenge(unittest.TestCase):
    """Adversarial stress-test cases challenging ProtocolRuler."""

    # -------------------------------------------------------------------------
    # Challenge Dimension 1: Socket Cleanup Under Drops and Resets
    # -------------------------------------------------------------------------

    def test_01_stress_socket_cleanup_tcp_rst(self):
        """Stress-test: 25 rapid TCP RST connections verify zero open socket descriptors leaked."""
        srv = EphemeralResetServer(mode="rst")
        srv.start()
        time.sleep(0.1)
        created_sockets: List[socket.socket] = []
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=0.5)
            orig_open = ruler._open_socket

            def tracking_open():
                s = orig_open()
                created_sockets.append(s)
                return s

            ruler._open_socket = tracking_open

            for i in range(25):
                code, resp, _ = ruler.send_probe(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                self.assertEqual(code, 0, f"Iteration {i} should return status 0 on RST")
                self.assertEqual(resp, b"")

            self.assertEqual(len(created_sockets), 25)
            for s in created_sockets:
                self.assertEqual(s.fileno(), -1, "Socket descriptor was not closed (-1)!")
        finally:
            srv.stop()

    def test_02_stress_socket_cleanup_fin_drop(self):
        """Stress-test: 25 rapid FIN connection drops verify zero open socket descriptors leaked."""
        srv = EphemeralResetServer(mode="fin")
        srv.start()
        time.sleep(0.1)
        created_sockets: List[socket.socket] = []
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=0.5)
            orig_open = ruler._open_socket

            def tracking_open():
                s = orig_open()
                created_sockets.append(s)
                return s

            ruler._open_socket = tracking_open

            for i in range(25):
                code, resp, _ = ruler.send_probe(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                self.assertEqual(code, 0)
                self.assertEqual(resp, b"")

            self.assertEqual(len(created_sockets), 25)
            for s in created_sockets:
                self.assertEqual(s.fileno(), -1, "Socket descriptor was not closed (-1)!")
        finally:
            srv.stop()

    def test_03_stress_socket_cleanup_partial_response(self):
        """Stress-test: Partial response mid-stream truncation properly closes client socket."""
        srv = EphemeralResetServer(mode="partial")
        srv.start()
        time.sleep(0.1)
        created_sockets: List[socket.socket] = []
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=0.5)
            orig_open = ruler._open_socket

            def tracking_open():
                s = orig_open()
                created_sockets.append(s)
                return s

            ruler._open_socket = tracking_open

            for i in range(25):
                code, resp, _ = ruler.send_probe(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                # Either 0 or partial handled, but must close socket
                self.assertIn(code, (0, 200))

            self.assertEqual(len(created_sockets), 25)
            for s in created_sockets:
                self.assertEqual(s.fileno(), -1, "Socket descriptor was not closed (-1)!")
        finally:
            srv.stop()

    def test_04_stress_socket_cleanup_timeout(self):
        """Stress-test: Server hang causing read timeout properly closes client socket."""
        srv = EphemeralResetServer(mode="hang")
        srv.start()
        time.sleep(0.1)
        created_sockets: List[socket.socket] = []
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=0.2)
            orig_open = ruler._open_socket

            def tracking_open():
                s = orig_open()
                created_sockets.append(s)
                return s

            ruler._open_socket = tracking_open

            for i in range(10):
                code, resp, _ = ruler.send_probe(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                self.assertEqual(code, 0)

            self.assertEqual(len(created_sockets), 10)
            for s in created_sockets:
                self.assertEqual(s.fileno(), -1, "Socket descriptor was not closed on timeout!")
        finally:
            srv.stop()

    def test_05_stress_socket_cleanup_tls_handshake_abort(self):
        """Stress-test: TLS handshake failure against plain server closes raw socket cleanly."""
        srv = EphemeralResetServer(mode="rst")
        srv.start()
        time.sleep(0.1)
        raw_sockets: List[socket.socket] = []
        orig_conn = socket.create_connection

        def tracking_create_connection(*args, **kwargs):
            s = orig_conn(*args, **kwargs)
            raw_sockets.append(s)
            return s

        socket.create_connection = tracking_create_connection
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, use_tls=True, timeout=0.5)
            for i in range(15):
                code, _, _ = ruler.send_probe(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                self.assertEqual(code, 0)

            self.assertEqual(len(raw_sockets), 15)
            for s in raw_sockets:
                self.assertEqual(s.fileno(), -1, "Raw socket descriptor leaked on TLS wrap failure!")
        finally:
            socket.create_connection = orig_conn
            srv.stop()

    def test_06_verify_psutil_zero_socket_descriptors_leaked(self):
        """Verify process-level socket count does not accumulate active connections to server after 50 failure probes."""
        srv = EphemeralResetServer(mode="rst")
        srv.start()
        time.sleep(0.1)
        proc = psutil.Process()
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=0.2)
            # Run 50 rapid probes
            for _ in range(50):
                ruler.send_probe(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")

            # Verify no ESTABLISHED or open connections remain to target server
            remaining_active = [
                c for c in proc.net_connections()
                if c.raddr and c.raddr.port == srv.port and c.status == "ESTABLISHED"
            ]
            self.assertEqual(len(remaining_active), 0, f"Leaked active socket connections to target server: {remaining_active}")
        finally:
            srv.stop()

    # -------------------------------------------------------------------------
    # Challenge Dimension 2: Bracket Calibration with Small min_size (100, 300, 500)
    # -------------------------------------------------------------------------

    def test_07_calibrate_small_min_size_100_limit_100(self):
        """Validates bracket calibration with min_size=100 and limit at exactly 100 bytes."""
        srv = CustomLimitServer(limit=100)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            limit = ruler.calibrate_baseline_limit(min_size=100, max_size=500)
            self.assertEqual(limit, 100)
        finally:
            srv.stop()

    def test_08_calibrate_small_min_size_100_limit_250(self):
        """Validates bracket calibration with min_size=100 and limit at 250 bytes."""
        srv = CustomLimitServer(limit=250)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            limit = ruler.calibrate_baseline_limit(min_size=100, max_size=600)
            self.assertEqual(limit, 250)
        finally:
            srv.stop()

    def test_09_calibrate_small_min_size_300_limit_300(self):
        """Validates bracket calibration with min_size=300 and limit at exactly 300 bytes."""
        srv = CustomLimitServer(limit=300)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            limit = ruler.calibrate_baseline_limit(min_size=300, max_size=1000)
            self.assertEqual(limit, 300)
        finally:
            srv.stop()

    def test_10_calibrate_small_min_size_300_limit_475(self):
        """Validates bracket calibration with min_size=300 and limit at 475 bytes."""
        srv = CustomLimitServer(limit=475)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            limit = ruler.calibrate_baseline_limit(min_size=300, max_size=1000)
            self.assertEqual(limit, 475)
        finally:
            srv.stop()

    def test_11_calibrate_small_min_size_500_limit_500(self):
        """Validates bracket calibration with min_size=500 and limit at exactly 500 bytes."""
        srv = CustomLimitServer(limit=500)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            limit = ruler.calibrate_baseline_limit(min_size=500, max_size=2000)
            self.assertEqual(limit, 500)
        finally:
            srv.stop()

    def test_12_calibrate_small_min_size_500_limit_850(self):
        """Validates bracket calibration with min_size=500 and limit at 850 bytes."""
        srv = CustomLimitServer(limit=850)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            limit = ruler.calibrate_baseline_limit(min_size=500, max_size=2000)
            self.assertEqual(limit, 850)
        finally:
            srv.stop()

    def test_13_calibrate_limit_below_min_size_returns_none(self):
        """Validates that when server rejects requests even at min_size, None is returned."""
        srv = CustomLimitServer(limit=80)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            limit = ruler.calibrate_baseline_limit(min_size=100, max_size=500)
            self.assertIsNone(limit)
        finally:
            srv.stop()

    def test_14_calibrate_limit_above_max_size_returns_none(self):
        """Validates that when server accepts requests through max_size, None is returned."""
        srv = CustomLimitServer(limit=2000)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            limit = ruler.calibrate_baseline_limit(min_size=100, max_size=500)
            self.assertIsNone(limit)
        finally:
            srv.stop()

    # -------------------------------------------------------------------------
    # Challenge Dimension 3: Sequence Measurement with Universally Rejected Sequences
    # -------------------------------------------------------------------------

    def test_15_sequence_universally_rejected_http_400(self):
        """Validates that sequence universally rejected with 400 is classified as REJECTED_OR_OVERSIZED."""
        srv = CustomLimitServer(limit=1000, rejected_token=b"FORBIDDEN_400", reject_code=400)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            res = ruler.measure_sequence_transformation(
                name="Forbidden 400",
                sequence_bytes=b"FORBIDDEN_400",
                baseline_limit=1000,
                search_radius=64,
            )
            self.assertEqual(res["classification"], "REJECTED_OR_OVERSIZED")
            self.assertIsNone(res["delta_bytes"])
            self.assertIsNone(res["mutated_limit"])
            self.assertEqual(res["code_ok"], 400)
            self.assertIsNone(res["code_err"])
            self.assertNotIn("EXPANSION", res["classification"])
        finally:
            srv.stop()

    def test_16_sequence_universally_rejected_http_413(self):
        """Validates that sequence universally rejected with 413 is classified as REJECTED_OR_OVERSIZED."""
        srv = CustomLimitServer(limit=1000, rejected_token=b"FORBIDDEN_413", reject_code=413)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            res = ruler.measure_sequence_transformation(
                name="Forbidden 413",
                sequence_bytes=b"FORBIDDEN_413",
                baseline_limit=1000,
                search_radius=64,
            )
            self.assertEqual(res["classification"], "REJECTED_OR_OVERSIZED")
            self.assertIsNone(res["delta_bytes"])
            self.assertIsNone(res["mutated_limit"])
            self.assertEqual(res["code_ok"], 413)
        finally:
            srv.stop()

    def test_17_sequence_universally_rejected_http_500(self):
        """Validates that sequence universally rejected with 500 is classified as REJECTED_OR_OVERSIZED."""
        srv = CustomLimitServer(limit=1000, rejected_token=b"FORBIDDEN_500", reject_code=500)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            res = ruler.measure_sequence_transformation(
                name="Forbidden 500",
                sequence_bytes=b"FORBIDDEN_500",
                baseline_limit=1000,
                search_radius=64,
            )
            self.assertEqual(res["classification"], "REJECTED_OR_OVERSIZED")
            self.assertIsNone(res["delta_bytes"])
            self.assertIsNone(res["mutated_limit"])
            self.assertEqual(res["code_ok"], 500)
        finally:
            srv.stop()

    def test_18_sequence_universally_rejected_connection_drop(self):
        """Validates that sequence triggering immediate connection drop (0) is classified as REJECTED_OR_OVERSIZED."""
        srv = CustomLimitServer(limit=1000, rejected_token=b"DROP_TOKEN", reject_code=0)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            res = ruler.measure_sequence_transformation(
                name="Drop Token",
                sequence_bytes=b"DROP_TOKEN",
                baseline_limit=1000,
                search_radius=64,
            )
            self.assertEqual(res["classification"], "REJECTED_OR_OVERSIZED")
            self.assertIsNone(res["delta_bytes"])
            self.assertIsNone(res["mutated_limit"])
            self.assertEqual(res["code_ok"], 0)
        finally:
            srv.stop()

    def test_19_audit_summary_excludes_rejected_from_expansions_and_contractions(self):
        """Validates that run_comprehensive_audit excludes REJECTED_OR_OVERSIZED from expansions and contractions."""
        srv = CustomLimitServer(limit=1500, rejected_token=b"ALWAYS_REJECT", reject_code=400)
        srv.start()
        time.sleep(0.1)
        try:
            ruler = ProtocolRuler(host="127.0.0.1", port=srv.port, timeout=1.0)
            custom_seqs = [
                ("Valid Verbatim", b"NORMAL", "Valid sequence"),
                ("Always Reject 400", b"ALWAYS_REJECT", "Rejected sequence"),
            ]
            report = ruler.run_comprehensive_audit(custom_sequences=custom_seqs, max_size=2000)
            self.assertTrue(report["success"])
            self.assertEqual(report["baseline_limit"], 1500)
            # Verify rejected sequence is not in expansions or contractions
            exp_names = [e["name"] for e in report["expansions"]]
            con_names = [c["name"] for c in report["contractions"]]
            self.assertNotIn("Always Reject 400", exp_names)
            self.assertNotIn("Always Reject 400", con_names)
            # Find finding entry
            entry = next(f for f in report["findings"] if f["name"] == "Always Reject 400")
            self.assertEqual(entry["classification"], "REJECTED_OR_OVERSIZED")
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
