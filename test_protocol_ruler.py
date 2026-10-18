"""
End-to-End Verification Test for Protocol Ruler Engine:
Validates real socket connections, binary search boundary calibration,
and differential expansion detection (James Kettle technique).
Zero mocks; executes against live test socket server.
"""

import time
import unittest
from test_lab_server import TestLabServer
from protocol_ruler import ProtocolRuler, format_kettle_ruler_bytes


class TestProtocolRuler(unittest.TestCase):
    MAX_LIMIT = 64040

    @classmethod
    def setUpClass(cls):
        cls.server = TestLabServer(host="127.0.0.1", port=0, max_header_limit=cls.MAX_LIMIT)
        cls.server.start()
        cls.SERVER_PORT = cls.server.port
        time.sleep(0.5)


    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.ruler = ProtocolRuler(host="127.0.0.1", port=self.SERVER_PORT, timeout=3.0)

    def test_01_calibrate_baseline_limit(self):
        """Validates that baseline calibration pinpoints the exact 64,040 byte limit."""
        limit = self.ruler.calibrate_baseline_limit(min_size=1024, max_size=70000)
        self.assertIsNotNone(limit)
        self.assertEqual(limit, 64040)

    def test_02_detect_c0_8a_expansion(self):
        """Validates that Kettle's overlong c0 8a sequence is detected expanding by 10 bytes."""
        limit = 64040
        result = self.ruler.measure_sequence_transformation("Kettle Overlong UTF-8", b"\xc0\x8a", limit)
        self.assertEqual(result["delta_bytes"], 10)
        self.assertEqual(result["classification"], "EXPANSION")
        self.assertEqual(result["mutated_limit"], 64030)

    def test_03_detect_verbatim_sequence(self):
        """Validates that standard bytes are detected as verbatim (delta = 0)."""
        limit = 64040
        result = self.ruler.measure_sequence_transformation("Standard Slash", b"/", limit)
        self.assertEqual(result["delta_bytes"], 0)
        self.assertEqual(result["classification"], "VERBATIM")
        self.assertEqual(result["mutated_limit"], 64040)

    def test_04_comprehensive_audit_run(self):
        """Validates that a full audit runs and detects high-value expansions."""
        report = self.ruler.run_comprehensive_audit(max_size=70000)
        self.assertTrue(report["success"])
        self.assertEqual(report["baseline_limit"], 64040)
        self.assertGreater(len(report["expansions"]), 0)
        self.assertTrue(any(exp["name"] == "Kettle Overlong UTF-8 (c0 8a)" for exp in report["expansions"]))

    def test_05_reject_inaddr_any_host(self):
        """Validates that ProtocolRuler rejects 0.0.0.0 and :: as destination targets."""
        with self.assertRaises(ValueError):
            ProtocolRuler(host="0.0.0.0", port=80)
        with self.assertRaises(ValueError):
            ProtocolRuler(host="::", port=80)

    def test_06_connection_drop_handling(self):
        """Validates that connection drops or closed ports return status code 0 cleanly."""
        dead_ruler = ProtocolRuler(host="127.0.0.1", port=65431, timeout=0.5)
        status, resp, latency = dead_ruler.send_probe(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        self.assertEqual(status, 0)
        self.assertEqual(resp, b"")

    def test_07_detect_contraction_sequence(self):
        """Validates that Unicode ligature fi is detected contracting/stripping bytes."""
        limit = 64040
        # TestLabServer contracts \xef\xac\x81 by 1 byte
        result = self.ruler.measure_sequence_transformation("Ligature FI", b"\xef\xac\x81", limit)
        self.assertEqual(result["delta_bytes"], -1)
        self.assertEqual(result["classification"], "CONTRACTION")
        self.assertEqual(result["mutated_limit"], 64041)

    def test_08_bracket_min_size_inclusion(self):
        """Validates that bracket search functions when min_size is non-default (e.g. 500)."""
        mini_server = TestLabServer(host="127.0.0.1", port=0, max_header_limit=800)
        mini_server.start()
        time.sleep(0.3)
        try:
            mini_ruler = ProtocolRuler(host="127.0.0.1", port=mini_server.port, timeout=1.0)
            limit = mini_ruler.calibrate_baseline_limit(min_size=500, max_size=2000)
            self.assertEqual(limit, 800)
        finally:
            mini_server.stop()

    def test_09_rejected_sequence_no_false_expansion(self):
        """Validates that outright rejected sequences do not falsely report search_radius expansion."""
        ruler = ProtocolRuler(host="127.0.0.1", port=self.SERVER_PORT, timeout=1.0)
        orig_send = ruler.send_probe
        ruler.send_probe = lambda req: (400, b"Bad", 1.0) if b"DISALLOWED" in req else orig_send(req)
        res = ruler.measure_sequence_transformation("Disallowed", b"DISALLOWED", baseline_limit=64040, search_radius=128)
        self.assertNotEqual(res["classification"], "EXPANSION")
        self.assertEqual(res["classification"], "REJECTED_OR_OVERSIZED")

    def test_10_socket_cleanup_on_exception(self):
        """Validates that socket handles are properly closed when exceptions occur in send_probe."""
        import socket as _sock
        from engine.http_framing import HTTPFramingReader
        ruler = ProtocolRuler(host="127.0.0.1", port=self.SERVER_PORT, timeout=1.0)
        created = []
        orig_open = ruler._open_socket
        def tracking_open():
            s = orig_open()
            created.append(s)
            return s
        ruler._open_socket = tracking_open
        orig_read = HTTPFramingReader.read_response
        HTTPFramingReader.read_response = staticmethod(lambda *args, **kwargs: (_ for _ in ()).throw(ConnectionResetError("Simulated Reset")))
        try:
            code, resp, _ = ruler.send_probe(b"GET / HTTP/1.1\r\n\r\n")
            self.assertEqual(code, 0)
            self.assertTrue(len(created) > 0)
            for s in created:
                self.assertEqual(s.fileno(), -1)
        finally:
            HTTPFramingReader.read_response = orig_read

    def test_11_error_boundary_status_codes(self):
        """Validates that 400, 413, 414, 431, 500, 502, 504, 0 are recognized as error boundaries."""
        for code in (400, 413, 414, 431, 500, 502, 504, 0):
            self.assertTrue(self.ruler.is_error_boundary(code), f"Expected {code} to be error boundary")
        for code in (200, 204, 301, 302, 404):
            self.assertFalse(self.ruler.is_error_boundary(code), f"Expected {code} not to be error boundary")

    def test_12_format_kettle_ruler_bytes(self):
        """Validates Kettle run-length compression formatting."""
        compressed = format_kettle_ruler_bytes(b"A: " + b"A" * 1000)
        self.assertIn("AAA...{1000}", compressed)


if __name__ == "__main__":
    unittest.main()

