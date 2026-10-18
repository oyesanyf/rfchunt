"""
Deterministic Evaluation Harness:
Implements PortSwigger's core evaluation primitive for desync verification:
1. Establish baseline response on Connection A (Victim).
2. Fire candidate probe on Connection B (Attacker).
3. Send follow-up request on Connection A to detect cross-connection contamination.
4. Follow-up classification phase (HTTP/777, TRACE, CL.0) to categorize the attack class.
"""

import concurrent.futures
import re
import socket
import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from anomaly_detector import AnomalyDetector
from database import Database
from engine.http_framing import HTTPFramingReader


class DeterministicHarness:
    """
    Evaluates candidate attack vectors by testing for cross-connection state
    contamination using raw sockets, followed by anomaly cascade detection.
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        use_tls: bool = False,
        timeout: float = 3.5,
        db: Optional[Database] = None,
        verbose: bool = False,
        on_trace: Optional[Callable[[str], None]] = None,
    ):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.db = db
        self.verbose = verbose
        self.on_trace = on_trace

    def _open_connection(self) -> socket.socket:
        is_local = self.host in ("127.0.0.1", "localhost", "::1", "[::1]") or self.host.startswith("127.")
        from engine.safe_network_validator import validate_target_host
        is_safe, reason = validate_target_host(self.host, allow_private=is_local)
        if not is_safe:
            raise PermissionError(f"Target '{self.host}' rejected by SSRF safety boundary: {reason}")
        from mcp_server import TargetAuthorizationGate
        TargetAuthorizationGate.check_target(self.host)
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context.wrap_socket(raw_sock, server_hostname=self.host)
        return raw_sock

    def _send_and_receive(self, sock: socket.socket, data: bytes, read_until_close: bool = False) -> bytes:
        sock.sendall(data)
        if read_until_close:
            buffer = bytearray()
            sock.settimeout(self.timeout)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer.extend(chunk)
            except (socket.timeout, ConnectionResetError, ConnectionAbortedError):
                pass
            return bytes(buffer)

        framed = HTTPFramingReader.read_response(sock, timeout=self.timeout)
        return framed.raw_response

    def _prepare_probe_bytes(self, raw_template: str, payload: str) -> bytes:
        probe_str = raw_template.replace("target.local", self.host)
        probe_str = probe_str.replace("$PAYLOAD", payload)
        if "\r\n" not in probe_str and "\\r\\n" in probe_str:
            try:
                probe_str = probe_str.encode("utf-8").decode("unicode_escape")
            except Exception:
                probe_str = probe_str.replace("\\r\\n", "\r\n")
        if "\r\n\r\n" in probe_str and re.search(r"Content-Length:\s*(\$LENGTH|N)\b", probe_str, re.IGNORECASE):
            _, body_part = probe_str.split("\r\n\r\n", 1)
            body_len = len(body_part.encode("latin-1", errors="replace"))
            probe_str = re.sub(
                r"(Content-Length:\s*)(?:\$LENGTH|N)\b",
                rf"\g<1>{body_len}",
                probe_str,
                flags=re.IGNORECASE,
            )
        try:
            return probe_str.encode("latin-1")
        except UnicodeEncodeError:
            return probe_str.encode("utf-8", errors="replace")

    def run_evaluation(self, probe_dict: Dict[str, Any]) -> Tuple[bool, Optional[str], str, Dict[str, Any]]:
        """
        Runs the full 3-step evaluation primitive and anomaly cascade.
        Returns: (is_vulnerable, desync_class, details, metadata)
        """
        raw_template = probe_dict.get("raw_request", "")
        probe_id = probe_dict.get("probe_id")
        is_clean = bool(probe_dict.get("is_clean", False))

        baseline_req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: HTTPTerminator-Victim/1.0\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode("utf-8")

        # Nested test marker
        marker_path = "/terminator_marker_8821"
        nested_marker = (
            f"GET {marker_path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"X-Ignore: 1\r\n\r\n"
        )

        probe_bytes = self._prepare_probe_bytes(raw_template, nested_marker)

        eval_metadata: Dict[str, Any] = {"anomalies": []}

        try:
            # 1. Establish baseline connection (Victim Connection A)
            conn_victim = self._open_connection()
            baseline_resp = self._send_and_receive(conn_victim, baseline_req)
            if not baseline_resp:
                conn_victim.close()
                return False, None, "Failed to establish baseline response on Connection A", eval_metadata

            # 2. Fire the attack probe on an independent connection (Attacker Connection B)
            conn_attacker = self._open_connection()
            attacker_resp = self._send_and_receive(conn_attacker, probe_bytes)
            conn_attacker.close()

            # Anomaly inspection on attacker response
            attacker_anomalies = AnomalyDetector.analyze_response(
                attacker_resp, baseline_response=baseline_resp, is_clean_probe=is_clean, db=self.db
            )
            for anom in attacker_anomalies:
                eval_metadata["anomalies"].append(anom)

            # 3. Test if Connection A's internal request queue was poisoned
            polluted_resp = self._send_and_receive(conn_victim, baseline_req)
            conn_victim.close()

            # Anomaly inspection on victim polluted response
            victim_anomalies = AnomalyDetector.analyze_response(
                polluted_resp, baseline_response=baseline_resp, is_clean_probe=False, db=self.db
            )
            for anom in victim_anomalies:
                eval_metadata["anomalies"].append(anom)

            eval_metadata["baseline_resp"] = baseline_resp.decode('latin-1', errors='replace')
            eval_metadata["attacker_resp"] = attacker_resp.decode('latin-1', errors='replace')
            eval_metadata["polluted_resp"] = polluted_resp.decode('latin-1', errors='replace') if polluted_resp else ""

            b_line = baseline_resp.split(b"\r\n")[0].decode(errors='ignore') if baseline_resp else "NO_RESPONSE"
            a_line = attacker_resp.split(b"\r\n")[0].decode(errors='ignore') if attacker_resp else "NO_RESPONSE"
            p_line = polluted_resp.split(b"\r\n")[0].decode(errors='ignore') if polluted_resp else "CONNECTION_CLOSED"
            req_headline = probe_bytes.split(b"\r\n")[0].decode(errors='ignore')

            if self.verbose:
                log_fn = self.on_trace or print
                log_fn(f"      [Host Activity Trace]:")
                log_fn(f"        -> Conn A (Baseline) : GET / -> {b_line}")
                log_fn(f"        -> Conn B (Probe)    : {req_headline} -> {a_line} [{len(attacker_resp)} bytes]")
                log_fn(f"        -> Conn A (Re-Test)  : GET / -> {p_line}")

            if not polluted_resp:
                if self.db and probe_id:
                    eval_id = self.db.record_evaluation(
                        probe_id=probe_id,
                        target_host=self.host,
                        target_port=self.port,
                        is_vulnerable=False,
                        desync_class=None,
                        details="Victim connection reset without state leakage",
                        raw_evidence="",
                    )
                    for anom in attacker_anomalies:
                        self.db.record_anomaly(eval_id, anom["type"], anom["description"], attacker_resp)
                return False, None, "Victim connection reset without state leakage", eval_metadata

            baseline_status = baseline_resp.split(b"\r\n")[0]
            polluted_status = polluted_resp.split(b"\r\n")[0]

            # Primary Check 1: Did the status line shift?
            is_status_shift = baseline_status != polluted_status
            is_marker_reflected = marker_path.encode() in polluted_resp or b"terminator_marker" in polluted_resp

            if is_status_shift or is_marker_reflected:
                # Contamination detected! Run follow-up classification
                desync_class = self._classify_desync(raw_template)
                details = f"Contamination verified: {baseline_status.decode(errors='ignore')} -> {polluted_status.decode(errors='ignore')}"
                if is_marker_reflected:
                    details += " [Direct Queue Poisoning Confirmed: marker reflected]"

                raw_evidence = (
                    f"--- BASELINE ---\n{baseline_resp.decode('latin-1', errors='replace')}\n\n"
                    f"--- POLLUTED ---\n{polluted_resp.decode('latin-1', errors='replace')}"
                )

                if self.db and probe_id:
                    eval_id = self.db.record_evaluation(
                        probe_id=probe_id,
                        target_host=self.host,
                        target_port=self.port,
                        is_vulnerable=True,
                        desync_class=desync_class,
                        details=details,
                        raw_evidence=raw_evidence,
                    )
                    for anom in attacker_anomalies:
                        self.db.record_anomaly(eval_id, anom["type"], anom["description"], attacker_resp)
                    for anom in victim_anomalies:
                        self.db.record_anomaly(eval_id, anom["type"], anom["description"], polluted_resp)

                details = "[LABORATORY_RESEARCH_FINDING] " + details
                return True, desync_class, details, eval_metadata

            if self.db and probe_id:
                eval_id = self.db.record_evaluation(
                    probe_id=probe_id,
                    target_host=self.host,
                    target_port=self.port,
                    is_vulnerable=False,
                    desync_class=None,
                    details="No cross-request contamination observed",
                    raw_evidence="",
                )
                for anom in attacker_anomalies:
                    self.db.record_anomaly(eval_id, anom["type"], anom["description"], attacker_resp)
                for anom in victim_anomalies:
                    self.db.record_anomaly(eval_id, anom["type"], anom["description"], polluted_resp)

            return False, None, "No cross-request contamination observed", eval_metadata

        except Exception as e:
            return False, None, f"Harness evaluation error: {str(e)}", eval_metadata

    def _classify_desync(self, candidate_raw_template: str) -> str:
        """
        Follow-up phase: attempts to elicit secondary signatures (HTTP/777, TRACE, 0.CL)
        to categorize the vulnerability.
        """
        test_payloads = [
            ("CL.0 / Version Confusion", f"GET / HTTP/777\r\nX-Test: 1\r\n\r\n", b"505"),
            ("TRACE Gadget", f"TRACE / HTTP/1.1\r\nHost: {self.host}\r\nX-Test: 1\r\n\r\n", b"501"),
            ("CRLF-RHI (417 Expectation Failed)", f"GET / HTTP/1.1\r\nHost: {self.host}\r\nExpect: asdf\r\n\r\n", b"417"),
            ("CRLF-RHI (501 TE Desync)", f"GET / HTTP/1.1\r\nHost: {self.host}\r\nTransfer-Encoding: asdf\r\n\r\n", b"501"),
            ("CRLF-Splitting (505 Version Unsupported)", f"GET / HTTP/13.37\r\nHost: {self.host}\r\n\r\n", b"505"),
        ]

        for classification_name, payload_snippet, expected_bytes in test_payloads:
            try:
                probe_bytes = self._prepare_probe_bytes(candidate_raw_template, payload_snippet)

                conn_v = self._open_connection()
                _ = self._send_and_receive(conn_v, f"GET / HTTP/1.1\r\nHost: {self.host}\r\n\r\n".encode())

                conn_a = self._open_connection()
                self._send_and_receive(conn_a, probe_bytes)
                conn_a.close()

                resp_v = self._send_and_receive(conn_v, f"GET / HTTP/1.1\r\nHost: {self.host}\r\n\r\n".encode())
                conn_v.close()

                if expected_bytes in resp_v:
                    return classification_name
            except Exception:
                pass

        return "Unclassified Novel Desync Trigger"

    def evaluate_probe(self, probe_dict: Dict[str, Any]) -> Tuple[bool, Optional[str], str, Dict[str, Any]]:
        """Alias for run_evaluation."""
        return self.run_evaluation(probe_dict)

    def evaluate_batch_concurrent(
        self,
        probes: List[Dict[str, Any]],
        max_concurrency: int = 4,
    ) -> List[Tuple[bool, Optional[str], str, Dict[str, Any]]]:
        """
        Evaluates a batch of candidate probes concurrently using a bounded thread pool and semaphore.
        Guarantees that socket I/O is parallelized while strictly enforcing a maximum in-flight socket limit.
        """
        sem = threading.BoundedSemaphore(max(1, max_concurrency))

        def _worker(p):
            with sem:
                return self.run_evaluation(p)

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_concurrency)) as executor:
            futures = [executor.submit(_worker, p) for p in probes]
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as e:
                    results.append((False, None, f"Execution exception: {e}", {}))
        return results

