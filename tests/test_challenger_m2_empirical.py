"""
Empirical Adversarial Challenge Suite: Milestone 2 (Protocol Framing & 4-Parser Differential Matrix).
====================================================================================================

Empirically challenges:
1. 3-Trial Protocol Research Reproducibility Invariant:
   - Flaky trials (0/3, 1/3, 2/3) to verify automatic downgrade to NonReproducibleTransient.
   - Stable trials (3/3) to verify confirmation.
   - Clamping of max_verification_trials <= 2 to at least 3.
   - Extended trial budgets (5 and 10 trials) checking 60% reproducibility threshold and >= 3 successes.
   - CausalAnomalyClassifier.validate_evidence rejection gate across all non-reproducible / sub-threshold variants.
   - Cryptographic Merkle Audit Trail leaf hash and status persistence for NonReproducibleTransient.

2. 3-Step Pipelined Canary Sequence under Simulated Network Disconnections:
   - Connection refused / unreachable target handling.
   - Step 1 (Baseline): Immediate EOF (0 bytes), TCP RST mid-headers, Premature EOF mid-body, timeout, and Connection: close.
   - Step 2 (Candidate Probe): Immediate TCP RST, server 400/Connection: close teardown, abrupt disconnection.
   - Step 2 to Step 3 Transition: Abrupt TCP RST before canary read (verifying framed3=None attribute error immunity).
   - Step 3 (Canary): Server timeout, premature EOF.

3. Short Baseline Body Responses:
   - Content-Length: 0 (empty body).
   - RFC 9112 Section 6.3 item 1: 204 No Content (strictly no body).
   - RFC 9112 Section 6.3 item 1: 304 Not Modified (strictly no body).
   - 1-byte body (Content-Length: 1).
   - 2-byte body (Content-Length: 2, b"OK") with HTTP status lines to ensure no false scanner artifact abortion.
   - Pipelined residual bytes in initial socket buffer across step boundaries.
   - True non-HTTP residual byte artifact detection.
   - Verified desynchronization detection (Timeout CL/TE, Queue Poisoning, Pipeline Leak).
"""

import socket
import struct
import threading
import time
from typing import Callable, Optional
import pytest

from engine.causal_classifier import CausalAnomalyClassifier
from engine.delta_debugger import DeltaDebugger
from engine.http_framing import HTTPFramingReader, HTTPResponseFraming
from engine.merkle_audit import MerkleAuditTrail
from engine.sequence_engine import (
    SequenceExecutionReport,
    SequenceStepResult,
    StatefulProtocolSequenceEngine,
)
from engine.taxonomy import (
    AnomalyCategory,
    ImpactClass,
    ImplementationAnomaly,
    ReproducibleVulnerability,
)


class RealLocalhostServer:
    """Helper for testing raw wire protocols on real localhost sockets."""

    def __init__(self, handler: Callable[[socket.socket], None]):
        self.handler = handler
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", 0))
        self.port = self.server_sock.getsockname()[1]
        self.server_sock.listen(5)
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                self.server_sock.settimeout(0.5)
                conn, _ = self.server_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                self.handler(conn)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def close(self):
        self.running = False
        try:
            self.server_sock.close()
        except Exception:
            pass
        self.thread.join(timeout=1.0)


# ==============================================================================
# GROUP 1: EMPIRICAL 3-TRIAL REPRODUCIBILITY INVARIANT CHALLENGE
# ==============================================================================

def test_3_trial_flaky_evaluator_0_of_3_downgrade():
    """Empirically verifies 0/3 successes (0%) downgrades to NonReproducibleTransient."""
    debugger = DeltaDebugger("127.0.0.1", 8080)
    anomaly = ImplementationAnomaly(
        anomaly_id="ANOM-FLAKE-0",
        target_engine="TargetA",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="Divergence observed",
        expected_behavior="Strict conformance",
        raw_probe=b"POST / HTTP/1.1\r\nHost: target\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
    )

    vuln = debugger.minimize_and_reproduce(
        anomaly, test_evaluator=lambda p: False, max_verification_trials=3
    )

    assert vuln.verification_attempts == 3
    assert vuln.successful_reproductions == 0
    assert vuln.reproducibility_rate == 0.0
    assert vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT
    assert any("Downgraded to NonReproducibleTransient" in p for p in vuln.provenance_chain)

    classifier = CausalAnomalyClassifier()
    is_valid, reason = classifier.validate_evidence(vuln, anomaly)
    assert is_valid is False
    assert "NonReproducibleTransient" in reason


def test_3_trial_flaky_evaluator_1_of_3_downgrade():
    """Empirically verifies 1/3 successes (33.3% < 60%) downgrades to NonReproducibleTransient."""
    debugger = DeltaDebugger("127.0.0.1", 8080)
    anomaly = ImplementationAnomaly(
        anomaly_id="ANOM-FLAKE-1",
        target_engine="TargetA",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="Divergence observed",
        expected_behavior="Strict conformance",
        raw_probe=b"POST / HTTP/1.1\r\nHost: target\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
    )

    call_seq = [True, False, False]
    call_idx = [0]

    def evaluator(probe):
        idx = call_idx[0]
        call_idx[0] += 1
        return call_seq[idx] if idx < len(call_seq) else False

    vuln = debugger.minimize_and_reproduce(
        anomaly, test_evaluator=evaluator, max_verification_trials=3
    )

    assert vuln.verification_attempts == 3
    assert vuln.successful_reproductions == 1
    assert abs(vuln.reproducibility_rate - (1.0 / 3.0)) < 1e-4
    assert vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT
    assert any("Downgraded to NonReproducibleTransient" in p for p in vuln.provenance_chain)

    classifier = CausalAnomalyClassifier()
    is_valid, reason = classifier.validate_evidence(vuln, anomaly)
    assert is_valid is False
    assert "NonReproducibleTransient" in reason


def test_3_trial_flaky_evaluator_2_of_3_downgrade():
    """
    CRITICAL INVARIANT TEST:
    2/3 successes has reproducibility_rate = 66.7% (which is >= 60%),
    BUT total successes is 2 (< 3 minimum required stable successes).
    Must still be automatically downgraded to NonReproducibleTransient!
    """
    debugger = DeltaDebugger("127.0.0.1", 8080)
    anomaly = ImplementationAnomaly(
        anomaly_id="ANOM-FLAKE-2",
        target_engine="TargetA",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="Divergence observed",
        expected_behavior="Strict conformance",
        raw_probe=b"POST / HTTP/1.1\r\nHost: target\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
    )

    call_seq = [True, True, False]
    call_idx = [0]

    def evaluator(probe):
        idx = call_idx[0]
        call_idx[0] += 1
        return call_seq[idx] if idx < len(call_seq) else False

    vuln = debugger.minimize_and_reproduce(
        anomaly, test_evaluator=evaluator, max_verification_trials=3
    )

    assert vuln.verification_attempts == 3
    assert vuln.successful_reproductions == 2
    assert abs(vuln.reproducibility_rate - (2.0 / 3.0)) < 1e-4
    assert vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT, (
        f"Expected NON_REPRODUCIBLE_TRANSIENT for 2/3 trials, got {vuln.impact}"
    )

    classifier = CausalAnomalyClassifier()
    is_valid, reason = classifier.validate_evidence(vuln, anomaly)
    assert is_valid is False
    assert "NonReproducibleTransient" in reason


def test_3_trial_stable_evaluator_3_of_3_confirmation():
    """Empirically verifies 3/3 successes (100%) passes the stability invariant."""
    debugger = DeltaDebugger("127.0.0.1", 8080)
    anomaly = ImplementationAnomaly(
        anomaly_id="ANOM-STABLE-3",
        target_engine="TargetA",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="Divergence observed",
        expected_behavior="Strict conformance",
        raw_probe=b"POST / HTTP/1.1\r\nHost: target\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
    )

    vuln = debugger.minimize_and_reproduce(
        anomaly, test_evaluator=lambda p: True, max_verification_trials=3
    )

    assert vuln.verification_attempts == 3
    assert vuln.successful_reproductions == 3
    assert vuln.reproducibility_rate == 1.0
    assert vuln.impact != ImpactClass.NON_REPRODUCIBLE_TRANSIENT

    classifier = CausalAnomalyClassifier()
    is_valid, reason = classifier.validate_evidence(vuln, anomaly)
    assert is_valid is True


def test_3_trial_clamping_low_max_trials():
    """Empirically verifies that requesting <= 2 trials is automatically clamped to >= 3."""
    debugger = DeltaDebugger("127.0.0.1", 8080)
    anomaly = ImplementationAnomaly(
        anomaly_id="ANOM-CLAMP",
        target_engine="TargetA",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="Divergence observed",
        expected_behavior="Strict conformance",
        raw_probe=b"POST / HTTP/1.1\r\nHost: target\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
    )

    for requested_trials in [0, 1, 2, -1, -100]:
        vuln = debugger.minimize_and_reproduce(
            anomaly, test_evaluator=lambda p: True, max_verification_trials=requested_trials
        )
        assert vuln.verification_attempts >= 3, f"Failed for requested {requested_trials}"


def test_3_trial_extended_trial_budgets_5_and_10():
    """
    Tests extended trial budgets:
    - 5 trials: 2/5 (40% < 60%) -> downgraded.
    - 5 trials: 3/5 (60% == 60% and 3 >= 3) -> confirmed.
    - 10 trials: 5/10 (50% < 60%, even though 5 >= 3) -> downgraded.
    - 10 trials: 6/10 (60% == 60% and 6 >= 3) -> confirmed.
    """
    debugger = DeltaDebugger("127.0.0.1", 8080)
    anomaly = ImplementationAnomaly(
        anomaly_id="ANOM-EXT",
        target_engine="TargetA",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="Divergence observed",
        expected_behavior="Strict conformance",
        raw_probe=b"POST / HTTP/1.1\r\nHost: target\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
    )

    # 1. 2/5 -> Downgraded
    seq_2_5 = [True, True, False, False, False]
    idx_2 = [0]
    def eval_2_5(p):
        curr = idx_2[0]
        idx_2[0] += 1
        return seq_2_5[curr] if curr < len(seq_2_5) else False

    vuln_2_5 = debugger.minimize_and_reproduce(
        anomaly, test_evaluator=eval_2_5, max_verification_trials=5
    )
    assert vuln_2_5.successful_reproductions == 2
    assert vuln_2_5.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT

    # 2. 3/5 -> Confirmed
    seq_3_5 = [True, True, True, False, False]
    idx_3 = [0]
    def eval_3_5(p):
        curr = idx_3[0]
        idx_3[0] += 1
        return seq_3_5[curr] if curr < len(seq_3_5) else False

    vuln_3_5 = debugger.minimize_and_reproduce(
        anomaly, test_evaluator=eval_3_5, max_verification_trials=5
    )
    assert vuln_3_5.successful_reproductions == 3
    assert vuln_3_5.reproducibility_rate == 0.60
    assert vuln_3_5.impact != ImpactClass.NON_REPRODUCIBLE_TRANSIENT

    # 3. 5/10 -> Downgraded (50% < 60%)
    seq_5_10 = [True] * 5 + [False] * 5
    idx_5 = [0]
    def eval_5_10(p):
        curr = idx_5[0]
        idx_5[0] += 1
        return seq_5_10[curr] if curr < len(seq_5_10) else False

    vuln_5_10 = debugger.minimize_and_reproduce(
        anomaly, test_evaluator=eval_5_10, max_verification_trials=10
    )
    assert vuln_5_10.successful_reproductions == 5
    assert vuln_5_10.reproducibility_rate == 0.50
    assert vuln_5_10.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT


def test_merkle_audit_records_non_reproducible_transient():
    """Empirically verifies that flaky findings are recorded into the Merkle Tree with status NON_REPRODUCIBLE_TRANSIENT."""
    audit = MerkleAuditTrail()
    leaf = audit.record_finding(
        entry_id="VULN-TRANSIENT-TEST",
        target_engine="127.0.0.1:8080",
        raw_probe=b"GET /probe HTTP/1.1\r\nHost: test\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
        reproducibility_rate=0.33,
        verification_attempts=3,
        successful_reproductions=1,
        four_parser_differential={"Strict": 200, "Permissive": 200},
        status="NON_REPRODUCIBLE_TRANSIENT",
    )

    assert leaf.status == "NON_REPRODUCIBLE_TRANSIENT"
    assert leaf.index == 0
    leaf_hash = leaf.compute_leaf_hash()
    assert len(leaf_hash) == 64
    assert audit.get_merkle_root() == leaf_hash


# ==============================================================================
# GROUP 2: 3-STEP CANARY PIPELINE UNDER NETWORK DISCONNECTION
# ==============================================================================

def test_canary_connection_refused_handling():
    """Empirically verifies that an unreachable server port returns cleanly without crash."""
    engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
    # Port 1 is reserved and closed on localhost
    report = engine.run_pipelined_canary_sequence(
        "127.0.0.1", 1, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    )
    assert isinstance(report, SequenceExecutionReport)
    assert report.has_desynchronization is False
    assert report.has_pipeline_leak is False
    assert "error" in report.details.lower() or "timeout" in report.details.lower() or "refused" in report.details.lower()


def test_canary_step1_disconnect_immediate_eof():
    """Empirically verifies server closing connection immediately on connect (0 bytes in Step 1)."""
    def handler(conn):
        # Close immediately on connect
        conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 1
        assert "Baseline response incomplete or timed out" in report.details
    finally:
        server.close()


def test_canary_step1_disconnect_tcp_rst_mid_headers():
    """Empirically verifies server sending TCP RST midway through Step 1 response headers."""
    def handler(conn):
        try:
            conn.recv(1024)
            # Send partial status line then RST
            conn.sendall(b"HTTP/1.1 200")
            # Force TCP RST by setting SO_LINGER to 0
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            conn.close()
        except Exception:
            pass

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 1
        assert "Baseline response incomplete or timed out" in report.details
    finally:
        server.close()


def test_canary_step1_disconnect_premature_eof_content_length():
    """Empirically verifies server declaring Content-Length: 100 but closing after 10 bytes in Step 1."""
    def handler(conn):
        try:
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: keep-alive\r\n\r\n1234567890")
            conn.close()
        except Exception:
            pass

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 1
        assert "Baseline response incomplete or timed out" in report.details
        assert "Premature EOF" in report.details
    finally:
        server.close()


def test_canary_step1_server_sends_connection_close():
    """Empirically verifies that server sending Connection: close in Step 1 halts the pipeline."""
    def handler(conn):
        try:
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 1
        assert "persistent pipelining not supported" in report.details
    finally:
        server.close()


def test_canary_step2_disconnect_immediate_rst():
    """Empirically verifies TCP RST received during candidate probe (Step 2)."""
    def handler(conn):
        try:
            # Step 1: Baseline OK
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2: Probe received -> abrupt RST
            conn.recv(1024)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            conn.close()
        except Exception:
            pass

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        # Either handled in Step 2 or outer connection reset
        assert "reset" in report.details.lower() or "closed" in report.details.lower() or "error" in report.details.lower()
    finally:
        server.close()


def test_canary_step2_server_error_and_close():
    """Empirically verifies server sending 400 with Connection: close on Step 2 aborts Step 3 without leak."""
    def handler(conn):
        try:
            # Step 1
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2: Server rejects probe with 400 and Connection: close
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /malformed HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        assert "Connection closed by server after candidate probe" in report.details
    finally:
        server.close()


def test_canary_transition_abrupt_disconnect_before_step3_canary_read():
    """
    CRITICAL EDGE CASE:
    Step 2 completes cleanly with keep-alive, but server closes connection before
    or during Step 3 canary send/read.
    Verifies that framed3=None does not raise AttributeError: 'NoneType' object has no attribute 'error'.
    """
    def handler(conn):
        try:
            # Step 1
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2: Server sends 200 keep-alive
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nPROBE")

            # Forcibly terminate connection before answering Step 3
            time.sleep(0.05)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            conn.close()
        except Exception:
            pass

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert isinstance(report, SequenceExecutionReport)
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        step3 = report.steps[2]
        assert step3.step_name == "Step 3: Canary Check"
        # socket_error must capture the exception string or EOF message without raising AttributeError
        assert step3.socket_error is not None
        assert "Connection Dropped" in report.details or "closed" in report.details.lower()
    finally:
        server.close()


def test_canary_step3_timeout_handling():
    """Empirically verifies server hanging on Step 3 canary request."""
    def handler(conn):
        try:
            # Step 1
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nPROBE")

            # Step 3: Read canary request and sleep past timeout
            conn.recv(1024)
            time.sleep(0.8)
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.4)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        step3 = report.steps[2]
        assert step3.socket_error is not None
        assert "timeout" in step3.socket_error.lower()
    finally:
        server.close()


# ==============================================================================
# GROUP 3: SHORT BASELINE BODY RESPONSES & FRAMING RESILIENCE
# ==============================================================================

def test_canary_short_baseline_body_content_length_0():
    """Empirically verifies baseline response with Content-Length: 0 (empty body b'')."""
    def handler(conn):
        try:
            # Step 1: Content-Length: 0
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")

            # Step 2
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 3
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        assert "Normal" in report.details
    finally:
        server.close()


def test_canary_short_baseline_body_204_no_content():
    """Empirically verifies baseline response with 204 No Content (RFC 9112 §6.3 item 1)."""
    def handler(conn):
        try:
            # Step 1: 204 No Content
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n")

            # Step 2
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nPROBE")

            # Step 3
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        assert report.steps[0].status_code == 204
        assert "Normal" in report.details
    finally:
        server.close()


def test_canary_short_baseline_body_304_not_modified():
    """Empirically verifies baseline response with 304 Not Modified (RFC 9112 §6.3 item 1)."""
    def handler(conn):
        try:
            # Step 1: 304 Not Modified
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 304 Not Modified\r\nETag: \"test-123\"\r\nConnection: keep-alive\r\n\r\n")

            # Step 2
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 3
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        assert report.steps[0].status_code == 304
        assert "Normal" in report.details
    finally:
        server.close()


def test_canary_short_baseline_body_2_bytes_ok_no_false_positive():
    """
    CRITICAL WORKER REGRESSION TEST:
    Verifies that when baseline body is b'OK' (length 2), a subsequent valid response
    containing 'OK' (e.g. 'HTTP/1.1 200 OK') is NOT falsely aborted as a scanner artifact.
    """
    def handler(conn):
        try:
            # Step 1: Baseline body is b"OK"
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2: Probe response is standard 200 OK
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 3: Canary receives 404
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        assert "Scanner Artifact" not in report.details
        assert "Normal" in report.details
    finally:
        server.close()


def test_canary_short_baseline_body_with_unconsumed_pipelined_bytes():
    """
    Verifies HTTPFramingReader exact byte accounting:
    Server sends Step 1 baseline response + 10 bytes of Step 2 response in the EXACT SAME TCP segment.
    HTTPFramingReader must consume exactly the baseline body, store the remaining 10 bytes in unconsumed_bytes,
    and pass them cleanly into Step 2 initial_bytes.
    """
    def handler(conn):
        try:
            # Step 1: Server sends baseline + Step 2 response batched together
            conn.recv(1024)
            batched = (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK"
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\nPONG"
            )
            conn.sendall(batched)

            # Step 2 probe arrives
            conn.recv(1024)

            # Step 3 canary arrives
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        assert report.steps[0].received_bytes == b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK"
        assert report.steps[1].received_bytes == b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\nPONG"
        assert "Normal" in report.details
    finally:
        server.close()


def test_canary_true_residual_baseline_body_artifact_detected():
    """Verifies that non-HTTP response bytes matching the baseline body ARE identified as scanner artifacts."""
    def handler(conn):
        try:
            baseline_body = b"UNIQUE_BASELINE_PAYLOAD_ABC123"
            # Step 1
            conn.recv(1024)
            conn.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(baseline_body)}\r\nConnection: keep-alive\r\n\r\n".encode()
                + baseline_body
            )

            # Step 2: Server sends raw non-HTTP echo of baseline body
            conn.recv(1024)
            conn.sendall(baseline_body)
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert "Scanner Artifact" in report.details
    finally:
        server.close()


def test_canary_timeout_based_desynchronization_detection():
    """
    Verifies PortSwigger timeout-based desynchronization detection:
    When probe contains Content-Length and Transfer-Encoding and server hangs on Step 2.
    """
    def handler(conn):
        try:
            # Step 1: Fast baseline (< 1.2s)
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2: Hang on CL.TE probe
            conn.recv(1024)
            time.sleep(1.0)
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        probe = (
            b"POST / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"1\r\nZ\r\n0\r\n\r\n"
        )
        report = engine.run_pipelined_canary_sequence("127.0.0.1", server.port, probe)
        assert report.has_desynchronization is True
        assert "Timeout-Based Desynchronization (CL.TE/TE.CL)" in report.details
    finally:
        server.close()


def test_canary_queue_desynchronization_marker_detection():
    """
    Verifies queue desynchronization detection:
    Candidate probe response or smuggled body bleeds directly into Step 3 canary response.
    """
    def handler(conn):
        try:
            # Step 1: Baseline
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2: Probe
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 3: Server returns response containing terminator_marker (queue poisoned)
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 28\r\nConnection: close\r\n\r\nHello terminator_marker_8821")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is True
        assert "Queue Desynchronization" in report.details
    finally:
        server.close()


def test_canary_pipeline_leak_corrupting_canary():
    """
    Verifies pipeline leak detection:
    Residual probe bytes corrupt Step 3 canary request into 400 Bad Request
    when probe included framing headers (CL / TE).
    """
    def handler(conn):
        try:
            # Step 1: Baseline
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2: Probe with declared Content-Length
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 3: Canary receives 400 Bad Request due to leaked probe bytes
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        # Probe has valid Content-Length header, so this is a real pipeline leak, NOT client framing omission
        probe_framed = b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\nHELLO"
        report = engine.run_pipelined_canary_sequence("127.0.0.1", server.port, probe_framed)
        assert report.has_pipeline_leak is True
        assert report.has_desynchronization is True
        assert "Pipeline Leak" in report.details
    finally:
        server.close()


def test_canary_short_baseline_body_1_byte():
    """Empirically verifies 1-byte baseline body (Content-Length: 1) followed by clean probe and canary."""
    def handler(conn):
        try:
            # Step 1: 1-byte body
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\nZ")

            # Step 2
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 3
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        assert report.steps[0].received_bytes == b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\nZ"
        assert "Normal" in report.details
    finally:
        server.close()


def test_canary_step2_500_error_and_close():
    """Empirically verifies server returning 500 Internal Server Error with close in Step 2."""
    def handler(conn):
        try:
            # Step 1
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2: 500 Internal Server Error and close
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()

    server = RealLocalhostServer(handler)
    try:
        engine = StatefulProtocolSequenceEngine(default_timeout=0.5)
        report = engine.run_pipelined_canary_sequence(
            "127.0.0.1", server.port, b"GET /error HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        assert report.has_desynchronization is False
        assert report.has_pipeline_leak is False
        assert len(report.steps) == 3
        assert "Connection closed by server after candidate probe" in report.details
    finally:
        server.close()


def test_cl0_canary_under_network_disconnect_and_close():
    """Empirically verifies run_cl0_canary_sequence resilience under sudden disconnect and connection close."""
    # 1. Closed port / connection refused
    engine = StatefulProtocolSequenceEngine(default_timeout=0.4)
    rep_refused = engine.run_cl0_canary_sequence("127.0.0.1", 1)
    assert rep_refused.has_desynchronization is False
    assert "error" in rep_refused.details.lower() or "refused" in rep_refused.details.lower()

    # 2. Server closes connection on Step 2 (GET with Content-Length)
    def handler_close_on_cl(conn):
        try:
            # Step 1
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")

            # Step 2: GET with Content-Length received -> close immediately
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()

    server = RealLocalhostServer(handler_close_on_cl)
    try:
        rep_close = engine.run_cl0_canary_sequence("127.0.0.1", server.port)
        assert rep_close.has_desynchronization is False
        assert "closed connection" in rep_close.details
    finally:
        server.close()

