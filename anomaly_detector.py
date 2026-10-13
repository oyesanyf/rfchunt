"""
Anomaly Detection Cascade:
Implements the 4 core anomaly detectors from the HTTP Terminator research:
1. Text/Binary Blend (Memory leaks, unaligned socket buffer dumps)
2. Double HTML / Response Forking (Unframed second response)
3. Inline HTTP Response Headers (Backend pipeline confusion / CVE-2026-63078)
4. Clean-Probe Multi-Response (RFC-compliant request triggering multiple responses)
"""

import re
from typing import Dict, List, Optional, Tuple


class AnomalyDetector:
    """
    Scans raw socket byte responses for unexpected structural anomalies
    that reveal server memory leaks, response forking, or pipeline misalignments.
    """

    @classmethod
    def analyze_response(
        cls,
        raw_response: bytes,
        baseline_response: Optional[bytes] = None,
        is_clean_probe: bool = False,
        separate_responses_count: int = 1,
        db: Optional[object] = None,
    ) -> List[Dict[str, str]]:
        # Exact baseline subtraction (only suppress when response bytes are identical to baseline)
        if baseline_response and raw_response == baseline_response:
            return []

        anomalies: List[Dict[str, str]] = []

        if not raw_response:
            return anomalies

        # 1. Check for Text / Binary Blend (Memory Leak or unhandled compression)
        is_blend, blend_details = cls._check_text_binary_blend(raw_response)
        if is_blend:
            anomalies.append({
                "type": "text_binary_blend",
                "description": f"Text/Binary Blend detected: {blend_details}",
            })

        # 2. Check for Double HTML (Response Forking)
        is_fork, fork_details = cls._check_double_html(raw_response)
        if is_fork:
            anomalies.append({
                "type": "double_html",
                "description": f"Response Forking / Double HTML: {fork_details}",
            })

        # 3. Check for Inline HTTP Headers (CVE-2026-63078 pattern)
        is_inline, inline_details = cls._check_inline_headers(raw_response)
        if is_inline:
            anomalies.append({
                "type": "inline_headers",
                "description": f"Inline HTTP Response Headers in body: {inline_details}",
            })

        # 4. Check for Clean Probe Dual-Response
        if is_clean_probe and (separate_responses_count >= 2 or cls._count_http_status_lines(raw_response) >= 2):
            anomalies.append({
                "type": "clean_dual_response",
                "description": "Clean (RFC-compliant) request triggered multiple HTTP responses on one connection!",
            })

        # 5. Check for Status-Line Reflection / HTTP/0.9 downgrade
        is_status_refl, status_refl_details = cls._check_status_line_reflection(raw_response)
        if is_status_refl:
            anomalies.append({
                "type": "status_line_reflection",
                "description": f"Status-Line Reflection / Downgrade detected: {status_refl_details}",
            })

        # 6. Check for Range Cache Mismatch (200 OK with Content-Range or multipart/byteranges)
        is_range_mismatch, range_details = cls._check_range_cache_mismatch(raw_response)
        if is_range_mismatch:
            anomalies.append({
                "type": "range_cache_mismatch",
                "description": f"Range Cache Mismatch detected: {range_details}",
            })

        # 7. Check database-registered custom anomaly fingerprints if db is provided
        if db is not None and hasattr(db, "get_anomaly_fingerprints"):
            try:
                text_resp = raw_response.decode("latin-1", errors="ignore")
                for fp in db.get_anomaly_fingerprints():
                    pat = fp.get("pattern", "")
                    if pat and re.search(pat, text_resp, re.IGNORECASE):
                        anomalies.append({
                            "type": fp.get("name", "custom_fingerprint"),
                            "description": fp.get("description", f"Matched custom fingerprint: {pat}"),
                        })
            except Exception:
                pass

        return anomalies

    @staticmethod
    def _count_http_status_lines(data: bytes) -> int:
        status_pattern = re.compile(rb"HTTP/\d\.\d\s+\d{3}\s+[^\r\n]*\r\n")
        return len(status_pattern.findall(data))

    @staticmethod
    def _check_status_line_reflection(data: bytes) -> Tuple[bool, str]:
        """
        Detects reflected non-standard protocol tokens in the response status line
        or unexpected HTTP/0.9 status lines (from Status-line Injection / HTTP/0.9 section of the paper).
        """
        first_line = data.split(b"\r\n", 1)[0].strip()
        if not first_line:
            return False, ""
        if first_line.startswith(b"HTTP/0.9"):
            return True, f"HTTP/0.9 status line returned: {first_line.decode('latin-1', errors='ignore')}"
        # Match non-standard protocol prefix before a 3-digit status code (e.g., 'COW< 200 OK')
        if not first_line.startswith((b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2", b"HTTP/3")):
            m = re.match(rb"^([A-Za-z0-9_<>/\.\-]+)\s+(\d{3})\s+", first_line)
            if m:
                return True, f"Reflected/non-standard status-line protocol token: {first_line.decode('latin-1', errors='ignore')}"
        return False, ""

    @staticmethod
    def _check_range_cache_mismatch(data: bytes) -> Tuple[bool, str]:
        """
        Detects HTTP 200 OK responses that unexpectedly include Content-Range headers
        or multipart/byteranges framing (Range Cache Poisoning indicator).
        """
        parts = data.split(b"\r\n\r\n", 1)
        header_block = parts[0].decode("latin-1", errors="ignore")
        lines = header_block.split("\r\n")
        if not lines:
            return False, ""
        status_line = lines[0]
        if re.match(r"^HTTP/\d\.\d\s+200\b", status_line):
            lower_headers = header_block.lower()
            if "\r\ncontent-range:" in lower_headers or "multipart/byteranges" in lower_headers:
                return True, "HTTP 200 OK response contains Content-Range / multipart/byteranges framing instead of 206 Partial Content"
        return False, ""

    @classmethod
    def _check_text_binary_blend(cls, data: bytes) -> Tuple[bool, str]:
        """
        Splits headers from body. If the body starts as text or HTML,
        but contains runs of unprintable nulls / binary sequences, flag as leak.
        """
        parts = data.split(b"\r\n\r\n", 1)
        if len(parts) < 2:
            return False, ""

        body = parts[1]
        if len(body) < 32:
            return False, ""

        # Check if first part of body is printable ASCII
        header_text = parts[0].decode("latin-1", errors="ignore").lower()
        if "content-encoding: gzip" in header_text or "content-encoding: br" in header_text:
            # Expected to be binary
            return False, ""

        prefix_len = min(32, len(body))
        prefix = body[:prefix_len]
        ascii_chars = sum(1 for b in prefix if 32 <= b <= 126 or b in (9, 10, 13))
        if ascii_chars / prefix_len >= 0.70:
            null_runs = len(re.findall(rb"\x00{3,}", body))
            non_printables = sum(1 for b in body[prefix_len:] if b < 9 or (13 < b < 32) or b > 126)
            trailing_len = max(1, len(body) - prefix_len)
            ratio = non_printables / trailing_len
            if null_runs > 0 or ratio > 0.25:
                return True, f"Printable text header/body followed by binary stream (nulls={null_runs}, non-ascii={ratio:.1%})"

        return False, ""

    @staticmethod
    def _check_double_html(data: bytes) -> Tuple[bool, str]:
        """Flags multiple <!DOCTYPE or <html openings inside the same stream."""
        lower_data = data.lower()
        doctype_count = lower_data.count(b"<!doctype")
        html_count = lower_data.count(b"<html")

        if doctype_count >= 2 or html_count >= 2:
            return True, f"Found {doctype_count} <!DOCTYPE and {html_count} <html tags in stream"
        return False, ""

    @staticmethod
    def _check_inline_headers(data: bytes) -> Tuple[bool, str]:
        """
        Looks for response headers embedded inside the message body.
        In CVE-2026-63078, ATS leaked 'Server: ATS' and Amazon Trace IDs inside response bodies.
        """
        parts = data.split(b"\r\n\r\n", 1)
        if len(parts) < 2:
            return False, ""

        body = parts[1]
        # Look for HTTP status line or standard server headers in body
        suspicious_headers = [
            rb"HTTP/1\.[01]\s+\d{3}",
            rb"\r\nServer:\s*[^\r\n]+",
            rb"\r\nContent-Type:\s*[^\r\n]+",
            rb"\r\nX-Amzn-Trace-Id:",
            rb"\r\nAkamai-Cache-Status:",
        ]

        found = []
        for pat in suspicious_headers:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                found.append(m.group(0).decode("latin-1", errors="ignore").strip())

        if found:
            return True, f"Found leaked headers in response body: {', '.join(found[:3])}"

        return False, ""
