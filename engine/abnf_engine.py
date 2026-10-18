"""
Module 1: ABNF Grammar Extractor and Inversion Engine (P0).

Extracts specification-grounded Augmented Backus-Naur Form (ABNF) definitions
from RFC texts (RFC 5234 compliance) and synthesizes both conforming and
systematically boundary-inverting protocol mutations.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from engine.taxonomy import RFCRequirement, RequirementType


def _strip_abnf_comment(line: str) -> str:
    """Strips trailing ABNF comment (; ...) while preserving semicolons inside quoted strings."""
    in_dquote = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_dquote = not in_dquote
        elif ch == ';' and not in_dquote:
            return line[:i].rstrip()
    return line.rstrip()


class ABNFGrammarEngine:
    """
    Parses ABNF grammar rules from RFCs and provides an inversion engine
    to generate boundary-violating test vectors directly tied to specification rules.
    """

    # RFC 5234 / RFC 9112 Core ABNF Patterns
    ABNF_RULE_REGEX = re.compile(
        r"^[ \t]*([a-zA-Z][a-zA-Z0-9_-]*)[ \t]*(=/|=)[ \t]*(.+?)(?=;.*)?$",
        re.MULTILINE,
    )

    CORE_HTTP_RULES = {
        "OWS": '*( SP / HTAB )',
        "RWS": '1*( SP / HTAB )',
        "BWS": 'OWS',
        "obs-fold": 'CRLF 1*( SP / HTAB )',
        "chunk-ext": '*( ";" chunk-ext-name [ "=" chunk-ext-val ] )',
        "header-field": 'field-name ":" OWS field-value OWS',
        "request-line": 'method SP request-target SP HTTP-version CRLF',
        "tchar": '"!" / "#" / "$" / "%" / "&" / "\'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA',
        "transfer-coding": '"chunked" / "compress" / "deflate" / "gzip" / transfer-extension',
    }

    def __init__(self):
        self.extracted_rules: Dict[str, Dict[str, str]] = {}
        # Preload canonical specifications
        for rule_name, rule_def in self.CORE_HTTP_RULES.items():
            self.extracted_rules[rule_name] = {
                "rfc_id": "RFC9112",
                "definition": rule_def,
                "section": "Core",
            }

    def extract_from_rfc_text(self, rfc_id: str, text: str) -> List[RFCRequirement]:
        """
        Scans raw RFC text and extracts formal ABNF rules, supporting multi-line
        indented continuations (RFC 5234 §2.1) and incremental alternatives (=/ RFC 5234 §2.3).
        """
        requirements: List[RFCRequirement] = []
        rule_head_re = re.compile(r"^([ \t]*)([a-zA-Z][a-zA-Z0-9_-]*)[ \t]*(=/|=)[ \t]*(.*)$")
        lines = text.splitlines()
        i = 0
        n_lines = len(lines)

        while i < n_lines:
            line = lines[i]
            m = rule_head_re.match(line)
            if not m:
                i += 1
                continue

            indent = len(m.group(1))
            rule_name = m.group(2).strip()
            op = m.group(3).strip()
            first_body = _strip_abnf_comment(m.group(4)).strip()

            # Collect continuation lines (RFC 5234 §2.1: lines starting with SP/HTAB)
            body_parts = [first_body] if first_body else []
            i += 1
            while i < n_lines:
                next_line = lines[i]
                if not next_line.strip():
                    break
                # If next line matches a new rule definition, stop continuation (regardless of indentation)
                cont_m = rule_head_re.match(next_line)
                if cont_m:
                    break

                # Continuation line must be indented with spaces or tabs and deeper than rule header
                next_indent = len(next_line) - len(next_line.lstrip(" \t"))
                if (next_line.startswith(" ") or next_line.startswith("\t")) and next_indent > indent:
                    cont_text = _strip_abnf_comment(next_line).strip()
                    if cont_text:
                        body_parts.append(cont_text)
                    i += 1
                else:
                    break

            full_body = " ".join(body_parts).strip()
            # Filter out non-grammar lines that accidentally match
            if len(full_body) < 2 or full_body.startswith("//") or full_body.startswith("/*"):
                continue

            # Support incremental alternatives (RFC 5234 §2.3: rule =/ elements)
            if op == "=/" and rule_name in self.extracted_rules:
                self.extracted_rules[rule_name]["definition"] += f" / {full_body}"
            else:
                self.extracted_rules[rule_name] = {
                    "rfc_id": rfc_id,
                    "definition": full_body,
                    "section": "ABNF-Extracted",
                }

            req = RFCRequirement(
                requirement_id=f"ABNF-{rfc_id}-{rule_name.upper()}",
                rfc_id=rfc_id,
                section="ABNF",
                req_type=RequirementType.SYNTACTIC_ABNF,
                raw_statement=f"{rule_name} {op} {full_body}",
                formal_expression=f"{rule_name} {op} {full_body}",
            )
            requirements.append(req)

        return requirements

    def generate_conforming(self, rule_name: str) -> bytes:
        """Generates standard, strictly conforming byte representation."""
        rule_lower = rule_name.lower()
        if rule_lower in ("ows", "bws"):
            return b" "
        elif rule_lower == "rws":
            return b" "
        elif rule_lower == "obs-fold":
            return b"\r\n "
        elif rule_lower == "chunk-ext":
            return b";k=v"
        elif rule_lower in ("header-field", "field-line"):
            return b"X-Spec-Test: valid\r\n"
        elif rule_lower == "field-name":
            return b"X-Header"
        elif rule_lower == "field-value":
            return b"valid-value"
        elif rule_lower == "request-line":
            return b"GET / HTTP/1.1\r\n"
        elif rule_lower == "status-line":
            return b"HTTP/1.1 200 OK\r\n"
        elif rule_lower == "tchar":
            return b"a"
        elif rule_lower in ("transfer-coding", "transfer-encoding"):
            return b"chunked"
        return b""

    def generate_inversions(self, rule_name: str, base_context: Optional[bytes] = None) -> List[Tuple[str, bytes]]:
        """
        Synthesizes boundary-violating mutations by inverting the ABNF constraints
        across RFC 9112, 9110, 9113, 7230, and 2616.
        Returns a list of (mutation_strategy_name, inverted_bytes).
        """
        rule_lower = rule_name.lower()
        mutations: List[Tuple[str, bytes]] = []

        if rule_lower in ("ows", "bws"):
            # OWS is *( SP / HTAB ). Inversions test illegal whitespace, bare controls, and nulls.
            mutations.extend([
                ("OWS_BARE_VTAB", b"\x0b"),
                ("OWS_NULL_BYTE", b"\x00"),
                ("OWS_UNICODE_NBSP", b"\xc2\xa0"),
                ("OWS_CARRIAGE_RETURN_SOLO", b"\r"),
                ("OWS_LINE_FEED_SOLO", b"\n"),
            ])
        elif rule_lower == "rws":
            # RWS is 1*( SP / HTAB ). Inversion tests missing whitespace, control chars, and nulls.
            mutations.extend([
                ("RWS_ZERO_WHITESPACE", b""),
                ("RWS_BARE_VTAB", b"\x0b"),
                ("RWS_NULL_BYTE", b"\x00"),
                ("RWS_CARRIAGE_RETURN_SOLO", b"\r"),
                ("RWS_LINE_FEED_SOLO", b"\n"),
            ])
        elif rule_lower in ("header-field", "field-line"):
            # header-field = field-name ":" OWS field-value OWS
            # Inversions: space before colon (RFC 9112 Section 5.1 forbidden), obs-fold, control chars
            mutations.extend([
                ("PRE_COLON_SPACE", b"X-Custom-Header : invalid-space-before-colon\r\n"),
                ("PRE_COLON_TAB", b"X-Custom-Header\t: invalid-tab-before-colon\r\n"),
                ("OBS_FOLD_LF_SPACE", b"X-Custom-Header: fold\n continuing\r\n"),
                ("OBS_FOLD_CRLF_TAB", b"X-Custom-Header: fold\r\n\tcontinuing\r\n"),
                ("EMBEDDED_NULL_HEADER_NAME", b"X-Cust\x00om: null-in-name\r\n"),
                ("DUPLICATE_COLON", b"X-Custom-Header:: double-colon\r\n"),
            ])
        elif rule_lower == "field-name":
            # RFC 9112 §5.1 / RFC 7230 §3.2: field-name = token
            mutations.extend([
                ("FIELD_NAME_SPACE_BEFORE_COLON", b"X-Custom-Header :"),
                ("FIELD_NAME_TAB_BEFORE_COLON", b"X-Custom-Header\t:"),
                ("FIELD_NAME_INTERNAL_SPACE", b"X Custom Header:"),
                ("FIELD_NAME_EMBEDDED_NULL", b"X-Cust\x00om:"),
                ("FIELD_NAME_TRAILING_CR", b"X-Custom-Header\r:"),
            ])
        elif rule_lower == "field-value":
            # RFC 9112 §5.5: field-value = *( field-vchar [ 1*( SP / HTAB ) field-vchar ] )
            mutations.extend([
                ("FIELD_VALUE_EMBEDDED_CR", b"val\runsafe\r\n"),
                ("FIELD_VALUE_EMBEDDED_LF", b"val\nunsafe\r\n"),
                ("FIELD_VALUE_NULL_BYTE", b"val\x00unsafe\r\n"),
                ("FIELD_VALUE_LONG_OVERFLOW", b"A" * 8192 + b"\r\n"),
            ])
        elif rule_lower == "chunk-ext":
            # chunk-ext = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
            # Inversions: missing name, unquoted illegal chars, runaway extensions, null in extension
            mutations.extend([
                ("CHUNK_EXT_EMPTY_SEMICOLON", b";\r\n"),
                ("CHUNK_EXT_SPECIAL_CHARS", b";name=\"unclosed_quote\r\n"),
                ("CHUNK_EXT_NULL_BYTE", b";ext\x00=value\r\n"),
                ("CHUNK_EXT_LONG_PADDING", b";" + (b"A" * 2048) + b"\r\n"),
                ("CHUNK_EXT_DOUBLE_SEMICOLON", b";;key=val\r\n"),
            ])
        elif rule_lower == "obs-fold":
            # obs-fold = CRLF 1*( SP / HTAB )
            # Modern servers MUST reject or sanitize obs-fold.
            mutations.extend([
                ("OBS_FOLD_STANDALONE", b"\r\n "),
                ("OBS_FOLD_MULTIPLE_TABS", b"\r\n\t\t\t"),
                ("OBS_FOLD_CR_ONLY_SPACE", b"\r "),
                ("OBS_FOLD_LF_ONLY_SPACE", b"\n "),
            ])
        elif rule_lower in ("transfer-coding", "transfer-encoding"):
            mutations.extend([
                ("TE_CHUNKS_MIXED_CASE", b"Transfer-Encoding: cHuNkEd\r\n"),
                ("TE_DOUBLE_SPACE_DELIM", b"Transfer-Encoding:  chunked\r\n"),
                ("TE_SPACE_AFTER_CHUNKED", b"Transfer-Encoding: chunked \r\n"),
                ("TE_COMMA_PREFIXED", b"Transfer-Encoding: ,chunked\r\n"),
                ("TE_IDENTITY_CHUNKED_DUAL", b"Transfer-Encoding: identity, chunked\r\n"),
                ("TE_CHUNKED_COW_INVALID", b"Transfer-Encoding: chunked, cow\r\n"),
            ])
        elif rule_lower == "request-line":
            # request-line = method SP request-target SP HTTP-version CRLF
            mutations.extend([
                ("REQ_LINE_MISSING_VERSION", b"GET /\r\n"),
                ("REQ_LINE_TAB_DELIMITED", b"GET\t/\tHTTP/1.1\r\n"),
                ("REQ_LINE_EXTRA_SPACES", b"GET  /  HTTP/1.1\r\n"),
                ("REQ_LINE_BARE_LF", b"GET / HTTP/1.1\n"),
                ("REQ_LINE_CRLF_IN_TARGET", b"GET /path\r\nHost: evil.com HTTP/1.1\r\n"),
            ])
        elif rule_lower == "status-line":
            # status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF
            mutations.extend([
                ("STATUS_LINE_NON_NUMERIC_CODE", b"HTTP/1.1 ABC OK\r\n"),
                ("STATUS_LINE_MISSING_CODE", b"HTTP/1.1 OK\r\n"),
                ("STATUS_LINE_TAB_DELIMITED", b"HTTP/1.1\t200\tOK\r\n"),
                ("STATUS_LINE_BARE_LF", b"HTTP/1.1 200 OK\n"),
            ])
        elif rule_lower == "tchar":
            # tchar inversions: non-tchar chars outside token grammar
            mutations.extend([
                ("TCHAR_AT_SIGN", b"@"),
                ("TCHAR_QUESTION_MARK", b"?"),
                ("TCHAR_SPACE", b" "),
                ("TCHAR_NULL_BYTE", b"\x00"),
                ("TCHAR_COLON", b":"),
            ])
        elif rule_lower in ("pseudo-header", "h2-pseudo-header", "h2-path"):
            # RFC 9113 §8 translation pseudo-header inversions
            mutations.extend([
                ("H2_PATH_CRLF_INJECTION", b"/index\r\nX-Smuggled: 1"),
                ("H2_PATH_NULL_BYTE", b"/test\x00admin"),
                ("H2_UPPERCASE_PSEUDO_HEADER", b":Method"),
            ])
        else:
            # Generic boundary inversion: inject high-order byte, null byte, and bare LF
            mutations.extend([
                ("GENERIC_NULL_BYTE_INJECTION", b"\x00"),
                ("GENERIC_BARE_LF", b"\n"),
                ("GENERIC_OVERFLOW_PADDING", b"X" * 1024),
            ])

        return mutations

    def list_known_rules(self) -> List[str]:
        return list(self.extracted_rules.keys())
