"""
Terminator RFC Selector: Purpose-built RFC specification selector for HTTP Terminators,
Reverse Proxies, Gateways, and Load Balancers.

Prioritizes the exact suite of IETF RFC specifications governing HTTP message syntax,
framing, line terminators (CRLF, bare LF, bare CR), Transfer-Encoding, Content-Length,
and intermediary gateway downgrades based on PortSwigger's HTTP Terminator research by James Kettle.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TerminatorRFCSpec:
    num: int
    rfc_id: str
    title: str
    weight: float
    category: str
    key_sections: List[str]
    discrepancy_focus: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "num": self.num,
            "id": self.rfc_id,
            "title": self.title,
            "weight": self.weight,
            "category": self.category,
            "key_sections": self.key_sections,
            "discrepancy_focus": self.discrepancy_focus,
        }


# Curated specifications governing HTTP Terminators and Intermediaries
# Ranked in order of desync / discrepancy attack yield
TERMINATOR_CORE_RFCS: List[TerminatorRFCSpec] = [
    TerminatorRFCSpec(
        num=9112,
        rfc_id="RFC9112",
        title="HTTP/1.1 (Message Syntax and Framing)",
        weight=1.00,
        category="Core Message Syntax & Framing",
        key_sections=[
            "Section 2.2: Line Terminators (CRLF, bare LF, bare CR)",
            "Section 6.1: Transfer-Encoding vs Content-Length Precedence",
            "Section 6.3: Message Body Length Determination",
            "Section 7.1: Chunked Transfer Coding & Chunk Extensions",
            "Section 5.2: Obsolete Line Folding (obs-fold)",
        ],
        discrepancy_focus="Primary line and message boundary specification. Defines CRLF/LF leniency and chunked framing discrepancies.",
    ),
    TerminatorRFCSpec(
        num=9110,
        rfc_id="RFC9110",
        title="HTTP Semantics",
        weight=0.95,
        category="Intermediary Semantics & Gateways",
        key_sections=[
            "Section 6.3: Intermediaries (Gateways, Proxies, Terminators)",
            "Section 7.2: Host and Authority Identification",
            "Section 9: Method Definitions & Body Expectations",
            "Section 15: Status Codes & Protocol State Signaling",
        ],
        discrepancy_focus="Defines intermediary routing, connection-specific fields, and hop-by-hop header handling.",
    ),
    TerminatorRFCSpec(
        num=7230,
        rfc_id="RFC7230",
        title="HTTP/1.1 Message Syntax and Routing (Predecessor Standard)",
        weight=0.90,
        category="Predecessor Proxy Standard",
        key_sections=[
            "Section 3.3.3: Message Body Length",
            "Section 3.5: Message Parsing Robustness",
            "Section 4: Transfer Codings",
        ],
        discrepancy_focus="Predecessor standard implemented by many active terminators (ALB, Nginx, Envoy, Cloudflare). Discrepancies with RFC 9112 cause desync.",
    ),
    TerminatorRFCSpec(
        num=2616,
        rfc_id="RFC2616",
        title="Hypertext Transfer Protocol -- HTTP/1.1 (Historic Standard)",
        weight=0.85,
        category="Historic Discrepancy Baseline",
        key_sections=[
            "Section 19.2: Tolerant Applications & Parser Leniency",
            "Section 19.4.6: Introduction of Transfer-Encoding",
            "Section 4.4: Message Length determination",
        ],
        discrepancy_focus="Historic 1999 standard. Source of multipart/byteranges parser leniency and obsolete folding confusion.",
    ),
    TerminatorRFCSpec(
        num=9113,
        rfc_id="RFC9113",
        title="HTTP/2 (Extensible Prioritization Scheme & Gateway Translation)",
        weight=0.80,
        category="Intermediary Protocol Translation",
        key_sections=[
            "Section 8: HTTP/2 to HTTP/1.1 Gateway Translation",
            "Section 8.1.1: Malformed Requests and Streams",
            "Section 8.2: HTTP Header Fields and Pseudo-Headers",
        ],
        discrepancy_focus="Rules for translating HTTP/2 frames into HTTP/1.1 wire requests at front-end terminators (H2.CL / H2.TE).",
    ),
    TerminatorRFCSpec(
        num=7540,
        rfc_id="RFC7540",
        title="Hypertext Transfer Protocol Version 2 (HTTP/2)",
        weight=0.75,
        category="Legacy H2 Framing & Intermediary Downgrades",
        key_sections=[
            "Section 8.1.2: HTTP Header Fields",
            "Section 8.1.2.2: Connection-Specific Header Fields",
        ],
        discrepancy_focus="Legacy HTTP/2 framing rules and intermediary downgrade vulnerabilities.",
    ),
    TerminatorRFCSpec(
        num=9114,
        rfc_id="RFC9114",
        title="HTTP/3 (QUIC-based Gateway Termination)",
        weight=0.70,
        category="HTTP/3 Gateway Termination",
        key_sections=[
            "Section 4.1: HTTP/3 Frame Format",
            "Section 4.2: Bidirectional and Unidirectional Streams",
        ],
        discrepancy_focus="QUIC stream boundary and mapping discrepancies across HTTP/3 reverse proxies.",
    ),
    TerminatorRFCSpec(
        num=8446,
        rfc_id="RFC8446",
        title="The Transport Layer Security (TLS) Protocol Version 1.3",
        weight=0.65,
        category="TLS Terminator & Transport",
        key_sections=[
            "Section 4.2.11: Pre-Shared Key Exchange & 0-RTT Early Data",
            "Section 4.2.7: Supported Versions & ALPN Protocol Negotiation",
        ],
        discrepancy_focus="TLS terminator handshakes, ALPN negotiation, and 0-RTT early data request smuggling.",
    ),
    TerminatorRFCSpec(
        num=3986,
        rfc_id="RFC3986",
        title="Uniform Resource Identifier (URI): Generic Syntax",
        weight=0.60,
        category="URI Normalization & Path Truncation",
        key_sections=[
            "Section 3.3: Path Component",
            "Section 5.2.4: Remove Dot Segments",
        ],
        discrepancy_focus="Path normalization, dot-segment removal, and NUL-byte truncation discrepancies between terminator and origin.",
    ),
    TerminatorRFCSpec(
        num=6265,
        rfc_id="RFC6265",
        title="HTTP State Management Mechanism (Cookies)",
        weight=0.55,
        category="Header Parsing & Delimiters",
        key_sections=[
            "Section 4.2: Cookie Header",
            "Section 5.4: The Cookie Header Field",
        ],
        discrepancy_focus="Cookie semicolon vs comma separator handling between reverse proxy and origin application.",
    ),
    TerminatorRFCSpec(
        num=2046,
        rfc_id="RFC2046",
        title="Multipurpose Internet Mail Extensions (MIME) Part Two: Media Types",
        weight=0.50,
        category="Multipart Boundary Delimiters",
        key_sections=[
            "Section 5.1: Multipart Media Type",
            "Section 5.1.1: Common Syntax and Boundaries",
        ],
        discrepancy_focus="Multipart delimiter parsing, preamble interpretation, and boundary quote discrepancies.",
    ),
    TerminatorRFCSpec(
        num=9111,
        rfc_id="RFC9111",
        title="HTTP Caching",
        weight=0.78,
        category="Cache Terminator & Range Poisoning",
        key_sections=[
            "Section 3: Storing Header andTrailer Fields",
            "Section 4.3: Validation & Conditional Requests",
        ],
        discrepancy_focus="Cache key normalization, 206 Partial Content / Range cache poisoning, and Vary header discrepancies.",
    ),
    TerminatorRFCSpec(
        num=7239,
        rfc_id="RFC7239",
        title="Forwarded HTTP Extension",
        weight=0.74,
        category="Intermediary & Reverse Proxy Headers",
        key_sections=[
            "Section 4: Forwarded HTTP Header Field",
            "Section 6: Syntax and Delimiter Rules",
        ],
        discrepancy_focus="Semicolon and comma parameter delimiters in Forwarded/X-Forwarded-* headers across multi-tier terminators.",
    ),
    TerminatorRFCSpec(
        num=8470,
        rfc_id="RFC8470",
        title="Using Early Data in HTTP",
        weight=0.72,
        category="TLS 0-RTT & Early-Data Terminators",
        key_sections=[
            "Section 5.1: The Early-Data Header Field",
            "Section 5.2:The 425 (Too Early) Status Code",
        ],
        discrepancy_focus="0-RTT early data boundary confusion between TLS terminators and backend HTTP/1.1 connection pools.",
    ),
    TerminatorRFCSpec(
        num=6455,
        rfc_id="RFC6455",
        title="The WebSocket Protocol",
        weight=0.68,
        category="Upgrade Tunnel & Stream Terminators",
        key_sections=[
            "Section 4: Opening Handshake & Upgrade",
            "Section 5.2: Base Framing Protocol",
        ],
        discrepancy_focus="101 Switching Protocols upgrade confusion and raw stream tunneling through front-end HTTP terminators.",
    ),
    TerminatorRFCSpec(
        num=8441,
        rfc_id="RFC8441",
        title="Bootstrapping WebSockets with HTTP/2",
        weight=0.66,
        category="H2 Extended CONNECT Terminators",
        key_sections=[
            "Section 4: Using Extended CONNECT To Bootstrap The WebSocket Protocol",
            "Section 5: ':protocol' Pseudo-Header Field",
        ],
        discrepancy_focus="HTTP/2 :protocol pseudo-header downgrade into HTTP/1.1 Upgrade headers at reverse proxies.",
    ),
    TerminatorRFCSpec(
        num=9220,
        rfc_id="RFC9220",
        title="Bootstrapping WebSockets with HTTP/3",
        weight=0.64,
        category="H3 Extended CONNECT Terminators",
        key_sections=[
            "Section 3: WebSockets Upgrade over HTTP/3",
        ],
        discrepancy_focus="QUIC stream termination and HTTP/3 Extended CONNECT translation to backend HTTP/1.1.",
    ),
    TerminatorRFCSpec(
        num=9297,
        rfc_id="RFC9297",
        title="HTTP Datagrams and the Capsule Protocol",
        weight=0.62,
        category="Capsule Framing & Datagram Terminators",
        key_sections=[
            "Section 3.1: Capsule-Protocol Header Field",
            "Section 3.2: Capsule Stream Framing",
        ],
        discrepancy_focus="Variable-length integer capsule length delimiters vs HTTP/1.1 body framing on intermediaries.",
    ),
    TerminatorRFCSpec(
        num=9298,
        rfc_id="RFC9298",
        title="Proxying UDP in HTTP (MASQUE Connect-UDP)",
        weight=0.61,
        category="Gateway Tunnel Terminators",
        key_sections=[
            "Section 3: UDP Proxying Request & Response Framing",
        ],
        discrepancy_focus="Connect-UDP tunnel upgrades and datagram frame termination across multi-hop gateways.",
    ),
    TerminatorRFCSpec(
        num=9651,
        rfc_id="RFC9651",
        title="Structured Field Values for HTTP",
        weight=0.67,
        category="Structured Header Delimiters & Terminators",
        key_sections=[
            "Section 3: Structured Data Types (Lists, Dictionaries, Byte Sequences)",
            "Section 4.2: Parsing Structured Fields",
        ],
        discrepancy_focus="Strict ABNF parsing of colon-delimited `:byte-sequence:`, parameters, and inner-list terminators.",
    ),
    TerminatorRFCSpec(
        num=9421,
        rfc_id="RFC9421",
        title="HTTP Message Signatures",
        weight=0.58,
        category="Signature Boundary & Canonicalization",
        key_sections=[
            "Section 2: Signature Base Construction & Line Terminators",
            "Section 4: Signature-Input and Signature Fields",
        ],
        discrepancy_focus="Header canonicalization, line-folding normalization, and derived component ambiguity at API gateways.",
    ),
    TerminatorRFCSpec(
        num=7541,
        rfc_id="RFC7541",
        title="HPACK: Header Compression for HTTP/2",
        weight=0.63,
        category="Header Compression & EOS Terminators",
        key_sections=[
            "Section 5.2: String Literal Representation & Huffman EOS",
            "Section 6: Binary Format & Dynamic Table Indexing",
        ],
        discrepancy_focus="Huffman End-of-String (EOS) padding termination and control byte injection during H2->H1 decompression.",
    ),
    TerminatorRFCSpec(
        num=9204,
        rfc_id="RFC9204",
        title="QPACK: Field Compression for HTTP/3",
        weight=0.59,
        category="QPACK Stream & Field Line Terminators",
        key_sections=[
            "Section 4: Wire Format for Encoder and Decoder Streams",
        ],
        discrepancy_focus="QPACK field section prefix and blocked stream termination when translating HTTP/3 to HTTP/1.1.",
    ),
    TerminatorRFCSpec(
        num=9209,
        rfc_id="RFC9209",
        title="The Proxy-Status HTTP Response Header Field",
        weight=0.57,
        category="Intermediary Telemetry & Error Terminators",
        key_sections=[
            "Section 2: The Proxy-Status HTTP Header Field",
        ],
        discrepancy_focus="Reverse proxy upstream error signaling, timeout handling, and connection reuse state after backend errors.",
    ),
    TerminatorRFCSpec(
        num=8297,
        rfc_id="RFC8297",
        title="An HTTP Status Code for Indicating Hints (103 Early Hints)",
        weight=0.69,
        category="Interim Response Terminators",
        key_sections=[
            "Section 2: The 103 (Early Hints) Informational Status Code",
        ],
        discrepancy_focus="Multi-status line framing (100/103 interim responses followed by final response) confusing shared parsers.",
    ),
]

# Keywords specifically indicating operative terminator behavior or parsing ambiguities
TERMINATOR_OPERATIVE_KEYWORDS = [
    # Message Boundaries & Line Terminators
    "terminator", "line terminator", "crlf", "bare cr", "bare lf", "lfcr",
    "end of headers", "empty line", "delimiter", "delimit", "null", "octet",
    # Framing & Chunking
    "transfer-encoding", "content-length", "chunked", "chunk extension",
    "chunk-size", "chunk-data", "trailer", "last-chunk", "message body length",
    "content-range", "byteranges", "capsule", "capsule-protocol",
    # Intermediaries & Gateways
    "intermediary", "gateway", "reverse proxy", "proxy", "recipient",
    "sender", "inbound", "outbound", "forwarding", "downgrade", "early-data",
    "forwarded", "proxy-status", "early hints", "100-continue", "switching protocols",
    # Parsing Tolerances & Divergence
    "obs-fold", "folding", "line folding", "whitespace", "sp", "htab", "bws", "ows",
    "must reject", "must ignore", "must not", "should reject",
    "multipart/byteranges", "boundary", "tunnel", "upgrade", "websocket",
    "structured field", "huffman", "pseudo-header"
]


class TerminatorRFCSelector:
    """
    Intelligent RFC Selector optimized for discovering implementation discrepancies
    in HTTP Terminators, Reverse Proxies, and Gateways.
    """

    @classmethod
    def get_terminator_specs(cls) -> List[TerminatorRFCSpec]:
        """Returns the full list of curated Terminator RFC specifications."""
        return list(TERMINATOR_CORE_RFCS)

    @classmethod
    def get_terminator_corpus(cls, max_rfcs: Optional[int] = None) -> List[int]:
        """
        Returns the ordered list of RFC numbers prioritized specifically for
        HTTP Terminators. RFC 9112 is guaranteed to be position 0.
        """
        nums = [spec.num for spec in TERMINATOR_CORE_RFCS]
        if max_rfcs and max_rfcs > 0:
            return nums[:max_rfcs]
        return nums

    @classmethod
    def get_spec_by_num(cls, rfc_num: int) -> Optional[TerminatorRFCSpec]:
        """Looks up a Terminator specification by its numeric identifier."""
        for spec in TERMINATOR_CORE_RFCS:
            if spec.num == rfc_num:
                return spec
        return None

    @classmethod
    def score_text_for_terminator(cls, text: str) -> Tuple[float, List[str]]:
        """
        Scores a text segment (RFC chunk or section) based on its density of
        terminator-specific discrepancy and framing keywords.
        Returns (score, matched_keywords).
        """
        if not text:
            return 0.0, []

        text_lower = text.lower()
        matched = []
        weight_sum = 0.0

        high_impact = {
            "line terminator": 3.0,
            "terminator": 2.5,
            "bare cr": 3.0,
            "bare lf": 3.0,
            "lfcr": 3.0,
            "crlf": 2.5,
            "transfer-encoding": 3.0,
            "content-length": 3.0,
            "chunk extension": 3.0,
            "last-chunk": 2.5,
            "trailer": 2.5,
            "obs-fold": 3.0,
            "intermediary": 2.5,
            "gateway": 2.0,
            "reverse proxy": 2.5,
            "multipart/byteranges": 3.0,
            "content-range": 2.5,
            "early-data": 2.5,
            "early hints": 2.5,
            "capsule": 2.5,
            "pseudo-header": 2.5,
            "must reject": 2.5,
            "must ignore": 2.5,
        }

        for kw in TERMINATOR_OPERATIVE_KEYWORDS:
            if kw in text_lower:
                matched.append(kw)
                weight_sum += high_impact.get(kw, 1.0)

        # Normalize score relative to text length
        word_count = max(1, len(text.split()))
        normalized_score = round((weight_sum / (word_count ** 0.5)) * 10.0, 3)

        return normalized_score, matched

    @classmethod
    def is_terminator_relevant(cls, rfc_num: int) -> bool:
        """Checks if a given RFC number is part of the core Terminator suite."""
        return any(spec.num == rfc_num for spec in TERMINATOR_CORE_RFCS)
