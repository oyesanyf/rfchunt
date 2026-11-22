"""
AIxCC Upgrade #4: Canonical Structural Fingerprinting & Known-Technique Novelty Corpus.

Provides:
1. `CanonicalStructuralFingerprinter`:
   - Canonicalizes raw protocol wire probes (method/target/version tokens, header framing
     topology including CL/TE/chunk-ext/obs-fold/trailer/NUL/HTTP2 pseudo-headers,
     line delimiters & byte-class tokens, and multi-implementation parser divergence vectors).
   - Canonicalizes AST / static code-taint findings (source/sink/sanitizer structural
     signature + CWE family) while stripping superficial file paths, line numbers, and
     variable names.
   - Computes deterministic shingle/token Jaccard + corpus TF-IDF cosine similarity
     strictly in the Python standard library (zero heavy external dependencies).

2. `NoveltyCorpusIndex`:
   - Built strictly offline by default (zero network calls) from:
     a) Built-in structured PortSwigger HTTP desync & protocol research catalog,
     b) Built-in CWE/CVE protocol-flaw & code-taint taxonomy,
     c) Workspace Nuclei YAML templates (`defense_rules/`, `templates/`, `data/`),
     d) Prior verified findings loaded from `terminator.db` (`reproducible_vulnerabilities`
        / `vulnerabilities`, `novel_techniques`, `blackboard_nodes` `FACT` rows).
   - Exposes explicit opt-in `refresh_from_sources(paths_or_urls, allow_network=False)`
     for CLI-driven ingestion of local JSON/YAML/Nuclei catalogs or explicitly permitted
     remote feeds (validated against SSRF invariants when `allow_network=True`).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants & Canonical Vocabularies
# ---------------------------------------------------------------------------

DEFAULT_NOVELTY_THRESHOLD: float = 0.72

_STANDARD_HTTP_METHODS: Set[str] = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE",
    "PRI",
}

_NOISE_HEADERS: Set[str] = {
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "accept-charset",
    "cookie",
    "referer",
    "origin",
    "date",
    "dnt",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "x-b3-traceid",
    "x-b3-spanid",
    "traceparent",
    "tracestate",
    "x-nonce",
    "x-canary",
    "x-timestamp",
    "x-random",
    "x-test-id",
    "x-session-id",
    "authorization",
    "x-api-key",
    "x-csrf-token",
    "x-xsrf-token",
    "upgrade-insecure-requests",
}

_NOISE_HEADER_RX = re.compile(
    r"^x-(?:nonce|rand|random|req|request|trace|corr|correlation|canary|probe|trial|run|session|token|id|client|debug)[-_0-9a-z]*$",
    re.IGNORECASE,
)

_PROXY_OVERRIDE_HEADERS: Set[str] = {
    "x-forwarded-host",
    "x-host",
    "x-original-url",
    "x-rewrite-url",
    "x-forwarded-scheme",
    "x-forwarded-proto",
    "forwarded",
}

_RESPONSE_STATUS_LINE_RX = re.compile(rb"^HTTP/(\d)\.(\d)\s+(\d{3})(?:\s|$)", re.IGNORECASE)
_EMBEDDED_HTTP_REQ_RX = re.compile(
    rb"(?:^|[\r\n])(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|GPOST|SMUGGLED)\s+\S+\s+HTTP/\d\.\d",
    re.IGNORECASE,
)
_EMBEDDED_HTTP_REQ_PREFIX_RX = re.compile(
    rb"(?:^|[\r\n])(?:GPOST|SMUGGLED|GET\s+/|POST\s+/|HEAD\s+/|DELETE\s+/|PUT\s+/)",
    re.IGNORECASE,
)
_EMBEDDED_HTTP_RESP_RX = re.compile(rb"(?:^|[\r\n])HTTP/\d\.\d\s+\d{3}\b", re.IGNORECASE)
_CHUNK_EXT_LINE_RX = re.compile(rb"(?:^|[\r\n])[0-9a-fA-F]+[ \t]*;([^\r\n]*)")
_CHUNK_NONZERO_LINE_RX = re.compile(rb"^[0-9a-fA-F]{1,16}(?:[ \t]*;[^\r\n]*)?\r?\n")
_PCT_CRLF_RX = re.compile(rb"(?:%0[da]|%250[da])", re.IGNORECASE)
_DOTDOT_RX = re.compile(rb"(?:\.\./|\.\.\\|%2e%2e|%252e%252e)", re.IGNORECASE)

_CWE_FAMILY_MAP: Dict[str, str] = {
    "CWE-89": "INJECTION_SQL",
    "CWE-564": "INJECTION_SQL",
    "CWE-78": "INJECTION_CMD",
    "CWE-77": "INJECTION_CMD",
    "CWE-88": "INJECTION_CMD",
    "CWE-79": "INJECTION_XSS",
    "CWE-80": "INJECTION_XSS",
    "CWE-94": "INJECTION_CODE",
    "CWE-95": "INJECTION_CODE",
    "CWE-96": "INJECTION_CODE",
    "CWE-1336": "INJECTION_TEMPLATE",
    "CWE-90": "INJECTION_LDAP",
    "CWE-643": "INJECTION_XPATH",
    "CWE-22": "PATH_TRAVERSAL",
    "CWE-23": "PATH_TRAVERSAL",
    "CWE-36": "PATH_TRAVERSAL",
    "CWE-73": "PATH_TRAVERSAL",
    "CWE-918": "SSRF",
    "CWE-502": "DESERIALIZATION",
    "CWE-611": "XXE",
    "CWE-776": "XXE",
    "CWE-444": "HTTP_DESYNC",
    "CWE-113": "HTTP_HEADER_INJECTION",
    "CWE-436": "INTERPRETATION_CONFLICT",
    "CWE-287": "AUTH_BYPASS",
    "CWE-288": "AUTH_BYPASS",
    "CWE-306": "AUTH_BYPASS",
    "CWE-862": "AUTHZ_BYPASS",
    "CWE-863": "AUTHZ_BYPASS",
    "CWE-1321": "PROTOTYPE_POLLUTION",
    "CWE-327": "WEAK_CRYPTO",
    "CWE-328": "WEAK_CRYPTO",
    "CWE-330": "WEAK_CRYPTO",
    "CWE-190": "INTEGER_OVERFLOW",
    "CWE-400": "RESOURCE_EXHAUSTION",
    "CWE-770": "RESOURCE_EXHAUSTION",
}

_AST_SOURCE_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "HTTP_HEADER",
        re.compile(
            r"\b(request\.headers|req\.headers|http_header|x-forwarded|cookie|header_value|get_header|headers\.get)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "HTTP_PATH",
        re.compile(
            r"\b(request\.path|req\.path|req\.url|request\.url|url_path|route_param|path_param|request_uri)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "AUTH_TOKEN",
        re.compile(
            r"\b(jwt|oidc|id_token|idtoken|access_token|bearer|session_token|auth_token|claims)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "RPC_IPC",
        re.compile(
            r"\b(ipc|ipcmain|ipcrenderer|postmessage|grpc|websocket|rpc_payload|message_event)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CLI_ENV",
        re.compile(
            r"\b(sys\.argv|process\.argv|os\.environ|process\.env|getenv|cli_arg|argv)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "FILE_NET_STREAM",
        re.compile(
            r"\b(socket\.recv|recv\(|stdin|file\.read|read_bytes|untrusted_bytes|raw_stream|network_stream|external_payload|serialized_data|pickle_bytes)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "HTTP_PARAM",
        re.compile(
            r"\b(request\.args|request\.form|request\.json|request\.values|request\.data|req\.query|req\.body|req\.params|\$_get|\$_post|query_param|http_param|user_input|untrusted_input|form_input|api_input)\b",
            re.IGNORECASE,
        ),
    ),
)

_AST_SINK_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "SQL_EXEC",
        re.compile(
            r"\b(cursor\.execute|db\.execute|conn\.execute|session\.execute|raw_sql|sequelize\.query|sql_exec|sql_query|executemany|query_raw)\b|select\s+.+\s+from\s+",
            re.IGNORECASE,
        ),
    ),
    (
        "OS_CMD_EXEC",
        re.compile(
            r"\b(os\.system|os\.popen|subprocess\.(?:run|popen|call|check_output|check_call)|child_process\.exec|execsync|shell=true|runtime\.getruntime\(\)\.exec|os_cmd|cmd_exec|shell_exec)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CODE_EVAL",
        re.compile(
            r"\b(eval|exec|compile|vm\.runincontext|vm\.runinnewcontext|new\s+function|code_eval|dynamic_eval)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "TEMPLATE_RENDER",
        re.compile(
            r"\b(render_template_string|jinja2\.template|mako\.template|ejs\.render|pug\.render|ssti|template_render)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "HTML_DOM_XSS",
        re.compile(
            r"\b(innerhtml|outerhtml|document\.write|dangerouslysetinnerhtml|mark_safe|html_response|dom_xss|xss_sink)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "FS_PATH_IO",
        re.compile(
            r"\b(open|os\.path\.join|pathlib\.path|fs\.readfile|fs\.writefile|send_file|send_from_directory|shutil\.(?:copy|move|rmtree)|file_read|file_write|fs_path_io)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "NET_SSRF",
        re.compile(
            r"\b(requests\.(?:get|post|put|delete|request)|urllib\.request|urlopen|httpx\.(?:get|post|request)|aiohttp|axios|fetch|http\.get|socket\.connect|net_ssrf|http_client_fetch)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DESERIALIZE",
        re.compile(
            r"\b(pickle\.loads|pickle\.load|yaml\.load|yaml\.unsafe_load|marshal\.loads|objectinputstream|unserialize|node-serialize|deserialize)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "XML_PARSE",
        re.compile(
            r"\b(etree\.fromstring|etree\.parse|xml\.sax|minidom|documentbuilder|xmlparser|lxml\.etree|xml_parse)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "AUTHZ_BYPASS",
        re.compile(
            r"\b(verify_jwt|verify_oidc|verifyidtoken|jwt\.verify|jwt\.decode|audience|role_check|auth_bypass|authz_bypass|privilege_check|internal_route)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PROTO_POLLUTE",
        re.compile(
            r"\b(__proto__|constructor\.prototype|deep_merge|object\.assign|lodash\.merge|proto_pollute)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "HTTP_HEADER_OUT",
        re.compile(
            r"\b(set_header|add_header|res\.setheader|response\.headers|send_header|http_header_out|redirect_header)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CRYPTO_WEAK",
        re.compile(
            r"\b(hashlib\.md5|hashlib\.sha1|aes\.mode_ecb|des\.new|arc4|rc4|random\.random|crypto_weak|weak_hash)\b",
            re.IGNORECASE,
        ),
    ),
)

_AST_SANITIZER_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("PARAM_BIND", re.compile(r"\b(parameterized|prepared_statement|bind_param|placeholder|sql_param)\b", re.IGNORECASE)),
    ("ALLOWLIST", re.compile(r"\b(allowlist|whitelist|cidr_check|validate_target_host|is_safe_target_ip)\b", re.IGNORECASE)),
    ("ESCAPE_ENCODE", re.compile(r"\b(html\.escape|dompurify|shlex\.quote|urlencode|escape|sanitize_html)\b", re.IGNORECASE)),
    ("CANONICAL_PATH", re.compile(r"\b(realpath|resolve|is_relative_to|commonpath|canonical_path)\b", re.IGNORECASE)),
    ("SAFE_LOADER", re.compile(r"\b(safe_load|defusedxml|json\.loads|safeloader)\b", re.IGNORECASE)),
    ("AUTHZ_GUARD", re.compile(r"\b(audience_check|require_service|check_audience|mtls|rbac_guard)\b", re.IGNORECASE)),
    ("SCHEMA_VALIDATE", re.compile(r"\b(pydantic|jsonschema|schema_validate|strict_regex)\b", re.IGNORECASE)),
)


# ---------------------------------------------------------------------------
# Data Contracts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StructuralFingerprint:
    """Canonical minimized structural fingerprint for wire probes or AST taint findings."""

    fingerprint_id: str
    kind: str  # "wire", "ast", or "hybrid"
    canonical_form: str
    tokens: Tuple[str, ...]
    shingles: Tuple[str, ...]
    features: Dict[str, Any] = field(default_factory=dict)

    def all_terms(self) -> Tuple[str, ...]:
        """Returns deterministic combined term sequence (tokens + structural shingles)."""
        return self.tokens + self.shingles

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_id": self.fingerprint_id,
            "kind": self.kind,
            "canonical_form": self.canonical_form,
            "tokens": list(self.tokens),
            "shingles": list(self.shingles),
            "features": self.features,
        }


@dataclass
class CorpusEntry:
    """A single known technique or prior finding indexed in `NoveltyCorpusIndex`."""

    entry_id: str
    title: str
    source: str
    kind: str
    category: str
    fingerprint: StructuralFingerprint
    description: str = ""
    cwe_ids: Tuple[str, ...] = ()
    cve_ids: Tuple[str, ...] = ()
    rfc_refs: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()
    canonical_probe: Optional[bytes] = None
    ast_signature: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "title": self.title,
            "source": self.source,
            "kind": self.kind,
            "category": self.category,
            "description": self.description,
            "cwe_ids": list(self.cwe_ids),
            "cve_ids": list(self.cve_ids),
            "rfc_refs": list(self.rfc_refs),
            "references": list(self.references),
            "fingerprint": self.fingerprint.to_dict(),
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class SimilarityMatch:
    """Nearest-neighbor match result returned by `NoveltyCorpusIndex.query*`."""

    entry_id: str
    title: str
    source: str
    category: str
    similarity: float
    jaccard_similarity: float
    tfidf_cosine_similarity: float
    matched_tokens: Tuple[str, ...]
    explanation: str
    cwe_ids: Tuple[str, ...] = ()
    cve_ids: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()
    fingerprint_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "title": self.title,
            "source": self.source,
            "category": self.category,
            "similarity": round(self.similarity, 4),
            "jaccard_similarity": round(self.jaccard_similarity, 4),
            "tfidf_cosine_similarity": round(self.tfidf_cosine_similarity, 4),
            "matched_tokens": list(self.matched_tokens),
            "explanation": self.explanation,
            "cwe_ids": list(self.cwe_ids),
            "cve_ids": list(self.cve_ids),
            "references": list(self.references),
            "fingerprint_id": self.fingerprint_id,
        }


@dataclass(frozen=True)
class NoveltyQueryResult:
    """Complete novelty similarity evaluation result against `NoveltyCorpusIndex`."""

    query_fingerprint: StructuralFingerprint
    max_similarity: float
    threshold: float
    is_known: bool
    nearest_matches: Tuple[SimilarityMatch, ...]
    corpus_size: int
    sources_loaded: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_fingerprint": self.query_fingerprint.to_dict(),
            "max_similarity": round(self.max_similarity, 4),
            "threshold": round(self.threshold, 4),
            "is_known": self.is_known,
            "nearest_matches": [m.to_dict() for m in self.nearest_matches],
            "corpus_size": self.corpus_size,
            "sources_loaded": dict(self.sources_loaded),
        }


# ---------------------------------------------------------------------------
# Canonical Structural Fingerprinter
# ---------------------------------------------------------------------------

def _normalize_cwe_id(raw: Any) -> Optional[str]:
    text = str(raw or "").strip().upper()
    if not text:
        return None
    m = re.search(r"(?:CWE[-_:\s]*)?0*(\d{1,5})\b", text)
    if not m:
        return None
    return f"CWE-{int(m.group(1))}"


def _slugify_token(raw: str, max_len: int = 32) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", str(raw or "").strip()).strip("_").upper()
    return cleaned[:max_len] if cleaned else "UNKNOWN"


def _build_grouped_shingles(tokens: Sequence[str]) -> Tuple[str, ...]:
    """
    Constructs deterministic structural 2-gram shingles grouped by semantic prefix.
    Grouping ensures that a benign method variation (e.g., GET vs POST) does not
    shatter anomaly/framing bigrams, while still encoding structural co-occurrence.
    """
    if len(tokens) < 2:
        return ()

    buckets: Dict[str, List[str]] = {
        "context": [],
        "mechanism": [],
        "body_div": [],
        "ast": [],
    }
    for tok in tokens:
        if tok.startswith(("PROTO:", "M:", "V:", "DELIM:", "TARGET:", "H2:")):
            buckets["context"].append(tok)
        elif tok.startswith(("FRAMING:", "ANOM:", "SYNTAX:", "DESYNC:", "INVERSION:", "BYTE:", "HDR:", "HOST:", "STARTLINE:")):
            buckets["mechanism"].append(tok)
        elif tok.startswith(("BODY:", "DIV:")):
            buckets["body_div"].append(tok)
        else:
            buckets["ast"].append(tok)

    shingles: List[str] = []
    seen: Set[str] = set()

    def _emit(seq: Sequence[str], tag: str) -> None:
        ordered = sorted(set(seq))
        for i in range(len(ordered) - 1):
            sh = f"SH2:{tag}:{ordered[i]}+{ordered[i + 1]}"
            if sh not in seen:
                seen.add(sh)
                shingles.append(sh)

    for b_name, b_toks in buckets.items():
        _emit(b_toks, b_name.upper())

    # Cross-link high-signal mechanism tokens with protocol/body anchors
    mech_ordered = sorted(set(buckets["mechanism"]))
    if mech_ordered and buckets["context"]:
        proto_anchor = next((t for t in sorted(buckets["context"]) if t.startswith("PROTO:")), buckets["context"][0])
        for m_tok in mech_ordered[:6]:
            sh = f"SH2:XLINK:{proto_anchor}+{m_tok}"
            if sh not in seen:
                seen.add(sh)
                shingles.append(sh)
    if mech_ordered and buckets["body_div"]:
        for m_tok in mech_ordered[:3]:
            for bd_tok in sorted(set(buckets["body_div"]))[:3]:
                sh = f"SH2:MBD:{m_tok}+{bd_tok}"
                if sh not in seen:
                    seen.add(sh)
                    shingles.append(sh)

    return tuple(sorted(shingles))


def _status_bucket(status: int) -> str:
    if status <= 0:
        return "0"
    if 100 <= status < 200:
        return "1XX"
    if 200 <= status < 300:
        return "2XX"
    if 300 <= status < 400:
        return "3XX"
    if 400 <= status < 500:
        return "4XX"
    if 500 <= status < 600:
        return "5XX"
    return "OTHER"


class CanonicalStructuralFingerprinter:
    """
    Produces canonical minimized wire & AST fingerprints and deterministic
    pure-stdlib Jaccard similarity helpers.
    """

    def extract_divergence_tokens(self, divergence_matrix: Optional[Dict[str, Any]]) -> Tuple[List[str], Dict[str, Any]]:
        """Normalizes a multi-implementation parser divergence matrix into compact structural tokens."""
        if not isinstance(divergence_matrix, dict) or not divergence_matrix:
            return [], {"has_divergence": False, "status_buckets": [], "socket_states": []}

        statuses: List[int] = []
        status_buckets: Set[str] = set()
        socket_states: Set[str] = set()
        for entry in divergence_matrix.values():
            if not isinstance(entry, dict):
                continue
            st = entry.get("status", entry.get("status_code"))
            if isinstance(st, int):
                if st > 0:
                    statuses.append(st)
                status_buckets.add(_status_bucket(st))
            s_state = str(entry.get("socket_state") or "").strip().upper()
            if s_state:
                socket_states.add(s_state)

        distinct_statuses = sorted(set(statuses))
        distinct_states = sorted(socket_states)
        has_div = len(distinct_statuses) > 1 or len(distinct_states) > 1

        tokens: List[str] = []
        if has_div:
            tokens.append("DIV:PARSER_DIVERGENCE")
            has_accept = any(200 <= s < 400 for s in distinct_statuses)
            has_reject = any(400 <= s < 500 for s in distinct_statuses)
            has_err = any(s >= 500 for s in distinct_statuses)
            if has_accept and has_reject:
                tokens.append("DIV:ACCEPT_VS_REJECT")
            elif has_accept and has_err:
                tokens.append("DIV:ACCEPT_VS_SERVER_ERR")
            elif has_reject and has_err:
                tokens.append("DIV:REJECT_VS_SERVER_ERR")
            if "TIMEOUT" in socket_states and "OK" in socket_states:
                tokens.append("DIV:TIMEOUT_VS_OK")
            elif "CONNECTION_CLOSED" in socket_states and "OK" in socket_states:
                tokens.append("DIV:CLOSED_VS_OK")
        return tokens, {
            "has_divergence": has_div,
            "statuses": distinct_statuses,
            "status_buckets": sorted(status_buckets),
            "socket_states": distinct_states,
        }

    def extract_wire_features(
        self,
        raw_probe: Union[bytes, str],
        *,
        divergence_matrix: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Extracts canonical framing, syntax, byte-class, and divergence features from a wire probe."""
        if isinstance(raw_probe, str):
            probe = raw_probe.encode("latin-1", errors="replace")
        else:
            probe = bytes(raw_probe or b"")

        tokens: List[str] = []
        features: Dict[str, Any] = {
            "probe_len": len(probe),
            "protocol": "H1",
            "method": None,
            "version": None,
            "delimiters": [],
            "framing_flags": [],
            "anomalies": [],
            "desync_classes": [],
            "byte_classes": [],
            "headers_canonical": [],
            "body_classes": [],
            "has_structural_anomaly": False,
        }

        if not probe:
            tokens.append("PROTO:EMPTY")
            features["protocol"] = "EMPTY"
            features["tokens"] = tokens
            return features

        # 1. Split header block and body while capturing delimiter topology
        delim_kind = "NO_TERM"
        head = probe
        body = b""
        if b"\r\n\r\n" in probe:
            head, body = probe.split(b"\r\n\r\n", 1)
            delim_kind = "CRLF"
        elif b"\n\n" in probe:
            head, body = probe.split(b"\n\n", 1)
            delim_kind = "BARE_LF"
        elif b"\r\r" in probe:
            head, body = probe.split(b"\r\r", 1)
            delim_kind = "BARE_CR"
        elif b"\r\n\n" in probe or b"\n\r\n" in probe:
            m_sep = re.search(rb"(?:\r\n\n|\n\r\n)", probe)
            if m_sep:
                head = probe[: m_sep.start()]
                body = probe[m_sep.end() :]
            delim_kind = "MIXED_LF"

        # Inspect line delimiters inside header block
        head_no_crlf = head.replace(b"\r\n", b"")
        has_bare_lf_in_head = b"\n" in head_no_crlf
        has_bare_cr_in_head = b"\r" in head_no_crlf
        if delim_kind == "CRLF" and (has_bare_lf_in_head or has_bare_cr_in_head):
            delim_kind = "MIXED_LF" if has_bare_lf_in_head else "MIXED_CR"

        features["delimiters"].append(delim_kind)

        # Normalize line split for structural parsing
        raw_lines = re.split(rb"\r\n|\n|\r", head)
        start_line = raw_lines[0] if raw_lines else b""
        header_lines = raw_lines[1:] if len(raw_lines) > 1 else []

        # Check for HTTP/2 pseudo-header block or HTTP/2 connection preface
        is_h2_preface = probe.startswith(b"PRI * HTTP/2.0")
        has_h2_pseudo_lines = any(
            line.lstrip().startswith((b":method", b":path", b":authority", b":scheme", b":status"))
            for line in raw_lines[:8]
        )
        is_resp_inversion = bool(_RESPONSE_STATUS_LINE_RX.match(start_line))

        # Byte-class inspection (NUL, VTAB/FF, CTL, high bytes)
        has_nul_start = b"\x00" in start_line
        has_nul_head = any(b"\x00" in ln for ln in header_lines)
        has_nul_body = b"\x00" in body
        if has_nul_start or has_nul_head or has_nul_body:
            features["byte_classes"].append("NUL")
            tokens.extend(["BYTE:NUL_FRAME", "ANOM:NUL_BYTE_TRUNCATION", "INVERSION:C_STRING_NUL"])
            if has_nul_start:
                tokens.append("BYTE:NUL_STARTLINE")
            if has_nul_head:
                tokens.append("BYTE:NUL_HEADER")
            if has_nul_body:
                tokens.append("BYTE:NUL_BODY")

        has_vtab_ff_head = (b"\x0b" in head) or (b"\x0c" in head)
        if has_vtab_ff_head:
            features["byte_classes"].append("VTAB_FF")
            tokens.append("BYTE:VTAB_FF_HEAD")

        other_ctl_head = any(
            (1 <= b <= 8) or (14 <= b <= 31) or b == 127
            for b in head
        )
        if other_ctl_head:
            features["byte_classes"].append("CTL_HEAD")
            tokens.append("BYTE:CTL_IN_HEAD")

        if any(b >= 128 for b in head):
            features["byte_classes"].append("HIGH_HEAD")
            tokens.append("BYTE:HIGH_BYTES_HEAD")

        # 2. Protocol & Start-Line classification
        method_norm: Optional[str] = None
        version_norm: Optional[str] = None
        h2_pseudo_map: Dict[str, bytes] = {}
        h2_header_crlf = False
        h2_pseudo_crlf = False

        if is_resp_inversion:
            features["protocol"] = "RESP_INVERSION"
            m_st = _RESPONSE_STATUS_LINE_RX.match(start_line)
            st_code = int(m_st.group(3)) if m_st else 200
            tokens.extend([
                "PROTO:RESP_INVERSION",
                "STARTLINE:HTTP_STATUS_AS_REQ",
                f"STARTLINE:RESP_{_status_bucket(st_code)}",
                "ANOM:RESPONSE_STATUS_IN_REQUEST",
                "INVERSION:SHARED_PARSER",
            ])
            features["anomalies"].append("RESPONSE_STATUS_IN_REQUEST")
        elif is_h2_preface or has_h2_pseudo_lines:
            features["protocol"] = "H2"
            tokens.append("PROTO:H2")
            if is_h2_preface:
                tokens.append("H2:PREFACE")
            # Collect pseudo-headers from all lines in head (including line 0 if starts with ':')
            pseudo_scan = raw_lines if start_line.lstrip().startswith(b":") else header_lines
            remaining_header_lines: List[bytes] = []
            for ln in pseudo_scan:
                stripped = ln.strip()
                if stripped.startswith(b":") and b":" in stripped[1:]:
                    idx = stripped.index(b":", 1)
                    pname = stripped[:idx].decode("latin-1", errors="replace").strip().lower()
                    pval = stripped[idx + 1 :].strip()
                    h2_pseudo_map[pname] = pval
                    if b"\\r\\n" in pval or b"\r" in pval or b"\n" in pval or _PCT_CRLF_RX.search(pval):
                        h2_pseudo_crlf = True
                else:
                    remaining_header_lines.append(ln)
            header_lines = remaining_header_lines

            if ":status" in h2_pseudo_map:
                tokens.extend([
                    "H2:STATUS_AS_REQ",
                    "ANOM:RESPONSE_STATUS_IN_REQUEST",
                    "INVERSION:SHARED_PARSER",
                ])
                features["anomalies"].append("H2_STATUS_IN_REQUEST")
            else:
                tokens.append("H2:PSEUDO_REQ")
                if ":method" in h2_pseudo_map:
                    raw_m = h2_pseudo_map[":method"].decode("latin-1", errors="replace").strip().upper()
                    method_norm = raw_m if raw_m in _STANDARD_HTTP_METHODS else "CUSTOM"
                    features["method"] = method_norm
                    tokens.append(f"M:{method_norm}")
                    if raw_m == "CONNECT":
                        tokens.append("H2:CONNECT_METHOD")
                if ":path" in h2_pseudo_map:
                    pval = h2_pseudo_map[":path"]
                    if b" " in pval or b"\t" in pval or b"\\r\\n" in pval or _PCT_CRLF_RX.search(pval):
                        h2_pseudo_crlf = True
                if ":authority" in h2_pseudo_map:
                    aval = h2_pseudo_map[":authority"]
                    if b" " in aval or b"@" in aval or b"\\r\\n" in aval or _PCT_CRLF_RX.search(aval):
                        h2_pseudo_crlf = True
        else:
            # Parse HTTP/1.x or custom wire start-line
            parts = start_line.split(b" ")
            if len(parts) >= 3 and parts[-1].upper().startswith(b"HTTP/"):
                raw_method = parts[0].decode("latin-1", errors="replace").strip().upper()
                raw_target = b" ".join(parts[1:-1])
                raw_ver = parts[-1].decode("latin-1", errors="replace").strip()

                method_norm = raw_method if raw_method in _STANDARD_HTTP_METHODS else "CUSTOM"
                features["method"] = method_norm
                ver_upper = raw_ver.upper()
                if ver_upper == "HTTP/1.1":
                    version_norm = "H1.1"
                    features["protocol"] = "H1"
                elif ver_upper == "HTTP/1.0":
                    version_norm = "H1.0"
                    features["protocol"] = "H1"
                elif ver_upper in ("HTTP/2", "HTTP/2.0"):
                    version_norm = "H2"
                    features["protocol"] = "H2"
                elif ver_upper in ("HTTP/3", "HTTP/3.0"):
                    version_norm = "H3"
                    features["protocol"] = "H3"
                elif ver_upper == "HTTP/0.9":
                    version_norm = "H0.9"
                    features["protocol"] = "H1"
                else:
                    version_norm = "MALFORMED"
                    features["protocol"] = "H1"
                    tokens.append("ANOM:MALFORMED_VERSION")
                    features["anomalies"].append("MALFORMED_VERSION")

                features["version"] = version_norm
                tokens.append(f"PROTO:{features['protocol']}")
                tokens.append(f"M:{method_norm}")
                tokens.append(f"V:{version_norm}")

                if len(parts) > 3:
                    tokens.append("STARTLINE:EXTRA_WS")
                    features["anomalies"].append("STARTLINE_EXTRA_WS")
                if b"\t" in start_line:
                    tokens.append("STARTLINE:HTAB_SEP")
                    features["anomalies"].append("STARTLINE_HTAB")

                # Canonical target classification
                low_target = raw_target.lower()
                if _PCT_CRLF_RX.search(raw_target) or b"\r" in raw_target or b"\n" in raw_target:
                    tokens.extend(["TARGET:CRLF_INJ", "ANOM:CRLF_INJECTION", "SYNTAX:REQUEST_SPLIT", "DESYNC:CRLF_HEADER_INJ"])
                    features["anomalies"].append("CRLF_URI_INJECTION")
                    features["desync_classes"].append("CRLF_HEADER_INJ")
                elif _DOTDOT_RX.search(raw_target):
                    tokens.extend(["TARGET:DOTDOT_TRAVERSAL", "ANOM:PATH_NORM_CONFLICT"])
                    features["anomalies"].append("PATH_TRAVERSAL_NORM")
                elif low_target.startswith((b"http://", b"https://")):
                    tokens.append("TARGET:ABSOLUTE_URI")
                elif raw_target == b"*":
                    tokens.append("TARGET:ASTERISK")
            else:
                # Non-HTTP or malformed start-line
                features["protocol"] = "RAW_NON_HTTP"
                tokens.extend(["PROTO:RAW_NON_HTTP", "STARTLINE:NON_STANDARD"])
                if b"\r" in start_line or b"\n" in start_line or _PCT_CRLF_RX.search(start_line):
                    tokens.extend(["ANOM:CRLF_INJECTION", "SYNTAX:REQUEST_SPLIT", "DESYNC:CRLF_HEADER_INJ"])
                    features["anomalies"].append("CRLF_STARTLINE_INJECTION")
                # Capture deterministic structural signature of non-HTTP start-line framing
                first_tok = _slugify_token(start_line.split(b" ", 1)[0].decode("latin-1", errors="replace"), max_len=20)
                if first_tok and first_tok != "UNKNOWN":
                    tokens.append(f"STARTLINE:TOK_{first_tok}")

        # Delimiter tokens
        if delim_kind == "CRLF":
            tokens.append("DELIM:CRLF")
        elif delim_kind in ("BARE_LF", "BARE_CR", "MIXED_LF", "MIXED_CR"):
            tokens.extend([
                f"DELIM:{delim_kind}",
                "ANOM:BARE_LINE_DELIM",
                "SYNTAX:LINE_DELIM_SPLIT",
                "DESYNC:LINE_DELIM_SPLIT",
            ])
            features["anomalies"].append(f"DELIM_{delim_kind}")
            features["desync_classes"].append("LINE_DELIM_SPLIT")
        else:
            tokens.append("DELIM:NO_TERM")

        # 3. Header framing topology analysis
        cl_values: List[str] = []
        te_values: List[str] = []
        te_syntax_obf = False
        host_values: List[str] = []
        framing_order: List[str] = []
        has_obs_fold = False
        has_pre_colon_ws = False
        has_leading_ws_name = False
        has_underscore_framing = False
        has_trailer_hdr = False
        has_expect_100 = False
        has_upgrade_hdr = False
        has_conn_upgrade = False
        has_conn_keepalive = False
        has_range_hdr = False
        has_proxy_override = False
        non_noise_headers: List[str] = []

        for hline in header_lines:
            if not hline:
                continue
            if hline.startswith((b" ", b"\t")):
                has_obs_fold = True
                continue
            if b":" not in hline:
                tokens.append("ANOM:HEADER_NO_COLON")
                features["anomalies"].append("HEADER_NO_COLON")
                continue

            raw_name, raw_val = hline.split(b":", 1)
            if raw_name.endswith((b" ", b"\t")):
                has_pre_colon_ws = True
            if raw_name.startswith((b" ", b"\t")):
                has_leading_ws_name = True

            name_norm = raw_name.decode("latin-1", errors="replace").strip().lower()
            val_raw_str = raw_val.decode("latin-1", errors="replace")
            val_norm = val_raw_str.strip()
            val_low = val_norm.lower()

            if b"\\r\\n" in raw_val or _PCT_CRLF_RX.search(raw_val):
                if features["protocol"] == "H2":
                    h2_header_crlf = True
                else:
                    tokens.extend(["ANOM:CRLF_INJECTION", "SYNTAX:REQUEST_SPLIT", "DESYNC:CRLF_HEADER_INJ"])
                    features["anomalies"].append("CRLF_HEADER_VALUE")
                    features["desync_classes"].append("CRLF_HEADER_INJ")

            if name_norm in ("transfer_encoding", "content_length"):
                has_underscore_framing = True

            if name_norm == "content-length" or name_norm == "content_length":
                cl_values.append(val_norm)
                framing_order.append("CL")
            elif name_norm == "transfer-encoding" or name_norm == "transfer_encoding":
                te_values.append(val_norm)
                framing_order.append("TE")
                if raw_name.endswith((b" ", b"\t")) or raw_name.startswith((b" ", b"\t")) or name_norm == "transfer_encoding":
                    te_syntax_obf = True
                if b"\x0b" in raw_val or b"\x0c" in raw_val or b"\t" in raw_val:
                    te_syntax_obf = True
            elif name_norm == "host":
                host_values.append(val_low)
            elif name_norm == "trailer":
                has_trailer_hdr = True
            elif name_norm == "expect":
                if "100-continue" in val_low:
                    has_expect_100 = True
                elif val_low:
                    non_noise_headers.append("expect")
            elif name_norm == "upgrade":
                has_upgrade_hdr = True
            elif name_norm == "connection":
                if "upgrade" in val_low:
                    has_conn_upgrade = True
                if "keep-alive" in val_low:
                    has_conn_keepalive = True
            elif name_norm == "range":
                has_range_hdr = True
            elif name_norm in _PROXY_OVERRIDE_HEADERS:
                has_proxy_override = True
            elif name_norm and name_norm not in _NOISE_HEADERS and not _NOISE_HEADER_RX.match(name_norm):
                non_noise_headers.append(name_norm)

        # Header syntax anomaly tokens
        if has_obs_fold:
            tokens.extend(["ANOM:OBS_FOLD", "SYNTAX:HEADER_FOLD_CONT", "DESYNC:OBS_FOLD"])
            features["anomalies"].append("OBS_FOLD")
            features["desync_classes"].append("OBS_FOLD")
        if has_pre_colon_ws and not te_syntax_obf:
            tokens.extend(["ANOM:PRE_COLON_WS", "SYNTAX:HEADER_NAME_WS", "DESYNC:PRE_COLON_WS"])
            features["anomalies"].append("PRE_COLON_WS")
            features["desync_classes"].append("PRE_COLON_WS")
        elif has_pre_colon_ws and te_syntax_obf:
            tokens.append("ANOM:PRE_COLON_WS")
            features["anomalies"].append("PRE_COLON_WS")
        if has_leading_ws_name:
            tokens.append("ANOM:LEADING_WS_HEADER")
            features["anomalies"].append("LEADING_WS_HEADER")
        if has_underscore_framing:
            tokens.append("ANOM:UNDERSCORE_FRAMING")
            features["anomalies"].append("UNDERSCORE_FRAMING")

        # Host / Proxy cache-poisoning ambiguity
        if len(set(host_values)) > 1:
            tokens.extend(["HOST:DUPLICATE_CONFLICT", "ANOM:HOST_PROXY_AMBIGUITY", "DESYNC:HOST_CACHE_POISON"])
            features["anomalies"].append("DUPLICATE_HOST")
            features["desync_classes"].append("HOST_CACHE_POISON")
        elif has_proxy_override or ("TARGET:ABSOLUTE_URI" in tokens and bool(host_values)):
            tokens.extend(["ANOM:HOST_PROXY_AMBIGUITY", "DESYNC:HOST_CACHE_POISON"])
            if has_proxy_override:
                tokens.append("HDR:PROXY_OVERRIDE")
            features["anomalies"].append("HOST_PROXY_AMBIGUITY")
            features["desync_classes"].append("HOST_CACHE_POISON")

        # Content-Length semantics
        parsed_cls: List[int] = []
        cl_invalid = False
        cl_overflow = False
        for cv in cl_values:
            if not cv:
                cl_invalid = True
                continue
            if "," in cv:
                cl_invalid = True
                tokens.append("FRAMING:CL_COMMA_LIST")
                continue
            if re.fullmatch(r"[+-]?\d+", cv):
                if len(cv.lstrip("+-")) > 18:
                    cl_overflow = True
                    continue
                val_int = int(cv)
                if val_int < 0 or val_int > 2**31 - 1:
                    cl_overflow = True
                else:
                    parsed_cls.append(val_int)
            else:
                cl_invalid = True

        has_cl = len(cl_values) > 0
        has_cl_conflict = len(set(cl_values)) > 1
        if cl_overflow or cl_invalid:
            tokens.extend(["FRAMING:CL_INVALID_OVERFLOW", "ANOM:CL_INT_OVERFLOW"])
            features["framing_flags"].append("CL_INVALID_OVERFLOW")
            features["anomalies"].append("CL_INT_OVERFLOW")
        if has_cl_conflict:
            tokens.extend(["FRAMING:CL_DUPLICATE_CONFLICT", "DESYNC:CL_CL"])
            features["framing_flags"].append("CL_DUPLICATE_CONFLICT")
            features["desync_classes"].append("CL_CL")

        # Transfer-Encoding semantics
        has_te = len(te_values) > 0
        te_has_chunked = any("chunked" in tv.lower() for tv in te_values)
        te_has_obf_val = any(
            tv.strip().lower() != "chunked" for tv in te_values
        )
        te_duplicate = len(te_values) > 1
        is_te_obfuscated = has_te and (te_duplicate or te_has_obf_val or te_syntax_obf)

        # 4. Body structural analysis
        has_chunk_zero_term = bool(re.search(rb"(?:^|\r?\n)0(?:[ \t]*;[^\r\n]*)?\r?\n\r?\n", body))
        post_chunk_bytes = b""
        if has_chunk_zero_term:
            m_zero = re.search(rb"(?:^|\r?\n)0(?:[ \t]*;[^\r\n]*)?\r?\n\r?\n", body)
            if m_zero:
                post_chunk_bytes = body[m_zero.end() :]
        has_post_chunk_smuggle = len(post_chunk_bytes.strip()) > 0
        has_chunk_ext = bool(_CHUNK_EXT_LINE_RX.search(body))
        chunk_ext_overflow = False
        if has_chunk_ext:
            for m_ext in _CHUNK_EXT_LINE_RX.finditer(body):
                if len(m_ext.group(1)) >= 48:
                    chunk_ext_overflow = True
        has_chunk_trailer = bool(re.search(rb"(?:^|\r?\n)0\r?\n[A-Za-z0-9\-]+:\s*[^\r\n]+", body))
        has_chunk_nonzero = bool(_CHUNK_NONZERO_LINE_RX.match(body)) and not body.startswith((b"0\r\n", b"0\n", b"0;"))
        has_embedded_http_req = bool(_EMBEDDED_HTTP_REQ_RX.search(body) or _EMBEDDED_HTTP_REQ_PREFIX_RX.search(body))
        has_embedded_http_resp = bool(_EMBEDDED_HTTP_RESP_RX.search(body))

        if has_chunk_ext:
            tokens.extend(["BODY:CHUNK_EXT", "DESYNC:CHUNK_EXT"])
            features["body_classes"].append("CHUNK_EXT")
            features["desync_classes"].append("CHUNK_EXT")
            if chunk_ext_overflow:
                tokens.append("BODY:CHUNK_EXT_OVERFLOW")
        if has_chunk_trailer or (has_te and has_trailer_hdr):
            tokens.extend(["BODY:CHUNK_TRAILER", "DESYNC:CHUNK_TRAILER"])
            if has_trailer_hdr:
                tokens.append("HDR:TRAILER")
            features["body_classes"].append("CHUNK_TRAILER")
            features["desync_classes"].append("CHUNK_TRAILER")
        if has_chunk_zero_term:
            tokens.append("BODY:CHUNK_ZERO_TERM")
            features["body_classes"].append("CHUNK_ZERO_TERM")
        if has_post_chunk_smuggle:
            tokens.append("BODY:POST_CHUNK_SMUGGLE")
            features["body_classes"].append("POST_CHUNK_SMUGGLE")
        if has_chunk_nonzero:
            tokens.append("BODY:CHUNK_DATA")
            features["body_classes"].append("CHUNK_DATA")
        if has_embedded_http_req:
            tokens.append("BODY:EMBEDDED_HTTP_REQ")
            features["body_classes"].append("EMBEDDED_HTTP_REQ")
        if has_embedded_http_resp:
            tokens.append("BODY:EMBEDDED_HTTP_RESP")
            features["body_classes"].append("EMBEDDED_HTTP_RESP")

        # 5. Combined Framing & Desync Topology Classification
        if features["protocol"] == "H2":
            if has_cl:
                tokens.extend(["FRAMING:CL", "DESYNC:H2_CL"])
                features["framing_flags"].append("H2_CL")
                features["desync_classes"].append("H2_CL")
            if has_te:
                tokens.extend(["FRAMING:TE_CHUNKED", "DESYNC:H2_TE"])
                features["framing_flags"].append("H2_TE")
                features["desync_classes"].append("H2_TE")
            if h2_header_crlf:
                tokens.extend(["ANOM:H2_HEADER_CRLF", "DESYNC:H2_CRLF_SPLIT"])
                features["anomalies"].append("H2_HEADER_CRLF")
                features["desync_classes"].append("H2_CRLF_SPLIT")
            if h2_pseudo_crlf or ("H2:CONNECT_METHOD" in tokens and has_embedded_http_req):
                tokens.extend(["ANOM:H2_PSEUDO_INJ", "DESYNC:H2_TUNNEL"])
                features["anomalies"].append("H2_PSEUDO_INJ")
                features["desync_classes"].append("H2_TUNNEL")
        else:
            # HTTP/1.x framing classes
            if is_te_obfuscated:
                tokens.extend(["FRAMING:TE_OBFUSCATED", "DESYNC:TE_TE"])
                if te_duplicate:
                    tokens.append("FRAMING:TE_DUPLICATE")
                if te_syntax_obf:
                    tokens.append("ANOM:TE_SYNTAX_OBF")
                if has_cl:
                    tokens.append("FRAMING:CL")
                features["framing_flags"].append("TE_OBFUSCATED")
                features["desync_classes"].append("TE_TE")
            elif has_cl and has_te:
                tokens.extend(["FRAMING:CL", "FRAMING:TE_CHUNKED", "FRAMING:DUAL_CL_TE"])
                features["framing_flags"].append("DUAL_CL_TE")
                # Distinguish TE.CL vs CL.TE structurally
                first_cl = parsed_cls[0] if parsed_cls else 0
                is_te_cl = has_chunk_nonzero and (
                    (0 < first_cl < len(body)) or (framing_order[:2] == ["TE", "CL"] and not has_post_chunk_smuggle)
                )
                if is_te_cl:
                    tokens.append("DESYNC:TE_CL")
                    features["desync_classes"].append("TE_CL")
                else:
                    tokens.append("DESYNC:CL_TE")
                    features["desync_classes"].append("CL_TE")
            elif has_cl and not has_te and not has_cl_conflict and not cl_overflow and not cl_invalid:
                first_cl = parsed_cls[0] if parsed_cls else 0
                if has_expect_100 or (first_cl > 0 and len(body) < first_cl and (has_expect_100 or not has_embedded_http_req)):
                    if has_expect_100:
                        tokens.extend(["HDR:EXPECT_100", "FRAMING:CL_PAUSE_MISMATCH", "DESYNC:PAUSE_EARLY_RESP"])
                        features["framing_flags"].append("CL_PAUSE_MISMATCH")
                        features["desync_classes"].append("PAUSE_EARLY_RESP")
                    elif first_cl > len(body) and len(body) == 0 and method_norm in ("POST", "PUT"):
                        tokens.extend(["FRAMING:CL_PAUSE_MISMATCH", "DESYNC:PAUSE_EARLY_RESP"])
                        features["framing_flags"].append("CL_PAUSE_MISMATCH")
                        features["desync_classes"].append("PAUSE_EARLY_RESP")
                    elif first_cl > 0 and (method_norm in ("GET", "HEAD", "OPTIONS") or has_embedded_http_req):
                        tokens.extend(["FRAMING:CL_POSITIVE", "DESYNC:CL_0"])
                        if has_conn_keepalive:
                            tokens.append("HDR:CONN_KEEPALIVE")
                        features["framing_flags"].append("CL_0")
                        features["desync_classes"].append("CL_0")
                    else:
                        tokens.append("FRAMING:CL_SINGLE")
                elif first_cl > 0 and (method_norm in ("GET", "HEAD", "OPTIONS") or has_embedded_http_req):
                    tokens.extend(["FRAMING:CL_POSITIVE", "DESYNC:CL_0"])
                    if has_conn_keepalive:
                        tokens.append("HDR:CONN_KEEPALIVE")
                    features["framing_flags"].append("CL_0")
                    features["desync_classes"].append("CL_0")
                elif first_cl == 0 and len(body.strip()) > 0:
                    tokens.extend(["FRAMING:CL_ZERO_WITH_BODY", "DESYNC:CL_0"])
                    features["framing_flags"].append("CL_ZERO_WITH_BODY")
                    features["desync_classes"].append("CL_0")
                else:
                    tokens.append("FRAMING:CL_SINGLE")
            elif has_te and not has_cl:
                tokens.append("FRAMING:TE_CHUNKED")
                if te_has_chunked and has_post_chunk_smuggle:
                    tokens.append("DESYNC:CHUNK_TRAILING_SMUGGLE")
                    features["desync_classes"].append("CHUNK_TRAILING_SMUGGLE")

        # Upgrade smuggling
        if has_upgrade_hdr and (has_conn_upgrade or has_embedded_http_req):
            tokens.extend(["HDR:UPGRADE", "HDR:CONN_UPGRADE", "DESYNC:UPGRADE_SMUGGLE"])
            features["desync_classes"].append("UPGRADE_SMUGGLE")

        # HEAD + Range overread
        if method_norm == "HEAD" and has_range_hdr:
            tokens.extend(["HDR:RANGE", "DESYNC:HEAD_RANGE_OVERREAD"])
            features["desync_classes"].append("HEAD_RANGE_OVERREAD")
        elif has_range_hdr:
            tokens.append("HDR:RANGE")

        # Keep non-noise RFC / extension headers when no known desync pattern already defines the probe
        # (prevents arbitrary benign headers from diluting known desync matches while giving genuinely
        # novel protocol header combinations a crisp, host/nonce-invariant structural signature!)
        has_known_desync_or_anom = bool(
            features["desync_classes"]
            or features["anomalies"]
            or features["framing_flags"]
            or features["byte_classes"]
        )
        if not has_known_desync_or_anom and non_noise_headers:
            unique_ext = sorted(set(non_noise_headers))[:12]
            features["headers_canonical"] = unique_ext
            for hn in unique_ext:
                tokens.append(f"HDR:{_slugify_token(hn, max_len=24)}")

        # 6. Parser divergence vector normalization
        div_tokens, div_info = self.extract_divergence_tokens(divergence_matrix)
        tokens.extend(div_tokens)
        features["divergence"] = div_info

        # Determine whether probe exhibits any structural protocol anomaly or divergence
        features["has_structural_anomaly"] = bool(
            has_known_desync_or_anom
            or div_info.get("has_divergence")
            or features["protocol"] in ("RESP_INVERSION", "RAW_NON_HTTP")
            or bool(features["headers_canonical"]) and features["protocol"] in ("H2", "H3")
        )
        features["tokens"] = sorted(set(tokens))
        return features

    def fingerprint_wire(
        self,
        raw_probe: Union[bytes, str],
        *,
        divergence_matrix: Optional[Dict[str, Any]] = None,
        impact: Optional[str] = None,
        rfc_context: Optional[str] = None,
        extra_tags: Optional[Sequence[str]] = None,
    ) -> StructuralFingerprint:
        """Produces a deterministic canonical minimized wire fingerprint."""
        features = self.extract_wire_features(raw_probe, divergence_matrix=divergence_matrix)
        tokens = list(features.get("tokens") or [])
        if extra_tags:
            for tag in extra_tags:
                t_clean = _slugify_token(str(tag), max_len=32)
                if t_clean and t_clean != "UNKNOWN":
                    tokens.append(f"TAG:{t_clean}")

        dedup_tokens = tuple(sorted(set(tokens)))
        shingles = _build_grouped_shingles(dedup_tokens)
        canonical_form = "WIRE|" + "|".join(dedup_tokens)
        digest = hashlib.sha256(canonical_form.encode("utf-8")).hexdigest()[:16]

        meta_features = {k: v for k, v in features.items() if k != "tokens"}
        if impact:
            meta_features["impact"] = str(impact)
        if rfc_context:
            meta_features["rfc_context"] = str(rfc_context)

        return StructuralFingerprint(
            fingerprint_id=f"FP-WIRE-{digest}",
            kind="wire",
            canonical_form=canonical_form,
            tokens=dedup_tokens,
            shingles=shingles,
            features=meta_features,
        )

    def extract_ast_features(self, finding: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """Normalizes an AST / static code-taint finding into canonical source/sink/sanitizer/CWE features."""
        if isinstance(finding, dict):
            data = finding
        elif hasattr(finding, "to_dict") and callable(finding.to_dict):
            data = finding.to_dict()
        elif hasattr(finding, "__dict__"):
            data = dict(vars(finding))
        else:
            data = {"description": str(finding)}

        # Extract CWE IDs
        cwe_set: List[str] = []
        raw_cwes: List[Any] = []
        for k in ("cwe_id", "cwe", "cwe_ids"):
            v = data.get(k)
            if isinstance(v, (list, tuple, set)):
                raw_cwes.extend(v)
            elif v:
                raw_cwes.append(v)
        for item in raw_cwes:
            norm = _normalize_cwe_id(item)
            if norm and norm not in cwe_set:
                cwe_set.append(norm)

        # Infer CWE from text if absent
        combined_text = " ".join(
            str(data.get(k) or "")
            for k in ("title", "description", "rule_id", "threat_category", "category", "snippet", "evidence")
        )
        if not cwe_set:
            for m in re.finditer(r"CWE[-_:\s]*(\d{1,5})\b", combined_text, flags=re.IGNORECASE):
                norm = f"CWE-{int(m.group(1))}"
                if norm not in cwe_set:
                    cwe_set.append(norm)

        # Canonical source classification
        explicit_source = str(data.get("source") or data.get("taint_source") or data.get("entry_point") or "").strip()
        src_probe_text = f"{explicit_source} {combined_text}"
        source_class = "UNKNOWN"
        for label, rx in _AST_SOURCE_PATTERNS:
            if rx.search(explicit_source):
                source_class = label
                break
        if source_class == "UNKNOWN" and explicit_source:
            # Preserve explicit custom source category rather than collapsing genuinely novel sources
            for label, rx in _AST_SOURCE_PATTERNS:
                if rx.search(src_probe_text):
                    source_class = label
                    break
            if source_class == "UNKNOWN":
                source_class = f"CUSTOM_{_slugify_token(explicit_source, max_len=24)}"
        elif source_class == "UNKNOWN":
            for label, rx in _AST_SOURCE_PATTERNS:
                if rx.search(combined_text):
                    source_class = label
                    break

        # Canonical sink classification
        explicit_sink = str(data.get("sink") or data.get("taint_sink") or data.get("dangerous_call") or "").strip()
        sink_class = "UNKNOWN"
        for label, rx in _AST_SINK_PATTERNS:
            if rx.search(explicit_sink):
                sink_class = label
                break
        if sink_class == "UNKNOWN" and explicit_sink:
            for label, rx in _AST_SINK_PATTERNS:
                if rx.search(f"{explicit_sink} {combined_text}"):
                    sink_class = label
                    break
            if sink_class == "UNKNOWN":
                sink_class = f"CUSTOM_{_slugify_token(explicit_sink, max_len=24)}"
        elif sink_class == "UNKNOWN":
            for label, rx in _AST_SINK_PATTERNS:
                if rx.search(combined_text):
                    sink_class = label
                    break

        # Canonical sanitizer posture
        raw_san = data.get("sanitizers", data.get("sanitizer", data.get("guards")))
        san_items: List[str] = []
        if isinstance(raw_san, str):
            if raw_san.strip() and raw_san.strip().lower() not in ("none", "null", "false", "n/a"):
                san_items = [s.strip() for s in re.split(r"[,;]+", raw_san) if s.strip()]
        elif isinstance(raw_san, (list, tuple, set)):
            san_items = [
                str(s).strip()
                for s in raw_san
                if str(s).strip() and str(s).strip().lower() not in ("none", "null", "false", "n/a")
            ]

        san_classes: List[str] = []
        for s_item in san_items:
            matched_san = None
            for label, rx in _AST_SANITIZER_PATTERNS:
                if rx.search(s_item):
                    matched_san = label
                    break
            if not matched_san:
                matched_san = f"CUSTOM_{_slugify_token(s_item, max_len=20)}"
            if matched_san not in san_classes:
                san_classes.append(matched_san)
        if not san_classes:
            san_classes = ["NONE"]

        # CWE family
        cwe_families = sorted({
            _CWE_FAMILY_MAP[c] for c in cwe_set if c in _CWE_FAMILY_MAP
        })
        if not cwe_families and sink_class in (
            "SQL_EXEC", "OS_CMD_EXEC", "CODE_EVAL", "HTML_DOM_XSS", "FS_PATH_IO",
            "NET_SSRF", "DESERIALIZE", "XML_PARSE", "TEMPLATE_RENDER", "AUTHZ_BYPASS",
            "PROTO_POLLUTE", "HTTP_HEADER_OUT", "CRYPTO_WEAK",
        ):
            sink_to_family = {
                "SQL_EXEC": "INJECTION_SQL",
                "OS_CMD_EXEC": "INJECTION_CMD",
                "CODE_EVAL": "INJECTION_CODE",
                "HTML_DOM_XSS": "INJECTION_XSS",
                "FS_PATH_IO": "PATH_TRAVERSAL",
                "NET_SSRF": "SSRF",
                "DESERIALIZE": "DESERIALIZATION",
                "XML_PARSE": "XXE",
                "TEMPLATE_RENDER": "INJECTION_TEMPLATE",
                "AUTHZ_BYPASS": "AUTH_BYPASS",
                "PROTO_POLLUTE": "PROTOTYPE_POLLUTION",
                "HTTP_HEADER_OUT": "HTTP_HEADER_INJECTION",
                "CRYPTO_WEAK": "WEAK_CRYPTO",
            }
            cwe_families = [sink_to_family[sink_class]]

        # Build canonical tokens
        tokens: List[str] = [
            "AST:TAINT_FLOW",
            f"SRC:{source_class}",
            f"SINK:{sink_class}",
            f"FLOW:{source_class}->{sink_class}",
        ]
        for san in sorted(san_classes):
            tokens.append(f"SAN:{san}")
        tokens.append(f"FLOW_GUARD:{source_class}->{'+'.join(sorted(san_classes))}->{sink_class}")
        for cwe in sorted(cwe_set):
            tokens.append(f"CWE:{cwe}")
        for fam in cwe_families:
            tokens.append(f"CWE_FAMILY:{fam}")

        # Optional normalized AST operator node types (only structural ops, never identifiers/lines)
        raw_ast_nodes = data.get("ast_path") or data.get("node_types") or []
        if isinstance(raw_ast_nodes, (list, tuple)):
            norm_ops = [
                _slugify_token(str(n), max_len=20)
                for n in raw_ast_nodes[:8]
                if str(n).strip()
            ]
            if norm_ops:
                tokens.append("AST_CHAIN:" + ">".join(norm_ops[:4]))

        return {
            "source": source_class,
            "sink": sink_class,
            "sanitizers": sorted(san_classes),
            "cwe_ids": sorted(cwe_set),
            "cwe_families": cwe_families,
            "has_unmitigated_taint": (
                source_class != "UNKNOWN"
                and sink_class != "UNKNOWN"
                and san_classes == ["NONE"]
            ),
            "tokens": sorted(set(tokens)),
        }

    def fingerprint_ast(self, finding: Union[Dict[str, Any], Any]) -> StructuralFingerprint:
        """Produces a deterministic canonical AST / code-taint structural fingerprint."""
        features = self.extract_ast_features(finding)
        dedup_tokens = tuple(features["tokens"])
        shingles = _build_grouped_shingles(dedup_tokens)
        canonical_form = "AST|" + "|".join(dedup_tokens)
        digest = hashlib.sha256(canonical_form.encode("utf-8")).hexdigest()[:16]
        meta_features = {k: v for k, v in features.items() if k != "tokens"}
        return StructuralFingerprint(
            fingerprint_id=f"FP-AST-{digest}",
            kind="ast",
            canonical_form=canonical_form,
            tokens=dedup_tokens,
            shingles=shingles,
            features=meta_features,
        )

    def fingerprint_hybrid(
        self,
        *,
        raw_probe: Optional[Union[bytes, str]] = None,
        ast_finding: Optional[Union[Dict[str, Any], Any]] = None,
        divergence_matrix: Optional[Dict[str, Any]] = None,
        impact: Optional[str] = None,
        rfc_context: Optional[str] = None,
    ) -> StructuralFingerprint:
        """Fingerprints wire, AST, or combined wire+AST evidence cleanly."""
        if raw_probe is not None and ast_finding is None:
            return self.fingerprint_wire(
                raw_probe,
                divergence_matrix=divergence_matrix,
                impact=impact,
                rfc_context=rfc_context,
            )
        if ast_finding is not None and raw_probe is None:
            return self.fingerprint_ast(ast_finding)

        wire_fp = self.fingerprint_wire(
            raw_probe or b"",
            divergence_matrix=divergence_matrix,
            impact=impact,
            rfc_context=rfc_context,
        )
        ast_fp = self.fingerprint_ast(ast_finding or {})
        merged_tokens = tuple(sorted(set(wire_fp.tokens) | set(ast_fp.tokens)))
        merged_shingles = tuple(sorted(set(wire_fp.shingles) | set(ast_fp.shingles)))
        canonical_form = f"HYBRID|{wire_fp.canonical_form}||{ast_fp.canonical_form}"
        digest = hashlib.sha256(canonical_form.encode("utf-8")).hexdigest()[:16]
        return StructuralFingerprint(
            fingerprint_id=f"FP-HYBRID-{digest}",
            kind="hybrid",
            canonical_form=canonical_form,
            tokens=merged_tokens,
            shingles=merged_shingles,
            features={"wire": wire_fp.features, "ast": ast_fp.features},
        )

    @staticmethod
    def jaccard_similarity(fp_a: StructuralFingerprint, fp_b: StructuralFingerprint) -> float:
        """Pure-stdlib deterministic Jaccard similarity over structural tokens + shingles."""
        set_a = set(fp_a.all_terms())
        set_b = set(fp_b.all_terms())
        if not set_a or not set_b:
            return 0.0
        inter = len(set_a & set_b)
        union = len(set_a | set_b)
        return float(inter / union) if union > 0 else 0.0

    @staticmethod
    def has_structural_protocol_anomaly(fp: StructuralFingerprint) -> bool:
        """Returns True if fingerprint captures an actual protocol anomaly, inversion, divergence, or unmitigated AST taint."""
        if fp.kind == "wire":
            return bool(fp.features.get("has_structural_anomaly"))
        if fp.kind == "ast":
            return bool(fp.features.get("has_unmitigated_taint"))
        if fp.kind == "hybrid":
            w_anom = bool((fp.features.get("wire") or {}).get("has_structural_anomaly"))
            a_anom = bool((fp.features.get("ast") or {}).get("has_unmitigated_taint"))
            return w_anom or a_anom
        return False


# ---------------------------------------------------------------------------
# Pure-Stdlib Nuclei / YAML & JSON Catalog Parsers
# ---------------------------------------------------------------------------

def _parse_nuclei_yaml_text(yaml_text: str, source_label: str) -> Optional[Dict[str, Any]]:
    """
    Parses a ProjectDiscovery Nuclei YAML template (or RFCHunt ExploitExporter YAML)
    into a normalized dict without requiring PyYAML (uses PyYAML if present, with a
    resilient pure-stdlib fallback parser).
    Returns None if the YAML file is not a security/Nuclei template.
    """
    text = str(yaml_text or "")
    if not text.strip():
        return None

    # Quick structural check: must look like a Nuclei template (id + info + http/requests/network/tcp)
    has_id = bool(re.search(r"(?m)^\s*id\s*:\s*\S+", text))
    has_info = bool(re.search(r"(?m)^\s*info\s*:", text))
    has_proto_block = bool(re.search(r"(?m)^\s*(?:http|requests|network|tcp|ssl|websocket)\s*:", text))
    if not (has_id and has_info and has_proto_block):
        return None

    parsed: Optional[Dict[str, Any]] = None
    try:
        import yaml  # type: ignore

        loaded = yaml.safe_load(text)
        if isinstance(loaded, dict) and loaded.get("id") and isinstance(loaded.get("info"), dict):
            parsed = loaded
    except Exception:
        parsed = None

    raw_probes: List[bytes] = []
    template_id = ""
    name = ""
    description = ""
    tags: List[str] = []
    cwe_ids: List[str] = []
    cve_ids: List[str] = []
    references: List[str] = []

    if parsed is not None:
        template_id = str(parsed.get("id") or "").strip()
        info = parsed.get("info") or {}
        name = str(info.get("name") or template_id).strip()
        description = str(info.get("description") or "").strip()
        raw_tags = info.get("tags")
        if isinstance(raw_tags, str):
            tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
        elif isinstance(raw_tags, list):
            tags = [str(t).strip() for t in raw_tags if str(t).strip()]
        raw_refs = info.get("reference") or info.get("references") or []
        if isinstance(raw_refs, str):
            references = [raw_refs.strip()]
        elif isinstance(raw_refs, list):
            references = [str(r).strip() for r in raw_refs if str(r).strip()]
        cls = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        for cwe_val in _iter_str_values(cls.get("cwe-id") or cls.get("cwe_id")):
            norm = _normalize_cwe_id(cwe_val)
            if norm and norm not in cwe_ids:
                cwe_ids.append(norm)
        for cve_val in _iter_str_values(cls.get("cve-id") or cls.get("cve_id")):
            cve_u = cve_val.upper()
            if cve_u.startswith("CVE-") and cve_u not in cve_ids:
                cve_ids.append(cve_u)

        for proto_key in ("http", "requests", "network", "tcp"):
            blocks = parsed.get(proto_key)
            if not isinstance(blocks, list):
                continue
            for blk in blocks:
                if not isinstance(blk, dict):
                    continue
                raw_items = blk.get("raw") or blk.get("inputs")
                if isinstance(raw_items, list):
                    for item in raw_items:
                        raw_str = item.get("data") if isinstance(item, dict) else item
                        if isinstance(raw_str, str) and raw_str.strip():
                            raw_probes.append(_normalize_nuclei_raw_probe(raw_str, tags))
                elif isinstance(raw_items, str) and raw_items.strip():
                    raw_probes.append(_normalize_nuclei_raw_probe(raw_items, tags))
                elif blk.get("method") or blk.get("path"):
                    method = str(blk.get("method") or "GET").strip().upper()
                    paths = blk.get("path") or ["/"]
                    path_val = str(paths[0] if isinstance(paths, list) and paths else paths)
                    path_val = path_val.replace("{{BaseURL}}", "").replace("{{RootURL}}", "") or "/"
                    if not path_val.startswith("/") and not path_val.lower().startswith(("http://", "https://")):
                        path_val = "/" + path_val
                    hdrs = blk.get("headers") if isinstance(blk.get("headers"), dict) else {}
                    lines = [f"{method} {path_val} HTTP/1.1", "Host: template.local"]
                    for hk, hv in hdrs.items():
                        lines.append(f"{hk}: {hv}")
                    body = str(blk.get("body") or "")
                    wire = "\r\n".join(lines) + "\r\n\r\n" + body
                    raw_probes.append(wire.encode("latin-1", errors="replace"))

    # Fallback pure-stdlib extractor (also handles ExploitExporter indentation without `- |`)
    if not template_id:
        m_id = re.search(r"(?m)^\s*id\s*:\s*['\"]?([^'\"\r\n#]+)", text)
        template_id = m_id.group(1).strip() if m_id else Path(source_label).stem
    if not name:
        m_name = re.search(r"(?m)^\s+name\s*:\s*['\"]?([^'\"\r\n]+)", text)
        name = m_name.group(1).strip() if m_name else template_id
    if not description:
        m_desc = re.search(r"(?m)^\s+description\s*:\s*['\"]?([^'\"\r\n]+)", text)
        description = m_desc.group(1).strip() if m_desc else ""
    if not tags:
        m_tags = re.search(r"(?m)^\s+tags\s*:\s*['\"]?([^'\"\r\n]+)", text)
        if m_tags:
            tags = [t.strip() for t in m_tags.group(1).split(",") if t.strip()]
    if not cwe_ids:
        for m_cwe in re.finditer(r"CWE-(\d{1,5})", text, flags=re.IGNORECASE):
            norm = f"CWE-{int(m_cwe.group(1))}"
            if norm not in cwe_ids:
                cwe_ids.append(norm)
    if not cve_ids:
        for m_cve in re.finditer(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE):
            cve_u = m_cve.group(0).upper()
            if cve_u not in cve_ids:
                cve_ids.append(cve_u)

    if not raw_probes:
        raw_probes.extend(_extract_raw_blocks_stdlib(text, tags))

    if not raw_probes:
        return None

    return {
        "id": template_id,
        "title": name,
        "description": description,
        "tags": tags,
        "cwe_ids": cwe_ids,
        "cve_ids": cve_ids,
        "references": references,
        "raw_probes": raw_probes,
    }


def _iter_str_values(val: Any) -> Iterable[str]:
    if isinstance(val, str):
        for part in re.split(r"[,\s]+", val):
            if part.strip():
                yield part.strip()
    elif isinstance(val, (list, tuple, set)):
        for item in val:
            if str(item).strip():
                yield str(item).strip()


def _normalize_nuclei_raw_probe(raw_text: str, tags: Sequence[str]) -> bytes:
    """Converts a Nuclei YAML raw HTTP request string into wire bytes."""
    cleaned = raw_text.replace("{{Hostname}}", "template.local").replace("{{BaseURL}}", "http://template.local")
    cleaned = cleaned.replace("{{RootURL}}", "http://template.local")
    # Unescape literal \x00 or \x0b tokens if author wrote them escaped inside single-line YAML
    tag_low = {t.lower() for t in tags}
    bare_lf_mode = any(k in tag_low for k in ("bare-lf", "lf-only", "bare_lf"))
    if "\r\n" not in cleaned and not bare_lf_mode:
        cleaned = cleaned.replace("\n", "\r\n")
    if "\r\n\r\n" not in cleaned and "\n\n" not in cleaned:
        cleaned = cleaned.rstrip("\r\n") + ("\n\n" if bare_lf_mode else "\r\n\r\n")
    return cleaned.encode("latin-1", errors="replace")


def _extract_raw_blocks_stdlib(yaml_text: str, tags: Sequence[str]) -> List[bytes]:
    """Pure-stdlib extractor for `raw:` blocks inside Nuclei YAML templates."""
    lines = yaml_text.splitlines()
    blocks: List[bytes] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m_raw = re.match(r"^(\s*(?:-\s+)?)raw\s*:\s*$", line)
        if not m_raw:
            i += 1
            continue
        raw_indent = len(line) - len(line.lstrip(" "))
        i += 1
        while i < len(lines):
            cur = lines[i]
            if not cur.strip():
                i += 1
                continue
            cur_indent = len(cur) - len(cur.lstrip(" "))
            if cur_indent <= raw_indent and not cur.lstrip(" ").startswith("-"):
                break
            stripped = cur.lstrip(" ")
            # Standard `- |` or `- |-` block scalar
            if re.match(r"^-\s*[|>][-+]?\s*$", stripped):
                dash_indent = cur_indent
                i += 1
                buf: List[str] = []
                block_indent: Optional[int] = None
                while i < len(lines):
                    bl = lines[i]
                    if not bl.strip():
                        buf.append("")
                        i += 1
                        continue
                    bl_indent = len(bl) - len(bl.lstrip(" "))
                    if bl_indent <= dash_indent:
                        break
                    if block_indent is None:
                        block_indent = bl_indent
                    buf.append(bl[min(block_indent, bl_indent) :])
                    i += 1
                if buf:
                    blocks.append(_normalize_nuclei_raw_probe("\n".join(buf), tags))
                continue
            # ExploitExporter indented HTTP lines directly under `raw:`
            if cur_indent > raw_indent and not stripped.startswith(("unsafe:", "matchers", "redirects", "threads", "req-condition")):
                block_indent = cur_indent
                buf = []
                while i < len(lines):
                    bl = lines[i]
                    if not bl.strip():
                        buf.append("")
                        i += 1
                        continue
                    bl_indent = len(bl) - len(bl.lstrip(" "))
                    bl_strip = bl.lstrip(" ")
                    if bl_indent < block_indent or (
                        bl_indent == raw_indent + 2
                        and bl_strip.startswith(("unsafe:", "matchers", "redirects", "req-condition"))
                    ):
                        break
                    buf.append(bl[min(block_indent, bl_indent) :])
                    i += 1
                if buf:
                    blocks.append(_normalize_nuclei_raw_probe("\n".join(buf), tags))
                continue
            break
    return blocks


# ---------------------------------------------------------------------------
# Built-In Offline Knowledge Catalog (PortSwigger Desync + CWE/CVE Taxonomy)
# ---------------------------------------------------------------------------

def _builtin_portswigger_wire_specs() -> List[Dict[str, Any]]:
    """
    Structured offline catalog of well-known PortSwigger HTTP desync, HTTP/2
    downgrade, chunking, header framing, and cache poisoning techniques.
    NOTE: Genuinely novel research classes (e.g., Shared-Parser Confusion
    response-to-request inversion and Null-Byte Frame Truncation) are
    intentionally excluded so they remain classified as novel unless
    previously persisted in `terminator.db`.
    """
    return [
        {
            "entry_id": "PSW-CL-TE",
            "title": "CL.TE HTTP/1.1 Request Smuggling",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:6.3", "RFC7230:3.3.3"),
            "references": ("https://portswigger.net/web-security/request-smuggling",),
            "description": "Front-end uses Content-Length while back-end uses Transfer-Encoding: chunked, smuggling trailing request after 0-length terminator.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 44\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"0\r\n\r\n"
                b"GET /404 HTTP/1.1\r\nHost: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-CL-TE-MINIMAL",
            "title": "CL.TE Dual Content-Length and Transfer-Encoding Framing Conflict",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:6.3",),
            "references": ("https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",),
            "description": "Minimal CL.TE framing conflict containing both Content-Length and Transfer-Encoding: chunked with short terminator.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 6\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"0\r\n\r\nG"
            ),
        },
        {
            "entry_id": "PSW-CL-TE-EMPTY",
            "title": "CL.TE Dual Header Conflict (Empty/Basic Chunked)",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:6.3",),
            "references": ("https://portswigger.net/web-security/request-smuggling",),
            "description": "Basic dual Content-Length and Transfer-Encoding: chunked probe without trailing payload.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 5\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"0\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-TE-CL",
            "title": "TE.CL HTTP/1.1 Request Smuggling",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:6.3",),
            "references": ("https://portswigger.net/web-security/request-smuggling",),
            "description": "Front-end processes Transfer-Encoding: chunked while back-end truncates on small Content-Length, interpreting chunk data as a new request.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 4\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"2e\r\n"
                b"GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
                b"\r\n0\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-TE-TE-DUPLICATE",
            "title": "TE.TE Obfuscated Duplicate Transfer-Encoding Smuggling",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:6.3",),
            "references": ("https://portswigger.net/web-security/request-smuggling/finding",),
            "description": "Duplicate Transfer-Encoding headers with invalid/obfuscated coding token causing front-end/back-end disagreement.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 4\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Transfer-Encoding: cow\r\n\r\n"
                b"0\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-TE-TE-OBFUSCATION",
            "title": "TE.TE Syntax/Whitespace Obfuscated Transfer-Encoding Smuggling",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:5.1", "RFC9112:6.3"),
            "references": ("https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",),
            "description": "Obfuscated Transfer-Encoding header using vertical-tab/tab/pre-colon space or non-standard token.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 6\r\n"
                b"Transfer-Encoding:\x0bchunked\r\n\r\n"
                b"0\r\n\r\nG"
            ),
        },
        {
            "entry_id": "PSW-TE-TE-XCHUNKED",
            "title": "TE.TE Non-Standard Coding Token Obfuscation",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:6.1",),
            "references": ("https://portswigger.net/web-security/request-smuggling",),
            "description": "Single obfuscated Transfer-Encoding token (e.g., xchunked or comma-padded coding) triggering parser disagreement.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 4\r\n"
                b"Transfer-Encoding: xchunked\r\n\r\n"
                b"0\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-CL-CL",
            "title": "CL.CL Conflicting Duplicate Content-Length Smuggling",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:6.3",),
            "references": ("https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",),
            "description": "Two conflicting Content-Length headers interpreted differently by proxy and origin.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 5\r\n"
                b"Content-Length: 44\r\n\r\n"
                b"12345GET /404 HTTP/1.1\r\nHost: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-CL-0",
            "title": "CL.0 Request Smuggling",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:6.3",),
            "references": ("https://portswigger.net/web-security/request-smuggling/browser/cl-0",),
            "description": "Back-end ignores Content-Length on an endpoint while front-end forwards the body, leaving a smuggled request prefix on the connection.",
            "probe": (
                b"POST /static HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Connection: keep-alive\r\n"
                b"Content-Length: 40\r\n\r\n"
                b"GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-CL-0-GET",
            "title": "CL.0 GET Body / Browser-Powered Client-Side Desync",
            "source": "portswigger_catalog",
            "category": "CLIENT_SIDE_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9110:9.3.1", "RFC9112:6.3"),
            "references": ("https://portswigger.net/research/browser-powered-desync-attacks",),
            "description": "Client-side / browser-powered desync using GET with non-zero Content-Length and keep-alive smuggled prefix.",
            "probe": (
                b"GET / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Connection: keep-alive\r\n"
                b"Content-Length: 39\r\n\r\n"
                b"GET /404 HTTP/1.1\r\nHost: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-CL-0-HEAD",
            "title": "HEAD with Non-Zero Content-Length Queue Poisoning",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9110:9.3.2",),
            "references": ("https://portswigger.net/research/browser-powered-desync-attacks",),
            "description": "HEAD request carrying non-zero Content-Length and trailing smuggled request bytes.",
            "probe": (
                b"HEAD / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 39\r\n\r\n"
                b"GET /404 HTTP/1.1\r\nHost: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-PAUSE-BASED-DESYNC",
            "title": "Pause-Based / 0.CL Server-Side Desync",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9110:10.1.1", "RFC9112:6.3"),
            "references": ("https://portswigger.net/research/browser-powered-desync-attacks#pause-based-desync",),
            "description": "Early-response / pause-based desync using Expect: 100-continue or incomplete Content-Length body before connection reuse.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Expect: 100-continue\r\n"
                b"Content-Length: 60\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-H2-CL",
            "title": "H2.CL HTTP/2 Downgrade Request Smuggling",
            "source": "portswigger_catalog",
            "category": "H2_DOWNGRADE",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9113:8.6",),
            "references": ("https://portswigger.net/research/http2",),
            "description": "HTTP/2 request downgraded to HTTP/1.1 with attacker-supplied Content-Length overriding HTTP/2 frame length.",
            "probe": (
                b":method: POST\r\n"
                b":path: /\r\n"
                b":scheme: https\r\n"
                b":authority: target.example\r\n"
                b"content-length: 0\r\n\r\n"
                b"GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-H2-TE",
            "title": "H2.TE HTTP/2 Downgrade Request Smuggling",
            "source": "portswigger_catalog",
            "category": "H2_DOWNGRADE",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9113:8.2.2",),
            "references": ("https://portswigger.net/research/http2",),
            "description": "HTTP/2 request carrying forbidden Transfer-Encoding: chunked header passed through downgrade to HTTP/1.1 back-end.",
            "probe": (
                b":method: POST\r\n"
                b":path: /\r\n"
                b":scheme: https\r\n"
                b":authority: target.example\r\n"
                b"transfer-encoding: chunked\r\n\r\n"
                b"0\r\n\r\n"
                b"GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-H2-0-TUNNEL",
            "title": "H2.0 / HTTP/2 Request Tunneling via Pseudo-Header Injection",
            "source": "portswigger_catalog",
            "category": "H2_DOWNGRADE",
            "cwe_ids": ("CWE-444", "CWE-113"),
            "rfc_refs": ("RFC9113:8.2.1", "RFC9113:8.3.1"),
            "references": ("https://portswigger.net/research/http2#request-tunnelling",),
            "description": "HTTP/2 request tunneling injecting CRLF/space into :path or :authority pseudo-headers during HTTP/1.1 downgrade.",
            "probe": (
                b":method: GET\r\n"
                b":path: / HTTP/1.1\\r\\nHost: target.example\\r\\n\\r\\nGET /internal HTTP/1.1\r\n"
                b":scheme: https\r\n"
                b":authority: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-H2-CONNECT-TUNNEL",
            "title": "H2.0 / HTTP/2 CONNECT Request Tunneling",
            "source": "portswigger_catalog",
            "category": "H2_DOWNGRADE",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9113:8.5",),
            "references": ("https://portswigger.net/research/http2#request-tunnelling",),
            "description": "HTTP/2 CONNECT pseudo-header tunnel smuggling an inner HTTP/1.1 request.",
            "probe": (
                b":method: CONNECT\r\n"
                b":authority: target.example:443\r\n\r\n"
                b"GET /internal HTTP/1.1\r\nHost: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-H2-HEADER-CRLF",
            "title": "HTTP/2 Header CRLF Splitting on Downgrade",
            "source": "portswigger_catalog",
            "category": "H2_DOWNGRADE",
            "cwe_ids": ("CWE-113", "CWE-444"),
            "rfc_refs": ("RFC9113:8.2.1",),
            "references": ("https://portswigger.net/research/http2",),
            "description": "CRLF sequence injected inside an HTTP/2 header value and emitted verbatim on HTTP/1.1 backend.",
            "probe": (
                b":method: GET\r\n"
                b":path: /\r\n"
                b":scheme: https\r\n"
                b":authority: target.example\r\n"
                b"x-injected: foo\\r\\nTransfer-Encoding: chunked\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-CHUNK-EXT-SMUGGLING",
            "title": "Chunk-Extension Parsing Discrepancy & Smuggling",
            "source": "portswigger_catalog",
            "category": "CHUNKING_SMUGGLING",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:7.1.1",),
            "references": ("https://portswigger.net/research/http1-must-die",),
            "description": "Chunked transfer-coding extension (;ext=val) parsed inconsistently across proxies and origin servers.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"4;ext=val\r\ntest\r\n0;fin=1\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-CHUNK-TRAILER-SMUGGLING",
            "title": "Chunked Trailer Header Injection & Smuggling",
            "source": "portswigger_catalog",
            "category": "CHUNKING_SMUGGLING",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:7.1.2",),
            "references": ("https://portswigger.net/research/http1-must-die",),
            "description": "Chunked trailer headers appended after terminating 0-chunk to smuggle restricted headers past front-end filters.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Trailer: X-Forwarded-For\r\n\r\n"
                b"0\r\n"
                b"X-Forwarded-For: 127.0.0.1\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-OBS-FOLD",
            "title": "Obsolete Header Line Folding (obs-fold) Desync",
            "source": "portswigger_catalog",
            "category": "HEADER_FRAMING",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC7230:3.2.4", "RFC9112:5.2"),
            "references": ("https://datatracker.ietf.org/doc/html/rfc9112#section-5.2",),
            "description": "Obsolete header line continuation (CRLF followed by SP/HTAB) accepted by legacy parsers and rejected by strict RFC 9112 parsers.",
            "probe": (
                b"GET / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"X-Folded: part1\r\n part2\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-PRE-COLON-WS",
            "title": "Pre-Colon Header Field-Name Whitespace Ambiguity",
            "source": "portswigger_catalog",
            "category": "HEADER_FRAMING",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9112:5.1",),
            "references": ("https://datatracker.ietf.org/doc/html/rfc9112#section-5.1",),
            "description": "Whitespace between header field-name and colon causing asymmetric header interpretation across proxies.",
            "probe": (
                b"GET / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"X-Test : value\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-BARE-LF-DESYNC",
            "title": "Bare LF / Non-CRLF Line Delimiter Desync",
            "source": "portswigger_catalog",
            "category": "LINE_DELIMITER",
            "cwe_ids": ("CWE-444", "CWE-113"),
            "rfc_refs": ("RFC9112:2.2",),
            "references": ("https://portswigger.net/research/http1-must-die",),
            "description": "Bare LF line terminators without preceding CR causing line-boundary desynchronization between strict and permissive parsers.",
            "probe": b"GET / HTTP/1.1\nHost: target.example\n\n",
        },
        {
            "entry_id": "PSW-MIXED-LF-DESYNC",
            "title": "Mixed CRLF / Bare LF Header Delimiter Smuggling",
            "source": "portswigger_catalog",
            "category": "LINE_DELIMITER",
            "cwe_ids": ("CWE-444", "CWE-113"),
            "rfc_refs": ("RFC9112:2.2",),
            "references": ("https://portswigger.net/research/http1-must-die",),
            "description": "Mixed CRLF and bare LF inside header block allowing hidden header injection on LF-splitting backends.",
            "probe": b"GET / HTTP/1.1\r\nHost: target.example\r\nX-Split: a\nX-Smuggled: b\r\n\r\n",
        },
        {
            "entry_id": "PSW-CRLF-HEADER-INJECTION",
            "title": "CRLF Request Header Injection / Request Splitting",
            "source": "portswigger_catalog",
            "category": "HEADER_INJECTION",
            "cwe_ids": ("CWE-113",),
            "cve_ids": ("CVE-2023-25690",),
            "rfc_refs": ("RFC9112:2.2",),
            "references": ("https://portswigger.net/kb/issues/00200200_http-response-header-injection",),
            "description": "Encoded or raw CRLF sequence (%0d%0a) injected in request-target or header to split requests or inject arbitrary headers.",
            "probe": b"GET /path%0d%0aX-Injected:%20true HTTP/1.1\r\nHost: target.example\r\n\r\n",
        },
        {
            "entry_id": "PSW-HOST-CACHE-POISONING",
            "title": "Web Cache Poisoning via Unkeyed Host / Proxy Override Headers",
            "source": "portswigger_catalog",
            "category": "CACHE_POISONING",
            "cwe_ids": ("CWE-436", "CWE-345"),
            "rfc_refs": ("RFC9110:7.2",),
            "references": ("https://portswigger.net/research/practical-web-cache-poisoning",),
            "description": "Unkeyed X-Forwarded-Host / X-Original-URL or conflicting Host/absolute-URI headers poisoning shared caches.",
            "probe": (
                b"GET / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"X-Forwarded-Host: attacker.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-WS-UPGRADE-SMUGGLING",
            "title": "WebSocket / h2c Upgrade Request Smuggling",
            "source": "portswigger_catalog",
            "category": "UPGRADE_SMUGGLING",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9110:7.8", "RFC6455"),
            "references": ("https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",),
            "description": "Connection: Upgrade + Upgrade: websocket/h2c abusing reverse-proxy tunnel promotion to smuggle HTTP requests.",
            "probe": (
                b"GET / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Connection: Upgrade\r\n"
                b"Upgrade: websocket\r\n\r\n"
                b"GET /internal HTTP/1.1\r\nHost: target.example\r\n\r\n"
            ),
        },
        {
            "entry_id": "PSW-HEAD-RANGE-OVERREAD",
            "title": "HEAD + Range Response Framing Overread",
            "source": "portswigger_catalog",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-444",),
            "rfc_refs": ("RFC9110:9.3.2", "RFC9110:14.2"),
            "references": ("https://datatracker.ietf.org/doc/html/rfc9110#section-9.3.2",),
            "description": "HEAD request with Range header triggering unexpected body framing or response overread.",
            "probe": (
                b"HEAD / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Range: bytes=0-0, 1-1\r\n\r\n"
            ),
        },
    ]


def _builtin_cwe_cve_specs() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Built-in offline CWE/CVE protocol-flaw (wire) and code-taint (AST) catalog entries."""
    wire_specs = [
        {
            "entry_id": "CVE-2021-41773-PATH-NORM",
            "title": "Proxy/Origin Path Normalization & Dot-Dot Traversal Conflict (CWE-22 / CWE-436)",
            "source": "cwe_cve_taxonomy",
            "category": "PATH_NORMALIZATION",
            "cwe_ids": ("CWE-22", "CWE-436"),
            "cve_ids": ("CVE-2021-41773", "CVE-2021-42013"),
            "rfc_refs": ("RFC3986:5.2.4",),
            "references": ("https://nvd.nist.gov/vuln/detail/CVE-2021-41773",),
            "description": "Encoded dot-dot path traversal (%2e%2e/) decoded differently between proxy ACL and origin server.",
            "probe": b"GET /icons/.%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: target.example\r\n\r\n",
        },
        {
            "entry_id": "CVE-2020-12440-CL-OVERFLOW",
            "title": "Integer Overflow / Negative Content-Length Framing Bug (CWE-190 / CWE-444)",
            "source": "cwe_cve_taxonomy",
            "category": "HTTP_DESYNC",
            "cwe_ids": ("CWE-190", "CWE-444"),
            "cve_ids": ("CVE-2020-12440",),
            "rfc_refs": ("RFC9110:8.6",),
            "references": ("https://cwe.mitre.org/data/definitions/444.html",),
            "description": "Negative or 64-bit overflowing Content-Length value causing asymmetric body length parsing.",
            "probe": (
                b"POST / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Content-Length: 99999999999999999999999999\r\n\r\n"
                b"body"
            ),
        },
        {
            "entry_id": "CWE-436-DUPLICATE-HOST",
            "title": "Duplicate Conflicting Host Header Routing Conflict (CWE-436)",
            "source": "cwe_cve_taxonomy",
            "category": "ROUTING_CONFLICT",
            "cwe_ids": ("CWE-436",),
            "rfc_refs": ("RFC9112:3.2",),
            "references": ("https://cwe.mitre.org/data/definitions/436.html",),
            "description": "Multiple distinct Host headers causing reverse proxy and origin vhost routing divergence.",
            "probe": (
                b"GET / HTTP/1.1\r\n"
                b"Host: target.example\r\n"
                b"Host: internal.local\r\n\r\n"
            ),
        },
    ]

    ast_specs = [
        {
            "entry_id": "CWE-89-SQL-INJECTION",
            "title": "Unsanitized External Input to SQL Execution Sink (CWE-89)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_INJECTION",
            "cwe_ids": ("CWE-89",),
            "references": ("https://cwe.mitre.org/data/definitions/89.html",),
            "description": "Untrusted HTTP parameter concatenated/interpolated directly into SQL execution without parameterization.",
            "ast_signature": {"cwe_id": "CWE-89", "source": "http_param", "sink": "sql_exec", "sanitizers": []},
        },
        {
            "entry_id": "CWE-78-OS-CMD-INJECTION",
            "title": "Unsanitized External Input to OS Command Execution Sink (CWE-78)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_INJECTION",
            "cwe_ids": ("CWE-78",),
            "references": ("https://cwe.mitre.org/data/definitions/78.html",),
            "description": "Untrusted HTTP parameter passed directly into OS shell or subprocess command execution.",
            "ast_signature": {"cwe_id": "CWE-78", "source": "http_param", "sink": "os_cmd_exec", "sanitizers": []},
        },
        {
            "entry_id": "CWE-79-XSS",
            "title": "Unsanitized External Input to HTML/DOM Sink (CWE-79)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_INJECTION",
            "cwe_ids": ("CWE-79",),
            "references": ("https://cwe.mitre.org/data/definitions/79.html",),
            "description": "Untrusted HTTP input rendered into HTML or DOM sink without output encoding.",
            "ast_signature": {"cwe_id": "CWE-79", "source": "http_param", "sink": "html_dom_xss", "sanitizers": []},
        },
        {
            "entry_id": "CWE-94-CODE-INJECTION",
            "title": "Unsanitized External Input to Dynamic Code Eval Sink (CWE-94)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_INJECTION",
            "cwe_ids": ("CWE-94",),
            "references": ("https://cwe.mitre.org/data/definitions/94.html",),
            "description": "Untrusted external input evaluated directly by eval/exec/dynamic Function constructor.",
            "ast_signature": {"cwe_id": "CWE-94", "source": "http_param", "sink": "code_eval", "sanitizers": []},
        },
        {
            "entry_id": "CWE-22-PATH-TRAVERSAL",
            "title": "Unsanitized External Path to Filesystem I/O Sink (CWE-22)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_PATH",
            "cwe_ids": ("CWE-22",),
            "references": ("https://cwe.mitre.org/data/definitions/22.html",),
            "description": "Untrusted user path used in filesystem open/read/write without canonical root containment.",
            "ast_signature": {"cwe_id": "CWE-22", "source": "http_param", "sink": "fs_path_io", "sanitizers": []},
        },
        {
            "entry_id": "CWE-918-SSRF",
            "title": "Unsanitized External URL to Outbound HTTP/Socket Fetch Sink (CWE-918)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_SSRF",
            "cwe_ids": ("CWE-918",),
            "references": ("https://cwe.mitre.org/data/definitions/918.html",),
            "description": "Untrusted URL passed into outbound HTTP client without IP/CIDR allowlist verification.",
            "ast_signature": {"cwe_id": "CWE-918", "source": "http_param", "sink": "net_ssrf", "sanitizers": []},
        },
        {
            "entry_id": "CWE-502-DESERIALIZATION",
            "title": "Untrusted Stream to Unsafe Deserializer Sink (CWE-502)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_DESERIALIZATION",
            "cwe_ids": ("CWE-502",),
            "references": ("https://cwe.mitre.org/data/definitions/502.html",),
            "description": "Untrusted bytes deserialized via pickle/yaml.load/ObjectInputStream without safe loader.",
            "ast_signature": {"cwe_id": "CWE-502", "source": "file_net_stream", "sink": "deserialize", "sanitizers": []},
        },
        {
            "entry_id": "CWE-611-XXE",
            "title": "Untrusted XML Payload to External-Entity Parser Sink (CWE-611)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_XXE",
            "cwe_ids": ("CWE-611",),
            "references": ("https://cwe.mitre.org/data/definitions/611.html",),
            "description": "Untrusted XML parsed without disabling DTD/external entity resolution.",
            "ast_signature": {"cwe_id": "CWE-611", "source": "http_param", "sink": "xml_parse", "sanitizers": []},
        },
        {
            "entry_id": "CWE-1336-SSTI",
            "title": "Unsanitized External Input to Server-Side Template Engine (CWE-1336)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_INJECTION",
            "cwe_ids": ("CWE-1336",),
            "references": ("https://cwe.mitre.org/data/definitions/1336.html",),
            "description": "Untrusted input compiled directly as template source in Jinja2/Mako/EJS.",
            "ast_signature": {"cwe_id": "CWE-1336", "source": "http_param", "sink": "template_render", "sanitizers": []},
        },
        {
            "entry_id": "CWE-287-OIDC-AUTH-BYPASS",
            "title": "Missing Audience / Service-Principal Verification on Internal Route (CWE-287 / CWE-863)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_AUTH",
            "cwe_ids": ("CWE-287", "CWE-863"),
            "references": ("https://cwe.mitre.org/data/definitions/287.html",),
            "description": "OIDC/JWT token verified without strict audience or service-account caller guard.",
            "ast_signature": {"cwe_id": "CWE-287", "source": "auth_token", "sink": "authz_bypass", "sanitizers": []},
        },
        {
            "entry_id": "CWE-1321-PROTOTYPE-POLLUTION",
            "title": "Untrusted Object Merge to Prototype Pollution Sink (CWE-1321)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_PROTOTYPE",
            "cwe_ids": ("CWE-1321",),
            "references": ("https://cwe.mitre.org/data/definitions/1321.html",),
            "description": "Untrusted JSON/query object merged recursively without blocking __proto__/constructor keys.",
            "ast_signature": {"cwe_id": "CWE-1321", "source": "http_param", "sink": "proto_pollute", "sanitizers": []},
        },
        {
            "entry_id": "CWE-113-HEADER-INJECTION-AST",
            "title": "Unsanitized Input to Outbound HTTP Response Header Sink (CWE-113)",
            "source": "cwe_cve_taxonomy",
            "category": "TAINT_INJECTION",
            "cwe_ids": ("CWE-113",),
            "references": ("https://cwe.mitre.org/data/definitions/113.html",),
            "description": "Untrusted request input written into outbound HTTP header without stripping CR/LF.",
            "ast_signature": {"cwe_id": "CWE-113", "source": "http_param", "sink": "http_header_out", "sanitizers": []},
        },
    ]

    return wire_specs, ast_specs


# ---------------------------------------------------------------------------
# Local Known-Technique Disclosure Index
# ---------------------------------------------------------------------------

class NoveltyCorpusIndex:
    """
    Offline-by-default structural novelty corpus indexing:
      - Built-in PortSwigger HTTP desync & protocol research catalog
      - Built-in CWE/CVE protocol-flaw & AST code-taint taxonomy
      - Workspace Nuclei templates (`defense_rules/`, `templates/`, `data/`)
      - Prior verified findings from `terminator.db` (`reproducible_vulnerabilities`
        / `vulnerabilities`, `novel_techniques`, `blackboard_nodes` `FACT` rows)

    Computes deterministic combined Jaccard + corpus TF-IDF cosine similarity (`[0.0, 1.0]`).
    Zero network calls are ever performed during default construction or querying.
    """

    def __init__(
        self,
        *,
        db: Optional[Any] = None,
        db_path: Optional[Union[str, Path]] = None,
        workspace_root: Optional[Union[str, Path]] = None,
        include_builtin_catalog: bool = True,
        include_workspace_templates: bool = True,
        fingerprinter: Optional[CanonicalStructuralFingerprinter] = None,
        novelty_threshold: float = DEFAULT_NOVELTY_THRESHOLD,
    ) -> None:
        self._lock = threading.RLock()
        self.fingerprinter = fingerprinter or CanonicalStructuralFingerprinter()
        self.novelty_threshold = float(novelty_threshold)
        self._entries: Dict[str, CorpusEntry] = {}
        self._df: Counter[str] = Counter()
        self._idf_dirty: bool = True
        self._idf_cache: Dict[str, float] = {}
        self._entry_vecs: Dict[str, Tuple[Dict[str, float], float]] = {}

        if include_builtin_catalog:
            self._load_builtin_catalog()

        if include_workspace_templates:
            resolved_root = (
                Path(workspace_root)
                if workspace_root is not None
                else Path(__file__).resolve().parent.parent
            )
            if resolved_root.exists():
                self.ingest_workspace_templates(resolved_root)

        if db is not None:
            self.ingest_database(db)
        elif db_path is not None:
            self.ingest_database(Path(db_path))

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def entries(self) -> List[CorpusEntry]:
        with self._lock:
            return list(self._entries.values())

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            by_source: Counter[str] = Counter(e.source for e in self._entries.values())
            by_kind: Counter[str] = Counter(e.kind for e in self._entries.values())
            return {
                "total_entries": len(self._entries),
                "novelty_threshold": self.novelty_threshold,
                "by_source": dict(sorted(by_source.items())),
                "by_kind": dict(sorted(by_kind.items())),
            }

    # -- Indexing helpers ---------------------------------------------------

    def add_entry(self, entry: CorpusEntry) -> bool:
        """Adds or updates a `CorpusEntry` in the index. Returns True if newly added."""
        with self._lock:
            existed = entry.entry_id in self._entries
            if existed:
                old_terms = set(self._entries[entry.entry_id].fingerprint.all_terms())
                for term in old_terms:
                    self._df[term] = max(0, self._df[term] - 1)
                    if self._df[term] == 0:
                        del self._df[term]

            self._entries[entry.entry_id] = entry
            for term in set(entry.fingerprint.all_terms()):
                self._df[term] += 1
            self._idf_dirty = True
            return not existed

    def add_wire_technique(
        self,
        *,
        entry_id: str,
        title: str,
        probe: Union[bytes, str],
        source: str = "custom",
        category: str = "HTTP_DESYNC",
        description: str = "",
        cwe_ids: Sequence[str] = (),
        cve_ids: Sequence[str] = (),
        rfc_refs: Sequence[str] = (),
        references: Sequence[str] = (),
        divergence_matrix: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CorpusEntry:
        probe_bytes = probe.encode("latin-1", errors="replace") if isinstance(probe, str) else bytes(probe)
        fp = self.fingerprinter.fingerprint_wire(probe_bytes, divergence_matrix=divergence_matrix)
        entry = CorpusEntry(
            entry_id=entry_id,
            title=title,
            source=source,
            kind="wire",
            category=category,
            fingerprint=fp,
            description=description,
            cwe_ids=tuple(cwe_ids),
            cve_ids=tuple(cve_ids),
            rfc_refs=tuple(rfc_refs),
            references=tuple(references),
            canonical_probe=probe_bytes,
            metadata=dict(metadata or {}),
        )
        self.add_entry(entry)
        return entry

    def add_ast_technique(
        self,
        *,
        entry_id: str,
        title: str,
        finding: Union[Dict[str, Any], Any],
        source: str = "custom",
        category: str = "TAINT_INJECTION",
        description: str = "",
        cwe_ids: Sequence[str] = (),
        cve_ids: Sequence[str] = (),
        references: Sequence[str] = (),
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CorpusEntry:
        fp = self.fingerprinter.fingerprint_ast(finding)
        norm_cwes = list(cwe_ids) or list(fp.features.get("cwe_ids") or [])
        ast_sig = dict(finding) if isinstance(finding, dict) else dict(fp.features)
        entry = CorpusEntry(
            entry_id=entry_id,
            title=title,
            source=source,
            kind="ast",
            category=category,
            fingerprint=fp,
            description=description,
            cwe_ids=tuple(norm_cwes),
            cve_ids=tuple(cve_ids),
            references=tuple(references),
            ast_signature=ast_sig,
            metadata=dict(metadata or {}),
        )
        self.add_entry(entry)
        return entry

    def _load_builtin_catalog(self) -> None:
        for spec in _builtin_portswigger_wire_specs():
            self.add_wire_technique(
                entry_id=spec["entry_id"],
                title=spec["title"],
                probe=spec["probe"],
                source=spec["source"],
                category=spec["category"],
                description=spec.get("description", ""),
                cwe_ids=spec.get("cwe_ids", ()),
                cve_ids=spec.get("cve_ids", ()),
                rfc_refs=spec.get("rfc_refs", ()),
                references=spec.get("references", ()),
            )
        wire_cwe, ast_cwe = _builtin_cwe_cve_specs()
        for spec in wire_cwe:
            self.add_wire_technique(
                entry_id=spec["entry_id"],
                title=spec["title"],
                probe=spec["probe"],
                source=spec["source"],
                category=spec["category"],
                description=spec.get("description", ""),
                cwe_ids=spec.get("cwe_ids", ()),
                cve_ids=spec.get("cve_ids", ()),
                rfc_refs=spec.get("rfc_refs", ()),
                references=spec.get("references", ()),
            )
        for spec in ast_cwe:
            self.add_ast_technique(
                entry_id=spec["entry_id"],
                title=spec["title"],
                finding=spec["ast_signature"],
                source=spec["source"],
                category=spec["category"],
                description=spec.get("description", ""),
                cwe_ids=spec.get("cwe_ids", ()),
                cve_ids=spec.get("cve_ids", ()),
                references=spec.get("references", ()),
            )

    # -- Workspace Nuclei & Catalog Ingestion -------------------------------

    def ingest_workspace_templates(self, workspace_root: Union[str, Path]) -> int:
        """
        Scans local workspace directories (`defense_rules/`, `nuclei_templates/`,
        `nuclei-templates/`, `templates/`, `data/`, and top-level `.yaml`/`.yml`)
        for Nuclei templates and novelty catalog files without any network calls.
        """
        root = Path(workspace_root)
        if not root.exists():
            return 0

        candidate_files: List[Path] = []
        scan_subdirs = ("defense_rules", "nuclei_templates", "nuclei-templates", "templates", "data")
        for sub in scan_subdirs:
            sub_path = root / sub
            if sub_path.is_dir():
                for fp in sorted(sub_path.rglob("*")):
                    if not fp.is_file():
                        continue
                    ext = fp.suffix.lower()
                    if ext in (".yaml", ".yml"):
                        candidate_files.append(fp)
                    elif ext == ".json" and sub == "defense_rules":
                        candidate_files.append(fp)
                    elif ext == ".json" and sub == "data" and "novelty" in fp.name.lower():
                        candidate_files.append(fp)

        # Also inspect top-level .yaml/.yml directly in workspace_root (strictly validated as Nuclei)
        if root.is_dir():
            for fp in sorted(root.iterdir()):
                if fp.is_file() and fp.suffix.lower() in (".yaml", ".yml"):
                    candidate_files.append(fp)

        ingested = 0
        seen_paths: Set[Path] = set()
        for fpath in candidate_files:
            try:
                resolved = fpath.resolve()
            except OSError:
                continue
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            added, _ = self._ingest_local_file(resolved, default_source="workspace_nuclei")
            ingested += added
        return ingested

    def _ingest_local_file(
        self,
        path: Path,
        *,
        default_source: str = "external_file",
    ) -> Tuple[int, int]:
        """Ingests a single local YAML/Nuclei, JSON catalog, or SQLite DB file. Returns (added, updated)."""
        if not path.is_file():
            return 0, 0
        ext = path.suffix.lower()
        if ext in (".db", ".sqlite", ".sqlite3"):
            count = self.ingest_database(path)
            return count, 0

        text = path.read_text(encoding="utf-8", errors="replace")
        return self._ingest_payload_text(
            text,
            source_label=str(path),
            ext_hint=ext,
            default_source=default_source,
        )

    def _ingest_payload_text(
        self,
        text: str,
        *,
        source_label: str,
        ext_hint: str,
        default_source: str,
    ) -> Tuple[int, int]:
        added = 0
        updated = 0
        stripped = text.strip()
        if not stripped:
            return 0, 0

        # JSON catalog ingestion
        if ext_hint == ".json" or stripped.startswith(("{", "[")):
            try:
                payload = json.loads(stripped)
            except ValueError:
                payload = None
            if payload is not None:
                items: List[Any] = []
                if isinstance(payload, list):
                    items = payload
                elif isinstance(payload, dict):
                    for key in ("entries", "techniques", "items", "catalog", "vulnerabilities", "findings"):
                        val = payload.get(key)
                        if isinstance(val, list):
                            items = val
                            break
                    if not items and any(k in payload for k in ("probe", "minimized_probe", "raw_probe", "ast_signature", "sink")):
                        items = [payload]
                for idx, item in enumerate(items):
                    if not isinstance(item, dict):
                        continue
                    is_new = self._ingest_catalog_dict(
                        item,
                        fallback_id=f"CAT-{_slugify_token(Path(source_label).stem, 16)}-{idx + 1}",
                        default_source=default_source,
                        source_label=source_label,
                    )
                    if is_new is True:
                        added += 1
                    elif is_new is False:
                        updated += 1
                return added, updated

        # YAML / Nuclei template ingestion
        parsed_nuclei = _parse_nuclei_yaml_text(text, source_label=source_label)
        if parsed_nuclei is not None:
            t_id = parsed_nuclei["id"]
            probes = parsed_nuclei["raw_probes"]
            for idx, probe_bytes in enumerate(probes):
                e_id = f"NUCLEI-{t_id}" if len(probes) == 1 else f"NUCLEI-{t_id}-{idx + 1}"
                existed = e_id in self._entries
                self.add_wire_technique(
                    entry_id=e_id,
                    title=parsed_nuclei["title"],
                    probe=probe_bytes,
                    source=default_source,
                    category="NUCLEI_TEMPLATE",
                    description=parsed_nuclei["description"],
                    cwe_ids=parsed_nuclei["cwe_ids"],
                    cve_ids=parsed_nuclei["cve_ids"],
                    references=parsed_nuclei["references"],
                    metadata={
                        "template_id": t_id,
                        "tags": parsed_nuclei["tags"],
                        "source_file": source_label,
                    },
                )
                if existed:
                    updated += 1
                else:
                    added += 1
            return added, updated

        return 0, 0

    def _ingest_catalog_dict(
        self,
        item: Dict[str, Any],
        *,
        fallback_id: str,
        default_source: str,
        source_label: str,
    ) -> Optional[bool]:
        """Ingests a single JSON technique/finding record. Returns True if added, False if updated, None if skipped."""
        entry_id = str(
            item.get("entry_id")
            or item.get("technique_id")
            or item.get("id")
            or item.get("vuln_id")
            or fallback_id
        ).strip()
        title = str(item.get("title") or item.get("name") or entry_id).strip()
        source = str(item.get("source") or default_source).strip()
        category = str(item.get("category") or item.get("impact") or "EXTERNAL_CATALOG").strip()
        description = str(item.get("description") or item.get("conceptual_model") or "").strip()

        cwe_ids: List[str] = []
        for k in ("cwe_ids", "cwe_id", "cwe"):
            for val in _iter_str_values(item.get(k)):
                norm = _normalize_cwe_id(val)
                if norm and norm not in cwe_ids:
                    cwe_ids.append(norm)
        cve_ids = [
            v.upper()
            for v in _iter_str_values(item.get("cve_ids") or item.get("cve_id") or item.get("cve"))
            if v.upper().startswith("CVE-")
        ]
        rfc_refs = list(_iter_str_values(item.get("rfc_refs") or item.get("rfc_ref")))
        references = list(_iter_str_values(item.get("references") or item.get("reference")))

        probe_val = item.get("probe") or item.get("minimized_probe") or item.get("raw_probe") or item.get("raw_request")
        ast_sig = item.get("ast_signature")
        if ast_sig is None and any(k in item for k in ("source", "taint_source", "sink", "taint_sink")):
            if item.get("sink") or item.get("taint_sink"):
                ast_sig = item

        existed = entry_id in self._entries
        if probe_val:
            div_mat = item.get("divergence_matrix") if isinstance(item.get("divergence_matrix"), dict) else None
            self.add_wire_technique(
                entry_id=entry_id,
                title=title,
                probe=probe_val,
                source=source,
                category=category,
                description=description,
                cwe_ids=cwe_ids,
                cve_ids=cve_ids,
                rfc_refs=rfc_refs,
                references=references,
                divergence_matrix=div_mat,
                metadata={"source_origin": source_label},
            )
            return not existed
        if isinstance(ast_sig, dict):
            self.add_ast_technique(
                entry_id=entry_id,
                title=title,
                finding=ast_sig,
                source=source,
                category=category,
                description=description,
                cwe_ids=cwe_ids,
                cve_ids=cve_ids,
                references=references,
                metadata={"source_origin": source_label},
            )
            return not existed
        return None

    # -- `terminator.db` Prior Findings Ingestion ---------------------------

    def ingest_database(self, db_or_path: Any) -> int:
        """
        Loads prior confirmed findings from `terminator.db` (or any SQLite `Database`
        instance / connection / path):
          - `reproducible_vulnerabilities` and/or `vulnerabilities`
          - `novel_techniques`
          - `blackboard_nodes` (`node_type = 'FACT'`)
        Strictly read-only; never creates stray DB files or mutates tables.
        """
        conn: Optional[sqlite3.Connection] = None
        owns_conn = False
        db_lock = None

        if isinstance(db_or_path, (str, Path)):
            raw_p = str(db_or_path)
            if not raw_p or raw_p == ":memory:":
                return 0
            p = Path(raw_p)
            if not p.is_file():
                return 0
            conn = sqlite3.connect(str(p), timeout=10.0)
            conn.row_factory = sqlite3.Row
            owns_conn = True
        elif isinstance(db_or_path, sqlite3.Connection):
            conn = db_or_path
        elif hasattr(db_or_path, "conn"):
            conn = getattr(db_or_path, "conn", None)
            db_lock = getattr(db_or_path, "_lock", None)

        if conn is None:
            return 0

        ingested = 0
        try:
            if db_lock is not None:
                with db_lock:
                    ingested = self._ingest_sqlite_conn(conn)
            else:
                ingested = self._ingest_sqlite_conn(conn)
        except sqlite3.Error:
            return ingested
        finally:
            if owns_conn:
                try:
                    conn.close()
                except Exception:
                    pass
        return ingested

    def _ingest_sqlite_conn(self, conn: sqlite3.Connection) -> int:
        cur = conn.cursor()
        tables = {
            str(r[0])
            for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }

        # Map anomaly_id -> divergence_matrix when available
        anomaly_div_map: Dict[str, Dict[str, Any]] = {}
        if "implementation_anomalies" in tables:
            try:
                for row in cur.execute("SELECT anomaly_id, divergence_matrix FROM implementation_anomalies").fetchall():
                    aid = str(row[0] or "")
                    raw_dm = row[1]
                    if aid and isinstance(raw_dm, str) and raw_dm.strip():
                        try:
                            dm = json.loads(raw_dm)
                            if isinstance(dm, dict):
                                anomaly_div_map[aid] = dm
                        except ValueError:
                            pass
            except sqlite3.Error:
                pass

        vuln_probes_by_id: Dict[str, bytes] = {}
        ingested = 0

        # 1. `reproducible_vulnerabilities` and/or `vulnerabilities`
        for tbl_name in ("reproducible_vulnerabilities", "vulnerabilities"):
            if tbl_name not in tables:
                continue
            try:
                cols = {str(r[1]) for r in cur.execute(f"PRAGMA table_info({tbl_name})").fetchall()}
                rows = cur.execute(f"SELECT * FROM {tbl_name}").fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                rd = dict(zip([d[0] for d in cur.description], row)) if not isinstance(row, sqlite3.Row) else dict(row)
                impact = str(rd.get("impact") or "").strip()
                if impact.lower() == "nonreproducibletransient":
                    continue
                if "verification_attempts" in cols and rd.get("verification_attempts") is not None:
                    try:
                        if int(rd["verification_attempts"]) < 3:
                            continue
                    except (TypeError, ValueError):
                        pass
                if "reproducibility_rate" in cols and rd.get("reproducibility_rate") is not None:
                    try:
                        if float(rd["reproducibility_rate"]) < 0.66:
                            continue
                    except (TypeError, ValueError):
                        pass

                raw_probe = rd.get("minimized_probe") or rd.get("raw_probe") or rd.get("probe")
                if not raw_probe or (isinstance(raw_probe, str) and raw_probe.startswith("enc:v1:")):
                    continue
                probe_bytes = (
                    raw_probe.encode("latin-1", errors="replace")
                    if isinstance(raw_probe, str)
                    else bytes(raw_probe)
                )
                vid = str(rd.get("vuln_id") or rd.get("id") or hashlib.sha256(probe_bytes).hexdigest()[:10])
                vuln_probes_by_id[vid] = probe_bytes
                aid = str(rd.get("anomaly_id") or "")
                div_mat = anomaly_div_map.get(aid)
                e_id = f"DB-VULN-{vid}"
                is_new = e_id not in self._entries
                self.add_wire_technique(
                    entry_id=e_id,
                    title=f"Prior Confirmed Finding {vid} ({impact or 'VULNERABILITY'})",
                    probe=probe_bytes,
                    source="terminator_db_vuln",
                    category=impact or "PRIOR_VULN",
                    description=f"Loaded from terminator.db:{tbl_name} ({vid})",
                    divergence_matrix=div_mat,
                    metadata={"table": tbl_name, "vuln_id": vid, "anomaly_id": aid},
                )
                if is_new:
                    ingested += 1

        # 2. `novel_techniques`
        if "novel_techniques" in tables:
            try:
                rows = cur.execute("SELECT * FROM novel_techniques").fetchall()
                desc_cols = [d[0] for d in cur.description] if cur.description else []
            except sqlite3.Error:
                rows = []
                desc_cols = []
            for row in rows:
                rd = dict(zip(desc_cols, row)) if not isinstance(row, sqlite3.Row) else dict(row)
                tid = str(rd.get("technique_id") or "").strip()
                if not tid:
                    continue
                title = str(rd.get("title") or tid).strip()
                inv = str(rd.get("inversion_pattern") or "")
                model = str(rd.get("conceptual_model") or "")

                # Attempt to recover wire probe via supporting_vulnerabilities or embedded canonical token
                linked_probe: Optional[bytes] = None
                raw_supp = rd.get("supporting_vulnerabilities")
                supp_ids: List[str] = []
                if isinstance(raw_supp, str) and raw_supp.strip():
                    try:
                        parsed_supp = json.loads(raw_supp)
                        if isinstance(parsed_supp, list):
                            supp_ids = [str(x) for x in parsed_supp]
                    except ValueError:
                        pass
                for sid in supp_ids:
                    if sid in vuln_probes_by_id:
                        linked_probe = vuln_probes_by_id[sid]
                        break

                e_id = f"DB-TECH-{tid}"
                is_new = e_id not in self._entries
                if linked_probe is not None:
                    self.add_wire_technique(
                        entry_id=e_id,
                        title=title,
                        probe=linked_probe,
                        source="terminator_db_novel",
                        category="PRIOR_NOVEL_TECHNIQUE",
                        description=model,
                        metadata={"technique_id": tid, "supporting_vulnerabilities": supp_ids},
                    )
                    if is_new:
                        ingested += 1
                    continue

                # Check if canonical tokens were persisted in inversion_pattern (e.g. [CANON:WIRE|...])
                m_canon = re.search(r"\[CANON:(WIRE\|[^\]]+|AST\|[^\]]+)\]", inv)
                if m_canon:
                    canon_str = m_canon.group(1)
                    parts = canon_str.split("|")
                    kind_tag = parts[0].lower()
                    toks = tuple(sorted(set(p for p in parts[1:] if p)))
                    shingles = _build_grouped_shingles(toks)
                    digest = hashlib.sha256(canon_str.encode("utf-8")).hexdigest()[:16]
                    fp = StructuralFingerprint(
                        fingerprint_id=f"FP-{parts[0]}-{digest}",
                        kind=kind_tag,
                        canonical_form=canon_str,
                        tokens=toks,
                        shingles=shingles,
                        features={"restored_from_db": True, "technique_id": tid},
                    )
                    entry = CorpusEntry(
                        entry_id=e_id,
                        title=title,
                        source="terminator_db_novel",
                        kind=kind_tag,
                        category="PRIOR_NOVEL_TECHNIQUE",
                        fingerprint=fp,
                        description=model,
                        metadata={"technique_id": tid},
                    )
                    if self.add_entry(entry):
                        ingested += 1
                    continue

                # Well-known built-in technique IDs persisted without supporting probe rows
                if tid == "TECH-SHARED-PARSER-CONFUSION":
                    self.add_wire_technique(
                        entry_id=e_id,
                        title=title,
                        probe=b"HTTP/1.1 200 OK\r\nHost: target.example\r\n\r\n",
                        source="terminator_db_novel",
                        category="PRIOR_NOVEL_TECHNIQUE",
                        description=model,
                        metadata={"technique_id": tid},
                    )
                    if is_new:
                        ingested += 1
                elif tid == "TECH-NULL-BYTE-FRAME-DESYNC":
                    self.add_wire_technique(
                        entry_id=e_id,
                        title=title,
                        probe=b"GET / HTTP/1.1\r\nHost: target.example\r\nX-Null: a\x00b\r\n\r\n",
                        source="terminator_db_novel",
                        category="PRIOR_NOVEL_TECHNIQUE",
                        description=model,
                        metadata={"technique_id": tid},
                    )
                    if is_new:
                        ingested += 1

        # 3. `blackboard_nodes` FACTs
        if "blackboard_nodes" in tables:
            try:
                rows = cur.execute(
                    "SELECT node_id, content, payload_json, domain, rfc_id, status "
                    "FROM blackboard_nodes WHERE node_type = 'FACT' AND UPPER(COALESCE(status, 'ACTIVE')) != 'INACTIVE'"
                ).fetchall()
            except sqlite3.Error:
                rows = []
            for row in rows:
                node_id = str(row[0] or "").strip()
                content = str(row[1] or "")
                raw_payload = row[2]
                domain = str(row[3] or "")
                rfc_id = str(row[4] or "")
                payload: Dict[str, Any] = {}
                if isinstance(raw_payload, str) and raw_payload.strip():
                    try:
                        decoded = json.loads(raw_payload)
                        if isinstance(decoded, dict):
                            payload = decoded
                    except ValueError:
                        payload = {}
                if not payload:
                    continue

                # Skip transient/unverified FACTs if explicitly marked
                if str(payload.get("impact") or "").lower() == "nonreproducibletransient":
                    continue

                raw_probe = payload.get("minimized_probe") or payload.get("raw_probe") or payload.get("probe")
                e_id = f"DB-FACT-{node_id}"
                is_new = e_id not in self._entries
                if raw_probe and not (isinstance(raw_probe, str) and raw_probe.startswith("enc:v1:")):
                    div_mat = payload.get("divergence_matrix") if isinstance(payload.get("divergence_matrix"), dict) else None
                    self.add_wire_technique(
                        entry_id=e_id,
                        title=content[:120] or f"Blackboard FACT {node_id}",
                        probe=raw_probe,
                        source="terminator_db_fact",
                        category=str(payload.get("impact") or domain or "BLACKBOARD_FACT"),
                        description=content,
                        rfc_refs=(rfc_id,) if rfc_id else (),
                        divergence_matrix=div_mat,
                        metadata={"node_id": node_id, "domain": domain},
                    )
                    if is_new:
                        ingested += 1
                elif (payload.get("sink") or payload.get("taint_sink")) and (
                    payload.get("source") or payload.get("taint_source") or payload.get("cwe_id") or payload.get("cwe")
                ):
                    self.add_ast_technique(
                        entry_id=e_id,
                        title=content[:120] or f"Blackboard AST FACT {node_id}",
                        finding=payload,
                        source="terminator_db_fact",
                        category=str(payload.get("threat_category") or domain or "BLACKBOARD_AST_FACT"),
                        description=content,
                        metadata={"node_id": node_id, "domain": domain},
                    )
                    if is_new:
                        ingested += 1

        return ingested

    # -- Explicit Opt-In Refresh --------------------------------------------

    def refresh_from_sources(
        self,
        paths_or_urls: Union[str, Path, Sequence[Union[str, Path]]],
        *,
        allow_network: bool = False,
        timeout_s: float = 10.0,
        max_bytes: int = 5 * 1024 * 1024,
    ) -> Dict[str, Any]:
        """
        Explicit opt-in CLI-callable catalog refresh from local JSON/YAML/Nuclei/SQLite
        files/directories OR explicitly permitted external HTTP(S) feeds.

        NEVER invoked automatically during default offline runs.
        Fail-closed: passing an `http://`/`https://` URL when `allow_network=False`
        raises `PermissionError` without opening any socket.
        When `allow_network=True`, remote URLs are strictly validated against SSRF
        invariants (`validate_target_host(..., allow_private=False)`).
        """
        if isinstance(paths_or_urls, (str, Path)):
            items: List[Union[str, Path]] = [paths_or_urls]
        else:
            items = list(paths_or_urls)

        added_total = 0
        updated_total = 0
        skipped_total = 0
        errors: List[str] = []
        sources_processed: List[str] = []

        for item in items:
            raw_str = str(item or "").strip()
            if not raw_str:
                skipped_total += 1
                continue
            if "\x00" in raw_str:
                errors.append(f"Rejected source with NUL byte: {raw_str!r}")
                skipped_total += 1
                continue

            parsed_url = urlparse(raw_str)
            scheme = (parsed_url.scheme or "").lower()
            is_windows_drive = len(scheme) == 1 and raw_str[1:2] == ":"

            if scheme in ("http", "https"):
                if not allow_network:
                    raise PermissionError(
                        f"Offline-by-default novelty corpus blocked remote URL '{raw_str}'. "
                        "Pass allow_network=True explicitly to fetch external feeds."
                    )
                text, ext_hint = self._fetch_remote_feed(
                    raw_str,
                    timeout_s=timeout_s,
                    max_bytes=max_bytes,
                )
                a, u = self._ingest_payload_text(
                    text,
                    source_label=raw_str,
                    ext_hint=ext_hint,
                    default_source="external_url",
                )
                added_total += a
                updated_total += u
                sources_processed.append(raw_str)
                continue

            if scheme and not is_windows_drive:
                raise PermissionError(
                    f"Unsupported URI scheme '{scheme}' for novelty corpus refresh; "
                    "only local filesystem paths and opt-in http(s) URLs are allowed."
                )

            p = Path(raw_str)
            if not p.exists():
                errors.append(f"Local source not found: {raw_str}")
                skipped_total += 1
                continue

            if p.is_dir():
                for child in sorted(p.rglob("*")):
                    if not child.is_file():
                        continue
                    if child.suffix.lower() not in (".json", ".yaml", ".yml", ".db", ".sqlite", ".sqlite3"):
                        continue
                    a, u = self._ingest_local_file(child, default_source="external_file")
                    added_total += a
                    updated_total += u
                    if a or u:
                        sources_processed.append(str(child))
            else:
                a, u = self._ingest_local_file(p, default_source="external_file")
                added_total += a
                updated_total += u
                sources_processed.append(str(p))

        return {
            "added": added_total,
            "updated": updated_total,
            "skipped": skipped_total,
            "errors": errors,
            "sources_processed": sources_processed,
            "total_corpus_entries": len(self),
            "allow_network": bool(allow_network),
        }

    def _fetch_remote_feed(
        self,
        url: str,
        *,
        timeout_s: float,
        max_bytes: int,
    ) -> Tuple[str, str]:
        """Fetches an opt-in remote JSON/YAML feed after mathematical SSRF verification."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            raise ValueError(f"Invalid feed URL (missing hostname): {url}")

        from engine.safe_network_validator import validate_target_host

        is_safe, reason = validate_target_host(host, allow_private=False)
        if not is_safe:
            raise PermissionError(f"Remote novelty feed '{url}' rejected by SSRF guard: {reason}")

        import urllib.request

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "RFCHunt-NoveltyCorpus/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=float(timeout_s)) as resp:
            raw_bytes = resp.read(int(max_bytes) + 1)
        if len(raw_bytes) > int(max_bytes):
            raise ValueError(f"Remote feed '{url}' exceeded maximum allowed size ({max_bytes} bytes).")

        path_ext = Path(parsed.path).suffix.lower()
        return raw_bytes.decode("utf-8", errors="replace"), path_ext

    def export_catalog(self, output_path: Union[str, Path]) -> int:
        """Exports the current corpus entries to a local UTF-8 JSON catalog file."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            records = []
            for entry in self._entries.values():
                rec: Dict[str, Any] = {
                    "entry_id": entry.entry_id,
                    "title": entry.title,
                    "source": entry.source,
                    "kind": entry.kind,
                    "category": entry.category,
                    "description": entry.description,
                    "cwe_ids": list(entry.cwe_ids),
                    "cve_ids": list(entry.cve_ids),
                    "rfc_refs": list(entry.rfc_refs),
                    "references": list(entry.references),
                    "fingerprint_id": entry.fingerprint.fingerprint_id,
                    "canonical_form": entry.fingerprint.canonical_form,
                }
                if entry.canonical_probe is not None:
                    rec["probe"] = entry.canonical_probe.decode("latin-1", errors="replace")
                if entry.ast_signature is not None:
                    rec["ast_signature"] = entry.ast_signature
                records.append(rec)
        out.write_text(
            json.dumps({"schema": "rfchunt-novelty-corpus-v1", "entries": records}, indent=2),
            encoding="utf-8",
        )
        return len(records)

    # -- Similarity Scoring (Jaccard + Smooth Corpus TF-IDF Cosine) ---------

    def _ensure_tfidf_index(self) -> None:
        if not self._idf_dirty:
            return
        n_docs = len(self._entries)
        idf: Dict[str, float] = {}
        for term, df_val in self._df.items():
            idf[term] = math.log((n_docs + 1.0) / (df_val + 1.0)) + 1.0

        vecs: Dict[str, Tuple[Dict[str, float], float]] = {}
        for eid, entry in self._entries.items():
            counts = Counter(entry.fingerprint.all_terms())
            vec: Dict[str, float] = {}
            sq_sum = 0.0
            for term, tf in counts.items():
                w = (1.0 + math.log(tf)) * idf.get(term, 1.0)
                vec[term] = w
                sq_sum += w * w
            vecs[eid] = (vec, math.sqrt(sq_sum) if sq_sum > 0.0 else 0.0)

        self._idf_cache = idf
        self._entry_vecs = vecs
        self._idf_dirty = False

    def _tfidf_vector(self, fp: StructuralFingerprint) -> Tuple[Dict[str, float], float]:
        n_docs = len(self._entries)
        unseen_idf = math.log((n_docs + 1.0) / 1.0) + 1.0
        counts = Counter(fp.all_terms())
        vec: Dict[str, float] = {}
        sq_sum = 0.0
        for term, tf in counts.items():
            w = (1.0 + math.log(tf)) * self._idf_cache.get(term, unseen_idf)
            vec[term] = w
            sq_sum += w * w
        return vec, math.sqrt(sq_sum) if sq_sum > 0.0 else 0.0

    @staticmethod
    def _strip_divergence_terms(fp: StructuralFingerprint) -> StructuralFingerprint:
        """
        Builds a divergence-neutral projection of a wire fingerprint so a probe evaluated
        with a live divergence matrix still compares fairly against corpus entries indexed
        without a divergence matrix (and vice versa), without discarding divergence signals
        when both sides provide them.
        """
        core_tokens = tuple(t for t in fp.tokens if not t.startswith("DIV:"))
        core_shingles = _build_grouped_shingles(core_tokens)
        return StructuralFingerprint(
            fingerprint_id=fp.fingerprint_id,
            kind=fp.kind,
            canonical_form=fp.canonical_form,
            tokens=core_tokens,
            shingles=core_shingles,
            features=fp.features,
        )

    def _score_pair(
        self,
        query_fp: StructuralFingerprint,
        q_vec: Dict[str, float],
        q_norm: float,
        entry: CorpusEntry,
    ) -> Tuple[float, float, float, Tuple[str, ...]]:
        e_vec, e_norm = self._entry_vecs[entry.entry_id]
        jaccard = self.fingerprinter.jaccard_similarity(query_fp, entry.fingerprint)

        cosine = 0.0
        if q_norm > 0.0 and e_norm > 0.0:
            if len(q_vec) <= len(e_vec):
                dot = sum(w * e_vec.get(t, 0.0) for t, w in q_vec.items())
            else:
                dot = sum(w * q_vec.get(t, 0.0) for t, w in e_vec.items())
            cosine = max(0.0, min(1.0, dot / (q_norm * e_norm)))

        combined = max(0.0, min(1.0, 0.5 * jaccard + 0.5 * cosine))
        matched_toks = tuple(sorted(set(query_fp.tokens) & set(entry.fingerprint.tokens)))
        return combined, jaccard, cosine, matched_toks

    def query(
        self,
        fingerprint: StructuralFingerprint,
        *,
        top_k: int = 5,
        threshold: Optional[float] = None,
        kind_filter: Optional[str] = None,
    ) -> NoveltyQueryResult:
        """Returns top-k nearest known techniques with similarity scores and match explanations."""
        eff_threshold = self.novelty_threshold if threshold is None else float(threshold)
        k = max(1, int(top_k))

        with self._lock:
            self._ensure_tfidf_index()
            q_vec, q_norm = self._tfidf_vector(fingerprint)

            q_has_div = any(t.startswith("DIV:") for t in fingerprint.tokens)
            q_nodiv_fp: Optional[StructuralFingerprint] = None
            q_nodiv_vec: Dict[str, float] = {}
            q_nodiv_norm = 0.0
            if q_has_div and fingerprint.kind == "wire":
                q_nodiv_fp = self._strip_divergence_terms(fingerprint)
                q_nodiv_vec, q_nodiv_norm = self._tfidf_vector(q_nodiv_fp)

            scored: List[SimilarityMatch] = []
            for entry in self._entries.values():
                if kind_filter and entry.kind != kind_filter:
                    continue
                if not kind_filter and fingerprint.kind in ("wire", "ast") and entry.kind != fingerprint.kind:
                    continue

                combined, jaccard, cosine, matched_toks = self._score_pair(
                    fingerprint, q_vec, q_norm, entry
                )

                # If query carries divergence tokens while corpus entry had none, also score
                # the divergence-neutral structural core so known techniques (e.g. CL.TE with a
                # live divergence matrix) still match their catalog counterpart accurately.
                entry_has_div = any(t.startswith("DIV:") for t in entry.fingerprint.tokens)
                if q_nodiv_fp is not None and not entry_has_div:
                    c2, j2, cos2, mt2 = self._score_pair(q_nodiv_fp, q_nodiv_vec, q_nodiv_norm, entry)
                    if c2 > combined:
                        combined, jaccard, cosine, matched_toks = c2, j2, cos2, mt2

                high_sig = [
                    t for t in matched_toks
                    if t.startswith(("DESYNC:", "ANOM:", "FRAMING:", "INVERSION:", "BYTE:", "CWE:", "FLOW:", "SINK:", "SRC:"))
                ]
                shown = high_sig[:6] if high_sig else list(matched_toks[:6])
                explanation = (
                    f"Matched {entry.entry_id} ({entry.source}) with combined={combined:.3f} "
                    f"(jaccard={jaccard:.3f}, tfidf_cosine={cosine:.3f}); "
                    f"shared structural features: {', '.join(shown) if shown else 'none'}"
                )
                scored.append(
                    SimilarityMatch(
                        entry_id=entry.entry_id,
                        title=entry.title,
                        source=entry.source,
                        category=entry.category,
                        similarity=combined,
                        jaccard_similarity=jaccard,
                        tfidf_cosine_similarity=cosine,
                        matched_tokens=matched_toks,
                        explanation=explanation,
                        cwe_ids=entry.cwe_ids,
                        cve_ids=entry.cve_ids,
                        references=entry.references,
                        fingerprint_id=entry.fingerprint.fingerprint_id,
                    )
                )

            scored.sort(key=lambda m: (-m.similarity, -m.tfidf_cosine_similarity, m.entry_id))
            top_matches = tuple(scored[:k])
            max_sim = top_matches[0].similarity if top_matches else 0.0
            sources_loaded = dict(sorted(Counter(e.source for e in self._entries.values()).items()))
            return NoveltyQueryResult(
                query_fingerprint=fingerprint,
                max_similarity=max_sim,
                threshold=eff_threshold,
                is_known=max_sim >= eff_threshold,
                nearest_matches=top_matches,
                corpus_size=len(self._entries),
                sources_loaded=sources_loaded,
            )

    def query_wire(
        self,
        raw_probe: Union[bytes, str],
        *,
        divergence_matrix: Optional[Dict[str, Any]] = None,
        impact: Optional[str] = None,
        rfc_context: Optional[str] = None,
        top_k: int = 5,
        threshold: Optional[float] = None,
    ) -> NoveltyQueryResult:
        fp = self.fingerprinter.fingerprint_wire(
            raw_probe,
            divergence_matrix=divergence_matrix,
            impact=impact,
            rfc_context=rfc_context,
        )
        return self.query(fp, top_k=top_k, threshold=threshold, kind_filter="wire")

    def query_ast(
        self,
        finding: Union[Dict[str, Any], Any],
        *,
        top_k: int = 5,
        threshold: Optional[float] = None,
    ) -> NoveltyQueryResult:
        fp = self.fingerprinter.fingerprint_ast(finding)
        return self.query(fp, top_k=top_k, threshold=threshold, kind_filter="ast")


# ---------------------------------------------------------------------------
# Ergonomic CLI-Callable Refresh Hook
# ---------------------------------------------------------------------------

def refresh_novelty_corpus(
    paths_or_urls: Union[str, Path, Sequence[Union[str, Path]]],
    *,
    db: Optional[Any] = None,
    db_path: Optional[Union[str, Path]] = None,
    workspace_root: Optional[Union[str, Path]] = None,
    allow_network: bool = False,
    output_path: Optional[Union[str, Path]] = None,
    novelty_threshold: float = DEFAULT_NOVELTY_THRESHOLD,
) -> Dict[str, Any]:
    """
    CLI-callable entry point to build the local `NoveltyCorpusIndex`, ingest explicit
    external catalog files or opt-in feeds, and optionally export a merged offline JSON
    catalog snapshot.
    """
    corpus = NoveltyCorpusIndex(
        db=db,
        db_path=db_path,
        workspace_root=workspace_root,
        include_builtin_catalog=True,
        include_workspace_templates=True,
        novelty_threshold=novelty_threshold,
    )
    report = corpus.refresh_from_sources(paths_or_urls, allow_network=allow_network)
    if output_path is not None:
        exported = corpus.export_catalog(output_path)
        report["exported_path"] = str(Path(output_path))
        report["exported_entries"] = exported
    report["corpus_summary"] = corpus.summary()
    return report
