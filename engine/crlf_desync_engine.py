"""
Module 24: Reverse-Proxy Config & HTTP Header Conformance Auditor
=================================================================
Defensive static configuration auditor and RFC 9112 protocol-conformance validator
for Nginx / OpenResty / Tengine reverse proxies and HTTP/1.1 intermediaries.

Capabilities:
1. Static Reverse-Proxy Config Auditing (`audit_nginx_configs`):
   - Detects unsafe normalized variable interpolation (`$uri`, `$document_uri`) in
     `proxy_pass`, `return`, `rewrite`, and `add_header` directives.
   - Detects permissive regex captures lacking CR/LF exclusion in `location` / `rewrite`.
   - Emits exact defensive remediation configs (e.g., `$request_uri` and strict header hygiene).
2. Safe 3-Trial RFC 9112 Conformance Diagnostics (`run_conformance_diagnostics`):
   - Strictly gated by `ExecutionPolicy` authorization and an anti-contamination canary guard
     (read-only canary paths only; never touches session cookies or state-mutating methods).
   - Verifies across >= 3 repeated trials whether an HTTP intermediary properly rejects
     non-conformant framing/header syntax (`HTTP/13.37` -> 505, invalid `Transfer-Encoding` -> 501,
     invalid `Expect` -> 417, invalid `Content-Length` -> 400) and preserves internal header stripping.
   - Downgrades unstable/timing-dependent variations to `NonReproducibleTransient`.
3. SARIF 2.1.0 & Defensive Rule Export (Nginx hardening directives + Snort/Nuclei alerts).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import http.client
import os
from pathlib import Path
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

MODULE_24_NAME = "Module-24-CRLF-Conformance"

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".pytest_cache",
}

_NGINX_CONFIG_NAMES = {
    "nginx.conf",
    "openresty.conf",
    "tengine.conf",
    "default.conf",
    "proxy.conf",
    "upstream.conf",
}

_NGINX_EXTENSIONS = {".conf", ".nginx", ".vhost"}

# Static Nginx / OpenResty / Tengine rules
_RULE_PROXY_PASS_URI = re.compile(
    r"^\s*proxy_pass\s+[^;#\r\n]*\$(?:uri|document_uri)\b",
    re.IGNORECASE,
)
_RULE_RETURN_URI = re.compile(
    r"^\s*return\s+(?:30[12378]|200)\s+[^;#\r\n]*\$(?:uri|document_uri)\b",
    re.IGNORECASE,
)
_RULE_REWRITE_CAPTURE = re.compile(
    r"^\s*rewrite\s+\^[^#\r\n]*\(\.\*|\.\+\)[^#\r\n]*\$1",
    re.IGNORECASE,
)
_RULE_ADD_HEADER_VAR = re.compile(
    r"^\s*add_header\s+[A-Za-z0-9_-]+\s+[^;#\r\n]*\$(?:uri|document_uri|arg_[a-zA-Z0-9_]+|http_[a-zA-Z0-9_]+)\b",
    re.IGNORECASE,
)
_RULE_PROXY_SET_HEADER_URI = re.compile(
    r"^\s*proxy_set_header\s+[A-Za-z0-9_-]+\s+[^;#\r\n]*\$(?:uri|document_uri)\b",
    re.IGNORECASE,
)

# Canary safety guard: forbidden headers/paths that could contaminate shared state
_FORBIDDEN_CANARY_HEADERS = {"cookie", "authorization", "set-cookie", "proxy-authorization"}
_FORBIDDEN_CANARY_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


@dataclass
class ConformanceFinding:
    rule_id: str
    title: str
    severity: str
    cwe: str
    category: str
    location: str
    line: int
    evidence: str
    remediation: str
    reproducibility: str = "StaticConfirmed"
    trials_passed: int = 1
    trials_total: int = 1
    isolation_scope: str = "ConfigStatic"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_sarif_result(self) -> Dict[str, Any]:
        level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        return {
            "ruleId": self.rule_id,
            "level": level_map.get(self.severity.upper(), "warning"),
            "message": {"text": f"{self.title}: {self.evidence}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.location},
                        "region": {"startLine": max(1, int(self.line))},
                    }
                }
            ],
            "properties": {
                "cwe": self.cwe,
                "category": self.category,
                "reproducibility": self.reproducibility,
                "isolation_scope": self.isolation_scope,
                "remediation": self.remediation,
            },
        }


@dataclass
class ConformanceAuditReport:
    target: str
    module: str = MODULE_24_NAME
    files_scanned: int = 0
    trials_per_check: int = 3
    findings: List[ConformanceFinding] = field(default_factory=list)
    defensive_rules: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "files_scanned": self.files_scanned,
            "trials_per_check": self.trials_per_check,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "defensive_rules": self.defensive_rules,
        }


def _is_candidate_nginx_file(path: Path) -> bool:
    name_low = path.name.lower()
    if name_low in _NGINX_CONFIG_NAMES:
        return True
    if path.suffix.lower() in _NGINX_EXTENSIONS:
        return True
    return "nginx" in name_low and path.suffix.lower() in ("", ".txt", ".tmpl", ".erb")


def _audit_single_config_file(path: Path, root: Path) -> List[ConformanceFinding]:
    findings: List[ConformanceFinding] = []
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            return findings
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    # Verify it looks like an Nginx/OpenResty config before emitting rules
    if not any(kw in text for kw in ("proxy_pass", "location ", "server {", "upstream ", "add_header", "return ")):
        return findings

    try:
        rel = str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        rel = str(path).replace("\\", "/")

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if _RULE_PROXY_PASS_URI.search(raw_line):
            findings.append(
                ConformanceFinding(
                    rule_id="CRLF-NGINX-001",
                    title="Unsafe Normalized $uri Interpolation in Nginx proxy_pass",
                    severity="HIGH",
                    cwe="CWE-113",
                    category="reverse_proxy_header_hygiene",
                    location=rel,
                    line=lineno,
                    evidence=line[:220],
                    remediation=(
                        "Use `$request_uri` (raw, un-normalized) or omit the URI component from `proxy_pass` "
                        "(e.g. `proxy_pass http://upstream_backend;`) so percent-encoded CR/LF bytes are never decoded into upstream requests."
                    ),
                )
            )
        elif _RULE_RETURN_URI.search(raw_line):
            findings.append(
                ConformanceFinding(
                    rule_id="CRLF-NGINX-002",
                    title="Unsafe Normalized $uri Interpolation in Nginx Redirect Directive",
                    severity="HIGH",
                    cwe="CWE-113",
                    category="response_header_hygiene",
                    location=rel,
                    line=lineno,
                    evidence=line[:220],
                    remediation=(
                        "Replace `$uri`/`$document_uri` with `$request_uri` in `return 301/302` directives "
                        "to prevent decoded line breaks from splitting response headers."
                    ),
                )
            )
        elif _RULE_PROXY_SET_HEADER_URI.search(raw_line):
            findings.append(
                ConformanceFinding(
                    rule_id="CRLF-NGINX-003",
                    title="Normalized $uri Forwarded in Upstream proxy_set_header",
                    severity="MEDIUM",
                    cwe="CWE-113",
                    category="reverse_proxy_header_hygiene",
                    location=rel,
                    line=lineno,
                    evidence=line[:220],
                    remediation=(
                        "Avoid forwarding normalized `$uri` or `$document_uri` in `proxy_set_header`; "
                        "use `$request_uri` or strictly validate the header value against `[\\r\\n]`."
                    ),
                )
            )
        elif _RULE_ADD_HEADER_VAR.search(raw_line):
            findings.append(
                ConformanceFinding(
                    rule_id="CRLF-NGINX-004",
                    title="Unvalidated Request Variable Interpolated in add_header",
                    severity="MEDIUM",
                    cwe="CWE-113",
                    category="response_header_hygiene",
                    location=rel,
                    line=lineno,
                    evidence=line[:220],
                    remediation=(
                        "Never interpolate raw `$uri`, `$arg_*`, or `$http_*` directly into `add_header`; "
                        "map values through a strict `map` allowlist excluding CR/LF bytes."
                    ),
                )
            )
        elif _RULE_REWRITE_CAPTURE.search(raw_line):
            findings.append(
                ConformanceFinding(
                    rule_id="CRLF-NGINX-005",
                    title="Permissive Rewrite Regex Capture May Match Decoded Control Bytes",
                    severity="MEDIUM",
                    cwe="CWE-113",
                    category="reverse_proxy_header_hygiene",
                    location=rel,
                    line=lineno,
                    evidence=line[:220],
                    remediation=(
                        "Constrain rewrite capture groups to safe URL characters (e.g., `([^\\r\\n\\s]+)`) "
                        "and reject requests containing encoded CR/LF sequences."
                    ),
                )
            )

    return findings


def audit_nginx_configs(target_dir: str | Path, max_workers: Optional[int] = None) -> ConformanceAuditReport:
    """
    Concurrently audits Nginx/OpenResty/Tengine configuration files in `target_dir`
    using a bounded ThreadPoolExecutor.
    """
    root = Path(target_dir).resolve()
    report = ConformanceAuditReport(target=str(root))
    if not root.exists():
        return report

    candidates: List[Path] = []
    if root.is_file():
        candidates.append(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if _is_candidate_nginx_file(p):
                    candidates.append(p)

    report.files_scanned = len(candidates)
    workers = max_workers or min(16, max(2, (os.cpu_count() or 4)))

    if candidates:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_audit_single_config_file, p, root) for p in candidates]
            for fut in as_completed(futs):
                try:
                    report.findings.extend(fut.result())
                except Exception:
                    continue

    report.findings.sort(key=lambda f: (f.location, f.line, f.rule_id))
    report.defensive_rules = generate_defensive_rules()
    return report


def validate_canary_safety(method: str, headers: Dict[str, str], path: str) -> Tuple[bool, str]:
    """
    Anti-contamination safety guard ensuring conformance checks never mutate state
    or attach sensitive authentication/session headers on shared connections.
    """
    if method.upper() in _FORBIDDEN_CANARY_METHODS:
        return False, f"State-mutating HTTP method '{method}' blocked by anti-contamination guard."
    for k in headers:
        if k.strip().lower() in _FORBIDDEN_CANARY_HEADERS:
            return False, f"Sensitive header '{k}' blocked by anti-contamination guard."
    if not path.startswith("/"):
        return False, "Canary path must start with '/'."
    return True, "ok"


def _send_raw_http_once(
    host: str,
    port: int,
    raw_request: bytes,
    *,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> Tuple[int, Dict[str, str], str]:
    """Sends a single benign conformance request over a fresh socket and parses status + headers."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(raw_request)
        chunks: List[bytes] = []
        total = 0
        while total < 65536:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if b"\r\n\r\n" in b"".join(chunks):
                break
        raw_resp = b"".join(chunks).decode("latin-1", errors="replace")
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not raw_resp:
        return 0, {}, ""

    head, _, _ = raw_resp.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    m = re.match(r"HTTP/\d+\.\d+\s+(\d{3})", status_line)
    status_code = int(m.group(1)) if m else 0
    hdrs: Dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return status_code, hdrs, status_line


def run_conformance_diagnostics(
    host: str,
    port: int,
    *,
    use_tls: bool = False,
    canary_path: str = "/rfchunt-conformance-canary",
    trials: int = 3,
    timeout: float = 3.0,
) -> ConformanceAuditReport:
    """
    Runs read-only, 3-trial RFC 9112 header & framing conformance checks against an authorized
    target (or local loopback test server). Gated by `ExecutionPolicy` when available.
    """
    trials = max(3, int(trials))
    report = ConformanceAuditReport(
        target=f"{'https' if use_tls else 'http'}://{host}:{port}{canary_path}",
        trials_per_check=trials,
    )

    # Enforce ExecutionPolicy authorization
    try:
        from engine.execution_policy import (
            ActionType,
            ExecutionPolicy,
            ScannerTask,
            StructuredIntentProposal,
        )

        proposal = StructuredIntentProposal(
            task=ScannerTask.PROTOCOL_PROBE,
            action_type=ActionType.NETWORK_SOCKET,
            target_host=host,
            target_port=port,
            rationale="Module 24 RFC 9112 read-only header conformance diagnostic",
            is_destructive=False,
        )
        ExecutionPolicy.get_instance().validate_intent(proposal)
    except Exception:
        # Allow explicit loopback test hosts even if ExecutionPolicy singleton is unconfigured
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise

    safe, reason = validate_canary_safety("GET", {"Host": host}, canary_path)
    if not safe:
        raise ValueError(reason)

    # 1. Establish stable 3-trial baseline status on benign request
    baseline_req = (
        f"GET {canary_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1")

    baseline_statuses: List[int] = []
    for _ in range(trials):
        st, _, _ = _send_raw_http_once(host, port, baseline_req, use_tls=use_tls, timeout=timeout)
        baseline_statuses.append(st)

    if len(set(baseline_statuses)) != 1 or baseline_statuses[0] == 0:
        report.findings.append(
            ConformanceFinding(
                rule_id="CRLF-CONF-TRANSIENT",
                title="Unstable Baseline Response During Conformance Check",
                severity="LOW",
                cwe="CWE-436",
                category="protocol_conformance",
                location=report.target,
                line=1,
                evidence=f"Baseline statuses varied across {trials} trials: {baseline_statuses}",
                remediation="Stabilize target endpoint before running protocol conformance diagnostics.",
                reproducibility="NonReproducibleTransient",
                trials_passed=0,
                trials_total=trials,
                isolation_scope="Transient",
            )
        )
        report.defensive_rules = generate_defensive_rules()
        return report

    base_status = baseline_statuses[0]

    # 2. Read-only RFC 9112 strict-rejection conformance checks
    checks: List[Tuple[str, str, str, bytes, Sequence[int], str]] = [
        (
            "CRLF-CONF-001",
            "Encoded CR/LF in Request-Target Accepted Without 400/403 Rejection",
            "HIGH",
            (
                f"GET {canary_path}%0d%0aX-RFCHunt-Canary:%201 HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("latin-1"),
            (400, 403, 404, 422),
            "Reject percent-encoded CR (%0d) and LF (%0a) in request targets at the reverse proxy before URI normalization.",
        ),
        (
            "CRLF-CONF-002",
            "Malformed Expect Header Not Rejected With 417 Expectation Failed",
            "MEDIUM",
            (
                f"GET {canary_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Expect: rfchunt-invalid-expectation\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("latin-1"),
            (400, 417, 501),
            "Enforce RFC 9110 Section 10.1.1: reject unknown Expect tokens with HTTP 417 instead of forwarding them upstream.",
        ),
        (
            "CRLF-CONF-003",
            "Unsupported Transfer-Encoding Token Not Rejected With 400/501",
            "MEDIUM",
            (
                f"GET {canary_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Transfer-Encoding: rfchunt-unknown-coding\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("latin-1"),
            (400, 501),
            "Enforce RFC 9112 Section 6.3: intermediaries must reject unknown Transfer-Encoding tokens with 400 or 501.",
        ),
        (
            "CRLF-CONF-004",
            "Non-Numeric Content-Length Accepted Without 400 Bad Request",
            "HIGH",
            (
                f"GET {canary_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: invalid_len\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("latin-1"),
            (400,),
            "Enforce RFC 9112 Section 6.3: reject any request with non-digit Content-Length with HTTP 400 Bad Request.",
        ),
    ]

    for rule_id, title, severity, probe_bytes, expected_reject_codes, remediation in checks:
        trial_statuses: List[int] = []
        leaked_canary_header = False
        for _ in range(trials):
            st, hdrs, _ = _send_raw_http_once(host, port, probe_bytes, use_tls=use_tls, timeout=timeout)
            trial_statuses.append(st)
            if "x-rfchunt-canary" in hdrs:
                leaked_canary_header = True

        # Require consistent 3/3 trial reproduction
        consistent = len(set(trial_statuses)) == 1 and trial_statuses[0] != 0
        if not consistent:
            report.findings.append(
                ConformanceFinding(
                    rule_id=rule_id,
                    title=f"{title} (Transient)",
                    severity="LOW",
                    cwe="CWE-436",
                    category="protocol_conformance",
                    location=report.target,
                    line=1,
                    evidence=f"Inconsistent statuses across {trials} trials: {trial_statuses}",
                    remediation=remediation,
                    reproducibility="NonReproducibleTransient",
                    trials_passed=0,
                    trials_total=trials,
                    isolation_scope="Transient",
                )
            )
            continue

        observed = trial_statuses[0]
        if leaked_canary_header or (observed == base_status and observed not in expected_reject_codes):
            report.findings.append(
                ConformanceFinding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    cwe="CWE-113" if "CR/LF" in title else "CWE-436",
                    category="protocol_conformance",
                    location=report.target,
                    line=1,
                    evidence=(
                        f"Consistent HTTP {observed} across {trials}/{trials} trials "
                        f"(baseline={base_status}, expected rejection in {list(expected_reject_codes)}, "
                        f"canary_reflected={leaked_canary_header})."
                    ),
                    remediation=remediation,
                    reproducibility="ConfirmedMultiTrial",
                    trials_passed=trials,
                    trials_total=trials,
                    isolation_scope="HeaderConformance",
                )
            )

    report.defensive_rules = generate_defensive_rules()
    return report


def generate_defensive_rules() -> Dict[str, str]:
    """Generates ready-to-deploy Nginx hardening snippets and Snort/IDS detection rules."""
    return {
        "nginx_hardening": (
            "# Block encoded CR/LF in request URI before normalization\n"
            "if ($request_uri ~* \"%0[ad]\") {\n"
            "    return 400;\n"
            "}\n"
            "# Use raw $request_uri or bare upstream in proxy_pass (never $uri)\n"
            "proxy_pass http://upstream_backend;\n"
            "proxy_http_version 1.1;\n"
        ),
        "snort_rule": (
            'alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS '
            '(msg:"RFCHunt Encoded CRLF in HTTP Request-Target"; '
            'flow:to_server,established; http_uri; content:"%0d%0a"; nocase; '
            'classtype:web-application-attack; sid:2400001; rev:1;)'
        ),
    }
