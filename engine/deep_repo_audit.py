"""
Deep Repository Security Audit Engine (`--deep-audit` / `deep-audit`).

Bridges static scanning toward real bug discovery for code repositories via three
composable, strictly CLI-only, non-destructive pillars:
  1. Live Loopback Proxy Fuzzing (`--live-proxy-fuzz`):
     Spins up (or attaches to) the target repo's HTTP/proxy server strictly on `127.0.0.1`
     (loopback-only fail-closed), executes 3-trial RFC 9112 framing & proxy-smuggling probes,
     and cross-checks responses through `MultiImplementationDifferentialOracle` (+ optional
     Docker parser matrix when Docker is running).
  2. Line-by-Line Trust-Boundary Security Review (`--trust-boundary-review`):
     Ranks production trust-boundary files (HTTP/TLS proxies, path resolvers, authz/policy/ACL
     evaluators, credential/SigV4 filters, OS/FFI sandbox wrappers — including nested first-party
     crates like `vendor/*/src`) and performs bounded multithreaded line-by-line structural &
     invariant inspection enriched with `CallGraphSlicer` cross-file taint slices.
  3. Coverage-Guided Fuzzing (`--coverage-fuzz`):
     Runs `LLMFuzzBridge` (`cargo-fuzz`/`libFuzzer`, `Jazzer`, `AFL++`/`LibAFL`, `Atheris`)
     against root repo parsers AND nested Rust/C/C++ crates (e.g., `vendor/srt-win-src`),
     writing all harnesses/corpora strictly outside the target repo under `<output-dir>/deep_audit/`.

Safety invariants:
  - Strictly CLI-only (zero GUI imports), zero `shell=True`, zero mutations to target repo.
  - Loopback-only (`127.0.0.1` / `localhost` / `::1`) fail-closed for live proxy fuzzing.
  - Strictly respects `PYTEST_CURRENT_TEST`, `CI`, `RFCHUNT_OFFLINE=1`, and `approval_mode="deny"`.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
from urllib.parse import urlparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from engine.call_graph_slicer import slice_repository
from engine.differential_oracle import (
    DEFAULT_DIFFERENTIAL_PROBES,
    MultiImplementationDifferentialOracle,
)
from engine.fuzz_bridge import run_fuzz_bridge_scan
from engine.poc_generator import _resolve_constant_binding, _STATIC_LITERAL_RE

MAX_FILE_BYTES = 512 * 1024
DEFAULT_MAX_TRUST_FILES = 80
LIVE_PROBE_TRIALS = 3

_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "dist",
        "build",
        "target",
        "out",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".venv",
        "venv",
        "reports",
        "runs",
        "coverage",
    }
)

_TEST_DIR_NAMES = frozenset({"test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata", "mocks"})
_TEST_FILE_RE = re.compile(
    r"(^test_.*|\.(test|spec)\.[A-Za-z0-9]+$|_test\.[A-Za-z0-9]+$|Test\.[A-Za-z0-9]+$)",
    re.IGNORECASE,
)
_SOURCE_EXTS = frozenset({".ts", ".tsx", ".js", ".mjs", ".cjs", ".rs", ".py", ".go", ".c", ".cc", ".cpp", ".h", ".java"})

_TRUST_CATEGORIES: Tuple[Tuple[str, int, re.Pattern], ...] = (
    (
        "http_proxy_parser",
        10,
        re.compile(r"(proxy|http|request|header|parser|frame|mitm|tls|forwarding|routing|url|host)", re.IGNORECASE),
    ),
    (
        "authz_policy_fail_closed",
        9,
        re.compile(r"(authz|policy|filter|decider|acl|dacl|seccomp|guard|allowlist|deny|rule|permission|wfp|firewall|netfilter|ebpf)", re.IGNORECASE),
    ),
    (
        "path_confinement",
        9,
        re.compile(r"(sandbox|path|jail|chroot|mount|symlink|fs|file|resolve|canonical|glob|pattern|seatbelt)", re.IGNORECASE),
    ),
    (
        "credential_crypto_boundary",
        8,
        re.compile(r"(cred|sigv4|secret|token|ca|cert|key|crypto|mask|sign|auth)", re.IGNORECASE),
    ),
    (
        "process_exec_isolation",
        7,
        re.compile(r"(exec|spawn|install|win|linux|mac|container|broker|process|job|wfp|reg|bwrap)", re.IGNORECASE),
    ),
)

_COMMENT_RE = re.compile(r"^\s*(///|//!|//|#|/\*|\*|--)")
_FORBIDDEN_CMD_META = (";", "|", "&", "$(", "`", "\n", "\r", "\x00", ">", "<")

_FAIL_OPEN_CATCH_RE = re.compile(
    r"\b(catch\s*(\([^)]*\))?\s*\{|except\b[^:]*:|Err\s*\([^)]*\)\s*=>)"
)
_RETURN_ALLOW_RE = re.compile(r"\b(return\s+true\b|return\s+True\b|Ok\s*\(\s*true\s*\)|allow\s*[:=]\s*true\b)")
_BARE_LF_SPLIT_RE = re.compile(r"""\.split\s*\(\s*['"]\\n['"]\s*\)""")
_PATH_JOIN_RE = re.compile(r"\b(?:path\.join|os\.path\.join|Path::join|filepath\.Join)\s*\(")
_PATH_CONTAINMENT_RE = re.compile(
    r"\b(is_relative_to|startsWith|starts_with|strip_prefix|realpath|canonicalize|resolve\(|normalize\(|isSubpath|withinRoot)\b"
)
_SHELL_EXEC_RE = re.compile(
    r"(?:(?<![.\w])|\b(?:child_process|cp)\.)(execSync|exec|spawnSync|spawn|subprocess\.run|subprocess\.Popen|os\.system)\s*\(\s*([^,\)\n]+)"
)
_SHELL_TRUE_RE = re.compile(r"\bshell\s*[:=]\s*(true|True)\b")
_TLS_DISABLE_RE = re.compile(
    r"(rejectUnauthorized\s*:\s*false|danger_accept_invalid_certs\s*\(\s*true\s*\)|InsecureSkipVerify\s*:\s*true|verify\s*=\s*False)"
)
_PERMISSIVE_ACL_CODE_RE = re.compile(
    r"(0o?777\b|0o?666\b|chmod\s*\([^,]+,\s*0o?(?:777|666)\b|WELL_KNOWN_SID_TYPE::WinBuiltinUsersSid|WinBuiltinUsersSid|WinWorldSid|BUILTIN\\\\Users.*Modify|S-1-5-32-545|S-1-1-0)"
)
_RUST_UNSAFE_BLOCK_RE = re.compile(r"\bunsafe\s*\{")
_RUST_FFI_SENSITIVE_RE = re.compile(
    r"\b(CreateProcess[A-Za-z]*|SetNamedSecurityInfo[A-Za-z]*|SetSecurityInfo|OpenProcess|AssignProcessToJobObject|ConvertStringSidToSid[A-Za-z]*|AllocateAndInitializeSid|LocalFree|FreeSid|CloseHandle|RegSetValue[A-Za-z]*|CreateFile[A-Za-z]*|DeviceIoControl)\b"
)
_RUST_CLEANUP_RE = re.compile(r"\b(FreeSid|LocalFree|CloseHandle|Drop|ManuallyDrop|defer|guard|Err\(|bail!|ensure!|anyhow!|\?)\b")

# Structural multi-token detectors for real-world proxy, TLS, OS-sandbox, and regex/URL trust boundaries
_TLS_HANDSHAKE_BYTE_RE = re.compile(r"\b0x16\b")
_TLS_MAJOR_BYTE_RE = re.compile(r"\[\s*1\s*\]\s*!?\s*(?:===|==)\s*(?:0x0?3|3)\b")
_TLS_MINOR_CAP_RE = re.compile(
    r"\[\s*2\s*\]\s*!?\s*(?:<=\s*(?:0x0?3|3)\b|<\s*(?:0x0?4|4)\b|(?:===|==)\s*(?:0x0?1|0x0?3)\b)"
)

_CRED_INJECT_CALL_RE = re.compile(
    r"\b(mutateHeaders[A-Za-z0-9_]*|planSigv4|inject(?:Auth|Cred|Secret|Header)[A-Za-z0-9_]*|substituteCredentials?|applyCredentials?)\s*(?:\?\.)?\s*\("
)
_CRED_DECL_RE = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:function|type|interface|def|fn|class)\b")
_HTTP_PROXY_SERVER_CTX_RE = re.compile(
    r"\b(req\.method|IncomingMessage|ServerResponse|createServer|forwardUpstream|handleConnect|http\.request|https\.request)\b"
)
_HTTP_FORWARD_HDR_CTX_RE = re.compile(
    r"\b(fwdHeaders|proxyReq|forwardUpstream|httpsRequest|httpRequest|upstream)\b"
)
_ECHO_METHOD_GUARD_RE = re.compile(
    r"""(?:\bECHO_METHODS\b|\bisEchoMethod\b|['"]TRACE['"]|['"]TRACK['"]|\bMethod::TRACE\b|\bhttp\.MethodTrace\b)"""
)

_WIN_CREATEFILE_RE = re.compile(r"\bCreateFile[WA]\s*\(")
_WFP_OUTBOUND_CONNECT_RE = re.compile(r"\bFWPM_LAYER_ALE_AUTH_CONNECT_V[46]\b")
_WFP_FILTER_API_RE = re.compile(
    r"\b(FwpmFilterAdd0|FwpmFilterCreateEnumHandle0|FWPM_FILTER0|FwpmSubLayerAdd0)\b"
)
_WFP_INBOUND_LAYER_RE = re.compile(
    r"\b(FWPM_LAYER_ALE_AUTH_LISTEN_V[46]|FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V[46])\b"
)

_BWRAP_REF_RE = re.compile(r"""(?:\bbwrapArgs\b|['"]bwrap['"]|\bbwrap\b)""")
_SECCOMP_REF_RE = re.compile(r"\b(applySeccomp[A-Za-z0-9_]*|apply-seccomp|seccomp)\b", re.IGNORECASE)
_BWRAP_SHELL_C_RE = re.compile(
    r"""(?:bwrapArgs\.push\s*\([^)]*['"]-c['"]|['"]--['"]\s*,\s*(?:shell|binShell|['"][^'"]*(?:sh|bash|zsh)['"])\s*,\s*['"]-c['"])"""
)
_BWRAP_CLEARENV_RE = re.compile(r"--clearenv\b")
_BWRAP_BASH_ENV_RE = re.compile(r"""['"]BASH_ENV['"]""")
_BWRAP_ZDOTDIR_RE = re.compile(r"""['"]ZDOTDIR['"]""")

_BRACKET_REPLACE_CALL_RE = re.compile(
    r"""(?:\[\s*\$\{[^}\n]*\.replace\s*\(|['"]\[['"]\s*\+[^;\n]*\.replace\s*\(|f['"]\[\{re\.sub\s*\()"""
)
_BRACKET_BACKSLASH_SUB_RE = re.compile(r"""(?:['"]\\\\\$&['"]|['"]\\\\\$0['"]|r['"]\\\\\\1['"]|r['"]\\\\g<0>['"])""")
_BRACKET_CLASS_ARG_RE = re.compile(r"/\[([^\]]+)\]/g?|r?['\"]\[([^\]]+)\]['\"]")

_SYNTHETIC_URL_HOST_RE = re.compile(
    r"""(?:new\s+URL\s*\(\s*(?:`https?://\$\{[^`}]+\}[^`]*`|['"]https?://['"]\s*\+[^)]+)\)|urlparse\s*\(\s*f['"]https?://\{[^'"}]+\}[^'"]*['"]\s*\))"""
)
_URL_HOST_ACCESS_RE = re.compile(r"\.hostname\b")
_URL_USERINFO_CHECK_RE = re.compile(r"\.(username|password)\b")
_URL_STRUCT_CHECK_RE = re.compile(r"\.(pathname|port|search|hash)\b")
_SINGLE_TRAILING_DOT_RE = re.compile(r"""\.replace\s*\(\s*/\\\.\$/\s*,\s*['"]['"]\s*\)""")

_LIVE_PROXY_PROBES: Tuple[Tuple[str, str, bytes], ...] = (
    (
        "PROXY-CL-TE-001",
        "Conflicting Content-Length and Transfer-Encoding: chunked",
        b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\nX",
    ),
    (
        "PROXY-TE-OBF-002",
        "Obfuscated Transfer-Encoding header with Content-Length",
        b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nTransfer-Encoding: xchunked\r\nConnection: close\r\n\r\n1234",
    ),
    (
        "PROXY-CL-CL-003",
        "Duplicate conflicting Content-Length headers",
        b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\nhello",
    ),
    (
        "PROXY-BARE-LF-004",
        "Bare LF header line delimiter without CR",
        b"GET / HTTP/1.1\nHost: 127.0.0.1\nConnection: close\n\n",
    ),
    (
        "PROXY-OBS-FOLD-005",
        "Deprecated obs-fold multi-line Host header",
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n evil.invalid\r\nConnection: close\r\n\r\n",
    ),
    (
        "PROXY-CONNECT-AMBIG-006",
        "CONNECT request-target vs mismatched Host header authority",
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: blocked.invalid:443\r\nConnection: close\r\n\r\n",
    ),
)


@dataclass
class TrustBoundaryFinding:
    """Line-level structural security finding from targeted trust-boundary review."""

    rule_id: str
    severity: str
    category: str
    file_path: str
    line_number: int
    title: str
    description: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "scanner": "DeepRepoAudit-TrustBoundary",
        }


@dataclass
class DeepRepoAuditReport:
    """Unified output of `--deep-audit` across all three real-bug discovery pillars."""

    repo_path: str
    output_dir: str
    live_proxy_fuzz: Dict[str, Any]
    trust_boundary_review: Dict[str, Any]
    coverage_fuzz: Dict[str, Any]
    findings: List[Dict[str, Any]] = field(default_factory=list)
    report_markdown_path: str = ""
    summary_json_path: str = ""
    elapsed_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": "completed",
            "repo_path": self.repo_path,
            "output_dir": self.output_dir,
            "total_findings": len(self.findings),
            "live_proxy_fuzz": self.live_proxy_fuzz,
            "trust_boundary_review": self.trust_boundary_review,
            "coverage_fuzz": self.coverage_fuzz,
            "findings": self.findings,
            "report_markdown_path": self.report_markdown_path,
            "summary_json_path": self.summary_json_path,
            "elapsed_sec": round(self.elapsed_sec, 3),
        }


def _is_loopback_host(host: str) -> bool:
    cleaned = str(host or "").strip().lower().strip("[]")
    if cleaned in ("127.0.0.1", "localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


def _validate_safe_proxy_cmd(cmd_str: str) -> List[str]:
    if not cmd_str or not str(cmd_str).strip():
        raise ValueError("Empty --proxy-cmd")
    for tok in _FORBIDDEN_CMD_META:
        if tok in cmd_str:
            raise PermissionError(f"--proxy-cmd contains forbidden shell metacharacter: {tok!r}")
    argv = shlex.split(cmd_str, posix=(os.name != "nt"))
    if not argv:
        raise ValueError("Empty parsed --proxy-cmd")
    return argv


def _is_test_path(rel_path: Path) -> bool:
    parts = [p.lower() for p in rel_path.parts]
    if any(seg in _TEST_DIR_NAMES for seg in parts[:-1]):
        return True
    return bool(_TEST_FILE_RE.search(rel_path.name))


def discover_trust_boundary_files(
    repo_path: Union[str, Path],
    *,
    max_files: int = DEFAULT_MAX_TRUST_FILES,
) -> List[Tuple[Path, str, int]]:
    """
    Discovers and ranks production trust-boundary source files in `repo_path`.
    Includes first-party nested crates (e.g., `vendor/srt-win-src/src/*.rs`) while
    strictly excluding tests, `node_modules`, `dist`, `target`, and `.git`.
    """
    root = Path(repo_path).resolve(strict=False)
    if not root.is_dir():
        return []

    ranked: List[Tuple[int, str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d
            for d in dirnames
            if d.lower() not in _EXCLUDED_DIRS and d.lower() not in _TEST_DIR_NAMES
        ]
        cur = Path(dirpath)
        for fname in filenames:
            fpath = cur / fname
            if fpath.suffix.lower() not in _SOURCE_EXTS:
                continue
            try:
                rel = fpath.relative_to(root)
            except Exception:
                continue
            if _is_test_path(rel):
                continue
            rel_posix = rel.as_posix()
            best_score = 0
            best_cat = "general"
            for cat, weight, rx in _TRUST_CATEGORIES:
                if rx.search(rel_posix):
                    if weight > best_score:
                        best_score = weight
                        best_cat = cat
            if best_score > 0:
                # Boost core src/ files slightly over auxiliary scripts
                if rel.parts and rel.parts[0].lower() in ("src", "lib", "engine", "vendor"):
                    best_score += 2
                ranked.append((best_score, best_cat, fpath))

    ranked.sort(key=lambda item: (-item[0], item[2].as_posix().lower()))
    return [(fp, cat, score) for score, cat, fp in ranked[: max(1, int(max_files))]]


def _strip_c_line_comment(line: str) -> str:
    """Strips trailing `//` comment outside string literals."""
    in_quote: Optional[str] = None
    escaped = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if in_quote:
            if ch == "\\":
                escaped = True
            elif ch == in_quote:
                in_quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            in_quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n and line[i + 1] == "/":
            return line[:i]
        i += 1
    return line


def _extract_balanced_call(lines: Sequence[str], start_idx_1based: int, col_start: int, max_lines: int = 16) -> str:
    """Extracts a balanced `func(...)` call across multiple lines with comments stripped."""
    chunks: List[str] = []
    depth = 0
    saw_open = False
    for offset in range(max_lines):
        pos = (start_idx_1based - 1) + offset
        if pos >= len(lines):
            break
        raw_line = lines[pos]
        if _COMMENT_RE.match(raw_line):
            continue
        seg = _strip_c_line_comment(raw_line)
        if offset == 0:
            seg = seg[col_start:]
        chunks.append(seg)
        for ch in seg:
            if ch == "(":
                depth += 1
                saw_open = True
            elif ch == ")":
                depth -= 1
                if saw_open and depth <= 0:
                    return "\n".join(chunks)
    return "\n".join(chunks)


def _is_posix_ere_bracket_escape(line: str) -> bool:
    """Returns True when a line builds a `[...]` regex set by backslash-escaping POSIX-literal metacharacters."""
    if not _BRACKET_REPLACE_CALL_RE.search(line):
        return False
    if not _BRACKET_BACKSLASH_SUB_RE.search(line):
        return False
    m_cls = _BRACKET_CLASS_ARG_RE.search(line)
    if not m_cls:
        return False
    cls_body = m_cls.group(1) or m_cls.group(2) or ""
    posix_literals = sum(1 for ch in ".^$+{}()|" if ch in cls_body)
    return posix_literals >= 2


def _audit_single_trust_file(
    file_path: Path,
    category: str,
    repo_root: Path,
) -> List[TrustBoundaryFinding]:
    """Performs targeted, low-noise line-by-line trust-boundary audit on a single source file."""
    findings: List[TrustBoundaryFinding] = []
    try:
        raw = file_path.read_bytes()[:MAX_FILE_BYTES]
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return findings

    lines = text.splitlines()
    rel = file_path.relative_to(repo_root).as_posix() if file_path.is_relative_to(repo_root) else str(file_path)
    ext = file_path.suffix.lower()

    # Precompute comment-stripped executable lines once per file for context-aware invariants
    exec_indexed: List[Tuple[int, str]] = [
        (i, _strip_c_line_comment(l) if ext in (".ts", ".tsx", ".js", ".mjs", ".cjs", ".rs", ".go", ".c", ".cc", ".cpp", ".h", ".java") else l)
        for i, l in enumerate(lines, 1)
        if l.strip() and not _COMMENT_RE.match(l)
    ]
    exec_text = "\n".join(seg for _, seg in exec_indexed)

    has_proxy_forward_ctx = bool(
        _HTTP_PROXY_SERVER_CTX_RE.search(exec_text) and _HTTP_FORWARD_HDR_CTX_RE.search(exec_text)
    )
    has_echo_method_guard = bool(_ECHO_METHOD_GUARD_RE.search(exec_text))
    last_echo_finding_line = -100

    has_bwrap_seccomp_ctx = bool(_BWRAP_REF_RE.search(exec_text) and _SECCOMP_REF_RE.search(exec_text))
    has_bwrap_shell_env_guard = bool(
        _BWRAP_CLEARENV_RE.search(exec_text)
        or (_BWRAP_BASH_ENV_RE.search(exec_text) and _BWRAP_ZDOTDIR_RE.search(exec_text))
    )
    emitted_bwrap_preseccomp = False

    # File-level Check A: Windows WFP outbound-only ALE connect filters without inbound/listen layers
    if ext in (".rs", ".c", ".cc", ".cpp", ".h", ".go"):
        if (
            _WFP_OUTBOUND_CONNECT_RE.search(exec_text)
            and _WFP_FILTER_API_RE.search(exec_text)
            and not _WFP_INBOUND_LAYER_RE.search(exec_text)
        ):
            first_wfp_line = next(
                (ln for ln, seg in exec_indexed if _WFP_OUTBOUND_CONNECT_RE.search(seg)),
                1,
            )
            findings.append(
                TrustBoundaryFinding(
                    rule_id="TB-WIN-WFP-MISSING-INBOUND",
                    severity="HIGH",
                    category=category,
                    file_path=str(file_path),
                    line_number=first_wfp_line,
                    title=f"WFP outbound-only ALE filters omit inbound/listen layers in {rel}:{first_wfp_line}",
                    description=(
                        "Windows Filtering Platform (WFP) module registers outbound `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` "
                        "filters without corresponding `FWPM_LAYER_ALE_AUTH_LISTEN` or `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT` "
                        "enforcement, allowing sandboxed processes to bind listeners and accept inbound network traffic."
                    ),
                    evidence=lines[first_wfp_line - 1].strip()[:200],
                    remediation=(
                        "Install matching `FWPM_LAYER_ALE_AUTH_LISTEN_V4/V6` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` "
                        "block filters (with explicit loopback permit rules if required)."
                    ),
                )
            )

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(line):
            continue

        code_line = (
            _strip_c_line_comment(line)
            if ext in (".ts", ".tsx", ".js", ".mjs", ".cjs", ".rs", ".go", ".c", ".cc", ".cpp", ".h", ".java")
            else line
        )
        if not code_line.strip():
            continue

        window_after = "\n".join(lines[idx - 1 : min(len(lines), idx + 6)])
        window_around = "\n".join(lines[max(0, idx - 4) : min(len(lines), idx + 6)])

        # 1. Fail-open catch/error handler in authz/policy/filter/guard files (strictly scoped to catch/except body)
        if category in ("authz_policy_fail_closed", "http_proxy_parser", "path_confinement"):
            m_catch = _FAIL_OPEN_CATCH_RE.search(line)
            if m_catch:
                tail_after_catch = line[m_catch.start() :]
                catch_body_lines: List[str] = [tail_after_catch]
                if "{" in tail_after_catch:
                    brace_depth = tail_after_catch.count("{") - tail_after_catch.count("}")
                    for nxt in lines[idx : min(len(lines), idx + 12)]:
                        if brace_depth <= 0:
                            break
                        catch_body_lines.append(nxt)
                        brace_depth += nxt.count("{") - nxt.count("}")
                else:
                    base_indent = len(line) - len(line.lstrip())
                    for nxt in lines[idx : min(len(lines), idx + 8)]:
                        if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= base_indent:
                            break
                        catch_body_lines.append(nxt)
                catch_body = "\n".join(catch_body_lines)
                if _RETURN_ALLOW_RE.search(catch_body):
                    findings.append(
                        TrustBoundaryFinding(
                            rule_id="TB-FAIL-OPEN-CATCH",
                            severity="HIGH",
                            category=category,
                            file_path=str(file_path),
                            line_number=idx,
                            title=f"Fail-open exception/error handler in {rel}:{idx}",
                            description=(
                                "Error/exception branch in a security policy or filter appears to return "
                                "an allow/true verdict instead of failing closed (deny/false)."
                            ),
                            evidence=catch_body[:240],
                            remediation="Fail closed (`return false` / `Err(...)` / deny) on all parsing or authorization errors.",
                        )
                    )

        # 2. HTTP parser bare-LF splitting in proxy/HTTP files
        if category == "http_proxy_parser" and _BARE_LF_SPLIT_RE.search(line):
            if "\\r\\n" not in window_around and "strict" not in window_around.lower():
                findings.append(
                    TrustBoundaryFinding(
                        rule_id="TB-HTTP-FRAMING-SMUGGLE",
                        severity="MEDIUM",
                        category=category,
                        file_path=str(file_path),
                        line_number=idx,
                        title=f"Permissive bare-LF HTTP splitting in {rel}:{idx}",
                        description=(
                            "Splitting HTTP messages/headers on bare `\\n` without rejecting missing `\\r\\n` "
                            "can diverge from strict RFC 9112 parsers and enable request smuggling."
                        ),
                        evidence=line.strip()[:200],
                        remediation="Require strict `\\r\\n` CRLF framing per RFC 9112 and reject bare LF with 400 Bad Request.",
                    )
                )

        # 3. Path join without containment check in path/sandbox/jail files
        if category == "path_confinement" and _PATH_JOIN_RE.search(line):
            wider = "\n".join(lines[max(0, idx - 8) : min(len(lines), idx + 12)])
            if not _PATH_CONTAINMENT_RE.search(wider) and ("req." in wider or "input" in wider or "user" in wider or "arg" in wider):
                findings.append(
                    TrustBoundaryFinding(
                        rule_id="TB-PATH-CONFINEMENT",
                        severity="HIGH",
                        category=category,
                        file_path=str(file_path),
                        line_number=idx,
                        title=f"Unbounded path join near external input in {rel}:{idx}",
                        description=(
                            "Path join appears near dynamic input without a nearby canonicalization and "
                            "root-containment check (`resolve` + `startsWith` / `is_relative_to` / `strip_prefix`)."
                        ),
                        evidence=line.strip()[:200],
                        remediation="Canonicalize the resolved path and assert it remains strictly within the sandbox root (rejecting `..`, drive letters, UNC paths, and symlinks).",
                    )
                )

        # 4. Dynamic (non-constant) shell execution sink
        m_exec = _SHELL_EXEC_RE.search(line)
        if m_exec:
            func_name = m_exec.group(1)
            arg_expr = m_exec.group(2).strip()
            is_shell_sink = func_name in ("execSync", "exec", "os.system") or bool(_SHELL_TRUE_RE.search(window_after))
            if is_shell_sink:
                is_static = bool(_STATIC_LITERAL_RE.match(arg_expr)) or (_resolve_constant_binding(lines, arg_expr) is not None)
                if not is_static:
                    findings.append(
                        TrustBoundaryFinding(
                            rule_id="TB-DYNAMIC-SHELL-EXEC",
                            severity="HIGH",
                            category=category,
                            file_path=str(file_path),
                            line_number=idx,
                            title=f"Dynamic command passed to shell sink `{func_name}` in {rel}:{idx}",
                            description=(
                                f"`{func_name}({arg_expr})` receives a non-constant expression with shell "
                                "interpretation enabled in a production trust-boundary file."
                            ),
                            evidence=line.strip()[:200],
                            remediation="Use shell-free argv execution (`execFileSync` / `spawnSync(..., { shell: false })` / `subprocess.run([...], shell=False)`).",
                        )
                    )

        # 5. TLS certificate verification disabled in production
        if _TLS_DISABLE_RE.search(line):
            findings.append(
                TrustBoundaryFinding(
                    rule_id="TB-TLS-VERIFY-DISABLED",
                    severity="HIGH",
                    category=category,
                    file_path=str(file_path),
                    line_number=idx,
                    title=f"TLS certificate verification disabled in {rel}:{idx}",
                    description="Production code disables TLS peer certificate validation, permitting MITM attacks.",
                    evidence=line.strip()[:200],
                    remediation="Enable strict TLS certificate verification and pin or trust only explicit managed CA roots.",
                )
            )

        # 6. Permissive ACL / DACL / chmod mode in executable code (never comments)
        if _PERMISSIVE_ACL_CODE_RE.search(line):
            findings.append(
                TrustBoundaryFinding(
                    rule_id="TB-PERMISSIVE-ACL-MODE",
                    severity="MEDIUM",
                    category=category,
                    file_path=str(file_path),
                    line_number=idx,
                    title=f"Broad multi-user ACL/permission grant in {rel}:{idx}",
                    description=(
                        "Executable code grants broad world/BUILTIN\\Users permissions; verify sensitive key "
                        "material, sockets, or sandbox controls cannot be tampered with by other local users."
                    ),
                    evidence=line.strip()[:200],
                    remediation="Restrict ACLs/modes to owner/SYSTEM/Administrators where possible, or document and isolate per-user state.",
                )
            )

        # 7. Rust unsafe FFI blocks touching Win32 security/process APIs without nearby cleanup/error check
        if ext == ".rs" and _RUST_UNSAFE_BLOCK_RE.search(line):
            block_win = "\n".join(lines[idx - 1 : min(len(lines), idx + 18)])
            if _RUST_FFI_SENSITIVE_RE.search(block_win) and not _RUST_CLEANUP_RE.search(block_win):
                findings.append(
                    TrustBoundaryFinding(
                        rule_id="TB-RUST-UNSAFE-FFI",
                        severity="MEDIUM",
                        category=category,
                        file_path=str(file_path),
                        line_number=idx,
                        title=f"Rust unsafe FFI security call needs handle/error audit in {rel}:{idx}",
                        description=(
                            "An `unsafe` Rust block invokes sensitive OS/Win32 process or ACL FFI APIs without "
                            "an obvious local handle-free or error propagation guard in the immediate block."
                        ),
                        evidence=line.strip()[:200],
                        remediation="Check all Win32 return codes/NTSTATUS fail-closed and free all SIDs/handles (`FreeSid`, `LocalFree`, `CloseHandle`) via RAII drop guards.",
                    )
                )

        # 8. TLS ClientHello sniffer capping record minor version at <= 0x03 (RFC 8446 0x0304..0x03ff MITM/inspection bypass)
        if _TLS_MINOR_CAP_RE.search(code_line):
            tls_win = "\n".join(
                _strip_c_line_comment(l)
                for l in lines[max(0, idx - 4) : min(len(lines), idx + 3)]
                if not _COMMENT_RE.match(l)
            )
            if _TLS_HANDSHAKE_BYTE_RE.search(tls_win) and _TLS_MAJOR_BYTE_RE.search(tls_win):
                findings.append(
                    TrustBoundaryFinding(
                        rule_id="TB-TLS-CLIENTHELLO-VERSION-CAP",
                        severity="HIGH",
                        category=category,
                        file_path=str(file_path),
                        line_number=idx,
                        title=f"TLS ClientHello sniffer caps record minor version <= 0x03 in {rel}:{idx}",
                        description=(
                            "TLS ClientHello detection caps byte 2 (`legacy_record_version` minor byte) at `<= 0x03`. "
                            "TLS 1.3 servers accept `0x0304..0x03ff` ClientHello records (RFC 8446 §5.1), allowing a "
                            "client to evade TLS termination/inspection and fall back to an opaque passthrough tunnel."
                        ),
                        evidence=code_line.strip()[:200],
                        remediation=(
                            "Match TLS handshake records on `buf[0] === 0x16 && buf[1] === 0x03` without capping "
                            "byte 2 at `<= 0x03` (or fail closed instead of downgrading to an opaque tunnel)."
                        ),
                    )
                )

        # 9. HTTP proxy credential/header injection without unconditional TRACE/TRACK echo-method refusal
        if (
            has_proxy_forward_ctx
            and not has_echo_method_guard
            and idx - last_echo_finding_line >= 30
            and not _CRED_DECL_RE.match(code_line)
            and _CRED_INJECT_CALL_RE.search(code_line)
        ):
            last_echo_finding_line = idx
            findings.append(
                TrustBoundaryFinding(
                    rule_id="TB-HTTP-ECHO-METHOD-GATED",
                    severity="HIGH",
                    category=category,
                    file_path=str(file_path),
                    line_number=idx,
                    title=f"Proxy credential injection lacks unconditional TRACE/TRACK refusal in {rel}:{idx}",
                    description=(
                        "HTTP/TLS request forwarder invokes credential or header mutation hooks without "
                        "unconditionally rejecting echo methods (`TRACE`/`TRACK`) in the forwarding pipeline. "
                        "When optional per-request filtering is omitted, `TRACE`/`TRACK` can echo injected secrets back."
                    ),
                    evidence=code_line.strip()[:200],
                    remediation=(
                        "Unconditionally refuse `TRACE` and `TRACK` (405 Method Not Allowed) in the forwarding "
                        "path BEFORE credential substitution or signing, independent of optional filter hooks."
                    ),
                )
            )

        # 10. Win32 CreateFileW/A with FILE_FLAG_BACKUP_SEMANTICS lacking FILE_FLAG_OPEN_REPARSE_POINT
        if ext in (".rs", ".c", ".cc", ".cpp", ".h"):
            m_cf = _WIN_CREATEFILE_RE.search(code_line)
            if m_cf:
                call_expr = _extract_balanced_call(lines, idx, m_cf.start(), max_lines=16)
                prev_exec = "\n".join(
                    _strip_c_line_comment(l)
                    for l in lines[max(0, idx - 9) : idx - 1]
                    if not _COMMENT_RE.match(l)
                )
                has_backup = "FILE_FLAG_BACKUP_SEMANTICS" in call_expr or (
                    "FILE_FLAG_BACKUP_SEMANTICS" in prev_exec and "flags" in call_expr.lower()
                )
                has_open_reparse = (
                    "FILE_FLAG_OPEN_REPARSE_POINT" in call_expr
                    or "FILE_FLAG_OPEN_REPARSE_POINT" in prev_exec
                )
                if has_backup and not has_open_reparse:
                    findings.append(
                        TrustBoundaryFinding(
                            rule_id="TB-WIN-REPARSE-NO-FLAG",
                            severity="HIGH",
                            category=category,
                            file_path=str(file_path),
                            line_number=idx,
                            title=f"CreateFile with BACKUP_SEMANTICS omits FILE_FLAG_OPEN_REPARSE_POINT in {rel}:{idx}",
                            description=(
                                "Win32 `CreateFileW/A` opens a directory/metadata handle using `FILE_FLAG_BACKUP_SEMANTICS` "
                                "without `FILE_FLAG_OPEN_REPARSE_POINT`, transparently following unprivileged NTFS junctions "
                                "or mount points across sandbox boundaries."
                            ),
                            evidence=re.sub(r"\s+", " ", call_expr).strip()[:220],
                            remediation=(
                                "Combine `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` when inspecting "
                                "untrusted paths, check `FILE_ATTRIBUTE_REPARSE_POINT`, and reject unexpected junctions."
                            ),
                        )
                    )

        # 11. Linux bwrap launching shell -c before seccomp without clearing shell startup env vars
        if (
            has_bwrap_seccomp_ctx
            and not has_bwrap_shell_env_guard
            and not emitted_bwrap_preseccomp
            and _BWRAP_SHELL_C_RE.search(code_line)
        ):
            emitted_bwrap_preseccomp = True
            findings.append(
                TrustBoundaryFinding(
                    rule_id="TB-LINUX-BWRAP-PRESECCOMP-SHELL",
                    severity="HIGH",
                    category=category,
                    file_path=str(file_path),
                    line_number=idx,
                    title=f"Linux bwrap runs shell -c pre-seccomp without clearing BASH_ENV/ZDOTDIR in {rel}:{idx}",
                    description=(
                        "Bubblewrap (`bwrap`) invokes a user shell with `-c` prior to applying seccomp without "
                        "passing `--clearenv` or unsetting `BASH_ENV` and `ZDOTDIR`. Non-interactive `zsh` loads "
                        "`~/.zshenv` and `bash` executes `$BASH_ENV` before the seccomp BPF filter is installed."
                    ),
                    evidence=code_line.strip()[:200],
                    remediation=(
                        "Pass `--unsetenv BASH_ENV --unsetenv ZDOTDIR --unsetenv ENV` (or `--clearenv`), use "
                        "`zsh -f` / `bash --norc --noprofile`, or exec `apply-seccomp` directly before spawning a shell."
                    ),
                )
            )

        # 12. POSIX ERE bracket-expression metacharacter escaping inside [...]
        if _is_posix_ere_bracket_escape(code_line):
            findings.append(
                TrustBoundaryFinding(
                    rule_id="TB-POSIX-ERE-BRACKET-ESCAPE",
                    severity="HIGH",
                    category=category,
                    file_path=str(file_path),
                    line_number=idx,
                    title=f"Backslash-escaping regex metacharacters inside `[...]` bracket expression in {rel}:{idx}",
                    description=(
                        "Glob-to-regex translation inserts backslashes (`\\$&`) before regex metacharacters inside "
                        "a `[...]` character class. Under POSIX ERE (`regcomp` / macOS Seatbelt), `\\` is literal inside "
                        "bracket expressions, corrupting character classes and weakening path deny/allow rules."
                    ),
                    evidence=code_line.strip()[:200],
                    remediation=(
                        "Do not backslash-escape metacharacters inside POSIX ERE `[...]` sets; position `]` first, "
                        "`-` last, and avoid placing `^` first unless negating."
                    ),
                )
            )

        # 13. Synthetic `new URL('http://' + host).hostname` canonicalizer without component validation / single-dot strip
        if _SYNTHETIC_URL_HOST_RE.search(code_line):
            fn_lines: List[str] = []
            for ln in lines[max(0, idx - 6) : min(len(lines), idx + 12)]:
                if _COMMENT_RE.match(ln):
                    continue
                fn_lines.append(
                    _strip_c_line_comment(ln)
                    if ext in (".ts", ".tsx", ".js", ".mjs", ".cjs")
                    else ln
                )
            fn_exec = "\n".join(fn_lines)
            if _URL_HOST_ACCESS_RE.search(fn_exec):
                missing_components = not (
                    _URL_USERINFO_CHECK_RE.search(fn_exec) and _URL_STRUCT_CHECK_RE.search(fn_exec)
                )
                single_dot_strip = bool(_SINGLE_TRAILING_DOT_RE.search(fn_exec))
                if missing_components or single_dot_strip:
                    reasons: List[str] = []
                    if missing_components:
                        reasons.append("omits username/password/port/pathname/search/hash emptiness checks")
                    if single_dot_strip:
                        reasons.append("strips only a single trailing dot (`/.$/`) instead of rejecting/normalizing multiple dots")
                    findings.append(
                        TrustBoundaryFinding(
                            rule_id="TB-URL-CANONICALIZE-STRIP",
                            severity="MEDIUM",
                            category=category,
                            file_path=str(file_path),
                            line_number=idx,
                            title=f"URL-based host canonicalizer silently strips URL parts in {rel}:{idx}",
                            description=(
                                f"Host canonicalizer builds a synthetic URL to read `.hostname` but "
                                f"{' and '.join(reasons)}, allowing authority confusion (`user@host`, `host/path`, `host..`)."
                            ),
                            evidence=code_line.strip()[:200],
                            remediation=(
                                "Reject any synthetic URL whose `username`, `password`, `port`, `search`, or `hash` "
                                "is non-empty or whose `pathname !== '/'`, and normalize/reject multiple trailing dots."
                            ),
                        )
                    )

    return findings


def run_trust_boundary_review(
    repo_path: Union[str, Path],
    *,
    max_files: int = DEFAULT_MAX_TRUST_FILES,
    max_workers: Optional[int] = None,
    db: Any = None,
    task_id: str = "default",
) -> Dict[str, Any]:
    """Runs Pillar 2: parallel line-by-line targeted trust-boundary review + CallGraphSlicer."""
    t0 = time.perf_counter()
    root = Path(repo_path).resolve(strict=False)
    ranked = discover_trust_boundary_files(root, max_files=max_files)

    all_findings: List[TrustBoundaryFinding] = []
    if ranked:
        workers = max(1, min(int(max_workers or min(8, (os.cpu_count() or 4) * 2)), len(ranked)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_audit_single_trust_file, fp, cat, root) for fp, cat, _ in ranked]
            for fut in concurrent.futures.as_completed(futs):
                all_findings.extend(fut.result())

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: (sev_rank.get(f.severity, 9), f.file_path.lower(), f.line_number))

    # Pair with whole-repo CallGraphSlicer for multi-file source->sink visibility
    slicer_summary: Dict[str, Any] = {}
    try:
        cg_report = slice_repository(root, max_slices=20)
        cg_dict = cg_report.to_dict() if hasattr(cg_report, "to_dict") else dict(cg_report)
        slicer_summary = {
            "status": cg_dict.get("status", "completed"),
            "total_slices": cg_dict.get("total_slices", 0),
            "cross_file_slices_count": cg_dict.get("cross_file_slices_count", 0),
        }
    except Exception as exc:
        slicer_summary = {"status": "error", "error": str(exc)}

    if db is not None and hasattr(db, "add_fact"):
        for idx, f in enumerate(all_findings[:30]):
            try:
                db.add_fact(
                    f"[{f.severity}] {f.title}",
                    node_id=f"fact:trust_boundary:{task_id}:{idx}",
                    task_id=task_id,
                    domain="trust_boundary",
                    source_agent="deep_repo_audit",
                    payload=f.to_dict(),
                )
            except Exception:
                pass

    return {
        "status": "completed",
        "files_reviewed": len(ranked),
        "top_trust_boundary_files": [
            {
                "file": fp.relative_to(root).as_posix() if fp.is_relative_to(root) else str(fp),
                "category": cat,
                "risk_weight": score,
            }
            for fp, cat, score in ranked
        ],
        "findings_count": len(all_findings),
        "findings": [f.to_dict() for f in all_findings],
        "call_graph_slicer": slicer_summary,
        "elapsed_sec": round(time.perf_counter() - t0, 3),
    }


def _send_raw_loopback_probe(host: str, port: int, probe: bytes, timeout: float = 2.5) -> Tuple[int, str, int]:
    """Sends a single non-destructive raw HTTP framing probe strictly to loopback."""
    if not _is_loopback_host(host):
        raise PermissionError(f"LiveLoopbackProxyFuzzer strictly forbids non-loopback host: {host!r}")
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        sock.sendall(probe)
        sock.settimeout(timeout)
        chunks: List[bytes] = []
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) >= 32768:
                    break
            except socket.timeout:
                break
        raw = b"".join(chunks)
        first_line = raw.split(b"\r\n", 1)[0].split(b"\n", 1)[0].decode("latin-1", errors="replace")
        parts = first_line.split(" ")
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        return status, first_line[:120], len(raw)
    finally:
        sock.close()


def _pick_ephemeral_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_loopback_port(host: str, port: int, timeout_sec: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def parse_proxy_target(
    proxy_spec: Optional[str],
    *,
    default_host: str = "127.0.0.1",
) -> Tuple[str, Optional[int], Optional[str], bool]:
    """
    Parses the `--proxy` flag value into `(proxy_host, proxy_port, proxy_cmd, auto_spawn)`.
    Accepted forms:
      - `None` / `""` -> `(default_host, None, None, False)`
      - `"auto"` -> `("127.0.0.1", None, None, True)`
      - `"8080"` -> `("127.0.0.1", 8080, None, False)`
      - `"127.0.0.1:8080"` / `"localhost:3128"` / `"[::1]:8080"` / `"http://127.0.0.1:8080"`
        -> validates loopback host fail-closed (`PermissionError` on non-loopback!)
      - `"node server.js"` -> validates safe command (`shell=False`) and returns proxy_cmd
    """
    raw = str(proxy_spec or "").strip()
    if not raw:
        return default_host, None, None, False
    if raw.lower() == "auto":
        return "127.0.0.1", None, None, True
    if raw.isdigit():
        port_i = int(raw)
        if not (1 <= port_i <= 65535):
            raise ValueError(f"Invalid --proxy port: {raw!r}")
        return "127.0.0.1", port_i, None, False

    # URL or host:port form (no spaces)
    if " " not in raw and ("\t" not in raw):
        if "://" in raw:
            parsed = urlparse(raw)
            host = (parsed.hostname or "").strip()
            port = parsed.port
            if not host or port is None:
                raise ValueError(f"--proxy URL must include loopback host and port: {raw!r}")
            if not _is_loopback_host(host):
                raise PermissionError(f"--proxy strictly forbids non-loopback host: {host!r}")
            return host, int(port), None, False

        m_v6 = re.match(r"^\[([^\]]+)\]:(\d{1,5})$", raw)
        if m_v6:
            host, port_i = m_v6.group(1), int(m_v6.group(2))
            if not _is_loopback_host(host):
                raise PermissionError(f"--proxy strictly forbids non-loopback host: {host!r}")
            if not (1 <= port_i <= 65535):
                raise ValueError(f"Invalid --proxy port: {port_i}")
            return host, port_i, None, False

        if ":" in raw and raw.count(":") == 1:
            host_part, port_part = raw.split(":", 1)
            if port_part.isdigit():
                port_i = int(port_part)
                if not _is_loopback_host(host_part):
                    raise PermissionError(f"--proxy strictly forbids non-loopback host: {host_part!r}")
                if not (1 <= port_i <= 65535):
                    raise ValueError(f"Invalid --proxy port: {port_i}")
                return host_part, port_i, None, False

    # Otherwise treat as a safe local proxy launch command
    _validate_safe_proxy_cmd(raw)
    return "127.0.0.1", None, raw, False


def _find_node_proxy_entrypoint(root: Path) -> Optional[Path]:
    for rel in (
        Path("dist") / "sandbox" / "http-proxy.js",
        Path("dist") / "http-proxy.js",
    ):
        cand = root / rel
        if cand.is_file():
            return cand
    return None


def _run_auto_node_proxy_harness(
    root: Path,
    entrypoint: Path,
    *,
    timeout_sec: float = 25.0,
) -> Optional[Dict[str, Any]]:
    """
    Spins up a compiled Node `createHttpProxyServer` module strictly on `127.0.0.1:0`
    in an isolated stdin ESM process (zero writes inside `root`) and runs 3-trial RFC 9112
    smuggling & allowlist-bypass probes against it.
    """
    node_exe = shutil.which("node")
    if not node_exe:
        return None
    dist_dir_posix = entrypoint.parent.resolve(strict=False).as_posix()
    entry_posix = entrypoint.resolve(strict=False).as_posix()
    script = f"""
import http from 'node:http';
import net from 'node:net';
import {{ pathToFileURL }} from 'node:url';

const entryMod = await import(pathToFileURL({entry_posix!r}).href);
if (typeof entryMod.createHttpProxyServer !== 'function') {{
  console.log(JSON.stringify({{ status: 'unsupported_entrypoint' }}));
  process.exit(0);
}}
let canonicalizeHost = (h) => String(h || '').toLowerCase().replace(/\\.$/, '');
let matchDomain = (h, _p, pat) => h === pat;
try {{
  const pp = await import(pathToFileURL({(dist_dir_posix + '/parent-proxy.js')!r}).href);
  if (typeof pp.canonicalizeHost === 'function') canonicalizeHost = pp.canonicalizeHost;
}} catch {{}}
try {{
  const dp = await import(pathToFileURL({(dist_dir_posix + '/domain-pattern.js')!r}).href);
  if (typeof dp.matchesDomainPatternWithPort === 'function') matchDomain = dp.matchesDomainPatternWithPort;
}} catch {{}}

const upstreamHits = [];
const upstream = http.createServer((req, res) => {{
  upstreamHits.push({{ method: req.method, url: req.url, host: req.headers.host || '' }});
  res.writeHead(200, {{ 'Content-Type': 'text/plain', 'Connection': 'close' }});
  res.end('ok');
}});
await new Promise(r => upstream.listen(0, '127.0.0.1', r));
const upPort = upstream.address().port;

const proxy = entryMod.createHttpProxyServer({{
  requireHostMatch: true,
  filter: (port, host) => {{
    const h = canonicalizeHost(host);
    return !!h && matchDomain(h, port, 'allowed.local') && port === upPort;
  }},
  lookupFor: () => (_h, o, cb) =>
    typeof o === 'function'
      ? o(null, '127.0.0.1', 4)
      : cb(null, o && o.all ? [{{ address: '127.0.0.1', family: 4 }}] : '127.0.0.1', 4),
}});
await new Promise(r => proxy.listen(0, '127.0.0.1', r));
const pPort = proxy.address().port;

function sendRaw(raw) {{
  return new Promise(resolve => {{
    const s = net.createConnection({{ host: '127.0.0.1', port: pPort }});
    const chunks = [];
    let settled = false;
    const finish = () => {{
      if (settled) return;
      settled = true;
      s.destroy();
      const txt = Buffer.concat(chunks).toString('latin1');
      const fl = (txt.split('\\r\\n')[0] || txt.split('\\n')[0] || '').slice(0, 120);
      const m = /^HTTP\\/\\d\\.\\d\\s+(\\d{{3}})/.exec(fl);
      resolve({{ status: m ? Number(m[1]) : 0, firstLine: fl }});
    }};
    s.setTimeout(1500, finish);
    s.on('error', finish);
    s.on('end', finish);
    s.on('data', d => chunks.push(d));
    s.on('connect', () => s.write(Buffer.from(raw, 'latin1')));
  }});
}}

const probes = [
  {{ id: 'PROXY-CL-TE-001', desc: 'Conflicting Content-Length and Transfer-Encoding', expectDeny: true, raw: `POST http://allowed.local:${{upPort}}/p HTTP/1.1\\r\\nHost: allowed.local:${{upPort}}\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\nConnection: close\\r\\n\\r\\n0\\r\\n\\r\\nX` }},
  {{ id: 'PROXY-TE-OBF-002', desc: 'Obfuscated Transfer-Encoding with Content-Length', expectDeny: true, raw: `POST http://allowed.local:${{upPort}}/p HTTP/1.1\\r\\nHost: allowed.local:${{upPort}}\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: xchunked\\r\\nConnection: close\\r\\n\\r\\n1234` }},
  {{ id: 'PROXY-CL-CL-003', desc: 'Duplicate conflicting Content-Length headers', expectDeny: true, raw: `POST http://allowed.local:${{upPort}}/p HTTP/1.1\\r\\nHost: allowed.local:${{upPort}}\\r\\nContent-Length: 5\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\nhello` }},
  {{ id: 'PROXY-BARE-LF-004', desc: 'Bare LF delimiter without CR', expectDeny: true, raw: `GET http://allowed.local:${{upPort}}/lf HTTP/1.1\\nHost: allowed.local:${{upPort}}\\nConnection: close\\n\\n` }},
  {{ id: 'PROXY-OBS-FOLD-005', desc: 'Deprecated obs-fold multi-line Host header', expectDeny: true, raw: `GET http://allowed.local:${{upPort}}/fold HTTP/1.1\\r\\nHost: allowed.local:${{upPort}}\\r\\n blocked.local\\r\\nConnection: close\\r\\n\\r\\n` }},
  {{ id: 'PROXY-DOUBLE-HOST-006', desc: 'Duplicate mismatched Host headers', expectDeny: true, raw: `GET http://allowed.local:${{upPort}}/dh HTTP/1.1\\r\\nHost: allowed.local:${{upPort}}\\r\\nHost: blocked.local:${{upPort}}\\r\\nConnection: close\\r\\n\\r\\n` }},
  {{ id: 'PROXY-URI-HOST-007', desc: 'Absolute-URI vs mismatched Host header', expectDeny: true, raw: `GET http://allowed.local:${{upPort}}/m HTTP/1.1\\r\\nHost: blocked.local:${{upPort}}\\r\\nConnection: close\\r\\n\\r\\n` }},
  {{ id: 'PROXY-USERINFO-008', desc: 'Userinfo @ authority confusion', expectDeny: true, raw: `GET http://allowed.local@blocked.local:${{upPort}}/at HTTP/1.1\\r\\nHost: allowed.local:${{upPort}}\\r\\nConnection: close\\r\\n\\r\\n` }},
  {{ id: 'PROXY-CONNECT-BLOCKED-009', desc: 'CONNECT blocked host with allowed Host header', expectDeny: true, raw: `CONNECT blocked.local:${{upPort}} HTTP/1.1\\r\\nHost: allowed.local:${{upPort}}\\r\\nConnection: close\\r\\n\\r\\n` }},
  {{ id: 'PROXY-CONNECT-V4MAPPED-010', desc: 'CONNECT IPv4-mapped IPv6 loopback literal', expectDeny: true, raw: `CONNECT [::ffff:127.0.0.1]:${{upPort}} HTTP/1.1\\r\\nHost: [::ffff:127.0.0.1]:${{upPort}}\\r\\nConnection: close\\r\\n\\r\\n` }},
];

const results = [];
for (const p of probes) {{
  const before = upstreamHits.length;
  const statuses = [];
  let firstLine = '';
  for (let i = 0; i < 3; i++) {{
    const r = await sendRaw(p.raw);
    statuses.push(r.status);
    if (i === 0) firstLine = r.firstLine;
  }}
  const hits = upstreamHits.length - before;
  results.push({{
    rule_id: p.id,
    description: p.desc,
    trial_statuses: statuses,
    first_line: firstLine,
    upstream_hits: hits,
    raw_probe: p.raw,
    bypass: p.expectDeny && (hits > 0 || statuses.some(st => st >= 200 && st < 400)),
  }});
}}

proxy.close();
upstream.close();
console.log(JSON.stringify({{ status: 'completed', target: `127.0.0.1:${{pPort}}`, results }}));
process.exit(0);
"""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    proc = subprocess.run(
        [node_exe, "--input-type=module", "-"],
        input=script,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_sec,
        shell=False,
        creationflags=creationflags,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        return None


def run_live_proxy_fuzz(
    repo_path: Union[str, Path],
    *,
    proxy_target: Optional[str] = None,
    proxy_host: str = "127.0.0.1",
    proxy_port: Optional[int] = None,
    proxy_cmd: Optional[str] = None,
    auto_spawn_repo_proxy: bool = False,
    run_docker_matrix: bool = False,
    approval_mode: str = "policy",
    db: Any = None,
    task_id: str = "default",
) -> Dict[str, Any]:
    """
    Runs Pillar 1: Live loopback-only proxy fuzzing + 3-trial RFC 9112 differential verification.
    Strictly enforces `127.0.0.1`/loopback-only and guaranteed subprocess teardown in `finally`.
    """
    t0 = time.perf_counter()
    if proxy_target:
        p_host, p_port, p_cmd, p_auto = parse_proxy_target(proxy_target, default_host=proxy_host)
        proxy_host = p_host
        if p_port is not None and proxy_port is None:
            proxy_port = p_port
        if p_cmd and not proxy_cmd:
            proxy_cmd = p_cmd
        if p_auto:
            auto_spawn_repo_proxy = True

    if not _is_loopback_host(proxy_host):
        raise PermissionError(f"Live loopback proxy fuzzing strictly requires a loopback host, got: {proxy_host!r}")

    if str(approval_mode or "policy").strip().lower() == "deny":
        return {
            "status": "skipped_approval_deny",
            "probes_sent": 0,
            "confirmed_divergences": [],
            "elapsed_sec": round(time.perf_counter() - t0, 3),
        }

    root = Path(repo_path).resolve(strict=False)
    discovered_proxies = [
        fp.relative_to(root).as_posix()
        for fp, cat, _ in discover_trust_boundary_files(root, max_files=25)
        if cat == "http_proxy_parser"
    ][:10]

    spawned_proc: Optional[subprocess.Popen] = None
    active_port = int(proxy_port) if proxy_port else None

    try:
        # Auto-spawn compiled Node repo proxy (e.g., dist/sandbox/http-proxy.js) on 127.0.0.1:0 when `--proxy` is used
        if auto_spawn_repo_proxy and not active_port and not proxy_cmd:
            node_entry = _find_node_proxy_entrypoint(root)
            if node_entry is not None:
                auto_res = _run_auto_node_proxy_harness(root, node_entry)
                if auto_res and auto_res.get("status") == "completed":
                    oracle = MultiImplementationDifferentialOracle()
                    probe_rows = auto_res.get("results") or []
                    confirmed: List[Dict[str, Any]] = []
                    for row in probe_rows:
                        raw_b = str(row.get("raw_probe") or "").encode("latin-1", errors="replace")
                        diff_res = oracle.evaluate_matrix_4parsers(raw_b, rule_id=row["rule_id"])
                        row["oracle_diverged"] = bool(
                            getattr(diff_res, "divergence_detected", getattr(diff_res, "is_divergent", False))
                        )
                        if row.get("bypass"):
                            finding = {
                                "rule_id": row["rule_id"],
                                "title": f"Auto-Spawned Repo Proxy Bypass/Acceptance: {row['description']}",
                                "severity": "HIGH",
                                "file_path": str(node_entry),
                                "line_number": None,
                                "rfc_num": 9112,
                                "verification_attempts": LIVE_PROBE_TRIALS,
                                "reproducibility_rate": 1.0,
                                "raw_probe": row.get("raw_probe", ""),
                                "poe_level": 3,
                                "verified": True,
                                "scanner": "DeepRepoAudit-LiveProxyFuzz",
                            }
                            confirmed.append(finding)
                            if db is not None and hasattr(db, "add_fact"):
                                try:
                                    db.add_fact(
                                        f"[POE=3] {finding['title']} ({row['trial_statuses']})",
                                        node_id=f"fact:live_proxy:{task_id}:{row['rule_id']}",
                                        task_id=task_id,
                                        domain="protocol_proxy",
                                        source_agent="deep_repo_audit",
                                        payload=row,
                                    )
                                except Exception:
                                    pass
                    docker_matrix_summary = None
                    if run_docker_matrix:
                        try:
                            docker_matrix_summary = oracle.run_docker_parser_matrix(fallback_to_4parsers=True)
                        except Exception as exc:
                            docker_matrix_summary = {"status": "error", "error": str(exc)}
                    return {
                        "status": "completed",
                        "mode": "auto_spawned_node_proxy",
                        "entrypoint": node_entry.relative_to(root).as_posix(),
                        "target": auto_res.get("target", "127.0.0.1:ephemeral"),
                        "discovered_proxy_files": discovered_proxies,
                        "probes_sent": len(probe_rows) * LIVE_PROBE_TRIALS,
                        "unique_probes": len(probe_rows),
                        "probe_results": probe_rows,
                        "confirmed_divergences": confirmed,
                        "docker_parser_matrix": docker_matrix_summary,
                        "elapsed_sec": round(time.perf_counter() - t0, 3),
                    }

        if proxy_cmd and not active_port:
            argv = _validate_safe_proxy_cmd(proxy_cmd)
            active_port = _pick_ephemeral_loopback_port()
            env = dict(os.environ)
            env["HOST"] = "127.0.0.1"
            env["PORT"] = str(active_port)
            env["PROXY_PORT"] = str(active_port)
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            spawned_proc = subprocess.Popen(
                argv,
                cwd=str(root),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=creationflags,
            )
            if not _wait_for_loopback_port("127.0.0.1", active_port, timeout_sec=8.0):
                return {
                    "status": "proxy_start_timeout",
                    "discovered_proxy_files": discovered_proxies,
                    "probes_sent": 0,
                    "confirmed_divergences": [],
                    "elapsed_sec": round(time.perf_counter() - t0, 3),
                }

        if not active_port:
            return {
                "status": "skipped_no_live_proxy",
                "reason": (
                    "No live loopback proxy port or --proxy-cmd supplied. Pass `--proxy-port <port>` "
                    "for a running 127.0.0.1 proxy or `--proxy-cmd \"...\"` to spawn one automatically."
                ),
                "discovered_proxy_files": discovered_proxies,
                "probes_sent": 0,
                "confirmed_divergences": [],
                "elapsed_sec": round(time.perf_counter() - t0, 3),
            }

        oracle = MultiImplementationDifferentialOracle()
        probe_results: List[Dict[str, Any]] = []
        confirmed_findings: List[Dict[str, Any]] = []

        for rule_id, desc, raw_probe in _LIVE_PROXY_PROBES:
            trial_statuses: List[int] = []
            trial_lines: List[str] = []
            for _ in range(LIVE_PROBE_TRIALS):
                try:
                    st, fl, _ = _send_raw_loopback_probe(proxy_host, active_port, raw_probe)
                except OSError as exc:
                    st, fl = 0, f"socket_error:{type(exc).__name__}"
                trial_statuses.append(st)
                trial_lines.append(fl)

            # A strict RFC 9112 proxy MUST reject malformed/ambiguous probes with 4xx (400/403/405/411/431/501)
            permissive_trials = [s for s in trial_statuses if 200 <= s < 400]
            crash_trials = [s for s in trial_statuses if s >= 500]
            repro_rate = max(len(permissive_trials), len(crash_trials)) / float(LIVE_PROBE_TRIALS)
            reproduced = repro_rate >= 0.66

            # Independent 4-parser differential matrix cross-check
            diff_res = oracle.evaluate_matrix_4parsers(raw_probe, rule_id=rule_id)
            entry = {
                "rule_id": rule_id,
                "description": desc,
                "target": f"{proxy_host}:{active_port}",
                "trial_statuses": trial_statuses,
                "first_line": trial_lines[0] if trial_lines else "",
                "reproducibility_rate": round(repro_rate, 3),
                "verification_attempts": LIVE_PROBE_TRIALS,
                "reproduced_permissive_or_5xx": reproduced,
                "oracle_diverged": bool(getattr(diff_res, "divergence_detected", getattr(diff_res, "is_divergent", False))),
            }
            probe_results.append(entry)

            if reproduced:
                finding = {
                    "rule_id": rule_id,
                    "title": f"Live Loopback Proxy Accepted/Crashed on Ambiguous RFC Probe: {desc}",
                    "severity": "HIGH" if permissive_trials else "MEDIUM",
                    "file_path": f"{proxy_host}:{active_port}",
                    "line_number": None,
                    "rfc_num": 9112,
                    "verification_attempts": LIVE_PROBE_TRIALS,
                    "reproducibility_rate": round(repro_rate, 3),
                    "raw_probe": raw_probe.decode("latin-1", errors="replace"),
                    "poe_level": 3,
                    "verified": True,
                    "description": (
                        f"3-trial live loopback fuzzing against {proxy_host}:{active_port} observed "
                        f"non-rejecting statuses {trial_statuses} on malformed probe `{rule_id}`."
                    ),
                    "scanner": "DeepRepoAudit-LiveProxyFuzz",
                }
                confirmed_findings.append(finding)
                if db is not None and hasattr(db, "add_fact"):
                    try:
                        db.add_fact(
                            f"[POE=3] {finding['title']} ({trial_statuses})",
                            node_id=f"fact:live_proxy:{task_id}:{rule_id}",
                            task_id=task_id,
                            domain="protocol_proxy",
                            source_agent="deep_repo_audit",
                            payload=entry,
                        )
                    except Exception:
                        pass

        docker_matrix_summary: Optional[Dict[str, Any]] = None
        if run_docker_matrix:
            try:
                docker_matrix_summary = oracle.run_docker_parser_matrix(fallback_to_4parsers=True)
            except Exception as exc:
                docker_matrix_summary = {"status": "error", "error": str(exc)}

        return {
            "status": "completed",
            "target": f"{proxy_host}:{active_port}",
            "discovered_proxy_files": discovered_proxies,
            "probes_sent": len(probe_results) * LIVE_PROBE_TRIALS,
            "unique_probes": len(probe_results),
            "probe_results": probe_results,
            "confirmed_divergences": confirmed_findings,
            "docker_parser_matrix": docker_matrix_summary,
            "elapsed_sec": round(time.perf_counter() - t0, 3),
        }
    finally:
        if spawned_proc is not None:
            try:
                spawned_proc.terminate()
                spawned_proc.wait(timeout=3.0)
            except Exception:
                try:
                    spawned_proc.kill()
                    spawned_proc.wait(timeout=2.0)
                except Exception:
                    pass


def discover_nested_fuzz_crates(repo_path: Union[str, Path]) -> List[Path]:
    """Finds first-party nested Rust/C/C++ crates (e.g., `vendor/srt-win-src/Cargo.toml`)."""
    root = Path(repo_path).resolve(strict=False)
    nested: List[Path] = []
    for sub_parent in ("vendor", "crates", "packages", "native"):
        base = root / sub_parent
        if not base.is_dir():
            continue
        try:
            for child in sorted(base.iterdir()):
                if not child.is_dir():
                    continue
                if any((child / marker).is_file() for marker in ("Cargo.toml", "CMakeLists.txt", "Makefile")):
                    nested.append(child)
        except Exception:
            continue
    return nested


def run_coverage_fuzz_orchestration(
    repo_path: Union[str, Path],
    *,
    output_dir: Union[str, Path],
    dry_run: bool = False,
    fuzz_max_time: int = 30,
    fuzz_timeout: int = 60,
    languages: Optional[Sequence[str]] = None,
    approval_mode: str = "policy",
    db: Any = None,
    task_id: str = "default",
) -> Dict[str, Any]:
    """
    Runs Pillar 3: Coverage-guided fuzzing (`LLMFuzzBridge`) on the repo root AND any
    nested first-party crates (such as `vendor/srt-win-src` Rust crates), writing all
    generated harnesses/corpora strictly under `output_dir`.
    """
    t0 = time.perf_counter()
    root = Path(repo_path).resolve(strict=False)
    out_root = Path(output_dir).resolve(strict=False) / "fuzz_bridge"
    out_root.mkdir(parents=True, exist_ok=True)

    is_guarded = (
        str(approval_mode or "policy").strip().lower() == "deny"
        or bool(os.environ.get("PYTEST_CURRENT_TEST"))
        or bool(os.environ.get("CI"))
        or os.environ.get("RFCHUNT_OFFLINE", "").strip() in ("1", "true", "TRUE", "yes")
    )
    effective_dry_run = bool(dry_run or is_guarded)

    targets: List[Tuple[str, Path]] = [("root", root)]
    for crate_dir in discover_nested_fuzz_crates(root):
        label = crate_dir.relative_to(root).as_posix().replace("/", "_")
        targets.append((label, crate_dir))

    target_reports: Dict[str, Any] = {}
    all_langs: List[str] = []
    all_crashes: List[Dict[str, Any]] = []
    all_plateaus: List[Dict[str, Any]] = []
    total_artifacts = 0

    for label, target_dir in targets:
        sub_out = out_root / label
        sub_out.mkdir(parents=True, exist_ok=True)
        try:
            rep = run_fuzz_bridge_scan(
                repo_path=target_dir,
                output_dir=sub_out,
                db=db,
                task_id=f"{task_id}:{label}",
                languages=list(languages) if languages else None,
                timeout_sec=float(fuzz_timeout),
                max_total_time_sec=int(fuzz_max_time),
                execute_containers=not effective_dry_run,
            )
            rep_dict = rep.to_dict() if hasattr(rep, "to_dict") else dict(rep)
        except Exception as exc:
            rep_dict = {"status": "error", "error": str(exc)}

        target_reports[label] = rep_dict
        for lg in rep_dict.get("detected_languages") or []:
            if lg not in all_langs:
                all_langs.append(lg)
        for cr in rep_dict.get("crashes") or []:
            if isinstance(cr, dict):
                all_crashes.append(cr)
        for pl in rep_dict.get("plateaus") or []:
            if isinstance(pl, dict):
                all_plateaus.append(pl)
        total_artifacts += len(rep_dict.get("generated_files") or [])

    return {
        "status": "dry_run" if effective_dry_run else "completed",
        "dry_run": effective_dry_run,
        "targets_scanned": [label for label, _ in targets],
        "detected_languages": all_langs,
        "crashes_count": len(all_crashes),
        "plateaus_count": len(all_plateaus),
        "generated_artifacts_count": total_artifacts,
        "output_dir": str(out_root),
        "crashes": all_crashes,
        "targets": target_reports,
        "elapsed_sec": round(time.perf_counter() - t0, 3),
    }


def _render_deep_audit_markdown(report: DeepRepoAuditReport) -> str:
    lp = report.live_proxy_fuzz
    tb = report.trust_boundary_review
    cf = report.coverage_fuzz
    lines = [
        "# RFCHunt `--deep-audit` Repository Security Report",
        "",
        f"- **Repository**: `{report.repo_path}` (read-only; zero target mutations)",
        f"- **Output Directory**: `{report.output_dir}`",
        f"- **Total Findings**: `{len(report.findings)}`",
        f"- **Elapsed**: `{report.elapsed_sec:.3f}s`",
        "",
        "## 1. Live Loopback Proxy Fuzzing (`--live-proxy-fuzz`)",
        f"- **Status**: `{lp.get('status', 'disabled')}`",
        f"- **Target**: `{lp.get('target', 'none')}` | **Probes Sent**: `{lp.get('probes_sent', 0)}`",
        f"- **Confirmed 3-Trial Divergences**: `{len(lp.get('confirmed_divergences') or [])}`",
        f"- **Discovered Proxy Files**: {', '.join(f'`{f}`' for f in (lp.get('discovered_proxy_files') or [])) or 'none'}",
        "",
        "## 2. Line-by-Line Trust-Boundary Review (`--trust-boundary-review`)",
        f"- **Status**: `{tb.get('status', 'disabled')}`",
        f"- **Trust-Boundary Files Reviewed**: `{tb.get('files_reviewed', 0)}`",
        f"- **Findings**: `{tb.get('findings_count', 0)}`",
        f"- **Call-Graph Slicer**: `{tb.get('call_graph_slicer', {})}`",
        "",
        "## 3. Coverage-Guided Fuzzing (`--coverage-fuzz`)",
        f"- **Status**: `{cf.get('status', 'disabled')}` (`dry_run={cf.get('dry_run', True)}`)",
        f"- **Targets**: {', '.join(f'`{t}`' for t in (cf.get('targets_scanned') or [])) or 'none'}",
        f"- **Detected Languages**: {', '.join(f'`{l}`' for l in (cf.get('detected_languages') or [])) or 'none'}",
        f"- **Sanitizer Crashes**: `{cf.get('crashes_count', 0)}` | **Coverage Plateaus**: `{cf.get('plateaus_count', 0)}`",
        f"- **Harnesses/Corpora Written**: `{cf.get('generated_artifacts_count', 0)}` under `{cf.get('output_dir', '')}`",
        "",
    ]

    if report.findings:
        lines.append("## Findings Summary")
        lines.append("")
        lines.append("| Severity | Rule | Location | Title |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for f in report.findings[:60]:
            loc = f"{f.get('file_path', '')}:{f.get('line_number')}" if f.get("line_number") else str(f.get("file_path", ""))
            loc_s = loc[-58:] if len(loc) > 58 else loc
            title_s = str(f.get("title", "")).replace("|", "/")[:110]
            lines.append(f"| `{f.get('severity', 'INFO')}` | `{f.get('rule_id', '')}` | `{loc_s}` | {title_s} |")
        lines.append("")
    return "\n".join(lines)


def run_deep_repo_audit(
    repo_path: Union[str, Path],
    *,
    output_dir: Union[str, Path] = "reports",
    enable_live_proxy_fuzz: bool = True,
    enable_trust_boundary_review: bool = True,
    enable_coverage_fuzz: bool = True,
    proxy_target: Optional[str] = None,
    proxy_host: str = "127.0.0.1",
    proxy_port: Optional[int] = None,
    proxy_cmd: Optional[str] = None,
    run_docker_matrix: bool = False,
    max_trust_files: int = DEFAULT_MAX_TRUST_FILES,
    fuzz_dry_run: bool = False,
    fuzz_max_time: int = 30,
    fuzz_timeout: int = 60,
    fuzz_languages: Optional[Sequence[str]] = None,
    approval_mode: str = "policy",
    db: Any = None,
    task_id: str = "default",
) -> DeepRepoAuditReport:
    """Executes the unified `--deep-audit` 3-pillar real-bug discovery pipeline on `repo_path`."""
    t0 = time.perf_counter()
    root = Path(repo_path).resolve(strict=False)
    out_dir = Path(output_dir).resolve(strict=False) / "deep_audit"
    out_dir.mkdir(parents=True, exist_ok=True)

    live_res: Dict[str, Any] = {"status": "disabled"}
    tb_res: Dict[str, Any] = {"status": "disabled"}
    cov_res: Dict[str, Any] = {"status": "disabled"}
    aggregated: List[Dict[str, Any]] = []

    if enable_trust_boundary_review:
        tb_res = run_trust_boundary_review(
            root,
            max_files=max_trust_files,
            db=db,
            task_id=task_id,
        )
        aggregated.extend(tb_res.get("findings") or [])

    if enable_live_proxy_fuzz:
        live_res = run_live_proxy_fuzz(
            root,
            proxy_target=proxy_target,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            proxy_cmd=proxy_cmd,
            run_docker_matrix=run_docker_matrix,
            approval_mode=approval_mode,
            db=db,
            task_id=task_id,
        )
        aggregated.extend(live_res.get("confirmed_divergences") or [])

    if enable_coverage_fuzz:
        cov_res = run_coverage_fuzz_orchestration(
            root,
            output_dir=out_dir,
            dry_run=fuzz_dry_run,
            fuzz_max_time=fuzz_max_time,
            fuzz_timeout=fuzz_timeout,
            languages=fuzz_languages,
            approval_mode=approval_mode,
            db=db,
            task_id=task_id,
        )
        for cr in cov_res.get("crashes") or []:
            aggregated.append(
                {
                    "rule_id": cr.get("rule_id") or "FUZZ-SANITIZER-CRASH",
                    "severity": "CRITICAL",
                    "title": cr.get("summary") or "Coverage-guided fuzzer sanitizer crash",
                    "file_path": cr.get("file_path") or cr.get("target") or str(root),
                    "line_number": cr.get("line_number"),
                    "poe_level": 3,
                    "verified": True,
                    "scanner": "DeepRepoAudit-CoverageFuzz",
                }
            )

    report = DeepRepoAuditReport(
        repo_path=str(root),
        output_dir=str(out_dir),
        live_proxy_fuzz=live_res,
        trust_boundary_review=tb_res,
        coverage_fuzz=cov_res,
        findings=aggregated,
        elapsed_sec=time.perf_counter() - t0,
    )

    md_path = out_dir / "DEEP_AUDIT_REPORT.md"
    json_path = out_dir / "deep_audit_summary.json"
    report.report_markdown_path = str(md_path)
    report.summary_json_path = str(json_path)
    md_path.write_text(_render_deep_audit_markdown(report), encoding="utf-8")
    json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return report
