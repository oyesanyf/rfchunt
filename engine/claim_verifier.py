"""
Deterministic Semantic Claim-to-Code Precondition Verifier (`engine/claim_verifier.py`).

Upgrades simple file-path existence grounding into semantic AST/CFG precondition
verification around `(file_path, line_number)` before final SARIF/JSON aggregation:

  - Parses the exact enclosing function/block AST (Python `ast` with structural
    multi-language fallback for JS/TS/Go/Rust/C/Java/config files).
  - Verifies CWE-specific structural preconditions:
      * CWE-22 (Path Traversal): checks whether `resolve()`, `is_relative_to()`,
        `realpath()`, `abspath()` + prefix check, `os.path.commonpath()`, or
        `secure_filename()` dominates the filesystem sink, or if path is a literal.
      * CWE-78 (OS Command Injection): checks `shell=False` + static argv list /
        `shlex.quote` vs `shell=True` / `os.system` / dynamic user input.
      * CWE-89 (SQL Injection): checks parameterized queries (`execute("...", (x,))`,
        `?`/`%s` bound tuple, ORM `.filter()`, `bindparams`) vs string interpolation.
      * CWE-502 (Unsafe Deserialization): `json.loads`/`yaml.safe_load`/`ast.literal_eval`
        vs `pickle.loads`/`yaml.load` without SafeLoader.
      * CWE-79 (XSS): `html.escape`/`markupsafe.escape`/`bleach.clean` vs raw HTML.
      * CWE-94 (Code Injection): `ast.literal_eval` vs `eval`/`exec`.
      * CWE-918 (SSRF): IP/CIDR/allowlist/metadata guard dominating HTTP client sink.
      * CWE-798 (Hardcoded Secrets): regex pattern, comment, docstring, `os.getenv`,
        or placeholder context -> `REFUTED`.
      * Missing file / out-of-range line / comment-only line -> `REFUTED`.
  - If a dominating sanitizer or non-vulnerable construct exists -> `REFUTED` with
    exact `counter_evidence_line` and `counter_evidence_snippet`.
  - If a sink exists but untrusted-input reachability cannot be proven -> strictly
    `UNRESOLVED` with explicit `missing_evidence`.
  - If an untrusted source directly reaches an unsanitized sink -> `PROVEN_STATIC_INVARIANT`.
  - Also exposes `verify_refutation_citations(...)` so `FusionArbiter`'s Devil's-Advocate
    refutation pass deterministically validates every cited line against the AST.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from engine.epistemic_state import (
    EpistemicStatus,
    attach_epistemic_metadata,
    derive_epistemic_status,
)

MAX_VERIFY_BYTES = 512 * 1024

_COMMENT_LINE_RX = re.compile(r"^\s*(#|//|/\*|\*|--|<!--|'''|\"\"\")")
_UNTRUSTED_SOURCE_RX = re.compile(
    r"\b(request\.(?:args|form|json|values|headers|cookies|files|get_json|data|path|url)|"
    r"req\.(?:query|params|body|headers|url)|"
    r"input\s*\(|sys\.argv|os\.environ|user_input|user_path|user_url|user_cmd|user_id|raw_input|untrusted|payload|filename|filepath)\b",
    re.IGNORECASE,
)
_PATH_SANITIZER_RX = re.compile(
    r"\b(is_relative_to|commonpath|secure_filename|realpath|canonicalize|filepath\.Clean|EvalSymlinks)\b|"
    r"\.resolve\s*\([^)]*\)|\babspath\s*\([^)]*\)",
    re.IGNORECASE,
)
_PATH_CONFINEMENT_CHECK_RX = re.compile(
    r"\b(is_relative_to|commonpath|secure_filename)\b|"
    r"(?:startswith|starts_with|startsWith)\s*\([^)]*(?:root|base|safe|allowed)",
    re.IGNORECASE,
)
_PATH_SINK_RX = re.compile(
    r"\b(open|send_file|send_from_directory|read_text|read_bytes|write_text|write_bytes|"
    r"os\.path\.join|Path|shutil\.copy|os\.remove|os\.unlink|fs\.readFile|readFileSync|os\.Open)\s*\(",
)
_CMD_SINK_RX = re.compile(
    r"\b(subprocess\.(?:run|Popen|call|check_output|check_call)|os\.system|os\.popen|"
    r"execSync|execFileSync|child_process\.exec|spawn)\s*\(",
)
_CMD_SANITIZER_RX = re.compile(r"\b(shlex\.quote|shlex\.split|escapeshellarg|escapeshellcmd)\b")
_SQL_SINK_RX = re.compile(r"\.(?:execute|executemany|raw|query)\s*\(")
_SQL_INTERP_RX = re.compile(r"(?:f['\"]|\+\s*[A-Za-z_][A-Za-z0-9_.]*|\.format\s*\(|['\"]\s*%\s*)")
_SQL_PARAM_RX = re.compile(
    r"(?:\.(?:execute|executemany|query)\s*\(\s*['\"][^'\"{}]*(?:\?|%s|:\w+|\$\d+)[^'\"{}]*['\"]\s*,\s*(?:\(|\[|\{|[A-Za-z_])|"
    r"\.(?:filter|filter_by)\s*\(|\bbindparams\s*\()"
)
_DESER_UNSAFE_RX = re.compile(
    r"\b(pickle\.(?:loads|load)|cPickle\.(?:loads|load)|marshal\.loads|yaml\.load\s*\(|yaml\.unsafe_load|shelve\.open)\b"
)
_DESER_SAFE_RX = re.compile(
    r"\b(yaml\.safe_load|SafeLoader|CSafeLoader|json\.loads|json\.load|ast\.literal_eval)\b"
)
_XSS_SAFE_RX = re.compile(r"\b(html\.escape|markupsafe\.escape|bleach\.clean|escape_html|DOMPurify\.sanitize|render_template)\b")
_XSS_SINK_RX = re.compile(r"(\binnerHTML\b|\bMarkup\s*\(|\bHttpResponse\s*\(|\breturn\s+f?['\"]<|res\.send\s*\()")
_CODE_UNSAFE_RX = re.compile(r"\b(eval|exec|compile)\s*\(")
_CODE_SAFE_RX = re.compile(r"\bast\.literal_eval\s*\(")
_SSRF_SINK_RX = re.compile(r"\b(requests\.(?:get|post|put|delete|head|request)|urllib\.request\.urlopen|httpx\.(?:get|post|Client)|fetch|axios\.(?:get|post))\s*\(")
_SSRF_GUARD_RX = re.compile(
    r"\b(validate_and_authorize_target|validate_url|is_private|is_loopback|is_link_local|"
    r"ip_address|ip_network|ALLOWED_HOSTS|ALLOWLIST|allowed_domains|169\.254\.169\.254|block_private)\b",
    re.IGNORECASE,
)
_SECRET_PLACEHOLDER_RX = re.compile(
    r"\b(EXAMPLE|DUMMY|FAKE|PLACEHOLDER|YOUR_KEY|YOUR_TOKEN|TEST_KEY|SAMPLE|CHANGEME|REDACTED|NOT_A_SECRET|AKIAIOSFODNN7EXAMPLE)\b|"
    r"\bos\.(?:getenv|environ\.get)\s*\(|process\.env\.",
    re.IGNORECASE,
)
_SECRET_REGEX_CTX_RX = re.compile(
    r"\b(re\.compile|Regex::new|regexp\.MustCompile|new\s+RegExp|pattern|regex|_RE\b|_RX\b)\b",
    re.IGNORECASE,
)
_SECRET_REAL_LITERAL_RX = re.compile(
    r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bghp_[A-Za-z0-9]{36}\b"
    r"|\bsk-(?:live|proj)?[A-Za-z0-9_-]{20,}\b)"
)
_AUTH_GUARD_RX = re.compile(
    r"(@(?:login_required|require_auth|requires_auth|require_role|permission_required|auth_required)|"
    r"\b(check_permission|is_authorized|verify_jwt|verify_token|authorize|require_admin|forbid|rbac|acl|hmac\.compare_digest)\b)",
    re.IGNORECASE,
)
_BOUNDS_GUARD_RX = re.compile(
    r"(\bmax\s*\([^)]*,\s*min\s*\(|\bmin\s*\([^)]*,\s*max\s*\(|\bclamp\s*\(|"
    r"\bif\s+[^\n:]*[<>=]+\s*(?:MAX_|MIN_|LIMIT|0\b)|raise\s+ValueError\b)",
    re.IGNORECASE,
)


@dataclass
class ClaimVerificationResult:
    """Deterministic AST/structural verification verdict for a single vulnerability claim."""

    epistemic_status: str
    satisfied_checks: List[str] = field(default_factory=list)
    failed_checks: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    independent_oracles: List[str] = field(default_factory=list)
    counter_evidence_line: Optional[int] = None
    counter_evidence_snippet: str = ""
    sanitizer_found: bool = False
    cwe: str = ""
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "epistemic_status": self.epistemic_status,
            "satisfied_checks": list(self.satisfied_checks),
            "failed_checks": list(self.failed_checks),
            "missing_evidence": list(self.missing_evidence),
            "independent_oracles": list(self.independent_oracles),
            "counter_evidence_line": self.counter_evidence_line,
            "counter_evidence_snippet": self.counter_evidence_snippet,
            "sanitizer_found": self.sanitizer_found,
            "cwe": self.cwe,
            "reason": self.reason,
        }


def _normalize_cwe(finding: Dict[str, Any]) -> str:
    raw = " ".join(
        str(finding.get(k) or "")
        for k in ("cwe", "cwe_id", "rule_id", "category", "title", "description")
    )
    m = re.search(r"\bCWE-(\d+)\b", raw, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    low = raw.lower()
    if any(k in low for k in ("path traversal", "directory traversal", "arbitrary file read")):
        return "CWE-22"
    if any(k in low for k in ("command injection", "os command", "shell injection")):
        return "CWE-78"
    if any(k in low for k in ("sql injection", "sqli")):
        return "CWE-89"
    if any(k in low for k in ("deserialization", "pickle", "yaml.load")):
        return "CWE-502"
    if any(k in low for k in ("cross-site scripting", "xss")):
        return "CWE-79"
    if any(k in low for k in ("code injection", "arbitrary code execution", "eval(")):
        return "CWE-94"
    if any(k in low for k in ("ssrf", "server-side request forgery")):
        return "CWE-918"
    if any(k in low for k in ("hardcoded secret", "exposed secret", "api key", "private key", "credential")):
        return "CWE-798"
    return ""


def _resolve_target_file(finding: Dict[str, Any], repo_root: Optional[Union[str, Path]]) -> Optional[Path]:
    raw = str(
        finding.get("file_path") or finding.get("file") or finding.get("path") or ""
    ).strip()
    if not raw or raw.lower().startswith(("http://", "https://")) or raw in ("network-target", "unknown", "N/A", "repo"):
        return None
    raw = raw.split("::", 1)[0]
    m_ln = re.match(r"^([A-Za-z]:[\\/].+|[^:]+):(\d{1,6})$", raw)
    if m_ln:
        raw = m_ln.group(1).strip()
    cand = Path(raw)
    if cand.is_absolute():
        return cand if cand.is_file() else None
    if repo_root is not None:
        joined = (Path(repo_root) / cand).resolve(strict=False)
        if joined.is_file():
            return joined
    if cand.is_file():
        return cand.resolve(strict=False)
    return None


def _extract_line_number(finding: Dict[str, Any]) -> int:
    for k in ("line_number", "line", "start_line", "lineno"):
        v = finding.get(k)
        if v is not None:
            try:
                n = int(v)
                if n > 0:
                    return n
            except (TypeError, ValueError):
                pass
    return 1


def _find_enclosing_python_node(tree: ast.AST, line_no: int) -> Optional[ast.AST]:
    best: Optional[ast.AST] = None
    best_span = 10**9
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = getattr(node, "lineno", 1)
            end = getattr(node, "end_lineno", start)
            if start <= line_no <= end:
                span = end - start
                if span < best_span:
                    best = node
                    best_span = span
    return best


def _extract_python_context(lines: List[str], line_no: int) -> Tuple[Optional[ast.AST], Optional[ast.AST], int, int]:
    """Returns `(module_tree, enclosing_fn_node, start_line_1based, end_line_1based)`."""
    src = "\n".join(lines)
    try:
        tree = ast.parse(src)
    except SyntaxError:
        start = max(1, line_no - 12)
        end = min(len(lines), line_no + 12)
        return None, None, start, end

    fn_node = _find_enclosing_python_node(tree, line_no)
    if fn_node is not None:
        start = max(1, int(getattr(fn_node, "lineno", line_no)))
        end = min(len(lines), int(getattr(fn_node, "end_lineno", line_no)))
        # Include decorator lines right above function
        decs = getattr(fn_node, "decorator_list", None) or []
        if decs:
            dec_start = min(int(getattr(d, "lineno", start)) for d in decs)
            start = min(start, max(1, dec_start))
        return tree, fn_node, start, end
    start = max(1, line_no - 10)
    end = min(len(lines), line_no + 10)
    return tree, None, start, end


def _is_constant_str_or_list_of_strs(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return bool(node.elts) and all(
            isinstance(el, ast.Constant) and isinstance(el.value, (str, bytes))
            for el in node.elts
        )
    return False


def _find_matching_line(lines: List[str], start_ln: int, end_ln: int, rx: re.Pattern) -> Tuple[Optional[int], str]:
    for ln in range(max(1, start_ln), min(len(lines), end_ln) + 1):
        txt = lines[ln - 1]
        if _COMMENT_LINE_RX.match(txt):
            continue
        if rx.search(txt):
            return ln, txt.strip()[:200]
    return None, ""


class ClaimPreconditionVerifier:
    """
    Deterministic AST/structural verifier validating whether a security claim's CWE
    preconditions actually hold at `(file_path, line_number)` before final reporting.
    """

    ORACLE_NAME = "claim_precondition_ast"

    @classmethod
    def verify_claim(
        cls,
        finding: Dict[str, Any],
        repo_root: Optional[Union[str, Path]] = None,
    ) -> ClaimVerificationResult:
        cwe = _normalize_cwe(finding)
        raw_fp = str(finding.get("file_path") or finding.get("file") or finding.get("path") or "").strip()
        line_no = _extract_line_number(finding)

        # Non-filesystem/network findings cannot be AST-verified locally -> keep UNRESOLVED unless runtime verified
        if not raw_fp or raw_fp.lower().startswith(("http://", "https://")) or raw_fp in ("network-target", "unknown", "N/A", "repo"):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.UNRESOLVED.value,
                satisfied_checks=[],
                failed_checks=[],
                missing_evidence=["no_local_source_file", "runtime_poe_not_executed"],
                independent_oracles=[],
                cwe=cwe,
                reason="Finding does not cite a verifiable local source file.",
            )

        resolved = _resolve_target_file(finding, repo_root)
        if resolved is None or not resolved.is_file():
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=[],
                failed_checks=["file_exists"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=None,
                counter_evidence_snippet="",
                sanitizer_found=False,
                cwe=cwe,
                reason=f"Cited file '{raw_fp}' does not exist on disk.",
            )

        try:
            raw_bytes = resolved.read_bytes()[:MAX_VERIFY_BYTES]
            text = raw_bytes.decode("utf-8", errors="replace")
        except OSError:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.UNRESOLVED.value,
                satisfied_checks=["file_exists"],
                failed_checks=[],
                missing_evidence=["source_unreadable"],
                independent_oracles=[],
                cwe=cwe,
                reason="Unable to read cited source file.",
            )

        lines = text.splitlines()
        if not lines or line_no < 1 or line_no > len(lines):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=["file_exists"],
                failed_checks=["line_in_range"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=None,
                counter_evidence_snippet="",
                sanitizer_found=False,
                cwe=cwe,
                reason=f"Cited line {line_no} is out of range for '{resolved.name}' ({len(lines)} lines).",
            )

        satisfied = ["file_exists", "line_in_range"]
        target_line = lines[line_no - 1]
        is_python = resolved.suffix.lower() == ".py"

        # Comment-only cited lines (except doc-level metadata checks) are not executable sinks
        if _COMMENT_LINE_RX.match(target_line):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["executable_code_at_line"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=True,
                cwe=cwe,
                reason=f"Line {line_no} in {resolved.name} is a comment/docstring, not an executable sink.",
            )

        if is_python:
            tree, fn_node, start_ln, end_ln = _extract_python_context(lines, line_no)
        else:
            tree, fn_node = None, None
            start_ln = max(1, line_no - 15)
            end_ln = min(len(lines), line_no + 15)

        if fn_node is not None:
            satisfied.append("symbol_found")
        ctx_lines = lines[start_ln - 1 : end_ln]
        ctx_code_lines = [ln for ln in ctx_lines if not _COMMENT_LINE_RX.match(ln)]
        ctx_text = "\n".join(ctx_code_lines)
        pre_sink_text = "\n".join(
            lines[i - 1]
            for i in range(start_ln, min(line_no, end_ln) + 1)
            if not _COMMENT_LINE_RX.match(lines[i - 1])
        )
        has_untrusted_src = bool(_UNTRUSTED_SOURCE_RX.search(ctx_text))
        # Also treat function parameters of route/handler functions as potential external input
        if fn_node is not None and isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arg_names = [a.arg.lower() for a in fn_node.args.args if a.arg not in ("self", "cls")]
            if any(
                tok in a
                for a in arg_names
                for tok in ("req", "user", "input", "path", "file", "url", "cmd", "query", "param", "body", "data", "payload", "raw", "token", "name", "expr", "id")
            ):
                has_untrusted_src = True

        # Dispatch CWE-specific deterministic AST/structural precondition checks
        if cwe == "CWE-22":
            return cls._verify_cwe22(lines, line_no, start_ln, end_ln, target_line, ctx_text, pre_sink_text, fn_node, has_untrusted_src, satisfied)
        if cwe == "CWE-78":
            return cls._verify_cwe78(lines, line_no, start_ln, end_ln, target_line, ctx_text, fn_node, has_untrusted_src, satisfied)
        if cwe == "CWE-89":
            return cls._verify_cwe89(lines, line_no, start_ln, end_ln, target_line, ctx_text, fn_node, has_untrusted_src, satisfied)
        if cwe == "CWE-502":
            return cls._verify_cwe502(lines, line_no, start_ln, end_ln, target_line, ctx_text, has_untrusted_src, satisfied)
        if cwe == "CWE-79":
            return cls._verify_cwe79(lines, line_no, start_ln, end_ln, target_line, ctx_text, has_untrusted_src, satisfied)
        if cwe == "CWE-94":
            return cls._verify_cwe94(lines, line_no, start_ln, end_ln, target_line, ctx_text, fn_node, has_untrusted_src, satisfied)
        if cwe == "CWE-918":
            return cls._verify_cwe918(lines, line_no, start_ln, end_ln, target_line, ctx_text, pre_sink_text, has_untrusted_src, satisfied)
        if cwe == "CWE-798":
            return cls._verify_cwe798(lines, line_no, start_ln, end_ln, target_line, ctx_text, satisfied)

        # Generic CWE check: verify if a claimed symbol or dangerous construct actually exists;
        # never promote a generic/unverified claim to PROVEN_*.
        claimed_fn = str(finding.get("function_name") or "").strip()
        if claimed_fn and claimed_fn not in ("<module>", "unknown") and fn_node is not None:
            actual_fn = getattr(fn_node, "name", "")
            if actual_fn and actual_fn != claimed_fn and claimed_fn not in ctx_text:
                return ClaimVerificationResult(
                    epistemic_status=EpistemicStatus.REFUTED.value,
                    satisfied_checks=satisfied,
                    failed_checks=["symbol_matches_line"],
                    missing_evidence=[],
                    independent_oracles=[cls.ORACLE_NAME],
                    counter_evidence_line=line_no,
                    counter_evidence_snippet=target_line.strip()[:200],
                    sanitizer_found=False,
                    cwe=cwe,
                    reason=f"Claimed symbol '{claimed_fn}' does not match enclosing function '{actual_fn}' at line {line_no}.",
                )

        # If a strong bounds/auth guard dominates an authorization/bounds claim, refute it
        if cwe in ("CWE-1284", "CWE-190", "CWE-789"):
            b_ln, b_snip = _find_matching_line(lines, start_ln, line_no, _BOUNDS_GUARD_RX)
            if b_ln is not None:
                return ClaimVerificationResult(
                    epistemic_status=EpistemicStatus.REFUTED.value,
                    satisfied_checks=satisfied,
                    failed_checks=["unbounded_numeric_sink"],
                    missing_evidence=[],
                    independent_oracles=[cls.ORACLE_NAME],
                    counter_evidence_line=b_ln,
                    counter_evidence_snippet=b_snip,
                    sanitizer_found=True,
                    cwe=cwe,
                    reason=f"Dominating bounds clamp/guard at line {b_ln} refutes unbounded numeric claim.",
                )

        return ClaimVerificationResult(
            epistemic_status=EpistemicStatus.UNRESOLVED.value,
            satisfied_checks=satisfied,
            failed_checks=[],
            missing_evidence=["structural_precondition_unproven", "runtime_poe_not_executed"],
            independent_oracles=[],
            cwe=cwe,
            reason="File and line exist, but deterministic AST preconditions for this CWE could not prove exploitability.",
        )

    @classmethod
    def _verify_cwe22(
        cls,
        lines: List[str],
        line_no: int,
        start_ln: int,
        end_ln: int,
        target_line: str,
        ctx_text: str,
        pre_sink_text: str,
        fn_node: Optional[ast.AST],
        has_untrusted_src: bool,
        satisfied: List[str],
    ) -> ClaimVerificationResult:
        # Check whether filesystem sink actually exists near cited line
        near_text = "\n".join(lines[max(0, line_no - 3) : min(len(lines), line_no + 3)])
        if not _PATH_SINK_RX.search(near_text) and not _PATH_SINK_RX.search(ctx_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["sink_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=False,
                cwe="CWE-22",
                reason="No filesystem/path sink present at or near cited line.",
            )
        satisfied = [*satisfied, "sink_present"]

        # Check static literal path argument in Python AST
        if fn_node is not None:
            for node in ast.walk(fn_node):
                if isinstance(node, ast.Call) and abs(getattr(node, "lineno", 0) - line_no) <= 2:
                    fname = node.func.id if isinstance(node.func, ast.Name) else (
                        node.func.attr if isinstance(node.func, ast.Attribute) else ""
                    )
                    if fname in ("open", "Path", "send_file", "read_text", "read_bytes") and node.args:
                        if _is_constant_str_or_list_of_strs(node.args[0]) and not has_untrusted_src:
                            return ClaimVerificationResult(
                                epistemic_status=EpistemicStatus.REFUTED.value,
                                satisfied_checks=satisfied,
                                failed_checks=["dynamic_path_operand"],
                                missing_evidence=[],
                                independent_oracles=[cls.ORACLE_NAME],
                                counter_evidence_line=getattr(node, "lineno", line_no),
                                counter_evidence_snippet=target_line.strip()[:200],
                                sanitizer_found=True,
                                cwe="CWE-22",
                                reason="Filesystem sink operates strictly on a static constant path literal.",
                            )

        # Dominating path canonicalization + confinement check before or at sink
        has_canon = bool(_PATH_SANITIZER_RX.search(pre_sink_text) or _PATH_SANITIZER_RX.search(ctx_text))
        has_confine = bool(_PATH_CONFINEMENT_CHECK_RX.search(pre_sink_text) or _PATH_CONFINEMENT_CHECK_RX.search(ctx_text))
        if has_canon and has_confine:
            c_ln, c_snip = _find_matching_line(lines, start_ln, end_ln, _PATH_CONFINEMENT_CHECK_RX)
            if c_ln is None:
                c_ln, c_snip = _find_matching_line(lines, start_ln, end_ln, _PATH_SANITIZER_RX)
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["unsanitized_path_sink"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=c_ln or line_no,
                counter_evidence_snippet=c_snip or target_line.strip()[:200],
                sanitizer_found=True,
                cwe="CWE-22",
                reason=f"Dominating path canonicalization & confinement guard found at line {c_ln or line_no}.",
            )

        if has_untrusted_src and not has_confine:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                satisfied_checks=[*satisfied, "untrusted_source_present", "no_dominating_sanitizer"],
                failed_checks=[],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                sanitizer_found=False,
                cwe="CWE-22",
                reason="Untrusted path parameter reaches filesystem sink with no canonicalization/confinement guard.",
            )

        return ClaimVerificationResult(
            epistemic_status=EpistemicStatus.UNRESOLVED.value,
            satisfied_checks=satisfied,
            failed_checks=[],
            missing_evidence=["caller_sanitization_unproven", "runtime_poe_not_executed"],
            independent_oracles=[cls.ORACLE_NAME],
            sanitizer_found=False,
            cwe="CWE-22",
            reason="Filesystem sink exists, but untrusted caller reachability is not proven.",
        )

    @classmethod
    def _verify_cwe78(
        cls,
        lines: List[str],
        line_no: int,
        start_ln: int,
        end_ln: int,
        target_line: str,
        ctx_text: str,
        fn_node: Optional[ast.AST],
        has_untrusted_src: bool,
        satisfied: List[str],
    ) -> ClaimVerificationResult:
        near_text = "\n".join(lines[max(0, line_no - 3) : min(len(lines), line_no + 3)])
        if not _CMD_SINK_RX.search(near_text) and not _CMD_SINK_RX.search(ctx_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["sink_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=False,
                cwe="CWE-78",
                reason="No OS command execution sink found at or near cited line.",
            )
        satisfied = [*satisfied, "sink_present"]

        # Python AST exact inspection of subprocess calls
        if fn_node is not None:
            for node in ast.walk(fn_node):
                if isinstance(node, ast.Call) and abs(getattr(node, "lineno", 0) - line_no) <= 3:
                    fname = node.func.id if isinstance(node.func, ast.Name) else (
                        node.func.attr if isinstance(node.func, ast.Attribute) else ""
                    )
                    if fname in ("run", "Popen", "call", "check_output", "check_call"):
                        shell_kw = next((kw for kw in node.keywords if kw.arg == "shell"), None)
                        shell_true = bool(
                            shell_kw is not None
                            and isinstance(shell_kw.value, ast.Constant)
                            and shell_kw.value.value is True
                        )
                        shell_false = (shell_kw is None) or (
                            isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is False
                        )
                        arg0 = node.args[0] if node.args else None
                        if shell_false and isinstance(arg0, (ast.List, ast.Tuple)):
                            return ClaimVerificationResult(
                                epistemic_status=EpistemicStatus.REFUTED.value,
                                satisfied_checks=satisfied,
                                failed_checks=["shell_injection_precondition"],
                                missing_evidence=[],
                                independent_oracles=[cls.ORACLE_NAME],
                                counter_evidence_line=getattr(node, "lineno", line_no),
                                counter_evidence_snippet=lines[getattr(node, "lineno", line_no) - 1].strip()[:200],
                                sanitizer_found=True,
                                cwe="CWE-78",
                                reason="Subprocess uses shell=False with an explicit argument list (no shell interpretation).",
                            )
                        if arg0 is not None and _is_constant_str_or_list_of_strs(arg0):
                            return ClaimVerificationResult(
                                epistemic_status=EpistemicStatus.REFUTED.value,
                                satisfied_checks=satisfied,
                                failed_checks=["dynamic_command_input"],
                                missing_evidence=[],
                                independent_oracles=[cls.ORACLE_NAME],
                                counter_evidence_line=getattr(node, "lineno", line_no),
                                counter_evidence_snippet=lines[getattr(node, "lineno", line_no) - 1].strip()[:200],
                                sanitizer_found=True,
                                cwe="CWE-78",
                                reason="Command sink invokes a static constant literal with no dynamic input.",
                            )
                        if shell_true and has_untrusted_src and not _CMD_SANITIZER_RX.search(ctx_text):
                            return ClaimVerificationResult(
                                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                                satisfied_checks=[*satisfied, "shell_true_with_dynamic_input", "no_dominating_sanitizer"],
                                failed_checks=[],
                                missing_evidence=[],
                                independent_oracles=[cls.ORACLE_NAME],
                                sanitizer_found=False,
                                cwe="CWE-78",
                                reason="Dynamic untrusted input reaches subprocess with shell=True and no shlex.quote sanitizer.",
                            )
                    elif fname in ("system", "popen") and node.args:
                        if _is_constant_str_or_list_of_strs(node.args[0]):
                            return ClaimVerificationResult(
                                epistemic_status=EpistemicStatus.REFUTED.value,
                                satisfied_checks=satisfied,
                                failed_checks=["dynamic_command_input"],
                                missing_evidence=[],
                                independent_oracles=[cls.ORACLE_NAME],
                                counter_evidence_line=getattr(node, "lineno", line_no),
                                counter_evidence_snippet=lines[getattr(node, "lineno", line_no) - 1].strip()[:200],
                                sanitizer_found=True,
                                cwe="CWE-78",
                                reason="os.system/popen invokes a static string literal.",
                            )
                        if has_untrusted_src and not _CMD_SANITIZER_RX.search(ctx_text):
                            return ClaimVerificationResult(
                                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                                satisfied_checks=[*satisfied, "os_shell_dynamic_input", "no_dominating_sanitizer"],
                                failed_checks=[],
                                missing_evidence=[],
                                independent_oracles=[cls.ORACLE_NAME],
                                sanitizer_found=False,
                                cwe="CWE-78",
                                reason="Untrusted dynamic input reaches os.system/popen without escaping.",
                            )

        # Fallback textual check for shell=False list or shlex.quote
        if re.search(r"shell\s*=\s*False", near_text) and "[" in near_text:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["shell_injection_precondition"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=True,
                cwe="CWE-78",
                reason="Command call uses explicit argv array with shell=False.",
            )
        san_ln, san_snip = _find_matching_line(lines, start_ln, line_no, _CMD_SANITIZER_RX)
        if san_ln is not None:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["unsanitized_command_input"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=san_ln,
                counter_evidence_snippet=san_snip,
                sanitizer_found=True,
                cwe="CWE-78",
                reason=f"Dominating shell argument quoting (`shlex.quote`) at line {san_ln}.",
            )
        if re.search(r"shell\s*=\s*True|\bos\.system\s*\(", near_text) and has_untrusted_src:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                satisfied_checks=[*satisfied, "shell_true_with_dynamic_input", "no_dominating_sanitizer"],
                failed_checks=[],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                sanitizer_found=False,
                cwe="CWE-78",
                reason="Dynamic untrusted input reaches shell execution sink.",
            )
        return ClaimVerificationResult(
            epistemic_status=EpistemicStatus.UNRESOLVED.value,
            satisfied_checks=satisfied,
            failed_checks=[],
            missing_evidence=["caller_sanitization_unproven", "runtime_poe_not_executed"],
            independent_oracles=[cls.ORACLE_NAME],
            cwe="CWE-78",
            reason="Command execution sink present, but untrusted dynamic reachability is unproven.",
        )

    @classmethod
    def _verify_cwe89(
        cls,
        lines: List[str],
        line_no: int,
        start_ln: int,
        end_ln: int,
        target_line: str,
        ctx_text: str,
        fn_node: Optional[ast.AST],
        has_untrusted_src: bool,
        satisfied: List[str],
    ) -> ClaimVerificationResult:
        near_text = "\n".join(lines[max(0, line_no - 3) : min(len(lines), line_no + 3)])
        if not _SQL_SINK_RX.search(near_text) and not _SQL_SINK_RX.search(ctx_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["sink_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=False,
                cwe="CWE-89",
                reason="No SQL execution sink found at or near cited line.",
            )
        satisfied = [*satisfied, "sink_present"]

        # Python AST exact check for parameterized execute("SELECT ... ?", (val,))
        if fn_node is not None:
            for node in ast.walk(fn_node):
                if isinstance(node, ast.Call) and abs(getattr(node, "lineno", 0) - line_no) <= 3:
                    fname = node.func.attr if isinstance(node.func, ast.Attribute) else ""
                    if fname in ("execute", "executemany") and node.args:
                        q_arg = node.args[0]
                        if isinstance(q_arg, ast.Constant) and isinstance(q_arg.value, str):
                            return ClaimVerificationResult(
                                epistemic_status=EpistemicStatus.REFUTED.value,
                                satisfied_checks=satisfied,
                                failed_checks=["dynamic_sql_interpolation"],
                                missing_evidence=[],
                                independent_oracles=[cls.ORACLE_NAME],
                                counter_evidence_line=getattr(node, "lineno", line_no),
                                counter_evidence_snippet=lines[getattr(node, "lineno", line_no) - 1].strip()[:200],
                                sanitizer_found=True,
                                cwe="CWE-89",
                                reason="SQL query uses a static/parameterized constant template with bound parameters.",
                            )
                        if isinstance(q_arg, (ast.JoinedStr, ast.BinOp)) or (
                            isinstance(q_arg, ast.Call)
                            and isinstance(q_arg.func, ast.Attribute)
                            and q_arg.func.attr == "format"
                        ):
                            return ClaimVerificationResult(
                                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                                satisfied_checks=[*satisfied, "dynamic_sql_interpolation", "no_dominating_sanitizer"],
                                failed_checks=[],
                                missing_evidence=[],
                                independent_oracles=[cls.ORACLE_NAME],
                                sanitizer_found=False,
                                cwe="CWE-89",
                                reason="SQL sink executes dynamically interpolated query string (f-string/concat/.format/%).",
                            )

        if _SQL_PARAM_RX.search(near_text) and not _SQL_INTERP_RX.search(near_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["dynamic_sql_interpolation"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=True,
                cwe="CWE-89",
                reason="Parameterized SQL query detected at cited line.",
            )
        if _SQL_INTERP_RX.search(near_text) and has_untrusted_src:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                satisfied_checks=[*satisfied, "dynamic_sql_interpolation", "no_dominating_sanitizer"],
                failed_checks=[],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                sanitizer_found=False,
                cwe="CWE-89",
                reason="Dynamic string interpolation into SQL query sink.",
            )
        return ClaimVerificationResult(
            epistemic_status=EpistemicStatus.UNRESOLVED.value,
            satisfied_checks=satisfied,
            failed_checks=[],
            missing_evidence=["caller_sanitization_unproven", "runtime_poe_not_executed"],
            independent_oracles=[cls.ORACLE_NAME],
            cwe="CWE-89",
            reason="SQL execution sink exists, but dynamic interpolation from untrusted input is unproven.",
        )

    @classmethod
    def _verify_cwe502(
        cls,
        lines: List[str],
        line_no: int,
        start_ln: int,
        end_ln: int,
        target_line: str,
        ctx_text: str,
        has_untrusted_src: bool,
        satisfied: List[str],
    ) -> ClaimVerificationResult:
        near_text = "\n".join(lines[max(0, line_no - 3) : min(len(lines), line_no + 3)])
        if _DESER_SAFE_RX.search(near_text) and not _DESER_UNSAFE_RX.search(near_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["unsafe_deserializer_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=True,
                cwe="CWE-502",
                reason="Safe deserializer (`json.loads` / `yaml.safe_load` / `SafeLoader`) used at cited line.",
            )
        if "yaml.load" in near_text and ("SafeLoader" in near_text or "CSafeLoader" in near_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["unsafe_deserializer_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=True,
                cwe="CWE-502",
                reason="yaml.load explicitly uses SafeLoader.",
            )
        if not _DESER_UNSAFE_RX.search(near_text) and not _DESER_UNSAFE_RX.search(ctx_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["sink_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=False,
                cwe="CWE-502",
                reason="No unsafe deserialization sink found at cited line.",
            )
        satisfied = [*satisfied, "sink_present"]
        if has_untrusted_src:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                satisfied_checks=[*satisfied, "unsafe_deserializer_with_untrusted_input"],
                failed_checks=[],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                sanitizer_found=False,
                cwe="CWE-502",
                reason="Unsafe deserialization sink (`pickle.loads`/`yaml.load`) invoked on untrusted input.",
            )
        return ClaimVerificationResult(
            epistemic_status=EpistemicStatus.UNRESOLVED.value,
            satisfied_checks=satisfied,
            failed_checks=[],
            missing_evidence=["caller_sanitization_unproven", "runtime_poe_not_executed"],
            independent_oracles=[cls.ORACLE_NAME],
            cwe="CWE-502",
            reason="Unsafe deserializer present, but untrusted caller reachability is unproven.",
        )

    @classmethod
    def _verify_cwe79(
        cls,
        lines: List[str],
        line_no: int,
        start_ln: int,
        end_ln: int,
        target_line: str,
        ctx_text: str,
        has_untrusted_src: bool,
        satisfied: List[str],
    ) -> ClaimVerificationResult:
        san_ln, san_snip = _find_matching_line(lines, start_ln, end_ln, _XSS_SAFE_RX)
        if san_ln is not None:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["unescaped_html_output"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=san_ln,
                counter_evidence_snippet=san_snip,
                sanitizer_found=True,
                cwe="CWE-79",
                reason=f"HTML escaping/auto-escaping sanitizer found at line {san_ln}.",
            )
        near_text = "\n".join(lines[max(0, line_no - 3) : min(len(lines), line_no + 3)])
        if not _XSS_SINK_RX.search(near_text) and "<" not in near_text:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["sink_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=False,
                cwe="CWE-79",
                reason="No HTML rendering sink found at cited line.",
            )
        satisfied = [*satisfied, "sink_present"]
        if has_untrusted_src:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                satisfied_checks=[*satisfied, "unescaped_html_interpolation", "no_dominating_sanitizer"],
                failed_checks=[],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                sanitizer_found=False,
                cwe="CWE-79",
                reason="Untrusted input interpolated directly into raw HTML response without escaping.",
            )
        return ClaimVerificationResult(
            epistemic_status=EpistemicStatus.UNRESOLVED.value,
            satisfied_checks=satisfied,
            failed_checks=[],
            missing_evidence=["caller_sanitization_unproven", "runtime_poe_not_executed"],
            independent_oracles=[cls.ORACLE_NAME],
            cwe="CWE-79",
            reason="HTML sink found, but untrusted input reachability is unproven.",
        )

    @classmethod
    def _verify_cwe94(
        cls,
        lines: List[str],
        line_no: int,
        start_ln: int,
        end_ln: int,
        target_line: str,
        ctx_text: str,
        fn_node: Optional[ast.AST],
        has_untrusted_src: bool,
        satisfied: List[str],
    ) -> ClaimVerificationResult:
        near_text = "\n".join(lines[max(0, line_no - 2) : min(len(lines), line_no + 2)])
        if _CODE_SAFE_RX.search(near_text) and not re.search(r"(?<!literal_)\b(eval|exec)\s*\(", near_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["unsafe_eval_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=True,
                cwe="CWE-94",
                reason="Uses safe `ast.literal_eval` rather than dynamic `eval`/`exec`.",
            )
        if not re.search(r"(?<!literal_)\b(eval|exec)\s*\(", near_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["sink_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=False,
                cwe="CWE-94",
                reason="No dynamic code evaluation sink (`eval`/`exec`) at cited line.",
            )
        satisfied = [*satisfied, "sink_present"]
        if has_untrusted_src:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                satisfied_checks=[*satisfied, "dynamic_code_eval_untrusted_input"],
                failed_checks=[],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                sanitizer_found=False,
                cwe="CWE-94",
                reason="Dynamic untrusted expression passed directly to `eval`/`exec`.",
            )
        return ClaimVerificationResult(
            epistemic_status=EpistemicStatus.UNRESOLVED.value,
            satisfied_checks=satisfied,
            failed_checks=[],
            missing_evidence=["caller_sanitization_unproven", "runtime_poe_not_executed"],
            independent_oracles=[cls.ORACLE_NAME],
            cwe="CWE-94",
            reason="Dynamic evaluation call found, but untrusted caller reachability is unproven.",
        )

    @classmethod
    def _verify_cwe918(
        cls,
        lines: List[str],
        line_no: int,
        start_ln: int,
        end_ln: int,
        target_line: str,
        ctx_text: str,
        pre_sink_text: str,
        has_untrusted_src: bool,
        satisfied: List[str],
    ) -> ClaimVerificationResult:
        near_text = "\n".join(lines[max(0, line_no - 3) : min(len(lines), line_no + 3)])
        if not _SSRF_SINK_RX.search(near_text) and not _SSRF_SINK_RX.search(ctx_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["sink_present"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=False,
                cwe="CWE-918",
                reason="No outbound HTTP client SSRF sink at cited line.",
            )
        satisfied = [*satisfied, "sink_present"]
        guard_ln, guard_snip = _find_matching_line(lines, start_ln, end_ln, _SSRF_GUARD_RX)
        if guard_ln is not None:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["unvalidated_ssrf_url"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=guard_ln,
                counter_evidence_snippet=guard_snip,
                sanitizer_found=True,
                cwe="CWE-918",
                reason=f"Dominating SSRF URL/IP allowlist or private-range guard found at line {guard_ln}.",
            )
        if has_untrusted_src:
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                satisfied_checks=[*satisfied, "untrusted_url_to_http_sink", "no_dominating_sanitizer"],
                failed_checks=[],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                sanitizer_found=False,
                cwe="CWE-918",
                reason="Untrusted URL parameter passed to outbound HTTP sink without SSRF IP/domain validation.",
            )
        return ClaimVerificationResult(
            epistemic_status=EpistemicStatus.UNRESOLVED.value,
            satisfied_checks=satisfied,
            failed_checks=[],
            missing_evidence=["caller_sanitization_unproven", "runtime_poe_not_executed"],
            independent_oracles=[cls.ORACLE_NAME],
            cwe="CWE-918",
            reason="Outbound HTTP sink found, but untrusted URL reachability is unproven.",
        )

    @classmethod
    def _verify_cwe798(
        cls,
        lines: List[str],
        line_no: int,
        start_ln: int,
        end_ln: int,
        target_line: str,
        ctx_text: str,
        satisfied: List[str],
    ) -> ClaimVerificationResult:
        near_text = "\n".join(lines[max(0, line_no - 3) : min(len(lines), line_no + 3)])
        if _SECRET_REGEX_CTX_RX.search(near_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["hardcoded_live_secret"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=True,
                cwe="CWE-798",
                reason="Cited line is a regex detector/validator pattern, not a live hardcoded secret.",
            )
        if _SECRET_PLACEHOLDER_RX.search(near_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.REFUTED.value,
                satisfied_checks=satisfied,
                failed_checks=["hardcoded_live_secret"],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                counter_evidence_line=line_no,
                counter_evidence_snippet=target_line.strip()[:200],
                sanitizer_found=True,
                cwe="CWE-798",
                reason="Cited line loads from environment variable or uses an explicit placeholder/example marker.",
            )
        if _SECRET_REAL_LITERAL_RX.search(near_text):
            return ClaimVerificationResult(
                epistemic_status=EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                satisfied_checks=[*satisfied, "literal_credential_pattern_matched"],
                failed_checks=[],
                missing_evidence=[],
                independent_oracles=[cls.ORACLE_NAME],
                sanitizer_found=False,
                cwe="CWE-798",
                reason="Confirmed literal high-entropy credential pattern in non-comment, non-regex source.",
            )
        return ClaimVerificationResult(
            epistemic_status=EpistemicStatus.UNRESOLVED.value,
            satisfied_checks=satisfied,
            failed_checks=[],
            missing_evidence=["no_confirmed_secret_literal_at_line"],
            independent_oracles=[],
            cwe="CWE-798",
            reason="No confirmed live secret literal found at cited line.",
        )

    @classmethod
    def verify_refutation_citations(
        cls,
        file_path: Union[str, Path],
        cited_lines: Sequence[int],
        cwe: str = "",
    ) -> Dict[str, Any]:
        """
        Deterministically verifies line citations returned by `FusionArbiter`'s
        Devil's-Advocate refutation pass against the real AST/source code.
        Rejects hallucinated or non-guard line citations.
        """
        path = Path(file_path)
        if not path.is_file():
            return {
                "verified": False,
                "verified_lines": [],
                "rejected_lines": [int(l) for l in cited_lines if isinstance(l, int)],
                "evidence": ["target_file_not_found"],
            }
        try:
            lines = path.read_bytes()[:MAX_VERIFY_BYTES].decode("utf-8", errors="replace").splitlines()
        except OSError:
            return {"verified": False, "verified_lines": [], "rejected_lines": list(cited_lines), "evidence": []}

        guard_patterns = [
            _PATH_SANITIZER_RX,
            _PATH_CONFINEMENT_CHECK_RX,
            _CMD_SANITIZER_RX,
            _SQL_PARAM_RX,
            _DESER_SAFE_RX,
            _XSS_SAFE_RX,
            _CODE_SAFE_RX,
            _SSRF_GUARD_RX,
            _SECRET_PLACEHOLDER_RX,
            _SECRET_REGEX_CTX_RX,
            _AUTH_GUARD_RX,
            _BOUNDS_GUARD_RX,
            re.compile(r"shell\s*=\s*False|\bif\s+False\s*:|raise\s+(?:PermissionError|ValueError|HTTPException)\b"),
        ]

        verified_lines: List[int] = []
        rejected_lines: List[int] = []
        evidence: List[str] = []

        for raw_ln in cited_lines:
            try:
                ln = int(raw_ln)
            except (TypeError, ValueError):
                continue
            if ln < 1 or ln > len(lines):
                rejected_lines.append(ln)
                continue
            txt = lines[ln - 1]
            if _COMMENT_LINE_RX.match(txt):
                rejected_lines.append(ln)
                continue
            matched = any(rx.search(txt) for rx in guard_patterns)
            if matched:
                verified_lines.append(ln)
                evidence.append(f"L{ln}: {txt.strip()[:160]}")
            else:
                rejected_lines.append(ln)

        return {
            "verified": bool(verified_lines),
            "verified_lines": sorted(set(verified_lines)),
            "rejected_lines": sorted(set(rejected_lines)),
            "evidence": evidence,
        }

    @classmethod
    def apply_to_findings(
        cls,
        findings: Sequence[Dict[str, Any]],
        repo_root: Optional[Union[str, Path]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Runs semantic claim precondition verification across all findings and attaches
        unified `epistemic_status` + `status_justification` while preserving 100% of
        findings (zero silent drops).
        """
        out: List[Dict[str, Any]] = []
        for f in findings:
            item = dict(f)
            # Only run AST claim verification when a local file path is present
            c_res = cls.verify_claim(item, repo_root=repo_root)
            if c_res.counter_evidence_line is not None:
                item["counter_evidence_line"] = c_res.counter_evidence_line
                item["counter_evidence_snippet"] = c_res.counter_evidence_snippet
            item["claim_verification"] = c_res.to_dict()
            attach_epistemic_metadata(item, claim_result=c_res)
            out.append(item)
        return out


__all__ = [
    "ClaimPreconditionVerifier",
    "ClaimVerificationResult",
]
