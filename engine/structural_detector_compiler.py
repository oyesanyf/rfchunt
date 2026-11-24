"""
Structural AST & Dataflow Detector Compiler for Harvested ArXiv Papers & Security Skills
=========================================================================================

Replaces flat keyword co-occurrence matching on newly harvested ArXiv research papers
(`--reseach-num`) and `last30days-skill` sightings (`--skills-num`) with 5 parameterized
structural AST/CFG/dataflow templates and a mandatory Positive (vulnerable) + Negative
(patched/commented) Self-Test Verification Gate:

  1. `SOURCE_TO_SINK_TAINT` (`CWE-78`, `CWE-74`, `CWE-89`, `CWE-918`, `CWE-22`, `CWE-502`, `CWE-77`)
  2. `MISSING_GUARD_BEFORE_SINK` (`CWE-862`, `CWE-306`, `CWE-285`, `CWE-522`, `CWE-347`, `CWE-732`, `CWE-345`)
  3. `FAIL_OPEN_EXCEPTION` (`CWE-636`, `CWE-252`, `CWE-755`)
  4. `TOCTOU_CHECK_THEN_ACT` (`CWE-362`, `CWE-367`, `CWE-444`, `CWE-436`)
  5. `UNSAFE_CAPABILITY_OR_CONFIG` (`CWE-250`, `CWE-269`, `CWE-119`, `CWE-190`, `CWE-829`, `CWE-798`)
"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

STRUCTURAL_TEMPLATE_IDS: Tuple[str, ...] = (
    "SOURCE_TO_SINK_TAINT",
    "MISSING_GUARD_BEFORE_SINK",
    "FAIL_OPEN_EXCEPTION",
    "TOCTOU_CHECK_THEN_ACT",
    "UNSAFE_CAPABILITY_OR_CONFIG",
)

_CWE_TO_TEMPLATE: Dict[str, str] = {
    "CWE-78": "SOURCE_TO_SINK_TAINT",
    "CWE-77": "SOURCE_TO_SINK_TAINT",
    "CWE-74": "SOURCE_TO_SINK_TAINT",
    "CWE-79": "SOURCE_TO_SINK_TAINT",
    "CWE-89": "SOURCE_TO_SINK_TAINT",
    "CWE-94": "SOURCE_TO_SINK_TAINT",
    "CWE-22": "SOURCE_TO_SINK_TAINT",
    "CWE-502": "SOURCE_TO_SINK_TAINT",
    "CWE-918": "SOURCE_TO_SINK_TAINT",
    "CWE-862": "MISSING_GUARD_BEFORE_SINK",
    "CWE-863": "MISSING_GUARD_BEFORE_SINK",
    "CWE-306": "MISSING_GUARD_BEFORE_SINK",
    "CWE-285": "MISSING_GUARD_BEFORE_SINK",
    "CWE-287": "MISSING_GUARD_BEFORE_SINK",
    "CWE-522": "MISSING_GUARD_BEFORE_SINK",
    "CWE-345": "MISSING_GUARD_BEFORE_SINK",
    "CWE-347": "MISSING_GUARD_BEFORE_SINK",
    "CWE-732": "MISSING_GUARD_BEFORE_SINK",
    "CWE-636": "FAIL_OPEN_EXCEPTION",
    "CWE-252": "FAIL_OPEN_EXCEPTION",
    "CWE-755": "FAIL_OPEN_EXCEPTION",
    "CWE-362": "TOCTOU_CHECK_THEN_ACT",
    "CWE-367": "TOCTOU_CHECK_THEN_ACT",
    "CWE-444": "TOCTOU_CHECK_THEN_ACT",
    "CWE-436": "TOCTOU_CHECK_THEN_ACT",
    "CWE-250": "UNSAFE_CAPABILITY_OR_CONFIG",
    "CWE-269": "UNSAFE_CAPABILITY_OR_CONFIG",
    "CWE-119": "UNSAFE_CAPABILITY_OR_CONFIG",
    "CWE-190": "UNSAFE_CAPABILITY_OR_CONFIG",
    "CWE-829": "UNSAFE_CAPABILITY_OR_CONFIG",
    "CWE-798": "UNSAFE_CAPABILITY_OR_CONFIG",
}


@dataclass(frozen=True)
class StructuralTemplateSpec:
    template_id: str
    cwe_id: str
    source_patterns: Tuple[str, ...]
    sink_patterns: Tuple[str, ...]
    guard_patterns: Tuple[str, ...]
    self_test_passed: bool = True
    positive_test_hits: int = 1
    negative_test_hits: int = 0
    adversarial_comment_test_hits: int = 0
    self_test_precision: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StructuralMatch:
    template_id: str
    line: int
    function_name: str
    evidence_snippet: str
    description: str


def strip_comments_preserve_lines(content: str, ext: str = ".py") -> str:
    """Strips block (`/* ... */`) and single-line (`//`, `#`) comments while preserving line count."""
    text = re.sub(
        r"/\*[\s\S]*?\*/",
        lambda m: "".join("\n" if ch == "\n" else " " for ch in m.group(0)),
        content,
    )
    out_lines: List[str] = []
    for line in text.splitlines():
        s = line.lstrip()
        if s.startswith("#") or s.startswith("//"):
            out_lines.append("")
            continue
        idx = line.find(" //")
        if idx != -1 and "://" not in line[max(0, idx - 6) : idx + 3]:
            line = line[:idx]
        idx_h = line.find(" #")
        if idx_h != -1:
            line = line[:idx_h]
        out_lines.append(line)
    return "\n".join(out_lines)


def infer_structural_template_id(
    cwe_id: str,
    title: str = "",
    summary: str = "",
    indicators: Optional[Sequence[str]] = None,
) -> str:
    """Deterministically selects the best of the 5 structural AST/dataflow templates."""
    cwe_norm = (cwe_id or "").strip().upper()
    if cwe_norm in _CWE_TO_TEMPLATE:
        return _CWE_TO_TEMPLATE[cwe_norm]
    blob = f"{title} {summary} {' '.join(indicators or ())}".lower()
    if any(k in blob for k in ("fail-open", "fail open", "except", "catch", "fallback")):
        return "FAIL_OPEN_EXCEPTION"
    if any(k in blob for k in ("toctou", "race", "rebinding", "single-packet", "desync", "smuggl")):
        return "TOCTOU_CHECK_THEN_ACT"
    if any(k in blob for k in ("auth", "rbac", "bola", "idor", "jwt", "consent", "server action", "presigned")):
        return "MISSING_GUARD_BEFORE_SINK"
    if any(k in blob for k in ("sandbox", "docker.sock", "cap_sys_admin", "unsafe", "set_len", "delegat", "rug-pull")):
        return "UNSAFE_CAPABILITY_OR_CONFIG"
    return "SOURCE_TO_SINK_TAINT"


def _split_function_windows(clean_content: str) -> List[Tuple[int, str, List[str]]]:
    """Splits a source file into `(start_line_1based, fn_name, lines)` function windows."""
    lines = clean_content.splitlines()
    fn_re = re.compile(
        r"^\s*(?:export\s+)?(?:public\s+|private\s+|pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
        r"(?:def|fn|func|function)\s+([A-Za-z_][A-Za-z0-9_]*)"
    )
    starts: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        m = fn_re.search(line)
        if m:
            starts.append((idx + 1, m.group(1)))
    if not starts:
        return [(1, "<module>", lines)]
    windows: List[Tuple[int, str, List[str]]] = []
    for i, (s_line, fn_name) in enumerate(starts):
        e_line = starts[i + 1][0] - 1 if i + 1 < len(starts) else len(lines)
        # Include up to 2 decorator lines immediately above the function signature
        dec_start = max(1, s_line - 2)
        windows.append((dec_start, fn_name, lines[dec_start - 1 : e_line]))
    return windows


def execute_structural_template(
    content: str,
    ext: str,
    spec: StructuralTemplateSpec,
) -> List[StructuralMatch]:
    """
    Executes one of the 5 structural AST/dataflow templates over `content`, stripping
    comments first and enforcing source -> sink / missing-guard / fail-open / TOCTOU
    structural constraints.
    """
    clean = strip_comments_preserve_lines(content, ext)
    raw_lines = content.splitlines()
    matches: List[StructuralMatch] = []
    tid = spec.template_id

    # Python AST path for SOURCE_TO_SINK_TAINT (intraprocedural def-use taint tracking)
    if tid == "SOURCE_TO_SINK_TAINT" and ext == ".py" and hasattr(ast, "unparse"):
        try:
            tree = ast.parse(clean)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_src = ast.unparse(node)
                    if any(re.search(gpat, fn_src, re.IGNORECASE) for gpat in spec.guard_patterns):
                        continue
                    tainted_vars = {
                        arg.arg
                        for arg in node.args.args
                        if any(re.search(spat, arg.arg, re.IGNORECASE) for spat in spec.source_patterns)
                    }
                    for stmt in ast.walk(node):
                        if isinstance(stmt, ast.Assign) and stmt.value is not None:
                            rhs_s = ast.unparse(stmt.value)
                            is_rhs_tainted = any(
                                re.search(spat, rhs_s, re.IGNORECASE) for spat in spec.source_patterns
                            ) or any(
                                isinstance(sub_n, ast.Name) and sub_n.id in tainted_vars
                                for sub_n in ast.walk(stmt.value)
                            )
                            is_rhs_guarded = any(
                                re.search(gpat, rhs_s, re.IGNORECASE) for gpat in spec.guard_patterns
                            )
                            for tgt in stmt.targets:
                                if isinstance(tgt, ast.Name):
                                    if is_rhs_tainted and not is_rhs_guarded:
                                        tainted_vars.add(tgt.id)
                                    elif is_rhs_guarded and tgt.id in tainted_vars:
                                        tainted_vars.discard(tgt.id)
                    if tainted_vars:
                        for sub in ast.walk(node):
                            if isinstance(sub, ast.Call):
                                call_s = ast.unparse(sub)
                                if any(re.search(kpat, call_s, re.IGNORECASE) for kpat in spec.sink_patterns):
                                    uses_tainted = any(
                                        isinstance(arg_n, ast.Name) and arg_n.id in tainted_vars
                                        for arg_n in ast.walk(sub)
                                    )
                                    if uses_tainted:
                                        lno = int(getattr(sub, "lineno", node.lineno))
                                        matches.append(
                                            StructuralMatch(
                                                template_id=tid,
                                                line=lno,
                                                function_name=node.name,
                                                evidence_snippet=(raw_lines[lno - 1] if 1 <= lno <= len(raw_lines) else call_s).strip(),
                                                description=f"Python AST def-use taint flow from {sorted(tainted_vars)} into sink `{call_s[:80]}` in `{node.name}`.",
                                            )
                                        )
                                        break
            if matches:
                return matches
        except SyntaxError:
            pass

    # Python AST path for FAIL_OPEN_EXCEPTION when parsing valid Python
    if tid == "FAIL_OPEN_EXCEPTION" and ext == ".py":
        try:
            tree = ast.parse(clean)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.ExceptHandler):
                            for stmt in ast.walk(sub):
                                if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
                                    if stmt.value.value is True or stmt.value.value == "ALLOW":
                                        lno = getattr(stmt, "lineno", getattr(sub, "lineno", node.lineno))
                                        matches.append(
                                            StructuralMatch(
                                                template_id=tid,
                                                line=lno,
                                                function_name=node.name,
                                                evidence_snippet=(raw_lines[lno - 1] if 1 <= lno <= len(raw_lines) else "return True").strip(),
                                                description=f"Exception handler in `{node.name}` fails open (`return {stmt.value.value!r}`).",
                                            )
                                        )
                                elif isinstance(stmt, ast.Call):
                                    call_src = ast.unparse(stmt) if hasattr(ast, "unparse") else ""
                                    if any(s in call_src for s in ("subprocess.Popen", "subprocess.run", "os.system")):
                                        lno = getattr(stmt, "lineno", getattr(sub, "lineno", node.lineno))
                                        matches.append(
                                            StructuralMatch(
                                                template_id=tid,
                                                line=lno,
                                                function_name=node.name,
                                                evidence_snippet=(raw_lines[lno - 1] if 1 <= lno <= len(raw_lines) else call_src).strip(),
                                                description=f"Exception handler in `{node.name}` falls back to unisolated host execution.",
                                            )
                                        )
            if matches:
                return matches
        except SyntaxError:
            pass

    for start_ln, fn_name, win_lines in _split_function_windows(clean):
        win_text = "\n".join(win_lines)
        if not win_text.strip():
            continue

        if tid == "SOURCE_TO_SINK_TAINT":
            has_source = any(re.search(pat, win_text, re.IGNORECASE) for pat in spec.source_patterns)
            has_guard = any(re.search(pat, win_text, re.IGNORECASE) for pat in spec.guard_patterns)
            if has_source and not has_guard:
                for offset, line in enumerate(win_lines):
                    if any(re.search(pat, line, re.IGNORECASE) for pat in spec.sink_patterns):
                        lno = start_ln + offset
                        matches.append(
                            StructuralMatch(
                                template_id=tid,
                                line=lno,
                                function_name=fn_name,
                                evidence_snippet=(raw_lines[lno - 1] if 1 <= lno <= len(raw_lines) else line).strip(),
                                description=f"Untrusted source flows into sink in `{fn_name}` without dominating sanitizer/guard.",
                            )
                        )
                        break

        elif tid == "MISSING_GUARD_BEFORE_SINK":
            has_entry = any(re.search(pat, win_text, re.IGNORECASE) for pat in spec.source_patterns)
            has_guard = any(re.search(pat, win_text, re.IGNORECASE) for pat in spec.guard_patterns)
            if has_entry and not has_guard:
                for offset, line in enumerate(win_lines):
                    if any(re.search(pat, line, re.IGNORECASE) for pat in spec.sink_patterns):
                        lno = start_ln + offset
                        matches.append(
                            StructuralMatch(
                                template_id=tid,
                                line=lno,
                                function_name=fn_name,
                                evidence_snippet=(raw_lines[lno - 1] if 1 <= lno <= len(raw_lines) else line).strip(),
                                description=f"Sensitive sink in `{fn_name}` executes without required authorization/consent/signature guard.",
                            )
                        )
                        break

        elif tid == "FAIL_OPEN_EXCEPTION":
            for offset, line in enumerate(win_lines):
                if re.search(r"\b(?:except\b|catch\b)", line):
                    sub_win = "\n".join(win_lines[offset : min(len(win_lines), offset + 6)])
                    has_fail_closed = bool(
                        re.search(r"\b(?:return\s+(?:false|False|None|null|undefined|Err\b)|raise\b|throw\b)", sub_win)
                    )
                    if not has_fail_closed and any(re.search(pat, sub_win, re.IGNORECASE) for pat in spec.sink_patterns):
                        lno = start_ln + offset
                        matches.append(
                            StructuralMatch(
                                template_id=tid,
                                line=lno,
                                function_name=fn_name,
                                evidence_snippet=(raw_lines[lno - 1] if 1 <= lno <= len(raw_lines) else line).strip(),
                                description=f"Exception handler in `{fn_name}` fails open instead of denying.",
                            )
                        )
                        break

        elif tid == "TOCTOU_CHECK_THEN_ACT":
            step1_offset: Optional[int] = None
            for offset, line in enumerate(win_lines):
                if step1_offset is None and any(re.search(pat, line, re.IGNORECASE) for pat in spec.source_patterns):
                    step1_offset = offset
                elif step1_offset is not None and any(re.search(pat, line, re.IGNORECASE) for pat in spec.sink_patterns):
                    has_atomic_guard = any(re.search(pat, win_text, re.IGNORECASE) for pat in spec.guard_patterns)
                    if not has_atomic_guard:
                        lno = start_ln + offset
                        matches.append(
                            StructuralMatch(
                                template_id=tid,
                                line=lno,
                                function_name=fn_name,
                                evidence_snippet=(raw_lines[lno - 1] if 1 <= lno <= len(raw_lines) else line).strip(),
                                description=f"Non-atomic check-then-act / two-step TOCTOU sequence in `{fn_name}` without atomic lock/pinning.",
                            )
                        )
                        break

        elif tid == "UNSAFE_CAPABILITY_OR_CONFIG":
            has_guard = any(re.search(pat, win_text, re.IGNORECASE) for pat in spec.guard_patterns)
            if not has_guard:
                for offset, line in enumerate(win_lines):
                    if any(
                        diag in line
                        for diag in ("die(", "throw ", "logForDebugging(", "eprintln!(", "MISSING_MESSAGE", "re.compile")
                    ):
                        continue
                    if any(re.search(pat, line, re.IGNORECASE) for pat in spec.sink_patterns):
                        lno = start_ln + offset
                        matches.append(
                            StructuralMatch(
                                template_id=tid,
                                line=lno,
                                function_name=fn_name,
                                evidence_snippet=(raw_lines[lno - 1] if 1 <= lno <= len(raw_lines) else line).strip(),
                                description=f"Unsafe privilege/capability or memory-safety configuration in `{fn_name}`.",
                            )
                        )
                        break

    return matches


def build_structural_template_spec(
    cwe_id: str,
    title: str = "",
    summary: str = "",
    custom_indicators: Optional[Sequence[str]] = None,
) -> StructuralTemplateSpec:
    """
    Compiles a harvested ArXiv paper or `last30days` security skill into a parameterized
    `StructuralTemplateSpec` and verifies it via a Positive (vulnerable) + Negative
    (safe/patched/commented) self-test gate.
    """
    tid = infer_structural_template_id(cwe_id, title, summary, custom_indicators)
    ind_escaped = [
        re.escape(tok.strip())
        for tok in (custom_indicators or ())
        if tok and len(tok.strip()) >= 4 and tok.strip().lower() not in ("true", "false", "none", "null")
    ][:4]

    if tid == "SOURCE_TO_SINK_TAINT":
        sources = (
            r"\b(?:req|request|user_input|untrusted|payload|raw_input|ext_data|rag_chunk|tool_output)\b",
        )
        sinks = tuple(
            [
                r"\b(?:subprocess\.(?:run|Popen|call)|os\.system|eval|exec|pickle\.loads|yaml\.load|child_process\.exec)\s*\(",
                r"role['\"]?\s*:\s*['\"]system['\"].*\+",
            ]
            + ind_escaped
        )
        guards = (
            r"\b(?:shlex\.quote|allowlist|canonicalize|realpath|safe_load|verify_envelope|sanitize_full)\b",
        )
        pos_fixture = (
            "def run_user_cmd(user_input: str):\n"
            "    return subprocess.run(user_input, shell=True)\n"
        )
        neg_fixture = (
            "# Comment mentioning subprocess.run(user_input, shell=True)\n"
            "def run_user_cmd_safe(user_input: str):\n"
            "    clean = shlex.quote(user_input)\n"
            "    return subprocess.run(['echo', clean], shell=False)\n"
        )
    elif tid == "MISSING_GUARD_BEFORE_SINK":
        sources = (
            r"(?:@app\.(?:post|put|delete|get)|use server|def\s+\w+|export\s+async\s+function\s+\w+)",
        )
        sinks = tuple(
            [
                r"\b(?:db\.(?:delete|update|create|execute)|prisma\.\w+\.(?:delete|update|create)|jwt\.decode\s*\([^)]*verify(?:_signature)?\s*=\s*False|generate_presigned_url\s*\(\s*['\"]put_object['\"])\b",
            ]
            + ind_escaped
        )
        guards = (
            r"\b(?:verify_jwt|check_permission|require_auth|getServerSession|current_user|positive_consent|user_consent|ContentType)\b",
        )
        pos_fixture = (
            "@app.delete('/users/{id}')\n"
            "def delete_account(id: str):\n"
            "    return db.delete(id)\n"
        )
        neg_fixture = (
            "# Comment mentioning db.delete(id)\n"
            "@app.delete('/users/{id}')\n"
            "def delete_account_safe(id: str, current_user: dict):\n"
            "    require_auth(current_user, id)\n"
            "    return db.delete(id)\n"
        )
    elif tid == "FAIL_OPEN_EXCEPTION":
        sources = (r"\b(?:try|except|catch)\b",)
        sinks = (
            r"\breturn\s+(?:True|true|['\"]ALLOW['\"])\b",
            r"\bsubprocess\.(?:Popen|run)\s*\(",
        )
        guards = (r"\b(?:return\s+(?:False|false|Err\b)|raise\b|throw\b)",)
        pos_fixture = (
            "def check_guardrail(payload: str) -> bool:\n"
            "    try:\n"
            "        return evaluate_policy(payload)\n"
            "    except Exception:\n"
            "        return True\n"
        )
        neg_fixture = (
            "# Comment mentioning except Exception: return True\n"
            "def check_guardrail_safe(payload: str) -> bool:\n"
            "    try:\n"
            "        return evaluate_policy(payload)\n"
            "    except Exception:\n"
            "        return False\n"
        )
    elif tid == "TOCTOU_CHECK_THEN_ACT":
        sources = (
            r"\b(?:socket\.gethostbyname|socket\.getaddrinfo|SELECT\s+balance|fs\.statSync)\b",
        )
        sinks = (
            r"\b(?:requests\.(?:get|post)|httpx\.(?:get|post)|UPDATE\s+\w+\s+SET\s+balance|SetNamedSecurityInfoW)\b",
        )
        guards = (
            r"\b(?:FOR\s+UPDATE|with_for_update|WHERE\s+balance\s*>=|FILE_FLAG_OPEN_REPARSE_POINT|pinned_ip)\b",
        )
        pos_fixture = (
            "def fetch_webhook(url: str, host: str):\n"
            "    ip = socket.gethostbyname(host)\n"
            "    return requests.get(url)\n"
        )
        neg_fixture = (
            "# Comment mentioning socket.gethostbyname and requests.get(url)\n"
            "def fetch_webhook_safe(url: str, host: str):\n"
            "    pinned_ip = socket.gethostbyname(host)\n"
            "    return requests.get(pinned_ip)\n"
        )
    else:  # UNSAFE_CAPABILITY_OR_CONFIG
        sources = (r".+",)
        sinks = tuple(
            [
                r"(?:/var/run/docker\.sock|--privileged\b|seccomp[=:]\s*unconfined|\.set_len\s*\(|curl\s+[^\n|]+\|\s*(?:ba)?sh\b|permissions\s*=\s*\[\s*['\"]\*['\"]\s*\])",
            ]
            + ind_escaped
        )
        guards = (
            r"(?:DelegationScope\.meet|\bsha256sum\b|--cap-drop\s+ALL|\bchecked_mul\b)",
        )
        pos_fixture = (
            "def launch_container():\n"
            "    cmd = 'docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock alpine'\n"
            "    return cmd\n"
        )
        neg_fixture = (
            "/* Comment mentioning --privileged and /var/run/docker.sock */\n"
            "def launch_container_safe():\n"
            "    return 'docker run --cap-drop ALL alpine'\n"
        )

    provisional = StructuralTemplateSpec(
        template_id=tid,
        cwe_id=cwe_id or "CWE-20",
        source_patterns=sources,
        sink_patterns=sinks,
        guard_patterns=guards,
    )
    adv_comment_fixture = "\n".join(
        f"# {ln}\n// {ln}\n/* {ln} */" for ln in pos_fixture.splitlines() if ln.strip()
    )
    pos_matches = execute_structural_template(pos_fixture, ".py", provisional)
    neg_matches = execute_structural_template(neg_fixture, ".py", provisional)
    adv_matches = execute_structural_template(adv_comment_fixture, ".py", provisional)
    passed = len(pos_matches) >= 1 and len(neg_matches) == 0 and len(adv_matches) == 0
    total_pos = len(pos_matches)
    total_fp = len(neg_matches) + len(adv_matches)
    precision = round(total_pos / float(total_pos + total_fp), 4) if (total_pos + total_fp) > 0 else 0.0
    return StructuralTemplateSpec(
        template_id=tid,
        cwe_id=cwe_id or "CWE-20",
        source_patterns=sources,
        sink_patterns=sinks,
        guard_patterns=guards,
        self_test_passed=passed,
        positive_test_hits=len(pos_matches),
        negative_test_hits=len(neg_matches),
        adversarial_comment_test_hits=len(adv_matches),
        self_test_precision=precision,
    )
