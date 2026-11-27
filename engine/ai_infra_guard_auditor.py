"""
AI-Infra-Guard & DeepAudit Static Auditor (M1 / Component 4).
=============================================================
Pure-Python, multithreaded static auditor targeting AI infrastructure and
source-code trust boundaries:
  1. `AI-INFRA-BIND-001` (`CWE-306`): Unauthenticated model servers (`0.0.0.0` Ollama,
     vLLM without `--api-key`, Triton, Ray, Gradio `share=True`, Jupyter `--allow-root`, MLflow).
  2. `AI-INFRA-DESER-002` (`CWE-502`): Unsafe deserialization (`pickle.load`, `cloudpickle`,
     `dill`, `torch.load` without `weights_only=True`, `yaml.load` without `SafeLoader`).
  3. `AI-INFRA-SSTI-003` (`CWE-94` / `CWE-1336`): Jinja2 SSTI in prompt templates & `eval`/`exec`.
  4. `AI-INFRA-K8S-004` (`CWE-250` / `CWE-269`): Privileged containers, `hostNetwork`,
     `docker.sock` mount, sensitive `hostPath`, `:latest` unpinned Dockerfile base images.
  5. `AI-INFRA-TAINT-005` (`CWE-78` / `CWE-918`): DeepAudit Python AST intra-procedural
     source-to-sink taint flow (and JS/TS fallback) without intermediate sanitizers.
"""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from engine.linux_poc_runner import validate_mount_path
from engine.parity_invariant_auditor import is_non_production_noise


_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "target",
        "dist",
        "build",
        ".pytest_cache",
        "reports",
    }
)

_MAX_FILE_BYTES = 1_048_576
_SCAN_EXTS: frozenset[str] = frozenset(
    {".py", ".yaml", ".yml", ".json", ".toml", ".sh", ".env", ".ts", ".tsx", ".js", ".mjs"}
)

_TAINT_SOURCES: frozenset[str] = frozenset(
    {"prompt", "user_input", "tool_args", "messages", "request", "req", "body", "query", "payload"}
)
_SANITIZER_EXACT_CALLS: frozenset[str] = frozenset(
    {
        "validate_target_host",
        "shlex.quote",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
        "quote",
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
        "re.escape",
    }
)
_SANITIZER_LEAF_PREFIXES: Tuple[str, ...] = (
    "sanitize",
    "escape",
    "validate_target",
)


def _make_finding(
    *,
    rule_id: str,
    title: str,
    cwe: str,
    severity: str,
    confidence: float,
    file_path: str,
    line: int,
    summary: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    noise = is_non_production_noise(file_path)
    meta = dict(metadata or {})
    meta["non_production_noise"] = noise
    return {
        "engine": "ai_infra_guard",
        "rule_id": rule_id,
        "title": title,
        "cwe": cwe,
        "severity": severity,
        "confidence": confidence,
        "file_path": file_path,
        "line": max(1, int(line)),
        "summary": summary,
        "deterministic": True,
        "confirmed": True,
        "non_production_noise": noise,
        "metadata": meta,
    }


def _scan_ai_bind_configs(rel_path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        low = line.lower()
        if "ollama_host" in low and "0.0.0.0" in low:
            findings.append(
                _make_finding(
                    rule_id="AI-INFRA-BIND-001",
                    title="Ollama bound to 0.0.0.0 without authentication",
                    cwe="CWE-306",
                    severity="HIGH",
                    confidence=0.90,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"`OLLAMA_HOST=0.0.0.0` exposes unauthenticated Ollama API in {rel_path}:{line_no}.",
                )
            )
        if "vllm" in low and "0.0.0.0" in low and "--api-key" not in text.lower():
            findings.append(
                _make_finding(
                    rule_id="AI-INFRA-BIND-001",
                    title="vLLM server exposed on 0.0.0.0 without `--api-key`",
                    cwe="CWE-306",
                    severity="HIGH",
                    confidence=0.88,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"vLLM binds `0.0.0.0` without `--api-key` in {rel_path}:{line_no}.",
                )
            )
        if any(srv in low for srv in ("tritonserver", "mlflow", "ray start")) and (
            "0.0.0.0" in low or "--allow-http" in low or "--dashboard-host=0.0.0.0" in low
        ):
            findings.append(
                _make_finding(
                    rule_id="AI-INFRA-BIND-001",
                    title="AI serving/orchestration endpoint bound to all interfaces (`0.0.0.0`)",
                    cwe="CWE-306",
                    severity="HIGH",
                    confidence=0.85,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"Model/orchestration service exposed on `0.0.0.0` in {rel_path}:{line_no}.",
                )
            )
        if ".launch(" in line and ("0.0.0.0" in line or "share=true" in low) and "auth=" not in low:
            findings.append(
                _make_finding(
                    rule_id="AI-INFRA-BIND-001",
                    title="Gradio interface launched on 0.0.0.0 / share=True without auth",
                    cwe="CWE-306",
                    severity="HIGH",
                    confidence=0.87,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"Gradio `.launch(...)` omits `auth=` while binding externally in {rel_path}:{line_no}.",
                )
            )
        if "jupyter" in low and ("--ip=0.0.0.0" in low or "--allow-root" in low) and (
            "token=''" in low or 'token=""' in low or "--notebookapp.token=''" in low or "--identityprovider.token=''" in low
        ):
            findings.append(
                _make_finding(
                    rule_id="AI-INFRA-BIND-001",
                    title="Jupyter server exposed on 0.0.0.0 with empty token",
                    cwe="CWE-306",
                    severity="CRITICAL",
                    confidence=0.92,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"Unauthenticated Jupyter configuration in {rel_path}:{line_no}.",
                )
            )
    return findings


def _scan_k8s_and_docker(rel_path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    name_l = Path(rel_path).name.lower()
    lines = text.splitlines()

    if name_l == "dockerfile" or name_l.startswith("dockerfile."):
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if re.match(r"(?i)^FROM\s+\S+:latest(?:\s|$)", stripped):
                findings.append(
                    _make_finding(
                        rule_id="AI-INFRA-K8S-004",
                        title="Unpinned `:latest` container base image in Dockerfile",
                        cwe="CWE-829",
                        severity="LOW",
                        confidence=0.78,
                        file_path=rel_path,
                        line=line_no,
                        summary=f"Unpinned `:latest` tag in {rel_path}:{line_no}; pin by SHA256 digest.",
                    )
                )
            if "--privileged" in stripped.lower() or re.search(r"\bchmod\s+777\s+/\s*$", stripped):
                findings.append(
                    _make_finding(
                        rule_id="AI-INFRA-K8S-004",
                        title="Privileged container instruction in Dockerfile",
                        cwe="CWE-250",
                        severity="HIGH",
                        confidence=0.86,
                        file_path=rel_path,
                        line=line_no,
                        summary=f"Dangerous container privilege configuration in {rel_path}:{line_no}.",
                    )
                )
        return findings

    if Path(rel_path).suffix.lower() in (".yaml", ".yml"):
        for line_no, line in enumerate(lines, start=1):
            if re.search(r"^\s*privileged\s*:\s*true\b", line, re.IGNORECASE):
                findings.append(
                    _make_finding(
                        rule_id="AI-INFRA-K8S-004",
                        title="Kubernetes/Compose privileged container (`privileged: true`)",
                        cwe="CWE-250",
                        severity="CRITICAL",
                        confidence=0.92,
                        file_path=rel_path,
                        line=line_no,
                        summary=f"`privileged: true` enables container escape in {rel_path}:{line_no}.",
                    )
                )
            if re.search(r"^\s*(?:hostNetwork|hostPID|hostIPC|allowPrivilegeEscalation)\s*:\s*true\b", line, re.IGNORECASE):
                findings.append(
                    _make_finding(
                        rule_id="AI-INFRA-K8S-004",
                        title="Container shares host namespace or allows privilege escalation",
                        cwe="CWE-250",
                        severity="HIGH",
                        confidence=0.87,
                        file_path=rel_path,
                        line=line_no,
                        summary=f"Host namespace / escalation flag enabled at {rel_path}:{line_no}.",
                    )
                )
            if re.search(r"^\s*runAsUser\s*:\s*0\b", line):
                findings.append(
                    _make_finding(
                        rule_id="AI-INFRA-K8S-004",
                        title="Container runs as UID 0 (root)",
                        cwe="CWE-250",
                        severity="MEDIUM",
                        confidence=0.82,
                        file_path=rel_path,
                        line=line_no,
                        summary=f"`runAsUser: 0` at {rel_path}:{line_no}.",
                    )
                )
            if "/var/run/docker.sock" in line:
                findings.append(
                    _make_finding(
                        rule_id="AI-INFRA-K8S-004",
                        title="Docker socket (`/var/run/docker.sock`) mounted inside container",
                        cwe="CWE-250",
                        severity="CRITICAL",
                        confidence=0.94,
                        file_path=rel_path,
                        line=line_no,
                        summary=f"Mounting `/var/run/docker.sock` grants host root equivalence in {rel_path}:{line_no}.",
                    )
                )
            m_hp = re.search(r"^\s*path\s*:\s*[\"']?(/(?:etc|root|proc|sys)?)\s*[\"']?\s*$", line)
            if m_hp:
                findings.append(
                    _make_finding(
                        rule_id="AI-INFRA-K8S-004",
                        title=f"Sensitive hostPath mount `{m_hp.group(1)}`",
                        cwe="CWE-250",
                        severity="HIGH",
                        confidence=0.88,
                        file_path=rel_path,
                        line=line_no,
                        summary=f"Sensitive hostPath `{m_hp.group(1)}` mounted in {rel_path}:{line_no}.",
                    )
                )
    return findings


def _call_name(node: ast.Call) -> str:
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        parts = [fn.attr]
        cur = fn.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _expr_uses_names(node: ast.AST, names: Set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in names:
            return True
    return False


def _is_sanitizer_call(node: ast.Call) -> bool:
    cname = _call_name(node)
    if not cname:
        return False
    if cname in _SANITIZER_EXACT_CALLS:
        return True
    leaf = cname.rsplit(".", 1)[-1].lower()
    return leaf.startswith(_SANITIZER_LEAF_PREFIXES) or "allowlist" in leaf


def _contains_sanitizer_call(node: ast.AST) -> bool:
    return any(isinstance(sub, ast.Call) and _is_sanitizer_call(sub) for sub in ast.walk(node))


def _expr_has_direct_source(node: ast.AST) -> bool:
    try:
        src_low = ast.unparse(node).lower()
    except Exception:
        src_low = ""
    return any(
        src in src_low
        for src in (
            "request.json",
            "request.args",
            "request.form",
            "request.data",
            "user_input",
            "prompt",
            "tool_args",
        )
    )


def _expr_has_unsanitized_taint(node: ast.AST, tainted_names: Set[str]) -> bool:
    stack: List[ast.AST] = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, ast.Call) and _is_sanitizer_call(cur):
            continue
        if isinstance(cur, ast.Name) and cur.id in tainted_names:
            return True
        if isinstance(cur, (ast.Attribute, ast.Subscript)):
            try:
                src_low = ast.unparse(cur).lower()
            except Exception:
                src_low = ""
            if any(
                src in src_low
                for src in ("request.json", "request.args", "request.form", "request.data")
            ):
                return True
        stack.extend(ast.iter_child_nodes(cur))
    return False


def _extract_target_names(target: ast.AST) -> List[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: List[str] = []
        for elt in target.elts:
            names.extend(_extract_target_names(elt))
        return names
    return []


def _scan_python_ast(rel_path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return findings

    seen: Set[Tuple[str, int]] = set()

    def _emit(rule_id: str, title: str, cwe: str, severity: str, conf: float, line: int, summary: str) -> None:
        key = (rule_id, line)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            _make_finding(
                rule_id=rule_id,
                title=title,
                cwe=cwe,
                severity=severity,
                confidence=conf,
                file_path=rel_path,
                line=line,
                summary=summary,
            )
        )

    # AST pass 1: Deserialization, SSTI, dynamic eval/exec
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        cname = _call_name(node)
        line_no = getattr(node, "lineno", 1)

        if cname in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "cloudpickle.load", "cloudpickle.loads", "dill.load", "dill.loads"):
            _emit(
                "AI-INFRA-DESER-002",
                f"Unsafe model/artifact deserialization (`{cname}`)",
                "CWE-502",
                "CRITICAL",
                0.93,
                line_no,
                f"`{cname}` executes arbitrary code on untrusted payloads at {rel_path}:{line_no}.",
            )
        elif cname == "torch.load":
            weights_kw = next((kw for kw in node.keywords if kw.arg == "weights_only"), None)
            is_safe = isinstance(weights_kw.value, ast.Constant) and weights_kw.value.value is True if weights_kw else False
            if not is_safe:
                _emit(
                    "AI-INFRA-DESER-002",
                    "Unsafe `torch.load()` without `weights_only=True`",
                    "CWE-502",
                    "CRITICAL" if weights_kw is not None else "HIGH",
                    0.91,
                    line_no,
                    f"`torch.load` in {rel_path}:{line_no} allows pickle RCE without `weights_only=True`.",
                )
        elif cname in ("yaml.unsafe_load", "yaml.load"):
            if cname == "yaml.unsafe_load":
                is_safe_yaml = False
            else:
                loader_node = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
                if loader_node is None and len(node.args) >= 2:
                    loader_node = node.args[1]
                loader_src = (
                    ast.unparse(loader_node)
                    if (loader_node is not None and hasattr(ast, "unparse"))
                    else ""
                )
                is_safe_yaml = (
                    loader_src in ("SafeLoader", "CSafeLoader", "yaml.SafeLoader", "yaml.CSafeLoader")
                    or loader_src.endswith((".SafeLoader", ".CSafeLoader"))
                )
            if not is_safe_yaml:
                _emit(
                    "AI-INFRA-DESER-002",
                    f"Unsafe YAML deserialization (`{cname}`)",
                    "CWE-502",
                    "HIGH",
                    0.89,
                    line_no,
                    f"`{cname}` without `SafeLoader` at {rel_path}:{line_no}.",
                )
        elif cname in ("jinja2.Template", "Template", "render_template_string"):
            _emit(
                "AI-INFRA-SSTI-003",
                f"Potential prompt/template SSTI via `{cname}`",
                "CWE-1336",
                "HIGH",
                0.84,
                line_no,
                f"Unsandboxed template rendering (`{cname}`) at {rel_path}:{line_no}.",
            )
        elif cname in ("jinja2.Environment", "Environment"):
            ae_kw = next((kw for kw in node.keywords if kw.arg == "autoescape"), None)
            if ae_kw is not None and isinstance(ae_kw.value, ast.Constant) and ae_kw.value.value is False:
                _emit(
                    "AI-INFRA-SSTI-003",
                    "Jinja2 `Environment(autoescape=False)` without SandboxedEnvironment",
                    "CWE-94",
                    "HIGH",
                    0.85,
                    line_no,
                    f"`Environment(autoescape=False)` at {rel_path}:{line_no}.",
                )
        elif cname in ("eval", "exec"):
            _emit(
                "AI-INFRA-SSTI-003",
                f"Dynamic Python code execution (`{cname}`)",
                "CWE-94",
                "HIGH",
                0.86,
                line_no,
                f"Dynamic `{cname}(...)` call at {rel_path}:{line_no}.",
            )

    # AST pass 2: DeepAudit intra-procedural source-to-sink taint
    for fn_node in ast.walk(tree):
        if not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tainted: Set[str] = {
            arg.arg
            for arg in fn_node.args.args + fn_node.args.kwonlyargs
            if arg.arg.lower() in _TAINT_SOURCES or any(s in arg.arg.lower() for s in ("prompt", "user_input", "tool_arg"))
        }
        sanitized: Set[str] = set()

        def _check_expr_sinks(expr_node: ast.AST, t_state: Set[str]) -> None:
            for sub in ast.walk(expr_node):
                if not isinstance(sub, ast.Call):
                    continue
                cname = _call_name(sub)
                is_shell_run = cname in ("subprocess.run", "subprocess.Popen", "subprocess.call") and any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in sub.keywords
                )
                is_cmd_sink = is_shell_run or cname in ("os.system", "eval", "exec")
                is_ssrf_sink = cname in ("requests.get", "requests.post", "httpx.get", "httpx.post")
                if (is_cmd_sink or is_ssrf_sink) and _expr_has_unsanitized_taint(sub, t_state):
                    cwe = "CWE-78" if is_cmd_sink else "CWE-918"
                    _emit(
                        "AI-INFRA-TAINT-005",
                        f"DeepAudit source-to-sink taint flow into `{cname}`",
                        cwe,
                        "HIGH",
                        0.87,
                        getattr(sub, "lineno", fn_node.lineno),
                        f"Untrusted input flows into `{cname}` without sanitization in `{fn_node.name}` ({rel_path}).",
                    )

        def _apply_assignment(
            targets: List[ast.AST],
            rhs: Optional[ast.AST],
            t_state: Set[str],
            s_state: Set[str],
            *,
            is_aug: bool = False,
        ) -> None:
            if rhs is None:
                return
            rhs_has_taint = _expr_has_unsanitized_taint(rhs, t_state) or (
                _expr_has_direct_source(rhs) and not _contains_sanitizer_call(rhs)
            )
            rhs_is_sanitized = _contains_sanitizer_call(rhs) and not _expr_has_unsanitized_taint(rhs, t_state)
            target_names: List[str] = []
            for t in targets:
                target_names.extend(_extract_target_names(t))
            if rhs_has_taint:
                for name in target_names:
                    s_state.discard(name)
                    t_state.add(name)
            elif rhs_is_sanitized and not is_aug:
                for name in target_names:
                    s_state.add(name)
                    t_state.discard(name)

        def _walk_stmts(
            stmts: List[ast.stmt],
            in_tainted: Set[str],
            in_sanitized: Set[str],
        ) -> Tuple[Set[str], Set[str]]:
            t_state = set(in_tainted)
            s_state = set(in_sanitized)
            for stmt in stmts:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue

                if isinstance(stmt, ast.Assign):
                    _check_expr_sinks(stmt.value, t_state)
                    _apply_assignment(list(stmt.targets), stmt.value, t_state, s_state)
                elif isinstance(stmt, ast.AnnAssign):
                    if stmt.value is not None:
                        _check_expr_sinks(stmt.value, t_state)
                        _apply_assignment([stmt.target], stmt.value, t_state, s_state)
                elif isinstance(stmt, ast.AugAssign):
                    _check_expr_sinks(stmt.value, t_state)
                    _apply_assignment([stmt.target], stmt.value, t_state, s_state, is_aug=True)
                elif isinstance(stmt, ast.If):
                    _check_expr_sinks(stmt.test, t_state)
                    base_t = set(t_state)
                    base_s = set(s_state)
                    body_t, body_s = _walk_stmts(stmt.body, base_t, base_s)
                    if stmt.orelse:
                        else_t, else_s = _walk_stmts(stmt.orelse, base_t, base_s)
                    else:
                        else_t, else_s = set(base_t), set(base_s)
                    t_state = body_t | else_t
                    s_state = body_s & else_s
                    # Recognize early-exit sanitizer guard: `if not sanitize(x): return/raise`
                    if (
                        not stmt.orelse
                        and isinstance(stmt.test, ast.UnaryOp)
                        and isinstance(stmt.test.op, ast.Not)
                        and isinstance(stmt.test.operand, ast.Call)
                        and _is_sanitizer_call(stmt.test.operand)
                        and stmt.body
                        and isinstance(stmt.body[-1], (ast.Return, ast.Raise))
                    ):
                        for arg in stmt.test.operand.args:
                            if isinstance(arg, ast.Name):
                                s_state.add(arg.id)
                                t_state.discard(arg.id)
                elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                    _check_expr_sinks(stmt.iter, t_state)
                    cur_t = set(t_state)
                    cur_s = set(s_state)
                    for _ in range(32):
                        iter_t = set(cur_t)
                        iter_s = set(cur_s)
                        _apply_assignment([stmt.target], stmt.iter, iter_t, iter_s)
                        body_t, body_s = _walk_stmts(stmt.body, iter_t, iter_s)
                        next_t = cur_t | body_t
                        next_s = cur_s & body_s
                        if next_t == cur_t and next_s == cur_s:
                            break
                        cur_t, cur_s = next_t, next_s
                    if stmt.orelse:
                        t_state, s_state = _walk_stmts(stmt.orelse, set(cur_t), set(cur_s))
                    else:
                        t_state, s_state = set(cur_t), set(cur_s)
                elif isinstance(stmt, ast.While):
                    cur_t = set(t_state)
                    cur_s = set(s_state)
                    for _ in range(32):
                        _check_expr_sinks(stmt.test, cur_t)
                        body_t, body_s = _walk_stmts(stmt.body, set(cur_t), set(cur_s))
                        next_t = cur_t | body_t
                        next_s = cur_s & body_s
                        if next_t == cur_t and next_s == cur_s:
                            break
                        cur_t, cur_s = next_t, next_s
                    _check_expr_sinks(stmt.test, cur_t)
                    if stmt.orelse:
                        t_state, s_state = _walk_stmts(stmt.orelse, set(cur_t), set(cur_s))
                    else:
                        t_state, s_state = set(cur_t), set(cur_s)
                elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                    for item in stmt.items:
                        _check_expr_sinks(item.context_expr, t_state)
                        if item.optional_vars is not None:
                            _apply_assignment([item.optional_vars], item.context_expr, t_state, s_state)
                    t_state, s_state = _walk_stmts(stmt.body, t_state, s_state)
                elif isinstance(stmt, ast.Try) or (
                    hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar)
                ):
                    base_t = set(t_state)
                    base_s = set(s_state)
                    body_t, body_s = _walk_stmts(stmt.body, base_t, base_s)
                    if stmt.orelse:
                        orelse_t, orelse_s = _walk_stmts(stmt.orelse, body_t, body_s)
                    else:
                        orelse_t, orelse_s = set(body_t), set(body_s)

                    handler_entry_t = base_t | body_t
                    handler_entry_s = base_s & body_s
                    handler_ts: List[Set[str]] = []
                    handler_ss: List[Set[str]] = []
                    for handler in stmt.handlers:
                        h_t, h_s = _walk_stmts(handler.body, handler_entry_t, handler_entry_s)
                        handler_ts.append(h_t)
                        handler_ss.append(h_s)

                    post_t_sets: List[Set[str]] = [orelse_t, *handler_ts]
                    post_s_sets: List[Set[str]] = [orelse_s, *handler_ss]
                    joined_t = set().union(*post_t_sets)
                    joined_s = set.intersection(*post_s_sets) if post_s_sets else set()
                    if stmt.finalbody:
                        _walk_stmts(stmt.finalbody, base_t | joined_t, base_s & joined_s)
                        t_state, s_state = _walk_stmts(stmt.finalbody, set(joined_t), set(joined_s))
                    else:
                        t_state, s_state = joined_t, joined_s
                elif hasattr(ast, "Match") and isinstance(stmt, ast.Match):
                    _check_expr_sinks(stmt.subject, t_state)
                    base_t = set(t_state)
                    base_s = set(s_state)
                    has_wildcard = any(
                        getattr(case, "guard", None) is None
                        and isinstance(case.pattern, ast.MatchAs)
                        and case.pattern.pattern is None
                        for case in stmt.cases
                    )
                    case_t_sets: List[Set[str]] = []
                    case_s_sets: List[Set[str]] = []
                    for case in stmt.cases:
                        if getattr(case, "guard", None) is not None:
                            _check_expr_sinks(case.guard, base_t)
                        c_t, c_s = _walk_stmts(case.body, base_t, base_s)
                        case_t_sets.append(c_t)
                        case_s_sets.append(c_s)
                    if not has_wildcard or not stmt.cases:
                        case_t_sets.append(set(base_t))
                        case_s_sets.append(set(base_s))
                    t_state = set().union(*case_t_sets)
                    s_state = set.intersection(*case_s_sets) if case_s_sets else set()
                else:
                    _check_expr_sinks(stmt, t_state)
            return t_state, s_state

        _walk_stmts(fn_node.body, tainted, sanitized)

    return findings


def _scan_js_ts_taint_and_eval(rel_path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for m in re.finditer(
        r"""(?:req\.body|req\.query|prompt|userInput)[\s\S]{0,200}?(?:execSync|exec|eval|fetch)\s*\(""",
        text,
    ):
        ctx = m.group(0)
        if "validate_target_host" in ctx or "sanitize" in ctx:
            continue
        line_no = text[: m.start()].count("\n") + 1
        findings.append(
            _make_finding(
                rule_id="AI-INFRA-TAINT-005",
                title="Untrusted AI/request input reaches dangerous JS/TS execution or fetch sink",
                cwe="CWE-78" if "exec" in ctx or "eval" in ctx else "CWE-918",
                severity="HIGH",
                confidence=0.81,
                file_path=rel_path,
                line=line_no,
                summary=f"Source-to-sink flow detected at {rel_path}:{line_no}.",
            )
        )
    return findings


def _audit_single_file(repo_root: Path, fpath: Path) -> List[Dict[str, Any]]:
    try:
        rel = fpath.relative_to(repo_root).as_posix()
        if fpath.stat().st_size > _MAX_FILE_BYTES:
            return []
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    hits: List[Dict[str, Any]] = []
    hits.extend(_scan_ai_bind_configs(rel, text))
    hits.extend(_scan_k8s_and_docker(rel, text))
    ext = fpath.suffix.lower()
    if ext == ".py":
        hits.extend(_scan_python_ast(rel, text))
    elif ext in (".ts", ".tsx", ".js", ".mjs"):
        hits.extend(_scan_js_ts_taint_and_eval(rel, text))
    return hits


def audit_ai_infra(
    repo_path: Union[Path, str],
    *,
    target_files: Optional[Sequence[Union[Path, str]]] = None,
) -> List[Dict[str, Any]]:
    """
    Multithreaded pure-Python static auditor for AI serving configs, deserialization,
    prompt SSTI, container/Kubernetes escapes, and source-to-sink taint flows.
    Supports diff-scoped `target_files` to avoid full-repository walks on `<72h` commits.
    """
    ok_mount, resolved_repo = validate_mount_path(repo_path)
    if not ok_mount:
        return []
    root = Path(resolved_repo)

    targets: List[Path] = []
    if target_files is not None:
        seen_paths: set[Path] = set()
        for raw_f in target_files:
            cand = Path(raw_f)
            cand = (root / cand).resolve() if not cand.is_absolute() else cand.resolve()
            try:
                cand.relative_to(root)
            except ValueError:
                continue
            if cand in seen_paths or not cand.is_file():
                continue
            seen_paths.add(cand)
            nl = cand.name.lower()
            if nl == "dockerfile" or nl.startswith(("dockerfile.", ".env")) or cand.suffix.lower() in _SCAN_EXTS:
                targets.append(cand)
    else:
        for walk_root, dirs, filenames in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
            for fname in sorted(filenames):
                fpath = Path(walk_root) / fname
                nl = fname.lower()
                if nl == "dockerfile" or nl.startswith(("dockerfile.", ".env")) or fpath.suffix.lower() in _SCAN_EXTS:
                    targets.append(fpath)

    if not targets:
        return []

    max_workers = min(8, max(2, os.cpu_count() or 4))
    findings: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for file_hits in pool.map(lambda p: _audit_single_file(root, p), targets):
            findings.extend(file_hits)

    findings.sort(key=lambda f: (f["file_path"], f["line"], f["rule_id"]))
    return findings
