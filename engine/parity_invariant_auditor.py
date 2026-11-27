"""
Sibling Parity & Invariant Auditor + Production Signal Noise Filter (M1 / Component 6).
=====================================================================================
Provides:
  1. `is_non_production_noise` & `filter_production_candidates` — deterministic
     suppression of test, fixture, example, docstring, and pure lint-hygiene noise
     while preserving `poc_verified == True` and production findings.
  2. `audit_parity_and_invariants` — discovers sibling packages/SDKs and same-file
     handlers to detect asymmetric security guard coverage (`sanitize*`, `CSP`,
     `allowFrom`, `verifySignature`, `O_NOFOLLOW`/symlink checks).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union


NOISE_DIR_SEGMENTS: frozenset[str] = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "__mocks__",
        "__fixtures__",
        "fixtures",
        "fixture",
        "example",
        "examples",
        "sample",
        "samples",
        "demo",
        "demos",
        "docs",
        "doc",
        "benchmark",
        "benchmarks",
        "testdata",
        "spec",
        "specs",
    }
)

NOISE_FILENAMES: frozenset[str] = frozenset(
    {
        "readme.md",
        "readme.txt",
        "readme.rst",
        "changelog.md",
        "changes.md",
        "contributing.md",
        "license",
        "license.md",
        "conftest.py",
    }
)

_SKIP_SCAN_DIRS: frozenset[str] = frozenset(
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
        "vendor",
    }
)

_SUPPORTED_EXTS: frozenset[str] = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".java", ".rb", ".rs"}
)

_MAX_FILE_BYTES = 1_048_576

_CONTAINER_ROOTS: frozenset[str] = frozenset(
    {
        "packages",
        "external_plugins",
        "plugins",
        "apps",
        "crates",
        "sdks",
        "sdk",
        "extensions",
        "modules",
        "services",
        "handlers",
        "routes",
        "entrypoints",
    }
)

GUARD_PATTERNS: Dict[str, Tuple[re.Pattern[str], str, str]] = {
    "sanitize_escape": (
        re.compile(
            r"\b(?:sanitize[A-Za-z0-9_]*|escapeHtml|escape_html|escape[A-Z][A-Za-z0-9_]*|"
            r"DOMPurify|bleach\.clean|html\.escape|encodeURIComponent)\b",
            re.IGNORECASE,
        ),
        "CWE-79",
        "sanitization / output escaping",
    ),
    "csp_nonce": (
        re.compile(
            r"(?:Content-Security-Policy|frame-ancestors|setCspHeaders|\bcsp\b|\bnonce\b)",
            re.IGNORECASE,
        ),
        "CWE-693",
        "Content-Security-Policy / frame-ancestors / nonce protection",
    ),
    "allowlist_authz": (
        re.compile(
            r"\b(?:allowFrom|isSelfChat|isDM|isAllowed|allowedSenders|"
            r"checkPermission|hasPermission|requireAuth|authenticate[A-Za-z0-9_]*|"
            r"authorize[A-Za-z0-9_]*|checkAuth|verifyAuth)\b"
        ),
        "CWE-862",
        "allowlist / authorization / authentication check",
    ),
    "signature_verify": (
        re.compile(
            r"\b(?:verifySignature|verifyHmac|timingSafeEqual|compare_digest|"
            r"verifyToken|verifyJwt|validateSignature|checkSignature)\b"
        ),
        "CWE-347",
        "cryptographic signature / HMAC verification",
    ),
    "symlink_path_guard": (
        re.compile(
            r"\b(?:O_NOFOLLOW|lstatSync|lstat|realpathSync|realpath|"
            r"is_symlink|is_relative_to|canonicalize)\b"
        ),
        "CWE-59",
        "symlink / canonical path containment guard",
    ),
}

_SEC_FN_NAME_RE = re.compile(
    r"^(?:renderAppBridge|handle[A-Za-z0-9_]*|on[A-Z][A-Za-z0-9_]*|"
    r"authenticate[A-Za-z0-9_]*|authorize[A-Za-z0-9_]*|"
    r"verify[A-Za-z0-9_]*|validate[A-Za-z0-9_]*|"
    r"check[A-Za-z0-9_]*|process[A-Za-z0-9_]*|"
    r"serve[A-Za-z0-9_]*|dispatch[A-Za-z0-9_]*|"
    r"resolve[A-Za-z0-9_]*|read_?file[A-Za-z0-9_]*)$"
)

_HANDLER_FN_NAME_RE = re.compile(
    r"^(?:handle[A-Za-z0-9_]*|on[A-Z][A-Za-z0-9_]*|process[A-Za-z0-9_]*|"
    r"dispatch[A-Za-z0-9_]*|serve[A-Za-z0-9_]*|route[A-Za-z0-9_]*|"
    r"webhook[A-Za-z0-9_]*|handler_[A-Za-z0-9_]+)$"
)

_PY_DEF_RE = re.compile(r"^([ \t]*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_RB_DEF_RE = re.compile(r"^([ \t]*)def\s+(?:self\.)?([A-Za-z_][A-Za-z0-9_!?]*)\b")
_GO_FUNC_RE = re.compile(
    r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_RUST_FN_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"
)
_JS_FN_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(
        r"^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("
    ),
    re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>"
    ),
    re.compile(
        r"^\s*(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^;]*\)\s*(?::[^{;]+)?\{"
    ),
)
_JAVA_METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?[A-Za-z0-9_<>\[\], ?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(?:throws\s+[^{]+)?\{"
)
_ROUTE_CALLBACK_RE = re.compile(
    r"""^\s*(?:app|router|bot|ipcMain)\.(get|post|put|patch|delete|use|on|handle)\s*\(\s*["']([^"']+)["']"""
)

_NON_FN_KEYWORDS: frozenset[str] = frozenset(
    {"if", "for", "while", "switch", "catch", "else", "return", "try", "class"}
)


def is_non_production_noise(
    file_path: str,
    metadata: Optional[Dict[str, Any]] = None,
    *,
    rule_id: str = "",
    summary: str = "",
) -> bool:
    """
    Returns True if a finding comes from tests, fixtures, examples, docs,
    docstrings, or pure lint/hygiene metadata rather than production code.
    """
    if isinstance(metadata, dict):
        if (
            metadata.get("non_production_noise") is True
            or metadata.get("hygiene_only") is True
            or metadata.get("in_docstring") is True
            or metadata.get("is_comment_only") is True
        ):
            return True

    fp = (file_path or "").strip().replace("\\", "/").lower()
    while fp.startswith("./"):
        fp = fp[2:]

    if fp:
        is_dir_path = fp.endswith("/")
        parts = [p for p in fp.split("/") if p]
        dir_parts = parts if is_dir_path else parts[:-1]
        if any(seg in NOISE_DIR_SEGMENTS for seg in dir_parts):
            return True
        if parts and not is_dir_path:
            base = parts[-1]
            if base in NOISE_FILENAMES:
                return True
            if base.endswith((".md", ".mdx", ".rst")):
                return True
            if base.endswith(("_test.go", "_test.py", "_test.rs", "_test.rb", "_spec.rb")):
                return True
            if base.startswith("test_") and base.endswith(".py"):
                return True
            if ".test." in base or ".spec." in base:
                return True

    rid = (rule_id or "").strip().upper()
    if (
        rid.startswith(("LINT-", "HYGIENE-"))
        or "-LINT-" in rid
        or "-HYGIENE-" in rid
        or rid.endswith(("-LINT", "-HYGIENE"))
    ):
        return True

    summ = (summary or "").strip().lower()
    if any(
        tok in summ
        for tok in ("[hygiene_only]", "hygiene_only", "lint hygiene", "in docstring", "comment-only")
    ):
        return True

    return False


def _extract_item_attr(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _set_noise_tag(item: Any, is_noise: bool) -> None:
    if isinstance(item, dict):
        item["non_production_noise"] = is_noise
        meta = item.get("metadata")
        if isinstance(meta, dict):
            meta["non_production_noise"] = is_noise
    else:
        meta = getattr(item, "metadata", None)
        if isinstance(meta, dict):
            meta["non_production_noise"] = is_noise
        try:
            setattr(item, "non_production_noise", is_noise)
        except (AttributeError, TypeError):
            pass


def _coerce_strict_bool(val: Any) -> bool:
    """Strictly coerce booleans without fail-open bool('false') / bool('0')."""
    if isinstance(val, bool):
        return val
    if isinstance(val, int) and not isinstance(val, bool):
        return val == 1
    if isinstance(val, str):
        return val.strip().lower() in {"true", "1", "yes", "on"}
    return False


def filter_production_candidates(
    findings: Sequence[Any],
) -> Tuple[List[Any], List[Any]]:
    """
    Partitions findings into `(production_findings, noise_findings)`.
    Findings with `poc_verified == True` ALWAYS remain in `production_findings`.
    """
    production: List[Any] = []
    noise: List[Any] = []
    for item in findings:
        meta = _extract_item_attr(item, "metadata", None)
        if not isinstance(meta, dict):
            meta = {}
        poc_verified = (
            _coerce_strict_bool(_extract_item_attr(item, "poc_verified", False))
            or _coerce_strict_bool(meta.get("poc_verified", False))
        )
        if poc_verified:
            _set_noise_tag(item, False)
            production.append(item)
            continue

        fp = str(_extract_item_attr(item, "file_path", "") or "")
        rid = str(_extract_item_attr(item, "rule_id", "") or "")
        summ = str(_extract_item_attr(item, "summary", "") or "")
        is_noise = is_non_production_noise(fp, meta, rule_id=rid, summary=summ)
        _set_noise_tag(item, is_noise)
        if is_noise:
            noise.append(item)
        else:
            production.append(item)
    return production, noise


@dataclass
class _ExtractedFunction:
    file_path: str
    line: int
    name: str
    norm_name: str
    group_root: str
    pkg_name: str
    is_handler: bool
    guards: Set[str]
    non_production_noise: bool


def _sibling_group_and_pkg(rel_path: str) -> Tuple[str, str]:
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
    if len(parts) < 2:
        return "", ""
    # e.g. packages/apps/shopify-app-remix/... -> group="packages/apps", pkg="shopify-app-remix"
    if parts[0] == "packages" and len(parts) >= 3:
        if parts[1] in ("apps", "plugins", "sdks", "sdk", "modules") or parts[1].startswith("@"):
            return f"{parts[0]}/{parts[1]}", parts[2]
        return parts[0], parts[1]
    if parts[0] in _CONTAINER_ROOTS and len(parts) >= 2:
        # e.g. external_plugins/foo/... -> group="external_plugins", pkg="foo"
        if len(parts) >= 3 or "." not in parts[1]:
            return parts[0], parts[1]
    if len(parts) >= 3 and parts[0] == "src" and parts[1] in _CONTAINER_ROOTS:
        return f"src/{parts[1]}", parts[2] if len(parts) >= 4 else ""
    return "", ""


def _extract_brace_body(lines: Sequence[str], start_idx: int, max_lines: int = 300) -> str:
    depth = 0
    saw_open = False
    collected: List[str] = []
    limit = min(len(lines), start_idx + max_lines)
    for idx in range(start_idx, limit):
        line = lines[idx]
        collected.append(line)
        # Strip quoted strings & // comments lightly before counting braces
        cleaned = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`', "", line)
        cleaned = re.sub(r"//.*$", "", cleaned)
        for ch in cleaned:
            if ch == "{":
                depth += 1
                saw_open = True
            elif ch == "}":
                depth -= 1
        if saw_open and depth <= 0:
            break
    return "\n".join(collected)


def _extract_indent_body(lines: Sequence[str], start_idx: int, base_indent: int, max_lines: int = 300) -> str:
    collected: List[str] = [lines[start_idx]]
    limit = min(len(lines), start_idx + max_lines)
    for idx in range(start_idx + 1, limit):
        line = lines[idx]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            collected.append(line)
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if indent <= base_indent:
            break
        collected.append(line)
    return "\n".join(collected)


_C_STR_OR_COMMENT_RE = re.compile(
    r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)|/\*[\s\S]*?\*/|//[^\n]*'
)
_PY_STR_OR_COMMENT_RE = re.compile(
    r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|#[^\n]*'
)


def _strip_comments_preserve_strings(body: str, ext: str = "") -> str:
    def _keep_str_only(m: re.Match[str]) -> str:
        return m.group(1) if m.group(1) is not None else " "

    ext_l = (ext or "").lower()
    if ext_l in (".py", ".rb"):
        return _PY_STR_OR_COMMENT_RE.sub(_keep_str_only, body)
    if ext_l in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".java", ".rs"):
        return _C_STR_OR_COMMENT_RE.sub(_keep_str_only, body)
    stripped = _C_STR_OR_COMMENT_RE.sub(_keep_str_only, body)
    return _PY_STR_OR_COMMENT_RE.sub(_keep_str_only, stripped)


def _strip_signature_header(body: str, ext: str = "") -> str:
    """
    Strips the function signature / parameter list before guard scanning so unused
    parameter names (e.g., `allowFrom: string[]`) never mask missing guards in the body.
    """
    ext_l = (ext or "").lower()
    if ext_l in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".java", ".rs"):
        brace_idx = body.find("{")
        if brace_idx != -1:
            return body[brace_idx + 1 :]
        arrow_idx = body.find("=>")
        if arrow_idx != -1:
            return body[arrow_idx + 2 :]
        return body
    if ext_l in (".py", ".rb"):
        lines = body.splitlines()
        if len(lines) > 1:
            return "\n".join(lines[1:])
        colon_idx = body.find(":")
        if colon_idx != -1:
            return body[colon_idx + 1 :]
    return body


def _detect_guards(body: str, ext: str = "") -> Set[str]:
    body_only = _strip_signature_header(body, ext=ext)
    cleaned = _strip_comments_preserve_strings(body_only, ext=ext)
    found: Set[str] = set()
    for gname, (pat, _, _) in GUARD_PATTERNS.items():
        if pat.search(cleaned):
            found.add(gname)
    return found


def _extract_functions_from_file(rel_path: str, text: str) -> List[_ExtractedFunction]:
    ext = Path(rel_path).suffix.lower()
    lines = text.splitlines()
    group_root, pkg_name = _sibling_group_and_pkg(rel_path)
    is_noise = is_non_production_noise(rel_path)
    out: List[_ExtractedFunction] = []
    seen_lines: Set[int] = set()

    for idx, line in enumerate(lines):
        line_no = idx + 1
        if line_no in seen_lines:
            continue

        fn_name: Optional[str] = None
        body: str = ""
        is_handler = False

        if ext == ".py":
            m = _PY_DEF_RE.match(line)
            if m:
                fn_name = m.group(2)
                body = _extract_indent_body(lines, idx, len(m.group(1)))
        elif ext == ".rb":
            m = _RB_DEF_RE.match(line)
            if m:
                fn_name = m.group(2)
                body = _extract_indent_body(lines, idx, len(m.group(1)))
        elif ext == ".go":
            m = _GO_FUNC_RE.match(line)
            if m:
                fn_name = m.group(1)
                body = _extract_brace_body(lines, idx)
        elif ext == ".rs":
            m = _RUST_FN_RE.match(line)
            if m:
                fn_name = m.group(1)
                body = _extract_brace_body(lines, idx)
        elif ext == ".java":
            m = _JAVA_METHOD_RE.match(line)
            if m:
                fn_name = m.group(1)
                body = _extract_brace_body(lines, idx)
        else:
            # JS / TS
            mr = _ROUTE_CALLBACK_RE.match(line)
            if mr:
                verb_or_evt = mr.group(1)
                target = re.sub(r"[^A-Za-z0-9_]+", "_", mr.group(2)).strip("_") or "root"
                fn_name = f"handler_{verb_or_evt}_{target}"
                is_handler = True
                body = _extract_brace_body(lines, idx)
            else:
                for pat in _JS_FN_PATTERNS:
                    mj = pat.match(line)
                    if mj:
                        cand = mj.group(1)
                        if cand not in _NON_FN_KEYWORDS:
                            fn_name = cand
                            body = _extract_brace_body(lines, idx)
                            break

        if not fn_name or not body:
            continue

        if _HANDLER_FN_NAME_RE.match(fn_name):
            is_handler = True

        guards = _detect_guards(body, ext=ext)
        if not (_SEC_FN_NAME_RE.match(fn_name) or is_handler or guards):
            continue

        seen_lines.add(line_no)
        norm_name = re.sub(r"[_\-]", "", fn_name).lower()
        out.append(
            _ExtractedFunction(
                file_path=rel_path,
                line=line_no,
                name=fn_name,
                norm_name=norm_name,
                group_root=group_root,
                pkg_name=pkg_name,
                is_handler=is_handler,
                guards=guards,
                non_production_noise=is_noise,
            )
        )

    return out


def _collect_repo_files(repo_root: Path, include_noise: bool) -> List[Tuple[str, Path]]:
    files: List[Tuple[str, Path]] = []
    for root, dirs, filenames in os.walk(repo_root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_SCAN_DIRS and not d.startswith(".git"))
        for fname in sorted(filenames):
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in _SUPPORTED_EXTS:
                continue
            try:
                rel = fpath.relative_to(repo_root).as_posix()
                if not include_noise and is_non_production_noise(rel):
                    continue
                if fpath.stat().st_size > _MAX_FILE_BYTES:
                    continue
                files.append((rel, fpath))
            except OSError:
                continue
    return files


def audit_parity_and_invariants(
    repo_path: Union[Path, str],
    *,
    target_files: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Scans `repo_path` for:
      - `PARITY-SIBLING-GUARD-001`: sibling packages/SDKs with matching security-critical
        functions where one package enforces a guard family and another omits it.
      - `PARITY-SAME-FILE-HANDLER-002`: parallel handlers in the same file where one
        enforces an auth/allowlist/signature/sanitization guard and another omits it.
    """
    root = Path(repo_path)
    if not root.exists() or not root.is_dir():
        return []

    norm_targets: Optional[Set[str]] = None
    if target_files is not None:
        norm_targets = set()
        for tf in target_files:
            tf_str = str(tf or "").strip()
            if not tf_str:
                continue
            try:
                tf_p = Path(tf_str)
                if tf_p.is_absolute():
                    norm_targets.add(tf_p.resolve().relative_to(root.resolve()).as_posix())
                    continue
            except (OSError, ValueError):
                pass
            norm_targets.add(tf_str.replace("\\", "/").lstrip("./"))

    candidates = _collect_repo_files(root, include_noise=bool(norm_targets))
    if not candidates:
        return []

    def _scan_one(item: Tuple[str, Path]) -> List[_ExtractedFunction]:
        rel, fpath = item
        if is_non_production_noise(rel) and (not norm_targets or rel not in norm_targets):
            return []
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return _extract_functions_from_file(rel, text)

    max_workers = min(8, max(2, os.cpu_count() or 4))
    all_funcs: List[_ExtractedFunction] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for fn_list in pool.map(_scan_one, candidates):
            all_funcs.extend(fn_list)

    findings: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[str, str, int, str]] = set()

    # 1. Sibling package / SDK parity
    sibling_groups: Dict[Tuple[str, str], List[_ExtractedFunction]] = {}
    for fn in all_funcs:
        if fn.group_root and fn.pkg_name and not fn.non_production_noise:
            sibling_groups.setdefault((fn.group_root, fn.norm_name), []).append(fn)

    for (group_root, _norm_name), fns in sibling_groups.items():
        distinct_pkgs = {f.pkg_name for f in fns}
        if len(distinct_pkgs) < 2:
            continue
        union_guards: Dict[str, List[str]] = {}
        for f in fns:
            for g in f.guards:
                union_guards.setdefault(g, [])
                if f.pkg_name not in union_guards[g]:
                    union_guards[g].append(f.pkg_name)

        for f in fns:
            missing = sorted(g for g in union_guards if g not in f.guards)
            if not missing:
                continue
            primary_guard = missing[0]
            _, cwe, guard_desc = GUARD_PATTERNS[primary_guard]
            ref_pkgs = sorted(union_guards[primary_guard])
            dedup = ("PARITY-SIBLING-GUARD-001", f.file_path, f.line, primary_guard)
            if dedup in seen_keys:
                continue
            seen_keys.add(dedup)
            findings.append(
                {
                    "engine": "parity_auditor",
                    "rule_id": "PARITY-SIBLING-GUARD-001",
                    "title": f"Sibling parity gap in `{f.name}` ({f.pkg_name}) missing {primary_guard}",
                    "cwe": cwe,
                    "severity": "HIGH",
                    "confidence": 0.82,
                    "file_path": f.file_path,
                    "line": f.line,
                    "summary": (
                        f"Function `{f.name}` in sibling `{group_root}/{f.pkg_name}` omits {guard_desc} "
                        f"({', '.join(missing)}), whereas sibling package(s) {ref_pkgs} enforce it."
                    ),
                    "deterministic": True,
                    "confirmed": True,
                    "non_production_noise": f.non_production_noise,
                    "metadata": {
                        "group_root": group_root,
                        "package": f.pkg_name,
                        "function": f.name,
                        "missing_guards": missing,
                        "reference_packages": ref_pkgs,
                        "non_production_noise": f.non_production_noise,
                    },
                }
            )

    # 2. Same-file handler asymmetry
    by_file: Dict[str, List[_ExtractedFunction]] = {}
    for fn in all_funcs:
        if fn.is_handler:
            by_file.setdefault(fn.file_path, []).append(fn)

    for rel_path, handlers in by_file.items():
        if len(handlers) < 2:
            continue
        guard_holders: Dict[str, List[str]] = {}
        for h in handlers:
            for g in h.guards:
                guard_holders.setdefault(g, []).append(h.name)

        if not guard_holders:
            continue

        for h in handlers:
            missing = sorted(g for g in guard_holders if g not in h.guards)
            if not missing:
                continue
            primary_guard = missing[0]
            _, cwe, guard_desc = GUARD_PATTERNS[primary_guard]
            ref_handlers = sorted(guard_holders[primary_guard])
            dedup = ("PARITY-SAME-FILE-HANDLER-002", h.file_path, h.line, primary_guard)
            if dedup in seen_keys:
                continue
            seen_keys.add(dedup)
            findings.append(
                {
                    "engine": "parity_auditor",
                    "rule_id": "PARITY-SAME-FILE-HANDLER-002",
                    "title": f"Same-file handler asymmetry: `{h.name}` omits {primary_guard}",
                    "cwe": cwe,
                    "severity": "HIGH",
                    "confidence": 0.86,
                    "file_path": h.file_path,
                    "line": h.line,
                    "summary": (
                        f"Handler `{h.name}` in `{h.file_path}` omits {guard_desc} "
                        f"({', '.join(missing)}), unlike sibling handler(s) {ref_handlers} in the same file."
                    ),
                    "deterministic": True,
                    "confirmed": True,
                    "non_production_noise": h.non_production_noise,
                    "metadata": {
                        "function": h.name,
                        "missing_guards": missing,
                        "reference_handlers": ref_handlers,
                        "non_production_noise": h.non_production_noise,
                    },
                }
            )

    if norm_targets is not None:
        findings = [f for f in findings if f["file_path"] in norm_targets]

    findings.sort(key=lambda f: (f["file_path"], f["line"], f["rule_id"]))
    return findings
