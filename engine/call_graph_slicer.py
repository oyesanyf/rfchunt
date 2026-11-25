"""
Whole-Repo Multi-Language Call-Graph & Taint Slicer (AIxCC Upgrade #2).

Builds cross-file call graphs and source-to-sink taint slices across Python,
TypeScript/JavaScript, Rust, Go, C/C++, and Java repositories so 8B-14B local
models receive focused multi-file execution paths (`entry point -> middleware
-> sanitizer -> sink`) rather than blind fixed-line chunks.

Parser strategy:
1. Dynamically uses `tree_sitter` (with `tree_sitter_language_pack`,
   `tree_sitter_languages`, or per-language `tree_sitter_<lang>` bindings)
   whenever installed.
2. Falls back cleanly to genuine structural AST / scope-aware multi-file
   symbol-table parsing (`ast` for Python; comment/string-aware brace-balanced
   tokenizer & import/route/call/assignment extractor for TS/JS/Rust/Go/C/Java)
   when a Tree-sitter grammar binding is absent.
3. Optionally integrates with the `codeql` CLI (`shell=False`) for SARIF/BQRS
   path extraction when explicitly present and enabled, returning a structured
   detection report when absent.
"""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
import hashlib
import importlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

logger = logging.getLogger("terminator.call_graph_slicer")

# =============================================================================
# Constants & Language Tables
# =============================================================================

LANGUAGE_BY_EXT: Dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".rs": "rust",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".java": "java",
}

SKIP_DIR_NAMES: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".swarm_workspaces",
    "vendor",
    "coverage",
    ".next",
    ".nuxt",
    "yara",
    "rules",
    "reports",
    "runs",
    "logs",
    "caldera_export",
    "caldera_plugin",
}

CONTROL_KEYWORDS: Set[str] = {
    "if",
    "else",
    "elif",
    "for",
    "while",
    "switch",
    "case",
    "catch",
    "try",
    "finally",
    "match",
    "loop",
    "return",
    "yield",
    "await",
    "throw",
    "raise",
    "sizeof",
    "typeof",
    "new",
    "delete",
    "synchronized",
    "with",
    "assert",
    "select",
    "defer",
    "go",
}

CWE_BY_CLASS: Dict[str, Tuple[str, str]] = {
    "command_injection": ("CWE-78", "CRITICAL"),
    "code_execution": ("CWE-94", "CRITICAL"),
    "sql_injection": ("CWE-89", "CRITICAL"),
    "deserialization": ("CWE-502", "CRITICAL"),
    "path_traversal": ("CWE-22", "HIGH"),
    "ssrf": ("CWE-918", "HIGH"),
    "memory_unsafe": ("CWE-119", "HIGH"),
    "xss": ("CWE-79", "MEDIUM"),
    "open_redirect": ("CWE-601", "MEDIUM"),
    "auth_bypass": ("CWE-287", "HIGH"),
    "taint_flow": ("CWE-20", "MEDIUM"),
}

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# Source indicators (user-controlled inputs)
_SOURCE_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("http_request_input", re.compile(r"\b(?:request|req)\s*\.\s*(?:args|form|json|data|values|files|headers|cookies|body|query|params|query_params|get_json|text)\b")),
    ("http_query_getter", re.compile(r"\b(?:getParameter|getHeader|getQueryString|FormValue|URL\.Query|PostFormValue|ReadAll)\s*\(")),
    ("rust_http_extractor", re.compile(r"\b(?:web::Query|web::Json|web::Path|web::Form|extract::Query|extract::Json|extract::Path|HttpRequest|Request<|Query<|Json<|Path<)")),
    ("cli_or_env_input", re.compile(r"\b(?:sys\.argv|std::env::args|os\.Args|process\.argv|os\.environ|getenv|input\s*\(|fgets\s*\(|recv\s*\(|scanf\s*\()")),
    ("framework_param", re.compile(r"@(?:RequestParam|RequestBody|PathVariable|QueryParam|HeaderParam)\b")),
    ("llm_tool_arg", re.compile(r"\b(?:tool_call\.function\.arguments|tool_use\.input|function_call\.arguments|tool_args|agent_action\.tool_input)\b")),
    ("llm_response_output", re.compile(r"\b(?:choices\[0\]\.message\.content|completion\.content|generate_content\([^)]*\)\.text|llm\.invoke\(|model_response|llm_output)\b")),
)

# Strong vs weak sanitizer patterns
_STRONG_SANITIZER_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("shlex_quote", re.compile(r"\bshlex\s*\.\s*(?:quote|split)\b")),
    ("html_escape", re.compile(r"\b(?:html\.escape|markupsafe\.escape|bleach\.clean|DOMPurify\.sanitize|escapeHtml|encodeURIComponent|HtmlUtils\.htmlEscape)\b")),
    ("strict_allowlist", re.compile(r"\b(?:is_relative_to|commonpath|fullmatch|isAlphanumeric|ALLOWED_(?:CMDS|COMMANDS|HOSTS|PATHS)|allowlist)\b", re.IGNORECASE)),
    ("parameterized_sql", re.compile(r"\b(?:PreparedStatement|sqlx::query!|bind_param|setString)\b")),
    ("safe_yaml", re.compile(r"\byaml\s*\.\s*safe_load\b")),
)

_WEAK_SANITIZER_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("blacklist_replace", re.compile(r"\.\s*replace\s*\(\s*['\"`](?:\.\.|;|&&|\||<script|'|--|\$\(|`|\.\./)['\"`]")),
    ("regex_strip_blacklist", re.compile(r"\b(?:re\.sub|replaceAll|replace)\s*\([^)]*(?:;|&&|\||<script|\.\.)")),
    ("trim_or_strip_only", re.compile(r"\.\s*(?:strip|trim|lstrip|rstrip)\s*\(\s*\)")),
    ("denylist_check", re.compile(r"\b(?:blacklist|denylist|forbidden|blocked_chars|bad_chars)\b", re.IGNORECASE)),
)

_SANITIZER_NAME_RX = re.compile(
    r"(?:sanitiz|clean|escap|filter|validat|scrub|purify|normaliz|encode|strip|safe_)",
    re.IGNORECASE,
)
_MIDDLEWARE_NAME_RX = re.compile(
    r"(?:middleware|mw_|_mw$|guard|auth|verify|intercept|dispatch|pre_?process|pipeline|router_?wrap|filter_?req|check_?req)",
    re.IGNORECASE,
)
_ENTRY_NAME_RX = re.compile(
    r"(?:^(?:handle|api|route|endpoint|view|controller|serve|do_GET|do_POST|do_PUT|do_DELETE|main)|(?:_handler|_endpoint|_route|_view|Handler|Controller)$)",
)

# Sink patterns mapped to vulnerability class
_SINK_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("command_injection", re.compile(r"\b(?:os\.system|os\.popen|subprocess\.(?:run|Popen|call|check_output|check_call)|child_process\.(?:exec|execSync|spawn|spawnSync)|execSync|execFile|Command::new|std::process::Command::new|exec\.Command|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|popen)\s*\(")),
    ("command_injection", re.compile(r"(?:^|[^\w.])(?:exec|system)\s*\(")),
    ("code_execution", re.compile(r"\b(?:eval|vm\.runInNewContext|vm\.runInContext|vm\.runInThisContext|ScriptEngine\.eval|new\s+Function)\s*\(")),
    ("sql_injection", re.compile(r"\b(?:cursor\.execute|conn\.execute|db\.execute|db\.query|pool\.query|connection\.query|sequelize\.query|sqlx::query|stmt\.executeQuery|stmt\.execute|db\.Exec|db\.Query)\s*\(")),
    ("path_traversal", re.compile(r"\b(?:fs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|openSync)|std::fs::(?:read|read_to_string|write|File::open)|File::open|os\.(?:Open|ReadFile|WriteFile)|ioutil\.ReadFile|Files\.(?:readString|readAllBytes|write)|send_file|sendFile|fopen)\s*\(")),
    ("path_traversal", re.compile(r"(?:^|[^\w.])open\s*\(")),
    ("ssrf", re.compile(r"\b(?:requests\.(?:get|post|put|delete|request)|httpx\.(?:get|post|request)|urllib\.request\.urlopen|axios\.(?:get|post|request)|reqwest::(?:get|Client)|http\.Get|openConnection)\s*\(")),
    ("ssrf", re.compile(r"(?:^|[^\w.])fetch\s*\(")),
    ("deserialization", re.compile(r"\b(?:pickle\.loads?|marshal\.loads?|yaml\.load|ObjectInputStream|readObject|unserialize)\s*\(")),
    ("xss", re.compile(r"\b(?:render_template_string|dangerouslySetInnerHTML|innerHTML|document\.write|Markup)\b")),
    ("memory_unsafe", re.compile(r"\b(?:strcpy|strcat|sprintf|gets|memcpy|from_raw_parts)\s*\(")),
)

_ROUTE_DECORATOR_RX = re.compile(
    r"""(?:@|#\[)\s*(?:[\w.]+\.)?(?:route|get|post|put|patch|delete|options|head|api_view|GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping|Path)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_TS_JS_ROUTE_CALL_RX = re.compile(
    r"""\b(?P<obj>[A-Za-z_$][\w$]*)\s*\.\s*(?P<method>get|post|put|patch|delete|all|use)\s*\(\s*(?:(?P<quote>['"`])(?P<path>[^'"`]*)(?P=quote)\s*,\s*)?(?P<args>[^;)]+)\)""",
    re.IGNORECASE,
)

_GO_ROUTE_CALL_RX = re.compile(
    r"""\b(?P<obj>[A-Za-z_]\w*)\s*\.\s*(?P<method>HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Use)\s*\(\s*(?:"(?P<path>[^"]*)"\s*,\s*)?(?P<args>[^)\n]+)\)""",
)

_RUST_ROUTE_CALL_RX = re.compile(
    r"""\.\s*route\s*\(\s*"(?P<path>[^"]+)"\s*,\s*(?P<method>get|post|put|patch|delete|any)\s*\(\s*(?P<handler>[A-Za-z_][\w:]*)\s*\)\s*\)""",
)

_RUST_LAYER_RX = re.compile(
    r"""\.\s*(?:layer|route_layer)\s*\(\s*(?:[\w:]+::)?(?:from_fn\s*\(\s*)?(?P<mw>[A-Za-z_][\w:]*)\s*\)?""",
)


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class ImportRecord:
    module: str
    names: Dict[str, str] = field(default_factory=dict)  # local_alias -> original_name ("*" for namespace)
    level: int = 0
    line: int = 1


@dataclass
class CallSite:
    callee_name: str
    qualifier: Optional[str] = None
    line: int = 1
    arguments: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    is_return: bool = False
    raw_expr: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RouteRegistration:
    method: str
    route_path: str
    handlers: List[str]
    file_path: str
    line: int
    is_middleware_use: bool = False


@dataclass
class SymbolNode:
    symbol_id: str
    name: str
    qualified_name: str
    file_path: str
    language: str
    start_line: int
    end_line: int
    params: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    role: str = "helper"
    roles: List[str] = field(default_factory=list)
    route_pattern: Optional[str] = None
    source_indicators: List[str] = field(default_factory=list)
    sanitizer_indicators: List[str] = field(default_factory=list)
    sanitizer_strength: str = "none"  # "none" | "weak" | "strong"
    sink_matches: List[Dict[str, Any]] = field(default_factory=list)
    calls: List[CallSite] = field(default_factory=list)
    assignments: Dict[str, Set[str]] = field(default_factory=dict)  # var -> referenced vars/calls
    parser_backend: str = "structural_ast"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symbol_id": self.symbol_id,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "file_path": self.file_path,
            "language": self.language,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "params": list(self.params),
            "decorators": list(self.decorators),
            "role": self.role,
            "roles": list(self.roles),
            "route_pattern": self.route_pattern,
            "source_indicators": list(self.source_indicators),
            "sanitizer_indicators": list(self.sanitizer_indicators),
            "sanitizer_strength": self.sanitizer_strength,
            "sink_matches": list(self.sink_matches),
            "parser_backend": self.parser_backend,
        }


@dataclass
class CallEdge:
    caller_id: str
    callee_id: str
    file_path: str
    line: int
    edge_kind: str = "direct_call"  # "direct_call" | "middleware_chain" | "route_handler" | "codeql_flow"
    tainted_args: List[str] = field(default_factory=list)
    confidence: float = 0.8

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SliceStep:
    step_index: int
    role: str  # "entry_point" | "middleware" | "sanitizer" | "propagation" | "sink"
    symbol_id: str
    symbol_name: str
    file_path: str
    start_line: int
    end_line: int
    call_line: Optional[int]
    language: str
    snippet: str
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaintSlice:
    slice_id: str
    vulnerability_class: str
    cwe: str
    severity: str
    entry_point: str
    sink: str
    sink_call: str
    sink_file: str
    sink_line: int
    steps: List[SliceStep]
    files_involved: List[str]
    is_cross_file: bool
    sanitizers: List[Dict[str, Any]]
    sanitizer_status: str  # "unsanitized" | "weak_sanitizer" | "sanitized"
    taint_confidence: float
    poe_hint: int
    source_backend: str
    prompt_context: str = ""

    def to_prompt_block(self, max_chars: int = 4000) -> str:
        """Formats a concise, token-budgeted, XML-nonce-fenced multi-file prompt block for 8B-14B models."""
        from engine.execution_policy import sanitize_for_llm_prompt

        chain_arrow = " -> ".join(
            f"{s.role}:{s.symbol_name} ({s.file_path}:L{s.start_line}-L{s.end_line})"
            for s in self.steps
        )
        san_desc = (
            ", ".join(
                f"{item.get('symbol_name') or item.get('symbol_id')} [{item.get('strength', 'unknown')}]"
                for item in self.sanitizers
            )
            if self.sanitizers
            else "none"
        )
        lines: List[str] = [
            f"=== TAINT SLICE {self.slice_id} ===",
            f"Class: {self.vulnerability_class} ({self.cwe}) | Severity: {self.severity} | "
            f"SanitizerStatus: {self.sanitizer_status} ({san_desc}) | Confidence: {self.taint_confidence:.2f}",
            f"Chain: {chain_arrow}",
            f"Sink: {self.sink_call} at {self.sink_file}:L{self.sink_line}",
            f"Files ({len(self.files_involved)}): {', '.join(self.files_involved)}",
        ]
        total_budget = max(600, int(max_chars))
        wrapper_overhead = 96
        inner_budget = max(200, total_budget - wrapper_overhead)
        per_step_budget = max(160, (inner_budget - sum(len(x) + 1 for x in lines)) // max(1, len(self.steps)))

        for step in self.steps:
            header = (
                f"\n--- Step {step.step_index + 1} [{step.role.upper()}] "
                f"{step.symbol_name} ({step.file_path}:L{step.start_line}-L{step.end_line})"
            )
            if step.call_line:
                header += f" @call:L{step.call_line}"
            if step.notes:
                header += f" | {step.notes}"
            header += " ---"
            snippet = step.snippet.strip()
            if len(snippet) > per_step_budget:
                snippet = snippet[: max(80, per_step_budget - 18)].rstrip() + "\n... [truncated]"
            lines.append(header)
            lines.append(snippet)

        rendered = "\n".join(lines)
        if len(rendered) > inner_budget:
            rendered = rendered[: max(120, inner_budget - 16)].rstrip() + "\n... [truncated]"
        fenced = sanitize_for_llm_prompt(rendered, max_chars=inner_budget, source="taint_slice")
        if len(fenced) > total_budget:
            # Guard against expansion from neutralized injection tokens exceeding total_budget
            m_open = re.match(r'^(<untrusted_data nonce="[^"]+">\n)', fenced)
            closing = "\n</untrusted_data>"
            if m_open and fenced.endswith(closing):
                open_tag = m_open.group(1)
                body = fenced[len(open_tag) : -len(closing)]
                max_body = max(100, total_budget - len(open_tag) - len(closing))
                if len(body) > max_body:
                    trunc_marker = "\n... [truncated]"
                    body = body[: max(40, max_body - len(trunc_marker))].rstrip()
                    body = re.sub(r"(?i)<\s*/?\s*untrusted_data(?:\b[^>]*)?>?$", "", body).rstrip()
                    body = f"{body}{trunc_marker}"
                fenced = f"{open_tag}{body}{closing}"
        return fenced

    def to_escalation_candidate(self) -> Dict[str, Any]:
        """Exports this slice into the normalized schema consumed by `TieredModelRouter`."""
        return {
            "candidate_id": self.slice_id,
            "title": f"{self.vulnerability_class} ({self.cwe}) across {len(self.files_involved)} file(s)",
            "vulnerability_class": self.vulnerability_class,
            "cwe": self.cwe,
            "severity": self.severity,
            "poe_level": self.poe_hint,
            "signal_score": self.taint_confidence,
            "is_multi_file_chain": self.is_cross_file,
            "files_involved": list(self.files_involved),
            "sanitizer_status": self.sanitizer_status,
            "entry_point": self.entry_point,
            "sink": self.sink,
            "prompt_context": self.prompt_context or self.to_prompt_block(),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slice_id": self.slice_id,
            "vulnerability_class": self.vulnerability_class,
            "cwe": self.cwe,
            "severity": self.severity,
            "entry_point": self.entry_point,
            "sink": self.sink,
            "sink_call": self.sink_call,
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "steps": [s.to_dict() for s in self.steps],
            "files_involved": list(self.files_involved),
            "is_cross_file": self.is_cross_file,
            "sanitizers": list(self.sanitizers),
            "sanitizer_status": self.sanitizer_status,
            "taint_confidence": self.taint_confidence,
            "poe_hint": self.poe_hint,
            "source_backend": self.source_backend,
            "prompt_context": self.prompt_context,
        }


@dataclass
class CodeQLReport:
    available: bool = False
    binary_path: Optional[str] = None
    version: Optional[str] = None
    enabled: bool = False
    executed: bool = False
    status: str = "disabled"  # "disabled" | "unavailable" | "detected" | "executed" | "failed" | "skipped_no_database"
    sarif_paths: List[str] = field(default_factory=list)
    bqrs_paths: List[str] = field(default_factory=list)
    extracted_slices: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CallGraphContext:
    """In-memory parsed AST + forward/reverse call-graph context for downstream static passes."""

    repo_root: Path
    parsed_files: Dict[str, _ParsedFile]
    symbols_by_id: Dict[str, SymbolNode]
    adj: Dict[str, List[CallEdge]]
    rev_adj: Dict[str, List[CallEdge]]
    edges: List[CallEdge]
    report: "CallGraphReport"


@dataclass
class CallGraphReport:
    repo_root: str
    files_scanned: int
    languages_detected: Dict[str, int]
    parser_backends: Dict[str, str]
    tree_sitter_available: bool
    symbols_count: int
    edges_count: int
    slices: List[TaintSlice]
    cross_file_slices_count: int
    codeql: CodeQLReport
    elapsed_sec: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo_root": self.repo_root,
            "files_scanned": self.files_scanned,
            "languages_detected": dict(self.languages_detected),
            "parser_backends": dict(self.parser_backends),
            "tree_sitter_available": self.tree_sitter_available,
            "symbols_count": self.symbols_count,
            "edges_count": self.edges_count,
            "slices": [s.to_dict() for s in self.slices],
            "cross_file_slices_count": self.cross_file_slices_count,
            "codeql": self.codeql.to_dict(),
            "elapsed_sec": round(self.elapsed_sec, 4),
        }


@dataclass
class _ParsedFile:
    rel_path: str
    abs_path: Path
    language: str
    parser_backend: str
    lines: List[str]
    imports: List[ImportRecord] = field(default_factory=list)
    symbols: List[SymbolNode] = field(default_factory=list)
    routes: List[RouteRegistration] = field(default_factory=list)


# =============================================================================
# Comment/String-Aware Structural Scanner Helpers
# =============================================================================


def _strip_comments_preserve_lines(source: str, language: str) -> str:
    """
    Removes comments while keeping line count and character offsets aligned
    and preserving string literals untouched.
    """
    n = len(source)
    out: List[str] = []
    i = 0
    nested_block = language == "rust"

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        # Rust raw string r#"..."#
        if language == "rust" and ch == "r" and nxt in ('"', "#"):
            j = i + 1
            hashes = 0
            while j < n and source[j] == "#":
                hashes += 1
                j += 1
            if j < n and source[j] == '"':
                end_delim = '"' + ("#" * hashes)
                end_pos = source.find(end_delim, j + 1)
                if end_pos == -1:
                    out.append(source[i:])
                    break
                out.append(source[i : end_pos + len(end_delim)])
                i = end_pos + len(end_delim)
                continue

        # Single-line // comments
        if ch == "/" and nxt == "/":
            j = i + 2
            while j < n and source[j] not in ("\n", "\r"):
                j += 1
            out.append(" " * (j - i))
            i = j
            continue

        # Block /* ... */ comments
        if ch == "/" and nxt == "*":
            depth = 1
            j = i + 2
            out.append("  ")
            while j < n and depth > 0:
                c1 = source[j]
                c2 = source[j + 1] if j + 1 < n else ""
                if nested_block and c1 == "/" and c2 == "*":
                    depth += 1
                    out.append("  ")
                    j += 2
                elif c1 == "*" and c2 == "/":
                    depth -= 1
                    out.append("  ")
                    j += 2
                elif c1 in ("\n", "\r"):
                    out.append(c1)
                    j += 1
                else:
                    out.append(" ")
                    j += 1
            i = j
            continue

        # String / template / char literals
        if ch in ('"', "'", "`"):
            quote = ch
            # In Rust, `'a` is a lifetime rather than a char literal unless followed by closing `'`
            if language == "rust" and quote == "'":
                if i + 2 < n and source[i + 1] == "\\":
                    end_char = source.find("'", i + 3)
                    if end_char != -1 and end_char - i <= 8:
                        out.append(source[i : end_char + 1])
                        i = end_char + 1
                        continue
                elif i + 2 < n and source[i + 2] == "'":
                    out.append(source[i : i + 3])
                    i += 3
                    continue
                out.append(ch)
                i += 1
                continue

            j = i + 1
            while j < n:
                cj = source[j]
                if cj == "\\" and quote != "`":
                    j += 2
                    continue
                if cj == quote:
                    j += 1
                    break
                if cj == "\n" and quote != "`":
                    break
                j += 1
            out.append(source[i:j])
            i = j
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _find_matching_brace(text: str, open_pos: int) -> int:
    """Finds the matching '}' for '{' at `open_pos`, ignoring strings/chars."""
    n = len(text)
    depth = 0
    i = open_pos
    while i < n:
        ch = text[i]
        if ch in ('"', "'", "`"):
            quote = ch
            i += 1
            while i < n:
                if text[i] == "\\" and quote != "`":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                if text[i] == "\n" and quote != "`":
                    break
                i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def _find_matching_paren(text: str, open_pos: int) -> int:
    """Finds the matching ')' for '(' at `open_pos`, ignoring strings/chars."""
    n = len(text)
    depth = 0
    i = open_pos
    while i < n:
        ch = text[i]
        if ch in ('"', "'", "`"):
            quote = ch
            i += 1
            while i < n:
                if text[i] == "\\" and quote != "`":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                if text[i] == "\n" and quote != "`":
                    break
                i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _split_top_level_args(arg_str: str) -> List[str]:
    """Splits a call argument list on top-level commas, respecting nested brackets/strings."""
    args: List[str] = []
    buf: List[str] = []
    depth_p = depth_b = depth_c = 0
    i = 0
    n = len(arg_str)
    while i < n:
        ch = arg_str[i]
        if ch in ('"', "'", "`"):
            quote = ch
            buf.append(ch)
            i += 1
            while i < n:
                buf.append(arg_str[i])
                if arg_str[i] == "\\" and quote != "`" and i + 1 < n:
                    i += 1
                    buf.append(arg_str[i])
                elif arg_str[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == "(":
            depth_p += 1
        elif ch == ")":
            depth_p = max(0, depth_p - 1)
        elif ch == "[":
            depth_b += 1
        elif ch == "]":
            depth_b = max(0, depth_b - 1)
        elif ch == "{":
            depth_c += 1
        elif ch == "}":
            depth_c = max(0, depth_c - 1)
        elif ch == "," and depth_p == 0 and depth_b == 0 and depth_c == 0:
            item = "".join(buf).strip()
            if item:
                args.append(item)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        args.append(tail)
    return args


def _offset_to_line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _extract_param_names(raw_params: str, language: str) -> List[str]:
    params: List[str] = []
    for part in _split_top_level_args(raw_params):
        cleaned = part.strip()
        if not cleaned or cleaned in ("self", "&self", "&mut self", "mut self", "void", "..."):
            continue
        # Remove default value
        cleaned = cleaned.split("=", 1)[0].strip()
        if language in ("typescript", "javascript", "rust"):
            # `name: Type` or `mut name: Type`
            lhs = cleaned.split(":", 1)[0].strip()
            lhs = re.sub(r"^(?:mut|ref|readonly|public|private|protected|\.\.\.)\s+", "", lhs).strip()
            m = re.search(r"([A-Za-z_$][\w$]*)$", lhs)
            if m:
                params.append(m.group(1))
        elif language == "go":
            tokens = cleaned.split()
            if tokens:
                params.append(tokens[0].lstrip("*"))
        else:
            # C/C++/Java: `const Type *name`
            cleaned = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", cleaned).strip()
            m = re.search(r"([A-Za-z_]\w*)\s*(?:\[\s*\])?$", cleaned)
            if m:
                params.append(m.group(1))
    return params


def _extract_identifiers(expr: str) -> Set[str]:
    return {
        tok
        for tok in re.findall(r"\b[A-Za-z_$][\w$]*\b", expr)
        if tok not in CONTROL_KEYWORDS and tok not in ("true", "false", "null", "None", "True", "False", "undefined")
    }


def _build_focused_snippet(
    lines: List[str],
    start_line: int,
    end_line: int,
    focus_lines: Optional[Sequence[int]] = None,
    max_lines: int = 18,
) -> str:
    """
    Produces a focused, line-numbered snippet for a symbol:
    keeps the declaration signature + highlighted focus lines (taint/sanitizer/call/sink)
    rather than blindly slicing an arbitrary 30-line window.
    """
    if not lines:
        return ""
    s = max(1, start_line)
    e = min(len(lines), max(s, end_line))
    total = e - s + 1
    if total <= max_lines:
        return "\n".join(f"L{ln}: {lines[ln - 1]}" for ln in range(s, e + 1))

    keep: Set[int] = set(range(s, min(e + 1, s + 4)))
    keep.add(e)
    for fl in (focus_lines or ()):
        if s <= fl <= e:
            for neighbor in range(max(s, fl - 2), min(e, fl + 2) + 1):
                keep.add(neighbor)

    ordered = sorted(keep)
    if len(ordered) > max_lines:
        # Preserve signature lines and focus lines first
        ordered = ordered[:max_lines]

    rendered: List[str] = []
    prev: Optional[int] = None
    for ln in ordered:
        if prev is not None and ln > prev + 1:
            rendered.append(f"... ({ln - prev - 1} lines omitted) ...")
        rendered.append(f"L{ln}: {lines[ln - 1]}")
        prev = ln
    return "\n".join(rendered)


# =============================================================================
# Semantic Role, Source, Sanitizer & Sink Analysis
# =============================================================================


def _analyze_symbol_semantics(symbol: SymbolNode, body_text: str, body_lines: List[str]) -> None:
    """Populates source/sanitizer/sink metadata and semantic roles on a SymbolNode."""
    roles: List[str] = []

    # 1. Entry point signals
    for dec in symbol.decorators:
        m_route = _ROUTE_DECORATOR_RX.search(dec)
        if m_route:
            symbol.route_pattern = m_route.group(1)
            if "entry_point" not in roles:
                roles.append("entry_point")

    for src_label, rx in _SOURCE_PATTERNS:
        if rx.search(body_text):
            if src_label not in symbol.source_indicators:
                symbol.source_indicators.append(src_label)

    param_low = {p.lower() for p in symbol.params}
    has_req_param = bool(param_low & {"req", "request", "http_request", "ctx", "context", "event", "argv"})
    has_next_param = "next" in param_low or "call_next" in param_low or "next_fn" in param_low

    if symbol.source_indicators or (has_req_param and _ENTRY_NAME_RX.search(symbol.name)):
        if "entry_point" not in roles:
            roles.append("entry_point")

    # 2. Middleware signals
    if has_next_param or _MIDDLEWARE_NAME_RX.search(symbol.name) or _MIDDLEWARE_NAME_RX.search(symbol.file_path):
        if "middleware" not in roles:
            roles.append("middleware")

    # 3. Sanitizer signals (distinguishing strong vs weak)
    strong_hits: List[str] = []
    weak_hits: List[str] = []
    for label, rx in _STRONG_SANITIZER_PATTERNS:
        if rx.search(body_text):
            strong_hits.append(label)
    for label, rx in _WEAK_SANITIZER_PATTERNS:
        if rx.search(body_text):
            weak_hits.append(label)

    is_named_sanitizer = bool(
        _SANITIZER_NAME_RX.search(symbol.name) or _SANITIZER_NAME_RX.search(Path(symbol.file_path).stem)
    )
    if strong_hits:
        symbol.sanitizer_indicators.extend(strong_hits)
        symbol.sanitizer_strength = "strong"
        if "sanitizer" not in roles:
            roles.append("sanitizer")
    elif weak_hits:
        symbol.sanitizer_indicators.extend(weak_hits)
        symbol.sanitizer_strength = "weak"
        if "sanitizer" not in roles:
            roles.append("sanitizer")
    elif is_named_sanitizer and "middleware" not in roles:
        symbol.sanitizer_indicators.append("named_sanitizer_fn")
        # Without strong allowlist/encoding primitives, treat custom sanitizer as weak until proven strong
        symbol.sanitizer_strength = "weak"
        if "sanitizer" not in roles:
            roles.append("sanitizer")

    # 4. Sink detection (line-by-line within function body)
    seen_sinks: Set[Tuple[str, int]] = set()
    for idx, raw_line in enumerate(body_lines):
        abs_line = symbol.start_line + idx
        line_stripped = raw_line.strip()
        if not line_stripped or line_stripped.startswith(("#", "//", "/*", "*")):
            continue
        # Skip declaration header line itself
        if idx == 0 and re.match(r"^(?:async\s+)?(?:def|function|fn|func|pub\s+|export\s+)", line_stripped):
            continue
        for vuln_cls, rx in _SINK_PATTERNS:
            m = rx.search(line_stripped)
            if not m:
                continue
            # Filter out known-safe variants
            if vuln_cls == "command_injection" and "subprocess." in line_stripped and "shell=False" in line_stripped:
                continue
            if vuln_cls == "deserialization" and "yaml.safe_load" in line_stripped:
                continue
            if vuln_cls == "sql_injection":
                # Skip purely static literal SQL calls with no interpolation/variable
                after = line_stripped[m.end() :]
                if re.match(r"""^\s*['"][^'"%{}]+['"]\s*\)""", after):
                    continue
            if vuln_cls == "command_injection" and m.group(0).strip().startswith("exec(") and symbol.language == "python":
                vuln_cls = "code_execution"
            key = (vuln_cls, abs_line)
            if key in seen_sinks:
                continue
            seen_sinks.add(key)
            cwe, sev = CWE_BY_CLASS.get(vuln_cls, ("CWE-20", "MEDIUM"))
            symbol.sink_matches.append(
                {
                    "vulnerability_class": vuln_cls,
                    "cwe": cwe,
                    "severity": sev,
                    "line": abs_line,
                    "call_text": line_stripped[:160],
                    "matched_token": m.group(0).strip(),
                }
            )
            if "sink" not in roles:
                roles.append("sink")

    symbol.roles = roles if roles else ["helper"]
    # Primary role priority for display
    for preferred in ("entry_point", "sink", "sanitizer", "middleware", "helper"):
        if preferred in symbol.roles:
            symbol.role = preferred
            break


# =============================================================================
# Dynamic Tree-sitter Backend (Optional)
# =============================================================================


class _TreeSitterBackend:
    """
    Dynamically loads `tree_sitter` and available grammar packs
    (`tree_sitter_language_pack`, `tree_sitter_languages`, or individual
    `tree_sitter_<lang>` wheels). Fails cleanly when unavailable.
    """

    def __init__(self) -> None:
        self._ts_mod: Any = None
        self._pack_mod: Any = None
        self._langs_mod: Any = None
        self._parsers: Dict[str, Any] = {}
        self.available: bool = False
        self._probe()

    def _probe(self) -> None:
        try:
            self._ts_mod = importlib.import_module("tree_sitter")
        except Exception:
            return

        for mod_name, attr in (
            ("tree_sitter_language_pack", "_pack_mod"),
            ("tree_sitter_languages", "_langs_mod"),
        ):
            try:
                setattr(self, attr, importlib.import_module(mod_name))
            except Exception:
                pass

        for lang in ("python", "typescript", "javascript", "rust", "go", "c", "cpp", "java"):
            parser = self._load_parser_for_language(lang)
            if parser is not None:
                self._parsers[lang] = parser

        self.available = bool(self._parsers)

    def _load_parser_for_language(self, lang: str) -> Optional[Any]:
        if self._pack_mod is not None and hasattr(self._pack_mod, "get_parser"):
            try:
                return self._pack_mod.get_parser(lang)
            except Exception:
                pass
        if self._langs_mod is not None and hasattr(self._langs_mod, "get_parser"):
            try:
                return self._langs_mod.get_parser(lang)
            except Exception:
                pass
        # Try individual language wheels (tree_sitter_python, etc.)
        if self._ts_mod is not None:
            wheel_name = f"tree_sitter_{lang}"
            try:
                lmod = importlib.import_module(wheel_name)
                lang_fn = getattr(lmod, "language", None)
                if lang_fn is None and lang == "typescript":
                    lang_fn = getattr(lmod, "language_typescript", None)
                if callable(lang_fn):
                    ts_lang = self._ts_mod.Language(lang_fn())
                    parser = self._ts_mod.Parser()
                    if hasattr(parser, "language"):
                        parser.language = ts_lang
                    elif hasattr(parser, "set_language"):
                        parser.set_language(ts_lang)
                    return parser
            except Exception:
                pass
        return None

    def supports(self, language: str) -> bool:
        return language in self._parsers

    def parse_file(self, abs_path: Path, rel_path: str, source: str, language: str) -> Optional[_ParsedFile]:
        parser = self._parsers.get(language)
        if parser is None:
            return None
        try:
            source_bytes = source.encode("utf-8", errors="replace")
            tree = parser.parse(source_bytes)
            root = tree.root_node
        except Exception as exc:
            logger.debug("Tree-sitter parse failed for %s: %s", rel_path, exc)
            return None

        lines = source.splitlines()
        parsed = _ParsedFile(
            rel_path=rel_path,
            abs_path=abs_path,
            language=language,
            parser_backend="tree_sitter",
            lines=lines,
        )

        # Extract imports and route registrations structurally alongside Tree-sitter CST symbols
        if language == "python":
            py_aux = _parse_python_ast(abs_path, rel_path, source)
            if py_aux is not None:
                parsed.imports = py_aux.imports
                parsed.routes = py_aux.routes
        else:
            stripped = _strip_comments_preserve_lines(source, language)
            parsed.imports = _extract_non_py_imports(stripped, language)
            parsed.routes = _extract_non_py_routes(stripped, rel_path, language)

        fn_node_types = {
            "function_definition",
            "function_declaration",
            "method_definition",
            "method_declaration",
            "function_item",
            "arrow_function",
        }
        call_node_types = {"call", "call_expression", "method_invocation", "macro_invocation"}

        def _node_text(node: Any) -> str:
            return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

        def _extract_calls_from_node(node: Any, calls_out: List[CallSite], assigns_out: Dict[str, Set[str]]) -> None:
            stack = [node]
            while stack:
                cur = stack.pop()
                ctype = getattr(cur, "type", "")
                if ctype in call_node_types:
                    raw = _node_text(cur)
                    line_no = int(cur.start_point[0]) + 1
                    m_call = re.match(r"^(?:([\w$.:]+)(?:\.|::))?([A-Za-z_$][\w$]*)\s*\((.*)\)$", raw.strip(), re.DOTALL)
                    if m_call:
                        qual = m_call.group(1)
                        cname = m_call.group(2)
                        args = _split_top_level_args(m_call.group(3))
                        assigned_to: Optional[str] = None
                        is_ret = False
                        parent = getattr(cur, "parent", None)
                        if parent is not None:
                            ptype = getattr(parent, "type", "")
                            ptxt = _node_text(parent).strip()
                            if "return" in ptype:
                                is_ret = True
                            elif any(k in ptype for k in ("assign", "declar", "let")):
                                m_lhs = re.match(r"^(?:const|let|var|mut)?\s*([A-Za-z_$][\w$]*)\s*(?::[^=]+)?[:=]", ptxt)
                                if m_lhs:
                                    assigned_to = m_lhs.group(1)
                                    assigns_out.setdefault(assigned_to, set()).update(_extract_identifiers(raw))
                        if cname not in CONTROL_KEYWORDS:
                            calls_out.append(
                                CallSite(
                                    callee_name=cname,
                                    qualifier=qual,
                                    line=line_no,
                                    arguments=args,
                                    assigned_to=assigned_to,
                                    is_return=is_ret,
                                    raw_expr=raw[:160],
                                )
                            )
                for child in reversed(getattr(cur, "children", ())):
                    stack.append(child)

        def _walk(node: Any, class_stack: List[str]) -> None:
            ntype = getattr(node, "type", "")
            if ntype in ("class_definition", "class_declaration", "impl_item", "struct_item"):
                cname_node = node.child_by_field_name("name") if hasattr(node, "child_by_field_name") else None
                cname = _node_text(cname_node).strip() if cname_node is not None else ""
                if cname:
                    class_stack.append(cname)
                for ch in getattr(node, "children", ()):
                    _walk(ch, class_stack)
                if cname:
                    class_stack.pop()
                return

            if ntype in fn_node_types:
                start_ln = int(node.start_point[0]) + 1
                end_ln = int(node.end_point[0]) + 1
                name_node = node.child_by_field_name("name") if hasattr(node, "child_by_field_name") else None
                fn_name = _node_text(name_node).strip() if name_node is not None else ""
                if not fn_name and ntype == "arrow_function":
                    parent = getattr(node, "parent", None)
                    if parent is not None:
                        p_name = parent.child_by_field_name("name") if hasattr(parent, "child_by_field_name") else None
                        if p_name is not None:
                            fn_name = _node_text(p_name).strip()
                if fn_name and fn_name not in CONTROL_KEYWORDS:
                    params_node = node.child_by_field_name("parameters") if hasattr(node, "child_by_field_name") else None
                    raw_params = _node_text(params_node).strip("()") if params_node is not None else ""
                    params = _extract_param_names(raw_params, language)
                    qname = f"{'.'.join(class_stack)}.{fn_name}" if class_stack else fn_name
                    sym_id = f"{rel_path}::{qname}"
                    decorators: List[str] = []
                    # Inspect up to 3 lines immediately preceding function for decorators/attributes
                    for back in range(max(1, start_ln - 3), start_ln):
                        prev_ln = lines[back - 1].strip()
                        if prev_ln.startswith(("@", "#[")):
                            decorators.append(prev_ln)
                    calls: List[CallSite] = []
                    assigns: Dict[str, Set[str]] = {}
                    _extract_calls_from_node(node, calls, assigns)
                    body_lines = lines[start_ln - 1 : end_ln]
                    body_text = "\n".join(body_lines)
                    sym = SymbolNode(
                        symbol_id=sym_id,
                        name=fn_name,
                        qualified_name=qname,
                        file_path=rel_path,
                        language=language,
                        start_line=start_ln,
                        end_line=end_ln,
                        params=params,
                        decorators=decorators,
                        calls=calls,
                        assignments=assigns,
                        parser_backend="tree_sitter",
                    )
                    _analyze_symbol_semantics(sym, body_text, body_lines)
                    parsed.symbols.append(sym)
                    return

            for ch in getattr(node, "children", ()):
                _walk(ch, class_stack)

        _walk(root, [])
        return parsed if parsed.symbols or parsed.routes else None


# =============================================================================
# Python Built-in AST Parser
# =============================================================================


def _unparse_expr(node: Optional[ast.AST]) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _parse_python_ast(abs_path: Path, rel_path: str, source: str) -> Optional[_ParsedFile]:
    """Genuine full Python AST parser extracting imports, routes, symbols, calls, and dataflow."""
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        logger.debug("Python AST syntax error in %s: %s", rel_path, exc)
        return None

    lines = source.splitlines()
    parsed = _ParsedFile(
        rel_path=rel_path,
        abs_path=abs_path,
        language="python",
        parser_backend="python_ast",
        lines=lines,
    )

    # 1. Imports & top-level route registrations
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                parsed.imports.append(
                    ImportRecord(module=alias.name, names={local: "*"}, level=0, line=getattr(node, "lineno", 1))
                )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            names_map: Dict[str, str] = {}
            for alias in node.names:
                local = alias.asname or alias.name
                names_map[local] = alias.name
            parsed.imports.append(
                ImportRecord(
                    module=mod,
                    names=names_map,
                    level=int(node.level or 0),
                    line=getattr(node, "lineno", 1),
                )
            )
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr.lower()
            if attr in ("add_url_rule", "add_api_route", "add_route") and node.args:
                route_path = _unparse_expr(node.args[0]).strip("'\"")
                handlers: List[str] = []
                for arg in node.args[1:]:
                    if isinstance(arg, (ast.Name, ast.Attribute)):
                        handlers.append(_unparse_expr(arg))
                for kw in node.keywords:
                    if kw.arg in ("view_func", "endpoint", "handler"):
                        handlers.append(_unparse_expr(kw.value))
                if handlers:
                    parsed.routes.append(
                        RouteRegistration(
                            method="ANY",
                            route_path=route_path or "/",
                            handlers=handlers,
                            file_path=rel_path,
                            line=getattr(node, "lineno", 1),
                        )
                    )

    # 2. Functions & methods with intra-procedural calls & assignments
    def _extract_fn_calls_and_assigns(
        fn_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
    ) -> Tuple[List[CallSite], Dict[str, Set[str]]]:
        calls: List[CallSite] = []
        assigns: Dict[str, Set[str]] = {}

        def _record_call(call_node: ast.Call, assigned_to: Optional[str] = None, is_ret: bool = False) -> None:
            qual: Optional[str] = None
            callee = ""
            if isinstance(call_node.func, ast.Name):
                callee = call_node.func.id
            elif isinstance(call_node.func, ast.Attribute):
                callee = call_node.func.attr
                qual = _unparse_expr(call_node.func.value)
            if not callee:
                return
            arg_strs = [_unparse_expr(a) for a in call_node.args]
            for kw in call_node.keywords:
                if kw.arg:
                    arg_strs.append(f"{kw.arg}={_unparse_expr(kw.value)}")
                else:
                    arg_strs.append(f"**{_unparse_expr(kw.value)}")
            calls.append(
                CallSite(
                    callee_name=callee,
                    qualifier=qual,
                    line=int(getattr(call_node, "lineno", fn_node.lineno)),
                    arguments=arg_strs,
                    assigned_to=assigned_to,
                    is_return=is_ret,
                    raw_expr=_unparse_expr(call_node)[:160],
                )
            )
            # Recurse into nested call arguments
            for sub in list(call_node.args) + [kw.value for kw in call_node.keywords]:
                for child in ast.walk(sub):
                    if isinstance(child, ast.Call):
                        _record_call(child)

        def _visit_stmts(stmts: Sequence[ast.stmt]) -> None:
            for st in stmts:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if isinstance(st, ast.Assign):
                    rhs_txt = _unparse_expr(st.value)
                    rhs_ids = _extract_identifiers(rhs_txt)
                    lhs_name: Optional[str] = None
                    for tgt in st.targets:
                        if isinstance(tgt, ast.Name):
                            lhs_name = tgt.id
                            assigns.setdefault(tgt.id, set()).update(rhs_ids)
                        elif isinstance(tgt, ast.Tuple):
                            for elt in tgt.elts:
                                if isinstance(elt, ast.Name):
                                    assigns.setdefault(elt.id, set()).update(rhs_ids)
                    if isinstance(st.value, ast.Call):
                        _record_call(st.value, assigned_to=lhs_name)
                    else:
                        for child in ast.walk(st.value):
                            if isinstance(child, ast.Call):
                                _record_call(child, assigned_to=lhs_name)
                elif isinstance(st, ast.AnnAssign) and st.value is not None:
                    lhs_name = st.target.id if isinstance(st.target, ast.Name) else None
                    if lhs_name:
                        assigns.setdefault(lhs_name, set()).update(_extract_identifiers(_unparse_expr(st.value)))
                    if isinstance(st.value, ast.Call):
                        _record_call(st.value, assigned_to=lhs_name)
                    else:
                        for child in ast.walk(st.value):
                            if isinstance(child, ast.Call):
                                _record_call(child, assigned_to=lhs_name)
                elif isinstance(st, ast.Return) and st.value is not None:
                    if isinstance(st.value, ast.Call):
                        _record_call(st.value, is_ret=True)
                    else:
                        for child in ast.walk(st.value):
                            if isinstance(child, ast.Call):
                                _record_call(child, is_ret=True)
                elif isinstance(st, ast.Expr):
                    for child in ast.walk(st.value):
                        if isinstance(child, ast.Call):
                            _record_call(child)
                else:
                    # Handle nested blocks (if/for/try/with) without descending into inner defs
                    for field_name in ("body", "orelse", "finalbody"):
                        sub_stmts = getattr(st, field_name, None)
                        if isinstance(sub_stmts, list):
                            _visit_stmts(sub_stmts)
                    if isinstance(st, ast.Try):
                        for h in st.handlers:
                            _visit_stmts(h.body)
                    if isinstance(st, ast.With):
                        for item in st.items:
                            if isinstance(item.context_expr, ast.Call):
                                var = item.optional_vars.id if isinstance(item.optional_vars, ast.Name) else None
                                _record_call(item.context_expr, assigned_to=var)
                    if isinstance(st, ast.If):
                        for child in ast.walk(st.test):
                            if isinstance(child, ast.Call):
                                _record_call(child)

        _visit_stmts(fn_node.body)
        return calls, assigns

    def _visit_body(stmts: Sequence[ast.stmt], class_stack: List[str]) -> None:
        for st in stmts:
            if isinstance(st, ast.ClassDef):
                class_stack.append(st.name)
                _visit_body(st.body, class_stack)
                class_stack.pop()
            elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_ln = int(st.lineno)
                end_ln = int(getattr(st, "end_lineno", start_ln) or start_ln)
                qname = f"{'.'.join(class_stack)}.{st.name}" if class_stack else st.name
                sym_id = f"{rel_path}::{qname}"
                params = [a.arg for a in st.args.posonlyargs + st.args.args + st.args.kwonlyargs if a.arg != "self"]
                if st.args.vararg:
                    params.append(st.args.vararg.arg)
                if st.args.kwarg:
                    params.append(st.args.kwarg.arg)
                decorators = ["@" + _unparse_expr(d) for d in st.decorator_list]
                calls, assigns = _extract_fn_calls_and_assigns(st)
                body_lines = lines[start_ln - 1 : end_ln]
                body_text = "\n".join(body_lines)
                sym = SymbolNode(
                    symbol_id=sym_id,
                    name=st.name,
                    qualified_name=qname,
                    file_path=rel_path,
                    language="python",
                    start_line=start_ln,
                    end_line=end_ln,
                    params=params,
                    decorators=decorators,
                    calls=calls,
                    assignments=assigns,
                    parser_backend="python_ast",
                )
                _analyze_symbol_semantics(sym, body_text, body_lines)
                parsed.symbols.append(sym)
                # Also index nested inner functions (e.g. FastAPI/Flask factories)
                _visit_body(st.body, class_stack + [st.name])

    _visit_body(tree.body, [])
    return parsed


# =============================================================================
# Structural Multi-Language Parser (TypeScript / JS / Rust / Go / C / C++ / Java)
# =============================================================================


def _extract_non_py_imports(stripped: str, language: str) -> List[ImportRecord]:
    imports: List[ImportRecord] = []

    if language in ("typescript", "javascript"):
        # import { a, b as c } from './mod'
        for m in re.finditer(
            r"""\bimport\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]""",
            stripped,
        ):
            names: Dict[str, str] = {}
            for item in m.group(1).split(","):
                item = item.strip()
                if not item:
                    continue
                if " as " in item:
                    orig, alias = [p.strip() for p in item.split(" as ", 1)]
                    names[alias] = orig
                else:
                    names[item] = item
            imports.append(ImportRecord(module=m.group(2), names=names, line=_offset_to_line(stripped, m.start())))

        # import defaultName from './mod'  or  import * as ns from './mod'
        for m in re.finditer(
            r"""\bimport\s+(?:\*\s+as\s+([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*))\s+from\s+['"]([^'"]+)['"]""",
            stripped,
        ):
            ns_alias = m.group(1)
            def_alias = m.group(2)
            mod = m.group(3)
            if ns_alias:
                imports.append(ImportRecord(module=mod, names={ns_alias: "*"}, line=_offset_to_line(stripped, m.start())))
            elif def_alias:
                imports.append(ImportRecord(module=mod, names={def_alias: "default"}, line=_offset_to_line(stripped, m.start())))

        # const { a, b } = require('./mod')  or  const mod = require('./mod')
        for m in re.finditer(
            r"""\b(?:const|let|var)\s+(?:\{([^}]+)\}|([A-Za-z_$][\w$]*))\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",
            stripped,
        ):
            mod = m.group(3)
            if m.group(1):
                names = {}
                for item in m.group(1).split(","):
                    item = item.strip()
                    if not item:
                        continue
                    if ":" in item:
                        orig, alias = [p.strip() for p in item.split(":", 1)]
                        names[alias] = orig
                    else:
                        names[item] = item
                imports.append(ImportRecord(module=mod, names=names, line=_offset_to_line(stripped, m.start())))
            elif m.group(2):
                imports.append(ImportRecord(module=mod, names={m.group(2): "*"}, line=_offset_to_line(stripped, m.start())))

    elif language == "rust":
        # use crate::a::b::{c, d as e};  or  use crate::a::b::c;
        for m in re.finditer(r"""\buse\s+([\w:]+)(?:::\{([^}]+)\}|::(\w+)(?:\s+as\s+(\w+))?)?\s*;""", stripped):
            prefix = m.group(1)
            group = m.group(2)
            single = m.group(3)
            single_alias = m.group(4)
            line_no = _offset_to_line(stripped, m.start())
            if group:
                names = {}
                for item in group.split(","):
                    item = item.strip()
                    if not item or item == "self":
                        continue
                    if " as " in item:
                        orig, alias = [p.strip() for p in item.split(" as ", 1)]
                        names[alias] = orig
                    else:
                        names[item] = item
                imports.append(ImportRecord(module=prefix, names=names, line=line_no))
            elif single:
                imports.append(ImportRecord(module=prefix, names={single_alias or single: single}, line=line_no))
            else:
                parts = prefix.split("::")
                if len(parts) >= 2:
                    imports.append(
                        ImportRecord(module="::".join(parts[:-1]), names={parts[-1]: parts[-1]}, line=line_no)
                    )
        # mod foo;
        for m in re.finditer(r"""\b(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*;""", stripped):
            mod_name = m.group(1)
            imports.append(
                ImportRecord(module=f"self::{mod_name}", names={mod_name: "*"}, line=_offset_to_line(stripped, m.start()))
            )

    elif language == "go":
        # Single import "pkg" or import alias "pkg"
        for m in re.finditer(r"""\bimport\s+(?:([A-Za-z_]\w*)\s+)?"([^"]+)" """, stripped + " "):
            alias = m.group(1) or m.group(2).rsplit("/", 1)[-1]
            imports.append(ImportRecord(module=m.group(2), names={alias: "*"}, line=_offset_to_line(stripped, m.start())))
        # Grouped import ( ... )
        for m in re.finditer(r"""\bimport\s*\(([\s\S]*?)\)""", stripped):
            base_ln = _offset_to_line(stripped, m.start())
            for item in re.finditer(r"""(?:([A-Za-z_]\w*)\s+)?"([^"]+)" """, m.group(1) + " "):
                alias = item.group(1) or item.group(2).rsplit("/", 1)[-1]
                imports.append(ImportRecord(module=item.group(2), names={alias: "*"}, line=base_ln))

    elif language in ("c", "cpp"):
        for m in re.finditer(r"""#include\s+"([^"]+)" """, stripped + " "):
            imports.append(ImportRecord(module=m.group(1), names={"*": "*"}, line=_offset_to_line(stripped, m.start())))

    elif language == "java":
        for m in re.finditer(r"""\bimport\s+(?:static\s+)?([\w.]+)\.([A-Za-z_*]\w*)\s*;""", stripped):
            imports.append(
                ImportRecord(
                    module=m.group(1),
                    names={m.group(2): m.group(2)},
                    line=_offset_to_line(stripped, m.start()),
                )
            )

    return imports


def _extract_non_py_routes(stripped: str, rel_path: str, language: str) -> List[RouteRegistration]:
    routes: List[RouteRegistration] = []
    if language in ("typescript", "javascript"):
        for m in _TS_JS_ROUTE_CALL_RX.finditer(stripped):
            method = m.group("method").upper()
            rpath = m.group("path") or "/"
            raw_args = _split_top_level_args(m.group("args"))
            handlers: List[str] = []
            for arg in raw_args:
                arg_clean = arg.strip()
                # Direct identifier or property reference (e.g., authMiddleware, handlers.execCmd)
                if re.fullmatch(r"[A-Za-z_$][\w$.]*", arg_clean):
                    handlers.append(arg_clean)
                else:
                    # Wrapper call like requireAuth(role) -> record outer fn if present
                    m_wrap = re.match(r"^([A-Za-z_$][\w$.]*)\s*\(", arg_clean)
                    if m_wrap and m_wrap.group(1) not in CONTROL_KEYWORDS:
                        handlers.append(m_wrap.group(1))
            if handlers:
                routes.append(
                    RouteRegistration(
                        method=method,
                        route_path=rpath,
                        handlers=handlers,
                        file_path=rel_path,
                        line=_offset_to_line(stripped, m.start()),
                        is_middleware_use=(method == "USE"),
                    )
                )
    elif language == "rust":
        layers = [m.group("mw").strip() for m in _RUST_LAYER_RX.finditer(stripped)]
        for m in _RUST_ROUTE_CALL_RX.finditer(stripped):
            handlers = list(layers) + [m.group("handler").strip()]
            routes.append(
                RouteRegistration(
                    method=m.group("method").upper(),
                    route_path=m.group("path"),
                    handlers=handlers,
                    file_path=rel_path,
                    line=_offset_to_line(stripped, m.start()),
                )
            )
    elif language == "go":
        for m in _GO_ROUTE_CALL_RX.finditer(stripped):
            method = m.group("method").upper()
            rpath = m.group("path") or "/"
            raw_args = _split_top_level_args(m.group("args"))
            handlers: List[str] = []
            for arg in raw_args:
                # Flatten wrapper chains like `authMiddleware(sanitize(execHandler))`
                nested = re.findall(r"[A-Za-z_][\w.]*", arg)
                for tok in nested:
                    if tok not in CONTROL_KEYWORDS and tok not in handlers:
                        handlers.append(tok)
            if handlers:
                routes.append(
                    RouteRegistration(
                        method=method,
                        route_path=rpath,
                        handlers=handlers,
                        file_path=rel_path,
                        line=_offset_to_line(stripped, m.start()),
                        is_middleware_use=(method == "USE"),
                    )
                )
    return routes


def _extract_calls_and_assigns_structural(
    body_stripped: str,
    start_line: int,
    language: str,
) -> Tuple[List[CallSite], Dict[str, Set[str]]]:
    """Extracts call sites and variable assignments from a comment-stripped function body."""
    calls: List[CallSite] = []
    assigns: Dict[str, Set[str]] = {}

    # 1. Assignments line-by-line
    for offset_idx, raw_ln in enumerate(body_stripped.splitlines()):
        ln = raw_ln.strip()
        if not ln:
            continue
        m_asg = re.match(
            r"^(?:const|let|var|mut|auto|final|String|int|char\s*\*|std::string|let\s+mut)?\s*"
            r"([A-Za-z_$][\w$]*)\s*(?::[^=]+)?\s*(?::=|=)\s*(.+?);?$",
            ln,
        )
        if m_asg:
            lhs = m_asg.group(1)
            rhs = m_asg.group(2)
            if lhs not in CONTROL_KEYWORDS and not rhs.startswith("="):
                assigns.setdefault(lhs, set()).update(_extract_identifiers(rhs))

    # 2. Call expressions across the function body
    call_rx = re.compile(r"(?:([A-Za-z_$][\w$.:]*)(?:\.|::))?([A-Za-z_$][\w$]*)\s*\(")
    # Skip the function declaration header on line 0
    first_brace = body_stripped.find("{")
    scan_start = first_brace + 1 if first_brace != -1 else 0

    for m in call_rx.finditer(body_stripped, scan_start):
        qual = m.group(1)
        cname = m.group(2)
        if cname in CONTROL_KEYWORDS:
            continue
        # Avoid matching function declarations inside body (e.g. `function foo(`)
        prefix_window = body_stripped[max(scan_start, m.start() - 24) : m.start()]
        if re.search(r"\b(?:function|fn|func|def|class|struct|enum)\s+$", prefix_window):
            continue

        open_paren = m.end() - 1
        close_paren = _find_matching_paren(body_stripped, open_paren)
        if close_paren == -1:
            continue
        arg_str = body_stripped[open_paren + 1 : close_paren]
        args = _split_top_level_args(arg_str)
        rel_line = _offset_to_line(body_stripped, m.start())
        abs_line = start_line + rel_line - 1

        # Determine enclosing line context for assignment or return
        line_start = body_stripped.rfind("\n", 0, m.start()) + 1
        line_prefix = body_stripped[line_start : m.start()].strip()
        assigned_to: Optional[str] = None
        is_ret = bool(re.match(r"^return\b", line_prefix))
        m_lhs = re.match(
            r"^(?:const|let|var|let\s+mut|mut)?\s*([A-Za-z_$][\w$]*)\s*(?::[^=]+)?\s*(?::=|=)\s*(?:await\s+)?$",
            line_prefix,
        )
        if m_lhs and m_lhs.group(1) not in CONTROL_KEYWORDS:
            assigned_to = m_lhs.group(1)

        calls.append(
            CallSite(
                callee_name=cname,
                qualifier=qual,
                line=abs_line,
                arguments=args,
                assigned_to=assigned_to,
                is_return=is_ret,
                raw_expr=body_stripped[m.start() : min(close_paren + 1, m.start() + 160)],
            )
        )

    return calls, assigns


def _parse_structural_file(abs_path: Path, rel_path: str, source: str, language: str) -> _ParsedFile:
    """
    Genuine scope-aware structural parser for TypeScript, JavaScript, Rust,
    Go, C/C++, and Java using comment-stripped brace-balanced function extraction.
    """
    lines = source.splitlines()
    stripped = _strip_comments_preserve_lines(source, language)
    parsed = _ParsedFile(
        rel_path=rel_path,
        abs_path=abs_path,
        language=language,
        parser_backend="structural_ast",
        lines=lines,
        imports=_extract_non_py_imports(stripped, language),
        routes=_extract_non_py_routes(stripped, rel_path, language),
    )

    # Language-specific function definition regexes (anchored to opening `{`)
    fn_patterns: List[re.Pattern[str]] = []
    if language in ("typescript", "javascript"):
        fn_patterns = [
            re.compile(
                r"""(?:^|\n)[ \t]*(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*(?:<[^>{]*>)?\s*\(([^)]*)\)[^{;\n]*\{"""
            ),
            re.compile(
                r"""(?:^|\n)[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?\(([^)]*)\)\s*(?::[^=>{]+)?=>\s*\{"""
            ),
            re.compile(
                r"""(?:^|\n)[ \t]+(?:public|private|protected|static|async|\s)*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?::[^{;\n]+)?\{"""
            ),
        ]
    elif language == "rust":
        fn_patterns = [
            re.compile(
                r"""(?:^|\n)[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>{]*>)?\s*\(([^)]*)\)[^{;]*\{"""
            )
        ]
    elif language == "go":
        fn_patterns = [
            re.compile(
                r"""(?:^|\n)[ \t]*func\s+(?:\([^)]*\)\s+)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\(([^)]*)\)[^{]*\{"""
            )
        ]
    elif language in ("c", "cpp"):
        fn_patterns = [
            re.compile(
                r"""(?:^|\n)[ \t]*(?:static\s+|inline\s+|extern\s+|virtual\s+|const\s+)*(?:[\w:*&<>]+\s+)+([A-Za-z_][\w:]*)\s*\(([^;{}]*)\)\s*(?:const\s*)?\{"""
            )
        ]
    elif language == "java":
        fn_patterns = [
            re.compile(
                r"""(?:^|\n)[ \t]*(?:public|private|protected|static|final|synchronized|abstract|\s)+(?:<[^>]+>\s+)?[\w<>\[\],.?]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\{"""
            )
        ]

    seen_spans: Set[Tuple[str, int]] = set()
    for pat in fn_patterns:
        for m in pat.finditer(stripped):
            fn_name = m.group(1).strip()
            short_name = fn_name.rsplit("::", 1)[-1]
            if not short_name or short_name in CONTROL_KEYWORDS:
                continue
            brace_pos = m.end() - 1
            if brace_pos < 0 or stripped[brace_pos] != "{":
                continue
            close_pos = _find_matching_brace(stripped, brace_pos)
            match_start = m.start() + (1 if stripped[m.start() : m.start() + 1] == "\n" else 0)
            start_ln = _offset_to_line(stripped, match_start)
            end_ln = _offset_to_line(stripped, close_pos)
            span_key = (short_name, start_ln)
            if span_key in seen_spans:
                continue
            seen_spans.add(span_key)

            decorators: List[str] = []
            for back in range(max(1, start_ln - 4), start_ln):
                prev_ln = lines[back - 1].strip()
                if prev_ln.startswith(("@", "#[")):
                    decorators.append(prev_ln)

            params = _extract_param_names(m.group(2), language)
            body_stripped = stripped[match_start : close_pos + 1]
            calls, assigns = _extract_calls_and_assigns_structural(body_stripped, start_ln, language)
            body_lines = lines[start_ln - 1 : end_ln]
            body_text = "\n".join(body_lines)

            sym_id = f"{rel_path}::{fn_name}"
            sym = SymbolNode(
                symbol_id=sym_id,
                name=short_name,
                qualified_name=fn_name,
                file_path=rel_path,
                language=language,
                start_line=start_ln,
                end_line=end_ln,
                params=params,
                decorators=decorators,
                calls=calls,
                assignments=assigns,
                parser_backend="structural_ast",
            )
            _analyze_symbol_semantics(sym, body_text, body_lines)
            parsed.symbols.append(sym)

    return parsed


# =============================================================================
# CodeQL Optional CLI & SARIF / BQRS Path Extraction
# =============================================================================


def detect_codeql(codeql_bin: Optional[str] = None, *, enabled: bool = False) -> CodeQLReport:
    """
    Detects whether the `codeql` CLI binary is available (`shell=False`)
    without failing when absent.
    """
    resolved: Optional[str] = None
    if codeql_bin:
        cand = Path(codeql_bin)
        if cand.is_file():
            resolved = str(cand)
        else:
            resolved = shutil.which(str(codeql_bin))
    else:
        resolved = shutil.which("codeql")

    if not resolved:
        return CodeQLReport(
            available=False,
            binary_path=None,
            version=None,
            enabled=enabled,
            executed=False,
            status="unavailable" if enabled else "disabled",
        )

    version: Optional[str] = None
    try:
        proc = subprocess.run(
            [resolved, "version", "--format=terse"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            shell=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            version = proc.stdout.strip().splitlines()[0].strip()
    except Exception as exc:
        logger.debug("CodeQL version probe failed: %s", exc)

    return CodeQLReport(
        available=True,
        binary_path=resolved,
        version=version,
        enabled=enabled,
        executed=False,
        status="detected" if enabled else "disabled",
    )


def _safe_resolve_under_repo(repo_root: Path, uri: str) -> Optional[Tuple[str, Path]]:
    """Safely maps a SARIF/BQRS artifact URI into `repo_root` without allowing path escape."""
    cleaned = str(uri or "").strip().replace("\\", "/")
    if cleaned.startswith("file:///"):
        cleaned = cleaned[8:]
    elif cleaned.startswith("file://"):
        cleaned = cleaned[7:]
    if not cleaned or "\x00" in cleaned:
        return None
    base = repo_root.resolve()
    try:
        p = Path(cleaned)
        target = p.resolve() if p.is_absolute() else (base / cleaned).resolve()
        if not target.is_relative_to(base):
            return None
        rel = target.relative_to(base).as_posix()
        return rel, target
    except Exception:
        return None


def _classify_rule_id(rule_id: str, message: str = "") -> Tuple[str, str, str]:
    blob = f"{rule_id} {message}".lower()
    if any(k in blob for k in ("command-line-injection", "command_injection", "os-command", "cwe-078", "cwe-78")):
        return "command_injection", "CWE-78", "CRITICAL"
    if any(k in blob for k in ("sql-injection", "sql_injection", "sqli", "cwe-089", "cwe-89")):
        return "sql_injection", "CWE-89", "CRITICAL"
    if any(k in blob for k in ("path-injection", "path-traversal", "path_traversal", "cwe-022", "cwe-22")):
        return "path_traversal", "CWE-22", "HIGH"
    if any(k in blob for k in ("ssrf", "request-forgery", "cwe-918")):
        return "ssrf", "CWE-918", "HIGH"
    if any(k in blob for k in ("code-injection", "code_execution", "eval", "cwe-094", "cwe-94")):
        return "code_execution", "CWE-94", "CRITICAL"
    if any(k in blob for k in ("xss", "cross-site-scripting", "cwe-079", "cwe-79")):
        return "xss", "CWE-79", "MEDIUM"
    if any(k in blob for k in ("deserializ", "unsafe-deserialization", "cwe-502")):
        return "deserialization", "CWE-502", "CRITICAL"
    return "taint_flow", "CWE-20", "HIGH"


def parse_codeql_sarif_slices(sarif_path: Union[str, Path], repo_root: Union[str, Path]) -> List[TaintSlice]:
    """Extracts multi-file `TaintSlice` chains from a CodeQL SARIF 2.1.0 report."""
    sp = Path(sarif_path)
    root = Path(repo_root).resolve()
    if not sp.is_file():
        return []

    data = json.loads(sp.read_text(encoding="utf-8-sig"))
    slices: List[TaintSlice] = []
    file_cache: Dict[str, List[str]] = {}

    def _read_lines(rel: str, abs_p: Path) -> List[str]:
        if rel not in file_cache:
            try:
                file_cache[rel] = abs_p.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                file_cache[rel] = []
        return file_cache[rel]

    for run in data.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        for res in run.get("results", []) or []:
            if not isinstance(res, dict):
                continue
            rule_id = str(res.get("ruleId") or "codeql-flow")
            msg = str((res.get("message") or {}).get("text") or "")
            vuln_cls, cwe, sev = _classify_rule_id(rule_id, msg)

            code_flows = res.get("codeFlows") or []
            if not code_flows:
                # Single-location result fallback
                locs = res.get("locations") or []
                if not locs:
                    continue
                code_flows = [{"threadFlows": [{"locations": [{"location": locs[0]}]}]}]

            for cf in code_flows:
                for tf in (cf.get("threadFlows") or []):
                    tf_locs = tf.get("locations") or []
                    steps: List[SliceStep] = []
                    files_involved: List[str] = []
                    for idx, item in enumerate(tf_locs):
                        loc = item.get("location") if isinstance(item, dict) else None
                        if not isinstance(loc, dict):
                            continue
                        phys = loc.get("physicalLocation") or {}
                        art = (phys.get("artifactLocation") or {}).get("uri") or ""
                        reg = phys.get("region") or {}
                        start_ln = int(reg.get("startLine") or 1)
                        end_ln = int(reg.get("endLine") or start_ln)
                        resolved = _safe_resolve_under_repo(root, str(art))
                        if resolved is not None:
                            rel_str, abs_p = resolved
                            src_lines = _read_lines(rel_str, abs_p)
                            snippet = _build_focused_snippet(src_lines, max(1, start_ln - 2), end_ln + 2, [start_ln])
                            lang = LANGUAGE_BY_EXT.get(abs_p.suffix.lower(), "unknown")
                        else:
                            rel_str = PurePosixPath(str(art).replace("\\", "/")).as_posix() or "unknown"
                            snippet = str(((reg.get("snippet") or {}).get("text")) or f"L{start_ln}: <external>")
                            lang = LANGUAGE_BY_EXT.get(Path(rel_str).suffix.lower(), "unknown")

                        if rel_str not in files_involved:
                            files_involved.append(rel_str)
                        step_msg = str((loc.get("message") or {}).get("text") or "")
                        if idx == 0:
                            role = "entry_point"
                        elif idx == len(tf_locs) - 1:
                            role = "sink"
                        elif _SANITIZER_NAME_RX.search(step_msg) or _SANITIZER_NAME_RX.search(rel_str):
                            role = "sanitizer"
                        elif _MIDDLEWARE_NAME_RX.search(step_msg) or _MIDDLEWARE_NAME_RX.search(rel_str):
                            role = "middleware"
                        else:
                            role = "propagation"
                        sym_name = step_msg.split()[0] if step_msg.strip() else f"step_{idx + 1}"
                        steps.append(
                            SliceStep(
                                step_index=idx,
                                role=role,
                                symbol_id=f"{rel_str}::{sym_name}@L{start_ln}",
                                symbol_name=sym_name,
                                file_path=rel_str,
                                start_line=start_ln,
                                end_line=end_ln,
                                call_line=start_ln,
                                language=lang,
                                snippet=snippet,
                                notes=step_msg[:120],
                            )
                        )
                    if not steps:
                        continue
                    sink_step = steps[-1]
                    entry_step = steps[0]
                    digest = hashlib.sha256(
                        f"codeql|{rule_id}|{entry_step.symbol_id}|{sink_step.symbol_id}".encode("utf-8")
                    ).hexdigest()[:12]
                    sl = TaintSlice(
                        slice_id=f"cql-{digest}",
                        vulnerability_class=vuln_cls,
                        cwe=cwe,
                        severity=sev,
                        entry_point=entry_step.symbol_id,
                        sink=sink_step.symbol_id,
                        sink_call=msg[:140] or rule_id,
                        sink_file=sink_step.file_path,
                        sink_line=sink_step.start_line,
                        steps=steps,
                        files_involved=files_involved,
                        is_cross_file=len(files_involved) >= 2,
                        sanitizers=[],
                        sanitizer_status="unsanitized",
                        taint_confidence=0.92,
                        poe_hint=1,
                        source_backend="codeql",
                    )
                    sl.prompt_context = sl.to_prompt_block()
                    slices.append(sl)
    return slices


def parse_codeql_bqrs_slices(
    bqrs_path: Union[str, Path],
    repo_root: Union[str, Path],
    codeql_bin: str,
) -> List[TaintSlice]:
    """Decodes a CodeQL `.bqrs` file via `codeql bqrs decode --format=json` (`shell=False`)."""
    bp = Path(bqrs_path)
    root = Path(repo_root).resolve()
    if not bp.is_file() or not codeql_bin:
        return []

    try:
        proc = subprocess.run(
            [codeql_bin, "bqrs", "decode", "--format=json", str(bp)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
            shell=False,
        )
    except Exception as exc:
        logger.debug("CodeQL BQRS decode failed: %s", exc)
        return []

    if proc.returncode != 0 or not proc.stdout.strip():
        return []

    try:
        decoded = json.loads(proc.stdout)
    except Exception:
        return []

    slices: List[TaintSlice] = []
    select_obj = decoded.get("#select") if isinstance(decoded, dict) else None
    tuples = select_obj.get("tuples", []) if isinstance(select_obj, dict) else []
    for idx, row in enumerate(tuples):
        if not isinstance(row, list) or len(row) < 2:
            continue
        steps: List[SliceStep] = []
        files_involved: List[str] = []
        msg = str(row[-1]) if isinstance(row[-1], str) else "CodeQL BQRS taint flow"
        for col_idx, cell in enumerate(row):
            if not isinstance(cell, dict):
                continue
            url_obj = cell.get("url") or {}
            uri = str(url_obj.get("uri") or "")
            start_ln = int(url_obj.get("startLine") or 1)
            end_ln = int(url_obj.get("endLine") or start_ln)
            resolved = _safe_resolve_under_repo(root, uri)
            if resolved is not None:
                rel_str, abs_p = resolved
                try:
                    src_lines = abs_p.read_text(encoding="utf-8", errors="replace").splitlines()
                except Exception:
                    src_lines = []
                snippet = _build_focused_snippet(src_lines, max(1, start_ln - 1), end_ln + 1, [start_ln])
                lang = LANGUAGE_BY_EXT.get(abs_p.suffix.lower(), "unknown")
            else:
                rel_str = uri or "unknown"
                snippet = str(cell.get("label") or f"L{start_ln}")
                lang = "unknown"
            if rel_str not in files_involved:
                files_involved.append(rel_str)
            label = str(cell.get("label") or f"node_{col_idx}")
            steps.append(
                SliceStep(
                    step_index=len(steps),
                    role="entry_point" if len(steps) == 0 else "propagation",
                    symbol_id=f"{rel_str}::{label}@L{start_ln}",
                    symbol_name=label,
                    file_path=rel_str,
                    start_line=start_ln,
                    end_line=end_ln,
                    call_line=start_ln,
                    language=lang,
                    snippet=snippet,
                    notes=label,
                )
            )
        if not steps:
            continue
        steps[-1].role = "sink"
        vuln_cls, cwe, sev = _classify_rule_id(msg, msg)
        digest = hashlib.sha256(f"bqrs|{idx}|{steps[0].symbol_id}|{steps[-1].symbol_id}".encode("utf-8")).hexdigest()[:12]
        sl = TaintSlice(
            slice_id=f"bqrs-{digest}",
            vulnerability_class=vuln_cls,
            cwe=cwe,
            severity=sev,
            entry_point=steps[0].symbol_id,
            sink=steps[-1].symbol_id,
            sink_call=msg[:140],
            sink_file=steps[-1].file_path,
            sink_line=steps[-1].start_line,
            steps=steps,
            files_involved=files_involved,
            is_cross_file=len(files_involved) >= 2,
            sanitizers=[],
            sanitizer_status="unsanitized",
            taint_confidence=0.88,
            poe_hint=1,
            source_backend="codeql",
        )
        sl.prompt_context = sl.to_prompt_block()
        slices.append(sl)
    return slices


# =============================================================================
# Whole-Repo Multi-Language CallGraphSlicer
# =============================================================================


class CallGraphSlicer:
    """
    Whole-repository multi-language call-graph builder and cross-file taint slicer.

    Produces structured `TaintSlice` chains (`entry point -> middleware ->
    sanitizer -> sink`) with exact file paths, line spans, symbol names,
    sanitizer strength/status, and concise LLM prompt blocks.
    """

    def __init__(
        self,
        *,
        max_file_bytes: int = 512 * 1024,
        max_depth: int = 8,
        max_slices: int = 200,
        max_prompt_chars: int = 4000,
        max_workers: Optional[int] = None,
    ) -> None:
        self.max_file_bytes = max(4096, int(max_file_bytes))
        self.max_depth = max(2, int(max_depth))
        self.max_slices = max(1, int(max_slices))
        self.max_prompt_chars = max(600, int(max_prompt_chars))
        cpu = os.cpu_count() or 4
        self.max_workers = max(1, min(16, int(max_workers))) if max_workers is not None else max(2, min(16, cpu * 2))
        self._ts_backend = _TreeSitterBackend()

    @property
    def tree_sitter_available(self) -> bool:
        return self._ts_backend.available

    def _discover_source_files(self, repo_root: Path) -> List[Tuple[Path, str, str]]:
        root = repo_root.resolve()
        discovered: List[Tuple[Path, str, str]] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".git"))
            for fname in sorted(filenames):
                fl = fname.lower()
                if fl.endswith((".min.js", ".min.mjs", ".min.cjs", ".bundle.js")):
                    continue
                ext = Path(fname).suffix.lower()
                lang = LANGUAGE_BY_EXT.get(ext)
                if not lang:
                    continue
                fpath = Path(dirpath) / fname
                try:
                    resolved = fpath.resolve()
                    if not resolved.is_relative_to(root):
                        continue
                    if not resolved.is_file() or resolved.stat().st_size > self.max_file_bytes:
                        continue
                    rel = resolved.relative_to(root).as_posix()
                except OSError:
                    continue
                discovered.append((resolved, rel, lang))
        return discovered

    def _parse_single_file(self, item: Tuple[Path, str, str]) -> Optional[_ParsedFile]:
        abs_path, rel_path, lang = item
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        # Skip minified single-line bundles (prevents O(N^2) brace-matching stalls)
        if len(source) > 16_384 and source.count("\n") < max(1, len(source) // 512):
            return None

        if self._ts_backend.supports(lang):
            ts_parsed = self._ts_backend.parse_file(abs_path, rel_path, source, lang)
            if ts_parsed is not None:
                return ts_parsed

        if lang == "python":
            py_parsed = _parse_python_ast(abs_path, rel_path, source)
            if py_parsed is not None:
                return py_parsed
        return _parse_structural_file(abs_path, rel_path, source, lang)

    @staticmethod
    def _resolve_import_files(
        from_rel: str,
        imp: ImportRecord,
        language: str,
        all_files: Set[str],
    ) -> List[str]:
        """Resolves an import specification to matching relative file paths inside the repo."""
        from_dir = PurePosixPath(from_rel).parent
        matches: List[str] = []

        def _check_candidates(base_candidates: Sequence[str], exts: Sequence[str]) -> None:
            for base in base_candidates:
                norm = PurePosixPath(base).as_posix().lstrip("./")
                if norm in all_files and norm not in matches:
                    matches.append(norm)
                for ext in exts:
                    c1 = f"{norm}{ext}"
                    c2 = f"{norm}/index{ext}"
                    c3 = f"{norm}/__init__{ext}"
                    c4 = f"{norm}/mod{ext}"
                    for cand in (c1, c2, c3, c4):
                        if cand in all_files and cand not in matches:
                            matches.append(cand)

        if language == "python":
            mod_path = imp.module.replace(".", "/") if imp.module else ""
            if imp.level > 0:
                anchor = from_dir
                for _ in range(imp.level - 1):
                    anchor = anchor.parent
                base = (anchor / mod_path).as_posix() if mod_path else anchor.as_posix()
                _check_candidates([base], (".py",))
                # Also handle `from . import middleware` where name itself is the module
                for orig_name in imp.names.values():
                    if orig_name != "*":
                        _check_candidates([(anchor / orig_name).as_posix()], (".py",))
            else:
                if mod_path:
                    cands = [mod_path, f"src/{mod_path}"]
                    if str(from_dir) not in ("", "."):
                        cands.append((from_dir / mod_path).as_posix())
                    _check_candidates(cands, (".py",))
                    # Fallback suffix match for package roots
                    suffix = f"/{mod_path}.py"
                    for f in all_files:
                        if f.endswith(suffix) or f == f"{mod_path}.py":
                            if f not in matches:
                                matches.append(f)

        elif language in ("typescript", "javascript"):
            spec = imp.module.strip()
            if spec.startswith("."):
                joined = os.path.normpath(os.path.join(str(from_dir), spec)).replace("\\", "/")
                _check_candidates([joined], (".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs"))
            else:
                _check_candidates([spec, f"src/{spec}"], (".ts", ".tsx", ".js", ".jsx"))

        elif language == "rust":
            mod_spec = imp.module.strip()
            if mod_spec.startswith("crate::"):
                rel_mod = mod_spec[len("crate::") :].replace("::", "/")
                _check_candidates([f"src/{rel_mod}", rel_mod], (".rs",))
            elif mod_spec.startswith("super::"):
                rel_mod = mod_spec[len("super::") :].replace("::", "/")
                joined = os.path.normpath(os.path.join(str(from_dir.parent), rel_mod)).replace("\\", "/")
                _check_candidates([joined], (".rs",))
            elif mod_spec.startswith("self::"):
                rel_mod = mod_spec[len("self::") :].replace("::", "/")
                joined = os.path.normpath(os.path.join(str(from_dir), rel_mod)).replace("\\", "/")
                _check_candidates([joined], (".rs",))
            else:
                rel_mod = mod_spec.replace("::", "/")
                _check_candidates([f"src/{rel_mod}", rel_mod, (from_dir / rel_mod).as_posix()], (".rs",))

        elif language == "go":
            tail = imp.module.rsplit("/", 1)[-1]
            for f in all_files:
                if f.endswith(".go") and (PurePosixPath(f).parent.name == tail or PurePosixPath(f).stem == tail):
                    matches.append(f)

        elif language in ("c", "cpp"):
            joined = os.path.normpath(os.path.join(str(from_dir), imp.module)).replace("\\", "/")
            stem = str(PurePosixPath(joined).with_suffix(""))
            _check_candidates([joined, stem], (".h", ".hpp", ".c", ".cpp", ".cc"))

        elif language == "java":
            path_part = imp.module.replace(".", "/")
            for orig_name in imp.names.values():
                if orig_name == "*":
                    for f in all_files:
                        if f.endswith(".java") and path_part in f:
                            matches.append(f)
                else:
                    target_suffix = f"{path_part}/{orig_name}.java"
                    for f in all_files:
                        if f.endswith(target_suffix) or f.endswith(f"/{orig_name}.java"):
                            if f not in matches:
                                matches.append(f)

        return matches

    def _build_call_graph(
        self,
        parsed_files: Dict[str, _ParsedFile],
    ) -> Tuple[Dict[str, SymbolNode], Dict[str, List[CallEdge]], List[CallEdge]]:
        all_files = set(parsed_files.keys())
        symbols_by_id: Dict[str, SymbolNode] = {}
        symbols_by_file_name: Dict[Tuple[str, str], List[SymbolNode]] = {}
        symbols_by_name: Dict[str, List[SymbolNode]] = {}

        for pf in parsed_files.values():
            for sym in pf.symbols:
                symbols_by_id[sym.symbol_id] = sym
                symbols_by_file_name.setdefault((pf.rel_path, sym.name), []).append(sym)
                symbols_by_name.setdefault(sym.name, []).append(sym)

        # Build per-file resolved import symbol map:
        # file_import_symbols[rel_path][local_alias] -> List[(target_file, target_orig_name)]
        file_import_symbols: Dict[str, Dict[str, List[Tuple[str, str]]]] = {}
        for rel_path, pf in parsed_files.items():
            amap: Dict[str, List[Tuple[str, str]]] = {}
            for imp in pf.imports:
                target_files = self._resolve_import_files(rel_path, imp, pf.language, all_files)
                for local_alias, orig_name in imp.names.items():
                    for tf in target_files:
                        amap.setdefault(local_alias, []).append((tf, orig_name))
            file_import_symbols[rel_path] = amap

        def _resolve_target_symbol(
            caller_file: str,
            caller_lang: str,
            callee_name: str,
            qualifier: Optional[str],
        ) -> List[SymbolNode]:
            amap = file_import_symbols.get(caller_file, {})
            # 1. Qualified call where qualifier is an imported module/namespace alias
            if qualifier:
                q_root = qualifier.split(".", 1)[0].split("::", 1)[0]
                if q_root in amap:
                    hits: List[SymbolNode] = []
                    for tf, _ in amap[q_root]:
                        hits.extend(symbols_by_file_name.get((tf, callee_name), []))
                    if hits:
                        return hits
                # Rust path qualifier e.g. `crate::sanitizer::clean` or `sanitizer::clean`
                if "::" in qualifier or qualifier in ("crate", "super", "self"):
                    q_mod = qualifier.replace("crate::", "").replace("self::", "").replace("super::", "")
                    q_stem = q_mod.rsplit("::", 1)[-1]
                    for sym in symbols_by_name.get(callee_name, []):
                        if sym.language == caller_lang and (
                            PurePosixPath(sym.file_path).stem == q_stem
                            or q_mod.replace("::", "/") in sym.file_path
                        ):
                            return [sym]

            # 2. Direct imported symbol alias (e.g. `from .sanitizer import clean_cmd as cc`)
            if not qualifier and callee_name in amap:
                hits = []
                for tf, orig_name in amap[callee_name]:
                    lookup_name = callee_name if orig_name in ("*", "default") else orig_name
                    cands = symbols_by_file_name.get((tf, lookup_name), [])
                    if not cands and orig_name == "default":
                        # Match default exported function in target file
                        cands = parsed_files[tf].symbols[:1]
                    hits.extend(cands)
                if hits:
                    return hits

            # 3. Same-file symbol (including self.method / this.method)
            same_file = symbols_by_file_name.get((caller_file, callee_name), [])
            if same_file and (not qualifier or qualifier in ("self", "this", "cls", "super")):
                return same_file

            # 4. Same-language cross-file fallback when symbol name is unambiguous or same dir
            global_cands = [
                s
                for s in symbols_by_name.get(callee_name, [])
                if s.language == caller_lang
                or ({s.language, caller_lang} <= {"typescript", "javascript"})
                or ({s.language, caller_lang} <= {"c", "cpp"})
            ]
            if len(global_cands) == 1:
                return global_cands
            if global_cands:
                caller_dir = PurePosixPath(caller_file).parent
                same_dir = [s for s in global_cands if PurePosixPath(s.file_path).parent == caller_dir]
                if len(same_dir) == 1:
                    return same_dir
                # Match by qualifier stem (e.g. `svc.run_cmd`)
                if qualifier:
                    q_low = qualifier.rsplit(".", 1)[-1].lower()
                    by_q = [s for s in global_cands if q_low in s.file_path.lower() or q_low in s.qualified_name.lower()]
                    if by_q:
                        return by_q[:2]
            return []

        adj: Dict[str, List[CallEdge]] = {}
        edges: List[CallEdge] = []
        seen_edges: Set[Tuple[str, str, int, str]] = set()

        def _add_edge(edge: CallEdge) -> None:
            if edge.caller_id == edge.callee_id:
                return
            key = (edge.caller_id, edge.callee_id, edge.line, edge.edge_kind)
            if key in seen_edges:
                return
            seen_edges.add(key)
            adj.setdefault(edge.caller_id, []).append(edge)
            edges.append(edge)

        # A. Direct function/method calls across files
        for sym in list(symbols_by_id.values()):
            for cs in sym.calls:
                targets = _resolve_target_symbol(sym.file_path, sym.language, cs.callee_name, cs.qualifier)
                for tgt in targets:
                    _add_edge(
                        CallEdge(
                            caller_id=sym.symbol_id,
                            callee_id=tgt.symbol_id,
                            file_path=sym.file_path,
                            line=cs.line,
                            edge_kind="direct_call",
                            tainted_args=list(cs.arguments[:4]),
                            confidence=0.9 if tgt.file_path != sym.file_path else 0.85,
                        )
                    )

        # B. Framework route & middleware pipelines (Express/Fastify/Axum/Gin/Flask)
        for rel_path, pf in parsed_files.items():
            file_middlewares: List[SymbolNode] = []
            for route in pf.routes:
                if route.is_middleware_use:
                    for h in route.handlers:
                        parts = h.rsplit(".", 1)
                        qual, name = (parts[0], parts[1]) if len(parts) == 2 else (None, parts[0])
                        for resolved_mw in _resolve_target_symbol(rel_path, pf.language, name, qual):
                            if "middleware" not in resolved_mw.roles:
                                resolved_mw.roles.append("middleware")
                                if resolved_mw.role == "helper":
                                    resolved_mw.role = "middleware"
                            if resolved_mw not in file_middlewares:
                                file_middlewares.append(resolved_mw)

            for route in pf.routes:
                if route.is_middleware_use:
                    continue
                chain_nodes: List[SymbolNode] = list(file_middlewares)
                for h in route.handlers:
                    if "::" in h:
                        qual, name = h.rsplit("::", 1)
                    elif "." in h:
                        qual, name = h.rsplit(".", 1)
                    else:
                        qual, name = None, h
                    resolved = _resolve_target_symbol(rel_path, pf.language, name, qual)
                    if resolved and resolved[0] not in chain_nodes:
                        chain_nodes.append(resolved[0])

                if not chain_nodes:
                    continue

                # Synthesize route entry node so route declaration file is always represented
                route_sym_id = f"{rel_path}::route[{route.method} {route.route_path}]@L{route.line}"
                route_sym = SymbolNode(
                    symbol_id=route_sym_id,
                    name=f"{route.method} {route.route_path}",
                    qualified_name=f"route[{route.method} {route.route_path}]",
                    file_path=rel_path,
                    language=pf.language,
                    start_line=max(1, route.line - 1),
                    end_line=min(len(pf.lines), route.line + 1),
                    role="entry_point",
                    roles=["entry_point"],
                    route_pattern=route.route_path,
                    source_indicators=["route_registration"],
                    parser_backend=pf.parser_backend,
                )
                symbols_by_id[route_sym_id] = route_sym

                # Mark intermediate handlers as middleware when not already sanitizer/sink
                for mid in chain_nodes[:-1]:
                    if "sanitizer" not in mid.roles and "middleware" not in mid.roles:
                        mid.roles.append("middleware")
                        if mid.role == "helper":
                            mid.role = "middleware"

                prev_node = route_sym
                for next_node in chain_nodes:
                    _add_edge(
                        CallEdge(
                            caller_id=prev_node.symbol_id,
                            callee_id=next_node.symbol_id,
                            file_path=rel_path,
                            line=route.line,
                            edge_kind="middleware_chain",
                            tainted_args=[route.route_path],
                            confidence=0.95,
                        )
                    )
                    prev_node = next_node

        return symbols_by_id, adj, edges

    def _find_inline_sibling_sanitizers(
        self,
        caller: SymbolNode,
        next_edge: CallEdge,
        adj: Dict[str, List[CallEdge]],
        symbols_by_id: Dict[str, SymbolNode],
    ) -> List[Tuple[SymbolNode, CallEdge]]:
        """
        Detects imperative data-flow sanitizers invoked inside `caller` BEFORE
        `next_edge` (e.g. `clean = sanitize_cmd(raw); run_command(clean)`).
        """
        hits: List[Tuple[SymbolNode, CallEdge]] = []
        callee_arg_ids: Set[str] = set()
        for arg in next_edge.tainted_args:
            callee_arg_ids.update(_extract_identifiers(arg))
        # Expand one level of local variable assignments (`x = clean`)
        expanded_ids = set(callee_arg_ids)
        for var in list(callee_arg_ids):
            expanded_ids.update(caller.assignments.get(var, set()))

        for sibling_edge in adj.get(caller.symbol_id, []):
            if sibling_edge.callee_id == next_edge.callee_id:
                continue
            if sibling_edge.line > next_edge.line:
                continue
            sib_sym = symbols_by_id.get(sibling_edge.callee_id)
            if sib_sym is None or "sanitizer" not in sib_sym.roles:
                continue
            # Check whether sibling sanitizer return value feeds `next_edge` or sits directly prior
            matched_var = False
            for cs in caller.calls:
                if cs.line == sibling_edge.line and cs.callee_name == sib_sym.name:
                    if cs.assigned_to and cs.assigned_to in expanded_ids:
                        matched_var = True
                        break
                    if not cs.assigned_to and cs.raw_expr in " ".join(next_edge.tainted_args):
                        matched_var = True
                        break
            if matched_var or (0 <= next_edge.line - sibling_edge.line <= 6):
                hits.append((sib_sym, sibling_edge))
        return hits

    def _extract_taint_slices(
        self,
        parsed_files: Dict[str, _ParsedFile],
        symbols_by_id: Dict[str, SymbolNode],
        adj: Dict[str, List[CallEdge]],
    ) -> List[TaintSlice]:
        entry_nodes = [
            sym
            for sym in symbols_by_id.values()
            if "entry_point" in sym.roles or bool(sym.source_indicators)
        ]
        # If no explicit HTTP/CLI entry decorator found, seed from root callers (in-degree == 0) that reach sinks
        if not entry_nodes:
            in_deg: Dict[str, int] = {sid: 0 for sid in symbols_by_id}
            for elist in adj.values():
                for e in elist:
                    if e.callee_id in in_deg:
                        in_deg[e.callee_id] += 1
            entry_nodes = [
                sym
                for sid, sym in symbols_by_id.items()
                if in_deg.get(sid, 0) == 0 and (sid in adj or bool(sym.sink_matches))
            ]

        slices: List[TaintSlice] = []
        seen_slice_keys: Set[Tuple[str, Tuple[str, ...], str, int]] = set()

        def _build_slice(
            node_path: List[SymbolNode],
            edge_path: List[CallEdge],
            sink_match: Dict[str, Any],
        ) -> Optional[TaintSlice]:
            # Expand sibling sanitizers invoked along the path in exact execution order
            ordered_entries: List[Tuple[SymbolNode, Optional[int], str]] = []
            for idx, node in enumerate(node_path):
                edge_out = edge_path[idx] if idx < len(edge_path) else None
                if idx == 0:
                    step_role = "entry_point"
                elif idx == len(node_path) - 1:
                    step_role = "sink"
                elif "sanitizer" in node.roles:
                    step_role = "sanitizer"
                elif "middleware" in node.roles:
                    step_role = "middleware"
                else:
                    step_role = "propagation"

                call_ln = edge_out.line if edge_out is not None else int(sink_match["line"])
                ordered_entries.append((node, call_ln, step_role))

                if edge_out is not None:
                    sib_sanitizers = self._find_inline_sibling_sanitizers(node, edge_out, adj, symbols_by_id)
                    existing_ids = {n.symbol_id for n in node_path}
                    for sib_sym, sib_edge in sib_sanitizers:
                        if sib_sym.symbol_id not in existing_ids:
                            ordered_entries.append((sib_sym, sib_edge.line, "sanitizer"))

            # Also detect sibling sanitizer called directly inside the sink node right before the sink line
            sink_node = node_path[-1]
            sink_line = int(sink_match["line"])
            pseudo_sink_edge = CallEdge(
                caller_id=sink_node.symbol_id,
                callee_id=f"__sink__@{sink_line}",
                file_path=sink_node.file_path,
                line=sink_line,
                tainted_args=[str(sink_match.get("call_text", ""))],
            )
            sink_sibs = self._find_inline_sibling_sanitizers(sink_node, pseudo_sink_edge, adj, symbols_by_id)
            present_ids = {n.symbol_id for n, _, _ in ordered_entries}
            for sib_sym, sib_edge in sink_sibs:
                if sib_sym.symbol_id not in present_ids:
                    # Insert sanitizer step right before the final sink step
                    ordered_entries.insert(max(1, len(ordered_entries) - 1), (sib_sym, sib_edge.line, "sanitizer"))

            path_ids = tuple(n.symbol_id for n, _, _ in ordered_entries)
            vuln_cls = str(sink_match["vulnerability_class"])
            dedup_key = (ordered_entries[0][0].symbol_id, path_ids, vuln_cls, sink_line)
            if dedup_key in seen_slice_keys:
                return None
            seen_slice_keys.add(dedup_key)

            steps: List[SliceStep] = []
            files_involved: List[str] = []
            sanitizers_info: List[Dict[str, Any]] = []
            backends_used: Set[str] = set()

            for step_idx, (sym, call_ln, role) in enumerate(ordered_entries):
                pf = parsed_files.get(sym.file_path)
                file_lines = pf.lines if pf is not None else []
                focus: List[int] = []
                if call_ln:
                    focus.append(call_ln)
                if step_idx == len(ordered_entries) - 1:
                    focus.append(sink_line)
                snippet = _build_focused_snippet(file_lines, sym.start_line, sym.end_line, focus_lines=focus)
                if sym.file_path not in files_involved:
                    files_involved.append(sym.file_path)
                backends_used.add(sym.parser_backend)

                notes_parts: List[str] = []
                if sym.route_pattern:
                    notes_parts.append(f"route={sym.route_pattern}")
                if sym.source_indicators and step_idx == 0:
                    notes_parts.append("sources=" + ",".join(sym.source_indicators[:2]))
                if sym.sanitizer_strength != "none":
                    notes_parts.append(f"sanitizer={sym.sanitizer_strength}({','.join(sym.sanitizer_indicators[:2])})")
                    sanitizers_info.append(
                        {
                            "symbol_id": sym.symbol_id,
                            "symbol_name": sym.name,
                            "file_path": sym.file_path,
                            "start_line": sym.start_line,
                            "end_line": sym.end_line,
                            "strength": sym.sanitizer_strength,
                            "indicators": list(sym.sanitizer_indicators),
                        }
                    )
                if step_idx == len(ordered_entries) - 1:
                    notes_parts.append(f"sink={sink_match['matched_token']}")

                steps.append(
                    SliceStep(
                        step_index=step_idx,
                        role=role,
                        symbol_id=sym.symbol_id,
                        symbol_name=sym.name,
                        file_path=sym.file_path,
                        start_line=sym.start_line,
                        end_line=sym.end_line,
                        call_line=call_ln,
                        language=sym.language,
                        snippet=snippet,
                        notes="; ".join(notes_parts),
                    )
                )

            if any(s["strength"] == "strong" for s in sanitizers_info):
                sanitizer_status = "sanitized"
            elif sanitizers_info:
                sanitizer_status = "weak_sanitizer"
            else:
                sanitizer_status = "unsanitized"

            # Confidence calibration
            conf = 0.65
            if ordered_entries[0][0].source_indicators or ordered_entries[0][0].route_pattern:
                conf += 0.15
            if len(files_involved) >= 2:
                conf += 0.10
            if sanitizer_status == "unsanitized":
                conf += 0.08
            elif sanitizer_status == "weak_sanitizer":
                conf += 0.04
            else:
                conf -= 0.15
            conf = max(0.15, min(0.99, round(conf, 3)))

            poe_hint = 1 if sanitizer_status in ("unsanitized", "weak_sanitizer") and conf >= 0.7 else 0
            source_backend = (
                next(iter(backends_used)) if len(backends_used) == 1 else "hybrid"
            )
            digest = hashlib.sha256(
                f"{path_ids}|{vuln_cls}|{sink_line}".encode("utf-8")
            ).hexdigest()[:12]

            sl = TaintSlice(
                slice_id=f"slice-{digest}",
                vulnerability_class=vuln_cls,
                cwe=str(sink_match["cwe"]),
                severity=str(sink_match["severity"]),
                entry_point=ordered_entries[0][0].symbol_id,
                sink=f"{sink_node.symbol_id}@L{sink_line}",
                sink_call=str(sink_match["call_text"]),
                sink_file=sink_node.file_path,
                sink_line=sink_line,
                steps=steps,
                files_involved=files_involved,
                is_cross_file=len(files_involved) >= 2,
                sanitizers=sanitizers_info,
                sanitizer_status=sanitizer_status,
                taint_confidence=conf,
                poe_hint=poe_hint,
                source_backend=source_backend,
            )
            sl.prompt_context = sl.to_prompt_block(max_chars=self.max_prompt_chars)
            return sl

        # Precompute reverse reachability from all sink-bearing symbols in O(V + E)
        # so the forward DFS never explores dead-end subgraphs that cannot reach a sink.
        rev_adj: Dict[str, List[str]] = {}
        for caller_id, elist in adj.items():
            for e in elist:
                rev_adj.setdefault(e.callee_id, []).append(caller_id)

        dist_to_sink: Dict[str, int] = {}
        bfs_queue: List[str] = []
        for sid, sym in symbols_by_id.items():
            if sym.sink_matches:
                dist_to_sink[sid] = 0
                bfs_queue.append(sid)
        q_idx = 0
        while q_idx < len(bfs_queue):
            cur_sid = bfs_queue[q_idx]
            q_idx += 1
            cur_d = dist_to_sink[cur_sid]
            if cur_d + 1 >= self.max_depth:
                continue
            for prev_sid in rev_adj.get(cur_sid, ()):
                if prev_sid not in dist_to_sink:
                    dist_to_sink[prev_sid] = cur_d + 1
                    bfs_queue.append(prev_sid)

        # Bounded DFS from each entry point that can reach at least one sink
        for entry in entry_nodes:
            if entry.symbol_id not in dist_to_sink:
                continue
            stack: List[Tuple[List[SymbolNode], List[CallEdge], Set[str]]] = [([entry], [], {entry.symbol_id})]
            seen_at_depth: Dict[str, int] = {entry.symbol_id: 1}
            expansions = 0
            entry_slices = 0
            while stack and expansions < 512 and entry_slices < 16:
                cur_nodes, cur_edges, visited = stack.pop()
                expansions += 1
                tail = cur_nodes[-1]

                if tail.sink_matches:
                    for sm in tail.sink_matches:
                        sl = _build_slice(cur_nodes, cur_edges, sm)
                        if sl is not None:
                            slices.append(sl)
                            entry_slices += 1
                            if len(slices) >= self.max_slices:
                                return slices

                cur_len = len(cur_nodes)
                if cur_len >= self.max_depth:
                    continue
                rem_budget = self.max_depth - cur_len

                for edge in adj.get(tail.symbol_id, []):
                    cid = edge.callee_id
                    if cid in visited:
                        continue
                    rem_dist = dist_to_sink.get(cid)
                    if rem_dist is None or rem_dist >= rem_budget:
                        continue
                    prev_best = seen_at_depth.get(cid)
                    if prev_best is not None and prev_best <= cur_len + 1:
                        continue
                    seen_at_depth[cid] = cur_len + 1
                    nxt = symbols_by_id.get(cid)
                    if nxt is None:
                        continue
                    stack.append((cur_nodes + [nxt], cur_edges + [edge], visited | {cid}))

        return slices

    def _run_optional_codeql(
        self,
        repo_root: Path,
        *,
        enable_codeql: bool,
        codeql_bin: Optional[str],
        codeql_sarif_paths: Optional[Sequence[Union[str, Path]]],
        codeql_bqrs_paths: Optional[Sequence[Union[str, Path]]],
        codeql_db_path: Optional[Union[str, Path]],
        codeql_query_suite: Optional[str],
    ) -> Tuple[CodeQLReport, List[TaintSlice]]:
        cql_report = detect_codeql(codeql_bin=codeql_bin, enabled=enable_codeql)
        extracted: List[TaintSlice] = []

        # Ingest explicit SARIF reports even when CodeQL CLI is absent
        for raw_sarif in (codeql_sarif_paths or ()):
            sp = Path(raw_sarif)
            if sp.is_file():
                cql_report.sarif_paths.append(str(sp))
                extracted.extend(parse_codeql_sarif_slices(sp, repo_root))

        # Ingest explicit BQRS files if CodeQL CLI is available
        if cql_report.available and cql_report.binary_path:
            for raw_bqrs in (codeql_bqrs_paths or ()):
                bp = Path(raw_bqrs)
                if bp.is_file():
                    cql_report.bqrs_paths.append(str(bp))
                    extracted.extend(parse_codeql_bqrs_slices(bp, repo_root, cql_report.binary_path))

        if enable_codeql and cql_report.available and cql_report.binary_path:
            if codeql_db_path is not None:
                db_dir = Path(codeql_db_path)
                if db_dir.is_dir():
                    out_sarif = db_dir / "rfchunt_codeql_results.sarif"
                    cmd = [
                        cql_report.binary_path,
                        "database",
                        "analyze",
                        str(db_dir),
                        "--format=sarifv2.1.0",
                        f"--output={out_sarif}",
                    ]
                    if codeql_query_suite:
                        cmd.append(str(codeql_query_suite))
                    try:
                        proc = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            timeout=180,
                            check=False,
                            shell=False,
                        )
                        if proc.returncode == 0 and out_sarif.is_file():
                            cql_report.executed = True
                            cql_report.status = "executed"
                            cql_report.sarif_paths.append(str(out_sarif))
                            extracted.extend(parse_codeql_sarif_slices(out_sarif, repo_root))
                        else:
                            cql_report.status = "failed"
                            cql_report.error = (proc.stderr or proc.stdout or f"exit={proc.returncode}").strip()[:300]
                    except Exception as exc:
                        cql_report.status = "failed"
                        cql_report.error = str(exc)[:300]
                else:
                    cql_report.status = "skipped_no_database"
            elif extracted:
                cql_report.executed = True
                cql_report.status = "executed"

        cql_report.extracted_slices = len(extracted)
        return cql_report, extracted

    def analyze_repo(
        self,
        repo_path: Union[str, Path],
        *,
        enable_codeql: bool = False,
        codeql_bin: Optional[str] = None,
        codeql_sarif_paths: Optional[Sequence[Union[str, Path]]] = None,
        codeql_bqrs_paths: Optional[Sequence[Union[str, Path]]] = None,
        codeql_db_path: Optional[Union[str, Path]] = None,
        codeql_query_suite: Optional[str] = None,
    ) -> CallGraphReport:
        """
        Concurrently parses all supported source files in `repo_path`, builds
        the cross-file call graph, extracts source-to-sink `TaintSlice` chains,
        and merges optional CodeQL SARIF/BQRS flows.
        """
        t0 = time.perf_counter()
        root = Path(repo_path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Repository path does not exist: {repo_path}")

        if root.is_file():
            ext = root.suffix.lower()
            lang = LANGUAGE_BY_EXT.get(ext)
            source_items = [(root, root.name, lang)] if lang else []
            root = root.parent
        else:
            source_items = self._discover_source_files(root)

        parsed_files: Dict[str, _ParsedFile] = {}
        languages_detected: Dict[str, int] = {}
        parser_backends: Dict[str, str] = {}

        if len(source_items) > 1 and self.max_workers > 1:
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(source_items))) as pool:
                for pf in pool.map(self._parse_single_file, source_items):
                    if pf is not None:
                        parsed_files[pf.rel_path] = pf
                        languages_detected[pf.language] = languages_detected.get(pf.language, 0) + 1
                        parser_backends[pf.language] = pf.parser_backend
        else:
            for item in source_items:
                pf = self._parse_single_file(item)
                if pf is not None:
                    parsed_files[pf.rel_path] = pf
                    languages_detected[pf.language] = languages_detected.get(pf.language, 0) + 1
                    parser_backends[pf.language] = pf.parser_backend

        symbols_by_id, adj, edges = self._build_call_graph(parsed_files)
        slices = self._extract_taint_slices(parsed_files, symbols_by_id, adj)

        cql_report, cql_slices = self._run_optional_codeql(
            root,
            enable_codeql=enable_codeql,
            codeql_bin=codeql_bin,
            codeql_sarif_paths=codeql_sarif_paths,
            codeql_bqrs_paths=codeql_bqrs_paths,
            codeql_db_path=codeql_db_path,
            codeql_query_suite=codeql_query_suite,
        )
        if cql_slices:
            slices.extend(cql_slices)

        # Deterministic ranking: unsanitized/weak cross-file high-severity first
        san_rank = {"unsanitized": 2, "weak_sanitizer": 1, "sanitized": 0}
        slices.sort(
            key=lambda s: (
                -san_rank.get(s.sanitizer_status, 0),
                -(1 if s.is_cross_file else 0),
                -SEVERITY_ORDER.get(s.severity, 0),
                -s.taint_confidence,
                s.slice_id,
            )
        )
        if len(slices) > self.max_slices:
            slices = slices[: self.max_slices]

        elapsed = time.perf_counter() - t0
        self._last_parsed_files = parsed_files
        self._last_symbols_by_id = symbols_by_id
        self._last_adj = adj
        self._last_edges = edges
        return CallGraphReport(
            repo_root=str(root),
            files_scanned=len(parsed_files),
            languages_detected=languages_detected,
            parser_backends=parser_backends,
            tree_sitter_available=self.tree_sitter_available,
            symbols_count=len(symbols_by_id),
            edges_count=len(edges),
            slices=slices,
            cross_file_slices_count=sum(1 for s in slices if s.is_cross_file),
            codeql=cql_report,
            elapsed_sec=elapsed,
        )

    def build_graph_context(self, repo_path: Union[str, Path]) -> CallGraphContext:
        """
        Builds and returns the full `CallGraphContext` (parsed files, symbol table,
        forward adjacency `adj`, reverse adjacency `rev_adj`, and `CallGraphReport`)
        in a single pass so static verification-inversion passes can reuse it.
        """
        report = self.analyze_repo(repo_path)
        parsed_files = getattr(self, "_last_parsed_files", {})
        symbols_by_id = getattr(self, "_last_symbols_by_id", {})
        adj = getattr(self, "_last_adj", {})
        edges = getattr(self, "_last_edges", [])
        rev_adj: Dict[str, List[CallEdge]] = {}
        for elist in adj.values():
            for e in elist:
                rev_adj.setdefault(e.callee_id, []).append(e)
        return CallGraphContext(
            repo_root=Path(report.repo_root),
            parsed_files=parsed_files,
            symbols_by_id=symbols_by_id,
            adj=adj,
            rev_adj=rev_adj,
            edges=edges,
            report=report,
        )


def slice_repository(
    repo_path: Union[str, Path],
    *,
    enable_codeql: bool = False,
    codeql_bin: Optional[str] = None,
    codeql_sarif_paths: Optional[Sequence[Union[str, Path]]] = None,
    codeql_bqrs_paths: Optional[Sequence[Union[str, Path]]] = None,
    codeql_db_path: Optional[Union[str, Path]] = None,
    codeql_query_suite: Optional[str] = None,
    max_depth: int = 8,
    max_slices: int = 200,
    max_prompt_chars: int = 4000,
) -> CallGraphReport:
    """Convenience entry point for CLI and swarm orchestrators."""
    slicer = CallGraphSlicer(
        max_depth=max_depth,
        max_slices=max_slices,
        max_prompt_chars=max_prompt_chars,
    )
    return slicer.analyze_repo(
        repo_path,
        enable_codeql=enable_codeql,
        codeql_bin=codeql_bin,
        codeql_sarif_paths=codeql_sarif_paths,
        codeql_bqrs_paths=codeql_bqrs_paths,
        codeql_db_path=codeql_db_path,
        codeql_query_suite=codeql_query_suite,
    )
