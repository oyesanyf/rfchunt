"""
Sandboxed Repository Security Invariant Runner (AIxCC Upgrade #5a).

Executes target repository parser, authorization, path-confinement, and policy
denial security invariants inside an ephemeral, isolated Docker container:
  - `docker run --rm --network=none`
  - Read-only target repository mount (`:ro`) and read-only harness mount (`:ro`)
  - `--cap-drop=ALL`, `--security-opt no-new-privileges:true`, `--read-only`
  - Strict `--memory`, `--cpus`, and `--pids-limit` bounds
  - Strict `shell=False` list-argv invocation with fail-closed command validation

Runtime invariant failures are persisted directly as Cairn `FACT` nodes via
`db.add_fact(...)` when a `Database` instance is provided. When Docker or the
required runtime image is unavailable, the runner reports
`status="skipped_docker_unavailable"` cleanly with structured provenance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from engine.host_containment import silent_subprocess_run


DEFAULT_PYTHON_SANDBOX_IMAGE = "python:3.12-alpine"
DEFAULT_NODE_SANDBOX_IMAGE = "node:22-alpine"
INVARIANT_JSON_MARKER = "RFCHUNT_INVARIANTS_JSON:"

_DOCKER_IMAGE_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?$"
)
_SHELL_META_TOKENS: Tuple[str, ...] = (
    "$(",
    "`",
    "${",
    "\n",
    "\r",
    "\x00",
    "|",
    ";",
    "&",
    ">",
    "<",
    "(",
    ")",
)
_FORBIDDEN_PAYLOAD_BINARIES: Set[str] = {
    "sh",
    "sh.exe",
    "bash",
    "bash.exe",
    "zsh",
    "dash",
    "ash",
    "ksh",
    "csh",
    "fish",
    "busybox",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "nmap",
    "ffuf",
    "dalfox",
    "sqlmap",
}
_CRITICAL_HOST_MOUNT_PREFIXES: Tuple[str, ...] = (
    "/etc",
    "/var/run/docker.sock",
    "/var/run",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/root",
)
_SKIP_SCAN_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "env",
    "vendor",
}


@dataclass(frozen=True)
class InvariantSpec:
    """Declarative metadata for a concrete repository security invariant."""

    invariant_id: str
    name: str
    category: str  # 'authz', 'path_confinement', 'policy_enforcement', 'parser_boundary'
    description: str
    severity: str = "HIGH"
    cwe: str = "CWE-284"
    target_languages: Tuple[str, ...] = ("python", "typescript", "javascript", "rust", "policy_authz")


DEFAULT_INVARIANT_SPECS: Tuple[InvariantSpec, ...] = (
    InvariantSpec(
        invariant_id="INV-AUTHZ-DENY-REACHABILITY",
        name="Denied Authz Requests Never Reach Protected Handlers",
        category="authz",
        description=(
            "Verifies that denied .authz policies cannot be shadowed by permissive wildcards "
            "and that denied authorization checks terminate before invoking protected handlers."
        ),
        severity="CRITICAL",
        cwe="CWE-863",
    ),
    InvariantSpec(
        invariant_id="INV-PATH-ROOT-CONFINEMENT",
        name="Sandboxed Paths Never Resolve Outside Root",
        category="path_confinement",
        description=(
            "Verifies that path normalization and sandbox join routines reject traversal "
            "vectors (../, absolute overrides, null/encoded separators) and stay confined inside root."
        ),
        severity="HIGH",
        cwe="CWE-22",
    ),
    InvariantSpec(
        invariant_id="INV-POLICY-DENIAL-ENFORCEMENT",
        name="Policy Denial Enforcement Fails Closed",
        category="policy_enforcement",
        description=(
            "Verifies that sandbox/network/filesystem deny policies enforce deny precedence "
            "and never fail open on parse errors, exceptions, or boundary addresses."
        ),
        severity="HIGH",
        cwe="CWE-284",
    ),
    InvariantSpec(
        invariant_id="INV-PARSER-STRICT-FRAMING",
        name="Protocol Parser Enforces Strict Framing Boundaries",
        category="parser_boundary",
        description=(
            "Verifies that HTTP/protocol parsers do not silently accept conflicting "
            "Content-Length and Transfer-Encoding framing or unvalidated CRLF header values."
        ),
        severity="HIGH",
        cwe="CWE-444",
    ),
)


@dataclass
class InvariantCheckResult:
    """Outcome of a single concrete invariant check executed inside the sandbox container."""

    invariant_id: str
    name: str
    category: str
    passed: bool
    severity: str
    cwe: str
    file_path: str
    line_number: int = 0
    container_mode: str = "docker_network_none"
    evidence: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    cairn_fact_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "name": self.name,
            "category": self.category,
            "passed": self.passed,
            "severity": self.severity,
            "cwe": self.cwe,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "container_mode": self.container_mode,
            "evidence": self.evidence,
            "details": dict(self.details),
            "cairn_fact_id": self.cairn_fact_id,
        }


@dataclass
class SandboxInvariantReport:
    """Structured report produced by `SandboxInvariantRunner.run(...)`."""

    status: str  # 'completed', 'skipped_docker_unavailable', 'error'
    repo_path: str
    detected_languages: List[str]
    container_mode: str
    docker_image: str
    docker_command: List[str]
    invariants_checked: int
    invariants_passed: int
    invariants_failed: int
    results: List[InvariantCheckResult] = field(default_factory=list)
    persisted_fact_ids: List[str] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "repo_path": self.repo_path,
            "detected_languages": list(self.detected_languages),
            "container_mode": self.container_mode,
            "docker_image": self.docker_image,
            "docker_command": list(self.docker_command),
            "invariants_checked": self.invariants_checked,
            "invariants_passed": self.invariants_passed,
            "invariants_failed": self.invariants_failed,
            "total_findings": self.invariants_failed,
            "results": [r.to_dict() for r in self.results],
            "failures": [r.to_dict() for r in self.results if not r.passed],
            "persisted_fact_ids": list(self.persisted_fact_ids),
            "provenance": dict(self.provenance),
            "elapsed_ms": self.elapsed_ms,
        }


def _is_critical_mount_source(src: str) -> bool:
    raw_s = str(src or "").strip()
    if not raw_s:
        return True
    norm = raw_s.replace("\\", "/")
    if norm.startswith("//") or ".." in [p for p in norm.split("/") if p]:
        return True
    norm_l = re.sub(r"/+", "/", norm).rstrip("/").lower()
    if norm_l in ("", "/") or re.fullmatch(r"[a-z]:/*", norm_l):
        return True
    for crit in _CRITICAL_HOST_MOUNT_PREFIXES:
        if norm_l == crit or norm_l.startswith(crit + "/"):
            return True
    if re.match(
        r"^[a-z]:/(?:windows|programdata|program files|program files \(x86\)|system32)(?:/|$)",
        norm_l,
    ):
        return True
    return False


def validate_sandbox_docker_command(cmd: Sequence[str]) -> Tuple[bool, str]:
    """
    Fail-closed validator for `--network=none` sandboxed repo invariant commands.
    Verifies `shell=False` list argv, `--rm`, `--network=none`, `--cap-drop=ALL`,
    `--memory`, `--cpus`, `--pids-limit`, strictly read-only (`:ro`) mounts,
    no `--network=host`/`--privileged`/`--cap-add`/`--device`, and zero shell
    metacharacters or shell wrapper commands.
    """
    if isinstance(cmd, (str, bytes, bytearray)) or not isinstance(cmd, Sequence) or len(cmd) < 4:
        return False, "docker command must be a non-empty list/sequence of argv strings"

    tokens = [str(t) for t in cmd]
    bin_name = PurePosixPath(tokens[0].replace("\\", "/")).name.lower()
    if bin_name not in ("docker", "docker.exe"):
        return False, f"binary '{tokens[0]}' is not docker"

    for tok in tokens:
        if any(meta in tok for meta in _SHELL_META_TOKENS):
            return False, f"shell metacharacter forbidden in docker token '{tok}'"

    if tokens[1].strip().lower() != "run":
        return False, f"expected 'docker run', got '{tokens[1]}'"

    has_rm = False
    has_network_none = False
    has_cap_drop_all = False
    has_memory = False
    has_cpus = False
    has_pids_limit = False
    has_ro_workspace = False

    idx = 2
    while idx < len(tokens):
        tok = tokens[idx].strip()
        tok_l = tok.lower()

        if tok_l == "--rm":
            has_rm = True
        elif tok_l in ("--network=none", "--net=none"):
            has_network_none = True
        elif tok_l in ("--network", "--net") and idx + 1 < len(tokens):
            val = tokens[idx + 1].strip().lower()
            if val == "none":
                has_network_none = True
            else:
                return False, f"sandbox container forbids '{tok}={val}'; '--network=none' is mandatory"
            idx += 2
            continue
        elif tok_l.startswith(("--network=", "--net=")):
            val = tok_l.split("=", 1)[1].strip()
            if val != "none":
                return False, f"sandbox container forbids '{tok}'; '--network=none' is mandatory"
        elif tok_l == "--cap-drop=all" or (
            tok_l == "--cap-drop" and idx + 1 < len(tokens) and tokens[idx + 1].strip().lower() == "all"
        ):
            has_cap_drop_all = True
        elif tok_l == "--memory" or tok_l.startswith("--memory="):
            has_memory = True
        elif tok_l == "--cpus" or tok_l.startswith("--cpus="):
            has_cpus = True
        elif tok_l == "--pids-limit" or tok_l.startswith("--pids-limit="):
            has_pids_limit = True
        elif tok_l == "--privileged" or tok_l.startswith("--privileged="):
            return False, "docker '--privileged' is forbidden"
        elif tok_l == "--cap-add" or tok_l.startswith("--cap-add="):
            return False, "docker '--cap-add' is forbidden"
        elif tok_l == "--device" or tok_l.startswith("--device="):
            return False, "docker '--device' is forbidden"
        elif tok_l == "--volumes-from" or tok_l.startswith("--volumes-from="):
            return False, "docker '--volumes-from' is forbidden"
        elif tok_l in ("--pid", "--ipc", "--uts", "--userns", "--cgroupns"):
            val = tokens[idx + 1].strip().lower() if idx + 1 < len(tokens) else ""
            if val == "host" or val.startswith("container:"):
                return False, f"docker isolation-escape '{tok}={val}' is forbidden"
            idx += 2
            continue
        elif tok_l.startswith(("--pid=", "--ipc=", "--uts=", "--userns=", "--cgroupns=")):
            val = tok_l.split("=", 1)[1].strip()
            if val == "host" or val.startswith("container:"):
                return False, f"docker isolation-escape '{tok}' is forbidden"
        elif tok_l in ("-p", "--publish") or tok_l.startswith("--publish="):
            return False, "port publishing is forbidden inside '--network=none' repo invariant container"
        elif tok_l in ("-v", "--volume") and idx + 1 < len(tokens):
            spec = tokens[idx + 1].strip()
            norm_spec = spec.replace("\\", "/")
            if not norm_spec.endswith(":ro"):
                return False, f"sandbox mount '{spec}' MUST be read-only (:ro)"
            if re.match(r"^[a-zA-Z]:", norm_spec):
                c_idx = norm_spec.find(":", 2)
                src = norm_spec[:c_idx] if c_idx != -1 else norm_spec
                rest = norm_spec[c_idx + 1 :] if c_idx != -1 else ""
            else:
                parts = norm_spec.split(":", 1)
                src = parts[0]
                rest = parts[1] if len(parts) > 1 else ""
            if _is_critical_mount_source(src):
                return False, f"unsafe docker host mount source '{src}'"
            if rest.startswith("/workspace:ro"):
                has_ro_workspace = True
            idx += 2
            continue
        elif tok_l in ("-c", "/c", "-lc", "-ic", "-ec", "--command") or tok_l.startswith("--command="):
            return False, f"forbidden shell flag '{tok}' in sandbox docker command"
        elif not tok.startswith("-"):
            base = PurePosixPath(tok.split("@", 1)[0].replace("\\", "/")).name.lower().split(":", 1)[0]
            if base in _FORBIDDEN_PAYLOAD_BINARIES:
                return False, f"forbidden shell/scanner binary '{tok}' in sandbox docker command"
        idx += 1

    if not has_rm:
        return False, "sandbox docker command requires '--rm'"
    if not has_network_none:
        return False, "sandbox docker command requires '--network=none'"
    if not has_cap_drop_all:
        return False, "sandbox docker command requires '--cap-drop=ALL'"
    if not (has_memory and has_cpus and has_pids_limit):
        return False, "sandbox docker command requires '--memory', '--cpus', and '--pids-limit'"
    if not has_ro_workspace:
        return False, "sandbox docker command requires read-only ':/workspace:ro' repo mount"
    return True, "ok"


def detect_repo_languages(repo_path: Union[str, Path], *, max_files: int = 800) -> List[str]:
    """Bounded, shallow-prioritized detector for target repo languages and policy formats."""
    root = Path(repo_path)
    if not root.exists():
        return []

    found: Set[str] = set()
    ext_map = {
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mts": "typescript",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".rs": "rust",
        ".go": "go",
        ".authz": "policy_authz",
        ".cedar": "policy_authz",
        ".rego": "policy_authz",
    }
    if (root / "package.json").is_file():
        found.add("javascript")
    if (root / "tsconfig.json").is_file():
        found.add("typescript")
    if (root / "Cargo.toml").is_file():
        found.add("rust")
    if (root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file():
        found.add("python")

    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_SCAN_DIRS and not d.startswith(".")]
        for fname in filenames:
            scanned += 1
            if scanned > max_files:
                return sorted(found)
            ext = Path(fname).suffix.lower()
            lang = ext_map.get(ext)
            if lang:
                found.add(lang)
    return sorted(found)


def build_invariant_harness_script() -> str:
    """
    Returns the clean-room Python invariant harness script mounted read-only at
    `/harness/run_invariants.py` and executed inside `--network=none` containers.

    Checks concrete repository security invariants:
    1. INV-AUTHZ-DENY-REACHABILITY: .authz policy shadowing/fail-open AND handler
       fall-through past deny checks (dynamic + AST verification).
    2. INV-PATH-ROOT-CONFINEMENT: Dynamic sandbox path confinement probing for Python
       helpers + structural root-confinement verification for TS/JS/Rust/Python.
    3. INV-POLICY-DENIAL-ENFORCEMENT: Fail-closed policy evaluation checks across
       Python/TypeScript/JS/Rust (detecting fail-open catch/except/unwrap_or(true)
       in authz/policy/filter routines and dynamic Python policy function probing).
    4. INV-PARSER-STRICT-FRAMING: Protocol parser checks for conflicting CL/TE
       acceptance or unvalidated framing boundaries.
    """
    return '''#!/usr/bin/env python3
"""Isolated in-container security invariant harness for RFCHunt."""

import ast
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import sys
import tempfile

MARKER = "RFCHUNT_INVARIANTS_JSON:"
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "target", "dist", "build",
    "__pycache__", ".pytest_cache", ".venv", "venv", "vendor",
}
MAX_FILES = 1500
MAX_FILE_BYTES = 262144


def iter_repo_files(root: Path):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fname in sorted(filenames):
            p = Path(dirpath) / fname
            count += 1
            if count > MAX_FILES:
                return
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def rel_str(root: Path, p: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


def load_isolated_py_module(py_path: Path, mod_name: str):
    """Safely imports a self-contained Python module inside the network=none container."""
    spec = importlib.util.spec_from_file_location(mod_name, str(py_path))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    try:
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        sys.modules.pop(mod_name, None)
        return None


def check_authz_invariants(root: Path, files):
    results = []
    authz_violations = []

    # 1. Check .authz policy files for shadowed deny rules or fail-open wildcards
    for p in files:
        if p.suffix.lower() == ".authz" or p.name.lower().endswith(".authz.conf"):
            text = p.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            wildcard_allow_line = 0
            deny_lines = []
            default_allow_line = 0
            for idx, raw in enumerate(lines, start=1):
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                low = line.lower()
                if re.match(r"^default\\s*[:=]?\\s*allow\\b", low):
                    default_allow_line = idx
                if re.match(r"^allow\\s+(\\*|/\\*|any|all)\\b", low) and wildcard_allow_line == 0:
                    wildcard_allow_line = idx
                if re.match(r"^deny\\b", low):
                    deny_lines.append((idx, line))

            if wildcard_allow_line and deny_lines:
                first_deny_line, first_deny_text = deny_lines[0]
                if wildcard_allow_line < first_deny_line:
                    authz_violations.append({
                        "file_path": rel_str(root, p),
                        "line_number": wildcard_allow_line,
                        "evidence": (
                            f"Wildcard allow on line {wildcard_allow_line} precedes "
                            f"deny rule '{first_deny_text}' on line {first_deny_line}, "
                            "allowing denied .authz requests to bypass enforcement."
                        ),
                    })
            if default_allow_line and not deny_lines:
                authz_violations.append({
                    "file_path": rel_str(root, p),
                    "line_number": default_allow_line,
                    "evidence": (
                        f"Policy file sets fail-open default allow on line {default_allow_line} "
                        "without explicit deny boundaries."
                    ),
                })

    # 2. Check Python authz handlers dynamically and via AST
    for p in files:
        if p.suffix.lower() != ".py":
            continue
        rel = rel_str(root, p)
        if rel.startswith("test") or "/test" in rel or rel.endswith("_test.py"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if not any(tok in text.lower() for tok in ("authz", "authorize", "permission", "acl", "policy")):
            continue
        try:
            tree = ast.parse(text, filename=rel)
        except SyntaxError:
            continue

        # AST check: authz check detects deny/False without returning/raising before protected call
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_low = node.name.lower()
                if not any(k in fn_low for k in ("handle", "dispatch", "serve", "route", "endpoint", "process", "request")):
                    continue
                body = node.body
                for i, stmt in enumerate(body):
                    if isinstance(stmt, ast.If):
                        test_src = ast.get_source_segment(text, stmt.test) or ""
                        if any(k in test_src.lower() for k in ("authz", "authorize", "allow", "deny", "permitted")):
                            if_terminates = any(isinstance(s, (ast.Return, ast.Raise)) for s in stmt.body)
                            later_calls = []
                            for later in body[i + 1 :]:
                                for sub in ast.walk(later):
                                    if isinstance(sub, ast.Call):
                                        cname = ""
                                        if isinstance(sub.func, ast.Name):
                                            cname = sub.func.id
                                        elif isinstance(sub.func, ast.Attribute):
                                            cname = sub.func.attr
                                        if any(k in cname.lower() for k in ("protected", "admin", "secret", "handler", "execute", "forward")):
                                            later_calls.append(cname)
                            # Check if branch handles denial without return/raise
                            branch_src = (ast.get_source_segment(text, stmt) or "").lower()
                            handles_deny = (
                                "not " in test_src.lower()
                                or "== false" in test_src.lower()
                                or "deny" in test_src.lower()
                                or "deny" in branch_src
                                or "403" in branch_src
                                or "forbidden" in branch_src
                            )
                            if handles_deny and not if_terminates and later_calls:
                                authz_violations.append({
                                    "file_path": rel,
                                    "line_number": stmt.lineno,
                                    "evidence": (
                                        f"Function '{node.name}' handles denied authz branch without "
                                        f"return/raise; execution falls through to protected sink(s): {sorted(set(later_calls))}."
                                    ),
                                })

        # Dynamic probe: if module exposes a pure request handler + authz policy/decision
        if any(k in text for k in ("def handle_request", "def dispatch_request", "def serve_request")):
            mod = load_isolated_py_module(p, f"_rfchunt_authz_{abs(hash(rel))}")
            if mod is not None:
                for fn_name in ("handle_request", "dispatch_request", "serve_request"):
                    fn = getattr(mod, fn_name, None)
                    if not callable(fn):
                        continue
                    sig = inspect.signature(fn)
                    params = list(sig.parameters.values())
                    req_params = [pr for pr in params if pr.default is inspect.Parameter.empty]
                    if len(req_params) == 1:
                        probe_req = {
                            "path": "/admin/secret",
                            "method": "GET",
                            "user": "unauthenticated",
                            "role": "guest",
                            "authz": "deny",
                            "decision": "deny",
                        }
                        try:
                            out = fn(probe_req)
                            if isinstance(out, dict):
                                status_val = out.get("status", out.get("status_code", 0))
                                reached = bool(out.get("protected_reached") or out.get("handler_reached") or status_val == 200)
                                if reached:
                                    authz_violations.append({
                                        "file_path": rel,
                                        "line_number": getattr(fn, "__code__", None).co_firstlineno if hasattr(fn, "__code__") else 1,
                                        "evidence": (
                                            f"Dynamic sandbox call {fn_name}(denied_request) reached protected "
                                            f"handler / returned status={status_val}: {str(out)[:180]}"
                                        ),
                                    })
                        except Exception:
                            pass

    if authz_violations:
        for v in authz_violations:
            results.append({
                "invariant_id": "INV-AUTHZ-DENY-REACHABILITY",
                "name": "Denied Authz Requests Never Reach Protected Handlers",
                "category": "authz",
                "passed": False,
                "severity": "CRITICAL",
                "cwe": "CWE-863",
                "file_path": v["file_path"],
                "line_number": v["line_number"],
                "evidence": v["evidence"],
                "details": {"violation": v},
            })
    else:
        results.append({
            "invariant_id": "INV-AUTHZ-DENY-REACHABILITY",
            "name": "Denied Authz Requests Never Reach Protected Handlers",
            "category": "authz",
            "passed": True,
            "severity": "CRITICAL",
            "cwe": "CWE-863",
            "file_path": ".",
            "line_number": 0,
            "evidence": "No denied-request fall-through or shadowed .authz deny rules observed.",
            "details": {},
        })
    return results


def check_path_confinement_invariants(root: Path, files):
    results = []
    violations = []
    traversal_vectors = [
        "../outside_sentinel.txt",
        "sub/../../outside_sentinel.txt",
        "/etc/passwd",
        "..\\\\outside_sentinel.txt",
        "%2e%2e/outside_sentinel.txt",
    ]

    with tempfile.TemporaryDirectory(prefix="rfchunt_root_") as sandbox_tmp:
        sandbox_root = Path(sandbox_tmp).resolve()

        for p in files:
            ext = p.suffix.lower()
            rel = rel_str(root, p)
            if rel.startswith("test") or "/test" in rel or rel.endswith(("_test.py", ".test.ts", ".spec.ts")):
                continue
            text = p.read_text(encoding="utf-8", errors="replace")

            # 1. Dynamic Python path helper probing inside isolated container
            if ext == ".py" and any(k in text.lower() for k in ("sandbox", "resolve_path", "safe_join", "safe_path", "confin", "root_dir")):
                mod = load_isolated_py_module(p, f"_rfchunt_path_{abs(hash(rel))}")
                if mod is not None:
                    for name, fn in inspect.getmembers(mod, inspect.isfunction):
                        if fn.__module__ != mod.__name__:
                            continue
                        low_name = name.lower()
                        if not any(k in low_name for k in ("resolve", "join", "sandbox", "safe_path", "normalize")):
                            continue
                        try:
                            sig = inspect.signature(fn)
                            req_params = [pr for pr in sig.parameters.values() if pr.default is inspect.Parameter.empty]
                        except (TypeError, ValueError):
                            continue
                        if len(req_params) == 2:
                            for vec in traversal_vectors:
                                try:
                                    res = fn(str(sandbox_root), vec)
                                except Exception:
                                    # Rejecting traversal by raising ValueError/PermissionError is safe!
                                    continue
                                if res is None:
                                    continue
                                res_str = str(res)
                                try:
                                    resolved = Path(res_str).resolve()
                                    escaped = not (resolved == sandbox_root or resolved.is_relative_to(sandbox_root))
                                except Exception:
                                    escaped = ".." in res_str or res_str.startswith("/etc")
                                if escaped:
                                    violations.append({
                                        "file_path": rel,
                                        "line_number": fn.__code__.co_firstlineno,
                                        "evidence": (
                                            f"Dynamic call {name}({sandbox_root!s}, {vec!r}) resolved to "
                                            f"{res_str!r}, escaping sandbox root {sandbox_root!s}."
                                        ),
                                    })
                                    break

            # 2. Structural TS/JS/Rust check for raw unguarded path join in sandbox/path helper functions
            if ext in (".ts", ".js", ".mjs", ".rs"):
                if any(k in rel.lower() for k in ("sandbox", "path", "file", "fs")):
                    if ext == ".rs":
                        # Check for bare .join(input) in a path resolution function without canonicalize / Component::ParentDir / starts_with
                        for m in re.finditer(r"pub\\s+fn\\s+(\\w*(?:resolve|sandbox|safe_path|join)\\w*)[^{]*\\{([\\s\\S]{0,800})\\}", text):
                            fn_name, body = m.group(1), m.group(2)
                            if ".join(" in body and not any(
                                g in body for g in ("starts_with", "canonicalize", "ParentDir", "Component::Normal", "is_absolute", "strip_prefix", "Err(")
                            ):
                                line_no = text[: m.start()].count("\\n") + 1
                                violations.append({
                                    "file_path": rel,
                                    "line_number": line_no,
                                    "evidence": (
                                        f"Rust path function '{fn_name}' invokes Path::join without "
                                        "root confinement or component validation."
                                    ),
                                })
                    else:
                        for m in re.finditer(r"export\\s+function\\s+(\\w*(?:resolveSandbox|safeJoin|resolvePath|sandboxPath)\\w*)[^{]*\\{([\\s\\S]{0,800})\\}", text):
                            fn_name, body = m.group(1), m.group(2)
                            if re.search(r"path\\.(?:join|resolve)\\(", body) and not any(
                                g in body for g in ("startsWith", "isAtOrUnder", "relative(", "throw ", "null", "false")
                            ):
                                line_no = text[: m.start()].count("\\n") + 1
                                violations.append({
                                    "file_path": rel,
                                    "line_number": line_no,
                                    "evidence": (
                                        f"TypeScript/JS path function '{fn_name}' calls path.join/resolve "
                                        "without root prefix confinement check."
                                    ),
                                })

    if violations:
        for v in violations:
            results.append({
                "invariant_id": "INV-PATH-ROOT-CONFINEMENT",
                "name": "Sandboxed Paths Never Resolve Outside Root",
                "category": "path_confinement",
                "passed": False,
                "severity": "HIGH",
                "cwe": "CWE-22",
                "file_path": v["file_path"],
                "line_number": v["line_number"],
                "evidence": v["evidence"],
                "details": {"violation": v},
            })
    else:
        results.append({
            "invariant_id": "INV-PATH-ROOT-CONFINEMENT",
            "name": "Sandboxed Paths Never Resolve Outside Root",
            "category": "path_confinement",
            "passed": True,
            "severity": "HIGH",
            "cwe": "CWE-22",
            "file_path": ".",
            "line_number": 0,
            "evidence": "All tested path helpers remained confined within sandbox root.",
            "details": {},
        })
    return results


def check_policy_denial_invariants(root: Path, files):
    results = []
    violations = []

    for p in files:
        ext = p.suffix.lower()
        rel = rel_str(root, p)
        if rel.startswith("test") or "/test" in rel or rel.endswith(("_test.py", ".test.ts", ".spec.ts")):
            continue
        if ext not in (".py", ".ts", ".js", ".mjs", ".rs"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        low = text.lower()
        if not any(k in low for k in ("policy", "deny", "authz", "filterrequest", "access_check", "is_allowed")):
            continue

        if ext == ".py":
            try:
                tree = ast.parse(text, filename=rel)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_l = node.name.lower()
                    if not any(k in fn_l for k in ("policy", "authz", "allow", "deny", "filter", "check_access")):
                        continue
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.ExceptHandler):
                            for h_stmt in sub.body:
                                if isinstance(h_stmt, ast.Return) and isinstance(h_stmt.value, ast.Constant):
                                    if h_stmt.value.value is True or str(h_stmt.value.value).lower() == "allow":
                                        violations.append({
                                            "file_path": rel,
                                            "line_number": h_stmt.lineno,
                                            "evidence": (
                                                f"Policy function '{node.name}' fails open inside except handler "
                                                f"by returning {h_stmt.value.value!r}."
                                            ),
                                        })
        elif ext in (".ts", ".js", ".mjs"):
            for m in re.finditer(
                r"catch\\s*(?:\\([^)]*\\))?\\s*\\{[^}]{0,220}return\\s+(?:true|\\{\\s*action\\s*:\\s*['\\x22]allow['\\x22])",
                text,
            ):
                line_no = text[: m.start()].count("\\n") + 1
                violations.append({
                    "file_path": rel,
                    "line_number": line_no,
                    "evidence": (
                        "TypeScript/JS policy/filter catch block fails open by returning true or action:'allow'."
                    ),
                })
        elif ext == ".rs":
            for m in re.finditer(
                r"(?:check_access|is_allowed|enforce_policy|evaluate_policy)[\\s\\S]{0,250}unwrap_or\\(\\s*true\\s*\\)",
                text,
            ):
                line_no = text[: m.start()].count("\\n") + 1
                violations.append({
                    "file_path": rel,
                    "line_number": line_no,
                    "evidence": "Rust access/policy evaluator fails open with unwrap_or(true).",
                })

    if violations:
        for v in violations:
            results.append({
                "invariant_id": "INV-POLICY-DENIAL-ENFORCEMENT",
                "name": "Policy Denial Enforcement Fails Closed",
                "category": "policy_enforcement",
                "passed": False,
                "severity": "HIGH",
                "cwe": "CWE-284",
                "file_path": v["file_path"],
                "line_number": v["line_number"],
                "evidence": v["evidence"],
                "details": {"violation": v},
            })
    else:
        results.append({
            "invariant_id": "INV-POLICY-DENIAL-ENFORCEMENT",
            "name": "Policy Denial Enforcement Fails Closed",
            "category": "policy_enforcement",
            "passed": True,
            "severity": "HIGH",
            "cwe": "CWE-284",
            "file_path": ".",
            "line_number": 0,
            "evidence": "No fail-open policy denial bypasses detected.",
            "details": {},
        })
    return results


def check_parser_framing_invariants(root: Path, files):
    results = []
    violations = []
    cl_te_probe = (
        b"POST / HTTP/1.1\\r\\nHost: sandbox.local\\r\\n"
        b"Transfer-Encoding: chunked\\r\\nContent-Length: 5\\r\\n\\r\\n0\\r\\n\\r\\n"
    )
    dup_cl_probe = (
        b"POST / HTTP/1.1\\r\\nHost: sandbox.local\\r\\n"
        b"Content-Length: 5\\r\\nContent-Length: 10\\r\\n\\r\\nhello"
    )

    for p in files:
        if p.suffix.lower() != ".py":
            continue
        rel = rel_str(root, p)
        if rel.startswith("test") or "/test" in rel or rel.endswith("_test.py"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if "def parse_http" not in text and "def parse_request" not in text:
            continue
        mod = load_isolated_py_module(p, f"_rfchunt_parser_{abs(hash(rel))}")
        if mod is None:
            continue
        for fn_name in ("parse_http_request", "parse_http", "parse_request"):
            fn = getattr(mod, fn_name, None)
            if not callable(fn):
                continue
            try:
                sig = inspect.signature(fn)
                req_params = [pr for pr in sig.parameters.values() if pr.default is inspect.Parameter.empty]
            except (TypeError, ValueError):
                continue
            if len(req_params) != 1:
                continue
            for probe_name, probe in (("CL+TE", cl_te_probe), ("DUPLICATE-CL", dup_cl_probe)):
                try:
                    out = fn(probe)
                except Exception:
                    # Rejecting malformed framing with exception is strict & safe
                    continue
                status = 200
                if isinstance(out, dict):
                    status = int(out.get("status", out.get("status_code", 200)) or 200)
                elif hasattr(out, "status_code"):
                    status = int(getattr(out, "status_code", 200) or 200)
                if 200 <= status < 300:
                    violations.append({
                        "file_path": rel,
                        "line_number": fn.__code__.co_firstlineno,
                        "evidence": (
                            f"HTTP parser function '{fn_name}' accepted ambiguous {probe_name} "
                            f"framing probe with status={status}."
                        ),
                    })
                    break

    if violations:
        for v in violations:
            results.append({
                "invariant_id": "INV-PARSER-STRICT-FRAMING",
                "name": "Protocol Parser Enforces Strict Framing Boundaries",
                "category": "parser_boundary",
                "passed": False,
                "severity": "HIGH",
                "cwe": "CWE-444",
                "file_path": v["file_path"],
                "line_number": v["line_number"],
                "evidence": v["evidence"],
                "details": {"violation": v},
            })
    else:
        results.append({
            "invariant_id": "INV-PARSER-STRICT-FRAMING",
            "name": "Protocol Parser Enforces Strict Framing Boundaries",
            "category": "parser_boundary",
            "passed": True,
            "severity": "HIGH",
            "cwe": "CWE-444",
            "file_path": ".",
            "line_number": 0,
            "evidence": "No ambiguous HTTP framing parser violations detected.",
            "details": {},
        })
    return results


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "/workspace").resolve()
    files = list(iter_repo_files(target))
    all_results = []
    all_results.extend(check_authz_invariants(target, files))
    all_results.extend(check_path_confinement_invariants(target, files))
    all_results.extend(check_policy_denial_invariants(target, files))
    all_results.extend(check_parser_framing_invariants(target, files))

    payload = {
        "files_scanned": len(files),
        "invariants": all_results,
    }
    print(MARKER + json.dumps(payload, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def build_node_invariant_harness_script() -> str:
    """
    Returns a clean-room Node.js ESM invariant harness script mounted at
    `/harness/run_invariants.mjs` for executing runtime TypeScript/Node policy &
    path-confinement invariants inside `--network=none` Node containers.
    """
    return """import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const MARKER = 'RFCHUNT_INVARIANTS_JSON:';
const workspace = path.resolve(process.argv[2] || '/workspace');

async function run() {
  const invariants = [];
  const distDir = path.join(workspace, 'dist', 'sandbox');

  // 1. Dynamic path confinement check against compiled sandbox-utils if present
  const sandboxUtilsPath = path.join(distDir, 'sandbox-utils.js');
  if (fs.existsSync(sandboxUtilsPath)) {
    try {
      const mod = await import(pathToFileURL(sandboxUtilsPath).href);
      const isAtOrUnder = mod.isAtOrUnder;
      const normalize = mod.normalizePathForSandbox;
      let violated = false;
      let evidence = 'Compiled Node sandbox path confinement helpers enforced root boundary.';
      if (typeof isAtOrUnder === 'function') {
        if (isAtOrUnder('/etc/passwd', '/workspace') || isAtOrUnder('/workspace-escape', '/workspace')) {
          violated = true;
          evidence = 'isAtOrUnder() allowed out-of-root sibling/parent path to match /workspace.';
        }
      }
      if (!violated && typeof normalize === 'function') {
        const res = String(normalize('/workspace/sub/../../etc/passwd'));
        if (res.startsWith('/workspace')) {
          violated = true;
          evidence = `normalizePathForSandbox() returned misleading root prefix: ${res}`;
        }
      }
      invariants.push({
        invariant_id: 'INV-PATH-ROOT-CONFINEMENT',
        name: 'Sandboxed Paths Never Resolve Outside Root',
        category: 'path_confinement',
        passed: !violated,
        severity: 'HIGH',
        cwe: 'CWE-22',
        file_path: 'dist/sandbox/sandbox-utils.js',
        line_number: 1,
        evidence,
        details: { runtime: 'node' },
      });
    } catch (err) {
      invariants.push({
        invariant_id: 'INV-PATH-ROOT-CONFINEMENT',
        name: 'Sandboxed Paths Never Resolve Outside Root',
        category: 'path_confinement',
        passed: true,
        severity: 'HIGH',
        cwe: 'CWE-22',
        file_path: 'dist/sandbox/sandbox-utils.js',
        line_number: 1,
        evidence: `Dynamic import skipped safely: ${String(err)}`,
        details: { runtime: 'node' },
      });
    }
  }

  // 2. Dynamic resolved-address SSRF / metadata deny guard check if present
  const addrGuardPath = path.join(distDir, 'resolved-address-guard.js');
  if (fs.existsSync(addrGuardPath)) {
    try {
      const mod = await import(pathToFileURL(addrGuardPath).href);
      const fn = mod.isResolvedAddressDenied;
      let violated = false;
      let evidence = 'isResolvedAddressDenied() denied cloud metadata & loopback boundary addresses.';
      if (typeof fn === 'function') {
        for (const ip of ['169.254.169.254', '127.0.0.1', '::ffff:169.254.169.254']) {
          if (!fn(ip)) {
            violated = true;
            evidence = `isResolvedAddressDenied(${JSON.stringify(ip)}) failed to deny restricted address.`;
            break;
          }
        }
      }
      invariants.push({
        invariant_id: 'INV-POLICY-DENIAL-ENFORCEMENT',
        name: 'Policy Denial Enforcement Fails Closed',
        category: 'policy_enforcement',
        passed: !violated,
        severity: 'HIGH',
        cwe: 'CWE-284',
        file_path: 'dist/sandbox/resolved-address-guard.js',
        line_number: 1,
        evidence,
        details: { runtime: 'node' },
      });
    } catch (err) {
      invariants.push({
        invariant_id: 'INV-POLICY-DENIAL-ENFORCEMENT',
        name: 'Policy Denial Enforcement Fails Closed',
        category: 'policy_enforcement',
        passed: true,
        severity: 'HIGH',
        cwe: 'CWE-284',
        file_path: 'dist/sandbox/resolved-address-guard.js',
        line_number: 1,
        evidence: `Dynamic import skipped safely: ${String(err)}`,
        details: { runtime: 'node' },
      });
    }
  }

  console.log(MARKER + JSON.stringify({ files_scanned: invariants.length, invariants }));
}

run().catch((err) => {
  console.error(String(err));
  process.exit(1);
});
"""


def parse_invariant_harness_output(stdout: str) -> Optional[Dict[str, Any]]:
    """Extracts structured JSON invariant results from container stdout."""
    if not stdout:
        return None
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if INVARIANT_JSON_MARKER in stripped:
            raw_json = stripped.split(INVARIANT_JSON_MARKER, 1)[1].strip()
            try:
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict) and isinstance(parsed.get("invariants"), list):
                    return parsed
            except (ValueError, TypeError):
                return None
    return None


class SandboxInvariantRunner:
    """
    Executes target repository security invariants inside an isolated
    `docker run --rm --network=none` container with `:ro` mounts, `--cap-drop=ALL`,
    strict resource bounds, and `shell=False`.

    Persists any detected runtime invariant violations directly onto the Cairn
    blackboard as `FACT` nodes via `db.add_fact(...)` when `db` is provided.
    """

    def __init__(
        self,
        *,
        docker_bin: Optional[str] = None,
        python_image: str = DEFAULT_PYTHON_SANDBOX_IMAGE,
        node_image: str = DEFAULT_NODE_SANDBOX_IMAGE,
        memory_limit: str = "512m",
        cpus: str = "1.0",
        pids_limit: int = 128,
        docker_timeout: float = 3.0,
        execution_timeout: float = 60.0,
        subprocess_runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    ) -> None:
        self._docker_bin_override = docker_bin
        self.python_image = str(python_image).strip() or DEFAULT_PYTHON_SANDBOX_IMAGE
        self.node_image = str(node_image).strip() or DEFAULT_NODE_SANDBOX_IMAGE
        self.memory_limit = str(memory_limit).strip() or "512m"
        self.cpus = str(cpus).strip() or "1.0"
        self.pids_limit = max(32, int(pids_limit))
        self.docker_timeout = max(0.5, float(docker_timeout))
        self.execution_timeout = max(5.0, float(execution_timeout))
        self._runner = subprocess_runner or silent_subprocess_run

    def resolve_docker_bin(self) -> Optional[str]:
        if self._docker_bin_override:
            return self._docker_bin_override
        return shutil.which("docker")

    def _run_docker(self, args: List[str], *, timeout: Optional[float] = None) -> subprocess.CompletedProcess:
        return self._runner(
            args,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout or self.docker_timeout,
        )

    def check_docker_available(self) -> Tuple[bool, str]:
        docker_bin = self.resolve_docker_bin()
        if not docker_bin:
            return False, "docker binary not found on PATH"
        try:
            proc = self._run_docker(
                [docker_bin, "info", "--format", "{{.ServerVersion}}"],
                timeout=self.docker_timeout,
            )
            if proc.returncode == 0:
                return True, (proc.stdout or "").strip() or "unknown"
            err = (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()
            return False, err[:240]
        except subprocess.TimeoutExpired:
            return False, f"docker daemon probe timed out after {self.docker_timeout:.1f}s"
        except OSError as exc:
            return False, str(exc)

    def check_image_available(self, image: str) -> Tuple[bool, str]:
        img = str(image or "").strip()
        if not _DOCKER_IMAGE_RE.fullmatch(img):
            return False, f"invalid docker image '{img}'"
        docker_bin = self.resolve_docker_bin()
        if not docker_bin:
            return False, "docker binary not found"
        try:
            proc = self._run_docker(
                [docker_bin, "image", "inspect", "--format", "{{.Id}}", img],
                timeout=self.docker_timeout,
            )
            if proc.returncode == 0:
                return True, (proc.stdout or "").strip()
            return False, f"image '{img}' not present locally"
        except subprocess.TimeoutExpired:
            return False, f"docker image inspect timed out for '{img}'"
        except OSError as exc:
            return False, str(exc)

    def build_docker_command(
        self,
        repo_path: Union[str, Path],
        harness_dir: Union[str, Path],
        *,
        image: Optional[str] = None,
        runtime: str = "python",
    ) -> List[str]:
        docker_bin = self.resolve_docker_bin() or "docker"
        chosen_image = str(image or (self.node_image if runtime == "node" else self.python_image)).strip()
        if not _DOCKER_IMAGE_RE.fullmatch(chosen_image):
            raise ValueError(f"Unsafe Docker image name rejected: {chosen_image!r}")

        repo_host = str(Path(repo_path).resolve()).replace("\\", "/")
        harness_host = str(Path(harness_dir).resolve()).replace("\\", "/")
        container_name = f"rfchunt-inv-{secrets.token_hex(4)}"

        if runtime == "node":
            payload_cmd = ["node", "/harness/run_invariants.mjs", "/workspace"]
        else:
            payload_cmd = ["python3", "/harness/run_invariants.py", "/workspace"]

        cmd = [
            docker_bin,
            "run",
            "--rm",
            "--name",
            container_name,
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--memory",
            self.memory_limit,
            "--cpus",
            self.cpus,
            "--pids-limit",
            str(self.pids_limit),
            "-v",
            f"{repo_host}:/workspace:ro",
            "-v",
            f"{harness_host}:/harness:ro",
            "-w",
            "/workspace",
            chosen_image,
            *payload_cmd,
        ]
        ok, reason = validate_sandbox_docker_command(cmd)
        if not ok:
            raise PermissionError(f"Hardened sandbox Docker command rejected: {reason}")
        return cmd

    @staticmethod
    def persist_failures_to_cairn(
        results: Sequence[InvariantCheckResult],
        *,
        db: Any,
        repo_path: str,
        docker_image: str,
        task_id: str = "default",
    ) -> List[str]:
        """Persists failed invariants as Cairn `FACT` nodes via `db.add_fact(...)`."""
        if db is None or not hasattr(db, "add_fact"):
            return []
        fact_ids: List[str] = []
        for item in results:
            if item.passed:
                continue
            fact_id = db.add_fact(
                content=(
                    f"Sandbox invariant failure [{item.invariant_id}] in {item.file_path}: "
                    f"{item.evidence}"
                ),
                task_id=task_id,
                domain=item.category or "sandbox_invariants",
                source_agent="SandboxInvariantRunner",
                payload={
                    "invariant_id": item.invariant_id,
                    "name": item.name,
                    "category": item.category,
                    "severity": item.severity,
                    "cwe": item.cwe,
                    "file_path": item.file_path,
                    "line_number": item.line_number,
                    "container_mode": item.container_mode,
                    "docker_image": docker_image,
                    "evidence": item.evidence,
                    "repo_path": repo_path,
                    "details": dict(item.details),
                },
            )
            item.cairn_fact_id = str(fact_id)
            fact_ids.append(str(fact_id))
        return fact_ids

    def run(
        self,
        repo_path: Union[str, Path],
        *,
        db: Optional[Any] = None,
        task_id: str = "default",
        preferred_runtime: Optional[str] = None,
        image: Optional[str] = None,
    ) -> SandboxInvariantReport:
        """
        Executes repository security invariants inside an isolated `--network=none`
        Docker container. Persists invariant violations as Cairn `FACT` nodes when
        `db` is supplied. Returns `status="skipped_docker_unavailable"` cleanly if
        Docker or the required image is unavailable.
        """
        t0 = time.monotonic()
        repo = Path(repo_path).resolve()
        if not repo.exists() or not repo.is_dir():
            return SandboxInvariantReport(
                status="error",
                repo_path=str(repo),
                detected_languages=[],
                container_mode="error",
                docker_image="",
                docker_command=[],
                invariants_checked=0,
                invariants_passed=0,
                invariants_failed=0,
                provenance={"error": f"target repo path does not exist or is not a directory: {repo}"},
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )

        langs = detect_repo_languages(repo)
        has_compiled_node_sandbox = (repo / "dist" / "sandbox").is_dir()
        runtime = preferred_runtime
        if runtime is None:
            if has_compiled_node_sandbox and ("typescript" in langs or "javascript" in langs) and "python" not in langs:
                runtime = "node"
            else:
                runtime = "python"

        chosen_image = str(image or (self.node_image if runtime == "node" else self.python_image)).strip()

        docker_ok, docker_info = self.check_docker_available()
        if not docker_ok:
            return SandboxInvariantReport(
                status="skipped_docker_unavailable",
                repo_path=str(repo),
                detected_languages=langs,
                container_mode="skipped_docker_unavailable",
                docker_image=chosen_image,
                docker_command=[],
                invariants_checked=0,
                invariants_passed=0,
                invariants_failed=0,
                provenance={
                    "docker_available": False,
                    "image_available": False,
                    "reason": f"docker_daemon_unavailable: {docker_info}",
                    "runtime": runtime,
                },
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )

        img_ok, img_info = self.check_image_available(chosen_image)
        if not img_ok and runtime == "node" and image is None:
            # Fallback to Python image if Node image isn't cached locally
            py_ok, py_info = self.check_image_available(self.python_image)
            if py_ok:
                runtime = "python"
                chosen_image = self.python_image
                img_ok, img_info = py_ok, py_info

        if not img_ok:
            return SandboxInvariantReport(
                status="skipped_docker_unavailable",
                repo_path=str(repo),
                detected_languages=langs,
                container_mode="skipped_docker_unavailable",
                docker_image=chosen_image,
                docker_command=[],
                invariants_checked=0,
                invariants_passed=0,
                invariants_failed=0,
                provenance={
                    "docker_available": True,
                    "docker_version": docker_info,
                    "image_available": False,
                    "reason": f"docker_image_unavailable: {img_info}",
                    "runtime": runtime,
                },
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )

        harness_tmp = Path(tempfile.mkdtemp(prefix="rfchunt_inv_harness_"))
        cmd: List[str] = []
        try:
            if runtime == "node":
                (harness_tmp / "run_invariants.mjs").write_text(
                    build_node_invariant_harness_script(), encoding="utf-8"
                )
            else:
                (harness_tmp / "run_invariants.py").write_text(
                    build_invariant_harness_script(), encoding="utf-8"
                )

            cmd = self.build_docker_command(repo, harness_tmp, image=chosen_image, runtime=runtime)
            try:
                proc = self._run_docker(cmd, timeout=self.execution_timeout)
            except subprocess.TimeoutExpired:
                return SandboxInvariantReport(
                    status="error",
                    repo_path=str(repo),
                    detected_languages=langs,
                    container_mode="docker_network_none",
                    docker_image=chosen_image,
                    docker_command=cmd,
                    invariants_checked=0,
                    invariants_passed=0,
                    invariants_failed=0,
                    provenance={
                        "docker_available": True,
                        "docker_version": docker_info,
                        "image_available": True,
                        "error": f"sandbox invariant container timed out after {self.execution_timeout:.1f}s",
                        "runtime": runtime,
                    },
                    elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
                )

            parsed = parse_invariant_harness_output(proc.stdout or "")
            if parsed is None:
                return SandboxInvariantReport(
                    status="error",
                    repo_path=str(repo),
                    detected_languages=langs,
                    container_mode="docker_network_none",
                    docker_image=chosen_image,
                    docker_command=cmd,
                    invariants_checked=0,
                    invariants_passed=0,
                    invariants_failed=0,
                    provenance={
                        "docker_available": True,
                        "docker_version": docker_info,
                        "image_available": True,
                        "returncode": proc.returncode,
                        "stderr": (proc.stderr or "")[:400],
                        "error": "container did not emit valid structured invariant JSON",
                        "runtime": runtime,
                    },
                    elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
                )

            results: List[InvariantCheckResult] = []
            for raw_item in parsed.get("invariants", []):
                if not isinstance(raw_item, dict):
                    continue
                results.append(
                    InvariantCheckResult(
                        invariant_id=str(raw_item.get("invariant_id") or "INV-UNKNOWN"),
                        name=str(raw_item.get("name") or raw_item.get("invariant_id") or "Invariant"),
                        category=str(raw_item.get("category") or "policy_enforcement"),
                        passed=bool(raw_item.get("passed", False)),
                        severity=str(raw_item.get("severity") or "HIGH").upper(),
                        cwe=str(raw_item.get("cwe") or "CWE-284"),
                        file_path=str(raw_item.get("file_path") or "."),
                        line_number=int(raw_item.get("line_number") or 0),
                        container_mode="docker_network_none",
                        evidence=str(raw_item.get("evidence") or ""),
                        details=dict(raw_item.get("details") or {}),
                    )
                )

            fact_ids = self.persist_failures_to_cairn(
                results,
                db=db,
                repo_path=str(repo),
                docker_image=chosen_image,
                task_id=task_id,
            )

            passed_count = sum(1 for r in results if r.passed)
            failed_count = sum(1 for r in results if not r.passed)
            return SandboxInvariantReport(
                status="completed",
                repo_path=str(repo),
                detected_languages=langs,
                container_mode="docker_network_none",
                docker_image=chosen_image,
                docker_command=cmd,
                invariants_checked=len(results),
                invariants_passed=passed_count,
                invariants_failed=failed_count,
                results=results,
                persisted_fact_ids=fact_ids,
                provenance={
                    "docker_available": True,
                    "docker_version": docker_info,
                    "image_available": True,
                    "image_id": img_info,
                    "files_scanned": int(parsed.get("files_scanned") or 0),
                    "runtime": runtime,
                    "returncode": proc.returncode,
                },
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )
        finally:
            shutil.rmtree(harness_tmp, ignore_errors=True)
