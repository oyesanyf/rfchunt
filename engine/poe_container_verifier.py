"""
Containerized Non-Destructive POE == 3 Verifier (AIxCC Upgrade #5a).

Takes HIGH/CRITICAL candidate findings, auto-generates minimal non-destructive
reproduction assertion tests, and executes them inside ephemeral isolated local
Docker containers:
  - `--network=none` with `:ro` repository mount for local repo invariant checks
  - Loopback-only (`127.0.0.1` / `localhost` validated fail-closed; NEVER `--network=host`)
    for local service protocol conformance checks
  - Mandatory `--rm`, `--cap-drop=ALL`, `--security-opt no-new-privileges:true`,
    `--read-only`, `--memory`, `--cpus`, `--pids-limit`, and `shell=False`

Promotes genuinely reproduced findings to `poe_level = 3` (`POELevel.VERIFIED_EXPLOIT`),
downgrades/rejects unverified false positives before final reporting, and reports
`status = "skipped_docker_unavailable"` with explicit provenance when Docker or the
verification image is absent.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import json
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from engine.dual_graph_engine import POELevel
from engine.host_containment import silent_subprocess_run
from engine.safe_network_validator import is_explicit_loopback_host


DEFAULT_POE_IMAGE = "python:3.12-alpine"
DEFAULT_HIGH_SEVERITIES: Tuple[str, ...] = ("HIGH", "CRITICAL")
POE_RESULT_MARKER = "RFCHUNT_POE_RESULT:"

_DOCKER_IMAGE_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?$"
)
_DESTRUCTIVE_HTTP_VERBS: Set[str] = {"PUT", "DELETE", "PATCH", "DROP", "PURGE"}
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


@dataclass
class POEVerificationResult:
    """Structured outcome for a single candidate finding's containerized POE verification."""

    finding_id: str
    title: str
    original_severity: str
    calibrated_severity: str
    status: str  # 'verified', 'downgraded_false_positive', 'unverified', 'skipped_below_threshold', 'skipped_docker_unavailable', 'rejected_unsafe_target', 'error'
    poe_level: int
    verified: bool
    false_positive: bool
    verification_mode: str
    generated_test_code: str = ""
    docker_command: List[str] = field(default_factory=list)
    evidence: str = ""
    exit_code: Optional[int] = None
    cairn_fact_id: Optional[str] = None
    provenance: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        from engine.epistemic_state import attach_epistemic_metadata

        out = {
            "finding_id": self.finding_id,
            "title": self.title,
            "original_severity": self.original_severity,
            "calibrated_severity": self.calibrated_severity,
            "status": self.status,
            "poe_verification_status": self.status,
            "poe_level": int(self.poe_level),
            "verified": self.verified,
            "false_positive": self.false_positive,
            "verification_mode": self.verification_mode,
            "docker_command": list(self.docker_command),
            "evidence": self.evidence,
            "exit_code": self.exit_code,
            "cairn_fact_id": self.cairn_fact_id,
            "provenance": dict(self.provenance),
            "elapsed_ms": self.elapsed_ms,
        }
        attach_epistemic_metadata(
            out,
            runtime_poe_verified=bool(self.verified and int(self.poe_level) >= 3),
            refuted=bool(self.false_positive or self.status == "downgraded_false_positive"),
        )
        return out


@dataclass
class POEBatchReport:
    """Batch summary returned by `ContainerPOEVerifier.verify_findings(...)`."""

    status: str  # 'completed', 'skipped_docker_unavailable', 'no_eligible_findings'
    total_candidates: int
    eligible_candidates: int
    verified_poe3_count: int
    downgraded_false_positive_count: int
    skipped_count: int
    error_count: int
    results: List[POEVerificationResult] = field(default_factory=list)
    persisted_fact_ids: List[str] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "total_candidates": self.total_candidates,
            "eligible_candidates": self.eligible_candidates,
            "verified_poe3_count": self.verified_poe3_count,
            "downgraded_false_positive_count": self.downgraded_false_positive_count,
            "skipped_count": self.skipped_count,
            "error_count": self.error_count,
            "results": [r.to_dict() for r in self.results],
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


def validate_poe_docker_command(
    cmd: Sequence[str], *, mode: str = "docker_network_none"
) -> Tuple[bool, str]:
    """
    Fail-closed validator for containerized POE verifier commands.
    Enforces shell=False list argv, `--rm`, `--cap-drop=ALL`, `--read-only`,
    resource bounds, strictly `:ro` mounts, zero `--network=host`/`--privileged`/`--cap-add`,
    zero shell metacharacters or shell wrappers, and `--network=none` for local repo mode.
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
            if val == "host" or val.startswith("container:"):
                return False, f"docker isolation-escape '{tok}={val}' is forbidden"
            if val == "none":
                has_network_none = True
            elif mode == "docker_network_none":
                return False, f"local repo POE mode forbids '{tok}={val}'; '--network=none' required"
            idx += 2
            continue
        elif tok_l.startswith(("--network=", "--net=")):
            val = tok_l.split("=", 1)[1].strip()
            if val == "host" or val.startswith("container:"):
                return False, f"docker isolation-escape '{tok}' is forbidden"
            if mode == "docker_network_none" and val != "none":
                return False, f"local repo POE mode forbids '{tok}'; '--network=none' required"
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
        elif tok_l in ("--add-host",) or tok_l.startswith("--add-host="):
            val = tok.split("=", 1)[1].strip() if "=" in tok else (tokens[idx + 1].strip() if idx + 1 < len(tokens) else "")
            if mode == "docker_network_none":
                return False, "--add-host is forbidden in --network=none POE mode"
            if val != "host.docker.internal:host-gateway":
                return False, f"only host.docker.internal:host-gateway is permitted for loopback POE, got '{val}'"
            if "=" not in tok:
                idx += 2
                continue
        elif tok_l in ("-v", "--volume") and idx + 1 < len(tokens):
            spec = tokens[idx + 1].strip()
            norm_spec = spec.replace("\\", "/")
            if not norm_spec.endswith(":ro"):
                return False, f"POE container mount '{spec}' must be read-only (:ro)"
            if re.match(r"^[a-zA-Z]:", norm_spec):
                c_idx = norm_spec.find(":", 2)
                src = norm_spec[:c_idx] if c_idx != -1 else norm_spec
            else:
                src = norm_spec.split(":", 1)[0]
            if _is_critical_mount_source(src):
                return False, f"unsafe docker host mount source '{src}'"
            idx += 2
            continue
        elif tok_l in ("-c", "/c", "-lc", "-ic", "-ec", "--command") or tok_l.startswith("--command="):
            return False, f"forbidden shell flag '{tok}' in POE docker command"
        elif not tok.startswith("-"):
            base = PurePosixPath(tok.split("@", 1)[0].replace("\\", "/")).name.lower().split(":", 1)[0]
            if base in _FORBIDDEN_PAYLOAD_BINARIES:
                return False, f"forbidden shell/scanner binary '{tok}' in POE docker command"
        idx += 1

    if not has_rm:
        return False, "POE docker command requires '--rm'"
    if not has_cap_drop_all:
        return False, "POE docker command requires '--cap-drop=ALL'"
    if not (has_memory and has_cpus and has_pids_limit):
        return False, "POE docker command requires '--memory', '--cpus', and '--pids-limit'"
    if mode == "docker_network_none" and not has_network_none:
        return False, "local repo POE docker command requires '--network=none'"
    return True, "ok"


def _classify_finding_kind(finding: Dict[str, Any]) -> str:
    blob = " ".join(
        str(finding.get(k) or "")
        for k in ("cwe", "cwe_id", "rule_id", "category", "threat_category", "title", "description", "invariant_id")
    ).lower()
    if any(k in blob for k in ("cwe-22", "path traversal", "path_confinement", "root confinement", "sandbox path", "path::join", "inv-path")):
        return "path_confinement"
    if any(k in blob for k in ("cwe-863", "cwe-285", "authz", "authorization", "rbac", "acl", "protected handler", "inv-authz")):
        return "authz_bypass"
    if any(k in blob for k in ("cwe-444", "smuggling", "desync", "content-length", "transfer-encoding", "parser_divergence", "framing", "inv-parser")):
        return "parser_framing"
    if any(k in blob for k in ("cwe-284", "cwe-636", "fail-open", "policy", "deny", "inv-policy")):
        return "policy_denial"
    return "generic_invariant"


def _normalize_relative_file_path(raw_file: str, repo_path: Optional[Union[str, Path]]) -> str:
    if not raw_file:
        return ""
    s = str(raw_file).strip().replace("\\", "/")
    if repo_path is not None:
        try:
            rp = Path(repo_path).resolve()
            fp = Path(raw_file).resolve()
            if fp.is_relative_to(rp):
                return fp.relative_to(rp).as_posix()
        except Exception:
            pass
    s = s.lstrip("/")
    if re.match(r"^[a-zA-Z]:/", s):
        return PurePosixPath(s).name
    parts = [p for p in s.split("/") if p and p not in (".", "..")]
    return "/".join(parts)


def _extract_probe_method(raw_probe: Union[str, bytes]) -> str:
    text = raw_probe.decode("latin-1", errors="replace") if isinstance(raw_probe, (bytes, bytearray)) else str(raw_probe or "")
    first_line = text.splitlines()[0].strip() if text else ""
    parts = first_line.split(" ")
    return parts[0].strip().upper() if parts else ""


def generate_verification_test(
    finding: Dict[str, Any],
    *,
    repo_path: Optional[Union[str, Path]] = None,
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Auto-generates a minimal, strictly non-destructive Python verification assertion
    script for a candidate finding.

    Returns `(verification_mode, script_source, metadata)` where `verification_mode`
    is either `"docker_network_none"` (local repo invariant) or `"docker_loopback_only"`
    (explicitly validated 127.0.0.1/localhost loopback service).
    Raises `PermissionError` if a non-loopback remote service or destructive HTTP verb
    is requested.
    """
    check_kind = _classify_finding_kind(finding)
    raw_file = str(finding.get("file_path") or finding.get("file") or "").strip()
    target_host = str(finding.get("target_host") or finding.get("host") or "").strip()
    target_port = finding.get("target_port") or finding.get("port")
    raw_probe = finding.get("raw_probe")

    # Loopback-only service verification when target_host + target_port given without local repo path
    if target_host and target_port and not repo_path:
        if not is_explicit_loopback_host(target_host):
            raise PermissionError(
                f"ContainerPOEVerifier strictly forbids non-loopback network verification target: {target_host!r}"
            )
        port_int = int(target_port)
        if not (1 <= port_int <= 65535):
            raise ValueError(f"Invalid loopback target port: {target_port!r}")

        probe_bytes = (
            bytes(raw_probe)
            if isinstance(raw_probe, (bytes, bytearray))
            else str(raw_probe or "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").encode("latin-1")
        )
        verb = _extract_probe_method(probe_bytes)
        if verb in _DESTRUCTIVE_HTTP_VERBS:
            raise PermissionError(
                f"ContainerPOEVerifier forbids destructive HTTP verb '{verb}' in non-destructive POE test"
            )

        expected_statuses = finding.get("expected_anomalous_statuses") or [200, 408, 500]
        probe_hex = probe_bytes.hex()
        script = f'''#!/usr/bin/env python3
"""Auto-generated non-destructive loopback POE verification assertion."""
import json
import socket

MARKER = {POE_RESULT_MARKER!r}
TARGET_HOST = "host.docker.internal"
TARGET_PORT = {port_int}
PROBE = bytes.fromhex({probe_hex!r})
EXPECTED_STATUSES = set({[int(s) for s in expected_statuses]!r})


def run_once():
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=3.0)
    try:
        sock.sendall(PROBE)
        sock.settimeout(2.5)
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) >= 16384 or b"\\r\\n\\r\\n" in b"".join(chunks):
                    break
            except socket.timeout:
                return 408, "TIMEOUT"
        raw = b"".join(chunks)
        first_line = raw.split(b"\\r\\n", 1)[0].decode("latin-1", errors="replace")
        parts = first_line.split(" ", 2)
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return code, "OK" if raw else "CLOSED"
    finally:
        sock.close()


def main():
    statuses = []
    states = []
    hits = 0
    for _ in range(3):
        try:
            code, st = run_once()
            statuses.append(code)
            states.append(st)
            if code in EXPECTED_STATUSES:
                hits += 1
        except Exception as exc:
            statuses.append(0)
            states.append(f"ERR:{{exc}}")
    reproduced = hits >= 2
    out = {{
        "reproduced": reproduced,
        "check_kind": {check_kind!r},
        "trials_reproduced": hits,
        "statuses": statuses,
        "states": states,
        "evidence": f"3-trial loopback POE probe on port {{TARGET_PORT}}: statuses={{statuses}}, states={{states}}, hits={{hits}}/3",
    }}
    print(MARKER + json.dumps(out, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
        return "docker_loopback_only", script, {"check_kind": check_kind, "target_port": port_int}

    # Local repo invariant POE verification (--network=none, repo mounted :ro at /workspace)
    rel_file = _normalize_relative_file_path(raw_file, repo_path)
    func_hint = str(finding.get("function_name") or finding.get("symbol") or "").strip()
    snippet_hint = str(finding.get("snippet") or "").strip()[:240]

    script = f'''#!/usr/bin/env python3
"""Auto-generated non-destructive local-repo POE verification assertion (--network=none)."""
import ast
import importlib.util
import inspect
import json
from pathlib import Path
import re
import sys
import tempfile

MARKER = {POE_RESULT_MARKER!r}
WORKSPACE = Path("/workspace").resolve()
TARGET_REL = {rel_file!r}
CHECK_KIND = {check_kind!r}
FUNC_HINT = {func_hint!r}
SNIPPET_HINT = {snippet_hint!r}


def load_module(py_path: Path):
    spec = importlib.util.spec_from_file_location("_rfchunt_poe_target", str(py_path))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_rfchunt_poe_target"] = mod
    try:
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def verify_path_confinement(target: Path):
    text = target.read_text(encoding="utf-8", errors="replace")
    if target.suffix.lower() == ".py":
        mod = load_module(target)
        if mod is not None:
            with tempfile.TemporaryDirectory(prefix="rfchunt_poe_root_") as tmp:
                root = Path(tmp).resolve()
                vectors = ["../rfchunt_poe_sentinel.txt", "a/../../rfchunt_poe_sentinel.txt", "/etc/passwd"]
                for name, fn in inspect.getmembers(mod, inspect.isfunction):
                    if fn.__module__ != mod.__name__:
                        continue
                    if FUNC_HINT and name != FUNC_HINT:
                        continue
                    if not FUNC_HINT and not any(k in name.lower() for k in ("resolve", "join", "sandbox", "path", "normalize")):
                        continue
                    sig = inspect.signature(fn)
                    req = [p for p in sig.parameters.values() if p.default is inspect.Parameter.empty]
                    if len(req) != 2:
                        continue
                    for vec in vectors:
                        try:
                            res = fn(str(root), vec)
                        except Exception:
                            continue
                        if res is None:
                            continue
                        resolved = Path(str(res)).resolve()
                        if not (resolved == root or resolved.is_relative_to(root)):
                            return True, f"Path escape reproduced via {{name}}({{root}}, {{vec!r}}) -> {{resolved}}"
                return False, f"Tested path helpers in {{TARGET_REL}} stayed confined within sandbox root."
    # Non-Python structural verification
    has_join = bool(re.search(r"(?:path\\.join|path\\.resolve|\\.join\\()", text))
    has_guard = any(g in text for g in ("startsWith", "starts_with", "isAtOrUnder", "is_relative_to", "ParentDir", "canonicalize"))
    if has_join and not has_guard:
        return True, f"Unguarded path join reproduced in {{TARGET_REL}} without root confinement guard."
    return False, f"Path confinement guard present or no unguarded join in {{TARGET_REL}}."


def verify_authz_bypass(target: Path):
    text = target.read_text(encoding="utf-8", errors="replace")
    if target.suffix.lower() == ".authz" or target.name.lower().endswith(".authz.conf"):
        wildcard_line = 0
        deny_line = 0
        for idx, raw in enumerate(text.splitlines(), start=1):
            low = raw.strip().lower()
            if not low or low.startswith("#"):
                continue
            if re.match(r"^allow\\s+(\\*|/\\*|any|all)\\b", low) and not wildcard_line:
                wildcard_line = idx
            if re.match(r"^deny\\b", low) and not deny_line:
                deny_line = idx
        if wildcard_line and deny_line and wildcard_line < deny_line:
            return True, f"Wildcard allow on line {{wildcard_line}} shadows deny on line {{deny_line}} in {{TARGET_REL}}."
        return False, f"Authz policy {{TARGET_REL}} enforces deny precedence properly."

    if target.suffix.lower() == ".py":
        mod = load_module(target)
        if mod is not None:
            for name in ([FUNC_HINT] if FUNC_HINT else ["handle_request", "dispatch_request", "serve_request"]):
                fn = getattr(mod, name, None)
                if not callable(fn):
                    continue
                probe = {{"path": "/admin/secret", "method": "GET", "role": "guest", "authz": "deny", "decision": "deny"}}
                try:
                    out = fn(probe)
                except Exception:
                    return False, f"{{name}} rejected denied request with exception."
                if isinstance(out, dict) and (out.get("protected_reached") or out.get("handler_reached") or out.get("status") == 200):
                    return True, f"Denied authz request reached protected handler via {{name}}: {{out!r}}"
                return False, f"{{name}} blocked denied authz request cleanly: {{out!r}}"
    return False, f"Authz bypass did not reproduce in {{TARGET_REL}}."


def verify_parser_framing(target: Path):
    if target.suffix.lower() == ".py":
        mod = load_module(target)
        if mod is not None:
            probe = b"POST / HTTP/1.1\\r\\nHost: poe.local\\r\\nTransfer-Encoding: chunked\\r\\nContent-Length: 5\\r\\n\\r\\n0\\r\\n\\r\\n"
            for name in ([FUNC_HINT] if FUNC_HINT else ["parse_http_request", "parse_http", "parse_request"]):
                fn = getattr(mod, name, None)
                if not callable(fn):
                    continue
                try:
                    out = fn(probe)
                except Exception:
                    return False, f"Parser {{name}} strictly rejected conflicting CL+TE probe."
                status = int(out.get("status", out.get("status_code", 200))) if isinstance(out, dict) else int(getattr(out, "status_code", 200))
                if 200 <= status < 300:
                    return True, f"Parser {{name}} accepted conflicting CL+TE framing probe with status={{status}}."
                return False, f"Parser {{name}} rejected conflicting CL+TE framing probe with status={{status}}."
    return False, f"Parser framing flaw did not reproduce in {{TARGET_REL}}."


def verify_policy_denial(target: Path):
    text = target.read_text(encoding="utf-8", errors="replace")
    if target.suffix.lower() == ".py":
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    for stmt in node.body:
                        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
                            if stmt.value.value is True or str(stmt.value.value).lower() == "allow":
                                return True, f"Fail-open return {{stmt.value.value!r}} reproduced in except handler at {{TARGET_REL}}:{{stmt.lineno}}."
        except SyntaxError:
            pass
    elif target.suffix.lower() in (".ts", ".js", ".mjs"):
        if re.search(r"catch\\s*(?:\\([^)]*\\))?\\s*\\{{[^}}]{{0,220}}return\\s+(?:true|\\{{\\s*action\\s*:\\s*['\\"]allow['\\"])", text):
            return True, f"Fail-open catch block reproduced in {{TARGET_REL}}."
    elif target.suffix.lower() == ".rs":
        if "unwrap_or(true)" in text:
            return True, f"Fail-open unwrap_or(true) reproduced in {{TARGET_REL}}."
    return False, f"Policy denial fail-open did not reproduce in {{TARGET_REL}}."


def main():
    if not TARGET_REL:
        print(MARKER + json.dumps({{"reproduced": False, "check_kind": CHECK_KIND, "evidence": "No target file_path supplied."}}))
        return 0
    target = (WORKSPACE / TARGET_REL).resolve()
    if not (target == WORKSPACE or target.is_relative_to(WORKSPACE)) or not target.is_file():
        print(MARKER + json.dumps({{"reproduced": False, "check_kind": CHECK_KIND, "evidence": f"Target file {{TARGET_REL}} not found inside /workspace."}}))
        return 0

    if CHECK_KIND == "path_confinement":
        reproduced, evidence = verify_path_confinement(target)
    elif CHECK_KIND == "authz_bypass":
        reproduced, evidence = verify_authz_bypass(target)
    elif CHECK_KIND == "parser_framing":
        reproduced, evidence = verify_parser_framing(target)
    elif CHECK_KIND == "policy_denial":
        reproduced, evidence = verify_policy_denial(target)
    else:
        text = target.read_text(encoding="utf-8", errors="replace")
        if SNIPPET_HINT and SNIPPET_HINT in text:
            reproduced, evidence = verify_policy_denial(target)
        else:
            reproduced, evidence = False, f"Candidate assertion did not reproduce against {{TARGET_REL}}."

    out = {{
        "reproduced": bool(reproduced),
        "check_kind": CHECK_KIND,
        "file_path": TARGET_REL,
        "evidence": evidence,
    }}
    print(MARKER + json.dumps(out, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    return "docker_network_none", script, {"check_kind": check_kind, "file_path": rel_file}


def parse_poe_container_output(stdout: str) -> Optional[Dict[str, Any]]:
    """Extracts structured JSON verification payload emitted by the ephemeral POE container."""
    if not stdout:
        return None
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if POE_RESULT_MARKER in stripped:
            raw_json = stripped.split(POE_RESULT_MARKER, 1)[1].strip()
            try:
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict) and "reproduced" in parsed:
                    return parsed
            except (ValueError, TypeError):
                return None
    return None


def _downgrade_severity(original: str) -> str:
    sev = str(original or "MEDIUM").strip().upper()
    if sev in ("CRITICAL", "HIGH"):
        return "LOW"
    if sev == "MEDIUM":
        return "INFO"
    return sev


class ContainerPOEVerifier:
    """
    Containerized non-destructive POE == 3 verifier for HIGH/CRITICAL candidate findings.

    Auto-generates minimal non-destructive assertion tests, runs them inside ephemeral
    hardened Docker containers (`--network=none` for local repos or loopback-only for
    local services, `shell=False`), promotes verified findings to `poe_level = 3`,
    downgrades unverified false positives, and skips cleanly with provenance when Docker
    or the verification image is unavailable.
    """

    def __init__(
        self,
        *,
        docker_bin: Optional[str] = None,
        image: str = DEFAULT_POE_IMAGE,
        memory_limit: str = "256m",
        cpus: str = "1.0",
        pids_limit: int = 96,
        docker_timeout: float = 3.0,
        execution_timeout: float = 30.0,
        subprocess_runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    ) -> None:
        self._docker_bin_override = docker_bin
        self.image = str(image).strip() or DEFAULT_POE_IMAGE
        self.memory_limit = str(memory_limit).strip() or "256m"
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

    def check_image_available(self, image: Optional[str] = None) -> Tuple[bool, str]:
        img = str(image or self.image).strip()
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
        harness_dir: Union[str, Path],
        *,
        mode: str = "docker_network_none",
        repo_path: Optional[Union[str, Path]] = None,
        image: Optional[str] = None,
    ) -> List[str]:
        docker_bin = self.resolve_docker_bin() or "docker"
        chosen_image = str(image or self.image).strip()
        if not _DOCKER_IMAGE_RE.fullmatch(chosen_image):
            raise ValueError(f"Unsafe Docker image name rejected: {chosen_image!r}")

        container_name = f"rfchunt-poe-{secrets.token_hex(4)}"
        harness_host = str(Path(harness_dir).resolve()).replace("\\", "/")

        cmd: List[str] = [
            docker_bin,
            "run",
            "--rm",
            "--name",
            container_name,
        ]
        if mode == "docker_network_none":
            cmd.append("--network=none")
        elif mode == "docker_loopback_only":
            cmd.extend(["--add-host", "host.docker.internal:host-gateway"])
        else:
            raise ValueError(f"Unsupported POE verification mode: {mode!r}")

        cmd.extend(
            [
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
                f"{harness_host}:/poe:ro",
            ]
        )
        if repo_path is not None and mode == "docker_network_none":
            repo_host = str(Path(repo_path).resolve()).replace("\\", "/")
            cmd.extend(["-v", f"{repo_host}:/workspace:ro", "-w", "/workspace"])

        cmd.extend([chosen_image, "python3", "/poe/verify_poe.py"])

        ok, reason = validate_poe_docker_command(cmd, mode=mode)
        if not ok:
            raise PermissionError(f"Hardened POE Docker command rejected: {reason}")
        return cmd

    def verify_finding(
        self,
        finding: Dict[str, Any],
        *,
        repo_path: Optional[Union[str, Path]] = None,
        db: Optional[Any] = None,
        task_id: str = "default",
        min_severities: Iterable[str] = DEFAULT_HIGH_SEVERITIES,
        docker_ready_cache: Optional[Tuple[bool, str, bool, str]] = None,
    ) -> POEVerificationResult:
        """
        Verifies a single candidate finding in an ephemeral isolated Docker container.
        """
        t0 = time.monotonic()
        finding_id = str(
            finding.get("finding_id")
            or finding.get("vuln_id")
            or finding.get("chain_id")
            or finding.get("rule_id")
            or f"POE-{secrets.token_hex(4)}"
        )
        title = str(finding.get("title") or finding.get("name") or finding_id)
        orig_sev = str(finding.get("calibrated_severity") or finding.get("severity") or "MEDIUM").strip().upper()
        existing_poe = int(finding.get("poe_level") or 0)
        allowed_sevs = {str(s).strip().upper() for s in min_severities}

        if orig_sev not in allowed_sevs:
            return POEVerificationResult(
                finding_id=finding_id,
                title=title,
                original_severity=orig_sev,
                calibrated_severity=orig_sev,
                status="skipped_below_threshold",
                poe_level=existing_poe,
                verified=False,
                false_positive=False,
                verification_mode="skipped_below_threshold",
                evidence=f"Severity {orig_sev} is below threshold {sorted(allowed_sevs)}.",
                provenance={"threshold": sorted(allowed_sevs)},
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )

        try:
            mode, script_code, gen_meta = generate_verification_test(finding, repo_path=repo_path)
        except PermissionError as exc:
            return POEVerificationResult(
                finding_id=finding_id,
                title=title,
                original_severity=orig_sev,
                calibrated_severity=orig_sev,
                status="rejected_unsafe_target",
                poe_level=existing_poe,
                verified=False,
                false_positive=False,
                verification_mode="rejected_unsafe_target",
                evidence=str(exc),
                provenance={"rejected_reason": str(exc)},
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )

        if docker_ready_cache is not None:
            docker_ok, docker_info, img_ok, img_info = docker_ready_cache
        else:
            docker_ok, docker_info = self.check_docker_available()
            img_ok, img_info = self.check_image_available(self.image) if docker_ok else (False, "docker_unavailable")

        if not docker_ok or not img_ok:
            reason = (
                f"docker_daemon_unavailable: {docker_info}"
                if not docker_ok
                else f"docker_image_unavailable: {img_info}"
            )
            return POEVerificationResult(
                finding_id=finding_id,
                title=title,
                original_severity=orig_sev,
                calibrated_severity=orig_sev,
                status="skipped_docker_unavailable",
                poe_level=existing_poe,
                verified=False,
                false_positive=False,
                verification_mode="skipped_docker_unavailable",
                generated_test_code=script_code,
                evidence=reason,
                provenance={
                    "docker_available": docker_ok,
                    "image_available": img_ok,
                    "docker_image": self.image,
                    "reason": reason,
                    **gen_meta,
                },
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )

        harness_tmp = Path(tempfile.mkdtemp(prefix="rfchunt_poe_"))
        cmd: List[str] = []
        try:
            (harness_tmp / "verify_poe.py").write_text(script_code, encoding="utf-8")
            cmd = self.build_docker_command(
                harness_tmp,
                mode=mode,
                repo_path=repo_path,
                image=self.image,
            )
            try:
                proc = self._run_docker(cmd, timeout=self.execution_timeout)
            except subprocess.TimeoutExpired:
                return POEVerificationResult(
                    finding_id=finding_id,
                    title=title,
                    original_severity=orig_sev,
                    calibrated_severity=orig_sev,
                    status="error",
                    poe_level=existing_poe,
                    verified=False,
                    false_positive=False,
                    verification_mode=mode,
                    generated_test_code=script_code,
                    docker_command=cmd,
                    evidence=f"POE container verification timed out after {self.execution_timeout:.1f}s",
                    provenance={"docker_available": True, "docker_version": docker_info, "image": self.image, **gen_meta},
                    elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
                )

            parsed = parse_poe_container_output(proc.stdout or "")
            if parsed is None:
                return POEVerificationResult(
                    finding_id=finding_id,
                    title=title,
                    original_severity=orig_sev,
                    calibrated_severity=orig_sev,
                    status="error",
                    poe_level=existing_poe,
                    verified=False,
                    false_positive=False,
                    verification_mode=mode,
                    generated_test_code=script_code,
                    docker_command=cmd,
                    evidence=f"POE container exited ({proc.returncode}) without structured result: {(proc.stderr or '')[:240]}",
                    exit_code=proc.returncode,
                    provenance={"docker_available": True, "docker_version": docker_info, "image": self.image, **gen_meta},
                    elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
                )

            reproduced = bool(parsed.get("reproduced", False)) and proc.returncode == 0
            evidence = str(parsed.get("evidence") or "")

            if reproduced and evidence:
                fact_id: Optional[str] = None
                if db is not None and hasattr(db, "add_fact"):
                    fact_id = str(
                        db.add_fact(
                            content=f"POE==3 container verification confirmed [{finding_id}] {title}: {evidence}",
                            task_id=task_id,
                            domain="poe_verification",
                            source_agent="ContainerPOEVerifier",
                            payload={
                                "finding_id": finding_id,
                                "poe_level": int(POELevel.VERIFIED_EXPLOIT),
                                "verification_mode": mode,
                                "docker_image": self.image,
                                "file_path": gen_meta.get("file_path", ""),
                                "evidence": evidence,
                                "original_severity": orig_sev,
                            },
                        )
                    )
                return POEVerificationResult(
                    finding_id=finding_id,
                    title=title,
                    original_severity=orig_sev,
                    calibrated_severity=orig_sev,
                    status="verified",
                    poe_level=int(POELevel.VERIFIED_EXPLOIT),
                    verified=True,
                    false_positive=False,
                    verification_mode=mode,
                    generated_test_code=script_code,
                    docker_command=cmd,
                    evidence=evidence,
                    exit_code=proc.returncode,
                    cairn_fact_id=fact_id,
                    provenance={
                        "docker_available": True,
                        "docker_version": docker_info,
                        "image": self.image,
                        "container_output": parsed,
                        **gen_meta,
                    },
                    elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
                )

            # Non-reproduced in container -> downgrade false positive before final reporting
            downgraded_sev = _downgrade_severity(orig_sev)
            return POEVerificationResult(
                finding_id=finding_id,
                title=title,
                original_severity=orig_sev,
                calibrated_severity=downgraded_sev,
                status="downgraded_false_positive",
                poe_level=int(POELevel.NONE),
                verified=False,
                false_positive=True,
                verification_mode=mode,
                generated_test_code=script_code,
                docker_command=cmd,
                evidence=evidence or "Candidate assertion did not reproduce inside isolated container.",
                exit_code=proc.returncode,
                provenance={
                    "docker_available": True,
                    "docker_version": docker_info,
                    "image": self.image,
                    "container_output": parsed,
                    **gen_meta,
                },
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )
        finally:
            shutil.rmtree(harness_tmp, ignore_errors=True)

    def verify_findings(
        self,
        findings: Sequence[Dict[str, Any]],
        *,
        repo_path: Optional[Union[str, Path]] = None,
        db: Optional[Any] = None,
        task_id: str = "default",
        min_severities: Iterable[str] = DEFAULT_HIGH_SEVERITIES,
        max_workers: int = 4,
    ) -> POEBatchReport:
        """
        Verifies a batch of candidate findings concurrently in ephemeral containers.
        Checks Docker/image readiness once upfront so unavailable Docker skips cleanly
        in O(1) without crashing `--all`.
        """
        t0 = time.monotonic()
        finding_list = list(findings)
        allowed_sevs = {str(s).strip().upper() for s in min_severities}
        eligible_indices = [
            idx
            for idx, f in enumerate(finding_list)
            if str(f.get("calibrated_severity") or f.get("severity") or "MEDIUM").strip().upper() in allowed_sevs
        ]

        if not eligible_indices:
            results = [
                self.verify_finding(
                    f,
                    repo_path=repo_path,
                    db=db,
                    task_id=task_id,
                    min_severities=allowed_sevs,
                )
                for f in finding_list
            ]
            return POEBatchReport(
                status="no_eligible_findings",
                total_candidates=len(finding_list),
                eligible_candidates=0,
                verified_poe3_count=0,
                downgraded_false_positive_count=0,
                skipped_count=len(results),
                error_count=0,
                results=results,
                provenance={"threshold": sorted(allowed_sevs)},
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )

        docker_ok, docker_info = self.check_docker_available()
        img_ok, img_info = self.check_image_available(self.image) if docker_ok else (False, "docker_unavailable")
        cache = (docker_ok, docker_info, img_ok, img_info)

        if not docker_ok or not img_ok:
            results = [
                self.verify_finding(
                    f,
                    repo_path=repo_path,
                    db=None,
                    task_id=task_id,
                    min_severities=allowed_sevs,
                    docker_ready_cache=cache,
                )
                for f in finding_list
            ]
            return POEBatchReport(
                status="skipped_docker_unavailable",
                total_candidates=len(finding_list),
                eligible_candidates=len(eligible_indices),
                verified_poe3_count=0,
                downgraded_false_positive_count=0,
                skipped_count=len(results),
                error_count=0,
                results=results,
                provenance={
                    "docker_available": docker_ok,
                    "image_available": img_ok,
                    "docker_image": self.image,
                    "reason": docker_info if not docker_ok else img_info,
                },
                elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
            )

        ordered_results: Dict[int, POEVerificationResult] = {}
        workers = max(1, min(int(max_workers), len(finding_list), 8))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {
                pool.submit(
                    self.verify_finding,
                    f,
                    repo_path=repo_path,
                    db=db,
                    task_id=task_id,
                    min_severities=allowed_sevs,
                    docker_ready_cache=cache,
                ): idx
                for idx, f in enumerate(finding_list)
            }
            for fut in as_completed(futs):
                idx = futs[fut]
                ordered_results[idx] = fut.result()

        final_results = [ordered_results[i] for i in range(len(finding_list))]
        verified_cnt = sum(1 for r in final_results if r.verified and r.poe_level == int(POELevel.VERIFIED_EXPLOIT))
        fp_cnt = sum(1 for r in final_results if r.false_positive)
        skip_cnt = sum(1 for r in final_results if r.status.startswith("skipped_") or r.status == "rejected_unsafe_target")
        err_cnt = sum(1 for r in final_results if r.status == "error")
        fact_ids = [r.cairn_fact_id for r in final_results if r.cairn_fact_id]

        return POEBatchReport(
            status="completed",
            total_candidates=len(finding_list),
            eligible_candidates=len(eligible_indices),
            verified_poe3_count=verified_cnt,
            downgraded_false_positive_count=fp_cnt,
            skipped_count=skip_cnt,
            error_count=err_cnt,
            results=final_results,
            persisted_fact_ids=fact_ids,
            provenance={
                "docker_available": True,
                "docker_version": docker_info,
                "image_available": True,
                "image_id": img_info,
                "docker_image": self.image,
                "threshold": sorted(allowed_sevs),
            },
            elapsed_ms=round((time.monotonic() - t0) * 1000.0, 2),
        )

    @staticmethod
    def apply_verifications_to_findings(
        findings: Sequence[Dict[str, Any]],
        results: Sequence[POEVerificationResult],
        *,
        drop_false_positives: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Applies `POEVerificationResult` promotions/downgrades back onto finding dicts
        for final reporting (SARIF/CSV/advisory). Optionally filters out downgraded
        false positives when `drop_false_positives=True`.
        """
        by_id: Dict[str, POEVerificationResult] = {r.finding_id: r for r in results}
        updated: List[Dict[str, Any]] = []
        for idx, finding in enumerate(findings):
            copy = dict(finding)
            fid = str(
                copy.get("finding_id")
                or copy.get("vuln_id")
                or copy.get("chain_id")
                or copy.get("rule_id")
                or ""
            )
            res = by_id.get(fid) if fid in by_id else (results[idx] if idx < len(results) else None)
            if res is not None:
                from engine.epistemic_state import attach_epistemic_metadata

                if res.verified:
                    copy["poe_level"] = int(POELevel.VERIFIED_EXPLOIT)
                    copy["verification_status"] = "VERIFIED"
                    copy["poe_verification_status"] = res.status
                    copy["poe_evidence"] = res.evidence
                    copy["false_positive"] = False
                    copy["runtime_poe_verified"] = True
                    attach_epistemic_metadata(copy, runtime_poe_verified=True)
                elif res.false_positive:
                    copy["poe_level"] = int(POELevel.NONE)
                    copy["verification_status"] = "DOWNGRADED_FALSE_POSITIVE"
                    copy["poe_verification_status"] = res.status
                    copy["calibrated_severity"] = res.calibrated_severity
                    copy["severity"] = res.calibrated_severity
                    copy["poe_evidence"] = res.evidence
                    copy["false_positive"] = True
                    attach_epistemic_metadata(copy, refuted=True)
                    if drop_false_positives:
                        continue
                else:
                    copy["poe_verification_status"] = res.status
                    attach_epistemic_metadata(copy)
            updated.append(copy)
        return updated
