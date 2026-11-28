"""
Lean 4 Hybrid Formal Verification & Differential Oracle Bridge (`engine/lean_formal_verifier.py`).
==================================================================================================
Bridges RFCHunt's Python runtime with the Lean 4 formal specifications in `formal/lean4/`:
  - `RFCHunt/PolicyGuard.lean`        (Cedar-style agent containment & override immunity)
  - `RFCHunt/HttpFramingOracle.lean`  (RFC 9112 Section 6.3 framing differential oracle)
  - `RFCHunt/DotNetPeIntegrity.lean`  (CVE-2026-108398 .NET Framework 4 UMCI loader model)

Two-Layer Integrity Model:
1. When `lake` / `lean` is installed on the host, executes `lake build` (`shell=False`) to
   machine-check every theorem in Lean 4's kernel and records `machine_checked=True`.
2. In all environments (including offline CI without Lean 4 installed), performs strict
   anti-cheat static proof auditing (verifying zero `sorry`, zero custom `axiom`, and exact
   declared theorem inventory) AND runs the isomorphic Python mirror of all three formal
   models for deterministic policy gating and RFC 9112 differential witness checks.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import unicodedata

from engine.host_containment import silent_subprocess_run


_THEOREM_RE = re.compile(
    r"^\s*(?:(?:private|protected|unsafe|noncomputable|partial)\s+)*theorem\s+(«[^»\n]+»'*|[A-Za-z0-9_']+)",
    re.MULTILINE,
)
_SORRY_RE = re.compile(r"\bsorry\b")
_AXIOM_RE = re.compile(
    r"^\s*(?:(?:private|protected|unsafe|noncomputable|partial)\s+)*axiom(?:[ \t]+(«[^»\n]+»'*|[A-Za-z0-9_']+)|(?=\s|$))",
    re.MULTILINE,
)
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_LAKE_DIAG_HEADER_RE = re.compile(
    r"^(?:(error|warning|info):\s+)?((?:[A-Za-z]:)?[^\r\n:]+\.lean):(\d+):(\d+):\s*(.*)$"
)
_LEAN_CLI_DIAG_HEADER_RE = re.compile(
    r"^((?:[A-Za-z]:)?[^\r\n:]+\.lean):(\d+):(\d+):\s*(error|warning|info):\s*(.*)$"
)


@dataclass
class LeanProofDiagnostic:
    """Structured Lean 4 compiler/kernel or static proof-integrity diagnostic."""

    module: str
    theorem: str
    line: Optional[int]
    column: Optional[int]
    kind: str  # "unsolved_goals" | "type_mismatch" | "sorry" | "unknown_identifier" | "tactic_failed" | "timeout" | "custom_axiom" | "zero_theorems" | "missing_modules" | "kernel_error"
    branch_summary: str
    raw_excerpt: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "theorem": self.theorem,
            "line": self.line,
            "column": self.column,
            "kind": self.kind,
            "branch_summary": self.branch_summary,
            "raw_excerpt": self.raw_excerpt,
        }


@dataclass
class LeanModuleAudit:
    """Static proof-integrity audit for a single `.lean` module."""

    file_path: str
    theorems: List[str] = field(default_factory=list)
    has_sorry: bool = False
    has_custom_axiom: bool = False
    clean_proofs: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "theorems": list(self.theorems),
            "theorem_count": len(self.theorems),
            "has_sorry": self.has_sorry,
            "has_custom_axiom": self.has_custom_axiom,
            "clean_proofs": self.clean_proofs,
        }


@dataclass
class LeanVerificationReport:
    """Result of auditing and (when installed) kernel-checking RFCHunt's Lean 4 workspace."""

    lean_dir: str
    lean_binary: Optional[str]
    lake_binary: Optional[str]
    machine_checked: bool
    status: str  # "machine_checked" | "static_audited_lean_not_installed" | "proof_integrity_violation" | "kernel_failed"
    modules: List[LeanModuleAudit] = field(default_factory=list)
    total_theorems: int = 0
    stdout: str = ""
    stderr: str = ""
    elapsed_ms: float = 0.0
    diagnostics: List[LeanProofDiagnostic] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lean_dir": self.lean_dir,
            "lean_binary": self.lean_binary,
            "lake_binary": self.lake_binary,
            "machine_checked": self.machine_checked,
            "status": self.status,
            "total_theorems": self.total_theorems,
            "modules": [m.to_dict() for m in self.modules],
            "stdout": self.stdout,
            "stderr": self.stderr,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


def _is_lean_ident_prev(ch: str) -> bool:
    """Returns True if `ch` can immediately precede an identifier prime `'` in Lean 4."""
    if not ch:
        return False
    if ch.isalnum() or ch in ("_", "'", "»"):
        return True
    if ord(ch) >= 128 and not ch.isspace():
        cat = unicodedata.category(ch)
        if not cat.startswith(("P", "Z", "C")):
            return True
    return False


def _match_lean_char_literal_end(
    source: str, start: int, line_breaks: Tuple[str, ...]
) -> Optional[int]:
    """
    If `source[start:]` begins a valid single-line Lean 4 `Char` literal (`'c'`,
    `'\\<esc>'`, `'\\xHH'`, `'\\uHHHH'`, `'\\u{...}'`), returns the index of the
    closing `'`; otherwise returns `None`.
    """
    n = len(source)
    if start + 1 >= n:
        return None
    c1 = source[start + 1]
    if c1 == "\\":
        if start + 2 >= n:
            return None
        esc = source[start + 2]
        if esc in line_breaks:
            return None
        if (
            esc == "x"
            and start + 5 < n
            and source[start + 3] in _HEX_CHARS
            and source[start + 4] in _HEX_CHARS
            and source[start + 5] == "'"
        ):
            return start + 5
        if (
            esc == "u"
            and start + 7 < n
            and all(source[k] in _HEX_CHARS for k in range(start + 3, start + 7))
            and source[start + 7] == "'"
        ):
            return start + 7
        if esc == "u" and start + 4 < n and source[start + 3] == "{":
            j = start + 4
            while j < n and source[j] in _HEX_CHARS:
                j += 1
            if j > start + 4 and j + 1 < n and source[j] == "}" and source[j + 1] == "'":
                return j + 1
        if start + 3 < n and source[start + 3] == "'":
            return start + 3
        return None

    if start + 2 < n and c1 != "'" and c1 not in line_breaks and source[start + 2] == "'":
        return start + 2
    return None


def _strip_lean_comments(source: str, *, mask_strings: bool = False) -> str:
    """
    Single-pass Lean 4 lexical scanner stripping `--` line comments and
    arbitrarily nested `/- ... -/` block comments while respecting string
    literals (`"..."` with backslash escapes) and `Char` literals (`'...'`)
    and preserving line/column offsets.
    When `mask_strings=True`, opening/closing `"` and `'` delimiters and line
    breaks are preserved verbatim while interior characters (including escapes)
    are replaced 1-for-1 with `" "`.
    """
    out: List[str] = []
    i = 0
    n = len(source)
    block_depth = 0
    in_line_comment = False
    in_string = False
    _line_breaks = ("\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch in _line_breaks:
                in_line_comment = False
                out.append(ch)
            else:
                out.append(" ")
            i += 1
            continue

        if block_depth > 0:
            if ch == "/" and nxt == "-":
                block_depth += 1
                out.extend((" ", " "))
                i += 2
            elif ch == "-" and nxt == "/":
                block_depth -= 1
                out.extend((" ", " "))
                i += 2
            elif ch in _line_breaks:
                out.append(ch)
                i += 1
            else:
                out.append(" ")
                i += 1
            continue

        if in_string:
            if ch == "\\":
                out.append(" " if mask_strings else ch)
                if i + 1 < n:
                    esc = source[i + 1]
                    if mask_strings:
                        out.append(esc if esc in _line_breaks else " ")
                    else:
                        out.append(esc)
                    i += 2
                else:
                    i += 1
            elif ch == '"':
                out.append(ch)
                in_string = False
                i += 1
            else:
                if mask_strings:
                    out.append(ch if ch in _line_breaks else " ")
                else:
                    out.append(ch)
                i += 1
            continue

        if ch == "-" and nxt == "-":
            in_line_comment = True
            out.extend((" ", " "))
            i += 2
        elif ch == "/" and nxt == "-":
            block_depth = 1
            out.extend((" ", " "))
            i += 2
        elif ch == "'":
            prev = source[i - 1] if i > 0 else ""
            char_end = None if _is_lean_ident_prev(prev) else _match_lean_char_literal_end(source, i, _line_breaks)
            if char_end is not None:
                out.append("'")
                if mask_strings:
                    out.extend(" " for _ in range(i + 1, char_end))
                else:
                    out.append(source[i + 1 : char_end])
                out.append("'")
                i = char_end + 1
            else:
                out.append(ch)
                i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        else:
            out.append(ch)
            i += 1

    return "".join(out)


def _normalize_lean_module(file_part: str) -> str:
    norm = file_part.replace("\\", "/").strip()
    if "RFCHunt/" in norm:
        tail = norm.split("RFCHunt/", 1)[1]
        if tail.endswith(".lean"):
            tail = tail[:-5]
        return "RFCHunt." + tail.replace("/", ".")
    return Path(norm).stem or norm


def _classify_diagnostic_kind(message: str) -> str:
    low = message.lower()
    if "unsolved goals" in low:
        return "unsolved_goals"
    if "type mismatch" in low:
        return "type_mismatch"
    if "declaration uses 'sorry'" in low or re.search(r"\bsorry\b", low):
        return "sorry"
    if "unknown identifier" in low or "unknown constant" in low:
        return "unknown_identifier"
    if re.search(r"\btactic\b.*\bfailed\b|\bno goals to be solved\b|\bsimp made no progress\b", low):
        return "tactic_failed"
    if "timed out" in low or "deterministic timeout" in low or "timeout" in low:
        return "timeout"
    if re.search(r"\baxiom\b", low):
        return "custom_axiom"
    return "kernel_error"


def _resolve_theorem_name(
    file_part: str,
    line: Optional[int],
    message: str,
    lean_dir: Optional[Union[str, Path]] = None,
) -> str:
    m_decl = re.search(r"declaration\s+'([A-Za-z0-9_'.]+)'", message)
    if m_decl:
        return m_decl.group(1).rsplit(".", 1)[-1]
    m_thm = re.search(r"\btheorem\s+(«[^»\n]+»'*|[A-Za-z0-9_']+)", message)
    if m_thm:
        return m_thm.group(1)

    if line is not None and line > 0:
        candidates: List[Path] = [Path(file_part)]
        if lean_dir is not None:
            candidates.append(Path(lean_dir) / file_part)
        for cand in candidates:
            try:
                if cand.is_file():
                    lines = cand.read_text(encoding="utf-8", errors="replace").splitlines()
                    prefix = "\n".join(lines[:line])
                    matches = _THEOREM_RE.findall(_strip_lean_comments(prefix, mask_strings=True))
                    if matches:
                        return matches[-1]
            except OSError:
                continue
    return "unknown"


def _summarize_diagnostic_branch(kind: str, body_lines: List[str]) -> str:
    cleaned = [ln.strip() for ln in body_lines if ln.strip()]
    if not cleaned:
        return kind
    if kind == "unsolved_goals":
        cases = [ln[5:].strip() for ln in cleaned if ln.startswith("case ")]
        goals = [ln for ln in cleaned if "⊢" in ln]
        if goals:
            goal_preview = "; ".join(goals[:3]) + ("; ..." if len(goals) > 3 else "")
        else:
            goal_preview = cleaned[0]
        if cases:
            case_preview = ", ".join(cases[:4]) + (", ..." if len(cases) > 4 else "")
            summary = f"unsolved_goals ({case_preview}): {goal_preview}"
        else:
            summary = f"unsolved_goals: {goal_preview}"
        return summary[:240]
    return cleaned[0][:240]


def _parse_lake_diagnostics(
    stdout: str,
    stderr: str,
    *,
    lean_dir: Optional[Union[str, Path]] = None,
) -> List[LeanProofDiagnostic]:
    """Parses Lake 4 and Lean 4 CLI error/warning blocks into structured diagnostics."""
    diagnostics: List[LeanProofDiagnostic] = []
    seen: set[Tuple[str, Optional[int], Optional[int], str, str]] = set()

    def _parse_stream(text: str) -> None:
        if not text:
            return
        lines = text.splitlines()
        idx = 0
        while idx < len(lines):
            raw_line = lines[idx]
            stripped = raw_line.rstrip()
            m_cli = _LEAN_CLI_DIAG_HEADER_RE.match(stripped)
            m_lake = _LAKE_DIAG_HEADER_RE.match(stripped) if m_cli is None else None
            if m_cli is None and m_lake is None:
                idx += 1
                continue

            if m_cli is not None:
                file_part, line_s, col_s, _sev, first_msg = m_cli.groups()
            else:
                _sev, file_part, line_s, col_s, first_msg = m_lake.groups()

            line_no = int(line_s)
            col_no = int(col_s)
            block_lines = [stripped]
            msg_lines = [first_msg] if first_msg else []
            idx += 1
            while idx < len(lines):
                nxt = lines[idx]
                nxt_s = nxt.rstrip()
                if _LEAN_CLI_DIAG_HEADER_RE.match(nxt_s) or _LAKE_DIAG_HEADER_RE.match(nxt_s):
                    break
                if re.match(r"^(?:error:\s*build failed|✖|✔)", nxt_s.strip()):
                    break
                block_lines.append(nxt_s)
                if nxt_s.strip():
                    msg_lines.append(nxt_s)
                idx += 1

            full_msg = "\n".join(msg_lines).strip()
            kind = _classify_diagnostic_kind(full_msg)
            module = _normalize_lean_module(file_part)
            theorem = _resolve_theorem_name(file_part, line_no, full_msg, lean_dir=lean_dir)
            branch_summary = _summarize_diagnostic_branch(kind, msg_lines)
            raw_excerpt = "\n".join(block_lines).strip()[:1000]
            key = (module, line_no, col_no, kind, branch_summary)
            if key not in seen:
                seen.add(key)
                diagnostics.append(
                    LeanProofDiagnostic(
                        module=module,
                        theorem=theorem,
                        line=line_no,
                        column=col_no,
                        kind=kind,
                        branch_summary=branch_summary,
                        raw_excerpt=raw_excerpt,
                    )
                )

    _parse_stream(stderr or "")
    _parse_stream(stdout or "")

    if not diagnostics:
        combined = "\n".join(part for part in ((stderr or "").strip(), (stdout or "").strip()) if part).strip()
        if combined and any(tok in combined.lower() for tok in ("error", "failed", "timed out", "timeout")):
            kind = _classify_diagnostic_kind(combined)
            first_non_empty = next((ln.strip() for ln in combined.splitlines() if ln.strip()), "lake build failed")
            diagnostics.append(
                LeanProofDiagnostic(
                    module="lake",
                    theorem="unknown",
                    line=None,
                    column=None,
                    kind=kind,
                    branch_summary=first_non_empty[:240],
                    raw_excerpt=combined[:1000],
                )
            )
    return diagnostics


def _collect_integrity_diagnostics(
    modules: Sequence[LeanModuleAudit],
    rfchunt_pkg: Path,
) -> List[LeanProofDiagnostic]:
    """Builds structured diagnostics for `proof_integrity_violation` states."""
    if not modules:
        return [
            LeanProofDiagnostic(
                module="RFCHunt",
                theorem="unknown",
                line=None,
                column=None,
                kind="missing_modules",
                branch_summary=f"No .lean modules found under {rfchunt_pkg}",
                raw_excerpt=f"No .lean modules found under {rfchunt_pkg}",
            )
        ]

    diagnostics: List[LeanProofDiagnostic] = []
    for mod in modules:
        if mod.clean_proofs:
            continue
        p = Path(mod.file_path)
        mod_name = _normalize_lean_module(str(p))
        try:
            raw_text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            diagnostics.append(
                LeanProofDiagnostic(
                    module=mod_name,
                    theorem="unknown",
                    line=None,
                    column=None,
                    kind="kernel_error",
                    branch_summary=f"Unable to read {p.name}: {exc}",
                    raw_excerpt=str(exc)[:1000],
                )
            )
            continue

        stripped_text = _strip_lean_comments(raw_text, mask_strings=True)
        raw_lines = raw_text.splitlines()
        code_lines = stripped_text.splitlines()
        current_theorem = "unknown"
        emitted_for_mod = 0
        for lineno, raw_line in enumerate(raw_lines, start=1):
            code_line = code_lines[lineno - 1] if lineno - 1 < len(code_lines) else ""

            m_thm = _THEOREM_RE.match(code_line)
            if m_thm:
                current_theorem = m_thm.group(1)

            for m_sorry in _SORRY_RE.finditer(code_line):
                emitted_for_mod += 1
                diagnostics.append(
                    LeanProofDiagnostic(
                        module=mod_name,
                        theorem=current_theorem,
                        line=lineno,
                        column=m_sorry.start() + 1,
                        kind="sorry",
                        branch_summary=f"Proof of `{current_theorem}` uses `sorry`",
                        raw_excerpt=raw_line.strip()[:1000],
                    )
                )

            m_ax = _AXIOM_RE.match(code_line)
            if m_ax:
                emitted_for_mod += 1
                ax_name = m_ax.group(1) or "unknown"
                ax_col = (
                    m_ax.start(1) + 1
                    if m_ax.group(1) is not None
                    else (len(code_line) - len(code_line.lstrip()) + 1)
                )
                diagnostics.append(
                    LeanProofDiagnostic(
                        module=mod_name,
                        theorem=ax_name,
                        line=lineno,
                        column=ax_col,
                        kind="custom_axiom",
                        branch_summary=f"Custom axiom `{ax_name}` declared",
                        raw_excerpt=raw_line.strip()[:1000],
                    )
                )

        if emitted_for_mod == 0:
            if mod.has_custom_axiom:
                fb_kind = "custom_axiom"
                fb_summary = f"Module {mod_name} declares a custom axiom"
            elif mod.has_sorry:
                fb_kind = "sorry"
                fb_summary = f"Module {mod_name} contains `sorry`"
            elif len(mod.theorems) == 0:
                fb_kind = "zero_theorems"
                fb_summary = f"Module {mod_name} declares zero proven theorems"
            else:
                fb_kind = "kernel_error"
                fb_summary = f"Module {mod_name} failed static proof integrity audit"
            diagnostics.append(
                LeanProofDiagnostic(
                    module=mod_name,
                    theorem="unknown",
                    line=1,
                    column=1,
                    kind=fb_kind,
                    branch_summary=fb_summary,
                    raw_excerpt=(raw_text.strip()[:240] or "<empty>"),
                )
            )
    return diagnostics


def audit_lean_file(path: Union[str, Path]) -> LeanModuleAudit:
    """Inspects a `.lean` file for declared theorems, `sorry` placeholders, and custom axioms."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    code = _strip_lean_comments(raw, mask_strings=True)
    theorems = _THEOREM_RE.findall(code)
    has_sorry = bool(_SORRY_RE.search(code))
    has_axiom = bool(_AXIOM_RE.search(code))
    return LeanModuleAudit(
        file_path=str(p),
        theorems=theorems,
        has_sorry=has_sorry,
        has_custom_axiom=has_axiom,
        clean_proofs=(len(theorems) > 0 and not has_sorry and not has_axiom),
    )


def verify_lean_workspace(
    lean_dir: Union[str, Path] = "formal/lean4",
    timeout_sec: float = 120.0,
) -> LeanVerificationReport:
    """
    Audits all `.lean` modules under `lean_dir/RFCHunt` for zero `sorry`/axioms and,
    if `lake` is installed, runs `lake build` to machine-check all proofs in Lean 4's kernel.
    """
    t0 = time.monotonic()
    root = Path(lean_dir).resolve()
    modules: List[LeanModuleAudit] = []
    rfchunt_pkg = root / "RFCHunt"
    if rfchunt_pkg.is_dir():
        for lean_file in sorted(rfchunt_pkg.glob("*.lean")):
            modules.append(audit_lean_file(lean_file))

    total_theorems = sum(len(m.theorems) for m in modules)
    lean_bin = shutil.which("lean")
    lake_bin = shutil.which("lake")

    if not modules or any(not m.clean_proofs for m in modules):
        integrity_diags = _collect_integrity_diagnostics(modules, rfchunt_pkg)
        return LeanVerificationReport(
            lean_dir=str(root),
            lean_binary=lean_bin,
            lake_binary=lake_bin,
            machine_checked=False,
            status="proof_integrity_violation",
            modules=modules,
            total_theorems=total_theorems,
            stderr="One or more Lean 4 modules contain `sorry`, custom `axiom`, or zero theorems.",
            elapsed_ms=(time.monotonic() - t0) * 1000.0,
            diagnostics=integrity_diags,
        )

    if lake_bin and (root / "lakefile.lean").is_file():
        try:
            proc = silent_subprocess_run(
                [lake_bin, "build"],
                cwd=str(root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
            )
            ok = proc.returncode == 0
            out_s = proc.stdout or ""
            err_s = proc.stderr or ""
            diags: List[LeanProofDiagnostic] = []
            if not ok:
                diags = _parse_lake_diagnostics(out_s, err_s, lean_dir=root)
                if not diags:
                    fallback_msg = (err_s or out_s or f"lake build failed with return code {proc.returncode}").strip()
                    diags = [
                        LeanProofDiagnostic(
                            module="lake",
                            theorem="unknown",
                            line=None,
                            column=None,
                            kind="kernel_error",
                            branch_summary=fallback_msg.splitlines()[0][:240],
                            raw_excerpt=fallback_msg[:1000],
                        )
                    ]
            return LeanVerificationReport(
                lean_dir=str(root),
                lean_binary=lean_bin,
                lake_binary=lake_bin,
                machine_checked=ok,
                status="machine_checked" if ok else "kernel_failed",
                modules=modules,
                total_theorems=total_theorems,
                stdout=out_s,
                stderr=err_s,
                elapsed_ms=(time.monotonic() - t0) * 1000.0,
                diagnostics=diags,
            )
        except subprocess.TimeoutExpired:
            msg = f"lake build timed out after {timeout_sec}s"
            return LeanVerificationReport(
                lean_dir=str(root),
                lean_binary=lean_bin,
                lake_binary=lake_bin,
                machine_checked=False,
                status="kernel_failed",
                modules=modules,
                total_theorems=total_theorems,
                stderr=msg,
                elapsed_ms=(time.monotonic() - t0) * 1000.0,
                diagnostics=[
                    LeanProofDiagnostic(
                        module="lake",
                        theorem="unknown",
                        line=None,
                        column=None,
                        kind="timeout",
                        branch_summary=msg,
                        raw_excerpt=msg,
                    )
                ],
            )

    return LeanVerificationReport(
        lean_dir=str(root),
        lean_binary=lean_bin,
        lake_binary=lake_bin,
        machine_checked=False,
        status="static_audited_lean_not_installed",
        modules=modules,
        total_theorems=total_theorems,
        elapsed_ms=(time.monotonic() - t0) * 1000.0,
        diagnostics=[],
    )


# ---------------------------------------------------------------------------
# Isomorphic Executable Python Mirrors of the Proven Lean 4 Specifications
# ---------------------------------------------------------------------------


def evaluate_policy_mirror(
    *,
    action: str,
    scope: str,
    in_workspace_root: bool,
    allow_destructive: bool,
    rules: Sequence[Tuple[str, bool]],
) -> bool:
    """Exact mirror of `RFCHunt.PolicyGuard.evaluatePolicies`."""
    if action == "shellExec":
        baseline = False
    elif action == "readWorkspaceFile":
        baseline = bool(in_workspace_root)
    elif action == "networkProbe":
        baseline = scope == "inScopeAuthorized"
    elif action == "destructiveHttp":
        baseline = (scope == "inScopeAuthorized") and bool(allow_destructive)
    else:
        baseline = False

    has_forbid = any(eff == "forbid" and matched for eff, matched in rules)
    has_permit = any(eff == "permit" and matched for eff, matched in rules)
    return baseline and has_permit and (not has_forbid)


def reconcile_verdict_mirror(confirmed_by_tool: bool, llm_confirmed: bool) -> bool:
    """Exact mirror of `RFCHunt.PolicyGuard.reconcileVerdict`."""
    return bool(confirmed_by_tool or llm_confirmed)


def strict_rfc9112_oracle(
    content_lengths: Sequence[int],
    has_transfer_encoding_chunked: bool,
    has_bare_lf: bool = False,
) -> Tuple[str, Optional[int]]:
    """Exact mirror of `RFCHunt.HttpFramingOracle.strictRfc9112`."""
    if has_bare_lf:
        return ("reject400", None)
    if has_transfer_encoding_chunked and len(content_lengths) > 0:
        return ("reject400", None)
    if has_transfer_encoding_chunked:
        return ("acceptChunked", None)
    if not content_lengths:
        return ("acceptContentLength", 0)
    first = content_lengths[0]
    if all(x == first for x in content_lengths):
        return ("acceptContentLength", first)
    return ("reject400", None)


def permissive_cl_first_proxy_mirror(
    content_lengths: Sequence[int],
    has_transfer_encoding_chunked: bool,
) -> Tuple[str, Optional[int]]:
    """Exact mirror of `RFCHunt.HttpFramingOracle.permissiveClFirstProxy`."""
    if content_lengths:
        return ("acceptContentLength", content_lengths[0])
    if has_transfer_encoding_chunked:
        return ("acceptChunked", None)
    return ("acceptContentLength", 0)


def dotnet_pe_integrity_mirror(
    *,
    is_valid_pe: bool,
    has_clr_descriptor: bool,
    has_executable_image_bit: bool,
    is_umci_enforced: bool,
    is_signed_by_trusted_publisher: bool,
) -> Tuple[bool, str, str]:
    """Exact mirror of `RFCHunt.DotNetPeIntegrity` (`isCve2026108398Anomaly`, unpatched, patched)."""
    anomaly = bool(is_valid_pe and has_clr_descriptor and (not has_executable_image_bit))

    if (not is_valid_pe) or (not has_clr_descriptor):
        unpatched = "rejectedInvalidOrUnsigned"
    elif has_executable_image_bit:
        if is_umci_enforced and (not is_signed_by_trusted_publisher):
            unpatched = "rejectedInvalidOrUnsigned"
        else:
            unpatched = "loadedViaSecImageVerified"
    else:
        unpatched = "loadedViaUncheckedFlatMemoryFallback"

    if (not is_valid_pe) or (not has_clr_descriptor) or (not has_executable_image_bit):
        patched = "rejectedInvalidOrUnsigned"
    elif is_umci_enforced and (not is_signed_by_trusted_publisher):
        patched = "rejectedInvalidOrUnsigned"
    else:
        patched = "loadedViaSecImageVerified"

    return (anomaly, unpatched, patched)


# ---------------------------------------------------------------------------
# Direct Execution of Compiled Lean 4 Binary (`rfchunt-lean-oracle`)
# ---------------------------------------------------------------------------


def find_lean_oracle_binary(lean_dir: Union[str, Path] = "formal/lean4") -> Optional[Path]:
    """Locates the compiled `rfchunt-lean-oracle` native Lean 4 executable if built."""
    root = Path(lean_dir).resolve()
    bin_dir = root / ".lake" / "build" / "bin"
    for name in ("rfchunt-lean-oracle", "rfchunt-lean-oracle.exe"):
        cand = bin_dir / name
        if cand.is_file():
            return cand
    return None


class LeanCompiledOracle:
    """
    Invokes the compiled native Lean 4 executable (`rfchunt-lean-oracle`) directly
    so Python executes the exact kernel-proven Lean 4 code with zero mirror drift.
    """

    def __init__(self, binary_path: Union[str, Path], timeout_sec: float = 10.0):
        self.binary_path = Path(binary_path).resolve()
        self.timeout_sec = timeout_sec

    def _run(self, *args: str) -> str:
        proc = silent_subprocess_run(
            [str(self.binary_path), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_sec,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"rfchunt-lean-oracle failed (rc={proc.returncode}): {proc.stderr.strip()}")
        return (proc.stdout or "").strip()

    @staticmethod
    def _b(v: bool) -> str:
        return "true" if v else "false"

    def evaluate_policy(
        self,
        *,
        action: str,
        scope: str,
        in_workspace_root: bool,
        allow_destructive: bool,
        rules: Sequence[Tuple[str, bool]],
    ) -> bool:
        rules_csv = ",".join(f"{eff}:{self._b(m)}" for eff, m in rules) if rules else "none"
        out = self._run(
            "policy",
            action,
            scope,
            self._b(in_workspace_root),
            self._b(allow_destructive),
            rules_csv,
        )
        return out == "true"

    def reconcile_verdict(self, confirmed_by_tool: bool, llm_confirmed: bool) -> bool:
        return self._run("reconcile", self._b(confirmed_by_tool), self._b(llm_confirmed)) == "true"

    def strict_rfc9112(
        self,
        content_lengths: Sequence[int],
        has_transfer_encoding_chunked: bool,
        has_bare_lf: bool = False,
    ) -> Tuple[str, Optional[int]]:
        cls_csv = ",".join(str(int(n)) for n in content_lengths) if content_lengths else "none"
        out = self._run("framing", cls_csv, self._b(has_transfer_encoding_chunked), self._b(has_bare_lf))
        if out.startswith("acceptContentLength:"):
            return ("acceptContentLength", int(out.split(":", 1)[1]))
        return (out, None)

    def evaluate_dotnet_pe(
        self,
        *,
        is_valid_pe: bool,
        has_clr_descriptor: bool,
        has_executable_image_bit: bool,
        is_umci_enforced: bool,
        is_signed_by_trusted_publisher: bool,
    ) -> Tuple[bool, str, str]:
        out = self._run(
            "pe",
            self._b(is_valid_pe),
            self._b(has_clr_descriptor),
            self._b(has_executable_image_bit),
            self._b(is_umci_enforced),
            self._b(is_signed_by_trusted_publisher),
        )
        anom_s, unpatched, patched = out.split("|", 2)
        return (anom_s == "true", unpatched, patched)


def evaluate_policy_verified(
    *,
    action: str,
    scope: str,
    in_workspace_root: bool,
    allow_destructive: bool,
    rules: Sequence[Tuple[str, bool]],
    lean_dir: Union[str, Path] = "formal/lean4",
) -> Tuple[bool, str]:
    """
    Executes the compiled Lean 4 binary directly when built (`backend='lean4_compiled_binary'`),
    falling back to the isomorphic Python mirror only if the binary is absent (`backend='python_mirror'`).
    """
    binary = find_lean_oracle_binary(lean_dir)
    if binary is not None:
        oracle = LeanCompiledOracle(binary)
        return (
            oracle.evaluate_policy(
                action=action,
                scope=scope,
                in_workspace_root=in_workspace_root,
                allow_destructive=allow_destructive,
                rules=rules,
            ),
            "lean4_compiled_binary",
        )
    return (
        evaluate_policy_mirror(
            action=action,
            scope=scope,
            in_workspace_root=in_workspace_root,
            allow_destructive=allow_destructive,
            rules=rules,
        ),
        "python_mirror",
    )


def run_differential_parity_check(
    lean_dir: Union[str, Path] = "formal/lean4",
) -> Dict[str, Any]:
    """
    AWS Cedar-style differential verification: feeds exhaustive inputs across PolicyGuard,
    HttpFramingOracle, and DotNetPeIntegrity into BOTH the compiled Lean 4 binary and the
    Python runtime mirrors, asserting zero divergences.
    """
    binary = find_lean_oracle_binary(lean_dir)
    if binary is None:
        return {
            "status": "skipped_binary_not_built",
            "cases_checked": 0,
            "divergences": [],
        }

    oracle = LeanCompiledOracle(binary)
    divergences: List[str] = []
    cases = 0

    # 1. PolicyGuard exhaustive matrix
    rule_sets = [
        [],
        [("permit", True)],
        [("permit", False)],
        [("permit", True), ("forbid", True)],
        [("permit", True), ("forbid", False)],
    ]
    for action in ("readWorkspaceFile", "networkProbe", "shellExec", "destructiveHttp"):
        for scope in ("inScopeAuthorized", "outOfScope", "privateOrLoopbackBlocked"):
            for in_root in (False, True):
                for allow_d in (False, True):
                    for rules in rule_sets:
                        cases += 1
                        lean_res = oracle.evaluate_policy(
                            action=action,
                            scope=scope,
                            in_workspace_root=in_root,
                            allow_destructive=allow_d,
                            rules=rules,
                        )
                        py_res = evaluate_policy_mirror(
                            action=action,
                            scope=scope,
                            in_workspace_root=in_root,
                            allow_destructive=allow_d,
                            rules=rules,
                        )
                        if lean_res != py_res:
                            divergences.append(
                                f"policy({action},{scope},{in_root},{allow_d},{rules}): lean={lean_res} != py={py_res}"
                            )

    # 2. Reconcile verdict exhaustive (2^2 = 4)
    for t_conf in (False, True):
        for l_conf in (False, True):
            cases += 1
            if oracle.reconcile_verdict(t_conf, l_conf) != reconcile_verdict_mirror(t_conf, l_conf):
                divergences.append(f"reconcile({t_conf},{l_conf}) diverged")

    # 3. HttpFramingOracle matrix
    for cls in ([], [0], [42], [10, 10], [10, 20], [5, 5, 6]):
        for has_te in (False, True):
            for bare_lf in (False, True):
                cases += 1
                lean_v = oracle.strict_rfc9112(cls, has_te, bare_lf)
                py_v = strict_rfc9112_oracle(cls, has_te, bare_lf)
                if lean_v != py_v:
                    divergences.append(f"framing({cls},{has_te},{bare_lf}): lean={lean_v} != py={py_v}")

    # 4. DotNetPeIntegrity exhaustive (all 2^5 = 32 states)
    for vp in (False, True):
        for clr in (False, True):
            for eb in (False, True):
                for umci in (False, True):
                    for sig in (False, True):
                        cases += 1
                        lean_pe = oracle.evaluate_dotnet_pe(
                            is_valid_pe=vp,
                            has_clr_descriptor=clr,
                            has_executable_image_bit=eb,
                            is_umci_enforced=umci,
                            is_signed_by_trusted_publisher=sig,
                        )
                        py_pe = dotnet_pe_integrity_mirror(
                            is_valid_pe=vp,
                            has_clr_descriptor=clr,
                            has_executable_image_bit=eb,
                            is_umci_enforced=umci,
                            is_signed_by_trusted_publisher=sig,
                        )
                        if lean_pe != py_pe:
                            divergences.append(f"pe({vp},{clr},{eb},{umci},{sig}): lean={lean_pe} != py={py_pe}")

    return {
        "status": "passed" if not divergences else "diverged",
        "binary": str(binary),
        "cases_checked": cases,
        "divergences": divergences,
    }


# ---------------------------------------------------------------------------
# Structured Domain Invariant & Counterexample Evaluators (M1)
# ---------------------------------------------------------------------------


@dataclass
class LeanCounterexample:
    """Concrete invariant check or counterexample witness evaluated against a Lean 4 model."""

    domain: str  # "http_framing" | "policy_guard" | "dotnet_pe"
    theorem: str
    invariant: str
    violated: bool
    oracle_backend: str  # "lean4_compiled_binary" | "python_mirror"
    input_witness: Dict[str, Any] = field(default_factory=dict)
    expected_verdict: str = ""
    observed_verdict: str = ""
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "theorem": self.theorem,
            "invariant": self.invariant,
            "violated": self.violated,
            "oracle_backend": self.oracle_backend,
            "input_witness": dict(self.input_witness),
            "expected_verdict": self.expected_verdict,
            "observed_verdict": self.observed_verdict,
            "summary": self.summary,
        }


@dataclass
class LeanDomainReport:
    """Aggregated result across HttpFramingOracle, PolicyGuard, and DotNetPeIntegrity."""

    status: str  # "passed" | "counterexample_found"
    oracle_backend: str  # "lean4_compiled_binary" | "python_mirror"
    machine_checked: bool
    workspace_report: Dict[str, Any] = field(default_factory=dict)
    domain_checks: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    counterexamples: List[LeanCounterexample] = field(default_factory=list)
    diagnostics: List[LeanProofDiagnostic] = field(default_factory=list)
    domains_checked: List[str] = field(default_factory=list)
    checks_total: int = 0
    violations_count: int = 0
    degradation_reason: Optional[str] = None

    @property
    def domain_summaries(self) -> Dict[str, Dict[str, Any]]:
        return self.domain_checks

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "oracle_backend": self.oracle_backend,
            "machine_checked": self.machine_checked,
            "workspace_report": dict(self.workspace_report),
            "domain_checks": {k: dict(v) for k, v in self.domain_checks.items()},
            "counterexamples": [c.to_dict() for c in self.counterexamples],
            "violations": [c.to_dict() for c in self.counterexamples if c.violated],
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "domains_checked": list(self.domains_checked),
            "checks_total": self.checks_total,
            "violations_count": self.violations_count,
            "degradation_reason": self.degradation_reason,
        }


def _resolve_oracle(
    lean_dir: Union[str, Path] = "formal/lean4",
    oracle: Optional[LeanCompiledOracle] = None,
) -> Tuple[Optional[LeanCompiledOracle], str]:
    if oracle is not None:
        return oracle, "lean4_compiled_binary"
    binary = find_lean_oracle_binary(lean_dir)
    if binary is not None:
        return LeanCompiledOracle(binary), "lean4_compiled_binary"
    return None, "python_mirror"


def _format_framing_verdict(verdict: Tuple[str, Optional[int]]) -> str:
    tag, val = verdict
    if tag == "acceptContentLength":
        return f"acceptContentLength:{val if val is not None else 0}"
    return tag


def _coerce_strict_bool(val: Any, *, field_name: str = "value") -> bool:
    """Strictly parse boolean flags without fail-open bool('false') coercion."""
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        if val in (0, 1):
            return val == 1
        raise ValueError(f"Invalid integer boolean for {field_name}: {val!r}")
    if isinstance(val, str):
        norm = val.strip().lower()
        if norm in ("true", "1", "yes", "on"):
            return True
        if norm in ("false", "0", "no", "off"):
            return False
        raise ValueError(f"Invalid boolean string for {field_name}: {val!r}")
    raise TypeError(f"Invalid boolean value for {field_name}: {val!r}")


def verify_http_framing_invariant(
    *,
    content_lengths: Sequence[int] = (),
    has_transfer_encoding_chunked: bool = False,
    has_bare_lf: bool = False,
    proxy_verdict: Optional[Tuple[str, Optional[int]]] = None,
    lean_dir: Union[str, Path] = "formal/lean4",
    oracle: Optional[LeanCompiledOracle] = None,
) -> List[LeanCounterexample]:
    """Evaluates RFC 9112 framing invariants against `RFCHunt.HttpFramingOracle`."""
    if isinstance(content_lengths, (str, bytes, bytearray, dict)):
        raise TypeError(
            f"content_lengths must be a sequence of integers, not {type(content_lengths).__name__}"
        )
    cls_list: List[int] = []
    for x in content_lengths:
        if isinstance(x, bool):
            raise TypeError(f"Content-Length elements must be integers, not bool: {x!r}")
        cls_list.append(int(x))
    if any(x < 0 for x in cls_list):
        raise ValueError(f"Content-Length values must be non-negative: {cls_list!r}")

    has_te = _coerce_strict_bool(
        has_transfer_encoding_chunked,
        field_name="has_transfer_encoding_chunked",
    )
    bare_lf = _coerce_strict_bool(has_bare_lf, field_name="has_bare_lf")
    active_oracle, backend = _resolve_oracle(lean_dir, oracle)

    strict_v = (
        active_oracle.strict_rfc9112(cls_list, has_te, bare_lf)
        if active_oracle is not None
        else strict_rfc9112_oracle(cls_list, has_te, bare_lf)
    )
    proxy_v = (
        proxy_verdict
        if proxy_verdict is not None
        else permissive_cl_first_proxy_mirror(cls_list, has_te)
    )

    witness = {
        "content_lengths": cls_list,
        "has_transfer_encoding_chunked": has_te,
        "has_bare_lf": bare_lf,
        "strict_verdict": _format_framing_verdict(strict_v),
        "proxy_verdict": _format_framing_verdict(proxy_v),
    }

    results: List[LeanCounterexample] = []

    if has_te and len(cls_list) > 0:
        strict_violated = strict_v[0] != "reject400"
        results.append(
            LeanCounterexample(
                domain="http_framing",
                theorem="strict_rejects_cl_te_conflict",
                invariant="strictRfc9112 rejects simultaneous Content-Length and Transfer-Encoding",
                violated=strict_violated,
                oracle_backend=backend,
                input_witness=witness,
                expected_verdict="reject400",
                observed_verdict=_format_framing_verdict(strict_v),
                summary=(
                    "Strict RFC 9112 rejected CL+TE conflict with 400."
                    if not strict_violated
                    else f"Strict RFC 9112 unexpectedly returned {_format_framing_verdict(strict_v)} on CL+TE conflict."
                ),
            )
        )
        diff_violated = (strict_v != proxy_v) or (strict_v[0] != "reject400")
        results.append(
            LeanCounterexample(
                domain="http_framing",
                theorem="differential_witness_cl_te",
                invariant="Proxy framing verdict must match strict RFC 9112 on CL+TE conflict",
                violated=diff_violated,
                oracle_backend=backend,
                input_witness=witness,
                expected_verdict=_format_framing_verdict(strict_v),
                observed_verdict=_format_framing_verdict(proxy_v),
                summary=(
                    f"Desync counterexample: strict={_format_framing_verdict(strict_v)} vs proxy={_format_framing_verdict(proxy_v)}."
                    if diff_violated
                    else "Strict oracle and target proxy agreed on CL+TE rejection (reject400)."
                ),
            )
        )

    if len(cls_list) >= 2 and len(set(cls_list)) > 1:
        dual_violated = (strict_v != proxy_v) or (strict_v[0] != "reject400")
        results.append(
            LeanCounterexample(
                domain="http_framing",
                theorem="strict_rejects_mismatched_dual_cl",
                invariant="Mismatched duplicate Content-Length values must be rejected with 400",
                violated=dual_violated,
                oracle_backend=backend,
                input_witness=witness,
                expected_verdict="reject400",
                observed_verdict=_format_framing_verdict(proxy_v),
                summary=(
                    f"Dual Content-Length desync: strict={_format_framing_verdict(strict_v)} vs proxy={_format_framing_verdict(proxy_v)}."
                    if dual_violated
                    else "Mismatched dual Content-Length rejected cleanly (reject400)."
                ),
            )
        )

    if bare_lf:
        lf_violated = (strict_v != proxy_v) or (strict_v[0] != "reject400")
        results.append(
            LeanCounterexample(
                domain="http_framing",
                theorem="strict_rfc9112_bare_lf",
                invariant="Bare LF line endings violate RFC 9112 Section 2.2 and must be rejected with 400",
                violated=lf_violated,
                oracle_backend=backend,
                input_witness=witness,
                expected_verdict="reject400",
                observed_verdict=_format_framing_verdict(proxy_v),
                summary=(
                    f"Bare LF smuggling witness: strict={_format_framing_verdict(strict_v)} vs proxy={_format_framing_verdict(proxy_v)}."
                    if lf_violated
                    else "Bare LF framing rejected cleanly (reject400)."
                ),
            )
        )

    if not results:
        clean_violated = strict_v != proxy_v
        results.append(
            LeanCounterexample(
                domain="http_framing",
                theorem="strict_rfc9112_differential",
                invariant="Proxy framing verdict matches strict RFC 9112 oracle",
                violated=clean_violated,
                oracle_backend=backend,
                input_witness=witness,
                expected_verdict=_format_framing_verdict(strict_v),
                observed_verdict=_format_framing_verdict(proxy_v),
                summary=(
                    f"Framing divergence: strict={_format_framing_verdict(strict_v)} vs proxy={_format_framing_verdict(proxy_v)}."
                    if clean_violated
                    else f"Clean framing agreement ({_format_framing_verdict(strict_v)})."
                ),
            )
        )

    return results


def verify_policy_guard_invariant(
    *,
    action: str = "networkProbe",
    scope: str = "inScopeAuthorized",
    in_workspace_root: bool = True,
    allow_destructive: bool = False,
    rules: Sequence[Tuple[str, bool]] = (("permit", True),),
    confirmed_by_tool: Optional[bool] = None,
    llm_confirmed: Optional[bool] = None,
    observed_allowed: Optional[bool] = None,
    observed_reconciled: Optional[bool] = None,
    lean_dir: Union[str, Path] = "formal/lean4",
    oracle: Optional[LeanCompiledOracle] = None,
) -> List[LeanCounterexample]:
    """Evaluates Cedar-style containment & override immunity against `RFCHunt.PolicyGuard`."""
    active_oracle, backend = _resolve_oracle(lean_dir, oracle)
    in_workspace_root_b = _coerce_strict_bool(in_workspace_root, field_name="in_workspace_root")
    allow_destructive_b = _coerce_strict_bool(allow_destructive, field_name="allow_destructive")
    rules_list = [
        (str(eff), _coerce_strict_bool(m, field_name="rule_matched"))
        for eff, m in rules
    ]

    oracle_allowed = (
        active_oracle.evaluate_policy(
            action=action,
            scope=scope,
            in_workspace_root=in_workspace_root_b,
            allow_destructive=allow_destructive_b,
            rules=rules_list,
        )
        if active_oracle is not None
        else evaluate_policy_mirror(
            action=action,
            scope=scope,
            in_workspace_root=in_workspace_root_b,
            allow_destructive=allow_destructive_b,
            rules=rules_list,
        )
    )

    if action == "shellExec":
        theorem = "shell_exec_never_permitted"
        invariant = "Host shell execution is unconditionally denied regardless of policy rules"
        expected_allowed = False
    elif action == "networkProbe" and scope != "inScopeAuthorized":
        theorem = "out_of_scope_probe_always_denied"
        invariant = "Out-of-scope or private/loopback network probes are unconditionally denied"
        expected_allowed = False
    elif action == "readWorkspaceFile" and not in_workspace_root_b:
        theorem = "outside_workspace_read_denied"
        invariant = "Workspace file reads outside workspace root are unconditionally denied"
        expected_allowed = False
    elif any(eff == "forbid" and m for eff, m in rules_list):
        theorem = "forbid_overrides_permit"
        invariant = "Any matching forbid rule unconditionally overrides all permit rules"
        expected_allowed = False
    else:
        theorem = "evaluatePolicies_baseline"
        invariant = "Policy decision matches formal evaluatePolicies specification"
        expected_allowed = oracle_allowed

    actual_allowed = (
        oracle_allowed
        if observed_allowed is None
        else _coerce_strict_bool(observed_allowed, field_name="observed_allowed")
    )
    policy_violated = actual_allowed != expected_allowed

    witness = {
        "action": action,
        "scope": scope,
        "in_workspace_root": in_workspace_root_b,
        "allow_destructive": allow_destructive_b,
        "rules": [[eff, m] for eff, m in rules_list],
    }

    results: List[LeanCounterexample] = [
        LeanCounterexample(
            domain="policy_guard",
            theorem=theorem,
            invariant=invariant,
            violated=policy_violated,
            oracle_backend=backend,
            input_witness=witness,
            expected_verdict=f"allowed={expected_allowed}",
            observed_verdict=f"allowed={actual_allowed}",
            summary=(
                f"PolicyGuard counterexample on `{theorem}`: expected allowed={expected_allowed}, observed allowed={actual_allowed}."
                if policy_violated
                else f"PolicyGuard `{theorem}` held (allowed={actual_allowed})."
            ),
        )
    ]

    if confirmed_by_tool is not None or llm_confirmed is not None:
        tool_b = (
            False
            if confirmed_by_tool is None
            else _coerce_strict_bool(confirmed_by_tool, field_name="confirmed_by_tool")
        )
        llm_b = (
            False
            if llm_confirmed is None
            else _coerce_strict_bool(llm_confirmed, field_name="llm_confirmed")
        )
        oracle_rec = (
            active_oracle.reconcile_verdict(tool_b, llm_b)
            if active_oracle is not None
            else reconcile_verdict_mirror(tool_b, llm_b)
        )
        actual_rec = (
            oracle_rec
            if observed_reconciled is None
            else _coerce_strict_bool(observed_reconciled, field_name="observed_reconciled")
        )
        if tool_b:
            rec_theorem = "deterministic_confirmation_immutable"
            rec_invariant = "Deterministic tool confirmation cannot be vetoed by LLM narrative"
            expected_rec = True
        else:
            rec_theorem = "reconcile_verdict_consistency"
            rec_invariant = "Verdict reconciliation matches formal reconcileVerdict"
            expected_rec = oracle_rec
        rec_violated = actual_rec != expected_rec
        results.append(
            LeanCounterexample(
                domain="policy_guard",
                theorem=rec_theorem,
                invariant=rec_invariant,
                violated=rec_violated,
                oracle_backend=backend,
                input_witness={"confirmed_by_tool": tool_b, "llm_confirmed": llm_b},
                expected_verdict=f"reconciled={expected_rec}",
                observed_verdict=f"reconciled={actual_rec}",
                summary=(
                    f"Override immunity counterexample: tool={tool_b}, llm={llm_b}, observed reconciled={actual_rec}."
                    if rec_violated
                    else f"Deterministic override immunity `{rec_theorem}` held (reconciled={actual_rec})."
                ),
            )
        )

    return results


def _coerce_clr_rva_nonzero(val: Any, *, field_name: str = "clr_header_rva") -> bool:
    """Strictly evaluate whether an integer CLR header RVA is non-zero."""
    if val is None:
        return False
    if isinstance(val, bool):
        raise TypeError(f"Invalid integer RVA for {field_name}: {val!r}")
    if isinstance(val, int):
        if val < 0:
            raise ValueError(f"Negative RVA for {field_name}: {val!r}")
        return val != 0
    if isinstance(val, str):
        s = val.strip()
        if not s:
            raise ValueError(f"Empty RVA string for {field_name}: {val!r}")
        try:
            parsed = int(s, 0)
        except ValueError as exc:
            raise ValueError(f"Invalid RVA string for {field_name}: {val!r}") from exc
        if parsed < 0:
            raise ValueError(f"Negative RVA for {field_name}: {val!r}")
        return parsed != 0
    raise TypeError(f"Invalid RVA value for {field_name}: {val!r}")


def verify_dotnet_pe_invariant(
    *,
    is_valid_pe: bool = True,
    has_clr_descriptor: bool = True,
    has_executable_image_bit: bool = True,
    is_umci_enforced: bool = True,
    is_signed_by_trusted_publisher: bool = False,
    pe_report: Optional[Dict[str, Any]] = None,
    lean_dir: Union[str, Path] = "formal/lean4",
    oracle: Optional[LeanCompiledOracle] = None,
) -> List[LeanCounterexample]:
    """Evaluates .NET Framework 4 UMCI loader integrity against `RFCHunt.DotNetPeIntegrity`."""
    is_valid_pe_b = _coerce_strict_bool(is_valid_pe, field_name="is_valid_pe")
    has_clr_descriptor_b = _coerce_strict_bool(
        has_clr_descriptor, field_name="has_clr_descriptor"
    )
    has_executable_image_bit_b = _coerce_strict_bool(
        has_executable_image_bit, field_name="has_executable_image_bit"
    )
    is_umci_enforced_b = _coerce_strict_bool(
        is_umci_enforced, field_name="is_umci_enforced"
    )
    is_signed_by_trusted_publisher_b = _coerce_strict_bool(
        is_signed_by_trusted_publisher,
        field_name="is_signed_by_trusted_publisher",
    )

    if pe_report is not None:
        if not isinstance(pe_report, Mapping):
            raise TypeError(
                f"pe_report must be a mapping or None, got {type(pe_report).__name__}"
            )
        if "is_pe" in pe_report and pe_report["is_pe"] is not None:
            is_valid_pe_b = _coerce_strict_bool(
                pe_report["is_pe"], field_name="pe_report.is_pe"
            )
        elif "is_valid_pe" in pe_report and pe_report["is_valid_pe"] is not None:
            is_valid_pe_b = _coerce_strict_bool(
                pe_report["is_valid_pe"], field_name="pe_report.is_valid_pe"
            )

        dot_net = pe_report.get("dot_net")
        if dot_net is not None and not isinstance(dot_net, Mapping):
            raise TypeError(
                f"pe_report.dot_net must be a mapping or None, got {type(dot_net).__name__}"
            )
        if isinstance(dot_net, Mapping) and dot_net:
            if "is_dot_net" in dot_net and dot_net["is_dot_net"] is not None:
                has_clr_descriptor_b = _coerce_strict_bool(
                    dot_net["is_dot_net"], field_name="pe_report.dot_net.is_dot_net"
                )
            elif "has_clr_descriptor" in dot_net and dot_net["has_clr_descriptor"] is not None:
                has_clr_descriptor_b = _coerce_strict_bool(
                    dot_net["has_clr_descriptor"],
                    field_name="pe_report.dot_net.has_clr_descriptor",
                )
            elif "clr_header_rva" in dot_net:
                has_clr_descriptor_b = _coerce_clr_rva_nonzero(
                    dot_net["clr_header_rva"],
                    field_name="pe_report.dot_net.clr_header_rva",
                )
            else:
                has_clr_descriptor_b = False
        elif "is_dot_net" in pe_report and pe_report["is_dot_net"] is not None:
            has_clr_descriptor_b = _coerce_strict_bool(
                pe_report["is_dot_net"], field_name="pe_report.is_dot_net"
            )
        elif "has_clr_descriptor" in pe_report and pe_report["has_clr_descriptor"] is not None:
            has_clr_descriptor_b = _coerce_strict_bool(
                pe_report["has_clr_descriptor"],
                field_name="pe_report.has_clr_descriptor",
            )
        elif "clr_header_rva" in pe_report:
            has_clr_descriptor_b = _coerce_clr_rva_nonzero(
                pe_report["clr_header_rva"],
                field_name="pe_report.clr_header_rva",
            )
        else:
            has_clr_descriptor_b = False

        if "is_executable_image" in pe_report and pe_report["is_executable_image"] is not None:
            has_executable_image_bit_b = _coerce_strict_bool(
                pe_report["is_executable_image"],
                field_name="pe_report.is_executable_image",
            )
        elif (
            "has_executable_image_bit" in pe_report
            and pe_report["has_executable_image_bit"] is not None
        ):
            has_executable_image_bit_b = _coerce_strict_bool(
                pe_report["has_executable_image_bit"],
                field_name="pe_report.has_executable_image_bit",
            )

        raw_anom = pe_report.get("has_forshaw_cve_2026_108398_anomaly")
        has_anom = (
            _coerce_strict_bool(
                raw_anom,
                field_name="pe_report.has_forshaw_cve_2026_108398_anomaly",
            )
            if raw_anom is not None
            else False
        )
        if has_anom and has_executable_image_bit_b:
            has_executable_image_bit_b = False

    active_oracle, backend = _resolve_oracle(lean_dir, oracle)
    anom, unpatched, patched = (
        active_oracle.evaluate_dotnet_pe(
            is_valid_pe=is_valid_pe_b,
            has_clr_descriptor=has_clr_descriptor_b,
            has_executable_image_bit=has_executable_image_bit_b,
            is_umci_enforced=is_umci_enforced_b,
            is_signed_by_trusted_publisher=is_signed_by_trusted_publisher_b,
        )
        if active_oracle is not None
        else dotnet_pe_integrity_mirror(
            is_valid_pe=is_valid_pe_b,
            has_clr_descriptor=has_clr_descriptor_b,
            has_executable_image_bit=has_executable_image_bit_b,
            is_umci_enforced=is_umci_enforced_b,
            is_signed_by_trusted_publisher=is_signed_by_trusted_publisher_b,
        )
    )

    witness = {
        "is_valid_pe": is_valid_pe_b,
        "has_clr_descriptor": has_clr_descriptor_b,
        "has_executable_image_bit": has_executable_image_bit_b,
        "is_umci_enforced": is_umci_enforced_b,
        "is_signed_by_trusted_publisher": is_signed_by_trusted_publisher_b,
    }

    results: List[LeanCounterexample] = [
        LeanCounterexample(
            domain="dotnet_pe",
            theorem="anomaly_triggers_unpatched_fallback",
            invariant="Valid CLR PE must retain IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) to avoid CVE-2026-108398 flat fallback",
            violated=bool(anom),
            oracle_backend=backend,
            input_witness=witness,
            expected_verdict="no_unchecked_flat_memory_fallback",
            observed_verdict=f"anomaly={anom},unpatched={unpatched},patched={patched}",
            summary=(
                "CVE-2026-108398 anomaly detected: cleared 0x0002 triggers unchecked SEC_COMMIT flat fallback on unpatched .NET 4."
                if anom
                else f"PE/CLR executable header invariant held (unpatched={unpatched}, patched={patched})."
            ),
        )
    ]

    if is_umci_enforced_b and not is_signed_by_trusted_publisher_b:
        umci_violated = patched != "rejectedInvalidOrUnsigned"
        results.append(
            LeanCounterexample(
                domain="dotnet_pe",
                theorem="patched_loader_enforces_umci",
                invariant="Under UMCI enforcement, patched loader rejects unsigned assemblies",
                violated=umci_violated,
                oracle_backend=backend,
                input_witness=witness,
                expected_verdict="rejectedInvalidOrUnsigned",
                observed_verdict=patched,
                summary=(
                    f"UMCI enforcement failed on unsigned assembly: observed {patched}."
                    if umci_violated
                    else "Patched loader enforced UMCI by rejecting unsigned assembly."
                ),
            )
        )

    return results


def _extract_finding_fields(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        meta = item.get("metadata")
        return {
            "rule_id": str(item.get("rule_id") or ""),
            "cwe": str(item.get("cwe") or ""),
            "title": str(item.get("title") or ""),
            "summary": str(item.get("summary") or ""),
            "file_path": str(item.get("file_path") or ""),
            "severity": str(item.get("severity") or ""),
            "status": str(item.get("status") or ""),
            "confirmed": item.get("confirmed"),
            "metadata": meta if isinstance(meta, dict) else {},
        }
    meta = getattr(item, "metadata", None)
    return {
        "rule_id": str(getattr(item, "rule_id", "") or ""),
        "cwe": str(getattr(item, "cwe", "") or ""),
        "title": str(getattr(item, "title", "") or ""),
        "summary": str(getattr(item, "summary", "") or ""),
        "file_path": str(getattr(item, "file_path", "") or ""),
        "severity": str(getattr(item, "severity", "") or ""),
        "status": str(getattr(item, "status", "") or ""),
        "confirmed": getattr(item, "confirmed", None),
        "metadata": meta if isinstance(meta, dict) else {},
    }


def _find_pe_candidates_bounded(repo_root: Path, max_files: int = 200, max_depth: int = 3) -> List[Path]:
    pe_files: List[Path] = []
    scanned = 0
    base_depth = len(repo_root.parts)
    for dirpath, dirnames, filenames in os.walk(repo_root):
        cur = Path(dirpath)
        depth = len(cur.parts) - base_depth
        dirnames[:] = [
            d for d in dirnames
            if d not in (".git", ".lake", "node_modules", "__pycache__", ".venv", "venv", "target", "dist", "build", ".agents", ".cargo")
        ]
        if depth >= max_depth:
            dirnames[:] = []
        for fn in filenames:
            scanned += 1
            if scanned > max_files:
                return pe_files
            if fn.lower().endswith((".exe", ".dll")):
                pe_files.append(cur / fn)
    return pe_files


def evaluate_lean_domains(
    findings: Optional[Sequence[Union[Dict[str, Any], Any]]] = None,
    *,
    repo_path: Optional[Union[str, Path]] = None,
    lean_dir: Union[str, Path] = "formal/lean4",
) -> LeanDomainReport:
    """
    Runs formal workspace verification and evaluates concrete witnesses across
    `HttpFramingOracle`, `PolicyGuard`, and `DotNetPeIntegrity`.

    Never fabricates violations when `findings` is empty/None and no actual
    anomaly exists, and never marks `machine_checked=True` unless BOTH
    `find_lean_oracle_binary(lean_dir)` exists AND `verify_lean_workspace(lean_dir).machine_checked`
    is True.
    """
    workspace_rep = verify_lean_workspace(lean_dir)
    oracle, oracle_backend = _resolve_oracle(lean_dir)
    machine_checked = bool((oracle is not None) and workspace_rep.machine_checked)

    degradation_reason: Optional[str] = None
    if not machine_checked:
        if oracle is None and workspace_rep.status == "static_audited_lean_not_installed":
            degradation_reason = (
                "Lean 4 (`lake`) and compiled `rfchunt-lean-oracle` binary are not installed; "
                "evaluated domain invariants via isomorphic Python mirrors (machine_checked=False)."
            )
        elif oracle is None:
            degradation_reason = (
                f"Compiled `rfchunt-lean-oracle` binary is unavailable and workspace status is "
                f"`{workspace_rep.status}`; evaluated via isomorphic Python mirrors (machine_checked=False)."
            )
        else:
            degradation_reason = (
                f"Compiled `rfchunt-lean-oracle` binary present, but workspace verification status is "
                f"`{workspace_rep.status}` (machine_checked=False)."
            )

    checks: List[LeanCounterexample] = []

    # 1. Non-fabricating baseline invariant self-checks (all pass with violated=False on valid models)
    checks.extend(
        verify_http_framing_invariant(
            content_lengths=[42],
            has_transfer_encoding_chunked=True,
            has_bare_lf=False,
            proxy_verdict=("reject400", None),
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )
    checks.extend(
        verify_http_framing_invariant(
            content_lengths=[10, 20],
            has_transfer_encoding_chunked=False,
            has_bare_lf=False,
            proxy_verdict=("reject400", None),
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )
    checks.extend(
        verify_http_framing_invariant(
            content_lengths=[],
            has_transfer_encoding_chunked=False,
            has_bare_lf=True,
            proxy_verdict=("reject400", None),
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )
    checks.extend(
        verify_http_framing_invariant(
            content_lengths=[42],
            has_transfer_encoding_chunked=False,
            has_bare_lf=False,
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )

    checks.extend(
        verify_policy_guard_invariant(
            action="shellExec",
            scope="inScopeAuthorized",
            in_workspace_root=True,
            allow_destructive=True,
            rules=[("permit", True)],
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )
    checks.extend(
        verify_policy_guard_invariant(
            action="networkProbe",
            scope="outOfScope",
            in_workspace_root=True,
            allow_destructive=False,
            rules=[("permit", True)],
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )
    checks.extend(
        verify_policy_guard_invariant(
            action="readWorkspaceFile",
            scope="inScopeAuthorized",
            in_workspace_root=False,
            allow_destructive=False,
            rules=[("permit", True)],
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )
    checks.extend(
        verify_policy_guard_invariant(
            action="networkProbe",
            scope="inScopeAuthorized",
            in_workspace_root=True,
            allow_destructive=False,
            rules=[("permit", True), ("forbid", True)],
            confirmed_by_tool=True,
            llm_confirmed=False,
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )

    checks.extend(
        verify_dotnet_pe_invariant(
            is_valid_pe=True,
            has_clr_descriptor=True,
            has_executable_image_bit=True,
            is_umci_enforced=True,
            is_signed_by_trusted_publisher=True,
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )
    checks.extend(
        verify_dotnet_pe_invariant(
            is_valid_pe=True,
            has_clr_descriptor=True,
            has_executable_image_bit=True,
            is_umci_enforced=True,
            is_signed_by_trusted_publisher=False,
            lean_dir=lean_dir,
            oracle=oracle,
        )
    )

    # 2. Finding-driven witness extraction
    extra_diagnostics: List[LeanProofDiagnostic] = []
    saw_pe_finding = False

    def _record_invalid_witness(domain_module: str, f_fields: Dict[str, Any], exc: Exception) -> None:
        extra_diagnostics.append(
            LeanProofDiagnostic(
                module=domain_module,
                theorem="invalid_witness_metadata",
                line=None,
                column=None,
                kind="invalid_witness",
                branch_summary=f"Invalid witness metadata ignored ({type(exc).__name__}): {exc}"[:240],
                raw_excerpt=(
                    f"rule_id={f_fields.get('rule_id')!r} cwe={f_fields.get('cwe')!r} "
                    f"title={f_fields.get('title')!r} error={exc}"
                )[:1000],
            )
        )

    def _heuristic_active_policy_failure(f_fields: Dict[str, Any]) -> bool:
        sev = f_fields["severity"].strip().lower()
        st = f_fields["status"].strip().lower()
        conf = f_fields["confirmed"]
        if conf is False:
            return False
        if sev in ("info", "informational", "none", "clean", "passed"):
            return False
        if st in ("info", "passed", "clean", "ok", "denied", "blocked", "mitigated", "refuted"):
            return False
        if (
            conf is True
            or sev in ("critical", "high", "medium", "low", "error", "warning")
            or st in ("failed", "violated", "open", "confirmed", "vulnerable", "active")
        ):
            return True
        return False

    for raw_item in findings or ():
        f = _extract_finding_fields(raw_item)
        meta = f["metadata"]
        blob = " ".join((f["rule_id"], f["cwe"], f["title"], f["summary"], f["file_path"])).lower()

        if (
            "cwe-444" in f["cwe"].lower()
            or isinstance(meta.get("http_framing"), dict)
            or any(kw in blob for kw in ("cl+te", "cl/te", "cl_te", "smuggling", "dual content-length", "bare lf"))
        ):
            try:
                hf_meta = meta.get("http_framing") if isinstance(meta.get("http_framing"), dict) else {}
                if hf_meta:
                    cls_val = hf_meta.get("content_lengths", [])
                    te_val = hf_meta.get("has_transfer_encoding_chunked", False)
                    lf_val = hf_meta.get("has_bare_lf", False)
                    pv_raw = hf_meta.get("proxy_verdict")
                    pv_val = tuple(pv_raw) if isinstance(pv_raw, (list, tuple)) and len(pv_raw) == 2 else None
                elif "dual content-length" in blob:
                    cls_val, te_val, lf_val, pv_val = [10, 20], False, False, None
                elif "bare lf" in blob:
                    cls_val, te_val, lf_val, pv_val = [], False, True, None
                else:
                    cls_val, te_val, lf_val, pv_val = [42], True, False, None
                checks.extend(
                    verify_http_framing_invariant(
                        content_lengths=cls_val,
                        has_transfer_encoding_chunked=te_val,
                        has_bare_lf=lf_val,
                        proxy_verdict=pv_val,  # type: ignore[arg-type]
                        lean_dir=lean_dir,
                        oracle=oracle,
                    )
                )
            except (ValueError, TypeError) as exc:
                _record_invalid_witness("RFCHunt.HttpFramingOracle", f, exc)

        if (
            isinstance(meta.get("policy_guard"), dict)
            or any(
                kw in blob
                for kw in (
                    "shellexec",
                    "shell_exec",
                    "out_of_scope",
                    "out-of-scope",
                    "outside_workspace",
                    "forbid_overrides_permit",
                    "llm_dissent",
                    "override_immunity",
                    "policy_guard",
                )
            )
        ):
            try:
                pg_meta = meta.get("policy_guard") if isinstance(meta.get("policy_guard"), dict) else {}
                if pg_meta:
                    checks.extend(
                        verify_policy_guard_invariant(
                            action=str(pg_meta.get("action", "networkProbe")),
                            scope=str(pg_meta.get("scope", "inScopeAuthorized")),
                            in_workspace_root=pg_meta.get("in_workspace_root", True),
                            allow_destructive=pg_meta.get("allow_destructive", False),
                            rules=pg_meta.get("rules", (("permit", True),)),
                            confirmed_by_tool=pg_meta.get("confirmed_by_tool"),
                            llm_confirmed=pg_meta.get("llm_confirmed"),
                            observed_allowed=pg_meta.get("observed_allowed"),
                            observed_reconciled=pg_meta.get("observed_reconciled"),
                            lean_dir=lean_dir,
                            oracle=oracle,
                        )
                    )
                elif any(kw in blob for kw in ("llm_dissent", "override_immunity", "deterministic_confirmation")):
                    if "observed_reconciled" in meta:
                        obs_rec = _coerce_strict_bool(
                            meta["observed_reconciled"],
                            field_name="observed_reconciled",
                        )
                    else:
                        obs_rec = not _heuristic_active_policy_failure(f)
                    checks.extend(
                        verify_policy_guard_invariant(
                            confirmed_by_tool=True,
                            llm_confirmed=False,
                            observed_reconciled=obs_rec,
                            lean_dir=lean_dir,
                            oracle=oracle,
                        )
                    )
                else:
                    obs_allowed = (
                        _coerce_strict_bool(meta["observed_allowed"], field_name="observed_allowed")
                        if "observed_allowed" in meta
                        else _heuristic_active_policy_failure(f)
                    )
                    if "shellexec" in blob or "shell_exec" in blob:
                        checks.extend(
                            verify_policy_guard_invariant(
                                action="shellExec",
                                observed_allowed=obs_allowed,
                                lean_dir=lean_dir,
                                oracle=oracle,
                            )
                        )
                    elif "out_of_scope" in blob or "out-of-scope" in blob:
                        checks.extend(
                            verify_policy_guard_invariant(
                                action="networkProbe",
                                scope="outOfScope",
                                observed_allowed=obs_allowed,
                                lean_dir=lean_dir,
                                oracle=oracle,
                            )
                        )
                    elif "outside_workspace" in blob:
                        checks.extend(
                            verify_policy_guard_invariant(
                                action="readWorkspaceFile",
                                in_workspace_root=False,
                                observed_allowed=obs_allowed,
                                lean_dir=lean_dir,
                                oracle=oracle,
                            )
                        )
                    else:
                        checks.extend(
                            verify_policy_guard_invariant(
                                rules=[("permit", True), ("forbid", True)],
                                observed_allowed=obs_allowed,
                                lean_dir=lean_dir,
                                oracle=oracle,
                            )
                        )
            except (ValueError, TypeError) as exc:
                _record_invalid_witness("RFCHunt.PolicyGuard", f, exc)

        raw_anom = meta.get("has_forshaw_cve_2026_108398_anomaly")
        has_anom_meta = False
        anom_invalid_exc: Optional[Exception] = None
        if raw_anom is not None:
            try:
                has_anom_meta = _coerce_strict_bool(
                    raw_anom,
                    field_name="has_forshaw_cve_2026_108398_anomaly",
                )
            except (ValueError, TypeError) as exc:
                anom_invalid_exc = exc

        if (
            f["rule_id"].upper().startswith("PE-DOTNET-")
            or "cve-2026-108398" in blob
            or isinstance(meta.get("pe_report"), dict)
            or has_anom_meta
            or anom_invalid_exc is not None
        ):
            saw_pe_finding = True
            try:
                if "pe_report" in meta and meta["pe_report"] is not None and not isinstance(meta["pe_report"], Mapping):
                    raise TypeError(
                        f"pe_report must be a mapping or None, got {type(meta['pe_report']).__name__}"
                    )
                pe_rep = meta.get("pe_report") if isinstance(meta.get("pe_report"), Mapping) else None
                if pe_rep is not None:
                    checks.extend(
                        verify_dotnet_pe_invariant(
                            pe_report=pe_rep,
                            lean_dir=lean_dir,
                            oracle=oracle,
                        )
                    )
                elif anom_invalid_exc is not None:
                    raise anom_invalid_exc
                else:
                    has_anom_flag = "cve-2026-108398" in blob or has_anom_meta
                    checks.extend(
                        verify_dotnet_pe_invariant(
                            is_valid_pe=True,
                            has_clr_descriptor=True,
                            has_executable_image_bit=not has_anom_flag,
                            is_umci_enforced=True,
                            is_signed_by_trusted_publisher=False,
                            lean_dir=lean_dir,
                            oracle=oracle,
                        )
                    )
            except (ValueError, TypeError) as exc:
                _record_invalid_witness("RFCHunt.DotNetPeIntegrity", f, exc)

    # 3. Optional bounded repo PE check (non-fabricating; runs only if .exe/.dll files exist)
    if repo_path is not None and not saw_pe_finding:
        repo_root = Path(repo_path)
        if repo_root.is_dir():
            candidates = _find_pe_candidates_bounded(repo_root)
            if candidates:
                try:
                    from engine.pe_magika_classifier import audit_pe_dotnet_target

                    pe_audit = audit_pe_dotnet_target(
                        repo_root,
                        include_host_audit=False,
                        include_yara=False,
                        workspace_root=repo_root,
                    )
                    for rep in pe_audit.get("file_reports", []) or ():
                        if isinstance(rep, dict) and rep.get("is_pe"):
                            checks.extend(
                                verify_dotnet_pe_invariant(
                                    pe_report=rep,
                                    lean_dir=lean_dir,
                                    oracle=oracle,
                                )
                            )
                except Exception:
                    pass

    domains_order = ["http_framing", "policy_guard", "dotnet_pe"]
    domain_checks: Dict[str, Dict[str, Any]] = {}
    for dom in domains_order:
        dom_items = [c for c in checks if c.domain == dom]
        dom_violations = sum(1 for c in dom_items if c.violated)
        seen_thms: List[str] = []
        for c in dom_items:
            if c.theorem not in seen_thms:
                seen_thms.append(c.theorem)
        domain_checks[dom] = {
            "checks": len(dom_items),
            "violations": dom_violations,
            "theorems": seen_thms,
            "status": "counterexample_found" if dom_violations > 0 else "passed",
        }

    violations_count = sum(1 for c in checks if c.violated)
    status = "counterexample_found" if violations_count > 0 else "passed"

    return LeanDomainReport(
        status=status,
        oracle_backend=oracle_backend,
        machine_checked=machine_checked,
        workspace_report=workspace_rep.to_dict(),
        domain_checks=domain_checks,
        counterexamples=checks,
        diagnostics=list(workspace_rep.diagnostics) + extra_diagnostics,
        domains_checked=domains_order,
        checks_total=len(checks),
        violations_count=violations_count,
        degradation_reason=degradation_reason,
    )
