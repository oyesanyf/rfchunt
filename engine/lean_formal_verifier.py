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

from dataclasses import dataclass, field
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from engine.host_containment import silent_subprocess_run


_THEOREM_RE = re.compile(r"^\s*theorem\s+([A-Za-z0-9_']+)", re.MULTILINE)
_SORRY_RE = re.compile(r"\bsorry\b")
_AXIOM_RE = re.compile(r"^\s*axiom\s+", re.MULTILINE)


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
        }


def _strip_lean_comments(source: str) -> str:
    no_block = re.sub(r"/-.*?-/", "", source, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", "", no_block)


def audit_lean_file(path: Union[str, Path]) -> LeanModuleAudit:
    """Inspects a `.lean` file for declared theorems, `sorry` placeholders, and custom axioms."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    code = _strip_lean_comments(raw)
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
            return LeanVerificationReport(
                lean_dir=str(root),
                lean_binary=lean_bin,
                lake_binary=lake_bin,
                machine_checked=ok,
                status="machine_checked" if ok else "kernel_failed",
                modules=modules,
                total_theorems=total_theorems,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                elapsed_ms=(time.monotonic() - t0) * 1000.0,
            )
        except subprocess.TimeoutExpired:
            return LeanVerificationReport(
                lean_dir=str(root),
                lean_binary=lean_bin,
                lake_binary=lake_bin,
                machine_checked=False,
                status="kernel_failed",
                modules=modules,
                total_theorems=total_theorems,
                stderr=f"lake build timed out after {timeout_sec}s",
                elapsed_ms=(time.monotonic() - t0) * 1000.0,
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
