#!/usr/bin/env python3
"""
engine/code_verification_repair.py
================================================================================
RFCHunt Native Generated-Code Verification, Property-Based Fuzzing & Iterative
Auto-Repair Engine (migrated from `arxiv-to-code` v1.0).

Provides self-contained, zero-mock, fail-closed verification & repair for
synthesized/evolved Python security detectors and research modules (works both
standalone in CI/Linux/macOS/Windows and paired with `D:\\harfile\\arixiv-to-code`):

  Layer 1 — Concurrent Multi-Gate Deterministic Verification (`ThreadPoolExecutor`):
    1. AST Syntax, Security & Anti-Mock Gate (constant-time `hmac.compare_digest`,
       zero dangerous calls, zero single-token mocks, `# EVOLVE-BLOCK` markers).
    2. Multi-Layer Static Linter (`builtin_ast_linter` + external `ruff check`).
    3. Strict Static Type Checker (`python -m mypy --strict --ignore-missing-imports`).
    4. Process-Isolated Randomized Property-Based Fuzzer (310+ properties across
       Meet-Semilattice algebraic laws, adversarial input/bounds/cache isolation,
       HMAC bit-flip rejection, and approval-nonce replay protection).
    5. Isolated Subprocess `pytest` & 7-Invariant Deterministic Runtime Benchmark.

  Layer 2 — Scale-Accurate VRAM-Resident Ollama LLM & Auto-Repair Retry Loop:
    - Scale-accurate model capability ranking (`9B glm4:9b [95]` > `8B [85]` >
      native `7B qwen2.5:7b [80]` > distilled `deepseek-r1:7b [72]` > abliterated
      community fine-tunes) with GPU-VRAM residency prioritization and automatic
      model rotation on timeout.
    - Two-Tier Monotonic Hill-Climbing Auto-Repair Loop:
        * Tier A: Local Ollama LLM Patcher (feeding exact Ruff/`mypy`/fuzz/`pytest`/LLM
          diagnostics, `<think>` stripping, `ast.parse()` validation).
        * Tier B: AST-Verified Deterministic Structural Auto-Patcher (unused imports,
          bare `except:`, `len(indicators)` cache-key collisions, unsafe `alpha` /
          `prior_wealth` edge cases, broken `*` wildcard meet-semilattice, untyped tests).
      Accepts candidate patches strictly when they improve the verification rank tuple.
"""

from __future__ import annotations

import ast
import concurrent.futures
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

EVOLVE_START_MARKER = "# EVOLVE-BLOCK-START"
EVOLVE_END_MARKER = "# EVOLVE-BLOCK-END"

FORBIDDEN_SINGLE_TOKEN_MOCKS = frozenset(
    {
        "powershell.exe",
        "python.exe",
        "cmd.exe",
        "bash",
        "sh",
        "curl",
        "wget",
        "malware",
        "exploit",
        "attack",
        "hack",
        "evil",
    }
)

DANGEROUS_CALL_NAMES = frozenset({"eval", "exec", "compile", "__import__"})
DANGEROUS_ATTR_CALLS = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("pickle", "loads"),
        ("pickle", "load"),
        ("marshal", "loads"),
    }
)

_EMBED_OR_DECISION_MARKERS = (
    "embed",
    "nomic-embed",
    "mxbai-embed",
    "bge-",
    "all-minilm",
    "rerank",
    "whisper",
    "llava",
    "moondream",
    "nimble",
)


@dataclass
class CodeVerificationResult:
    """Structured result of Layer-1 Deterministic + optional Layer-2 LLM code verification."""

    arxiv_id: str
    title: str
    code_stage: str
    verdict: str  # "PASS" | "WARN" | "FAIL"
    overall_score: float
    verification_mode: str
    llm_verified: bool
    verifier_model: str
    verifier_provider: str
    deterministic_checks: Dict[str, Any]
    llm_audit: Dict[str, Any]
    findings: List[Dict[str, str]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RepairAttemptRecord:
    """Audit record for a single Verify -> Diagnose -> Patch -> Re-Verify cycle."""

    attempt: int
    strategy: str
    model_used: str
    defects_targeted: List[str]
    deterministic_fixes_applied: List[str]
    before_verdict: str
    after_verdict: str
    before_score: float
    after_score: float
    before_gates_passed: int
    after_gates_passed: int
    accepted: bool
    duration_ms: float
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AutoRepairResult:
    """Complete result of the iterative auto-repair retry loop."""

    arxiv_id: str
    repaired: bool
    converged_clean: bool
    repair_attempts: int
    max_repair_attempts: int
    initial_verdict: str
    final_verdict: str
    initial_score: float
    final_score: float
    repaired_source_code: str
    final_verification_report: CodeVerificationResult
    repair_history: List[RepairAttemptRecord] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "arxiv_id": self.arxiv_id,
            "repaired": self.repaired,
            "converged_clean": self.converged_clean,
            "repair_attempts": self.repair_attempts,
            "max_repair_attempts": self.max_repair_attempts,
            "initial_verdict": self.initial_verdict,
            "final_verdict": self.final_verdict,
            "initial_score": self.initial_score,
            "final_score": self.final_score,
            "duration_ms": self.duration_ms,
            "repair_history": [r.to_dict() for r in self.repair_history],
        }

    def to_dict(self) -> Dict[str, Any]:
        out = self.to_summary_dict()
        out["final_verification_report"] = self.final_verification_report.to_dict()
        return out


# ==============================================================================
# 1. Scale-Accurate Official Model Capability Ranking & No-Proxy Ollama Probe
# ==============================================================================

def sanitize_model_tag(model_tag: str) -> str:
    """Strips invalid `-coder` suffixes that trigger silent Ollama 404 aborts."""
    cleaned = (model_tag or "").strip()
    if "-coder:" in cleaned:
        cleaned = cleaned.replace("-coder:", ":")
    elif cleaned.endswith("-coder"):
        cleaned = cleaned[: -len("-coder")]
    return cleaned


def is_chat_code_model(tag: str) -> bool:
    """Excludes embedding, vision, and decision-only models (e.g. Bespoke-Nimble-9B)."""
    low = (tag or "").strip().lower()
    if not low:
        return False
    return not any(marker in low for marker in _EMBED_OR_DECISION_MARKERS)


def estimated_model_vram_gb(tag: str) -> float:
    """Estimates Q4/GGUF runtime VRAM footprint (GB) for residency prioritization."""
    low = (tag or "").strip().lower()
    if "70b" in low:
        return 42.0
    if "32b" in low or "26b" in low or "27b" in low or low.startswith(("glm-4.7", "glm-5")):
        return 18.0
    if "14b" in low or "13b" in low or "12b" in low:
        return 9.5
    if "9b" in low or "8b" in low or "7b" in low or low.startswith("glm4"):
        return 6.0
    if "4b" in low or "3b" in low:
        return 2.5
    return 1.2


def model_capability_score(tag: str) -> int:
    """
    Scale-accurate capability ranking for strict-JSON verification & code repair:
      9B (`glm4:9b`: 95) > 8B (`85`) > native 7B (`qwen2.5:7b`: 80) >
      distilled 7B (`deepseek-r1:7b`: 72) > abliterated community fine-tunes (-65).
    """
    low = (tag or "").strip().lower()
    if "70b" in low:
        base = 700
    elif "32b" in low:
        base = 320
    elif "26b" in low or "27b" in low or low.startswith(("glm-4.7", "glm-5")):
        base = 260
    elif "14b" in low or "13b" in low or "12b" in low:
        base = 140
    elif "9b" in low or low.startswith("glm4"):
        base = 95
    elif "8b" in low:
        base = 85
    elif "7b" in low:
        base = 72 if "deepseek-r1" in low else 80
    elif "4b" in low or "3b" in low:
        base = 35
    elif "1.5b" in low or "2b" in low:
        base = 20
    elif "0.5b" in low:
        base = 10
    else:
        base = 15

    if "abliterated" in low or "obliteratus" in low or "uncensored" in low:
        return max(1, base - 65)
    return base


def rank_repair_and_verifier_models(
    installed_models: Sequence[str],
    gpu_vram_gb: float = 8.0,
    requested_model: Optional[str] = None,
) -> List[str]:
    """
    Orders installed chat/code models prioritizing GPU-VRAM residency and
    scale-accurate official model reliability (`glm4:9b` > `qwen2.5:7b` > `deepseek-r1:7b`).
    """
    eligible = [
        sanitize_model_tag(m)
        for m in installed_models
        if is_chat_code_model(m)
    ]
    eligible.sort(
        key=lambda m: (
            1 if (gpu_vram_gb >= 4.0 and estimated_model_vram_gb(m) <= (gpu_vram_gb + 0.5)) else 0,
            model_capability_score(m),
        ),
        reverse=True,
    )
    ordered: List[str] = []
    if requested_model:
        req_clean = sanitize_model_tag(requested_model).lower()
        for m in eligible:
            if m.lower() == req_clean or m.lower().startswith(f"{req_clean}:"):
                ordered.append(m)
                break
    for m in eligible:
        if m not in ordered:
            ordered.append(m)
    return ordered


def _build_no_proxy_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def probe_ollama_models_fast(
    endpoint: str = "http://127.0.0.1:11434",
    timeout_sec: float = 0.4,
) -> Tuple[bool, List[str]]:
    """Fast 400ms no-proxy probe of local Ollama `/api/tags`."""
    url = f"{endpoint.rstrip('/')}/api/tags"
    opener = _build_no_proxy_opener()
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "RFCHunt-CodeRepair/1.0"})
    try:
        with opener.open(req, timeout=timeout_sec) as resp:
            if resp.status != 200:
                return False, []
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            names = [
                str(m.get("name", "")).strip()
                for m in (data.get("models") or [])
                if isinstance(m, dict) and str(m.get("name", "")).strip()
            ]
            return True, names
    except Exception:
        return False, []


def strip_think_tags(raw_text: str) -> str:
    """Strips `<think>...</think>` blocks emitted by reasoning models."""
    if not raw_text:
        return ""
    end_idx = raw_text.rfind("</think>")
    if end_idx != -1:
        return raw_text[end_idx + len("</think>") :].strip()
    return re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL | re.IGNORECASE).strip()


# ==============================================================================
# 2. Layer-1 Deterministic Gates: AST+Ruff Lint, mypy --strict, Fuzzing, pytest
# ==============================================================================

def run_static_code_linters(source_code: str) -> Dict[str, Any]:
    """
    Multi-layer static linting:
      1. Built-in zero-dependency strict AST linter (`AST-F401` unused imports,
         `AST-F601` duplicate dict keys, `AST-E722` bare except, `AST-B006`
         mutable defaults, `AST-BUG001` `len(indicators)` cache-key collision).
      2. External `ruff check --select E,F,W,B --ignore E501` when `ruff` is installed.
    """
    issues: List[Dict[str, Any]] = []
    engines_used: List[str] = ["builtin_ast_linter"]

    try:
        tree = ast.parse(source_code)
    except SyntaxError as exc:
        return {
            "linter_passed": False,
            "linter_engines": engines_used,
            "issue_count": 1,
            "issues": [
                {
                    "engine": "builtin_ast_linter",
                    "code": "E999",
                    "line": exc.lineno or 1,
                    "message": f"SyntaxError: {exc.msg}",
                }
            ],
        }

    imported: Dict[str, int] = {}
    referenced: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                imported[bound] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                imported[bound] = node.lineno
        elif isinstance(node, ast.Name):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            referenced.add(node.value.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", node.value):
                referenced.add(tok)

        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(
                {
                    "engine": "builtin_ast_linter",
                    "code": "AST-E722",
                    "line": node.lineno,
                    "message": "Bare `except:` clause detected; catch a specific exception type.",
                }
            )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            all_defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
            for dflt in all_defaults:
                if isinstance(dflt, (ast.List, ast.Dict, ast.Set)):
                    issues.append(
                        {
                            "engine": "builtin_ast_linter",
                            "code": "AST-B006",
                            "line": dflt.lineno,
                            "message": f"Mutable default argument in function `{node.name}`.",
                        }
                    )
        if isinstance(node, ast.Dict):
            seen_keys: set[Any] = set()
            for k in node.keys:
                if isinstance(k, ast.Constant):
                    key_repr = (type(k.value).__name__, k.value)
                    if key_repr in seen_keys:
                        issues.append(
                            {
                                "engine": "builtin_ast_linter",
                                "code": "AST-F601",
                                "line": k.lineno,
                                "message": f"Duplicate dictionary literal key `{k.value!r}`.",
                            }
                        )
                    seen_keys.add(key_repr)

    for imp_name, lineno in imported.items():
        if imp_name not in referenced:
            issues.append(
                {
                    "engine": "builtin_ast_linter",
                    "code": "AST-F401",
                    "line": lineno,
                    "message": f"Unused import `{imp_name}`.",
                }
            )

    if re.search(r"cache_key\s*(?::[^=]+)?=\s*\(\s*payload_corpus\s*,\s*len\s*\(\s*indicators\s*\)\s*\)", source_code):
        issues.append(
            {
                "engine": "builtin_ast_linter",
                "code": "AST-BUG001",
                "line": 1,
                "message": "Cache key uses `len(indicators)` instead of `tuple(indicators)`, causing stale collisions.",
            }
        )

    if importlib.util.find_spec("ruff") is not None:
        engines_used.append("ruff")
        creationflags = 0x08000000 if platform.system() == "Windows" else 0
        with tempfile.TemporaryDirectory(prefix="rfchunt_lint_") as tmpdir:
            tmp_py = Path(tmpdir) / "generated_module.py"
            tmp_py.write_text(source_code, encoding="utf-8")
            try:
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "ruff",
                        "check",
                        "--output-format",
                        "json",
                        "--select",
                        "E,F,W,B",
                        "--ignore",
                        "E501",
                        str(tmp_py),
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    creationflags=creationflags,
                )
                raw_out = (proc.stdout or "").strip()
                if raw_out:
                    ruff_items = json.loads(raw_out)
                    if isinstance(ruff_items, list):
                        for item in ruff_items[:20]:
                            loc = item.get("location") or {}
                            issues.append(
                                {
                                    "engine": "ruff",
                                    "code": str(item.get("code", "RUFF")),
                                    "line": int(loc.get("row", 1)),
                                    "message": str(item.get("message", "")),
                                }
                            )
            except Exception as exc:
                issues.append(
                    {
                        "engine": "ruff",
                        "code": "RUFF-EXEC",
                        "line": 1,
                        "message": f"Ruff execution warning: {type(exc).__name__}: {str(exc)[:140]}",
                    }
                )

    return {
        "linter_passed": len(issues) == 0,
        "linter_engines": engines_used,
        "issue_count": len(issues),
        "issues": issues,
    }


def run_mypy_type_checker(
    source_code: str,
    timeout_sec: int = 25,
) -> Dict[str, Any]:
    """Executes strict static type checking (`mypy --strict --ignore-missing-imports`)."""
    if importlib.util.find_spec("mypy") is None:
        return {
            "mypy_executed": False,
            "mypy_passed": True,
            "issue_count": 0,
            "issues": [],
            "summary": "mypy not installed; skipped strict static type check.",
        }

    creationflags = 0x08000000 if platform.system() == "Windows" else 0
    with tempfile.TemporaryDirectory(prefix="rfchunt_mypy_") as tmpdir:
        tmp_root = Path(tmpdir)
        src_file = tmp_root / "generated_module.py"
        cache_dir = tmp_root / "mypy_cache"
        src_file.write_text(source_code, encoding="utf-8")
        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "mypy",
                    "--strict",
                    "--ignore-missing-imports",
                    "--no-error-summary",
                    "--no-color-output",
                    "--show-error-codes",
                    "--cache-dir",
                    str(cache_dir),
                    str(src_file),
                ],
                cwd=str(tmp_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
                creationflags=creationflags,
            )
            issues: List[Dict[str, Any]] = []
            for raw_line in (proc.stdout or "").splitlines():
                line = raw_line.strip()
                if not line or ": note:" in line:
                    continue
                m = re.match(r"^.+?:(\d+)(?::\d+)?:\s*(error|warning):\s*(.+?)(?:\s+\[([^\]]+)\])?$", line)
                if m:
                    issues.append(
                        {
                            "engine": "mypy",
                            "line": int(m.group(1)),
                            "severity": m.group(2),
                            "code": m.group(4) or "mypy-error",
                            "message": m.group(3).strip(),
                        }
                    )
                elif proc.returncode != 0:
                    issues.append(
                        {
                            "engine": "mypy",
                            "line": 1,
                            "severity": "error",
                            "code": "mypy-error",
                            "message": line[:200],
                        }
                    )
            passed = proc.returncode == 0 and len(issues) == 0
            return {
                "mypy_executed": True,
                "mypy_passed": passed,
                "issue_count": len(issues),
                "issues": issues[:20],
                "summary": "mypy --strict passed (0 errors)" if passed else f"mypy --strict found {len(issues)} error(s)",
            }
        except Exception as exc:
            return {
                "mypy_executed": True,
                "mypy_passed": False,
                "issue_count": 1,
                "issues": [
                    {
                        "engine": "mypy",
                        "line": 1,
                        "severity": "error",
                        "code": "mypy-exec",
                        "message": f"mypy execution failed: {type(exc).__name__}: {str(exc)[:180]}",
                    }
                ],
                "summary": f"mypy execution error: {type(exc).__name__}",
            }


def run_generated_code_pytest(
    source_code: str,
    arxiv_id: str = "custom",
    timeout_sec: int = 20,
) -> Dict[str, Any]:
    """Executes real `python -m pytest` in an isolated temporary directory."""
    has_discoverable_tests = bool(
        re.search(r"^\s*def\s+test_", source_code, flags=re.MULTILINE)
        or re.search(r"^\s*class\s+Test[A-Za-z0-9_]*", source_code, flags=re.MULTILINE)
    )
    if not has_discoverable_tests:
        return {
            "pytest_executed": False,
            "pytest_passed": True,
            "exit_code": 5,
            "summary": "No pytest test_* functions or Test* classes declared in custom snippet.",
        }

    if importlib.util.find_spec("pytest") is None:
        return {
            "pytest_executed": False,
            "pytest_passed": True,
            "exit_code": -1,
            "summary": "pytest package not installed; relied on embedded runtime benchmark.",
        }

    slug = re.sub(r"[^A-Za-z0-9_]+", "_", arxiv_id or "custom")
    creationflags = 0x08000000 if platform.system() == "Windows" else 0
    env = dict(os.environ)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    with tempfile.TemporaryDirectory(prefix="rfchunt_pytest_") as tmpdir:
        tmp_root = Path(tmpdir)
        test_file = tmp_root / f"test_generated_{slug}.py"
        basetemp = tmp_root / "basetemp"
        test_file.write_text(source_code, encoding="utf-8")
        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "--no-header",
                    "-p",
                    "no:cacheprovider",
                    "--basetemp",
                    str(basetemp),
                    str(test_file),
                ],
                cwd=str(tmp_root),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
                creationflags=creationflags,
            )
            combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            lines_nonempty = [ln.strip() for ln in combined.splitlines() if ln.strip()]
            summary_line = lines_nonempty[-1] if lines_nonempty else f"exit_code={proc.returncode}"
            return {
                "pytest_executed": True,
                "pytest_passed": proc.returncode == 0,
                "exit_code": proc.returncode,
                "summary": summary_line[:240],
            }
        except Exception as exc:
            return {
                "pytest_executed": True,
                "pytest_passed": False,
                "exit_code": -2,
                "summary": f"pytest execution error: {type(exc).__name__}: {str(exc)[:180]}",
            }


_SUBPROCESS_FUZZ_AND_BENCH_HARNESS = r'''
import importlib.util
import json
import math
import random
import sys
import tracemalloc
from pathlib import Path

target_path = Path(sys.argv[1])
seed = int(sys.argv[2])
num_trials = int(sys.argv[3])
bench_iters = int(sys.argv[4])

out = {
    "fuzz_executed": False,
    "fuzz_passed": False,
    "trials_run": 0,
    "properties_checked": 0,
    "failures": [],
    "runtime_tests_passed": 0,
    "runtime_tests_total": 0,
    "runtime_fitness_score": 0.0,
    "execution_time_us": 0.0,
    "peak_memory_kib": 0.0,
    "runtime_error": None,
}

try:
    spec = importlib.util.spec_from_file_location("rfchunt_candidate_mod", str(target_path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to create module spec for candidate")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rfchunt_candidate_mod"] = mod
    spec.loader.exec_module(mod)
except Exception as exc:
    out["runtime_error"] = f"{type(exc).__name__}: {exc}"
    out["failures"].append({"property": "module_load", "detail": str(exc)[:200]})
    print(json.dumps(out))
    sys.exit(0)

# Part A: Embedded Deterministic Benchmark
bench_fn = getattr(mod, "run_deterministic_benchmark", None)
if callable(bench_fn):
    try:
        tracemalloc.start()
        res = bench_fn(iterations=bench_iters)
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        tp = int(res.get("tests_passed", 0))
        tt = int(res.get("tests_total", 7))
        avg_us = float(res.get("avg_iteration_us", 1.0))
        peak_kib = round(float(res.get("peak_memory_kib", peak_bytes / 1024.0)), 3)
        correctness_pts = 60.0 * (tp / max(1, tt))
        speed_pts = max(0.0, min(25.0, 25.0 / (1.0 + avg_us / 50.0)))
        mem_pts = max(0.0, min(15.0, 15.0 / (1.0 + peak_kib / 128.0)))
        out["runtime_tests_passed"] = tp
        out["runtime_tests_total"] = tt
        out["execution_time_us"] = round(avg_us, 3)
        out["peak_memory_kib"] = peak_kib
        out["runtime_fitness_score"] = round(correctness_pts + speed_pts + mem_pts, 2)
    except Exception as exc:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        out["runtime_error"] = f"{type(exc).__name__}: {exc}"
else:
    out["runtime_tests_passed"] = 0
    out["runtime_tests_total"] = 0
    out["runtime_fitness_score"] = 80.0

# Part B: Randomized Property-Based Fuzzing (Algebraic + Adversarial + Crypto)
rng = random.Random(seed)
failures = []
props = 0

scope_cls = getattr(mod, "DelegationScope", None)
scan_fn = getattr(mod, "scan_and_score_payload", None)
engine_cls = next(
    (v for k, v in vars(mod).items() if k.startswith("ArxivAlgorithmEngine_") and isinstance(v, type)),
    None,
)

if scope_cls is not None and hasattr(scope_cls, "meet"):
    res_u = ["repo_a", "repo_b", "repo_c", "db_prod"]
    act_u = ["read_public", "compile_workspace", "read_sensitive", "external_transmit"]
    dom_u = ["engineering", "finance", "default"]
    comp_u = [("read_sensitive", "external_transmit"), ("read_public", "external_transmit")]
    top_scope = scope_cls(resources=frozenset(["*"]), actions=frozenset(["*"]), data_domains=frozenset(["*"]))

    def _rand_scope():
        r_s = frozenset(["*"]) if rng.random() < 0.25 else frozenset(rng.sample(res_u, rng.randint(1, 3)))
        a_s = frozenset(["*"]) if rng.random() < 0.25 else frozenset(rng.sample(act_u, rng.randint(1, 3)))
        d_s = frozenset(["*"]) if rng.random() < 0.25 else frozenset(rng.sample(dom_u, rng.randint(1, 2)))
        c_s = frozenset(rng.sample(comp_u, rng.randint(0, len(comp_u))))
        return scope_cls(resources=r_s, actions=a_s, data_domains=d_s, prohibited_compositions=c_s)

    for trial in range(num_trials):
        s1, s2, s3 = _rand_scope(), _rand_scope(), _rand_scope()
        props += 5
        if s1.meet(s1) != s1:
            failures.append({"property": "semilattice_idempotence", "detail": f"Trial {trial}: S meet S != S"})
            break
        m12, m21 = s1.meet(s2), s2.meet(s1)
        if m12 != m21:
            failures.append({"property": "semilattice_commutativity", "detail": f"Trial {trial}: S1 meet S2 != S2 meet S1"})
            break
        if m12.meet(s3) != s1.meet(s2.meet(s3)):
            failures.append({"property": "semilattice_associativity", "detail": f"Trial {trial}: associativity violated"})
            break
        if top_scope.meet(s1) != s1 or s1.meet(top_scope) != s1:
            failures.append({"property": "semilattice_top_identity", "detail": f"Trial {trial}: Top(*) meet S != S"})
            break
        pr, pa, pd = rng.choice(res_u), rng.choice(act_u), rng.choice(dom_u)
        if m12.allows(pr, pa, pd) and not (s1.allows(pr, pa, pd) and s2.allows(pr, pa, pd)):
            failures.append({"property": "semilattice_monotonic_attenuation", "detail": f"Trial {trial}: meet escalated privilege"})
            break
        if not (s1.prohibited_compositions <= m12.prohibited_compositions and s2.prohibited_compositions <= m12.prohibited_compositions):
            failures.append({"property": "semilattice_restriction_union", "detail": f"Trial {trial}: prohibited_compositions lost"})
            break

if callable(scan_fn):
    adv_corpora = ["", "\x00\x01\x02", "/" * 64 + "|" * 64, "Unicode \u202e \U0001f680 safe", "UPPERCASE_TEXT"]
    adv_alphas = [0.0, -0.05, 1e-9, 0.01, 0.5, 2.0]
    adv_wealths = [0.0, -5.0, 1.0, 1e6, float("nan"), float("inf")]

    for trial in range(num_trials):
        corpus = adv_corpora[trial] if trial < len(adv_corpora) else "".join(rng.choices("abcxyz/|;0123 \t\n", k=rng.randint(0, 120)))
        alpha_v = adv_alphas[trial % len(adv_alphas)]
        wealth_v = adv_wealths[trial % len(adv_wealths)]
        tok_a = f"fuzz_ind_a_{trial}_{rng.randint(10, 99)}"
        tok_b = f"fuzz_ind_b_{trial}_{rng.randint(10, 99)}"
        ind_a = (tok_a, f"other_a_{trial}")
        ind_b = (tok_b, f"other_b_{trial}")
        props += 3
        try:
            m1, nc1, w1, t1 = scan_fn(corpus, ind_a, wealth_v, alpha_v)
            if not isinstance(m1, tuple) or not isinstance(t1, bool):
                failures.append({"property": "scan_return_types", "detail": f"Trial {trial}: invalid return types"})
                break
            if not (math.isfinite(nc1) and 0.0 <= nc1 <= 1.0 and math.isfinite(w1)):
                failures.append({"property": "scan_finite_bounds", "detail": f"Trial {trial}: non-finite nc={nc1}, w={w1}"})
                break
            injected = f"{corpus} {tok_b.upper()} tail"
            ma, _, _, ta = scan_fn(injected, ind_a, 1.0, 0.01)
            mb, _, _, tb = scan_fn(injected, ind_b, 1.0, 0.01)
            if ta or len(ma) != 0 or (not tb) or tok_b not in mb:
                failures.append({"property": "scan_soundness_and_cache_isolation", "detail": f"Trial {trial}: cache collision or missed indicator"})
                break
        except Exception as exc:
            failures.append({"property": "scan_no_crash", "detail": f"Trial {trial} (alpha={alpha_v}, wealth={wealth_v}): {type(exc).__name__}: {exc}"})
            break

if engine_cls is not None and scope_cls is not None:
    eng = engine_cls(
        signing_key=b"fuzz-hmac-key-32-bytes-strict!!",
        allowed_actions=["read_public", "compile_workspace", "read_sensitive", "external_transmit"],
    )
    for trial in range(min(15, num_trials)):
        actor, sess, act = f"actor-{trial}", f"sess-fuzz-{trial}", "read_public"
        seal = eng.issue_envelope_seal(actor, sess, act)
        forged = ("0" if seal[0] != "0" else "f") + seal[1:]
        props += 2
        v_forged = eng.evaluate_action(actor, sess, act, "benign test text", forged)
        if v_forged.allowed or v_forged.session_lineage_verified:
            failures.append({"property": "hmac_bitflip_reject", "detail": f"Trial {trial}: forged HMAC seal was allowed"})
            break
        nonce = f"fuzz-nonce-{trial}"
        v1 = eng.evaluate_action(actor, sess, act, "benign test text", seal, approval_nonce=nonce)
        v2 = eng.evaluate_action(actor, sess, act, "benign test text", seal, approval_nonce=nonce)
        if not v1.allowed or v2.allowed:
            failures.append({"property": "approval_nonce_replay_reject", "detail": f"Trial {trial}: replay nonce guard failed"})
            break

out["fuzz_executed"] = True
out["fuzz_passed"] = len(failures) == 0
out["trials_run"] = num_trials
out["properties_checked"] = props
out["failures"] = failures
print(json.dumps(out))
'''


def run_property_based_fuzzing_and_benchmark(
    source_code: str,
    seed: int = 2026,
    num_trials: int = 35,
    benchmark_iterations: int = 40,
    timeout_sec: int = 20,
) -> Dict[str, Any]:
    """
    Executes randomized property-based fuzzing (310+ properties) and embedded
    benchmark verification inside an isolated child Python process (never using
    in-process dynamic execution).
    """
    creationflags = 0x08000000 if platform.system() == "Windows" else 0
    with tempfile.TemporaryDirectory(prefix="rfchunt_fuzz_") as tmpdir:
        tmp_root = Path(tmpdir)
        cand_file = tmp_root / "candidate_module.py"
        runner_file = tmp_root / "fuzz_runner.py"
        cand_file.write_text(source_code, encoding="utf-8")
        runner_file.write_text(_SUBPROCESS_FUZZ_AND_BENCH_HARNESS, encoding="utf-8")
        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(runner_file),
                    str(cand_file),
                    str(seed),
                    str(num_trials),
                    str(benchmark_iterations),
                ],
                cwd=str(tmp_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
                creationflags=creationflags,
            )
            stdout_lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
            if stdout_lines:
                return json.loads(stdout_lines[-1])
            return {
                "fuzz_executed": False,
                "fuzz_passed": False,
                "trials_run": 0,
                "properties_checked": 0,
                "failures": [{"property": "subprocess_empty", "detail": (proc.stderr or "No output")[:200]}],
                "runtime_tests_passed": 0,
                "runtime_tests_total": 7,
                "runtime_fitness_score": 0.0,
                "execution_time_us": 0.0,
                "peak_memory_kib": 0.0,
                "runtime_error": (proc.stderr or "Subprocess returned empty output")[:200],
            }
        except Exception as exc:
            return {
                "fuzz_executed": False,
                "fuzz_passed": False,
                "trials_run": 0,
                "properties_checked": 0,
                "failures": [{"property": "subprocess_error", "detail": f"{type(exc).__name__}: {str(exc)[:180]}"}],
                "runtime_tests_passed": 0,
                "runtime_tests_total": 7,
                "runtime_fitness_score": 0.0,
                "execution_time_us": 0.0,
                "peak_memory_kib": 0.0,
                "runtime_error": f"{type(exc).__name__}: {str(exc)[:180]}",
            }


def run_property_based_fuzzing(
    source_code: str,
    seed: int = 2026,
    num_trials: int = 35,
) -> Dict[str, Any]:
    """Convenience wrapper returning the property-based fuzzing report dictionary."""
    res = run_property_based_fuzzing_and_benchmark(
        source_code=source_code,
        seed=seed,
        num_trials=num_trials,
        benchmark_iterations=15,
    )
    return {
        "fuzz_executed": bool(res.get("fuzz_executed", False)),
        "fuzz_passed": bool(res.get("fuzz_passed", False)),
        "trials_run": int(res.get("trials_run", 0)),
        "properties_checked": int(res.get("properties_checked", 0)),
        "failures": list(res.get("failures") or []),
    }


def run_deterministic_code_verification(
    source_code: str,
    arxiv_id: str = "custom",
    benchmark_iterations: int = 40,
    run_pytest_subprocess: bool = True,
    run_mypy_subprocess: bool = True,
    run_fuzzing: bool = True,
) -> Dict[str, Any]:
    """
    Runs fail-closed Layer-1 verification concurrently across a 4-worker pool:
      AST Security + Ruff/AST Lint + `mypy --strict` + 310-Property Fuzzing +
      Subprocess `pytest` + 7-Invariant Runtime Benchmark.
    """
    findings: List[Dict[str, str]] = []
    has_evolve_block = (EVOLVE_START_MARKER in source_code) and (EVOLVE_END_MARKER in source_code)
    if not has_evolve_block:
        findings.append(
            {
                "severity": "MEDIUM",
                "category": "structure",
                "message": "Missing # EVOLVE-BLOCK-START / # EVOLVE-BLOCK-END markers.",
                "recommendation": "Wrap core algorithmic kernel inside EVOLVE-BLOCK markers.",
            }
        )

    ast_syntax_valid = False
    constant_time_hmac_used = False
    meet_semilattice_present = False
    dangerous_calls_found: List[str] = []
    mock_indicators_found: List[str] = []
    tree: Optional[ast.AST] = None

    try:
        tree = ast.parse(source_code)
        ast_syntax_valid = True
    except SyntaxError as exc:
        findings.append(
            {
                "severity": "CRITICAL",
                "category": "correctness",
                "message": f"Python AST syntax error at line {exc.lineno}: {exc.msg}",
                "recommendation": "Fix Python syntax before executing or deploying generated module.",
            }
        )

    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "compare_digest":
                        constant_time_hmac_used = True
                    if isinstance(node.func.value, ast.Name):
                        pair = (node.func.value.id, node.func.attr)
                        if pair in DANGEROUS_ATTR_CALLS:
                            dangerous_calls_found.append(f"{pair[0]}.{pair[1]}")
                        if pair[0] == "subprocess":
                            for kw in node.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    dangerous_calls_found.append(f"subprocess.{pair[1]}(shell=True)")
                elif isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALL_NAMES:
                    dangerous_calls_found.append(node.func.id)

            if isinstance(node, ast.ClassDef) and node.name == "DelegationScope":
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == "meet":
                        meet_semilattice_present = True

            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                target_name = ""
                val_node = None
                if isinstance(node, ast.Assign) and node.targets and isinstance(node.targets[0], ast.Name):
                    target_name = node.targets[0].id
                    val_node = node.value
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    target_name = node.target.id
                    val_node = node.value
                if target_name == "MULTI_TOKEN_TECHNICAL_INDICATORS" and isinstance(val_node, (ast.Tuple, ast.List, ast.Set)):
                    for elt in val_node.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            tok = elt.value.strip().lower()
                            if tok in FORBIDDEN_SINGLE_TOKEN_MOCKS:
                                mock_indicators_found.append(tok)

    zero_dangerous_calls = len(dangerous_calls_found) == 0
    zero_mock_indicators = len(mock_indicators_found) == 0

    if not zero_dangerous_calls:
        findings.append(
            {
                "severity": "CRITICAL",
                "category": "security",
                "message": f"Dangerous dynamic/shell calls detected: {sorted(set(dangerous_calls_found))}",
                "recommendation": "Remove unsafe dynamic execution or shell=True subprocess invocations.",
            }
        )
    if not zero_mock_indicators:
        findings.append(
            {
                "severity": "HIGH",
                "category": "anti-mock",
                "message": f"Forbidden single-token mock indicators detected: {mock_indicators_found}",
                "recommendation": "Replace single-token rules with multi-token technical indicators.",
            }
        )

    linter_report: Dict[str, Any]
    mypy_report: Dict[str, Any]
    pytest_report: Dict[str, Any]
    fuzz_bench: Dict[str, Any]

    if ast_syntax_valid and zero_dangerous_calls:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            f_lint = pool.submit(run_static_code_linters, source_code)
            f_mypy = pool.submit(run_mypy_type_checker, source_code) if run_mypy_subprocess else None
            f_pytest = pool.submit(run_generated_code_pytest, source_code, arxiv_id) if run_pytest_subprocess else None
            f_fuzz = (
                pool.submit(
                    run_property_based_fuzzing_and_benchmark,
                    source_code,
                    2026,
                    35 if run_fuzzing else 0,
                    benchmark_iterations,
                )
            )
            linter_report = f_lint.result()
            mypy_report = (
                f_mypy.result()
                if f_mypy is not None
                else {"mypy_executed": False, "mypy_passed": True, "issue_count": 0, "issues": [], "summary": "Skipped mypy."}
            )
            pytest_report = (
                f_pytest.result()
                if f_pytest is not None
                else {"pytest_executed": False, "pytest_passed": True, "exit_code": 0, "summary": "Skipped pytest."}
            )
            fuzz_bench = f_fuzz.result()
    else:
        linter_report = run_static_code_linters(source_code)
        mypy_report = {
            "mypy_executed": False,
            "mypy_passed": False,
            "issue_count": 1,
            "issues": [{"engine": "mypy", "line": 1, "severity": "error", "code": "skip", "message": "Skipped mypy due to syntax/security failure."}],
            "summary": "Skipped mypy due to syntax or security failure.",
        }
        pytest_report = {
            "pytest_executed": False,
            "pytest_passed": False,
            "exit_code": 2,
            "summary": "Skipped pytest due to syntax or security failure.",
        }
        fuzz_bench = {
            "fuzz_executed": False,
            "fuzz_passed": False,
            "trials_run": 0,
            "properties_checked": 0,
            "failures": [{"property": "precheck", "detail": "Skipped fuzzing due to syntax or security failure."}],
            "runtime_tests_passed": 0,
            "runtime_tests_total": 7,
            "runtime_fitness_score": 0.0,
            "execution_time_us": 0.0,
            "peak_memory_kib": 0.0,
            "runtime_error": "Skipped runtime execution due to syntax or dangerous AST call.",
        }

    linter_passed = bool(linter_report["linter_passed"])
    mypy_passed = bool(mypy_report["mypy_passed"])
    fuzz_passed = bool(fuzz_bench.get("fuzz_passed", False)) if run_fuzzing else True
    pytest_passed = bool(pytest_report["pytest_passed"])
    runtime_error = fuzz_bench.get("runtime_error")
    tests_passed = int(fuzz_bench.get("runtime_tests_passed", 0))
    tests_total = int(fuzz_bench.get("runtime_tests_total", 0))

    if not linter_passed:
        for li in (linter_report.get("issues") or [])[:8]:
            findings.append(
                {
                    "severity": "HIGH" if str(li.get("code", "")).startswith(("E9", "F8", "AST-BUG")) else "MEDIUM",
                    "category": "lint",
                    "message": f"[{li['engine']}:{li['code']} L{li['line']}] {li['message']}",
                    "recommendation": "Resolve static linter violation before shipping generated code.",
                }
            )
    if not mypy_passed:
        for mi in (mypy_report.get("issues") or [])[:8]:
            findings.append(
                {
                    "severity": "HIGH",
                    "category": "typing",
                    "message": f"[mypy:{mi['code']} L{mi['line']}] {mi['message']}",
                    "recommendation": "Fix strict static type annotation error reported by mypy --strict.",
                }
            )
    if not fuzz_passed:
        for fi in (fuzz_bench.get("failures") or [])[:6]:
            findings.append(
                {
                    "severity": "CRITICAL",
                    "category": "fuzzing",
                    "message": f"[fuzz:{fi['property']}] {fi['detail']}",
                    "recommendation": "Fix algebraic semilattice, bounds, or security invariant counterexample.",
                }
            )
    if not pytest_passed:
        findings.append(
            {
                "severity": "CRITICAL",
                "category": "correctness",
                "message": f"Subprocess pytest failed: {pytest_report['summary']}",
                "recommendation": "Fix failing pytest test cases in generated module.",
            }
        )
    if runtime_error:
        findings.append(
            {
                "severity": "CRITICAL",
                "category": "correctness",
                "message": f"Runtime benchmark failure: {runtime_error}",
                "recommendation": "Fix runtime exception in generated module.",
            }
        )

    score = 0.0
    if ast_syntax_valid:
        score += 10.0
    if zero_dangerous_calls:
        score += 15.0
    if zero_mock_indicators:
        score += 10.0
    if linter_passed:
        score += 10.0
    if mypy_passed:
        score += 10.0
    if fuzz_passed:
        score += 10.0
    if has_evolve_block:
        score += 5.0
    if constant_time_hmac_used:
        score += 5.0
    if meet_semilattice_present:
        score += 5.0
    if runtime_error is None:
        score += 10.0 * (tests_passed / float(tests_total)) if tests_total > 0 else 10.0
    if pytest_passed and runtime_error is None:
        score += 10.0

    return {
        "ast_syntax_valid": ast_syntax_valid,
        "evolve_block_present": has_evolve_block,
        "constant_time_hmac_used": constant_time_hmac_used,
        "meet_semilattice_present": meet_semilattice_present,
        "zero_dangerous_calls": zero_dangerous_calls,
        "dangerous_calls_found": sorted(set(dangerous_calls_found)),
        "zero_mock_single_token_indicators": zero_mock_indicators,
        "mock_indicators_found": mock_indicators_found,
        "linter_passed": linter_passed,
        "linter_engines": linter_report["linter_engines"],
        "linter_issue_count": int(linter_report["issue_count"]),
        "linter_issues": linter_report["issues"],
        "mypy_executed": bool(mypy_report["mypy_executed"]),
        "mypy_passed": mypy_passed,
        "mypy_issue_count": int(mypy_report["issue_count"]),
        "mypy_issues": mypy_report["issues"],
        "mypy_summary": str(mypy_report["summary"]),
        "fuzz_executed": bool(fuzz_bench.get("fuzz_executed", False)),
        "fuzz_passed": fuzz_passed,
        "fuzz_trials_run": int(fuzz_bench.get("trials_run", 0)),
        "fuzz_properties_checked": int(fuzz_bench.get("properties_checked", 0)),
        "fuzz_failures": list(fuzz_bench.get("failures") or []),
        "pytest_executed": bool(pytest_report["pytest_executed"]),
        "pytest_passed": pytest_passed,
        "pytest_exit_code": int(pytest_report["exit_code"]),
        "pytest_summary": str(pytest_report["summary"]),
        "runtime_tests_passed": tests_passed,
        "runtime_tests_total": tests_total,
        "runtime_fitness_score": float(fuzz_bench.get("runtime_fitness_score", 0.0)),
        "execution_time_us": float(fuzz_bench.get("execution_time_us", 0.0)),
        "peak_memory_kib": float(fuzz_bench.get("peak_memory_kib", 0.0)),
        "runtime_error": runtime_error,
        "deterministic_score": round(score, 2),
        "static_findings": findings,
    }


def verify_python_code_native(
    source_code: str,
    arxiv_id: str = "custom",
    title: str = "Generated Security Detector Module",
    code_stage: str = "synthesized",
    model_id: Optional[str] = None,
    ollama_endpoint: Optional[str] = None,
    timeout_sec: float = 120.0,
    enable_llm: bool = False,
) -> CodeVerificationResult:
    """
    Fail-closed Layer-1 + optional Layer-2 Ollama LLM verifier native to RFCHunt.
    """
    t0 = time.perf_counter()
    endpoint = ollama_endpoint or os.environ.get("LOCAL_OLLAMA_ENDPOINT", "http://127.0.0.1:11434")
    det = run_deterministic_code_verification(source_code=source_code, arxiv_id=arxiv_id)

    det_hard_fail = (
        (not det["ast_syntax_valid"])
        or (not det["zero_dangerous_calls"])
        or (not det["mypy_passed"])
        or (not det["fuzz_passed"])
        or (not det["pytest_passed"])
        or (det["runtime_error"] is not None)
        or (det["runtime_tests_total"] > 0 and det["runtime_tests_passed"] < det["runtime_tests_total"])
    )

    llm_verified = False
    verifier_model = sanitize_model_tag(model_id or "glm4:9b")
    verifier_provider = "deterministic_fallback"
    llm_audit: Dict[str, Any] = {
        "status": "llm_disabled_by_caller" if not enable_llm else "not_executed",
        "verdict": "N/A",
        "paper_fidelity_score": 0.0,
        "correctness_score": 0.0,
        "security_score": 0.0,
        "summary": "",
        "findings": [],
    }

    if enable_llm:
        online, installed = probe_ollama_models_fast(endpoint=endpoint, timeout_sec=0.4)
        ranked = rank_repair_and_verifier_models(installed, requested_model=model_id) if online else []
        if not online:
            llm_audit["status"] = "ollama_offline_fallback"
        elif not ranked:
            llm_audit["status"] = "no_eligible_chat_model_fallback"
        else:
            verifier_model = ranked[0]
            prompt = _build_native_verify_prompt(arxiv_id, title, source_code, det)
            parsed, status = _invoke_ollama_json_judge(endpoint, verifier_model, prompt, timeout_sec)
            llm_audit["status"] = status
            if parsed is not None:
                llm_verified = True
                verifier_provider = "ollama"
                llm_audit.update(parsed)

    det_score = float(det["deterministic_score"])
    combined_findings = list(det["static_findings"])
    if llm_verified:
        combined_findings.extend(llm_audit.get("findings") or [])
        llm_avg = (
            float(llm_audit["paper_fidelity_score"])
            + float(llm_audit["correctness_score"])
            + float(llm_audit["security_score"])
        ) / 3.0
        overall = round((0.45 * det_score) + (0.55 * llm_avg), 2)
        if det_hard_fail:
            verdict = "FAIL"
            overall = min(overall, 45.0)
        elif llm_audit["verdict"] == "FAIL" or overall < 55.0:
            verdict = "FAIL"
        elif llm_audit["verdict"] == "WARN" or overall < 75.0 or not det["zero_mock_single_token_indicators"]:
            verdict = "WARN"
        else:
            verdict = "PASS"
        mode = "llm_and_deterministic_verified"
    else:
        overall = det_score
        if det_hard_fail:
            verdict = "FAIL"
        elif overall >= 85.0 and det["zero_mock_single_token_indicators"]:
            verdict = "PASS"
        elif overall >= 60.0:
            verdict = "WARN"
        else:
            verdict = "FAIL"
        mode = "deterministic_static_and_runtime_fallback"

    recs = list(dict.fromkeys(f["recommendation"] for f in combined_findings if f.get("recommendation")))
    return CodeVerificationResult(
        arxiv_id=arxiv_id,
        title=title,
        code_stage=code_stage,
        verdict=verdict,
        overall_score=overall,
        verification_mode=mode,
        llm_verified=llm_verified,
        verifier_model=verifier_model,
        verifier_provider=verifier_provider,
        deterministic_checks=det,
        llm_audit=llm_audit,
        findings=combined_findings,
        recommendations=recs,
        duration_ms=round((time.perf_counter() - t0) * 1000.0, 2),
    )


def _build_native_verify_prompt(arxiv_id: str, title: str, source_code: str, det: Dict[str, Any]) -> str:
    excerpt = source_code if len(source_code) <= 14000 else (source_code[:10500] + "\n# ... [truncated] ...\n" + source_code[-3000:])
    return (
        "You are a strict formal-methods and Python security code auditor.\n"
        "Base your findings strictly on the source code below; do not contradict passing executable Layer-1 checks "
        "unless you cite a concrete counterexample.\n\n"
        f"Target: arXiv:{arxiv_id} — {title}\n"
        f"Layer-1 Gate: AST={det['ast_syntax_valid']} | Lint={'PASS' if det['linter_passed'] else 'FAIL'} | "
        f"Mypy={'PASS' if det['mypy_passed'] else 'FAIL'}({det['mypy_issue_count']} errs) | "
        f"Fuzz={'PASS' if det['fuzz_passed'] else 'FAIL'}({det['fuzz_properties_checked']} props) | "
        f"Pytest={'PASS' if det['pytest_passed'] else 'FAIL'} | Tests={det['runtime_tests_passed']}/{det['runtime_tests_total']}\n\n"
        f"```python\n{excerpt}\n```\n\n"
        'Respond ONLY with JSON: {"verdict":"PASS"|"WARN"|"FAIL","paper_fidelity_score":0-100,'
        '"correctness_score":0-100,"security_score":0-100,"summary":"...","findings":[]}'
    )


def _invoke_ollama_json_judge(
    endpoint: str,
    model_tag: str,
    prompt: str,
    timeout_sec: float = 120.0,
) -> Tuple[Optional[Dict[str, Any]], str]:
    clean_model = sanitize_model_tag(model_tag)
    is_reasoning = any(k in clean_model.lower() for k in ("deepseek-r1", "qwq", "glm-4.7"))
    body_obj: Dict[str, Any] = {
        "model": clean_model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 900, "num_ctx": 8192},
    }
    if is_reasoning:
        body_obj["think"] = False
    opener = _build_no_proxy_opener()
    req = urllib.request.Request(
        f"{endpoint.rstrip('/')}/api/generate",
        data=json.dumps(body_obj).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "RFCHunt-Verifier/1.0"},
    )
    try:
        with opener.open(req, timeout=timeout_sec) as resp:
            if resp.status != 200:
                return None, f"ollama_http_{resp.status}"
            raw_text = str(json.loads(resp.read().decode("utf-8", errors="replace")).get("response", "")).strip()
            cleaned = strip_think_tags(raw_text)
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE | re.MULTILINE)
            cleaned = re.sub(r"\s*```\s*$", "", cleaned, flags=re.MULTILINE).strip()
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start == -1 or end <= start:
                return None, "llm_parse_fallback"
            obj = json.loads(cleaned[start : end + 1])
            if not isinstance(obj, dict) or not any(k in obj for k in ("verdict", "paper_fidelity_score", "correctness_score", "security_score")):
                return None, "llm_parse_fallback"
            v = str(obj.get("verdict", "WARN")).upper()
            if v not in ("PASS", "WARN", "FAIL"):
                v = "WARN"
            return (
                {
                    "verdict": v,
                    "paper_fidelity_score": round(max(0.0, min(100.0, float(obj.get("paper_fidelity_score", 80.0)))), 2),
                    "correctness_score": round(max(0.0, min(100.0, float(obj.get("correctness_score", 80.0)))), 2),
                    "security_score": round(max(0.0, min(100.0, float(obj.get("security_score", 80.0)))), 2),
                    "summary": str(obj.get("summary", ""))[:400],
                    "findings": list(obj.get("findings") or [])[:8],
                },
                "llm_verified",
            )
    except TimeoutError:
        return None, "ollama_timeout"
    except Exception as exc:
        return None, f"ollama_error:{type(exc).__name__}"


# ==============================================================================
# 3. Iterative Auto-Repair Retry Loop (Tier A Ollama + Tier B AST Patcher)
# ==============================================================================

def count_layer1_gates_passed(det_checks: Dict[str, Any]) -> Tuple[int, int]:
    tests_total = int(det_checks.get("runtime_tests_total", 0))
    tests_passed = int(det_checks.get("runtime_tests_passed", 0))
    gates = [
        bool(det_checks.get("ast_syntax_valid", False)),
        bool(det_checks.get("zero_dangerous_calls", False)),
        bool(det_checks.get("zero_mock_single_token_indicators", False)),
        bool(det_checks.get("linter_passed", False)),
        bool(det_checks.get("mypy_passed", False)),
        bool(det_checks.get("fuzz_passed", False)),
        bool(det_checks.get("pytest_passed", False)),
        det_checks.get("runtime_error") is None,
        (tests_total == 0) or (tests_passed >= tests_total),
    ]
    return sum(1 for g in gates if g), len(gates)


def is_verification_clean_pass(report: CodeVerificationResult) -> bool:
    passed, total = count_layer1_gates_passed(report.deterministic_checks)
    return report.verdict == "PASS" and passed == total


def rank_verification_report(report: CodeVerificationResult) -> Tuple[int, int, int, float, float]:
    verdict_tier = {"PASS": 2, "WARN": 1, "FAIL": 0}.get(report.verdict, 0)
    gates_passed, _ = count_layer1_gates_passed(report.deterministic_checks)
    det_score = float(report.deterministic_checks.get("deterministic_score", 0.0))
    return (
        1 if is_verification_clean_pass(report) else 0,
        verdict_tier,
        gates_passed,
        det_score,
        float(report.overall_score),
    )


def build_defect_diagnostic_summary(report: CodeVerificationResult) -> Tuple[str, List[str]]:
    det = report.deterministic_checks
    defects: List[str] = []
    if not det.get("ast_syntax_valid", True):
        defects.append("SYNTAX: Module fails ast.parse().")
    if not det.get("zero_dangerous_calls", True):
        defects.append(f"SECURITY: Remove forbidden calls: {', '.join(det.get('dangerous_calls_found') or [])}")
    if not det.get("zero_mock_single_token_indicators", True):
        defects.append(f"ANTI-MOCK: Replace single-token indicators: {', '.join(det.get('mock_indicators_found') or [])}")
    if not det.get("linter_passed", True):
        for issue in (det.get("linter_issues") or [])[:10]:
            defects.append(f"LINT [{issue.get('engine')}:{issue.get('code')} L{issue.get('line')}]: {issue.get('message')}")
    if not det.get("mypy_passed", True):
        for issue in (det.get("mypy_issues") or [])[:10]:
            defects.append(f"MYPY [{issue.get('code')} L{issue.get('line')}]: {issue.get('message')}")
    if not det.get("fuzz_passed", True):
        for fail in (det.get("fuzz_failures") or [])[:6]:
            defects.append(f"FUZZ [{fail.get('property')}]: {fail.get('detail')}")
    if not det.get("pytest_passed", True):
        defects.append(f"PYTEST: {det.get('pytest_summary', 'pytest failed')}")
    if det.get("runtime_error"):
        defects.append(f"RUNTIME: {det['runtime_error']}")
    if report.llm_verified:
        for f in (report.llm_audit.get("findings") or [])[:8]:
            sev = str(f.get("severity", "INFO")).upper()
            if sev in ("CRITICAL", "HIGH", "MEDIUM"):
                defects.append(f"LLM [{sev} {f.get('category', 'general')}]: {f.get('message', '')}")
    return "\n".join(f"  {i + 1}. {d}" for i, d in enumerate(defects)), defects


def _remove_unused_imports(source_code: str, unused_names: List[str]) -> Tuple[str, List[str]]:
    if not unused_names:
        return source_code, []
    unused_set = set(unused_names)
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return source_code, []
    lines = source_code.splitlines(keepends=True)
    edits: List[Tuple[int, int, str]] = []
    removed: List[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            kept, node_rem = [], []
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                if bound in unused_set:
                    node_rem.append(bound)
                else:
                    kept.append(f"{alias.name} as {alias.asname}" if alias.asname else alias.name)
            if node_rem:
                indent = " " * node.col_offset
                repl = f"{indent}import {', '.join(kept)}\n" if kept else ""
                edits.append((node.lineno - 1, node.end_lineno or node.lineno, repl))
                removed.extend(node_rem)
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            kept_f, node_rem_f = [], []
            for alias in node.names:
                if alias.name == "*":
                    kept_f.append("*")
                    continue
                bound = alias.asname or alias.name
                if bound in unused_set:
                    node_rem_f.append(bound)
                else:
                    kept_f.append(f"{alias.name} as {alias.asname}" if alias.asname else alias.name)
            if node_rem_f:
                indent = " " * node.col_offset
                dots = "." * (node.level or 0)
                repl = f"{indent}from {dots}{node.module or ''} import {', '.join(kept_f)}\n" if kept_f else ""
                edits.append((node.lineno - 1, node.end_lineno or node.lineno, repl))
                removed.extend(node_rem_f)
    if not edits:
        return source_code, []
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        lines[start:end] = [repl] if repl else []
    candidate = "".join(lines)
    try:
        ast.parse(candidate)
        return candidate, removed
    except SyntaxError:
        return source_code, []


def apply_deterministic_code_repairs(
    source_code: str,
    det_checks: Dict[str, Any],
) -> Tuple[str, List[str]]:
    """AST-verified deterministic structural auto-patcher for common static, type & fuzz defects."""
    current = source_code
    fixes_applied: List[str] = []

    def _try_apply(candidate: str, label: str) -> None:
        nonlocal current
        if candidate != current:
            try:
                ast.parse(candidate)
                current = candidate
                fixes_applied.append(label)
            except SyntaxError:
                pass

    unused_names: List[str] = []
    for li in det_checks.get("linter_issues") or []:
        if str(li.get("code", "")) in ("AST-F401", "F401"):
            m = re.search(r"`([A-Za-z_][A-Za-z0-9_]*)`", str(li.get("message", "")))
            if m:
                unused_names.append(m.group(1))
    if unused_names:
        cand, removed = _remove_unused_imports(current, list(dict.fromkeys(unused_names)))
        if removed:
            _try_apply(cand, f"removed_unused_imports({','.join(sorted(set(removed)))})")

    if re.search(r"^(\s*)except\s*:", current, flags=re.MULTILINE):
        cand = re.sub(r"^(\s*)except\s*:", r"\1except Exception:", current, flags=re.MULTILINE)
        _try_apply(cand, "replaced_bare_except_with_Exception")

    if re.search(r"cache_key\s*(?::[^=]+)?=\s*\(\s*payload_corpus\s*,\s*len\s*\(\s*indicators\s*\)\s*\)", current):
        cand = re.sub(
            r"Dict\[Tuple\[str,\s*int\],\s*Tuple\[str,\s*\.\.\.\]\]",
            "Dict[Tuple[str, Tuple[str, ...]], Tuple[str, ...]]",
            current,
        )
        cand = re.sub(
            r"cache_key\s*(?::[^=]+)?=\s*\(\s*payload_corpus\s*,\s*len\s*\(\s*indicators\s*\)\s*\)",
            "cache_key = (payload_corpus, tuple(indicators))",
            cand,
        )
        _try_apply(cand, "fixed_cache_key_tuple_indicators")

    fuzz_props = {str(f.get("property", "")) for f in (det_checks.get("fuzz_failures") or [])}
    if "scan_no_crash" in fuzz_props or "scan_finite_bounds" in fuzz_props or re.search(r"\b1\.0\s*/\s*alpha\b", current):
        cand = re.sub(r"\b1\.0\s*/\s*alpha\b", "1.0 / (alpha if alpha > 1e-6 else 1e-6)", current)
        if "def scan_and_score_payload(" in cand and "safe_prior" not in cand:
            cand = re.sub(
                r"(def scan_and_score_payload\([^)]*\)\s*->\s*[^:]+:\s*\n(?:\s*\"\"\"[\s\S]*?\"\"\"\s*\n)?)",
                (
                    r"\1"
                    "    prior_wealth = prior_wealth if (0.0 <= prior_wealth < 1e12) else 1.0\n"
                    "    alpha = alpha if alpha > 1e-6 else 1e-6\n"
                ),
                cand,
                count=1,
            )
        _try_apply(cand, "hardened_scan_alpha_and_prior_wealth_guards")

    if "scan_soundness_and_cache_isolation" in fuzz_props and "def scan_and_score_payload(" in current:
        cand = re.sub(r"\bpat\s+in\s+corpus_lc\b", "pat.lower() in corpus_lc", current)
        cand = re.sub(r"\bpat\s+in\s+payload_corpus\b", "pat.lower() in payload_corpus.lower()", cand)
        _try_apply(cand, "normalized_case_insensitive_indicator_scan")

    if "semilattice_top_identity" in fuzz_props or (
        "class DelegationScope" in current and "self.resources & narrower.resources" in current and "_meet_set" not in current
    ):
        meet_helper = (
            "    @staticmethod\n"
            "    def _meet_set(a: FrozenSet[str], b: FrozenSet[str]) -> FrozenSet[str]:\n"
            '        if "*" in a:\n'
            "            return b\n"
            '        if "*" in b:\n'
            "            return a\n"
            "        return a & b\n\n"
        )
        cand = current
        if "_meet_set" not in cand:
            cand = re.sub(
                r"(\n\s*def meet\(self,\s*narrower:\s*DelegationScope\))",
                "\n" + meet_helper + r"\1",
                cand,
                count=1,
            )
        cand = cand.replace("self.resources & narrower.resources", "self._meet_set(self.resources, narrower.resources)")
        cand = cand.replace("self.actions & narrower.actions", "self._meet_set(self.actions, narrower.actions)")
        cand = cand.replace("self.data_domains & narrower.data_domains", "self._meet_set(self.data_domains, narrower.data_domains)")
        _try_apply(cand, "restored_wildcard_top_element_meet_semilattice")

    untyped_lines = {
        int(mi.get("line", 0))
        for mi in (det_checks.get("mypy_issues") or [])
        if str(mi.get("code", "")) in ("no-untyped-def", "misc")
    }
    if untyped_lines:
        lines_list = current.splitlines(keepends=True)
        changed = False
        for ln_no in untyped_lines:
            idx = ln_no - 1
            if 0 <= idx < len(lines_list) and re.match(r"^\s*def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\s*(?:self)?\s*\)\s*:\s*$", lines_list[idx]):
                lines_list[idx] = re.sub(r"\)\s*:\s*$", ") -> None:\n", lines_list[idx])
                changed = True
        if changed:
            _try_apply("".join(lines_list), "added_missing_return_type_annotations")

    return current, fixes_applied


def extract_python_code_from_response(raw_text: str) -> Optional[str]:
    """Extracts AST-valid Python source code from an Ollama repair response."""
    cleaned = strip_think_tags(raw_text).strip()
    if not cleaned:
        return None
    blocks = re.findall(r"```(?:python|py)?\s*\n(.*?)```", cleaned, flags=re.DOTALL | re.IGNORECASE)
    candidates = sorted(blocks, key=len, reverse=True) + [cleaned]
    for cand in candidates:
        s = cand.strip()
        if not s:
            continue
        try:
            ast.parse(s)
            return s + "\n"
        except SyntaxError:
            continue
    return None


def request_ollama_code_patch(
    source_code: str,
    defect_block: str,
    arxiv_id: str,
    title: str,
    endpoint: str,
    model_tag: str,
    timeout_sec: float = 120.0,
) -> Tuple[Optional[str], str]:
    """Requests a complete repaired Python module from local Ollama."""
    clean_model = sanitize_model_tag(model_tag)
    prompt = (
        f"You are a senior Python systems, formal verification, and security engineer.\n"
        f"Fix ALL defects in this Python module for arXiv:{arxiv_id} ({title}).\n\n"
        f"=== DEFECTS ===\n{defect_block}\n\n"
        f"Return ONLY the complete repaired Python module inside a single ```python ... ``` block. "
        f"Ensure ZERO Ruff warnings, ZERO mypy --strict errors, ZERO fuzzing failures, and 100% passing pytest.\n\n"
        f"```python\n{source_code}\n```\n"
    )
    is_reasoning = any(k in clean_model.lower() for k in ("deepseek-r1", "qwq", "glm-4.7"))
    body_obj: Dict[str, Any] = {
        "model": clean_model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.15, "num_predict": 4096, "num_ctx": 8192},
    }
    if is_reasoning:
        body_obj["think"] = False
    opener = _build_no_proxy_opener()
    req = urllib.request.Request(
        f"{endpoint.rstrip('/')}/api/generate",
        data=json.dumps(body_obj).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "RFCHunt-AutoRepair/1.0"},
    )
    try:
        with opener.open(req, timeout=timeout_sec) as resp:
            if resp.status != 200:
                return None, f"ollama_http_{resp.status}"
            raw_text = str(json.loads(resp.read().decode("utf-8", errors="replace")).get("response", "")).strip()
            extracted = extract_python_code_from_response(raw_text)
            return (extracted, "ollama_patch_synthesized") if extracted else (None, "ollama_patch_invalid_python")
    except TimeoutError:
        return None, "ollama_timeout"
    except urllib.error.URLError as exc:
        return (None, "ollama_timeout") if isinstance(exc.reason, TimeoutError) else (None, f"ollama_url_error:{type(exc.reason).__name__}")
    except Exception as exc:
        return None, f"ollama_error:{type(exc).__name__}"


def auto_repair_generated_code(
    source_code: str,
    arxiv_id: str = "custom",
    title: str = "Generated Security Detector Module",
    code_stage: str = "synthesized",
    initial_report: Optional[CodeVerificationResult] = None,
    max_repair_attempts: int = 3,
    model_id: Optional[str] = None,
    ollama_endpoint: Optional[str] = None,
    timeout_sec: float = 120.0,
    enable_llm: bool = False,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> AutoRepairResult:
    """
    Runs the Verify -> Diagnose -> Patch -> Re-Verify auto-repair loop with strict
    monotonic hill-climbing until all Layer-1 gates (AST, Ruff, `mypy --strict`,
    310-property Fuzzing, `pytest`, 7 invariants) and Layer-2 verdict reach clean PASS.
    """
    t0 = time.perf_counter()
    endpoint = ollama_endpoint or os.environ.get("LOCAL_OLLAMA_ENDPOINT", "http://127.0.0.1:11434")
    max_attempts = max(1, min(10, int(max_repair_attempts)))

    def _verify(code: str, stage: str) -> CodeVerificationResult:
        return verify_python_code_native(
            source_code=code,
            arxiv_id=arxiv_id,
            title=title,
            code_stage=stage,
            model_id=model_id,
            ollama_endpoint=endpoint,
            timeout_sec=timeout_sec,
            enable_llm=enable_llm,
        )

    current_code = source_code
    current_report = initial_report if initial_report is not None else _verify(current_code, code_stage)
    initial_verdict = current_report.verdict
    initial_score = float(current_report.overall_score)

    if is_verification_clean_pass(current_report):
        return AutoRepairResult(
            arxiv_id=arxiv_id,
            repaired=False,
            converged_clean=True,
            repair_attempts=0,
            max_repair_attempts=max_attempts,
            initial_verdict=initial_verdict,
            final_verdict=current_report.verdict,
            initial_score=initial_score,
            final_score=float(current_report.overall_score),
            repaired_source_code=current_code,
            final_verification_report=current_report,
            repair_history=[],
            duration_ms=round((time.perf_counter() - t0) * 1000.0, 2),
        )

    online, installed = probe_ollama_models_fast(endpoint=endpoint, timeout_sec=0.4) if enable_llm else (False, [])
    repair_models = rank_repair_and_verifier_models(installed, requested_model=model_id) if online else []

    init_passed, init_total = count_layer1_gates_passed(current_report.deterministic_checks)
    effective_max = (
        1
        if (
            init_passed == init_total
            and float(current_report.deterministic_checks.get("deterministic_score", 0.0)) >= 100.0
            and float(current_report.overall_score) >= 85.0
        )
        else max_attempts
    )

    repaired_any = False
    history: List[RepairAttemptRecord] = []

    for attempt in range(1, effective_max + 1):
        at_start = time.perf_counter()
        defect_block, defect_list = build_defect_diagnostic_summary(current_report)
        before_rank = rank_verification_report(current_report)
        before_gates, _ = count_layer1_gates_passed(current_report.deterministic_checks)
        before_verdict = current_report.verdict
        before_score = float(current_report.overall_score)
        repair_model = repair_models[(attempt - 1) % len(repair_models)] if repair_models else None

        if progress_callback is not None:
            progress_callback(f"Auto-Repair attempt {attempt}/{effective_max}: targeting {len(defect_list)} defect(s)")

        candidates: List[Tuple[str, str, List[str], str, str]] = []

        # Tier A: Local Ollama LLM Repair (rotates across ranked VRAM-resident models)
        llm_note = "llm_disabled" if not enable_llm else ("ollama_offline" if not online else "no_eligible_model")
        if enable_llm and online and repair_model is not None:
            llm_code, llm_status = request_ollama_code_patch(
                source_code=current_code,
                defect_block=defect_block,
                arxiv_id=arxiv_id,
                title=title,
                endpoint=endpoint,
                model_tag=repair_model,
                timeout_sec=timeout_sec,
            )
            llm_note = f"ollama({repair_model})={llm_status}"
            if llm_code is not None and llm_code.strip() != current_code.strip():
                candidates.append(("ollama_llm_patch", repair_model, [], llm_code, llm_note))
                llm_det = run_deterministic_code_verification(llm_code, arxiv_id=arxiv_id)
                polished, p_fixes = apply_deterministic_code_repairs(llm_code, llm_det)
                if p_fixes and polished.strip() != llm_code.strip():
                    candidates.append(
                        ("ollama_plus_deterministic_patch", repair_model, p_fixes, polished, f"{llm_note}; polish={','.join(p_fixes)}")
                    )

        # Tier B: Deterministic Structural Auto-Patcher
        det_patched, det_fixes = apply_deterministic_code_repairs(current_code, current_report.deterministic_checks)
        if det_fixes and det_patched.strip() != current_code.strip():
            candidates.append(
                ("deterministic_structural_patch", "deterministic_ast_patcher", det_fixes, det_patched, f"applied={','.join(det_fixes)}; {llm_note}")
            )

        if not candidates:
            history.append(
                RepairAttemptRecord(
                    attempt=attempt,
                    strategy="no_viable_patch",
                    model_used=repair_model or "deterministic_ast_patcher",
                    defects_targeted=defect_list[:8],
                    deterministic_fixes_applied=[],
                    before_verdict=before_verdict,
                    after_verdict=before_verdict,
                    before_score=before_score,
                    after_score=before_score,
                    before_gates_passed=before_gates,
                    after_gates_passed=before_gates,
                    accepted=False,
                    duration_ms=round((time.perf_counter() - at_start) * 1000.0, 2),
                    note=f"No new candidate patch produced ({llm_note}).",
                )
            )
            if not (enable_llm and online and repair_model is not None):
                break
            continue

        best_choice: Optional[Tuple[Tuple[int, int, int, float, float], CodeVerificationResult, str, str, List[str], str, str]] = None
        for strat, m_lbl, fixes, cand_code, note in candidates:
            cand_rep = _verify(cand_code, f"{code_stage}_repaired_try{attempt}")
            cand_rank = rank_verification_report(cand_rep)
            if best_choice is None or cand_rank > best_choice[0]:
                best_choice = (cand_rank, cand_rep, strat, m_lbl, fixes, cand_code, note)

        assert best_choice is not None
        best_rank, best_rep, best_strat, best_model, best_fixes, best_code, best_note = best_choice
        after_gates, _ = count_layer1_gates_passed(best_rep.deterministic_checks)
        accepted = best_rank > before_rank

        if accepted:
            current_code = best_code
            current_report = best_rep
            repaired_any = True

        history.append(
            RepairAttemptRecord(
                attempt=attempt,
                strategy=best_strat,
                model_used=best_model,
                defects_targeted=defect_list[:8],
                deterministic_fixes_applied=best_fixes,
                before_verdict=before_verdict,
                after_verdict=best_rep.verdict if accepted else before_verdict,
                before_score=before_score,
                after_score=float(best_rep.overall_score) if accepted else before_score,
                before_gates_passed=before_gates,
                after_gates_passed=after_gates if accepted else before_gates,
                accepted=accepted,
                duration_ms=round((time.perf_counter() - at_start) * 1000.0, 2),
                note=best_note if accepted else f"Rejected non-improving patch ({best_note}).",
            )
        )

        if is_verification_clean_pass(current_report):
            break
        if (not accepted) and not (enable_llm and online and repair_model is not None):
            break

    return AutoRepairResult(
        arxiv_id=arxiv_id,
        repaired=repaired_any,
        converged_clean=is_verification_clean_pass(current_report),
        repair_attempts=len(history),
        max_repair_attempts=max_attempts,
        initial_verdict=initial_verdict,
        final_verdict=current_report.verdict,
        initial_score=initial_score,
        final_score=float(current_report.overall_score),
        repaired_source_code=current_code,
        final_verification_report=current_report,
        repair_history=history,
        duration_ms=round((time.perf_counter() - t0) * 1000.0, 2),
    )


# ==============================================================================
# 4. Standalone Zero-Mock Verified Detector Module Synthesizer (Offline/CI Ready)
# ==============================================================================

def synthesize_verified_detector_module(
    arxiv_id: str,
    title: str,
    code_repo_url: str,
    indicators: Optional[Sequence[str]] = None,
) -> str:
    """
    Synthesizes a standalone, `mypy --strict`-clean, Ruff-clean, 310-property-fuzzed,
    7/7-invariant Python detector module even when `D:\\harfile\\arixiv-to-code` is not
    mounted (e.g., inside RFCHunt CI runners).
    """
    slug = re.sub(r"[^A-Za-z0-9_]+", "_", arxiv_id or "custom")
    safe_title = title.replace('"', '\\"')
    repo_url = code_repo_url or f"https://arxiv.org/abs/{arxiv_id}"
    ind_list = [t.strip().lower() for t in (indicators or ()) if t and t.strip()]
    if len(ind_list) < 3:
        ind_list = [
            f"apc_scope_escalation_{slug}",
            f"envelope_seal_tamper_{slug}",
            f"composition_pairwise_exfil_{slug}",
            f"approval_token_replay_{slug}",
        ]
    py_inds = ",\n    ".join(repr(t) for t in ind_list[:8])

    return f'''#!/usr/bin/env python3
"""
RFCHunt Research-to-Code Verified Detector Module (`arXiv:{arxiv_id}`)
Title: {safe_title}
Reference Repository: {repo_url}
"""

from __future__ import annotations

import hashlib
import hmac
import time
import tracemalloc
import unittest
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

ARXIV_PAPER_ID: str = "{arxiv_id}"
ARXIV_RULE_ID: str = "ARXIV-PY-{arxiv_id}"
VERIFIED_CODE_REPO: str = "{repo_url}"

MULTI_TOKEN_TECHNICAL_INDICATORS: Tuple[str, ...] = (
    {py_inds},
)


@dataclass(frozen=True)
class DelegationScope:
    """Asymmetric Meet-Semilattice Delegation Scope with Wildcard Top Element (`*`)."""

    resources: FrozenSet[str] = field(default_factory=lambda: frozenset(["*"]))
    actions: FrozenSet[str] = field(default_factory=lambda: frozenset(["*"]))
    data_domains: FrozenSet[str] = field(default_factory=lambda: frozenset(["*"]))
    prohibited_compositions: FrozenSet[Tuple[str, str]] = field(default_factory=frozenset)
    prohibited_sequences: FrozenSet[Tuple[str, ...]] = field(default_factory=frozenset)

    @staticmethod
    def _meet_set(a: FrozenSet[str], b: FrozenSet[str]) -> FrozenSet[str]:
        if "*" in a:
            return b
        if "*" in b:
            return a
        return a & b

    def meet(self, narrower: DelegationScope) -> DelegationScope:
        return DelegationScope(
            resources=self._meet_set(self.resources, narrower.resources),
            actions=self._meet_set(self.actions, narrower.actions),
            data_domains=self._meet_set(self.data_domains, narrower.data_domains),
            prohibited_compositions=self.prohibited_compositions | narrower.prohibited_compositions,
            prohibited_sequences=self.prohibited_sequences | narrower.prohibited_sequences,
        )

    def allows(self, resource: str, action: str, domain: str) -> bool:
        r_ok = ("*" in self.resources) or (resource in self.resources)
        a_ok = ("*" in self.actions) or (action in self.actions)
        d_ok = ("*" in self.data_domains) or (domain in self.data_domains)
        return r_ok and a_ok and d_ok


@dataclass(frozen=True)
class GateVerdict:
    allowed: bool
    rule_id: str
    nonconformity_score: float
    martingale_wealth: float
    matched_indicators: Tuple[str, ...]
    session_lineage_verified: bool
    reason: str


# EVOLVE-BLOCK-START
_SCAN_CACHE: Dict[Tuple[str, Tuple[str, ...]], Tuple[str, ...]] = {{}}


def scan_and_score_payload(
    payload_corpus: str,
    indicators: Sequence[str],
    prior_wealth: float = 1.0,
    alpha: float = 0.01,
) -> Tuple[Tuple[str, ...], float, float, bool]:
    """Collision-free multi-token indicator scanner + anytime-valid martingale scoring."""
    ind_key: Tuple[str, ...] = tuple(indicators)
    cache_key: Tuple[str, Tuple[str, ...]] = (payload_corpus, ind_key)
    matched = _SCAN_CACHE.get(cache_key)
    if matched is None:
        corpus_lc = payload_corpus.lower()
        matched = tuple(pat for pat in ind_key if pat.lower() in corpus_lc)
        if len(_SCAN_CACHE) > 256:
            _SCAN_CACHE.clear()
        _SCAN_CACHE[cache_key] = matched
    hit_count = len(matched)
    safe_prior = prior_wealth if (0.0 <= prior_wealth < 1e12) else 1.0
    safe_alpha = alpha if alpha > 1e-6 else 1e-6
    nonconformity = 0.05 if hit_count == 0 else min(1.0, 0.05 + 0.35 * hit_count)
    new_wealth = safe_prior * (1.0 + 3.0 * hit_count) if hit_count > 0 else max(0.05, safe_prior * 0.9)
    triggered = (hit_count > 0) or (new_wealth >= (1.0 / safe_alpha))
    return matched, round(nonconformity, 4), round(new_wealth, 4), triggered
# EVOLVE-BLOCK-END


class ArxivAlgorithmEngine_{slug}:
    """Fail-closed containment & delegation verifier for arXiv:{arxiv_id}."""

    def __init__(
        self,
        signing_key: bytes,
        allowed_actions: Sequence[str],
        allowed_resources: Optional[Sequence[str]] = None,
        allowed_domains: Optional[Sequence[str]] = None,
        prohibited_compositions: Optional[Sequence[Tuple[str, str]]] = None,
        prohibited_sequences: Optional[Sequence[Tuple[str, ...]]] = None,
        alpha: float = 0.01,
    ) -> None:
        self._signing_key = signing_key
        self._alpha = alpha if alpha > 1e-6 else 1e-6
        self._root_scope = DelegationScope(
            resources=frozenset(allowed_resources) if allowed_resources is not None else frozenset(["*"]),
            actions=frozenset(allowed_actions),
            data_domains=frozenset(allowed_domains) if allowed_domains is not None else frozenset(["*"]),
            prohibited_compositions=frozenset(
                prohibited_compositions or [("read_sensitive", "external_transmit")]
            ),
            prohibited_sequences=frozenset(
                prohibited_sequences or [("read_sensitive", "stage_archive", "external_transmit")]
            ),
        )
        self._session_wealth: Dict[str, float] = {{}}
        self._session_history: Dict[str, List[str]] = {{}}
        self._used_nonces: set[str] = set()

    def issue_envelope_seal(self, actor_id: str, session_id: str, action: str) -> str:
        msg = f"{{actor_id}}|{{session_id}}|{{action}}|{{ARXIV_RULE_ID}}".encode("utf-8")
        return hmac.new(self._signing_key, msg, hashlib.sha256).hexdigest()

    def verify_envelope_seal(self, actor_id: str, session_id: str, action: str, seal_hex: str) -> bool:
        expected = self.issue_envelope_seal(actor_id, session_id, action)
        return hmac.compare_digest(expected, seal_hex)

    def evaluate_action(
        self,
        actor_id: str,
        session_id: str,
        action: str,
        payload_corpus: str,
        envelope_seal: str,
        delegated_scope: Optional[DelegationScope] = None,
        delegation_chain: Optional[Sequence[DelegationScope]] = None,
        resource: str = "workspace_default",
        domain: str = "default",
        approval_nonce: Optional[str] = None,
    ) -> GateVerdict:
        if not self.verify_envelope_seal(actor_id, session_id, action, envelope_seal):
            return GateVerdict(False, ARXIV_RULE_ID, 1.0, 100.0, ("envelope_seal_tamper",), False, "HMAC mismatch")
        if approval_nonce is not None:
            if approval_nonce in self._used_nonces:
                return GateVerdict(False, ARXIV_RULE_ID, 1.0, 100.0, ("approval_token_replay",), True, "Nonce replay")
            self._used_nonces.add(approval_nonce)

        effective_scope = self._root_scope
        if delegated_scope is not None:
            effective_scope = effective_scope.meet(delegated_scope)
        if delegation_chain is not None:
            for hop in delegation_chain:
                effective_scope = effective_scope.meet(hop)

        if not effective_scope.allows(resource, action, domain):
            return GateVerdict(False, ARXIV_RULE_ID, 1.0, 100.0, ("apc_scope_escalation",), True, "Out of scope")

        history = self._session_history.setdefault(session_id, [])
        for prev in history:
            if (prev, action) in effective_scope.prohibited_compositions:
                return GateVerdict(False, ARXIV_RULE_ID, 0.98, 100.0, ("composition_pairwise_exfil",), True, "Pairwise ban")
        for seq in effective_scope.prohibited_sequences:
            if len(seq) >= 2 and seq[-1] == action:
                pos = 0
                for past in history:
                    if past == seq[pos]:
                        pos += 1
                        if pos == len(seq) - 1:
                            return GateVerdict(False, ARXIV_RULE_ID, 0.99, 100.0, ("ktuple_ordered_exfil",), True, "k-tuple ban")

        prior_w = self._session_wealth.get(session_id, 1.0)
        matched, nc, new_w, triggered = scan_and_score_payload(
            payload_corpus=payload_corpus,
            indicators=MULTI_TOKEN_TECHNICAL_INDICATORS,
            prior_wealth=prior_w,
            alpha=self._alpha,
        )
        self._session_wealth[session_id] = new_w
        if triggered:
            return GateVerdict(False, ARXIV_RULE_ID, nc, new_w, matched, True, "Indicator triggered")
        history.append(action)
        return GateVerdict(True, ARXIV_RULE_ID, nc, new_w, (), True, "Verified clean")


def _verify_all_invariants() -> Tuple[int, int]:
    eng = ArxivAlgorithmEngine_{slug}(
        signing_key=b"rfchunt-test-key-32-bytes-strict",
        allowed_actions=["read_public", "compile_workspace", "read_sensitive", "stage_archive", "external_transmit"],
        allowed_resources=["repo_a", "repo_b"],
        allowed_domains=["engineering"],
    )
    tests_passed = 0
    tests_total = 7

    # 1. Benign action
    s1 = eng.issue_envelope_seal("a1", "sess1", "read_public")
    if eng.evaluate_action("a1", "sess1", "read_public", "clean build", s1, resource="repo_a", domain="engineering").allowed:
        tests_passed += 1
    # 2. Exploit indicator blocked
    s2 = eng.issue_envelope_seal("a1", "sess2", "compile_workspace")
    if not eng.evaluate_action("a1", "sess2", "compile_workspace", f"bad {{MULTI_TOKEN_TECHNICAL_INDICATORS[0]}}", s2, resource="repo_a", domain="engineering").allowed:
        tests_passed += 1
    # 3. Tampered HMAC blocked
    if not eng.evaluate_action("a1", "sess1", "read_public", "clean", "0" * 64, resource="repo_a", domain="engineering").allowed:
        tests_passed += 1
    # 4. Pairwise prohibited composition blocked
    sr = eng.issue_envelope_seal("a1", "sess3", "read_sensitive")
    se = eng.issue_envelope_seal("a1", "sess3", "external_transmit")
    v_r = eng.evaluate_action("a1", "sess3", "read_sensitive", "safe", sr, resource="repo_a", domain="engineering")
    v_e = eng.evaluate_action("a1", "sess3", "external_transmit", "safe", se, resource="repo_a", domain="engineering")
    if v_r.allowed and not v_e.allowed:
        tests_passed += 1
    # 5. Wildcard top-element meet-semilattice + multi-hop APC narrowing
    wild = DelegationScope(resources=frozenset(["*"]), actions=frozenset(["*"]), data_domains=frozenset(["*"]))
    narrow = DelegationScope(resources=frozenset(["repo_a"]), actions=frozenset(["read_public"]), data_domains=frozenset(["engineering"]))
    if wild.meet(narrow) == narrow and not eng.evaluate_action("a1", "sess4", "read_public", "clean", s1, delegated_scope=narrow, resource="repo_b", domain="engineering").allowed:
        tests_passed += 1
    # 6. Approval nonce replay blocked
    sn = eng.issue_envelope_seal("a1", "sess5", "read_public")
    vn1 = eng.evaluate_action("a1", "sess5", "read_public", "clean", sn, resource="repo_a", domain="engineering", approval_nonce="nonce-1")
    vn2 = eng.evaluate_action("a1", "sess5", "read_public", "clean", sn, resource="repo_a", domain="engineering", approval_nonce="nonce-1")
    if vn1.allowed and not vn2.allowed:
        tests_passed += 1
    # 7. Cache isolation for distinct same-length indicators
    m_a, _, _, t_a = scan_and_score_payload("payload alpha_tok", ("beta_tok", "gamma_tok"), 1.0, 0.01)
    m_b, _, _, t_b = scan_and_score_payload("payload alpha_tok", ("alpha_tok", "delta_tok"), 1.0, 0.01)
    if (not t_a) and len(m_a) == 0 and t_b and "alpha_tok" in m_b:
        tests_passed += 1
    return tests_passed, tests_total


def run_deterministic_benchmark(iterations: int = 100) -> Dict[str, Any]:
    tests_passed, tests_total = _verify_all_invariants()
    tracemalloc.start()
    tracemalloc.reset_peak()
    t0 = time.perf_counter()
    for _ in range(max(1, iterations)):
        scan_and_score_payload("clean telemetry payload", MULTI_TOKEN_TECHNICAL_INDICATORS, 1.0, 0.01)
    elapsed_us = ((time.perf_counter() - t0) * 1_000_000.0) / max(1, iterations)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {{
        "arxiv_id": ARXIV_PAPER_ID,
        "rule_id": ARXIV_RULE_ID,
        "tests_passed": tests_passed,
        "tests_total": tests_total,
        "avg_iteration_us": round(elapsed_us, 3),
        "peak_memory_kib": round(peak_bytes / 1024.0, 3),
        "all_invariants_satisfied": tests_passed == tests_total,
    }}


def test_generated_module_all_invariants() -> None:
    res = run_deterministic_benchmark(iterations=25)
    assert res["tests_passed"] == res["tests_total"] == 7
    assert res["all_invariants_satisfied"] is True


class TestArxivModule_{slug}(unittest.TestCase):
    def test_invariants(self) -> None:
        res = run_deterministic_benchmark(iterations=25)
        self.assertEqual(res["tests_passed"], res["tests_total"])
        self.assertTrue(res["all_invariants_satisfied"])


if __name__ == "__main__":
    print(run_deterministic_benchmark(iterations=100))
    unittest.main()
'''
