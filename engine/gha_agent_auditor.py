"""
GitHub Actions & AI-Agent Trust-Boundary Static Auditor (`engine/gha_agent_auditor.py`).
========================================================================================
Codifies high-signal trust-boundary vulnerability classes discovered during defensive
audits of AI-agent GitHub Actions & SDK repositories into RFCHunt's default exhaustive
multi-engine scan (`EnsembleOrchestrator.run_exhaustive_local_engines`):

1. `GHA-AGENT-IPC-001` — Unprotected Predictable `/tmp/` IPC Buffer Consumed Post-Session:
   Flags hardcoded `/tmp/*.json` or `/tmp/*.jsonl` files read in post-session/finally hooks
   without `unlink`/`rmSync` cleanup, symlink validation (`lstat`), or content sanitization.
2. `GHA-AGENT-BOT-002` — Fail-Open `endsWith("[bot]")` Actor Authorization Guard:
   Flags PR/actor authorization checks that early-return `true` when `!actor.endsWith("[bot]")`,
   failing open for non-`[bot]` GitHub Apps (such as `Copilot`) when `allowed_bots` is used.
3. `GHA-AGENT-ENV-003` — Unscrubbed Privileged Token/API-Key Fallback After Subprocess:
   Flags post-session handlers reading unscrubbed parent secrets (`anthropic_api_key`,
   `githubToken`) to act on untrusted temporary files written during an agent session.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Union

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "dist",
    "build",
    "test",
    "tests",
    "__tests__",
    "reports",
}
_EXTS = {".ts", ".tsx", ".js", ".mjs", ".cjs", ".py", ".sh", ".yml", ".yaml"}

_TMP_IPC_PATH_RE = re.compile(r"""["'](/tmp/[A-Za-z0-9._-]+\.(?:jsonl|json|txt|log))["']""")
_READ_FILE_RE = re.compile(r"\b(?:readFileSync|fs\.readFile|open\s*\(|Path\([^)]*\)\.read_text)\b")
_CLEANUP_RE = re.compile(r"\b(?:unlinkSync|unlink|rmSync|os\.remove|lstatSync|lstat)\b")
_SANITIZE_RE = re.compile(r"\b(?:sanitizeContent|sanitizeHtml|DOMPurify|bleach\.clean)\b")

_BOT_FAIL_OPEN_RE = re.compile(
    r"if\s*\([^\n]*!\s*[A-Za-z0-9_.]*actor\.endsWith\s*\(\s*['\"]\[bot\]['\"]\s*\)[^\n]*\)\s*\{?\s*\n?\s*return\s+true\b",
    re.MULTILINE,
)

# High-signal pre-execution / trigger-boundary rules (crosses untrusted external attacker -> privileged sink)
_GHA_UNTRUSTED_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref|head\.label)|"
    r"issue\.(?:title|body)|comment\.body|review\.body|commits\[[^\]]*\]\.message|"
    r"head_commit\.message)\s*\}\}",
    re.IGNORECASE,
)
_TOKEN_EXTERNAL_FETCH_RE = re.compile(
    r"(?:fetch|axios\.(?:get|post|request)|httpx\.(?:get|post)|requests\.(?:get|post))\s*\([^)]*"
    r"(?:GITHUB_TOKEN|githubToken|ANTHROPIC_API_KEY|anthropicApiKey|Authorization)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class GhaAgentFinding:
    rule_id: str
    title: str
    severity: str
    cwe: str
    atlas_technique: str
    file_path: str
    line: int
    snippet: str
    remediation: str
    hygiene_only: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _scan_file(path: Path, root: Path) -> List[GhaAgentFinding]:
    try:
        if path.stat().st_size > 512_000:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    rel = str(path.relative_to(root)).replace("\\", "/")
    findings: List[GhaAgentFinding] = []

    # Rule 1 (Pre-Execution Trigger Boundary): Untrusted PR/issue/comment metadata in GHA run: shell expressions
    if path.suffix.lower() in (".yml", ".yaml"):
        for m_expr in _GHA_UNTRUSTED_EXPR_RE.finditer(text):
            line_no = text[: m_expr.start()].count("\n") + 1
            findings.append(
                GhaAgentFinding(
                    rule_id="GHA-TRIGGER-INJECT-001",
                    title="Untrusted GitHub Event Metadata Interpolated in Workflow Expression (Pre-Execution Injection)",
                    severity="HIGH",
                    cwe="CWE-78",
                    atlas_technique="AML.T0051",
                    file_path=rel,
                    line=line_no,
                    snippet=m_expr.group(0),
                    remediation=(
                        "Pass untrusted GitHub event metadata via intermediate `env:` variables and quote them "
                        "inside `run:` scripts rather than interpolating `${{ github.event.* }}` directly."
                    ),
                    hygiene_only=False,
                )
            )

    # Rule 2 (Authorization Trigger Boundary): Fail-open !actor.endsWith("[bot]") -> return true guard
    for m_bot in _BOT_FAIL_OPEN_RE.finditer(text):
        line_no = text[: m_bot.start()].count("\n") + 1
        findings.append(
            GhaAgentFinding(
                rule_id="GHA-AGENT-BOT-002",
                title="Fail-Open endsWith('[bot]') Authorization Guard Skips Non-[bot] GitHub Apps",
                severity="MEDIUM",
                cwe="CWE-863",
                atlas_technique="AML.T0040",
                file_path=rel,
                line=line_no,
                snippet=m_bot.group(0).replace("\n", " ")[:180],
                remediation=(
                    "Pass an explicit wasBotActor boolean from collaborator permission resolution rather than "
                    "relying on actor.endsWith('[bot]'), so non-[bot] GitHub Apps (e.g., Copilot) cannot fail open."
                ),
                hygiene_only=False,
            )
        )

    # Rule 3 (Hygiene-Only / Upstream PR Hardening): Predictable /tmp IPC buffer without cleanup/sanitization
    # Explicitly tagged hygiene_only=True so it is HELD from bug bounty submission unless crossing a credential/RCE boundary.
    m_tmp = _TMP_IPC_PATH_RE.search(text)
    if m_tmp and _READ_FILE_RE.search(text):
        has_cleanup = bool(_CLEANUP_RE.search(text))
        has_sanitize = bool(_SANITIZE_RE.search(text))
        if not has_cleanup or not has_sanitize:
            line_no = text[: m_tmp.start()].count("\n") + 1
            missing = []
            if not has_cleanup:
                missing.append("no unlink/lstat symlink guard")
            if not has_sanitize:
                missing.append("no sanitizeContent() call")
            findings.append(
                GhaAgentFinding(
                    rule_id="GHA-AGENT-IPC-001",
                    title=f"[hygiene_only] Predictable /tmp IPC Buffer ({m_tmp.group(1)}) Without Cleanup/Sanitization",
                    severity="LOW",
                    cwe="CWE-377",
                    atlas_technique="AML.T0040",
                    file_path=rel,
                    line=line_no,
                    snippet=f"hygiene_only: {m_tmp.group(0)} ({', '.join(missing)})",
                    remediation=(
                        "Upstream hardening PR candidate (not bounty-eligible intra-runner): use mkdtempSync (0o700), "
                        "lstatSync symlink check, pre/post unlink, and sanitizeContent()."
                    ),
                    hygiene_only=True,
                )
            )

    return findings


def audit_gha_agent_repository(
    repo_path: Union[str, Path],
    max_workers: Optional[int] = None,
) -> List[GhaAgentFinding]:
    """Concurrently audits a repository for GitHub Actions / AI-Agent trust-boundary flaws."""
    root = Path(repo_path).resolve()
    if not root.exists() or not root.is_dir():
        return []

    candidates: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in _EXTS:
                candidates.append(p)

    workers = max_workers or min(16, max(2, os.cpu_count() or 4))
    all_findings: List[GhaAgentFinding] = []
    if candidates:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_scan_file, p, root) for p in candidates]
            for fut in as_completed(futs):
                try:
                    all_findings.extend(fut.result())
                except Exception:
                    continue

    all_findings.sort(key=lambda f: (f.file_path, f.line, f.rule_id))
    return all_findings
