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

from engine.gha_workflow_scanners import (
    GHA_CLASS_AI_AGENT_BOUNDARY,
    GhaWorkflowFinding,
    discover_workflow_files,
    gha_findings_to_sarif,
    scan_single_workflow_yaml_for_gha_agent,
)

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
    gha_class: str = ""
    deterministic: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_workflow_finding(self) -> GhaWorkflowFinding:
        return GhaWorkflowFinding(
            engine="gha_agent",
            rule_id=self.rule_id,
            gha_class=self.gha_class or GHA_CLASS_AI_AGENT_BOUNDARY,
            title=self.title,
            severity=self.severity,
            cwe=self.cwe,
            atlas_technique=self.atlas_technique,
            file_path=self.file_path,
            line=self.line,
            snippet=self.snippet,
            remediation=self.remediation,
            execution_mode="python_parity",
            hygiene_only=self.hygiene_only,
            deterministic=self.deterministic,
            confirmed=True,
            metadata=dict(self.metadata),
        )

    def to_sarif_result(self) -> Dict[str, Any]:
        return self.to_workflow_finding().to_sarif_result()


def _scan_file(path: Path, root: Path) -> List[GhaAgentFinding]:
    try:
        if path.stat().st_size > 512_000:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    try:
        rel = str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        rel = path.name
    findings: List[GhaAgentFinding] = []

    # Rule 1 (YAML Structural R1 Analysis): Covers all 7 GHA vulnerability classes with env:-binding FP mitigation
    if path.suffix.lower() in (".yml", ".yaml"):
        wf_findings = scan_single_workflow_yaml_for_gha_agent(path, root)
        for wf in wf_findings:
            findings.append(
                GhaAgentFinding(
                    rule_id=wf.rule_id,
                    title=wf.title,
                    severity=wf.severity,
                    cwe=wf.cwe,
                    atlas_technique=wf.atlas_technique,
                    file_path=wf.file_path,
                    line=wf.line,
                    snippet=wf.snippet,
                    remediation=wf.remediation,
                    hygiene_only=wf.hygiene_only,
                    gha_class=wf.gha_class,
                    deterministic=True,
                    metadata=dict(wf.metadata),
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
                gha_class=GHA_CLASS_AI_AGENT_BOUNDARY,
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
                    gha_class=GHA_CLASS_AI_AGENT_BOUNDARY,
                )
            )

    # Rule 4 (`GHA-AGENT-ENV-003`): Unscrubbed privileged token/API-key forwarded to external HTTP fetch
    # paired with untrusted /tmp buffer or GitHub event payload
    if path.suffix.lower() not in (".yml", ".yaml"):
        for m_tok in _TOKEN_EXTERNAL_FETCH_RE.finditer(text):
            call_txt = m_tok.group(0)
            is_trusted_api = bool(
                re.search(r"https://api\.(?:github|anthropic|openai)\.com", call_txt, re.IGNORECASE)
            )
            has_untrusted_ctx = bool(_TMP_IPC_PATH_RE.search(text) or "github.event" in text or not is_trusted_api)
            if has_untrusted_ctx:
                line_no = text[: m_tok.start()].count("\n") + 1
                findings.append(
                    GhaAgentFinding(
                        rule_id="GHA-AGENT-ENV-003",
                        title="Unscrubbed Privileged Token/API-Key Used in External HTTP Fetch Over Untrusted Context",
                        severity="HIGH",
                        cwe="CWE-522",
                        atlas_technique="AML.T0051",
                        file_path=rel,
                        line=line_no,
                        snippet=call_txt.replace("\n", " ")[:180],
                        remediation=(
                            "Scrub privileged tokens from subprocess/post-session environments and restrict outbound "
                            "requests strictly to pinned GitHub/API endpoints with sanitized payloads."
                        ),
                        hygiene_only=False,
                        gha_class=GHA_CLASS_AI_AGENT_BOUNDARY,
                    )
                )

    return findings


def audit_gha_agent_repository(
    repo_path: Union[str, Path],
    max_workers: Optional[int] = None,
) -> List[GhaAgentFinding]:
    """Concurrently audits a repository for GitHub Actions / AI-Agent trust-boundary flaws."""
    root = Path(repo_path).resolve()
    if not root.exists():
        return []
    if root.is_file():
        if root.suffix.lower() in _EXTS:
            return _scan_file(root, root.parent)
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


def audit_gha_workflows(
    target_path: Union[str, Path],
    max_workers: Optional[int] = None,
) -> List[GhaAgentFinding]:
    """
    Audits a single workflow YAML file, a `.github/workflows` directory, or a repository
    for all 7 R1 GitHub Actions & AI-agent vulnerability classes (including cross-workflow
    artifact poisoning correlation), without skipping explicitly targeted fixture directories.
    """
    target = Path(target_path).resolve()
    if not target.exists():
        return []

    root, wf_files = discover_workflow_files(target)
    findings: List[GhaAgentFinding] = []
    if target.is_dir():
        findings.extend(audit_gha_agent_repository(target, max_workers=max_workers))
    elif target.is_file() and target.suffix.lower() in _EXTS:
        findings.extend(_scan_file(target, root))

    # Ensure workflow files directly targeted (even under test temp dirs) and cross-workflow chains are included
    seen = {(f.file_path, f.line, f.rule_id) for f in findings}
    if wf_files:
        for wf in wf_files:
            for item in scan_single_workflow_yaml_for_gha_agent(wf, root):
                k = (item.file_path, item.line, item.rule_id)
                if k not in seen:
                    seen.add(k)
                    findings.append(
                        GhaAgentFinding(
                            rule_id=item.rule_id,
                            title=item.title,
                            severity=item.severity,
                            cwe=item.cwe,
                            atlas_technique=item.atlas_technique,
                            file_path=item.file_path,
                            line=item.line,
                            snippet=item.snippet,
                            remediation=item.remediation,
                            hygiene_only=item.hygiene_only,
                            gha_class=item.gha_class,
                            deterministic=True,
                            metadata=dict(item.metadata),
                        )
                    )
        # Cross-workflow artifact poisoning check when scanning multiple workflows
        if len(wf_files) >= 2:
            from engine.gha_workflow_scanners import _load_parsed_workflows, _run_zizmor_parity_on_docs

            _, _, parsed_docs, _ = _load_parsed_workflows(target)
            for item in _run_zizmor_parity_on_docs(parsed_docs):
                if item.rule_id == "ZIZMOR-PY-CROSS-WF-ARTIFACT-POISONING":
                    k = (item.file_path, item.line, "GHA-ARTIFACT-POISON-002")
                    if k not in seen:
                        seen.add(k)
                        findings.append(
                            GhaAgentFinding(
                                rule_id="GHA-ARTIFACT-POISON-002",
                                title=item.title,
                                severity=item.severity,
                                cwe=item.cwe,
                                atlas_technique=item.atlas_technique,
                                file_path=item.file_path,
                                line=item.line,
                                snippet=item.snippet,
                                remediation=item.remediation,
                                hygiene_only=False,
                                gha_class=item.gha_class,
                                deterministic=True,
                                metadata=dict(item.metadata),
                            )
                        )

    findings.sort(key=lambda f: (f.file_path, f.line, f.rule_id))
    return findings


def gha_agent_findings_to_sarif(findings: Sequence[GhaAgentFinding]) -> Dict[str, Any]:
    """Converts `GhaAgentFinding` objects to an OASIS SARIF 2.1.0 document."""
    return gha_findings_to_sarif(
        [f.to_workflow_finding() for f in findings],
        tool_name="RFCHunt-GHA-Agent-Auditor",
    )
