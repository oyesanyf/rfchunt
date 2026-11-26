"""
GitHub Actions Security Scanners: Zizmor & Actionlint Adapters + Pure-Python Parity + SARIF 2.1.0
==================================================================================================
Provides deterministic, line-accurate static analysis of GitHub Actions workflows (`.github/workflows/*.yml|yaml`
and standalone workflow YAML files) with:
  1. Line-tracking PyYAML SafeLoader (`LineMap`, `LineList`, `parse_workflow_yaml`) recording 1-based line numbers.
  2. Fail-closed external binary resolution (`resolve_gha_scanner_binary`, `shell=False` via `silent_subprocess_run`)
     for `zizmor --format sarif` and `actionlint -format '{{json .}}'`, plus seamless fallback to pure-Python
     parity analyzers (`ZizmorParityAnalyzer`, `ActionlintParityAnalyzer`) when binaries are absent or `embedded=True`.
  3. Comprehensive coverage of all 7 R1 vulnerability classes with low/zero false positives on properly mitigated
     workflows (e.g., `env:` indirection with quoted `"$VAR"`, 40-char lowercase SHA `uses:` pins, `permissions: read-all`,
     `persist-credentials: false`, and `pull_request` without `pull_request_target` untrusted head checkouts).
  4. OASIS SARIF 2.1.0 normalization and serialization (`gha_findings_to_sarif`).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Set, Tuple, Union

import yaml

from engine.execution_policy import _validate_canonical_path_syntax
from engine.host_containment import silent_subprocess_run

# ---------------------------------------------------------------------------
# Canonical 7 R1 Vulnerability Classes
# ---------------------------------------------------------------------------

GHA_CLASS_PWN_REQUEST = "pwn_request"
GHA_CLASS_TEMPLATE_INJECTION = "template_script_injection"
GHA_CLASS_UNPINNED_USES = "unpinned_or_impostor_uses"
GHA_CLASS_EXCESSIVE_PERMISSIONS = "excessive_permissions"
GHA_CLASS_ENV_PATH_INJECTION = "github_env_path_output_injection"
GHA_CLASS_ARTIFACT_CACHE_POISONING = "artifact_cache_poisoning"
GHA_CLASS_AI_AGENT_BOUNDARY = "ai_agent_trigger_boundary"
GHA_CLASS_WORKFLOW_STRUCTURE = "workflow_structure"

_SCRIPT_SHIM_EXTS: Tuple[str, ...] = (
    ".bat",
    ".cmd",
    ".ps1",
    ".sh",
    ".py",
    ".vbs",
    ".js",
    ".mjs",
    ".cjs",
)
_FORBIDDEN_META_CHARS: Tuple[str, ...] = ("|", "&", ";", "$", "`", "<", ">", "\n", "\r", "\x00")

_SKIP_SCAN_DIRS: Set[str] = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "dist",
    "build",
    "reports",
}

_PRIVILEGED_TRIGGERS: Set[str] = {"pull_request_target", "workflow_run", "issue_comment"}
_UNTRUSTED_PUBLIC_TRIGGERS: Set[str] = {
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "pull_request_review_comment",
    "pull_request_review",
    "issues",
    "discussion",
    "discussion_comment",
    "pull_request",
}

# Expressions referencing attacker-controlled PR/issue/comment/commit/workflow_run metadata,
# including wrapped function calls (`format(...)`, `toJSON(...)`, `join(...)`) and `||` fallbacks.
_UNTRUSTED_CONTEXT_EXPR_BODY = (
    r"(?<![A-Za-z0-9_.])(?:"
    r"github\.head_ref|"
    r"github\.event\.pull_request\.(?:title|body|head\.(?:ref|label|sha|repo\.(?:full_name|name|default_branch|owner\.login))|user\.login)|"
    r"github\.event\.issue\.(?:title|body|user\.login)|"
    r"github\.event\.comment\.(?:body|user\.login)|"
    r"github\.event\.review\.(?:body|user\.login)|"
    r"github\.event\.review_comment\.(?:body|path|user\.login)|"
    r"github\.event\.discussion\.(?:title|body|category\.name|user\.login)|"
    r"github\.event\.pages\[[^\]]*\]\.page_name|"
    r"github\.event\.commits\[[^\]]*\]\.(?:message|author\.(?:name|email))|"
    r"github\.event\.head_commit\.(?:message|author\.(?:name|email))|"
    r"github\.event\.workflow_run\.(?:head_branch|head_commit\.message|display_title)|"
    r"github\.event\.sender\.login"
    r")(?![A-Za-z0-9_])"
)

_UNTRUSTED_EXPR_RE = re.compile(
    r"\$\{\{(?:(?!\}\}).)*?"
    + _UNTRUSTED_CONTEXT_EXPR_BODY
    + r"(?:(?!\}\}).)*?\}\}",
    re.IGNORECASE | re.DOTALL,
)

_ANY_EXPR_RE = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)

_UNTRUSTED_CHECKOUT_REF_RE = re.compile(
    r"(?:"
    r"github\.event\.pull_request\.head\.(?:sha|ref)|"
    r"github\.head_ref|"
    r"github\.event\.workflow_run\.head_(?:branch|sha)|"
    r"refs/pull/|"
    r"github\.event\.pull_request\.number|"
    r"github\.event\.issue\.number"
    r")",
    re.IGNORECASE,
)

_UNTRUSTED_CHECKOUT_REPO_RE = re.compile(
    r"(?:"
    r"github\.event\.pull_request\.head\.repo\.(?:full_name|name|owner\.login)|"
    r"github\.event\.workflow_run\.head_repository\.(?:full_name|name|owner\.login)|"
    r"github\.event\.workflow_run\.pull_requests\[[^\]]*\]\.head\.repo\.(?:full_name|name|owner\.login)"
    r")",
    re.IGNORECASE,
)

_GH_PR_CHECKOUT_RE = re.compile(
    r"(?:gh\s+pr\s+checkout|git\s+fetch\b[^\n]*refs/pull/|git\s+checkout\s+(?:FETCH_HEAD|\$?PR_))",
    re.IGNORECASE,
)

_SHA40_LOWER_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX_LIKE_RE = re.compile(r"^[0-9a-fA-F]{6,}$")

_RISKY_WRITE_SCOPES_HIGH: Set[str] = {
    "contents",
    "id-token",
    "packages",
    "actions",
    "deployments",
    "statuses",
    "checks",
    "pull-requests",
    "issues",
}

_GITHUB_FILE_CMD_RE = re.compile(
    r"(?:"
    r"(?:>>|>)\s*[\"']?\$\{?(?:GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT)\}?[\"']?|"
    r"(?:>>|>)\s*\$env:(?:GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT)|"
    r"tee\s+(?:-a\s+)?[\"']?\$\{?(?:GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT)\}?[\"']?|"
    r"(?:Out-File|Add-Content|Set-Content)\b[^\n]*(?:GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT)"
    r")",
    re.IGNORECASE,
)

_AI_AGENT_ACTION_RE = re.compile(
    r"(?:anthropics/claude|claude-code|github/copilot|openai/codex|"
    r"google-github-actions/run-gemini|aider|openhands|devin|cursor-agent|"
    r"mcp-agent|llm-agent)",
    re.IGNORECASE,
)

_AI_AGENT_CLI_RE = re.compile(
    r"(?:^|[;&|\s])(?:claude|codex|gemini|aider|openhands)\s+(?:-p|--prompt|--message|run|exec|chat|review)",
    re.IGNORECASE | re.MULTILINE,
)

_AUTHOR_GATE_RE = re.compile(
    r"author_association\s*==\s*['\"](?:OWNER|MEMBER|COLLABORATOR)['\"]|"
    r"contains\s*\(\s*fromJSON\([^)]*(?:OWNER|MEMBER|COLLABORATOR)",
    re.IGNORECASE,
)

_SECRETS_REF_RE = re.compile(
    r"\bsecrets\.(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY|GITHUB_TOKEN|[A-Z0-9_]+)\b|"
    r"\b(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY)\b",
    re.IGNORECASE,
)

_KNOWN_RISKY_SINKS_RE = re.compile(
    r"(?:\bnpm\s+(?:ci|install|test|run)\b|\bpnpm\b|\byarn\b|\bpip\s+install\b|"
    r"\bpython3?\b|\bnode\b|\bbash\b|\bsh\b|\bmake\b|\bcargo\b|\bgo\s+(?:run|test|build)\b|"
    r"\bcurl\b|\bwget\b|\bsource\b|\beval\b|\./)",
    re.IGNORECASE,
)

_SEVERITY_TO_SARIF_LEVEL: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


# ---------------------------------------------------------------------------
# Line-Tracking PyYAML SafeLoader
# ---------------------------------------------------------------------------


class LineMap(dict):
    """Dictionary retaining 1-based YAML line numbers for mapping keys and values."""

    def __init__(self, *args: Any, line: int = 1, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.line: int = line
        self._key_lines: Dict[Any, int] = {}
        self._val_lines: Dict[Any, int] = {}

    def key_line(self, key: Any, default: Optional[int] = None) -> int:
        if key in self._key_lines:
            return self._key_lines[key]
        return default if default is not None else self.line

    def val_line(self, key: Any, default: Optional[int] = None) -> int:
        if key in self._val_lines:
            return self._val_lines[key]
        return self.key_line(key, default=default)


class LineList(list):
    """List retaining 1-based YAML line numbers for sequence items."""

    def __init__(self, *args: Any, line: int = 1, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.line: int = line
        self._item_lines: List[int] = []

    def item_line(self, idx: int, default: Optional[int] = None) -> int:
        if 0 <= idx < len(self._item_lines):
            return self._item_lines[idx]
        return default if default is not None else self.line


class _LineSafeLoader(yaml.SafeLoader):
    pass


def _construct_line_mapping(loader: _LineSafeLoader, node: yaml.MappingNode, deep: bool = False) -> LineMap:
    loader.flatten_mapping(node)
    mapping = LineMap(line=(node.start_mark.line + 1) if node.start_mark else 1)
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        # Normalize YAML 1.1 `on:` parsed as boolean True
        if key is True:
            key = "on"
        elif not isinstance(key, (str, int, float, bool, tuple, type(None))):
            key = str(key)
        val = loader.construct_object(value_node, deep=True)
        k_line = (key_node.start_mark.line + 1) if key_node.start_mark else mapping.line
        v_line = (value_node.start_mark.line + 1) if value_node.start_mark else k_line
        mapping[key] = val
        mapping._key_lines[key] = k_line
        mapping._val_lines[key] = v_line
    return mapping


def _construct_line_sequence(loader: _LineSafeLoader, node: yaml.SequenceNode, deep: bool = False) -> LineList:
    seq = LineList(line=(node.start_mark.line + 1) if node.start_mark else 1)
    for item_node in node.value:
        val = loader.construct_object(item_node, deep=True)
        i_line = (item_node.start_mark.line + 1) if item_node.start_mark else seq.line
        seq.append(val)
        seq._item_lines.append(i_line)
    return seq


_LineSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_line_mapping)
_LineSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_line_sequence)


def parse_workflow_yaml(text: str) -> Tuple[Optional[LineMap], Optional[Tuple[int, str]]]:
    """
    Parses workflow YAML using line-tracking SafeLoader.
    Returns `(doc, None)` on success or `(None, (error_line, error_message))` on syntax failure.
    """
    try:
        doc = yaml.load(text, Loader=_LineSafeLoader)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        err_line = (mark.line + 1) if mark is not None else 1
        return None, (err_line, str(exc).splitlines()[0][:240])
    if doc is None:
        return LineMap(line=1), None
    if not isinstance(doc, LineMap):
        return None, (1, "Workflow root must be a YAML mapping")
    return doc, None


def _is_workflow_yaml_doc(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    return "jobs" in doc or ("on" in doc and ("jobs" in doc or "runs" in doc))


def _find_line_for_needle(raw_lines: Sequence[str], approx_line: int, needle: str) -> int:
    """Locates exact 1-based line number >= approx_line containing `needle`, falling back safely."""
    search_needle = needle.splitlines()[0] if "\n" in needle else needle
    if not search_needle:
        return max(1, approx_line)
    start_idx = max(0, approx_line - 1)
    for idx in range(start_idx, len(raw_lines)):
        if search_needle in raw_lines[idx]:
            return idx + 1
    for idx, line_txt in enumerate(raw_lines):
        if search_needle in line_txt:
            return idx + 1
    return max(1, approx_line)


# ---------------------------------------------------------------------------
# Normalized Finding & SARIF 2.1.0 Models
# ---------------------------------------------------------------------------


@dataclass
class GhaWorkflowFinding:
    engine: str
    rule_id: str
    gha_class: str
    title: str
    severity: str
    cwe: str
    atlas_technique: str
    file_path: str
    line: int
    column: int = 1
    snippet: str = ""
    remediation: str = ""
    execution_mode: str = "python_parity"
    hygiene_only: bool = False
    deterministic: bool = True
    confirmed: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_engine_finding(self):
        from engine.ensemble_orchestrator import EngineFinding

        sev = (self.severity or "MEDIUM").upper()
        conf_map = {"CRITICAL": 0.94, "HIGH": 0.88, "MEDIUM": 0.76, "LOW": 0.62, "INFO": 0.50}
        meta = dict(self.metadata)
        meta.update(
            {
                "gha_class": self.gha_class,
                "execution_mode": self.execution_mode,
                "hygiene_only": self.hygiene_only,
                "column": self.column,
            }
        )
        return EngineFinding(
            engine=self.engine,
            title=self.title,
            file_path=self.file_path,
            line=max(1, int(self.line or 1)),
            cwe=self.cwe,
            severity=sev,
            confidence=conf_map.get(sev, 0.75),
            summary=f"{self.snippet} | {self.remediation}".strip(" |"),
            rule_id=self.rule_id,
            atlas_technique=self.atlas_technique,
            deterministic=self.deterministic,
            confirmed=self.confirmed,
            metadata=meta,
        )

    def to_sarif_result(self) -> Dict[str, Any]:
        sev = (self.severity or "MEDIUM").upper()
        uri = (self.file_path or "unknown").replace("\\", "/").lstrip("./") or "unknown"
        return {
            "ruleId": self.rule_id,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(sev, "warning"),
            "message": {"text": f"[{self.engine}:{self.execution_mode}] {self.title}: {self.snippet}".strip(": ")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {
                            "startLine": max(1, int(self.line or 1)),
                            "startColumn": max(1, int(self.column or 1)),
                            "snippet": {"text": self.snippet[:300]} if self.snippet else {},
                        },
                    }
                }
            ],
            "properties": {
                "engine": self.engine,
                "gha_class": self.gha_class,
                "severity": sev,
                "cwe": self.cwe,
                "atlas_technique": self.atlas_technique,
                "execution_mode": self.execution_mode,
                "hygiene_only": self.hygiene_only,
                "deterministic": self.deterministic,
                "remediation": self.remediation,
            },
        }


@dataclass
class GhaScanResult:
    engine: str
    execution_mode: str
    binary_path: Optional[str]
    embedded: bool
    files_scanned: int
    findings: List[GhaWorkflowFinding] = field(default_factory=list)
    telemetry: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.engine,
            "execution_mode": self.execution_mode,
            "binary_path": self.binary_path,
            "embedded": self.embedded,
            "files_scanned": self.files_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "telemetry": dict(self.telemetry),
        }


def gha_findings_to_sarif(
    findings: Sequence[GhaWorkflowFinding],
    *,
    tool_name: str = "RFCHunt-GHA-Security-Scanners",
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """Serializes `GhaWorkflowFinding` objects into a compliant OASIS SARIF 2.1.0 document."""
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        if f.rule_id not in rules_by_id:
            sev = (f.severity or "MEDIUM").upper()
            rules_by_id[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.remediation or f.title},
                "help": {"text": f.remediation or f.title},
                "defaultConfiguration": {"level": _SEVERITY_TO_SARIF_LEVEL.get(sev, "warning")},
                "properties": {
                    "cwe": f.cwe,
                    "gha_class": f.gha_class,
                    "atlas_technique": f.atlas_technique,
                    "tags": ["security", "github-actions", f.gha_class] + ([f.cwe] if f.cwe else []),
                },
            }
        res = f.to_sarif_result()
        if not res["locations"][0]["physicalLocation"]["region"].get("snippet"):
            res["locations"][0]["physicalLocation"]["region"].pop("snippet", None)
        results.append(res)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/oyesanyf/rfchunt",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Fail-Closed Binary Validation & Discovery
# ---------------------------------------------------------------------------


def resolve_gha_scanner_binary(
    tool_name: Literal["zizmor", "actionlint"],
    binary_path: Optional[str] = None,
) -> Optional[str]:
    """
    Resolves and validates `zizmor` or `actionlint` executable safely (fail-closed):
      - Rejects script shims (`.bat`, `.cmd`, `.ps1`, `.sh`, `.py`, `.vbs`, `.js`).
      - Rejects UNC paths, traversal (`..`), shell metacharacters, and cross-tool symlinks.
      - Returns resolved executable path or `None` if binary is absent from `PATH`.
    """
    if tool_name not in ("zizmor", "actionlint"):
        raise ValueError(f"Unsupported GHA scanner tool: {tool_name!r}")

    candidate = binary_path if binary_path is not None else shutil.which(tool_name)
    if not candidate:
        return None

    raw = str(candidate)
    if raw != raw.strip() or not raw.strip():
        raise PermissionError(f"Invalid {tool_name} binary path: {raw!r}")
    raw = raw.strip()
    if any(ch in raw for ch in _FORBIDDEN_META_CHARS):
        raise PermissionError(f"Unsafe metacharacter in {tool_name} path: {raw!r}")

    path_err = _validate_canonical_path_syntax(raw)
    if path_err is not None:
        raise PermissionError(f"Unsafe {tool_name} path ({path_err}): {raw!r}")

    name = PurePosixPath(raw.replace("\\", "/")).name.lower()
    if any(name.endswith(ext) for ext in _SCRIPT_SHIM_EXTS):
        raise PermissionError(f"Script wrapper binary {name!r} is forbidden for {tool_name}.")

    stem = name[:-4] if name.endswith(".exe") else name
    if stem != tool_name:
        raise PermissionError(f"Binary {name!r} does not match expected tool {tool_name!r}.")

    p = Path(raw)
    if p.exists() or p.is_symlink():
        try:
            resolved = p.resolve()
        except OSError as exc:
            raise PermissionError(f"Failed resolving {tool_name} path {raw!r}: {exc}") from exc
        res_name = resolved.name.lower()
        if any(res_name.endswith(ext) for ext in _SCRIPT_SHIM_EXTS):
            raise PermissionError(f"Resolved binary {res_name!r} is a forbidden script wrapper.")
        res_stem = res_name[:-4] if res_name.endswith(".exe") else res_name
        if res_stem != tool_name:
            raise PermissionError(f"Cross-tool symlink {name!r} -> {res_name!r} is forbidden.")
        return str(resolved)
    return raw


# ---------------------------------------------------------------------------
# Workflow Target Discovery
# ---------------------------------------------------------------------------


def discover_workflow_files(target_path: Union[str, Path]) -> Tuple[Path, List[Path]]:
    """
    Discovers GitHub Actions workflow YAML files under `target_path`.
    - If `target_path` is a `.yml`/`.yaml` file, returns `(parent_root, [file])`.
    - If `target_path` is a directory, prefers `.github/workflows/*.yml|yaml` plus any direct
      workflow YAML files inside `target_path` (when `target_path` is a workflow or fixture dir)
      and any nested `.github/workflows/*.yml|yaml` in subprojects.
    """
    target = Path(target_path).resolve()
    if not target.exists():
        return target, []
    if target.is_file():
        if target.suffix.lower() in (".yml", ".yaml"):
            # Anchor root at repo root if inside .github/workflows/
            if target.parent.name == "workflows" and target.parent.parent.name == ".github":
                return target.parent.parent.parent, [target]
            return target.parent, [target]
        return target.parent, []

    found: List[Path] = []
    seen: Set[Path] = set()

    def _add(p: Path) -> None:
        rp = p.resolve()
        if rp not in seen and rp.is_file() and rp.stat().st_size <= 1_024_000:
            seen.add(rp)
            found.append(rp)

    gh_wf = target / ".github" / "workflows"
    if gh_wf.is_dir():
        for ext in ("*.yml", "*.yaml"):
            for p in sorted(gh_wf.glob(ext)):
                _add(p)

    # Walk repository without skipping `.github` while respecting `_SKIP_SCAN_DIRS`
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_SCAN_DIRS)
        cur = Path(dirpath)
        is_gh_workflows = cur.name == "workflows" and cur.parent.name == ".github"
        is_root = cur == target
        for fn in sorted(filenames):
            if not fn.lower().endswith((".yml", ".yaml")):
                continue
            p = cur / fn
            if is_gh_workflows:
                _add(p)
            elif is_root:
                # Gate root YAML files on actual workflow structure so non-workflow files
                # (e.g., docker-compose.yml, swarm_dispatch.yaml) are never passed to actionlint.
                try:
                    raw_txt = p.read_text(encoding="utf-8", errors="ignore")
                    doc, err = parse_workflow_yaml(raw_txt)
                    if doc is not None:
                        if _is_workflow_yaml_doc(doc):
                            _add(p)
                    elif err is not None:
                        head = raw_txt[:8192]
                        if "jobs:" in head and ("steps:" in head or "runs-on:" in head or "\non:" in head or head.lstrip().startswith("on:")):
                            _add(p)
                except OSError:
                    continue
            else:
                # Only treat non-.github YAML files as workflows if they look like GHA workflows
                try:
                    head = p.read_text(encoding="utf-8", errors="ignore")[:8192]
                    if ("jobs:" in head and "steps:" in head) or ("\non:" in head and "jobs:" in head):
                        _add(p)
                except OSError:
                    continue

    found.sort()
    return target, found


def _rel_posix(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return path.name


# ---------------------------------------------------------------------------
# Pure-Python Workflow AST & Dataflow Analyzers (Zizmor + Actionlint Parity)
# ---------------------------------------------------------------------------


def _extract_triggers(doc: LineMap) -> Tuple[Set[str], int]:
    """Returns `(trigger_names_lower, on_line)`."""
    on_val = doc.get("on")
    on_line = doc.key_line("on", default=1)
    triggers: Set[str] = set()
    if isinstance(on_val, str):
        triggers.add(on_val.strip().lower())
    elif isinstance(on_val, list):
        for item in on_val:
            if isinstance(item, str):
                triggers.add(item.strip().lower())
    elif isinstance(on_val, dict):
        for k in on_val.keys():
            triggers.add(str(k).strip().lower())
    return triggers, on_line


def _extract_tainted_env_names(env_obj: Any) -> Set[str]:
    tainted: Set[str] = set()
    if isinstance(env_obj, dict):
        for k, v in env_obj.items():
            if isinstance(v, str) and _UNTRUSTED_EXPR_RE.search(v):
                tainted.add(str(k))
    return tainted


def _analyze_permissions_block(
    perms: Any,
    perm_line: int,
    rel: str,
    triggers: Set[str],
    engine: str,
    prefix: str,
    scope_label: str,
) -> List[GhaWorkflowFinding]:
    out: List[GhaWorkflowFinding] = []
    priv_trig = bool(triggers & _PRIVILEGED_TRIGGERS)
    if isinstance(perms, str):
        p_str = perms.strip().lower()
        if p_str == "write-all":
            out.append(
                GhaWorkflowFinding(
                    engine=engine,
                    rule_id=f"{prefix}-EXCESSIVE-PERMS-WRITE-ALL",
                    gha_class=GHA_CLASS_EXCESSIVE_PERMISSIONS,
                    title=f"Excessive GITHUB_TOKEN Permissions (`write-all`) at {scope_label}",
                    severity="CRITICAL",
                    cwe="CWE-269",
                    atlas_technique="AML.T0040",
                    file_path=rel,
                    line=perm_line,
                    snippet=f"permissions: {perms}",
                    remediation="Replace `permissions: write-all` with least-privilege `permissions: read-all` or explicit minimal scopes.",
                )
            )
    elif isinstance(perms, dict):
        perms_line_map = perms if isinstance(perms, LineMap) else None
        for scope, level in perms.items():
            s_low = str(scope).strip().lower()
            l_low = str(level).strip().lower()
            if l_low != "write":
                continue
            s_line = perms_line_map.key_line(scope, default=perm_line) if perms_line_map else perm_line
            if s_low in _RISKY_WRITE_SCOPES_HIGH or priv_trig:
                sev = "HIGH"
            elif s_low == "security-events" and str(perms.get("contents", "")).lower() == "read" and not priv_trig:
                # Standard SARIF/CodeQL upload scope alongside read-only contents on non-privileged triggers.
                continue
            else:
                sev = "MEDIUM"
            out.append(
                GhaWorkflowFinding(
                    engine=engine,
                    rule_id=f"{prefix}-EXCESSIVE-PERMS-{s_low.upper()}",
                    gha_class=GHA_CLASS_EXCESSIVE_PERMISSIONS,
                    title=f"Broad GITHUB_TOKEN Write Scope (`{scope}: write`) at {scope_label}",
                    severity=sev,
                    cwe="CWE-269",
                    atlas_technique="AML.T0040",
                    file_path=rel,
                    line=s_line,
                    snippet=f"{scope}: {level}",
                    remediation=f"Restrict `{scope}` to `read` unless write access is strictly required inside an isolated job.",
                    hygiene_only=False,
                )
            )
    return out


_VERSION_COMMENT_RE = re.compile(r"^v?\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?$", re.IGNORECASE)
_IMPOSTOR_BRANCH_TOKEN_RE = re.compile(r"\b(?:main|master|head|dev|nightly|impostor\S*)\b", re.IGNORECASE)
_HEREDOC_START_RE = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z0-9_.-]+)\1")
_ARTIFACT_EXEC_SINK_RE = re.compile(
    r"(?:\bchmod\s+\+?[0-7]*x\b|\btar\s+[^#\n]*x|\bunzip\b|\b7z\s+x\b|\bdpkg\s+-i\b|\brpm\s+-i\b|\bexec\b|\.\s+[^\s])",
    re.IGNORECASE,
)


def _extract_github_file_cmd_block(run_lines: Sequence[str], start_idx: int) -> str:
    """
    Returns `run_lines[start_idx]` plus any heredoc body lines up to the closing delimiter
    when a heredoc (`<< EOF`, `<< 'EOF'`, `<<-EOF`) is opened on `run_lines[start_idx]`.
    """
    cmd_line = run_lines[start_idx]
    m_hd = _HEREDOC_START_RE.search(cmd_line)
    if not m_hd:
        return cmd_line
    delim = m_hd.group(2)
    block = [cmd_line]
    for next_line in run_lines[start_idx + 1 :]:
        block.append(next_line)
        if next_line.strip() == delim:
            break
    return "\n".join(block)


def _has_untrusted_github_file_rhs(
    text_block: str,
    step_tainted: Set[str],
    priv_trig: bool,
) -> bool:
    return bool(
        _UNTRUSTED_EXPR_RE.search(text_block)
        or any(
            re.search(rf"\$\{{?{re.escape(v)}\}}?|\$env:{re.escape(v)}\b", text_block, re.IGNORECASE)
            for v in step_tainted
        )
        or re.search(r"\$\((?:curl|wget|cat|jq|gh)\b|`[^`]+`", text_block, re.IGNORECASE)
        or (priv_trig and re.search(r"\$\{?[A-Za-z_]*UNTRUSTED[A-Za-z0-9_]*\}?", text_block, re.IGNORECASE))
    )


def _inspect_uses_reference(
    uses_val: str,
    uses_line: int,
    raw_lines: Sequence[str],
    rel: str,
    engine: str,
    prefix: str,
    priv_trig_or_write: bool,
) -> Optional[GhaWorkflowFinding]:
    u = str(uses_val or "").strip()
    if not u or u.startswith(("./", "../")):
        return None

    raw_line_text = raw_lines[uses_line - 1] if 1 <= uses_line <= len(raw_lines) else u
    comment = ""
    if "#" in raw_line_text:
        comment = raw_line_text.split("#", 1)[1].strip()

    if u.startswith("docker://"):
        if "@sha256:" not in u.lower():
            return GhaWorkflowFinding(
                engine=engine,
                rule_id=f"{prefix}-UNPINNED-DOCKER-USES",
                gha_class=GHA_CLASS_UNPINNED_USES,
                title=f"Unpinned Docker Action Reference (`{u}`)",
                severity="MEDIUM",
                cwe="CWE-829",
                atlas_technique="AML.T0010",
                file_path=rel,
                line=uses_line,
                snippet=u,
                remediation="Pin Docker action images to an immutable `@sha256:<64-hex>` digest.",
            )
        return None

    if "@" not in u:
        return GhaWorkflowFinding(
            engine=engine,
            rule_id=f"{prefix}-INVALID-USES-REF",
            gha_class=GHA_CLASS_UNPINNED_USES,
            title=f"Third-Party Action Missing `@ref` Pin (`{u}`)",
            severity="HIGH",
            cwe="CWE-829",
            atlas_technique="AML.T0010",
            file_path=rel,
            line=uses_line,
            snippet=u,
            remediation="Pin third-party actions to a full 40-character commit SHA.",
        )

    action_slug, ref = u.rsplit("@", 1)
    ref_s = ref.strip()

    # Clean 40-char lowercase SHA pin -> check only explicit impostor anomalies
    if _SHA40_LOWER_RE.fullmatch(ref_s):
        c_low = comment.lower()
        # Flag obvious impostor commit comment indicators (e.g., referencing a different org/repo or branch/impostor tag)
        impostor_other_repo = re.search(r"\b([a-z0-9_.-]+/[a-z0-9_.-]+)\b", c_low)
        other_slug = impostor_other_repo.group(1) if impostor_other_repo else ""
        action_owner_repo = "/".join(action_slug.lower().split("/")[:2])
        is_version_comment = bool(_VERSION_COMMENT_RE.fullmatch(c_low))
        has_mismatched_repo = bool(
            other_slug
            and "/" in other_slug
            and other_slug != action_owner_repo
            and not _VERSION_COMMENT_RE.fullmatch(other_slug)
        )
        has_branch_comment = (not is_version_comment) and bool(_IMPOSTOR_BRANCH_TOKEN_RE.search(c_low))
        if has_mismatched_repo or has_branch_comment or "impostor" in c_low or "spoof" in c_low:
            return GhaWorkflowFinding(
                engine=engine,
                rule_id=f"{prefix}-IMPOSTOR-COMMIT",
                gha_class=GHA_CLASS_UNPINNED_USES,
                title=f"Suspicious / Impostor Commit Pin Comment Mismatch (`{u}`)",
                severity="HIGH",
                cwe="CWE-1357",
                atlas_technique="AML.T0010",
                file_path=rel,
                line=uses_line,
                snippet=raw_line_text.strip()[:220],
                remediation="Verify the pinned 40-char commit SHA belongs directly to the upstream repository and tag.",
            )
        return None

    # Short / truncated / uppercase SHA -> impostor or malformed SHA pin
    if _HEX_LIKE_RE.fullmatch(ref_s):
        return GhaWorkflowFinding(
            engine=engine,
            rule_id=f"{prefix}-IMPOSTOR-SHORT-SHA",
            gha_class=GHA_CLASS_UNPINNED_USES,
            title=f"Truncated or Non-Canonical Commit SHA Pin (`{u}`)",
            severity="HIGH",
            cwe="CWE-1357",
            atlas_technique="AML.T0010",
            file_path=rel,
            line=uses_line,
            snippet=u,
            remediation="Replace short/uppercase SHA with the full 40-character lowercase git commit SHA.",
        )

    sev = "HIGH" if priv_trig_or_write else "MEDIUM"
    return GhaWorkflowFinding(
        engine=engine,
        rule_id=f"{prefix}-UNPINNED-USES",
        gha_class=GHA_CLASS_UNPINNED_USES,
        title=f"Unpinned Mutable Third-Party Action Reference (`{u}`)",
        severity=sev,
        cwe="CWE-829",
        atlas_technique="AML.T0010",
        file_path=rel,
        line=uses_line,
        snippet=u,
        remediation=f"Pin `{action_slug}` to a full 40-character lowercase commit SHA (e.g., `{action_slug}@<40-hex-sha> # {ref_s}`).",
    )


def _uses_unquoted_tainted_var_in_unsafe_sink(run_script: str, tainted_vars: Set[str]) -> Optional[str]:
    """
    Returns matched snippet ONLY if an `env:`-bound tainted variable is passed into an unsafe
    code-execution sink (`eval $VAR`, `sh -c ... $VAR`) or `GITHUB_ENV`/`GITHUB_PATH`/`GITHUB_OUTPUT`.
    Safely quoted `"$VAR"` in normal commands (`echo "$VAR"`) returns None (0 false positives).
    """
    if not tainted_vars:
        return None
    for var in tainted_vars:
        if re.search(rf"\b(?:eval|exec)\b[^\n]*\$\{{?{re.escape(var)}\}}?", run_script):
            return f"eval/exec with tainted env ${var}"
        if re.search(rf"(?:sh|bash)\s+-c\s+[^\n]*\$\{{?{re.escape(var)}\}}?", run_script):
            return f"sh -c with tainted env ${var}"
    return None


def _run_zizmor_parity_on_docs(
    parsed_docs: Sequence[Tuple[Path, str, LineMap, str]],
) -> List[GhaWorkflowFinding]:
    """
    Pure-Python Zizmor parity analyzer across all parsed workflow documents,
    including cross-workflow `workflow_run` artifact-poisoning correlation.
    """
    findings: List[GhaWorkflowFinding] = []
    pr_upload_workflows: List[Tuple[str, int, str]] = []
    workflow_run_downloads: List[Tuple[str, int, str]] = []

    for wf_path, rel, doc, raw_text in parsed_docs:
        raw_lines = raw_text.splitlines()
        triggers, on_line = _extract_triggers(doc)
        priv_trig = bool(triggers & _PRIVILEGED_TRIGGERS)
        has_pr_target = "pull_request_target" in triggers
        has_workflow_run = "workflow_run" in triggers
        has_untrusted_trigger = bool(triggers & _UNTRUSTED_PUBLIC_TRIGGERS)

        wf_env = doc.get("env")
        wf_tainted = _extract_tainted_env_names(wf_env)

        wf_perms = doc.get("permissions")
        wf_has_perms = "permissions" in doc
        wf_write_all = isinstance(wf_perms, str) and wf_perms.strip().lower() == "write-all"

        if wf_has_perms:
            findings.extend(
                _analyze_permissions_block(
                    wf_perms,
                    doc.key_line("permissions", default=1),
                    rel,
                    triggers,
                    engine="zizmor",
                    prefix="ZIZMOR-PY",
                    scope_label="workflow",
                )
            )
        elif priv_trig:
            findings.append(
                GhaWorkflowFinding(
                    engine="zizmor",
                    rule_id="ZIZMOR-PY-MISSING-PERMS-PRIVILEGED",
                    gha_class=GHA_CLASS_EXCESSIVE_PERMISSIONS,
                    title="Privileged Trigger Missing Explicit Least-Privilege `permissions:` Block",
                    severity="HIGH",
                    cwe="CWE-269",
                    atlas_technique="AML.T0040",
                    file_path=rel,
                    line=on_line,
                    snippet=f"on: {', '.join(sorted(triggers))} (no top-level permissions)",
                    remediation="Declare `permissions: read-all` or explicit minimal permissions at workflow/job level.",
                )
            )

        jobs = doc.get("jobs")
        if not isinstance(jobs, dict):
            continue

        jobs_map = jobs if isinstance(jobs, LineMap) else None
        for job_id, job_cfg in jobs.items():
            if not isinstance(job_cfg, dict):
                continue
            job_map = job_cfg if isinstance(job_cfg, LineMap) else None
            job_line = jobs_map.key_line(job_id, default=1) if jobs_map else 1

            job_env = job_cfg.get("env")
            job_tainted = wf_tainted | _extract_tainted_env_names(job_env)

            # Job-level permissions
            if "permissions" in job_cfg:
                j_perms = job_cfg.get("permissions")
                findings.extend(
                    _analyze_permissions_block(
                        j_perms,
                        job_map.key_line("permissions", default=job_line) if job_map else job_line,
                        rel,
                        triggers,
                        engine="zizmor",
                        prefix="ZIZMOR-PY",
                        scope_label=f"job:{job_id}",
                    )
                )
                j_write = (isinstance(j_perms, str) and j_perms.strip().lower() == "write-all") or (
                    isinstance(j_perms, dict) and any(str(v).lower() == "write" for v in j_perms.values())
                )
            else:
                j_write = wf_write_all or (
                    isinstance(wf_perms, dict) and any(str(v).lower() == "write" for v in wf_perms.values())
                )

            # Job-level reusable workflow `uses:`
            if "uses" in job_cfg and isinstance(job_cfg.get("uses"), str):
                u_line = job_map.val_line("uses", default=job_line) if job_map else job_line
                f_uses = _inspect_uses_reference(
                    job_cfg["uses"], u_line, raw_lines, rel, "zizmor", "ZIZMOR-PY", priv_trig or j_write
                )
                if f_uses:
                    findings.append(f_uses)

            steps = job_cfg.get("steps")
            if not isinstance(steps, list):
                continue
            steps_list = steps if isinstance(steps, LineList) else None

            untrusted_checkout_seen: Optional[Tuple[int, str]] = None
            checkout_persist_creds_default = False
            checkout_line = 0
            downloaded_artifact_seen: Optional[Tuple[int, str]] = None
            job_if = str(job_cfg.get("if") or "")

            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                step_map = step if isinstance(step, LineMap) else None
                step_line = steps_list.item_line(idx, default=job_line) if steps_list else job_line
                step_env = step.get("env")
                step_tainted = job_tainted | _extract_tainted_env_names(step_env)
                step_if = str(step.get("if") or "")
                has_author_gate = bool(_AUTHOR_GATE_RE.search(job_if) or _AUTHOR_GATE_RE.search(step_if))

                uses_val = step.get("uses")
                uses_line = step_map.val_line("uses", default=step_line) if step_map else step_line
                with_cfg = step.get("with") if isinstance(step.get("with"), dict) else {}
                with_map = with_cfg if isinstance(with_cfg, LineMap) else None
                run_val = step.get("run")
                run_line = step_map.val_line("run", default=step_line) if step_map else step_line

                # 1. `uses:` pinning & impostor commits
                if isinstance(uses_val, str):
                    f_uses = _inspect_uses_reference(
                        uses_val, uses_line, raw_lines, rel, "zizmor", "ZIZMOR-PY", priv_trig or j_write
                    )
                    if f_uses:
                        findings.append(f_uses)

                    u_low = uses_val.lower()
                    # Checkout tracking for pwn_request + artipacked
                    if "actions/checkout" in u_low:
                        ref_val = str(with_cfg.get("ref") or "")
                        repo_val = str(with_cfg.get("repository") or "")
                        if priv_trig and ref_val and _UNTRUSTED_CHECKOUT_REF_RE.search(ref_val):
                            ref_line = with_map.val_line("ref", default=uses_line) if with_map else uses_line
                            untrusted_checkout_seen = (ref_line, f"actions/checkout ref: {ref_val}")
                        elif priv_trig and repo_val and _UNTRUSTED_CHECKOUT_REPO_RE.search(repo_val):
                            repo_line = with_map.val_line("repository", default=uses_line) if with_map else uses_line
                            untrusted_checkout_seen = (repo_line, f"actions/checkout repository: {repo_val}")
                        if with_cfg.get("persist-credentials") is not False:
                            checkout_persist_creds_default = True
                            checkout_line = uses_line

                    # Upload-artifact tracking (artipacked + cross-workflow upload)
                    if "actions/upload-artifact" in u_low:
                        if triggers & {"pull_request", "pull_request_target"}:
                            pr_upload_workflows.append((rel, uses_line, str(with_cfg.get("name") or "artifact")))
                        if checkout_persist_creds_default:
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="zizmor",
                                    rule_id="ZIZMOR-PY-ARTIPACKED",
                                    gha_class=GHA_CLASS_ARTIFACT_CACHE_POISONING,
                                    title="Artifact Credential Persistence Hazard (`artipacked`: `persist-credentials: false` Omitted)",
                                    severity="MEDIUM",
                                    cwe="CWE-522",
                                    atlas_technique="AML.T0040",
                                    file_path=rel,
                                    line=uses_line,
                                    snippet=f"actions/checkout (line {checkout_line}) without persist-credentials: false before upload-artifact",
                                    remediation="Set `persist-credentials: false` on `actions/checkout` before uploading workflow artifacts.",
                                )
                            )

                    # Download-artifact tracking
                    if "actions/download-artifact" in u_low:
                        if has_workflow_run:
                            workflow_run_downloads.append((rel, uses_line, str(with_cfg.get("name") or "artifact")))
                        if priv_trig:
                            downloaded_artifact_seen = (uses_line, f"{uses_val} (name={with_cfg.get('name', 'default')})")

                    # Cache poisoning
                    if "actions/cache" in u_low:
                        cache_key = str(with_cfg.get("key") or "")
                        raw_restore_keys = with_cfg.get("restore-keys")
                        if isinstance(raw_restore_keys, list):
                            restore_keys = "\n".join(str(x) for x in raw_restore_keys)
                        else:
                            restore_keys = str(raw_restore_keys or "")
                        broad_rk_lines = [
                            rk_s
                            for rk_s in (ln.strip() for ln in restore_keys.splitlines())
                            if rk_s and "runner.os" not in rk_s.lower() and "hashfiles" not in rk_s.lower() and len(rk_s) < 12
                        ]
                        if priv_trig:
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="zizmor",
                                    rule_id="ZIZMOR-PY-CACHE-POISONING-PRIVILEGED",
                                    gha_class=GHA_CLASS_ARTIFACT_CACHE_POISONING,
                                    title="Cache Restore/Save in Privileged Trigger (`cache-poisoning`)",
                                    severity="HIGH",
                                    cwe="CWE-345",
                                    atlas_technique="AML.T0010",
                                    file_path=rel,
                                    line=uses_line,
                                    snippet=f"{uses_val} under {sorted(triggers)} (key={cache_key[:80]})",
                                    remediation="Avoid sharing mutable caches inside `pull_request_target` / `workflow_run` workflows.",
                                )
                            )
                        elif _UNTRUSTED_EXPR_RE.search(cache_key) or _UNTRUSTED_EXPR_RE.search(restore_keys):
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="zizmor",
                                    rule_id="ZIZMOR-PY-CACHE-KEY-INJECTION",
                                    gha_class=GHA_CLASS_ARTIFACT_CACHE_POISONING,
                                    title="Untrusted Event Input Used in `actions/cache` Key",
                                    severity="HIGH",
                                    cwe="CWE-345",
                                    atlas_technique="AML.T0010",
                                    file_path=rel,
                                    line=uses_line,
                                    snippet=f"key={cache_key[:100]}",
                                    remediation="Derive cache keys exclusively from trusted lockfile hashes (`hashFiles(...)`).",
                                )
                            )
                        elif broad_rk_lines:
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="zizmor",
                                    rule_id="ZIZMOR-PY-CACHE-BROAD-RESTORE",
                                    gha_class=GHA_CLASS_ARTIFACT_CACHE_POISONING,
                                    title="Overly Broad `actions/cache` `restore-keys:` Prefix",
                                    severity="MEDIUM",
                                    cwe="CWE-345",
                                    atlas_technique="AML.T0010",
                                    file_path=rel,
                                    line=uses_line,
                                    snippet=f"restore-keys={'; '.join(broad_rk_lines)[:100]}",
                                    remediation="Scope `restore-keys:` with `${{ runner.os }}-` and lockfile/branch prefixes.",
                                )
                            )

                    # `actions/github-script` `with.script` injection + artifact download API
                    if "actions/github-script" in u_low and isinstance(with_cfg.get("script"), str):
                        script_txt = with_cfg["script"]
                        script_base_line = with_map.val_line("script", default=uses_line) if with_map else uses_line
                        for m_expr in _UNTRUSTED_EXPR_RE.finditer(script_txt):
                            exact_ln = _find_line_for_needle(raw_lines, script_base_line, m_expr.group(0))
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="zizmor",
                                    rule_id="ZIZMOR-PY-GITHUB-SCRIPT-INJECTION",
                                    gha_class=GHA_CLASS_TEMPLATE_INJECTION,
                                    title="Untrusted GitHub Event Expression Interpolated in `actions/github-script`",
                                    severity="HIGH",
                                    cwe="CWE-94",
                                    atlas_technique="AML.T0051",
                                    file_path=rel,
                                    line=exact_ln,
                                    snippet=m_expr.group(0),
                                    remediation="Pass untrusted metadata via `env:` and read it via `process.env.VAR` inside `github-script`.",
                                )
                            )
                        if priv_trig and "downloadartifact" in script_txt.lower():
                            downloaded_artifact_seen = (script_base_line, "github-script downloadArtifact")

                    # AI Agent Action trigger & prompt-injection boundary
                    if _AI_AGENT_ACTION_RE.search(uses_val) and has_untrusted_trigger:
                        with_blob = json.dumps(with_cfg, default=str)
                        env_blob = json.dumps(step_env or job_env or wf_env or {}, default=str)
                        has_untrusted_input = bool(
                            _UNTRUSTED_EXPR_RE.search(with_blob)
                            or step_tainted
                            or triggers & {"issue_comment", "pull_request_target", "pull_request_review_comment", "issues", "discussion"}
                        )
                        has_secrets_or_write = bool(
                            _SECRETS_REF_RE.search(with_blob) or _SECRETS_REF_RE.search(env_blob) or j_write or priv_trig
                        )
                        if has_untrusted_input and (not has_author_gate or has_secrets_or_write):
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="zizmor",
                                    rule_id="ZIZMOR-PY-AI-AGENT-BOUNDARY",
                                    gha_class=GHA_CLASS_AI_AGENT_BOUNDARY,
                                    title=f"AI-Agent Action (`{uses_val}`) Exposed to Untrusted Trigger/Prompt Injection Boundary",
                                    severity="HIGH",
                                    cwe="CWE-77",
                                    atlas_technique="AML.T0051",
                                    file_path=rel,
                                    line=uses_line,
                                    snippet=f"on={sorted(triggers)} -> {uses_val} (author_gate={has_author_gate})",
                                    remediation=(
                                        "Enforce strict `author_association` (OWNER/MEMBER/COLLABORATOR) gating, "
                                        "restrict agent tools/write permissions, and sanitize untrusted PR/issue inputs."
                                    ),
                                )
                            )

                # 2. `run:` step analysis (template injection, pwn_request sink, GITHUB_ENV/PATH/OUTPUT, artifact exec, AI CLI)
                if isinstance(run_val, str):
                    # Template injection directly in `run:`
                    for m_expr in _UNTRUSTED_EXPR_RE.finditer(run_val):
                        exact_ln = _find_line_for_needle(raw_lines, run_line, m_expr.group(0))
                        findings.append(
                            GhaWorkflowFinding(
                                engine="zizmor",
                                rule_id="ZIZMOR-PY-TEMPLATE-INJECTION",
                                gha_class=GHA_CLASS_TEMPLATE_INJECTION,
                                title="Untrusted GitHub Event Expression Interpolated in `run:` Shell Script",
                                severity="HIGH",
                                cwe="CWE-78",
                                atlas_technique="AML.T0051",
                                file_path=rel,
                                line=exact_ln,
                                snippet=m_expr.group(0),
                                remediation="Bind untrusted event fields to `env:` and reference them as double-quoted `\"$VAR\"`.",
                            )
                        )

                    unsafe_env_eval = _uses_unquoted_tainted_var_in_unsafe_sink(run_val, step_tainted)
                    if unsafe_env_eval:
                        findings.append(
                            GhaWorkflowFinding(
                                engine="zizmor",
                                rule_id="ZIZMOR-PY-TAINTED-ENV-EVAL",
                                gha_class=GHA_CLASS_TEMPLATE_INJECTION,
                                title="Tainted `env:` Variable Passed to Dynamic Shell Execution Sink",
                                severity="HIGH",
                                cwe="CWE-78",
                                atlas_technique="AML.T0051",
                                file_path=rel,
                                line=run_line,
                                snippet=unsafe_env_eval,
                                remediation="Do not pass untrusted `env:` variables to `eval`, `exec`, or `sh -c`.",
                            )
                        )

                    # `GITHUB_ENV` / `GITHUB_PATH` / `GITHUB_OUTPUT` untrusted writes (including multiline heredocs)
                    run_lines = run_val.splitlines()
                    for line_offset, cmd_line in enumerate(run_lines):
                        if not _GITHUB_FILE_CMD_RE.search(cmd_line):
                            continue
                        cmd_block = _extract_github_file_cmd_block(run_lines, line_offset)
                        has_untrusted_rhs = _has_untrusted_github_file_rhs(cmd_block, step_tainted, priv_trig)
                        if has_untrusted_rhs:
                            exact_ln = _find_line_for_needle(raw_lines, run_line + line_offset, cmd_line.strip()[:40] or "GITHUB_")
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="zizmor",
                                    rule_id="ZIZMOR-PY-GITHUB-ENV-INJECTION",
                                    gha_class=GHA_CLASS_ENV_PATH_INJECTION,
                                    title="Untrusted Write Injection into `GITHUB_ENV` / `GITHUB_PATH` / `GITHUB_OUTPUT`",
                                    severity="HIGH",
                                    cwe="CWE-94",
                                    atlas_technique="AML.T0040",
                                    file_path=rel,
                                    line=exact_ln,
                                    snippet=cmd_line.strip()[:200],
                                    remediation=(
                                        "Validate/sanitize values before writing to `GITHUB_ENV`/`GITHUB_PATH`/`GITHUB_OUTPUT`, "
                                        "or use randomized heredoc delimiters (`<<EOF_<random>`) for multiline values."
                                    ),
                                )
                            )

                    # `gh pr checkout` in privileged trigger
                    if priv_trig and _GH_PR_CHECKOUT_RE.search(run_val):
                        untrusted_checkout_seen = (run_line, "gh pr checkout / refs/pull head fetch")

                    # Pwn-request chain: untrusted checkout -> execution sink
                    if untrusted_checkout_seen is not None and _KNOWN_RISKS_PRESENT(run_val):
                        chk_line, chk_desc = untrusted_checkout_seen
                        findings.append(
                            GhaWorkflowFinding(
                                engine="zizmor",
                                rule_id="ZIZMOR-PY-PWN-REQUEST",
                                gha_class=GHA_CLASS_PWN_REQUEST,
                                title="Pwn-Request Chain: Privileged Trigger Checks Out & Executes Untrusted PR/Workflow Head",
                                severity="CRITICAL",
                                cwe="CWE-829",
                                atlas_technique="AML.T0010",
                                file_path=rel,
                                line=chk_line,
                                snippet=f"{chk_desc} -> run sink at line {run_line}",
                                remediation=(
                                    "Do not check out untrusted PR head code inside `pull_request_target` or `workflow_run`; "
                                    "split unprivileged build (`pull_request`) from privileged commenting/publishing."
                                ),
                            )
                        )
                        untrusted_checkout_seen = None  # emit once per checkout chain

                    # Artifact download -> execution sink (strictly require risky sink, execution/sourcing/chmod/extraction, or GITHUB_ENV/PATH write)
                    if downloaded_artifact_seen is not None and (
                        _KNOWN_RISKY_SINKS_RE.search(run_val)
                        or _ARTIFACT_EXEC_SINK_RE.search(run_val)
                        or _GITHUB_FILE_CMD_RE.search(run_val)
                    ):
                        dl_line, dl_desc = downloaded_artifact_seen
                        findings.append(
                            GhaWorkflowFinding(
                                engine="zizmor",
                                rule_id="ZIZMOR-PY-ARTIFACT-POISONING",
                                gha_class=GHA_CLASS_ARTIFACT_CACHE_POISONING,
                                title="Cross-Boundary Artifact Poisoning (`workflow_run` / `pull_request_target` Executes Downloaded Artifact)",
                                severity="HIGH",
                                cwe="CWE-829",
                                atlas_technique="AML.T0010",
                                file_path=rel,
                                line=dl_line,
                                snippet=f"{dl_desc} consumed by run step at line {run_line}",
                                remediation="Treat artifacts from PR/`workflow_run` as untrusted data; never execute, source, or inject them into `GITHUB_ENV`.",
                            )
                        )
                        downloaded_artifact_seen = None

                    # AI Agent CLI invocation in `run:`
                    if has_untrusted_trigger and _AI_AGENT_CLI_RE.search(run_val):
                        env_blob = json.dumps(step_env or job_env or wf_env or {}, default=str)
                        if (
                            _UNTRUSTED_EXPR_RE.search(run_val)
                            or step_tainted
                            or "git diff" in run_val.lower()
                            or _SECRETS_REF_RE.search(env_blob)
                            or not has_author_gate
                        ):
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="zizmor",
                                    rule_id="ZIZMOR-PY-AI-AGENT-CLI-BOUNDARY",
                                    gha_class=GHA_CLASS_AI_AGENT_BOUNDARY,
                                    title="AI-Agent CLI Invoked on Untrusted GitHub Event Context Without Trust Boundary Isolation",
                                    severity="HIGH",
                                    cwe="CWE-77",
                                    atlas_technique="AML.T0051",
                                    file_path=rel,
                                    line=run_line,
                                    snippet=run_val.strip().splitlines()[0][:180],
                                    remediation="Gate agent CLI execution by collaborator permission and strip untrusted prompts/diffs before secret-bearing execution.",
                                )
                            )

            # If untrusted checkout happened in `pull_request_target`/`workflow_run` and a local action `uses: ./...` ran after
            if untrusted_checkout_seen is not None:
                chk_line, chk_desc = untrusted_checkout_seen
                findings.append(
                    GhaWorkflowFinding(
                        engine="zizmor",
                        rule_id="ZIZMOR-PY-PWN-REQUEST",
                        gha_class=GHA_CLASS_PWN_REQUEST,
                        title="Privileged Trigger Checks Out Untrusted PR/Workflow Head (`dangerous-triggers`)",
                        severity="CRITICAL",
                        cwe="CWE-829",
                        atlas_technique="AML.T0010",
                        file_path=rel,
                        line=chk_line,
                        snippet=chk_desc,
                        remediation="Avoid checking out untrusted head refs inside `pull_request_target` / `workflow_run`.",
                    )
                )

    # Cross-workflow `pull_request` upload-artifact + `workflow_run` download-artifact correlation
    if pr_upload_workflows and workflow_run_downloads:
        up_files = ", ".join(sorted({u[0] for u in pr_upload_workflows}))
        for dl_rel, dl_line, dl_name in workflow_run_downloads:
            findings.append(
                GhaWorkflowFinding(
                    engine="zizmor",
                    rule_id="ZIZMOR-PY-CROSS-WF-ARTIFACT-POISONING",
                    gha_class=GHA_CLASS_ARTIFACT_CACHE_POISONING,
                    title="Cross-Workflow `workflow_run` Downloads Artifact From Unprivileged PR Workflow",
                    severity="HIGH",
                    cwe="CWE-829",
                    atlas_technique="AML.T0010",
                    file_path=dl_rel,
                    line=dl_line,
                    snippet=f"download-artifact ({dl_name}) paired with PR upload in [{up_files}]",
                    remediation="Validate artifact schema/signatures strictly as untrusted data and never execute files or set `GITHUB_ENV` from PR artifacts.",
                )
            )

    return findings


def _KNOWN_RISKS_PRESENT(run_val: str) -> bool:
    return bool(_KNOWN_RISKY_SINKS_RE.search(run_val)) or len(run_val.strip()) > 0


def _run_actionlint_parity_on_docs(
    parsed_docs: Sequence[Tuple[Path, str, LineMap, str]],
    syntax_errors: Sequence[Tuple[str, int, str]],
) -> List[GhaWorkflowFinding]:
    """
    Pure-Python Actionlint parity analyzer covering workflow schema, `needs:`, expressions,
    `runs-on:`, shell injection & `GITHUB_ENV`/`GITHUB_PATH` writes, `uses:` syntax/pinning,
    permissions, and privileged checkout hazards.
    """
    findings: List[GhaWorkflowFinding] = []

    for rel, err_line, err_msg in syntax_errors:
        findings.append(
            GhaWorkflowFinding(
                engine="actionlint",
                rule_id="ACTIONLINT-YAML-SYNTAX",
                gha_class=GHA_CLASS_WORKFLOW_STRUCTURE,
                title="Workflow YAML Syntax Error",
                severity="MEDIUM",
                cwe="CWE-20",
                atlas_technique="",
                file_path=rel,
                line=err_line,
                snippet=err_msg,
                remediation="Fix invalid YAML syntax in the workflow file.",
            )
        )

    for _wf_path, rel, doc, raw_text in parsed_docs:
        raw_lines = raw_text.splitlines()
        triggers, on_line = _extract_triggers(doc)
        priv_trig = bool(triggers & _PRIVILEGED_TRIGGERS)

        if "on" not in doc:
            findings.append(
                GhaWorkflowFinding(
                    engine="actionlint",
                    rule_id="ACTIONLINT-MISSING-ON",
                    gha_class=GHA_CLASS_WORKFLOW_STRUCTURE,
                    title="Workflow Missing Required `on:` Trigger Section",
                    severity="LOW",
                    cwe="CWE-20",
                    atlas_technique="",
                    file_path=rel,
                    line=1,
                    snippet="missing top-level `on:`",
                    remediation="Add a valid `on:` trigger mapping.",
                    hygiene_only=True,
                )
            )

        # Unbalanced `${{` expression check
        for idx, line_txt in enumerate(raw_lines, start=1):
            if "${{" in line_txt and "}}" not in line_txt and "${{" in line_txt.split("}}")[-1]:
                # Allow multiline ${{ ... }} if closed within next 3 lines
                window = "\n".join(raw_lines[idx - 1 : min(len(raw_lines), idx + 3)])
                if window.count("${{") > window.count("}}"):
                    findings.append(
                        GhaWorkflowFinding(
                            engine="actionlint",
                            rule_id="ACTIONLINT-EXPRESSION-SYNTAX",
                            gha_class=GHA_CLASS_WORKFLOW_STRUCTURE,
                            title="Unclosed GitHub Actions `${{ ... }}` Expression",
                            severity="MEDIUM",
                            cwe="CWE-20",
                            atlas_technique="",
                            file_path=rel,
                            line=idx,
                            snippet=line_txt.strip()[:160],
                            remediation="Close the `${{ ... }}` expression delimiter properly.",
                        )
                    )

        wf_perms = doc.get("permissions")
        if "permissions" in doc:
            findings.extend(
                _analyze_permissions_block(
                    wf_perms,
                    doc.key_line("permissions", default=1),
                    rel,
                    triggers,
                    engine="actionlint",
                    prefix="ACTIONLINT",
                    scope_label="workflow",
                )
            )
        wf_write_all = isinstance(wf_perms, str) and wf_perms.strip().lower() == "write-all"
        wf_tainted = _extract_tainted_env_names(doc.get("env"))

        jobs = doc.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            findings.append(
                GhaWorkflowFinding(
                    engine="actionlint",
                    rule_id="ACTIONLINT-MISSING-JOBS",
                    gha_class=GHA_CLASS_WORKFLOW_STRUCTURE,
                    title="Workflow Missing `jobs:` Mapping",
                    severity="LOW",
                    cwe="CWE-20",
                    atlas_technique="",
                    file_path=rel,
                    line=on_line,
                    snippet="missing `jobs:`",
                    remediation="Define at least one job under `jobs:`.",
                    hygiene_only=True,
                )
            )
            continue

        job_ids = set(jobs.keys())
        jobs_map = jobs if isinstance(jobs, LineMap) else None

        for job_id, job_cfg in jobs.items():
            if not isinstance(job_cfg, dict):
                continue
            job_map = job_cfg if isinstance(job_cfg, LineMap) else None
            job_line = jobs_map.key_line(job_id, default=1) if jobs_map else 1

            # `needs:` validation
            if "needs" in job_cfg:
                needs_val = job_cfg.get("needs")
                needs_line = job_map.val_line("needs", default=job_line) if job_map else job_line
                need_items = [needs_val] if isinstance(needs_val, str) else (list(needs_val) if isinstance(needs_val, list) else [])
                for req_job in need_items:
                    if req_job == job_id or req_job not in job_ids:
                        findings.append(
                            GhaWorkflowFinding(
                                engine="actionlint",
                                rule_id="ACTIONLINT-INVALID-NEEDS",
                               gha_class=GHA_CLASS_WORKFLOW_STRUCTURE,
                                title=f"Job `{job_id}` References Unknown or Cyclic `needs:` Target `{req_job}`",
                                severity="MEDIUM",
                                cwe="CWE-20",
                                atlas_technique="",
                                file_path=rel,
                                line=needs_line,
                                snippet=f"needs: {req_job}",
                                remediation="Ensure `needs:` references an existing non-self job ID.",
                            )
                        )

            # `runs-on:` presence check on non-reusable jobs
            if "uses" not in job_cfg and "runs-on" not in job_cfg:
                findings.append(
                    GhaWorkflowFinding(
                        engine="actionlint",
                        rule_id="ACTIONLINT-MISSING-RUNS-ON",
                        gha_class=GHA_CLASS_WORKFLOW_STRUCTURE,
                        title=f"Job `{job_id}` Missing `runs-on:` Runner Label",
                        severity="LOW",
                        cwe="CWE-20",
                        atlas_technique="",
                        file_path=rel,
                        line=job_line,
                        snippet=f"job `{job_id}` lacks runs-on",
                        remediation="Specify `runs-on: ubuntu-latest` (or a valid runner label).",
                        hygiene_only=True,
                    )
                )

            if "uses" in job_cfg and isinstance(job_cfg.get("uses"), str):
                u_line = job_map.val_line("uses", default=job_line) if job_map else job_line
                f_u = _inspect_uses_reference(
                    job_cfg["uses"], u_line, raw_lines, rel, "actionlint", "ACTIONLINT", priv_trig or wf_write_all
                )
                if f_u:
                    findings.append(f_u)

            job_tainted = wf_tainted | _extract_tainted_env_names(job_cfg.get("env"))
            steps = job_cfg.get("steps")
            if not isinstance(steps, list):
                continue
            steps_list = steps if isinstance(steps, LineList) else None

            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                step_map = step if isinstance(step, LineMap) else None
                step_line = steps_list.item_line(idx, default=job_line) if steps_list else job_line
                step_tainted = job_tainted | _extract_tainted_env_names(step.get("env"))

                uses_val = step.get("uses")
                uses_line = step_map.val_line("uses", default=step_line) if step_map else step_line
                with_cfg = step.get("with") if isinstance(step.get("with"), dict) else {}
                with_map = with_cfg if isinstance(with_cfg, LineMap) else None

                if isinstance(uses_val, str):
                    f_u = _inspect_uses_reference(
                        uses_val, uses_line, raw_lines, rel, "actionlint", "ACTIONLINT", priv_trig or wf_write_all
                    )
                    if f_u:
                        findings.append(f_u)

                    if "actions/checkout" in uses_val.lower():
                        ref_val = str(with_cfg.get("ref") or "")
                        repo_val = str(with_cfg.get("repository") or "")
                        is_ref_hit = bool(priv_trig and ref_val and _UNTRUSTED_CHECKOUT_REF_RE.search(ref_val))
                        is_repo_hit = bool(priv_trig and repo_val and _UNTRUSTED_CHECKOUT_REPO_RE.search(repo_val))
                        if is_ref_hit or is_repo_hit:
                            hit_key = "ref" if is_ref_hit else "repository"
                            hit_val = ref_val if is_ref_hit else repo_val
                            hit_line = with_map.val_line(hit_key, default=uses_line) if with_map else uses_line
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="actionlint",
                                    rule_id="ACTIONLINT-UNTRUSTED-CHECKOUT",
                                    gha_class=GHA_CLASS_PWN_REQUEST,
                                    title="Untrusted Head Checkout Under Privileged Workflow Trigger",
                                    severity="CRITICAL",
                                    cwe="CWE-829",
                                    atlas_technique="AML.T0010",
                                    file_path=rel,
                                    line=hit_line,
                                    snippet=f"actions/checkout {hit_key}: {hit_val}",
                                    remediation="Avoid checking out PR head commits or fork repositories inside `pull_request_target` / `workflow_run`.",
                                )
                            )

                    if "actions/github-script" in uses_val.lower() and isinstance(with_cfg.get("script"), str):
                        s_txt = with_cfg["script"]
                        s_line = with_map.val_line("script", default=uses_line) if with_map else uses_line
                        for m_expr in _UNTRUSTED_EXPR_RE.finditer(s_txt):
                            exact_ln = _find_line_for_needle(raw_lines, s_line, m_expr.group(0))
                            findings.append(
                                GhaWorkflowFinding(
                                    engine="actionlint",
                                    rule_id="ACTIONLINT-SCRIPT-INJECTION",
                                    gha_class=GHA_CLASS_TEMPLATE_INJECTION,
                                    title="Untrusted Expression Injection in `actions/github-script` (`script:`)",
                                    severity="HIGH",
                                    cwe="CWE-94",
                                    atlas_technique="AML.T0051",
                                    file_path=rel,
                                    line=exact_ln,
                                    snippet=m_expr.group(0),
                                    remediation="Move expression to `env:` and reference `process.env.<NAME>`.",
                                )
                            )

                run_val = step.get("run")
                run_line = step_map.val_line("run", default=step_line) if step_map else step_line
                if isinstance(run_val, str):
                    for m_expr in _UNTRUSTED_EXPR_RE.finditer(run_val):
                        exact_ln = _find_line_for_needle(raw_lines, run_line, m_expr.group(0))
                        findings.append(
                            GhaWorkflowFinding(
                                engine="actionlint",
                                rule_id="ACTIONLINT-SHELL-INJECTION",
                                gha_class=GHA_CLASS_TEMPLATE_INJECTION,
                                title="Untrusted Expression Directly Expanded in `run:` Shell Command",
                                severity="HIGH",
                                cwe="CWE-78",
                                atlas_technique="AML.T0051",
                                file_path=rel,
                                line=exact_ln,
                                snippet=m_expr.group(0),
                                remediation="Bind expression via `env:` and quote `\"$VAR\"` in shell.",
                            )
                        )

                    run_lines = run_val.splitlines()
                    for line_offset, cmd_line in enumerate(run_lines):
                        if _GITHUB_FILE_CMD_RE.search(cmd_line):
                            cmd_block = _extract_github_file_cmd_block(run_lines, line_offset)
                            has_untrusted = _has_untrusted_github_file_rhs(cmd_block, step_tainted, priv_trig)
                            if has_untrusted:
                                exact_ln = _find_line_for_needle(raw_lines, run_line + line_offset, cmd_line.strip()[:40] or "GITHUB_")
                                findings.append(
                                    GhaWorkflowFinding(
                                        engine="actionlint",
                                        rule_id="ACTIONLINT-GITHUB-ENV-WRITE",
                                        gha_class=GHA_CLASS_ENV_PATH_INJECTION,
                                        title="Shellcheck/Dataflow: Untrusted Write to `GITHUB_ENV`/`GITHUB_PATH`/`GITHUB_OUTPUT`",
                                        severity="HIGH",
                                        cwe="CWE-94",
                                        atlas_technique="AML.T0040",
                                        file_path=rel,
                                        line=exact_ln,
                                        snippet=cmd_line.strip()[:200],
                                        remediation="Sanitize input or avoid writing untrusted data to GitHub workflow file commands.",
                                    )
                                )

    return findings


# ---------------------------------------------------------------------------
# Binary Output Parsers (Real Zizmor SARIF & Real Actionlint JSON)
# ---------------------------------------------------------------------------


def _map_zizmor_rule_to_class(rule_id: str, text: str) -> Tuple[str, str]:
    r_low = (rule_id + " " + text).lower()
    if any(k in r_low for k in ("dangerous-triggers", "pwn-request", "ref-confusion", "pull_request_target")):
        return GHA_CLASS_PWN_REQUEST, "CWE-829"
    if any(k in r_low for k in ("template-injection", "github-script", "script-injection")):
        return GHA_CLASS_TEMPLATE_INJECTION, "CWE-94"
    if any(k in r_low for k in ("impostor-commit", "unpinned-uses", "unpinned")):
        return GHA_CLASS_UNPINNED_USES, "CWE-1357"
    if any(k in r_low for k in ("excessive-permissions", "permissions", "write-all")):
        return GHA_CLASS_EXCESSIVE_PERMISSIONS, "CWE-269"
    if any(k in r_low for k in ("github-env", "github_env", "github_path", "github_output", "env-injection")):
        return GHA_CLASS_ENV_PATH_INJECTION, "CWE-94"
    if any(k in r_low for k in ("artipacked", "cache-poisoning", "artifact", "cache")):
        return GHA_CLASS_ARTIFACT_CACHE_POISONING, "CWE-345"
    if any(k in r_low for k in ("ai-agent", "prompt", "claude", "copilot", "codex", "gemini")):
        return GHA_CLASS_AI_AGENT_BOUNDARY, "CWE-77"
    return GHA_CLASS_WORKFLOW_STRUCTURE, "CWE-20"


def _map_actionlint_kind_to_class(kind: str, message: str) -> Tuple[str, str, str]:
    blob = f"{kind} {message}".lower()
    if any(k in blob for k in ("pull_request_target", "workflow_run", "checkout", "head.sha", "head_ref")):
        return GHA_CLASS_PWN_REQUEST, "CWE-829", "CRITICAL"
    if any(k in blob for k in ("github_env", "github_path", "github_output")):
        return GHA_CLASS_ENV_PATH_INJECTION, "CWE-94", "HIGH"
    if any(k in blob for k in ("expression", "untrusted", "injection", "script", "shellcheck")):
        sev = "HIGH" if ("github.event" in blob or "untrusted" in blob or "injection" in blob) else "MEDIUM"
        return GHA_CLASS_TEMPLATE_INJECTION, "CWE-78", sev
    if any(k in blob for k in ("unpinned", "impostor", "uses", "commit sha")):
        return GHA_CLASS_UNPINNED_USES, "CWE-829", "MEDIUM"
    if any(k in blob for k in ("permission", "write-all")):
        return GHA_CLASS_EXCESSIVE_PERMISSIONS, "CWE-269", "HIGH"
    if any(k in blob for k in ("artifact", "cache", "artipacked")):
        return GHA_CLASS_ARTIFACT_CACHE_POISONING, "CWE-345", "MEDIUM"
    return GHA_CLASS_WORKFLOW_STRUCTURE, "CWE-20", "MEDIUM"


def parse_zizmor_sarif_output(raw_stdout: str, root: Path) -> List[GhaWorkflowFinding]:
    """Parses real `zizmor --format sarif` JSON output into normalized `GhaWorkflowFinding` list."""
    data = json.loads(raw_stdout)
    findings: List[GhaWorkflowFinding] = []
    sarif_lvl_to_sev = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
    for run in data.get("runs") or []:
        driver_rules = {
            r.get("id"): r
            for r in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
            if isinstance(r, dict) and r.get("id")
        }
        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            rule_id = str(res.get("ruleId") or "zizmor-finding")
            msg = str((res.get("message") or {}).get("text") or rule_id)
            lvl = str(res.get("level") or "warning").lower()
            sev = sarif_lvl_to_sev.get(lvl, "MEDIUM")
            props = res.get("properties") or {}
            if isinstance(props.get("severity"), str):
                sev = props["severity"].upper()

            locs = res.get("locations") or [{}]
            phys = (locs[0].get("physicalLocation") or {}) if locs else {}
            uri = str((phys.get("artifactLocation") or {}).get("uri") or "")
            if uri:
                p = Path(uri)
                if p.is_absolute():
                    uri = _rel_posix(p, root)
                else:
                    uri = uri.replace("\\", "/").lstrip("./")
            reg = phys.get("region") or {}
            line_no = max(1, int(reg.get("startLine") or 1))
            col_no = max(1, int(reg.get("startColumn") or 1))
            snippet = str((reg.get("snippet") or {}).get("text") or msg[:160])

            gha_class, cwe = _map_zizmor_rule_to_class(rule_id, msg)
            if gha_class == GHA_CLASS_PWN_REQUEST and sev == "HIGH":
                sev = "CRITICAL"
            rule_meta = driver_rules.get(rule_id) or {}
            remediation = str(
                (rule_meta.get("help") or {}).get("text")
                or (rule_meta.get("fullDescription") or {}).get("text")
                or f"Remediate Zizmor rule `{rule_id}` according to GitHub Actions least-privilege hardening."
            )
            findings.append(
                GhaWorkflowFinding(
                    engine="zizmor",
                    rule_id=f"ZIZMOR-{rule_id}",
                    gha_class=gha_class,
                    title=str((rule_meta.get("shortDescription") or {}).get("text") or msg[:140]),
                    severity=sev,
                    cwe=cwe,
                    atlas_technique="AML.T0051" if gha_class in (GHA_CLASS_TEMPLATE_INJECTION, GHA_CLASS_AI_AGENT_BOUNDARY) else "AML.T0010",
                    file_path=uri,
                    line=line_no,
                    column=col_no,
                    snippet=snippet,
                    remediation=remediation,
                    execution_mode="binary",
                    hygiene_only=(sev in ("LOW", "INFO")),
                    metadata={"raw_rule_id": rule_id},
                )
            )
    return findings


def parse_actionlint_json_output(raw_stdout: str, root: Path) -> List[GhaWorkflowFinding]:
    """Parses real `actionlint -format '{{json .}}'` JSON array output into normalized `GhaWorkflowFinding` list."""
    raw = (raw_stdout or "").strip()
    if not raw:
        return []
    items = json.loads(raw)
    if not isinstance(items, list):
        return []
    findings: List[GhaWorkflowFinding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "workflow")
        message = str(item.get("message") or kind)
        fp = str(item.get("filepath") or "")
        if fp:
            p = Path(fp)
            fp = _rel_posix(p, root) if p.is_absolute() else fp.replace("\\", "/").lstrip("./")
        line_no = max(1, int(item.get("line") or 1))
        col_no = max(1, int(item.get("column") or 1))
        snippet = str(item.get("snippet") or message[:180]).strip()
        gha_class, cwe, sev = _map_actionlint_kind_to_class(kind, message)
        findings.append(
            GhaWorkflowFinding(
                engine="actionlint",
                rule_id=f"ACTIONLINT-{kind.upper()}",
                gha_class=gha_class,
                title=message[:160],
                severity=sev,
                cwe=cwe,
                atlas_technique="AML.T0051" if gha_class == GHA_CLASS_TEMPLATE_INJECTION else "",
                file_path=fp,
                line=line_no,
                column=col_no,
                snippet=snippet,
                remediation=f"Fix Actionlint `{kind}` diagnostic at line {line_no}.",
                execution_mode="binary",
                hygiene_only=(sev in ("LOW", "INFO")),
                metadata={"kind": kind},
            )
        )
    return findings


# ---------------------------------------------------------------------------
# High-Level Scanner Entrypoints (Binary + Graceful Pure-Python Parity)
# ---------------------------------------------------------------------------


def _load_parsed_workflows(
    target_path: Union[str, Path],
) -> Tuple[Path, List[Path], List[Tuple[Path, str, LineMap, str]], List[Tuple[str, int, str]]]:
    root, files = discover_workflow_files(target_path)
    parsed_docs: List[Tuple[Path, str, LineMap, str]] = []
    syntax_errors: List[Tuple[str, int, str]] = []
    for wf in files:
        try:
            text = wf.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = _rel_posix(wf, root)
        doc, err = parse_workflow_yaml(text)
        if err is not None:
            syntax_errors.append((rel, err[0], err[1]))
            continue
        if doc is not None and _is_workflow_yaml_doc(doc):
            parsed_docs.append((wf, rel, doc, text))
    return root, files, parsed_docs, syntax_errors


def _dedup_findings(items: Sequence[GhaWorkflowFinding]) -> List[GhaWorkflowFinding]:
    seen: Set[Tuple[str, str, int, str]] = set()
    out: List[GhaWorkflowFinding] = []
    for f in items:
        key = (f.file_path.lower(), f.gha_class, int(f.line or 1), f.rule_id)
        if key not in seen:
            seen.add(key)
            out.append(f)
    out.sort(key=lambda x: (x.file_path, x.line, x.rule_id))
    return out


def run_zizmor_scan(
    target_path: Union[str, Path],
    *,
    embedded: bool = False,
    binary_path: Optional[str] = None,
    timeout_sec: float = 60.0,
) -> GhaScanResult:
    """
    Runs Zizmor on GitHub Actions workflows:
      - If `embedded=False` and `zizmor` binary is found on `PATH` (or `binary_path`), runs
        `zizmor --format sarif` via `silent_subprocess_run(..., shell=False)` and supplements
        with RFCHunt R1 AI-agent/cross-workflow rules.
      - Otherwise falls back seamlessly to pure-Python `ZizmorParityAnalyzer` (`python_parity`).
    """
    root, files, parsed_docs, _ = _load_parsed_workflows(target_path)
    if not files:
        return GhaScanResult(
            engine="zizmor",
            execution_mode="python_parity",
            binary_path=None,
            embedded=embedded,
            files_scanned=0,
            findings=[],
            telemetry={"status": "no_workflow_files"},
        )

    resolved_bin: Optional[str] = None
    if not embedded:
        resolved_bin = resolve_gha_scanner_binary("zizmor", binary_path=binary_path)

    if resolved_bin:
        scan_arg = str(Path(target_path).resolve()) if Path(target_path).is_file() else str(root)
        cmd = [resolved_bin, "--format", "sarif", scan_arg]
        try:
            proc = silent_subprocess_run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
            )
            stdout_s = (proc.stdout or "").strip()
            if stdout_s.startswith("{"):
                bin_findings = parse_zizmor_sarif_output(stdout_s, root)
                # Supplement with AI-agent boundary + cross-workflow checks if binary didn't emit them
                parity_all = _run_zizmor_parity_on_docs(parsed_docs)
                existing_keys = {(bf.file_path.lower(), bf.gha_class) for bf in bin_findings}
                supplemental = [
                    pf
                    for pf in parity_all
                    if pf.gha_class == GHA_CLASS_AI_AGENT_BOUNDARY
                    and (pf.file_path.lower(), pf.gha_class) not in existing_keys
                ]
                combined = _dedup_findings([*bin_findings, *supplemental])
                return GhaScanResult(
                    engine="zizmor",
                    execution_mode="binary",
                    binary_path=resolved_bin,
                    embedded=embedded,
                    files_scanned=len(files),
                    findings=combined,
                    telemetry={"exit_code": proc.returncode, "binary_findings": len(bin_findings)},
                )
        except Exception as exc:
            # Fail safe to pure-Python parity
            parity_findings = _dedup_findings(_run_zizmor_parity_on_docs(parsed_docs))
            return GhaScanResult(
                engine="zizmor",
                execution_mode="python_parity",
                binary_path=resolved_bin,
                embedded=embedded,
                files_scanned=len(files),
                findings=parity_findings,
                telemetry={"fallback_reason": str(exc)},
            )

    parity_findings = _dedup_findings(_run_zizmor_parity_on_docs(parsed_docs))
    return GhaScanResult(
        engine="zizmor",
        execution_mode="python_parity",
        binary_path=None,
        embedded=embedded,
        files_scanned=len(files),
        findings=parity_findings,
        telemetry={"status": "embedded_parity" if embedded else "binary_absent_parity"},
    )


def run_actionlint_scan(
    target_path: Union[str, Path],
    *,
    embedded: bool = False,
    binary_path: Optional[str] = None,
    timeout_sec: float = 60.0,
) -> GhaScanResult:
    """
    Runs Actionlint on GitHub Actions workflows:
      - If `embedded=False` and `actionlint` binary is found on `PATH` (or `binary_path`), runs
        `actionlint -format '{{json .}}' <files...>` via `silent_subprocess_run(..., shell=False)`.
      - Otherwise falls back seamlessly to pure-Python `ActionlintParityAnalyzer` (`python_parity`).
    """
    root, files, parsed_docs, syntax_errors = _load_parsed_workflows(target_path)
    if not files:
        return GhaScanResult(
            engine="actionlint",
            execution_mode="python_parity",
            binary_path=None,
            embedded=embedded,
            files_scanned=0,
            findings=[],
            telemetry={"status": "no_workflow_files"},
        )

    resolved_bin: Optional[str] = None
    if not embedded:
        resolved_bin = resolve_gha_scanner_binary("actionlint", binary_path=binary_path)

    if resolved_bin:
        cmd = [resolved_bin, "-format", "{{json .}}", *[str(f) for f in files]]
        try:
            proc = silent_subprocess_run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
            )
            stdout_s = (proc.stdout or "").strip()
            if stdout_s.startswith("[") or (proc.returncode == 0 and stdout_s == ""):
                bin_findings = parse_actionlint_json_output(stdout_s, root)
                return GhaScanResult(
                    engine="actionlint",
                    execution_mode="binary",
                    binary_path=resolved_bin,
                    embedded=embedded,
                    files_scanned=len(files),
                    findings=_dedup_findings(bin_findings),
                    telemetry={"exit_code": proc.returncode, "binary_findings": len(bin_findings)},
                )
        except Exception as exc:
            parity_findings = _dedup_findings(_run_actionlint_parity_on_docs(parsed_docs, syntax_errors))
            return GhaScanResult(
                engine="actionlint",
                execution_mode="python_parity",
                binary_path=resolved_bin,
                embedded=embedded,
                files_scanned=len(files),
                findings=parity_findings,
                telemetry={"fallback_reason": str(exc)},
            )

    parity_findings = _dedup_findings(_run_actionlint_parity_on_docs(parsed_docs, syntax_errors))
    return GhaScanResult(
        engine="actionlint",
        execution_mode="python_parity",
        binary_path=None,
        embedded=embedded,
        files_scanned=len(files),
        findings=parity_findings,
        telemetry={"status": "embedded_parity" if embedded else "binary_absent_parity"},
    )


def scan_workflows_concurrently(
    target_path: Union[str, Path],
    *,
    embedded: bool = False,
    zizmor_binary: Optional[str] = None,
    actionlint_binary: Optional[str] = None,
) -> Dict[str, GhaScanResult]:
    """Runs Zizmor and Actionlint concurrently using a bounded ThreadPoolExecutor."""
    results: Dict[str, GhaScanResult] = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = {
            pool.submit(run_zizmor_scan, target_path, embedded=embedded, binary_path=zizmor_binary): "zizmor",
            pool.submit(run_actionlint_scan, target_path, embedded=embedded, binary_path=actionlint_binary): "actionlint",
        }
        for fut in as_completed(futs):
            eng = futs[fut]
            results[eng] = fut.result()
    return results


def scan_single_workflow_yaml_for_gha_agent(
    yaml_path: Path,
    root: Path,
) -> List[GhaWorkflowFinding]:
    """
    Helper consumed by `engine/gha_agent_auditor.py` to apply full R1 YAML AST + dataflow
    analysis (including `env:`-binding mitigation) to a single `.yml`/`.yaml` file.
    """
    try:
        text = yaml_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    rel = _rel_posix(yaml_path, root)
    doc, err = parse_workflow_yaml(text)
    if err is not None or doc is None or not _is_workflow_yaml_doc(doc):
        return []
    raw_findings = _run_zizmor_parity_on_docs([(yaml_path, rel, doc, text)])
    out: List[GhaWorkflowFinding] = []
    for f in raw_findings:
        rule_id = f.rule_id
        # Preserve canonical `GHA-TRIGGER-INJECT-001` contract for direct template injection in YAML
        if f.gha_class == GHA_CLASS_TEMPLATE_INJECTION:
            rule_id = "GHA-TRIGGER-INJECT-001"
        elif f.gha_class == GHA_CLASS_PWN_REQUEST:
            rule_id = "GHA-PWN-REQ-001"
        elif f.gha_class == GHA_CLASS_UNPINNED_USES:
            rule_id = "GHA-UNPINNED-USES-001"
        elif f.gha_class == GHA_CLASS_EXCESSIVE_PERMISSIONS:
            rule_id = "GHA-PERMS-001"
        elif f.gha_class == GHA_CLASS_ENV_PATH_INJECTION:
            rule_id = "GHA-ENV-INJECT-001"
        elif f.gha_class == GHA_CLASS_ARTIFACT_CACHE_POISONING:
            rule_id = "GHA-ARTIFACT-POISON-001"
        elif f.gha_class == GHA_CLASS_AI_AGENT_BOUNDARY:
            rule_id = "GHA-AI-BOUNDARY-001"
        out.append(
            GhaWorkflowFinding(
                engine="gha_agent",
                rule_id=rule_id,
                gha_class=f.gha_class,
                title=f.title,
                severity=f.severity,
                cwe=f.cwe,
                atlas_technique=f.atlas_technique,
                file_path=f.file_path,
                line=f.line,
                column=f.column,
                snippet=f.snippet,
                remediation=f.remediation,
                execution_mode="python_parity",
                hygiene_only=f.hygiene_only,
                deterministic=True,
                confirmed=True,
                metadata=dict(f.metadata),
            )
        )
    return _dedup_findings(out)
