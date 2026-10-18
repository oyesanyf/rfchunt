"""
Module 16: Google Research Harness² Recursive Agent Harnessing Engine.

Implements the two-level recursive agent harnessing architecture from:
  "Harness²: Recursive Agent Harnessing for an Open World"
  Ruiyao Xu, Yanfei Chen, Zhongying CuiZhu, Bhavana Dalvi Mishra, Yifei Ming,
  Han Yu, Rujun Han, Chen-Yu Lee, Tomas Pfister (Google Research, arXiv:2610.14224, 2026)
  Repository: https://github.com/google-research/harness2

Core Architecture:
  1. Eight Editable Harness Components (c1..c8 SurfaceSpec):
     - c1: systemprompt.md (Always-on micro-inspiration & protocol synthesis prompt)
     - c2: guardrails.md (Always-on constraints, anti-anchoring rules & skill triggers)
     - c3: LongTermMEMORY.md (Always-on cross-RFC empirical protocol memory)
     - c4: tool_descriptions/tool_guidance.md (Always-on 3-step canary & ruler tool guidance)
     - c5: sub_agents/<name>/AGENT.md (Delegated protocol specialist subagents)
     - c6: skills/<name>/SKILL.md (Reusable on-demand protocol audit workflows)
     - c7: scripts/<name>.py (Deterministic Python wire-framing & boundary helpers)
     - c8: plugin/<name>.ts (In-loop guard plugins enforcing protocol invariants)

  2. Level 1 - Task-Level Contrastive Recursion (Propose -> Probe -> Compose):
     - Refines the execution harness for the current RFC/protocol task without ground-truth
       labels by contrasting behavioral trajectories across candidate harnesses.
     - Supports both 'parallel' ('agg' - width exploration) and 'sequential' ('seq' - depth
       refinement) modes under strict budget accounting:
         R = 4k rollouts  (k shared base + 2k candidates + k finals)
         P = 3k stages    (k INV + k DOM + k compositions)

  3. Level 2 - Harnessing-Level Recursion (Per-Domain Experience Library):
     - Updates a persistent per-domain library on disk with adopted full c1..c8 trees
       and evidence-supported lessons (cue, lesson, evidence) in INDEX.md and EXPERIENCE.md
       to guide future unseen RFCs and protocol targets.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import shutil
import time
import unicodedata
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from engine.differential_oracle import MultiImplementationDifferentialOracle
from engine.dream_world_model import ProtocolWorldModel

Tree = Dict[str, str]

RESERVED_SCRIPTS = frozenset({"read_doc.py", "pack.py", "unpack.py"})
WIN_DEVICE_NAMES = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
    "conin$", "conout$", "clock$",
})
STAGE_ATTEMPTS = 2
PHASE_WIDTH = 4
_NAME_PATTERN = r"[a-z0-9][a-z0-9_\-]*"



# =====================================================================
# 1. Editable Surface Specification (c1..c8 Component Tree)
# =====================================================================

@dataclass(frozen=True)
class SurfaceSpec:
    """The editable c1..c8 surface of the agent framework: paths, caps, and validation rules."""

    name: str
    always_on: Tuple[str, ...]
    always_on_max: int
    always_on_cap_reason: str
    skill_dir: str
    skill_name_rule: str
    trigger_hint: str
    autotrigger_file: str
    trigger_line: str
    subagent_requires_mode: bool
    plugin_dir: Optional[str]
    hooks_file: Optional[str]
    hook_events: frozenset[str] = frozenset()
    compile_skill_scripts: bool = True
    reject_empty_always_on: bool = True
    stubs: Tuple[Tuple[str, str], ...] = ()


RFCHUNT_SURFACE = SurfaceSpec(
    name="rfchunt_opencode",
    always_on=(
        "systemprompt.md",
        "guardrails.md",
        "LongTermMEMORY.md",
        "tool_descriptions/tool_guidance.md",
    ),
    always_on_max=24_000,
    always_on_cap_reason="every token here competes with the agent's own wire synthesis budget",
    skill_dir="skills",
    skill_name_rule="must_match",
    trigger_hint=(
        "Fix it by adding a trigger line naming `{name}` to systemprompt.md or "
        'guardrails.md, e.g. "- When <the situation this skill handles>, load the '
        '`{name}` skill."'
    ),
    autotrigger_file="guardrails.md",
    trigger_line="- When {desc}, load the `{name}` skill.\n",
    subagent_requires_mode=True,
    plugin_dir="plugin",
    hooks_file=None,
    compile_skill_scripts=True,
    reject_empty_always_on=True,
    stubs=(
        (
            "scripts/README.md",
            "<!-- c7: deterministic helpers, run as `python3 scripts/<name>.py`. "
            "Add one by emitting scripts/<name>.py. -->\n",
        ),
        (
            "sub_agents/README.md",
            "<!-- c5: delegated subagents, invoked with the `task` tool in their OWN context. "
            "Add one as sub_agents/<name>/AGENT.md with frontmatter `mode: subagent` and "
            "`description:`. -->\n",
        ),
        (
            "plugin/README.md",
            "<!-- c8: in-loop plugins. Acts INSIDE the tool loop -- the only lever that can "
            "enforce something the model cannot skip. Add one as plugin/<name>.ts. -->\n",
        ),
        (
            "skills/README.md",
            "<!-- c6: reusable workflows loaded on demand via the `skill` tool. Add one as "
            "skills/<name>/SKILL.md with frontmatter `name:` matching the directory and a "
            "`description:`. -->\n",
        ),
    ),
)


@lru_cache(maxsize=8)
def _compiled_surface_regexes(
    surface_name: str, skill_dir: str, plugin_dir: Optional[str]
) -> Dict[str, re.Pattern]:
    sd = re.escape(skill_dir)
    out = {
        "skill": re.compile(rf"{sd}/({_NAME_PATTERN})/SKILL\.md"),
        "skill_script": re.compile(rf"{sd}/{_NAME_PATTERN}/scripts/[A-Za-z0-9_.\-]+"),
        "subagent": re.compile(rf"sub_agents/({_NAME_PATTERN})/AGENT\.md"),
        "script": re.compile(r"scripts/[a-z0-9_][a-z0-9_]*\.py"),
        "script_ref": re.compile(rf"(?:python3?\s+)((?:{sd}/[\w\-]+/)?scripts/[\w.\-]+\.py)"),
    }
    if plugin_dir is not None:
        out["plugin"] = re.compile(rf"{re.escape(plugin_dir)}/({_NAME_PATTERN})\.ts")
    return out


def _rx(surface: SurfaceSpec) -> Dict[str, re.Pattern]:
    return _compiled_surface_regexes(surface.name, surface.skill_dir, surface.plugin_dir)


def normalize_rel(rel: str, base_dir: Optional[Path] = None) -> Any:
    """Normalise a relative path, rejecting escapes, drive letters, and percent-encoded traversal.

    If base_dir is supplied, validates that the path resolves strictly inside base_dir and returns
    the canonical Path object per PROJECT.md:68. Otherwise returns the cleaned normalized relative string.
    """
    raw = str(rel).strip()
    if not raw:
        raise ValueError(f"empty relative path on harness surface: {rel!r}")

    # 1. Iterative URL decoding (up to 10 iterations) to reach fixed point
    curr = raw
    for _ in range(10):
        dec = urllib.parse.unquote(curr)
        if dec == curr:
            break
        curr = dec

    # 2. Normalize Unicode (NFKC) to defeat fullwidth slashes, dots, and colons
    normalized_str = unicodedata.normalize("NFKC", curr)

    # 3. Reject null bytes across raw, decoded, and normalized representations
    if "\x00" in raw or "\x00" in curr or "\x00" in normalized_str:
        raise ValueError(f"path escapes the harness: {rel!r}")

    # 4. Multi-level percent-encoding regex interceptor for traversal, colons, nulls, slashes
    raw_lower = raw.lower()
    if re.search(r"%(?:25)*(?:2e|2f|5c|3a|00)", raw_lower):
        raise ValueError(f"path escapes the harness: {rel!r}")

    # 5. Normalize path separators to forward slash
    norm_slash = normalized_str.replace("\\", "/")
    raw_slash = raw.replace("\\", "/")

    # 6. Reject absolute paths, UNC paths, and colons (drive letters and NTFS ADS)
    if (
        norm_slash.startswith("/")
        or raw_slash.startswith("/")
        or ":" in norm_slash
        or ":" in raw_slash
        or "//" in norm_slash
        or "//" in raw_slash
        or raw.startswith("//")
        or raw.startswith(r"\\")
        or raw_slash.startswith("//")
    ):
        raise ValueError(f"path escapes the harness: {rel!r}")

    # 7. Strip leading relative prefixes (./)
    while norm_slash.startswith("./"):
        norm_slash = norm_slash[2:]
    while raw_slash.startswith("./"):
        raw_slash = raw_slash[2:]

    # 8. Check for directory traversal sequences (..) and curdir (.)
    parts = norm_slash.split("/")
    raw_parts = raw_slash.split("/")
    if any(p == ".." or p == "." for p in parts if p) or any(p == ".." for p in raw_parts if p):
        raise ValueError(f"path escapes the harness: {rel!r}")

    cleaned = norm_slash.strip("/")
    if not cleaned or cleaned == ".":
        raise ValueError(f"empty relative path on harness surface: {rel!r}")

    # 9. Exhaustive Windows reserved device name check across normalized and decoded components
    for part in cleaned.split("/"):
        stem = part.split(".")[0].rstrip(" .").lower()
        part_clean = part.rstrip(" .").lower()
        if stem in WIN_DEVICE_NAMES or part_clean in WIN_DEVICE_NAMES:
            raise ValueError(f"path contains Windows reserved device name: {rel!r}")

    for part in curr.replace("\\", "/").strip("/").split("/"):
        stem = part.split(".")[0].rstrip(" .").lower()
        part_clean = part.rstrip(" .").lower()
        if stem in WIN_DEVICE_NAMES or part_clean in WIN_DEVICE_NAMES:
            raise ValueError(f"path contains Windows reserved device name: {rel!r}")

    # 10. Post-join canonical containment check against base_dir
    if base_dir is not None:
        base_path = Path(base_dir).resolve()
        resolved = (base_path / cleaned).resolve()
        if resolved == base_path or not resolved.is_relative_to(base_path):
            raise ValueError(f"path escapes base directory: {rel!r}")
        return resolved

    return cleaned


def is_allowed(surface: SurfaceSpec, rel: str) -> bool:
    """Whether this path is on the editable c1..c8 surface. Never raises."""
    try:
        rel = normalize_rel(rel)
    except ValueError:
        return False
    if rel in surface.always_on:
        return True
    if surface.hooks_file is not None and rel == surface.hooks_file:
        return True
    r = _rx(surface)
    if (
        r["skill"].fullmatch(rel)
        or r["skill_script"].fullmatch(rel)
        or r["subagent"].fullmatch(rel)
        or r["script"].fullmatch(rel)
    ):
        return True
    return "plugin" in r and bool(r["plugin"].fullmatch(rel))


def skill_names(surface: SurfaceSpec, tree: Tree) -> List[str]:
    rx = _rx(surface)["skill"]
    return sorted({m.group(1) for rel in tree if (m := rx.fullmatch(rel))})


def subagent_names(surface: SurfaceSpec, tree: Tree) -> List[str]:
    rx = _rx(surface)["subagent"]
    return sorted({m.group(1) for rel in tree if (m := rx.fullmatch(rel))})


def _frontmatter_field(body: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}:\s*(.+)$", body[:800], re.M)
    return m.group(1).strip().strip("'\"") if m else ""


def autotrigger(surface: SurfaceSpec, tree: Tree) -> List[str]:
    """Ensure every skill on c6 is referenced in always-on text; auto-inject trigger lines if missing."""
    always_text = "\n".join(tree.get(k, "") for k in surface.always_on)
    rx = _rx(surface)["skill"]
    triggered: List[str] = []
    for rel, body in list(tree.items()):
        m = rx.fullmatch(rel)
        if not m:
            continue
        name = m.group(1)
        if not re.search(rf"\b{re.escape(name)}\b", always_text):
            desc = _frontmatter_field(body, "description") or f"analyzing {name} protocol anomalies"
            line = surface.trigger_line.format(name=name, desc=desc)
            current_guard = tree.get(surface.autotrigger_file, "")
            if current_guard and not current_guard.endswith("\n"):
                current_guard += "\n"
            tree[surface.autotrigger_file] = current_guard + line
            always_text += "\n" + line
            triggered.append(name)
    return triggered



def validate_tree(
    surface: SurfaceSpec,
    tree: Tree,
    *,
    allow_subagents: bool = True,
    reserved_scripts: frozenset[str] = RESERVED_SCRIPTS,
) -> None:
    """Validate c1..c8 surface constraints, caps, frontmatter rules, and Python script syntax."""
    for rel in tree:
        try:
            norm = normalize_rel(rel)
        except ValueError:
            raise ValueError(f"off-surface path rejected: {rel!r}")
        if not is_allowed(surface, norm):
            raise ValueError(f"off-surface path rejected: {rel!r}")

    if surface.reject_empty_always_on:
        if not any(a in tree for a in surface.always_on) or not all(
            tree.get(a, "").strip() for a in surface.always_on if a in tree
        ):
            raise ValueError("always-on harness components (c1..c4) cannot be empty")

    always_chars = sum(len(tree.get(a, "")) for a in surface.always_on)
    if always_chars > surface.always_on_max:
        raise ValueError(
            f"always-on text length ({always_chars}) exceeds cap ({surface.always_on_max}): "
            f"{surface.always_on_cap_reason}"
        )

    r = _rx(surface)
    for rel, body in tree.items():
        norm = normalize_rel(rel)
        if m := r["skill"].fullmatch(norm):
            skill_id = m.group(1)
            fm_name = _frontmatter_field(body, "name")
            fm_desc = _frontmatter_field(body, "description")
            if surface.skill_name_rule == "must_match" and fm_name != skill_id:
                raise ValueError(
                    f"skill {norm!r} frontmatter `name: {fm_name!r}` must match directory `{skill_id}`"
                )
            if not fm_desc:
                raise ValueError(f"skill {norm!r} is missing frontmatter `description:`")

        elif m := r["subagent"].fullmatch(norm):
            if not allow_subagents:
                raise ValueError(f"subagents are disabled for this spec: {norm!r}")
            fm_mode = _frontmatter_field(body, "mode")
            fm_desc = _frontmatter_field(body, "description")
            if surface.subagent_requires_mode and fm_mode != "subagent":
                raise ValueError(f"subagent {norm!r} requires frontmatter `mode: subagent`")
            if not fm_desc:
                raise ValueError(f"subagent {norm!r} requires frontmatter `description:`")

        elif "plugin" in r and r["plugin"].fullmatch(norm):
            if not body.strip():
                raise ValueError(f"plugin {norm!r} (c8) cannot be empty")

        elif r["script"].fullmatch(norm) or (
            surface.compile_skill_scripts and r["skill_script"].fullmatch(norm) and norm.endswith(".py")
        ):
            basename = Path(norm).name
            if basename in reserved_scripts:
                raise ValueError(f"script {basename!r} is reserved and cannot be overwritten")
            try:
                ast.parse(body, filename=norm)
            except SyntaxError as exc:
                raise ValueError(f"Python syntax error in harness script {norm!r}: {exc}") from exc


def diff_summary(surface: SurfaceSpec, old: Tree, new: Tree) -> Dict[str, List[str]]:
    """Compute added, removed, and modified files between two c1..c8 trees."""
    old_keys = {normalize_rel(k) for k in old if is_allowed(surface, k)}
    new_keys = {normalize_rel(k) for k in new if is_allowed(surface, k)}
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    modified = sorted(k for k in (old_keys & new_keys) if old.get(k) != new.get(k))
    return {"added": added, "removed": removed, "modified": modified}


def diversity(trees: Mapping[str, Tree]) -> Dict[str, Any]:
    """Compute pairwise Jaccard token diversity across composed candidate trees."""
    labels = sorted(trees.keys())
    if len(labels) < 2:
        return {"mean_jaccard_similarity": 1.0, "pairwise": {}}

    token_sets: Dict[str, set[str]] = {}
    for lbl in labels:
        combined = "\n".join(f"{k}:{v}" for k, v in sorted(trees[lbl].items()))
        tokens = set(re.findall(r"[A-Za-z0-9_\-]+", combined.lower()))
        token_sets[lbl] = tokens or {"_empty_"}

    pairwise: Dict[str, float] = {}
    scores: List[float] = []
    for i in range(len(labels)):
        for j in range(i + 1, len(labels)):
            a, b = labels[i], labels[j]
            inter = len(token_sets[a] & token_sets[b])
            union = len(token_sets[a] | token_sets[b]) or 1
            sim = round(inter / union, 4)
            pairwise[f"{a}__vs__{b}"] = sim
            scores.append(sim)

    mean_sim = round(sum(scores) / len(scores), 4) if scores else 1.0
    return {
        "mean_jaccard_similarity": mean_sim,
        "diversity_index": round(1.0 - mean_sim, 4),
        "pairwise": pairwise,
    }


def read_tree(
    surface: SurfaceSpec, d: Path | str, *, rejected: Optional[List[str]] = None
) -> Tree:
    """Read rel -> content for every file on the editable c1..c8 surface, excluding README stubs."""
    d = Path(d)
    out: Tree = {}
    if not d.is_dir():
        return out
    stubs = frozenset(rel for rel, _ in surface.stubs)
    for p in sorted(d.rglob("*")):
        if not p.is_file() or "__pycache__" in p.parts:
            continue
        rel = str(p.relative_to(d)).replace("\\", "/")
        if rel in stubs:
            continue
        if not is_allowed(surface, rel):
            if rejected is not None:
                rejected.append(rel)
            continue
        out[rel] = p.read_text(encoding="utf-8", errors="replace")
    return out


def write_tree(
    surface: SurfaceSpec, tree: Tree, dest: Path | str, *, stubs: bool = True
) -> Path:
    """Write a validated c1..c8 tree to disk, optionally including README component stubs."""
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    for a in surface.always_on:
        p = dest / normalize_rel(a)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(tree.get(a, ""), encoding="utf-8")

    for rel, content in sorted(tree.items()):
        norm = normalize_rel(rel)
        if not is_allowed(surface, norm):
            continue
        p = dest / norm
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    if stubs:
        for stub_rel, stub_body in surface.stubs:
            sp = dest / normalize_rel(stub_rel)
            if not sp.exists():
                sp.parent.mkdir(parents=True, exist_ok=True)
                sp.write_text(stub_body, encoding="utf-8")

    return dest


def merge_tree_proposal(surface: SurfaceSpec, base: Tree, delta: Tree) -> Tree:
    """Omitted-is-inherited edit contract: a proposal emits only what it changes."""
    merged = copy.deepcopy(base)
    for rel, body in delta.items():
        norm = normalize_rel(rel)
        if is_allowed(surface, norm):
            merged[norm] = body
    autotrigger(surface, merged)
    return merged


# =====================================================================
# 2. Budget Accounting Ledger (R = 4k Rollouts, P = 3k Stages)
# =====================================================================

def expected_rollouts(k: int) -> int:
    """R = 4k: k shared base + 2k candidates + k finals."""
    return 4 * int(k)


def expected_sessions(k: int) -> int:
    """P = 3k: k INV + k DOM + k compositions (parallel: agg1..aggk; sequential: c1..ck)."""
    return 3 * int(k)


class BudgetError(AssertionError):
    """The Harness² ledger did not land on the exact R = 4k / P = 3k budget identity."""


@dataclass
class Entry:
    kind: str  # 'rollout' or 'session'
    label: str
    usd: float = 0.0
    cached: bool = False
    attempts: int = 1


@dataclass
class Ledger:
    """Everything one recursion mode spent on one RFC/protocol task."""

    mode: str
    task_id: str
    k: int
    entries: List[Entry] = field(default_factory=list)

    def rollout(self, label: str, usd: float = 0.0, *, cached: bool = False) -> None:
        self.entries.append(Entry("rollout", label, usd=usd, cached=cached, attempts=1))

    def session(
        self, label: str, usd: float = 0.0, *, cached: bool = False, attempts: int = 1
    ) -> None:
        self.entries.append(
            Entry("session", label, usd=usd, cached=cached, attempts=max(1, attempts))
        )

    @property
    def rollouts_count(self) -> int:
        return sum(1 for e in self.entries if e.kind == "rollout")

    @property
    def rollouts(self) -> int:
        return self.rollouts_count

    @property
    def sessions_count(self) -> int:
        return sum(1 for e in self.entries if e.kind == "session")

    @property
    def sessions(self) -> int:
        return self.sessions_count

    @property
    def expected_rollouts(self) -> int:
        return expected_rollouts(self.k)

    @property
    def expected_sessions(self) -> int:
        return expected_sessions(self.k)

    def assert_identity(self) -> None:
        exp_r = expected_rollouts(self.k)
        exp_p = expected_sessions(self.k)
        if self.rollouts_count != exp_r or self.sessions_count != exp_p:
            raise BudgetError(
                f"Harness² budget violation on task={self.task_id!r} (mode={self.mode}, k={self.k}): "
                f"expected R={exp_r} rollouts & P={exp_p} sessions, "
                f"got R={self.rollouts_count} & P={self.sessions_count}"
            )

    def verify_budget(self) -> bool:
        self.assert_identity()
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "task_id": self.task_id,
            "k": self.k,
            "expected_rollouts": expected_rollouts(self.k),
            "actual_rollouts": self.rollouts_count,
            "expected_sessions": expected_sessions(self.k),
            "actual_sessions": self.sessions_count,
            "budget_verified": (
                self.rollouts_count == expected_rollouts(self.k)
                and self.sessions_count == expected_sessions(self.k)
            ),
            "total_usd": round(sum(e.usd for e in self.entries), 4),
            "entries": [
                {
                    "kind": e.kind,
                    "label": e.label,
                    "usd": e.usd,
                    "cached": e.cached,
                    "attempts": e.attempts,
                }
                for e in self.entries
            ],
        }


# =====================================================================
# 3. Per-Domain Experience Library (Harnessing-Level Recursion)
# =====================================================================

def slug(task_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]", "__", str(task_id).strip()) or "task"


def domain_dir(domain: str) -> str:
    return re.sub(r"\s*[/\\]\s*", "__", str(domain)).strip() or "unknown"


def has_experience(experience: Optional[Dict[str, str]]) -> bool:
    return isinstance(experience, dict) and all(
        isinstance(experience.get(key), str) and experience[key].strip()
        for key in ("cue", "lesson", "evidence")
    )


@dataclass
class Library:
    """Per-domain experience library R: read before each task, appended after."""

    root: Path
    domain: str
    surface: SurfaceSpec = RFCHUNT_SURFACE

    @property
    def dir(self) -> Path:
        return Path(self.root) / domain_dir(self.domain)

    @property
    def index(self) -> Path:
        return self.dir / "INDEX.md"

    def entry_dir(self, task_id: str) -> Path:
        return self.dir / "harnesses" / slug(task_id)

    def exists(self) -> bool:
        return self.index.is_file()

    def context_dir(self) -> Optional[Path]:
        return self.dir if self.exists() and any(self.dir.rglob("EXPERIENCE.md")) else None

    def entries(self) -> List[str]:
        d = self.dir / "harnesses"
        if not d.is_dir():
            return []
        dirs = [p for p in d.iterdir() if p.is_dir()]
        dirs.sort(key=lambda p: p.stat().st_mtime)
        return [p.name for p in dirs]

    def tree_of(self, task_id: str) -> Tree:
        return read_tree(self.surface, self.entry_dir(task_id) / "harness")

    def record(
        self,
        task_id: str,
        adopted_tree: Tree,
        experience: Dict[str, str],
        *,
        picked_label: str = "agg1",
        contrast_score: float = 0.0,
    ) -> Path:
        """Persist the full adopted c1..c8 tree and EXPERIENCE.md into the domain library."""
        if not has_experience(experience):
            raise ValueError(
                f"experience for {task_id!r} must include non-empty 'cue', 'lesson', and 'evidence'"
            )
        edir = self.entry_dir(task_id)
        write_tree(self.surface, adopted_tree, edir / "harness", stubs=True)

        exp_md = (
            f"# Experience Record: {task_id}\n\n"
            f"- **Domain**: `{self.domain}`\n"
            f"- **Adopted Candidate**: `{picked_label}`\n"
            f"- **Behavioral Contrast Score**: `{contrast_score:.2f}`\n"
            f"- **Cue**: {experience['cue'].strip()}\n"
            f"- **Lesson**: {experience['lesson'].strip()}\n"
            f"- **Evidence**: {experience['evidence'].strip()}\n"
        )
        (edir / "EXPERIENCE.md").write_text(exp_md, encoding="utf-8")

        self.dir.mkdir(parents=True, exist_ok=True)
        idx_header = (
            f"# Harness² Domain Experience Library: `{self.domain}`\n\n"
            "| Task ID | Adopted Stage | Contrast Score | Cue | Lesson |\n"
            "| :--- | :--- | :--- | :--- | :--- |\n"
        )
        current_idx = self.index.read_text(encoding="utf-8") if self.index.is_file() else idx_header
        row = (
            f"| `{task_id}` | `{picked_label}` | `{contrast_score:.2f}` | "
            f"{experience['cue'].strip()} | {experience['lesson'].strip()} |\n"
        )
        pattern = rf"^\|\s*`{re.escape(task_id)}`\s*\|.*$"
        if re.search(pattern, current_idx, flags=re.M):
            current_idx = re.sub(pattern, row.strip(), current_idx, flags=re.M)
            if not current_idx.endswith("\n"):
                current_idx += "\n"
        else:
            if not current_idx.endswith("\n"):
                current_idx += "\n"
            current_idx += row
        self.index.write_text(current_idx, encoding="utf-8")
        return edir

    def load_domain_lessons(self) -> List[Dict[str, str]]:
        """Read all prior EXPERIENCE.md lessons in this domain for harnessing-level recursion."""
        lessons: List[Dict[str, str]] = []
        d = self.dir / "harnesses"
        if not d.is_dir():
            return lessons
        dir_entries = [p for p in d.iterdir() if p.is_dir()]
        dir_entries.sort(key=lambda p: p.stat().st_mtime)
        for p in dir_entries:
            exp_file = p / "EXPERIENCE.md"
            if not exp_file.is_file():
                continue
            txt = exp_file.read_text(encoding="utf-8", errors="replace")
            cue_m = re.search(r"-\s*\*\*Cue\*\*:\s*(.+)", txt)
            les_m = re.search(r"-\s*\*\*Lesson\*\*:\s*(.+)", txt)
            evi_m = re.search(r"-\s*\*\*Evidence\*\*:\s*(.+)", txt)
            if cue_m and les_m and evi_m:
                lessons.append(
                    {
                        "task": p.name,
                        "cue": cue_m.group(1).strip(),
                        "lesson": les_m.group(1).strip(),
                        "evidence": evi_m.group(1).strip(),
                    }
                )
        return lessons


# =====================================================================
# 4. Rollout Views, Stage Records & Mode Results
# =====================================================================

@dataclass
class RunView:
    """Behavioral trajectory captured when probing a candidate c1..c8 harness on an RFC task."""

    label: str
    task_id: str
    probes_executed: int = 0
    parser_divergences: int = 0
    simulated_vulns: int = 0
    simulated_anomalies: int = 0
    false_positives: int = 0
    behavioral_score: float = 0.0
    sample_probes: List[str] = field(default_factory=list)
    active_skills: List[str] = field(default_factory=list)
    active_subagents: List[str] = field(default_factory=list)
    contrast_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "task_id": self.task_id,
            "probes_executed": self.probes_executed,
            "parser_divergences": self.parser_divergences,
            "simulated_vulns": self.simulated_vulns,
            "simulated_anomalies": self.simulated_anomalies,
            "false_positives": self.false_positives,
            "behavioral_score": round(self.behavioral_score, 4),
            "active_skills": self.active_skills,
            "active_subagents": self.active_subagents,
            "contrast_summary": self.contrast_summary,
        }


@dataclass
class Stage:
    """One Propose or Compose stage, including retries, validated tree, and decision notes."""

    label: str
    dim: str  # 'INV', 'DOM', 'AGG', or 'COMPOSE'
    tree: Tree
    kept_base: bool = False
    fell_back: bool = False
    error: str = ""
    usd: float = 0.0
    attempts: int = 1
    cached: bool = False
    notes: str = ""


@dataclass
class ModeResult:
    """Result of executing parallel ('agg') or sequential ('seq') Harness² recursion on a task."""

    mode: str
    task_id: str
    domain: str
    k: int
    stages: List[Stage] = field(default_factory=list)
    trees: Dict[str, Tree] = field(default_factory=dict)
    rollouts: Dict[str, RunView] = field(default_factory=dict)
    finals: List[str] = field(default_factory=list)
    adopted_label: str = ""
    adopted_tree: Tree = field(default_factory=dict)
    experience: Dict[str, str] = field(default_factory=dict)
    ledger: Optional[Ledger] = None
    similarity: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.finals) and not self.errors

    @property
    def fell_back(self) -> List[str]:
        return [s.label for s in self.stages if s.fell_back]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "task_id": self.task_id,
            "domain": self.domain,
            "k": self.k,
            "finals": self.finals,
            "adopted_label": self.adopted_label,
            "ok": self.ok,
            "fell_back": self.fell_back,
            "kept_base": [s.label for s in self.stages if s.kept_base],
            "experience": self.experience,
            "stages": [
                {
                    "label": s.label,
                    "dim": s.dim,
                    "fell_back": s.fell_back,
                    "kept_base": s.kept_base,
                    "attempts": s.attempts,
                    "usd": s.usd,
                    "cached": s.cached,
                    "notes": s.notes,
                    "error": (s.error or "")[:400],
                }
                for s in self.stages
            ],
            "rollouts": {k: v.to_dict() for k, v in self.rollouts.items()},
            "similarity": self.similarity,
            "ledger": self.ledger.to_dict() if self.ledger else None,
            "errors": self.errors,
        }


# =====================================================================
# 5. RFC Protocol Harness² Engine (Propose-Probe-Compose + Library)
# =====================================================================

class Harness2ProtocolEngine:
    """
    Google Research Harness² Recursive Agent Harnessing Engine integrated with rfchunt.
    Connects task-level recursion (Propose-Probe-Compose across c1..c8) with
    harnessing-level recursion (persistent per-domain experience libraries).
    """

    RFC_DOMAIN_MAP: Dict[str, str] = {
        "9112": "http11_framing",
        "7230": "http11_framing",
        "2616": "http11_framing",
        "9110": "http_semantics_intermediaries",
        "9113": "h2_translation",
        "7540": "h2_translation",
        "9114": "h3_quic",
        "8446": "tls13_pqc",
        "3986": "uri_normalization",
        "5321": "smtp_pipeline",
    }

    def __init__(
        self,
        runs_root: str | Path = "runs/harness2",
        target_host: str = "127.0.0.1",
        target_port: int = 8080,
        db_path: str = "terminator.db",
        surface: SurfaceSpec = RFCHUNT_SURFACE,
    ):
        self.runs_root = Path(runs_root)
        self.target_host = target_host
        self.target_port = target_port
        self.db_path = db_path
        self.surface = surface
        self.world_model = ProtocolWorldModel(target_host=target_host, target_port=target_port)
        self.world_model.ingest_history_from_db(db_path=db_path)
        self.diff_matrix = MultiImplementationDifferentialOracle()

    def resolve_domain(self, task_id: str, explicit_domain: str = "auto") -> str:
        if explicit_domain and explicit_domain != "auto":
            return explicit_domain
        num = re.sub(r"[^0-9]", "", str(task_id))
        return self.RFC_DOMAIN_MAP.get(num, "http11_framing")

    def build_base_harness(self, domain: str = "http11_framing") -> Tree:
        """Constructs the initial baseline c1..c8 component tree for protocol research."""
        tree: Tree = {
            "systemprompt.md": (
                "# Protocol Research Swarm System Directive (c1)\n"
                "Extract isolated 1-3 sentence normative grammar clauses from IETF RFC specifications.\n"
                "Synthesize raw wire HTTP/TLS byte sequences testing parser state boundaries.\n"
                "When analyzing chunked or content-length framing, load the `desync_framing` skill.\n"
            ),
            "guardrails.md": (
                "# Protocol Research Invariants & Guardrails (c2)\n"
                "- Never use generic exploit buzzwords ('request smuggling') in micro-inspiration prompts.\n"
                "- Enforce 3-trial deterministic verification before promoting any wire anomaly.\n"
                "- Submit all framing candidates to the 4-parser differential matrix.\n"
                "- When analyzing chunked or content-length framing, load the `desync_framing` skill.\n"
            ),
            "LongTermMEMORY.md": (
                f"# Long-Term Empirical Protocol Memory (c3) - Domain: {domain}\n"
                "- Front-end terminators frequently normalize obsolete line folding (obs-fold) into SP.\n"
                "- GET/HEAD requests carrying non-zero Content-Length (CL.0) trigger backend queue poisoning.\n"
            ),
            "tool_descriptions/tool_guidance.md": (
                "# Tool Execution Guidance (c4)\n"
                "1. Execute 3-Step Canary Pipeline: REQ 1 (Baseline) -> REQ 2 (Candidate) -> REQ 3 (Canary).\n"
                "2. Calibrate front-end header buffer limits via Protocol Ruler binary search.\n"
                "3. Delta-debug confirmed anomalies down to the minimal triggering byte sequence.\n"
            ),
            "skills/desync_framing/SKILL.md": (
                "---\n"
                "name: desync_framing\n"
                "description: analyzing chunked or content-length framing\n"
                "---\n"
                "# Desync Framing Skill (c6)\n"
                "Test dual Content-Length / Transfer-Encoding headers, chunk extensions, and CL.0 queues.\n"
            ),
            "sub_agents/boundary_arbiter/AGENT.md": (
                "---\n"
                "mode: subagent\n"
                "description: Differential boundary parser specialist\n"
                "---\n"
                "# Boundary Arbiter Subagent (c5)\n"
                "Compare Strict RFC 9112, Legacy RFC 2616, CDN Proxy, and Async Gateway parse trees.\n"
            ),
            "scripts/wire_frame_helper.py": (
                "def build_cl0_probe(host: str = '127.0.0.1') -> bytes:\n"
                "    return f'GET / HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 5\\r\\n\\r\\n0\\r\\n\\r\\n'.encode('latin-1')\n"
            ),
            "plugin/framing_guard.ts": (
                "// c8: In-loop protocol framing enforcement plugin\n"
                "export function enforceStrictCRLF(payload: string): boolean {\n"
                "  return payload.includes('\\r\\n\\r\\n');\n"
                "}\n"
            ),
        }
        autotrigger(self.surface, tree)
        validate_tree(self.surface, tree)
        return tree

    def _propose_candidate_tree(
        self,
        *,
        label: str,
        dim: str,
        index: int,
        round_t: Optional[int],
        base_tree: Tree,
        task_id: str,
        domain: str,
        prior_rollouts: Sequence[RunView],
        domain_lessons: Sequence[Dict[str, str]],
        pool: Sequence[Tuple[str, Tree, RunView]] = (),
    ) -> Tuple[Tree, str]:
        """
        Synthesizes a proposed c1..c8 harness edit along INV (general invariant),
        DOM (RFC domain-specific), AGG (parallel composition), or COMPOSE (sequential composition).
        """
        delta: Tree = {}
        notes_parts: List[str] = []

        if dim == "INV":
            skill_name = f"inv_ruler_norm_{index}"
            delta["guardrails.md"] = (
                base_tree.get("guardrails.md", "")
                + f"- [INV-{index}] Enforce strict byte-length differential checks on overlong UTF-8 and obs-fold sequences for {task_id}.\n"
            )
            delta[f"skills/{skill_name}/SKILL.md"] = (
                "---\n"
                f"name: {skill_name}\n"
                f"description: verifying byte-length invariants on {task_id} round {index}\n"
                "---\n"
                f"# Invariant Verification Skill ({label})\n"
                "Probe overlong UTF-8 (\\xc0\\x8a), NUL path termination, and trailing chunk extensions.\n"
            )
            delta[f"scripts/inv_helper_{index}.py"] = (
                "def synthesize_invariant_probes(host: str) -> list[bytes]:\n"
                "    return [\n"
                "        f'GET / HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 5\\r\\n\\r\\n0\\r\\n\\r\\n'.encode('latin-1'),\n"
                "        f'POST / HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\n'.encode('latin-1'),\n"
                "        f'GET / HTTP/1.1\\r\\nHost: {host}\\r\\nX-Fold: val\\r\\n continued\\r\\n\\r\\n'.encode('latin-1'),\n"
                "    ]\n"
            )
            notes_parts.append(
                f"Proposed INV candidate {label}: added skill `{skill_name}` and `scripts/inv_helper_{index}.py` for general framing invariants."
            )

        elif dim == "DOM":
            skill_name = f"dom_{domain}_{index}".replace("-", "_")[:32]
            lesson_hint = (
                domain_lessons[-1]["lesson"]
                if domain_lessons
                else f"Exploit {domain} state-machine transition ambiguities between front-end and origin."
            )
            delta["LongTermMEMORY.md"] = (
                base_tree.get("LongTermMEMORY.md", "")
                + f"- [DOM-{index} / {task_id}] {lesson_hint}\n"
            )
            delta["tool_descriptions/tool_guidance.md"] = (
                base_tree.get("tool_descriptions/tool_guidance.md", "")
                + f"\n4. [{label}] Prioritize {domain} boundary vectors (CL.0, H2.TE, TE.TE tab/VT obfuscation, CRLF splitting).\n"
            )
            delta[f"skills/{skill_name}/SKILL.md"] = (
                "---\n"
                f"name: {skill_name}\n"
                f"description: targeting {domain} specification edge cases on {task_id}\n"
                "---\n"
                f"# Domain Specialist Skill ({label})\n"
                f"Focus on {domain} grammar clauses in {task_id}: CL.0 HEAD/GET queue poisoning and TE obfuscation.\n"
            )
            delta[f"sub_agents/dom_specialist_{index}/AGENT.md"] = (
                "---\n"
                "mode: subagent\n"
                f"description: {domain} RFC grammar specialist {index}\n"
                "---\n"
                f"# Domain Subagent ({label})\n"
                f"Derive state-machine boundary probes for {task_id} in domain `{domain}`.\n"
            )
            notes_parts.append(
                f"Proposed DOM candidate {label}: specialized LongTermMEMORY.md, skill `{skill_name}`, and subagent for `{domain}`."
            )

        elif dim in ("AGG", "COMPOSE"):
            # Contrast behavioral rollouts from candidate pool and compose the winning edits
            ranked_pool = sorted(
                pool,
                key=lambda item: item[2].behavioral_score if item[2] else 0.0,
                reverse=True,
            )
            composed = copy.deepcopy(base_tree)
            adopted_sources: List[str] = []
            for cand_label, cand_tree, cand_view in ranked_pool:
                if cand_view and cand_view.behavioral_score >= 0:
                    adopted_sources.append(f"{cand_label}({cand_view.behavioral_score:.1f})")
                    for rel, content in cand_tree.items():
                        if rel not in composed or len(content) > len(composed[rel]):
                            composed[rel] = content

            comp_tag = f"{dim.lower()}_{label}"
            composed["systemprompt.md"] = (
                composed.get("systemprompt.md", "")
                + f"\n# Composed Refinement ({label} from {', '.join(adopted_sources[:4])})\n"
                f"Synthesize high-contrast {domain} probes combining invariant framing checks with domain grammar rules.\n"
            )
            composed[f"scripts/composed_{comp_tag}.py"] = (
                "def composed_probe_suite(host: str = '127.0.0.1') -> list[bytes]:\n"
                "    return [\n"
                "        f'GET / HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 5\\r\\n\\r\\n0\\r\\n\\r\\n'.encode('latin-1'),\n"
                "        f'HEAD / HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 5\\r\\n\\r\\n0\\r\\n\\r\\n'.encode('latin-1'),\n"
                "        f'POST / HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\n'.encode('latin-1'),\n"
                "        f'POST /nul HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 0\\r\\n\\r\\n'.encode('latin-1'),\n"
                "        f'GET / HTTP/1.1\\r\\nHost: {host}\\r\\nX-Foo:\\tbar\\r\\n\\r\\n'.encode('latin-1'),\n"
                "    ]\n"
            )
            autotrigger(self.surface, composed)
            return (
                composed,
                f"Composed {label} ({dim}) contrasting {', '.join(adopted_sources)}: merged top INV+DOM skills, subagents, and scripts.",
            )

        merged = merge_tree_proposal(self.surface, base_tree, delta)
        return merged, " ".join(notes_parts)

    def _run_stage(
        self,
        *,
        label: str,
        dim: str,
        index: int,
        round_t: Optional[int],
        fallback: Tree,
        task_id: str,
        domain: str,
        rollouts: Sequence[RunView],
        domain_lessons: Sequence[Dict[str, str]],
        pool: Sequence[Tuple[str, Tree, RunView]] = (),
    ) -> Stage:
        """Build evidence, propose/compose a c1..c8 edit, and retry an invalid proposal once."""
        last_err = ""
        for attempt in range(1, STAGE_ATTEMPTS + 1):
            try:
                cand_tree, notes = self._propose_candidate_tree(
                    label=label,
                    dim=dim,
                    index=index,
                    round_t=round_t,
                    base_tree=fallback,
                    task_id=task_id,
                    domain=domain,
                    prior_rollouts=rollouts,
                    domain_lessons=domain_lessons,
                    pool=pool,
                )
                autotrigger(self.surface, cand_tree)
                validate_tree(self.surface, cand_tree)
                changed = diff_summary(self.surface, fallback, cand_tree)
                kept_base = not (changed["added"] or changed["removed"] or changed["modified"])
                return Stage(
                    label=label,
                    dim=dim,
                    tree=cand_tree,
                    kept_base=kept_base,
                    fell_back=False,
                    attempts=attempt,
                    notes=notes,
                )
            except Exception as exc:
                last_err = str(exc)

        return Stage(
            label=label,
            dim=dim,
            tree=copy.deepcopy(fallback),
            kept_base=True,
            fell_back=True,
            error=last_err,
            attempts=STAGE_ATTEMPTS,
            notes=f"Fell back to base tree after {STAGE_ATTEMPTS} attempts: {last_err}",
        )

    def _probe_harness(
        self, label: str, task_id: str, domain: str, tree: Tree
    ) -> RunView:
        """
        Executes a candidate c1..c8 harness against the ProtocolWorldModel and
        4-Parser Differential Matrix without ground-truth labels to measure behavioral contrast.
        """
        skills = skill_names(self.surface, tree)
        subagents = subagent_names(self.surface, tree)
        scripts_count = sum(1 for k in tree if k.startswith("scripts/") and k.endswith(".py"))

        probe_suite: List[bytes] = [
            f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nContent-Length: 5\r\n\r\n0\r\n\r\n".encode("latin-1"),
            f"POST / HTTP/1.1\r\nHost: {self.target_host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".encode("latin-1"),
            f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nX-Fold: val\r\n continued\r\n\r\n".encode("latin-1"),
        ]

        # Enrich probes based on c1..c8 harness components present in tree
        if any("dom_" in s for s in skills) or subagents:
            probe_suite.extend([
                f"HEAD / HTTP/1.1\r\nHost: {self.target_host}\r\nContent-Length: 5\r\n\r\n0\r\n\r\n".encode("latin-1"),
                f"POST /nul HTTP/1.1\r\nHost: {self.target_host}\r\nContent-Length: 0\r\n\r\n".encode("latin-1"),
                f"POST / HTTP/1.1\r\nHost: {self.target_host}\r\nContent-Type: multipart/byteranges; boundary=B\r\nContent-Length: 0\r\n\r\n".encode("latin-1"),
            ])
        if scripts_count >= 2 or "composed" in " ".join(tree.keys()):
            probe_suite.extend([
                f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\nX-Tab:\tbar\r\n\r\n".encode("latin-1"),
                b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Ruler: \xc0\x8a\r\n\r\n",
                f"POST / HTTP/1.1\r\nHost: {self.target_host}\r\nTransfer-Encoding : chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n".encode("latin-1"),
            ])

        vulns = 0
        anomalies = 0
        divergences = 0
        fps = 0

        for raw_probe in probe_suite:
            sim = self.world_model.simulate_probe(raw_probe)
            if sim.is_vulnerability:
                vulns += 1
            elif sim.is_anomaly:
                anomalies += 1
            elif "framing omission" in sim.details.lower():
                fps += 1

            has_discrepancy, _, _ = self.diff_matrix.evaluate_matrix_4parsers(raw_probe)
            if has_discrepancy:
                divergences += 1

        score = (
            (10.0 * vulns)
            + (4.0 * divergences)
            + (3.0 * anomalies)
            + (1.5 * len(skills))
            + (1.5 * len(subagents))
            + (1.0 * scripts_count)
            - (8.0 * fps)
        )
        summary = (
            f"[{label}] Probes={len(probe_suite)} | Divergences={divergences} | "
            f"SimVulns={vulns} | SimAnomalies={anomalies} | Skills={len(skills)} | "
            f"Subagents={len(subagents)} | Score={score:.1f}"
        )
        return RunView(
            label=label,
            task_id=task_id,
            probes_executed=len(probe_suite),
            parser_divergences=divergences,
            simulated_vulns=vulns,
            simulated_anomalies=anomalies,
            false_positives=fps,
            behavioral_score=score,
            sample_probes=[p.decode("latin-1", errors="replace")[:80] for p in probe_suite[:3]],
            active_skills=skills,
            active_subagents=subagents,
            contrast_summary=summary,
        )

    def run_parallel(
        self,
        task_id: str,
        k: int = 1,
        *,
        domain: str = "auto",
        base_tree: Optional[Tree] = None,
        work_dir: Optional[Path] = None,
        library: Optional[Library] = None,
    ) -> ModeResult:
        """
        WIDTH (Parallel 'agg' mode):
          - k base rollouts
          - 2k candidate proposals (inv1..invk, dom1..domk) & 2k candidate rollouts
          - k independent compositions (agg1..aggk) & k final rollouts
          Total: R = 4k rollouts, P = 3k sessions.
        """
        k = max(1, int(k))
        resolved_domain = self.resolve_domain(task_id, domain)
        base_tree = copy.deepcopy(base_tree) if base_tree else self.build_base_harness(resolved_domain)
        work_dir = Path(work_dir) if work_dir else (self.runs_root / "work" / slug(task_id) / "agg")
        write_tree(self.surface, base_tree, work_dir / "harnesses" / "base")

        domain_lessons = library.load_domain_lessons() if library else []
        ledger = Ledger(mode="agg", task_id=task_id, k=k)
        result = ModeResult(mode="agg", task_id=task_id, domain=resolved_domain, k=k, ledger=ledger)

        # 1. Execute k shared base rollouts
        base_views: List[RunView] = []
        for i in range(1, k + 1):
            lbl = f"base{i}"
            view = self._probe_harness(lbl, task_id, resolved_domain, base_tree)
            ledger.rollout(lbl)
            result.rollouts[lbl] = view
            base_views.append(view)

        # 2. Propose 2k candidates (INV and DOM) in parallel
        specs = [(f"{d.lower()}{i}", d, i) for i in range(1, k + 1) for d in ("INV", "DOM")]
        with ThreadPoolExecutor(max_workers=min(len(specs), PHASE_WIDTH)) as pool_x:
            stages = list(
                pool_x.map(
                    lambda s: self._run_stage(
                        label=s[0],
                        dim=s[1],
                        index=s[2],
                        round_t=None,
                        fallback=base_tree,
                        task_id=task_id,
                        domain=resolved_domain,
                        rollouts=base_views,
                        domain_lessons=domain_lessons,
                    ),
                    specs,
                )
            )

        for st in stages:
            ledger.session(st.label, usd=st.usd, cached=st.cached, attempts=st.attempts)
            result.stages.append(st)
            result.trees[st.label] = st.tree
            write_tree(self.surface, st.tree, work_dir / "harnesses" / st.label)

        # 3. Probe all 2k candidate harnesses
        for st in stages:
            view = self._probe_harness(st.label, task_id, resolved_domain, st.tree)
            ledger.rollout(st.label)
            result.rollouts[st.label] = view

        # 4. Compose k aggregated harnesses (agg1..aggk) from behavioral contrast pool
        pool_ev: List[Tuple[str, Tree, RunView]] = [
            (st.label, st.tree, result.rollouts[st.label]) for st in stages
        ]
        agg_specs = [(f"agg{i}", i) for i in range(1, k + 1)]
        with ThreadPoolExecutor(max_workers=min(len(agg_specs), PHASE_WIDTH)) as pool_x:
            aggs = list(
                pool_x.map(
                    lambda a: self._run_stage(
                        label=a[0],
                        dim="AGG",
                        index=a[1],
                        round_t=None,
                        fallback=base_tree,
                        task_id=task_id,
                        domain=resolved_domain,
                        rollouts=base_views,
                        domain_lessons=domain_lessons,
                        pool=pool_ev,
                    ),
                    agg_specs,
                )
            )

        for st in aggs:
            ledger.session(st.label, usd=st.usd, cached=st.cached, attempts=st.attempts)
            result.stages.append(st)
            result.trees[st.label] = st.tree
            result.finals.append(st.label)
            write_tree(self.surface, st.tree, work_dir / "harnesses" / st.label)

        # 5. Execute k final rollouts
        for st in aggs:
            view = self._probe_harness(st.label, task_id, resolved_domain, st.tree)
            ledger.rollout(st.label)
            result.rollouts[st.label] = view

        result.similarity = diversity({st.label: st.tree for st in aggs})
        ledger.assert_identity()

        # Select best final harness & record experience
        best_final = max(result.finals, key=lambda lbl: result.rollouts[lbl].behavioral_score)
        result.adopted_label = best_final
        result.adopted_tree = result.trees[best_final]
        best_view = result.rollouts[best_final]
        base_score = base_views[0].behavioral_score if base_views else 0.0
        gain = best_view.behavioral_score - base_score

        result.experience = {
            "cue": f"When auditing {task_id} in domain `{resolved_domain}` for boundary desynchronization",
            "lesson": (
                f"Combine invariant byte-length ruler checks with {resolved_domain} specialist skills "
                f"({', '.join(best_view.active_skills[:3])}) to surface parser divergences without false positives."
            ),
            "evidence": (
                f"Composed harness `{best_final}` improved behavioral score by +{gain:.1f} over base "
                f"(Divergences={best_view.parser_divergences}, SimVulns={best_view.simulated_vulns})."
            ),
        }

        if library is not None:
            library.record(
                task_id,
                result.adopted_tree,
                result.experience,
                picked_label=best_final,
                contrast_score=best_view.behavioral_score,
            )

        return result

    def run_sequential(
        self,
        task_id: str,
        k: int = 1,
        *,
        domain: str = "auto",
        base_tree: Optional[Tree] = None,
        work_dir: Optional[Path] = None,
        library: Optional[Library] = None,
    ) -> ModeResult:
        """
        DEPTH (Sequential 'seq' mode):
          - k shared base rollouts
          - Across t = 1..k iterative rounds:
              * Propose inv{t} and dom{t} from current refined harness
              * Probe inv{t} and dom{t}
              * Compose c{t} and probe c{t}, carrying c{t} forward to round t+1
          Total: R = 4k rollouts, P = 3k sessions.
        """
        k = max(1, int(k))
        resolved_domain = self.resolve_domain(task_id, domain)
        base_tree = copy.deepcopy(base_tree) if base_tree else self.build_base_harness(resolved_domain)
        work_dir = Path(work_dir) if work_dir else (self.runs_root / "work" / slug(task_id) / "seq")

        domain_lessons = library.load_domain_lessons() if library else []
        ledger = Ledger(mode="seq", task_id=task_id, k=k)
        result = ModeResult(mode="seq", task_id=task_id, domain=resolved_domain, k=k, ledger=ledger)

        # 1. Execute k shared base rollouts
        base_views: List[RunView] = []
        for i in range(1, k + 1):
            lbl = f"base{i}"
            view = self._probe_harness(lbl, task_id, resolved_domain, base_tree)
            ledger.rollout(lbl)
            result.rollouts[lbl] = view
            base_views.append(view)

        current_harness = copy.deepcopy(base_tree)
        history: List[Tuple[str, Tree, RunView]] = []

        # 2. Run k sequential Propose -> Probe -> Compose rounds
        for t in range(1, k + 1):
            current_label = f"c{t - 1}" if t > 1 else "base"
            write_tree(self.surface, current_harness, work_dir / "harnesses" / current_label)

            specs = [(f"inv{t}", "INV"), (f"dom{t}", "DOM")]
            with ThreadPoolExecutor(max_workers=2) as pool_x:
                stages = list(
                    pool_x.map(
                        lambda s: self._run_stage(
                            label=s[0],
                            dim=s[1],
                            index=t,
                            round_t=t,
                            fallback=current_harness,
                            task_id=task_id,
                            domain=resolved_domain,
                            rollouts=base_views,
                            domain_lessons=domain_lessons,
                            pool=list(history),
                        ),
                        specs,
                    )
                )

            for st in stages:
                ledger.session(st.label, usd=st.usd, cached=st.cached, attempts=st.attempts)
                result.stages.append(st)
                result.trees[st.label] = st.tree
                write_tree(self.surface, st.tree, work_dir / "harnesses" / st.label)

            for st in stages:
                view = self._probe_harness(st.label, task_id, resolved_domain, st.tree)
                ledger.rollout(st.label)
                result.rollouts[st.label] = view

            round_pool = list(history) + [
                (st.label, st.tree, result.rollouts[st.label]) for st in stages
            ]
            ck = f"c{t}"
            comp = self._run_stage(
                label=ck,
                dim="COMPOSE",
                index=t,
                round_t=t,
                fallback=current_harness,
                task_id=task_id,
                domain=resolved_domain,
                rollouts=base_views,
                domain_lessons=domain_lessons,
                pool=round_pool,
            )
            ledger.session(comp.label, usd=comp.usd, cached=comp.cached, attempts=comp.attempts)
            result.stages.append(comp)
            result.trees[ck] = comp.tree
            write_tree(self.surface, comp.tree, work_dir / "harnesses" / ck)

            ck_view = self._probe_harness(ck, task_id, resolved_domain, comp.tree)
            ledger.rollout(ck)
            result.rollouts[ck] = ck_view

            history = round_pool + [(ck, comp.tree, ck_view)]
            current_harness = comp.tree

        result.finals = [f"c{idx}" for idx in range(1, k + 1)]
        result.similarity = diversity({lbl: result.trees[lbl] for lbl in result.finals})
        ledger.assert_identity()

        best_final = max(result.finals, key=lambda lbl: result.rollouts[lbl].behavioral_score)
        result.adopted_label = best_final
        result.adopted_tree = result.trees[best_final]
        best_view = result.rollouts[best_final]
        base_score = base_views[0].behavioral_score if base_views else 0.0
        gain = best_view.behavioral_score - base_score

        result.experience = {
            "cue": f"When sequentially refining harnesses across {k} depth rounds on {task_id} (`{resolved_domain}`)",
            "lesson": (
                f"Carry composed c1..c8 trees across sequential rounds to accumulate specialist skills "
                f"({', '.join(best_view.active_skills[:3])}) and eliminate framing false positives."
            ),
            "evidence": (
                f"Sequential composition `{best_final}` achieved score {best_view.behavioral_score:.1f} "
                f"(+{gain:.1f} over base) with R={ledger.rollouts_count} rollouts and P={ledger.sessions_count} stages."
            ),
        }

        if library is not None:
            library.record(
                task_id,
                result.adopted_tree,
                result.experience,
                picked_label=best_final,
                contrast_score=best_view.behavioral_score,
            )

        return result

    def run_mode(
        self,
        mode: str,
        task_id: str,
        k: int = 1,
        *,
        domain: str = "auto",
        run_tag: str = "default",
    ) -> ModeResult:
        """
        Dispatch on mode ('parallel'/'agg' or 'sequential'/'seq') and update the
        persistent per-domain experience library (Level 2 Harnessing-Level Recursion).
        """
        norm_mode = "agg" if mode.lower() in ("parallel", "agg") else "seq"
        if mode.lower() not in ("parallel", "agg", "sequential", "seq"):
            raise ValueError(
                f"unknown mode {mode!r}; Harness² supports 'parallel' ('agg') and 'sequential' ('seq')"
            )

        resolved_domain = self.resolve_domain(task_id, domain)
        lib_root = self.runs_root / run_tag / norm_mode
        lib = Library(root=lib_root, domain=resolved_domain, surface=self.surface)

        # If domain library already has adopted trees from prior tasks, inherit the latest as base!
        base_tree = self.build_base_harness(resolved_domain)
        prior_entries = lib.entries()
        if prior_entries:
            inherited = lib.tree_of(prior_entries[-1])
            if inherited:
                base_tree = merge_tree_proposal(self.surface, base_tree, inherited)

        work_dir = self.runs_root / run_tag / norm_mode / domain_dir(resolved_domain) / "work" / slug(task_id)
        if norm_mode == "agg":
            return self.run_parallel(
                task_id,
                k=k,
                domain=resolved_domain,
                base_tree=base_tree,
                work_dir=work_dir,
                library=lib,
            )
        return self.run_sequential(
            task_id,
            k=k,
            domain=resolved_domain,
            base_tree=base_tree,
            work_dir=work_dir,
            library=lib,
        )

    def run_suite(
        self,
        rfc_list: Sequence[str],
        k: int = 1,
        mode: str = "parallel",
        domain: str = "auto",
        db_instance: Any = None,
    ) -> List[ModeResult]:
        """Executes Harness² across one or more RFCs in parallel, sequential, or both modes."""
        modes_to_run = ["parallel", "sequential"] if mode.lower() == "both" else [mode]
        results: List[ModeResult] = []
        for raw_rfc in rfc_list:
            rfc_clean = str(raw_rfc).strip().replace("RFC-", "").replace("RFC", "")
            task_id = f"RFC{rfc_clean}"
            for m in modes_to_run:
                res = self.run_mode(mode=m, task_id=task_id, k=k, domain=domain)
                if db_instance is not None and hasattr(db_instance, "save_harness2_run"):
                    db_instance.save_harness2_run(res.to_dict())
                results.append(res)
        return results

    def format_cli_report(
        self,
        summary: Optional[Sequence[ModeResult]] = None,
        db_instance: Any = None,
    ) -> str:
        """Formats a CLI report for a suite of ModeResults or historical database runs."""
        lines = [
            "=" * 78,
            "  GOOGLE RESEARCH HARNESS²: RECURSIVE AGENT HARNESSING FOR AN OPEN WORLD",
            "  Citation : Xu et al., Google Research (arXiv:2610.14224, 2026)",
            "  Repo     : https://github.com/google-research/harness2",
            "=" * 78,
        ]
        if summary:
            for res in summary:
                l_dict = res.ledger.to_dict() if res.ledger else {}
                lines.append(
                    f"  [+] Task: {res.task_id} | Mode: {res.mode} | Domain: {res.domain} | "
                    f"Adopted: `{res.adopted_label}` | R={l_dict.get('actual_rollouts')}/{l_dict.get('expected_rollouts')} "
                    f"P={l_dict.get('actual_sessions')}/{l_dict.get('expected_sessions')}"
                )
                lines.append(f"      Lesson: {res.experience.get('lesson', '')}")
        elif db_instance is not None and hasattr(db_instance, "get_harness2_runs"):
            runs = db_instance.get_harness2_runs(limit=25)
            lines.append(f"  [*] Historical Harness² Runs ({len(runs)} recorded):")
            for r in runs:
                lines.append(
                    f"  - [{r['run_id']}] {r['task_id']} ({r['domain']}) mode={r['mode']} k={r['k_budget']} "
                    f"R/P={r['rollouts_count']}/{r['sessions_count']} adopted={r['adopted_label']} score={r['contrast_score']:.1f}"
                )
        lines.append("=" * 78)
        return "\n".join(lines)
