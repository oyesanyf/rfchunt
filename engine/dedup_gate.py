"""
RFCHunt Pre-Submission Deduplication, Freshness & Surface Congestion Gate (`engine/dedup_gate.py`)
==================================================================================================

Minimizes avoidable HackerOne duplicate collisions (e.g., Circle Arc `#4234132` colliding with
`#4035475` in congested `started_round.rs`, or Anthropic `#4235853`/`#4235881`/`#4235898`) across
three orthogonal engineering layers — strictly lightweight (pure Python stdlib, 8 GB RAM safe)
and zero guardrail violations (`shell=False`, Windows `CREATE_NO_WINDOW`, HTTPS host pinning):

  1. Automated Upstream & Advisory Gate:
     - Local `git log` / `-L` line-range inspection (100% offline): computes exact `code_age_hours`
       and flags recent commits mentioning security/fix terms (`guard`, `validation`, `byzantine`,
       `hash`, `fix`, `cve`, `ghsa`, `sanitize`, `bypass`, `deadlock`, `undecided`).
     - GitHub REST API Pre-Check (HTTPS pinned to `https://api.github.com`; automatically skipped
       when `RFCHUNT_OFFLINE=1`, `dry_run=True`, or `allow_network=False`): checks recent commits
       touching `file_path`, open/merged PRs, open/closed issues, and GitHub Security Advisories.
     - Local Cross-Report Structural Vector Index (stored in SQLite `report_signatures` table):
       deterministic TF-IDF cosine + structural 2-gram shingle Jaccard similarity over
       `(file_path, function_name, cwe, sink_type, title, evidence)` so RFCHunt never drafts two
       overlapping variants of the same root cause across your own submissions or known duplicates.
  2. Commit Velocity & Fresh-Code Diff-Scoped Slicing:
     - `slice_changed_hunks(repo_path, since_hours=72)` parses unified diff hunks (`@@ -a,b +c,d @@`)
       to isolate newly introduced/modified files, line ranges, and symbols landed within 24–72h.
     - Awards a calibrated Fresh-Code Bonus (`<= 24h` / `<= 72h`) and penalizes stale `> 180d` code.
  3. Surface Congestion & Deep Cross-Boundary Scoring:
     - Penalizes high-traffic first-read surfaces (top-level consensus round handlers like
       `started_round.rs`, block-hash validation, standard OAuth/login callbacks, top-level entry
       files in saturated repos).
     - Boosts deep cross-boundary rare surfaces (AWS Nitro Enclave KMS attestation, Post-Quantum
       precompile metering/decode, multi-hop cross-crate boundaries, WAL/GossipSub recovery).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request

GITHUB_API_BASE = "https://api.github.com"

CROSS_REPORT_SIMILARITY_HOLD_THRESHOLD = 0.72
CROSS_REPORT_SIMILARITY_WARN_THRESHOLD = 0.50

_STOP_WORDS: Set[str] = {
    "the", "and", "for", "with", "from", "into", "that", "this", "via", "when", "without",
    "allows", "allow", "enables", "enable", "missing", "issue", "bug", "flaw", "defect",
    "vulnerability", "security", "report", "finding", "code", "file", "line", "function",
    "can", "could", "should", "must", "not", "are", "was", "were", "has", "have", "had",
}

_SECURITY_COMMIT_KEYWORDS_RX = re.compile(
    r"\b(?:fix(?:ed|es|ing)?|patch(?:ed)?|guard|validat(?:e|ion|ing)|byzantine|block[- _]?hash|"
    r"undecided|deadlock|cve-\d{4}-\d+|ghsa-[a-z0-9-]+|securit(?:y|ies)|sanitiz(?:e|ation)|"
    r"bypass|overflow|underflow|attestation|hmac|csrf|ssrf|traversal|sandbox|harden(?:ing)?)\b",
    re.IGNORECASE,
)

# High-congestion surfaces: first files every manual auditor & automated scanner inspects
_HIGH_CONGESTION_SURFACES: Tuple[Tuple[str, float, re.Pattern[str]], ...] = (
    (
        "top_level_consensus_round_handler",
        0.34,
        re.compile(
            r"(?:started_round\.rs|round_state|propose_round|block_hash|verify_proposal|"
            r"may_be_stored_as_undecided|consensus/src/(?:state|round|driver))",
            re.IGNORECASE,
        ),
    ),
    (
        "standard_oauth_login_callback",
        0.24,
        re.compile(
            r"(?:oauth.?callback|login\.(?:ts|js|py|go|rb)|authorize\.(?:ts|js|py)|"
            r"auth/callback|session_controller)",
            re.IGNORECASE,
        ),
    ),
    (
        "top_level_entrypoint_proxy",
        0.18,
        re.compile(
            r"(?:^|/)(?:main|index|server|app|proxy|router|handler)\.(?:rs|ts|js|py|go)$",
            re.IGNORECASE,
        ),
    ),
    (
        "generic_secondary_consensus_core",
        0.22,
        re.compile(
            r"(?:malachite.{0,20}consensus|secondary\s+consensus|consensus\s+core)",
            re.IGNORECASE,
        ),
    ),
)

# Deep cross-boundary / low-congestion rare surfaces where generic scanners & first-pass audits rarely reach
_DEEP_BOUNDARY_SURFACES: Tuple[Tuple[str, float, re.Pattern[str]], ...] = (
    (
        "hardware_tee_enclave_kms_attestation",
        -0.24,
        re.compile(
            r"\b(?:nitro|enclave|kms.{0,20}attestation|attestation\s+binding|remote[- _]?signer|"
            r"pcr\d*|sgx|sev[- ]snp|tpm\s+quote|hsm)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "post_quantum_or_custom_precompile",
        -0.20,
        re.compile(
            r"\b(?:post[- ]quantum|pqc|ml[- ]kem|ml[- ]dsa|slh[- ]dsa|kyber|dilithium|"
            r"precompile.{0,25}(?:decode|meter|gas)|eip[- ]\d{4}|zk[- ]?(?:proof|circuit|verifier))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "wasm_guest_host_memory_or_limiter",
        -0.16,
        re.compile(
            r"\b(?:poll_oneoff|deterministic[- ]wasi|ptr::read|maybeuninit|resourcelimiter|"
            r"function[- ]runner|wasmtime|guest[- ]writable)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "multi_component_wal_p2p_gossipsub_sync",
        -0.14,
        re.compile(
            r"\b(?:wal\s+replay|write[- ]ahead\s+log|gossipsub|peer[- ]scoring|p2p\s+eclipse|"
            r"peer\s+table|cross[- ]crate|multi[- ]hop|state[- ]sync|android.{0,20}@javascriptinterface)\b",
            re.IGNORECASE,
        ),
    ),
)

_SINK_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("consensus_state_guard", re.compile(r"undecided|started_round|block.?hash|byzantine|validator|consensus", re.IGNORECASE)),
    ("enclave_kms_attestation", re.compile(r"nitro|enclave|kms|attestation|remote.?signer", re.IGNORECASE)),
    ("pqc_precompile_decode", re.compile(r"precompile|post.?quantum|pqc|ml-kem|ml-dsa", re.IGNORECASE)),
    ("wasm_host_memory", re.compile(r"wasi|wasm|ptr::read|poll_oneoff|resourcelimiter|heap", re.IGNORECASE)),
    ("jwt_oauth_authz", re.compile(r"jwt|oidc|oauth|webauthn|hmac|iss|dest|storefront|admin|rbac", re.IGNORECASE)),
    ("filesystem_sandbox_path", re.compile(r"ntfs|junction|ads|seatbelt|seccomp|traversal|symlink|zshenv", re.IGNORECASE)),
    ("framing_proxy_parser", re.compile(r"splitlines|smuggling|proxy|double.?decode|clienthello|sni|trace", re.IGNORECASE)),
    ("subprocess_code_exec", re.compile(r"subprocess|command.?injection|eval|exec|rce|deserializ", re.IGNORECASE)),
)

_FUNC_NAME_RX = re.compile(
    r"\b([a-zA-Z_][a-zA-Z0-9_]{2,48})\s*\(\s*\)|"
    r"\b(?:fn|def|function|func)\s+([a-zA-Z_][a-zA-Z0-9_]{2,48})\b",
)

_DIFF_FILE_RX = re.compile(r"^\+\+\+\s+b/(.+)$")
_DIFF_HUNK_RX = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@(?:\s*(.*))?$")


@dataclass
class StructuralSignature:
    program_handle: str
    file_path: str
    file_basename: str
    function_name: str
    cwe: str
    sink_type: str
    tokens: List[str]
    shingles: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FreshCodeSlice:
    file_path: str
    changed_line_ranges: List[Tuple[int, int]] = field(default_factory=list)
    enclosing_symbols: List[str] = field(default_factory=list)
    newest_commit_age_hours: float = 0.0
    commit_sha: str = ""
    commit_subject: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LocalGitHistoryResult:
    git_available: bool
    code_age_hours: Optional[float] = None
    last_commit_sha: str = ""
    last_commit_subject: str = ""
    recent_security_commits: List[str] = field(default_factory=list)
    likely_patched_in_git: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UpstreamGateResult:
    verdict: str  # CLEAN | LIKELY_PATCHED_OR_IN_REVIEW | OFFLINE_SKIPPED
    matched_commits: List[str] = field(default_factory=list)
    matched_prs: List[str] = field(default_factory=list)
    matched_issues: List[str] = field(default_factory=list)
    matched_advisories: List[str] = field(default_factory=list)
    dup_risk_delta: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SurfaceCongestionResult:
    congestion_score: float  # 0.0 (deep/rare) .. 1.0 (maximally congested first-read file)
    congestion_tier: str  # LOW_CONGESTION_DEEP_BOUNDARY | MODERATE | HIGH_CONGESTION_CROWDED
    freshness_tier: str  # FRESH_24H | FRESH_72H | RECENT_30D | STALE_CORE | UNKNOWN
    dup_risk_adjustment: float
    matched_signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DedupGateResult:
    gate_verdict: str  # PASS_NOVEL_FRESH | PASS_LOW_CONGESTION | WARN_HIGH_CONGESTION | HOLD_CROSS_REPORT_DUPLICATE | HOLD_LIKELY_PATCHED_UPSTREAM
    adjusted_p_duplicate: float
    code_age_hours: Optional[float]
    congestion_score: float
    congestion_tier: str
    freshness_tier: str
    cross_report_similarity: float
    closest_prior_report: str
    upstream_hits: List[str] = field(default_factory=list)
    rationale: str = ""
    signature: Dict[str, Any] = field(default_factory=dict)
    local_git: Dict[str, Any] = field(default_factory=dict)
    upstream_github: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _tokenize_canonical(text: str) -> List[str]:
    raw_tokens = re.findall(r"[a-z0-9_]{3,}", str(text or "").lower())
    out: List[str] = []
    for tok in raw_tokens:
        if tok in _STOP_WORDS or tok.isdigit():
            continue
        out.append(tok)
    return out


def _infer_sink_type(blob: str) -> str:
    for name, rx in _SINK_PATTERNS:
        if rx.search(blob):
            return name
    return "generic_security_sink"


def _infer_function_name(finding: Dict[str, Any], blob: str) -> str:
    explicit = str(finding.get("function_name") or finding.get("symbol") or "").strip()
    if explicit:
        return explicit.lower()
    m = _FUNC_NAME_RX.search(blob)
    if m:
        return (m.group(1) or m.group(2) or "").strip().lower()
    return ""


def build_structural_signature(finding: Dict[str, Any], *, program_handle: str = "") -> StructuralSignature:
    """
    Extracts a deterministic canonical structural AST/token signature for local
    cross-report deduplication (zero heavy ML dependencies).
    """
    fp = str(finding.get("file_path") or finding.get("file") or finding.get("asset_identifier") or "").replace("\\", "/").strip()
    basename = Path(fp.split("(")[0].split("@")[0].strip()).name.lower() if fp else ""
    # Also extract parenthesized filename e.g. Arc/Malachite(started_round.rs) -> started_round.rs
    paren_m = re.search(r"\(([A-Za-z0-9_.-]+\.[A-Za-z0-9]+)\)", fp)
    if paren_m:
        basename = paren_m.group(1).lower()
    cwe = str(finding.get("cwe") or finding.get("cwe_id") or finding.get("weakness_cwe") or "").strip().upper()
    blob = " ".join(
        [
            fp,
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("evidence") or ""),
            cwe,
        ]
    )
    fn_name = _infer_function_name(finding, blob)
    sink = _infer_sink_type(blob)
    tokens = _tokenize_canonical(blob)
    if basename:
        tokens.extend([basename, f"file:{basename}"])
    if fn_name:
        tokens.extend([fn_name, f"fn:{fn_name}"])
    if cwe:
        tokens.append(f"cwe:{cwe.lower()}")
    tokens.append(f"sink:{sink}")

    # Deterministic 2-gram shingles preserving structural order
    unique_ordered = list(dict.fromkeys(tokens))
    shingles = [f"{unique_ordered[i]}::{unique_ordered[i + 1]}" for i in range(max(0, len(unique_ordered) - 1))]
    return StructuralSignature(
        program_handle=str(program_handle or finding.get("program_handle") or "").strip().lower(),
        file_path=fp.lower(),
        file_basename=basename,
        function_name=fn_name,
        cwe=cwe,
        sink_type=sink,
        tokens=tokens[:120],
        shingles=shingles[:120],
    )


def _cosine_counter(a: Counter[str], b: Counter[str]) -> float:
    if not a or not b:
        return 0.0
    common = set(a.keys()) & set(b.keys())
    if not common:
        return 0.0
    dot = sum(a[k] * b[k] for k in common)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / (na * nb)


def score_cross_report_similarity(
    candidate_sig: StructuralSignature,
    prior_signatures: Sequence[Dict[str, Any]],
    *,
    exclude_draft_id: str = "",
) -> Tuple[float, str]:
    """
    Computes maximum structural TF-IDF-weighted cosine + Jaccard similarity against
    all stored prior reports, closed duplicates, and active drafts.
    Returns `(max_similarity_0_to_1, closest_prior_label)`.
    """
    if not prior_signatures:
        return 0.0, ""

    # Build document frequencies across corpus + candidate for genuine IDF weighting
    doc_freq: Counter[str] = Counter(set(candidate_sig.tokens))
    parsed_priors: List[Tuple[Dict[str, Any], List[str], Set[str]]] = []
    for row in prior_signatures:
        if exclude_draft_id and str(row.get("draft_id") or "") == exclude_draft_id:
            continue
        p_toks = row.get("tokens")
        if isinstance(p_toks, str):
            try:
                p_toks = json.loads(p_toks)
            except Exception:
                p_toks = _tokenize_canonical(p_toks)
        p_toks_list = [str(t) for t in (p_toks or []) if str(t).strip()]
        p_sh = row.get("shingles")
        if isinstance(p_sh, str):
            try:
                p_sh = json.loads(p_sh)
            except Exception:
                p_sh = []
        p_sh_set = {str(s) for s in (p_sh or []) if str(s).strip()}
        doc_freq.update(set(p_toks_list))
        parsed_priors.append((row, p_toks_list, p_sh_set))

    if not parsed_priors:
        return 0.0, ""

    n_docs = len(parsed_priors) + 1
    cand_counts = Counter(candidate_sig.tokens)
    cand_tfidf = Counter({k: v * (1.0 + math.log((n_docs + 1.0) / (doc_freq[k] + 1.0))) for k, v in cand_counts.items()})
    cand_shingles = set(candidate_sig.shingles)

    best_sim = 0.0
    best_label = ""
    for row, p_toks_list, p_sh_set in parsed_priors:
        # Only compare strongly within same program (or cross-program if same file & function)
        row_prog = str(row.get("program_handle") or "").strip().lower()
        same_program = bool(not candidate_sig.program_handle or not row_prog or row_prog == candidate_sig.program_handle)
        if not same_program:
            continue

        p_counts = Counter(p_toks_list)
        p_tfidf = Counter({k: v * (1.0 + math.log((n_docs + 1.0) / (doc_freq[k] + 1.0))) for k, v in p_counts.items()})
        cos = _cosine_counter(cand_tfidf, p_tfidf)
        jacc = (
            len(cand_shingles & p_sh_set) / float(len(cand_shingles | p_sh_set))
            if (cand_shingles and p_sh_set)
            else 0.0
        )
        sim = 0.72 * cos + 0.28 * jacc

        # Exact structural root-cause collision bonus: same file_basename + same function_name or same file + sink + CWE
        row_base = str(row.get("file_basename") or "").strip().lower()
        row_fn = str(row.get("function_name") or "").strip().lower()
        row_cwe = str(row.get("cwe") or "").strip().upper()
        row_sink = str(row.get("sink_type") or "").strip().lower()

        if candidate_sig.file_basename and row_base and candidate_sig.file_basename == row_base:
            if candidate_sig.function_name and row_fn and candidate_sig.function_name == row_fn:
                sim = max(sim, 0.92)
            elif candidate_sig.sink_type == row_sink and candidate_sig.cwe and candidate_sig.cwe == row_cwe:
                sim = max(sim, 0.84)
            elif candidate_sig.sink_type == row_sink and cos >= 0.35:
                sim = max(sim, 0.78)

        if sim > best_sim:
            best_sim = min(1.0, round(sim, 3))
            rem = str(row.get("remote_report_id") or "").strip()
            st = str(row.get("verdict_outcome") or row.get("state") or "").strip()
            did = str(row.get("draft_id") or "")
            best_label = f"{did}{f' ({rem})' if rem else ''}{f' [{st}]' if st else ''}"

    return best_sim, best_label


def inspect_local_git_history(
    repo_path: Optional[str],
    file_path: str,
    *,
    line_number: int = 0,
    lookback_days: int = 30,
) -> LocalGitHistoryResult:
    """
    100% offline local `git log` inspection (`shell=False`, Windows `CREATE_NO_WINDOW`).
    Computes exact `code_age_hours` and detects recent security/fix commits touching the file.
    """
    if not repo_path:
        return LocalGitHistoryResult(git_available=False)
    root = Path(repo_path).resolve(strict=False)
    if not (root / ".git").exists():
        return LocalGitHistoryResult(git_available=False)

    rel_target = str(file_path or "").replace("\\", "/").strip()
    try:
        fp_obj = Path(file_path)
        if fp_obj.is_absolute():
            rel_target = str(fp_obj.resolve(strict=False).relative_to(root)).replace("\\", "/")
    except Exception:
        pass
    if not rel_target or rel_target.startswith("-") or ".." in rel_target.split("/"):
        return LocalGitHistoryResult(git_available=True)

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    cmd = ["git", "-C", str(root), "log", "-n", "10", "--format=%H|%ct|%s", "--", rel_target]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            shell=False,
            creationflags=creationflags,
        )
    except Exception:
        return LocalGitHistoryResult(git_available=False)

    if proc.returncode != 0 or not proc.stdout.strip():
        return LocalGitHistoryResult(git_available=True)

    now_ts = time.time()
    recent_cutoff = now_ts - (max(1, int(lookback_days)) * 86400.0)
    lines = [ln.strip() for ln in proc.stdout.splitlines() if "|" in ln]
    if not lines:
        return LocalGitHistoryResult(git_available=True)

    first_parts = lines[0].split("|", 2)
    last_sha = first_parts[0][:12]
    try:
        last_ts = float(first_parts[1])
        age_hours = max(0.0, round((now_ts - last_ts) / 3600.0, 2))
    except Exception:
        age_hours = None
    last_subj = first_parts[2].strip() if len(first_parts) > 2 else ""

    sec_commits: List[str] = []
    for ln in lines:
        parts = ln.split("|", 2)
        if len(parts) < 3:
            continue
        sha_s, ts_s, subj = parts[0][:10], parts[1], parts[2].strip()
        try:
            c_ts = float(ts_s)
        except Exception:
            continue
        if c_ts >= recent_cutoff and _SECURITY_COMMIT_KEYWORDS_RX.search(subj):
            sec_commits.append(f"{sha_s}: {subj[:90]}")

    return LocalGitHistoryResult(
        git_available=True,
        code_age_hours=age_hours,
        last_commit_sha=last_sha,
        last_commit_subject=last_subj,
        recent_security_commits=sec_commits[:5],
        likely_patched_in_git=len(sec_commits) > 0,
    )


def slice_changed_hunks(repo_path: str, *, since_hours: int = 72, max_files: int = 40) -> List[FreshCodeSlice]:
    """
    Diff-scoped fresh-code slicer: parses unified git diffs landed within the last `since_hours`
    (default 72h) to isolate newly introduced/modified files, exact line ranges, and enclosing symbols.
    Runs 100% offline with `shell=False` + Windows `CREATE_NO_WINDOW`.
    """
    root = Path(repo_path).resolve(strict=False)
    if not (root / ".git").exists():
        return []

    hours = max(1, int(since_hours or 72))
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    cmd = [
        "git",
        "-C",
        str(root),
        "log",
        f"--since={hours} hours ago",
        "-p",
        "-U0",
        "--no-color",
        "--format=RFCHUNT_COMMIT|%H|%ct|%s",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            shell=False,
            creationflags=creationflags,
        )
    except Exception:
        return []

    if proc.returncode != 0 or not proc.stdout.strip():
        return []

    now_ts = time.time()
    by_file: Dict[str, FreshCodeSlice] = {}
    cur_sha = ""
    cur_age = 0.0
    cur_subj = ""
    cur_file = ""

    for raw_line in proc.stdout.splitlines():
        if raw_line.startswith("RFCHUNT_COMMIT|"):
            parts = raw_line.split("|", 3)
            cur_sha = parts[1][:12] if len(parts) > 1 else ""
            try:
                cur_age = max(0.0, round((now_ts - float(parts[2])) / 3600.0, 2))
            except Exception:
                cur_age = 0.0
            cur_subj = parts[3].strip() if len(parts) > 3 else ""
            cur_file = ""
            continue
        m_file = _DIFF_FILE_RX.match(raw_line)
        if m_file:
            cur_file = m_file.group(1).strip()
            if cur_file not in by_file and len(by_file) < max_files:
                by_file[cur_file] = FreshCodeSlice(
                    file_path=cur_file,
                    newest_commit_age_hours=cur_age,
                    commit_sha=cur_sha,
                    commit_subject=cur_subj[:100],
                )
            elif cur_file in by_file and cur_age < by_file[cur_file].newest_commit_age_hours:
                by_file[cur_file].newest_commit_age_hours = cur_age
                by_file[cur_file].commit_sha = cur_sha
                by_file[cur_file].commit_subject = cur_subj[:100]
            continue
        if cur_file and cur_file in by_file:
            m_hunk = _DIFF_HUNK_RX.match(raw_line)
            if m_hunk:
                start_ln = int(m_hunk.group(1))
                count_ln = int(m_hunk.group(2)) if m_hunk.group(2) is not None else 1
                end_ln = start_ln + max(0, count_ln - 1)
                sl = by_file[cur_file]
                if count_ln > 0:
                    sl.changed_line_ranges.append((start_ln, end_ln))
                ctx = (m_hunk.group(3) or "").strip()
                if ctx and ctx[:80] not in sl.enclosing_symbols:
                    sl.enclosing_symbols.append(ctx[:80])

    slices = list(by_file.values())
    slices.sort(key=lambda s: (s.newest_commit_age_hours, s.file_path))
    return slices


def query_github_upstream_dedup(
    finding: Dict[str, Any],
    *,
    repo_url: str = "",
    allow_network: bool = False,
    dry_run: bool = False,
    timeout_sec: float = 7.0,
) -> UpstreamGateResult:
    """
    Read-only GitHub REST API pre-check pinned strictly to `https://api.github.com`:
      - Recent commits touching `file_path`,
      - Open/merged PRs matching security/fix terms or filename,
      - Open/closed issues matching filename/function/CWE,
      - Repository security advisories (GHSAs).
    Skips cleanly when `RFCHUNT_OFFLINE=1`, `dry_run=True`, or `allow_network=False`.
    """
    offline = str(os.environ.get("RFCHUNT_OFFLINE") or "").strip().lower() in ("1", "true", "yes")
    if dry_run or offline or not allow_network or not repo_url:
        return UpstreamGateResult(verdict="OFFLINE_SKIPPED")

    parsed = urllib.parse.urlparse(str(repo_url).strip())
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != "github.com":
        return UpstreamGateResult(verdict="OFFLINE_SKIPPED")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return UpstreamGateResult(verdict="OFFLINE_SKIPPED")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    if not re.match(r"^[A-Za-z0-9_.-]+$", owner) or not re.match(r"^[A-Za-z0-9_.-]+$", repo):
        return UpstreamGateResult(verdict="OFFLINE_SKIPPED")

    headers = {"Accept": "application/vnd.github+json", "User-Agent": "RFCHunt-DedupGate/2.0"}
    gh_tok = (os.environ.get("GITHUB_TOKEN") or "").strip()
    if gh_tok:
        headers["Authorization"] = f"Bearer {gh_tok}"

    def _gh_get(path_and_q: str) -> Any:
        url = f"{GITHUB_API_BASE}/{path_and_q.lstrip('/')}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=max(2.0, float(timeout_sec))) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    sig = build_structural_signature(finding)
    file_rel = str(finding.get("file_path") or finding.get("file") or "").replace("\\", "/").lstrip("/")
    matched_commits: List[str] = []
    matched_prs: List[str] = []
    matched_issues: List[str] = []
    matched_advisories: List[str] = []

    # 1. Recent commits touching exact file
    if file_rel and "/" in file_rel and not file_rel.startswith(("c:/", "d:/")):
        try:
            commits = _gh_get(f"repos/{owner}/{repo}/commits?path={urllib.parse.quote(file_rel)}&per_page=5")
            if isinstance(commits, list):
                for c in commits[:5]:
                    msg = str(((c.get("commit") or {}).get("message")) or "").splitlines()[0]
                    sha = str(c.get("sha") or "")[:10]
                    if _SECURITY_COMMIT_KEYWORDS_RX.search(msg) or (sig.function_name and sig.function_name in msg.lower()):
                        matched_commits.append(f"{sha}: {msg[:85]}")
        except Exception:
            pass

    # 2. Recent open/closed PRs mentioning file/function/security keywords
    try:
        prs = _gh_get(f"repos/{owner}/{repo}/pulls?state=all&sort=updated&direction=desc&per_page=15")
        if isinstance(prs, list):
            for pr in prs[:15]:
                pt = str(pr.get("title") or "")
                pb = str(pr.get("body") or "")[:400]
                blob_pr = f"{pt} {pb}".lower()
                if (
                    (sig.file_basename and sig.file_basename in blob_pr)
                    or (sig.function_name and sig.function_name in blob_pr)
                ) and _SECURITY_COMMIT_KEYWORDS_RX.search(blob_pr):
                    matched_prs.append(f"PR #{pr.get('number')} ({pr.get('state')}): {pt[:80]}")
    except Exception:
        pass

    # 3. Issues search
    q_terms = " ".join(
        [t for t in [sig.file_basename, sig.function_name, sig.cwe] if t][:3]
    ).strip()
    if q_terms:
        try:
            res_i = _gh_get(f"search/issues?q={urllib.parse.quote(f'repo:{owner}/{repo} {q_terms}')}&per_page=5")
            if isinstance(res_i, dict):
                for item in (res_i.get("items") or [])[:5]:
                    matched_issues.append(f"#{item.get('number')} ({item.get('state')}): {str(item.get('title') or '')[:80]}")
        except Exception:
            pass

    # 4. Repository Security Advisories (GHSAs)
    try:
        advs = _gh_get(f"repos/{owner}/{repo}/security-advisories?per_page=10")
        if isinstance(advs, list):
            for adv in advs[:10]:
                summary = str(adv.get("summary") or "")
                ghsa_id = str(adv.get("ghsa_id") or "")
                adv_blob = f"{summary} {str(adv.get('description') or '')[:400]}".lower()
                if (
                    (sig.file_basename and sig.file_basename in adv_blob)
                    or (sig.function_name and sig.function_name in adv_blob)
                    or (sig.cwe and sig.cwe.lower() in adv_blob)
                ):
                    matched_advisories.append(f"{ghsa_id}: {summary[:80]}")
    except Exception:
        pass

    total_hits = len(matched_commits) + len(matched_prs) + len(matched_issues) + len(matched_advisories)
    if total_hits > 0:
        delta = min(0.65, 0.25 + 0.15 * min(3, total_hits))
        verdict = "LIKELY_PATCHED_OR_IN_REVIEW"
    else:
        delta = 0.0
        verdict = "CLEAN"

    return UpstreamGateResult(
        verdict=verdict,
        matched_commits=matched_commits[:5],
        matched_prs=matched_prs[:5],
        matched_issues=matched_issues[:5],
        matched_advisories=matched_advisories[:5],
        dup_risk_delta=round(delta, 3),
    )


def score_surface_congestion(
    finding: Dict[str, Any],
    *,
    code_age_hours: Optional[float] = None,
    resolved_count: int = 25,
) -> SurfaceCongestionResult:
    """
    Scores target surface congestion & code freshness:
      - Penalizes high-traffic first-read files (`started_round.rs`, OAuth callbacks, top-level entrypoints)
        and stale core files untouched for months on crowded programs.
      - Boosts deep cross-boundary rare surfaces (AWS Nitro Enclave KMS attestation, Post-Quantum
        precompiles, WASI host-guest internals, WAL/GossipSub/P2P) and fresh `< 72h` commits.
    """
    blob = " ".join(
        [
            str(finding.get("file_path") or finding.get("file") or finding.get("asset_identifier") or ""),
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("evidence") or ""),
        ]
    )
    score = 0.45  # Neutral baseline
    adj = 0.0
    signals: List[str] = []

    for label, delta, rx in _HIGH_CONGESTION_SURFACES:
        if rx.search(blob):
            score += delta
            adj += delta * 0.75
            signals.append(f"congested:{label}(+{delta:.2f})")

    for label, delta, rx in _DEEP_BOUNDARY_SURFACES:
        if rx.search(blob):
            score += delta  # negative reduces congestion
            adj += delta * 0.85
            signals.append(f"deep_boundary:{label}({delta:.2f})")

    # Freshness tier & adjustment
    if code_age_hours is None:
        freshness = "UNKNOWN"
    elif code_age_hours <= 24.0:
        freshness = "FRESH_24H"
        score -= 0.28
        adj -= 0.24
        signals.append("fresh_code:<=24h(-0.24)")
    elif code_age_hours <= 72.0:
        freshness = "FRESH_72H"
        score -= 0.20
        adj -= 0.16
        signals.append("fresh_code:<=72h(-0.16)")
    elif code_age_hours <= 24.0 * 30.0:
        freshness = "RECENT_30D"
        score -= 0.05
        adj -= 0.04
        signals.append("recent_code:<=30d(-0.04)")
    elif code_age_hours >= 24.0 * 180.0:
        freshness = "STALE_CORE"
        stale_pen = 0.18 if resolved_count >= 100 else 0.10
        score += stale_pen
        adj += stale_pen
        signals.append(f"stale_core:>180d(+{stale_pen:.2f})")
    else:
        freshness = "ESTABLISHED"

    score_clamped = round(max(0.05, min(0.98, score)), 3)
    if score_clamped <= 0.35:
        tier = "LOW_CONGESTION_DEEP_BOUNDARY"
    elif score_clamped >= 0.65:
        tier = "HIGH_CONGESTION_CROWDED"
    else:
        tier = "MODERATE"

    return SurfaceCongestionResult(
        congestion_score=score_clamped,
        congestion_tier=tier,
        freshness_tier=freshness,
        dup_risk_adjustment=round(adj, 3),
        matched_signals=signals,
    )


def evaluate_dedup_gate(
    finding: Dict[str, Any],
    *,
    program_handle: str = "",
    resolved_count: int = 25,
    prior_signatures: Sequence[Dict[str, Any]] = (),
    exclude_draft_id: str = "",
    local_repo_path: Optional[str] = None,
    repo_url: str = "",
    allow_network: bool = False,
    dry_run: bool = False,
) -> DedupGateResult:
    """
    Unified 3-Pillar Pre-Submission Deduplication, Freshness & Surface Congestion Gate.
    """
    from engine.cash_bounty_tuner import estimate_program_duplicate_prior

    sig = build_structural_signature(finding, program_handle=program_handle)
    sim_score, closest_prior = score_cross_report_similarity(
        sig,
        prior_signatures,
        exclude_draft_id=exclude_draft_id,
    )

    git_res = inspect_local_git_history(
        local_repo_path,
        str(finding.get("file_path") or finding.get("file") or ""),
        line_number=int(finding.get("line_number") or finding.get("line") or 0),
    )
    gh_res = query_github_upstream_dedup(
        finding,
        repo_url=repo_url,
        allow_network=allow_network,
        dry_run=dry_run,
    )
    cong = score_surface_congestion(
        finding,
        code_age_hours=git_res.code_age_hours,
        resolved_count=resolved_count,
    )

    base_prior = estimate_program_duplicate_prior(resolved_count)
    adj_dup = base_prior + cong.dup_risk_adjustment + gh_res.dup_risk_delta
    if git_res.likely_patched_in_git:
        adj_dup += 0.45
    if sim_score >= CROSS_REPORT_SIMILARITY_HOLD_THRESHOLD:
        adj_dup = max(adj_dup, 0.90)
    elif sim_score >= CROSS_REPORT_SIMILARITY_WARN_THRESHOLD:
        adj_dup += 0.20
    adj_dup = round(max(0.03, min(0.97, adj_dup)), 3)

    upstream_hits: List[str] = (
        list(git_res.recent_security_commits)
        + list(gh_res.matched_advisories)
        + list(gh_res.matched_prs)
        + list(gh_res.matched_issues)
        + list(gh_res.matched_commits)
    )

    if sim_score >= CROSS_REPORT_SIMILARITY_HOLD_THRESHOLD:
        verdict = "HOLD_CROSS_REPORT_DUPLICATE"
        rationale = f"Structural overlap ({sim_score:.2f}) with prior report/duplicate {closest_prior}; hold to protect submission slot."
    elif git_res.likely_patched_in_git or gh_res.verdict == "LIKELY_PATCHED_OR_IN_REVIEW":
        verdict = "HOLD_LIKELY_PATCHED_UPSTREAM"
        rationale = f"Matched {len(upstream_hits)} recent upstream security commit/PR/issue/advisory hit(s): {upstream_hits[0][:90]}"
    elif cong.freshness_tier in ("FRESH_24H", "FRESH_72H") and cong.congestion_score < 0.65:
        verdict = "PASS_NOVEL_FRESH"
        rationale = f"Fresh code ({cong.freshness_tier}, age={git_res.code_age_hours}h) with low/moderate congestion ({cong.congestion_score:.2f})."
    elif cong.congestion_tier == "LOW_CONGESTION_DEEP_BOUNDARY":
        verdict = "PASS_LOW_CONGESTION"
        rationale = f"Deep cross-boundary low-congestion surface ({cong.congestion_score:.2f}; {', '.join(cong.matched_signals[:3])})."
    elif cong.congestion_tier == "HIGH_CONGESTION_CROWDED":
        verdict = "WARN_HIGH_CONGESTION"
        rationale = f"High-congestion first-read surface ({cong.congestion_score:.2f}); deprioritized behind deeper/fresher targets."
    else:
        verdict = "PASS_LOW_CONGESTION"
        rationale = f"Moderate surface congestion ({cong.congestion_score:.2f}) with no upstream or local duplicate collision."

    return DedupGateResult(
        gate_verdict=verdict,
        adjusted_p_duplicate=adj_dup,
        code_age_hours=git_res.code_age_hours,
        congestion_score=cong.congestion_score,
        congestion_tier=cong.congestion_tier,
        freshness_tier=cong.freshness_tier,
        cross_report_similarity=sim_score,
        closest_prior_report=closest_prior,
        upstream_hits=upstream_hits[:8],
        rationale=rationale,
        signature=sig.to_dict(),
        local_git=git_res.to_dict(),
        upstream_github=gh_res.to_dict(),
    )


def score_draft_batch(
    tickets: Sequence[Dict[str, Any]],
    *,
    prior_signatures: Sequence[Dict[str, Any]] = (),
    program_resolved_counts: Optional[Dict[str, int]] = None,
    local_repo_path: Optional[str] = None,
    repo_url: str = "",
    allow_network: bool = False,
    dry_run: bool = False,
) -> List[Dict[str, Any]]:
    """
    Scores a batch of pending/local drafts (e.g. remaining 14 Circle Arc drafts) by
    Deduplication Gate, Surface Congestion, Code Freshness, and Adjusted Cash EV,
    returning them ordered strictly best-next-submission first.
    """
    actionable = {
        "ready_to_submit",
        "queued_cooldown",
        "draft_saved_on_site",
        "held_cool_off",
        "draft_local",
        "needs_live_poc",
    }
    res_counts = dict(program_resolved_counts or {})
    scored: List[Dict[str, Any]] = []
    for t in tickets:
        if str(t.get("state") or "") not in actionable:
            continue
        handle = str(t.get("program_handle") or "").lower()
        rc = int(res_counts.get(handle, 25))
        gate = evaluate_dedup_gate(
            t,
            program_handle=handle,
            resolved_count=rc,
            prior_signatures=prior_signatures,
            exclude_draft_id=str(t.get("draft_id") or ""),
            local_repo_path=local_repo_path,
            repo_url=repo_url,
            allow_network=allow_network,
            dry_run=dry_run,
        )
        base_payout = float(t.get("expected_payout_usd") or t.get("cash_ev_usd") or 0.0)
        p_valid = float(t.get("p_valid") or (0.88 if int(t.get("poc_verified_runtime") or 0) == 1 else 0.55))
        adj_ev = round(max(0.0, p_valid * (1.0 - gate.adjusted_p_duplicate) * base_payout - 75.0), 2)
        if gate.gate_verdict in ("HOLD_CROSS_REPORT_DUPLICATE", "HOLD_LIKELY_PATCHED_UPSTREAM"):
            adj_ev = 0.0
        scored.append(
            {
                **dict(t),
                "dedup_gate_verdict": gate.gate_verdict,
                "adjusted_p_duplicate": gate.adjusted_p_duplicate,
                "congestion_score": gate.congestion_score,
                "congestion_tier": gate.congestion_tier,
                "freshness_tier": gate.freshness_tier,
                "code_age_hours": gate.code_age_hours,
                "cross_report_similarity": gate.cross_report_similarity,
                "closest_prior_report": gate.closest_prior_report,
                "adjusted_cash_ev_usd": adj_ev,
                "dedup_rationale": gate.rationale,
            }
        )

    verdict_order = {
        "PASS_NOVEL_FRESH": 0,
        "PASS_LOW_CONGESTION": 1,
        "WARN_HIGH_CONGESTION": 2,
        "HOLD_LIKELY_PATCHED_UPSTREAM": 3,
        "HOLD_CROSS_REPORT_DUPLICATE": 4,
    }
    scored.sort(
        key=lambda x: (
            verdict_order.get(str(x.get("dedup_gate_verdict") or ""), 9),
            0 if int(x.get("poc_verified_runtime") or 0) == 1 else 1,
            -float(x.get("adjusted_cash_ev_usd") or 0.0),
            float(x.get("congestion_score") or 0.5),
            str(x.get("draft_id") or ""),
        )
    )
    for idx, item in enumerate(scored, start=1):
        item["dedup_rank"] = idx
    return scored


__all__ = [
    "CROSS_REPORT_SIMILARITY_HOLD_THRESHOLD",
    "CROSS_REPORT_SIMILARITY_WARN_THRESHOLD",
    "DedupGateResult",
    "FreshCodeSlice",
    "LocalGitHistoryResult",
    "StructuralSignature",
    "SurfaceCongestionResult",
    "UpstreamGateResult",
    "build_structural_signature",
    "evaluate_dedup_gate",
    "inspect_local_git_history",
    "query_github_upstream_dedup",
    "score_cross_report_similarity",
    "score_draft_batch",
    "score_surface_congestion",
    "slice_changed_hunks",
]
