"""
RFCHunt `--all --ensemble` End-to-End Bounty & Audit Orchestrator (`engine/ensemble_orchestrator.py`).
=====================================================================================================
Solves the three core failure modes in bug bounty & security audit triage:
  1. Freshness-First Diff Gate (Stage 0): inspects local git commit age (`<72h` = `FRESH_UNDER_72H`,
     `<14d` = `RECENT_UNDER_14D`, older = `STALE_DUPLICATE_RISK`) so brand-new code changes always
     rank above duplicate-prone stale branches.
  2. Multi-Engine Consensus + Deterministic Override Immunity (Stages 1-2): clusters findings across
     independent engine families (`mantis`, `aiscan`, `raptor`, `rea`, `pe_magika`, `slicer`,
     `artex`, `web_llm`, `atlas_llm`, `lean4`), computes calibrated ensemble confidence
     `1 - prod(1 - w_i)`, and enforces Lean 4's `deterministic_confirmation_immutable` invariant.
  3. Vendor Threat-Model Gate + Mandatory Live PoC Gate (Stages 3-4):
     - Evaluates program-specific boundaries (`shopify`, `anthropic`, `arc-bbp`, `cloudflare`,
       `coinbase`, `generic`) fail-closed before drafting.
     - Strictly caps static-only agreement at `ENSEMBLE_CORROBORATED_STATIC` — a finding can NEVER
       reach `SUBMISSION_READY` without verified runtime PoC output (`poc_verified=True` via
       `LinuxPocRunner` or matching target-OS runtime evidence).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from engine.host_containment import silent_subprocess_run
from engine.linux_poc_runner import LinuxPocRunner, VerifiableTranscript

# Engine reliability weights for independent-family consensus fusion
ENGINE_WEIGHTS: Dict[str, float] = {
    "lean4": 0.95,
    "linux_poc": 0.95,
    "raptor": 0.72,
    "mantis": 0.68,
    "aiscan": 0.65,
    "web_llm": 0.66,
    "atlas_llm": 0.70,
    "artex": 0.64,
    "pe_magika": 0.74,
    "rea": 0.70,
    "slicer": 0.62,
    "smuggling": 0.68,
}

# Disposition priority order (lower number = higher priority in final report)
DISPOSITION_RANK: Dict[str, int] = {
    "SUBMISSION_READY": 0,
    "ENSEMBLE_CORROBORATED_STATIC": 1,
    "SINGLE_ENGINE_CORROBORATE": 2,
    "LOW_CONFIDENCE_NOISE": 3,
    "HELD_OUT_OF_THREAT_MODEL": 4,
}

FRESHNESS_RANK: Dict[str, int] = {
    "FRESH_UNDER_72H": 0,
    "RECENT_UNDER_14D": 1,
    "STALE_DUPLICATE_RISK": 2,
    "UNKNOWN_FRESHNESS": 3,
}

SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass
class RepoFreshnessSnapshot:
    """Stage 0 git freshness telemetry for a target repository."""

    repo_path: str
    is_git_repo: bool
    head_commit: str = ""
    head_timestamp_iso: str = ""
    head_age_hours: Optional[float] = None
    freshness_hours_window: int = 72
    freshness_status: str = "UNKNOWN_FRESHNESS"
    fresh_files: List[str] = field(default_factory=list)
    recent_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EngineFinding:
    """Normalized finding emitted by any RFCHunt scanner engine."""

    engine: str
    title: str
    file_path: str = ""
    line: int = 0
    cwe: str = ""
    severity: str = "MEDIUM"
    confidence: float = 0.65
    summary: str = ""
    rule_id: str = ""
    atlas_technique: str = ""
    deterministic: bool = False
    confirmed: bool = True
    target_os_required: str = ""  # e.g. "macos", "android", "windows", "linux"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatModelVerdict:
    """Stage 3 vendor threat-model evaluation outcome."""

    program: str
    passed: bool
    matched_rules: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EnsembleCluster:
    """Fused multi-engine finding cluster with freshness, threat-model, and live PoC gates."""

    cluster_id: str
    fingerprint: str
    title: str
    file_path: str
    line: int
    cwe_family: str
    severity: str
    engines: List[str]
    engine_count: int
    ensemble_confidence: float
    disposition: str
    freshness_status: str = "UNKNOWN_FRESHNESS"
    changed_in_fresh_diff: bool = False
    lean_verified: bool = False
    deterministic_override_protected: bool = False
    llm_dissent_ignored: bool = False
    threat_model: ThreatModelVerdict = field(
        default_factory=lambda: ThreatModelVerdict(program="generic", passed=True)
    )
    poc_verified: bool = False
    poc_target_os: str = ""
    poc_transcript: Optional[Dict[str, Any]] = None
    atlas_techniques: List[str] = field(default_factory=list)
    summary: str = ""
    member_findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def to_sarif_result(self) -> Dict[str, Any]:
        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        return {
            "ruleId": f"ENSEMBLE-{self.cwe_family or 'GEN'}",
            "level": level_map.get(self.severity.upper(), "warning"),
            "message": {
                "text": (
                    f"[{self.disposition} | {self.freshness_status}] {self.title} "
                    f"(engines={','.join(self.engines)}, conf={self.ensemble_confidence:.2f}, "
                    f"poc_verified={self.poc_verified})"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.file_path or "unknown"},
                        "region": {"startLine": max(1, int(self.line or 1))},
                    }
                }
            ],
            "properties": {
                "cluster_id": self.cluster_id,
                "disposition": self.disposition,
                "freshness_status": self.freshness_status,
                "changed_in_fresh_diff": self.changed_in_fresh_diff,
                "engines": self.engines,
                "ensemble_confidence": round(self.ensemble_confidence, 4),
                "poc_verified": self.poc_verified,
                "lean_verified": self.lean_verified,
                "threat_model_passed": self.threat_model.passed,
                "atlas_techniques": self.atlas_techniques,
            },
        }


@dataclass
class EnsembleReport:
    """Complete output of `--all --ensemble`."""

    target: str
    program: str
    quorum: int
    freshness: RepoFreshnessSnapshot
    clusters: List[EnsembleCluster] = field(default_factory=list)
    counts_by_disposition: Dict[str, int] = field(default_factory=dict)
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "program": self.program,
            "quorum": self.quorum,
            "generated_at_utc": self.generated_at_utc,
            "freshness": self.freshness.to_dict(),
            "counts_by_disposition": dict(self.counts_by_disposition),
            "total_clusters": len(self.clusters),
            "clusters": [c.to_dict() for c in self.clusters],
        }

    def to_sarif(self) -> Dict[str, Any]:
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "RFCHunt-Ensemble-Orchestrator",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/oyesanyf/rfchunt",
                        }
                    },
                    "results": [c.to_sarif_result() for c in self.clusters],
                }
            ],
        }


def _norm_path(path_str: str) -> str:
    p = (path_str or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lower()


def _norm_cwe_family(cwe: str, title: str = "") -> str:
    m = re.search(r"CWE-(\d+)", (cwe or "") + " " + (title or ""), re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    clean = re.sub(r"[^A-Za-z0-9]+", "_", (cwe or "GENERIC").upper()).strip("_")
    return clean or "GENERIC"


def _classify_age_hours(age_hours: Optional[float], freshness_hours: int = 72) -> str:
    if age_hours is None:
        return "UNKNOWN_FRESHNESS"
    if age_hours <= float(freshness_hours):
        return "FRESH_UNDER_72H"
    if age_hours <= 14.0 * 24.0:
        return "RECENT_UNDER_14D"
    return "STALE_DUPLICATE_RISK"


def inspect_repo_freshness(
    repo_path: Union[str, Path],
    freshness_hours: int = 72,
    now_epoch: Optional[float] = None,
) -> RepoFreshnessSnapshot:
    """
    Stage 0: Inspects local git history (read-only, `shell=False`) to classify HEAD age
    and extract files modified within `freshness_hours` (`<72h`) and 14 days.
    """
    root = Path(repo_path)
    if not root.exists() or not root.is_dir():
        return RepoFreshnessSnapshot(
            repo_path=str(root),
            is_git_repo=False,
            freshness_hours_window=freshness_hours,
        )

    check = silent_subprocess_run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10.0,
    )
    if check.returncode != 0 or check.stdout.strip().lower() != "true":
        return RepoFreshnessSnapshot(
            repo_path=str(root),
            is_git_repo=False,
            freshness_hours_window=freshness_hours,
        )

    head_proc = silent_subprocess_run(
        ["git", "-C", str(root), "log", "-1", "--format=%H|%ct|%cI"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10.0,
    )
    head_commit = ""
    head_iso = ""
    head_age_hours: Optional[float] = None
    now_ts = float(now_epoch if now_epoch is not None else time.time())
    if head_proc.returncode == 0 and "|" in head_proc.stdout.strip():
        parts = head_proc.stdout.strip().split("|", 2)
        head_commit = parts[0]
        head_iso = parts[2] if len(parts) > 2 else ""
        try:
            commit_ts = float(parts[1])
            head_age_hours = max(0.0, (now_ts - commit_ts) / 3600.0)
        except ValueError:
            head_age_hours = None

    def _files_since(hours: int) -> List[str]:
        since_epoch = int(max(0.0, now_ts - hours * 3600.0))
        proc = silent_subprocess_run(
            [
                "git",
                "-C",
                str(root),
                "log",
                f"--since=@{since_epoch}",
                "--name-only",
                "--pretty=format:",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15.0,
        )
        if proc.returncode != 0:
            return []
        seen: Set[str] = set()
        out: List[str] = []
        for line in proc.stdout.splitlines():
            norm = _norm_path(line)
            if norm and norm not in seen:
                seen.add(norm)
                out.append(norm)
        return sorted(out)

    fresh_files = _files_since(freshness_hours)
    recent_files = _files_since(14 * 24)
    status = _classify_age_hours(head_age_hours, freshness_hours=freshness_hours)
    return RepoFreshnessSnapshot(
        repo_path=str(root),
        is_git_repo=True,
        head_commit=head_commit,
        head_timestamp_iso=head_iso,
        head_age_hours=round(head_age_hours, 2) if head_age_hours is not None else None,
        freshness_hours_window=freshness_hours,
        freshness_status=status,
        fresh_files=fresh_files,
        recent_files=recent_files,
    )


def evaluate_vendor_threat_model(
    *,
    title: str,
    summary: str,
    file_path: str,
    program: str = "generic",
    poc_verified: bool = False,
    poc_target_os: str = "",
    target_os_required: str = "",
) -> ThreatModelVerdict:
    """
    Stage 3: Program-specific fail-closed vendor threat-model gate.
    Prevents submitting findings that fall outside documented vendor trust boundaries
    (e.g., Anthropic shared srt-sandbox cross-session access, unverified macOS Seatbelt/APFS
    claims, or Shopify local-CLI self-execution).
    """
    prog = (program or "generic").strip().lower()
    blob = f"{title} {summary} {file_path}".lower()
    matched_rules: List[str] = []
    reasons: List[str] = []

    # Universal OS-runtime fidelity check (e.g. macOS APFS/Seatbelt #4235906, Android WebView)
    req_os = (target_os_required or "").strip().lower()
    if not req_os:
        if any(k in blob for k in ("seatbelt", "apfs", "sandbox-exec", "macos kernel", "darwin")):
            req_os = "macos"
        elif any(k in blob for k in ("android webview", "checkout-sheet-kit-android", "apk")):
            req_os = "android"
    if req_os and poc_verified and poc_target_os and poc_target_os.strip().lower() != req_os:
        matched_rules.append("OS_RUNTIME_MISMATCH")
        reasons.append(
            f"Finding claims {req_os}-specific behavior but PoC ran on {poc_target_os}; "
            f"target-OS ({req_os}) runtime verification is mandatory."
        )
    elif req_os == "macos" and not (poc_verified and poc_target_os.strip().lower() == "macos"):
        matched_rules.append("MACOS_RUNTIME_EVIDENCE_REQUIRED")
        reasons.append(
            "macOS Seatbelt/APFS claims require live macOS runtime reproduction output before submission."
        )

    if prog == "anthropic":
        # Shared srt-sandbox cross-session OpenProcess / same-UID isolation is outside threat model (#4235888)
        if (
            any(k in blob for k in ("srt-sandbox", "cross-session", "cross session", "openprocess"))
            and not any(k in blob for k in ("host filesystem", "host user", "domain allowlist bypass", "escape to host"))
        ):
            matched_rules.append("ANTHROPIC_SHARED_SANDBOX_NON_BOUNDARY")
            reasons.append(
                "Anthropic threat model excludes cross-session access between processes sharing "
                "the same srt-sandbox boundary; must cross sandbox -> host or bypass domain allowlist."
            )
        # Intra-runner /tmp manipulation, symlink/FIFO races, env-var tampering in same job, or self-hosted runner persistence (#4239545)
        if (
            any(k in blob for k in ("/tmp/", "self-hosted runner", "tmp buffer", "symlink race", "fifo", "hygiene_only"))
            and not any(k in blob for k in ("anthropic_api_key exfil", "cloud credential leak", "untrusted external rce", "github_token exfil"))
        ):
            matched_rules.append("ANTHROPIC_INTRA_RUNNER_HYGIENE_NON_BOUNDARY")
            reasons.append(
                "Anthropic threat model excludes intra-runner /tmp manipulation, symlink/FIFO races, "
                "same-job env tampering, and non-ephemeral self-hosted runner persistence. Focus on "
                "pre-execution trigger boundaries, unauthorized run starts, or external credential exfiltration."
            )

    elif prog == "vercel":
        if any(k in blob for k in ("examples/", "/examples/", "test/", "__tests__/", "fixtures/", "hygiene_only")):
            matched_rules.append("VERCEL_NON_PRODUCTION_EXAMPLE_OR_TEST_CODE")
            reasons.append(
                "Vercel OSS policy excludes findings solely in example, test, or fixture code."
            )

    elif prog == "cloudflare":
        if any(k in blob for k in ("hygiene_only", "open redirect", "turnstile bypass", "subdomain takeover")):
            matched_rules.append("CLOUDFLARE_OUT_OF_SCOPE_CLASS")
            reasons.append(
                "Cloudflare policy excludes hygiene-only issues, open redirects, Turnstile bypasses, and subdomain takeovers."
            )

    elif prog == "shopify":
        # Local CLI self-execution where caller already controls local execution (#06 ucp-cli)
        if any(k in blob for k in ("ucp-cli", "local cli self-execution", "local-only cli", "user-supplied --exec")):
            matched_rules.append("SHOPIFY_LOCAL_CLI_SELF_EXEC_OUT_OF_SCOPE")
            reasons.append(
                "Shopify policy excludes local CLI self-execution without a remote or cross-tenant trust boundary."
            )

    elif prog == "arc-bbp":
        if any(k in blob for k in ("informational", "style nit", "missing comment", "todo")):
            matched_rules.append("ARC_BBP_NON_SECURITY_SIGNAL_GUARD")
            reasons.append(
                "Arc BBP enforces Signal >= 3.0; non-security/informational findings are blocked to protect trial reports."
            )

    passed = len(reasons) == 0
    return ThreatModelVerdict(
        program=prog,
        passed=passed,
        matched_rules=matched_rules,
        reasons=reasons,
    )


def _compute_ensemble_confidence(findings: Sequence[EngineFinding]) -> float:
    """Computes independent-engine calibrated probability `1 - prod(1 - w_i)`."""
    by_engine: Dict[str, float] = {}
    for f in findings:
        if not f.confirmed:
            continue
        eng = f.engine.strip().lower()
        base_w = ENGINE_WEIGHTS.get(eng, 0.55)
        eff = max(0.05, min(0.98, base_w * max(0.2, min(1.0, float(f.confidence)))))
        by_engine[eng] = max(by_engine.get(eng, 0.0), eff)
    if not by_engine:
        return 0.0
    complement = 1.0
    for w in by_engine.values():
        complement *= (1.0 - w)
    return round(1.0 - complement, 4)


def _strongest_severity(findings: Sequence[EngineFinding]) -> str:
    best = "INFO"
    best_rank = SEVERITY_RANK[best]
    for f in findings:
        sev = (f.severity or "MEDIUM").upper()
        r = SEVERITY_RANK.get(sev, 2)
        if r < best_rank:
            best = sev
            best_rank = r
    return best


class EnsembleConsensusVoter:
    """
    Stages 1-4: Clusters multi-engine findings, enforces Lean 4 deterministic override
    immunity, runs the Vendor Threat-Model Gate, and enforces the Mandatory Live PoC Gate.
    """

    def __init__(
        self,
        *,
        program: str = "generic",
        quorum: int = 2,
        line_bucket_size: int = 15,
    ) -> None:
        self.program = (program or "generic").strip().lower()
        self.quorum = max(1, int(quorum))
        self.line_bucket_size = max(1, int(line_bucket_size))

    def _fingerprint(self, f: EngineFinding) -> str:
        norm_p = _norm_path(f.file_path)
        bucket = int(f.line or 0) // self.line_bucket_size
        cwe_fam = _norm_cwe_family(f.cwe, f.title)
        return f"{norm_p}|{bucket}|{cwe_fam}"

    def fuse(
        self,
        findings: Sequence[EngineFinding],
        *,
        freshness: Optional[RepoFreshnessSnapshot] = None,
        poc_transcripts: Optional[Dict[str, VerifiableTranscript]] = None,
    ) -> List[EnsembleCluster]:
        """
        Fuses findings into ranked `EnsembleCluster` objects using proximity-based line
        clustering within `(normalized_path, cwe_family)` so adjacent lines never split
        across arbitrary bucket boundaries.
        `poc_transcripts` maps either cluster `fingerprint`, `file_path`, or `"*"` to a
        `VerifiableTranscript` produced by `LinuxPocRunner` (or target-OS runner).
        """
        by_file_cwe: Dict[Tuple[str, str], List[EngineFinding]] = {}
        for f in findings:
            key = (_norm_path(f.file_path), _norm_cwe_family(f.cwe, f.title))
            by_file_cwe.setdefault(key, []).append(f)

        grouped: Dict[str, List[EngineFinding]] = {}
        for (norm_p, cwe_fam), items in by_file_cwe.items():
            items_sorted = sorted(items, key=lambda x: int(x.line or 0))
            subclusters: List[Tuple[int, List[EngineFinding]]] = []
            for item in items_sorted:
                ln = int(item.line or 0)
                if subclusters and abs(ln - subclusters[-1][0]) <= self.line_bucket_size:
                    subclusters[-1][1].append(item)
                else:
                    subclusters.append((ln, [item]))
            for anchor_ln, members in subclusters:
                fp = f"{norm_p}|{anchor_ln}|{cwe_fam}"
                grouped[fp] = members

        fresh_set = set(freshness.fresh_files) if freshness else set()
        recent_set = set(freshness.recent_files) if freshness else set()
        default_freshness = freshness.freshness_status if freshness else "UNKNOWN_FRESHNESS"
        transcripts = poc_transcripts or {}

        clusters: List[EnsembleCluster] = []
        for fp, members in grouped.items():
            # Determine deterministic / Lean 4 witness presence and LLM dissent
            has_deterministic_confirmed = any(
                (m.deterministic or m.engine.lower() in ("lean4", "linux_poc")) and m.confirmed
                for m in members
            )
            lean_verified = any(m.engine.lower() == "lean4" and m.confirmed for m in members)
            has_llm_dissent = any(not m.confirmed for m in members)

            # Enforce Lean 4 deterministic_confirmation_immutable invariant:
            # an unconfirmed LLM vote can NEVER downgrade a deterministic or PoC witness.
            llm_dissent_ignored = bool(has_deterministic_confirmed and has_llm_dissent)

            confirmed_engines = sorted({m.engine.lower() for m in members if m.confirmed})
            all_engines = sorted({m.engine.lower() for m in members})
            primary = sorted(
                members,
                key=lambda m: (
                    0 if m.deterministic else 1,
                    SEVERITY_RANK.get((m.severity or "MEDIUM").upper(), 2),
                    -float(m.confidence),
                ),
            )[0]

            norm_file = _norm_path(primary.file_path)
            changed_in_fresh = bool(norm_file and norm_file in fresh_set)
            if changed_in_fresh:
                f_status = "FRESH_UNDER_72H"
            elif norm_file and norm_file in recent_set:
                f_status = "RECENT_UNDER_14D"
            else:
                f_status = default_freshness

            # Match verified live PoC transcript if provided
            matched_tr = (
                transcripts.get(fp)
                or transcripts.get(primary.file_path)
                or transcripts.get(norm_file)
                or transcripts.get("*")
            )
            poc_verified = bool(matched_tr and matched_tr.verified)
            poc_target_os = ""
            if matched_tr:
                backend = (matched_tr.backend or "").lower()
                if "macos" in backend or "darwin" in backend:
                    poc_target_os = "macos"
                elif "android" in backend:
                    poc_target_os = "android"
                elif "windows" in backend:
                    poc_target_os = "windows"
                elif backend:
                    poc_target_os = "linux"

            req_os = next((m.target_os_required for m in members if m.target_os_required), "")
            tm_verdict = evaluate_vendor_threat_model(
                title=primary.title,
                summary=" ".join(m.summary for m in members if m.summary),
                file_path=primary.file_path,
                program=self.program,
                poc_verified=poc_verified,
                poc_target_os=poc_target_os,
                target_os_required=req_os,
            )

            # Stage 4 Hard Fail-Closed Promotion Rule:
            # Static agreement alone is strictly capped at ENSEMBLE_CORROBORATED_STATIC.
            engine_count = len(confirmed_engines)
            ens_conf = _compute_ensemble_confidence(members)
            if not tm_verdict.passed:
                disposition = "HELD_OUT_OF_THREAT_MODEL"
            elif poc_verified and (engine_count >= self.quorum or lean_verified or has_deterministic_confirmed or poc_verified):
                disposition = "SUBMISSION_READY"
            elif engine_count >= self.quorum or lean_verified:
                disposition = "ENSEMBLE_CORROBORATED_STATIC"
            elif engine_count == 1 and ens_conf >= 0.45:
                disposition = "SINGLE_ENGINE_CORROBORATE"
            else:
                disposition = "LOW_CONFIDENCE_NOISE"

            atlas_ids = sorted({m.atlas_technique for m in members if m.atlas_technique})
            cid = "ENS-" + hashlib.sha256(fp.encode("utf-8")).hexdigest()[:10].upper()
            clusters.append(
                EnsembleCluster(
                    cluster_id=cid,
                    fingerprint=fp,
                    title=primary.title,
                    file_path=primary.file_path,
                    line=int(primary.line or 0),
                    cwe_family=_norm_cwe_family(primary.cwe, primary.title),
                    severity=_strongest_severity(members),
                    engines=all_engines,
                    engine_count=engine_count,
                    ensemble_confidence=ens_conf,
                    disposition=disposition,
                    freshness_status=f_status,
                    changed_in_fresh_diff=changed_in_fresh,
                    lean_verified=lean_verified,
                    deterministic_override_protected=has_deterministic_confirmed or poc_verified,
                    llm_dissent_ignored=llm_dissent_ignored,
                    threat_model=tm_verdict,
                    poc_verified=poc_verified,
                    poc_target_os=poc_target_os,
                    poc_transcript=matched_tr.to_dict() if matched_tr else None,
                    atlas_techniques=atlas_ids,
                    summary=primary.summary,
                    member_findings=[m.to_dict() for m in members],
                )
            )

        # Rank: SUBMISSION_READY first, then FRESH_UNDER_72H first, then severity, then confidence
        clusters.sort(
            key=lambda c: (
                DISPOSITION_RANK.get(c.disposition, 99),
                FRESHNESS_RANK.get(c.freshness_status, 99),
                0 if c.changed_in_fresh_diff else 1,
                SEVERITY_RANK.get(c.severity.upper(), 9),
                -c.ensemble_confidence,
                c.cluster_id,
            )
        )
        return clusters


class EnsembleOrchestrator:
    """High-level coordinator for `--all --ensemble` / `revenue_cli.py ensemble-audit`."""

    def __init__(
        self,
        *,
        program: str = "generic",
        freshness_hours: int = 72,
        quorum: int = 2,
        exhaustive_default: bool = True,
    ) -> None:
        self.program = (program or "generic").strip().lower()
        self.freshness_hours = int(freshness_hours)
        self.quorum = max(1, int(quorum))
        self.exhaustive_default = bool(exhaustive_default)

    @staticmethod
    def run_exhaustive_local_engines(
        repo_path: Union[str, Path],
        *,
        refresh_stix: bool = True,
    ) -> Tuple[List[EngineFinding], Dict[str, Any]]:
        """
        Default exhaustive multi-engine local fan-out (bounded ThreadPoolExecutor).
        Runs all available RFCHunt local static & formal engines concurrently:
          - Module 25 `WebLLMAuditor` + Live MITRE ATLAS STIX 2.1 stack-adaptive enrichment
          - Lean 4 formal proof workspace verification (`lean_formal_verifier`)
          - Local `raptor` / `semgrep` SAST scan (if installed on host)
          - `PE/.NET Magika` binary integrity sweep (for any `.exe`/`.dll` artifacts)
        """
        from concurrent.futures import ThreadPoolExecutor

        root = Path(repo_path)
        collected: List[EngineFinding] = []
        telemetry: Dict[str, Any] = {"engines_executed": []}

        def _run_web_llm_atlas() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            from engine.web_llm_auditor import (
                audit_web_llm_repository,
                enrich_web_llm_report_with_atlas,
            )

            rep = audit_web_llm_repository(root)
            enr = enrich_web_llm_report_with_atlas(rep, refresh_stix=refresh_stix)
            out: List[EngineFinding] = []
            for item in enr.get("enriched_findings", []):
                out.append(
                    EngineFinding(
                        engine="web_llm",
                        title=item["title"],
                        file_path=item["file_path"],
                        line=int(item["line"]),
                        cwe=item["cwe"],
                        severity=item["severity"],
                        confidence=0.72,
                        summary=f"{item['owasp_llm']} | {item['snippet']} | {item['remediation']}",
                        rule_id=item["rule_id"],
                        atlas_technique=item.get("atlas_technique_id", ""),
                    )
                )
            return (
                "web_llm+atlas_stix",
                out,
                {
                    "files_scanned": rep.files_scanned,
                    "stix_mode": enr["stix_metadata"].get("source_mode"),
                    "stix_techniques": enr["stix_metadata"].get("total_techniques"),
                    "detected_stacks": enr.get("detected_stacks", []),
                    "adaptive_skills_count": len(enr.get("adaptive_skills", [])),
                },
            )

        def _run_lean4() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            lean_dir = Path(__file__).resolve().parent.parent / "formal" / "lean4"
            if not lean_dir.is_dir():
                return ("lean4", [], {"status": "not_present"})
            from engine.lean_formal_verifier import verify_lean_workspace

            lrep = verify_lean_workspace(lean_dir)
            return (
                "lean4",
                [],
                {
                    "status": lrep.status,
                    "machine_checked": lrep.machine_checked,
                    "total_theorems": lrep.total_theorems,
                },
            )

        def _run_semgrep_raptor() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            import shutil

            semgrep_bin = shutil.which("semgrep")
            if not semgrep_bin or not root.is_dir():
                return ("raptor_semgrep", [], {"status": "semgrep_not_installed"})
            proc = silent_subprocess_run(
                [semgrep_bin, "--config", "auto", "--json", "--quiet", str(root)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180.0,
            )
            out: List[EngineFinding] = []
            try:
                data = json.loads(proc.stdout or "{}")
                for r in data.get("results") or []:
                    extra = r.get("extra") or {}
                    meta = extra.get("metadata") or {}
                    cwes = meta.get("cwe") or []
                    cwe_str = cwes[0] if isinstance(cwes, list) and cwes else str(cwes or "")
                    sev_raw = str(extra.get("severity") or "WARNING").upper()
                    sev = "HIGH" if sev_raw == "ERROR" else ("MEDIUM" if sev_raw == "WARNING" else "LOW")
                    out.append(
                        EngineFinding(
                            engine="raptor",
                            title=str(r.get("check_id") or "Semgrep Finding"),
                            file_path=str(r.get("path") or ""),
                            line=int((r.get("start") or {}).get("line") or 1),
                            cwe=cwe_str,
                            severity=sev,
                            confidence=0.75,
                            summary=str(extra.get("message") or ""),
                            rule_id=str(r.get("check_id") or ""),
                        )
                    )
            except Exception as exc:
                return ("raptor_semgrep", [], {"status": f"parse_error:{exc}"})
            return ("raptor_semgrep", out, {"status": "completed", "findings": len(out)})

        def _run_gha_agent_auditor() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            from engine.gha_agent_auditor import audit_gha_agent_repository

            gfindings = audit_gha_agent_repository(root)
            out = [
                EngineFinding(
                    engine="gha_agent",
                    title=f.title,
                    file_path=f.file_path,
                    line=f.line,
                    cwe=f.cwe,
                    severity=f.severity,
                    confidence=0.82,
                    summary=f"{f.snippet} | {f.remediation}",
                    rule_id=f.rule_id,
                    atlas_technique=f.atlas_technique,
                )
                for f in gfindings
            ]
            return ("gha_agent", out, {"findings": len(out)})

        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = [
                pool.submit(_run_web_llm_atlas),
                pool.submit(_run_gha_agent_auditor),
                pool.submit(_run_lean4),
                pool.submit(_run_semgrep_raptor),
            ]
            for fut in futs:
                try:
                    eng_name, eng_findings, info = fut.result()
                    telemetry["engines_executed"].append(eng_name)
                    telemetry[eng_name] = info
                    collected.extend(eng_findings)
                except Exception as exc:
                    telemetry.setdefault("errors", []).append(str(exc))

        return collected, telemetry

    def run(
        self,
        target: Union[str, Path],
        findings: Optional[Sequence[EngineFinding]] = None,
        *,
        poc_transcripts: Optional[Dict[str, VerifiableTranscript]] = None,
        poc_lang: Optional[str] = None,
        poc_cmd: Optional[Sequence[str]] = None,
        out_dir: Optional[Union[str, Path]] = None,
        package_client_name: Optional[str] = None,
        refresh_stix: bool = True,
    ) -> EnsembleReport:
        target_str = str(target)
        freshness = inspect_repo_freshness(target_str, freshness_hours=self.freshness_hours)

        active_findings: List[EngineFinding] = list(findings) if findings is not None else []
        if findings is None and self.exhaustive_default and Path(target_str).is_dir():
            auto_findings, _tele = self.run_exhaustive_local_engines(
                target_str, refresh_stix=refresh_stix
            )
            active_findings.extend(auto_findings)

        transcripts: Dict[str, VerifiableTranscript] = dict(poc_transcripts or {})
        if poc_lang and poc_cmd and Path(target_str).is_dir():
            runner = LinuxPocRunner()
            tr = runner.run_poc(language=poc_lang, repo_path=target_str, cmd=list(poc_cmd))
            transcripts["*"] = tr

        voter = EnsembleConsensusVoter(program=self.program, quorum=self.quorum)
        clusters = voter.fuse(active_findings, freshness=freshness, poc_transcripts=transcripts)

        counts: Dict[str, int] = {}
        for c in clusters:
            counts[c.disposition] = counts.get(c.disposition, 0) + 1

        report = EnsembleReport(
            target=target_str,
            program=self.program,
            quorum=self.quorum,
            freshness=freshness,
            clusters=clusters,
            counts_by_disposition=counts,
        )

        if out_dir:
            self.export_artifacts(report, out_dir=out_dir, package_client_name=package_client_name)
        return report

    def export_artifacts(
        self,
        report: EnsembleReport,
        *,
        out_dir: Union[str, Path],
        package_client_name: Optional[str] = None,
    ) -> Dict[str, str]:
        dest = Path(out_dir)
        dest.mkdir(parents=True, exist_ok=True)

        json_path = dest / "ensemble_report.json"
        md_path = dest / "ensemble_summary.md"
        sarif_path = dest / "ensemble_findings.sarif"

        json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        sarif_path.write_text(json.dumps(report.to_sarif(), indent=2), encoding="utf-8")
        md_path.write_text(render_ensemble_markdown(report), encoding="utf-8")

        exported = {
            "json": str(json_path),
            "markdown": str(md_path),
            "sarif": str(sarif_path),
        }

        if package_client_name:
            from engine.client_audit_packager import ClientAuditPackager

            pack_findings = [
                {
                    "id": c.cluster_id,
                    "title": c.title,
                    "severity": c.severity,
                    "cwe": c.cwe_family,
                    "file": c.file_path,
                    "line": c.line,
                    "description": c.summary or f"[{c.disposition}] {c.title}",
                    "remediation": (
                        "Verify runtime PoC and apply defense-in-depth fix."
                        if c.disposition != "HELD_OUT_OF_THREAT_MODEL"
                        else "; ".join(c.threat_model.reasons)
                    ),
                }
                for c in report.clusters
                if c.disposition in ("SUBMISSION_READY", "ENSEMBLE_CORROBORATED_STATIC")
            ]
            bundle_dir = dest / "client_audit_bundle"
            ClientAuditPackager().package(
                client_name=package_client_name,
                scope_description=f"RFCHunt --all --ensemble ({report.program}) on {report.target}",
                findings=pack_findings,
                out_dir=str(bundle_dir),
            )
            exported["client_audit_bundle"] = str(bundle_dir)

        return exported


def render_ensemble_markdown(report: EnsembleReport) -> str:
    lines = [
        f"# RFCHunt Ensemble Security Audit Summary ({report.program})",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Freshness Status:** `{report.freshness.freshness_status}` (HEAD age: `{report.freshness.head_age_hours}`h, window: `{report.freshness.freshness_hours_window}`h)",
        f"- **Quorum:** `{report.quorum}` independent engines",
        f"- **Dispositions:** `{json.dumps(report.counts_by_disposition)}`",
        "",
        "| Cluster | Disposition | Freshness | Severity | Engines | Conf | Live PoC | File |",
        "|---|---|---|---|---|---:|:---:|---|",
    ]
    for c in report.clusters:
        lines.append(
            f"| `{c.cluster_id}` | `{c.disposition}` | `{c.freshness_status}` | **{c.severity}** | "
            f"`{', '.join(c.engines)}` | `{c.ensemble_confidence:.2f}` | "
            f"{'YES' if c.poc_verified else 'NO'} | `{c.file_path}:{c.line}` |"
        )
    return "\n".join(lines) + "\n"
