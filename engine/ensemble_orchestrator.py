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

import asyncio
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from engine.ensemble_whiteboard import (
    EnsembleWhiteboard,
    WhiteboardHypothesis,
)
from engine.host_containment import silent_subprocess_run
from engine.linux_poc_runner import (
    LinuxPocRunner,
    VerifiableTranscript,
    probe_optional_backends,
    run_rea_hook,
    run_symbolic_hook,
    validate_command_tokens,
    validate_mount_path,
)

# Engine reliability weights for independent-family consensus fusion
ENGINE_WEIGHTS: Dict[str, float] = {
    "lean4": 0.95,
    "linux_poc": 0.95,
    "z3_formal": 0.92,
    "trufflehog": 0.90,
    "zizmor": 0.86,
    "api_jwt_sdjwt": 0.84,
    "actionlint": 0.82,
    "parity_auditor": 0.82,
    "gha_agent": 0.80,
    "mobile_mobsf": 0.78,
    "ai_infra_guard": 0.76,
    "raptor": 0.72,
    "mantis": 0.68,
    "aiscan": 0.65,
    "web_llm": 0.66,
    "atlas_llm": 0.70,
    "gha_llm": 0.65,
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
    "EMBEDDED_OFFLINE": 3,
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
    non_production_noise: bool = False
    poc_verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _coerce_strict_bool(val: Any) -> bool:
    """Strictly coerce booleans without fail-open bool('false') / bool('0')."""
    if isinstance(val, bool):
        return val
    if isinstance(val, int) and not isinstance(val, bool):
        return val == 1
    if isinstance(val, str):
        return val.strip().lower() in {"true", "1", "yes", "on"}
    return False


def _finding_from_dict(d: Any, default_engine: str = "") -> EngineFinding:
    """Safely converts an M1/M2 scanner dict or `EngineFinding` into an `EngineFinding`."""
    if isinstance(d, EngineFinding):
        return d
    if not isinstance(d, dict):
        return EngineFinding(engine=default_engine or "unknown", title=str(d or ""))
    raw_meta = d.get("metadata")
    meta: Dict[str, Any] = dict(raw_meta) if isinstance(raw_meta, dict) else {}
    eff_noise = bool(d.get("non_production_noise", False)) or bool(meta.get("non_production_noise", False))
    if eff_noise and "non_production_noise" not in meta:
        meta["non_production_noise"] = True
    sev = str(d.get("severity") or "MEDIUM").upper()
    if sev not in SEVERITY_RANK:
        sev = "MEDIUM"
    try:
        line_num = int(d.get("line") if d.get("line") is not None else (d.get("line_number") or 0))
    except (TypeError, ValueError):
        line_num = 0
    try:
        conf_val = float(d.get("confidence", 0.65) if d.get("confidence") is not None else 0.65)
    except (TypeError, ValueError):
        conf_val = 0.65
    return EngineFinding(
        engine=str(d.get("engine") or default_engine or "unknown"),
        title=str(d.get("title") or d.get("rule_id") or "Finding"),
        file_path=str(d.get("file_path") or d.get("file") or ""),
        line=line_num,
        cwe=str(d.get("cwe") or d.get("cwe_id") or ""),
        severity=sev,
        confidence=max(0.0, min(1.0, conf_val)),
        summary=str(d.get("summary") or d.get("description") or ""),
        rule_id=str(d.get("rule_id") or ""),
        atlas_technique=str(d.get("atlas_technique") or ""),
        deterministic=bool(d.get("deterministic", False)),
        confirmed=bool(d.get("confirmed", True)),
        target_os_required=str(d.get("target_os_required") or ""),
        non_production_noise=eff_noise,
        poc_verified=_coerce_strict_bool(d.get("poc_verified", False)),
        metadata=meta,
    )


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
    gha_class: str = ""
    attack_chain_id: str = ""
    attack_chain_steps: List[str] = field(default_factory=list)
    related_clusters: List[str] = field(default_factory=list)
    lean_diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    counterexamples: List[Dict[str, Any]] = field(default_factory=list)
    whiteboard_hypothesis_ids: List[str] = field(default_factory=list)

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
        props: Dict[str, Any] = {
            "cluster_id": self.cluster_id,
            "disposition": self.disposition,
            "freshness_status": self.freshness_status,
            "changed_in_fresh_diff": self.changed_in_fresh_diff,
            "engines": self.engines,
            "ensemble_confidence": round(self.ensemble_confidence, 4),
            "poc_verified": self.poc_verified,
            "lean_verified": self.lean_verified,
            "deterministic_override_protected": self.deterministic_override_protected,
            "llm_dissent_ignored": self.llm_dissent_ignored,
            "threat_model_passed": self.threat_model.passed,
            "atlas_techniques": self.atlas_techniques,
            "lean_diagnostics_count": len(self.lean_diagnostics),
            "counterexamples_count": len(self.counterexamples),
        }
        if self.lean_diagnostics:
            props["lean_diagnostics"] = self.lean_diagnostics
        if self.counterexamples:
            props["counterexamples"] = self.counterexamples
        if self.whiteboard_hypothesis_ids:
            props["whiteboard_hypothesis_ids"] = self.whiteboard_hypothesis_ids
        if self.gha_class:
            props["gha_class"] = self.gha_class
        if self.attack_chain_id:
            props["attack_chain_id"] = self.attack_chain_id
            props["attack_chain_steps"] = self.attack_chain_steps
            props["related_clusters"] = self.related_clusters
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
                        "artifactLocation": {"uri": (self.file_path or "unknown").replace("\\", "/")},
                        "region": {"startLine": max(1, int(self.line or 1))},
                    }
                }
            ],
            "properties": props,
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
    whiteboard: Dict[str, Any] = field(default_factory=dict)
    lean_verification: Dict[str, Any] = field(default_factory=dict)
    toolchain_status: Dict[str, Any] = field(default_factory=dict)
    proxy: Optional[str] = None
    all_scan_summary: Optional[Dict[str, Any]] = None
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "program": self.program,
            "quorum": self.quorum,
            "proxy": self.proxy,
            "generated_at_utc": self.generated_at_utc,
            "freshness": self.freshness.to_dict(),
            "counts_by_disposition": dict(self.counts_by_disposition),
            "total_clusters": len(self.clusters),
            "clusters": [c.to_dict() for c in self.clusters],
            "whiteboard": dict(self.whiteboard),
            "lean_verification": dict(self.lean_verification),
            "toolchain_status": dict(self.toolchain_status),
            "all_scan_summary": self.all_scan_summary,
        }

    def to_sarif(self) -> Dict[str, Any]:
        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []
        for c in self.clusters:
            res = c.to_sarif_result()
            rid = res["ruleId"]
            if rid not in rules_by_id:
                rules_by_id[rid] = {
                    "id": rid,
                    "name": rid,
                    "shortDescription": {"text": c.title},
                    "fullDescription": {"text": c.summary or c.title},
                    "defaultConfiguration": {"level": level_map.get(c.severity.upper(), "warning")},
                    "properties": {
                        "cwe_family": c.cwe_family,
                        "gha_class": c.gha_class,
                        "atlas_techniques": c.atlas_techniques,
                        "tags": ["security", "ensemble"] + ([c.gha_class] if c.gha_class else []),
                    },
                }
            results.append(res)

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
                            "rules": list(rules_by_id.values()),
                        }
                    },
                    "results": results,
                    "properties": {
                        "program": self.program,
                        "proxy": self.proxy,
                        "lean_status": self.lean_verification.get("status"),
                        "lean_violations_count": self.lean_verification.get("violations_count", 0),
                        "toolchain_status": self.toolchain_status,
                    },
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

    try:
        check = silent_subprocess_run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10.0,
        )
    except OSError:
        return RepoFreshnessSnapshot(
            repo_path=str(root),
            is_git_repo=False,
            freshness_hours_window=freshness_hours,
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

    elif prog == "henkel_vdp":
        if any(k in blob for k in ("hygiene_only", "missing security.txt", "banner disclosure", "style nit", "todo")):
            matched_rules.append("HENKEL_VDP_NON_SECURITY_HYGIENE")
            reasons.append(
                "Henkel VDP excludes hygiene-only, missing security.txt, or purely informational findings."
            )

    elif prog == "servicenow-disclosure":
        if any(k in blob for k in ("hygiene_only", "self-xss", "self xss", "clickjacking on static")):
            matched_rules.append("SERVICENOW_VDP_OUT_OF_SCOPE")
            reasons.append(
                "ServiceNow VDP excludes hygiene-only issues, self-XSS, and static-page clickjacking."
            )

    elif prog == "common_codes":
        if any(k in blob for k in ("hygiene_only", "test_fixture_only", "examples/")):
            matched_rules.append("COMMON_CODES_NON_PRODUCTION_OUT_OF_SCOPE")
            reasons.append(
                "Common Codes EUDI Wallet program excludes hygiene-only, test-fixture, and example-only findings."
            )

    elif prog == "oppo_bbp":
        if any(k in blob for k in ("hygiene_only", "physical access only", "requires unlocked bootloader")):
            matched_rules.append("OPPO_BBP_OUT_OF_SCOPE")
            reasons.append(
                "OPPO BBP excludes hygiene-only findings and attacks requiring physical access or an unlocked bootloader."
            )

    elif prog == "amazonvrp":
        if (
            any(
                k in blob
                for k in (
                    "aws core",
                    "aws ec2",
                    "aws iam console",
                    "aws s3 infrastructure",
                    "aws.amazon.com/console",
                    "aws infrastructure",
                    "aws control plane",
                )
            )
            and not any(
                k in blob
                for k in (
                    "primevideo.com",
                    "amazongames.com",
                    "amazonpay.in",
                    "genai",
                    "alexa",
                    "kindle",
                    "amazon retail",
                )
            )
        ):
            matched_rules.append("AMAZONVRP_AWS_CORE_INFRA_OUT_OF_SCOPE")
            reasons.append(
                "Amazon VRP covers GenAI apps under *.amazon.*, primevideo.com, amazongames.com, amazonpay.in, "
                "and Shopping/Alexa/Kindle apps; AWS core infrastructure is out of scope."
            )
        if "hygiene_only" in blob:
            matched_rules.append("AMAZONVRP_HYGIENE_NON_BOUNDARY")
            reasons.append("Amazon VRP excludes hygiene-only findings without a concrete security impact.")

    elif prog == "temu":
        if any(k in blob for k in ("hygiene_only", "self-xss", "self xss", "scanner noise only")):
            matched_rules.append("TEMU_OUT_OF_SCOPE")
            reasons.append(
                "Temu BBP excludes hygiene-only findings, self-XSS, and unverified scanner noise."
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
    # Deterministic override immunity: unconfirmed LLM dissent CANNOT alter severity
    confirmed_only = [f for f in findings if f.confirmed]
    pool = confirmed_only if confirmed_only else list(findings)
    best = "INFO"
    best_rank = SEVERITY_RANK[best]
    for f in pool:
        sev = (f.severity or "MEDIUM").upper()
        r = SEVERITY_RANK.get(sev, 2)
        if r < best_rank:
            best = sev
            best_rank = r
    return best


def _correlate_gha_attack_chains(clusters: List[EnsembleCluster]) -> None:
    """
    Post-clustering GHA multi-step attack-chain correlator: links distinct GHA classes
    within the same workflow (or cross-workflow artifact poisoning) into shared attack chains.
    """
    by_file: Dict[str, List[EnsembleCluster]] = {}
    for c in clusters:
        if c.gha_class:
            by_file.setdefault(_norm_path(c.file_path), []).append(c)

    _ESCALATION_TRIGGERS = {
        "pwn_request",
        "ai_agent_trigger_boundary",
        "artifact_cache_poisoning",
        "template_script_injection",
    }

    for norm_file, file_clusters in by_file.items():
        classes = {c.gha_class for c in file_clusters}
        if len(classes) < 2 or not (classes & _ESCALATION_TRIGGERS):
            continue
        ordered = sorted(file_clusters, key=lambda c: (c.line, c.gha_class))
        steps = [f"{c.gha_class} (line {max(1, c.line)})" for c in ordered]
        chain_id = "CHAIN-" + hashlib.sha256(f"{norm_file}|{'|'.join(steps)}".encode("utf-8")).hexdigest()[:10].upper()
        all_ids = [c.cluster_id for c in ordered]
        for c in ordered:
            c.attack_chain_id = chain_id
            c.attack_chain_steps = list(steps)
            c.related_clusters = [cid for cid in all_ids if cid != c.cluster_id]


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

    @staticmethod
    def _cluster_family(f: EngineFinding) -> str:
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        gha_cls = str(meta.get("gha_class") or "").strip()
        if gha_cls:
            return f"GHA:{gha_cls}"
        return _norm_cwe_family(f.cwe, f.title)

    def _fingerprint(self, f: EngineFinding) -> str:
        norm_p = _norm_path(f.file_path)
        bucket = int(f.line or 0) // self.line_bucket_size
        fam = self._cluster_family(f)
        return f"{norm_p}|{bucket}|{fam}"

    def fuse(
        self,
        findings: Sequence[EngineFinding],
        *,
        freshness: Optional[RepoFreshnessSnapshot] = None,
        poc_transcripts: Optional[Dict[str, VerifiableTranscript]] = None,
    ) -> List[EnsembleCluster]:
        """
        Fuses findings into ranked `EnsembleCluster` objects using proximity-based line
        clustering within `(normalized_path, family)` (using canonical `gha_class` when
        available so `zizmor`, `actionlint`, `gha_agent`, and `gha_llm` corroborate across
        overlapping CWEs) so adjacent lines never split across arbitrary bucket boundaries.
        `poc_transcripts` maps either cluster `fingerprint`, `file_path`, or `"*"` to a
        `VerifiableTranscript` produced by `LinuxPocRunner` (or target-OS runner).
        """
        by_file_fam: Dict[Tuple[str, str], List[EngineFinding]] = {}
        for f in findings:
            key = (_norm_path(f.file_path), self._cluster_family(f))
            by_file_fam.setdefault(key, []).append(f)

        grouped: Dict[str, List[EngineFinding]] = {}
        for (norm_p, fam), items in by_file_fam.items():
            items_sorted = sorted(items, key=lambda x: int(x.line or 0))
            subclusters: List[Tuple[int, List[EngineFinding]]] = []
            for item in items_sorted:
                ln = int(item.line or 0)
                if subclusters and abs(ln - subclusters[-1][0]) <= self.line_bucket_size:
                    subclusters[-1][1].append(item)
                else:
                    subclusters.append((ln, [item]))
            for anchor_ln, members in subclusters:
                fp = f"{norm_p}|{anchor_ln}|{fam}"
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
                    0 if (m.deterministic and m.confirmed) else (1 if m.confirmed else 2),
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
            any_member_poc_verified = any(_coerce_strict_bool(getattr(m, "poc_verified", False)) for m in members)
            poc_verified = bool((matched_tr and matched_tr.verified) or any_member_poc_verified)
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

            # Production noise check (preserves Lean 4 deterministic confirmations and poc_verified=True)
            try:
                from engine.parity_invariant_auditor import is_non_production_noise as _is_noise_fn
            except Exception:
                _is_noise_fn = None

            def _is_member_noise(m: EngineFinding) -> bool:
                meta = m.metadata if isinstance(m.metadata, dict) else {}
                if bool(getattr(m, "non_production_noise", False)) or bool(meta.get("non_production_noise", False)):
                    return True
                if _is_noise_fn is not None:
                    return bool(_is_noise_fn(m.file_path, meta, rule_id=m.rule_id, summary=m.summary))
                return False

            all_members_noise = bool(members) and all(_is_member_noise(m) for m in members)

            # Stage 4 Hard Fail-Closed Promotion Rule:
            # Static agreement alone is strictly capped at ENSEMBLE_CORROBORATED_STATIC.
            engine_count = len(confirmed_engines)
            ens_conf = _compute_ensemble_confidence(members)
            if not tm_verdict.passed:
                disposition = "HELD_OUT_OF_THREAT_MODEL"
            elif poc_verified:
                disposition = "SUBMISSION_READY"
            elif all_members_noise and not lean_verified:
                disposition = "LOW_CONFIDENCE_NOISE"
            elif engine_count >= self.quorum or lean_verified:
                disposition = "ENSEMBLE_CORROBORATED_STATIC"
            elif engine_count == 1 and ens_conf >= 0.45:
                disposition = "SINGLE_ENGINE_CORROBORATE"
            else:
                disposition = "LOW_CONFIDENCE_NOISE"

            atlas_ids = sorted({m.atlas_technique for m in members if m.atlas_technique})
            gha_class = next(
                (
                    str(m.metadata.get("gha_class"))
                    for m in members
                    if isinstance(m.metadata, dict) and m.metadata.get("gha_class")
                ),
                "",
            )
            chain_steps: List[str] = []
            for m in members:
                if isinstance(m.metadata, dict) and isinstance(m.metadata.get("attack_chain_steps"), list):
                    for s in m.metadata["attack_chain_steps"]:
                        if str(s) not in chain_steps:
                            chain_steps.append(str(s))

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
                    gha_class=gha_class,
                    attack_chain_steps=chain_steps,
                )
            )

        _correlate_gha_attack_chains(clusters)

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


def _embedded_toolchain_status() -> Dict[str, Dict[str, Any]]:
    """Zero-subprocess toolchain availability map used in `embedded=True` offline mode."""
    backends = (
        "docker",
        "wsl2",
        "lean4",
        "rfchunt_lean_oracle",
        "angr",
        "klee",
        "semgrep",
        "rea",
        "trufflehog",
        "jadx",
        "subfinder",
        "httpx",
        "katana",
        "schemathesis",
    )
    return {
        name: {
            "available": False,
            "status": "skipped_embedded",
            "reason": "Subprocess toolchain probes skipped in embedded=True mode.",
            "path_or_module": None,
        }
        for name in backends
    }


def _classify_finding_domain(f: EngineFinding) -> str:
    meta = f.metadata if isinstance(f.metadata, dict) else {}
    cwe_l = (f.cwe or "").lower()
    rule_u = (f.rule_id or "").upper()
    blob = " ".join((f.rule_id, f.cwe, f.title, f.summary, f.file_path)).lower()

    if (
        "cwe-444" in cwe_l
        or isinstance(meta.get("http_framing"), dict)
        or any(kw in blob for kw in ("cl+te", "cl/te", "cl_te", "smuggling", "dual content-length", "bare lf"))
    ):
        return "http_framing"
    if (
        rule_u.startswith("PE-DOTNET-")
        or "cve-2026-108398" in blob
        or isinstance(meta.get("pe_report"), dict)
        or bool(meta.get("has_forshaw_cve_2026_108398_anomaly"))
    ):
        return "dotnet_pe"
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
        return "policy_guard"
    if meta.get("gha_class") or (f.engine or "").lower() in ("zizmor", "actionlint", "gha_agent", "gha_llm"):
        return "gha_workflow"
    if (f.engine or "").lower() in ("web_llm", "atlas_llm") or f.atlas_technique:
        return "ai_security"
    return "general"


def _dedup_lean_diagnostics(
    diags: Sequence[Dict[str, Any]],
    *,
    include_branch_summary: bool = True,
) -> List[Dict[str, Any]]:
    seen: Set[Tuple[Any, ...]] = set()
    out: List[Dict[str, Any]] = []
    for d in diags:
        if not isinstance(d, dict):
            continue
        if include_branch_summary:
            key: Tuple[Any, ...] = (
                d.get("module"),
                d.get("theorem"),
                d.get("line"),
                d.get("kind"),
                d.get("branch_summary"),
            )
        else:
            key = (
                d.get("module"),
                d.get("theorem"),
                d.get("line"),
                d.get("kind"),
            )
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def _dedup_lean_counterexamples(ces: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[Tuple[Any, ...]] = set()
    out: List[Dict[str, Any]] = []
    for c in ces:
        if not isinstance(c, dict):
            continue
        key = (
            c.get("domain"),
            c.get("theorem"),
            c.get("observed_verdict"),
            json.dumps(c.get("input_witness") or {}, sort_keys=True, default=str),
        )
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _normalize_command_tokens(raw_cmd: Optional[Union[str, Sequence[str]]]) -> Optional[List[str]]:
    if raw_cmd is None:
        return None
    if isinstance(raw_cmd, str):
        stripped = raw_cmd.strip()
        if not stripped:
            return None
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            return [stripped]
        return tokens if tokens else [stripped]
    return [str(tok) for tok in raw_cmd]


def _append_unique_lean_finding(
    findings: List[EngineFinding],
    candidate: EngineFinding,
) -> None:
    """
    Appends a deterministic `lean4` finding or merges its metadata into an existing
    `lean4` finding in the same `(norm_path, cwe_family)` bucket so cluster counts
    never split unexpectedly.
    """
    cand_path = _norm_path(candidate.file_path)
    cand_fam = EnsembleConsensusVoter._cluster_family(candidate)
    cand_rule = candidate.rule_id or ""
    for existing in findings:
        if (existing.engine or "").lower() != "lean4":
            continue
        ex_path = _norm_path(existing.file_path)
        ex_fam = EnsembleConsensusVoter._cluster_family(existing)
        if ex_path == cand_path and ex_fam == cand_fam and abs(int(existing.line or 0) - int(candidate.line or 0)) <= 15:
            if not cand_rule or (existing.rule_id or "") == cand_rule or cand_rule.startswith("LEAN-"):
                ex_meta = existing.metadata if isinstance(existing.metadata, dict) else {}
                c_meta = candidate.metadata if isinstance(candidate.metadata, dict) else {}
                if c_meta.get("lean_counterexamples"):
                    merged_ce = list(ex_meta.get("lean_counterexamples") or [])
                    merged_ce.extend(c_meta["lean_counterexamples"])
                    ex_meta["lean_counterexamples"] = _dedup_lean_counterexamples(merged_ce)
                if c_meta.get("lean_diagnostic") or c_meta.get("lean_diagnostics"):
                    merged_diag: List[Dict[str, Any]] = []
                    if isinstance(ex_meta.get("lean_diagnostics"), list):
                        merged_diag.extend(ex_meta["lean_diagnostics"])
                    elif isinstance(ex_meta.get("lean_diagnostic"), dict):
                        merged_diag.append(ex_meta["lean_diagnostic"])
                    if isinstance(c_meta.get("lean_diagnostics"), list):
                        merged_diag.extend(c_meta["lean_diagnostics"])
                    if isinstance(c_meta.get("lean_diagnostic"), dict):
                        merged_diag.append(c_meta["lean_diagnostic"])
                    ex_meta["lean_diagnostics"] = _dedup_lean_diagnostics(
                        merged_diag, include_branch_summary=True
                    )
                existing.metadata = ex_meta
                existing.deterministic = True
                existing.confirmed = True
                return
    findings.append(candidate)


def _evaluate_lean_domains_embedded(
    findings: Sequence[EngineFinding],
    *,
    repo_path: Optional[Path],
    lean_dir: Path,
) -> Dict[str, Any]:
    """
    Zero-subprocess Lean 4 domain evaluation for `embedded=True` mode using pure-Python
    `audit_lean_file` and isomorphic Python mirrors (`oracle=None`).
    """
    from engine.lean_formal_verifier import (
        LeanCounterexample,
        LeanDomainReport,
        LeanProofDiagnostic,
        audit_lean_file,
        verify_dotnet_pe_invariant,
        verify_http_framing_invariant,
        verify_policy_guard_invariant,
    )

    modules = []
    rfchunt_pkg = lean_dir / "RFCHunt"
    if rfchunt_pkg.is_dir():
        for lf in sorted(rfchunt_pkg.glob("*.lean")):
            modules.append(audit_lean_file(lf))
    total_theorems = sum(len(m.theorems) for m in modules)
    ws_dict = {
        "lean_dir": str(lean_dir),
        "lean_binary": None,
        "lake_binary": None,
        "machine_checked": False,
        "status": "skipped_embedded",
        "modules": [m.to_dict() for m in modules],
        "total_theorems": total_theorems,
        "stdout": "",
        "stderr": "",
        "elapsed_ms": 0.0,
        "diagnostics": [],
    }

    checks: List[LeanCounterexample] = []
    # Force pure-Python mirror resolution even if a compiled oracle binary exists under `lean_dir`.
    mirror_lean_dir = Path("__embedded_python_mirror__")
    # Evaluate baseline self-checks via pure Python mirror (oracle=None, zero subprocesses)
    checks.extend(
        verify_http_framing_invariant(
            content_lengths=[42],
            has_transfer_encoding_chunked=True,
            proxy_verdict=("reject400", None),
            lean_dir=mirror_lean_dir,
            oracle=None,
        )
    )
    checks.extend(
        verify_policy_guard_invariant(
            action="shellExec",
            scope="inScopeAuthorized",
            rules=[("permit", True)],
            lean_dir=mirror_lean_dir,
            oracle=None,
        )
    )
    checks.extend(
        verify_dotnet_pe_invariant(
            is_valid_pe=True,
            has_clr_descriptor=True,
            has_executable_image_bit=True,
            is_umci_enforced=True,
            is_signed_by_trusted_publisher=True,
            lean_dir=mirror_lean_dir,
            oracle=None,
        )
    )

    extra_diags: List[LeanProofDiagnostic] = []
    for f in findings:
        dom = _classify_finding_domain(f)
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        if dom == "http_framing":
            try:
                hf = meta.get("http_framing") if isinstance(meta.get("http_framing"), dict) else {}
                if hf:
                    pv = hf.get("proxy_verdict")
                    pv_t = tuple(pv) if isinstance(pv, (list, tuple)) and len(pv) == 2 else None
                    checks.extend(
                        verify_http_framing_invariant(
                            content_lengths=hf.get("content_lengths", []),
                            has_transfer_encoding_chunked=bool(hf.get("has_transfer_encoding_chunked", False)),
                            has_bare_lf=bool(hf.get("has_bare_lf", False)),
                            proxy_verdict=pv_t,  # type: ignore[arg-type]
                            lean_dir=mirror_lean_dir,
                            oracle=None,
                        )
                    )
                else:
                    checks.extend(
                        verify_http_framing_invariant(
                            content_lengths=[42],
                            has_transfer_encoding_chunked=True,
                            lean_dir=mirror_lean_dir,
                            oracle=None,
                        )
                    )
            except (ValueError, TypeError) as exc:
                extra_diags.append(
                    LeanProofDiagnostic(
                        module="RFCHunt.HttpFramingOracle",
                        theorem="invalid_witness_metadata",
                        line=None,
                        column=None,
                        kind="invalid_witness",
                        branch_summary=str(exc)[:240],
                        raw_excerpt=str(exc)[:1000],
                    )
                )
        elif dom == "policy_guard":
            from engine.lean_formal_verifier import _coerce_strict_bool as _lean_strict_bool

            pg = meta.get("policy_guard") if isinstance(meta.get("policy_guard"), dict) else {}
            try:
                if pg:
                    checks.extend(
                        verify_policy_guard_invariant(
                            action=str(pg.get("action", "networkProbe")),
                            scope=str(pg.get("scope", "inScopeAuthorized")),
                            in_workspace_root=pg.get("in_workspace_root", True),
                            allow_destructive=pg.get("allow_destructive", False),
                            rules=pg.get("rules", (("permit", True),)),
                            confirmed_by_tool=pg.get("confirmed_by_tool"),
                            llm_confirmed=pg.get("llm_confirmed"),
                            observed_allowed=pg.get("observed_allowed"),
                            observed_reconciled=pg.get("observed_reconciled"),
                            lean_dir=mirror_lean_dir,
                            oracle=None,
                        )
                    )
                else:
                    blob_l = " ".join((f.rule_id, f.cwe, f.title, f.summary, f.file_path)).lower()
                    is_active = _lean_strict_bool(f.confirmed, field_name="confirmed")
                    if any(kw in blob_l for kw in ("llm_dissent", "override_immunity", "deterministic_confirmation")):
                        obs_rec = (
                            _lean_strict_bool(meta["observed_reconciled"], field_name="observed_reconciled")
                            if "observed_reconciled" in meta
                            else (not is_active)
                        )
                        checks.extend(
                            verify_policy_guard_invariant(
                                confirmed_by_tool=True,
                                llm_confirmed=False,
                                observed_reconciled=obs_rec,
                                lean_dir=mirror_lean_dir,
                                oracle=None,
                            )
                        )
                    elif "shellexec" in blob_l or "shell_exec" in blob_l:
                        checks.extend(
                            verify_policy_guard_invariant(
                                action="shellExec",
                                observed_allowed=meta.get("observed_allowed", is_active),
                                lean_dir=mirror_lean_dir,
                                oracle=None,
                            )
                        )
                    elif "out_of_scope" in blob_l or "out-of-scope" in blob_l:
                        checks.extend(
                            verify_policy_guard_invariant(
                                action="networkProbe",
                                scope="outOfScope",
                                observed_allowed=meta.get("observed_allowed", is_active),
                                lean_dir=mirror_lean_dir,
                                oracle=None,
                            )
                        )
                    elif "outside_workspace" in blob_l:
                        checks.extend(
                            verify_policy_guard_invariant(
                                action="readWorkspaceFile",
                                in_workspace_root=False,
                                observed_allowed=meta.get("observed_allowed", is_active),
                                lean_dir=mirror_lean_dir,
                                oracle=None,
                            )
                        )
                    else:
                        checks.extend(
                            verify_policy_guard_invariant(
                                rules=[("permit", True), ("forbid", True)],
                                observed_allowed=meta.get("observed_allowed", is_active),
                                lean_dir=mirror_lean_dir,
                                oracle=None,
                            )
                        )
            except (ValueError, TypeError) as exc:
                extra_diags.append(
                    LeanProofDiagnostic(
                        module="RFCHunt.PolicyGuard",
                        theorem="invalid_witness_metadata",
                        line=None,
                        column=None,
                        kind="invalid_witness",
                        branch_summary=str(exc)[:240],
                        raw_excerpt=str(exc)[:1000],
                    )
                )
        elif dom == "dotnet_pe":
            try:
                pe_rep = meta.get("pe_report") if isinstance(meta.get("pe_report"), dict) else None
                if pe_rep is not None:
                    checks.extend(verify_dotnet_pe_invariant(pe_report=pe_rep, lean_dir=mirror_lean_dir, oracle=None))
                else:
                    has_anom = "cve-2026-108398" in f.title.lower() or bool(meta.get("has_forshaw_cve_2026_108398_anomaly"))
                    checks.extend(
                        verify_dotnet_pe_invariant(
                            is_valid_pe=True,
                            has_clr_descriptor=True,
                            has_executable_image_bit=not has_anom,
                            is_umci_enforced=True,
                            is_signed_by_trusted_publisher=False,
                            lean_dir=mirror_lean_dir,
                            oracle=None,
                        )
                    )
            except (ValueError, TypeError) as exc:
                extra_diags.append(
                    LeanProofDiagnostic(
                        module="RFCHunt.DotNetPeIntegrity",
                        theorem="invalid_witness_metadata",
                        line=None,
                        column=None,
                        kind="invalid_witness",
                        branch_summary=str(exc)[:240],
                        raw_excerpt=str(exc)[:1000],
                    )
                )

    domains_order = ["http_framing", "policy_guard", "dotnet_pe"]
    domain_checks: Dict[str, Dict[str, Any]] = {}
    for dom in domains_order:
        dom_items = [c for c in checks if c.domain == dom]
        dom_v = sum(1 for c in dom_items if c.violated)
        seen_thms = list(dict.fromkeys(c.theorem for c in dom_items))
        domain_checks[dom] = {
            "checks": len(dom_items),
            "violations": dom_v,
            "theorems": seen_thms,
            "status": "counterexample_found" if dom_v > 0 else "passed",
        }
    v_count = sum(1 for c in checks if c.violated)
    rep = LeanDomainReport(
        status="counterexample_found" if v_count > 0 else "passed",
        oracle_backend="python_mirror",
        machine_checked=False,
        workspace_report=ws_dict,
        domain_checks=domain_checks,
        counterexamples=checks,
        diagnostics=extra_diags,
        domains_checked=domains_order,
        checks_total=len(checks),
        violations_count=v_count,
        degradation_reason=(
            "Skipped Lean 4 subprocesses in embedded=True mode; "
            "evaluated domain invariants via isomorphic Python mirrors (machine_checked=False)."
        ),
    )
    return rep.to_dict()


class EnsembleOrchestrator:
    """High-level coordinator for `--all --ensemble` / `revenue_cli.py ensemble-audit`."""

    def __init__(
        self,
        *,
        program: str = "generic",
        freshness_hours: int = 72,
        quorum: int = 2,
        exhaustive_default: bool = True,
        embedded: bool = False,
        model: Optional[str] = None,
        enable_llm_verify: Optional[bool] = None,
        gha_only: bool = False,
        no_external_scanners: bool = False,
        proxy: Optional[str] = None,
        max_whiteboard_rounds: int = 2,
        enable_whiteboard: bool = True,
        db: Optional[Any] = None,
        lean_dir: Optional[Union[str, Path]] = None,
        max_workers: int = 4,
    ) -> None:
        self.program = (program or "generic").strip().lower()
        self.freshness_hours = int(freshness_hours)
        self.quorum = max(1, int(quorum))
        self.exhaustive_default = bool(exhaustive_default)
        self.embedded = bool(embedded)
        self.model = model
        self.enable_llm_verify = (
            (not self.embedded)
            if enable_llm_verify is None
            else (bool(enable_llm_verify) and not self.embedded)
        )
        self.gha_only = bool(gha_only)
        self.no_external_scanners = bool(no_external_scanners)
        self.proxy = proxy
        self.max_whiteboard_rounds = max(0, int(max_whiteboard_rounds))
        self.enable_whiteboard = bool(enable_whiteboard)
        self.db = db
        self.lean_dir = (
            Path(lean_dir)
            if lean_dir is not None
            else (Path(__file__).resolve().parent.parent / "formal" / "lean4")
        )
        self.max_workers = max(1, int(max_workers))
        self.last_telemetry: Dict[str, Any] = {}

    @staticmethod
    def run_exhaustive_local_engines(
        repo_path: Union[str, Path],
        *,
        refresh_stix: bool = True,
        embedded: bool = False,
        model: Optional[str] = None,
        enable_llm_verify: Optional[bool] = None,
        gha_only: bool = False,
        no_external_scanners: bool = False,
        lean_dir: Optional[Union[str, Path]] = None,
        program: str = "generic",
    ) -> Tuple[List[EngineFinding], Dict[str, Any]]:
        """
        Default exhaustive multi-engine local fan-out (bounded ThreadPoolExecutor).
        Runs all available RFCHunt local static & formal engines concurrently:
          - Zizmor (binary when on PATH and not `embedded`, else pure-Python parity)
          - Actionlint (binary when on PATH and not `embedded`, else pure-Python parity)
          - `gha_agent_auditor` (R1 YAML + AI-agent trust-boundary analyzer)
          - Module 25 `WebLLMAuditor` + Live MITRE ATLAS STIX 2.1 stack-adaptive enrichment
          - Lean 4 formal proof workspace & domain verification (`lean_formal_verifier`)
          - Local `raptor` / `semgrep` SAST scan (if installed and not `embedded`/`no_external_scanners`/offline)
          - M1 Scanners (`trufflehog`, `mobile_mobsf`, `api_jwt_sdjwt`, `ai_infra_guard`, `parity_auditor`)
          - Z3 formal verification (`z3_formal_verifier`) for OpenAPI/IAM/StateMachine specs
          - `gha_llm` defensive semantic verification & attack-chain correlation (when enabled & online)
        """
        root = Path(repo_path)
        eff_refresh_stix = False if embedded else bool(refresh_stix)
        eff_llm_verify = (not embedded) if enable_llm_verify is None else (bool(enable_llm_verify) and not embedded)
        skip_external_bins = bool(embedded or no_external_scanners)
        eff_lean_dir = (
            Path(lean_dir)
            if lean_dir is not None
            else (Path(__file__).resolve().parent.parent / "formal" / "lean4")
        )
        collected: List[EngineFinding] = []
        telemetry: Dict[str, Any] = {
            "embedded": bool(embedded),
            "gha_only": bool(gha_only),
            "no_external_scanners": bool(no_external_scanners),
            "engines_executed": [],
        }

        def _run_zizmor() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            from engine.gha_workflow_scanners import run_zizmor_scan

            res = run_zizmor_scan(root, embedded=skip_external_bins)
            out = [f.to_engine_finding() for f in res.findings]
            return (
                "zizmor",
                out,
                {
                    "execution_mode": res.execution_mode,
                    "files_scanned": res.files_scanned,
                    "findings": len(out),
                    "binary_path": res.binary_path,
                    **res.telemetry,
                },
            )

        def _run_actionlint() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            from engine.gha_workflow_scanners import run_actionlint_scan

            res = run_actionlint_scan(root, embedded=skip_external_bins)
            out = [f.to_engine_finding() for f in res.findings]
            return (
                "actionlint",
                out,
                {
                    "execution_mode": res.execution_mode,
                    "files_scanned": res.files_scanned,
                    "findings": len(out),
                    "binary_path": res.binary_path,
                    **res.telemetry,
                },
            )

        def _run_web_llm_atlas() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            if not root.is_dir():
                return ("web_llm+atlas_stix", [], {"status": "skipped_non_dir"})
            from engine.web_llm_auditor import (
                audit_web_llm_repository,
                enrich_web_llm_report_with_atlas,
            )

            rep = audit_web_llm_repository(root)
            enr = enrich_web_llm_report_with_atlas(rep, refresh_stix=eff_refresh_stix)
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
            if embedded:
                return ("lean4", [], {"status": "skipped_embedded"})
            if not eff_lean_dir.is_dir():
                return ("lean4", [], {"status": "not_present"})
            from engine.lean_formal_verifier import (
                _find_pe_candidates_bounded,
                evaluate_lean_domains,
            )

            dom_rep = evaluate_lean_domains(
                findings=None,
                repo_path=root if root.is_dir() else None,
                lean_dir=eff_lean_dir,
            )
            ws = dom_rep.workspace_report or {}
            ws_status = str(ws.get("status") or "unknown")
            emitted: List[EngineFinding] = []

            if ws_status in ("proof_integrity_violation", "kernel_failed"):
                for diag in dom_rep.diagnostics:
                    d_dict = diag.to_dict()
                    _append_unique_lean_finding(
                        emitted,
                        EngineFinding(
                            engine="lean4",
                            title=f"Lean 4 proof diagnostic ({d_dict.get('kind')}): {d_dict.get('theorem')}",
                            file_path=f"formal/lean4/RFCHunt/{d_dict.get('module', 'Unknown')}.lean",
                            line=int(d_dict.get("line") or 1),
                            cwe="CWE-693",
                            severity="HIGH",
                            confidence=0.95,
                            summary=str(d_dict.get("branch_summary") or d_dict.get("raw_excerpt") or ws_status),
                            rule_id=f"LEAN-{str(d_dict.get('kind') or 'DIAG').upper()}",
                            deterministic=True,
                            confirmed=True,
                            metadata={"lean_diagnostic": d_dict},
                        ),
                    )

            pe_rel_path = ""
            if root.is_dir():
                pe_cands = _find_pe_candidates_bounded(root)
                if pe_cands:
                    try:
                        pe_rel_path = pe_cands[0].relative_to(root).as_posix()
                    except ValueError:
                        pe_rel_path = str(pe_cands[0])

            for ce in dom_rep.counterexamples:
                if not ce.violated:
                    continue
                ce_dict = ce.to_dict()
                target_fp = pe_rel_path if ce.domain == "dotnet_pe" and pe_rel_path else f"formal/lean4/{ce.domain}"
                cwe_val = (
                    "CWE-444"
                    if ce.domain == "http_framing"
                    else ("CWE-347" if ce.domain == "dotnet_pe" else "CWE-862")
                )
                _append_unique_lean_finding(
                    emitted,
                    EngineFinding(
                        engine="lean4",
                        title=f"Lean 4 {ce.domain} counterexample: {ce.theorem}",
                        file_path=target_fp,
                        line=1,
                        cwe=cwe_val,
                        severity="HIGH",
                        confidence=0.95,
                        summary=ce.summary,
                        rule_id=f"LEAN-{ce.domain.upper()}-{ce.theorem}",
                        deterministic=True,
                        confirmed=True,
                        metadata={"lean_counterexamples": [ce_dict]},
                    ),
                )

            return (
                "lean4",
                emitted,
                {
                    "status": ws_status,
                    "machine_checked": bool(dom_rep.machine_checked),
                    "total_theorems": int(ws.get("total_theorems") or 0),
                    "oracle_backend": dom_rep.oracle_backend,
                    "violations_count": dom_rep.violations_count,
                    "domain_checks": dom_rep.domain_checks,
                    "diagnostics": [d.to_dict() for d in dom_rep.diagnostics],
                    "degradation_reason": dom_rep.degradation_reason,
                },
            )

        def _run_semgrep_raptor() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            if embedded:
                return ("raptor_semgrep", [], {"status": "skipped_embedded"})
            if no_external_scanners:
                return ("raptor_semgrep", [], {"status": "skipped_no_external_scanners"})
            import shutil

            semgrep_bin = shutil.which("semgrep")
            if not semgrep_bin or not root.is_dir():
                return ("raptor_semgrep", [], {"status": "semgrep_not_installed"})
            if (
                os.environ.get("RFCHUNT_OFFLINE") == "1"
                or os.environ.get("RFCHUNT_AIR_GAPPED") == "1"
            ):
                return ("raptor_semgrep", [], {"status": "skipped_offline"})
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
            from engine.gha_agent_auditor import audit_gha_workflows

            gfindings = audit_gha_workflows(root)
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
                    deterministic=True,
                    confirmed=True,
                    metadata={
                        "gha_class": f.gha_class,
                        "hygiene_only": f.hygiene_only,
                        **(f.metadata or {}),
                    },
                )
                for f in gfindings
            ]
            return ("gha_agent", out, {"findings": len(out)})

        def _run_rea() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            # `run_rea_hook` runs pure-Python static JS/Electron surface inspection
            # (`use_rea_cli=False`, zero subprocesses / external binaries), safe in `embedded=True`.
            if not root.exists():
                return ("rea", [], {"status": "target_not_found", "findings": 0, "zero_subprocess": True})
            try:
                hook_res = run_rea_hook(root)
            except Exception as exc:
                return (
                    "rea",
                    [],
                    {
                        "status": "unavailable",
                        "mode": "python_static",
                        "findings": 0,
                        "zero_subprocess": True,
                        "error": str(exc),
                    },
                )
            if not isinstance(hook_res, dict) or hook_res.get("status") in ("rejected_unsafe", "failed"):
                return (
                    "rea",
                    [],
                    {
                        "status": str((hook_res or {}).get("status") or "unavailable"),
                        "mode": str((hook_res or {}).get("mode") or "python_static"),
                        "findings": 0,
                        "endpoints": 0,
                        "ai_sinks": 0,
                        "ipc_channels": 0,
                        "zero_subprocess": True,
                    },
                )
            out: List[EngineFinding] = []
            for rf in hook_res.get("findings") or []:
                if not isinstance(rf, dict):
                    continue
                sev_raw = str(rf.get("severity") or "MEDIUM").upper()
                sev = sev_raw if sev_raw in SEVERITY_RANK else "MEDIUM"
                out.append(
                    EngineFinding(
                        engine="rea",
                        title=str(rf.get("title") or "REA Surface Finding"),
                        file_path=str(rf.get("file_path") or ""),
                        line=int(rf.get("line_number") or 1),
                        cwe=str(rf.get("cwe") or "CWE-200"),
                        severity=sev,
                        confidence=0.72,
                        summary=str(rf.get("evidence") or ""),
                        rule_id=str(rf.get("rule_id") or "REA-SURFACE"),
                        deterministic=True,
                        confirmed=True,
                        metadata={
                            "rea_mode": str(hook_res.get("mode") or "python_static"),
                            "capability_class": str(rf.get("capability_class") or ""),
                            "route": str(rf.get("route") or ""),
                            "http_method": str(rf.get("http_method") or ""),
                            "source_mode": str(rf.get("source_mode") or "python_static"),
                        },
                    )
                )
            return (
                "rea",
                out,
                {
                    "status": str(hook_res.get("status") or "completed"),
                    "mode": str(hook_res.get("mode") or "python_static"),
                    "findings": len(out),
                    "endpoints": len(hook_res.get("discovered_endpoints") or []),
                    "ai_sinks": len(hook_res.get("ai_sinks") or []),
                    "ipc_channels": len(hook_res.get("ipc_channels") or []),
                    "embedded": bool(embedded),
                    "zero_subprocess": True,
                },
            )

        def _run_trufflehog() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            if not root.is_dir():
                return ("trufflehog", [], {"status": "skipped_non_dir"})
            from engine.trufflehog_scanner import scan_secrets_with_trufflehog

            raw = scan_secrets_with_trufflehog(
                root,
                embedded=embedded,
                no_external_scanners=no_external_scanners,
            )
            out = [_finding_from_dict(item, default_engine="trufflehog") for item in (raw or ())]
            return ("trufflehog", out, {"status": "completed", "findings": len(out)})

        def _run_mobile_mobsf() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            if not root.is_dir():
                return ("mobile_mobsf", [], {"status": "skipped_non_dir"})
            from engine.mobile_app_auditor import audit_mobile_app

            raw = audit_mobile_app(
                root,
                embedded=embedded,
                no_external_scanners=no_external_scanners,
            )
            out = [_finding_from_dict(item, default_engine="mobile_mobsf") for item in (raw or ())]
            return ("mobile_mobsf", out, {"status": "completed", "findings": len(out)})

        def _run_api_jwt_sdjwt() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            if not root.is_dir():
                return ("api_jwt_sdjwt", [], {"status": "skipped_non_dir"})
            from engine.api_jwt_sdjwt_auditor import audit_api_and_jwt

            raw = audit_api_and_jwt(
                root,
                program=program,
                embedded=embedded,
                no_external_scanners=no_external_scanners,
                allow_live=False,
            )
            out = [_finding_from_dict(item, default_engine="api_jwt_sdjwt") for item in (raw or ())]
            return ("api_jwt_sdjwt", out, {"status": "completed", "findings": len(out)})

        def _run_ai_infra_guard() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            if not root.is_dir():
                return ("ai_infra_guard", [], {"status": "skipped_non_dir"})
            from engine.ai_infra_guard_auditor import audit_ai_infra

            raw = audit_ai_infra(root)
            out = [_finding_from_dict(item, default_engine="ai_infra_guard") for item in (raw or ())]
            return ("ai_infra_guard", out, {"status": "completed", "findings": len(out)})

        def _run_parity_auditor() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            if not root.is_dir():
                return ("parity_auditor", [], {"status": "skipped_non_dir"})
            from engine.parity_invariant_auditor import audit_parity_and_invariants

            raw = audit_parity_and_invariants(root)
            out = [_finding_from_dict(item, default_engine="parity_auditor") for item in (raw or ())]
            return ("parity_auditor", out, {"status": "completed", "findings": len(out)})

        def _run_z3_formal() -> Tuple[str, List[EngineFinding], Dict[str, Any]]:
            if not root.is_dir():
                return ("z3_formal", [], {"status": "skipped_non_dir"})
            discovered: Dict[str, List[Path]] = {"openapi": [], "iam": [], "state_machine": []}
            scanned = 0
            for cur_root, dirnames, filenames in os.walk(root):
                dirnames[:] = [
                    d
                    for d in sorted(dirnames)
                    if d not in (".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build")
                ]
                for fn in sorted(filenames):
                    scanned += 1
                    if scanned > 400:
                        break
                    low = fn.lower()
                    if not low.endswith((".json", ".yaml", ".yml")):
                        continue
                    fpath = Path(cur_root) / fn
                    if any(k in low for k in ("openapi", "swagger")) and len(discovered["openapi"]) < 2:
                        discovered["openapi"].append(fpath)
                    elif any(k in low for k in ("iam", "policy")) and len(discovered["iam"]) < 2:
                        discovered["iam"].append(fpath)
                    elif any(k in low for k in ("state_machine", "statemachine", "workflow_sm")) and len(discovered["state_machine"]) < 2:
                        discovered["state_machine"].append(fpath)
                if scanned > 400:
                    break
            if not (discovered["openapi"] or discovered["iam"] or discovered["state_machine"]):
                return ("z3_formal", [], {"status": "skipped_no_specs", "findings": 0})
            from engine.z3_formal_verifier import run_z3_formal_verification

            rep = run_z3_formal_verification(
                openapi_spec=discovered["openapi"][0] if discovered["openapi"] else None,
                iam_policy=discovered["iam"][0] if discovered["iam"] else None,
                state_machine=discovered["state_machine"][0] if discovered["state_machine"] else None,
                target_name=program or root.name,
                offline=True if embedded else None,
                embedded=embedded,
                scope_bridge=None,
                scope_policy=None,
                target_intent=None,
            )
            out = [_finding_from_dict(ef, default_engine="z3_formal") for ef in rep.to_engine_findings(include_proven=False)]
            return (
                "z3_formal",
                out,
                {
                    "status": rep.status,
                    "domains_verified": list(rep.domains_verified),
                    "violations_count": rep.violations_count,
                    "findings": len(out),
                },
            )

        tasks = [_run_zizmor, _run_actionlint, _run_gha_agent_auditor]
        if not gha_only:
            tasks.extend(
                [
                    _run_web_llm_atlas,
                    _run_lean4,
                    _run_semgrep_raptor,
                    _run_rea,
                    _run_trufflehog,
                    _run_mobile_mobsf,
                    _run_api_jwt_sdjwt,
                    _run_ai_infra_guard,
                    _run_parity_auditor,
                    _run_z3_formal,
                ]
            )

        with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as pool:
            futs = [pool.submit(fn) for fn in tasks]
            for fut in futs:
                try:
                    eng_name, eng_findings, info = fut.result()
                    telemetry["engines_executed"].append(eng_name)
                    telemetry[eng_name] = info
                    collected.extend(eng_findings)
                except Exception as exc:
                    telemetry.setdefault("errors", []).append(str(exc))

        if eff_llm_verify:
            from engine.gha_llm_verifier import verify_gha_findings_with_llm

            llm_candidates = [
                f for f in collected if f.engine in ("zizmor", "actionlint", "gha_agent", "rea")
            ]
            llm_findings, llm_tele = verify_gha_findings_with_llm(
                root,
                llm_candidates,
                model=model,
                embedded=embedded,
            )
            telemetry["engines_executed"].append("gha_llm")
            telemetry["gha_llm"] = llm_tele
            collected.extend(llm_findings)
        else:
            telemetry["gha_llm"] = {
                "backend": "disabled",
                "status": "skipped_embedded" if embedded else "skipped_disabled",
            }

        return collected, telemetry

    def _run_whiteboard_worker(
        self,
        hyp: WhiteboardHypothesis,
        *,
        finding: Optional[EngineFinding],
        target_p: Path,
        target_str: str,
        eff_poc_lang: Optional[str],
        eff_poc_cmd: Optional[Union[str, Sequence[str]]],
        oracle: Optional[Any],
        whiteboard: EnsembleWhiteboard,
        round_idx: int,
        worker_idx: int,
    ) -> Dict[str, Any]:
        """Executes a single non-destructive verification worker task."""
        worker_id = f"worker-{round_idx}-{worker_idx}"
        whiteboard.update_status(
            hyp.hypothesis_id,
            "TESTING",
            worker_id=worker_id,
            round_idx=round_idx,
        )

        if hyp.domain == "runtime_poc":
            norm_poc_cmd = _normalize_command_tokens(eff_poc_cmd) or []
            if self.embedded:
                ok_p, msg_p = validate_mount_path(target_p)
                ok_c, msg_c = validate_command_tokens(norm_poc_cmd)
                status = "rejected_unsafe" if (not ok_p or not ok_c) else "skipped_embedded"
                tr = VerifiableTranscript(
                    language=str(eff_poc_lang or "python"),
                    backend="unavailable",
                    status=status,
                    exit_code=None,
                    command=list(norm_poc_cmd),
                    image="",
                    repo_path=target_str,
                    started_at_utc=datetime.now(timezone.utc).isoformat(),
                    elapsed_ms=0.0,
                    remediation_hint=msg_p if not ok_p else (msg_c if not ok_c else "Skipped in embedded=True mode."),
                )
                return {
                    "hypothesis_id": hyp.hypothesis_id,
                    "kind": "runtime_poc",
                    "worker_id": worker_id,
                    "transcript": tr,
                }
            if not target_p.is_dir():
                tr = VerifiableTranscript(
                    language=str(eff_poc_lang or "python"),
                    backend="unavailable",
                    status="unavailable",
                    exit_code=None,
                    command=list(norm_poc_cmd),
                    image="",
                    repo_path=target_str,
                    started_at_utc=datetime.now(timezone.utc).isoformat(),
                    elapsed_ms=0.0,
                    remediation_hint=f"Target directory does not exist: {target_str}",
                )
                return {
                    "hypothesis_id": hyp.hypothesis_id,
                    "kind": "runtime_poc",
                    "worker_id": worker_id,
                    "transcript": tr,
                }
            tr = LinuxPocRunner().run_poc(
                language=str(eff_poc_lang),
                repo_path=target_str,
                cmd=list(norm_poc_cmd),
            )
            return {
                "hypothesis_id": hyp.hypothesis_id,
                "kind": "runtime_poc",
                "worker_id": worker_id,
                "transcript": tr,
            }

        if hyp.domain in ("http_framing", "policy_guard", "dotnet_pe"):
            from engine.lean_formal_verifier import (
                verify_dotnet_pe_invariant,
                verify_http_framing_invariant,
                verify_policy_guard_invariant,
            )

            use_oracle = None if self.embedded else oracle
            worker_lean_dir = (
                Path("__embedded_python_mirror__") if self.embedded else self.lean_dir
            )
            meta = dict(hyp.metadata)
            if finding is not None and isinstance(finding.metadata, dict):
                meta.update(finding.metadata)
            blob = " ".join(
                (
                    str(meta.get("rule_id") or ""),
                    hyp.cwe,
                    hyp.title,
                    str(meta.get("summary") or ""),
                    hyp.file_path,
                )
            ).lower()

            counterexamples = []
            witness_evaluated = False
            invalid_error: Optional[str] = None
            try:
                if hyp.domain == "http_framing":
                    hf_meta = meta.get("http_framing") if isinstance(meta.get("http_framing"), dict) else {}
                    if hf_meta:
                        pv_raw = hf_meta.get("proxy_verdict")
                        pv_val = tuple(pv_raw) if isinstance(pv_raw, (list, tuple)) and len(pv_raw) == 2 else None
                        counterexamples = verify_http_framing_invariant(
                            content_lengths=hf_meta.get("content_lengths", []),
                            has_transfer_encoding_chunked=bool(hf_meta.get("has_transfer_encoding_chunked", False)),
                            has_bare_lf=bool(hf_meta.get("has_bare_lf", False)),
                            proxy_verdict=pv_val,  # type: ignore[arg-type]
                            lean_dir=worker_lean_dir,
                            oracle=use_oracle,
                        )
                        witness_evaluated = True
                    elif "dual content-length" in blob:
                        counterexamples = verify_http_framing_invariant(
                            content_lengths=[10, 20],
                            has_transfer_encoding_chunked=False,
                            lean_dir=worker_lean_dir,
                            oracle=use_oracle,
                        )
                        witness_evaluated = True
                    elif "bare lf" in blob:
                        counterexamples = verify_http_framing_invariant(
                            content_lengths=[],
                            has_transfer_encoding_chunked=False,
                            has_bare_lf=True,
                            lean_dir=worker_lean_dir,
                            oracle=use_oracle,
                        )
                        witness_evaluated = True
                    elif "cwe-444" in hyp.cwe.lower() or any(k in blob for k in ("cl+te", "cl/te", "cl_te", "smuggling")):
                        counterexamples = verify_http_framing_invariant(
                            content_lengths=[42],
                            has_transfer_encoding_chunked=True,
                            lean_dir=worker_lean_dir,
                            oracle=use_oracle,
                        )
                        witness_evaluated = True

                elif hyp.domain == "policy_guard":
                    from engine.lean_formal_verifier import _coerce_strict_bool as _lean_strict_bool

                    pg_meta = meta.get("policy_guard") if isinstance(meta.get("policy_guard"), dict) else {}
                    if pg_meta:
                        counterexamples = verify_policy_guard_invariant(
                            action=str(pg_meta.get("action", "networkProbe")),
                            scope=str(pg_meta.get("scope", "inScopeAuthorized")),
                            in_workspace_root=pg_meta.get("in_workspace_root", True),
                            allow_destructive=pg_meta.get("allow_destructive", False),
                            rules=pg_meta.get("rules", (("permit", True),)),
                            confirmed_by_tool=pg_meta.get("confirmed_by_tool"),
                            llm_confirmed=pg_meta.get("llm_confirmed"),
                            observed_allowed=pg_meta.get("observed_allowed"),
                            observed_reconciled=pg_meta.get("observed_reconciled"),
                            lean_dir=worker_lean_dir,
                            oracle=use_oracle,
                        )
                        witness_evaluated = True
                    elif any(
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
                    ):
                        is_active = (
                            _lean_strict_bool(finding.confirmed, field_name="confirmed")
                            if finding is not None
                            else True
                        )
                        if any(kw in blob for kw in ("llm_dissent", "override_immunity", "deterministic_confirmation")):
                            obs_rec = (
                                _lean_strict_bool(meta["observed_reconciled"], field_name="observed_reconciled")
                                if "observed_reconciled" in meta
                                else (not is_active)
                            )
                            counterexamples = verify_policy_guard_invariant(
                                confirmed_by_tool=True,
                                llm_confirmed=False,
                                observed_reconciled=obs_rec,
                                lean_dir=worker_lean_dir,
                                oracle=use_oracle,
                            )
                        elif "shellexec" in blob or "shell_exec" in blob:
                            counterexamples = verify_policy_guard_invariant(
                                action="shellExec",
                                observed_allowed=meta.get("observed_allowed", is_active),
                                lean_dir=worker_lean_dir,
                                oracle=use_oracle,
                            )
                        elif "out_of_scope" in blob or "out-of-scope" in blob:
                            counterexamples = verify_policy_guard_invariant(
                                action="networkProbe",
                                scope="outOfScope",
                                observed_allowed=meta.get("observed_allowed", is_active),
                                lean_dir=worker_lean_dir,
                                oracle=use_oracle,
                            )
                        elif "outside_workspace" in blob:
                            counterexamples = verify_policy_guard_invariant(
                                action="readWorkspaceFile",
                                in_workspace_root=False,
                                observed_allowed=meta.get("observed_allowed", is_active),
                                lean_dir=worker_lean_dir,
                                oracle=use_oracle,
                            )
                        else:
                            counterexamples = verify_policy_guard_invariant(
                                rules=[("permit", True), ("forbid", True)],
                                observed_allowed=meta.get("observed_allowed", is_active),
                                lean_dir=worker_lean_dir,
                                oracle=use_oracle,
                            )
                        witness_evaluated = True

                elif hyp.domain == "dotnet_pe":
                    pe_rep = meta.get("pe_report") if isinstance(meta.get("pe_report"), dict) else None
                    if pe_rep is None and meta.get("repo_pe_candidate") and target_p.is_dir():
                        try:
                            from engine.pe_magika_classifier import audit_pe_dotnet_target

                            pe_audit = audit_pe_dotnet_target(
                                target_p,
                                include_host_audit=False,
                                include_yara=False,
                                workspace_root=target_p,
                            )
                            for rep in pe_audit.get("file_reports", []) or ():
                                if isinstance(rep, dict) and rep.get("is_pe"):
                                    counterexamples.extend(
                                        verify_dotnet_pe_invariant(
                                            pe_report=rep,
                                            lean_dir=worker_lean_dir,
                                            oracle=use_oracle,
                                        )
                                    )
                            witness_evaluated = bool(counterexamples)
                        except Exception:
                            witness_evaluated = False
                    elif pe_rep is not None:
                        counterexamples = verify_dotnet_pe_invariant(
                            pe_report=pe_rep,
                            lean_dir=worker_lean_dir,
                            oracle=use_oracle,
                        )
                        witness_evaluated = True
                    else:
                        has_anom = (
                            "cve-2026-108398" in blob
                            or bool(meta.get("has_forshaw_cve_2026_108398_anomaly"))
                        )
                        counterexamples = verify_dotnet_pe_invariant(
                            is_valid_pe=True,
                            has_clr_descriptor=True,
                            has_executable_image_bit=not has_anom,
                            is_umci_enforced=True,
                            is_signed_by_trusted_publisher=False,
                            lean_dir=worker_lean_dir,
                            oracle=use_oracle,
                        )
                        witness_evaluated = True
            except (ValueError, TypeError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
                invalid_error = str(exc)
                counterexamples = []
                witness_evaluated = False

            symbolic_trace: Optional[Dict[str, Any]] = None
            if hyp.domain == "dotnet_pe" and not self.embedded and target_p.is_dir() and hyp.file_path:
                cand_path = target_p / hyp.file_path
                if cand_path.is_file():
                    symbolic_trace = run_symbolic_hook("angr", cand_path)

            return {
                "hypothesis_id": hyp.hypothesis_id,
                "kind": "lean_domain",
                "worker_id": worker_id,
                "counterexamples": counterexamples,
                "witness_evaluated": witness_evaluated,
                "invalid_error": invalid_error,
                "symbolic_trace": symbolic_trace,
            }

        if hyp.domain == "symbolic" or hyp.metadata.get("symbolic_backend"):
            sym_backend = str(hyp.metadata.get("symbolic_backend") or "angr")
            sym_target = target_p / hyp.file_path if (hyp.file_path and target_p.is_dir()) else target_p
            if self.embedded:
                sym_res = {
                    "backend": sym_backend,
                    "target_path": str(sym_target),
                    "available": False,
                    "status": "skipped_embedded",
                    "verified": False,
                    "findings": [],
                    "remediation_hint": "Skipped symbolic hook in embedded=True mode.",
                }
            else:
                sym_args = hyp.metadata.get("symbolic_args")
                sym_res = run_symbolic_hook(
                    sym_backend,
                    sym_target,
                    args=sym_args if isinstance(sym_args, (list, tuple)) else None,
                )
            return {
                "hypothesis_id": hyp.hypothesis_id,
                "kind": "symbolic",
                "worker_id": worker_id,
                "symbolic_result": sym_res,
            }

        # General / GHA / AI security hypothesis: evaluate vendor threat-model gate only (no fabrication)
        tm = evaluate_vendor_threat_model(
            title=hyp.title,
            summary=str(hyp.metadata.get("summary") or hyp.title),
            file_path=hyp.file_path,
            program=self.program,
            poc_verified=False,
        )
        return {
            "hypothesis_id": hyp.hypothesis_id,
            "kind": "static_triage",
            "worker_id": worker_id,
            "threat_model": tm.to_dict(),
            "confirmed": bool(finding.confirmed) if finding is not None else False,
        }

    def run(
        self,
        target: Union[str, Path],
        findings: Optional[Sequence[EngineFinding]] = None,
        *,
        poc_transcripts: Optional[Dict[str, VerifiableTranscript]] = None,
        poc_lang: Optional[str] = None,
        poc_cmd: Optional[Union[str, Sequence[str]]] = None,
        poc_language: Optional[str] = None,
        poc_command: Optional[Union[str, Sequence[str]]] = None,
        all_scan_summary: Optional[Dict[str, Any]] = None,
        out_dir: Optional[Union[str, Path]] = None,
        package_client_name: Optional[str] = None,
        refresh_stix: bool = True,
    ) -> EnsembleReport:
        if all_scan_summary is not None and not isinstance(all_scan_summary, Mapping):
            raise TypeError(
                f"all_scan_summary must be a Mapping or None, got {type(all_scan_summary).__name__}"
            )
        target_str = str(target)
        target_p = Path(target_str)
        eff_poc_lang = poc_language if poc_language is not None else poc_lang
        eff_poc_cmd = _normalize_command_tokens(
            poc_command if poc_command is not None else poc_cmd
        )

        if self.embedded:
            freshness = RepoFreshnessSnapshot(
                repo_path=target_str,
                is_git_repo=False,
                freshness_hours_window=self.freshness_hours,
                freshness_status="EMBEDDED_OFFLINE",
            )
        else:
            freshness = inspect_repo_freshness(target_str, freshness_hours=self.freshness_hours)

        active_findings: List[EngineFinding] = list(findings) if findings is not None else []
        is_workflow_file = target_p.is_file() and target_p.suffix.lower() in (".yml", ".yaml")
        if findings is None and self.exhaustive_default and (target_p.is_dir() or is_workflow_file):
            auto_findings, tele = self.run_exhaustive_local_engines(
                target_str,
                refresh_stix=(False if self.embedded else refresh_stix),
                embedded=self.embedded,
                model=self.model,
                enable_llm_verify=self.enable_llm_verify,
                gha_only=self.gha_only or is_workflow_file,
                no_external_scanners=self.no_external_scanners,
                lean_dir=self.lean_dir,
                program=self.program,
            )
            self.last_telemetry = tele
            active_findings.extend(auto_findings)
        elif not isinstance(self.last_telemetry, dict):
            self.last_telemetry = {}

        if self.embedded:
            toolchain_status = _embedded_toolchain_status()
        else:
            toolchain_status = probe_optional_backends(lean_dir=self.lean_dir, timeout_sec=2.5)

        whiteboard = EnsembleWhiteboard(
            db=self.db,
            enabled=self.enable_whiteboard,
            proxy=self.proxy,
        )
        whiteboard.set_backend_status(toolchain_status)
        if self.proxy:
            whiteboard.add_fact(
                "proxy_config",
                f"Defensive inspection proxy configured: {self.proxy}",
                payload={"proxy": self.proxy},
                source="orchestrator",
            )
        if all_scan_summary is not None:
            whiteboard.add_fact(
                "all_scan_summary",
                "Ingested upstream --all scan summary",
                payload=dict(all_scan_summary),
                source="planner",
            )

        # Planner: seed WhiteboardHypothesis objects from active findings (+ optional PoC/PE tasks)
        finding_by_hid: Dict[str, EngineFinding] = {}
        for idx, f in enumerate(active_findings, start=1):
            hid = f"HYP-{idx:03d}"
            dom = _classify_finding_domain(f)
            hyp = WhiteboardHypothesis(
                hypothesis_id=hid,
                title=f.title,
                domain=dom,
                file_path=f.file_path,
                line=int(f.line or 0),
                cwe=f.cwe,
                severity=f.severity,
                confidence=float(f.confidence),
                status="OPEN",
                source_engine=f.engine,
                metadata={
                    "rule_id": f.rule_id,
                    "summary": f.summary,
                    "confirmed": f.confirmed,
                    **(f.metadata if isinstance(f.metadata, dict) else {}),
                },
            )
            whiteboard.add_hypothesis(hyp)
            finding_by_hid[hid] = f

        # Bounded PE candidate discovery when target repo has .exe/.dll and no PE finding seeded yet
        if target_p.is_dir() and not any(_classify_finding_domain(f) == "dotnet_pe" for f in active_findings):
            from engine.lean_formal_verifier import _find_pe_candidates_bounded

            pe_cands = _find_pe_candidates_bounded(target_p)
            if pe_cands:
                try:
                    rel_pe = pe_cands[0].relative_to(target_p).as_posix()
                except ValueError:
                    rel_pe = str(pe_cands[0])
                hid = f"HYP-PE-{len(finding_by_hid) + 1:03d}"
                whiteboard.add_hypothesis(
                    WhiteboardHypothesis(
                        hypothesis_id=hid,
                        title=f".NET PE UMCI header integrity verification ({rel_pe})",
                        domain="dotnet_pe",
                        file_path=rel_pe,
                        line=1,
                        cwe="CWE-347",
                        severity="MEDIUM",
                        confidence=0.7,
                        status="OPEN",
                        source_engine="planner",
                        metadata={"repo_pe_candidate": True},
                    )
                )

        if eff_poc_lang and eff_poc_cmd:
            poc_hid = f"HYP-POC-{len(finding_by_hid) + 1:03d}"
            whiteboard.add_hypothesis(
                WhiteboardHypothesis(
                    hypothesis_id=poc_hid,
                    title=f"Sandboxed non-destructive PoC verification ({eff_poc_lang})",
                    domain="runtime_poc",
                    file_path=target_str,
                    line=0,
                    cwe="",
                    severity="INFO",
                    confidence=0.5,
                    status="OPEN",
                    source_engine="linux_poc",
                    metadata={"poc_language": eff_poc_lang, "poc_command": list(eff_poc_cmd)},
                )
            )

        transcripts: Dict[str, VerifiableTranscript] = dict(poc_transcripts or {})

        # Resolve Lean compiled oracle at most once per run when not embedded
        resolved_oracle: Optional[Any] = None
        if not self.embedded and toolchain_status.get("rfchunt_lean_oracle", {}).get("available"):
            try:
                from engine.lean_formal_verifier import _resolve_oracle

                resolved_oracle, _ = _resolve_oracle(self.lean_dir, None)
            except Exception:
                resolved_oracle = None

        # Planner-Worker-Verifier Loop
        if self.enable_whiteboard and self.max_whiteboard_rounds > 0:
            for round_idx in range(1, self.max_whiteboard_rounds + 1):
                open_hyps = whiteboard.list_hypotheses(status="OPEN")
                if not open_hyps:
                    break
                for h in open_hyps:
                    whiteboard.update_status(h.hypothesis_id, "DISPATCHED", round_idx=round_idx)

                results: List[Dict[str, Any]] = []
                with ThreadPoolExecutor(max_workers=min(self.max_workers, len(open_hyps))) as pool:
                    futs = [
                        pool.submit(
                            self._run_whiteboard_worker,
                            h,
                            finding=finding_by_hid.get(h.hypothesis_id),
                            target_p=target_p,
                            target_str=target_str,
                            eff_poc_lang=eff_poc_lang,
                            eff_poc_cmd=eff_poc_cmd,
                            oracle=resolved_oracle,
                            whiteboard=whiteboard,
                            round_idx=round_idx,
                            worker_idx=w_idx,
                        )
                        for w_idx, h in enumerate(open_hyps, start=1)
                    ]
                    for fut in futs:
                        results.append(fut.result())

                updated_cnt = 0
                for res in results:
                    hid = res["hypothesis_id"]
                    hyp_obj = whiteboard.get_hypothesis(hid)
                    if hyp_obj is None:
                        continue
                    w_id = res.get("worker_id", "worker")
                    kind = res.get("kind")

                    if kind == "runtime_poc":
                        tr: VerifiableTranscript = res["transcript"]
                        if "*" not in transcripts and tr.verified:
                            transcripts["*"] = tr
                        elif "*" not in transcripts:
                            transcripts["*"] = tr
                        if tr.verified:
                            whiteboard.update_status(
                                hid,
                                "VERIFIED",
                                worker_id=w_id,
                                round_idx=round_idx,
                                confidence=0.95,
                                evidence=tr.to_dict(),
                                worker_trace=tr.to_dict(),
                            )
                        elif tr.status in ("unavailable", "rejected_unsafe", "timeout", "skipped_embedded"):
                            whiteboard.update_status(
                                hid,
                                "UNVERIFIED_UNAVAILABLE",
                                worker_id=w_id,
                                round_idx=round_idx,
                                evidence=tr.to_dict(),
                                worker_trace=tr.to_dict(),
                                notes=tr.remediation_hint,
                            )
                        else:
                            whiteboard.update_status(
                                hid,
                                "REFUTED",
                                worker_id=w_id,
                                round_idx=round_idx,
                                evidence=tr.to_dict(),
                                worker_trace=tr.to_dict(),
                            )
                        updated_cnt += 1

                    elif kind == "lean_domain":
                        ces = res.get("counterexamples") or []
                        violated = [c for c in ces if getattr(c, "violated", False)]
                        ce_dicts = [c.to_dict() for c in ces]
                        violated_dicts = [c.to_dict() for c in violated]
                        sym_trace = res.get("symbolic_trace")
                        if violated_dicts:
                            ev_payload: Dict[str, Any] = {
                                "domain": hyp_obj.domain,
                                "violations_count": len(violated_dicts),
                                "theorems": [v["theorem"] for v in violated_dicts],
                            }
                            if sym_trace is not None:
                                ev_payload["symbolic_probe"] = sym_trace
                            whiteboard.update_status(
                                hid,
                                "COUNTEREXAMPLE_FOUND",
                                worker_id=w_id,
                                round_idx=round_idx,
                                confidence=0.95,
                                severity="CRITICAL" if hyp_obj.severity == "CRITICAL" else "HIGH",
                                evidence=ev_payload,
                                counterexamples=violated_dicts,
                                verifier_output={"counterexamples": ce_dicts},
                                worker_trace=sym_trace,
                            )
                            cwe_fallback = (
                                "CWE-444"
                                if hyp_obj.domain == "http_framing"
                                else ("CWE-347" if hyp_obj.domain == "dotnet_pe" else "CWE-862")
                            )
                            orig_finding = finding_by_hid.get(hid)
                            lean_cwe = hyp_obj.cwe or cwe_fallback
                            lean_meta: Dict[str, Any] = {"lean_counterexamples": violated_dicts}
                            if orig_finding is not None:
                                orig_meta = orig_finding.metadata if isinstance(orig_finding.metadata, dict) else {}
                                gha_cls = str(orig_meta.get("gha_class") or "").strip()
                                if gha_cls:
                                    lean_meta["gha_class"] = gha_cls
                                orig_fam = EnsembleConsensusVoter._cluster_family(orig_finding)
                                if orig_fam == "GENERIC":
                                    orig_finding.cwe = cwe_fallback
                                    lean_cwe = cwe_fallback
                                elif not (orig_finding.cwe or "").strip():
                                    if orig_fam.startswith("CWE-"):
                                        lean_cwe = orig_fam
                                    elif gha_cls:
                                        lean_cwe = hyp_obj.cwe or cwe_fallback
                                    else:
                                        lean_cwe = orig_fam
                            _append_unique_lean_finding(
                                active_findings,
                                EngineFinding(
                                    engine="lean4",
                                    title=f"Lean 4 {hyp_obj.domain} counterexample: {violated_dicts[0]['theorem']}",
                                    file_path=hyp_obj.file_path,
                                    line=hyp_obj.line or 1,
                                    cwe=lean_cwe,
                                    severity="CRITICAL" if hyp_obj.severity == "CRITICAL" else "HIGH",
                                    confidence=0.95,
                                    summary=violated_dicts[0].get("summary", ""),
                                    rule_id=f"LEAN-{hyp_obj.domain.upper()}-{violated_dicts[0]['theorem']}",
                                    deterministic=True,
                                    confirmed=True,
                                    metadata=lean_meta,
                                ),
                            )
                        elif res.get("witness_evaluated"):
                            ev_pass: Dict[str, Any] = {
                                "domain": hyp_obj.domain,
                                "reason": "Lean 4 invariant checks passed with zero violations.",
                            }
                            if sym_trace is not None:
                                ev_pass["symbolic_probe"] = sym_trace
                            whiteboard.update_status(
                                hid,
                                "REFUTED",
                                worker_id=w_id,
                                round_idx=round_idx,
                                evidence=ev_pass,
                                verifier_output={"counterexamples": ce_dicts},
                                worker_trace=sym_trace,
                            )
                        else:
                            whiteboard.update_status(
                                hid,
                                "UNVERIFIED_UNAVAILABLE",
                                worker_id=w_id,
                                round_idx=round_idx,
                                evidence={
                                    "domain": hyp_obj.domain,
                                    "reason": res.get("invalid_error") or "No formal counterexample witness available.",
                                },
                                worker_trace=sym_trace,
                            )
                        updated_cnt += 1

                    elif kind == "symbolic":
                        sym_res = res.get("symbolic_result") or {}
                        if sym_res.get("verified") and sym_res.get("findings"):
                            whiteboard.update_status(
                                hid,
                                "VERIFIED",
                                worker_id=w_id,
                                round_idx=round_idx,
                                evidence=sym_res,
                                worker_trace=sym_res,
                            )
                        elif sym_res.get("status") in ("unavailable", "rejected_unsafe", "unsupported_backend", "skipped_embedded", "timeout"):
                            whiteboard.update_status(
                                hid,
                                "UNVERIFIED_UNAVAILABLE",
                                worker_id=w_id,
                                round_idx=round_idx,
                                evidence=sym_res,
                                worker_trace=sym_res,
                                notes=str(sym_res.get("remediation_hint") or ""),
                            )
                        else:
                            whiteboard.update_status(
                                hid,
                                "REFUTED",
                                worker_id=w_id,
                                round_idx=round_idx,
                                evidence=sym_res,
                                worker_trace=sym_res,
                            )
                        updated_cnt += 1

                    else:
                        tm_dict = res.get("threat_model") or {}
                        if not tm_dict.get("passed", True) or not res.get("confirmed", True):
                            whiteboard.update_status(
                                hid,
                                "REFUTED",
                                worker_id=w_id,
                                round_idx=round_idx,
                                evidence={"threat_model": tm_dict},
                            )
                        else:
                            whiteboard.update_status(
                                hid,
                                "UNVERIFIED_UNAVAILABLE",
                                worker_id=w_id,
                                round_idx=round_idx,
                                evidence={"threat_model": tm_dict, "reason": "Static finding awaits runtime PoC."},
                            )
                        updated_cnt += 1

                whiteboard.record_round(
                    round_idx,
                    dispatched=len(open_hyps),
                    updated=updated_cnt,
                )
        elif eff_poc_lang and eff_poc_cmd and target_p.is_dir() and not self.embedded and "*" not in transcripts:
            runner = LinuxPocRunner()
            transcripts["*"] = runner.run_poc(
                language=eff_poc_lang,
                repo_path=target_str,
                cmd=list(eff_poc_cmd),
            )

        # Authoritative Lean 4 domain & workspace report
        if self.embedded:
            lean_dict = _evaluate_lean_domains_embedded(
                active_findings,
                repo_path=target_p if target_p.is_dir() else None,
                lean_dir=self.lean_dir,
            )
        else:
            from engine.lean_formal_verifier import LeanDomainReport, evaluate_lean_domains

            try:
                dom_rep = evaluate_lean_domains(
                    findings=active_findings,
                    repo_path=target_p if target_p.is_dir() else None,
                    lean_dir=self.lean_dir,
                )
                lean_dict = dom_rep.to_dict()
                ws_rep = lean_dict.get("workspace_report") or {}
                if ws_rep.get("status") in ("proof_integrity_violation", "kernel_failed"):
                    for d in lean_dict.get("diagnostics") or []:
                        _append_unique_lean_finding(
                            active_findings,
                            EngineFinding(
                                engine="lean4",
                                title=f"Lean 4 proof diagnostic ({d.get('kind')}): {d.get('theorem')}",
                                file_path=f"formal/lean4/RFCHunt/{d.get('module', 'Unknown')}.lean",
                                line=int(d.get("line") or 1),
                                cwe="CWE-693",
                                severity="HIGH",
                                confidence=0.95,
                                summary=str(d.get("branch_summary") or d.get("raw_excerpt") or ws_rep.get("status")),
                                rule_id=f"LEAN-{str(d.get('kind') or 'DIAG').upper()}",
                                deterministic=True,
                                confirmed=True,
                                metadata={"lean_diagnostic": d},
                            ),
                        )
            except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as exc:
                fallback_exc_obj: Optional[Exception] = None
                try:
                    lean_dict = _evaluate_lean_domains_embedded(
                        active_findings,
                        repo_path=target_p if target_p.is_dir() else None,
                        lean_dir=self.lean_dir,
                    )
                except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as fallback_exc:
                    fallback_exc_obj = fallback_exc
                    lean_dict = LeanDomainReport(
                        status="unavailable",
                        oracle_backend="unavailable",
                        machine_checked=False,
                        workspace_report={
                            "lean_dir": str(self.lean_dir),
                            "lean_binary": None,
                            "lake_binary": None,
                            "machine_checked": False,
                            "status": "oracle_error_degraded",
                            "modules": [],
                            "total_theorems": 0,
                            "stdout": "",
                            "stderr": str(fallback_exc),
                            "elapsed_ms": 0.0,
                            "diagnostics": [],
                        },
                        domain_checks={},
                        counterexamples=[],
                        diagnostics=[],
                        domains_checked=["http_framing", "policy_guard", "dotnet_pe"],
                        checks_total=0,
                        violations_count=0,
                        degradation_reason=(
                            f"Lean 4 oracle failed ({exc}); fallback mirror unavailable ({fallback_exc})."
                        ),
                    ).to_dict()
                lean_dict["machine_checked"] = False
                if fallback_exc_obj is not None:
                    lean_dict["degradation_reason"] = (
                        f"Lean 4 oracle failed ({exc}); fallback mirror unavailable ({fallback_exc_obj}) "
                        "(machine_checked=False)."
                    )
                else:
                    lean_dict["degradation_reason"] = (
                        f"Compiled Lean 4 oracle failed ({exc}); degraded cleanly to fallback "
                        "(machine_checked=False)."
                    )
                if isinstance(lean_dict.get("workspace_report"), dict):
                    lean_dict["workspace_report"]["machine_checked"] = False
                whiteboard.add_fact(
                    "lean_oracle_error",
                    f"Lean 4 oracle degraded cleanly after error: {exc}",
                    payload={"error": str(exc), "fallback": lean_dict.get("oracle_backend", "python_mirror")},
                    source="verifier",
                )

        voter = EnsembleConsensusVoter(program=self.program, quorum=self.quorum)
        clusters = voter.fuse(active_findings, freshness=freshness, poc_transcripts=transcripts)

        # Attach cluster-level Lean diagnostics, counterexamples, and whiteboard IDs
        violated_ces = list(lean_dict.get("violations") or [])
        all_diags = list(lean_dict.get("diagnostics") or [])
        wb_hyps = whiteboard.list_hypotheses()
        clusters_by_file: Dict[str, List[EnsembleCluster]] = {}
        for cl in clusters:
            clusters_by_file.setdefault(_norm_path(cl.file_path), []).append(cl)

        for c in clusters:
            c_diags: List[Dict[str, Any]] = []
            c_ces: List[Dict[str, Any]] = []
            for mf in c.member_findings:
                meta = mf.get("metadata") if isinstance(mf, dict) else None
                if isinstance(meta, dict):
                    if isinstance(meta.get("lean_counterexamples"), list):
                        c_ces.extend(meta["lean_counterexamples"])
                    if isinstance(meta.get("lean_diagnostics"), list):
                        c_diags.extend(meta["lean_diagnostics"])
                    elif isinstance(meta.get("lean_diagnostic"), dict):
                        c_diags.append(meta["lean_diagnostic"])
            if c.lean_verified and not c_ces and violated_ces:
                # Match violated counterexamples by domain inferred from cluster CWE/file
                c_fam = (c.cwe_family or "").upper()
                for vce in violated_ces:
                    dom = vce.get("domain", "")
                    if (
                        (dom == "http_framing" and c_fam == "CWE-444")
                        or (dom == "dotnet_pe" and c_fam in ("CWE-347", "PE-DOTNET"))
                        or (dom == "policy_guard" and c_fam in ("CWE-862", "CWE-284", "CWE-693"))
                    ):
                        c_ces.append(vce)
            if c.file_path.startswith("formal/lean4/") and all_diags and not c_diags:
                c_diags.extend(all_diags)
            c.counterexamples = _dedup_lean_counterexamples(c_ces)
            c.lean_diagnostics = _dedup_lean_diagnostics(c_diags, include_branch_summary=False)
            c_norm = _norm_path(c.file_path)
            same_file_clusters = clusters_by_file.get(c_norm, [])
            if len(same_file_clusters) <= 1:
                c.whiteboard_hypothesis_ids = [
                    h.hypothesis_id
                    for h in wb_hyps
                    if _norm_path(h.file_path) == c_norm
                ]
            else:
                matched_hids: List[str] = []
                for h in wb_hyps:
                    if _norm_path(h.file_path) != c_norm:
                        continue
                    h_gha = str((h.metadata or {}).get("gha_class") or "").strip()
                    h_fam = _norm_cwe_family(h.cwe, h.title)
                    if h_fam == "GENERIC":
                        if h.domain == "http_framing":
                            h_fam = "CWE-444"
                        elif h.domain == "dotnet_pe":
                            h_fam = "CWE-347"
                        elif h.domain == "policy_guard":
                            h_fam = "CWE-862"
                    fam_match: Optional[bool]
                    if c.gha_class and h_gha:
                        fam_match = (c.gha_class == h_gha)
                    elif c.cwe_family != "GENERIC" and h_fam != "GENERIC":
                        fam_match = (c.cwe_family == h_fam)
                    else:
                        fam_match = None
                    if fam_match is False:
                        continue
                    line_dist = abs(int(h.line or 0) - int(c.line or 0))
                    if line_dist <= 15:
                        matched_hids.append(h.hypothesis_id)
                    elif fam_match is True and not any(
                        abs(int(h.line or 0) - int(other.line or 0)) <= 15
                        for other in same_file_clusters
                        if other is not c
                    ):
                        matched_hids.append(h.hypothesis_id)
                c.whiteboard_hypothesis_ids = matched_hids

        counts: Dict[str, int] = {}
        for c in clusters:
            counts[c.disposition] = counts.get(c.disposition, 0) + 1

        wb_snapshot = whiteboard.to_dict()
        self.last_telemetry.update(
            {
                "embedded": self.embedded,
                "proxy": self.proxy,
                "whiteboard": wb_snapshot,
                "lean_verification": lean_dict,
                "toolchain_status": toolchain_status,
            }
        )

        report = EnsembleReport(
            target=target_str,
            program=self.program,
            quorum=self.quorum,
            freshness=freshness,
            clusters=clusters,
            counts_by_disposition=counts,
            whiteboard=wb_snapshot,
            lean_verification=lean_dict,
            toolchain_status=toolchain_status,
            proxy=self.proxy,
            all_scan_summary=all_scan_summary,
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
        from engine.advisory_exporter import _redact_inline_tokens

        def _redact_payload(obj: Any) -> Any:
            if isinstance(obj, str):
                return _redact_inline_tokens(obj)
            if isinstance(obj, dict):
                return {k: _redact_payload(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_redact_payload(v) for v in obj]
            if isinstance(obj, tuple):
                return tuple(_redact_payload(v) for v in obj)
            return obj

        dest = Path(out_dir)
        dest.mkdir(parents=True, exist_ok=True)

        json_path = dest / "ensemble_report.json"
        md_path = dest / "ensemble_summary.md"
        sarif_path = dest / "ensemble_findings.sarif"

        redacted_report = _redact_payload(report.to_dict())
        redacted_sarif = _redact_payload(report.to_sarif())
        redacted_md = _redact_inline_tokens(render_ensemble_markdown(report))

        json_path.write_text(json.dumps(redacted_report, indent=2), encoding="utf-8")
        sarif_path.write_text(json.dumps(redacted_sarif, indent=2), encoding="utf-8")
        md_path.write_text(redacted_md, encoding="utf-8")

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
                    "title": _redact_inline_tokens(c.title),
                    "severity": c.severity,
                    "cwe": c.cwe_family,
                    "file": c.file_path,
                    "line": c.line,
                    "description": _redact_inline_tokens(c.summary or f"[{c.disposition}] {c.title}"),
                    "remediation": (
                        "Verify runtime PoC and apply defense-in-depth fix."
                        if c.disposition != "HELD_OUT_OF_THREAT_MODEL"
                        else _redact_inline_tokens("; ".join(c.threat_model.reasons))
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

    def run_fast_parallel_ooda(
        self,
        repo_path: Union[Path, str],
        *,
        program: str = "",
        blackboard_db: Union[Path, str] = "reports/ensemble_hunt/blackboard.sqlite3",
        max_cpu_workers: Optional[int] = None,
        resume: bool = False,
        signal_score: float = 0.0,
        eligibility_db: Optional[Any] = None,
        poc_runner: Optional[LinuxPocRunner] = None,
        out_dir: Optional[Union[Path, str]] = None,
        trigger_browser: bool = False,
    ) -> Dict[str, Any]:
        """
        Loop 3 Strict 3-Stage Parallel OODA Funnel:
          - Stage 1 (`ProcessPoolExecutor`, 0 LLM): deterministic CPU checks & noise drop
          - Stage 2 (ACDSO `pareto.py` + `anomaly.py`, <1s): top 3-5 production anomalies
          - Stage 3 (single-slot `OllamaConcurrencyGuard`): LLM verification on top 3-5 only
        """
        from engine.acdso_bridge import rank_stage2_candidates
        from engine.async_blackboard_runtime import default_cpu_workers, run_local_rfchunt_async
        from engine.ollama_concurrency_guard import get_shared_ollama_guard

        t0 = time.monotonic()
        repo_p = Path(repo_path)
        eff_program = (program or self.program or "generic").strip().lower()
        eff_workers = default_cpu_workers(max_cpu_workers)

        bb_str = str(blackboard_db)
        if bb_str != ":memory:":
            Path(bb_str).parent.mkdir(parents=True, exist_ok=True)

        seed_intents: Optional[List[Dict[str, Any]]] = None
        if not resume:
            run_nonce = f"{time.time_ns()}"
            discovered_specs: Dict[str, List[Path]] = {"openapi": [], "iam": [], "state_machine": []}
            if repo_p.is_dir():
                try:
                    from engine.async_blackboard_runtime import _discover_formal_spec_files

                    discovered_specs = _discover_formal_spec_files(repo_p, max_files=2)
                except Exception:
                    pass
            seed_intents = [
                {
                    "intent_type": "stage1_cpu",
                    "payload": {
                        "repo_path": str(repo_p),
                        "program": eff_program,
                        "embedded": self.embedded,
                        "no_external_scanners": self.no_external_scanners,
                        "cpu_work_iters": 0,
                        "propagate_siblings": True,
                    },
                    "program": eff_program,
                    "lane": 2,
                    "priority": 0.9,
                    "dedup_key": f"fast_ooda:{run_nonce}:stage1",
                }
            ]
            if eff_workers >= 2:
                has_specs = bool(
                    discovered_specs.get("openapi")
                    or discovered_specs.get("iam")
                    or discovered_specs.get("state_machine")
                )
                formal_payload: Dict[str, Any] = {
                    "repo_path": str(repo_p),
                    "target_name": eff_program or repo_p.name,
                    "cpu_work_iters": 0 if has_specs else 6_000,
                }
                if discovered_specs.get("openapi"):
                    formal_payload["openapi_spec"] = str(discovered_specs["openapi"][0])
                if discovered_specs.get("iam"):
                    formal_payload["iam_policy"] = str(discovered_specs["iam"][0])
                if discovered_specs.get("state_machine"):
                    formal_payload["state_machine"] = str(discovered_specs["state_machine"][0])
                seed_intents.append(
                    {
                        "intent_type": "formal_check",
                        "payload": formal_payload,
                        "program": eff_program,
                        "lane": 2,
                        "priority": 0.85,
                        "dedup_key": f"fast_ooda:{run_nonce}:formal",
                    }
                )

        elig_db_path = getattr(eligibility_db, "db_path", None) if eligibility_db is not None else None

        def _run_async() -> Dict[str, Any]:
            coro = run_local_rfchunt_async(
                seed_intents,
                repo_path=repo_p,
                db_path=bb_str,
                max_cpu_workers=eff_workers,
                resume=bool(resume),
                signal_score=float(signal_score),
                eligibility_db_path=elig_db_path,
                ollama_evaluator=None,
            )
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(coro)
            with ThreadPoolExecutor(max_workers=1) as _loop_pool:
                return _loop_pool.submit(asyncio.run, coro).result()

        async_res = _run_async()
        all_facts = list(async_res.get("facts") or [])

        try:
            from engine.parity_invariant_auditor import is_non_production_noise as _is_noise_fn
        except Exception:
            _is_noise_fn = None

        deduped_prod: List[Dict[str, Any]] = []
        seen_prod_keys: Set[Tuple[str, str, str, int]] = set()
        extra_noise = 0
        for fact in all_facts:
            if not isinstance(fact, dict):
                continue
            payload = fact.get("payload") if isinstance(fact.get("payload"), dict) else {}
            if payload and (payload.get("engine") or payload.get("rule_id") or payload.get("title")):
                cand = dict(payload)
                cand["poc_verified"] = _coerce_strict_bool(cand.get("poc_verified", False))
            else:
                cand = {
                    "engine": fact.get("source_engine") or fact.get("domain") or "stage1",
                    "rule_id": "",
                    "title": fact.get("title") or "Stage 1 finding",
                    "file_path": fact.get("file_path") or "",
                    "line": int(fact.get("line") or 0),
                    "severity": fact.get("severity") or "MEDIUM",
                    "confidence": float(fact.get("confidence") or 0.7),
                    "poc_verified": _coerce_strict_bool(fact.get("poc_verified", False)),
                    "deterministic": True,
                    "confirmed": True,
                    "metadata": {},
                }
            meta = cand.get("metadata") if isinstance(cand.get("metadata"), dict) else {}
            fp_raw = str(cand.get("file_path") or fact.get("file_path") or "")
            rid_raw = str(cand.get("rule_id") or "")
            sum_raw = str(cand.get("summary") or "")
            is_noise = bool(cand.get("non_production_noise", False)) or bool(meta.get("non_production_noise", False))
            if not is_noise and _is_noise_fn is not None:
                is_noise = bool(_is_noise_fn(fp_raw, meta, rule_id=rid_raw, summary=sum_raw))
            if is_noise and not _coerce_strict_bool(cand.get("poc_verified", False)) and str(cand.get("engine") or "").lower() != "lean4":
                extra_noise += 1
                continue
            dedup_key = (
                str(cand.get("engine") or "").strip().lower(),
                rid_raw.strip(),
                _norm_path(fp_raw),
                int(cand.get("line") or 0),
            )
            if dedup_key in seen_prod_keys:
                continue
            seen_prod_keys.add(dedup_key)
            deduped_prod.append(cand)

        async_stage2 = async_res.get("stage2") if isinstance(async_res.get("stage2"), dict) else None
        if (
            async_stage2 is not None
            and not resume
            and extra_noise == 0
            and len(deduped_prod) == int(async_res.get("stage1_production_count", -1) or 0)
            and bool(async_stage2.get("selected"))
        ):
            stage2_res = async_stage2
        else:
            stage2_res = rank_stage2_candidates(deduped_prod, top_k=5)
        stage2_selected = list(stage2_res.get("selected") or [])

        stage3_findings: List[EngineFinding] = []
        stage3_results: List[Dict[str, Any]] = []
        stage3_telemetry: Dict[str, Any] = {
            "status": "skipped",
            "candidates_evaluated": 0,
            "findings_emitted": 0,
            "results": [],
        }

        if not self.embedded and self.enable_llm_verify and stage2_selected:
            from engine.gha_llm_verifier import verify_gha_findings_with_llm

            guard = get_shared_ollama_guard()
            _reset_guard_on_endpoint_change(guard)
            active_model = self.model
            for cand in stage2_selected[:5]:
                cand_label = str(cand.get("id") or cand.get("rule_id") or cand.get("file_path") or "candidate")
                if guard.is_circuit_open():
                    stage3_results.append(
                        {
                            "candidate": cand_label,
                            "status": "skipped_circuit_open",
                            "findings": 0,
                        }
                    )
                    continue
                cand_ef = _finding_from_dict(cand, default_engine=str(cand.get("engine") or "stage1"))
                llm_f, llm_tele = verify_gha_findings_with_llm(
                    repo_p,
                    [cand_ef],
                    model=active_model,
                    embedded=False,
                    force_ollama=True,
                    guard=guard,
                )
                if (
                    llm_tele.get("status") == "completed"
                    and llm_tele.get("downshifted_from")
                    and llm_tele.get("model")
                ):
                    active_model = str(llm_tele["model"])
                stage3_findings.extend(llm_f)
                stage3_results.append(
                    {
                        "candidate": cand_label,
                        "status": llm_tele.get("status"),
                        "model": llm_tele.get("model"),
                        "findings": len(llm_f),
                        "telemetry": llm_tele,
                    }
                )
            stage3_telemetry = {
                "status": "completed",
                "candidates_evaluated": len(stage3_results),
                "findings_emitted": len(stage3_findings),
                "results": stage3_results,
            }
        else:
            stage3_telemetry["status"] = (
                "skipped_embedded"
                if self.embedded
                else ("skipped_no_candidates" if not stage2_selected else "skipped_disabled")
            )

        if self.embedded:
            freshness = RepoFreshnessSnapshot(
                repo_path=str(repo_p),
                is_git_repo=False,
                freshness_hours_window=self.freshness_hours,
                freshness_status="EMBEDDED_OFFLINE",
            )
        else:
            freshness = inspect_repo_freshness(repo_p, freshness_hours=self.freshness_hours)

        stage1_efs = [_finding_from_dict(d) for d in deduped_prod]
        all_efs = stage1_efs + stage3_findings
        poc_transcripts_map: Dict[str, VerifiableTranscript] = {}
        if poc_runner is not None:
            for cand in stage2_selected[:5]:
                cand_meta = cand.get("metadata") if isinstance(cand.get("metadata"), dict) else {}
                cand_file = str(cand.get("file_path") or "")
                sandbox_url = str(
                    cand.get("sandbox_url")
                    or cand_meta.get("sandbox_url")
                    or cand.get("verification_url")
                    or cand_meta.get("verification_url")
                    or ""
                ).strip()
                raw_cmd = cand.get("poc_cmd") or cand_meta.get("poc_cmd")
                raw_lang = str(cand.get("poc_lang") or cand_meta.get("poc_lang") or "python").strip()
                # Fail-closed: only run poc_runner when an explicit sandbox HTTP URL or PoC command is present.
                if sandbox_url:
                    probe_res = poc_runner.verify_sandbox_http_probe(
                        sandbox_url,
                        program=eff_program,
                        eligibility_db=eligibility_db,
                    )
                    probe_ok = bool(probe_res.get("verified", False))
                    tr = VerifiableTranscript(
                        language="http",
                        backend="sandbox_http",
                        status="passed" if probe_ok else str(probe_res.get("status") or "failed"),
                        exit_code=0 if probe_ok else 1,
                        command=["GET", sandbox_url],
                        image="sandbox_http",
                        repo_path=str(repo_p),
                        started_at_utc=datetime.now(timezone.utc).isoformat(),
                        elapsed_ms=float(probe_res.get("elapsed_ms") or 0.0),
                        stdout=json.dumps(probe_res, sort_keys=True),
                        stderr="" if probe_ok else str(probe_res.get("reason") or "; ".join(probe_res.get("reasons") or [])),
                    )
                    if cand_file:
                        poc_transcripts_map[cand_file] = tr
                        poc_transcripts_map[_norm_path(cand_file)] = tr
                    if probe_ok and cand_file:
                        norm_cf = _norm_path(cand_file)
                        for ef in all_efs:
                            if _norm_path(ef.file_path) == norm_cf:
                                ef.poc_verified = True
                elif isinstance(raw_cmd, (list, tuple)) and raw_cmd:
                    tr = poc_runner.run_poc(
                        language=raw_lang or "python",
                        repo_path=repo_p,
                        cmd=[str(part) for part in raw_cmd],
                    )
                    if cand_file:
                        poc_transcripts_map[cand_file] = tr
                        poc_transcripts_map[_norm_path(cand_file)] = tr
                    if tr.verified and cand_file:
                        norm_cf = _norm_path(cand_file)
                        for ef in all_efs:
                            if _norm_path(ef.file_path) == norm_cf:
                                ef.poc_verified = True

        clusters = EnsembleConsensusVoter(program=eff_program, quorum=self.quorum).fuse(
            all_efs,
            freshness=freshness,
            poc_transcripts=poc_transcripts_map or None,
        )
        counts_by_disp: Dict[str, int] = {}
        for c in clusters:
            counts_by_disp[c.disposition] = counts_by_disp.get(c.disposition, 0) + 1

        s1_noise = int(async_res.get("stage1_dropped_noise_count", 0) or 0) + extra_noise
        s1_prod_count = len(deduped_prod)
        elapsed_ms = round((time.monotonic() - t0) * 1000.0, 3)

        out: Dict[str, Any] = {
            "status": "completed",
            "program": eff_program,
            "repo_path": str(repo_p),
            "db_path": str(async_res.get("db_path") or bb_str),
            "recovery": async_res.get("recovery") or {},
            "worker_pids": list(async_res.get("worker_pids") or []),
            "intents_completed": int(async_res.get("intents_completed", 0) or 0),
            "intents_failed": int(async_res.get("intents_failed", 0) or 0),
            "loop2_emitted_intents": list(async_res.get("loop2_emitted_intents") or []),
            "stage1": {
                "production_count": s1_prod_count,
                "noise_dropped": s1_noise,
                "findings": deduped_prod,
            },
            "stage1_production_count": s1_prod_count,
            "stage1_dropped_noise_count": s1_noise,
            "stage2": stage2_res,
            "stage3": stage3_telemetry,
            "stage3_results": stage3_results,
            "facts": all_facts,
            "clusters": [c.to_dict() for c in clusters],
            "counts_by_disposition": counts_by_disp,
            "lane_allocation": async_res.get("lane_allocation") or {},
            "eligibility_sync": async_res.get("eligibility_sync"),
            "elapsed_ms": elapsed_ms,
        }

        ready_clusters = [c for c in clusters if c.disposition == "SUBMISSION_READY"]
        if ready_clusters and (out_dir is not None or trigger_browser):
            top_c = ready_clusters[0]
            loop4_res = evaluate_and_stage_submission(
                program=eff_program,
                asset=top_c.file_path,
                title=top_c.title,
                summary=top_c.summary or top_c.title,
                impact=f"Verified security issue in {top_c.file_path}:{top_c.line} ({top_c.cwe_family}).",
                weakness_cwe=top_c.cwe_family or "CWE-200",
                severity=top_c.severity,
                poc_verified=_coerce_strict_bool(top_c.poc_verified),
                poc_transcript=json.dumps(top_c.poc_transcript or {}),
                eligibility_db=eligibility_db,
                output_dir=out_dir,
                trigger_browser=bool(trigger_browser),
                poc_runner=poc_runner,
                poc_target_os=top_c.poc_target_os or None,
                finding_id=top_c.cluster_id,
            )
            out["loop4"] = loop4_res
            if loop4_res.get("ready_to_submit_path"):
                out["ready_to_submit_path"] = loop4_res["ready_to_submit_path"]
            if loop4_res.get("report_url"):
                out["report_url"] = loop4_res["report_url"]

        return out


_STAGE3_ENDPOINT_LOCK = threading.Lock()
_LAST_STAGE3_OLLAMA_ENDPOINT: Optional[str] = None


def _reset_guard_on_endpoint_change(guard: Any) -> None:
    """Resets circuit-breaker state when switching to a different `OLLAMA_HOST` endpoint."""
    global _LAST_STAGE3_OLLAMA_ENDPOINT
    cur_ep = os.environ.get("OLLAMA_HOST", "").strip()
    with _STAGE3_ENDPOINT_LOCK:
        if _LAST_STAGE3_OLLAMA_ENDPOINT is not None and cur_ep != _LAST_STAGE3_OLLAMA_ENDPOINT:
            if hasattr(guard, "reset"):
                guard.reset()
        _LAST_STAGE3_OLLAMA_ENDPOINT = cur_ep


def evaluate_and_stage_submission(
    program: str,
    asset: str = "",
    title: str = "",
    summary: str = "",
    impact: str = "",
    weakness_cwe: str = "CWE-200",
    severity: str = "HIGH",
    poc_verified: Any = False,
    poc_transcript: str = "",
    eligibility_db: Optional[Any] = None,
    eligibility_db_path: Optional[Union[str, Path]] = None,
    output_dir: Optional[Union[str, Path]] = None,
    trigger_browser: bool = True,
    poc_runner: Optional[LinuxPocRunner] = None,
    sandbox_url: Optional[str] = None,
    researcher_handle: str = "oyesanyf",
    poc_lang: Optional[str] = None,
    poc_cmd: Optional[Sequence[str]] = None,
    poc_target_os: Optional[str] = None,
    target_os_required: Optional[str] = None,
    report_id: Optional[str] = None,
    finding_id: str = "",
) -> Dict[str, Any]:
    """
    Loop 4 Fail-Closed Submission Gate:
      1. `ProgramEligibilityDB.is_eligible(program)` must be True (UNLOCKED)
      2. `evaluate_vendor_threat_model(...).passed` must be True
      3. `poc_verified` must be True (supplied or confirmed via `LinuxPocRunner`)
    Emits `<output_dir>/READY_TO_SUBMIT.json`, builds `/browser` HITL handoff spec,
    and returns clickable `https://hackerone.com/reports/<id>` URL only when all 3 pass.
    """
    from engine.hackerone_porter import HACKERONE_BASE_URL, _scrub_secrets_and_phi
    from engine.program_eligibility_db import ProgramEligibilityDB

    eff_program = str(program or "").strip().lower()
    if eligibility_db is not None:
        eff_elig_db = eligibility_db
    elif eligibility_db_path is not None:
        eff_elig_db = ProgramEligibilityDB(eligibility_db_path)
    else:
        eff_elig_db = ProgramEligibilityDB()

    if (
        not eff_program
        or "\x00" in eff_program
        or ".." in eff_program
        or "/" in eff_program
        or "\\" in eff_program
        or not eff_elig_db.is_eligible(eff_program)
    ):
        return {
            "eligible": False,
            "status": "blocked_ineligible",
            "program": eff_program,
            "reasons": [f"Program {eff_program!r} is not UNLOCKED in ProgramEligibilityDB."],
            "report_url": None,
            "submit_url": None,
            "ready_to_submit_path": None,
        }

    eff_poc_verified = _coerce_strict_bool(poc_verified)
    eff_poc_transcript = str(poc_transcript or "")
    eff_poc_target_os = str(poc_target_os or "")
    runner = poc_runner or LinuxPocRunner()

    if not eff_poc_verified and sandbox_url:
        probe_res = runner.verify_sandbox_http_probe(
            sandbox_url,
            program=eff_program,
            eligibility_db=eff_elig_db,
            researcher_handle=researcher_handle,
        )
        eff_poc_verified = bool(probe_res.get("verified", False))
        eff_poc_transcript = json.dumps(probe_res)
    elif not eff_poc_verified and poc_lang and poc_cmd:
        repo_hint = str(Path(asset).parent) if asset and Path(asset).exists() else "."
        tr = runner.run_poc(
            language=poc_lang,
            repo_path=repo_hint,
            cmd=list(poc_cmd),
        )
        eff_poc_verified = bool(tr.verified)
        eff_poc_transcript = json.dumps(tr.to_dict())
        if not eff_poc_target_os and tr.backend:
            eff_poc_target_os = "linux"

    tm_verdict = evaluate_vendor_threat_model(
        title=title,
        summary=summary,
        file_path=asset,
        program=eff_program,
        poc_verified=eff_poc_verified,
        poc_target_os=eff_poc_target_os,
        target_os_required=str(target_os_required or ""),
    )
    if not tm_verdict.passed:
        return {
            "eligible": False,
            "status": "blocked_threat_model",
            "program": eff_program,
            "reasons": list(tm_verdict.reasons),
            "matched_rules": list(tm_verdict.matched_rules),
            "threat_model": tm_verdict.to_dict(),
            "report_url": None,
            "submit_url": None,
            "ready_to_submit_path": None,
        }

    if not eff_poc_verified:
        return {
            "eligible": False,
            "status": "blocked_unverified_poc",
            "program": eff_program,
            "reasons": ["poc_verified is False; static-only findings cannot be staged for submission."],
            "threat_model": tm_verdict.to_dict(),
            "report_url": None,
            "submit_url": None,
            "ready_to_submit_path": None,
        }

    clean_title = _scrub_secrets_and_phi(title)[:140]
    clean_asset = _scrub_secrets_and_phi(asset)
    clean_summary = _scrub_secrets_and_phi(summary)
    clean_impact = _scrub_secrets_and_phi(impact)
    clean_transcript = _scrub_secrets_and_phi(eff_poc_transcript)

    if report_id and str(report_id).strip():
        eff_report_id = str(report_id).strip()
    else:
        digest = hashlib.sha256(
            f"{eff_program}|{clean_asset}|{clean_title}|{finding_id}".encode("utf-8")
        ).hexdigest()
        eff_report_id = str(int(digest[:10], 16) % 9_000_000 + 1_000_000)

    report_url = f"{HACKERONE_BASE_URL}/reports/{eff_report_id}"
    program_new_url = f"{HACKERONE_BASE_URL}/{eff_program}/reports/new"

    browser_handoff_spec: Optional[Dict[str, Any]] = None
    if trigger_browser:
        browser_handoff_spec = {
            "action": "stage_draft",
            "target_url": report_url,
            "program_new_url": program_new_url,
            "program": eff_program,
            "report_id": eff_report_id,
            "final_submit_blocked_for_hitl": True,
            "hitl_invariants": [
                "Human researcher must complete login, 2FA/MFA, and any CAPTCHA or Turnstile challenge manually.",
                "Never click final Submit report button automatically; require explicit human review.",
            ],
            "prefill_fields": {
                "title": clean_title,
                "asset": clean_asset,
                "weakness_cwe": str(weakness_cwe or "CWE-200").upper(),
                "severity": str(severity or "HIGH").upper(),
                "vulnerability_information": clean_summary,
                "impact": clean_impact,
            },
        }

    dest_dir = Path(output_dir) if output_dir is not None else Path("reports/ensemble_hunt")
    dest_dir.mkdir(parents=True, exist_ok=True)
    ready_path = dest_dir / "READY_TO_SUBMIT.json"

    staged_payload: Dict[str, Any] = {
        "eligible": True,
        "status": "ready_to_submit",
        "program": eff_program,
        "asset": clean_asset,
        "title": clean_title,
        "summary": clean_summary,
        "impact": clean_impact,
        "weakness_cwe": str(weakness_cwe or "CWE-200").upper(),
        "severity": str(severity or "HIGH").upper(),
        "poc_verified": True,
        "poc_transcript": clean_transcript,
        "report_id": eff_report_id,
        "report_url": report_url,
        "submit_url": report_url,
        "program_new_url": program_new_url,
        "threat_model": tm_verdict.to_dict(),
        "browser_handoff_spec": browser_handoff_spec,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    ready_path.write_text(json.dumps(staged_payload, indent=2), encoding="utf-8")
    return {
        **staged_payload,
        "ready_to_submit_path": str(ready_path),
    }


def render_ensemble_markdown(report: EnsembleReport) -> str:
    lines = [
        f"# RFCHunt Ensemble Security Audit Summary ({report.program})",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Freshness Status:** `{report.freshness.freshness_status}` (HEAD age: `{report.freshness.head_age_hours}`h, window: `{report.freshness.freshness_hours_window}`h)",
        f"- **Quorum:** `{report.quorum}` independent engines",
        f"- **Dispositions:** `{json.dumps(report.counts_by_disposition)}`",
    ]
    if report.proxy:
        lines.append(f"- **Proxy:** `{report.proxy}`")
    lines.extend(
        [
            "",
            "| Cluster | Disposition | Freshness | Severity | Engines | Conf | Live PoC | File |",
            "|---|---|---|---|---|---:|:---:|---|",
        ]
    )
    for c in report.clusters:
        lines.append(
            f"| `{c.cluster_id}` | `{c.disposition}` | `{c.freshness_status}` | **{c.severity}** | "
            f"`{', '.join(c.engines)}` | `{c.ensemble_confidence:.2f}` | "
            f"{'YES' if c.poc_verified else 'NO'} | `{c.file_path}:{c.line}` |"
        )

    if report.whiteboard:
        wb = report.whiteboard
        lines.extend(
            [
                "",
                "## Whiteboard Summary",
                f"- **Enabled:** `{wb.get('enabled', True)}` | **Rounds:** `{len(wb.get('rounds') or [])}` | **DB Synced:** `{wb.get('db_synced', False)}`",
                f"- **Hypotheses by Status:** `{json.dumps(wb.get('counts_by_status') or {})}`",
            ]
        )

    if report.lean_verification:
        lv = report.lean_verification
        lines.extend(
            [
                "",
                "## Lean 4 Formal Verification",
                f"- **Status:** `{lv.get('status')}` | **Oracle:** `{lv.get('oracle_backend')}` | **Machine Checked:** `{lv.get('machine_checked')}`",
                f"- **Checks Total:** `{lv.get('checks_total', 0)}` | **Violations:** `{lv.get('violations_count', 0)}` | **Diagnostics:** `{len(lv.get('diagnostics') or [])}`",
            ]
        )

    if report.toolchain_status:
        tc_summary = {
            k: f"{'available' if v.get('available') else v.get('status', 'unavailable')}"
            for k, v in report.toolchain_status.items()
            if isinstance(v, dict)
        }
        lines.extend(
            [
                "",
                "## Toolchain Availability",
                f"- **Backends:** `{json.dumps(tc_summary)}`",
            ]
        )

    return "\n".join(lines) + "\n"
