"""
RFCHunt Cash-Tuned Bounty ROI, Runtime PoE Gate, Duplicate Pre-Check & Queue Optimizer
======================================================================================

Empirically calibrated from RFCHunt's 39-finding security ledger across Google (4 GHSAs + 1 merged PR),
Anthropic (3 High Duplicates, 4 Informative, 4 open fix PRs), Shopify (live #4234525, queued #4236500,
staged #19-#23, local-CLI hold #24), and Circle Arc (queued Critical #4234132 + 14 local drafts).

Core objective: maximize cash payout per scarce HackerOne submission slot (24h cooldown + Signal):
  EV_cash = P(Valid | Epistemic, Precision_STRIDE, Runtime_PoE)
            * (1 - P(Duplicate | Program_Saturation, Upstream_GH_Precheck))
            * ExpectedPayout(Program, Severity, Cash_Archetype)
            - CooldownOpportunityCost

Guardrails:
  - Strictly offline-safe (`RFCHUNT_OFFLINE=1` or `dry_run=True` skips all live GitHub pre-checks).
  - Pinned exclusively to `https://api.github.com` for public read-only duplicate pre-checks.
  - Zero automatic submissions; integrates directly with `HackerOneTicketStore` (SQLite) and
    `DynamicStrideThreatEngine.evaluate_finding_against_threat_model(...)`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request

from engine.epistemic_state import EpistemicStatus
from engine.stride_engine import DynamicStrideThreatEngine, StrideBoundaryVerdict

GITHUB_API_BASE = "https://api.github.com"

# Severity payout multipliers relative to program average bounty
_SEV_PAYOUT_MULT: Dict[str, float] = {
    "critical": 3.5,
    "high": 1.8,
    "medium": 0.9,
    "low": 0.25,
    "info": 0.0,
    "none": 0.0,
}

# Empirically calibrated cash archetype weights from the 39-finding historical track record
CASH_ARCHETYPE_CATALOG: Tuple[Tuple[str, float, re.Pattern[str]], ...] = (
    (
        "cross_tenant_auth_jwt_oidc",
        1.55,
        re.compile(
            r"\b(?:cross[- ]tenant|oidc.{0,30}api[- ]?key|missing\s+iss|missing\s+dest|"
            r"storefront.{0,30}admin|buyer.{0,30}merchant|webauthn.{0,25}bypass|"
            r"oauth.{0,25}(?:hmac|csrf|bypass)|jwt.{0,25}(?:confusion|bypass)|cwe-287|cwe-863)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "wasm_sandbox_guest_to_host",
        1.50,
        re.compile(
            r"\b(?:uninitialized\s+host|ptr::read|poll_oneoff|resourcelimiter\s+bypass|"
            r"host\s+heap\s+allocation|host\s+panic|sandbox\s+(?:escape|bypass)|ntfs\s+(?:ads|junction)|"
            r"alternate\s+data\s+stream|ancestor\s+rename|@javascriptinterface|cwe-908|cwe-78)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "consensus_bft_enclave_signer",
        1.60,
        re.compile(
            r"\b(?:validator\s+bricking|chain\s+halt|may_be_stored_as_undecided|malachite|"
            r"consensus.{0,25}(?:halt|deadlock)|p2p\s+eclipse|gossipsub|nitro.{0,25}attestation|"
            r"kms\s+attestation|precompile.{0,25}unmetered|cwe-841)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "parser_framing_proxy_differential",
        1.35,
        re.compile(
            r"\b(?:framing\s+differential|splitlines|duplicate\s+query\s+param|double[- ]decode|"
            r"stray[- ]percent|pre[- ]sanitized|unrestricted\s+proxy|proxy\s+bypass|egress\s+inspection|"
            r"request\s+smuggling|cwe-436|cwe-444|cwe-284)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ssrf_rce_sqli_core",
        1.30,
        re.compile(
            r"\b(?:ssrf|command\s+injection|sql\s+injection|arbitrary\s+code\s+execution|"
            r"path\s+traversal|deserialization|cwe-918|cwe-89|cwe-22|cwe-502|cwe-94)\b",
            re.IGNORECASE,
        ),
    ),
)

# Host-verified active paid HackerOne bounty programs discovered read-only (2026-11-28)
DEFAULT_VERIFIED_BOUNTY_PROGRAMS: Tuple[Dict[str, Any], ...] = (
    {
        "handle": "common_codes",
        "name": "d-you App & German EUDI Wallet Ecosystem",
        "url": "https://hackerone.com/common_codes",
        "offers_bounties": True,
        "min_bounty_usd": 100.0,
        "avg_bounty_low_usd": 2000.0,
        "avg_bounty_high_usd": 3000.0,
        "resolved_count": 5,
        "launched_at": "2026-09",
        "has_source_code_scope": True,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "vercel",
        "name": "Vercel",
        "url": "https://hackerone.com/vercel",
        "offers_bounties": True,
        "min_bounty_usd": 50.0,
        "avg_bounty_low_usd": 1000.0,
        "avg_bounty_high_usd": 1000.0,
        "resolved_count": 368,
        "launched_at": "2026-09",
        "has_source_code_scope": True,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "shopify",
        "name": "Shopify",
        "url": "https://hackerone.com/shopify",
        "offers_bounties": True,
        "min_bounty_usd": 500.0,
        "avg_bounty_low_usd": 1000.0,
        "avg_bounty_high_usd": 2500.0,
        "resolved_count": 1200,
        "launched_at": "2014-01",
        "has_source_code_scope": True,
        "in_scope_repos": [
            "https://github.com/Shopify/deterministic-wasi-ctx",
            "https://github.com/Shopify/function-runner",
            "https://github.com/Shopify/shopify-app-js",
            "https://github.com/Shopify/shopify-app-python",
            "https://github.com/Shopify/hydrogen",
        ],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "arc-bbp",
        "name": "Circle Arc",
        "url": "https://hackerone.com/arc-bbp",
        "offers_bounties": True,
        "min_bounty_usd": 100.0,
        "avg_bounty_low_usd": 500.0,
        "avg_bounty_high_usd": 2500.0,
        "resolved_count": 4,
        "launched_at": "2026-09",
        "has_source_code_scope": True,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "omarchy",
        "name": "Omarchy",
        "url": "https://hackerone.com/omarchy",
        "offers_bounties": True,
        "min_bounty_usd": 50.0,
        "avg_bounty_low_usd": 200.0,
        "avg_bounty_high_usd": 500.0,
        "resolved_count": 0,
        "launched_at": "2026-10",
        "has_source_code_scope": True,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "northerntechhq",
        "name": "Northern.tech",
        "url": "https://hackerone.com/northerntechhq",
        "offers_bounties": True,
        "min_bounty_usd": 200.0,
        "avg_bounty_low_usd": 200.0,
        "avg_bounty_high_usd": 600.0,
        "resolved_count": 36,
        "launched_at": "2025-11",
        "has_source_code_scope": True,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "gitlab",
        "name": "GitLab",
        "url": "https://hackerone.com/gitlab",
        "offers_bounties": True,
        "min_bounty_usd": 100.0,
        "avg_bounty_low_usd": 1000.0,
        "avg_bounty_high_usd": 1500.0,
        "resolved_count": 2286,
        "launched_at": "2016-02",
        "has_source_code_scope": True,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "anthropic",
        "name": "Anthropic",
        "url": "https://hackerone.com/anthropic",
        "offers_bounties": True,
        "min_bounty_usd": 50.0,
        "avg_bounty_low_usd": 600.0,
        "avg_bounty_high_usd": 1000.0,
        "resolved_count": 543,
        "launched_at": "2026-05",
        "has_source_code_scope": True,
        "in_scope_repos": ["https://github.com/anthropic-experimental/sandbox-runtime"],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "live_nation",
        "name": "Live Nation",
        "url": "https://hackerone.com/live_nation",
        "offers_bounties": True,
        "min_bounty_usd": 50.0,
        "avg_bounty_low_usd": 500.0,
        "avg_bounty_high_usd": 2000.0,
        "resolved_count": 118,
        "launched_at": "2026-09",
        "has_source_code_scope": False,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "box_private",
        "name": "Box BB",
        "url": "https://hackerone.com/box_private",
        "offers_bounties": True,
        "min_bounty_usd": 150.0,
        "avg_bounty_low_usd": 500.0,
        "avg_bounty_high_usd": 750.0,
        "resolved_count": 269,
        "launched_at": "2026-08",
        "has_source_code_scope": False,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "coupang",
        "name": "Coupang",
        "url": "https://hackerone.com/coupang",
        "offers_bounties": True,
        "min_bounty_usd": 50.0,
        "avg_bounty_low_usd": 490.0,
        "avg_bounty_high_usd": 559.0,
        "resolved_count": 98,
        "launched_at": "2026-11",
        "has_source_code_scope": False,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
    {
        "handle": "twilio",
        "name": "Twilio",
        "url": "https://hackerone.com/twilio",
        "offers_bounties": True,
        "min_bounty_usd": 50.0,
        "avg_bounty_low_usd": 200.0,
        "avg_bounty_high_usd": 300.0,
        "resolved_count": 3125,
        "launched_at": "2026-01",
        "has_source_code_scope": True,
        "in_scope_repos": [],
        "roe_tier": "in_scope_only_manual_verify",
        "max_rps": 2.0,
    },
)


@dataclass
class RuntimePocAssessment:
    required_runtime: str
    poc_verified_runtime: bool
    poc_gate_status: str  # VERIFIED_RUNTIME_POE | NEEDS_LIVE_POC | OS_MISMATCH_UNVERIFIED
    recommended_command: str = ""
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DuplicateRiskAssessment:
    p_duplicate: float
    status: str  # LOW_DUP_RISK | MODERATE_DUP_RISK | HIGH_DUP_RISK | UPSTREAM_MATCH_FOUND | OFFLINE_ESTIMATE
    saturation_prior: float
    upstream_matches: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CashEvEvaluation:
    cash_ev_usd: float
    expected_payout_usd: float
    p_valid: float
    p_duplicate: float
    cooldown_slot_cost_usd: float
    matched_archetype: str
    archetype_multiplier: float
    stride_verdict: Dict[str, Any]
    runtime_poc: Dict[str, Any]
    duplicate_risk: Dict[str, Any]
    recommended_route: str  # SUBMIT_NEXT_SLOT | QUEUE_COOL_OFF | RUN_LIVE_POC_FIRST | GITHUB_HARDENING_PR | HOLD_DO_NOT_SUBMIT
    target_ticket_state: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def assess_runtime_poc_readiness(finding: Dict[str, Any], *, current_os: Optional[str] = None) -> RuntimePocAssessment:
    """
    Infers the target OS/runtime required to prove exploitability and checks whether
    live PoE execution actually passed (eliminates 'did not repro on modern OS' Informatives
    and tracks staged runtime PoCs cleanly).
    """
    fp = str(finding.get("file_path") or finding.get("file") or "").lower()
    blob = " ".join(
        [
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("evidence") or ""),
            fp,
        ]
    ).lower()
    ep_status = str(finding.get("epistemic_status") or "").strip().upper()
    poe_level = int(finding.get("poe_level", 1) or 1)
    runtime_verified = bool(
        finding.get("runtime_poe_verified") is True
        or (ep_status == EpistemicStatus.PROVEN_RUNTIME.value and poe_level >= 3)
        or str(finding.get("poe_verification_status") or "").strip().lower() == "verified"
    )
    host_os = (current_os or ("windows" if os.name == "nt" else "posix")).lower()

    # Determine required runtime / OS
    if any(k in blob for k in ("macos", "apfs", "seatbelt", "darwin")):
        req_rt = "macos_apfs"
        cmd = "Run native macOS APFS/Seatbelt repro harness on target macOS version"
    elif any(k in blob for k in ("android", "@javascriptinterface", "action_view", ".kt", ".java")):
        req_rt = "android_jdk"
        cmd = "./gradlew test --tests '*SecurityPoc*'"
    elif fp.endswith(".rs") or any(k in blob for k in ("wasmtime", "wasi", "malachite", "ptr::read", "cargo")):
        req_rt = "rust_cargo"
        cmd = "cargo test --nocapture"
    elif fp.endswith((".ts", ".tsx", ".js", ".mjs", ".cjs")) or any(k in blob for k in ("shopify-app-js", "hydrogen", "node")):
        req_rt = "node_js"
        cmd = "node --test poc_repro.test.mjs"
    elif fp.endswith(".rb") or "rack" in blob or "ruby" in blob:
        req_rt = "ruby"
        cmd = "bundle exec rspec spec/security_poc_spec.rb"
    elif fp.endswith(".go") or "golang" in blob:
        req_rt = "go_test"
        cmd = "go test -v ./..."
    elif any(k in blob for k in ("ntfs", "reparse", "openprocess", "srt-win", "wsl2", "windows")):
        req_rt = "windows_ntfs"
        cmd = "pytest -q poc_windows_repro.py"
    elif fp.endswith(".py") or "pytest" in blob:
        req_rt = "python_pytest"
        cmd = "pytest -q poc_repro.py"
    else:
        req_rt = "docker_container"
        cmd = "Run isolated PoE container harness (poe_container_verifier)"

    if runtime_verified:
        return RuntimePocAssessment(
            required_runtime=req_rt,
            poc_verified_runtime=True,
            poc_gate_status="VERIFIED_RUNTIME_POE",
            recommended_command=cmd,
            rationale=f"Live runtime PoE verified (`poe_level={poe_level}`, runtime={req_rt}).",
        )

    if req_rt == "macos_apfs" and host_os != "darwin":
        return RuntimePocAssessment(
            required_runtime=req_rt,
            poc_verified_runtime=False,
            poc_gate_status="OS_MISMATCH_UNVERIFIED",
            recommended_command=cmd,
            rationale="macOS APFS/Seatbelt claim cannot be live-verified on non-macOS host; hold until repro on modern macOS.",
        )

    return RuntimePocAssessment(
        required_runtime=req_rt,
        poc_verified_runtime=False,
        poc_gate_status="NEEDS_LIVE_POC",
        recommended_command=cmd,
        rationale=f"Static/invariant finding requires live `{req_rt}` PoC execution before spending a 24h HackerOne submission slot.",
    )


def estimate_program_duplicate_prior(resolved_count: int) -> float:
    """Empirical prior probability of duplicate based on HackerOne program saturation."""
    cnt = max(0, int(resolved_count or 0))
    if cnt <= 10:
        return 0.08
    if cnt <= 50:
        return 0.18
    if cnt <= 250:
        return 0.30
    if cnt <= 500:
        return 0.44
    return 0.56


def check_upstream_duplicate_risk(
    finding: Dict[str, Any],
    *,
    resolved_count: int = 0,
    repo_url: str = "",
    allow_network: bool = False,
    dry_run: bool = False,
    timeout_sec: float = 6.0,
) -> DuplicateRiskAssessment:
    """
    Computes duplicate probability using program saturation prior plus optional keyless
    read-only GitHub REST API pre-check (`https://api.github.com/repos/<owner>/<repo>/...`).
    Automatically skips network calls when `RFCHUNT_OFFLINE=1`, `dry_run=True`, or `allow_network=False`.
    """
    prior = estimate_program_duplicate_prior(resolved_count)
    offline = str(os.environ.get("RFCHUNT_OFFLINE") or "").strip().lower() in ("1", "true", "yes")
    if dry_run or offline or not allow_network or not repo_url:
        status = (
            "HIGH_DUP_RISK"
            if prior >= 0.45
            else ("MODERATE_DUP_RISK" if prior >= 0.25 else "LOW_DUP_RISK")
        )
        return DuplicateRiskAssessment(
            p_duplicate=round(prior, 3),
            status=status if not (dry_run or offline or not allow_network) else f"OFFLINE_ESTIMATE:{status}",
            saturation_prior=round(prior, 3),
            upstream_matches=[],
        )

    parsed = urllib.parse.urlparse(str(repo_url).strip())
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != "github.com":
        return DuplicateRiskAssessment(p_duplicate=round(prior, 3), status="OFFLINE_ESTIMATE", saturation_prior=round(prior, 3))

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return DuplicateRiskAssessment(p_duplicate=round(prior, 3), status="OFFLINE_ESTIMATE", saturation_prior=round(prior, 3))
    owner, repo = parts[0], parts[1].removesuffix(".git")
    if not re.match(r"^[A-Za-z0-9_.-]+$", owner) or not re.match(r"^[A-Za-z0-9_.-]+$", repo):
        return DuplicateRiskAssessment(p_duplicate=round(prior, 3), status="OFFLINE_ESTIMATE", saturation_prior=round(prior, 3))

    file_basename = Path(str(finding.get("file_path") or finding.get("file") or "")).name
    cwe = str(finding.get("cwe") or finding.get("cwe_id") or "").strip()
    title_words = [
        w for w in re.findall(r"[A-Za-z0-9_]{4,}", str(finding.get("title") or ""))
        if w.lower() not in ("bypass", "issue", "vulnerability", "missing", "error", "finding")
    ][:3]
    q_terms = " ".join([t for t in [file_basename, cwe, *title_words] if t]).strip()
    if not q_terms:
        return DuplicateRiskAssessment(p_duplicate=round(prior, 3), status="LOW_DUP_RISK", saturation_prior=round(prior, 3))

    matches: List[str] = []
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "RFCHunt-CashBountyTuner/2.0"}
    try:
        q = urllib.parse.quote(f"repo:{owner}/{repo} {q_terms}")
        url = f"{GITHUB_API_BASE}/search/issues?q={q}&per_page=5"
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=max(2.0, float(timeout_sec))) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            for item in (data.get("items") or [])[:5]:
                num = item.get("number")
                ititle = str(item.get("title") or "")[:90]
                istate = str(item.get("state") or "")
                matches.append(f"#{num} ({istate}): {ititle}")
    except Exception:
        pass

    eff_dup = min(0.95, prior + 0.40 * min(2, len(matches))) if matches else prior
    if matches:
        st = "UPSTREAM_MATCH_FOUND"
    elif eff_dup >= 0.45:
        st = "HIGH_DUP_RISK"
    elif eff_dup >= 0.25:
        st = "MODERATE_DUP_RISK"
    else:
        st = "LOW_DUP_RISK"
    return DuplicateRiskAssessment(
        p_duplicate=round(eff_dup, 3),
        status=st,
        saturation_prior=round(prior, 3),
        upstream_matches=matches,
    )


def score_finding_cash_ev(
    finding: Dict[str, Any],
    *,
    program_meta: Optional[Dict[str, Any]] = None,
    stride_model: Optional[Dict[str, Any]] = None,
    policy_text: str = "",
    cool_off_active: bool = False,
    cooldown_slot_cost_usd: float = 75.0,
    allow_network_dup_check: bool = False,
    prior_signatures: Sequence[Dict[str, Any]] = (),
    local_repo_path: Optional[str] = None,
    dry_run: bool = False,
    current_os: Optional[str] = None,
) -> CashEvEvaluation:
    """
    Evaluates a single finding end-to-end for Cash EV, Precision STRIDE boundary validity,
    Runtime PoE readiness, and 3-Pillar Deduplication/Freshness/Surface-Congestion Gate,
    returning an exact routing action and SQLite ticket state.
    """
    from engine.dedup_gate import evaluate_dedup_gate

    pm = dict(program_meta or {})
    offers_bounties = bool(pm.get("offers_bounties", True))
    avg_low = float(pm.get("avg_bounty_low_usd", 400.0) or 400.0)
    avg_high = float(pm.get("avg_bounty_high_usd", 800.0) or 800.0)
    min_bounty = float(pm.get("min_bounty_usd", 50.0) or 50.0)
    resolved_count = int(pm.get("resolved_count", 25) or 25)
    prog_handle = str(pm.get("handle") or finding.get("program_handle") or "").lower()
    repos = pm.get("in_scope_repos") or []
    primary_repo = str(repos[0]) if isinstance(repos, list) and repos else ""

    # 1. Precision STRIDE Trust-Boundary Verdict
    stride_v: StrideBoundaryVerdict = DynamicStrideThreatEngine.evaluate_finding_against_threat_model(
        finding,
        stride_model,
        policy_text=policy_text,
    )

    # 2. Target-OS / Runtime PoE Readiness
    poc_assess = assess_runtime_poc_readiness(finding, current_os=current_os)

    # 3. 3-Pillar Dedup, Freshness & Surface Congestion Gate
    dedup_gate = evaluate_dedup_gate(
        finding,
        program_handle=prog_handle,
        resolved_count=resolved_count,
        prior_signatures=prior_signatures,
        local_repo_path=local_repo_path,
        repo_url=primary_repo,
        allow_network=allow_network_dup_check,
        dry_run=dry_run,
    )
    dup_assess = DuplicateRiskAssessment(
        p_duplicate=dedup_gate.adjusted_p_duplicate,
        status=dedup_gate.gate_verdict,
        saturation_prior=round(estimate_program_duplicate_prior(resolved_count), 3),
        upstream_matches=list(dedup_gate.upstream_hits),
    )
    dup_dict = {
        **dup_assess.to_dict(),
        "congestion_score": dedup_gate.congestion_score,
        "congestion_tier": dedup_gate.congestion_tier,
        "freshness_tier": dedup_gate.freshness_tier,
        "code_age_hours": dedup_gate.code_age_hours,
        "cross_report_similarity": dedup_gate.cross_report_similarity,
        "closest_prior_report": dedup_gate.closest_prior_report,
        "rationale": dedup_gate.rationale,
    }

    # 4. Archetype Cash Multiplier
    blob = " ".join(
        [
            str(finding.get("rule_id") or ""),
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("cwe") or finding.get("cwe_id") or ""),
        ]
    )
    matched_arch = "general_security_defect"
    arch_mult = 1.0
    for arch_name, mult, rx in CASH_ARCHETYPE_CATALOG:
        if rx.search(blob):
            matched_arch = arch_name
            arch_mult = mult
            break

    # 5. Epistemic + STRIDE + PoE P(Valid)
    ep = str(finding.get("epistemic_status") or "").strip().upper()
    if stride_v.verdict in ("DOCUMENTED_AS_DESIGNED", "BOUNDARY_NOT_CROSSED"):
        p_valid = 0.02
    elif stride_v.verdict == "HARDENING_CANDIDATE_NOT_BOUNTY":
        p_valid = 0.08
    elif ep == EpistemicStatus.REFUTED.value:
        p_valid = 0.0
    elif ep == EpistemicStatus.UNRESOLVED.value:
        p_valid = 0.10
    elif poc_assess.poc_verified_runtime:
        p_valid = 0.88
    elif poc_assess.poc_gate_status == "OS_MISMATCH_UNVERIFIED":
        p_valid = 0.25
    else:
        # PROVEN_STATIC_INVARIANT without live execution yet
        p_valid = 0.55

    # 6. Expected Gross Payout & Net Cash EV
    sev_low = str(finding.get("severity") or "medium").strip().lower()
    sev_mult = _SEV_PAYOUT_MULT.get(sev_low, 0.5)
    base_avg = (avg_low + avg_high) / 2.0 if (avg_low > 0 or avg_high > 0) else max(min_bounty, 100.0)
    expected_payout = round(base_avg * sev_mult * arch_mult, 2) if offers_bounties else 0.0
    slot_cost = max(0.0, float(cooldown_slot_cost_usd)) if offers_bounties else 0.0
    cash_ev = round(p_valid * (1.0 - dup_assess.p_duplicate) * expected_payout - slot_cost, 2)

    # 7. Exact Routing & SQLite Ticket State Decision
    if stride_v.verdict == "DOCUMENTED_AS_DESIGNED":
        route = "HOLD_DO_NOT_SUBMIT"
        t_state = "informative_prevented"
    elif stride_v.verdict == "BOUNDARY_NOT_CROSSED":
        route = "HOLD_DO_NOT_SUBMIT"
        t_state = "do_not_submit"
    elif stride_v.verdict == "HARDENING_CANDIDATE_NOT_BOUNTY":
        route = "GITHUB_HARDENING_PR"
        t_state = "hardening_pr_only"
    elif dedup_gate.gate_verdict in ("HOLD_CROSS_REPORT_DUPLICATE", "HOLD_LIKELY_PATCHED_UPSTREAM"):
        route = "HOLD_DO_NOT_SUBMIT"
        t_state = "duplicate_risk_hold"
    elif not poc_assess.poc_verified_runtime and poc_assess.poc_gate_status in ("NEEDS_LIVE_POC", "OS_MISMATCH_UNVERIFIED"):
        route = "RUN_LIVE_POC_FIRST"
        t_state = "needs_live_poc"
    elif cash_ev <= 0.0 and offers_bounties:
        route = "HOLD_DO_NOT_SUBMIT"
        t_state = "do_not_submit"
    elif cool_off_active:
        route = "QUEUE_COOL_OFF"
        t_state = "held_cool_off"
    else:
        route = "SUBMIT_NEXT_SLOT"
        t_state = "ready_to_submit"

    return CashEvEvaluation(
        cash_ev_usd=cash_ev,
        expected_payout_usd=expected_payout,
        p_valid=round(p_valid, 3),
        p_duplicate=round(dup_assess.p_duplicate, 3),
        cooldown_slot_cost_usd=round(slot_cost, 2),
        matched_archetype=matched_arch,
        archetype_multiplier=arch_mult,
        stride_verdict=stride_v.to_dict(),
        runtime_poc=poc_assess.to_dict(),
        duplicate_risk=dup_dict,
        recommended_route=route,
        target_ticket_state=t_state,
    )


def rank_submission_queue(tickets: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Orders tickets for scarce 24h HackerOne submission slots:
      1. Ready / queued / saved-on-site / held-cool-off tickets first,
      2. Verified runtime PoE (`poc_verified_runtime == 1`) ahead of unexecuted PoCs,
      3. Highest `cash_ev_usd` descending,
      4. Severity rank descending.
    Excludes already-submitted/closed/do_not_submit/informative_prevented/hardening_pr_only tickets.
    """
    actionable_states = {
        "ready_to_submit",
        "queued_cooldown",
        "draft_saved_on_site",
        "held_cool_off",
        "draft_local",
        "needs_live_poc",
    }
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    state_priority = {
        "ready_to_submit": 0,
        "queued_cooldown": 1,
        "draft_saved_on_site": 2,
        "held_cool_off": 3,
        "draft_local": 4,
        "needs_live_poc": 5,
    }
    eligible = [dict(t) for t in tickets if str(t.get("state") or "") in actionable_states]
    eligible.sort(
        key=lambda t: (
            state_priority.get(str(t.get("state") or ""), 9),
            0 if int(t.get("poc_verified_runtime") or 0) == 1 else 1,
            -float(t.get("cash_ev_usd") or 0.0),
            -sev_rank.get(str(t.get("severity_rating") or "low").lower(), 0),
            str(t.get("draft_id") or ""),
        )
    )
    for rank_idx, item in enumerate(eligible, start=1):
        item["queue_rank"] = rank_idx
    return eligible


def seed_verified_bounty_programs(ticket_store: Any) -> List[Dict[str, Any]]:
    """Seeds today's host-verified paid HackerOne bounty programs into SQLite."""
    seeded: List[Dict[str, Any]] = []
    for prog in DEFAULT_VERIFIED_BOUNTY_PROGRAMS:
        seeded.append(ticket_store.upsert_bounty_program(**prog))
    return seeded


# Complete 39-finding historical RFCHunt security findings inventory across Google, Anthropic, Shopify, Circle Arc
_HISTORICAL_39_INVENTORY: Tuple[Dict[str, Any], ...] = (
    # 1. Google (5 Findings — 4 GHSAs + 1 Merged PR)
    {"id": "INV-01", "program": "google-vrp", "program_name": "Google", "offers_bounties": True, "asset": "google/cybernetic-agent-governance-engine", "remote_id": "GHSA-797p-rrgm-4p56", "title": "require_api_key() conflated end-user OIDC JWTs with service API keys", "severity": "high", "cwe": "CWE-287", "state": "resolved", "runtime": "python_pytest", "poc_ok": True, "ev": 2400.0, "stride": "Spoofing", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-02", "program": "google-vrp", "program_name": "Google", "offers_bounties": True, "asset": "google/cybernetic-agent-governance-engine", "remote_id": "GHSA-xm4c-x85r-38fp", "title": "Streaming SSE str.splitlines() vs WHATWG framing differential bypassed PII masking", "severity": "medium", "cwe": "CWE-436", "state": "resolved", "runtime": "python_pytest", "poc_ok": True, "ev": 1200.0, "stride": "Tampering", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-03", "program": "google-vrp", "program_name": "Google", "offers_bounties": True, "asset": "google/cybernetic-agent-governance-engine", "remote_id": "GHSA-gg2p-q2qw-3wx3", "title": "SymbolicGovernor.govern() signed RoutingSeal over pre-sanitized params", "severity": "medium", "cwe": "CWE-345", "state": "resolved", "runtime": "python_pytest", "poc_ok": True, "ev": 1100.0, "stride": "Tampering", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-04", "program": "google-vrp", "program_name": "Google", "offers_bounties": True, "asset": "google/cybernetic-agent-governance-engine", "remote_id": "GHSA-8r4c-xx89-28w5", "title": "/v1/defer/{id}/escalate bypassed WebAuthn presence gate with cross-decision replay", "severity": "low", "cwe": "CWE-287", "state": "resolved", "runtime": "python_pytest", "poc_ok": True, "ev": 500.0, "stride": "Spoofing", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-05", "program": "google-vrp", "program_name": "Google", "offers_bounties": True, "asset": "google/agentmesh", "remote_id": "Issue #923 / PR #924", "title": "Model Armor egress inspection skipped multimodal, system prompts, tool_calls & SSE", "severity": "high", "cwe": "CWE-284", "state": "resolved", "runtime": "python_pytest", "poc_ok": True, "ev": 1800.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    # 2. Anthropic — HackerOne (7 Findings: 3 High Duplicates, 4 Informative) + 4 Open Fix PRs
    {"id": "INV-06", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "#4235853", "title": "HTTP TRACE / TRACK Credential Echo Bypass", "severity": "high", "cwe": "CWE-200", "state": "duplicate", "runtime": "node_js", "poc_ok": True, "ev": 0.0, "stride": "Information Disclosure", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-07", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "#4235866", "title": "TLS ClientHello 0x0304..0x03ff Opaque Tunnel", "severity": "critical", "cwe": "CWE-436", "state": "informative", "runtime": "node_js", "poc_ok": True, "ev": 0.0, "stride": "Tampering", "verdict": "HARDENING_CANDIDATE_NOT_BOUNTY"},
    {"id": "INV-08", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "#4235876", "title": "Fragmented TLS ClientHello absent SNI", "severity": "low", "cwe": "CWE-436", "state": "informative", "runtime": "node_js", "poc_ok": True, "ev": 0.0, "stride": "Tampering", "verdict": "HARDENING_CANDIDATE_NOT_BOUNTY"},
    {"id": "INV-09", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "#4235881", "title": "Windows NTFS Junction Broker Follow (dup of #4032998)", "severity": "high", "cwe": "CWE-59", "state": "duplicate", "runtime": "windows_ntfs", "poc_ok": True, "ev": 0.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-10", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "#4235888", "title": "Windows Cross-Session OpenProcess(PROCESS_ALL_ACCESS) — working as designed", "severity": "high", "cwe": "CWE-269", "state": "informative", "runtime": "windows_ntfs", "poc_ok": True, "ev": 0.0, "stride": "Elevation of Privilege", "verdict": "DOCUMENTED_AS_DESIGNED"},
    {"id": "INV-11", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "#4235898", "title": ".zshenv & .zlogin Missing + Linux Pre-Seccomp Startup (dup of #4117258)", "severity": "high", "cwe": "CWE-732", "state": "duplicate", "runtime": "docker_container", "poc_ok": True, "ev": 0.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-12", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "#4235906", "title": "macOS Case-Insensitive APFS Seatbelt Bypass (did not repro on modern macOS)", "severity": "high", "cwe": "CWE-178", "state": "informative", "runtime": "macos_apfs", "poc_ok": False, "ev": 0.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-13", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "Issue #837 / PR #838", "title": "Windows NTFS Alternate Data Stream (:stream) & \\??\\ / \\Device\\ path-prefix bypass", "severity": "high", "cwe": "CWE-22", "state": "hardening_pr_only", "runtime": "windows_ntfs", "poc_ok": True, "ev": 0.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-14", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "Issue #839 / PR #841", "title": "Windows MXC spawnSandboxed bypassed rankWindowsFsAccess", "severity": "high", "cwe": "CWE-284", "state": "hardening_pr_only", "runtime": "windows_ntfs", "poc_ok": True, "ev": 0.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-15", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "Issue #840 / PR #854", "title": "Windows srt-win missing intermediate-directory pinning / ancestor rename bypass", "severity": "critical", "cwe": "CWE-363", "state": "hardening_pr_only", "runtime": "windows_ntfs", "poc_ok": True, "ev": 0.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-16", "program": "anthropic", "program_name": "Anthropic", "offers_bounties": True, "asset": "anthropics/sandbox-runtime", "remote_id": "Issue #847 / PR #852", "title": "Windows WSL2 NAT network egress bypass probe & opt-in WFP guard", "severity": "high", "cwe": "CWE-284", "state": "hardening_pr_only", "runtime": "windows_ntfs", "poc_ok": True, "ev": 0.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    # 3. Shopify (8 Findings)
    {"id": "INV-17", "program": "shopify", "program_name": "Shopify", "offers_bounties": True, "asset": "Shopify/deterministic-wasi-ctx@54933f4", "remote_id": "#4234525", "title": "Uninitialized Host Stack Memory Disclosure (11B/Event), Misaligned ptr::read UB & Host Panic in poll_oneoff", "severity": "high", "cwe": "CWE-908", "state": "submitted", "runtime": "rust_cargo", "poc_ok": True, "ev": 2850.0, "stride": "Information Disclosure", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-18", "program": "shopify", "program_name": "Shopify", "offers_bounties": True, "asset": "Shopify/function-runner@605ab69", "remote_id": "#4236500", "title": "Guest-Writable Provider Memory Enables Unchecked 4-12 GiB Host Heap Allocation (ResourceLimiter Bypass)", "severity": "high", "cwe": "CWE-770", "state": "queued_cooldown", "runtime": "rust_cargo", "poc_ok": True, "ev": 2400.0, "stride": "Denial of Service", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-19", "program": "shopify", "program_name": "Shopify", "offers_bounties": True, "asset": "Shopify/shopify-app-js@70e0d6b", "remote_id": "", "title": "OAuth Callback HMAC, Timestamp & state CSRF Bypass via Duplicate Query Parameter Differential", "severity": "high", "cwe": "CWE-345", "state": "needs_live_poc", "runtime": "node_js", "poc_ok": False, "ev": 1950.0, "stride": "Tampering", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-20", "program": "shopify", "program_name": "Shopify", "offers_bounties": True, "asset": "Shopify/shopify-app-python@8ea2f0d", "remote_id": "", "title": "Missing iss/dest Validation Allows Storefront Buyer JWTs to Authenticate as Merchant Admin & POS", "severity": "high", "cwe": "CWE-287", "state": "needs_live_poc", "runtime": "python_pytest", "poc_ok": False, "ev": 2250.0, "stride": "Spoofing", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-21", "program": "shopify", "program_name": "Shopify", "offers_bounties": True, "asset": "Shopify/checkout-sheet-kit-android@9abcc78", "remote_id": "", "title": "Unscoped @JavascriptInterface (window.android) & Cross-Frame ACTION_VIEW Intent Launch", "severity": "medium", "cwe": "CWE-749", "state": "needs_live_poc", "runtime": "android_jdk", "poc_ok": False, "ev": 1350.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-22", "program": "shopify", "program_name": "Shopify", "offers_bounties": True, "asset": "Shopify/hydrogen@b22b7ed", "remote_id": "", "title": "handleShopifyApiProxy (/__shopify/*) Unrestricted Proxy Bypasses handleSfapiProxy, UCP & CSP", "severity": "medium", "cwe": "CWE-284", "state": "needs_live_poc", "runtime": "node_js", "poc_ok": False, "ev": 1450.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-23", "program": "shopify", "program_name": "Shopify", "offers_bounties": True, "asset": "Shopify/rack-sanitizer@e4b2950", "remote_id": "", "title": "Stray-Percent Synthesis Bypasses UTF-8 Enforcement and Causes Double-Decode Differential", "severity": "medium", "cwe": "CWE-172", "state": "needs_live_poc", "runtime": "ruby", "poc_ok": False, "ev": 950.0, "stride": "Tampering", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-24", "program": "shopify", "program_name": "Shopify", "offers_bounties": True, "asset": "Shopify/ucp-cli@a214f10", "remote_id": "", "title": "Prototype Pollution via RFC 6901 --set JSON Pointer in buildOperationInput (local CLI hold)", "severity": "low", "cwe": "CWE-1321", "state": "do_not_submit", "runtime": "node_js", "poc_ok": False, "ev": 0.0, "stride": "Tampering", "verdict": "BOUNDARY_NOT_CROSSED"},
    # 4. Circle Arc (15 Findings: #25 closed Duplicate of #4035475 + 14 local drafts #26-#39)
    {"id": "INV-25", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/Malachite(started_round.rs)", "remote_id": "#4234132 (dup of #4035475)", "title": "Missing may_be_stored_as_undecided() Guard Enables Validator Bricking via Byzantine proposer block hash", "severity": "critical", "cwe": "CWE-841", "state": "duplicate", "runtime": "rust_cargo", "poc_ok": True, "ev": 0.0, "stride": "Denial of Service", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-26", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/Malachite(consensus)", "remote_id": "", "title": "Arc Malachite BFT Secondary Consensus / Chain-Halt Invariant Violation", "severity": "critical", "cwe": "CWE-841", "state": "held_cool_off", "runtime": "rust_cargo", "poc_ok": True, "ev": 4600.0, "stride": "Denial of Service", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-27", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/P2P(network)", "remote_id": "", "title": "Arc Rust Node P2P Eclipse Vulnerability in Peer Table Management", "severity": "high", "cwe": "CWE-400", "state": "held_cool_off", "runtime": "rust_cargo", "poc_ok": True, "ev": 2100.0, "stride": "Denial of Service", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-28", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/Precompile(pqc)", "remote_id": "", "title": "Unmetered Post-Quantum Precompile Decode Enables Unbounded Memory/CPU Exhaustion", "severity": "high", "cwe": "CWE-770", "state": "held_cool_off", "runtime": "rust_cargo", "poc_ok": True, "ev": 2300.0, "stride": "Denial of Service", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-29", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/NitroEnclave(remote-signer)", "remote_id": "", "title": "AWS Nitro Enclave Remote Signer KMS Attestation Binding Weakness", "severity": "high", "cwe": "CWE-345", "state": "held_cool_off", "runtime": "rust_cargo", "poc_ok": True, "ev": 2650.0, "stride": "Spoofing", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-30", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/Malachite(wal)", "remote_id": "", "title": "Malachite Consensus WAL Replay Integrity & Corruption Flaw", "severity": "high", "cwe": "CWE-345", "state": "held_cool_off", "runtime": "rust_cargo", "poc_ok": True, "ev": 2050.0, "stride": "Tampering", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-31", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/P2P(gossipsub)", "remote_id": "", "title": "Arc GossipSub Message Validation & Peer-Scoring Amplification Flaw", "severity": "high", "cwe": "CWE-841", "state": "held_cool_off", "runtime": "rust_cargo", "poc_ok": True, "ev": 1950.0, "stride": "Denial of Service", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-32", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/Consensus(high-6)", "remote_id": "", "title": "Arc Consensus / Remote Signer High-Severity Boundary Flaw (#6)", "severity": "high", "cwe": "CWE-863", "state": "held_cool_off", "runtime": "rust_cargo", "poc_ok": True, "ev": 1900.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-33", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/RPC(sync-1)", "remote_id": "", "title": "Arc RPC & State-Sync Boundary Defect #1", "severity": "medium", "cwe": "CWE-284", "state": "draft_local", "runtime": "rust_cargo", "poc_ok": False, "ev": 850.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-34", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/RPC(sync-2)", "remote_id": "", "title": "Arc RPC & State-Sync Boundary Defect #2", "severity": "medium", "cwe": "CWE-284", "state": "draft_local", "runtime": "rust_cargo", "poc_ok": False, "ev": 850.0, "stride": "Elevation of Privilege", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-35", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/RPC(sync-3)", "remote_id": "", "title": "Arc RPC & State-Sync Boundary Defect #3", "severity": "medium", "cwe": "CWE-20", "state": "draft_local", "runtime": "rust_cargo", "poc_ok": False, "ev": 800.0, "stride": "Tampering", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-36", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/RPC(sync-4)", "remote_id": "", "title": "Arc RPC & State-Sync Boundary Defect #4", "severity": "medium", "cwe": "CWE-20", "state": "draft_local", "runtime": "rust_cargo", "poc_ok": False, "ev": 800.0, "stride": "Tampering", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-37", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/RPC(sync-5)", "remote_id": "", "title": "Arc RPC & State-Sync Boundary Defect #5", "severity": "medium", "cwe": "CWE-841", "state": "draft_local", "runtime": "rust_cargo", "poc_ok": False, "ev": 780.0, "stride": "Denial of Service", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-38", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/RPC(sync-6)", "remote_id": "", "title": "Arc RPC & State-Sync Boundary Defect #6", "severity": "medium", "cwe": "CWE-841", "state": "draft_local", "runtime": "rust_cargo", "poc_ok": False, "ev": 780.0, "stride": "Denial of Service", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
    {"id": "INV-39", "program": "arc-bbp", "program_name": "Circle Arc", "offers_bounties": True, "asset": "Arc/RPC(sync-7)", "remote_id": "", "title": "Arc RPC & State-Sync Boundary Defect #7", "severity": "medium", "cwe": "CWE-200", "state": "draft_local", "runtime": "rust_cargo", "poc_ok": False, "ev": 750.0, "stride": "Information Disclosure", "verdict": "CASH_GRADE_BOUNDARY_VIOLATION"},
)


def seed_historical_findings_inventory(ticket_store: Any) -> Dict[str, Any]:
    """
    Idempotently imports all 39 empirical RFCHunt findings (Google, Anthropic, Shopify, Circle Arc)
    plus the verified paid HackerOne bounty programs into SQLite (`HackerOneTicketStore`).
    """
    from engine.hackerone_porter import HACKERONE_BASE_URL, HackerOneReportDraft

    programs = seed_verified_bounty_programs(ticket_store)
    imported = 0
    for item in _HISTORICAL_39_INVENTORY:
        handle = item["program"]
        fp = hashlib.sha256(f"inventory|{item['id']}|{handle}|{item['asset']}".encode("utf-8")).hexdigest()[:24]
        draft_id = f"H1-{handle.upper()}-{item['id']}"
        is_site_saved = bool(item["remote_id"].startswith("#") and item["state"] in ("queued_cooldown", "draft_saved_on_site"))
        draft = HackerOneReportDraft(
            draft_id=draft_id,
            fingerprint=fp,
            program_handle=handle,
            submit_url=f"{HACKERONE_BASE_URL}/{handle}/reports/new",
            title=item["title"][:140],
            weakness_cwe=item["cwe"],
            severity_rating=item["severity"],
            asset_identifier=item["asset"],
            evidence_lane="VERIFIED_EXPLOIT" if item["poc_ok"] else "DETERMINISTIC_STATIC",
            poe_level=3 if item["poc_ok"] else 2,
            vulnerability_information=item["title"],
            impact=item["title"],
            source_rule_id=item["id"],
            source_scanner="RFCHunt-HistoricalInventory",
            epistemic_status=(
                EpistemicStatus.PROVEN_RUNTIME.value if item["poc_ok"] else EpistemicStatus.PROVEN_STATIC_INVARIANT.value
            ),
            draft_only_cool_off=item["state"] in ("held_cool_off", "queued_cooldown"),
            site_draft_saved=is_site_saved,
            scope_match_status="in_scope",
        )
        ticket_store.upsert_draft(
            draft,
            state=item["state"],
            program_name=item["program_name"],
            offers_bounties=item["offers_bounties"],
            reason="imported_from_39_finding_inventory",
            actor="inventory_seeder",
            cash_ev_usd=item["ev"],
            expected_payout_usd=max(item["ev"], 0.0),
            p_valid=0.9 if item["poc_ok"] else 0.55,
            p_duplicate=0.5 if item["state"] == "duplicate" else 0.12,
            stride_category=item["stride"],
            stride_boundary_verdict=item["verdict"],
            required_runtime=item["runtime"],
            poc_verified_runtime=item["poc_ok"],
            remote_report_id=item["remote_id"],
        )
        imported += 1

    return {
        "status": "inventory_seeded",
        "programs_seeded": len(programs),
        "tickets_seeded": imported,
        "summary": ticket_store.get_state_summary(),
    }


__all__ = [
    "CASH_ARCHETYPE_CATALOG",
    "DEFAULT_VERIFIED_BOUNTY_PROGRAMS",
    "CashEvEvaluation",
    "DuplicateRiskAssessment",
    "RuntimePocAssessment",
    "assess_runtime_poc_readiness",
    "check_upstream_duplicate_risk",
    "estimate_program_duplicate_prior",
    "rank_submission_queue",
    "score_finding_cash_ev",
    "seed_historical_findings_inventory",
    "seed_verified_bounty_programs",
]
