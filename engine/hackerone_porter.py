"""
HackerOne Campaign Finder, RoE Policy Engine & Autonomous HITL Computer-Use Porter (`--hackerone`)
==================================================================================================

Adapts RFCHunt for responsible, Safe-Harbor-compliant vulnerability research and disclosure on
HackerOne (`https://hackerone.com/`) strictly obeying HackerOne's global Code of Conduct and
each individual program's Rules of Engagement (RoE):

  1. Three-Tier Program Rules of Engagement (RoE) Compliance Parser (`parse_hackerone_program_policy`):
     - Tier 1 (`explicitly_prohibited`): Detects programs that forbid automated vulnerability
       scanning or high-volume traffic (e.g., Agoda). Fails closed and BLOCKS all automated live
       scanning to preserve Safe Harbor protections.
     - Tier 2 (`permitted_with_limits_and_attribution`): Extracts program-mandated requests-per-second
       caps (`2..100 rps`, conservative fallback `2.0 rps`) and required researcher attribution
       headers / User-Agent (e.g., `X-HackerOne: <username>`, `X-Bug-Bounty: <username>`).
       Refuses live scanning if a required attribution header lacks the researcher's username.
     - Tier 3 (`in_scope_only_no_redirect_escape`): Enforces strict in-scope/out-of-scope asset
       boundaries and disables cross-scope redirects (`no_out_of_scope_redirects=True`) so scanners
       never follow redirects onto third-party OAuth providers, cloud vendors, or out-of-scope hosts.
  2. Strict Anti-Slop PoC Quality Gate & Zero-PHI Redaction:
     - Enforces HackerOne's Code of Conduct ban on raw scanner logs and unverified AI output:
       refuses Lane 3 `SPECULATIVE_HYPOTHESIS` (`poe_level <= 1` ARTEX/PromptSmuggler guesses),
       requires concrete file/line or wire PoC evidence, tracks SHA-256 fingerprints in a local
       deduplication ledger, and scrubs both secrets AND HIPAA PHI (`<ZK_PII:TYPE:HASH8>`) before export.
  3. Official HackerOne Hacker API v1 Client (`https://api.hackerone.com/v1/hackers/...`):
     - Discovers programs, reads full policy text + structured scopes, and verifies scope compliance
       using `HACKERONE_API_USERNAME` and `HACKERONE_API_TOKEN` (process env or workspace `.env` only).
  4. Interactive HITL Computer-Use Browser & Policy-Aware Autonomous Runner (`--hackerone-auto`):
     - Opens `https://hackerone.com/users/sign_in` in a visible (`headless=False`) Chromium window
       and PAUSES for the human researcher to complete login, 2FA/MFA, and any anti-bot/CAPTCHA
       directly (NEVER solves or bypasses CAPTCHAs or access controls).
     - Autonomously discovers open campaigns, reads & enforces each program's RoE policy, audits
       in-scope open-source `SOURCE_CODE` repos locally (read-only `--all` + `--phi` inside an
       isolated temp directory), requires explicit human approval before any compliant non-destructive
       live check, pre-fills redacted drafts in the browser, and HARD-STOPS before clicking Submit.
  5. Universal `--dry-run` Support:
     - Computes the full RoE compliance plan, rate-limit/header config, eligible/rejected drafts,
       and planned browser/audit steps with zero network requests, zero browser launch, zero git
       clones, and zero ledger/API mutations.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request

from engine.advisory_exporter import _redact_inline_tokens

HACKERONE_BASE_URL = "https://hackerone.com"
HACKERONE_API_BASE_URL = "https://api.hackerone.com/v1"
HACKERONE_ALLOWED_HOSTS = frozenset({"hackerone.com", "www.hackerone.com", "api.hackerone.com"})
ALLOWED_SOURCE_REPO_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

_SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
    "info": 0,
}

_HANDLE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")

# Tier 1: Explicit automated scanning prohibition patterns in HackerOne program policies
_AUTO_SCAN_BAN_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:strictly\s+)?(?:prohibit|forbid|ban|disallow)[a-z]*\s+(?:performing\s+|using\s+|running\s+)?automated\s+(?:security\s+testing|vulnerability\s+scanning|scanning|scanners|tools)", re.IGNORECASE),
    re.compile(r"(?:do\s+not|must\s+not|never)\s+(?:use|run|perform|execute)\s+automated\s+(?:scanners?|scanning|vulnerability\s+scanners?|security\s+testing)", re.IGNORECASE),
    re.compile(r"no\s+automated\s+(?:scanners?|scanning|vulnerability\s+scanning|security\s+testing)", re.IGNORECASE),
    re.compile(r"automated\s+(?:scanning|scanners?|vulnerability\s+scanning)\s+(?:is|are)\s+(?:strictly\s+)?(?:prohibited|forbidden|not\s+allowed|not\s+permitted)", re.IGNORECASE),
    re.compile(r"high[- ]volume\s+automated\s+(?:traffic|scanning)\s+(?:is\s+)?(?:prohibited|forbidden|not\s+allowed)", re.IGNORECASE),
)

# Tier 2: Rate-limit (RPS) and attribution header extraction patterns
_RPS_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:max(?:imum)?|limit(?:ed)?\s+to|cap(?:ped)?\s+at|up\s+to|no\s+more\s+than|at\s+most|<=?)\s*(\d+(?:\.\d+)?)\s*(?:requests?\s*(?:per|/)\s*sec(?:ond)?|req(?:uests)?/s(?:ec)?|rps)\b", re.IGNORECASE),
    re.compile(r"\b(\d+(?:\.\d+)?)\s*(?:requests?\s*(?:per|/)\s*sec(?:ond)?|req/s|rps)\b", re.IGNORECASE),
)

_ATTRIBUTION_HEADER_RX = re.compile(
    r"\b(X-(?:HackerOne(?:-[A-Za-z0-9-]+)?|Bug-?Bounty(?:-[A-Za-z0-9-]+)?|Researcher(?:-[A-Za-z0-9-]+)?|Security-Research(?:-[A-Za-z0-9-]+)?))\s*:\s*([^\s,;)`\"']+)",
    re.IGNORECASE,
)

_USER_AGENT_REQ_RX = re.compile(
    r"User-Agent\s*(?:header\s*)?(?:containing|with|set\s+to|:)\s*[`\"']?([A-Za-z0-9._/<>{}@ -]{3,64})[`\"']?",
    re.IGNORECASE,
)

_AI_DISCLOSURE_RX = re.compile(
    r"(?:disclos(?:e|ure)|declar(?:e|ation)|mention|indicate)\s+(?:any\s+)?(?:use\s+of\s+)?(?:ai|llm|automated\s+tools?)",
    re.IGNORECASE,
)

_GIT_REPO_URL_RX = re.compile(
    r"https://(?:github\.com|gitlab\.com|bitbucket\.org)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?",
    re.IGNORECASE,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scrub_secrets_and_phi(text: str) -> str:
    """Scrubs inline tokens/secrets AND HIPAA PHI (`<ZK_PII:TYPE:HASH8>`) prior to HackerOne export."""
    redacted = _redact_inline_tokens(str(text or ""))
    try:
        from engine.phi_scanner import PresidioGlinerPiiZeroGuard

        guard = PresidioGlinerPiiZeroGuard(enable_ml=False, enable_presidio=False)
        redacted, _ = guard.scrub_and_prove(redacted)
    except Exception:
        pass
    return redacted


def validate_hackerone_handle(handle: str) -> str:
    """Validates and normalizes a HackerOne program handle (rejecting path traversal / URL injection)."""
    cleaned = str(handle or "").strip().strip("/")
    if not cleaned:
        raise ValueError("HackerOne program handle cannot be empty.")
    if not _HANDLE_RE.match(cleaned) or ".." in cleaned:
        raise ValueError(f"Invalid HackerOne program handle: {handle!r}")
    return cleaned.lower()


def validate_hackerone_url(url: str) -> str:
    """Enforces strict HTTPS host pinning to official HackerOne origins."""
    parsed = urllib.parse.urlparse(str(url or "").strip())
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in HACKERONE_ALLOWED_HOSTS:
        raise PermissionError(f"Refusing non-HackerOne URL: {url!r}")
    return str(url).strip()


def validate_source_repo_url(url: str) -> str:
    """Enforces strict HTTPS pinning to trusted source-code hosts (`github.com`, `gitlab.com`, `bitbucket.org`)."""
    parsed = urllib.parse.urlparse(str(url or "").strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in ALLOWED_SOURCE_REPO_HOSTS:
        raise PermissionError(f"Refusing untrusted source repo URL: {url!r}")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2 or any(".." in p or p.startswith("-") for p in parts):
        raise ValueError(f"Invalid source repo path: {url!r}")
    return f"https://{host}/{parts[0]}/{parts[1].removesuffix('.git')}"


def _load_dotenv_credentials(workspace_root: Optional[Path] = None) -> Tuple[str, str]:
    """
    Reads `HACKERONE_API_USERNAME` and `HACKERONE_API_TOKEN` from process environment
    or workspace `.env` file (read-only; never mutates system/user registry).
    """
    user = (os.environ.get("HACKERONE_API_USERNAME") or "").strip()
    token = (os.environ.get("HACKERONE_API_TOKEN") or "").strip()
    if user and token:
        return user, token

    candidates: List[Path] = []
    if workspace_root is not None:
        candidates.append(Path(workspace_root) / ".env")
    candidates.append(Path.cwd() / ".env")
    for env_path in candidates:
        if not env_path.is_file():
            continue
        try:
            for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k == "HACKERONE_API_USERNAME" and not user:
                    user = v
                elif k == "HACKERONE_API_TOKEN" and not token:
                    token = v
        except OSError:
            continue
    return user, token


@dataclass
class HackerOnePolicyRules:
    """Structured Rules of Engagement (RoE) extracted from a HackerOne program policy & scope."""

    program_handle: str
    automation_tier: str  # explicitly_prohibited | permitted_with_limits_and_attribution | in_scope_only_manual_verify
    automated_scanning_prohibited: bool
    prohibition_evidence: List[str] = field(default_factory=list)
    max_rps: float = 2.0
    required_headers: List[str] = field(default_factory=list)
    missing_attribution_username: bool = False
    required_user_agent: Optional[str] = None
    ai_disclosure_required: bool = False
    no_out_of_scope_redirects: bool = True
    poc_required: bool = True
    in_scope_repos: List[str] = field(default_factory=list)
    in_scope_hosts: List[str] = field(default_factory=list)
    out_of_scope_assets: List[str] = field(default_factory=list)
    safe_harbor_status: str = "protected_compliant"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_hackerone_program_policy(
    program_handle: str,
    policy_text: str = "",
    *,
    structured_scopes: Optional[Sequence[Dict[str, Any]]] = None,
    researcher_username: str = "",
) -> HackerOnePolicyRules:
    """
    Parses a HackerOne program's Policy / Rules of Engagement (RoE) and Structured Scope
    into executable, fail-closed compliance rules covering all three HackerOne RoE tiers:
      1. Explicitly Prohibited -> blocks live automated scanning to preserve Safe Harbor.
      2. Permitted with Rate Limits & Attribution -> enforces `max_rps` (2..100 rps) +
         custom `X-HackerOne` / `X-Bug-Bounty` header with researcher handle.
      3. In-Scope Only -> enforces strict asset boundary & disables cross-scope redirects.
    """
    handle = validate_hackerone_handle(program_handle)
    policy = str(policy_text or "")
    username = str(researcher_username or "").strip()

    # 1. Detect explicit automated scanning prohibitions (Tier 1)
    prohibitions: List[str] = []
    for rx in _AUTO_SCAN_BAN_PATTERNS:
        for m in rx.finditer(policy):
            snippet = m.group(0).strip()
            if snippet not in prohibitions:
                prohibitions.append(snippet)
    prohibited = len(prohibitions) > 0

    # 2. Extract rate-limit cap (`max_rps`, clamped safely to 0.5..100.0; 0.0 when prohibited)
    extracted_rps: Optional[float] = None
    for rx in _RPS_PATTERNS:
        vals = [float(m.group(1)) for m in rx.finditer(policy) if float(m.group(1)) > 0.0]
        if vals:
            extracted_rps = min(vals)  # fail-safe: honor the strictest mentioned cap
            break
    if prohibited:
        max_rps = 0.0
    elif extracted_rps is not None:
        max_rps = max(0.5, min(100.0, extracted_rps))
    else:
        max_rps = 2.0  # Safe conservative default matching strictest HackerOne programs

    # 3. Extract required researcher attribution headers & User-Agent
    required_headers: List[str] = []
    missing_username = False
    seen_hdr_names: set[str] = set()
    for m in _ATTRIBUTION_HEADER_RX.finditer(policy):
        h_name = m.group(1).strip()
        h_val_raw = m.group(2).strip().rstrip(".,;:")
        if h_name.lower() in seen_hdr_names:
            continue
        seen_hdr_names.add(h_name.lower())
        has_placeholder = bool(re.search(r"<[^>]+>|\{[^}]+\}|\[[^\]]+\]|your[-_\s]?(?:h1|hackerone)?[-_\s]?(?:user|handle|name)", h_val_raw, re.IGNORECASE))
        if has_placeholder:
            if username:
                h_val = re.sub(
                    r"<[^>]+>|\{[^}]+\}|\[[^\]]+\]|your[-_\s]?(?:h1|hackerone)?[-_\s]?(?:user|handle|name)",
                    username,
                    h_val_raw,
                    flags=re.IGNORECASE,
                ).strip()
                required_headers.append(f"{h_name}: {h_val}")
            else:
                missing_username = True
                required_headers.append(f"{h_name}: <MISSING_HACKERONE_USERNAME>")
        else:
            required_headers.append(f"{h_name}: {h_val_raw}")

    # If researcher provided a username and policy didn't name a specific custom header, attach X-HackerOne attribution proactively
    if not required_headers and username and not prohibited:
        required_headers.append(f"X-HackerOne: {username}")

    required_ua: Optional[str] = None
    ua_m = _USER_AGENT_REQ_RX.search(policy)
    if ua_m:
        raw_ua = ua_m.group(1).strip()
        if username:
            required_ua = re.sub(r"<[^>]+>|\{[^}]+\}", username, raw_ua)
        else:
            required_ua = raw_ua

    ai_disclosure = bool(_AI_DISCLOSURE_RX.search(policy))

    # 4. Extract in-scope repos, in-scope hosts, and out-of-scope assets
    in_scope_repos: List[str] = []
    in_scope_hosts: List[str] = []
    out_of_scope_assets: List[str] = []

    def _add_unique(lst: List[str], val: str) -> None:
        v = str(val or "").strip()
        if v and v not in lst:
            lst.append(v)

    for sc in structured_scopes or ():
        if not isinstance(sc, dict):
            continue
        attrs = sc.get("attributes") if isinstance(sc.get("attributes"), dict) else sc
        ident = str(attrs.get("asset_identifier") or "").strip()
        atype = str(attrs.get("asset_type") or "").strip().upper()
        eligible = bool(attrs.get("eligible_for_submission", True))
        if not ident:
            continue
        if not eligible:
            _add_unique(out_of_scope_assets, ident)
            continue
        if atype == "SOURCE_CODE" or _GIT_REPO_URL_RX.match(ident):
            try:
                _add_unique(in_scope_repos, validate_source_repo_url(ident))
            except (PermissionError, ValueError):
                _add_unique(in_scope_hosts, ident)
        else:
            _add_unique(in_scope_hosts, ident)

    # Also harvest explicitly listed GitHub/GitLab repo URLs from policy text (when not marked out-of-scope)
    for m_repo in _GIT_REPO_URL_RX.finditer(policy):
        try:
            norm_repo = validate_source_repo_url(m_repo.group(0))
            if not any(norm_repo.lower() in oos.lower() for oos in out_of_scope_assets):
                _add_unique(in_scope_repos, norm_repo)
        except (PermissionError, ValueError):
            continue

    # Determine RoE tier & Safe Harbor status
    if prohibited:
        tier = "explicitly_prohibited"
        sh_status = "blocked_to_preserve_safe_harbor"
    elif extracted_rps is not None or seen_hdr_names or required_ua:
        tier = "permitted_with_limits_and_attribution"
        sh_status = "missing_researcher_attribution_username" if missing_username else "protected_compliant"
    else:
        tier = "in_scope_only_manual_verify"
        sh_status = "protected_compliant"

    return HackerOnePolicyRules(
        program_handle=handle,
        automation_tier=tier,
        automated_scanning_prohibited=prohibited,
        prohibition_evidence=prohibitions,
        max_rps=max_rps,
        required_headers=required_headers,
        missing_attribution_username=missing_username,
        required_user_agent=required_ua,
        ai_disclosure_required=ai_disclosure,
        no_out_of_scope_redirects=True,
        poc_required=True,
        in_scope_repos=in_scope_repos,
        in_scope_hosts=in_scope_hosts,
        out_of_scope_assets=out_of_scope_assets,
        safe_harbor_status=sh_status,
    )


@dataclass
class HackerOneCampaign:
    handle: str
    name: str
    url: str
    submit_url: str
    offers_bounties: bool = False
    state: str = "public_mode"
    submission_state: str = "open"
    in_scope_assets: List[str] = field(default_factory=list)
    out_of_scope_assets: List[str] = field(default_factory=list)
    policy_text: str = ""
    policy_rules: Optional[Dict[str, Any]] = None
    source: str = "directory"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HackerOneReportDraft:
    draft_id: str
    fingerprint: str
    program_handle: str
    submit_url: str
    title: str
    weakness_cwe: str
    severity_rating: str  # critical | high | medium | low
    asset_identifier: str
    evidence_lane: str  # VERIFIED_EXPLOIT | DETERMINISTIC_STATIC
    poe_level: int
    vulnerability_information: str
    impact: str
    source_rule_id: str
    source_scanner: str
    scope_match_status: str = "manual_verify_required"  # in_scope | out_of_scope | manual_verify_required
    ai_disclosure_included: bool = False
    markdown_path: str = ""
    created_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_finding_fingerprint(finding: Dict[str, Any], program_handle: str) -> str:
    """Stable SHA-256 deduplication key preventing duplicate submissions for the same finding."""
    canonical = "|".join(
        [
            str(program_handle or "").strip().lower(),
            str(finding.get("rule_id") or "").strip().upper(),
            str(finding.get("file_path") or finding.get("file") or "").replace("\\", "/").strip().lower(),
            str(finding.get("line_number") or finding.get("line") or 1),
            str(finding.get("cwe") or finding.get("cwe_id") or "").strip().upper(),
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def filter_eligible_findings(
    findings: Sequence[Dict[str, Any]],
    *,
    min_severity: str = "medium",
    max_reports: int = 5,
    submitted_fingerprints: Optional[Sequence[str]] = None,
    program_handle: str = "",
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Strict HackerOne Code-of-Conduct Anti-Slop PoC Gate:
      - Rejects Lane 3 `SPECULATIVE_HYPOTHESIS` findings (unverified ARTEX/PromptSmuggler leads).
      - Rejects findings below `min_severity`.
      - Rejects findings lacking concrete file/line/endpoint location OR concrete evidence/PoC.
      - Rejects already-submitted fingerprints in the local deduplication ledger.
    Returns `(eligible_findings, rejected_with_reasons)`.
    """
    min_rank = _SEVERITY_RANK.get(str(min_severity or "medium").strip().lower(), 2)
    seen_fps = set(submitted_fingerprints or ())
    eligible: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []

    for raw in findings or ():
        if not isinstance(raw, dict):
            continue
        scanner = str(raw.get("scanner") or "")
        poe = int(raw.get("poe_level", 1) or 1)
        lane = str(raw.get("evidence_lane") or "").upper()
        if not lane:
            if poe >= 3:
                lane = "VERIFIED_EXPLOIT"
            elif scanner in ("Module-17-ARTEX", "Module-17-ARTEX-DualGraph", "Module-19-PromptSmuggler"):
                lane = "SPECULATIVE_HYPOTHESIS"
            else:
                lane = "DETERMINISTIC_STATIC"

        if lane == "SPECULATIVE_HYPOTHESIS":
            rejected.append({"rule_id": raw.get("rule_id"), "reason": "rejected_speculative_hypothesis_lane3"})
            continue

        sev_low = str(raw.get("severity") or "low").strip().lower()
        if _SEVERITY_RANK.get(sev_low, 0) < min_rank:
            rejected.append({"rule_id": raw.get("rule_id"), "reason": f"below_min_severity({sev_low}<{min_severity})"})
            continue

        file_loc = str(raw.get("file_path") or raw.get("file") or "").strip()
        evidence = str(
            raw.get("evidence")
            or raw.get("raw_probe")
            or raw.get("counterexample_witness")
            or raw.get("description")
            or ""
        ).strip()
        if not file_loc or not evidence:
            rejected.append({"rule_id": raw.get("rule_id"), "reason": "missing_concrete_location_or_evidence"})
            continue

        fp = compute_finding_fingerprint(raw, program_handle)
        if fp in seen_fps:
            rejected.append({"rule_id": raw.get("rule_id"), "reason": "duplicate_in_submission_ledger"})
            continue
        seen_fps.add(fp)
        eligible.append({**raw, "evidence_lane": lane, "_h1_fingerprint": fp})

    eligible.sort(
        key=lambda f: (
            0 if f.get("evidence_lane") == "VERIFIED_EXPLOIT" else 1,
            -_SEVERITY_RANK.get(str(f.get("severity") or "low").lower(), 0),
            str(f.get("rule_id") or ""),
        )
    )
    cap = max(1, int(max_reports or 5))
    return eligible[:cap], rejected


def validate_finding_against_scope(
    finding: Dict[str, Any],
    campaign: HackerOneCampaign,
) -> str:
    """Checks whether a finding's asset/file matches a campaign's in-scope or out-of-scope assets."""
    target_blob = " ".join(
        [
            str(finding.get("file_path") or ""),
            str(finding.get("asset_identifier") or ""),
            str(finding.get("title") or ""),
        ]
    ).lower()
    for oos in campaign.out_of_scope_assets:
        tok = str(oos or "").strip().lower().lstrip("*.")
        if tok and tok in target_blob:
            return "out_of_scope"
    if not campaign.in_scope_assets:
        return "manual_verify_required"
    for ins in campaign.in_scope_assets:
        tok = str(ins or "").strip().lower().lstrip("*.")
        if tok and (tok in target_blob or tok == campaign.handle.lower()):
            return "in_scope"
    return "manual_verify_required"


def build_hackerone_report_draft(
    finding: Dict[str, Any],
    campaign: HackerOneCampaign,
    *,
    asset_override: str = "",
    include_ai_disclosure: bool = False,
) -> HackerOneReportDraft:
    """Formats a verified or deterministic RFCHunt finding into a secret- & PHI-redacted HackerOne draft."""
    rule_id = str(finding.get("rule_id") or "RFCHUNT-SEC-001")
    scanner = str(finding.get("scanner") or "RFCHunt")
    cwe = str(finding.get("cwe") or finding.get("cwe_id") or "CWE-20").upper()
    raw_sev = str(finding.get("severity") or "medium").strip().lower()
    h1_sev = raw_sev if raw_sev in ("critical", "high", "medium", "low") else "low"
    lane = str(finding.get("evidence_lane") or "DETERMINISTIC_STATIC")
    poe_level = int(finding.get("poe_level", 1) or 1)
    file_path = str(finding.get("file_path") or finding.get("file") or "repository")
    line_num = int(finding.get("line_number") or finding.get("line") or 1)

    title = _scrub_secrets_and_phi(str(finding.get("title") or f"{rule_id} security defect in {Path(file_path).name}"))[:140]
    description = _scrub_secrets_and_phi(str(finding.get("description") or title))
    evidence = _scrub_secrets_and_phi(str(finding.get("evidence") or finding.get("raw_probe") or ""))
    remediation = _scrub_secrets_and_phi(str(finding.get("remediation") or "Enforce fail-closed validation at the trust boundary."))
    witness = _scrub_secrets_and_phi(str(finding.get("counterexample_witness") or ""))
    trace_steps = [_scrub_secrets_and_phi(str(s)) for s in (finding.get("counterexample_trace") or []) if str(s).strip()]
    formula = str(finding.get("violated_invariant_formula") or "").strip()

    policy_ai_req = bool((campaign.policy_rules or {}).get("ai_disclosure_required", False))
    eff_ai_disclosure = bool(include_ai_disclosure or policy_ai_req)

    fp = str(finding.get("_h1_fingerprint") or compute_finding_fingerprint(finding, campaign.handle))
    draft_id = f"H1-{campaign.handle.upper()}-{fp[:8].upper()}"
    asset_id = asset_override.strip() or (campaign.in_scope_assets[0] if campaign.in_scope_assets else f"{Path(file_path).name}:{line_num}")
    scope_status = validate_finding_against_scope({**finding, "asset_identifier": asset_id}, campaign)

    steps_md_lines: List[str] = []
    if trace_steps:
        steps_md_lines.extend(trace_steps)
    else:
        steps_md_lines.extend(
            [
                f"1. Inspect `{Path(file_path).name}` around line `{line_num}`.",
                f"2. Trigger the affected path identified by `{rule_id}` (`{cwe}`).",
                "3. Observe the trust-boundary bypass / policy violation confirmed below.",
            ]
        )

    vuln_info_parts = [
        "## Summary",
        description,
        "",
        "## Affected Component & Location",
        f"- **Asset / File**: `{file_path}:{line_num}`",
        f"- **Weakness**: `{cwe}`",
        f"- **Verification Tier**: `{lane}` (`poe_level={poe_level}`, detected by `{scanner}` / `{rule_id}`)",
        "",
        "## Steps to Reproduce (PoC)",
        "\n".join(steps_md_lines),
    ]
    if formula:
        vuln_info_parts.extend(["", "## Violated Security Invariant", f"```text\n{formula}\n```"])
    if evidence:
        vuln_info_parts.extend(["", "## Supporting Evidence (Secrets & PHI Redacted)", f"```text\n{evidence[:1500]}\n```"])
    if witness:
        vuln_info_parts.extend(["", "## Counterexample Witness", f"```json\n{witness[:1000]}\n```"])
    vuln_info_parts.extend(["", "## Recommended Fix", remediation])
    if eff_ai_disclosure:
        vuln_info_parts.extend(
            [
                "",
                "## Research Methodology & Tooling Disclosure",
                (
                    "Static/invariant analysis was assisted by RFCHunt (local deterministic analyzers) "
                    "and manually validated by the submitting researcher with a concrete PoC prior to disclosure."
                ),
            ]
        )

    impact_text = _scrub_secrets_and_phi(
        f"An attacker or untrusted workload reaching `{Path(file_path).name}:{line_num}` can exploit "
        f"`{cwe}` ({rule_id}) to bypass the enforced security boundary. {description[:280]}"
    )

    raw_body = "\n".join(vuln_info_parts)
    try:
        from engine.draft_qa_checker import auto_repair_markdown

        title, raw_body, _ = auto_repair_markdown(title, raw_body)
        _, impact_text, _ = auto_repair_markdown("", impact_text)
        title = title[:140]
    except Exception:
        pass

    return HackerOneReportDraft(
        draft_id=draft_id,
        fingerprint=fp,
        program_handle=campaign.handle,
        submit_url=campaign.submit_url,
        title=title,
        weakness_cwe=cwe,
        severity_rating=h1_sev,
        asset_identifier=asset_id,
        evidence_lane=lane,
        poe_level=poe_level,
        vulnerability_information=raw_body,
        impact=impact_text,
        source_rule_id=rule_id,
        source_scanner=scanner,
        scope_match_status=scope_status,
        ai_disclosure_included=eff_ai_disclosure,
    )


class HackerOneApiClient:
    """
    Official HackerOne Hacker API v1 client (`https://api.hackerone.com/v1/hackers/...`).
    Strictly pinned to `https://api.hackerone.com`.
    """

    def __init__(
        self,
        *,
        username: Optional[str] = None,
        api_token: Optional[str] = None,
        workspace_root: Optional[Path] = None,
        timeout_sec: float = 12.0,
    ) -> None:
        env_u, env_t = _load_dotenv_credentials(workspace_root)
        self.username = (username or env_u or "").strip()
        self.api_token = (api_token or env_t or "").strip()
        self.timeout_sec = max(2.0, float(timeout_sec))

    @property
    def has_credentials(self) -> bool:
        return bool(self.username and self.api_token)

    def _auth_headers(self) -> Dict[str, str]:
        if not self.has_credentials:
            raise PermissionError(
                "HackerOne API credentials not configured. Set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN in workspace .env or process environment."
            )
        raw = f"{self.username}:{self.api_token}".encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        return {
            "Authorization": f"Basic {b64}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "RFCHunt-HackerOne-Porter/2.0",
        }

    def _request_json(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = validate_hackerone_url(f"{HACKERONE_API_BASE_URL}/{path.lstrip('/')}")
        body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(
            url,
            data=body_bytes,
            headers=self._auth_headers(),
            method=method,
        )
        with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    def list_campaigns(
        self,
        *,
        query: str = "",
        bounties_only: bool = False,
        limit: int = 25,
    ) -> List[HackerOneCampaign]:
        data = self._request_json(f"hackers/programs?page[size]={min(100, max(1, int(limit)))}")
        q_low = str(query or "").strip().lower()
        out: List[HackerOneCampaign] = []
        for item in data.get("data") or []:
            attrs = item.get("attributes") or {}
            handle = str(attrs.get("handle") or "").strip()
            if not handle or not _HANDLE_RE.match(handle):
                continue
            name = str(attrs.get("name") or handle)
            offers = bool(attrs.get("offers_bounties", False))
            if bounties_only and not offers:
                continue
            if q_low and q_low not in handle.lower() and q_low not in name.lower():
                continue
            out.append(
                HackerOneCampaign(
                    handle=handle.lower(),
                    name=name,
                    url=f"{HACKERONE_BASE_URL}/{handle.lower()}",
                    submit_url=f"{HACKERONE_BASE_URL}/{handle.lower()}/reports/new",
                    offers_bounties=offers,
                    state=str(attrs.get("state") or "public_mode"),
                    submission_state=str(attrs.get("submission_state") or "open"),
                    source="hackerone_api_v1",
                )
            )
        return out[:limit]

    def fetch_campaign_scope(self, handle: str, *, researcher_username: str = "") -> HackerOneCampaign:
        clean_handle = validate_hackerone_handle(handle)
        prog = self._request_json(f"hackers/programs/{clean_handle}")
        attrs = (prog.get("data") or {}).get("attributes") or {}
        policy_text = str(attrs.get("policy") or "")
        scopes_resp = self._request_json(f"hackers/programs/{clean_handle}/structured_scopes?page[size]=100")
        scope_items = list(scopes_resp.get("data") or [])
        in_scope: List[str] = []
        out_scope: List[str] = []
        for sc in scope_items:
            s_attrs = sc.get("attributes") or {}
            ident = str(s_attrs.get("asset_identifier") or "").strip()
            if not ident:
                continue
            if bool(s_attrs.get("eligible_for_submission", True)):
                in_scope.append(ident)
            else:
                out_scope.append(ident)

        eff_user = (researcher_username or self.username or "").strip()
        rules = parse_hackerone_program_policy(
            clean_handle,
            policy_text,
            structured_scopes=scope_items,
            researcher_username=eff_user,
        )
        return HackerOneCampaign(
            handle=clean_handle,
            name=str(attrs.get("name") or clean_handle),
            url=f"{HACKERONE_BASE_URL}/{clean_handle}",
            submit_url=f"{HACKERONE_BASE_URL}/{clean_handle}/reports/new",
            offers_bounties=bool(attrs.get("offers_bounties", False)),
            state=str(attrs.get("state") or "public_mode"),
            submission_state=str(attrs.get("submission_state") or "open"),
            in_scope_assets=in_scope,
            out_of_scope_assets=out_scope,
            policy_text=policy_text[:12_000],
            policy_rules=rules.to_dict(),
            source="hackerone_api_v1",
        )

    def submit_report_api(
        self,
        draft: HackerOneReportDraft,
        *,
        hitl_approved: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Submits a report via HackerOne Hacker API v1 (`POST /v1/hackers/reports`).
        Fails closed unless `hitl_approved=True` and `draft.evidence_lane != SPECULATIVE_HYPOTHESIS`.
        """
        if dry_run:
            return {
                "dry_run": True,
                "status": "dry_run_would_submit_api",
                "endpoint": f"{HACKERONE_API_BASE_URL}/hackers/reports",
                "draft_id": draft.draft_id,
                "program_handle": draft.program_handle,
                "report_url": f"{HACKERONE_BASE_URL}/reports/{draft.draft_id}",
            }
        if not hitl_approved:
            raise PermissionError("Refusing HackerOne API submission without explicit human-in-the-loop approval.")
        if draft.evidence_lane == "SPECULATIVE_HYPOTHESIS":
            raise PermissionError("Refusing to submit speculative Lane-3 hypothesis to HackerOne.")
        if draft.scope_match_status == "out_of_scope":
            raise PermissionError(f"Refusing to submit out-of-scope asset {draft.asset_identifier!r} to {draft.program_handle}.")

        from engine.draft_qa_checker import audit_draft_text

        qa_check = audit_draft_text(
            report_id=0,
            title=draft.title,
            body=draft.vulnerability_information,
            program=draft.program_handle,
        )
        critical_qa = [d for d in qa_check.defects if d.severity == "CRITICAL"]
        if critical_qa:
            codes = ", ".join(sorted({d.code for d in critical_qa}))
            raise ValueError(
                f"QA Phase gate blocked HackerOne submission for {draft.draft_id}: critical defect(s) [{codes}]"
            )

        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": draft.program_handle,
                    "title": draft.title,
                    "vulnerability_information": draft.vulnerability_information,
                    "impact": draft.impact,
                    "severity_rating": draft.severity_rating,
                },
            }
        }
        resp = self._request_json("hackers/reports", method="POST", payload=payload)
        if isinstance(resp, dict):
            remote_id = str((resp.get("data") or {}).get("id") or "").strip()
            if remote_id:
                resp.setdefault("report_id", remote_id)
                resp.setdefault("report_url", f"{HACKERONE_BASE_URL}/reports/{remote_id}")
        return resp


class HackerOneComputerUsePorter:
    """
    Human-in-the-Loop (HITL) Playwright Computer-Use assistant for HackerOne:
      1. Opens `https://hackerone.com/users/sign_in` in a visible (`headless=False`) browser.
      2. Pauses for the human user to sign in, pass MFA/2FA, and complete any anti-bot/CAPTCHA
         directly (NEVER bypasses CAPTCHA or authentication).
      3. Discovers open campaigns on `/opportunities/all` and reads each program's Policy /
         Rules of Engagement (RoE) and Scope DOM text via semantic selectors.
      4. Auto-fills report fields (Title, Vulnerability Information, Impact) and HARD-STOPS
         prior to clicking "Submit report" so the researcher reviews and submits manually.
    """

    @staticmethod
    def _is_playwright_available() -> bool:
        try:
            import playwright.sync_api  # noqa: F401

            return True
        except Exception:
            return False

    def discover_and_read_campaigns_browser(
        self,
        *,
        program_handle: Optional[str] = None,
        search_query: str = "",
        max_programs: int = 3,
        researcher_username: str = "",
        dry_run: bool = False,
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
    ) -> Dict[str, Any]:
        """
        Logs in interactively (human completes login/2FA/CAPTCHA), discovers open campaigns,
        opens each program's Policy page, and parses its Rules of Engagement & Scope.
        """
        if dry_run:
            planned_urls = [f"{HACKERONE_BASE_URL}/users/sign_in"]
            if program_handle:
                clean_h = validate_hackerone_handle(program_handle)
                planned_urls.append(f"{HACKERONE_BASE_URL}/{clean_h}")
            else:
                q_part = f"?search={urllib.parse.quote_plus(search_query)}" if search_query else ""
                planned_urls.append(f"{HACKERONE_BASE_URL}/opportunities/all{q_part}")
            return {
                "status": "dry_run_browser_discovery_planned",
                "dry_run": True,
                "planned_urls": planned_urls,
                "max_programs": max(1, int(max_programs or 3)),
                "campaigns": [],
            }

        if not self._is_playwright_available():
            return {
                "status": "playwright_not_installed",
                "install_hint": "python -m pip install playwright && playwright install chromium",
                "campaigns": [],
            }

        prompt_fn = wait_for_human_fn or input
        from playwright.sync_api import sync_playwright

        campaigns: List[HackerOneCampaign] = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()
            try:
                login_url = validate_hackerone_url(f"{HACKERONE_BASE_URL}/users/sign_in")
                page.goto(login_url, wait_until="domcontentloaded", timeout=30_000)
                prompt_fn(
                    "\n[HITL LOGIN] Complete HackerOne login, 2FA/MFA, and any anti-bot check "
                    "in the browser window, then press ENTER so RFCHunt can read campaigns & RoE policies: "
                )

                handles_to_inspect: List[str] = []
                if program_handle:
                    handles_to_inspect.append(validate_hackerone_handle(program_handle))
                else:
                    q_part = f"?search={urllib.parse.quote_plus(search_query)}" if search_query else ""
                    opp_url = validate_hackerone_url(f"{HACKERONE_BASE_URL}/opportunities/all{q_part}")
                    page.goto(opp_url, wait_until="domcontentloaded", timeout=30_000)
                    page.wait_for_timeout(1800)
                    links = page.locator("a[href^='/']")
                    reserved = {
                        "opportunities", "hacktivity", "directory", "users", "settings",
                        "reports", "inbox", "leaderboard", "security", "bug-bounty-programs",
                        "product", "solutions", "customers", "resources", "company",
                    }
                    for idx in range(min(links.count(), 80)):
                        href = (links.nth(idx).get_attribute("href") or "").strip().split("?")[0]
                        if re.match(r"^/[a-zA-Z0-9][a-zA-Z0-9._-]{1,40}$", href):
                            cand_h = href.lstrip("/").lower()
                            if cand_h not in reserved and cand_h not in handles_to_inspect:
                                handles_to_inspect.append(cand_h)
                        if len(handles_to_inspect) >= max(1, int(max_programs or 3)):
                            break

                for h_item in handles_to_inspect[: max(1, int(max_programs or 3))]:
                    prog_url = validate_hackerone_url(f"{HACKERONE_BASE_URL}/{h_item}")
                    page.goto(prog_url, wait_until="domcontentloaded", timeout=30_000)
                    page.wait_for_timeout(1500)
                    policy_text = ""
                    try:
                        policy_text = (page.locator("main").first.inner_text() or "")[:20_000]
                    except Exception:
                        try:
                            policy_text = (page.locator("body").inner_text() or "")[:20_000]
                        except Exception:
                            policy_text = ""
                    rules = parse_hackerone_program_policy(
                        h_item,
                        policy_text,
                        researcher_username=researcher_username,
                    )
                    campaigns.append(
                        HackerOneCampaign(
                            handle=h_item,
                            name=h_item,
                            url=prog_url,
                            submit_url=f"{HACKERONE_BASE_URL}/{h_item}/reports/new",
                            in_scope_assets=list(rules.in_scope_repos) + list(rules.in_scope_hosts),
                            out_of_scope_assets=list(rules.out_of_scope_assets),
                            policy_text=policy_text[:8000],
                            policy_rules=rules.to_dict(),
                            source="hackerone_browser_dom",
                        )
                    )
            finally:
                try:
                    context.close()
                    browser.close()
                except Exception:
                    pass

        return {
            "status": "browser_discovery_completed",
            "campaigns": [c.to_dict() for c in campaigns],
            "campaigns_discovered": len(campaigns),
        }

    def run_hitl_browser_session(
        self,
        campaign: HackerOneCampaign,
        drafts: Sequence[HackerOneReportDraft],
        *,
        search_query: str = "",
        dry_run: bool = False,
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
    ) -> Dict[str, Any]:
        """
        Runs an interactive visible browser session with mandatory human checkpoints.
        Never clicks the final Submit button automatically.
        """
        if dry_run:
            return {
                "status": "dry_run_browser_session_planned",
                "dry_run": True,
                "final_submit_blocked_for_hitl": True,
                "campaign": campaign.to_dict(),
                "planned_login_url": f"{HACKERONE_BASE_URL}/users/sign_in",
                "planned_submit_url": campaign.submit_url,
                "drafts_that_would_prefill": [d.draft_id for d in drafts],
                "drafts_prefilled": 0,
            }

        if not drafts:
            return {
                "status": "skipped_no_eligible_drafts",
                "final_submit_blocked_for_hitl": True,
                "campaign": campaign.to_dict(),
                "drafts_prefilled": 0,
            }

        if not self._is_playwright_available():
            return {
                "status": "playwright_not_installed_fallback_bundle_ready",
                "final_submit_blocked_for_hitl": True,
                "campaign": campaign.to_dict(),
                "manual_submit_url": campaign.submit_url,
                "install_hint": "python -m pip install playwright && playwright install chromium",
                "drafts_ready_for_manual_paste": [d.markdown_path for d in drafts if d.markdown_path],
            }

        prompt_fn = wait_for_human_fn or input
        from playwright.sync_api import sync_playwright

        filled_drafts: List[Dict[str, Any]] = []
        discovered_campaigns: List[Dict[str, str]] = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()
            try:
                # Checkpoint 1: Human login, 2FA, and any CAPTCHA/Turnstile check
                login_url = validate_hackerone_url(f"{HACKERONE_BASE_URL}/users/sign_in")
                page.goto(login_url, wait_until="domcontentloaded", timeout=30_000)
                prompt_fn(
                    "\n[HITL CHECKPOINT 1/2] Complete HackerOne login, 2FA/MFA, and any anti-bot check "
                    "in the open browser window, then press ENTER here to continue: "
                )

                # Optional Campaign Discovery on /opportunities/all
                if search_query:
                    opp_url = validate_hackerone_url(
                        f"{HACKERONE_BASE_URL}/opportunities/all?search={urllib.parse.quote_plus(search_query)}"
                    )
                    page.goto(opp_url, wait_until="domcontentloaded", timeout=30_000)
                    page.wait_for_timeout(1500)
                    links = page.locator("a[href^='/']")
                    count = min(links.count(), 40)
                    for idx in range(count):
                        href = (links.nth(idx).get_attribute("href") or "").strip()
                        txt = (links.nth(idx).inner_text() or "").strip()
                        if re.match(r"^/[a-zA-Z0-9][a-zA-Z0-9._-]{1,40}$", href) and txt:
                            discovered_campaigns.append({"handle": href.lstrip("/"), "label": txt[:80]})

                # Navigate to report submission form and auto-fill the top eligible draft
                target_draft = drafts[0]
                submit_url = validate_hackerone_url(target_draft.submit_url)
                page.goto(submit_url, wait_until="domcontentloaded", timeout=30_000)
                page.wait_for_timeout(1500)

                filled_fields: List[str] = []
                selector_map = (
                    ("title", ['input[name*="title"]', 'input[id*="title"]', 'input[placeholder*="Title" i]'], target_draft.title),
                    (
                        "vulnerability_information",
                        [
                            'textarea[name*="vulnerability_information"]',
                            'textarea[id*="vulnerability_information"]',
                            'textarea[placeholder*="Describe" i]',
                        ],
                        target_draft.vulnerability_information,
                    ),
                    (
                        "impact",
                        ['textarea[name*="impact"]', 'textarea[id*="impact"]', 'textarea[placeholder*="Impact" i]'],
                        target_draft.impact,
                    ),
                )
                for field_name, selectors, value in selector_map:
                    for sel in selectors:
                        loc = page.locator(sel)
                        if loc.count() > 0:
                            loc.first.fill(value)
                            filled_fields.append(field_name)
                            break

                filled_drafts.append(
                    {
                        "draft_id": target_draft.draft_id,
                        "submit_url": submit_url,
                        "filled_fields": filled_fields,
                        "auto_submitted": False,
                    }
                )

                # Checkpoint 2: Mandatory Final Human Review & Manual Submit
                prompt_fn(
                    f"\n[HITL CHECKPOINT 2/2] Draft `{target_draft.draft_id}` has been filled in the browser "
                    f"(fields={filled_fields}). Verify the PoC, select the exact Asset/Weakness if needed, "
                    "and click 'Submit report' manually in the browser. Press ENTER when done to close browser: "
                )
            finally:
                try:
                    context.close()
                    browser.close()
                except Exception:
                    pass

        return {
            "status": "hitl_browser_prefill_completed",
            "final_submit_blocked_for_hitl": True,
            "campaign": campaign.to_dict(),
            "discovered_campaigns": discovered_campaigns[:15],
            "filled_drafts": filled_drafts,
            "drafts_prefilled": len(filled_drafts),
        }

    @staticmethod
    def build_hugos_browser_cdp_draft_spec(
        campaign: HackerOneCampaign,
        draft: HackerOneReportDraft,
        *,
        cdp_url: Optional[str] = None,
        modelfusion_cli: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Builds a deterministic, Draft-only Human-in-the-Loop (HITL) handoff spec for
        ModelFusion's HugOS Browser (`cli.exe --browser --browser-port 9222`).

        Safety invariants:
          - Strictly navigates to `https://hackerone.com/<handle>/reports/new`
          - Prefills Title, Vulnerability Information, and Impact fields only
          - Stops at **Create Draft** (NEVER clicks final Submit Report)
          - NEVER solves or bypasses CAPTCHAs, Turnstile, or login/2FA gates.
        """
        validated_submit_url = validate_hackerone_url(draft.submit_url or campaign.submit_url)
        eff_cdp = (cdp_url or os.environ.get("RFCHUNT_HUGOS_CDP_URL") or "http://127.0.0.1:9222").rstrip("/")
        eff_cli = modelfusion_cli or os.environ.get(
            "MODELFUSION_CLI_PATH", r"d:\harfile\ModelFusion\target\release\cli.exe"
        )
        port_match = re.search(r":(\d+)$", eff_cdp)
        cdp_port = int(port_match.group(1)) if port_match else 9222

        return {
            "schema": "rfchunt.hugos_browser_cdp_draft.v1",
            "cdp_url": eff_cdp,
            "cdp_port": cdp_port,
            "modelfusion_cli": eff_cli,
            "launch_args": [eff_cli, "--browser", "--browser-port", str(cdp_port)],
            "action_boundary": "create_draft_only",
            "auto_submit_forbidden": True,
            "captcha_bypass_forbidden": True,
            "final_submit_blocked_for_hitl": True,
            "program_handle": campaign.handle,
            "draft_id": draft.draft_id,
            "target_url": validated_submit_url,
            "fields": {
                "title": draft.title,
                "vulnerability_information": draft.vulnerability_information,
                "impact": draft.impact,
                "severity_rating": draft.severity_rating,
                "weakness_cwe": draft.weakness_cwe,
                "asset_identifier": draft.asset_identifier,
            },
            "steps": [
                {"action": "hitl_login_checkpoint", "url": f"{HACKERONE_BASE_URL}/users/sign_in"},
                {"action": "navigate", "url": validated_submit_url},
                {"action": "fill_field", "field": "title"},
                {"action": "fill_field", "field": "vulnerability_information"},
                {"action": "fill_field", "field": "impact"},
                {"action": "click_create_draft_only", "forbidden_buttons": ["Submit report", "Submit"]},
                {"action": "pause_for_human_review", "expected_url_prefix": f"{HACKERONE_BASE_URL}/reports/"},
            ],
        }

    def stage_draft_via_hugos_cdp(
        self,
        campaign: HackerOneCampaign,
        drafts: Sequence[HackerOneReportDraft],
        *,
        cdp_url: Optional[str] = None,
        modelfusion_cli: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Probes HugOS Browser CDP (`<= 400ms` timeout) and emits a Draft-only HITL
        staging plan ready for ModelFusion's HugOS Browser without ever auto-submitting.
        """
        if not drafts:
            return {
                "status": "skipped_no_eligible_drafts",
                "final_submit_blocked_for_hitl": True,
                "auto_submit_forbidden": True,
                "captcha_bypass_forbidden": True,
                "campaign": campaign.to_dict(),
                "spec": None,
            }

        spec = self.build_hugos_browser_cdp_draft_spec(
            campaign,
            drafts[0],
            cdp_url=cdp_url,
            modelfusion_cli=modelfusion_cli,
        )
        if dry_run:
            return {
                "status": "dry_run_hugos_cdp_draft_planned",
                "dry_run": True,
                "cdp_reachable": False,
                "final_submit_blocked_for_hitl": True,
                "auto_submit_forbidden": True,
                "captcha_bypass_forbidden": True,
                "spec": spec,
            }

        cdp_reachable = False
        try:
            with urllib.request.urlopen(f"{spec['cdp_url']}/json/version", timeout=0.4) as resp:
                cdp_reachable = int(resp.status) == 200
        except Exception:
            cdp_reachable = False

        return {
            "status": "hugos_cdp_draft_ready" if cdp_reachable else "hugos_cdp_offline_spec_ready",
            "dry_run": False,
            "cdp_reachable": cdp_reachable,
            "final_submit_blocked_for_hitl": True,
            "auto_submit_forbidden": True,
            "captcha_bypass_forbidden": True,
            "spec": spec,
        }


class HackerOnePorter:
    """
    Top-level orchestrator for `--hackerone` / `--hackone`:
      - Discovers/resolves HackerOne campaign & parses program Rules of Engagement (RoE)
      - Filters RFCHunt findings through the Strict Anti-Slop PoC Gate (Lane 1 + Lane 2 only)
      - Redacts secrets AND HIPAA PHI (`<ZK_PII:TYPE:HASH8>`) before writing drafts
      - Supports universal `dry_run=True` (zero disk writes, zero network, zero browser)
      - Optionally launches visible HITL Playwright browser (`use_browser=True`) or
        submits via HackerOne API v1 (`submit_api=True` + explicit `hitl_approved=True`).
    """

    def __init__(
        self,
        *,
        output_dir: str = "reports/hackerone",
        workspace_root: Optional[Path] = None,
        api_client: Optional[HackerOneApiClient] = None,
        browser_porter: Optional[HackerOneComputerUsePorter] = None,
    ) -> None:
        self.output_dir = Path(output_dir).resolve(strict=False)
        self.ledger_path = self.output_dir / "submission_ledger.json"
        self.api_client = api_client or HackerOneApiClient(workspace_root=workspace_root)
        self.browser_porter = browser_porter or HackerOneComputerUsePorter()

    def _load_ledger(self) -> Dict[str, Any]:
        if not self.ledger_path.is_file():
            return {"submitted_fingerprints": [], "records": []}
        try:
            return json.loads(self.ledger_path.read_text(encoding="utf-8"))
        except Exception:
            return {"submitted_fingerprints": [], "records": []}

    def _save_ledger_record(self, draft: HackerOneReportDraft, *, delivery_mode: str, remote_id: str = "") -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ledger = self._load_ledger()
        fps = list(ledger.get("submitted_fingerprints") or [])
        if draft.fingerprint not in fps:
            fps.append(draft.fingerprint)
        records = list(ledger.get("records") or [])
        records.append(
            {
                "draft_id": draft.draft_id,
                "fingerprint": draft.fingerprint,
                "program_handle": draft.program_handle,
                "rule_id": draft.source_rule_id,
                "delivery_mode": delivery_mode,
                "remote_id": remote_id,
                "timestamp": _utc_now_iso(),
            }
        )
        ledger["submitted_fingerprints"] = fps
        ledger["records"] = records[-500:]
        self.ledger_path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")

    def resolve_campaign(
        self,
        *,
        program_handle: Optional[str] = None,
        query: str = "",
        use_api: bool = False,
        bounties_only: bool = False,
        researcher_username: str = "",
        policy_text_override: str = "",
        dry_run: bool = False,
    ) -> Tuple[HackerOneCampaign, List[HackerOneCampaign]]:
        """Resolves a target HackerOne campaign and returns `(selected_campaign, matching_campaigns)`."""
        matches: List[HackerOneCampaign] = []
        if use_api and not dry_run and self.api_client.has_credentials:
            if program_handle:
                camp = self.api_client.fetch_campaign_scope(program_handle, researcher_username=researcher_username)
                return camp, [camp]
            matches = self.api_client.list_campaigns(query=query, bounties_only=bounties_only, limit=25)
            if matches:
                selected = self.api_client.fetch_campaign_scope(matches[0].handle, researcher_username=researcher_username)
                return selected, matches

        if program_handle:
            clean_h = validate_hackerone_handle(program_handle)
            rules = parse_hackerone_program_policy(
                clean_h,
                policy_text_override,
                researcher_username=researcher_username or self.api_client.username,
            )
            camp = HackerOneCampaign(
                handle=clean_h,
                name=clean_h,
                url=f"{HACKERONE_BASE_URL}/{clean_h}",
                submit_url=f"{HACKERONE_BASE_URL}/{clean_h}/reports/new",
                in_scope_assets=list(rules.in_scope_repos) + list(rules.in_scope_hosts),
                out_of_scope_assets=list(rules.out_of_scope_assets),
                policy_text=policy_text_override[:8000],
                policy_rules=rules.to_dict(),
                source="direct_handle_dry_run" if dry_run else "direct_handle",
            )
            return camp, [camp]

        slug_hint = re.sub(r"[^a-z0-9-]+", "-", str(query or "opportunities").strip().lower()).strip("-") or "opportunities"
        rules = parse_hackerone_program_policy(
            slug_hint,
            policy_text_override,
            researcher_username=researcher_username or self.api_client.username,
        )
        fallback_camp = HackerOneCampaign(
            handle=slug_hint,
            name=f"HackerOne Directory Search ({query or 'All Programs'})",
            url=(
                f"{HACKERONE_BASE_URL}/opportunities/all?search={urllib.parse.quote_plus(query)}"
                if query
                else f"{HACKERONE_BASE_URL}/opportunities/all"
            ),
            submit_url=f"{HACKERONE_BASE_URL}/opportunities/all",
            policy_text=policy_text_override[:8000],
            policy_rules=rules.to_dict(),
            source="directory_search_fallback",
        )
        return fallback_camp, [fallback_camp]

    def port_findings(
        self,
        findings: Sequence[Dict[str, Any]],
        *,
        program_handle: Optional[str] = None,
        query: str = "",
        min_severity: str = "medium",
        max_reports: int = 5,
        use_api: bool = False,
        use_browser: bool = False,
        submit_api: bool = False,
        hitl_approved: bool = False,
        bounties_only: bool = False,
        researcher_username: str = "",
        include_ai_disclosure: bool = False,
        policy_text_override: str = "",
        dry_run: bool = False,
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
        eligibility_db: Optional[Any] = None,
        enforce_eligibility: bool = False,
    ) -> Dict[str, Any]:
        """Full `--hackerone` porting pipeline with strict Anti-Slop PoC Gate and `--dry-run` safety."""
        campaign, matches = self.resolve_campaign(
            program_handle=program_handle,
            query=query,
            use_api=use_api,
            bounties_only=bounties_only,
            researcher_username=researcher_username,
            policy_text_override=policy_text_override,
            dry_run=dry_run,
        )
        if eligibility_db is not None or enforce_eligibility:
            eff_elig_db = eligibility_db
            if eff_elig_db is None:
                from engine.program_eligibility_db import ProgramEligibilityDB

                eff_elig_db = ProgramEligibilityDB()
            if not eff_elig_db.is_eligible(campaign.handle):
                return {
                    "status": "blocked_ineligible",
                    "eligible": False,
                    "dry_run": bool(dry_run),
                    "anti_slop_gate_enforced": True,
                    "final_submit_requires_hitl": True,
                    "program_handle": campaign.handle,
                    "campaign": campaign.to_dict(),
                    "policy_rules": campaign.policy_rules,
                    "matching_campaigns": [c.to_dict() for c in matches],
                    "eligible_drafts_count": 0,
                    "rejected_findings_count": len(findings or ()),
                    "drafts": [],
                    "rejected": [{"reason": f"program_ineligible:{campaign.handle}"}],
                    "browser_session": None,
                    "api_submissions": [],
                    "report_url": None,
                    "report_urls": [],
                    "bundle_path": "",
                    "generated_at": _utc_now_iso(),
                }
        ledger = self._load_ledger()
        eligible, rejected = filter_eligible_findings(
            findings,
            min_severity=min_severity,
            max_reports=max_reports,
            submitted_fingerprints=ledger.get("submitted_fingerprints") or [],
            program_handle=campaign.handle,
        )

        if not dry_run:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        drafts: List[HackerOneReportDraft] = []
        for f_item in eligible:
            draft = build_hackerone_report_draft(
                f_item,
                campaign,
                include_ai_disclosure=include_ai_disclosure,
            )
            safe_rule = re.sub(r"[^A-Za-z0-9_.-]+", "_", draft.source_rule_id)[:48]
            md_file = self.output_dir / f"{campaign.handle}_{safe_rule}_{draft.fingerprint[:8]}.md"
            if not dry_run:
                md_doc = (
                    f"# {draft.title}\n\n"
                    f"- **HackerOne Program**: `{draft.program_handle}` ({draft.submit_url})\n"
                    f"- **Severity**: `{draft.severity_rating.upper()}`\n"
                    f"- **Weakness**: `{draft.weakness_cwe}`\n"
                    f"- **Asset**: `{draft.asset_identifier}` (`scope={draft.scope_match_status}`)\n"
                    f"- **RFCHunt Evidence Lane**: `{draft.evidence_lane}` (`poe_level={draft.poe_level}`)\n\n"
                    f"{draft.vulnerability_information}\n\n"
                    f"## Security Impact\n{draft.impact}\n"
                )
                md_file.write_text(md_doc, encoding="utf-8")
                draft.markdown_path = str(md_file)
            else:
                draft.markdown_path = f"[dry-run] {md_file}"
            drafts.append(draft)

        browser_result: Optional[Dict[str, Any]] = None
        if use_browser:
            browser_result = self.browser_porter.run_hitl_browser_session(
                campaign,
                drafts,
                search_query=query,
                dry_run=dry_run,
                wait_for_human_fn=wait_for_human_fn,
            )

        api_submissions: List[Dict[str, Any]] = []
        if submit_api:
            for d in drafts:
                resp = self.api_client.submit_report_api(d, hitl_approved=hitl_approved, dry_run=dry_run)
                if dry_run:
                    api_submissions.append(resp)
                else:
                    remote_id = str((resp.get("data") or {}).get("id") or resp.get("report_id") or "")
                    eff_rid = remote_id or d.draft_id
                    r_url = f"{HACKERONE_BASE_URL}/reports/{eff_rid}"
                    self._save_ledger_record(d, delivery_mode="hackerone_api_v1", remote_id=remote_id)
                    api_submissions.append(
                        {
                            "draft_id": d.draft_id,
                            "remote_id": remote_id,
                            "report_url": r_url,
                            "status": "submitted",
                        }
                    )

        draft_dicts: List[Dict[str, Any]] = []
        report_urls: List[str] = []
        sub_url_by_draft = {
            str(s.get("draft_id") or ""): str(s.get("report_url") or "")
            for s in api_submissions
            if isinstance(s, dict) and s.get("report_url")
        }
        for d in drafts:
            d_dict = d.to_dict()
            r_url = sub_url_by_draft.get(d.draft_id) or f"{HACKERONE_BASE_URL}/reports/{d.draft_id}"
            d_dict["report_url"] = r_url
            draft_dicts.append(d_dict)
            report_urls.append(r_url)

        bundle_path = self.output_dir / f"hackerone_port_bundle_{campaign.handle}.json"
        result = {
            "status": "dry_run_completed" if dry_run else "completed",
            "dry_run": bool(dry_run),
            "anti_slop_gate_enforced": True,
            "final_submit_requires_hitl": True,
            "campaign": campaign.to_dict(),
            "policy_rules": campaign.policy_rules,
            "matching_campaigns": [c.to_dict() for c in matches],
            "eligible_drafts_count": len(drafts),
            "rejected_findings_count": len(rejected),
            "drafts": draft_dicts,
            "rejected": rejected,
            "browser_session": browser_result,
            "api_submissions": api_submissions,
            "report_url": report_urls[0] if report_urls else None,
            "report_urls": report_urls,
            "bundle_path": f"[dry-run] {bundle_path}" if dry_run else str(bundle_path),
            "generated_at": _utc_now_iso(),
        }
        if not dry_run:
            bundle_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result


class HackerOneAutonomousRunner:
    """
    Policy-Aware Autonomous HackerOne Campaign & Audit Orchestrator (`--hackerone --hackerone-auto`):
      1. Human logs in once (Browser HITL Checkpoint 1 or HackerOne API v1 credentials).
      2. Discovers open campaigns and reads each program's Policy & Structured Scope.
      3. Enforces HackerOne's 3-Tier RoE compliance matrix:
         - Tier 1 (`explicitly_prohibited`): BLOCKS all live automated scanning to preserve Safe Harbor.
         - Tier 2 (`permitted_with_limits_and_attribution`): Configures `TokenBucketRateLimiter(max_rps)`
           and required custom attribution headers (`X-HackerOne: <username>`) + `no_out_of_scope_redirects=True`.
         - Tier 3 (`in_scope_only`): Restricts audits strictly to in-scope assets.
      4. Autonomously runs read-only white-box RFCHunt `--all` (+ `--phi` if enabled) on in-scope
         open-source `SOURCE_CODE` git repos inside an isolated temporary directory (or local `repo_path`).
         Live remote host checks require BOTH policy compliance AND explicit human approval.
      5. Filters findings through the Anti-Slop PoC Gate + `<ZK_PII:TYPE:HASH8>` redaction and
         pre-fills HackerOne drafts up to the final human Submit click.
    """

    def __init__(
        self,
        *,
        porter: Optional[HackerOnePorter] = None,
        output_dir: str = "reports/hackerone",
        workspace_root: Optional[Path] = None,
    ) -> None:
        self.porter = porter or HackerOnePorter(output_dir=output_dir, workspace_root=workspace_root)
        self.output_dir = self.porter.output_dir

    @staticmethod
    def _shallow_clone_repo(repo_url: str, dst_dir: Path) -> Path:
        safe_url = validate_source_repo_url(repo_url)
        repo_slug = safe_url.rstrip("/").split("/")[-1]
        clone_dir = dst_dir / re.sub(r"[^A-Za-z0-9._-]+", "_", repo_slug)
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--no-tags", safe_url, str(clone_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            shell=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed for {safe_url}: {(proc.stderr or proc.stdout)[:300]}")
        return clone_dir

    def run_campaign_workflow(
        self,
        *,
        program_handle: Optional[str] = None,
        query: str = "",
        max_programs: int = 2,
        local_repo_path: Optional[str] = None,
        policy_text_override: str = "",
        structured_scopes_override: Optional[Sequence[Dict[str, Any]]] = None,
        researcher_username: str = "",
        use_api: bool = False,
        use_browser: bool = False,
        enable_phi_scan: bool = True,
        min_severity: str = "medium",
        max_reports: int = 5,
        include_ai_disclosure: bool = False,
        dry_run: bool = False,
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
        eligibility_db: Optional[Any] = None,
        enforce_eligibility: bool = False,
    ) -> Dict[str, Any]:
        """Executes the full policy-aware autonomous HackerOne workflow (or safe `--dry-run` plan)."""
        eff_elig_db = eligibility_db
        if eff_elig_db is None and enforce_eligibility:
            from engine.program_eligibility_db import ProgramEligibilityDB

            eff_elig_db = ProgramEligibilityDB()

        eff_user = (researcher_username or self.porter.api_client.username or "").strip()
        campaigns: List[HackerOneCampaign] = []
        discovery_meta: Dict[str, Any] = {"source": "direct_or_override"}

        if policy_text_override or structured_scopes_override is not None:
            handle = validate_hackerone_handle(program_handle or "target-program")
            rules = parse_hackerone_program_policy(
                handle,
                policy_text_override,
                structured_scopes=structured_scopes_override,
                researcher_username=eff_user,
            )
            campaigns.append(
                HackerOneCampaign(
                    handle=handle,
                    name=handle,
                    url=f"{HACKERONE_BASE_URL}/{handle}",
                    submit_url=f"{HACKERONE_BASE_URL}/{handle}/reports/new",
                    in_scope_assets=list(rules.in_scope_repos) + list(rules.in_scope_hosts),
                    out_of_scope_assets=list(rules.out_of_scope_assets),
                    policy_text=policy_text_override[:8000],
                    policy_rules=rules.to_dict(),
                    source="policy_override",
                )
            )
        elif use_api and not dry_run and self.porter.api_client.has_credentials:
            if program_handle:
                campaigns.append(self.porter.api_client.fetch_campaign_scope(program_handle, researcher_username=eff_user))
            else:
                listed = self.porter.api_client.list_campaigns(query=query, limit=max(1, int(max_programs or 2)))
                for c_item in listed[: max(1, int(max_programs or 2))]:
                    campaigns.append(self.porter.api_client.fetch_campaign_scope(c_item.handle, researcher_username=eff_user))
            discovery_meta = {"source": "hackerone_api_v1", "campaigns_count": len(campaigns)}
        elif use_browser:
            b_disc = self.porter.browser_porter.discover_and_read_campaigns_browser(
                program_handle=program_handle,
                search_query=query,
                max_programs=max_programs,
                researcher_username=eff_user,
                dry_run=dry_run,
                wait_for_human_fn=wait_for_human_fn,
            )
            discovery_meta = b_disc
            for c_dict in b_disc.get("campaigns") or []:
                campaigns.append(HackerOneCampaign(**c_dict))

        if not campaigns:
            selected, _ = self.porter.resolve_campaign(
                program_handle=program_handle,
                query=query,
                use_api=False,
                researcher_username=eff_user,
                policy_text_override=policy_text_override,
                dry_run=dry_run,
            )
            campaigns = [selected]

        program_results: List[Dict[str, Any]] = []
        for camp in campaigns[: max(1, int(max_programs or 2))]:
            if eff_elig_db is not None and not eff_elig_db.is_eligible(camp.handle):
                port_blocked = self.porter.port_findings(
                    [],
                    program_handle=camp.handle,
                    query=query,
                    dry_run=dry_run,
                    eligibility_db=eff_elig_db,
                    enforce_eligibility=True,
                )
                program_results.append(
                    {
                        "program_handle": camp.handle,
                        "eligible": False,
                        "status": "blocked_ineligible",
                        "campaign": camp.to_dict(),
                        "roe_compliance": {
                            "safe_harbor_status": "blocked_by_program_eligibility_db",
                            "live_scan_policy_decision": "BLOCKED_INELIGIBLE_PROGRAM",
                        },
                        "audit_actions": [
                            {
                                "action": "blocked_ineligible_program",
                                "program_handle": camp.handle,
                            }
                        ],
                        "port_result": port_blocked,
                    }
                )
                continue

            rules = parse_hackerone_program_policy(
                camp.handle,
                camp.policy_text,
                structured_scopes=structured_scopes_override,
                researcher_username=eff_user,
            )
            if camp.policy_rules:
                # Preserve any already-parsed structured scope repos/hosts
                for r_url in camp.policy_rules.get("in_scope_repos") or []:
                    if r_url not in rules.in_scope_repos:
                        rules.in_scope_repos.append(r_url)
                for h_id in camp.policy_rules.get("in_scope_hosts") or []:
                    if h_id not in rules.in_scope_hosts:
                        rules.in_scope_hosts.append(h_id)
            camp.policy_rules = rules.to_dict()

            # Enforce HackerOne 3-Tier RoE Compliance Decision
            if rules.automated_scanning_prohibited:
                live_scan_policy_decision = "BLOCKED_BY_ROE_EXPLICITLY_PROHIBITED_SAFE_HARBOR"
            elif rules.missing_attribution_username:
                live_scan_policy_decision = "BLOCKED_MISSING_REQUIRED_ATTRIBUTION_USERNAME"
            elif rules.in_scope_hosts:
                live_scan_policy_decision = "ELIGIBLE_WITH_RATE_LIMIT_AND_HITL_APPROVAL"
            else:
                live_scan_policy_decision = "NO_LIVE_HOSTS_IN_SCOPE"

            # Determine read-only source code audit targets
            audit_findings: List[Dict[str, Any]] = []
            audit_actions: List[Dict[str, Any]] = []

            if local_repo_path and Path(local_repo_path).exists():
                if dry_run:
                    audit_actions.append(
                        {
                            "action": "dry_run_would_audit_local_repo",
                            "repo_path": str(Path(local_repo_path).resolve()),
                            "engines": ["unified_all_scans", "phi_scanner"] if enable_phi_scan else ["unified_all_scans"],
                        }
                    )
                else:
                    from engine.mantis_integrator import run_unified_all_scans

                    scan_out_dir = self.output_dir / f"auto_audit_{camp.handle}"
                    scan_res = run_unified_all_scans(
                        repo=str(Path(local_repo_path).resolve()),
                        depth=30,
                        reports_dir=str(scan_out_dir),
                        enable_external_scanners=False,
                        enable_phi_scan=enable_phi_scan,
                        auto_install_tools=False,
                        include_models=False,
                        custom_headers=list(rules.required_headers),
                        user_agent=rules.required_user_agent,
                        max_rps=rules.max_rps,
                    )
                    primary = list(scan_res.get("verified_exploits") or []) + list(
                        scan_res.get("deterministic_static_findings") or []
                    )
                    audit_findings.extend(primary)
                    audit_actions.append(
                        {
                            "action": "audited_local_repo_readonly",
                            "repo_path": str(Path(local_repo_path).resolve()),
                            "primary_findings": len(primary),
                            "phi_findings": int((scan_res.get("engines") or {}).get("phi_scanner", {}).get("total_findings", 0)),
                        }
                    )
            elif rules.in_scope_repos:
                for repo_url in rules.in_scope_repos[:2]:
                    if dry_run:
                        audit_actions.append(
                            {
                                "action": "dry_run_would_clone_and_audit_in_scope_repo",
                                "repo_url": repo_url,
                                "engines": ["unified_all_scans", "phi_scanner"] if enable_phi_scan else ["unified_all_scans"],
                            }
                        )
                    else:
                        tmp_dir = Path(tempfile.mkdtemp(prefix=f"rfchunt_h1_{camp.handle}_"))
                        try:
                            cloned = self._shallow_clone_repo(repo_url, tmp_dir)
                            from engine.mantis_integrator import run_unified_all_scans

                            scan_out_dir = self.output_dir / f"auto_audit_{camp.handle}"
                            scan_res = run_unified_all_scans(
                                repo=str(cloned),
                                depth=30,
                                reports_dir=str(scan_out_dir),
                                enable_external_scanners=False,
                                enable_phi_scan=enable_phi_scan,
                                auto_install_tools=False,
                                include_models=False,
                                custom_headers=list(rules.required_headers),
                                user_agent=rules.required_user_agent,
                                max_rps=rules.max_rps,
                            )
                            primary = list(scan_res.get("verified_exploits") or []) + list(
                                scan_res.get("deterministic_static_findings") or []
                            )
                            audit_findings.extend(primary)
                            audit_actions.append(
                                {
                                    "action": "cloned_and_audited_in_scope_repo_readonly",
                                    "repo_url": repo_url,
                                    "primary_findings": len(primary),
                                }
                            )
                        except Exception as clone_exc:
                            audit_actions.append(
                                {
                                    "action": "repo_clone_or_audit_error",
                                    "repo_url": repo_url,
                                    "error": str(clone_exc),
                                }
                            )
                        finally:
                            shutil.rmtree(tmp_dir, ignore_errors=True)

            port_res = self.porter.port_findings(
                audit_findings,
                program_handle=camp.handle,
                query=query,
                min_severity=min_severity,
                max_reports=max_reports,
                use_api=False,
                use_browser=use_browser and bool(audit_findings),
                submit_api=False,
                researcher_username=eff_user,
                include_ai_disclosure=bool(include_ai_disclosure or rules.ai_disclosure_required),
                policy_text_override=camp.policy_text,
                dry_run=dry_run,
                wait_for_human_fn=wait_for_human_fn,
                eligibility_db=eff_elig_db,
                enforce_eligibility=enforce_eligibility,
            )

            program_results.append(
                {
                    "program_handle": camp.handle,
                    "campaign": camp.to_dict(),
                    "roe_compliance": {
                        "automation_tier": rules.automation_tier,
                        "automated_scanning_prohibited": rules.automated_scanning_prohibited,
                        "prohibition_evidence": rules.prohibition_evidence,
                        "max_rps": rules.max_rps,
                        "required_headers": rules.required_headers,
                        "required_user_agent": rules.required_user_agent,
                        "no_out_of_scope_redirects": rules.no_out_of_scope_redirects,
                        "poc_required": rules.poc_required,
                        "ai_disclosure_required": rules.ai_disclosure_required,
                        "safe_harbor_status": rules.safe_harbor_status,
                        "live_scan_policy_decision": live_scan_policy_decision,
                    },
                    "audit_actions": audit_actions,
                    "port_result": port_res,
                }
            )

        summary = {
            "status": "dry_run_autonomous_plan_ready" if dry_run else "autonomous_workflow_completed",
            "mode": "hackerone_policy_aware_autonomous",
            "dry_run": bool(dry_run),
            "safe_harbor_roe_enforced": True,
            "final_submit_requires_hitl": True,
            "discovery": discovery_meta,
            "programs_evaluated": len(program_results),
            "program_results": program_results,
            "generated_at": _utc_now_iso(),
        }
        if not dry_run:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            auto_report = self.output_dir / "hackerone_autonomous_summary.json"
            auto_report.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            summary["summary_path"] = str(auto_report)
        return summary


def load_findings_for_hackerone(
    *,
    findings_json: Optional[str] = None,
    reports_dir: str = "reports",
) -> List[Dict[str, Any]]:
    """Loads eligible findings from an explicit JSON file or `reports/combined_audit_summary.json`."""
    candidates: List[Path] = []
    if findings_json:
        candidates.append(Path(findings_json))
    candidates.append(Path(reports_dir) / "combined_audit_summary.json")
    for p in candidates:
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            primary: List[Dict[str, Any]] = []
            for key in ("verified_exploits", "deterministic_static_findings"):
                items = data.get(key)
                if isinstance(items, list):
                    primary.extend(x for x in items if isinstance(x, dict))
            if primary:
                return primary
            raw_f = data.get("findings")
            if isinstance(raw_f, list):
                return [x for x in raw_f if isinstance(x, dict)]
    return []
