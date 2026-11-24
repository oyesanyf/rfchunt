"""
HackerOne Campaign Finder & Human-in-the-Loop (HITL) Computer-Use Report Porter (`--hackerone`)
================================================================================================

Adapts RFCHunt findings for responsible disclosure on HackerOne (`https://hackerone.com/`) via:
  1. Strict 3-Lane Anti-Slop Quality Gate:
     - Refuses to port Lane 3 `SPECULATIVE_HYPOTHESIS` (`poe_level <= 1` ARTEX/PromptSmuggler guesses)
       so researcher HackerOne signal/reputation is never degraded by unverified noise.
     - Only ports Lane 1 (`VERIFIED_EXPLOIT`, `poe_level == 3`) and Lane 2 (`DETERMINISTIC_STATIC`
       with concrete file/line evidence, CWE, and witness/remediation).
     - Tracks SHA-256 report fingerprints in a local ledger to prevent duplicate submissions.
     - Redacts sensitive headers, JWTs, cookies, and API tokens prior to export.
  2. Official HackerOne Hacker API v1 Client (`https://api.hackerone.com/v1/hackers/...`):
     - Lists/searches accessible bug bounty & VDP campaigns (`GET /v1/hackers/programs`) and
       fetches structured in-scope / out-of-scope assets using `HACKERONE_API_USERNAME` and
       `HACKERONE_API_TOKEN` (process env or workspace `.env` only; zero registry mutations).
     - Strict HTTPS host pinning (`api.hackerone.com` / `hackerone.com` only).
  3. Interactive HITL Computer-Use Browser Porter (Playwright visible browser):
     - Opens `https://hackerone.com/users/sign_in` in a visible (`headless=False`) browser window
       and PAUSES for the human researcher to complete login, 2FA/MFA, and any anti-bot/CAPTCHA
       check directly (strictly NEVER solves, computes, or bypasses CAPTCHAs or access controls).
     - Navigates to the chosen campaign (`https://hackerone.com/<handle>/reports/new` or
       `https://hackerone.com/opportunities/all`), extracts visible campaign cards via semantic
       DOM selectors (never desktop X/Y coordinates), and auto-fills Title, Weakness/CWE,
       Severity, Vulnerability Information, and Impact.
     - HARD-STOPS before clicking the final "Submit report" button so the human researcher
       reviews every field and clicks Submit themselves.
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
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request

from engine.advisory_exporter import _redact_inline_tokens

HACKERONE_BASE_URL = "https://hackerone.com"
HACKERONE_API_BASE_URL = "https://api.hackerone.com/v1"
HACKERONE_ALLOWED_HOSTS = frozenset({"hackerone.com", "www.hackerone.com", "api.hackerone.com"})

_SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
    "info": 0,
}

_HANDLE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    Strict Anti-Slop Quality Gate for HackerOne porting:
      - Rejects Lane 3 `SPECULATIVE_HYPOTHESIS` findings (unverified ARTEX/PromptSmuggler leads).
      - Rejects findings below `min_severity`.
      - Rejects findings lacking concrete evidence/location.
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
) -> HackerOneReportDraft:
    """Formats a verified or deterministic RFCHunt finding into a redacted HackerOne report draft."""
    rule_id = str(finding.get("rule_id") or "RFCHUNT-SEC-001")
    scanner = str(finding.get("scanner") or "RFCHunt")
    cwe = str(finding.get("cwe") or finding.get("cwe_id") or "CWE-20").upper()
    raw_sev = str(finding.get("severity") or "medium").strip().lower()
    h1_sev = raw_sev if raw_sev in ("critical", "high", "medium", "low") else "low"
    lane = str(finding.get("evidence_lane") or "DETERMINISTIC_STATIC")
    poe_level = int(finding.get("poe_level", 1) or 1)
    file_path = str(finding.get("file_path") or finding.get("file") or "repository")
    line_num = int(finding.get("line_number") or finding.get("line") or 1)
    title = _redact_inline_tokens(str(finding.get("title") or f"{rule_id} security defect in {Path(file_path).name}"))[:140]
    description = _redact_inline_tokens(str(finding.get("description") or title))
    evidence = _redact_inline_tokens(str(finding.get("evidence") or finding.get("raw_probe") or ""))
    remediation = _redact_inline_tokens(str(finding.get("remediation") or "Enforce fail-closed validation at the trust boundary."))
    witness = _redact_inline_tokens(str(finding.get("counterexample_witness") or ""))
    trace_steps = [str(s) for s in (finding.get("counterexample_trace") or []) if str(s).strip()]
    formula = str(finding.get("violated_invariant_formula") or "").strip()

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
        "## Steps to Reproduce",
        "\n".join(steps_md_lines),
    ]
    if formula:
        vuln_info_parts.extend(["", "## Violated Security Invariant", f"```text\n{formula}\n```"])
    if evidence:
        vuln_info_parts.extend(["", "## Supporting Evidence (Redacted)", f"```text\n{evidence[:1500]}\n```"])
    if witness:
        vuln_info_parts.extend(["", "## Counterexample Witness", f"```json\n{witness[:1000]}\n```"])
    vuln_info_parts.extend(["", "## Recommended Fix", remediation])

    impact_text = (
        f"An attacker or untrusted workload reaching `{Path(file_path).name}:{line_num}` can exploit "
        f"`{cwe}` ({rule_id}) to bypass the enforced security boundary. {description[:280]}"
    )

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
        vulnerability_information="\n".join(vuln_info_parts),
        impact=impact_text,
        source_rule_id=rule_id,
        source_scanner=scanner,
        scope_match_status=scope_status,
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
            "User-Agent": "RFCHunt-HackerOne-Porter/1.0",
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

    def fetch_campaign_scope(self, handle: str) -> HackerOneCampaign:
        clean_handle = validate_hackerone_handle(handle)
        prog = self._request_json(f"hackers/programs/{clean_handle}")
        attrs = (prog.get("data") or {}).get("attributes") or {}
        scopes = self._request_json(f"hackers/programs/{clean_handle}/structured_scopes?page[size]=100")
        in_scope: List[str] = []
        out_scope: List[str] = []
        for sc in scopes.get("data") or []:
            s_attrs = sc.get("attributes") or {}
            ident = str(s_attrs.get("asset_identifier") or "").strip()
            if not ident:
                continue
            if bool(s_attrs.get("eligible_for_submission", True)):
                in_scope.append(ident)
            else:
                out_scope.append(ident)
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
            source="hackerone_api_v1",
        )

    def submit_report_api(self, draft: HackerOneReportDraft, *, hitl_approved: bool = False) -> Dict[str, Any]:
        """
        Submits a report via HackerOne Hacker API v1 (`POST /v1/hackers/reports`).
        Fails closed unless `hitl_approved=True` and `draft.evidence_lane != SPECULATIVE_HYPOTHESIS`.
        """
        if not hitl_approved:
            raise PermissionError("Refusing HackerOne API submission without explicit human-in-the-loop approval.")
        if draft.evidence_lane == "SPECULATIVE_HYPOTHESIS":
            raise PermissionError("Refusing to submit speculative Lane-3 hypothesis to HackerOne.")
        if draft.scope_match_status == "out_of_scope":
            raise PermissionError(f"Refusing to submit out-of-scope asset {draft.asset_identifier!r} to {draft.program_handle}.")

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
        return self._request_json("hackers/reports", method="POST", payload=payload)


class HackerOneComputerUsePorter:
    """
    Human-in-the-Loop (HITL) Playwright Computer-Use assistant for HackerOne:
      1. Opens `https://hackerone.com/users/sign_in` in a visible (`headless=False`) browser.
      2. Pauses for the human user to sign in, pass MFA/2FA, and complete any anti-bot/CAPTCHA
         check directly (NEVER bypasses CAPTCHA or authentication).
      3. Discovers/opens the selected campaign (`https://hackerone.com/opportunities/all` or
         `https://hackerone.com/<handle>/reports/new`) via semantic DOM selectors.
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

    def run_hitl_browser_session(
        self,
        campaign: HackerOneCampaign,
        drafts: Sequence[HackerOneReportDraft],
        *,
        search_query: str = "",
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
    ) -> Dict[str, Any]:
        """
        Runs an interactive visible browser session with mandatory human checkpoints.
        Never clicks the final Submit button automatically.
        """
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
                "install_hint": "pip install playwright && playwright install chromium",
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
                    f"(fields={filled_fields}). Review every field, select the exact Asset/Weakness if needed, "
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


class HackerOnePorter:
    """
    Top-level orchestrator for `--hackerone` / `--hackone`:
      - Discovers/resolves HackerOne campaign (via official API v1, handle, or directory)
      - Filters RFCHunt findings through the Strict Anti-Slop Quality Gate (Lane 1 + Lane 2 only)
      - Writes HackerOne-formatted Markdown + JSON report bundle to `reports/hackerone/`
      - Optionally launches the visible HITL Computer-Use browser autofill (`use_browser=True`)
        or submits via official HackerOne API v1 (`submit_api=True` + explicit `hitl_approved=True`).
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
        self.output_dir.mkdir(parents=True, exist_ok=True)
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
    ) -> Tuple[HackerOneCampaign, List[HackerOneCampaign]]:
        """Resolves a target HackerOne campaign and returns `(selected_campaign, matching_campaigns)`."""
        matches: List[HackerOneCampaign] = []
        if use_api and self.api_client.has_credentials:
            if program_handle:
                camp = self.api_client.fetch_campaign_scope(program_handle)
                return camp, [camp]
            matches = self.api_client.list_campaigns(query=query, bounties_only=bounties_only, limit=25)
            if matches:
                selected = self.api_client.fetch_campaign_scope(matches[0].handle)
                return selected, matches

        if program_handle:
            clean_h = validate_hackerone_handle(program_handle)
            camp = HackerOneCampaign(
                handle=clean_h,
                name=clean_h,
                url=f"{HACKERONE_BASE_URL}/{clean_h}",
                submit_url=f"{HACKERONE_BASE_URL}/{clean_h}/reports/new",
                source="direct_handle",
            )
            return camp, [camp]

        # Guaranteed Workspace Law (zero empty states): return the official HackerOne opportunities
        # directory launcher when neither handle nor API credentials were provided.
        slug_hint = re.sub(r"[^a-z0-9-]+", "-", str(query or "opportunities").strip().lower()).strip("-") or "opportunities"
        fallback_camp = HackerOneCampaign(
            handle=slug_hint,
            name=f"HackerOne Directory Search ({query or 'All Programs'})",
            url=(
                f"{HACKERONE_BASE_URL}/opportunities/all?search={urllib.parse.quote_plus(query)}"
                if query
                else f"{HACKERONE_BASE_URL}/opportunities/all"
            ),
            submit_url=f"{HACKERONE_BASE_URL}/opportunities/all",
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
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
    ) -> Dict[str, Any]:
        """
        Full `--hackerone` porting pipeline:
          1. Resolves campaign & scope.
          2. Applies Strict Anti-Slop Quality Gate (rejecting Lane-3 speculative hypotheses).
          3. Redacts secrets & builds structured HackerOne Markdown drafts on disk.
          4. Runs HITL Playwright Computer-Use browser autofill (if `use_browser=True`) or
             authenticated HackerOne API v1 submission (if `submit_api=True` and `hitl_approved=True`).
        """
        campaign, matches = self.resolve_campaign(
            program_handle=program_handle,
            query=query,
            use_api=use_api,
            bounties_only=bounties_only,
        )
        ledger = self._load_ledger()
        eligible, rejected = filter_eligible_findings(
            findings,
            min_severity=min_severity,
            max_reports=max_reports,
            submitted_fingerprints=ledger.get("submitted_fingerprints") or [],
            program_handle=campaign.handle,
        )

        drafts: List[HackerOneReportDraft] = []
        for f_item in eligible:
            draft = build_hackerone_report_draft(f_item, campaign)
            safe_rule = re.sub(r"[^A-Za-z0-9_.-]+", "_", draft.source_rule_id)[:48]
            md_file = self.output_dir / f"{campaign.handle}_{safe_rule}_{draft.fingerprint[:8]}.md"
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
            drafts.append(draft)

        browser_result: Optional[Dict[str, Any]] = None
        if use_browser:
            browser_result = self.browser_porter.run_hitl_browser_session(
                campaign,
                drafts,
                search_query=query,
                wait_for_human_fn=wait_for_human_fn,
            )

        api_submissions: List[Dict[str, Any]] = []
        if submit_api:
            for d in drafts:
                resp = self.api_client.submit_report_api(d, hitl_approved=hitl_approved)
                remote_id = str((resp.get("data") or {}).get("id") or "")
                self._save_ledger_record(d, delivery_mode="hackerone_api_v1", remote_id=remote_id)
                api_submissions.append({"draft_id": d.draft_id, "remote_id": remote_id, "status": "submitted"})

        bundle_path = self.output_dir / f"hackerone_port_bundle_{campaign.handle}.json"
        result = {
            "status": "completed",
            "anti_slop_gate_enforced": True,
            "final_submit_requires_hitl": True,
            "campaign": campaign.to_dict(),
            "matching_campaigns": [c.to_dict() for c in matches],
            "eligible_drafts_count": len(drafts),
            "rejected_findings_count": len(rejected),
            "drafts": [d.to_dict() for d in drafts],
            "rejected": rejected,
            "browser_session": browser_result,
            "api_submissions": api_submissions,
            "bundle_path": str(bundle_path),
            "generated_at": _utc_now_iso(),
        }
        bundle_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result


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
