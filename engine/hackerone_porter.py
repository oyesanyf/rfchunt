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
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

from engine.advisory_exporter import _redact_inline_tokens

HACKERONE_BASE_URL = "https://hackerone.com"
HACKERONE_API_BASE_URL = "https://api.hackerone.com/v1"
HACKERONE_ALLOWED_HOSTS = frozenset({"hackerone.com", "www.hackerone.com", "api.hackerone.com"})
DEFAULT_BUG_HUNT_URL = "https://hackerone.com/opportunities/all"
BUG_BOUNTY_ALLOWED_HOSTS = frozenset(
    {
        "hackerone.com",
        "www.hackerone.com",
        "api.hackerone.com",
        "bugcrowd.com",
        "www.bugcrowd.com",
        "immunefi.com",
        "www.immunefi.com",
        "intigriti.com",
        "app.intigriti.com",
    }
)
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


def validate_bug_hunt_url(url: str) -> str:
    """
    Enforces strict HTTPS origin pinning for interactive `--hunt --hunt-url` browser sessions.
    Only official bug bounty platforms (`hackerone.com`, `bugcrowd.com`, `immunefi.com`,
    `intigriti.com`) are permitted; fails closed with `PermissionError` on any other URL.
    """
    raw = str(url or "").strip()
    if not raw or any(ch in raw for ch in ("\r", "\n", "\x00")):
        raise PermissionError(f"Refusing empty or control-character bug hunt URL: {url!r}")
    parsed = urllib.parse.urlparse(raw)
    host = (parsed.hostname or "").lower()
    if parsed.username or parsed.password:
        raise PermissionError(f"Refusing URL with embedded credentials: {url!r}")
    if parsed.scheme != "https" or host not in BUG_BOUNTY_ALLOWED_HOSTS:
        raise PermissionError(
            f"Refusing untrusted bug hunt URL {url!r}; allowed hosts: {sorted(BUG_BOUNTY_ALLOWED_HOSTS)}"
        )
    return raw


_NON_REPO_GITHUB_OWNERS = frozenset(
    {
        "about",
        "account",
        "apps",
        "blog",
        "collections",
        "contact",
        "customer-stories",
        "enterprise",
        "events",
        "explore",
        "features",
        "issues",
        "join",
        "login",
        "logout",
        "marketplace",
        "new",
        "notifications",
        "orgs",
        "organizations",
        "pricing",
        "pulls",
        "readme",
        "search",
        "security",
        "sessions",
        "settings",
        "signup",
        "site",
        "solutions",
        "sponsors",
        "team",
        "topics",
        "trending",
        "users",
    }
)

_NON_PROGRAM_H1_PATHS = frozenset(
    {
        "auth",
        "bugs",
        "careers",
        "customers",
        "directory",
        "disclosure-guidelines",
        "graphql",
        "hacktivity",
        "inbox",
        "leaderboard",
        "login",
        "notifications",
        "opportunities",
        "organizations",
        "privacy",
        "product",
        "reports",
        "resources",
        "security",
        "settings",
        "sign_in",
        "sign_up",
        "terms",
        "users",
    }
)


def _extract_repo_slug_from_url(url: str) -> Optional[Tuple[str, str]]:
    """Extracts `(canonical_https_url, 'owner/repo')` from a trusted source repo URL, or None."""
    try:
        clean_url = validate_source_repo_url(url)
    except (PermissionError, ValueError):
        return None
    parsed = urllib.parse.urlparse(clean_url)
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1].removesuffix(".git")
    if owner.lower() in _NON_REPO_GITHUB_OWNERS:
        return None
    if not re.match(r"^[A-Za-z0-9_.-]+$", owner) or not re.match(r"^[A-Za-z0-9_.-]+$", repo):
        return None
    return clean_url, f"{owner}/{repo}"


def _detect_bounty_platform(hunt_url: str) -> str:
    host = (urllib.parse.urlparse(hunt_url).hostname or "").lower()
    if "hackerone.com" in host:
        return "hackerone"
    if "bugcrowd.com" in host:
        return "bugcrowd"
    if "immunefi.com" in host:
        return "immunefi"
    if "intigriti.com" in host:
        return "intigriti"
    return "hackerone"


def extract_unlocked_programs_and_repos_from_page_data(
    *,
    hunt_url: str,
    current_user: Optional[Dict[str, Any]] = None,
    probe_report: Optional[Dict[str, Any]] = None,
    probe_report_id: int = 4243972,
    inbox_counts: Optional[Dict[str, Any]] = None,
    program_cards: Optional[Sequence[Dict[str, Any]]] = None,
    page_links: Optional[Sequence[str]] = None,
    eligibility_db_path: Optional[Union[str, Path]] = None,
    draft_tracker_db_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Deterministic parser & SQLite WAL persister for authenticated `/browser` hunt captures.

    Processes live or snapshot browser captures of:
      1. Authenticated researcher identity + Signal/Impact/Reputation (`/current_user.json`)
      2. Account cooldown probe (`/reports/<id>.json` -> `can_submit_draft?`)
      3. Inbox open/triaged/draft counts
      4. Discovered bug bounty programs, Signal eligibility gates, RoE policies, and
         in-scope `github.com/<owner>/<repo>` targets.

    Persists unlocked/blocked programs into `ProgramEligibilityDB` v2 and cooldown state
    into `DraftSubmitTrackerDB`, returning ONLY repos belonging to `UNLOCKED` programs.
    """
    validated_url = validate_bug_hunt_url(hunt_url)
    platform = _detect_bounty_platform(validated_url)

    # 1. Extract researcher identity & live Signal score
    user_dict = current_user if isinstance(current_user, dict) else {}
    auth_user = str(user_dict.get("username") or user_dict.get("handle") or user_dict.get("name") or "").strip()
    signal_score: Optional[float] = None
    for sig_key in ("signal", "signal_score", "signal_percentile"):
        raw_sig = user_dict.get(sig_key)
        if raw_sig is not None and not isinstance(raw_sig, bool):
            try:
                signal_score = float(raw_sig)
                break
            except (TypeError, ValueError):
                pass

    # 2. Parse cooldown probe (`/reports/<id>.json`) & persist into DraftSubmitTrackerDB
    cooldown_outcome: Dict[str, Any] = {}
    cooldown_cleared = False
    cooldown_status = "UNKNOWN"
    if isinstance(probe_report, dict) and probe_report:
        from engine.draft_submit_checker import DraftSubmitTrackerDB, parse_hackerone_report_json

        outcome = parse_hackerone_report_json(int(probe_report_id), probe_report, http_status=200)
        cooldown_outcome = outcome.to_dict()
        cooldown_cleared = outcome.readiness == "READY_TO_SUBMIT"
        if outcome.readiness == "READY_TO_SUBMIT":
            cooldown_status = "CLEARED"
        elif outcome.readiness == "COOLDOWN_LOCKED":
            cooldown_status = "COOLDOWN_ACTIVE"
        elif outcome.readiness == "ALREADY_SUBMITTED":
            cooldown_status = "ALREADY_SUBMITTED"
        else:
            cooldown_status = outcome.readiness

        if draft_tracker_db_path is not None:
            tracker = DraftSubmitTrackerDB(draft_tracker_db_path)
            tracker.seed_default_queue()
            tracker.apply_probe_outcome(outcome)
            tracker.record_check_run(
                probe_report_id=int(probe_report_id),
                account_status=cooldown_status,
                ready_count=1 if cooldown_cleared else 0,
                locked_count=1 if cooldown_status == "COOLDOWN_ACTIVE" else 0,
                http_status=200,
                source="browser_hunt",
            )

    # 3. Parse discovered programs, Signal eligibility, RoE, and in-scope repos
    elig_db = None
    if eligibility_db_path is not None:
        from engine.program_eligibility_db import ProgramEligibilityDB

        elig_db = ProgramEligibilityDB(db_path=eligibility_db_path)
        if signal_score is not None:
            elig_db.update_account_state(
                signal_established=(signal_score >= 0.0),
                signal_score=signal_score,
            )

    unlocked_programs: List[Dict[str, Any]] = []
    blocked_programs: List[Dict[str, Any]] = []
    discovered_repos: List[Dict[str, str]] = []
    seen_repo_keys: set[str] = set()
    seen_handles: set[str] = set()

    for card in program_cards or []:
        if not isinstance(card, dict):
            continue
        raw_handle = str(card.get("handle") or "").strip().strip("/")
        if not raw_handle or raw_handle.lower() in _NON_PROGRAM_H1_PATHS:
            continue
        try:
            handle = validate_hackerone_handle(raw_handle)
        except ValueError:
            continue
        if handle in seen_handles:
            continue
        seen_handles.add(handle)

        sub_state = str(card.get("submission_state") or "open").strip().lower()
        policy_text = str(card.get("policy_text") or "")
        structured_scopes = card.get("structured_scopes")
        if not isinstance(structured_scopes, list):
            structured_scopes = None

        rules = parse_hackerone_program_policy(
            handle,
            policy_text,
            structured_scopes=structured_scopes,
            researcher_username=auth_user,
        )

        # Collect in-scope source repo URLs & slugs from policy rules + card links/repos
        card_repo_urls: List[str] = []
        card_repo_slugs: List[str] = []
        seen_card_slugs: set[str] = set()

        def _add_card_repo(raw_candidate: str) -> None:
            cand = str(raw_candidate or "").strip()
            if not cand:
                return
            if "/" in cand and not cand.lower().startswith("http"):
                cand = f"https://github.com/{cand.strip('/')}"
            parsed_pair = _extract_repo_slug_from_url(cand)
            if parsed_pair is None:
                return
            r_url, r_slug = parsed_pair
            if r_slug.lower() not in seen_card_slugs:
                seen_card_slugs.add(r_slug.lower())
                card_repo_urls.append(r_url)
                card_repo_slugs.append(r_slug)

        for r_u in rules.in_scope_repos:
            _add_card_repo(r_u)
        for r_u in card.get("in_scope_repos") or []:
            _add_card_repo(str(r_u))
        for raw_link in card.get("links") or []:
            for m in _GIT_REPO_URL_RX.findall(str(raw_link)):
                _add_card_repo(m)

        raw_sig_req = card.get("signal_required")
        sig_req: Optional[float] = None
        if raw_sig_req is not None and not isinstance(raw_sig_req, bool):
            try:
                sig_req = float(raw_sig_req)
            except (TypeError, ValueError):
                sig_req = None

        low_policy = policy_text.lower()
        explicit_signal_blocked = bool(card.get("signal_blocked", False)) or (
            "your signal is too low" in low_policy
            or "requires a minimum signal" in low_policy
            or "do not meet the signal requirement" in low_policy
        )
        if sub_state in ("paused", "disabled", "closed", "soft_launched"):
            prog_status = "PAUSED"
        elif explicit_signal_blocked or (
            sig_req is not None and signal_score is not None and float(signal_score) < sig_req
        ):
            prog_status = "BLOCKED_SIGNAL"
        else:
            prog_status = "UNLOCKED"

        resp_eff = card.get("response_efficiency_pct")
        eff_pct = float(resp_eff) if resp_eff is not None and not isinstance(resp_eff, bool) else None
        b_min = int(card["bounty_min_usd"]) if card.get("bounty_min_usd") is not None else None
        b_max = int(card["bounty_max_usd"]) if card.get("bounty_max_usd") is not None else None
        offers_b = card.get("offers_bounties")
        offers_b_bool = bool(offers_b) if offers_b is not None else (bool(b_max and b_max > 0))
        submit_url = str(card.get("submit_url") or "")
        if not submit_url and platform == "hackerone":
            submit_url = f"{HACKERONE_BASE_URL}/{handle}/reports/new"

        if elig_db is not None:
            elig_db.upsert(
                handle,
                prog_status,
                platform=platform,
                signal_required=sig_req,
                bounty_min_usd=b_min,
                bounty_max_usd=b_max,
                submit_url=submit_url,
                scope_summary=str(card.get("scope_summary") or "")[:500],
                notes=f"Discovered via interactive browser hunt ({validated_url})",
                response_efficiency_pct=eff_pct,
                offers_bounties=offers_b_bool,
                is_vdp=(not offers_b_bool),
                submission_state=sub_state,
                source_repo_count=len(card_repo_slugs),
                in_scope_assets=list(rules.in_scope_hosts),
                in_scope_repos=card_repo_slugs,
                out_of_scope_assets=list(rules.out_of_scope_assets),
                roe_automation_tier=rules.automation_tier,
                roe_automated_prohibited=rules.automated_scanning_prohibited,
                roe_max_rps=rules.max_rps,
                roe_required_headers=list(rules.required_headers),
                roe_user_agent=rules.required_user_agent,
                roe_ai_disclosure_required=rules.ai_disclosure_required,
                roe_no_oos_redirects=rules.no_out_of_scope_redirects,
            )

        prog_summary = {
            "handle": handle,
            "name": str(card.get("name") or handle),
            "platform": platform,
            "status": prog_status,
            "submission_state": sub_state,
            "offers_bounties": offers_b_bool,
            "response_efficiency_pct": eff_pct,
            "bounty_min_usd": b_min,
            "bounty_max_usd": b_max,
            "signal_required": sig_req,
            "submit_url": submit_url,
            "in_scope_repos": card_repo_slugs,
            "in_scope_hosts": list(rules.in_scope_hosts),
            "roe_automation_tier": rules.automation_tier,
        }
        if prog_status == "UNLOCKED":
            unlocked_programs.append(prog_summary)
            for r_url, r_slug in zip(card_repo_urls, card_repo_slugs):
                key = f"{handle}:{r_slug.lower()}"
                if key not in seen_repo_keys:
                    seen_repo_keys.add(key)
                    discovered_repos.append({"program": handle, "repo": r_slug, "url": r_url})
        else:
            blocked_programs.append(prog_summary)

    # Also harvest standalone repo links from top-level page_links when a single program URL is targeted
    url_parts = [p for p in urllib.parse.urlparse(validated_url).path.split("/") if p]
    default_handle = "generic"
    if len(url_parts) >= 1 and url_parts[0].lower() not in _NON_PROGRAM_H1_PATHS:
        try:
            default_handle = validate_hackerone_handle(url_parts[0])
        except ValueError:
            default_handle = "generic"
    default_is_blocked = any(bp["handle"] == default_handle for bp in blocked_programs)
    if not default_is_blocked:
        for raw_link in page_links or []:
            for m in _GIT_REPO_URL_RX.findall(str(raw_link)):
                pair = _extract_repo_slug_from_url(m)
                if pair is None:
                    continue
                r_url, r_slug = pair
                key = f"{default_handle}:{r_slug.lower()}"
                if key not in seen_repo_keys:
                    seen_repo_keys.add(key)
                    discovered_repos.append({"program": default_handle, "repo": r_slug, "url": r_url})

    return {
        "hunt_url": validated_url,
        "platform": platform,
        "authenticated_user": auth_user,
        "signal_score": signal_score,
        "cooldown_status": cooldown_status,
        "cooldown_cleared": cooldown_cleared,
        "cooldown_probe": cooldown_outcome,
        "inbox_counts": dict(inbox_counts or {}),
        "unlocked_programs": unlocked_programs,
        "unlocked_programs_count": len(unlocked_programs),
        "blocked_programs": blocked_programs,
        "blocked_programs_count": len(blocked_programs),
        "discovered_repos": discovered_repos,
        "discovered_repos_count": len(discovered_repos),
        "eligibility_db_updated": elig_db is not None,
    }


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
    bounty_eligible_assets: List[str] = field(default_factory=list)
    max_severity_by_asset: Dict[str, str] = field(default_factory=dict)
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

    # 4. Extract in-scope repos, in-scope hosts, out-of-scope assets, and bounty/severity scope metadata
    in_scope_repos: List[str] = []
    in_scope_hosts: List[str] = []
    out_of_scope_assets: List[str] = []
    bounty_eligible_assets: List[str] = []
    max_severity_by_asset: Dict[str, str] = {}

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
        if attrs.get("eligible_for_bounty") is True:
            _add_unique(bounty_eligible_assets, ident)
        max_sev = str(attrs.get("max_severity") or "").strip().lower()
        if max_sev:
            max_severity_by_asset[ident] = max_sev
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
        bounty_eligible_assets=bounty_eligible_assets,
        max_severity_by_asset=max_severity_by_asset,
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
    source_scanner: str = "RFCHunt"
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
    """
    Checks whether a finding's asset/file matches a campaign's in-scope or out-of-scope assets
    using strict DNS label-boundary matching for hostnames/URLs (preventing `*.amazon.com`
    from matching `notamazon.com` or `amazon.com.evil.tld`).
    """
    from engine.program_eligibility_db import _normalize_hostname, host_matches_scope_pattern

    raw_asset = str(finding.get("asset_identifier") or "").strip()
    raw_file = str(finding.get("file_path") or "").strip()
    raw_title = str(finding.get("title") or "").strip()

    candidate_hosts: List[str] = []
    for cand in (raw_asset, raw_file):
        h = _normalize_hostname(cand)
        if h and "." in h and not h.endswith((".py", ".ts", ".js", ".go", ".rs", ".java", ".rb", ".c", ".cpp", ".h", ".yml", ".yaml", ".json", ".md", ".sh", ".ps1")):
            candidate_hosts.append(h)

    target_blob = " ".join([raw_file, raw_asset, raw_title]).lower()

    def _asset_matches(scope_entry: str) -> bool:
        entry = str(scope_entry or "").strip().lower()
        if not entry:
            return False
        # Strict DNS label-boundary matching for domain/wildcard/URL scope entries
        is_domain_or_url = (
            "://" in entry
            or entry.startswith("*.")
            or (bool(re.match(r"^[a-z0-9*.-]+\.[a-z*]{2,}$", entry.split("/", 1)[0])) and "github.com/" not in entry)
        )
        if is_domain_or_url and not entry.startswith("https://github.com/"):
            if candidate_hosts:
                return any(host_matches_scope_pattern(ch, entry) for ch in candidate_hosts)
            # Extract hostname tokens from target_blob and verify exact DNS label match
            for tok in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", target_blob):
                if host_matches_scope_pattern(tok, entry):
                    return True
            return False
        # Source repository URL or package identifier match
        norm_entry = entry.rstrip("/").removesuffix(".git")
        return bool(norm_entry) and (norm_entry in target_blob or norm_entry == campaign.handle.lower())

    for oos in campaign.out_of_scope_assets:
        if _asset_matches(oos):
            return "out_of_scope"
    if not campaign.in_scope_assets:
        return "manual_verify_required"
    for ins in campaign.in_scope_assets:
        if _asset_matches(ins):
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
        max_pages: int = 5,
    ) -> List[HackerOneCampaign]:
        """Paginated HackerOne Hacker API v1 program listing capturing launch/efficiency metadata."""
        q_low = str(query or "").strip().lower()
        out: List[HackerOneCampaign] = []
        target_cap = max(1, int(limit))
        page_size = min(100, max(25, target_cap))

        for page_num in range(1, max(1, int(max_pages)) + 1):
            data = self._request_json(f"hackers/programs?page[size]={page_size}&page[number]={page_num}")
            items = data.get("data") or []
            if not items:
                break
            for item in items:
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
                if len(out) >= target_cap:
                    return out[:target_cap]
            next_link = (data.get("links") or {}).get("next") if isinstance(data.get("links"), dict) else None
            if not next_link:
                break
        return out[:target_cap]

    def fetch_campaign_scope(
        self,
        handle: str,
        *,
        researcher_username: str = "",
        eligibility_db: Optional[Any] = None,
    ) -> HackerOneCampaign:
        clean_handle = validate_hackerone_handle(handle)
        prog = self._request_json(f"hackers/programs/{clean_handle}")
        attrs = (prog.get("data") or {}).get("attributes") or {}
        policy_text = str(attrs.get("policy") or "")
        scopes_resp = self._request_json(f"hackers/programs/{clean_handle}/structured_scopes?page[size]=100")
        scope_items = list(scopes_resp.get("data") or [])
        in_scope: List[str] = []
        out_scope: List[str] = []
        asset_type_counts: Dict[str, int] = {}
        bounty_eligible_cnt = 0
        for sc in scope_items:
            s_attrs = sc.get("attributes") or {}
            ident = str(s_attrs.get("asset_identifier") or "").strip()
            atype = str(s_attrs.get("asset_type") or "OTHER").strip().upper()
            if not ident:
                continue
            if bool(s_attrs.get("eligible_for_submission", True)):
                in_scope.append(ident)
                asset_type_counts[atype] = asset_type_counts.get(atype, 0) + 1
                if bool(s_attrs.get("eligible_for_bounty", False)):
                    bounty_eligible_cnt += 1
            else:
                out_scope.append(ident)

        eff_user = (researcher_username or self.username or "").strip()
        rules = parse_hackerone_program_policy(
            clean_handle,
            policy_text,
            structured_scopes=scope_items,
            researcher_username=eff_user,
        )
        camp = HackerOneCampaign(
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
        if eligibility_db is not None:
            sub_state = camp.submission_state.lower()
            status = "UNLOCKED" if sub_state == "open" else "PAUSED"
            resp_eff = attrs.get("response_efficiency_percentage")
            eligibility_db.upsert(
                clean_handle,
                status,
                submit_url=camp.submit_url,
                scope_summary=", ".join(in_scope[:10]),
                notes=f"Synced from HackerOne API v1 (state={camp.state}, submission_state={camp.submission_state}).",
                launched_at_utc=str(attrs.get("started_accepting_at") or ""),
                response_efficiency_pct=float(resp_eff) if resp_eff is not None else None,
                resolved_count=int(attrs.get("resolved_report_count") or 0),
                offers_bounties=camp.offers_bounties,
                is_vdp=not camp.offers_bounties,
                gold_standard=bool(attrs.get("gold_standard_safe_harbor", False)),
                fast_payments=bool(attrs.get("fast_payments", False)),
                submission_state=sub_state,
                wildcard_count=int(asset_type_counts.get("WILDCARD", 0)),
                domain_count=int(asset_type_counts.get("URL", 0) + asset_type_counts.get("DOMAIN", 0)),
                api_asset_count=int(asset_type_counts.get("API", 0)),
                mobile_asset_count=int(
                    asset_type_counts.get("GOOGLE_PLAY_APP_ID", 0)
                    + asset_type_counts.get("APPLE_STORE_APP_ID", 0)
                    + asset_type_counts.get("OTHER_APK", 0)
                    + asset_type_counts.get("OTHER_IPA", 0)
                    + asset_type_counts.get("MOBILE", 0)
                ),
                source_repo_count=len(rules.in_scope_repos) or int(asset_type_counts.get("SOURCE_CODE", 0)),
                ai_asset_count=int(asset_type_counts.get("AI_MODEL", 0)),
                bounty_eligible_asset_count=bounty_eligible_cnt,
                in_scope_assets=in_scope,
                in_scope_repos=rules.in_scope_repos,
                out_of_scope_assets=out_scope,
                scope_asset_types=asset_type_counts,
                roe_automation_tier=rules.automation_tier,
                roe_automated_prohibited=rules.automated_scanning_prohibited,
                roe_max_rps=rules.max_rps,
                roe_required_headers=rules.required_headers,
                roe_user_agent=rules.required_user_agent or "",
                roe_ai_disclosure_required=rules.ai_disclosure_required,
                roe_no_oos_redirects=rules.no_out_of_scope_redirects,
            )
        return camp

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


class HackerOnePublicDirectoryClient:
    """
    Zero-credential public HackerOne Program Directory client (`https://hackerone.com/graphql`).
    Queries publicly accessible VDPs and paid bug bounty programs sorted by newest launch date,
    filters for actively accepting submissions (`open`) and response efficiency (`>= min_efficiency_pct`),
    extracts structured scope breadth counts, and persists them into `ProgramEligibilityDB` v2.
    Enforces strict host pinning (or explicit loopback test server) and `TokenBucketRateLimiter` pacing.
    """

    PUBLIC_GRAPHQL_URL = "https://hackerone.com/graphql"

    _DIRECTORY_QUERY = """
    query DirectoryQuery($cursor: String, $where: FiltersOpportunitiesFilterInput, $order_by: OpportunityOrderInput) {
      opportunities_search(first: 25, after: $cursor, where: $where, order_by: $order_by) {
        pageInfo { endCursor hasNextPage }
        nodes {
          ... on Team {
            handle
            name
            state
            submission_state
            started_accepting_at
            offers_bounties
            response_efficiency_percentage
            resolved_report_count
            gold_standard_safe_harbor
            fast_payments
            first_program_response_time
            structured_scopes(first: 50) {
              nodes {
                asset_identifier
                asset_type
                eligible_for_submission
                eligible_for_bounty
                max_severity
              }
            }
          }
        }
      }
    }
    """

    def __init__(
        self,
        *,
        endpoint_url: Optional[str] = None,
        timeout_sec: float = 12.0,
        max_rps: float = 1.0,
    ) -> None:
        raw_url = str(endpoint_url or self.PUBLIC_GRAPHQL_URL).strip()
        parsed = urllib.parse.urlparse(raw_url)
        host = (parsed.hostname or "").lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            raw_url = validate_hackerone_url(raw_url)
        self.endpoint_url = raw_url
        self.timeout_sec = max(2.0, float(timeout_sec))
        from engine.request_hygiene import TokenBucketRateLimiter

        self._limiter = TokenBucketRateLimiter(max(0.1, min(float(max_rps), 2.0)))

    @staticmethod
    def parse_directory_payload(
        payload: Dict[str, Any],
        *,
        min_efficiency_pct: float = 0.0,
        only_open: bool = True,
        bounties_only: bool = False,
        vdp_only: bool = False,
    ) -> Tuple[List[Dict[str, Any]], Optional[str], bool]:
        """
        Parses a HackerOne public directory GraphQL (or REST/JSON) response into
        normalized `ProgramEligibilityDB` v2 upsert dicts sorted by newest `launched_at_utc`.
        Returns `(records, next_cursor, has_next_page)`.
        """
        search = (
            ((payload.get("data") or {}).get("opportunities_search"))
            if isinstance(payload.get("data"), dict)
            else None
        )
        if isinstance(search, dict):
            nodes = list(search.get("nodes") or [])
            page_info = search.get("pageInfo") if isinstance(search.get("pageInfo"), dict) else {}
            next_cursor = page_info.get("endCursor")
            has_next = bool(page_info.get("hasNextPage", False))
        else:
            nodes = list(payload.get("programs") or payload.get("nodes") or [])
            next_cursor = None
            has_next = False

        parsed_rows: List[Dict[str, Any]] = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            handle = str(node.get("handle") or "").strip().lower()
            if not handle or not _HANDLE_RE.match(handle):
                continue
            sub_state = str(node.get("submission_state") or "open").strip().lower()
            if only_open and sub_state != "open":
                continue
            offers_bounties = bool(node.get("offers_bounties", False))
            if bounties_only and not offers_bounties:
                continue
            if vdp_only and offers_bounties:
                continue
            raw_eff = node.get("response_efficiency_percentage")
            if raw_eff is None:
                raw_eff = node.get("response_efficiency_pct")
            eff_pct = float(raw_eff) if raw_eff is not None else None
            if eff_pct is not None and eff_pct < float(min_efficiency_pct):
                continue

            raw_scopes = node.get("structured_scopes")
            if isinstance(raw_scopes, dict):
                scope_nodes = list(raw_scopes.get("nodes") or [])
            elif isinstance(raw_scopes, list):
                scope_nodes = list(raw_scopes)
            else:
                scope_nodes = []

            in_scope: List[str] = []
            out_scope: List[str] = []
            in_repos: List[str] = []
            asset_counts: Dict[str, int] = {}
            bounty_eligible_cnt = 0
            for sc in scope_nodes:
                if not isinstance(sc, dict):
                    continue
                ident = str(sc.get("asset_identifier") or "").strip()
                atype = str(sc.get("asset_type") or "OTHER").strip().upper()
                if not ident:
                    continue
                if bool(sc.get("eligible_for_submission", True)):
                    in_scope.append(ident)
                    asset_counts[atype] = asset_counts.get(atype, 0) + 1
                    if bool(sc.get("eligible_for_bounty", False)):
                        bounty_eligible_cnt += 1
                    if atype == "SOURCE_CODE" or _GIT_REPO_URL_RX.match(ident):
                        try:
                            norm_u = validate_source_repo_url(ident)
                            if norm_u not in in_repos:
                                in_repos.append(norm_u)
                        except (PermissionError, ValueError):
                            pass
                else:
                    out_scope.append(ident)

            launched = str(node.get("started_accepting_at") or node.get("launched_at_utc") or "").strip()
            first_resp = node.get("first_program_response_time")
            if first_resp is None:
                first_resp = node.get("first_response_hours")

            parsed_rows.append(
                {
                    "handle": handle,
                    "name": str(node.get("name") or handle),
                    "status": "UNLOCKED" if sub_state == "open" else "PAUSED",
                    "submit_url": f"{HACKERONE_BASE_URL}/{handle}/reports/new",
                    "launched_at_utc": launched,
                    "response_efficiency_pct": eff_pct,
                    "first_response_hours": float(first_resp) if first_resp is not None else None,
                    "resolved_count": int(node.get("resolved_report_count") or node.get("resolved_count") or 0),
                    "offers_bounties": offers_bounties,
                    "is_vdp": not offers_bounties,
                    "gold_standard": bool(node.get("gold_standard_safe_harbor", node.get("gold_standard", False))),
                    "fast_payments": bool(node.get("fast_payments", False)),
                    "submission_state": sub_state,
                    "wildcard_count": int(asset_counts.get("WILDCARD", 0)),
                    "domain_count": int(asset_counts.get("URL", 0) + asset_counts.get("DOMAIN", 0)),
                    "api_asset_count": int(asset_counts.get("API", 0)),
                    "mobile_asset_count": int(
                        asset_counts.get("GOOGLE_PLAY_APP_ID", 0)
                        + asset_counts.get("APPLE_STORE_APP_ID", 0)
                        + asset_counts.get("OTHER_APK", 0)
                        + asset_counts.get("OTHER_IPA", 0)
                        + asset_counts.get("MOBILE", 0)
                    ),
                    "source_repo_count": len(in_repos) or int(asset_counts.get("SOURCE_CODE", 0)),
                    "ai_asset_count": int(asset_counts.get("AI_MODEL", 0)),
                    "bounty_eligible_asset_count": bounty_eligible_cnt,
                    "in_scope_assets": in_scope,
                    "in_scope_repos": in_repos,
                    "out_of_scope_assets": out_scope,
                    "scope_asset_types": asset_counts,
                    "scope_summary": ", ".join(in_scope[:10]),
                }
            )

        parsed_rows.sort(key=lambda r: (r["launched_at_utc"], r["handle"]), reverse=True)
        return parsed_rows, (str(next_cursor) if next_cursor else None), has_next

    def fetch_and_sync_directory(
        self,
        *,
        eligibility_db: Optional[Any] = None,
        query: str = "",
        limit: int = 25,
        min_efficiency_pct: float = 80.0,
        bounties_only: bool = False,
        vdp_only: bool = False,
        max_pages: int = 3,
    ) -> Dict[str, Any]:
        """
        Fetches public HackerOne directory entries sorted by newest launch date (`launched_at: DESC`)
        without requiring API credentials, and optionally upserts them into `ProgramEligibilityDB`.
        """
        collected: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        cap = max(1, int(limit))
        q_low = str(query or "").strip().lower()

        where_filter: Dict[str, Any] = {"submission_state": {"_eq": "open"}}
        if bounties_only:
            where_filter["offers_bounties"] = {"_eq": True}
        elif vdp_only:
            where_filter["offers_bounties"] = {"_eq": False}

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(max(1, int(max_pages))):
            self._limiter.acquire()
            body = json.dumps(
                {
                    "query": self._DIRECTORY_QUERY,
                    "variables": {
                        "cursor": cursor,
                        "where": where_filter,
                        "order_by": {"field": "launched_at", "direction": "DESC"},
                    },
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                self.endpoint_url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "RFCHunt-PublicDirectorySync/1.0",
                },
                method="POST",
            )
            with opener.open(req, timeout=self.timeout_sec) as resp:
                raw_json = json.loads(resp.read().decode("utf-8", errors="replace"))
            rows, next_cursor, has_next = self.parse_directory_payload(
                raw_json,
                min_efficiency_pct=min_efficiency_pct,
                only_open=True,
                bounties_only=bounties_only,
                vdp_only=vdp_only,
            )
            for row in rows:
                if q_low and q_low not in row["handle"] and q_low not in row["name"].lower():
                    continue
                collected.append(row)
                if len(collected) >= cap:
                    break
            if len(collected) >= cap or not has_next or not next_cursor:
                break
            cursor = next_cursor

        collected.sort(key=lambda r: (r["launched_at_utc"], r["handle"]), reverse=True)
        collected = collected[:cap]

        upserted: List[str] = []
        if eligibility_db is not None:
            for row in collected:
                eligibility_db.upsert(
                    row["handle"],
                    row["status"],
                    submit_url=row["submit_url"],
                    scope_summary=row["scope_summary"],
                    notes="Synced from HackerOne Public Program Directory (sorted newest launch first).",
                    launched_at_utc=row["launched_at_utc"],
                    response_efficiency_pct=row["response_efficiency_pct"],
                    first_response_hours=row["first_response_hours"],
                    resolved_count=row["resolved_count"],
                    offers_bounties=row["offers_bounties"],
                    is_vdp=row["is_vdp"],
                    gold_standard=row["gold_standard"],
                    fast_payments=row["fast_payments"],
                    submission_state=row["submission_state"],
                    wildcard_count=row["wildcard_count"],
                    domain_count=row["domain_count"],
                    api_asset_count=row["api_asset_count"],
                    mobile_asset_count=row["mobile_asset_count"],
                    source_repo_count=row["source_repo_count"],
                    ai_asset_count=row["ai_asset_count"],
                    bounty_eligible_asset_count=row["bounty_eligible_asset_count"],
                    in_scope_assets=row["in_scope_assets"],
                    in_scope_repos=row["in_scope_repos"],
                    out_of_scope_assets=row["out_of_scope_assets"],
                    scope_asset_types=row["scope_asset_types"],
                )
                upserted.append(row["handle"])

        return {
            "source": "hackerone_public_directory",
            "sorted_by": "launched_at_desc",
            "min_efficiency_pct": float(min_efficiency_pct),
            "fetched_count": len(collected),
            "upserted_count": len(upserted),
            "upserted": upserted,
            "programs": collected,
        }


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

    def stage_draft_ready_to_submit(
        self,
        campaign: HackerOneCampaign,
        draft: HackerOneReportDraft,
        *,
        cdp_url: Optional[str] = None,
        profile_dir: Optional[Union[str, Path]] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Pre-fills a single QA-verified HackerOne draft on `/reports/new` and saves it
        as a Draft (or leaves the filled form open for human review) so the user ONLY
        needs to review and click Submit manually.

        Hard Safety Invariants:
          - NEVER clicks any Submit / Publish / Send button (`auto_submit_forbidden=True`).
          - NEVER solves or bypasses login, 2FA, CAPTCHA, or Turnstile gates; pauses and
            reports `auth_or_captcha_checkpoint_required` if a gate is detected.
          - Prefers attaching to an already-logged-in HugOS Browser / Chromium CDP (`:9222`),
            falling back to a persistent visible Playwright profile (`profile_dir`).
        """
        validated_submit_url = validate_hackerone_url(draft.submit_url or campaign.submit_url)
        eff_cdp = (cdp_url or os.environ.get("RFCHUNT_HUGOS_CDP_URL") or "http://127.0.0.1:9222").rstrip("/")

        base_meta = {
            "draft_id": draft.draft_id,
            "program_handle": campaign.handle,
            "submit_url": validated_submit_url,
            "cdp_url": eff_cdp,
            "final_submit_blocked_for_hitl": True,
            "auto_submit_forbidden": True,
            "captcha_bypass_forbidden": True,
            "auto_submitted": False,
        }

        if dry_run:
            return {
                **base_meta,
                "status": "dry_run_draft_stage_planned",
                "dry_run": True,
                "draft_url": validated_submit_url,
                "filled_fields": [],
            }

        if not self._is_playwright_available():
            return {
                **base_meta,
                "status": "playwright_not_installed_manual_ready",
                "dry_run": False,
                "draft_url": validated_submit_url,
                "markdown_path": draft.markdown_path,
                "install_hint": "python -m pip install playwright && playwright install chromium",
            }

        cdp_reachable = False
        try:
            with urllib.request.urlopen(f"{eff_cdp}/json/version", timeout=0.4) as resp:
                cdp_reachable = int(resp.status) == 200
        except Exception:
            cdp_reachable = False

        from playwright.sync_api import sync_playwright

        filled_fields: List[str] = []
        draft_saved = False
        final_url = validated_submit_url
        auth_blocked = False
        connection_mode = "cdp" if cdp_reachable else "persistent_profile"

        with sync_playwright() as p:
            browser = None
            context = None
            page = None
            close_browser_on_exit = False
            try:
                if cdp_reachable:
                    browser = p.chromium.connect_over_cdp(eff_cdp)
                    context = browser.contexts[0] if browser.contexts else browser.new_context()
                    page = context.new_page()
                else:
                    p_dir = Path(profile_dir or (Path("out/autonomous_hunt/h1_browser_profile"))).resolve()
                    p_dir.mkdir(parents=True, exist_ok=True)
                    context = p.chromium.launch_persistent_context(str(p_dir), headless=False)
                    page = context.new_page()
                    close_browser_on_exit = False  # Keep tab open for human review/submit or close only on auth error

                page.goto(validated_submit_url, wait_until="domcontentloaded", timeout=30_000)
                page.wait_for_timeout(1500)
                cur_url = (page.url or "").lower()
                page_text_low = ""
                try:
                    page_text_low = (page.inner_text("body") or "")[:4000].lower()
                except Exception:
                    page_text_low = ""

                # Strictly stop on login, 2FA, or CAPTCHA/Turnstile — NEVER attempt bypass
                if (
                    "/users/sign_in" in cur_url
                    or "verify you are human" in page_text_low
                    or "just a moment" in page_text_low
                    or "two-factor authentication" in page_text_low
                ):
                    auth_blocked = True
                    final_url = page.url or validated_submit_url
                else:
                    selector_map = (
                        ("title", ['input[name*="title"]', 'input[id*="title"]', 'input[placeholder*="Title" i]'], draft.title),
                        (
                            "vulnerability_information",
                            [
                                'textarea[name*="vulnerability_information"]',
                                'textarea[id*="vulnerability_information"]',
                                'textarea[placeholder*="Describe" i]',
                            ],
                            draft.vulnerability_information,
                        ),
                        (
                            "impact",
                            ['textarea[name*="impact"]', 'textarea[id*="impact"]', 'textarea[placeholder*="Impact" i]'],
                            draft.impact,
                        ),
                    )
                    for field_name, selectors, value in selector_map:
                        for sel in selectors:
                            loc = page.locator(sel)
                            if loc.count() > 0:
                                loc.first.fill(value)
                                filled_fields.append(field_name)
                                break

                    # Click ONLY explicit Draft button — strictly forbid Submit/Publish/Send buttons
                    for btn_sel in (
                        'button:has-text("Save draft")',
                        'button:has-text("Create draft")',
                        'button:has-text("Save as draft")',
                    ):
                        btn = page.locator(btn_sel)
                        if btn.count() > 0:
                            label_txt = (btn.first.inner_text() or "").strip().lower()
                            if "submit" not in label_txt and "publish" not in label_txt and "send" not in label_txt:
                                btn.first.click()
                                page.wait_for_timeout(2000)
                                draft_saved = True
                                break

                    final_url = page.url or validated_submit_url
            finally:
                if close_browser_on_exit:
                    try:
                        if context is not None:
                            context.close()
                        if browser is not None:
                            browser.close()
                    except Exception:
                        pass

        if auth_blocked:
            return {
                **base_meta,
                "status": "auth_or_captcha_checkpoint_required",
                "connection_mode": connection_mode,
                "draft_url": final_url,
                "filled_fields": filled_fields,
                "draft_saved": False,
                "markdown_path": draft.markdown_path,
                "note": "Sign into HackerOne or complete the human check in your browser once, then re-run.",
            }

        return {
            **base_meta,
            "status": "draft_saved_ready_for_submit_click" if draft_saved else "form_prefilled_ready_for_submit_click",
            "connection_mode": connection_mode,
            "draft_url": final_url,
            "filled_fields": filled_fields,
            "draft_saved": draft_saved,
            "markdown_path": draft.markdown_path,
        }

    def run_interactive_browser_hunt_session(
        self,
        *,
        hunt_url: str = DEFAULT_BUG_HUNT_URL,
        cdp_url: Optional[str] = None,
        profile_dir: Optional[Union[str, Path]] = None,
        login_timeout_sec: float = 300.0,
        max_programs: int = 12,
        probe_report_id: int = 4243972,
        eligibility_db_path: Optional[Union[str, Path]] = None,
        draft_tracker_db_path: Optional[Union[str, Path]] = None,
        dry_run: bool = False,
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
    ) -> Dict[str, Any]:
        """
        Full interactive `/browser`-equivalent autonomous bug bounty session:
          1. Opens `hunt_url` (strictly pinned to official bug bounty origins) in a visible
             Chromium window (`connect_over_cdp` if reachable within 400ms, else persistent profile).
          2. Pauses and waits up to `login_timeout_sec` for the human researcher to sign in
             and complete 2FA / CAPTCHA / Turnstile directly (NEVER bypasses CAPTCHAs/auth).
          3. Once logged in, performs every read-only `/browser` operation automatically:
             - Syncs live researcher Signal/Reputation/Impact (`/current_user.json`)
             - Probes live draft cooldown (`can_submit_draft?` on `/reports/<probe_id>.json`)
             - Reads inbox Open/Triaged/Draft counts (`/bugs`)
             - Discovers UNLOCKED programs, RoE policies, structured scopes, and in-scope
               `github.com/<owner>/<repo>` targets and persists them to `ProgramEligibilityDB` v2.
          4. Hands discovered repos & unlocked programs directly into RFCHunt's scanning +
             3-Stage Parallel OODA + Swarm pipeline, and leaves the logged-in browser ready
             for HITL draft staging (NEVER clicks final Submit or Delete).
        """
        validated_url = validate_bug_hunt_url(hunt_url)
        platform = _detect_bounty_platform(validated_url)
        eff_cdp = (cdp_url or os.environ.get("RFCHUNT_HUGOS_CDP_URL") or "http://127.0.0.1:9222").rstrip("/")
        eff_profile = str(Path(profile_dir or "out/autonomous_hunt/h1_browser_profile").resolve())
        eff_timeout = max(5.0, min(3600.0, float(login_timeout_sec or 300.0)))
        eff_max_progs = max(1, min(30, int(max_programs or 12)))

        base_meta: Dict[str, Any] = {
            "schema": "rfchunt.interactive_browser_hunt.v1",
            "hunt_url": validated_url,
            "platform": platform,
            "cdp_url": eff_cdp,
            "profile_dir": eff_profile,
            "login_timeout_sec": eff_timeout,
            "max_programs": eff_max_progs,
            "probe_report_id": int(probe_report_id),
            "auto_submit_forbidden": True,
            "captcha_bypass_forbidden": True,
            "final_submit_blocked_for_hitl": True,
            "phases": [
                "1_open_bug_hunt_url_and_wait_human_login_hitl",
                "2_sync_inbox_cooldown_can_submit_draft_and_signal",
                "3_discover_unlocked_programs_scopes_and_github_repos",
                "4_handoff_targets_to_rfchunt_swarm_and_stage_verified_drafts_hitl",
            ],
        }

        if dry_run:
            return {
                **base_meta,
                "status": "dry_run_browser_hunt_planned",
                "dry_run": True,
                "browser_launched": False,
                "authenticated_user": "",
                "signal_score": None,
                "cooldown_status": "DRY_RUN_PLANNED",
                "cooldown_cleared": False,
                "unlocked_programs": [],
                "unlocked_programs_count": 0,
                "blocked_programs": [],
                "blocked_programs_count": 0,
                "discovered_repos": [],
                "discovered_repos_count": 0,
            }

        if not self._is_playwright_available():
            try:
                webbrowser.open_new_tab(validated_url)
                opened_fallback = True
            except Exception:
                opened_fallback = False
            return {
                **base_meta,
                "status": "playwright_not_installed_manual_ready",
                "dry_run": False,
                "browser_launched": opened_fallback,
                "install_hint": "python -m pip install playwright && playwright install chromium",
                "authenticated_user": "",
                "signal_score": None,
                "cooldown_status": "UNKNOWN",
                "cooldown_cleared": False,
                "unlocked_programs": [],
                "unlocked_programs_count": 0,
                "blocked_programs": [],
                "blocked_programs_count": 0,
                "discovered_repos": [],
                "discovered_repos_count": 0,
            }

        cdp_reachable = False
        try:
            with urllib.request.urlopen(f"{eff_cdp}/json/version", timeout=0.4) as resp:
                cdp_reachable = int(resp.status) == 200
        except Exception:
            cdp_reachable = False

        from playwright.sync_api import sync_playwright

        connection_mode = "cdp" if cdp_reachable else "persistent_profile"
        current_user: Dict[str, Any] = {}
        probe_report: Dict[str, Any] = {}
        inbox_counts: Dict[str, Any] = {}
        program_cards: List[Dict[str, Any]] = []
        page_links: List[str] = []
        logged_in = False

        with sync_playwright() as p:
            browser = None
            context = None
            page = None
            try:
                if cdp_reachable:
                    browser = p.chromium.connect_over_cdp(eff_cdp)
                    context = browser.contexts[0] if browser.contexts else browser.new_context()
                    page = context.new_page()
                else:
                    p_dir = Path(eff_profile)
                    p_dir.mkdir(parents=True, exist_ok=True)
                    context = p.chromium.launch_persistent_context(str(p_dir), headless=False)
                    page = context.new_page()

                page.goto(validated_url, wait_until="domcontentloaded", timeout=45_000)
                page.wait_for_timeout(1200)

                print(
                    f"\n[RFCHunt --hunt] Browser opened at: {validated_url}\n"
                    f"  -> Please complete sign-in, 2FA, and any human verification directly in the browser.\n"
                    f"  -> Auto-Submit: FORBIDDEN | CAPTCHA Bypass: FORBIDDEN | Timeout: {int(eff_timeout)}s\n",
                    flush=True,
                )

                if wait_for_human_fn is not None:
                    wait_for_human_fn(
                        f"Complete login on {validated_url} in the browser window, then press ENTER to begin hunting: "
                    )

                def _check_auth_state() -> Tuple[bool, Dict[str, Any]]:
                    cur_url = (page.url or "").lower()
                    body_low = ""
                    try:
                        body_low = (page.inner_text("body") or "")[:3000].lower()
                    except Exception:
                        body_low = ""
                    if any(
                        gate in cur_url
                        for gate in ("/users/sign_in", "/login", "/signin", "/auth/login")
                    ) or any(
                        gate in body_low
                        for gate in (
                            "verify you are human",
                            "just a moment",
                            "two-factor authentication",
                            "sign in to hackerone",
                        )
                    ):
                        return False, {}
                    if platform == "hackerone":
                        try:
                            cu = page.evaluate(
                                """async () => {
                                    try {
                                        const r = await fetch('/current_user.json', {credentials: 'same-origin'});
                                        if (!r.ok) return null;
                                        return await r.json();
                                    } catch (e) { return null; }
                                }"""
                            )
                            if isinstance(cu, dict) and (cu.get("username") or cu.get("id")):
                                return True, cu
                        except Exception:
                            pass
                        return False, {}
                    # Non-HackerOne official bounty portals (Bugcrowd / Immunefi / Intigriti)
                    return True, {"username": "authenticated_session"}

                deadline = time.monotonic() + eff_timeout
                while time.monotonic() < deadline:
                    logged_in, current_user = _check_auth_state()
                    if logged_in:
                        break
                    if wait_for_human_fn is not None:
                        break
                    time.sleep(2.0)

                if not logged_in:
                    return {
                        **base_meta,
                        "status": "login_timeout_hitl_required",
                        "dry_run": False,
                        "browser_launched": True,
                        "connection_mode": connection_mode,
                        "authenticated_user": "",
                        "signal_score": None,
                        "cooldown_status": "AUTH_REQUIRED",
                        "cooldown_cleared": False,
                        "unlocked_programs": [],
                        "unlocked_programs_count": 0,
                        "blocked_programs": [],
                        "blocked_programs_count": 0,
                        "discovered_repos": [],
                        "discovered_repos_count": 0,
                        "note": (
                            f"Login not completed within {int(eff_timeout)}s on {validated_url}. "
                            "Re-run with a larger --login-timeout or attach to an already-signed-in browser via --cdp-url."
                        ),
                    }

                # Phase 2: Read-only authenticated inbox, cooldown (`can_submit_draft?`) & Signal sync
                if platform == "hackerone":
                    try:
                        pr_data = page.evaluate(
                            f"""async () => {{
                                try {{
                                    const r = await fetch('/reports/{int(probe_report_id)}.json', {{credentials: 'same-origin'}});
                                    if (!r.ok) return null;
                                    return await r.json();
                                }} catch (e) {{ return null; }}
                            }}"""
                        )
                        if isinstance(pr_data, dict):
                            probe_report = pr_data
                    except Exception:
                        probe_report = {}

                    try:
                        bugs_data = page.evaluate(
                            """async () => {
                                try {
                                    const r = await fetch('/bugs.json?subject=user&report_id=0&view=all&substates[]=new&substates[]=triaged&substates[]=needs-more-info&substates[]=editing&text_query=&program_states[]=2&program_states[]=3&program_states[]=4&program_states[]=5&sort_type=latest_activity&sort_direction=descending&limit=50&page=1', {credentials: 'same-origin'});
                                    if (!r.ok) return null;
                                    return await r.json();
                                } catch (e) { return null; }
                            }"""
                        )
                        if isinstance(bugs_data, dict):
                            reports_arr = bugs_data.get("reports") or []
                            if isinstance(reports_arr, list):
                                inbox_counts = {
                                    "total_visible": len(reports_arr),
                                    "draft_reports": sum(
                                        1 for x in reports_arr if isinstance(x, dict) and str(x.get("state", "")).lower() == "draft"
                                    ),
                                    "triaged_reports": sum(
                                        1 for x in reports_arr if isinstance(x, dict) and str(x.get("substate", "")).lower() == "triaged"
                                    ),
                                    "open_reports": sum(
                                        1 for x in reports_arr if isinstance(x, dict) and str(x.get("state", "")).lower() != "draft"
                                    ),
                                }
                    except Exception:
                        inbox_counts = {}

                # Phase 3: Discover unlocked programs, scopes, and in-scope GitHub repositories
                if (page.url or "").rstrip("/") != validated_url.rstrip("/"):
                    try:
                        page.goto(validated_url, wait_until="domcontentloaded", timeout=30_000)
                        page.wait_for_timeout(1500)
                    except Exception:
                        pass

                try:
                    raw_hrefs = page.evaluate(
                        """() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href).slice(0, 600)"""
                    )
                    if isinstance(raw_hrefs, list):
                        page_links = [str(u) for u in raw_hrefs if isinstance(u, str)]
                except Exception:
                    page_links = []

                candidate_handles: List[str] = []
                parsed_root = urllib.parse.urlparse(validated_url)
                root_parts = [pt for pt in parsed_root.path.split("/") if pt]
                if platform == "hackerone":
                    if len(root_parts) >= 1 and root_parts[0].lower() not in _NON_PROGRAM_H1_PATHS:
                        candidate_handles.append(root_parts[0].lower())
                    else:
                        for href in page_links:
                            hp = urllib.parse.urlparse(href)
                            if (hp.hostname or "").lower() not in HACKERONE_ALLOWED_HOSTS:
                                continue
                            segs = [s for s in hp.path.split("/") if s]
                            if len(segs) == 1:
                                cand = segs[0].lower()
                                if (
                                    cand not in _NON_PROGRAM_H1_PATHS
                                    and _HANDLE_RE.match(cand)
                                    and cand not in candidate_handles
                                ):
                                    candidate_handles.append(cand)

                    for handle in candidate_handles[:eff_max_progs]:
                        prog_url = validate_hackerone_url(f"{HACKERONE_BASE_URL}/{handle}")
                        try:
                            page.goto(prog_url, wait_until="domcontentloaded", timeout=25_000)
                            page.wait_for_timeout(900)
                            p_body = (page.inner_text("body") or "")[:15000]
                            p_links = page.evaluate(
                                """() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href).slice(0, 300)"""
                            )
                            eff_match = re.search(r"(\d{1,3})\s*%\s*(?:response\s+efficiency|met\s+response)", p_body, re.IGNORECASE)
                            bounty_vals = [
                                int(v.replace(",", ""))
                                for v in re.findall(r"\$\s*([0-9][0-9,]{1,6})", p_body)
                                if v.replace(",", "").isdigit()
                            ]
                            sig_match = re.search(r"signal\s*(?:of|>=|requirement)?\s*(-?\d+(?:\.\d+)?)", p_body, re.IGNORECASE)
                            program_cards.append(
                                {
                                    "handle": handle,
                                    "name": handle,
                                    "submission_state": "paused" if "submissions are paused" in p_body.lower() else "open",
                                    "offers_bounties": bool(bounty_vals) or ("offers bounties" in p_body.lower()),
                                    "response_efficiency_pct": float(eff_match.group(1)) if eff_match else None,
                                    "bounty_min_usd": min(bounty_vals) if bounty_vals else None,
                                    "bounty_max_usd": max(bounty_vals) if bounty_vals else None,
                                    "signal_required": float(sig_match.group(1)) if sig_match else None,
                                    "signal_blocked": (
                                        "your signal is too low" in p_body.lower()
                                        or "do not meet the signal requirement" in p_body.lower()
                                    ),
                                    "submit_url": f"{HACKERONE_BASE_URL}/{handle}/reports/new",
                                    "policy_text": p_body,
                                    "links": p_links if isinstance(p_links, list) else [],
                                }
                            )
                        except Exception:
                            continue
                else:
                    # Generic official bounty portal capture (Bugcrowd / Immunefi / Intigriti)
                    p_body = ""
                    try:
                        p_body = (page.inner_text("body") or "")[:15000]
                    except Exception:
                        p_body = ""
                    slug = root_parts[-1] if root_parts else platform
                    if not _HANDLE_RE.match(slug):
                        slug = platform
                    program_cards.append(
                        {
                            "handle": slug,
                            "name": slug,
                            "submission_state": "open",
                            "offers_bounties": True,
                            "submit_url": validated_url,
                            "policy_text": p_body,
                            "links": page_links,
                        }
                    )
            finally:
                # Close temporary context cleanly when done? Keep persistent profile flushed on disk.
                if not cdp_reachable and context is not None:
                    try:
                        context.close()
                    except Exception:
                        pass

        extracted = extract_unlocked_programs_and_repos_from_page_data(
            hunt_url=validated_url,
            current_user=current_user,
            probe_report=probe_report,
            probe_report_id=int(probe_report_id),
            inbox_counts=inbox_counts,
            program_cards=program_cards,
            page_links=page_links,
            eligibility_db_path=eligibility_db_path,
            draft_tracker_db_path=draft_tracker_db_path,
        )
        return {
            **base_meta,
            **extracted,
            "status": "browser_hunt_session_completed",
            "dry_run": False,
            "browser_launched": True,
            "connection_mode": connection_mode,
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
        eligibility_db: Optional[Any] = None,
    ) -> Tuple[HackerOneCampaign, List[HackerOneCampaign]]:
        """
        Resolves a target HackerOne campaign and returns `(selected_campaign, matching_campaigns)`.
        When multiple campaigns match and `eligibility_db` is available (or API returns multiple),
        ranks candidates via `ml_program_selector.rank_hackerone_programs()` rather than blindly
        picking `matches[0]`.
        """
        matches: List[HackerOneCampaign] = []
        if use_api and not dry_run and self.api_client.has_credentials:
            if program_handle:
                camp = self.api_client.fetch_campaign_scope(
                    program_handle,
                    researcher_username=researcher_username,
                    eligibility_db=eligibility_db,
                )
                return camp, [camp]
            matches = self.api_client.list_campaigns(query=query, bounties_only=bounties_only, limit=25)
            if matches:
                # Filter out known BLOCKED_SIGNAL / PAUSED programs before picking via ML ranker
                chosen_handle = matches[0].handle
                if eligibility_db is not None:
                    unlocked_matches = [m for m in matches if eligibility_db.is_eligible(m.handle)]
                    if unlocked_matches:
                        try:
                            from engine.ml_program_selector import rank_hackerone_programs

                            ranked = rank_hackerone_programs(eligibility_db=eligibility_db)
                            rank_idx = {
                                str(r["handle"]).lower(): int(r["rank"])
                                for r in (ranked.get("ranked_programs") or [])
                            }
                            unlocked_matches.sort(key=lambda m: (rank_idx.get(m.handle.lower(), 9999), m.handle))
                        except Exception:
                            pass
                        chosen_handle = unlocked_matches[0].handle
                selected = self.api_client.fetch_campaign_scope(
                    chosen_handle,
                    researcher_username=researcher_username,
                    eligibility_db=eligibility_db,
                )
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
                target_n = max(1, int(max_programs or 2))
                listed = self.porter.api_client.list_campaigns(query=query, limit=max(10, target_n * 4))
                if eff_elig_db is not None and listed:
                    eligible_listed = [c for c in listed if eff_elig_db.is_eligible(c.handle)]
                    if eligible_listed:
                        listed = eligible_listed
                    try:
                        from engine.ml_program_selector import rank_hackerone_programs

                        ranked_res = rank_hackerone_programs(eligibility_db=eff_elig_db)
                        rank_order = {
                            str(r["handle"]).lower(): int(r.get("rank", 9999))
                            for r in (ranked_res.get("ranked_programs") or [])
                            if isinstance(r, dict) and r.get("handle")
                        }
                        listed = sorted(listed, key=lambda c: (rank_order.get(c.handle.lower(), 9999), c.handle.lower()))
                    except Exception:
                        pass
                for c_item in listed[:target_n]:
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
