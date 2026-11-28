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
import sqlite3
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request

from engine.advisory_exporter import _redact_inline_tokens
from engine.epistemic_state import (
    EpistemicStatus,
    _extract_oracles_from_finding,
    attach_epistemic_metadata,
)

HACKERONE_BASE_URL = "https://hackerone.com"
HACKERONE_API_BASE_URL = "https://api.hackerone.com/v1"
HACKERONE_ALLOWED_HOSTS = frozenset({"hackerone.com", "www.hackerone.com", "api.hackerone.com"})
ALLOWED_SOURCE_REPO_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

HACKERONE_TICKET_STATES: Tuple[str, ...] = (
    "draft_local",
    "held_cool_off",
    "queued_cooldown",
    "needs_live_poc",
    "hardening_pr_only",
    "do_not_submit",
    "duplicate_risk_hold",
    "informative_prevented",
    "draft_saved_on_site",
    "ready_to_submit",
    "submitted",
    "triaged",
    "needs_more_info",
    "retesting",
    "resolved",
    "bounty_awarded",
    "duplicate",
    "informative",
    "not_applicable",
    "closed",
)
HACKERONE_SUBMITTED_TICKET_STATES = frozenset(
    {
        "submitted",
        "triaged",
        "needs_more_info",
        "retesting",
        "resolved",
        "bounty_awarded",
        "duplicate",
    }
)

_COOL_OFF_ENV_VARS: Tuple[str, ...] = ("RFCHUNT_HACKERONE_COOL_OFF", "HACKERONE_COOL_OFF")

# Strict button label guards: on-site draft save may ONLY click explicit "Save draft" buttons, NEVER Submit
HACKERONE_SAVE_DRAFT_BUTTON_RX = re.compile(r"\bsave(?:\s+as)?\s+draft\b", re.IGNORECASE)
HACKERONE_SUBMIT_BUTTON_FORBIDDEN_RX = re.compile(
    r"\b(?:submit|publish|send\s+report|create\s+report|finalize\s+submission)\b",
    re.IGNORECASE,
)

# Read-only detection of HackerOne cool-off / cooldown / submission restriction notices
HACKERONE_COOL_OFF_BANNER_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"cool[- ]?off(?:\s+period)?", re.IGNORECASE),
    re.compile(r"cooldown(?:\s+period)?", re.IGNORECASE),
    re.compile(r"submission\s+limit(?:\s+reached)?", re.IGNORECASE),
    re.compile(r"(?:temporarily\s+)?(?:restricted|paused|blocked)\s+from\s+submitting", re.IGNORECASE),
    re.compile(r"cannot\s+submit\s+(?:new\s+)?reports?\s+(?:right\s+now|until|at\s+this\s+time)", re.IGNORECASE),
    re.compile(r"maximum\s+number\s+of\s+(?:open\s+)?reports", re.IGNORECASE),
    re.compile(r"signal\s+requirement\s+(?:not\s+met|is\s+not\s+met)", re.IGNORECASE),
)

# Safe Harbor hard exclusions: ALWAYS rejected even with runtime PoE (never draft DoS/phishing)
_H1_ALWAYS_EXCLUDED_SAFE_HARBOR_CLASSES: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "dos_ddos_resource_exhaustion",
        re.compile(
            r"\b(?:ddos|denial[- ]of[- ]service|redos|regular\s+expression\s+dos|volumetric\s+flood|"
            r"slowloris|cpu\s+exhaustion|memory\s+exhaustion|application[- ]layer\s+dos)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "social_engineering_or_physical",
        re.compile(
            r"\b(?:social\s+engineering|phishing|vishing|smishing|physical\s+(?:access|security)\s+attack|"
            r"spamming|mail\s+bombing)\b",
            re.IGNORECASE,
        ),
    ),
)

# Standard HackerOne non-qualifying / low-signal classes (rejected unless PROVEN_RUNTIME PoE=3 exploit chain)
_H1_STANDARD_NON_QUALIFYING_CLASSES: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "missing_security_headers",
        re.compile(
            r"\b(?:missing|absent|lack\s+of)\s+(?:http\s+)?(?:security\s+headers?|csp|content[- ]security[- ]policy|"
            r"hsts|strict[- ]transport[- ]security|x[- ]frame[- ]options|x[- ]content[- ]type[- ]options|"
            r"referrer[- ]policy|permissions[- ]policy)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "clickjacking_non_sensitive",
        re.compile(r"\b(?:clickjacking|ui\s+redressing)\b", re.IGNORECASE),
    ),
    (
        "self_xss_or_login_logout_csrf",
        re.compile(r"\b(?:self[- ]xss|login\s+csrf|logout\s+csrf|self[- ]csrf)\b", re.IGNORECASE),
    ),
    (
        "missing_cookie_flags",
        re.compile(
            r"\b(?:missing|without)\s+(?:httponly|secure|samesite)\s+(?:cookie\s+)?(?:flag|attribute)s?\b|"
            r"\bcookie\s+(?:missing|without)\s+(?:httponly|secure|samesite)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "missing_rate_limiting_or_enumeration",
        re.compile(
            r"\b(?:missing|no|lack\s+of)\s+rate[- ]?limit(?:ing)?\b|"
            r"\b(?:username|user|email|account)\s+enumeration\b|"
            r"\bweak\s+password\s+policy\b",
            re.IGNORECASE,
        ),
    ),
    (
        "dns_email_records",
        re.compile(
            r"\b(?:missing|weak|invalid)\s+(?:spf|dkim|dmarc|dnssec|caa)\s*(?:record|policy)?\b|"
            r"\bemail\s+spoofing\s+via\s+(?:missing\s+)?(?:spf|dmarc)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ssl_tls_best_practice_or_banner",
        re.compile(
            r"\b(?:server\s+version|software\s+version|banner)\s+disclosure\b|"
            r"\bx[- ]powered[- ]by\s+(?:header\s+)?disclosure\b|"
            r"\bweak\s+(?:ssl|tls)\s+cipher\s+suite\b|"
            r"\btls\s*1\.[01]\s+(?:enabled|supported)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "reverse_tabnabbing",
        re.compile(r"\b(?:reverse\s+)?tabnabbing\b|missing\s+rel=[\"']?noopener", re.IGNORECASE),
    ),
    (
        "open_redirect_unchained",
        re.compile(r"\bopen\s+redirect(?:ion)?\b", re.IGNORECASE),
    ),
    (
        "unverified_sca_dependency_only",
        re.compile(
            r"\b(?:outdated|vulnerable)\s+(?:software|library|package|dependency)\s+version\s+(?:without|only)\b|"
            r"\bdependency\s+bump\s+only\b",
            re.IGNORECASE,
        ),
    ),
    (
        "best_practice_or_informational",
        re.compile(
            r"\b(?:best[- ]practice\s+(?:only|recommendation|note)|hardening\s+(?:note|recommendation)|"
            r"defense[- ]in[- ]depth\s+only|informational\s+finding|code[- ]style\s+warning)\b",
            re.IGNORECASE,
        ),
    ),
)

# Exact path segments / filenames that represent non-production tests, fixtures, mocks, docs, or examples
_H1_TEST_OR_FIXTURE_SEGMENTS = frozenset(
    {
        "tests",
        "test",
        "__tests__",
        "fixtures",
        "fixture",
        "mocks",
        "mock",
        "examples",
        "example",
        "docs",
        "benchmarks",
        "testdata",
    }
)
_H1_TEST_FILENAME_RX = re.compile(
    r"^(?:test_.+\.py|.+_test\.(?:py|go|rs|ts|js)|.+\.(?:spec|test)\.(?:ts|tsx|js|jsx))$",
    re.IGNORECASE,
)

# Program-level out-of-scope / non-qualifying vulnerability extraction
_POLICY_OOS_SECTION_RX = re.compile(
    r"(?:out\s+of\s+scope|non[- ]qualifying\s+vulnerabilities?|excluded\s+vulnerabilities?|"
    r"we\s+do\s+not\s+accept|ineligible\s+findings?)[:\s-]*([^\n]{6,240})",
    re.IGNORECASE,
)

_REFUTED_VERIFICATION_STATUSES = frozenset(
    {
        "FALSE_POSITIVE",
        "DOWNGRADED_FALSE_POSITIVE",
        "REFUTED",
        "REJECTED",
        "REJECTED_COMMENT_LINE",
        "REJECTED_REGEX_PATTERN",
        "REJECTED_PLACEHOLDER",
        "REJECTED_CONSTANT_COMMAND",
        "REJECTED_CONSTANT_BINDING",
        "REJECTED_TEST_FIXTURE",
        "DOWNGRADED_PASSIVE_CHAIN",
        "TEST_FIXTURE",
        "HARDENING_NOTE",
        "UNSAT",
    }
)
_UNRESOLVED_VERIFICATION_STATUSES = frozenset(
    {
        "UNRESOLVED",
        "UNVERIFIED",
        "UNVERIFIED_CANDIDATE",
        "SKIPPED_DOCKER_UNAVAILABLE",
        "SKIPPED_BELOW_THRESHOLD",
        "REJECTED_UNSAFE_TARGET",
        "LLM_HEURISTIC",
        "SPECULATIVE_HYPOTHESIS",
    }
)

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


def is_cool_off_env_enabled() -> bool:
    """Returns True when cool-off / draft-only lock is active via environment variable."""
    for var in _COOL_OFF_ENV_VARS:
        val = (os.environ.get(var) or "").strip().lower()
        if val in ("1", "true", "yes", "on"):
            return True
    return False


def is_safe_save_draft_button_label(label: str) -> bool:
    """
    Fail-closed UI button label validator for on-site draft saving.
    Returns True ONLY for explicit 'Save draft' / 'Save as draft' labels and
    STRICTLY False if any submission verb ('submit', 'publish', 'send report', etc.) appears.
    """
    text = str(label or "").strip()
    if not text:
        return False
    if HACKERONE_SUBMIT_BUTTON_FORBIDDEN_RX.search(text):
        return False
    return bool(HACKERONE_SAVE_DRAFT_BUTTON_RX.search(text))


def detect_cool_off_notice(page_text: str) -> Optional[str]:
    """Detects read-only HackerOne cool-off / cooldown / submission-limit notices in page text."""
    text = str(page_text or "")
    if not text:
        return None
    for rx in HACKERONE_COOL_OFF_BANNER_PATTERNS:
        m = rx.search(text)
        if m:
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 80)
            return " ".join(text[start:end].split())
    return None


def _is_test_or_fixture_path(file_path: str) -> bool:
    """Detects non-production test, fixture, mock, example, or documentation paths."""
    norm = str(file_path or "").replace("\\", "/").strip()
    if not norm:
        return False
    parts = [p.lower() for p in norm.split("/") if p]
    if not parts:
        return False
    filename = parts[-1]
    if _H1_TEST_FILENAME_RX.match(filename):
        return True
    # Check directory segments while ignoring temporary pytest runner ancestor folders
    for seg in parts[:-1]:
        if seg.startswith("pytest-"):
            continue
        if seg in _H1_TEST_OR_FIXTURE_SEGMENTS:
            return True
    return False


def check_hackerone_signal_exclusions(
    finding: Dict[str, Any],
    *,
    policy_rules: Optional["HackerOnePolicyRules"] = None,
    epistemic_status: str = "",
) -> Optional[str]:
    """
    HackerOne Signal & Safe Harbor Quality Filter:
      1. ALWAYS rejects Safe Harbor prohibited classes (DoS/DDoS/ReDoS, social engineering/phishing),
         even with runtime PoE.
      2. Rejects test/fixture/mock/example/docs file paths.
      3. Rejects standard HackerOne non-qualifying / low-signal categories (missing security headers,
         clickjacking, self-XSS, login/logout CSRF, missing cookie flags, missing rate limiting,
         SPF/DMARC, banner disclosure, tabnabbing, unchained open redirect, unverified SCA-only,
         best-practice notes) UNLESS proven as a PoE>=3 `PROVEN_RUNTIME` exploit chain.
      4. Rejects findings matching program-specific excluded vulnerability classes parsed from RoE.
    """
    file_path = str(finding.get("file_path") or finding.get("file") or "").strip()
    if _is_test_or_fixture_path(file_path):
        return "rejected_h1_non_qualifying_test_or_fixture_path"

    blob = " ".join(
        [
            str(finding.get("rule_id") or ""),
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("cwe") or finding.get("cwe_id") or ""),
        ]
    )

    # 1. Safe Harbor absolute exclusions (never bypassable, even at PoE=3)
    for cls_name, rx in _H1_ALWAYS_EXCLUDED_SAFE_HARBOR_CLASSES:
        if rx.search(blob):
            return f"rejected_h1_safe_harbor_excluded_{cls_name}"

    poe_level = int(finding.get("poe_level", 1) or 1)
    eff_ep = str(epistemic_status or finding.get("epistemic_status") or "").strip().upper()
    is_proven_runtime_chain = eff_ep == EpistemicStatus.PROVEN_RUNTIME.value and poe_level >= 3

    # 2. Standard HackerOne non-qualifying / low-signal vulnerability classes
    if not is_proven_runtime_chain:
        for cls_name, rx in _H1_STANDARD_NON_QUALIFYING_CLASSES:
            if rx.search(blob):
                return f"rejected_h1_non_qualifying_{cls_name}"

    # 3. Program-specific excluded vulnerability classes extracted from RoE policy text
    if policy_rules and policy_rules.excluded_vuln_classes:
        blob_low = blob.lower()
        for excl in policy_rules.excluded_vuln_classes:
            tok = str(excl or "").strip().lower()
            if len(tok) >= 4 and tok in blob_low:
                safe_tok = re.sub(r"[^a-z0-9]+", "_", tok).strip("_")[:40]
                return f"rejected_h1_program_policy_excluded_{safe_tok}"

    return None


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
    excluded_vuln_classes: List[str] = field(default_factory=list)
    cool_off_enforced: bool = False
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

    # 5. Extract program-specific excluded / non-qualifying vulnerability classes from policy text
    excluded_vuln_classes: List[str] = []
    for m_oos in _POLICY_OOS_SECTION_RX.finditer(policy):
        clause = m_oos.group(1).strip()
        for piece in re.split(r"[,;/|]|\band\b", clause, flags=re.IGNORECASE):
            cleaned_piece = piece.strip(" .:-*•\t\r\n")
            if 4 <= len(cleaned_piece) <= 64 and not cleaned_piece.lower().startswith(("http://", "https://")):
                _add_unique(excluded_vuln_classes, cleaned_piece.lower())

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
        excluded_vuln_classes=excluded_vuln_classes,
        cool_off_enforced=is_cool_off_env_enabled(),
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
    epistemic_status: str = EpistemicStatus.PROVEN_STATIC_INVARIANT.value
    draft_only_cool_off: bool = False
    site_draft_saved: bool = False
    cash_ev_usd: float = 0.0
    expected_payout_usd: float = 0.0
    p_valid: float = 0.0
    p_duplicate: float = 0.0
    stride_category: str = ""
    stride_boundary_verdict: str = ""
    required_runtime: str = ""
    poc_verified_runtime: bool = False
    recommended_route: str = ""
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
    policy_rules: Optional[HackerOnePolicyRules] = None,
    strict_epistemic: bool = True,
    enforce_signal_filter: bool = True,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Strict HackerOne Code-of-Conduct Anti-Slop, 4-State Epistemic & Signal Protection Gate:
      - Enforces the 4-state Epistemic Lattice (`engine/epistemic_state.py`): rejects `REFUTED`,
        `UNRESOLVED`, `LLM_HEURISTIC`, multi-LLM correlated-only claims lacking an independent
        oracle, and spoofed `PROVEN_*` labels without independent oracles.
      - Rejects Lane 3 `SPECULATIVE_HYPOTHESIS` findings (unverified ARTEX/PromptSmuggler leads).
      - Rejects HackerOne Safe Harbor exclusions (DoS/DDoS/ReDoS, social engineering) and
        standard non-qualifying low-signal categories (missing headers, self-XSS, SPF/DMARC,
        test/fixture paths, and program-specific excluded classes).
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

        # 1. Strict 4-State Epistemic Lattice Gate (blocks REFUTED, UNRESOLVED, LLM-only consensus)
        resolved_epistemic = ""
        if strict_epistemic:
            existing_j = raw.get("status_justification") if isinstance(raw.get("status_justification"), dict) else {}
            raw_ep = str(raw.get("epistemic_status") or existing_j.get("epistemic_status") or "").strip().upper()
            ver_status = str(raw.get("verification_status") or raw.get("verdict") or "").strip().upper()
            z3_status = str(raw.get("z3_status") or "").strip().lower()
            poe_ver_status = str(raw.get("poe_verification_status") or "").strip().lower()
            indep_oracles, corr_oracles = _extract_oracles_from_finding(raw)

            if (
                raw_ep == EpistemicStatus.REFUTED.value
                or raw.get("false_positive") is True
                or z3_status == "unsat"
                or poe_ver_status in ("downgraded_false_positive", "refuted")
                or ver_status in _REFUTED_VERIFICATION_STATUSES
            ):
                rejected.append({"rule_id": raw.get("rule_id"), "reason": "rejected_epistemic_refuted"})
                continue

            if raw_ep == EpistemicStatus.UNRESOLVED.value or ver_status in _UNRESOLVED_VERIFICATION_STATUSES:
                rejected.append({"rule_id": raw.get("rule_id"), "reason": "rejected_epistemic_unresolved"})
                continue

            if lane == "LLM_HEURISTIC" or raw.get("llm_only") is True or (corr_oracles and not indep_oracles):
                rejected.append(
                    {"rule_id": raw.get("rule_id"), "reason": "rejected_epistemic_llm_only_no_independent_oracle"}
                )
                continue

            if raw_ep in (EpistemicStatus.PROVEN_RUNTIME.value, EpistemicStatus.PROVEN_STATIC_INVARIANT.value):
                # Enforce the Lean 4 hard cap: PROVEN_* MUST have at least one non-LLM independent oracle
                checked = attach_epistemic_metadata(
                    dict(raw),
                    justification={
                        **existing_j,
                        "epistemic_status": raw_ep,
                        "independent_oracles": indep_oracles,
                        "correlated_oracles": corr_oracles,
                    },
                )
                if checked.get("epistemic_status") not in (
                    EpistemicStatus.PROVEN_RUNTIME.value,
                    EpistemicStatus.PROVEN_STATIC_INVARIANT.value,
                ):
                    rejected.append(
                        {"rule_id": raw.get("rule_id"), "reason": "rejected_epistemic_llm_only_no_independent_oracle"}
                    )
                    continue
                resolved_epistemic = str(checked["epistemic_status"])
            else:
                # Deterministic legacy finding without explicit epistemic_status tag
                resolved_epistemic = (
                    EpistemicStatus.PROVEN_RUNTIME.value
                    if (lane == "VERIFIED_EXPLOIT" and poe >= 3)
                    else EpistemicStatus.PROVEN_STATIC_INVARIANT.value
                )
        else:
            resolved_epistemic = str(
                raw.get("epistemic_status")
                or (
                    EpistemicStatus.PROVEN_RUNTIME.value
                    if (lane == "VERIFIED_EXPLOIT" and poe >= 3)
                    else EpistemicStatus.PROVEN_STATIC_INVARIANT.value
                )
            ).upper()

        # 2. Minimum severity check
        sev_low = str(raw.get("severity") or "low").strip().lower()
        if _SEVERITY_RANK.get(sev_low, 0) < min_rank:
            rejected.append({"rule_id": raw.get("rule_id"), "reason": f"below_min_severity({sev_low}<{min_severity})"})
            continue

        # 3. Concrete location + concrete PoC/evidence requirement
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

        # 4. HackerOne Safe Harbor & Signal Protection Exclusion Filter
        if enforce_signal_filter:
            excl_reason = check_hackerone_signal_exclusions(
                raw,
                policy_rules=policy_rules,
                epistemic_status=resolved_epistemic,
            )
            if excl_reason:
                rejected.append({"rule_id": raw.get("rule_id"), "reason": excl_reason})
                continue

        # 5. Local SHA-256 deduplication ledger
        fp = compute_finding_fingerprint(raw, program_handle)
        if fp in seen_fps:
            rejected.append({"rule_id": raw.get("rule_id"), "reason": "duplicate_in_submission_ledger"})
            continue
        seen_fps.add(fp)
        eligible.append(
            {
                **raw,
                "evidence_lane": lane,
                "epistemic_status": resolved_epistemic,
                "_h1_fingerprint": fp,
            }
        )

    eligible.sort(
        key=lambda f: (
            0 if f.get("epistemic_status") == EpistemicStatus.PROVEN_RUNTIME.value else 1,
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
    cool_off_mode: bool = False,
) -> HackerOneReportDraft:
    """Formats a verified or deterministic RFCHunt finding into a secret- & PHI-redacted HackerOne draft."""
    rule_id = str(finding.get("rule_id") or "RFCHUNT-SEC-001")
    scanner = str(finding.get("scanner") or "RFCHunt")
    cwe = str(finding.get("cwe") or finding.get("cwe_id") or "CWE-20").upper()
    raw_sev = str(finding.get("severity") or "medium").strip().lower()
    h1_sev = raw_sev if raw_sev in ("critical", "high", "medium", "low") else "low"
    lane = str(finding.get("evidence_lane") or "DETERMINISTIC_STATIC")
    poe_level = int(finding.get("poe_level", 1) or 1)
    epistemic_status = str(
        finding.get("epistemic_status")
        or (
            EpistemicStatus.PROVEN_RUNTIME.value
            if (lane == "VERIFIED_EXPLOIT" and poe_level >= 3)
            else EpistemicStatus.PROVEN_STATIC_INVARIANT.value
        )
    ).upper()
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
        f"- **Epistemic Status**: `{epistemic_status}`",
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
        epistemic_status=epistemic_status,
        draft_only_cool_off=bool(cool_off_mode or is_cool_off_env_enabled()),
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
        cool_off_mode: bool = False,
        draft_only: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Submits a report via HackerOne Hacker API v1 (`POST /v1/hackers/reports`).
        Fails closed unconditionally while cool-off / draft-only mode is active, or unless
        `hitl_approved=True`, epistemic status is PROVEN_*, and scope is not out_of_scope.
        """
        eff_cool_off = bool(cool_off_mode or draft_only or draft.draft_only_cool_off or is_cool_off_env_enabled())
        if dry_run:
            if eff_cool_off:
                return {
                    "dry_run": True,
                    "status": "blocked_by_cool_off_draft_only_mode",
                    "submitted": False,
                    "endpoint": f"{HACKERONE_API_BASE_URL}/hackers/reports",
                    "draft_id": draft.draft_id,
                    "program_handle": draft.program_handle,
                }
            return {
                "dry_run": True,
                "status": "dry_run_would_submit_api",
                "endpoint": f"{HACKERONE_API_BASE_URL}/hackers/reports",
                "draft_id": draft.draft_id,
                "program_handle": draft.program_handle,
            }
        if eff_cool_off:
            raise PermissionError(
                "Refusing HackerOne API submission while cool-off / draft-only mode is active. "
                "Drafts are preserved locally (and may be saved via browser Save Draft only)."
            )
        if not hitl_approved:
            raise PermissionError("Refusing HackerOne API submission without explicit human-in-the-loop approval.")
        if draft.evidence_lane == "SPECULATIVE_HYPOTHESIS":
            raise PermissionError("Refusing to submit speculative Lane-3 hypothesis to HackerOne.")
        if str(draft.epistemic_status or "").upper() in (
            EpistemicStatus.UNRESOLVED.value,
            EpistemicStatus.REFUTED.value,
        ):
            raise PermissionError(
                f"Refusing to submit finding with epistemic_status={draft.epistemic_status!r} to HackerOne."
            )
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
        cool_off_mode: bool = False,
        save_draft_on_site: bool = False,
        dry_run: bool = False,
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
    ) -> Dict[str, Any]:
        """
        Runs an interactive visible browser session with mandatory human checkpoints.
        Never clicks the final Submit button automatically.
        When `save_draft_on_site=True`, fills each eligible draft and clicks ONLY a
        label-verified 'Save draft' button (`is_safe_save_draft_button_label`),
        never 'Submit report', and preserves local drafts if a cool-off notice blocks drafting.
        """
        eff_cool_off = bool(cool_off_mode or is_cool_off_env_enabled())
        if dry_run:
            return {
                "status": "dry_run_browser_session_planned",
                "dry_run": True,
                "cool_off_mode": eff_cool_off,
                "save_draft_on_site": bool(save_draft_on_site),
                "site_draft_action": (
                    "fill_and_save_draft_only_never_submit"
                    if save_draft_on_site
                    else "prefill_for_hitl_review_never_submit"
                ),
                "final_submit_blocked_for_hitl": True,
                "submission_hard_blocked": True,
                "campaign": campaign.to_dict(),
                "planned_login_url": f"{HACKERONE_BASE_URL}/users/sign_in",
                "planned_submit_url": campaign.submit_url,
                "planned_drafts_url": f"{HACKERONE_BASE_URL}/reports/drafts",
                "drafts_that_would_prefill": [d.draft_id for d in drafts],
                "drafts_prefilled": 0,
                "site_drafts_saved": 0,
            }

        if not drafts:
            return {
                "status": "skipped_no_eligible_drafts",
                "cool_off_mode": eff_cool_off,
                "save_draft_on_site": bool(save_draft_on_site),
                "final_submit_blocked_for_hitl": True,
                "submission_hard_blocked": True,
                "campaign": campaign.to_dict(),
                "drafts_prefilled": 0,
                "site_drafts_saved": 0,
            }

        if not self._is_playwright_available():
            return {
                "status": "playwright_not_installed_fallback_bundle_ready",
                "cool_off_mode": eff_cool_off,
                "save_draft_on_site": bool(save_draft_on_site),
                "final_submit_blocked_for_hitl": True,
                "submission_hard_blocked": True,
                "campaign": campaign.to_dict(),
                "manual_submit_url": campaign.submit_url,
                "install_hint": "python -m pip install playwright && playwright install chromium",
                "drafts_ready_for_manual_paste": [d.markdown_path for d in drafts if d.markdown_path],
                "site_drafts_saved": 0,
            }

        prompt_fn = wait_for_human_fn or input
        from playwright.sync_api import sync_playwright

        filled_drafts: List[Dict[str, Any]] = []
        discovered_campaigns: List[Dict[str, str]] = []
        cool_off_notices: List[str] = []
        site_drafts_saved = 0
        drafts_to_process = list(drafts) if save_draft_on_site else list(drafts[:1])

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

                save_draft_selectors = (
                    'button:has-text("Save draft")',
                    'button:has-text("Save as draft")',
                    '[data-testid*="save-draft" i]',
                    '[aria-label*="Save draft" i]',
                )

                for target_draft in drafts_to_process:
                    submit_url = validate_hackerone_url(target_draft.submit_url)
                    page.goto(submit_url, wait_until="domcontentloaded", timeout=30_000)
                    page.wait_for_timeout(1500)

                    # Read-only cool-off banner inspection
                    page_body_text = ""
                    try:
                        page_body_text = (page.locator("body").inner_text() or "")[:10_000]
                    except Exception:
                        page_body_text = ""
                    notice = detect_cool_off_notice(page_body_text)
                    if notice and notice not in cool_off_notices:
                        cool_off_notices.append(notice)

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

                    saved_on_site = False
                    site_status = "prefilled_only"
                    if not filled_fields and notice:
                        site_status = "blocked_by_site_cool_off_banner_local_draft_preserved"
                    elif save_draft_on_site and filled_fields:
                        # Strictly click ONLY a label-verified 'Save draft' button (NEVER Submit!)
                        for btn_sel in save_draft_selectors:
                            btn_loc = page.locator(btn_sel)
                            if btn_loc.count() > 0:
                                candidate = btn_loc.first
                                btn_label = ""
                                try:
                                    btn_label = (
                                        candidate.inner_text()
                                        or candidate.get_attribute("aria-label")
                                        or candidate.get_attribute("value")
                                        or ""
                                    ).strip()
                                except Exception:
                                    btn_label = ""
                                if is_safe_save_draft_button_label(btn_label):
                                    candidate.click()
                                    page.wait_for_timeout(1200)
                                    saved_on_site = True
                                    target_draft.site_draft_saved = True
                                    site_drafts_saved += 1
                                    site_status = "saved_on_site_as_draft_never_submitted"
                                    break
                        if not saved_on_site:
                            site_status = "form_prefilled_click_save_draft_manually"

                    filled_drafts.append(
                        {
                            "draft_id": target_draft.draft_id,
                            "submit_url": submit_url,
                            "filled_fields": filled_fields,
                            "site_draft_saved": saved_on_site,
                            "site_draft_status": site_status,
                            "cool_off_notice_detected": bool(notice),
                            "auto_submitted": False,
                            "cool_off_submission_blocked": eff_cool_off,
                        }
                    )

                # Checkpoint 2: Mandatory Final Human Review (NEVER auto-submit; warn during cool-off)
                if eff_cool_off or save_draft_on_site:
                    prompt_fn(
                        f"\n[HITL COOL-OFF / DRAFT-ONLY CHECKPOINT 2/2] Processed {len(filled_drafts)} draft(s) "
                        f"(saved_on_site={site_drafts_saved}; local drafts preserved on disk). "
                        "DO NOT click Submit during cool-off. Verify your draft(s) in HackerOne Drafts "
                        "and press ENTER to close browser: "
                    )
                else:
                    top_id = filled_drafts[0]["draft_id"] if filled_drafts else "none"
                    top_fields = filled_drafts[0]["filled_fields"] if filled_drafts else []
                    prompt_fn(
                        f"\n[HITL CHECKPOINT 2/2] Draft `{top_id}` has been filled in the browser "
                        f"(fields={top_fields}). Verify the PoC, select the exact Asset/Weakness if needed, "
                        "and click 'Submit report' manually in the browser. Press ENTER when done to close browser: "
                    )
            finally:
                try:
                    context.close()
                    browser.close()
                except Exception:
                    pass

        return {
            "status": (
                "hitl_browser_site_drafts_saved"
                if save_draft_on_site and site_drafts_saved > 0
                else (
                    "hitl_browser_blocked_by_cool_off_local_preserved"
                    if cool_off_notices and all(not d.get("filled_fields") for d in filled_drafts)
                    else "hitl_browser_prefill_completed"
                )
            ),
            "cool_off_mode": eff_cool_off,
            "save_draft_on_site": bool(save_draft_on_site),
            "cool_off_notices_detected": cool_off_notices,
            "final_submit_blocked_for_hitl": True,
            "submission_hard_blocked": True,
            "campaign": campaign.to_dict(),
            "discovered_campaigns": discovered_campaigns[:15],
            "filled_drafts": filled_drafts,
            "drafts_prefilled": len(filled_drafts),
            "site_drafts_saved": site_drafts_saved,
        }


def compute_bounty_opportunity_score(
    *,
    offers_bounties: bool,
    min_bounty_usd: float = 0.0,
    avg_bounty_low_usd: float = 0.0,
    avg_bounty_high_usd: float = 0.0,
    resolved_count: int = 0,
    has_source_code_scope: bool = False,
    automated_scanning_prohibited: bool = False,
) -> float:
    """
    Computes a transparent payout/ROI score for HackerOne programs:
      - Unpaid VDP programs (`offers_bounties=False`) score 0.0.
      - Weights average bounty payout heavily, adds freshness bonus for low resolved counts
        (lower competition), and rewards `SOURCE_CODE` scope (safe 100% offline local audits
        with zero network risk during cool-off).
    """
    if not offers_bounties:
        return 0.0
    avg_mid = (
        (float(avg_bounty_low_usd) + float(avg_bounty_high_usd)) / 2.0
        if (avg_bounty_low_usd > 0 or avg_bounty_high_usd > 0)
        else float(min_bounty_usd)
    )
    payout_pts = min(60.0, avg_mid / 40.0) + min(10.0, float(min_bounty_usd) / 25.0)
    # Fresh / low-competition bonus (0..20 pts)
    freshness_pts = 20.0 if resolved_count <= 10 else (14.0 if resolved_count <= 50 else (8.0 if resolved_count <= 250 else 3.0))
    # Local white-box source-code auditability bonus (100% Safe Harbor & cool-off friendly)
    source_pts = 15.0 if has_source_code_scope else 0.0
    # Slight penalty only if automated live scanning is banned AND no source code is in scope
    roe_penalty = -10.0 if (automated_scanning_prohibited and not has_source_code_scope) else 0.0
    return round(max(0.0, payout_pts + freshness_pts + source_pts + roe_penalty), 2)


class HackerOneTicketStore:
    """
    Persistent SQLite ticket, draft, state-transition history, and bounty program tracker.
    Uses parameterized queries and WAL mode; creates the DB file lazily so `--dry-run`
    never mutates disk.
    """

    def __init__(self, db_path: Path | str = "reports/hackerone/hackerone_tickets.db") -> None:
        self.db_path = Path(db_path).resolve(strict=False)

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema(conn)
        return conn

    @staticmethod
    def _init_schema(conn: sqlite3.Connection) -> None:
        states_sql = ", ".join(f"'{s}'" for s in HACKERONE_TICKET_STATES)
        conn.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS tickets (
                draft_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                program_handle TEXT NOT NULL,
                program_name TEXT NOT NULL DEFAULT '',
                offers_bounties INTEGER NOT NULL DEFAULT 0,
                title TEXT NOT NULL,
                weakness_cwe TEXT NOT NULL,
                severity_rating TEXT NOT NULL,
                epistemic_status TEXT NOT NULL,
                evidence_lane TEXT NOT NULL,
                poe_level INTEGER NOT NULL DEFAULT 1,
                asset_identifier TEXT NOT NULL,
                scope_match_status TEXT NOT NULL,
                source_rule_id TEXT NOT NULL,
                source_scanner TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ({states_sql})),
                cool_off_held INTEGER NOT NULL DEFAULT 0,
                local_markdown_path TEXT NOT NULL DEFAULT '',
                bundle_path TEXT NOT NULL DEFAULT '',
                submit_url TEXT NOT NULL DEFAULT '',
                site_draft_saved INTEGER NOT NULL DEFAULT 0,
                remote_report_id TEXT NOT NULL DEFAULT '',
                bounty_amount_usd REAL NOT NULL DEFAULT 0.0,
                cash_ev_usd REAL NOT NULL DEFAULT 0.0,
                expected_payout_usd REAL NOT NULL DEFAULT 0.0,
                p_valid REAL NOT NULL DEFAULT 0.0,
                p_duplicate REAL NOT NULL DEFAULT 0.0,
                stride_category TEXT NOT NULL DEFAULT '',
                stride_boundary_verdict TEXT NOT NULL DEFAULT '',
                target_boundary TEXT NOT NULL DEFAULT '',
                required_runtime TEXT NOT NULL DEFAULT '',
                poc_verified_runtime INTEGER NOT NULL DEFAULT 0,
                duplicate_check_status TEXT NOT NULL DEFAULT '',
                cooldown_unlock_at TEXT NOT NULL DEFAULT '',
                github_pr_url TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tickets_program_state ON tickets(program_handle, state);
            CREATE INDEX IF NOT EXISTS idx_tickets_state ON tickets(state);
            CREATE INDEX IF NOT EXISTS idx_tickets_cash_ev ON tickets(cash_ev_usd DESC);

            CREATE TABLE IF NOT EXISTS ticket_state_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_id TEXT NOT NULL,
                old_state TEXT NOT NULL,
                new_state TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                actor TEXT NOT NULL DEFAULT 'rfchunt',
                changed_at TEXT NOT NULL,
                FOREIGN KEY (draft_id) REFERENCES tickets(draft_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_history_draft_id ON ticket_state_history(draft_id);

            CREATE TABLE IF NOT EXISTS bounty_programs (
                handle TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                offers_bounties INTEGER NOT NULL DEFAULT 1,
                min_bounty_usd REAL NOT NULL DEFAULT 0.0,
                avg_bounty_low_usd REAL NOT NULL DEFAULT 0.0,
                avg_bounty_high_usd REAL NOT NULL DEFAULT 0.0,
                resolved_count INTEGER NOT NULL DEFAULT 0,
                launched_at TEXT NOT NULL DEFAULT '',
                has_source_code_scope INTEGER NOT NULL DEFAULT 0,
                in_scope_repos_json TEXT NOT NULL DEFAULT '[]',
                roe_tier TEXT NOT NULL DEFAULT '',
                max_rps REAL NOT NULL DEFAULT 2.0,
                payout_score REAL NOT NULL DEFAULT 0.0,
                discovered_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS report_signatures (
                draft_id TEXT PRIMARY KEY,
                program_handle TEXT NOT NULL,
                file_path TEXT NOT NULL DEFAULT '',
                file_basename TEXT NOT NULL DEFAULT '',
                function_name TEXT NOT NULL DEFAULT '',
                cwe TEXT NOT NULL DEFAULT '',
                sink_type TEXT NOT NULL DEFAULT '',
                tokens_json TEXT NOT NULL DEFAULT '[]',
                shingles_json TEXT NOT NULL DEFAULT '[]',
                verdict_outcome TEXT NOT NULL DEFAULT '',
                remote_report_id TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sig_program ON report_signatures(program_handle);
            CREATE INDEX IF NOT EXISTS idx_sig_file ON report_signatures(file_basename);
            """
        )
        HackerOneTicketStore._ensure_columns(conn)

    @staticmethod
    def _ensure_columns(conn: sqlite3.Connection) -> None:
        """Idempotently migrates older SQLite ticket tables to include cash-tuning, STRIDE & dedup columns."""
        existing = {str(r["name"]) for r in conn.execute("PRAGMA table_info(tickets)").fetchall()}
        additions = (
            ("cash_ev_usd", "REAL NOT NULL DEFAULT 0.0"),
            ("expected_payout_usd", "REAL NOT NULL DEFAULT 0.0"),
            ("p_valid", "REAL NOT NULL DEFAULT 0.0"),
            ("p_duplicate", "REAL NOT NULL DEFAULT 0.0"),
            ("stride_category", "TEXT NOT NULL DEFAULT ''"),
            ("stride_boundary_verdict", "TEXT NOT NULL DEFAULT ''"),
            ("target_boundary", "TEXT NOT NULL DEFAULT ''"),
            ("required_runtime", "TEXT NOT NULL DEFAULT ''"),
            ("poc_verified_runtime", "INTEGER NOT NULL DEFAULT 0"),
            ("duplicate_check_status", "TEXT NOT NULL DEFAULT ''"),
            ("cooldown_unlock_at", "TEXT NOT NULL DEFAULT ''"),
            ("github_pr_url", "TEXT NOT NULL DEFAULT ''"),
            ("code_age_hours", "REAL"),
            ("congestion_score", "REAL NOT NULL DEFAULT 0.45"),
            ("dedup_gate_verdict", "TEXT NOT NULL DEFAULT ''"),
            ("closest_prior_report", "TEXT NOT NULL DEFAULT ''"),
        )
        for col_name, col_def in additions:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE tickets ADD COLUMN {col_name} {col_def}")

    def _index_signature_conn(
        self,
        conn: sqlite3.Connection,
        *,
        draft_id: str,
        program_handle: str,
        file_path: str,
        title: str,
        cwe: str,
        evidence: str,
        verdict_outcome: str,
        remote_report_id: str = "",
    ) -> None:
        from engine.dedup_gate import build_structural_signature

        sig = build_structural_signature(
            {
                "file_path": file_path,
                "title": title,
                "cwe": cwe,
                "evidence": evidence,
                "program_handle": program_handle,
            },
            program_handle=program_handle,
        )
        now = _utc_now_iso()
        conn.execute(
            """
            INSERT INTO report_signatures (
                draft_id, program_handle, file_path, file_basename, function_name,
                cwe, sink_type, tokens_json, shingles_json, verdict_outcome,
                remote_report_id, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(draft_id) DO UPDATE SET
                file_path = excluded.file_path,
                file_basename = excluded.file_basename,
                function_name = excluded.function_name,
                cwe = excluded.cwe,
                sink_type = excluded.sink_type,
                tokens_json = excluded.tokens_json,
                shingles_json = excluded.shingles_json,
                verdict_outcome = excluded.verdict_outcome,
                remote_report_id = CASE WHEN excluded.remote_report_id != '' THEN excluded.remote_report_id ELSE report_signatures.remote_report_id END,
                updated_at = excluded.updated_at
            """,
            (
                draft_id,
                sig.program_handle,
                sig.file_path,
                sig.file_basename,
                sig.function_name,
                sig.cwe,
                sig.sink_type,
                json.dumps(sig.tokens),
                json.dumps(sig.shingles),
                str(verdict_outcome or ""),
                str(remote_report_id or ""),
                now,
            ),
        )

    def list_report_signatures(self, *, program_handle: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.db_path.is_file():
            return []
        with self._connect() as conn:
            if program_handle:
                rows = conn.execute(
                    "SELECT * FROM report_signatures WHERE program_handle = ? ORDER BY updated_at DESC",
                    (validate_hackerone_handle(program_handle),),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM report_signatures ORDER BY updated_at DESC").fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                d = dict(r)
                d["tokens"] = json.loads(d.get("tokens_json") or "[]")
                d["shingles"] = json.loads(d.get("shingles_json") or "[]")
                out.append(d)
            return out

    @staticmethod
    def validate_state(state: str) -> str:
        norm = str(state or "").strip().lower()
        if norm not in HACKERONE_TICKET_STATES:
            raise ValueError(f"Invalid HackerOne ticket state {state!r}; expected one of {HACKERONE_TICKET_STATES}")
        return norm

    def upsert_draft(
        self,
        draft: HackerOneReportDraft,
        *,
        state: str,
        bundle_path: str = "",
        program_name: str = "",
        offers_bounties: bool = False,
        reason: str = "draft_created",
        actor: str = "rfchunt",
        cash_ev_usd: Optional[float] = None,
        expected_payout_usd: Optional[float] = None,
        p_valid: Optional[float] = None,
        p_duplicate: Optional[float] = None,
        stride_category: Optional[str] = None,
        stride_boundary_verdict: Optional[str] = None,
        target_boundary: str = "",
        required_runtime: Optional[str] = None,
        poc_verified_runtime: Optional[bool] = None,
        duplicate_check_status: str = "",
        cooldown_unlock_at: str = "",
        remote_report_id: str = "",
    ) -> Dict[str, Any]:
        clean_state = self.validate_state(state)
        now = _utc_now_iso()
        eff_ev = float(draft.cash_ev_usd if cash_ev_usd is None else cash_ev_usd)
        eff_payout = float(draft.expected_payout_usd if expected_payout_usd is None else expected_payout_usd)
        eff_pvalid = float(draft.p_valid if p_valid is None else p_valid)
        eff_pdup = float(draft.p_duplicate if p_duplicate is None else p_duplicate)
        eff_stride = str(draft.stride_category if stride_category is None else stride_category)
        eff_verdict = str(draft.stride_boundary_verdict if stride_boundary_verdict is None else stride_boundary_verdict)
        eff_rt = str(draft.required_runtime if required_runtime is None else required_runtime)
        eff_poc_ok = 1 if (draft.poc_verified_runtime if poc_verified_runtime is None else poc_verified_runtime) else 0

        with self._connect() as conn:
            existing = conn.execute(
                "SELECT draft_id, state FROM tickets WHERE draft_id = ? OR fingerprint = ?",
                (draft.draft_id, draft.fingerprint),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO tickets (
                        draft_id, fingerprint, program_handle, program_name, offers_bounties,
                        title, weakness_cwe, severity_rating, epistemic_status, evidence_lane,
                        poe_level, asset_identifier, scope_match_status, source_rule_id,
                        source_scanner, state, cool_off_held, local_markdown_path, bundle_path,
                        submit_url, site_draft_saved, remote_report_id, bounty_amount_usd,
                        cash_ev_usd, expected_payout_usd, p_valid, p_duplicate,
                        stride_category, stride_boundary_verdict, target_boundary,
                        required_runtime, poc_verified_runtime, duplicate_check_status,
                        cooldown_unlock_at, github_pr_url, notes, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0.0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, ?)
                    """,
                    (
                        draft.draft_id,
                        draft.fingerprint,
                        draft.program_handle,
                        str(program_name or draft.program_handle),
                        1 if offers_bounties else 0,
                        draft.title,
                        draft.weakness_cwe,
                        draft.severity_rating,
                        draft.epistemic_status,
                        draft.evidence_lane,
                        int(draft.poe_level),
                        draft.asset_identifier,
                        draft.scope_match_status,
                        draft.source_rule_id,
                        draft.source_scanner,
                        clean_state,
                        1 if (draft.draft_only_cool_off or clean_state in ("held_cool_off", "queued_cooldown")) else 0,
                        draft.markdown_path,
                        str(bundle_path or ""),
                        draft.submit_url,
                        1 if draft.site_draft_saved else 0,
                        str(remote_report_id or ""),
                        eff_ev,
                        eff_payout,
                        eff_pvalid,
                        eff_pdup,
                        eff_stride,
                        eff_verdict,
                        str(target_boundary or ""),
                        eff_rt,
                        eff_poc_ok,
                        str(duplicate_check_status or ""),
                        str(cooldown_unlock_at or ""),
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO ticket_state_history (draft_id, old_state, new_state, reason, actor, changed_at)
                    VALUES (?, '', ?, ?, ?, ?)
                    """,
                    (draft.draft_id, clean_state, str(reason or "draft_created"), str(actor or "rfchunt"), now),
                )
            else:
                target_id = str(existing["draft_id"])
                old_state = str(existing["state"])
                # Never silently regress a submitted/triaged/paid ticket back to a draft state
                effective_state = (
                    old_state
                    if old_state in HACKERONE_SUBMITTED_TICKET_STATES and clean_state not in HACKERONE_SUBMITTED_TICKET_STATES
                    else clean_state
                )
                conn.execute(
                    """
                    UPDATE tickets
                    SET title = ?, severity_rating = ?, epistemic_status = ?, local_markdown_path = ?,
                        bundle_path = ?, state = ?, cool_off_held = ?,
                        site_draft_saved = CASE WHEN ? = 1 THEN 1 ELSE site_draft_saved END,
                        remote_report_id = CASE WHEN ? != '' THEN ? ELSE remote_report_id END,
                        cash_ev_usd = ?, expected_payout_usd = ?, p_valid = ?, p_duplicate = ?,
                        stride_category = CASE WHEN ? != '' THEN ? ELSE stride_category END,
                        stride_boundary_verdict = CASE WHEN ? != '' THEN ? ELSE stride_boundary_verdict END,
                        target_boundary = CASE WHEN ? != '' THEN ? ELSE target_boundary END,
                        required_runtime = CASE WHEN ? != '' THEN ? ELSE required_runtime END,
                        poc_verified_runtime = CASE WHEN ? = 1 THEN 1 ELSE poc_verified_runtime END,
                        duplicate_check_status = CASE WHEN ? != '' THEN ? ELSE duplicate_check_status END,
                        cooldown_unlock_at = CASE WHEN ? != '' THEN ? ELSE cooldown_unlock_at END,
                        updated_at = ?
                    WHERE draft_id = ?
                    """,
                    (
                        draft.title,
                        draft.severity_rating,
                        draft.epistemic_status,
                        draft.markdown_path,
                        str(bundle_path or ""),
                        effective_state,
                        1 if (draft.draft_only_cool_off or effective_state in ("held_cool_off", "queued_cooldown")) else 0,
                        1 if draft.site_draft_saved else 0,
                        str(remote_report_id or ""),
                        str(remote_report_id or ""),
                        eff_ev,
                        eff_payout,
                        eff_pvalid,
                        eff_pdup,
                        eff_stride,
                        eff_stride,
                        eff_verdict,
                        eff_verdict,
                        str(target_boundary or ""),
                        str(target_boundary or ""),
                        eff_rt,
                        eff_rt,
                        eff_poc_ok,
                        str(duplicate_check_status or ""),
                        str(duplicate_check_status or ""),
                        str(cooldown_unlock_at or ""),
                        str(cooldown_unlock_at or ""),
                        now,
                        target_id,
                    ),
                )
                if effective_state != old_state:
                    conn.execute(
                        """
                        INSERT INTO ticket_state_history (draft_id, old_state, new_state, reason, actor, changed_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (target_id, old_state, effective_state, str(reason or "draft_updated"), str(actor or "rfchunt"), now),
                    )
            row = conn.execute("SELECT * FROM tickets WHERE draft_id = ? OR fingerprint = ?", (draft.draft_id, draft.fingerprint)).fetchone()
            if row is not None:
                self._index_signature_conn(
                    conn,
                    draft_id=str(row["draft_id"]),
                    program_handle=str(row["program_handle"]),
                    file_path=str(row["asset_identifier"]),
                    title=str(row["title"]),
                    cwe=str(row["weakness_cwe"]),
                    evidence=str(draft.vulnerability_information[:600]),
                    verdict_outcome=str(row["state"]),
                    remote_report_id=str(row["remote_report_id"]),
                )
            return dict(row) if row is not None else {}

    def transition_state(
        self,
        draft_id: str,
        new_state: str,
        *,
        reason: str = "",
        remote_report_id: str = "",
        site_draft_saved: Optional[bool] = None,
        bounty_amount_usd: Optional[float] = None,
        notes: Optional[str] = None,
        actor: str = "rfchunt",
    ) -> Dict[str, Any]:
        clean_state = self.validate_state(new_state)
        now = _utc_now_iso()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tickets WHERE draft_id = ?", (draft_id,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown HackerOne ticket draft_id: {draft_id!r}")
            old_state = str(row["state"])
            eff_remote_id = str(remote_report_id or row["remote_report_id"] or "")
            eff_site_saved = int(row["site_draft_saved"]) if site_draft_saved is None else (1 if site_draft_saved else 0)
            eff_bounty = float(row["bounty_amount_usd"]) if bounty_amount_usd is None else max(0.0, float(bounty_amount_usd))
            eff_notes = str(row["notes"] or "") if notes is None else str(notes)
            eff_cool_off_held = 1 if clean_state == "held_cool_off" else (0 if clean_state in HACKERONE_SUBMITTED_TICKET_STATES else int(row["cool_off_held"]))
            conn.execute(
                """
                UPDATE tickets
                SET state = ?, cool_off_held = ?, site_draft_saved = ?, remote_report_id = ?,
                    bounty_amount_usd = ?, notes = ?, updated_at = ?
                WHERE draft_id = ?
                """,
                (clean_state, eff_cool_off_held, eff_site_saved, eff_remote_id, eff_bounty, eff_notes, now, draft_id),
            )
            if old_state != clean_state or reason:
                conn.execute(
                    """
                    INSERT INTO ticket_state_history (draft_id, old_state, new_state, reason, actor, changed_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (draft_id, old_state, clean_state, str(reason or "state_transition"), str(actor or "rfchunt"), now),
                )
            updated = conn.execute("SELECT * FROM tickets WHERE draft_id = ?", (draft_id,)).fetchone()
            if updated is not None:
                self._index_signature_conn(
                    conn,
                    draft_id=str(updated["draft_id"]),
                    program_handle=str(updated["program_handle"]),
                    file_path=str(updated["asset_identifier"]),
                    title=str(updated["title"]),
                    cwe=str(updated["weakness_cwe"]),
                    evidence=str(updated["notes"]),
                    verdict_outcome=str(updated["state"]),
                    remote_report_id=str(updated["remote_report_id"]),
                )
            return dict(updated) if updated is not None else {}

    def get_ticket(self, draft_id: str) -> Optional[Dict[str, Any]]:
        if not self.db_path.is_file():
            return None
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tickets WHERE draft_id = ?", (draft_id,)).fetchone()
            if row is None:
                return None
            hist = [
                dict(h)
                for h in conn.execute(
                    "SELECT old_state, new_state, reason, actor, changed_at FROM ticket_state_history WHERE draft_id = ? ORDER BY id ASC",
                    (draft_id,),
                ).fetchall()
            ]
            out = dict(row)
            out["history"] = hist
            return out

    def list_tickets(
        self,
        *,
        program_handle: Optional[str] = None,
        state: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if not self.db_path.is_file():
            return []
        clauses: List[str] = []
        params: List[Any] = []
        if program_handle:
            clauses.append("program_handle = ?")
            params.append(validate_hackerone_handle(program_handle))
        if state:
            clauses.append("state = ?")
            params.append(self.validate_state(state))
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(1000, int(limit or 100))))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM tickets {where_sql} ORDER BY updated_at DESC LIMIT ?",
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    def get_tracked_fingerprints(self, *, states: Optional[Sequence[str]] = None) -> List[str]:
        if not self.db_path.is_file():
            return []
        target_states = tuple(
            self.validate_state(s) for s in (states if states is not None else HACKERONE_SUBMITTED_TICKET_STATES)
        )
        if not target_states:
            return []
        placeholders = ", ".join("?" for _ in target_states)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT fingerprint FROM tickets WHERE state IN ({placeholders})",
                target_states,
            ).fetchall()
            return [str(r["fingerprint"]) for r in rows]

    def upsert_bounty_program(
        self,
        *,
        handle: str,
        name: str,
        url: str = "",
        offers_bounties: bool = True,
        min_bounty_usd: float = 0.0,
        avg_bounty_low_usd: float = 0.0,
        avg_bounty_high_usd: float = 0.0,
        resolved_count: int = 0,
        launched_at: str = "",
        has_source_code_scope: bool = False,
        in_scope_repos: Optional[Sequence[str]] = None,
        roe_tier: str = "",
        max_rps: float = 2.0,
        automated_scanning_prohibited: bool = False,
    ) -> Dict[str, Any]:
        clean_h = validate_hackerone_handle(handle)
        safe_url = validate_hackerone_url(url or f"{HACKERONE_BASE_URL}/{clean_h}")
        repos_clean = [validate_source_repo_url(r) for r in (in_scope_repos or ())]
        score = compute_bounty_opportunity_score(
            offers_bounties=offers_bounties,
            min_bounty_usd=min_bounty_usd,
            avg_bounty_low_usd=avg_bounty_low_usd,
            avg_bounty_high_usd=avg_bounty_high_usd,
            resolved_count=resolved_count,
            has_source_code_scope=bool(has_source_code_scope or repos_clean),
            automated_scanning_prohibited=automated_scanning_prohibited,
        )
        now = _utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO bounty_programs (
                    handle, name, url, offers_bounties, min_bounty_usd,
                    avg_bounty_low_usd, avg_bounty_high_usd, resolved_count,
                    launched_at, has_source_code_scope, in_scope_repos_json,
                    roe_tier, max_rps, payout_score, discovered_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(handle) DO UPDATE SET
                    name = excluded.name,
                    url = excluded.url,
                    offers_bounties = excluded.offers_bounties,
                    min_bounty_usd = excluded.min_bounty_usd,
                    avg_bounty_low_usd = excluded.avg_bounty_low_usd,
                    avg_bounty_high_usd = excluded.avg_bounty_high_usd,
                    resolved_count = excluded.resolved_count,
                    launched_at = excluded.launched_at,
                    has_source_code_scope = excluded.has_source_code_scope,
                    in_scope_repos_json = CASE
                        WHEN excluded.in_scope_repos_json != '[]' THEN excluded.in_scope_repos_json
                        ELSE bounty_programs.in_scope_repos_json
                    END,
                    roe_tier = CASE WHEN excluded.roe_tier != '' THEN excluded.roe_tier ELSE bounty_programs.roe_tier END,
                    max_rps = excluded.max_rps,
                    payout_score = excluded.payout_score,
                    updated_at = excluded.updated_at
                """,
                (
                    clean_h,
                    str(name or clean_h),
                    safe_url,
                    1 if offers_bounties else 0,
                    float(min_bounty_usd or 0.0),
                    float(avg_bounty_low_usd or 0.0),
                    float(avg_bounty_high_usd or 0.0),
                    int(resolved_count or 0),
                    str(launched_at or ""),
                    1 if (has_source_code_scope or repos_clean) else 0,
                    json.dumps(repos_clean),
                    str(roe_tier or ""),
                    float(max_rps if max_rps is not None else 2.0),
                    score,
                    now,
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM bounty_programs WHERE handle = ?", (clean_h,)).fetchone()
            out = dict(row) if row is not None else {}
            if out:
                out["in_scope_repos"] = json.loads(out.get("in_scope_repos_json") or "[]")
            return out

    def list_bounty_programs(
        self,
        *,
        bounties_only: bool = True,
        source_code_only: bool = False,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        if not self.db_path.is_file():
            return []
        clauses: List[str] = []
        params: List[Any] = []
        if bounties_only:
            clauses.append("offers_bounties = 1")
        if source_code_only:
            clauses.append("has_source_code_scope = 1")
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(200, int(limit or 25))))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM bounty_programs {where_sql} ORDER BY payout_score DESC, avg_bounty_high_usd DESC LIMIT ?",
                params,
            ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                d = dict(r)
                d["in_scope_repos"] = json.loads(d.get("in_scope_repos_json") or "[]")
                out.append(d)
            return out

    def get_state_summary(self) -> Dict[str, Any]:
        if not self.db_path.is_file():
            return {
                "db_path": str(self.db_path),
                "exists": False,
                "total_tickets": 0,
                "by_state": {},
                "cool_off_held_count": 0,
                "site_drafts_saved_count": 0,
                "total_bounty_usd": 0.0,
                "tracked_bounty_programs": 0,
            }
        with self._connect() as conn:
            state_rows = conn.execute("SELECT state, COUNT(*) AS cnt FROM tickets GROUP BY state").fetchall()
            by_state = {str(r["state"]): int(r["cnt"]) for r in state_rows}
            agg = conn.execute(
                """
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(cool_off_held), 0) AS cool_off_held,
                       COALESCE(SUM(site_draft_saved), 0) AS site_saved,
                       COALESCE(SUM(bounty_amount_usd), 0.0) AS total_bounty
                FROM tickets
                """
            ).fetchone()
            prog_cnt = conn.execute("SELECT COUNT(*) AS cnt FROM bounty_programs").fetchone()
            return {
                "db_path": str(self.db_path),
                "exists": True,
                "total_tickets": int(agg["total"] or 0),
                "by_state": by_state,
                "cool_off_held_count": int(agg["cool_off_held"] or 0),
                "site_drafts_saved_count": int(agg["site_saved"] or 0),
                "total_bounty_usd": round(float(agg["total_bounty"] or 0.0), 2),
                "tracked_bounty_programs": int(prog_cnt["cnt"] or 0),
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
        ticket_store: Optional[HackerOneTicketStore] = None,
    ) -> None:
        self.output_dir = Path(output_dir).resolve(strict=False)
        self.ledger_path = self.output_dir / "submission_ledger.json"
        self.ticket_store = ticket_store or HackerOneTicketStore(self.output_dir / "hackerone_tickets.db")
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
        cool_off_mode: bool = False,
        draft_only: bool = False,
        save_draft_on_site: bool = False,
        strict_epistemic: bool = True,
        enforce_signal_filter: bool = True,
        cash_tune: bool = True,
        stride_model: Optional[Dict[str, Any]] = None,
        allow_network_dup_check: bool = False,
        dry_run: bool = False,
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
    ) -> Dict[str, Any]:
        """
        Full `--hackerone` porting pipeline with:
          - Strict 4-State Epistemic Gate (blocks REFUTED, UNRESOLVED, LLM-only consensus),
          - Precision STRIDE Trust-Boundary & Non-Goal Verification + Cash EV Scorer,
          - HackerOne Safe Harbor & Signal Protection Exclusion Filter,
          - Cool-Off / Draft-Only Mode Lock (hard-blocks API submission & Submit button),
          - Persistent SQLite ticket/program state store (`hackerone_tickets.db`),
          - Local Markdown/JSON drafts + optional safe on-site 'Save draft' browser staging,
          - Universal `--dry-run` safety.
        """
        eff_cool_off = bool(cool_off_mode or draft_only or is_cool_off_env_enabled())
        if eff_cool_off and submit_api and not dry_run:
            raise PermissionError(
                "Refusing HackerOne API submission while cool-off / draft-only mode is active. "
                "Use local drafts and/or --hackerone-save-site-draft instead."
            )

        campaign, matches = self.resolve_campaign(
            program_handle=program_handle,
            query=query,
            use_api=use_api,
            bounties_only=bounties_only,
            researcher_username=researcher_username,
            policy_text_override=policy_text_override,
            dry_run=dry_run,
        )
        rules_obj: Optional[HackerOnePolicyRules] = None
        if isinstance(campaign.policy_rules, dict):
            try:
                rules_obj = HackerOnePolicyRules(**campaign.policy_rules)
            except Exception:
                rules_obj = None

        ledger = self._load_ledger()
        submitted_fps = set(ledger.get("submitted_fingerprints") or [])
        submitted_fps.update(self.ticket_store.get_tracked_fingerprints())
        eligible, rejected = filter_eligible_findings(
            findings,
            min_severity=min_severity,
            max_reports=max_reports,
            submitted_fingerprints=sorted(submitted_fps),
            program_handle=campaign.handle,
            policy_rules=rules_obj,
            strict_epistemic=strict_epistemic,
            enforce_signal_filter=enforce_signal_filter,
        )

        # Precision STRIDE + Cash EV calibration pass
        program_meta: Dict[str, Any] = {
            "offers_bounties": True if campaign.offers_bounties else True,
            "in_scope_repos": list((campaign.policy_rules or {}).get("in_scope_repos") or []),
        }
        tracked_progs = {p["handle"]: p for p in self.ticket_store.list_bounty_programs(bounties_only=False, limit=200)}
        if campaign.handle in tracked_progs:
            program_meta.update(tracked_progs[campaign.handle])

        cash_filtered: List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]] = []
        cash_held: List[Dict[str, Any]] = []
        if cash_tune:
            from engine.cash_bounty_tuner import score_finding_cash_ev

            prior_sigs = self.ticket_store.list_report_signatures(program_handle=campaign.handle)
            for f_item in eligible:
                cand_fp = str(f_item.get("_h1_fingerprint") or compute_finding_fingerprint(f_item, campaign.handle))
                cand_draft_id = f"H1-{campaign.handle.upper()}-{cand_fp[:8].upper()}"
                filtered_sigs = [s for s in prior_sigs if str(s.get("draft_id") or "") != cand_draft_id]
                ev_res = score_finding_cash_ev(
                    f_item,
                    program_meta={**program_meta, "handle": campaign.handle},
                    stride_model=stride_model,
                    policy_text=campaign.policy_text,
                    cool_off_active=eff_cool_off,
                    allow_network_dup_check=allow_network_dup_check,
                    prior_signatures=filtered_sigs,
                    dry_run=dry_run,
                )
                ev_dict = ev_res.to_dict()
                verdict = str((ev_dict.get("stride_verdict") or {}).get("verdict") or "")
                dup_st = str((ev_dict.get("duplicate_risk") or {}).get("status") or "")
                if verdict in ("DOCUMENTED_AS_DESIGNED", "BOUNDARY_NOT_CROSSED", "HARDENING_CANDIDATE_NOT_BOUNTY") or dup_st in (
                    "UPSTREAM_MATCH_FOUND",
                    "HOLD_CROSS_REPORT_DUPLICATE",
                    "HOLD_LIKELY_PATCHED_UPSTREAM",
                ):
                    reason_tag = f"cash_tuner_{ev_res.target_ticket_state}"
                    rejected.append({"rule_id": f_item.get("rule_id"), "reason": reason_tag, "cash_ev": ev_dict})
                    cash_held.append({"rule_id": f_item.get("rule_id"), "state": ev_res.target_ticket_state, "cash_ev": ev_dict})
                    if not dry_run:
                        held_draft = build_hackerone_report_draft(
                            f_item,
                            campaign,
                            include_ai_disclosure=include_ai_disclosure,
                            cool_off_mode=eff_cool_off,
                        )
                        held_draft.cash_ev_usd = ev_res.cash_ev_usd
                        held_draft.expected_payout_usd = ev_res.expected_payout_usd
                        held_draft.p_valid = ev_res.p_valid
                        held_draft.p_duplicate = ev_res.p_duplicate
                        held_draft.stride_category = str((ev_dict.get("stride_verdict") or {}).get("stride_category") or "")
                        held_draft.stride_boundary_verdict = verdict
                        held_draft.required_runtime = str((ev_dict.get("runtime_poc") or {}).get("required_runtime") or "")
                        held_draft.poc_verified_runtime = bool((ev_dict.get("runtime_poc") or {}).get("poc_verified_runtime"))
                        held_draft.recommended_route = ev_res.recommended_route
                        self.ticket_store.upsert_draft(
                            held_draft,
                            state=ev_res.target_ticket_state,
                            program_name=campaign.name,
                            offers_bounties=campaign.offers_bounties,
                            reason=reason_tag,
                            target_boundary=str((ev_dict.get("stride_verdict") or {}).get("target_boundary") or ""),
                            duplicate_check_status=dup_st,
                        )
                    continue
                cash_filtered.append((f_item, ev_dict))
            # Rank remaining drafts strictly by Cash EV descending
            cash_filtered.sort(
                key=lambda pair: (
                    0 if bool(((pair[1] or {}).get("runtime_poc") or {}).get("poc_verified_runtime")) else 1,
                    -float((pair[1] or {}).get("cash_ev_usd") or 0.0),
                )
            )
        else:
            cash_filtered = [(f_item, None) for f_item in eligible]

        if not dry_run:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        bundle_path = self.output_dir / f"hackerone_port_bundle_{campaign.handle}.json"
        drafts: List[HackerOneReportDraft] = []
        for f_item, ev_dict in cash_filtered:
            draft = build_hackerone_report_draft(
                f_item,
                campaign,
                include_ai_disclosure=include_ai_disclosure,
                cool_off_mode=eff_cool_off,
            )
            ticket_state = "held_cool_off" if eff_cool_off else "draft_local"
            target_boundary = ""
            dup_status = ""
            poc_cmd = ""
            if ev_dict:
                sv = ev_dict.get("stride_verdict") or {}
                rp = ev_dict.get("runtime_poc") or {}
                dr = ev_dict.get("duplicate_risk") or {}
                draft.cash_ev_usd = float(ev_dict.get("cash_ev_usd") or 0.0)
                draft.expected_payout_usd = float(ev_dict.get("expected_payout_usd") or 0.0)
                draft.p_valid = float(ev_dict.get("p_valid") or 0.0)
                draft.p_duplicate = float(ev_dict.get("p_duplicate") or 0.0)
                draft.stride_category = str(sv.get("stride_category") or "")
                draft.stride_boundary_verdict = str(sv.get("verdict") or "")
                draft.required_runtime = str(rp.get("required_runtime") or "")
                draft.poc_verified_runtime = bool(rp.get("poc_verified_runtime"))
                draft.recommended_route = str(ev_dict.get("recommended_route") or "")
                target_boundary = str(sv.get("target_boundary") or "")
                dup_status = str(dr.get("status") or "")
                poc_cmd = str(rp.get("recommended_command") or "")
                if not draft.poc_verified_runtime:
                    ticket_state = "needs_live_poc"
                elif eff_cool_off:
                    ticket_state = "held_cool_off"
                else:
                    ticket_state = "ready_to_submit"

            safe_rule = re.sub(r"[^A-Za-z0-9_.-]+", "_", draft.source_rule_id)[:48]
            md_file = self.output_dir / f"{campaign.handle}_{safe_rule}_{draft.fingerprint[:8]}.md"
            if not dry_run:
                cool_off_banner = (
                    "> **[DRAFT ONLY — COOL-OFF ACTIVE]**: Do NOT submit during your HackerOne cool-off period. "
                    "Saved locally for review / safe on-site Draft staging only.\n\n"
                    if eff_cool_off
                    else ""
                )
                cash_meta_lines = (
                    f"- **Cash EV / Expected Payout**: `${draft.cash_ev_usd:.2f}` (gross `${draft.expected_payout_usd:.2f}`, "
                    f"`p_valid={draft.p_valid:.2f}`, `p_dup={draft.p_duplicate:.2f}`, route=`{draft.recommended_route}`)\n"
                    f"- **Precision STRIDE**: `{draft.stride_category}` — `{draft.stride_boundary_verdict}` (`{target_boundary}`)\n"
                    f"- **Runtime PoE**: `verified={draft.poc_verified_runtime}` (`runtime={draft.required_runtime}`, cmd=`{poc_cmd}`)\n"
                    if ev_dict
                    else ""
                )
                md_doc = (
                    f"# {draft.title}\n\n"
                    f"{cool_off_banner}"
                    f"- **HackerOne Program**: `{draft.program_handle}` ({draft.submit_url})\n"
                    f"- **Severity**: `{draft.severity_rating.upper()}`\n"
                    f"- **Weakness**: `{draft.weakness_cwe}`\n"
                    f"- **Epistemic Status**: `{draft.epistemic_status}`\n"
                    f"{cash_meta_lines}"
                    f"- **Asset**: `{draft.asset_identifier}` (`scope={draft.scope_match_status}`)\n"
                    f"- **RFCHunt Evidence Lane**: `{draft.evidence_lane}` (`poe_level={draft.poe_level}`)\n\n"
                    f"{draft.vulnerability_information}\n\n"
                    f"## Security Impact\n{draft.impact}\n"
                )
                md_file.write_text(md_doc, encoding="utf-8")
                draft.markdown_path = str(md_file)
                self.ticket_store.upsert_draft(
                    draft,
                    state=ticket_state,
                    bundle_path=str(bundle_path),
                    program_name=campaign.name,
                    offers_bounties=campaign.offers_bounties,
                    reason="saved_locally_under_cool_off" if eff_cool_off else f"saved_locally_{ticket_state}",
                    target_boundary=target_boundary,
                    duplicate_check_status=dup_status,
                )
            else:
                draft.markdown_path = f"[dry-run] {md_file}"
            drafts.append(draft)

        browser_result: Optional[Dict[str, Any]] = None
        if use_browser or save_draft_on_site:
            browser_result = self.browser_porter.run_hitl_browser_session(
                campaign,
                drafts,
                search_query=query,
                cool_off_mode=eff_cool_off,
                save_draft_on_site=bool(save_draft_on_site),
                dry_run=dry_run,
                wait_for_human_fn=wait_for_human_fn,
            )
            if not dry_run and isinstance(browser_result, dict):
                for fd in browser_result.get("filled_drafts") or []:
                    d_id = str(fd.get("draft_id") or "")
                    if not d_id:
                        continue
                    if fd.get("site_draft_saved"):
                        self.ticket_store.transition_state(
                            d_id,
                            "draft_saved_on_site",
                            reason="saved_on_hackerone_via_save_draft_button_never_submitted",
                            site_draft_saved=True,
                        )
                    elif fd.get("site_draft_status") == "blocked_by_site_cool_off_banner_local_draft_preserved":
                        self.ticket_store.transition_state(
                            d_id,
                            "held_cool_off",
                            reason="site_cool_off_banner_blocked_form_local_draft_preserved",
                            site_draft_saved=False,
                        )

        api_submissions: List[Dict[str, Any]] = []
        if submit_api:
            for d in drafts:
                resp = self.api_client.submit_report_api(
                    d,
                    hitl_approved=hitl_approved,
                    cool_off_mode=eff_cool_off,
                    draft_only=eff_cool_off,
                    dry_run=dry_run,
                )
                if dry_run:
                    api_submissions.append(resp)
                else:
                    remote_id = str((resp.get("data") or {}).get("id") or "")
                    self._save_ledger_record(d, delivery_mode="hackerone_api_v1", remote_id=remote_id)
                    self.ticket_store.transition_state(
                        d.draft_id,
                        "submitted",
                        reason="submitted_via_hitl_hackerone_api_v1",
                        remote_report_id=remote_id,
                    )
                    api_submissions.append({"draft_id": d.draft_id, "remote_id": remote_id, "status": "submitted"})

        site_saved_count = int((browser_result or {}).get("site_drafts_saved", 0) or 0)
        result = {
            "status": "dry_run_completed" if dry_run else "completed",
            "dry_run": bool(dry_run),
            "cool_off_mode": eff_cool_off,
            "draft_only_enforced": eff_cool_off,
            "save_draft_on_site": bool(save_draft_on_site),
            "cash_tune_enforced": bool(cash_tune),
            "anti_slop_gate_enforced": True,
            "epistemic_gate_enforced": bool(strict_epistemic),
            "signal_filter_enforced": bool(enforce_signal_filter),
            "final_submit_requires_hitl": True,
            "campaign": campaign.to_dict(),
            "policy_rules": campaign.policy_rules,
            "matching_campaigns": [c.to_dict() for c in matches],
            "eligible_drafts_count": len(drafts),
            "local_drafts_saved": 0 if dry_run else len(drafts),
            "site_drafts_saved": site_saved_count,
            "rejected_findings_count": len(rejected),
            "cash_held_count": len(cash_held),
            "drafts": [d.to_dict() for d in drafts],
            "rejected": rejected,
            "browser_session": browser_result,
            "api_submissions": api_submissions,
            "ticket_db_path": f"[dry-run] {self.ticket_store.db_path}" if dry_run else str(self.ticket_store.db_path),
            "ticket_state_summary": self.ticket_store.get_state_summary(),
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
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
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
        enable_ensemble: bool = True,
        min_severity: str = "medium",
        max_reports: int = 5,
        include_ai_disclosure: bool = False,
        cool_off_mode: bool = False,
        save_draft_on_site: bool = False,
        strict_epistemic: bool = True,
        enforce_signal_filter: bool = True,
        dry_run: bool = False,
        wait_for_human_fn: Optional[Callable[[str], str]] = None,
    ) -> Dict[str, Any]:
        """Executes the full policy-aware autonomous HackerOne workflow (or safe `--dry-run` plan)."""
        eff_cool_off = bool(cool_off_mode or is_cool_off_env_enabled())
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
                        enable_ensemble=enable_ensemble,
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
                                enable_ensemble=enable_ensemble,
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

            stride_model_res: Optional[Dict[str, Any]] = None
            if local_repo_path and Path(local_repo_path).exists() and not dry_run:
                try:
                    from engine.stride_engine import DynamicStrideThreatEngine

                    stride_model_res = DynamicStrideThreatEngine.analyze_repository(
                        str(Path(local_repo_path).resolve()),
                        findings=audit_findings,
                        policy_text=camp.policy_text,
                        reports_dir=self.output_dir / f"stride_{camp.handle}",
                    )
                except Exception:
                    stride_model_res = None

            port_res = self.porter.port_findings(
                audit_findings,
                program_handle=camp.handle,
                query=query,
                min_severity=min_severity,
                max_reports=max_reports,
                use_api=False,
                use_browser=(use_browser or save_draft_on_site) and (bool(audit_findings) or dry_run),
                submit_api=False,
                researcher_username=eff_user,
                include_ai_disclosure=bool(include_ai_disclosure or rules.ai_disclosure_required),
                policy_text_override=camp.policy_text,
                cool_off_mode=eff_cool_off,
                draft_only=eff_cool_off,
                save_draft_on_site=bool(save_draft_on_site) and (bool(audit_findings) or dry_run),
                strict_epistemic=strict_epistemic,
                enforce_signal_filter=enforce_signal_filter,
                cash_tune=True,
                stride_model=stride_model_res,
                dry_run=dry_run,
                wait_for_human_fn=wait_for_human_fn,
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
                        "excluded_vuln_classes": rules.excluded_vuln_classes,
                        "cool_off_enforced": eff_cool_off,
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
            "cool_off_mode": eff_cool_off,
            "save_draft_on_site": bool(save_draft_on_site),
            "safe_harbor_roe_enforced": True,
            "epistemic_gate_enforced": bool(strict_epistemic),
            "signal_filter_enforced": bool(enforce_signal_filter),
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
