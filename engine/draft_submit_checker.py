"""
HackerOne Draft Submit-Readiness & Cooldown-Clear Checker (`draft_submit_checker.py`).
======================================================================================
Monitors saved HackerOne Drafts (`Editing (Draft)`) whose submission button is
temporarily gated by HackerOne's rolling account cooldown (`"can_submit_draft?": false`,
causing the UI dropdown to default to `Delete draft` / red `Delete`), and alerts the
researcher with prioritized clickable `https://hackerone.com/reports/<id>` URLs the
moment `"can_submit_draft?"` clears back to `true`.

Key Design Properties:
- Probe-first politeness: checks ONE anchor draft (`4243972` by default) via
  `https://hackerone.com/reports/<id>.json` before fanning out, avoiding unnecessary
  traffic while account-wide cooldown is active.
- Semaphore-bounded async checks (`asyncio.Semaphore` + strict rate limiter <= 2 RPS)
  using `httpx.AsyncClient` (with stdlib `urllib.request` fallback).
- Supports BOTH direct authenticated HTTP checks (`HACKERONE_SESSION_COOKIE` env or
  cookie file) AND browser-exported JSON snapshot ingestion (`ingest_snapshots`).
- Enforces safe daily submission pacing (`max_per_day`, default 2) in SQLite WAL so
  clearing cooldown does not immediately re-trigger HackerOne rate limits.
- Strictly read-only on HackerOne: NEVER clicks Submit, NEVER clicks Delete, NEVER
  bypasses CAPTCHAs or access controls.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request

try:
    import httpx
except Exception:  # pragma: no cover - optional runtime dependency fallback
    httpx = None  # type: ignore[assignment]


DEFAULT_TRACKER_DB = Path("reports/ensemble_hunt/draft_submit_tracker.sqlite3")
DEFAULT_READY_MD = Path("reports/ensemble_hunt/drafts_ready_to_submit.md")
DEFAULT_PROBE_REPORT_ID = 4243972
DEFAULT_HACKERONE_BASE_URL = "https://hackerone.com"

_SEVERITY_SCORE = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "none": 0,
}

_TIER_SCORE = {
    "PAID_CASH": 25,
    "FAST_SIGNAL_VDP": 22,
    "VDP": 12,
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@dataclass
class TrackedDraft:
    report_id: int
    program: str
    payout_tier: str
    severity: str
    title: str
    url: str = ""
    state: str = "Draft"
    substate: str = "editing"
    can_submit_draft: Optional[bool] = None
    can_delete_draft: Optional[bool] = None
    can_add_comment: Optional[bool] = None
    priority_rank: int = 100
    last_checked_utc: str = ""
    status_cleared_at_utc: str = ""
    submitted_at_utc: str = ""
    qa_status: str = "UNCHECKED"
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.url:
            self.url = f"{DEFAULT_HACKERONE_BASE_URL}/reports/{self.report_id}"


@dataclass
class ProbeOutcome:
    report_id: int
    url: str
    http_status: int
    readiness: str  # READY_TO_SUBMIT | COOLDOWN_LOCKED | ALREADY_SUBMITTED | AUTH_REQUIRED | NOT_FOUND | RATE_LIMITED | ERROR
    state: str = ""
    substate: str = ""
    can_submit_draft: Optional[bool] = None
    can_delete_draft: Optional[bool] = None
    can_add_comment: Optional[bool] = None
    program: str = ""
    title: str = ""
    error: str = ""
    checked_at_utc: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DraftCheckSummary:
    checked_at_utc: str
    account_status: str  # CLEARED | COOLDOWN_ACTIVE | AUTH_REQUIRED | RATE_LIMITED | UNKNOWN
    probe_report_id: int
    probe_outcome: Dict[str, Any]
    total_tracked_drafts: int
    ready_to_submit_count: int
    cooldown_locked_count: int
    already_submitted_count: int
    daily_limit: int
    submitted_today: int
    remaining_today: int
    recommended_next_batch: List[Dict[str, Any]]
    all_outcomes: List[Dict[str, Any]]
    newly_cleared_ids: List[int] = field(default_factory=list)
    ready_markdown_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Verified HackerOne queue captured from live sessions (Drafts + recently submitted Open reports)
SEEDED_DRAFTS: Tuple[Tuple[int, str, str, str, int, str, str], ...] = (
    # (report_id, program, payout_tier, severity, priority_rank, initial_state, title)
    # --- Priority Paid Cash: Anthropic ($100-$10,000) ---
    (4243972, "anthropic", "PAID_CASH", "High", 1, "Draft", "anthropic-sdk-python: _require_https() prefix bypass, redirect-following /v1/oauth/token POST, & missing sameOrigin"),
    (4243977, "anthropic", "PAID_CASH", "High", 2, "Draft", "claude-agent-sdk-python: Incomplete CVE-2026-96620 fix leaving 16 variadic/string CLI options in 2-token form"),
    (4244063, "anthropic", "PAID_CASH", "High", 3, "Draft", "anthropic-sdk-go & anthropic-sdk-java: Unvalidated Foundry/Vertex host interpolation & cross-origin X-Api-Key/Bearer leak"),
    (4243988, "anthropic", "PAID_CASH", "Medium", 12, "Draft", "anthropic-sdk-typescript: Cross-host OAuth/WIF Bearer token leakage via withOptions({ baseURL }) shared TokenCache"),
    (4244036, "anthropic", "PAID_CASH", "Medium", 13, "Draft", "anthropic-sdk-go: Multipart MIME header & part injection via unescaped CR/LF in filename/Content-Type"),
    (4244472, "anthropic", "PAID_CASH", "Medium", 14, "Draft", "anthropics/skills (run_eval.py): Path traversal write/delete via SKILL.md frontmatter & CLI flag injection"),
    (4244562, "anthropic", "PAID_CASH", "Medium", 15, "Draft", "anthropics/claude-quickstarts (autonomous-coding/security.py): Multiple Bash allowlist hook bypasses"),
    (4243651, "anthropic", "PAID_CASH", "Medium", 18, "Draft", "anthropics/skills (soffice.py/accept_changes.py/recalc.py): _without_outside_links() ZIP preamble/format bypasses"),
    (4243922, "anthropic", "PAID_CASH", "Medium", 19, "Draft", "anthropics/claude-quickstarts (computer-use-demo): Unquoted shell interpolation in computer.py & edit.py"),
    # --- Priority Paid Cash: OPPO ColorOS Android 15/16 Kernel ($1-$3,200+, 94% eff, Gold Standard) ---
    (4244055, "oppo_bbp", "PAID_CASH", "High", 4, "Draft", "Oplus io_metrics (procfs.c): 0666 /proc nodes -> BSS overrun (strncpy+strcat) & arbitrary filp_open write (A15 & A16)"),
    (4244468, "oppo_bbp", "PAID_CASH", "High", 5, "Draft", "Oplus Touchscreen IOCTL (tp_ioctl.c): Missing MSG_BUFF_SIZE=256 bound in ioc_int & uint8_t underflow (A15/A16/SM8850)"),
    (4244573, "oppo_bbp", "PAID_CASH", "High", 6, "Draft", "Oplus game_opt (rt_info.c/cpufreq_limits.c/debug.c): snprintf stack buffer overflow, NULL+1 deref & 0666 node (A15 & A16)"),
    (4243993, "oppo_bbp", "PAID_CASH", "High", 7, "Draft", "Oplus Theia (theia_kevent_kernel.c & powerkey_monitor.c): Unprivileged Netlink integer underflow & 0777 panic nodes"),
    (4243961, "oppo_bbp", "PAID_CASH", "High", 8, "Draft", "Oplus DNS Hook (oplus_dns_hook.c): Unprivileged kernel DNS poisoning & ARM64 ntohs(nla_len) slab OOB read (A15/A16/SM8850)"),
    (4243951, "oppo_bbp", "PAID_CASH", "High", 9, "Draft", "Oplus HANS (hans.c): Commented-out uid!=1000 check & missing GENL_ADMIN_PERM unprivileged Netfilter PKG control"),
    (4243981, "oppo_bbp", "PAID_CASH", "High", 10, "Draft", "Oplus comm_netlink.c: Uninitialized kmalloc heap disclosure, del_notify_client UAF & protobuf OOB read"),
    (4243926, "oppo_bbp", "PAID_CASH", "High", 16, "Draft", "Oplus oplus_kevent_upload.c: Unprivileged Netlink kevent_pid hijack, NLA_NUL_STRING slab OOB read & NULL deref"),
    (4243946, "oppo_bbp", "PAID_CASH", "High", 17, "Draft", "Oplus frk_netlink.c: Unprivileged Generic Netlink skb_get(skb) memory leak DoS & client_pid hijack"),
    (4244004, "oppo_bbp", "PAID_CASH", "High", 20, "Draft", "Oplus touchpanel_proc.c: 0666 snr raw __user deref & 0666 oplus_apk unbounded kzalloc(count)"),
    (4244009, "oppo_bbp", "PAID_CASH", "High", 21, "Draft", "Oplus oplus_game_first.c: Unprivileged Generic Netlink (.flags=0) & missing nla_len slab OOB read"),
    (4244060, "oppo_bbp", "PAID_CASH", "High", 22, "Draft", "Oplus LinkPower (linkpower_netlink.c): Unprivileged Netlink (.flags=0), unchecked nlattr OOB read & PID override"),
    (4244158, "oppo_bbp", "PAID_CASH", "High", 23, "Draft", "Oplus Wi-Fi Drivers (wificapcenter, routerboost, sla): Unprivileged Netlink (.flags=0), unchecked nlattr OOB & PID override"),
    (4244456, "oppo_bbp", "PAID_CASH", "High", 24, "Draft", "Oplus device_info (cs_press_f71.c, pogo_keyboard_core.c, oplus_tri_key.c): 0666 raw I2C, MCU FW flash & OOB"),
    (4244198, "oppo_bbp", "PAID_CASH", "Medium", 35, "Draft", "Oplus Scheduler Assist (sa_sysfs.c): 0666 disable_setting bypasses SYSTEM_UID/ROOT_UID check on ux_task"),
    (4244577, "oppo_bbp", "PAID_CASH", "Medium", 36, "Draft", "Oplus uxmem_opt (uxmem_opt.c): 0666 /proc/oplus_mem/ux_page_pool unbounded watermark OOM DoS"),
    # --- Priority Paid Cash: Common Codes ($1,500-$15,000+, 89% eff, low competition) ---
    (4243873, "common_codes", "PAID_CASH", "High", 11, "Draft", "d-you Wallet iOS: Unconditional .dev playground LoTE fallback + defaultPolicy .warning + sdjwt-swift@0.14.7"),
    (4243822, "common_codes", "PAID_CASH", "High", 25, "Draft", "d-you Wallet Android: Pinned eudi-lib-android-wallet-core@0.31.1 missing all 5 v0.32.0 security fixes"),
    (4243555, "common_codes", "PAID_CASH", "High", 26, "Draft", "d-you Wallet Android: Unscoped implicit broadcast leak + ContextCompat.RECEIVER_EXPORTED"),
    # --- Fast Signal Unlock: Rails (96% eff) & Ruby (93% eff) ---
    (4243900, "rails", "FAST_SIGNAL_VDP", "Medium", 27, "Draft", "ActiveSupport::SafeBuffer omits append_as_bytes/setbyte/encode!/force_encoding preserving html_safe?"),
    (4243711, "ruby", "FAST_SIGNAL_VDP", "High", 28, "Draft", "ruby/drb (lib/drb/ssl.rb): DRbSSLSocket omits TLS hostname verification & SNI under VERIFY_PEER"),
    (4243726, "ruby", "FAST_SIGNAL_VDP", "High", 29, "Draft", "ruby/rdoc: CVE-2024-27281 MarshalFilter bypass + unfiltered Marshal.load in ri --dump"),
    (4243840, "ruby", "FAST_SIGNAL_VDP", "Medium", 30, "Draft", "ruby/net-smtp: Skips post_connection_check for caller-supplied SSLContext"),
    (4243902, "ruby", "FAST_SIGNAL_VDP", "Medium", 31, "Draft", "ruby/open-uri: Leaks String-keyed Authorization/Cookie/Proxy-Authorization across cross-origin redirects"),
    (4243905, "ruby", "FAST_SIGNAL_VDP", "Medium", 32, "Draft", "ruby/resolv: MessageEncoder#put_length16 unchecked mod-65536 RDLENGTH truncation"),
    (4244460, "ruby", "FAST_SIGNAL_VDP", "Medium", 33, "Draft", "ruby/webrick (HTTPProxyServer): RFC 9110 s7.6.1 hop-by-hop bypass (split(/,\\s+/)) & upstream CONNECT injection"),
    # --- Unlocked VDPs: ServiceNow (82% eff) & IBM ---
    (4244478, "servicenow-disclosure", "VDP", "High", 34, "Draft", "ServiceNow/TapeAgents (remote_environment.py): Unsafe pickle.loads IPC over /tmp sockets & unauth EnvironmentServer"),
    (4243653, "servicenow-disclosure", "VDP", "Medium", 37, "Draft", "ServiceNow/PySNC (pysnc/attachment.py): Path traversal & arbitrary file write via unsanitized file_name"),
    (4243929, "servicenow-disclosure", "VDP", "Medium", 38, "Draft", "ServiceNow/sbom-upload (src/setup.ts): Plaintext core.info(JSON.stringify(actionArguments)) credential logging"),
    (4244016, "servicenow-disclosure", "VDP", "Medium", 39, "Draft", "ServiceNow/AgentLab (Agent X-Ray): Stored XSS via unescaped episode metadata inside unsandboxed iframe srcdoc"),
    (4244462, "servicenow-disclosure", "VDP", "Medium", 40, "Draft", "ServiceNow/servicenow-devops-* (8 repos): Unmasked Base64 Basic Auth & token headers logged via core.debug"),
    (4244491, "servicenow-disclosure", "VDP", "Medium", 41, "Draft", "ServiceNow/TapeAgents (TapeBrowser & Studio): Stored XSS via unescaped tape/LLM output in Gradio gr.HTML"),
    (4244566, "servicenow-disclosure", "VDP", "Medium", 42, "Draft", "ServiceNow/TapeAgents (simple_browser.py): Unrestricted file:// local file read & missing outbound URL validation"),
    (4244041, "ibm", "VDP", "High", 43, "Draft", "IBM/ibm-secretshare-operator: Cross-namespace arbitrary Secret/ConfigMap overwrite & namespace creation"),
    (4244204, "ibm", "VDP", "High", 44, "Draft", "IBM/ibm-namespace-scope-operator: Cross-namespace Role/RoleBinding projection without SubjectAccessReview"),
    (4243913, "ibm", "VDP", "Medium", 45, "Draft", "IBM/go-sdk-core: Unescaped multipart Content-Disposition/Content-Type header injection"),
    (4243918, "ibm", "VDP", "Medium", 46, "Draft", "IBM/mcp-context-forge: Unauthenticated RFC 9728 OAuth metadata poisoning via untrusted Host/X-Forwarded-Proto"),
    (4244483, "ibm", "VDP", "Medium", 47, "Draft", "IBM-Cloud/ibm-cloud-cli-sdk & bluemix-go: Trace sanitizer bypasses & 0644 world-readable logs"),
    (4244487, "ibm", "VDP", "Medium", 48, "Draft", "IBM/storage-protect-python-sdk: Untrusted CWD native DLL/SO search path in load.py"),
    (4244506, "ibm", "VDP", "Medium", 49, "Draft", "IBM/ibm-licensing-operator: Any tenant namespace can exclude arbitrary cluster namespaces from license metering"),
    # --- Already Submitted Open Reports (Tracked for Triage / Signal-Lift Detection) ---
    (4244509, "anthropic", "PAID_CASH", "High", 901, "Open", "claude-code-action: PR-controlled .gitattributes working-tree-encoding disables base-restored .claude/settings.json"),
    (4244523, "anthropic", "PAID_CASH", "High", 902, "Open", "claude-code-action: Plaintext GitHub token written to .git/config on default untrusted PR workflows"),
    (4244529, "anthropic", "PAID_CASH", "High", 903, "Open", "claude-code-action: Maintainer PR triage/moderation triggers unauthorized runs on external @claude body/title"),
    (4243825, "rails", "FAST_SIGNAL_VDP", "Medium", 904, "Open", "Rails strong_parameters.rb: select/reject/keep_if/delete_if yield unwrapped HashWithIndifferentAccess"),
    (4243990, "rails", "FAST_SIGNAL_VDP", "Medium", 905, "Open", "Rails ActionController::Live::SSE#perform_write bare CR & unsanitized option frame injection"),
    (4244042, "rails", "FAST_SIGNAL_VDP", "Medium", 906, "Open", "Rails HttpAuthentication::Digest missing RFC 7616 credentials[:uri] binding & timing-unsafe =="),
    (4244496, "rails", "FAST_SIGNAL_VDP", "Medium", 907, "Open", "Rails ActiveJob::Serializers.deserialize calls safe_constantize.deserialize without @serializers allowlist"),
)


def parse_hackerone_report_json(
    report_id: int,
    payload: Dict[str, Any],
    http_status: int = 200,
    base_url: str = DEFAULT_HACKERONE_BASE_URL,
) -> ProbeOutcome:
    """Parse a real `https://hackerone.com/reports/<id>.json` payload into a ProbeOutcome."""
    url = f"{base_url.rstrip('/')}/reports/{report_id}"
    if http_status in (401, 403):
        return ProbeOutcome(
            report_id=report_id,
            url=url,
            http_status=http_status,
            readiness="AUTH_REQUIRED",
            error="HackerOne authentication cookie/session required or expired.",
        )
    if http_status == 404:
        return ProbeOutcome(
            report_id=report_id,
            url=url,
            http_status=http_status,
            readiness="NOT_FOUND",
            error="Report not found or inaccessible.",
        )
    if http_status == 429:
        return ProbeOutcome(
            report_id=report_id,
            url=url,
            http_status=http_status,
            readiness="RATE_LIMITED",
            error="HTTP 429 rate limited by HackerOne; back off before retrying.",
        )
    if http_status != 200 or not isinstance(payload, dict):
        return ProbeOutcome(
            report_id=report_id,
            url=url,
            http_status=http_status,
            readiness="ERROR",
            error=f"Unexpected HTTP {http_status} or non-JSON response.",
        )

    state = str(payload.get("state") or "").strip()
    substate = str(payload.get("substate") or "").strip()
    abilities = payload.get("abilities")
    if not isinstance(abilities, dict):
        abilities = {}

    can_submit = abilities.get("can_submit_draft?")
    can_delete = abilities.get("can_delete_draft?")
    can_comment = abilities.get("can_add_comment?")

    can_submit_bool: Optional[bool] = bool(can_submit) if isinstance(can_submit, bool) else None
    can_delete_bool: Optional[bool] = bool(can_delete) if isinstance(can_delete, bool) else None
    can_comment_bool: Optional[bool] = bool(can_comment) if isinstance(can_comment, bool) else None

    team = payload.get("team") if isinstance(payload.get("team"), dict) else {}
    program = str(team.get("handle") or payload.get("program") or "").strip()
    title = str(payload.get("title") or "").strip()

    is_draft = state.lower() == "draft" or substate.lower() == "editing"
    if not is_draft and state:
        readiness = "ALREADY_SUBMITTED"
    elif is_draft and can_submit_bool is True:
        readiness = "READY_TO_SUBMIT"
    elif is_draft and can_submit_bool is False:
        readiness = "COOLDOWN_LOCKED"
    else:
        readiness = "AUTH_REQUIRED" if not state and not abilities else "ERROR"

    return ProbeOutcome(
        report_id=report_id,
        url=url,
        http_status=http_status,
        readiness=readiness,
        state=state or ("Draft" if is_draft else ""),
        substate=substate,
        can_submit_draft=can_submit_bool,
        can_delete_draft=can_delete_bool,
        can_add_comment=can_comment_bool,
        program=program,
        title=title,
    )


class DraftSubmitTrackerDB:
    """SQLite WAL persistence for tracked HackerOne Drafts, cooldown transitions, and daily pacing."""

    def __init__(self, db_path: str | Path = DEFAULT_TRACKER_DB) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tracked_drafts (
                    report_id INTEGER PRIMARY KEY,
                    url TEXT NOT NULL,
                    program TEXT NOT NULL,
                    payout_tier TEXT NOT NULL DEFAULT 'PAID_CASH',
                    severity TEXT NOT NULL DEFAULT 'Medium',
                    title TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT 'Draft',
                    substate TEXT NOT NULL DEFAULT 'editing',
                    can_submit_draft INTEGER,
                    can_delete_draft INTEGER,
                    can_add_comment INTEGER,
                    priority_rank INTEGER NOT NULL DEFAULT 100,
                    last_checked_utc TEXT NOT NULL DEFAULT '',
                    status_cleared_at_utc TEXT NOT NULL DEFAULT '',
                    submitted_at_utc TEXT NOT NULL DEFAULT '',
                    qa_status TEXT NOT NULL DEFAULT 'UNCHECKED',
                    notes TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS check_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    checked_at_utc TEXT NOT NULL,
                    probe_report_id INTEGER NOT NULL,
                    account_status TEXT NOT NULL,
                    ready_count INTEGER NOT NULL DEFAULT 0,
                    locked_count INTEGER NOT NULL DEFAULT 0,
                    http_status INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL DEFAULT 'http'
                );

                CREATE TABLE IF NOT EXISTS daily_pacing (
                    day_utc TEXT PRIMARY KEY,
                    submitted_count INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(tracked_drafts)").fetchall()}
            if "qa_status" not in cols:
                conn.execute("ALTER TABLE tracked_drafts ADD COLUMN qa_status TEXT NOT NULL DEFAULT 'UNCHECKED'")

    def seed_default_queue(self, overwrite_metadata: bool = False) -> int:
        """Seed all known live HackerOne Drafts & Open reports idempotently."""
        inserted = 0
        with self._connect() as conn:
            for report_id, program, tier, severity, rank, state, title in SEEDED_DRAFTS:
                url = f"{DEFAULT_HACKERONE_BASE_URL}/reports/{report_id}"
                substate = "editing" if state == "Draft" else "new"
                if overwrite_metadata:
                    conn.execute(
                        """
                        INSERT INTO tracked_drafts (
                            report_id, url, program, payout_tier, severity, title, state, substate, priority_rank
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(report_id) DO UPDATE SET
                            program=excluded.program,
                            payout_tier=excluded.payout_tier,
                            severity=excluded.severity,
                            title=excluded.title,
                            priority_rank=excluded.priority_rank
                        """,
                        (report_id, url, program, tier, severity, title, state, substate, rank),
                    )
                    inserted += 1
                else:
                    cur = conn.execute(
                        """
                        INSERT OR IGNORE INTO tracked_drafts (
                            report_id, url, program, payout_tier, severity, title, state, substate, priority_rank
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (report_id, url, program, tier, severity, title, state, substate, rank),
                    )
                    inserted += int(cur.rowcount or 0)
        return inserted

    def upsert_draft(self, draft: TrackedDraft) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tracked_drafts (
                    report_id, url, program, payout_tier, severity, title,
                    state, substate, can_submit_draft, can_delete_draft, can_add_comment,
                    priority_rank, last_checked_utc, status_cleared_at_utc, submitted_at_utc, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(report_id) DO UPDATE SET
                    url=excluded.url,
                    program=CASE WHEN excluded.program != '' THEN excluded.program ELSE tracked_drafts.program END,
                    payout_tier=excluded.payout_tier,
                    severity=excluded.severity,
                    title=CASE WHEN excluded.title != '' THEN excluded.title ELSE tracked_drafts.title END,
                    state=excluded.state,
                    substate=excluded.substate,
                    can_submit_draft=excluded.can_submit_draft,
                    can_delete_draft=excluded.can_delete_draft,
                    can_add_comment=excluded.can_add_comment,
                    priority_rank=excluded.priority_rank,
                    last_checked_utc=excluded.last_checked_utc,
                    status_cleared_at_utc=CASE
                        WHEN excluded.status_cleared_at_utc != '' THEN excluded.status_cleared_at_utc
                        ELSE tracked_drafts.status_cleared_at_utc
                    END,
                    submitted_at_utc=CASE
                        WHEN excluded.submitted_at_utc != '' THEN excluded.submitted_at_utc
                        ELSE tracked_drafts.submitted_at_utc
                    END,
                    notes=CASE WHEN excluded.notes != '' THEN excluded.notes ELSE tracked_drafts.notes END
                """,
                (
                    draft.report_id,
                    draft.url,
                    draft.program,
                    draft.payout_tier,
                    draft.severity,
                    draft.title,
                    draft.state,
                    draft.substate,
                    None if draft.can_submit_draft is None else int(draft.can_submit_draft),
                    None if draft.can_delete_draft is None else int(draft.can_delete_draft),
                    None if draft.can_add_comment is None else int(draft.can_add_comment),
                    draft.priority_rank,
                    draft.last_checked_utc,
                    draft.status_cleared_at_utc,
                    draft.submitted_at_utc,
                    draft.notes,
                ),
            )

    def apply_probe_outcome(self, outcome: ProbeOutcome) -> bool:
        """Persist probe outcome; returns True if the draft transitioned to READY_TO_SUBMIT."""
        newly_cleared = False
        now = outcome.checked_at_utc or _utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM tracked_drafts WHERE report_id = ?",
                (outcome.report_id,),
            ).fetchone()
            prev_can_submit = None if row is None else row["can_submit_draft"]
            if outcome.readiness == "READY_TO_SUBMIT" and prev_can_submit in (None, 0):
                newly_cleared = True

            cleared_ts = (
                now
                if newly_cleared
                else ("" if row is None else str(row["status_cleared_at_utc"] or ""))
            )
            if outcome.readiness == "COOLDOWN_LOCKED":
                cleared_ts = ""

            if row is None:
                conn.execute(
                    """
                    INSERT INTO tracked_drafts (
                        report_id, url, program, payout_tier, severity, title,
                        state, substate, can_submit_draft, can_delete_draft, can_add_comment,
                        priority_rank, last_checked_utc, status_cleared_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        outcome.report_id,
                        outcome.url,
                        outcome.program or "unknown",
                        "PAID_CASH",
                        "Medium",
                        outcome.title,
                        outcome.state or "Draft",
                        outcome.substate or "editing",
                        None if outcome.can_submit_draft is None else int(outcome.can_submit_draft),
                        None if outcome.can_delete_draft is None else int(outcome.can_delete_draft),
                        None if outcome.can_add_comment is None else int(outcome.can_add_comment),
                        100,
                        now,
                        cleared_ts,
                    ),
                )
            else:
                new_state = outcome.state or str(row["state"])
                new_substate = outcome.substate or str(row["substate"])
                new_program = outcome.program or str(row["program"])
                new_title = outcome.title or str(row["title"])
                submitted_at = str(row["submitted_at_utc"] or "")
                if outcome.readiness == "ALREADY_SUBMITTED" and not submitted_at:
                    submitted_at = now
                conn.execute(
                    """
                    UPDATE tracked_drafts
                    SET program = ?,
                        title = ?,
                        state = ?,
                        substate = ?,
                        can_submit_draft = ?,
                        can_delete_draft = ?,
                        can_add_comment = ?,
                        last_checked_utc = ?,
                        status_cleared_at_utc = ?,
                        submitted_at_utc = ?
                    WHERE report_id = ?
                    """,
                    (
                        new_program,
                        new_title,
                        new_state,
                        new_substate,
                        None if outcome.can_submit_draft is None else int(outcome.can_submit_draft),
                        None if outcome.can_delete_draft is None else int(outcome.can_delete_draft),
                        None if outcome.can_add_comment is None else int(outcome.can_add_comment),
                        now,
                        cleared_ts,
                        submitted_at,
                        outcome.report_id,
                    ),
                )
        return newly_cleared

    def record_check_run(
        self,
        *,
        probe_report_id: int,
        account_status: str,
        ready_count: int,
        locked_count: int,
        http_status: int,
        source: str = "http",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO check_history (
                    checked_at_utc, probe_report_id, account_status,
                    ready_count, locked_count, http_status, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (_utc_now_iso(), probe_report_id, account_status, ready_count, locked_count, http_status, source),
            )

    def mark_submitted(self, report_id: int, day_utc: Optional[str] = None) -> None:
        now = _utc_now_iso()
        day = day_utc or _utc_today()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE tracked_drafts
                SET state = 'Open', substate = 'new', can_submit_draft = 0, submitted_at_utc = ?
                WHERE report_id = ?
                """,
                (now, report_id),
            )
            conn.execute(
                """
                INSERT INTO daily_pacing (day_utc, submitted_count) VALUES (?, 1)
                ON CONFLICT(day_utc) DO UPDATE SET submitted_count = daily_pacing.submitted_count + 1
                """,
                (day,),
            )

    def get_submitted_today(self, day_utc: Optional[str] = None) -> int:
        day = day_utc or _utc_today()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT submitted_count FROM daily_pacing WHERE day_utc = ?",
                (day,),
            ).fetchone()
            return int(row["submitted_count"]) if row else 0

    def set_qa_status(self, report_id: int, qa_status: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE tracked_drafts SET qa_status = ? WHERE report_id = ?",
                (str(qa_status or "UNCHECKED").upper(), int(report_id)),
            )

    def sync_qa_statuses(self, status_map: Dict[int, str]) -> int:
        updated = 0
        with self._connect() as conn:
            for rid, status in status_map.items():
                cur = conn.execute(
                    "UPDATE tracked_drafts SET qa_status = ? WHERE report_id = ?",
                    (str(status or "UNCHECKED").upper(), int(rid)),
                )
                updated += int(cur.rowcount or 0)
        return updated

    def list_drafts(self, only_drafts: bool = True) -> List[TrackedDraft]:
        sql = "SELECT * FROM tracked_drafts"
        if only_drafts:
            sql += " WHERE lower(state) = 'draft'"
        sql += " ORDER BY priority_rank ASC, report_id ASC"
        with self._connect() as conn:
            rows = conn.execute(sql).fetchall()
        out: List[TrackedDraft] = []
        for r in rows:
            out.append(
                TrackedDraft(
                    report_id=int(r["report_id"]),
                    url=str(r["url"]),
                    program=str(r["program"]),
                    payout_tier=str(r["payout_tier"]),
                    severity=str(r["severity"]),
                    title=str(r["title"]),
                    state=str(r["state"]),
                    substate=str(r["substate"]),
                    can_submit_draft=None if r["can_submit_draft"] is None else bool(r["can_submit_draft"]),
                    can_delete_draft=None if r["can_delete_draft"] is None else bool(r["can_delete_draft"]),
                    can_add_comment=None if r["can_add_comment"] is None else bool(r["can_add_comment"]),
                    priority_rank=int(r["priority_rank"]),
                    last_checked_utc=str(r["last_checked_utc"] or ""),
                    status_cleared_at_utc=str(r["status_cleared_at_utc"] or ""),
                    submitted_at_utc=str(r["submitted_at_utc"] or ""),
                    qa_status=str(r["qa_status"] or "UNCHECKED"),
                    notes=str(r["notes"] or ""),
                )
            )
        return out


def _priority_sort_key(d: TrackedDraft) -> Tuple[int, int, int, int]:
    """Lower tuple sorts first (highest priority first)."""
    tier_score = _TIER_SCORE.get(d.payout_tier.upper(), 10)
    sev_score = _SEVERITY_SCORE.get(d.severity.lower(), 10)
    return (d.priority_rank, -(tier_score + sev_score), -sev_score, d.report_id)


def render_ready_markdown(summary: DraftCheckSummary, drafts: Sequence[TrackedDraft]) -> str:
    """Render a clean, clickable Markdown checklist of HackerOne Draft readiness."""
    lines: List[str] = [
        "# HackerOne Draft Submit-Readiness Status",
        "",
        f"- **Checked (UTC):** `{summary.checked_at_utc}`",
        f"- **Account Submit Gate:** `{summary.account_status}` (anchor probe: `#{summary.probe_report_id}`)",
        f"- **Ready to Submit (`can_submit_draft? == true`):** `{summary.ready_to_submit_count}`",
        f"- **Cooldown Locked (`can_submit_draft? == false`):** `{summary.cooldown_locked_count}`",
        f"- **Already Submitted / Open:** `{summary.already_submitted_count}`",
        f"- **Safe Daily Pacing:** `{summary.submitted_today}/{summary.daily_limit}` used today (`{summary.remaining_today}` remaining)",
        "",
    ]
    if summary.account_status == "CLEARED" and summary.recommended_next_batch:
        lines.append("## Recommended Next Batch to Submit Now (Safe Pacing)")
        lines.append("")
        lines.append("| Priority | Program | Tier | Severity | Clickable Report URL | Title |")
        lines.append("|---:|---|---|---|---|---|")
        for idx, item in enumerate(summary.recommended_next_batch, start=1):
            url = item["url"]
            lines.append(
                f"| {idx} | `{item['program']}` | `{item['payout_tier']}` | **{item['severity']}** "
                f"| [{item['report_id']}]({url}) | {item['title']} |"
            )
        lines.append("")
    elif summary.account_status == "COOLDOWN_ACTIVE":
        lines.append("> **Cooldown Active:** HackerOne currently returns `\"can_submit_draft?\": false`. ")
        lines.append("> Do **NOT** click `Delete` on any draft — wait until `Submit draft` returns, then submit 1-2 per day.")
        lines.append("")

    lines.append("## Full Tracked Draft Queue")
    lines.append("")
    lines.append("| Rank | Report | Program | Tier | Severity | Status | QA Phase | `can_submit_draft?` |")
    lines.append("|---:|---|---|---|---|---|---|---|")
    for d in sorted(drafts, key=_priority_sort_key):
        flag = "unknown" if d.can_submit_draft is None else ("true" if d.can_submit_draft else "false")
        lines.append(
            f"| {d.priority_rank} | [#{d.report_id}]({d.url}) | `{d.program}` | `{d.payout_tier}` "
            f"| {d.severity} | `{d.state}` | `{d.qa_status}` | `{flag}` |"
        )
    lines.append("")
    return "\n".join(lines)


class _AsyncRateLimiter:
    """Simple process-local token-interval pacer enforcing <= max_rps requests/second."""

    def __init__(self, max_rps: float = 2.0) -> None:
        self._min_interval = 1.0 / max(0.1, float(max_rps))
        self._lock = asyncio.Lock()
        self._last_ts = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait_s = self._min_interval - (now - self._last_ts)
            if wait_s > 0:
                await asyncio.sleep(wait_s)
            self._last_ts = time.monotonic()


class DraftSubmitChecker:
    """
    Polite, semaphore-bounded HackerOne Draft submission-readiness checker.

    Works with:
      1. Live authenticated `https://hackerone.com/reports/<id>.json` fetches
         (using `HACKERONE_SESSION_COOKIE` env var or explicit cookie header).
      2. Browser-fetched JSON snapshots (`ingest_snapshots`) when authentication lives
         in an active browser session.
    """

    def __init__(
        self,
        db: Optional[DraftSubmitTrackerDB] = None,
        *,
        base_url: str = DEFAULT_HACKERONE_BASE_URL,
        session_cookie: Optional[str] = None,
        timeout_s: float = 12.0,
        max_concurrency: int = 4,
        max_rps: float = 2.0,
        fetcher: Optional[Callable[[int], Tuple[int, Dict[str, Any]]]] = None,
    ) -> None:
        self.db = db or DraftSubmitTrackerDB()
        self.base_url = base_url.rstrip("/")
        self.session_cookie = (
            session_cookie
            if session_cookie is not None
            else os.environ.get("HACKERONE_SESSION_COOKIE", "").strip()
        )
        self.timeout_s = float(timeout_s)
        self.max_concurrency = max(1, min(8, int(max_concurrency)))
        self.max_rps = max(0.2, min(5.0, float(max_rps)))
        self._custom_fetcher = fetcher

    def _headers(self) -> Dict[str, str]:
        hdrs = {
            "Accept": "application/json",
            "User-Agent": "RFCHunt-DraftSubmitChecker/1.0 (read-only)",
        }
        if self.session_cookie:
            hdrs["Cookie"] = self.session_cookie
        return hdrs

    def _fetch_sync_urllib(self, report_id: int) -> Tuple[int, Dict[str, Any]]:
        url = f"{self.base_url}/reports/{report_id}.json"
        req = urllib_request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib_request.urlopen(req, timeout=self.timeout_s) as resp:
                status = int(getattr(resp, "status", 200))
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = {}
                return status, data if isinstance(data, dict) else {}
        except urllib_error.HTTPError as exc:
            return int(exc.code), {}
        except Exception as exc:
            return 0, {"_error": str(exc)}

    async def _fetch_one(
        self,
        report_id: int,
        sem: asyncio.Semaphore,
        limiter: _AsyncRateLimiter,
        client: Any = None,
    ) -> ProbeOutcome:
        async with sem:
            await limiter.wait()
            if self._custom_fetcher is not None:
                status, payload = await asyncio.to_thread(self._custom_fetcher, report_id)
                return parse_hackerone_report_json(report_id, payload, status, base_url=self.base_url)

            url = f"{self.base_url}/reports/{report_id}.json"
            if client is not None:
                try:
                    resp = await client.get(url, headers=self._headers(), follow_redirects=False)
                    status = int(resp.status_code)
                    payload: Dict[str, Any] = {}
                    if status == 200:
                        try:
                            parsed = resp.json()
                            if isinstance(parsed, dict):
                                payload = parsed
                        except Exception:
                            payload = {}
                    return parse_hackerone_report_json(report_id, payload, status, base_url=self.base_url)
                except Exception as exc:
                    return ProbeOutcome(
                        report_id=report_id,
                        url=f"{self.base_url}/reports/{report_id}",
                        http_status=0,
                        readiness="ERROR",
                        error=str(exc),
                    )

            status, payload = await asyncio.to_thread(self._fetch_sync_urllib, report_id)
            if status == 0 and "_error" in payload:
                return ProbeOutcome(
                    report_id=report_id,
                    url=f"{self.base_url}/reports/{report_id}",
                    http_status=0,
                    readiness="ERROR",
                    error=str(payload["_error"]),
                )
            return parse_hackerone_report_json(report_id, payload, status, base_url=self.base_url)

    async def check_async(
        self,
        *,
        report_ids: Optional[Sequence[int]] = None,
        probe_report_id: int = DEFAULT_PROBE_REPORT_ID,
        probe_first: bool = True,
        probe_only: bool = False,
        max_per_day: int = 2,
        out_md: Optional[str | Path] = DEFAULT_READY_MD,
    ) -> DraftCheckSummary:
        drafts = self.db.list_drafts(only_drafts=True)
        if not drafts:
            self.db.seed_default_queue()
            drafts = self.db.list_drafts(only_drafts=True)

        target_ids: List[int] = (
            [int(i) for i in report_ids]
            if report_ids
            else [d.report_id for d in sorted(drafts, key=_priority_sort_key)]
        )
        anchor_id = int(probe_report_id) if probe_report_id else (target_ids[0] if target_ids else DEFAULT_PROBE_REPORT_ID)

        sem = asyncio.Semaphore(self.max_concurrency)
        limiter = _AsyncRateLimiter(max_rps=self.max_rps)
        outcomes: List[ProbeOutcome] = []
        newly_cleared: List[int] = []

        async def _run(client: Any = None) -> None:
            probe_outcome = await self._fetch_one(anchor_id, sem, limiter, client=client)
            outcomes.append(probe_outcome)
            if self.db.apply_probe_outcome(probe_outcome):
                newly_cleared.append(probe_outcome.report_id)

            should_fan_out = not probe_only and (
                (not probe_first)
                or probe_outcome.readiness in ("READY_TO_SUBMIT", "ALREADY_SUBMITTED", "NOT_FOUND")
            )
            if should_fan_out:
                rest_ids = [rid for rid in target_ids if rid != anchor_id]
                tasks = [
                    asyncio.create_task(self._fetch_one(rid, sem, limiter, client=client))
                    for rid in rest_ids
                ]
                if tasks:
                    for res in await asyncio.gather(*tasks):
                        outcomes.append(res)
                        if self.db.apply_probe_outcome(res):
                            newly_cleared.append(res.report_id)

        if httpx is not None and self._custom_fetcher is None:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                await _run(client=client)
        else:
            await _run(client=None)

        return self._finalize_summary(
            anchor_id=anchor_id,
            outcomes=outcomes,
            newly_cleared=newly_cleared,
            max_per_day=max_per_day,
            out_md=out_md,
            source="http",
        )

    def check(
        self,
        *,
        report_ids: Optional[Sequence[int]] = None,
        probe_report_id: int = DEFAULT_PROBE_REPORT_ID,
        probe_first: bool = True,
        probe_only: bool = False,
        max_per_day: int = 2,
        out_md: Optional[str | Path] = DEFAULT_READY_MD,
    ) -> DraftCheckSummary:
        return asyncio.run(
            self.check_async(
                report_ids=report_ids,
                probe_report_id=probe_report_id,
                probe_first=probe_first,
                probe_only=probe_only,
                max_per_day=max_per_day,
                out_md=out_md,
            )
        )

    def ingest_snapshots(
        self,
        snapshots: Iterable[Dict[str, Any]],
        *,
        probe_report_id: int = DEFAULT_PROBE_REPORT_ID,
        max_per_day: int = 2,
        out_md: Optional[str | Path] = DEFAULT_READY_MD,
    ) -> DraftCheckSummary:
        """Ingest report JSON payloads exported from an authenticated HackerOne browser session."""
        if not self.db.list_drafts(only_drafts=False):
            self.db.seed_default_queue()

        outcomes: List[ProbeOutcome] = []
        newly_cleared: List[int] = []
        for snap in snapshots:
            if not isinstance(snap, dict):
                continue
            rid = int(snap.get("id") or snap.get("report_id") or 0)
            if rid <= 0:
                continue
            http_status = int(snap.get("_http_status", 200))
            outcome = parse_hackerone_report_json(rid, snap, http_status=http_status, base_url=self.base_url)
            outcomes.append(outcome)
            if self.db.apply_probe_outcome(outcome):
                newly_cleared.append(rid)

        anchor_id = probe_report_id
        if outcomes and all(o.report_id != anchor_id for o in outcomes):
            anchor_id = outcomes[0].report_id
        return self._finalize_summary(
            anchor_id=anchor_id,
            outcomes=outcomes,
            newly_cleared=newly_cleared,
            max_per_day=max_per_day,
            out_md=out_md,
            source="browser_snapshot",
        )

    def _finalize_summary(
        self,
        *,
        anchor_id: int,
        outcomes: List[ProbeOutcome],
        newly_cleared: List[int],
        max_per_day: int,
        out_md: Optional[str | Path],
        source: str,
    ) -> DraftCheckSummary:
        probe_out = next((o for o in outcomes if o.report_id == anchor_id), outcomes[0] if outcomes else None)
        readiness_set = {o.readiness for o in outcomes}
        if "READY_TO_SUBMIT" in readiness_set:
            account_status = "CLEARED"
        elif "COOLDOWN_LOCKED" in readiness_set:
            account_status = "COOLDOWN_ACTIVE"
        elif "RATE_LIMITED" in readiness_set:
            account_status = "RATE_LIMITED"
        elif "AUTH_REQUIRED" in readiness_set:
            account_status = "AUTH_REQUIRED"
        else:
            account_status = "UNKNOWN"

        drafts = self.db.list_drafts(only_drafts=True)
        all_rows = self.db.list_drafts(only_drafts=False)
        ready_drafts = [d for d in sorted(drafts, key=_priority_sort_key) if d.can_submit_draft is True]
        locked_drafts = [d for d in drafts if d.can_submit_draft is False]
        submitted_rows = [d for d in all_rows if d.state.lower() != "draft"]

        submitted_today = self.db.get_submitted_today()
        daily_limit = max(1, int(max_per_day))
        remaining_today = max(0, daily_limit - submitted_today)

        recommended: List[Dict[str, Any]] = []
        if account_status == "CLEARED" and remaining_today > 0:
            # Prefer verified READY_TO_SUBMIT drafts; fall back to top priority drafts if probe-only cleared.
            # Hard QA Phase gate: NEVER recommend any draft with an unresolved QA failure.
            _qa_blocked = {"FAIL", "NEEDS_SOURCE_EDIT", "AUTO_FIXED_PENDING_PUSH"}
            pool = ready_drafts if ready_drafts else sorted(drafts, key=_priority_sort_key)
            eligible_pool = [d for d in pool if str(d.qa_status or "UNCHECKED").upper() not in _qa_blocked]
            for d in eligible_pool[:remaining_today]:
                recommended.append(
                    {
                        "report_id": d.report_id,
                        "url": d.url,
                        "program": d.program,
                        "payout_tier": d.payout_tier,
                        "severity": d.severity,
                        "title": d.title,
                        "priority_rank": d.priority_rank,
                        "qa_status": d.qa_status,
                    }
                )

        self.db.record_check_run(
            probe_report_id=anchor_id,
            account_status=account_status,
            ready_count=len(ready_drafts),
            locked_count=len(locked_drafts),
            http_status=probe_out.http_status if probe_out else 0,
            source=source,
        )

        summary = DraftCheckSummary(
            checked_at_utc=_utc_now_iso(),
            account_status=account_status,
            probe_report_id=anchor_id,
            probe_outcome=probe_out.to_dict() if probe_out else {},
            total_tracked_drafts=len(drafts),
            ready_to_submit_count=len(ready_drafts),
            cooldown_locked_count=len(locked_drafts),
            already_submitted_count=len(submitted_rows),
            daily_limit=daily_limit,
            submitted_today=submitted_today,
            remaining_today=remaining_today,
            recommended_next_batch=recommended,
            all_outcomes=[o.to_dict() for o in outcomes],
            newly_cleared_ids=sorted(set(newly_cleared)),
            ready_markdown_path=str(out_md) if out_md else "",
        )

        if out_md:
            md_path = Path(out_md)
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(render_ready_markdown(summary, drafts), encoding="utf-8")

        return summary
