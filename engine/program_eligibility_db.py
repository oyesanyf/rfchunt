"""
SQLite Program Eligibility, Schema v2 Directory Metrics & Signal-Requirement Registry
(`engine/program_eligibility_db.py`).
===================================================================================
Persists HackerOne / bug bounty program eligibility statuses (`UNLOCKED`, `BLOCKED_SIGNAL`,
`PAUSED`, `NOT_FOUND`), structured directory metadata (launch date, response efficiency %,
first-response/triage latency, scope counts, RoE compliance contract), `hunt_outcomes` for
online ML learning, and `account_state` (Signal establishment & daily submission pacing).
"""

from __future__ import annotations

import contextlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse


DEFAULT_ELIGIBILITY_DB_PATH = (
    Path(__file__).resolve().parent.parent
    / "reports"
    / "ensemble_hunt"
    / "program_eligibility.sqlite3"
)


def resolve_eligibility_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolves the SQLite eligibility DB path, honoring `RFCHUNT_ELIGIBILITY_DB` when `db_path` is None."""
    if db_path is not None:
        raw = str(db_path).strip()
        if raw:
            return Path(raw)
    env_path = os.environ.get("RFCHUNT_ELIGIBILITY_DB", "").strip()
    if env_path:
        return Path(env_path)
    return DEFAULT_ELIGIBILITY_DB_PATH


VALID_STATUSES = frozenset({"UNLOCKED", "BLOCKED_SIGNAL", "PAUSED", "NOT_FOUND"})
VALID_OUTCOMES = frozenset({"TRIAGED", "RESOLVED", "BOUNTY", "DUPLICATE", "INFORMATIVE", "NA", "NO_FINDING"})

DEFAULT_RECHECK_HOURS: Dict[str, int] = {
    "UNLOCKED": 24,
    "BLOCKED_SIGNAL": 48,
    "PAUSED": 168,
    "NOT_FOUND": 336,
}

_SCHEMA_V2_COLUMNS: Tuple[Tuple[str, str], ...] = (
    ("launched_at_utc", "TEXT NOT NULL DEFAULT ''"),
    ("response_efficiency_pct", "REAL"),
    ("first_response_hours", "REAL"),
    ("triage_hours", "REAL"),
    ("bounty_hours", "REAL"),
    ("resolved_count", "INTEGER NOT NULL DEFAULT 0"),
    ("offers_bounties", "INTEGER NOT NULL DEFAULT 0"),
    ("is_vdp", "INTEGER NOT NULL DEFAULT 0"),
    ("gold_standard", "INTEGER NOT NULL DEFAULT 0"),
    ("fast_payments", "INTEGER NOT NULL DEFAULT 0"),
    ("submission_state", "TEXT NOT NULL DEFAULT 'open'"),
    ("signal_established_required", "INTEGER NOT NULL DEFAULT 0"),
    ("wildcard_count", "INTEGER NOT NULL DEFAULT 0"),
    ("domain_count", "INTEGER NOT NULL DEFAULT 0"),
    ("api_asset_count", "INTEGER NOT NULL DEFAULT 0"),
    ("mobile_asset_count", "INTEGER NOT NULL DEFAULT 0"),
    ("source_repo_count", "INTEGER NOT NULL DEFAULT 0"),
    ("ai_asset_count", "INTEGER NOT NULL DEFAULT 0"),
    ("bounty_eligible_asset_count", "INTEGER NOT NULL DEFAULT 0"),
    ("in_scope_assets_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("in_scope_repos_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("out_of_scope_assets_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("scope_asset_types_json", "TEXT NOT NULL DEFAULT '{}'"),
    ("roe_automation_tier", "TEXT NOT NULL DEFAULT 'in_scope_only_manual_verify'"),
    ("roe_automated_prohibited", "INTEGER NOT NULL DEFAULT 0"),
    ("roe_max_rps", "REAL NOT NULL DEFAULT 2.0"),
    ("roe_required_headers_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("roe_user_agent", "TEXT NOT NULL DEFAULT ''"),
    ("roe_ai_disclosure_required", "INTEGER NOT NULL DEFAULT 0"),
    ("roe_no_oos_redirects", "INTEGER NOT NULL DEFAULT 1"),
)


def _normalize_hostname(raw: str) -> str:
    """Extracts a normalized lowercase DNS hostname without scheme, port, path, or trailing dot."""
    s = str(raw or "").strip().lower()
    if not s:
        return ""
    if "://" in s:
        try:
            parsed = urlparse(s)
            s = (parsed.hostname or "").lower()
        except ValueError:
            return ""
    else:
        s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in s:
            return ""
        if ":" in s and not s.startswith("["):
            s = s.split(":", 1)[0]
    return s.strip(".")


def host_matches_scope_pattern(host: str, pattern: str) -> bool:
    """
    Strict DNS label-boundary matcher for HackerOne scope assets.
    Prevents substring bypasses:
      - `*.amazon.com` matches `api.amazon.com` and `deep.sub.amazon.com` (requires >=1 subdomain label)
      - `*.amazon.com` REJECTS bare apex `amazon.com`, `notamazon.com`, and `amazon.com.evil.tld`
      - `*.amazon.*` matches `shop.amazon.co.uk` / `api.amazon.com` while rejecting `notamazon.com`
      - `api.example.com` matches ONLY `api.example.com`
    """
    h = _normalize_hostname(host)
    if not h:
        return False

    raw_pat = str(pattern or "").strip().lower()
    if not raw_pat:
        return False
    if "://" in raw_pat:
        try:
            p_url = urlparse(raw_pat)
            raw_pat = (p_url.hostname or "").lower()
        except ValueError:
            return False
    else:
        raw_pat = raw_pat.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in raw_pat and not raw_pat.startswith("["):
            raw_pat = raw_pat.split(":", 1)[0]
    pat = raw_pat.strip(".")
    if not pat or pat == "*":
        return False

    # Case 1: Standard leading wildcard `*.example.com` (no other wildcards)
    if pat.startswith("*.") and "*" not in pat[2:]:
        base = pat[2:]
        if not base or "." not in base:
            return False
        return len(h) > len(base) + 1 and h.endswith("." + base)

    # Case 2: Multi-segment wildcard e.g. `*.amazon.*` or `sub.*.example.com`
    if "*" in pat:
        h_labels = h.split(".")
        p_labels = pat.split(".")
        # Match DNS labels with `*` matching >= 1 whole DNS label
        memo: Dict[Tuple[int, int], bool] = {}

        def _dp(pi: int, hi: int) -> bool:
            key = (pi, hi)
            if key in memo:
                return memo[key]
            if pi == len(p_labels) and hi == len(h_labels):
                memo[key] = True
                return True
            if pi == len(p_labels):
                memo[key] = False
                return False
            tok = p_labels[pi]
            if tok == "*":
                for next_hi in range(hi + 1, len(h_labels) + 1):
                    if _dp(pi + 1, next_hi):
                        memo[key] = True
                        return True
                memo[key] = False
                return False
            if hi >= len(h_labels):
                memo[key] = False
                return False
            if "*" in tok:
                # Partial-label wildcard such as `app-*.example.com`
                rx = "^" + re.escape(tok).replace(r"\*", r"[a-z0-9-]*") + "$"
                ok = bool(re.match(rx, h_labels[hi])) and _dp(pi + 1, hi + 1)
            else:
                ok = (h_labels[hi] == tok) and _dp(pi + 1, hi + 1)
            memo[key] = ok
            return ok

        return _dp(0, 0)

    # Case 3: Exact DNS hostname match
    return h == pat


def is_host_in_scope(
    host: str,
    in_scope_assets: Sequence[str],
    out_of_scope_assets: Sequence[str] = (),
) -> Tuple[bool, str]:
    """
    Fail-closed scope validator using strict DNS label-boundary matching.
    Out-of-scope rules always override in-scope rules.
    Returns `(allowed, reason)`.
    """
    h = _normalize_hostname(host)
    if not h:
        return False, "invalid_hostname"
    for oos in out_of_scope_assets:
        if host_matches_scope_pattern(h, oos):
            return False, f"out_of_scope:{oos}"
    if not in_scope_assets:
        return False, "no_in_scope_assets_declared"
    for ins in in_scope_assets:
        if host_matches_scope_pattern(h, ins):
            return True, f"matched_in_scope:{ins}"
    return False, "not_in_scope"


def _json_load_list(raw: Any) -> Tuple[str, ...]:
    if isinstance(raw, (list, tuple)):
        return tuple(str(x).strip() for x in raw if str(x or "").strip())
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return tuple(str(x).strip() for x in parsed if str(x or "").strip())
        except Exception:
            pass
    return ()


def _json_load_dict(raw: Any) -> Dict[str, int]:
    if isinstance(raw, dict):
        out: Dict[str, int] = {}
        for k, v in raw.items():
            try:
                out[str(k)] = int(v)
            except (TypeError, ValueError):
                continue
        return out
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return {str(k): int(v) for k, v in parsed.items() if isinstance(v, (int, float))}
        except Exception:
            pass
    return {}


def parse_scope_prose_metadata(
    handle: str,
    scope_summary: str,
    notes: str = "",
    *,
    bounty_max_usd: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Deterministically backfills structured Schema v2 columns from observed HackerOne
    baseline prose summaries (launch date, efficiency %, response latency, resolved count,
    scope asset counts, GitHub repos, and VDP vs BBP classification).
    """
    blob = f"{scope_summary or ''} {notes or ''}".strip()
    low = blob.lower()
    meta: Dict[str, Any] = {}

    # Launch date (`launched MM/YYYY` or `launched YYYY-MM`)
    m_launch = re.search(r"launched\s+(\d{1,2})/(\d{4})", low)
    if m_launch:
        mm = max(1, min(12, int(m_launch.group(1))))
        yyyy = int(m_launch.group(2))
        meta["launched_at_utc"] = f"{yyyy:04d}-{mm:02d}-01T00:00:00+00:00"
    else:
        m_iso = re.search(r"launched\s+(\d{4})-(\d{2})(?:-(\d{2}))?", low)
        if m_iso:
            dd = int(m_iso.group(3) or "1")
            meta["launched_at_utc"] = f"{int(m_iso.group(1)):04d}-{int(m_iso.group(2)):02d}-{dd:02d}T00:00:00+00:00"

    # Response efficiency percentage (`96% response efficiency` or `>=80% response efficiency`)
    m_eff = re.search(r"(>=?\s*)?(\d{1,3}(?:\.\d+)?)\s*%\s*response\s*efficiency", low)
    if m_eff:
        val = float(m_eff.group(2))
        if m_eff.group(1) and val == 80.0:
            val = 82.0  # conservative estimate for "High (>=80%) response efficiency"
        meta["response_efficiency_pct"] = max(0.0, min(100.0, val))

    # First response latency (`~15h first response`)
    m_resp = re.search(r"~?\s*(\d+(?:\.\d+)?)\s*h(?:ours?|rs?)?\s+first\s+response", low)
    if m_resp:
        meta["first_response_hours"] = float(m_resp.group(1))

    # Resolved count (`282 resolved`, `32,168 resolved`)
    m_res = re.search(r"\b(\d{1,3}(?:,\d{3})+|\d+)\s+resolved\b", low)
    if m_res:
        meta["resolved_count"] = int(m_res.group(1).replace(",", ""))

    # Gold standard / fast payments
    if "gold standard" in low:
        meta["gold_standard"] = True
    if "fast payments" in low:
        meta["fast_payments"] = True

    # VDP vs BBP classification
    has_cash = (bounty_max_usd is not None and int(bounty_max_usd) > 0)
    is_vdp = (not has_cash) and (
        "vdp" in low or "non-monetary" in low or handle.endswith("_vdp") or handle.endswith("-vdp") or "disclosure" in handle
    )
    meta["offers_bounties"] = bool(has_cash)
    meta["is_vdp"] = bool(is_vdp or not has_cash)

    # Explicit counts in prose
    m_wc = re.search(r"\b(\d+)\s+wildcards?\b", low)
    wildcards_list = re.findall(r"\*\.[a-z0-9.*-]+", low)
    wildcard_count = int(m_wc.group(1)) if m_wc else len(set(wildcards_list))

    m_dom = re.search(r"\b(\d+)\s+domains?\b", low)
    bare_domains = re.findall(r"\b(?:[a-z0-9-]+\.)+(?:com|org|net|io|dev|in|gov|edu|ai)\b", low)
    filtered_domains = [
        d for d in set(bare_domains)
        if not d.startswith("github.com") and not any(d in w for w in wildcards_list)
    ]
    domain_count = int(m_dom.group(1)) if m_dom else len(filtered_domains)

    # API assets
    api_endpoints = re.findall(r"/(?:v\d+/[a-z0-9_-]+|api/[a-z0-9_-]+|status-lists|graphql)", low)
    api_count = len(set(api_endpoints))
    if api_count == 0 and any(k in low for k in ("api", "graphql", "sandbox")):
        api_count = 1

    # Mobile assets
    mobile_pkgs = re.findall(r"\bcom\.[a-z0-9_.*-]+\b", low)
    mobile_count = len(set(mobile_pkgs))
    if mobile_count == 0:
        if "android" in low:
            mobile_count += 1
        if "ios" in low:
            mobile_count += 1
        if "apps" in low and any(k in low for k in ("shopping", "alexa", "kindle")):
            mobile_count += 3

    # AI assets
    m_ai = re.search(r"\b(\d+)\s+ai\s+models?\b", low)
    ai_count = int(m_ai.group(1)) if m_ai else (1 if any(k in low for k in ("genai", "claude", "ai models", "llm", "mcp")) else 0)

    # Source repos
    in_scope_repos: List[str] = []
    for m_gh in re.finditer(r"(?:https?://)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.*-]+)", blob):
        owner, repo = m_gh.group(1), m_gh.group(2).rstrip(".,;)")
        if repo != "*":
            url = f"https://github.com/{owner}/{repo}"
            if url not in in_scope_repos:
                in_scope_repos.append(url)
    # Seed well-known in-scope OSS repos for baseline programs whose prose cites org wildcards
    h_low = handle.strip().lower()
    if h_low == "anthropic":
        for slug in (
            "anthropics/claude-code",
            "anthropics/claude-code-action",
            "anthropics/anthropic-sdk-python",
            "anthropics/anthropic-sdk-typescript",
            "anthropics/anthropic-sdk-go",
            "anthropics/claude-agent-sdk-python",
        ):
            u = f"https://github.com/{slug}"
            if u not in in_scope_repos:
                in_scope_repos.append(u)
    elif h_low == "rails" and "https://github.com/rails/rails" not in in_scope_repos:
        in_scope_repos.append("https://github.com/rails/rails")
    elif h_low == "ruby" and "https://github.com/ruby/ruby" not in in_scope_repos:
        in_scope_repos.append("https://github.com/ruby/ruby")

    source_repo_count = len(in_scope_repos)
    if source_repo_count == 0 and "github.com/" in low:
        source_repo_count = 1

    in_scope_assets = sorted(set(wildcards_list + filtered_domains))
    meta.update(
        {
            "wildcard_count": wildcard_count,
            "domain_count": domain_count,
            "api_asset_count": api_count,
            "mobile_asset_count": mobile_count,
            "source_repo_count": source_repo_count,
            "ai_asset_count": ai_count,
            "bounty_eligible_asset_count": (wildcard_count + domain_count + api_count + mobile_count + source_repo_count + ai_count) if has_cash else 0,
            "in_scope_assets": tuple(in_scope_assets),
            "in_scope_repos": tuple(in_scope_repos),
            "scope_asset_types": {
                "WILDCARD": wildcard_count,
                "URL": domain_count,
                "API": api_count,
                "MOBILE": mobile_count,
                "SOURCE_CODE": source_repo_count,
                "AI_MODEL": ai_count,
            },
        }
    )
    return meta


@dataclass(frozen=True)
class ProgramEligibilityRecord:
    handle: str
    platform: str
    status: str
    signal_required: Optional[float]
    bounty_min_usd: Optional[int]
    bounty_max_usd: Optional[int]
    submit_url: str
    scope_summary: str
    last_checked_utc: str
    next_recheck_utc: str
    notes: str = ""
    # Schema v2 directory, scope & RoE fields (backwards-compatible defaults)
    launched_at_utc: str = ""
    response_efficiency_pct: Optional[float] = None
    first_response_hours: Optional[float] = None
    triage_hours: Optional[float] = None
    bounty_hours: Optional[float] = None
    resolved_count: int = 0
    offers_bounties: bool = False
    is_vdp: bool = False
    gold_standard: bool = False
    fast_payments: bool = False
    submission_state: str = "open"
    signal_established_required: bool = False
    wildcard_count: int = 0
    domain_count: int = 0
    api_asset_count: int = 0
    mobile_asset_count: int = 0
    source_repo_count: int = 0
    ai_asset_count: int = 0
    bounty_eligible_asset_count: int = 0
    in_scope_assets: Tuple[str, ...] = ()
    in_scope_repos: Tuple[str, ...] = ()
    out_of_scope_assets: Tuple[str, ...] = ()
    scope_asset_types: Dict[str, int] = field(default_factory=dict)
    roe_automation_tier: str = "in_scope_only_manual_verify"
    roe_automated_prohibited: bool = False
    roe_max_rps: float = 2.0
    roe_required_headers: Tuple[str, ...] = ()
    roe_user_agent: str = ""
    roe_ai_disclosure_required: bool = False
    roe_no_oos_redirects: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["in_scope_assets"] = list(self.in_scope_assets)
        d["in_scope_repos"] = list(self.in_scope_repos)
        d["out_of_scope_assets"] = list(self.out_of_scope_assets)
        d["roe_required_headers"] = list(self.roe_required_headers)
        return d


@dataclass(frozen=True)
class HuntOutcomeRecord:
    outcome_id: str
    handle: str
    repo: str
    commit_sha: str
    lane: int
    discovered_at_utc: str
    target_age_hours: float
    outcome: str
    signal_delta: float = 0.0
    bounty_usd: float = 0.0
    triage_hours_observed: Optional[float] = None
    cycle_id: str = ""
    features: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AccountSignalState:
    signal_established: bool = False
    signal_score: Optional[float] = None
    trial_reports_remaining: int = 0
    daily_submissions_count: int = 0
    daily_submissions_date_utc: str = ""
    updated_at_utc: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _utc_now(now: Optional[datetime] = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


class ProgramEligibilityDB:
    """Thread-safe SQLite store tracking unlocked vs Signal-blocked bounty programs & ML outcomes."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self.db_path = resolve_eligibility_db_path(db_path)
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        return conn

    def _init_schema(self) -> None:
        with contextlib.closing(self._connect()) as conn:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS program_eligibility (
                        handle TEXT PRIMARY KEY,
                        platform TEXT NOT NULL DEFAULT 'hackerone',
                        status TEXT NOT NULL,
                        signal_required REAL,
                        bounty_min_usd INTEGER,
                        bounty_max_usd INTEGER,
                        submit_url TEXT NOT NULL DEFAULT '',
                        scope_summary TEXT NOT NULL DEFAULT '',
                        last_checked_utc TEXT NOT NULL,
                        next_recheck_utc TEXT NOT NULL,
                        notes TEXT NOT NULL DEFAULT ''
                    );
                    """
                )
                existing_cols = {
                    str(r["name"])
                    for r in conn.execute("PRAGMA table_info(program_eligibility)").fetchall()
                }
                for col_name, col_ddl in _SCHEMA_V2_COLUMNS:
                    if col_name not in existing_cols:
                        conn.execute(f"ALTER TABLE program_eligibility ADD COLUMN {col_name} {col_ddl};")

                # Deterministic v1 -> v2 prose backfill for legacy rows missing structured v2 metadata
                legacy_rows = conn.execute(
                    """
                    SELECT handle, status, bounty_max_usd, scope_summary, notes
                    FROM program_eligibility
                    WHERE (scope_summary != '' OR notes != '')
                      AND scope_asset_types_json = '{}'
                      AND in_scope_repos_json = '[]'
                      AND in_scope_assets_json = '[]'
                    """
                ).fetchall()
                for row in legacy_rows:
                    parsed = parse_scope_prose_metadata(
                        str(row["handle"]),
                        str(row["scope_summary"] or ""),
                        str(row["notes"] or ""),
                        bounty_max_usd=row["bounty_max_usd"],
                    )
                    if not parsed:
                        continue
                    conn.execute(
                        """
                        UPDATE program_eligibility
                        SET launched_at_utc = CASE WHEN launched_at_utc = '' THEN ? ELSE launched_at_utc END,
                            response_efficiency_pct = COALESCE(response_efficiency_pct, ?),
                            first_response_hours = COALESCE(first_response_hours, ?),
                            resolved_count = CASE WHEN resolved_count = 0 THEN ? ELSE resolved_count END,
                            offers_bounties = ?,
                            is_vdp = ?,
                            gold_standard = CASE WHEN gold_standard = 0 THEN ? ELSE gold_standard END,
                            fast_payments = CASE WHEN fast_payments = 0 THEN ? ELSE fast_payments END,
                            wildcard_count = ?,
                            domain_count = ?,
                            api_asset_count = ?,
                            mobile_asset_count = ?,
                            source_repo_count = ?,
                            ai_asset_count = ?,
                            bounty_eligible_asset_count = ?,
                            in_scope_assets_json = ?,
                            in_scope_repos_json = ?,
                            scope_asset_types_json = ?
                        WHERE handle = ?
                        """,
                        (
                            str(parsed.get("launched_at_utc") or ""),
                            parsed.get("response_efficiency_pct"),
                            parsed.get("first_response_hours"),
                            int(parsed.get("resolved_count") or 0),
                            1 if parsed.get("offers_bounties") else 0,
                            1 if parsed.get("is_vdp") else 0,
                            1 if parsed.get("gold_standard") else 0,
                            1 if parsed.get("fast_payments") else 0,
                            int(parsed.get("wildcard_count") or 0),
                            int(parsed.get("domain_count") or 0),
                            int(parsed.get("api_asset_count") or 0),
                            int(parsed.get("mobile_asset_count") or 0),
                            int(parsed.get("source_repo_count") or 0),
                            int(parsed.get("ai_asset_count") or 0),
                            int(parsed.get("bounty_eligible_asset_count") or 0),
                            json.dumps(list(parsed.get("in_scope_assets") or ()), sort_keys=False),
                            json.dumps(list(parsed.get("in_scope_repos") or ()), sort_keys=False),
                            json.dumps(dict(parsed.get("scope_asset_types") or {}), sort_keys=True),
                            str(row["handle"]),
                        ),
                    )

                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_program_status_recheck
                    ON program_eligibility(status, next_recheck_utc);
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS hunt_outcomes (
                        outcome_id TEXT PRIMARY KEY,
                        handle TEXT NOT NULL,
                        repo TEXT NOT NULL DEFAULT '',
                        commit_sha TEXT NOT NULL DEFAULT '',
                        lane INTEGER NOT NULL DEFAULT 1,
                        discovered_at_utc TEXT NOT NULL,
                        target_age_hours REAL NOT NULL DEFAULT 0.0,
                        outcome TEXT NOT NULL,
                        signal_delta REAL NOT NULL DEFAULT 0.0,
                        bounty_usd REAL NOT NULL DEFAULT 0.0,
                        triage_hours_observed REAL,
                        cycle_id TEXT NOT NULL DEFAULT '',
                        features_json TEXT NOT NULL DEFAULT '{}'
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_hunt_outcomes_handle_ts
                    ON hunt_outcomes(handle, discovered_at_utc);
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS account_state (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        signal_established INTEGER NOT NULL DEFAULT 0,
                        signal_score REAL,
                        trial_reports_remaining INTEGER NOT NULL DEFAULT 0,
                        daily_submissions_count INTEGER NOT NULL DEFAULT 0,
                        daily_submissions_date_utc TEXT NOT NULL DEFAULT '',
                        updated_at_utc TEXT NOT NULL DEFAULT ''
                    );
                    """
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO account_state (
                        id, signal_established, signal_score, trial_reports_remaining,
                        daily_submissions_count, daily_submissions_date_utc, updated_at_utc
                    ) VALUES (1, 0, NULL, 0, 0, '', '');
                    """
                )

    def upsert(
        self,
        handle: str,
        status: str,
        *,
        platform: str = "hackerone",
        signal_required: Optional[float] = None,
        bounty_min_usd: Optional[int] = None,
        bounty_max_usd: Optional[int] = None,
        submit_url: str = "",
        scope_summary: str = "",
        notes: str = "",
        recheck_hours: Optional[int] = None,
        now: Optional[datetime] = None,
        # Optional Schema v2 fields
        launched_at_utc: Optional[str] = None,
        response_efficiency_pct: Optional[float] = None,
        first_response_hours: Optional[float] = None,
        triage_hours: Optional[float] = None,
        bounty_hours: Optional[float] = None,
        resolved_count: Optional[int] = None,
        offers_bounties: Optional[bool] = None,
        is_vdp: Optional[bool] = None,
        gold_standard: Optional[bool] = None,
        fast_payments: Optional[bool] = None,
        submission_state: Optional[str] = None,
        signal_established_required: Optional[bool] = None,
        wildcard_count: Optional[int] = None,
        domain_count: Optional[int] = None,
        api_asset_count: Optional[int] = None,
        mobile_asset_count: Optional[int] = None,
        source_repo_count: Optional[int] = None,
        ai_asset_count: Optional[int] = None,
        bounty_eligible_asset_count: Optional[int] = None,
        in_scope_assets: Optional[Sequence[str]] = None,
        in_scope_repos: Optional[Sequence[str]] = None,
        out_of_scope_assets: Optional[Sequence[str]] = None,
        scope_asset_types: Optional[Dict[str, int]] = None,
        roe_automation_tier: Optional[str] = None,
        roe_automated_prohibited: Optional[bool] = None,
        roe_max_rps: Optional[float] = None,
        roe_required_headers: Optional[Sequence[str]] = None,
        roe_user_agent: Optional[str] = None,
        roe_ai_disclosure_required: Optional[bool] = None,
        roe_no_oos_redirects: Optional[bool] = None,
    ) -> ProgramEligibilityRecord:
        norm_handle = handle.strip().lower()
        norm_status = status.strip().upper()
        if not norm_handle:
            raise ValueError("Program handle cannot be empty.")
        if norm_status not in VALID_STATUSES:
            raise ValueError(f"Unsupported status {status!r}; expected one of {sorted(VALID_STATUSES)}.")

        ts = _utc_now(now)
        hours = (
            max(1, int(recheck_hours))
            if recheck_hours is not None
            else DEFAULT_RECHECK_HOURS[norm_status]
        )
        next_ts = ts + timedelta(hours=hours)
        eff_url = submit_url or (
            f"https://hackerone.com/{norm_handle}/reports/new?type=team&report_type=vulnerability"
            if platform == "hackerone"
            else ""
        )

        # Backfill structured metadata from prose when not explicitly provided
        parsed_meta = (
            parse_scope_prose_metadata(
                norm_handle,
                scope_summary,
                notes,
                bounty_max_usd=bounty_max_usd,
            )
            if (scope_summary or notes)
            else {}
        )

        eff_launched = launched_at_utc if launched_at_utc is not None else str(parsed_meta.get("launched_at_utc") or "")
        eff_resp_eff = (
            float(response_efficiency_pct)
            if response_efficiency_pct is not None
            else parsed_meta.get("response_efficiency_pct")
        )
        eff_first_resp = (
            float(first_response_hours)
            if first_response_hours is not None
            else parsed_meta.get("first_response_hours")
        )
        eff_resolved = int(resolved_count) if resolved_count is not None else int(parsed_meta.get("resolved_count") or 0)
        eff_offers_bounties = (
            bool(offers_bounties)
            if offers_bounties is not None
            else bool(parsed_meta.get("offers_bounties", bool(bounty_max_usd and bounty_max_usd > 0)))
        )
        eff_is_vdp = (
            bool(is_vdp)
            if is_vdp is not None
            else bool(parsed_meta.get("is_vdp", not eff_offers_bounties))
        )
        eff_gold = bool(gold_standard) if gold_standard is not None else bool(parsed_meta.get("gold_standard", False))
        eff_fast = bool(fast_payments) if fast_payments is not None else bool(parsed_meta.get("fast_payments", False))
        eff_sub_state = (submission_state or ("paused" if norm_status == "PAUSED" else "open")).strip().lower()
        eff_sig_est = (
            bool(signal_established_required)
            if signal_established_required is not None
            else bool(norm_status == "BLOCKED_SIGNAL" and signal_required is not None and signal_required >= 0.0)
        )
        eff_wc = int(wildcard_count) if wildcard_count is not None else int(parsed_meta.get("wildcard_count") or 0)
        eff_dom = int(domain_count) if domain_count is not None else int(parsed_meta.get("domain_count") or 0)
        eff_api = int(api_asset_count) if api_asset_count is not None else int(parsed_meta.get("api_asset_count") or 0)
        eff_mob = int(mobile_asset_count) if mobile_asset_count is not None else int(parsed_meta.get("mobile_asset_count") or 0)
        eff_src = int(source_repo_count) if source_repo_count is not None else int(parsed_meta.get("source_repo_count") or 0)
        eff_ai = int(ai_asset_count) if ai_asset_count is not None else int(parsed_meta.get("ai_asset_count") or 0)
        eff_b_assets = (
            int(bounty_eligible_asset_count)
            if bounty_eligible_asset_count is not None
            else int(parsed_meta.get("bounty_eligible_asset_count") or 0)
        )
        eff_in_assets = (
            tuple(str(x).strip() for x in in_scope_assets if str(x or "").strip())
            if in_scope_assets is not None
            else tuple(parsed_meta.get("in_scope_assets") or ())
        )
        eff_in_repos = (
            tuple(str(x).strip() for x in in_scope_repos if str(x or "").strip())
            if in_scope_repos is not None
            else tuple(parsed_meta.get("in_scope_repos") or ())
        )
        eff_oos_assets = (
            tuple(str(x).strip() for x in out_of_scope_assets if str(x or "").strip())
            if out_of_scope_assets is not None
            else ()
        )
        eff_scope_types = (
            dict(scope_asset_types)
            if scope_asset_types is not None
            else dict(parsed_meta.get("scope_asset_types") or {})
        )
        eff_roe_tier = (roe_automation_tier or "in_scope_only_manual_verify").strip()
        eff_roe_prohib = bool(roe_automated_prohibited) if roe_automated_prohibited is not None else (eff_roe_tier == "explicitly_prohibited")
        eff_roe_rps = 0.0 if eff_roe_prohib else (float(roe_max_rps) if roe_max_rps is not None else 2.0)
        eff_roe_headers = tuple(str(x).strip() for x in (roe_required_headers or ()) if str(x or "").strip())
        eff_roe_ua = str(roe_user_agent or "").strip()
        eff_roe_ai = bool(roe_ai_disclosure_required) if roe_ai_disclosure_required is not None else False
        eff_roe_no_redir = bool(roe_no_oos_redirects) if roe_no_oos_redirects is not None else True

        rec = ProgramEligibilityRecord(
            handle=norm_handle,
            platform=platform.strip().lower() or "hackerone",
            status=norm_status,
            signal_required=signal_required,
            bounty_min_usd=bounty_min_usd,
            bounty_max_usd=bounty_max_usd,
            submit_url=eff_url,
            scope_summary=scope_summary.strip(),
            last_checked_utc=ts.isoformat(),
            next_recheck_utc=next_ts.isoformat(),
            notes=notes.strip(),
            launched_at_utc=eff_launched,
            response_efficiency_pct=eff_resp_eff,
            first_response_hours=eff_first_resp,
            triage_hours=float(triage_hours) if triage_hours is not None else None,
            bounty_hours=float(bounty_hours) if bounty_hours is not None else None,
            resolved_count=eff_resolved,
            offers_bounties=eff_offers_bounties,
            is_vdp=eff_is_vdp,
            gold_standard=eff_gold,
            fast_payments=eff_fast,
            submission_state=eff_sub_state,
            signal_established_required=eff_sig_est,
            wildcard_count=eff_wc,
            domain_count=eff_dom,
            api_asset_count=eff_api,
            mobile_asset_count=eff_mob,
            source_repo_count=eff_src,
            ai_asset_count=eff_ai,
            bounty_eligible_asset_count=eff_b_assets,
            in_scope_assets=eff_in_assets,
            in_scope_repos=eff_in_repos,
            out_of_scope_assets=eff_oos_assets,
            scope_asset_types=eff_scope_types,
            roe_automation_tier=eff_roe_tier,
            roe_automated_prohibited=eff_roe_prohib,
            roe_max_rps=eff_roe_rps,
            roe_required_headers=eff_roe_headers,
            roe_user_agent=eff_roe_ua,
            roe_ai_disclosure_required=eff_roe_ai,
            roe_no_oos_redirects=eff_roe_no_redir,
        )

        with contextlib.closing(self._connect()) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO program_eligibility (
                        handle, platform, status, signal_required,
                        bounty_min_usd, bounty_max_usd, submit_url,
                        scope_summary, last_checked_utc, next_recheck_utc, notes,
                        launched_at_utc, response_efficiency_pct, first_response_hours,
                        triage_hours, bounty_hours, resolved_count, offers_bounties,
                        is_vdp, gold_standard, fast_payments, submission_state,
                        signal_established_required, wildcard_count, domain_count,
                        api_asset_count, mobile_asset_count, source_repo_count,
                        ai_asset_count, bounty_eligible_asset_count,
                        in_scope_assets_json, in_scope_repos_json, out_of_scope_assets_json,
                        scope_asset_types_json, roe_automation_tier, roe_automated_prohibited,
                        roe_max_rps, roe_required_headers_json, roe_user_agent,
                        roe_ai_disclosure_required, roe_no_oos_redirects
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(handle) DO UPDATE SET
                        platform=excluded.platform,
                        status=excluded.status,
                        signal_required=excluded.signal_required,
                        bounty_min_usd=COALESCE(excluded.bounty_min_usd, program_eligibility.bounty_min_usd),
                        bounty_max_usd=COALESCE(excluded.bounty_max_usd, program_eligibility.bounty_max_usd),
                        submit_url=CASE WHEN excluded.submit_url != '' THEN excluded.submit_url ELSE program_eligibility.submit_url END,
                        scope_summary=CASE WHEN excluded.scope_summary != '' THEN excluded.scope_summary ELSE program_eligibility.scope_summary END,
                        last_checked_utc=excluded.last_checked_utc,
                        next_recheck_utc=excluded.next_recheck_utc,
                        notes=excluded.notes,
                        launched_at_utc=CASE WHEN excluded.launched_at_utc != '' THEN excluded.launched_at_utc ELSE program_eligibility.launched_at_utc END,
                        response_efficiency_pct=COALESCE(excluded.response_efficiency_pct, program_eligibility.response_efficiency_pct),
                        first_response_hours=COALESCE(excluded.first_response_hours, program_eligibility.first_response_hours),
                        triage_hours=COALESCE(excluded.triage_hours, program_eligibility.triage_hours),
                        bounty_hours=COALESCE(excluded.bounty_hours, program_eligibility.bounty_hours),
                        resolved_count=CASE WHEN excluded.resolved_count > 0 THEN excluded.resolved_count ELSE program_eligibility.resolved_count END,
                        offers_bounties=excluded.offers_bounties,
                        is_vdp=excluded.is_vdp,
                        gold_standard=CASE WHEN excluded.gold_standard = 1 THEN 1 ELSE program_eligibility.gold_standard END,
                        fast_payments=CASE WHEN excluded.fast_payments = 1 THEN 1 ELSE program_eligibility.fast_payments END,
                        submission_state=excluded.submission_state,
                        signal_established_required=excluded.signal_established_required,
                        wildcard_count=CASE WHEN excluded.wildcard_count > 0 THEN excluded.wildcard_count ELSE program_eligibility.wildcard_count END,
                        domain_count=CASE WHEN excluded.domain_count > 0 THEN excluded.domain_count ELSE program_eligibility.domain_count END,
                        api_asset_count=CASE WHEN excluded.api_asset_count > 0 THEN excluded.api_asset_count ELSE program_eligibility.api_asset_count END,
                        mobile_asset_count=CASE WHEN excluded.mobile_asset_count > 0 THEN excluded.mobile_asset_count ELSE program_eligibility.mobile_asset_count END,
                        source_repo_count=CASE WHEN excluded.source_repo_count > 0 THEN excluded.source_repo_count ELSE program_eligibility.source_repo_count END,
                        ai_asset_count=CASE WHEN excluded.ai_asset_count > 0 THEN excluded.ai_asset_count ELSE program_eligibility.ai_asset_count END,
                        bounty_eligible_asset_count=CASE WHEN excluded.bounty_eligible_asset_count > 0 THEN excluded.bounty_eligible_asset_count ELSE program_eligibility.bounty_eligible_asset_count END,
                        in_scope_assets_json=CASE WHEN excluded.in_scope_assets_json != '[]' THEN excluded.in_scope_assets_json ELSE program_eligibility.in_scope_assets_json END,
                        in_scope_repos_json=CASE WHEN excluded.in_scope_repos_json != '[]' THEN excluded.in_scope_repos_json ELSE program_eligibility.in_scope_repos_json END,
                        out_of_scope_assets_json=CASE WHEN excluded.out_of_scope_assets_json != '[]' THEN excluded.out_of_scope_assets_json ELSE program_eligibility.out_of_scope_assets_json END,
                        scope_asset_types_json=CASE WHEN excluded.scope_asset_types_json != '{}' THEN excluded.scope_asset_types_json ELSE program_eligibility.scope_asset_types_json END,
                        roe_automation_tier=CASE WHEN excluded.roe_automation_tier != 'in_scope_only_manual_verify' THEN excluded.roe_automation_tier ELSE program_eligibility.roe_automation_tier END,
                        roe_automated_prohibited=excluded.roe_automated_prohibited,
                        roe_max_rps=excluded.roe_max_rps,
                        roe_required_headers_json=CASE WHEN excluded.roe_required_headers_json != '[]' THEN excluded.roe_required_headers_json ELSE program_eligibility.roe_required_headers_json END,
                        roe_user_agent=CASE WHEN excluded.roe_user_agent != '' THEN excluded.roe_user_agent ELSE program_eligibility.roe_user_agent END,
                        roe_ai_disclosure_required=excluded.roe_ai_disclosure_required,
                        roe_no_oos_redirects=excluded.roe_no_oos_redirects;
                    """,
                    (
                        rec.handle,
                        rec.platform,
                        rec.status,
                        rec.signal_required,
                        rec.bounty_min_usd,
                        rec.bounty_max_usd,
                        rec.submit_url,
                        rec.scope_summary,
                        rec.last_checked_utc,
                        rec.next_recheck_utc,
                        rec.notes,
                        rec.launched_at_utc,
                        rec.response_efficiency_pct,
                        rec.first_response_hours,
                        rec.triage_hours,
                        rec.bounty_hours,
                        rec.resolved_count,
                        1 if rec.offers_bounties else 0,
                        1 if rec.is_vdp else 0,
                        1 if rec.gold_standard else 0,
                        1 if rec.fast_payments else 0,
                        rec.submission_state,
                        1 if rec.signal_established_required else 0,
                        rec.wildcard_count,
                        rec.domain_count,
                        rec.api_asset_count,
                        rec.mobile_asset_count,
                        rec.source_repo_count,
                        rec.ai_asset_count,
                        rec.bounty_eligible_asset_count,
                        json.dumps(list(rec.in_scope_assets)),
                        json.dumps(list(rec.in_scope_repos)),
                        json.dumps(list(rec.out_of_scope_assets)),
                        json.dumps(rec.scope_asset_types, sort_keys=True),
                        rec.roe_automation_tier,
                        1 if rec.roe_automated_prohibited else 0,
                        rec.roe_max_rps,
                        json.dumps(list(rec.roe_required_headers)),
                        rec.roe_user_agent,
                        1 if rec.roe_ai_disclosure_required else 0,
                        1 if rec.roe_no_oos_redirects else 0,
                    ),
                )
        return rec

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ProgramEligibilityRecord:
        keys = set(row.keys())
        return ProgramEligibilityRecord(
            handle=row["handle"],
            platform=row["platform"],
            status=row["status"],
            signal_required=row["signal_required"],
            bounty_min_usd=row["bounty_min_usd"],
            bounty_max_usd=row["bounty_max_usd"],
            submit_url=row["submit_url"],
            scope_summary=row["scope_summary"],
            last_checked_utc=row["last_checked_utc"],
            next_recheck_utc=row["next_recheck_utc"],
            notes=row["notes"],
            launched_at_utc=str(row["launched_at_utc"] or "") if "launched_at_utc" in keys else "",
            response_efficiency_pct=row["response_efficiency_pct"] if "response_efficiency_pct" in keys else None,
            first_response_hours=row["first_response_hours"] if "first_response_hours" in keys else None,
            triage_hours=row["triage_hours"] if "triage_hours" in keys else None,
            bounty_hours=row["bounty_hours"] if "bounty_hours" in keys else None,
            resolved_count=int(row["resolved_count"] or 0) if "resolved_count" in keys else 0,
            offers_bounties=bool(row["offers_bounties"]) if "offers_bounties" in keys else bool(row["bounty_max_usd"] and row["bounty_max_usd"] > 0),
            is_vdp=bool(row["is_vdp"]) if "is_vdp" in keys else not bool(row["bounty_max_usd"] and row["bounty_max_usd"] > 0),
            gold_standard=bool(row["gold_standard"]) if "gold_standard" in keys else False,
            fast_payments=bool(row["fast_payments"]) if "fast_payments" in keys else False,
            submission_state=str(row["submission_state"] or "open") if "submission_state" in keys else "open",
            signal_established_required=bool(row["signal_established_required"]) if "signal_established_required" in keys else False,
            wildcard_count=int(row["wildcard_count"] or 0) if "wildcard_count" in keys else 0,
            domain_count=int(row["domain_count"] or 0) if "domain_count" in keys else 0,
            api_asset_count=int(row["api_asset_count"] or 0) if "api_asset_count" in keys else 0,
            mobile_asset_count=int(row["mobile_asset_count"] or 0) if "mobile_asset_count" in keys else 0,
            source_repo_count=int(row["source_repo_count"] or 0) if "source_repo_count" in keys else 0,
            ai_asset_count=int(row["ai_asset_count"] or 0) if "ai_asset_count" in keys else 0,
            bounty_eligible_asset_count=int(row["bounty_eligible_asset_count"] or 0) if "bounty_eligible_asset_count" in keys else 0,
            in_scope_assets=_json_load_list(row["in_scope_assets_json"]) if "in_scope_assets_json" in keys else (),
            in_scope_repos=_json_load_list(row["in_scope_repos_json"]) if "in_scope_repos_json" in keys else (),
            out_of_scope_assets=_json_load_list(row["out_of_scope_assets_json"]) if "out_of_scope_assets_json" in keys else (),
            scope_asset_types=_json_load_dict(row["scope_asset_types_json"]) if "scope_asset_types_json" in keys else {},
            roe_automation_tier=str(row["roe_automation_tier"] or "in_scope_only_manual_verify") if "roe_automation_tier" in keys else "in_scope_only_manual_verify",
            roe_automated_prohibited=bool(row["roe_automated_prohibited"]) if "roe_automated_prohibited" in keys else False,
            roe_max_rps=float(row["roe_max_rps"] if row["roe_max_rps"] is not None else 2.0) if "roe_max_rps" in keys else 2.0,
            roe_required_headers=_json_load_list(row["roe_required_headers_json"]) if "roe_required_headers_json" in keys else (),
            roe_user_agent=str(row["roe_user_agent"] or "") if "roe_user_agent" in keys else "",
            roe_ai_disclosure_required=bool(row["roe_ai_disclosure_required"]) if "roe_ai_disclosure_required" in keys else False,
            roe_no_oos_redirects=bool(row["roe_no_oos_redirects"]) if "roe_no_oos_redirects" in keys else True,
        )

    def get(self, handle: str) -> Optional[ProgramEligibilityRecord]:
        norm = handle.strip().lower()
        with contextlib.closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM program_eligibility WHERE handle = ?", (norm,)
            ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def is_eligible(self, handle: str) -> bool:
        """Fail-closed eligibility check: returns True ONLY if explicitly UNLOCKED and open."""
        rec = self.get(handle)
        return (
            rec is not None
            and rec.status == "UNLOCKED"
            and (rec.submission_state or "open").strip().lower() == "open"
        )

    def list_by_status(self, status: str) -> List[ProgramEligibilityRecord]:
        norm = status.strip().upper()
        with contextlib.closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT * FROM program_eligibility
                WHERE status = ?
                ORDER BY COALESCE(bounty_max_usd, 0) DESC, handle ASC
                """,
                (norm,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def list_unlocked(self) -> List[ProgramEligibilityRecord]:
        return self.list_by_status("UNLOCKED")

    def list_all(self) -> List[ProgramEligibilityRecord]:
        with contextlib.closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM program_eligibility ORDER BY status ASC, COALESCE(bounty_max_usd, 0) DESC, handle ASC"
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def list_due_for_recheck(
        self,
        *,
        statuses: Sequence[str] = ("BLOCKED_SIGNAL", "PAUSED"),
        limit: int = 20,
        now: Optional[datetime] = None,
    ) -> List[ProgramEligibilityRecord]:
        """Returns blocked/paused programs whose `next_recheck_utc <= now` to test if restrictions lifted."""
        now_iso = _utc_now(now).isoformat()
        norm_statuses = [s.strip().upper() for s in statuses if s.strip()]
        if not norm_statuses:
            return []
        placeholders = ",".join("?" for _ in norm_statuses)
        with contextlib.closing(self._connect()) as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM program_eligibility
                WHERE status IN ({placeholders})
                  AND next_recheck_utc <= ?
                ORDER BY next_recheck_utc ASC, COALESCE(bounty_max_usd, 0) DESC
                LIMIT ?
                """,
                (*norm_statuses, now_iso, max(1, int(limit))),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def summary_counts(self) -> Dict[str, int]:
        with contextlib.closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM program_eligibility GROUP BY status"
            ).fetchall()
        return {str(r["status"]): int(r["cnt"]) for r in rows}

    # --- Hunt Outcomes (Online ML Feedback Loop) ---

    def record_hunt_outcome(
        self,
        *,
        handle: str,
        outcome: str,
        repo: str = "",
        commit_sha: str = "",
        lane: int = 1,
        target_age_hours: float = 0.0,
        signal_delta: float = 0.0,
        bounty_usd: float = 0.0,
        triage_hours_observed: Optional[float] = None,
        cycle_id: str = "",
        features: Optional[Dict[str, Any]] = None,
        outcome_id: Optional[str] = None,
        discovered_at_utc: Optional[str] = None,
    ) -> HuntOutcomeRecord:
        norm_handle = handle.strip().lower()
        norm_outcome = outcome.strip().upper()
        if not norm_handle:
            raise ValueError("handle cannot be empty.")
        if norm_outcome not in VALID_OUTCOMES:
            raise ValueError(f"Unsupported outcome {outcome!r}; expected one of {sorted(VALID_OUTCOMES)}.")
        ts_iso = discovered_at_utc or _utc_now().isoformat()
        eff_id = outcome_id or f"out_{norm_handle}_{int(_utc_now().timestamp() * 1000)}_{os.urandom(3).hex()}"
        rec = HuntOutcomeRecord(
            outcome_id=eff_id,
            handle=norm_handle,
            repo=str(repo or "").strip(),
            commit_sha=str(commit_sha or "").strip(),
            lane=max(1, min(2, int(lane))),
            discovered_at_utc=ts_iso,
            target_age_hours=max(0.0, float(target_age_hours or 0.0)),
            outcome=norm_outcome,
            signal_delta=float(signal_delta or 0.0),
            bounty_usd=max(0.0, float(bounty_usd or 0.0)),
            triage_hours_observed=float(triage_hours_observed) if triage_hours_observed is not None else None,
            cycle_id=str(cycle_id or "").strip(),
            features=dict(features or {}),
        )
        with contextlib.closing(self._connect()) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO hunt_outcomes (
                        outcome_id, handle, repo, commit_sha, lane, discovered_at_utc,
                        target_age_hours, outcome, signal_delta, bounty_usd,
                        triage_hours_observed, cycle_id, features_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rec.outcome_id,
                        rec.handle,
                        rec.repo,
                        rec.commit_sha,
                        rec.lane,
                        rec.discovered_at_utc,
                        rec.target_age_hours,
                        rec.outcome,
                        rec.signal_delta,
                        rec.bounty_usd,
                        rec.triage_hours_observed,
                        rec.cycle_id,
                        json.dumps(rec.features, sort_keys=True),
                    ),
                )
        return rec

    def list_hunt_outcomes(
        self,
        *,
        handle: Optional[str] = None,
        limit: int = 500,
    ) -> List[HuntOutcomeRecord]:
        with contextlib.closing(self._connect()) as conn:
            if handle:
                rows = conn.execute(
                    "SELECT * FROM hunt_outcomes WHERE handle = ? ORDER BY discovered_at_utc ASC LIMIT ?",
                    (handle.strip().lower(), max(1, int(limit))),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM hunt_outcomes ORDER BY discovered_at_utc ASC LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
        out: List[HuntOutcomeRecord] = []
        for r in rows:
            feats: Dict[str, Any] = {}
            try:
                parsed = json.loads(str(r["features_json"] or "{}"))
                if isinstance(parsed, dict):
                    feats = parsed
            except Exception:
                feats = {}
            out.append(
                HuntOutcomeRecord(
                    outcome_id=str(r["outcome_id"]),
                    handle=str(r["handle"]),
                    repo=str(r["repo"] or ""),
                    commit_sha=str(r["commit_sha"] or ""),
                    lane=int(r["lane"] or 1),
                    discovered_at_utc=str(r["discovered_at_utc"]),
                    target_age_hours=float(r["target_age_hours"] or 0.0),
                    outcome=str(r["outcome"]),
                    signal_delta=float(r["signal_delta"] or 0.0),
                    bounty_usd=float(r["bounty_usd"] or 0.0),
                    triage_hours_observed=r["triage_hours_observed"],
                    cycle_id=str(r["cycle_id"] or ""),
                    features=feats,
                )
            )
        return out

    # --- Account Signal State & Daily Submission Pacing ---

    def get_account_state(self) -> AccountSignalState:
        with contextlib.closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM account_state WHERE id = 1").fetchone()
        if row is None:
            return AccountSignalState()
        return AccountSignalState(
            signal_established=bool(row["signal_established"]),
            signal_score=float(row["signal_score"]) if row["signal_score"] is not None else None,
            trial_reports_remaining=int(row["trial_reports_remaining"] or 0),
            daily_submissions_count=int(row["daily_submissions_count"] or 0),
            daily_submissions_date_utc=str(row["daily_submissions_date_utc"] or ""),
            updated_at_utc=str(row["updated_at_utc"] or ""),
        )

    def update_account_state(
        self,
        *,
        signal_established: Optional[bool] = None,
        signal_score: Optional[float] = None,
        trial_reports_remaining: Optional[int] = None,
        now: Optional[datetime] = None,
    ) -> AccountSignalState:
        cur = self.get_account_state()
        eff_est = cur.signal_established if signal_established is None else bool(signal_established)
        eff_sig = cur.signal_score if signal_score is None else float(signal_score)
        if eff_sig is not None and signal_established is None:
            eff_est = True
        eff_trials = cur.trial_reports_remaining if trial_reports_remaining is None else max(0, int(trial_reports_remaining))
        ts_iso = _utc_now(now).isoformat()
        with contextlib.closing(self._connect()) as conn:
            with conn:
                conn.execute(
                    """
                    UPDATE account_state
                    SET signal_established = ?,
                        signal_score = ?,
                        trial_reports_remaining = ?,
                        updated_at_utc = ?
                    WHERE id = 1
                    """,
                    (1 if eff_est else 0, eff_sig, eff_trials, ts_iso),
                )
        return self.get_account_state()

    def can_submit_today(self, *, max_per_day: int = 2, now: Optional[datetime] = None) -> Tuple[bool, int]:
        """Returns `(allowed, remaining_slots)` enforcing safe daily submission pacing."""
        cap = max(1, int(max_per_day))
        today = _utc_now(now).strftime("%Y-%m-%d")
        st = self.get_account_state()
        used = st.daily_submissions_count if st.daily_submissions_date_utc == today else 0
        rem = max(0, cap - used)
        return rem > 0, rem

    def record_daily_submission(self, *, count: int = 1, now: Optional[datetime] = None) -> AccountSignalState:
        ts = _utc_now(now)
        today = ts.strftime("%Y-%m-%d")
        st = self.get_account_state()
        new_count = (st.daily_submissions_count if st.daily_submissions_date_utc == today else 0) + max(1, int(count))
        with contextlib.closing(self._connect()) as conn:
            with conn:
                conn.execute(
                    """
                    UPDATE account_state
                    SET daily_submissions_count = ?,
                        daily_submissions_date_utc = ?,
                        updated_at_utc = ?
                    WHERE id = 1
                    """,
                    (new_count, today, ts.isoformat()),
                )
        return self.get_account_state()

    def seed_observed_hackerone_baseline(self, *, now: Optional[datetime] = None) -> Dict[str, int]:
        """Seeds the database with live browser-verified HackerOne program eligibility states."""
        unlocked_entries: Sequence[Tuple[str, int, int, str, str]] = (
            (
                "amazonvrp",
                200,
                30000,
                "GenAI Apps under *.amazon.*, *.amazon.com, primevideo.com/*, amazongames.com, amazonpay.in, Shopping/Alexa/Kindle apps (AWS OOS)",
                "Verified UNLOCKED on /reports/new (no Signal modal).",
            ),
            (
                "temu",
                500,
                25000,
                "www.temu.com, ads.temu.com, partner.temu.com, seller.temu.com, Android com.einnovation.temu, iOS 1641486558",
                "Verified UNLOCKED on /reports/new (no Signal modal).",
            ),
            (
                "common_codes",
                100,
                15000,
                "d-you App & German EUDI Wallet Ecosystem: wallet-backend-sandbox.apps.sandbox.nwb.youniqx.com (/status-lists, /v1/mdvm, /v1/pns, /v1/rwsca, /v1/wpb), Android/iOS Test apps",
                "Verified UNLOCKED on /reports/new (no Signal modal).",
            ),
            (
                "anthropic",
                100,
                10000,
                "github.com/anthropics/* (non-archived/non-fork), claude-code, claude-code-action, Python/TS Agent SDKs, Claude Desktop Extensions/MCP",
                "Verified UNLOCKED on /reports/new (no Signal modal).",
            ),
            (
                "oppo_bbp",
                1,
                3200,
                "OPPO / ColorOS / Android apps (com.coloros.*, com.heytap.*, com.oplus.*, com.oppo.*) — 94% response efficiency, launched 02/2025",
                "Verified UNLOCKED on /reports/new (no Signal modal).",
            ),
            (
                "henkel_vdp",
                0,
                0,
                "VDP (Fast Signal): 215 Wildcards + 60 Domains, 100% response efficiency, Gold Standard, launched 12/2025",
                "Verified UNLOCKED VDP on /reports/new (100% response efficiency, fastest Signal lift).",
            ),
            (
                "anthropic-cyber-jailbreak",
                0,
                0,
                "VDP (Fast Signal): 5 AI Models, 100% response efficiency, launched 06/2026",
                "Verified UNLOCKED VDP on /reports/new (100% response efficiency).",
            ),
            (
                "servicenow-disclosure",
                0,
                0,
                "VDP (Fast Signal): High (>=80%) response efficiency, 282 resolved",
                "Verified UNLOCKED VDP on /reports/new.",
            ),
            (
                "ruby",
                0,
                0,
                "github.com/ruby/ruby (VDP / non-monetary as of June 2026)",
                "Verified UNLOCKED on /reports/new (non-monetary VDP).",
            ),
            (
                "deptofdefense",
                0,
                0,
                "VDP (Fast Signal): 99% response efficiency, 32,168 resolved, publicly accessible DoD web/info systems",
                "Verified UNLOCKED VDP on /reports/new (99% response efficiency).",
            ),
            (
                "ibm",
                0,
                0,
                "VDP (Fast Signal): 71% response efficiency, 5,465 resolved, IBM Websites (*.ibm.com), IBM Tokens & Secrets, IBM Products",
                "Verified UNLOCKED VDP on /reports/new (covers IBM Products & *.ibm.com).",
            ),
            (
                "rails",
                0,
                0,
                "VDP (Fast Signal): 96% response efficiency, ~15h first response, source code under https://github.com/rails (non-monetary post-Mar 2026 IBB)",
                "Verified UNLOCKED on /reports/new (96% response efficiency, fastest Signal lift).",
            ),
        )
        for handle, bmin, bmax, scope, notes in unlocked_entries:
            self.upsert(
                handle,
                "UNLOCKED",
                bounty_min_usd=bmin,
                bounty_max_usd=bmax,
                scope_summary=scope,
                notes=notes,
                now=now,
            )

        blocked_signal: Sequence[Tuple[str, float]] = (
            ("shopify", 1.0),
            ("vercel", 1.0),
            ("cloudflare", 1.0),
            ("github", 1.0),
            ("gitlab", 1.0),
            ("arc-bbp", 3.0),
            ("chainlink", 1.0),
            ("kubernetes", -1.0),
            ("netflix", 0.0),
            ("coinbase", 1.0),
            ("automattic", 0.0),
            ("stripe", 1.0),
            ("notion", 0.0),
            ("toolsforhumanity", 1.0),
            ("chia_network", 1.0),
            ("twilio", 1.0),
            ("circle-bbp", 1.0),
            ("privy-bbp", 1.0),
            ("omarchy", 0.0),
            ("northerntechhq", 4.0),
            ("gocardless_bbp", 1.0),
            ("tron_dao", 1.0),
            ("matomo", 1.0),
            ("doppler", 1.0),
            ("basecamp", 1.0),
            ("airtable", 1.0),
            ("okg", 1.0),
            ("moonpay", 1.0),
            ("exodus", 1.0),
            ("valve", 1.0),
            ("uber", 0.0),
            ("paypal", 0.0),
            ("live_nation", 3.0),
            ("coupang", 1.0),
            ("superhuman", 5.0),
            ("agoda-public", 1.0),
            ("box_private", 1.0),
            ("crypto", -1.0),
            ("eero", 0.0),
            ("ring", 0.0),
            ("snapchat", 0.0),
            ("walt_io", 0.0),
            ("figma", 0.0),
            ("files", 1.0),
            ("airbnb", 1.0),
            ("coinspot", 1.0),
            ("bitmex", 1.0),
            ("ui", 1.0),
            ("8x8-bounty", 3.0),
            ("playstation", 1.0),
            ("priceline", 0.0),
            ("deribit", 0.0),
            ("wolt", 1.0),
            ("coupang_tw", 1.0),
            ("slack", 3.0),
            ("nextcloud", 1.0),
            ("deriv", 2.0),
            ("wordpress", 1.0),
            ("ibb", 1.0),
            ("discourse", 0.0),
            ("coinmate", 0.0),
            ("nintendo", 0.0),
            ("spotify", 2.0),
            ("reddit", 1.0),
            ("wickr", 0.0),
            ("anduril_industries", 1.0),
            ("netscaler_public_program", 0.0),
            ("vodafone_oman", 0.0),
            ("gcash_vdp", 0.0),
            ("smartsheet_vdp", 0.0),
            ("xp_inc_vdp", 0.0),
            ("verisk_vdp", 0.0),
            ("aegean_airlines_vdp", 0.0),
            ("coindcx_vdp", 0.0),
            ("nebius_ai_vdp", 0.0),
            ("semtech", 0.0),
            ("vanguard", 0.0),
            ("essity", 0.0),
            ("prism_vdp", 0.0),
            ("discover-vdp", 0.0),
            ("epicgames-vdp", 0.0),
            ("gogo_vdp", 0.0),
            ("cognition", 0.0),
            ("mcgrawhill", 0.0),
            ("taxwell-vdp", 0.0),
            ("1win_com", 0.0),
            ("luminor", 0.0),
            ("clear_street_vdp", 0.0),
            ("getyourguide_vdp", 0.0),
            ("whatnot", 0.0),
            ("mod_supply_chain_vdp", 0.0),
            ("vodafone", 0.0),
            ("bose_vdp", 0.0),
            ("dailypay_vdp", 0.0),
            ("mufg-vdp", 0.0),
            ("bankunited", 0.0),
            ("fanduel-vdp", 0.0),
            ("mueller_water_products_vdp", 0.0),
            ("lovable-vdp", 0.0),
            ("baird_vdp", 0.0),
            ("kaseya", 0.0),
            ("hack_the_box", 0.0),
            ("tucows_vdp", 0.0),
            ("ferrero", 0.0),
            ("experian", 0.0),
            ("unico_idtech", 0.0),
            ("banco_plata", 0.0),
            ("stripchat", 0.0),
            ("ripio", 0.0),
            ("braze_inc", 0.0),
            ("audible", 0.0),
            ("zooplus", 0.0),
            ("fiserv", 0.0),
            ("autodesk", 0.0),
            ("liverpool_victoria", 0.0),
            ("peloton", 0.0),
            ("dib-vdp", 0.0),
            ("transunion", 0.0),
            ("aon", 0.0),
            ("oaknorth_bank", 0.0),
            ("wellhive", 0.0),
            ("cbre", 0.0),
            ("abn_amro_vdp", 0.0),
            ("aven_response", 0.0),
            ("fresenius", 0.0),
            ("latamairlines", 0.0),
            ("hexagon_vdp", 0.0),
            ("qinetiq", 0.0),
            ("tbs-sct", 0.0),
            ("clear", 0.0),
            ("phonepe_vdp", 0.0),
            ("curl", 0.0),
            ("bitwarden", 1.0),
            ("supabase", 1.0),
            ("databricks", 0.0),
            ("elastic", 1.0),
            ("mongodb", 6.0),
            ("crowdstrike", 0.0),
            ("tenable", 0.0),
            ("tomtom", 0.0),
            ("nutanix", -1.0),
            ("sony", 0.0),
            ("us-department-of-state", 0.0),
            ("city_of_los_angeles_vdp", 0.0),
            ("nodejs", 1.0),
            ("torproject", 0.0),
            ("concretecms", 0.0),
            ("rubygems", 1.0),
            ("revive_adserver", 1.0),
            ("phabricator", 0.0),
            ("duckduckgo", 0.0),
            ("att", 1.0),
            ("gm", 0.0),
            ("expediagroup", 0.0),
            ("mtn_group", 0.0),
            ("tiktok", 0.0),
            ("grammarly", 5.0),
            ("doordash", 0.0),
            ("linkedin", 1.0),
            ("instacart", 1.0),
            ("pfizer", 0.0),
            ("marriott", 1.0),
            ("hyatt", 1.0),
            ("toyota", 0.0),
        )
        for handle, sig in blocked_signal:
            self.upsert(
                handle,
                "BLOCKED_SIGNAL",
                signal_required=sig,
                signal_established_required=bool(sig >= 0.0),
                notes=f"Blocked by Signal Requirement ({sig}) / No trial reports left.",
                now=now,
            )

        for handle in (
            "mozilla",
            "brave",
            "django",
            "rocket_chat",
            "mattermost",
            "1password",
            "gsa_bbp",
            "nodejs-ecosystem",
            "fastify",
            "pyca",
            "mariadb",
            "klarna",
        ):
            self.upsert(handle, "PAUSED", submission_state="paused", notes="Program currently paused on HackerOne.", now=now)

        for handle in (
            "openai",
            "huggingface",
            "linear",
            "perplexity",
            "yahoo",
            "dropbox",
            "zoom",
            "adyen",
            "kong",
            "snowflake",
            "govtech",
            "tts",
            "siemens",
            "open-xchange",
            "perl",
            "litellm",
            "neon",
            "php",
            "openssl",
            "nginx",
            "adobe",
            "chime",
            "wikimedia",
            "sentry",
            "hashicorp",
            "okta",
            "nike",
            "workday",
            "intuit",
            "novartis",
            "walmart",
            "deutsche_telekom",
            "dell",
            "hp",
            "ericsson",
            "siemens_energy",
            "bosch",
            "volkswagen",
            "allianz",
            "honda",
        ):
            self.upsert(handle, "NOT_FOUND", submission_state="disabled", notes="404 / Not on HackerOne public handle.", now=now)

        return self.summary_counts()
