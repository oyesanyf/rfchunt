"""
SQLite Program Eligibility & Signal-Requirement Registry (`engine/program_eligibility_db.py`).
=============================================================================================
Persists HackerOne / bug bounty program eligibility statuses (`UNLOCKED`, `BLOCKED_SIGNAL`,
`PAUSED`, `NOT_FOUND`) in a local gitignored SQLite database so threat hunts:
  1. Never waste cycles attempting programs whose Signal Requirement the user does not meet.
  2. Immediately select the highest-payout UNLOCKED programs.
  3. Periodically re-check previously blocked programs (`next_recheck_utc <= now`) to detect
     automatically when Signal / trial-report restrictions are lifted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


DEFAULT_ELIGIBILITY_DB_PATH = (
    Path(__file__).resolve().parent.parent
    / "reports"
    / "ensemble_hunt"
    / "program_eligibility.sqlite3"
)

VALID_STATUSES = frozenset({"UNLOCKED", "BLOCKED_SIGNAL", "PAUSED", "NOT_FOUND"})

DEFAULT_RECHECK_HOURS: Dict[str, int] = {
    "UNLOCKED": 24,
    "BLOCKED_SIGNAL": 48,
    "PAUSED": 168,
    "NOT_FOUND": 336,
}


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _utc_now(now: Optional[datetime] = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


class ProgramEligibilityDB:
    """Thread-safe SQLite store tracking unlocked vs Signal-blocked bounty programs."""

    def __init__(self, db_path: Union[str, Path] = DEFAULT_ELIGIBILITY_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
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
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_program_status_recheck
                ON program_eligibility(status, next_recheck_utc);
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
        )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO program_eligibility (
                    handle, platform, status, signal_required,
                    bounty_min_usd, bounty_max_usd, submit_url,
                    scope_summary, last_checked_utc, next_recheck_utc, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    notes=excluded.notes;
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
                ),
            )
        return rec

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ProgramEligibilityRecord:
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
        )

    def get(self, handle: str) -> Optional[ProgramEligibilityRecord]:
        norm = handle.strip().lower()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM program_eligibility WHERE handle = ?", (norm,)
            ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def is_eligible(self, handle: str) -> bool:
        """Fail-closed eligibility check: returns True ONLY if explicitly UNLOCKED."""
        rec = self.get(handle)
        return rec is not None and rec.status == "UNLOCKED"

    def list_by_status(self, status: str) -> List[ProgramEligibilityRecord]:
        norm = status.strip().upper()
        with self._connect() as conn:
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
        with self._connect() as conn:
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
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM program_eligibility GROUP BY status"
            ).fetchall()
        return {str(r["status"]): int(r["cnt"]) for r in rows}

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
        )
        for handle, sig in blocked_signal:
            self.upsert(
                handle,
                "BLOCKED_SIGNAL",
                signal_required=sig,
                notes=f"Blocked by Signal Requirement ({sig}) / No trial reports left.",
                now=now,
            )

        for handle in ("mozilla", "brave"):
            self.upsert(handle, "PAUSED", notes="Program currently paused on HackerOne.", now=now)

        for handle in ("openai", "huggingface", "linear", "perplexity", "yahoo", "dropbox", "zoom"):
            self.upsert(handle, "NOT_FOUND", notes="404 / Not on HackerOne public handle.", now=now)

        return self.summary_counts()
