"""
ACDSO-Adapted ML HackerOne Program Selector, Survival Model, Generalized Pareto
Frontier, Two-Phase Quota Knapsack & Online Contextual Bandit
(`engine/ml_program_selector.py`).
================================================================================
Self-contained, pure-Python stdlib ML engine (zero cross-repo imports from
`D:\\harfile\\ACDSO`; optional `numpy`/`sklearn`/`lightgbm`/`ortools` acceleration)
designed to select the highest-yield, lowest-saturation public HackerOne VDPs
and paid BBPs faster than competing researchers while strictly obeying platform
Signal gating and per-program Rules of Engagement (RoE).

Core Components (adapted cleanly from ACDSO):
  1. `ProgramFeatureExtractor`   — 12 compact Tier-1 core features + signed-log1p
     skew stabilization + smoothed empirical Bayes yield encoding (Tier-2 adds
     12-dim compressed hashed scope text at n >= 60 to avoid p >> n overfitting).
  2. `classify_program_lane`     — Hard fail-closed `UNLOCKED` + `open` gate,
     >=80% response efficiency filter, Lane 1 Fast-Signal VDP vs Lane 2 Cash BBP.
  3. `ProgramSurvivalModel`      — Adapted ACDSO Cox PH (overflow-free Breslow NLL,
     exact Fenwick-tree Harrell's C-index) estimating un-duplicated survival
     S_fresh(dt | x) over a 72h triage race window.
  4. `ProgramRanker`             — 3-tier sample-size curriculum LTR (Tier 0 cold
     prior -> Tier 1 12-feat L2 pairwise logistic SGD -> Tier 2 full) gated by
     entity-grouped GroupKFold tie-aware NDCG@k.
  5. `ProgramParetoSelector`     — Generalized 6-objective Pareto frontier & chord
     knee-point selector (zero double-log distortion).
  6. `DailyHuntPortfolioOptimizer` — Two-Phase Reserved-Quota Knapsack enforcing
     Lane 1 VDP floor >= ceil(0.5 * capacity) while Signal is unestablished or < 1.0.
  7. `OnlineProgramBandit`       — Pure-Python Disjoint LinUCB (Sherman-Morrison
     updates) + Discounted Beta-Bernoulli Thompson Sampling per program.
"""

from __future__ import annotations

import hashlib
import math
import random
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from engine.acdso_bridge import (
    MultiObjectiveCandidate,
    generalized_pareto_front,
    select_pareto_knee,
)
from engine.program_eligibility_db import (
    AccountSignalState,
    HuntOutcomeRecord,
    ProgramEligibilityDB,
    ProgramEligibilityRecord,
)

TIER1_FEATURE_NAMES: tuple[str, ...] = (
    "freshness_decay",
    "response_efficiency_norm",
    "inv_triage_latency",
    "scope_breadth_log",
    "non_marketing_surface_ratio",
    "saturation_log",
    "bounty_max_log",
    "is_vdp_flag",
    "gold_standard_or_fast_pay",
    "roe_automation_score",
    "roe_rps_log",
    "historical_eb_yield",
)

# Positive/negative outcome reward grades for LTR & bandit learning
OUTCOME_REWARD_MAP: dict[str, float] = {
    "BOUNTY": 1.0,
    "RESOLVED": 0.90,
    "TRIAGED": 0.78,
    "INFORMATIVE": 0.15,
    "DUPLICATE": 0.10,
    "NO_FINDING": 0.05,
    "NA": 0.0,
}

# Cold-start calibrated feature weights by optimization preset
_COLD_PRIOR_WEIGHTS: dict[str, tuple[float, ...]] = {
    "signal_fast": (
        0.22,  # freshness_decay
        0.24,  # response_efficiency_norm
        0.14,  # inv_triage_latency
        0.16,  # scope_breadth_log
        0.14,  # non_marketing_surface_ratio
        -0.16, # saturation_log (lower saturation preferred)
        0.04,  # bounty_max_log
        0.26,  # is_vdp_flag (strong VDP fast-Signal boost)
        0.08,  # gold_standard_or_fast_pay
        0.10,  # roe_automation_score
        0.04,  # roe_rps_log
        0.18,  # historical_eb_yield
    ),
    "bounty_max": (
        0.18,
        0.18,
        0.10,
        0.18,
        0.14,
        -0.15,
        0.28,  # strong cash EV emphasis
        -0.10, # prefer paid BBPs
        0.10,
        0.10,
        0.05,
        0.22,
    ),
    "balanced": (
        0.20,
        0.22,
        0.12,
        0.18,
        0.14,
        -0.16,
        0.16,
        0.08,
        0.09,
        0.10,
        0.05,
        0.20,
    ),
    "safe": (
        0.16,
        0.26,
        0.14,
        0.14,
        0.12,
        -0.14,
        0.10,
        0.14,
        0.16,
        0.18,
        0.04,
        0.20,
    ),
}


def signed_log1p(x: float) -> float:
    """Skew stabilizer adapted from ACDSO `_NumericSkewStabilizer`."""
    f = float(x)
    if not math.isfinite(f):
        return 0.0
    return math.copysign(math.log1p(abs(f)), f)


def _parse_iso_utc(raw: str) -> datetime | None:
    s = str(raw or "").strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        return None


def signed_hash_features(text: str, *, dim: int = 12) -> list[float]:
    """Stateless signed SHA-256 feature hashing of word & bigram tokens (zero external deps)."""
    d = max(1, int(dim))
    vec = [0.0] * d
    tokens = re.findall(r"[a-z0-9_./*-]{2,}", (text or "").lower())
    if not tokens:
        return vec
    grams: list[str] = list(tokens[:120])
    for i in range(min(len(tokens) - 1, 80)):
        grams.append(f"{tokens[i]}|{tokens[i + 1]}")
    for g in grams:
        digest = hashlib.sha256(g.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:4], "little") % d
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        vec[bucket] += sign
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 1e-12:
        vec = [v / norm for v in vec]
    return vec


# ---------------------------------------------------------------------------
# 1. Feature Extraction & Lane Classification
# ---------------------------------------------------------------------------


def compute_empirical_bayes_yield(
    outcomes: Sequence[HuntOutcomeRecord],
    *,
    smoothing_m: float = 5.0,
) -> tuple[dict[str, float], dict[int, float]]:
    """
    Smoothed empirical Bayes target encoding of program yield (adapted from ACDSO
    `auto_preprocessing.TargetEncoder`): `(sum_y + m * prior) / (n + m)`.
    """
    lane_sums: dict[int, float] = {1: 0.0, 2: 0.0}
    lane_cnts: dict[int, int] = {1: 0, 2: 0}
    prog_sums: dict[str, float] = {}
    prog_cnts: dict[str, int] = {}
    prog_lane: dict[str, int] = {}

    for o in outcomes:
        y = OUTCOME_REWARD_MAP.get(o.outcome.upper(), 0.1)
        ln = 1 if int(o.lane) == 1 else 2
        lane_sums[ln] += y
        lane_cnts[ln] += 1
        h = o.handle.strip().lower()
        prog_sums[h] = prog_sums.get(h, 0.0) + y
        prog_cnts[h] = prog_cnts.get(h, 0) + 1
        prog_lane[h] = ln

    lane_priors: dict[int, float] = {
        1: (lane_sums[1] / lane_cnts[1]) if lane_cnts[1] > 0 else 0.55,
        2: (lane_sums[2] / lane_cnts[2]) if lane_cnts[2] > 0 else 0.45,
    }
    eb_by_handle: dict[str, float] = {}
    for h, s in prog_sums.items():
        n = prog_cnts[h]
        prior = lane_priors[prog_lane.get(h, 1)]
        eb_by_handle[h] = (s + smoothing_m * prior) / (n + smoothing_m)
    return eb_by_handle, lane_priors


def classify_program_lane(
    rec: ProgramEligibilityRecord,
    *,
    min_efficiency_pct: float = 80.0,
) -> tuple[str, str]:
    """
    Fail-closed HackerOne lane classifier:
      - `BLOCKED` if not `UNLOCKED` or `submission_state != 'open'`
      - `DEFERRED_LOW_EFFICIENCY` if `response_efficiency_pct < min_efficiency_pct`
      - `LANE_1_VDP_FAST_SIGNAL` for non-monetary VDPs (reputation/Signal lift)
      - `LANE_2_BBP_HIGH_EV` for paid public bug bounty programs
    """
    if rec.status != "UNLOCKED":
        return "BLOCKED", f"status={rec.status}"
    if (rec.submission_state or "open").strip().lower() != "open":
        return "BLOCKED", f"submission_state={rec.submission_state}"
    if rec.response_efficiency_pct is not None and float(rec.response_efficiency_pct) < float(min_efficiency_pct):
        return (
            "DEFERRED_LOW_EFFICIENCY",
            f"response_efficiency={rec.response_efficiency_pct:.1f}% < {min_efficiency_pct:.0f}%",
        )
    is_paid = bool(rec.offers_bounties or (rec.bounty_max_usd is not None and int(rec.bounty_max_usd) > 0))
    if rec.is_vdp and not is_paid:
        return "LANE_1_VDP_FAST_SIGNAL", "unlocked_vdp_fast_signal"
    if not is_paid:
        return "LANE_1_VDP_FAST_SIGNAL", "unlocked_non_monetary_vdp"
    return "LANE_2_BBP_HIGH_EV", "unlocked_paid_bbp"


def compute_unlock_distance(
    rec: ProgramEligibilityRecord,
    account_state: AccountSignalState,
) -> dict[str, Any]:
    """
    Computes exact unlock distance accounting for unestablished Signal (`signal_score=None`):
    On a new HackerOne account with `signal_established=False` and `trial_reports_remaining=0`,
    even `signal_required=0.0` is STILL blocked and requires 1-2 valid VDP reports first.
    """
    if rec.status == "UNLOCKED":
        return {"unlocked": True, "distance": 0.0, "estimated_vdp_reports_needed": 0, "reason": "unlocked"}
    if rec.status in ("PAUSED", "NOT_FOUND"):
        return {"unlocked": False, "distance": 99.0, "estimated_vdp_reports_needed": 99, "reason": f"status={rec.status}"}

    sig_req = float(rec.signal_required) if rec.signal_required is not None else 0.0
    if not account_state.signal_established:
        if sig_req <= 0.0:
            est_reports = 1 if account_state.trial_reports_remaining == 0 else 0
            return {
                "unlocked": False,
                "distance": 1.0,
                "estimated_vdp_reports_needed": max(1, est_reports),
                "reason": "unestablished_signal_requires_initial_vdp_triage",
            }
        return {
            "unlocked": False,
            "distance": 1.0 + sig_req,
            "estimated_vdp_reports_needed": max(2, math.ceil(1.0 + sig_req)),
            "reason": f"unestablished_signal_and_min_{sig_req}",
        }

    cur_sig = float(account_state.signal_score or 0.0)
    gap = max(0.0, sig_req - cur_sig)
    return {
        "unlocked": gap <= 0.0,
        "distance": round(gap, 3),
        "estimated_vdp_reports_needed": math.ceil(gap),
        "reason": "signal_gap" if gap > 0.0 else "ready_for_recheck",
    }


@dataclass
class ExtractedProgramFeatures:
    handle: str
    lane: str
    lane_reason: str
    tier1_vector: list[float]
    tier2_text_vector: list[float]
    feature_map: dict[str, float]
    launch_age_days: float
    total_assets: int
    estimated_scan_minutes: float


class ProgramFeatureExtractor:
    """Extracts leak-free, skew-stabilized 12-dim Tier 1 (+ 12-dim Tier 2) program vectors."""

    def __init__(
        self,
        outcomes: Sequence[HuntOutcomeRecord] = (),
        *,
        now: datetime | None = None,
    ) -> None:
        self.now = now.astimezone(UTC) if now is not None else datetime.now(UTC)
        self.eb_by_handle, self.lane_priors = compute_empirical_bayes_yield(outcomes)

    def extract(
        self,
        rec: ProgramEligibilityRecord,
        *,
        min_efficiency_pct: float = 80.0,
    ) -> ExtractedProgramFeatures:
        lane, lane_reason = classify_program_lane(rec, min_efficiency_pct=min_efficiency_pct)

        # 1. Freshness decay from launch date (newest launches boosted)
        launch_dt = _parse_iso_utc(rec.launched_at_utc)
        if launch_dt is not None:
            launch_age_days = max(1.0, (self.now - launch_dt).total_seconds() / 86400.0)
            freshness_decay = math.exp(-launch_age_days / 180.0)
        else:
            launch_age_days = 365.0
            freshness_decay = 0.25

        # 2. Response efficiency normalized [0, 1]
        resp_eff = (float(rec.response_efficiency_pct) / 100.0) if rec.response_efficiency_pct is not None else 0.65

        # 3. Inverse triage / first-response latency
        first_resp_h = float(rec.first_response_hours) if rec.first_response_hours is not None else 48.0
        inv_triage_latency = 1.0 / (1.0 + math.log1p(max(0.5, first_resp_h)))

        # 4 & 5. Scope breadth (skew-stabilized) + non-marketing surface ratio
        wc = max(0, int(rec.wildcard_count))
        dom = max(0, int(rec.domain_count))
        api = max(0, int(rec.api_asset_count))
        mob = max(0, int(rec.mobile_asset_count))
        src = max(0, int(rec.source_repo_count))
        ai = max(0, int(rec.ai_asset_count))
        total_assets = max(1, wc + dom + api + mob + src + ai)
        weighted_surface = 3.0 * wc + 2.5 * api + 2.0 * mob + 2.5 * src + 2.0 * ai + 1.0 * dom
        scope_breadth_log = signed_log1p(weighted_surface) / 6.5  # scaled roughly [0, 1.2]
        non_marketing_ratio = (wc + api + mob + src + ai) / float(total_assets)

        # 6. Saturation proxy: resolved reports per asset-month (lower = less saturated)
        months_active = max(1.0, launch_age_days / 30.0)
        resolved = max(0, int(rec.resolved_count))
        saturation_log = signed_log1p(resolved / max(1.0, float(total_assets) * months_active))

        # 7. Bounty ceiling log (scaled)
        b_max = max(0, int(rec.bounty_max_usd or 0))
        bounty_max_log = signed_log1p(float(b_max)) / 10.5

        # 8. VDP flag
        is_vdp_flag = 1.0 if (rec.is_vdp and not rec.offers_bounties and b_max == 0) else 0.0

        # 9. Gold standard / fast payments
        gold_fast = (0.5 if rec.gold_standard else 0.0) + (0.5 if rec.fast_payments else 0.0)

        # 10 & 11. RoE automation compatibility & RPS headroom
        if rec.roe_automated_prohibited:
            roe_auto_score = 0.60 if src > 0 else 0.0
        elif rec.roe_automation_tier == "permitted_with_limits_and_attribution":
            roe_auto_score = 1.0
        else:
            roe_auto_score = 0.85
        roe_rps_log = signed_log1p(max(0.0, float(rec.roe_max_rps))) / 4.6

        # 12. Smoothed empirical Bayes historical yield
        lane_num = 1 if is_vdp_flag >= 0.5 else 2
        eb_yield = self.eb_by_handle.get(rec.handle.lower(), self.lane_priors.get(lane_num, 0.5))

        t1 = [
            freshness_decay,
            resp_eff,
            inv_triage_latency,
            scope_breadth_log,
            non_marketing_ratio,
            saturation_log,
            bounty_max_log,
            is_vdp_flag,
            gold_fast,
            roe_auto_score,
            roe_rps_log,
            eb_yield,
        ]
        fmap = {name: round(val, 6) for name, val in zip(TIER1_FEATURE_NAMES, t1)}
        t2_text = signed_hash_features(f"{rec.scope_summary} {rec.notes}", dim=12)

        # Estimated scan cost in minutes for knapsack ROI budgeting
        est_minutes = 8.0 + min(25.0, 2.5 * src + 1.5 * api + 0.05 * wc + 2.0 * mob + 1.5 * ai)

        return ExtractedProgramFeatures(
            handle=rec.handle,
            lane=lane,
            lane_reason=lane_reason,
            tier1_vector=t1,
            tier2_text_vector=t2_text,
            feature_map=fmap,
            launch_age_days=round(launch_age_days, 2),
            total_assets=total_assets,
            estimated_scan_minutes=round(est_minutes, 2),
        )


# ---------------------------------------------------------------------------
# 2. Anti-Saturation Cox Survival Model (adapted from ACDSO survival.py)
# ---------------------------------------------------------------------------


def concordance_index(
    times: Sequence[float],
    events: Sequence[int],
    risk_scores: Sequence[float],
) -> float:
    """
    O(n log n) Harrell's Concordance Index (C-index) using a Fenwick (Binary Indexed)
    tree, adapted from ACDSO `survival.py`. Higher risk_score predicts shorter time-to-event.
    """
    n = min(len(times), len(events), len(risk_scores))
    if n < 2:
        return 0.5

    # Compress risk_scores to 1-based ranks
    uniq_scores = sorted({float(risk_scores[i]) for i in range(n)})
    rank_of = {val: idx + 1 for idx, val in enumerate(uniq_scores)}
    m = len(uniq_scores)

    bit = [0] * (m + 1)

    def _add(idx: int, delta: int) -> None:
        while idx <= m:
            bit[idx] += delta
            idx += idx & -idx

    def _sum(idx: int) -> int:
        s = 0
        while idx > 0:
            s += bit[idx]
            idx -= idx & -idx
        return s

    # Sort descending by time so previously inserted items have time_j > time_i
    order = sorted(range(n), key=lambda i: -float(times[i]))
    concordant = 0.0
    comparable = 0.0
    i = 0
    total_inserted = 0
    while i < n:
        t_cur = float(times[order[i]])
        j = i
        while j < n and float(times[order[j]]) == t_cur:
            j += 1
        # Evaluate all uncensored events in this time tie-group against strictly later items
        for k in range(i, j):
            idx = order[k]
            if int(events[idx]) == 1 and total_inserted > 0:
                r = rank_of[float(risk_scores[idx])]
                strictly_less = _sum(r - 1)
                le = _sum(r)
                tied = le - strictly_less
                concordant += strictly_less + 0.5 * tied
                comparable += total_inserted
        # Insert tie-group into Fenwick tree
        for k in range(i, j):
            idx = order[k]
            _add(rank_of[float(risk_scores[idx])], 1)
            total_inserted += 1
        i = j

    return (concordant / comparable) if comparable > 0.0 else 0.5


class ProgramSurvivalModel:
    """
    Cox Proportional Hazards anti-saturation model predicting S_fresh(dt | x) =
    probability a program / fresh target remains un-duplicated across a 72h triage window.
    Cold-start analytical prior -> L2 Breslow partial-likelihood refit when n >= 20.
    """

    # Higher hazard eta -> faster saturation / higher duplicate risk
    _COLD_BETA: tuple[float, ...] = (
        -0.95,  # freshness_decay (newer -> lower saturation hazard)
        -0.15,  # response_efficiency_norm (faster triage -> lower duplicate collision)
        -0.25,  # inv_triage_latency
        -0.45,  # scope_breadth_log (wider scope -> less crowding per asset)
        -0.30,  # non_marketing_surface_ratio
        0.85,   # saturation_log (higher historical density -> higher hazard)
        0.55,   # bounty_max_log (big cash bounties attract elite hunters)
        -0.55,  # is_vdp_flag (fewer top hunters compete on VDPs)
        -0.10,  # gold_standard_or_fast_pay
        0.0,    # roe_automation_score
        0.0,    # roe_rps_log
        -0.20,  # historical_eb_yield
    )

    def __init__(self, *, l2: float = 1.0) -> None:
        self.l2 = max(1e-3, float(l2))
        self.beta: list[float] = list(self._COLD_BETA)
        self.baseline_h0_72h: float = 0.35
        self.fitted_on_outcomes: bool = False
        self.c_index_cv: float = 0.5

    @staticmethod
    def _breslow_nll_and_grad(
        beta: Sequence[float],
        X: Sequence[Sequence[float]],
        times: Sequence[float],
        events: Sequence[int],
        l2: float,
    ) -> tuple[float, list[float]]:
        n = len(X)
        d = len(beta)
        order = sorted(range(n), key=lambda i: -float(times[i]))
        etas = [
            max(-20.0, min(20.0, sum(beta[j] * X[i][j] for j in range(d))))
            for i in range(n)
        ]
        max_eta = max(etas) if etas else 0.0
        exp_e = [math.exp(e - max_eta) for e in etas]

        nll = 0.0
        grad = [0.0] * d
        risk_sum = 0.0
        weighted_x = [0.0] * d

        k = 0
        while k < n:
            t_cur = float(times[order[k]])
            k2 = k
            while k2 < n and float(times[order[k2]]) == t_cur:
                idx = order[k2]
                w = exp_e[idx]
                risk_sum += w
                for j in range(d):
                    weighted_x[j] += w * X[idx][j]
                k2 += 1
            d_events = 0
            sum_x_ev = [0.0] * d
            sum_eta_ev = 0.0
            for m in range(k, k2):
                idx = order[m]
                if int(events[idx]) == 1:
                    d_events += 1
                    sum_eta_ev += etas[idx]
                    for j in range(d):
                        sum_x_ev[j] += X[idx][j]
            if d_events > 0 and risk_sum > 0.0:
                log_rs = math.log(risk_sum) + max_eta
                nll += d_events * log_rs - sum_eta_ev
                for j in range(d):
                    grad[j] += d_events * (weighted_x[j] / risk_sum) - sum_x_ev[j]
            k = k2

        inv_n = 1.0 / max(1, n)
        nll = nll * inv_n + 0.5 * l2 * sum(b * b for b in beta)
        grad = [g * inv_n + l2 * beta[j] for j, g in enumerate(grad)]
        return nll, grad

    def fit(
        self,
        X: Sequence[Sequence[float]],
        times: Sequence[float],
        events: Sequence[int],
    ) -> ProgramSurvivalModel:
        """Fits L2 Breslow Cox PH when n >= 20 and >= 2 duplicate events exist."""
        n = min(len(X), len(times), len(events))
        if n < 20 or sum(1 for e in events[:n] if int(e) == 1) < 2:
            self.fitted_on_outcomes = False
            return self

        d = len(X[0])
        beta = list(self._COLD_BETA[:d])
        if len(beta) < d:
            beta.extend([0.0] * (d - len(beta)))

        lr = 0.15
        cur_nll, grad = self._breslow_nll_and_grad(beta, X[:n], times[:n], events[:n], self.l2)
        for _ in range(45):
            cand = [beta[j] - lr * grad[j] for j in range(d)]
            cand_nll, cand_grad = self._breslow_nll_and_grad(cand, X[:n], times[:n], events[:n], self.l2)
            if cand_nll <= cur_nll:
                beta, cur_nll, grad = cand, cand_nll, cand_grad
                lr = min(0.4, lr * 1.1)
            else:
                lr *= 0.5
                if lr < 1e-4:
                    break

        risk_fitted = [sum(beta[j] * X[i][j] for j in range(d)) for i in range(n)]
        risk_prior = [sum(self._COLD_BETA[j] * X[i][j] for j in range(min(d, len(self._COLD_BETA)))) for i in range(n)]
        c_fit = concordance_index(times[:n], events[:n], risk_fitted)
        c_prior = concordance_index(times[:n], events[:n], risk_prior)
        if c_fit >= c_prior:
            # Smooth shrinkage blend with cold prior
            alpha = min(1.0, n / 50.0)
            self.beta = [
                alpha * beta[j] + (1.0 - alpha) * (self._COLD_BETA[j] if j < len(self._COLD_BETA) else 0.0)
                for j in range(d)
            ]
            self.fitted_on_outcomes = True
            self.c_index_cv = round(c_fit, 4)
        else:
            self.fitted_on_outcomes = False
            self.c_index_cv = round(c_prior, 4)
        return self

    def predict_fresh_survival(self, feature_vec: Sequence[float], *, window_hours: float = 72.0) -> float:
        """Returns S_fresh(window_hours | x) in [0.05, 0.99]: higher = less likely to collide with a duplicate."""
        d = min(len(self.beta), len(feature_vec))
        eta = sum(self.beta[j] * float(feature_vec[j]) for j in range(d))
        eta = max(-5.0, min(5.0, eta))
        h0 = self.baseline_h0_72h * (max(1.0, float(window_hours)) / 72.0)
        surv = math.exp(-h0 * math.exp(eta))
        return max(0.05, min(0.99, surv))


# ---------------------------------------------------------------------------
# 3. 3-Tier Curriculum Learning-to-Rank (adapted from ACDSO ranking.py)
# ---------------------------------------------------------------------------


def ndcg_at_k(y_true: Sequence[float], y_score: Sequence[float], k: int = 10) -> float:
    """Tie-aware exponential-gain NDCG@k adapted from ACDSO `ranking.py`."""
    n = min(len(y_true), len(y_score))
    if n == 0:
        return 0.0
    kk = min(max(1, int(k)), n)

    # Ideal DCG
    ideal = sorted((float(y_true[i]) for i in range(n)), reverse=True)[:kk]
    idcg = sum(((2.0 ** rel) - 1.0) / math.log2(pos + 2.0) for pos, rel in enumerate(ideal))
    if idcg <= 0.0:
        return 0.0

    # Group by tied scores and average true relevance within tie groups (tie-aware)
    order = sorted(range(n), key=lambda i: -float(y_score[i]))
    dcg = 0.0
    pos = 0
    while pos < kk:
        s_val = float(y_score[order[pos]])
        end = pos + 1
        while end < n and abs(float(y_score[order[end]]) - s_val) <= 1e-12:
            end += 1
        avg_rel = sum(float(y_true[order[idx]]) for idx in range(pos, end)) / float(end - pos)
        for p in range(pos, min(end, kk)):
            dcg += ((2.0 ** avg_rel) - 1.0) / math.log2(p + 2.0)
        pos = end
    return dcg / idcg


class ProgramRanker:
    """
    3-Tier Sample-Size Curriculum Learning-to-Rank (eliminating p >> n overfitting):
      - Tier 0 (n < 15):  Transparent domain-calibrated linear prior.
      - Tier 1 (15 <= n < 60): Compact 12-feature L2 pairwise logistic SGD, shrunk
        with Tier 0 via w(n) = n / (n + 25), promoted ONLY if GroupKFold CV beats Tier 0.
      - Tier 2 (n >= 60): Adds 12-dim compressed hashed scope text features, also
        gated by entity-grouped GroupKFold NDCG@5.
    """

    def __init__(self, *, preset: str = "balanced", l2: float = 1.0) -> None:
        self.preset = preset if preset in _COLD_PRIOR_WEIGHTS else "balanced"
        self.l2 = max(0.05, float(l2))
        self.tier_active: int = 0
        self.weights: list[float] = list(_COLD_PRIOR_WEIGHTS[self.preset])
        self.cv_ndcg_prior: float = 0.0
        self.cv_ndcg_learned: float = 0.0

    @staticmethod
    def _fit_pairwise_sgd(
        X: Sequence[Sequence[float]],
        y: Sequence[float],
        *,
        l2: float = 1.0,
        steps: int = 60,
        lr: float = 0.25,
    ) -> list[float]:
        n = min(len(X), len(y))
        if n < 2:
            return []
        d = len(X[0])
        pairs: list[tuple[list[float], float]] = []
        for i in range(n):
            for j in range(i + 1, n):
                diff_y = float(y[i]) - float(y[j])
                if abs(diff_y) < 0.05:
                    continue
                sign = 1.0 if diff_y > 0.0 else -1.0
                dx = [float(X[i][k]) - float(X[j][k]) for k in range(d)]
                pairs.append((dx, sign))
        if not pairs:
            return [0.0] * d

        w = [0.0] * d
        inv_p = 1.0 / float(len(pairs))
        for _ in range(steps):
            grad = [0.0] * d
            for dx, sign in pairs:
                margin = max(-20.0, min(20.0, sign * sum(w[k] * dx[k] for k in range(d))))
                prob_err = 1.0 / (1.0 + math.exp(margin))
                coef = -sign * prob_err * inv_p
                for k in range(d):
                    grad[k] += coef * dx[k]
            for k in range(d):
                w[k] -= lr * (grad[k] + l2 * w[k])
        return w

    def fit_from_outcomes(
        self,
        extracted_by_handle: dict[str, ExtractedProgramFeatures],
        outcomes: Sequence[HuntOutcomeRecord],
    ) -> ProgramRanker:
        rows_x1: list[list[float]] = []
        rows_x2: list[list[float]] = []
        rows_y: list[float] = []
        rows_groups: list[str] = []

        for o in outcomes:
            ef = extracted_by_handle.get(o.handle.lower())
            if ef is None:
                continue
            rows_x1.append(list(ef.tier1_vector))
            rows_x2.append(list(ef.tier1_vector) + list(ef.tier2_text_vector))
            rows_y.append(OUTCOME_REWARD_MAP.get(o.outcome.upper(), 0.1))
            rows_groups.append(o.handle.lower())

        n = len(rows_y)
        prior_w = list(_COLD_PRIOR_WEIGHTS[self.preset])
        if n < 15 or len(set(rows_groups)) < 3:
            self.tier_active = 0
            self.weights = prior_w
            return self

        use_tier2 = n >= 60
        X_use = rows_x2 if use_tier2 else rows_x1
        d_use = len(X_use[0])
        prior_pad = prior_w + [0.0] * (d_use - len(prior_w))

        # Entity-grouped GroupKFold (k=3) preventing same-program leakage across folds
        uniq_groups = sorted(set(rows_groups))
        k_folds = min(3, len(uniq_groups))
        fold_of = {g: idx % k_folds for idx, g in enumerate(uniq_groups)}

        prior_ndcgs: list[float] = []
        learned_ndcgs: list[float] = []
        for f_id in range(k_folds):
            tr_idx = [i for i, g in enumerate(rows_groups) if fold_of[g] != f_id]
            va_idx = [i for i, g in enumerate(rows_groups) if fold_of[g] == f_id]
            if len(tr_idx) < 4 or len(va_idx) < 2:
                continue
            w_fold = self._fit_pairwise_sgd(
                [X_use[i] for i in tr_idx],
                [rows_y[i] for i in tr_idx],
                l2=self.l2,
            )
            va_y = [rows_y[i] for i in va_idx]
            s_prior = [sum(prior_pad[j] * X_use[i][j] for j in range(d_use)) for i in va_idx]
            s_learn = [sum(w_fold[j] * X_use[i][j] for j in range(d_use)) for i in va_idx]
            prior_ndcgs.append(ndcg_at_k(va_y, s_prior, k=5))
            learned_ndcgs.append(ndcg_at_k(va_y, s_learn, k=5))

        avg_prior = sum(prior_ndcgs) / len(prior_ndcgs) if prior_ndcgs else 0.0
        avg_learn = sum(learned_ndcgs) / len(learned_ndcgs) if learned_ndcgs else 0.0
        self.cv_ndcg_prior = round(avg_prior, 4)
        self.cv_ndcg_learned = round(avg_learn, 4)

        if avg_learn > avg_prior + 0.01:
            w_full = self._fit_pairwise_sgd(X_use, rows_y, l2=self.l2)
            shrink = float(n) / float(n + 25.0)
            self.weights = [shrink * w_full[j] + (1.0 - shrink) * prior_pad[j] for j in range(d_use)]
            self.tier_active = 2 if use_tier2 else 1
        else:
            self.tier_active = 0
            self.weights = prior_w
        return self

    def score_and_explain(self, ef: ExtractedProgramFeatures) -> tuple[float, dict[str, float]]:
        vec = (ef.tier1_vector + ef.tier2_text_vector) if self.tier_active == 2 else ef.tier1_vector
        d = min(len(self.weights), len(vec))
        raw = sum(self.weights[j] * vec[j] for j in range(d))
        # Sigmoid squashing to calibrated [0, 1] score
        score = 1.0 / (1.0 + math.exp(-max(-15.0, min(15.0, raw))))
        attributions = {
            TIER1_FEATURE_NAMES[j]: round(self.weights[j] * ef.tier1_vector[j], 4)
            for j in range(min(len(TIER1_FEATURE_NAMES), len(self.weights)))
        }
        return round(score, 6), attributions


# ---------------------------------------------------------------------------
# 4. Online Contextual Bandit (Disjoint LinUCB + Discounted Beta-Thompson)
# ---------------------------------------------------------------------------


class OnlineProgramBandit:
    """
    Pure-Python Disjoint LinUCB (Sherman-Morrison inverse updates) for Lane 1/2
    contextual allocation + per-program Discounted Beta-Bernoulli Thompson Sampling.
    """

    def __init__(
        self,
        *,
        d_ctx: int = 4,
        alpha_ucb: float = 0.65,
        weekly_decay: float = 0.95,
        seed: int = 42,
    ) -> None:
        self.d_ctx = max(1, int(d_ctx))
        self.alpha_ucb = float(alpha_ucb)
        self.weekly_decay = max(0.5, min(1.0, float(weekly_decay)))
        self._rng = random.Random(seed)
        # Disjoint LinUCB per lane (lane 1 -> arm 0, lane 2 -> arm 1)
        self._A_inv: list[list[list[float]]] = [
            [[1.0 if i == j else 0.0 for j in range(self.d_ctx)] for i in range(self.d_ctx)]
            for _ in range(2)
        ]
        self._b: list[list[float]] = [[0.0] * self.d_ctx for _ in range(2)]
        self._beta_params: dict[str, tuple[float, float]] = {}

    def _sherman_morrison_update(self, arm: int, x: Sequence[float], reward: float) -> None:
        A_inv = self._A_inv[arm]
        d = self.d_ctx
        xv = [float(x[i]) if i < len(x) else 0.0 for i in range(d)]
        # A_inv @ x
        Ax = [sum(A_inv[i][j] * xv[j] for j in range(d)) for i in range(d)]
        denom = 1.0 + sum(xv[i] * Ax[i] for i in range(d))
        if denom > 1e-9:
            for i in range(d):
                for j in range(d):
                    A_inv[i][j] -= (Ax[i] * Ax[j]) / denom
        for i in range(d):
            self._b[arm][i] += float(reward) * xv[i]

    def fit_outcomes(
        self,
        outcomes: Sequence[HuntOutcomeRecord],
        *,
        now: datetime | None = None,
    ) -> OnlineProgramBandit:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(UTC)
        alpha_map: dict[str, float] = {}
        beta_map: dict[str, float] = {}

        for o in outcomes:
            y = OUTCOME_REWARD_MAP.get(o.outcome.upper(), 0.1)
            dt = _parse_iso_utc(o.discovered_at_utc)
            weeks_old = max(0.0, (ref_now - dt).total_seconds() / (86400.0 * 7.0)) if dt else 0.0
            disc = self.weekly_decay ** weeks_old
            h = o.handle.lower()
            alpha_map[h] = alpha_map.get(h, 1.5) + disc * y
            beta_map[h] = beta_map.get(h, 1.5) + disc * (1.0 - y)

            arm = 0 if int(o.lane) == 1 else 1
            x_ctx = [
                1.0 if o.signal_delta >= 0.0 else 0.0,
                min(2.0, max(0.0, float(o.signal_delta))),
                1.0 / (1.0 + math.log1p(max(0.0, float(o.target_age_hours)))),
                1.0,
            ]
            self._sherman_morrison_update(arm, x_ctx, y)

        for h in set(alpha_map.keys()) | set(beta_map.keys()):
            self._beta_params[h] = (alpha_map.get(h, 1.5), beta_map.get(h, 1.5))
        return self

    def lane_ucb_scores(self, context: Sequence[float]) -> tuple[float, float]:
        d = self.d_ctx
        xv = [float(context[i]) if i < len(context) else 0.0 for i in range(d)]
        scores: list[float] = []
        for arm in range(2):
            A_inv = self._A_inv[arm]
            b = self._b[arm]
            theta = [sum(A_inv[i][j] * b[j] for j in range(d)) for i in range(d)]
            mean = sum(theta[i] * xv[i] for i in range(d))
            Ax = [sum(A_inv[i][j] * xv[j] for j in range(d)) for i in range(d)]
            var = max(0.0, sum(xv[i] * Ax[i] for i in range(d)))
            scores.append(mean + self.alpha_ucb * math.sqrt(var))
        return round(scores[0], 5), round(scores[1], 5)

    def program_thompson_bonus(self, handle: str, *, deterministic: bool = True) -> float:
        """Returns posterior mean (deterministic) or Beta sample (exploratory) in [0, 1]."""
        a, b = self._beta_params.get(handle.lower(), (1.5, 1.5))
        if deterministic:
            return round(a / (a + b), 5)
        return round(self._rng.betavariate(max(0.1, a), max(0.1, b)), 5)


# ---------------------------------------------------------------------------
# 5. Two-Phase Reserved-Quota Knapsack (Fixes ACDSO D1!)
# ---------------------------------------------------------------------------


@dataclass
class PortfolioItem:
    handle: str
    lane: str
    expected_value: float
    scan_cost_minutes: float
    pareto_knee_score: float
    survival_72h: float
    bounty_max_usd: int
    response_efficiency_pct: float | None
    ai_in_scope: bool


class DailyHuntPortfolioOptimizer:
    """
    Two-Phase Reserved-Quota Knapsack fixing ACDSO `_optimize_greedy + FairnessConstraint`
    all-zero failure (D1):
      - Phase 1: When `not signal_established or signal_score < signal_threshold`,
        reserves `lane1_floor = min(ceil(0.5 * capacity), len(eligible_lane1))` and
        greedily fills Lane 1 VDPs by `expected_value / scan_cost_minutes` within budget.
      - Phase 2: Fills remaining slots & compute budget across remaining Lane 1 + Lane 2
        candidates by ROI (`expected_value / scan_cost_minutes`).
    """

    def optimize(
        self,
        items: Sequence[PortfolioItem],
        *,
        capacity: int = 6,
        budget_minutes: float = 120.0,
        account_state: AccountSignalState | None = None,
        signal_threshold: float = 1.0,
    ) -> dict[str, Any]:
        cap = max(0, int(capacity))
        budget = max(1.0, float(budget_minutes))
        st = account_state or AccountSignalState()
        low_signal = (not st.signal_established) or (st.signal_score is None) or (float(st.signal_score) < float(signal_threshold))

        eligible = [
            it for it in items
            if it.lane in ("LANE_1_VDP_FAST_SIGNAL", "LANE_2_BBP_HIGH_EV")
        ]
        if cap == 0 or not eligible:
            return {
                "selected": [],
                "lane1_count": 0,
                "lane2_count": 0,
                "lane1_reserved_floor": 0,
                "total_cost_minutes": 0.0,
                "total_expected_value": 0.0,
                "low_signal_regime": low_signal,
            }

        def _roi(it: PortfolioItem) -> tuple[float, float, str]:
            cost = max(1.0, float(it.scan_cost_minutes))
            return (-(it.expected_value / cost), -it.expected_value, it.handle)

        lane1_pool = sorted([it for it in eligible if it.lane == "LANE_1_VDP_FAST_SIGNAL"], key=_roi)
        lane1_floor = min(math.ceil(cap * 0.5), len(lane1_pool)) if low_signal else 0

        selected: list[PortfolioItem] = []
        selected_handles: set[str] = set()
        used_budget = 0.0

        # Phase 1: Guarantee reserved Lane 1 VDP floor (even if single item exceeds avg share, allow up to budget)
        for it in lane1_pool:
            if len(selected) >= lane1_floor:
                break
            if used_budget + it.scan_cost_minutes <= budget or len(selected) == 0:
                selected.append(it)
                selected_handles.add(it.handle)
                used_budget += it.scan_cost_minutes

        # Phase 2: Fill remaining capacity across all remaining eligible programs by ROI
        remaining_pool = sorted(
            [it for it in eligible if it.handle not in selected_handles],
            key=_roi,
        )
        for it in remaining_pool:
            if len(selected) >= cap:
                break
            if used_budget + it.scan_cost_minutes <= budget:
                selected.append(it)
                selected_handles.add(it.handle)
                used_budget += it.scan_cost_minutes

        l1_cnt = sum(1 for s in selected if s.lane == "LANE_1_VDP_FAST_SIGNAL")
        l2_cnt = sum(1 for s in selected if s.lane == "LANE_2_BBP_HIGH_EV")
        return {
            "selected": [asdict(s) for s in selected],
            "lane1_count": l1_cnt,
            "lane2_count": l2_cnt,
            "lane1_reserved_floor": lane1_floor,
            "total_cost_minutes": round(used_budget, 2),
            "total_expected_value": round(sum(s.expected_value for s in selected), 4),
            "low_signal_regime": low_signal,
        }


# ---------------------------------------------------------------------------
# 6. Top-Level Program Ranking & Pareto Selector API
# ---------------------------------------------------------------------------


_PROGRAM_OBJ_DIRECTIONS: tuple[bool, ...] = (
    True,   # 0: expected_value (MAX)
    False,  # 1: launch_staleness_log (MIN — newest launch wins)
    False,  # 2: saturation_log (MIN — least saturated wins)
    False,  # 3: triage_latency_log (MIN — fastest first response wins)
    False,  # 4: efficiency_and_roe_risk (MIN — >=80% eff + RoE friendly wins)
    False,  # 5: narrow_scope_penalty (MIN — wide wildcards/APIs/mobile/OSS wins)
)

_PROGRAM_OBJ_SCALES: tuple[float, ...] = (0.05, 0.25, 0.25, 0.20, 0.08, 0.08)


def rank_hackerone_programs(
    *,
    eligibility_db: ProgramEligibilityDB | None = None,
    db_path: str | None = None,
    min_efficiency_pct: float = 80.0,
    preset: str | None = None,
    capacity: int = 6,
    budget_minutes: float = 120.0,
    include_deferred: bool = False,
    deterministic_bandit: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    """
    End-to-end ACDSO-adapted ML HackerOne program ranking & portfolio optimization.
    Auto-selects `signal_fast` preset when Signal is unestablished or < 1.0,
    excludes `BLOCKED_SIGNAL`/`PAUSED`/`NOT_FOUND` programs fail-closed,
    deprioritizes `<80%` response efficiency programs, computes Cox anti-saturation
    survival, generalized 6-objective Pareto knee, online contextual bandit bonus,
    and Two-Phase Reserved-Quota Knapsack daily hunt plan.
    """
    db = eligibility_db if eligibility_db is not None else ProgramEligibilityDB(db_path=db_path)
    all_records = db.list_all()
    if not all_records:
        db.seed_observed_hackerone_baseline(now=now)
        all_records = db.list_all()

    account_state = db.get_account_state()
    outcomes = db.list_hunt_outcomes(limit=1000)

    low_signal = (not account_state.signal_established) or (account_state.signal_score is None) or (float(account_state.signal_score) < 1.0)
    eff_preset = (preset or ("signal_fast" if low_signal else "balanced")).strip().lower()
    if eff_preset not in _COLD_PRIOR_WEIGHTS:
        eff_preset = "balanced"

    extractor = ProgramFeatureExtractor(outcomes, now=now)
    extracted_all: dict[str, ExtractedProgramFeatures] = {}
    records_by_handle: dict[str, ProgramEligibilityRecord] = {}
    for rec in all_records:
        records_by_handle[rec.handle.lower()] = rec
        extracted_all[rec.handle.lower()] = extractor.extract(rec, min_efficiency_pct=min_efficiency_pct)

    # Fit survival model & 3-tier curriculum LTR on observed hunt_outcomes
    surv_model = ProgramSurvivalModel()
    if outcomes:
        s_X: list[list[float]] = []
        s_t: list[float] = []
        s_e: list[int] = []
        for o in outcomes:
            ef = extracted_all.get(o.handle.lower())
            if ef is None:
                continue
            s_X.append(ef.tier1_vector)
            s_t.append(max(1.0, float(o.target_age_hours or 24.0)))
            s_e.append(1 if o.outcome.upper() == "DUPLICATE" else 0)
        surv_model.fit(s_X, s_t, s_e)

    ranker = ProgramRanker(preset=eff_preset).fit_from_outcomes(extracted_all, outcomes)
    bandit = OnlineProgramBandit().fit_outcomes(outcomes, now=now)
    sig_ratio = max(0.0, min(2.0, float(account_state.signal_score or 0.0)))
    lane1_ucb, lane2_ucb = bandit.lane_ucb_scores(
        [1.0 if account_state.signal_established else 0.0, sig_ratio, 0.55, 0.45]
    )

    # Filter unlocked candidates (always exclude BLOCKED; optionally include DEFERRED_LOW_EFFICIENCY)
    active_handles: list[str] = []
    deferred_programs: list[dict[str, Any]] = []
    blocked_summary: list[dict[str, Any]] = []
    for h, ef in extracted_all.items():
        rec = records_by_handle[h]
        if ef.lane == "BLOCKED":
            if rec.status == "BLOCKED_SIGNAL":
                ud = compute_unlock_distance(rec, account_state)
                blocked_summary.append(
                    {
                        "handle": rec.handle,
                        "status": rec.status,
                        "signal_required": rec.signal_required,
                        "unlock_distance": ud["distance"],
                        "estimated_vdp_reports_needed": ud["estimated_vdp_reports_needed"],
                    }
                )
            continue
        if ef.lane == "DEFERRED_LOW_EFFICIENCY":
            deferred_programs.append(
                {
                    "handle": rec.handle,
                    "response_efficiency_pct": rec.response_efficiency_pct,
                    "reason": ef.lane_reason,
                }
            )
            if not include_deferred:
                continue
        active_handles.append(h)

    # Fallback: if zero programs met >=80% efficiency, include deferred unlocked programs so output is never empty
    if not active_handles and deferred_programs:
        active_handles = [d["handle"].lower() for d in deferred_programs]

    pareto_candidates: list[MultiObjectiveCandidate] = []
    prelim_rows: dict[str, dict[str, Any]] = {}

    for h in active_handles:
        rec = records_by_handle[h]
        ef = extracted_all[h]
        ltr_score, attributions = ranker.score_and_explain(ef)
        surv_72h = surv_model.predict_fresh_survival(ef.tier1_vector, window_hours=72.0)
        ts_bonus = bandit.program_thompson_bonus(h, deterministic=deterministic_bandit)
        expected_val = round(0.55 * ltr_score + 0.30 * surv_72h + 0.15 * ts_bonus, 6)

        launch_staleness_log = math.log1p(max(0.0, ef.launch_age_days))
        sat_log = ef.feature_map["saturation_log"]
        triage_lat_log = math.log1p(float(rec.first_response_hours if rec.first_response_hours is not None else 48.0))
        eff_risk = (1.0 - ef.feature_map["response_efficiency_norm"]) + (0.45 if rec.roe_automated_prohibited else 0.0)
        narrow_penalty = 1.0 - min(1.0, 0.55 * ef.feature_map["non_marketing_surface_ratio"] + 0.45 * min(1.0, ef.feature_map["scope_breadth_log"]))

        cand = MultiObjectiveCandidate(
            name=rec.handle,
            objectives=(
                expected_val,
                round(launch_staleness_log, 6),
                round(sat_log, 6),
                round(triage_lat_log, 6),
                round(eff_risk, 6),
                round(narrow_penalty, 6),
            ),
            directions=_PROGRAM_OBJ_DIRECTIONS,
            raw_metrics={
                "expected_value": expected_val,
                "launch_age_days": ef.launch_age_days,
                "resolved_count": rec.resolved_count,
                "first_response_hours": rec.first_response_hours,
                "response_efficiency_pct": rec.response_efficiency_pct,
                "total_assets": ef.total_assets,
            },
            meta={"lane": ef.lane},
        )
        pareto_candidates.append(cand)
        prelim_rows[h] = {
            "handle": rec.handle,
            "lane": ef.lane,
            "lane_reason": ef.lane_reason,
            "submit_url": rec.submit_url,
            "offers_bounties": rec.offers_bounties,
            "is_vdp": rec.is_vdp,
            "bounty_max_usd": int(rec.bounty_max_usd or 0),
            "response_efficiency_pct": rec.response_efficiency_pct,
            "first_response_hours": rec.first_response_hours,
            "launched_at_utc": rec.launched_at_utc,
            "launch_age_days": ef.launch_age_days,
            "resolved_count": rec.resolved_count,
            "ai_in_scope": rec.ai_asset_count > 0,
            "roe_automated_prohibited": rec.roe_automated_prohibited,
            "roe_max_rps": rec.roe_max_rps,
            "in_scope_repos": list(rec.in_scope_repos),
            "ltr_score": ltr_score,
            "survival_72h": round(surv_72h, 5),
            "thompson_bonus": ts_bonus,
            "expected_value": expected_val,
            "estimated_scan_minutes": ef.estimated_scan_minutes,
            "feature_attributions": attributions,
            "objectives": list(cand.objectives),
        }

    front = generalized_pareto_front(pareto_candidates, directions=_PROGRAM_OBJ_DIRECTIONS)
    front_names = {c.name for c in front}
    knee_winner_name = ""
    knee_scores: dict[str, float] = {}
    if front:
        # Score ALL active candidates for smooth ranking, while marking Pareto-optimal ones
        winner_c, front_scores = select_pareto_knee(
            front,
            directions=_PROGRAM_OBJ_DIRECTIONS,
            min_scales=_PROGRAM_OBJ_SCALES,
            preference=eff_preset,
        )
        knee_winner_name = winner_c.name
        _, all_scores = select_pareto_knee(
            pareto_candidates,
            directions=_PROGRAM_OBJ_DIRECTIONS,
            min_scales=_PROGRAM_OBJ_SCALES,
            preference=eff_preset,
        )
        knee_scores = {**all_scores, **front_scores}

    ranked: list[dict[str, Any]] = []
    portfolio_inputs: list[PortfolioItem] = []
    for h, row in prelim_rows.items():
        k_score = float(knee_scores.get(row["handle"], row["expected_value"]))
        is_front = row["handle"] in front_names
        # Slight bonus for Pareto-optimal members so non-dominated programs rise cleanly
        combined = round(0.60 * row["expected_value"] + 0.35 * k_score + (0.05 if is_front else 0.0), 6)
        row["pareto_optimal"] = is_front
        row["pareto_knee_score"] = round(k_score, 6)
        row["combined_rank_score"] = combined
        ranked.append(row)
        portfolio_inputs.append(
            PortfolioItem(
                handle=row["handle"],
                lane=row["lane"],
                expected_value=combined,
                scan_cost_minutes=float(row["estimated_scan_minutes"]),
                pareto_knee_score=round(k_score, 6),
                survival_72h=float(row["survival_72h"]),
                bounty_max_usd=int(row["bounty_max_usd"]),
                response_efficiency_pct=row["response_efficiency_pct"],
                ai_in_scope=bool(row["ai_in_scope"]),
            )
        )

    ranked.sort(key=lambda r: (-r["combined_rank_score"], -r["expected_value"], r["handle"]))
    for idx, r in enumerate(ranked, start=1):
        r["rank"] = idx

    # Check if top 2-3 candidates are within a tight 0.02 tie margin (eligible for optional /boost tie-breaker)
    tie_break_needed = (
        len(ranked) >= 2
        and abs(float(ranked[0]["combined_rank_score"]) - float(ranked[1]["combined_rank_score"])) <= 0.02
    )

    optimizer = DailyHuntPortfolioOptimizer()
    portfolio = optimizer.optimize(
        portfolio_inputs,
        capacity=capacity,
        budget_minutes=budget_minutes,
        account_state=account_state,
        signal_threshold=1.0,
    )

    blocked_summary.sort(key=lambda b: (b["unlock_distance"], b["handle"]))

    return {
        "schema": "rfchunt.ml_program_selection.v1",
        "preset": eff_preset,
        "min_efficiency_pct": float(min_efficiency_pct),
        "account_state": account_state.to_dict(),
        "ltr_curriculum_tier": ranker.tier_active,
        "ltr_cv_ndcg_prior": ranker.cv_ndcg_prior,
        "ltr_cv_ndcg_learned": ranker.cv_ndcg_learned,
        "survival_fitted_on_outcomes": surv_model.fitted_on_outcomes,
        "survival_c_index": surv_model.c_index_cv,
        "lane_ucb_scores": {"lane1_vdp": lane1_ucb, "lane2_bbp": lane2_ucb},
        "pareto_knee_winner": knee_winner_name,
        "pareto_front_handles": sorted(front_names),
        "tie_break_needed": tie_break_needed,
        "ranked_programs": ranked,
        "daily_hunt_portfolio": portfolio,
        "deferred_low_efficiency": deferred_programs,
        "closest_blocked_to_unlock": blocked_summary[:10],
        "ai_in_scope_programs": [r["handle"] for r in ranked if r["ai_in_scope"]],
    }


__all__ = [
    "OUTCOME_REWARD_MAP",
    "TIER1_FEATURE_NAMES",
    "DailyHuntPortfolioOptimizer",
    "ExtractedProgramFeatures",
    "OnlineProgramBandit",
    "PortfolioItem",
    "ProgramFeatureExtractor",
    "ProgramRanker",
    "ProgramSurvivalModel",
    "classify_program_lane",
    "compute_empirical_bayes_yield",
    "compute_unlock_distance",
    "concordance_index",
    "ndcg_at_k",
    "rank_hackerone_programs",
    "signed_hash_features",
    "signed_log1p",
]
