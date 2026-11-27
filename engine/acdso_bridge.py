"""
ACDSO ML Bridge (`engine/acdso_bridge.py`).
===========================================
Self-contained adaptation of ACDSO multi-objective Pareto optimization,
unsupervised anomaly scoring, and contextual-bandit policy scheduling
(`pareto.py`, `anomaly.py`, `decision/policy.py`, `utils.py`).

Design Invariants:
- Zero cross-repository imports from `D:\\harfile\\ACDSO`.
- Optional `numpy` / `scikit-learn` acceleration with deterministic pure-Python
  stdlib parity fallbacks so CI passes with `requirements.txt` alone.
- Strict edge-case guards for 0/1/2+ rows, constant/zero-std columns, NaN/Inf,
  single-class policy targets, and `exp` overflow (`[-10.0, 10.0]` clip).
- Enforces Loop 5 R4 invariant: while `signal_score < 1.0`, Lane 1 receives at
  least `math.ceil(queue_capacity * 0.5)` slots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import random
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


# Objective directions: True = maximize, False = minimize
# Index: 0=metric, 1=train_time, 2=memory, 3=latency, 4=risk, 5=robustness_drop
OBJECTIVE_DIRECTIONS: Tuple[bool, ...] = (
    True,   # 0: metric (higher is better)
    False,  # 1: log(train_time) (lower is better)
    False,  # 2: log(peak_mem) (lower is better)
    False,  # 3: log(latency) (lower is better)
    False,  # 4: risk_penalty (lower is better)
    False,  # 5: robustness_drop (lower is better)
)

OBJECTIVE_NAMES: Tuple[str, ...] = (
    "metric",
    "log_train_time",
    "log_peak_mem",
    "log_latency",
    "risk_penalty",
    "robustness_drop",
)

_SEVERITY_RANK: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.80,
    "MEDIUM": 0.55,
    "LOW": 0.30,
    "INFO": 0.10,
}

_DEFAULT_ENGINE_WEIGHTS: Dict[str, float] = {
    "z3_formal": 0.92,
    "lean4": 0.95,
    "trufflehog": 0.90,
    "api_jwt_sdjwt": 0.84,
    "parity_auditor": 0.82,
    "mobile_mobsf": 0.78,
    "ai_infra_guard": 0.76,
    "differential_oracle": 0.88,
    "rea": 0.74,
}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if math.isfinite(f) else default


def _mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / float(len(values))


def _std(values: Sequence[float], floor: float = 0.0) -> float:
    n = len(values)
    if n <= 1:
        return floor
    m = _mean(values)
    var = sum((v - m) ** 2 for v in values) / float(n)
    return max(math.sqrt(max(0.0, var)), floor)


def _median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 1:
        return s[mid]
    return 0.5 * (s[mid - 1] + s[mid])


# ---------------------------------------------------------------------------
# Pareto Multi-Objective Optimization (adapted from ACDSO pareto.py)
# ---------------------------------------------------------------------------


@dataclass
class CandidateResult:
    """Result of evaluating a candidate pipeline/finding across 6 objectives."""

    name: str
    pipeline: Any
    metric: float
    train_time_s: float
    peak_mem_mb: float
    latency_ms_per_row: float
    risk_penalty: float
    objectives: Tuple[float, ...]
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "name": self.name,
            "metric": self.metric,
            "train_time_s": self.train_time_s,
            "peak_mem_mb": self.peak_mem_mb,
            "latency_ms_per_row": self.latency_ms_per_row,
            "risk_penalty": self.risk_penalty,
            "objectives": list(self.objectives),
            "meta": dict(self.meta),
        }
        if len(self.objectives) >= 6:
            result["robustness_drop"] = self.objectives[5]
        return result

    @property
    def robustness_drop(self) -> float:
        return self.objectives[5] if len(self.objectives) >= 6 else 0.0


def dominates(a: CandidateResult, b: CandidateResult) -> bool:
    """Return True if candidate `a` Pareto-dominates candidate `b`."""
    obj_a = a.objectives
    obj_b = b.objectives
    n_obj = min(len(obj_a), len(obj_b), len(OBJECTIVE_DIRECTIONS))

    better_or_equal = True
    strictly_better = False

    for i in range(n_obj):
        maximize = OBJECTIVE_DIRECTIONS[i]
        va, vb = float(obj_a[i]), float(obj_b[i])
        a_nan = math.isnan(va)
        b_nan = math.isnan(vb)

        if a_nan and b_nan:
            continue
        if a_nan:
            better_or_equal = False
            break
        if b_nan:
            strictly_better = True
            continue

        if maximize:
            if va < vb:
                better_or_equal = False
                break
            if va > vb:
                strictly_better = True
        else:
            if va > vb:
                better_or_equal = False
                break
            if va < vb:
                strictly_better = True

    return better_or_equal and strictly_better


def pareto_front(candidates: Sequence[CandidateResult]) -> List[CandidateResult]:
    """Extract all non-dominated candidates from `candidates`."""
    front: List[CandidateResult] = []
    for c in candidates:
        is_dominated = any(dominates(o, c) for o in candidates if o is not c)
        if not is_dominated:
            front.append(c)
    return front


def _normalize_axis(
    values: Sequence[float],
    *,
    higher_better: bool,
    min_scale: float,
) -> List[float]:
    n = len(values)
    finite_vals = [v for v in values if math.isfinite(v)]
    if not finite_vals:
        z = [0.5] * n
    else:
        x_min = min(finite_vals)
        x_max = max(finite_vals)
        span = x_max - x_min
        const_tol = 1e-12 * max(abs(x_min), abs(x_max))
        if span <= const_tol:
            z = [1.0] * n
        else:
            scale = max(span, float(min_scale))
            z = []
            for v in values:
                if not math.isfinite(v):
                    z.append(0.5)
                elif higher_better:
                    raw = 1.0 - (x_max - v) / scale
                    z.append(max(0.0, min(1.0, raw)))
                else:
                    raw = 1.0 - (v - x_min) / scale
                    z.append(max(0.0, min(1.0, raw)))

    for idx, v in enumerate(values):
        if math.isinf(v):
            if v > 0:
                z[idx] = 1.0 if higher_better else 0.0
            else:
                z[idx] = 0.0 if higher_better else 1.0
        elif math.isnan(v):
            z[idx] = 0.5
    return z


def knee_point_selection(
    front: Sequence[CandidateResult],
    preference: str = "balanced",
) -> CandidateResult:
    """Select the optimal tradeoff knee point from a Pareto front (pure-Python parity)."""
    if not front:
        raise ValueError("Pareto front is empty; cannot select knee point.")
    if len(front) == 1:
        return front[0]

    working = list(front)
    finite_metric_front = [c for c in working if math.isfinite(float(c.metric))]
    if finite_metric_front:
        all_finite_front = [
            c
            for c in finite_metric_front
            if all(
                math.isfinite(float(v))
                for v in (
                    c.metric,
                    c.train_time_s,
                    c.peak_mem_mb,
                    c.latency_ms_per_row,
                    c.risk_penalty,
                    c.robustness_drop,
                )
            )
        ]
        working = all_finite_front if all_finite_front else finite_metric_front
        if len(working) == 1:
            return working[0]

    m = [float(c.metric) for c in working]
    t = [math.log1p(max(0.0, float(c.train_time_s))) if math.isfinite(float(c.train_time_s)) else float(c.train_time_s) for c in working]
    mem = [math.log1p(max(0.0, float(c.peak_mem_mb))) if math.isfinite(float(c.peak_mem_mb)) else float(c.peak_mem_mb) for c in working]
    lat = [math.log1p(max(0.0, float(c.latency_ms_per_row))) if math.isfinite(float(c.latency_ms_per_row)) else float(c.latency_ms_per_row) for c in working]
    r = [float(c.risk_penalty) for c in working]
    rob = [float(c.robustness_drop) for c in working]

    finite_m = [v for v in m if math.isfinite(v)]
    if finite_m:
        max_abs_m = max(abs(v) for v in finite_m)
        if max(finite_m) <= 0.0:
            m_floor = 0.01 * max(1e-12, max_abs_m)
        else:
            m_floor = 0.01 * max(1.0, max_abs_m)
    else:
        max_abs_m = 1.0
        m_floor = 0.01
    m_tie_scale = max(1e-30, max_abs_m) if max_abs_m > 0.0 else 1.0

    mb = _normalize_axis(m, higher_better=True, min_scale=m_floor)
    tb = _normalize_axis(t, higher_better=False, min_scale=0.25)
    memb = _normalize_axis(mem, higher_better=False, min_scale=0.25)
    latb = _normalize_axis(lat, higher_better=False, min_scale=0.10)
    rb = _normalize_axis(r, higher_better=False, min_scale=0.03)
    robb = _normalize_axis(rob, higher_better=False, min_scale=0.02)

    pref = str(preference or "balanced").strip().lower()
    if pref in ("accuracy", "metric"):
        w_t, w_mem, w_lat, w_r, w_rob = 0.15, 0.10, 0.10, 0.30, 0.35
        w_ben, w_cost = 0.90, 0.10
    elif pref in ("speed", "fast"):
        w_t, w_mem, w_lat, w_r, w_rob = 0.35, 0.15, 0.30, 0.10, 0.10
        w_ben, w_cost = 0.35, 0.65
    elif pref in ("low_risk", "safe"):
        w_t, w_mem, w_lat, w_r, w_rob = 0.10, 0.10, 0.10, 0.35, 0.35
        w_ben, w_cost = 0.55, 0.45
    else:
        pref = "balanced"
        w_t, w_mem, w_lat, w_r, w_rob = 0.25, 0.15, 0.15, 0.20, 0.25
        w_ben, w_cost = 0.60, 0.40

    benefit = mb
    costrisk = [
        1.0 - (w_t * tb[i] + w_mem * memb[i] + w_lat * latb[i] + w_r * rb[i] + w_rob * robb[i])
        for i in range(len(working))
    ]

    def _q(val: Any, decimals: Optional[int] = None) -> float:
        f = float(val)
        if not math.isfinite(f):
            return float("inf")
        return round(f, decimals) if decimals is not None else f

    def _q_metric(val: Any) -> float:
        f = float(val)
        if math.isnan(f):
            return float("inf")
        if math.isinf(f):
            return -f
        return -round(f / m_tie_scale, 8)

    def tie_key(i: int) -> Tuple[float, float, float, float, float, float, str]:
        c = working[i]
        return (
            _q_metric(c.metric),
            _q(c.risk_penalty, 3),
            _q(c.robustness_drop, 4),
            _q(c.peak_mem_mb, 1),
            _q(c.latency_ms_per_row, 1),
            _q(c.train_time_s, 1),
            str(c.name),
        )

    if pref != "balanced":
        scores = [w_ben * benefit[i] - w_cost * costrisk[i] for i in range(len(working))]
        max_s = max(scores)
        near_best = [i for i, s in enumerate(scores) if s >= max_s - 0.015]
        best_i = min(near_best, key=tie_key)
        return working[best_i]

    pts = [(benefit[i], costrisk[i]) for i in range(len(working))]
    a_idx = min(
        range(len(working)),
        key=lambda i: (-round(benefit[i], 12), round(costrisk[i], 12), tie_key(i)),
    )
    b_idx = min(
        range(len(working)),
        key=lambda i: (round(costrisk[i], 12), -round(benefit[i], 12), tie_key(i)),
    )

    if len(working) >= 3 and a_idx != b_idx:
        ax, ay = pts[a_idx]
        bx, by = pts[b_idx]
        db = bx - ax
        dc = by - ay
        ab_norm = math.hypot(db, dc)
        if abs(db) >= 0.05 and abs(dc) >= 0.08 and ab_norm >= 0.05:
            # Utopia is (1.0, 0.0)
            cross_u = db * (0.0 - ay) - dc * (1.0 - ax)
            orient = 1.0 if cross_u >= 0.0 else -1.0
            sdists = [
                orient * (db * (py - ay) - dc * (px - ax)) / ab_norm
                for px, py in pts
            ]
            max_sd = max(sdists)
            if max_sd > 0.01:
                near_best = [i for i, sd in enumerate(sdists) if sd >= max_sd - 1e-9]
                best_i = min(near_best, key=tie_key)
                return working[best_i]

    udists = [
        math.sqrt(w_ben * (1.0 - benefit[i]) ** 2 + w_cost * costrisk[i] ** 2)
        for i in range(len(working))
    ]
    min_u = min(udists)
    near_best = [i for i, u in enumerate(udists) if u <= min_u + 0.015]
    best_i = min(near_best, key=tie_key)
    return working[best_i]


def filter_by_constraints(
    candidates: Sequence[CandidateResult],
    max_train_time_s: Optional[float] = None,
    max_peak_mem_mb: Optional[float] = None,
    max_latency_ms_per_row: Optional[float] = None,
) -> Tuple[List[CandidateResult], List[Dict[str, Any]]]:
    """Filter candidates by runtime/memory/latency constraints."""
    passing: List[CandidateResult] = []
    pruned: List[Dict[str, Any]] = []
    for c in candidates:
        violations: List[str] = []
        if max_train_time_s is not None and c.train_time_s > max_train_time_s:
            violations.append(f"train_time={c.train_time_s:.2f}s > {max_train_time_s}s")
        if max_peak_mem_mb is not None and c.peak_mem_mb > max_peak_mem_mb:
            violations.append(f"peak_mem={c.peak_mem_mb:.1f}MB > {max_peak_mem_mb}MB")
        if max_latency_ms_per_row is not None and c.latency_ms_per_row > max_latency_ms_per_row:
            violations.append(f"latency={c.latency_ms_per_row:.2f}ms > {max_latency_ms_per_row}ms")
        if violations:
            pruned.append(
                {
                    "name": c.name,
                    "reason": "constraints",
                    "violations": violations,
                    "metrics": {
                        "train_time_s": c.train_time_s,
                        "peak_mem_mb": c.peak_mem_mb,
                        "latency_ms_per_row": c.latency_ms_per_row,
                        "metric": c.metric,
                        "risk_penalty": c.risk_penalty,
                    },
                }
            )
        else:
            passing.append(c)
    return passing, pruned


@dataclass
class MultiObjectiveCandidate:
    """
    Domain-agnostic multi-objective candidate (fixes double-log distortion in
    ML-specific `knee_point_selection` when optimizing HackerOne programs or commits).
    `directions[i] == True` means maximize `objectives[i]`, `False` means minimize.
    """

    name: str
    objectives: Tuple[float, ...]
    directions: Tuple[bool, ...]
    raw_metrics: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "objectives": list(self.objectives),
            "directions": list(self.directions),
            "raw_metrics": dict(self.raw_metrics),
            "meta": dict(self.meta),
        }


def generalized_dominates(
    a: MultiObjectiveCandidate,
    b: MultiObjectiveCandidate,
    directions: Optional[Sequence[bool]] = None,
) -> bool:
    """Return True if `a` Pareto-dominates `b` across explicit per-axis `directions`."""
    dirs = tuple(directions) if directions is not None else a.directions
    n_obj = min(len(a.objectives), len(b.objectives), len(dirs))
    if n_obj == 0:
        return False
    better_or_equal = True
    strictly_better = False
    for i in range(n_obj):
        va, vb = float(a.objectives[i]), float(b.objectives[i])
        a_nan, b_nan = math.isnan(va), math.isnan(vb)
        if a_nan and b_nan:
            continue
        if a_nan:
            better_or_equal = False
            break
        if b_nan:
            strictly_better = True
            continue
        if dirs[i]:
            if va < vb:
                better_or_equal = False
                break
            if va > vb:
                strictly_better = True
        else:
            if va > vb:
                better_or_equal = False
                break
            if va < vb:
                strictly_better = True
    return better_or_equal and strictly_better


def generalized_pareto_front(
    candidates: Sequence[MultiObjectiveCandidate],
    directions: Optional[Sequence[bool]] = None,
) -> List[MultiObjectiveCandidate]:
    """Extracts the exact non-dominated Pareto front for domain-agnostic objective vectors."""
    front: List[MultiObjectiveCandidate] = []
    for c in candidates:
        if not any(generalized_dominates(o, c, directions=directions) for o in candidates if o is not c):
            front.append(c)
    return front


def select_pareto_knee(
    front: Sequence[MultiObjectiveCandidate],
    *,
    directions: Optional[Sequence[bool]] = None,
    min_scales: Optional[Sequence[float]] = None,
    weights: Optional[Sequence[float]] = None,
    benefit_indices: Sequence[int] = (0,),
    preference: str = "balanced",
) -> Tuple[MultiObjectiveCandidate, Dict[str, float]]:
    """
    Domain-agnostic Pareto knee-point selector (chord distance to utopia `(1.0, 0.0)`
    with weighted L2 utopia fallback). Applies NO hidden `log1p` transform to caller
    objectives, eliminating double-log distortion. Returns `(winner, scores_by_name)`.
    """
    if not front:
        raise ValueError("Pareto front is empty; cannot select knee point.")
    if len(front) == 1:
        return front[0], {front[0].name: 1.0}

    dirs = tuple(directions) if directions is not None else front[0].directions
    n_obj = len(dirs)
    eff_scales = list(min_scales) if min_scales is not None else [0.05] * n_obj
    eff_weights = list(weights) if weights is not None else [1.0 / max(1, n_obj)] * n_obj
    if len(eff_scales) < n_obj:
        eff_scales.extend([0.05] * (n_obj - len(eff_scales)))
    if len(eff_weights) < n_obj:
        eff_weights.extend([1.0 / max(1, n_obj)] * (n_obj - len(eff_weights)))

    # Normalize every objective onto [0, 1] where 1.0 is utopia (best)
    norm_cols: List[List[float]] = []
    for j in range(n_obj):
        col = [float(c.objectives[j]) if j < len(c.objectives) else 0.0 for c in front]
        norm_cols.append(_normalize_axis(col, higher_better=bool(dirs[j]), min_scale=float(eff_scales[j])))

    ben_set = {i for i in benefit_indices if 0 <= i < n_obj}
    if not ben_set:
        ben_set = {0}
    cost_idxs = [i for i in range(n_obj) if i not in ben_set]

    ben_w_sum = sum(eff_weights[i] for i in ben_set) or 1.0
    cost_w_sum = sum(eff_weights[i] for i in cost_idxs) or 1.0

    benefit: List[float] = [
        sum(eff_weights[j] * norm_cols[j][i] for j in ben_set) / ben_w_sum
        for i in range(len(front))
    ]
    costrisk: List[float] = [
        (1.0 - sum(eff_weights[j] * norm_cols[j][i] for j in cost_idxs) / cost_w_sum)
        if cost_idxs
        else (1.0 - benefit[i])
        for i in range(len(front))
    ]

    pref = str(preference or "balanced").strip().lower()
    if pref in ("bounty_max", "accuracy", "metric"):
        w_ben, w_cost = 0.78, 0.22
    elif pref in ("signal_fast", "speed", "fast"):
        w_ben, w_cost = 0.55, 0.45
    elif pref in ("safe", "low_risk"):
        w_ben, w_cost = 0.45, 0.55
    else:
        w_ben, w_cost = 0.60, 0.40

    def _tie_key(i: int) -> Tuple[float, float, str]:
        return (-round(benefit[i], 8), round(costrisk[i], 8), str(front[i].name))

    # Compute weighted utopia proximity score for every candidate (higher = better, in [0, 1])
    scores_by_name: Dict[str, float] = {}
    udists: List[float] = []
    for i, c in enumerate(front):
        ud = math.sqrt(w_ben * (1.0 - benefit[i]) ** 2 + w_cost * costrisk[i] ** 2)
        udists.append(ud)
        scores_by_name[c.name] = round(max(0.0, 1.0 - ud), 6)

    if pref == "balanced" and len(front) >= 3:
        a_idx = min(range(len(front)), key=lambda i: (-round(benefit[i], 12), round(costrisk[i], 12), _tie_key(i)))
        b_idx = min(range(len(front)), key=lambda i: (round(costrisk[i], 12), -round(benefit[i], 12), _tie_key(i)))
        if a_idx != b_idx:
            ax, ay = benefit[a_idx], costrisk[a_idx]
            bx, by = benefit[b_idx], costrisk[b_idx]
            db, dc = bx - ax, by - ay
            ab_norm = math.hypot(db, dc)
            if abs(db) >= 0.04 and abs(dc) >= 0.06 and ab_norm >= 0.05:
                cross_u = db * (0.0 - ay) - dc * (1.0 - ax)
                orient = 1.0 if cross_u >= 0.0 else -1.0
                sdists = [orient * (db * (costrisk[i] - ay) - dc * (benefit[i] - ax)) / ab_norm for i in range(len(front))]
                max_sd = max(sdists)
                if max_sd > 0.01:
                    near_best = [i for i, sd in enumerate(sdists) if sd >= max_sd - 1e-9]
                    best_i = min(near_best, key=_tie_key)
                    return front[best_i], scores_by_name

    min_u = min(udists)
    near_best = [i for i, u in enumerate(udists) if u <= min_u + 0.01]
    best_i = min(near_best, key=_tie_key)
    return front[best_i], scores_by_name


# ---------------------------------------------------------------------------
# Anomaly Scoring (adapted from ACDSO anomaly.py & utils.py)
# ---------------------------------------------------------------------------


def _extract_feature_matrix(rows: Sequence[Dict[str, Any]]) -> List[List[float]]:
    """Convert heterogeneous finding/metric dicts into a clean finite numeric matrix."""
    if not rows:
        return []

    extra_num_keys: List[str] = []
    seen_extra: set[str] = set()
    reserved = {
        "confidence",
        "severity",
        "freshness_score",
        "surface_score",
        "deterministic",
        "confirmed",
        "line",
        "summary",
        "title",
        "engine",
        "cwe",
        "rule_id",
        "non_production_noise",
        "metadata",
    }
    for row in rows:
        if not isinstance(row, dict):
            continue
        for k, v in row.items():
            if k in reserved or k in seen_extra:
                continue
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                seen_extra.add(k)
                extra_num_keys.append(k)
    extra_num_keys.sort()

    matrix: List[List[float]] = []
    for row in rows:
        if not isinstance(row, dict):
            row = {}
        meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        sev = str(row.get("severity", "MEDIUM")).strip().upper()
        sev_rank = _SEVERITY_RANK.get(sev, 0.45)
        conf = max(0.0, min(1.0, _safe_float(row.get("confidence", 0.5), 0.5)))
        freshness = _safe_float(row.get("freshness_score", meta.get("freshness_score", 0.5)), 0.5)
        if freshness > 1.0:
            freshness = min(1.0, freshness / 100.0)
        surface = _safe_float(row.get("surface_score", meta.get("surface_score", 0.5)), 0.5)
        if surface > 1.0:
            surface = min(1.0, surface / 100.0)
        det = 1.0 if bool(row.get("deterministic", False)) else 0.0
        confirmed = 1.0 if bool(row.get("confirmed", True)) else 0.0
        engine_name = str(row.get("engine", "")).strip().lower()
        engine_w = _DEFAULT_ENGINE_WEIGHTS.get(engine_name, 0.65)
        has_cwe = 1.0 if str(row.get("cwe", "")).strip() else 0.0
        text_blob = f"{row.get('title', '')} {row.get('summary', '')} {row.get('rule_id', '')}".lower()
        summary_len = math.log1p(max(0, len(str(row.get("summary", "")))))
        line_log = math.log1p(max(0.0, _safe_float(row.get("line", 0), 0.0)))
        boundary_hit = 1.0 if any(
            kw in text_blob
            for kw in ("parity", "ssrf", "authz", "jwt", "symlink", "o_nofollow", "csp", "smuggling", "desync")
        ) else 0.0
        noise_flag = 1.0 if bool(row.get("non_production_noise", meta.get("non_production_noise", False))) else 0.0

        vec: List[float] = [
            conf,
            sev_rank,
            freshness,
            surface,
            det,
            confirmed,
            engine_w,
            has_cwe,
            summary_len,
            line_log,
            boundary_hit,
            noise_flag,
        ]
        for ek in extra_num_keys:
            vec.append(_safe_float(row.get(ek, 0.0), 0.0))
        matrix.append(vec)
    return matrix


def _standardize_matrix(matrix: List[List[float]]) -> List[List[float]]:
    if not matrix:
        return []
    n_rows = len(matrix)
    n_cols = len(matrix[0])
    means = [0.0] * n_cols
    stds = [1.0] * n_cols
    for j in range(n_cols):
        col = [matrix[i][j] for i in range(n_rows)]
        means[j] = _mean(col)
        stds[j] = _std(col, floor=1e-6)
    return [
        [(matrix[i][j] - means[j]) / stds[j] for j in range(n_cols)]
        for i in range(n_rows)
    ]


class ACDSOAnomalyScorer:
    """
    Unsupervised anomaly scorer adapted from `ACDSOAnomalyDetector`.

    Safely handles 0 rows, 1 row, 2+ rows, constant/zero-std columns, and
    NaN/Inf inputs. Uses `sklearn` (`IsolationForest` / `LocalOutlierFactor`)
    when available, with deterministic pure-Python parity fallback otherwise.
    """

    def __init__(
        self,
        *,
        contamination: Union[str, float] = "auto",
        random_state: int = 42,
        prefer_sklearn: bool = True,
    ) -> None:
        self.contamination = contamination
        self.random_state = int(random_state)
        self.prefer_sklearn = bool(prefer_sklearn)
        self.last_backend: str = "uninitialized"
        self.last_audit_trail: Dict[str, Any] = {}

    def _row_heuristic_score(self, row: Dict[str, Any]) -> float:
        if not isinstance(row, dict):
            return 0.5
        meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        if bool(row.get("non_production_noise", meta.get("non_production_noise", False))):
            return 0.05
        sev = _SEVERITY_RANK.get(str(row.get("severity", "MEDIUM")).strip().upper(), 0.45)
        conf = max(0.0, min(1.0, _safe_float(row.get("confidence", 0.5), 0.5)))
        det_bonus = 0.12 if bool(row.get("deterministic", False)) else 0.0
        eng_w = _DEFAULT_ENGINE_WEIGHTS.get(str(row.get("engine", "")).strip().lower(), 0.65)
        score = 0.40 * conf + 0.30 * sev + 0.18 * eng_w + det_bonus
        return max(0.0, min(1.0, round(score, 6)))

    def _score_tail_separation(
        self,
        anom_scores: Sequence[float],
        anom_rate: float,
    ) -> float:
        n_rows = len(anom_scores)
        if n_rows < 2:
            return 0.0
        q = 0.05 if self.contamination == "auto" else max(0.01, min(0.5, float(self.contamination)))
        k_tail = max(1, min(n_rows - 1, int(round(q * n_rows))))
        sorted_anom = sorted(anom_scores)
        bulk = sorted_anom[:-k_tail]
        tail = sorted_anom[-k_tail:]
        bulk_std = _std(bulk, floor=1e-6)
        separation = (_mean(tail) - _mean(bulk)) / bulk_std
        penalty = 0.0
        if anom_rate == 0.0:
            penalty += 2.0
        elif anom_rate > max(0.30, 2.5 * q):
            penalty += 3.0 * (anom_rate - max(0.30, 2.5 * q))
        if self.contamination != "auto":
            penalty += 2.0 * abs(anom_rate - float(self.contamination))
        return float(separation - penalty)

    def _fit_score_sklearn(self, std_mat: List[List[float]]) -> Optional[Tuple[List[float], str]]:
        if not self.prefer_sklearn:
            return None
        try:
            import numpy as np  # type: ignore
            from sklearn.ensemble import IsolationForest  # type: ignore
            from sklearn.neighbors import LocalOutlierFactor  # type: ignore
        except Exception:
            return None

        X_np = np.asarray(std_mat, dtype=np.float64)
        X_np = np.nan_to_num(X_np, nan=0.0, posinf=0.0, neginf=0.0)
        n_rows = X_np.shape[0]
        if n_rows < 2:
            return None

        candidates: List[Tuple[float, int, str, List[float]]] = []
        # 1. IsolationForest
        try:
            if_contam: Union[str, float] = (
                self.contamination if self.contamination == "auto" else max(0.01, min(0.49, float(self.contamination)))
            )
            iforest = IsolationForest(
                n_estimators=100,
                contamination=if_contam,
                random_state=self.random_state,
            )
            iforest.fit(X_np)
            dec = np.nan_to_num(np.asarray(iforest.decision_function(X_np), dtype=np.float64), nan=0.0)
            anom = (-dec).tolist()
            preds = iforest.predict(X_np)
            rate = float(np.mean(preds == -1))
            obj = self._score_tail_separation(anom, rate)
            candidates.append((obj, 2, "sklearn_iforest", anom))
        except Exception:
            pass

        # 2. LocalOutlierFactor (novelty=True) when n_rows >= 3
        if n_rows >= 3:
            try:
                eff_nn = max(1, min(20, n_rows - 1))
                lof_contam: Union[str, float] = (
                    self.contamination if self.contamination == "auto" else max(0.01, min(0.49, float(self.contamination)))
                )
                lof = LocalOutlierFactor(
                    n_neighbors=eff_nn,
                    contamination=lof_contam,
                    novelty=True,
                )
                lof.fit(X_np)
                dec = np.nan_to_num(np.asarray(lof.decision_function(X_np), dtype=np.float64), nan=0.0)
                anom = (-dec).tolist()
                preds = lof.predict(X_np)
                rate = float(np.mean(preds == -1))
                obj = self._score_tail_separation(anom, rate)
                candidates.append((obj, 1, "sklearn_lof", anom))
            except Exception:
                pass

        if not candidates:
            return None

        _, _, best_name, best_anom = max(candidates, key=lambda item: (item[0], item[1]))
        lo = min(best_anom)
        hi = max(best_anom)
        span = hi - lo
        if span <= 1e-12:
            normed = [0.5] * n_rows
        else:
            normed = [round(max(0.0, min(1.0, (v - lo) / span)), 6) for v in best_anom]
        return normed, best_name

    def _fit_score_python_parity(self, std_mat: List[List[float]]) -> List[float]:
        n_rows = len(std_mat)
        n_cols = len(std_mat[0]) if n_rows else 0
        if n_rows == 0:
            return []
        if n_rows == 1 or n_cols == 0:
            return [0.5] * n_rows

        # Robust median/MAD deviation + kNN L2 isolation distance
        col_medians = [_median([std_mat[i][j] for i in range(n_rows)]) for j in range(n_cols)]
        col_mads = [
            max(
                _median([abs(std_mat[i][j] - col_medians[j]) for i in range(n_rows)]),
                1e-6,
            )
            for j in range(n_cols)
        ]

        k = max(1, min(5, n_rows - 1))
        if n_rows > 250:
            step = n_rows / 250.0
            ref_indices = [int(idx * step) for idx in range(250)]
        else:
            ref_indices = list(range(n_rows))

        raw_scores: List[float] = []
        for i in range(n_rows):
            row = std_mat[i]
            robust_dev = sum(abs(row[j] - col_medians[j]) / col_mads[j] for j in range(n_cols)) / float(n_cols)
            dists: List[float] = []
            for p in ref_indices:
                if p == i:
                    continue
                other = std_mat[p]
                d = math.sqrt(sum((row[j] - other[j]) ** 2 for j in range(n_cols)) / float(n_cols))
                dists.append(d)
            dists.sort()
            knn_dist = _mean(dists[:k])
            raw_scores.append(0.55 * knn_dist + 0.45 * robust_dev)

        lo = min(raw_scores)
        hi = max(raw_scores)
        span = hi - lo
        if span <= 1e-12:
            return [0.5] * n_rows
        return [round(max(0.0, min(1.0, (s - lo) / span)), 6) for s in raw_scores]

    def fit_score(self, rows: Sequence[Dict[str, Any]]) -> List[float]:
        """Fit unsupervised outlier model on `rows` and return normalized anomaly scores in [0, 1]."""
        if not rows:
            self.last_backend = "empty"
            self.last_audit_trail = {"n_rows": 0, "backend": self.last_backend}
            return []

        if len(rows) == 1:
            self.last_backend = "single_row_passthrough"
            score = self._row_heuristic_score(rows[0] if isinstance(rows[0], dict) else {})
            self.last_audit_trail = {"n_rows": 1, "backend": self.last_backend}
            return [score]

        raw_mat = _extract_feature_matrix(rows)
        std_mat = _standardize_matrix(raw_mat)

        sk_res = self._fit_score_sklearn(std_mat)
        if sk_res is not None:
            anom_scores, backend = sk_res
        else:
            anom_scores = self._fit_score_python_parity(std_mat)
            backend = "python_parity"

        # Blend unsupervised isolation score with domain severity/confidence signal
        # so high-severity deterministic defects are prioritized over benign outliers.
        blended: List[float] = []
        for idx, row in enumerate(rows):
            heur = self._row_heuristic_score(row if isinstance(row, dict) else {})
            val = 0.45 * anom_scores[idx] + 0.55 * heur
            blended.append(round(max(0.0, min(1.0, val)), 6))

        self.last_backend = backend
        self.last_audit_trail = {
            "n_rows": len(rows),
            "n_features": len(std_mat[0]) if std_mat else 0,
            "backend": backend,
        }
        return blended


def rank_stage2_candidates(
    candidates: Sequence[Dict[str, Any]],
    *,
    top_k: int = 5,
    min_keep: int = 3,
    preference: str = "balanced",
) -> Dict[str, Any]:
    """
    Stage 2 ACDSO Pareto + Anomaly triage funnel.

    Scores Stage 1 production candidates in <1s and keeps only the top `top_k`
    (3..5 when >= 3 candidates are available) non-dominated / knee-ranked anomalies
    for Stage 3 local Ollama evaluation.
    """
    t0 = time.monotonic()
    cand_list = [dict(c) for c in candidates if isinstance(c, dict)]
    if not cand_list:
        return {
            "selected": [],
            "pareto_count": 0,
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 3),
            "backend": "empty",
        }

    scorer = ACDSOAnomalyScorer()
    anom_scores = scorer.fit_score(cand_list)

    cand_objs: List[CandidateResult] = []
    idx_by_name: Dict[str, int] = {}
    for idx, row in enumerate(cand_list):
        meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        is_noise = bool(row.get("non_production_noise", meta.get("non_production_noise", False)))
        sev = _SEVERITY_RANK.get(str(row.get("severity", "MEDIUM")).strip().upper(), 0.45)
        conf = max(0.0, min(1.0, _safe_float(row.get("confidence", 0.5), 0.5)))
        det = 1.0 if bool(row.get("deterministic", False)) else 0.0
        confirmed = 1.0 if bool(row.get("confirmed", True)) else 0.0
        eng_w = _DEFAULT_ENGINE_WEIGHTS.get(str(row.get("engine", "")).strip().lower(), 0.65)
        anom = anom_scores[idx]

        metric = 0.40 * anom + 0.25 * conf + 0.20 * sev + 0.15 * eng_w + (0.08 * det)
        if is_noise:
            metric *= 0.15

        summary_text = str(row.get("summary", ""))
        prompt_tokens_est = max(40, len(summary_text) // 4 + 40)
        train_time_s = round(0.1 + min(30.0, prompt_tokens_est * 0.004), 4)
        peak_mem_mb = round(16.0 + min(512.0, len(summary_text) * 0.02), 4)
        latency_ms = round(5.0 + min(200.0, prompt_tokens_est * 0.05), 4)
        risk_penalty = round(
            max(0.0, min(1.0, (0.75 if is_noise else 0.0) + (0.25 if not det else 0.05) + (0.15 if not confirmed else 0.0))),
            4,
        )
        robustness_drop = round(
            max(0.0, min(1.0, 1.0 - (0.5 * det + 0.3 * confirmed + 0.2 * conf))),
            4,
        )

        cname = f"cand_{idx}"
        idx_by_name[cname] = idx
        objectives = (
            metric,
            math.log1p(train_time_s),
            math.log1p(peak_mem_mb),
            math.log1p(latency_ms),
            risk_penalty,
            robustness_drop,
        )
        cand_objs.append(
            CandidateResult(
                name=cname,
                pipeline=None,
                metric=metric,
                train_time_s=train_time_s,
                peak_mem_mb=peak_mem_mb,
                latency_ms_per_row=latency_ms,
                risk_penalty=risk_penalty,
                objectives=objectives,
                meta={"anomaly_score": anom, "index": idx},
            )
        )

    front = pareto_front(cand_objs)
    eff_k = min(len(cand_list), max(1, int(top_k)))
    _ = min_keep

    selected_objs: List[CandidateResult] = []
    if front:
        knee = knee_point_selection(front, preference=preference)
        selected_objs.append(knee)

    seen_names = {c.name for c in selected_objs}
    # Rank remaining front members, then dominated members by metric descending & risk ascending
    remaining_front = sorted(
        [c for c in front if c.name not in seen_names],
        key=lambda c: (-c.metric, c.risk_penalty, c.robustness_drop, c.name),
    )
    for c in remaining_front:
        if len(selected_objs) >= eff_k:
            break
        selected_objs.append(c)
        seen_names.add(c.name)

    if len(selected_objs) < eff_k:
        remaining_rest = sorted(
            [c for c in cand_objs if c.name not in seen_names],
            key=lambda c: (-c.metric, c.risk_penalty, c.robustness_drop, c.name),
        )
        for c in remaining_rest:
            if len(selected_objs) >= eff_k:
                break
            selected_objs.append(c)
            seen_names.add(c.name)

    selected_dicts: List[Dict[str, Any]] = []
    front_names = {c.name for c in front}
    for rank_idx, obj in enumerate(selected_objs, start=1):
        orig_idx = idx_by_name[obj.name]
        enriched = dict(cand_list[orig_idx])
        enriched["acdso_stage2"] = {
            "rank": rank_idx,
            "score": round(obj.metric, 6),
            "anomaly_score": obj.meta.get("anomaly_score", 0.0),
            "pareto_optimal": obj.name in front_names,
            "risk_penalty": obj.risk_penalty,
            "robustness_drop": obj.robustness_drop,
            "backend": scorer.last_backend,
        }
        selected_dicts.append(enriched)

    elapsed_ms = round((time.monotonic() - t0) * 1000.0, 3)
    return {
        "selected": selected_dicts,
        "pareto_count": len(front),
        "elapsed_ms": elapsed_ms,
        "backend": scorer.last_backend,
    }


# ---------------------------------------------------------------------------
# Contextual Bandit & Two-Lane Policy Scheduler (adapted from decision/policy.py)
# ---------------------------------------------------------------------------


@dataclass
class PolicyResult:
    """Result of contextual bandit policy training."""

    policy: Any
    mean_reward: float = 0.0
    reward_history: List[float] = field(default_factory=list)
    best_iteration: int = 0
    action_distribution: Dict[int, float] = field(default_factory=dict)
    feature_importance: Dict[str, float] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    n_actions: int = 2

    def get_action(self, observation: Sequence[float]) -> int:
        if hasattr(self.policy, "compute_single_action"):
            return int(self.policy.compute_single_action(observation))
        if hasattr(self.policy, "predict"):
            pred = self.policy.predict([list(observation)])
            return int(pred[0])
        raise ValueError("Policy does not support action computation")

    def get_action_probs(self, observation: Sequence[float]) -> List[float]:
        if hasattr(self.policy, "predict_proba"):
            probs = self.policy.predict_proba([list(observation)])[0]
            return [float(p) for p in probs]
        action = self.get_action(observation)
        size = max(self.n_actions, len(self.action_distribution), action + 1)
        probs_list = [0.0] * size
        probs_list[action] = 1.0
        return probs_list

    def summary(self) -> str:
        return (
            "Policy Learning Results\n"
            f"Mean Reward: {self.mean_reward:.4f}\n"
            f"Best Iteration: {self.best_iteration}\n"
            f"Action Distribution: {self.action_distribution}\n"
        )


class ContextualBanditEnv:
    """Lightweight pure-Python (plus optional ndarray) Contextual Bandit environment."""

    def __init__(
        self,
        X: Sequence[Sequence[float]],
        rewards: Sequence[Sequence[float]],
        feature_names: Optional[List[str]] = None,
        action_names: Optional[List[str]] = None,
        seed: int = 42,
    ) -> None:
        self.X: List[List[float]] = [
            [_safe_float(v, 0.0) for v in row] for row in X
        ]
        self.rewards: List[List[float]] = [
            [_safe_float(v, 0.0) for v in row] for row in rewards
        ]
        if not self.X or not self.rewards:
            raise ValueError("ContextualBanditEnv requires non-empty X and rewards.")
        if len(self.X) != len(self.rewards):
            raise ValueError("X and rewards must have identical row counts.")

        self.n_samples = len(self.X)
        self.n_features = len(self.X[0])
        self.n_actions = len(self.rewards[0])
        if self.n_actions < 1:
            raise ValueError("ContextualBanditEnv requires at least 1 action.")

        self.feature_names = feature_names or [f"f{i}" for i in range(self.n_features)]
        self.action_names = action_names or [f"a{i}" for i in range(self.n_actions)]
        self._current_idx = 0
        self._rng = random.Random(seed)

    def reset(self, seed: Optional[int] = None) -> Tuple[List[float], Dict[str, Any]]:
        if seed is not None:
            self._rng = random.Random(seed)
        self._current_idx = self._rng.randrange(0, self.n_samples)
        return list(self.X[self._current_idx]), {"idx": self._current_idx}

    def step(self, action: int) -> Tuple[List[float], float, bool, bool, Dict[str, Any]]:
        eff_action = max(0, min(self.n_actions - 1, int(action)))
        reward = float(self.rewards[self._current_idx][eff_action])
        obs = list(self.X[self._current_idx])
        info = {
            "idx": self._current_idx,
            "action": eff_action,
            "action_name": self.action_names[eff_action],
        }
        return obs, reward, True, False, info


class _PurePythonBanditPolicy:
    """
    Context-aware pure-Python L2 multinomial logistic bandit policy (zero external deps).
    Falls back cleanly to static probability vector when constructed without linear weights.
    """

    def __init__(
        self,
        n_actions: int,
        probs: Sequence[float],
        best_action: int,
        *,
        weights_matrix: Optional[Sequence[Sequence[float]]] = None,
        biases: Optional[Sequence[float]] = None,
        means: Optional[Sequence[float]] = None,
        stds: Optional[Sequence[float]] = None,
    ) -> None:
        self.n_actions = max(1, int(n_actions))
        total = sum(max(0.0, float(p)) for p in probs)
        if total <= 0.0:
            self._probs = [1.0 / self.n_actions] * self.n_actions
        else:
            self._probs = [max(0.0, float(p)) / total for p in probs]
        self._best_action = max(0, min(self.n_actions - 1, int(best_action)))
        self._W: Optional[List[List[float]]] = (
            [[float(v) for v in row] for row in weights_matrix]
            if weights_matrix is not None and len(weights_matrix) == self.n_actions
            else None
        )
        self._b: Optional[List[float]] = (
            [float(v) for v in biases]
            if biases is not None and len(biases) == self.n_actions
            else None
        )
        self._means: List[float] = [float(v) for v in (means or ())]
        self._stds: List[float] = [max(1e-6, float(v)) for v in (stds or ())]

    def _row_probs(self, row: Sequence[float]) -> List[float]:
        if self._W is None or self._b is None or not self._means:
            return list(self._probs)
        n_feat = len(self._means)
        x_s = [
            ((_safe_float(row[j], 0.0) if j < len(row) else 0.0) - self._means[j]) / self._stds[j]
            for j in range(n_feat)
        ]
        logits: List[float] = []
        for a in range(self.n_actions):
            w_row = self._W[a]
            dot = self._b[a] + sum(w_row[j] * x_s[j] for j in range(min(len(w_row), n_feat)))
            logits.append(dot)
        max_l = max(logits)
        exps = [math.exp(max(-20.0, min(20.0, lv - max_l))) for lv in logits]
        tot = sum(exps) or 1.0
        return [e / tot for e in exps]

    def predict(self, X: Sequence[Sequence[float]]) -> List[int]:
        out: List[int] = []
        for row in X:
            p = self._row_probs(row)
            out.append(max(range(self.n_actions), key=lambda a: (p[a], -a)))
        return out

    def predict_proba(self, X: Sequence[Sequence[float]]) -> List[List[float]]:
        return [self._row_probs(row) for row in X]


class _SklearnWrappedPolicy:
    """Safe wrapper around sklearn LogisticRegression ensuring full n_actions probability vectors."""

    def __init__(self, clf: Any, means: List[float], stds: List[float], n_actions: int) -> None:
        self.clf = clf
        self.means = means
        self.stds = stds
        self.n_actions = n_actions

    def _transform(self, X: Sequence[Sequence[float]]) -> List[List[float]]:
        out: List[List[float]] = []
        for row in X:
            r_len = len(row)
            out.append(
                [
                    ((_safe_float(row[j], 0.0) if j < r_len else 0.0) - self.means[j]) / self.stds[j]
                    for j in range(len(self.means))
                ]
            )
        return out

    def predict(self, X: Sequence[Sequence[float]]) -> List[int]:
        X_s = self._transform(X)
        return [int(v) for v in self.clf.predict(X_s)]

    def predict_proba(self, X: Sequence[Sequence[float]]) -> List[List[float]]:
        X_s = self._transform(X)
        raw_probs = self.clf.predict_proba(X_s)
        classes = [int(c) for c in getattr(self.clf, "classes_", [])]
        result: List[List[float]] = []
        for row_p in raw_probs:
            full = [0.0] * self.n_actions
            for cls_id, prob in zip(classes, row_p):
                if 0 <= cls_id < self.n_actions:
                    full[cls_id] = float(prob)
            tot = sum(full)
            if tot <= 0.0:
                full = [1.0 / self.n_actions] * self.n_actions
            result.append(full)
        return result


class PolicyLearner:
    """
    Contextual bandit policy learner adapted from `ACDSO/decision/policy.py`.

    Fixes upstream bugs:
    - Clips standardized reward advantages to `[-10.0, 10.0]` before `exp(...)`.
    - Guards `std == 0` columns and single-class `y` (`len(set(y)) < 2`).
    - Falls back cleanly to deterministic pure-Python softmax bandit when
      `sklearn` / `numpy` are absent.
    """

    def __init__(
        self,
        env: ContextualBanditEnv,
        algorithm: str = "PPO",
        config: Optional[Dict[str, Any]] = None,
        *,
        seed: int = 42,
        prefer_sklearn: bool = True,
    ) -> None:
        self.env = env
        self.algorithm = algorithm
        self.config = dict(config or {})
        self.seed = int(seed)
        self.prefer_sklearn = bool(prefer_sklearn)
        self._result: Optional[PolicyResult] = None

    def train(
        self,
        n_iterations: int = 50,
        checkpoint_freq: int = 10,
        verbose: bool = False,
    ) -> PolicyResult:
        _ = checkpoint_freq, verbose
        rng = random.Random(self.seed)
        n_actions = self.env.n_actions
        rollouts = max(n_actions * 4, int(n_iterations) * 10)

        observations: List[List[float]] = []
        actions: List[int] = []
        rewards: List[float] = []
        counts = [0] * n_actions
        reward_sums = [0.0] * n_actions

        for step_idx in range(rollouts):
            obs, _ = self.env.reset()
            # Ensure initial exploration across all actions, then UCB1 + epsilon-greedy
            if step_idx < n_actions:
                action = step_idx
            elif rng.random() < 0.15:
                action = rng.randrange(0, n_actions)
            else:
                total_steps = max(1, step_idx)
                action = max(
                    range(n_actions),
                    key=lambda a: (
                        (reward_sums[a] / counts[a]) + math.sqrt(0.5 * math.log(total_steps + 1) / counts[a])
                        if counts[a] > 0
                        else float("inf")
                    ),
                )

            _, reward, _, _, _ = self.env.step(action)
            observations.append(obs)
            actions.append(action)
            rewards.append(reward)
            counts[action] += 1
            reward_sums[action] += reward

        r_mean = _mean(rewards)
        r_std = _std(rewards, floor=1e-6)
        weights = [
            math.exp(max(-10.0, min(10.0, (r - r_mean) / r_std)))
            for r in rewards
        ]

        unique_actions = set(actions)
        wrapped_policy: Any = None
        backend = "python_bandit"

        if self.prefer_sklearn and len(unique_actions) >= 2:
            try:
                import numpy as np  # type: ignore
                from sklearn.linear_model import LogisticRegression  # type: ignore

                n_feat = self.env.n_features
                means = [_mean([obs[j] for obs in observations]) for j in range(n_feat)]
                stds = [_std([obs[j] for obs in observations], floor=1e-6) for j in range(n_feat)]
                X_scaled = np.asarray(
                    [
                        [(obs[j] - means[j]) / stds[j] for j in range(n_feat)]
                        for obs in observations
                    ],
                    dtype=np.float64,
                )
                y_arr = np.asarray(actions, dtype=int)
                w_arr = np.asarray(weights, dtype=np.float64)
                clf = LogisticRegression(max_iter=500, random_state=self.seed)
                clf.fit(X_scaled, y_arr, sample_weight=w_arr)
                wrapped_policy = _SklearnWrappedPolicy(clf, means, stds, n_actions)
                backend = "sklearn_logreg"
            except Exception:
                wrapped_policy = None

        if wrapped_policy is None:
            weighted_action_scores = [0.0] * n_actions
            weighted_action_totals = [0.0] * n_actions
            for a, w, r in zip(actions, weights, rewards):
                weighted_action_scores[a] += w * (1.0 + max(-10.0, min(10.0, (r - r_mean) / r_std)))
                weighted_action_totals[a] += w
            avg_action = [
                (weighted_action_scores[a] / weighted_action_totals[a]) if weighted_action_totals[a] > 0 else 0.0
                for a in range(n_actions)
            ]
            max_avg = max(avg_action) if avg_action else 0.0
            exps = [math.exp(max(-10.0, min(10.0, v - max_avg))) for v in avg_action]
            exp_sum = sum(exps) or 1.0
            probs = [e / exp_sum for e in exps]
            best_action = max(range(n_actions), key=lambda a: (avg_action[a], -a))

            # Fit pure-Python context-aware L2 weighted multinomial logistic regression
            n_feat = self.env.n_features
            w_mat: Optional[List[List[float]]] = None
            b_vec: Optional[List[float]] = None
            means_py: List[float] = []
            stds_py: List[float] = []
            if len(unique_actions) >= 2 and n_feat > 0 and observations:
                means_py = [_mean([obs[j] for obs in observations]) for j in range(n_feat)]
                stds_py = [_std([obs[j] for obs in observations], floor=1e-6) for j in range(n_feat)]
                X_s = [
                    [(obs[j] - means_py[j]) / stds_py[j] for j in range(n_feat)]
                    for obs in observations
                ]
                w_sum = sum(weights) or 1.0
                norm_w = [w / w_sum for w in weights]
                w_mat = [[0.0] * n_feat for _ in range(n_actions)]
                b_vec = [0.0] * n_actions
                lr = 0.35
                l2 = 0.05
                for _ in range(60):
                    grad_w = [[0.0] * n_feat for _ in range(n_actions)]
                    grad_b = [0.0] * n_actions
                    for x_row, act, sw in zip(X_s, actions, norm_w):
                        logits = [
                            b_vec[a] + sum(w_mat[a][j] * x_row[j] for j in range(n_feat))
                            for a in range(n_actions)
                        ]
                        ml = max(logits)
                        ex = [math.exp(max(-20.0, min(20.0, lv - ml))) for lv in logits]
                        es = sum(ex) or 1.0
                        for a in range(n_actions):
                            target = 1.0 if a == act else 0.0
                            diff = sw * (target - (ex[a] / es))
                            grad_b[a] += diff
                            for j in range(n_feat):
                                grad_w[a][j] += diff * x_row[j]
                    for a in range(n_actions):
                        b_vec[a] += lr * grad_b[a]
                        for j in range(n_feat):
                            w_mat[a][j] += lr * (grad_w[a][j] - l2 * w_mat[a][j])
                backend = "python_contextual_logreg"

            wrapped_policy = _PurePythonBanditPolicy(
                n_actions,
                probs,
                best_action,
                weights_matrix=w_mat,
                biases=b_vec,
                means=means_py,
                stds=stds_py,
            )

        total_act = max(1, len(actions))
        action_dist = {a: counts[a] / float(total_act) for a in range(n_actions)}

        self._result = PolicyResult(
            policy=wrapped_policy,
            mean_reward=r_mean,
            reward_history=[r_mean],
            best_iteration=0,
            action_distribution=action_dist,
            config={
                "algorithm": self.algorithm,
                "backend": backend,
                "n_iterations": n_iterations,
                **self.config,
            },
            n_actions=n_actions,
        )
        return self._result

    def evaluate(self, n_episodes: int = 50) -> Dict[str, float]:
        if self._result is None:
            raise RuntimeError("Must train policy before evaluation")
        rewards: List[float] = []
        for _ in range(max(1, int(n_episodes))):
            obs, _ = self.env.reset()
            action = self._result.get_action(obs)
            _, reward, _, _, _ = self.env.step(action)
            rewards.append(reward)
        return {
            "mean_reward": _mean(rewards),
            "std_reward": _std(rewards, floor=0.0),
            "min_reward": min(rewards),
            "max_reward": max(rewards),
            "n_episodes": float(len(rewards)),
        }


class TwoLanePolicyScheduler:
    """
    Loop 5 Two-Lane Self-Adapting Queue Scheduler (`decision/policy.py` wrapper).

    Invariant (R4):
    - While `signal_score < signal_threshold` (default `1.0`), `lane1_slots`
      MUST be at least `math.ceil(queue_capacity * 0.5)`, reserved for unlocked,
      100%-response-efficiency, low-competition VDPs (`henkel_vdp`,
      `servicenow-disclosure`, `common_codes`).
    - When `signal_score >= signal_threshold`, the contextual bandit policy shifts
      capacity dynamically toward Lane 2 high-bounty targets (`anthropic`,
      `common_codes`, `oppo_bbp`, `amazonvrp`, `temu`, and newly unlocked
      programs such as `shopify`, `vercel`, `cloudflare`).
    """

    def __init__(
        self,
        *,
        lane1_programs: Sequence[str] = ("henkel_vdp", "servicenow-disclosure", "common_codes"),
        lane2_programs: Sequence[str] = ("anthropic", "common_codes", "oppo_bbp", "amazonvrp", "temu"),
        signal_threshold: float = 1.0,
        seed: int = 42,
    ) -> None:
        self.lane1_programs = tuple(lane1_programs)
        self.lane2_programs = tuple(lane2_programs)
        self.signal_threshold = float(signal_threshold)
        self.seed = int(seed)

    def allocate_slots(
        self,
        queue_capacity: int,
        *,
        signal_score: float,
        lane1_reward_history: Optional[Sequence[float]] = None,
        lane2_reward_history: Optional[Sequence[float]] = None,
    ) -> Dict[str, Any]:
        cap = max(0, int(queue_capacity))
        sig = _safe_float(signal_score, 0.0)
        if cap == 0:
            return {
                "queue_capacity": 0,
                "signal_score": sig,
                "signal_threshold": self.signal_threshold,
                "lane1_slots": 0,
                "lane2_slots": 0,
                "lane1_reserved_floor": 0,
                "policy_backend": "zero_capacity",
            }

        l1_hist = [_safe_float(v, 0.0) for v in (lane1_reward_history or (0.85, 0.90))]
        l2_hist = [_safe_float(v, 0.0) for v in (lane2_reward_history or (0.65, 0.70))]
        l1_mean = _mean(l1_hist)
        l2_mean = _mean(l2_hist)

        # Build contextual bandit contexts over signal regime and observed lane rewards
        sig_ratio = max(0.0, min(2.0, sig / max(1e-6, self.signal_threshold)))
        X_ctx = [
            [0.1, l1_mean, l2_mean, float(len(self.lane1_programs))],
            [0.5, l1_mean, l2_mean, float(len(self.lane1_programs))],
            [1.0, l1_mean, l2_mean, float(len(self.lane2_programs))],
            [1.5, l1_mean, l2_mean, float(len(self.lane2_programs))],
        ]
        # Action 0 = prioritize Lane 1 (Signal lift), Action 1 = prioritize Lane 2 (Bounty EV)
        rewards_ctx = [
            [max(0.1, l1_mean + 0.5), max(0.0, l2_mean - 0.1)],
            [max(0.1, l1_mean + 0.3), max(0.0, l2_mean)],
            [max(0.0, l1_mean * 0.4), max(0.1, l2_mean + 0.6)],
            [max(0.0, l1_mean * 0.3), max(0.1, l2_mean + 0.8)],
        ]
        env = ContextualBanditEnv(
            X=X_ctx,
            rewards=rewards_ctx,
            feature_names=["signal_ratio", "lane1_mean", "lane2_mean", "lane_breadth"],
            action_names=["lane1_signal_vdp", "lane2_bounty_diff"],
            seed=self.seed,
        )
        learner = PolicyLearner(env, seed=self.seed)
        policy_res = learner.train(n_iterations=25)
        probs = policy_res.get_action_probs(
            [sig_ratio, l1_mean, l2_mean, float(len(self.lane2_programs))]
        )
        p_lane1 = _safe_float(probs[0] if len(probs) >= 1 else 0.5, 0.5)
        learned_lane1 = int(round(cap * p_lane1))

        reserved_floor = math.ceil(cap * 0.5) if sig < self.signal_threshold else 0
        if sig < self.signal_threshold:
            lane1_slots = max(reserved_floor, learned_lane1)
            lane1_slots = min(cap, max(reserved_floor, lane1_slots))
        else:
            # High-signal regime: allow dynamic shift to Lane 2 while keeping >= 1 slot if cap >= 4
            min_explore = 1 if cap >= 4 else 0
            lane1_slots = max(min_explore, min(cap, learned_lane1))
            if lane1_slots > cap // 2 and l2_mean >= l1_mean * 0.5:
                lane1_slots = max(min_explore, cap // 4)

        lane2_slots = cap - lane1_slots
        return {
            "queue_capacity": cap,
            "signal_score": sig,
            "signal_threshold": self.signal_threshold,
            "lane1_slots": lane1_slots,
            "lane2_slots": lane2_slots,
            "lane1_reserved_floor": reserved_floor,
            "lane1_programs": list(self.lane1_programs),
            "lane2_programs": list(self.lane2_programs),
            "policy_probs": [round(float(p), 4) for p in probs],
            "policy_backend": str(policy_res.config.get("backend", "python_bandit")),
        }


__all__ = [
    "OBJECTIVE_DIRECTIONS",
    "OBJECTIVE_NAMES",
    "CandidateResult",
    "MultiObjectiveCandidate",
    "dominates",
    "pareto_front",
    "knee_point_selection",
    "generalized_dominates",
    "generalized_pareto_front",
    "select_pareto_knee",
    "filter_by_constraints",
    "ACDSOAnomalyScorer",
    "rank_stage2_candidates",
    "PolicyResult",
    "ContextualBanditEnv",
    "PolicyLearner",
    "TwoLanePolicyScheduler",
]
