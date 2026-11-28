"""
ACDSO-Adapted ML Diff Ranker, Surface-to-Scanner Router, Recon Asset & JS Bundle
Clusterer, and Streaming HTTP Anomaly Scorer (`engine/ml_diff_and_recon_ranker.py`).
====================================================================================
Self-contained pure-Python stdlib implementation (zero imports from `D:\\harfile\\ACDSO`)
adapting ACDSO `scale.py`, `nlp.py`, `multilabel.py`, `clustering.py`, `anomaly.py`,
and `timeseries/risk.py` so RFCHunt prioritizes `<72h` commits, routes ONLY matching
diff-scoped scanners, clusters homogeneous CDN/marketing hosts & JS bundles, and flags
anomalous API/admin endpoints faster than competing researchers.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from engine.ml_program_selector import signed_hash_features, signed_log1p
from engine.program_eligibility_db import ProgramEligibilityDB

# ---------------------------------------------------------------------------
# 1. O(1)-Memory Welford Online Scaler & Commit Velocity Burst Detector
# ---------------------------------------------------------------------------


class WelfordOnlineScaler:
    """
    O(1)-memory streaming mean/variance/z-score tracker adapted from ACDSO
    `scale.py` (`_StreamingNumericScaler`).
    """

    def __init__(self, n_features: int) -> None:
        self.n_features = max(1, int(n_features))
        self.count: int = 0
        self.mean: list[float] = [0.0] * self.n_features
        self.m2: list[float] = [0.0] * self.n_features

    def partial_fit_one(self, row: Sequence[float]) -> None:
        self.count += 1
        inv_n = 1.0 / float(self.count)
        for j in range(self.n_features):
            x = float(row[j]) if j < len(row) and math.isfinite(float(row[j])) else 0.0
            delta = x - self.mean[j]
            self.mean[j] += delta * inv_n
            delta2 = x - self.mean[j]
            self.m2[j] += delta * delta2

    def partial_fit(self, rows: Sequence[Sequence[float]]) -> WelfordOnlineScaler:
        for r in rows:
            self.partial_fit_one(r)
        return self

    def stds(self, *, floor: float = 1e-6) -> list[float]:
        if self.count <= 1:
            return [max(1.0, floor)] * self.n_features
        return [
            max(floor, math.sqrt(max(0.0, self.m2[j] / float(self.count))))
            for j in range(self.n_features)
        ]

    def transform_one(self, row: Sequence[float], *, clip: float = 8.0) -> list[float]:
        st = self.stds()
        out: list[float] = []
        for j in range(self.n_features):
            x = float(row[j]) if j < len(row) and math.isfinite(float(row[j])) else 0.0
            z = (x - self.mean[j]) / st[j]
            out.append(max(-clip, min(clip, z)))
        return out


class CommitVelocityBurstDetector:
    """
    Rolling Welford z-score burst detector over daily commit/PR counts per repo
    (adapted from ACDSO `timeseries/risk.py`). Flags sudden rushed feature launches
    or silent security patch bursts (`z > 2.0`).
    """

    def __init__(self, *, z_threshold: float = 2.0) -> None:
        self.z_threshold = max(0.5, float(z_threshold))
        self._scalers: dict[str, WelfordOnlineScaler] = {}

    def observe_and_score(self, repo_slug: str, current_daily_commits: float) -> tuple[float, bool]:
        key = str(repo_slug or "").strip().lower()
        val = max(0.0, float(current_daily_commits or 0.0))
        scaler = self._scalers.get(key)
        if scaler is None:
            scaler = WelfordOnlineScaler(1)
            self._scalers[key] = scaler
        if scaler.count >= 3:
            z = scaler.transform_one([val])[0]
        else:
            # Cold-start burst heuristic before 3 days of history exist
            z = max(0.0, (val - 3.0) / 2.5) if val > 3.0 else 0.0
        scaler.partial_fit_one([val])
        return round(z, 4), bool(z >= self.z_threshold)


# ---------------------------------------------------------------------------
# 2. Multi-Label Surface-to-Scanner Router (adapted from ACDSO multilabel.py)
# ---------------------------------------------------------------------------

ALL_SURFACES: tuple[str, ...] = (
    "wildcard_web",
    "rest_graphql_api",
    "mobile_android_ios",
    "oss_source_code",
    "ai_llm_mcp",
    "http_framing_proxy",
    "auth_jwt_sdjwt",
    "wasm_sandbox",
    "gha_ci",
)

_SURFACE_TO_SCANNERS: dict[str, tuple[str, ...]] = {
    "wildcard_web": ("parity_auditor", "trufflehog", "rea"),
    "rest_graphql_api": ("api_jwt_sdjwt", "parity_auditor", "trufflehog"),
    "mobile_android_ios": ("mobile_mobsf", "trufflehog", "parity_auditor"),
    "oss_source_code": ("parity_auditor", "trufflehog"),
    "ai_llm_mcp": ("ai_infra_guard", "parity_auditor", "trufflehog"),
    "http_framing_proxy": ("parity_auditor", "differential_oracle", "z3_formal"),
    "auth_jwt_sdjwt": ("api_jwt_sdjwt", "parity_auditor", "z3_formal"),
    "wasm_sandbox": ("parity_auditor", "z3_formal", "lean4"),
    "gha_ci": ("gha_workflow_scanners", "trufflehog", "parity_auditor"),
}

_SURFACE_PATH_HINTS: dict[str, tuple[str, ...]] = {
    "gha_ci": (".github/workflows/", "action.yml", "action.yaml", ".gitlab-ci"),
    "mobile_android_ios": ("androidmanifest.xml", "info.plist", "network_security_config.xml", ".kt", ".java", ".swift", ".m", ".mm", ".apk", ".ipa", "gradle"),
    "ai_llm_mcp": ("prompt", "mcp", "agent", "llm", "ollama", "vllm", "ray", "gradio", "langchain", "openai", "anthropic", "tool_call", "dockerfile", "pickle", "torch"),
    "auth_jwt_sdjwt": ("jwt", "jws", "jwk", "sdjwt", "sd-jwt", "oidc", "oauth", "openid", "saml", "auth", "token", "session", "cookie", "csrf", "rbac", "acl"),
    "rest_graphql_api": ("openapi", "swagger", "graphql", "schema.graphql", "/api/", "routes", "router", "controller", "endpoint", "handler", "webhook", "rpc"),
    "http_framing_proxy": ("proxy", "http", "h2", "http2", "hpack", "chunk", "header", "crlf", "smuggl", "nginx", "envoy", "redirect", "ssrf", "url", "socket", "tls"),
    "wasm_sandbox": ("sandbox", "seccomp", "appcontainer", "wasm", "symlink", "realpath", "chroot", "container", "isolation", "policy", "cedar", "rego"),
    "wildcard_web": (".html", ".jsx", ".tsx", ".vue", ".svelte", "webpack", "bundle", "electron", "preload", "ipc", "csp", "cors", "xss"),
}


class SurfaceToScannerRouter:
    """
    Adapted ACDSO multi-label router predicting active attack surfaces from
    changed file paths, commit text, and scope metadata -> dispatches ONLY the
    matching Stage 1 scanners for sub-second diff scanning.
    """

    def predict_surfaces(
        self,
        *,
        changed_files: Sequence[str] = (),
        text_context: str = "",
        scope_asset_types: dict[str, int] | None = None,
    ) -> dict[str, float]:
        blob_files = " ".join(str(f or "").replace("\\", "/").lower() for f in changed_files)
        blob_all = f"{blob_files} {(text_context or '').lower()}"
        probs: dict[str, float] = {s: 0.0 for s in ALL_SURFACES}

        for surface, hints in _SURFACE_PATH_HINTS.items():
            hits = sum(1 for h in hints if h in blob_all)
            if hits > 0:
                probs[surface] = round(min(0.98, 0.45 + 0.18 * hits), 4)

        if changed_files:
            probs["oss_source_code"] = max(probs["oss_source_code"], 0.85)

        if scope_asset_types:
            if int(scope_asset_types.get("WILDCARD", 0) or 0) > 0:
                probs["wildcard_web"] = max(probs["wildcard_web"], 0.80)
            if int(scope_asset_types.get("API", 0) or 0) > 0:
                probs["rest_graphql_api"] = max(probs["rest_graphql_api"], 0.85)
            if int(scope_asset_types.get("MOBILE", 0) or 0) > 0:
                probs["mobile_android_ios"] = max(probs["mobile_android_ios"], 0.85)
            if int(scope_asset_types.get("AI_MODEL", 0) or 0) > 0:
                probs["ai_llm_mcp"] = max(probs["ai_llm_mcp"], 0.90)
            if int(scope_asset_types.get("SOURCE_CODE", 0) or 0) > 0:
                probs["oss_source_code"] = max(probs["oss_source_code"], 0.85)

        return probs

    def route_scanners(
        self,
        *,
        changed_files: Sequence[str] = (),
        text_context: str = "",
        scope_asset_types: dict[str, int] | None = None,
        threshold: float = 0.40,
    ) -> dict[str, Any]:
        probs = self.predict_surfaces(
            changed_files=changed_files,
            text_context=text_context,
            scope_asset_types=scope_asset_types,
        )
        active_surfaces = [s for s, p in probs.items() if p >= threshold]
        scanners: list[str] = []
        seen: set[str] = set()
        for surf in sorted(active_surfaces, key=lambda s: -probs[s]):
            for sc in _SURFACE_TO_SCANNERS.get(surf, ()):
                if sc not in seen:
                    seen.add(sc)
                    scanners.append(sc)
        if not scanners:
            scanners = ["parity_auditor", "trufflehog"]
        return {
            "active_surfaces": active_surfaces,
            "surface_probabilities": probs,
            "recommended_scanners": scanners,
        }


# ---------------------------------------------------------------------------
# 3. ML Commit / PR Diff Prioritizer & Dynamic Unlocked Watchlist Sync
# ---------------------------------------------------------------------------

_HIGH_RISK_DIFF_TOKENS: tuple[tuple[str, float], ...] = (
    ("sanitize", 1.8),
    ("o_nofollow", 2.2),
    ("symlink", 2.0),
    ("traversal", 1.9),
    ("ssrf", 2.1),
    ("allowfrom", 1.8),
    ("redirect", 1.5),
    ("oauth", 1.7),
    ("oidc", 1.7),
    ("jwt", 1.7),
    ("sd-jwt", 1.8),
    ("authz", 1.9),
    ("rbac", 1.6),
    ("verify", 1.4),
    ("deserialize", 2.0),
    ("pickle", 2.1),
    ("marshal", 1.9),
    ("shell=true", 2.2),
    ("exec(", 1.8),
    ("eval(", 1.8),
    ("netlink", 2.0),
    ("copy_from_user", 2.2),
    ("ioctl", 1.9),
    ("nla_len", 2.1),
    ("csp", 1.4),
    ("srcdoc", 1.7),
    ("postmessage", 1.6),
    ("graphql", 1.4),
    ("pull_request_target", 2.1),
    ("mcp", 1.6),
    ("prompt", 1.3),
    ("cve-", 2.2),
    ("security", 1.5),
    ("bypass", 1.8),
)


class CommitDiffRanker:
    """
    ML-enhanced `<72h` commit/PR/release prioritizer combining:
      - Continuous exponential recency urgency `exp(-age_hours / 24.0)`
      - Security-fix & trust-boundary diff token density (Loop 2 sibling-parity bonus)
      - Structural diff size & code-file concentration
      - Program ML priority score + repo saturation decay + commit velocity burst z-score
      - Surface-to-Scanner routing plan per candidate
    """

    def __init__(
        self,
        *,
        burst_detector: CommitVelocityBurstDetector | None = None,
        router: SurfaceToScannerRouter | None = None,
    ) -> None:
        self.burst_detector = burst_detector or CommitVelocityBurstDetector()
        self.router = router or SurfaceToScannerRouter()

    def score_candidate(
        self,
        candidate: dict[str, Any],
        *,
        program_ml_score: float = 0.55,
        repo_stars: int = 0,
        daily_commit_rate: float | None = None,
    ) -> dict[str, Any]:
        age_hours = max(0.0, float(candidate.get("age_hours", 24.0) or 0.0))
        recency_urgency = math.exp(-age_hours / 24.0)

        event_type = str(candidate.get("event_type") or "commit").lower()
        event_bonus = {"release": 0.14, "merged_pr": 0.12, "commit": 0.08}.get(event_type, 0.06)

        changed_files = [str(f) for f in (candidate.get("changed_files") or []) if f]
        title = str(candidate.get("title") or "")
        body = str(candidate.get("body") or "")
        patch_text = str(candidate.get("patch") or "")
        full_text = f"{title}\n{body}\n{patch_text[:1500]}\n" + " ".join(changed_files)
        low_text = full_text.lower()

        # Token & security-fix signal density
        matched_signals: list[str] = []
        token_weight_sum = 0.0
        for tok, w in _HIGH_RISK_DIFF_TOKENS:
            if tok in low_text:
                matched_signals.append(tok)
                token_weight_sum += w
        security_signal_score = 1.0 - math.exp(-token_weight_sum / 4.5)
        triggers_sibling_parity = len(matched_signals) >= 1

        # Code file density (suppress docs/test-only commits)
        non_code_suffixes = (".md", ".txt", ".rst", ".png", ".jpg", ".svg", ".lock")
        code_files = [
            f for f in changed_files
            if not f.lower().endswith(non_code_suffixes)
            and not any(seg in f.lower().split("/") for seg in ("test", "tests", "__tests__", "spec", "docs", "fixtures"))
        ]
        code_ratio = (len(code_files) / float(len(changed_files))) if changed_files else 0.5
        base_surface = min(1.0, float(candidate.get("surface_score", 0) or 0) / 100.0)

        # Saturation penalty for ultra-popular mega-repos (higher competition)
        sat_penalty = min(0.25, signed_log1p(float(max(0, repo_stars))) / 48.0)

        # Commit velocity burst bonus
        burst_z = 0.0
        is_burst = False
        if daily_commit_rate is not None:
            burst_z, is_burst = self.burst_detector.observe_and_score(
                str(candidate.get("repo") or ""),
                daily_commit_rate,
            )
        burst_bonus = 0.12 if is_burst else min(0.08, max(0.0, burst_z) * 0.03)

        # Hashed diff feature vector (for downstream anomaly / dedup clustering)
        diff_hash_vec = signed_hash_features(full_text, dim=8)

        ml_priority = (
            0.30 * recency_urgency
            + 0.28 * security_signal_score
            + 0.16 * base_surface
            + 0.14 * float(program_ml_score)
            + 0.12 * code_ratio
            + event_bonus
            + burst_bonus
            - sat_penalty
        )
        ml_priority = max(0.0, min(1.0, ml_priority))

        routing = self.router.route_scanners(
            changed_files=changed_files,
            text_context=f"{title} {body[:400]}",
        )

        return {
            **candidate,
            "ml_priority_score": round(ml_priority, 5),
            "recency_urgency": round(recency_urgency, 5),
            "security_signal_score": round(security_signal_score, 5),
            "matched_security_signals": matched_signals[:10],
            "triggers_sibling_parity": triggers_sibling_parity,
            "code_file_ratio": round(code_ratio, 4),
            "velocity_burst_z": burst_z,
            "velocity_burst_flagged": is_burst,
            "active_surfaces": routing["active_surfaces"],
            "recommended_scanners": routing["recommended_scanners"],
            "diff_hash_fingerprint": [round(v, 4) for v in diff_hash_vec],
        }

    def rank_candidates(
        self,
        candidates: Sequence[dict[str, Any]],
        *,
        program_scores: dict[str, float] | None = None,
        repo_stars_map: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        prog_map = {k.lower(): float(v) for k, v in (program_scores or {}).items()}
        stars_map = {k.lower(): int(v) for k, v in (repo_stars_map or {}).items()}
        scored: list[dict[str, Any]] = []
        for c in candidates:
            prog = str(c.get("program") or "").lower()
            repo = str(c.get("repo") or "").lower()
            scored.append(
                self.score_candidate(
                    c,
                    program_ml_score=prog_map.get(prog, 0.55),
                    repo_stars=stars_map.get(repo, 0),
                )
            )
        scored.sort(
            key=lambda x: (
                -float(x.get("ml_priority_score", 0.0)),
                float(x.get("age_hours", 999.0)),
                str(x.get("repo") or ""),
            )
        )
        for idx, row in enumerate(scored, start=1):
            row["ml_rank"] = idx
        return scored


def build_unlocked_watchlist_from_db(
    *,
    eligibility_db: ProgramEligibilityDB | None = None,
    db_path: str | None = None,
    min_efficiency_pct: float = 80.0,
) -> list[dict[str, Any]]:
    """
    Dynamically synthesizes a WatchTarget list strictly from UNLOCKED programs'
    `in_scope_repos` in `ProgramEligibilityDB`, eliminating blocked-program deadweight.
    """
    db = eligibility_db if eligibility_db is not None else ProgramEligibilityDB(db_path=db_path)
    unlocked = db.list_unlocked()
    if not unlocked:
        db.seed_observed_hackerone_baseline()
        unlocked = db.list_unlocked()

    targets: list[dict[str, Any]] = []
    seen_repos: set[str] = set()
    for rec in unlocked:
        if rec.response_efficiency_pct is not None and rec.response_efficiency_pct < min_efficiency_pct:
            continue
        tier = "PAID_CASH" if (rec.offers_bounties or (rec.bounty_max_usd or 0) > 0) else "VDP_FAST_SIGNAL"
        repos = rec.in_scope_repos
        if not repos and (rec.scope_summary or rec.notes):
            from engine.program_eligibility_db import parse_scope_prose_metadata

            parsed_meta = parse_scope_prose_metadata(
                rec.handle,
                rec.scope_summary,
                rec.notes,
                bounty_max_usd=rec.bounty_max_usd,
            )
            repos = tuple(parsed_meta.get("in_scope_repos") or ())
        for repo_url in repos:
            m = re.search(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", repo_url)
            if not m:
                continue
            slug = m.group(1).removesuffix(".git")
            key = slug.lower()
            if key in seen_repos:
                continue
            seen_repos.add(key)
            targets.append(
                {
                    "program": rec.handle,
                    "repo": slug,
                    "bounty_tier": tier,
                    "scope_asset": repo_url,
                }
            )
    return targets


# ---------------------------------------------------------------------------
# 4. Recon Asset & JS Bundle Clusterer + Streaming HTTP Anomaly Scorer
#    (adapted from ACDSO clustering.py, anomaly.py, scale.py)
# ---------------------------------------------------------------------------

_HIGH_VALUE_RECON_TOKENS: tuple[str, ...] = (
    "graphql",
    "swagger",
    "openapi",
    "api-docs",
    "oidc",
    "oauth",
    "jwks",
    ".well-known",
    "admin",
    "internal",
    "staging",
    "sandbox",
    "debug",
    "metrics",
    "actuator",
    "mcp",
    "prompt",
    "completions",
    "postmessage",
    "websocket",
    "token",
    "apikey",
    "api_key",
    "sourcemap",
    ".map",
)


def _extract_recon_feature_vector(asset: dict[str, Any]) -> tuple[list[float], list[str]]:
    """Extracts a compact numeric + hashed-metadata feature vector for an HTTP endpoint / JS bundle."""
    url = str(asset.get("url") or asset.get("endpoint") or asset.get("host") or "")
    status_code = int(asset.get("status_code") or asset.get("status") or 200)
    content_len = max(0, int(asset.get("content_length") or asset.get("length") or 0))
    words = max(0, int(asset.get("words") or asset.get("word_count") or 0))
    title = str(asset.get("title") or "")
    tech = " ".join(str(t) for t in (asset.get("tech") or asset.get("technologies") or []))
    headers_blob = " ".join(
        sorted(str(k).lower() for k in (asset.get("headers") or {}))
        if isinstance(asset.get("headers"), dict)
        else [str(h).lower() for h in (asset.get("headers") or [])]
    )
    js_blob = " ".join(str(x) for x in (asset.get("js_tokens") or asset.get("js_bundles") or []))
    body_sample = str(asset.get("body_preview") or asset.get("snippet") or "")[:600]

    combined = f"{url} {title} {tech} {headers_blob} {js_blob} {body_sample}".lower()
    matched_tokens = [tok for tok in _HIGH_VALUE_RECON_TOKENS if tok in combined]

    path_part = url.split("://", 1)[-1].split("/", 1)[-1] if "/" in url.split("://", 1)[-1] else ""
    path_depth = float(len([seg for seg in path_part.split("?", 1)[0].split("/") if seg]))
    query_params = float(path_part.split("?", 1)[1].count("=") if "?" in path_part else 0)
    is_js_bundle = 1.0 if (".js" in url.lower() or bool(js_blob)) else 0.0
    is_auth_or_err = 1.0 if status_code in (401, 403, 405, 500, 502, 503) else 0.0

    # 8 numeric core features + 6 hashed metadata dims = 14 dims
    numeric = [
        float(status_code // 100) / 5.0,
        signed_log1p(float(content_len)) / 12.0,
        signed_log1p(float(words)) / 10.0,
        min(1.0, path_depth / 8.0),
        min(1.0, query_params / 8.0),
        is_js_bundle,
        is_auth_or_err,
        min(1.0, len(matched_tokens) / 4.0),
    ]
    hashed = signed_hash_features(f"{title} {tech} {headers_blob} {js_blob}", dim=6)
    return numeric + hashed, matched_tokens


def _euclid_sq(a: Sequence[float], b: Sequence[float]) -> float:
    return sum((float(x) - float(y)) ** 2 for x, y in zip(a, b))


class StreamingReconAnomalyScorer:
    """
    O(1)-memory Welford streaming scaler + MAD/centroid anomaly scorer for HTTP
    responses & JS bundles (adapted from ACDSO `scale.py` + `anomaly.py`).
    """

    def __init__(self, n_features: int = 14) -> None:
        self.scaler = WelfordOnlineScaler(n_features)

    def score_batch(self, vectors: Sequence[Sequence[float]]) -> list[float]:
        if not vectors:
            return []
        self.scaler.partial_fit(vectors)
        z_rows = [self.scaler.transform_one(v) for v in vectors]
        norms = [math.sqrt(sum(val * val for val in zr) / max(1, len(zr))) for zr in z_rows]
        if len(norms) == 1:
            return [round(min(1.0, norms[0] / 3.0), 5)]
        s_norms = sorted(norms)
        med = s_norms[len(s_norms) // 2]
        mad = sorted(abs(x - med) for x in norms)[len(norms) // 2] or 0.25
        out: list[float] = []
        for nm in norms:
            rob_z = max(0.0, (nm - med) / (1.4826 * mad))
            score = 1.0 - math.exp(-rob_z / 2.2)
            out.append(round(max(0.0, min(1.0, score)), 5))
        return out


class ReconAssetClusterer:
    """
    Adapted ACDSO K-Means++ + Inductive p95 Noise-Threshold Clusterer
    (`clustering.py` `_InductiveHDBSCAN` pattern) for HTTP recon assets & JS bundles:
      - Groups homogeneous static marketing/CDN pages into large low-priority clusters.
      - Flags rare/singleton clusters and points exceeding their cluster's 95th-percentile
        distance threshold as `cluster_id = -1` (`is_outlier_noise = True`) and ranks them
        at the top alongside high-value API/GraphQL/OIDC/JS-bundle anomalies.
    """

    def __init__(self, *, max_clusters: int = 8, max_iter: int = 25, seed: int = 42) -> None:
        self.max_clusters = max(2, int(max_clusters))
        self.max_iter = max(5, int(max_iter))
        self.seed = int(seed)
        self.anomaly_scorer = StreamingReconAnomalyScorer(n_features=14)

    def cluster_and_prioritize(
        self,
        assets: Sequence[dict[str, Any]],
        *,
        compliance_ctx: Any | None = None,
    ) -> dict[str, Any]:
        """
        Clusters recon assets and returns prioritized anomalies.
        If `compliance_ctx` is provided, filters out any out-of-scope host fail-closed.
        """
        filtered_assets: list[dict[str, Any]] = []
        skipped_oos: int = 0
        for a in assets:
            if not isinstance(a, dict):
                continue
            if compliance_ctx is not None:
                raw_target = str(a.get("url") or a.get("host") or a.get("endpoint") or "")
                if raw_target:
                    _auth_fn = getattr(compliance_ctx, "authorize_scope_host", compliance_ctx.authorize_live_host)
                    ok_host, _ = _auth_fn(raw_target, allow_loopback=True)
                    if not ok_host:
                        skipped_oos += 1
                        continue
            filtered_assets.append(a)

        n = len(filtered_assets)
        if n == 0:
            return {
                "total_assets": 0,
                "skipped_out_of_scope": skipped_oos,
                "clusters_count": 0,
                "outliers_count": 0,
                "suppressed_homogeneous_count": 0,
                "prioritized_assets": [],
                "cluster_summaries": [],
            }

        vectors: list[list[float]] = []
        token_hits: list[list[str]] = []
        for a in filtered_assets:
            vec, toks = _extract_recon_feature_vector(a)
            vectors.append(vec)
            token_hits.append(toks)

        anom_scores = self.anomaly_scorer.score_batch(vectors)

        # Standardize vectors for clustering
        scaler = WelfordOnlineScaler(len(vectors[0])).partial_fit(vectors)
        X = [scaler.transform_one(v) for v in vectors]

        # Deterministic farthest-first K-Means++ initialization
        k = 1 if n <= 2 else min(self.max_clusters, max(2, int(math.sqrt(n / 2.0))))
        centroids: list[list[float]] = [list(X[0])]
        for _ in range(1, k):
            best_i = max(
                range(n),
                key=lambda idx: min(_euclid_sq(X[idx], c) for c in centroids),
            )
            centroids.append(list(X[best_i]))

        labels = [0] * n
        for _ in range(self.max_iter):
            changed = False
            for i in range(n):
                new_lbl = min(range(len(centroids)), key=lambda c_idx: _euclid_sq(X[i], centroids[c_idx]))
                if new_lbl != labels[i]:
                    labels[i] = new_lbl
                    changed = True
            if not changed:
                break
            d = len(X[0])
            for c_idx in range(len(centroids)):
                members = [X[i] for i in range(n) if labels[i] == c_idx]
                if members:
                    centroids[c_idx] = [
                        sum(m[j] for m in members) / float(len(members))
                        for j in range(d)
                    ]

        # Compute per-cluster distances, sizes, and inductive p95 noise thresholds
        cluster_members: dict[int, list[int]] = {}
        dists = [math.sqrt(_euclid_sq(X[i], centroids[labels[i]])) for i in range(n)]
        for i, lbl in enumerate(labels):
            cluster_members.setdefault(lbl, []).append(i)

        p95_thresh: dict[int, float] = {}
        for lbl, idxs in cluster_members.items():
            s_d = sorted(dists[i] for i in idxs)
            p_idx = min(len(s_d) - 1, math.floor(0.95 * (len(s_d) - 1)))
            # Require nonzero threshold margin so identical points aren't falsely flagged
            p95_thresh[lbl] = max(s_d[p_idx], 0.35)

        final_labels: list[int] = []
        is_outlier: list[bool] = []
        suppressed_homogeneous = 0
        prioritized: list[dict[str, Any]] = []

        small_cluster_cap = max(1, math.floor(0.15 * n)) if n >= 6 else 1
        for i, a in enumerate(filtered_assets):
            orig_lbl = labels[i]
            c_size = len(cluster_members[orig_lbl])
            dist_val = dists[i]
            # Outlier if beyond cluster p95 radius OR tiny singleton/rare cluster (when n >= 6)
            outlier = (dist_val > p95_thresh[orig_lbl] * 1.05) or (n >= 6 and c_size <= small_cluster_cap and dist_val >= 0.0)
            eff_lbl = -1 if outlier else orig_lbl
            final_labels.append(eff_lbl)
            is_outlier.append(outlier)

            tok_bonus = min(1.0, len(token_hits[i]) / 3.0)
            rarity_score = 1.0 - (c_size / float(n))
            # Suppress large homogeneous marketing/CDN cluster members with zero high-value tokens
            is_homogeneous_bulk = (not outlier) and (c_size >= max(3, int(0.45 * n))) and (len(token_hits[i]) == 0)
            if is_homogeneous_bulk:
                suppressed_homogeneous += 1

            priority_score = (
                0.35 * anom_scores[i]
                + 0.30 * tok_bonus
                + 0.20 * rarity_score
                + (0.15 if outlier else 0.0)
                - (0.20 if is_homogeneous_bulk else 0.0)
            )
            priority_score = round(max(0.0, min(1.0, priority_score)), 5)

            prioritized.append(
                {
                    "url": str(a.get("url") or a.get("endpoint") or a.get("host") or f"asset_{i}"),
                    "status_code": int(a.get("status_code") or a.get("status") or 0),
                    "content_length": int(a.get("content_length") or a.get("length") or 0),
                    "cluster_id": eff_lbl,
                    "cluster_size": c_size,
                    "is_outlier_noise": outlier,
                    "is_homogeneous_bulk": is_homogeneous_bulk,
                    "anomaly_score": anom_scores[i],
                    "matched_high_value_tokens": token_hits[i],
                    "priority_score": priority_score,
                }
            )

        # Attach structured HTTP anomaly classification to every prioritized asset
        http_clf = HTTPResponseAnomalyClassifier()
        clf_rows = http_clf.classify_responses(filtered_assets)
        for p_row, c_row in zip(prioritized, clf_rows):
            p_row["anomaly_class"] = c_row["anomaly_class"]
            p_row["anomaly_reasons"] = c_row["anomaly_reasons"]

        prioritized.sort(key=lambda r: (-r["priority_score"], not r["is_outlier_noise"], r["url"]))
        cluster_summaries = [
            {
                "cluster_id": lbl,
                "size": len(idxs),
                "p95_distance": round(p95_thresh[lbl], 4),
                "sample_url": str(filtered_assets[idxs[0]].get("url") or filtered_assets[idxs[0]].get("host") or ""),
            }
            for lbl, idxs in sorted(cluster_members.items(), key=lambda kv: -len(kv[1]))
        ]

        return {
            "total_assets": n,
            "skipped_out_of_scope": skipped_oos,
            "clusters_count": len(cluster_members),
            "outliers_count": sum(1 for o in is_outlier if o),
            "suppressed_homogeneous_count": suppressed_homogeneous,
            "prioritized_assets": prioritized,
            "cluster_summaries": cluster_summaries,
        }


# ---------------------------------------------------------------------------
# 5. JavaScript Bundle Analyzer & HTTP Response Anomaly Classifier
# ---------------------------------------------------------------------------

_JS_ENDPOINT_RX = re.compile(
    r"""["'`](\/(?:api|v\d+|graphql|oauth|oidc|auth|admin|internal|rpc|webhook|\.well-known)[A-Za-z0-9_./:?=&%-]{0,140})["'`]""",
    re.IGNORECASE,
)
_JS_ABS_URL_RX = re.compile(r"""https?://[A-Za-z0-9._-]+(?::\d{1,5})?(?:/[A-Za-z0-9_./:?=&%-]{0,120})?""")
_JS_SOURCEMAP_RX = re.compile(r"""sourceMappingURL\s*=\s*([^\s'"]+)""", re.IGNORECASE)
_JS_SINK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("postMessage", re.compile(r"\.postMessage\s*\(", re.IGNORECASE)),
    ("message_listener", re.compile(r"""addEventListener\s*\(\s*["']message["']""", re.IGNORECASE)),
    ("innerHTML", re.compile(r"\.(?:innerHTML|outerHTML)\s*=", re.IGNORECASE)),
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE)),
    ("dynamic_eval", re.compile(r"\b(?:eval|Function)\s*\(", re.IGNORECASE)),
    ("document_write", re.compile(r"document\.write(?:ln)?\s*\(", re.IGNORECASE)),
    ("location_sink", re.compile(r"(?:window\.)?location(?:\.href)?\s*=", re.IGNORECASE)),
)
_JS_SECRET_HINT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("jwt_literal", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("bearer_literal", re.compile(r"""Bearer\s+[A-Za-z0-9_.-]{20,}""")),
    ("client_secret_assign", re.compile(r"""(?:client_secret|api_secret|private_key)\s*[:=]\s*["'][^"']{8,}["']""", re.IGNORECASE)),
)
_STACKTRACE_MARKERS: tuple[str, ...] = (
    "traceback (most recent call last)",
    "sqlstate[",
    "syntax error at or near",
    "exception in thread",
    "nullpointerexception",
    "stack trace:",
    "at java.",
    "at org.",
    "panic: runtime error",
    "fatal error:",
    "x-debug-token",
)
_LEAK_BODY_MARKERS: tuple[str, ...] = (
    "sourcemappingurl",
    "__schema",
    "\"openapi\"",
    "\"swagger\"",
    "aws_secret_access_key",
    "begin private key",
    "root:x:0:0:",
    "\"jwks_uri\"",
)


class JavaScriptBundleAnalyzer:
    """
    Static + ML feature-extraction analyzer for JavaScript bundles (`.js`, `.mjs`,
    `.js.map`) that extracts hidden API/GraphQL/OIDC endpoints, DOM/postMessage sinks,
    source-map references, and redacted credential indicators, strictly honoring
    `ProgramComplianceContext` scope allowlists and emitting `ReconAssetClusterer` rows.
    """

    def analyze_bundle_text(
        self,
        source_label: str,
        text: str,
        *,
        compliance_ctx: Any | None = None,
    ) -> dict[str, Any]:
        raw = str(text or "")
        rel_endpoints = sorted({m.group(1) for m in _JS_ENDPOINT_RX.finditer(raw)})[:80]
        raw_abs_urls = sorted({m.group(0) for m in _JS_ABS_URL_RX.finditer(raw)})[:80]

        in_scope_urls: list[str] = []
        skipped_oos_urls: int = 0
        for u in raw_abs_urls:
            if compliance_ctx is not None:
                _auth_fn = getattr(compliance_ctx, "authorize_scope_host", compliance_ctx.authorize_live_host)
                ok_h, _ = _auth_fn(u, allow_loopback=True)
                if not ok_h:
                    skipped_oos_urls += 1
                    continue
            in_scope_urls.append(u)

        sourcemaps = sorted({m.group(1) for m in _JS_SOURCEMAP_RX.finditer(raw)})[:10]
        dom_sinks = sorted({name for name, pat in _JS_SINK_PATTERNS if pat.search(raw)})
        secret_indicators = sorted({name for name, pat in _JS_SECRET_HINT_PATTERNS if pat.search(raw)})

        low = raw.lower()
        js_tokens = sorted({tok for tok in _HIGH_VALUE_RECON_TOKENS if tok in low})
        if sourcemaps and "sourcemap" not in js_tokens:
            js_tokens.append("sourcemap")
        for s in dom_sinks:
            if s.lower() not in js_tokens:
                js_tokens.append(s.lower())

        risk = (
            min(0.30, len(rel_endpoints) * 0.06)
            + min(0.25, len(dom_sinks) * 0.08)
            + (0.20 if sourcemaps else 0.0)
            + min(0.25, len(secret_indicators) * 0.15)
            + min(0.15, len(js_tokens) * 0.03)
        )
        risk_score = round(max(0.0, min(1.0, risk)), 5)

        recon_asset = {
            "url": source_label,
            "status_code": 200,
            "content_length": len(raw.encode("utf-8", errors="ignore")),
            "words": len(raw.split()),
            "title": f"JS Bundle ({Path(source_label.split('?', 1)[0]).name})",
            "tech": ["JavaScript"],
            "js_tokens": js_tokens,
            "body_preview": " ".join(rel_endpoints[:10] + dom_sinks[:6])[:400],
        }
        return {
            "source": source_label,
            "bytes": len(raw.encode("utf-8", errors="ignore")),
            "discovered_endpoints": rel_endpoints,
            "in_scope_urls": in_scope_urls,
            "skipped_out_of_scope_urls": skipped_oos_urls,
            "sourcemap_urls": sourcemaps,
            "dom_sinks": dom_sinks,
            "secret_indicators": secret_indicators,
            "js_tokens": js_tokens,
            "js_risk_score": risk_score,
            "recon_asset": recon_asset,
        }

    def analyze_bundles(
        self,
        bundles: Sequence[dict[str, Any]],
        *,
        compliance_ctx: Any | None = None,
        cluster: bool = True,
    ) -> dict[str, Any]:
        """Analyzes a batch of `{url|path, content}` dicts or on-disk `.js`/`.mjs`/`.js.map` files."""
        results: list[dict[str, Any]] = []
        skipped_oos_bundles = 0

        for item in bundles:
            if not isinstance(item, dict):
                continue
            label = str(item.get("url") or item.get("path") or item.get("source") or "bundle.js")
            if compliance_ctx is not None and "://" in label:
                _auth_fn = getattr(compliance_ctx, "authorize_scope_host", compliance_ctx.authorize_live_host)
                ok_b, _ = _auth_fn(label, allow_loopback=True)
                if not ok_b:
                    skipped_oos_bundles += 1
                    continue
            content = item.get("content")
            if content is None and item.get("path"):
                p = Path(str(item["path"]))
                if p.is_file():
                    try:
                        content = p.read_text(encoding="utf-8", errors="replace")[:1_500_000]
                    except OSError:
                        content = ""
            results.append(self.analyze_bundle_text(label, str(content or ""), compliance_ctx=compliance_ctx))

        results.sort(key=lambda r: (-r["js_risk_score"], r["source"]))
        cluster_report = None
        if cluster and results:
            cluster_report = ReconAssetClusterer().cluster_and_prioritize(
                [r["recon_asset"] for r in results],
                compliance_ctx=compliance_ctx,
            )

        return {
            "total_bundles": len(results),
            "skipped_out_of_scope_bundles": skipped_oos_bundles,
            "total_endpoints_discovered": sum(len(r["discovered_endpoints"]) for r in results),
            "total_dom_sinks": sum(len(r["dom_sinks"]) for r in results),
            "total_sourcemap_leaks": sum(len(r["sourcemap_urls"]) for r in results),
            "bundles": results,
            "recon_clustering": cluster_report,
        }


class HTTPResponseAnomalyClassifier:
    """
    Streaming Welford + MAD + differential baseline HTTP response anomaly classifier.
    Categorizes HTTP responses into actionable security classes without requiring
    heavy external ML libraries:
      - `SERVER_ERROR_OR_STACKTRACE`
      - `SENSITIVE_CONTENT_LEAK`
      - `AUTH_BOUNDARY_ANOMALY`
      - `HIGH_VALUE_API_SURFACE`
      - `SIZE_OR_STRUCTURE_OUTLIER`
      - `NORMAL`
    """

    def __init__(self) -> None:
        self.scorer = StreamingReconAnomalyScorer(n_features=14)

    def classify_responses(
        self,
        responses: Sequence[dict[str, Any]],
        *,
        baseline: dict[str, Any] | None = None,
        compliance_ctx: Any | None = None,
    ) -> list[dict[str, Any]]:
        filtered: list[dict[str, Any]] = []
        for r in responses:
            if not isinstance(r, dict):
                continue
            if compliance_ctx is not None:
                raw_target = str(r.get("url") or r.get("host") or r.get("endpoint") or "")
                if raw_target:
                    _auth_fn = getattr(compliance_ctx, "authorize_scope_host", compliance_ctx.authorize_live_host)
                    ok_h, _ = _auth_fn(raw_target, allow_loopback=True)
                    if not ok_h:
                        continue
            filtered.append(r)

        if not filtered:
            return []

        vecs: list[list[float]] = []
        tok_lists: list[list[str]] = []
        for r in filtered:
            v, toks = _extract_recon_feature_vector(r)
            vecs.append(v)
            tok_lists.append(toks)
        anom_scores = self.scorer.score_batch(vecs)

        base_status = int(baseline.get("status_code") or baseline.get("status") or 0) if isinstance(baseline, dict) else 0
        base_len = int(baseline.get("content_length") or baseline.get("length") or 0) if isinstance(baseline, dict) else 0

        out: list[dict[str, Any]] = []
        for idx, r in enumerate(filtered):
            status = int(r.get("status_code") or r.get("status") or 200)
            clen = max(0, int(r.get("content_length") or r.get("length") or 0))
            body_blob = " ".join(
                [
                    str(r.get("title") or ""),
                    str(r.get("body_preview") or r.get("snippet") or r.get("body") or ""),
                    " ".join(str(k) for k in (r.get("headers") or {}))
                    if isinstance(r.get("headers"), dict)
                    else "",
                ]
            ).lower()
            score = anom_scores[idx]
            toks = tok_lists[idx]
            reasons: list[str] = []

            has_stack = status >= 500 or any(m in body_blob for m in _STACKTRACE_MARKERS)
            has_leak = any(m in body_blob for m in _LEAK_BODY_MARKERS)
            auth_shift = (
                (base_status in (401, 403) and 200 <= status < 300)
                or (status in (401, 403, 405) and any(t in toks for t in ("admin", "internal", "graphql", "oidc", "oauth")))
            )
            len_shift = (
                base_len > 0
                and abs(clen - base_len) / float(max(base_len, 1)) >= 0.40
            ) or (base_status > 0 and status != base_status)

            if has_stack:
                cls = "SERVER_ERROR_OR_STACKTRACE"
                reasons.append(f"http_{status}_or_stacktrace_marker")
            elif has_leak:
                cls = "SENSITIVE_CONTENT_LEAK"
                reasons.append("sensitive_schema_or_secret_marker")
            elif auth_shift:
                cls = "AUTH_BOUNDARY_ANOMALY"
                reasons.append(f"auth_boundary_status_{status}_vs_baseline_{base_status}")
            elif len(toks) >= 2:
                cls = "HIGH_VALUE_API_SURFACE"
                reasons.append(f"high_value_tokens:{','.join(toks[:4])}")
            elif score >= 0.55 or len_shift:
                cls = "SIZE_OR_STRUCTURE_OUTLIER"
                if score >= 0.55:
                    reasons.append(f"welford_mad_outlier({score:.3f})")
                if len_shift:
                    reasons.append(f"baseline_diff(status={status}/{base_status},len={clen}/{base_len})")
            else:
                cls = "NORMAL"
                reasons.append("within_baseline_distribution")

            out.append(
                {
                    "url": str(r.get("url") or r.get("endpoint") or r.get("host") or f"resp_{idx}"),
                    "status_code": status,
                    "content_length": clen,
                    "anomaly_score": score,
                    "anomaly_class": cls,
                    "is_anomalous": cls != "NORMAL",
                    "anomaly_reasons": reasons,
                    "matched_high_value_tokens": toks,
                }
            )
        return out


__all__ = [
    "ALL_SURFACES",
    "CommitDiffRanker",
    "CommitVelocityBurstDetector",
    "HTTPResponseAnomalyClassifier",
    "JavaScriptBundleAnalyzer",
    "ReconAssetClusterer",
    "StreamingReconAnomalyScorer",
    "SurfaceToScannerRouter",
    "WelfordOnlineScaler",
    "build_unlocked_watchlist_from_db",
]
