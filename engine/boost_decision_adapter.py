"""
ModelFusion /boost Decision & Stage 3 Anti-Slop Adapter (`engine/boost_decision_adapter.py`).
=============================================================================================
Lightweight, fail-safe adapter connecting RFCHunt's ACDSO ML Program Selector and
Stage 3 OODA funnel to a local ModelFusion decision engine (`http://127.0.0.1:5000`)
or local Ollama daemon (`http://127.0.0.1:11434`) with strict <=400ms health probes
and zero-crash deterministic fallback.

Hard Engineering & Safety Invariants:
  1. Strict <= 400ms health probe timeout (`HEALTH_PROBE_TIMEOUT_SEC = 0.4`) so UI
     and pipelines never freeze when local daemons are offline or restarting.
  2. Pareto-knee tie-breaker fires ONLY when top 2-3 candidate scores are within
     `margin` (default `0.02`).
  3. Stage 3 anti-slop stress test evaluates at most top-3 candidates and NEVER
     overrides deterministic proofs (`poc_verified == True`, `lean4`, `z3_formal`,
     or confirmed `differential_oracle` counterexamples).
  4. Zero cloud API egress, zero Registry/PATH mutations, pure stdlib Python.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.request


HEALTH_PROBE_TIMEOUT_SEC: float = 0.4
DECISION_CALL_TIMEOUT_SEC: float = 0.4

_DETERMINISTIC_PROOF_ENGINES = frozenset(
    {"lean4", "z3_formal", "z3", "differential_oracle", "linux_poc"}
)

_SLOP_MARKERS: Tuple[str, ...] = (
    "potentially vulnerable",
    "might allow",
    "could theoretically",
    "best practice recommendation",
    "informational only",
    "missing security header",
    "version disclosure",
    "outdated banner",
)

_NOISE_PATH_MARKERS: Tuple[str, ...] = (
    "/tests/",
    "/test/",
    "/__tests__/",
    "/fixtures/",
    "/examples/",
    "/docs/",
    "readme.md",
)


def _is_offline_env() -> bool:
    return (
        os.environ.get("RFCHUNT_OFFLINE", "").strip() == "1"
        or bool(os.environ.get("CI", "").strip())
    )


def _http_json_request(
    url: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    timeout_sec: float = HEALTH_PROBE_TIMEOUT_SEC,
) -> Tuple[bool, int, Optional[Dict[str, Any]], str]:
    """Bounded stdlib HTTP JSON helper with proxies disabled (loopback-safe)."""
    eff_timeout = max(0.05, min(float(timeout_sec), 2.0))
    headers = {"Accept": "application/json", "User-Agent": "RFCHunt-BoostAdapter/1.0"}
    data: Optional[bytes] = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=eff_timeout) as resp:
            status = int(getattr(resp, "status", 200))
            raw = resp.read().decode("utf-8", errors="replace")
            if not raw.strip():
                return (200 <= status < 300), status, {}, ""
            try:
                parsed = json.loads(raw)
                return (200 <= status < 300), status, (parsed if isinstance(parsed, dict) else {"data": parsed}), ""
            except json.JSONDecodeError:
                return (200 <= status < 300), status, {"raw": raw[:256]}, ""
    except urllib.error.HTTPError as exc:
        return False, int(exc.code), None, f"http_{exc.code}"
    except Exception as exc:
        return False, 0, None, str(exc)[:160]


def probe_modelfusion_decision_api(
    base_url: str = "http://127.0.0.1:5000",
    *,
    timeout_sec: float = HEALTH_PROBE_TIMEOUT_SEC,
) -> Dict[str, Any]:
    """Probes local ModelFusion HTTP `/health` within <= 400ms without crashing."""
    t0 = time.monotonic()
    clean_base = str(base_url or "http://127.0.0.1:5000").rstrip("/")
    eff_timeout = min(float(timeout_sec), HEALTH_PROBE_TIMEOUT_SEC)
    ok, code, body, err = _http_json_request(f"{clean_base}/health", timeout_sec=eff_timeout)
    return {
        "available": bool(ok),
        "endpoint": f"{clean_base}/health",
        "status_code": code,
        "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
        "error": err,
        "details": body or {},
    }


def probe_ollama_tags(
    base_url: str = "http://127.0.0.1:11434",
    *,
    timeout_sec: float = HEALTH_PROBE_TIMEOUT_SEC,
) -> Dict[str, Any]:
    """Probes local Ollama `/api/tags` within <= 400ms and lists installed models."""
    t0 = time.monotonic()
    clean_base = str(base_url or "http://127.0.0.1:11434").rstrip("/")
    eff_timeout = min(float(timeout_sec), HEALTH_PROBE_TIMEOUT_SEC)
    ok, code, body, err = _http_json_request(f"{clean_base}/api/tags", timeout_sec=eff_timeout)
    models: List[str] = []
    if ok and isinstance(body, dict):
        for item in body.get("models") or ():
            if isinstance(item, dict) and item.get("name"):
                models.append(str(item["name"]))
    return {
        "available": bool(ok),
        "endpoint": f"{clean_base}/api/tags",
        "status_code": code,
        "models": models,
        "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
        "error": err,
    }


@dataclass
class BoostDecisionAdapter:
    """
    Hybrid local decision adapter:
      - Uses ModelFusion `/api/decision` when available and online (<=400ms probe).
      - Always degrades cleanly to deterministic local math when offline, embedded,
        or when daemons are restarting.
      - Never overrides deterministic proofs (`poc_verified`, Lean4, Z3, Differential).
    """

    modelfusion_url: str = "http://127.0.0.1:5000"
    ollama_url: str = "http://127.0.0.1:11434"
    probe_timeout_sec: float = HEALTH_PROBE_TIMEOUT_SEC
    embedded: bool = False
    _last_probe: Dict[str, Any] = field(default_factory=dict, repr=False)

    def health_check(self) -> Dict[str, Any]:
        if self.embedded or _is_offline_env():
            status = {
                "mode": "offline_deterministic",
                "modelfusion": {"available": False, "error": "offline_or_embedded"},
                "ollama": {"available": False, "models": [], "error": "offline_or_embedded"},
            }
            self._last_probe = status
            return status
        mf = probe_modelfusion_decision_api(self.modelfusion_url, timeout_sec=self.probe_timeout_sec)
        ol = probe_ollama_tags(self.ollama_url, timeout_sec=self.probe_timeout_sec)
        status = {
            "mode": "modelfusion" if mf["available"] else ("ollama" if ol["available"] else "local_deterministic"),
            "modelfusion": mf,
            "ollama": ol,
        }
        self._last_probe = status
        return status

    @staticmethod
    def _extract_score(item: Dict[str, Any]) -> float:
        for key in (
            "combined_rank_score",
            "expected_value",
            "final_score",
            "score",
            "pareto_score",
            "predicted_yield",
            "priority",
        ):
            if key in item and item[key] is not None:
                try:
                    return float(item[key])
                except (TypeError, ValueError):
                    continue
        return 0.0

    @staticmethod
    def _deterministic_tie_key(item: Dict[str, Any]) -> Tuple[float, float, float, str]:
        """
        Deterministic HackerOne tie-breaker:
          1. Newer launch (smaller `program_age_days` / `launch_age_days` -> higher recency score)
          2. Higher `response_efficiency_pct`
          3. Wider non-marketing scope (`wildcard_count + api_asset_count + oss_repo_count`)
          4. Stable lexical handle ordering
        """
        raw_age = item.get("program_age_days")
        if raw_age is None:
            raw_age = item.get("launch_age_days")
        age_days = float(raw_age if raw_age is not None else 3650.0)
        eff = float(item.get("response_efficiency_pct", 0.0) or 0.0)
        scope_w = float(
            item.get("scope_width")
            or (
                int(item.get("wildcard_count", 0) or 0) * 3
                + int(item.get("api_asset_count", 0) or 0) * 2
                + int(item.get("oss_repo_count", 0) or 0) * 2
            )
        )
        handle = str(item.get("handle") or item.get("program") or item.get("id") or "")
        return (-age_days, eff, scope_w, handle)

    def tie_break_pareto_knee(
        self,
        candidates: Sequence[Dict[str, Any]],
        *,
        top_k: int = 3,
        margin: float = 0.02,
    ) -> Dict[str, Any]:
        """
        Resolves near-ties among the top `<= top_k` Pareto-knee candidates when their
        primary scores differ by `<= margin`.
        """
        t0 = time.monotonic()
        items = [dict(c) for c in candidates if isinstance(c, dict)]
        if len(items) < 2:
            return {
                "tie_broken": False,
                "backend": "noop_singleton",
                "ordered": items,
                "reason": "fewer_than_two_candidates",
                "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
            }

        k = max(2, min(int(top_k), len(items), 3))
        top_slice = items[:k]
        tail_slice = items[k:]
        s0 = self._extract_score(top_slice[0])
        tied = [c for c in top_slice if abs(s0 - self._extract_score(c)) <= float(margin)]
        if len(tied) < 2:
            return {
                "tie_broken": False,
                "backend": "clear_leader",
                "ordered": items,
                "reason": "top_candidate_exceeds_margin",
                "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
            }

        backend = "local_deterministic"
        winner_handle: Optional[str] = None
        if not self.embedded and not _is_offline_env():
            mf_probe = probe_modelfusion_decision_api(
                self.modelfusion_url, timeout_sec=self.probe_timeout_sec
            )
            if mf_probe["available"]:
                payload = {
                    "task": "hackerone_pareto_tie_break",
                    "criteria": [
                        "newest_launch_date",
                        "response_efficiency_pct",
                        "non_marketing_scope_width",
                        "fast_signal_triage_velocity",
                    ],
                    "options": [
                        {
                            "id": str(c.get("handle") or c.get("program") or idx),
                            "score": self._extract_score(c),
                            "program_age_days": c.get("program_age_days"),
                            "response_efficiency_pct": c.get("response_efficiency_pct"),
                            "lane": c.get("lane"),
                            "scope_width": c.get("scope_width"),
                        }
                        for idx, c in enumerate(tied)
                    ],
                }
                ok, _, resp, _ = _http_json_request(
                    f"{self.modelfusion_url.rstrip('/')}/api/decision",
                    method="POST",
                    payload=payload,
                    timeout_sec=DECISION_CALL_TIMEOUT_SEC,
                )
                if ok and isinstance(resp, dict):
                    cand_id = str(
                        resp.get("selected_id")
                        or resp.get("winner")
                        or resp.get("decision")
                        or ""
                    ).strip()
                    if cand_id:
                        winner_handle = cand_id
                        backend = "modelfusion"

        reordered_tied = sorted(
            tied,
            key=lambda c: (
                1 if (winner_handle and str(c.get("handle") or c.get("program") or "") == winner_handle) else 0,
                self._deterministic_tie_key(c),
            ),
            reverse=True,
        )
        untied_top = [c for c in top_slice if c not in tied]
        ordered = reordered_tied + untied_top + tail_slice
        return {
            "tie_broken": True,
            "backend": backend,
            "tied_count": len(tied),
            "winner": str(reordered_tied[0].get("handle") or reordered_tied[0].get("program") or ""),
            "ordered": ordered,
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
        }

    @staticmethod
    def _is_deterministic_proof(cand: Dict[str, Any]) -> bool:
        if cand.get("poc_verified") is True:
            return True
        engine = str(cand.get("engine") or cand.get("source_engine") or "").strip().lower()
        if engine in _DETERMINISTIC_PROOF_ENGINES:
            if engine in ("lean4", "z3_formal", "z3", "differential_oracle"):
                return bool(cand.get("confirmed", True) or cand.get("deterministic", True))
            return True
        meta = cand.get("metadata") if isinstance(cand.get("metadata"), dict) else {}
        if meta.get("lean4_proven") is True or meta.get("z3_sat") is True:
            return True
        return False

    def stress_test_stage3_candidates(
        self,
        candidates: Sequence[Dict[str, Any]],
        *,
        top_k: int = 3,
        program: str = "generic",
    ) -> Dict[str, Any]:
        """
        Anti-slop stress test for ONLY the top `<= 3` Stage 3 findings.
        Deterministic proofs (`poc_verified=True`, Lean4, Z3, differential oracle)
        are ALWAYS preserved and can never be demoted by heuristic or LLM dissent.
        """
        t0 = time.monotonic()
        k = max(1, min(int(top_k), 3))
        slice_items = [dict(c) for c in candidates[:k] if isinstance(c, dict)]

        backend = "local_deterministic"
        mf_available = False
        if not self.embedded and not _is_offline_env():
            mf_probe = probe_modelfusion_decision_api(
                self.modelfusion_url, timeout_sec=self.probe_timeout_sec
            )
            mf_available = bool(mf_probe["available"])
            if mf_available:
                backend = "modelfusion"

        evaluated: List[Dict[str, Any]] = []
        kept: List[Dict[str, Any]] = []
        demoted: List[Dict[str, Any]] = []
        deterministic_preserved = 0

        for idx, cand in enumerate(slice_items):
            if self._is_deterministic_proof(cand):
                deterministic_preserved += 1
                entry = {
                    **cand,
                    "boost_verdict": "KEEP_DETERMINISTIC_PROOF",
                    "boost_reasons": ["deterministic_formal_or_poc_proof_preserved"],
                    "boost_backend": "deterministic_invariant",
                }
                evaluated.append(entry)
                kept.append(entry)
                continue

            reasons: List[str] = []
            fp = str(cand.get("file_path") or "").replace("\\", "/").lower()
            title = str(cand.get("title") or "")
            summary = str(cand.get("summary") or cand.get("description") or "")
            blob = f"{title} {summary}".lower()
            conf = float(cand.get("confidence", 0.5) or 0.5)
            sev = str(cand.get("severity") or "MEDIUM").strip().upper()
            line_no = int(cand.get("line") or cand.get("line_number") or 0)

            if any(m in fp for m in _NOISE_PATH_MARKERS):
                reasons.append("non_production_test_or_doc_path")
            if any(m in blob for m in _SLOP_MARKERS):
                reasons.append("speculative_or_informational_language")
            if not fp and line_no <= 0 and len(summary.strip()) < 30:
                reasons.append("missing_concrete_location_and_evidence")
            if conf < 0.35 and sev not in ("CRITICAL", "HIGH"):
                reasons.append("low_confidence_low_severity")

            # Optional ModelFusion local critic for non-deterministic leads
            if not reasons and mf_available:
                ok, _, resp, _ = _http_json_request(
                    f"{self.modelfusion_url.rstrip('/')}/api/decision",
                    method="POST",
                    payload={
                        "task": "stage3_anti_slop_critic",
                        "program": program,
                        "candidate": {
                            "index": idx,
                            "title": title[:200],
                            "file_path": fp[:200],
                            "line": line_no,
                            "severity": sev,
                            "confidence": conf,
                            "summary": summary[:400],
                        },
                    },
                    timeout_sec=DECISION_CALL_TIMEOUT_SEC,
                )
                if ok and isinstance(resp, dict) and resp.get("reject_as_slop") is True:
                    reasons.append(str(resp.get("reason") or "modelfusion_anti_slop_reject"))

            verdict = "DEMOTE_SLOP" if reasons else "KEEP_FOR_POC_VERIFICATION"
            entry = {
                **cand,
                "boost_verdict": verdict,
                "boost_reasons": reasons or ["passed_anti_slop_gate"],
                "boost_backend": backend,
            }
            evaluated.append(entry)
            if verdict == "DEMOTE_SLOP":
                demoted.append(entry)
            else:
                kept.append(entry)

        return {
            "status": "completed",
            "program": program,
            "backend": backend,
            "evaluated_count": len(evaluated),
            "kept_count": len(kept),
            "demoted_count": len(demoted),
            "deterministic_preserved": deterministic_preserved,
            "evaluated": evaluated,
            "kept": kept,
            "demoted": demoted,
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
        }


__all__ = [
    "HEALTH_PROBE_TIMEOUT_SEC",
    "DECISION_CALL_TIMEOUT_SEC",
    "probe_modelfusion_decision_api",
    "probe_ollama_tags",
    "BoostDecisionAdapter",
]
