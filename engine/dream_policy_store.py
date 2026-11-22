"""
Module 15: Dream-RSI Policy Store and Versioning Registry.

Persists evolved meta-exploration policies with explicit `simulator_backend`,
`stack_profile`, `val_fitness_score`, and meta-exploration control lineage,
and exports empirical self-improvement telemetry.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.dream_replay_pool import BACKEND_SYNTHETIC_FALLBACK
from engine.dream_rsi_optimizer import DreamPolicy


class DreamPolicyStore:
    """
    Registry for versioning, storing, and loading evolved Dream-RSI policies.
    Supports stack-profile lookup and backend provenance filtering.
    """

    def __init__(self, storage_path: str = "data/dream_policies.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.policies: List[DreamPolicy] = []
        self._load()

    def _resolved_path(self) -> Path:
        p = Path(self.storage_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def _load(self) -> None:
        p = Path(self.storage_path)
        if not p.exists():
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.policies = [DreamPolicy.from_dict(item) for item in data if isinstance(item, dict)]
                elif isinstance(data, dict) and isinstance(data.get("policies"), list):
                    self.policies = [
                        DreamPolicy.from_dict(item) for item in data["policies"] if isinstance(item, dict)
                    ]
        except Exception:
            self.policies = []

    def save_policy(self, policy: DreamPolicy) -> None:
        """Appends a newly evolved policy and persists the registry to disk as UTF-8 JSON."""
        self.policies.append(policy)
        payload = {
            "total_generations": len(self.policies),
            "latest_generation": int(policy.generation),
            "latest_simulator_backend": str(policy.simulator_backend),
            "latest_stack_profile": str(policy.stack_profile),
            "latest_val_fitness_score": round(float(policy.val_fitness_score), 4),
            "policies": [p.to_dict() for p in self.policies],
        }
        target_path = self._resolved_path()
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def get_latest_policy(
        self,
        stack_profile: Optional[str] = None,
        *,
        fallback_generic: bool = True,
        require_replay: bool = False,
    ) -> Optional[DreamPolicy]:
        """
        Returns the most recently saved `DreamPolicy`.

        When `stack_profile` is supplied, matches that stack profile first
        (case-insensitive), optionally falling back to `"generic"`.
        When `require_replay=True`, ignores `"synthetic_heuristic_fallback"` policies.
        """
        if not self.policies:
            return None

        candidates = (
            [p for p in self.policies if str(p.simulator_backend) != BACKEND_SYNTHETIC_FALLBACK]
            if require_replay
            else list(self.policies)
        )
        if not candidates:
            return None

        if stack_profile is None or not str(stack_profile).strip():
            return candidates[-1]

        target = str(stack_profile).strip().lower()
        for pol in reversed(candidates):
            if str(pol.stack_profile or "generic").strip().lower() == target:
                return pol

        if fallback_generic and target != "generic":
            for pol in reversed(candidates):
                if str(pol.stack_profile or "generic").strip().lower() == "generic":
                    return pol

        return None

    def export_summary(self, stack_profile: Optional[str] = None) -> Dict[str, Any]:
        """Returns empirical self-improvement summary with backend and meta-control provenance."""
        if not self.policies:
            return {"status": "No evolved policies recorded"}

        if stack_profile:
            target = str(stack_profile).strip().lower()
            scoped = [p for p in self.policies if str(p.stack_profile or "generic").strip().lower() == target]
            if not scoped:
                return {"status": f"No evolved policies recorded for stack_profile={stack_profile}"}
        else:
            scoped = self.policies

        latest = scoped[-1]
        baseline = scoped[0]
        cumulative_gain = (
            (latest.fitness_score - baseline.fitness_score) / max(1.0, abs(baseline.fitness_score))
        ) * 100.0

        return {
            "total_generations": len(scoped),
            "latest_generation": latest.generation,
            "latest_fitness": latest.fitness_score,
            "latest_val_fitness": latest.val_fitness_score,
            "cumulative_rsi_gain_pct": round(cumulative_gain, 2),
            "simulator_backend": latest.simulator_backend,
            "stack_profile": latest.stack_profile,
            "dominant_mutators": sorted(
                latest.mutator_weights.items(), key=lambda x: x[1], reverse=True
            )[:3],
            "simulated_yield": latest.simulated_yield,
            "false_positive_rate": latest.false_positive_rate,
            "meta_controls": {
                "branch_width": latest.branch_width,
                "depth_vs_breadth_alpha": latest.depth_vs_breadth_alpha,
                "early_stop_patience": latest.early_stop_patience,
                "parallel_group_size": latest.parallel_group_size,
                "priority_weights": dict(latest.priority_weights),
                "domain_weights": dict(latest.domain_weights),
            },
            "available_stack_profiles": sorted(
                {str(p.stack_profile or "generic").strip().lower() for p in self.policies}
            ),
        }
