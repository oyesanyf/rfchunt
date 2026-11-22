"""
Module 14: Dream-RSI Off-Policy Optimizer (Recursive Self-Improvement).

Executes off-policy meta-exploration optimization over recorded Cairn / ARTEX
discovery trees (`ReplayTreePool`) using a deterministic pure-stdlib Cross-Entropy
Method (CEM) with bounded discrete mutations and strict held-out validation gating.
Falls back to cold-start `ProtocolWorldModel.simulate_probe()` rollouts ONLY when
zero recorded trees exist, always stamping an explicit `simulator_backend` label.
"""

from __future__ import annotations

import copy
import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from engine.dream_replay_pool import (
    BACKEND_RECORDED_REPLAY,
    BACKEND_SYNTHETIC_FALLBACK,
    DiscoveryTree,
    ReplayTreePool,
)
from engine.dream_world_model import ProtocolWorldModel

DEFAULT_PRIORITY_WEIGHTS: Dict[str, float] = {
    "cascade_intent": 1.0,
    "dual_graph_multihop": 1.2,
    "abnf_seed": 0.8,
    "llm_candidate": 1.0,
    "hint_boost": 1.5,
}


def _clamp(val: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, float(val)))


def _clamp_int(val: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(val)))


def _normalize_weights(weights: Dict[str, float], floor: float = 0.02) -> Dict[str, float]:
    if not weights:
        return {}
    clamped = {k: max(floor, float(v)) for k, v in weights.items()}
    total = sum(clamped.values()) or 1.0
    return {k: v / total for k, v in clamped.items()}


def _softmax_logits(logits: Dict[str, float], floor: float = 0.02) -> Dict[str, float]:
    if not logits:
        return {}
    max_l = max(logits.values())
    exps = {k: math.exp(_clamp(v - max_l, -20.0, 20.0)) for k, v in logits.items()}
    total = sum(exps.values()) or 1.0
    probs = {k: max(floor, v / total) for k, v in exps.items()}
    norm = sum(probs.values()) or 1.0
    return {k: v / norm for k, v in probs.items()}


@dataclass
class DreamPolicy:
    generation: int
    mutator_weights: Dict[str, float] = field(default_factory=dict)
    normative_bias: float = 0.5  # 0.0 = exploratory/anti-anchored, 1.0 = strict MUST/SHOULD clauses
    delta_aggressiveness: float = 0.5  # early pruning threshold in DeltaDebugger / noise penalty
    fitness_score: float = 0.0
    rsi_gain: float = 0.0
    simulated_yield: float = 0.0
    false_positive_rate: float = 0.0
    # Meta-exploration controls (backward-compatible defaults)
    branch_width: int = 3
    depth_vs_breadth_alpha: float = 0.5  # 0.0 = pure BFS, 1.0 = pure DFS
    early_stop_patience: int = 4  # consecutive dead probes before pruning branch
    parallel_group_size: int = 4  # concurrent Explore batch size
    priority_weights: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_PRIORITY_WEIGHTS))
    domain_weights: Dict[str, float] = field(default_factory=dict)
    stack_profile: str = "generic"
    simulator_backend: str = BACKEND_RECORDED_REPLAY
    val_fitness_score: float = 0.0

    def score_intent_priority(
        self,
        base_priority: float = 0.0,
        *,
        source_kind: str = "llm_candidate",
        domain: str = "",
        mutator_family: str = "",
        depth: int = 0,
        max_depth: int = 5,
        has_active_hint: bool = False,
        branch_noise_count: int = 0,
    ) -> float:
        """
        Computes a unified meta-exploration priority score used both by the
        offline `ReplayTreePool` simulator and online Cairn `blackboard_router`.
        """
        src_w = float(self.priority_weights.get(source_kind, 1.0))

        if self.mutator_weights:
            n_arms = max(1, len(self.mutator_weights))
            raw_mw = float(self.mutator_weights.get(mutator_family, 1.0 / n_arms))
            mut_score = raw_mw * n_arms
        else:
            mut_score = 1.0

        dom_key = (domain or "").strip().lower()
        dom_w = float(self.domain_weights.get(dom_key, self.domain_weights.get(domain, 1.0))) if dom_key else 1.0

        depth_norm = min(1.0, max(0.0, float(depth)) / float(max(1, max_depth)))
        depth_bias = (2.0 * float(self.depth_vs_breadth_alpha) - 1.0) * depth_norm * 2.5

        hint_bonus = float(self.priority_weights.get("hint_boost", 1.5)) if has_active_hint else 0.0

        norm_bonus = 0.0
        if source_kind == "abnf_seed":
            norm_bonus = (float(self.normative_bias) - 0.5) * 1.5
        elif source_kind in ("llm_candidate", "dual_graph_multihop"):
            norm_bonus = (0.5 - float(self.normative_bias)) * 1.5

        prio_term = math.tanh(float(base_priority) / 25.0) * 1.5
        noise_penalty = float(self.delta_aggressiveness) * float(branch_noise_count) * 1.25

        return (
            2.5 * mut_score
            + 2.0 * src_w
            + 1.8 * dom_w
            + depth_bias
            + hint_bonus
            + norm_bonus
            + prio_term
            - noise_penalty
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generation": int(self.generation),
            "mutator_weights": {k: round(float(v), 6) for k, v in self.mutator_weights.items()},
            "normative_bias": round(float(self.normative_bias), 4),
            "delta_aggressiveness": round(float(self.delta_aggressiveness), 4),
            "fitness_score": round(float(self.fitness_score), 4),
            "rsi_gain": round(float(self.rsi_gain), 4),
            "simulated_yield": round(float(self.simulated_yield), 4),
            "false_positive_rate": round(float(self.false_positive_rate), 4),
            "branch_width": int(self.branch_width),
            "depth_vs_breadth_alpha": round(float(self.depth_vs_breadth_alpha), 4),
            "early_stop_patience": int(self.early_stop_patience),
            "parallel_group_size": int(self.parallel_group_size),
            "priority_weights": {k: round(float(v), 4) for k, v in self.priority_weights.items()},
            "domain_weights": {k: round(float(v), 4) for k, v in self.domain_weights.items()},
            "stack_profile": str(self.stack_profile or "generic"),
            "simulator_backend": str(self.simulator_backend or BACKEND_RECORDED_REPLAY),
            "val_fitness_score": round(float(self.val_fitness_score), 4),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DreamPolicy":
        raw_pw = data.get("priority_weights")
        merged_pw = dict(DEFAULT_PRIORITY_WEIGHTS)
        if isinstance(raw_pw, dict):
            for k, v in raw_pw.items():
                try:
                    merged_pw[str(k)] = float(v)
                except (ValueError, TypeError):
                    pass

        raw_dw = data.get("domain_weights")
        domain_w: Dict[str, float] = {}
        if isinstance(raw_dw, dict):
            for k, v in raw_dw.items():
                try:
                    domain_w[str(k)] = float(v)
                except (ValueError, TypeError):
                    pass

        raw_mw = data.get("mutator_weights")
        mut_w: Dict[str, float] = {}
        if isinstance(raw_mw, dict):
            for k, v in raw_mw.items():
                try:
                    mut_w[str(k)] = float(v)
                except (ValueError, TypeError):
                    pass

        return cls(
            generation=int(data.get("generation", 0) or 0),
            mutator_weights=mut_w,
            normative_bias=float(data.get("normative_bias", 0.5)),
            delta_aggressiveness=float(data.get("delta_aggressiveness", 0.5)),
            fitness_score=float(data.get("fitness_score", 0.0)),
            rsi_gain=float(data.get("rsi_gain", 0.0)),
            simulated_yield=float(data.get("simulated_yield", 0.0)),
            false_positive_rate=float(data.get("false_positive_rate", 0.0)),
            branch_width=_clamp_int(int(data.get("branch_width", 3) or 3), 1, 20),
            depth_vs_breadth_alpha=_clamp(float(data.get("depth_vs_breadth_alpha", 0.5)), 0.0, 1.0),
            early_stop_patience=_clamp_int(int(data.get("early_stop_patience", 4) or 4), 1, 50),
            parallel_group_size=_clamp_int(int(data.get("parallel_group_size", 4) or 4), 1, 32),
            priority_weights=merged_pw,
            domain_weights=domain_w,
            stack_profile=str(data.get("stack_profile", "generic") or "generic"),
            simulator_backend=str(data.get("simulator_backend", BACKEND_RECORDED_REPLAY) or BACKEND_RECORDED_REPLAY),
            val_fitness_score=float(data.get("val_fitness_score", 0.0)),
        )


class DreamRSIOptimizer:
    """
    Off-policy Dreaming Engine. Optimizes meta-exploration policies over recorded
    `ReplayTreePool` discovery trees via seeded Cross-Entropy Method (CEM) + bounded
    discrete evolution with strict held-out validation gating.
    """

    DEFAULT_ARMS = [
        "TE_CL_DUAL_HEADER",
        "PATH_NUL_EARLY_RESPONSE",
        "DANGLING_BYTE_STACKED_RESPONSE",
        "MULTIPART_BYTERANGES_SHARED_PARSER",
        "HEADER_TAB_SPACING",
        "CRLF_DELIMITER_SPLIT",
        "OBS_FOLD_LINE_JOIN",
        "OVERLONG_UTF8_NORMALIZATION",
    ]

    def __init__(self, world_model: ProtocolWorldModel):
        self.world_model = world_model
        self.current_generation = 0
        self.active_policy = self._create_baseline_policy()
        self.last_evolution_report: Dict[str, Any] = {}

    def _create_baseline_policy(
        self,
        *,
        extra_arms: Sequence[str] = (),
        domains: Sequence[str] = (),
        stack_profile: Optional[str] = None,
        simulator_backend: Optional[str] = None,
    ) -> DreamPolicy:
        """Constructs a uniform exploratory baseline policy (Generation 0)."""
        all_arms: List[str] = list(self.DEFAULT_ARMS)
        for arm in extra_arms:
            if arm and arm not in all_arms:
                all_arms.append(arm)
        uniform_weights = {arm: 1.0 / len(all_arms) for arm in all_arms}
        domain_weights = {d.strip().lower(): 1.0 for d in domains if d and d.strip()}
        resolved_stack = stack_profile or getattr(self.world_model, "server_signature", "generic") or "generic"
        resolved_backend = simulator_backend or (
            BACKEND_RECORDED_REPLAY
            if getattr(self.world_model, "has_recorded_replay_trees", False)
            else BACKEND_SYNTHETIC_FALLBACK
        )
        return DreamPolicy(
            generation=0,
            mutator_weights=uniform_weights,
            normative_bias=0.5,
            delta_aggressiveness=0.5,
            fitness_score=1.0,
            rsi_gain=0.0,
            branch_width=3,
            depth_vs_breadth_alpha=0.5,
            early_stop_patience=4,
            parallel_group_size=4,
            priority_weights=dict(DEFAULT_PRIORITY_WEIGHTS),
            domain_weights=domain_weights,
            stack_profile=resolved_stack,
            simulator_backend=resolved_backend,
            val_fitness_score=0.0,
        )

    def create_frozen_baseline_policy(
        self,
        *,
        trees: Sequence[DiscoveryTree] = (),
        stack_profile: Optional[str] = None,
        simulator_backend: str = BACKEND_RECORDED_REPLAY,
    ) -> DreamPolicy:
        """Creates a frozen Generation-0 baseline policy for `NoLearning` comparisons."""
        extra_arms, domains = self._extract_vocabulary(trees)
        return self._create_baseline_policy(
            extra_arms=extra_arms,
            domains=domains,
            stack_profile=stack_profile,
            simulator_backend=simulator_backend,
        )

    @staticmethod
    def _extract_vocabulary(trees: Sequence[DiscoveryTree]) -> Tuple[List[str], List[str]]:
        arms_set = set()
        dom_set = set()
        for t in trees:
            for nd in t.nodes.values():
                if nd.mutator_family:
                    arms_set.add(nd.mutator_family)
                if nd.domain and nd.domain.strip():
                    dom_set.add(nd.domain.strip().lower())
        return (sorted(arms_set), sorted(dom_set))

    def evaluate_policy_on_trees(
        self,
        policy: DreamPolicy,
        trees: Sequence[DiscoveryTree],
        *,
        replay_pool: Optional[ReplayTreePool] = None,
        budget_steps: int = 50,
        seed: int = 42,
        eval_seeds_per_tree: int = 1,
    ) -> Dict[str, float]:
        """
        Deterministically evaluates `policy` over a collection of recorded `DiscoveryTree`s
        with zero network I/O and zero LLM calls.
        """
        pool = replay_pool if replay_pool is not None else self.world_model.replay_pool
        if not trees:
            return {
                "mean_reward": 0.0,
                "mean_vuln_rate": 0.0,
                "mean_vuln_hit_rate": 0.0,
                "mean_noise_rate": 0.0,
                "total_vulns": 0.0,
                "total_chains": 0.0,
                "total_anomalies": 0.0,
                "total_noise": 0.0,
                "total_steps": 0.0,
                "episodes": 0.0,
            }

        rewards: List[float] = []
        vuln_rates: List[float] = []
        vuln_hit_rates: List[float] = []
        noise_rates: List[float] = []
        total_vulns = 0
        total_chains = 0
        total_anomalies = 0
        total_noise = 0
        total_steps = 0

        repeats = max(1, int(eval_seeds_per_tree))
        for t_idx, tree in enumerate(trees):
            for r_idx in range(repeats):
                ep_seed = int(seed) + t_idx * 997 + r_idx * 31
                out = pool.simulate_policy_traversal(
                    tree,
                    policy,
                    budget_steps=budget_steps,
                    seed=ep_seed,
                    mode="policy",
                )
                rewards.append(out.reward)
                vuln_rates.append(out.vuln_discovery_rate)
                vuln_hit_rates.append(out.vuln_hit_rate)
                noise_rates.append(out.noise_rate)
                total_vulns += out.vulns_found
                total_chains += out.chains_found
                total_anomalies += out.anomalies_found
                total_noise += out.noise_discards
                total_steps += out.steps_taken

        n_ep = float(max(1, len(rewards)))
        return {
            "mean_reward": sum(rewards) / n_ep,
            "mean_vuln_rate": sum(vuln_rates) / n_ep,
            "mean_vuln_hit_rate": sum(vuln_hit_rates) / n_ep,
            "mean_noise_rate": sum(noise_rates) / n_ep,
            "total_vulns": float(total_vulns),
            "total_chains": float(total_chains),
            "total_anomalies": float(total_anomalies),
            "total_noise": float(total_noise),
            "total_steps": float(total_steps),
            "episodes": n_ep,
        }

    def validate_policy_promotion(
        self,
        candidate: DreamPolicy,
        incumbent: DreamPolicy,
        val_trees: Sequence[DiscoveryTree],
        *,
        replay_pool: Optional[ReplayTreePool] = None,
        budget_steps: int = 50,
        seed: int = 42,
        min_gain: float = 1e-6,
    ) -> Tuple[bool, float, float]:
        """
        Held-out validation promotion gate.
        Returns `(should_promote, candidate_val_score, incumbent_val_score)`.
        """
        pool = replay_pool if replay_pool is not None else self.world_model.replay_pool
        cand_eval = self.evaluate_policy_on_trees(
            candidate, val_trees, replay_pool=pool, budget_steps=budget_steps, seed=seed
        )
        inc_eval = self.evaluate_policy_on_trees(
            incumbent, val_trees, replay_pool=pool, budget_steps=budget_steps, seed=seed
        )
        cand_score = cand_eval["mean_reward"]
        inc_score = inc_eval["mean_reward"]
        return (cand_score > inc_score + float(min_gain), cand_score, inc_score)

    def evolve_meta_policy_from_replay(
        self,
        replay_pool: Optional[ReplayTreePool] = None,
        *,
        generations: int = 5,
        population_size: int = 12,
        elite_fraction: float = 0.25,
        budget_steps: int = 50,
        seed: int = 42,
        val_ratio: float = 0.25,
        stack_profile: Optional[str] = None,
        eval_seeds_per_tree: int = 1,
        train_trees: Optional[Sequence[DiscoveryTree]] = None,
        val_trees: Optional[Sequence[DiscoveryTree]] = None,
    ) -> DreamPolicy:
        """
        Optimizes a `DreamPolicy` over recorded `DiscoveryTree`s using seeded
        Cross-Entropy Method (CEM) over continuous weights + bounded discrete
        mutations for `branch_width`, `early_stop_patience`, and `parallel_group_size`.

        Promotes a candidate generation ONLY if it improves held-out validation
        tree performance over the incumbent (preventing single-tree overfitting).
        """
        pool = replay_pool if replay_pool is not None else self.world_model.replay_pool
        gens = max(1, int(generations))
        pop_size = max(4, int(population_size))
        elite_frac = _clamp(float(elite_fraction), 0.1, 0.5)
        budget = max(1, int(budget_steps))
        base_seed = int(seed)

        resolved_stack = stack_profile or getattr(self.world_model, "server_signature", "generic") or "generic"

        if train_trees is not None:
            tr_trees = list(train_trees)
            vl_trees = list(val_trees) if val_trees is not None else []
        else:
            filtered = pool.list_trees(stack_profile=resolved_stack if resolved_stack != "generic" else None)
            if len(filtered) >= 2:
                tr_trees, vl_trees = pool.split_train_val(
                    val_ratio=val_ratio, seed=base_seed, stack_profile=resolved_stack if resolved_stack != "generic" else None
                )
            else:
                tr_trees, vl_trees = pool.split_train_val(val_ratio=val_ratio, seed=base_seed)

        if not tr_trees:
            fallback = copy.deepcopy(self.active_policy)
            fallback.generation = self.current_generation + gens
            fallback.simulator_backend = BACKEND_SYNTHETIC_FALLBACK
            fallback.rsi_gain = 0.0
            fallback.val_fitness_score = 0.0
            self.current_generation = fallback.generation
            self.active_policy = fallback
            self.last_evolution_report = {
                "simulator_backend": BACKEND_SYNTHETIC_FALLBACK,
                "train_tree_count": 0,
                "val_tree_count": 0,
                "promotions_accepted": 0,
                "promotions_rejected": 0,
            }
            return fallback

        # Extract search-space vocabulary strictly from train_trees (zero val leakage)
        extra_arms, train_domains = self._extract_vocabulary(tr_trees)
        all_arms: List[str] = list(self.DEFAULT_ARMS)
        for arm in extra_arms:
            if arm not in all_arms:
                all_arms.append(arm)
        for arm in self.active_policy.mutator_weights:
            if arm not in all_arms:
                all_arms.append(arm)

        prio_keys = list(DEFAULT_PRIORITY_WEIGHTS.keys())
        dom_keys = sorted(set(train_domains) | {k.lower() for k in self.active_policy.domain_weights})

        # Align incumbent policy to vocabulary
        incumbent = copy.deepcopy(self.active_policy)
        inc_mut = {arm: float(incumbent.mutator_weights.get(arm, 1.0 / len(all_arms))) for arm in all_arms}
        incumbent.mutator_weights = _normalize_weights(inc_mut, floor=0.02)
        for k in prio_keys:
            incumbent.priority_weights.setdefault(k, DEFAULT_PRIORITY_WEIGHTS[k])
        for d in dom_keys:
            incumbent.domain_weights.setdefault(d, 1.0)
        incumbent.stack_profile = resolved_stack
        incumbent.simulator_backend = BACKEND_RECORDED_REPLAY

        train_eval_seed = base_seed + 101
        val_eval_seed = base_seed + 5003

        base_train_metrics = self.evaluate_policy_on_trees(
            incumbent,
            tr_trees,
            replay_pool=pool,
            budget_steps=budget,
            seed=train_eval_seed,
            eval_seeds_per_tree=eval_seeds_per_tree,
        )
        baseline_train_score = base_train_metrics["mean_reward"]

        has_val = len(vl_trees) > 0
        if has_val:
            base_val_metrics = self.evaluate_policy_on_trees(
                incumbent,
                vl_trees,
                replay_pool=pool,
                budget_steps=budget,
                seed=val_eval_seed,
                eval_seeds_per_tree=eval_seeds_per_tree,
            )
            baseline_val_score = base_val_metrics["mean_reward"]
        else:
            base_val_metrics = base_train_metrics
            baseline_val_score = baseline_train_score

        incumbent.fitness_score = baseline_train_score
        incumbent.val_fitness_score = baseline_val_score if has_val else 0.0
        incumbent.simulated_yield = base_val_metrics["mean_vuln_rate"]
        incumbent.false_positive_rate = base_val_metrics["mean_noise_rate"]

        promoted_policy = copy.deepcopy(incumbent)
        best_val_score = baseline_val_score
        best_train_score = baseline_train_score
        best_train_policy = copy.deepcopy(incumbent)

        # Initialize CEM continuous distributions from incumbent
        mu_mut_logits: Dict[str, float] = {
            arm: math.log(max(0.02, incumbent.mutator_weights.get(arm, 1.0 / len(all_arms))))
            for arm in all_arms
        }
        sigma_mut_logits: Dict[str, float] = {arm: 1.15 for arm in all_arms}

        mu_prio: Dict[str, float] = {k: float(incumbent.priority_weights.get(k, DEFAULT_PRIORITY_WEIGHTS[k])) for k in prio_keys}
        sigma_prio: Dict[str, float] = {k: 0.85 for k in prio_keys}

        mu_dom: Dict[str, float] = {d: float(incumbent.domain_weights.get(d, 1.0)) for d in dom_keys}
        sigma_dom: Dict[str, float] = {d: 0.85 for d in dom_keys}

        mu_alpha = float(incumbent.depth_vs_breadth_alpha)
        sigma_alpha = 0.35
        mu_norm = float(incumbent.normative_bias)
        sigma_norm = 0.25
        mu_delta = float(incumbent.delta_aggressiveness)
        sigma_delta = 0.25

        # Discrete centers
        center_bw = int(incumbent.branch_width)
        center_patience = int(incumbent.early_stop_patience)
        center_pgs = int(incumbent.parallel_group_size)
        elite_bw_pool: List[int] = [center_bw, 2, 3, 4, 5]
        elite_pat_pool: List[int] = [center_patience, 1, 2, 3, 4]
        elite_pgs_pool: List[int] = [center_pgs, 1, 2, 3, 4]

        promotions_accepted = 0
        promotions_rejected = 0
        n_elite = max(2, int(round(pop_size * elite_frac)))
        polyak = 0.7

        def _policy_to_logits(pol: DreamPolicy) -> Dict[str, float]:
            return {arm: math.log(max(0.02, pol.mutator_weights.get(arm, 1.0 / len(all_arms)))) for arm in all_arms}

        for g in range(1, gens + 1):
            self.current_generation += 1
            rng = random.Random(base_seed + g * 7919)
            scored_population: List[Tuple[float, DreamPolicy, Dict[str, float], Dict[str, float]]] = []

            for c_idx in range(pop_size):
                if c_idx == 0 and g > 1:
                    # Elitist small perturbation around best train policy
                    base_logits = _policy_to_logits(best_train_policy)
                    cand_logits = {arm: base_logits[arm] + rng.gauss(0.0, 0.25) for arm in all_arms}
                    cand_prio = {
                        k: _clamp(best_train_policy.priority_weights[k] + rng.gauss(0.0, 0.2), 0.1, 4.0)
                        for k in prio_keys
                    }
                    cand_dom = {
                        d: _clamp(best_train_policy.domain_weights.get(d, 1.0) + rng.gauss(0.0, 0.2), 0.1, 4.0)
                        for d in dom_keys
                    }
                    cand_alpha = _clamp(best_train_policy.depth_vs_breadth_alpha + rng.gauss(0.0, 0.1), 0.0, 1.0)
                    cand_norm = _clamp(best_train_policy.normative_bias + rng.gauss(0.0, 0.08), 0.1, 0.9)
                    cand_delta = _clamp(best_train_policy.delta_aggressiveness + rng.gauss(0.0, 0.08), 0.1, 0.9)
                    cand_bw = _clamp_int(best_train_policy.branch_width + rng.choice([-1, 0, 1]), 1, 10)
                    cand_pat = _clamp_int(best_train_policy.early_stop_patience + rng.choice([-1, 0, 1]), 1, 10)
                    cand_pgs = _clamp_int(best_train_policy.parallel_group_size + rng.choice([-1, 0, 1]), 1, 8)
                else:
                    cand_logits = {
                        arm: mu_mut_logits[arm] + rng.gauss(0.0, sigma_mut_logits[arm])
                        for arm in all_arms
                    }
                    cand_prio = {
                        k: _clamp(mu_prio[k] + rng.gauss(0.0, sigma_prio[k]), 0.1, 4.0)
                        for k in prio_keys
                    }
                    cand_dom = {
                        d: _clamp(mu_dom[d] + rng.gauss(0.0, sigma_dom[d]), 0.1, 4.0)
                        for d in dom_keys
                    }
                    cand_alpha = _clamp(mu_alpha + rng.gauss(0.0, sigma_alpha), 0.0, 1.0)
                    cand_norm = _clamp(mu_norm + rng.gauss(0.0, sigma_norm), 0.1, 0.9)
                    cand_delta = _clamp(mu_delta + rng.gauss(0.0, sigma_delta), 0.1, 0.9)
                    cand_bw = _clamp_int(rng.choice(elite_bw_pool) + rng.choice([-2, -1, 0, 1, 2]), 1, 10)
                    cand_pat = _clamp_int(rng.choice(elite_pat_pool) + rng.choice([-2, -1, 0, 1, 2]), 1, 10)
                    cand_pgs = _clamp_int(rng.choice(elite_pgs_pool) + rng.choice([-1, 0, 1]), 1, 8)

                cand_policy = DreamPolicy(
                    generation=self.current_generation,
                    mutator_weights=_softmax_logits(cand_logits, floor=0.02),
                    normative_bias=cand_norm,
                    delta_aggressiveness=cand_delta,
                    branch_width=cand_bw,
                    depth_vs_breadth_alpha=cand_alpha,
                    early_stop_patience=cand_pat,
                    parallel_group_size=cand_pgs,
                    priority_weights=cand_prio,
                    domain_weights=cand_dom,
                    stack_profile=resolved_stack,
                    simulator_backend=BACKEND_RECORDED_REPLAY,
                )
                tr_metrics = self.evaluate_policy_on_trees(
                    cand_policy,
                    tr_trees,
                    replay_pool=pool,
                    budget_steps=budget,
                    seed=train_eval_seed,
                    eval_seeds_per_tree=eval_seeds_per_tree,
                )
                tr_score = tr_metrics["mean_reward"]
                cand_policy.fitness_score = tr_score
                cand_policy.simulated_yield = tr_metrics["mean_vuln_rate"]
                cand_policy.false_positive_rate = tr_metrics["mean_noise_rate"]
                scored_population.append((tr_score, cand_policy, cand_logits, tr_metrics))

            scored_population.sort(key=lambda item: item[0], reverse=True)
            elites = scored_population[:n_elite]

            # Update best-seen training policy
            gen_best_score, gen_best_policy, _, _ = elites[0]
            if gen_best_score > best_train_score:
                best_train_score = gen_best_score
                best_train_policy = copy.deepcopy(gen_best_policy)

            # CEM distribution update over elites (continuous Gaussian + discrete empirical pool)
            def _update_mean_std(vals: List[float], old_mu: float, old_sig: float, sig_floor: float) -> Tuple[float, float]:
                e_mu = sum(vals) / float(len(vals))
                var = sum((v - e_mu) ** 2 for v in vals) / float(max(1, len(vals)))
                e_sig = max(sig_floor, math.sqrt(var))
                new_mu = polyak * e_mu + (1.0 - polyak) * old_mu
                new_sig = max(sig_floor, polyak * e_sig + (1.0 - polyak) * old_sig)
                return (new_mu, new_sig)

            for arm in all_arms:
                # Re-center elite logits to zero-mean to avoid drift
                vals = []
                for _, _, lg, _ in elites:
                    mean_lg = sum(lg.values()) / float(max(1, len(lg)))
                    vals.append(lg[arm] - mean_lg)
                mu_mut_logits[arm], sigma_mut_logits[arm] = _update_mean_std(
                    vals, mu_mut_logits[arm], sigma_mut_logits[arm], sig_floor=0.12
                )
            for k in prio_keys:
                vals = [ep.priority_weights[k] for _, ep, _, _ in elites]
                mu_prio[k], sigma_prio[k] = _update_mean_std(vals, mu_prio[k], sigma_prio[k], sig_floor=0.10)
            for d in dom_keys:
                vals = [ep.domain_weights.get(d, 1.0) for _, ep, _, _ in elites]
                mu_dom[d], sigma_dom[d] = _update_mean_std(vals, mu_dom[d], sigma_dom[d], sig_floor=0.10)

            mu_alpha, sigma_alpha = _update_mean_std(
                [ep.depth_vs_breadth_alpha for _, ep, _, _ in elites], mu_alpha, sigma_alpha, sig_floor=0.08
            )
            mu_norm, sigma_norm = _update_mean_std(
                [ep.normative_bias for _, ep, _, _ in elites], mu_norm, sigma_norm, sig_floor=0.06
            )
            mu_delta, sigma_delta = _update_mean_std(
                [ep.delta_aggressiveness for _, ep, _, _ in elites], mu_delta, sigma_delta, sig_floor=0.06
            )

            elite_bw_pool = [ep.branch_width for _, ep, _, _ in elites]
            elite_pat_pool = [ep.early_stop_patience for _, ep, _, _ in elites]
            elite_pgs_pool = [ep.parallel_group_size for _, ep, _, _ in elites]

            # Held-out validation promotion gate
            if has_val:
                val_metrics = self.evaluate_policy_on_trees(
                    gen_best_policy,
                    vl_trees,
                    replay_pool=pool,
                    budget_steps=budget,
                    seed=val_eval_seed,
                    eval_seeds_per_tree=eval_seeds_per_tree,
                )
                cand_val_score = val_metrics["mean_reward"]
                if cand_val_score > best_val_score + 1e-6:
                    best_val_score = cand_val_score
                    promoted_policy = copy.deepcopy(gen_best_policy)
                    promoted_policy.val_fitness_score = cand_val_score
                    promoted_policy.simulated_yield = val_metrics["mean_vuln_rate"]
                    promoted_policy.false_positive_rate = val_metrics["mean_noise_rate"]
                    promotions_accepted += 1
                else:
                    promotions_rejected += 1
            else:
                if gen_best_score > best_val_score + 1e-6:
                    best_val_score = gen_best_score
                    promoted_policy = copy.deepcopy(gen_best_policy)
                    promoted_policy.val_fitness_score = 0.0
                    promotions_accepted += 1
                else:
                    promotions_rejected += 1

        promoted_policy.generation = self.current_generation
        promoted_policy.simulator_backend = BACKEND_RECORDED_REPLAY
        promoted_policy.stack_profile = resolved_stack

        if promotions_accepted > 0:
            promoted_policy.rsi_gain = (best_val_score - baseline_val_score) / max(1.0, abs(baseline_val_score))
        else:
            promoted_policy.rsi_gain = 0.0

        self.active_policy = promoted_policy
        self.last_evolution_report = {
            "simulator_backend": BACKEND_RECORDED_REPLAY,
            "stack_profile": resolved_stack,
            "generations": gens,
            "population_size": pop_size,
            "budget_steps": budget,
            "seed": base_seed,
            "train_tree_count": len(tr_trees),
            "val_tree_count": len(vl_trees),
            "baseline_train_score": round(baseline_train_score, 4),
            "baseline_val_score": round(baseline_val_score, 4),
            "final_train_score": round(promoted_policy.fitness_score, 4),
            "final_val_score": round(promoted_policy.val_fitness_score, 4),
            "promotions_accepted": promotions_accepted,
            "promotions_rejected": promotions_rejected,
            "rsi_gain": round(promoted_policy.rsi_gain, 4),
        }
        return self.active_policy

    def evaluate_policy_fitness(self, policy: DreamPolicy, rollouts: int = 200) -> float:
        """
        Cold-start fallback: runs simulated rollouts against `ProtocolWorldModel.simulate_probe()`.
        Reward objective:
          F(pi) = +10.0 * Vulns + 3.0 * Anomalies - 8.0 * FalsePositives - 0.01 * Steps
        """
        true_vulns = 0
        true_anomalies = 0
        false_positives = 0

        arms = list(policy.mutator_weights.keys())
        weights = list(policy.mutator_weights.values())
        total_w = sum(weights) or 1.0
        norm_weights = [w / total_w for w in weights]

        for _ in range(rollouts):
            chosen_arm = random.choices(arms, weights=norm_weights, k=1)[0]
            probe = self._synthesize_simulated_probe_for_arm(chosen_arm)
            sim_resp = self.world_model.simulate_probe(probe)

            if sim_resp.is_vulnerability:
                true_vulns += 1
            elif sim_resp.is_anomaly:
                true_anomalies += 1
            elif "framing omission" in sim_resp.details.lower():
                false_positives += 1

        fitness = (10.0 * true_vulns) + (3.0 * true_anomalies) - (8.0 * false_positives) - (0.01 * rollouts)
        policy.fitness_score = fitness
        policy.simulated_yield = (true_vulns + true_anomalies) / max(1, rollouts)
        policy.false_positive_rate = false_positives / max(1, rollouts)
        if not getattr(self.world_model, "has_recorded_replay_trees", False):
            policy.simulator_backend = BACKEND_SYNTHETIC_FALLBACK
        return fitness

    def _synthesize_simulated_probe_for_arm(self, arm_name: str) -> bytes:
        """Synthesizes structural byte patterns corresponding to exploration arms."""
        if arm_name == "TE_CL_DUAL_HEADER":
            return b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        elif arm_name == "PATH_NUL_EARLY_RESPONSE":
            return b"POST /nul HTTP/1.1\r\nHost: target.local\r\nContent-Length: 0\r\n\r\n"
        elif arm_name == "DANGLING_BYTE_STACKED_RESPONSE":
            return b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 1\r\n\r\n"
        elif arm_name == "MULTIPART_BYTERANGES_SHARED_PARSER":
            return b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Type: multipart/byteranges; boundary=B\r\nContent-Length: 0\r\n\r\n"
        elif arm_name == "HEADER_TAB_SPACING":
            return b"GET / HTTP/1.1\r\nHost: target.local\r\nX-Foo:\tbar\r\n\r\n"
        elif arm_name == "OBS_FOLD_LINE_JOIN":
            return b"GET / HTTP/1.1\r\nHost: target.local\r\nX-Header: val\r\n continued\r\n\r\n"
        elif arm_name == "OVERLONG_UTF8_NORMALIZATION":
            return b"GET / HTTP/1.1\r\nHost: target.local\r\nHeader: \xc0\x8a\r\n\r\n"
        return b"GET / HTTP/1.1\r\nHost: target.local\r\n\r\n"

    def evolve_policy_generation(
        self,
        rollouts_per_candidate: int = 200,
        population_size: int = 6,
        *,
        seed: Optional[int] = None,
        budget_steps: Optional[int] = None,
        stack_profile: Optional[str] = None,
    ) -> DreamPolicy:
        """
        Executes one evolutionary generation of off-policy dreaming.

        Prefers `self.world_model.replay_pool` whenever recorded discovery trees
        exist (`len(trees) >= 1`), stamping `simulator_backend='recorded_blackboard_replay'`.
        Falls back to cold-start `ProtocolWorldModel.simulate_probe()` ONLY when zero
        recorded trees exist, explicitly stamping `simulator_backend='synthetic_heuristic_fallback'`.
        """
        replay_pool = getattr(self.world_model, "replay_pool", None)
        if replay_pool is not None and len(replay_pool) >= 1:
            resolved_budget = int(budget_steps) if budget_steps is not None else max(15, min(int(rollouts_per_candidate), 60))
            resolved_seed = int(seed) if seed is not None else (42 + self.current_generation * 17)
            return self.evolve_meta_policy_from_replay(
                replay_pool,
                generations=1,
                population_size=max(6, int(population_size)),
                budget_steps=resolved_budget,
                seed=resolved_seed,
                stack_profile=stack_profile,
            )

        # Cold-start synthetic heuristic fallback (0 recorded trees)
        self.current_generation += 1
        base_fitness = self.evaluate_policy_fitness(self.active_policy, rollouts=rollouts_per_candidate)

        rng = random.Random(int(seed)) if seed is not None else random
        candidates: List[DreamPolicy] = []
        for _ in range(population_size):
            cand_weights = copy.deepcopy(self.active_policy.mutator_weights)
            for arm in cand_weights:
                perturbation = rng.gauss(0.0, 0.2)
                cand_weights[arm] = max(0.05, cand_weights[arm] + perturbation)

            sum_w = sum(cand_weights.values()) or 1.0
            for arm in cand_weights:
                cand_weights[arm] /= sum_w

            cand_policy = DreamPolicy(
                generation=self.current_generation,
                mutator_weights=cand_weights,
                normative_bias=_clamp(self.active_policy.normative_bias + rng.gauss(0.0, 0.1), 0.1, 0.9),
                delta_aggressiveness=_clamp(self.active_policy.delta_aggressiveness + rng.gauss(0.0, 0.1), 0.1, 0.9),
                branch_width=self.active_policy.branch_width,
                depth_vs_breadth_alpha=self.active_policy.depth_vs_breadth_alpha,
                early_stop_patience=self.active_policy.early_stop_patience,
                parallel_group_size=self.active_policy.parallel_group_size,
                priority_weights=dict(self.active_policy.priority_weights),
                domain_weights=dict(self.active_policy.domain_weights),
                stack_profile=stack_profile or self.active_policy.stack_profile or "generic",
                simulator_backend=BACKEND_SYNTHETIC_FALLBACK,
                val_fitness_score=0.0,
            )
            self.evaluate_policy_fitness(cand_policy, rollouts=rollouts_per_candidate)
            candidates.append(cand_policy)

        best_candidate = max(candidates, key=lambda p: p.fitness_score)

        if best_candidate.fitness_score > base_fitness:
            gain = (best_candidate.fitness_score - base_fitness) / max(1.0, abs(base_fitness))
            best_candidate.rsi_gain = gain
            best_candidate.simulator_backend = BACKEND_SYNTHETIC_FALLBACK
            self.active_policy = best_candidate
        else:
            self.active_policy = copy.deepcopy(self.active_policy)
            self.active_policy.generation = self.current_generation
            self.active_policy.rsi_gain = 0.0
            self.active_policy.simulator_backend = BACKEND_SYNTHETIC_FALLBACK

        self.last_evolution_report = {
            "simulator_backend": BACKEND_SYNTHETIC_FALLBACK,
            "train_tree_count": 0,
            "val_tree_count": 0,
            "final_train_score": round(self.active_policy.fitness_score, 4),
            "final_val_score": 0.0,
            "rsi_gain": round(self.active_policy.rsi_gain, 4),
        }
        return self.active_policy
