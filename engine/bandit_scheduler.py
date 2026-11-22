"""
Module 2: Adaptive Bandit and Genetic Scheduler (P0).

Employs Multi-Armed Bandit (UCB1 / Epsilon-Greedy) and Genetic Algorithm heuristics
to dynamically prioritize mutation families that yield high parser divergence
and protocol desynchronization, with bounded Dream-RSI prior injection and
meta-exploration control hot-reloading.
"""

import copy
import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class BanditArmStats:
    name: str
    pulls: int = 0
    total_reward: float = 0.0
    anomalies_found: int = 0
    vulnerabilities_confirmed: int = 0
    last_pulled_at: float = field(default_factory=time.time)

    @property
    def mean_reward(self) -> float:
        return self.total_reward / self.pulls if self.pulls > 0 else 0.0


@dataclass
class GeneticIndividual:
    payload: bytes
    mutation_family: str
    fitness_score: float = 0.0
    generation: int = 0


class AdaptiveBanditScheduler:
    """
    Manages active exploration vs exploitation across mutation families,
    breeds high-fitness protocol mutations using genetic operations, and
    accepts bounded Dream-RSI policy hot-reloads with meta-exploration controls.
    """

    CORE_MUTATION_FAMILIES = [
        "ABNF_INVERSION",
        "CRLF_DELIMITER_SPLIT",
        "TE_CL_DUAL_HEADER",
        "CHUNK_EXTENSION_CORRUPTION",
        "OBS_FOLD_MUTATION",
        "HOP_BY_HOP_INVERSION",
        "SHARED_PARSER_REVERSAL",
        "UNICODE_BOM_INJECTION",
    ]

    MAX_PRIOR_PULLS_PER_ARM = 4
    MAX_PRIOR_REWARD_PER_ARM = 10.0

    def __init__(self, exploration_weight: float = 1.414, epsilon: float = 0.15):
        self.c = exploration_weight  # UCB1 exploration constant
        self.epsilon = epsilon
        self.total_pulls = 0
        self.arms: Dict[str, BanditArmStats] = {
            name: BanditArmStats(name=name) for name in self.CORE_MUTATION_FAMILIES
        }
        self.population: List[GeneticIndividual] = []
        self.max_population = 50
        # Tracks previously applied Dream-RSI prior (pulls, reward) per arm to cap cumulative drift
        self._dream_prior_applied: Dict[str, Tuple[int, float]] = {}
        self.active_meta_controls: Dict[str, Any] = {
            "branch_width": 3,
            "depth_vs_breadth_alpha": 0.5,
            "early_stop_patience": 4,
            "parallel_group_size": 4,
            "priority_weights": {
                "cascade_intent": 1.0,
                "dual_graph_multihop": 1.2,
                "abnf_seed": 0.8,
                "llm_candidate": 1.0,
                "hint_boost": 1.5,
            },
            "domain_weights": {},
            "stack_profile": "generic",
            "simulator_backend": "none",
            "policy_generation": 0,
        }

    def select_arm(self) -> str:
        """Selects the next mutation family using UCB1 with epsilon-greedy fallback."""
        self.total_pulls += 1

        # Phase 1: Try every arm at least once (Cold Start)
        for name, arm in self.arms.items():
            if arm.pulls == 0:
                return name

        # Phase 2: Epsilon exploration
        if random.random() < self.epsilon:
            return random.choice(list(self.arms.keys()))

        # Phase 3: UCB1 score calculation
        best_score = -1.0
        best_arm = list(self.arms.keys())[0]

        for name, arm in self.arms.items():
            bonus = self.c * math.sqrt(math.log(max(1, self.total_pulls)) / arm.pulls)
            score = arm.mean_reward + bonus
            if score > best_score:
                best_score = score
                best_arm = name

        return best_arm

    def record_feedback(
        self,
        family: str,
        reward: float,
        is_anomaly: bool = False,
        is_vulnerability: bool = False,
        payload: Optional[bytes] = None,
    ) -> None:
        """Updates bandit arms and populates the genetic breeding pool."""
        if family not in self.arms:
            self.arms[family] = BanditArmStats(name=family)

        arm = self.arms[family]
        arm.pulls += 1
        arm.total_reward += reward
        arm.last_pulled_at = time.time()

        if is_anomaly:
            arm.anomalies_found += 1
        if is_vulnerability:
            arm.vulnerabilities_confirmed += 1

        # Register into genetic population if fitness is positive
        if payload and reward > 0.5:
            individual = GeneticIndividual(
                payload=payload,
                mutation_family=family,
                fitness_score=reward,
            )
            self.population.append(individual)
            self.population.sort(key=lambda ind: ind.fitness_score, reverse=True)
            if len(self.population) > self.max_population:
                self.population.pop()

    def breed_next_generation(self) -> Optional[bytes]:
        """
        Applies genetic crossover and mutation to breed a novel candidate probe
        from the highest-performing individuals in the population.
        """
        if len(self.population) < 2:
            return None

        # Tournament selection of parents
        parent1 = random.choice(self.population[:5])
        parent2 = random.choice(self.population[:10])

        # Crossover: split headers and combine
        p1_lines = parent1.payload.split(b"\r\n")
        p2_lines = parent2.payload.split(b"\r\n")

        split_idx1 = max(1, len(p1_lines) // 2)
        split_idx2 = max(1, len(p2_lines) // 2)

        child_lines = p1_lines[:split_idx1] + p2_lines[split_idx2:]
        child_payload = b"\r\n".join(child_lines)

        # Mutation: bit-flip or delimiter substitution
        child_payload = self._apply_genetic_mutation(child_payload)
        return child_payload

    def _apply_genetic_mutation(self, payload: bytes) -> bytes:
        """Applies point mutation to a byte sequence."""
        if not payload:
            return payload

        mutations = [
            lambda p: p.replace(b" ", b"\t", 1),
            lambda p: p.replace(b"\r\n", b"\n", 1),
            lambda p: p.replace(b"chunked", b"chunked ", 1),
            lambda p: p + b"\r\n0\r\n\r\n",
            lambda p: p.replace(b": ", b":\t", 1),
        ]
        choice = random.choice(mutations)
        try:
            return choice(payload)
        except Exception:
            return payload

    def get_summary(self) -> Dict[str, Any]:
        """Returns diagnostic metrics for arms."""
        return {
            name: {
                "pulls": arm.pulls,
                "mean_reward": round(arm.mean_reward, 4),
                "anomalies": arm.anomalies_found,
                "vulnerabilities": arm.vulnerabilities_confirmed,
            }
            for name, arm in self.arms.items()
        }

    def get_meta_controls(self) -> Dict[str, Any]:
        """Returns a copy of the currently active Dream-RSI meta-exploration controls."""
        return copy.deepcopy(self.active_meta_controls)

    def apply_dream_policy(self, policy: Any) -> None:
        """
        Hot-reloads mutator weights and meta-exploration controls evolved by Dream-RSI
        into the active scheduler. Replaces prior dream injections in-place and caps
        per-arm prior strength so repeated dream cycles never cause unbounded drift.
        """
        if policy is None:
            return

        # Always synchronize meta-exploration controls when present
        prio_w = getattr(policy, "priority_weights", None)
        dom_w = getattr(policy, "domain_weights", None)
        self.active_meta_controls = {
            "branch_width": max(1, int(getattr(policy, "branch_width", self.active_meta_controls["branch_width"]) or 3)),
            "depth_vs_breadth_alpha": max(
                0.0,
                min(
                    1.0,
                    float(
                        getattr(
                            policy,
                            "depth_vs_breadth_alpha",
                            self.active_meta_controls["depth_vs_breadth_alpha"],
                        )
                    ),
                ),
            ),
            "early_stop_patience": max(
                1, int(getattr(policy, "early_stop_patience", self.active_meta_controls["early_stop_patience"]) or 4)
            ),
            "parallel_group_size": max(
                1, int(getattr(policy, "parallel_group_size", self.active_meta_controls["parallel_group_size"]) or 4)
            ),
            "priority_weights": (
                {str(k): float(v) for k, v in prio_w.items()}
                if isinstance(prio_w, dict) and prio_w
                else copy.deepcopy(self.active_meta_controls["priority_weights"])
            ),
            "domain_weights": (
                {str(k): float(v) for k, v in dom_w.items()} if isinstance(dom_w, dict) else {}
            ),
            "stack_profile": str(getattr(policy, "stack_profile", "generic") or "generic"),
            "simulator_backend": str(getattr(policy, "simulator_backend", "recorded_blackboard_replay") or "recorded_blackboard_replay"),
            "policy_generation": int(getattr(policy, "generation", 0) or 0),
        }

        weights = getattr(policy, "mutator_weights", None)
        if not weights or not isinstance(weights, dict):
            return

        # Roll back previously injected dream priors so live empirical counts remain intact
        for prev_arm, (old_pulls, old_reward) in list(self._dream_prior_applied.items()):
            if prev_arm in self.arms:
                arm = self.arms[prev_arm]
                removable_pulls = min(arm.pulls, old_pulls)
                arm.pulls -= removable_pulls
                arm.total_reward = max(0.0, arm.total_reward - old_reward)
                self.total_pulls = max(0, self.total_pulls - removable_pulls)
        self._dream_prior_applied.clear()

        # Normalize positive weights if their total exceeds 1.0 to enforce bounded prior budget
        cleaned_weights: Dict[str, float] = {}
        for arm_name, raw_w in weights.items():
            try:
                w_val = max(0.0, float(raw_w))
            except (ValueError, TypeError):
                w_val = 0.0
            cleaned_weights[str(arm_name)] = w_val

        total_w = sum(cleaned_weights.values())
        scale = (1.0 / total_w) if total_w > 1.0 else 1.0

        prior_pulls = min(self.MAX_PRIOR_PULLS_PER_ARM, 2)
        for arm_name, w_val in cleaned_weights.items():
            if arm_name not in self.arms:
                self.arms[arm_name] = BanditArmStats(name=arm_name)
            prior_reward = min(self.MAX_PRIOR_REWARD_PER_ARM, (w_val * scale) * self.MAX_PRIOR_REWARD_PER_ARM)
            self.arms[arm_name].total_reward += prior_reward
            self.arms[arm_name].pulls += prior_pulls
            self.total_pulls += prior_pulls
            self._dream_prior_applied[arm_name] = (prior_pulls, prior_reward)
