"""
Module 15b: Standardized 4-Baseline Empirical RL Benchmark for Dream-RSI.

Compares 5 exploration policies over matched episode seeds and identical discovery
topologies:
  1. Disabled         (unguided FIFO traversal)
  2. Random           (uniform random frontier selection)
  3. Heuristic        (static priority + online UCB1 without dreaming)
  4. NoLearning       (frozen Generation-0 DreamPolicy)
  5. DreamRSI_Learned (meta-exploration policy evolved via CEM over replay trees)

Computes exact Student-t 95% Confidence Intervals over cumulative episode reward,
confirmed vulnerability discovery rate per budget step, and noise/wasted probe rate,
plus matched-seed paired difference CIs against each baseline.

Strictly labels `simulator_backend`:
  - "recorded_blackboard_replay": offline zero-network replay over recorded trees
  - "local_testlab_live": live loopback TCP socket execution against 127.0.0.1 TestLabServer
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import math
import random
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from engine.dream_policy_store import DreamPolicyStore
from engine.dream_replay_pool import (
    BACKEND_LIVE_TESTLAB,
    BACKEND_RECORDED_REPLAY,
    DiscoveryTree,
    ReplayNode,
    ReplayOutcome,
    ReplayTreePool,
    compute_replay_reward,
)
from engine.dream_rsi_optimizer import DreamPolicy, DreamRSIOptimizer
from engine.dream_world_model import ProtocolWorldModel

POLICY_ORDER: Tuple[str, ...] = (
    "Disabled",
    "Random",
    "Heuristic",
    "NoLearning",
    "DreamRSI_Learned",
)

BASELINE_NAMES: Tuple[str, ...] = (
    "Disabled",
    "Random",
    "Heuristic",
    "NoLearning",
)

_ALLOWED_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


# ---------------------------------------------------------------------------
# Pure-stdlib exact Student-t critical values and 95% Confidence Intervals
# ---------------------------------------------------------------------------

def _betacf(a: float, b: float, x: float) -> float:
    """Lentz modified continued fraction for the regularized incomplete beta function."""
    max_iter = 200
    eps = 3.0e-12
    fpmin = 1.0e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def _regularized_incomplete_beta(a: float, b: float, x: float) -> float:
    """Computes I_x(a, b) with double-precision accuracy."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_bt = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log(1.0 - x)
    )
    bt = math.exp(log_bt)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def student_t_critical(df: int, confidence: float = 0.95) -> float:
    """
    Computes exact two-tailed Student-t critical value t_{1 - alpha/2, df}
    using the regularized incomplete beta identity and bisection.
    """
    if df <= 0:
        return 0.0
    alpha = max(1e-9, min(0.999999, 1.0 - float(confidence)))

    def two_tail_p(t_val: float) -> float:
        x = float(df) / (float(df) + t_val * t_val)
        return _regularized_incomplete_beta(0.5 * float(df), 0.5, x)

    lo = 0.0
    hi = 2.0
    while two_tail_p(hi) > alpha and hi < 1e6:
        hi *= 2.0

    for _ in range(72):
        mid = 0.5 * (lo + hi)
        if two_tail_p(mid) > alpha:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


@dataclass
class ConfidenceInterval:
    mean: float
    std: float
    ci_low: float
    ci_high: float
    half_width: float
    t_critical: float
    n: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mean": round(self.mean, 4),
            "std": round(self.std, 4),
            "ci_low": round(self.ci_low, 4),
            "ci_high": round(self.ci_high, 4),
            "half_width": round(self.half_width, 4),
            "t_critical": round(self.t_critical, 4),
            "n": int(self.n),
        }

    def format_compact(self, precision: int = 2) -> str:
        return (
            f"{self.mean:.{precision}f} +/- {self.half_width:.{precision}f} "
            f"[{self.ci_low:.{precision}f}, {self.ci_high:.{precision}f}]"
        )


def compute_confidence_interval(samples: Sequence[float], confidence: float = 0.95) -> ConfidenceInterval:
    """Computes exact Student-t confidence interval: x_bar +/- t_{alpha/2, n-1} * s / sqrt(n)."""
    vals = [float(x) for x in samples]
    n = len(vals)
    if n == 0:
        return ConfidenceInterval(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0)
    mean = sum(vals) / float(n)
    if n == 1:
        return ConfidenceInterval(mean, 0.0, mean, mean, 0.0, 0.0, 1)
    var = sum((x - mean) ** 2 for x in vals) / float(n - 1)
    std = math.sqrt(max(0.0, var))
    t_crit = student_t_critical(n - 1, confidence=confidence)
    half_w = t_crit * (std / math.sqrt(float(n)))
    return ConfidenceInterval(
        mean=mean,
        std=std,
        ci_low=mean - half_w,
        ci_high=mean + half_w,
        half_width=half_w,
        t_critical=t_crit,
        n=n,
    )


@dataclass
class PolicyBenchmarkMetrics:
    policy_name: str
    cumulative_reward: ConfidenceInterval
    vuln_discovery_rate: ConfidenceInterval
    noise_rate: ConfidenceInterval
    mean_vulns_found: float
    mean_chains_found: float
    mean_anomalies_found: float
    mean_steps_taken: float
    mean_early_stopped_branches: float
    episode_rewards: List[float] = field(default_factory=list)
    episode_vuln_rates: List[float] = field(default_factory=list)
    episode_noise_rates: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "cumulative_reward": self.cumulative_reward.to_dict(),
            "vuln_discovery_rate": self.vuln_discovery_rate.to_dict(),
            "noise_rate": self.noise_rate.to_dict(),
            "mean_vulns_found": round(self.mean_vulns_found, 4),
            "mean_chains_found": round(self.mean_chains_found, 4),
            "mean_anomalies_found": round(self.mean_anomalies_found, 4),
            "mean_steps_taken": round(self.mean_steps_taken, 4),
            "mean_early_stopped_branches": round(self.mean_early_stopped_branches, 4),
            "episode_rewards": [round(r, 4) for r in self.episode_rewards],
        }


@dataclass
class BenchmarkReport:
    simulator_backend: str
    matched_seeds: List[int]
    budget_steps: int
    train_tree_count: int
    val_tree_count: int
    stack_profile: str
    policies: Dict[str, PolicyBenchmarkMetrics]
    paired_comparisons: Dict[str, Dict[str, Any]]
    learned_policy: Dict[str, Any]
    duration_seconds: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "simulator_backend": self.simulator_backend,
            "num_seeds": len(self.matched_seeds),
            "matched_seeds": list(self.matched_seeds),
            "budget_steps": int(self.budget_steps),
            "train_tree_count": int(self.train_tree_count),
            "val_tree_count": int(self.val_tree_count),
            "stack_profile": self.stack_profile,
            "duration_seconds": round(self.duration_seconds, 4),
            "policies": {k: v.to_dict() for k, v in self.policies.items()},
            "paired_comparisons": self.paired_comparisons,
            "learned_policy": self.learned_policy,
            "notes": list(self.notes),
        }

    def format_markdown_table(self) -> str:
        lines: List[str] = [
            f"### Dream-RSI Empirical 4-Baseline RL Benchmark (`{self.simulator_backend}`)",
            "",
            f"- **Simulator Backend**: `{self.simulator_backend}`",
            f"- **Matched Seeds**: `{len(self.matched_seeds)}` (`{self.matched_seeds[0]}..{self.matched_seeds[-1]}`)"
            if self.matched_seeds
            else "- **Matched Seeds**: `0`",
            f"- **Step Budget**: `{self.budget_steps}` | **Train Trees**: `{self.train_tree_count}` | **Eval Trees**: `{self.val_tree_count}` | **Stack**: `{self.stack_profile}`",
            "",
            "| Policy | Cumulative Reward (95% CI) | Vuln Rate / Budget (95% CI) | Noise Rate (95% CI) | Mean Vulns | Early Stops |",
            "| :--- | :--- | :--- | :--- | ---: | ---: |",
        ]
        for pname in POLICY_ORDER:
            m = self.policies.get(pname)
            if m is None:
                continue
            lines.append(
                f"| `{pname}` "
                f"| {m.cumulative_reward.format_compact(2)} "
                f"| {m.vuln_discovery_rate.format_compact(3)} "
                f"| {m.noise_rate.format_compact(3)} "
                f"| {m.mean_vulns_found:.2f} "
                f"| {m.mean_early_stopped_branches:.2f} |"
            )

        if self.paired_comparisons:
            lines.extend([
                "",
                "| Paired Comparison (`DreamRSI_Learned - Baseline`) | Reward Delta (95% CI) | Beats Baseline | 95% CI > 0 |",
                "| :--- | :--- | :---: | :---: |",
            ])
            for bname in BASELINE_NAMES:
                comp = self.paired_comparisons.get(bname)
                if not comp:
                    continue
                rd = comp["reward_delta"]
                ci_str = f"{rd['mean']:+.2f} +/- {rd['half_width']:.2f} [{rd['ci_low']:+.2f}, {rd['ci_high']:+.2f}]"
                lines.append(
                    f"| vs `{bname}` | {ci_str} | {'YES' if comp['beats_baseline'] else 'NO'} | "
                    f"{'YES' if comp['statistically_significant'] else 'NO'} |"
                )

        if self.notes:
            lines.append("")
            for note in self.notes:
                lines.append(f"- Note: {note}")
        return "\n".join(lines)


def _aggregate_policy_metrics(
    policy_name: str,
    per_seed_outcomes: List[List[ReplayOutcome]],
) -> PolicyBenchmarkMetrics:
    ep_rewards: List[float] = []
    ep_vuln_rates: List[float] = []
    ep_noise_rates: List[float] = []
    ep_vulns: List[float] = []
    ep_chains: List[float] = []
    ep_anoms: List[float] = []
    ep_steps: List[float] = []
    ep_stops: List[float] = []

    for seed_outs in per_seed_outcomes:
        if not seed_outs:
            continue
        k = float(len(seed_outs))
        ep_rewards.append(sum(o.reward for o in seed_outs) / k)
        ep_vuln_rates.append(sum(o.vuln_discovery_rate for o in seed_outs) / k)
        ep_noise_rates.append(sum(o.noise_rate for o in seed_outs) / k)
        ep_vulns.append(sum(o.vulns_found for o in seed_outs) / k)
        ep_chains.append(sum(o.chains_found for o in seed_outs) / k)
        ep_anoms.append(sum(o.anomalies_found for o in seed_outs) / k)
        ep_steps.append(sum(o.steps_taken for o in seed_outs) / k)
        ep_stops.append(sum(o.early_stopped_branches for o in seed_outs) / k)

    n = float(max(1, len(ep_rewards)))
    return PolicyBenchmarkMetrics(
        policy_name=policy_name,
        cumulative_reward=compute_confidence_interval(ep_rewards),
        vuln_discovery_rate=compute_confidence_interval(ep_vuln_rates),
        noise_rate=compute_confidence_interval(ep_noise_rates),
        mean_vulns_found=sum(ep_vulns) / n,
        mean_chains_found=sum(ep_chains) / n,
        mean_anomalies_found=sum(ep_anoms) / n,
        mean_steps_taken=sum(ep_steps) / n,
        mean_early_stopped_branches=sum(ep_stops) / n,
        episode_rewards=ep_rewards,
        episode_vuln_rates=ep_vuln_rates,
        episode_noise_rates=ep_noise_rates,
    )


def _build_paired_comparisons(
    policies: Dict[str, PolicyBenchmarkMetrics],
) -> Dict[str, Dict[str, Any]]:
    learned = policies.get("DreamRSI_Learned")
    if learned is None:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for bname in BASELINE_NAMES:
        base = policies.get(bname)
        if base is None:
            continue
        n = min(len(learned.episode_rewards), len(base.episode_rewards))
        deltas = [learned.episode_rewards[i] - base.episode_rewards[i] for i in range(n)]
        vuln_deltas = [learned.episode_vuln_rates[i] - base.episode_vuln_rates[i] for i in range(n)]
        noise_deltas = [learned.episode_noise_rates[i] - base.episode_noise_rates[i] for i in range(n)]
        r_ci = compute_confidence_interval(deltas)
        v_ci = compute_confidence_interval(vuln_deltas)
        n_ci = compute_confidence_interval(noise_deltas)
        out[bname] = {
            "reward_delta": r_ci.to_dict(),
            "vuln_rate_delta": v_ci.to_dict(),
            "noise_rate_delta": n_ci.to_dict(),
            "beats_baseline": bool(r_ci.mean > 0.0),
            "statistically_significant": bool(r_ci.ci_low > 0.0),
        }
    return out


# ---------------------------------------------------------------------------
# 1. Offline Recorded Blackboard Replay Benchmark (Zero Network / Zero LLM)
# ---------------------------------------------------------------------------

def run_replay_benchmark(
    replay_pool: ReplayTreePool,
    *,
    num_seeds: int = 10,
    budget_steps: int = 40,
    base_seed: int = 42,
    generations: int = 5,
    population_size: int = 12,
    val_ratio: float = 0.25,
    stack_profile: Optional[str] = None,
    learned_policy: Optional[DreamPolicy] = None,
) -> BenchmarkReport:
    """
    Runs the standardized 5-policy empirical RL benchmark strictly offline over
    recorded `DiscoveryTree`s in `replay_pool` (`simulator_backend='recorded_blackboard_replay'`).

    Splits `replay_pool` into disjoint `(train_trees, eval_trees)` so the learned
    policy is NEVER trained on the held-out evaluation trees.
    """
    t0 = time.perf_counter()
    if len(replay_pool) == 0:
        raise ValueError(
            "ReplayTreePool is empty; record blackboard_nodes into SQLite or run with live_lab=True."
        )

    resolved_stack = str(stack_profile or "generic").strip().lower() or "generic"
    n_seeds = max(2, int(num_seeds))
    budget = max(1, int(budget_steps))
    matched_seeds = [int(base_seed) + i for i in range(n_seeds)]
    notes: List[str] = []

    train_trees, eval_trees = replay_pool.split_train_val(
        val_ratio=val_ratio,
        seed=base_seed,
        stack_profile=resolved_stack if resolved_stack != "generic" else None,
    )
    if not train_trees and resolved_stack != "generic":
        train_trees, eval_trees = replay_pool.split_train_val(val_ratio=val_ratio, seed=base_seed)
        notes.append(f"No trees matched stack_profile='{resolved_stack}'; fell back to all recorded trees.")

    if not eval_trees:
        eval_trees = list(train_trees)
        notes.append("Single recorded tree in pool; evaluated on the available tree (add >=2 tasks for blind holdout).")

    world_model = ProtocolWorldModel()
    world_model.replay_pool = replay_pool
    optimizer = DreamRSIOptimizer(world_model)

    frozen_baseline = optimizer.create_frozen_baseline_policy(
        trees=train_trees,
        stack_profile=resolved_stack,
        simulator_backend=BACKEND_RECORDED_REPLAY,
    )

    if learned_policy is not None:
        evolved = copy.deepcopy(learned_policy)
        evolved.simulator_backend = BACKEND_RECORDED_REPLAY
    else:
        # Hold out inner validation slice strictly inside train_trees so eval_trees remains 100% blind
        if len(train_trees) >= 3:
            inner_rng = random.Random(base_seed + 313)
            shuffled_tr = list(train_trees)
            inner_rng.shuffle(shuffled_tr)
            n_inner_val = max(1, len(shuffled_tr) // 4)
            inner_train = shuffled_tr[:-n_inner_val]
            inner_val = shuffled_tr[-n_inner_val:]
        else:
            inner_train = list(train_trees)
            inner_val = []

        evolved = optimizer.evolve_meta_policy_from_replay(
            replay_pool,
            generations=generations,
            population_size=population_size,
            budget_steps=budget,
            seed=base_seed,
            stack_profile=resolved_stack,
            train_trees=inner_train,
            val_trees=inner_val,
        )

    policy_specs: List[Tuple[str, str, Optional[DreamPolicy]]] = [
        ("Disabled", "disabled", None),
        ("Random", "random", None),
        ("Heuristic", "heuristic", None),
        ("NoLearning", "nolearning", frozen_baseline),
        ("DreamRSI_Learned", "policy", evolved),
    ]

    policy_metrics: Dict[str, PolicyBenchmarkMetrics] = {}
    for pname, mode, pol in policy_specs:
        per_seed: List[List[ReplayOutcome]] = []
        for ep_seed in matched_seeds:
            seed_outs: List[ReplayOutcome] = []
            for t_idx, tree in enumerate(eval_trees):
                out = replay_pool.simulate_policy_traversal(
                    tree,
                    pol,
                    budget_steps=budget,
                    seed=ep_seed + t_idx * 997,
                    mode=mode,
                    policy_name=pname,
                )
                seed_outs.append(out)
            per_seed.append(seed_outs)
        policy_metrics[pname] = _aggregate_policy_metrics(pname, per_seed)

    paired = _build_paired_comparisons(policy_metrics)
    elapsed = time.perf_counter() - t0
    return BenchmarkReport(
        simulator_backend=BACKEND_RECORDED_REPLAY,
        matched_seeds=matched_seeds,
        budget_steps=budget,
        train_tree_count=len(train_trees),
        val_tree_count=len(eval_trees),
        stack_profile=resolved_stack,
        policies=policy_metrics,
        paired_comparisons=paired,
        learned_policy=evolved.to_dict(),
        duration_seconds=elapsed,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# 2. Local Loopback TestLabServer Live Benchmark (127.0.0.1 ONLY)
# ---------------------------------------------------------------------------

def _assert_loopback_host(host: str) -> str:
    cleaned = str(host or "").strip().lower()
    if cleaned not in _ALLOWED_LOOPBACK_HOSTS:
        raise ValueError(
            f"Live Dream-RSI benchmark strictly permits loopback hosts only (127.0.0.1/localhost/::1); got {host!r}."
        )
    return "127.0.0.1" if cleaned == "localhost" else cleaned


def _send_raw_http_probe(host: str, port: int, raw_request: bytes, timeout: float = 1.5) -> bytes:
    """
    Sends a real raw HTTP/1.1 TCP probe to local loopback `TestLabServer` and parses
    headers + Content-Length cleanly so keep-alive responses return immediately.
    """
    chunks = bytearray()
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(raw_request)
        expected_total: Optional[int] = None
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.extend(data)
            if expected_total is None and b"\r\n\r\n" in chunks:
                hdr, _ = bytes(chunks).split(b"\r\n\r\n", 1)
                m = re.search(rb"(?im)^Content-Length:\s*(\d+)\s*$", hdr)
                if m:
                    expected_total = len(hdr) + 4 + int(m.group(1))
            if expected_total is not None and len(chunks) >= expected_total:
                break
    return bytes(chunks)


def _reset_testlab_state(server: Any) -> None:
    """Resets transient shared pipeline buffers between matched live episodes."""
    lock = getattr(server, "lock", None)
    if lock is not None:
        with lock:
            server.poisoned_prefix = b""
            server.dangling_byte_pending = False
            server.stolen_victim_data = b""
    else:
        server.poisoned_prefix = b""
        server.dangling_byte_pending = False
        server.stolen_victim_data = b""


def _execute_live_probe_on_testlab(
    host: str,
    port: int,
    raw_request: bytes,
    *,
    followup_canary: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Executes a real TCP probe against `TestLabServer` and classifies the actual
    wire response into confirmed vuln / anomaly / chain / noise discard.
    """
    resp = _send_raw_http_probe(host, port, raw_request)
    status_line = resp.split(b"\r\n", 1)[0] if resp else b""
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""

    is_vuln = False
    is_anomaly = False
    is_chain = False
    is_noise = False
    poe_level = 0
    category = "CONFORMANT"

    # Check genuine TestLabServer vulnerability / anomaly signatures on wire bytes
    if b"\x00" * 16 in body and b"\x01\x02\xfe\xff" in body:
        is_vuln = True
        is_anomaly = True
        poe_level = 3
        category = "MEMORY_LEAK_BINARY_BLEND"
    elif body.count(b"<!DOCTYPE html>") >= 2:
        is_vuln = True
        is_anomaly = True
        poe_level = 3
        category = "DOUBLE_HTML_RESPONSE_SPLIT"
    elif b"Server: ATS" in body and b"HTTP/1.1 200 OK" in body:
        is_vuln = True
        is_anomaly = True
        poe_level = 3
        category = "LEAKED_INLINE_HEADERS"
    elif b'"scope": "governance-admin"' in body and b"200 OK" in status_line:
        is_vuln = True
        is_anomaly = True
        is_chain = True
        poe_level = 3
        category = "AUTH_BOUNDARY_BYPASS"
    elif b"Trigger Accepted" in body and followup_canary is not None:
        canary_resp = _send_raw_http_probe(host, port, followup_canary)
        if b"terminator_marker reflected on queue!" in canary_resp:
            is_vuln = True
            is_anomaly = True
            is_chain = True
            poe_level = 3
            category = "DESYNC_QUEUE_POISONING"
        else:
            is_anomaly = True
            category = "DESYNC_TRIGGER_UNCONFIRMED"
    elif b'"canary_echo": "RFCHUNT_CANARY_PROBE"' in body:
        is_anomaly = True
        poe_level = 1
        category = "AI_CHAT_CANARY_REFLECTION"
    elif b"400 Bad Request" in status_line or b"401 Unauthorized" in status_line:
        is_noise = True
        category = "EXPECTED_CLIENT_REJECTION"

    return {
        "is_confirmed_vuln": is_vuln,
        "is_anomaly": is_anomaly,
        "is_attack_chain": is_chain,
        "is_noise_discard": is_noise,
        "poe_level": poe_level,
        "category": category,
        "response_len": len(resp),
    }


def _build_live_testlab_probe_spec(topology_seed: int) -> List[Dict[str, Any]]:
    """
    Constructs a multi-branch candidate probe topology for loopback `TestLabServer`.
    Every candidate carries real HTTP/1.1 wire bytes (no fake outcomes).
    """
    rng = random.Random(int(topology_seed))
    smuggle_body = b"GET /terminator_marker HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    canary_req = b"GET /canary HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    oversized_a = b"A" * 64500

    # Branch 1 (queued first -> FIFO hits noise first): Noise / 400 / 401 rejections
    noise_branch_1 = [
        {
            "node_id": "b_noise_tab_root",
            "parent_node_id": "",
            "mutator_family": "HEADER_TAB_SPACING",
            "domain": "static_noise",
            "rfc_id": "RFC9112-5.1",
            "source_kind": "abnf_seed",
            "priority": 10.0,
            "raw_request": b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nA: " + oversized_a + b"\r\nConnection: close\r\n\r\n",
        },
        {
            "node_id": "b_noise_tab_1",
            "parent_node_id": "b_noise_tab_root",
            "mutator_family": "HEADER_TAB_SPACING",
            "domain": "static_noise",
            "rfc_id": "RFC9112-5.1",
            "source_kind": "abnf_seed",
            "priority": 8.0,
            "raw_request": b"GET /internal/service HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        },
        {
            "node_id": "b_noise_tab_2",
            "parent_node_id": "b_noise_tab_root",
            "mutator_family": "HEADER_TAB_SPACING",
            "domain": "static_noise",
            "rfc_id": "RFC9112-5.1",
            "source_kind": "abnf_seed",
            "priority": 7.0,
            "raw_request": b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        },
        {
            "node_id": "b_noise_tab_3",
            "parent_node_id": "b_noise_tab_1",
            "mutator_family": "HEADER_TAB_SPACING",
            "domain": "static_noise",
            "rfc_id": "RFC9112-5.1",
            "source_kind": "abnf_seed",
            "priority": 6.0,
            "raw_request": b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nA: " + oversized_a + b"\r\nConnection: close\r\n\r\n",
        },
        {
            "node_id": "b_noise_tab_4",
            "parent_node_id": "b_noise_tab_2",
            "mutator_family": "HEADER_TAB_SPACING",
            "domain": "static_noise",
            "rfc_id": "RFC9112-5.1",
            "source_kind": "abnf_seed",
            "priority": 5.0,
            "raw_request": b"GET /internal/service HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        },
    ]

    # Branch 2: Legacy OBS_FOLD noise & conformant dead-ends
    noise_branch_2 = [
        {
            "node_id": "b_obs_root",
            "parent_node_id": "",
            "mutator_family": "OBS_FOLD_LINE_JOIN",
            "domain": "legacy_headers",
            "rfc_id": "RFC9112-5.2",
            "source_kind": "llm_candidate",
            "priority": 9.0,
            "raw_request": b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Fold: a\r\n b\r\nConnection: close\r\n\r\n",
        },
        {
            "node_id": "b_obs_1",
            "parent_node_id": "b_obs_root",
            "mutator_family": "OBS_FOLD_LINE_JOIN",
            "domain": "legacy_headers",
            "rfc_id": "RFC9112-5.2",
            "source_kind": "llm_candidate",
            "priority": 7.0,
            "raw_request": b"GET /internal/service HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        },
        {
            "node_id": "b_obs_2",
            "parent_node_id": "b_obs_root",
            "mutator_family": "OBS_FOLD_LINE_JOIN",
            "domain": "legacy_headers",
            "rfc_id": "RFC9112-5.2",
            "source_kind": "llm_candidate",
            "priority": 6.0,
            "raw_request": b"GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        },
        {
            "node_id": "b_obs_3",
            "parent_node_id": "b_obs_1",
            "mutator_family": "OBS_FOLD_LINE_JOIN",
            "domain": "legacy_headers",
            "rfc_id": "RFC9112-5.2",
            "source_kind": "llm_candidate",
            "priority": 5.0,
            "raw_request": b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nA: " + oversized_a + b"\r\nConnection: close\r\n\r\n",
        },
    ]

    # Branch 3: High-yield HTTP framing desync branch (TE_CL_DUAL_HEADER + cascade)
    desync_branch = [
        {
            "node_id": "b_desync_root",
            "parent_node_id": "",
            "mutator_family": "TE_CL_DUAL_HEADER",
            "domain": "http_framing",
            "rfc_id": "RFC9112-6.3",
            "source_kind": "cascade_intent",
            "priority": 12.0,
            "raw_request": (
                b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                + f"Content-Length: {len(smuggle_body)}\r\nContent-Length: {len(smuggle_body)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + smuggle_body
            ),
            "followup_canary": canary_req,
        },
        {
            "node_id": "b_desync_child_1",
            "parent_node_id": "b_desync_root",
            "mutator_family": "MULTIPART_BYTERANGES_SHARED_PARSER",
            "domain": "http_framing",
            "rfc_id": "RFC9112-6.3",
            "source_kind": "cascade_intent",
            "priority": 18.0,
            "raw_request": (
                b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"Content-Type: multipart/byteranges; boundary=B\r\n"
                + f"Content-Length: {len(smuggle_body)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + smuggle_body
            ),
            "followup_canary": canary_req,
        },
        {
            "node_id": "b_desync_child_2",
            "parent_node_id": "b_desync_child_1",
            "mutator_family": "SHARED_PARSER_REVERSAL",
            "domain": "http_framing",
            "rfc_id": "RFC9112-6.3",
            "source_kind": "dual_graph_multihop",
            "priority": 20.0,
            "raw_request": b"GET /inline_headers HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        },
    ]

    # Branch 4: High-yield shared-parser / leak / auth-boundary branch
    parser_branch = [
        {
            "node_id": "b_parser_root",
            "parent_node_id": "",
            "mutator_family": "SHARED_PARSER_REVERSAL",
            "domain": "http_framing",
            "rfc_id": "RFC9110-7",
            "source_kind": "dual_graph_multihop",
            "priority": 11.0,
            "raw_request": b"GET /leak HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        },
        {
            "node_id": "b_parser_child_1",
            "parent_node_id": "b_parser_root",
            "mutator_family": "SHARED_PARSER_REVERSAL",
            "domain": "http_framing",
            "rfc_id": "RFC9110-7",
            "source_kind": "dual_graph_multihop",
            "priority": 16.0,
            "raw_request": b"GET /double_html HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        },
        {
            "node_id": "b_parser_child_2",
            "parent_node_id": "b_parser_child_1",
            "mutator_family": "AUTH_BOUNDARY_BYPASS",
            "domain": "auth_boundary",
            "rfc_id": "RFC9110-11",
            "source_kind": "dual_graph_multihop",
            "priority": 22.0,
            "raw_request": (
                b"GET /internal/service HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"Authorization: Bearer rfchunt-lab-token\r\nConnection: close\r\n\r\n"
            ),
        },
        {
            "node_id": "b_parser_child_3",
            "parent_node_id": "b_parser_root",
            "mutator_family": "TE_CL_DUAL_HEADER",
            "domain": "http_framing",
            "rfc_id": "RFC9110-7",
            "source_kind": "llm_candidate",
            "priority": 10.0,
            "raw_request": (
                b"POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"Content-Length: 34\r\nConnection: close\r\n\r\n"
                b'{"msg":"RFCHUNT_CANARY_PROBE_lab"}'
            ),
        },
    ]

    # Add seed-specific extra noise leaves so each topology seed has slight realistic variation
    extra_noise: List[Dict[str, Any]] = []
    for k in range(2):
        if rng.random() < 0.7:
            extra_noise.append({
                "node_id": f"b_extra_noise_{topology_seed}_{k}",
                "parent_node_id": "b_noise_tab_root" if k == 0 else "b_obs_root",
                "mutator_family": "HEADER_TAB_SPACING" if k == 0 else "OBS_FOLD_LINE_JOIN",
                "domain": "static_noise" if k == 0 else "legacy_headers",
                "rfc_id": "RFC9112-5.1",
                "source_kind": "abnf_seed",
                "priority": 7.5,
                "raw_request": b"GET /internal/service HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            })

    return noise_branch_1 + noise_branch_2 + extra_noise + desync_branch + parser_branch


def _record_live_tree_from_testlab(
    server: Any,
    host: str,
    port: int,
    tree_id: str,
    topology_seed: int,
) -> Tuple[DiscoveryTree, Dict[str, Dict[str, Any]]]:
    """
    Executes the full candidate topology once against live loopback `TestLabServer`
    to construct a genuine observed `DiscoveryTree` (zero fabricated outcomes).
    """
    spec_list = _build_live_testlab_probe_spec(topology_seed)
    spec_map = {item["node_id"]: item for item in spec_list}
    _reset_testlab_state(server)

    nodes: Dict[str, ReplayNode] = {}
    for item in spec_list:
        res = _execute_live_probe_on_testlab(
            host,
            port,
            item["raw_request"],
            followup_canary=item.get("followup_canary"),
        )
        _reset_testlab_state(server)
        nodes[item["node_id"]] = ReplayNode(
            node_id=item["node_id"],
            parent_node_id=item["parent_node_id"],
            node_type="INTENT",
            source_agent="live_testlab_prober",
            domain=item["domain"],
            rfc_id=item["rfc_id"],
            mutator_family=item["mutator_family"],
            priority=float(item["priority"]),
            step_cost=1,
            token_cost=0,
            is_anomaly=res["is_anomaly"],
            is_confirmed_vuln=res["is_confirmed_vuln"],
            is_attack_chain=res["is_attack_chain"],
            is_noise_discard=res["is_noise_discard"],
            poe_level=res["poe_level"],
            source_kind=item["source_kind"],
            status="DONE",
            content=res["category"],
            metadata={"live_response_len": res["response_len"]},
        )

    tree = DiscoveryTree(
        tree_id=tree_id,
        task_id=tree_id,
        stack_profile="testlab",
        nodes=nodes,
        source=BACKEND_LIVE_TESTLAB,
    ).finalize_topology()
    return (tree, spec_map)


def _execute_live_policy_episode(
    server: Any,
    host: str,
    port: int,
    template_tree: DiscoveryTree,
    spec_map: Dict[str, Dict[str, Any]],
    policy: Optional[DreamPolicy],
    *,
    budget_steps: int,
    seed: int,
    mode: str,
    policy_name: str,
) -> ReplayOutcome:
    """
    Runs a live policy traversal against loopback `TestLabServer`, sending real
    TCP HTTP/1.1 bytes for every selected probe node rather than reading cached labels.
    """
    _reset_testlab_state(server)
    rng = random.Random(int(seed))
    budget = max(1, int(budget_steps))
    max_depth = max(1, template_tree.max_depth)
    branch_keys = ReplayTreePool._compute_branch_keys(template_tree)

    mode_norm = str(mode or "policy").strip().lower()
    if mode_norm in ("disabled", "random"):
        branch_width = 10**6
        parallel_group_size = 1
        early_stop_patience = 10**6
    elif mode_norm == "heuristic":
        branch_width = 4
        parallel_group_size = 4
        early_stop_patience = 5
    else:
        branch_width = max(1, int(getattr(policy, "branch_width", 3) or 3))
        parallel_group_size = max(1, int(getattr(policy, "parallel_group_size", 4) or 4))
        early_stop_patience = max(1, int(getattr(policy, "early_stop_patience", 4) or 4))

    frontier: List[str] = list(template_tree.root_ids)
    in_frontier = set(frontier)
    visited = set()
    visited_order: List[str] = []

    branch_dead_streak: Dict[str, int] = {}
    branch_noise_count: Dict[str, int] = {}
    pruned_branches = set()

    ucb_pulls: Dict[str, int] = {}
    ucb_rewards: Dict[str, float] = {}
    ucb_total_pulls = 0

    steps_taken = 0
    vulns_found = 0
    chains_found = 0
    anomalies_found = 0
    noise_discards = 0
    early_stopped_branches = 0

    def _score(nid: str) -> float:
        nd = template_tree.nodes[nid]
        bkey = branch_keys.get(nid, nid)
        if mode_norm == "heuristic":
            arm = nd.mutator_family or "GENERIC_PROBE"
            pulls = ucb_pulls.get(arm, 0)
            if pulls == 0:
                ucb = 2.0
            else:
                ucb = (ucb_rewards.get(arm, 0.0) / float(pulls)) + 1.414 * math.sqrt(
                    math.log(max(2, ucb_total_pulls + 1)) / float(pulls)
                )
            return ucb + math.tanh(float(nd.priority) / 25.0) * 1.5 + rng.uniform(0.0, 0.02)
        assert policy is not None
        return (
            policy.score_intent_priority(
                base_priority=nd.priority,
                source_kind=nd.source_kind,
                domain=nd.domain,
                mutator_family=nd.mutator_family,
                depth=nd.depth,
                max_depth=max_depth,
                has_active_hint=False,
                branch_noise_count=branch_noise_count.get(bkey, 0),
            )
            + rng.gauss(0.0, 0.03)
        )

    while frontier and steps_taken < budget:
        remaining = budget - steps_taken
        batch_limit = min(parallel_group_size, remaining, len(frontier))
        if mode_norm == "disabled":
            batch_ids = [frontier.pop(0)]
            in_frontier.discard(batch_ids[0])
        elif mode_norm == "random":
            idx = rng.randrange(len(frontier))
            nid = frontier.pop(idx)
            in_frontier.discard(nid)
            batch_ids = [nid]
        else:
            scored = [(_score(nid), idx, nid) for idx, nid in enumerate(frontier)]
            scored.sort(key=lambda item: (item[0], -item[1]), reverse=True)
            batch_ids = [nid for _, _, nid in scored[:batch_limit]]
            bset = set(batch_ids)
            frontier = [nid for nid in frontier if nid not in bset]
            for nid in batch_ids:
                in_frontier.discard(nid)

        new_children: List[str] = []
        for nid in batch_ids:
            if nid in visited or steps_taken >= budget:
                continue
            nd = template_tree.nodes[nid]
            spec = spec_map[nid]
            # Execute REAL TCP socket probe against loopback TestLabServer
            live_res = _execute_live_probe_on_testlab(
                host,
                port,
                spec["raw_request"],
                followup_canary=spec.get("followup_canary"),
            )
            _reset_testlab_state(server)

            visited.add(nid)
            visited_order.append(nid)
            steps_taken += 1

            bkey = branch_keys.get(nid, nid)
            positive_signal = False
            step_sig = 0.0

            if live_res["is_confirmed_vuln"]:
                vulns_found += 1
                positive_signal = True
                step_sig += 3.0
            elif live_res["is_anomaly"]:
                anomalies_found += 1
                positive_signal = True
                step_sig += 1.0

            if live_res["is_attack_chain"]:
                chains_found += 1
                positive_signal = True
                step_sig += 1.5

            if live_res["is_noise_discard"] and not live_res["is_confirmed_vuln"]:
                noise_discards += 1
                branch_noise_count[bkey] = branch_noise_count.get(bkey, 0) + 1
                step_sig -= 1.5

            if mode_norm == "heuristic":
                arm = nd.mutator_family or "GENERIC_PROBE"
                ucb_pulls[arm] = ucb_pulls.get(arm, 0) + 1
                ucb_rewards[arm] = ucb_rewards.get(arm, 0.0) + step_sig
                ucb_total_pulls += 1

            if positive_signal:
                branch_dead_streak[bkey] = 0
            else:
                streak = branch_dead_streak.get(bkey, 0) + 1
                branch_dead_streak[bkey] = streak
                if (
                    mode_norm not in ("disabled", "random")
                    and streak >= early_stop_patience
                    and bkey not in pruned_branches
                ):
                    pruned_branches.add(bkey)
                    early_stopped_branches += 1
                    kept: List[str] = []
                    for fnid in frontier:
                        if branch_keys.get(fnid) == bkey:
                            in_frontier.discard(fnid)
                        else:
                            kept.append(fnid)
                    frontier = kept

            if bkey not in pruned_branches and nd.children:
                cands = [cid for cid in nd.children if cid not in visited and cid not in in_frontier]
                if cands:
                    if mode_norm in ("disabled", "random"):
                        chosen = cands
                    else:
                        sc = [(_score(cid), idx, cid) for idx, cid in enumerate(cands)]
                        sc.sort(key=lambda item: (item[0], -item[1]), reverse=True)
                        chosen = [cid for _, _, cid in sc[:branch_width]]
                    new_children.extend(chosen)

        for cid in new_children:
            if cid not in visited and cid not in in_frontier and branch_keys.get(cid, cid) not in pruned_branches:
                frontier.append(cid)
                in_frontier.add(cid)

    reward = compute_replay_reward(
        vulns=vulns_found,
        chains=chains_found,
        anomalies=anomalies_found,
        noise_discards=noise_discards,
        steps_taken=steps_taken,
    )
    return ReplayOutcome(
        tree_id=template_tree.tree_id,
        policy_name=policy_name,
        seed=int(seed),
        budget_steps=budget,
        steps_taken=steps_taken,
        vulns_found=vulns_found,
        chains_found=chains_found,
        anomalies_found=anomalies_found,
        noise_discards=noise_discards,
        early_stopped_branches=early_stopped_branches,
        total_token_cost=0,
        reward=reward,
        vuln_discovery_rate=vulns_found / float(budget),
        vuln_hit_rate=vulns_found / float(max(1, steps_taken)),
        noise_rate=noise_discards / float(max(1, steps_taken)),
        visited_node_ids=visited_order,
        simulator_backend=BACKEND_LIVE_TESTLAB,
    )


def run_live_lab_benchmark(
    *,
    num_seeds: int = 10,
    budget_steps: int = 7,
    base_seed: int = 42,
    generations: int = 5,
    population_size: int = 12,
    host: str = "127.0.0.1",
    port: int = 0,
    learned_policy: Optional[DreamPolicy] = None,
) -> BenchmarkReport:
    """
    Runs the standardized 5-policy empirical RL benchmark LIVE against an ephemeral
    local loopback `TestLabServer` on `127.0.0.1` (zero external network traffic!).

    Phase 1: Records genuine live TCP discovery trees into a `ReplayTreePool`.
    Phase 2: Evolves `DreamRSI_Learned` offline over the recorded training trees.
    Phase 3: Evaluates all 5 policies LIVE over real TCP sockets across matched seeds
             and identical candidate topologies, stamping `simulator_backend='local_testlab_live'`.
    """
    t0 = time.perf_counter()
    safe_host = _assert_loopback_host(host)
    n_seeds = max(2, int(num_seeds))
    budget = max(2, min(int(budget_steps), 14))
    matched_seeds = [int(base_seed) + i for i in range(n_seeds)]

    from test_lab_server import TestLabServer

    server = TestLabServer(host=safe_host, port=int(port))
    with contextlib.redirect_stdout(io.StringIO()):
        server.start()
    try:
        live_port = int(server.port)

        # Phase 1: Record genuine training discovery trees from live TestLabServer
        train_pool = ReplayTreePool()
        for t_idx in range(4):
            tr_tree, _ = _record_live_tree_from_testlab(
                server, safe_host, live_port, f"live_train_{t_idx}", base_seed + 100 + t_idx
            )
            train_pool.add_tree(tr_tree)

        world_model = ProtocolWorldModel(target_host=safe_host, target_port=live_port)
        world_model.server_signature = "testlab"
        world_model.replay_pool = train_pool
        optimizer = DreamRSIOptimizer(world_model)

        all_train_trees = train_pool.list_trees()
        frozen_baseline = optimizer.create_frozen_baseline_policy(
            trees=all_train_trees,
            stack_profile="testlab",
            simulator_backend=BACKEND_LIVE_TESTLAB,
        )

        # Phase 2: Train DreamRSI_Learned strictly on recorded training trees
        if learned_policy is not None:
            evolved = copy.deepcopy(learned_policy)
            evolved.simulator_backend = BACKEND_LIVE_TESTLAB
        else:
            evolved = optimizer.evolve_meta_policy_from_replay(
                train_pool,
                generations=generations,
                population_size=population_size,
                budget_steps=budget,
                seed=base_seed,
                stack_profile="testlab",
            )
            evolved.simulator_backend = BACKEND_LIVE_TESTLAB

        # Phase 3: Evaluate all 5 policies LIVE on matched episode seeds & identical topologies
        eval_templates: List[Tuple[DiscoveryTree, Dict[str, Dict[str, Any]]]] = []
        for ep_seed in matched_seeds:
            spec_list = _build_live_testlab_probe_spec(ep_seed)
            spec_map = {item["node_id"]: item for item in spec_list}
            nodes = {
                item["node_id"]: ReplayNode(
                    node_id=item["node_id"],
                    parent_node_id=item["parent_node_id"],
                    node_type="INTENT",
                    source_agent="live_testlab_prober",
                    domain=item["domain"],
                    rfc_id=item["rfc_id"],
                    mutator_family=item["mutator_family"],
                    priority=float(item["priority"]),
                    step_cost=1,
                    source_kind=item["source_kind"],
                )
                for item in spec_list
            }
            tmpl = DiscoveryTree(
                tree_id=f"live_eval_{ep_seed}",
                task_id=f"live_eval_{ep_seed}",
                stack_profile="testlab",
                nodes=nodes,
                source=BACKEND_LIVE_TESTLAB,
            ).finalize_topology()
            eval_templates.append((tmpl, spec_map))

        policy_specs: List[Tuple[str, str, Optional[DreamPolicy]]] = [
            ("Disabled", "disabled", None),
            ("Random", "random", None),
            ("Heuristic", "heuristic", None),
            ("NoLearning", "nolearning", frozen_baseline),
            ("DreamRSI_Learned", "policy", evolved),
        ]

        policy_metrics: Dict[str, PolicyBenchmarkMetrics] = {}
        for pname, mode, pol in policy_specs:
            per_seed: List[List[ReplayOutcome]] = []
            for ep_seed, (tmpl, spec_map) in zip(matched_seeds, eval_templates):
                out = _execute_live_policy_episode(
                    server,
                    safe_host,
                    live_port,
                    tmpl,
                    spec_map,
                    pol,
                    budget_steps=budget,
                    seed=ep_seed,
                    mode=mode,
                    policy_name=pname,
                )
                per_seed.append([out])
            policy_metrics[pname] = _aggregate_policy_metrics(pname, per_seed)

        paired = _build_paired_comparisons(policy_metrics)
        elapsed = time.perf_counter() - t0
        return BenchmarkReport(
            simulator_backend=BACKEND_LIVE_TESTLAB,
            matched_seeds=matched_seeds,
            budget_steps=budget,
            train_tree_count=len(all_train_trees),
            val_tree_count=len(eval_templates),
            stack_profile="testlab",
            policies=policy_metrics,
            paired_comparisons=paired,
            learned_policy=evolved.to_dict(),
            duration_seconds=elapsed,
            notes=[
                f"Executed live TCP HTTP/1.1 probes against loopback TestLabServer on {safe_host}:{live_port} (zero external traffic)."
            ],
        )
    finally:
        with contextlib.redirect_stdout(io.StringIO()):
            server.stop()


# ---------------------------------------------------------------------------
# 3. Unified CLI Entry Point (for rfc_hunt_swarm.py & python -m)
# ---------------------------------------------------------------------------

def run_dream_benchmark_cli(
    *,
    db_path: str = "terminator.db",
    live_lab: bool = False,
    num_seeds: int = 10,
    budget_steps: int = 40,
    base_seed: int = 42,
    generations: int = 5,
    population_size: int = 12,
    stack_profile: Optional[str] = None,
    strict_offline: bool = False,
    save_policy_path: Optional[str] = None,
) -> BenchmarkReport:
    """
    Top-level entry point wired by `rfc_hunt_swarm.py --mode dream --dream-benchmark`.
    Uses offline `"recorded_blackboard_replay"` when recorded trees exist in `db_path`,
    or live loopback `"local_testlab_live"` when `live_lab=True` (or when `db_path` has
    no recorded trees and `strict_offline=False`).
    """
    if live_lab:
        live_budget = min(int(budget_steps), 7) if int(budget_steps) >= 14 else int(budget_steps)
        report = run_live_lab_benchmark(
            num_seeds=num_seeds,
            budget_steps=live_budget,
            base_seed=base_seed,
            generations=generations,
            population_size=population_size,
        )
    else:
        pool = ReplayTreePool()
        pool.ingest_from_db(db_path)
        if len(pool) >= 1:
            report = run_replay_benchmark(
                pool,
                num_seeds=num_seeds,
                budget_steps=budget_steps,
                base_seed=base_seed,
                generations=generations,
                population_size=population_size,
                stack_profile=stack_profile,
            )
        elif strict_offline:
            raise ValueError(
                f"No recorded blackboard_nodes discovery trees found in {db_path!r} and strict_offline=True."
            )
        else:
            live_budget = min(int(budget_steps), 7) if int(budget_steps) >= 14 else int(budget_steps)
            report = run_live_lab_benchmark(
                num_seeds=num_seeds,
                budget_steps=live_budget,
                base_seed=base_seed,
                generations=generations,
                population_size=population_size,
            )
            report.notes.append(
                f"No recorded blackboard_nodes found in {db_path}; benchmarked live against loopback TestLabServer."
            )

    if save_policy_path:
        store = DreamPolicyStore(storage_path=save_policy_path)
        store.save_policy(DreamPolicy.from_dict(report.learned_policy))

    return report


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Dream-RSI Standardized 4-Baseline Empirical RL Benchmark"
    )
    parser.add_argument("--db", default="terminator.db", help="SQLite DB path with recorded blackboard_nodes")
    parser.add_argument("--seeds", type=int, default=10, help="Number of matched episode seeds (default: 10)")
    parser.add_argument("--budget", type=int, default=40, help="Step budget per episode (default: 40)")
    parser.add_argument("--base-seed", type=int, default=42, help="Starting random seed (default: 42)")
    parser.add_argument("--generations", type=int, default=5, help="CEM optimization generations (default: 5)")
    parser.add_argument("--population", type=int, default=12, help="CEM population size (default: 12)")
    parser.add_argument("--stack-profile", default=None, help="Optional target stack profile filter")
    parser.add_argument(
        "--live-lab",
        action="store_true",
        default=False,
        help="Run live loopback benchmark against local 127.0.0.1 TestLabServer (zero external traffic)",
    )
    parser.add_argument(
        "--strict-offline",
        action="store_true",
        default=False,
        help="Fail instead of using loopback TestLabServer if DB has zero recorded trees",
    )
    parser.add_argument("--save-policy", default=None, help="Optional DreamPolicyStore JSON path to save learned policy")
    parser.add_argument("--json", action="store_true", default=False, help="Emit machine-readable JSON report")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)
    report = run_dream_benchmark_cli(
        db_path=args.db,
        live_lab=bool(args.live_lab),
        num_seeds=int(args.seeds),
        budget_steps=int(args.budget),
        base_seed=int(args.base_seed),
        generations=int(args.generations),
        population_size=int(args.population),
        stack_profile=args.stack_profile,
        strict_offline=bool(args.strict_offline),
        save_policy_path=args.save_policy,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.format_markdown_table())
    return 0


if __name__ == "__main__":
    sys.exit(main())
