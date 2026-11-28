"""
ModelFusion Consensus & Arbitration Engine:
Faithfully ported from ModelFusion's Rust CLI architecture (d:\\harfile\\ModelFusion\\crates\\cli\\src\\fusion_arbiter.rs).
Implements multi-model ensemble rollouts, specialist role delegation, and DeepSeek-R1 / GLM arbitration:

Specialists:
1. Protocol Specialist: Abliterated Google Gemma (`hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M` / `gemma2`)
2. Exploit Boundary Specialist: Foundation-Sec (`huihui_ai/foundation-sec-abliterated:8b` / `fenkohq/foundation-sec-8b:latest`)
3. Deep Reasoning Arbiter: Abliterated GLM / DeepSeek-R1 (`huihui_ai/glm-4.7-flash-abliterated:latest` / `huihui_ai/deepseek-r1-abliterated:8b` / `glm4:9b`)
"""

import ast
import json
import logging
import math
import os
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import httpx

from database import Database
from engine.paid_model_provider import (
    PaidModelClient,
    PaidModelConfig,
    is_explicit_ollama_spec,
    is_loopback_url,
    is_ollama_model_tag,
    load_paid_model_config,
    strip_ollama_prefix,
)
from ollama_manager import (
    HEALTH_PROBE_MAX_TIMEOUT_SEC,
    OllamaLifecycleManager,
    compute_ollama_concurrency_limits,
    get_free_memory_gb,
    get_free_vram_mb,
    is_embedding_model,
    size_qwen_for_free_memory,
)

logger = logging.getLogger("terminator.fusion")


class CandidateProposal:
    def __init__(
        self,
        candidate_id: str,
        model: str,
        specialist_type: str,
        rationale: str,
        raw_request: str,
        is_clean: bool = False,
    ):
        self.candidate_id = candidate_id
        self.model = model
        self.specialist_type = specialist_type
        self.rationale = rationale
        self.raw_request = raw_request
        self.is_clean = is_clean

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.candidate_id,
            "model": self.model,
            "specialist": self.specialist_type,
            "rationale": self.rationale,
            "raw_request": self.raw_request,
            "is_clean": self.is_clean,
        }


class FusionArbitrationResult:
    def __init__(
        self,
        consensus_type: str,
        fused_probes: List[Dict[str, Any]],
        reasoning: str,
        participating_models: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.consensus_type = consensus_type
        self.fused_probes = fused_probes
        self.reasoning = reasoning
        self.participating_models = participating_models
        self.metadata: Dict[str, Any] = dict(metadata or {})

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "consensus_type": self.consensus_type,
            "fused_probes": self.fused_probes,
            "reasoning": self.reasoning,
            "participating_models": self.participating_models,
        }
        if self.metadata:
            out["metadata"] = dict(self.metadata)
        return out


def _repair_json_string(raw: str) -> str:
    """
    Deterministically repairs common malformed LLM JSON output:
    - Normalizes smart/curly quotes.
    - Escapes literal CR/LF/TAB characters inside double-quoted JSON string literals.
    - Strips trailing commas immediately preceding `}` or `]` outside strings.
    """
    if not raw:
        return ""
    s = (
        raw.replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2018", "'")
        .replace("\u2019", "'")
    )
    out: List[str] = []
    in_str = False
    escaped = False
    for ch in s:
        if in_str:
            if escaped:
                out.append(ch)
                escaped = False
            elif ch == "\\":
                out.append(ch)
                escaped = True
            elif ch == '"':
                out.append(ch)
                in_str = False
            elif ch == "\r":
                out.append("\\r")
            elif ch == "\n":
                out.append("\\n")
            elif ch == "\t":
                out.append("\\t")
            else:
                out.append(ch)
        else:
            if ch == '"':
                in_str = True
            out.append(ch)
    repaired = "".join(out)
    # Remove trailing commas before closing object/array braces outside strings
    final_chars: List[str] = []
    in_str = False
    escaped = False
    n = len(repaired)
    i = 0
    while i < n:
        ch = repaired[i]
        if in_str:
            final_chars.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            final_chars.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and repaired[j] in " \t\r\n":
                j += 1
            if j < n and repaired[j] in "}]":
                i += 1
                continue
        final_chars.append(ch)
        i += 1
    return "".join(final_chars)


class FusionArbiter:
    """
    Orchestrates arbitrary N-model ensemble generation, single-model low-RAM collapse,
    hybrid local+cloud routing, model-grouped batching, and consensus arbitration.
    """

    DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434"

    def __init__(
        self,
        endpoint: Optional[str] = None,
        db: Optional[Database] = None,
        sec_model: Optional[str] = None,
        preferred_model: Optional[str] = None,
        arbiter_model: Optional[str] = None,
        quiet: bool = False,
        env_local_path: Optional[str] = None,
        force_ollama: bool = False,
        panel_models: Optional[Sequence[str]] = None,
        voting_quorum: float = 0.5,
        fallback_timeout: Optional[float] = None,
        hybrid_mode: Optional[bool] = None,
    ):
        self.endpoint = endpoint or os.environ.get("OLLAMA_ENDPOINT", self.DEFAULT_OLLAMA_ENDPOINT)
        self.db = db
        timeout_env = os.environ.get("OLLAMA_TIMEOUT", "120.0")
        self.timeout = float(timeout_env) if float(timeout_env) > 0 else None
        if fallback_timeout is not None and float(fallback_timeout) > 0:
            self.fallback_timeout: float = float(fallback_timeout)
        else:
            fb_env = os.environ.get("OLLAMA_FALLBACK_TIMEOUT", "").strip()
            if fb_env:
                try:
                    self.fallback_timeout = max(10.0, float(fb_env))
                except ValueError:
                    self.fallback_timeout = max(60.0, min(self.timeout or 120.0, 180.0))
            else:
                self.fallback_timeout = max(60.0, min(self.timeout or 120.0, 180.0))

        self.free_ram_gb = self._get_free_memory_gb()
        self.free_vram_mb = self._get_free_vram_mb()
        self.voting_quorum: float = min(1.0, max(0.34, float(voting_quorum or 0.5)))
        _, ollama_num_parallel = compute_ollama_concurrency_limits(self.free_ram_gb, self.free_vram_mb)
        self.max_concurrent_queries: int = max(1, int(ollama_num_parallel))

        raw_panel: List[str] = []
        if panel_models:
            raw_panel = [str(m).strip() for m in panel_models if str(m).strip()]
        else:
            env_panel = os.environ.get("RFCHUNT_PANEL_MODELS", "").strip()
            if env_panel:
                raw_panel = [m.strip() for m in env_panel.split(",") if m.strip()]

        self.paid_config: PaidModelConfig = load_paid_model_config(
            env_local_path=env_local_path,
            force_ollama=force_ollama,
        )
        self.paid_client: Optional[PaidModelClient] = None
        self.ollama_client: Optional[httpx.Client] = None

        explicit_hybrid = bool(hybrid_mode) or any(is_explicit_ollama_spec(m) for m in raw_panel)
        is_hybrid = bool(self.paid_config.enabled and (self.paid_config.hybrid_mode or explicit_hybrid))
        if is_hybrid and not self.paid_config.hybrid_mode:
            self.paid_config = PaidModelConfig(
                enabled=self.paid_config.enabled,
                provider=self.paid_config.provider,
                primary_model=self.paid_config.primary_model,
                sec_model=self.paid_config.sec_model,
                arbiter_model=self.paid_config.arbiter_model,
                panel_models=self.paid_config.panel_models,
                source_file=self.paid_config.source_file,
                timeout_sec=self.paid_config.timeout_sec,
                providers=self.paid_config.providers,
                reason="hybrid_panel_active",
                hybrid_mode=True,
            )

        if self.paid_config.enabled and not is_hybrid:
            self.backend_mode = "paid_api"
            self.using_ollama = False
            self.paid_client = PaidModelClient(self.paid_config, timeout=self.timeout)
            self.client = self.paid_client.client

            exp_pref = (
                preferred_model
                if (preferred_model and not is_ollama_model_tag(preferred_model))
                else None
            )
            exp_sec = (
                sec_model
                if (sec_model and not is_ollama_model_tag(sec_model))
                else None
            )
            exp_arb = (
                arbiter_model
                if (arbiter_model and not is_ollama_model_tag(arbiter_model))
                else None
            )

            if raw_panel:
                self.specialist_models = list(raw_panel) if exp_arb else (
                    list(raw_panel[:-1]) if len(raw_panel) >= 3 else list(raw_panel)
                )
                self.gemma_model = self.specialist_models[0]
                self.sec_model = self.specialist_models[1] if len(self.specialist_models) > 1 else self.specialist_models[0]
                self.arbiter_model = exp_arb or raw_panel[-1]
            else:
                self.gemma_model = exp_pref or self.paid_config.primary_model
                self.sec_model = exp_sec or self.paid_config.sec_model
                self.arbiter_model = exp_arb or self.paid_config.arbiter_model
                self.specialist_models = [self.gemma_model, self.sec_model]

            panel_tags: List[str] = []
            for m in (*self.specialist_models, self.arbiter_model, *self.paid_config.panel_models):
                if m and m not in panel_tags:
                    panel_tags.append(m)
            self.available_tags = panel_tags
            self.panel_models: List[str] = list(dict.fromkeys([*self.specialist_models, self.arbiter_model]))
            self.max_concurrent_queries = max(2, min(8, len(self.specialist_models)))

            if not quiet:
                print(
                    f"[ModelFusion] Paid API Panel Initialized "
                    f"(provider={self.paid_config.provider}, Ollama bypassed, source={self.paid_config.source_file}):"
                )
                print(f"  - Specialists ({len(self.specialist_models)}) : {', '.join(self.specialist_models)}")
                print(f"  - Reasoning Arbiter   : {self.arbiter_model}")
            return

        if is_hybrid:
            self.backend_mode = "hybrid"
            self.using_ollama = True
            self.paid_client = PaidModelClient(self.paid_config, timeout=self.timeout)
            self.ollama_client = httpx.Client(timeout=httpx.Timeout(self.timeout, connect=10.0))
            self.client = self.ollama_client
            local_tags = self._fetch_available_tags()
            hybrid_pool = raw_panel or list(self.paid_config.panel_models)
            if not hybrid_pool:
                default_local = f"ollama/{local_tags[0]}" if local_tags else f"ollama/{size_qwen_for_free_memory(self.free_ram_gb, self.free_vram_mb)}"
                hybrid_pool = [default_local, self.paid_config.primary_model]
            if arbiter_model:
                self.specialist_models = list(hybrid_pool)
                self.arbiter_model = arbiter_model
            elif len(hybrid_pool) >= 3:
                self.specialist_models = list(hybrid_pool[:-1])
                self.arbiter_model = hybrid_pool[-1]
            else:
                self.specialist_models = list(hybrid_pool)
                self.arbiter_model = self.paid_config.arbiter_model or hybrid_pool[-1]

            if preferred_model and is_explicit_ollama_spec(preferred_model):
                self.specialist_models[0] = preferred_model
            elif preferred_model and not is_ollama_model_tag(preferred_model):
                self.specialist_models[0] = preferred_model
            if sec_model and len(self.specialist_models) >= 2:
                self.specialist_models[1] = sec_model

            self.gemma_model = self.specialist_models[0]
            self.sec_model = self.specialist_models[1] if len(self.specialist_models) > 1 else self.specialist_models[0]
            self.available_tags = list(dict.fromkeys([*local_tags, *self.specialist_models, self.arbiter_model, *self.paid_config.panel_models]))
            self.panel_models = list(dict.fromkeys([*self.specialist_models, self.arbiter_model]))
            self.max_concurrent_queries = max(1, min(4, len(self.specialist_models)))
            if not quiet:
                print(f"[ModelFusion] Hybrid Local+Cloud Panel Initialized (source={self.paid_config.source_file}):")
                print(f"  - Specialists ({len(self.specialist_models)}) : {', '.join(self.specialist_models)}")
                print(f"  - Reasoning Arbiter   : {self.arbiter_model}")
            return

        self.backend_mode = "ollama"
        self.using_ollama = True
        self.client = httpx.Client(timeout=httpx.Timeout(self.timeout, connect=10.0))
        self.available_tags = self._fetch_available_tags()

        # Dynamically pull missing preferred models at runtime when online
        # (automatically no-ops under RFCHUNT_OFFLINE=1, CI, or pytest unless explicitly enabled).
        fetch_is_patched = "mock" in type(self._fetch_available_tags).__name__.lower()
        if not fetch_is_patched:
            self.available_tags = OllamaLifecycleManager.ensure_panel_models_installed(
                available_tags=self.available_tags,
                endpoint=self.endpoint,
                free_ram_gb=self.free_ram_gb,
                free_vram_mb=self.free_vram_mb,
                preferred_model=preferred_model,
                sec_model=sec_model,
                arbiter_model=arbiter_model,
            )

        sized_qwen = self._size_qwen_for_free_memory(self.free_ram_gb, self.free_vram_mb)
        generative_tags = [t for t in self.available_tags if not self._is_embedding_model(t)]
        has_24g_mem = self.free_ram_gb >= 24.0 or self.free_vram_mb >= 14336.0
        has_20g_mem = self.free_ram_gb >= 20.0 or self.free_vram_mb >= 12288.0

        # Check for configured abliterated / OBLITERATUS models already installed in Ollama
        abliterated_candidates = [
            t for t in generative_tags
            if ("abliterat" in t.lower() or "obliterat" in t.lower())
            and (has_24g_mem or not any(tag in t.lower() for tag in ("70b", "72b", "755b")))
        ]
        abliterated_gemma = [t for t in abliterated_candidates if "gemma" in t.lower()]
        abliterated_sec = [t for t in abliterated_candidates if any(k in t.lower() for k in ("foundation-sec", "cisco"))]
        abliterated_glm = [t for t in abliterated_candidates if "glm" in t.lower()]
        abliterated_r1 = [t for t in abliterated_candidates if "deepseek-r1" in t.lower()]
        installed_glm = [t for t in generative_tags if "glm" in t.lower()]

        # Default Panel Role 1 (Protocol Specialist)
        if preferred_model and preferred_model.lower() not in ("auto", "gemma2:2b"):
            self.gemma_model = self._resolve_model(
                [strip_ollama_prefix(preferred_model), *abliterated_gemma, "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"],
                fallback=strip_ollama_prefix(preferred_model),
            )
        else:
            self.gemma_model = self._resolve_model(
                [
                    *abliterated_gemma,
                    "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
                    *abliterated_candidates,
                    *(["gemma4:26b"] if has_20g_mem else []),
                    "gemma2:9b",
                    sized_qwen,
                    "gemma2:2b",
                ],
                fallback="hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            )

        # Default Panel Role 2 (Boundary Security Specialist) — prefer a distinct installed tag when available
        distinct_small = [
            t for t in generative_tags
            if t != self.gemma_model
            and (has_24g_mem or not any(h in t.lower() for h in ("26b", "27b", "30b", "32b", "70b", "72b", "strix-deepseek", "glm-4.7-flash")))
        ]
        if sec_model and sec_model.lower() != "fenkohq/foundation-sec-8b:latest":
            self.sec_model = self._resolve_model([strip_ollama_prefix(sec_model)], fallback="fenkohq/foundation-sec-8b:latest")
        elif sec_model:
            self.sec_model = self._resolve_model(
                [*abliterated_sec, strip_ollama_prefix(sec_model)],
                fallback="fenkohq/foundation-sec-8b:latest",
            )
        else:
            other_abliterated = [t for t in abliterated_candidates if t != self.gemma_model]
            self.sec_model = self._resolve_model(
                [
                    *abliterated_sec,
                    "huihui_ai/foundation-sec-abliterated:8b",
                    "fenkohq/foundation-sec-8b:latest",
                    *other_abliterated,
                    *distinct_small,
                    sized_qwen,
                    "qwen2.5:7b",
                    "qwen2.5:3b",
                    "qwen2.5:1.5b",
                    "strix-qwen:latest",
                ],
                fallback="fenkohq/foundation-sec-8b:latest",
            )

        # Default Panel Role 3 (Reasoning Arbiter) — prefer a distinct installed tag when available
        distinct_arb = [t for t in distinct_small if t != self.sec_model]
        if arbiter_model:
            self.arbiter_model = self._resolve_model([strip_ollama_prefix(arbiter_model)], fallback="glm4:9b")
        else:
            self.arbiter_model = self._resolve_model(
                [
                    *abliterated_glm,
                    *abliterated_r1,
                    *(["huihui_ai/glm-4.7-flash-abliterated:latest"] if has_20g_mem else []),
                    "huihui_ai/deepseek-r1-abliterated:8b",
                    "glm4:9b",
                    *(["glm-4.7-flash:latest"] if has_20g_mem else []),
                    *installed_glm,
                    "deepseek-r1:1.5b",
                    *distinct_arb,
                    sized_qwen,
                    "strix-deepseek:latest",
                ],
                fallback="glm4:9b",
            )

        if raw_panel:
            resolved_panel = [
                self._resolve_model([strip_ollama_prefix(m)], fallback=strip_ollama_prefix(m))
                for m in raw_panel
            ]
            if arbiter_model:
                self.specialist_models = list(resolved_panel)
            elif len(resolved_panel) >= 3:
                self.specialist_models = list(resolved_panel[:-1])
                self.arbiter_model = resolved_panel[-1]
            else:
                self.specialist_models = list(resolved_panel)
                self.arbiter_model = resolved_panel[-1]
            self.gemma_model = self.specialist_models[0]
            self.sec_model = self.specialist_models[1] if len(self.specialist_models) > 1 else self.specialist_models[0]
        else:
            self.specialist_models = [self.gemma_model, self.sec_model]

        self.panel_models = list(dict.fromkeys([*self.specialist_models, self.arbiter_model]))

        if not quiet:
            print("[ModelFusion] Panel Initialized:")
            print(f"  - Specialists ({len(self.specialist_models)}) : {', '.join(self.specialist_models)}")
            print(f"  - Reasoning Arbiter   : {self.arbiter_model}")
            print(f"  - Max Concurrency     : {self.max_concurrent_queries} (free_ram={self.free_ram_gb:.1f}GB)")

    def close(self) -> None:
        paid_client = getattr(self, "paid_client", None)
        if paid_client is not None:
            try:
                paid_client.close()
            except Exception:
                pass
        ollama_client = getattr(self, "ollama_client", None)
        if ollama_client is not None:
            try:
                ollama_client.close()
            except Exception:
                pass
        client = getattr(self, "client", None)
        if client is not None and client is not ollama_client and (paid_client is None or client is not getattr(paid_client, "client", None)):
            try:
                client.close()
            except Exception:
                pass

    def __enter__(self) -> "FusionArbiter":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def _is_embedding_model(tag: str) -> bool:
        return is_embedding_model(tag)

    @staticmethod
    def _get_free_memory_gb() -> float:
        """Evaluates runtime free/available RAM in GB (never total physical RAM)."""
        return get_free_memory_gb()

    @staticmethod
    def _get_free_vram_mb() -> float:
        """Evaluates runtime free/available GPU VRAM in MB (never total VRAM)."""
        return get_free_vram_mb()

    @staticmethod
    def _size_qwen_for_free_memory(free_ram_gb: float, free_vram_mb: float = 0.0) -> str:
        """Sizes Qwen model strictly by runtime available memory (never `-coder` suffixes)."""
        return size_qwen_for_free_memory(free_ram_gb, free_vram_mb)

    def _fetch_available_tags(self) -> List[str]:
        """Probes Ollama (<=400ms) and auto-readies the daemon when online (skipped in paid API mode)."""
        if not getattr(self, "using_ollama", True):
            cfg = getattr(self, "paid_config", None)
            return list(cfg.panel_models) if cfg and cfg.enabled else list(getattr(self, "available_tags", []) or [])
        if os.environ.get("RFCHUNT_OFFLINE") == "1":
            return []
        auto_install = os.environ.get("RFCHUNT_AUTO_INSTALL_TOOLS", "1") != "0"
        try:
            return OllamaLifecycleManager.ensure_ollama_ready(
                endpoint=self.endpoint,
                auto_install=auto_install,
            )
        except Exception:
            try:
                resp = httpx.get(
                    f"{self.endpoint}/api/tags",
                    timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [m["name"] for m in data.get("models", []) if "name" in m]
            except Exception:
                pass
        return []

    @staticmethod
    def _is_refusal(text: str) -> bool:
        """Detects whether an LLM completion is an AI safety refusal rather than technical output."""
        if not text:
            return False
        lower = text.lower()
        explicit_refusal_markers = (
            "i cannot fulfill",
            "i cannot assist",
            "i cannot generate",
            "i am unable to generate",
            "i am unable to provide",
            "as an ai",
            "as a language model",
            "as a responsible ai",
            "against safety guidelines",
            "against my safety policies",
            "ethical guidelines",
            "cannot assist with creating exploits",
            "cannot create attacks",
            "cannot provide exploit payloads",
            "cannot create code that exploits",
            "i'm sorry, but i cannot",
            "i am sorry, but i cannot",
            "cannot generate harmful",
            "harmful attacks",
        )
        if any(marker in lower for marker in explicit_refusal_markers):
            return True
        refusal_intent = any(
            verb in lower
            for verb in ("cannot", "can't", "unable to", "i'm sorry", "i am sorry", "i will not", "i won't", "refuse to")
        )
        if refusal_intent and any(
            adj in lower for adj in ("harmful or malicious", "potentially harmful", "malicious payloads")
        ):
            return True
        return False

    def _resolve_model(self, candidates: List[str], fallback: str) -> str:
        raw_tags = getattr(self, "available_tags", None) or []
        generative_tags = [t for t in raw_tags if not self._is_embedding_model(t)]
        if not generative_tags:
            return fallback

        free_ram = float(getattr(self, "free_ram_gb", 16.0))
        free_vram = float(getattr(self, "free_vram_mb", 0.0))
        has_24g_mem = free_ram >= 24.0 or free_vram >= 14336.0

        obliterated_aliases = {
            "hf.co/obliteratus/gemma-4-12b-obliterated:q4_k_m",
            "gemma-4-12b-obliterated:q4_k_m",
            "gemma-4-12b-obliterated",
            "gemma4-12b-obliterated",
            "gemma-4-obliterated",
            "gemma4-obliterated",
            "obliteratus/gemma-4-12b-obliterated",
            "obliteratus",
            "obliterated",
            "abliterated",
            "gemma-obliterated",
            "gemma4:12b-obliterated",
            "gemma-12b-obliterated",
        }
        obliterated_bases = {a.split(":")[0] for a in obliterated_aliases}

        # Pass 1: Case-insensitive exact tag match FIRST (prevents cross-family hijacking)
        for cand in candidates:
            c_low = (cand or "").strip().lower()
            if not c_low:
                continue
            for tag in generative_tags:
                t_low = tag.lower()
                if c_low == t_low or t_low.startswith(c_low + ":") or c_low.startswith(t_low + ":"):
                    return tag

        # Pass 2: Shorthand abliterated alias matches (prefer Gemma family when Gemma alias requested)
        for cand in candidates:
            c_low = (cand or "").strip().lower()
            if c_low in obliterated_aliases or c_low in obliterated_bases:
                gemma_abl = [
                    t for t in generative_tags
                    if ("obliterat" in t.lower() or "abliterat" in t.lower()) and "gemma" in t.lower()
                ]
                if gemma_abl:
                    return gemma_abl[0]
                any_abl = [
                    t for t in generative_tags
                    if "obliterat" in t.lower() or "abliterat" in t.lower()
                ]
                if any_abl:
                    return any_abl[0]

        # Pass 3: Base family match, avoiding oversized models and embedding models
        for cand in candidates:
            cand_base = (cand or "").strip().lower().split(":")[0]
            if not cand_base:
                continue
            for tag in generative_tags:
                t_low = tag.strip().lower()
                tag_base = t_low.split(":")[0]
                if cand_base == tag_base or cand_base in t_low:
                    if not has_24g_mem and any(h in t_low for h in ("26b", "27b", "30b", "32b", "70b", "72b", "strix-deepseek", "glm-4.7-flash")):
                        continue
                    return tag

        # Pass 4: Any installed lightweight generative model
        for tag in generative_tags:
            t_low = tag.lower()
            if not any(h in t_low for h in ("26b", "27b", "30b", "32b", "70b", "72b", "strix-deepseek")):
                return tag
        return generative_tags[0]

    def _is_cloud_slot(self, model: str) -> bool:
        paid_cfg = getattr(self, "paid_config", None)
        paid_client = getattr(self, "paid_client", None)
        if paid_client is None or paid_cfg is None or not paid_cfg.enabled:
            return False
        if getattr(self, "backend_mode", "ollama") == "hybrid" or getattr(paid_cfg, "hybrid_mode", False):
            return not paid_cfg.is_local_ollama_slot(model)
        return not getattr(self, "using_ollama", True)

    def _canonical_slot_key(self, model: str) -> Tuple[str, str]:
        if self._is_cloud_slot(model):
            return ("cloud", (model or "").strip().lower())
        return ("ollama", strip_ollama_prefix(model or "").strip().lower())

    def _query_paid_model(
        self,
        model: str,
        prompt: str,
        system_prompt: str,
        num_predict: int = 160,
    ) -> str:
        paid_client = self.paid_client
        if paid_client is None:
            return ""
        resp_txt = paid_client.generate(
            system_prompt=system_prompt,
            user_prompt=prompt,
            model=model,
            max_tokens=max(int(num_predict), 256),
            temperature=0.3,
            expect_json=True,
        )
        if resp_txt:
            return resp_txt
        for fb_model in getattr(self, "available_tags", []) or []:
            if fb_model and fb_model != model and self._is_cloud_slot(fb_model):
                fb_txt = paid_client.generate(
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                    model=fb_model,
                    max_tokens=max(int(num_predict), 256),
                    temperature=0.3,
                    expect_json=True,
                )
                if fb_txt:
                    return fb_txt
        return ""

    def _query_model(
        self,
        model: str,
        prompt: str,
        system_prompt: str,
        num_predict: int = 160,
    ) -> str:
        if self._is_cloud_slot(model):
            return self._query_paid_model(model, prompt, system_prompt, num_predict=num_predict)

        clean_model = strip_ollama_prefix(model)
        if not self.available_tags:
            self.available_tags = self._fetch_available_tags()

        generative_tags = [
            strip_ollama_prefix(t)
            for t in self.available_tags
            if not self._is_embedding_model(t) and not self._is_cloud_slot(t)
        ]
        target_model = clean_model
        if target_model not in generative_tags:
            try:
                if OllamaLifecycleManager.ensure_model_installed(target_model, endpoint=self.endpoint):
                    self.available_tags = self._fetch_available_tags()
                    generative_tags = [
                        strip_ollama_prefix(t)
                        for t in self.available_tags
                        if not self._is_embedding_model(t) and not self._is_cloud_slot(t)
                    ]
                else:
                    OllamaLifecycleManager.trigger_background_pull(target_model, endpoint=self.endpoint)
            except Exception:
                pass
            if generative_tags and target_model not in generative_tags:
                target_model = self._resolve_model([clean_model], fallback=generative_tags[0])

        is_r1 = "deepseek-r1" in target_model.lower()
        effective_predict = max(int(num_predict), 384) if is_r1 else int(num_predict)
        stop_tokens = ["<|end_of_text|>"]

        payload: Dict[str, Any] = {
            "model": target_model,
            "prompt": f"{system_prompt}\n{prompt}" if "foundation-sec" in target_model.lower() else f"### SYSTEM:\n{system_prompt}\n\n### INSTRUCTION:\n{prompt}",
            "stream": False,
            "keep_alive": "60m",
            "options": {"temperature": 0.7, "num_predict": effective_predict, "stop": stop_tokens},
        }
        if not is_r1:
            payload["format"] = "json"
        http_client = getattr(self, "ollama_client", None) or self.client
        try:
            resp = http_client.post(
                f"{self.endpoint}/api/generate",
                json=payload,
                timeout=httpx.Timeout(self.timeout, connect=10.0),
            )
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
            logger.warning("Ollama returned HTTP %s for %s; trying fallback.", resp.status_code, target_model)
        except Exception as e:
            logger.warning("Ollama query failed for %s: %s", target_model, e)

        # Resilient fallback using configurable CPU-aware fallback_timeout (never hardcoded to 30s)
        fb_timeout = float(getattr(self, "fallback_timeout", max(60.0, min(self.timeout or 120.0, 180.0))))
        if self.timeout is not None:
            fb_timeout = min(fb_timeout, float(self.timeout))
        for fb in ("gemma2:2b", "qwen2.5:1.5b", "qwen2.5:3b", "qwen2.5:7b", "deepseek-r1:1.5b", *generative_tags):
            if fb != target_model and not self._is_embedding_model(fb) and (not generative_tags or fb in generative_tags):
                try:
                    fb_payload = dict(payload)
                    fb_payload["model"] = fb
                    if "deepseek-r1" in fb.lower():
                        fb_payload.pop("format", None)
                        fb_payload["options"] = dict(payload["options"], num_predict=max(effective_predict, 384))
                    else:
                        fb_payload["format"] = "json"
                    resp = http_client.post(
                        f"{self.endpoint}/api/generate",
                        json=fb_payload,
                        timeout=httpx.Timeout(fb_timeout, connect=5.0),
                    )
                    if resp.status_code == 200:
                        return resp.json().get("response", "").strip()
                except Exception:
                    continue
        return ""

    @staticmethod
    def _is_valid_http_template(req: str) -> bool:
        s = (req or "").strip()
        if len(s) < 14 or s == "...":
            return False
        u = s.upper()
        return "HTTP/" in u or any(u.startswith(m) for m in ("GET ", "POST ", "HEAD ", "OPTIONS ", "CONNECT ", "PUT ", "DELETE ", "TRACE ", "PRI "))

    def _normalize_probe_signature(self, raw_request: str) -> str:
        norm = self._normalize_crlf(raw_request).strip()
        return re.sub(r"[ \t]+", " ", norm).lower()

    def _specialist_role_prompt(
        self,
        role_idx: int,
        rfc_fragment: str,
        hint_block: str,
        fact_block: str,
    ) -> Tuple[str, str, str]:
        if role_idx == 0:
            role_label = "Protocol Specialist"
            sys_p = (
                "You are a protocol security researcher (James Kettle HTTP Terminator methodology). "
                "Invert RFC response/framing rules into an incoming client HTTP/1.1 request (Shared-Parser Confusion)."
            )
        elif role_idx == 1:
            role_label = "Boundary Specialist"
            sys_p = (
                "You are an HTTP framing boundary specialist (Cisco Foundation-Sec / PortSwigger methodology). "
                "Construct a parser-confusion or framing-discrepancy HTTP/1.1 request from the RFC clue."
            )
        else:
            role_label = f"Ensemble Specialist #{role_idx + 1}"
            sys_p = (
                "You are an independent HTTP/TLS protocol compliance & parser-differential auditor. "
                "Derive an RFC boundary edge-case HTTP/1.1 request exposing front-end/back-end framing disagreement."
            )
        user_p = (
            f"RFC Clue: {rfc_fragment}\n"
            f"{hint_block}{fact_block}"
            "Task: Output a single-line JSON object with keys rationale, raw_request "
            "(starting with POST / HTTP/1.1\\r\\nHost: target.local and ending with \\r\\n\\r\\n$PAYLOAD), and is_clean.\n"
            "JSON: "
        )
        return role_label, sys_p, user_p

    def _extract_proposals_from_output(
        self,
        raw_out: str,
        model_name: str,
        specialist_type: str,
        start_idx: int,
    ) -> Tuple[List[CandidateProposal], bool]:
        if self._is_refusal(raw_out):
            return [], True
        extracted: List[CandidateProposal] = []
        for item in self._parse_json(raw_out):
            norm_req = self._normalize_crlf(item.get("raw_request", ""))
            rat = str(item.get("rationale", "")).strip()
            if self._is_refusal(norm_req) or self._is_refusal(rat) or not self._is_valid_http_template(norm_req):
                continue
            if not rat or rat == "...":
                rat = f"{specialist_type} protocol boundary edge-case"
            extracted.append(
                CandidateProposal(
                    candidate_id=f"cand_{start_idx + len(extracted) + 1}",
                    model=model_name,
                    specialist_type=specialist_type,
                    rationale=rat,
                    raw_request=norm_req,
                    is_clean=bool(item.get("is_clean", False)),
                )
            )
        return extracted, False

    def _arbitrate_proposals(
        self,
        *,
        rfc_fragment: str,
        fragment_id: Optional[int],
        proposals: List[CandidateProposal],
        participating_models: List[str],
        unique_specialists: List[str],
        hint_block: str,
        fact_block: str,
        collapsed_single_model: bool = False,
        redundant_calls_saved: int = 0,
    ) -> FusionArbitrationResult:
        # Gate 0: Single-Model Low-RAM Collapse Fast Path (skip redundant same-model Arbiter)
        if collapsed_single_model and proposals:
            res_probes = [p.to_dict() for p in proposals]
            self._save_probes_to_db(res_probes, fragment_id, "SingleModelCollapsed")
            return FusionArbitrationResult(
                consensus_type="SingleModelCollapsed",
                fused_probes=res_probes,
                reasoning=(
                    f"All panel slots resolved to a single model ({unique_specialists[0]}); "
                    f"executed 1 combined pass and skipped {redundant_calls_saved} redundant same-model calls."
                ),
                participating_models=list(unique_specialists),
                metadata={
                    "unique_models": 1,
                    "redundant_calls_saved": redundant_calls_saved,
                    "backend_mode": getattr(self, "backend_mode", "ollama"),
                },
            )

        # Gate 1: Single Candidate Bypass
        if len(proposals) <= 1:
            res_probes = [p.to_dict() for p in proposals]
            self._save_probes_to_db(res_probes, fragment_id, "SingleBypass")
            return FusionArbitrationResult(
                consensus_type="SingleBypass",
                fused_probes=res_probes,
                reasoning="Single candidate available; bypassed arbitration.",
                participating_models=participating_models,
            )

        # Gate 2: Unanimous Identical Implementations Bypass
        first_sig = self._normalize_probe_signature(proposals[0].raw_request)
        if all(self._normalize_probe_signature(p.raw_request) == first_sig for p in proposals):
            res_probes = [proposals[0].to_dict()]
            self._save_probes_to_db(res_probes, fragment_id, "Unanimous")
            return FusionArbitrationResult(
                consensus_type="Unanimous",
                fused_probes=res_probes,
                reasoning="All specialists produced identical request templates.",
                participating_models=participating_models,
            )

        # Gate 3: Arbitrary N-Model Quorum Majority Consensus (for N >= 3 distinct specialists)
        if len(unique_specialists) >= 3:
            clusters: Dict[str, List[CandidateProposal]] = {}
            for p in proposals:
                sig = self._normalize_probe_signature(p.raw_request)
                clusters.setdefault(sig, []).append(p)
            quorum_needed = max(2, int(math.ceil(len(unique_specialists) * float(getattr(self, "voting_quorum", 0.5)))))
            ranked_clusters = sorted(
                clusters.values(),
                key=lambda grp: len({g.model for g in grp}),
                reverse=True,
            )
            top_group = ranked_clusters[0]
            top_voters = list(dict.fromkeys(g.model for g in top_group))
            if len(top_voters) >= quorum_needed:
                winner = top_group[0].to_dict()
                winner["corroborated_by_models"] = top_voters
                winner["vote_count"] = len(top_voters)
                winner["panel_size"] = len(unique_specialists)
                res_probes = [winner]
                self._save_probes_to_db(res_probes, fragment_id, "QuorumConsensus")
                return FusionArbitrationResult(
                    consensus_type="QuorumConsensus",
                    fused_probes=res_probes,
                    reasoning=(
                        f"N-model quorum reached ({len(top_voters)}/{len(unique_specialists)} distinct models agreed; "
                        f"threshold={quorum_needed})."
                    ),
                    participating_models=participating_models,
                    metadata={
                        "vote_tally": {k[:40]: len({g.model for g in v}) for k, v in clusters.items()},
                        "quorum_needed": quorum_needed,
                        "voters": top_voters,
                    },
                )

        # Gate 4: Synthesis via Reasoning Arbiter (with bounded JSON-repair retry)
        arb_key = self._canonical_slot_key(self.arbiter_model)
        if len(unique_specialists) == 1 and arb_key == self._canonical_slot_key(unique_specialists[0]):
            res_probes = [p.to_dict() for p in proposals]
            self._save_probes_to_db(res_probes, fragment_id, "SingleModelCollapsed")
            return FusionArbitrationResult(
                consensus_type="SingleModelCollapsed",
                fused_probes=res_probes,
                reasoning="Arbiter matched sole specialist model; retained specialist output without redundant reload.",
                participating_models=list(unique_specialists),
                metadata={"unique_models": 1, "redundant_calls_saved": redundant_calls_saved + 1},
            )

        if self.arbiter_model not in participating_models:
            participating_models.append(self.arbiter_model)
        candidates_summary = "\n\n".join([
            f"Candidate [{p.candidate_id}] by {p.model} ({p.specialist_type}):\n"
            f"- Rationale: {p.rationale}\n"
            f"- Raw Request Template:\n{p.raw_request}"
            for p in proposals if p.raw_request
        ])

        arbiter_sys = (
            "You are the Fusion Arbiter for ModelFusion (James Kettle research architect). "
            "You are given competing HTTP probe proposals derived from an RFC clue. "
            "Synthesize 1 unified HTTP/1.1 probe combining protocol nuance and boundary manipulation. "
            "Return strictly valid JSON with keys 'rationale', 'raw_request', and 'is_clean'."
        )
        arbiter_prompt = (
            f"RFC Snippet Under Investigation:\n\"\"\"{rfc_fragment}\"\"\"\n\n"
            f"{hint_block}{fact_block}"
            f"Candidate Proposals Submitted to Fusion Arbiter:\n{candidates_summary}\n\n"
            f"Synthesize the optimal consensus probe as valid JSON."
        )

        t2 = time.time()
        print(f"    -> [ModelFusion Arbiter] Reasoning Arbiter ({self.arbiter_model}) synthesizing...", end=" ", flush=True)
        arbiter_out = self._query_model(self.arbiter_model, arbiter_prompt, arbiter_sys)
        if self._is_refusal(arbiter_out):
            arbiter_out = ""
        synthesized_probes = self._parse_json(arbiter_out)

        # Bounded 1-shot JSON-repair retry if Arbiter returned non-empty malformed text
        json_retry_used = False
        if not synthesized_probes and arbiter_out.strip():
            json_retry_used = True
            repair_prompt = (
                "Reformat the following response into a SINGLE valid JSON object with keys "
                "'rationale', 'raw_request' (escaped \\r\\n), and 'is_clean' (boolean). Output JSON ONLY.\n\n"
                f"Previous output:\n{arbiter_out[:1200]}"
            )
            repaired_raw = self._query_model(self.arbiter_model, repair_prompt, "Output strictly valid JSON only.", num_predict=256)
            if repaired_raw and not self._is_refusal(repaired_raw):
                synthesized_probes = self._parse_json(repaired_raw)
        print(f"done ({time.time() - t2:.1f}s)", flush=True)

        has_24g_mem = float(getattr(self, "free_ram_gb", 0.0)) >= 24.0 or float(getattr(self, "free_vram_mb", 0.0)) >= 14336.0
        abliterated_candidates = [
            t for t in self.available_tags
            if not self._is_embedding_model(t)
            and ("abliterat" in t.lower() or "obliterat" in t.lower())
            and (has_24g_mem or not any(tag in t.lower() for tag in ("70b", "72b", "755b")))
        ]

        final_fused: List[Dict[str, Any]] = []
        if not synthesized_probes and abliterated_candidates:
            abl_arb = abliterated_candidates[0]
            if abl_arb != self.arbiter_model:
                print(f"    -> [ModelFusion Fallback] Synthesizing via {abl_arb}...", end=" ", flush=True)
                abl_arb_out = self._query_model(abl_arb, arbiter_prompt, arbiter_sys)
                if not self._is_refusal(abl_arb_out):
                    synthesized_probes = self._parse_json(abl_arb_out)
                print(f"done ({len(synthesized_probes)} probes)", flush=True)
                if synthesized_probes:
                    for sp in synthesized_probes:
                        if not isinstance(sp, dict):
                            continue
                        raw = self._normalize_crlf(sp.get("raw_request", ""))
                        rat = str(sp.get("rationale", "Synthesized consensus vector"))
                        if not self._is_refusal(raw) and not self._is_refusal(rat) and self._is_valid_http_template(raw):
                            final_fused.append({
                                "id": f"fused_abliterated_{len(final_fused)+1}",
                                "model": f"{abl_arb} [AbliteratedConsensus: {' + '.join(unique_specialists)}]",
                                "specialist": "Abliterated Consensus Synthesis",
                                "rationale": f"[ModelFusion Abliteration] {rat}",
                                "raw_request": raw,
                                "is_clean": bool(sp.get("is_clean", False)),
                            })

        if not final_fused and synthesized_probes:
            for sp in synthesized_probes:
                if not isinstance(sp, dict):
                    continue
                raw = self._normalize_crlf(sp.get("raw_request", ""))
                rat = str(sp.get("rationale", "Synthesized consensus vector"))
                if not self._is_refusal(raw) and not self._is_refusal(rat) and self._is_valid_http_template(raw):
                    final_fused.append({
                        "id": f"fused_arbiter_{len(final_fused)+1}",
                        "model": f"{self.arbiter_model} [Fused: {' + '.join(unique_specialists)}]",
                        "specialist": "Arbiter Consensus Synthesis",
                        "rationale": f"[ModelFusion Consensus] {rat}",
                        "raw_request": raw,
                        "is_clean": bool(sp.get("is_clean", False)),
                    })

        has_abliterated = any(
            "abliterat" in str(p.get("model", "")).lower() or "obliterat" in str(p.get("model", "")).lower()
            for p in (final_fused or [p.to_dict() for p in proposals])
        )

        if final_fused:
            consensus_type = "AbliteratedConsensus" if has_abliterated else "ArbiterSynthesized"
            reasoning = f"Arbiter successfully synthesized {len(final_fused)} unified probes from {len(unique_specialists)} specialists."
        else:
            consensus_type = "AbliteratedConsensus" if has_abliterated else "DominantWinner"
            reasoning = "Arbiter timed out or unparseable; retained individual specialist candidates."
            for p in proposals:
                if p.raw_request:
                    final_fused.append(p.to_dict())

        self._save_probes_to_db(final_fused, fragment_id, consensus_type)

        return FusionArbitrationResult(
            consensus_type=consensus_type,
            fused_probes=final_fused,
            reasoning=reasoning,
            participating_models=participating_models,
            metadata={
                "unique_specialists": len(unique_specialists),
                "json_retry_used": json_retry_used,
                "backend_mode": getattr(self, "backend_mode", "ollama"),
            },
        )

    def run_fusion_pipeline(
        self,
        rfc_fragment: str,
        fragment_id: Optional[int] = None,
        *,
        hints: Optional[List[str]] = None,
        facts: Optional[List[str]] = None,
    ) -> FusionArbitrationResult:
        """
        Executes N-model ModelFusion arbitration with:
        - Single-model low-RAM collapse fast path (avoids 2-3x redundant CPU calls when all slots map to 1 model).
        - Memory-aware concurrency (`max_concurrent_queries=1` on <=8 GB RAM local Ollama to prevent thrashing).
        - Gate 1 (SingleBypass), Gate 2 (Unanimous), Gate 3 (N-Model QuorumConsensus), Gate 4 (Arbiter + JSON retry).
        """
        import concurrent.futures

        raw_specialists = list(getattr(self, "specialist_models", None) or [self.gemma_model, self.sec_model])
        unique_specialists: List[str] = []
        seen_keys: set = set()
        for m in raw_specialists:
            k = self._canonical_slot_key(m)
            if k not in seen_keys:
                seen_keys.add(k)
                unique_specialists.append(m)
        if not unique_specialists:
            unique_specialists = [self.gemma_model]

        participating_models = list(unique_specialists)
        proposals: List[CandidateProposal] = []

        clean_hints = [str(h).strip() for h in (hints or []) if str(h).strip()]
        clean_facts = [str(f).strip() for f in (facts or []) if str(f).strip()]
        hint_block = (
            "Active Steering Hints (highest priority first):\n"
            + "\n".join(f"- {h}" for h in clean_hints)
            + "\n"
            if clean_hints
            else ""
        )
        fact_block = (
            "Observed Blackboard Facts:\n"
            + "\n".join(f"- {f}" for f in clean_facts)
            + "\n"
            if clean_facts
            else ""
        )

        # Single-model low-RAM collapse fast path: 1 combined prompt instead of 2-3 redundant identical-model calls
        arb_same_as_sole = (
            len(unique_specialists) == 1
            and self._canonical_slot_key(self.arbiter_model) == self._canonical_slot_key(unique_specialists[0])
        )
        if len(unique_specialists) == 1 and len(raw_specialists) >= 2:
            sole_model = unique_specialists[0]
            saved_calls = (len(raw_specialists) - 1) + (1 if arb_same_as_sole else 0)
            combined_sys = (
                "You are a combined Protocol & HTTP Framing Boundary Researcher. "
                "Analyze both RFC state-machine inversion and front-end/back-end framing discrepancies in one pass."
            )
            combined_prompt = (
                f"RFC Clue: {rfc_fragment}\n"
                f"{hint_block}{fact_block}"
                "Task: Output a single-line JSON object with keys rationale, raw_request "
                "(starting with POST / HTTP/1.1\\r\\nHost: target.local and ending with \\r\\n\\r\\n$PAYLOAD), and is_clean.\n"
                "JSON: "
            )
            t_start = time.time()
            print(
                f"    -> [ModelFusion FastPath] Single unique model ({sole_model}); "
                f"running 1 combined pass (saving {saved_calls} redundant calls)...",
                end=" ",
                flush=True,
            )
            sole_out = self._query_model(sole_model, combined_prompt, combined_sys)
            extracted, _ = self._extract_proposals_from_output(sole_out, sole_model, "Combined Specialist", 0)
            proposals.extend(extracted)
            print(f"done ({time.time() - t_start:.1f}s | {len(proposals)} proposals)", flush=True)
            return self._arbitrate_proposals(
                rfc_fragment=rfc_fragment,
                fragment_id=fragment_id,
                proposals=proposals,
                participating_models=participating_models,
                unique_specialists=unique_specialists,
                hint_block=hint_block,
                fact_block=fact_block,
                collapsed_single_model=arb_same_as_sole,
                redundant_calls_saved=saved_calls,
            )

        t_start = time.time()
        max_w = max(1, min(len(unique_specialists), int(getattr(self, "max_concurrent_queries", 2))))
        print(
            f"    -> [ModelFusion Specialists] Querying {len(unique_specialists)} models "
            f"(concurrency={max_w}: {' + '.join(unique_specialists)})...",
            end=" ",
            flush=True,
        )
        role_tasks = [
            (idx, mdl, *self._specialist_role_prompt(idx, rfc_fragment, hint_block, fact_block))
            for idx, mdl in enumerate(unique_specialists)
        ]
        raw_outputs: List[Tuple[str, str, str]] = []
        if max_w == 1:
            for _, mdl, role_label, sys_p, user_p in role_tasks:
                raw_outputs.append((mdl, role_label, self._query_model(mdl, user_p, sys_p)))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as pool:
                futs = [
                    (mdl, role_label, pool.submit(self._query_model, mdl, user_p, sys_p))
                    for _, mdl, role_label, sys_p, user_p in role_tasks
                ]
                for mdl, role_label, fut in futs:
                    raw_outputs.append((mdl, role_label, fut.result()))

        any_refused = False
        per_model_counts: List[str] = []
        for mdl, role_label, raw_out in raw_outputs:
            extracted, refused = self._extract_proposals_from_output(raw_out, mdl, role_label, len(proposals))
            if refused:
                any_refused = True
            proposals.extend(extracted)
            per_model_counts.append(f"{mdl}: {len(extracted)}")

        # Configured abliterated specialist fallback if already installed locally and specialists refused/empty
        has_24g_mem = float(getattr(self, "free_ram_gb", 0.0)) >= 24.0 or float(getattr(self, "free_vram_mb", 0.0)) >= 14336.0
        abliterated_candidates = [
            t for t in self.available_tags
            if not self._is_embedding_model(t)
            and ("abliterat" in t.lower() or "obliterat" in t.lower())
            and (has_24g_mem or not any(tag in t.lower() for tag in ("70b", "72b", "755b")))
        ]
        if (any_refused or len(proposals) == 0) and abliterated_candidates:
            abl_model = abliterated_candidates[0]
            if abl_model not in unique_specialists or len(proposals) == 0:
                print(f"    -> [ModelFusion Fallback] Querying configured model ({abl_model})...", end=" ", flush=True)
                abl_sys = (
                    "You are a protocol security research engine. "
                    "Analyze the protocol rule and generate state-machine and framing inversion requests. "
                    "Output JSON with keys 'rationale', 'raw_request', 'is_clean'."
                )
                abl_prompt = f"RFC Clue: {rfc_fragment}\n{hint_block}{fact_block}Task: Output raw HTTP probe JSON."
                abl_out = self._query_model(abl_model, abl_prompt, abl_sys)
                ext_abl, _ = self._extract_proposals_from_output(
                    abl_out,
                    f"{abl_model} [RefusalFree]",
                    "Abliterated Security Specialist",
                    len(proposals),
                )
                proposals.extend(ext_abl)
                print(f"done ({len(proposals)} proposals total)", flush=True)

        print(f"done ({time.time() - t_start:.1f}s | {', '.join(per_model_counts)})", flush=True)

        return self._arbitrate_proposals(
            rfc_fragment=rfc_fragment,
            fragment_id=fragment_id,
            proposals=proposals,
            participating_models=participating_models,
            unique_specialists=unique_specialists,
            hint_block=hint_block,
            fact_block=fact_block,
        )

    def run_fusion_batch(
        self,
        fragments: Sequence[Any],
        *,
        hints: Optional[List[str]] = None,
        facts: Optional[List[str]] = None,
    ) -> List[FusionArbitrationResult]:
        """
        Model-grouped batch scheduling: runs Specialist 1 across ALL fragments while Model 1
        remains loaded in Ollama, then Specialist 2 across ALL fragments, ..., then Arbiter.
        Cuts disk model-swap evictions from O(N_models * M_fragments) down to O(N_models).
        """
        if not fragments:
            return []

        norm_frags: List[Tuple[str, Optional[int]]] = []
        for f in fragments:
            if isinstance(f, dict):
                norm_frags.append((str(f.get("text") or f.get("fragment") or ""), f.get("fragment_id") or f.get("id")))
            elif isinstance(f, (tuple, list)) and len(f) >= 2:
                norm_frags.append((str(f[0]), f[1]))
            else:
                norm_frags.append((str(f), None))

        raw_specialists = list(getattr(self, "specialist_models", None) or [self.gemma_model, self.sec_model])
        unique_specialists: List[str] = []
        seen_keys: set = set()
        for m in raw_specialists:
            k = self._canonical_slot_key(m)
            if k not in seen_keys:
                seen_keys.add(k)
                unique_specialists.append(m)
        if not unique_specialists:
            unique_specialists = [self.gemma_model]

        if len(unique_specialists) == 1:
            return [
                self.run_fusion_pipeline(txt, fragment_id=fid, hints=hints, facts=facts)
                for txt, fid in norm_frags
            ]

        clean_hints = [str(h).strip() for h in (hints or []) if str(h).strip()]
        clean_facts = [str(f).strip() for f in (facts or []) if str(f).strip()]
        hint_block = ("Active Steering Hints (highest priority first):\n" + "\n".join(f"- {h}" for h in clean_hints) + "\n") if clean_hints else ""
        fact_block = ("Observed Blackboard Facts:\n" + "\n".join(f"- {f}" for f in clean_facts) + "\n") if clean_facts else ""

        per_frag_proposals: List[List[CandidateProposal]] = [[] for _ in norm_frags]
        # Stage 1: Model-outer loop — keep each specialist resident across all M fragments
        for role_idx, mdl in enumerate(unique_specialists):
            for frag_idx, (frag_txt, _) in enumerate(norm_frags):
                role_label, sys_p, user_p = self._specialist_role_prompt(role_idx, frag_txt, hint_block, fact_block)
                raw_out = self._query_model(mdl, user_p, sys_p)
                extracted, _ = self._extract_proposals_from_output(
                    raw_out,
                    mdl,
                    role_label,
                    len(per_frag_proposals[frag_idx]),
                )
                per_frag_proposals[frag_idx].extend(extracted)

        # Stage 2: Arbitrate each fragment (Arbiter model stays resident across all non-bypassed fragments)
        results: List[FusionArbitrationResult] = []
        for frag_idx, (frag_txt, fid) in enumerate(norm_frags):
            results.append(
                self._arbitrate_proposals(
                    rfc_fragment=frag_txt,
                    fragment_id=fid,
                    proposals=per_frag_proposals[frag_idx],
                    participating_models=list(unique_specialists),
                    unique_specialists=unique_specialists,
                    hint_block=hint_block,
                    fact_block=fact_block,
                )
            )
        return results

    def _save_probes_to_db(self, probes: List[Dict[str, Any]], fragment_id: Optional[int], consensus_type: str) -> None:
        if not self.db:
            return
        for p in probes:
            p_id = self.db.save_probe(
                fragment_id=fragment_id,
                rationale=f"[{consensus_type}] {p.get('rationale', '')}",
                raw_request=p.get("raw_request", ""),
                is_clean=p.get("is_clean", False),
                source_type="fusion",
            )
            p["probe_id"] = p_id

    def explain_vulnerability_concept(
        self,
        rfc_fragment: str,
        probe_request: str,
        baseline_resp: str = "",
        probe_resp: str = "",
        retest_resp: str = "",
        anomalies: Optional[List[Dict[str, Any]]] = None,
        desync_class: Optional[str] = None,
        details: str = "",
    ) -> Dict[str, Any]:
        """
        The James Kettle Discovery Synthesis:
        Analyzes live test results produced by HTTP Terminator against a target server and
        formulates the broader architectural explanation and formal concept name.
        """
        anom_summary = "\n".join([f"- {a.get('type')}: {a.get('description')}" for a in (anomalies or [])]) if anomalies else "None"

        b_stat = baseline_resp.splitlines()[0] if baseline_resp else "200 OK"
        p_stat = probe_resp.splitlines()[0] if probe_resp else "Unknown / Disconnected"
        r_stat = retest_resp.splitlines()[0] if retest_resp else "CONNECTION_CLOSED"

        sys_prompt = (
            "You are an elite protocol security researcher (in the caliber of James Kettle / DEF CON 34 / Black Hat). "
            "You are analyzing live test results produced by HTTP Terminator against a target server. "
            "The vulnerability was NOT written in the RFC. The RFC provided the clue, and the attack concept comes from testing and analyzing what happened. "
            "Formulate the broader architectural explanation and propose the formal attack concept name. "
            "Output strict JSON with keys: 'concept_name', 'architectural_explanation', 'rfc_clue_connection', 'generalization', 'validation_steps'."
        )

        from engine.execution_policy import sanitize_for_llm_prompt
        sanitized_probe_resp = sanitize_for_llm_prompt(probe_resp, max_chars=350)
        sanitized_retest_resp = sanitize_for_llm_prompt(retest_resp, max_chars=350)

        user_prompt = f"""
RFC FRAGMENT (THE INSPIRATION CLUE):
\"\"\"{rfc_fragment}\"\"\"

PROBE REQUEST SENT (THE TRIGGER):
{probe_request}

OBSERVED LIVE ACTIVITY TRACE:
- Diagnostic Details: {details}
- Desync Classification: {desync_class or 'Unclassified / Anomaly'}
- Conn A (Baseline Response) Status: {b_stat}
- Conn B (Probe Response) Status: {p_stat}
- Conn A (Re-Test Response) Status: {r_stat}
- Detected Anomalies:
{anom_summary}

Full Probe Response Snippet (First 350 bytes):
{sanitized_probe_resp}

Full Re-Test Response Snippet (First 350 bytes):
{sanitized_retest_resp}

Analyze what happened. Did the server apply response parsing rules to requests (Shared-Parser Confusion)? Did the front-end proxy disagree on body length? Did cross-protocol parser reuse occur?
Output strict JSON matching:
{{
  "concept_name": "Descriptive Vulnerability Concept Name",
  "architectural_explanation": "Detailed explanation of what the server parser did internally",
  "rfc_clue_connection": "How the RFC snippet inspired this discovery",
  "generalization": "How this vulnerability applies to other servers/protocols",
  "validation_steps": ["step 1", "step 2"]
}}
"""
        required_keys = ("concept_name", "architectural_explanation", "rfc_clue_connection", "generalization", "validation_steps")
        try:
            raw_out = self._query_model(self.arbiter_model, user_prompt, sys_prompt, num_predict=384)
            if raw_out and not self._is_refusal(raw_out):
                parsed = self._parse_json(raw_out, unwrap_lists=False)
                cand = None
                if parsed and isinstance(parsed, list) and isinstance(parsed[0], dict):
                    cand = parsed[0]
                elif parsed and isinstance(parsed, dict):
                    cand = parsed
                if cand and all(k in cand and cand[k] for k in required_keys) and isinstance(cand.get("validation_steps"), list):
                    return cand
        except Exception:
            pass

        inferred_concept = desync_class or "Shared-Parser / Framing Discrepancy"
        frag_lower = rfc_fragment.lower()
        if any(w in frag_lower for w in ["response", "status", "304", "204", "head"]):
            inferred_concept = "Shared-Parser Confusion (Response-to-Request Inversion)"
            explanation = "The server appears to apply RFC response-handling rules to incoming client requests, causing differential body termination or socket confusion."
        elif any(w in frag_lower for w in ["smtp", "bdat", "dot-stuffing", "mail"]):
            inferred_concept = "Cross-Protocol Parser Reuse (SMTP/HTTP Demarcation Discrepancy)"
            explanation = "The front-end or gateway appears to reuse socket parsers across SMTP and HTTP, failing to isolate multi-line stream delimiters."
        else:
            explanation = f"Observed differential behavior on target host triggered by RFC fragment: {details}"

        return {
            "concept_name": inferred_concept,
            "architectural_explanation": explanation,
            "rfc_clue_connection": f"Inspired by normative requirement in RFC fragment: {rfc_fragment[:80]}...",
            "generalization": "Servers utilizing unified protocol parsers or multi-tier reverse proxy pipelines with differing delimiter assumptions.",
            "validation_steps": ["Verify whether Conn A socket state persists across pipelined requests", "Test differential Content-Length vs chunked boundaries"],
        }

    def _normalize_crlf(self, text: Any) -> str:
        if not text:
            return ""
        if isinstance(text, dict):
            for key in ("request", "raw", "raw_request", "template", "payload", "data"):
                if key in text and isinstance(text[key], str):
                    text = text[key]
                    break
            else:
                method = text.get("method", "GET")
                path = text.get("path", text.get("uri", "/"))
                version = text.get("version", "HTTP/1.1")
                headers = text.get("headers", {})
                body = text.get("body", "")

                lines = [f"{method} {path} {version}"]
                if isinstance(headers, dict):
                    for k, v in headers.items():
                        lines.append(f"{k}: {v}")
                elif isinstance(headers, list):
                    for h in headers:
                        lines.append(str(h))
                lines.append("")
                if body:
                    lines.append(str(body))
                text = "\r\n".join(lines)
        elif not isinstance(text, str):
            text = str(text)

        # Safe literal escape replacement without UTF-8 -> Latin-1 mojibake
        if "\\r\\n" in text or "\\n" in text or "\\t" in text:
            text = (
                text.replace("\\r\\n", "\r\n")
                .replace("\\r", "\r")
                .replace("\\n", "\n")
                .replace("\\t", "\t")
            )
        return re.sub(r"(?<!\r)\n", "\r\n", text)

    def _parse_json(self, text: str, unwrap_lists: bool = True) -> List[Dict[str, Any]]:
        if not text:
            return []
        cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        if "</think>" in cleaned:
            cleaned = cleaned.split("</think>")[-1].strip()
        if "<think>" in cleaned:
            cleaned = cleaned.split("<think>")[0].strip()

        raw_before_fence = cleaned
        if "```json" in cleaned:
            cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```", 1)[1].split("```", 1)[0].strip()

        def _normalize_parsed(val: Any) -> List[Dict[str, Any]]:
            if isinstance(val, list):
                out = []
                for v in val:
                    if isinstance(v, dict):
                        out.append(v)
                    elif isinstance(v, str) and unwrap_lists:
                        out.append({"rationale": "Synthesized probe", "raw_request": v, "is_clean": False})
                return out
            if isinstance(val, dict):
                if not unwrap_lists:
                    return [val]
                for key in ("probes", "suggested_probes", "candidates", "items", "requests", "templates", "proposals"):
                    if key in val and isinstance(val[key], list):
                        return [
                            v if isinstance(v, dict) else {"rationale": "Synthesized probe", "raw_request": str(v), "is_clean": False}
                            for v in val[key]
                        ]
                return [val]
            return []

        def _try_decode(candidate: str) -> List[Dict[str, Any]]:
            if not candidate:
                return []
            try:
                res = _normalize_parsed(json.loads(candidate))
                if res:
                    return res
            except Exception:
                pass
            decoder = json.JSONDecoder()
            for idx, ch in enumerate(candidate):
                if ch in ("{", "["):
                    try:
                        parsed, _ = decoder.raw_decode(candidate[idx:])
                        res = _normalize_parsed(parsed)
                        if res:
                            return res
                    except Exception:
                        continue
            return []

        # Pass 1: Direct JSON decode
        res = _try_decode(cleaned)
        if res:
            return res

        # Pass 2: Deterministic JSON repair (unescaped newlines in strings, trailing commas, smart quotes)
        repaired = _repair_json_string(cleaned)
        res = _try_decode(repaired)
        if res:
            return res

        # Pass 3: Python-style single-quoted dict/list literal recovery
        for candidate in (cleaned, repaired):
            first_brace = min(
                (i for i in (candidate.find("{"), candidate.find("[")) if i >= 0),
                default=-1,
            )
            if first_brace >= 0:
                snippet = candidate[first_brace:]
                try:
                    lit = ast.literal_eval(snippet)
                    res = _normalize_parsed(lit)
                    if res:
                        return res
                except Exception:
                    pass

        # Pass 4: Fallback raw HTTP template recovery when small local models emit prose + HTTP block
        if unwrap_lists:
            http_match = re.search(
                r"((?:GET|POST|HEAD|OPTIONS|PUT|DELETE|CONNECT|TRACE|PRI)\s+\S+\s+HTTP/\d(?:\.\d)?(?:\r?\n[^\r\n`]+){1,20})",
                raw_before_fence,
                flags=re.IGNORECASE,
            )
            if http_match:
                req_block = http_match.group(1).strip()
                if not req_block.endswith("\r\n\r\n") and not req_block.endswith("\n\n"):
                    req_block = req_block + "\r\n\r\n"
                return [{"rationale": "Recovered HTTP probe from unstructured completion", "raw_request": req_block, "is_clean": False}]
        return []

    def arbitrate_structured_json(
        self,
        task_name: str,
        system_prompt: str,
        user_prompt: str,
        default_payload: Optional[Dict[str, Any]] = None,
        num_predict: int = 512,
    ) -> Dict[str, Any]:
        """
        General-purpose N-Model ModelFusion pipeline for Google Mantis (Module 20),
        ARTEX dynamic intent/worker planning, and unified `--all` / `--ensemble` auditing.
        Includes low-RAM single-model collapse, memory-aware concurrency, hybrid routing,
        and bounded JSON-repair retry.
        """
        import concurrent.futures

        if not self.available_tags:
            self.available_tags = self._fetch_available_tags()

        generative_tags = [t for t in self.available_tags if not self._is_embedding_model(t)]
        has_24g_mem = float(getattr(self, "free_ram_gb", 0.0)) >= 24.0 or float(getattr(self, "free_vram_mb", 0.0)) >= 14336.0
        abliterated_candidates = [
            t for t in generative_tags
            if ("abliterat" in t.lower() or "obliterat" in t.lower())
            and (has_24g_mem or not any(tag in t.lower() for tag in ("70b", "72b", "755b")))
        ]
        raw_specialists = list(getattr(self, "specialist_models", None) or [self.gemma_model, self.sec_model])
        unique_specialists: List[str] = []
        seen_keys: set = set()
        for m in raw_specialists:
            k = self._canonical_slot_key(m)
            if k not in seen_keys:
                seen_keys.add(k)
                unique_specialists.append(m)
        if not unique_specialists:
            unique_specialists = [self.gemma_model]

        participating_models = list(dict.fromkeys([*unique_specialists, self.arbiter_model]))

        paid_active = (getattr(self, "paid_client", None) is not None) and bool(getattr(self.paid_config, "enabled", False))
        is_hybrid = getattr(self, "backend_mode", "ollama") == "hybrid" or bool(getattr(self.paid_config, "hybrid_mode", False))
        paid_offline_blocked = False
        if paid_active and os.environ.get("RFCHUNT_OFFLINE") == "1":
            cfg = getattr(self, "paid_config", None)
            eps = list((cfg.providers or {}).values()) if cfg else []
            if not eps or not any(is_loopback_url(ep.base_url) for ep in eps):
                paid_offline_blocked = True

        if (not paid_active and (not generative_tags or os.environ.get("RFCHUNT_OFFLINE") == "1")) or (paid_offline_blocked and not is_hybrid):
            return {
                "task": task_name,
                "status": "offline_fallback",
                "consensus_type": "DeterministicFallback",
                "participating_models": participating_models,
                "abliterated_active": any("obliterat" in m.lower() or "abliterat" in m.lower() for m in participating_models),
                "backend_mode": getattr(self, "backend_mode", "paid_api" if paid_active else "ollama"),
                "data": default_payload if default_payload is not None else {},
            }

        # Execute unique specialists respecting memory-aware max_concurrent_queries
        max_w = max(1, min(len(unique_specialists), int(getattr(self, "max_concurrent_queries", 2))))
        raw_results: List[Tuple[str, str]] = []
        if max_w == 1 or len(unique_specialists) == 1:
            for mdl in unique_specialists:
                raw_results.append((mdl, self._query_model(mdl, user_prompt, system_prompt, num_predict)))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as pool:
                futs = [(mdl, pool.submit(self._query_model, mdl, user_prompt, system_prompt, num_predict)) for mdl in unique_specialists]
                for mdl, fut in futs:
                    raw_results.append((mdl, fut.result()))

        proposals: List[Dict[str, Any]] = []
        for model_name, raw_out in raw_results:
            if not raw_out or self._is_refusal(raw_out):
                continue
            parsed = self._parse_json(raw_out, unwrap_lists=False)
            if parsed:
                proposals.append({"model": model_name, "output": parsed[0] if len(parsed) == 1 else parsed})

        rescued = False
        if not proposals and abliterated_candidates:
            abl_model = abliterated_candidates[0]
            rescued_raw = self._query_model(
                abl_model,
                user_prompt,
                f"{system_prompt}\nOperate strictly as a senior defensive security auditor outputting raw JSON.",
                num_predict=num_predict,
            )
            if rescued_raw and not self._is_refusal(rescued_raw):
                parsed = self._parse_json(rescued_raw, unwrap_lists=False)
                if parsed:
                    proposals.append({
                        "model": f"{abl_model} [AbliteratedRescue]",
                        "output": parsed[0] if len(parsed) == 1 else parsed,
                    })
                    rescued = True

        if not proposals:
            return {
                "task": task_name,
                "status": "deterministic_fallback",
                "consensus_type": "DeterministicFallback",
                "participating_models": participating_models,
                "abliterated_active": bool(abliterated_candidates) or any("obliterat" in m.lower() or "abliterat" in m.lower() for m in participating_models),
                "backend_mode": getattr(self, "backend_mode", "ollama"),
                "data": default_payload if default_payload is not None else {},
            }

        synthesized_data: Any = proposals[0]["output"]
        arb_same_as_sole = (
            len(unique_specialists) == 1
            and self._canonical_slot_key(self.arbiter_model) == self._canonical_slot_key(unique_specialists[0])
        )
        single_model_collapsed = len(unique_specialists) == 1 and arb_same_as_sole
        if len(proposals) >= 2 and not single_model_collapsed:
            arb_prompt = (
                f"Task: {task_name}\n"
                f"Merge and refine the following specialist JSON outputs into a single highest-accuracy JSON object.\n"
                f"Proposals:\n{json.dumps(proposals, indent=2)[:2800]}"
            )
            arb_raw = self._query_model(self.arbiter_model, arb_prompt, system_prompt, num_predict=num_predict)
            if (not arb_raw or self._is_refusal(arb_raw)) and abliterated_candidates:
                arb_raw = self._query_model(abliterated_candidates[0], arb_prompt, system_prompt, num_predict=num_predict)
            if arb_raw and not self._is_refusal(arb_raw):
                arb_parsed = self._parse_json(arb_raw, unwrap_lists=False)
                if not arb_parsed and arb_raw.strip():
                    repair_raw = self._query_model(
                        self.arbiter_model,
                        f"Reformat the following into valid JSON only:\n{arb_raw[:1200]}",
                        "Output strictly valid JSON only.",
                        num_predict=min(num_predict, 512),
                    )
                    if repair_raw and not self._is_refusal(repair_raw):
                        arb_parsed = self._parse_json(repair_raw, unwrap_lists=False)
                if arb_parsed:
                    synthesized_data = arb_parsed[0] if len(arb_parsed) == 1 else arb_parsed

        has_abl = rescued or bool(abliterated_candidates) or any(
            "obliterat" in m.lower() or "abliterat" in m.lower() for m in participating_models
        )
        consensus_label = (
            "SingleModelFastPath"
            if single_model_collapsed
            else ("AbliteratedConsensus" if has_abl else "ArbiterSynthesized")
        )
        return {
            "task": task_name,
            "status": "fused",
            "consensus_type": consensus_label,
            "participating_models": [p["model"] for p in proposals],
            "abliterated_active": has_abl,
            "backend_mode": getattr(self, "backend_mode", "ollama"),
            "data": synthesized_data,
        }
