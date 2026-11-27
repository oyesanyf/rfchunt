"""
Model Adapter & Local Fusion Engine:
Adapted from ModelFusion (d:\\harfile\\ModelFusion) and Ollama client adapters.
Enables 24/7 zero-cost local LLM inference using Google Gemma, Qwen, Foundation-Sec,
and GLM / DeepSeek-R1 via local Ollama with multi-model panel fusion.
"""

import json
import logging
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional
import httpx

from engine.ollama_concurrency_guard import get_shared_ollama_guard
from engine.paid_model_provider import (
    PaidModelClient,
    PaidModelConfig,
    is_ollama_model_tag,
    load_paid_model_config,
)
from ollama_manager import OllamaLifecycleManager, is_embedding_model

logger = logging.getLogger("terminator.models")

_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", flags=re.DOTALL | re.IGNORECASE)
_FILE_PATH_RE = re.compile(
    r"(?:^|[\s`'\"\(\[\{,:;])"
    r"((?:\.github/|[A-Za-z0-9_.-]+/)[A-Za-z0-9_./-]*[A-Za-z0-9_-]"
    r"\.(?:py|rs|ts|tsx|js|jsx|mjs|cjs|go|java|rb|php|c|cc|cpp|h|hpp|cs|yml|yaml|json|toml|sh|ps1|sql|html|xml|md|tf|kt|swift))"
    r"(?:$|[\s`'\"\)\]\},:;\#])"
)


def strip_think_blocks(raw: str) -> str:
    """Strips `<think>...</think>` blocks and dangling unclosed `<think>` tags."""
    if not raw:
        return ""
    cleaned = _THINK_BLOCK_RE.sub("", raw)
    lower = cleaned.lower()
    if "</think>" in lower:
        idx = lower.rfind("</think>")
        cleaned = cleaned[idx + len("</think>") :]
        lower = cleaned.lower()
    if "<think>" in lower:
        idx = lower.find("<think>")
        before = cleaned[:idx].strip()
        cleaned = before if before else ""
    return cleaned.strip()


def _has_repeated_char_stutter(text: str) -> bool:
    prev = ""
    run = 0
    for ch in text:
        if ch in "-=*#_~` \t\n\r":
            prev = ""
            run = 0
            continue
        if ch == prev:
            run += 1
            if run >= 24:
                return True
        else:
            prev = ch
            run = 1
    return False


def detect_repetition_loop(text: str) -> Optional[str]:
    """Detects classic abliterated GGUF repetition / stutter loops."""
    trimmed = (text or "").strip()
    if not trimmed:
        return None
    if _has_repeated_char_stutter(trimmed):
        return "character_stutter_loop"

    line_counts: Dict[str, int] = {}
    for line in trimmed.splitlines():
        norm = line.strip().lower()
        if len(norm) >= 20 and not norm.startswith("```") and not all(c in "-=*#_~| " for c in norm):
            line_counts[norm] = line_counts.get(norm, 0) + 1
            if line_counts[norm] >= 3:
                return "repeated_line_loop"

    words = [
        re.sub(r"^[^a-z0-9_-]+|[^a-z0-9_-]+$", "", w.lower())
        for w in trimmed.split()
    ]
    words = [w for w in words if w]
    if len(words) >= 24:
        ngram_counts: Dict[str, int] = {}
        for i in range(len(words) - 5):
            ng = " ".join(words[i : i + 6])
            ngram_counts[ng] = ngram_counts.get(ng, 0) + 1
            if ngram_counts[ng] >= 4:
                return "repeated_ngram_loop"
    if len(words) >= 50:
        ratio = len(set(words)) / float(len(words))
        if ratio < 0.20:
            return f"low_lexical_diversity({ratio:.2f})"
    return None


def detect_meta_slop(text: str) -> Optional[str]:
    """Detects generic meta-commentary / filler slop or verbatim prompt-stub echoes."""
    lower = (text or "").strip().lower()
    if not lower:
        return "empty_response"
    hard_markers = (
        "in summary, the key steps to continue",
        "the code snippet provided is well-structured",
        "aligns with best practices",
        "based on the judge analysis",
        "the panel agrees that",
        "i don't have access to your files",
        "without access to the actual source code",
        "here is a hypothetical example of how",
    )
    for m in hard_markers:
        if m in lower:
            return f"meta_slop:{m}"
    if (
        '"rationale": "..."' in lower
        or '"raw_request": "..."' in lower
        or "todo: fill in vulnerability" in lower
    ):
        return "placeholder_template_stub"
    return None


def extract_file_paths(text: str) -> List[str]:
    """Extracts normalized relative source/workflow file paths mentioned in text."""
    seen = set()
    out: List[str] = []
    for m in _FILE_PATH_RE.finditer(text or ""):
        norm = m.group(1).lstrip("./").replace("\\", "/").lower()
        if norm.startswith(("http/", "https/")):
            continue
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def validate_abliterated_output(
    raw_text: str,
    *,
    allowed_file_paths: Optional[List[str]] = None,
    require_json: bool = False,
) -> Dict[str, Any]:
    """
    Deterministic Anti-Junk & Grounding Guard for abliterated local models.
    Strips `<think>` blocks and rejects refusals, repetition loops, meta-slop,
    invalid required JSON, and fabricated file paths not in `allowed_file_paths`.
    """
    reasons: List[str] = []
    cleaned = strip_think_blocks(raw_text or "")
    if len(cleaned) < 4:
        return {
            "accepted": False,
            "cleaned_text": cleaned,
            "rejection_reasons": ["empty_or_think_only"],
            "hallucinated_paths": [],
        }

    if ModelFusionAdapter._is_refusal(cleaned):
        reasons.append("safety_refusal")

    loop_err = detect_repetition_loop(cleaned)
    if loop_err:
        reasons.append(loop_err)

    slop_err = detect_meta_slop(cleaned)
    if slop_err:
        reasons.append(slop_err)

    if require_json:
        parsed_ok = False
        cand = cleaned
        if "```json" in cand:
            cand = cand.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in cand:
            cand = cand.split("```", 1)[1].split("```", 1)[0].strip()
        try:
            json.loads(cand)
            parsed_ok = True
        except Exception:
            for open_ch, close_ch in (("{", "}"), ("[", "]")):
                s_idx = cand.find(open_ch)
                e_idx = cand.rfind(close_ch)
                if 0 <= s_idx < e_idx:
                    try:
                        json.loads(cand[s_idx : e_idx + 1])
                        parsed_ok = True
                        break
                    except Exception:
                        pass
        if not parsed_ok:
            reasons.append("invalid_required_json")

    hallucinated: List[str] = []
    grounded: List[str] = []
    norm_allowed = [
        p.strip().lstrip("./").replace("\\", "/").lower()
        for p in (allowed_file_paths or [])
        if p and str(p).strip()
    ]
    if norm_allowed:
        allowed_bases = {p.rsplit("/", 1)[-1] for p in norm_allowed}
        for cited in extract_file_paths(cleaned):
            base = cited.rsplit("/", 1)[-1]
            if (
                any(cited == a or a.endswith(cited) or cited.endswith(a) for a in norm_allowed)
                or base in allowed_bases
            ):
                grounded.append(cited)
            else:
                hallucinated.append(cited)
        if hallucinated and (not grounded or (len(hallucinated) >= 2 and len(hallucinated) > len(grounded))):
            reasons.append(f"hallucinated_file_paths({','.join(hallucinated[:4])})")

    return {
        "accepted": len(reasons) == 0,
        "cleaned_text": cleaned,
        "rejection_reasons": reasons,
        "hallucinated_paths": hallucinated,
    }


class ModelFusionAdapter:
    """
    Manages LLM inference and panel fusion across models.
    - When `.env.local` configures paid/enterprise models (Anthropic, OpenAI,
      Azure OpenAI, Gemini, OpenRouter, or OpenAI-compatible gateways), routes
      all inference directly to those paid models and bypasses Ollama completely.
    - Otherwise runs 100% locally via Ollama (Gemma, Qwen, Foundation-Sec, GLM, DeepSeek-R1).
    """

    DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434"
    DEFAULT_MODELFUSION_ENDPOINT = "http://127.0.0.1:5000"

    def __init__(
        self,
        preferred_model: Optional[str] = None,
        ollama_endpoint: Optional[str] = None,
        use_fusion: bool = True,
        sec_model: Optional[str] = None,
        env_local_path: Optional[str] = None,
        force_ollama: bool = False,
        modelfusion_endpoint: Optional[str] = None,
        use_modelfusion_server: Optional[bool] = None,
    ):
        self.endpoint = ollama_endpoint or os.environ.get("OLLAMA_ENDPOINT", self.DEFAULT_OLLAMA_ENDPOINT)
        self.modelfusion_endpoint = (
            modelfusion_endpoint
            or os.environ.get("MODELFUSION_ENDPOINT")
            or self.DEFAULT_MODELFUSION_ENDPOINT
        ).rstrip("/")
        if use_modelfusion_server is None:
            self.use_modelfusion_server = os.environ.get("RFCHUNT_USE_MODELFUSION", "0").strip() == "1"
        else:
            self.use_modelfusion_server = bool(use_modelfusion_server)
        self.modelfusion_server_ready = False
        self.enable_anti_junk_guard = os.environ.get("RFCHUNT_ENABLE_ANTI_JUNK_GUARD", "1").strip() != "0"
        self.use_fusion = use_fusion if os.environ.get("USE_MODEL_FUSION") is None else (os.environ.get("USE_MODEL_FUSION") == "1")
        self.free_ram_gb = self._get_free_memory_gb()
        self.sized_qwen = self._size_qwen_for_free_memory(self.free_ram_gb)

        timeout_env = os.environ.get("OLLAMA_TIMEOUT", "120.0")
        self.timeout = float(timeout_env) if float(timeout_env) > 0 else None

        self.paid_config: PaidModelConfig = load_paid_model_config(
            env_local_path=env_local_path,
            force_ollama=force_ollama,
        )
        self.paid_client: Optional[PaidModelClient] = None

        if self.paid_config.enabled:
            self.backend_mode = "paid_api"
            self.using_ollama = False
            self.paid_client = PaidModelClient(self.paid_config, timeout=self.timeout)
            self.client = self.paid_client.client
            explicit_paid_pref = (
                preferred_model
                if (preferred_model and not is_ollama_model_tag(preferred_model))
                else None
            )
            explicit_paid_sec = (
                sec_model
                if (sec_model and not is_ollama_model_tag(sec_model))
                else None
            )
            self.preferred_model = explicit_paid_pref or self.paid_config.primary_model
            self.sec_model = explicit_paid_sec or self.paid_config.sec_model
            panel: List[str] = []
            for m in (self.preferred_model, self.sec_model, *self.paid_config.panel_models):
                if m and m not in panel:
                    panel.append(m)
            self.available_tags = panel
            self.active_model = self.preferred_model
            logger.info(
                "[ModelFusion] Paid API backend active via %s (provider=%s, models=%s; Ollama bypassed)",
                self.paid_config.source_file,
                self.paid_config.provider,
                ", ".join(self.available_tags),
            )
            return

        self.backend_mode = "ollama"
        self.using_ollama = True
        self.preferred_model = preferred_model or os.environ.get(
            "LOCAL_MODEL", "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
        )
        self.sec_model = sec_model
        self.available_tags = self._fetch_available_tags()

        fetch_is_patched = "mock" in type(self._fetch_available_tags).__name__.lower()
        if not fetch_is_patched:
            self.available_tags = OllamaLifecycleManager.ensure_panel_models_installed(
                available_tags=self.available_tags,
                endpoint=self.endpoint,
                free_ram_gb=self.free_ram_gb,
                preferred_model=self.preferred_model,
                sec_model=self.sec_model,
            )

        self.active_model = self._resolve_model(self.preferred_model)
        self.client = httpx.Client(timeout=httpx.Timeout(self.timeout, connect=10.0))
        if self.use_modelfusion_server and not force_ollama:
            self.modelfusion_server_ready = self._probe_modelfusion_server()
            if self.modelfusion_server_ready:
                self.backend_mode = "modelfusion_http"
                logger.info(
                    "[ModelFusion] Local ModelFusion server active at %s (direct Ollama fallback ready)",
                    self.modelfusion_endpoint,
                )

    def _probe_modelfusion_server(self, timeout_sec: float = 0.4) -> bool:
        """Fast <=400ms health probe against ModelFusion local HTTP server (:5000)."""
        eff_timeout = min(max(float(timeout_sec), 0.05), 0.4)
        base = getattr(self, "modelfusion_endpoint", self.DEFAULT_MODELFUSION_ENDPOINT).rstrip("/")
        for path in ("/health", "/api/health", "/api/status"):
            try:
                resp = httpx.get(f"{base}{path}", timeout=eff_timeout)
                if 200 <= resp.status_code < 400:
                    return True
            except Exception:
                continue
        return False

    def _query_modelfusion_server(
        self,
        system_instruction: str,
        user_prompt: str,
        schema_hint: Optional[str] = None,
        num_predict: int = 256,
    ) -> List[Dict[str, Any]]:
        """
        Routes grounded consensus triage through ModelFusion's local HTTP server (`:5000`)
        behind the shared `OllamaConcurrencyGuard` single-slot lock, applying the
        deterministic Anti-Junk & Grounding Guard before returning structured JSON items.
        """
        if os.environ.get("RFCHUNT_OFFLINE") == "1":
            base_low = self.modelfusion_endpoint.lower()
            if not any(h in base_low for h in ("127.0.0.1", "localhost", "[::1]")):
                return []

        expected_schema = schema_hint or '{"probes": [{"rationale": "...", "raw_request": "...", "is_clean": false}]}'
        combined_prompt = (
            f"{system_instruction}\n\n{user_prompt}\n\n"
            f"CRITICAL: Output ONLY valid JSON matching schema: {expected_schema}."
        ).strip()
        allowed_files = extract_file_paths(user_prompt)

        payload_orchestrate = {
            "prompt": combined_prompt,
            "task": "code-vulnerability-detection",
            "fusion": bool(self.use_fusion),
            "model": self.active_model,
            "temperature": 0.15,
            "max_tokens": max(int(num_predict), 256),
        }
        payload_openai = {
            "model": self.active_model,
            "temperature": 0.15,
            "max_tokens": max(int(num_predict), 256),
            "messages": [
                {"role": "system", "content": system_instruction or "You are a defensive security auditor. Output ONLY valid JSON."},
                {"role": "user", "content": f"{user_prompt}\n\nCRITICAL: Output ONLY valid JSON matching schema: {expected_schema}."},
            ],
        }

        guard = get_shared_ollama_guard()
        if guard.is_circuit_open():
            return []

        raw_text = ""
        with guard.acquire(timeout_sec=guard.acquire_timeout_sec) as acquired:
            if not acquired:
                return []
            for path, body in (
                ("/api/orchestrate", payload_orchestrate),
                ("/orchestrate", payload_orchestrate),
                ("/v1/chat/completions", payload_openai),
            ):
                try:
                    resp = self.client.post(
                        f"{self.modelfusion_endpoint}{path}",
                        json=body,
                        timeout=httpx.Timeout(self.timeout, connect=5.0),
                    )
                except Exception as exc:
                    logger.debug("[ModelFusion] HTTP %s failed: %s", path, exc)
                    continue
                if resp.status_code == 404:
                    continue
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        raw_text = (resp.text or "").strip()
                        break
                    if isinstance(data, dict):
                        raw_text = str(
                            data.get("content")
                            or data.get("response")
                            or data.get("result")
                            or data.get("answer")
                            or ((data.get("message") or {}).get("content") if isinstance(data.get("message"), dict) else "")
                            or (
                                (((data.get("choices") or [{}])[0].get("message") or {}).get("content"))
                                if isinstance(data.get("choices"), list) and data.get("choices")
                                else ""
                            )
                            or ""
                        ).strip()
                    break

        if not raw_text:
            return []

        if getattr(self, "enable_anti_junk_guard", True):
            verdict = validate_abliterated_output(
                raw_text,
                allowed_file_paths=allowed_files,
                require_json=True,
            )
            if not verdict["accepted"]:
                logger.warning(
                    "[ModelFusion] Anti-junk guard rejected server output (%s); falling back to local Ollama panel.",
                    verdict["rejection_reasons"],
                )
                return []
            raw_text = verdict["cleaned_text"]

        items = self._parse_json_array(raw_text, unwrap_lists=(schema_hint is None))
        cleaned_items: List[Dict[str, Any]] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            if self._is_refusal(json.dumps(it, sort_keys=True)):
                continue
            it["fused_model"] = f"modelfusion:{self.active_model}"
            cleaned_items.append(it)
        return cleaned_items

    def close(self) -> None:
        paid_client = getattr(self, "paid_client", None)
        if paid_client is not None:
            try:
                paid_client.close()
            except Exception:
                pass
            return
        client = getattr(self, "client", None)
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    def __enter__(self) -> "ModelFusionAdapter":
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
        """Evaluates runtime free/available RAM in GB across Windows, Linux, and macOS."""
        try:
            if os.name == "nt":
                import ctypes

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                    return stat.ullAvailPhys / (1024 ** 3)
            elif os.path.isfile("/proc/meminfo"):
                with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("MemAvailable:"):
                            kb = int(line.split()[1])
                            return kb / (1024 ** 2)
            elif sys.platform == "darwin":
                out = subprocess.check_output(["vm_stat"], text=True, timeout=2)
                page_size = 4096
                m_ps = re.search(r"page size of (\d+) bytes", out)
                if m_ps:
                    page_size = int(m_ps.group(1))
                free_pages = 0
                for key in ("Pages free", "Pages inactive", "Pages speculative"):
                    m_pg = re.search(rf"{key}:\s+(\d+)", out)
                    if m_pg:
                        free_pages += int(m_pg.group(1))
                if free_pages > 0:
                    return (free_pages * page_size) / (1024 ** 3)
        except Exception:
            pass
        return 8.0

    @staticmethod
    def _size_qwen_for_free_memory(free_ram_gb: float, free_vram_mb: float = 0.0) -> str:
        """Sizes Qwen model strictly by runtime available memory."""
        if free_ram_gb >= 48.0 or free_vram_mb >= 24576.0:
            return "qwen2.5:32b"
        if free_ram_gb >= 24.0 or free_vram_mb >= 14336.0:
            return "qwen2.5:14b"
        if free_ram_gb >= 12.0 or free_vram_mb >= 4608.0:
            return "qwen2.5:7b"
        if free_ram_gb >= 6.0 or free_vram_mb >= 2048.0:
            return "qwen2.5:3b"
        return "qwen2.5:1.5b"

    def _fetch_available_tags(self) -> List[str]:
        """Probes Ollama and auto-installs/auto-starts the daemon if missing (skipped in paid API mode)."""
        if not getattr(self, "using_ollama", True):
            cfg = getattr(self, "paid_config", None)
            return list(cfg.panel_models) if cfg and cfg.enabled else list(getattr(self, "available_tags", []) or [])
        try:
            return OllamaLifecycleManager.ensure_ollama_ready(endpoint=self.endpoint)
        except Exception:
            try:
                resp = httpx.get(f"{self.endpoint}/api/tags", timeout=0.4)
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

    def _resolve_model(self, preferred: str) -> str:
        """
        Dynamically resolves a valid generative model tag to avoid 404 aborts, OOMs, and embedding-model mismatches.
        """
        raw_tags = getattr(self, "available_tags", None) or []
        generative_tags = [t for t in raw_tags if not self._is_embedding_model(t)]
        if not generative_tags:
            return preferred

        free_ram = float(getattr(self, "free_ram_gb", 16.0))
        sized_qwen = getattr(self, "sized_qwen", None) or self._size_qwen_for_free_memory(free_ram)
        pref_lower = (preferred or "").strip().lower()

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
            "huihui_ai/foundation-sec-abliterated:8b",
            "hf.co/audnai/penclaw-glm-5.3-abliterated",
            "hf.co/msuiche/glm-5.3-abliterated-cyber-glp-77",
            "hf.co/huihui-ai/glm-5.3-abliterated",
            "huihui_ai/glm-4.7-flash-abliterated:latest",
            "hf.co/huihui-ai/huihui-glm-4.7-flash-abliterated",
            "hf.co/jsantillana/glm-4.7-flash-abliterated",
            "huihui_ai/deepseek-r1-abliterated:8b",
            "hf.co/bartowski/glm-4-9b-chat-abliterated-gguf:q4_k_m",
            "hf.co/byroneverson/glm-4-9b-chat-abliterated",
            "hf.co/byroneverson/longwriter-glm4-9b-abliterated",
        }
        obliterated_bases = {a.split(":")[0] for a in obliterated_aliases}

        # Pass 1: Exact match FIRST (case-insensitive)
        for tag in generative_tags:
            tag_lower = tag.lower()
            if tag_lower == pref_lower or tag_lower.startswith(pref_lower + ":") or pref_lower.startswith(tag_lower + ":"):
                return tag

        # Pass 2: Alias resolution for Gemma-4-12B-OBLITERATED and abliterated models
        if pref_lower in obliterated_aliases or pref_lower in obliterated_bases:
            gemma_abl = [
                t for t in generative_tags
                if ("obliterat" in t.lower() or "abliterat" in t.lower()) and "gemma" in t.lower()
            ]
            if gemma_abl:
                return gemma_abl[0]
            for tag in generative_tags:
                tag_lower = tag.lower()
                if "obliterat" in tag_lower or "abliterat" in tag_lower:
                    return tag

        # Pass 3: Base family match (case-insensitive)
        clean_pref = pref_lower.split(":")[0]
        if clean_pref:
            for tag in generative_tags:
                tag_lower = tag.lower()
                if clean_pref == tag_lower.split(":")[0] or clean_pref in tag_lower:
                    if free_ram < 24.0 and any(h in tag_lower for h in ("26b", "27b", "30b", "32b", "70b", "72b", "strix-deepseek", "glm-4.7-flash")):
                        continue
                    return tag

        # Pass 4: Preference hierarchy for zero-cost local research
        candidates = ["gemma2:2b", sized_qwen, "gemma2:9b", "qwen2.5:7b", "qwen2.5:3b", "qwen2.5:1.5b", "deepseek-r1:1.5b"]
        for cand in candidates:
            cand_base = cand.split(":")[0]
            for tag in generative_tags:
                tag_lower = tag.lower()
                if cand == tag_lower or cand_base in tag_lower:
                    if free_ram < 24.0 and any(h in tag_lower for h in ("26b", "27b", "30b", "32b", "70b", "72b", "strix-deepseek")):
                        continue
                    return tag

        return generative_tags[0]

    def generate_json(
        self,
        system_instruction: str,
        user_prompt: str,
        schema_hint: Optional[str] = None,
        num_predict: int = 160,
    ) -> List[Dict[str, Any]]:
        """
        Executes structured JSON generation using configured paid models (when `.env.local`
        defines paid providers) or local Ollama model(s) otherwise.
        """
        if not getattr(self, "using_ollama", True) and getattr(self, "paid_client", None) is not None:
            if self.use_fusion and len(self.available_tags) > 1:
                res = self._run_paid_panel_fusion(
                    system_instruction,
                    user_prompt,
                    schema_hint=schema_hint,
                    num_predict=num_predict,
                )
                if res:
                    return res
            return self._query_paid_model(
                self.active_model,
                system_instruction,
                user_prompt,
                schema_hint=schema_hint,
                num_predict=num_predict,
            )

        if getattr(self, "use_modelfusion_server", False):
            if getattr(self, "modelfusion_server_ready", False) or self._probe_modelfusion_server():
                self.modelfusion_server_ready = True
                mf_res = self._query_modelfusion_server(
                    system_instruction,
                    user_prompt,
                    schema_hint=schema_hint,
                    num_predict=num_predict,
                )
                if mf_res:
                    return mf_res

        if not self.available_tags:
            self.available_tags = self._fetch_available_tags()

        if self.use_fusion:
            res = self._run_panel_fusion(
                system_instruction,
                user_prompt,
                schema_hint=schema_hint,
                num_predict=num_predict,
            )
            if res:
                return res

        result = self._query_ollama(
            self.active_model,
            system_instruction,
            user_prompt,
            schema_hint=schema_hint,
            num_predict=num_predict,
        )
        if result:
            return result

        return []

    def _query_paid_model(
        self,
        model: str,
        system_instruction: str,
        user_prompt: str,
        schema_hint: Optional[str] = None,
        num_predict: int = 160,
    ) -> List[Dict[str, Any]]:
        paid_client = getattr(self, "paid_client", None)
        if paid_client is None:
            return []
        expected_schema = schema_hint or '{"probes": [{"rationale": "...", "raw_request": "...", "is_clean": false}]}'
        full_user = (
            f"{user_prompt}\n\n"
            f"CRITICAL: Output ONLY valid JSON matching schema: {expected_schema}."
        )
        raw_text = paid_client.generate(
            system_prompt=system_instruction,
            user_prompt=full_user,
            model=model,
            max_tokens=max(int(num_predict), 256),
            temperature=0.3,
            expect_json=True,
        )
        if not raw_text or self._is_refusal(raw_text):
            return []
        items = self._parse_json_array(raw_text, unwrap_lists=(schema_hint is None))
        return [
            it for it in items
            if isinstance(it, dict) and not self._is_refusal(json.dumps(it, sort_keys=True))
        ]

    def _run_paid_panel_fusion(
        self,
        system_instruction: str,
        user_prompt: str,
        schema_hint: Optional[str] = None,
        num_predict: int = 160,
    ) -> List[Dict[str, Any]]:
        panel = list(getattr(self, "available_tags", None) or [self.active_model])
        logger.info("[ModelFusion] Executing Paid API panel fusion across: %s", " + ".join(panel))
        all_probes: List[Dict[str, Any]] = []
        seen_requests = set()
        for model in panel:
            probes = self._query_paid_model(
                model,
                system_instruction,
                user_prompt,
                schema_hint=schema_hint,
                num_predict=num_predict,
            )
            for p in probes:
                if not isinstance(p, dict):
                    continue
                if schema_hint is not None:
                    serialized = json.dumps(p, sort_keys=True)
                    if self._is_refusal(serialized):
                        continue
                    p["fused_model"] = model
                    all_probes.append(p)
                    continue
                raw_val = p.get("raw_request", "")
                if isinstance(raw_val, dict):
                    raw_val = raw_val.get("raw_request", raw_val.get("request", ""))
                raw_req = str(raw_val).strip()
                rat = str(p.get("rationale", "")).strip()
                if self._is_refusal(raw_req) or self._is_refusal(rat):
                    continue
                if raw_req and raw_req not in seen_requests:
                    seen_requests.add(raw_req)
                    p["raw_request"] = raw_req
                    p["fused_model"] = model
                    all_probes.append(p)
        return all_probes

    def _query_ollama(
        self,
        model: str,
        system_instruction: str,
        user_prompt: str,
        schema_hint: Optional[str] = None,
        num_predict: int = 160,
    ) -> List[Dict[str, Any]]:
        if not getattr(self, "using_ollama", True) and getattr(self, "paid_client", None) is not None:
            return self._query_paid_model(
                model,
                system_instruction,
                user_prompt,
                schema_hint=schema_hint,
                num_predict=num_predict,
            )
        if not self.available_tags:
            self.available_tags = self._fetch_available_tags()
        client_is_mocked = (
            "mock" in type(self.client).__name__.lower()
            or "mock" in type(getattr(self.client, "post", None)).__name__.lower()
        )
        if os.environ.get("RFCHUNT_OFFLINE") == "1" and not client_is_mocked:
            return []
        if not self.available_tags and "PYTEST_CURRENT_TEST" in os.environ and not client_is_mocked:
            return []

        generative_tags = [t for t in self.available_tags if not self._is_embedding_model(t)]
        target_model = model
        if not client_is_mocked and target_model not in generative_tags:
            if OllamaLifecycleManager.ensure_model_installed(target_model, endpoint=self.endpoint):
                self.available_tags = self._fetch_available_tags()
                generative_tags = [t for t in self.available_tags if not self._is_embedding_model(t)]
            else:
                OllamaLifecycleManager.trigger_background_pull(target_model, endpoint=self.endpoint)
            if generative_tags and target_model not in generative_tags:
                target_model = self._resolve_model(target_model)

        expected_schema = schema_hint or '{"probes": [{"rationale": "...", "raw_request": "...", "is_clean": false}]}'
        full_prompt = (
            f"{user_prompt}\n\n"
            f"CRITICAL: Output ONLY valid JSON matching schema: {expected_schema}."
        )

        is_r1 = "deepseek-r1" in target_model.lower()
        effective_predict = max(int(num_predict), 384) if is_r1 else int(num_predict)
        messages: List[Dict[str, str]] = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": full_prompt})
        payload: Dict[str, Any] = {
            "model": target_model,
            "messages": messages,
            "stream": False,
            "keep_alive": "60m",
            "options": {
                "temperature": 0.15 if schema_hint is not None else 0.4,
                "repeat_penalty": 1.15,
                "num_predict": effective_predict,
            },
        }
        if not is_r1:
            payload["format"] = "json"

        allowed_files = extract_file_paths(user_prompt)
        try:
            resp = self.client.post(
                f"{self.endpoint}/api/chat",
                json=payload,
                timeout=httpx.Timeout(self.timeout, connect=10.0),
            )
            if resp.status_code == 200:
                data = resp.json()
                msg = data.get("message") if isinstance(data, dict) else None
                msg_content = str(msg.get("content") or "").strip() if isinstance(msg, dict) else ""
                raw_text = msg_content or str((data.get("response") if isinstance(data, dict) else "") or "").strip()
                if self._is_refusal(raw_text):
                    return []
                if getattr(self, "enable_anti_junk_guard", True):
                    verdict = validate_abliterated_output(
                        raw_text,
                        allowed_file_paths=allowed_files if schema_hint is not None else None,
                        require_json=False,
                    )
                    if not verdict["accepted"]:
                        logger.info(
                            "[ModelFusion] Anti-junk guard filtered response from %s (%s)",
                            target_model,
                            verdict["rejection_reasons"],
                        )
                        return []
                    raw_text = verdict["cleaned_text"]
                items = self._parse_json_array(raw_text, unwrap_lists=(schema_hint is None))
                return [
                    it for it in items
                    if isinstance(it, dict) and not self._is_refusal(json.dumps(it, sort_keys=True))
                ]
        except Exception as e:
            logger.warning("Ollama query failed on %s: %s", target_model, e)
        return []

    def _run_panel_fusion(
        self,
        system_instruction: str,
        user_prompt: str,
        schema_hint: Optional[str] = None,
        num_predict: int = 160,
    ) -> List[Dict[str, Any]]:
        """
        ModelFusion Panel: Queries a fusion of Google Gemma (protocol state machine specialist),
        Cisco Foundation-Sec (boundary specialist), and GLM / DeepSeek-R1 (reasoning specialist).
        """
        if not self.available_tags:
            self.available_tags = self._fetch_available_tags()
        generative_tags = [t for t in self.available_tags if not self._is_embedding_model(t)]
        if not generative_tags or os.environ.get("RFCHUNT_OFFLINE") == "1":
            return []

        abliterated_candidates = [
            t for t in generative_tags
            if ("abliterat" in t.lower() or "obliterat" in t.lower())
            and (self.free_ram_gb >= 24.0 or not any(tag in t.lower() for tag in ("70b", "72b", "755b")))
        ]

        abliterated_gemma = [t for t in abliterated_candidates if "gemma" in t.lower()]
        abliterated_sec = [t for t in abliterated_candidates if any(k in t.lower() for k in ("foundation-sec", "cisco"))]
        abliterated_glm = [t for t in abliterated_candidates if "glm" in t.lower()]
        abliterated_r1 = [t for t in abliterated_candidates if "deepseek-r1" in t.lower()]
        installed_glm = [t for t in generative_tags if "glm" in t.lower()]

        active_is_abliterated = any(kw in self.active_model.lower() for kw in ("obliterat", "abliterat")) and self.active_model in generative_tags
        pref_is_gemma4 = any(kw in self.active_model.lower() for kw in ("gemma4", "gemma-4")) and self.active_model in generative_tags

        if active_is_abliterated or pref_is_gemma4:
            gemma_model = self.active_model
        elif abliterated_gemma:
            gemma_model = abliterated_gemma[0]
        elif abliterated_candidates and self.preferred_model in ("auto", "gemma2:2b", "gemma-4-12b-obliterated", "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"):
            gemma_model = abliterated_candidates[0]
        else:
            gemma_model = self._resolve_model("gemma2:2b")

        if getattr(self, "sec_model", None):
            if str(self.sec_model).lower() == "fenkohq/foundation-sec-8b:latest" and abliterated_sec:
                sec_model = abliterated_sec[0]
            else:
                sec_model = self._resolve_model(str(self.sec_model))
        else:
            if abliterated_sec and abliterated_sec[0] != gemma_model:
                sec_model = abliterated_sec[0]
            elif not active_is_abliterated and abliterated_candidates and abliterated_candidates[0] != gemma_model:
                sec_model = abliterated_candidates[0]
            else:
                sec_model = None
                for tag in ["huihui_ai/foundation-sec-abliterated:8b", "fenkohq/foundation-sec-8b:latest", self.sized_qwen, "qwen2.5:7b", "qwen2.5:3b", "qwen2.5:1.5b", "deepseek-r1:1.5b"]:
                    matched = [t for t in generative_tags if tag == t or tag.split(":")[0] in t]
                    if matched:
                        cand_tag = matched[0]
                        if self.free_ram_gb < 24.0 and any(h in cand_tag.lower() for h in ("26b", "27b", "30b", "32b", "70b", "72b", "strix-deepseek")):
                            continue
                        sec_model = cand_tag
                        break
                if not sec_model:
                    sec_model = generative_tags[0]

        glm_model = None
        if abliterated_glm:
            glm_model = abliterated_glm[0]
        elif abliterated_r1:
            glm_model = abliterated_r1[0]
        elif installed_glm:
            for tag in ["glm4:9b", "glm-4.7-flash:latest", *installed_glm]:
                matched = [t for t in generative_tags if tag == t or tag.split(":")[0] in t]
                if matched:
                    cand_tag = matched[0]
                    if self.free_ram_gb < 20.0 and any(h in cand_tag.lower() for h in ("26b", "32b", "70b", "glm-4.7-flash")):
                        continue
                    glm_model = cand_tag
                    break

        fusion_panel: List[str] = []
        if gemma_model:
            fusion_panel.append(gemma_model)
        if sec_model and sec_model not in fusion_panel:
            fusion_panel.append(sec_model)
        if glm_model and glm_model not in fusion_panel:
            fusion_panel.append(glm_model)

        if not fusion_panel:
            fusion_panel = [self.active_model]

        logger.info("[ModelFusion] Executing panel fusion across: %s", " + ".join(fusion_panel))

        all_probes: List[Dict[str, Any]] = []
        seen_requests = set()

        for model in fusion_panel:
            probes = self._query_ollama(
                model,
                system_instruction,
                user_prompt,
                schema_hint=schema_hint,
                num_predict=num_predict,
            )
            for p in probes:
                if not isinstance(p, dict):
                    continue
                if schema_hint is not None:
                    serialized = json.dumps(p, sort_keys=True)
                    if self._is_refusal(serialized):
                        logger.info("[ModelFusion] Model %s produced refusal; dropping candidate.", model)
                        continue
                    p["fused_model"] = model
                    all_probes.append(p)
                    continue

                raw_val = p.get("raw_request", "")
                if isinstance(raw_val, dict):
                    raw_val = raw_val.get("raw_request", raw_val.get("request", ""))
                raw_req = str(raw_val).strip()
                rat = str(p.get("rationale", "")).strip()

                if self._is_refusal(raw_req) or self._is_refusal(rat):
                    logger.info("[ModelFusion] Model %s produced refusal; dropping probe.", model)
                    continue

                if raw_req and raw_req not in seen_requests:
                    seen_requests.add(raw_req)
                    p["raw_request"] = raw_req
                    p["fused_model"] = model
                    all_probes.append(p)

        if not all_probes and abliterated_candidates:
            abl_tag = abliterated_candidates[0]
            if abl_tag not in fusion_panel:
                logger.info("[ModelFusion] Panel produced 0 items; rescuing with abliterated model %s", abl_tag)
                abl_probes = self._query_ollama(
                    abl_tag,
                    system_instruction,
                    user_prompt,
                    schema_hint=schema_hint,
                    num_predict=num_predict,
                )
                for p in abl_probes:
                    if not isinstance(p, dict):
                        continue
                    serialized = json.dumps(p, sort_keys=True)
                    if self._is_refusal(serialized):
                        continue
                    if schema_hint is None and not str(p.get("raw_request", "")).strip():
                        continue
                    p["fused_model"] = f"{abl_tag} [AbliteratedRescue]"
                    all_probes.append(p)

        return all_probes

    def _parse_json_array(self, text: str, unwrap_lists: bool = True) -> List[Dict[str, Any]]:
        """Robust parser for JSON objects/arrays in LLM completions."""
        if not text:
            return []

        cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        if "</think>" in cleaned:
            cleaned = cleaned.split("</think>")[-1].strip()
        if "<think>" in cleaned:
            cleaned = cleaned.split("<think>")[0].strip()

        if "```json" in cleaned:
            cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0]
        elif "```" in cleaned:
            cleaned = cleaned.split("```", 1)[1].split("```", 1)[0]

        cleaned = cleaned.strip()

        def _clean_list(raw_list: list) -> List[Dict[str, Any]]:
            res = []
            for item in raw_list:
                if isinstance(item, dict):
                    res.append(item)
                elif isinstance(item, str) and item.strip() and unwrap_lists:
                    res.append({"rationale": item.strip(), "raw_request": "", "is_clean": False})
            return res

        def _normalize(parsed: Any) -> List[Dict[str, Any]]:
            if isinstance(parsed, list):
                return _clean_list(parsed)
            if isinstance(parsed, dict):
                if not unwrap_lists:
                    return [parsed]
                for k in ("suggested_probes", "probes", "items", "candidates", "proposals", "requests"):
                    if k in parsed and isinstance(parsed[k], list):
                        return _clean_list(parsed[k])
                return [parsed]
            return []

        try:
            return _normalize(json.loads(cleaned))
        except json.JSONDecodeError:
            pass

        decoder = json.JSONDecoder()
        for idx, ch in enumerate(cleaned):
            if ch in ("{", "["):
                try:
                    raw_parsed, _ = decoder.raw_decode(cleaned[idx:])
                    res = _normalize(raw_parsed)
                    if res:
                        return res
                except Exception:
                    continue

        return []
