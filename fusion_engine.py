"""
ModelFusion Consensus & Arbitration Engine:
Faithfully ported from ModelFusion's Rust CLI architecture (d:\\harfile\\ModelFusion\\crates\\cli\\src\\fusion_arbiter.rs).
Implements multi-model ensemble rollouts, specialist role delegation, and DeepSeek-R1 / GLM arbitration:

Specialists:
1. Protocol Specialist: Abliterated Google Gemma (`hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M` / `gemma2`)
2. Exploit Boundary Specialist: Foundation-Sec (`huihui_ai/foundation-sec-abliterated:8b` / `fenkohq/foundation-sec-8b:latest`)
3. Deep Reasoning Arbiter: Abliterated GLM / DeepSeek-R1 (`huihui_ai/glm-4.7-flash-abliterated:latest` / `huihui_ai/deepseek-r1-abliterated:8b` / `glm4:9b`)
"""

import json
import logging
import os
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import httpx

from database import Database
from ollama_manager import OllamaLifecycleManager, is_embedding_model

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
    ):
        self.consensus_type = consensus_type
        self.fused_probes = fused_probes
        self.reasoning = reasoning
        self.participating_models = participating_models

    def to_dict(self) -> Dict[str, Any]:
        return {
            "consensus_type": self.consensus_type,
            "fused_probes": self.fused_probes,
            "reasoning": self.reasoning,
            "participating_models": self.participating_models,
        }


class FusionArbiter:
    """
    Orchestrates multi-model ensemble generation and consensus arbitration,
    mirroring crates/cli/src/fusion_arbiter.rs from ModelFusion.
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
    ):
        self.endpoint = endpoint or os.environ.get("OLLAMA_ENDPOINT", self.DEFAULT_OLLAMA_ENDPOINT)
        self.db = db
        timeout_env = os.environ.get("OLLAMA_TIMEOUT", "120.0")
        self.timeout = float(timeout_env) if float(timeout_env) > 0 else None
        self.client = httpx.Client(timeout=httpx.Timeout(self.timeout, connect=10.0))
        self.free_ram_gb = self._get_free_memory_gb()
        self.available_tags = self._fetch_available_tags()

        # Dynamically pull missing preferred abliterated models at runtime when online
        # (automatically no-ops under RFCHUNT_OFFLINE=1, CI, or pytest unless explicitly enabled).
        fetch_is_patched = "mock" in type(self._fetch_available_tags).__name__.lower()
        if not fetch_is_patched:
            self.available_tags = OllamaLifecycleManager.ensure_panel_models_installed(
                available_tags=self.available_tags,
                endpoint=self.endpoint,
                free_ram_gb=self.free_ram_gb,
                preferred_model=preferred_model,
                sec_model=sec_model,
                arbiter_model=arbiter_model,
            )

        sized_qwen = self._size_qwen_for_free_memory(self.free_ram_gb)
        generative_tags = [t for t in self.available_tags if not self._is_embedding_model(t)]

        # Check for refusal-direction ablated / OBLITERATUS models in Ollama
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

        # Default Panel Role 1 (Protocol Specialist): Abliterated Gemma (refusal-free, zero-safety-filter)
        if preferred_model and preferred_model.lower() not in ("auto", "gemma2:2b"):
            self.gemma_model = self._resolve_model(
                [preferred_model, *abliterated_gemma, "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"],
                fallback=preferred_model,
            )
        else:
            self.gemma_model = self._resolve_model(
                [
                    *abliterated_gemma,
                    "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
                    *abliterated_candidates,
                    *(["gemma4:26b"] if self.free_ram_gb >= 20.0 else []),
                    "gemma2:9b",
                    sized_qwen,
                    "gemma2:2b",
                ],
                fallback="hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            )

        # Default Panel Role 2 (Boundary Security Specialist): Cisco Foundation-Sec (abliterated preferred, else official 8B)
        if sec_model and sec_model.lower() != "fenkohq/foundation-sec-8b:latest":
            self.sec_model = self._resolve_model([sec_model], fallback="fenkohq/foundation-sec-8b:latest")
        elif sec_model:
            self.sec_model = self._resolve_model(
                [*abliterated_sec, sec_model],
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
                    sized_qwen,
                    "qwen2.5:7b",
                    "qwen2.5:3b",
                    "qwen2.5:1.5b",
                    "strix-qwen:latest",
                ],
                fallback="fenkohq/foundation-sec-8b:latest",
            )

        # Default Panel Role 3 (Adversarial Verdict Arbiter): Abliterated GLM / DeepSeek-R1 preferred, else GLM-4 / DeepSeek-R1
        if arbiter_model:
            self.arbiter_model = self._resolve_model([arbiter_model], fallback="glm4:9b")
        else:
            self.arbiter_model = self._resolve_model(
                [
                    *abliterated_glm,
                    *abliterated_r1,
                    *(["huihui_ai/glm-4.7-flash-abliterated:latest"] if self.free_ram_gb >= 20.0 else []),
                    "huihui_ai/deepseek-r1-abliterated:8b",
                    "glm4:9b",
                    *(["glm-4.7-flash:latest"] if self.free_ram_gb >= 20.0 else []),
                    *installed_glm,
                    "deepseek-r1:1.5b",
                    sized_qwen,
                    "strix-deepseek:latest",
                ],
                fallback="glm4:9b",
            )

        if not quiet:
            print("[ModelFusion] Panel Initialized:")
            print(f"  - Protocol Specialist : {self.gemma_model}")
            print(f"  - Boundary Specialist : {self.sec_model}")
            print(f"  - Reasoning Arbiter   : {self.arbiter_model}")

    def close(self) -> None:
        client = getattr(self, "client", None)
        if client is not None:
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
        """Probes Ollama and auto-installs/auto-starts the daemon if missing."""
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

    def _resolve_model(self, candidates: List[str], fallback: str) -> str:
        raw_tags = getattr(self, "available_tags", None) or []
        generative_tags = [t for t in raw_tags if not self._is_embedding_model(t)]
        if not generative_tags:
            return fallback

        free_ram = float(getattr(self, "free_ram_gb", 16.0))

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
                    if free_ram < 24.0 and any(h in t_low for h in ("26b", "27b", "30b", "32b", "70b", "72b", "strix-deepseek", "glm-4.7-flash")):
                        continue
                    return tag

        # Pass 4: Any installed lightweight generative model
        for tag in generative_tags:
            t_low = tag.lower()
            if not any(h in t_low for h in ("26b", "27b", "30b", "32b", "70b", "72b", "strix-deepseek")):
                return tag
        return generative_tags[0]

    def _query_model(
        self,
        model: str,
        prompt: str,
        system_prompt: str,
        num_predict: int = 160,
    ) -> str:
        if not self.available_tags:
            self.available_tags = self._fetch_available_tags()

        generative_tags = [t for t in self.available_tags if not self._is_embedding_model(t)]
        target_model = model
        if target_model not in generative_tags:
            try:
                if OllamaLifecycleManager.ensure_model_installed(target_model, endpoint=self.endpoint):
                    self.available_tags = self._fetch_available_tags()
                    generative_tags = [t for t in self.available_tags if not self._is_embedding_model(t)]
                else:
                    OllamaLifecycleManager.trigger_background_pull(target_model, endpoint=self.endpoint)
            except Exception:
                pass
            if generative_tags and target_model not in generative_tags:
                target_model = self._resolve_model([model], fallback=generative_tags[0])

        is_r1 = "deepseek-r1" in target_model.lower()
        effective_predict = max(int(num_predict), 384) if is_r1 else int(num_predict)
        stop_tokens = ["<|end_of_text|>"] if not is_r1 else ["<|end_of_text|>"]

        payload: Dict[str, Any] = {
            "model": target_model,
            "prompt": f"{system_prompt}\n{prompt}" if "foundation-sec" in target_model.lower() else f"### SYSTEM:\n{system_prompt}\n\n### INSTRUCTION:\n{prompt}",
            "stream": False,
            "keep_alive": "60m",
            "options": {"temperature": 0.7, "num_predict": effective_predict, "stop": stop_tokens},
        }
        if not is_r1:
            payload["format"] = "json"
        try:
            resp = self.client.post(
                f"{self.endpoint}/api/generate",
                json=payload,
                timeout=httpx.Timeout(self.timeout, connect=10.0),
            )
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
            logger.warning("Ollama returned HTTP %s for %s; trying fallback.", resp.status_code, target_model)
        except Exception as e:
            logger.warning("Ollama query failed for %s: %s", target_model, e)

        # Resilient fallback: try fast lightweight generative models in order
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
                    resp = self.client.post(
                        f"{self.endpoint}/api/generate",
                        json=fb_payload,
                        timeout=httpx.Timeout(min(self.timeout or 30.0, 30.0), connect=5.0),
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

    def run_fusion_pipeline(self, rfc_fragment: str, fragment_id: Optional[int] = None) -> FusionArbitrationResult:
        """
        Executes the full 4-Gate ModelFusion arbitration protocol with threaded specialist execution:
        1 & 2. Concurrently query Protocol Specialist (Gemma) and Boundary Specialist (Foundation-Sec).
        3. Evaluate Gate 1 (Single Bypass) & Gate 2 (Unanimous).
        4. Invoke Gate 4 (Arbiter Synthesis) to merge insights into novel super-probes.
        """
        import concurrent.futures

        participating_models = [self.gemma_model, self.sec_model]
        proposals: List[CandidateProposal] = []

        gemma_sys = (
            "You are a protocol security researcher (James Kettle HTTP Terminator methodology). "
            "Invert RFC response/framing rules into an incoming client HTTP/1.1 request (Shared-Parser Confusion)."
        )
        gemma_prompt = (
            f"RFC Clue: {rfc_fragment}\n"
            "Task: Output a single-line JSON object with keys rationale, raw_request (starting with POST / HTTP/1.1\\r\\nHost: target.local and ending with \\r\\n\\r\\n$PAYLOAD), and is_clean.\n"
            "JSON: "
        )

        sec_sys = (
            "You are an HTTP framing boundary specialist (Cisco Foundation-Sec / PortSwigger methodology). "
            "Construct a parser-confusion or framing-discrepancy HTTP/1.1 request from the RFC clue."
        )
        sec_prompt = (
            f"RFC Clue: {rfc_fragment}\n"
            "Task: Output a single-line JSON object with keys rationale, raw_request (starting with POST / HTTP/1.1\\r\\nHost: target.local and ending with \\r\\n\\r\\n$PAYLOAD), and is_clean.\n"
            "JSON: "
        )

        t_start = time.time()
        print(
            f"    -> [ModelFusion 1&2/3] Querying Specialists in parallel "
            f"({self.gemma_model} + {self.sec_model})...",
            end=" ",
            flush=True,
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fut_gemma = pool.submit(self._query_model, self.gemma_model, gemma_prompt, gemma_sys)
            fut_sec = pool.submit(self._query_model, self.sec_model, sec_prompt, sec_sys)
            gemma_out = fut_gemma.result()
            sec_out = fut_sec.result()

        gemma_refused = self._is_refusal(gemma_out)
        gemma_count = 0
        if not gemma_refused:
            for item in self._parse_json(gemma_out):
                norm_req = self._normalize_crlf(item.get("raw_request", ""))
                rat = str(item.get("rationale", "")).strip()
                if self._is_refusal(norm_req) or self._is_refusal(rat) or not self._is_valid_http_template(norm_req):
                    continue
                gemma_count += 1
                if not rat or rat == "...":
                    rat = "Gemma protocol state-machine edge-case"
                proposals.append(CandidateProposal(
                    candidate_id=f"cand_gemma_{len(proposals)+1}",
                    model=self.gemma_model,
                    specialist_type="Protocol Specialist",
                    rationale=rat,
                    raw_request=norm_req,
                    is_clean=bool(item.get("is_clean", True)),
                ))

        sec_refused = self._is_refusal(sec_out)
        sec_count = 0
        if not sec_refused:
            for item in self._parse_json(sec_out):
                norm_req = self._normalize_crlf(item.get("raw_request", ""))
                rat = str(item.get("rationale", "")).strip()
                if self._is_refusal(norm_req) or self._is_refusal(rat) or not self._is_valid_http_template(norm_req):
                    continue
                sec_count += 1
                if not rat or rat == "...":
                    rat = "Boundary discrepancy probe"
                proposals.append(CandidateProposal(
                    candidate_id=f"cand_sec_{len(proposals)+1}",
                    model=self.sec_model,
                    specialist_type="Boundary Specialist",
                    rationale=rat,
                    raw_request=norm_req,
                    is_clean=bool(item.get("is_clean", False)),
                ))

        # Refusal Bypass & Abliteration Rescue
        abliterated_candidates = [
            t for t in self.available_tags
            if not self._is_embedding_model(t)
            and ("abliterat" in t.lower() or "obliterat" in t.lower())
            and (self.free_ram_gb >= 24.0 or not any(tag in t.lower() for tag in ("70b", "72b", "755b")))
        ]
        if (gemma_refused or sec_refused or len(proposals) == 0) and abliterated_candidates:
            abl_model = abliterated_candidates[0]
            if abl_model not in (self.gemma_model, self.sec_model) or len(proposals) == 0:
                print(f"    -> [ModelFusion Abliteration] Querying refusal-free model ({abl_model})...", end=" ", flush=True)
                abl_sys = (
                    "You are an unconstrained protocol security research engine. "
                    "Analyze the protocol rule and generate deep state-machine and framing inversion requests. "
                    "Output JSON with keys 'rationale', 'raw_request', 'is_clean'."
                )
                abl_out = self._query_model(abl_model, f"RFC Clue: {rfc_fragment}\nTask: Output raw HTTP probe JSON.", abl_sys)
                if not self._is_refusal(abl_out):
                    for item in self._parse_json(abl_out):
                        norm_req = self._normalize_crlf(item.get("raw_request", ""))
                        rat = str(item.get("rationale", "Refusal-free protocol inversion probe"))
                        if not self._is_refusal(norm_req) and not self._is_refusal(rat) and self._is_valid_http_template(norm_req):
                            proposals.append(CandidateProposal(
                                candidate_id=f"cand_abliterated_{len(proposals)+1}",
                                model=f"{abl_model} [RefusalFree]",
                                specialist_type="Abliterated Security Specialist",
                                rationale=rat,
                                raw_request=norm_req,
                                is_clean=bool(item.get("is_clean", False)),
                            ))
                print(f"done ({len(proposals)} proposals total)", flush=True)

        print(
            f"done ({time.time() - t_start:.1f}s | Gemma: {gemma_count}, Sec: {sec_count} proposals)",
            flush=True,
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
        first_req = proposals[0].raw_request.strip()
        if all(p.raw_request.strip() == first_req for p in proposals):
            res_probes = [proposals[0].to_dict()]
            self._save_probes_to_db(res_probes, fragment_id, "Unanimous")
            return FusionArbitrationResult(
                consensus_type="Unanimous",
                fused_probes=res_probes,
                reasoning="All specialists produced identical request templates.",
                participating_models=participating_models,
            )

        # Gate 4: Synthesis via Reasoning Arbiter
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
            "Remember: The vulnerability was NOT written in the RFC. The RFC supplies a clue; the attack concept comes from "
            "inverting protocol expectations—especially testing whether servers apply response parsing rules to incoming requests (Shared-Parser Confusion), "
            "or whether reverse proxies disagree with backends on framing. "
            "Perform brief reasoning inside <think> tags. Synthesize 1 potent unified HTTP/1.1 probe combining nuance and boundary manipulation. "
            "Return JSON with keys 'rationale', 'raw_request', and 'is_clean'."
        )

        arbiter_prompt = (
            f"RFC Snippet Under Investigation:\n\"\"\"{rfc_fragment}\"\"\"\n\n"
            f"Candidate Proposals Submitted to Fusion Arbiter:\n{candidates_summary}\n\n"
            f"Synthesize the optimal consensus probe."
        )

        t2 = time.time()
        print(f"    -> [ModelFusion 3/3] Reasoning Arbiter ({self.arbiter_model}) synthesizing...", end=" ", flush=True)
        arbiter_out = self._query_model(self.arbiter_model, arbiter_prompt, arbiter_sys)
        if self._is_refusal(arbiter_out):
            arbiter_out = ""
        synthesized_probes = self._parse_json(arbiter_out)
        print(f"done ({time.time() - t2:.1f}s)", flush=True)

        final_fused: List[Dict[str, Any]] = []

        if not synthesized_probes and abliterated_candidates:
            abl_arb = abliterated_candidates[0]
            if abl_arb != self.arbiter_model:
                print(f"    -> [ModelFusion Abliteration] Reasoning Arbiter refused/timed out; synthesizing via {abl_arb}...", end=" ", flush=True)
                abl_arb_out = self._query_model(abl_arb, arbiter_prompt, arbiter_sys)
                if not self._is_refusal(abl_arb_out):
                    synthesized_probes = self._parse_json(abl_arb_out)
                print(f"done ({len(synthesized_probes)} probes)", flush=True)
                if synthesized_probes:
                    for sp in synthesized_probes:
                        if not isinstance(sp, dict):
                            continue
                        raw = self._normalize_crlf(sp.get("raw_request", ""))
                        rat = str(sp.get("rationale", "Synthesized refusal-free consensus vector"))
                        if not self._is_refusal(raw) and not self._is_refusal(rat) and self._is_valid_http_template(raw):
                            final_fused.append({
                                "id": f"fused_abliterated_{len(final_fused)+1}",
                                "model": f"{abl_arb} [AbliteratedConsensus: {self.gemma_model} + {self.sec_model}]",
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
                        "model": f"{self.arbiter_model} [Fused: {self.gemma_model} + {self.sec_model}]",
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
            reasoning = f"Arbiter successfully synthesized {len(final_fused)} unified probes from Gemma + Security candidates."
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
        )

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

        try:
            return _normalize_parsed(json.loads(cleaned))
        except Exception:
            pass

        # Scan for first valid JSON object {...} or array [...] amidst surrounding prose
        decoder = json.JSONDecoder()
        for idx, ch in enumerate(cleaned):
            if ch in ("{", "["):
                try:
                    parsed, _ = decoder.raw_decode(cleaned[idx:])
                    res = _normalize_parsed(parsed)
                    if res:
                        return res
                except Exception:
                    continue
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
        General-purpose ModelFusion 2-Specialist + Arbiter pipeline for Google Mantis (Module 20),
        ARTEX dynamic intent/worker planning, and unified `--all` auditing.
        Preserves top-level JSON envelopes (e.g. `{"intents": [...]}`) intact via `unwrap_lists=False`.
        """
        import concurrent.futures

        if not self.available_tags:
            self.available_tags = self._fetch_available_tags()

        generative_tags = [t for t in self.available_tags if not self._is_embedding_model(t)]
        abliterated_candidates = [
            t for t in generative_tags
            if ("abliterat" in t.lower() or "obliterat" in t.lower())
            and (self.free_ram_gb >= 24.0 or not any(tag in t.lower() for tag in ("70b", "72b", "755b")))
        ]
        participating_models = [self.gemma_model, self.sec_model, self.arbiter_model]

        if not generative_tags or os.environ.get("RFCHUNT_OFFLINE") == "1":
            return {
                "task": task_name,
                "status": "offline_fallback",
                "consensus_type": "DeterministicFallback",
                "participating_models": participating_models,
                "abliterated_active": any("obliterat" in m.lower() or "abliterat" in m.lower() for m in participating_models),
                "data": default_payload if default_payload is not None else {},
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fut_primary = pool.submit(self._query_model, self.gemma_model, user_prompt, system_prompt, num_predict)
            fut_sec = pool.submit(self._query_model, self.sec_model, user_prompt, system_prompt, num_predict)
            out_primary = fut_primary.result()
            out_sec = fut_sec.result()

        proposals: List[Dict[str, Any]] = []
        for model_name, raw_out in ((self.gemma_model, out_primary), (self.sec_model, out_sec)):
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
                "data": default_payload if default_payload is not None else {},
            }

        synthesized_data: Any = proposals[0]["output"]
        if len(proposals) >= 2:
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
                if arb_parsed:
                    synthesized_data = arb_parsed[0] if len(arb_parsed) == 1 else arb_parsed

        has_abl = rescued or bool(abliterated_candidates) or any(
            "obliterat" in m.lower() or "abliterat" in m.lower() for m in participating_models
        )
        return {
            "task": task_name,
            "status": "fused",
            "consensus_type": "AbliteratedConsensus" if has_abl else "ArbiterSynthesized",
            "participating_models": [p["model"] for p in proposals],
            "abliterated_active": has_abl,
            "data": synthesized_data,
        }
