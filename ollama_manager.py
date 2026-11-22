"""
Ollama Lifecycle, Auto-Install, Auto-Start & Model Resilience Manager
=====================================================================
Ensures zero-crash local AI execution for RFC Hunt Swarm:
1. Fast 400ms health probe (`probe_ollama`) with busy-daemon fallback.
2. Auto-detects installed `ollama` binary across PATH and standard Windows/Unix locations.
3. Auto-installs Ollama if missing (via winget / official installer on Windows, install.sh on Unix)
   using strictly `shell=False` and process-scoped environment variables.
4. Auto-starts `ollama serve` in the background if the daemon is not running.
5. Dynamically pulls missing preferred abliterated specialist/arbiter models at runtime when online
   (`hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M`, `huihui_ai/foundation-sec-abliterated:8b`,
   `huihui_ai/glm-4.7-flash-abliterated:latest` / `huihui_ai/deepseek-r1-abliterated:8b`),
   and filters out embedding-only tags from generative model selection.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import httpx

logger = logging.getLogger("terminator.ollama")

HEALTH_PROBE_MAX_TIMEOUT_SEC: float = 0.4
CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

EMBEDDING_MODEL_MARKERS: Tuple[str, ...] = (
    "embed",
    "bge-",
    "bge:",
    "all-minilm",
    "paraphrase-",
    "e5-",
    "gte-",
    "jina-embeddings",
)


def is_embedding_model(tag: str) -> bool:
    """Returns True if an Ollama model tag is an embedding-only model rather than text-generative."""
    low = (tag or "").strip().lower()
    if not low:
        return False
    return any(marker in low for marker in EMBEDDING_MODEL_MARKERS)


def get_free_memory_gb() -> float:
    """
    Evaluates runtime FREE/AVAILABLE system RAM in GB (NEVER total physical RAM)
    across Windows, Linux, and macOS.
    """
    try:
        if os.name == "nt":
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
                return float(stat.ullAvailPhys) / (1024 ** 3)
        elif os.path.isfile("/proc/meminfo"):
            with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        kb = int(line.split()[1])
                        return float(kb) / (1024 ** 2)
    except Exception:
        pass

    try:
        import psutil  # type: ignore[import-untyped]

        return float(psutil.virtual_memory().available) / (1024 ** 3)
    except Exception:
        pass

    if sys.platform == "darwin" and not OllamaLifecycleManager._is_automated_or_offline_env():
        try:
            proc = subprocess.run(
                ["vm_stat"],
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                page_size = 4096
                m_ps = re.search(r"page size of (\d+) bytes", proc.stdout)
                if m_ps:
                    page_size = int(m_ps.group(1))
                free_pages = 0
                for key in ("Pages free", "Pages inactive", "Pages speculative"):
                    m_pg = re.search(rf"{key}:\s+(\d+)", proc.stdout)
                    if m_pg:
                        free_pages += int(m_pg.group(1))
                if free_pages > 0:
                    return float(free_pages * page_size) / (1024 ** 3)
        except Exception:
            pass
    return 8.0


def get_free_vram_mb(*, allow_in_tests: bool = False) -> float:
    """
    Evaluates runtime FREE/AVAILABLE GPU VRAM in MB (NEVER total VRAM) via `nvidia-smi`
    with a strict <=400ms timeout and zero subprocesses in offline/CI/test runs.
    """
    if OllamaLifecycleManager._is_automated_or_offline_env(allow_in_tests=allow_in_tests):
        return 0.0

    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi and os.name == "nt":
        sys_cand = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "nvidia-smi.exe"
        if sys_cand.is_file():
            nvidia_smi = str(sys_cand)
    if not nvidia_smi:
        return 0.0

    try:
        cf = CREATE_NO_WINDOW if (sys.platform == "win32" or os.name == "nt") else 0
        proc = subprocess.run(
            [nvidia_smi, "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC,
            check=False,
            creationflags=cf,
        )
        if proc.returncode == 0 and proc.stdout:
            free_vals: List[float] = []
            for raw_line in proc.stdout.splitlines():
                clean = raw_line.strip()
                if not clean:
                    continue
                try:
                    val = float(clean.split(",")[0].strip())
                    if val >= 0.0:
                        free_vals.append(val)
                except ValueError:
                    continue
            if free_vals:
                return max(free_vals)
    except Exception:
        pass
    return 0.0


def get_runtime_free_memory(*, allow_in_tests: bool = False) -> Tuple[float, float]:
    """Returns `(free_ram_gb, free_vram_mb)` strictly from runtime free/available memory."""
    return get_free_memory_gb(), get_free_vram_mb(allow_in_tests=allow_in_tests)


def size_qwen_for_free_memory(free_ram_gb: float, free_vram_mb: float = 0.0) -> str:
    """
    Sizes the base Qwen model strictly from runtime free/available memory
    (NEVER total physical RAM, NEVER appends `-coder` suffixes).
    """
    ram = max(0.0, float(free_ram_gb))
    vram = max(0.0, float(free_vram_mb))
    if ram >= 48.0 or vram >= 24576.0:
        return "qwen2.5:32b"
    if ram >= 24.0 or vram >= 14336.0:
        return "qwen2.5:14b"
    if ram >= 12.0 or vram >= 4608.0:
        return "qwen2.5:7b"
    if ram >= 6.0 or vram >= 2048.0:
        return "qwen2.5:3b"
    return "qwen2.5:1.5b"


def select_raptor_model_for_free_memory(
    free_ram_gb: Optional[float] = None,
    free_vram_mb: Optional[float] = None,
    *,
    available_tags: Optional[Iterable[str]] = None,
    allow_in_tests: bool = False,
) -> str:
    """
    Selects the best RAPTOR Ollama model strictly from runtime free RAM/VRAM.
    Uses Foundation-Sec-8B (abliterated preferred when installed) when >=8GB free RAM
    or >=6GB free VRAM is available; otherwise falls back to free-memory-sized `qwen2.5`.
    """
    eff_ram = get_free_memory_gb() if free_ram_gb is None else float(free_ram_gb)
    eff_vram = get_free_vram_mb(allow_in_tests=allow_in_tests) if free_vram_mb is None else float(free_vram_mb)
    sized_qwen = size_qwen_for_free_memory(eff_ram, eff_vram)
    if eff_ram >= 8.0 or eff_vram >= 6144.0:
        gen_tags = [t for t in (available_tags or ()) if t and not is_embedding_model(t)]
        for tag in gen_tags:
            tl = tag.lower()
            if ("abliterat" in tl or "obliterat" in tl) and ("foundation-sec" in tl or "cisco" in tl):
                return tag
        return "fenkohq/foundation-sec-8b:latest"
    return sized_qwen


class OllamaLifecycleManager:
    DEFAULT_ENDPOINT = "http://127.0.0.1:11434"
    _lock = threading.RLock()
    _cached_tags: List[str] = []
    _cached_by_endpoint: Dict[str, Tuple[float, List[str]]] = {}
    _last_probe_ts: float = 0.0
    _daemon_checked: bool = False
    _pulling_models: set = set()
    _failed_pulls: set = set()

    @staticmethod
    def is_embedding_model(tag: str) -> bool:
        return is_embedding_model(tag)

    @staticmethod
    def filter_generative_tags(tags: Iterable[str]) -> List[str]:
        """Filters out embedding-only tags so text generation never selects an embedding model."""
        return [t for t in tags if t and not is_embedding_model(t)]

    @classmethod
    def _is_automated_or_offline_env(cls, allow_in_tests: bool = False) -> bool:
        if os.environ.get("RFCHUNT_OFFLINE") == "1":
            return True
        if os.environ.get("RFCHUNT_AUTO_PULL_MODELS") == "0":
            return True
        if not allow_in_tests and (
            "PYTEST_CURRENT_TEST" in os.environ
            or "pytest" in sys.modules
            or bool(os.environ.get("CI"))
            or bool(os.environ.get("GITHUB_ACTIONS"))
        ):
            return True
        return False

    @classmethod
    def find_ollama_binary(cls) -> Optional[str]:
        """Locates the ollama executable in process PATH or standard installation directories."""
        found = shutil.which("ollama")
        if found:
            return found

        if os.name == "nt":
            local_app_data = os.environ.get("LOCALAPPDATA", "")
            program_files = os.environ.get("PROGRAMFILES", "C:\\Program Files")
            user_profile = os.environ.get("USERPROFILE", "")
            candidates = [
                Path(local_app_data) / "Programs" / "Ollama" / "ollama.exe",
                Path(program_files) / "Ollama" / "ollama.exe",
                Path(user_profile) / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe",
            ]
            for cand in candidates:
                if cand.is_file():
                    # Add to process-scoped PATH only (never touch registry/setx)
                    bin_dir = str(cand.parent)
                    current_path = os.environ.get("PATH", "")
                    if bin_dir not in current_path:
                        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{current_path}"
                    return str(cand)
        else:
            for unix_path in ("/usr/local/bin/ollama", "/usr/bin/ollama", "/opt/homebrew/bin/ollama"):
                if os.path.isfile(unix_path):
                    return unix_path
        return None

    @classmethod
    def _update_cache(cls, endpoint: str, models: List[str]) -> None:
        now = time.time()
        norm_ep = (endpoint or cls.DEFAULT_ENDPOINT).rstrip("/")
        with cls._lock:
            cls._cached_tags = list(models)
            cls._last_probe_ts = now
            cls._cached_by_endpoint[norm_ep] = (now, list(models))

    @classmethod
    def probe_ollama(cls, endpoint: str = DEFAULT_ENDPOINT, fast_timeout: float = 0.4) -> Optional[List[str]]:
        """
        Probes Ollama `/api/tags` with a strict <=400ms health probe timeout.
        On timeout while Ollama is busy or restarting, falls back immediately to
        cached endpoint tags rather than blocking the caller.
        """
        norm_ep = (endpoint or cls.DEFAULT_ENDPOINT).rstrip("/")
        probe_timeout = min(max(float(fast_timeout), 0.05), HEALTH_PROBE_MAX_TIMEOUT_SEC)
        try:
            resp = httpx.get(f"{norm_ep}/api/tags", timeout=probe_timeout)
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", []) if "name" in m]
                cls._update_cache(norm_ep, models)
                return models
        except httpx.TimeoutException:
            with cls._lock:
                cached = cls._cached_by_endpoint.get(norm_ep)
                if cached and cached[1]:
                    return list(cached[1])
                if cls._cached_tags:
                    return list(cls._cached_tags)
        except Exception:
            pass
        return None

    @classmethod
    def install_ollama_if_missing(cls, *, allow_in_tests: bool = False) -> Optional[str]:
        """
        Automatically installs Ollama if the binary is not present on the machine.
        Strictly uses `shell=False` and process-scoped environment variables.
        """
        existing = cls.find_ollama_binary()
        if existing:
            return existing

        if os.environ.get("RFCHUNT_AUTO_INSTALL_TOOLS") == "0" or cls._is_automated_or_offline_env(allow_in_tests=allow_in_tests):
            return None

        print("[*] [Ollama Auto-Setup] Ollama binary not found. Attempting automatic installation...", file=sys.stderr)
        if os.name == "nt":
            winget_bin = shutil.which("winget")
            if winget_bin:
                try:
                    print("[*] [Ollama Auto-Setup] Installing Ollama via winget...", file=sys.stderr)
                    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                    subprocess.run(
                        [
                            winget_bin,
                            "install",
                            "--id",
                            "Ollama.Ollama",
                            "-e",
                            "--silent",
                            "--accept-package-agreements",
                            "--accept-source-agreements",
                        ],
                        shell=False,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creation_flags,
                        timeout=180,
                        check=False,
                    )
                    installed = cls.find_ollama_binary()
                    if installed:
                        print(f"[+] [Ollama Auto-Setup] Ollama installed at {installed}", file=sys.stderr)
                        return installed
                except Exception as e:
                    logger.debug("winget install failed: %s", e)

            try:
                installer_path = Path(tempfile.gettempdir()) / "OllamaSetup.exe"
                if not installer_path.exists():
                    print("[*] [Ollama Auto-Setup] Downloading official OllamaSetup.exe...", file=sys.stderr)
                    with httpx.stream("GET", "https://ollama.com/download/OllamaSetup.exe", follow_redirects=True, timeout=60.0) as r:
                        if r.status_code == 200:
                            with open(installer_path, "wb") as f:
                                for chunk in r.iter_bytes():
                                    f.write(chunk)
                if installer_path.is_file():
                    print("[*] [Ollama Auto-Setup] Running silent installer OllamaSetup.exe /SILENT...", file=sys.stderr)
                    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                    subprocess.run(
                        [str(installer_path), "/SILENT"],
                        shell=False,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creation_flags,
                        timeout=180,
                        check=False,
                    )
                    installed = cls.find_ollama_binary()
                    if installed:
                        print(f"[+] [Ollama Auto-Setup] Ollama installed at {installed}", file=sys.stderr)
                        return installed
            except Exception as e:
                logger.warning("Automatic Ollama installer download failed: %s", e)
        else:
            sh_bin = shutil.which("sh")
            if sh_bin:
                try:
                    print("[*] [Ollama Auto-Setup] Downloading official install.sh...", file=sys.stderr)
                    resp = httpx.get("https://ollama.com/install.sh", follow_redirects=True, timeout=60.0)
                    if resp.status_code == 200 and resp.content:
                        subprocess.run(
                            [sh_bin],
                            shell=False,
                            input=resp.content,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=180,
                            check=False,
                        )
                        installed = cls.find_ollama_binary()
                        if installed:
                            return installed
                except Exception as e:
                    logger.warning("Unix Ollama install failed: %s", e)

        return cls.find_ollama_binary()

    @classmethod
    def ensure_ollama_ready(
        cls,
        endpoint: str = DEFAULT_ENDPOINT,
        auto_install: bool = True,
        *,
        allow_in_tests: bool = False,
    ) -> List[str]:
        """
        Ensures the Ollama daemon is installed, running, and returns available model tags.
        Uses endpoint-keyed in-process caching so repeated calls within 30s are instantaneous
        and enforces <=400ms health probes.
        """
        norm_ep = (endpoint or cls.DEFAULT_ENDPOINT).rstrip("/")
        with cls._lock:
            cached = cls._cached_by_endpoint.get(norm_ep)
            if cached and cached[1] and (time.time() - cached[0]) < 30.0:
                return list(cached[1])

            if os.environ.get("RFCHUNT_OFFLINE") == "1":
                return list(cached[1]) if cached else list(cls._cached_tags)

            tags = cls.probe_ollama(endpoint=norm_ep, fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC)
            if tags is not None:
                cls._daemon_checked = True
                return tags

            if cls._is_automated_or_offline_env(allow_in_tests=allow_in_tests):
                return list(cached[1]) if cached else list(cls._cached_tags)

            effective_auto_install = bool(auto_install) and (os.environ.get("RFCHUNT_AUTO_INSTALL_TOOLS", "1") != "0")
            ollama_bin = cls.find_ollama_binary()
            if not ollama_bin and effective_auto_install and not cls._daemon_checked:
                ollama_bin = cls.install_ollama_if_missing(allow_in_tests=allow_in_tests)

            cls._daemon_checked = True
            if not ollama_bin:
                return list(cached[1]) if cached else list(cls._cached_tags)

            print(f"[*] [Ollama Auto-Start] Starting local Ollama daemon ({ollama_bin} serve)...", file=sys.stderr)
            proc_env = os.environ.copy()
            proc_env.setdefault("OLLAMA_NUM_PARALLEL", "2")
            proc_env.setdefault("OLLAMA_MAX_LOADED_MODELS", "2")
            proc_env.setdefault("OLLAMA_KEEP_ALIVE", "60m")

            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            try:
                subprocess.Popen(
                    [ollama_bin, "serve"],
                    shell=False,
                    env=proc_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creation_flags,
                )
            except Exception as e:
                logger.warning("Failed to start ollama serve: %s", e)
                return list(cached[1]) if cached else list(cls._cached_tags)

            for _ in range(16):
                time.sleep(0.5)
                tags = cls.probe_ollama(endpoint=norm_ep, fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC)
                if tags is not None:
                    print(f"[+] [Ollama Auto-Start] Ollama daemon online ({len(tags)} models available).", file=sys.stderr)
                    return tags

            return list(cached[1]) if cached else list(cls._cached_tags)

    @classmethod
    def _pull_model_via_http(cls, model_name: str, endpoint: str, timeout_sec: int = 900) -> bool:
        """Pulls a model using Ollama's HTTP `/api/pull` endpoint (`shell=False`, zero CLI dependency)."""
        norm_ep = (endpoint or cls.DEFAULT_ENDPOINT).rstrip("/")
        try:
            with httpx.Client(timeout=httpx.Timeout(float(timeout_sec), connect=10.0)) as client:
                with client.stream("POST", f"{norm_ep}/api/pull", json={"name": model_name, "stream": True}) as resp:
                    if resp.status_code != 200:
                        return False
                    for line in resp.iter_lines():
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                        except Exception:
                            continue
                        if isinstance(evt, dict) and evt.get("error"):
                            logger.warning("Ollama HTTP pull error for %s: %s", model_name, evt.get("error"))
                            return False
                        if isinstance(evt, dict) and str(evt.get("status", "")).lower() == "success":
                            return True
            return True
        except Exception as exc:
            logger.debug("Ollama HTTP pull failed for %s: %s", model_name, exc)
            return False

    @classmethod
    def ensure_model_installed(
        cls,
        model_name: str,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout_sec: int = 900,
        allow_in_tests: bool = False,
    ) -> bool:
        """
        Synchronously pulls `model_name` if missing locally (via `ollama pull` with `shell=False`
        or Ollama HTTP `/api/pull`), refreshing cached tags upon completion.
        Memoizes failed pulls per process so unreachable models never stall repeatedly.
        """
        clean_name = (model_name or "").strip()
        if not clean_name or is_embedding_model(clean_name):
            return False
        if cls._is_automated_or_offline_env(allow_in_tests=allow_in_tests):
            return False

        norm_ep = (endpoint or cls.DEFAULT_ENDPOINT).rstrip("/")
        with cls._lock:
            cached = cls._cached_by_endpoint.get(norm_ep)
            known = list(cached[1]) if cached else list(cls._cached_tags)
            low_clean = clean_name.lower()
            if any(t.lower() == low_clean or t.lower().startswith(low_clean + ":") for t in known):
                return True
            if clean_name in cls._failed_pulls or clean_name in cls._pulling_models:
                return False
            cls._pulling_models.add(clean_name)

        print(
            f"[*] [Ollama Dynamic Install] Model '{clean_name}' is missing locally -- pulling dynamically...",
            file=sys.stderr,
            flush=True,
        )
        ok = False
        try:
            ollama_bin = cls.find_ollama_binary()
            if ollama_bin:
                creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
                try:
                    res = subprocess.run(
                        [ollama_bin, "pull", clean_name],
                        shell=False,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=timeout_sec,
                        check=False,
                        creationflags=creation_flags,
                    )
                    ok = res.returncode == 0
                except Exception as exc:
                    logger.debug("ollama CLI pull failed for %s: %s", clean_name, exc)
                    ok = False
            if not ok:
                ok = cls._pull_model_via_http(clean_name, endpoint=norm_ep, timeout_sec=timeout_sec)

            if ok:
                refreshed = cls.probe_ollama(endpoint=norm_ep, fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC) or []
                if any(t.lower() == clean_name.lower() or t.lower().startswith(clean_name.lower() + ":") for t in refreshed):
                    print(f"[+] [Ollama Dynamic Install] Successfully installed '{clean_name}'.", file=sys.stderr, flush=True)
                    return True
                # Even if tag normalized slightly (e.g. :latest appended), probe_ollama refreshed cache
                if refreshed:
                    print(f"[+] [Ollama Dynamic Install] Pull completed for '{clean_name}'.", file=sys.stderr, flush=True)
                    return True
            with cls._lock:
                cls._failed_pulls.add(clean_name)
            logger.warning("Dynamic pull did not succeed for %s; falling back to installed generative models.", clean_name)
            return False
        finally:
            with cls._lock:
                cls._pulling_models.discard(clean_name)

    @classmethod
    def ensure_panel_models_installed(
        cls,
        available_tags: List[str],
        endpoint: str = DEFAULT_ENDPOINT,
        free_ram_gb: Optional[float] = None,
        preferred_model: Optional[str] = None,
        sec_model: Optional[str] = None,
        arbiter_model: Optional[str] = None,
        allow_in_tests: bool = False,
        free_vram_mb: Optional[float] = None,
    ) -> List[str]:
        """
        Ensures the 3-specialist refusal-free ModelFusion panel models are dynamically pulled
        when missing on a live online machine, sized strictly from runtime free RAM/VRAM
        (skipped automatically in CI / pytest / offline).
        """
        if cls._is_automated_or_offline_env(allow_in_tests=allow_in_tests):
            return list(available_tags)

        norm_ep = (endpoint or cls.DEFAULT_ENDPOINT).rstrip("/")
        # Only attempt dynamic pulls when Ollama daemon is actually reachable (<=400ms probe)
        probed = cls.probe_ollama(endpoint=norm_ep, fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC) if not available_tags else list(available_tags)
        if not available_tags and probed is None:
            return list(available_tags)
        current = list(probed or [])

        eff_ram = get_free_memory_gb() if free_ram_gb is None else float(free_ram_gb)
        eff_vram = get_free_vram_mb(allow_in_tests=allow_in_tests) if free_vram_mb is None else float(free_vram_mb)
        sized_qwen = size_qwen_for_free_memory(eff_ram, eff_vram)
        gen_tags = cls.filter_generative_tags(current)

        def _has_abliterated_family(keywords: Tuple[str, ...]) -> bool:
            for t in gen_tags:
                tl = t.lower()
                if ("abliterat" in tl or "obliterat" in tl) and any(k in tl for k in keywords):
                    return True
            return False

        def _has_exact(cand: str) -> bool:
            cl = cand.strip().lower()
            return any(t.lower() == cl or t.lower().startswith(cl + ":") for t in gen_tags)

        # 1. Protocol Specialist (Abliterated Gemma when free memory supports 12B, else memory-sized Qwen/Gemma)
        if preferred_model and preferred_model.lower() not in ("auto", "gemma2:2b", "hf.co/obliteratus/gemma-4-12b-obliterated:q4_k_m", "gemma-4-12b-obliterated"):
            role1_cands = [preferred_model] if not _has_exact(preferred_model) else []
        elif not _has_abliterated_family(("gemma",)):
            if eff_ram >= 10.0 or eff_vram >= 8192.0:
                role1_cands = ["hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M", sized_qwen, "gemma2:2b"]
            elif eff_ram >= 6.0 or eff_vram >= 2048.0:
                role1_cands = [sized_qwen, "gemma2:2b"]
            else:
                role1_cands = [sized_qwen]
        else:
            role1_cands = []

        # 2. Boundary Specialist (Abliterated Foundation-Sec when >=8GB free RAM or >=6GB free VRAM, else memory-sized Qwen)
        if sec_model and sec_model.lower() != "fenkohq/foundation-sec-8b:latest":
            role2_cands = [sec_model] if not _has_exact(sec_model) else []
        elif not _has_abliterated_family(("foundation-sec", "cisco")):
            if eff_ram >= 8.0 or eff_vram >= 6144.0:
                role2_cands = ["huihui_ai/foundation-sec-abliterated:8b", "fenkohq/foundation-sec-8b:latest", sized_qwen]
            else:
                role2_cands = [sized_qwen]
        else:
            role2_cands = []

        # 3. Reasoning Arbiter (Abliterated GLM / DeepSeek-R1 scaled strictly to runtime free RAM/VRAM)
        if arbiter_model:
            role3_cands = [arbiter_model] if not _has_exact(arbiter_model) else []
        elif not _has_abliterated_family(("glm", "deepseek-r1")):
            if eff_ram >= 24.0 or eff_vram >= 14336.0:
                role3_cands = [
                    "huihui_ai/glm-4.7-flash-abliterated:latest",
                    "huihui_ai/deepseek-r1-abliterated:8b",
                    "glm4:9b",
                    sized_qwen,
                ]
            elif eff_ram >= 10.0 or eff_vram >= 6144.0:
                role3_cands = [
                    "huihui_ai/deepseek-r1-abliterated:8b",
                    "glm4:9b",
                    sized_qwen,
                ]
            elif eff_ram >= 6.0 or eff_vram >= 2048.0:
                role3_cands = [
                    "deepseek-r1:1.5b",
                    sized_qwen,
                ]
            else:
                role3_cands = [sized_qwen]
        else:
            role3_cands = []

        pulled_any = False
        satisfied_models: set = {t.lower() for t in gen_tags}
        for cands in (role1_cands, role2_cands, role3_cands):
            for cand in cands:
                cl = cand.strip().lower()
                if any(m == cl or m.startswith(cl + ":") for m in satisfied_models):
                    break
                if cls.ensure_model_installed(cand, endpoint=norm_ep, allow_in_tests=allow_in_tests):
                    pulled_any = True
                    satisfied_models.add(cl)
                    break

        if pulled_any:
            refreshed = cls.probe_ollama(endpoint=norm_ep, fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC)
            if refreshed is not None:
                return refreshed
        return current

    @classmethod
    def trigger_background_pull(cls, model_name: str, endpoint: str = DEFAULT_ENDPOINT) -> None:
        """
        Triggers a non-blocking background `ollama pull <model>` if a requested model is missing,
        and prints clear guidance to stderr.
        """
        clean_name = (model_name or "").strip()
        if not clean_name or is_embedding_model(clean_name):
            return
        if cls._is_automated_or_offline_env():
            return
        with cls._lock:
            if clean_name in cls._pulling_models or clean_name in cls._failed_pulls:
                return
            cls._pulling_models.add(clean_name)
            installed_str = ", ".join(cls._cached_tags[:6]) if cls._cached_tags else "none"

        print(
            f"[*] [Ollama Auto-Pull] Model '{clean_name}' not found locally. "
            f"Auto-pulling in background (`ollama pull {clean_name}`). "
            f"Installed models: [{installed_str}]",
            file=sys.stderr,
        )

        def _pull_worker() -> None:
            ok = False
            try:
                ollama_bin = cls.find_ollama_binary()
                if ollama_bin:
                    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
                    res = subprocess.run(
                        [ollama_bin, "pull", clean_name],
                        shell=False,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=600,
                        check=False,
                        creationflags=creation_flags,
                    )
                    if res.returncode == 0:
                        ok = True
                        cls.probe_ollama(endpoint=endpoint, fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC)
                if not ok:
                    ok = cls._pull_model_via_http(clean_name, endpoint=endpoint, timeout_sec=600)
                    if ok:
                        cls.probe_ollama(endpoint=endpoint, fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC)
                if not ok:
                    with cls._lock:
                        cls._failed_pulls.add(clean_name)
            except Exception:
                with cls._lock:
                    cls._failed_pulls.add(clean_name)
            finally:
                with cls._lock:
                    cls._pulling_models.discard(clean_name)

        t = threading.Thread(target=_pull_worker, daemon=True)
        t.start()


filter_generative_tags = OllamaLifecycleManager.filter_generative_tags
ensure_model_installed = OllamaLifecycleManager.ensure_model_installed
ensure_panel_models_installed = OllamaLifecycleManager.ensure_panel_models_installed
