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

import json
import logging
import os
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
        Probes Ollama `/api/tags`.
        Starts with a strict 400ms fast probe; if Ollama is busy swapping weights on localhost,
        allows a single 3.5s grace read so active local models are never mistakenly marked empty.
        """
        norm_ep = (endpoint or cls.DEFAULT_ENDPOINT).rstrip("/")
        try:
            resp = httpx.get(f"{norm_ep}/api/tags", timeout=fast_timeout)
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", []) if "name" in m]
                cls._update_cache(norm_ep, models)
                return models
        except httpx.ReadTimeout:
            try:
                resp = httpx.get(f"{norm_ep}/api/tags", timeout=3.5)
                if resp.status_code == 200:
                    models = [m["name"] for m in resp.json().get("models", []) if "name" in m]
                    cls._update_cache(norm_ep, models)
                    return models
            except Exception:
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
    def install_ollama_if_missing(cls) -> Optional[str]:
        """
        Automatically installs Ollama if the binary is not present on the machine.
        Strictly uses `shell=False` and process-scoped environment variables.
        """
        existing = cls.find_ollama_binary()
        if existing:
            return existing

        if cls._is_automated_or_offline_env():
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
    def ensure_ollama_ready(cls, endpoint: str = DEFAULT_ENDPOINT, auto_install: bool = True) -> List[str]:
        """
        Ensures the Ollama daemon is installed, running, and returns available model tags.
        Uses endpoint-keyed in-process caching so repeated calls within 30s are instantaneous.
        """
        norm_ep = (endpoint or cls.DEFAULT_ENDPOINT).rstrip("/")
        with cls._lock:
            cached = cls._cached_by_endpoint.get(norm_ep)
            if cached and cached[1] and (time.time() - cached[0]) < 30.0:
                return list(cached[1])

            tags = cls.probe_ollama(endpoint=norm_ep, fast_timeout=0.4)
            if tags is not None:
                cls._daemon_checked = True
                return tags

            if cls._is_automated_or_offline_env():
                return list(cached[1]) if cached else list(cls._cached_tags)

            ollama_bin = cls.find_ollama_binary()
            if not ollama_bin and auto_install and not cls._daemon_checked:
                ollama_bin = cls.install_ollama_if_missing()

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
                tags = cls.probe_ollama(endpoint=norm_ep, fast_timeout=0.5)
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
            f"[*] [Ollama Dynamic Install] Model '{clean_name}' is missing locally — pulling dynamically...",
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
                refreshed = cls.probe_ollama(endpoint=norm_ep, fast_timeout=2.0) or []
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
        free_ram_gb: float = 16.0,
        preferred_model: Optional[str] = None,
        sec_model: Optional[str] = None,
        arbiter_model: Optional[str] = None,
        allow_in_tests: bool = False,
    ) -> List[str]:
        """
        Ensures the 3-specialist refusal-free ModelFusion panel models are dynamically pulled
        when missing on a live online machine (skipped automatically in CI / pytest / offline).
        """
        if cls._is_automated_or_offline_env(allow_in_tests=allow_in_tests):
            return list(available_tags)

        norm_ep = (endpoint or cls.DEFAULT_ENDPOINT).rstrip("/")
        # Only attempt dynamic pulls when Ollama daemon is actually reachable
        current = list(available_tags) if available_tags else (cls.probe_ollama(endpoint=norm_ep, fast_timeout=0.8) or [])
        if current == [] and cls.probe_ollama(endpoint=norm_ep, fast_timeout=0.8) is None:
            return list(available_tags)

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

        # 1. Protocol Specialist (Abliterated Gemma)
        if preferred_model and preferred_model.lower() not in ("auto", "gemma2:2b", "hf.co/obliteratus/gemma-4-12b-obliterated:q4_k_m", "gemma-4-12b-obliterated"):
            role1_cands = [preferred_model] if not _has_exact(preferred_model) else []
        elif not _has_abliterated_family(("gemma",)):
            role1_cands = (
                ["hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M", "gemma2:2b"]
                if free_ram_gb >= 8.0
                else ["gemma2:2b"]
            )
        else:
            role1_cands = []

        # 2. Boundary Specialist (Abliterated Foundation-Sec)
        if sec_model and sec_model.lower() != "fenkohq/foundation-sec-8b:latest":
            role2_cands = [sec_model] if not _has_exact(sec_model) else []
        elif not _has_abliterated_family(("foundation-sec", "cisco")):
            role2_cands = ["huihui_ai/foundation-sec-abliterated:8b", "fenkohq/foundation-sec-8b:latest"]
        else:
            role2_cands = []

        # 3. Reasoning Arbiter (Abliterated GLM / DeepSeek-R1)
        if arbiter_model:
            role3_cands = [arbiter_model] if not _has_exact(arbiter_model) else []
        elif not _has_abliterated_family(("glm", "deepseek-r1")):
            if free_ram_gb >= 22.0:
                role3_cands = [
                    "huihui_ai/glm-4.7-flash-abliterated:latest",
                    "huihui_ai/deepseek-r1-abliterated:8b",
                    "glm4:9b",
                ]
            else:
                role3_cands = [
                    "huihui_ai/deepseek-r1-abliterated:8b",
                    "glm4:9b",
                ]
        else:
            role3_cands = []

        pulled_any = False
        for cands in (role1_cands, role2_cands, role3_cands):
            for cand in cands:
                if cls.ensure_model_installed(cand, endpoint=norm_ep, allow_in_tests=allow_in_tests):
                    pulled_any = True
                    break

        if pulled_any:
            refreshed = cls.probe_ollama(endpoint=norm_ep, fast_timeout=2.0)
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
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=600,
                        check=False,
                        creationflags=creation_flags,
                    )
                    if res.returncode == 0:
                        ok = True
                        cls.probe_ollama(endpoint=endpoint, fast_timeout=1.0)
                if not ok:
                    ok = cls._pull_model_via_http(clean_name, endpoint=endpoint, timeout_sec=600)
                    if ok:
                        cls.probe_ollama(endpoint=endpoint, fast_timeout=1.0)
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
