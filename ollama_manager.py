"""
Ollama Lifecycle, Auto-Install, Auto-Start & Model Resilience Manager
=====================================================================
Ensures zero-crash local AI execution for RFC Hunt Swarm:
1. Fast 400ms health probe (`probe_ollama`) with busy-daemon fallback.
2. Auto-detects installed `ollama` binary across PATH and standard Windows/Unix locations.
3. Auto-installs Ollama if missing (via winget / official installer on Windows, install.sh on Unix)
   using strictly process-scoped environment variables (never mutating system/user registry PATH).
4. Auto-starts `ollama serve` in the background if the daemon is not running.
5. Auto-pulls missing models (`fenkohq/foundation-sec-8b:latest`, `gemma2:2b`, `deepseek-r1:1.5b`)
   and provides interactive terminal guidance.
"""

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import List, Optional

import httpx

logger = logging.getLogger("terminator.ollama")


class OllamaLifecycleManager:
    DEFAULT_ENDPOINT = "http://127.0.0.1:11434"
    _lock = threading.Lock()
    _cached_tags: List[str] = []
    _last_probe_ts: float = 0.0
    _daemon_checked: bool = False
    _pulling_models: set = set()

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
    def probe_ollama(cls, endpoint: str = DEFAULT_ENDPOINT, fast_timeout: float = 0.4) -> Optional[List[str]]:
        """
        Probes Ollama `/api/tags`.
        Starts with a strict 400ms fast probe; if Ollama is busy swapping weights on localhost,
        allows a single 3.0s grace read so active local models are never mistakenly marked empty.
        """
        try:
            resp = httpx.get(f"{endpoint}/api/tags", timeout=fast_timeout)
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", []) if "name" in m]
                cls._cached_tags = models
                cls._last_probe_ts = time.time()
                return models
        except httpx.ReadTimeout:
            # Socket connected in <400ms, meaning Ollama daemon IS running but busy loading weights
            try:
                resp = httpx.get(f"{endpoint}/api/tags", timeout=3.5)
                if resp.status_code == 200:
                    models = [m["name"] for m in resp.json().get("models", []) if "name" in m]
                    cls._cached_tags = models
                    cls._last_probe_ts = time.time()
                    return models
            except Exception:
                if cls._cached_tags:
                    return list(cls._cached_tags)
        except Exception:
            pass
        return None

    @classmethod
    def install_ollama_if_missing(cls) -> Optional[str]:
        """
        Automatically installs Ollama if the binary is not present on the machine.
        Strictly uses process-scoped environment variables.
        """
        existing = cls.find_ollama_binary()
        if existing:
            return existing

        # Do not trigger heavy network installs inside pytest runs
        if "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules:
            return None

        print("[*] [Ollama Auto-Setup] Ollama binary not found. Attempting automatic installation...")
        if os.name == "nt":
            # 1. Try winget first
            winget_bin = shutil.which("winget")
            if winget_bin:
                try:
                    print("[*] [Ollama Auto-Setup] Installing Ollama via winget...")
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
                        timeout=180,
                        check=False,
                    )
                    installed = cls.find_ollama_binary()
                    if installed:
                        print(f"[+] [Ollama Auto-Setup] Ollama installed at {installed}")
                        return installed
                except Exception as e:
                    logger.debug("winget install failed: %s", e)

            # 2. Fallback: Download official OllamaSetup.exe to temp and run silently
            try:
                installer_path = Path(tempfile.gettempdir()) / "OllamaSetup.exe"
                if not installer_path.exists():
                    print("[*] [Ollama Auto-Setup] Downloading official OllamaSetup.exe...")
                    with httpx.stream("GET", "https://ollama.com/download/OllamaSetup.exe", follow_redirects=True, timeout=60.0) as r:
                        if r.status_code == 200:
                            with open(installer_path, "wb") as f:
                                for chunk in r.iter_bytes():
                                    f.write(chunk)
                if installer_path.is_file():
                    print("[*] [Ollama Auto-Setup] Running silent installer OllamaSetup.exe /SILENT...")
                    subprocess.run([str(installer_path), "/SILENT"], timeout=180, check=False)
                    installed = cls.find_ollama_binary()
                    if installed:
                        print(f"[+] [Ollama Auto-Setup] Ollama installed at {installed}")
                        return installed
            except Exception as e:
                logger.warning("Automatic Ollama installer download failed: %s", e)
        else:
            try:
                print("[*] [Ollama Auto-Setup] Installing Ollama via official install.sh...")
                subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, timeout=180, check=False)
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
        Uses in-process caching so repeated calls within 30s are instantaneous.
        """
        with cls._lock:
            if cls._cached_tags and (time.time() - cls._last_probe_ts) < 30.0:
                return list(cls._cached_tags)

            # 1. Check if Ollama is already responding
            tags = cls.probe_ollama(endpoint=endpoint, fast_timeout=0.4)
            if tags is not None:
                cls._daemon_checked = True
                return tags

            # Skip spawning external daemons during unit tests if offline
            if "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules:
                return list(cls._cached_tags)

            # 2. Locate or auto-install Ollama binary
            ollama_bin = cls.find_ollama_binary()
            if not ollama_bin and auto_install and not cls._daemon_checked:
                ollama_bin = cls.install_ollama_if_missing()

            cls._daemon_checked = True
            if not ollama_bin:
                return list(cls._cached_tags)

            # 3. Auto-start `ollama serve` in background with process-scoped parallel env
            print(f"[*] [Ollama Auto-Start] Starting local Ollama daemon ({ollama_bin} serve)...")
            proc_env = os.environ.copy()
            proc_env.setdefault("OLLAMA_NUM_PARALLEL", "2")
            proc_env.setdefault("OLLAMA_MAX_LOADED_MODELS", "2")
            proc_env.setdefault("OLLAMA_KEEP_ALIVE", "60m")

            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            try:
                subprocess.Popen(
                    [ollama_bin, "serve"],
                    env=proc_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creation_flags,
                )
            except Exception as e:
                logger.warning("Failed to start ollama serve: %s", e)
                return list(cls._cached_tags)

            # 4. Poll up to 8 seconds for daemon readiness
            for _ in range(16):
                time.sleep(0.5)
                tags = cls.probe_ollama(endpoint=endpoint, fast_timeout=0.5)
                if tags is not None:
                    print(f"[+] [Ollama Auto-Start] Ollama daemon online ({len(tags)} models available).")
                    return tags

            return list(cls._cached_tags)

    @classmethod
    def trigger_background_pull(cls, model_name: str, endpoint: str = DEFAULT_ENDPOINT) -> None:
        """
        Triggers a non-blocking background `ollama pull <model>` if a requested model is missing,
        and prints clear guidance with already-installed fallback models.
        """
        if not model_name or model_name in cls._pulling_models:
            return
        if "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules:
            return

        cls._pulling_models.add(model_name)
        installed_str = ", ".join(cls._cached_tags[:6]) if cls._cached_tags else "none"
        print(
            f"[*] [Ollama Auto-Pull] Model '{model_name}' not found locally. "
            f"Auto-pulling in background (`ollama pull {model_name}`). "
            f"Installed models: [{installed_str}]"
        )

        def _pull_worker():
            ollama_bin = cls.find_ollama_binary()
            if ollama_bin:
                creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
                try:
                    res = subprocess.run(
                        [ollama_bin, "pull", model_name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=600,
                        creationflags=creation_flags,
                    )
                    if res.returncode == 0:
                        cls.probe_ollama(endpoint=endpoint, fast_timeout=1.0)
                except Exception:
                    pass

        t = threading.Thread(target=_pull_worker, daemon=True)
        t.start()
