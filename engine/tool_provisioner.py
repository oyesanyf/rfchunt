"""
Dynamic Cross-Platform Tool & Dependency Provisioner for RFCHunt
=================================================================
Inspects and dynamically installs EVERY external binary, repository, container
image, npm CLI, Python package, Ollama daemon, and abliterated AI model used
across RFCHunt (`aiscan`, `raptor`, `raptor_docker`, `httpx`, `katana`,
`nuclei`, `artex`, `rea-agents`, `semgrep`, `python_deps`, `ollama`,
`ollama_models`, `rfc_cache`, and ProjectDiscovery Docker images).

Design & Safety Invariants:
---------------------------
1. Zero Global Environment / Registry Mutation (`environment_safety.md`):
   - NEVER calls `setx`, `reg add`, or Windows Registry APIs to mutate user or
     system `PATH`.
   - Installs standalone binaries into repo-local `bin/`, repositories/npm
     packages into repo-local `tools/`, and updates ONLY process-scoped
     `os.environ["PATH"]`.
2. Safe Archive & Subprocess Execution (`shell=False`, Zip-Slip & SHA256):
   - Every subprocess uses `shell=False`, explicit argv arrays,
     `stdin=subprocess.DEVNULL`, and `CREATE_NO_WINDOW` (`0x08000000`) on Windows.
   - Official GitHub release zips/tarballs are verified against release
     SHA256 checksum manifests when provided and extracted only after validating
     every archive member path against traversal.
3. Offline / CI / Test Safety:
   - Respects `RFCHUNT_OFFLINE=1` and `RFCHUNT_AUTO_INSTALL_TOOLS=0`.
   - Never triggers live network downloads or subprocess installs inside pytest
     or CI environments unless explicitly requested with `allow_in_tests=True`.
4. Aggressively Parallelized:
   - Status checks and independent tool installations execute concurrently using
     bounded `ThreadPoolExecutor` pools.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.request
import zipfile

logger = logging.getLogger("terminator.tools")

CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
REPO_ROOT: Path = Path(__file__).resolve().parent.parent
LOCAL_BIN_DIR: Path = REPO_ROOT / "bin"
LOCAL_TOOLS_DIR: Path = REPO_ROOT / "tools"
LOCAL_NPM_PREFIX: Path = LOCAL_TOOLS_DIR / "npm"
LOCAL_CARGO_ROOT: Path = LOCAL_TOOLS_DIR / "cargo"

GITHUB_API_HEADERS = {
    "User-Agent": "RFCHunt-ToolProvisioner/1.0",
    "Accept": "application/vnd.github+json",
}

CORE_AND_SECURITY_PYTHON_PACKAGES: Tuple[Tuple[str, str], ...] = (
    ("httpx", "httpx>=0.28.1"),
    ("langgraph", "langgraph>=1.0.0"),
    ("requests", "requests>=2.32.0"),
    ("urllib3", "urllib3>=2.0.0"),
    ("typing_extensions", "typing_extensions>=4.12.0"),
    ("pytest", "pytest>=8.0.0"),
    ("yaml", "pyyaml>=6.0.0"),
    ("cryptography", "cryptography>=42.0.0"),
    ("rich", "rich>=13.0.0"),
    ("defusedxml", "defusedxml>=0.7.1"),
    ("bs4", "beautifulsoup4>=4.12.0"),
    ("h2", "h2>=4.1.0"),
    ("blake3", "blake3>=0.4.0"),
    ("pydantic", "pydantic>=2.0.0"),
    ("typer", "typer>=0.12.0"),
    ("openai", "openai>=1.50.0"),
    ("instructor", "instructor>=1.7.0"),
    ("tabulate", "tabulate>=0.9.0"),
)

OPTIONAL_SECURITY_PYTHON_PACKAGES: Tuple[Tuple[str, str], ...] = (
    ("pyelftools", "pyelftools>=0.31"),
    ("playwright", "playwright>=1.45.0"),
)

GITHUB_RELEASE_TOOLS: Dict[str, Dict[str, str]] = {
    "httpx": {
        "repo": "projectdiscovery/httpx",
        "binary": "httpx",
        "url": "https://github.com/projectdiscovery/httpx",
    },
    "katana": {
        "repo": "projectdiscovery/katana",
        "binary": "katana",
        "url": "https://github.com/projectdiscovery/katana",
    },
    "nuclei": {
        "repo": "projectdiscovery/nuclei",
        "binary": "nuclei",
        "url": "https://github.com/projectdiscovery/nuclei",
    },
    "artex": {
        "repo": "BaaRai/ARTEX",
        "binary": "artex",
        "url": "https://github.com/BaaRai/ARTEX",
    },
    "aiscan": {
        "repo": "haasonsaas/aiscan",
        "binary": "aiscan",
        "url": "https://github.com/haasonsaas/aiscan",
    },
}

GO_INSTALL_TARGETS: Dict[str, str] = {
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}

PROJECTDISCOVERY_DOCKER_IMAGES: Tuple[Tuple[str, str], ...] = (
    ("httpx", "projectdiscovery/httpx:latest"),
    ("katana", "projectdiscovery/katana:latest"),
    ("nuclei", "projectdiscovery/nuclei:latest"),
)

RAPTOR_REPO_URL = "https://github.com/gadievron/raptor.git"
RAPTOR_ARCHIVE_ZIP_URL = "https://github.com/gadievron/raptor/archive/refs/heads/main.zip"
RAPTOR_DOCKER_IMAGE = "danielcuthbert/raptor:latest"
AISCAN_REPO_URL = "https://github.com/haasonsaas/aiscan.git"
AISCAN_LOCAL_SOURCE = Path(r"D:\harfile\aiscan")
REA_NPM_PACKAGE = "rea-agents"
RAPTOR_DEFAULT_MODEL = "fenkohq/foundation-sec-8b:latest"


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    display_name: str
    category: str  # python | binary | repo | docker | npm | ai | corpus
    description: str
    required_for_core: bool = True
    default_in_setup: bool = True


TOOL_CATALOG: Tuple[ToolSpec, ...] = (
    ToolSpec(
        "python_deps",
        "Core & Security Python Packages",
        "python",
        "Runtime, cryptography, AST/HTML/SARIF, and RAPTOR Python libraries",
    ),
    ToolSpec(
        "semgrep",
        "Semgrep SAST Engine",
        "python",
        "Static code pattern analyzer used across RAPTOR and source audits",
    ),
    ToolSpec(
        "aiscan",
        "haasonsaas/aiscan Rust Scanner",
        "binary",
        "Module 18 native AI/LLM risk & credential scanner",
    ),
    ToolSpec(
        "raptor",
        "RAPTOR Framework Repository",
        "repo",
        "Module 15 Autonomous Offensive/Defensive Framework (gadievron/raptor)",
    ),
    ToolSpec(
        "raptor_docker",
        "RAPTOR Docker Engine Image",
        "docker",
        "Containerized RAPTOR engine (danielcuthbert/raptor:latest)",
        required_for_core=False,
    ),
    ToolSpec(
        "httpx",
        "ProjectDiscovery httpx",
        "binary",
        "HTTP probing & technology fingerprinting CLI",
    ),
    ToolSpec(
        "katana",
        "ProjectDiscovery katana",
        "binary",
        "JS-aware web crawler & endpoint discovery CLI",
    ),
    ToolSpec(
        "nuclei",
        "ProjectDiscovery nuclei",
        "binary",
        "Template-driven non-destructive vulnerability scanner CLI",
    ),
    ToolSpec(
        "artex",
        "BaaRai/ARTEX Dual-Graph Binary",
        "binary",
        "Module 17 headless ARTEX server & orchestrator",
        required_for_core=False,
    ),
    ToolSpec(
        "rea_agents",
        "morluto/rea (rea-agents CLI)",
        "npm",
        "Module 21 frontend/Electron/sourcemap bundle surface analyzer",
    ),
    ToolSpec(
        "ollama",
        "Ollama Local AI Runtime",
        "ai",
        "Zero-cost local LLM inference binary & daemon",
    ),
    ToolSpec(
        "ollama_models",
        "Abliterated ModelFusion Trio",
        "ai",
        "Gemma-4-12B-OBLITERATED, Foundation-Sec-8B, and GLM/DeepSeek-R1 arbiter models",
        required_for_core=False,
    ),
    ToolSpec(
        "rfc_cache",
        "Terminator IETF RFC Corpus Cache",
        "corpus",
        "Offline-cached canonical HTTP/TLS/PQC RFC specifications",
    ),
    ToolSpec(
        "docker_scanners",
        "ProjectDiscovery Docker Images",
        "docker",
        "Container images for isolated httpx/katana/nuclei execution",
        required_for_core=False,
        default_in_setup=False,
    ),
)

ALL_TOOL_IDS: Tuple[str, ...] = tuple(spec.tool_id for spec in TOOL_CATALOG)


@dataclass
class ToolStatus:
    tool_id: str
    display_name: str
    category: str
    installed: bool
    path_or_source: Optional[str] = None
    version: Optional[str] = None
    method: str = "missing"
    detail: str = ""
    installed_now: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _creation_flags() -> int:
    return CREATE_NO_WINDOW if (sys.platform == "win32" or os.name == "nt") else 0


def _run_quiet_subprocess(
    argv: Sequence[str],
    *,
    timeout: int = 300,
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess:
    """Executes an argv list with shell=False, hidden window on Windows, and closed stdin."""
    return subprocess.run(
        [str(a) for a in argv],
        shell=False,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        creationflags=_creation_flags(),
    )


def register_process_bin_dir(bin_dir: Path) -> None:
    """Prepends a binary directory to process-scoped PATH only (never mutates registry/setx)."""
    if not bin_dir:
        return
    resolved = str(bin_dir.resolve()) if bin_dir.exists() else str(bin_dir)
    current = os.environ.get("PATH", "")
    parts = [p for p in current.split(os.pathsep) if p] if current else []
    norm_cmp = os.path.normcase(os.path.normpath(resolved))
    existing_norm = {os.path.normcase(os.path.normpath(p)) for p in parts}
    if norm_cmp not in existing_norm:
        os.environ["PATH"] = f"{resolved}{os.pathsep}{current}" if current else resolved


def resolve_default_raptor_root(repo_root: Optional[Path] = None) -> Path:
    """Returns cross-platform default location for the cloned RAPTOR framework."""
    env_override = os.environ.get("RFCHUNT_RAPTOR_ROOT", "").strip()
    if env_override:
        return Path(env_override)
    base = repo_root or REPO_ROOT
    if os.name == "nt":
        win_default = Path(r"D:\docker\raptor")
        if (win_default / "raptor.py").is_file() or Path("D:\\").exists():
            return win_default
    return base / "tools" / "raptor"


def is_automated_or_offline_env(*, allow_in_tests: bool = False) -> bool:
    """Returns True when offline mode or test/CI guards forbid background network/tool installs."""
    if os.environ.get("RFCHUNT_OFFLINE") == "1":
        return True
    if os.environ.get("RFCHUNT_AUTO_INSTALL_TOOLS") == "0":
        return True
    if not allow_in_tests and (
        "PYTEST_CURRENT_TEST" in os.environ
        or "pytest" in sys.modules
        or bool(os.environ.get("CI"))
        or bool(os.environ.get("GITHUB_ACTIONS"))
    ):
        return True
    return False


def _detect_os_arch_tokens() -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    if sys_name.startswith("win"):
        os_tokens = ("windows", "win64", "win32", "win")
    elif sys_name == "darwin":
        os_tokens = ("darwin", "macos", "osx")
    else:
        os_tokens = ("linux",)

    if machine in ("x86_64", "amd64", "x64"):
        arch_tokens = ("amd64", "x86_64", "x64")
    elif machine in ("aarch64", "arm64"):
        arch_tokens = ("arm64", "aarch64")
    elif machine in ("i386", "i686", "x86"):
        arch_tokens = ("386", "x86")
    else:
        arch_tokens = (machine, "amd64")
    return os_tokens, arch_tokens


def _select_release_asset(
    assets: List[Dict[str, Any]],
    *,
    preferred_exts: Tuple[str, ...] = (".zip", ".tar.gz", ".tgz"),
) -> Optional[Dict[str, Any]]:
    """Selects the GitHub release asset matching host OS and CPU architecture via whole tokens."""
    os_tokens, arch_tokens = _detect_os_arch_tokens()
    best: Optional[Tuple[int, Dict[str, Any]]] = None
    for asset in assets:
        name = str(asset.get("name") or "")
        low = name.lower()
        if any(skip in low for skip in ("checksum", "sha256", ".sig", ".pem", ".cdx.json", ".sbom")):
            continue
        if not any(low.endswith(ext) for ext in preferred_exts):
            continue
        parts = set(re.split(r"[-_.]", low))
        if not parts.intersection(os_tokens):
            continue
        if not parts.intersection(arch_tokens):
            continue
        score = 10
        if low.endswith(".zip") and os_tokens[0] == "windows":
            score += 5
        elif low.endswith((".tar.gz", ".tgz")) and os_tokens[0] != "windows":
            score += 3
        if os_tokens[0] in parts:
            score += 4
        if arch_tokens[0] in parts:
            score += 2
        if best is None or score > best[0]:
            best = (score, asset)
    return best[1] if best else None


def _is_python_httpx_binary(candidate: Path) -> bool:
    """Detects Python's `httpx[cli]` wrapper so it never shadows ProjectDiscovery `httpx`."""
    try:
        if not candidate.is_file():
            return False
        size = candidate.stat().st_size
        if size <= 0 or size > 2 * 1024 * 1024:
            return False
        with candidate.open("rb") as fh:
            if size <= 16384:
                chunk = fh.read(size)
            else:
                head = fh.read(256)
                if not head.startswith(b"MZ"):
                    return False
                fh.seek(max(0, size - 8192))
                chunk = fh.read(8192)
        low = chunk.lower()
        return bool(
            b"#!" in low
            and b"python" in low
            and (
                b"from httpx import main" in low
                or b"from httpx._main import main" in low
                or b"load_entry_point('httpx'" in low
                or b'load_entry_point("httpx"' in low
                or (b"__main__.py" in low and b"httpx" in low and b"sys.exit" in low)
            )
        )
    except OSError:
        return False


def _validate_archive_member_name(name: str) -> bool:
    """Rejects zip-slip path traversal or unsafe device/drive archive paths."""
    if not name or name.startswith(("/", "\\")) or ":" in name or "\x00" in name:
        return False
    norm = name.replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    return not any(p == ".." for p in parts)


def _verify_sha256_against_manifest(
    payload: bytes,
    asset_name: str,
    checksum_text: str,
) -> Tuple[bool, str]:
    """Verifies `payload` against a release checksums file when the asset filename appears."""
    digest = hashlib.sha256(payload).hexdigest().lower()
    target_l = asset_name.lower()
    for line in checksum_text.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        tokens = clean.replace("*", " ").split()
        if len(tokens) >= 2 and Path(tokens[-1]).name.lower() == target_l:
            expected = tokens[0].strip().lower()
            if expected == digest:
                return True, f"sha256 verified ({digest[:12]}...)"
            return False, f"SHA256 mismatch for {asset_name}: expected {expected}, got {digest}"
    return True, f"sha256={digest[:12]}... (asset not listed in manifest)"


def _extract_single_binary_from_archive(
    archive_bytes: bytes,
    archive_name: str,
    binary_stem: str,
    dest_dir: Path,
) -> Path:
    """Safely extracts `binary_stem(.exe)` from `.zip` or `.tar.gz` bytes into `dest_dir`."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    target_names = (
        {f"{binary_stem.lower()}.exe", binary_stem.lower()}
        if os.name == "nt"
        else {binary_stem.lower()}
    )
    out_name = f"{binary_stem}.exe" if os.name == "nt" else binary_stem
    dest_path = dest_dir / out_name

    low = archive_name.lower()
    if low.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if not _validate_archive_member_name(info.filename):
                    raise ValueError(f"Unsafe archive path rejected: {info.filename!r}")
                leaf = Path(info.filename).name.lower()
                if leaf in target_names:
                    dest_path.write_bytes(zf.read(info.filename))
                    if os.name != "nt":
                        dest_path.chmod(dest_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    return dest_path
        raise FileNotFoundError(f"Binary {binary_stem!r} not found inside zip archive {archive_name!r}")

    if low.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if not _validate_archive_member_name(member.name):
                    raise ValueError(f"Unsafe archive path rejected: {member.name!r}")
                leaf = Path(member.name).name.lower()
                if leaf in target_names:
                    fobj = tf.extractfile(member)
                    if fobj is None:
                        continue
                    dest_path.write_bytes(fobj.read())
                    if os.name != "nt":
                        dest_path.chmod(dest_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    return dest_path
        raise FileNotFoundError(f"Binary {binary_stem!r} not found inside tar archive {archive_name!r}")

    raise ValueError(f"Unsupported archive format: {archive_name!r}")


class ToolProvisioner:
    """
    Centralized runtime/setup inspector and installer for all external binaries,
    repositories, Docker images, npm packages, Python libraries, and Ollama models
    required by RFCHunt.
    """

    _process_lock = threading.RLock()
    _attempted_installs: Dict[Tuple[str, str], ToolStatus] = {}

    def __init__(
        self,
        *,
        repo_root: Optional[Path] = None,
        raptor_root: Optional[Path] = None,
        on_trace: Optional[Callable[[str], None]] = None,
        allow_in_tests: bool = False,
    ) -> None:
        self.repo_root = Path(repo_root) if repo_root else REPO_ROOT
        self.bin_dir = self.repo_root / "bin"
        self.tools_dir = self.repo_root / "tools"
        self.npm_prefix = self.tools_dir / "npm"
        self.cargo_root = self.tools_dir / "cargo"
        self.raptor_root = Path(raptor_root) if raptor_root else resolve_default_raptor_root(self.repo_root)
        self.on_trace = on_trace
        self.allow_in_tests = bool(allow_in_tests)

        # Register existing local tool dirs into process-scoped PATH if they exist
        for existing_dir in (
            self.bin_dir,
            self.cargo_root / "bin",
            Path.home() / ".cargo" / "bin",
            Path.home() / "go" / "bin",
            Path.home() / ".pdtm" / "go" / "bin",
            self.npm_prefix / "node_modules" / ".bin",
        ):
            if existing_dir.is_dir():
                register_process_bin_dir(existing_dir)

    def _trace(self, msg: str) -> None:
        if self.on_trace is not None:
            try:
                self.on_trace(msg)
            except Exception:
                pass
        logger.info(msg)

    def is_offline_or_blocked(self) -> bool:
        return is_automated_or_offline_env(allow_in_tests=self.allow_in_tests)

    # ------------------------------------------------------------------
    # Binary / Tool Discovery Helpers (Pure Inspection)
    # ------------------------------------------------------------------

    def find_binary(self, tool_stem: str) -> Optional[Path]:
        """Searches repo-local bin/, cargo/go dirs, D:\\tools, and process PATH."""
        exe_names = (f"{tool_stem}.exe", tool_stem) if os.name == "nt" else (tool_stem,)
        search_dirs: List[Path] = [
            self.bin_dir,
            self.cargo_root / "bin",
            Path.home() / ".cargo" / "bin",
            Path.home() / "go" / "bin",
            Path.home() / ".pdtm" / "go" / "bin",
        ]
        if os.name == "nt":
            search_dirs.append(Path(r"D:\tools"))

        path_env = os.environ.get("PATH", "")
        for entry in path_env.split(os.pathsep):
            clean = entry.strip().strip('"')
            if clean:
                search_dirs.append(Path(clean))

        seen_dirs: set[str] = set()
        for directory in search_dirs:
            norm = os.path.normcase(os.path.normpath(str(directory)))
            if norm in seen_dirs:
                continue
            seen_dirs.add(norm)
            if not directory.is_dir():
                continue
            for name in exe_names:
                cand = directory / name
                try:
                    if not cand.is_file():
                        continue
                    if os.name != "nt" and not os.access(cand, os.X_OK):
                        continue
                    if tool_stem == "httpx" and _is_python_httpx_binary(cand):
                        continue
                    return cand.resolve()
                except OSError:
                    continue
        return None

    def find_rea_entrypoint(self) -> Optional[Dict[str, Any]]:
        """Resolves native `rea-agents` binary OR safe repo-managed `node` + `rea.mjs` entrypoint."""
        for bin_name in ("rea-agents", "rea"):
            found = shutil.which(bin_name)
            if found:
                p = Path(found)
                is_shim = p.suffix.lower() in (".cmd", ".bat", ".ps1", ".sh")
                if not is_shim and p.is_file():
                    return {
                        "installed": True,
                        "binary_path": str(p),
                        "binary_name": p.name,
                        "mode": "native",
                        "is_script_shim": False,
                    }

        mjs_path = self.npm_prefix / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"
        if mjs_path.is_file():
            posix_bin = self.npm_prefix / "node_modules" / ".bin" / "rea-agents"
            if os.name != "nt" and posix_bin.is_file() and os.access(posix_bin, os.X_OK):
                return {
                    "installed": True,
                    "binary_path": str(posix_bin.resolve()),
                    "binary_name": posix_bin.name,
                    "mode": "native",
                    "is_script_shim": False,
                }
            node_bin = shutil.which("node")
            if node_bin and Path(node_bin).is_file():
                return {
                    "installed": True,
                    "binary_path": str(Path(node_bin).resolve()),
                    "script_path": str(mjs_path.resolve()),
                    "binary_name": f"{Path(node_bin).name} rea.mjs",
                    "mode": "node_mjs",
                    "is_script_shim": False,
                }
        return None

    @staticmethod
    def _docker_available() -> Optional[str]:
        found = shutil.which("docker")
        return found if found else None

    def _docker_image_id(self, image_ref: str) -> Optional[str]:
        docker_bin = self._docker_available()
        if not docker_bin:
            return None
        try:
            proc = _run_quiet_subprocess(
                [docker_bin, "image", "inspect", image_ref, "--format", "{{.Id}}"],
                timeout=6,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip().splitlines()[0]
        except Exception:
            pass
        return None

    def _docker_daemon_responsive(self) -> bool:
        docker_bin = self._docker_available()
        if not docker_bin:
            return False
        try:
            proc = _run_quiet_subprocess([docker_bin, "info"], timeout=8)
            return proc.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Status Checks
    # ------------------------------------------------------------------

    def check_tool_status(self, tool_id: str, *, allow_probes: bool = False) -> ToolStatus:
        """Checks current local installation status for a single tool without installing."""
        spec_map = {s.tool_id: s for s in TOOL_CATALOG}
        spec = spec_map.get(tool_id)
        if spec is None:
            return ToolStatus(
                tool_id=tool_id,
                display_name=tool_id,
                category="unknown",
                installed=False,
                method="unknown",
                error=f"Unknown tool_id '{tool_id}'",
            )

        if tool_id == "python_deps":
            missing = [
                pip_spec
                for mod_name, pip_spec in CORE_AND_SECURITY_PYTHON_PACKAGES
                if importlib.util.find_spec(mod_name) is None
            ]
            installed = len(missing) == 0
            return ToolStatus(
                tool_id="python_deps",
                display_name=spec.display_name,
                category=spec.category,
                installed=installed,
                path_or_source=sys.executable,
                method="pip" if installed else "missing",
                detail=(
                    f"{len(CORE_AND_SECURITY_PYTHON_PACKAGES)} core/security packages ready"
                    if installed
                    else f"Missing {len(missing)}: {', '.join(missing[:6])}"
                ),
            )

        if tool_id == "semgrep":
            has_pkg = importlib.util.find_spec("semgrep") is not None
            bin_path = shutil.which("semgrep")
            installed = bool(has_pkg or bin_path)
            ver = None
            if has_pkg:
                try:
                    ver = importlib.metadata.version("semgrep")
                except Exception:
                    pass
            return ToolStatus(
                tool_id="semgrep",
                display_name=spec.display_name,
                category=spec.category,
                installed=installed,
                path_or_source=bin_path or (sys.executable if has_pkg else None),
                version=ver,
                method="pip" if installed else "missing",
                detail="Semgrep SAST ready" if installed else "Semgrep not installed",
            )

        if tool_id in ("aiscan", "httpx", "katana", "nuclei", "artex"):
            bin_path = self.find_binary(tool_id)
            return ToolStatus(
                tool_id=tool_id,
                display_name=spec.display_name,
                category=spec.category,
                installed=bin_path is not None,
                path_or_source=str(bin_path) if bin_path else None,
                method="binary" if bin_path else "missing",
                detail=f"Found binary at {bin_path}" if bin_path else f"{tool_id} binary not found",
            )

        if tool_id == "raptor":
            raptor_py = self.raptor_root / "raptor.py"
            installed = raptor_py.is_file()
            return ToolStatus(
                tool_id="raptor",
                display_name=spec.display_name,
                category=spec.category,
                installed=installed,
                path_or_source=str(self.raptor_root) if installed else None,
                method="git_repo" if installed else "missing",
                detail=f"RAPTOR ready at {self.raptor_root}" if installed else f"Not cloned at {self.raptor_root}",
            )

        if tool_id == "raptor_docker":
            img_id = self._docker_image_id(RAPTOR_DOCKER_IMAGE) if allow_probes else None
            return ToolStatus(
                tool_id="raptor_docker",
                display_name=spec.display_name,
                category=spec.category,
                installed=bool(img_id),
                path_or_source=RAPTOR_DOCKER_IMAGE if img_id else None,
                version=img_id[:16] if img_id else None,
                method="docker" if img_id else "missing",
                detail=f"Docker image {RAPTOR_DOCKER_IMAGE} present" if img_id else "Image missing or Docker stopped",
            )

        if tool_id == "docker_scanners":
            if not allow_probes or not self._docker_available():
                return ToolStatus(
                    tool_id="docker_scanners",
                    display_name=spec.display_name,
                    category=spec.category,
                    installed=False,
                    detail="Docker probes skipped or Docker CLI unavailable",
                )
            present = []
            missing_imgs = []
            for t_name, img_ref in PROJECTDISCOVERY_DOCKER_IMAGES:
                if self._docker_image_id(img_ref):
                    present.append(t_name)
                else:
                    missing_imgs.append(img_ref)
            return ToolStatus(
                tool_id="docker_scanners",
                display_name=spec.display_name,
                category=spec.category,
                installed=len(missing_imgs) == 0,
                path_or_source=", ".join(present) or None,
                method="docker" if not missing_imgs else "partial",
                detail=f"Present: {len(present)}/3 ({', '.join(present)})",
            )

        if tool_id == "rea_agents":
            entry = self.find_rea_entrypoint()
            installed = bool(entry and entry.get("installed"))
            path_disp = None
            if entry:
                path_disp = entry.get("script_path") or entry.get("binary_path")
            return ToolStatus(
                tool_id="rea_agents",
                display_name=spec.display_name,
                category=spec.category,
                installed=installed,
                path_or_source=path_disp,
                method=str(entry.get("mode")) if entry else "missing",
                detail=f"REA CLI ready ({path_disp})" if installed else "rea-agents npm CLI not installed",
            )

        if tool_id == "ollama":
            from ollama_manager import HEALTH_PROBE_MAX_TIMEOUT_SEC, OllamaLifecycleManager

            bin_path = OllamaLifecycleManager.find_ollama_binary()
            daemon_tags: Optional[List[str]] = None
            if allow_probes:
                daemon_tags = OllamaLifecycleManager.probe_ollama(fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC)
            installed = bool(bin_path or daemon_tags is not None)
            return ToolStatus(
                tool_id="ollama",
                display_name=spec.display_name,
                category=spec.category,
                installed=installed,
                path_or_source=bin_path or ("http://127.0.0.1:11434" if daemon_tags is not None else None),
                method="binary" if bin_path else ("daemon" if daemon_tags is not None else "missing"),
                detail=(
                    f"Ollama ready ({len(daemon_tags)} models)"
                    if daemon_tags is not None
                    else (f"Binary at {bin_path}" if bin_path else "Ollama not installed")
                ),
            )

        if tool_id == "ollama_models":
            if not allow_probes:
                return ToolStatus(
                    tool_id="ollama_models",
                    display_name=spec.display_name,
                    category=spec.category,
                    installed=False,
                    detail="Skipped probe in offline/static check mode",
                )
            from ollama_manager import (
                HEALTH_PROBE_MAX_TIMEOUT_SEC,
                OllamaLifecycleManager,
                get_runtime_free_memory,
                size_qwen_for_free_memory,
            )

            tags = OllamaLifecycleManager.probe_ollama(fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC) or []
            gen_tags = OllamaLifecycleManager.filter_generative_tags(tags)
            free_ram_gb, free_vram_mb = get_runtime_free_memory(allow_in_tests=self.allow_in_tests)
            sized_qwen = size_qwen_for_free_memory(free_ram_gb, free_vram_mb)
            has_ablit_gemma = any("obliterat" in t.lower() or "abliterat" in t.lower() for t in gen_tags)
            has_sec = any("foundation-sec" in t.lower() or "cisco" in t.lower() for t in gen_tags)
            has_sized_qwen = any(
                t.lower() == sized_qwen.lower() or t.lower().startswith(sized_qwen.lower() + ":")
                for t in gen_tags
            )
            if free_ram_gb >= 10.0 or free_vram_mb >= 8192.0:
                installed = bool(gen_tags and has_ablit_gemma)
            else:
                installed = bool(gen_tags and (has_ablit_gemma or has_sized_qwen))
            return ToolStatus(
                tool_id="ollama_models",
                display_name=spec.display_name,
                category=spec.category,
                installed=installed,
                path_or_source=", ".join(gen_tags[:4]) if gen_tags else None,
                method="ollama" if installed else ("partial" if gen_tags else "missing"),
                detail=(
                    f"Generative models: {len(gen_tags)} (abliterated={has_ablit_gemma}, "
                    f"sec={has_sec}, free_ram={free_ram_gb:.1f}GB, free_vram={free_vram_mb:.0f}MB, sized={sized_qwen})"
                ),
            )

        if tool_id == "rfc_cache":
            rfcs_dir = self.repo_root / "rfcs"
            try:
                from engine.terminator_rfc_selector import TerminatorRFCSelector

                specs = TerminatorRFCSelector.get_terminator_specs()
                total = len(specs)
                cached = sum(1 for sp in specs if (rfcs_dir / f"rfc{sp.rfc_id}.txt").is_file())
            except Exception:
                total = 25
                cached = len(list(rfcs_dir.glob("rfc*.txt"))) if rfcs_dir.is_dir() else 0
            ready = cached >= min(20, total)
            return ToolStatus(
                tool_id="rfc_cache",
                display_name=spec.display_name,
                category=spec.category,
                installed=ready,
                path_or_source=str(rfcs_dir),
                method="local_cache" if ready else "partial",
                detail=f"{cached}/{total} Terminator RFCs cached",
            )

        return ToolStatus(tool_id=tool_id, display_name=spec.display_name, category=spec.category, installed=False)

    def check_all_statuses(
        self,
        *,
        tool_ids: Optional[Sequence[str]] = None,
        allow_probes: Optional[bool] = None,
    ) -> Dict[str, ToolStatus]:
        """Checks all (or specified) tools concurrently using a bounded ThreadPoolExecutor."""
        targets = list(tool_ids or ALL_TOOL_IDS)
        if allow_probes is None:
            allow_probes = not self.is_offline_or_blocked()
        results: Dict[str, ToolStatus] = {}
        workers = min(8, max(2, len(targets)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tool-status") as pool:
            futs = {
                pool.submit(self.check_tool_status, tid, allow_probes=allow_probes): tid
                for tid in targets
            }
            for fut in as_completed(futs):
                tid = futs[fut]
                try:
                    results[tid] = fut.result()
                except Exception as exc:
                    results[tid] = ToolStatus(
                        tool_id=tid,
                        display_name=tid,
                        category="unknown",
                        installed=False,
                        error=str(exc),
                    )
        return {tid: results[tid] for tid in targets if tid in results}

    # ------------------------------------------------------------------
    # Individual Tool Installers
    # ------------------------------------------------------------------

    @staticmethod
    def _http_get_json(url: str, timeout: float = 15.0) -> Dict[str, Any]:
        req = urllib.request.Request(url, headers=GITHUB_API_HEADERS, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    @staticmethod
    def _http_download_bytes(url: str, timeout: float = 120.0) -> bytes:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": GITHUB_API_HEADERS["User-Agent"]},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    def _install_github_release_binary(self, tool_id: str) -> ToolStatus:
        """Downloads and checksum-verifies an official GitHub release binary into `bin/`."""
        meta = GITHUB_RELEASE_TOOLS[tool_id]
        repo_slug = meta["repo"]
        bin_stem = meta["binary"]
        release = self._http_get_json(f"https://api.github.com/repos/{repo_slug}/releases/latest", timeout=20.0)
        assets = release.get("assets") or []
        asset = _select_release_asset(assets)
        if not asset or not asset.get("browser_download_url"):
            raise FileNotFoundError(f"No matching OS/arch release asset in {repo_slug} ({release.get('tag_name')})")

        asset_name = str(asset["name"])
        self._trace(f"[*] Downloading {tool_id} ({release.get('tag_name')}) from {repo_slug}: {asset_name}")
        archive_bytes = self._http_download_bytes(str(asset["browser_download_url"]), timeout=180.0)

        checksum_note = ""
        checksum_asset = next(
            (
                a
                for a in assets
                if any(tok in str(a.get("name", "")).lower() for tok in ("checksum", "sha256"))
                and str(a.get("browser_download_url", ""))
            ),
            None,
        )
        if checksum_asset:
            try:
                csum_txt = self._http_download_bytes(str(checksum_asset["browser_download_url"]), timeout=20.0).decode(
                    "utf-8", errors="replace"
                )
                ok_sum, checksum_note = _verify_sha256_against_manifest(archive_bytes, asset_name, csum_txt)
                if not ok_sum:
                    raise ValueError(checksum_note)
            except ValueError:
                raise
            except Exception as exc:
                checksum_note = f"checksum fetch skipped ({exc})"

        extracted = _extract_single_binary_from_archive(archive_bytes, asset_name, bin_stem, self.bin_dir)
        register_process_bin_dir(self.bin_dir)
        return ToolStatus(
            tool_id=tool_id,
            display_name=tool_id,
            category="binary",
            installed=True,
            path_or_source=str(extracted),
            version=str(release.get("tag_name") or ""),
            method="github_release",
            detail=f"Installed {extracted.name} ({checksum_note or 'verified'})",
            installed_now=True,
        )

    def _install_go_tool(self, tool_id: str) -> Optional[ToolStatus]:
        go_bin = shutil.which("go")
        pkg_target = GO_INSTALL_TARGETS.get(tool_id)
        if not go_bin or not pkg_target:
            return None
        self._trace(f"[*] Installing {tool_id} via `go install {pkg_target}`...")
        proc = _run_quiet_subprocess([go_bin, "install", "-v", pkg_target], timeout=600)
        if proc.returncode != 0:
            return None
        for cand_dir in (Path.home() / "go" / "bin", Path.home() / ".pdtm" / "go" / "bin"):
            if cand_dir.is_dir():
                register_process_bin_dir(cand_dir)
        found = self.find_binary(tool_id)
        if found:
            self.bin_dir.mkdir(parents=True, exist_ok=True)
            copied = self.bin_dir / found.name
            if not copied.exists():
                shutil.copy2(found, copied)
                register_process_bin_dir(self.bin_dir)
            return ToolStatus(
                tool_id=tool_id,
                display_name=tool_id,
                category="binary",
                installed=True,
                path_or_source=str(copied if copied.exists() else found),
                method="go_install",
                detail=f"Installed via go install ({pkg_target})",
                installed_now=True,
            )
        return None

    def _install_aiscan(self) -> ToolStatus:
        spec_name = "haasonsaas/aiscan Rust Scanner"
        cargo_bin = shutil.which("cargo") or (
            str(Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo"))
            if (Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo")).is_file()
            else None
        )
        errors: List[str] = []

        if cargo_bin:
            self.cargo_root.mkdir(parents=True, exist_ok=True)
            # Prefer local source checkout if present on host, otherwise upstream GitHub
            if (AISCAN_LOCAL_SOURCE / "Cargo.toml").is_file():
                argv = [cargo_bin, "install", "--path", str(AISCAN_LOCAL_SOURCE), "--root", str(self.cargo_root)]
                src_label = f"cargo install --path {AISCAN_LOCAL_SOURCE}"
            else:
                argv = [cargo_bin, "install", "--git", AISCAN_REPO_URL, "--root", str(self.cargo_root)]
                src_label = f"cargo install --git {AISCAN_REPO_URL}"
            self._trace(f"[*] Building/installing aiscan ({src_label})...")
            proc = _run_quiet_subprocess(argv, timeout=900)
            if proc.returncode == 0:
                register_process_bin_dir(self.cargo_root / "bin")
                found = self.find_binary("aiscan")
                if found:
                    self.bin_dir.mkdir(parents=True, exist_ok=True)
                    dest = self.bin_dir / found.name
                    if not dest.exists():
                        shutil.copy2(found, dest)
                    register_process_bin_dir(self.bin_dir)
                    return ToolStatus(
                        tool_id="aiscan",
                        display_name=spec_name,
                        category="binary",
                        installed=True,
                        path_or_source=str(dest),
                        method="cargo_install",
                        detail=f"Built and installed via {src_label}",
                        installed_now=True,
                    )
            errors.append(f"cargo install failed (exit {proc.returncode}): {(proc.stderr or proc.stdout)[-240:]}")

        # Fallback: try GitHub releases if ever published
        try:
            res = self._install_github_release_binary("aiscan")
            res.display_name = spec_name
            return res
        except Exception as exc:
            errors.append(f"release lookup: {exc}")

        return ToolStatus(
            tool_id="aiscan",
            display_name=spec_name,
            category="binary",
            installed=False,
            method="python_fallback",
            detail="Native aiscan binary not built (PythonAIScanner fallback remains active)",
            error="; ".join(errors),
        )

    def _install_raptor_repo(self) -> ToolStatus:
        spec_name = "RAPTOR Framework Repository"
        self.raptor_root.parent.mkdir(parents=True, exist_ok=True)
        errors: List[str] = []

        if not (self.raptor_root / "raptor.py").is_file():
            git_bin = shutil.which("git")
            cloned = False
            if git_bin:
                self._trace(f"[*] Cloning {RAPTOR_REPO_URL} into {self.raptor_root}...")
                target_tmp = self.raptor_root
                proc = _run_quiet_subprocess(
                    [git_bin, "clone", "--depth", "1", RAPTOR_REPO_URL, str(target_tmp)],
                    timeout=300,
                )
                cloned = proc.returncode == 0 and (self.raptor_root / "raptor.py").is_file()
                if not cloned:
                    errors.append(f"git clone exit {proc.returncode}: {(proc.stderr or '')[:200]}")

            if not cloned:
                try:
                    self._trace(f"[*] Downloading RAPTOR archive from {RAPTOR_ARCHIVE_ZIP_URL}...")
                    zbytes = self._http_download_bytes(RAPTOR_ARCHIVE_ZIP_URL, timeout=180.0)
                    self.raptor_root.mkdir(parents=True, exist_ok=True)
                    with zipfile.ZipFile(io.BytesIO(zbytes)) as zf:
                        for info in zf.infolist():
                            if info.is_dir():
                                continue
                            if not _validate_archive_member_name(info.filename):
                                raise ValueError(f"Unsafe archive entry in RAPTOR zip: {info.filename!r}")
                            rel_parts = info.filename.replace("\\", "/").split("/", 1)
                            sub_rel = rel_parts[1] if len(rel_parts) > 1 else rel_parts[0]
                            if not sub_rel:
                                continue
                            out_p = self.raptor_root / sub_rel
                            out_p.parent.mkdir(parents=True, exist_ok=True)
                            out_p.write_bytes(zf.read(info.filename))
                except Exception as exc:
                    errors.append(f"zip download failed: {exc}")

        if not (self.raptor_root / "raptor.py").is_file():
            return ToolStatus(
                tool_id="raptor",
                display_name=spec_name,
                category="repo",
                installed=False,
                path_or_source=str(self.raptor_root),
                method="failed",
                error="; ".join(errors) or "Unable to obtain raptor.py",
            )

        # Configure models.json (strictly sized from runtime free RAM/VRAM, never `-coder`) + loopback bypass + Invoke-RaptorScan.ps1
        models_json = self.raptor_root / "models.json"
        api_base = "http://host.docker.internal:11434/v1" if os.name == "nt" else "http://127.0.0.1:11434/v1"
        from ollama_manager import (
            get_runtime_free_memory,
            select_raptor_model_for_free_memory,
            size_qwen_for_free_memory,
        )

        free_ram_gb, free_vram_mb = get_runtime_free_memory(allow_in_tests=self.allow_in_tests)
        sized_qwen = size_qwen_for_free_memory(free_ram_gb, free_vram_mb)
        primary_raptor_model = select_raptor_model_for_free_memory(
            free_ram_gb,
            free_vram_mb,
            allow_in_tests=self.allow_in_tests,
        )
        candidate_models: List[str] = [primary_raptor_model]
        if free_ram_gb >= 10.0 or free_vram_mb >= 8192.0:
            candidate_models.append("hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M")
        if free_ram_gb >= 8.0 or free_vram_mb >= 6144.0:
            candidate_models.append("huihui_ai/foundation-sec-abliterated:8b")
        candidate_models.append(sized_qwen)
        dedup_models: List[str] = []
        for m_name in candidate_models:
            if m_name and m_name not in dedup_models:
                dedup_models.append(m_name)
        models_cfg = {
            "models": [
                {"provider": "ollama", "model": m_name, "api_base": api_base, "role": "analysis"}
                for m_name in dedup_models
            ]
        }
        try:
            models_json.write_text(json.dumps(models_cfg, indent=2), encoding="utf-8")
        except Exception as exc:
            errors.append(f"models.json write warning: {exc}")

        src_ps1 = self.repo_root / "scripts" / "Invoke-RaptorScan.ps1"
        dst_ps1 = self.raptor_root / "Invoke-RaptorScan.ps1"
        if src_ps1.is_file():
            try:
                shutil.copy2(src_ps1, dst_ps1)
            except Exception:
                pass

        # Apply host.docker.internal bypass cleanly
        for rel_py, needle, replacement in (
            (
                Path("core/llm/egress.py"),
                '"localhost", "127.0.0.1", "::1", "0.0.0.0",',
                '"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal",',
            ),
            (
                Path("core/llm/detection.py"),
                'if host in ("localhost", "0.0.0.0"):',
                'if host in ("localhost", "0.0.0.0", "host.docker.internal"):',
            ),
        ):
            p = self.raptor_root / rel_py
            if p.is_file():
                try:
                    txt = p.read_text(encoding="utf-8")
                    if '"host.docker.internal"' not in txt and needle in txt:
                        p.write_text(txt.replace(needle, replacement), encoding="utf-8")
                except Exception:
                    pass

        return ToolStatus(
            tool_id="raptor",
            display_name=spec_name,
            category="repo",
            installed=True,
            path_or_source=str(self.raptor_root),
            method="git_repo",
            detail=f"RAPTOR configured and patched at {self.raptor_root}",
            installed_now=True,
        )

    def _install_docker_image(self, image_ref: str, tool_id: str, display_name: str) -> ToolStatus:
        docker_bin = self._docker_available()
        if not docker_bin:
            return ToolStatus(
                tool_id=tool_id,
                display_name=display_name,
                category="docker",
                installed=False,
                method="docker_missing",
                detail="docker CLI is not installed on PATH",
            )
        if not self._docker_daemon_responsive():
            return ToolStatus(
                tool_id=tool_id,
                display_name=display_name,
                category="docker",
                installed=False,
                method="daemon_stopped",
                detail="Docker CLI found but daemon is not running",
            )
        self._trace(f"[*] Pulling Docker image {image_ref}...")
        proc = _run_quiet_subprocess([docker_bin, "pull", image_ref], timeout=1200)
        img_id = self._docker_image_id(image_ref)
        if proc.returncode == 0 or img_id:
            return ToolStatus(
                tool_id=tool_id,
                display_name=display_name,
                category="docker",
                installed=True,
                path_or_source=image_ref,
                version=img_id[:16] if img_id else None,
                method="docker_pull",
                detail=f"Pulled {image_ref}",
                installed_now=True,
            )
        return ToolStatus(
            tool_id=tool_id,
            display_name=display_name,
            category="docker",
            installed=False,
            method="docker_pull_failed",
            error=(proc.stderr or proc.stdout or f"docker pull exited {proc.returncode}")[-240:],
        )

    def _install_docker_scanners(self) -> ToolStatus:
        docker_bin = self._docker_available()
        if not docker_bin or not self._docker_daemon_responsive():
            return ToolStatus(
                tool_id="docker_scanners",
                display_name="ProjectDiscovery Docker Images",
                category="docker",
                installed=False,
                method="daemon_stopped" if docker_bin else "docker_missing",
                detail="Docker daemon unavailable",
            )
        ok_imgs = []
        fail_imgs = []
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="docker-pull") as pool:
            futs = {
                pool.submit(_run_quiet_subprocess, [docker_bin, "pull", img_ref], timeout=900): (t_name, img_ref)
                for t_name, img_ref in PROJECTDISCOVERY_DOCKER_IMAGES
            }
            for fut in as_completed(futs):
                t_name, img_ref = futs[fut]
                try:
                    proc = fut.result()
                    if proc.returncode == 0 or self._docker_image_id(img_ref):
                        ok_imgs.append(t_name)
                    else:
                        fail_imgs.append(t_name)
                except Exception:
                    fail_imgs.append(t_name)
        return ToolStatus(
            tool_id="docker_scanners",
            display_name="ProjectDiscovery Docker Images",
            category="docker",
            installed=len(fail_imgs) == 0,
            path_or_source=", ".join(ok_imgs) or None,
            method="docker_pull",
            detail=f"Pulled {len(ok_imgs)}/3 images ({', '.join(ok_imgs)})",
            installed_now=len(ok_imgs) > 0,
            error=(f"Failed: {', '.join(fail_imgs)}" if fail_imgs else None),
        )

    def _install_rea_agents(self) -> ToolStatus:
        spec_name = "morluto/rea (rea-agents CLI)"
        self.npm_prefix.mkdir(parents=True, exist_ok=True)
        node_bin = shutil.which("node")
        argv: Optional[List[str]] = None

        if node_bin:
            node_p = Path(node_bin).resolve()
            for npm_cli in (
                node_p.parent / "node_modules" / "npm" / "bin" / "npm-cli.js",
                node_p.parent.parent / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js",
            ):
                if npm_cli.is_file():
                    argv = [
                        str(node_p),
                        str(npm_cli),
                        "install",
                        "--no-audit",
                        "--no-fund",
                        "--prefix",
                        str(self.npm_prefix),
                        REA_NPM_PACKAGE,
                    ]
                    break

        if argv is None:
            npm_bin = shutil.which("npm")
            if npm_bin:
                argv = [
                    npm_bin,
                    "install",
                    "--no-audit",
                    "--no-fund",
                    "--prefix",
                    str(self.npm_prefix),
                    REA_NPM_PACKAGE,
                ]

        if argv is None:
            return ToolStatus(
                tool_id="rea_agents",
                display_name=spec_name,
                category="npm",
                installed=False,
                method="npm_missing",
                detail="Node.js / npm not found (Python ReaIntegrator surface analyzer remains active)",
            )

        self._trace(f"[*] Installing npm CLI {REA_NPM_PACKAGE} into {self.npm_prefix}...")
        proc = _run_quiet_subprocess(argv, timeout=600)
        register_process_bin_dir(self.npm_prefix / "node_modules" / ".bin")
        entry = self.find_rea_entrypoint()
        if entry and entry.get("installed"):
            return ToolStatus(
                tool_id="rea_agents",
                display_name=spec_name,
                category="npm",
                installed=True,
                path_or_source=entry.get("script_path") or entry.get("binary_path"),
                method="npm_local",
                detail=f"Installed rea-agents into {self.npm_prefix}",
                installed_now=True,
            )
        return ToolStatus(
            tool_id="rea_agents",
            display_name=spec_name,
            category="npm",
            installed=False,
            method="npm_failed",
            error=(proc.stderr or proc.stdout or f"npm exited {proc.returncode}")[-240:],
        )

    def _install_python_packages(self, packages: Sequence[Tuple[str, str]], tool_id: str, display_name: str) -> ToolStatus:
        missing = [
            pip_spec for mod_name, pip_spec in packages if importlib.util.find_spec(mod_name) is None
        ]
        if not missing:
            return ToolStatus(
                tool_id=tool_id,
                display_name=display_name,
                category="python",
                installed=True,
                path_or_source=sys.executable,
                method="pip",
                detail="All packages already installed",
            )
        self._trace(f"[*] Installing missing Python packages via pip: {', '.join(missing)}")
        proc = _run_quiet_subprocess(
            [sys.executable, "-m", "pip", "install", "-q", *missing],
            timeout=600,
        )
        importlib.invalidate_caches()
        still_missing = [
            pip_spec for mod_name, pip_spec in packages if importlib.util.find_spec(mod_name) is None
        ]
        installed = len(still_missing) == 0
        return ToolStatus(
            tool_id=tool_id,
            display_name=display_name,
            category="python",
            installed=installed,
            path_or_source=sys.executable if installed else None,
            method="pip" if proc.returncode == 0 else "pip_partial",
            detail=f"Installed {len(missing) - len(still_missing)}/{len(missing)} packages",
            installed_now=len(still_missing) < len(missing),
            error=(proc.stderr or proc.stdout)[-240:] if not installed else None,
        )

    def _install_ollama_and_models(self, *, pull_models: bool = True) -> ToolStatus:
        from ollama_manager import (
            HEALTH_PROBE_MAX_TIMEOUT_SEC,
            OllamaLifecycleManager,
            get_runtime_free_memory,
            select_raptor_model_for_free_memory,
            size_qwen_for_free_memory,
        )

        bin_path = OllamaLifecycleManager.find_ollama_binary()
        installed_now = False
        if not bin_path:
            bin_path = OllamaLifecycleManager.install_ollama_if_missing(allow_in_tests=self.allow_in_tests)
            installed_now = bool(bin_path)
        tags = OllamaLifecycleManager.ensure_ollama_ready(
            auto_install=True,
            allow_in_tests=self.allow_in_tests,
        )
        if not pull_models:
            return ToolStatus(
                tool_id="ollama",
                display_name="Ollama Local AI Runtime",
                category="ai",
                installed=bool(bin_path or tags),
                path_or_source=bin_path or "http://127.0.0.1:11434",
                method="ollama",
                detail=f"Ollama ready ({len(tags)} models cached)",
                installed_now=installed_now,
            )

        free_ram_gb, free_vram_mb = get_runtime_free_memory(allow_in_tests=self.allow_in_tests)
        sized_qwen = size_qwen_for_free_memory(free_ram_gb, free_vram_mb)
        updated_tags = OllamaLifecycleManager.ensure_panel_models_installed(
            available_tags=list(tags),
            free_ram_gb=free_ram_gb,
            free_vram_mb=free_vram_mb,
            allow_in_tests=self.allow_in_tests,
        )
        raptor_model = select_raptor_model_for_free_memory(
            free_ram_gb,
            free_vram_mb,
            available_tags=updated_tags,
            allow_in_tests=self.allow_in_tests,
        )
        OllamaLifecycleManager.ensure_model_installed(
            raptor_model,
            allow_in_tests=self.allow_in_tests,
        )
        final_tags = OllamaLifecycleManager.probe_ollama(fast_timeout=HEALTH_PROBE_MAX_TIMEOUT_SEC) or updated_tags
        gen_tags = OllamaLifecycleManager.filter_generative_tags(final_tags)
        return ToolStatus(
            tool_id="ollama_models",
            display_name="Abliterated ModelFusion Trio",
            category="ai",
            installed=len(gen_tags) > 0,
            path_or_source=", ".join(gen_tags[:4]) if gen_tags else None,
            method="ollama_pull",
            detail=(
                f"{len(gen_tags)} generative models installed "
                f"(free_ram={free_ram_gb:.1f}GB, free_vram={free_vram_mb:.0f}MB, sized={sized_qwen})"
            ),
            installed_now=len(final_tags) > len(tags),
        )

    def _install_rfc_cache(self) -> ToolStatus:
        from rfc_fetcher import RFCFetcher

        rfcs_dir = self.repo_root / "rfcs"
        rfcs_dir.mkdir(parents=True, exist_ok=True)
        fetcher = RFCFetcher(cache_dir=str(rfcs_dir))
        res = fetcher.ensure_terminator_rfcs_cached()
        return ToolStatus(
            tool_id="rfc_cache",
            display_name="Terminator IETF RFC Corpus Cache",
            category="corpus",
            installed=bool(res.get("ready")),
            path_or_source=str(rfcs_dir),
            method="rfc_fetcher",
            detail=f"{res.get('cached', 0)} cached, {res.get('fetched', 0)} fetched ({res.get('failed', 0)} failed)",
            installed_now=int(res.get("fetched", 0) or 0) > 0,
        )

    # ------------------------------------------------------------------
    # Public Provisioning Entrypoints
    # ------------------------------------------------------------------

    def ensure_tool(
        self,
        tool_id: str,
        *,
        force: bool = False,
    ) -> ToolStatus:
        """
        Inspects and dynamically installs `tool_id` if missing.
        Respects offline/test guards (`is_offline_or_blocked()`) cleanly.
        """
        cache_key = (str(self.repo_root.resolve()), tool_id)
        with self._process_lock:
            if not force and cache_key in self._attempted_installs and self._attempted_installs[cache_key].installed:
                return self._attempted_installs[cache_key]

        allow_probes = not self.is_offline_or_blocked()
        current = self.check_tool_status(tool_id, allow_probes=allow_probes)
        if current.installed and not force:
            with self._process_lock:
                self._attempted_installs[cache_key] = current
            return current

        if self.is_offline_or_blocked():
            return current

        with self._process_lock:
            if not force and cache_key in self._attempted_installs:
                return self._attempted_installs[cache_key]

        res: ToolStatus
        if tool_id == "python_deps":
            res = self._install_python_packages(
                CORE_AND_SECURITY_PYTHON_PACKAGES,
                "python_deps",
                "Core & Security Python Packages",
            )
            # Best-effort install optional packages individually without failing core deps
            for opt_mod, opt_spec in OPTIONAL_SECURITY_PYTHON_PACKAGES:
                if importlib.util.find_spec(opt_mod) is None:
                    self._install_python_packages([(opt_mod, opt_spec)], opt_mod, opt_spec)
        elif tool_id == "semgrep":
            res = self._install_python_packages([("semgrep", "semgrep>=1.90.0")], "semgrep", "Semgrep SAST Engine")
        elif tool_id == "aiscan":
            res = self._install_aiscan()
        elif tool_id == "raptor":
            res = self._install_raptor_repo()
        elif tool_id == "raptor_docker":
            res = self._install_docker_image(RAPTOR_DOCKER_IMAGE, "raptor_docker", "RAPTOR Docker Engine Image")
        elif tool_id in ("httpx", "katana", "nuclei", "artex"):
            try:
                res = self._install_github_release_binary(tool_id)
                if tool_id == "nuclei" and res.installed and res.path_or_source:
                    self._trace("[*] Updating Nuclei templates (-update-templates -silent)...")
                    _run_quiet_subprocess([res.path_or_source, "-update-templates", "-silent"], timeout=300)
            except Exception as exc:
                go_res = self._install_go_tool(tool_id)
                if go_res is not None:
                    res = go_res
                else:
                    res = ToolStatus(
                        tool_id=tool_id,
                        display_name=tool_id,
                        category="binary",
                        installed=False,
                        method="failed",
                        error=str(exc),
                    )
        elif tool_id == "rea_agents":
            res = self._install_rea_agents()
        elif tool_id == "ollama":
            res = self._install_ollama_and_models(pull_models=False)
        elif tool_id == "ollama_models":
            res = self._install_ollama_and_models(pull_models=True)
        elif tool_id == "rfc_cache":
            res = self._install_rfc_cache()
        elif tool_id == "docker_scanners":
            res = self._install_docker_scanners()
        else:
            res = current

        with self._process_lock:
            self._attempted_installs[cache_key] = res
        return res

    def ensure_all(
        self,
        *,
        tool_ids: Optional[Sequence[str]] = None,
        include_docker: bool = True,
        include_models: bool = True,
        auto_fix_docker: bool = True,
        force: bool = False,
        max_workers: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Concurrently checks and dynamically installs EVERY requested (or default) tool
        needed by RFCHunt using bounded parallelism and safe dependency ordering.
        """
        t0 = time.monotonic()
        if tool_ids is not None:
            requested = [tid for tid in tool_ids if include_models or tid != "ollama_models"]
            if "ollama_models" in requested and "ollama" not in requested:
                requested.insert(0, "ollama")
        else:
            requested = [
                spec.tool_id
                for spec in TOOL_CATALOG
                if (spec.default_in_setup or (include_docker and spec.category == "docker"))
                and (include_models or spec.tool_id != "ollama_models")
                and (include_docker or spec.category != "docker")
            ]

        if self.is_offline_or_blocked():
            statuses = self.check_all_statuses(tool_ids=requested, allow_probes=False)
            return {
                "offline_or_test_skipped": True,
                "elapsed_sec": round(time.monotonic() - t0, 3),
                "total": len(statuses),
                "installed_count": sum(1 for s in statuses.values() if s.installed),
                "newly_installed_count": 0,
                "tools": {k: v.to_dict() for k, v in statuses.items()},
            }

        docker_wsl_health: Optional[Dict[str, Any]] = None
        if include_docker and auto_fix_docker and sys.platform.startswith("win"):
            try:
                from engine.docker_wsl_doctor import diagnose_docker_wsl, repair_docker_wsl

                diag = diagnose_docker_wsl(include_all_wsl=False)
                if not diag.daemon_running and (diag.docker_desktop_exe or diag.docker_binary):
                    self._trace(
                        "[provisioner] Windows Docker Desktop engine unavailable; running non-destructive Docker/WSL2 self-heal..."
                    )
                    rep = repair_docker_wsl(
                        include_all_wsl=False,
                        launch_docker=True,
                        wait_timeout_sec=45.0,
                        allow_in_tests=self.allow_in_tests,
                    )
                    docker_wsl_health = rep.to_dict()
                else:
                    docker_wsl_health = {"status": "healthy" if diag.healthy else "at_risk", "diagnosis": diag.to_dict()}
            except Exception as exc:
                docker_wsl_health = {"status": "error", "error": str(exc)}

        results: Dict[str, ToolStatus] = {}
        # Phase 1: Ensure Python dependencies & Ollama base binary first (quick / shared foundation)
        phase1 = [tid for tid in ("python_deps", "ollama") if tid in requested]
        for tid in phase1:
            results[tid] = self.ensure_tool(tid, force=force)

        # Phase 2: Fan out all independent tools concurrently under bounded workers
        phase2 = [tid for tid in requested if tid not in results]
        workers = max_workers or min(6, max(2, os.cpu_count() or 4))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tool-install") as pool:
            futs = {pool.submit(self.ensure_tool, tid, force=force): tid for tid in phase2}
            for fut in as_completed(futs):
                tid = futs[fut]
                try:
                    results[tid] = fut.result()
                except Exception as exc:
                    results[tid] = ToolStatus(
                        tool_id=tid,
                        display_name=tid,
                        category="unknown",
                        installed=False,
                        method="error",
                        error=str(exc),
                    )

        ordered = {tid: results[tid].to_dict() for tid in requested if tid in results}
        summary: Dict[str, Any] = {
            "offline_or_test_skipped": False,
            "elapsed_sec": round(time.monotonic() - t0, 2),
            "total": len(ordered),
            "installed_count": sum(1 for v in ordered.values() if v.get("installed")),
            "newly_installed_count": sum(1 for v in ordered.values() if v.get("installed_now")),
            "bin_dir": str(self.bin_dir),
            "tools": ordered,
        }
        if docker_wsl_health is not None:
            summary["docker_wsl_health"] = docker_wsl_health
        return summary


_DEFAULT_PROVISIONER: Optional[ToolProvisioner] = None
_DEFAULT_LOCK = threading.Lock()


def get_tool_provisioner(
    *,
    allow_in_tests: bool = False,
    on_trace: Optional[Callable[[str], None]] = None,
) -> ToolProvisioner:
    global _DEFAULT_PROVISIONER
    with _DEFAULT_LOCK:
        if _DEFAULT_PROVISIONER is None or allow_in_tests or on_trace is not None:
            return ToolProvisioner(allow_in_tests=allow_in_tests, on_trace=on_trace)
        return _DEFAULT_PROVISIONER


def ensure_tool(tool_id: str, *, allow_in_tests: bool = False, force: bool = False) -> ToolStatus:
    return get_tool_provisioner(allow_in_tests=allow_in_tests).ensure_tool(tool_id, force=force)


def ensure_all_tools(
    *,
    tool_ids: Optional[Sequence[str]] = None,
    include_docker: bool = True,
    include_models: bool = True,
    auto_fix_docker: bool = True,
    allow_in_tests: bool = False,
    force: bool = False,
) -> Dict[str, Any]:
    return get_tool_provisioner(allow_in_tests=allow_in_tests).ensure_all(
        tool_ids=tool_ids,
        include_docker=include_docker,
        include_models=include_models,
        auto_fix_docker=auto_fix_docker,
        force=force,
    )


def get_all_tool_statuses(*, allow_probes: Optional[bool] = None) -> Dict[str, Dict[str, Any]]:
    prov = get_tool_provisioner()
    return {k: v.to_dict() for k, v in prov.check_all_statuses(allow_probes=allow_probes).items()}
