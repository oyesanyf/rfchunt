"""
Shared fixtures and helpers for the RFCHunt Ensemble Whiteboard & Lean 4 E2E Suite.

Opaque-box, offline-safe, non-destructive fixtures isolated under `tmp_path`.
Never modifies `D:\\harfile\\rfchunt` source files, `formal/lean4/`, or sibling test suites.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


_MISSING = object()


def pytest_configure(config: pytest.Config) -> None:
    """Register tier1-tier4 markers cleanly when running this suite standalone."""
    config.addinivalue_line("markers", "tier1: Tier 1 core feature coverage tests (F1-F7)")
    config.addinivalue_line("markers", "tier2: Tier 2 boundary, edge-case, and error-handling tests")
    config.addinivalue_line("markers", "tier3: Tier 3 pairwise cross-feature combination tests")
    config.addinivalue_line("markers", "tier4: Tier 4 realistic end-to-end defensive audit scenarios")


def import_contract(module_path: str, symbol: str) -> Any:
    """
    Dynamically import `symbol` from `module_path` inside a test body.
    Fails with a clear AssertionError (never pytest.skip) if M1-M3 contract is missing.
    """
    try:
        mod = importlib.import_module(module_path)
    except Exception as exc:
        raise AssertionError(
            f"Missing contract module {module_path!r} (required for {symbol!r}): {exc}"
        ) from exc
    if not hasattr(mod, symbol):
        raise AssertionError(
            f"Missing contract symbol {symbol!r} in module {module_path!r}"
        )
    return getattr(mod, symbol)


def import_first_available(candidates: Sequence[Tuple[str, str]]) -> Any:
    """Resolve the first available `(module_path, symbol)` pair from `candidates`."""
    errors: List[str] = []
    for mod_path, sym in candidates:
        try:
            mod = importlib.import_module(mod_path)
        except Exception as exc:
            errors.append(f"{mod_path}.{sym}: {exc}")
            continue
        if hasattr(mod, sym):
            return getattr(mod, sym)
        errors.append(f"{mod_path}.{sym}: attribute missing")
    raise AssertionError(
        "Missing contract symbol across candidates: " + "; ".join(errors)
    )


def extract_field(obj: Any, *names: str, default: Any = _MISSING) -> Any:
    """Read the first matching key/attribute from a dict or dataclass/object."""
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    if default is not _MISSING:
        return default
    raise AssertionError(f"Expected one of {names!r} on {type(obj).__name__}: {obj!r}")


_PROXY_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


@pytest.fixture(autouse=True)
def isolated_ensemble_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    """
    Enforce offline, non-destructive safety invariants and restore singleton policy gates
    before and after every test.
    """
    import engine.ollama_concurrency_guard as ocg
    from engine.execution_policy import ExecutionPolicy
    from mcp_server import TargetAuthorizationGate

    orig_targets = set(TargetAuthorizationGate.ALLOWED_TARGETS)
    orig_history = {k: list(v) for k, v in TargetAuthorizationGate._request_history.items()}

    ExecutionPolicy.reset_instance()
    TargetAuthorizationGate.ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "[::1]"}
    TargetAuthorizationGate._request_history.clear()
    ocg._SHARED_GUARD = None

    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("RFCHUNT_AIR_GAPPED", "1")
    monkeypatch.setenv("RFCHUNT_AUTO_INSTALL_TOOLS", "0")
    monkeypatch.setenv("RFCHUNT_AUTO_PULL_MODELS", "0")
    monkeypatch.setenv("RFCHUNT_NO_EMOJI", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")
    monkeypatch.setenv("SEMGREP_SEND_METRICS", "off")
    monkeypatch.setenv("RFCHUNT_OLLAMA_LOCK_PATH", str(tmp_path / "ollama_slot.lock"))
    monkeypatch.delenv("RFCHUNT_ALLOW_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("RFCHUNT_AUTHORIZED_TARGETS", raising=False)
    for pkey in _PROXY_ENV_KEYS:
        monkeypatch.delenv(pkey, raising=False)

    try:
        yield
    finally:
        ocg._SHARED_GUARD = None
        ExecutionPolicy.reset_instance()
        TargetAuthorizationGate.ALLOWED_TARGETS = orig_targets
        TargetAuthorizationGate._request_history.clear()
        for k, hist in orig_history.items():
            TargetAuthorizationGate._request_history[k] = hist


@pytest.fixture
def isolated_out_dir(tmp_path: Path) -> Path:
    out = tmp_path / "e2e_out"
    out.mkdir(parents=True, exist_ok=True)
    return out


@pytest.fixture
def isolated_db_path(tmp_path: Path) -> Path:
    return tmp_path / "e2e_rfchunt.db"


def _run_git(repo_dir: Path, args: Sequence[str], *, env_extra: Optional[Dict[str, str]] = None) -> None:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        env=env,
        timeout=30,
        check=True,
    )
    assert proc.returncode == 0


def add_git_commit(
    repo_dir: Path,
    files: Dict[str, Union[str, bytes]],
    *,
    commit_age_hours: float = 1.0,
    message: str = "update files",
) -> Path:
    """Write files into an existing git repo and commit them at the requested age."""
    for rel_path, content in files.items():
        dest = repo_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            dest.write_bytes(content)
        else:
            dest.write_text(content, encoding="utf-8")

    commit_dt = datetime.now(timezone.utc) - timedelta(hours=float(commit_age_hours))
    iso_ts = commit_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    _run_git(repo_dir, ["add", "-A"])
    _run_git(
        repo_dir,
        ["commit", "-m", message],
        env_extra={"GIT_AUTHOR_DATE": iso_ts, "GIT_COMMITTER_DATE": iso_ts},
    )
    return repo_dir


def make_git_repo(
    base_dir: Path,
    name: str,
    files: Dict[str, Union[str, bytes]],
    *,
    commit_age_hours: float = 1.0,
    message: str = "initial commit",
) -> Path:
    """Create a real local git repository under `base_dir / name` with deterministic commit age."""
    repo_dir = base_dir / name
    repo_dir.mkdir(parents=True, exist_ok=True)
    _run_git(repo_dir, ["init"])
    _run_git(repo_dir, ["config", "user.email", "e2e-tester@rfchunt.local"])
    _run_git(repo_dir, ["config", "user.name", "RFCHunt E2E"])
    return add_git_commit(repo_dir, files, commit_age_hours=commit_age_hours, message=message)


class SyntheticPEBuilder:
    """Self-contained deterministic PE32 / PE32+ / .NET / BSJB binary builder."""

    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_DLL = 0x2000
    SCN_RWX_CODE = 0xE0000020

    @classmethod
    def build_pe(
        cls,
        *,
        is_64bit: bool = True,
        characteristics: int = IMAGE_FILE_EXECUTABLE_IMAGE,
        include_clr_dir: bool = False,
        clr_rva: int = 0x2000,
        clr_size: int = 72,
        include_bsjb: bool = False,
        bsjb_version: str = "v4.0.30319",
        section_characteristics: int = 0x60000020,
        section_alignment: int = 0x1000,
        file_alignment: int = 0x200,
        size_of_image: int = 0x4000,
        section_name: bytes = b".text",
        virtual_size: int = 0x1000,
        raw_data_size: int = 0x200,
    ) -> bytes:
        buf = bytearray(max(0x400, 0x200 + raw_data_size))
        buf[0:2] = b"MZ"
        lfanew = 0x80
        struct.pack_into("<I", buf, 0x3C, lfanew)
        buf[lfanew : lfanew + 4] = b"PE\x00\x00"

        machine = 0x8664 if is_64bit else 0x014C
        opt_hdr_size = 240 if is_64bit else 224
        struct.pack_into(
            "<HHIIIHH",
            buf,
            lfanew + 4,
            machine,
            1,
            0,
            0,
            0,
            opt_hdr_size,
            characteristics,
        )

        opt_offset = lfanew + 24
        magic = 0x020B if is_64bit else 0x010B
        struct.pack_into("<H", buf, opt_offset, magic)
        struct.pack_into("<II", buf, opt_offset + 32, section_alignment, file_alignment)
        struct.pack_into("<II", buf, opt_offset + 56, size_of_image, 0x200)
        struct.pack_into("<HH", buf, opt_offset + 68, 3, 0)

        rva_count_offset = opt_offset + (108 if is_64bit else 92)
        struct.pack_into("<I", buf, rva_count_offset, 16)

        com_offset = rva_count_offset + 4 + (14 * 8)
        if include_clr_dir:
            struct.pack_into("<II", buf, com_offset, clr_rva, clr_size)

        sec_offset = opt_offset + opt_hdr_size
        buf[sec_offset : sec_offset + 8] = (section_name[:8]).ljust(8, b"\x00")
        struct.pack_into(
            "<IIII",
            buf,
            sec_offset + 8,
            virtual_size,
            0x2000,
            raw_data_size,
            0x200,
        )
        struct.pack_into("<I", buf, sec_offset + 36, section_characteristics)

        if include_bsjb:
            ver_bytes = bsjb_version.encode("ascii")
            ver_len = (len(ver_bytes) + 3) & ~3
            bsjb_blob = bytearray()
            bsjb_blob.extend(b"BSJB")
            bsjb_blob.extend(struct.pack("<HHI", 1, 1, 0))
            bsjb_blob.extend(struct.pack("<I", ver_len))
            bsjb_blob.extend(ver_bytes.ljust(ver_len, b"\x00"))
            bsjb_blob.extend(struct.pack("<HH", 0, 2))
            bsjb_blob.extend(struct.pack("<II", 0x100, 0x200))
            bsjb_blob.extend(b"#~\x00\x00")
            bsjb_blob.extend(struct.pack("<II", 0x300, 0x400))
            bsjb_blob.extend(b"#Strings\x00\x00\x00\x00")

            if include_clr_dir and clr_rva == 0x2000 and 0x200 + 0x80 + len(bsjb_blob) <= len(buf):
                struct.pack_into(
                    "<IHHIIIIIIIIIIIIIIII",
                    buf,
                    0x200,
                    72,
                    2,
                    5,
                    0x2080,
                    len(bsjb_blob),
                    1,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                )
                buf[0x280 : 0x280 + len(bsjb_blob)] = bsjb_blob
            else:
                buf.extend(bsjb_blob)

        return bytes(buf)

    @classmethod
    def build_clean_dotnet(cls) -> bytes:
        return cls.build_pe(
            is_64bit=True,
            characteristics=cls.IMAGE_FILE_EXECUTABLE_IMAGE | cls.IMAGE_FILE_DLL,
            include_clr_dir=True,
            include_bsjb=True,
        )

    @classmethod
    def build_cve_2026_108398_dotnet(cls) -> bytes:
        return cls.build_pe(
            is_64bit=True,
            characteristics=cls.IMAGE_FILE_DLL,
            include_clr_dir=True,
            include_bsjb=True,
        )


@pytest.fixture
def pe_builder() -> type[SyntheticPEBuilder]:
    return SyntheticPEBuilder


@pytest.fixture
def http_framing_repo(tmp_path: Path) -> Path:
    """Real git repo with stale parser + fresh <72h HTTP proxy CL/TE desync artifact."""
    repo = make_git_repo(
        tmp_path,
        "http_framing_repo",
        {
            "src/old_parser.py": (
                "def parse_legacy_headers(headers):\n"
                "    return {'cl': headers.get('content-length')}\n"
            ),
        },
        commit_age_hours=24.0 * 90.0,
        message="legacy parser commit",
    )
    add_git_commit(
        repo,
        {
            "src/http_proxy.py": (
                "# CL+TE HTTP/1.1 framing desync candidate (CWE-444)\n"
                "def parse_request_framing(raw_headers: dict) -> tuple[str, int | None]:\n"
                "    # Permissive CL-first proxy accepts Content-Length even when Transfer-Encoding: chunked is present\n"
                "    if 'Content-Length' in raw_headers:\n"
                "        return ('acceptContentLength', int(raw_headers['Content-Length']))\n"
                "    if 'chunked' in raw_headers.get('Transfer-Encoding', '').lower():\n"
                "        return ('acceptChunked', None)\n"
                "    return ('acceptContentLength', 0)\n"
            ),
            "fixtures/cl_te_probe.json": (
                '{"content_lengths": [42], "has_transfer_encoding_chunked": true, "has_bare_lf": false}\n'
            ),
        },
        commit_age_hours=1.0,
        message="fresh permissive CL-first proxy",
    )
    return repo


@pytest.fixture
def policy_guard_repo(tmp_path: Path) -> Path:
    """
    Real git repo triggering WebLLMAuditor + GhaAgentAuditor rules.
    NOTE: Vulnerable files live in `src/` and `.github/workflows/` (never `tests/`)
    because `gha_agent_auditor.py` skips `tests/` subdirectories.
    """
    return make_git_repo(
        tmp_path,
        "policy_guard_repo",
        {
            ".github/workflows/agent_ci.yml": (
                "name: Agent PR Triage\n"
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  triage:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo \"${{ github.event.pull_request.title }}\"\n"
            ),
            "src/auth_guard.ts": (
                "export function isAllowedActor(actor: string): boolean {\n"
                "  if (!actor.endsWith(\"[bot]\")) {\n"
                "    return true;\n"
                "  }\n"
                "  return false;\n"
                "}\n"
            ),
            "src/agent_handler.py": (
                "import subprocess\n"
                "def delete_user(user_id: str) -> str:\n"
                "    return f'deleted {user_id}'\n"
                "@tool\n"
                "def admin_agent_tool(tool_args: dict) -> str:\n"
                "    target = tool_args.get('user_id', '')\n"
                "    subprocess.run(['echo', target], check=False)\n"
                "    return delete_user(target)\n"
            ),
            "src/post_comments.ts": (
                "import * as fs from 'fs';\n"
                "export function readBuffer(): string {\n"
                "  return fs.readFileSync('/tmp/inline-comments-buffer.jsonl', 'utf8');\n"
                "}\n"
            ),
            "scripts/poc_check.py": (
                "print('VERIFIED_NON_DESTRUCTIVE')\n"
            ),
        },
        commit_age_hours=2.0,
        message="add agent workflow and handlers",
    )


@pytest.fixture
def dotnet_pe_repo(tmp_path: Path) -> Path:
    """Real git repo containing valid signed-layout .NET PE and CVE-2026-108398 anomaly PE."""
    return make_git_repo(
        tmp_path,
        "dotnet_pe_repo",
        {
            "bin/clean_signed.dll": SyntheticPEBuilder.build_clean_dotnet(),
            "bin/cve_2026_108398_bypass.dll": SyntheticPEBuilder.build_cve_2026_108398_dotnet(),
            "README.md": "# Synthetic .NET PE Audit Fixture\n",
        },
        commit_age_hours=3.0,
        message="add synthetic dotnet pe artifacts",
    )


@pytest.fixture
def clean_hardened_repo(tmp_path: Path) -> Path:
    """Real git repo with clean, sanitized code and zero vulnerabilities (non-fabrication check)."""
    return make_git_repo(
        tmp_path,
        "clean_hardened_repo",
        {
            "src/math_utils.py": (
                "def add(a: int, b: int) -> int:\n"
                "    return a + b\n\n"
                "def sanitize_for_llm_prompt(text: str) -> str:\n"
                "    return text.replace('<', '&lt;').replace('>', '&gt;')\n"
            ),
            "src/safe_prompt.py": (
                "from src.math_utils import sanitize_for_llm_prompt\n\n"
                "def build_safe_message(external_data: str) -> dict:\n"
                "    safe_body = sanitize_for_llm_prompt(external_data)\n"
                "    return {'role': 'user', 'content': safe_body}\n"
            ),
        },
        commit_age_hours=4.0,
        message="clean hardened module",
    )


@pytest.fixture
def multi_module_repo(tmp_path: Path) -> Path:
    """Real git repo combining stale + fresh commits, HTTP framing, policy violations, and .NET PE."""
    repo = make_git_repo(
        tmp_path,
        "multi_module_repo",
        {
            "src/legacy_service.py": (
                "def legacy_ping() -> str:\n"
                "    return 'pong'\n"
            ),
        },
        commit_age_hours=24.0 * 90.0,
        message="legacy baseline",
    )
    add_git_commit(
        repo,
        {
            ".github/workflows/release_agent.yml": (
                "name: Release Agent\n"
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  check:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo \"${{ github.event.pull_request.title }}\"\n"
            ),
            "src/http_proxy.py": (
                "# CL+TE HTTP/1.1 framing desync candidate (CWE-444)\n"
                "def forward(cl_val: int) -> tuple[str, int]:\n"
                "    return ('acceptContentLength', cl_val)\n"
            ),
            "src/agent_tool.py": (
                "import subprocess\n"
                "def delete_user(uid: str) -> str:\n"
                "    return uid\n"
                "@tool\n"
                "def run_admin(tool_args: dict) -> str:\n"
                "    subprocess.run(['echo', str(tool_args)], check=False)\n"
                "    return delete_user(str(tool_args))\n"
            ),
            "bin/cve_2026_108398_bypass.dll": SyntheticPEBuilder.build_cve_2026_108398_dotnet(),
            "scripts/poc_check.py": "print('VERIFIED_NON_DESTRUCTIVE')\n",
        },
        commit_age_hours=1.5,
        message="fresh multi-domain feature commit",
    )
    return repo


@pytest.fixture
def lean_workspace_copy(tmp_path: Path) -> Path:
    """Copy `formal/lean4/` (excluding `.lake/`) to `tmp_path / 'lean4'` for safe mutation tests."""
    src = REPO_ROOT / "formal" / "lean4"
    dest = tmp_path / "lean4"
    shutil.copytree(
        src,
        dest,
        ignore=shutil.ignore_patterns(".lake", "__pycache__"),
    )
    return dest


@pytest.fixture
def degraded_toolchain_env(monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    """
    Simulate an offline host where external binaries (`docker`, `wsl`, `lean`, `lake`,
    `rfchunt-lean-oracle`, `angr`, `klee`, `semgrep`) are absent without mutating host PATH.
    """
    import engine.docker_wsl_doctor as dwd
    import engine.lean_formal_verifier as lfv
    import engine.linux_poc_runner as lpr

    def _activate() -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        monkeypatch.setattr(lpr.shutil, "which", lambda _name: None)
        monkeypatch.setattr(lfv.shutil, "which", lambda _name: None)
        disabled_diag = dwd.DockerWSLDiagnosis(
            platform="windows",
            docker_binary=None,
            docker_desktop_exe=None,
            daemon_running=False,
            server_version=None,
            issues=["Docker disabled in degraded_toolchain_env"],
            healthy=False,
        )
        for mod in (lpr, dwd):
            monkeypatch.setattr(mod, "find_docker_binary", lambda *_a, **_kw: None)
            monkeypatch.setattr(mod, "probe_docker_daemon", lambda *_a, **_kw: (False, None))
            monkeypatch.setattr(mod, "diagnose_docker_wsl", lambda *_a, **_kw: disabled_diag)
        monkeypatch.setattr(dwd, "find_docker_desktop_exe", lambda *_a, **_kw: None)
        monkeypatch.setattr(lfv, "find_lean_oracle_binary", lambda *_a, **_kw: None)
        monkeypatch.setattr(lpr, "_safe_find_spec", lambda _mod: None)

    return _activate


def make_verified_transcript(
    repo_path: Union[str, Path],
    *,
    language: str = "python",
    backend: str = "docker",
    status: str = "passed",
    exit_code: Optional[int] = 0,
    stdout: str = "VERIFIED_NON_DESTRUCTIVE",
) -> Any:
    from engine.linux_poc_runner import VerifiableTranscript

    return VerifiableTranscript(
        language=language,
        backend=backend,
        status=status,
        exit_code=exit_code,
        command=["python3", "scripts/poc_check.py"],
        image="python:3.12-slim" if backend == "docker" else "wsl2-linux",
        repo_path=str(repo_path),
        started_at_utc=datetime.now(timezone.utc).isoformat(),
        elapsed_ms=85.0,
        stdout=stdout,
        stderr="",
    )


def run_cli_subprocess(
    script_rel: str,
    args: Sequence[str],
    *,
    env_extra: Optional[Dict[str, str]] = None,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    """Execute a RFCHunt CLI entry point in a clean offline subprocess (`shell=False`)."""
    script_path = REPO_ROOT / script_rel
    env = os.environ.copy()
    env.update(
        {
            "CI": "true",
            "RFCHUNT_OFFLINE": "1",
            "RFCHUNT_AIR_GAPPED": "1",
            "RFCHUNT_AUTO_INSTALL_TOOLS": "0",
            "RFCHUNT_AUTO_PULL_MODELS": "0",
            "RFCHUNT_NO_EMOJI": "1",
            "NO_COLOR": "1",
            "PYTHONIOENCODING": "utf-8",
            "SEMGREP_SEND_METRICS": "off",
        }
    )
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-u", str(script_path), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        env=env,
        timeout=timeout,
    )
