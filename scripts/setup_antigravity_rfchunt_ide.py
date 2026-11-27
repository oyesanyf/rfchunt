#!/usr/bin/env python3
"""
Portable Antigravity IDE + RFCHunt Bootstrap Script (`scripts/setup_antigravity_rfchunt_ide.py`).
=================================================================================================
Run this script on another Windows, macOS, or Linux workstation after cloning `oyesanyf/rfchunt`:
    python scripts/setup_antigravity_rfchunt_ide.py

What it configures (strictly zero Windows Registry and zero system PATH mutation):
  1. Installs Python dependencies from `requirements.txt` (optional `--skip-pip`).
  2. Installs the global Antigravity threat-hunting & security-engineering rule into
     `~/.gemini/config/rules/bounty_threat_hunting_and_coding_protocol.md`.
  3. Writes/updates `~/.gemini/config/local_models.json` with local Ollama security/abliterated
     models (including the GLM-5.3 / GLM-4.7-Flash / GLM-4-9B abliterated catalog) and
     Docker-based vLLM configuration (`vllm/vllm-openai:latest` at `http://127.0.0.1:8000/v1`).
  4. Registers `rfchunt-bugbounty` (`bugbounty_mcp_server.py`) inside
     `~/.gemini/config/mcp_config.json` without overwriting existing MCP servers.
  5. Seeds the local gitignored SQLite Program Eligibility DB
     (`reports/ensemble_hunt/program_eligibility.sqlite3`).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
GEMINI_CONFIG_DIR = Path.home() / ".gemini" / "config"
RULES_DIR = GEMINI_CONFIG_DIR / "rules"
LOCAL_MODELS_PATH = GEMINI_CONFIG_DIR / "local_models.json"
MCP_CONFIG_PATH = GEMINI_CONFIG_DIR / "mcp_config.json"

RULE_CONTENT = """# Bug Bounty Threat Hunting & Security Tooling Engineering Protocol

## 1. Zero-Signal-Mismatch & Program Eligibility Gate
- **Never Attempt Unmet Signal Requirements**: Never open, draft, submit, or spend hunt cycles targeting a bug bounty program whose Signal Requirement the user does not currently meet.
- **SQLite Eligibility Cache & Periodic Lift Check**: Persist every checked program's status (`UNLOCKED`, `BLOCKED_SIGNAL`, `PAUSED`, `NOT_FOUND`) in `reports/ensemble_hunt/program_eligibility.sqlite3` via `engine/program_eligibility_db.py` (`ProgramEligibilityDB`). Query `is_eligible()` / `list_unlocked()` before hunting and periodically re-check only `list_due_for_recheck()` entries.
- **Browser Submission & Anti-Bot Discipline**: Always save a **Draft** first for every `poc_verified == true` finding. When requested, attempt clicking **Submit** cleanly; if HackerOne presents a CAPTCHA or anti-bot challenge, stop immediately (never bypass CAPTCHAs) and hand the user the clickable `https://hackerone.com/reports/<id>` URL.

## 2. Freshness-First Anti-Duplicate & Trust-Boundary Law
- **Hunt `<72h` Fresh Commits First**: Prioritize recently merged PRs and `<72h` commits over long-lived code to avoid `Duplicate` closures.
- **Strict External Trust-Boundary Gate**: Only stage findings that cross a genuine external-attacker -> victim trust boundary and pass local non-destructive PoC verification (`poc_verified == true`) against unmodified upstream code.
- **Confidential Local Storage**: Clone target repos and save all hunt reports strictly inside gitignored `reports/ensemble_hunt/`.

## 3. Mandatory Exhaustive Default (`--all --ensemble --proxy auto`)
- Every bug-bounty and threat-hunt scan defaults to `--all --ensemble --proxy auto` (supporting `--ensemble` / `--essemble` / `--essample` and `--target` / `--repo`), fusing `run_unified_all_scans(...)` and `run_exhaustive_local_engines(...)` (Zizmor, Actionlint, GHA Agent Auditor, WebLLMAuditor + live MITRE ATLAS STIX 2.1, Lean 4, RAPTOR/Semgrep, auto-loaded REA `morluto/rea`, Z3 formal verifier, and local LLM verification).

## 4. Local Abliterated/Security Model Fusion & Docker vLLM on Windows
- Prioritize locally installed security/abliterated models (`foundation-sec-abliterated`, `penclaw-GLM-5.3-abliterated`, `GLM-5.3-abliterated-cyber-GLP-77`, `GLM-5.3-abliterated`, `GLM-4.7-Flash-abliterated`, `Gemma-4-12B-OBLITERATED`, `glm-4-9b-chat-abliterated-GGUF`, `LongWriter-glm4-9b-abliterated`) dynamically sized against runtime free RAM/VRAM (400ms probe timeout).
- Never configure native Windows vLLM; large vLLM builds (`OpenYourMind/GLM-5.2-abliterated`, `skyblanket/GLM-5-abliterated`) run strictly via **Docker** (`vllm/vllm-openai:latest`, `http://127.0.0.1:8000/v1`).

## 5. Bounded Concurrency & Windows IDE/Shell Stability Law
- Parallelize with strict bounded concurrency (`ThreadPoolExecutor`, `MaxConcurrentRepos` clamped `1..3`) and isolated per-worker logs merged single-writer after completion.
- Never spawn unbounded concurrent PowerShell/pytest/cargo processes; always pass `-o addopts="" --basetemp <isolated_dir>` to `pytest` and never mutate Windows Registry or system `PATH`.
"""

DEFAULT_LOCAL_MODELS: Dict[str, Any] = {
    "schema_version": 1,
    "default_backend": "auto",
    "ollama": {
        "base_url": "http://127.0.0.1:11434/v1",
        "api_url": "http://127.0.0.1:11434",
        "probe_timeout_ms": 400,
        "preferred_general_models": [
            "qwen2.5:32b",
            "gemma4:26b",
            "qwen2.5:14b",
            "qwen2.5:7b",
            "glm4:9b",
            "deepseek-r1:7b",
            "qwen2.5:3b",
            "qwen2.5:1.5b",
        ],
        "preferred_security_models": [
            "huihui_ai/foundation-sec-abliterated:8b",
            "hf.co/audnai/penclaw-GLM-5.3-abliterated",
            "hf.co/msuiche/GLM-5.3-abliterated-cyber-GLP-77",
            "hf.co/huihui-ai/GLM-5.3-abliterated",
            "huihui_ai/glm-4.7-flash-abliterated:latest",
            "hf.co/huihui-ai/Huihui-GLM-4.7-Flash-abliterated",
            "hf.co/jsantillana/glm-4.7-flash-abliterated",
            "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            "hf.co/bartowski/glm-4-9b-chat-abliterated-GGUF:Q4_K_M",
            "hf.co/byroneverson/glm-4-9b-chat-abliterated",
            "hf.co/byroneverson/LongWriter-glm4-9b-abliterated",
            "deepseek-r1:7b",
            "qwen2.5:7b",
        ],
        "vllm_docker_security_models": {
            "runtime": "docker",
            "image": "vllm/vllm-openai:latest",
            "endpoint": "http://127.0.0.1:8000/v1",
            "models": [
                "OpenYourMind/GLM-5.2-abliterated",
                "skyblanket/GLM-5-abliterated",
            ],
        },
        "fallback_endpoints": [
            "http://127.0.0.1:1234/v1",
            "http://127.0.0.1:8000/v1",
        ],
    },
    "agent_defaults": {
        "lightweight": True,
        "allow_write_tools": False,
        "enforce_workspace_boundary": True,
    },
}


def install_requirements(python_exe: str) -> None:
    req_file = REPO_ROOT / "requirements.txt"
    if not req_file.is_file():
        print(f"[!] requirements.txt not found at {req_file}; skipping pip install.")
        return
    print(f"[*] Installing Python requirements from {req_file}...")
    subprocess.check_call(
        [python_exe, "-m", "pip", "install", "-r", str(req_file), "pytest"],
        cwd=str(REPO_ROOT),
    )


def write_global_rule() -> Path:
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    rule_path = RULES_DIR / "bounty_threat_hunting_and_coding_protocol.md"
    rule_path.write_text(RULE_CONTENT, encoding="utf-8")
    print(f"[+] Wrote global rule: {rule_path}")
    return rule_path


def write_local_models_config() -> Path:
    GEMINI_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if LOCAL_MODELS_PATH.is_file():
        try:
            existing = json.loads(LOCAL_MODELS_PATH.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    else:
        existing = {}

    merged = dict(DEFAULT_LOCAL_MODELS)
    if isinstance(existing, dict):
        merged.update(existing)
        merged_ollama = dict(DEFAULT_LOCAL_MODELS["ollama"])
        if isinstance(existing.get("ollama"), dict):
            merged_ollama.update(existing["ollama"])
        merged_ollama["preferred_security_models"] = DEFAULT_LOCAL_MODELS["ollama"]["preferred_security_models"]
        merged_ollama["vllm_docker_security_models"] = DEFAULT_LOCAL_MODELS["ollama"]["vllm_docker_security_models"]
        merged["ollama"] = merged_ollama

    LOCAL_MODELS_PATH.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Updated local models config: {LOCAL_MODELS_PATH}")
    return LOCAL_MODELS_PATH


def register_mcp_server(python_exe: str) -> Path:
    GEMINI_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if MCP_CONFIG_PATH.is_file():
        try:
            cfg = json.loads(MCP_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            cfg = {}
    else:
        cfg = {}

    if not isinstance(cfg, dict):
        cfg = {}
    servers = cfg.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        servers = {}
        cfg["mcpServers"] = servers

    servers["rfchunt-bugbounty"] = {
        "command": python_exe,
        "args": [str(REPO_ROOT / "bugbounty_mcp_server.py")],
        "cwd": str(REPO_ROOT),
        "env": {
            "RFCHUNT_REPO_ROOT": str(REPO_ROOT),
        },
    }
    MCP_CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Registered MCP server 'rfchunt-bugbounty' in: {MCP_CONFIG_PATH}")
    return MCP_CONFIG_PATH


def seed_eligibility_db() -> None:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from engine.program_eligibility_db import ProgramEligibilityDB

    env_db = os.environ.get("RFCHUNT_ELIGIBILITY_DB", "").strip()
    db = ProgramEligibilityDB(env_db) if env_db else ProgramEligibilityDB()
    counts = db.seed_observed_hackerone_baseline()
    print(f"[+] Seeded SQLite Program Eligibility DB ({db.db_path}): {counts}")


EXTERNAL_CLI_TOOLS: Sequence[str] = (
    "trufflehog",
    "subfinder",
    "httpx",
    "katana",
    "jadx",
    "schemathesis",
)

GO_INSTALL_PACKAGES: Sequence[tuple[str, str]] = (
    ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("katana", "github.com/projectdiscovery/katana/cmd/katana@latest"),
)


def _process_tool_search_dirs() -> List[Path]:
    """Build process-local candidate binary directories (Go bin + repo bin) without mutating PATH."""
    candidates: List[Path] = [Path.home() / "go" / "bin"]
    for env_key in ("HOME", "USERPROFILE"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            candidates.append(Path(raw) / "go" / "bin")
    gopath = os.environ.get("GOPATH", "").strip()
    if gopath:
        candidates.append(Path(gopath) / "bin")
    candidates.append(Path(r"C:\Program Files\Go\bin"))
    candidates.append(REPO_ROOT / "bin")

    deduped: List[Path] = []
    seen: set[str] = set()
    for d in candidates:
        key = str(d)
        if key not in seen:
            seen.add(key)
            deduped.append(d)
    return deduped


def _is_python_httpx_binary(candidate: str) -> bool:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    try:
        from engine.external_scanners import _is_python_httpx_cli_binary

        return bool(_is_python_httpx_cli_binary(candidate))
    except Exception:
        low = str(candidate).replace("\\", "/").lower()
        return "/scripts/httpx" in low or "python" in low


def probe_external_cli_tools() -> Dict[str, Optional[str]]:
    """Probe the 6 external CLI tools using PATH plus in-memory ~/go/bin and Go program dirs."""
    search_dirs = _process_tool_search_dirs()
    suffixes = (".exe", "") if os.name == "nt" else ("",)
    found: Dict[str, Optional[str]] = {}

    for tool in EXTERNAL_CLI_TOOLS:
        aliases = ("jadx", "jadx-gui") if tool == "jadx" else (tool,)
        resolved: Optional[str] = None

        for alias in aliases:
            cand = shutil.which(alias)
            if cand:
                if tool == "httpx" and _is_python_httpx_binary(cand):
                    try:
                        from engine.external_scanners import _find_non_python_httpx_on_path

                        alt = _find_non_python_httpx_on_path(cand)
                        if alt:
                            resolved = alt
                            break
                    except Exception:
                        pass
                    continue
                resolved = cand
                break

        if resolved is None:
            for base_dir in search_dirs:
                if not base_dir.is_dir():
                    continue
                for alias in aliases:
                    for suf in suffixes:
                        cand_path = base_dir / f"{alias}{suf}"
                        if cand_path.is_file():
                            cand_str = str(cand_path)
                            if tool == "httpx" and _is_python_httpx_binary(cand_str):
                                continue
                            resolved = cand_str
                            break
                    if resolved is not None:
                        break
                if resolved is not None:
                    break

        if resolved is None and tool == "schemathesis":
            spec = importlib.util.find_spec("schemathesis")
            if spec is not None:
                resolved = getattr(spec, "origin", None) or "python-module:schemathesis"

        found[tool] = resolved
        if resolved:
            print(f"[+] CLI tool probe: {tool} -> available ({resolved})")
        else:
            print(f"[-] CLI tool probe: {tool} -> unavailable (optional)")

    return found


def install_go_tools() -> Dict[str, Any]:
    """Install ProjectDiscovery Go tools into ~/go/bin when `go` is on PATH (process-scoped env only)."""
    go_bin = shutil.which("go")
    if not go_bin:
        print("[!] 'go' binary not found on PATH; skipping --install-go-tools cleanly.")
        return {"status": "skipped_go_absent", "installed": [], "failed": []}

    proc_env = os.environ.copy()
    proc_env.setdefault("GOPATH", str(Path.home() / "go"))
    installed: List[str] = []
    failed: List[str] = []

    for tool_name, pkg in GO_INSTALL_PACKAGES:
        print(f"[*] Installing {tool_name} via `{go_bin} install {pkg}`...")
        proc = subprocess.run(
            [go_bin, "install", pkg],
            env=proc_env,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if proc.returncode == 0:
            installed.append(tool_name)
            print(f"[+] Installed Go tool: {tool_name}")
        else:
            failed.append(tool_name)
            err_tail = (proc.stderr or proc.stdout or "").strip().splitlines()
            msg = err_tail[-1] if err_tail else f"exit code {proc.returncode}"
            print(f"[!] Optional Go tool install did not succeed for {tool_name}: {msg}")

    return {"status": "completed", "installed": installed, "failed": failed}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap RFCHunt + Antigravity IDE integration on a new workstation (zero Registry/PATH mutation)."
    )
    parser.add_argument(
        "--skip-pip",
        action="store_true",
        help="Skip `pip install -r requirements.txt pytest`.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable path to register in Antigravity MCP config (default: current interpreter).",
    )
    parser.add_argument(
        "--install-go-tools",
        action="store_true",
        help="Attempt `go install` for subfinder, httpx, and katana into ~/go/bin without modifying PATH or Registry.",
    )
    args = parser.parse_args()

    print(f"[*] Bootstrapping RFCHunt Antigravity IDE integration from: {REPO_ROOT}")
    if not args.skip_pip:
        install_requirements(args.python)
    write_global_rule()
    write_local_models_config()
    register_mcp_server(args.python)
    seed_eligibility_db()
    if args.install_go_tools:
        install_go_tools()
    probe_external_cli_tools()
    print("[+] Done! Restart Antigravity IDE to load the global rule, local_models.json, and rfchunt-bugbounty MCP server.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
