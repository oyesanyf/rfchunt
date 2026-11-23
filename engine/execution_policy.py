"""
Deterministic LLM Action Governance & Scanner-Defined Confinement Layer.

Enforces fail-closed deterministic policy boundaries between LLM agents,
autonomous subagents, and physical execution sinks:
1. Scanner Task Confinement (Restricts execution strictly to 8+ approved scanner tasks)
2. Target Authorization & SSRF Invariant Enforcement
3. Destructive Action Gating (--allow-destructive / RFCHUNT_ALLOW_DESTRUCTIVE=1)
4. Host OS / Shell Execution Blocking (Rejects cmd.exe, sh, bash, curl, whoami, etc.)
5. File Write Confinement (Confines file writes to designated reports/out/runs directories)
6. Offensive Capability Preservation (Aggressive HTTP verbs & desync framing payloads proceed unhindered on authorized targets)
7. Untrusted Remote Response Sanitization & Prompt Injection Defense
8. Strict Schema Validation with Deterministic Baseline Fallbacks
"""

from __future__ import annotations

from collections.abc import Sequence
import csv
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import socket
import sys
import tempfile
import threading
from typing import Any, Dict, List, Optional, Set, Tuple, Union


from urllib.parse import urlparse

_EXCLUDED_SCANNER_STEMS: Set[str] = {"nmap", "ffuf", "dalfox", "sqlmap"}

_DOCKER_PAYLOAD_SHELLS_AND_WRAPPERS: Set[str] = {
    "sh", "sh.exe",
    "bash", "bash.exe",
    "zsh", "zsh.exe",
    "dash", "dash.exe",
    "ksh", "ksh.exe",
    "csh", "csh.exe",
    "ash", "ash.exe",
    "fish", "fish.exe",
    "tcsh", "tcsh.exe",
    "mksh", "mksh.exe",
    "busybox", "busybox.exe",
    "cmd", "cmd.exe",
    "powershell", "powershell.exe",
    "pwsh", "pwsh.exe",
    "env", "env.exe",
    "sudo", "sudo.exe",
    "doas", "su", "su.exe",
    "runas", "runas.exe",
    "xargs", "xargs.exe",
    "nohup", "nohup.exe",
    "timeout", "timeout.exe",
    "nice", "ionice", "stdbuf", "chroot", "strace", "script",
    "wsl", "wsl.exe",
    "mshta", "mshta.exe",
    "wscript", "wscript.exe",
    "cscript", "cscript.exe",
    "rundll32", "rundll32.exe",
}

_CRITICAL_POSIX_MOUNT_PREFIXES: Tuple[str, ...] = (
    "/etc",
    "/var/run/docker.sock",
    "/var/run",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/root",
)


_ALLOWED_EXTERNAL_SCANNER_BINARIES: Set[str] = {
    "httpx",
    "httpx.exe",
    "katana",
    "katana.exe",
    "nuclei",
    "nuclei.exe",
    "docker",
    "docker.exe",
    "ollama",
    "ollama.exe",
}

_PYTHON_BIN_RE = re.compile(r"^pythonw?(?:\d+(?:\.\d+)*t?)?(?:\.exe)?$")


_WIN_DRIVE_PREFIX_RE = re.compile(r"^([a-zA-Z]):(.*)$")


def _is_unc_path(raw_path: str) -> bool:
    """Returns True for any NT, UNC, or Windows device namespace path (including mixed-slash \\/ and /\\)."""
    s = str(raw_path or "").strip()
    if not s:
        return False
    norm = s.replace("\\", "/")
    norm_l = norm.lower()
    if norm.startswith("//"):
        return True
    if norm_l in ("/??", "/device", "/global??", "/globalroot", "/dosdevices") or norm_l.startswith(
        ("/??/", "/device/", "/global??/", "/globalroot/", "/dosdevices/")
    ):
        return True
    for cls in (PureWindowsPath, Path):
        try:
            if cls(s).drive.startswith(("\\\\", "//")):
                return True
        except Exception:
            pass
    return False


def _is_drive_relative_or_colon_unsafe(raw_path: str) -> bool:
    """
    Returns True for empty strings, Windows drive-relative paths (e.g. `C:foo`,
    `C:scripts/x`, `C:`), or NTFS Alternate Data Streams / stray colons.
    """
    s = str(raw_path or "").strip()
    if not s:
        return True
    norm = s.replace("\\", "/")
    m = _WIN_DRIVE_PREFIX_RE.match(norm)
    if m:
        rest = m.group(2)
        if not rest.startswith("/") or ":" in rest:
            return True
    elif ":" in norm:
        return True
    try:
        win_d = PureWindowsPath(s).drive
        if win_d and win_d.startswith(("\\\\", "//")):
            return True
    except Exception:
        pass
    return False


def _validate_canonical_path_syntax(
    raw_path: Any, *, allow_trailing_slash: bool = False
) -> Optional[str]:
    """
    Pure-lexical canonical path validator with ZERO filesystem touches.
    Returns None if valid, else a short human-readable deny reason.
    """
    if not isinstance(raw_path, str):
        return "path must be a string"
    if not raw_path or not raw_path.strip():
        return "empty path"
    if raw_path != raw_path.strip():
        return "leading/trailing whitespace obfuscation forbidden"
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_path):
        return "control/NUL character forbidden in path"
    if _is_unc_path(raw_path):
        return "NT/UNC/device path forbidden"
    if _is_drive_relative_or_colon_unsafe(raw_path):
        return "drive-relative path or ADS/unsafe colon forbidden"

    norm = raw_path.replace("\\", "/")
    if not allow_trailing_slash and norm.endswith("/"):
        return "trailing path separator forbidden"

    seg_str = norm[2:] if _WIN_DRIVE_PREFIX_RE.match(norm) else norm
    raw_parts = [p for p in seg_str.split("/") if p]
    if not raw_parts and not allow_trailing_slash:
        return "bare root or empty path segments forbidden"

    for part in raw_parts:
        if (
            part == ".."
            or part.rstrip(". ") == ".."
            or part.endswith(":..")
            or (part != "." and part.strip(". ") == "")
        ):
            return "path traversal '..' forbidden"
        if part != "." and (part.endswith(".") or part.endswith(" ")):
            return "Win32 trailing dot/space obfuscation forbidden"

    if raw_parts and raw_parts[-1] == ".":
        return "directory '.' target forbidden"

    return None


def _extract_basename_lower(raw_token: str) -> str:
    """Pure-lexical OS-independent basename extractor (zero FS touches)."""
    s = str(raw_token or "").strip()
    if not s:
        return ""
    norm = s.replace("\\", "/")
    m = _WIN_DRIVE_PREFIX_RE.match(norm)
    if m:
        norm = m.group(2)
    norm = norm.rstrip("/")
    if not norm:
        return ""
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return ""
    return parts[-1].rstrip(". ").lower()


def _is_python_binary_name(binary_name: str) -> bool:
    return bool(_PYTHON_BIN_RE.fullmatch(str(binary_name or "").strip().lower()))


def _is_safe_aiscan_name(binary_name: str) -> bool:
    return (
        binary_name in {"aiscan", "aiscan.exe"}
        or binary_name.startswith(("aiscan-", "aiscan_"))
    ) and not binary_name.endswith((".sh", ".bat", ".cmd", ".ps1", ".vbs", ".js"))


_ALLOWED_REA_SUBCOMMANDS: Set[str] = {
    "analyze-javascript-application",
    "analyze-website",
    "--version",
    "-v",
    "--help",
    "-h",
}


def _is_safe_rea_name(binary_name: str) -> bool:
    return binary_name in {"rea-agents", "rea-agents.exe", "rea", "rea.exe"}


def _is_safe_rea_node(tokens: Sequence[str]) -> bool:
    """
    Permits `[node(.exe), <repo_root>/tools/npm/node_modules/rea-agents/scripts/rea.mjs, <subcmd>, ...]`
    strictly on Windows/POSIX so npm CLI `rea-agents` runs via native `node` without shell `.cmd` wrappers.
    """
    if len(tokens) < 3:
        return False
    t0 = str(tokens[0] or "")
    t1 = str(tokens[1] or "")
    if _validate_canonical_path_syntax(t0) is not None or _validate_canonical_path_syntax(t1) is not None:
        return False
    base_bin = _extract_basename_lower(t0)
    if base_bin not in {"node", "node.exe"}:
        return False
    try:
        repo_npm = (Path(__file__).resolve().parent.parent / "tools" / "npm" / "node_modules" / "rea-agents" / "scripts" / "rea.mjs").resolve()
        resolved_script = Path(t1).resolve()
        if resolved_script != repo_npm:
            return False
    except (OSError, RuntimeError):
        return False
    return _validate_rea_tokens(["rea-agents", *[str(t) for t in tokens[2:]]]) is None


def _validate_rea_tokens(tokens: List[str]) -> Optional[str]:
    if len(tokens) < 2:
        return "Unrequested host OS command execution blocked: rea-agents requires an approved web/JS subcommand."
    sub = tokens[1].strip().lower()
    if sub not in _ALLOWED_REA_SUBCOMMANDS:
        return (
            f"Unrequested host OS command execution blocked: rea-agents subcommand '{tokens[1]}' "
            f"is outside web/JS/Electron surface scope (allowed: {sorted(_ALLOWED_REA_SUBCOMMANDS)})."
        )
    for arg in tokens[2:]:
        arg_l = arg.strip().lower()
        if any(b in arg_l for b in ("ghidra", "ida64", "idat", "hopper", "radare2", "decompile-binary")):
            return f"Unrequested host OS command execution blocked: binary decompiler option '{arg}' is forbidden."
    return None


def _binary_tool_family(
    name: str,
    *,
    is_raptor_ps1: bool = False,
    is_rea_node: bool = False,
) -> Optional[str]:
    n = str(name or "").strip().lower()
    if not n:
        return None
    stem = n[:-4] if n.endswith(".exe") else n
    if _is_python_binary_name(n):
        return "python"
    if _is_safe_aiscan_name(n):
        return "aiscan"
    if _is_safe_rea_name(n):
        return "rea"
    if is_rea_node and n in ("node", "node.exe"):
        return "node"
    if n in _ALLOWED_EXTERNAL_SCANNER_BINARIES:
        return stem
    if is_raptor_ps1 and n in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
        return "powershell"
    return None


def _is_http_url_token(arg: str) -> bool:
    arg_s = str(arg or "").strip()
    arg_l = arg_s.lower()
    if arg_l.startswith(("http://", "https://")):
        return True
    if arg_s.startswith("-") and "=" in arg_s:
        val_l = arg_s.split("=", 1)[1].strip().lower()
        return val_l.startswith(("http://", "https://"))
    return False


_URL_TARGET_FLAGS: Set[str] = {
    "-u", "--url", "-url",
    "-target", "--target",
    "-host", "--host",
    "-proxy", "--proxy", "-http-proxy", "--http-proxy",
    "-https-proxy", "--https-proxy",
    "-proxy-url", "--proxy-url",
    "-socks-proxy", "--socks-proxy",
    "-socks5-proxy", "--socks5-proxy",
    "-endpoint", "--endpoint",
    "-connect", "--connect", "--connect-to",
    "-base-url", "--base-url",
    "-interactsh-server", "--interactsh-server",
    "-interactsh-url", "--interactsh-url",
    "-callback-url", "--callback-url",
}

_NUMERIC_OR_SCALAR_NON_TARGET_FLAGS: Set[str] = {
    "-body-read-limit", "--body-read-limit",
    "-max-host-error", "--max-host-error",
    "--maxfail",
    "-timeout", "--timeout",
    "-read-timeout", "--read-timeout",
    "-write-timeout", "--write-timeout",
    "-dial-timeout", "--dial-timeout",
    "-crawl-duration", "--crawl-duration",
    "-max-size", "--max-size",
    "-response-size-to-save", "--response-size-to-save",
    "-response-size-to-read", "--response-size-to-read",
    "-rl", "-rate-limit", "--rate-limit",
    "-rlm", "-rate-limit-minute", "--rate-limit-minute",
    "-retries", "--retries",
    "-threads", "--threads",
    "-c", "-concurrency", "--concurrency",
    "-p", "--port", "-ports", "--ports",
    "-delay", "--delay",
    "-depth", "--depth",
    "-bulk-size", "--bulk-size", "-bs",
    "-max-redirects", "--max-redirects",
    "-max-hr", "--max-hr",
    "-n", "--durations",
    "--memory", "--memory-reservation", "--memory-swap", "--memory-swappiness",
    "--cpus", "--cpu-shares", "--cpu-period", "--cpu-quota",
    "--pids-limit", "--shm-size", "--ulimit",
    "--blkio-weight", "--oom-score-adj", "--stop-timeout",
}


def _is_non_canonical_ipv4_host(host: str) -> bool:
    """
    Returns True if `host` is a non-canonical IPv4 representation (pure integer,
    hex `0x...`, octal leading-zero segments, or shortened `<4`-octet dotted IPv4)
    that `socket.inet_aton`/Go/cURL can resolve to an IPv4 address while failing
    strict 4-octet `ipaddress.IPv4Address` parsing. Does NOT invoke DNS.
    """
    h = str(host or "").strip().lower()
    if not h:
        return False
    try:
        ipaddress.IPv4Address(h)
        return False
    except ValueError:
        pass

    parts = h.split(".")
    if 1 <= len(parts) <= 4 and all(re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", p) for p in parts):
        return True

    try:
        socket.inet_aton(h)
        return True
    except OSError:
        return False


def _extract_token_host_candidate(
    tok_s: str, *, allow_bare_decimal: bool = True
) -> Tuple[Optional[str], bool]:
    """
    Returns (host, has_url_scheme) for a subprocess argument token.
    - When '://' is present (including '-flag=http://...'), returns (hostname, True).
    - When '://' is absent, returns (ip_literal_or_non_canonical_ipv4, False) ONLY if the
      token (or '-flag=val') is an IP literal or unambiguous obfuscated IPv4 form,
      avoiding DNS lookups and avoiding false positives on normal numeric flags.
    """
    if "://" in tok_s:
        eq_idx = tok_s.find("=")
        scheme_idx = tok_s.find("://")
        url_part = tok_s[eq_idx + 1 :].strip() if (eq_idx != -1 and eq_idx < scheme_idx) else tok_s
        after_scheme = url_part.split("://", 1)[1]
        authority = re.split(r"[/?#]", after_scheme, maxsplit=1)[0]
        if "\\" in authority:
            return "", True
        try:
            host = (urlparse(url_part).hostname or "").strip().lower().rstrip(".")
        except ValueError:
            host = ""
        return host, True

    val = tok_s.split("=", 1)[1].strip() if (tok_s.startswith("-") and "=" in tok_s) else tok_s
    if not val or val.startswith("-"):
        return None, False

    is_win_drive_path = bool(re.match(r"^[a-zA-Z]:[/\\]", val))
    is_host_port_or_path = (
        not is_win_drive_path
        and not val.startswith("/")
        and (":" in val or "/" in val)
    )

    host_port = val.split("/", 1)[0].strip()
    if host_port.startswith("[") and "]" in host_port:
        cand = host_port[1 : host_port.index("]")].strip().lower()
    elif host_port.count(":") == 1:
        cand = host_port.split(":", 1)[0].strip().lower()
    else:
        cand = host_port.lower()

    if not cand:
        return None, False
    try:
        ipaddress.ip_address(cand)
        return cand, False
    except ValueError:
        pass

    cand_clean = cand.rstrip(".")
    if _is_non_canonical_ipv4_host(cand_clean):
        if cand_clean.startswith("0x"):
            return cand_clean, False
        if cand_clean.isdigit() and int(cand_clean) > 65535:
            if allow_bare_decimal or is_host_port_or_path:
                return cand_clean, False
            return None, False
        if "." in cand_clean:
            parts = cand_clean.split(".")
            if len(parts) == 4 or any(p.startswith(("0x", "0")) and len(p) > 1 for p in parts):
                return cand_clean, False
            try:
                packed = socket.inet_aton(cand_clean)
                unpacked = ipaddress.IPv4Address(packed)
                if (
                    unpacked.is_private
                    or unpacked.is_loopback
                    or unpacked.is_link_local
                    or unpacked.is_unspecified
                    or unpacked.is_multicast
                    or unpacked.is_reserved
                ):
                    return cand_clean, False
            except OSError:
                return cand_clean, False
    return None, False


_DOCKER_EXEC_VALUE_FLAGS: Set[str] = {
    "--detach-keys", "-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir",
}

_DOCKER_RUN_VALUE_FLAGS: Set[str] = {
    "-a", "--attach", "--add-host", "--annotation",
    "--blkio-weight", "--blkio-weight-device",
    "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile",
    "--cpu-period", "--cpu-quota", "--cpu-rt-period", "--cpu-rt-runtime",
    "-c", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems",
    "--detach-keys", "--device", "--device-cgroup-rule",
    "--device-read-bps", "--device-read-iops", "--device-write-bps", "--device-write-iops",
    "--dns", "--dns-option", "--dns-search", "--domainname",
    "--entrypoint", "-e", "--env", "--env-file", "--expose",
    "--gpus", "--group-add",
    "--health-cmd", "--health-interval", "--health-retries", "--health-start-period", "--health-timeout",
    "-h", "--hostname", "--ip", "--ip6", "--ipc", "--isolation",
    "--kernel-memory", "-l", "--label", "--label-file", "--link", "--link-local-ip",
    "--log-driver", "--log-opt", "--mac-address",
    "-m", "--memory", "--memory-reservation", "--memory-swap", "--memory-swappiness",
    "--mount", "--name", "--network", "--net", "--network-alias", "--net-alias",
    "--oom-score-adj", "--pid", "--pids-limit", "--platform", "-p", "--publish", "--pull",
    "--restart", "--runtime", "--security-opt", "--shm-size",
    "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl",
    "--tmpfs", "--ulimit", "-u", "--user", "--userns", "--uts",
    "-v", "--volume", "--volumes-from", "-w", "--workdir",
}


_ALLOWED_DOCKER_SUBCOMMANDS: Set[Tuple[str, str]] = {
    ("", "run"),
    ("container", "run"),
    ("image", "inspect"),
    ("compose", "ps"),
}


def _resolve_docker_subcommand_info(tokens: Sequence[str]) -> Tuple[str, str, int, int, Set[str]]:
    """
    Returns (subcmd_group, subcmd, subcmd_idx, target_idx, val_flags) for a Docker CLI command,
    where `subcmd_group` is e.g. "", "container", "compose", "image", "service", "stack", "system",
    and `target_idx` is the index of `<image>`/`<container>` for run/exec/create, or -1.
    """
    subcmd_group = ""
    subcmd = ""
    subcmd_idx = -1
    i = 1
    while i < len(tokens):
        t = str(tokens[i]).strip()
        if not t:
            i += 1
            continue
        if t in ("-H", "-c", "-l") or t.lower() in (
            "--config", "--context", "--host", "--log-level",
            "--tlscacert", "--tlscert", "--tlskey",
        ):
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        subcmd = t.lower()
        subcmd_idx = i
        break

    _docker_subcmd_value_flags = {
        "-f", "--file",
        "-p", "--project-name",
        "--project-directory",
        "--env-file",
        "--profile",
        "--ansi",
        "--progress",
        "--parallel",
        "-c", "--compose-file",
        "-H", "--host", "--context", "--config", "--log-level",
    }
    if subcmd in ("container", "compose", "service", "stack", "image", "system") and subcmd_idx != -1:
        subcmd_group = subcmd
        nested_subcmd = ""
        nested_idx = -1
        i = subcmd_idx + 1
        while i < len(tokens):
            t = str(tokens[i]).strip()
            if not t:
                i += 1
                continue
            t_l = t.lower()
            if t in ("-f", "-p", "-c", "-H") or t_l in _docker_subcmd_value_flags:
                i += 2
                continue
            if t.startswith("-"):
                i += 1
                continue
            nested_subcmd = t_l
            nested_idx = i
            break
        if nested_subcmd:
            subcmd = nested_subcmd
            subcmd_idx = nested_idx
        else:
            subcmd = ""

    target_idx = -1
    val_flags: Set[str] = _DOCKER_EXEC_VALUE_FLAGS if subcmd == "exec" else _DOCKER_RUN_VALUE_FLAGS
    if subcmd in ("run", "exec", "create") and subcmd_idx != -1:
        k = subcmd_idx + 1
        while k < len(tokens):
            t = str(tokens[k]).strip()
            if not t:
                k += 1
                continue
            t_l = t.lower()
            if t == "--":
                if k + 1 < len(tokens):
                    target_idx = k + 1
                break
            if t_l in val_flags:
                if t_l == "-c" and not (k + 1 < len(tokens) and str(tokens[k + 1]).strip().isdigit()):
                    k += 1
                    continue
                k += 2
                continue
            if t.startswith("-"):
                k += 1
                continue
            target_idx = k
            break

    return subcmd_group, subcmd, subcmd_idx, target_idx, val_flags


def _docker_subcmd_and_target_idx(tokens: Sequence[str]) -> Tuple[str, int, int, Set[str]]:
    """
    Returns (subcmd, subcmd_idx, target_idx, val_flags) for a Docker CLI command,
    where `target_idx` is the index of `<image>`/`<container>` for run/exec/create, or -1.
    """
    _, subcmd, subcmd_idx, target_idx, val_flags = _resolve_docker_subcommand_info(tokens)
    return subcmd, subcmd_idx, target_idx, val_flags


def _validate_command_ssrf_tokens(tokens: Sequence[str]) -> Optional[str]:
    """
    Validates URL and IP-literal tokens in subprocess arguments against SSRF invariants,
    including non-canonical IPv4 obfuscation (decimal, hex, octal, shortened, 0) without
    performing DNS lookups on domain hostnames.
    """
    from engine.safe_network_validator import is_explicit_loopback_host, validate_target_host

    bin_name = PurePosixPath(str(tokens[0]).strip().replace("\\", "/")).name.lower() if tokens else ""
    bin_family = _binary_tool_family(bin_name)
    docker_subcmd = ""
    docker_target_idx = -1
    if bin_family == "docker":
        docker_subcmd, _, docker_target_idx, _ = _docker_subcmd_and_target_idx(tokens)

    for idx, tok in enumerate(tokens[1:], start=1):
        tok_s = str(tok).strip()
        if not tok_s:
            continue
        is_flag_eq = tok_s.startswith("-") and "=" in tok_s
        eq_flag_l = tok_s.split("=", 1)[0].strip().lower() if is_flag_eq else ""
        prev_l = str(tokens[idx - 1]).strip().lower() if idx >= 1 else ""
        if (
            not is_flag_eq
            and prev_l in ("-h", "-header", "-headers")
            and ":" in tok_s
            and bin_family in ("httpx", "katana", "nuclei")
        ):
            continue

        is_docker_user_flag_val = (
            bin_family == "docker"
            and (
                (not is_flag_eq and prev_l == "--user")
                or (is_flag_eq and eq_flag_l == "--user")
                or (
                    docker_subcmd in ("run", "exec", "create")
                    and (docker_target_idx == -1 or idx < docker_target_idx)
                    and ((not is_flag_eq and prev_l == "-u") or (is_flag_eq and eq_flag_l == "-u"))
                )
            )
        )
        is_u_target_disabled = (
            bin_family == "python"
            or (
                bin_family == "docker"
                and (
                    docker_subcmd not in ("run", "exec", "create")
                    or docker_target_idx == -1
                    or idx < docker_target_idx
                )
            )
        )
        effective_target_flags = (
            _URL_TARGET_FLAGS - {"-u"} if is_u_target_disabled else _URL_TARGET_FLAGS
        )

        is_target_flag_val = (
            (not is_flag_eq and prev_l in effective_target_flags)
            or (is_flag_eq and eq_flag_l in effective_target_flags)
        )
        is_non_target_flag_val = (
            (is_flag_eq and eq_flag_l not in effective_target_flags)
            or (not is_flag_eq and prev_l in _NUMERIC_OR_SCALAR_NON_TARGET_FLAGS)
            or is_docker_user_flag_val
        )

        cand_host, has_scheme = _extract_token_host_candidate(
            tok_s, allow_bare_decimal=not is_non_target_flag_val
        )
        if has_scheme and not cand_host:
            return (
                f"Unrequested host OS command execution blocked: malformed URL target "
                f"'{tok_s}' rejected by SSRF boundary (forbidden)."
            )
        if cand_host:
            if _is_non_canonical_ipv4_host(cand_host):
                return (
                    f"Unrequested host OS command execution blocked: non-canonical IPv4 SSRF target "
                    f"'{tok_s}' rejected by SSRF boundary (forbidden)."
                )
            is_ip_literal = False
            try:
                ipaddress.ip_address(cand_host)
                is_ip_literal = True
            except ValueError:
                is_ip_literal = False
            if is_ip_literal:
                is_local = is_explicit_loopback_host(cand_host)
                is_safe_ip, ssrf_reason = validate_target_host(cand_host, allow_private=is_local)
                if not is_safe_ip:
                    return (
                        f"Unrequested host OS command execution blocked: target '{tok_s}' "
                        f"rejected by SSRF boundary (forbidden): {ssrf_reason}"
                    )
        elif is_target_flag_val:
            val = tok_s.split("=", 1)[1].strip() if (tok_s.startswith("-") and "=" in tok_s) else tok_s
            host_port = val.split("/", 1)[0].strip()
            bare_cand = (
                host_port.split(":", 1)[0].strip().lower()
                if host_port.count(":") == 1
                else host_port.lower()
            ).rstrip(".")
            if bare_cand and _is_non_canonical_ipv4_host(bare_cand):
                return (
                    f"Unrequested host OS command execution blocked: non-canonical IPv4 SSRF target "
                    f"'{tok_s}' rejected by SSRF boundary (forbidden)."
                )
    return None


def _is_unsafe_mount_source(src: str) -> bool:
    raw_s = str(src or "")
    s = raw_s.strip().replace("\\", "/")
    if not s:
        return False
    # Reject control/NUL chars, NT/UNC/device paths, and drive-relative/ADS colon paths
    if (
        any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_s)
        or _is_unc_path(raw_s)
        or _is_drive_relative_or_colon_unsafe(raw_s)
    ):
        return True
    raw_parts = [p for p in s.split("/") if p]
    if ".." in raw_parts or any(p.endswith(":..") or p.rstrip() == ".." for p in raw_parts):
        return True
    # Reject drive-relative Windows paths (e.g., C:windows, C:users)
    if re.match(r"^[a-zA-Z]:(?!/|$)", s):
        return True
    s = re.sub(r"/+", "/", s)
    if s.startswith("/"):
        parts = [p for p in s.split("/") if p and p != "."]
        s = "/" + "/".join(parts)
    elif re.match(r"^[a-zA-Z]:/", s):
        drive = s[:2]
        parts = []
        for p in s[2:].split("/"):
            p_clean = p.rstrip(". ")
            if p_clean and p_clean != ".":
                parts.append(p_clean)
        s = drive + "/" + "/".join(parts)
    if s == "/":
        return True
    if re.fullmatch(r"[a-zA-Z]:/*", s):
        return True
    s_norm = s.rstrip("/").lower()
    for crit in _CRITICAL_POSIX_MOUNT_PREFIXES:
        if s_norm == crit or s_norm.startswith(crit + "/"):
            return True
    if re.match(
        r"^[a-z]:/(?:windows|users|programdata|program files|program files \(x86\)|system32)(?:/|$)",
        s_norm,
    ):
        return True
    return False


def _is_unsafe_docker_mount_spec(spec: str, *, is_mount_flag: bool = False) -> bool:
    raw_s = str(spec or "").strip()
    if not raw_s:
        return False
    if is_mount_flag:
        try:
            fields = next(csv.reader([raw_s], skipinitialspace=True), [])
        except csv.Error:
            fields = raw_s.split(",")
        for raw_part in fields:
            part = raw_part.strip()
            if len(part) >= 2 and part[0] == part[-1] and part[0] in ('"', "'"):
                part = part[1:-1].strip()
            if "=" in part:
                k, v = part.split("=", 1)
                k_clean = k.strip().strip('"').strip("'").strip().lower()
                v_clean = v.strip().strip('"').strip("'").strip()
                if k_clean in ("source", "src"):
                    if _is_unsafe_mount_source(v_clean):
                        return True
        return False

    s = raw_s.replace("\\", "/")
    if re.match(r"^[a-zA-Z]:", s):
        colon_idx = s.find(":", 2)
        src = s[:colon_idx] if colon_idx != -1 else s
    else:
        src = s.split(":", 1)[0]
    return _is_unsafe_mount_source(src)


def _has_unsafe_docker_mounts(tokens: List[str]) -> bool:
    for idx, tok in enumerate(tokens):
        tok_s = str(tok).strip()
        tok_l = tok_s.lower()
        if tok_l in ("-v", "--volume") and idx + 1 < len(tokens):
            if _is_unsafe_docker_mount_spec(str(tokens[idx + 1]), is_mount_flag=False):
                return True
        elif tok_l.startswith("--volume="):
            if _is_unsafe_docker_mount_spec(tok_s.split("=", 1)[1], is_mount_flag=False):
                return True
        elif tok_l.startswith("-v") and len(tok_s) > 2:
            if _is_unsafe_docker_mount_spec(tok_s[2:].lstrip("="), is_mount_flag=False):
                return True
        elif tok_l == "--mount" and idx + 1 < len(tokens):
            if _is_unsafe_docker_mount_spec(str(tokens[idx + 1]), is_mount_flag=True):
                return True
        elif tok_l.startswith("--mount="):
            if _is_unsafe_docker_mount_spec(tok_s.split("=", 1)[1], is_mount_flag=True):
                return True
    return False


def _is_excluded_python_module_spec(mod_spec: str, excluded_scanners: Set[str]) -> bool:
    mod = str(mod_spec or "").strip().lower()
    if not mod:
        return False
    if mod in excluded_scanners:
        return True
    for seg in mod.split("."):
        seg_l = seg.strip()
        if not seg_l:
            continue
        if seg_l in excluded_scanners or seg_l in _EXCLUDED_SCANNER_STEMS:
            return True
        if any(
            tok in excluded_scanners
            or tok in _EXCLUDED_SCANNER_STEMS
            or any(tok.startswith(ex) for ex in _EXCLUDED_SCANNER_STEMS)
            for tok in re.split(r"[^a-z0-9]+", seg_l)
            if tok
        ):
            return True
    return False


def _check_python_script_path(script_tok: str, excluded_scanners: Set[str]) -> Optional[str]:
    norm = str(script_tok or "").strip().replace("\\", "/")
    if not norm:
        return None
    p = PurePosixPath(norm)
    script_name = p.name.lower()
    script_stem = p.stem.lower()
    script_tokens = [tok for tok in re.split(r"[^a-z0-9]+", script_stem) if tok]
    if (
        script_name in excluded_scanners
        or script_name.split(".")[0] in _EXCLUDED_SCANNER_STEMS
        or any(
            tok in excluded_scanners
            or tok in _EXCLUDED_SCANNER_STEMS
            or any(tok.startswith(ex) for ex in _EXCLUDED_SCANNER_STEMS)
            for tok in script_tokens
        )
    ):
        return f"Unrequested host OS command execution blocked: excluded native scanner script '{script_name}' is forbidden."
    parent_parts = p.parts[:-1]
    for seg in parent_parts:
        seg_l = seg.strip().lower().rstrip(". ")
        if not seg_l or seg_l in ("/", "\\", ".", ".."):
            continue
        seg_tokens = [tok for tok in re.split(r"[^a-z0-9]+", seg_l) if tok]
        if (
            seg_l in excluded_scanners
            or seg_l in _EXCLUDED_SCANNER_STEMS
            or any(
                tok in excluded_scanners
                or tok in _EXCLUDED_SCANNER_STEMS
                or any(tok.startswith(ex) for ex in _EXCLUDED_SCANNER_STEMS)
                for tok in seg_tokens
            )
        ):
            return (
                f"Unrequested host OS command execution blocked: excluded native scanner "
                f"package path '{script_tok}' is forbidden."
            )
    return None


_PYTHON_BLOCKED_RUNNERS: Set[str] = {"timeit", "code", "idlelib"}
_PYTHON_TRAMPOLINE_RUNNERS: Set[str] = {
    "runpy", "cprofile", "profile", "pdb", "trace", "unittest", "pydoc", "doctest",
}
_PYTHON_RUNNER_VALUE_FLAGS_BY_MODULE: Dict[str, Set[str]] = {
    "trace": {"-f", "--file", "-C", "--coverdir", "--ignore-module", "--ignore-dir"},
    "cprofile": {"-o", "--outfile", "-s", "--sort"},
    "profile": {"-o", "--outfile", "-s", "--sort"},
    "unittest": set(),
    "doctest": set(),
    "pydoc": set(),
    "runpy": set(),
    "pdb": set(),
}


def _validate_python_tokens(tokens: List[str], excluded_scanners: Set[str]) -> Optional[str]:
    def _check_mod_token(mod_val: str) -> Tuple[Optional[str], bool, str]:
        mod_l = mod_val.strip().lower()
        if _is_excluded_python_module_spec(mod_l, excluded_scanners):
            return (
                f"Unrequested host OS command execution blocked: excluded native scanner module '{mod_l}' is forbidden.",
                False,
                "",
            )
        mod_root = mod_l.split(".", 1)[0]
        if mod_root in _PYTHON_BLOCKED_RUNNERS:
            return (
                f"Unrequested host OS command execution blocked: python code-runner module '{mod_l}' is forbidden.",
                False,
                "",
            )
        if mod_root in _PYTHON_TRAMPOLINE_RUNNERS:
            return None, True, mod_root
        return None, False, ""

    idx = 1
    in_runner_mode = False
    active_runner_value_flags: Set[str] = set()
    while idx < len(tokens):
        tok = tokens[idx].strip()
        if not tok:
            idx += 1
            continue
        if tok == "--":
            if idx + 1 < len(tokens):
                next_tok = tokens[idx + 1]
                err = _check_python_script_path(next_tok, excluded_scanners)
                if err:
                    return err
                if in_runner_mode and _is_excluded_python_module_spec(next_tok, excluded_scanners):
                    return f"Unrequested host OS command execution blocked: excluded native scanner module '{next_tok.strip().lower()}' is forbidden."
            if not in_runner_mode:
                break
            idx += 1
            continue
        if tok == "-m":
            mod = tokens[idx + 1].strip().lower() if idx + 1 < len(tokens) else ""
            err, is_trampoline, mod_root = _check_mod_token(mod)
            if err:
                return err
            if is_trampoline:
                in_runner_mode = True
                active_runner_value_flags = _PYTHON_RUNNER_VALUE_FLAGS_BY_MODULE.get(mod_root, set())
                idx += 2
                continue
            if not in_runner_mode:
                break
            idx += 2
            continue
        if tok.startswith("-m") and len(tok) > 2:
            mod = tok[2:].strip().lower()
            err, is_trampoline, mod_root = _check_mod_token(mod)
            if err:
                return err
            if is_trampoline:
                in_runner_mode = True
                active_runner_value_flags = _PYTHON_RUNNER_VALUE_FLAGS_BY_MODULE.get(mod_root, set())
                idx += 1
                continue
            if not in_runner_mode:
                break
            idx += 1
            continue
        if tok == "--check-hash-based-pycs":
            idx += 2
            continue
        if tok.startswith("--"):
            if in_runner_mode and tok.split("=", 1)[0].lower() in active_runner_value_flags and "=" not in tok:
                idx += 2
                continue
            idx += 1
            continue
        if tok == "-":
            return "Unrequested host OS command execution blocked: stdin python '-' execution is forbidden."
        if tok.startswith("-"):
            if in_runner_mode and tok in active_runner_value_flags:
                idx += 2
                continue
            step = 1
            matched_non_trampoline_m = False
            for pos in range(1, len(tok)):
                ch = tok[pos]
                if ch == "c":
                    return "Unrequested host OS command execution blocked: inline python '-c' execution is forbidden."
                if ch == "m":
                    after_m = tok[pos + 1 :].strip()
                    if after_m:
                        mod = after_m.lower()
                        step = 1
                    else:
                        mod = tokens[idx + 1].strip().lower() if idx + 1 < len(tokens) else ""
                        step = 2
                    err, is_trampoline, mod_root = _check_mod_token(mod)
                    if err:
                        return err
                    if is_trampoline:
                        in_runner_mode = True
                        active_runner_value_flags = _PYTHON_RUNNER_VALUE_FLAGS_BY_MODULE.get(mod_root, set())
                    else:
                        matched_non_trampoline_m = True
                    break
                if ch in ("W", "X", "Q"):
                    step = 2 if pos == len(tok) - 1 else 1
                    break
            if matched_non_trampoline_m and not in_runner_mode:
                return None
            idx += step
            continue
        err = _check_python_script_path(tok, excluded_scanners)
        if err:
            return err
        if in_runner_mode and _is_excluded_python_module_spec(tok, excluded_scanners):
            return f"Unrequested host OS command execution blocked: excluded native scanner module '{tok.strip().lower()}' is forbidden."
        if not in_runner_mode:
            break
        idx += 1
    return None


def _validate_docker_command(
    tokens: List[str],
    forbidden_commands: Set[str],
    excluded_scanners: Set[str],
) -> Optional[str]:
    if _has_unsafe_docker_mounts(tokens):
        return "Unrequested host OS command execution blocked: unsafe docker host mount is forbidden."

    has_python_entrypoint = False
    _ns_escape_flags = ("--network", "--net", "--pid", "--ipc", "--uts", "--userns", "--cgroupns")
    _safe_security_opts = {
        "no-new-privileges",
        "no-new-privileges=true",
        "no-new-privileges:true",
        "no-new-privileges=1",
        "no-new-privileges:1",
    }

    for idx, tok in enumerate(tokens[1:], start=1):
        tok_s = tok.strip()
        if not tok_s:
            continue
        tok_l = tok_s.lower()
        if tok_l == "--privileged" or tok_l.startswith("--privileged="):
            return "Unrequested host OS command execution blocked: docker '--privileged' execution is forbidden."
        if tok_l == "--cap-add" or tok_l.startswith("--cap-add="):
            return "Unrequested host OS command execution blocked: docker '--cap-add' capability escalation is forbidden."
        if tok_l == "--device" or tok_l.startswith("--device="):
            return "Unrequested host OS command execution blocked: docker '--device' host device mount is forbidden."
        if tok_l == "--volumes-from" or tok_l.startswith("--volumes-from="):
            return "Unrequested host OS command execution blocked: docker '--volumes-from' inherited mount is forbidden."

        for ns_flag in _ns_escape_flags:
            ns_val: Optional[str] = None
            if tok_l.startswith(ns_flag + "="):
                ns_val = tok_s.split("=", 1)[1].strip().lower()
            elif tok_l == ns_flag and idx + 1 < len(tokens):
                ns_val = tokens[idx + 1].strip().lower()
            if ns_val is not None:
                if (
                    ns_val == "host"
                    or ns_val.startswith("container:")
                    or (ns_flag == "--ipc" and ns_val == "shareable")
                ):
                    return (
                        f"Unrequested host OS command execution blocked: docker container isolation-escape "
                        f"flag '{ns_flag}={ns_val}' is forbidden."
                    )

        if tok_l == "--security-opt" or tok_l.startswith("--security-opt="):
            if tok_l.startswith("--security-opt="):
                sec_val = tok_s.split("=", 1)[1].strip().lower()
            elif idx + 1 < len(tokens):
                sec_val = tokens[idx + 1].strip().lower()
            else:
                sec_val = ""
            if sec_val not in _safe_security_opts:
                return (
                    f"Unrequested host OS command execution blocked: docker '--security-opt' "
                    f"value '{sec_val}' is forbidden."
                )

        ep_val: Optional[str] = None
        if tok_l.startswith("--entrypoint="):
            ep_val = tok_s.split("=", 1)[1].strip()
        elif tok_l == "--entrypoint" and idx + 1 < len(tokens):
            ep_val = tokens[idx + 1].strip()

        if ep_val is not None:
            ep_name = PurePosixPath(ep_val.replace("\\", "/")).name.lower()
            ep_stem = ep_name[:-4] if ep_name.endswith(".exe") else ep_name
            if (
                not ep_name
                or ep_name in _DOCKER_PAYLOAD_SHELLS_AND_WRAPPERS
                or ep_stem in _DOCKER_PAYLOAD_SHELLS_AND_WRAPPERS
                or ep_name in forbidden_commands
                or ep_stem in forbidden_commands
                or ep_name in excluded_scanners
                or ep_stem in _EXCLUDED_SCANNER_STEMS
                or any(ex in ep_name for ex in _EXCLUDED_SCANNER_STEMS)
            ):
                return f"Unrequested host OS command execution blocked: forbidden docker entrypoint '{ep_val}'."
            if _is_python_binary_name(ep_name):
                has_python_entrypoint = True

        if tok_s.startswith("-") or _is_http_url_token(tok_s):
            continue
        prev_l = tokens[idx - 1].strip().lower() if idx >= 1 else ""
        is_non_image_flag_val = prev_l in ("-v", "--volume", "--mount", "--format", "-o", "--output", "-h", "--header", "-e", "--env")
        tok_no_digest = tok_s.split("@", 1)[0]
        tok_name = PurePosixPath(tok_no_digest.replace("\\", "/")).name.lower()
        tok_base = tok_name.split(":", 1)[0]
        tok_stem = tok_base[:-4] if tok_base.endswith(".exe") else tok_base
        if (
            tok_name in excluded_scanners
            or tok_base in _EXCLUDED_SCANNER_STEMS
            or tok_stem in _EXCLUDED_SCANNER_STEMS
            or (
                not is_non_image_flag_val
                and (
                    any(ex in tok_name for ex in _EXCLUDED_SCANNER_STEMS)
                    or any(
                        seg in excluded_scanners or seg in _EXCLUDED_SCANNER_STEMS
                        or any(part in _EXCLUDED_SCANNER_STEMS for part in re.split(r"[^a-z0-9]+", seg) if part)
                        for seg in tok_no_digest.replace("\\", "/").lower().split("/")
                        if seg
                    )
                )
            )
        ):
            return f"Unrequested host OS command execution blocked: excluded native scanner '{tok_base}' is forbidden in docker invocation."

    # Locate docker subcommand and <image>/<container> target index positionally
    subcmd_group, subcmd, subcmd_idx, target_idx, val_flags = _resolve_docker_subcommand_info(tokens)

    if (subcmd_group, subcmd) not in _ALLOWED_DOCKER_SUBCOMMANDS:
        disp = f"{subcmd_group} {subcmd}".strip() if subcmd_group else (subcmd or "<none>")
        return (
            f"Unrequested host OS command execution blocked: docker subcommand '{disp}' "
            f"is not in the allowed subcommands (forbidden)."
        )

    is_python_image = False
    if target_idx != -1 and subcmd in ("run", "create"):
        img_tok = tokens[target_idx].strip()
        if any(ex in img_tok.lower() for ex in _EXCLUDED_SCANNER_STEMS):
            return (
                f"Unrequested host OS command execution blocked: excluded native scanner "
                f"docker image '{img_tok}' is forbidden."
            )
        img_no_digest = img_tok.split("@", 1)[0]
        img_name = PurePosixPath(img_no_digest.replace("\\", "/")).name.lower()
        img_base = img_name.split(":", 1)[0]
        if _is_python_binary_name(img_base):
            is_python_image = True

    if subcmd in ("run", "create") and subcmd_idx != -1:
        payload_start = target_idx + 1 if target_idx != -1 else subcmd_idx + 1
        for j in range(subcmd_idx + 1, len(tokens)):
            arg_s = tokens[j].strip()
            if not arg_s:
                continue
            arg_l = arg_s.lower()
            prev_arg_l = tokens[j - 1].strip().lower() if j >= 1 else ""
            if arg_l == "/c":
                return (
                    f"Unrequested host OS command execution blocked: forbidden shell flag '{arg_s}' "
                    f"in docker {subcmd} payload."
                )
            if arg_s.startswith("-"):
                is_trace_coverdir = (
                    arg_s == "-C"
                    and any(
                        tokens[m_idx].strip().lower() in ("-m", "-mtrace")
                        and (
                            tokens[m_idx].strip().lower() == "-mtrace"
                            or (m_idx + 1 < j and tokens[m_idx + 1].strip().lower() == "trace")
                        )
                        for m_idx in range(subcmd_idx + 1, j)
                    )
                )
                if arg_l in ("-lc", "-ic", "-ec", "--command") or arg_l.startswith("--command=") or (
                    (arg_s == "-c" or (arg_l == "-c" and not is_trace_coverdir))
                    and not (j + 1 < len(tokens) and tokens[j + 1].strip().isdigit())
                ):
                    return (
                        f"Unrequested host OS command execution blocked: forbidden shell flag '{arg_s}' "
                        f"in docker {subcmd} payload."
                    )
                if not arg_s.startswith("--") and (j >= payload_start or prev_arg_l not in val_flags):
                    m_flag = re.match(r"^-[A-Za-z]*?m(.*)$", arg_s)
                    if m_flag:
                        after_m = m_flag.group(1).strip()
                        is_python_m_flag = (
                            arg_s == "-m"
                            or after_m == ""
                            or has_python_entrypoint
                            or is_python_image
                            or _is_excluded_python_module_spec(after_m, excluded_scanners)
                            or after_m.lower().split(".", 1)[0] in (_PYTHON_BLOCKED_RUNNERS | _PYTHON_TRAMPOLINE_RUNNERS)
                        )
                        if is_python_m_flag:
                            py_err = _validate_python_tokens(["python", *tokens[j:]], excluded_scanners)
                            if py_err:
                                return py_err
                continue
            if "://" in arg_s or _is_http_url_token(arg_s):
                continue
            is_non_img_arg = prev_arg_l in ("-v", "--volume", "--mount", "--format", "-o", "--output", "-h", "--header", "-e", "--env")
            tok_no_digest = arg_s.split("@", 1)[0]
            tok_name = PurePosixPath(tok_no_digest.replace("\\", "/")).name.lower()
            tok_base = tok_name.split(":", 1)[0]
            tok_stem = tok_base[:-4] if tok_base.endswith(".exe") else tok_base
            if (
                tok_name in _DOCKER_PAYLOAD_SHELLS_AND_WRAPPERS
                or tok_base in _DOCKER_PAYLOAD_SHELLS_AND_WRAPPERS
                or tok_stem in _DOCKER_PAYLOAD_SHELLS_AND_WRAPPERS
                or tok_name in forbidden_commands
                or tok_base in forbidden_commands
                or tok_stem in forbidden_commands
                or tok_name in excluded_scanners
                or tok_base in _EXCLUDED_SCANNER_STEMS
                or tok_stem in _EXCLUDED_SCANNER_STEMS
                or (
                    not is_non_img_arg
                    and (
                        any(ex in tok_name for ex in _EXCLUDED_SCANNER_STEMS)
                        or any(
                            seg in excluded_scanners or seg in _EXCLUDED_SCANNER_STEMS
                            or any(part in _EXCLUDED_SCANNER_STEMS for part in re.split(r"[^a-z0-9]+", seg) if part)
                            for seg in tok_no_digest.replace("\\", "/").lower().split("/")
                            if seg
                        )
                    )
                )
            ):
                return (
                    f"Unrequested host OS command execution blocked: forbidden shell/wrapper/scanner "
                    f"'{arg_s}' in docker {subcmd} payload."
                )
            if _is_python_binary_name(tok_base):
                py_err = _validate_python_tokens(tokens[j:], excluded_scanners)
                if py_err:
                    return py_err

        if has_python_entrypoint or is_python_image:
            if target_idx != -1:
                post_image_tokens = tokens[target_idx + 1 :]
                if post_image_tokens:
                    py_err = _validate_python_tokens(["python", *post_image_tokens], excluded_scanners)
                    if py_err:
                        return py_err

            # Fallback scan over non-Docker-flag tokens in case an unknown Docker flag preceded the image
            # or no image token was supplied (stops once a post-image script path is reached).
            k = subcmd_idx + 1
            while k < len(tokens):
                t = tokens[k].strip()
                if not t:
                    k += 1
                    continue
                t_l = t.lower()
                if (target_idx == -1 or k < target_idx) and t_l in val_flags:
                    if t_l == "-c" and not (k + 1 < len(tokens) and tokens[k + 1].strip().isdigit()):
                        py_err = _validate_python_tokens(["python", *tokens[k:]], excluded_scanners)
                        if py_err:
                            return py_err
                    elif t_l == "-m" and k + 1 < len(tokens):
                        py_err = _validate_python_tokens(["python", *tokens[k:]], excluded_scanners)
                        if py_err:
                            return py_err
                    k += 2
                    continue
                if target_idx != -1 and k == target_idx:
                    k += 1
                    continue
                if t.startswith("-"):
                    py_err = _validate_python_tokens(["python", *tokens[k:]], excluded_scanners)
                    if py_err:
                        return py_err
                    k += 1
                    continue
                if target_idx != -1 and k > target_idx and t_l.endswith(".py"):
                    break
                k += 1

    return None


class ScannerTask(str, Enum):
    PROTOCOL_RULER = "protocol_ruler"
    DETERMINISTIC_HARNESS = "deterministic_harness"
    RQP_WEAPONIZER = "rqp_weaponizer"
    ARTEX_DUAL_GRAPH = "artex_dual_graph"
    PROMPT_SMUGGLING = "prompt_smuggling"
    MANTIS_REPRO = "mantis_repro"
    RAPTOR_DAST = "raptor_dast"
    HARNESS2 = "harness2"
    ACTIVE_FLAW_PROBER = "active_flaw_prober"
    DIFFERENTIAL_ORACLE = "differential_oracle"
    RFC_PROBE_GENERATOR = "rfc_probe_generator"
    DISCOVERY_CASCADE = "discovery_cascade"
    REA_SURFACE = "rea_surface"


class ActionType(str, Enum):
    NETWORK_SOCKET = "network_socket"
    SUBPROCESS_EXEC = "subprocess_exec"
    FILE_WRITE = "file_write"


@dataclass
class StructuredIntentProposal:
    task: Union[ScannerTask, str]
    action_type: Union[ActionType, str]
    target_host: Optional[str] = None
    target_port: Optional[int] = None
    http_method: Optional[str] = None
    raw_payload: Optional[Union[str, bytes]] = None
    command_args: Optional[List[str]] = None
    file_path: Optional[Union[str, Path]] = None
    rationale: str = ""
    is_destructive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExecutionPolicy:
    """
    Deterministic Safety & Confinement Policy Engine.
    Operates fail-closed across all network, process, and file actions.
    """

    _instance: Optional[ExecutionPolicy] = None
    _instance_lock: threading.Lock = threading.Lock()

    # State-mutating methods that alter server state or delete resources
    DESTRUCTIVE_HTTP_METHODS: Set[str] = {
        "PUT",
        "DELETE",
        "PATCH",
        "DROP",
        "PURGE",
    }

    # Prohibited shell binaries, wrappers, and system execution commands
    FORBIDDEN_SHELL_COMMANDS: Set[str] = {
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "sh",
        "sh.exe",
        "bash",
        "bash.exe",
        "zsh",
        "zsh.exe",
        "ksh",
        "ksh.exe",
        "csh",
        "csh.exe",
        "dash",
        "dash.exe",
        "ash",
        "ash.exe",
        "fish",
        "fish.exe",
        "tcsh",
        "tcsh.exe",
        "mksh",
        "mksh.exe",
        "busybox",
        "busybox.exe",
        "curl",
        "curl.exe",
        "wget",
        "wget.exe",
        "whoami",
        "whoami.exe",
        "id",
        "id.exe",
        "net",
        "net.exe",
        "ipconfig",
        "ipconfig.exe",
        "ifconfig",
        "cat",
        "cat.exe",
        "calc",
        "calc.exe",
        "mshta",
        "mshta.exe",
        "rundll32",
        "rundll32.exe",
        "wscript",
        "wscript.exe",
        "cscript",
        "cscript.exe",
        "env",
        "env.exe",
        "sudo",
        "sudo.exe",
        "doas",
        "xargs",
        "xargs.exe",
        "nohup",
        "nohup.exe",
        "timeout",
        "timeout.exe",
        "nice",
        "ionice",
        "chroot",
        "strace",
        "script",
        "regsvr32",
        "regsvr32.exe",
        "certutil",
        "certutil.exe",
        "bitsadmin",
        "bitsadmin.exe",
        "osascript",
    }

    # Native scanners explicitly excluded from the autonomous host loop
    EXCLUDED_NATIVE_SCANNERS: Set[str] = {
        "nmap",
        "nmap.exe",
        "nmap.py",
        "ffuf",
        "ffuf.exe",
        "ffuf.py",
        "dalfox",
        "dalfox.exe",
        "dalfox.py",
        "sqlmap",
        "sqlmap.exe",
        "sqlmap.py",
    }

    # Explicitly allowlisted scanner/isolation binaries (shell=False list-arg only)
    ALLOWED_EXTERNAL_SCANNER_BINARIES: Set[str] = set(_ALLOWED_EXTERNAL_SCANNER_BINARIES)

    # Shell metacharacter substrings rejected in every token (preserves Go template '{{.Id}}')
    SHELL_META_SUBSTRINGS: Tuple[str, ...] = (
        "$(",
        "`",
        "${",
        "\n",
        "\r",
        "\x00",
        "|",
        ";",
        "&",
        ">",
        "<",
        "(",
        ")",
    )

    # Designated directories permitted for scanner output and state persistence
    ALLOWED_WRITE_SUBDIRS: Set[str] = {
        "reports",
        "out",
        "runs",
        "runs/harness2",
        "rfcs",
        "data",
        "defense_rules",
        "caldera_export",
    }

    def __init__(self, allow_destructive: bool = False):
        env_destructive = os.environ.get("RFCHUNT_ALLOW_DESTRUCTIVE", "").lower() in ("1", "true", "yes")
        self.allow_destructive: bool = allow_destructive or env_destructive

    @classmethod
    def get_instance(cls) -> ExecutionPolicy:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._instance_lock:
            cls._instance = None

    def is_destructive_method(self, method: Optional[str]) -> bool:
        if not method:
            return False
        return method.strip().upper() in self.DESTRUCTIVE_HTTP_METHODS

    def is_approved_scanner_task(self, task: Union[ScannerTask, str]) -> bool:
        task_str = task.value if isinstance(task, ScannerTask) else str(task).lower()
        return any(task_str == t.value for t in ScannerTask)

    def validate_intent(self, proposal: StructuredIntentProposal) -> bool:
        """
        Validates a structured intent proposal against all safety invariants fail-closed.
        Raises PermissionError or ValueError on policy violation.
        Returns True if action is approved.
        """
        # Invariant 1: Task Confinement
        if not self.is_approved_scanner_task(proposal.task):
            raise PermissionError(
                f"Execution rejected: action is outside scanner-defined tasks: '{proposal.task}'. "
                f"Approved tasks are: {[t.value for t in ScannerTask]}."
            )

        act_type = proposal.action_type.value if isinstance(proposal.action_type, ActionType) else str(proposal.action_type).lower()

        # Invariant 2: Network Socket Confinement & Target Authorization
        if act_type == ActionType.NETWORK_SOCKET.value:
            return self._validate_network_intent(proposal)

        # Invariant 3: Subprocess Confinement & Host Shell Blocking
        elif act_type == ActionType.SUBPROCESS_EXEC.value:
            return self._validate_subprocess_intent(proposal)

        # Invariant 4: File Write Directory Confinement
        elif act_type == ActionType.FILE_WRITE.value:
            return self._validate_file_write_intent(proposal)

        else:
            raise PermissionError(f"Execution rejected: unknown action type '{proposal.action_type}'.")

    def _validate_network_intent(self, proposal: StructuredIntentProposal) -> bool:
        host = proposal.target_host
        if not host:
            raise ValueError("Network socket action requires a target_host.")

        from engine.safe_network_validator import validate_target_host, is_explicit_loopback_host
        from mcp_server import TargetAuthorizationGate

        cleaned_host = str(host).strip().lower()
        if _is_non_canonical_ipv4_host(cleaned_host.rstrip(".")):
            raise PermissionError(
                f"Target '{host}' rejected by SSRF safety boundary: non-canonical IPv4 representation is forbidden."
            )

        # Enforce mathematical SSRF validation
        is_local = is_explicit_loopback_host(cleaned_host)
        is_safe_net, net_reason = validate_target_host(cleaned_host, allow_private=is_local)
        if not is_safe_net:
            raise PermissionError(f"Target '{host}' rejected by SSRF safety boundary: {net_reason}")

        # Enforce TargetAuthorizationGate
        TargetAuthorizationGate.check_target(cleaned_host)

        # Destructive action gating (allow extensive red-team framing probes on authorized targets;
        # gate explicit state-mutating HTTP verbs or explicit is_destructive=True unless --allow-destructive)
        method_str = (proposal.http_method or "").strip().upper()
        method_destructive = self.is_destructive_method(method_str)
        task_destructive = bool(proposal.is_destructive)

        if (method_destructive or task_destructive):
            env_destructive = os.environ.get("RFCHUNT_ALLOW_DESTRUCTIVE", "").lower() in ("1", "true", "yes")
            if not self.allow_destructive and not env_destructive:
                raise PermissionError(
                    f"Destructive action gated: state-mutating request (method='{method_str}', "
                    f"task='{proposal.task}') requires explicit --allow-destructive opt-in."
                )

        # Preserving Red-Team offensive operations:
        # Aggressive verbs (TRACE, CONNECT, custom verbs) and desync framing headers
        # are explicitly permitted on authorized targets.
        return True

    def validate_subprocess_command(
        self,
        cmd_args: Sequence[str],
        *,
        shell: bool = False,
    ) -> Tuple[bool, str]:
        """
        Validates a subprocess invocation strictly for shell=False list-argv execution.
        Returns (True, "ok") when permitted or (False, reason) when blocked.
        """
        if shell:
            return False, "Unrequested host OS command execution blocked: shell=True is forbidden."

        if isinstance(cmd_args, (str, bytes, bytearray)) or not isinstance(cmd_args, Sequence):
            return (
                False,
                "Unrequested host OS command execution blocked: raw string/non-sequence commands are forbidden; list/sequence argv required.",
            )

        if len(cmd_args) == 0:
            return False, "Subprocess execution blocked: empty or null command arguments."

        tokens: List[str] = []
        for elem in cmd_args:
            if not isinstance(elem, (str, os.PathLike)):
                return (
                    False,
                    "Unrequested host OS command execution blocked: command arguments must be strings or path objects; non-string types are forbidden.",
                )
            try:
                fs_val = os.fspath(elem)
            except TypeError:
                return (
                    False,
                    "Unrequested host OS command execution blocked: invalid PathLike command argument.",
                )
            if not isinstance(fs_val, str):
                return (
                    False,
                    "Unrequested host OS command execution blocked: PathLike argument resolved to non-str/bytes, which is forbidden.",
                )
            tokens.append(fs_val)

        if not tokens[0].strip():
            return False, "Subprocess execution blocked: empty executable in command arguments."

        if tokens[0] != tokens[0].strip():
            return (
                False,
                f"Unrequested host OS command execution blocked: whitespace obfuscation forbidden in binary '{tokens[0]}'.",
            )

        if "=" in tokens[0] and not tokens[0].startswith("-"):
            return (
                False,
                f"Unrequested host OS command execution blocked: prefix env assignment '{tokens[0]}' is forbidden.",
            )

        _HEADER_VALUE_META = ("$(", "`", "${", "\n", "\r", "\x00", "|", "&", ">", "<")
        _has_scanner_tok = any(
            any(stem in t.lower() for stem in ("httpx", "katana", "nuclei"))
            for t in tokens[:14]
        )
        for idx, tok in enumerate(tokens):
            is_scanner_hdr_val = (
                _has_scanner_tok
                and idx > 0
                and tokens[idx - 1] in ("-H", "-header", "-headers")
                and ":" in tok
            )
            meta_set = _HEADER_VALUE_META if is_scanner_hdr_val else self.SHELL_META_SUBSTRINGS
            if any(meta in tok for meta in meta_set):
                return (
                    False,
                    f"Unrequested host OS command execution blocked: shell metacharacter forbidden in token '{tok}'.",
                )

        path_err = _validate_canonical_path_syntax(tokens[0])
        if path_err is not None:
            return (
                False,
                f"Unrequested host OS command execution blocked: {path_err} in binary '{tokens[0]}'.",
            )

        binary_name = _extract_basename_lower(tokens[0])
        if not binary_name:
            return False, "Subprocess execution blocked: empty executable basename."

        from engine.approval_gate import _is_safe_raptor_ps1

        is_raptor_ps1 = _is_safe_raptor_ps1(tokens)
        is_rea_node = _is_safe_rea_node(tokens)

        resolved_name: Optional[str] = None
        try:
            bin_path = Path(tokens[0].strip())
            if bin_path.exists() or bin_path.is_symlink():
                resolved_path = bin_path.resolve()
                resolved_s = str(resolved_path)
                if _is_unc_path(resolved_s) or _is_drive_relative_or_colon_unsafe(resolved_s):
                    return (
                        False,
                        f"Unrequested host OS command execution blocked by execution policy: resolved binary path '{resolved_s}' is forbidden.",
                    )
                resolved_name = resolved_path.name.lower()
                resolved_stem = resolved_name[:-4] if resolved_name.endswith(".exe") else resolved_name
                if resolved_name in self.EXCLUDED_NATIVE_SCANNERS or resolved_stem in _EXCLUDED_SCANNER_STEMS:
                    return (
                        False,
                        f"Unrequested host OS command execution blocked by execution policy: resolved binary '{resolved_name}' is forbidden.",
                    )
                if (
                    resolved_name in self.FORBIDDEN_SHELL_COMMANDS
                    or resolved_stem in self.FORBIDDEN_SHELL_COMMANDS
                ) and not (
                    is_raptor_ps1 and resolved_name in ("powershell", "powershell.exe", "pwsh", "pwsh.exe")
                ):
                    return (
                        False,
                        f"Unrequested host OS command execution blocked by execution policy: resolved binary '{resolved_name}' is forbidden.",
                    )
                base_family = _binary_tool_family(binary_name, is_raptor_ps1=is_raptor_ps1, is_rea_node=is_rea_node)
                res_family = _binary_tool_family(resolved_name, is_raptor_ps1=is_raptor_ps1, is_rea_node=is_rea_node)
                if not res_family:
                    return (
                        False,
                        f"Unrequested host OS command execution blocked by execution policy: resolved binary '{resolved_name}' is not an approved scanner tool (forbidden).",
                    )
                if base_family != res_family:
                    return (
                        False,
                        f"Unrequested host OS command execution blocked by execution policy: cross-tool symlink '{binary_name}' -> '{resolved_name}' is forbidden.",
                    )
        except OSError:
            pass

        if binary_name in self.EXCLUDED_NATIVE_SCANNERS:
            return (
                False,
                f"Unrequested host OS command execution blocked: excluded native scanner '{binary_name}' is forbidden.",
            )

        if binary_name in self.FORBIDDEN_SHELL_COMMANDS and not is_raptor_ps1:
            return (
                False,
                f"Unrequested host OS command execution blocked by execution policy: '{binary_name}' is forbidden.",
            )

        for arg in tokens[1:]:
            arg_lower = arg.lower()
            is_url = _is_http_url_token(arg)
            forbidden_substrings = (
                ("cmd.exe", "powershell -c", "bash -c", "sh -c", "zsh -c", "pwsh -c", "cmd /c")
                if is_url
                else ("cmd.exe", "whoami", "powershell -c", "bash -c", "sh -c", "zsh -c", "pwsh -c", "cmd /c")
            )
            if any(forbidden in arg_lower for forbidden in forbidden_substrings):
                return (
                    False,
                    f"Unrequested host OS command execution blocked in arguments (forbidden): '{arg}'",
                )

        nested_shell_names = {
            "sh", "sh.exe", "bash", "bash.exe", "zsh", "zsh.exe", "dash", "dash.exe",
            "ksh", "ksh.exe", "csh", "csh.exe", "ash", "ash.exe", "fish", "fish.exe",
            "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        }
        nested_shell_flags = {"-c", "/c", "-command", "-encodedcommand", "-e", "-ec", "-lc", "-ic"}
        for idx in range(1, len(tokens) - 1):
            t_cur = _extract_basename_lower(tokens[idx])
            t_next = tokens[idx + 1].strip().lower()
            is_shell_flag = (
                t_next in nested_shell_flags
                or t_next.startswith(("/co", "/en", "-co", "-en"))
                or (t_next.startswith("-") and not t_next.startswith("--") and ("c" in t_next[1:] or "e" in t_next[1:]))
            )
            if t_cur in nested_shell_names and is_shell_flag:
                return (
                    False,
                    f"Unrequested host OS command execution blocked: nested shell invocation '{t_cur} {t_next}' is forbidden.",
                )

        names_to_check = [binary_name]
        if resolved_name and resolved_name not in names_to_check:
            names_to_check.append(resolved_name)

        is_python = any(_is_python_binary_name(n) for n in names_to_check)
        is_aiscan = _is_safe_aiscan_name(binary_name) and (
            resolved_name is None or _is_safe_aiscan_name(resolved_name)
        )
        is_rea = _is_safe_rea_name(binary_name) and (
            resolved_name is None or _is_safe_rea_name(resolved_name)
        )
        is_allowed_bin = binary_name in self.ALLOWED_EXTERNAL_SCANNER_BINARIES and (
            resolved_name is None or resolved_name in self.ALLOWED_EXTERNAL_SCANNER_BINARIES
        )

        if is_python:
            py_err = _validate_python_tokens(tokens, self.EXCLUDED_NATIVE_SCANNERS)
            if py_err:
                return False, py_err

        if is_rea:
            rea_err = _validate_rea_tokens(tokens)
            if rea_err:
                return False, rea_err

        if any((n[:-4] if n.endswith(".exe") else n) == "docker" for n in names_to_check):
            docker_err = _validate_docker_command(
                tokens,
                self.FORBIDDEN_SHELL_COMMANDS,
                self.EXCLUDED_NATIVE_SCANNERS,
            )
            if docker_err:
                return False, docker_err

        if not (is_python or is_aiscan or is_rea or is_rea_node or is_allowed_bin or is_raptor_ps1):
            return (
                False,
                f"Unrequested host OS command execution blocked by execution policy: '{binary_name}' is not an approved scanner tool.",
            )

        # IP-literal and obfuscated IPv4 SSRF boundary check (without DNS lookup on domain hostnames)
        ssrf_err = _validate_command_ssrf_tokens(tokens)
        if ssrf_err:
            return False, ssrf_err

        return True, "ok"

    def _validate_subprocess_intent(self, proposal: StructuredIntentProposal) -> bool:
        shell_flag = bool((proposal.metadata or {}).get("shell", False))
        ok, reason = self.validate_subprocess_command(proposal.command_args, shell=shell_flag)
        if not ok:
            raise PermissionError(reason)
        return True

    def _validate_file_write_intent(self, proposal: StructuredIntentProposal) -> bool:
        raw_path = proposal.file_path
        if raw_path is None or (isinstance(raw_path, str) and not raw_path.strip()):
            raise ValueError("File write action requires a file_path.")
        if not isinstance(raw_path, str):
            raw_path = str(raw_path)

        path_err = _validate_canonical_path_syntax(raw_path, allow_trailing_slash=False)
        if path_err is not None:
            raise PermissionError(
                f"Arbitrary file write blocked outside designated report directories: {path_err} ('{raw_path}')."
            )

        path_str = raw_path
        resolved_path = Path(path_str).resolve()
        resolved_str = str(resolved_path)
        if _is_unc_path(resolved_str) or _is_drive_relative_or_colon_unsafe(resolved_str):
            raise PermissionError(
                f"Arbitrary file write blocked outside designated report directories: unsafe resolved path '{resolved_str}'."
            )

        rfchunt_root = Path(__file__).resolve().parent.parent

        # Tempdir is permitted for isolated scratch work
        temp_root = Path(tempfile.gettempdir()).resolve()
        if resolved_path != temp_root and resolved_path.is_relative_to(temp_root):
            return True

        # Custom pytest --basetemp (pytest.ini: d:/harfile/.pytest_temp) per-test scratch directories
        if os.environ.get("PYTEST_CURRENT_TEST"):
            pytest_temp_root = (rfchunt_root.parent / ".pytest_temp").resolve()
            if (
                resolved_path != pytest_temp_root
                and resolved_path.parent != pytest_temp_root
                and resolved_path.is_relative_to(pytest_temp_root)
            ):
                return True

        # Check allowed subdirectories within rfchunt root
        for allowed_sub in self.ALLOWED_WRITE_SUBDIRS:
            allowed_dir = (rfchunt_root / allowed_sub).resolve()
            if resolved_path != allowed_dir and resolved_path.is_relative_to(allowed_dir):
                return True

        # Top-level database files directly under rfchunt_root (e.g. terminator.db) are permitted
        if resolved_path.parent == rfchunt_root and resolved_path.suffix.lower() in (".db", ".sqlite"):
            return True

        raise PermissionError(
            f"Arbitrary file write blocked outside designated report directories: '{path_str}'. "
            f"Allowed directories: {sorted(list(self.ALLOWED_WRITE_SUBDIRS))}."
        )


def sanitize_for_llm_prompt(untrusted_text: Union[str, bytes], max_chars: int = 1000) -> str:
    """
    Sanitizes untrusted remote HTTP response headers and bodies before feeding them into LLM contexts.
    - Decodes bytes safely
    - Strips non-printable ASCII control characters
    - Neutralizes prompt injection directives and instruction tokens
    - Defuses markdown code fence escapes
    - Wraps data in strict quarantine tags with random nonce
    """
    if isinstance(untrusted_text, bytes):
        text = untrusted_text.decode("latin-1", errors="replace")
    else:
        text = str(untrusted_text or "")

    # Truncate to maximum characters
    text = text[:max_chars]

    # Strip ASCII control characters except \r, \n, \t
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Neutralize LLM prompt injection tokens & role markers
    text = re.sub(r"(?i)###\s*(system|instruction|task|human|assistant|prompt)", "[REDACTED_MARKER]", text)
    text = re.sub(r"(?i)<\|(im_start|im_end|endoftext|system|user|assistant)\|>", "[TOKEN_NEUTRALIZED]", text)
    text = re.sub(r"(?i)(ignore\s+(all\s+)?previous\s+instructions|system\s+prompt\s*:)", "[PROMPT_OVERRIDE_DEFUSED]", text)
    text = re.sub(r"(?i)(admin_override|jailbreak|disregard\s+prior)", "[DIRECTIVE_NEUTRALIZED]", text)

    # Defuse markdown code fence injection
    text = text.replace("```", "` ` `")

    nonce = secrets.token_hex(8)
    return f'<untrusted_remote_response_data nonce="{nonce}">\n{text}\n</untrusted_remote_response_data>'


def validate_llm_json_response(data: Any, schema_type: str = "probe") -> Tuple[bool, Any, Optional[str]]:
    """
    Validates LLM-generated JSON completions against expected schemas.
    If malformed or invalid, provides safe deterministic fallbacks to baseline scanner checks
    without corrupting SARIF reports or crashing execution.
    """
    if schema_type == "probe":
        if isinstance(data, list):
            valid_probes = []
            for item in data:
                if isinstance(item, dict):
                    clean_item = {
                        "raw_request": str(item.get("raw_request") or item.get("probe") or ""),
                        "rationale": str(item.get("rationale") or "Deterministic baseline probe"),
                        "is_clean": bool(item.get("is_clean", False)),
                        "framing_technique": str(item.get("framing_technique") or "CL.TE"),
                    }
                    valid_probes.append(clean_item)
            if valid_probes:
                return True, valid_probes, None

        # Fallback to deterministic baseline probe
        fallback = [{
            "raw_request": "GET / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n",
            "rationale": "Deterministic RFC 7230/9112 CL.TE baseline fallback probe",
            "is_clean": False,
            "framing_technique": "CL.TE",
        }]
        return False, fallback, "Malformed or empty probe response; used deterministic baseline fallback."

    elif schema_type == "threat_model":
        if isinstance(data, dict) and "entry_points" in data:
            return True, data, None
        default_threat_model = {
            "threat_model_id": "TM-BASELINE-001",
            "entry_points": [{"function": "/api/chat", "method": "POST", "risk": "HIGH"}],
            "assets": ["HTTP/1.1 wire framing boundaries", "AI prompt sinks"],
            "hypotheses": ["Desynchronized HTTP request framing enables prompt injection into AI endpoint"],
        }
        return False, default_threat_model, "Invalid threat model; used deterministic baseline model."

    elif schema_type == "artex_plan":
        raw_items = data.get("intents") if isinstance(data, dict) else (data if isinstance(data, list) else None)
        if isinstance(raw_items, list):
            sanitized = []
            for item in raw_items[:20]:
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title") or item.get("label") or "").strip()[:160]
                attack_type = re.sub(r"[^A-Z0-9_]", "_", str(item.get("attack_type") or "LLM_PLANNED_CHAIN").upper())[:48]
                target_route = str(item.get("target_route") or "/").strip()[:200]
                if not title:
                    continue
                steps = (
                    item.get("chain_steps")
                    if isinstance(item.get("chain_steps"), list)
                    else (item.get("steps") if isinstance(item.get("steps"), list) else [])
                )
                clean_steps = []
                for idx, st in enumerate(steps[:6], start=1):
                    if isinstance(st, dict):
                        clean_steps.append({
                            "step": idx,
                            "capability": str(st.get("capability") or "").upper()[:32],
                            "desc": str(st.get("desc") or st.get("title") or f"Step {idx}")[:240],
                            "finding_id": str(st.get("finding_id") or "")[:80],
                        })
                raw_method = str(item.get("method") or "GET").strip().upper()
                sanitized_method = re.sub(r"[^A-Z]", "", raw_method)[:12] or "GET"
                sanitized.append({
                    "title": title,
                    "attack_type": attack_type,
                    "target_route": target_route,
                    "method": sanitized_method,
                    "rationale": str(item.get("rationale") or title)[:400],
                    "source_finding_ids": [str(s)[:80] for s in (item.get("source_finding_ids") or [])[:5]],
                    "chain_steps": clean_steps or [{"step": 1, "desc": title}],
                })
            return True, {"intents": sanitized}, None
        return False, {"intents": []}, "Malformed ARTEX planner JSON; falling back to deterministic graph plan."

    return True, data, None
