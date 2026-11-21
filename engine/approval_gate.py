"""
CLI-Native Human-in-the-Loop Interception & Approval Gate (Pillar 3)
====================================================================
Mirrors BaaRai/ARTEX's interception gate strictly for CLI workflows (zero GUI):
- Evaluates high-risk / active actions against ordered rules before execution:
  1. Hard `ExecutionPolicy` deny always takes precedence (non-bypassable).
  2. Configurable approval rules: `exact_host`, `regex`, `http_method`, or
     `argv_prefix` (1-8 tokens matching a single simple command only; rejects
     pipes, lists, redirections, subshells, prefix assignments, and command
     substitutions—matching ARTEX's safe argv-prefix rule semantics).
  3. Mode fallback:
     - `policy` (default): non-interactive fail-closed (safe for CI/automation).
     - `prompt`: interactive TTY prompt `[a]pprove / [r]emember / [d]eny / [q]uit`.
     - `deny`: dry-run mode rejecting all live outbound/mutating actions.
- Records every decision with attribution (`human`, `rule`, `policy`, `system`)
  in `approval_decisions` in `terminator.db`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
import json
import logging
import os
from pathlib import Path, PureWindowsPath
import re
import shlex
import sys
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from engine.execution_policy import (
    _WIN_DRIVE_PREFIX_RE,
    _extract_basename_lower,
    _is_drive_relative_or_colon_unsafe,
    _is_unc_path,
    _validate_canonical_path_syntax,
)

logger = logging.getLogger("terminator.artex.approval")


def _extract_hostname(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        after_scheme = raw.split("://", 1)[1]
        authority = re.split(r"[/?#]", after_scheme, maxsplit=1)[0]
        if "\\" in authority:
            return ""
        try:
            return (urlparse(raw).hostname or "").strip().lower()
        except ValueError:
            return ""
    host_port = raw.split("/", 1)[0].strip()
    if host_port.startswith("[") and "]" in host_port:
        return host_port[1 : host_port.index("]")].strip().lower()
    if host_port.count(":") == 1:
        return host_port.split(":", 1)[0].strip().lower()
    return host_port.lower()

SHELL_META_TOKENS = frozenset({"|", "||", "&&", ";", "&", ">", ">>", "<", "<<", "2>", "2>&1", "(", ")", "`"})
SHELL_META_SUBSTRINGS = ("$(", "`", "${", "\n", "\r", "\x00", "|", ";", "&", ">", "<", "(", ")")
WRAPPER_BINARIES = frozenset({
    "env", "env.exe",
    "sudo", "sudo.exe",
    "doas", "su", "su.exe",
    "runas", "runas.exe",
    "sh", "sh.exe",
    "bash", "bash.exe",
    "zsh", "zsh.exe",
    "ksh", "ksh.exe",
    "csh", "csh.exe",
    "dash", "dash.exe",
    "ash", "ash.exe",
    "fish", "fish.exe",
    "tcsh", "tcsh.exe",
    "busybox", "busybox.exe",
    "cmd", "cmd.exe",
    "powershell", "powershell.exe",
    "pwsh", "pwsh.exe",
    "xargs", "xargs.exe",
    "nohup", "nohup.exe",
    "timeout", "timeout.exe",
    "nice", "stdbuf", "chroot", "script",
    "wsl", "wsl.exe",
    "mshta", "mshta.exe",
    "wscript", "wscript.exe",
    "cscript", "cscript.exe",
    "rundll32", "rundll32.exe",
})
EXCLUDED_SCANNER_BINARIES = frozenset({
    "nmap", "nmap.exe", "nmap.py",
    "ffuf", "ffuf.exe", "ffuf.py",
    "dalfox", "dalfox.exe", "dalfox.py",
    "sqlmap", "sqlmap.exe", "sqlmap.py",
})
_EXCLUDED_SCANNER_STEMS = frozenset({"nmap", "ffuf", "dalfox", "sqlmap"})
_DOCKER_PAYLOAD_SHELLS = frozenset({
    "sh", "sh.exe",
    "bash", "bash.exe",
    "zsh", "zsh.exe",
    "ksh", "ksh.exe",
    "csh", "csh.exe",
    "dash", "dash.exe",
    "ash", "ash.exe",
    "fish", "fish.exe",
    "cmd", "cmd.exe",
    "powershell", "powershell.exe",
    "pwsh", "pwsh.exe",
})


def _split_command_tokens(raw: str) -> Optional[List[str]]:
    use_posix = "\\" not in raw
    try:
        tokens = shlex.split(raw, posix=use_posix)
    except ValueError:
        return None
    if not use_posix:
        cleaned: List[str] = []
        for tok in tokens:
            if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ('"', "'"):
                tok = tok[1:-1]
            cleaned.append(tok)
        return cleaned
    return tokens


def parse_simple_argv(command: Union[str, List[str]]) -> Optional[List[str]]:
    """
    Parses a single simple command into argv tokens for safe argv-prefix matching.
    Returns `None` if the command contains pipes, lists, redirections, subshells,
    prefix env assignments, wrappers, excluded scanners, or command/parameter substitutions
    (matching ARTEX's strict argv-prefix rule semantics).
    """
    if isinstance(command, str):
        raw = command.strip()
        if not raw:
            return None
        if any(s in raw for s in SHELL_META_SUBSTRINGS):
            return None
        tokens = _split_command_tokens(raw)
        if tokens is None:
            return None
    elif isinstance(command, (list, tuple)):
        if any(isinstance(t, (bytes, bytearray)) or t is None for t in command):
            return None
        tokens = []
        for t in command:
            if isinstance(t, os.PathLike):
                try:
                    fs = os.fspath(t)
                except TypeError:
                    return None
                if not isinstance(fs, str):
                    return None
                tokens.append(fs)
            else:
                tokens.append(str(t))
    else:
        return None

    if not tokens or not str(tokens[0]).strip() or str(tokens[0]) != str(tokens[0]).strip():
        return None

    # Reject shell metacharacters, command substitutions, or redirections inside tokens
    for tok in tokens:
        if tok in SHELL_META_TOKENS or any(s in tok for s in SHELL_META_SUBSTRINGS):
            return None

    # Reject prefix environment assignments like FOO=bar cmd
    if "=" in tokens[0] and not tokens[0].startswith("-"):
        return None

    # Reject NT/UNC/device, drive-relative, ADS colon, trailing slash/dot/space, traversal before basename matching
    if _validate_canonical_path_syntax(tokens[0]) is not None:
        return None

    # Reject wrapper binaries (sudo, env, sh, bash, etc.) and excluded scanners
    base_bin = _extract_basename_lower(tokens[0])
    if not base_bin:
        return None
    base_stem = base_bin[:-4] if base_bin.endswith(".exe") else base_bin
    if base_bin in WRAPPER_BINARIES or base_bin in EXCLUDED_SCANNER_BINARIES or base_stem in _EXCLUDED_SCANNER_STEMS:
        return None

    return tokens


def match_argv_prefix(pattern: List[str], command: Union[str, List[str]]) -> bool:
    """
    ARTEX-compatible argv-prefix matcher:
    - Pattern must be 1 to 8 non-empty tokens.
    - Matches ONLY a single simple command whose parsed leading positional tokens
      (ignoring trailing flags after the prefix, and NOT skipping flags inserted
      inside the prefix—e.g. `["git","push"]` matches `git push --force`,
      but `git -C /repo push` matches nothing).
    """
    if not isinstance(pattern, list) or not (1 <= len(pattern) <= 8):
        return False
    clean_pat = [str(p).strip() for p in pattern]
    if any(not p for p in clean_pat):
        return False

    tokens = parse_simple_argv(command)
    if tokens is None or len(tokens) < len(clean_pat):
        return False

    if "/" in clean_pat[0] or "\\" in clean_pat[0] or ":" in clean_pat[0]:
        if _validate_canonical_path_syntax(clean_pat[0]) is not None:
            return False
        first_match = tokens[0].replace("\\", "/") == clean_pat[0].replace("\\", "/")
    else:
        base_cmd = _extract_basename_lower(tokens[0])
        pat_lower = clean_pat[0].lower()
        first_match = (
            tokens[0] == clean_pat[0]
            or base_cmd == pat_lower
            or (base_cmd.endswith(".exe") and base_cmd[:-4] == pat_lower)
        )
    if not first_match:
        return False

    return tokens[1 : len(clean_pat)] == clean_pat[1:]


@dataclass
class ApprovalRule:
    rule_id: str
    rule_type: str  # 'exact_host', 'regex', 'http_method', 'argv_prefix'
    action: str = "APPROVE"  # 'APPROVE' or 'DENY'
    pattern: Union[str, List[str]] = ""
    description: str = ""
    method_scope: str = ""

    def matches(
        self,
        *,
        target: str = "",
        method: str = "",
        action_summary: str = "",
        command: Optional[Union[str, List[str]]] = None,
    ) -> bool:
        if self.method_scope and str(method or "").strip().upper() != self.method_scope.strip().upper():
            return False
        rtype = self.rule_type.strip().lower()
        if rtype == "exact_host":
            if not target:
                return False
            raw_t = str(target).strip().lower()
            pat = str(self.pattern).strip().lower().strip("[]").rstrip(".")
            if not pat:
                return False
            if raw_t.strip("[]").rstrip(".") == pat:
                return True
            return _extract_hostname(raw_t).strip("[]").rstrip(".") == pat
        if rtype == "http_method":
            return bool(method) and str(method).strip().upper() == str(self.pattern).strip().upper()
        if rtype == "regex":
            try:
                cmd_str = " ".join(str(x) for x in command) if isinstance(command, (list, tuple)) else str(command or "")
                haystack = f"{method} {target} {action_summary} {cmd_str}".strip()
                return bool(re.search(str(self.pattern), haystack, re.IGNORECASE))
            except re.error:
                return False
        if rtype == "argv_prefix":
            if command is None or not isinstance(self.pattern, list):
                return False
            return match_argv_prefix(self.pattern, command)
        return False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApprovalDecision:
    approved: bool
    decided_by: str  # 'human', 'rule', 'policy', 'system'
    decision: str    # 'APPROVE', 'DENY'
    rule_id: str = ""
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _is_safe_raptor_ps1(tokens: List[str]) -> bool:
    """
    Strict left-to-right allowlist parser for RAPTOR PowerShell launcher invocations.
    Permits PowerShell ONLY when:
    - Tokens before `-File`/`-f` consist strictly of allowlisted benign launcher flags
      (zero-arg `-noprofile`/`-nop`/`-noninteractive`/`-noni`/`-nologo`/`-sta`/`-mta`,
      or value-taking `-executionpolicy`/`-ep`/`-windowstyle`/`-w` with a benign value).
      Rejects any leading positional arg, `/` flag, `:`/`=`-attached flag, or `-c`/`-e`/`-ec`.
    - `-File` (or `-f`) appears exactly once, immediately followed by `<script_path>`
      with no `..` traversal, not a UNC (`\\` or `//`) path, and normalized basename
      in `{"invoke-raptorscan.ps1", "raptorscan.ps1"}`.
    - Remaining script arguments contain no duplicate `-File`/`-f`/`/File` flags and no
      PowerShell `-c`/`-e`/`-ec`/`/c`/`/e`/`/ec`/`-co*`/`-en*`/`/co*`/`/en*` flags.
    """
    if len(tokens) < 3:
        return False
    tok0_raw = os.fspath(tokens[0]) if isinstance(tokens[0], os.PathLike) else tokens[0]
    if _validate_canonical_path_syntax(tok0_raw) is not None:
        return False
    base_bin = _extract_basename_lower(tok0_raw)
    if base_bin not in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
        return False

    raw_args = [str(a) for a in tokens[1:]]
    pre_file_noarg_flags = {
        "-noprofile", "-nop",
        "-noninteractive", "-noni",
        "-nologo",
        "-sta",
        "-mta",
    }
    pre_file_value_flags = {
        "-executionpolicy": {"bypass", "remotesigned", "allsigned", "restricted", "unrestricted", "default", "undefined"},
        "-ep": {"bypass", "remotesigned", "allsigned", "restricted", "unrestricted", "default", "undefined"},
        "-windowstyle": {"normal", "minimized", "maximized", "hidden"},
        "-w": {"normal", "minimized", "maximized", "hidden"},
    }

    idx = 0
    script_raw: Optional[str] = None
    while idx < len(raw_args):
        arg_raw = raw_args[idx]
        arg_s = arg_raw.strip()
        if not arg_s or arg_raw != arg_s:
            return False
        arg_l = arg_s.lower()

        if arg_l in ("-file", "-f"):
            if idx + 1 >= len(raw_args):
                return False
            script_raw = raw_args[idx + 1]
            idx += 2
            break

        if arg_l in pre_file_noarg_flags:
            idx += 1
            continue

        if arg_l in pre_file_value_flags:
            if idx + 1 >= len(raw_args):
                return False
            val_raw = raw_args[idx + 1]
            val_s = val_raw.strip()
            if not val_s or val_raw != val_s:
                return False
            if val_s.lower() not in pre_file_value_flags[arg_l]:
                return False
            idx += 2
            continue

        # Any other token before -File/-f (positional args, /Command, -c:..., -File:..., etc.) is rejected
        return False

    if script_raw is None:
        return False

    # Reject NT/UNC/device, drive-relative, ADS colons, traversal, trailing slashes/dots/spaces BEFORE any filesystem touch
    if _validate_canonical_path_syntax(script_raw) is not None:
        return False

    script_s = script_raw
    script_norm = script_s.replace("\\", "/")
    script_name = _extract_basename_lower(script_s)
    if script_name not in ("invoke-raptorscan.ps1", "raptorscan.ps1"):
        return False

    repo_root = Path(__file__).resolve().parent.parent
    repo_scripts_dir = (repo_root / "scripts").resolve()
    is_rooted = script_norm.startswith("/") or bool(_WIN_DRIVE_PREFIX_RE.match(script_norm))

    try:
        if is_rooted:
            resolved_script = Path(script_s).resolve()
            resolved_s = str(resolved_script)
            if _validate_canonical_path_syntax(resolved_s) is not None:
                return False
            if (
                not resolved_script.is_relative_to(repo_scripts_dir)
                or resolved_script.name.lower() not in ("invoke-raptorscan.ps1", "raptorscan.ps1")
            ):
                return False
        else:
            # Check CWD hijack/symlink first if present in current working directory
            cwd_cand = Path.cwd() / script_s
            if cwd_cand.exists() or cwd_cand.is_symlink():
                resolved_cwd = cwd_cand.resolve()
                resolved_cwd_s = str(resolved_cwd)
                if _validate_canonical_path_syntax(resolved_cwd_s) is not None:
                    return False
                if (
                    not resolved_cwd.is_relative_to(repo_scripts_dir)
                    or resolved_cwd.name.lower() not in ("invoke-raptorscan.ps1", "raptorscan.ps1")
                ):
                    return False
            # Also anchor relative path to repo_root so legitimate "scripts/Invoke-RaptorScan.ps1" works from any CWD
            repo_cand = (repo_root / script_s).resolve()
            repo_cand_s = str(repo_cand)
            if _validate_canonical_path_syntax(repo_cand_s) is not None:
                return False
            if (
                not repo_cand.is_relative_to(repo_scripts_dir)
                or repo_cand.name.lower() not in ("invoke-raptorscan.ps1", "raptorscan.ps1")
            ):
                return False
    except OSError:
        return False

    # Validate remaining script arguments after `<script_path>`
    forbidden_cmd_prefixes = (
        "-c:", "-c=", "-e:", "-e=", "-ec:", "-ec=",
        "/c:", "/c=", "/e:", "/e=", "/ec:", "/ec=",
        "-co", "-en", "--co", "--en", "/co", "/en",
    )
    forbidden_file_prefixes = (
        "-file:", "-file=", "-f:", "-f=",
        "/file:", "/file=", "/f:", "/f=",
    )
    for rem_raw in raw_args[idx:]:
        rem_s = rem_raw.strip()
        if not rem_s:
            return False
        rem_l = rem_s.lower()
        if rem_l in ("-file", "-f", "/file", "/f") or rem_l.startswith(forbidden_file_prefixes):
            return False
        if rem_l == "--%" or rem_l in ("-c", "-e", "-ec", "/c", "/e", "/ec") or rem_l.startswith(forbidden_cmd_prefixes):
            return False

    return True


class ApprovalGate:
    """
    CLI-native interception gate sitting above ExecutionPolicy.
    Supports `policy` (default), `prompt` (interactive TTY), and `deny` (dry-run).
    """

    def __init__(
        self,
        mode: str = "policy",
        rules: Optional[List[ApprovalRule]] = None,
        db: Optional[Any] = None,
        task_id: str = "default",
        input_fn: Optional[Callable[[str], str]] = None,
        output_fn: Optional[Callable[[str], None]] = None,
    ):
        clean_mode = str(mode or "policy").strip().lower()
        if clean_mode not in ("policy", "prompt", "deny"):
            clean_mode = "policy"
        self.mode = clean_mode
        self.rules: List[ApprovalRule] = list(rules or [])
        self.db = db
        self.task_id = task_id
        self._input_fn = input_fn or input
        self._output_fn = output_fn or print
        self._lock = threading.Lock()
        self.history: List[Dict[str, Any]] = []

    @classmethod
    def from_rules_file(
        cls,
        rules_path: Optional[Union[str, Path]],
        mode: str = "policy",
        db: Optional[Any] = None,
        task_id: str = "default",
    ) -> "ApprovalGate":
        loaded: List[ApprovalRule] = []
        if rules_path and Path(rules_path).is_file():
            p = Path(rules_path)
            raw_text = p.read_text(encoding="utf-8-sig")
            if p.suffix.lower() in (".yml", ".yaml"):
                import yaml as _yaml
                raw = _yaml.safe_load(raw_text)
            else:
                raw = json.loads(raw_text)
            items = raw.get("rules", raw) if isinstance(raw, dict) else raw
            if isinstance(items, list):
                for idx, item in enumerate(items, start=1):
                    if isinstance(item, dict):
                        loaded.append(
                            ApprovalRule(
                                rule_id=str(item.get("rule_id") or f"RULE-{idx:03d}"),
                                rule_type=str(item.get("rule_type") or "regex"),
                                action=str(item.get("action") or "APPROVE").upper(),
                                pattern=item.get("pattern", ""),
                                description=str(item.get("description") or ""),
                                method_scope=str(item.get("method_scope") or "").strip().upper(),
                            )
                        )
        return cls(mode=mode, rules=loaded, db=db, task_id=task_id)

    def _record(
        self,
        action_type: str,
        target: str,
        method: str,
        rationale: str,
        decision: ApprovalDecision,
        action_summary: str = "",
    ) -> ApprovalDecision:
        summary_val = action_summary or rationale or f"{action_type} {method} {target}".strip()
        rec = {
            "task_id": self.task_id,
            "action_type": action_type,
            "target": target,
            "method": method,
            "decision": decision.decision,
            "decided_by": decision.decided_by,
            "rule_id": decision.rule_id,
            "rationale": decision.reason or rationale,
            "action_summary": summary_val,
        }
        with self._lock:
            self.history.append(rec)
        if self.db and hasattr(self.db, "save_approval_decision"):
            try:
                self.db.save_approval_decision(**rec)
            except Exception as exc:
                logger.debug("Failed persisting approval decision: %s", exc)
        return decision

    @staticmethod
    def _has_unsafe_docker_root_mount(tokens: List[str]) -> bool:
        from engine.execution_policy import _has_unsafe_docker_mounts

        return _has_unsafe_docker_mounts(tokens)

    def _check_hard_execution_policy(
        self,
        *,
        action_type: str,
        target: str,
        method: str,
        command: Optional[Union[str, List[str]]],
        shell: bool = False,
    ) -> Optional[str]:
        """
        Enforces non-overrideable ExecutionPolicy invariants BEFORE any ApprovalRule:
        - SSRF / private / metadata / unspecified host rejection
        - Forbidden host OS shell commands, wrappers, excluded scanners & metacharacters
        - File write path traversal (`..`) and out-of-bounds write paths
        Returns a deny reason string if violated, or None if cleared.
        """
        from engine.execution_policy import (
            ActionType,
            ExecutionPolicy,
            ScannerTask,
            StructuredIntentProposal,
            _binary_tool_family,
            _extract_token_host_candidate,
            _is_http_url_token,
            _is_non_canonical_ipv4_host,
            _is_python_binary_name,
            _is_safe_aiscan_name,
            _validate_command_ssrf_tokens,
            _validate_docker_command,
            _validate_python_tokens,
        )
        from engine.safe_network_validator import is_explicit_loopback_host, validate_target_host

        policy = ExecutionPolicy.get_instance()
        act = str(action_type or "").strip().lower()

        # 1. Subprocess / command hard invariants (forbidden OS shells, excluded scanners & shell metacharacters)
        if act in ("subprocess", "subprocess_exec") or command is not None:
            if shell:
                return "Subprocess execution blocked by ExecutionPolicy: shell=True is forbidden."

            cmd_input = command if command is not None else target
            if isinstance(cmd_input, (bytes, bytearray)):
                return "Subprocess execution blocked by ExecutionPolicy: raw bytes command is forbidden."

            if act == "subprocess_exec" and isinstance(cmd_input, str):
                return (
                    "Subprocess execution blocked by ExecutionPolicy: raw string commands are forbidden "
                    "for subprocess_exec; provide argv list with shell=False."
                )

            if isinstance(cmd_input, str):
                raw = cmd_input.strip()
                if not raw:
                    return "Subprocess execution blocked by ExecutionPolicy: empty command."
                if any(s in raw for s in SHELL_META_SUBSTRINGS):
                    return f"Subprocess execution blocked by ExecutionPolicy: shell metacharacters in '{raw}'."
                tokens = _split_command_tokens(raw)
                if tokens is None:
                    return "Subprocess execution blocked by ExecutionPolicy: invalid command syntax."
            elif isinstance(cmd_input, (list, tuple)):
                if any(isinstance(t, (bytes, bytearray)) or t is None for t in cmd_input):
                    return "Subprocess execution blocked by ExecutionPolicy: invalid token type in command."
                tokens = []
                for t in cmd_input:
                    if isinstance(t, os.PathLike):
                        try:
                            fs_val = os.fspath(t)
                        except TypeError:
                            return "Subprocess execution blocked by ExecutionPolicy: invalid PathLike command token."
                        if not isinstance(fs_val, str):
                            return "Subprocess execution blocked by ExecutionPolicy: non-str PathLike command token is forbidden."
                        tokens.append(fs_val)
                    else:
                        tokens.append(str(t))
            else:
                return "Subprocess execution blocked by ExecutionPolicy: invalid command type."

            if not tokens or not str(tokens[0]).strip():
                return "Subprocess execution blocked by ExecutionPolicy: empty command tokens."

            t0_raw = str(tokens[0])
            t0 = t0_raw.strip()
            if t0_raw != t0:
                return f"Subprocess execution blocked by ExecutionPolicy: whitespace obfuscation in executable '{t0_raw}'."

            for tok in tokens:
                if tok in SHELL_META_TOKENS or any(s in tok for s in SHELL_META_SUBSTRINGS):
                    return f"Subprocess execution blocked by ExecutionPolicy: shell metacharacter in token '{tok}'."

            if "=" in t0 and not t0.startswith("-"):
                return f"Subprocess execution blocked by ExecutionPolicy: prefix env assignment '{t0}' is forbidden."

            path_err = _validate_canonical_path_syntax(t0_raw)
            if path_err is not None:
                return f"Subprocess execution blocked by ExecutionPolicy: {path_err} ('{t0_raw}')."

            base_bin = _extract_basename_lower(t0_raw)
            if not base_bin:
                return f"Subprocess execution blocked by ExecutionPolicy: empty executable basename ('{t0_raw}')."
            base_stem = base_bin[:-4] if base_bin.endswith(".exe") else base_bin
            is_raptor_ps1 = _is_safe_raptor_ps1(tokens)

            if base_bin in EXCLUDED_SCANNER_BINARIES or base_stem in _EXCLUDED_SCANNER_STEMS:
                return f"Excluded native scanner blocked by ExecutionPolicy: '{base_bin}'."

            if (
                base_bin in policy.FORBIDDEN_SHELL_COMMANDS
                or base_stem in policy.FORBIDDEN_SHELL_COMMANDS
                or base_bin in WRAPPER_BINARIES
                or base_stem in WRAPPER_BINARIES
            ) and not is_raptor_ps1:
                return f"Forbidden host OS/wrapper command blocked by ExecutionPolicy: '{base_bin}'."

            resolved_name: Optional[str] = None
            try:
                bin_path = Path(t0)
                if bin_path.exists() or bin_path.is_symlink():
                    resolved_bin = bin_path.resolve()
                    resolved_bin_s = str(resolved_bin)
                    if _is_unc_path(resolved_bin_s) or _is_drive_relative_or_colon_unsafe(resolved_bin_s):
                        return (
                            f"Subprocess execution blocked by ExecutionPolicy: resolved binary path "
                            f"'{resolved_bin_s}' is forbidden."
                        )
                    resolved_name = resolved_bin.name.lower()
                    resolved_stem = resolved_name[:-4] if resolved_name.endswith(".exe") else resolved_name
                    if (
                        resolved_name in EXCLUDED_SCANNER_BINARIES
                        or resolved_stem in _EXCLUDED_SCANNER_STEMS
                    ):
                        return f"Excluded native scanner blocked by ExecutionPolicy (resolved target): '{resolved_name}'."
                    if (
                        resolved_name in policy.FORBIDDEN_SHELL_COMMANDS
                        or resolved_stem in policy.FORBIDDEN_SHELL_COMMANDS
                        or resolved_name in WRAPPER_BINARIES
                        or resolved_stem in WRAPPER_BINARIES
                    ) and not (is_raptor_ps1 and resolved_name in ("powershell", "powershell.exe", "pwsh", "pwsh.exe")):
                        return f"Forbidden host OS/wrapper command blocked by ExecutionPolicy (resolved target): '{resolved_name}'."
                    if resolved_stem != base_stem:
                        base_family = _binary_tool_family(base_bin, is_raptor_ps1=is_raptor_ps1)
                        res_family = _binary_tool_family(resolved_name, is_raptor_ps1=is_raptor_ps1)
                        if not (base_family and res_family and base_family == res_family):
                            return (
                                f"Subprocess execution blocked by ExecutionPolicy: resolved binary "
                                f"'{resolved_name}' differs from '{base_bin}' (cross-tool or unapproved symlink target)."
                            )
            except OSError:
                pass

            for idx, arg in enumerate(tokens[1:], start=1):
                arg_s = str(arg).strip()
                arg_lower = arg_s.lower()
                is_url = _is_http_url_token(arg_s)
                forbidden_subs = (
                    ("cmd.exe", "powershell -c", "bash -c", "sh -c", "pwsh -c", "/bin/sh", "/bin/bash")
                    if is_url
                    else ("cmd.exe", "whoami", "powershell -c", "bash -c", "sh -c", "pwsh -c", "/bin/sh", "/bin/bash")
                )
                if any(forbidden in arg_lower for forbidden in forbidden_subs):
                    return f"Forbidden host OS command blocked in arguments by ExecutionPolicy: '{arg}'."

                # Consecutive shell + execution flag check (e.g. ["sh", "-c", ...], ["bash", "-lc", ...])
                if idx + 1 < len(tokens):
                    cur_name = _extract_basename_lower(arg_s)
                    next_flag = str(tokens[idx + 1]).strip().lower()
                    is_shell_flag = (
                        next_flag in ("-c", "/c", "-command", "-encodedcommand", "-e", "-ec", "-lc", "-ic")
                        or next_flag.startswith(("/co", "/en", "-co", "-en"))
                        or (
                            next_flag.startswith("-")
                            and not next_flag.startswith("--")
                            and ("c" in next_flag[1:] or "e" in next_flag[1:])
                        )
                    )
                    if cur_name in _DOCKER_PAYLOAD_SHELLS and is_shell_flag:
                        return f"Forbidden nested shell invocation blocked by ExecutionPolicy: '{cur_name} {next_flag}'."

                if "://" not in arg_s and not arg_s.startswith("-") and not is_url:
                    tok_no_digest = arg_s.split("@", 1)[0]
                    tok_name = _extract_basename_lower(tok_no_digest)
                    tok_base = tok_name.split(":", 1)[0]
                    tok_stem = tok_base[:-4] if tok_base.endswith(".exe") else tok_base
                    if tok_name in EXCLUDED_SCANNER_BINARIES or tok_base in _EXCLUDED_SCANNER_STEMS or tok_stem in _EXCLUDED_SCANNER_STEMS:
                        return f"Excluded native scanner blocked in arguments by ExecutionPolicy: '{arg_s}'."

            names_to_check = [base_bin]
            if resolved_name and resolved_name not in names_to_check:
                names_to_check.append(resolved_name)

            # Python -c / combined-c / -m / combined-m excluded-scanner checks (for both subprocess and subprocess_exec)
            if any(_is_python_binary_name(n) for n in names_to_check):
                py_err = _validate_python_tokens(tokens, set(EXCLUDED_SCANNER_BINARIES))
                if py_err:
                    return py_err

            # Unified Docker safety invariants (positional subcommand scan, --privileged, mounts, --entrypoint, payloads)
            if any((n[:-4] if n.endswith(".exe") else n) == "docker" for n in names_to_check):
                docker_err = _validate_docker_command(
                    tokens,
                    policy.FORBIDDEN_SHELL_COMMANDS,
                    set(EXCLUDED_SCANNER_BINARIES),
                )
                if docker_err:
                    return docker_err

            if act == "subprocess_exec":
                validator = getattr(policy, "validate_subprocess_command", None)
                if callable(validator):
                    ok_cmd, cmd_reason = validator(cmd_input, shell=shell)
                    if not ok_cmd:
                        return cmd_reason
                else:
                    is_python = _is_python_binary_name(base_bin)
                    is_aiscan = _is_safe_aiscan_name(base_bin)
                    is_allowed_bin = base_stem in {"httpx", "katana", "nuclei", "docker", "ollama"}
                    if not (is_python or is_aiscan or is_allowed_bin or is_raptor_ps1):
                        return f"Subprocess execution blocked by ExecutionPolicy: '{base_bin}' is not an approved scanner tool."

            # Validate SSRF on URL tokens (including -flag=http://...), obfuscated IPv4, and IP literals
            ssrf_err = _validate_command_ssrf_tokens(tokens)
            if ssrf_err:
                return ssrf_err
            for tok in tokens[1:]:
                tok_s = str(tok).strip()
                if not tok_s:
                    continue
                if "://" in tok_s:
                    tok_host, _ = _extract_token_host_candidate(tok_s)
                    if not tok_host:
                        return f"Command URL '{tok_s}' rejected by ExecutionPolicy SSRF boundary: unable to extract hostname."
                    is_local = is_explicit_loopback_host(tok_host)
                    is_safe, reason = validate_target_host(tok_host, allow_private=is_local)
                    if not is_safe:
                        return f"Command URL '{tok_s}' rejected by ExecutionPolicy SSRF boundary: {reason}"

        # 2. File-write hard invariants (path traversal & directory confinement)
        if act in ("file_write", "write"):
            try:
                policy.validate_intent(
                    StructuredIntentProposal(
                        task=ScannerTask.ARTEX_DUAL_GRAPH,
                        action_type=ActionType.FILE_WRITE,
                        file_path=target,
                    )
                )
            except (PermissionError, ValueError) as exc:
                return str(exc)

        # 3. Network / SSRF hard invariants
        host_candidate = _extract_hostname(target).rstrip(".")
        if act not in ("file_write", "write") and "://" in str(target) and not host_candidate:
            return f"Target '{target}' rejected by ExecutionPolicy SSRF boundary: malformed URL authority."
        is_non_canonical_ip = (
            act not in ("file_write", "write")
            and bool(host_candidate)
            and _is_non_canonical_ipv4_host(host_candidate)
        )
        is_ip_like = False
        if host_candidate:
            try:
                ipaddress.ip_address(host_candidate)
                is_ip_like = True
            except ValueError:
                is_ip_like = (
                    is_non_canonical_ip
                    or host_candidate in ("localhost", "localhost.localdomain")
                    or host_candidate.endswith(".localhost")
                )

        if act in ("network_socket", "network", "http", "https", "mcp_tool") or "://" in str(target) or is_ip_like:
            if act not in ("file_write", "write") and _is_unc_path(str(target)):
                return f"Target '{target}' rejected by ExecutionPolicy SSRF/UNC boundary: NT/UNC/device target is forbidden."
            if is_non_canonical_ip:
                return f"Target '{target}' rejected by ExecutionPolicy SSRF boundary: non-canonical IPv4 literal '{host_candidate}' is forbidden."
            host = host_candidate
            if host:
                is_local = is_explicit_loopback_host(host)
                is_safe, reason = validate_target_host(host, allow_private=is_local)
                if not is_safe:
                    return f"Target '{target}' rejected by ExecutionPolicy SSRF boundary: {reason}"

        return None

    def check(
        self,
        *,
        action_type: str,
        target: str = "",
        method: str = "GET",
        rationale: str = "",
        command: Optional[Union[str, List[str]]] = None,
        is_high_risk: bool = False,
        shell: bool = False,
    ) -> ApprovalDecision:
        """
        Evaluates an action with deterministic precedence:
        1. Hard `ExecutionPolicy` deny (SSRF, forbidden OS shells, path traversal — never overrideable)
        2. Configured `ApprovalRule`s (DENY rules checked before APPROVE rules)
        3. Mode fallback (`deny`, `prompt`, or `policy`)
        Raises nothing on deny — callers inspect `decision.approved` (or call `require(...)`).
        """
        from engine.execution_policy import ExecutionPolicy

        cmd_summary = " ".join(str(x) for x in command) if isinstance(command, (list, tuple)) else str(command or "")
        summary = rationale or f"{action_type} {method} {target or cmd_summary}".strip()

        # 1. Hard ExecutionPolicy deny (non-overrideable)
        hard_deny_reason = self._check_hard_execution_policy(
            action_type=action_type,
            target=target,
            method=method,
            command=command,
            shell=shell,
        )
        if hard_deny_reason:
            return self._record(
                action_type,
                target,
                method,
                rationale,
                ApprovalDecision(False, "policy", "DENY", "EXECUTION_POLICY_HARD_DENY", hard_deny_reason),
                action_summary=summary,
            )

        # 2. Explicit rules (DENY rules checked before APPROVE rules for fail-closed safety)
        with self._lock:
            rules_snapshot = list(self.rules)
            mode_snapshot = self.mode

        deny_rules = [r for r in rules_snapshot if r.action.upper() == "DENY"]
        approve_rules = [r for r in rules_snapshot if r.action.upper() == "APPROVE"]

        for rule in deny_rules:
            if rule.matches(target=target, method=method, action_summary=summary, command=command):
                return self._record(
                    action_type, target, method, rationale,
                    ApprovalDecision(False, "rule", "DENY", rule.rule_id, f"Blocked by deny rule {rule.rule_id}: {rule.description}"),
                    action_summary=summary,
                )

        for rule in approve_rules:
            if rule.matches(target=target, method=method, action_summary=summary, command=command):
                return self._record(
                    action_type, target, method, rationale,
                    ApprovalDecision(True, "rule", "APPROVE", rule.rule_id, f"Approved by rule {rule.rule_id}: {rule.description}"),
                    action_summary=summary,
                )

        # 3. Mode fallback
        if mode_snapshot == "deny":
            return self._record(
                action_type, target, method, rationale,
                ApprovalDecision(False, "system", "DENY", "", "Approval gate in dry-run deny mode."),
                action_summary=summary,
            )

        if mode_snapshot == "prompt":
            return self._prompt_human(action_type, target, method, rationale)

        # Default `policy` mode: allow non-high-risk policy-cleared actions;
        # respect ExecutionPolicy.allow_destructive for destructive HTTP methods when is_high_risk=True
        policy = ExecutionPolicy.get_instance()
        act_lower = str(action_type or "").strip().lower()
        if is_high_risk:
            if (
                act_lower not in ("subprocess", "subprocess_exec")
                and command is None
                and policy.allow_destructive
                and policy.is_destructive_method(method)
            ):
                return self._record(
                    action_type, target, method, rationale,
                    ApprovalDecision(True, "policy", "APPROVE", "", "High-risk HTTP action approved via ExecutionPolicy allow_destructive."),
                    action_summary=summary,
                )
            return self._record(
                action_type, target, method, rationale,
                ApprovalDecision(False, "policy", "DENY", "", "High-risk action denied in non-interactive policy mode without matching approve rule."),
                action_summary=summary,
            )

        # For non-high-risk subprocess actions without a matching APPROVE rule,
        # enforce ExecutionPolicy binary allowlist before granting baseline approval.
        if act_lower in ("subprocess", "subprocess_exec") or command is not None:
            cmd_input = command if command is not None else target
            tokens_for_allowlist: Optional[List[str]]
            if isinstance(cmd_input, str):
                tokens_for_allowlist = _split_command_tokens(cmd_input.strip())
            elif isinstance(cmd_input, (list, tuple)):
                tokens_for_allowlist = []
                for t in cmd_input:
                    if isinstance(t, os.PathLike):
                        try:
                            fs = os.fspath(t)
                        except TypeError:
                            tokens_for_allowlist = None
                            break
                        if not isinstance(fs, str):
                            tokens_for_allowlist = None
                            break
                        tokens_for_allowlist.append(fs)
                    else:
                        tokens_for_allowlist.append(str(t))
            else:
                tokens_for_allowlist = None

            allowlist_ok = False
            if tokens_for_allowlist:
                validator = getattr(policy, "validate_subprocess_command", None)
                if callable(validator):
                    allowlist_ok, _ = validator(tokens_for_allowlist, shell=shell)
                else:
                    from engine.execution_policy import _is_python_binary_name, _is_safe_aiscan_name

                    base_bin = _extract_basename_lower(tokens_for_allowlist[0])
                    base_stem = base_bin[:-4] if base_bin.endswith(".exe") else base_bin
                    allowlist_ok = (
                        _validate_canonical_path_syntax(tokens_for_allowlist[0]) is None
                        and bool(base_bin)
                        and (
                            _is_python_binary_name(base_bin)
                            or _is_safe_aiscan_name(base_bin)
                            or base_stem in {"httpx", "katana", "nuclei", "docker", "ollama"}
                            or _is_safe_raptor_ps1(tokens_for_allowlist)
                        )
                    )
            if not allowlist_ok:
                return self._record(
                    action_type, target, method, rationale,
                    ApprovalDecision(
                        False,
                        "policy",
                        "DENY",
                        "",
                        "Unallowlisted subprocess action denied in non-interactive policy mode without matching approve rule.",
                    ),
                    action_summary=summary,
                )

        return self._record(
            action_type, target, method, rationale,
            ApprovalDecision(True, "policy", "APPROVE", "", "Approved by non-interactive policy baseline."),
            action_summary=summary,
        )

    def _prompt_human(self, action_type: str, target: str, method: str, rationale: str) -> ApprovalDecision:
        with self._lock:
            self._output_fn(
                f"\n[APPROVAL GATE] {action_type} | {method} {target}\n"
                f"  Rationale: {rationale}\n"
                f"  Choose: [a]pprove once | [r]emember host rule | [d]eny (default) | [q]uit: "
            )
            try:
                ans = str(self._input_fn("") or "").strip().lower()
            except EOFError:
                ans = "d"

        if ans in ("q", "quit"):
            with self._lock:
                self.mode = "deny"
            return self._record(
                action_type, target, method, rationale,
                ApprovalDecision(False, "human", "DENY", "", "Aborted by CLI operator ([q]uit)."),
            )
        if ans in ("a", "y", "yes", "approve"):
            return self._record(
                action_type, target, method, rationale,
                ApprovalDecision(True, "human", "APPROVE", "", "Approved once by CLI operator."),
            )
        if ans in ("r", "remember"):
            remembered_host = _extract_hostname(target) or target
            with self._lock:
                rid = f"HUMAN-HOST-{len(self.rules) + 1:03d}"
                if remembered_host:
                    self.rules.append(
                        ApprovalRule(
                            rule_id=rid,
                            rule_type="exact_host",
                            action="APPROVE",
                            pattern=remembered_host,
                            description="Operator remembered host",
                            method_scope=str(method or "").strip().upper(),
                        )
                    )
            return self._record(
                action_type, target, method, rationale,
                ApprovalDecision(True, "human", "APPROVE", rid, f"Approved and remembered host rule {rid} ({remembered_host})."),
            )
        return self._record(
            action_type, target, method, rationale,
            ApprovalDecision(False, "human", "DENY", "", "Denied by CLI operator."),
        )

    def require(self, **kwargs: Any) -> ApprovalDecision:
        dec = self.check(**kwargs)
        if not dec.approved:
            raise PermissionError(f"ApprovalGate denied action ({dec.decided_by}): {dec.reason}")
        return dec
