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

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple, Union


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

    # State-mutating methods that alter server state or delete resources
    DESTRUCTIVE_HTTP_METHODS: Set[str] = {
        "PUT",
        "DELETE",
        "PATCH",
        "DROP",
        "PURGE",
    }

    # Prohibited shell binaries and system execution commands
    FORBIDDEN_SHELL_COMMANDS: Set[str] = {
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "sh",
        "bash",
        "zsh",
        "ksh",
        "csh",
        "dash",
        "curl",
        "curl.exe",
        "wget",
        "wget.exe",
        "whoami",
        "whoami.exe",
        "id",
        "net",
        "net.exe",
        "ipconfig",
        "ifconfig",
        "cat",
        "calc",
        "calc.exe",
        "mshta",
        "mshta.exe",
        "rundll32",
        "rundll32.exe",
        "wscript",
        "cscript",
    }

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
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
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

        # Enforce mathematical SSRF validation
        is_local = is_explicit_loopback_host(cleaned_host)
        is_safe_net, net_reason = validate_target_host(cleaned_host, allow_private=is_local)
        if not is_safe_net:
            raise PermissionError(f"Target '{host}' rejected by SSRF safety boundary: {net_reason}")

        # Enforce TargetAuthorizationGate
        TargetAuthorizationGate.check_target(cleaned_host)

        # Destructive action gating
        method_str = (proposal.http_method or "").strip().upper()
        method_destructive = self.is_destructive_method(method_str)
        task_destructive = (
            proposal.is_destructive
            or (isinstance(proposal.task, ScannerTask) and proposal.task == ScannerTask.RQP_WEAPONIZER)
            or (str(proposal.task).lower() == ScannerTask.RQP_WEAPONIZER.value)
        )

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

    def _validate_subprocess_intent(self, proposal: StructuredIntentProposal) -> bool:
        cmd_args = proposal.command_args
        if not cmd_args:
            raise PermissionError("Subprocess execution blocked: empty or null command arguments.")

        cmd_entry = str(cmd_args[0]).strip().replace("\\", "/")
        binary_name = Path(cmd_entry).name.lower()

        # Check if this is the approved RAPTOR launcher script
        is_raptor_ps1 = (
            binary_name in ("powershell", "powershell.exe", "pwsh", "pwsh.exe")
            and len(cmd_args) >= 3
            and any("raptorscan" in str(a).lower() for a in cmd_args)
        )

        # Reject prohibited shell and OS binaries unconditionally (unless approved scanner script)
        if binary_name in self.FORBIDDEN_SHELL_COMMANDS and not is_raptor_ps1:
            raise PermissionError(
                f"Unrequested host OS command execution blocked by execution policy: '{binary_name}' is forbidden."
            )

        for arg in cmd_args[1:]:
            arg_lower = str(arg).lower()
            if any(forbidden in arg_lower for forbidden in ("cmd.exe", "whoami", "powershell -c", "bash -c")):
                raise PermissionError(
                    f"Unrequested host OS command execution blocked in arguments: '{arg}'"
                )

        # Whitelist legitimate scanner tools:
        # 1. sys.executable running isolated canary script in temp dir
        # 2. aiscan scanner
        # 3. ollama daemon
        # 4. Invoke-RaptorScan script for RAPTOR web scan
        is_python = binary_name.startswith("python")
        is_aiscan = "aiscan" in binary_name
        is_ollama = binary_name == "ollama" or binary_name == "ollama.exe"
        is_raptor_ps1 = (
            binary_name in ("powershell", "powershell.exe", "pwsh", "pwsh.exe")
            and len(cmd_args) >= 3
            and any("raptorscan" in str(a).lower() for a in cmd_args)
        )

        if not (is_python or is_aiscan or is_ollama or is_raptor_ps1):
            raise PermissionError(
                f"Unrequested host OS command execution blocked by execution policy: '{binary_name}' is not an approved scanner tool."
            )

        return True

    def _validate_file_write_intent(self, proposal: StructuredIntentProposal) -> bool:
        raw_path = proposal.file_path
        if not raw_path:
            raise ValueError("File write action requires a file_path.")

        path_str = str(raw_path).strip().replace("\x00", "")

        # Reject path traversal patterns
        norm_parts = path_str.replace("\\", "/").split("/")
        if ".." in norm_parts:
            raise PermissionError(
                f"Arbitrary file write blocked outside designated report directories: path traversal '..' detected in '{path_str}'."
            )

        resolved_path = Path(path_str).resolve()
        rfchunt_root = Path(__file__).resolve().parent.parent

        # Tempdir is permitted for isolated scratch work
        temp_root = Path(tempfile.gettempdir()).resolve()
        if str(resolved_path).startswith(str(temp_root)):
            return True

        # Database file is permitted
        if resolved_path.name.endswith(".db") or resolved_path.name.endswith(".sqlite"):
            return True

        # Check allowed subdirectories within rfchunt root or report dirs
        for allowed_sub in self.ALLOWED_WRITE_SUBDIRS:
            allowed_dir = (rfchunt_root / allowed_sub).resolve()
            if str(resolved_path).startswith(str(allowed_dir)):
                return True

        # If writing to a direct filename like 'reports/foo.sarif'
        try:
            rel = resolved_path.relative_to(rfchunt_root)
            top_level = rel.parts[0] if rel.parts else ""
            if top_level in self.ALLOWED_WRITE_SUBDIRS or resolved_path.name.endswith(".db"):
                return True
        except ValueError:
            pass

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

    return True, data, None
