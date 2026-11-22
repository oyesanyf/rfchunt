"""
Module 21: `morluto/rea` Surface, Bundle & Electron Artifact Security Analyzer
==============================================================================
Pure-CLI, offline-first static & same-origin client bundle security auditor
inspired by and interoperable with `morluto/rea` (*REA: Reverse Engineer Anything*).

CREDIT & ATTRIBUTION:
---------------------
- Project : morluto/rea (Reverse Engineer Anything)
- URL     : https://github.com/morluto/rea
- Package : rea-agents (MIT License)

Scope Boundary:
---------------
Strictly confined to authorized web/API/AppSec client-bundle surface auditing:
- JavaScript / TypeScript / Web frontend bundles (`.js`, `.ts`, `.mjs`, `.cjs`, `.jsx`, `.tsx`)
- Source maps (`.map`) and HTML script inventories (`.html`, `.htm`)
- Electron `.asar` application archives (`package.json`, `webPreferences`, IPC channels)
- Optional opt-in local `rea-agents` CLI (`analyze-javascript-application` / `analyze-website`)
Native binary decompilers (Ghidra/IDA/Hopper/radare2) and DRM circumvention are excluded fail-closed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import html.parser
import json
import logging
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse

from engine.approval_gate import ApprovalGate
from engine.artex_bridge import TrafficCaptureSession
from engine.dual_graph_engine import NoiseGovernor
from engine.execution_policy import (
    ActionType,
    ExecutionPolicy,
    ScannerTask,
    StructuredIntentProposal,
    _validate_canonical_path_syntax,
)
from engine.host_containment import silent_subprocess_run
from engine.safe_network_validator import (
    is_explicit_loopback_host,
    parse_host_and_port,
    validate_and_authorize_target,
)

logger = logging.getLogger("rfchunt.rea")

REA_ATTRIBUTION_URL = "https://github.com/morluto/rea"
REA_SCANNER_NAME = "Module-21-REA"

JS_ARTIFACT_EXTENSIONS: Tuple[str, ...] = (
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".jsx",
    ".tsx",
    ".asar",
    ".map",
    ".html",
    ".htm",
)

EXCLUDED_BINARY_EXTENSIONS: Tuple[str, ...] = (
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".elf",
    ".sys",
    ".drv",
    ".ko",
)

STATIC_ASSET_EXTENSIONS: Tuple[str, ...] = (
    ".css",
    ".scss",
    ".less",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".webp",
    ".avif",
    ".pdf",
    ".mp4",
    ".webm",
    ".mp3",
    ".wav",
    ".wasm",
    ".map",
)

MIME_PREFIXES: Tuple[str, ...] = (
    "application/",
    "text/",
    "image/",
    "font/",
    "audio/",
    "video/",
    "multipart/",
)

NOISE_ROUTE_PREFIXES: Tuple[str, ...] = (
    "/__webpack",
    "/webpack",
    "/node_modules/",
    "/static/js/",
    "/static/css/",
    "/static/media/",
    "/_next/static/",
    "/assets/index-",
    "/build/static/",
)

SKIP_WALK_DIRS: Set[str] = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "reports",
    "runs",
    "caldera_export",
    ".pytest_cache",
}

MAX_ASAR_HEADER_BYTES = 16 * 1024 * 1024  # 16 MiB cap against malformed ASAR pickle headers
MAX_ASAR_ENTRY_BYTES = 8 * 1024 * 1024    # 8 MiB per inner file
MAX_STATIC_BUNDLE_BYTES = 10 * 1024 * 1024  # 10 MiB per on-disk bundle

DEFAULT_MAX_ENDPOINTS_PER_BUNDLE = 25
DEFAULT_MAX_FINDINGS_PER_BUNDLE = 20
DEFAULT_MAX_TOTAL_ENDPOINTS = 60
DEFAULT_MAX_LIVE_SCRIPTS = 15
DEFAULT_MAX_SCRIPT_BYTES = 2 * 1024 * 1024      # 2 MiB per live script
DEFAULT_MAX_TOTAL_LIVE_BYTES = 15 * 1024 * 1024  # 15 MiB total live scripts


class _ScriptSrcParser(html.parser.HTMLParser):
    """Extracts `<script src="...">` and inline `<script>` blocks from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.script_srcs: List[str] = []
        self.inline_scripts: List[str] = []
        self._in_inline_script = False
        self._inline_buf: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "script":
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs if k}
        src = attr_map.get("src", "").strip()
        if src:
            self.script_srcs.append(src)
        else:
            self._in_inline_script = True
            self._inline_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_inline_script and data:
            self._inline_buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_inline_script:
            self._in_inline_script = False
            joined = "".join(self._inline_buf).strip()
            if joined:
                self.inline_scripts.append(joined)
            self._inline_buf = []


@dataclass
class ReaFinding:
    finding_id: str
    rule_id: str
    title: str
    severity: str
    cwe: str
    file_path: str
    line_number: int
    evidence: str
    limitations: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    capability_class: str = "AUTH_BOUNDARY"
    scanner: str = REA_SCANNER_NAME
    source_mode: str = "python_static"
    route: str = ""
    http_method: str = "GET"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReaAnalysisResult:
    target: str
    status: str = "completed"
    mode: str = "python_static"
    discovered_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    ipc_channels: List[Dict[str, Any]] = field(default_factory=list)
    ai_sinks: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[ReaFinding] = field(default_factory=list)
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    report_files: Dict[str, str] = field(default_factory=dict)
    attribution_url: str = REA_ATTRIBUTION_URL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "status": self.status,
            "mode": self.mode,
            "total_findings": len(self.findings),
            "total_endpoints": len(self.discovered_endpoints),
            "total_ai_sinks": len(self.ai_sinks),
            "total_ipc_channels": len(self.ipc_channels),
            "discovered_endpoints": list(self.discovered_endpoints),
            "ipc_channels": list(self.ipc_channels),
            "ai_sinks": list(self.ai_sinks),
            "findings": [f.to_dict() for f in self.findings],
            "evidence_items": list(self.evidence_items),
            "limitations": list(self.limitations),
            "unknowns": list(self.unknowns),
            "report_files": dict(self.report_files),
            "attribution_url": self.attribution_url,
        }


# Compiled detection patterns for client-bundle / Electron surface inspection
_ROUTE_LITERAL_RX = re.compile(
    r"""(?P<q>["'`])(?P<route>/(?:api|internal|admin|service|v[1-9]\d*|graphql|ws|mcp|oauth|oidc|auth|debug|metrics|actuator|management| chat|completions)(?:/[A-Za-z0-9._~:@!$&'()*+,;=%{}-]+)*)(?P=q)""",
    re.IGNORECASE,
)
_FETCH_CALL_RX = re.compile(
    r"""\b(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*["'`](?P<route>/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%{}-]{2,160})["'`]""",
    re.IGNORECASE,
)
_WS_URL_RX = re.compile(
    r"""["'`](?P<ws>wss?://[A-Za-z0-9._:-]+(?:/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%{}-]*)?)["'`]""",
    re.IGNORECASE,
)
_AI_ROUTE_HINT_RX = re.compile(
    r"(?i)/(?:chat|completions|embeddings|generate|prompt|llm|ai|rag|infer|messages|assistants|mcp)\b"
)
_PRIVILEGED_ROUTE_HINT_RX = re.compile(
    r"(?i)^/(?:internal|service|admin|management|actuator|debug|metrics)(?:/|$)"
)
_ELECTRON_INSECURE_PREF_RX: List[Tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"\bnodeIntegration\s*:\s*true\b"),
        "nodeIntegration: true",
        "CRITICAL",
        "CWE-94",
    ),
    (
        re.compile(r"\bcontextIsolation\s*:\s*false\b"),
        "contextIsolation: false",
        "HIGH",
        "CWE-693",
    ),
    (
        re.compile(r"\bwebSecurity\s*:\s*false\b"),
        "webSecurity: false",
        "HIGH",
        "CWE-346",
    ),
    (
        re.compile(r"\ballowRunningInsecureContent\s*:\s*true\b"),
        "allowRunningInsecureContent: true",
        "MEDIUM",
        "CWE-319",
    ),
    (
        re.compile(r"\bsandbox\s*:\s*false\b"),
        "sandbox: false",
        "MEDIUM",
        "CWE-269",
    ),
]
_IPC_CHANNEL_RX = re.compile(
    r"""\b(?P<api>ipcMain\.(?:handle|on)|ipcRenderer\.(?:invoke|send|sendSync))\s*\(\s*["'`](?P<channel>[A-Za-z0-9:._/-]{1,100})["'`]"""
)
_DANGEROUS_IPC_SINK_RX = re.compile(
    r"\b(?:child_process|execSync|execFile|spawn\s*\(|shell\.openExternal\s*\(|eval\s*\(|fs\.writeFile)"
)
_CLIENT_SECRET_PATTERNS: List[Tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"""["'](sk-(?:proj-)?[A-Za-z0-9_-]{24,})["']"""), "OpenAI Secret Key in Client Bundle", "CRITICAL"),
    (re.compile(r"""["'](sk-ant-[A-Za-z0-9_-]{24,})["']"""), "Anthropic Secret Key in Client Bundle", "CRITICAL"),
    (re.compile(r"""["'](AIzaSy[A-Za-z0-9_-]{33})["']"""), "Google API Key in Client Bundle", "HIGH"),
    (re.compile(r"""["'](ghp_[A-Za-z0-9]{30,})["']"""), "GitHub Personal Access Token in Client Bundle", "CRITICAL"),
    (re.compile(r"""["'](AKIA[0-9A-Z]{16})["']"""), "AWS Access Key ID in Client Bundle", "HIGH"),
    (
        re.compile(r"""(?i)(?:client_secret|service_token|internal_api_key|admin_token)\s*[:=]\s*["']([A-Za-z0-9._~+/-]{16,128})["']"""),
        "Hardcoded Client/Service Secret in Bundle",
        "HIGH",
    ),
]
_OIDC_CONFIG_RX = re.compile(
    r"""(?i)\b(?P<key>audience|client_id|issuer|authority|redirect_uri|token_endpoint)\s*:\s*["'`](?P<val>[^"'`\r\n]{4,180})["'`]"""
)
_SOURCEMAP_DIRECTIVE_RX = re.compile(r"//#\s*sourceMappingURL=(?P<url>\S+)")


def _make_finding_id(rule_id: str, file_path: str, line_num: int, extra: str = "") -> str:
    digest = hashlib.sha256(f"{rule_id}|{file_path}|{line_num}|{extra}".encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"{rule_id}-{digest}"


def _mask_secret(raw: str) -> str:
    if len(raw) <= 10:
        return raw[:2] + "***"
    return f"{raw[:5]}...{raw[-3:]}"


def _is_noise_route(candidate: str) -> bool:
    s = (candidate or "").strip()
    if not s or len(s) < 2 or len(s) > 180:
        return True
    if not s.startswith("/"):
        return True
    if s.startswith("//") or "\\" in s or any(ord(c) < 33 for c in s):
        return True
    low = s.lower()
    no_q = low.split("?", 1)[0].split("#", 1)[0]
    if no_q in ("/", "/.", "/.."):
        return True
    # Filter MIME types (e.g. "/json" when preceded by application, or "text/html" without leading slash; also "/application/json" style fragments)
    stripped = no_q.lstrip("/")
    if any(stripped.startswith(mp) for mp in MIME_PREFIXES):
        return True
    if any(no_q.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS):
        return True
    if any(no_q.startswith(pref) for pref in NOISE_ROUTE_PREFIXES):
        return True
    # Filter regex literals mistakenly matched such as `/[a-z]+/g`
    if any(ch in no_q for ch in ("^", "$", "*", "(", ")", "[", "]", "|")):
        return True
    return False


def parse_asar_archive(
    asar_path: Path,
    *,
    max_header_bytes: int = MAX_ASAR_HEADER_BYTES,
    max_entry_bytes: int = MAX_ASAR_ENTRY_BYTES,
) -> Tuple[Dict[str, bytes], List[str]]:
    """
    Safely parses a Chromium/Electron `.asar` archive header and extracts text-inspectable
    entries (`package.json`, `.js`, `.mjs`, `.cjs`, `.ts`, `.map`, `.html`) in memory
    without executing target code or risking header memory bombs.
    """
    limitations: List[str] = []
    extracted: Dict[str, bytes] = {}
    file_size = asar_path.stat().st_size
    if file_size < 16:
        raise ValueError(f"Invalid .asar archive '{asar_path.name}': file smaller than 16-byte Chromium Pickle header.")

    with open(asar_path, "rb") as fh:
        preamble = fh.read(16)
        if len(preamble) < 16:
            raise ValueError(f"Truncated .asar header in '{asar_path.name}'.")
        pickle_size, header_total_size, json_pickle_size, json_str_len = struct.unpack("<IIII", preamble)
        if pickle_size != 4:
            raise ValueError(f"Invalid .asar pickle size prefix ({pickle_size} != 4) in '{asar_path.name}'.")
        if json_str_len == 0 or json_str_len > max_header_bytes or header_total_size > max_header_bytes + 64:
            raise ValueError(
                f"Rejected .asar header size ({json_str_len} bytes exceeds safety cap {max_header_bytes} bytes)."
            )
        data_base_offset = 8 + header_total_size
        if data_base_offset > file_size:
            raise ValueError(f"Corrupt .asar header offset ({data_base_offset} > file size {file_size}).")

        raw_json = fh.read(json_str_len)
        if len(raw_json) < json_str_len:
            raise ValueError(f"Truncated .asar JSON index in '{asar_path.name}'.")
        try:
            index_obj = json.loads(raw_json.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Malformed .asar JSON header in '{asar_path.name}': {exc}") from exc

        if not isinstance(index_obj, dict) or not isinstance(index_obj.get("files"), dict):
            raise ValueError(f"Missing top-level 'files' map in .asar archive '{asar_path.name}'.")

        inspectable_exts = {".json", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".map", ".html", ".htm"}

        def _walk_tree(prefix: str, files_dict: Dict[str, Any]) -> None:
            for name, meta in files_dict.items():
                if not isinstance(meta, dict):
                    continue
                clean_seg = str(name).replace("\\", "/").strip("/")
                if not clean_seg or clean_seg in (".", "..") or "/" in clean_seg:
                    continue
                rel_path = f"{prefix}/{clean_seg}" if prefix else clean_seg
                if isinstance(meta.get("files"), dict):
                    if clean_seg not in ("node_modules", ".git"):
                        _walk_tree(rel_path, meta["files"])
                    else:
                        limitations.append(f"Skipped bundled dependency directory '{rel_path}' inside {asar_path.name}.")
                    continue
                if meta.get("unpacked"):
                    limitations.append(f"Skipped unpacked external entry '{rel_path}' in {asar_path.name}.")
                    continue
                ext = Path(clean_seg).suffix.lower()
                if ext not in inspectable_exts:
                    continue
                try:
                    rel_off = int(meta.get("offset", 0))
                    sz = int(meta.get("size", 0))
                except (TypeError, ValueError):
                    continue
                if rel_off < 0 or sz < 0:
                    continue
                if sz > max_entry_bytes:
                    limitations.append(
                        f"Skipped oversized entry '{rel_path}' ({sz} bytes > {max_entry_bytes} cap) in {asar_path.name}."
                    )
                    continue
                abs_off = data_base_offset + rel_off
                if abs_off + sz > file_size:
                    limitations.append(f"Out-of-bounds .asar entry '{rel_path}' skipped in {asar_path.name}.")
                    continue
                fh.seek(abs_off)
                extracted[rel_path] = fh.read(sz)

        _walk_tree("", index_obj["files"])

    return extracted, limitations


class ReaIntegrator:
    """
    Module 21 (`morluto/rea`) Pure-CLI Surface, Bundle & Electron Security Analyzer.
    """

    def __init__(
        self,
        db: Optional[Any] = None,
        reports_dir: Optional[Union[str, Path]] = None,
        approval_gate: Optional[ApprovalGate] = None,
        noise_governor: Optional[NoiseGovernor] = None,
        max_endpoints_per_bundle: int = DEFAULT_MAX_ENDPOINTS_PER_BUNDLE,
        max_findings_per_bundle: int = DEFAULT_MAX_FINDINGS_PER_BUNDLE,
        max_total_endpoints: int = DEFAULT_MAX_TOTAL_ENDPOINTS,
        max_live_scripts: int = DEFAULT_MAX_LIVE_SCRIPTS,
        max_script_bytes: int = DEFAULT_MAX_SCRIPT_BYTES,
        max_total_live_bytes: int = DEFAULT_MAX_TOTAL_LIVE_BYTES,
    ) -> None:
        self.db = db
        default_rep = Path(__file__).resolve().parent.parent / "reports"
        self.reports_dir = Path(reports_dir) if reports_dir else default_rep
        self.approval_gate = approval_gate
        self.noise_governor = noise_governor or NoiseGovernor()
        self.max_endpoints_per_bundle = max(1, int(max_endpoints_per_bundle))
        self.max_findings_per_bundle = max(1, int(max_findings_per_bundle))
        self.max_total_endpoints = max(1, int(max_total_endpoints))
        self.max_live_scripts = max(1, int(max_live_scripts))
        self.max_script_bytes = max(1024, int(max_script_bytes))
        self.max_total_live_bytes = max(self.max_script_bytes, int(max_total_live_bytes))

    @staticmethod
    def check_rea_cli_status() -> Dict[str, Any]:
        """Checks for a locally pre-installed `rea-agents` or `rea` binary (or repo-local node/rea.mjs)."""
        for bin_name in ("rea-agents", "rea"):
            found = shutil.which(bin_name)
            if found:
                p = Path(found)
                # ExecutionPolicy requires native executable or non-shell binary; report status transparently
                is_script_shim = p.suffix.lower() in (".cmd", ".bat", ".ps1", ".sh")
                if not is_script_shim:
                    return {
                        "installed": True,
                        "binary_path": str(p),
                        "binary_name": p.name,
                        "is_script_shim": False,
                        "attribution_url": REA_ATTRIBUTION_URL,
                    }
        try:
            from engine.tool_provisioner import ToolProvisioner

            entry = ToolProvisioner().find_rea_entrypoint()
            if entry and entry.get("installed"):
                entry["attribution_url"] = REA_ATTRIBUTION_URL
                return entry
        except Exception:
            pass
        return {
            "installed": False,
            "binary_path": None,
            "binary_name": None,
            "is_script_shim": False,
            "attribution_url": REA_ATTRIBUTION_URL,
        }

    def _collect_js_artifacts(self, target_path: Path) -> Tuple[List[Path], List[str]]:
        """Scans target path for JS/TS/Electron/HTML/sourcemap artifacts; rejects native binaries fail-closed."""
        limitations: List[str] = []
        if not target_path.exists():
            return [], [f"Target path does not exist: {target_path}"]

        if target_path.is_file():
            ext = target_path.suffix.lower()
            if ext in EXCLUDED_BINARY_EXTENSIONS:
                raise PermissionError(
                    f"Module 21 (`morluto/rea`) excludes native binary decompilation ('{target_path.name}'). "
                    f"Only web/JS/Electron/.asar/.map/HTML artifacts are supported."
                )
            if ext in JS_ARTIFACT_EXTENSIONS or target_path.name.lower() == "package.json":
                return [target_path], limitations
            return [], limitations

        matched: List[Path] = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_WALK_DIRS and not d.startswith(".")]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext in JS_ARTIFACT_EXTENSIONS:
                    matched.append(Path(root) / fname)
        return matched, limitations

    def _inspect_text_artifact(
        self,
        *,
        display_path: str,
        content: str,
        source_mode: str,
        seen_endpoints: Set[Tuple[str, str]],
        discovered_endpoints: List[Dict[str, Any]],
        ai_sinks: List[Dict[str, Any]],
        ipc_channels: List[Dict[str, Any]],
        findings: List[ReaFinding],
        evidence_items: List[Dict[str, Any]],
        limitations: List[str],
        unknowns: List[str],
        host_hint: Optional[str] = None,
        port_hint: Optional[int] = None,
    ) -> None:
        bundle_endpoints = 0
        bundle_findings = 0
        lines = content.splitlines() or [content]

        def _can_add_finding() -> bool:
            nonlocal bundle_findings
            if bundle_findings >= self.max_findings_per_bundle:
                return False
            bundle_findings += 1
            return True

        def _register_route(route: str, method: str, line_no: int, origin_kind: str) -> None:
            nonlocal bundle_endpoints
            if bundle_endpoints >= self.max_endpoints_per_bundle or len(discovered_endpoints) >= self.max_total_endpoints:
                return
            clean_r = route.split("?", 1)[0].split("#", 1)[0].strip()
            if _is_noise_route(clean_r):
                return
            m_up = method.upper()
            key = (m_up, clean_r)
            if key in seen_endpoints:
                return
            seen_endpoints.add(key)
            bundle_endpoints += 1
            is_ai = bool(_AI_ROUTE_HINT_RX.search(clean_r))
            rec: Dict[str, Any] = {
                "route": clean_r,
                "method": m_up,
                "node_type": "AI_SINK" if is_ai else "ENDPOINT",
                "source": "module21",
                "file_path": display_path,
                "line_number": line_no,
            }
            if host_hint:
                rec["host"] = host_hint
            if port_hint:
                rec["port"] = port_hint
            discovered_endpoints.append(rec)
            if is_ai:
                ai_sinks.append(dict(rec))
                if _can_add_finding():
                    findings.append(ReaFinding(
                        finding_id=_make_finding_id("REA-AI-ENDPOINT-007", display_path, line_no, clean_r),
                        rule_id="REA-AI-ENDPOINT-007",
                        title=f"Client-Referenced AI/LLM Endpoint ({clean_r})",
                        severity="MEDIUM",
                        cwe="CWE-200",
                        file_path=display_path,
                        line_number=line_no,
                        evidence=f"{origin_kind} references AI route '{clean_r}' ({m_up})",
                        limitations=["Static bundle discovery cannot confirm server-side rate limiting without live probe."],
                        unknowns=[f"Whether '{clean_r}' enforces strict prompt isolation and per-principal auth."],
                        capability_class="AI_INJECTION",
                        source_mode=source_mode,
                        route=clean_r,
                        http_method="POST" if m_up == "GET" else m_up,
                    ))
            elif _PRIVILEGED_ROUTE_HINT_RX.search(clean_r) and _can_add_finding():
                findings.append(ReaFinding(
                    finding_id=_make_finding_id("REA-ROUTE-001", display_path, line_no, clean_r),
                    rule_id="REA-ROUTE-001",
                    title=f"Privileged / Internal Backend Route Exposed in Client Artifact ({clean_r})",
                    severity="MEDIUM",
                    cwe="CWE-200",
                    file_path=display_path,
                    line_number=line_no,
                    evidence=f"Client bundle '{display_path}:{line_no}' references privileged route '{clean_r}'",
                    limitations=["Static route extraction requires live differential auth probing to verify access control."],
                    unknowns=[f"Whether end-user tokens are rejected on '{clean_r}' (MANTIS-AUTH-011 / AUTH_BOUNDARY)."],
                    capability_class="AUTH_BOUNDARY",
                    source_mode=source_mode,
                    route=clean_r,
                    http_method=m_up,
                ))

        # 1. Source map JSON (`sources` / `sourcesContent`) handling
        if display_path.lower().endswith(".map"):
            try:
                smap = json.loads(content)
                if isinstance(smap, dict):
                    sources = [str(s) for s in (smap.get("sources") or []) if s]
                    if sources and _can_add_finding():
                        findings.append(ReaFinding(
                            finding_id=_make_finding_id("REA-SOURCEMAP-006", display_path, 1, str(len(sources))),
                            rule_id="REA-SOURCEMAP-006",
                            title=f"Production Source Map Exposes Original Client Sources ({len(sources)} files)",
                            severity="LOW",
                            cwe="CWE-540",
                            file_path=display_path,
                            line_number=1,
                            evidence=f"Source map enumerates {len(sources)} source files (e.g. {', '.join(sources[:3])})",
                            limitations=["Source map disclosure is informational unless paired with privileged routes or secrets."],
                            unknowns=["Whether the .map file is publicly served without authentication in production."],
                            capability_class="AUTH_BOUNDARY",
                            source_mode=source_mode,
                        ))
                    src_contents = [s for s in (smap.get("sourcesContent") or []) if isinstance(s, str)]
                    if src_contents:
                        content = "\n".join(src_contents[:20])
                        lines = content.splitlines() or [content]
            except Exception:
                limitations.append(f"Could not parse JSON source map '{display_path}'; fell back to raw text scan.")

        # 2. Line-by-line inspection
        oidc_hits: Dict[str, Tuple[int, str]] = {}
        for line_no, line in enumerate(lines, start=1):
            snippet_line = line[:4000]  # Bound regex work on ultra-long minified lines
            if len(line) > 4000:
                # Scan chunked windows of minified single-line bundles (up to 512 KiB)
                windows = [line[pos : pos + 4000] for pos in range(0, min(len(line), 524288), 3900)]
            else:
                windows = [snippet_line]

            for win in windows:
                # Routes from fetch/axios
                for fm in _FETCH_CALL_RX.finditer(win):
                    call_txt = fm.group(0).lower()
                    meth = "POST" if ".post" in call_txt else ("PUT" if ".put" in call_txt else ("DELETE" if ".delete" in call_txt else "GET"))
                    _register_route(fm.group("route"), meth, line_no, "HTTP client call")

                # Routes from string literals
                for rm in _ROUTE_LITERAL_RX.finditer(win):
                    r_val = rm.group("route")
                    meth = "POST" if _AI_ROUTE_HINT_RX.search(r_val) else "GET"
                    _register_route(r_val, meth, line_no, "Bundle route literal")

                # WebSocket endpoints
                for wm in _WS_URL_RX.finditer(win):
                    ws_url = wm.group("ws")
                    parsed_ws = urlparse(ws_url)
                    ws_path = parsed_ws.path or "/ws"
                    _register_route(ws_path, "GET", line_no, f"WebSocket endpoint ({ws_url[:80]})")

                # Electron BrowserWindow insecure webPreferences
                for rx, pref_label, sev, cwe in _ELECTRON_INSECURE_PREF_RX:
                    if rx.search(win) and _can_add_finding():
                        findings.append(ReaFinding(
                            finding_id=_make_finding_id("REA-ELECTRON-003", display_path, line_no, pref_label),
                            rule_id="REA-ELECTRON-003",
                            title=f"Insecure Electron webPreferences ({pref_label})",
                            severity=sev,
                            cwe=cwe,
                            file_path=display_path,
                            line_number=line_no,
                            evidence=f"{display_path}:{line_no} configures `{pref_label}`",
                            limitations=["Static configuration match; verify whether untrusted remote content can reach this BrowserWindow."],
                            unknowns=["Whether CSP or navigation guards restrict renderer origins."],
                            capability_class="EXEC_SINK",
                            source_mode=source_mode,
                        ))

                # Electron IPC channels & dangerous main-process sinks
                for im in _IPC_CHANNEL_RX.finditer(win):
                    api_call = im.group("api")
                    chan = im.group("channel")
                    ipc_channels.append({
                        "channel": chan,
                        "api": api_call,
                        "file_path": display_path,
                        "line_number": line_no,
                    })
                    if api_call.startswith("ipcMain."):
                        ctx_end = min(len(lines), line_no + 12)
                        handler_window = "\n".join(lines[line_no - 1 : ctx_end])[:2000]
                        has_dangerous_sink = bool(_DANGEROUS_IPC_SINK_RX.search(handler_window))
                        has_sender_check = any(
                            g in handler_window for g in ("senderFrame", "event.sender", "validateSender", "allowedOrigins")
                        )
                        if (has_dangerous_sink or not has_sender_check) and _can_add_finding():
                            sev = "HIGH" if has_dangerous_sink else "MEDIUM"
                            findings.append(ReaFinding(
                                finding_id=_make_finding_id("REA-IPC-002", display_path, line_no, chan),
                                rule_id="REA-IPC-002",
                                title=f"Electron IPC Handler Missing Sender Validation ('{chan}')",
                                severity=sev,
                                cwe="CWE-285" if not has_dangerous_sink else "CWE-78",
                                file_path=display_path,
                                line_number=line_no,
                                evidence=(
                                    f"`{api_call}('{chan}')` in {display_path}:{line_no}"
                                    + (" invokes OS/shell sink without senderFrame check" if has_dangerous_sink else " lacks event.senderFrame origin validation")
                                ),
                                limitations=["Static window inspection around ipcMain registration."],
                                unknowns=[f"Whether preload script exposes '{chan}' directly via contextBridge."],
                                capability_class="EXEC_SINK" if has_dangerous_sink else "AUTH_BOUNDARY",
                                source_mode=source_mode,
                            ))

                # Hardcoded client-side secrets / API keys
                for s_rx, s_title, s_sev in _CLIENT_SECRET_PATTERNS:
                    sm = s_rx.search(win)
                    if sm and _can_add_finding():
                        masked = _mask_secret(sm.group(1))
                        findings.append(ReaFinding(
                            finding_id=_make_finding_id("REA-SECRET-004", display_path, line_no, masked),
                            rule_id="REA-SECRET-004",
                            title=s_title,
                            severity=s_sev,
                            cwe="CWE-798",
                            file_path=display_path,
                            line_number=line_no,
                            evidence=f"Embedded credential `{masked}` in client-shipped artifact {display_path}:{line_no}",
                            limitations=["Token liveness and scope are not tested passively."],
                            unknowns=["Whether the embedded key grants write or service-level privileges."],
                            capability_class="AUTH_SECRET",
                            source_mode=source_mode,
                        ))

                # OIDC / JWT client configuration discovery
                for om in _OIDC_CONFIG_RX.finditer(win):
                    k_low = om.group("key").lower()
                    v_str = om.group("val").strip()
                    if k_low not in oidc_hits and v_str:
                        oidc_hits[k_low] = (line_no, v_str)

                # SourceMappingURL directive
                sm_dir = _SOURCEMAP_DIRECTIVE_RX.search(win)
                if sm_dir and not sm_dir.group("url").startswith("data:") and _can_add_finding():
                    map_ref = sm_dir.group("url")[:120]
                    findings.append(ReaFinding(
                        finding_id=_make_finding_id("REA-SOURCEMAP-006", display_path, line_no, map_ref),
                        rule_id="REA-SOURCEMAP-006",
                        title=f"Bundle References External Source Map ({map_ref})",
                        severity="LOW",
                        cwe="CWE-540",
                        file_path=display_path,
                        line_number=line_no,
                        evidence=f"`sourceMappingURL={map_ref}` in {display_path}:{line_no}",
                        limitations=["Directive presence does not prove the .map asset is reachable over HTTP."],
                        unknowns=[f"Whether '{map_ref}' is served publicly on the target host."],
                        capability_class="AUTH_BOUNDARY",
                        source_mode=source_mode,
                    ))

        if ("audience" in oidc_hits or ("client_id" in oidc_hits and "issuer" in oidc_hits)) and _can_add_finding():
            first_line = next(iter(oidc_hits.values()))[0]
            summary_pairs = ", ".join(f"{k}='{v[1][:60]}'" for k, v in sorted(oidc_hits.items()))
            findings.append(ReaFinding(
                finding_id=_make_finding_id("REA-OIDC-005", display_path, first_line, summary_pairs),
                rule_id="REA-OIDC-005",
                title="Client OIDC / JWT Audience Configuration Discovered",
                severity="LOW",
                cwe="CWE-287",
                file_path=display_path,
                line_number=first_line,
                evidence=f"OIDC client parameters in {display_path}:{first_line}: {summary_pairs}",
                limitations=["OIDC client config is expected in SPAs; risk arises if backend service routes accept this end-user audience."],
                unknowns=["Whether backend `/internal` or `/service` endpoints validate `aud` against service-only audiences (MANTIS-AUTH-011)."],
                capability_class="AUTH_BOUNDARY",
                source_mode=source_mode,
            ))

        if bundle_endpoints >= self.max_endpoints_per_bundle:
            limitations.append(
                f"Capped extracted routes for '{display_path}' at {self.max_endpoints_per_bundle} to prevent planner fan-out."
            )
        if bundle_findings >= self.max_findings_per_bundle:
            limitations.append(
                f"Capped findings for '{display_path}' at {self.max_findings_per_bundle} to suppress minified bundle noise."
            )

        evidence_items.append({
            "artifact": display_path,
            "mode": source_mode,
            "endpoints_extracted": bundle_endpoints,
            "findings_emitted": bundle_findings,
        })

    def _fetch_live_frontend_bundles(
        self,
        *,
        host: str,
        port: Optional[int],
        use_tls: bool,
        authorized: bool,
        traffic_session: Optional[TrafficCaptureSession],
        seen_endpoints: Set[Tuple[str, str]],
        discovered_endpoints: List[Dict[str, Any]],
        ai_sinks: List[Dict[str, Any]],
        ipc_channels: List[Dict[str, Any]],
        findings: List[ReaFinding],
        evidence_items: List[Dict[str, Any]],
        limitations: List[str],
        unknowns: List[str],
    ) -> None:
        clean_host, resolved_port, resolved_tls = parse_host_and_port(
            host,
            default_port=port,
            use_tls=True if use_tls else None,
        )
        is_loopback = is_explicit_loopback_host(clean_host)
        ok, reason = validate_and_authorize_target(clean_host, authorized=authorized)
        if not ok:
            raise PermissionError(reason)

        policy = ExecutionPolicy.get_instance()
        policy.validate_intent(StructuredIntentProposal(
            task=ScannerTask.REA_SURFACE,
            action_type=ActionType.NETWORK_SOCKET,
            target_host=clean_host,
            target_port=resolved_port,
            http_method="GET",
            rationale=f"Module 21 REA live same-origin frontend script discovery on {clean_host}:{resolved_port}",
        ))
        if os.environ.get("RFCHUNT_OFFLINE") == "1" and not is_loopback:
            limitations.append(f"Skipped live frontend bundle mining for '{clean_host}' under RFCHUNT_OFFLINE=1.")
            return
        if self.approval_gate is not None:
            self.approval_gate.require(
                action_type=ActionType.NETWORK_SOCKET.value,
                target=f"{clean_host}:{resolved_port}",
                method="GET",
                rationale="Module 21 REA non-destructive GET of root HTML and same-origin JS bundles",
            )

        scheme = "https" if resolved_tls else "http"
        host_fmt = f"[{clean_host}]" if ":" in clean_host and not clean_host.startswith("[") else clean_host
        base_url = f"{scheme}://{host_fmt}:{resolved_port}/"

        owns_session = traffic_session is None
        session = traffic_session or TrafficCaptureSession(db=self.db, task_id="rea_surface")
        eff_authorized = bool(authorized or is_loopback)
        total_bytes = 0
        scripts_fetched = 0
        try:
            self.noise_governor.acquire_slot(clean_host)
            root_ex = session.send_and_capture("GET", base_url, authorized=eff_authorized, timeout=8.0)
            root_bytes = root_ex.decoded_response_bytes()
            if root_ex.status_code <= 0 or not root_bytes:
                unknowns.append(f"Root page {base_url} returned status {root_ex.status_code} with empty body.")
                return

            html_text = root_bytes[: self.max_script_bytes].decode("utf-8", errors="replace")
            parser = _ScriptSrcParser()
            try:
                parser.feed(html_text)
            except Exception:
                pass

            for idx, inline_js in enumerate(parser.inline_scripts[:5], start=1):
                self._inspect_text_artifact(
                    display_path=f"{base_url}#inline-script-{idx}",
                    content=inline_js,
                    source_mode="live_same_origin",
                    seen_endpoints=seen_endpoints,
                    discovered_endpoints=discovered_endpoints,
                    ai_sinks=ai_sinks,
                    ipc_channels=ipc_channels,
                    findings=findings,
                    evidence_items=evidence_items,
                    limitations=limitations,
                    unknowns=unknowns,
                    host_hint=clean_host,
                    port_hint=resolved_port,
                )

            seen_script_urls: Set[str] = set()
            for raw_src in parser.script_srcs:
                if scripts_fetched >= self.max_live_scripts or total_bytes >= self.max_total_live_bytes:
                    limitations.append(
                        f"Reached live JS fetch cap (scripts={scripts_fetched}/{self.max_live_scripts}, bytes={total_bytes}/{self.max_total_live_bytes})."
                    )
                    break
                resolved_url = urljoin(base_url, raw_src)
                parsed_u = urlparse(resolved_url)
                if parsed_u.scheme.lower() not in ("http", "https"):
                    continue
                u_host = (parsed_u.hostname or "").strip().lower().rstrip(".")
                u_port = parsed_u.port or (443 if parsed_u.scheme.lower() == "https" else 80)
                # Strictly enforce same-origin host & port!
                if u_host != clean_host or u_port != resolved_port:
                    limitations.append(f"Skipped cross-origin script '{resolved_url}' (same-origin policy enforced).")
                    continue
                if resolved_url in seen_script_urls:
                    continue
                seen_script_urls.add(resolved_url)

                self.noise_governor.acquire_slot(clean_host)
                js_ex = session.send_and_capture("GET", resolved_url, authorized=eff_authorized, timeout=8.0)
                if js_ex.status_code != 200:
                    continue
                js_body = js_ex.decoded_response_bytes()
                if len(js_body) > self.max_script_bytes:
                    limitations.append(
                        f"Truncated live script '{resolved_url}' at {self.max_script_bytes} bytes (original {len(js_body)} bytes)."
                    )
                    js_body = js_body[: self.max_script_bytes]
                total_bytes += len(js_body)
                scripts_fetched += 1
                self._inspect_text_artifact(
                    display_path=resolved_url,
                    content=js_body.decode("utf-8", errors="replace"),
                    source_mode="live_same_origin",
                    seen_endpoints=seen_endpoints,
                    discovered_endpoints=discovered_endpoints,
                    ai_sinks=ai_sinks,
                    ipc_channels=ipc_channels,
                    findings=findings,
                    evidence_items=evidence_items,
                    limitations=limitations,
                    unknowns=unknowns,
                    host_hint=clean_host,
                    port_hint=resolved_port,
                )
        finally:
            if owns_session and hasattr(session, "close"):
                session.close()

    def run_rea_cli(
        self,
        target: str,
        command: str = "analyze-javascript-application",
        timeout_sec: int = 60,
        *,
        auto_install: bool = True,
    ) -> Dict[str, Any]:
        """
        Opt-in adapter for local `rea-agents` CLI (`shell=False` only, never `npx -y ...@latest`).
        Dynamically installs `rea-agents` locally via ToolProvisioner when live online and missing.
        """
        if os.environ.get("RFCHUNT_OFFLINE") == "1":
            return {"ok": False, "reason": "offline_mode", "data": {}}
        if command not in ("analyze-javascript-application", "analyze-website"):
            raise PermissionError(f"Disallowed rea-agents command '{command}'.")

        cli_info = self.check_rea_cli_status()
        if (not cli_info.get("installed") or not cli_info.get("binary_path")) and auto_install:
            try:
                from engine.tool_provisioner import ToolProvisioner
                prov = ToolProvisioner()
                if not prov.is_offline_or_blocked():
                    prov.ensure_tool("rea_agents")
                    cli_info = self.check_rea_cli_status()
            except Exception as exc:
                logger.debug("Dynamic rea-agents install skipped/failed: %s", exc)

        if not cli_info.get("installed") or not cli_info.get("binary_path"):
            return {"ok": False, "reason": "rea_cli_not_installed", "data": {}}

        bin_path = str(cli_info["binary_path"])
        if cli_info.get("mode") == "node_mjs" and cli_info.get("script_path"):
            argv = [bin_path, str(cli_info["script_path"]), command, str(target), "--json"]
        else:
            argv = [bin_path, command, str(target), "--json"]

        policy = ExecutionPolicy.get_instance()
        policy.validate_intent(StructuredIntentProposal(
            task=ScannerTask.REA_SURFACE,
            action_type=ActionType.SUBPROCESS_EXEC,
            command_args=argv,
            rationale=f"Opt-in Module 21 rea-agents {command} on {target}",
            metadata={"shell": False},
        ))
        if self.approval_gate is not None:
            self.approval_gate.require(
                action_type=ActionType.SUBPROCESS_EXEC.value,
                target=str(target),
                command=argv,
                rationale=f"Execute local rea-agents {command}",
            )

        proc = silent_subprocess_run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            check=False,
        )
        if proc.returncode != 0 or not (proc.stdout or "").strip():
            return {
                "ok": False,
                "reason": f"rea_cli_exit_{proc.returncode}",
                "stderr": (proc.stderr or "")[:400],
                "data": {},
            }
        try:
            parsed = json.loads(proc.stdout)
            if isinstance(parsed, dict):
                return {"ok": True, "reason": "ok", "data": parsed}
        except Exception as exc:
            return {"ok": False, "reason": f"malformed_json: {exc}", "data": {}}
        return {"ok": False, "reason": "unexpected_json_shape", "data": {}}

    def analyze(
        self,
        target_path: Optional[Union[str, Path]] = None,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        use_tls: bool = False,
        authorized: bool = False,
        use_rea_cli: bool = False,
        traffic_session: Optional[TrafficCaptureSession] = None,
        write_reports: bool = True,
    ) -> ReaAnalysisResult:
        """
        Executes Module 21 surface & bundle analysis across local JS/Electron/.asar/.map/HTML artifacts
        and/or bounded same-origin frontend scripts on an authorized live host.
        """
        target_label = str(target_path or host or ".")
        seen_endpoints: Set[Tuple[str, str]] = set()
        discovered_endpoints: List[Dict[str, Any]] = []
        ai_sinks: List[Dict[str, Any]] = []
        ipc_channels: List[Dict[str, Any]] = []
        findings: List[ReaFinding] = []
        evidence_items: List[Dict[str, Any]] = []
        limitations: List[str] = []
        unknowns: List[str] = []

        local_artifacts: List[Path] = []
        resolved_tp: Optional[Path] = None
        if target_path is not None and str(target_path).strip():
            raw_tp = str(target_path).strip()
            path_err = _validate_canonical_path_syntax(raw_tp, allow_trailing_slash=True)
            if path_err is not None and raw_tp != ".":
                raise PermissionError(f"Unsafe REA target_path rejected: {path_err} ('{raw_tp}')")
            resolved_tp = Path(raw_tp).resolve()
            local_artifacts, collect_lims = self._collect_js_artifacts(resolved_tp)
            limitations.extend(collect_lims)

        # Fast short-circuit for non-JS repositories when no live host is requested
        if not local_artifacts and not host:
            return ReaAnalysisResult(
                target=str(resolved_tp or target_label),
                status="skipped_no_js_artifacts",
                mode="python_static",
                limitations=limitations,
            )

        mode_used = "python_static"

        # 1. Inspect local static JS / HTML / .map / .asar artifacts
        for art in local_artifacts:
            if len(discovered_endpoints) >= self.max_total_endpoints:
                limitations.append(f"Reached global endpoint cap ({self.max_total_endpoints}); remaining bundle routes skipped.")
                break
            ext = art.suffix.lower()
            if ext == ".asar":
                try:
                    asar_entries, asar_lims = parse_asar_archive(art)
                    limitations.extend(asar_lims)
                    for inner_rel, raw_bytes in asar_entries.items():
                        disp = f"{art}::{inner_rel}"
                        text_data = raw_bytes.decode("utf-8", errors="replace")
                        self._inspect_text_artifact(
                            display_path=disp,
                            content=text_data,
                            source_mode="python_static",
                            seen_endpoints=seen_endpoints,
                            discovered_endpoints=discovered_endpoints,
                            ai_sinks=ai_sinks,
                            ipc_channels=ipc_channels,
                            findings=findings,
                            evidence_items=evidence_items,
                            limitations=limitations,
                            unknowns=unknowns,
                            host_hint=host,
                            port_hint=port,
                        )
                except ValueError as exc:
                    limitations.append(str(exc))
                continue

            try:
                fsize = art.stat().st_size
                if fsize > MAX_STATIC_BUNDLE_BYTES:
                    limitations.append(
                        f"Truncated static read of '{art.name}' at {MAX_STATIC_BUNDLE_BYTES} bytes (size={fsize})."
                    )
                with open(art, "rb") as fh:
                    raw_content = fh.read(MAX_STATIC_BUNDLE_BYTES).decode("utf-8", errors="replace")
            except OSError as exc:
                limitations.append(f"Failed reading '{art}': {exc}")
                continue

            if ext in (".html", ".htm"):
                parser = _ScriptSrcParser()
                try:
                    parser.feed(raw_content)
                except Exception:
                    pass
                combined = "\n".join(parser.inline_scripts) if parser.inline_scripts else raw_content
                self._inspect_text_artifact(
                    display_path=str(art),
                    content=combined,
                    source_mode="python_static",
                    seen_endpoints=seen_endpoints,
                    discovered_endpoints=discovered_endpoints,
                    ai_sinks=ai_sinks,
                    ipc_channels=ipc_channels,
                    findings=findings,
                    evidence_items=evidence_items,
                    limitations=limitations,
                    unknowns=unknowns,
                    host_hint=host,
                    port_hint=port,
                )
            else:
                self._inspect_text_artifact(
                    display_path=str(art),
                    content=raw_content,
                    source_mode="python_static",
                    seen_endpoints=seen_endpoints,
                    discovered_endpoints=discovered_endpoints,
                    ai_sinks=ai_sinks,
                    ipc_channels=ipc_channels,
                    findings=findings,
                    evidence_items=evidence_items,
                    limitations=limitations,
                    unknowns=unknowns,
                    host_hint=host,
                    port_hint=port,
                )

        # 2. Optional live same-origin frontend JS bundle fetch
        if host:
            self._fetch_live_frontend_bundles(
                host=host,
                port=port,
                use_tls=use_tls,
                authorized=authorized,
                traffic_session=traffic_session,
                seen_endpoints=seen_endpoints,
                discovered_endpoints=discovered_endpoints,
                ai_sinks=ai_sinks,
                ipc_channels=ipc_channels,
                findings=findings,
                evidence_items=evidence_items,
                limitations=limitations,
                unknowns=unknowns,
            )

        # 3. Optional opt-in external `rea-agents` CLI merge
        if use_rea_cli and resolved_tp is not None:
            cli_out = self.run_rea_cli(str(resolved_tp), command="analyze-javascript-application")
            if cli_out.get("ok") and isinstance(cli_out.get("data"), dict):
                mode_used = "hybrid"
                cdata = cli_out["data"]
                for lim in cdata.get("limitations") or []:
                    limitations.append(str(lim))
                for unk in cdata.get("unknowns") or []:
                    unknowns.append(str(unk))
                for ep in cdata.get("endpoints") or cdata.get("routes") or []:
                    if len(discovered_endpoints) >= self.max_total_endpoints:
                        break
                    if isinstance(ep, str):
                        ep_route, ep_meth = ep, "GET"
                    elif isinstance(ep, dict):
                        ep_route = str(ep.get("route") or ep.get("path") or "")
                        ep_meth = str(ep.get("method") or "GET").upper()
                    else:
                        continue
                    if not _is_noise_route(ep_route) and (ep_meth, ep_route) not in seen_endpoints:
                        seen_endpoints.add((ep_meth, ep_route))
                        is_ai = bool(_AI_ROUTE_HINT_RX.search(ep_route))
                        rec = {
                            "route": ep_route,
                            "method": ep_meth,
                            "node_type": "AI_SINK" if is_ai else "ENDPOINT",
                            "source": "rea_cli",
                            "file_path": str(resolved_tp),
                            "line_number": 1,
                        }
                        discovered_endpoints.append(rec)
                        if is_ai:
                            ai_sinks.append(dict(rec))
                for cf in cdata.get("findings") or []:
                    if not isinstance(cf, dict):
                        continue
                    f_title = str(cf.get("title") or "REA CLI Surface Finding")
                    f_fp = str(cf.get("file_path") or cf.get("file") or resolved_tp)
                    f_ln = int(cf.get("line_number") or cf.get("line") or 1)
                    f_rule = str(cf.get("rule_id") or "REA-ROUTE-001")
                    findings.append(ReaFinding(
                        finding_id=_make_finding_id(f_rule, f_fp, f_ln, f_title),
                        rule_id=f_rule,
                        title=f_title,
                        severity=str(cf.get("severity") or "MEDIUM").upper(),
                        cwe=str(cf.get("cwe") or "CWE-200"),
                        file_path=f_fp,
                        line_number=f_ln,
                        evidence=str(cf.get("evidence") or f_title),
                        limitations=[str(x) for x in (cf.get("limitations") or [])],
                        unknowns=[str(x) for x in (cf.get("unknowns") or [])],
                        capability_class=str(cf.get("capability_class") or "AUTH_BOUNDARY"),
                        source_mode="rea_cli",
                    ))
            else:
                limitations.append(
                    f"Opt-in rea-agents CLI unavailable or skipped ({cli_out.get('reason', 'unknown')}); used built-in Python inspector."
                )

        # Persist findings to SQLite when DB is attached
        if self.db is not None and hasattr(self.db, "save_rea_finding"):
            for f in findings:
                payload = f.to_dict()
                payload["target_path"] = str(resolved_tp or target_label)
                try:
                    self.db.save_rea_finding(payload)
                except Exception as exc:
                    logger.debug("Failed to persist REA finding %s: %s", f.finding_id, exc)

        result = ReaAnalysisResult(
            target=str(resolved_tp or target_label),
            status="completed",
            mode=mode_used,
            discovered_endpoints=discovered_endpoints,
            ipc_channels=ipc_channels,
            ai_sinks=ai_sinks,
            findings=findings,
            evidence_items=evidence_items,
            limitations=limitations,
            unknowns=unknowns,
        )
        if write_reports:
            result.report_files = self.write_reports(result, base_root=resolved_tp)
        return result

    @staticmethod
    def to_sarif_findings(findings: Iterable[ReaFinding], base_root: Optional[Path] = None) -> Dict[str, Any]:
        """Formats Module 21 REA findings as a valid SARIF v2.1.0 document."""
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []
        for f in findings:
            sev = f.severity.upper()
            level = "error" if sev in ("CRITICAL", "HIGH") else ("warning" if sev == "MEDIUM" else "note")
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title[:120],
                    "shortDescription": {"text": f.title},
                    "helpUri": REA_ATTRIBUTION_URL,
                    "defaultConfiguration": {"level": level},
                }
            raw_fp = f.file_path.split("::", 1)[0] if "::" in f.file_path else f.file_path
            if raw_fp.lower().startswith(("http://", "https://")):
                uri = raw_fp
            elif base_root is not None:
                try:
                    root_dir = base_root if base_root.is_dir() else base_root.parent
                    uri = str(Path(raw_fp).resolve().relative_to(root_dir.resolve())).replace("\\", "/")
                except Exception:
                    uri = Path(raw_fp).name
            else:
                uri = raw_fp.replace("\\", "/")

            results.append({
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f"{f.title} — {f.evidence}"},
                "properties": {
                    "cwe": f.cwe,
                    "capability_class": f.capability_class,
                    "limitations": f.limitations,
                    "unknowns": f.unknowns,
                    "scanner": f.scanner,
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": max(1, int(f.line_number or 1))},
                    }
                }],
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": REA_SCANNER_NAME,
                        "informationUri": REA_ATTRIBUTION_URL,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }

    def write_reports(self, result: ReaAnalysisResult, base_root: Optional[Path] = None) -> Dict[str, str]:
        """Writes JSON, SARIF 2.1.0, and plain-text summary reports into `self.reports_dir`."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        json_path = self.reports_dir / f"rea_report_{ts}.json"
        sarif_path = self.reports_dir / f"rea_report_{ts}.sarif"
        txt_path = self.reports_dir / f"rea_summary_{ts}.txt"

        policy = ExecutionPolicy.get_instance()
        rfchunt_root = Path(__file__).resolve().parent.parent
        resolved_reports_dir = self.reports_dir.resolve()
        in_repo_root = resolved_reports_dir.is_relative_to(rfchunt_root)
        for out_p in (json_path, sarif_path, txt_path):
            syntax_err = _validate_canonical_path_syntax(str(out_p), allow_trailing_slash=False)
            if syntax_err is not None:
                raise PermissionError(f"Unsafe REA report path rejected: {syntax_err} ('{out_p}')")
            if not out_p.resolve().is_relative_to(resolved_reports_dir):
                raise PermissionError(f"REA report path escaped reports_dir: '{out_p}'")
            if in_repo_root:
                policy.validate_intent(StructuredIntentProposal(
                    task=ScannerTask.REA_SURFACE,
                    action_type=ActionType.FILE_WRITE,
                    file_path=str(out_p),
                    rationale="Write Module 21 REA analysis report",
                ))

        self.reports_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        sarif_path.write_text(
            json.dumps(self.to_sarif_findings(result.findings, base_root=base_root), indent=2),
            encoding="utf-8",
        )
        summary_lines = [
            "=" * 72,
            "  MODULE 21: REA CLIENT BUNDLE, ELECTRON & SURFACE AUDIT REPORT",
            f"  Attribution: {REA_ATTRIBUTION_URL}",
            "=" * 72,
            f"Target          : {result.target}",
            f"Status / Mode   : {result.status} ({result.mode})",
            f"Total Findings  : {len(result.findings)}",
            f"Routes Mined    : {len(result.discovered_endpoints)} (AI Sinks: {len(result.ai_sinks)})",
            f"Electron IPC    : {len(result.ipc_channels)}",
            "-" * 72,
        ]
        for idx, f in enumerate(result.findings, start=1):
            summary_lines.append(f"[{idx}] {f.severity} | {f.rule_id} ({f.cwe}) — {f.title}")
            summary_lines.append(f"    Location : {f.file_path}:{f.line_number}")
            summary_lines.append(f"    Evidence : {f.evidence}")
            if f.limitations:
                summary_lines.append(f"    Limits   : {'; '.join(f.limitations)}")
            if f.unknowns:
                summary_lines.append(f"    Unknowns : {'; '.join(f.unknowns)}")
        summary_lines.append("=" * 72)
        txt_path.write_text("\n".join(summary_lines), encoding="utf-8")

        return {
            "json": str(json_path),
            "sarif": str(sarif_path),
            "summary": str(txt_path),
        }
