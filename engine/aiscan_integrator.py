"""
haasonsaas/aiscan Integrator & Native AI Risk Audit Engine (Module 18)
====================================================================
Integrates AI/LLM risk scanning, prompt injection sink discovery, model inventory,
and credential auditing into RFC Hunt Swarm.

Supports:
1. Native execution of the haasonsaas/aiscan Rust binary if present in PATH, D:\\tools, or bin/
2. High-performance embedded Python AST / Regex scanner fallback
3. Persistence of findings into terminator.db (ai_security_findings)
4. Extraction of internal AI endpoints for cross-layer 'Desynchronized Prompt Injection' synthesis
5. Direct report generation into the reports/ folder (JSON, SARIF, Summary)
"""

from __future__ import annotations

import ast
import functools
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from engine.execution_policy import (
    ExecutionPolicy,
    _collect_intermediate_reparse_hops,
    _is_symlink_or_reparse,
    _normalize_win_readlink_target,
    _validate_canonical_path_syntax,
)

logger = logging.getLogger("terminator.aiscan")


def _reject_aiscan_reparse_ancestors(target_p: Union[str, Path], label: str = "path") -> None:
    """
    Rejects traversal (`..`), canonical syntax hazards, and direct or intermediate symlinks /
    Windows NTFS junctions / mount-point reparse points (including broken junctions) across
    both uncollapsed prefix segments and resolved components up to drive/filesystem anchor.
    """
    raw_s = os.fspath(target_p) if isinstance(target_p, os.PathLike) else str(target_p)
    syn_err = _validate_canonical_path_syntax(raw_s, allow_trailing_slash=True)
    if syn_err is not None and raw_s != ".":
        raise PermissionError(f"Unsafe {label} rejected: {syn_err}")

    cand_raw = Path(raw_s)
    cur_raw: Optional[Path] = cand_raw
    seen_raw: set = set()
    while cur_raw is not None and str(cur_raw) not in ("", "."):
        rk = os.path.normcase(str(cur_raw))
        if rk in seen_raw or cur_raw.parent == cur_raw:
            break
        seen_raw.add(rk)
        if _is_symlink_or_reparse(cur_raw):
            raise PermissionError(
                f"Unsafe symlink/junction {label} rejected: '{target_p}' traverses reparse point '{cur_raw}'."
            )
        cur_raw = cur_raw.parent

    cand_abs = Path(os.path.abspath(raw_s))
    cur: Optional[Path] = cand_abs
    seen: set = set()
    while cur is not None:
        cur_key = os.path.normcase(str(cur))
        if cur_key in seen or cur.parent == cur:
            break
        seen.add(cur_key)
        if _is_symlink_or_reparse(cur):
            raise PermissionError(
                f"Unsafe symlink/junction {label} rejected: '{target_p}' traverses reparse point '{cur}'."
            )
        cur = cur.parent

    hops = _collect_intermediate_reparse_hops(cand_abs, None)
    if hops:
        raise PermissionError(
            f"Unsafe symlink/junction {label} rejected: '{target_p}' traverses reparse point '{hops[0]}'."
        )


@dataclass
class AIFinding:
    finding_type: str  # 'prompt_injection_sink', 'hardcoded_ai_credential', 'insecure_deserialization', 'unmetered_ai_endpoint'
    severity: str      # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    file_path: str
    line_number: int
    model_or_api: str
    description: str
    snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveredAIEndpoint:
    file_path: str
    line_number: int
    route_path: str
    http_method: str
    model_provider: str
    prompt_variable: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PythonAIScanner:
    """
    Embedded high-fidelity scanner for AI vulnerabilities, prompt injection sinks,
    and exposed model infrastructure in Python, JS/TS, Go, Rust, and configs.
    """

    KEY_PATTERNS = [
        (re.compile(r'(?i)(?:openai[_-]?api[_-]?key|OPENAI_API_KEY)\s*[:=]\s*["\'](sk-[a-zA-Z0-9_-]{20,})["\']'), "OpenAI API Key", "CRITICAL"),
        (re.compile(r'(?i)(?:anthropic[_-]?api[_-]?key|ANTHROPIC_API_KEY)\s*[:=]\s*["\'](sk-ant-[a-zA-Z0-9_-]{20,})["\']'), "Anthropic API Key", "CRITICAL"),
        (re.compile(r'(?i)(?:hf[_-]?token|HUGGINGFACE_TOKEN|HUGGING_FACE_HUB_TOKEN)\s*[:=]\s*["\'](hf_[a-zA-Z0-9]{20,})["\']'), "Hugging Face Token", "CRITICAL"),
        (re.compile(r'(?i)(?:cohere[_-]?api[_-]?key|COHERE_API_KEY)\s*[:=]\s*["\']([a-zA-Z0-9_-]{30,})["\']'), "Cohere API Key", "HIGH"),
        (re.compile(r'(?i)(?:gemini[_-]?api[_-]?key|GEMINI_API_KEY)\s*[:=]\s*["\'](AIzaSy[a-zA-Z0-9_-]{33})["\']'), "Google Gemini Key", "CRITICAL"),
        (re.compile(r'(?i)(?:mistral[_-]?api[_-]?key|MISTRAL_API_KEY)\s*[:=]\s*["\']([a-zA-Z0-9_-]{32})["\']'), "Mistral API Key", "CRITICAL"),
        (re.compile(r'(?i)(?:groq[_-]?api[_-]?key|GROQ_API_KEY)\s*[:=]\s*["\'](gsk_[a-zA-Z0-9_-]{40,})["\']'), "Groq API Key", "CRITICAL"),
        (re.compile(r'(?i)(?:perplexity[_-]?api[_-]?key|PERPLEXITY_API_KEY)\s*[:=]\s*["\'](pplx-[a-zA-Z0-9_-]{40,})["\']'), "Perplexity API Key", "CRITICAL"),
        (re.compile(r'(?i)(?:together[_-]?api[_-]?key|TOGETHER_API_KEY)\s*[:=]\s*["\']([a-f0-9]{64})["\']'), "Together AI Key", "HIGH"),
        (re.compile(r'(?i)(?:replicate[_-]?api[_-]?token|REPLICATE_API_TOKEN)\s*[:=]\s*["\'](r8_[a-zA-Z0-9]{30,})["\']'), "Replicate API Token", "HIGH"),
        (re.compile(r'(?i)(?:aws[_-]?bedrock[_-]?key|BEDROCK_AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']'), "AWS Bedrock Key", "CRITICAL"),
        (re.compile(r'(?i)(?:azure[_-]?openai[_-]?key|AZURE_OPENAI_API_KEY)\s*[:=]\s*["\']([a-f0-9]{32})["\']'), "Azure OpenAI Key", "CRITICAL"),
    ]

    UNSAFE_DESERIALIZATION = [
        (re.compile(r'(?i)\bpickle\.load(?:s)?\s*\('), "pickle.load", "CRITICAL", "Unsafe pickle deserialization allows remote code execution when loading untrusted model weights."),
        (re.compile(r'(?i)\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)'), "torch.load (without weights_only=True)", "HIGH", "PyTorch load without weights_only=True allows arbitrary code execution via malicious .pt/.bin weights."),
        (re.compile(r'(?i)\bjoblib\.load\s*\('), "joblib.load", "HIGH", "Joblib model deserialization executes arbitrary code during unpickling."),
        (re.compile(r'(?i)\b(?:numpy|np)\.load\s*\([^)]*allow_pickle\s*=\s*True'), "numpy.load (allow_pickle=True)", "HIGH", "Numpy deserialization with allow_pickle=True permits arbitrary code execution."),
        (re.compile(r'(?i)\byaml\.(?:unsafe_load|load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader|CLoader)\b)'), "yaml.unsafe_load / UnsafeLoader", "CRITICAL", "Unsafe YAML deserialization allows arbitrary code execution during object construction."),
    ]

    PROMPT_INJECTION_SINKS = [
        (re.compile(r'(?i)f["\'][^"\'\r\n]{0,200}(?:system|prompt|instruction)[^"\'\r\n]{0,200}\{(?P<var>[a-zA-Z0-9_]+)\}[^"\'\r\n]{0,200}["\']'), "Direct f-string injection into system prompt"),
        (re.compile(r'(?i)["\'][^"\'\r\n]{0,200}(?:system|prompt|instruction)[^"\'\r\n]{0,200}["\']\s*\+\s*(?P<var>[a-zA-Z0-9_]+)'), "Direct string concatenation into prompt"),
        (re.compile(r'(?i)(?:prompt|messages|input)\s*=\s*(?:request\.(?:args|form|json|data)|req\.body)'), "Unsanitized client request body passed directly to LLM context"),
        (re.compile(r'(?i)(?:system|prompt|instruction)[^\r\n]{0,160}\.format\s*\('), "Direct .format() interpolation into system prompt"),
        (re.compile(r'(?i)(?:system|prompt|instruction)[^\r\n]{0,160}%\s*(?:\([^)]{0,120}\)|[a-zA-Z0-9_]+)'), "Direct % printf-style formatting into prompt"),
        (re.compile(r'(?i)\bPromptTemplate(?:\.from_template)?\s*\('), "LangChain PromptTemplate unescaped user parameter interpolation"),
        (re.compile(r'(?i)["\'][^"\'\r\n]{0,40}["\']\.join\s*\([^)]{0,200}(?:prompt|system|instruction|message)[^)]{0,200}\)'), "String join concatenation into system prompt"),
        (re.compile(r'(?i)\$\{(?:prompt|user_input|instruction|system|query)\}'), "Template literal interpolation into prompt"),
    ]

    ROUTE_DECORATOR_PATTERN = re.compile(
        r'(?i)@(app|router|bp)\.(get|post|put|route)\s*\(\s*["\'](?P<route>/[^"\']+)["\']'
    )

    POLYGLOT_ROUTE_PATTERNS = [
        re.compile(
            r'(?i)\b(?:app|router|server|fastify|hono)\.(?P<method>get|post|put|all)\s*\(\s*["\'](?P<route>/[^"\']+)["\']'
        ),
        re.compile(
            r'(?i)\b(?:http|mux|r|router)\.(?:HandleFunc|Handle|Post|Get)\s*\(\s*["\'](?P<route>/[^"\']+)["\']'
        ),
        re.compile(
            r'(?i)\.route\s*\(\s*["\'](?P<route>/[^"\']+)["\']\s*,\s*(?:axum::routing::|web::)?(?P<method>post|get|put)\b'
        ),
    ]

    NEXTJS_APP_ROUTER_EXPORT = re.compile(
        r'\bexport\s+(?:async\s+)?function\s+(?P<method>POST|GET|PUT)\s*\('
    )

    AI_FRAMEWORK_IMPORTS = re.compile(
        r'(?i)\b(?:import\s+(?:openai|anthropic|langchain|llamaindex|ollama|transformers|torch)|from\s+(?:openai|anthropic|langchain|llamaindex|ollama|transformers|torch)|require\s*\(\s*["\'](?:openai|@anthropic-ai/sdk|@langchain|ai|ollama)["\']\)|from\s+["\'](?:openai|@anthropic-ai/sdk|@langchain|ai|ollama)["\'])'
    )

    AI_ROUTE_KEYWORDS = re.compile(
        r'(?i)/(?:api/)?(?:v\d+/)?(?:chat|generate|prompt|llm|ai|rag|completion|predict|embeddings?|infer)'
    )

    UNICODE_SMUGGLING_PATTERN = re.compile(
        r'[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\U000e0000-\U000e007f]'
    )

    MCP_TOOL_POISONING_PATTERNS = [
        (
            re.compile(
                r'(?i)(?:<IMPORTANT>|<!--\s*HIDDEN_INSTRUCTION|ignore\s+all\s+previous\s+instructions|do\s+not\s+mention\s+this\s+to\s+the\s+user|silently\s+read\s+~/.ssh|exfiltrate\s+to\s+https?://)'
            ),
            "AISCAN-MCP-POISON-001",
            "CRITICAL",
            "MCP Tool-Description Prompt-Poisoning / Hidden Instruction Directive (CWE-77)",
        ),
        (
            re.compile(
                r'(?i)(?:override\s+tool|shadow\s+tool|before\s+calling\s+any\s+(?:other\s+)?tool|replace\s+the\s+output\s+of\s+tool|intercept\s+calls\s+to\s+tool)'
            ),
            "AISCAN-MCP-SHADOW-002",
            "CRITICAL",
            "MCP Cross-Server Tool Shadowing / Interception Directive (CWE-77)",
        ),
        (
            re.compile(
                r'(?i)(?:"args"\s*:\s*\[\s*"-y"\s*,\s*"(?![^"@\r\n]+@[0-9])[^"\r\n]*mcp[^"\r\n]*"|"url"\s*:\s*"http://(?!127\.0\.0\.1|localhost|\[::1\])[^"\r\n]+/(?:sse|mcp)\b)'
            ),
            "AISCAN-MCP-UNPINNED-EXEC-003",
            "HIGH",
            "MCP Server Configuration with Unpinned Remote Package Execution or Cleartext Non-Loopback Transport (CWE-829)",
        ),
    ]

    _FAST_AI_KEYWORDS: Tuple[bytes, ...] = (
        b"openai",
        b"anthropic",
        b"hf_",
        b"sk-",
        b"aizasy",
        b"gsk_",
        b"pplx-",
        b"cohere",
        b"mistral",
        b"replicate",
        b"bedrock",
        b"pickle",
        b"torch",
        b"joblib",
        b"numpy",
        b"np.load",
        b"yaml",
        b"prompt",
        b"system",
        b"instruction",
        b"messages",
        b"langchain",
        b"llamaindex",
        b"ollama",
        b"transformers",
        b"@app.",
        b"@router.",
        b"@bp.",
        b"app.post",
        b"router.post",
        b"handlefunc",
        b".route(",
        b"function post",
        b"<important>",
        b"ignore all previous",
        b"do not mention",
        b"silently read",
        b"exfiltrate",
        b"override tool",
        b"shadow tool",
        b"before calling any",
        b"mcpservers",
        b"/sse",
        b"/mcp",
        b"\xe2\x80",
        b"\xf3\xa0\x80",
    )

    _MAX_CODE_LINE_LEN: int = 8192
    _NON_CODE_EXTS = frozenset({".json", ".yaml", ".yml", ".toml", ".md"})

    @staticmethod
    def _is_within_root(cand: Path, root_cmp: Path) -> bool:
        try:
            resolved = cand.resolve(strict=False)
            cand_cmp = Path(os.path.normcase(str(resolved)))
            if cand_cmp != root_cmp and not cand_cmp.is_relative_to(root_cmp):
                return False
        except OSError:
            return False
        if _is_symlink_or_reparse(cand):
            try:
                raw_link = _normalize_win_readlink_target(os.readlink(cand))
                link_target = Path(raw_link)
                if not link_target.is_absolute():
                    link_target = cand.parent / link_target
                link_cmp = Path(os.path.normcase(str(link_target.resolve(strict=False))))
                if link_cmp != root_cmp and not link_cmp.is_relative_to(root_cmp):
                    return False
            except OSError:
                return False
        return True

    def scan_file(
        self,
        file_path: Path,
        *,
        root_dir: Optional[Union[str, Path]] = None,
    ) -> Tuple[List[AIFinding], List[DiscoveredAIEndpoint]]:
        if root_dir is not None:
            ok_fp, detail_fp = ExecutionPolicy.get_instance().validate_file_path(
                file_path,
                workspace_root=root_dir,
                allow_directory=False,
                allow_nonexistent=False,
            )
            if not ok_fp:
                raise PermissionError(f"Unsafe file_path rejected outside root_dir: {detail_fp}")
            file_path = Path(detail_fp)
        else:
            _reject_aiscan_reparse_ancestors(file_path, label="file_path")
            file_path = Path(file_path)

        findings: List[AIFinding] = []
        endpoints: List[DiscoveredAIEndpoint] = []

        fname_low = file_path.name.lower()
        if fname_low.endswith((".min.js", ".min.css", ".bundle.js")):
            return findings, endpoints

        try:
            if file_path.stat().st_size > 2_000_000:
                return findings, endpoints
            raw_bytes = file_path.read_bytes()
        except Exception as e:
            logger.warning("Error reading file %s: %s", file_path, e)
            return findings, endpoints

        if len(raw_bytes) > 2_000_000:
            return findings, endpoints

        raw_lower = raw_bytes.lower()
        if not any(kw in raw_lower for kw in self._FAST_AI_KEYWORDS):
            return findings, endpoints

        content = raw_bytes.decode("utf-8", errors="replace")
        lines = content.splitlines()
        is_code_file = file_path.suffix.lower() not in self._NON_CODE_EXTS

        # 0. MCP Tool-Description Prompt-Poisoning & Invisible Unicode Smuggling
        for line_num, line in enumerate(lines, 1):
            if "re.compile(" in line or "AISCAN-MCP-" in line or "AISCAN-UNICODE-" in line:
                continue
            for pat, rule_id, severity, desc in self.MCP_TOOL_POISONING_PATTERNS:
                if pat.search(line):
                    findings.append(
                        AIFinding(
                            finding_type=rule_id,
                            severity=severity,
                            file_path=str(file_path),
                            line_number=line_num,
                            model_or_api="MCP Tool Schema / Agent Skill",
                            description=desc,
                            snippet=line.strip()[:200],
                        )
                    )
            if self.UNICODE_SMUGGLING_PATTERN.search(line):
                findings.append(
                    AIFinding(
                        finding_type="AISCAN-UNICODE-SMUGGLE-001",
                        severity="CRITICAL",
                        file_path=str(file_path),
                        line_number=line_num,
                        model_or_api="Unicode Tag / BiDi / Zero-Width Prompt Smuggling",
                        description="Invisible Unicode Tag (U+E0000..U+E007F), BiDi override, or zero-width characters detected in prompt/skill/config (CWE-77).",
                        snippet=repr(line.strip()[:120]),
                    )
                )

        # 1. API Keys & Credentials
        for line_num, line in enumerate(lines, 1):
            for pat, key_type, severity in self.KEY_PATTERNS:
                m = pat.search(line)
                if m:
                    val = m.group(1)
                    masked = val[:6] + "..." + val[-4:] if len(val) > 10 else "***"
                    findings.append(AIFinding(
                        finding_type="hardcoded_ai_credential",
                        severity=severity,
                        file_path=str(file_path),
                        line_number=line_num,
                        model_or_api=key_type,
                        description=f"Exposed {key_type} found in source file: {masked}",
                        snippet=line.strip()[:200],
                    ))

            if not is_code_file or len(line) > self._MAX_CODE_LINE_LEN:
                continue

            # 2. Deserialization
            for pat, name, severity, desc in self.UNSAFE_DESERIALIZATION:
                if pat.search(line):
                    findings.append(AIFinding(
                        finding_type="insecure_deserialization",
                        severity=severity,
                        file_path=str(file_path),
                        line_number=line_num,
                        model_or_api=name,
                        description=desc,
                        snippet=line.strip()[:200],
                    ))

            # 3. Prompt Injection Sinks
            for pat, desc in self.PROMPT_INJECTION_SINKS:
                m = pat.search(line)
                if m:
                    findings.append(AIFinding(
                        finding_type="prompt_injection_sink",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_num,
                        model_or_api="LLM Prompt Template",
                        description=f"{desc} allows prompt smuggling and system instruction override.",
                        snippet=line.strip()[:200],
                    ))

        # 4. Detect AI Endpoints in Web Frameworks (Flask, FastAPI, Express/Fastify/Hono, Next.js, Go, Rust)
        if is_code_file:
            has_ai_import = bool(self.AI_FRAMEWORK_IMPORTS.search(content))
            norm_path = str(file_path).replace("\\", "/")
            is_nextjs_route = bool(re.search(r"/app/(?P<route>api/[^/]+(?:/[^/]+)*)/route\.(?:ts|js|tsx|jsx)$", norm_path))
            nextjs_route_match = re.search(r"/app/(?P<route>api/[^/]+(?:/[^/]+)*)/route\.(?:ts|js|tsx|jsx)$", norm_path)
            for line_num, line in enumerate(lines, 1):
                if len(line) > self._MAX_CODE_LINE_LEN:
                    continue
                matched_route: Optional[str] = None
                matched_method: str = "POST"
                route_match = self.ROUTE_DECORATOR_PATTERN.search(line)
                if route_match:
                    matched_route = route_match.group("route")
                    raw_m = (route_match.group(2) or "POST").upper()
                    matched_method = raw_m if raw_m != "ROUTE" else "POST"
                else:
                    for poly_pat in self.POLYGLOT_ROUTE_PATTERNS:
                        pm = poly_pat.search(line)
                        if pm:
                            matched_route = pm.group("route")
                            raw_m = (pm.groupdict().get("method") or "POST").upper()
                            matched_method = raw_m if raw_m not in ("ROUTE", "ALL") else "POST"
                            break
                    if matched_route is None and is_nextjs_route and nextjs_route_match:
                        nm = self.NEXTJS_APP_ROUTER_EXPORT.search(line)
                        if nm:
                            matched_route = "/" + nextjs_route_match.group("route")
                            matched_method = nm.group("method").upper()

                if matched_route and (has_ai_import or self.AI_ROUTE_KEYWORDS.search(matched_route)):
                    endpoints.append(DiscoveredAIEndpoint(
                        file_path=str(file_path),
                        line_number=line_num,
                        route_path=matched_route,
                        http_method=matched_method,
                        model_provider="local/llm",
                        prompt_variable="prompt",
                    ))
                    findings.append(AIFinding(
                        finding_type="unmetered_ai_endpoint",
                        severity="MEDIUM",
                        file_path=str(file_path),
                        line_number=line_num,
                        model_or_api="Web AI Endpoint",
                        description=f"AI endpoint route '{matched_route}' exposed without verified rate-limiting or framing isolation.",
                        snippet=line.strip()[:200],
                    ))

        return findings, endpoints

    def scan_directory(self, root_dir: Path) -> Tuple[List[AIFinding], List[DiscoveredAIEndpoint]]:
        from concurrent.futures import ThreadPoolExecutor

        all_findings: List[AIFinding] = []
        all_endpoints: List[DiscoveredAIEndpoint] = []

        skip_dirs = {
            ".git", "node_modules", "target", "venv", ".venv", "__pycache__",
            "out", "reports", "runs", "caldera_export", "caldera_plugin",
            "yara", "rules", "coverage", ".pytest_cache", ".mypy_cache",
            ".agents", ".cargo", ".swarm_workspaces", "vendor",
        }
        valid_exts = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".json", ".yaml", ".yml", ".env",
            ".rego", ".cedar", ".tf", ".hcl", ".sh", ".ps1", ".toml", ".md",
        }
        data_exts = {".json", ".yaml", ".yml", ".toml"}
        data_files_scanned = 0
        candidate_files: List[Path] = []

        _reject_aiscan_reparse_ancestors(root_dir, label="root_dir")
        root_resolved = Path(root_dir).resolve(strict=False)
        root_cmp = Path(os.path.normcase(str(root_resolved)))

        for root, dirs, files in os.walk(root_resolved, followlinks=False):
            root_p = Path(root)
            if root_p != root_resolved and (
                _is_symlink_or_reparse(root_p) or not self._is_within_root(root_p, root_cmp)
            ):
                logger.warning("Skipping symlink/junction directory outside scan root: %s", root_p)
                dirs[:] = []
                continue

            kept_dirs: List[str] = []
            for d in sorted(dirs):
                if d in skip_dirs:
                    continue
                sub_p = root_p / d
                if _is_symlink_or_reparse(sub_p) or not self._is_within_root(sub_p, root_cmp):
                    logger.warning("Pruned symlink/junction subdirectory outside scan root: %s", sub_p)
                    continue
                kept_dirs.append(d)
            dirs[:] = kept_dirs

            for file in sorted(files):
                cand = root_p / file
                if not self._is_within_root(cand, root_cmp):
                    logger.warning("Skipped symlink/reparse file escaping scan root: %s", cand)
                    continue
                ext = Path(file).suffix.lower()
                is_dockerfile = file.lower() in ("dockerfile", "containerfile") or file.lower().startswith("dockerfile.")
                if ext in valid_exts or is_dockerfile:
                    if ext in data_exts:
                        data_files_scanned += 1
                        if data_files_scanned > 150:
                            continue
                    candidate_files.append(cand)

        if candidate_files:
            max_workers = min(16, max(4, (os.cpu_count() or 4) * 2))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                for f_list, e_list in pool.map(
                    functools.partial(self.scan_file, root_dir=root_resolved),
                    candidate_files,
                ):
                    all_findings.extend(f_list)
                    all_endpoints.extend(e_list)

        return all_findings, all_endpoints

    def build_ai_bom(
        self,
        target_path: Path,
        findings: List[AIFinding],
        endpoints: List[DiscoveredAIEndpoint],
    ) -> Dict[str, Any]:
        """Builds a CycloneDX 1.6 ML/AI Bill of Materials (AI-BOM) cataloging models, weights, MCP servers, and endpoints."""
        weights_exts = {".safetensors", ".gguf", ".onnx", ".pt", ".pth", ".bin"}
        weights_files: List[str] = []
        mcp_servers: List[str] = []
        models = sorted({f.model_or_api for f in findings if f.model_or_api})

        _reject_aiscan_reparse_ancestors(target_path, label="target_path")
        tp_obj = Path(target_path)
        root = (tp_obj if tp_obj.is_dir() else tp_obj.parent).resolve(strict=False)
        root_cmp = Path(os.path.normcase(str(root)))
        skip_dirs = {
            ".git", "node_modules", "target", "venv", ".venv", "__pycache__",
            "yara", "rules", "reports", "runs", "logs", "caldera_export", "caldera_plugin",
            ".agents", ".cargo", ".swarm_workspaces", "vendor",
        }
        try:
            for r_dir, dirs, files in os.walk(root, followlinks=False):
                r_p = Path(r_dir)
                if r_p != root and (_is_symlink_or_reparse(r_p) or not self._is_within_root(r_p, root_cmp)):
                    dirs[:] = []
                    continue
                kept_dirs: List[str] = []
                for d in sorted(dirs):
                    if d in skip_dirs:
                        continue
                    sub_p = r_p / d
                    if _is_symlink_or_reparse(sub_p) or not self._is_within_root(sub_p, root_cmp):
                        continue
                    kept_dirs.append(d)
                dirs[:] = kept_dirs

                for fname in sorted(files):
                    fp = r_p / fname
                    if not self._is_within_root(fp, root_cmp):
                        continue
                    fl = fname.lower()
                    ext = Path(fname).suffix.lower()
                    if ext in weights_exts:
                        weights_files.append(str(fp))
                    elif fl in ("mcp.json", ".mcp.json", "claude_desktop_config.json"):
                        mcp_servers.append(str(fp))
        except OSError:
            pass

        poisoning_count = sum(1 for f in findings if f.finding_type == "AISCAN-MCP-POISON-001")
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "models": models,
            "weights_files": weights_files[:50],
            "mcp_servers": mcp_servers[:50],
            "ai_endpoints": [e.to_dict() for e in endpoints],
            "mcp_poisoning_findings_count": poisoning_count,
        }


DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def _is_offline_or_test_env() -> bool:
    """Returns True in offline, CI, or pytest runs so host binaries are not accidentally spawned."""
    return bool(
        os.environ.get("RFCHUNT_OFFLINE") == "1"
        or os.environ.get("CI")
        or os.environ.get("GITHUB_ACTIONS")
        or "PYTEST_CURRENT_TEST" in os.environ
    )


class AiscanIntegrator:
    """
    Main manager for haasonsaas/aiscan and Python fallback scanner integration.
    Saves findings into terminator.db and generates JSON/SARIF reports into reports/.
    """

    def __init__(
        self,
        db: Optional[Any] = None,
        reports_dir: Optional[Union[str, Path]] = None,
        auto_install: bool = True,
        use_native_binary: Optional[bool] = None,
    ):
        self.db = db
        self.reports_dir = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.python_scanner = PythonAIScanner()
        self.auto_install = bool(auto_install)
        self.use_native_binary = (
            (not _is_offline_or_test_env()) if use_native_binary is None else bool(use_native_binary)
        )
        self.binary_path = self._find_aiscan_binary() if self.use_native_binary else None

    def _find_aiscan_binary(self) -> Optional[Path]:
        """Locates aiscan binary in repo-local bin/, tools/cargo/bin/, PATH, or D:\\tools."""
        repo_root = Path(__file__).resolve().parent.parent
        exe_name = "aiscan.exe" if sys.platform == "win32" else "aiscan"
        candidates = [
            repo_root / "bin" / exe_name,
            repo_root / "bin" / "aiscan",
            repo_root / "tools" / "cargo" / "bin" / exe_name,
            shutil.which("aiscan"),
            Path("bin/aiscan.exe"),
            Path("bin/aiscan"),
            Path(r"D:\tools\aiscan.exe"),
            Path(r"D:\tools\aiscan"),
            Path.home() / ".cargo" / "bin" / exe_name,
        ]
        for c in candidates:
            if c:
                try:
                    p = Path(c).resolve()
                    if p.exists() and p.is_file() and os.access(p, os.X_OK):
                        return p
                except OSError:
                    continue
        return None

    def ensure_binary_installed(self, *, allow_in_tests: bool = False) -> Optional[Path]:
        """Dynamically installs `aiscan` via ToolProvisioner when live online and missing."""
        if self.binary_path and self.binary_path.exists():
            return self.binary_path
        self.binary_path = self._find_aiscan_binary()
        if self.binary_path:
            return self.binary_path
        if not self.auto_install:
            return None
        try:
            from engine.tool_provisioner import ToolProvisioner
            prov = ToolProvisioner(allow_in_tests=allow_in_tests)
            if prov.is_offline_or_blocked():
                return None
            prov.ensure_tool("aiscan")
            self.binary_path = self._find_aiscan_binary()
        except Exception as exc:
            logger.debug("Dynamic aiscan installation skipped/failed: %s", exc)
        return self.binary_path

    def scan_target(
        self,
        target_path: Union[str, Path],
        *,
        auto_install: Optional[bool] = None,
        workspace_root: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Executes AI risk audit on target directory using aiscan binary if present
        (dynamically provisioning when online and allowed), falling back to embedded
        Python AST scanner.
        """
        raw_tp = str(target_path)
        if "\x00" in raw_tp:
            raise ValueError("Invalid null byte in target_path")
        if workspace_root is not None:
            ok_tp, detail_tp = ExecutionPolicy.get_instance().validate_file_path(
                raw_tp,
                workspace_root=workspace_root,
                allow_directory=True,
                allow_nonexistent=True,
            )
            if not ok_tp:
                raise PermissionError(f"Unsafe target_path rejected outside workspace_root: {detail_tp}")
            tp = Path(detail_tp).resolve(strict=False)
        else:
            if not raw_tp.strip():
                raise ValueError("target_path must be a non-empty path.")
            _reject_aiscan_reparse_ancestors(raw_tp, label="target_path")
            tp = Path(raw_tp).resolve(strict=False)
        if not tp.exists():
            return {"error": f"Target path does not exist: {tp}", "findings": [], "endpoints": []}

        should_install = self.auto_install if auto_install is None else bool(auto_install)
        if self.use_native_binary and not self.binary_path and should_install:
            is_mocked_subproc = getattr(subprocess.run, "__module__", None) != "subprocess"
            if not is_mocked_subproc:
                self.ensure_binary_installed()

        findings: List[AIFinding] = []
        endpoints: List[DiscoveredAIEndpoint] = []
        engine_used = "python_ast_fallback"

        # Attempt native Rust binary if installed (or explicitly assigned on the instance)
        if self.binary_path:
            try:
                cf = CREATE_NO_WINDOW if (sys.platform == "win32" or os.name == "nt") else 0
                proc = subprocess.run(
                    [str(self.binary_path), "scan", "--format", "json", str(tp)],
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                    check=False,
                    creationflags=cf,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    data = json.loads(proc.stdout)
                    engine_used = "haasonsaas/aiscan"
                    for item in data.get("findings", []):
                        findings.append(AIFinding(
                            finding_type=item.get("type", "ai_vulnerability"),
                            severity=item.get("severity", "MEDIUM").upper(),
                            file_path=item.get("file", str(tp)),
                            line_number=item.get("line", 0),
                            model_or_api=item.get("model", "generic_ai"),
                            description=item.get("message", ""),
                            snippet=item.get("snippet", ""),
                        ))
            except Exception as e:
                logger.warning("aiscan binary execution failed, using Python fallback: %s", e)

        # Always run embedded scanner to discover web AI endpoints and AST sinks so endpoints are never dropped
        if tp.is_file():
            f_ast, e_ast = self.python_scanner.scan_file(
                tp,
                root_dir=(workspace_root if workspace_root is not None else tp.parent),
            )
        else:
            f_ast, e_ast = self.python_scanner.scan_directory(tp)

        seen_f = {
            (f.finding_type, str(Path(f.file_path).resolve()), int(f.line_number or 0))
            for f in findings
        }
        for fa in f_ast:
            fkey = (fa.finding_type, str(Path(fa.file_path).resolve()), int(fa.line_number or 0))
            if fkey not in seen_f:
                seen_f.add(fkey)
                findings.append(fa)

        seen_e = {(e.http_method.upper(), e.route_path) for e in endpoints}
        for ea in e_ast:
            ekey = (ea.http_method.upper(), ea.route_path)
            if ekey not in seen_e:
                seen_e.add(ekey)
                endpoints.append(ea)
        if not findings and engine_used != "haasonsaas/aiscan":
            engine_used = "python_ast_fallback"

        # Persist into terminator.db if database available
        if self.db and hasattr(self.db, "save_ai_finding"):
            for f in findings:
                try:
                    self.db.save_ai_finding(
                        target_path=str(tp),
                        finding_type=f.finding_type,
                        severity=f.severity,
                        file_path=f.file_path,
                        line_number=f.line_number,
                        model_or_api=f.model_or_api,
                        description=f.description,
                        snippet=f.snippet,
                    )
                except Exception as e:
                    logger.debug("Failed to persist AI finding: %s", e)

        # Generate reports in reports/ folder (No UI!)
        report_files = self.generate_reports(tp, findings, endpoints, engine_used)
        ai_bom = self.python_scanner.build_ai_bom(tp, findings, endpoints)

        return {
            "target_path": str(tp),
            "engine": engine_used,
            "total_findings": len(findings),
            "total_endpoints": len(endpoints),
            "findings": [f.to_dict() for f in findings],
            "endpoints": [e.to_dict() for e in endpoints],
            "ai_bom": ai_bom,
            "report_files": report_files,
        }

    def generate_reports(
        self,
        target_path: Path,
        findings: List[AIFinding],
        endpoints: List[DiscoveredAIEndpoint],
        engine_used: str,
    ) -> Dict[str, str]:
        """Saves JSON, SARIF, and Summary reports directly into reports/ folder."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = self.reports_dir / f"aiscan_report_{timestamp}.json"
        sarif_file = self.reports_dir / f"aiscan_report_{timestamp}.sarif"
        summary_file = self.reports_dir / f"aiscan_summary_{timestamp}.txt"

        # 1. JSON Report
        json_data = {
            "target": str(target_path),
            "scan_timestamp": timestamp,
            "engine": engine_used,
            "total_findings": len(findings),
            "total_endpoints": len(endpoints),
            "findings": [f.to_dict() for f in findings],
            "endpoints": [e.to_dict() for e in endpoints],
        }
        json_file.write_text(json.dumps(json_data, indent=2), encoding="utf-8")

        # 2. SARIF Report
        sarif_data = self._to_sarif(target_path, findings)
        sarif_file.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")

        # 3. CLI Summary Text Report
        lines = [
            "=" * 70,
            f"  AISCAN AI & PROMPT RISK AUDIT REPORT",
            "=" * 70,
            f"Target Directory : {target_path}",
            f"Engine Used      : {engine_used}",
            f"Timestamp        : {timestamp}",
            f"Total Findings   : {len(findings)}",
            f"Total AI Sinks   : {len(endpoints)}",
            "-" * 70,
        ]
        for idx, f in enumerate(findings, 1):
            lines.append(f"[{idx}] {f.severity} | {f.finding_type.upper()}")
            lines.append(f"    File: {f.file_path}:{f.line_number}")
            lines.append(f"    Model/API: {f.model_or_api}")
            lines.append(f"    Desc: {f.description}")
            if f.snippet:
                lines.append(f"    Snippet: {f.snippet}")
            lines.append("")

        if endpoints:
            lines.append("-" * 70)
            lines.append("DISCOVERED BACKEND AI ENDPOINTS (PROMPT SMUGGLING TARGETS):")
            for e in endpoints:
                lines.append(f"  -> {e.http_method} {e.route_path} ({e.file_path}:{e.line_number})")
            lines.append("")

        lines.append("=" * 70)
        summary_file.write_text("\n".join(lines), encoding="utf-8")

        return {
            "json": str(json_file),
            "sarif": str(sarif_file),
            "summary": str(summary_file),
        }

    def _to_sarif(self, target_path: Path, findings: List[AIFinding]) -> Dict[str, Any]:
        """Formats findings into standard SARIF v2.1.0."""
        results = []
        rules = {}

        for f in findings:
            rule_id = f"AISCAN-{f.finding_type.upper().replace('_', '-')}"
            level = "error" if f.severity in ("CRITICAL", "HIGH") else ("warning" if f.severity == "MEDIUM" else "note")
            rules[rule_id] = {
                "id": rule_id,
                "name": f.finding_type,
                "shortDescription": {"text": f.description},
                "defaultConfiguration": {"level": level},
            }

            try:
                rel_path = str(Path(f.file_path).relative_to(target_path)).replace("\\", "/")
            except ValueError:
                rel_path = f.file_path.replace("\\", "/")

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel_path},
                        "region": {
                            "startLine": f.line_number or 1,
                            "snippet": {"text": f.snippet},
                        },
                    }
                }],
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "aiscan",
                        "informationUri": "https://github.com/haasonsaas/aiscan",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }
