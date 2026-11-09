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

logger = logging.getLogger("terminator.aiscan")


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
    ]

    UNSAFE_DESERIALIZATION = [
        (re.compile(r'(?i)\bpickle\.load(?:s)?\s*\('), "pickle.load", "CRITICAL", "Unsafe pickle deserialization allows remote code execution when loading untrusted model weights."),
        (re.compile(r'(?i)\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)'), "torch.load (without weights_only=True)", "HIGH", "PyTorch load without weights_only=True allows arbitrary code execution via malicious .pt/.bin weights."),
        (re.compile(r'(?i)\bjoblib\.load\s*\('), "joblib.load", "HIGH", "Joblib model deserialization executes arbitrary code during unpickling."),
    ]

    PROMPT_INJECTION_SINKS = [
        (re.compile(r'(?i)f["\'].*?(?:system|prompt|instruction).*?\{(?P<var>[a-zA-Z0-9_]+)\}.*?["\']'), "Direct f-string injection into system prompt"),
        (re.compile(r'(?i)["\'].*?(?:system|prompt|instruction).*?["\']\s*\+\s*(?P<var>[a-zA-Z0-9_]+)'), "Direct string concatenation into prompt"),
        (re.compile(r'(?i)(?:prompt|messages|input)\s*=\s*(?:request\.(?:args|form|json|data)|req\.body)'), "Unsanitized client request body passed directly to LLM context"),
    ]

    ROUTE_DECORATOR_PATTERN = re.compile(
        r'(?i)@(app|router|bp)\.(get|post|put|route)\s*\(\s*["\'](?P<route>/[^"\']+)["\']'
    )

    AI_FRAMEWORK_IMPORTS = re.compile(
        r'(?i)\b(?:import\s+(?:openai|anthropic|langchain|llamaindex|ollama|transformers)|from\s+(?:openai|anthropic|langchain|llamaindex|ollama|transformers))'
    )

    def scan_file(self, file_path: Path) -> Tuple[List[AIFinding], List[DiscoveredAIEndpoint]]:
        findings: List[AIFinding] = []
        endpoints: List[DiscoveredAIEndpoint] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings, endpoints

        lines = content.splitlines()

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

        # 4. Detect AI Endpoints in Web Frameworks (Flask, FastAPI, Express)
        has_ai = bool(self.AI_FRAMEWORK_IMPORTS.search(content))
        if has_ai:
            for line_num, line in enumerate(lines, 1):
                route_match = self.ROUTE_DECORATOR_PATTERN.search(line)
                if route_match:
                    route = route_match.group("route")
                    method = (route_match.group(2) or "POST").upper()
                    endpoints.append(DiscoveredAIEndpoint(
                        file_path=str(file_path),
                        line_number=line_num,
                        route_path=route,
                        http_method=method if method != "ROUTE" else "POST",
                        model_provider="local/llm",
                        prompt_variable="prompt",
                    ))
                    findings.append(AIFinding(
                        finding_type="unmetered_ai_endpoint",
                        severity="MEDIUM",
                        file_path=str(file_path),
                        line_number=line_num,
                        model_or_api="Web AI Endpoint",
                        description=f"AI endpoint route '{route}' exposed without verified rate-limiting or framing isolation.",
                        snippet=line.strip()[:200],
                    ))

        return findings, endpoints

    def scan_directory(self, root_dir: Path) -> Tuple[List[AIFinding], List[DiscoveredAIEndpoint]]:
        all_findings: List[AIFinding] = []
        all_endpoints: List[DiscoveredAIEndpoint] = []

        skip_dirs = {".git", "node_modules", "target", "venv", ".venv", "__pycache__", "out", "reports"}
        valid_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".json", ".yaml", ".yml", ".env"}

        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in valid_exts:
                    fp = Path(root) / file
                    f_list, e_list = self.scan_file(fp)
                    all_findings.extend(f_list)
                    all_endpoints.extend(e_list)

        return all_findings, all_endpoints


DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


class AiscanIntegrator:
    """
    Main manager for haasonsaas/aiscan and Python fallback scanner integration.
    Saves findings into terminator.db and generates JSON/SARIF reports into reports/.
    """

    def __init__(self, db: Optional[Any] = None, reports_dir: Optional[Union[str, Path]] = None):
        self.db = db
        self.reports_dir = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.python_scanner = PythonAIScanner()
        self.binary_path = self._find_aiscan_binary()

    def _find_aiscan_binary(self) -> Optional[Path]:
        """Locates aiscan binary in PATH or standard tool directories."""
        candidates = [
            shutil.which("aiscan"),
            Path("bin/aiscan.exe"),
            Path("bin/aiscan"),
            Path(r"D:\tools\aiscan.exe"),
            Path(r"D:\tools\aiscan"),
            Path.home() / ".cargo" / "bin" / ("aiscan.exe" if sys.platform == "win32" else "aiscan"),
        ]
        for c in candidates:
            if c:
                p = Path(c).resolve()
                if p.exists() and os.access(p, os.X_OK):
                    return p
        return None

    def scan_target(self, target_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Executes AI risk audit on target directory using aiscan binary if present,
        falling back to embedded Python AST scanner.
        """
        tp = Path(target_path).resolve()
        if not tp.exists():
            return {"error": f"Target path does not exist: {tp}", "findings": [], "endpoints": []}

        findings: List[AIFinding] = []
        endpoints: List[DiscoveredAIEndpoint] = []
        engine_used = "python_ast_fallback"

        # Attempt native Rust binary if installed
        if self.binary_path:
            try:
                proc = subprocess.run(
                    [str(self.binary_path), "scan", "--format", "json", str(tp)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
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

        # If binary produced no findings or was missing, run embedded scanner
        if not findings:
            f_ast, e_ast = self.python_scanner.scan_directory(tp)
            findings.extend(f_ast)
            endpoints.extend(e_ast)
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

        return {
            "target_path": str(tp),
            "engine": engine_used,
            "total_findings": len(findings),
            "total_endpoints": len(endpoints),
            "findings": [f.to_dict() for f in findings],
            "endpoints": [e.to_dict() for e in endpoints],
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
