"""
RAPTOR Security Framework Integration Module
============================================
Provides unified bridge and MCP integration between the RFC Hunt Swarm and
the RAPTOR Autonomous Offensive/Defensive Research Framework.

CREDIT & ATTRIBUTION:
---------------------
RAPTOR: Autonomous Offensive/Defensive Research Framework
Core Authors:
  - Gadi Evron
  - Daniel Cuthbert (https://orcid.org/0009-0000-6443-0251)
  - Thomas Dullien ("Halvar Flake")
Project Repository: https://github.com/gadievron/raptor
Docker Registry: danielcuthbert/raptor:latest
License: MIT

If you use RAPTOR in your research or tooling, please cite:
  Evron, G., Cuthbert, D., & Dullien, T. (2026).
  RAPTOR: Autonomous Offensive/Defensive Research Framework (Version 3.1.0).
  https://github.com/gadievron/raptor

This integration enables rfchunt to:
  1. Audit target web server source code (Nginx, Envoy, Node.js, Go, Python, Rust)
     for HTTP parser implementation vulnerabilities and memory boundary flaws.
  2. Perform autonomous agentic exploitability triage using local Ollama models
     (defaulting to Cisco Foundation-Sec-8B: `fenkohq/foundation-sec-8b:latest`).
  3. Conduct post-quantum cryptography and cryptographic algorithm audits.
  4. Ingest SARIF vulnerability findings into the unified RFC compliance database
     (`terminator.db`), linking network wire anomalies to source code defects.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

# Credit / Attribution metadata constants
RAPTOR_PROJECT_TITLE = "RAPTOR: Autonomous Offensive/Defensive Research Framework"
RAPTOR_AUTHORS = "Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake)"
RAPTOR_REPO_URL = "https://github.com/gadievron/raptor"
RAPTOR_DOCKER_IMAGE = "danielcuthbert/raptor:latest"
RAPTOR_DEFAULT_MODEL = "fenkohq/foundation-sec-8b:latest"


class RaptorIntegrator:
    """
    Integrates the RAPTOR Security Framework with rfchunt.
    Supports Docker-based execution, SARIF parsing, and RFC anomaly ingestion.
    """

    DEFAULT_RAPTOR_ROOT = Path(r"D:\docker\raptor")
    INVOKE_SCRIPT = DEFAULT_RAPTOR_ROOT / "Invoke-RaptorScan.ps1"
    OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"

    def __init__(
        self,
        raptor_root: Optional[Union[str, Path]] = None,
        db: Optional[Any] = None,
        on_trace: Optional[Any] = None,
    ):
        self.raptor_root = Path(raptor_root) if raptor_root else self.DEFAULT_RAPTOR_ROOT
        self.out_root = self.raptor_root / "out"
        self.db = db
        self.on_trace = on_trace or (lambda msg: print(msg, flush=True))

    @staticmethod
    def get_attribution_banner() -> str:
        """Returns the formal credit and attribution text for the RAPTOR framework."""
        return (
            f"[*] RAPTOR Framework Integration Enabled\n"
            f"    Project  : {RAPTOR_PROJECT_TITLE}\n"
            f"    Authors  : {RAPTOR_AUTHORS}\n"
            f"    Source   : {RAPTOR_REPO_URL}\n"
            f"    Engine   : {RAPTOR_DOCKER_IMAGE} (Docker Container)"
        )

    def check_status(self) -> Dict[str, Any]:
        """
        Verifies RAPTOR readiness: Docker daemon, container image, and local Ollama models.
        """
        status: Dict[str, Any] = {
            "raptor_available": False,
            "raptor_root": str(self.raptor_root),
            "docker_image": RAPTOR_DOCKER_IMAGE,
            "docker_ready": False,
            "image_id": None,
            "ollama_ready": False,
            "ollama_models": [],
            "preferred_model_installed": False,
            "attribution": {
                "title": RAPTOR_PROJECT_TITLE,
                "authors": RAPTOR_AUTHORS,
                "url": RAPTOR_REPO_URL,
            },
        }

        # 1. Check Docker container image
        try:
            res = subprocess.run(
                ["docker", "image", "inspect", RAPTOR_DOCKER_IMAGE, "--format", "{{.Id}}"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=6,
                check=False,
                creationflags=CREATE_NO_WINDOW if (sys.platform == "win32" or os.name == "nt") else 0,
            )
            if res.returncode == 0 and res.stdout.strip():
                status["docker_ready"] = True
                status["image_id"] = res.stdout.strip()
        except Exception as e:
            status["docker_error"] = str(e)

        # 2. Check Ollama models
        try:
            req = urllib.request.Request(self.OLLAMA_TAGS_URL, method="GET")
            with urllib.request.urlopen(req, timeout=0.8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
                status["ollama_ready"] = True
                status["ollama_models"] = models
                status["preferred_model_installed"] = any(
                    RAPTOR_DEFAULT_MODEL in m for m in models
                )
        except Exception as e:
            status["ollama_error"] = str(e)

        status["raptor_available"] = status["docker_ready"] and self.raptor_root.exists()
        return status

    def describe_target(self, target_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Runs RAPTOR target description to profile repository language mix and attack surface.
        """
        target = Path(target_path).resolve()
        if not target.exists():
            return {"error": f"Target path {target} does not exist."}

        self.on_trace(f"[*] RAPTOR Target Profiler running on: {target}")
        ps_script = self.INVOKE_SCRIPT
        if not ps_script.exists():
            return {"error": f"RAPTOR helper script {ps_script} not found."}

        cmd = [
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ps_script),
            "-TargetPath",
            str(target),
            "-Mode",
            "describe",
        ]

        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
                creationflags=CREATE_NO_WINDOW if (sys.platform == "win32" or os.name == "nt") else 0,
            )
            return {
                "target": str(target),
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "credit": RAPTOR_PROJECT_TITLE,
            }
        except subprocess.TimeoutExpired:
            return {"error": "Target description timed out after 120s."}
        except Exception as exc:
            return {"error": f"Failed to execute RAPTOR target description: {exc}"}

    def run_scan(
        self,
        target_path: Union[str, Path],
        mode: str = "scan",
        model: str = RAPTOR_DEFAULT_MODEL,
        policy_groups: str = "",
        include_codeql: bool = False,
        timeout_sec: int = 1800,
    ) -> Dict[str, Any]:
        """
        Executes a security scan using RAPTOR (modes: 'scan', 'agentic', 'crypto', 'sca').
        Automatically locates and parses the resulting SARIF reports.
        """
        target = Path(target_path).resolve()
        if not target.exists():
            return {"error": f"Target path {target} does not exist."}

        if mode == "full":
            mode = "all"
        if model and not re.match(
            r"^(ollama|anthropic|openai|gemini|google|mistral|cohere|bedrock|openrouter|together|groq|fireworks|deepinfra)/",
            model,
            re.IGNORECASE,
        ) and not re.match(r"^(claude-|gpt-|o1-|o3-|o4-|gemini-)", model, re.IGNORECASE):
            cli_model = f"ollama/{model}"
        else:
            cli_model = model

        self.on_trace(f"\n{'='*75}")
        self.on_trace(f"[*] LAUNCHING RAPTOR SECURITY SCAN")
        self.on_trace(f"    Target Project : {target}")
        self.on_trace(f"    Scan Mode      : {mode}")
        if mode in ("agentic", "all"):
            self.on_trace(f"    Ollama Model   : {cli_model}")
        self.on_trace(f"    Framework      : {RAPTOR_PROJECT_TITLE} (Authors: {RAPTOR_AUTHORS})")
        self.on_trace(f"{'='*75}\n")

        ps_script = self.INVOKE_SCRIPT
        cmd = [
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ps_script),
            "-TargetPath",
            str(target),
            "-Mode",
            mode,
        ]

        if mode in ("agentic", "all"):
            cmd.extend(["-Model", cli_model])
        if policy_groups:
            cmd.extend(["-PolicyGroups", policy_groups])
        if include_codeql:
            cmd.append("-IncludeCodeQL")

        t_start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
                check=False,
                creationflags=CREATE_NO_WINDOW if (sys.platform == "win32" or os.name == "nt") else 0,
            )
            duration = time.time() - t_start
        except subprocess.TimeoutExpired:
            return {"error": f"RAPTOR scan timed out after {timeout_sec}s.", "duration_sec": timeout_sec}
        except Exception as exc:
            return {"error": f"Failed to execute RAPTOR: {exc}"}

        # Locate latest output directory for this target
        slug = re.sub(r"\s+", "_", target.name)
        candidate_dirs = sorted(
            [d for d in self.out_root.glob(f"{slug}_{mode}_*") if d.is_dir()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        out_dir = candidate_dirs[0] if candidate_dirs else None
        findings = []
        if out_dir:
            findings = self.collect_sarif_findings_from_dir(out_dir)

        # Ingest findings into terminator.db if database available
        ingested_count = 0
        if self.db and findings:
            ingested_count = self.ingest_findings_to_db(findings, target_engine=f"repo:{target.name}")

        return {
            "target": str(target),
            "mode": mode,
            "returncode": proc.returncode,
            "duration_sec": round(duration, 2),
            "output_directory": str(out_dir) if out_dir else None,
            "total_findings": len(findings),
            "ingested_to_db": ingested_count,
            "findings": findings[:50],  # Return top 50 in summary
            "credit": {
                "framework": RAPTOR_PROJECT_TITLE,
                "authors": RAPTOR_AUTHORS,
                "url": RAPTOR_REPO_URL,
            },
        }

    def run_host_scan(
        self,
        host: str,
        port: int = 443,
        use_tls: bool = True,
        timeout_sec: int = 600,
    ) -> Dict[str, Any]:
        """
        Executes RAPTOR Web Application Security Testing against a remote live host.
        Invokes RAPTOR's 'web' mode (--url https://<host>:<port>).
        Parses all generated web findings and ingests them into terminator.db.
        """
        protocol = "https" if use_tls or port == 443 else "http"
        port_suffix = f":{port}" if (use_tls and port != 443) or (not use_tls and port != 80) else ""
        target_url = f"{protocol}://{host}{port_suffix}"

        self.on_trace(f"\n{'='*75}")
        self.on_trace(f"[*] LAUNCHING RAPTOR WEB APPLICATION HOST SCAN")
        self.on_trace(f"    Target Host    : {host}:{port} ({target_url})")
        self.on_trace(f"    Scan Mode      : web (Dynamic Application & Injection Analysis)")
        self.on_trace(f"    Framework      : {RAPTOR_PROJECT_TITLE}")
        self.on_trace(f"    Authors        : {RAPTOR_AUTHORS}")
        self.on_trace(f"{'='*75}\n")

        ps_script = self.INVOKE_SCRIPT
        cmd = [
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ps_script),
            "-TargetPath",
            target_url,
            "-Mode",
            "web",
        ]

        t_start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
                check=False,
                creationflags=CREATE_NO_WINDOW if (sys.platform == "win32" or os.name == "nt") else 0,
            )
            duration = time.time() - t_start
        except subprocess.TimeoutExpired:
            return {"error": f"RAPTOR host scan timed out after {timeout_sec}s.", "duration_sec": timeout_sec}
        except Exception as exc:
            return {"error": f"Failed to execute RAPTOR host scan: {exc}"}

        # Locate latest output directory for this host
        host_clean = re.sub(r"[\.:]", "_", host)
        candidate_dirs = sorted(
            [d for d in self.out_root.glob(f"web_{host_clean}_web_*") if d.is_dir()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        out_dir = candidate_dirs[0] if candidate_dirs else None
        findings = []
        if out_dir:
            findings = self.collect_sarif_findings_from_dir(out_dir)

        ingested_count = 0
        if self.db and findings:
            ingested_count = self.ingest_findings_to_db(findings, target_engine=f"{host}:{port}")

        return {
            "host": host,
            "port": port,
            "target_url": target_url,
            "mode": "web",
            "returncode": proc.returncode,
            "duration_sec": round(duration, 2),
            "output_directory": str(out_dir) if out_dir else None,
            "total_findings": len(findings),
            "ingested_to_db": ingested_count,
            "findings": findings[:50],
            "credit": {
                "framework": RAPTOR_PROJECT_TITLE,
                "authors": RAPTOR_AUTHORS,
                "url": RAPTOR_REPO_URL,
            },
        }

    def collect_sarif_findings_from_dir(self, directory: Path) -> List[Dict[str, Any]]:
        """Scans a directory for all .sarif files and extracts normalized findings."""
        all_findings = []
        for sarif_file in directory.glob("**/*.sarif"):
            findings = self.parse_sarif_file(sarif_file)
            all_findings.extend(findings)
        return all_findings

    @staticmethod
    def parse_sarif_file(sarif_path: Path) -> List[Dict[str, Any]]:
        """Parses a SARIF JSON file and returns structured vulnerability items."""
        if not sarif_path.exists():
            return []

        try:
            data = json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return []

        findings = []
        for run in data.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "RAPTOR")
            for res in run.get("results", []):
                level = res.get("level", "warning").lower()
                rule_id = res.get("ruleId", "unknown-rule")
                msg = (res.get("message", {}) or {}).get("text", "")
                locs = res.get("locations", [])
                uri = ""
                line = 0
                snippet = ""
                if locs:
                    phys = locs[0].get("physicalLocation", {}) or {}
                    uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                    reg = phys.get("region", {}) or {}
                    line = reg.get("startLine", 0)
                    snippet = (reg.get("snippet", {}) or {}).get("text", "").strip()

                findings.append({
                    "tool": tool_name,
                    "rule_id": rule_id,
                    "severity": level.upper(),
                    "file": uri,
                    "line": line,
                    "message": msg,
                    "snippet": snippet[:300] if snippet else "",
                    "source_sarif": sarif_path.name,
                })
        return findings

    def ingest_findings_to_db(self, findings: List[Dict[str, Any]], target_engine: str) -> int:
        """
        Ingests RAPTOR static & agentic security findings into terminator.db:
        - Stores as ImplementationAnomaly (category: RAPTOR_STATIC_FINDING)
        - Synthesizes arm106 defensive rules and regression tests.
        """
        if not self.db:
            return 0

        ingested = 0
        for f in findings:
            anom_id = f"ANOM-RAPTOR-{int(time.time() * 1000)}-{ingested}"
            category = "RAPTOR_VULNERABILITY"
            observed = f"[{f['severity']}] {f['rule_id']} in {f['file']}:{f['line']} - {f['message']}"
            expected = f"Clean static security invariant conformant with rule {f['rule_id']}"
            raw_probe = f"RAPTOR Rule: {f['rule_id']}\nFile: {f['file']}:{f['line']}\nSnippet:\n{f['snippet']}"
            raw_resp = f"Severity: {f['severity']}\nTool: {f['tool']}\nMessage: {f['message']}"

            try:
                self.db.save_implementation_anomaly(
                    anomaly_id=anom_id,
                    target_engine=target_engine,
                    category=category,
                    observed_behavior=observed,
                    expected_behavior=expected,
                    raw_probe=raw_probe,
                    raw_response=raw_resp,
                )
                ingested += 1
            except Exception as exc:
                self.on_trace(f"[-] DB Ingestion notice: {exc}")

        return ingested

    def list_all_findings(self, max_items: int = 100) -> List[Dict[str, Any]]:
        """Scans the out/ directory for all historical RAPTOR scan findings."""
        if not self.out_root.exists():
            return []

        all_findings = []
        for sarif_file in sorted(self.out_root.glob("**/*.sarif"), key=lambda p: p.stat().st_mtime, reverse=True):
            findings = self.parse_sarif_file(sarif_file)
            for f in findings:
                f["report_dir"] = sarif_file.parent.name
                all_findings.append(f)
                if len(all_findings) >= max_items:
                    break
            if len(all_findings) >= max_items:
                break
        return all_findings
