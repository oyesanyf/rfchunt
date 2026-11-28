"""
RFCHunt Dynamic STRIDE Threat Modeling, MITRE ATT&CK, Zero Trust & Attack-Tree Engine
=====================================================================================
Replaces static STRIDE checklists with dynamic per-component/per-asset threat modeling
derived directly from any target repository or local folder (`--folder` / `--repo`):

1. Dynamic Component & Trust-Boundary Extraction:
   Groups discovered files, routes, sinks, data flows, and scanner findings into concrete
   components (`Web/API Surface`, `Auth & Identity`, `AI / LLM / MCP Layer`,
   `Database & Persistence`, `OS / Subprocess Boundary`, `Network & HTTP Framing`,
   `Cryptography & Secrets`, `Containers / IaC / Supply Chain`).
2. Per-Component STRIDE Matrix (S / T / R / I / D / E):
   Derives component-specific threat scenarios with concrete file references, severity,
   MITRE ATT&CK / ATLAS tactic & technique IDs, and linked scanner findings.
3. Zero Trust Architecture Assessment (CISA 5 Pillars):
   Scores & emits concrete Zero Trust recommendations across Identity, Workloads,
   Networks, Applications, and Data.
4. Actionable Security Requirements:
   Numbered, verifiable requirements (`SR-001`..`SR-N`) tied to CWE, OWASP ASVS, and
   SOC 2 / ISO 27001 controls.
5. Hierarchical Attack Trees & Pure-Python Visual Diagrams (Zero Graphviz / Heavy ML):
   Generates self-contained SVG diagrams (`threat_model_diagram.svg`,
   `attack_tree_diagram.svg`) AND Mermaid diagrams (`flowchart TD`), plus a downloadable
   5-section comprehensive report (`stride_threat_model_report.md`,
   `stride_threat_model_report.html`, `stride_threat_model.json`):
     - Section 1: Executive Summary
     - Section 2: Threat Model Diagram
     - Section 3: Threat Scenarios (STRIDE + MITRE ATT&CK + Zero Trust)
     - Section 4: Security Requirements
     - Section 5: Attack Trees
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

STRIDE_CATEGORIES: Tuple[str, ...] = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)

COMPONENT_SIGNATURES: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    ("api_routes", "Web & API Entry Points", ("@app.", "@router.", "fastapi", "flask", "express", "handlefunc", "route(", "/api/", "graphql", "http.server")),
    ("auth_identity", "Authentication & Access Control", ("jwt", "oauth", "auth", "login", "session", "rbac", "token", "bearer", "password", "permission", "policy")),
    ("ai_llm_mcp", "AI / LLM & MCP Agent Layer", ("openai", "anthropic", "ollama", "langchain", "mcp", "prompt", "system_prompt", "embedding", "rag", "skill.md", "transformers")),
    ("data_storage", "Database & State Persistence", ("sqlite", "postgres", "mysql", "redis", "mongo", "cursor.execute", "sqlalchemy", "orm", "database", ".db")),
    ("os_subprocess", "OS / Subprocess & File Execution", ("subprocess", "os.system", "popen", "exec(", "eval(", "pickle.", "yaml.load", "shutil.", "tempfile")),
    ("network_framing", "Network, HTTP Framing & Proxy", ("socket", "ssl", "tls", "http/1.1", "http/2", "h2", "transfer-encoding", "content-length", "proxy", "requests.", "httpx.")),
    ("crypto_secrets", "Cryptography & Secret Management", ("cryptography", "hashlib", "hmac", "aes", "rsa", "ecdsa", "kyber", "ml-kem", "secret", "api_key", ".env")),
    ("supply_chain_iac", "Dependencies, Containers & IaC", ("dockerfile", "docker-compose", "requirements", "package.json", "package-lock", "cargo.toml", "go.mod", "terraform", ".tf", "github/workflows")),
)

# Concrete per-component STRIDE + MITRE ATT&CK + Security Requirement templates grounded in real evidence
_COMPONENT_THREAT_CATALOG: Dict[str, List[Dict[str, Any]]] = {
    "api_routes": [
        {
            "stride": "Spoofing",
            "title": "Unauthenticated or Forged Caller Reaching Exposed API Route",
            "mitre_tactic": "TA0001 Initial Access",
            "mitre_technique": "T1190 Exploit Public-Facing Application",
            "cwe": "CWE-306",
            "severity": "HIGH",
            "requirement": "Enforce centralized authentication middleware and explicit authorization decorators on every non-public HTTP/RPC route.",
            "asvs": "ASVS 4.1.1",
            "zero_trust_pillar": "Identity",
        },
        {
            "stride": "Denial of Service",
            "title": "Unbounded Request Payload or Rate Exhaustion on API Surface",
            "mitre_tactic": "TA0040 Impact",
            "mitre_technique": "T1499 Endpoint Denial of Service",
            "cwe": "CWE-770",
            "severity": "MEDIUM",
            "requirement": "Apply strict request body size caps, per-client rate limiting, and pagination bounds on every API endpoint.",
            "asvs": "ASVS 11.1.4",
            "zero_trust_pillar": "Applications",
        },
    ],
    "auth_identity": [
        {
            "stride": "Elevation of Privilege",
            "title": "Authorization Bypass or Broken Object-Level Access Control (BOLA/RBAC)",
            "mitre_tactic": "TA0004 Privilege Escalation",
            "mitre_technique": "T1078 Valid Accounts",
            "cwe": "CWE-863",
            "severity": "CRITICAL",
            "requirement": "Adopt fail-closed default-deny authorization where explicit `forbid` rules strictly override `permit` and object ownership is re-checked per request.",
            "asvs": "ASVS 4.1.3",
            "zero_trust_pillar": "Identity",
        },
        {
            "stride": "Repudiation",
            "title": "Missing Tamper-Evident Audit Trail for Identity & Privilege Decisions",
            "mitre_tactic": "TA0005 Defense Evasion",
            "mitre_technique": "T1070 Indicator Removal",
            "cwe": "CWE-778",
            "severity": "MEDIUM",
            "requirement": "Log all authentication, authorization denial, and privilege-change events to an append-only tamper-evident audit ledger.",
            "asvs": "ASVS 7.2.1",
            "zero_trust_pillar": "Identity",
        },
    ],
    "ai_llm_mcp": [
        {
            "stride": "Tampering",
            "title": "Prompt Injection & MCP Tool-Description Poisoning Hijacking Agent Actions",
            "mitre_tactic": "AML.TA0001 AI Initial Access",
            "mitre_technique": "AML.T0051 LLM Prompt Injection",
            "cwe": "CWE-77",
            "severity": "CRITICAL",
            "requirement": "Quarantine untrusted data outside system prompts, sanitize Unicode control characters, and enforce tool-call allowlists with human/policy approval gates.",
            "asvs": "OWASP LLM01",
            "zero_trust_pillar": "Applications",
        },
        {
            "stride": "Information Disclosure",
            "title": "Sensitive Context, System Prompt, or AI API Key Leakage",
            "mitre_tactic": "TA0006 Credential Access",
            "mitre_technique": "T1552 Unsecured Credentials",
            "cwe": "CWE-798",
            "severity": "HIGH",
            "requirement": "Store AI provider tokens exclusively in runtime secret vaults/ignored `.env.local` and redact secrets/PII before LLM prompt assembly and report output.",
            "asvs": "OWASP LLM06",
            "zero_trust_pillar": "Data",
        },
    ],
    "data_storage": [
        {
            "stride": "Tampering",
            "title": "SQL / Query Injection Modifying Persistent Application State",
            "mitre_tactic": "TA0001 Initial Access",
            "mitre_technique": "T1190 Exploit Public-Facing Application",
            "cwe": "CWE-89",
            "severity": "CRITICAL",
            "requirement": "Use parameterized prepared statements exclusively; forbid string interpolation (`f\"...\"`, `%`, `.format()`) in database queries.",
            "asvs": "ASVS 5.3.4",
            "zero_trust_pillar": "Data",
        },
        {
            "stride": "Information Disclosure",
            "title": "Unencrypted Sensitive Data or PHI/PII Exposure in Storage & Logs",
            "mitre_tactic": "TA0009 Collection",
            "mitre_technique": "T1005 Data from Local System",
            "cwe": "CWE-359",
            "severity": "HIGH",
            "requirement": "Encrypt sensitive records at rest using AEAD (AES-256-GCM) and apply zero-knowledge redaction before writing logs or telemetry.",
            "asvs": "ASVS 8.3.4",
            "zero_trust_pillar": "Data",
        },
    ],
    "os_subprocess": [
        {
            "stride": "Elevation of Privilege",
            "title": "OS Command Injection or Unsafe Deserialization (RCE) on Host Runtime",
            "mitre_tactic": "TA0002 Execution",
            "mitre_technique": "T1059 Command and Scripting Interpreter",
            "cwe": "CWE-78",
            "severity": "CRITICAL",
            "requirement": "Invoke all subprocesses strictly with `shell=False` and validated argv arrays; prohibit `eval()`, `exec()`, `pickle.loads()`, and `yaml.unsafe_load()` on untrusted input.",
            "asvs": "ASVS 5.3.8",
            "zero_trust_pillar": "Workloads",
        },
        {
            "stride": "Tampering",
            "title": "Path Traversal or Arbitrary File Write Outside Designated Output Roots",
            "mitre_tactic": "TA0003 Persistence",
            "mitre_technique": "T1546 Event Triggered Execution",
            "cwe": "CWE-22",
            "severity": "HIGH",
            "requirement": "Canonicalize all file paths (`resolve()`), reject traversal/symlinks/NUL bytes, and enforce strict allowlisted write root directories.",
            "asvs": "ASVS 12.3.1",
            "zero_trust_pillar": "Workloads",
        },
    ],
    "network_framing": [
        {
            "stride": "Tampering",
            "title": "HTTP/1.1 & HTTP/2 Framing Desynchronization (CL.TE / TE.CL Request Smuggling)",
            "mitre_tactic": "TA0001 Initial Access",
            "mitre_technique": "T1190 Exploit Public-Facing Application",
            "cwe": "CWE-444",
            "severity": "CRITICAL",
            "requirement": "Enforce strict RFC 9112 parsing: reject dual `Content-Length` + `Transfer-Encoding`, bare LF/CR line endings, and obs-fold headers at all proxies and origins.",
            "asvs": "ASVS 14.5.1",
            "zero_trust_pillar": "Networks",
        },
        {
            "stride": "Information Disclosure",
            "title": "SSRF Toward Internal Services or Cloud Metadata (169.254.169.254) / TLS Bypass",
            "mitre_tactic": "TA0007 Discovery",
            "mitre_technique": "T1552.005 Cloud Instance Metadata API",
            "cwe": "CWE-918",
            "severity": "HIGH",
            "requirement": "Validate and resolve outbound hosts fail-closed against RFC 1918, link-local, metadata, and unspecified CIDRs; enforce full TLS certificate verification.",
            "asvs": "ASVS 12.6.1",
            "zero_trust_pillar": "Networks",
        },
    ],
    "crypto_secrets": [
        {
            "stride": "Information Disclosure",
            "title": "Hardcoded Credentials, Weak Hash Algorithms, or Non-PQC Long-Lived Keys",
            "mitre_tactic": "TA0006 Credential Access",
            "mitre_technique": "T1552.001 Credentials In Files",
            "cwe": "CWE-798",
            "severity": "HIGH",
            "requirement": "Eliminate hardcoded secrets with pre-commit/CI secret scanning, replace MD5/SHA1 with SHA-256/BLAKE3, and plan hybrid PQC (ML-KEM / ML-DSA) migration for long-lived keys.",
            "asvs": "ASVS 6.2.1",
            "zero_trust_pillar": "Data",
        },
    ],
    "supply_chain_iac": [
        {
            "stride": "Elevation of Privilege",
            "title": "Compromised Third-Party Dependency, Unpinned Container Tag, or Root Container",
            "mitre_tactic": "TA0001 Initial Access",
            "mitre_technique": "T1195.002 Compromise Software Supply Chain",
            "cwe": "CWE-1395",
            "severity": "HIGH",
            "requirement": "Pin dependency lockfiles and immutable container digests, verify release SHA-256 checksums, enforce non-root `USER` in Dockerfiles, and continuously match against exposure catalogs (Trivy + Bumblebee).",
            "asvs": "ASVS 14.2.1",
            "zero_trust_pillar": "Workloads",
        },
    ],
}


@dataclass
class ComponentSurface:
    component_id: str
    name: str
    files: List[str] = field(default_factory=list)
    entry_points: List[Dict[str, Any]] = field(default_factory=list)
    trust_boundaries: List[Dict[str, Any]] = field(default_factory=list)
    linked_findings_count: int = 0
    highest_severity: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DynamicStrideThreatEngine:
    """
    Dynamically derives per-component STRIDE threat models, MITRE ATT&CK mappings,
    Zero Trust evaluations, Security Requirements, Attack Trees, pure-Python SVG/Mermaid
    diagrams, and a comprehensive 5-section downloadable report for any codebase.
    """

    SCANNER_NAME = "RFCHunt-STRIDE-Engine"

    @staticmethod
    def _sev_rank(sev: str) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(str(sev or "INFO").upper(), 0)

    @classmethod
    def analyze_repository(
        cls,
        target_path: str,
        *,
        files: Optional[Sequence[str]] = None,
        entry_points: Optional[Sequence[Dict[str, Any]]] = None,
        trust_boundaries: Optional[Sequence[Dict[str, Any]]] = None,
        data_flows: Optional[Sequence[Dict[str, Any]]] = None,
        findings: Optional[Sequence[Dict[str, Any]]] = None,
        reports_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        resolved = str(Path(target_path).resolve())
        root = Path(resolved)

        # Discover source/config files if not supplied by MantisThreatModeler
        if files is None:
            skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "bin", "tools", "rfcs", "reports", "runs", ".pytest_cache", ".pytest_temp", "caldera_export"}
            discovered: List[str] = []
            if root.is_file():
                discovered.append(str(root))
            elif root.is_dir():
                for r, dirs, fnames in os.walk(root):
                    dirs[:] = sorted(d for d in dirs if d.lower() not in skip and not d.startswith(".pytest_"))
                    for fn in sorted(fnames):
                        discovered.append(str(Path(r) / fn))
                        if len(discovered) >= 1200:
                            break
                    if len(discovered) >= 1200:
                        break
            files_list = discovered
        else:
            files_list = [str(f) for f in files]

        ep_list = list(entry_points or [])
        tb_list = list(trust_boundaries or [])
        df_list = list(data_flows or [])
        findings_list = [dict(f) for f in (findings or []) if isinstance(f, dict)]

        # 1. Dynamic Component Discovery
        comp_files: Dict[str, List[str]] = {cid: [] for cid, _, _ in COMPONENT_SIGNATURES}
        comp_names: Dict[str, str] = {cid: cname for cid, cname, _ in COMPONENT_SIGNATURES}

        for fp_str in files_list[:800]:
            fp = Path(fp_str)
            try:
                rel = str(fp.resolve().relative_to(root)).replace("\\", "/")
            except Exception:
                rel = fp.name
            rel_low = rel.lower()
            sample = ""
            try:
                if fp.is_file() and fp.stat().st_size <= 256 * 1024 and fp.suffix.lower() in (
                    ".py", ".js", ".ts", ".tsx", ".go", ".rs", ".java", ".yaml", ".yml", ".json", ".toml", ".md", ".rego", ".cedar", ".tf", ""
                ):
                    sample = fp.read_text(encoding="utf-8", errors="ignore")[:8000].lower()
            except OSError:
                sample = ""
            haystack = f"{rel_low}\n{sample}"
            for cid, _, tokens in COMPONENT_SIGNATURES:
                if any(tok in haystack for tok in tokens):
                    if rel not in comp_files[cid]:
                        comp_files[cid].append(rel)

        # Link findings to components by file path / CWE
        comp_finding_counts: Dict[str, int] = {cid: 0 for cid, _, _ in COMPONENT_SIGNATURES}
        comp_max_sev: Dict[str, str] = {cid: "INFO" for cid, _, _ in COMPONENT_SIGNATURES}
        cwe_to_comp = {
            "CWE-78": "os_subprocess", "CWE-94": "os_subprocess", "CWE-502": "os_subprocess", "CWE-22": "os_subprocess",
            "CWE-89": "data_storage", "CWE-359": "data_storage", "CWE-532": "data_storage",
            "CWE-77": "ai_llm_mcp", "CWE-829": "ai_llm_mcp",
            "CWE-444": "network_framing", "CWE-436": "network_framing", "CWE-918": "network_framing", "CWE-295": "network_framing",
            "CWE-798": "crypto_secrets", "CWE-327": "crypto_secrets", "CWE-328": "crypto_secrets",
            "CWE-287": "auth_identity", "CWE-306": "api_routes", "CWE-862": "auth_identity", "CWE-863": "auth_identity",
            "CWE-1395": "supply_chain_iac", "CWE-1104": "supply_chain_iac", "CWE-16": "supply_chain_iac", "CWE-250": "supply_chain_iac",
        }
        for f in findings_list:
            fcwe = str(f.get("cwe") or "").upper()
            fsev = str(f.get("severity") or "MEDIUM").upper()
            ffp = str(f.get("file_path") or "").replace("\\", "/").lower()
            matched_cids: Set[str] = set()
            if fcwe in cwe_to_comp:
                matched_cids.add(cwe_to_comp[fcwe])
            for cid, cfiles in comp_files.items():
                if any(cf.lower() in ffp or ffp.endswith(cf.lower()) for cf in cfiles[:80]):
                    matched_cids.add(cid)
            for cid in matched_cids:
                comp_finding_counts[cid] += 1
                if cls._sev_rank(fsev) > cls._sev_rank(comp_max_sev[cid]):
                    comp_max_sev[cid] = fsev

        components: List[ComponentSurface] = []
        for cid, cname, _ in COMPONENT_SIGNATURES:
            cfiles = comp_files[cid]
            if not cfiles and comp_finding_counts[cid] == 0:
                continue
            comp_eps = [e for e in ep_list if any(str(e.get("file", "")).replace("\\", "/") == cf for cf in cfiles)]
            comp_tbs = [b for b in tb_list if any(str(b.get("file", "")).replace("\\", "/") == cf for cf in cfiles)]
            components.append(ComponentSurface(
                component_id=cid,
                name=cname,
                files=cfiles[:30],
                entry_points=comp_eps[:20],
                trust_boundaries=comp_tbs[:20],
                linked_findings_count=comp_finding_counts[cid],
                highest_severity=comp_max_sev[cid],
            ))

        if not components:
            components.append(ComponentSurface(
                component_id="api_routes",
                name="Application Core Surface",
                files=[Path(f).name for f in files_list[:15]],
                entry_points=ep_list[:10],
                trust_boundaries=tb_list[:10],
                linked_findings_count=len(findings_list),
                highest_severity="MEDIUM" if findings_list else "INFO",
            ))

        # 2. Dynamic Per-Component STRIDE Scenarios, MITRE ATT&CK, and Security Requirements
        stride_matrix: Dict[str, List[str]] = {cat: [] for cat in STRIDE_CATEGORIES}
        threat_scenarios: List[Dict[str, Any]] = []
        security_requirements: List[Dict[str, Any]] = []
        mitre_techniques: Dict[str, Dict[str, Any]] = {}
        zt_pillar_issues: Dict[str, List[str]] = {
            "Identity": [],
            "Workloads": [],
            "Networks": [],
            "Applications": [],
            "Data": [],
        }

        scenario_idx = 0
        req_idx = 0
        for comp in components:
            templates = _COMPONENT_THREAT_CATALOG.get(comp.component_id, [])
            for tmpl in templates:
                scenario_idx += 1
                req_idx += 1
                sid = f"THR-{scenario_idx:03d}"
                rid = f"SR-{req_idx:03d}"
                sev = tmpl["severity"]
                if comp.linked_findings_count > 0 and cls._sev_rank(comp.highest_severity) > cls._sev_rank(sev):
                    sev = comp.highest_severity
                evidence_files = comp.files[:4]
                sc_entry = {
                    "scenario_id": sid,
                    "component_id": comp.component_id,
                    "component_name": comp.name,
                    "stride_category": tmpl["stride"],
                    "title": tmpl["title"],
                    "severity": sev,
                    "cwe": tmpl["cwe"],
                    "mitre_tactic": tmpl["mitre_tactic"],
                    "mitre_technique": tmpl["mitre_technique"],
                    "zero_trust_pillar": tmpl["zero_trust_pillar"],
                    "evidence_files": evidence_files,
                    "linked_findings_count": comp.linked_findings_count,
                    "security_requirement_id": rid,
                    "mitigation": tmpl["requirement"],
                }
                threat_scenarios.append(sc_entry)
                stride_matrix[tmpl["stride"]].append(
                    f"[{comp.name}] {tmpl['title']} ({tmpl['cwe']} / {tmpl['mitre_technique']}; files={len(comp.files)}, linked_findings={comp.linked_findings_count})"
                )
                security_requirements.append({
                    "requirement_id": rid,
                    "component": comp.name,
                    "stride_category": tmpl["stride"],
                    "priority": sev,
                    "cwe": tmpl["cwe"],
                    "standard_ref": tmpl["asvs"],
                    "requirement": tmpl["requirement"],
                    "verification_method": "Automated RFCHunt --ensemble + Z3/Lean4 + regression unit tests",
                })
                tech_id = tmpl["mitre_technique"].split()[0]
                mitre_techniques[tech_id] = {
                    "technique_id": tech_id,
                    "technique": tmpl["mitre_technique"],
                    "tactic": tmpl["mitre_tactic"],
                    "components": sorted(set((mitre_techniques.get(tech_id, {}).get("components") or []) + [comp.name])),
                    "severity": sev,
                }
                zt_pillar_issues[tmpl["zero_trust_pillar"]].append(f"{sid}: {tmpl['title']} ({comp.name})")

        # Ensure every STRIDE bucket has a truthful component-grounded entry
        for cat in STRIDE_CATEGORIES:
            if not stride_matrix[cat]:
                stride_matrix[cat].append(
                    f"No elevated {cat} component signatures detected across {len(files_list)} indexed files; maintain baseline verification."
                )

        # 3. Zero Trust Architecture Assessment (5 CISA Pillars)
        zero_trust_assessment: List[Dict[str, Any]] = []
        zt_recommendations = {
            "Identity": "Enforce explicit per-request authentication, short-lived tokens, and fail-closed default-deny RBAC.",
            "Workloads": "Run subprocesses with shell=False, containerize with non-root USER, and pin immutable dependency checksums.",
            "Networks": "Enforce strict RFC 9112 framing rejection, TLS 1.3 verification, and fail-closed SSRF CIDR filtering.",
            "Applications": "Apply structured input validation, prompt-boundary isolation, and rate/size caps on every route.",
            "Data": "Zero-knowledge redact secrets/PHI before logging, encrypt at rest (AES-256-GCM), and migrate long-lived keys toward hybrid PQC.",
        }
        for pillar, issues in zt_pillar_issues.items():
            readiness = "NEEDS_HARDENING" if len(issues) >= 2 else ("REVIEW" if len(issues) == 1 else "BASELINE_OK")
            zero_trust_assessment.append({
                "pillar": pillar,
                "status": readiness,
                "exposed_scenarios_count": len(issues),
                "exposed_scenarios": issues[:6],
                "recommendation": zt_recommendations[pillar],
            })

        # 4. Hierarchical Attack Trees for Top Critical/High Scenarios
        top_scenarios = sorted(
            threat_scenarios,
            key=lambda s: (-cls._sev_rank(s["severity"]), -int(s["linked_findings_count"]), s["scenario_id"]),
        )[:5]
        attack_trees: List[Dict[str, Any]] = []
        for idx_at, sc in enumerate(top_scenarios, start=1):
            attack_trees.append({
                "tree_id": f"AT-{idx_at:02d}",
                "root_goal": f"Exploit {sc['component_name']}: {sc['title']}",
                "scenario_id": sc["scenario_id"],
                "severity": sc["severity"],
                "mitre_technique": sc["mitre_technique"],
                "operator": "OR",
                "branches": [
                    {
                        "branch_id": f"AT-{idx_at:02d}-B1",
                        "label": f"Direct Entry via {sc['component_name']}",
                        "operator": "AND",
                        "leaves": [
                            f"Reach entry/boundary in {', '.join(sc['evidence_files'][:2]) or sc['component_name']}",
                            f"Trigger {sc['cwe']} condition ({sc['stride_category']})",
                        ],
                        "countermeasure": sc["mitigation"],
                    },
                    {
                        "branch_id": f"AT-{idx_at:02d}-B2",
                        "label": "Chained Escalation / Supply-Chain Pivot",
                        "operator": "OR",
                        "leaves": [
                            "Pivot via unverified dependency, leaked secret, or poisoned MCP/skill config",
                            "Chain across trust boundary into privileged execution or data exfiltration",
                        ],
                        "countermeasure": "Enforce Zero Trust boundary verification, lockfile integrity (Trivy + Bumblebee), and formal RBAC/framing invariants (Z3 + Lean 4).",
                    },
                ],
            })

        # 5. Pure-Python Mermaid & Visual SVG Diagrams + 5-Section Downloadable Reports
        threat_mermaid = cls._build_threat_model_mermaid(root.name, components, threat_scenarios)
        attack_tree_mermaid = cls._build_attack_tree_mermaid(attack_trees)
        threat_svg = cls._render_threat_model_svg(root.name, components, threat_scenarios)
        attack_tree_svg = cls._render_attack_tree_svg(attack_trees)

        model_id = "stride-" + hashlib.sha256(f"{resolved}:{len(files_list)}:{len(components)}".encode("utf-8")).hexdigest()[:12]
        result: Dict[str, Any] = {
            "model_id": model_id,
            "target_repo": resolved,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "files_indexed": len(files_list),
            "components_discovered": len(components),
            "components": [c.to_dict() for c in components],
            "stride_matrix": stride_matrix,
            "threat_scenarios": threat_scenarios,
            "mitre_attack_mapping": sorted(mitre_techniques.values(), key=lambda m: m["technique_id"]),
            "zero_trust_assessment": zero_trust_assessment,
            "security_requirements": security_requirements,
            "attack_trees": attack_trees,
            "diagrams": {
                "threat_model_mermaid": threat_mermaid,
                "attack_tree_mermaid": attack_tree_mermaid,
            },
            "report_files": {},
        }

        if reports_dir is not None:
            reports_dir.mkdir(parents=True, exist_ok=True)
            tm_svg_path = reports_dir / "threat_model_diagram.svg"
            at_svg_path = reports_dir / "attack_tree_diagram.svg"
            md_path = reports_dir / "stride_threat_model_report.md"
            html_path = reports_dir / "stride_threat_model_report.html"
            json_path = reports_dir / "stride_threat_model.json"

            tm_svg_path.write_text(threat_svg, encoding="utf-8")
            at_svg_path.write_text(attack_tree_svg, encoding="utf-8")
            md_text = cls._build_markdown_report(result)
            md_path.write_text(md_text, encoding="utf-8")
            html_text = cls._build_html_report(result, threat_svg, attack_tree_svg)
            html_path.write_text(html_text, encoding="utf-8")

            result["report_files"] = {
                "threat_model_svg": str(tm_svg_path),
                "attack_tree_svg": str(at_svg_path),
                "markdown_report": str(md_path),
                "html_report": str(html_path),
                "json_report": str(json_path),
            }
            json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

        return result

    @staticmethod
    def _build_threat_model_mermaid(repo_name: str, components: Sequence[ComponentSurface], scenarios: Sequence[Dict[str, Any]]) -> str:
        lines = [
            "flowchart LR",
            '    Actor["External Threat Actor / Untrusted Input"]',
            f'    subgraph TB["Trust Boundary: {repo_name}"]',
        ]
        for c in components:
            label = f"{c.name} (files={len(c.files)}, findings={c.linked_findings_count})"
            lines.append(f'        {c.component_id}["{label}"]')
        lines.append("    end")
        for c in components:
            lines.append(f"    Actor --> {c.component_id}")
        for sc in scenarios[:6]:
            sid = sc["scenario_id"].replace("-", "_")
            lines.append(f'    {sid}["{sc["stride_category"]}: {sc["cwe"]} ({sc["severity"]})"]')
            lines.append(f'    {sc["component_id"]} -.-> {sid}')
        return "\n".join(lines)

    @staticmethod
    def _build_attack_tree_mermaid(attack_trees: Sequence[Dict[str, Any]]) -> str:
        lines = ["flowchart TD"]
        for t in attack_trees[:3]:
            tid = t["tree_id"].replace("-", "_")
            goal = t["root_goal"].replace('"', "'")[:72]
            lines.append(f'    {tid}["GOAL: {goal} ({t["severity"]})"]')
            for b in t.get("branches") or []:
                bid = b["branch_id"].replace("-", "_")
                blabel = b["label"].replace('"', "'")[:64]
                lines.append(f'    {bid}["[{b["operator"]}] {blabel}"]')
                lines.append(f"    {tid} --> {bid}")
                for l_idx, leaf in enumerate(b.get("leaves") or [], start=1):
                    lid = f"{bid}_L{l_idx}"
                    ltxt = str(leaf).replace('"', "'")[:64]
                    lines.append(f'    {lid}["{ltxt}"]')
                    lines.append(f"    {bid} --> {lid}")
                mid = f"{bid}_MIT"
                mtxt = str(b.get("countermeasure") or "").replace('"', "'")[:64]
                lines.append(f'    {mid}["MITIGATION: {mtxt}"]')
                lines.append(f"    {bid} -.-> {mid}")
        return "\n".join(lines)

    @staticmethod
    def _render_threat_model_svg(repo_name: str, components: Sequence[ComponentSurface], scenarios: Sequence[Dict[str, Any]]) -> str:
        width = 1040
        row_h = 74
        height = max(320, 110 + len(components) * row_h)
        sev_fill = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#475569"}
        elems: List[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="Segoe UI, Arial, sans-serif">',
            f'<rect width="{width}" height="{height}" fill="#0f172a" rx="10"/>',
            f'<text x="24" y="38" fill="#f8fafc" font-size="20" font-weight="bold">RFCHunt Dynamic STRIDE Threat Model — {html.escape(repo_name)}</text>',
            f'<text x="24" y="60" fill="#94a3b8" font-size="12">Components: {len(components)} | Threat Scenarios: {len(scenarios)} | Trust Boundary Architecture</text>',
            # Threat Actor Box
            '<rect x="24" y="96" width="190" height="84" rx="8" fill="#1e293b" stroke="#ef4444" stroke-width="2"/>',
            '<text x="119" y="130" fill="#fca5a5" font-size="13" font-weight="bold" text-anchor="middle">Untrusted Input /</text>',
            '<text x="119" y="150" fill="#fca5a5" font-size="13" font-weight="bold" text-anchor="middle">Threat Actors</text>',
            # Trust boundary container
            f'<rect x="260" y="80" width="756" height="{height - 104}" rx="10" fill="#111827" stroke="#38bdf8" stroke-dasharray="6 4" stroke-width="2"/>',
            '<text x="276" y="100" fill="#38bdf8" font-size="12" font-weight="bold">TRUST BOUNDARY — APPLICATION COMPONENTS &amp; STRIDE RISKS</text>',
        ]
        for idx, c in enumerate(components):
            y = 114 + idx * row_h
            col = sev_fill.get(c.highest_severity, "#475569")
            elems.append(f'<line x1="214" y1="138" x2="284" y2="{y + 28}" stroke="#64748b" stroke-width="1.5"/>')
            elems.append(f'<rect x="284" y="{y}" width="330" height="56" rx="6" fill="#1e293b" stroke="{col}" stroke-width="2"/>')
            elems.append(f'<text x="298" y="{y + 23}" fill="#f8fafc" font-size="13" font-weight="bold">{html.escape(c.name[:34])}</text>')
            elems.append(f'<text x="298" y="{y + 42}" fill="#cbd5e1" font-size="11">Files: {len(c.files)} | Entries: {len(c.entry_points)} | Findings: {c.linked_findings_count}</text>')
            # Linked top threat badge
            top_sc = next((s for s in scenarios if s["component_id"] == c.component_id), None)
            if top_sc:
                sc_col = sev_fill.get(top_sc["severity"], "#d97706")
                elems.append(f'<line x1="614" y1="{y + 28}" x2="646" y2="{y + 28}" stroke="{sc_col}" stroke-width="1.5"/>')
                elems.append(f'<rect x="646" y="{y}" width="352" height="56" rx="6" fill="#1e1b4b" stroke="{sc_col}" stroke-width="1.5"/>')
                elems.append(f'<text x="660" y="{y + 22}" fill="#e2e8f0" font-size="12" font-weight="bold">[{html.escape(top_sc["stride_category"])}] {html.escape(top_sc["cwe"])} ({html.escape(top_sc["severity"])})</text>')
                elems.append(f'<text x="660" y="{y + 42}" fill="#a5b4fc" font-size="11">{html.escape(top_sc["mitre_technique"][:44])}</text>')
        elems.append("</svg>")
        return "\n".join(elems)

    @staticmethod
    def _render_attack_tree_svg(attack_trees: Sequence[Dict[str, Any]]) -> str:
        width = 1040
        shown = list(attack_trees[:3])
        block_h = 200
        height = max(260, 86 + len(shown) * block_h)
        elems: List[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="Segoe UI, Arial, sans-serif">',
            f'<rect width="{width}" height="{height}" fill="#0f172a" rx="10"/>',
            '<text x="24" y="38" fill="#f8fafc" font-size="20" font-weight="bold">RFCHunt Attack Trees &amp; Defensive Countermeasures</text>',
            f'<text x="24" y="58" fill="#94a3b8" font-size="12">Top {len(shown)} prioritized threat goals with OR/AND attack paths and verified mitigations</text>',
        ]
        for idx, t in enumerate(shown):
            y0 = 78 + idx * block_h
            elems.append(f'<rect x="24" y="{y0}" width="992" height="184" rx="8" fill="#111827" stroke="#334155" stroke-width="1.5"/>')
            elems.append(f'<rect x="40" y="{y0 + 14}" width="960" height="36" rx="6" fill="#7f1d1d" stroke="#ef4444" stroke-width="1.5"/>')
            elems.append(f'<text x="54" y="{y0 + 37}" fill="#fef2f2" font-size="13" font-weight="bold">{html.escape(t["tree_id"])} GOAL ({html.escape(t["severity"])}): {html.escape(t["root_goal"][:86])}</text>')
            branches = t.get("branches") or []
            for b_idx, b in enumerate(branches[:2]):
                bx = 40 + b_idx * 488
                by = y0 + 64
                elems.append(f'<line x1="{bx + 230}" y1="{y0 + 50}" x2="{bx + 230}" y2="{by}" stroke="#f87171" stroke-width="1.5"/>')
                elems.append(f'<rect x="{bx}" y="{by}" width="472" height="52" rx="6" fill="#1e293b" stroke="#f59e0b" stroke-width="1.5"/>')
                elems.append(f'<text x="{bx + 12}" y="{by + 20}" fill="#fde68a" font-size="12" font-weight="bold">[{html.escape(b["operator"])}] {html.escape(b["label"][:52])}</text>')
                leaf_preview = "; ".join(str(x) for x in (b.get("leaves") or []))[:66]
                elems.append(f'<text x="{bx + 12}" y="{by + 39}" fill="#cbd5e1" font-size="10.5">{html.escape(leaf_preview)}</text>')
                elems.append(f'<rect x="{bx}" y="{by + 60}" width="472" height="44" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>')
                elems.append(f'<text x="{bx + 12}" y="{by + 86}" fill="#d1fae5" font-size="10.5">MITIGATION: {html.escape(str(b.get("countermeasure") or "")[:64])}</text>')
        elems.append("</svg>")
        return "\n".join(elems)

    @staticmethod
    def _build_markdown_report(res: Dict[str, Any]) -> str:
        lines: List[str] = [
            f"# RFCHunt Comprehensive STRIDE Threat Model Report",
            "",
            f"- **Model ID**: `{res['model_id']}`",
            f"- **Target Repository**: `{res['target_repo']}`",
            f"- **Generated (UTC)**: `{res['generated_at_utc']}`",
            f"- **Files Indexed**: `{res['files_indexed']}` | **Components Discovered**: `{res['components_discovered']}` | **Threat Scenarios**: `{len(res['threat_scenarios'])}`",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"This automated threat assessment analyzed `{res['files_indexed']}` files across `{res['components_discovered']}` architectural components, identifying `{len(res['threat_scenarios'])}` STRIDE threat scenarios mapped to `{len(res['mitre_attack_mapping'])}` MITRE ATT&CK/ATLAS techniques and `{len(res['security_requirements'])}` prioritized security requirements.",
            "",
            "### Zero Trust Readiness Summary",
            "| Pillar | Status | Exposed Scenarios | Key Recommendation |",
            "|---|---|---|---|",
        ]
        for zt in res["zero_trust_assessment"]:
            lines.append(f"| **{zt['pillar']}** | `{zt['status']}` | {zt['exposed_scenarios_count']} | {zt['recommendation']} |")

        lines.extend([
            "",
            "---",
            "",
            "## 2. Threat Model Diagram",
            "",
            "Visual SVG diagram saved to `threat_model_diagram.svg`.",
            "",
            "```mermaid",
            res["diagrams"]["threat_model_mermaid"],
            "```",
            "",
            "---",
            "",
            "## 3. Threat Scenarios (STRIDE + MITRE ATT&CK)",
            "",
            "| ID | Component | STRIDE | Severity | CWE | MITRE ATT&CK | Scenario |",
            "|---|---|---|---|---|---|---|",
        ])
        for sc in res["threat_scenarios"]:
            lines.append(
                f"| `{sc['scenario_id']}` | {sc['component_name']} | **{sc['stride_category']}** | `{sc['severity']}` | `{sc['cwe']}` | `{sc['mitre_technique']}` | {sc['title']} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 4. Security Requirements",
            "",
            "| Req ID | Priority | Component | Standard | CWE | Security Requirement |",
            "|---|---|---|---|---|---|",
        ])
        for sr in res["security_requirements"]:
            lines.append(
                f"| `{sr['requirement_id']}` | `{sr['priority']}` | {sr['component']} | `{sr['standard_ref']}` | `{sr['cwe']}` | {sr['requirement']} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 5. Attack Trees",
            "",
            "Visual SVG attack tree saved to `attack_tree_diagram.svg`.",
            "",
            "```mermaid",
            res["diagrams"]["attack_tree_mermaid"],
            "```",
            "",
        ])
        for at in res["attack_trees"]:
            lines.append(f"### {at['tree_id']} — {at['root_goal']} (`{at['severity']}` / `{at['mitre_technique']}`)")
            for b in at["branches"]:
                lines.append(f"- **[{b['operator']}] {b['label']}**")
                for leaf in b["leaves"]:
                    lines.append(f"  - Precondition: {leaf}")
                lines.append(f"  - **Mitigation**: {b['countermeasure']}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _build_html_report(res: Dict[str, Any], threat_svg: str, attack_tree_svg: str) -> str:
        sc_rows = "\n".join(
            f"<tr><td><code>{html.escape(s['scenario_id'])}</code></td><td>{html.escape(s['component_name'])}</td>"
            f"<td><b>{html.escape(s['stride_category'])}</b></td><td>{html.escape(s['severity'])}</td>"
            f"<td><code>{html.escape(s['cwe'])}</code></td><td>{html.escape(s['mitre_technique'])}</td>"
            f"<td>{html.escape(s['title'])}</td></tr>"
            for s in res["threat_scenarios"]
        )
        sr_rows = "\n".join(
            f"<tr><td><code>{html.escape(r['requirement_id'])}</code></td><td>{html.escape(r['priority'])}</td>"
            f"<td>{html.escape(r['component'])}</td><td><code>{html.escape(r['standard_ref'])}</code></td>"
            f"<td>{html.escape(r['requirement'])}</td></tr>"
            for r in res["security_requirements"]
        )
        zt_rows = "\n".join(
            f"<tr><td><b>{html.escape(z['pillar'])}</b></td><td><code>{html.escape(z['status'])}</code></td>"
            f"<td>{z['exposed_scenarios_count']}</td><td>{html.escape(z['recommendation'])}</td></tr>"
            for z in res["zero_trust_assessment"]
        )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>RFCHunt STRIDE Threat Model Report — {html.escape(res['model_id'])}</title>
<style>
  body {{ font-family: Segoe UI, Arial, sans-serif; background: #0b1120; color: #e2e8f0; margin: 28px auto; max-width: 1120px; line-height: 1.5; }}
  h1, h2 {{ color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 14px 0 24px 0; font-size: 13px; }}
  th, td {{ border: 1px solid #334155; padding: 8px 10px; text-align: left; }}
  th {{ background: #1e293b; color: #93c5fd; }}
  tr:nth-child(even) {{ background: #111827; }}
  .svg-wrap {{ overflow-x: auto; margin: 16px 0; }}
  code {{ background: #1e293b; padding: 2px 5px; border-radius: 4px; color: #f8fafc; }}
</style>
</head>
<body>
<h1>RFCHunt Comprehensive STRIDE Threat Model Report</h1>
<p><b>Model ID:</b> <code>{html.escape(res['model_id'])}</code> | <b>Target:</b> <code>{html.escape(res['target_repo'])}</code> | <b>Components:</b> {res['components_discovered']} | <b>Scenarios:</b> {len(res['threat_scenarios'])}</p>

<h2>1. Executive Summary &amp; Zero Trust Assessment</h2>
<table><thead><tr><th>Zero Trust Pillar</th><th>Status</th><th>Exposed Scenarios</th><th>Recommendation</th></tr></thead><tbody>{zt_rows}</tbody></table>

<h2>2. Threat Model Diagram</h2>
<div class="svg-wrap">{threat_svg}</div>

<h2>3. Threat Scenarios (STRIDE + MITRE ATT&amp;CK)</h2>
<table><thead><tr><th>ID</th><th>Component</th><th>STRIDE</th><th>Severity</th><th>CWE</th><th>MITRE ATT&amp;CK</th><th>Scenario</th></tr></thead><tbody>{sc_rows}</tbody></table>

<h2>4. Security Requirements</h2>
<table><thead><tr><th>Req ID</th><th>Priority</th><th>Component</th><th>Standard</th><th>Requirement</th></tr></thead><tbody>{sr_rows}</tbody></table>

<h2>5. Attack Trees</h2>
<div class="svg-wrap">{attack_tree_svg}</div>
</body>
</html>
"""


__all__ = [
    "COMPONENT_SIGNATURES",
    "ComponentSurface",
    "DynamicStrideThreatEngine",
    "STRIDE_CATEGORIES",
]
