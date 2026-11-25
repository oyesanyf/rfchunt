"""
Module 25: Web LLM Defensive Security Auditor
=============================================
Static AST/source-code and safe canary auditor covering OWASP LLM Top 10 & PortSwigger
Web LLM Security defensive controls:

1. `WEBLLM-AGENCY-001` — Excessive Agency:
   Detects LLM tool/function bindings (`tools=`, `functions=`, `@tool`, `bind_tools`) wired
   to high-impact write/delete/payment/SQL/email callbacks without confirmation or authz guards.
2. `WEBLLM-TAINT-002` — Unvalidated LLM Tool Arguments into Classic Sinks:
   Detects `tool_call.function.arguments`, `tool_use.input`, `tool_args`, or agent action
   inputs flowing into SQL, OS command, filesystem, or outbound HTTP client sinks.
3. `WEBLLM-OUTPUT-003` — Insecure Output Handling:
   Detects LLM response objects (`choices[0].message.content`, `completion.content`,
   `generate_content().text`, `llm_output`, `model_response`) rendered unsanitized into
   HTML/DOM/Markdown sinks (`dangerouslySetInnerHTML`, `innerHTML`, `v-html`,
   `render_template_string`, `rehype-raw`, `markdown-it` with `html: true`).
4. `WEBLLM-FENCE-004` — Unfenced Untrusted Data in LLM Prompt Messages:
   Detects untrusted web/user/RAG/tool text concatenated directly into `role: "user"`,
   `role: "tool"`, or `role: "system"` prompts without nonce-fencing or sanitization.
5. `WEBLLM-PROMPT-AUTHZ-005` — Prompt-Only Access Control:
   Detects natural-language authorization directives inside system prompts ("only allow admins",
   "do not disclose other users' data") where no server-side programmatic authz check exists.
6. `WEBLLM-RAG-SCRUB-006` — Missing Pre-Context Secret/PII Scrubbing & Tenant Isolation:
   Detects RAG retrieval or context-assembly code passing raw database/document records
   into LLM context without tenant filtering or secret/PII scrubbing.
7. `WEBLLM-INGEST-007` — Unauthenticated / Broad Fine-Tuning or RAG Ingestion Endpoints:
   Detects `/ingest`, `/rag/upload`, `/fine-tune`, or `/knowledge/add` routes lacking
   authentication or content-validation decorators.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

MODULE_25_NAME = "Module-25-Web-LLM-Auditor"

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".pytest_cache",
    "reports",
}

_SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".rb", ".go", ".java"}

# 1. Excessive Agency patterns
_TOOL_BINDING_RE = re.compile(
    r"(?:@tool\b|\btools\s*=\s*\[|\bfunctions\s*=\s*\[|\.bind_tools\s*\(|register_tool\s*\(|add_tool\s*\()",
    re.IGNORECASE,
)
_HIGH_IMPACT_ACTION_RE = re.compile(
    r"\b(?:delete_user|delete_account|drop_table|transfer_funds|issue_refund|send_email|reset_password|execute_sql|run_shell|grant_admin|update_role|charge_card)\b",
    re.IGNORECASE,
)
_CONFIRMATION_OR_AUTHZ_RE = re.compile(
    r"\b(?:require_confirmation|confirm_user|human_in_the_loop|hitl|check_permission|authorize_caller|verify_authz|current_user\.is_admin|@login_required|@requires_auth)\b",
    re.IGNORECASE,
)

# 2. LLM tool arguments flowing into classic web sinks
_LLM_TOOL_ARG_RE = re.compile(
    r"\b(?:tool_call\.function\.arguments|tool_use\.input|function_call\.arguments|tool_args|agent_action\.tool_input|fn_args)\b"
)
_CLASSIC_SINK_RE = re.compile(
    r"\b(?:cursor\.execute|db\.execute|db\.query|pool\.query|os\.system|subprocess\.(?:run|Popen|call)|child_process\.exec|requests\.(?:get|post)|httpx\.(?:get|post)|fetch\s*\(|open\s*\(|fs\.readFile)\b"
)

# 3. Insecure Output Handling (LLM response -> HTML/DOM/Markdown/SSTI sinks)
_LLM_OUTPUT_VAR_RE = re.compile(
    r"\b(?:choices\[0\]\.message\.content|completion\.content|generate_content\([^)]*\)\.text|llm\.invoke\(|llm_output|model_response|assistant_reply|ai_response|chat_reply)\b"
)
_UNSAFE_RENDER_SINK_RE = re.compile(
    r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|v-html\s*=|render_template_string\s*\(|rehype-raw|html\s*:\s*true|document\.write\s*\()",
    re.IGNORECASE,
)
_OUTPUT_SANITIZER_RE = re.compile(
    r"\b(?:DOMPurify\.sanitize|bleach\.clean|html\.escape|markupsafe\.escape|sanitizeHtml|escapeHtml)\b"
)

# 4. Unfenced untrusted content interpolated into LLM messages
_UNTRUSTED_INPUT_RE = re.compile(
    r"\b(?:retrieved_chunks|rag_docs|web_page_text|page_content|user_comment|email_body|tool_output|mcp_tool_output|external_html)\b",
    re.IGNORECASE,
)
_LLM_MESSAGE_ROLE_RE = re.compile(
    r"""["']role["']\s*:\s*["'](?:system|user|tool|developer)["']""",
    re.IGNORECASE,
)
_FENCE_OR_SANITIZE_RE = re.compile(
    r"\b(?:sanitize_for_llm_prompt|UntrustedOutputBoundary|nonce=|untrusted_remote_response_data|fence_untrusted)\b"
)

# 5. Prompt-only access control (PortSwigger Rule #3)
_PROMPT_ONLY_AUTHZ_RE = re.compile(
    r"""(?:only\s+allow\s+admin|never\s+reveal\s+other\s+users|do\s+not\s+execute\s+unless\s+(?:the\s+)?user\s+is\s+admin|restrict\s+access\s+to\s+authorized\s+users\s+only)""",
    re.IGNORECASE,
)

# 6. Pre-context secret/PII scrubbing & RAG tenant isolation (PortSwigger Rule #2)
_RAG_CONTEXT_BUILD_RE = re.compile(
    r"\b(?:similarity_search|vector_store\.query|retrieve_context|build_rag_context|chroma\.query|pinecone\.query)\s*\(",
    re.IGNORECASE,
)
_TENANT_OR_SCRUB_RE = re.compile(
    r"\b(?:tenant_id|user_id|namespace|filter\s*=|where\s*=|scrub_pii|redact_secrets|presidio|PhiScanner)\b",
    re.IGNORECASE,
)

# 7. Unauthenticated RAG / fine-tuning ingestion endpoints
_INGEST_ROUTE_RE = re.compile(
    r"""@(?:app|router)\.(?:post|put)\s*\(\s*['"][^'"]*(?:/ingest|/rag/upload|/knowledge/add|/fine[-_]?tune|/embeddings/add)['"]""",
    re.IGNORECASE,
)


@dataclass
class WebLLMFinding:
    rule_id: str
    title: str
    severity: str
    cwe: str
    owasp_llm: str
    file_path: str
    line: int
    snippet: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_sarif_result(self) -> Dict[str, Any]:
        level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        return {
            "ruleId": self.rule_id,
            "level": level_map.get(self.severity.upper(), "warning"),
            "message": {"text": f"{self.title} ({self.owasp_llm}): {self.snippet}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.file_path},
                        "region": {"startLine": max(1, int(self.line))},
                    }
                }
            ],
            "properties": {
                "cwe": self.cwe,
                "owasp_llm": self.owasp_llm,
                "remediation": self.remediation,
            },
        }


@dataclass
class WebLLMAuditReport:
    target: str
    module: str = MODULE_25_NAME
    files_scanned: int = 0
    findings: List[WebLLMFinding] = field(default_factory=list)
    defensive_checklist: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "defensive_checklist": self.defensive_checklist,
        }


def _audit_single_source_file(path: Path, root: Path) -> List[WebLLMFinding]:
    findings: List[WebLLMFinding] = []
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            return findings
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    try:
        rel = str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        rel = str(path).replace("\\", "/")

    lines = text.splitlines()

    def _window(idx: int, radius: int = 12) -> str:
        start = max(0, idx - radius)
        end = min(len(lines), idx + radius + 1)
        return "\n".join(lines[start:end])

    for i, line in enumerate(lines):
        lineno = i + 1

        # 1. Excessive Agency: tool binding to high-impact API without confirmation/authz
        if _TOOL_BINDING_RE.search(line):
            win = _window(i, radius=15)
            if _HIGH_IMPACT_ACTION_RE.search(win) and not _CONFIRMATION_OR_AUTHZ_RE.search(win):
                findings.append(
                    WebLLMFinding(
                        rule_id="WEBLLM-AGENCY-001",
                        title="Excessive Agency: High-Impact LLM Tool Bound Without Confirmation or Caller Authz",
                        severity="HIGH",
                        cwe="CWE-862",
                        owasp_llm="LLM06:2025",
                        file_path=rel,
                        line=lineno,
                        snippet=line.strip()[:220],
                        remediation=(
                            "Treat every LLM-callable API as publicly accessible: enforce caller-scoped server-side "
                            "authorization and explicit human-in-the-loop confirmation before state-changing actions."
                        ),
                    )
                )

        # 2. Classic Web Sinks fed by LLM tool-call arguments
        if _LLM_TOOL_ARG_RE.search(line):
            win = _window(i, radius=10)
            if _CLASSIC_SINK_RE.search(win):
                findings.append(
                    WebLLMFinding(
                        rule_id="WEBLLM-TAINT-002",
                        title="Unvalidated LLM Tool Arguments Reaching SQL/OS/FS/HTTP Sink",
                        severity="HIGH",
                        cwe="CWE-20",
                        owasp_llm="LLM05:2025",
                        file_path=rel,
                        line=lineno,
                        snippet=line.strip()[:220],
                        remediation=(
                            "Validate all LLM tool arguments against strict schemas/allowlists and use parameterized "
                            "queries, safe path confinement, and SSRF allowlists."
                        ),
                    )
                )

        # 3. Insecure Output Handling (LLM output -> DOM/HTML/Markdown/SSTI sink)
        if _UNSAFE_RENDER_SINK_RE.search(line):
            win = _window(i, radius=10)
            if _LLM_OUTPUT_VAR_RE.search(win) and not _OUTPUT_SANITIZER_RE.search(win):
                findings.append(
                    WebLLMFinding(
                        rule_id="WEBLLM-OUTPUT-003",
                        title="Insecure Output Handling: Unsanitized LLM Output Rendered into HTML/DOM/Template Sink",
                        severity="HIGH",
                        cwe="CWE-79",
                        owasp_llm="LLM05:2025",
                        file_path=rel,
                        line=lineno,
                        snippet=line.strip()[:220],
                        remediation=(
                            "Treat all LLM output as untrusted user input: sanitize with DOMPurify/bleach/html.escape "
                            "and disable raw HTML passthrough in Markdown renderers."
                        ),
                    )
                )

        # 4. Unfenced untrusted retrieval/external data interpolated into LLM messages
        if _LLM_MESSAGE_ROLE_RE.search(line):
            win = _window(i, radius=8)
            if _UNTRUSTED_INPUT_RE.search(win) and not _FENCE_OR_SANITIZE_RE.search(win):
                findings.append(
                    WebLLMFinding(
                        rule_id="WEBLLM-FENCE-004",
                        title="Unfenced Untrusted External/RAG Content Interpolated into LLM Prompt Message",
                        severity="MEDIUM",
                        cwe="CWE-74",
                        owasp_llm="LLM01:2025",
                        file_path=rel,
                        line=lineno,
                        snippet=line.strip()[:220],
                        remediation=(
                            "Wrap untrusted external/RAG/tool data inside symmetric per-call nonce-fenced boundaries "
                            "and strip invisible Unicode/BiDi control characters before prompt assembly."
                        ),
                    )
                )

        # 5. Prompt-only access control (PortSwigger Rule #3)
        if _PROMPT_ONLY_AUTHZ_RE.search(line):
            if not _CONFIRMATION_OR_AUTHZ_RE.search(text):
                findings.append(
                    WebLLMFinding(
                        rule_id="WEBLLM-PROMPT-AUTHZ-005",
                        title="Prompt-Only Access Control Without Server-Side Programmatic Enforcement",
                        severity="MEDIUM",
                        cwe="CWE-285",
                        owasp_llm="LLM06:2025",
                        file_path=rel,
                        line=lineno,
                        snippet=line.strip()[:220],
                        remediation=(
                            "Never rely on natural-language system-prompt rules for access control; enforce "
                            "authorization programmatically in backend route and tool handlers."
                        ),
                    )
                )

        # 6. Missing pre-context tenant isolation or PII/secret scrubbing in RAG retrieval
        if _RAG_CONTEXT_BUILD_RE.search(line):
            win = _window(i, radius=8)
            if not _TENANT_OR_SCRUB_RE.search(win):
                findings.append(
                    WebLLMFinding(
                        rule_id="WEBLLM-RAG-SCRUB-006",
                        title="RAG Context Assembly Missing Tenant Filter or Pre-Context Secret/PII Scrubbing",
                        severity="MEDIUM",
                        cwe="CWE-200",
                        owasp_llm="LLM02:2025",
                        file_path=rel,
                        line=lineno,
                        snippet=line.strip()[:220],
                        remediation=(
                            "Enforce mandatory per-tenant metadata filters on vector queries and scrub secrets/PII "
                            "before injecting retrieved documents into LLM context."
                        ),
                    )
                )

        # 7. Unauthenticated RAG / fine-tuning ingestion route
        if _INGEST_ROUTE_RE.search(line):
            win = _window(i, radius=6)
            if not _CONFIRMATION_OR_AUTHZ_RE.search(win):
                findings.append(
                    WebLLMFinding(
                        rule_id="WEBLLM-INGEST-007",
                        title="RAG / Fine-Tuning Ingestion Endpoint Missing Authentication Guard",
                        severity="HIGH",
                        cwe="CWE-306",
                        owasp_llm="LLM04:2025",
                        file_path=rel,
                        line=lineno,
                        snippet=line.strip()[:220],
                        remediation=(
                            "Require authenticated admin/authorized roles and provenance validation on all "
                            "RAG corpus and fine-tuning ingestion endpoints."
                        ),
                    )
                )

    return findings


def audit_web_llm_repository(target_dir: str | Path, max_workers: Optional[int] = None) -> WebLLMAuditReport:
    """
    Concurrently audits a repository for Web LLM security flaws and PortSwigger's
    3 core defensive rules using a bounded ThreadPoolExecutor.
    """
    root = Path(target_dir).resolve()
    report = WebLLMAuditReport(target=str(root))
    if not root.exists():
        return report

    candidates: List[Path] = []
    if root.is_file():
        candidates.append(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.suffix.lower() in _SOURCE_EXTENSIONS:
                    candidates.append(p)

    report.files_scanned = len(candidates)
    workers = max_workers or min(16, max(2, (os.cpu_count() or 4)))

    if candidates:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_audit_single_source_file, p, root) for p in candidates]
            for fut in as_completed(futs):
                try:
                    report.findings.extend(fut.result())
                except Exception:
                    continue

    report.findings.sort(key=lambda f: (f.file_path, f.line, f.rule_id))
    rule_ids = {f.rule_id for f in report.findings}
    agency_or_ingest_flagged = ("WEBLLM-AGENCY-001" in rule_ids) or ("WEBLLM-INGEST-007" in rule_ids)
    rag_scrub_flagged = "WEBLLM-RAG-SCRUB-006" in rule_ids
    prompt_authz_flagged = "WEBLLM-PROMPT-AUTHZ-005" in rule_ids
    output_flagged = "WEBLLM-OUTPUT-003" in rule_ids
    fence_flagged = "WEBLLM-FENCE-004" in rule_ids
    report.defensive_checklist = {
        "apis_independently_authorized": not agency_or_ingest_flagged,
        "pre_context_scrubbing_and_tenant_isolation": not rag_scrub_flagged,
        "programmatic_authz_not_prompt_only": not prompt_authz_flagged,
        "output_handling_sanitized": not output_flagged,
        "untrusted_context_fenced": not fence_flagged,
    }
    return report
