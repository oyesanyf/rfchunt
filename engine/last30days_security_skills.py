#!/usr/bin/env python3
"""
engine/last30days_security_skills.py
================================================================================
Zero-API-Key Adaptation of `mvanhorn/last30days-skill` for Security & Pentesting Skills

Integrates last-30-days security & bug-bounty detection skills into RFCHunt using
STRICTLY ZERO-API-KEY public sources ("no api is required"):
  1. Reddit Public Keyless JSON (`r/netsec`, `r/bugbounty`, `r/redteamsec`, `r/llmsecurity`)
  2. Hacker News Algolia Keyless API (`hn.algolia.com/api/v1/search_by_date`)
  3. GitHub Keyless Public Search (`api.github.com/search/repositories` for security skills & PoCs)
  4. arXiv Keyless Atom API (`export.arxiv.org/api/query` for `cs.CR` / `cs.AI`)
  5. DEV Community (`dev.to`) Keyless Articles API (`dev.to/api/articles?tag=security`)
  6. Local Corpus & `SKILL.md` / `.claude-plugin` / `.codex-plugin` directories

Also ships 10 built-in Zero-API Security & Hacking Detection Skills (5 AI/Agent Security +
5 Application/Web Pentesting & Bug-Bounty Skills), a Hermes-style `SKILL.md` supply-chain
and cookie-consent auditor, and automatic `SKILL.md` skill generator controlled by
`--reseach-num` / `--research-num`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


# Strictly keyless source lane registry (0 paid or API-key lanes permitted)
KEYLESS_SOURCE_LANES: Tuple[str, ...] = (
    "reddit_keyless_json",
    "hackernews_algolia_keyless",
    "github_public_keyless",
    "arxiv_atom_keyless",
    "devto_public_keyless",
    "local_corpus_skillmd",
)

FORBIDDEN_PAID_API_LANES: Tuple[str, ...] = (
    "scrapecreators",
    "x_bearer_token",
    "xquik_api",
    "perplexity_api",
    "openrouter_sonar",
    "brightdata",
    "truthsocial_token",
    "telegram_scrapecreators",
)


@dataclass
class SecuritySkillSpec:
    skill_id: str
    skill_slug: str
    detector_name: str
    domain: str  # "AI_SECURITY" | "APP_CODE_SECURITY"
    title: str
    source_lane: str
    source_url: str
    cwe_id: str
    severity: str
    engagement_score: float  # 0.0 - 100.0
    requires_api_key: bool
    summary: str
    detection_logic_description: str
    remediation: str
    skill_md_path: str = ""
    synthesized_python_path: str = ""
    custom_indicators: List[str] = field(default_factory=list)
    corroborating_lanes: List[str] = field(default_factory=list)
    structural_template: str = ""
    self_test_passed: bool = True


@dataclass
class SecuritySkillFinding:
    rule_id: str
    skill_slug: str
    detector_name: str
    domain: str
    source_lane: str
    source_url: str
    cwe_id: str
    severity: str
    title: str
    file: str
    line: int
    function_name: str
    evidence_snippet: str
    remediation: str
    confidence: str = "HIGH"
    poe_level: int = 2
    verification_status: str = "STATIC_SKILL_VERIFIED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# 10 Built-In Zero-API Security & Hacking Detection Skills
# (5 AI/Agent Security Skills + 5 Application/Web Pentesting Skills)
# ==============================================================================

BUILTIN_LAST30DAYS_SECURITY_SKILLS: Tuple[SecuritySkillSpec, ...] = (
    # --- 5 AI / Agent Security & Hacking Detection Skills ---
    SecuritySkillSpec(
        skill_id="SKILL-L30D-AI-01-MCP-RUGPULL-SHADOWING",
        skill_slug="mcp-rugpull-and-tool-shadowing",
        detector_name="detect_mcp_rugpull_and_tool_shadowing",
        domain="AI_SECURITY",
        title="MCP Tool Shadowing, Dynamic Rug-Pull & Unpinned Schema Detector",
        source_lane="github_public_keyless",
        source_url="https://github.com/mvanhorn/last30days-skill",
        cwe_id="CWE-494",
        severity="CRITICAL",
        engagement_score=96.5,
        requires_api_key=False,
        summary=(
            "Detects MCP servers and agent tool loaders that mutate tool descriptions "
            "after initial registration (rug-pull), shadow built-in system tools across "
            "untrusted servers, or register external MCP tools without SHA-256 schema pinning."
        ),
        detection_logic_description=(
            "Scans MCP server/client code for dynamic post-approval tool description mutation, "
            "duplicate/shadowed tool names across servers, and unpinned remote MCP tool definitions."
        ),
        remediation=(
            "Pin SHA-256 hashes of approved MCP tool schemas and reject runtime tool-description "
            "mutations or duplicate tool names across distinct MCP server namespaces."
        ),
    ),
    SecuritySkillSpec(
        skill_id="SKILL-L30D-AI-02-AGENT-COOKIE-SIDECAR-CONSENT",
        skill_slug="agent-cookie-sidecar-consent-guard",
        detector_name="detect_unconsented_cookie_and_keychain_reads",
        domain="AI_SECURITY",
        title="Agent Browser Cookie Sidecar & Keychain Unconsented Access Detector",
        source_lane="github_public_keyless",
        source_url="https://github.com/mvanhorn/last30days-skill/pull/1440",
        cwe_id="CWE-522",
        severity="CRITICAL",
        engagement_score=95.0,
        requires_api_key=False,
        summary=(
            "Adapted from last30days-skill PR #1440 (agentcookie positive consent) & PR #1526 "
            "(protect research databases): detects agent skills or scripts that read browser "
            "SQLite cookie stores (Cookies, cookies.sqlite, Login Data) or OS keychains without "
            "an explicit positive consent check."
        ),
        detection_logic_description=(
            "Flags direct access to Chrome/Edge/Firefox/Safari cookie SQLite files, DPAPI "
            "Local State, or macOS security find-generic-password without a preceding user consent gate."
        ),
        remediation=(
            "Require explicit positive user consent before reading browser cookie sidecars or "
            "OS credential stores, and restrict local research SQLite DB permissions to 0600."
        ),
    ),
    SecuritySkillSpec(
        skill_id="SKILL-L30D-AI-03-SKILLMD-HERMES-INSTALL-SCAN",
        skill_slug="hermes-skillmd-supply-chain-scanner",
        detector_name="detect_hermes_skill_supply_chain_backdoor",
        domain="AI_SECURITY",
        title="Hermes Agent Skill (SKILL.md / Plugin Manifest) Supply-Chain & Exfiltration Scanner",
        source_lane="github_public_keyless",
        source_url="https://github.com/mvanhorn/last30days-skill/commit/030a2c8fe66641812a44ff1e0965368fb8ed0c3a",
        cwe_id="CWE-506",
        severity="CRITICAL",
        engagement_score=94.0,
        requires_api_key=False,
        summary=(
            "Adapted from last30days-skill Hermes install scanner: audits SKILL.md, "
            ".claude-plugin, .codex-plugin, .grok-plugin, and gemini-extension.json files "
            "for curl|sh bootstrap backdoors, base64 obfuscated shell payloads, and covert "
            "environment-variable exfiltration."
        ),
        detection_logic_description=(
            "Scans agent skill markdown, hooks, and plugin manifests for piped remote execution, "
            "encoded bootstrap scripts, and silent outbound webhook exfiltration."
        ),
        remediation=(
            "Remove remote piped shell execution, hidden base64 commands, and outbound secret "
            "transmission from SKILL.md and plugin hook definitions."
        ),
    ),
    SecuritySkillSpec(
        skill_id="SKILL-L30D-AI-04-RAG-VECTOR-TENANT-LEAK",
        skill_slug="rag-vector-multi-tenant-isolation",
        detector_name="detect_rag_vector_cross_tenant_leak",
        domain="AI_SECURITY",
        title="Multi-Tenant RAG Vector Store Unfiltered Similarity Search Detector",
        source_lane="hackernews_algolia_keyless",
        source_url="https://news.ycombinator.com/",
        cwe_id="CWE-284",
        severity="HIGH",
        engagement_score=89.5,
        requires_api_key=False,
        summary=(
            "Detects vector database similarity queries (Chroma, Qdrant, Pinecone, Milvus, "
            "FAISS, pgvector) that retrieve top-k embeddings without enforcing a mandatory "
            "tenant_id / user_id / namespace metadata filter."
        ),
        detection_logic_description=(
            "Inspects similarity_search, query_points, and collection.query calls for missing "
            "tenant/owner filter predicates."
        ),
        remediation=(
            "Enforce mandatory tenant_id/user_id metadata filters and per-tenant namespaces "
            "on every vector similarity search query."
        ),
    ),
    SecuritySkillSpec(
        skill_id="SKILL-L30D-AI-05-STRUCTURED-OUTPUT-GRAMMAR-INJECTION",
        skill_slug="llm-structured-output-grammar-injection",
        detector_name="detect_structured_output_sink_injection",
        domain="AI_SECURITY",
        title="LLM Structured-Output Extra-Field & Template/SQL Sink Injection Detector",
        source_lane="devto_public_keyless",
        source_url="https://dev.to/t/security",
        cwe_id="CWE-74",
        severity="HIGH",
        engagement_score=87.0,
        requires_api_key=False,
        summary=(
            "Detects LLM structured-output schemas permitting arbitrary extra fields "
            "(extra='allow' / additionalProperties: true) or forwarding unvalidated "
            "LLM JSON fields directly into Jinja2/template rendering or raw SQL queries."
        ),
        detection_logic_description=(
            "Flags permissive structured-output schema configs and direct template/SQL "
            "interpolation of parsed LLM response fields."
        ),
        remediation=(
            "Enforce extra='forbid' (additionalProperties: false) and strict enum/regex "
            "constraints on LLM structured outputs before passing fields to downstream sinks."
        ),
    ),
    # --- 5 Application & Web Pentest / Bug-Bounty Detection Skills ---
    SecuritySkillSpec(
        skill_id="SKILL-L30D-APP-01-SSR-SERVER-ACTION-AUTH-BYPASS",
        skill_slug="ssr-server-action-direct-invocation-authz",
        detector_name="detect_server_action_missing_inline_authz",
        domain="APP_CODE_SECURITY",
        title="SSR / React Server Action Direct Invocation Missing Inline Authorization Detector",
        source_lane="reddit_keyless_json",
        source_url="https://www.reddit.com/r/bugbounty/",
        cwe_id="CWE-306",
        severity="HIGH",
        engagement_score=93.5,
        requires_api_key=False,
        summary=(
            "Detects Next.js / React Server Actions ('use server') and RPC mutation handlers "
            "that perform database writes or sensitive state changes without verifying the "
            "caller's session/role inside the exported action body."
        ),
        detection_logic_description=(
            "Scans 'use server' modules for exported async functions that invoke db/prisma/sql "
            "mutations (create, update, delete) without calling an authentication/session check."
        ),
        remediation=(
            "Verify session authentication and object-level authorization inside every "
            "exported 'use server' function rather than relying solely on route middleware."
        ),
    ),
    SecuritySkillSpec(
        skill_id="SKILL-L30D-APP-02-JWT-JKU-KID-CONFUSION",
        skill_slug="jwt-jku-kid-signature-confusion",
        detector_name="detect_jwt_unverified_or_jku_kid_injection",
        domain="APP_CODE_SECURITY",
        title="JWT Unverified Decode, JKU/X5U SSRF & KID Injection Pentest Detector",
        source_lane="reddit_keyless_json",
        source_url="https://www.reddit.com/r/netsec/",
        cwe_id="CWE-347",
        severity="CRITICAL",
        engagement_score=94.5,
        requires_api_key=False,
        summary=(
            "Detects JWT handling flaws where verify_signature is disabled, alg='none' is "
            "permitted, jku/x5u header URLs are fetched dynamically without origin pinning, "
            "or unvalidated kid headers flow into file paths or SQL queries."
        ),
        detection_logic_description=(
            "Matches jwt.decode(..., verify=False / verify_signature=False), unpinned "
            "unverified_header['jku'/'x5u'] fetches, and raw unverified_header['kid'] usage."
        ),
        remediation=(
            "Always enforce cryptographic signature verification with an explicit asymmetric "
            "algorithm allowlist and pin JWKS keys to a static trusted issuer configuration."
        ),
    ),
    SecuritySkillSpec(
        skill_id="SKILL-L30D-APP-03-WEBHOOK-DNS-REBIND-SSRF",
        skill_slug="webhook-toctou-dns-rebinding-ssrf",
        detector_name="detect_dns_rebinding_toctou_ssrf",
        domain="APP_CODE_SECURITY",
        title="Webhook Two-Step DNS Resolution TOCTOU (DNS Rebinding SSRF) Detector",
        source_lane="hackernews_algolia_keyless",
        source_url="https://news.ycombinator.com/",
        cwe_id="CWE-918",
        severity="HIGH",
        engagement_score=91.0,
        requires_api_key=False,
        summary=(
            "Detects URL validators that resolve a hostname via socket.gethostbyname/getaddrinfo "
            "to check for private IPs and subsequently pass the original hostname URL to "
            "requests.get/httpx/fetch, creating a DNS-rebinding TOCTOU window."
        ),
        detection_logic_description=(
            "Identifies functions performing DNS resolution validation followed by an HTTP "
            "client request using the unpinned hostname with redirects enabled."
        ),
        remediation=(
            "Pin the validated IP address at the socket/transport layer, disable automatic "
            "HTTP redirects, and re-verify every hop against RFC1918/loopback/metadata ranges."
        ),
    ),
    SecuritySkillSpec(
        skill_id="SKILL-L30D-APP-04-PRESIGNED-URL-OVERSCOPE",
        skill_slug="cloud-presigned-url-overscope",
        detector_name="detect_overscoped_presigned_upload_url",
        domain="APP_CODE_SECURITY",
        title="Cloud Storage Presigned Upload URL Missing Content-Type / Size Pinning Detector",
        source_lane="devto_public_keyless",
        source_url="https://dev.to/t/bugbounty",
        cwe_id="CWE-732",
        severity="HIGH",
        engagement_score=86.5,
        requires_api_key=False,
        summary=(
            "Detects S3/GCS presigned upload URL generators (generate_presigned_url('put_object'), "
            "generate_presigned_post, getSignedUrl) that allow arbitrary ContentType, "
            "unbounded upload size, or user-controlled object key paths."
        ),
        detection_logic_description=(
            "Scans presigned URL generation calls for missing ContentType restrictions, "
            "missing content-length-range conditions, or raw user key concatenation."
        ),
        remediation=(
            "Enforce strict ContentType allowlists, content-length-range bounds, and "
            "server-generated UUID object keys on all presigned upload URLs."
        ),
    ),
    SecuritySkillSpec(
        skill_id="SKILL-L30D-APP-05-DB-TOCTOU-RACE-WINDOW",
        skill_slug="single-packet-db-toctou-race-window",
        detector_name="detect_db_balance_toctou_race_window",
        domain="APP_CODE_SECURITY",
        title="Single-Packet HTTP/2 Race & Database Read-Modify-Write TOCTOU Detector",
        source_lane="reddit_keyless_json",
        source_url="https://www.reddit.com/r/bugbounty/",
        cwe_id="CWE-362",
        severity="HIGH",
        engagement_score=92.0,
        requires_api_key=False,
        summary=(
            "Detects balance, quota, coupon, or vote handlers that read current state, "
            "check a threshold in application memory, and write back the updated value "
            "without row-level locking (FOR UPDATE) or atomic conditional updates."
        ),
        detection_logic_description=(
            "Identifies check-then-act patterns on balance/credits/coupon/quota variables "
            "lacking SELECT ... FOR UPDATE, with_for_update(), or atomic SQL updates."
        ),
        remediation=(
            "Use row-level locking (SELECT ... FOR UPDATE / with_for_update) or single-statement "
            "atomic conditional updates (UPDATE ... SET balance = balance - :amt WHERE balance >= :amt)."
        ),
    ),
)

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "env",
    "out",
    "artifacts",
    "work",
    "yara",
    "rules",
    "reports",
    "runs",
    "logs",
    "caldera_export",
    "caldera_plugin",
    "coverage",
    "vendor",
    ".agents",
    ".cargo",
    ".swarm_workspaces",
}

_SCAN_EXTENSIONS = {
    ".py",
    ".rs",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".sh",
    ".ps1",
}


# ==============================================================================
# Compiled Multi-Token Patterns for the 10 Zero-API Security Skills
# ==============================================================================

# 1. SKILL-L30D-AI-01: MCP Tool Rug-Pull & Shadowing
_L30D_AI01_RUGPULL_RE = re.compile(
    r"""(?:tool\.description\s*=\s*[^"\n]+|update_tool_description\s*\(|mutate_tool_schema\s*\(|allow_tool_override\s*[:=]\s*(?:True|true)|override_existing_tool\s*[:=]\s*(?:True|true))""",
    re.IGNORECASE,
)

# 2. SKILL-L30D-AI-02: Unconsented Browser Cookie Sidecar / Keychain Read
_L30D_AI02_COOKIE_SIDECAR_RE = re.compile(
    r"""(?:Chrome(?:\\+|/)User Data(?:\\+|/)Default(?:\\+|/)Network(?:\\+|/)Cookies|Firefox(?:\\+|/)Profiles(?:\\+|/)[^"']*cookies\.sqlite|Library/Cookies/Cookies\.binarycookies|Login Data["']|CryptUnprotectData\s*\(|security\s+find-generic-password\b)""",
    re.IGNORECASE,
)

# 3. SKILL-L30D-AI-03: Hermes SKILL.md / Plugin Manifest Supply-Chain Backdoor
_L30D_AI03_HERMES_BACKDOOR_RE = re.compile(
    r"""(?:curl\s+-[sSfL]+\s+https?://[^\s|]{1,300}\s*\|\s*(?:sh|bash|zsh)\b|wget\s+-qO-\s+https?://[^\s|]{1,300}\s*\|\s*(?:sh|bash)\b|Invoke-WebRequest[^|\r\n]{1,300}\|\s*(?:iex|Invoke-Expression)\b|base64\s+-d\s*\|\s*(?:sh|bash)\b)""",
    re.IGNORECASE,
)

# 4. SKILL-L30D-AI-04: RAG Vector Store Unfiltered Multi-Tenant Similarity Search
_L30D_AI04_VECTOR_QUERY_RE = re.compile(
    r"\b(?:vector_store\.similarity_search|collection\.query|qdrant_client\.query_points|index\.query)\s*\(([^)]{1,260})\)",
    re.DOTALL,
)

# 5. SKILL-L30D-AI-05: LLM Structured Output Grammar / Extra-Field Injection
_L30D_AI05_EXTRA_ALLOW_RE = re.compile(
    r"""(?:["']?extra["']?\s*[:=]\s*["']allow["']|["']?additionalProperties["']?\s*:\s*(?:true|True)|render_template_string\s*\(\s*(?:llm_output|structured_output|model_response|parsed_json))""",
)

# 6. SKILL-L30D-APP-01: SSR / React Server Action Missing Inline Authorization
_L30D_APP01_USE_SERVER_RE = re.compile(r"""["']use server["']""")
_L30D_APP01_SERVER_FN_RE = re.compile(
    r"export\s+async\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{([\s\S]{1,700}?)\}",
)
_L30D_APP01_MUTATION_SINK_RE = re.compile(
    r"\b(?:prisma|db|database|sql)\.[A-Za-z0-9_.]*\b(?:delete|update|create|execute|raw)\s*\(",
)
_L30D_APP01_AUTH_CHECK_RE = re.compile(
    r"\b(?:getServerSession|auth\s*\(|verifySession|requireAuth|currentUser|checkPermission|verifyToken)\b",
)

# 7. SKILL-L30D-APP-02: JWT Unverified Decode / JKU / KID Confusion
_L30D_APP02_JWT_FLAW_RE = re.compile(
    r"""(?:verify_signature["']?\s*[:=]\s*(?:False|false)|jwt\.decode\s*\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[[^\]]*["']none["']|requests\.get\s*\(\s*unverified_header\[["'](?:jku|x5u)["']\])""",
    re.IGNORECASE,
)

# 8. SKILL-L30D-APP-03: Webhook Two-Step DNS Resolution TOCTOU (DNS Rebinding SSRF)
_L30D_APP03_DNS_TOCTOU_RE = re.compile(
    r"socket\.(?:gethostbyname|getaddrinfo)\s*\([^)]+\)[\s\S]{1,320}?(?:requests|httpx|urllib\.request)\.(?:get|post|request|urlopen)\s*\(\s*(?:url|webhook_url|callback_url|target_url)\b",
)

# 9. SKILL-L30D-APP-04: Presigned Cloud Upload URL Missing ContentType / Size Pinning
_L30D_APP04_PRESIGNED_PUT_RE = re.compile(
    r"""generate_presigned_url\s*\(\s*["']put_object["']\s*,\s*Params\s*=\s*\{([^}]{1,260})\}""",
    re.DOTALL,
)

# 10. SKILL-L30D-APP-05: Single-Packet Race & Database Read-Modify-Write TOCTOU
_L30D_APP05_DB_TOCTOU_RE = re.compile(
    r"(?:balance|credits|quota|coupon_uses)\s*=\s*[^\n]+[\s\S]{1,220}?if\s+(?:balance|credits|quota|coupon_uses)\s*(?:>=|>|<|<=)\s*[^\n:]+:[\s\S]{1,220}?(?:balance|credits|quota|coupon_uses)\s*[-+]=\s*",
)


class Last30DaysSecuritySkillsEngine:
    """
    Zero-API-key adaptation of `mvanhorn/last30days-skill` tailored for discovering,
    clustering, scoring, and executing last-30-days AI security and application/web
    pentesting skills.
    """

    def __init__(
        self,
        skills_dir: Optional[Path] = None,
        research_num: int = 5,
        skills_num: Optional[int] = None,
    ) -> None:
        self.rfchunt_root = Path(__file__).resolve().parent.parent
        self.skills_dir = Path(
            skills_dir or (self.rfchunt_root / "engine" / "security_skills_catalog")
        )
        effective_n = skills_num if skills_num is not None else research_num
        self.research_num = max(1, int(effective_n))
        self.skills_num = self.research_num
        self._active_skills: Dict[str, SecuritySkillSpec] = {
            s.skill_id: s for s in BUILTIN_LAST30DAYS_SECURITY_SKILLS
        }
        self._load_registry()

    def _registry_path(self) -> Path:
        return self.skills_dir / "last30days_security_skills_registry.json"

    def _load_registry(self) -> None:
        reg = self._registry_path()
        if not reg.exists():
            return
        try:
            data = json.loads(reg.read_text(encoding="utf-8"))
            for item in data.get("skills", []):
                if item.get("requires_api_key", False):
                    continue
                sid = item.get("skill_id", "")
                if sid and sid not in self._active_skills:
                    self._active_skills[sid] = SecuritySkillSpec(**item)
        except Exception:
            pass

    def _save_registry(self) -> None:
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "zero_api_key_invariant_enforced": True,
            "keyless_sources_enabled": list(KEYLESS_SOURCE_LANES),
            "forbidden_paid_lanes_excluded": list(FORBIDDEN_PAID_API_LANES),
            "total_skills": len(self._active_skills),
            "skills": [asdict(s) for s in self._active_skills.values()],
        }
        self._registry_path().write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def list_active_skills(self, domain: str = "all") -> List[Dict[str, Any]]:
        dom_norm = (domain or "all").strip().upper()
        result: List[Dict[str, Any]] = []
        for s in self._active_skills.values():
            if s.requires_api_key:
                continue
            if dom_norm in ("ALL", "BOTH", "") or s.domain.upper() == dom_norm:
                result.append(asdict(s))
        return result

    # ==========================================================================
    # Keyless Last-30-Days Harvesters (Zero API Keys Required)
    # ==========================================================================

    @staticmethod
    def _fetch_json_keyless(url: str, timeout: float = 2.0) -> Optional[Any]:
        if os.environ.get("RFCHUNT_OFFLINE") == "1":
            return None
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "RFCHunt-Last30Days-ZeroAPI-SkillEngine/1.0",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            return None

    def _harvest_hackernews_keyless(self, topic: str, days: int = 30) -> List[Dict[str, Any]]:
        cutoff = int(time.time()) - (days * 86400)
        q = urllib.parse.quote_plus(topic)
        url = (
            f"https://hn.algolia.com/api/v1/search_by_date?query={q}"
            f"&tags=story&numericFilters=created_at_i>{cutoff}&hitsPerPage=10"
        )
        data = self._fetch_json_keyless(url)
        if not isinstance(data, dict):
            return []
        items: List[Dict[str, Any]] = []
        for hit in data.get("hits", []) or []:
            points = int(hit.get("points") or 0)
            comments = int(hit.get("num_comments") or 0)
            title = str(hit.get("title") or "").strip()
            if not title:
                continue
            items.append(
                {
                    "title": title,
                    "source_lane": "hackernews_algolia_keyless",
                    "source_url": hit.get("url")
                    or f"https://news.ycombinator.com/item?id={hit.get('objectID', '')}",
                    "engagement_score": min(100.0, round(45.0 + points * 0.15 + comments * 0.2, 1)),
                    "requires_api_key": False,
                }
            )
        return items

    def _harvest_reddit_keyless(self, topic: str) -> List[Dict[str, Any]]:
        q = urllib.parse.quote_plus(topic)
        url = f"https://www.reddit.com/r/netsec+bugbounty/search.json?q={q}&restrict_sr=1&sort=top&t=month&limit=10"
        data = self._fetch_json_keyless(url)
        if not isinstance(data, dict):
            return []
        children = (data.get("data") or {}).get("children") or []
        items: List[Dict[str, Any]] = []
        for child in children:
            post = child.get("data") or {}
            title = str(post.get("title") or "").strip()
            ups = int(post.get("ups") or 0)
            if not title:
                continue
            items.append(
                {
                    "title": title,
                    "source_lane": "reddit_keyless_json",
                    "source_url": f"https://www.reddit.com{post.get('permalink', '')}",
                    "engagement_score": min(100.0, round(50.0 + ups * 0.12, 1)),
                    "requires_api_key": False,
                }
            )
        return items

    def _harvest_github_keyless(self, topic: str, days: int = 30) -> List[Dict[str, Any]]:
        cutoff_date = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
        q = urllib.parse.quote_plus(f"{topic} pushed:>{cutoff_date}")
        url = f"https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page=10"
        data = self._fetch_json_keyless(url)
        if not isinstance(data, dict):
            return []
        items: List[Dict[str, Any]] = []
        for repo in data.get("items", []) or []:
            stars = int(repo.get("stargazers_count") or 0)
            full_name = str(repo.get("full_name") or "").strip()
            desc = str(repo.get("description") or "").strip()
            if not full_name:
                continue
            items.append(
                {
                    "title": f"{full_name}: {desc}"[:140],
                    "source_lane": "github_public_keyless",
                    "source_url": str(repo.get("html_url") or f"https://github.com/{full_name}"),
                    "engagement_score": min(100.0, round(55.0 + stars * 0.08, 1)),
                    "requires_api_key": False,
                }
            )
        return items

    def _harvest_devto_keyless(self, tag: str = "security") -> List[Dict[str, Any]]:
        url = f"https://dev.to/api/articles?tag={urllib.parse.quote_plus(tag)}&top=30&per_page=10"
        data = self._fetch_json_keyless(url)
        if not isinstance(data, list):
            return []
        items: List[Dict[str, Any]] = []
        for art in data:
            if not isinstance(art, dict):
                continue
            title = str(art.get("title") or "").strip()
            desc = str(art.get("description") or "").strip()
            reactions = int(art.get("public_reactions_count") or 0)
            if not title:
                continue
            items.append(
                {
                    "title": title,
                    "summary": desc or title,
                    "source_lane": "devto_public_keyless",
                    "source_url": str(art.get("url") or "https://dev.to/t/security"),
                    "engagement_score": min(100.0, round(48.0 + reactions * 0.4, 1)),
                    "requires_api_key": False,
                }
            )
        return items

    def _harvest_arxiv_keyless(self, topic: str) -> List[Dict[str, Any]]:
        """Harvests last-30-days security papers from arXiv's public keyless Atom API."""
        if os.environ.get("RFCHUNT_OFFLINE") == "1":
            return []
        q = urllib.parse.quote_plus(f"all:{topic} AND (cat:cs.CR OR cat:cs.AI)")
        url = f"http://export.arxiv.org/api/query?search_query={q}&sortBy=submittedDate&sortOrder=descending&max_results=8"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "RFCHunt-Last30Days-ZeroAPI-SkillEngine/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                xml_txt = resp.read().decode("utf-8", errors="replace")
        except Exception:
            return []
        entries = re.findall(r"<entry>([\s\S]*?)</entry>", xml_txt)
        items: List[Dict[str, Any]] = []
        for idx, ent in enumerate(entries):
            t_m = re.search(r"<title>([\s\S]*?)</title>", ent)
            s_m = re.search(r"<summary>([\s\S]*?)</summary>", ent)
            id_m = re.search(r"<id>([\s\S]*?)</id>", ent)
            title = re.sub(r"\s+", " ", t_m.group(1)).strip() if t_m else ""
            summary = re.sub(r"\s+", " ", s_m.group(1)).strip() if s_m else ""
            link = id_m.group(1).strip() if id_m else "https://arxiv.org/list/cs.CR/recent"
            if not title:
                continue
            has_repo = "github.com/" in summary.lower() or "gitlab.com/" in summary.lower()
            items.append(
                {
                    "title": title,
                    "summary": summary or title,
                    "source_lane": "arxiv_atom_keyless",
                    "source_url": link,
                    "engagement_score": min(100.0, round(68.0 + (18.0 if has_repo else 0.0) - idx * 1.5, 1)),
                    "requires_api_key": False,
                }
            )
        return items

    def _harvest_local_corpus_skillmd(
        self,
        corpus_dirs: Optional[Sequence[str | Path]] = None,
    ) -> List[Dict[str, Any]]:
        """Harvests security skills & detection patterns from local SKILL.md, plugin manifests, and corpus directories."""
        raw_env_dirs = os.environ.get("LAST30DAYS_CORPUS_DIRS", "").strip()
        dirs_to_scan: List[Path] = []
        if corpus_dirs:
            dirs_to_scan.extend(Path(p) for p in corpus_dirs if p)
        if raw_env_dirs:
            for part in raw_env_dirs.split(os.pathsep):
                if part.strip():
                    dirs_to_scan.append(Path(part.strip()))
        items: List[Dict[str, Any]] = []
        for cdir in dirs_to_scan:
            if not cdir.exists():
                continue
            files = [cdir] if cdir.is_file() else list(cdir.rglob("*.md"))[:30]
            for fp in files:
                try:
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                first_heading = next(
                    (ln.lstrip("# ").strip() for ln in txt.splitlines() if ln.strip().startswith("#")),
                    fp.stem,
                )
                items.append(
                    {
                        "title": first_heading[:140],
                        "summary": txt[:600],
                        "source_lane": "local_corpus_skillmd",
                        "source_url": fp.resolve().as_uri() if fp.is_absolute() else str(fp),
                        "engagement_score": 88.0,
                        "requires_api_key": False,
                    }
                )
        return items

    @staticmethod
    def _classify_sighting_domain(title: str, summary: str) -> str:
        combined = f"{title} {summary}".lower()
        ai_kws = (
            "llm", "agent", "mcp", "prompt injection", "jailbreak", "rag",
            "embedding", "vector", "skill.md", "claude", "ollama", "guardrail",
            "model", "copilot", "sandbox escape",
        )
        if any(k in combined for k in ai_kws):
            return "AI_SECURITY"
        return "APP_CODE_SECURITY"

    @staticmethod
    def _extract_harvested_indicators(title: str, summary: str) -> Tuple[str, str, List[str]]:
        """Extracts CWE, severity, and multi-token code/config indicators from a harvested sighting."""
        combined = f"{title} {summary}"
        low = combined.lower()
        cwe_m = re.search(r"\b(CWE-\d{1,4})\b", combined, re.IGNORECASE)
        if cwe_m:
            cwe = cwe_m.group(1).upper()
        elif "ssrf" in low or "rebind" in low:
            cwe = "CWE-918"
        elif "jwt" in low or "signature" in low:
            cwe = "CWE-347"
        elif "prompt" in low or "mcp" in low or "command" in low:
            cwe = "CWE-77"
        elif "idor" in low or "bola" in low or "auth" in low:
            cwe = "CWE-639"
        elif "race" in low or "toctou" in low:
            cwe = "CWE-362"
        else:
            cwe = "CWE-20"

        sev = "CRITICAL" if any(k in low for k in ("rce", "critical", "zero-day", "0day", "bypass", "rug-pull", "backdoor")) else "HIGH"

        indicators: List[str] = []
        # Extract inline code spans or multi-token technical identifiers (`...`)
        for m in re.finditer(r"`([^`\r\n]{4,64})`", combined):
            cand = m.group(1).strip()
            if len(cand) >= 4 and ("." in cand or "_" in cand or "(" in cand or "/" in cand or ":" in cand):
                indicators.append(cand)
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\s*\()", combined):
            indicators.append(m.group(1).strip())
        dedup_ind = list(dict.fromkeys(indicators))[:8]
        return cwe, sev, dedup_ind

    def harvest_and_cluster_sightings(
        self,
        topic: str = "AI security prompt injection bug bounty pentesting",
        days: int = 30,
        corpus_dirs: Optional[Sequence[str | Path]] = None,
        custom_sightings: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Harvests across all 6 strictly zero-API-key lanes in parallel, filters out any item
        requiring an API key, clusters sightings of the same story/technique across platforms,
        and scores clusters by community engagement + cross-platform corroboration.
        """
        raw_sightings: List[Dict[str, Any]] = []
        if custom_sightings:
            for cs in custom_sightings:
                if isinstance(cs, dict) and not cs.get("requires_api_key", False):
                    lane = str(cs.get("source_lane") or "local_corpus_skillmd")
                    if lane in KEYLESS_SOURCE_LANES and lane not in FORBIDDEN_PAID_API_LANES:
                        raw_sightings.append(dict(cs))

        if corpus_dirs or os.environ.get("LAST30DAYS_CORPUS_DIRS"):
            raw_sightings.extend(self._harvest_local_corpus_skillmd(corpus_dirs))

        if os.environ.get("RFCHUNT_OFFLINE") != "1":
            with ThreadPoolExecutor(max_workers=5) as pool:
                f_hn = pool.submit(self._harvest_hackernews_keyless, topic, days)
                f_rd = pool.submit(self._harvest_reddit_keyless, topic)
                f_gh = pool.submit(self._harvest_github_keyless, topic, days)
                f_dv = pool.submit(self._harvest_devto_keyless, "security")
                f_ax = pool.submit(self._harvest_arxiv_keyless, topic)
                for fut in (f_hn, f_rd, f_gh, f_dv, f_ax):
                    try:
                        raw_sightings.extend(fut.result())
                    except Exception:
                        pass

        # Cluster by normalized title token fingerprint
        clusters: Dict[str, Dict[str, Any]] = {}
        for item in raw_sightings:
            if item.get("requires_api_key", False):
                continue
            lane = str(item.get("source_lane") or "")
            if lane not in KEYLESS_SOURCE_LANES or lane in FORBIDDEN_PAID_API_LANES:
                continue
            title = str(item.get("title") or "").strip()
            summary = str(item.get("summary") or title).strip()
            if not title:
                continue
            words = re.findall(r"[a-z0-9]{3,}", title.lower())
            cluster_key = "-".join(words[:5]) if words else hashlib.sha256(title.encode("utf-8")).hexdigest()[:10]
            if cluster_key not in clusters:
                dom = str(item.get("domain") or self._classify_sighting_domain(title, summary))
                cwe, sev, inds = self._extract_harvested_indicators(title, summary)
                if isinstance(item.get("custom_indicators"), list):
                    inds = list(dict.fromkeys([*item["custom_indicators"], *inds]))[:8]
                clusters[cluster_key] = {
                    "cluster_key": cluster_key,
                    "title": title,
                    "summary": summary,
                    "domain": dom,
                    "source_lane": lane,
                    "source_url": str(item.get("source_url") or ""),
                    "corroborating_lanes": [lane],
                    "engagement_score": float(item.get("engagement_score") or 75.0),
                    "cwe_id": str(item.get("cwe_id") or cwe),
                    "severity": str(item.get("severity") or sev),
                    "custom_indicators": inds,
                    "requires_api_key": False,
                }
            else:
                existing = clusters[cluster_key]
                if lane not in existing["corroborating_lanes"]:
                    existing["corroborating_lanes"].append(lane)
                    existing["engagement_score"] = min(
                        100.0, round(existing["engagement_score"] + 8.0, 1)
                    )

        ranked_clusters = sorted(
            clusters.values(),
            key=lambda c: (len(c["corroborating_lanes"]), c["engagement_score"]),
            reverse=True,
        )
        return ranked_clusters

    @staticmethod
    def _synthesize_skill_detector_python(spec: SecuritySkillSpec) -> str:
        """
        Synthesizes an executable `# EVOLVE-BLOCK` Python detector module for a harvested
        or built-in security skill (using D:\\harfile\\arixiv-to-code when present).
        """
        indicators_repr = repr(tuple(spec.custom_indicators or [spec.skill_slug]))
        slug_ident = re.sub(r"[^a-zA-Z0-9_]", "_", spec.skill_slug)
        safe_title = str(spec.title or "").replace('"""', r'\"\"\"').replace("\r", " ").replace("\n", " ")[:240]
        safe_url = str(spec.source_url or "").replace('"""', r'\"\"\"').replace("\r", "").replace("\n", "")[:300]
        safe_lane = str(spec.source_lane or "").replace('"""', r'\"\"\"').replace("\r", "").replace("\n", "")[:80]
        safe_lanes = ", ".join(
            str(l).replace('"""', r'\"\"\"').replace("\r", "").replace("\n", "")
            for l in (spec.corroborating_lanes or [spec.source_lane])
        )[:240]
        return (
            f'#!/usr/bin/env python3\n'
            f'"""\n'
            f'Auto-Harvested Zero-API Last30Days Security Skill Detector: {spec.skill_id}\n'
            f'Title: {safe_title}\n'
            f'Keyless Source Lane: {safe_lane} ({safe_url})\n'
            f'Corroborating Lanes: {safe_lanes}\n'
            f'"""\n'
            f"from __future__ import annotations\n"
            f"from typing import Dict, List, Sequence, Tuple\n\n"
            f"SKILL_ID = {spec.skill_id!r}\n"
            f"SKILL_SLUG = {spec.skill_slug!r}\n"
            f"DOMAIN = {spec.domain!r}\n"
            f"CWE_ID = {spec.cwe_id!r}\n"
            f"SEVERITY = {spec.severity!r}\n"
            f"REQUIRES_API_KEY = False\n"
            f"INDICATORS: Tuple[str, ...] = {indicators_repr}\n\n"
            f"# EVOLVE-BLOCK-START\n"
            f"def {spec.detector_name}(content: str, indicators: Sequence[str] = INDICATORS) -> List[Dict[str, object]]:\n"
            f'    """Executes multi-token detection for {spec.skill_id}."""\n'
            f"    findings: List[Dict[str, object]] = []\n"
            f"    lines = content.splitlines()\n"
            f"    for line_no, line in enumerate(lines, start=1):\n"
            f"        for ind in indicators:\n"
            f"            if ind and ind in line:\n"
            f"                findings.append({{\n"
            f'                    "rule_id": SKILL_ID,\n'
            f'                    "line": line_no,\n'
            f'                    "matched_indicator": ind,\n'
            f'                    "snippet": line.strip()[:200],\n'
            f"                }})\n"
            f"    return findings\n"
            f"# EVOLVE-BLOCK-END\n"
        )

    @staticmethod
    def render_skill_markdown(spec: SecuritySkillSpec) -> str:
        """Synthesizes an Agent Skills (`agentskills.io` / Antigravity) `SKILL.md` file."""
        lanes_str = ", ".join(spec.corroborating_lanes or [spec.source_lane])
        return (
            f"---\n"
            f"name: {spec.skill_slug}\n"
            f"description: {spec.title} ({spec.skill_id}, {spec.cwe_id}, Zero-API Last30Days Security Skill)\n"
            f"---\n\n"
            f"# {spec.title}\n\n"
            f"- **Skill ID**: `{spec.skill_id}`\n"
            f"- **Domain**: `{spec.domain}`\n"
            f"- **Keyless Source Lane**: `{spec.source_lane}` (`requires_api_key: false`)\n"
            f"- **Corroborating Lanes**: `{lanes_str}`\n"
            f"- **Reference URL**: {spec.source_url}\n"
            f"- **CWE / Severity**: `{spec.cwe_id}` (`{spec.severity}`)\n"
            f"- **Community Engagement Score**: `{spec.engagement_score}/100`\n\n"
            f"## Overview\n\n"
            f"{spec.summary}\n\n"
            f"## Detection & Pentest Methodology\n\n"
            f"{spec.detection_logic_description}\n\n"
            f"## Remediation Invariant\n\n"
            f"{spec.remediation}\n"
        )

    def discover_and_build_security_skills(
        self,
        topic: str = "AI security prompt injection bug bounty pentesting",
        domain: str = "both",
        research_num: Optional[int] = None,
        skills_num: Optional[int] = None,
        days: int = 30,
        emit_skill_md: bool = True,
        output_dir: Optional[Path] = None,
        corpus_dirs: Optional[Sequence[str | Path]] = None,
        custom_sightings: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Harvests last-30-days security & hacking skills across all 6 strictly zero-API-key lanes,
        clusters cross-platform sightings, selects the top `skills_num` (`--skills-num` /
        `--reseach-num` / `--research-num`) skills per domain, and emits both `SKILL.md`
        packages and `# EVOLVE-BLOCK` Python detector modules.
        """
        raw_n = skills_num if skills_num is not None else (research_num if research_num is not None else self.skills_num)
        target_n = max(1, int(raw_n))
        base_out = Path(output_dir or self.skills_dir)
        base_out.mkdir(parents=True, exist_ok=True)

        dom_norm = (domain or "both").strip().upper()
        if dom_norm in ("BOTH", "ALL", ""):
            domains_to_run = ["AI_SECURITY", "APP_CODE_SECURITY"]
        elif "AI" in dom_norm:
            domains_to_run = ["AI_SECURITY"]
        else:
            domains_to_run = ["APP_CODE_SECURITY"]

        harvested_clusters = self.harvest_and_cluster_sightings(
            topic=topic,
            days=days,
            corpus_dirs=corpus_dirs,
            custom_sightings=custom_sightings,
        )

        from engine.structural_detector_compiler import build_structural_template_spec

        # Convert harvested clusters into SecuritySkillSpec objects with verified structural AST templates
        harvested_specs_by_domain: Dict[str, List[SecuritySkillSpec]] = {
            "AI_SECURITY": [],
            "APP_CODE_SECURITY": [],
        }
        for idx, cl in enumerate(harvested_clusters, start=1):
            c_dom = cl["domain"] if cl["domain"] in harvested_specs_by_domain else "APP_CODE_SECURITY"
            slug = re.sub(r"[^a-z0-9]+", "-", cl["cluster_key"].lower()).strip("-")[:42] or f"harvested-skill-{idx}"
            sid = f"SKILL-L30D-HARVEST-{c_dom[:3]}-{idx:02d}-{slug[:18].upper().replace('-', '_')}"
            det_name = f"detect_harvested_{slug.replace('-', '_')}"
            tpl_spec = build_structural_template_spec(
                cwe_id=cl["cwe_id"],
                title=cl["title"],
                summary=cl["summary"],
                custom_indicators=cl["custom_indicators"],
            )
            h_spec = SecuritySkillSpec(
                skill_id=sid,
                skill_slug=f"harvested-{slug}",
                detector_name=det_name,
                domain=c_dom,
                title=cl["title"],
                source_lane=cl["source_lane"],
                source_url=cl["source_url"],
                cwe_id=cl["cwe_id"],
                severity=cl["severity"],
                engagement_score=cl["engagement_score"],
                requires_api_key=False,
                summary=cl["summary"],
                detection_logic_description=(
                    f"Harvested from keyless lanes ({', '.join(cl['corroborating_lanes'])}). "
                    f"Compiled to structural AST template `{tpl_spec.template_id}` "
                    f"(self_test_passed={tpl_spec.self_test_passed}) over indicators: {cl['custom_indicators']}"
                ),
                remediation=f"Remediate {cl['cwe_id']} vulnerability pattern identified in {cl['title']}.",
                custom_indicators=list(cl["custom_indicators"]),
                corroborating_lanes=list(cl["corroborating_lanes"]),
                structural_template=tpl_spec.template_id,
                self_test_passed=tpl_spec.self_test_passed,
            )
            if tpl_spec.self_test_passed:
                harvested_specs_by_domain[c_dom].append(h_spec)

        selected_skills: List[Dict[str, Any]] = []
        for dom in domains_to_run:
            dom_builtins = [
                s
                for s in BUILTIN_LAST30DAYS_SECURITY_SKILLS
                if s.domain == dom and not s.requires_api_key
            ]
            # Combine live harvested skills + built-in zero-API catalog up to target_n per domain
            combined_pool = harvested_specs_by_domain.get(dom, []) + dom_builtins
            combined_pool.sort(key=lambda s: s.engagement_score, reverse=True)
            chosen = combined_pool[:target_n]

            for spec in chosen:
                assert spec.requires_api_key is False
                assert spec.source_lane in KEYLESS_SOURCE_LANES
                skill_dir = base_out / spec.skill_slug
                skill_md_file = skill_dir / "SKILL.md"
                py_det_file = skill_dir / f"detector_{spec.skill_slug.replace('-', '_')}.py"
                if emit_skill_md:
                    skill_dir.mkdir(parents=True, exist_ok=True)
                    skill_md_file.write_text(
                        self.render_skill_markdown(spec),
                        encoding="utf-8",
                    )
                    py_det_file.write_text(
                        self._synthesize_skill_detector_python(spec),
                        encoding="utf-8",
                    )
                updated_spec = SecuritySkillSpec(
                    **{
                        **asdict(spec),
                        "skill_md_path": str(skill_md_file) if emit_skill_md else "",
                        "synthesized_python_path": str(py_det_file) if emit_skill_md else "",
                        "corroborating_lanes": list(spec.corroborating_lanes or [spec.source_lane]),
                    }
                )
                self._active_skills[updated_spec.skill_id] = updated_spec
                selected_skills.append(asdict(updated_spec))

        self._save_registry()
        return {
            "status": "completed",
            "zero_api_key_invariant_enforced": True,
            "keyless_sources_queried": list(KEYLESS_SOURCE_LANES),
            "forbidden_paid_lanes_excluded": list(FORBIDDEN_PAID_API_LANES),
            "days_window": int(days),
            "research_num_per_domain": target_n,
            "skills_num_per_domain": target_n,
            "domains_processed": domains_to_run,
            "live_keyless_sightings_count": len(harvested_clusters),
            "harvested_clusters": harvested_clusters,
            "total_skills_extracted": len(selected_skills),
            "skills": selected_skills,
        }

    # ==========================================================================
    # Hermes-Style Agent Skill & Plugin Package Auditor (`SKILL.md` / `.claude-plugin`)
    # ==========================================================================

    def audit_agent_skill_package(self, skill_or_repo_path: str | Path) -> Dict[str, Any]:
        """
        Audits an agent skill directory or repository (`SKILL.md`, `.claude-plugin`,
        `.codex-plugin`, `.grok-plugin`, `gemini-extension.json`, scripts) for:
          1. Piped remote shell bootstrap (`curl | sh`, `iex`),
          2. Unconsented browser cookie sidecar or keychain reads (PR #1440),
          3. Unpinned MCP tool rug-pull / tool-shadowing definitions,
          4. Prompt-override / exfiltration hooks.
        Returns a Hermes-compatible install verdict (`CLEAN` or `BLOCKED_CRITICAL`).
        """
        target = Path(skill_or_repo_path).resolve()
        scan_res = self.scan_repository(target, domain="AI_SECURITY")
        crit_findings = [
            f
            for f in scan_res["findings"]
            if f["severity"] in ("CRITICAL", "HIGH")
        ]
        verdict = "CLEAN" if not crit_findings else "BLOCKED_CRITICAL"
        return {
            "status": "completed",
            "target_path": str(target),
            "install_verdict": verdict,
            "zero_api_key_required": True,
            "critical_or_high_findings_count": len(crit_findings),
            "findings": scan_res["findings"],
        }

    # ==========================================================================
    # Repository Scanner Executing All 10 Zero-API Last30Days Security Skills
    # ==========================================================================

    def _collect_files(self, repo_path: Path) -> List[Path]:
        if repo_path.is_file():
            return [repo_path]
        files_out: List[Path] = []
        _data_exts = {".json", ".yaml", ".yml", ".toml"}
        _manifest_names = {"package.json", "cargo.toml", "pyproject.toml", "tsconfig.json"}
        data_files_added = 0
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [
                d
                for d in dirs
                if d not in _SKIP_DIRS
                and not d.startswith(".")
                and "test" not in d.lower()
                and "tests" not in d.lower()
            ]
            for fname in files:
                fl = fname.lower()
                if fl.startswith("test_") or fl.endswith("_test.py") or fl.endswith(".test.ts"):
                    continue
                if fl.endswith((".min.js", ".min.css", ".bundle.js")):
                    continue
                if fl in ("last30days_security_skills.py", "arxiv_security_bridge.py"):
                    continue
                ext = Path(fname).suffix.lower()
                if ext in _SCAN_EXTENSIONS or fl == "skill.md":
                    if ext in _data_exts and fl not in _manifest_names:
                        data_files_added += 1
                        if data_files_added > 150:
                            continue
                    fpath = Path(root) / fname
                    try:
                        if fpath.stat().st_size <= 1_500_000:
                            files_out.append(fpath)
                    except OSError:
                        pass
        return files_out

    @staticmethod
    def _line_at(content: str, offset: int) -> int:
        return content.count("\n", 0, max(0, offset)) + 1

    @staticmethod
    def _enclosing_fn(content: str, line_no: int) -> str:
        lines = content.splitlines()
        start = max(0, line_no - 30)
        fn_re = re.compile(r"(?:def|fn|func|function)\s+([A-Za-z_][A-Za-z0-9_]*)")
        for idx in range(min(line_no - 1, len(lines) - 1), start - 1, -1):
            m = fn_re.search(lines[idx])
            if m:
                return m.group(1)
        return "<module>"

    def _scan_file(
        self,
        fpath: Path,
        repo_root: Path,
        enabled_domains: Sequence[str],
    ) -> List[SecuritySkillFinding]:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        try:
            rel_path = str(fpath.resolve().relative_to(repo_root.resolve())).replace("\\", "/")
        except ValueError:
            rel_path = fpath.name

        findings: List[SecuritySkillFinding] = []
        lines = content.splitlines()
        run_ai = "AI_SECURITY" in enabled_domains
        run_app = "APP_CODE_SECURITY" in enabled_domains

        def emit(skill_id: str, title: str, line_no: int, snippet: str) -> None:
            spec = self._active_skills[skill_id]
            findings.append(
                SecuritySkillFinding(
                    rule_id=spec.skill_id,
                    skill_slug=spec.skill_slug,
                    detector_name=spec.detector_name,
                    domain=spec.domain,
                    source_lane=spec.source_lane,
                    source_url=spec.source_url,
                    cwe_id=spec.cwe_id,
                    severity=spec.severity,
                    title=title,
                    file=rel_path,
                    line=line_no,
                    function_name=self._enclosing_fn(content, line_no),
                    evidence_snippet=snippet.strip()[:240],
                    remediation=spec.remediation,
                )
            )

        if run_ai:
            # 1. SKILL-L30D-AI-01: MCP Tool Rug-Pull & Shadowing
            for m in _L30D_AI01_RUGPULL_RE.finditer(content):
                lno = self._line_at(content, m.start())
                emit(
                    "SKILL-L30D-AI-01-MCP-RUGPULL-SHADOWING",
                    "Dynamic post-approval MCP tool description mutation or tool-name override (Rug-Pull / Shadowing)",
                    lno,
                    lines[lno - 1] if 1 <= lno <= len(lines) else m.group(0),
                )

            # 2. SKILL-L30D-AI-02: Unconsented Browser Cookie Sidecar / Keychain Read
            for m in _L30D_AI02_COOKIE_SIDECAR_RE.finditer(content):
                lno = self._line_at(content, m.start())
                matched_tok = m.group(0)
                window = "\n".join(lines[max(0, lno - 6) : min(len(lines), lno + 4)])
                # When matching generic OS DPAPI (`CryptUnprotectData`), require browser/cookie/profile context
                # or lack of explicit machine-store DACL documentation so standalone OS DPAPI utilities aren't misclassified.
                if "CryptUnprotectData" in matched_tok:
                    low_full = content.lower()
                    has_browser_cookie_ctx = any(
                        b_tok in low_full
                        for b_tok in (
                            "cookie", "login data", "local state", "chrome", "chromium",
                            "firefox", "safari", "brave", "edge", "browser", "keychain",
                        )
                    )
                    if not has_browser_cookie_ctx:
                        continue
                if "positive_consent" not in window and "user_consent" not in window and "require_consent" not in window:
                    emit(
                        "SKILL-L30D-AI-02-AGENT-COOKIE-SIDECAR-CONSENT",
                        f"Browser cookie sidecar or OS keychain accessed ({matched_tok}) without positive user consent check",
                        lno,
                        lines[lno - 1] if 1 <= lno <= len(lines) else matched_tok,
                    )

            # 3. SKILL-L30D-AI-03: Hermes SKILL.md / Plugin Supply-Chain Backdoor
            for m in _L30D_AI03_HERMES_BACKDOOR_RE.finditer(content):
                lno = self._line_at(content, m.start())
                emit(
                    "SKILL-L30D-AI-03-SKILLMD-HERMES-INSTALL-SCAN",
                    "Remote piped shell execution or obfuscated bootstrap command in skill/plugin package",
                    lno,
                    m.group(0),
                )

            # 4. SKILL-L30D-AI-04: RAG Vector Store Unfiltered Multi-Tenant Similarity Search
            for m in _L30D_AI04_VECTOR_QUERY_RE.finditer(content):
                args_str = m.group(1)
                if (
                    "filter" not in args_str
                    and "where" not in args_str
                    and "namespace" not in args_str
                    and "tenant" not in args_str
                ):
                    lno = self._line_at(content, m.start())
                    emit(
                        "SKILL-L30D-AI-04-RAG-VECTOR-TENANT-LEAK",
                        "Vector store similarity query omits tenant/user metadata filter (`where`/`filter`/`namespace`)",
                        lno,
                        m.group(0),
                    )

            # 5. SKILL-L30D-AI-05: LLM Structured Output Grammar / Extra-Field Injection
            for m in _L30D_AI05_EXTRA_ALLOW_RE.finditer(content):
                lno = self._line_at(content, m.start())
                emit(
                    "SKILL-L30D-AI-05-STRUCTURED-OUTPUT-GRAMMAR-INJECTION",
                    "LLM structured-output schema allows arbitrary extra fields or renders unvalidated LLM output in template sink",
                    lno,
                    m.group(0),
                )

        if run_app:
            # 6. SKILL-L30D-APP-01: SSR / React Server Action Missing Inline Authorization
            if _L30D_APP01_USE_SERVER_RE.search(content):
                for m in _L30D_APP01_SERVER_FN_RE.finditer(content):
                    fn_name = m.group(1)
                    fn_body = m.group(2)
                    if _L30D_APP01_MUTATION_SINK_RE.search(fn_body) and not _L30D_APP01_AUTH_CHECK_RE.search(fn_body):
                        lno = self._line_at(content, m.start())
                        emit(
                            "SKILL-L30D-APP-01-SSR-SERVER-ACTION-AUTH-BYPASS",
                            f"Exported Server Action `{fn_name}` executes database mutation without inline session/role verification",
                            lno,
                            fn_body.splitlines()[0] if fn_body.splitlines() else fn_name,
                        )

            # 7. SKILL-L30D-APP-02: JWT Unverified Decode / JKU / KID Confusion
            for m in _L30D_APP02_JWT_FLAW_RE.finditer(content):
                lno = self._line_at(content, m.start())
                emit(
                    "SKILL-L30D-APP-02-JWT-JKU-KID-CONFUSION",
                    "JWT signature verification disabled, `alg: none` enabled, or unpinned JKU/X5U header URL fetched",
                    lno,
                    m.group(0),
                )

            # 8. SKILL-L30D-APP-03: Webhook Two-Step DNS Resolution TOCTOU (DNS Rebinding SSRF)
            for m in _L30D_APP03_DNS_TOCTOU_RE.finditer(content):
                lno = self._line_at(content, m.start())
                emit(
                    "SKILL-L30D-APP-03-WEBHOOK-DNS-REBIND-SSRF",
                    "Two-step DNS hostname validation followed by unpinned HTTP fetch enables DNS-rebinding TOCTOU SSRF",
                    lno,
                    m.group(0),
                )

            # 9. SKILL-L30D-APP-04: Presigned Cloud Upload URL Missing ContentType / Size Pinning
            for m in _L30D_APP04_PRESIGNED_PUT_RE.finditer(content):
                params_body = m.group(1)
                if "ContentType" not in params_body:
                    lno = self._line_at(content, m.start())
                    emit(
                        "SKILL-L30D-APP-04-PRESIGNED-URL-OVERSCOPE",
                        "Presigned `put_object` upload URL generated without pinning `ContentType` constraint",
                        lno,
                        m.group(0),
                    )

            # 10. SKILL-L30D-APP-05: Single-Packet Race & Database Read-Modify-Write TOCTOU
            for m in _L30D_APP05_DB_TOCTOU_RE.finditer(content):
                lno = self._line_at(content, m.start())
                window = "\n".join(lines[max(0, lno - 4) : min(len(lines), lno + 8)])
                if "for_update" not in window.lower() and "for update" not in window.lower() and "atomic" not in window.lower():
                    emit(
                        "SKILL-L30D-APP-05-DB-TOCTOU-RACE-WINDOW",
                        "Non-atomic balance/quota read-modify-write check-then-act window vulnerable to single-packet HTTP/2 race",
                        lno,
                        m.group(0),
                    )

        # 11. Dynamically Harvested Zero-API Skills (Compiled Structural AST/Dataflow Templates)
        dyn_skills = [
            s
            for s in self._active_skills.values()
            if s.custom_indicators and s.domain in enabled_domains and s.self_test_passed
        ]
        if dyn_skills:
            from engine.structural_detector_compiler import (
                build_structural_template_spec,
                execute_structural_template,
                strip_comments_preserve_lines,
            )

            ext = fpath.suffix.lower()
            clean_code = strip_comments_preserve_lines(content, ext)
            for dyn_spec in dyn_skills:
                tpl_spec = build_structural_template_spec(
                    cwe_id=dyn_spec.cwe_id,
                    title=dyn_spec.title,
                    summary=dyn_spec.summary,
                    custom_indicators=dyn_spec.custom_indicators,
                )
                if not tpl_spec.self_test_passed:
                    continue
                struct_matches = execute_structural_template(content, ext, tpl_spec)
                if struct_matches:
                    sm = struct_matches[0]
                    emit(
                        dyn_spec.skill_id,
                        f"Harvested Zero-API Structural Skill Match [{tpl_spec.template_id}]: {dyn_spec.title}",
                        sm.line,
                        sm.evidence_snippet,
                    )
                else:
                    # Comment-stripped structural fallback for custom indicator sinks without guard
                    has_guard = any(
                        re.search(gp, clean_code, re.IGNORECASE) for gp in tpl_spec.guard_patterns
                    )
                    if not has_guard:
                        for ind in dyn_spec.custom_indicators:
                            if ind and ind in clean_code:
                                pos = clean_code.find(ind)
                                lno = self._line_at(clean_code, pos)
                                line_txt = lines[lno - 1] if 1 <= lno <= len(lines) else ind
                                emit(
                                    dyn_spec.skill_id,
                                    f"Harvested Zero-API Security Skill Match (`{ind}`): {dyn_spec.title}",
                                    lno,
                                    line_txt,
                                )
                                break

        return findings

    def scan_repository(
        self,
        repo_path: str | Path,
        domain: str = "both",
        sync_online: bool = False,
        topic: str = "",
        research_num: Optional[int] = None,
        skills_num: Optional[int] = None,
        corpus_dirs: Optional[Sequence[str | Path]] = None,
    ) -> Dict[str, Any]:
        """
        Executes all active zero-API Last30Days security skill detectors across `repo_path`.
        """
        start_ts = time.perf_counter()
        target = Path(repo_path).resolve()
        raw_n = skills_num if skills_num is not None else (research_num if research_num is not None else self.skills_num)
        target_n = max(1, int(raw_n))

        discovery_report: Optional[Dict[str, Any]] = None
        if sync_online or topic.strip() or corpus_dirs:
            discovery_report = self.discover_and_build_security_skills(
                topic=topic or "AI security prompt injection bug bounty pentesting",
                domain=domain,
                research_num=target_n,
                skills_num=target_n,
                days=30,
                emit_skill_md=True,
                corpus_dirs=corpus_dirs,
            )

        dom_norm = (domain or "both").strip().upper()
        if dom_norm in ("BOTH", "ALL", ""):
            enabled_domains = ("AI_SECURITY", "APP_CODE_SECURITY")
        elif "AI" in dom_norm:
            enabled_domains = ("AI_SECURITY",)
        else:
            enabled_domains = ("APP_CODE_SECURITY",)

        files = self._collect_files(target)
        findings: List[SecuritySkillFinding] = []
        if files:
            max_workers = min(16, max(4, (os.cpu_count() or 4) * 2))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futs = [pool.submit(self._scan_file, f, target, enabled_domains) for f in files]
                for fut in futs:
                    findings.extend(fut.result())

        by_rule: Dict[str, int] = {}
        by_domain: Dict[str, int] = {"AI_SECURITY": 0, "APP_CODE_SECURITY": 0}
        for f in findings:
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
            by_domain[f.domain] = by_domain.get(f.domain, 0) + 1

        return {
            "status": "completed",
            "zero_api_key_invariant_enforced": True,
            "repo_path": str(target),
            "files_scanned": len(files),
            "elapsed_seconds": round(time.perf_counter() - start_ts, 4),
            "research_num": target_n,
            "skills_num": target_n,
            "active_skills_count": len(self.list_active_skills(domain=domain)),
            "total_findings": len(findings),
            "findings_by_domain": by_domain,
            "findings_by_rule": by_rule,
            "findings": [f.to_dict() for f in findings],
            "discovery_report": discovery_report,
        }
