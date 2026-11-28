#!/usr/bin/env python3
"""
engine/preflight_discovery.py
================================================================================
Module 23: Fresh Pre-Flight Stack, Post-Quantum (PQC), HackerOne-Category,
           Keyless Live Research & Safe Local Skill Discovery Engine

Executes at the start of every RFCHunt run (`--all`, `--deep-audit`,
`--hackerone-auto`, `--preflight-only`, and `--dry-run`) WITHOUT reusing cached
outputs from prior sessions (`cache_reused: false` invariant):

  1. Workspace & Prompt Stack Inspector (`WorkspaceStackInspector`):
     - Parses user prompt / scope hints, manifest files (`Cargo.toml`,
       `pyproject.toml`, `requirements*.txt`, `package.json`, `go.mod`,
       `pom.xml`, `build.gradle*`, `Gemfile`, `composer.json`, `Package.swift`,
       `pubspec.yaml`, `*.csproj`, `Dockerfile`, Terraform/K8s/CI YAML,
       `foundry.toml`, `hardhat.config.*`), schema definitions (`.proto`,
       `.graphql`, `.avsc`, OpenAPI/Swagger, AsyncAPI, MCP/A2A manifests,
       `.sol`/`.vy`/`.move`, `.wat`/`.wasm`, eBPF), and file extensions.
     - Extracts exact workspace dependency versions and compiler/runtime metadata.
  2. 14-Category Domain, Protocol, Post-Quantum & HackerOne Taxonomy Classifier:
     - Covers all 12 core engineering domains + dedicated Post-Quantum
       Cryptography (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA,
       FN-DSA/Falcon, HQC, XMSS/LMS, Hybrid TLS/SSH/HPKE/COSE, HNDL legacy
       crypto inventory) + Web3/Smart Contracts & full HackerOne Asset/Weakness
       taxonomy across every detected programming language.
  3. Conditional Fresh Live Keyless Research Engine (`FreshLiveResearchRunner`):
     - Queries OSV.dev exact-version CVE batch API, IETF Datatracker RFC/draft
       API, arXiv Atom API, Hacker News Algolia, GitHub public search, and
       dev.to with `Cache-Control: no-cache, no-store` anchored to the current
       year and exact workspace library versions (zero API keys required;
       automatically suppressed with 0 sockets under `--offline`, `CI`, or
       `--dry-run`).
  4. Post-Quantum Cryptography Static Auditor (`PostQuantumPreflightAuditor`):
     - Detects active PQC implementation flaws (`PQC-01`..`PQC-05`: KyberSlash
       timing hazard, XMSS/LMS stateful index reuse, hybrid downgrade, weak
       seed/missing domain `ctx`, unmetered PQC deserialization) and quantum-
       vulnerable HNDL classical-only crypto inventory (`PQC-06`).
  5. Local Skill Directory & Registry Scanner + Fail-Closed Safety Gate
     (`LocalSkillDiscoveryAndSafetyGate`):
     - Scans workspace and user skill paths (`.claude/skills`, `~/.claude/skills`,
       `~/.gemini/config/plugins/*/skills`, `~/.gemini/antigravity/builtin/skills`,
       `.agents/skills`, `.cursor/skills`, RFCHunt registries), inspects every
       candidate skill for safety (piped shell backdoors, Unicode tags/BiDi,
       prompt-injection overrides, persistent PATH/env mutation, unconsented
       cookie/keychain exfiltration), quarantines unsafe skills, and loads all
       matching safe skills into context.
  6. Pre-Flight Checklist Synthesizer & Adaptive `--all` Steering Plan:
     - Emits `preflight_checklist.json` and `preflight_checklist.md` and feeds
       tailored queries, HackerOne categories, PQC focus, nuclei tags, and
       active skills directly into `--all`.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

try:
    import tomllib  # Python 3.11+ stdlib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


# ==============================================================================
# Constants & Memory-Disciplined Bounds
# ==============================================================================

MAX_MANIFEST_BYTES = 262_144  # 256 KiB per manifest/schema file
MAX_SOURCE_SCAN_BYTES = 196_608  # 192 KiB per source file during static PQC scan
MAX_SOURCE_FILES_SCANNED = 4_000
MAX_SKILL_FILE_BYTES = 262_144
MAX_HTTP_RESPONSE_BYTES = 262_144
MAX_OSV_BATCH_QUERIES = 80

_SKIP_DIRS: Set[str] = {
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
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "out",
    "artifacts",
    "work",
    "reports",
    "runs",
    "logs",
    "coverage",
    "vendor",
    ".next",
    ".nuxt",
    ".turbo",
    ".gradle",
    "Pods",
}

_SOURCE_CODE_EXTS: Set[str] = {
    ".py",
    ".rs",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".java",
    ".kt",
    ".kts",
    ".swift",
    ".rb",
    ".php",
    ".cs",
    ".dart",
    ".sol",
    ".vy",
    ".move",
    ".cairo",
    ".zig",
    ".ex",
    ".exs",
    ".sh",
    ".bash",
    ".ps1",
    ".wat",
    ".yaml",
    ".yml",
    ".toml",
    ".tf",
    ".hcl",
}

_EXT_TO_LANGUAGE: Dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".rs": "Rust",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".go": "Go",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".dart": "Dart",
    ".sol": "Solidity",
    ".vy": "Vyper",
    ".move": "Move",
    ".cairo": "Cairo",
    ".zig": "Zig",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".wat": "WebAssembly",
    ".wasm": "WebAssembly",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".sql": "SQL",
    ".tf": "Terraform/HCL",
    ".hcl": "Terraform/HCL",
    ".liquid": "Liquid",
}

_LANGUAGE_SECURITY_NOTES: Dict[str, Dict[str, Any]] = {
    "Rust": {
        "focus": "unsafe blocks, FFI alignment/uninitialized padding UB (CWE-908/758), panic-safety, integer overflow, async lock/cancellation safety",
        "linters": ["clippy", "cargo-audit", "cargo-deny", "miri"],
        "osv_ecosystem": "crates.io",
    },
    "Python": {
        "focus": "deserialization (pickle/yaml), SSRF, SQL/command injection, JWT/OAuth validation, PyJWT required claims, async concurrency, type safety",
        "linters": ["ruff", "mypy --strict", "bandit", "pip-audit"],
        "osv_ecosystem": "PyPI",
    },
    "TypeScript": {
        "focus": "prototype pollution, URL/query param differential, SSRF, XSS/CSP, Server Action authz, strict compiler checks, dependency supply chain",
        "linters": ["eslint", "tsc --noEmit", "biome", "npm audit"],
        "osv_ecosystem": "npm",
    },
    "JavaScript": {
        "focus": "prototype pollution, XSS/DOM sinks, auth/HMAC differential, ReDoS, Electron/Node child_process injection",
        "linters": ["eslint", "biome", "npm audit"],
        "osv_ecosystem": "npm",
    },
    "Go": {
        "focus": "race conditions, HTTP/2 & reverse-proxy desync, path traversal, shell escaping, crypto constant-time comparisons, nil/bounds panics",
        "linters": ["golangci-lint", "govulncheck", "go vet"],
        "osv_ecosystem": "Go",
    },
    "C": {
        "focus": "buffer overflows, use-after-free, integer wraparound, format strings, uninitialized memory disclosure, constant-time crypto",
        "linters": ["clang-tidy", "cppcheck", "ASan/UBSan"],
        "osv_ecosystem": "",
    },
    "C++": {
        "focus": "memory safety, lifetime/iterator invalidation, integer overflow, FFI/JNI boundaries, constant-time crypto",
        "linters": ["clang-tidy", "cppcheck", "ASan/UBSan"],
        "osv_ecosystem": "",
    },
    "Java": {
        "focus": "deserialization gadgets, XXE, SSRF, Spring auth bypass, JNDI/EL injection, WebView/Android intents",
        "linters": ["spotbugs", "semgrep", "dependency-check"],
        "osv_ecosystem": "Maven",
    },
    "Kotlin": {
        "focus": "Android WebView @JavascriptInterface origin isolation, deep-link/Intent hijacking, coroutine cancellation, serialization",
        "linters": ["detekt", "ktlint", "Android Lint"],
        "osv_ecosystem": "Maven",
    },
    "Swift": {
        "focus": "WKWebView bridge/origin checks, URL scheme/Universal Link validation, Keychain accessibility, memory safety in UnsafePointer",
        "linters": ["swiftlint"],
        "osv_ecosystem": "SwiftURL",
    },
    "Ruby": {
        "focus": "Rack/Rails parameter/UTF-8 smuggling, mass assignment, SSTI/Liquid sandbox escapes, YAML/Marshal deserialization, command injection",
        "linters": ["rubocop", "brakeman", "bundler-audit"],
        "osv_ecosystem": "RubyGems",
    },
    "PHP": {
        "focus": "type juggling, HMAC/OAuth verification, unserialize/phar gadget chains, SSRF, SQLi, path traversal",
        "linters": ["phpstan", "psalm", "composer audit"],
        "osv_ecosystem": "Packagist",
    },
    "Solidity": {
        "focus": "reentrancy, access control, oracle manipulation, flash-loan invariants, unchecked arithmetic, signature replay",
        "linters": ["slither", "foundry-fuzz", "echidna"],
        "osv_ecosystem": "",
    },
    "WebAssembly": {
        "focus": "WASI sandbox boundaries, linear memory bounds, host fuel/epoch metering, determinism invariants",
        "linters": ["wasm-validate", "wasm-tools"],
        "osv_ecosystem": "",
    },
    "Terraform/HCL": {
        "focus": "IAM least privilege, public storage/network exposure, IMDSv2 enforcement, unencrypted secrets/state",
        "linters": ["tfsec", "checkov", "tflint"],
        "osv_ecosystem": "",
    },
    "Shell": {
        "focus": "word splitting, command injection, unquoted eval/glob expansion, PATH/environment hygiene",
        "linters": ["shellcheck"],
        "osv_ecosystem": "",
    },
}


# ==============================================================================
# 14-Category Domain, Protocol, Post-Quantum & HackerOne Taxonomy Registry
# ==============================================================================

PREFLIGHT_TAXONOMY: Dict[str, Dict[str, Any]] = {
    "web_frontend": {
        "label": "Web & Frontend (SPAs, SSR/SSG, Browser UI)",
        "packages": {
            "react", "react-dom", "next", "vue", "nuxt", "svelte", "@sveltejs/kit",
            "tailwindcss", "astro", "remix", "@remix-run/node", "@remix-run/react",
            "react-router", "@shopify/hydrogen", "vite", "webpack", "angular",
            "@angular/core", "solid-js", "htmx.org", "preact", "lit",
        },
        "extensions": {".html", ".htm", ".css", ".scss", ".jsx", ".tsx", ".vue", ".svelte", ".astro", ".liquid"},
        "filenames": {"next.config.js", "next.config.mjs", "next.config.ts", "tailwind.config.js", "tailwind.config.ts", "vite.config.ts", "vite.config.js", "svelte.config.js"},
        "keywords": [
            "website", "webapp", "web app", "frontend", "spa", "ssr", "ssg", "html", "css",
            "react", "next.js", "nextjs", "vue", "svelte", "tailwind", "hydrogen", "browser ui",
            "xss", "csrf", "csp", "clickjacking", "dom", "cors", "server action",
        ],
        "rfcs_and_specs": [
            "RFC 9110 (HTTP Semantics)",
            "RFC 6265bis (HTTP State Management / Cookies)",
            "W3C CSP Level 3 & Fetch Metadata",
            "WHATWG HTML / URL Living Standards",
        ],
        "ietf_docs": ["rfc9110", "draft-ietf-httpbis-rfc6265bis"],
        "hackerone_asset_types": ["URL", "WILDCARD", "OTHER"],
        "hackerone_cwes": ["CWE-79", "CWE-352", "CWE-601", "CWE-918", "CWE-862", "CWE-345"],
        "nuclei_tags": ["xss", "csrf", "cors", "ssrf", "misconfig", "exposure"],
        "rfchunt_modules": ["Mantis", "RAPTOR", "Last30DaysSecuritySkills", "VerificationInversionHunter"],
        "live_query": "web frontend SSR CSP XSS CSRF server action security",
    },
    "mcp_agent_interop": {
        "label": "MCP & Agent Interoperability Protocols (MCP, A2A, ACP, JSON-RPC 2.0)",
        "packages": {
            "mcp", "fastmcp", "@modelcontextprotocol/sdk", "modelcontextprotocol",
            "a2a-sdk", "@a2a-js/sdk", "acp-sdk", "jsonrpsee", "jsonrpsee-server",
            "jsonrpcserver", "jayson",
        },
        "extensions": set(),
        "filenames": {"mcp.json", "mcp_server.py", "agent-card.json", "agent.json", "server.json"},
        "keywords": [
            "mcp", "model context protocol", "stdio transport", "streamable http", "a2a",
            "agent-to-agent", "agent communication protocol", "acp", "json-rpc", "jsonrpc",
            "tool schema", "tool shadowing", "rug-pull", "mcp server",
        ],
        "rfcs_and_specs": [
            "Model Context Protocol (MCP) 2025/2026 Specification (stdio / Streamable HTTP / OAuth)",
            "JSON-RPC 2.0 Specification",
            "Agent2Agent (A2A) Protocol Specification",
            "Agent Communication Protocol (ACP)",
        ],
        "ietf_docs": ["rfc8259"],
        "hackerone_asset_types": ["API", "AI_MODEL", "SOURCE_CODE"],
        "hackerone_cwes": ["CWE-494", "CWE-284", "CWE-20", "CWE-74", "CWE-863"],
        "nuclei_tags": ["api", "exposure", "misconfig"],
        "rfchunt_modules": ["aiscan", "Last30DaysSecuritySkills", "ArxivSecurityBridge", "PromptSmuggling", "Mantis"],
        "live_query": "Model Context Protocol MCP A2A JSON-RPC tool shadowing security",
    },
    "apis_service_contracts": {
        "label": "APIs & Service Contracts (REST, GraphQL, gRPC, WebSockets, SSE, OpenAPI, Webhooks)",
        "packages": {
            "fastapi", "flask", "django", "djangorestframework", "starlette", "aiohttp",
            "express", "fastify", "koa", "@nestjs/core", "hono", "trpc", "@trpc/server",
            "graphql", "apollo-server", "@apollo/server", "strawberry-graphql", "graphene",
            "async-graphql", "tonic", "prost", "grpcio", "google.golang.org/grpc",
            "@grpc/grpc-js", "websockets", "ws", "socket.io", "axum", "actix-web",
            "gin", "github.com/gin-gonic/gin", "github.com/labstack/echo", "spring-boot-starter-web",
            "openapi-core", "swagger-ui-express", "@shopify/shopify-api", "shopifyapp",
        },
        "extensions": {".proto", ".graphql", ".gql", ".avsc"},
        "filenames": {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.json", "asyncapi.yaml", "asyncapi.json"},
        "keywords": [
            "rest", "api", "graphql", "grpc", "protobuf", "websocket", "websockets",
            "server-sent events", "sse", "openapi", "swagger", "asyncapi", "webhook",
            "api gateway", "bola", "idor", "bfla", "rate limit",
        ],
        "rfcs_and_specs": [
            "RFC 9110 (HTTP Semantics)",
            "RFC 6455 (WebSocket Protocol)",
            "OpenAPI 3.1 / AsyncAPI 3.0 Specifications",
            "GraphQL Specification & OWASP API Security Top 10",
            "gRPC over HTTP/2 Protocol",
        ],
        "ietf_docs": ["rfc9110", "rfc6455"],
        "hackerone_asset_types": ["API", "URL", "SOURCE_CODE"],
        "hackerone_cwes": ["CWE-639", "CWE-862", "CWE-345", "CWE-915", "CWE-285", "CWE-400"],
        "nuclei_tags": ["api", "graphql", "swagger", "exposure", "auth-bypass"],
        "rfchunt_modules": ["Mantis", "RAPTOR", "VerificationInversionHunter", "ArxivSecurityBridge", "PhiScanner"],
        "live_query": "REST GraphQL gRPC WebSocket OpenAPI webhook BOLA auth bypass security",
    },
    "network_transport_messaging": {
        "label": "Network, Transport & Messaging Protocols (HTTP/1.1, HTTP/2, HTTP/3/QUIC, TLS 1.3, DNS, MQTT, Kafka, NATS, libp2p)",
        "packages": {
            "h2", "hyper", "h3", "quinn", "rustls", "openssl", "aioquic", "httpx", "urllib3",
            "undici", "libp2p", "rust-libp2p", "paho-mqtt", "rumqttc", "kafka-python",
            "confluent-kafka", "rdkafka", "nats-py", "async-nats", "pika", "lapin",
            "aiortc", "webrtc", "dnspython", "hickory-dns", "trust-dns", "envoy", "nginx",
        },
        "extensions": {".pcap", ".pcapng"},
        "filenames": {"nginx.conf", "envoy.yaml", "haproxy.cfg"},
        "keywords": [
            "http/1.1", "http/2", "http2", "http/3", "http3", "quic", "tcp", "udp",
            "tls 1.3", "mtls", "dns", "mqtt", "amqp", "rabbitmq", "kafka", "nats",
            "libp2p", "gossipsub", "webrtc", "request smuggling", "desync", "proxy",
        ],
        "rfcs_and_specs": [
            "RFC 9112 (HTTP/1.1)",
            "RFC 9113 (HTTP/2)",
            "RFC 9114 (HTTP/3) & RFC 9000 (QUIC)",
            "RFC 8446 (TLS 1.3)",
            "RFC 9458 / RFC 9298 (MASQUE / Proxy)",
        ],
        "ietf_docs": ["rfc9112", "rfc9113", "rfc9114", "rfc8446"],
        "hackerone_asset_types": ["IP_ADDRESS", "CIDR", "WILDCARD", "OTHER"],
        "hackerone_cwes": ["CWE-444", "CWE-436", "CWE-295", "CWE-400", "CWE-20"],
        "nuclei_tags": ["network", "ssl", "dns", "http2", "smuggling", "proxy"],
        "rfchunt_modules": ["H2Desync", "ActiveFlawProber", "ProtocolRuler", "DifferentialOracle", "PromptSmuggling", "RAPTOR"],
        "live_query": "HTTP/2 HTTP/3 QUIC TLS 1.3 libp2p request smuggling desync security",
    },
    "identity_auth_crypto": {
        "label": "Identity, Auth & Cryptographic Protocols (OAuth 2.0/2.1, OIDC, SAML, JWT/JOSE/COSE, WebAuthn, SPIFFE/SPIRE)",
        "packages": {
            "pyjwt", "python-jose", "authlib", "jwcrypto", "jsonwebtoken", "jose", "passport",
            "next-auth", "@auth/core", "oauthlib", "simplewebauthn", "@simplewebauthn/server",
            "webauthn", "python3-saml", "samlify", "pyspiffe", "spiffe", "cryptography",
            "pynacl", "ring", "ed25519-dalek", "k256", "p256", "hmac", "sha2", "bcrypt",
            "argon2-cffi", "golang.org/x/crypto", "golang.org/x/oauth2", "cose", "coset",
            "aws-nitro-enclaves-nsm-api", "ejson", "ejson2env",
        },
        "extensions": {".pem", ".crt", ".cer", ".jwk", ".jwks", ".ejson"},
        "filenames": {"jwks.json", "oidc.json"},
        "keywords": [
            "oauth", "oauth2", "oauth 2.1", "oidc", "openid", "saml", "jwt", "jws", "jwe",
            "jose", "cose", "webauthn", "passkey", "passkeys", "fido2", "spiffe", "spire",
            "hmac", "kms", "hsm", "nitro enclave", "attestation", "crypto", "cryptography",
            "session token", "sso", "rbac", "mfa", "totp",
        ],
        "rfcs_and_specs": [
            "RFC 6749 / RFC 9700 (OAuth 2.0 Security Best Current Practice) & OAuth 2.1 Draft",
            "RFC 7519 / RFC 8725 (JWT Best Current Practices)",
            "RFC 9052 / RFC 9053 (COSE)",
            "W3C WebAuthn Level 3 & SPIFFE/SPIRE Identity Specs",
        ],
        "ietf_docs": ["rfc9700", "rfc8725", "rfc9052", "draft-ietf-oauth-v2-1"],
        "hackerone_asset_types": ["API", "URL", "SOURCE_CODE"],
        "hackerone_cwes": ["CWE-287", "CWE-347", "CWE-345", "CWE-352", "CWE-327", "CWE-384"],
        "nuclei_tags": ["oauth", "jwt", "saml", "auth-bypass", "token"],
        "rfchunt_modules": ["Mantis", "RAPTOR", "VerificationInversionHunter", "ArxivSecurityBridge"],
        "live_query": "OAuth 2.1 OIDC SAML JWT JOSE COSE WebAuthn SPIFFE bypass vulnerability",
    },
    "post_quantum_crypto": {
        "label": "Post-Quantum Cryptography (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, FN-DSA, HQC, XMSS/LMS, Hybrid TLS/SSH & HNDL)",
        "packages": {
            "ml-kem", "ml-dsa", "slh-dsa", "fips203", "fips204", "fips205", "x-wing",
            "pqcrypto", "pqcrypto-kyber", "pqcrypto-dilithium", "pqcrypto-falcon",
            "pqcrypto-sphincsplus", "pqcrypto-mlkem", "pqcrypto-mldsa", "pqcrypto-hqc",
            "rustls-post-quantum", "oqs", "liboqs", "liboqs-python", "kyber-py",
            "dilithium-py", "@noble/post-quantum", "mlkem", "crystals-kyber",
            "crystals-dilithium", "liboqs-js", "github.com/cloudflare/circl",
            "github.com/open-quantum-safe/liboqs-go", "bcprov-jdk18on", "aws-lc-rs",
            "aws-lc-sys", "boring", "openssl-sys", "cryptography", "ring",
        },
        "extensions": set(),
        "filenames": set(),
        "keywords": [
            "post quantum", "post-quantum", "pqc", "quantum", "ml-kem", "mlkem", "kyber",
            "fips 203", "fips203", "ml-dsa", "mldsa", "dilithium", "fips 204", "fips204",
            "slh-dsa", "slhdsa", "sphincs", "fips 205", "fips205", "fn-dsa", "falcon",
            "fips 206", "hqc", "xmss", "lms", "x25519mlkem768", "secp256r1mlkem768",
            "liboqs", "circl", "kyberslash", "pqxdh", "cnsa 2.0", "hndl",
            "harvest now decrypt later", "quantum-safe", "hybrid kem", "x-wing",
        ],
        "rfcs_and_specs": [
            "NIST FIPS 203 (ML-KEM / Module-Lattice-Based Key-Encapsulation Mechanism)",
            "NIST FIPS 204 (ML-DSA / Module-Lattice-Based Digital Signature Algorithm)",
            "NIST FIPS 205 (SLH-DSA / Stateless Hash-Based Digital Signature Algorithm)",
            "NIST IR 8547 (Transition to Post-Quantum Cryptography Standards) & CNSA 2.0",
            "RFC 8391 (XMSS) & RFC 8554 (LMS Stateful Hash-Based Signatures)",
            "IETF draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768) & draft-ietf-tls-hybrid-design",
            "IETF draft-ietf-cose-dilithium / draft-ietf-hpke-pq (X-Wing Hybrid KEM)",
        ],
        "ietf_docs": ["rfc8391", "rfc8554", "draft-ietf-tls-ecdhe-mlkem", "draft-ietf-tls-hybrid-design", "draft-ietf-cose-dilithium"],
        "hackerone_asset_types": ["SOURCE_CODE", "API", "URL", "DOWNLOADABLE_EXECUTABLES"],
        "hackerone_cwes": ["CWE-327", "CWE-326", "CWE-208", "CWE-323", "CWE-330", "CWE-347", "CWE-757", "CWE-770"],
        "nuclei_tags": ["ssl", "tls", "crypto", "pqc"],
        "rfchunt_modules": ["PostQuantumPreflightAuditor", "RAPTOR", "VerificationInversionHunter", "Mantis"],
        "live_query": "post-quantum ML-KEM FIPS 203 ML-DSA FIPS 204 SLH-DSA hybrid TLS KyberSlash vulnerability",
    },
    "llm_agents_ai_safety": {
        "label": "LLM, Agents & AI Safety (Orchestration, Tool Calling, Inference, Guardrails, Sandboxing)",
        "packages": {
            "openai", "anthropic", "google-genai", "google-generativeai", "langchain",
            "langchain-core", "langgraph", "llamaindex", "llama-index", "crewai", "autogen",
            "pydantic-ai", "litellm", "ollama", "vllm", "transformers", "accelerate",
            "ai", "@ai-sdk/openai", "@anthropic-ai/sdk", "instructor", "dspy", "smolagents",
            "nemo-guardrails", "guardrails-ai", "gliner", "presidio-analyzer",
        },
        "extensions": set(),
        "filenames": {"prompts.yaml", "system_prompt.md", "Modelfile"},
        "keywords": [
            "llm", "agent", "agents", "ai safety", "prompt injection", "indirect prompt injection",
            "jailbreak", "guardrail", "guardrails", "tool calling", "function calling",
            "structured output", "structured outputs", "inference", "ollama", "vllm",
            "sidekick", "orchestration", "agentic", "sandbox", "mcp",
        ],
        "rfcs_and_specs": [
            "OWASP Top 10 for LLM Applications & Agentic AI (2025/2026)",
            "NIST AI Risk Management Framework (AI RMF) & Generative AI Profile",
            "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)",
        ],
        "ietf_docs": [],
        "hackerone_asset_types": ["AI_MODEL", "API", "SOURCE_CODE", "OTHER"],
        "hackerone_cwes": ["CWE-77", "CWE-74", "CWE-250", "CWE-269", "CWE-863", "CWE-359"],
        "nuclei_tags": ["ai", "llm", "prompt-injection", "exposure"],
        "rfchunt_modules": ["aiscan", "PromptSmuggling", "ArxivSecurityBridge", "Last30DaysSecuritySkills", "PhiScanner", "ARTEX"],
        "live_query": "LLM agent prompt injection tool hijack guardrail sandbox escape security",
    },
    "rag_knowledge_systems": {
        "label": "RAG & Knowledge Systems (Embeddings, Vector/Hybrid Search, Chunking, Rerankers, GraphRAG, OCR, Retrieval ACLs)",
        "packages": {
            "chromadb", "qdrant-client", "pinecone", "pinecone-client", "pymilvus", "pgvector",
            "lancedb", "faiss-cpu", "faiss-gpu", "weaviate-client", "tantivy", "rank-bm25",
            "sentence-transformers", "pypdf", "pymupdf", "pdfplumber", "python-docx",
            "pytesseract", "unstructured", "neo4j", "networkx", "graphrag",
        },
        "extensions": set(),
        "filenames": set(),
        "keywords": [
            "rag", "retrieval", "embedding", "embeddings", "vector search", "hybrid search",
            "chunking", "reranker", "rerankers", "graphrag", "ocr", "document ingestion",
            "retrieval acl", "vector store", "qdrant", "chroma", "pinecone", "milvus",
            "pgvector", "lancedb", "faiss", "tantivy",
        ],
        "rfcs_and_specs": [
            "OWASP LLM08 (Vector and Embedding Weaknesses) & Multi-Tenant Retrieval ACLs",
            "HIPAA Safe Harbor / PII Redaction for RAG Ingestion Pipelines",
        ],
        "ietf_docs": [],
        "hackerone_asset_types": ["AI_MODEL", "API", "SOURCE_CODE"],
        "hackerone_cwes": ["CWE-284", "CWE-200", "CWE-359", "CWE-918", "CWE-74"],
        "nuclei_tags": ["api", "exposure", "misconfig"],
        "rfchunt_modules": ["Last30DaysSecuritySkills", "aiscan", "PhiScanner", "ArxivSecurityBridge", "Mantis"],
        "live_query": "RAG vector database multi-tenant ACL bypass poisoning OCR prompt injection",
    },
    "systems_kernel_security": {
        "label": "Systems, Kernel & Security Engineering (OS Internals, Drivers, eBPF, EDR/Telemetry, Binary Analysis, Fuzzing, Sandboxing, Wasm)",
        "packages": {
            "wasmtime", "wasmtime-wasi", "wasmer", "deterministic-wasi-ctx", "aya", "libbpf-rs",
            "bcc", "capstone", "keystone-engine", "unicorn", "lief", "pefile", "yara-python",
            "libafl", "afl", "cargo-fuzz", "seccompiler", "nix", "libc", "windows-sys",
            "windows", "winapi", "goblin", "object", "frida",
        },
        "extensions": {".c", ".cc", ".cpp", ".h", ".hpp", ".s", ".asm", ".wat", ".wasm", ".sys", ".ko"},
        "filenames": {"CMakeLists.txt", "Makefile", "meson.build", "Kbuild"},
        "keywords": [
            "kernel", "driver", "drivers", "ebpf", "edr", "telemetry", "binary analysis",
            "fuzzing", "fuzzer", "sandbox", "sandboxing", "wasm", "wasi", "wasmtime",
            "appcontainer", "seccomp", "cgroups", "namespace", "memory corruption",
            "use-after-free", "unsafe rust", "ffi", "win32", "ioctl",
        ],
        "rfcs_and_specs": [
            "WASI Preview 1/2 & WebAssembly Core 2.0 Security Model",
            "Linux eBPF Verifier / Seccomp-BPF / Capabilities Model",
            "Windows AppContainer & Job Object Isolation Invariants",
            "Rust Unsafe Code Guidelines & Rudra Panic-Safety Invariants",
        ],
        "ietf_docs": [],
        "hackerone_asset_types": ["DOWNLOADABLE_EXECUTABLES", "HARDWARE", "SOURCE_CODE", "OTHER"],
        "hackerone_cwes": ["CWE-119", "CWE-787", "CWE-908", "CWE-758", "CWE-250", "CWE-362", "CWE-190"],
        "nuclei_tags": ["cve", "rce", "memory"],
        "rfchunt_modules": ["VerificationInversionHunter", "ArxivSecurityBridge", "RAPTOR", "Mantis", "FuzzBridge"],
        "live_query": "eBPF Wasmtime WASI sandbox escape unsafe Rust kernel fuzzing vulnerability",
    },
    "data_ml_analytics": {
        "label": "Data, ML & Analytics (ETL, SQL/NoSQL, Model Training/Fine-Tuning, Evaluation Benchmarks)",
        "packages": {
            "torch", "tensorflow", "jax", "scikit-learn", "xgboost", "lightgbm", "pandas",
            "polars", "duckdb", "pyspark", "apache-airflow", "dbt-core", "sqlalchemy",
            "psycopg", "psycopg2", "pymongo", "redis", "prisma", "drizzle-orm", "onnx",
            "onnxruntime", "safetensors", "datasets", "mlflow", "wandb", "ray",
        },
        "extensions": {".sql", ".ipynb", ".parquet", ".onnx", ".safetensors", ".gguf"},
        "filenames": {"dbt_project.yml", "airflow.cfg"},
        "keywords": [
            "etl", "sql", "nosql", "postgres", "mysql", "mongodb", "redis", "duckdb", "spark",
            "airflow", "dbt", "model training", "fine-tuning", "finetuning", "pytorch",
            "pickle", "safetensors", "onnx", "gguf", "mlflow", "benchmark", "analytics",
        ],
        "rfcs_and_specs": [
            "OWASP SQL/NoSQL Injection Prevention & Safe Model Serialization (Safetensors vs Pickle)",
            "MITRE ATLAS ML Supply Chain & Data Poisoning Mitigations",
        ],
        "ietf_docs": [],
        "hackerone_asset_types": ["API", "SOURCE_CODE", "AI_MODEL"],
        "hackerone_cwes": ["CWE-502", "CWE-89", "CWE-943", "CWE-359", "CWE-494"],
        "nuclei_tags": ["sqli", "nosqli", "mlflow", "ray", "exposure"],
        "rfchunt_modules": ["Mantis", "RAPTOR", "PhiScanner", "ArxivSecurityBridge"],
        "live_query": "ML pipeline pickle ONNX MLflow Ray SQL NoSQL deserialization security",
    },
    "mobile_desktop_crossplatform": {
        "label": "Mobile, Desktop & Cross-Platform (iOS, Android, React Native, Flutter, Tauri, Electron)",
        "packages": {
            "react-native", "expo", "electron", "@tauri-apps/api", "@tauri-apps/cli",
            "tauri", "androidx.webkit", "flutter", "capacitor", "@capacitor/core",
            "@shopify/checkout-sheet-kit",
        },
        "extensions": {".swift", ".kt", ".kts", ".dart", ".apk", ".ipa"},
        "filenames": {"AndroidManifest.xml", "Info.plist", "Package.swift", "pubspec.yaml", "tauri.conf.json", "capacitor.config.ts"},
        "keywords": [
            "ios", "android", "react native", "flutter", "tauri", "electron", "mobile",
            "webview", "wkwebview", "javascriptinterface", "deep link", "intent",
            "universal link", "keychain", "desktop app", "ipc",
        ],
        "rfcs_and_specs": [
            "OWASP MASVS / MASTG (Mobile Application Security Verification Standard)",
            "Electron Security Checklist (contextIsolation, sandbox, nodeIntegration=false)",
            "Tauri v2 Capability & Scope Permission Model",
            "Android WebView WebMessageListener Origin Rules & CATEGORY_BROWSABLE",
        ],
        "ietf_docs": [],
        "hackerone_asset_types": ["APPLE_STORE_APP_ID", "GOOGLE_PLAY_APP_ID", "WINDOWS_APP_STORE_APP_ID", "DOWNLOADABLE_EXECUTABLES"],
        "hackerone_cwes": ["CWE-749", "CWE-926", "CWE-79", "CWE-94", "CWE-522", "CWE-200"],
        "nuclei_tags": ["mobile", "android", "ios", "electron"],
        "rfchunt_modules": ["Mantis", "RAPTOR", "VerificationInversionHunter"],
        "live_query": "Android WebView iOS WKWebView React Native Flutter Electron Tauri security",
    },
    "devops_cloud_infra": {
        "label": "DevOps, Cloud & Infrastructure (Containers, Kubernetes, IaC, CI/CD, Observability, IAM/Networking)",
        "packages": {
            "kubernetes", "k8s.io/client-go", "boto3", "google-cloud-storage", "azure-identity",
            "docker", "pulumi", "aws-cdk-lib", "cdktf", "opentelemetry-api", "prometheus-client",
            "helm", "krane", "shipit",
        },
        "extensions": {".tf", ".tfvars", ".hcl"},
        "filenames": {
            "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Chart.yaml",
            "Jenkinsfile", "Procfile", "helmfile.yaml", "skaffold.yaml", ".gitlab-ci.yml",
        },
        "keywords": [
            "docker", "container", "containers", "kubernetes", "k8s", "helm", "terraform",
            "iac", "pulumi", "ci/cd", "github actions", "gitlab ci", "observability",
            "prometheus", "opentelemetry", "iam", "aws", "gcp", "azure", "vpc", "cloud",
        ],
        "rfcs_and_specs": [
            "CIS Benchmarks (Docker, Kubernetes, AWS/GCP/Azure)",
            "GitHub Actions Security Hardening (pull_request_target, OIDC, pinned SHAs)",
            "Kubernetes Pod Security Standards (Restricted Profile)",
        ],
        "ietf_docs": [],
        "hackerone_asset_types": ["CLOUD", "AWS_ACCOUNT", "GCP_PROJECT", "AZURE_SUBSCRIPTION", "OTHER"],
        "hackerone_cwes": ["CWE-78", "CWE-250", "CWE-732", "CWE-798", "CWE-918", "CWE-269"],
        "nuclei_tags": ["cloud", "aws", "k8s", "docker", "devops", "exposure", "misconfig"],
        "rfchunt_modules": ["ArxivSecurityBridge", "RAPTOR", "Mantis", "Last30DaysSecuritySkills"],
        "live_query": "Kubernetes container escape Terraform IAM GitHub Actions CI/CD security",
    },
    "web3_blockchain_smart_contracts": {
        "label": "Web3, Blockchain Consensus & Smart Contracts (Solidity, EVM, BFT, Validators, Bridges)",
        "packages": {
            "ethers", "viem", "web3", "hardhat", "foundry", "@openzeppelin/contracts",
            "revm", "alloy", "alloy-primitives", "reth", "malachite", "cometbft",
            "tendermint", "anchor-lang", "solana-sdk", "cosmwasm-std",
        },
        "extensions": {".sol", ".vy", ".move", ".cairo"},
        "filenames": {"foundry.toml", "hardhat.config.ts", "hardhat.config.js", "Anchor.toml", "Move.toml", "truffle-config.js"},
        "keywords": [
            "blockchain", "web3", "smart contract", "solidity", "vyper", "evm", "revm",
            "consensus", "bft", "validator", "malachite", "tendermint", "cometbft",
            "bridge", "signer", "precompile", "foundry", "hardhat", "defi",
        ],
        "rfcs_and_specs": [
            "EIP / Ethereum Execution & Consensus Specifications",
            "Tendermint / Malachite BFT Safety & Liveness Invariants",
            "SWC Registry (Smart Contract Weakness Classification)",
        ],
        "ietf_docs": [],
        "hackerone_asset_types": ["SMART_CONTRACT", "SOURCE_CODE", "OTHER"],
        "hackerone_cwes": ["CWE-841", "CWE-190", "CWE-345", "CWE-862", "CWE-400", "CWE-754"],
        "nuclei_tags": ["web3", "rpc", "exposure"],
        "rfchunt_modules": ["VerificationInversionHunter", "Mantis", "RAPTOR", "ArxivSecurityBridge"],
        "live_query": "smart contract EVM BFT consensus validator precompile security audit",
    },
}


# ==============================================================================
# Data Models
# ==============================================================================

@dataclass
class DetectedDependency:
    ecosystem: str
    name: str
    version: str
    source_file: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PreflightFinding:
    rule_id: str
    category: str
    severity: str
    cwe_id: str
    title: str
    file: str
    line: int
    evidence: str
    remediation: str
    confidence: str = "HIGH"
    poe_level: int = 2
    scanner: str = "PreflightDiscovery"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LocalSkillAuditRecord:
    name: str
    description: str
    skill_md_path: str
    source_type: str  # "workspace" | "home" | "rfchunt_registry"
    matched_categories: List[str]
    relevance_score: float
    safety_status: str  # "SAFE" | "BLOCKED_UNSAFE"
    safety_reasons: List[str] = field(default_factory=list)
    guidelines_preview: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# 1. Workspace & Prompt Stack Inspector
# ==============================================================================

_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(?:==|~=|>=|<=|>|<|!=)?\s*([A-Za-z0-9.*+_-]+)?"
)
_GOMOD_REQ_RE = re.compile(r"^\s*([a-zA-Z0-9._/-]+)\s+(v[0-9]+\.[0-9]+\.[0-9]+[^\s]*)")
_GO_VER_RE = re.compile(r"^\s*go\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.MULTILINE)
_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*["']([^:"']+):([^:"']+):([^"']+)["']"""
)
_GEMFILE_RE = re.compile(r"""^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?""", re.MULTILINE)
_PUBSPEC_DEP_RE = re.compile(r"^\s{2}([a-zA-Z0-9_-]+):\s*\^?([0-9][0-9a-zA-Z.+_-]*)\s*$")
_SWIFT_PKG_RE = re.compile(r"""url:\s*["']([^"']+)["'][^)]*(?:from:|exact:)\s*["']([^"']+)["']""")
_CSPROJ_PKG_RE = re.compile(
    r"""PackageReference\s+Include=["']([^"']+)["'][^>]*Version=["']([^"']+)["']""",
    re.IGNORECASE,
)


def _read_bounded_text(path: Path, max_bytes: int = MAX_MANIFEST_BYTES) -> str:
    try:
        with path.open("rb") as fh:
            raw = fh.read(max_bytes)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _clean_version(raw: str) -> str:
    val = str(raw or "").strip()
    val = re.sub(r"^[\^~>=<!\s]+", "", val)
    val = val.split(",")[0].strip()
    return val[:48]


class WorkspaceStackInspector:
    """Multithreaded, memory-bounded inspector for manifests, schemas, extensions, and prompts."""

    def __init__(self, max_workers: Optional[int] = None) -> None:
        cpu = os.cpu_count() or 4
        self.max_workers = max_workers or min(16, max(4, cpu * 2))

    def inspect(
        self,
        target_path: Optional[str] = None,
        prompt: str = "",
        policy_text: str = "",
        target_host: Optional[str] = None,
    ) -> Dict[str, Any]:
        root: Optional[Path] = None
        if target_path:
            cand = Path(target_path).resolve(strict=False)
            if cand.exists():
                root = cand

        manifest_files: List[Path] = []
        schema_files: List[Path] = []
        source_files: List[Path] = []
        ext_counts: Dict[str, int] = {}
        filename_hits: Set[str] = set()
        ci_workflow_files: List[Path] = []

        if root is not None:
            if root.is_file():
                all_files = [root]
            else:
                all_files = self._walk_files(root)
            for fp in all_files:
                name = fp.name
                lname = name.lower()
                ext = fp.suffix.lower()
                if ext:
                    ext_counts[ext] = ext_counts.get(ext, 0) + 1
                filename_hits.add(name)

                # Manifests
                if (
                    name in {
                        "Cargo.toml", "pyproject.toml", "package.json", "go.mod",
                        "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile",
                        "composer.json", "Package.swift", "pubspec.yaml",
                        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
                        "Chart.yaml", "foundry.toml", "Anchor.toml", "Move.toml",
                        "AndroidManifest.xml", "Info.plist", "tauri.conf.json",
                        "mcp.json", "agent-card.json",
                    }
                    or lname.startswith("requirements") and ext == ".txt"
                    or ext == ".csproj"
                    or lname.startswith("dockerfile.")
                ):
                    manifest_files.append(fp)

                # GitHub / GitLab CI workflows
                rel_posix = self._rel_posix(fp, root)
                if ".github/workflows/" in rel_posix and ext in (".yml", ".yaml"):
                    ci_workflow_files.append(fp)
                elif name == ".gitlab-ci.yml":
                    ci_workflow_files.append(fp)

                # Schemas
                if (
                    ext in {".proto", ".graphql", ".gql", ".avsc", ".sol", ".vy", ".move", ".cairo", ".wat", ".wasm"}
                    or ("openapi" in lname or "swagger" in lname or "asyncapi" in lname) and ext in (".yaml", ".yml", ".json")
                    or (".bpf." in lname or ".ebpf." in lname)
                ):
                    schema_files.append(fp)

                # Source scan pool (bounded)
                if ext in _SOURCE_CODE_EXTS and len(source_files) < MAX_SOURCE_FILES_SCANNED:
                    source_files.append(fp)

        dependencies: List[DetectedDependency] = []
        runtime_versions: Dict[str, str] = {}
        manifests_parsed: List[str] = []

        if manifest_files:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futs = {
                    pool.submit(self._parse_manifest, fp, root): fp
                    for fp in manifest_files[:200]
                }
                for fut in as_completed(futs):
                    try:
                        deps, runtimes, rel_label = fut.result()
                        if rel_label:
                            manifests_parsed.append(rel_label)
                        dependencies.extend(deps)
                        for k, v in runtimes.items():
                            if v and k not in runtime_versions:
                                runtime_versions[k] = v
                    except Exception:
                        continue

        # Deduplicate dependencies preserving exact versions
        dedup_deps: Dict[Tuple[str, str, str], DetectedDependency] = {}
        for dep in dependencies:
            key = (dep.ecosystem, dep.name.lower(), dep.version)
            if key not in dedup_deps:
                dedup_deps[key] = dep
        unique_deps = sorted(
            dedup_deps.values(),
            key=lambda d: (d.ecosystem, d.name.lower(), d.version),
        )

        # Detect programming languages from extensions + manifests + prompt
        languages: Dict[str, Dict[str, Any]] = {}
        for ext, count in ext_counts.items():
            lang = _EXT_TO_LANGUAGE.get(ext)
            if lang:
                entry = languages.setdefault(
                    lang,
                    {
                        "language": lang,
                        "file_count": 0,
                        "runtime_version": runtime_versions.get(lang, ""),
                        "security_focus": _LANGUAGE_SECURITY_NOTES.get(lang, {}).get("focus", ""),
                        "recommended_linters": _LANGUAGE_SECURITY_NOTES.get(lang, {}).get("linters", []),
                    },
                )
                entry["file_count"] += count

        # Ensure languages implied by manifests appear even if few source files
        manifest_lang_map = {
            "Cargo.toml": "Rust",
            "pyproject.toml": "Python",
            "package.json": "JavaScript",
            "go.mod": "Go",
            "pom.xml": "Java",
            "Gemfile": "Ruby",
            "composer.json": "PHP",
            "Package.swift": "Swift",
            "pubspec.yaml": "Dart",
            "foundry.toml": "Solidity",
        }
        for mf in manifest_files:
            inferred = manifest_lang_map.get(mf.name)
            if inferred and inferred not in languages:
                languages[inferred] = {
                    "language": inferred,
                    "file_count": 0,
                    "runtime_version": runtime_versions.get(inferred, ""),
                    "security_focus": _LANGUAGE_SECURITY_NOTES.get(inferred, {}).get("focus", ""),
                    "recommended_linters": _LANGUAGE_SECURITY_NOTES.get(inferred, {}).get("linters", []),
                }

        # Prompt language mentions
        combined_text = "\n".join(x for x in (prompt, policy_text, target_host or "") if x).lower()
        for lang_name in _LANGUAGE_SECURITY_NOTES:
            token = lang_name.lower()
            if len(token) >= 2 and re.search(rf"(?<![a-z0-9_]){re.escape(token)}(?![a-z0-9_])", combined_text):
                if lang_name not in languages:
                    languages[lang_name] = {
                        "language": lang_name,
                        "file_count": 0,
                        "runtime_version": runtime_versions.get(lang_name, ""),
                        "security_focus": _LANGUAGE_SECURITY_NOTES[lang_name]["focus"],
                        "recommended_linters": _LANGUAGE_SECURITY_NOTES[lang_name]["linters"],
                    }

        for lang_name, info in languages.items():
            if not info.get("runtime_version") and runtime_versions.get(lang_name):
                info["runtime_version"] = runtime_versions[lang_name]

        schema_rel = sorted({self._rel_posix(p, root) for p in schema_files[:150]})
        ci_rel = sorted({self._rel_posix(p, root) for p in ci_workflow_files[:50]})

        return {
            "target_path": str(root) if root is not None else "",
            "manifests_parsed": sorted(set(manifests_parsed)),
            "schemas_detected": schema_rel,
            "ci_workflows_detected": ci_rel,
            "extensions_summary": dict(sorted(ext_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:40]),
            "filenames_seen": sorted(filename_hits),
            "dependencies": unique_deps,
            "runtime_versions": runtime_versions,
            "languages": sorted(languages.values(), key=lambda x: (-x["file_count"], x["language"])),
            "source_files": source_files,
            "combined_prompt_text": combined_text,
        }

    def _walk_files(self, root: Path) -> List[Path]:
        found: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            base = Path(dirpath)
            for fn in filenames:
                found.append(base / fn)
                if len(found) >= 12_000:
                    return found
        return found

    @staticmethod
    def _rel_posix(path: Path, root: Optional[Path]) -> str:
        if root is not None:
            try:
                return path.relative_to(root).as_posix()
            except ValueError:
                pass
        return path.as_posix()

    def _parse_manifest(
        self,
        fp: Path,
        root: Optional[Path],
    ) -> Tuple[List[DetectedDependency], Dict[str, str], str]:
        rel = self._rel_posix(fp, root)
        text = _read_bounded_text(fp, MAX_MANIFEST_BYTES)
        if not text:
            return [], {}, rel

        deps: List[DetectedDependency] = []
        runtimes: Dict[str, str] = {}
        name = fp.name
        lname = name.lower()

        if name == "Cargo.toml" and tomllib is not None:
            try:
                data = tomllib.loads(text)
                pkg = data.get("package") or {}
                if isinstance(pkg, dict):
                    if pkg.get("rust-version"):
                        runtimes["Rust"] = str(pkg["rust-version"])
                    elif pkg.get("edition"):
                        runtimes["Rust"] = f"edition-{pkg['edition']}"
                for section_key in ("dependencies", "dev-dependencies", "build-dependencies"):
                    sec = data.get(section_key) or {}
                    if isinstance(sec, dict):
                        for dep_name, spec in sec.items():
                            ver = ""
                            if isinstance(spec, str):
                                ver = _clean_version(spec)
                            elif isinstance(spec, dict):
                                ver = _clean_version(str(spec.get("version") or ""))
                            deps.append(DetectedDependency("crates.io", str(dep_name), ver, rel))
                ws_deps = (data.get("workspace") or {}).get("dependencies") or {}
                if isinstance(ws_deps, dict):
                    for dep_name, spec in ws_deps.items():
                        ver = _clean_version(spec if isinstance(spec, str) else str((spec or {}).get("version", "")))
                        deps.append(DetectedDependency("crates.io", str(dep_name), ver, rel))
            except Exception:
                pass

        elif name == "pyproject.toml" and tomllib is not None:
            try:
                data = tomllib.loads(text)
                proj = data.get("project") or {}
                if isinstance(proj, dict):
                    if proj.get("requires-python"):
                        runtimes["Python"] = str(proj["requires-python"])
                    for raw_dep in proj.get("dependencies") or []:
                        m = _REQ_LINE_RE.match(str(raw_dep))
                        if m:
                            deps.append(DetectedDependency("PyPI", m.group(1), _clean_version(m.group(2) or ""), rel))
                    opt_deps = proj.get("optional-dependencies") or {}
                    if isinstance(opt_deps, dict):
                        for group_items in opt_deps.values():
                            for raw_dep in group_items or []:
                                m = _REQ_LINE_RE.match(str(raw_dep))
                                if m:
                                    deps.append(DetectedDependency("PyPI", m.group(1), _clean_version(m.group(2) or ""), rel))
                poetry_deps = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
                if isinstance(poetry_deps, dict):
                    for k, v in poetry_deps.items():
                        if k.lower() == "python":
                            runtimes["Python"] = str(v)
                            continue
                        ver = _clean_version(v if isinstance(v, str) else str((v or {}).get("version", "")))
                        deps.append(DetectedDependency("PyPI", str(k), ver, rel))
            except Exception:
                pass

        elif lname.startswith("requirements") and fp.suffix.lower() == ".txt":
            for raw_line in text.splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = _REQ_LINE_RE.match(line)
                if m:
                    deps.append(DetectedDependency("PyPI", m.group(1), _clean_version(m.group(2) or ""), rel))

        elif name == "package.json":
            try:
                data = json.loads(text)
                engines = data.get("engines") or {}
                if isinstance(engines, dict) and engines.get("node"):
                    runtimes["JavaScript"] = f"node {engines['node']}"
                    runtimes["TypeScript"] = f"node {engines['node']}"
                for sec_name in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    sec = data.get(sec_name) or {}
                    if isinstance(sec, dict):
                        for pkg_name, ver in sec.items():
                            deps.append(DetectedDependency("npm", str(pkg_name), _clean_version(str(ver)), rel))
                            if pkg_name == "typescript":
                                runtimes["TypeScript"] = _clean_version(str(ver))
            except Exception:
                pass

        elif name == "go.mod":
            m_go = _GO_VER_RE.search(text)
            if m_go:
                runtimes["Go"] = m_go.group(1)
            for line in text.splitlines():
                clean = line.split("//", 1)[0].strip()
                if clean.startswith("require "):
                    clean = clean[len("require "):].strip()
                m = _GOMOD_REQ_RE.match(clean)
                if m and "/" in m.group(1):
                    deps.append(DetectedDependency("Go", m.group(1), m.group(2), rel))

        elif name == "pom.xml":
            if "<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper():
                try:
                    root_el = ET.fromstring(text)
                    for dep_el in root_el.iter():
                        if dep_el.tag.endswith("dependency"):
                            gid = aid = ver = ""
                            for child in dep_el:
                                if child.tag.endswith("groupId") and child.text:
                                    gid = child.text.strip()
                                elif child.tag.endswith("artifactId") and child.text:
                                    aid = child.text.strip()
                                elif child.tag.endswith("version") and child.text:
                                    ver = child.text.strip()
                            if gid and aid:
                                deps.append(DetectedDependency("Maven", f"{gid}:{aid}", _clean_version(ver), rel))
                except Exception:
                    pass

        elif name in ("build.gradle", "build.gradle.kts"):
            for m in _GRADLE_DEP_RE.finditer(text):
                deps.append(DetectedDependency("Maven", f"{m.group(1)}:{m.group(2)}", _clean_version(m.group(3)), rel))

        elif name == "Gemfile":
            for m in _GEMFILE_RE.finditer(text):
                deps.append(DetectedDependency("RubyGems", m.group(1), _clean_version(m.group(2) or ""), rel))

        elif name == "composer.json":
            try:
                data = json.loads(text)
                for sec_name in ("require", "require-dev"):
                    sec = data.get(sec_name) or {}
                    if isinstance(sec, dict):
                        for k, v in sec.items():
                            if k == "php":
                                runtimes["PHP"] = str(v)
                            else:
                                deps.append(DetectedDependency("Packagist", str(k), _clean_version(str(v)), rel))
            except Exception:
                pass

        elif name == "pubspec.yaml":
            for line in text.splitlines():
                m = _PUBSPEC_DEP_RE.match(line)
                if m and m.group(1) not in ("sdk", "version"):
                    deps.append(DetectedDependency("Pub", m.group(1), _clean_version(m.group(2)), rel))

        elif name == "Package.swift":
            for m in _SWIFT_PKG_RE.finditer(text):
                deps.append(DetectedDependency("SwiftURL", m.group(1), _clean_version(m.group(2)), rel))

        elif fp.suffix.lower() == ".csproj":
            for m in _CSPROJ_PKG_RE.finditer(text):
                deps.append(DetectedDependency("NuGet", m.group(1), _clean_version(m.group(2)), rel))

        return deps, runtimes, rel


# ==============================================================================
# 2. Post-Quantum Cryptography (PQC) & HNDL Static Auditor
# ==============================================================================

_PQC_ACTIVE_CODE_RE = re.compile(
    r"(?<![a-z0-9])(?:ml[_-]?kem|mlkem|kyber|fips203|ml[_-]?dsa|mldsa|dilithium|fips204|slh[_-]?dsa|slhdsa|sphincs|fips205|fn[_-]?dsa|falcon|fips206|hqc|xmss|lms|hss|liboqs|oqs_kem|oqs_sig|x25519mlkem768|secp256r1mlkem768|rustls_post_quantum|pqcrypto|circl/kem|circl/sign|pqxdh|x[_-]?wing)(?![a-z])",
    re.IGNORECASE,
)

# PQC-01: Non-constant-time timing hazard / KyberSlash pattern in ML-KEM / Kyber code
_PQC01_KEM_RE = re.compile(r"\b(?:ml[_-]?kem|kyber|fips203|oqs_kem|decapsulate|kem_decaps)\b", re.IGNORECASE)
_PQC01_TIMING_RE = re.compile(
    r"(?:shared_secret\s*(?:==|!=)|ciphertext\s*(?:==|!=)|(?:poly|coeff|msg|ss)[A-Za-z0-9_]*\s*/\s*(?:3329|q\b|KYBER_Q)|if\s+[^:\n]{0,80}(?:shared_secret|decap_ok|reencrypt)\s*==)",
    re.IGNORECASE,
)
_PQC01_CT_GUARD_RE = re.compile(
    r"\b(?:ct_eq|constant_time_eq|compare_digest|timingSafeEqual|subtle::|ConstantTimeCompare|CRYPTO_memcmp)\b"
)

# PQC-02: Stateful hash-based signature (XMSS/LMS/HSS) without durable/atomic state guard
_PQC02_STATEFUL_SIGN_RE = re.compile(r"\b(?:xmss|lms|hss)_[a-z0-9_]*sign\b|\b(?:XMSS|LMS|HSS)Signer\b", re.IGNORECASE)
_PQC02_STATE_PERSIST_RE = re.compile(
    r"\b(?:fsync|sync_all|sync_data|flock|FileLock|atomic_write|persist_state|save_state|increment_index|Mutex|RwLock)\b",
    re.IGNORECASE,
)

# PQC-03: Hybrid PQC/classical downgrade or missing transcript binding
_PQC03_DOWNGRADE_RE = re.compile(
    r"""(?:\ballow_classical_fallback\s*[:=]\s*(?:True|true)\b|\bfallback_to_classical\s*[:=]\s*(?:True|true)\b|\bpqc_optional\s*[:=]\s*(?:True|true)\b|\bignore_pq_failure\s*[:=]\s*(?:True|true)\b|\bhybrid_downgrade_allowed\s*[:=]\s*(?:True|true)\b)""",
    re.IGNORECASE,
)

# PQC-04: Weak/hardcoded RNG seed or static entropy in PQC keygen/signing
_PQC04_WEAK_SEED_RE = re.compile(
    r"""(?:\bseed\s*[:=]\s*(?:\[0u8;\s*(?:32|64)\]|b["']\\x00["']\s*\*\s*(?:32|64)|bytes\((?:32|64)\)|["']0{32,}["'])|StdRng::seed_from_u64\s*\(|SmallRng::seed_from_u64\s*\(|random\.seed\s*\(\s*\d+\s*\))""",
    re.IGNORECASE,
)

# PQC-05: Unmetered / pre-gas or unbounded PQC deserialization before bounds/gas check
_PQC05_UNMETERED_DECODE_RE = re.compile(
    r"\b(?:abi_decode_raw_validate|abi_decode|from_bytes_unchecked|deserialize_unbounded)\s*\([^)]*(?:ml_dsa|dilithium|falcon|slh_dsa|ml_kem|pq_sig|pq_key|pqc|pubkey|signature)",
    re.IGNORECASE,
)
_PQC05_GAS_OR_LEN_GUARD_RE = re.compile(r"\b(?:charge_gas|gas_limit|MAX_PQ|max_len|checked_sub|ensure_len)\b", re.IGNORECASE)

# PQC-06: Quantum-vulnerable HNDL classical-only key exchange / long-lived signing
_PQC06_LEGACY_CRYPTO_RE = re.compile(
    r"\b(?:RSAPrivateKey|rsa\.generate_private_key|RSA_generate_key|PKCS1v15|ec\.generate_private_key|ecdsa\.GenerateKey|Ed25519PrivateKey|X25519PrivateKey|DiffieHellman|DHParameters|SSL_CTX_set_ecdh|TLS_ECDHE_RSA|TLS_RSA_WITH_|crypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"](?:rsa|ec|ed25519|x25519|dsa)['\"])",
)


class PostQuantumPreflightAuditor:
    """Fast multithreaded static Post-Quantum Cryptography & HNDL auditor (`PQC-01`..`PQC-06`)."""

    def __init__(self, max_workers: Optional[int] = None) -> None:
        cpu = os.cpu_count() or 4
        self.max_workers = max_workers or min(16, max(4, cpu * 2))

    def audit(
        self,
        source_files: Sequence[Path],
        root: Optional[Path],
        detected_dependencies: Sequence[DetectedDependency],
    ) -> Dict[str, Any]:
        pqc_pkg_names = PREFLIGHT_TAXONOMY["post_quantum_crypto"]["packages"]
        pqc_libraries_detected = sorted(
            {
                f"{d.name}@{d.version}" if d.version else d.name
                for d in detected_dependencies
                if d.name.lower() in pqc_pkg_names
                and d.name.lower() not in {"cryptography", "ring", "openssl-sys"}
            }
        )

        pqc_code_files: List[str] = []
        legacy_crypto_files: List[Tuple[str, int, str]] = []
        active_findings: List[PreflightFinding] = []

        if source_files:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futs = [pool.submit(self._scan_file, fp, root) for fp in source_files]
                for fut in as_completed(futs):
                    try:
                        has_pqc, rel, f_list, legacy_hit = fut.result()
                        if has_pqc:
                            pqc_code_files.append(rel)
                        active_findings.extend(f_list)
                        if legacy_hit is not None:
                            legacy_crypto_files.append(legacy_hit)
                    except Exception:
                        continue

        has_pqc_migration = bool(pqc_libraries_detected or pqc_code_files)
        hndl_findings: List[PreflightFinding] = []
        if legacy_crypto_files and not has_pqc_migration:
            for rel, ln, snippet in sorted(legacy_crypto_files)[:10]:
                hndl_findings.append(
                    PreflightFinding(
                        rule_id="PQC-06-HNDL-CLASSICAL-ONLY",
                        category="post_quantum_crypto",
                        severity="LOW",
                        cwe_id="CWE-326",
                        title="Quantum-Vulnerable Classical-Only Public-Key Cryptography (HNDL Readiness Gap)",
                        file=rel,
                        line=ln,
                        evidence=snippet[:180],
                        remediation=(
                            "Plan crypto-agile migration toward NIST FIPS 203 (ML-KEM / hybrid X25519MLKEM768) "
                            "for key exchange and FIPS 204/205 (ML-DSA / SLH-DSA) for long-lived signatures per NIST IR 8547 & CNSA 2.0."
                        ),
                        confidence="MEDIUM",
                        poe_level=1,
                        scanner="PostQuantumPreflightAuditor",
                    )
                )

        all_findings = active_findings + hndl_findings
        if active_findings:
            readiness_status = "PQC_IMPLEMENTATION_DEFECTS_DETECTED"
        elif has_pqc_migration:
            readiness_status = "PQC_ENABLED_NO_STATIC_DEFECTS"
        elif legacy_crypto_files:
            readiness_status = "CLASSICAL_ONLY_HNDL_EXPOSED"
        else:
            readiness_status = "NO_ASYMMETRIC_CRYPTO_DETECTED"

        return {
            "status": readiness_status,
            "pqc_libraries_detected": pqc_libraries_detected,
            "pqc_source_files_count": len(pqc_code_files),
            "pqc_source_files": sorted(pqc_code_files)[:30],
            "classical_hndl_files_count": len(legacy_crypto_files),
            "classical_hndl_files": [r for r, _, _ in sorted(legacy_crypto_files)[:20]],
            "standards_checked": [
                "NIST FIPS 203 (ML-KEM)",
                "NIST FIPS 204 (ML-DSA)",
                "NIST FIPS 205 (SLH-DSA)",
                "RFC 8391 (XMSS) / RFC 8554 (LMS)",
                "IETF draft-ietf-tls-ecdhe-mlkem / CNSA 2.0",
            ],
            "total_findings": len(all_findings),
            "findings": [f.to_dict() for f in all_findings],
        }

    @staticmethod
    def _scan_file(
        fp: Path,
        root: Optional[Path],
    ) -> Tuple[bool, str, List[PreflightFinding], Optional[Tuple[str, int, str]]]:
        rel = WorkspaceStackInspector._rel_posix(fp, root)
        # Skip test fixtures inside RFCHunt's own preflight test suite unless explicitly scanned directly
        text = _read_bounded_text(fp, MAX_SOURCE_SCAN_BYTES)
        if not text:
            return False, rel, [], None

        has_pqc = bool(_PQC_ACTIVE_CODE_RE.search(text))
        findings: List[PreflightFinding] = []
        lines = text.splitlines()

        def _line_no(offset: int) -> int:
            return text.count("\n", 0, offset) + 1

        if has_pqc:
            # PQC-01: Timing / KyberSlash hazard
            if _PQC01_KEM_RE.search(text) and not _PQC01_CT_GUARD_RE.search(text):
                m = _PQC01_TIMING_RE.search(text)
                if m:
                    ln = _line_no(m.start())
                    findings.append(
                        PreflightFinding(
                            rule_id="PQC-01-KYBERSLASH-TIMING",
                            category="post_quantum_crypto",
                            severity="HIGH",
                            cwe_id="CWE-208",
                            title="Potential Non-Constant-Time Operation in ML-KEM / Kyber Decapsulation",
                            file=rel,
                            line=ln,
                            evidence=(lines[ln - 1].strip() if 0 < ln <= len(lines) else m.group(0))[:180],
                            remediation=(
                                "Replace secret-dependent branches, variable-time divisions (KyberSlash), "
                                "and non-constant-time equality checks with constant-time primitives "
                                "(subtle::ConstantTimeEq, hmac.compare_digest, crypto.timingSafeEqual, or Barrett reduction)."
                            ),
                            scanner="PostQuantumPreflightAuditor",
                        )
                    )

            # PQC-02: Stateful XMSS / LMS index reuse hazard
            m2 = _PQC02_STATEFUL_SIGN_RE.search(text)
            if m2 and not _PQC02_STATE_PERSIST_RE.search(text):
                ln = _line_no(m2.start())
                findings.append(
                    PreflightFinding(
                        rule_id="PQC-02-STATEFUL-HASH-SIG-REUSE",
                        category="post_quantum_crypto",
                        severity="CRITICAL",
                        cwe_id="CWE-323",
                        title="Stateful Post-Quantum Signature (XMSS/LMS/HSS) Missing Atomic State Persistence",
                        file=rel,
                        line=ln,
                        evidence=(lines[ln - 1].strip() if 0 < ln <= len(lines) else m2.group(0))[:180],
                        remediation=(
                            "Enforce exclusive locking and durable fsync'd monotonic state-index advancement BEFORE "
                            "releasing any XMSS/LMS signature (RFC 8391 / RFC 8554), or migrate to stateless FIPS 205 SLH-DSA."
                        ),
                        scanner="PostQuantumPreflightAuditor",
                    )
                )

            # PQC-03: Hybrid KEM downgrade
            m3 = _PQC03_DOWNGRADE_RE.search(text)
            if m3:
                ln = _line_no(m3.start())
                findings.append(
                    PreflightFinding(
                        rule_id="PQC-03-HYBRID-DOWNGRADE",
                        category="post_quantum_crypto",
                        severity="HIGH",
                        cwe_id="CWE-757",
                        title="Hybrid Post-Quantum Key Exchange Permits Silent Classical-Only Downgrade",
                        file=rel,
                        line=ln,
                        evidence=(lines[ln - 1].strip() if 0 < ln <= len(lines) else m3.group(0))[:180],
                        remediation=(
                            "Disable silent fallback from hybrid PQ key exchange (e.g., X25519MLKEM768) to "
                            "classical-only cipher suites and bind both classical and PQ transcripts in the KDF combiner."
                        ),
                        scanner="PostQuantumPreflightAuditor",
                    )
                )

            # PQC-04: Static/weak seed in PQC keygen/signing
            m4 = _PQC04_WEAK_SEED_RE.search(text)
            if m4:
                ln = _line_no(m4.start())
                findings.append(
                    PreflightFinding(
                        rule_id="PQC-04-WEAK-PQC-RNG-SEED",
                        category="post_quantum_crypto",
                        severity="HIGH",
                        cwe_id="CWE-330",
                        title="Hardcoded or Deterministic RNG Seed in Post-Quantum Cryptographic Module",
                        file=rel,
                        line=ln,
                        evidence=(lines[ln - 1].strip() if 0 < ln <= len(lines) else m4.group(0))[:180],
                        remediation=(
                            "Source all ML-KEM/ML-DSA/SLH-DSA key generation and hedged signing randomness "
                            "exclusively from an OS CSPRNG (OsRng, os.urandom, crypto.randomBytes) and bind FIPS 204/205 ctx."
                        ),
                        scanner="PostQuantumPreflightAuditor",
                    )
                )

            # PQC-05: Unmetered PQC deserialization before bounds/gas check
            m5 = _PQC05_UNMETERED_DECODE_RE.search(text)
            if m5:
                ln = _line_no(m5.start())
                window_start = max(0, ln - 12)
                window_text = "\n".join(lines[window_start:ln])
                if not _PQC05_GAS_OR_LEN_GUARD_RE.search(window_text):
                    findings.append(
                        PreflightFinding(
                            rule_id="PQC-05-UNMETERED-PQC-DECODE",
                            category="post_quantum_crypto",
                            severity="HIGH",
                            cwe_id="CWE-770",
                            title="Unmetered Post-Quantum Key or Signature Deserialization Before Bounds/Gas Guard",
                            file=rel,
                            line=ln,
                            evidence=(lines[ln - 1].strip() if 0 < ln <= len(lines) else m5.group(0))[:180],
                            remediation=(
                                "Enforce strict maximum byte-length and resource/gas charging BEFORE decoding "
                                "large post-quantum keys or signatures (ML-DSA/SLH-DSA/ML-KEM)."
                            ),
                            scanner="PostQuantumPreflightAuditor",
                        )
                    )

        # PQC-06: Classical-only HNDL inventory
        legacy_hit: Optional[Tuple[str, int, str]] = None
        m6 = _PQC06_LEGACY_CRYPTO_RE.search(text)
        if m6:
            ln = _line_no(m6.start())
            snip = lines[ln - 1].strip() if 0 < ln <= len(lines) else m6.group(0)
            legacy_hit = (rel, ln, snip)

        return has_pqc, rel, findings, legacy_hit


# ==============================================================================
# 3. Local Skill Directory & Registry Scanner + Fail-Closed Safety Gate
# ==============================================================================

_SKILL_FRONTMATTER_RE = re.compile(r"\A---\s*\r?\n(.*?)\r?\n---\s*\r?\n", re.DOTALL)
_SKILL_NAME_RE = re.compile(r"^\s*name\s*:\s*['\"]?([^'\"\r\n]+)['\"]?\s*$", re.MULTILINE)
_SKILL_DESC_RE = re.compile(r"^\s*description\s*:\s*['\"]?([^\r\n]+)['\"]?\s*$", re.MULTILINE)

# Multi-token safety gate rules (fail-closed, low false-positive)
_UNSAFE_PIPED_EXEC_RE = re.compile(
    r"(?:(?:curl|wget)\s+[^\n|]{3,240}\|\s*(?:ba)?sh\b|irm\s+[^\n|]{3,200}\|\s*iex\b|iwr\s+[^\n|]{3,200}\|\s*iex\b|base64\s+-d[^\n|]{0,80}\|\s*(?:ba)?sh\b|powershell(?:\.exe)?[^\n]{0,120}-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{24,})",
    re.IGNORECASE,
)
_UNSAFE_PROMPT_OVERRIDE_RE = re.compile(
    r"(?:(?:ignore|disregard|override)\s+(?:(?:all|any|the|previous|prior|above|system|developer)\s+){1,4}(?:instructions?|prompts?|rules?|safety\s+policies?)[\s\S]{0,200}\b(?:exfiltrate|send|upload|execute|disable|bypass|reveal|dump)\b|silently\s+(?:send|post|exfiltrate|upload)\s+[\s\S]{0,120}\b(?:env|secret|token|api[_-]?key|cookie|credential)|\*{2,3}\s*important\s+system\s+message|-{2,3}\s*(?:user|assistant|system)\s+response\s*-{2,3})",
    re.IGNORECASE,
)
_UNSAFE_PATH_MUTATION_RE = re.compile(
    r"(?:\bsetx\s+PATH\b|reg\s+add\s+HK(?:CU|LM)\\[^\n]*Environment|\[Environment\]::SetEnvironmentVariable\([^\n]*(?:['\"]User['\"]|['\"]Machine['\"]))",
    re.IGNORECASE,
)
_UNSAFE_COOKIE_EXFIL_RE = re.compile(
    r"(?:cookies\.sqlite|Login Data|Local State|find-generic-password)",
    re.IGNORECASE,
)
_UNSAFE_COOKIE_SINK_RE = re.compile(
    r"(?:sqlite3\.connect|shutil\.copy|requests\.post|urllib\.request\.urlopen|curl\s+-X\s+POST)",
    re.IGNORECASE,
)
_CONSENT_GUARD_RE = re.compile(r"\b(?:explicit\s+consent|positive\s+consent|confirm_user|ask_user|user_consent)\b", re.IGNORECASE)
_BIDI_CODEPOINTS: Set[int] = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
_ZERO_WIDTH_CODEPOINTS: Set[int] = {0x200B, 0x200C, 0x200D, 0xFEFF}


def audit_skill_content_safety(text: str, filename: str = "SKILL.md") -> Tuple[bool, List[str]]:
    """Fail-closed safety audit for local agent skill files before loading into context."""
    reasons: List[str] = []

    # 1. Unicode tag smuggling (U+E0000..U+E007F) or BiDi Trojan-Source overrides
    tag_count = sum(1 for ch in text if 0xE0000 <= ord(ch) <= 0xE007F)
    if tag_count > 0:
        reasons.append(f"{filename}: detected {tag_count} hidden Unicode tag character(s) (U+E0000-U+E007F)")

    bidi_count = sum(1 for ch in text if ord(ch) in _BIDI_CODEPOINTS)
    if bidi_count > 0:
        reasons.append(f"{filename}: detected {bidi_count} BiDi override control character(s) (Trojan Source)")

    zw_count = sum(1 for ch in text if ord(ch) in _ZERO_WIDTH_CODEPOINTS)
    if zw_count >= 8:
        reasons.append(f"{filename}: detected suspicious burst of {zw_count} zero-width characters")

    # 2. Piped remote shell execution / encoded PowerShell dropper
    if _UNSAFE_PIPED_EXEC_RE.search(text):
        reasons.append(f"{filename}: piped remote shell execution or encoded command bootstrap detected")

    # 3. Direct agent prompt-injection / covert exfiltration directive
    if _UNSAFE_PROMPT_OVERRIDE_RE.search(text):
        reasons.append(f"{filename}: agent prompt-injection override or covert secret exfiltration directive detected")

    # 4. Persistent user/system PATH / registry mutation
    if _UNSAFE_PATH_MUTATION_RE.search(text):
        reasons.append(f"{filename}: forbidden persistent OS PATH / environment registry mutation detected")

    # 5. Unconsented browser cookie/keychain scraping
    if (
        _UNSAFE_COOKIE_EXFIL_RE.search(text)
        and _UNSAFE_COOKIE_SINK_RE.search(text)
        and not _CONSENT_GUARD_RE.search(text)
    ):
        reasons.append(f"{filename}: unconsented browser cookie/keychain access without positive user consent gate")

    return (len(reasons) == 0), reasons


class LocalSkillDiscoveryAndSafetyGate:
    """Scans workspace & user skill directories + RFCHunt registries and safety-gates every skill."""

    def discover_and_load(
        self,
        *,
        workspace_root: Optional[Path],
        active_categories: Sequence[str],
        active_languages: Sequence[str],
        extra_skills_dirs: Optional[Sequence[str]] = None,
        include_home_skills: bool = True,
        include_rfchunt_registries: bool = True,
    ) -> Dict[str, Any]:
        search_roots: List[Tuple[Path, str]] = []
        if workspace_root is not None and workspace_root.exists():
            base = workspace_root if workspace_root.is_dir() else workspace_root.parent
            for rel in (".claude/skills", ".agents/skills", ".cursor/skills", ".gemini/skills", "skills"):
                cand = base / rel
                if cand.exists() and cand.is_dir():
                    search_roots.append((cand, "workspace"))

        if extra_skills_dirs:
            for raw_dir in extra_skills_dirs:
                cand = Path(str(raw_dir)).expanduser().resolve(strict=False)
                if cand.exists() and cand.is_dir():
                    search_roots.append((cand, "workspace"))

        if include_home_skills:
            home = Path.home()
            for rel in (
                ".claude/skills",
                ".codex/skills",
                ".cursor/skills",
                ".gemini/antigravity/builtin/skills",
            ):
                cand = home / rel
                if cand.exists() and cand.is_dir():
                    search_roots.append((cand, "home"))
            plugins_dir = home / ".gemini" / "config" / "plugins"
            if plugins_dir.exists() and plugins_dir.is_dir():
                for skill_dir in plugins_dir.glob("*/skills"):
                    if skill_dir.is_dir():
                        search_roots.append((skill_dir, "home"))

        # Deduplicate root directories
        seen_roots: Set[str] = set()
        unique_roots: List[Tuple[Path, str]] = []
        for root_p, src_type in search_roots:
            key = str(root_p.resolve(strict=False)).lower()
            if key not in seen_roots:
                seen_roots.add(key)
                unique_roots.append((root_p, src_type))

        # Build matching keyword set from active categories + languages
        match_terms: Dict[str, Set[str]] = {}
        for cat in active_categories:
            spec = PREFLIGHT_TAXONOMY.get(cat)
            if spec:
                terms = {kw.lower() for kw in spec["keywords"]} | {p.lower() for p in spec["packages"]}
                terms.add(cat.replace("_", " "))
                match_terms[cat] = terms
        lang_terms = {lang.lower() for lang in active_languages if len(lang) >= 2}

        skill_files: List[Tuple[Path, str]] = []
        seen_skill_paths: Set[str] = set()
        for root_p, src_type in unique_roots:
            for cur_root, cur_dirs, cur_files in os.walk(root_p, followlinks=False):
                cur_dirs[:] = [
                    d for d in sorted(cur_dirs)
                    if d not in _SKIP_DIRS
                ]
                if "SKILL.md" in cur_files:
                    sk_md = Path(cur_root) / "SKILL.md"
                    resolved = str(sk_md.resolve(strict=False))
                    if resolved.lower() not in seen_skill_paths:
                        seen_skill_paths.add(resolved.lower())
                        skill_files.append((sk_md, src_type))
                    if len(skill_files) >= 250:
                        break
            if len(skill_files) >= 250:
                break

        active_safe_skills: List[LocalSkillAuditRecord] = []
        blocked_unsafe_skills: List[LocalSkillAuditRecord] = []
        findings: List[PreflightFinding] = []

        for sk_md, src_type in skill_files:
            rec = self._inspect_local_skill(sk_md, src_type, match_terms, lang_terms)
            if rec is None:
                continue
            if rec.safety_status == "BLOCKED_UNSAFE":
                blocked_unsafe_skills.append(rec)
                findings.append(
                    PreflightFinding(
                        rule_id="PREFLIGHT-SKILL-UNSAFE",
                        category="llm_agents_ai_safety",
                        severity="HIGH",
                        cwe_id="CWE-506",
                        title=f"Unsafe Agent Skill Quarantined Before Loading: {rec.name}",
                        file=rec.skill_md_path,
                        line=1,
                        evidence="; ".join(rec.safety_reasons)[:240],
                        remediation=(
                            "Remove obfuscated Unicode tags, piped remote shell execution, prompt-injection "
                            "overrides, or persistent PATH/credential tampering before trusting this skill."
                        ),
                        scanner="LocalSkillDiscoveryAndSafetyGate",
                    )
                )
            elif rec.relevance_score > 0.0 or src_type == "workspace":
                active_safe_skills.append(rec)

        # Also pull matching built-in/registry skills from RFCHunt's Last30Days & ArXiv catalogs
        if include_rfchunt_registries:
            registry_skills = self._discover_rfchunt_registry_skills(match_terms, lang_terms)
            active_safe_skills.extend(registry_skills)

        active_safe_skills.sort(key=lambda r: (-r.relevance_score, r.name.lower()))
        return {
            "scanned_directories": [str(p) for p, _ in unique_roots],
            "total_local_skills_inspected": len(skill_files),
            "active_safe_skills_count": len(active_safe_skills),
            "blocked_unsafe_skills_count": len(blocked_unsafe_skills),
            "active_safe_skills": [s.to_dict() for s in active_safe_skills[:40]],
            "blocked_unsafe_skills": [s.to_dict() for s in blocked_unsafe_skills],
            "findings": [f.to_dict() for f in findings],
        }

    def _inspect_local_skill(
        self,
        sk_md: Path,
        src_type: str,
        match_terms: Dict[str, Set[str]],
        lang_terms: Set[str],
    ) -> Optional[LocalSkillAuditRecord]:
        text = _read_bounded_text(sk_md, MAX_SKILL_FILE_BYTES)
        if not text:
            return None

        name = sk_md.parent.name
        desc = ""
        fm = _SKILL_FRONTMATTER_RE.match(text)
        body = text
        if fm:
            front = fm.group(1)
            body = text[fm.end():]
            m_name = _SKILL_NAME_RE.search(front)
            m_desc = _SKILL_DESC_RE.search(front)
            if m_name:
                name = m_name.group(1).strip()
            if m_desc:
                desc = m_desc.group(1).strip().strip("\"'")

        # Audit SKILL.md + sibling helper scripts inside the skill folder
        is_safe, reasons = audit_skill_content_safety(text, sk_md.name)
        skill_dir = sk_md.parent
        sibling_scripts = [
            p
            for p in skill_dir.rglob("*")
            if p.is_file()
            and p != sk_md
            and p.suffix.lower() in {".py", ".sh", ".ps1", ".js", ".ts", ".mjs", ".rb", ".bat", ".cmd"}
        ][:12]
        for sib in sibling_scripts:
            sib_text = _read_bounded_text(sib, MAX_SKILL_FILE_BYTES)
            sib_safe, sib_reasons = audit_skill_content_safety(sib_text, sib.name)
            if not sib_safe:
                is_safe = False
                reasons.extend(sib_reasons)

        # Score relevance against active domains/protocols/PQC/languages
        haystack = f"{name}\n{desc}\n{body[:2500]}".lower()
        matched_cats: List[str] = []
        score = 0.0
        for cat, terms in match_terms.items():
            hits = sum(1 for t in terms if len(t) >= 3 and t in haystack)
            if hits > 0:
                matched_cats.append(cat)
                score += min(10.0, float(hits) * 2.0)
        lang_hits = sum(
            1
            for lt in lang_terms
            if len(lt) >= 3 and re.search(rf"(?<![a-z0-9_]){re.escape(lt)}(?![a-z0-9_])", haystack)
        )
        score += min(6.0, float(lang_hits) * 1.5)
        if src_type == "workspace":
            score += 3.0

        preview_lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")][:3]
        preview = " ".join(preview_lines)[:240]

        return LocalSkillAuditRecord(
            name=name,
            description=desc[:240],
            skill_md_path=str(sk_md),
            source_type=src_type,
            matched_categories=sorted(matched_cats),
            relevance_score=round(score, 2),
            safety_status="SAFE" if is_safe else "BLOCKED_UNSAFE",
            safety_reasons=reasons,
            guidelines_preview=preview if is_safe else "[QUARANTINED_UNSAFE]",
        )

    @staticmethod
    def _discover_rfchunt_registry_skills(
        match_terms: Dict[str, Set[str]],
        lang_terms: Set[str],
    ) -> List[LocalSkillAuditRecord]:
        records: List[LocalSkillAuditRecord] = []
        try:
            from engine.last30days_security_skills import BUILTIN_LAST30DAYS_SECURITY_SKILLS

            for spec in BUILTIN_LAST30DAYS_SECURITY_SKILLS:
                hay = f"{spec.skill_slug} {spec.title} {spec.summary}".lower()
                matched_cats = [
                    cat
                    for cat, terms in match_terms.items()
                    if any(len(t) >= 3 and t in hay for t in terms)
                ]
                if not matched_cats and not any(len(lt) >= 3 and lt in hay for lt in lang_terms):
                    continue
                records.append(
                    LocalSkillAuditRecord(
                        name=spec.skill_slug,
                        description=spec.title,
                        skill_md_path=spec.skill_md_path or f"registry://last30days/{spec.skill_id}",
                        source_type="rfchunt_registry",
                        matched_categories=sorted(matched_cats),
                        relevance_score=round(min(10.0, 2.5 + 2.0 * len(matched_cats)), 2),
                        safety_status="SAFE",
                        guidelines_preview=spec.summary[:220],
                    )
                )
        except Exception:
            pass

        try:
            from engine.arxiv_security_bridge import BUILTIN_RESEARCH_DETECTORS

            for det in BUILTIN_RESEARCH_DETECTORS:
                hay = f"{det.detector_id} {det.title} {det.summary}".lower()
                matched_cats = [
                    cat
                    for cat, terms in match_terms.items()
                    if any(len(t) >= 3 and t in hay for t in terms)
                ]
                if not matched_cats:
                    continue
                records.append(
                    LocalSkillAuditRecord(
                        name=det.detector_id.lower(),
                        description=f"arXiv:{det.arxiv_id} — {det.title}",
                        skill_md_path=f"registry://arxiv/{det.arxiv_id}",
                        source_type="rfchunt_registry",
                        matched_categories=sorted(matched_cats),
                        relevance_score=round(min(10.0, 2.0 + 1.8 * len(matched_cats)), 2),
                        safety_status="SAFE",
                        guidelines_preview=det.defense_countermeasure[:220],
                    )
                )
        except Exception:
            pass

        return records


# ==============================================================================
# 4. Conditional Fresh Live Keyless Research Runner (Zero Cross-Session Cache)
# ==============================================================================

class FreshLiveResearchRunner:
    """
    Executes fresh, zero-API-key live lookups anchored to the current year and
    exact workspace dependency versions with `Cache-Control: no-cache, no-store`.
    """

    DEFAULT_ENDPOINTS: Dict[str, str] = {
        "osv_batch": "https://api.osv.dev/v1/querybatch",
        "ietf_doc": "https://datatracker.ietf.org/api/v1/doc/document/{doc}/",
        "arxiv_atom": "https://export.arxiv.org/api/query",
        "hn_algolia": "https://hn.algolia.com/api/v1/search_by_date",
        "devto_articles": "https://dev.to/api/articles",
    }

    def __init__(
        self,
        *,
        timeout_per_req: float = 5.0,
        total_budget_sec: float = 15.0,
        endpoints: Optional[Dict[str, str]] = None,
    ) -> None:
        self.timeout_per_req = max(1.0, float(timeout_per_req))
        self.total_budget_sec = max(2.0, float(total_budget_sec))
        self.endpoints = dict(self.DEFAULT_ENDPOINTS)
        if endpoints:
            self.endpoints.update(endpoints)

    def _http_request(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, str]:
        data_bytes: Optional[bytes] = None
        headers = {
            "User-Agent": "RFCHunt-PreflightDiscovery/2.0 (Keyless Fresh Research)",
            "Accept": "application/json, application/atom+xml, text/plain;q=0.8",
            "Cache-Control": "no-cache, no-store, max-age=0",
            "Pragma": "no-cache",
        }
        if json_body is not None:
            data_bytes = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=self.timeout_per_req) as resp:
            status = int(getattr(resp, "status", 200))
            raw = resp.read(MAX_HTTP_RESPONSE_BYTES)
            return status, raw.decode("utf-8", errors="replace")

    def execute_fresh_research(
        self,
        *,
        active_categories: Sequence[str],
        dependencies: Sequence[DetectedDependency],
        current_year: int,
        run_id: str,
    ) -> Dict[str, Any]:
        started = time.monotonic()
        osv_advisories: List[Dict[str, Any]] = []
        ietf_docs: List[Dict[str, Any]] = []
        arxiv_papers: List[Dict[str, Any]] = []
        community_advisories: List[Dict[str, Any]] = []
        findings: List[PreflightFinding] = []
        lanes_attempted: List[str] = []
        lane_errors: Dict[str, str] = {}

        # Collect versioned deps eligible for OSV.dev batch lookup
        versioned_deps = [
            d
            for d in dependencies
            if d.ecosystem in {"PyPI", "npm", "crates.io", "Go", "Maven", "RubyGems", "Packagist", "NuGet", "Pub"}
            and d.version
            and re.match(r"^[vV]?[0-9]+\.[0-9]+", d.version)
        ][:MAX_OSV_BATCH_QUERIES]

        # Collect IETF RFC / draft names for active categories
        target_ietf_docs: List[str] = []
        for cat in active_categories:
            for doc in PREFLIGHT_TAXONOMY.get(cat, {}).get("ietf_docs", []):
                if doc not in target_ietf_docs:
                    target_ietf_docs.append(doc)
        target_ietf_docs = target_ietf_docs[:6]

        # Build concise current-year arXiv & HN queries covering detected domains + PQC
        domain_terms: List[str] = []
        for cat in active_categories[:4]:
            q = PREFLIGHT_TAXONOMY.get(cat, {}).get("live_query", "")
            if q:
                domain_terms.append(q.split()[0])
        if "post_quantum_crypto" in active_categories:
            arxiv_q = f"all:post-quantum ML-KEM ML-DSA security {current_year}"
        elif domain_terms:
            arxiv_q = f"all:({' OR '.join(domain_terms)}) security vulnerability {current_year}"
        else:
            arxiv_q = f"all:security vulnerability protocol {current_year}"

        hn_q = f"{' '.join(domain_terms[:3]) or 'security'} CVE vulnerability {current_year}"

        with ThreadPoolExecutor(max_workers=6) as pool:
            futs: Dict[Any, str] = {}
            if versioned_deps:
                lanes_attempted.append("osv_exact_version_cves")
                futs[pool.submit(self._query_osv_batch, versioned_deps)] = "osv_exact_version_cves"
            if target_ietf_docs:
                lanes_attempted.append("ietf_rfc_datatracker")
                futs[pool.submit(self._query_ietf_docs, target_ietf_docs)] = "ietf_rfc_datatracker"
            lanes_attempted.append("arxiv_current_year")
            futs[pool.submit(self._query_arxiv, arxiv_q, run_id)] = "arxiv_current_year"
            lanes_attempted.append("hackernews_current_year")
            futs[pool.submit(self._query_hn, hn_q)] = "hackernews_current_year"

            for fut in as_completed(futs, timeout=self.total_budget_sec):
                lane = futs[fut]
                try:
                    data = fut.result(timeout=max(0.5, self.total_budget_sec - (time.monotonic() - started)))
                    if lane == "osv_exact_version_cves":
                        osv_advisories, osv_findings = data
                        findings.extend(osv_findings)
                    elif lane == "ietf_rfc_datatracker":
                        ietf_docs = data
                    elif lane == "arxiv_current_year":
                        arxiv_papers = data
                    elif lane == "hackernews_current_year":
                        community_advisories = data
                except Exception as exc:
                    lane_errors[lane] = str(exc)[:180]

        return {
            "status": "executed_fresh_live",
            "cache_reused": False,
            "current_year": current_year,
            "elapsed_sec": round(time.monotonic() - started, 3),
            "lanes_attempted": lanes_attempted,
            "lane_errors": lane_errors,
            "osv_exact_version_cves": osv_advisories,
            "ietf_specifications": ietf_docs,
            "arxiv_recent_papers": arxiv_papers,
            "community_advisories": community_advisories,
            "findings": [f.to_dict() for f in findings],
        }

    def _query_osv_batch(
        self,
        deps: Sequence[DetectedDependency],
    ) -> Tuple[List[Dict[str, Any]], List[PreflightFinding]]:
        queries = [
            {
                "version": d.version.lstrip("vV") if d.ecosystem != "Go" else d.version,
                "package": {"name": d.name, "ecosystem": d.ecosystem},
            }
            for d in deps
        ]
        _, raw = self._http_request(
            self.endpoints["osv_batch"],
            method="POST",
            json_body={"queries": queries},
        )
        parsed = json.loads(raw)
        results = parsed.get("results") or []
        advisories: List[Dict[str, Any]] = []
        findings: List[PreflightFinding] = []
        for dep, res_item in zip(deps, results):
            vulns = res_item.get("vulns") or []
            for v in vulns[:5]:
                vid = str(v.get("id") or "OSV-UNKNOWN")
                summary = str(v.get("summary") or v.get("modified") or "Known vulnerability in workspace dependency")
                advisories.append(
                    {
                        "id": vid,
                        "ecosystem": dep.ecosystem,
                        "package": dep.name,
                        "version": dep.version,
                        "source_file": dep.source_file,
                        "summary": summary[:220],
                    }
                )
                findings.append(
                    PreflightFinding(
                        rule_id=f"OSV-{vid}",
                        category="supply_chain_cve",
                        severity="HIGH",
                        cwe_id="CWE-1395",
                        title=f"Known Dependency Advisory {vid} in {dep.ecosystem} {dep.name}@{dep.version}",
                        file=dep.source_file,
                        line=1,
                        evidence=f"{dep.ecosystem}:{dep.name}=={dep.version} -> {vid}: {summary[:160]}",
                        remediation=f"Upgrade {dep.name} beyond vulnerable version {dep.version} per advisory {vid}.",
                        scanner="PreflightOSVExactVersionCVE",
                    )
                )
        return advisories, findings

    def _query_ietf_docs(self, doc_names: Sequence[str]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for doc in doc_names:
            url = self.endpoints["ietf_doc"].format(doc=urllib.parse.quote(doc))
            try:
                _, raw = self._http_request(url, method="GET")
                data = json.loads(raw)
                out.append(
                    {
                        "name": str(data.get("name") or doc),
                        "title": str(data.get("title") or "")[:180],
                        "rev": str(data.get("rev") or ""),
                        "time": str(data.get("time") or ""),
                    }
                )
            except Exception:
                continue
        return out

    def _query_arxiv(self, query: str, run_id: str) -> List[Dict[str, Any]]:
        qs = urllib.parse.urlencode(
            {
                "search_query": query,
                "start": 0,
                "max_results": 5,
                "sortBy": "submittedDate",
                "sortOrder": "descending",
                "_fresh": run_id[:8],
            }
        )
        _, raw = self._http_request(f"{self.endpoints['arxiv_atom']}?{qs}", method="GET")
        if "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
            return []
        root = ET.fromstring(raw)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        papers: List[Dict[str, Any]] = []
        for entry in root.findall("atom:entry", ns)[:5]:
            title_el = entry.find("atom:title", ns)
            id_el = entry.find("atom:id", ns)
            pub_el = entry.find("atom:published", ns)
            title = " ".join((title_el.text or "").split()) if title_el is not None else ""
            if title:
                papers.append(
                    {
                        "id": (id_el.text or "").strip() if id_el is not None else "",
                        "title": title[:180],
                        "published": (pub_el.text or "").strip()[:10] if pub_el is not None else "",
                    }
                )
        return papers

    def _query_hn(self, query: str) -> List[Dict[str, Any]]:
        qs = urllib.parse.urlencode({"query": query, "tags": "story", "hitsPerPage": 5})
        _, raw = self._http_request(f"{self.endpoints['hn_algolia']}?{qs}", method="GET")
        data = json.loads(raw)
        items: List[Dict[str, Any]] = []
        for hit in (data.get("hits") or [])[:5]:
            title = str(hit.get("title") or "").strip()
            if title:
                items.append(
                    {
                        "title": title[:180],
                        "url": str(hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID', '')}"),
                        "created_at": str(hit.get("created_at") or "")[:10],
                        "points": int(hit.get("points") or 0),
                    }
                )
        return items


# ==============================================================================
# 5. Unified Pre-Flight Discovery Orchestrator (`PreflightDiscoveryEngine`)
# ==============================================================================

class PreflightDiscoveryEngine:
    """
    Runs a fresh, zero-cache pre-flight pass at the start of every RFCHunt run,
    classifying every active domain/protocol/PQC/language/HackerOne category,
    running conditional fresh live research, auditing local skills for safety,
    and emitting an actionable checklist & adaptive `--all` scanner plan.
    """

    def __init__(
        self,
        *,
        max_workers: Optional[int] = None,
        live_endpoints: Optional[Dict[str, str]] = None,
    ) -> None:
        self.inspector = WorkspaceStackInspector(max_workers=max_workers)
        self.pqc_auditor = PostQuantumPreflightAuditor(max_workers=max_workers)
        self.skill_gate = LocalSkillDiscoveryAndSafetyGate()
        self.live_endpoints = live_endpoints

    def run(
        self,
        *,
        target_path: Optional[str] = None,
        prompt: str = "",
        policy_text: str = "",
        target_host: Optional[str] = None,
        live: bool = True,
        enable_pqc: bool = True,
        include_home_skills: bool = True,
        extra_skills_dirs: Optional[Sequence[str]] = None,
        output_dir: Optional[str] = None,
        timeout_sec: float = 15.0,
        dry_run: bool = False,
        allow_live_in_tests: bool = False,
    ) -> Dict[str, Any]:
        t0 = time.monotonic()
        run_id = uuid.uuid4().hex
        now_utc = datetime.now(timezone.utc)
        started_at_utc = now_utc.isoformat()
        current_year = now_utc.year

        # 1. Inspect manifests, schemas, extensions, prompt, and dependency versions
        stack = self.inspector.inspect(
            target_path=target_path,
            prompt=prompt,
            policy_text=policy_text,
            target_host=target_host,
        )
        root_path = Path(stack["target_path"]) if stack["target_path"] else None
        dependencies: List[DetectedDependency] = stack["dependencies"]
        source_files: List[Path] = stack["source_files"]

        # 2. Classify across all 13 engineering/PQC/Web3 categories (+ languages as 14th)
        detected_domains = self._classify_domains(stack, dependencies)
        active_category_ids = [d["id"] for d in detected_domains]
        active_languages = [lang["language"] for lang in stack["languages"]]

        # 3. Determine offline / CI / dry-run live research policy (fail-closed)
        offline_or_ci = (
            os.environ.get("RFCHUNT_OFFLINE") == "1"
            or bool(os.environ.get("CI"))
            or bool(os.environ.get("GITHUB_ACTIONS"))
        )
        should_run_live = bool(live) and (not dry_run) and ((not offline_or_ci) or allow_live_in_tests)

        # 4. Run PQC static audit, local skill safety scan, and conditional fresh live research in parallel
        pqc_res: Dict[str, Any] = {
            "status": "disabled",
            "pqc_libraries_detected": [],
            "pqc_source_files_count": 0,
            "pqc_source_files": [],
            "classical_hndl_files_count": 0,
            "classical_hndl_files": [],
            "standards_checked": [],
            "total_findings": 0,
            "findings": [],
        }
        skills_res: Dict[str, Any] = {}
        live_res: Dict[str, Any] = {
            "status": "planned_dry_run" if dry_run else ("skipped_offline" if not should_run_live else "pending"),
            "cache_reused": False,
            "current_year": current_year,
            "lanes_attempted": [],
            "lane_errors": {},
            "osv_exact_version_cves": [],
            "ietf_specifications": [],
            "arxiv_recent_papers": [],
            "community_advisories": [],
            "findings": [],
        }

        with ThreadPoolExecutor(max_workers=3) as pool:
            fut_pqc = (
                pool.submit(self.pqc_auditor.audit, source_files, root_path, dependencies)
                if enable_pqc
                else None
            )
            fut_skills = pool.submit(
                self.skill_gate.discover_and_load,
                workspace_root=root_path,
                active_categories=active_category_ids,
                active_languages=active_languages,
                extra_skills_dirs=extra_skills_dirs,
                include_home_skills=include_home_skills,
                include_rfchunt_registries=True,
            )
            fut_live = None
            if should_run_live:
                runner = FreshLiveResearchRunner(
                    timeout_per_req=min(5.0, max(1.0, timeout_sec / 2.5)),
                    total_budget_sec=timeout_sec,
                    endpoints=self.live_endpoints,
                )
                fut_live = pool.submit(
                    runner.execute_fresh_research,
                    active_categories=active_category_ids,
                    dependencies=dependencies,
                    current_year=current_year,
                    run_id=run_id,
                )

            if fut_pqc is not None:
                pqc_res = fut_pqc.result()
            skills_res = fut_skills.result()
            if fut_live is not None:
                live_res = fut_live.result()

        # If PQC static auditor detected active PQC or classical HNDL code, ensure post_quantum_crypto is listed
        if (
            enable_pqc
            and (pqc_res["pqc_source_files_count"] > 0 or pqc_res["classical_hndl_files_count"] > 0)
            and "post_quantum_crypto" not in active_category_ids
        ):
            pqc_spec = PREFLIGHT_TAXONOMY["post_quantum_crypto"]
            evidence_bits = []
            if pqc_res["pqc_source_files_count"] > 0:
                evidence_bits.append(f"pqc_source_files:{pqc_res['pqc_source_files_count']}")
            if pqc_res["classical_hndl_files_count"] > 0:
                evidence_bits.append(f"hndl_classical_crypto_files:{pqc_res['classical_hndl_files_count']}")
            detected_domains.append(
                {
                    "id": "post_quantum_crypto",
                    "label": pqc_spec["label"],
                    "signals": evidence_bits,
                    "rfcs_and_specs": list(pqc_spec["rfcs_and_specs"]),
                    "hackerone_asset_types": list(pqc_spec["hackerone_asset_types"]),
                    "hackerone_cwes": list(pqc_spec["hackerone_cwes"]),
                    "rfchunt_modules": list(pqc_spec["rfchunt_modules"]),
                }
            )
            active_category_ids.append("post_quantum_crypto")

        # 5. Synthesize HackerOne category mapping, RFC/spec checklist & adaptive `--all` steering plan
        hackerone_map = self._build_hackerone_mapping(detected_domains)
        rfc_rules = self._collect_rfc_and_spec_rules(detected_domains)
        scanner_plan = self._build_adaptive_scanner_plan(
            detected_domains=detected_domains,
            active_languages=active_languages,
            pqc_res=pqc_res,
            current_year=current_year,
            should_run_live=should_run_live,
        )

        combined_findings: List[Dict[str, Any]] = []
        combined_findings.extend(pqc_res.get("findings") or [])
        combined_findings.extend(skills_res.get("findings") or [])
        combined_findings.extend(live_res.get("findings") or [])

        checklist: Dict[str, Any] = {
            "status": "dry_run_preflight_ready" if dry_run else "completed",
            "run_id": run_id,
            "started_at_utc": started_at_utc,
            "current_year": current_year,
            "cache_reused": False,
            "dry_run": bool(dry_run),
            "elapsed_sec": round(time.monotonic() - t0, 3),
            "target_path": stack["target_path"],
            "target_host": target_host or "",
            "manifests_parsed": stack["manifests_parsed"],
            "schemas_detected": stack["schemas_detected"],
            "ci_workflows_detected": stack["ci_workflows_detected"],
            "detected_languages": stack["languages"],
            "detected_dependencies_count": len(dependencies),
            "detected_dependencies": [d.to_dict() for d in dependencies[:120]],
            "detected_domains": detected_domains,
            "active_category_ids": active_category_ids,
            "hackerone_categories": hackerone_map,
            "rfc_and_spec_rules": rfc_rules,
            "post_quantum_readiness": pqc_res,
            "live_research": live_res,
            "skills": skills_res,
            "recommended_scanner_plan": scanner_plan,
            "total_findings": len(combined_findings),
            "findings": combined_findings,
        }

        checklist_md = self.render_markdown_checklist(checklist)
        checklist["checklist_markdown"] = checklist_md

        # Persist current-run observability artifacts (NEVER read back as cache!)
        if output_dir and not dry_run:
            out_p = Path(output_dir)
            out_p.mkdir(parents=True, exist_ok=True)
            json_path = out_p / "preflight_checklist.json"
            md_path = out_p / "preflight_checklist.md"
            json_payload = {k: v for k, v in checklist.items() if k != "checklist_markdown"}
            json_path.write_text(json.dumps(json_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            md_path.write_text(checklist_md, encoding="utf-8")
            checklist["artifacts"] = {
                "json": str(json_path),
                "markdown": str(md_path),
            }

        return checklist

    def _classify_domains(
        self,
        stack: Dict[str, Any],
        dependencies: Sequence[DetectedDependency],
    ) -> List[Dict[str, Any]]:
        dep_names = {d.name.lower() for d in dependencies}
        ext_set = set(stack["extensions_summary"].keys())
        fn_set = set(stack["filenames_seen"])
        ci_present = bool(stack["ci_workflows_detected"])
        schemas_lower = [s.lower() for s in stack["schemas_detected"]]
        prompt_text = stack["combined_prompt_text"]

        matched: List[Dict[str, Any]] = []
        for cat_id, spec in PREFLIGHT_TAXONOMY.items():
            signals: List[str] = []

            pkg_hits = sorted(dep_names & {p.lower() for p in spec["packages"]})
            if pkg_hits:
                signals.append(f"packages:{','.join(pkg_hits[:8])}")

            ext_hits = sorted(ext_set & spec["extensions"])
            if ext_hits:
                signals.append(f"extensions:{','.join(ext_hits[:6])}")

            fn_hits = sorted(fn_set & spec["filenames"])
            if fn_hits:
                signals.append(f"files:{','.join(fn_hits[:6])}")

            if cat_id == "devops_cloud_infra" and ci_present:
                signals.append(f"ci_workflows:{len(stack['ci_workflows_detected'])}")

            if cat_id == "apis_service_contracts":
                api_schemas = [s for s in schemas_lower if any(tok in s for tok in (".proto", ".graphql", ".gql", ".avsc", "openapi", "swagger", "asyncapi"))]
                if api_schemas:
                    signals.append(f"schemas:{len(api_schemas)}")

            if cat_id == "systems_kernel_security":
                ebpf_or_wasm = [s for s in schemas_lower if any(tok in s for tok in (".bpf.", ".ebpf.", ".wat", ".wasm"))]
                if ebpf_or_wasm:
                    signals.append(f"lowlevel_artifacts:{len(ebpf_or_wasm)}")

            kw_hits = [
                kw
                for kw in spec["keywords"]
                if re.search(rf"(?<![a-z0-9_]){re.escape(kw.lower())}(?![a-z0-9_])", prompt_text)
            ]
            if kw_hits:
                signals.append(f"prompt_keywords:{','.join(kw_hits[:6])}")

            if signals:
                matched.append(
                    {
                        "id": cat_id,
                        "label": spec["label"],
                        "signals": signals,
                        "rfcs_and_specs": list(spec["rfcs_and_specs"]),
                        "hackerone_asset_types": list(spec["hackerone_asset_types"]),
                        "hackerone_cwes": list(spec["hackerone_cwes"]),
                        "rfchunt_modules": list(spec["rfchunt_modules"]),
                    }
                )
        return matched

    @staticmethod
    def _build_hackerone_mapping(detected_domains: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        asset_types: Set[str] = set()
        cwe_counts: Dict[str, int] = {}
        categories_detail: List[Dict[str, Any]] = []
        for dom in detected_domains:
            for at in dom.get("hackerone_asset_types") or []:
                asset_types.add(at)
            for cwe in dom.get("hackerone_cwes") or []:
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            categories_detail.append(
                {
                    "domain_id": dom["id"],
                    "label": dom["label"],
                    "asset_types": dom.get("hackerone_asset_types") or [],
                    "priority_cwes": dom.get("hackerone_cwes") or [],
                }
            )
        prioritized_cwes = [k for k, _ in sorted(cwe_counts.items(), key=lambda kv: (-kv[1], kv[0]))]
        return {
            "asset_types": sorted(asset_types),
            "prioritized_cwes": prioritized_cwes,
            "categories": categories_detail,
        }

    @staticmethod
    def _collect_rfc_and_spec_rules(detected_domains: Sequence[Dict[str, Any]]) -> List[str]:
        seen: Set[str] = set()
        out: List[str] = []
        for dom in detected_domains:
            for rule in dom.get("rfcs_and_specs") or []:
                if rule not in seen:
                    seen.add(rule)
                    out.append(rule)
        return out

    @staticmethod
    def _build_adaptive_scanner_plan(
        *,
        detected_domains: Sequence[Dict[str, Any]],
        active_languages: Sequence[str],
        pqc_res: Dict[str, Any],
        current_year: int,
        should_run_live: bool,
    ) -> Dict[str, Any]:
        domain_ids = [d["id"] for d in detected_domains]
        modules_to_boost: List[str] = []
        nuclei_tags: List[str] = []
        arxiv_terms: List[str] = []
        last30days_terms: List[str] = []

        for did in domain_ids:
            spec = PREFLIGHT_TAXONOMY.get(did, {})
            for m in spec.get("rfchunt_modules", []):
                if m not in modules_to_boost:
                    modules_to_boost.append(m)
            for tag in spec.get("nuclei_tags", []):
                if tag not in nuclei_tags:
                    nuclei_tags.append(tag)
            lq = spec.get("live_query", "")
            if lq:
                arxiv_terms.append(lq.split()[0])
                last30days_terms.append(did.replace("_", " "))

        if "post_quantum_crypto" in domain_ids or pqc_res.get("pqc_source_files_count", 0) > 0:
            arxiv_terms.insert(0, "post-quantum ML-KEM ML-DSA FIPS-203 FIPS-204")
            last30days_terms.insert(0, "post-quantum cryptography PQC")

        lang_suffix = " ".join(active_languages[:4])
        tailored_arxiv_query = (
            f"{' '.join(arxiv_terms[:4])} {lang_suffix} security {current_year}".strip()
            if (arxiv_terms or lang_suffix)
            else f"application protocol AI security {current_year}"
        )
        tailored_last30days_topic = (
            f"{', '.join(last30days_terms[:4])} {lang_suffix} bug bounty {current_year}".strip()
            if (last30days_terms or lang_suffix)
            else f"bug bounty pentesting security {current_year}"
        )

        return {
            "focus_domains": domain_ids,
            "focus_languages": list(active_languages),
            "modules_to_boost": modules_to_boost,
            "recommended_nuclei_tags": nuclei_tags[:16],
            "tailored_arxiv_query": tailored_arxiv_query,
            "tailored_last30days_topic": tailored_last30days_topic,
            "enable_pqc_audit": bool(
                "post_quantum_crypto" in domain_ids
                or "identity_auth_crypto" in domain_ids
                or pqc_res.get("pqc_source_files_count", 0) > 0
                or pqc_res.get("classical_hndl_files_count", 0) > 0
            ),
            "enable_h2_desync": bool(
                "network_transport_messaging" in domain_ids
                or "apis_service_contracts" in domain_ids
                or "web_frontend" in domain_ids
            ),
            "sync_live_research_and_skills": bool(should_run_live),
        }

    @staticmethod
    def render_markdown_checklist(checklist: Dict[str, Any]) -> str:
        lines: List[str] = [
            "# RFCHunt Fresh Pre-Flight Research, Post-Quantum & Safe Skill Checklist",
            "",
            f"- **Run ID:** `{checklist['run_id']}`",
            f"- **Started (UTC):** `{checklist['started_at_utc']}`",
            f"- **Current Year Anchor:** `{checklist['current_year']}`",
            f"- **Prior-Session Cache Reused:** `{checklist['cache_reused']}` (guaranteed fresh)",
            f"- **Target Path:** `{checklist.get('target_path') or '(none)'}`",
            f"- **Elapsed:** `{checklist['elapsed_sec']}s`",
            "",
            "## 1. Detected Programming Languages & Versions",
        ]
        langs = checklist.get("detected_languages") or []
        if langs:
            for item in langs:
                ver = f" (`{item['runtime_version']}`)" if item.get("runtime_version") else ""
                lines.append(
                    f"- **{item['language']}**{ver} — {item['file_count']} files | Focus: {item.get('security_focus') or 'standard security checks'}"
                )
        else:
            lines.append("- None detected.")

        lines.extend(["", "## 2. Detected Domains, Protocols & HackerOne Categories"])
        doms = checklist.get("detected_domains") or []
        if doms:
            for d in doms:
                sigs = "; ".join(d.get("signals") or [])
                cwes = ", ".join(d.get("hackerone_cwes") or [])
                assets = ", ".join(d.get("hackerone_asset_types") or [])
                lines.append(f"- **{d['label']}** (`{d['id']}`)")
                lines.append(f"  - Signals: `{sigs}`")
                lines.append(f"  - HackerOne Assets: `{assets}` | Priority CWEs: `{cwes}`")
        else:
            lines.append("- No specialized domains matched.")

        pqc = checklist.get("post_quantum_readiness") or {}
        lines.extend([
            "",
            "## 3. Post-Quantum Cryptography (PQC) Readiness & Findings",
            f"- **Status:** `{pqc.get('status', 'unknown')}`",
            f"- **PQC Libraries Detected:** `{', '.join(pqc.get('pqc_libraries_detected') or []) or 'none'}`",
            f"- **PQC Source Files:** `{pqc.get('pqc_source_files_count', 0)}` | **Classical HNDL Files:** `{pqc.get('classical_hndl_files_count', 0)}`",
            f"- **PQC Findings:** `{pqc.get('total_findings', 0)}`",
        ])

        lines.extend(["", "## 4. Applicable RFCs, NIST FIPS & Security Specifications"])
        for rule in checklist.get("rfc_and_spec_rules") or ["(none)"]:
            lines.append(f"- {rule}")

        live = checklist.get("live_research") or {}
        lines.extend([
            "",
            "## 5. Fresh Live Research & Exact-Version Dependency Advisories",
            f"- **Live Research Status:** `{live.get('status', 'unknown')}`",
            f"- **Exact-Version OSV.dev CVEs:** `{len(live.get('osv_exact_version_cves') or [])}`",
            f"- **IETF Specs Fetched:** `{len(live.get('ietf_specifications') or [])}`",
            f"- **Current-Year arXiv Papers:** `{len(live.get('arxiv_recent_papers') or [])}`",
            f"- **Community Advisories:** `{len(live.get('community_advisories') or [])}`",
        ])

        sk = checklist.get("skills") or {}
        lines.extend([
            "",
            "## 6. Local & Registry Skill Discovery (Safety-Gated)",
            f"- **Local Skills Inspected:** `{sk.get('total_local_skills_inspected', 0)}`",
            f"- **Active SAFE Skills Loaded:** `{sk.get('active_safe_skills_count', 0)}`",
            f"- **BLOCKED UNSAFE Skills Quarantined:** `{sk.get('blocked_unsafe_skills_count', 0)}`",
        ])
        for s in (sk.get("active_safe_skills") or [])[:12]:
            lines.append(f"  - `[SAFE]` **{s['name']}** (`{s['source_type']}`, score={s['relevance_score']}) — {s.get('description') or s.get('guidelines_preview')}")
        for b in sk.get("blocked_unsafe_skills") or []:
            lines.append(f"  - `[BLOCKED_UNSAFE]` **{b['name']}** — {'; '.join(b.get('safety_reasons') or [])}")

        plan = checklist.get("recommended_scanner_plan") or {}
        lines.extend([
            "",
            "## 7. Adaptive `--all` Scanner Steering Plan",
            f"- **Modules Boosted:** `{', '.join(plan.get('modules_to_boost') or []) or 'default'}`",
            f"- **Tailored arXiv Query:** `{plan.get('tailored_arxiv_query', '')}`",
            f"- **Tailored Last30Days Topic:** `{plan.get('tailored_last30days_topic', '')}`",
            f"- **PQC Audit Enabled:** `{plan.get('enable_pqc_audit', False)}`",
            f"- **Recommended Nuclei Tags:** `{', '.join(plan.get('recommended_nuclei_tags') or []) or 'none'}`",
            "",
        ])
        return "\n".join(lines)


def run_preflight_discovery(
    target_path: Optional[str] = None,
    *,
    prompt: str = "",
    policy_text: str = "",
    target_host: Optional[str] = None,
    live: bool = True,
    enable_pqc: bool = True,
    include_home_skills: bool = True,
    extra_skills_dirs: Optional[Sequence[str]] = None,
    output_dir: Optional[str] = None,
    timeout_sec: float = 15.0,
    dry_run: bool = False,
    live_endpoints: Optional[Dict[str, str]] = None,
    allow_live_in_tests: bool = False,
) -> Dict[str, Any]:
    """Convenience entry point for running a fresh zero-cache RFCHunt pre-flight discovery pass."""
    engine = PreflightDiscoveryEngine(live_endpoints=live_endpoints)
    return engine.run(
        target_path=target_path,
        prompt=prompt,
        policy_text=policy_text,
        target_host=target_host,
        live=live,
        enable_pqc=enable_pqc,
        include_home_skills=include_home_skills,
        extra_skills_dirs=extra_skills_dirs,
        output_dir=output_dir,
        timeout_sec=timeout_sec,
        dry_run=dry_run,
        allow_live_in_tests=allow_live_in_tests,
    )
