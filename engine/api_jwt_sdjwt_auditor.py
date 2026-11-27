"""
Authorized API Surface (`subfinder`/`httpx`/`katana`/`schemathesis`) & JWT/SD-JWT Auditor (M1 / Component 3).
=============================================================================================================
Provides:
  1. Pure-Python offline cryptographic & OpenAPI static auditing (always runs):
     - `JWT-ALG-NONE-001` (`alg: none`, `verify_signature=False`, unverified `SignedJWT.parse`)
     - `JWT-ALG-CONFUSION-002` (mixed symmetric/asymmetric algorithms, unpinned public key verify)
     - `JWT-CLAIMS-MISSING-003` (`verify_exp=False`, `verify_aud=False`, `verify_iss=False`, missing nonce/c_nonce)
     - `JWT-HEADER-SSRF-004` (unpinned `jku`/`x5u` fetch, `kid` path traversal)
     - `SDJWT-BINDING-005` (SD-JWT `~` split without `_sd_alg`/`_sd`/`kb_jwt`/`cnf`/`sd_hash` checks)
     - `OPENAPI-AUTH-MISSING-006` (OpenAPI/Swagger unauthenticated state-changing or sensitive routes)
  2. Fail-closed authorized live pipeline (`subfinder` -> `httpx` -> `katana` -> `schemathesis`):
     - Disabled unless `allow_live=True and not embedded and not no_external_scanners` AND
       `ProgramEligibilityDB.is_eligible(program) == True` AND `validate_target_host` passes.
     - Enforces `TokenBucketRateLimiter` (`<= min(max_rps, 2.0)`) and required HackerOne attribution
       headers derived from `ProgramComplianceContext` / `HACKERONE_RESEARCHER_HANDLE`. Zero weaponized payloads.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from engine.external_scanners import (
    _find_non_python_httpx_on_path,
    _is_python_httpx_cli_binary,
)
from engine.host_containment import silent_subprocess_run
from engine.linux_poc_runner import validate_command_tokens, validate_mount_path
from engine.parity_invariant_auditor import is_non_production_noise
from engine.safe_network_validator import (
    _clean_host,
    is_cloud_metadata,
    is_explicit_loopback_host,
    is_safe_target_ip,
    validate_target_host,
)

_SKIP_DIRS: frozenset[str] = frozenset(
    {
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
)

_CODE_EXTS: frozenset[str] = frozenset(
    {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".go", ".java", ".kt", ".rb", ".rs"}
)
_SPEC_EXTS: frozenset[str] = frozenset({".yaml", ".yml", ".json"})
_MAX_FILE_BYTES = 1_048_576

_SENSITIVE_OPENAPI_PATHS: tuple[str, ...] = (
    "/admin",
    "/internal",
    "/status-lists",
    "/v1/mdvm",
    "/v1/pns",
    "/v1/rwsca",
    "/v1/wpb",
    "/token",
    "/credential",
)


def _make_finding(
    *,
    rule_id: str,
    title: str,
    cwe: str,
    severity: str,
    confidence: float,
    file_path: str,
    line: int,
    summary: str,
    metadata: dict[str, Any] | None = None,
    is_live: bool = False,
) -> dict[str, Any]:
    noise = False if is_live else is_non_production_noise(file_path)
    meta = dict(metadata or {})
    meta["non_production_noise"] = noise
    return {
        "engine": "api_jwt_sdjwt",
        "rule_id": rule_id,
        "title": title,
        "cwe": cwe,
        "severity": severity,
        "confidence": confidence,
        "file_path": file_path,
        "line": max(1, int(line)),
        "summary": summary,
        "deterministic": True,
        "confirmed": True,
        "non_production_noise": noise,
        "metadata": meta,
    }


def _audit_code_file(rel_path: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    def _emit(rule_id: str, title: str, cwe: str, severity: str, conf: float, pos: int, summary: str) -> None:
        line_no = text[:pos].count("\n") + 1
        key = (rule_id, line_no)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            _make_finding(
                rule_id=rule_id,
                title=title,
                cwe=cwe,
                severity=severity,
                confidence=conf,
                file_path=rel_path,
                line=line_no,
                summary=summary,
            )
        )

    def _extract_balanced_call(src: str, start_idx: int, open_paren_idx: int, max_chars: int = 600) -> str:
        depth = 0
        in_quote: str | None = None
        escaped = False
        limit = min(len(src), start_idx + max_chars)
        for idx in range(open_paren_idx, limit):
            ch = src[idx]
            if escaped:
                escaped = False
                continue
            if in_quote is not None:
                if ch == "\\":
                    escaped = True
                elif ch == in_quote:
                    in_quote = None
                continue
            if ch in ("'", '"', "`"):
                in_quote = ch
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return src[start_idx : idx + 1]
        return src[start_idx:limit]

    # 1. JWT-ALG-NONE-001
    for pat in (
        re.compile(r"""["']?\balgorithms\b["']?\s*[:=]\s*[\[\(][^\]\)]*["']none["']""", re.IGNORECASE),
        re.compile(r"""["']?\balg\b["']?\s*[:=]\s*["']none["']""", re.IGNORECASE),
        re.compile(r"""["']?\bverify_signature\b["']?\s*[:=]\s*(?:False|false)"""),
        re.compile(r"""\bjwt\.decode\s*\([^;\n]*\bverify\s*=\s*False"""),
        re.compile(r"""["']\bverify\b["']\s*:\s*(?:False|false)"""),
        re.compile(r"""\bjwt\.decodeUnverified\b"""),
    ):
        for m in pat.finditer(text):
            _emit(
                "JWT-ALG-NONE-001",
                "JWT signature verification disabled or `alg: none` accepted",
                "CWE-347",
                "CRITICAL",
                0.94,
                m.start(),
                f"JWT verification bypass pattern `{m.group(0)[:60]}` in {rel_path}.",
            )

    if "SignedJWT.parse" in text and ".verify(" not in text:
        pos = text.index("SignedJWT.parse")
        _emit(
            "JWT-ALG-NONE-001",
            "Nimbus SignedJWT.parse() called without .verify()",
            "CWE-347",
            "CRITICAL",
            0.90,
            pos,
            f"`SignedJWT.parse` used without `.verify(` in {rel_path}.",
        )

    # 2. JWT-ALG-CONFUSION-002
    asym_hmac_re = re.compile(
        r"""["']?\balgorithms\b["']?\s*[:=]\s*[\[\(]([^\]\)]+)[\]\)]""", re.IGNORECASE
    )
    for m in asym_hmac_re.finditer(text):
        inner = m.group(1).upper()
        if any(a in inner for a in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256")) and any(
            h in inner for h in ("HS256", "HS384", "HS512")
        ):
            _emit(
                "JWT-ALG-CONFUSION-002",
                "Mixed asymmetric and HMAC algorithms in JWT verification allowlist",
                "CWE-327",
                "HIGH",
                0.90,
                m.start(),
                f"Allowing both asymmetric and HS* algorithms enables RS256->HS256 key confusion in {rel_path}.",
            )

    for m in re.finditer(r"""\bjwt\.(?:verify|decode)\s*\(""", text, re.IGNORECASE):
        snippet = _extract_balanced_call(text, m.start(), m.end() - 1)
        if re.search(r"""(?:public_?key|pub_key|pem)""", snippet, re.IGNORECASE) and not re.search(
            r"""\balgorithms\b""", snippet, re.IGNORECASE
        ):
            _emit(
                "JWT-ALG-CONFUSION-002",
                "JWT verification with public key lacks explicit `algorithms` pinning",
                "CWE-327",
                "HIGH",
                0.85,
                m.start(),
                f"`jwt.verify/decode` with public key omits `algorithms` pin in {rel_path}.",
            )

    # 3. JWT-CLAIMS-MISSING-003
    for pat in (
        re.compile(r"""["']?\bverify_(?:exp|aud|iss)\b["']?\s*[:=]\s*(?:False|false)"""),
        re.compile(r"""["']?\bignoreExpiration\b["']?\s*:\s*true""", re.IGNORECASE),
    ):
        for m in pat.finditer(text):
            _emit(
                "JWT-CLAIMS-MISSING-003",
                "JWT critical claim validation disabled (`exp`/`aud`/`iss`)",
                "CWE-287",
                "HIGH",
                0.88,
                m.start(),
                f"Disabled claim validation (`{m.group(0)}`) in {rel_path}.",
            )

    if (
        re.search(r"""(?:openid4vci|openid4vp|oid4vci|c_nonce)""", text, re.IGNORECASE)
        and "jwt" in text.lower()
        and not re.search(r"""\b(?:nonce|c_nonce)\b""", text)
    ):
        pos = text.lower().find("oid4vci") if "oid4vci" in text.lower() else text.lower().find("openid4vci")
        _emit(
            "JWT-CLAIMS-MISSING-003",
            "OID4VCI/OID4VP verification handler missing `nonce`/`c_nonce` check",
            "CWE-287",
            "HIGH",
            0.80,
            max(0, pos),
            f"OID4VCI/VP flow in {rel_path} lacks explicit `nonce`/`c_nonce` verification.",
        )

    # 4. JWT-HEADER-SSRF-004
    for pat, msg in (
        (
            re.compile(r"""(?:header|hdr|unverified_header)\s*(?:\[|\.)\s*["']?(?:jku|x5u)["']?"""),
            "Unpinned `jku`/`x5u` JWT header referenced (check SSRF allowlist)",
        ),
        (
            re.compile(r"""(?:open|readFile|readFileSync|Path)\s*\([^)]*\bkid\b"""),
            "JWT `kid` header concatenated into filesystem path (path traversal risk)",
        ),
    ):
        for m in pat.finditer(text):
            snippet_ctx = text[max(0, m.start() - 120) : min(len(text), m.end() + 200)]
            if "validate_target_host" in snippet_ctx or "allowed_jku" in snippet_ctx or "allowlist" in snippet_ctx:
                continue
            _emit(
                "JWT-HEADER-SSRF-004",
                "Unpinned JWT header (`jku`/`x5u`/`kid`) SSRF or path traversal",
                "CWE-918",
                "HIGH",
                0.83,
                m.start(),
                f"{msg} in {rel_path}.",
            )

    # 5. SDJWT-BINDING-005
    for m in re.finditer(r"""\.split\s*\(\s*["']~["']\s*\)""", text):
        has_sd_alg = bool(re.search(r"""_sd_alg|sha-256|sha-384|sha-512""", text, re.IGNORECASE))
        has_sd_digest = bool(re.search(r"""_sd\b""", text))
        has_kb = bool(re.search(r"""(?:kb_jwt|sd_hash|\bcnf\b|key_binding)""", text, re.IGNORECASE))
        if not (has_sd_alg and has_sd_digest and has_kb):
            missing_parts = [
                name
                for name, ok in (("_sd_alg", has_sd_alg), ("_sd", has_sd_digest), ("kb_jwt/cnf/sd_hash", has_kb))
                if not ok
            ]
            _emit(
                "SDJWT-BINDING-005",
                "Incomplete SD-JWT selective-disclosure or holder key-binding verification",
                "CWE-345",
                "HIGH",
                0.86,
                m.start(),
                f"SD-JWT `~` split in {rel_path} misses verification for: {', '.join(missing_parts)}.",
            )

    return findings


def _audit_openapi_spec(rel_path: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        if rel_path.lower().endswith(".json"):
            doc = json.loads(text)
        else:
            doc = yaml.safe_load(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return findings

    if not isinstance(doc, dict):
        return findings
    if "openapi" not in doc and "swagger" not in doc:
        return findings

    lines = text.splitlines()

    def _find_line(needle: str, fallback_key: str = "servers") -> int:
        for idx, ln in enumerate(lines, start=1):
            if needle and needle in ln:
                return idx
        for idx, ln in enumerate(lines, start=1):
            if fallback_key in ln:
                return idx
        return 1

    def _is_ssrf_server_target(raw_target: str) -> tuple[bool, str, str]:
        s = str(raw_target or "").strip()
        if not s or (s.startswith("/") and not s.startswith("//")):
            return False, "", ""
        if "://" in s or s.startswith("//"):
            try:
                p = urlparse(s)
            except ValueError:
                return False, "", ""
            sch = (p.scheme or "").lower()
            if sch and sch not in ("http", "https"):
                return True, f"non-HTTP(S) server scheme `{sch}:`", "HIGH"
            host_cand = (p.hostname or "").strip("[] ").lower()
        else:
            host_cand = _clean_host(s)
        if not host_cand:
            return False, "", ""
        if "{" in host_cand or "}" in host_cand:
            return False, "", ""
        try:
            ip_obj = ipaddress.ip_address(host_cand)
            if is_cloud_metadata(ip_obj):
                return True, f"cloud metadata / link-local address `{host_cand}`", "CRITICAL"
            if not is_safe_target_ip(host_cand, allow_private=False):
                return True, f"private/loopback/reserved IP `{host_cand}`", "HIGH"
            return False, "", ""
        except ValueError:
            pass
        if (
            host_cand in ("localhost", "localhost.localdomain", "metadata.google.internal", "metadata")
            or host_cand.endswith((".localhost", ".internal", ".local"))
        ):
            sev = "CRITICAL" if "metadata" in host_cand else "HIGH"
            return True, f"internal/metadata hostname `{host_cand}`", sev
        return False, "", ""

    servers = doc.get("servers")
    if isinstance(servers, list):
        for srv in servers:
            if not isinstance(srv, dict):
                continue
            srv_url = str(srv.get("url") or "").strip()
            is_ssrf, reason, sev = _is_ssrf_server_target(srv_url)
            if is_ssrf:
                findings.append(
                    _make_finding(
                        rule_id="OPENAPI-SERVER-SSRF-007",
                        title=f"OpenAPI server URL targets restricted/metadata address `{srv_url}`",
                        cwe="CWE-918",
                        severity=sev,
                        confidence=0.92,
                        file_path=rel_path,
                        line=_find_line(srv_url, "servers"),
                        summary=f"OpenAPI `servers[].url` (`{srv_url}`) in {rel_path} references {reason}.",
                        metadata={"server_url": srv_url, "reason": reason},
                    )
                )

    swagger_host = doc.get("host")
    if isinstance(swagger_host, str) and swagger_host.strip():
        sh = swagger_host.strip()
        is_ssrf, reason, sev = _is_ssrf_server_target(sh)
        if is_ssrf:
            findings.append(
                _make_finding(
                    rule_id="OPENAPI-SERVER-SSRF-007",
                    title=f"Swagger host targets restricted/metadata address `{sh}`",
                    cwe="CWE-918",
                    severity=sev,
                    confidence=0.92,
                    file_path=rel_path,
                    line=_find_line(sh, "host"),
                    summary=f"Swagger `host` (`{sh}`) in {rel_path} references {reason}.",
                    metadata={"server_url": sh, "reason": reason},
                )
            )

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return findings

    top_security = doc.get("security")
    has_top_sec = isinstance(top_security, list) and len(top_security) > 0

    for route_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        route_str = str(route_path)
        is_sensitive_route = any(route_str.lower().startswith(p) or p in route_str.lower() for p in _SENSITIVE_OPENAPI_PATHS)
        for verb in ("post", "put", "patch", "delete", "get"):
            op = path_item.get(verb)
            if not isinstance(op, dict):
                continue
            if verb == "get" and not is_sensitive_route:
                continue
            op_sec = op.get("security")
            explicitly_open = isinstance(op_sec, list) and len(op_sec) == 0
            inherits_none = op_sec is None and not has_top_sec
            if explicitly_open or inherits_none:
                line_no = 1
                for idx, ln in enumerate(lines, start=1):
                    if route_str in ln:
                        line_no = idx
                        break
                findings.append(
                    _make_finding(
                        rule_id="OPENAPI-AUTH-MISSING-006",
                        title=f"Unauthenticated OpenAPI operation `{verb.upper()} {route_str}`",
                        cwe="CWE-306",
                        severity="HIGH" if is_sensitive_route else "MEDIUM",
                        confidence=0.84,
                        file_path=rel_path,
                        line=line_no,
                        summary=(
                            f"OpenAPI operation `{verb.upper()} {route_str}` in {rel_path} "
                            f"{'sets `security: []`' if explicitly_open else 'omits security schemes'}."
                        ),
                        metadata={"route": route_str, "method": verb.upper()},
                    )
                )
    return findings


def _which_is_unmocked() -> bool:
    return (
        getattr(shutil.which, "__module__", None) == "shutil"
        and getattr(shutil.which, "__qualname__", None) == "which"
    )


def _resolve_go_tool(name: str) -> str | None:
    cand = shutil.which(name)
    if cand:
        return cand
    if not _which_is_unmocked():
        return None
    suffixes = (".exe", "") if os.name == "nt" else ("",)
    extra_dirs = (
        Path.home() / "go" / "bin",
        Path(r"C:\Program Files\Go\bin"),
        Path(__file__).resolve().parent.parent / "bin",
    )
    for base in extra_dirs:
        if not base.is_dir():
            continue
        for suf in suffixes:
            cand_p = base / f"{name}{suf}"
            if cand_p.is_file():
                if os.name != "nt" and not os.access(str(cand_p), os.X_OK):
                    continue
                return str(cand_p)
    return None


def _resolve_pd_httpx() -> str | None:
    cand = shutil.which("httpx")
    if cand:
        if not _is_python_httpx_cli_binary(cand):
            return cand
        if _which_is_unmocked():
            alt = _find_non_python_httpx_on_path(cand)
            if alt:
                return alt
    if not _which_is_unmocked():
        return None
    suffixes = (".exe", "") if os.name == "nt" else ("",)
    extra_dirs = (
        Path.home() / "go" / "bin",
        Path(r"C:\Program Files\Go\bin"),
        Path(__file__).resolve().parent.parent / "bin",
    )
    for base in extra_dirs:
        if not base.is_dir():
            continue
        for suf in suffixes:
            cand_p = base / f"httpx{suf}"
            if cand_p.is_file():
                if os.name != "nt" and not os.access(str(cand_p), os.X_OK):
                    continue
                cand_s = str(cand_p)
                if not _is_python_httpx_cli_binary(cand_s):
                    return cand_s
    return None


def _resolve_schemathesis_argv() -> list[str] | None:
    cand = shutil.which("schemathesis")
    if cand:
        return [cand]
    if not _which_is_unmocked():
        return None
    try:
        spec = importlib.util.find_spec("schemathesis")
    except (ImportError, ValueError, AttributeError, OSError):
        spec = None
    if spec is not None:
        return [sys.executable, "-m", "schemathesis"]
    return None


def _extract_url_host(raw: str) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    if "://" in s:
        try:
            return (urlparse(s).hostname or "").strip("[] ").lower()
        except ValueError:
            return ""
    return _clean_host(s)


def _is_in_target_scope(cand_host: str, base_host: str) -> bool:
    c = (cand_host or "").strip("[] ").lower().rstrip(".")
    b = (base_host or "").strip("[] ").lower().rstrip(".")
    if not c or not b:
        return False
    if c == b:
        return True
    try:
        ipaddress.ip_address(b)
        return False
    except ValueError:
        pass
    return c.endswith("." + b)


def _is_valid_live_target(
    raw_url_or_host: str,
    *,
    base_host: str,
    allow_private: bool,
    rust_authorize: Any = None,
) -> bool:
    s = str(raw_url_or_host or "").strip()
    if not s or "@" in s:
        return False
    if "://" in s:
        try:
            p = urlparse(s)
        except ValueError:
            return False
        if (p.scheme or "").lower() not in ("http", "https"):
            return False
        if p.username is not None or p.password is not None:
            return False
    cand_host = _extract_url_host(s)
    if not cand_host:
        return False
    if not _is_in_target_scope(cand_host, base_host):
        return False
    ok_host, _ = validate_target_host(cand_host, allow_private=allow_private)
    if not ok_host:
        return False
    if rust_authorize is not None:
        try:
            if not rust_authorize(cand_host):
                return False
        except Exception:  # noqa: BLE001
            return False
    return True


def _parse_subfinder_jsonl(
    stdout: str,
    *,
    base_host: str,
    allow_private: bool,
    rust_authorize: Any = None,
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        cand = ""
        if line.startswith("{"):
            try:
                rec = json.loads(line)
                if isinstance(rec, dict):
                    cand = str(rec.get("host") or rec.get("domain") or rec.get("url") or "").strip()
            except json.JSONDecodeError:
                continue
        else:
            cand = line
        if not cand:
            continue
        if not _is_valid_live_target(
            cand,
            base_host=base_host,
            allow_private=allow_private,
            rust_authorize=rust_authorize,
        ):
            continue
        key = cand.lower()
        if key not in seen:
            seen.add(key)
            out.append(cand)
    return out


_OPENAPI_SPEC_SUFFIXES: tuple[str, ...] = (
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",
    "swagger.yaml",
    "v2/api-docs",
    "v3/api-docs",
)


def _parse_httpx_jsonl(
    stdout: str,
    *,
    base_host: str,
    allow_private: bool,
    rust_authorize: Any = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    live_spec_urls: list[str] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        rec_url = str(rec.get("url") or rec.get("final_url") or rec.get("input") or "").strip()
        if not rec_url or not _is_valid_live_target(
            rec_url,
            base_host=base_host,
            allow_private=allow_private,
            rust_authorize=rust_authorize,
        ):
            continue
        raw_sc = rec.get("status_code") if rec.get("status_code") is not None else rec.get("status-code")
        try:
            status_code: int | None = int(raw_sc) if raw_sc is not None else None
        except (TypeError, ValueError):
            status_code = None
        title = str(rec.get("title") or "").strip()
        raw_hdrs = rec.get("header") if isinstance(rec.get("header"), dict) else rec.get("headers")
        tech = rec.get("tech") if rec.get("tech") is not None else rec.get("technologies")

        try:
            url_path = (urlparse(rec_url).path or "/").lower()
        except ValueError:
            url_path = "/"

        high_paths = ("/admin", "/internal", "/actuator", "/metrics", "/debug")
        med_paths = (
            "/swagger",
            "/openapi",
            "/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/graphql",
            "/graphiql",
            "/redoc",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
        )
        is_high_exp = any(p in url_path for p in high_paths)
        is_med_exp = any(p in url_path for p in med_paths) or any(
            kw in title.lower() for kw in ("swagger", "openapi", "graphiql")
        )
        if (status_code is None or status_code < 400) and (is_high_exp or is_med_exp):
            findings.append(
                _make_finding(
                    rule_id="API-HTTPX-EXPOSURE-007",
                    title=f"Live API/admin/spec endpoint exposed at `{rec_url}`",
                    cwe="CWE-284" if is_high_exp else "CWE-200",
                    severity="HIGH" if is_high_exp else "MEDIUM",
                    confidence=0.84,
                    file_path=rec_url,
                    line=1,
                    summary=f"Live `httpx` probe discovered `{rec_url}` (status={status_code}, title={title!r}).",
                    metadata={"url": rec_url, "status_code": status_code, "title": title, "tech": tech},
                    is_live=True,
                )
            )
            if (
                any(tok in url_path or tok in title.lower() for tok in ("openapi", "swagger", "api-docs"))
                and rec_url not in live_spec_urls
            ):
                live_spec_urls.append(rec_url)

        if isinstance(raw_hdrs, dict) and len(raw_hdrs) > 0 and (status_code is None or 200 <= status_code < 400):
            hdr_map = {str(k).lower(): str(v) for k, v in raw_hdrs.items()}
            missing: list[str] = []
            if "content-security-policy" not in hdr_map:
                missing.append("Content-Security-Policy")
            if "x-content-type-options" not in hdr_map:
                missing.append("X-Content-Type-Options")
            if "x-frame-options" not in hdr_map and "frame-ancestors" not in hdr_map.get(
                "content-security-policy", ""
            ).lower():
                missing.append("X-Frame-Options")
            if rec_url.lower().startswith("https://") and "strict-transport-security" not in hdr_map:
                missing.append("Strict-Transport-Security")
            if missing:
                findings.append(
                    _make_finding(
                        rule_id="API-HTTPX-HEADERS-008",
                        title=f"Live endpoint `{rec_url}` missing {len(missing)} security header(s)",
                        cwe="CWE-693",
                        severity="MEDIUM" if len(missing) >= 3 else "LOW",
                        confidence=0.80,
                        file_path=rec_url,
                        line=1,
                        summary=f"Live `httpx` response for `{rec_url}` omits: {', '.join(missing)}.",
                        metadata={
                            "url": rec_url,
                            "missing_headers": missing,
                            "status_code": status_code,
                            "tech": tech,
                        },
                        is_live=True,
                    )
                )
    return findings, live_spec_urls


def _parse_katana_jsonl(
    stdout: str,
    *,
    base_host: str,
    allow_private: bool,
    rust_authorize: Any = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    live_spec_urls: list[str] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        req = rec.get("request") if isinstance(rec.get("request"), dict) else {}
        resp = rec.get("response") if isinstance(rec.get("response"), dict) else {}
        ep_url = str(
            req.get("endpoint") or req.get("url") or rec.get("endpoint") or rec.get("url") or ""
        ).strip()
        if not ep_url or not _is_valid_live_target(
            ep_url,
            base_host=base_host,
            allow_private=allow_private,
            rust_authorize=rust_authorize,
        ):
            continue
        method = str(req.get("method") or rec.get("method") or "GET").upper()
        raw_sc = (
            resp.get("status_code")
            if resp.get("status_code") is not None
            else (resp.get("status-code") if resp.get("status-code") is not None else rec.get("status_code"))
        )
        try:
            status_code: int | None = int(raw_sc) if raw_sc is not None else None
        except (TypeError, ValueError):
            status_code = None

        if status_code is not None and status_code >= 400:
            continue

        try:
            ep_path = (urlparse(ep_url).path or "/").lower()
        except ValueError:
            ep_path = "/"

        is_spec_ep = any(s in ep_path for s in _OPENAPI_SPEC_SUFFIXES) or ep_path.endswith(
            ("/openapi", "/swagger", "/api-docs")
        )
        if is_spec_ep:
            findings.append(
                _make_finding(
                    rule_id="API-KATANA-SPEC-009",
                    title=f"Exposed OpenAPI/Swagger specification discovered at `{ep_url}`",
                    cwe="CWE-200",
                    severity="MEDIUM",
                    confidence=0.86,
                    file_path=ep_url,
                    line=1,
                    summary=f"`katana` crawler discovered live OpenAPI/Swagger spec `{method} {ep_url}`.",
                    metadata={"url": ep_url, "method": method, "status_code": status_code},
                    is_live=True,
                )
            )
            if ep_url not in live_spec_urls:
                live_spec_urls.append(ep_url)
            continue

        is_high_ep = "/admin" in ep_path or "/internal" in ep_path
        is_med_ep = any(
            tok in ep_path
            for tok in (
                "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server",
                "/.well-known/jwks.json",
                "/graphql",
                "/graphiql",
                "/oauth",
                "/jwt",
            )
        ) or any(s in ep_path for s in _SENSITIVE_OPENAPI_PATHS)
        if is_high_ep or is_med_ep:
            findings.append(
                _make_finding(
                    rule_id="API-KATANA-ENDPOINT-010",
                    title=f"Sensitive live API/auth endpoint discovered at `{ep_url}`",
                    cwe="CWE-284" if is_high_ep else "CWE-200",
                    severity="HIGH" if is_high_ep else "MEDIUM",
                    confidence=0.82,
                    file_path=ep_url,
                    line=1,
                    summary=f"`katana` crawler discovered sensitive route `{method} {ep_url}`.",
                    metadata={"url": ep_url, "method": method, "status_code": status_code},
                    is_live=True,
                )
            )
    return findings, live_spec_urls


def _parse_schemathesis_output(
    stdout: str,
    stderr: str,
    returncode: int,
    *,
    spec_label: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_routes: set[str] = set()

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        status_str = str(rec.get("status") or "").upper()
        sc = rec.get("status_code")
        is_fail = status_str == "FAILURE" or "failure" in rec or (isinstance(sc, int) and sc >= 500)
        if is_fail:
            method = str(rec.get("method") or "UNKNOWN").upper()
            path = str(rec.get("path") or rec.get("endpoint") or "/")
            route_key = f"{method} {path}"
            if route_key in seen_routes:
                continue
            seen_routes.add(route_key)
            findings.append(
                _make_finding(
                    rule_id="API-SCHEMATHESIS-5XX-011",
                    title=f"Schemathesis detected server error on `{route_key}`",
                    cwe="CWE-755",
                    severity="HIGH",
                    confidence=0.89,
                    file_path=spec_label,
                    line=1,
                    summary=f"Non-destructive `schemathesis` probe triggered `not_a_server_error` failure on `{route_key}` ({spec_label}).",
                    metadata={"spec": spec_label, "route": route_key, "status_code": sc},
                    is_live=True,
                )
            )

    if findings:
        return findings

    if returncode != 0:
        combined = ((stdout or "") + "\n" + (stderr or "")).strip()
        low = combined.lower()
        markers = ("not_a_server_error", "500", "502", "503", "504", "server error", "failed", "status code")
        if any(mk in low for mk in markers):
            m_route = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[^\s\)\],;]*)", combined)
            route_str = f"{m_route.group(1)} {m_route.group(2)}" if m_route else spec_label
            findings.append(
                _make_finding(
                    rule_id="API-SCHEMATHESIS-5XX-011",
                    title=f"Schemathesis check failure on `{route_str}`",
                    cwe="CWE-755",
                    severity="HIGH",
                    confidence=0.87,
                    file_path=spec_label,
                    line=1,
                    summary=f"Non-destructive `schemathesis` run exited {returncode} on `{route_str}`: {combined[:220]}",
                    metadata={"spec": spec_label, "route": route_str, "returncode": returncode},
                    is_live=True,
                )
            )
    return findings


def _is_openapi_spec_file(path: Path) -> bool:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.lower() == ".json":
            doc = json.loads(text)
        else:
            doc = yaml.safe_load(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return False
    if not isinstance(doc, dict):
        return False
    if "openapi" not in doc and "swagger" not in doc:
        return False
    paths = doc.get("paths")
    return isinstance(paths, dict) and len(paths) > 0


def _run_authorized_live_pipeline(
    *,
    program: str,
    target_hosts: Sequence[str],
    eligibility_db: Any,
    max_rps: float,
    spec_targets: Sequence[Path | str] = (),
    repo_root: Path | None = None,
    researcher_handle: str | None = None,
) -> list[dict[str, Any]]:
    """
    Strictly fail-closed live API surface pipeline (`subfinder` -> `httpx` -> `katana` -> `schemathesis`).
    Hydrates `ProgramComplianceContext` to enforce Tier 1 prohibitions, exact DNS label-boundary
    scope allowlists, fractional sub-1 RPS pacing, per-program attribution headers, and no
    out-of-scope redirects.
    """
    from engine.request_hygiene import build_program_compliance_context

    ctx = build_program_compliance_context(
        program,
        eligibility_db=eligibility_db,
        researcher_handle=researcher_handle,
        max_rps_cap=min(max(0.05, float(max_rps)), 2.0),
    )
    if not ctx.eligible or not ctx.live_allowed or ctx.rate_limiter is None:
        return []

    limiter = ctx.rate_limiter
    eff_rps = ctx.effective_max_rps
    pd_rate_args: list[str] = (
        ["-rlm", str(max(1, round(eff_rps * 60.0)))]
        if eff_rps < 1.0
        else ["-rl", str(max(1, int(eff_rps)))]
    )
    cli_header_args: list[str] = []
    for hk, hv in ctx.to_cli_header_pairs():
        cli_header_args.extend(["-H", f"{hk}: {hv}"])

    safe_hosts: list[str] = []
    for raw_host in target_hosts:
        h = str(raw_host or "").strip()
        if not h or "@" in h:
            continue
        if "://" in h:
            try:
                p = urlparse(h)
            except ValueError:
                continue
            if (p.scheme or "").lower() not in ("http", "https"):
                continue
            if p.username is not None or p.password is not None or not p.hostname:
                continue
        ok_auth, _ = ctx.authorize_live_host(h, allow_loopback=True)
        if not ok_auth:
            continue
        safe_hosts.append(h)

    if not safe_hosts:
        return []

    # Optional Rust/Kani scope gatekeeper check if available
    try:
        from engine.rust_scope_bridge import authorize_intent as _rust_authorize  # type: ignore
    except ImportError:
        _rust_authorize = None

    findings: list[dict[str, Any]] = []
    seen_finding_keys: set[tuple[str, str, int]] = set()

    def _add_live_findings(items: Sequence[dict[str, Any]]) -> None:
        for item in items:
            key = (str(item.get("rule_id", "")), str(item.get("file_path", "")), int(item.get("line", 1)))
            if key not in seen_finding_keys:
                seen_finding_keys.add(key)
                findings.append(item)

    subfinder_bin = _resolve_go_tool("subfinder")
    httpx_bin = _resolve_pd_httpx()
    katana_bin = _resolve_go_tool("katana")
    schemathesis_argv = _resolve_schemathesis_argv()

    for host in safe_hosts:
        base_host = _extract_url_host(host)
        parent_is_loopback = is_explicit_loopback_host(base_host)
        scheme = urlparse(host).scheme.lower() if "://" in host else "https"

        if _rust_authorize is not None:
            try:
                if not _rust_authorize(base_host):
                    continue
            except Exception:  # noqa: BLE001, S112
                continue

        initial_url = host if host.startswith(("http://", "https://")) else f"https://{host}"
        discovered_urls: list[str] = [initial_url]
        live_spec_urls: list[str] = []

        is_ip_literal = False
        try:
            ipaddress.ip_address(base_host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

        if subfinder_bin and not parent_is_loopback and not is_ip_literal:
            cmd = [subfinder_bin, "-d", base_host, "-silent", "-json"]
            ok_cmd, _ = validate_command_tokens(cmd)
            if ok_cmd:
                limiter.acquire()
                try:
                    proc = silent_subprocess_run(
                        cmd,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=20.0,
                    )
                    sub_hits = _parse_subfinder_jsonl(
                        proc.stdout or "",
                        base_host=base_host,
                        allow_private=parent_is_loopback,
                        rust_authorize=_rust_authorize,
                    )
                    for sub in sub_hits:
                        ok_sub, _ = ctx.authorize_live_host(sub, allow_loopback=parent_is_loopback)
                        if not ok_sub:
                            continue
                        sub_url = sub if sub.startswith(("http://", "https://")) else f"{scheme}://{sub}"
                        if sub_url not in discovered_urls:
                            discovered_urls.append(sub_url)
                        sub_host = _extract_url_host(sub)
                        if sub_host.startswith(("admin.", "internal.", "staging.", "dev.", "swagger.", "oauth.", "oidc.")):
                            _add_live_findings(
                                [
                                    _make_finding(
                                        rule_id="API-SURFACE-SUBDOMAIN-007",
                                        title=f"Interesting API/admin subdomain discovered: `{sub_host}`",
                                        cwe="CWE-200",
                                        severity="LOW",
                                        confidence=0.75,
                                        file_path=sub_url,
                                        line=1,
                                        summary=f"`subfinder` discovered sensitive subdomain `{sub_host}` for `{base_host}`.",
                                        metadata={"subdomain": sub_host, "parent_host": base_host},
                                        is_live=True,
                                    )
                                ]
                            )
                except (OSError, subprocess.TimeoutExpired):
                    pass

        for url in discovered_urls[:5]:
            if httpx_bin:
                cmd = [
                    httpx_bin,
                    "-u",
                    url,
                    "-silent",
                    "-jsonl",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    *pd_rate_args,
                    *cli_header_args,
                ]
                ok_cmd, _ = validate_command_tokens(cmd)
                if ok_cmd:
                    limiter.acquire()
                    try:
                        proc = silent_subprocess_run(
                            cmd,
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            timeout=15.0,
                        )
                        hx_findings, hx_specs = _parse_httpx_jsonl(
                            proc.stdout or "",
                            base_host=base_host,
                            allow_private=parent_is_loopback,
                            rust_authorize=_rust_authorize,
                        )
                        _add_live_findings(hx_findings)
                        for sp in hx_specs:
                            if sp not in live_spec_urls:
                                live_spec_urls.append(sp)
                    except (OSError, subprocess.TimeoutExpired):
                        pass

            if katana_bin:
                cmd = [
                    katana_bin,
                    "-u",
                    url,
                    "-silent",
                    "-jsonl",
                    "-d",
                    "2",
                    *pd_rate_args,
                    *cli_header_args,
                ]
                ok_cmd, _ = validate_command_tokens(cmd)
                if ok_cmd:
                    limiter.acquire()
                    try:
                        proc = silent_subprocess_run(
                            cmd,
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            timeout=20.0,
                        )
                        kt_findings, kt_specs = _parse_katana_jsonl(
                            proc.stdout or "",
                            base_host=base_host,
                            allow_private=parent_is_loopback,
                            rust_authorize=_rust_authorize,
                        )
                        _add_live_findings(kt_findings)
                        for sp in kt_specs:
                            if sp not in live_spec_urls:
                                live_spec_urls.append(sp)
                    except (OSError, subprocess.TimeoutExpired):
                        pass

        if schemathesis_argv:
            schemathesis_targets: list[tuple[str, str | None]] = []
            seen_specs: set[str] = set()
            for sp_url in live_spec_urls[:3]:
                if sp_url not in seen_specs:
                    seen_specs.add(sp_url)
                    schemathesis_targets.append((sp_url, None))
            if discovered_urls:
                primary_base = discovered_urls[0]
                local_added = 0
                for sp_path in spec_targets:
                    if local_added >= 2:
                        break
                    p_obj = Path(sp_path)
                    if not _is_openapi_spec_file(p_obj):
                        continue
                    p_str = str(p_obj)
                    if p_str not in seen_specs:
                        seen_specs.add(p_str)
                        schemathesis_targets.append((p_str, primary_base))
                        local_added += 1

            sch_rate = f"{max(1, round(eff_rps * 60.0))}/m" if eff_rps < 1.0 else f"{int(eff_rps)}/s"
            for spec_target, base_url_opt in schemathesis_targets[:3]:
                target_check = base_url_opt if base_url_opt is not None else spec_target
                if not _is_valid_live_target(
                    target_check,
                    base_host=base_host,
                    allow_private=parent_is_loopback,
                    rust_authorize=_rust_authorize,
                ):
                    continue
                cmd = [
                    *schemathesis_argv,
                    "run",
                    "--checks=not_a_server_error",
                    "--max-examples=5",
                    f"--rate-limit={sch_rate}",
                    *cli_header_args,
                ]
                if base_url_opt is not None:
                    cmd.extend(["--url", base_url_opt, str(spec_target)])
                else:
                    cmd.append(str(spec_target))
                ok_cmd, _ = validate_command_tokens(cmd)
                if not ok_cmd:
                    continue
                limiter.acquire()
                spec_label = str(spec_target)
                if base_url_opt is not None and repo_root is not None:
                    try:
                        spec_label = Path(spec_target).relative_to(repo_root).as_posix()
                    except ValueError:
                        spec_label = str(spec_target)
                try:
                    proc = silent_subprocess_run(
                        cmd,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=30.0,
                    )
                    sch_findings = _parse_schemathesis_output(
                        proc.stdout or "",
                        proc.stderr or "",
                        proc.returncode,
                        spec_label=spec_label,
                    )
                    _add_live_findings(sch_findings)
                except (OSError, subprocess.TimeoutExpired):
                    pass

    return findings


def audit_api_and_jwt(
    repo_path: Path | str,
    *,
    program: str = "",
    embedded: bool = False,
    no_external_scanners: bool = False,
    allow_live: bool = False,
    eligibility_db: Any = None,
    max_rps: float = 2.0,
    target_hosts: Sequence[str] | None = None,
    target_files: Sequence[Path | str] | None = None,
    researcher_handle: str | None = None,
) -> list[dict[str, Any]]:
    """
    Runs offline JWT/JWS/SD-JWT/OID4VCI and OpenAPI authentication auditing across `repo_path`
    (or strictly scoped to `target_files` when provided for fast `<72h` diff scanning).
    Live API pipeline (`subfinder`/`httpx`/`katana`/`schemathesis`) remains disabled unless
    `allow_live=True and not embedded and not no_external_scanners` AND `ProgramComplianceContext.live_allowed`.
    """
    ok_mount, resolved_repo = validate_mount_path(repo_path)
    if not ok_mount:
        return []
    root = Path(resolved_repo)

    code_targets: list[Path] = []
    spec_targets: list[Path] = []
    if target_files is not None:
        seen_paths: set[Path] = set()
        for raw_f in target_files:
            cand = Path(raw_f)
            cand = (root / cand).resolve() if not cand.is_absolute() else cand.resolve()
            try:
                cand.relative_to(root)
            except ValueError:
                continue
            if cand in seen_paths or not cand.is_file():
                continue
            seen_paths.add(cand)
            ext = cand.suffix.lower()
            if ext in _CODE_EXTS:
                code_targets.append(cand)
            elif ext in _SPEC_EXTS:
                spec_targets.append(cand)
    else:
        for walk_root, dirs, filenames in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
            for fname in sorted(filenames):
                fpath = Path(walk_root) / fname
                ext = fpath.suffix.lower()
                if ext in _CODE_EXTS:
                    code_targets.append(fpath)
                elif ext in _SPEC_EXTS:
                    spec_targets.append(fpath)

    def _scan_path(fpath: Path, is_spec: bool) -> list[dict[str, Any]]:
        try:
            rel = fpath.relative_to(root).as_posix()
            if fpath.stat().st_size > _MAX_FILE_BYTES:
                return []
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return _audit_openapi_spec(rel, text) if is_spec else _audit_code_file(rel, text)

    max_workers = min(8, max(2, os.cpu_count() or 4))
    findings: list[dict[str, Any]] = []
    if code_targets or spec_targets:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_scan_path, p, False) for p in code_targets] + [
                pool.submit(_scan_path, p, True) for p in spec_targets
            ]
            for fut in futures:
                findings.extend(fut.result())

    if allow_live and not embedded and not no_external_scanners and target_hosts:
        findings.extend(
            _run_authorized_live_pipeline(
                program=program,
                target_hosts=target_hosts,
                eligibility_db=eligibility_db,
                max_rps=max_rps,
                spec_targets=spec_targets,
                repo_root=root,
                researcher_handle=researcher_handle,
            )
        )

    findings.sort(key=lambda f: (f["file_path"], f["line"], f["rule_id"]))
    return findings
