"""
Automated Z3 Formal Invariant Verifier (M1: F1-F5) for RFCHunt.

Strictly defensive formal verification engine using `z3-solver` over:
  - F1: OpenAPI 3.x / Swagger 2.0 specifications (deterministic JSON/YAML parser)
  - F2: IAM Policies (deterministic JSON/YAML parser with explicit Deny precedence)
  - F3: Application State Machines (deterministic JSON/YAML parser)
  - F4: Optional model-assisted formal-state translation (sanitized, schema-validated,
        gracefully disabled when offline or embedded)
  - F5: Z3 symbolic invariant solver, bounded multi-step reachability, defensive
        counterexample/proof reporting, EngineFinding & SARIF 2.1.0 output, and
        fail-closed optional `scope_bridge` pre-gate hook.

Never generates weaponized exploit scripts, HTTP wire payloads, or shell commands.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import urlparse

import httpx
import yaml
import z3

from engine.ensemble_orchestrator import EngineFinding
from engine.execution_policy import sanitize_for_llm_prompt, validate_llm_json_response
from engine.gha_llm_verifier import resolve_gha_llm_backend
from model_adapter import ModelFusionAdapter

# ---------------------------------------------------------------------------
# Status Constants & Exceptions
# ---------------------------------------------------------------------------

STATUS_SAT_VIOLATION = "SAT_VIOLATION"
STATUS_UNSAT_PROVEN = "UNSAT_PROVEN"
STATUS_UNKNOWN = "UNKNOWN"

_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_PRIVILEGED_ROUTE_TOKENS = (
    "/admin",
    "/internal",
    "/root",
    "/system",
    "/billing",
    "/iam",
    "/role",
    "/roles",
    "/permissions",
    "/export",
    "/config",
    "/audit",
    "/rpc",
    "/agent",
    "/service",
    "/worker",
    "/debug",
    "/metrics",
)

_PUBLIC_AUTH_PATHS = frozenset(
    {
        "/login",
        "/signin",
        "/signup",
        "/register",
        "/auth/login",
        "/auth/signin",
        "/auth/signup",
        "/auth/register",
        "/auth/token",
        "/oauth/token",
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/ping",
        "/version",
        "/openapi.json",
        "/docs",
    }
)

_PRIVILEGED_ROLE_TOKENS = frozenset(
    {
        "admin",
        "administrator",
        "superadmin",
        "superuser",
        "root",
        "operator",
        "staff",
        "owner",
        "service",
        "system",
    }
)

_LOW_PRIVILEGE_ROLES = ("anonymous", "guest", "user", "readonly")

_TENANT_PARAM_NAMES = frozenset(
    {
        "tenant_id",
        "tenantid",
        "org_id",
        "orgid",
        "organization_id",
        "organizationid",
        "account_id",
        "accountid",
        "workspace_id",
        "workspaceid",
        "user_id",
        "userid",
        "customer_id",
        "customerid",
    }
)

_TENANT_ROUTE_SEGMENT_RE = re.compile(
    r"/(?:tenants?|orgs?|organizations?|accounts?|workspaces?|users?|customers?)/\{[^}]+\}",
    re.IGNORECASE,
)

_WEAPONIZED_ARTIFACT_RE = re.compile(
    r"(?i)(?:\b(?:curl|sqlmap|nmap|wget|hydra|msfconsole|powershell|bash\s+-c)\b|HTTP/1\.[01]\s*\r?\n|#!/bin/)",
)


class ScopeGateDeniedError(PermissionError):
    """Raised (fail-closed) when a Rust/Python scope gate denies or errors."""


# ---------------------------------------------------------------------------
# Canonical IR & Verification Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class OpenApiEndpointIR:
    path: str
    method: str
    operation_id: str = ""
    auth_required: bool = True
    allows_anonymous: bool = False
    security_schemes: List[str] = field(default_factory=list)
    required_roles: List[str] = field(default_factory=list)
    required_scopes: List[str] = field(default_factory=list)
    is_privileged: bool = False
    is_state_changing: bool = False
    is_tenant_scoped: bool = False
    tenant_ownership_enforced: bool = False
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    line: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OpenApiModelIR:
    title: str
    version: str
    spec_format: str
    servers: List[str] = field(default_factory=list)
    security_schemes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    global_security: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: List[OpenApiEndpointIR] = field(default_factory=list)
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "version": self.version,
            "spec_format": self.spec_format,
            "servers": list(self.servers),
            "security_schemes": dict(self.security_schemes),
            "global_security": list(self.global_security),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "source_path": self.source_path,
        }


@dataclass
class IamStatementIR:
    sid: str
    effect: str
    principals: List[str] = field(default_factory=list)
    not_principals: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    not_actions: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    not_resources: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    line: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IamPolicyIR:
    version: str
    statements: List[IamStatementIR] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "statements": [s.to_dict() for s in self.statements],
            "roles": list(self.roles),
            "source_path": self.source_path,
        }


@dataclass
class StateTransitionIR:
    name: str
    from_state: str
    to_state: str
    action: str
    required_auth: bool = False
    required_roles: List[str] = field(default_factory=list)
    guards: Dict[str, Any] = field(default_factory=dict)
    same_tenant_required: bool = False
    sets_auth: Optional[bool] = None
    grants_role: Optional[str] = None
    sets_mfa: Optional[bool] = None
    line: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StateMachineIR:
    name: str
    initial_state: str
    states: List[str] = field(default_factory=list)
    privileged_states: List[str] = field(default_factory=list)
    transitions: List[StateTransitionIR] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    variables: Dict[str, str] = field(default_factory=dict)
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "initial_state": self.initial_state,
            "states": list(self.states),
            "privileged_states": list(self.privileged_states),
            "transitions": [t.to_dict() for t in self.transitions],
            "roles": list(self.roles),
            "variables": dict(self.variables),
            "source_path": self.source_path,
        }


@dataclass
class FormalVerificationFinding:
    finding_id: str
    domain: str
    invariant_name: str
    status: str
    severity: str
    cwe: str
    title: str
    summary: str
    file_path: str = ""
    line: int = 1
    counterexample: Dict[str, Any] = field(default_factory=dict)
    trace: List[Dict[str, Any]] = field(default_factory=list)
    proof_certificate: Dict[str, Any] = field(default_factory=dict)
    proof_summary: str = ""
    remediation: str = ""
    confidence: float = 0.94
    solver_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_engine_finding(self) -> EngineFinding:
        rule_id = f"Z3-{self.domain.upper()}-{self.invariant_name.upper()}"
        return EngineFinding(
            engine="z3_formal",
            title=self.title,
            file_path=self.file_path or self.domain,
            line=max(1, int(self.line or 1)),
            cwe=self.cwe,
            severity=self.severity,
            confidence=float(self.confidence),
            summary=self.summary,
            rule_id=rule_id,
            deterministic=True,
            confirmed=(self.status == STATUS_SAT_VIOLATION),
            metadata={
                "finding_id": self.finding_id,
                "z3_domain": self.domain,
                "invariant_name": self.invariant_name,
                "status": self.status,
                "counterexample": dict(self.counterexample),
                "trace": list(self.trace),
                "proof_certificate": dict(self.proof_certificate),
                "proof_summary": self.proof_summary,
                "remediation": self.remediation,
                "solver_time_ms": self.solver_time_ms,
            },
        )


@dataclass
class FormalVerificationReport:
    target: str
    status: str
    findings: List[FormalVerificationFinding] = field(default_factory=list)
    violations_count: int = 0
    proven_count: int = 0
    unknown_count: int = 0
    domains_verified: List[str] = field(default_factory=list)
    z3_version: str = field(default_factory=z3.get_version_string)
    llm_translation_telemetry: Dict[str, Any] = field(default_factory=dict)
    scope_gate_decision: Optional[Dict[str, Any]] = None
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "violations_count": self.violations_count,
            "proven_count": self.proven_count,
            "unknown_count": self.unknown_count,
            "domains_verified": list(self.domains_verified),
            "z3_version": self.z3_version,
            "llm_translation_telemetry": dict(self.llm_translation_telemetry),
            "scope_gate_decision": dict(self.scope_gate_decision)
            if isinstance(self.scope_gate_decision, dict)
            else self.scope_gate_decision,
            "generated_at_utc": self.generated_at_utc,
        }

    def to_engine_findings(self, include_proven: bool = False) -> List[EngineFinding]:
        selected = (
            self.findings
            if include_proven
            else [f for f in self.findings if f.status == STATUS_SAT_VIOLATION]
        )
        return [f.to_engine_finding() for f in selected]

    def to_sarif(self, include_proven: bool = False) -> Dict[str, Any]:
        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        selected = (
            self.findings
            if include_proven
            else [f for f in self.findings if f.status == STATUS_SAT_VIOLATION]
        )
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []
        for f in selected:
            rule_id = f"Z3-{f.domain.upper()}-{f.invariant_name.upper()}"
            if f.status == STATUS_SAT_VIOLATION:
                level = level_map.get(f.severity.upper(), "warning")
            else:
                level = "note"
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.summary or f.title},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "cwe": f.cwe,
                        "domain": f.domain,
                        "invariant": f.invariant_name,
                        "tags": ["security", "formal-verification", "z3", f.domain],
                    },
                }
            uri = (f.file_path or self.target or f"{f.domain}_spec").replace("\\", "/")
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": f"[{f.status}] {f.title}: {f.summary}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": max(1, int(f.line or 1))},
                            }
                        }
                    ],
                    "properties": {
                        "finding_id": f.finding_id,
                        "status": f.status,
                        "domain": f.domain,
                        "invariant_name": f.invariant_name,
                        "cwe": f.cwe,
                        "counterexample": dict(f.counterexample),
                        "trace": list(f.trace),
                        "proof_certificate": dict(f.proof_certificate),
                        "remediation": f.remediation,
                    },
                }
            )

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "RFCHunt-Z3-Formal-Verifier",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/oyesanyf/rfchunt",
                            "rules": list(rules_by_id.values()),
                        }
                    },
                    "results": results,
                    "properties": {
                        "target": self.target,
                        "status": self.status,
                        "z3_version": self.z3_version,
                        "violations_count": self.violations_count,
                        "proven_count": self.proven_count,
                        "unknown_count": self.unknown_count,
                        "domains_verified": list(self.domains_verified),
                    },
                }
            ],
        }


# ---------------------------------------------------------------------------
# Internal Input Loading & Defensive Text Helpers
# ---------------------------------------------------------------------------


def _load_structured_source(
    source: Union[str, Path, Dict[str, Any]],
    kind_label: str,
) -> Tuple[Dict[str, Any], str]:
    """Load JSON/YAML dict from a dict, file Path, path string, or raw JSON/YAML text."""
    if isinstance(source, dict):
        return source, ""

    source_path = ""
    raw_text = ""
    is_yaml_hint = False

    if isinstance(source, Path):
        if not source.is_file():
            raise FileNotFoundError(f"{kind_label} file not found: {source}")
        raw_text = source.read_text(encoding="utf-8-sig")
        source_path = str(source)
        is_yaml_hint = source.suffix.lower() in (".yml", ".yaml")
    elif isinstance(source, str):
        stripped = source.strip()
        if not stripped:
            raise ValueError(f"{kind_label} input cannot be empty.")
        looks_inline = (
            "\n" in source
            or "\r" in source
            or stripped.startswith(("{", "["))
            or len(stripped) >= 512
        )
        if not looks_inline:
            p = Path(stripped)
            try:
                exists = p.is_file()
            except OSError:
                exists = False
            if exists:
                raw_text = p.read_text(encoding="utf-8-sig")
                source_path = str(p)
                is_yaml_hint = p.suffix.lower() in (".yml", ".yaml")
            elif p.suffix.lower() in (".json", ".yml", ".yaml") and ":" not in stripped[2:]:
                raise FileNotFoundError(f"{kind_label} file not found: {p}")
            else:
                raw_text = source
        else:
            raw_text = source
    else:
        raise TypeError(
            f"{kind_label} source must be dict, Path, or str; got {type(source).__name__}."
        )

    parsed: Any = None
    if is_yaml_hint:
        parsed = yaml.safe_load(raw_text)
    else:
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            parsed = yaml.safe_load(raw_text)

    if not isinstance(parsed, dict):
        raise ValueError(f"Invalid {kind_label} document: expected JSON/YAML mapping.")
    return parsed, source_path


def _as_str_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, str):
        s = val.strip()
        return [s] if s else []
    if isinstance(val, (list, tuple, set)):
        out: List[str] = []
        for item in val:
            s = str(item).strip()
            if s:
                out.append(s)
        return out
    return [str(val).strip()] if str(val).strip() else []


def _dedupe_preserve(items: Sequence[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _deterministic_finding_id(domain: str, invariant_name: str, discriminator: str) -> str:
    digest = hashlib.sha256(
        f"{domain}|{invariant_name}|{discriminator}".encode("utf-8")
    ).hexdigest()[:12].upper()
    return f"Z3-{digest}"


def _formula_sha256(solver: z3.Solver) -> str:
    try:
        smt2 = solver.to_smt2()
    except Exception:
        smt2 = repr(solver.assertions())
    return hashlib.sha256(smt2.encode("utf-8", errors="replace")).hexdigest()


def _sanitize_defensive_text(text: str) -> str:
    """Ensure no weaponized command/wire artifact leaks into output strings."""
    cleaned = _WEAPONIZED_ARTIFACT_RE.sub("[defensive-redacted]", text or "")
    return cleaned.strip()


def _model_eval_int(model: z3.ModelRef, sym: z3.ArithRef, default: int = 0) -> int:
    val = model.eval(sym, model_completion=True)
    if z3.is_int_value(val):
        return int(val.as_long())
    return default


def _model_eval_bool(model: z3.ModelRef, sym: z3.BoolRef, default: bool = False) -> bool:
    val = model.eval(sym, model_completion=True)
    if z3.is_true(val):
        return True
    if z3.is_false(val):
        return False
    return default


# ---------------------------------------------------------------------------
# F1: OpenAPI 3.x / Swagger 2.0 Deterministic Parser
# ---------------------------------------------------------------------------


def parse_openapi_spec(source: Union[str, Path, Dict[str, Any]]) -> OpenApiModelIR:
    """Deterministically parse an OpenAPI 3.x or Swagger 2.0 spec into OpenApiModelIR."""
    spec, source_path = _load_structured_source(source, "OpenAPI/Swagger specification")

    if "openapi" not in spec and "swagger" not in spec and "paths" not in spec:
        raise ValueError(
            "Invalid OpenAPI/Swagger specification: missing 'openapi', 'swagger', or 'paths'."
        )

    spec_format = "swagger2" if "swagger" in spec and "openapi" not in spec else "openapi3"
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    title = str(info.get("title") or "Untitled API")
    version = str(info.get("version") or "0.0.0")

    servers: List[str] = []
    server_base_path = ""
    raw_servers = spec.get("servers")
    if isinstance(raw_servers, list):
        for srv in raw_servers:
            if not isinstance(srv, dict) or not srv.get("url"):
                continue
            url_str = str(srv["url"])
            srv_vars = srv.get("variables")
            if isinstance(srv_vars, dict):
                for v_name, v_spec in srv_vars.items():
                    if isinstance(v_spec, dict) and v_spec.get("default") is not None:
                        url_str = url_str.replace("{" + str(v_name) + "}", str(v_spec["default"]))
            servers.append(url_str)
            if not server_base_path:
                parsed_url = urlparse(url_str)
                if parsed_url.path and parsed_url.path != "/":
                    server_base_path = parsed_url.path.rstrip("/")
    elif spec.get("host"):
        schemes = spec.get("schemes") if isinstance(spec.get("schemes"), list) else ["https"]
        scheme = str(schemes[0]) if schemes else "https"
        bp = str(spec.get("basePath") or "").rstrip("/")
        servers.append(f"{scheme}://{spec['host']}{bp}")

    base_path = str(spec.get("basePath") or server_base_path or "").rstrip("/")

    raw_schemes = (
        (spec.get("components") or {}).get("securitySchemes")
        if isinstance(spec.get("components"), dict)
        else None
    )
    if not isinstance(raw_schemes, dict):
        raw_schemes = spec.get("securityDefinitions") if isinstance(spec.get("securityDefinitions"), dict) else {}

    security_schemes: Dict[str, Dict[str, Any]] = {
        str(k): (dict(v) if isinstance(v, dict) else {})
        for k, v in raw_schemes.items()
    }
    global_security = [
        dict(req)
        for req in (spec.get("security") or [])
        if isinstance(req, dict)
    ]

    paths = spec.get("paths")
    if paths is None:
        paths = {}
    if not isinstance(paths, dict):
        raise ValueError("Invalid OpenAPI/Swagger specification: 'paths' must be a mapping.")

    endpoints: List[OpenApiEndpointIR] = []
    for route_key, path_obj in paths.items():
        if not isinstance(path_obj, dict):
            continue
        full_route = f"{base_path}{route_key}" if base_path else str(route_key)
        path_params = [
            dict(p) for p in (path_obj.get("parameters") or []) if isinstance(p, dict)
        ]
        path_roles = _dedupe_preserve(
            _as_str_list(path_obj.get("x-required-role"))
            + _as_str_list(path_obj.get("x-required-roles"))
            + _as_str_list(path_obj.get("x-roles"))
        )

        for method_key, op in path_obj.items():
            if method_key.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            method = method_key.upper()
            operation_id = str(op.get("operationId") or f"{method.lower()}_{full_route}")

            # OpenAPI inheritance: operation-level "security" overrides top-level spec.security
            effective_sec = op.get("security") if "security" in op else spec.get("security")

            scheme_names: List[str] = []
            required_scopes: List[str] = []
            allows_anonymous = False
            auth_required = False

            if isinstance(effective_sec, list) and len(effective_sec) > 0:
                has_non_empty_req = False
                for req in effective_sec:
                    if not isinstance(req, dict):
                        continue
                    if len(req) == 0:
                        allows_anonymous = True
                    else:
                        has_non_empty_req = True
                        for s_name, s_scopes in req.items():
                            scheme_names.append(str(s_name))
                            required_scopes.extend(_as_str_list(s_scopes))
                auth_required = has_non_empty_req and not allows_anonymous
            else:
                allows_anonymous = True
                auth_required = False

            required_scopes.extend(_as_str_list(op.get("x-scopes")))
            explicit_roles = (
                path_roles
                + _as_str_list(op.get("x-required-role"))
                + _as_str_list(op.get("x-required-roles"))
                + _as_str_list(op.get("x-roles"))
                + _as_str_list(op.get("x-permissions"))
                + _as_str_list(op.get("x-auth-role"))
            )
            required_roles = list(explicit_roles)
            # Infer privileged role constraint from scopes only when auth is NOT optional
            if not allows_anonymous:
                for sc in required_scopes:
                    low_sc = sc.lower()
                    for role_tok in _PRIVILEGED_ROLE_TOKENS:
                        if role_tok in low_sc.replace(":", " ").replace("_", " ").split():
                            required_roles.append(role_tok)
                            break
                        if low_sc.startswith(f"{role_tok}:") or low_sc.endswith(f":{role_tok}"):
                            required_roles.append(role_tok)
                            break
            else:
                # Optional `{}` security branch does not enforce OAuth scopes on anonymous callers
                required_scopes = _as_str_list(op.get("x-scopes"))
            required_roles = _dedupe_preserve([r.lower() for r in required_roles])

            op_params = path_params + [
                dict(p) for p in (op.get("parameters") or []) if isinstance(p, dict)
            ]
            tags_lower = " ".join(str(t).lower() for t in (op.get("tags") or []))
            route_lower = full_route.lower()
            is_public_auth = route_lower in _PUBLIC_AUTH_PATHS

            is_privileged = (
                any(tok in route_lower for tok in _PRIVILEGED_ROUTE_TOKENS)
                or any(tok in tags_lower for tok in ("admin", "internal", "iam", "system", "billing", "security"))
                or any(r in _PRIVILEGED_ROLE_TOKENS for r in required_roles)
            )
            is_state_changing = method in _STATE_CHANGING_METHODS and not is_public_auth

            param_names_lower = {
                str(p.get("name") or "").strip().lower() for p in op_params
            }
            is_tenant_scoped = bool(
                (param_names_lower & _TENANT_PARAM_NAMES)
                or _TENANT_ROUTE_SEGMENT_RE.search(full_route)
            )
            tenant_ownership_enforced = bool(
                op.get("x-tenant-isolated")
                or op.get("x-tenant-check")
                or op.get("x-ownership-check")
                or str(op.get("x-tenant-policy") or "").strip().lower() in ("enforced", "strict", "isolated")
                or any("tenant:own" in sc.lower() or "tenant:strict" in sc.lower() for sc in required_scopes)
            )

            endpoints.append(
                OpenApiEndpointIR(
                    path=full_route,
                    method=method,
                    operation_id=operation_id,
                    auth_required=auth_required,
                    allows_anonymous=allows_anonymous,
                    security_schemes=_dedupe_preserve(scheme_names),
                    required_roles=required_roles,
                    required_scopes=_dedupe_preserve(required_scopes),
                    is_privileged=is_privileged,
                    is_state_changing=is_state_changing,
                    is_tenant_scoped=is_tenant_scoped,
                    tenant_ownership_enforced=tenant_ownership_enforced,
                    parameters=op_params,
                )
            )

    return OpenApiModelIR(
        title=title,
        version=version,
        spec_format=spec_format,
        servers=servers,
        security_schemes=security_schemes,
        global_security=global_security,
        endpoints=endpoints,
        source_path=source_path,
    )


# ---------------------------------------------------------------------------
# F2: IAM Policy Deterministic Parser
# ---------------------------------------------------------------------------


def _extract_iam_principals(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else []
    if isinstance(raw, list):
        out: List[str] = []
        for item in raw:
            out.extend(_extract_iam_principals(item))
        return _dedupe_preserve(out)
    if isinstance(raw, dict):
        out = []
        for _, v in raw.items():
            out.extend(_extract_iam_principals(v))
        return _dedupe_preserve(out)
    return [str(raw).strip()]


def parse_iam_policy(source: Union[str, Path, Dict[str, Any]]) -> IamPolicyIR:
    """Deterministically parse an IAM policy (JSON/YAML) into IamPolicyIR."""
    doc, source_path = _load_structured_source(source, "IAM policy")

    raw_stmts = doc.get("Statement") if "Statement" in doc else doc.get("statements")
    if isinstance(raw_stmts, dict):
        raw_stmts = [raw_stmts]
    if not isinstance(raw_stmts, list) or not raw_stmts:
        raise ValueError(
            "Invalid IAM policy: 'Statement' (or 'statements') must be a non-empty list or object."
        )

    version = str(doc.get("Version") or doc.get("version") or "2012-10-17")
    default_principals = _extract_iam_principals(
        doc.get("Principal") if "Principal" in doc else doc.get("principal")
    )
    roles: List[str] = list(default_principals)
    statements: List[IamStatementIR] = []

    for idx, stmt in enumerate(raw_stmts, start=1):
        if not isinstance(stmt, dict):
            raise ValueError(f"Invalid IAM statement at index {idx - 1}: expected mapping.")

        raw_effect = stmt.get("Effect") if "Effect" in stmt else stmt.get("effect")
        effect_norm = str(raw_effect or "").strip().lower()
        if effect_norm == "allow":
            effect = "Allow"
        elif effect_norm == "deny":
            effect = "Deny"
        else:
            raise ValueError(
                f"Invalid IAM statement Effect {raw_effect!r} at index {idx - 1}; expected 'Allow' or 'Deny'."
            )

        principals = _extract_iam_principals(
            stmt.get("Principal")
            if "Principal" in stmt
            else (stmt.get("principal") if "principal" in stmt else stmt.get("principals"))
        )
        not_principals = _extract_iam_principals(
            stmt.get("NotPrincipal") if "NotPrincipal" in stmt else stmt.get("not_principal")
        )
        if not principals and not not_principals:
            principals = list(default_principals) if default_principals else ["*"]

        actions = _dedupe_preserve(
            _as_str_list(
                stmt.get("Action")
                if "Action" in stmt
                else (stmt.get("action") if "action" in stmt else stmt.get("actions"))
            )
        )
        not_actions = _dedupe_preserve(
            _as_str_list(
                stmt.get("NotAction") if "NotAction" in stmt else stmt.get("not_action")
            )
        )
        if not actions and not not_actions:
            raise ValueError(
                f"Invalid IAM statement at index {idx - 1}: must specify 'Action' or 'NotAction'."
            )

        resources = _dedupe_preserve(
            _as_str_list(
                stmt.get("Resource")
                if "Resource" in stmt
                else (stmt.get("resource") if "resource" in stmt else stmt.get("resources"))
            )
        )
        not_resources = _dedupe_preserve(
            _as_str_list(
                stmt.get("NotResource") if "NotResource" in stmt else stmt.get("not_resource")
            )
        )
        if not resources and not not_resources:
            resources = ["*"]

        raw_cond = (
            stmt.get("Condition")
            if "Condition" in stmt
            else (stmt.get("condition") if "condition" in stmt else stmt.get("conditions"))
        )
        conditions = dict(raw_cond) if isinstance(raw_cond, dict) else {}

        sid = str(stmt.get("Sid") or stmt.get("sid") or f"Stmt{idx}")
        for p in principals + not_principals:
            if p and p != "*":
                roles.append(p)

        statements.append(
            IamStatementIR(
                sid=sid,
                effect=effect,
                principals=principals,
                not_principals=not_principals,
                actions=actions,
                not_actions=not_actions,
                resources=resources,
                not_resources=not_resources,
                conditions=conditions,
                line=idx,
            )
        )

    return IamPolicyIR(
        version=version,
        statements=statements,
        roles=_dedupe_preserve(roles),
        source_path=source_path,
    )


# ---------------------------------------------------------------------------
# F3: State Machine Deterministic Parser
# ---------------------------------------------------------------------------


def parse_state_machine(source: Union[str, Path, Dict[str, Any]]) -> StateMachineIR:
    """Deterministically parse a formal state machine definition (JSON/YAML)."""
    doc, source_path = _load_structured_source(source, "State machine")

    raw_states = doc.get("states")
    states = _dedupe_preserve(_as_str_list(raw_states))
    if not states:
        raise ValueError("Invalid state machine: 'states' must be a non-empty list.")

    initial_state = str(doc.get("initial_state") or doc.get("initial") or "").strip()
    if not initial_state or initial_state not in states:
        raise ValueError(
            f"Invalid state machine: 'initial_state' ({initial_state!r}) must be one of {states}."
        )

    raw_priv = (
        doc.get("privileged_states")
        or doc.get("admin_states")
        or doc.get("target_states")
        or []
    )
    privileged_states = _dedupe_preserve(_as_str_list(raw_priv))
    for ps in privileged_states:
        if ps not in states:
            raise ValueError(
                f"Invalid state machine: privileged state {ps!r} is not declared in 'states'."
            )
    if not privileged_states:
        privileged_states = [
            s
            for s in states
            if any(tok in s.lower() for tok in ("admin", "root", "privileged", "superuser"))
        ]

    raw_transitions = doc.get("transitions")
    if not isinstance(raw_transitions, list):
        raise ValueError("Invalid state machine: 'transitions' must be a list.")

    roles: List[str] = ["anonymous", "guest", "user", "service", "admin"]
    roles.extend([r.lower() for r in _as_str_list(doc.get("roles"))])

    transitions: List[StateTransitionIR] = []
    for idx, tr in enumerate(raw_transitions, start=1):
        if not isinstance(tr, dict):
            raise ValueError(f"Invalid transition at index {idx - 1}: expected mapping.")
        from_state = str(
            tr.get("from") or tr.get("from_state") or tr.get("source") or ""
        ).strip()
        to_state = str(
            tr.get("to") or tr.get("to_state") or tr.get("target") or ""
        ).strip()
        if from_state not in states or to_state not in states:
            raise ValueError(
                f"Invalid transition at index {idx - 1}: endpoints ({from_state!r} -> {to_state!r}) "
                f"must exist in states {states}."
            )
        action = str(
            tr.get("action") or tr.get("event") or tr.get("name") or f"{from_state}_to_{to_state}"
        ).strip()
        req_roles = [
            r.lower()
            for r in _dedupe_preserve(
                _as_str_list(tr.get("required_roles"))
                + _as_str_list(tr.get("required_role"))
                + _as_str_list(tr.get("allowed_roles"))
            )
        ]
        roles.extend(req_roles)
        guards_raw = tr.get("guards")
        guards = dict(guards_raw) if isinstance(guards_raw, dict) else {}
        req_auth = bool(
            tr.get("required_auth")
            if "required_auth" in tr
            else tr.get("requires_auth", False)
        )
        same_tenant_req = bool(
            tr.get("same_tenant_required")
            or guards.get("same_tenant")
            or guards.get("tenant_match")
        )
        sets_auth = tr.get("sets_auth") if isinstance(tr.get("sets_auth"), bool) else None
        grants_role = (
            str(tr.get("grants_role")).strip().lower()
            if tr.get("grants_role")
            else None
        )
        if grants_role:
            roles.append(grants_role)
        sets_mfa = tr.get("sets_mfa") if isinstance(tr.get("sets_mfa"), bool) else None

        transitions.append(
            StateTransitionIR(
                name=str(tr.get("name") or action),
                from_state=from_state,
                to_state=to_state,
                action=action,
                required_auth=req_auth,
                required_roles=req_roles,
                guards=guards,
                same_tenant_required=same_tenant_req,
                sets_auth=sets_auth,
                grants_role=grants_role,
                sets_mfa=sets_mfa,
                line=idx,
            )
        )

    variables_raw = doc.get("variables")
    variables = (
        {str(k): str(v) for k, v in variables_raw.items()}
        if isinstance(variables_raw, dict)
        else {}
    )

    return StateMachineIR(
        name=str(doc.get("name") or doc.get("id") or "formal_state_machine"),
        initial_state=initial_state,
        states=states,
        privileged_states=privileged_states,
        transitions=transitions,
        roles=_dedupe_preserve(roles),
        variables=variables,
        source_path=source_path,
    )


# ---------------------------------------------------------------------------
# F4: Optional Model-Assisted Formal-State Translation (Offline-Safe & Strictly Validated)
# ---------------------------------------------------------------------------

_F4_SYSTEM_PROMPT = (
    "You are a defensive formal-methods security modeler. Convert the target specification "
    "into a strict JSON StateMachineIR object with keys: "
    '"name" (str), "initial_state" (str), "states" (list[str]), "privileged_states" (list[str]), '
    '"roles" (list[str]), and "transitions" (list of objects with keys '
    '"from", "to", "action", "required_auth" (bool), "required_roles" (list[str]), "guards" (dict)). '
    "Strictly defensive modeling only: NEVER output exploit scripts, HTTP wire payloads, curl/sqlmap "
    "commands, or attack instructions. Output ONLY valid JSON."
)


def _extract_json_dict(raw_text: str) -> Optional[Dict[str, Any]]:
    text = (raw_text or "").strip()
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1).strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(0))
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
    return None


def _validate_formal_model_dict(data: Any) -> Tuple[bool, Optional[str]]:
    """Strict structural & safety validator for LLM-generated formal StateMachine dicts."""
    ok_policy, _, err_policy = validate_llm_json_response(data, schema_type="formal_model")
    if not ok_policy:
        return False, err_policy or "Rejected by execution policy."

    if not isinstance(data, dict):
        return False, "Expected JSON object for formal model."

    allowed_top_keys = {
        "name",
        "initial_state",
        "initial",
        "states",
        "privileged_states",
        "admin_states",
        "target_states",
        "roles",
        "variables",
        "transitions",
    }
    unknown_keys = set(data.keys()) - allowed_top_keys
    if unknown_keys:
        return False, f"Unexpected keys in formal model: {sorted(unknown_keys)}"

    serialized = json.dumps(data, ensure_ascii=False)
    if _WEAPONIZED_ARTIFACT_RE.search(serialized):
        return False, "Rejected formal model containing disallowed command/payload markers."

    states = data.get("states")
    if not isinstance(states, list) or not states or not all(isinstance(s, str) and s.strip() for s in states):
        return False, "'states' must be a non-empty list of strings."

    initial = data.get("initial_state") or data.get("initial")
    if not isinstance(initial, str) or initial not in states:
        return False, "'initial_state' must be a valid member of 'states'."

    transitions = data.get("transitions")
    if not isinstance(transitions, list):
        return False, "'transitions' must be a list."

    allowed_tr_keys = {
        "name",
        "from",
        "from_state",
        "source",
        "to",
        "to_state",
        "target",
        "action",
        "event",
        "required_auth",
        "requires_auth",
        "required_role",
        "required_roles",
        "allowed_roles",
        "guards",
        "same_tenant_required",
    }
    for idx, tr in enumerate(transitions):
        if not isinstance(tr, dict):
            return False, f"Transition {idx} must be an object."
        if set(tr.keys()) - allowed_tr_keys:
            return False, f"Transition {idx} contains unexpected keys."
        src = tr.get("from") or tr.get("from_state") or tr.get("source")
        dst = tr.get("to") or tr.get("to_state") or tr.get("target")
        if src not in states or dst not in states:
            return False, f"Transition {idx} references unknown state."

    return True, None


def translate_target_to_formal_model(
    target_description: Union[str, Dict[str, Any]],
    *,
    model: Optional[str] = None,
    offline: Optional[bool] = None,
    embedded: bool = False,
    ollama_endpoint: Optional[str] = None,
    probe_timeout_sec: float = 0.4,
    request_timeout_sec: float = 20.0,
    env_local_path: Optional[Union[str, Path]] = None,
    force_ollama: bool = False,
) -> Tuple[Optional[StateMachineIR], Dict[str, Any]]:
    """
    Optional model-assisted translation of a target description into a formal `StateMachineIR`.

    Strictly sanitizes inputs via `sanitize_for_llm_prompt`, skips cleanly without fake
    outputs when `offline=True`, `embedded=True`, `RFCHUNT_OFFLINE=1`, `RFCHUNT_AIR_GAPPED=1`,
    or no local/paid model backend is reachable, and validates responses strictly.
    """
    raw_desc = (
        json.dumps(target_description, ensure_ascii=False, indent=2)
        if isinstance(target_description, dict)
        else str(target_description or "")
    )
    sanitized_desc = sanitize_for_llm_prompt(
        raw_desc,
        max_chars=4000,
        source="z3_formal_target",
    )

    telemetry: Dict[str, Any] = {
        "backend": "disabled",
        "status": "unknown",
        "model": model or "",
        "prompt_sanitized": True,
        "sanitized_length": len(sanitized_desc),
    }

    if not raw_desc.strip():
        telemetry["status"] = "skipped_empty_input"
        return None, telemetry

    if embedded:
        telemetry["status"] = "skipped_embedded"
        return None, telemetry

    air_gapped = os.environ.get("RFCHUNT_AIR_GAPPED") == "1"
    env_offline = os.environ.get("RFCHUNT_OFFLINE") == "1"
    explicit_offline = (offline is True) or air_gapped or (offline is None and env_offline)
    if explicit_offline:
        telemetry["status"] = "skipped_offline"
        return None, telemetry

    resolution = resolve_gha_llm_backend(
        model=model,
        embedded=embedded,
        offline=offline,
        ollama_endpoint=ollama_endpoint,
        probe_timeout_sec=probe_timeout_sec,
        env_local_path=env_local_path,
        force_ollama=force_ollama,
    )
    telemetry.update(resolution.to_telemetry())
    if resolution.status != "ready":
        if resolution.paid_client is not None:
            resolution.paid_client.close()
        return None, telemetry

    user_prompt = (
        "Translate the following target description into a formal defensive StateMachineIR JSON object.\n\n"
        f"{sanitized_desc}"
    )

    raw_response = ""
    used_model = resolution.model
    try:
        if resolution.backend == "paid_api" and resolution.paid_client is not None:
            raw_response = resolution.paid_client.generate(
                system_prompt=_F4_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                model=resolution.model,
                max_tokens=1024,
                temperature=0.1,
                expect_json=True,
            )
        elif resolution.backend == "ollama":
            candidates = list(dict.fromkeys([resolution.model, *resolution.available_models]))
            for cand_model in candidates[:3]:
                try:
                    resp = httpx.post(
                        f"{resolution.endpoint.rstrip('/')}/api/chat",
                        json={
                            "model": cand_model,
                            "stream": False,
                            "format": "json",
                            "options": {"temperature": 0.1},
                            "messages": [
                                {"role": "system", "content": _F4_SYSTEM_PROMPT},
                                {"role": "user", "content": user_prompt},
                            ],
                        },
                        timeout=request_timeout_sec,
                    )
                    resp.raise_for_status()
                    payload = resp.json()
                    txt = str(((payload.get("message") or {}).get("content")) or payload.get("response") or "")
                except Exception:
                    continue
                if txt and not ModelFusionAdapter._is_refusal(txt):
                    raw_response = txt
                    used_model = cand_model
                    break
    except Exception as exc:
        telemetry["status"] = "error_graceful_skip"
        telemetry["error"] = str(exc)[:240]
        return None, telemetry
    finally:
        if resolution.paid_client is not None:
            resolution.paid_client.close()

    parsed = _extract_json_dict(raw_response)
    if not parsed:
        telemetry["status"] = "invalid_or_empty_json"
        telemetry["model"] = used_model
        return None, telemetry

    ok_schema, err_schema = _validate_formal_model_dict(parsed)
    if not ok_schema:
        telemetry["status"] = "invalid_schema"
        telemetry["model"] = used_model
        telemetry["error"] = err_schema or "Schema validation failed."
        return None, telemetry

    try:
        sm_ir = parse_state_machine(parsed)
    except Exception as exc:
        telemetry["status"] = "invalid_state_machine"
        telemetry["model"] = used_model
        telemetry["error"] = str(exc)[:240]
        return None, telemetry

    telemetry["status"] = "translated"
    telemetry["model"] = used_model
    return sm_ir, telemetry


# ---------------------------------------------------------------------------
# F5: Z3 Symbolic Verification Engines (OpenAPI, IAM, State Machine)
# ---------------------------------------------------------------------------


def _make_proof_certificate(
    solver: z3.Solver,
    *,
    domain: str,
    invariant_name: str,
    bounded_steps: Optional[int] = None,
) -> Dict[str, Any]:
    cert: Dict[str, Any] = {
        "solver": "z3",
        "z3_version": z3.get_version_string(),
        "domain": domain,
        "invariant_name": invariant_name,
        "constraints_count": len(solver.assertions()),
        "formula_sha256": _formula_sha256(solver),
        "invariant_verified": True,
    }
    if bounded_steps is not None:
        cert["bounded_steps"] = int(bounded_steps)
    return cert


def _is_privileged_scope(scope_name: str) -> bool:
    low = scope_name.lower()
    tokens = re.split(r"[:._/\-\s]+", low)
    return any(tok in _PRIVILEGED_ROLE_TOKENS for tok in tokens)


def verify_openapi_invariants(
    spec_or_ir: Union[OpenApiModelIR, str, Path, Dict[str, Any]],
    *,
    timeout_ms: int = 5000,
) -> List[FormalVerificationFinding]:
    """Symbolically verify OpenAPI/Swagger access-control, RBAC, and tenant isolation invariants."""
    model = spec_or_ir if isinstance(spec_or_ir, OpenApiModelIR) else parse_openapi_spec(spec_or_ir)
    if not model.endpoints:
        return []

    all_roles = _dedupe_preserve(
        ["anonymous", "guest", "user", "service", "admin"]
        + [r for ep in model.endpoints for r in ep.required_roles]
    )
    role_to_id = {r: i for i, r in enumerate(all_roles)}
    id_to_role = {i: r for r, i in role_to_id.items()}

    all_scopes = _dedupe_preserve([sc for ep in model.endpoints for sc in ep.required_scopes])
    priv_or_mut_indices = [
        i for i, ep in enumerate(model.endpoints) if ep.is_privileged or ep.is_state_changing
    ]
    priv_indices = [i for i, ep in enumerate(model.endpoints) if ep.is_privileged]
    tenant_indices = [i for i, ep in enumerate(model.endpoints) if ep.is_tenant_scoped]

    findings: List[FormalVerificationFinding] = []

    def _build_openapi_solver() -> Tuple[z3.Context, z3.Solver, Dict[str, Any]]:
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)
        solver.set("timeout", max(1, int(timeout_ms)))

        caller_auth = z3.Bool("caller_authenticated", ctx=ctx)
        caller_role = z3.Int("caller_role", ctx=ctx)
        caller_tenant = z3.Int("caller_tenant", ctx=ctx)
        target_tenant = z3.Int("target_tenant", ctx=ctx)
        endpoint_idx = z3.Int("endpoint_idx", ctx=ctx)
        access_granted = z3.Bool("access_granted", ctx=ctx)
        scope_vars = {sc: z3.Bool(f"scope_{idx}", ctx=ctx) for idx, sc in enumerate(all_scopes)}

        solver.add(caller_role >= 0, caller_role < len(all_roles))
        solver.add(caller_tenant >= 0, caller_tenant <= 1)
        solver.add(target_tenant >= 0, target_tenant <= 1)
        solver.add(endpoint_idx >= 0, endpoint_idx < len(model.endpoints))

        anon_id = role_to_id["anonymous"]
        solver.add(z3.Implies(z3.Not(caller_auth), caller_role == anon_id, ctx))
        solver.add(z3.Implies(caller_auth, caller_role != anon_id, ctx))

        # Low-privilege roles cannot possess privileged scopes or unauthenticated users cannot hold any scope
        priv_role_ids = [
            role_to_id[r]
            for r in all_roles
            if r in _PRIVILEGED_ROLE_TOKENS or any(tok in r for tok in _PRIVILEGED_ROLE_TOKENS)
        ]
        for sc, sc_var in scope_vars.items():
            solver.add(z3.Implies(z3.Not(caller_auth), z3.Not(sc_var), ctx))
            if _is_privileged_scope(sc) and priv_role_ids:
                solver.add(
                    z3.Implies(
                        sc_var,
                        z3.Or([caller_role == rid for rid in priv_role_ids]),
                        ctx,
                    )
                )

        for idx, ep in enumerate(model.endpoints):
            conds: List[z3.BoolRef] = []
            if ep.auth_required and not ep.allows_anonymous:
                conds.append(caller_auth)
            if ep.required_roles:
                conds.append(z3.Or([caller_role == role_to_id[r] for r in ep.required_roles]))
            if ep.required_scopes:
                conds.append(z3.And([scope_vars[sc] for sc in ep.required_scopes]))
            if ep.is_tenant_scoped and ep.tenant_ownership_enforced:
                admin_ids = [
                    role_to_id[r] for r in all_roles if r in ("admin", "superadmin", "superuser")
                ]
                if admin_ids:
                    conds.append(
                        z3.Or(
                            caller_tenant == target_tenant,
                            z3.Or([caller_role == aid for aid in admin_ids]),
                        )
                    )
                else:
                    conds.append(caller_tenant == target_tenant)

            ep_allowed = z3.And(conds) if conds else z3.BoolVal(True, ctx=ctx)
            solver.add(z3.Implies(endpoint_idx == idx, access_granted == ep_allowed, ctx))

        syms = {
            "caller_auth": caller_auth,
            "caller_role": caller_role,
            "caller_tenant": caller_tenant,
            "target_tenant": target_tenant,
            "endpoint_idx": endpoint_idx,
            "access_granted": access_granted,
        }
        return ctx, solver, syms

    # Invariant 1: Unauthenticated access to privileged / state-changing endpoints
    if priv_or_mut_indices:
        t0 = time.perf_counter()
        ctx, solver, syms = _build_openapi_solver()
        solver.add(z3.Not(syms["caller_auth"]))
        solver.add(z3.Or([syms["endpoint_idx"] == i for i in priv_or_mut_indices]))
        solver.add(syms["access_granted"] == True)  # noqa: E712
        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        if res == z3.sat:
            m = solver.model()
            ep_idx = _model_eval_int(m, syms["endpoint_idx"], priv_or_mut_indices[0])
            ep = model.endpoints[ep_idx]
            role_name = id_to_role.get(_model_eval_int(m, syms["caller_role"], 0), "anonymous")
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("openapi", "unauthenticated_privileged_access", f"{ep.method}:{ep.path}"),
                    domain="openapi",
                    invariant_name="unauthenticated_privileged_access",
                    status=STATUS_SAT_VIOLATION,
                    severity="CRITICAL",
                    cwe="CWE-306",
                    title=f"Unauthenticated access permitted on {ep.method} {ep.path}",
                    summary=_sanitize_defensive_text(
                        f"Z3 proved that an unauthenticated principal ({role_name}) satisfies the "
                        f"effective OpenAPI security constraints for {ep.method} {ep.path} "
                        f"(auth_required={ep.auth_required}, allows_anonymous={ep.allows_anonymous})."
                    ),
                    file_path=model.source_path,
                    line=ep.line,
                    counterexample={
                        "auth_state": "unauthenticated",
                        "caller_authenticated": _model_eval_bool(m, syms["caller_auth"], False),
                        "caller_role": role_name,
                        "method": ep.method,
                        "endpoint": ep.path,
                        "operation_id": ep.operation_id,
                        "allows_anonymous": ep.allows_anonymous,
                    },
                    remediation=(
                        f"Enforce a non-empty authenticated security scheme on {ep.method} {ep.path}, "
                        "remove empty `security: []` or optional `{}` security entries, and require an "
                        "explicit privileged role or scope."
                    ),
                    solver_time_ms=elapsed_ms,
                )
            )
        elif res == z3.unsat:
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("openapi", "unauthenticated_privileged_access", model.title),
                    domain="openapi",
                    invariant_name="unauthenticated_privileged_access",
                    status=STATUS_UNSAT_PROVEN,
                    severity="INFO",
                    cwe="CWE-306",
                    title="Unauthenticated privileged endpoint access invariant proven",
                    summary=(
                        f"Z3 formally proved no unauthenticated caller can access any of the "
                        f"{len(priv_or_mut_indices)} privileged or state-changing endpoints."
                    ),
                    file_path=model.source_path,
                    proof_certificate=_make_proof_certificate(
                        solver, domain="openapi", invariant_name="unauthenticated_privileged_access"
                    ),
                    proof_summary="UNSAT: All privileged/state-changing endpoints enforce authentication.",
                    remediation="No remediation required; preserve strict authentication requirements.",
                    solver_time_ms=elapsed_ms,
                )
            )
        else:
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("openapi", "unauthenticated_privileged_access", "unknown"),
                    domain="openapi",
                    invariant_name="unauthenticated_privileged_access",
                    status=STATUS_UNKNOWN,
                    severity="INFO",
                    cwe="CWE-306",
                    title="OpenAPI authentication invariant solver returned UNKNOWN",
                    summary="Z3 returned unknown within the configured timeout.",
                    file_path=model.source_path,
                    solver_time_ms=elapsed_ms,
                )
            )

    # Invariant 2: Low-privilege role escalation to privileged endpoints
    if priv_indices:
        low_priv_ids = [role_to_id[r] for r in _LOW_PRIVILEGE_ROLES if r in role_to_id]
        t0 = time.perf_counter()
        ctx, solver, syms = _build_openapi_solver()
        solver.add(z3.Or([syms["caller_role"] == rid for rid in low_priv_ids]))
        solver.add(z3.Or([syms["endpoint_idx"] == i for i in priv_indices]))
        solver.add(syms["access_granted"] == True)  # noqa: E712
        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        if res == z3.sat:
            m = solver.model()
            ep_idx = _model_eval_int(m, syms["endpoint_idx"], priv_indices[0])
            ep = model.endpoints[ep_idx]
            role_name = id_to_role.get(_model_eval_int(m, syms["caller_role"], 0), "user")
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("openapi", "low_privilege_role_escalation", f"{ep.method}:{ep.path}"),
                    domain="openapi",
                    invariant_name="low_privilege_role_escalation",
                    status=STATUS_SAT_VIOLATION,
                    severity="HIGH",
                    cwe="CWE-862",
                    title=f"Low-privilege role '{role_name}' can access privileged endpoint {ep.method} {ep.path}",
                    summary=_sanitize_defensive_text(
                        f"Z3 found a concrete assignment where role '{role_name}' satisfies the "
                        f"endpoint policy for privileged route {ep.method} {ep.path} due to missing "
                        "role or privileged-scope enforcement."
                    ),
                    file_path=model.source_path,
                    line=ep.line,
                    counterexample={
                        "caller_authenticated": _model_eval_bool(m, syms["caller_auth"], True),
                        "caller_role": role_name,
                        "method": ep.method,
                        "endpoint": ep.path,
                        "required_roles": ep.required_roles,
                        "required_scopes": ep.required_scopes,
                    },
                    remediation=(
                        f"Restrict {ep.method} {ep.path} with explicit privileged OAuth2/RBAC scopes "
                        "or `x-required-role` constraints (e.g., `admin`) and enforce server-side RBAC."
                    ),
                    solver_time_ms=elapsed_ms,
                )
            )
        elif res == z3.unsat:
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("openapi", "low_privilege_role_escalation", model.title),
                    domain="openapi",
                    invariant_name="low_privilege_role_escalation",
                    status=STATUS_UNSAT_PROVEN,
                    severity="INFO",
                    cwe="CWE-862",
                    title="Privileged endpoint RBAC isolation invariant proven",
                    summary=(
                        f"Z3 formally proved low-privilege roles ({', '.join(_LOW_PRIVILEGE_ROLES)}) "
                        f"cannot satisfy access rules for any of the {len(priv_indices)} privileged endpoints."
                    ),
                    file_path=model.source_path,
                    proof_certificate=_make_proof_certificate(
                        solver, domain="openapi", invariant_name="low_privilege_role_escalation"
                    ),
                    proof_summary="UNSAT: All privileged endpoints require privileged roles or scopes.",
                    remediation="No remediation required; maintain strict RBAC enforcement.",
                    solver_time_ms=elapsed_ms,
                )
            )
        else:
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("openapi", "low_privilege_role_escalation", "unknown"),
                    domain="openapi",
                    invariant_name="low_privilege_role_escalation",
                    status=STATUS_UNKNOWN,
                    severity="INFO",
                    cwe="CWE-862",
                    title="OpenAPI RBAC invariant solver returned UNKNOWN",
                    summary="Z3 returned unknown within the configured timeout.",
                    file_path=model.source_path,
                    solver_time_ms=elapsed_ms,
                )
            )

    # Invariant 3: Cross-tenant IDOR access on tenant-scoped endpoints
    if tenant_indices:
        low_priv_ids = [role_to_id[r] for r in _LOW_PRIVILEGE_ROLES if r in role_to_id]
        t0 = time.perf_counter()
        ctx, solver, syms = _build_openapi_solver()
        solver.add(syms["caller_tenant"] != syms["target_tenant"])
        solver.add(z3.Or([syms["caller_role"] == rid for rid in low_priv_ids]))
        solver.add(z3.Or([syms["endpoint_idx"] == i for i in tenant_indices]))
        solver.add(syms["access_granted"] == True)  # noqa: E712
        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        if res == z3.sat:
            m = solver.model()
            ep_idx = _model_eval_int(m, syms["endpoint_idx"], tenant_indices[0])
            ep = model.endpoints[ep_idx]
            role_name = id_to_role.get(_model_eval_int(m, syms["caller_role"], 0), "user")
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("openapi", "cross_tenant_idor_access", f"{ep.method}:{ep.path}"),
                    domain="openapi",
                    invariant_name="cross_tenant_idor_access",
                    status=STATUS_SAT_VIOLATION,
                    severity="HIGH",
                    cwe="CWE-639",
                    title=f"Cross-tenant access possible on {ep.method} {ep.path}",
                    summary=_sanitize_defensive_text(
                        f"Z3 found a cross-tenant assignment (caller_tenant != target_tenant) "
                        f"permitted on tenant-parameterized route {ep.method} {ep.path} lacking "
                        "declared tenant ownership enforcement."
                    ),
                    file_path=model.source_path,
                    line=ep.line,
                    counterexample={
                        "caller_role": role_name,
                        "caller_tenant": _model_eval_int(m, syms["caller_tenant"], 0),
                        "target_tenant": _model_eval_int(m, syms["target_tenant"], 1),
                        "method": ep.method,
                        "endpoint": ep.path,
                        "tenant_ownership_enforced": ep.tenant_ownership_enforced,
                    },
                    remediation=(
                        f"Enforce object-level tenant ownership checks on {ep.method} {ep.path} "
                        "(matching authenticated principal tenant claim against resource tenant) and "
                        "declare tenant isolation metadata (`x-tenant-isolated: true`)."
                    ),
                    solver_time_ms=elapsed_ms,
                )
            )
        elif res == z3.unsat:
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("openapi", "cross_tenant_idor_access", model.title),
                    domain="openapi",
                    invariant_name="cross_tenant_idor_access",
                    status=STATUS_UNSAT_PROVEN,
                    severity="INFO",
                    cwe="CWE-639",
                    title="Cross-tenant OpenAPI isolation invariant proven",
                    summary=(
                        f"Z3 formally proved cross-tenant access is blocked across all "
                        f"{len(tenant_indices)} tenant-scoped endpoints."
                    ),
                    file_path=model.source_path,
                    proof_certificate=_make_proof_certificate(
                        solver, domain="openapi", invariant_name="cross_tenant_idor_access"
                    ),
                    proof_summary="UNSAT: Tenant-scoped endpoints enforce caller_tenant == target_tenant.",
                    remediation="No remediation required; maintain tenant ownership enforcement.",
                    solver_time_ms=elapsed_ms,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# F5 (IAM): IAM Policy Z3 Verification
# ---------------------------------------------------------------------------


def _iam_glob_match(pattern: str, candidate: str) -> bool:
    p = (pattern or "").strip().lower()
    c = (candidate or "").strip().lower()
    if p == "*":
        return True
    if fnmatch.fnmatchcase(c, p):
        return True
    # Also match role short name against ARN-like principals (e.g. arn:aws:iam::123:role/admin -> admin)
    if "/" in p and p.rsplit("/", 1)[-1] == c:
        return True
    if "/" in c and c.rsplit("/", 1)[-1] == p:
        return True
    return False


def _is_privileged_iam_action(action: str) -> bool:
    low = (action or "").strip().lower()
    if low in ("*", "*:*", "__wildcard_other__"):
        return True
    return any(
        tok in low
        for tok in ("admin", "iam:", "delete", "write", "put", "create", "update", "escalat", "root", "passrole")
    )


def _encode_iam_conditions(
    conditions: Dict[str, Any],
    ctx: z3.Context,
    mfa_present: z3.BoolRef,
    source_ip_trusted: z3.BoolRef,
    principal_tenant: z3.IntRef,
    resource_tenant: z3.IntRef,
    extra_str_vars: Dict[str, Tuple[z3.IntRef, Dict[str, int]]],
    extra_num_vars: Dict[str, z3.IntRef],
    solver: z3.Solver,
) -> z3.BoolRef:
    if not conditions:
        return z3.BoolVal(True, ctx=ctx)

    clauses: List[z3.BoolRef] = []

    def _get_str_var(key_name: str, literal_val: str) -> Tuple[z3.IntRef, int]:
        if key_name not in extra_str_vars:
            sym = z3.Int(f"cond_str_{len(extra_str_vars)}", ctx=ctx)
            mapping = {"__other__": 0}
            extra_str_vars[key_name] = (sym, mapping)
        sym, mapping = extra_str_vars[key_name]
        if literal_val not in mapping:
            mapping[literal_val] = len(mapping)
        return sym, mapping[literal_val]

    def _get_num_var(key_name: str) -> z3.IntRef:
        if key_name not in extra_num_vars:
            extra_num_vars[key_name] = z3.Int(f"cond_num_{len(extra_num_vars)}", ctx=ctx)
        return extra_num_vars[key_name]

    for op_name, cond_body in conditions.items():
        op_low = str(op_name).strip().lower()
        if not isinstance(cond_body, dict):
            continue
        for c_key, c_val in cond_body.items():
            key_low = str(c_key).strip().lower()
            vals = _as_str_list(c_val) if not isinstance(c_val, bool) else [str(c_val).lower()]
            if not vals:
                continue

            if op_low in ("bool", "boolifexists"):
                want_true = vals[0].lower() in ("true", "1", "yes")
                if "mfa" in key_low or "multifactor" in key_low:
                    clauses.append(mfa_present if want_true else z3.Not(mfa_present))
                elif "trusted" in key_low or "securetransport" in key_low:
                    clauses.append(source_ip_trusted if want_true else z3.Not(source_ip_trusted))
                elif "tenant" in key_low:
                    clauses.append(
                        (principal_tenant == resource_tenant)
                        if want_true
                        else (principal_tenant != resource_tenant)
                    )
                else:
                    sym, lit_id = _get_str_var(key_low, "true" if want_true else "false")
                    clauses.append(sym == lit_id)

            elif op_low in ("null",):
                is_null = vals[0].lower() in ("true", "1", "yes")
                if "mfa" in key_low or "multifactor" in key_low:
                    clauses.append(z3.Not(mfa_present) if is_null else mfa_present)

            elif op_low in ("ipaddress", "notipaddress"):
                clauses.append(source_ip_trusted if op_low == "ipaddress" else z3.Not(source_ip_trusted))

            elif op_low in ("stringequals", "stringequalsignorecase", "stringnotequals", "stringnotequalsignorecase"):
                negate = "not" in op_low
                is_tenant_eq = (
                    "tenant" in key_low
                    and any(
                        "${" in v and ("resource" in v.lower() or "tenant" in v.lower())
                        for v in vals
                    )
                ) or (key_low in ("same_tenant", "tenant_match"))
                if is_tenant_eq:
                    expr = principal_tenant == resource_tenant
                    clauses.append(z3.Not(expr) if negate else expr)
                else:
                    eq_opts = []
                    for v in vals:
                        sym, lit_id = _get_str_var(key_low, v.lower())
                        eq_opts.append(sym == lit_id)
                    combined = z3.Or(eq_opts)
                    clauses.append(z3.Not(combined) if negate else combined)

            elif op_low in ("numericlessthan", "numericgreaterthan", "numericequals", "numericlessthanequals", "numericgreaterthanequals"):
                try:
                    num_target = int(float(vals[0]))
                except ValueError:
                    continue
                sym = _get_num_var(key_low)
                if op_low == "numericlessthan":
                    clauses.append(sym < num_target)
                elif op_low == "numericlessthanequals":
                    clauses.append(sym <= num_target)
                elif op_low == "numericgreaterthan":
                    clauses.append(sym > num_target)
                elif op_low == "numericgreaterthanequals":
                    clauses.append(sym >= num_target)
                else:
                    clauses.append(sym == num_target)

    # Bound dynamic string condition domains after collection
    for sym, mapping in extra_str_vars.values():
        solver.add(sym >= 0, sym <= max(len(mapping), 1))

    return z3.And(clauses) if clauses else z3.BoolVal(True, ctx=ctx)


def verify_iam_invariants(
    policy_or_ir: Union[IamPolicyIR, str, Path, Dict[str, Any]],
    *,
    timeout_ms: int = 5000,
) -> List[FormalVerificationFinding]:
    """Symbolically verify IAM policy Allow/Deny precedence, privilege, MFA, and tenant invariants."""
    policy = policy_or_ir if isinstance(policy_or_ir, IamPolicyIR) else parse_iam_policy(policy_or_ir)
    if not policy.statements:
        return []

    principals_universe = _dedupe_preserve(
        ["anonymous", "guest", "user", "readonly", "admin", "__wildcard_other__"]
        + [p for s in policy.statements for p in (s.principals + s.not_principals) if p != "*"]
    )
    actions_universe = _dedupe_preserve(
        [
            "read:profile",
            "admin:*",
            "admin:users",
            "iam:PassRole",
            "iam:CreatePolicyVersion",
            "delete:resource",
            "__wildcard_other__",
        ]
        + [a for s in policy.statements for a in (s.actions + s.not_actions) if "*" not in a]
    )
    resources_universe = _dedupe_preserve(
        [
            "arn:aws:s3:::tenant-data/*",
            "arn:aws:iam::*:role/admin",
            "__wildcard_other__",
        ]
        + [r for s in policy.statements for r in (s.resources + s.not_resources) if r != "*"]
    )

    p_to_id = {p: i for i, p in enumerate(principals_universe)}
    id_to_p = {i: p for p, i in p_to_id.items()}
    a_to_id = {a: i for i, a in enumerate(actions_universe)}
    id_to_a = {i: a for a, i in a_to_id.items()}
    r_to_id = {r: i for i, r in enumerate(resources_universe)}
    id_to_r = {i: r for r, i in r_to_id.items()}

    low_priv_principals = [
        p
        for p in principals_universe
        if p.lower() in ("anonymous", "guest", "user", "readonly", "__wildcard_other__")
    ]
    priv_actions = [a for a in actions_universe if _is_privileged_iam_action(a)]

    def _build_iam_solver() -> Tuple[z3.Context, z3.Solver, Dict[str, Any]]:
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)
        solver.set("timeout", max(1, int(timeout_ms)))

        principal_sym = z3.Int("principal_id", ctx=ctx)
        action_sym = z3.Int("action_id", ctx=ctx)
        resource_sym = z3.Int("resource_id", ctx=ctx)
        mfa_present = z3.Bool("mfa_present", ctx=ctx)
        source_ip_trusted = z3.Bool("source_ip_trusted", ctx=ctx)
        principal_tenant = z3.Int("principal_tenant", ctx=ctx)
        resource_tenant = z3.Int("resource_tenant", ctx=ctx)

        solver.add(principal_sym >= 0, principal_sym < len(principals_universe))
        solver.add(action_sym >= 0, action_sym < len(actions_universe))
        solver.add(resource_sym >= 0, resource_sym < len(resources_universe))
        solver.add(principal_tenant >= 0, principal_tenant <= 1)
        solver.add(resource_tenant >= 0, resource_tenant <= 1)

        extra_str_vars: Dict[str, Tuple[z3.IntRef, Dict[str, int]]] = {}
        extra_num_vars: Dict[str, z3.IntRef] = {}

        allow_formulas: List[z3.BoolRef] = []
        deny_formulas: List[z3.BoolRef] = []

        for stmt in policy.statements:
            # Principals
            if stmt.principals:
                matched_pids = [
                    p_to_id[p]
                    for p in principals_universe
                    if any(_iam_glob_match(pat, p) for pat in stmt.principals)
                ]
                p_expr = (
                    z3.Or([principal_sym == pid for pid in matched_pids])
                    if matched_pids
                    else z3.BoolVal(False, ctx=ctx)
                )
            elif stmt.not_principals:
                excluded_pids = [
                    p_to_id[p]
                    for p in principals_universe
                    if any(_iam_glob_match(pat, p) for pat in stmt.not_principals)
                ]
                p_expr = (
                    z3.And([principal_sym != pid for pid in excluded_pids])
                    if excluded_pids
                    else z3.BoolVal(True, ctx=ctx)
                )
            else:
                p_expr = z3.BoolVal(True, ctx=ctx)

            # Actions
            if stmt.actions:
                matched_aids = [
                    a_to_id[a]
                    for a in actions_universe
                    if any(_iam_glob_match(pat, a) for pat in stmt.actions)
                ]
                a_expr = (
                    z3.Or([action_sym == aid for aid in matched_aids])
                    if matched_aids
                    else z3.BoolVal(False, ctx=ctx)
                )
            else:
                excluded_aids = [
                    a_to_id[a]
                    for a in actions_universe
                    if any(_iam_glob_match(pat, a) for pat in stmt.not_actions)
                ]
                a_expr = (
                    z3.And([action_sym != aid for aid in excluded_aids])
                    if excluded_aids
                    else z3.BoolVal(True, ctx=ctx)
                )

            # Resources
            if stmt.resources:
                matched_rids = [
                    r_to_id[r]
                    for r in resources_universe
                    if any(_iam_glob_match(pat, r) for pat in stmt.resources)
                ]
                r_expr = (
                    z3.Or([resource_sym == rid for rid in matched_rids])
                    if matched_rids
                    else z3.BoolVal(False, ctx=ctx)
                )
            else:
                excluded_rids = [
                    r_to_id[r]
                    for r in resources_universe
                    if any(_iam_glob_match(pat, r) for pat in stmt.not_resources)
                ]
                r_expr = (
                    z3.And([resource_sym != rid for rid in excluded_rids])
                    if excluded_rids
                    else z3.BoolVal(True, ctx=ctx)
                )

            c_expr = _encode_iam_conditions(
                stmt.conditions,
                ctx,
                mfa_present,
                source_ip_trusted,
                principal_tenant,
                resource_tenant,
                extra_str_vars,
                extra_num_vars,
                solver,
            )

            stmt_expr = z3.And(p_expr, a_expr, r_expr, c_expr)
            if stmt.effect == "Allow":
                allow_formulas.append(stmt_expr)
            else:
                deny_formulas.append(stmt_expr)

        explicit_allow = z3.Or(allow_formulas) if allow_formulas else z3.BoolVal(False, ctx=ctx)
        explicit_deny = z3.Or(deny_formulas) if deny_formulas else z3.BoolVal(False, ctx=ctx)
        effective_allow = z3.And(explicit_allow, z3.Not(explicit_deny))

        syms = {
            "principal_sym": principal_sym,
            "action_sym": action_sym,
            "resource_sym": resource_sym,
            "mfa_present": mfa_present,
            "source_ip_trusted": source_ip_trusted,
            "principal_tenant": principal_tenant,
            "resource_tenant": resource_tenant,
            "explicit_allow": explicit_allow,
            "explicit_deny": explicit_deny,
            "effective_allow": effective_allow,
        }
        return ctx, solver, syms

    findings: List[FormalVerificationFinding] = []

    # Invariant 1: Explicit Deny precedence soundness
    t0 = time.perf_counter()
    ctx, solver, syms = _build_iam_solver()
    solver.add(syms["explicit_deny"])
    solver.add(syms["effective_allow"])
    res = solver.check()
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    if res == z3.unsat:
        findings.append(
            FormalVerificationFinding(
                finding_id=_deterministic_finding_id("iam", "explicit_deny_precedence", policy.version),
                domain="iam",
                invariant_name="explicit_deny_precedence",
                status=STATUS_UNSAT_PROVEN,
                severity="INFO",
                cwe="CWE-284",
                title="Explicit Deny precedence invariant proven",
                summary=(
                    "Z3 formally proved that no principal/action/resource/condition assignment "
                    "can achieve effective_allow when an explicit Deny statement matches."
                ),
                file_path=policy.source_path,
                proof_certificate=_make_proof_certificate(
                    solver, domain="iam", invariant_name="explicit_deny_precedence"
                ),
                proof_summary="UNSAT: explicit_deny strictly overrides explicit_allow.",
                remediation="No remediation required; explicit Deny precedence holds.",
                solver_time_ms=elapsed_ms,
            )
        )

    # Invariant 2: Low-privilege / untrusted principal reaching privileged action
    if low_priv_principals and priv_actions:
        t0 = time.perf_counter()
        ctx, solver, syms = _build_iam_solver()
        solver.add(z3.Or([syms["principal_sym"] == p_to_id[p] for p in low_priv_principals]))
        solver.add(z3.Or([syms["action_sym"] == a_to_id[a] for a in priv_actions]))
        solver.add(syms["effective_allow"])
        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        if res == z3.sat:
            m = solver.model()
            p_name = id_to_p.get(_model_eval_int(m, syms["principal_sym"]), "anonymous")
            a_name = id_to_a.get(_model_eval_int(m, syms["action_sym"]), "admin:*")
            r_name = id_to_r.get(_model_eval_int(m, syms["resource_sym"]), "*")
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("iam", "unauthenticated_or_low_priv_admin_access", f"{p_name}:{a_name}"),
                    domain="iam",
                    invariant_name="unauthenticated_or_low_priv_admin_access",
                    status=STATUS_SAT_VIOLATION,
                    severity="CRITICAL",
                    cwe="CWE-269",
                    title=f"Low-privilege/wildcard principal '{p_name}' granted privileged action '{a_name}'",
                    summary=_sanitize_defensive_text(
                        f"Z3 produced a satisfying assignment allowing principal '{p_name}' to execute "
                        f"privileged IAM action '{a_name}' on resource '{r_name}'."
                    ),
                    file_path=policy.source_path,
                    counterexample={
                        "principal": p_name,
                        "action": a_name,
                        "resource": r_name,
                        "mfa_present": _model_eval_bool(m, syms["mfa_present"], False),
                        "source_ip_trusted": _model_eval_bool(m, syms["source_ip_trusted"], False),
                    },
                    remediation=(
                        f"Narrow IAM policy Principal/Action scope away from '{a_name}' for low-privilege "
                        "or wildcard principals, add explicit `Deny` guards, and enforce MFA/tenant conditions."
                    ),
                    solver_time_ms=elapsed_ms,
                )
            )
        elif res == z3.unsat:
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("iam", "unauthenticated_or_low_priv_admin_access", "proven"),
                    domain="iam",
                    invariant_name="unauthenticated_or_low_priv_admin_access",
                    status=STATUS_UNSAT_PROVEN,
                    severity="INFO",
                    cwe="CWE-269",
                    title="Privileged IAM action isolation invariant proven",
                    summary=(
                        "Z3 formally proved no low-privilege or wildcard principal can perform "
                        "privileged actions under the policy's Allow/Deny and Condition constraints."
                    ),
                    file_path=policy.source_path,
                    proof_certificate=_make_proof_certificate(
                        solver, domain="iam", invariant_name="unauthenticated_or_low_priv_admin_access"
                    ),
                    proof_summary="UNSAT: Privileged IAM actions are unreachable by low-privilege principals.",
                    remediation="No remediation required.",
                    solver_time_ms=elapsed_ms,
                )
            )

    # Invariant 3: MFA / security condition bypass on privileged actions
    if priv_actions:
        t0 = time.perf_counter()
        ctx, solver, syms = _build_iam_solver()
        solver.add(z3.Or([syms["action_sym"] == a_to_id[a] for a in priv_actions]))
        solver.add(z3.Not(syms["mfa_present"]))
        solver.add(syms["effective_allow"])
        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        if res == z3.sat:
            m = solver.model()
            p_name = id_to_p.get(_model_eval_int(m, syms["principal_sym"]), "user")
            a_name = id_to_a.get(_model_eval_int(m, syms["action_sym"]), "admin:*")
            r_name = id_to_r.get(_model_eval_int(m, syms["resource_sym"]), "*")
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("iam", "condition_bypass_access", f"{p_name}:{a_name}"),
                    domain="iam",
                    invariant_name="condition_bypass_access",
                    status=STATUS_SAT_VIOLATION,
                    severity="HIGH",
                    cwe="CWE-287",
                    title=f"Privileged IAM action '{a_name}' permitted without MFA condition",
                    summary=_sanitize_defensive_text(
                        f"Z3 proved principal '{p_name}' can execute '{a_name}' on '{r_name}' "
                        "with mfa_present=False."
                    ),
                    file_path=policy.source_path,
                    counterexample={
                        "principal": p_name,
                        "action": a_name,
                        "resource": r_name,
                        "mfa_present": False,
                    },
                    remediation=(
                        "Require `Bool: {\"aws:MultiFactorAuthPresent\": \"true\"}` (and explicit Deny "
                        "when MFA is absent) on all privileged Allow statements."
                    ),
                    solver_time_ms=elapsed_ms,
                )
            )
        elif res == z3.unsat:
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("iam", "condition_bypass_access", "proven"),
                    domain="iam",
                    invariant_name="condition_bypass_access",
                    status=STATUS_UNSAT_PROVEN,
                    severity="INFO",
                    cwe="CWE-287",
                    title="Privileged IAM MFA condition enforcement proven",
                    summary="Z3 formally proved no privileged action can succeed when mfa_present=False.",
                    file_path=policy.source_path,
                    proof_certificate=_make_proof_certificate(
                        solver, domain="iam", invariant_name="condition_bypass_access"
                    ),
                    proof_summary="UNSAT: MFA condition or explicit Deny prevents unverified privileged actions.",
                    remediation="No remediation required.",
                    solver_time_ms=elapsed_ms,
                )
            )

    # Invariant 4: Cross-tenant IAM access (principal_tenant != resource_tenant)
    t0 = time.perf_counter()
    ctx, solver, syms = _build_iam_solver()
    solver.add(syms["principal_tenant"] != syms["resource_tenant"])
    solver.add(syms["effective_allow"])
    res = solver.check()
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    if res == z3.sat:
        m = solver.model()
        p_name = id_to_p.get(_model_eval_int(m, syms["principal_sym"]), "user")
        a_name = id_to_a.get(_model_eval_int(m, syms["action_sym"]), "*")
        r_name = id_to_r.get(_model_eval_int(m, syms["resource_sym"]), "*")
        findings.append(
            FormalVerificationFinding(
                finding_id=_deterministic_finding_id("iam", "cross_tenant_iam_access", f"{p_name}:{a_name}:{r_name}"),
                domain="iam",
                invariant_name="cross_tenant_iam_access",
                status=STATUS_SAT_VIOLATION,
                severity="HIGH",
                cwe="CWE-639",
                title=f"Cross-tenant IAM access permitted for '{p_name}' on '{a_name}'",
                summary=_sanitize_defensive_text(
                    f"Z3 proved principal '{p_name}' with principal_tenant != resource_tenant "
                    f"achieves effective_allow=True on action '{a_name}', resource '{r_name}'."
                ),
                file_path=policy.source_path,
                counterexample={
                    "principal": p_name,
                    "action": a_name,
                    "resource": r_name,
                    "principal_tenant": _model_eval_int(m, syms["principal_tenant"], 0),
                    "resource_tenant": _model_eval_int(m, syms["resource_tenant"], 1),
                },
                remediation=(
                    "Bind tenant identity via `StringEquals: {\"aws:PrincipalTag/tenant\": \"${resource:tenant}\"}` "
                    "on Allow statements so cross-tenant access is denied."
                ),
                solver_time_ms=elapsed_ms,
            )
        )
    elif res == z3.unsat:
        findings.append(
            FormalVerificationFinding(
                finding_id=_deterministic_finding_id("iam", "cross_tenant_iam_access", "proven"),
                domain="iam",
                invariant_name="cross_tenant_iam_access",
                status=STATUS_UNSAT_PROVEN,
                severity="INFO",
                cwe="CWE-639",
                title="Cross-tenant IAM isolation invariant proven",
                summary="Z3 formally proved cross-tenant access (principal_tenant != resource_tenant) is impossible.",
                file_path=policy.source_path,
                proof_certificate=_make_proof_certificate(
                    solver, domain="iam", invariant_name="cross_tenant_iam_access"
                ),
                proof_summary="UNSAT: Tenant condition or explicit Deny prevents cross-tenant access.",
                remediation="No remediation required.",
                solver_time_ms=elapsed_ms,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# F5 (State Machine): Bounded Multi-Step Reachability Z3 Verifier
# ---------------------------------------------------------------------------


def verify_state_machine_invariants(
    sm_or_ir: Union[StateMachineIR, str, Path, Dict[str, Any]],
    *,
    max_steps: int = 8,
    timeout_ms: int = 5000,
) -> List[FormalVerificationFinding]:
    """Symbolically verify bounded multi-step reachability of privileged states in StateMachineIR."""
    sm = sm_or_ir if isinstance(sm_or_ir, StateMachineIR) else parse_state_machine(sm_or_ir)
    if not sm.states or not sm.privileged_states:
        return []

    steps = max(1, min(int(max_steps), 15))
    state_to_id = {s: i for i, s in enumerate(sm.states)}
    id_to_state = {i: s for s, i in state_to_id.items()}

    roles_universe = _dedupe_preserve(
        ["anonymous", "guest", "user", "readonly", "service", "admin"] + list(sm.roles)
    )
    role_to_id = {r: i for i, r in enumerate(roles_universe)}
    id_to_role = {i: r for r, i in role_to_id.items()}

    # Collect custom boolean guard keys beyond core built-ins
    custom_guard_keys = sorted(
        {
            str(k)
            for tr in sm.transitions
            for k, v in tr.guards.items()
            if isinstance(v, bool)
            and str(k).lower()
            not in (
                "mfa",
                "mfa_verified",
                "mfa_present",
                "step_up",
                "same_tenant",
                "tenant_match",
                "auth",
                "authenticated",
            )
        }
    )

    models_tenant = any(
        tr.same_tenant_required
        or any("tenant" in str(k).lower() for k in tr.guards)
        for tr in sm.transitions
    ) or any("tenant" in str(k).lower() for k in sm.variables)

    def _build_bmc_solver() -> Tuple[z3.Context, z3.Solver, Dict[str, Any]]:
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)
        solver.set("timeout", max(1, int(timeout_ms)))

        state_vars = [z3.Int(f"state_{t}", ctx=ctx) for t in range(steps + 1)]
        auth_vars = [z3.Bool(f"auth_{t}", ctx=ctx) for t in range(steps + 1)]
        role_vars = [z3.Int(f"role_{t}", ctx=ctx) for t in range(steps + 1)]
        mfa_vars = [z3.Bool(f"mfa_{t}", ctx=ctx) for t in range(steps + 1)]
        principal_tenant = z3.Int("principal_tenant", ctx=ctx)
        target_tenant = z3.Int("target_tenant", ctx=ctx)
        action_vars = [z3.Int(f"action_{t}", ctx=ctx) for t in range(steps)]
        custom_vars: Dict[str, List[z3.BoolRef]] = {
            gk: [z3.Bool(f"guard_{gk}_{t}", ctx=ctx) for t in range(steps + 1)]
            for gk in custom_guard_keys
        }

        solver.add(principal_tenant >= 0, principal_tenant <= 1)
        solver.add(target_tenant >= 0, target_tenant <= 1)

        stutter_id = len(sm.transitions)
        for t in range(steps + 1):
            solver.add(state_vars[t] >= 0, state_vars[t] < len(sm.states))
            solver.add(role_vars[t] >= 0, role_vars[t] < len(roles_universe))

        for t in range(steps):
            solver.add(action_vars[t] >= 0, action_vars[t] <= stutter_id)
            step_options: List[z3.BoolRef] = []

            # Stutter step (permitted only once already in a privileged target state so traces stay minimal)
            stutter_clauses: List[z3.BoolRef] = [
                action_vars[t] == stutter_id,
                z3.Or([state_vars[t] == state_to_id[ps] for ps in sm.privileged_states]),
                state_vars[t + 1] == state_vars[t],
                auth_vars[t + 1] == auth_vars[t],
                role_vars[t + 1] == role_vars[t],
                mfa_vars[t + 1] == mfa_vars[t],
            ]
            for gk in custom_guard_keys:
                stutter_clauses.append(custom_vars[gk][t + 1] == custom_vars[gk][t])
            step_options.append(z3.And(stutter_clauses))

            # Explicit transitions
            for tr_idx, tr in enumerate(sm.transitions):
                tr_clauses: List[z3.BoolRef] = [
                    action_vars[t] == tr_idx,
                    state_vars[t] == state_to_id[tr.from_state],
                    state_vars[t + 1] == state_to_id[tr.to_state],
                ]
                if tr.required_auth:
                    tr_clauses.append(auth_vars[t] == True)  # noqa: E712
                if tr.required_roles:
                    tr_clauses.append(
                        z3.Or([role_vars[t] == role_to_id[r] for r in tr.required_roles])
                    )
                if tr.same_tenant_required:
                    tr_clauses.append(principal_tenant == target_tenant)

                for gk, gv in tr.guards.items():
                    gk_low = str(gk).lower()
                    if gk_low in ("mfa", "mfa_verified", "mfa_present", "step_up"):
                        tr_clauses.append(mfa_vars[t] == bool(gv))
                    elif gk_low in ("same_tenant", "tenant_match"):
                        tr_clauses.append(
                            (principal_tenant == target_tenant)
                            if bool(gv)
                            else (principal_tenant != target_tenant)
                        )
                    elif gk_low in ("auth", "authenticated"):
                        tr_clauses.append(auth_vars[t] == bool(gv))
                    elif isinstance(gv, bool) and str(gk) in custom_vars:
                        tr_clauses.append(custom_vars[str(gk)][t] == gv)

                # Propagate auth/role/mfa/custom guards to t+1
                if tr.sets_auth is not None:
                    tr_clauses.append(auth_vars[t + 1] == tr.sets_auth)
                else:
                    tr_clauses.append(auth_vars[t + 1] == auth_vars[t])

                if tr.grants_role is not None and tr.grants_role in role_to_id:
                    tr_clauses.append(role_vars[t + 1] == role_to_id[tr.grants_role])
                else:
                    tr_clauses.append(role_vars[t + 1] == role_vars[t])

                if tr.sets_mfa is not None:
                    tr_clauses.append(mfa_vars[t + 1] == tr.sets_mfa)
                else:
                    tr_clauses.append(mfa_vars[t + 1] == mfa_vars[t])

                for gk in custom_guard_keys:
                    tr_clauses.append(custom_vars[gk][t + 1] == custom_vars[gk][t])

                step_options.append(z3.And(tr_clauses))

            solver.add(z3.Or(step_options))

        syms = {
            "state_vars": state_vars,
            "auth_vars": auth_vars,
            "role_vars": role_vars,
            "mfa_vars": mfa_vars,
            "principal_tenant": principal_tenant,
            "target_tenant": target_tenant,
            "action_vars": action_vars,
            "custom_vars": custom_vars,
            "stutter_id": stutter_id,
        }
        return ctx, solver, syms

    def _extract_trace(m: z3.ModelRef, syms: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
        trace: List[Dict[str, Any]] = []
        priv_set = set(sm.privileged_states)
        reached_priv = sm.privileged_states[0]

        for t in range(steps + 1):
            st_name = id_to_state.get(_model_eval_int(m, syms["state_vars"][t]), sm.initial_state)
            role_name = id_to_role.get(_model_eval_int(m, syms["role_vars"][t]), "anonymous")
            auth_val = _model_eval_bool(m, syms["auth_vars"][t], False)
            mfa_val = _model_eval_bool(m, syms["mfa_vars"][t], False)
            step_entry: Dict[str, Any] = {
                "step": t,
                "state": st_name,
                "authenticated": auth_val,
                "role": role_name,
                "mfa_verified": mfa_val,
            }
            if t < steps:
                act_idx = _model_eval_int(m, syms["action_vars"][t], syms["stutter_id"])
                if act_idx == syms["stutter_id"]:
                    step_entry["next_action"] = "stutter"
                else:
                    step_entry["next_action"] = sm.transitions[act_idx].action
            trace.append(step_entry)
            if st_name in priv_set:
                reached_priv = st_name
                break

        return trace, reached_priv

    findings: List[FormalVerificationFinding] = []

    # Invariant 1: Unauthenticated reachability to privileged state
    t0 = time.perf_counter()
    ctx, solver, syms = _build_bmc_solver()
    solver.add(syms["state_vars"][0] == state_to_id[sm.initial_state])
    solver.add(syms["auth_vars"][0] == False)  # noqa: E712
    solver.add(syms["role_vars"][0] == role_to_id["anonymous"])
    solver.add(syms["mfa_vars"][0] == False)  # noqa: E712
    for gk in custom_guard_keys:
        solver.add(syms["custom_vars"][gk][0] == False)  # noqa: E712
    solver.add(
        z3.Or(
            [
                syms["state_vars"][t] == state_to_id[ps]
                for t in range(steps + 1)
                for ps in sm.privileged_states
            ]
        )
    )
    res = solver.check()
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    if res == z3.sat:
        m = solver.model()
        trace, reached_priv = _extract_trace(m, syms)
        findings.append(
            FormalVerificationFinding(
                finding_id=_deterministic_finding_id("state_machine", "unauthenticated_privileged_reachability", f"{sm.name}:{reached_priv}"),
                domain="state_machine",
                invariant_name="unauthenticated_privileged_reachability",
                status=STATUS_SAT_VIOLATION,
                severity="CRITICAL",
                cwe="CWE-306",
                title=f"Unauthenticated caller reaches privileged state '{reached_priv}' in {len(trace) - 1} step(s)",
                summary=_sanitize_defensive_text(
                    f"Z3 bounded model checking (K={steps}) found a transition sequence from "
                    f"initial state '{sm.initial_state}' (authenticated=False, role=anonymous) "
                    f"to privileged state '{reached_priv}'."
                ),
                file_path=sm.source_path,
                counterexample={
                    "initial_state": sm.initial_state,
                    "reached_privileged_state": reached_priv,
                    "initial_authenticated": False,
                    "initial_role": "anonymous",
                    "steps_taken": len(trace) - 1,
                    "actions": [s["next_action"] for s in trace[:-1] if "next_action" in s],
                },
                trace=trace,
                remediation=(
                    f"Enforce `required_auth: true`, privileged `required_roles` (e.g., `admin`), "
                    f"and step-up/MFA guards on every transition leading toward '{reached_priv}'."
                ),
                solver_time_ms=elapsed_ms,
            )
        )
    elif res == z3.unsat:
        findings.append(
            FormalVerificationFinding(
                finding_id=_deterministic_finding_id("state_machine", "unauthenticated_privileged_reachability", sm.name),
                domain="state_machine",
                invariant_name="unauthenticated_privileged_reachability",
                status=STATUS_UNSAT_PROVEN,
                severity="INFO",
                cwe="CWE-306",
                title=f"Privileged states unreachable without authentication (K={steps})",
                summary=(
                    f"Z3 formally proved no transition path up to K={steps} steps reaches any "
                    f"privileged state {sm.privileged_states} from an unauthenticated initial state."
                ),
                file_path=sm.source_path,
                proof_certificate=_make_proof_certificate(
                    solver,
                    domain="state_machine",
                    invariant_name="unauthenticated_privileged_reachability",
                    bounded_steps=steps,
                ),
                proof_summary=f"UNSAT: Proven unreachable within K={steps} transition steps.",
                remediation="No remediation required.",
                solver_time_ms=elapsed_ms,
            )
        )
    else:
        findings.append(
            FormalVerificationFinding(
                finding_id=_deterministic_finding_id("state_machine", "unauthenticated_privileged_reachability", "unknown"),
                domain="state_machine",
                invariant_name="unauthenticated_privileged_reachability",
                status=STATUS_UNKNOWN,
                severity="INFO",
                cwe="CWE-306",
                title="State machine unauthenticated reachability solver returned UNKNOWN",
                summary="Z3 returned unknown within the configured timeout.",
                file_path=sm.source_path,
                solver_time_ms=elapsed_ms,
            )
        )

    # Invariant 2: Low-privilege authenticated user reaching privileged state
    low_ids = [role_to_id[r] for r in ("guest", "user", "readonly") if r in role_to_id]
    t0 = time.perf_counter()
    ctx, solver, syms = _build_bmc_solver()
    solver.add(syms["state_vars"][0] == state_to_id[sm.initial_state])
    solver.add(syms["auth_vars"][0] == True)  # noqa: E712
    solver.add(z3.Or([syms["role_vars"][0] == rid for rid in low_ids]))
    solver.add(syms["mfa_vars"][0] == False)  # noqa: E712
    for gk in custom_guard_keys:
        solver.add(syms["custom_vars"][gk][0] == False)  # noqa: E712
    solver.add(
        z3.Or(
            [
                syms["state_vars"][t] == state_to_id[ps]
                for t in range(steps + 1)
                for ps in sm.privileged_states
            ]
        )
    )
    res = solver.check()
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    if res == z3.sat:
        m = solver.model()
        trace, reached_priv = _extract_trace(m, syms)
        init_role = trace[0]["role"] if trace else "user"
        findings.append(
            FormalVerificationFinding(
                finding_id=_deterministic_finding_id("state_machine", "low_privilege_escalation_reachability", f"{sm.name}:{reached_priv}"),
                domain="state_machine",
                invariant_name="low_privilege_escalation_reachability",
                status=STATUS_SAT_VIOLATION,
                severity="HIGH",
                cwe="CWE-269",
                title=f"Low-privilege role '{init_role}' reaches privileged state '{reached_priv}'",
                summary=_sanitize_defensive_text(
                    f"Z3 bounded model checking (K={steps}) found a transition sequence allowing "
                    f"authenticated role '{init_role}' to reach '{reached_priv}'."
                ),
                file_path=sm.source_path,
                counterexample={
                    "initial_state": sm.initial_state,
                    "reached_privileged_state": reached_priv,
                    "initial_authenticated": True,
                    "initial_role": init_role,
                    "steps_taken": len(trace) - 1,
                    "actions": [s["next_action"] for s in trace[:-1] if "next_action" in s],
                },
                trace=trace,
                remediation=(
                    f"Require privileged role membership and MFA verification on transitions entering '{reached_priv}'."
                ),
                solver_time_ms=elapsed_ms,
            )
        )
    elif res == z3.unsat:
        findings.append(
            FormalVerificationFinding(
                finding_id=_deterministic_finding_id("state_machine", "low_privilege_escalation_reachability", sm.name),
                domain="state_machine",
                invariant_name="low_privilege_escalation_reachability",
                status=STATUS_UNSAT_PROVEN,
                severity="INFO",
                cwe="CWE-269",
                title=f"Low-privilege role escalation unreachable (K={steps})",
                summary=(
                    f"Z3 formally proved no low-privilege role can reach {sm.privileged_states} "
                    f"within K={steps} transition steps."
                ),
                file_path=sm.source_path,
                proof_certificate=_make_proof_certificate(
                    solver,
                    domain="state_machine",
                    invariant_name="low_privilege_escalation_reachability",
                    bounded_steps=steps,
                ),
                proof_summary=f"UNSAT: Low-privilege escalation proven unreachable within K={steps} steps.",
                remediation="No remediation required.",
                solver_time_ms=elapsed_ms,
            )
        )

    # Invariant 3: Cross-tenant reachability when tenant guards/variables are modeled
    if models_tenant:
        t0 = time.perf_counter()
        ctx, solver, syms = _build_bmc_solver()
        solver.add(syms["state_vars"][0] == state_to_id[sm.initial_state])
        solver.add(syms["principal_tenant"] != syms["target_tenant"])
        solver.add(
            z3.Or(
                [
                    syms["state_vars"][t] == state_to_id[ps]
                    for t in range(steps + 1)
                    for ps in sm.privileged_states
                ]
            )
        )
        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        if res == z3.sat:
            m = solver.model()
            trace, reached_priv = _extract_trace(m, syms)
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("state_machine", "cross_tenant_privileged_reachability", f"{sm.name}:{reached_priv}"),
                    domain="state_machine",
                    invariant_name="cross_tenant_privileged_reachability",
                    status=STATUS_SAT_VIOLATION,
                    severity="HIGH",
                    cwe="CWE-639",
                    title=f"Cross-tenant transition reaches privileged state '{reached_priv}'",
                    summary=_sanitize_defensive_text(
                        f"Z3 found a path (K={steps}) to '{reached_priv}' while principal_tenant != target_tenant."
                    ),
                    file_path=sm.source_path,
                    counterexample={
                        "principal_tenant": _model_eval_int(m, syms["principal_tenant"], 0),
                        "target_tenant": _model_eval_int(m, syms["target_tenant"], 1),
                        "reached_privileged_state": reached_priv,
                        "steps_taken": len(trace) - 1,
                    },
                    trace=trace,
                    remediation="Enforce `same_tenant_required: true` on all tenant-sensitive state transitions.",
                    solver_time_ms=elapsed_ms,
                )
            )
        elif res == z3.unsat:
            findings.append(
                FormalVerificationFinding(
                    finding_id=_deterministic_finding_id("state_machine", "cross_tenant_privileged_reachability", sm.name),
                    domain="state_machine",
                    invariant_name="cross_tenant_privileged_reachability",
                    status=STATUS_UNSAT_PROVEN,
                    severity="INFO",
                    cwe="CWE-639",
                    title=f"Cross-tenant privileged state reachability proven blocked (K={steps})",
                    summary=f"Z3 formally proved cross-tenant reachability is blocked within K={steps} steps.",
                    file_path=sm.source_path,
                    proof_certificate=_make_proof_certificate(
                        solver,
                        domain="state_machine",
                        invariant_name="cross_tenant_privileged_reachability",
                        bounded_steps=steps,
                    ),
                    proof_summary=f"UNSAT: Cross-tenant reachability blocked within K={steps} steps.",
                    remediation="No remediation required.",
                    solver_time_ms=elapsed_ms,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Unified Orchestrator & Optional Fail-Closed Scope Bridge Pre-Gate
# ---------------------------------------------------------------------------


def _evaluate_scope_bridge_pregate(
    *,
    scope_bridge: Optional[Any],
    scope_policy: Optional[Dict[str, Any]],
    target_intent: Optional[Dict[str, Any]],
    target_label: str,
) -> Dict[str, Any]:
    """
    Fail-closed scope-gate pre-check before formal verification runs.
    Accepts an injected `scope_bridge` (with `.authorize_intent(...)` or callable),
    or lazily loads `engine.rust_scope_bridge.RustScopeBridge` when M2 is present.
    """
    bridge = scope_bridge
    if bridge is None:
        try:
            from engine.rust_scope_bridge import RustScopeBridge  # type: ignore

            bridge = RustScopeBridge()
        except Exception as exc:
            raise ScopeGateDeniedError(
                f"Scope gate fail-closed: unable to initialize RustScopeBridge ({exc})."
            ) from exc

    intent = dict(target_intent) if isinstance(target_intent, dict) else {
        "target_url": target_label,
        "action": "formal_verify",
        "method": "GET",
        "payload_preview": "",
        "command": "",
    }

    try:
        if hasattr(bridge, "authorize_intent") and callable(bridge.authorize_intent):
            try:
                decision = bridge.authorize_intent(intent=intent, policy=scope_policy)
            except TypeError:
                decision = bridge.authorize_intent(intent, scope_policy)
        elif callable(bridge):
            decision = bridge(intent=intent, policy=scope_policy)
        else:
            raise ScopeGateDeniedError("Invalid scope_bridge object: missing authorize_intent().")
    except ScopeGateDeniedError:
        raise
    except PermissionError as exc:
        raise ScopeGateDeniedError(f"Scope gate denied target intent: {exc}") from exc
    except Exception as exc:
        raise ScopeGateDeniedError(f"Scope gate fail-closed error: {exc}") from exc

    if isinstance(decision, dict):
        decision_dict = dict(decision)
        allowed = decision_dict.get("allowed") is True
    elif hasattr(decision, "allowed"):
        allowed = getattr(decision, "allowed", None) is True
        decision_dict = (
            decision.to_dict()
            if hasattr(decision, "to_dict") and callable(decision.to_dict)
            else {"allowed": allowed, "reasons": list(getattr(decision, "reasons", []))}
        )
    else:
        raise ScopeGateDeniedError("Scope gate fail-closed: unexpected decision payload.")

    if not allowed:
        reasons = decision_dict.get("reasons") or ["Out-of-scope or policy-denied intent."]
        raise ScopeGateDeniedError(f"Scope gate denied verification: {reasons}")

    return decision_dict


def run_z3_formal_verification(
    *,
    openapi_spec: Optional[Union[OpenApiModelIR, str, Path, Dict[str, Any]]] = None,
    iam_policy: Optional[Union[IamPolicyIR, str, Path, Dict[str, Any]]] = None,
    state_machine: Optional[Union[StateMachineIR, str, Path, Dict[str, Any]]] = None,
    target_description: Optional[Union[str, Dict[str, Any]]] = None,
    target_name: str = "rfchunt_formal_target",
    model: Optional[str] = None,
    offline: Optional[bool] = None,
    embedded: bool = False,
    ollama_endpoint: Optional[str] = None,
    max_steps: int = 8,
    timeout_ms: int = 5000,
    scope_bridge: Optional[Any] = None,
    scope_policy: Optional[Dict[str, Any]] = None,
    target_intent: Optional[Dict[str, Any]] = None,
) -> FormalVerificationReport:
    """
    Unified Z3 formal verification entrypoint across OpenAPI, IAM, State Machine,
    and optional model-assisted target translation, with fail-closed scope gating.
    """
    scope_decision: Optional[Dict[str, Any]] = None
    if scope_bridge is not None or scope_policy is not None or target_intent is not None:
        scope_decision = _evaluate_scope_bridge_pregate(
            scope_bridge=scope_bridge,
            scope_policy=scope_policy,
            target_intent=target_intent,
            target_label=target_name,
        )

    findings: List[FormalVerificationFinding] = []
    domains_verified: List[str] = []
    llm_telemetry: Dict[str, Any] = {}

    if openapi_spec is not None:
        domains_verified.append("openapi")
        findings.extend(verify_openapi_invariants(openapi_spec, timeout_ms=timeout_ms))

    if iam_policy is not None:
        domains_verified.append("iam")
        findings.extend(verify_iam_invariants(iam_policy, timeout_ms=timeout_ms))

    if state_machine is not None:
        domains_verified.append("state_machine")
        findings.extend(
            verify_state_machine_invariants(state_machine, max_steps=max_steps, timeout_ms=timeout_ms)
        )

    if target_description is not None:
        translated_sm, llm_telemetry = translate_target_to_formal_model(
            target_description,
            model=model,
            offline=offline,
            embedded=embedded,
            ollama_endpoint=ollama_endpoint,
        )
        if translated_sm is not None:
            if "state_machine" not in domains_verified:
                domains_verified.append("state_machine")
            findings.extend(
                verify_state_machine_invariants(
                    translated_sm, max_steps=max_steps, timeout_ms=timeout_ms
                )
            )

    violations_count = sum(1 for f in findings if f.status == STATUS_SAT_VIOLATION)
    proven_count = sum(1 for f in findings if f.status == STATUS_UNSAT_PROVEN)
    unknown_count = sum(1 for f in findings if f.status == STATUS_UNKNOWN)

    if violations_count > 0:
        overall_status = STATUS_SAT_VIOLATION
    elif unknown_count > 0:
        overall_status = STATUS_UNKNOWN
    elif proven_count > 0:
        overall_status = STATUS_UNSAT_PROVEN
    else:
        overall_status = STATUS_UNKNOWN

    return FormalVerificationReport(
        target=target_name,
        status=overall_status,
        findings=findings,
        violations_count=violations_count,
        proven_count=proven_count,
        unknown_count=unknown_count,
        domains_verified=domains_verified,
        z3_version=z3.get_version_string(),
        llm_translation_telemetry=llm_telemetry,
        scope_gate_decision=scope_decision,
    )


__all__ = [
    "STATUS_SAT_VIOLATION",
    "STATUS_UNSAT_PROVEN",
    "STATUS_UNKNOWN",
    "ScopeGateDeniedError",
    "OpenApiEndpointIR",
    "OpenApiModelIR",
    "IamStatementIR",
    "IamPolicyIR",
    "StateTransitionIR",
    "StateMachineIR",
    "FormalVerificationFinding",
    "FormalVerificationReport",
    "parse_openapi_spec",
    "parse_iam_policy",
    "parse_state_machine",
    "translate_target_to_formal_model",
    "verify_openapi_invariants",
    "verify_iam_invariants",
    "verify_state_machine_invariants",
    "run_z3_formal_verification",
]
