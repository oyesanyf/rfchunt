"""
CLI Authenticated Session & External Surface Importer (Pillar 2 & Pillar 5)
===========================================================================
Hydrates RFCHunt's Dual-Graph `AssetGraph`, `TrafficCaptureSession`, and
multi-role auth contexts strictly from CLI files (zero browser/GUI required):
- `--auth-profile <file.json>`: Named caller contexts (`anonymous`, `end_user_oidc`,
  `service_account`, etc.) for cross-role `AUTH_BOUNDARY` differential verification.
- `--import-har <file.har>`: Parses HAR 1.2 captures into `AssetGraph` endpoints
  and `traffic_evidence` records.
- `--import-openapi <spec.json|yaml>`: Parses OpenAPI 3.x / Swagger 2.0 specs into
  `AssetGraph` `ENDPOINT` nodes with auth metadata for accurate coverage ledgers.
- `--scope-file <scope.txt>`: Loads authorized scope hosts/domains.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import yaml


@dataclass
class AuthProfile:
    """Represents a single caller identity/auth context for CLI boundary testing."""

    name: str
    role: str = "end_user"  # 'anonymous', 'end_user', 'end_user_oidc', 'service', 'admin'
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""

    def build_headers(self) -> Dict[str, str]:
        hdrs = {str(k): str(v) for k, v in self.headers.items()}
        if self.bearer_token and not any(k.lower() == "authorization" for k in hdrs):
            clean_tok = self.bearer_token.strip()
            if clean_tok.lower().startswith("bearer "):
                clean_tok = clean_tok[7:].strip()
            if clean_tok:
                hdrs["Authorization"] = f"Bearer {clean_tok}"
        if self.cookies and not any(k.lower() == "cookie" for k in hdrs):
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return hdrs


def _build_auth_profile(name: str, item: Dict[str, Any]) -> AuthProfile:
    hdrs = dict(item.get("headers") or {})
    bearer = str(item.get("bearer_token") or "")
    token_val = str(item.get("token") or "")
    auth_type = str(item.get("auth_type") or "").strip().lower()
    if auth_type == "header" and item.get("header_name") and token_val:
        hdrs.setdefault(str(item["header_name"]), token_val)
    elif token_val and not bearer:
        bearer = token_val
    return AuthProfile(
        name=name,
        role=str(item.get("role") or name),
        headers=hdrs,
        cookies=dict(item.get("cookies") or {}),
        bearer_token=bearer,
    )


def load_auth_profiles(path: Union[str, Path]) -> Dict[str, AuthProfile]:
    """
    Loads one or more named auth contexts from JSON or YAML.
    Supports `{"profiles": [...]}`, `{"profiles": {"name": {...}}}`, or `{"end_user_oidc": {...}, ...}`.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Auth profile file not found: {p}")
    raw_text = p.read_text(encoding="utf-8-sig")
    data = yaml.safe_load(raw_text) if p.suffix.lower() in (".yml", ".yaml") else json.loads(raw_text)

    profiles: Dict[str, AuthProfile] = {}
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("name"):
                name = str(item["name"])
                profiles[name] = _build_auth_profile(name, item)
    elif isinstance(data, dict) and isinstance(data.get("profiles"), list):
        for item in data["profiles"]:
            if isinstance(item, dict) and item.get("name"):
                name = str(item["name"])
                profiles[name] = _build_auth_profile(name, item)
    elif isinstance(data, dict) and isinstance(data.get("profiles"), dict):
        for name, item in data["profiles"].items():
            if isinstance(item, dict):
                profiles[str(name)] = _build_auth_profile(str(name), item)
    elif isinstance(data, dict) and isinstance(data.get("name"), str) and any(
        k in data for k in ("role", "headers", "cookies", "bearer_token", "token", "auth_type")
    ):
        name = str(data["name"])
        profiles[name] = _build_auth_profile(name, data)
    elif isinstance(data, dict):
        for name, item in data.items():
            if isinstance(item, dict):
                profiles[str(name)] = _build_auth_profile(str(name), item)
    return profiles


def load_scope_file(path: Union[str, Path]) -> Dict[str, List[str]]:
    """
    Reads scope rules from YAML/JSON (`allow_hosts`, `deny_hosts`, `deny_routes`)
    or newline-delimited `.txt` authorized hosts (ignoring `#` comments).
    Always returns `{"allow_hosts": [...], "deny_hosts": [...], "deny_routes": [...]}`.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Scope file not found: {p}")
    raw_text = p.read_text(encoding="utf-8-sig")

    def _norm_host(entry: str) -> str:
        cleaned = str(entry).strip()
        if not cleaned:
            return ""
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            return (parsed.hostname or "").rstrip(".").lower()
        authority = cleaned.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
        if authority.startswith("[") and "]" in authority:
            return authority[1 : authority.index("]")].lower()
        if authority.count(":") >= 2:
            return authority.lower()
        return authority.split(":", 1)[0].rstrip(".").lower()

    if p.suffix.lower() in (".yml", ".yaml", ".json"):
        doc = yaml.safe_load(raw_text) if p.suffix.lower() in (".yml", ".yaml") else json.loads(raw_text)
        if isinstance(doc, dict):
            allow = sorted({_norm_host(h) for h in (doc.get("allow_hosts") or doc.get("allow") or []) if _norm_host(h)})
            deny = sorted({_norm_host(h) for h in (doc.get("deny_hosts") or doc.get("deny") or []) if _norm_host(h)})
            routes = [str(r).strip() for r in (doc.get("deny_routes") or []) if str(r).strip()]
            return {"allow_hosts": allow, "deny_hosts": deny, "deny_routes": routes}
        if isinstance(doc, list):
            allow = sorted({_norm_host(h) for h in doc if _norm_host(h)})
            return {"allow_hosts": allow, "deny_hosts": [], "deny_routes": []}

    hosts: Set[str] = set()
    for line in raw_text.splitlines():
        cleaned = line.split("#", 1)[0].strip()
        if not cleaned:
            continue
        nh = _norm_host(cleaned)
        if nh:
            hosts.add(nh)
    return {"allow_hosts": sorted(hosts), "deny_hosts": [], "deny_routes": []}


def import_openapi_spec(
    spec_path: Union[str, Path],
    asset_graph: Any,
    default_host: str = "127.0.0.1",
    default_port: int = 8080,
    host: Optional[str] = None,
    port: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Imports an OpenAPI 3.x or Swagger 2.0 specification (JSON or YAML) into `AssetGraph`
    so `AssetCoverageLedger` measures real endpoint coverage.
    """
    explicit_host = bool(host)
    explicit_port = port is not None
    if host:
        default_host = host
    if port is not None:
        default_port = int(port)
    p = Path(spec_path)
    if not p.is_file():
        raise FileNotFoundError(f"OpenAPI spec file not found: {p}")
    raw_text = p.read_text(encoding="utf-8-sig")
    spec = yaml.safe_load(raw_text) if p.suffix.lower() in (".yml", ".yaml") else json.loads(raw_text)
    if not isinstance(spec, dict):
        raise ValueError("Invalid OpenAPI/Swagger document.")

    host = default_host
    port = int(default_port)
    server_base_path = ""
    # Extract server URL if caller did not explicitly override host/port
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict) and servers[0].get("url"):
        raw_srv_url = str(servers[0]["url"])
        srv_vars = servers[0].get("variables")
        if isinstance(srv_vars, dict):
            for v_name, v_spec in srv_vars.items():
                if isinstance(v_spec, dict) and v_spec.get("default") is not None:
                    raw_srv_url = raw_srv_url.replace("{" + str(v_name) + "}", str(v_spec["default"]))
        parsed = urlparse(raw_srv_url)
        if parsed.hostname and not explicit_host:
            host = parsed.hostname
        if not explicit_port:
            if parsed.port:
                port = int(parsed.port)
            elif parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "http":
                port = 80
        if parsed.path and parsed.path != "/":
            server_base_path = parsed.path.rstrip("/")
    elif spec.get("host"):
        raw_h = str(spec["host"])
        if raw_h.startswith("[") and "]" in raw_h:
            rb_idx = raw_h.index("]")
            h_part = raw_h[1:rb_idx]
            rest = raw_h[rb_idx + 1:]
            if not explicit_host:
                host = h_part
            if not explicit_port and rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
        elif ":" in raw_h and raw_h.count(":") == 1:
            h_part, prt = raw_h.rsplit(":", 1)
            if not explicit_host:
                host = h_part
            if not explicit_port and prt.isdigit():
                port = int(prt)
        elif not explicit_host:
            host = raw_h

    base_path = str(spec.get("basePath") or server_base_path or "").rstrip("/")
    domain_id = f"ASSET-HOST-{host}"
    port_id = f"ASSET-PORT-{host}-{port}"
    asset_graph.add_asset(domain_id, "DOMAIN", host, {"host": host, "source": "openapi"})
    asset_graph.add_asset(port_id, "IP_PORT", f"{host}:{port}", {"host": host, "port": port, "source": "openapi"})
    asset_graph.add_relation(domain_id, port_id, "HOSTS")

    paths = spec.get("paths") or {}
    http_methods = {"get", "post", "put", "delete", "patch", "head", "options"}
    imported_endpoints: List[str] = []
    ai_sinks_count = 0

    for route_key, path_obj in paths.items():
        if not isinstance(path_obj, dict):
            continue
        full_route = f"{base_path}{route_key}" if base_path else str(route_key)
        for m_name, op in path_obj.items():
            if m_name.lower() not in http_methods or not isinstance(op, dict):
                continue
            method = m_name.upper()
            summary = str(op.get("summary") or op.get("operationId") or "")
            security_reqs = op.get("security") if "security" in op else spec.get("security")
            is_service_route = any(
                tok in full_route.lower()
                for tok in ("/internal", "/service", "/admin", "/worker", "/system", "/rpc", "/agent")
            )
            is_ai_route = any(
                tok in f"{full_route} {summary}".lower()
                for tok in ("/chat", "/completions", "/generate", "/prompt", "/llm", "/agent")
            )
            node_type = "AI_SINK" if is_ai_route else "ENDPOINT"
            ep_hash = hashlib.sha256(f"openapi|{host}|{port}|{method}|{full_route}".encode("utf-8")).hexdigest()[:10]
            ep_id = f"ASSET-EP-{ep_hash}"
            asset_graph.add_asset(
                ep_id,
                node_type,
                f"{method} {full_route}",
                {
                    "host": host,
                    "port": port,
                    "route": full_route,
                    "method": method,
                    "summary": summary,
                    "security": security_reqs or [],
                    "is_service_route": is_service_route,
                    "source": "openapi",
                },
            )
            asset_graph.add_relation(port_id, ep_id, "DISPATCHES_TO" if is_ai_route else "EXPOSES")
            imported_endpoints.append(f"{method} {full_route}")
            if is_ai_route:
                ai_sinks_count += 1

    return {
        "source": str(p),
        "host": host,
        "port": port,
        "endpoints_imported": len(imported_endpoints),
        "ai_sinks_imported": ai_sinks_count,
        "endpoints": imported_endpoints,
    }


def import_har_file(
    har_path: Union[str, Path],
    asset_graph: Any,
    traffic_session: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Imports a standard HAR 1.2 file into `AssetGraph` endpoints and
    `TrafficCaptureSession` (`traffic_evidence`), extracting auth headers/cookies.
    """
    p = Path(har_path)
    if not p.is_file():
        raise FileNotFoundError(f"HAR file not found: {p}")
    har = json.loads(p.read_text(encoding="utf-8-sig"))
    entries = ((har.get("log") or {}).get("entries") or []) if isinstance(har, dict) else []

    endpoints_seen: Set[Tuple[str, int, str, str]] = set()
    recorded_ids: List[str] = []
    discovered_auth_headers: Dict[str, str] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = str(req.get("url") or "")
        if not url:
            continue
        method = str(req.get("method") or "GET").upper()
        if method == "CONNECT":
            continue
        parsed = urlparse(url)
        scheme_lower = (parsed.scheme or "").lower()
        if scheme_lower not in ("http", "https", "ws", "wss"):
            continue
        host = (parsed.hostname or "localhost").lower()
        port = int(parsed.port or (443 if scheme_lower in ("https", "wss") else 80))
        route = parsed.path or "/"

        req_hdrs = {
            str(h.get("name")): str(h.get("value") or "")
            for h in (req.get("headers") or [])
            if isinstance(h, dict) and h.get("name")
        }
        req_cookies = [
            f"{str(c.get('name'))}={str(c.get('value') or '')}"
            for c in (req.get("cookies") or [])
            if isinstance(c, dict) and c.get("name")
        ]
        if req_cookies and not any(k.lower() == "cookie" for k in req_hdrs):
            req_hdrs["Cookie"] = "; ".join(req_cookies)

        resp_hdrs = {
            str(h.get("name")): str(h.get("value") or "")
            for h in (resp.get("headers") or [])
            if isinstance(h, dict) and h.get("name")
        }
        resp_cookies = [
            f"{str(c.get('name'))}={str(c.get('value') or '')}"
            for c in (resp.get("cookies") or [])
            if isinstance(c, dict) and c.get("name")
        ]
        if resp_cookies and not any(k.lower() == "set-cookie" for k in resp_hdrs):
            resp_hdrs["Set-Cookie"] = "; ".join(resp_cookies)

        for k, v in req_hdrs.items():
            if k.lower() in ("authorization", "cookie", "x-api-key"):
                discovered_auth_headers[k] = v

        domain_id = f"ASSET-HOST-{host}"
        port_id = f"ASSET-PORT-{host}-{port}"
        if domain_id not in asset_graph.nodes:
            asset_graph.add_asset(domain_id, "DOMAIN", host, {"host": host, "source": "har"})
        if port_id not in asset_graph.nodes:
            asset_graph.add_asset(port_id, "IP_PORT", f"{host}:{port}", {"host": host, "port": port, "source": "har"})
            asset_graph.add_relation(domain_id, port_id, "HOSTS")

        ep_key = (host, port, method, route)
        if ep_key not in endpoints_seen:
            endpoints_seen.add(ep_key)
            ep_hash = hashlib.sha256(f"har|{host}|{port}|{method}|{route}".encode("utf-8")).hexdigest()[:10]
            ep_id = f"ASSET-EP-{ep_hash}"
            asset_graph.add_asset(
                ep_id,
                "ENDPOINT",
                f"{method} {route}",
                {"host": host, "port": port, "route": route, "method": method, "source": "har"},
            )
            asset_graph.add_relation(port_id, ep_id, "EXPOSES")

        if traffic_session is not None:
            req_body = str((req.get("postData") or {}).get("text") or "")
            resp_content = resp.get("content") or {}
            resp_text = str(resp_content.get("text") or "")
            if str(resp_content.get("encoding") or "").strip().lower() == "base64" and resp_text:
                try:
                    resp_bytes = base64.b64decode(resp_text)
                except Exception:
                    resp_bytes = resp_text.encode("utf-8", errors="replace")
            else:
                resp_bytes = resp_text.encode("utf-8", errors="replace")
            ex = traffic_session.record_exchange(
                method=method,
                url=url,
                host=host,
                port=port,
                request_headers=req_hdrs,
                request_body=req_body,
                status_code=int(resp.get("status") or 0),
                response_headers=resp_hdrs,
                response_body=resp_bytes,
                source="har_import",
            )
            recorded_ids.append(ex.traffic_id)

    return {
        "source": str(p),
        "entries_processed": len(entries),
        "endpoints_imported": len(endpoints_seen),
        "traffic_recorded": len(recorded_ids),
        "auth_headers_found": sorted(discovered_auth_headers.keys()),
        "extracted_auth_headers": discovered_auth_headers,
    }
