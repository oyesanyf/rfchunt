"""
Module 4: Multi-Implementation Differential Oracle (P0 + AIxCC Docker Parser Matrix).

Dispatches identical protocol wire probes to multiple real parsers/endpoints
(including an ephemeral loopback-bound local Docker parser matrix covering
nginx, envoy, haproxy, Node undici, Go net/http, and Rust hyper) and evaluates
signature-free divergence across status codes, header/body framing semantics,
acceptance boundaries, and socket connection states.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from engine.host_containment import silent_subprocess_run
from engine.http_framing import HTTPFramingReader
from engine.taxonomy import AnomalyCategory, ImplementationAnomaly


_DOCKER_IMAGE_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?$"
)
_CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
_LOOPBACK_PORT_PUBLISH_RE = re.compile(r"^127\.0\.0\.1:(\d{1,5}):(\d{1,5})(?:/tcp)?$")
_SHELL_META_TOKENS: Tuple[str, ...] = (
    "$(",
    "`",
    "${",
    "\n",
    "\r",
    "\x00",
    "|",
    ";",
    "&",
    ">",
    "<",
    "(",
    ")",
)
_FORBIDDEN_DOCKER_PAYLOAD_BINARIES: Set[str] = {
    "sh",
    "sh.exe",
    "bash",
    "bash.exe",
    "zsh",
    "dash",
    "ash",
    "ksh",
    "csh",
    "fish",
    "busybox",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "nmap",
    "ffuf",
    "dalfox",
    "sqlmap",
}
_CRITICAL_HOST_MOUNT_PREFIXES: Tuple[str, ...] = (
    "/etc",
    "/var/run/docker.sock",
    "/var/run",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/root",
)


# ==============================================================================
# REAL HTTP PARSER MATRIX CONTAINER CONFIGS / CLEAN-ROOM RESPONDERS
# ==============================================================================

_NGINX_MATRIX_CONF = """\
daemon off;
worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;

events {
    worker_connections 64;
}

http {
    access_log off;
    client_body_temp_path /tmp/nginx_body;
    proxy_temp_path /tmp/nginx_proxy;
    fastcgi_temp_path /tmp/nginx_fastcgi;
    uwsgi_temp_path /tmp/nginx_uwsgi;
    scgi_temp_path /tmp/nginx_scgi;

    server {
        listen 8080;
        server_name _;

        location / {
            add_header X-Parser-Impl "nginx" always;
            add_header X-Parsed-Method $request_method always;
            add_header X-Parsed-Path $uri always;
            add_header X-Parsed-CL $content_length always;
            return 200 "OK\\n";
        }
    }
}
"""

_ENVOY_MATRIX_YAML = """\
static_resources:
  listeners:
    - name: rfchunt_diff_http
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: rfchunt_diff
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: local_service
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          direct_response:
                            status: 200
                            body:
                              inline_string: "OK\\n"
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"""

_HAPROXY_MATRIX_CFG = """\
global
    maxconn 64

defaults
    mode http
    timeout connect 2000ms
    timeout client 3000ms
    timeout server 3000ms

frontend rfchunt_http_in
    bind *:8080
    http-request return status 200 content-type text/plain hdr X-Parser-Impl haproxy lf-string "OK\\n"
"""

_NODE_UNDICI_MATRIX_JS = """\
import http from 'node:http';

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const payload = JSON.stringify({
      parser: 'node_undici',
      parsed_method: req.method || '',
      parsed_path: req.url || '',
      parsed_content_length: req.headers['content-length'] ?? null,
      parsed_transfer_encoding: req.headers['transfer-encoding'] ?? null,
      parsed_body_len: body.length,
      parsed_header_count: Object.keys(req.headers).length,
    });
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-Parser-Impl': 'node_undici',
      'X-Parsed-Method': String(req.method || ''),
      'X-Parsed-Path': String(req.url || ''),
      'X-Parsed-Body-Len': String(body.length),
      'X-Parsed-CL': String(req.headers['content-length'] ?? ''),
      'Connection': 'close',
    });
    res.end(payload);
  });
});

server.on('clientError', (_err, socket) => {
  if (socket.writable) {
    socket.end('HTTP/1.1 400 Bad Request\\r\\nX-Parser-Impl: node_undici\\r\\nConnection: close\\r\\nContent-Length: 0\\r\\n\\r\\n');
  }
});

server.listen(8080, '0.0.0.0');
"""

_GO_NET_HTTP_MATRIX_GO = """\
package main

import (
\t"encoding/json"
\t"io"
\t"net/http"
\t"strconv"
\t"strings"
)

func main() {
\tmux := http.NewServeMux()
\tmux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
\t\tbody, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
\t\t_ = r.Body.Close()
\t\tresp := map[string]any{
\t\t\t"parser":                   "go_net_http",
\t\t\t"parsed_method":            r.Method,
\t\t\t"parsed_path":              r.RequestURI,
\t\t\t"parsed_content_length":    r.ContentLength,
\t\t\t"parsed_transfer_encoding": strings.Join(r.TransferEncoding, ","),
\t\t\t"parsed_body_len":          len(body),
\t\t\t"parsed_header_count":      len(r.Header),
\t\t}
\t\tw.Header().Set("Content-Type", "application/json")
\t\tw.Header().Set("X-Parser-Impl", "go_net_http")
\t\tw.Header().Set("X-Parsed-Method", r.Method)
\t\tw.Header().Set("X-Parsed-Path", r.RequestURI)
\t\tw.Header().Set("X-Parsed-Body-Len", strconv.Itoa(len(body)))
\t\tw.Header().Set("X-Parsed-CL", strconv.FormatInt(r.ContentLength, 10))
\t\tw.Header().Set("Connection", "close")
\t\tw.WriteHeader(http.StatusOK)
\t\t_ = json.NewEncoder(w).Encode(resp)
\t})
\t_ = http.ListenAndServe("0.0.0.0:8080", mux)
}
"""

_RUST_HYPER_MATRIX_RS = """\
// Minimal Rust hyper HTTP/1.1 differential parser responder reference source.
// Prebuilt hyper images expose /usr/local/bin/rfchunt-hyper-server listening on 0.0.0.0:8080.
use std::convert::Infallible;
use std::net::SocketAddr;

pub const LISTEN_ADDR: &str = "0.0.0.0:8080";
pub const PARSER_IMPL: &str = "rust_hyper";
"""


@dataclass(frozen=True)
class ParserMatrixSpec:
    """Specification for a single real HTTP/protocol parser container in DockerParserMatrix."""

    name: str
    display_name: str
    image: str
    container_port: int = 8080
    protocol: str = "http/1.1"
    entrypoint: Optional[str] = None
    command: Tuple[str, ...] = ()
    config_filename: Optional[str] = None
    config_mount_path: Optional[str] = None
    config_content: str = ""
    tmpfs_mounts: Tuple[str, ...] = ("/tmp:rw,noexec,nosuid,size=64m",)
    env: Tuple[Tuple[str, str], ...] = ()
    memory_limit: str = "256m"
    cpus: str = "1.0"
    pids_limit: int = 128
    startup_timeout: float = 15.0


DEFAULT_PARSER_MATRIX_SPECS: Dict[str, ParserMatrixSpec] = {
    "nginx": ParserMatrixSpec(
        name="nginx",
        display_name="Nginx HTTP/1.1",
        image="nginx:1.27-alpine",
        container_port=8080,
        protocol="http/1.1",
        command=("nginx",),
        config_filename="nginx.conf",
        config_mount_path="/etc/nginx/nginx.conf",
        config_content=_NGINX_MATRIX_CONF,
        tmpfs_mounts=(
            "/tmp:rw,noexec,nosuid,size=64m",
            "/var/cache/nginx:rw,noexec,nosuid,size=32m",
        ),
        memory_limit="256m",
        cpus="1.0",
        pids_limit=128,
        startup_timeout=12.0,
    ),
    "envoy": ParserMatrixSpec(
        name="envoy",
        display_name="Envoy Proxy",
        image="envoyproxy/envoy:v1.31-latest",
        container_port=8080,
        protocol="http/1.1",
        command=("envoy", "--config-path", "/etc/envoy/rfchunt.yaml", "--concurrency", "1"),
        config_filename="envoy.yaml",
        config_mount_path="/etc/envoy/rfchunt.yaml",
        config_content=_ENVOY_MATRIX_YAML,
        tmpfs_mounts=("/tmp:rw,noexec,nosuid,size=64m",),
        memory_limit="512m",
        cpus="1.0",
        pids_limit=128,
        startup_timeout=15.0,
    ),
    "haproxy": ParserMatrixSpec(
        name="haproxy",
        display_name="HAProxy",
        image="haproxy:3.0-alpine",
        container_port=8080,
        protocol="http/1.1",
        command=("haproxy", "-W", "-db", "-f", "/usr/local/etc/haproxy/rfchunt.cfg"),
        config_filename="haproxy.cfg",
        config_mount_path="/usr/local/etc/haproxy/rfchunt.cfg",
        config_content=_HAPROXY_MATRIX_CFG,
        tmpfs_mounts=("/tmp:rw,noexec,nosuid,size=32m",),
        memory_limit="256m",
        cpus="1.0",
        pids_limit=128,
        startup_timeout=12.0,
    ),
    "node_undici": ParserMatrixSpec(
        name="node_undici",
        display_name="Node.js undici/llhttp",
        image="node:22-alpine",
        container_port=8080,
        protocol="http/1.1",
        command=("node", "/harness/server.mjs"),
        config_filename="server.mjs",
        config_mount_path="/harness/server.mjs",
        config_content=_NODE_UNDICI_MATRIX_JS,
        tmpfs_mounts=("/tmp:rw,noexec,nosuid,size=64m",),
        memory_limit="256m",
        cpus="1.0",
        pids_limit=128,
        startup_timeout=12.0,
    ),
    "go_net_http": ParserMatrixSpec(
        name="go_net_http",
        display_name="Go net/http",
        image="golang:1.23-alpine",
        container_port=8080,
        protocol="http/1.1",
        command=("go", "run", "/harness/main.go"),
        config_filename="main.go",
        config_mount_path="/harness/main.go",
        config_content=_GO_NET_HTTP_MATRIX_GO,
        tmpfs_mounts=("/tmp:rw,nosuid,size=128m",),
        env=(("GOCACHE", "/tmp/gocache"), ("GOPATH", "/tmp/gopath"), ("HOME", "/tmp")),
        memory_limit="512m",
        cpus="1.0",
        pids_limit=128,
        startup_timeout=20.0,
    ),
    "rust_hyper": ParserMatrixSpec(
        name="rust_hyper",
        display_name="Rust hyper",
        image=os.environ.get("RFCHUNT_RUST_HYPER_IMAGE", "rfchunt/rust-hyper:latest").strip()
        or "rfchunt/rust-hyper:latest",
        container_port=8080,
        protocol="http/1.1",
        command=("/usr/local/bin/rfchunt-hyper-server",),
        config_filename="hyper_reference.rs",
        config_mount_path="/harness/hyper_reference.rs",
        config_content=_RUST_HYPER_MATRIX_RS,
        tmpfs_mounts=("/tmp:rw,noexec,nosuid,size=64m",),
        memory_limit="256m",
        cpus="1.0",
        pids_limit=128,
        startup_timeout=15.0,
    ),
}

PARSER_NAME_ALIASES: Dict[str, str] = {
    "nginx": "nginx",
    "envoy": "envoy",
    "haproxy": "haproxy",
    "undici": "node_undici",
    "node": "node_undici",
    "node_undici": "node_undici",
    "node-undici": "node_undici",
    "go": "go_net_http",
    "net/http": "go_net_http",
    "go_net_http": "go_net_http",
    "go-net-http": "go_net_http",
    "rust": "rust_hyper",
    "hyper": "rust_hyper",
    "rust_hyper": "rust_hyper",
    "rust-hyper": "rust_hyper",
}

DEFAULT_DIFFERENTIAL_PROBES: Tuple[Tuple[str, bytes], ...] = (
    (
        "RFC9112-PRE-COLON-WHITESPACE",
        b"GET / HTTP/1.1\r\nHost : target.local\r\nConnection: close\r\n\r\n",
    ),
    (
        "RFC9112-OBS-FOLD",
        b"GET / HTTP/1.1\r\nHost: target.local\r\nX-Fold: a\r\n b\r\nConnection: close\r\n\r\n",
    ),
    (
        "RFC9112-DUPLICATE-CONFLICTING-CL",
        b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 5\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello",
    ),
    (
        "RFC9112-TE-AND-CL",
        b"POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\nConnection: close\r\n\r\n0\r\n\r\n",
    ),
    (
        "RFC9112-BARE-LF-HEADER",
        b"GET / HTTP/1.1\r\nHost: target.local\nX-Bare: 1\r\nConnection: close\r\n\r\n",
    ),
    (
        "RFC9112-CHUNK-EXT",
        b"POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n",
    ),
)


@dataclass
class TargetEndpoint:
    name: str
    host: str
    port: int
    timeout: float = 3.0


@dataclass
class TargetResponse:
    target_name: str
    status_code: int
    headers: Dict[str, str]
    raw_response: bytes
    latency: float
    socket_state: str  # 'OK', 'TIMEOUT', 'CONNECTION_CLOSED', 'CONNECTION_REFUSED'


@dataclass
class DifferentialResult:
    """Structured result of a signature-free multi-implementation differential evaluation."""

    status: str  # 'divergent', 'consistent', 'skipped_docker_unavailable', 'skipped_insufficient_parsers', 'error'
    parser_matrix_backend: str  # 'docker_parser_matrix', 'loopback_http_endpoints', 'reference_4parser_fallback', 'docker_unavailable'
    is_divergent: bool
    divergence_vector: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    divergence_dimensions: List[str] = field(default_factory=list)
    active_parsers: List[str] = field(default_factory=list)
    unavailable_parsers: List[str] = field(default_factory=list)
    unavailable_reasons: Dict[str, str] = field(default_factory=dict)
    anomaly: Optional[ImplementationAnomaly] = None
    raw_probe_preview: str = ""
    rule_id: Optional[str] = None
    provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "parser_matrix_backend": self.parser_matrix_backend,
            "is_divergent": self.is_divergent,
            "divergence_vector": self.divergence_vector,
            "divergence_dimensions": list(self.divergence_dimensions),
            "active_parsers": list(self.active_parsers),
            "unavailable_parsers": list(self.unavailable_parsers),
            "unavailable_reasons": dict(self.unavailable_reasons),
            "anomaly": self.anomaly.to_dict() if self.anomaly is not None else None,
            "raw_probe_preview": self.raw_probe_preview,
            "rule_id": self.rule_id,
            "provenance": dict(self.provenance),
        }


def _is_critical_mount_source(src: str) -> bool:
    raw_s = str(src or "").strip()
    if not raw_s:
        return True
    norm = raw_s.replace("\\", "/")
    if norm.startswith("//") or ".." in [p for p in norm.split("/") if p]:
        return True
    norm_l = re.sub(r"/+", "/", norm).rstrip("/").lower()
    if norm_l in ("", "/") or re.fullmatch(r"[a-z]:/*", norm_l):
        return True
    for crit in _CRITICAL_HOST_MOUNT_PREFIXES:
        if norm_l == crit or norm_l.startswith(crit + "/"):
            return True
    if re.match(
        r"^[a-z]:/(?:windows|programdata|program files|program files \(x86\)|system32)(?:/|$)",
        norm_l,
    ):
        return True
    return False


def validate_parser_matrix_docker_command(cmd: Sequence[str]) -> Tuple[bool, str]:
    """
    Fail-closed validator for ephemeral loopback Docker parser matrix commands.
    Enforces shell=False list argv, no --network=host, no --privileged/--cap-add,
    mandatory --rm and --cap-drop=ALL, strictly 127.0.0.1 loopback port bindings,
    read-only mounts, and zero shell metacharacters or shell wrappers.
    """
    if isinstance(cmd, (str, bytes, bytearray)) or not isinstance(cmd, Sequence) or len(cmd) < 3:
        return False, "docker command must be a non-empty list/sequence of argv strings"

    tokens = [str(tok) for tok in cmd]
    bin_name = PurePosixPath(tokens[0].replace("\\", "/")).name.lower()
    if bin_name not in ("docker", "docker.exe"):
        return False, f"binary '{tokens[0]}' is not docker"

    for tok in tokens:
        if any(meta in tok for meta in _SHELL_META_TOKENS):
            return False, f"shell metacharacter forbidden in docker token '{tok}'"

    subcmd = tokens[1].strip().lower()
    if subcmd != "run":
        return False, f"expected 'docker run', got '{subcmd}'"

    has_rm = False
    has_cap_drop_all = False
    has_loopback_publish = False

    idx = 2
    while idx < len(tokens):
        tok = tokens[idx].strip()
        tok_l = tok.lower()

        if tok_l == "--rm":
            has_rm = True
        elif tok_l == "--cap-drop=all" or (
            tok_l == "--cap-drop" and idx + 1 < len(tokens) and tokens[idx + 1].strip().lower() == "all"
        ):
            has_cap_drop_all = True
        elif tok_l == "--privileged" or tok_l.startswith("--privileged="):
            return False, "docker '--privileged' is forbidden"
        elif tok_l == "--cap-add" or tok_l.startswith("--cap-add="):
            return False, "docker '--cap-add' is forbidden"
        elif tok_l == "--device" or tok_l.startswith("--device="):
            return False, "docker '--device' is forbidden"
        elif tok_l == "--volumes-from" or tok_l.startswith("--volumes-from="):
            return False, "docker '--volumes-from' is forbidden"
        elif tok_l in ("--network", "--net", "--pid", "--ipc", "--uts", "--userns", "--cgroupns"):
            val = tokens[idx + 1].strip().lower() if idx + 1 < len(tokens) else ""
            if val == "host" or val.startswith("container:"):
                return False, f"docker isolation-escape '{tok}={val}' is forbidden"
        elif tok_l.startswith(("--network=", "--net=", "--pid=", "--ipc=", "--uts=", "--userns=", "--cgroupns=")):
            val = tok_l.split("=", 1)[1].strip()
            if val == "host" or val.startswith("container:"):
                return False, f"docker isolation-escape '{tok}' is forbidden"
        elif tok_l in ("-p", "--publish") and idx + 1 < len(tokens):
            pub = tokens[idx + 1].strip()
            m = _LOOPBACK_PORT_PUBLISH_RE.fullmatch(pub)
            if not m:
                return False, f"docker publish '{pub}' must bind strictly to 127.0.0.1:<host>:<container>"
            hp, cp = int(m.group(1)), int(m.group(2))
            if not (1 <= hp <= 65535 and 1 <= cp <= 65535):
                return False, f"docker publish port out of range in '{pub}'"
            has_loopback_publish = True
            idx += 2
            continue
        elif tok_l.startswith("--publish="):
            pub = tok.split("=", 1)[1].strip()
            m = _LOOPBACK_PORT_PUBLISH_RE.fullmatch(pub)
            if not m:
                return False, f"docker publish '{pub}' must bind strictly to 127.0.0.1:<host>:<container>"
            has_loopback_publish = True
        elif tok_l in ("-v", "--volume") and idx + 1 < len(tokens):
            spec = tokens[idx + 1].strip()
            norm_spec = spec.replace("\\", "/")
            if not norm_spec.endswith(":ro"):
                return False, f"docker parser matrix mount '{spec}' must be read-only (:ro)"
            if re.match(r"^[a-zA-Z]:", norm_spec):
                c_idx = norm_spec.find(":", 2)
                src = norm_spec[:c_idx] if c_idx != -1 else norm_spec
            else:
                src = norm_spec.split(":", 1)[0]
            if _is_critical_mount_source(src):
                return False, f"unsafe docker host mount source '{src}'"
            idx += 2
            continue
        elif tok_l in ("-c", "/c", "-lc", "-ic", "-ec", "--command") or tok_l.startswith("--command="):
            return False, f"forbidden shell flag '{tok}' in docker command"
        elif not tok.startswith("-"):
            base = PurePosixPath(tok.split("@", 1)[0].replace("\\", "/")).name.lower().split(":", 1)[0]
            if base in _FORBIDDEN_DOCKER_PAYLOAD_BINARIES:
                return False, f"forbidden shell/scanner binary '{tok}' in docker command"
        idx += 1

    if not has_rm:
        return False, "docker parser matrix command requires '--rm'"
    if not has_cap_drop_all:
        return False, "docker parser matrix command requires '--cap-drop=ALL'"
    if not has_loopback_publish:
        return False, "docker parser matrix command requires strictly 127.0.0.1 loopback port publish"
    return True, "ok"


def _wait_for_loopback_tcp(host: str, port: int, timeout: float = 12.0) -> bool:
    """Polls 127.0.0.1:<port> until a TCP listener accepts connections or timeout elapses."""
    deadline = time.monotonic() + max(0.2, float(timeout))
    while time.monotonic() < deadline:
        sock = None
        try:
            sock = socket.create_connection((host, int(port)), timeout=0.4)
            return True
        except OSError:
            time.sleep(0.15)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return False


class DockerParserMatrix:
    """
    Ephemeral loopback-bound local Docker parser matrix manager covering real
    HTTP/protocol implementations (nginx, envoy, haproxy, Node undici, Go net/http,
    and Rust hyper). Strictly enforces 127.0.0.1 port binding, shell=False,
    capability dropping, and guaranteed teardown in `finally` / `__exit__`.
    """

    def __init__(
        self,
        parsers: Optional[Sequence[str]] = None,
        *,
        specs: Optional[Dict[str, ParserMatrixSpec]] = None,
        docker_bin: Optional[str] = None,
        docker_timeout: float = 3.0,
        startup_timeout: Optional[float] = None,
        image_overrides: Optional[Dict[str, str]] = None,
        subprocess_runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
        readiness_probe: Optional[Callable[[str, int, float], bool]] = None,
        endpoint_timeout: float = 3.0,
    ) -> None:
        base_specs = dict(specs or DEFAULT_PARSER_MATRIX_SPECS)
        if image_overrides:
            for key, img in image_overrides.items():
                canonical = self.resolve_parser_names([key], available_specs=base_specs)[0]
                if canonical in base_specs and img:
                    spec = base_specs[canonical]
                    base_specs[canonical] = ParserMatrixSpec(
                        name=spec.name,
                        display_name=spec.display_name,
                        image=str(img).strip(),
                        container_port=spec.container_port,
                        protocol=spec.protocol,
                        entrypoint=spec.entrypoint,
                        command=spec.command,
                        config_filename=spec.config_filename,
                        config_mount_path=spec.config_mount_path,
                        config_content=spec.config_content,
                        tmpfs_mounts=spec.tmpfs_mounts,
                        env=spec.env,
                        memory_limit=spec.memory_limit,
                        cpus=spec.cpus,
                        pids_limit=spec.pids_limit,
                        startup_timeout=spec.startup_timeout,
                    )
        self._specs: Dict[str, ParserMatrixSpec] = base_specs
        self.requested_parsers: List[str] = self.resolve_parser_names(parsers, available_specs=self._specs)
        self._docker_bin_override: Optional[str] = docker_bin
        self.docker_timeout: float = max(0.5, float(docker_timeout))
        self.startup_timeout_override: Optional[float] = startup_timeout
        self.endpoint_timeout: float = max(0.5, float(endpoint_timeout))
        self._runner = subprocess_runner or silent_subprocess_run
        self._readiness_probe = readiness_probe or _wait_for_loopback_tcp

        self.docker_available: bool = False
        self.docker_version: str = ""
        self.docker_error: str = ""
        self.active_endpoints: List[TargetEndpoint] = []
        self.active_parsers: List[str] = []
        self.unavailable_parsers: List[str] = []
        self.unavailable_reasons: Dict[str, str] = {}
        self.started_containers: Dict[str, str] = {}
        self.built_commands: Dict[str, List[str]] = {}
        self._temp_dir: Optional[Path] = None

    @staticmethod
    def resolve_parser_names(
        parsers: Optional[Sequence[str]] = None,
        *,
        available_specs: Optional[Dict[str, ParserMatrixSpec]] = None,
    ) -> List[str]:
        spec_map = available_specs or DEFAULT_PARSER_MATRIX_SPECS
        if not parsers:
            return list(spec_map.keys())
        resolved: List[str] = []
        for raw in parsers:
            key = str(raw or "").strip().lower()
            canonical = PARSER_NAME_ALIASES.get(key, key)
            if canonical in spec_map and canonical not in resolved:
                resolved.append(canonical)
            elif key in spec_map and key not in resolved:
                resolved.append(key)
        return resolved

    def resolve_docker_bin(self) -> Optional[str]:
        if self._docker_bin_override:
            return self._docker_bin_override
        return shutil.which("docker")

    @staticmethod
    def allocate_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return int(s.getsockname()[1])

    def _run_docker(self, args: List[str], *, timeout: Optional[float] = None) -> subprocess.CompletedProcess:
        return self._runner(
            args,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout or self.docker_timeout,
        )

    def check_docker_available(self) -> Tuple[bool, str]:
        docker_bin = self.resolve_docker_bin()
        if not docker_bin:
            return False, "docker binary not found on PATH"
        try:
            proc = self._run_docker(
                [docker_bin, "info", "--format", "{{.ServerVersion}}"],
                timeout=self.docker_timeout,
            )
            if proc.returncode == 0:
                version = (proc.stdout or "").strip() or "unknown"
                return True, version
            err = (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()
            return False, err[:240]
        except subprocess.TimeoutExpired:
            return False, f"docker daemon probe timed out after {self.docker_timeout:.1f}s"
        except OSError as exc:
            return False, str(exc)

    def check_image_available(self, image: str) -> Tuple[bool, str]:
        img = str(image or "").strip()
        if not _DOCKER_IMAGE_RE.fullmatch(img):
            return False, f"invalid docker image reference '{img}'"
        docker_bin = self.resolve_docker_bin()
        if not docker_bin:
            return False, "docker binary not found"
        try:
            proc = self._run_docker(
                [docker_bin, "image", "inspect", "--format", "{{.Id}}", img],
                timeout=self.docker_timeout,
            )
            if proc.returncode == 0:
                return True, (proc.stdout or "").strip()
            return False, f"image '{img}' not present locally"
        except subprocess.TimeoutExpired:
            return False, f"docker image inspect timed out for '{img}'"
        except OSError as exc:
            return False, str(exc)

    def build_run_command(
        self,
        spec: ParserMatrixSpec,
        *,
        container_name: str,
        host_port: int,
        config_host_path: Optional[Path] = None,
    ) -> List[str]:
        docker_bin = self.resolve_docker_bin() or "docker"
        if not _DOCKER_IMAGE_RE.fullmatch(spec.image):
            raise ValueError(f"Unsafe Docker image name rejected: {spec.image!r}")
        if not _CONTAINER_NAME_RE.fullmatch(container_name):
            raise ValueError(f"Unsafe Docker container name rejected: {container_name!r}")
        if not (1 <= int(host_port) <= 65535 and 1 <= int(spec.container_port) <= 65535):
            raise ValueError(f"Invalid port mapping: {host_port}->{spec.container_port}")

        cmd: List[str] = [
            docker_bin,
            "run",
            "-d",
            "--rm",
            "--name",
            container_name,
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--memory",
            str(spec.memory_limit),
            "--cpus",
            str(spec.cpus),
            "--pids-limit",
            str(int(spec.pids_limit)),
            "-p",
            f"127.0.0.1:{int(host_port)}:{int(spec.container_port)}",
        ]
        for tmpfs in spec.tmpfs_mounts:
            cmd.extend(["--tmpfs", str(tmpfs)])
        for k, v in spec.env:
            cmd.extend(["-e", f"{k}={v}"])
        if config_host_path is not None and spec.config_mount_path:
            host_mount = str(Path(config_host_path).resolve()).replace("\\", "/")
            cmd.extend(["-v", f"{host_mount}:{spec.config_mount_path}:ro"])
        if spec.entrypoint:
            cmd.extend(["--entrypoint", spec.entrypoint])
        cmd.append(spec.image)
        cmd.extend(list(spec.command))

        ok, reason = validate_parser_matrix_docker_command(cmd)
        if not ok:
            raise PermissionError(f"Hardened Docker parser matrix command rejected: {reason}")
        return cmd

    def start(self) -> Dict[str, Any]:
        """
        Inspects Docker/image availability and launches ephemeral loopback-bound
        parser containers concurrently. Returns structured provenance status without
        raising when Docker daemon or images are unavailable.
        """
        self.active_endpoints = []
        self.active_parsers = []
        self.unavailable_parsers = []
        self.unavailable_reasons = {}
        self.started_containers = {}
        self.built_commands = {}

        docker_ok, docker_info = self.check_docker_available()
        self.docker_available = docker_ok
        if not docker_ok:
            self.docker_error = docker_info
            self.unavailable_parsers = list(self.requested_parsers)
            self.unavailable_reasons = {p: f"docker_unavailable: {docker_info}" for p in self.requested_parsers}
            return {
                "status": "skipped_docker_unavailable",
                "docker_available": False,
                "docker_error": docker_info,
                "active_parsers": [],
                "unavailable_parsers": list(self.unavailable_parsers),
                "unavailable_reasons": dict(self.unavailable_reasons),
            }

        self.docker_version = docker_info
        self._temp_dir = Path(tempfile.mkdtemp(prefix="rfchunt_diff_matrix_"))

        # Check local image availability concurrently
        available_specs: List[ParserMatrixSpec] = []
        max_workers = max(1, min(len(self.requested_parsers), 6))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            img_futures = {
                pool.submit(self.check_image_available, self._specs[p].image): p
                for p in self.requested_parsers
                if p in self._specs
            }
            img_status: Dict[str, Tuple[bool, str]] = {}
            for fut in as_completed(img_futures):
                p_name = img_futures[fut]
                img_status[p_name] = fut.result()

        for p_name in self.requested_parsers:
            spec = self._specs.get(p_name)
            if spec is None:
                self.unavailable_parsers.append(p_name)
                self.unavailable_reasons[p_name] = "unknown_parser_spec"
                continue
            ok, detail = img_status.get(p_name, (False, "image_check_failed"))
            if not ok:
                self.unavailable_parsers.append(p_name)
                self.unavailable_reasons[p_name] = detail
            else:
                available_specs.append(spec)

        if not available_specs:
            self.stop()
            return {
                "status": "skipped_docker_unavailable",
                "docker_available": True,
                "docker_version": self.docker_version,
                "reason": "no_parser_images_available_locally",
                "active_parsers": [],
                "unavailable_parsers": list(self.unavailable_parsers),
                "unavailable_reasons": dict(self.unavailable_reasons),
            }

        def _launch_one(spec: ParserMatrixSpec) -> Tuple[str, Optional[TargetEndpoint], Optional[str], Optional[str], Optional[List[str]]]:
            host_port = self.allocate_loopback_port()
            cid_name = f"rfchunt-diff-{spec.name.replace('_', '-')}-{secrets.token_hex(4)}"
            cfg_path: Optional[Path] = None
            if spec.config_filename and spec.config_content and self._temp_dir is not None:
                cfg_path = self._temp_dir / f"{spec.name}_{spec.config_filename}"
                cfg_path.write_text(spec.config_content, encoding="utf-8")

            cmd = self.build_run_command(
                spec,
                container_name=cid_name,
                host_port=host_port,
                config_host_path=cfg_path,
            )
            try:
                proc = self._run_docker(cmd, timeout=max(10.0, self.docker_timeout * 3.0))
            except Exception as exc:
                return spec.name, None, None, f"docker_run_failed: {exc}", cmd

            if proc.returncode != 0:
                err = (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()[:240]
                return spec.name, None, None, f"docker_run_exit_{proc.returncode}: {err}", cmd

            ready_timeout = (
                float(self.startup_timeout_override)
                if self.startup_timeout_override is not None
                else float(spec.startup_timeout)
            )
            if not self._readiness_probe("127.0.0.1", host_port, ready_timeout):
                self._remove_container(cid_name)
                return spec.name, None, None, f"container_not_ready_within_{ready_timeout:.1f}s", cmd

            endpoint = TargetEndpoint(
                name=spec.name,
                host="127.0.0.1",
                port=host_port,
                timeout=self.endpoint_timeout,
            )
            return spec.name, endpoint, cid_name, None, cmd

        launch_results: Dict[str, Tuple[Optional[TargetEndpoint], Optional[str], Optional[str], Optional[List[str]]]] = {}
        with ThreadPoolExecutor(max_workers=max(1, min(len(available_specs), 6))) as pool:
            futs = {pool.submit(_launch_one, spec): spec.name for spec in available_specs}
            for fut in as_completed(futs):
                p_name, ep, cid_name, err, cmd = fut.result()
                launch_results[p_name] = (ep, cid_name, err, cmd)

        for spec in available_specs:
            ep, cid_name, err, cmd = launch_results[spec.name]
            if cmd is not None:
                self.built_commands[spec.name] = cmd
            if ep is not None and cid_name is not None:
                self.active_endpoints.append(ep)
                self.active_parsers.append(spec.name)
                self.started_containers[spec.name] = cid_name
            else:
                self.unavailable_parsers.append(spec.name)
                self.unavailable_reasons[spec.name] = err or "startup_failed"

        status = "ready" if len(self.active_endpoints) >= 2 else "skipped_docker_unavailable"
        return {
            "status": status,
            "docker_available": True,
            "docker_version": self.docker_version,
            "active_parsers": list(self.active_parsers),
            "unavailable_parsers": list(self.unavailable_parsers),
            "unavailable_reasons": dict(self.unavailable_reasons),
            "started_containers": dict(self.started_containers),
        }

    def _remove_container(self, container_name: str) -> bool:
        if not _CONTAINER_NAME_RE.fullmatch(container_name):
            return False
        docker_bin = self.resolve_docker_bin()
        if not docker_bin:
            return False
        try:
            proc = self._run_docker([docker_bin, "rm", "-f", container_name], timeout=max(5.0, self.docker_timeout))
            return proc.returncode == 0
        except Exception:
            return False

    def stop(self) -> Dict[str, Any]:
        """Idempotently force-removes all started ephemeral containers and temporary config files."""
        containers = dict(self.started_containers)
        removed: List[str] = []
        if containers:
            with ThreadPoolExecutor(max_workers=max(1, min(len(containers), 6))) as pool:
                futs = {pool.submit(self._remove_container, cid): name for name, cid in containers.items()}
                for fut in as_completed(futs):
                    name = futs[fut]
                    try:
                        if fut.result():
                            removed.append(name)
                    except Exception:
                        pass
        self.started_containers.clear()
        self.active_endpoints.clear()
        self.active_parsers.clear()

        if self._temp_dir is not None:
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
            except Exception:
                pass
            self._temp_dir = None

        return {"cleaned_up": True, "removed_parsers": sorted(removed)}

    def __enter__(self) -> "DockerParserMatrix":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


def _extract_response_body(raw_response: bytes) -> bytes:
    if b"\r\n\r\n" in raw_response:
        return raw_response.split(b"\r\n\r\n", 1)[1]
    if b"\n\n" in raw_response:
        return raw_response.split(b"\n\n", 1)[1]
    return b""


def _extract_parsed_semantics(resp: TargetResponse) -> Dict[str, str]:
    """
    Extracts normalized parser-echoed request interpretation metadata (headers or JSON body)
    when loopback implementations report how they parsed a request, enabling signature-free
    semantic divergence detection even when two implementations both return HTTP 200.
    """
    semantics: Dict[str, str] = {}
    header_map = {
        "x-parsed-method": "parsed_method",
        "x-parsed-path": "parsed_path",
        "x-parsed-cl": "parsed_content_length",
        "x-parsed-content-length": "parsed_content_length",
        "x-parsed-te": "parsed_transfer_encoding",
        "x-parsed-transfer-encoding": "parsed_transfer_encoding",
        "x-parsed-body-len": "parsed_body_len",
        "x-parsed-header-count": "parsed_header_count",
    }
    for hdr_k, sem_k in header_map.items():
        if hdr_k in resp.headers and str(resp.headers[hdr_k]).strip() != "":
            semantics[sem_k] = str(resp.headers[hdr_k]).strip()

    body = _extract_response_body(resp.raw_response).strip()
    if body.startswith(b"{") and body.endswith(b"}") and len(body) <= 65536:
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
            if isinstance(parsed, dict):
                for sem_k in (
                    "parsed_method",
                    "parsed_path",
                    "parsed_content_length",
                    "parsed_transfer_encoding",
                    "parsed_body_len",
                    "parsed_header_count",
                ):
                    if sem_k in parsed and parsed[sem_k] is not None and str(parsed[sem_k]).strip() != "":
                        semantics.setdefault(sem_k, str(parsed[sem_k]).strip())
        except (ValueError, TypeError):
            pass
    return semantics


class MultiImplementationDifferentialOracle:
    """
    Executes differential probes across multiple server implementations (loopback
    HTTP endpoints, real Docker parser matrix containers, or the 4 independent
    algorithmic reference parsers) to detect parser divergence without requiring
    pre-written attack signatures or a golden reference model.
    """

    def __init__(
        self,
        targets: Optional[List[TargetEndpoint]] = None,
        *,
        docker_matrix: Optional[DockerParserMatrix] = None,
        max_workers: int = 8,
        compliance_ctx: Optional[Any] = None,
    ):
        self.targets = targets or [
            TargetEndpoint(name="AgentOctopus", host="127.0.0.1", port=5006),
            TargetEndpoint(name="TestLabServer", host="127.0.0.1", port=8888),
        ]
        self.docker_matrix: Optional[DockerParserMatrix] = docker_matrix
        self.max_workers: int = max(1, min(int(max_workers), 16))
        self.compliance_ctx: Optional[Any] = compliance_ctx

    def add_target(self, target: TargetEndpoint) -> None:
        self.targets.append(target)

    def dispatch_single_target(self, target: TargetEndpoint, raw_probe: bytes) -> TargetResponse:
        """
        Sends raw bytes to a single target and records response telemetry.
        When `compliance_ctx` (or process-wide `RequestHygieneConfig`) is configured,
        enforces fail-closed RoE scope allowlists, fractional RPS rate throttling,
        and non-destructive custom testing header / `User-Agent` injection.
        """
        from engine.execution_policy import ExecutionPolicy, StructuredIntentProposal, ScannerTask, ActionType
        from engine.request_hygiene import resolve_hygiene

        wire_probe = raw_probe
        if self.compliance_ctx is not None:
            ok_auth, auth_reason = self.compliance_ctx.authorize_live_host(target.host, allow_loopback=True)
            if not ok_auth:
                return TargetResponse(
                    target_name=target.name,
                    status_code=0,
                    headers={},
                    raw_response=b"",
                    latency=0.0,
                    socket_state=f"BLOCKED_BY_ROE:{auth_reason}",
                )
            limiter = getattr(self.compliance_ctx, "rate_limiter", None)
            if limiter is not None:
                limiter.acquire()
            hygiene = getattr(self.compliance_ctx, "hygiene", None)
            if hygiene is not None:
                wire_probe = hygiene.inject_raw_http1(raw_probe)
        else:
            active_hygiene, active_limiter = resolve_hygiene()
            if active_limiter is not None:
                active_limiter.acquire()
            if active_hygiene is not None and active_hygiene.is_active:
                wire_probe = active_hygiene.inject_raw_http1(raw_probe)

        proposal = StructuredIntentProposal(
            task=ScannerTask.DIFFERENTIAL_ORACLE,
            action_type=ActionType.NETWORK_SOCKET,
            target_host=target.host,
            target_port=target.port,
            raw_payload=wire_probe,
            rationale="Differential oracle cross-implementation discrepancy testing",
        )
        ExecutionPolicy.get_instance().validate_intent(proposal)
        start_time = time.time()
        sock = None
        try:
            sock = socket.create_connection((target.host, target.port), timeout=target.timeout)
            sock.sendall(wire_probe)

            framed = HTTPFramingReader.read_response(sock, timeout=target.timeout)
            response_data = framed.raw_response
            latency = time.time() - start_time
            if not response_data:
                return TargetResponse(
                    target_name=target.name,
                    status_code=0,
                    headers={},
                    raw_response=b"",
                    latency=latency,
                    socket_state="CONNECTION_CLOSED",
                )

            status_code = framed.status_code
            headers = framed.headers
            return TargetResponse(
                target_name=target.name,
                status_code=status_code,
                headers=headers,
                raw_response=response_data,
                latency=latency,
                socket_state="OK",
            )

        except socket.timeout:
            return TargetResponse(
                target_name=target.name,
                status_code=408,
                headers={},
                raw_response=b"",
                latency=time.time() - start_time,
                socket_state="TIMEOUT",
            )
        except ConnectionRefusedError:
            return TargetResponse(
                target_name=target.name,
                status_code=0,
                headers={},
                raw_response=b"",
                latency=time.time() - start_time,
                socket_state="CONNECTION_REFUSED",
            )
        except Exception as e:
            return TargetResponse(
                target_name=target.name,
                status_code=500,
                headers={},
                raw_response=str(e).encode("utf-8", errors="replace"),
                latency=time.time() - start_time,
                socket_state="ERROR",
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _dispatch_targets_concurrent(
        self, endpoints: Sequence[TargetEndpoint], raw_probe: bytes
    ) -> Dict[str, TargetResponse]:
        """Dispatches a probe concurrently across multiple targets while preserving endpoint order."""
        endpoint_list = list(endpoints)
        if not endpoint_list:
            return {}
        if len(endpoint_list) == 1:
            t = endpoint_list[0]
            return {t.name: self.dispatch_single_target(t, raw_probe)}

        workers = max(1, min(len(endpoint_list), self.max_workers))
        unordered: Dict[str, TargetResponse] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            fut_map = {pool.submit(self.dispatch_single_target, t, raw_probe): t.name for t in endpoint_list}
            for fut in as_completed(fut_map):
                name = fut_map[fut]
                unordered[name] = fut.result()

        return {t.name: unordered[t.name] for t in endpoint_list if t.name in unordered}

    def analyze_responses_for_divergence(
        self,
        responses: Dict[str, TargetResponse],
        raw_probe: bytes,
        *,
        rule_id: Optional[str] = None,
        backend: str = "loopback_http_endpoints",
        unavailable_parsers: Optional[List[str]] = None,
        unavailable_reasons: Optional[Dict[str, str]] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> DifferentialResult:
        """
        Signature-free cross-implementation divergence evaluator.
        Surfaces disagreements across status codes, acceptance boundaries (2xx/3xx vs 4xx/5xx),
        socket connection states, and echoed parsed framing semantics without pre-written rules.
        """
        active = {k: v for k, v in responses.items() if v.socket_state != "CONNECTION_REFUSED"}
        unavail = list(unavailable_parsers or [])
        unavail_reasons = dict(unavailable_reasons or {})
        for name, resp in responses.items():
            if resp.socket_state == "CONNECTION_REFUSED" and name not in unavail:
                unavail.append(name)
                unavail_reasons.setdefault(name, "connection_refused")

        vector: Dict[str, Dict[str, Any]] = {}
        semantics_by_parser: Dict[str, Dict[str, str]] = {}
        for name, resp in active.items():
            body = _extract_response_body(resp.raw_response)
            sem = _extract_parsed_semantics(resp)
            semantics_by_parser[name] = sem
            vector[name] = {
                "status_code": resp.status_code,
                "socket_state": resp.socket_state,
                "accepted": bool(200 <= resp.status_code < 400 and resp.socket_state == "OK"),
                "content_length": resp.headers.get("content-length"),
                "transfer_encoding": resp.headers.get("transfer-encoding"),
                "connection": resp.headers.get("connection"),
                "header_count": len(resp.headers),
                "bytes_len": len(resp.raw_response),
                "body_sha256": hashlib.sha256(body).hexdigest()[:16],
                "latency_ms": round(resp.latency * 1000.0, 2),
                "parsed_semantics": sem,
            }

        probe_preview = raw_probe[:160].decode("latin-1", errors="replace")
        if len(active) < 2:
            return DifferentialResult(
                status="skipped_insufficient_parsers",
                parser_matrix_backend=backend,
                is_divergent=False,
                divergence_vector=vector,
                divergence_dimensions=[],
                active_parsers=list(active.keys()),
                unavailable_parsers=unavail,
                unavailable_reasons=unavail_reasons,
                anomaly=None,
                raw_probe_preview=probe_preview,
                rule_id=rule_id,
                provenance=dict(provenance or {}),
            )

        dimensions: List[str] = []
        status_codes = {r.status_code for r in active.values() if r.status_code != 0}
        socket_states = {r.socket_state for r in active.values()}
        accepted_flags = {v["accepted"] for v in vector.values()}

        if len(status_codes) > 1:
            dimensions.append("status_code_disagreement")
        if len(accepted_flags) > 1:
            dimensions.append("acceptance_boundary_disagreement")
        if len(socket_states) > 1:
            dimensions.append("socket_state_disagreement")

        # Compare parsed framing semantics when >=2 parsers report a shared semantic attribute
        all_sem_keys: Set[str] = set()
        for sem in semantics_by_parser.values():
            all_sem_keys.update(sem.keys())
        for sem_key in sorted(all_sem_keys):
            reported_vals = {
                sem[sem_key] for sem in semantics_by_parser.values() if sem_key in sem
            }
            reporting_count = sum(1 for sem in semantics_by_parser.values() if sem_key in sem)
            if reporting_count >= 2 and len(reported_vals) > 1:
                dimensions.append(f"semantic_disagreement:{sem_key}")

        is_divergent = bool(dimensions)
        anomaly: Optional[ImplementationAnomaly] = None
        if is_divergent:
            primary_name = next(iter(active.keys()))
            primary_resp = active[primary_name]
            status_summary = ", ".join(f"{k}={v.status_code}/{v.socket_state}" for k, v in active.items())
            anomaly = ImplementationAnomaly(
                anomaly_id=f"ANOM-DIFF-{int(time.time() * 1000)}",
                target_engine=f"{backend}({','.join(active.keys())})",
                category=AnomalyCategory.PARSER_DIVERGENCE,
                observed_behavior=(
                    f"Cross-implementation divergence across [{status_summary}] "
                    f"on dimensions: {', '.join(dimensions)}"
                ),
                expected_behavior="Consistently identical protocol framing and validation across implementations.",
                raw_probe=raw_probe,
                raw_response=primary_resp.raw_response,
                triggering_rule_id=rule_id,
                divergence_matrix=vector,
            )

        return DifferentialResult(
            status="divergent" if is_divergent else "consistent",
            parser_matrix_backend=backend,
            is_divergent=is_divergent,
            divergence_vector=vector,
            divergence_dimensions=dimensions,
            active_parsers=list(active.keys()),
            unavailable_parsers=unavail,
            unavailable_reasons=unavail_reasons,
            anomaly=anomaly,
            raw_probe_preview=probe_preview,
            rule_id=rule_id,
            provenance=dict(provenance or {}),
        )

    def evaluate_endpoints_differential(
        self,
        raw_probe: bytes,
        *,
        endpoints: Optional[Sequence[TargetEndpoint]] = None,
        rule_id: Optional[str] = None,
        backend: str = "loopback_http_endpoints",
        unavailable_parsers: Optional[List[str]] = None,
        unavailable_reasons: Optional[Dict[str, str]] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> DifferentialResult:
        """
        Sends `raw_probe` concurrently across `endpoints` (or `self.targets`) and
        returns a structured signature-free `DifferentialResult`.
        """
        target_list = list(endpoints) if endpoints is not None else list(self.targets)
        responses = self._dispatch_targets_concurrent(target_list, raw_probe)
        return self.analyze_responses_for_divergence(
            responses,
            raw_probe,
            rule_id=rule_id,
            backend=backend,
            unavailable_parsers=unavailable_parsers,
            unavailable_reasons=unavailable_reasons,
            provenance=provenance,
        )

    def run_docker_parser_matrix(
        self,
        probes: Optional[Sequence[Union[bytes, Tuple[str, bytes]]]] = None,
        *,
        parsers: Optional[Sequence[str]] = None,
        rule_ids: Optional[Sequence[Optional[str]]] = None,
        fallback_to_4parsers: bool = False,
        docker_matrix: Optional[DockerParserMatrix] = None,
    ) -> Dict[str, Any]:
        """
        Runs a full local Docker differential parser matrix lifecycle:
        starts ephemeral 127.0.0.1-bound parser containers, sends probes across all
        running real implementations, collects signature-free `DifferentialResult`s,
        and guarantees container teardown in `finally`.

        When Docker daemon or required images are unavailable, skips cleanly with
        `status="skipped_docker_unavailable"` and explicit provenance rather than crashing.
        """
        t0 = time.monotonic()
        normalized_probes: List[Tuple[Optional[str], bytes]] = []
        raw_probe_list = list(probes) if probes is not None else list(DEFAULT_DIFFERENTIAL_PROBES)
        for idx, item in enumerate(raw_probe_list):
            if isinstance(item, tuple) and len(item) == 2:
                normalized_probes.append((str(item[0]) if item[0] is not None else None, bytes(item[1])))
            else:
                rid = rule_ids[idx] if (rule_ids is not None and idx < len(rule_ids)) else None
                normalized_probes.append((rid, bytes(item)))

        matrix_mgr = docker_matrix or self.docker_matrix or DockerParserMatrix(parsers=parsers)
        results: List[DifferentialResult] = []
        start_info: Dict[str, Any] = {}
        cleanup_info: Dict[str, Any] = {"cleaned_up": False, "removed_parsers": []}

        try:
            start_info = matrix_mgr.start()
            if start_info.get("status") != "ready" or len(matrix_mgr.active_endpoints) < 2:
                fallback_results: List[Dict[str, Any]] = []
                if fallback_to_4parsers:
                    for rid, probe_bytes in normalized_probes:
                        has_div, anom, mat = self.evaluate_matrix_4parsers(probe_bytes, rule_id=rid)
                        fallback_results.append(
                            DifferentialResult(
                                status="divergent" if has_div else "consistent",
                                parser_matrix_backend="reference_4parser_fallback",
                                is_divergent=has_div,
                                divergence_vector=mat,
                                divergence_dimensions=["reference_parser_disagreement"] if has_div else [],
                                active_parsers=list(mat.keys()),
                                unavailable_parsers=list(matrix_mgr.unavailable_parsers),
                                unavailable_reasons=dict(matrix_mgr.unavailable_reasons),
                                anomaly=anom,
                                raw_probe_preview=probe_bytes[:160].decode("latin-1", errors="replace"),
                                rule_id=rid,
                                provenance={
                                    "docker_available": matrix_mgr.docker_available,
                                    "docker_error": matrix_mgr.docker_error,
                                    "fallback_reason": start_info.get("reason") or matrix_mgr.docker_error,
                                },
                            ).to_dict()
                        )

                divergent_fb = [r for r in fallback_results if r["is_divergent"]]
                return {
                    "status": "skipped_docker_unavailable",
                    "parser_matrix_backend": (
                        "reference_4parser_fallback" if fallback_to_4parsers else "docker_unavailable"
                    ),
                    "docker_available": matrix_mgr.docker_available,
                    "docker_version": matrix_mgr.docker_version,
                    "docker_error": matrix_mgr.docker_error,
                    "active_parsers": list(matrix_mgr.active_parsers),
                    "unavailable_parsers": list(matrix_mgr.unavailable_parsers),
                    "unavailable_reasons": dict(matrix_mgr.unavailable_reasons),
                    "probes_evaluated": len(fallback_results),
                    "divergences_found": len(divergent_fb),
                    "total_findings": len(divergent_fb),
                    "results": fallback_results,
                    "provenance": {
                        "requested_parsers": list(matrix_mgr.requested_parsers),
                        "start_status": start_info.get("status", "skipped_docker_unavailable"),
                        "reason": start_info.get("reason") or matrix_mgr.docker_error or "insufficient_parsers",
                        "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                    },
                }

            base_prov = {
                "docker_available": True,
                "docker_version": matrix_mgr.docker_version,
                "requested_parsers": list(matrix_mgr.requested_parsers),
                "started_containers": dict(matrix_mgr.started_containers),
            }
            for rid, probe_bytes in normalized_probes:
                diff_res = self.evaluate_endpoints_differential(
                    probe_bytes,
                    endpoints=matrix_mgr.active_endpoints,
                    rule_id=rid,
                    backend="docker_parser_matrix",
                    unavailable_parsers=list(matrix_mgr.unavailable_parsers),
                    unavailable_reasons=dict(matrix_mgr.unavailable_reasons),
                    provenance=base_prov,
                )
                results.append(diff_res)

            divergences = [r for r in results if r.is_divergent]
            return {
                "status": "completed",
                "parser_matrix_backend": "docker_parser_matrix",
                "docker_available": True,
                "docker_version": matrix_mgr.docker_version,
                "docker_error": "",
                "active_parsers": list(matrix_mgr.active_parsers),
                "unavailable_parsers": list(matrix_mgr.unavailable_parsers),
                "unavailable_reasons": dict(matrix_mgr.unavailable_reasons),
                "probes_evaluated": len(results),
                "divergences_found": len(divergences),
                "total_findings": len(divergences),
                "results": [r.to_dict() for r in results],
                "anomalies": [r.anomaly.to_dict() for r in divergences if r.anomaly is not None],
                "provenance": {
                    **base_prov,
                    "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
                },
            }
        finally:
            cleanup_info = matrix_mgr.stop()
            if results:
                for r in results:
                    r.provenance["cleanup"] = cleanup_info

    def evaluate_matrix_4parsers(
        self, raw_probe: bytes, rule_id: Optional[str] = None
    ) -> Tuple[bool, Optional[ImplementationAnomaly], Dict[str, Any]]:
        """
        Executes probe across the 4 independent algorithmic reference parsers:
        1. Strict RFC 7230 Parser
        2. Permissive Legacy Parser
        3. CDN / Reverse Proxy Parser
        4. Async Event-Driven Microservice Parser
        Guarantees deterministic, reproducible differential results offline without external network dependencies.
        """
        parsers = [
            StrictRFC7230Parser(),
            PermissiveLegacyParser(),
            CDNProxyParser(),
            AsyncMicroserviceParser(),
        ]

        responses: Dict[str, TargetResponse] = {}
        for p in parsers:
            try:
                responses[p.name] = p.parse(raw_probe)
            except Exception as e:
                responses[p.name] = TargetResponse(p.name, 500, {}, str(e).encode("utf-8", errors="replace"), 0.0, "ERROR")

        matrix = {
            name: {
                "status": resp.status_code,
                "socket_state": resp.socket_state,
                "latency": round(resp.latency, 4),
                "bytes_len": len(resp.raw_response),
            }
            for name, resp in responses.items()
        }

        status_codes = {resp.status_code for resp in responses.values() if resp.status_code != 0}
        socket_states = {resp.socket_state for resp in responses.values()}

        is_divergent = len(status_codes) > 1 or len(socket_states) > 1

        if is_divergent:
            primary_name = list(responses.keys())[0]
            primary_resp = responses[primary_name]

            anomaly = ImplementationAnomaly(
                anomaly_id=f"ANOM-DIFF4-{int(time.time() * 1000)}",
                target_engine=f"4ParserDifferentialMatrix({','.join(responses.keys())})",
                category=AnomalyCategory.PARSER_DIVERGENCE,
                observed_behavior=f"Divergence detected across 4 differential parsers: {status_codes}, states: {socket_states}",
                expected_behavior="Consistently identical specification handling across all implementations.",
                raw_probe=raw_probe,
                raw_response=primary_resp.raw_response,
                triggering_rule_id=rule_id,
                divergence_matrix=matrix,
            )
            return True, anomaly, matrix

        return False, None, matrix

    def evaluate_divergence(
        self, raw_probe: bytes, rule_id: Optional[str] = None
    ) -> Tuple[bool, Optional[ImplementationAnomaly], Dict[str, Any]]:
        """
        Sends the probe to all targets and determines if any two parsers diverge.
        If fewer than 2 network targets respond, automatically evaluates against the
        independent 4-parser differential matrix (Strict RFC 7230, Permissive Legacy, CDN Proxy, Async Microservice).
        """
        responses: Dict[str, TargetResponse] = self._dispatch_targets_concurrent(self.targets, raw_probe)

        # Filter out targets that were unreachable/refused
        active_responses = {k: v for k, v in responses.items() if v.socket_state != "CONNECTION_REFUSED"}

        matrix = {
            name: {
                "status": resp.status_code,
                "socket_state": resp.socket_state,
                "latency": round(resp.latency, 4),
                "bytes_len": len(resp.raw_response),
            }
            for name, resp in responses.items()
        }

        # If network targets are inactive, evaluate against the 4 independent reference parsers
        if len(active_responses) < 2:
            return self.evaluate_matrix_4parsers(raw_probe, rule_id=rule_id)

        diff_result = self.analyze_responses_for_divergence(
            active_responses,
            raw_probe,
            rule_id=rule_id,
            backend="DifferentialMatrix",
        )
        if diff_result.is_divergent and diff_result.anomaly is not None:
            diff_result.anomaly.divergence_matrix = matrix
            return True, diff_result.anomaly, matrix

        return False, None, matrix

    def _parse_http_response(self, data: bytes) -> Tuple[int, Dict[str, str]]:
        """Extracts status code and headers from raw bytes."""
        try:
            head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
            lines = head.split("\r\n")
            if not lines:
                return 0, {}

            # Status line: HTTP/1.1 200 OK
            status_parts = lines[0].split(" ", 2)
            status_code = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 200

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            return status_code, headers
        except Exception:
            return 200, {}


# ==============================================================================
# 4 INDEPENDENT ALGORITHMIC REFERENCE PARSERS
# (Required by Protocol Research Reproducibility Invariant)
# ==============================================================================

class StrictRFC7230Parser:
    """Parser 1: Strict RFC 7230 / RFC 9112 Reference Parser."""
    name = "StrictRFC7230"

    def parse(self, raw_probe: bytes) -> TargetResponse:
        t0 = time.time()
        # Enforce CRLF: Bare LF without preceding CR is forbidden in start-line and headers
        if b"\r\n\r\n" not in raw_probe:
            if b"\n\n" in raw_probe or b"\r\r" in raw_probe:
                # Delimiter line error
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nBare delimiter error", time.time() - t0, "OK")
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nIncomplete request headers", time.time() - t0, "OK")

        head, body = raw_probe.split(b"\r\n\r\n", 1)
        # Check for bare LF or bare CR inside head (RFC 7230 §3.2.4 / RFC 9112 §2.2)
        head_no_crlf = head.replace(b"\r\n", b"")
        if b"\r" in head_no_crlf or b"\n" in head_no_crlf:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nBare delimiter error", time.time() - t0, "OK")

        lines = head.split(b"\r\n")
        req_line = lines[0]
        parts = req_line.split(b" ")
        if len(parts) != 3:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nMalformed Request-Line", time.time() - t0, "OK")

        # Obs-fold check: RFC 7230 Section 3.2.4 mandates rejecting obs-fold in incoming requests
        headers: Dict[str, str] = {}
        cl_values = []
        has_te = False

        for line in lines[1:]:
            if line.startswith((b" ", b"\t")):
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nObs-fold rejected by RFC 7230", time.time() - t0, "OK")
            if b":" not in line:
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid header syntax", time.time() - t0, "OK")

            k_raw, v_raw = line.split(b":", 1)
            # Whitespace before colon forbidden (RFC 7230 Section 3.2.4)
            if k_raw.endswith((b" ", b"\t")):
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nWhitespace before colon", time.time() - t0, "OK")

            k = k_raw.decode("latin-1", errors="replace").strip().lower()
            v = v_raw.decode("latin-1", errors="replace").strip()
            if k == "content-length":
                cl_values.append(v)
            if k == "transfer-encoding":
                has_te = True
            headers[k] = v

        # Multiple Content-Length with conflicting values -> 400 Bad Request
        if len(set(cl_values)) > 1:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nConflicting Content-Length headers", time.time() - t0, "OK")

        # TE and CL both present: RFC 7230 mandates rejecting or prioritizing chunked
        if has_te and cl_values:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nTE and CL mutually exclusive", time.time() - t0, "OK")

        return TargetResponse(self.name, 200, headers, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", time.time() - t0, "OK")


class PermissiveLegacyParser:
    """Parser 2: Permissive Legacy Server Parser (historic pre-RFC 7230 leniency)."""
    name = "PermissiveLegacy"

    def parse(self, raw_probe: bytes) -> TargetResponse:
        t0 = time.time()
        # Tolerates bare LF or bare CR
        normalized = raw_probe.replace(b"\r\r\n", b"\r\n").replace(b"\n\r", b"\r\n")
        delimiter = b"\r\n\r\n" if b"\r\n\r\n" in normalized else (b"\n\n" if b"\n\n" in normalized else b"\r\r")
        if delimiter not in normalized:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.0 400 Bad Request\r\n\r\n", time.time() - t0, "OK")

        head, _body = normalized.split(delimiter, 1)
        # Folds obs-fold (replaces \r\n followed by space/tab with single space)
        lines = [line for line in head.split(b"\r\n") if line]
        if not lines:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.0 400 Bad Request\r\n\r\n", time.time() - t0, "OK")

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                # Tolerates whitespace before colon and picks first CL without error
                key_str = k.decode("latin-1", errors="replace").strip().lower()
                val_str = v.decode("latin-1", errors="replace").strip()
                if key_str not in headers:
                    headers[key_str] = val_str

        return TargetResponse(self.name, 200, headers, b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", time.time() - t0, "OK")


class CDNProxyParser:
    """Parser 3: CDN / Reverse Proxy Gateway Parser (Nginx / Cloudflare style)."""
    name = "CDNProxy"

    def parse(self, raw_probe: bytes) -> TargetResponse:
        t0 = time.time()
        # Normalizes paths: unencodes %20, %0d%0a, stripping or unmasking RHI
        if b"\r\n\r\n" not in raw_probe:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\nServer: cdn\r\n\r\n", time.time() - t0, "OK")

        head, _body = raw_probe.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        req_line = lines[0].decode("latin-1", errors="replace")

        # Simulate path unencoding: if %0d%0a or %20 occurs in path
        if "%0d%0a" in req_line.lower() or "%250d%250a" in req_line.lower():
            # RHI path injection triggered! If Expect: asdf is present in unencoded string, emit 417
            if "expect: asdf" in req_line.lower() or "expect:%20asdf" in req_line.lower():
                return TargetResponse(self.name, 417, {}, b"HTTP/1.1 417 Expectation Failed\r\nServer: cdn\r\n\r\n", time.time() - t0, "OK")
            if "transfer-encoding" in req_line.lower():
                return TargetResponse(self.name, 501, {}, b"HTTP/1.1 501 Not Implemented\r\nServer: cdn\r\n\r\n", time.time() - t0, "OK")
            if "13.37" in req_line:
                return TargetResponse(self.name, 505, {}, b"HTTP/1.1 505 HTTP Version Not Supported\r\nServer: cdn\r\n\r\n", time.time() - t0, "OK")

        # Check for Expect: 100-continue in headers
        lower_head = head.lower()
        if b"expect: 100-continue" in lower_head:
            # Emits interim 100 Continue
            return TargetResponse(self.name, 100, {}, b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", time.time() - t0, "OK")

        # Prioritize Transfer-Encoding: chunked over Content-Length
        if b"transfer-encoding: chunked" in lower_head:
            return TargetResponse(self.name, 200, {"transfer-encoding": "chunked"}, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", time.time() - t0, "OK")

        return TargetResponse(self.name, 200, {}, b"HTTP/1.1 200 OK\r\nServer: cdn\r\nContent-Length: 0\r\n\r\n", time.time() - t0, "OK")


class AsyncMicroserviceParser:
    """Parser 4: Event-driven Async Microservice Parser (Node.js / Netty / Tornado style)."""
    name = "AsyncMicroservice"

    def parse(self, raw_probe: bytes) -> TargetResponse:
        t0 = time.time()
        if b"\r\n\r\n" not in raw_probe:
            return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\n", time.time() - t0, "OK")

        head, body = raw_probe.split(b"\r\n\r\n", 1)
        lower_head = head.lower()

        # Dangling byte detection: If Content-Length declared is larger than received body, async parser pauses/hangs
        cl_match = re.search(rb"(?:^|\r\n)content-length:\s*(\d+)", lower_head)
        if cl_match:
            try:
                declared_len = int(cl_match.group(1))
            except (ValueError, OverflowError):
                return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid Content-Length", time.time() - t0, "OK")
            if declared_len > len(body):
                # Dangling byte: Pauses waiting for remaining body bytes
                return TargetResponse(self.name, 408, {}, b"", time.time() - t0 + 0.1, "TIMEOUT")

        # Chunked parsing validation
        if b"transfer-encoding:" in lower_head and b"chunked" in lower_head:
            # Check if chunk size is valid hex
            chunk_lines = body.split(b"\r\n")
            if chunk_lines:
                first_chunk_size = chunk_lines[0].split(b";")[0].strip()
                try:
                    int(first_chunk_size, 16)
                except ValueError:
                    return TargetResponse(self.name, 400, {}, b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid chunk size hex", time.time() - t0, "OK")

        return TargetResponse(self.name, 200, {}, b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n", time.time() - t0, "OK")
