"""
Comprehensive test suite for AIxCC Upgrades #1 and #5a:
1. Real Differential Docker Parser Matrix (`engine/differential_oracle.py`)
2. Sandboxed Repository Invariant Runner (`engine/sandbox_invariant_runner.py`)
3. Containerized Non-Destructive POE == 3 Verifier (`engine/poe_container_verifier.py`)

Covers:
- Hardened Docker command construction (`--network=none`, `--cap-drop=ALL`, `shell=False`,
  read-only mounts, loopback-only port publishing, rejection of `--network=host`/injection).
- Signature-free cross-parser divergence detection across 2+ live local 127.0.0.1 HTTP servers
  (both status-code/acceptance divergence and same-status parsed framing semantic divergence).
- Real invariant harness execution against vulnerable vs compliant multi-language repos and
  Cairn `FACT` persistence via `Database.add_fact(...)`.
- POE == 3 promotion for reproduced findings vs false-positive downgrade & filtering.
- Clean `status="skipped_docker_unavailable"` provenance when Docker daemon or images are absent.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from database import Database
from engine.differential_oracle import (
    DEFAULT_DIFFERENTIAL_PROBES,
    DEFAULT_PARSER_MATRIX_SPECS,
    DifferentialResult,
    DockerParserMatrix,
    MultiImplementationDifferentialOracle,
    TargetEndpoint,
    validate_parser_matrix_docker_command,
)
from engine.dual_graph_engine import POELevel
from engine.execution_policy import ExecutionPolicy
from engine.poe_container_verifier import (
    ContainerPOEVerifier,
    POE_RESULT_MARKER,
    generate_verification_test,
    validate_poe_docker_command,
)
from engine.sandbox_invariant_runner import (
    SandboxInvariantRunner,
    build_invariant_harness_script,
    build_node_invariant_harness_script,
    detect_repo_languages,
    parse_invariant_harness_output,
    validate_sandbox_docker_command,
)
from engine.taxonomy import AnomalyCategory


# ==============================================================================
# HELPERS: REAL LOOPBACK TCP/HTTP PARSER SERVERS FOR DIFFERENTIAL TESTING
# ==============================================================================


class _LoopbackRawHTTPServer:
    """Minimal real TCP HTTP/1.1 server bound strictly to 127.0.0.1 on an ephemeral port."""

    def __init__(self, responder: Callable[[bytes], bytes]):
        self._responder = responder
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port: int = int(self._sock.getsockname()[1])
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "_LoopbackRawHTTPServer":
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(1.5)
                chunks: List[bytes] = []
                while True:
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    chunks.append(data)
                    joined = b"".join(chunks)
                    if b"\r\n\r\n" in joined or b"\n\n" in joined:
                        break
                raw_req = b"".join(chunks)
                resp = self._responder(raw_req)
                if resp:
                    conn.sendall(resp)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def __enter__(self) -> "_LoopbackRawHTTPServer":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def _strict_http_responder(raw_req: bytes) -> bytes:
    """Strict RFC 9112 responder: rejects pre-colon space, conflicting CL, and CL+TE."""
    if b"\r\n\r\n" not in raw_req:
        return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    head, _body = raw_req.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    cl_vals = []
    has_te = False
    for line in lines[1:]:
        if b":" not in line:
            return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        k_raw, v_raw = line.split(b":", 1)
        if k_raw.endswith((b" ", b"\t")):
            return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        k = k_raw.strip().lower()
        v = v_raw.strip().decode("latin-1", errors="replace")
        if k == b"content-length":
            cl_vals.append(v)
        elif k == b"transfer-encoding":
            has_te = True
    if len(set(cl_vals)) > 1 or (has_te and cl_vals):
        return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    cl_hdr = cl_vals[0] if cl_vals else "0"
    body = b'{"ok":true}'
    return (
        f"HTTP/1.1 200 OK\r\nX-Parser-Impl: strict\r\nX-Parsed-CL: {cl_hdr}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("latin-1") + body


def _permissive_http_responder(raw_req: bytes) -> bytes:
    """Permissive responder: accepts pre-colon space and takes first Content-Length."""
    cl_val = "0"
    if b"\r\n\r\n" in raw_req:
        head, _ = raw_req.split(b"\r\n\r\n", 1)
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                if k.strip().lower() == b"content-length" and cl_val == "0":
                    cl_val = v.strip().decode("latin-1", errors="replace")
    body = b'{"ok":true}'
    return (
        f"HTTP/1.1 200 OK\r\nX-Parser-Impl: permissive\r\nX-Parsed-CL: {cl_val}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("latin-1") + body


def _last_cl_http_responder(raw_req: bytes) -> bytes:
    """Permissive responder variant: takes LAST Content-Length (creates 200 vs 200 semantic divergence)."""
    cl_val = "0"
    if b"\r\n\r\n" in raw_req:
        head, _ = raw_req.split(b"\r\n\r\n", 1)
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                if k.strip().lower() == b"content-length":
                    cl_val = v.strip().decode("latin-1", errors="replace")
    body = b'{"ok":true}'
    return (
        f"HTTP/1.1 200 OK\r\nX-Parser-Impl: last_cl\r\nX-Parsed-CL: {cl_val}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("latin-1") + body


# ==============================================================================
# 1. DOCKER PARSER MATRIX SPECS & HARDENED COMMAND CONSTRUCTION
# ==============================================================================


def test_default_parser_matrix_specs_and_aliases():
    expected = {"nginx", "envoy", "haproxy", "node_undici", "go_net_http", "rust_hyper"}
    assert set(DEFAULT_PARSER_MATRIX_SPECS.keys()) == expected
    resolved = DockerParserMatrix.resolve_parser_names(["nginx", "undici", "go", "hyper", "envoy", "haproxy"])
    assert set(resolved) == expected
    assert len(DEFAULT_DIFFERENTIAL_PROBES) >= 4


def test_docker_parser_matrix_command_construction_hardened():
    matrix = DockerParserMatrix(docker_bin="docker")
    # Use a safe workspace-relative mount path (also validates against ExecutionPolicy)
    repo_root = Path(__file__).resolve().parent.parent
    fake_cfg = repo_root / "runs" / "test_cfg_placeholder.conf"

    for name, spec in DEFAULT_PARSER_MATRIX_SPECS.items():
        cmd = matrix.build_run_command(
            spec,
            container_name=f"rfchunt-diff-{name.replace('_', '-')}-abcd",
            host_port=18080,
            config_host_path=fake_cfg,
        )
        assert isinstance(cmd, list)
        assert cmd[0] == "docker"
        assert cmd[1] == "run"
        assert "--rm" in cmd
        assert "--cap-drop=ALL" in cmd
        assert "--read-only" in cmd
        assert "no-new-privileges:true" in cmd
        assert "--memory" in cmd
        assert "--cpus" in cmd
        assert "--pids-limit" in cmd
        assert "127.0.0.1:18080:8080" in cmd
        assert "--network=host" not in cmd
        assert "--privileged" not in cmd
        assert "--cap-add" not in cmd
        assert "-c" not in cmd

        ok, reason = validate_parser_matrix_docker_command(cmd)
        assert ok is True, f"{name} command rejected: {reason}"

        # Also passes global ExecutionPolicy subprocess validator with shell=False
        ep_ok, ep_reason = ExecutionPolicy.get_instance().validate_subprocess_command(cmd, shell=False)
        assert ep_ok is True, f"{name} rejected by ExecutionPolicy: {ep_reason}"


@pytest.mark.parametrize(
    "bad_cmd,expected_substr",
    [
        ("docker run --rm nginx", "list/sequence"),
        (["docker", "run", "--rm", "--cap-drop=ALL", "--network=host", "-p", "127.0.0.1:8080:80", "nginx"], "isolation-escape"),
        (["docker", "run", "--rm", "--cap-drop=ALL", "--privileged", "-p", "127.0.0.1:8080:80", "nginx"], "--privileged"),
        (["docker", "run", "--rm", "--cap-drop=ALL", "--cap-add=NET_ADMIN", "-p", "127.0.0.1:8080:80", "nginx"], "--cap-add"),
        (["docker", "run", "--rm", "--cap-drop=ALL", "-p", "0.0.0.0:8080:80", "nginx"], "127.0.0.1"),
        (["docker", "run", "--rm", "--cap-drop=ALL", "-p", "127.0.0.1:8080:80", "nginx;id"], "metacharacter"),
        (["docker", "run", "--rm", "--cap-drop=ALL", "-p", "127.0.0.1:8080:80", "-v", "/etc/passwd:/x:ro", "nginx"], "unsafe docker host mount"),
        (["docker", "run", "--rm", "--cap-drop=ALL", "-p", "127.0.0.1:8080:80", "nginx", "sh", "-c", "echo hi"], "forbidden"),
        (["docker", "run", "--cap-drop=ALL", "-p", "127.0.0.1:8080:80", "nginx"], "--rm"),
        (["docker", "run", "--rm", "-p", "127.0.0.1:8080:80", "nginx"], "--cap-drop=ALL"),
    ],
)
def test_parser_matrix_docker_validator_rejects_unsafe_commands(bad_cmd, expected_substr):
    ok, reason = validate_parser_matrix_docker_command(bad_cmd)
    assert ok is False
    assert expected_substr.lower() in reason.lower()


# ==============================================================================
# 2. LIVE LOOPBACK CROSS-PARSER DIVERGENCE DETECTION WITHOUT SIGNATURES
# ==============================================================================


def test_cross_parser_divergence_across_live_loopback_http_servers():
    """Verifies signature-free status/acceptance divergence across 2 live 127.0.0.1 servers."""
    with _LoopbackRawHTTPServer(_strict_http_responder) as srv_strict, _LoopbackRawHTTPServer(
        _permissive_http_responder
    ) as srv_perm:
        endpoints = [
            TargetEndpoint(name="strict_http", host="127.0.0.1", port=srv_strict.port, timeout=2.0),
            TargetEndpoint(name="permissive_http", host="127.0.0.1", port=srv_perm.port, timeout=2.0),
        ]
        oracle = MultiImplementationDifferentialOracle(targets=endpoints)

        # Clean RFC-conforming probe -> consistent across both parsers
        clean_probe = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        clean_res = oracle.evaluate_endpoints_differential(clean_probe)
        assert isinstance(clean_res, DifferentialResult)
        assert clean_res.status == "consistent"
        assert clean_res.is_divergent is False
        assert clean_res.divergence_dimensions == []
        assert clean_res.parser_matrix_backend == "loopback_http_endpoints"

        # Pre-colon whitespace probe -> strict returns 400, permissive returns 200 (no signature needed!)
        div_probe = b"GET / HTTP/1.1\r\nHost : 127.0.0.1\r\nConnection: close\r\n\r\n"
        div_res = oracle.evaluate_endpoints_differential(div_probe, rule_id="DIFF-PRE-COLON")
        assert div_res.status == "divergent"
        assert div_res.is_divergent is True
        assert "status_code_disagreement" in div_res.divergence_dimensions
        assert "acceptance_boundary_disagreement" in div_res.divergence_dimensions
        assert div_res.divergence_vector["strict_http"]["status_code"] == 400
        assert div_res.divergence_vector["permissive_http"]["status_code"] == 200
        assert div_res.anomaly is not None
        assert div_res.anomaly.category == AnomalyCategory.PARSER_DIVERGENCE

        # Legacy evaluate_divergence tuple contract also detects live divergence cleanly
        has_div, anom, mat = oracle.evaluate_divergence(div_probe)
        assert has_div is True
        assert anom is not None
        assert mat["strict_http"]["status"] == 400
        assert mat["permissive_http"]["status"] == 200


def test_cross_parser_semantic_divergence_when_both_return_200():
    """Verifies signature-free semantic framing divergence even when both servers return 200 OK."""
    with _LoopbackRawHTTPServer(_permissive_http_responder) as srv_first, _LoopbackRawHTTPServer(
        _last_cl_http_responder
    ) as srv_last:
        endpoints = [
            TargetEndpoint(name="first_cl_parser", host="127.0.0.1", port=srv_first.port, timeout=2.0),
            TargetEndpoint(name="last_cl_parser", host="127.0.0.1", port=srv_last.port, timeout=2.0),
        ]
        oracle = MultiImplementationDifferentialOracle(targets=endpoints)
        dup_cl_probe = (
            b"POST /submit HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Length: 5\r\nContent-Length: 12\r\nConnection: close\r\n\r\nhello"
        )
        res = oracle.evaluate_endpoints_differential(dup_cl_probe)
        assert res.is_divergent is True
        assert res.divergence_vector["first_cl_parser"]["status_code"] == 200
        assert res.divergence_vector["last_cl_parser"]["status_code"] == 200
        assert "semantic_disagreement:parsed_content_length" in res.divergence_dimensions


def test_run_docker_parser_matrix_lifecycle_and_guaranteed_teardown():
    """
    Verifies DockerParserMatrix orchestration: checks images, builds hardened shell=False
    127.0.0.1 commands, probes active endpoints, and tears down started containers in finally.
    """
    recorded_cmds: List[Tuple[List[str], bool]] = []
    removed_cids: List[str] = []

    with _LoopbackRawHTTPServer(_strict_http_responder) as srv_a, _LoopbackRawHTTPServer(
        _permissive_http_responder
    ) as srv_b:
        port_iter = iter([srv_a.port, srv_b.port])

        def fake_docker_runner(args, **kwargs):
            assert kwargs.get("shell") is False
            recorded_cmds.append((list(args), bool(kwargs.get("shell", False))))
            if args[1] == "info":
                return subprocess.CompletedProcess(args, 0, stdout="27.3.1\n", stderr="")
            if args[1] == "image" and args[2] == "inspect":
                img = args[-1]
                if "nginx" in img or "node:" in img:
                    return subprocess.CompletedProcess(args, 0, stdout="sha256:abc123\n", stderr="")
                return subprocess.CompletedProcess(args, 1, stdout="", stderr="No such image")
            if args[1] == "run":
                return subprocess.CompletedProcess(args, 0, stdout="cid-123456\n", stderr="")
            if args[1] == "rm":
                removed_cids.append(args[-1])
                return subprocess.CompletedProcess(args, 0, stdout=args[-1] + "\n", stderr="")
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="unexpected")

        mgr = DockerParserMatrix(
            parsers=["nginx", "node_undici", "envoy"],
            docker_bin="docker",
            subprocess_runner=fake_docker_runner,
            readiness_probe=lambda host, port, timeout: host == "127.0.0.1",
        )
        # Bind allocated ports to our live loopback test servers
        mgr.allocate_loopback_port = lambda: next(port_iter)  # type: ignore[method-assign]

        oracle = MultiImplementationDifferentialOracle(targets=[])
        report = oracle.run_docker_parser_matrix(
            probes=[("TEST-PRE-COLON", b"GET / HTTP/1.1\r\nHost : 127.0.0.1\r\nConnection: close\r\n\r\n")],
            docker_matrix=mgr,
        )

        assert report["status"] == "completed"
        assert report["parser_matrix_backend"] == "docker_parser_matrix"
        assert report["docker_available"] is True
        assert set(report["active_parsers"]) == {"nginx", "node_undici"}
        assert "envoy" in report["unavailable_parsers"]
        assert report["divergences_found"] == 1
        assert len(removed_cids) == 2
        assert all(cid.startswith("rfchunt-diff-") for cid in removed_cids)
        assert all(shell_flag is False for _, shell_flag in recorded_cmds)


def test_docker_parser_matrix_clean_skip_when_docker_unavailable():
    def offline_runner(args, **kwargs):
        assert kwargs.get("shell") is False
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="Cannot connect to the Docker daemon")

    mgr = DockerParserMatrix(
        parsers=["nginx", "envoy", "haproxy", "node_undici", "go_net_http", "rust_hyper"],
        docker_bin="docker",
        subprocess_runner=offline_runner,
    )
    oracle = MultiImplementationDifferentialOracle(targets=[])
    report = oracle.run_docker_parser_matrix(docker_matrix=mgr)

    assert report["status"] == "skipped_docker_unavailable"
    assert report["parser_matrix_backend"] == "docker_unavailable"
    assert report["docker_available"] is False
    assert set(report["unavailable_parsers"]) == {
        "nginx",
        "envoy",
        "haproxy",
        "node_undici",
        "go_net_http",
        "rust_hyper",
    }
    assert report["divergences_found"] == 0
    assert "docker" in report["provenance"]["reason"].lower()


# ==============================================================================
# 3. SANDBOXED REPO INVARIANT RUNNER & CAIRN FACT PERSISTENCE
# ==============================================================================


def test_sandbox_invariant_docker_command_construction_and_validation(tmp_path):
    repo_dir = tmp_path / "sample_repo"
    harness_dir = tmp_path / "harness"
    repo_dir.mkdir()
    harness_dir.mkdir()

    runner = SandboxInvariantRunner(docker_bin="docker", memory_limit="384m", cpus="0.5", pids_limit=64)
    cmd = runner.build_docker_command(repo_dir, harness_dir, runtime="python")

    assert cmd[0] == "docker"
    assert cmd[1] == "run"
    assert "--rm" in cmd
    assert "--network=none" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--read-only" in cmd
    assert "no-new-privileges:true" in cmd
    assert "--memory" in cmd and "384m" in cmd
    assert "--cpus" in cmd and "0.5" in cmd
    assert "--pids-limit" in cmd and "64" in cmd
    assert any(tok.endswith(":/workspace:ro") for tok in cmd)
    assert any(tok.endswith(":/harness:ro") for tok in cmd)
    assert "--network=host" not in cmd
    assert "-c" not in cmd

    ok, reason = validate_sandbox_docker_command(cmd)
    assert ok is True, reason

    # Validate Node runtime command too
    cmd_node = runner.build_docker_command(repo_dir, harness_dir, runtime="node")
    assert "node" in cmd_node and "/harness/run_invariants.mjs" in cmd_node
    ok_node, reason_node = validate_sandbox_docker_command(cmd_node)
    assert ok_node is True, reason_node

    # Validate unsafe commands are strictly rejected
    for bad in (
        ["docker", "run", "--rm", "--network=host", "--cap-drop=ALL", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "-v", f"{repo_dir}:/workspace:ro", "python:3.12-alpine", "python3", "/harness/run_invariants.py"],
        ["docker", "run", "--rm", "--network=none", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "-v", f"{repo_dir}:/workspace:ro", "python:3.12-alpine", "python3", "/harness/run_invariants.py"],
        ["docker", "run", "--rm", "--network=none", "--cap-drop=ALL", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "-v", f"{repo_dir}:/workspace:rw", "python:3.12-alpine", "python3", "/harness/run_invariants.py"],
        ["docker", "run", "--rm", "--network=none", "--cap-drop=ALL", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "-v", f"{repo_dir}:/workspace:ro", "python:3.12-alpine", "sh", "-c", "id"],
        ["docker", "run", "--rm", "--network=none", "--cap-drop=ALL", "--privileged", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "-v", f"{repo_dir}:/workspace:ro", "python:3.12-alpine", "python3", "/harness/run_invariants.py"],
    ):
        bad_ok, _ = validate_sandbox_docker_command(bad)
        assert bad_ok is False


def _create_vulnerable_fixture_repo(repo_dir: Path) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    # 1. Shadowed .authz policy
    (repo_dir / "service.authz").write_text(
        "allow * /api/*\ndeny guest /admin/secret\n",
        encoding="utf-8",
    )
    # 2. Authz handler with fall-through past deny
    (repo_dir / "authz_handler.py").write_text(
        "def protected_admin_action(req):\n"
        "    return {'status': 200, 'protected_reached': True, 'secret': 'ok'}\n\n"
        "def handle_request(req):\n"
        "    if req.get('authz') == 'deny':\n"
        "        audit_log = 'denied'\n"
        "    return protected_admin_action(req)\n",
        encoding="utf-8",
    )
    # 3. Path helper that escapes sandbox root
    (repo_dir / "sandbox_paths.py").write_text(
        "import os\n\n"
        "def resolve_sandbox_path(root_dir, user_path):\n"
        "    return os.path.join(root_dir, user_path)\n",
        encoding="utf-8",
    )
    # 4. TypeScript fail-open policy catch
    (repo_dir / "policy_filter.ts").write_text(
        "export function evaluatePolicy(req: any) {\n"
        "  try {\n"
        "    return { action: 'deny' };\n"
        "  } catch (err) {\n"
        "    return { action: 'allow' };\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    # 5. Permissive HTTP framing parser accepting CL+TE
    (repo_dir / "http_parser.py").write_text(
        "def parse_http_request(raw: bytes):\n"
        "    return {'status': 200, 'len': len(raw)}\n",
        encoding="utf-8",
    )


def _create_compliant_fixture_repo(repo_dir: Path) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "service.authz").write_text(
        "deny guest /admin/secret\nallow admin /admin/secret\n",
        encoding="utf-8",
    )
    (repo_dir / "authz_handler.py").write_text(
        "def protected_admin_action(req):\n"
        "    return {'status': 200, 'protected_reached': True}\n\n"
        "def handle_request(req):\n"
        "    if req.get('authz') == 'deny' or req.get('decision') == 'deny':\n"
        "        return {'status': 403, 'protected_reached': False}\n"
        "    return protected_admin_action(req)\n",
        encoding="utf-8",
    )
    (repo_dir / "sandbox_paths.py").write_text(
        "from pathlib import Path\n\n"
        "def resolve_sandbox_path(root_dir, user_path):\n"
        "    root = Path(root_dir).resolve()\n"
        "    if '..' in str(user_path) or str(user_path).startswith(('/', '\\\\')) or '%2e' in str(user_path).lower():\n"
        "        raise ValueError('traversal denied')\n"
        "    cand = (root / user_path).resolve()\n"
        "    if not (cand == root or cand.is_relative_to(root)):\n"
        "        raise ValueError('escaped root')\n"
        "    return str(cand)\n",
        encoding="utf-8",
    )
    (repo_dir / "policy_filter.ts").write_text(
        "export function evaluatePolicy(req: any) {\n"
        "  try {\n"
        "    return { action: 'deny' };\n"
        "  } catch (err) {\n"
        "    return { action: 'deny' };\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo_dir / "http_parser.py").write_text(
        "def parse_http_request(raw: bytes):\n"
        "    low = raw.lower()\n"
        "    if b'transfer-encoding' in low and b'content-length' in low:\n"
        "        return {'status': 400}\n"
        "    if low.count(b'content-length:') > 1:\n"
        "        return {'status': 400}\n"
        "    return {'status': 200}\n",
        encoding="utf-8",
    )


def test_invariant_harness_scripts_compile_and_detect_violations_vs_compliant(tmp_path):
    # Compile Python harness script to guarantee zero syntax issues
    py_script = build_invariant_harness_script()
    compile(py_script, "run_invariants.py", "exec")
    node_script = build_node_invariant_harness_script()
    assert "RFCHUNT_INVARIANTS_JSON:" in node_script

    harness_path = tmp_path / "run_invariants.py"
    harness_path.write_text(py_script, encoding="utf-8")

    # Vulnerable repo -> detects all 4 concrete invariant categories
    vuln_repo = tmp_path / "vuln_repo"
    _create_vulnerable_fixture_repo(vuln_repo)
    assert "python" in detect_repo_languages(vuln_repo)
    assert "policy_authz" in detect_repo_languages(vuln_repo)
    assert "typescript" in detect_repo_languages(vuln_repo)

    proc_vuln = subprocess.run(
        [sys.executable, str(harness_path), str(vuln_repo)],
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert proc_vuln.returncode == 0, proc_vuln.stderr
    parsed_vuln = parse_invariant_harness_output(proc_vuln.stdout)
    assert parsed_vuln is not None
    failed_ids = {item["invariant_id"] for item in parsed_vuln["invariants"] if not item["passed"]}
    assert "INV-AUTHZ-DENY-REACHABILITY" in failed_ids
    assert "INV-PATH-ROOT-CONFINEMENT" in failed_ids
    assert "INV-POLICY-DENIAL-ENFORCEMENT" in failed_ids
    assert "INV-PARSER-STRICT-FRAMING" in failed_ids

    # Compliant repo -> all invariants pass cleanly (zero false positives)
    safe_repo = tmp_path / "safe_repo"
    _create_compliant_fixture_repo(safe_repo)
    proc_safe = subprocess.run(
        [sys.executable, str(harness_path), str(safe_repo)],
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert proc_safe.returncode == 0, proc_safe.stderr
    parsed_safe = parse_invariant_harness_output(proc_safe.stdout)
    assert parsed_safe is not None
    assert all(item["passed"] is True for item in parsed_safe["invariants"])


def test_sandbox_invariant_runner_persists_cairn_facts_on_violation(tmp_path):
    """
    Runs SandboxInvariantRunner end-to-end against a real vulnerable fixture repo and
    a real in-memory Cairn Database, verifying docker args & persisted FACT node payloads.
    """
    vuln_repo = tmp_path / "vuln_repo"
    _create_vulnerable_fixture_repo(vuln_repo)
    captured_docker_run: List[List[str]] = []

    def simulated_docker_runner(args, **kwargs):
        assert kwargs.get("shell") is False
        if args[1] == "info":
            return subprocess.CompletedProcess(args, 0, stdout="27.3.1\n", stderr="")
        if args[1] == "image" and args[2] == "inspect":
            return subprocess.CompletedProcess(args, 0, stdout="sha256:py312\n", stderr="")
        if args[1] == "run":
            captured_docker_run.append(list(args))
            # Extract mounted /harness host path and execute the real harness script locally
            harness_dir = None
            for idx, tok in enumerate(args):
                if tok == "-v" and idx + 1 < len(args) and args[idx + 1].endswith(":/harness:ro"):
                    spec = args[idx + 1]
                    harness_dir = spec[: -len(":/harness:ro")]
            assert harness_dir is not None
            real_proc = subprocess.run(
                [sys.executable, str(Path(harness_dir) / "run_invariants.py"), str(vuln_repo)],
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=20,
            )
            return subprocess.CompletedProcess(args, real_proc.returncode, stdout=real_proc.stdout, stderr=real_proc.stderr)
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="unexpected")

    db = Database(":memory:")
    try:
        runner = SandboxInvariantRunner(docker_bin="docker", subprocess_runner=simulated_docker_runner)
        report = runner.run(vuln_repo, db=db, task_id="cairn-inv-test")

        assert report.status == "completed"
        assert report.container_mode == "docker_network_none"
        assert report.invariants_failed >= 4
        assert len(report.persisted_fact_ids) == report.invariants_failed
        assert len(captured_docker_run) == 1
        ok, reason = validate_sandbox_docker_command(captured_docker_run[0])
        assert ok is True, reason

        facts = db.get_facts(task_id="cairn-inv-test")
        assert len(facts) == report.invariants_failed
        for fact in facts:
            assert fact["node_type"] == "FACT"
            assert fact["source_agent"] == "SandboxInvariantRunner"
            payload = fact["payload"]
            assert payload["invariant_id"]
            assert payload["file_path"]
            assert payload["container_mode"] == "docker_network_none"
            assert payload["evidence"]
    finally:
        db.close()


def test_sandbox_invariant_runner_clean_skip_when_docker_unavailable(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

    def unavailable_runner(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="docker daemon not running")

    runner = SandboxInvariantRunner(docker_bin="docker", subprocess_runner=unavailable_runner)
    report = runner.run(repo)

    assert report.status == "skipped_docker_unavailable"
    assert report.container_mode == "skipped_docker_unavailable"
    assert report.invariants_failed == 0
    assert report.provenance["docker_available"] is False


# ==============================================================================
# 4. CONTAINERIZED NON-DESTRUCTIVE POE == 3 VERIFIER
# ==============================================================================


def test_poe_verifier_docker_command_construction_and_safety_guards(tmp_path):
    repo_dir = tmp_path / "repo"
    harness_dir = tmp_path / "poe_harness"
    repo_dir.mkdir()
    harness_dir.mkdir()

    verifier = ContainerPOEVerifier(docker_bin="docker")

    # Local repo mode -> strictly --network=none + :ro mounts
    cmd_repo = verifier.build_docker_command(harness_dir, mode="docker_network_none", repo_path=repo_dir)
    assert "--rm" in cmd_repo
    assert "--network=none" in cmd_repo
    assert "--cap-drop=ALL" in cmd_repo
    assert "--read-only" in cmd_repo
    assert "--network=host" not in cmd_repo
    assert "--add-host" not in cmd_repo
    ok_repo, reason_repo = validate_poe_docker_command(cmd_repo, mode="docker_network_none")
    assert ok_repo is True, reason_repo

    # Loopback-only mode -> NO --network=host, only host.docker.internal:host-gateway
    cmd_loop = verifier.build_docker_command(harness_dir, mode="docker_loopback_only")
    assert "--rm" in cmd_loop
    assert "--cap-drop=ALL" in cmd_loop
    assert "--network=host" not in cmd_loop
    assert "host.docker.internal:host-gateway" in cmd_loop
    ok_loop, reason_loop = validate_poe_docker_command(cmd_loop, mode="docker_loopback_only")
    assert ok_loop is True, reason_loop

    # Reject non-loopback target host fail-closed
    res_ssrf = verifier.verify_finding(
        {
            "finding_id": "F-SSRF",
            "title": "External check attempt",
            "severity": "CRITICAL",
            "target_host": "169.254.169.254",
            "target_port": 80,
        }
    )
    assert res_ssrf.status == "rejected_unsafe_target"
    assert res_ssrf.verified is False
    assert res_ssrf.poe_level == 0

    # Reject destructive HTTP verb fail-closed
    res_dest = verifier.verify_finding(
        {
            "finding_id": "F-DEST",
            "title": "Destructive probe attempt",
            "severity": "HIGH",
            "target_host": "127.0.0.1",
            "target_port": 8080,
            "raw_probe": b"DELETE /resource HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        }
    )
    assert res_dest.status == "rejected_unsafe_target"
    assert res_dest.verified is False


def test_poe_verifier_promotion_to_poe3_vs_false_positive_downgrade(tmp_path):
    """
    Executes auto-generated non-destructive POE test scripts against a real repo containing
    one genuine path confinement flaw and one false-positive candidate pointing to safe code.
    Verifies POE==3 promotion, Cairn FACT persistence, false-positive downgrade, and filtering.
    """
    repo_dir = tmp_path / "poe_repo"
    repo_dir.mkdir()
    (repo_dir / "vuln_paths.py").write_text(
        "import os\n"
        "def resolve_sandbox_path(root_dir, user_path):\n"
        "    return os.path.join(root_dir, user_path)\n",
        encoding="utf-8",
    )
    (repo_dir / "safe_paths.py").write_text(
        "from pathlib import Path\n"
        "def resolve_sandbox_path(root_dir, user_path):\n"
        "    root = Path(root_dir).resolve()\n"
        "    if '..' in str(user_path) or str(user_path).startswith('/'):\n"
        "        raise ValueError('blocked')\n"
        "    cand = (root / user_path).resolve()\n"
        "    if not (cand == root or cand.is_relative_to(root)):\n"
        "        raise ValueError('blocked')\n"
        "    return str(cand)\n",
        encoding="utf-8",
    )

    captured_cmds: List[List[str]] = []

    def simulated_poe_docker_runner(args, **kwargs):
        assert kwargs.get("shell") is False
        if args[1] == "info":
            return subprocess.CompletedProcess(args, 0, stdout="27.3.1\n", stderr="")
        if args[1] == "image" and args[2] == "inspect":
            return subprocess.CompletedProcess(args, 0, stdout="sha256:py312\n", stderr="")
        if args[1] == "run":
            captured_cmds.append(list(args))
            poe_dir = None
            for idx, tok in enumerate(args):
                if tok == "-v" and idx + 1 < len(args) and args[idx + 1].endswith(":/poe:ro"):
                    poe_dir = args[idx + 1][: -len(":/poe:ro")]
            assert poe_dir is not None
            script_path = Path(poe_dir) / "verify_poe.py"
            # Compile check + run generated script with WORKSPACE pointed to repo_dir
            code = script_path.read_text(encoding="utf-8")
            compile(code, str(script_path), "exec")
            adapted_path = Path(poe_dir) / "verify_poe_local.py"
            adapted_path.write_text(
                code.replace('Path("/workspace").resolve()', f"Path({str(repo_dir)!r}).resolve()"),
                encoding="utf-8",
            )
            real_proc = subprocess.run(
                [sys.executable, str(adapted_path)],
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=20,
            )
            return subprocess.CompletedProcess(args, real_proc.returncode, stdout=real_proc.stdout, stderr=real_proc.stderr)
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="unexpected")

    findings = [
        {
            "finding_id": "FIND-REAL-PATH",
            "title": "Sandbox path traversal escape in vuln_paths.py",
            "severity": "HIGH",
            "cwe": "CWE-22",
            "file_path": "vuln_paths.py",
            "function_name": "resolve_sandbox_path",
        },
        {
            "finding_id": "FIND-FP-PATH",
            "title": "Suspected path traversal in safe_paths.py",
            "severity": "CRITICAL",
            "cwe": "CWE-22",
            "file_path": "safe_paths.py",
            "function_name": "resolve_sandbox_path",
        },
        {
            "finding_id": "FIND-LOW-INFO",
            "title": "Informational style note",
            "severity": "LOW",
            "file_path": "safe_paths.py",
        },
    ]

    db = Database(":memory:")
    try:
        verifier = ContainerPOEVerifier(docker_bin="docker", subprocess_runner=simulated_poe_docker_runner)
        batch = verifier.verify_findings(findings, repo_path=repo_dir, db=db, task_id="poe-test-task")

        assert batch.status == "completed"
        assert batch.eligible_candidates == 2
        assert batch.verified_poe3_count == 1
        assert batch.downgraded_false_positive_count == 1
        assert batch.skipped_count == 1

        by_id = {r.finding_id: r for r in batch.results}
        real_res = by_id["FIND-REAL-PATH"]
        assert real_res.status == "verified"
        assert real_res.verified is True
        assert real_res.false_positive is False
        assert real_res.poe_level == int(POELevel.VERIFIED_EXPLOIT) == 3
        assert real_res.cairn_fact_id is not None

        fp_res = by_id["FIND-FP-PATH"]
        assert fp_res.status == "downgraded_false_positive"
        assert fp_res.verified is False
        assert fp_res.false_positive is True
        assert fp_res.poe_level == 0
        assert fp_res.calibrated_severity == "LOW"

        low_res = by_id["FIND-LOW-INFO"]
        assert low_res.status == "skipped_below_threshold"

        # Verify all executed docker commands pass hardened validation
        assert len(captured_cmds) == 2
        for cmd in captured_cmds:
            ok, reason = validate_poe_docker_command(cmd, mode="docker_network_none")
            assert ok is True, reason

        # Verify Cairn FACT node persisted for POE == 3 verified finding
        facts = db.get_facts(task_id="poe-test-task")
        assert len(facts) == 1
        assert facts[0]["payload"]["poe_level"] == 3
        assert facts[0]["payload"]["finding_id"] == "FIND-REAL-PATH"

        # Verify apply_verifications_to_findings updates & optionally drops false positives
        annotated = ContainerPOEVerifier.apply_verifications_to_findings(findings, batch.results, drop_false_positives=False)
        assert annotated[0]["poe_level"] == 3
        assert annotated[1]["false_positive"] is True
        assert annotated[1]["calibrated_severity"] == "LOW"

        filtered = ContainerPOEVerifier.apply_verifications_to_findings(findings, batch.results, drop_false_positives=True)
        assert [f["finding_id"] for f in filtered] == ["FIND-REAL-PATH", "FIND-LOW-INFO"]
    finally:
        db.close()


def test_poe_verifier_clean_skip_when_docker_unavailable(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("x = 1\n", encoding="utf-8")

    def offline_runner(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="docker daemon unavailable")

    verifier = ContainerPOEVerifier(docker_bin="docker", subprocess_runner=offline_runner)
    findings = [
        {
            "finding_id": "F-CRIT-1",
            "title": "Critical authz issue",
            "severity": "CRITICAL",
            "cwe": "CWE-863",
            "file_path": "app.py",
            "poe_level": 1,
        }
    ]
    batch = verifier.verify_findings(findings, repo_path=repo_dir)
    assert batch.status == "skipped_docker_unavailable"
    assert batch.verified_poe3_count == 0
    assert batch.downgraded_false_positive_count == 0
    assert batch.results[0].status == "skipped_docker_unavailable"
    assert batch.results[0].poe_level == 1  # Preserved without false promotion or false downgrade
    assert batch.provenance["docker_available"] is False


def test_poe_loopback_generated_test_reproduces_against_live_loopback_server(tmp_path):
    """Compiles and runs the auto-generated loopback-only POE test against a real 127.0.0.1 server."""
    with _LoopbackRawHTTPServer(_permissive_http_responder) as srv:
        mode, code, meta = generate_verification_test(
            {
                "finding_id": "F-LOOP-1",
                "title": "Permissive parser accepts pre-colon whitespace",
                "severity": "HIGH",
                "cwe": "CWE-444",
                "target_host": "127.0.0.1",
                "target_port": srv.port,
                "raw_probe": b"GET / HTTP/1.1\r\nHost : 127.0.0.1\r\nConnection: close\r\n\r\n",
                "expected_anomalous_statuses": [200],
            }
        )
        assert mode == "docker_loopback_only"
        assert meta["target_port"] == srv.port
        compile(code, "verify_loopback_poe.py", "exec")

        # Execute against 127.0.0.1 locally (in container it routes via host.docker.internal)
        local_script = tmp_path / "verify_loopback_poe.py"
        local_script.write_text(code.replace('"host.docker.internal"', '"127.0.0.1"'), encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(local_script)],
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
        )
        assert proc.returncode == 0, proc.stderr
        assert POE_RESULT_MARKER in proc.stdout
        payload = json.loads(proc.stdout.split(POE_RESULT_MARKER, 1)[1].strip())
        assert payload["reproduced"] is True
        assert payload["trials_reproduced"] == 3
