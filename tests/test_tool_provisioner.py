"""
Unit and Integration Tests for Dynamic Tool Provisioning (`engine/tool_provisioner.py`)
=====================================================================================
Verifies:
1. Complete tool catalog coverage (`aiscan`, `raptor`, `raptor_docker`, `httpx`,
   `katana`, `nuclei`, `artex`, `rea_agents`, `semgrep`, `python_deps`, `ollama`,
   `ollama_models`, `rfc_cache`, `docker_scanners`).
2. Strict offline/CI/pytest safety (`RFCHUNT_OFFLINE=1` / default pytest blocks
   unexpected downloads and external installer subprocesses).
3. Safe archive handling: OS/arch asset matching, SHA256 verification (positive &
   tamper rejection), and zip-slip path traversal rejection.
4. Process-scoped `PATH` registration (NEVER mutates registry or runs `setx`).
5. Python `httpx[cli]` disambiguation so ProjectDiscovery `httpx` is never shadowed.
6. Controlled end-to-end installer command construction (`aiscan` via cargo, `raptor`
   via git/zip + loopback patch, `httpx`/`katana`/`nuclei`/`artex` via GitHub zip,
   `rea_agents` via local npm prefix + `ExecutionPolicy` / `ApprovalGate` parity).
7. CLI (`rfc_hunt_swarm.py setup` / `--tool-status` / `--no-auto-install`) and
   MCP (`rfchunt_provision_tools`) integration.
"""

from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import zipfile

import pytest

from engine.approval_gate import ApprovalGate
from engine.execution_policy import ActionType, ExecutionPolicy, ScannerTask, StructuredIntentProposal
from engine.tool_provisioner import (
    ALL_TOOL_IDS,
    TOOL_CATALOG,
    ToolProvisioner,
    ToolStatus,
    _extract_single_binary_from_archive,
    _is_python_httpx_binary,
    _select_release_asset,
    _validate_archive_member_name,
    _verify_sha256_against_manifest,
    register_process_bin_dir,
)
from mcp_server import TerminatorMCPServer
from rfc_hunt_swarm import ALL_MODES, main_swarm, parse_swarm_arguments


def test_tool_catalog_complete_and_unique() -> None:
    ids = [spec.tool_id for spec in TOOL_CATALOG]
    assert len(ids) == len(set(ids))
    for required in (
        "python_deps",
        "semgrep",
        "aiscan",
        "raptor",
        "raptor_docker",
        "httpx",
        "katana",
        "nuclei",
        "artex",
        "rea_agents",
        "ollama",
        "ollama_models",
        "rfc_cache",
        "docker_scanners",
    ):
        assert required in ALL_TOOL_IDS


def test_offline_guard_blocks_install_subprocesses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    prov = ToolProvisioner(repo_root=tmp_path, raptor_root=tmp_path / "raptor")

    called = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: called.append(a))
    summary = prov.ensure_all(include_docker=True, include_models=True)

    assert summary["offline_or_test_skipped"] is True
    assert len(called) == 0


def test_archive_zip_slip_sha256_and_binary_extraction(tmp_path: Path) -> None:
    assert _validate_archive_member_name("httpx.exe") is True
    assert _validate_archive_member_name("../evil.exe") is False
    assert _validate_archive_member_name("/etc/passwd") is False
    assert _validate_archive_member_name("C:\\evil.exe") is False

    # Build a synthetic official zip release archive
    bin_name = "httpx.exe" if os.name == "nt" else "httpx"
    bin_payload = b"MZ\x90\x00ProjectDiscoveryHttpxStub" + b"\x00" * 512
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.md", "ProjectDiscovery httpx")
        zf.writestr(bin_name, bin_payload)
    archive_bytes = buf.getvalue()
    sha = hashlib.sha256(archive_bytes).hexdigest()

    ok_sum, _ = _verify_sha256_against_manifest(archive_bytes, "httpx_1.0_win.zip", f"{sha}  httpx_1.0_win.zip\n")
    assert ok_sum is True
    bad_sum, err_msg = _verify_sha256_against_manifest(archive_bytes, "httpx_1.0_win.zip", f"{'0'*64}  httpx_1.0_win.zip\n")
    assert bad_sum is False
    assert "mismatch" in err_msg.lower()

    out_dir = tmp_path / "bin"
    extracted = _extract_single_binary_from_archive(archive_bytes, "httpx_1.0_win.zip", "httpx", out_dir)
    assert extracted.is_file()
    assert extracted.read_bytes() == bin_payload

    # Reject malicious archive member paths
    evil_buf = io.BytesIO()
    with zipfile.ZipFile(evil_buf, "w") as zf:
        zf.writestr(f"../../{bin_name}", b"evil")
    with pytest.raises(ValueError):
        _extract_single_binary_from_archive(evil_buf.getvalue(), "evil.zip", "httpx", out_dir)


def test_release_asset_selection_cross_platform() -> None:
    assets = [
        {"name": "httpx_1.12.0_checksums.txt", "browser_download_url": "https://example.invalid/csum"},
        {"name": "httpx_1.12.0_linux_amd64.zip", "browser_download_url": "https://example.invalid/linux_amd64"},
        {"name": "httpx_1.12.0_linux_arm64.zip", "browser_download_url": "https://example.invalid/linux_arm64"},
        {"name": "httpx_1.12.0_macOS_arm64.zip", "browser_download_url": "https://example.invalid/macos_arm64"},
        {"name": "httpx_1.12.0_windows_amd64.zip", "browser_download_url": "https://example.invalid/win_amd64"},
        {"name": "httpx_1.12.0_windows_386.zip", "browser_download_url": "https://example.invalid/win_386"},
    ]
    chosen = _select_release_asset(assets)
    assert chosen is not None
    assert "checksum" not in chosen["name"].lower()

    # Regression: "win" substring in "darwin" must never cause Windows to select darwin archive
    artex_assets = [
        {"name": "artex-0.7.0-darwin-amd64.zip", "browser_download_url": "https://example.invalid/darwin"},
        {"name": "artex-0.7.0-linux-amd64.zip", "browser_download_url": "https://example.invalid/linux"},
        {"name": "artex-0.7.0-windows-amd64.zip", "browser_download_url": "https://example.invalid/windows"},
    ]
    chosen_artex = _select_release_asset(artex_assets)
    assert chosen_artex is not None
    if os.name == "nt":
        assert "windows" in chosen_artex["name"]
    elif os.sys.platform == "darwin" if hasattr(os, "sys") else False:
        assert "darwin" in chosen_artex["name"]


def test_process_scoped_path_and_python_httpx_filter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "local_bin"
    bin_dir.mkdir()
    py_dir = tmp_path / "py_scripts"
    py_dir.mkdir()

    py_httpx = py_dir / ("httpx.exe" if os.name == "nt" else "httpx")
    py_httpx.write_bytes(b"#!/usr/bin/python\nfrom httpx import main\nsys.exit(main())\n")
    assert _is_python_httpx_binary(py_httpx) is True

    monkeypatch.setenv("PATH", str(py_dir))
    register_process_bin_dir(bin_dir)
    # Process PATH prepended locally; registry untouched
    assert os.environ["PATH"].startswith(str(bin_dir.resolve()))

    pd_httpx = bin_dir / ("httpx.exe" if os.name == "nt" else "httpx")
    pd_httpx.write_bytes(b"MZ\x90\x00PD-HTTPX-REAL" + b"\x00" * 512)
    if os.name != "nt":
        pd_httpx.chmod(0o755)

    prov = ToolProvisioner(repo_root=tmp_path, raptor_root=tmp_path / "raptor")
    found = prov.find_binary("httpx")
    assert found is not None
    assert found.resolve() == pd_httpx.resolve()


def test_dynamic_installers_github_cargo_raptor_and_npm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    monkeypatch.setenv("RFCHUNT_OFFLINE", "0")
    monkeypatch.delenv("RFCHUNT_AUTO_INSTALL_TOOLS", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    repo_root = tmp_path / "rfchunt_mock"
    (repo_root / "scripts").mkdir(parents=True)
    (repo_root / "scripts" / "Invoke-RaptorScan.ps1").write_text("# ps1 stub\n", encoding="utf-8")
    raptor_root = tmp_path / "raptor_dst"

    prov = ToolProvisioner(repo_root=repo_root, raptor_root=raptor_root, allow_in_tests=True)

    # 1. Mock GitHub release download for katana + SHA256 manifest
    bin_name = "katana.exe" if os.name == "nt" else "katana"
    fake_bin = b"MZ\x90\x00PD-KATANA-BIN" + b"\x00" * 256
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr(bin_name, fake_bin)
    zbytes = zbuf.getvalue()
    sha = hashlib.sha256(zbytes).hexdigest()

    asset_name = "katana_1.8.0_windows_amd64.zip" if os.name == "nt" else (
        "katana_1.8.0_macOS_arm64.zip" if sys.platform == "darwin" else "katana_1.8.0_linux_amd64.zip"
    )
    checksum_txt = f"{sha}  {asset_name}\n".encode("utf-8")

    # Serve release assets from a real loopback HTTP server so _http_download_bytes exercises real urllib HTTP
    class _AssetHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/katana.zip":
                data = zbytes
            elif self.path == "/checksums.txt":
                data = checksum_txt
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _AssetHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        release_meta = {
            "tag_name": "v1.8.0",
            "assets": [
                {"name": asset_name, "browser_download_url": f"http://127.0.0.1:{port}/katana.zip"},
                {
                    "name": "katana_1.8.0_linux_amd64.zip",
                    "browser_download_url": f"http://127.0.0.1:{port}/katana.zip",
                },
                {
                    "name": "katana_1.8.0_linux_arm64.zip",
                    "browser_download_url": f"http://127.0.0.1:{port}/katana.zip",
                },
                {
                    "name": "katana_1.8.0_macOS_amd64.zip",
                    "browser_download_url": f"http://127.0.0.1:{port}/katana.zip",
                },
                {
                    "name": "katana-1.8.0-checksums.txt",
                    "browser_download_url": f"http://127.0.0.1:{port}/checksums.txt",
                },
            ],
        }
        with monkeypatch.context() as mp:
            mp.setattr(ToolProvisioner, "_http_get_json", staticmethod(lambda *a, **kw: release_meta))
            st_katana = prov.ensure_tool("katana", force=True)
        assert st_katana.installed is True
        assert st_katana.installed_now is True
        assert Path(st_katana.path_or_source).read_bytes() == fake_bin
    finally:
        srv.shutdown()
        srv.server_close()

    # 2. Test RAPTOR provisioning + models.json + Invoke-RaptorScan.ps1 + host.docker.internal patch
    raptor_zip = io.BytesIO()
    with zipfile.ZipFile(raptor_zip, "w") as zf:
        zf.writestr("raptor-main/raptor.py", "print('raptor')\n")
        zf.writestr(
            "raptor-main/core/llm/egress.py",
            'HOSTS = ("localhost", "127.0.0.1", "::1", "0.0.0.0",)\n',
        )
        zf.writestr(
            "raptor-main/core/llm/detection.py",
            'if host in ("localhost", "0.0.0.0"):\n    pass\n',
        )
    with monkeypatch.context() as mp:
        mp.setattr(shutil, "which", lambda *a, **kw: None)
        mp.setattr(ToolProvisioner, "_http_download_bytes", staticmethod(lambda *a, **kw: raptor_zip.getvalue()))
        st_raptor = prov.ensure_tool("raptor", force=True)
    assert st_raptor.installed is True
    assert (raptor_root / "raptor.py").is_file()
    assert (raptor_root / "models.json").is_file()
    assert (raptor_root / "Invoke-RaptorScan.ps1").is_file()
    assert '"host.docker.internal"' in (raptor_root / "core" / "llm" / "egress.py").read_text(encoding="utf-8")

    # 3. Test aiscan installation via cargo_root
    recorded_cmds = []

    def _fake_subproc(argv, **kwargs):
        recorded_cmds.append(list(argv))
        if argv and "cargo" in Path(argv[0]).name.lower() and "install" in argv:
            cbin = prov.cargo_root / "bin"
            cbin.mkdir(parents=True, exist_ok=True)
            exe_n = "aiscan.exe" if os.name == "nt" else "aiscan"
            p = cbin / exe_n
            p.write_bytes(b"AISCAN-BIN")
            if os.name != "nt":
                p.chmod(0o755)
        elif argv and "npm" in " ".join(argv).lower():
            mjs = prov.npm_prefix / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"
            mjs.parent.mkdir(parents=True, exist_ok=True)
            mjs.write_text("console.log('{}');\n", encoding="utf-8")
            pbin = prov.npm_prefix / "node_modules" / ".bin" / "rea-agents"
            pbin.parent.mkdir(parents=True, exist_ok=True)
            pbin.write_text("#!/usr/bin/env node\n", encoding="utf-8")
            if os.name != "nt":
                pbin.chmod(0o755)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    expected_aiscan = prov.cargo_root / "bin" / ("aiscan.exe" if os.name == "nt" else "aiscan")
    find_seq = iter([None, expected_aiscan])
    import engine.tool_provisioner as tp_mod

    with monkeypatch.context() as mp:
        mp.setattr(tp_mod, "_run_quiet_subprocess", _fake_subproc)
        mp.setattr(ToolProvisioner, "find_binary", lambda self, stem: next(find_seq))
        mp.setattr(shutil, "which", lambda *a, **kw: "/usr/bin/cargo")
        st_ai = prov.ensure_tool("aiscan", force=True)
    assert st_ai.installed is True
    assert any("cargo" in " ".join(c).lower() and "install" in c for c in recorded_cmds)

    # 4. Test rea-agents npm local installation
    with monkeypatch.context() as mp:
        mp.setattr(tp_mod, "_run_quiet_subprocess", _fake_subproc)
        mp.setattr(shutil, "which", lambda *a, **kw: "/usr/bin/npm")
        st_rea = prov.ensure_tool("rea_agents", force=True)
    assert (prov.npm_prefix / "node_modules" / "rea-agents" / "scripts" / "rea.mjs").is_file()
    if os.name != "nt":
        assert st_rea.installed is True


def test_execution_policy_allows_only_safe_repo_rea_node() -> None:
    ExecutionPolicy.reset_instance()
    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(mode="policy")
    safe_mjs = (
        Path(__file__).resolve().parent.parent
        / "tools"
        / "npm"
        / "node_modules"
        / "rea-agents"
        / "scripts"
        / "rea.mjs"
    )
    ok_cmd = ["node", str(safe_mjs), "analyze-javascript-application", ".", "--json"]
    ok, reason = policy.validate_subprocess_command(ok_cmd, shell=False)
    assert ok is True, reason
    assert gate.check(action_type="subprocess_exec", target=".", command=ok_cmd).approved is True

    # Arbitrary node scripts or eval remain strictly blocked fail-closed!
    for bad_node in (
        ["node", "-e", "require('child_process').exec('id')"],
        ["node", "/tmp/evil.js"],
        ["node", str(safe_mjs), "analyze-binary", "app.exe"],
        ["node", str(safe_mjs), "analyze-javascript-application", "--ghidra"],
    ):
        ok_b, _ = policy.validate_subprocess_command(bad_node, shell=False)
        assert ok_b is False, f"Expected ExecutionPolicy to reject {bad_node!r}"


def test_cli_setup_and_mcp_provision_tools(capsys: pytest.CaptureFixture[str]) -> None:
    assert "setup" in ALL_MODES
    assert "install-tools" in ALL_MODES

    args_setup = parse_swarm_arguments(["setup", "--tool-status", "--json"])
    assert args_setup.command == "setup"
    assert args_setup.tool_status is True

    args_no_auto = parse_swarm_arguments(["--all", "--repo", ".", "--no-auto-install"])
    assert args_no_auto.auto_install is False

    # Run setup --tool-status --json via main_swarm safely offline
    main_swarm(["setup", "--tool-status", "--tools", "python_deps,raptor,httpx", "--json"])
    out_json = json.loads(capsys.readouterr().out)
    assert out_json["total"] == 3
    assert set(out_json["tools"].keys()) == {"python_deps", "raptor", "httpx"}

    # Verify MCP server exposes and executes rfchunt_provision_tools
    with TerminatorMCPServer(db_path=":memory:") as srv:
        names = [t["name"] for t in srv._get_tool_definitions()]
        assert "rfchunt_provision_tools" in names
        mcp_res = srv._execute_tool("rfchunt_provision_tools", {"install_missing": False, "tools": ["python_deps", "aiscan"]})
        assert mcp_res["total"] == 2
        assert "python_deps" in mcp_res["tools"]


def test_dynamic_free_ram_and_vram_ollama_sizing_never_appends_coder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ollama_manager
    from fusion_engine import FusionArbiter
    from engine.raptor_integrator import RaptorIntegrator

    # 1. Verify strict runtime free-RAM tiers (never total physical RAM, never `-coder`)
    ram_cases = [
        (4.0, 0.0, "qwen2.5:1.5b"),
        (6.0, 0.0, "qwen2.5:3b"),
        (12.0, 0.0, "qwen2.5:7b"),
        (24.0, 0.0, "qwen2.5:14b"),
        (48.0, 0.0, "qwen2.5:32b"),
    ]
    for ram_gb, vram_mb, expected in ram_cases:
        got = ollama_manager.size_qwen_for_free_memory(ram_gb, vram_mb)
        assert got == expected
        assert "-coder" not in got
        assert FusionArbiter._size_qwen_for_free_memory(ram_gb, vram_mb) == expected

    # 2. Verify runtime free-VRAM overrides low system RAM safely
    vram_cases = [
        (4.0, 2048.0, "qwen2.5:3b"),
        (4.0, 4608.0, "qwen2.5:7b"),
        (4.0, 14336.0, "qwen2.5:14b"),
        (4.0, 24576.0, "qwen2.5:32b"),
    ]
    for ram_gb, vram_mb, expected in vram_cases:
        got = ollama_manager.size_qwen_for_free_memory(ram_gb, vram_mb)
        assert got == expected
        assert "-coder" not in got

    # 3. Verify RAPTOR runtime model & models.json adapt to constrained free memory without `-coder`
    monkeypatch.setattr(ollama_manager, "get_runtime_free_memory", lambda allow_in_tests=False: (4.0, 0.0))
    raptor = RaptorIntegrator(raptor_root=tmp_path / "raptor_low")
    rec_low = raptor.resolve_runtime_model()
    assert rec_low == "qwen2.5:1.5b"
    assert "-coder" not in rec_low

    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    monkeypatch.setenv("RFCHUNT_OFFLINE", "0")
    monkeypatch.delenv("RFCHUNT_AUTO_INSTALL_TOOLS", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    raptor_zip = io.BytesIO()
    with zipfile.ZipFile(raptor_zip, "w") as zf:
        zf.writestr("raptor-main/raptor.py", "print('ok')\n")
    prov = ToolProvisioner(repo_root=tmp_path / "repo_low", raptor_root=tmp_path / "raptor_low_dst", allow_in_tests=True)
    with monkeypatch.context() as mp:
        mp.setattr(shutil, "which", lambda *a, **kw: None)
        mp.setattr(ToolProvisioner, "_http_download_bytes", staticmethod(lambda *a, **kw: raptor_zip.getvalue()))
        prov.ensure_tool("raptor", force=True)
    models_cfg = json.loads((tmp_path / "raptor_low_dst" / "models.json").read_text(encoding="utf-8"))
    model_names = [entry["model"] for entry in models_cfg["models"]]
    assert model_names == ["qwen2.5:1.5b"]
    assert all("-coder" not in m for m in model_names)

    # 4. Verify ensure_panel_models_installed respects runtime free RAM/VRAM (low RAM -> 1.5b only; high VRAM -> full trio)
    pulled_low: list[str] = []
    with monkeypatch.context() as mp:
        mp.setattr(ollama_manager.OllamaLifecycleManager, "probe_ollama", staticmethod(lambda *a, **kw: []))
        mp.setattr(
            ollama_manager.OllamaLifecycleManager,
            "ensure_model_installed",
            staticmethod(lambda name, **kw: pulled_low.append(name) or True),
        )
        ollama_manager.OllamaLifecycleManager.ensure_panel_models_installed(
            available_tags=[],
            free_ram_gb=4.0,
            free_vram_mb=0.0,
            allow_in_tests=True,
        )
    assert pulled_low == ["qwen2.5:1.5b"]
    assert all("-coder" not in m for m in pulled_low)

    pulled_vram: list[str] = []
    with monkeypatch.context() as mp:
        mp.setattr(ollama_manager.OllamaLifecycleManager, "probe_ollama", staticmethod(lambda *a, **kw: []))
        mp.setattr(
            ollama_manager.OllamaLifecycleManager,
            "ensure_model_installed",
            staticmethod(lambda name, **kw: pulled_vram.append(name) or True),
        )
        ollama_manager.OllamaLifecycleManager.ensure_panel_models_installed(
            available_tags=[],
            free_ram_gb=4.0,
            free_vram_mb=16384.0,
            allow_in_tests=True,
        )
    assert any("Gemma-4-12B-OBLITERATED" in m for m in pulled_vram)
    assert any("foundation-sec" in m for m in pulled_vram)
    assert any("glm-4.7-flash-abliterated" in m for m in pulled_vram)
    assert all("-coder" not in m for m in pulled_vram)


def test_ollama_health_probe_timeouts_clamped_to_400ms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx as _httpx
    import ollama_manager
    import engine.raptor_integrator as ri_mod
    from engine.raptor_integrator import RaptorIntegrator

    seen_timeouts: list[float] = []

    def _fake_httpx_get(url: str, timeout: float = 0.4, **kwargs):
        seen_timeouts.append(float(timeout))
        raise _httpx.ReadTimeout("busy daemon")

    with ollama_manager.OllamaLifecycleManager._lock:
        ollama_manager.OllamaLifecycleManager._cached_by_endpoint.clear()
        ollama_manager.OllamaLifecycleManager._cached_tags = ["qwen2.5:3b"]

    with monkeypatch.context() as mp:
        mp.setattr(_httpx, "get", _fake_httpx_get)
        res = ollama_manager.OllamaLifecycleManager.probe_ollama(
            endpoint="http://127.0.0.1:11434",
            fast_timeout=5.0,
        )
    # Single <=400ms probe with immediate cached fallback (zero 3.5s retry!)
    assert len(seen_timeouts) == 1
    assert seen_timeouts[0] <= 0.4
    assert res == ["qwen2.5:3b"]

    # Verify RaptorIntegrator.check_status also enforces <=400ms Ollama probe timeout
    raptor_timeouts: list[float] = []

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({"models": [{"name": "qwen2.5:7b"}]}).encode("utf-8")

    def _fake_urlopen(req, timeout=0.4):
        raptor_timeouts.append(float(timeout))
        return _FakeResp()

    monkeypatch.setattr(ollama_manager, "get_runtime_free_memory", lambda allow_in_tests=False: (12.0, 0.0))
    raptor = RaptorIntegrator(raptor_root=tmp_path / "raptor_probe")
    with monkeypatch.context() as mp:
        mp.setattr(ri_mod.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1, stdout="", stderr=""))
        mp.setattr(ri_mod.urllib.request, "urlopen", _fake_urlopen)
        st = raptor.check_status()
    assert len(raptor_timeouts) == 1
    assert raptor_timeouts[0] <= 0.4
    assert st["ollama_ready"] is True
    assert st["free_ram_gb"] == 12.0
    assert "-coder" not in st["recommended_model"]

    # Verify get_free_vram_mb enforces <=400ms timeout and zero subprocesses under offline guard
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    with monkeypatch.context() as mp:
        def _forbid_subproc(*a, **kw):
            raise AssertionError("must not run nvidia-smi offline")

        mp.setattr(ollama_manager.subprocess, "run", _forbid_subproc)
        assert ollama_manager.get_free_vram_mb(allow_in_tests=True) == 0.0

    monkeypatch.setenv("RFCHUNT_OFFLINE", "0")
    monkeypatch.delenv("RFCHUNT_AUTO_PULL_MODELS", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    vram_calls: list[dict] = []

    def _fake_nvidia(argv, **kw):
        vram_calls.append({"argv": list(argv), "timeout": kw.get("timeout"), "shell": kw.get("shell")})
        return subprocess.CompletedProcess(argv, 0, stdout="8192\n16384\n", stderr="")

    with monkeypatch.context() as mp:
        mp.setattr(ollama_manager.shutil, "which", lambda *a, **kw: "/usr/bin/nvidia-smi")
        mp.setattr(ollama_manager.subprocess, "run", _fake_nvidia)
        vram_mb = ollama_manager.get_free_vram_mb(allow_in_tests=True)
    assert vram_mb == 16384.0
    assert len(vram_calls) == 1
    assert vram_calls[0]["shell"] is False
    assert float(vram_calls[0]["timeout"]) <= 0.4
    assert "--query-gpu=memory.free" in vram_calls[0]["argv"]


def test_tool_provisioner_ollama_auto_ready_and_include_models(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ollama_manager

    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    monkeypatch.setenv("RFCHUNT_OFFLINE", "0")
    monkeypatch.delenv("RFCHUNT_AUTO_INSTALL_TOOLS", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    prov = ToolProvisioner(repo_root=tmp_path / "repo_ai", raptor_root=tmp_path / "raptor_ai", allow_in_tests=True)
    events: list[tuple[str, dict]] = []

    pulled_tags: list[str] = []

    def _fake_panel_install(**kw):
        events.append(("ensure_panel_models_installed", kw))
        pulled_tags[:] = [
            "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M",
            "fenkohq/foundation-sec-8b:latest",
        ]
        return list(pulled_tags)

    with monkeypatch.context() as mp:
        mp.setattr(ollama_manager, "get_runtime_free_memory", lambda *a, **kw: (16.0, 8192.0))
        mp.setattr(ollama_manager.OllamaLifecycleManager, "find_ollama_binary", staticmethod(lambda: "/usr/bin/ollama"))
        mp.setattr(
            ollama_manager.OllamaLifecycleManager,
            "ensure_ollama_ready",
            staticmethod(lambda **kw: events.append(("ensure_ollama_ready", kw)) or ["qwen2.5:7b"]),
        )
        mp.setattr(
            ollama_manager.OllamaLifecycleManager,
            "ensure_panel_models_installed",
            staticmethod(_fake_panel_install),
        )
        mp.setattr(
            ollama_manager.OllamaLifecycleManager,
            "ensure_model_installed",
            staticmethod(lambda name, **kw: events.append(("ensure_model_installed", {"name": name, **kw})) or True),
        )
        mp.setattr(
            ollama_manager.OllamaLifecycleManager,
            "probe_ollama",
            staticmethod(lambda **kw: list(pulled_tags)),
        )
        res = prov.ensure_all(tool_ids=["ollama_models"], include_docker=False, include_models=True, force=True)

    assert res["offline_or_test_skipped"] is False
    assert "ollama" in res["tools"]
    assert "ollama_models" in res["tools"]
    assert res["tools"]["ollama_models"]["installed"] is True
    panel_ev = next(kw for name, kw in events if name == "ensure_panel_models_installed")
    assert panel_ev["free_ram_gb"] == 16.0
    assert panel_ev["free_vram_mb"] == 8192.0

    # include_models=False filters out ollama_models even when passed in tool_ids
    res_no_models = prov.ensure_all(tool_ids=["python_deps", "ollama_models"], include_docker=False, include_models=False)
    assert "ollama_models" not in res_no_models["tools"]


def test_run_unified_all_scans_provisioning_order_include_models_and_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.aiscan_integrator as ai_mod
    import engine.mantis_integrator as mi
    import engine.raptor_integrator as ri_mod
    from database import Database

    repo_dir = tmp_path / "mini_repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    # 1. Online mode: ToolProvisioner MUST run BEFORE FusionArbiter & MantisIntegrator,
    #    with include_models=True by default and ollama + ollama_models + default-ON tools in requested_tools.
    monkeypatch.setenv("RFCHUNT_OFFLINE", "0")
    monkeypatch.delenv("RFCHUNT_AUTO_INSTALL_TOOLS", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    order: list[str] = []
    prov_calls: list[dict] = []

    def _fake_ensure_all(self, **kwargs):
        order.append("provisioner")
        prov_calls.append(dict(kwargs))
        return {"offline_or_test_skipped": False, "total": len(kwargs.get("tool_ids") or []), "tools": {}}

    class _SpyArbiter:
        def __init__(self, *args, **kwargs):
            order.append("fusion_arbiter")
            self.gemma_model = "gemma2:2b"
            self.sec_model = "fenkohq/foundation-sec-8b:latest"
            self.arbiter_model = "glm4:9b"

        def arbitrate_structured_json(self, *args, **kwargs):
            return {"data": kwargs.get("default_payload", {})}

    orig_mantis_init = mi.MantisIntegrator.__init__

    def _spy_mantis_init(self, *args, **kwargs):
        order.append("mantis_integrator")
        orig_mantis_init(self, *args, **kwargs)

    db = Database(str(tmp_path / "prov_order.db"), secret_key_path=str(tmp_path / "k" / "s.key"))
    try:
        with monkeypatch.context() as mp:
            mp.setattr(ToolProvisioner, "ensure_all", _fake_ensure_all)
            mp.setattr(mi, "FusionArbiter", _SpyArbiter)
            mp.setattr(mi.MantisIntegrator, "__init__", _spy_mantis_init)
            mp.setattr(ai_mod.AiscanIntegrator, "_find_aiscan_binary", lambda self: None)
            mp.setattr(ri_mod.RaptorIntegrator, "check_status", lambda self: {})
            mi.run_unified_all_scans(
                repo=str(repo_dir),
                db=db,
                reports_dir=str(tmp_path / "rep_online"),
                enable_preflight=False,
                enable_arxiv_detect=False,
                enable_last30days_skills=False,
                enable_pe_audit=False,
                enable_verification_inversion=False,
                quiet=True,
            )

        assert order[:3] == ["provisioner", "fusion_arbiter", "mantis_integrator"]
        assert len(prov_calls) == 1
        assert prov_calls[0]["include_models"] is True
        req_tools = set(prov_calls[0]["tool_ids"])
        for expected_tid in ("ollama", "ollama_models", "httpx", "katana", "nuclei", "rea_agents"):
            assert expected_tid in req_tools

        # 2. include_models=False excludes ollama & ollama_models from provisioning
        prov_calls.clear()
        with monkeypatch.context() as mp:
            mp.setattr(ToolProvisioner, "ensure_all", _fake_ensure_all)
            mp.setattr(mi, "FusionArbiter", _SpyArbiter)
            mp.setattr(ai_mod.AiscanIntegrator, "_find_aiscan_binary", lambda self: None)
            mp.setattr(ri_mod.RaptorIntegrator, "check_status", lambda self: {})
            mi.run_unified_all_scans(
                repo=str(repo_dir),
                db=db,
                reports_dir=str(tmp_path / "rep_nomodels"),
                include_models=False,
                enable_preflight=False,
                enable_arxiv_detect=False,
                enable_last30days_skills=False,
                enable_pe_audit=False,
                enable_verification_inversion=False,
                enable_rea=False,
                quiet=True,
            )
        assert len(prov_calls) == 1
        assert prov_calls[0]["include_models"] is False
        assert "ollama" not in prov_calls[0]["tool_ids"]
        assert "ollama_models" not in prov_calls[0]["tool_ids"]

        # 3. Offline / CI / PYTEST_CURRENT_TEST / approval_mode="deny" / auto_install_tools=False guards
        guard_cases = [
            ({"RFCHUNT_OFFLINE": "1"}, {}),
            ({"CI": "true"}, {}),
            ({"PYTEST_CURRENT_TEST": "tests/test_tool_provisioner.py::guard"}, {}),
            ({}, {"approval_mode": "deny", "include_models": True}),
            ({}, {"auto_install_tools": False, "include_models": True}),
        ]
        for env_overrides, extra_kw in guard_cases:
            prov_calls.clear()
            with monkeypatch.context() as mp:
                for ek, ev in env_overrides.items():
                    mp.setenv(ek, ev)
                mp.setattr(ToolProvisioner, "ensure_all", _fake_ensure_all)
                mp.setattr(mi, "FusionArbiter", _SpyArbiter)
                mp.setattr(ai_mod.AiscanIntegrator, "_find_aiscan_binary", lambda self: None)
                mp.setattr(ri_mod.RaptorIntegrator, "check_status", lambda self: {})
                mi.run_unified_all_scans(
                    repo=str(repo_dir),
                    db=db,
                    reports_dir=str(tmp_path / "rep_guard"),
                    enable_preflight=False,
                    enable_arxiv_detect=False,
                    enable_last30days_skills=False,
                    enable_pe_audit=False,
                    enable_verification_inversion=False,
                    enable_rea=False,
                    quiet=True,
                    **extra_kw,
                )
            assert len(prov_calls) == 0, f"Provisioner must be skipped under {env_overrides!r} / {extra_kw!r}"
    finally:
        db.close()
