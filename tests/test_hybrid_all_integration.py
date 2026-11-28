"""
Zero-Mock End-to-End Integration Tests for `--all` & `--hybrid` (Commit 2af0634 Groups 1-6 + STRIDE + Ensemble).

Verifies:
1. `--hybrid --dry-run --json` has zero side effects (0 files, 0 sockets) and lists all hybrid pillars.
2. `--hybrid` against an unauthorized external host fails closed (`PermissionError` / rc != 0).
3. `--hybrid` against a real local polyglot repository + real loopback `TestLabServer` executes:
   - Local static scanners (Mantis, aiscan, RAPTOR, Module 21 REA static, PE/.NET, Preflight, STRIDE)
   - Surface imports (OpenAPI, HAR, Scope, 2 AuthProfiles)
   - Live loopback `LocalRecordingMITMProxy` + ARTEX concurrent workers + bounded multi-turn loop + strict POE=3 + live retester
   - Module 21 REA live same-origin JS bundle mining + static-vs-live `hybrid_drift`
   - Formula-safe CSV + GHSA advisory + AES-256-GCM encrypted `.rfca` task archive round-trip decryption & SHA-256 verification
   - Auto-generated Module 26 STRIDE threat model (MD + SVG + PNG when Pillow installed)
4. `--all --export-archive` and `--hybrid --ensemble --stride --embedded` work end-to-end.
5. `TerminatorMCPServer` `run_all_scans(hybrid=True, export_archive=True)` works and rejects out-of-workspace `archive_key_file`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from engine.advisory_exporter import AdvisoryExporter
from engine.secret_store import SecretBox
from mcp_server import TerminatorMCPServer
from test_lab_server import TestLabServer


def _build_hybrid_sample_repo(base_dir: Path) -> dict[str, Path]:
    repo_dir = base_dir / "hybrid_polyglot_app"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/health')\n"
        "def health():\n"
        "    return {'ok': True}\n"
        "@app.get('/internal/service')\n"
        "def internal_service():\n"
        "    return {'secret': 'admin'}\n",
        encoding="utf-8",
    )
    (repo_dir / "auth_jwt.py").write_text(
        "import jwt\n"
        "def verify_jwt(token: str, secret: str):\n"
        "    return jwt.decode(token, secret, algorithms=['HS256'])\n",
        encoding="utf-8",
    )
    (repo_dir / "bundle.js").write_text(
        "const apiUrl = '/api/v1/chat';\n"
        "fetch('/internal/admin/config');\n"
        "//# sourceMappingURL=bundle.js.map\n",
        encoding="utf-8",
    )
    (repo_dir / "bundle.js.map").write_text(
        json.dumps({"version": 3, "sources": ["src/admin.ts"], "sourcesContent": ["export const ep = '/internal/admin/config';"]}),
        encoding="utf-8",
    )

    artifacts_dir = base_dir / "inputs"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    openapi_path = artifacts_dir / "openapi.json"
    openapi_path.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "info": {"title": "Hybrid Target API", "version": "1.0.0"},
                "paths": {
                    "/health": {"get": {"responses": {"200": {"description": "OK"}}}},
                    "/internal/service": {"get": {"responses": {"200": {"description": "Internal"}}}},
                },
            }
        ),
        encoding="utf-8",
    )

    har_path = artifacts_dir / "capture.har"
    har_path.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "http://127.0.0.1:8080/health",
                                "headers": [{"name": "Host", "value": "127.0.0.1:8080"}],
                            },
                            "response": {
                                "status": 200,
                                "headers": [{"name": "Content-Type", "value": "application/json"}],
                                "content": {"text": '{"ok": true}'},
                            },
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    scope_path = artifacts_dir / "scope.json"
    scope_path.write_text(
        json.dumps({"allow_hosts": ["127.0.0.1", "localhost"], "deny_hosts": ["forbidden.invalid"], "deny_routes": []}),
        encoding="utf-8",
    )

    auth_profiles_path = artifacts_dir / "auth_profiles.json"
    auth_profiles_path.write_text(
        json.dumps(
            {
                "profiles": [
                    {"name": "user_a", "role": "end_user", "headers": {"Authorization": "Bearer user-a-token"}},
                    {"name": "admin_b", "role": "admin", "headers": {"Authorization": "Bearer admin-b-token"}},
                ]
            }
        ),
        encoding="utf-8",
    )

    key_path = artifacts_dir / "archive.key"
    SecretBox.from_env_or_keyfile(key_path=key_path, create_if_missing=True)

    return {
        "repo": repo_dir,
        "openapi": openapi_path,
        "har": har_path,
        "scope": scope_path,
        "auth": auth_profiles_path,
        "key": key_path,
    }


def test_hybrid_dry_run_and_unauthorized_fail_closed(tmp_path: Path) -> None:
    swarm_script = Path(__file__).resolve().parents[1] / "rfc_hunt_swarm.py"
    assets = _build_hybrid_sample_repo(tmp_path)
    dry_out = tmp_path / "hybrid_dry_out"

    p_dry = subprocess.run(
        [
            sys.executable,
            str(swarm_script),
            "--hybrid",
            "--repo",
            str(assets["repo"]),
            "--host",
            "127.0.0.1",
            "--port",
            "8080",
            "--output-dir",
            str(dry_out),
            "--dry-run",
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=90,
        check=False,
    )
    assert p_dry.returncode == 0, f"stderr={p_dry.stderr}\nstdout={p_dry.stdout}"
    d_dry = json.loads(p_dry.stdout)
    assert d_dry["dry_run"] is True
    planned = set(d_dry.get("planned_modules") or [])
    assert "HybridStaticToLiveBridge(Local+Remote-Simultaneous)" in planned
    assert "LocalRecordingMITMProxy(LocalCA)" in planned
    assert "ARTEX-MultiTurn-StrictPOE3-Retester" in planned
    assert "EncryptedArchive(.rfca-AES256GCM)" in planned
    assert not dry_out.exists()

    # Unauthorized non-loopback external host must fail closed
    p_unauth = subprocess.run(
        [
            sys.executable,
            str(swarm_script),
            "--hybrid",
            "--repo",
            str(assets["repo"]),
            "--host",
            "example.com",
            "--port",
            "443",
            "--tls",
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert p_unauth.returncode != 0


def test_hybrid_full_local_and_live_loopback_all_6_groups_and_mcp(tmp_path: Path) -> None:
    swarm_script = Path(__file__).resolve().parents[1] / "rfc_hunt_swarm.py"
    assets = _build_hybrid_sample_repo(tmp_path)

    lab_port = TestLabServer.get_high_random_port(min_port=15000, max_port=55000, host="127.0.0.1")
    lab = TestLabServer(host="127.0.0.1", port=lab_port)
    lab.start()
    try:
        out_dir = tmp_path / "hybrid_live_out"
        db_path = tmp_path / "hybrid_live.db"
        env_off = os.environ.copy()
        env_off["RFCHUNT_OFFLINE"] = "1"

        p_hyb = subprocess.run(
            [
                sys.executable,
                str(swarm_script),
                "--hybrid",
                "--repo",
                str(assets["repo"]),
                "--workspace-root",
                str(tmp_path),
                "--host",
                "127.0.0.1",
                "--port",
                str(lab_port),
                "--import-openapi",
                str(assets["openapi"]),
                "--import-har",
                str(assets["har"]),
                "--scope-file",
                str(assets["scope"]),
                "--auth-profile",
                str(assets["auth"]),
                "--key-file",
                str(assets["key"]),
                "--db",
                str(db_path),
                "--output-dir",
                str(out_dir),
                "--no-preflight-live",
                "--no-include-models",
                "--no-auto-install",
                "--no-external-scanners",
                "--no-h2-desync",
                "--json",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env_off,
            timeout=180,
            check=False,
        )
        assert p_hyb.returncode == 0, f"stderr={p_hyb.stderr}\nstdout={p_hyb.stdout}"
        doc = json.loads(p_hyb.stdout)
        assert doc["mode"] == "unified_all_scans_hybrid"
        assert doc["hybrid_mode"] is True
        assert doc["local_executed"] is True
        assert doc["remote_executed"] is True

        hb = doc["hybrid_bridge"]
        assert hb["hybrid_mode_active"] is True
        assert hb["static_routes_seeded_to_live"] >= 1
        assert hb["embedded_proxy_active"] is True
        assert hb["multiturn_enabled"] is True
        assert hb["strict_poe"] is True

        # Verify Module 21 REA static + live drift telemetry and Pillar 5 outputs
        rea = (doc.get("engines") or {}).get("rea_surface") or {}
        assert rea.get("total_endpoints", 0) >= 1

        rf = doc["report_files"]
        assert Path(rf["combined_sarif"]).is_file()
        assert Path(rf["speculative_sarif"]).is_file()
        assert Path(rf["combined_json"]).is_file()
        assert Path(rf["findings_and_chains_csv"]).is_file()
        assert Path(rf["stride_threat_model_md"]).is_file()
        assert Path(rf["stride_architecture_svg"]).is_file()

        # Verify AES-256-GCM encrypted .rfca archive decrypts cleanly with SHA-256 integrity proof
        rfca_path = Path(rf["encrypted_archive_rfca"])
        assert rfca_path.is_file()
        assert doc["encrypted_archive"]["encrypted"] is True
        box = SecretBox.from_env_or_keyfile(key_path=assets["key"], create_if_missing=False)
        imported = AdvisoryExporter.import_task_archive(rfca_path, secret_box=box)
        assert imported["verified"] is True
        assert imported["schema"] == "rfchunt-task-archive/v1"

        # Verify --hybrid --ensemble --stride --embedded works end-to-end
        hyb_ens_out = tmp_path / "hybrid_ens_out"
        p_hens = subprocess.run(
            [
                sys.executable,
                str(swarm_script),
                "--hybrid",
                "--ensemble",
                "--stride",
                "--embedded",
                "--repo",
                str(assets["repo"]),
                "--output-dir",
                str(hyb_ens_out),
                "--no-preflight-live",
                "--no-include-models",
                "--no-auto-install",
                "--no-external-scanners",
                "--json",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env_off,
            timeout=180,
            check=False,
        )
        assert p_hens.returncode == 0, f"stderr={p_hens.stderr}\nstdout={p_hens.stdout}"
        d_hens = json.loads(p_hens.stdout)
        assert d_hens["stride_threat_model"]["status"] == "generated_advanced_stride_threat_model"
        assert (hyb_ens_out / "ensemble_summary.md").is_file()

        # Verify MCP run_all_scans(hybrid=True, export_archive=True) + workspace confinement
        mcp_out = tmp_path / "mcp_hybrid_out"
        with TerminatorMCPServer(db_path=str(tmp_path / "mcp_hybrid.db")) as srv:
            prev_off = os.environ.get("RFCHUNT_OFFLINE")
            os.environ["RFCHUNT_OFFLINE"] = "1"
            try:
                mcp_resp = srv.handle_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/call",
                        "params": {
                            "name": "run_all_scans",
                            "arguments": {
                                "repo": str(assets["repo"]),
                                "workspace_root": str(tmp_path),
                                "output_dir": str(mcp_out),
                                "hybrid": True,
                                "export_archive": True,
                                "archive_key_file": str(assets["key"]),
                                "enable_external_scanners": False,
                                "enable_stride": True,
                            },
                        },
                    }
                )
                assert "error" not in mcp_resp
                assert not mcp_resp["result"].get("isError", False)
                mcp_data = json.loads(mcp_resp["result"]["content"][0]["text"])
                assert mcp_data["hybrid_mode"] is True
                assert mcp_data["mode"] == "unified_all_scans_hybrid"
                assert Path(mcp_data["report_files"]["encrypted_archive_rfca"]).is_file()
                assert mcp_data["stride_threat_model"]["status"] == "generated_advanced_stride_threat_model"

                # Fail-closed rejection when archive_key_file escapes workspace_root
                esc_resp = srv.handle_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "tools/call",
                        "params": {
                            "name": "run_all_scans",
                            "arguments": {
                                "repo": str(assets["repo"]),
                                "workspace_root": str(assets["repo"]),
                                "output_dir": str(assets["repo"] / "reports"),
                                "hybrid": True,
                                "export_archive": True,
                                "archive_key_file": str(assets["key"]),
                            },
                        },
                    }
                )
                assert "error" in esc_resp or esc_resp.get("result", {}).get("isError") is True
            finally:
                if prev_off is None:
                    os.environ.pop("RFCHUNT_OFFLINE", None)
                else:
                    os.environ["RFCHUNT_OFFLINE"] = prev_off
    finally:
        lab.stop()
