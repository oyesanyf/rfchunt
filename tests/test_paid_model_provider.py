"""
Real Loopback-HTTP & Configuration Tests for `.env.local` Paid-Model Routing
============================================================================
Verifies that whenever `.env.local` defines paid/enterprise LLM credentials
(Anthropic, OpenAI / OpenAI-compatible gateway, Azure OpenAI, Google Gemini,
OpenRouter, or heterogeneous multi-provider panels):
  1. RFCHunt automatically uses those paid models across `ModelFusionAdapter`,
     `FusionArbiter`, `ToolProvisioner`, `RaptorIntegrator`, `TieredModelRouter`,
     `MantisIntegrator` (`--all`), and `--dry-run`.
  2. ZERO Ollama probes, auto-starts, or model pulls execute when `.env.local`
     paid models are active.
  3. When `.env.local` is absent or has no paid credentials (or `--force-ollama`
     is set), RFCHunt preserves its default zero-cost local Ollama backend even
     if ambient shell environment variables exist.
  4. Raw API keys NEVER appear in serialized config summaries, dry-run output,
     URL query strings, or logged error messages.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Tuple
from unittest.mock import patch

import pytest

from engine.paid_model_provider import (
    PaidModelClient,
    load_paid_model_config,
    mask_api_key,
    parse_env_local_file,
)
from engine.raptor_integrator import RaptorIntegrator
from engine.swarm_dispatcher import DispatchEscalationConfig, TieredModelRouter
from engine.tool_provisioner import ToolProvisioner
from fusion_engine import FusionArbiter
from model_adapter import ModelFusionAdapter
from ollama_manager import OllamaLifecycleManager
import rfc_hunt_swarm


class _LoopbackPaidAPIServer:
    """Real multi-protocol loopback HTTP server speaking OpenAI, Anthropic, Azure & Gemini wire formats."""

    def __init__(self) -> None:
        self.received: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw_body = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    parsed = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    parsed = {}

                rec = {
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": parsed,
                }
                with parent._lock:
                    parent.received.append(rec)

                probe_json = json.dumps(
                    {
                        "rationale": f"Paid model probe via {self.path}",
                        "raw_request": "POST / HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n$PAYLOAD",
                        "is_clean": False,
                    }
                )

                if self.path.endswith("/v1/messages"):
                    resp_obj = {
                        "id": "msg_test_01",
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "text", "text": probe_json}],
                    }
                elif ":generateContent" in self.path:
                    resp_obj = {
                        "candidates": [
                            {
                                "content": {
                                    "role": "model",
                                    "parts": [{"text": probe_json}],
                                }
                            }
                        ]
                    }
                else:
                    resp_obj = {
                        "id": "chatcmpl_test_01",
                        "object": "chat.completion",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": probe_json},
                                "finish_reason": "stop",
                            }
                        ],
                    }

                data = json.dumps(resp_obj).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "_LoopbackPaidAPIServer":
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._server.shutdown()
        self._server.server_close()


def _fail_if_ollama_called(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("Ollama must NEVER be probed, started, or pulled when .env.local configures paid models!")


def test_env_local_parser_and_placeholder_filtering(tmp_path: Path) -> None:
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "\n".join(
            [
                "# Comment line",
                "export OPENAI_API_KEY='unit-test-paid-token-9876543210' # inline comment",
                'OPENAI_MODEL="gpt-4o-mini"',
                "ANTHROPIC_API_KEY=REPLACE_ME",  # placeholder must be ignored
                "GEMINI_API_KEY=<YOUR_KEY>",  # placeholder must be ignored
                "RFCHUNT_PAID_TIMEOUT=45",
            ]
        ),
        encoding="utf-8",
    )

    parsed = parse_env_local_file(env_file)
    assert parsed["OPENAI_API_KEY"] == "unit-test-paid-token-9876543210"
    assert parsed["OPENAI_MODEL"] == "gpt-4o-mini"

    cfg = load_paid_model_config(env_local_path=env_file)
    assert cfg.enabled is True
    assert cfg.ollama_bypassed is True
    assert cfg.provider == "openai"
    assert cfg.primary_model == "gpt-4o-mini"
    assert cfg.timeout_sec == 45.0
    assert "anthropic" not in cfg.providers
    assert "gemini" not in cfg.providers

    safe = cfg.to_safe_dict()
    serialized = json.dumps(safe)
    assert "unit-test-paid-token-9876543210" not in serialized
    assert safe["mode"] == "paid_api"
    assert safe["using_ollama"] is False
    assert safe["ollama_bypassed"] is True
    assert mask_api_key("unit-test-paid-token-9876543210").startswith("unit...")


def test_no_env_local_preserves_local_ollama_even_with_ambient_shell_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RFCHUNT_ENV_LOCAL", str(tmp_path / "nonexistent.env.local"))
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-shell-token-should-not-override-ollama")
    monkeypatch.setenv("GEMINI_API_KEY", "ambient-gemini-token-should-not-override-ollama")
    monkeypatch.delenv("RFCHUNT_USE_PAID_MODELS", raising=False)
    monkeypatch.delenv("RFCHUNT_FORCE_OLLAMA", raising=False)

    cfg = load_paid_model_config()
    assert cfg.enabled is False
    assert cfg.using_ollama if hasattr(cfg, "using_ollama") else (not cfg.ollama_bypassed)
    assert cfg.provider == "ollama"

    with patch.object(ModelFusionAdapter, "_fetch_available_tags", return_value=["gemma2:2b"]):
        adapter = ModelFusionAdapter(use_fusion=False)
        try:
            assert adapter.using_ollama is True
            assert adapter.backend_mode == "ollama"
        finally:
            adapter.close()


def test_model_adapter_and_fusion_arbiter_use_paid_models_and_bypass_ollama(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _LoopbackPaidAPIServer() as srv:
        env_file = tmp_path / ".env.local"
        env_file.write_text(
            "\n".join(
                [
                    "ANTHROPIC_API_KEY=loopback-token-alpha-111111111111",
                    "ANTHROPIC_MODEL=claude-sonnet-4-20250514",
                    f"ANTHROPIC_BASE_URL={srv.base_url}",
                    "OPENAI_API_KEY=loopback-token-beta-222222222222",
                    "OPENAI_MODEL=gpt-4o",
                    f"OPENAI_BASE_URL={srv.base_url}/v1",
                    "GEMINI_API_KEY=loopback-token-gamma-333333333333",
                    "GEMINI_MODEL=gemini-2.5-pro",
                    f"GEMINI_BASE_URL={srv.base_url}",
                    "RFCHUNT_PAID_MODELS=claude-sonnet-4-20250514,gpt-4o,gemini-2.5-pro",
                ]
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("RFCHUNT_ENV_LOCAL", str(env_file))
        monkeypatch.delenv("RFCHUNT_FORCE_OLLAMA", raising=False)

        with (
            patch.object(OllamaLifecycleManager, "probe_ollama", side_effect=_fail_if_ollama_called),
            patch.object(OllamaLifecycleManager, "ensure_ollama_ready", side_effect=_fail_if_ollama_called),
            patch.object(OllamaLifecycleManager, "ensure_panel_models_installed", side_effect=_fail_if_ollama_called),
            patch.object(OllamaLifecycleManager, "ensure_model_installed", side_effect=_fail_if_ollama_called),
            patch.object(OllamaLifecycleManager, "trigger_background_pull", side_effect=_fail_if_ollama_called),
        ):
            # 1. ModelFusionAdapter executes heterogeneous 3-provider paid panel fusion
            with ModelFusionAdapter(use_fusion=True) as adapter:
                assert adapter.using_ollama is False
                assert adapter.backend_mode == "paid_api"
                assert adapter.active_model == "claude-sonnet-4-20250514"
                assert adapter.available_tags == ["claude-sonnet-4-20250514", "gpt-4o", "gemini-2.5-pro"]
                probes = adapter.generate_json(
                    "Protocol researcher system prompt",
                    "Synthesize framing probe",
                    schema_hint='{"rationale":"...","raw_request":"...","is_clean":false}',
                    num_predict=128,
                )
                assert len(probes) == 3
                assert {p["fused_model"] for p in probes} == {
                    "claude-sonnet-4-20250514",
                    "gpt-4o",
                    "gemini-2.5-pro",
                }

            # Verify all 3 real wire protocols fired cleanly and Gemini key stayed in header (not URL query)
            paths = [r["path"] for r in srv.received]
            assert "/v1/messages" in paths
            assert "/v1/chat/completions" in paths
            gem_reqs = [r for r in srv.received if ":generateContent" in r["path"]]
            assert len(gem_reqs) == 1
            assert "loopback-token-gamma-333333333333" not in gem_reqs[0]["path"]
            assert gem_reqs[0]["headers"].get("x-goog-api-key") == "loopback-token-gamma-333333333333"

            # 2. FusionArbiter assigns all 3 specialist/arbiter roles to paid models and runs arbitration
            with FusionArbiter(quiet=True) as arbiter:
                assert arbiter.using_ollama is False
                assert arbiter.backend_mode == "paid_api"
                assert arbiter.gemma_model == "claude-sonnet-4-20250514"
                assert arbiter.sec_model == "gpt-4o"
                assert arbiter.arbiter_model == "gemini-2.5-pro"

                arb_res = arbiter.arbitrate_structured_json(
                    task_name="Paid API Arbitration Test",
                    system_prompt="Return strict JSON.",
                    user_prompt="Analyze framing boundary.",
                    default_payload={"fallback": True},
                    num_predict=128,
                )
                assert arb_res["status"] == "fused"
                assert isinstance(arb_res["data"], dict)
                assert "raw_request" in arb_res["data"]


def test_azure_openai_and_openrouter_loopback_wire_protocols(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _LoopbackPaidAPIServer() as srv:
        env_azure = tmp_path / "azure.env.local"
        env_azure.write_text(
            "\n".join(
                [
                    "AZURE_OPENAI_API_KEY=loopback-azure-token-999999999999",
                    f"AZURE_OPENAI_ENDPOINT={srv.base_url}",
                    "AZURE_OPENAI_DEPLOYMENT=corp-gpt4o-sec",
                    "AZURE_OPENAI_API_VERSION=2024-10-21",
                ]
            ),
            encoding="utf-8",
        )
        cfg_az = load_paid_model_config(env_local_path=env_azure)
        assert cfg_az.enabled is True
        assert cfg_az.provider == "azure_openai"
        with PaidModelClient(cfg_az) as client:
            out = client.generate(system_prompt="sys", user_prompt="usr", max_tokens=128)
            assert "raw_request" in out
        az_req = srv.received[-1]
        assert "/openai/deployments/corp-gpt4o-sec/chat/completions?api-version=2024-10-21" == az_req["path"]
        assert az_req["headers"].get("api-key") == "loopback-azure-token-999999999999"

        env_or = tmp_path / "openrouter.env.local"
        env_or.write_text(
            "\n".join(
                [
                    "OPENROUTER_API_KEY=loopback-openrouter-token-888888888888",
                    "OPENROUTER_MODEL=anthropic/claude-3.7-sonnet",
                    f"OPENROUTER_BASE_URL={srv.base_url}/api/v1",
                ]
            ),
            encoding="utf-8",
        )
        cfg_or = load_paid_model_config(env_local_path=env_or)
        assert cfg_or.enabled is True
        assert cfg_or.provider == "openrouter"
        with PaidModelClient(cfg_or) as client:
            out_or = client.generate(system_prompt="sys", user_prompt="usr", max_tokens=128)
            assert "raw_request" in out_or
        or_req = srv.received[-1]
        assert or_req["path"] == "/api/v1/chat/completions"
        assert or_req["headers"].get("authorization") == "Bearer loopback-openrouter-token-888888888888"


def test_provisioner_raptor_router_and_cli_dry_run_bypass_ollama_with_env_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "\n".join(
            [
                "OPENAI_API_KEY=loopback-enterprise-token-777777777777",
                "OPENAI_MODEL=gpt-4.1",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RFCHUNT_ENV_LOCAL", str(env_file))
    monkeypatch.delenv("RFCHUNT_FORCE_OLLAMA", raising=False)

    with (
        patch.object(OllamaLifecycleManager, "probe_ollama", side_effect=_fail_if_ollama_called),
        patch.object(OllamaLifecycleManager, "ensure_ollama_ready", side_effect=_fail_if_ollama_called),
        patch.object(OllamaLifecycleManager, "ensure_panel_models_installed", side_effect=_fail_if_ollama_called),
    ):
        # 1. ToolProvisioner marks ollama & ollama_models as bypassed (0 Ollama probes/installs)
        prov = ToolProvisioner()
        st_oll = prov.check_tool_status("ollama", allow_probes=True)
        st_mod = prov.check_tool_status("ollama_models", allow_probes=True)
        assert st_oll.installed is True and st_oll.method == "bypassed_paid_env_local"
        assert st_mod.installed is True and st_mod.method == "bypassed_paid_env_local"

        # 2. RaptorIntegrator resolves paid model and skips Ollama probe
        raptor = RaptorIntegrator(raptor_root=tmp_path / "raptor_stub")
        assert raptor.resolve_runtime_model() == "openai/gpt-4.1"

        # 3. TieredModelRouter routes candidates to paid provider instead of ollama
        router = TieredModelRouter(config=DispatchEscalationConfig(enabled=True))
        plan = router.rank_and_route(
            [
                {"candidate_id": "c1", "severity": "HIGH", "poe_level": 2},
                {"candidate_id": "c2", "severity": "LOW", "poe_level": 0},
            ],
            free_ram_gb=16.0,
        )
        assert all(d.provider == "openai" and d.provider != "ollama" for d in plan.decisions)

        # 4. Universal CLI `--dry-run --json` reports paid backend & masks secret key
        rfc_hunt_swarm.main_swarm(
            [
                "--all",
                "--repo",
                str(tmp_path),
                "--env-local",
                str(env_file),
                "--dry-run",
                "--json",
            ]
        )
        out = capsys.readouterr().out
        assert "loopback-enterprise-token-777777777777" not in out
        parsed_plan = json.loads(out)
        assert parsed_plan["llm_backend"]["mode"] == "paid_api"
        assert parsed_plan["llm_backend"]["provider"] == "openai"
        assert parsed_plan["llm_backend"]["ollama_bypassed"] is True

    # 5. `--force-ollama` overrides `.env.local` back to Ollama cleanly
    cfg_forced = load_paid_model_config(env_local_path=env_file, force_ollama=True)
    assert cfg_forced.enabled is False
    assert cfg_forced.reason == "forced_ollama"


def test_unified_all_scans_records_paid_backend_and_skips_ollama(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from engine.mantis_integrator import run_unified_all_scans

    sample_repo = tmp_path / "repo"
    sample_repo.mkdir()
    (sample_repo / "app.py").write_text("def hello() -> str:\n    return 'ok'\n", encoding="utf-8")

    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "ANTHROPIC_API_KEY=loopback-anthropic-token-1234567890\n"
        "ANTHROPIC_MODEL=claude-sonnet-4-20250514\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("RFCHUNT_ENV_LOCAL", str(env_file))
    monkeypatch.delenv("RFCHUNT_FORCE_OLLAMA", raising=False)

    out_dir = tmp_path / "reports"
    with (
        patch.object(OllamaLifecycleManager, "probe_ollama", side_effect=_fail_if_ollama_called),
        patch.object(OllamaLifecycleManager, "ensure_ollama_ready", side_effect=_fail_if_ollama_called),
        patch.object(OllamaLifecycleManager, "ensure_panel_models_installed", side_effect=_fail_if_ollama_called),
    ):
        summary = run_unified_all_scans(
            repo=str(sample_repo),
            reports_dir=str(out_dir),
            depth=10,
            include_models=True,
            quiet=True,
            enable_external_scanners=False,
            enable_rea=False,
            auto_install_tools=False,
            enable_preflight=False,
        )

    assert summary["llm_backend"]["mode"] == "paid_api"
    assert summary["llm_backend"]["provider"] == "anthropic"
    assert summary["llm_backend"]["using_ollama"] is False
    assert summary["llm_backend"]["ollama_bypassed"] is True
    assert "claude-sonnet-4-20250514" in summary["fusion_models"]
    serialized = json.dumps(summary)
    assert "loopback-anthropic-token-1234567890" not in serialized

