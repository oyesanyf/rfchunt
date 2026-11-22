"""
Tests for AIxCC Upgrade #2:
- Whole-Repo Multi-Language Call-Graph & Taint Slicer (`engine/call_graph_slicer.py`)
  across Python, TypeScript/JS, Rust, Go, and optional CodeQL SARIF/BQRS integration
- Tiered Model Escalation in `swarm_dispatch.yaml` & `engine/swarm_dispatcher.py`
  (`DispatchEscalationConfig`, runtime free RAM/VRAM sizing, `TieredModelRouter`)
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine.call_graph_slicer import (
    CallGraphSlicer,
    TaintSlice,
    detect_codeql,
    parse_codeql_sarif_slices,
    slice_repository,
)
from engine.swarm_dispatcher import (
    DispatchEscalationConfig,
    ModelRoutingDecision,
    RuntimeMemorySnapshot,
    TieredModelRouter,
    load_dispatch_config,
    model_fits_free_memory,
    probe_runtime_free_memory,
    size_fast_local_model_for_free_memory,
    size_model_for_free_memory,
)


# =============================================================================
# 1. Multi-File Call-Graph & Taint Slicing (Python, TypeScript/JS, Rust, Go)
# =============================================================================


def test_python_multifile_entry_middleware_sanitizer_sink_slice(tmp_path: Path) -> None:
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "__init__.py").write_text("", encoding="utf-8")

    (app_dir / "routes.py").write_text(
        "\n".join(
            [
                "from flask import request",
                "from .middleware import dispatch_job",
                "",
                "@app.post('/api/exec')",
                "def handle_exec():",
                "    raw_cmd = request.json.get('cmd', '')",
                "    return dispatch_job(raw_cmd)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (app_dir / "middleware.py").write_text(
        "\n".join(
            [
                "from .sanitizer import sanitize_cmd",
                "from .executor import run_shell_command",
                "",
                "def dispatch_job(user_cmd: str):",
                "    cleaned = sanitize_cmd(user_cmd)",
                "    return run_shell_command(cleaned)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (app_dir / "sanitizer.py").write_text(
        "\n".join(
            [
                "def sanitize_cmd(raw: str) -> str:",
                "    return raw.replace(';', '').strip()",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (app_dir / "executor.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "",
                "def run_shell_command(cmd: str):",
                "    return subprocess.run(cmd, shell=True, capture_output=True)",
                "",
            ]
        ),
        encoding="utf-8",
    )

    report = slice_repository(tmp_path)
    assert report.files_scanned >= 4
    assert report.languages_detected["python"] >= 4
    assert report.parser_backends["python"] in ("python_ast", "tree_sitter")
    assert report.cross_file_slices_count >= 1

    cmd_slices = [s for s in report.slices if s.vulnerability_class == "command_injection" and s.is_cross_file]
    assert len(cmd_slices) >= 1
    sl = cmd_slices[0]

    assert sl.cwe == "CWE-78"
    assert sl.severity == "CRITICAL"
    assert sl.sanitizer_status == "weak_sanitizer"
    assert sl.poe_hint == 1
    assert set(sl.files_involved) == {
        "app/routes.py",
        "app/middleware.py",
        "app/sanitizer.py",
        "app/executor.py",
    }
    roles = [step.role for step in sl.steps]
    assert roles == ["entry_point", "middleware", "sanitizer", "sink"]
    assert [step.symbol_name for step in sl.steps] == [
        "handle_exec",
        "dispatch_job",
        "sanitize_cmd",
        "run_shell_command",
    ]
    assert sl.sink_file == "app/executor.py"
    assert sl.sink_line == 4
    assert len(sl.sanitizers) == 1
    assert sl.sanitizers[0]["strength"] == "weak"

    # Prompt-ready context block is focused, concise, and contains all 4 files
    assert sl.prompt_context
    assert len(sl.prompt_context) <= 4000
    for fpath in ("app/routes.py", "app/middleware.py", "app/sanitizer.py", "app/executor.py"):
        assert fpath in sl.prompt_context
    assert "weak_sanitizer" in sl.prompt_context
    assert "subprocess.run" in sl.prompt_context


def test_python_strong_sanitizer_marks_slice_sanitized(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from sanitizer import quote_arg\nfrom runner import run_cmd\n\n"
        "@app.get('/ping')\n"
        "def ping_handler():\n"
        "    host = request.args.get('host')\n"
        "    safe_host = quote_arg(host)\n"
        "    return run_cmd(safe_host)\n",
        encoding="utf-8",
    )
    (tmp_path / "sanitizer.py").write_text(
        "import shlex\n\ndef quote_arg(val: str) -> str:\n    return shlex.quote(val)\n",
        encoding="utf-8",
    )
    (tmp_path / "runner.py").write_text(
        "import os\n\ndef run_cmd(arg: str):\n    return os.system('ping -c 1 ' + arg)\n",
        encoding="utf-8",
    )

    report = slice_repository(tmp_path)
    slices = [s for s in report.slices if s.vulnerability_class == "command_injection" and s.is_cross_file]
    assert len(slices) >= 1
    assert slices[0].sanitizer_status == "sanitized"
    assert slices[0].poe_hint == 0
    assert any(san["strength"] == "strong" for san in slices[0].sanitizers)


def test_typescript_multifile_middleware_pipeline_slice(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()

    (src / "routes.ts").write_text(
        "\n".join(
            [
                "import express from 'express';",
                "import { authMiddleware } from './middleware';",
                "import { sanitizeCommand } from './sanitizer';",
                "import { executeTask } from './executor';",
                "",
                "const app = express();",
                "app.post('/api/task', authMiddleware, sanitizeCommand, executeTask);",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (src / "middleware.ts").write_text(
        "\n".join(
            [
                "export function authMiddleware(req: any, res: any, next: any) {",
                "  const token = req.headers['authorization'];",
                "  if (!token) { return res.status(401).end(); }",
                "  return next();",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (src / "sanitizer.ts").write_text(
        "\n".join(
            [
                "export function sanitizeCommand(req: any, res: any, next: any) {",
                "  req.body.cmd = String(req.body.cmd || '').replace(';', '');",
                "  return next();",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (src / "executor.ts").write_text(
        "\n".join(
            [
                "import child_process from 'child_process';",
                "",
                "export function executeTask(req: any, res: any) {",
                "  const cmd = req.body.cmd;",
                "  return child_process.exec(cmd, () => res.send('ok'));",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    report = slice_repository(tmp_path)
    assert report.languages_detected["typescript"] == 4
    assert report.parser_backends["typescript"] in ("structural_ast", "tree_sitter")

    ts_slices = [s for s in report.slices if s.vulnerability_class == "command_injection" and s.is_cross_file]
    assert len(ts_slices) >= 1
    sl = ts_slices[0]

    assert sl.cwe == "CWE-78"
    assert sl.sanitizer_status == "weak_sanitizer"
    assert set(sl.files_involved) == {
        "src/routes.ts",
        "src/middleware.ts",
        "src/sanitizer.ts",
        "src/executor.ts",
    }
    assert [step.role for step in sl.steps] == ["entry_point", "middleware", "sanitizer", "sink"]
    assert sl.steps[1].symbol_name == "authMiddleware"
    assert sl.steps[2].symbol_name == "sanitizeCommand"
    assert sl.steps[3].symbol_name == "executeTask"
    assert sl.sink_file == "src/executor.ts"
    assert sl.sink_line == 5
    assert "src/sanitizer.ts" in sl.prompt_context
    assert "child_process.exec" in sl.prompt_context


def test_javascript_commonjs_multifile_path_traversal_slice(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const { validateMiddleware } = require('./middleware');\n"
        "function handleDownload(req, res) {\n"
        "  const fileParam = req.query.file;\n"
        "  return validateMiddleware(fileParam);\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "middleware.js").write_text(
        "const { cleanPath } = require('./sanitizer');\n"
        "const { readDoc } = require('./storage');\n"
        "function validateMiddleware(rawPath) {\n"
        "  const p = cleanPath(rawPath);\n"
        "  return readDoc(p);\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "sanitizer.js").write_text(
        "function cleanPath(p) {\n"
        "  return p.replace('..', '');\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "storage.js").write_text(
        "const fs = require('fs');\n"
        "function readDoc(filePath) {\n"
        "  return fs.readFileSync('/srv/docs/' + filePath, 'utf8');\n"
        "}\n",
        encoding="utf-8",
    )

    report = slice_repository(tmp_path)
    pt_slices = [s for s in report.slices if s.vulnerability_class == "path_traversal" and s.is_cross_file]
    assert len(pt_slices) >= 1
    sl = pt_slices[0]
    assert sl.cwe == "CWE-22"
    assert sl.sanitizer_status == "weak_sanitizer"
    assert set(sl.files_involved) == {"server.js", "middleware.js", "sanitizer.js", "storage.js"}
    assert [step.role for step in sl.steps] == ["entry_point", "middleware", "sanitizer", "sink"]


def test_rust_multifile_entry_middleware_sanitizer_sink_slice(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()

    (src / "routes.rs").write_text(
        "\n".join(
            [
                "use crate::middleware::auth_dispatch;",
                "",
                "#[post(\"/api/run\")]",
                "pub async fn handle_run(req: HttpRequest, q: web::Query<RunParams>) -> String {",
                "    auth_dispatch(&q.cmd)",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (src / "middleware.rs").write_text(
        "\n".join(
            [
                "use crate::sanitizer::clean_shell_arg;",
                "use crate::executor::exec_shell;",
                "",
                "pub fn auth_dispatch(raw: &str) -> String {",
                "    let cleaned = clean_shell_arg(raw);",
                "    exec_shell(&cleaned)",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (src / "sanitizer.rs").write_text(
        "\n".join(
            [
                "pub fn clean_shell_arg(input: &str) -> String {",
                "    input.replace(\";\", \"\").trim().to_string()",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (src / "executor.rs").write_text(
        "\n".join(
            [
                "use std::process::Command;",
                "",
                "pub fn exec_shell(cmd: &str) -> String {",
                "    let _ = Command::new(\"sh\").arg(\"-c\").arg(cmd).output();",
                "    String::from(\"done\")",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    report = slice_repository(tmp_path)
    assert report.languages_detected["rust"] == 4
    assert report.parser_backends["rust"] in ("structural_ast", "tree_sitter")

    rs_slices = [s for s in report.slices if s.vulnerability_class == "command_injection" and s.is_cross_file]
    assert len(rs_slices) >= 1
    sl = rs_slices[0]

    assert sl.cwe == "CWE-78"
    assert sl.sanitizer_status == "weak_sanitizer"
    assert set(sl.files_involved) == {
        "src/routes.rs",
        "src/middleware.rs",
        "src/sanitizer.rs",
        "src/executor.rs",
    }
    assert [step.role for step in sl.steps] == ["entry_point", "middleware", "sanitizer", "sink"]
    assert [step.symbol_name for step in sl.steps] == [
        "handle_run",
        "auth_dispatch",
        "clean_shell_arg",
        "exec_shell",
    ]
    assert sl.sink_file == "src/executor.rs"
    assert sl.sink_line == 4
    assert "Command::new" in sl.prompt_context


# =============================================================================
# 2. Optional CodeQL CLI Detection, Skip Behavior, SARIF & BQRS Path Extraction
# =============================================================================


def test_codeql_detection_clean_skip_when_absent(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    det = detect_codeql(codeql_bin="codeql_nonexistent_binary_for_test", enabled=True)
    assert det.available is False
    assert det.binary_path is None
    assert det.status == "unavailable"
    assert det.executed is False

    report = slice_repository(tmp_path, enable_codeql=True, codeql_bin="codeql_nonexistent_binary_for_test")
    assert report.codeql.available is False
    assert report.codeql.status == "unavailable"
    assert report.codeql.extracted_slices == 0


def test_codeql_sarif_codeflow_extraction_and_path_escape_containment(tmp_path: Path) -> None:
    (tmp_path / "entry.py").write_text("def endpoint(req):\n    return req.args['x']\n", encoding="utf-8")
    (tmp_path / "sink.py").write_text("import os\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")

    sarif_file = tmp_path / "results.sarif"
    sarif_doc = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "py/command-line-injection",
                        "message": {"text": "User input reaches os.system"},
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "message": {"text": "endpoint source"},
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "entry.py"},
                                                        "region": {"startLine": 2, "endLine": 2},
                                                    },
                                                }
                                            },
                                            {
                                                "location": {
                                                    "message": {"text": "run sink"},
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "sink.py"},
                                                        "region": {"startLine": 3, "endLine": 3},
                                                    },
                                                }
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ],
    }
    sarif_file.write_text(json.dumps(sarif_doc), encoding="utf-8")

    slices = parse_codeql_sarif_slices(sarif_file, tmp_path)
    assert len(slices) == 1
    sl = slices[0]
    assert sl.source_backend == "codeql"
    assert sl.vulnerability_class == "command_injection"
    assert sl.cwe == "CWE-78"
    assert sl.is_cross_file is True
    assert sl.files_involved == ["entry.py", "sink.py"]
    assert "os.system" in sl.prompt_context

    # Merged cleanly through CallGraphSlicer
    report = slice_repository(
        tmp_path,
        enable_codeql=False,
        codeql_sarif_paths=[sarif_file],
    )
    assert report.codeql.extracted_slices == 1
    assert any(s.source_backend == "codeql" for s in report.slices)


def test_codeql_cli_detection_and_bqrs_decode_uses_shell_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import engine.call_graph_slicer as cgs

    (tmp_path / "entry.py").write_text("def handle(req):\n    return req.args['q']\n", encoding="utf-8")
    (tmp_path / "sink.py").write_text("import os\ndef exec_it(c):\n    os.system(c)\n", encoding="utf-8")
    fake_bqrs = tmp_path / "alerts.bqrs"
    fake_bqrs.write_bytes(b"BQRS")

    seen_calls: List[Dict[str, Any]] = []

    def _fake_run(cmd: List[str], **kwargs: Any) -> SimpleNamespace:
        seen_calls.append({"cmd": list(cmd), "shell": kwargs.get("shell")})
        if "version" in cmd:
            return SimpleNamespace(returncode=0, stdout="2.18.4\n", stderr="")
        if "bqrs" in cmd:
            payload = {
                "#select": {
                    "tuples": [
                        [
                            {"label": "handle", "url": {"uri": "entry.py", "startLine": 1, "endLine": 2}},
                            {"label": "exec_it", "url": {"uri": "sink.py", "startLine": 3, "endLine": 3}},
                            "command-line-injection flow",
                        ]
                    ]
                }
            }
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unexpected")

    monkeypatch.setattr(cgs.shutil, "which", lambda name: "/usr/local/bin/codeql" if "codeql" in str(name) else None)
    monkeypatch.setattr(cgs.subprocess, "run", _fake_run)

    report = slice_repository(tmp_path, enable_codeql=True, codeql_bqrs_paths=[fake_bqrs])
    assert report.codeql.available is True
    assert report.codeql.version == "2.18.4"
    assert report.codeql.status == "executed"
    assert report.codeql.extracted_slices == 1
    assert all(c["shell"] is False for c in seen_calls)
    assert any(s.source_backend == "codeql" and s.is_cross_file for s in report.slices)


# =============================================================================
# 3. `swarm_dispatch.yaml` Escalation Schema Validation
# =============================================================================


def _base_valid_dispatch(ws_root: Path) -> Dict[str, Any]:
    return {
        "version": 1,
        "runtime": {"execution": "local", "offline": True},
        "workers": {"backend": "all", "concurrency": 2, "use_fusion": False},
        "workspace": {"root": str(ws_root), "per_target_isolation": True},
        "targets": [
            {
                "name": "local_lab",
                "host": "127.0.0.1",
                "port": 8080,
                "tls": False,
                "authorized": True,
                "modes": ["all"],
                "rfcs": ["9112"],
            }
        ],
    }


def test_reference_swarm_dispatch_yaml_loads_local_only_escalation_defaults() -> None:
    cfg = load_dispatch_config(REPO_ROOT / "swarm_dispatch.yaml")
    assert cfg.escalation is cfg.workers.escalation
    assert cfg.escalation.enabled is True
    assert cfg.escalation.max_escalation_fraction == pytest.approx(0.05)
    assert cfg.escalation.min_poe_for_escalation == 1
    assert cfg.escalation.frontier_api_opt_in is False
    assert cfg.escalation.frontier_provider is None
    assert cfg.escalation.frontier_model is None
    assert cfg.escalation.frontier_api_env_var is None


def test_top_level_and_opt_in_frontier_escalation_yaml_validates(tmp_path: Path) -> None:
    doc = _base_valid_dispatch(tmp_path / "ws")
    doc["escalation"] = {
        "enabled": True,
        "fast_local_model": "qwen2.5:7b",
        "max_escalation_fraction": 0.03,
        "min_poe_for_escalation": 2,
        "strong_local_model": "qwen2.5:14b",
        "frontier_api_opt_in": True,
        "frontier_provider": "anthropic",
        "frontier_model": "claude-sonnet-4-20250514",
        "frontier_api_env_var": "ANTHROPIC_API_KEY",
    }
    cfg_path = tmp_path / "opt_in.yaml"
    cfg_path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    cfg = load_dispatch_config(cfg_path)
    assert cfg.escalation is cfg.workers.escalation
    assert cfg.escalation.frontier_api_opt_in is True
    assert cfg.escalation.frontier_provider == "anthropic"
    assert cfg.escalation.frontier_model == "claude-sonnet-4-20250514"
    assert cfg.escalation.frontier_api_env_var == "ANTHROPIC_API_KEY"
    assert cfg.escalation.max_escalation_fraction == pytest.approx(0.03)
    assert cfg.escalation.min_poe_for_escalation == 2


@pytest.mark.parametrize(
    "bad_escalation",
    [
        # Raw API keys under forbidden field names
        {"enabled": True, "api_key": "sk-1234567890abcdef123456"},
        {"enabled": True, "frontier_api_key": "sk-ant-api03-secretvalue12345"},
        {"enabled": True, "secret": "supersecret"},
        {"enabled": True, "token": "ghp_1234567890abcdefghij123456"},
        # Raw API key stuffed into frontier_api_env_var
        {
            "frontier_api_opt_in": True,
            "frontier_provider": "openai",
            "frontier_model": "gpt-4.1",
            "frontier_api_env_var": "sk-proj-1234567890abcdef123456",
        },
        {
            "frontier_api_opt_in": True,
            "frontier_provider": "google",
            "frontier_model": "gemini-2.5-pro",
            "frontier_api_env_var": "AIzaSyD1234567890abcdefghijklmnop",
        },
        # Lowercase / invalid env var name
        {
            "frontier_api_opt_in": True,
            "frontier_provider": "anthropic",
            "frontier_model": "claude-sonnet-4-20250514",
            "frontier_api_env_var": "not-an-env-var",
        },
        # Frontier settings provided while frontier_api_opt_in is False (local-only default violation)
        {"frontier_api_opt_in": False, "frontier_provider": "openai"},
        {"frontier_api_opt_in": False, "frontier_model": "gpt-4.1"},
        {"frontier_api_opt_in": False, "frontier_api_env_var": "OPENAI_API_KEY"},
        {"frontier_provider": "anthropic", "frontier_model": "claude-sonnet-4-20250514", "frontier_api_env_var": "ANTHROPIC_API_KEY"},
        # Frontier opt-in missing required fields
        {"frontier_api_opt_in": True, "frontier_provider": "openai"},
        {"frontier_api_opt_in": True, "frontier_provider": "unknown_cloud", "frontier_model": "m", "frontier_api_env_var": "MY_API_KEY"},
        # Invalid fractions & types
        {"max_escalation_fraction": 0.0},
        {"max_escalation_fraction": -0.05},
        {"max_escalation_fraction": 1.5},
        {"max_escalation_fraction": True},
        {"max_escalation_fraction": "0.05"},
        {"max_escalation_fraction": float("nan")},
        {"max_escalation_fraction": float("inf")},
        # Invalid min_poe_for_escalation
        {"min_poe_for_escalation": 0},
        {"min_poe_for_escalation": -1},
        {"min_poe_for_escalation": 4},
        {"min_poe_for_escalation": True},
        {"min_poe_for_escalation": "1"},
        # Invalid boolean types
        {"enabled": "true"},
        {"frontier_api_opt_in": "false"},
        # Forbidden `-coder` suffixes
        {"fast_local_model": "qwen2.5-coder:7b"},
        {"strong_local_model": "qwen2.5-coder:32b"},
    ],
)
def test_escalation_schema_rejects_secrets_invalid_types_and_unopted_frontier(
    tmp_path: Path,
    bad_escalation: Dict[str, Any],
) -> None:
    doc = _base_valid_dispatch(tmp_path / "ws")
    doc["workers"]["escalation"] = bad_escalation
    cfg_path = tmp_path / "bad_esc.yaml"
    cfg_path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    with pytest.raises((ValueError, PermissionError, yaml.YAMLError)):
        load_dispatch_config(cfg_path)
    assert list(tmp_path.rglob("*.db")) == []


def test_duplicate_top_level_and_workers_escalation_rejected(tmp_path: Path) -> None:
    doc = _base_valid_dispatch(tmp_path / "ws")
    doc["escalation"] = {"enabled": True}
    doc["workers"]["escalation"] = {"enabled": True}
    cfg_path = tmp_path / "dup_esc.yaml"
    cfg_path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    with pytest.raises(ValueError):
        load_dispatch_config(cfg_path)


# =============================================================================
# 4. Dynamic Runtime Free-RAM/VRAM Sizing (NEVER total physical RAM, NEVER -coder)
# =============================================================================


@pytest.mark.parametrize(
    ("free_ram_gb", "free_vram_mb", "expected_strong", "expected_fast"),
    [
        (4.0, 0.0, "qwen2.5:1.5b", "qwen2.5:1.5b"),
        (8.0, 0.0, "qwen2.5:3b", "qwen2.5:3b"),
        (16.0, 0.0, "qwen2.5:7b", "qwen2.5:7b"),
        (28.0, 0.0, "qwen2.5:14b", "qwen2.5:14b"),
        (56.0, 0.0, "qwen2.5:32b", "qwen2.5:14b"),
        # VRAM-driven sizing even when system RAM is constrained
        (4.0, 2500.0, "qwen2.5:3b", "qwen2.5:3b"),
        (4.0, 5000.0, "qwen2.5:7b", "qwen2.5:7b"),
        (4.0, 15000.0, "qwen2.5:14b", "qwen2.5:14b"),
        (4.0, 25000.0, "qwen2.5:32b", "qwen2.5:14b"),
    ],
)
def test_dynamic_free_memory_model_sizing_and_zero_coder_suffix(
    free_ram_gb: float,
    free_vram_mb: float,
    expected_strong: str,
    expected_fast: str,
) -> None:
    strong = size_model_for_free_memory(free_ram_gb, free_vram_mb)
    fast = size_fast_local_model_for_free_memory(free_ram_gb, free_vram_mb)
    assert strong == expected_strong
    assert fast == expected_fast
    assert "-coder" not in strong.lower()
    assert "-coder" not in fast.lower()


def test_probe_runtime_free_memory_uses_available_not_total_ram(monkeypatch: pytest.MonkeyPatch) -> None:
    import psutil

    # Host has 128 GiB total physical RAM, but only 5 GiB currently available -> MUST size for 5 GiB!
    fake_vm = SimpleNamespace(
        total=128 * (1024 ** 3),
        available=5 * (1024 ** 3),
    )
    monkeypatch.setattr(psutil, "virtual_memory", lambda: fake_vm)

    snap = probe_runtime_free_memory(check_gpu=False)
    assert snap.free_ram_gb == pytest.approx(5.0, abs=0.05)
    assert snap.ram_source == "psutil.virtual_memory.available"
    assert size_model_for_free_memory(snap.free_ram_gb, snap.free_vram_mb) == "qwen2.5:1.5b"


def test_router_downgrades_oversized_strong_local_model_when_free_ram_low() -> None:
    assert model_fits_free_memory("qwen2.5:32b", free_ram_gb=8.0, free_vram_mb=0.0) is False
    assert model_fits_free_memory("qwen2.5:32b", free_ram_gb=52.0, free_vram_mb=0.0) is True

    cfg = DispatchEscalationConfig(
        enabled=True,
        fast_local_model="qwen2.5:3b",
        strong_local_model="qwen2.5:32b",
        max_escalation_fraction=0.05,
        min_poe_for_escalation=1,
        frontier_api_opt_in=False,
    )
    router = TieredModelRouter(
        cfg,
        memory_probe=lambda: RuntimeMemorySnapshot(free_ram_gb=8.0, free_vram_mb=0.0),
    )
    plan = router.rank_and_route(
        [{"candidate_id": "high-1", "severity": "CRITICAL", "poe_level": 2, "is_multi_file_chain": True}]
    )
    assert plan.escalated_count == 1
    dec = plan.decisions[0]
    assert dec.tier == "strong_local"
    assert dec.model == "qwen2.5:3b"
    assert "-coder" not in dec.model
    assert dec.downgraded_for_memory is True


# =============================================================================
# 5. TieredModelRouter: Top-5% Cap, POE >= 1 Gate, Local-Only Default & Frontier Opt-In
# =============================================================================


def test_router_enforces_top_5_percent_cap_and_poe_gate_local_only_default() -> None:
    cfg = DispatchEscalationConfig(
        enabled=True,
        max_escalation_fraction=0.05,
        min_poe_for_escalation=1,
        frontier_api_opt_in=False,
    )
    router = TieredModelRouter(
        cfg,
        memory_probe=lambda: RuntimeMemorySnapshot(free_ram_gb=52.0, free_vram_mb=0.0),
    )

    candidates: List[Dict[str, Any]] = []
    # 70 unverified POE=0 items (including CRITICAL ones that MUST NOT escalate!)
    for i in range(70):
        candidates.append(
            {
                "candidate_id": f"poe0-{i}",
                "severity": "CRITICAL" if i < 10 else "LOW",
                "poe_level": 0,
                "is_multi_file_chain": True,
                "signal_score": 0.99,
            }
        )
    # 25 moderate POE=1 single-file items
    for i in range(25):
        candidates.append(
            {
                "candidate_id": f"poe1-single-{i}",
                "severity": "MEDIUM",
                "poe_level": 1,
                "is_multi_file_chain": False,
                "signal_score": 0.5,
            }
        )
    # 5 top high-signal cross-file POE>=2 items
    top_ids = set()
    for i in range(5):
        cid = f"top-chain-{i}"
        top_ids.add(cid)
        candidates.append(
            {
                "candidate_id": cid,
                "severity": "CRITICAL",
                "poe_level": 2,
                "is_multi_file_chain": True,
                "sanitizer_status": "unsanitized",
                "signal_score": 0.95,
            }
        )

    plan = router.rank_and_route(candidates)
    assert plan.total_candidates == 100
    assert plan.eligible_candidates == 30
    assert plan.escalation_budget == 5
    assert plan.escalated_count == 5
    assert plan.frontier_enabled is False
    assert plan.fast_local_model == "qwen2.5:14b"
    assert plan.strong_local_model == "qwen2.5:32b"

    escalated = [d for d in plan.decisions if d.escalated]
    assert {d.candidate_id for d in escalated} == top_ids
    for d in escalated:
        assert d.tier == "strong_local"
        assert d.provider == "ollama"
        assert d.model == "qwen2.5:32b"
        assert d.poe_level >= 1

    # Every POE=0 item MUST stay on fast_local
    for d in plan.decisions:
        if d.candidate_id.startswith("poe0-"):
            assert d.escalated is False
            assert d.tier == "fast_local"
            assert "below_min_poe_gate" in d.reason

    # Forcing frontier invocation under local-only default MUST raise PermissionError
    forced = ModelRoutingDecision(
        candidate_id="forced",
        tier="frontier_api",
        model="claude-sonnet-4-20250514",
        provider="anthropic",
        escalated=True,
        rank_score=2.0,
        poe_level=3,
        reason="forced",
        free_ram_gb=52.0,
        free_vram_mb=0.0,
    )
    with pytest.raises(PermissionError):
        router.invoke_decision(forced, "sys", "usr")


def test_router_blocks_all_escalation_when_all_candidates_below_poe_gate() -> None:
    router = TieredModelRouter(
        DispatchEscalationConfig(enabled=True, max_escalation_fraction=0.05, min_poe_for_escalation=1),
        memory_probe=lambda: RuntimeMemorySnapshot(free_ram_gb=28.0, free_vram_mb=0.0),
    )
    cands = [{"candidate_id": f"c-{i}", "severity": "CRITICAL", "poe_level": 0} for i in range(25)]
    plan = router.rank_and_route(cands)
    assert plan.eligible_candidates == 0
    assert plan.escalation_budget == 0
    assert plan.escalated_count == 0
    assert all(d.tier == "fast_local" and not d.escalated for d in plan.decisions)


def test_router_frontier_opt_in_invokes_only_when_explicit_online_and_env_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = DispatchEscalationConfig(
        enabled=True,
        max_escalation_fraction=0.05,
        min_poe_for_escalation=1,
        frontier_api_opt_in=True,
        frontier_provider="anthropic",
        frontier_model="claude-sonnet-4-20250514",
        frontier_api_env_var="RFCHUNT_TEST_FRONTIER_KEY",
    )
    cands = [
        {"candidate_id": f"bg-{i}", "severity": "LOW", "poe_level": 1, "signal_score": 0.2}
        for i in range(19)
    ] + [
        {
            "candidate_id": "high-chain",
            "severity": "CRITICAL",
            "poe_level": 3,
            "is_multi_file_chain": True,
            "signal_score": 0.99,
        }
    ]

    # 1. Env var unset -> graceful local fallback (never crashes, never calls frontier)
    monkeypatch.delenv("RFCHUNT_TEST_FRONTIER_KEY", raising=False)
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    router_missing = TieredModelRouter(
        cfg,
        offline=False,
        memory_probe=lambda: RuntimeMemorySnapshot(free_ram_gb=28.0, free_vram_mb=0.0),
    )
    plan_missing = router_missing.rank_and_route(cands)
    assert plan_missing.frontier_enabled is False
    esc_missing = [d for d in plan_missing.decisions if d.escalated]
    assert len(esc_missing) == 1
    assert esc_missing[0].tier == "strong_local"
    assert "frontier_env_var_unset_fallback_local" in esc_missing[0].reason

    # 2. Offline mode -> strictly local fallback even when env var is set
    monkeypatch.setenv("RFCHUNT_TEST_FRONTIER_KEY", "test-ephemeral-runtime-value")
    router_offline = TieredModelRouter(
        cfg,
        offline=True,
        memory_probe=lambda: RuntimeMemorySnapshot(free_ram_gb=28.0, free_vram_mb=0.0),
    )
    plan_offline = router_offline.rank_and_route(cands)
    assert plan_offline.frontier_enabled is False
    assert [d for d in plan_offline.decisions if d.escalated][0].tier == "strong_local"

    # 3. Online + opt-in + env var set -> routes top 5% (1 of 20) to frontier_api & invokes cleanly
    invoked: List[Dict[str, Any]] = []

    def _fake_frontier(**kwargs: Any) -> str:
        invoked.append(kwargs)
        return '{"verdict":"confirmed"}'

    router_online = TieredModelRouter(
        cfg,
        offline=False,
        memory_probe=lambda: RuntimeMemorySnapshot(free_ram_gb=28.0, free_vram_mb=0.0),
        frontier_invoker=_fake_frontier,
    )
    plan_online = router_online.rank_and_route(cands)
    assert plan_online.frontier_enabled is True
    assert plan_online.escalated_count == 1
    esc_dec = [d for d in plan_online.decisions if d.escalated][0]
    assert esc_dec.candidate_id == "high-chain"
    assert esc_dec.tier == "frontier_api"
    assert esc_dec.provider == "anthropic"
    assert esc_dec.model == "claude-sonnet-4-20250514"

    resp = router_online.invoke_decision(esc_dec, "Analyze slice", "entry -> sink")
    assert resp["tier"] == "frontier_api"
    assert resp["response"] == '{"verdict":"confirmed"}'
    assert len(invoked) == 1
    assert invoked[0]["provider"] == "anthropic"
    assert invoked[0]["model"] == "claude-sonnet-4-20250514"


def test_end_to_end_taint_slices_feed_directly_into_tiered_model_router(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from exec_mod import run_cmd\n@app.post('/run')\ndef api_run():\n    return run_cmd(request.args.get('c'))\n",
        encoding="utf-8",
    )
    (tmp_path / "exec_mod.py").write_text(
        "import subprocess\ndef run_cmd(c):\n    return subprocess.run(c, shell=True)\n",
        encoding="utf-8",
    )
    report = slice_repository(tmp_path)
    assert len(report.slices) >= 1
    assert isinstance(report.slices[0], TaintSlice)

    router = TieredModelRouter(
        DispatchEscalationConfig(enabled=True, max_escalation_fraction=0.05, min_poe_for_escalation=1),
        memory_probe=lambda: RuntimeMemorySnapshot(free_ram_gb=26.0, free_vram_mb=0.0),
    )
    plan = router.rank_and_route(report.slices)
    assert plan.escalated_count == 1
    assert plan.decisions[0].tier == "strong_local"
    assert plan.decisions[0].model == "qwen2.5:14b"
