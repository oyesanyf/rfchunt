"""Comprehensive tests for Module 20 (Google Mantis) & Unified --all Orchestrator."""

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from database import Database  # noqa: E402
from engine.mantis_integrator import (  # noqa: E402
    DEFAULT_ABLITERATED_MODEL,
    MantisHypothesis,
    MantisHypothesisGenerator,
    MantisIntegrator,
    MantisPatchEngine,
    MantisReproducer,
    MantisSeverityRubric,
    MantisThreatModeler,
    MantisZeroDaySynthesizer,
    compute_depth_profile,
    run_unified_all_scans,
)
from mcp_server import TerminatorMCPServer  # noqa: E402
import rfc_hunt_swarm  # noqa: E402


VULN_PY_SAMPLE = '''import hashlib
import os
import subprocess
import sqlite3
import yaml
import requests

@app.route('/admin/run')
def handle_admin_exec(user_cmd):
    subprocess.run(user_cmd, shell=True)

def eval_payload(expr):
    return eval(expr)

def load_user_yaml(raw_text):
    return yaml.load(raw_text)

def query_user(cursor, username):
    return cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")

def weak_digest_and_tls(payload, url):
    digest = hashlib.md5(payload.encode()).hexdigest()
    return requests.get(url, verify=False), digest
'''

SAFE_PY_SAMPLE = '''
import shlex
import subprocess

def safe_exec(user_cmd):
    cleaned = shlex.quote(str(user_cmd))
    return cleaned
'''


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    app_dir = tmp_path / "sample_app"
    (app_dir / "routes").mkdir(parents=True)
    (app_dir / "utils").mkdir(parents=True)

    (app_dir / "routes" / "admin_api.py").write_text(
        VULN_PY_SAMPLE,
        encoding="utf-8",
    )
    (app_dir / "utils" / "safe_helpers.py").write_text(SAFE_PY_SAMPLE, encoding="utf-8")
    (app_dir / "utils" / "extra1.py").write_text("x = 1\n", encoding="utf-8")
    (app_dir / "utils" / "extra2.py").write_text("y = 2\n", encoding="utf-8")
    (app_dir / "utils" / "extra3.py").write_text("z = 3\n", encoding="utf-8")
    (app_dir / "utils" / "extra4.py").write_text("w = 4\n", encoding="utf-8")
    (app_dir / "utils" / "extra5.py").write_text("v = 5\n", encoding="utf-8")
    (app_dir / "requirements.txt").write_text("PyYAML==5.3\nrequests>=2.31.0\n", encoding="utf-8")
    return app_dir


def test_fusion_and_abliterated_models_enforced(monkeypatch: pytest.MonkeyPatch, sample_repo: Path, tmp_path: Path):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    reports_dir = tmp_path / "reports"
    db = Database(str(tmp_path / "mantis_fusion.db"))

    integrator = MantisIntegrator(db=db, reports_dir=str(reports_dir))
    assert integrator.use_fusion is True
    assert integrator.preferred_model == DEFAULT_ABLITERATED_MODEL
    assert "OBLITERATED" in integrator.preferred_model.upper()
    assert integrator.fusion_arbiter is not None
    assert integrator.model_adapter is not None
    assert integrator.model_adapter.use_fusion is True

    all_res = run_unified_all_scans(
        repo=str(sample_repo),
        depth=30,
        db=db,
        reports_dir=str(reports_dir),
    )
    assert all_res["fusion_enabled"] is True
    assert all_res["abliterated_model"] == DEFAULT_ABLITERATED_MODEL
    assert len(all_res["fusion_models"]) >= 2
    db.close()


def test_threat_modeler_ranks_routes_above_benign(sample_repo: Path):
    modeler = MantisThreatModeler()
    files = [
        str(sample_repo / "utils" / "safe_helpers.py"),
        str(sample_repo / "routes" / "admin_api.py"),
        str(sample_repo / "utils" / "extra1.py"),
    ]
    tm = modeler.build_threat_model(str(sample_repo), files)
    assert tm.model_id.startswith("tm-")
    assert len(tm.entry_points) >= 1
    assert any(ep.get("network_exposed") for ep in tm.entry_points)
    assert tm.risk_ranked_files[0]["rel_path"].endswith("routes/admin_api.py")
    assert set(tm.stride_matrix.keys()) >= {"Spoofing", "Tampering", "Elevation of Privilege"}


def test_depth_scaling_and_tier_filtering(sample_repo: Path):
    p10 = compute_depth_profile(10)
    p30 = compute_depth_profile(30)
    p100 = compute_depth_profile(100)
    assert p10["passes"] < p30["passes"] < p100["passes"]
    assert p10["coverage_ratio"] < p30["coverage_ratio"] < p100["coverage_ratio"]
    assert p10["allowed_tiers"] == {"HIGH"}
    assert "MEDIUM" in p30["allowed_tiers"]
    assert p100["allowed_tiers"] == {"HIGH", "MEDIUM", "LOW"}

    files = [str(p) for p in sorted(sample_repo.rglob("*.py"))]
    tm = MantisThreatModeler().build_threat_model(str(sample_repo), files)
    gen = MantisHypothesisGenerator()

    hyps_10 = gen.generate_hypotheses(files, tm, depth=10)
    hyps_100 = gen.generate_hypotheses(files, tm, depth=100)
    rules_10 = {h.rule_id for h in hyps_10}
    rules_100 = {h.rule_id for h in hyps_100}

    assert "MANTIS-CMD-001" in rules_10
    assert "MANTIS-CRYPTO-008" not in rules_10
    assert "MANTIS-CRYPTO-008" in rules_100
    assert len(hyps_100) > len(hyps_10)


def test_reproducer_tier1_ast_and_tier2_canary_sandbox(tmp_path: Path):
    vuln_file = tmp_path / "vuln_exec.py"
    vuln_file.write_text(
        "import subprocess\n\ndef run_cmd(user_input):\n    subprocess.run(user_input, shell=True)\n",
        encoding="utf-8",
    )
    safe_file = tmp_path / "safe_exec.py"
    safe_file.write_text(SAFE_PY_SAMPLE, encoding="utf-8")

    tm = MantisThreatModeler().build_threat_model(str(tmp_path), [str(vuln_file)])
    hyps = MantisHypothesisGenerator().generate_hypotheses([str(vuln_file)], tm, depth=30)
    cmd_hyps = [h for h in hyps if h.rule_id == "MANTIS-CMD-001"]
    assert len(cmd_hyps) == 1

    repro = MantisReproducer()
    res = repro.reproduce(cmd_hyps[0], enable_tier2=True)
    assert res.reproduced is True
    assert res.tier == "TIER_2_SANDBOX_CANARY"
    assert res.canary_reached_sink is True

    # Verify sanitized hypothesis fails reproduction
    fake_safe_hyp = MantisHypothesis(
        hypothesis_id="HYP-SAFE01",
        rule_id="MANTIS-CMD-001",
        title="Test",
        cwe="CWE-78",
        category="Command Execution",
        file_path=str(safe_file),
        line_number=5,
        function_name="safe_exec",
        sink="subprocess.run",
        source_hint="user_cmd",
        code_snippet="cleaned = shlex.quote(str(user_cmd))",
        raw_severity="CRITICAL",
        confidence=0.5,
        description="test",
        remediation="test",
    )
    safe_res = repro.reproduce(fake_safe_hyp, enable_tier2=True)
    assert safe_res.reproduced is False


def test_severity_rubric_anti_inflation(tmp_path: Path):
    rubric = MantisSeverityRubric()
    hyp_prod = MantisHypothesis(
        hypothesis_id="HYP-1",
        rule_id="MANTIS-CMD-001",
        title="Cmd Injection",
        cwe="CWE-78",
        category="Command Execution",
        file_path=str(tmp_path / "routes" / "api.py"),
        line_number=4,
        function_name="api_exec",
        sink="os.system",
        source_hint="user_cmd",
        code_snippet="os.system(user_cmd)",
        raw_severity="CRITICAL",
        confidence=0.95,
        description="desc",
        remediation="rem",
    )
    from engine.mantis_integrator import ReproductionResult

    repro_confirmed = ReproductionResult(True, "TIER_2_SANDBOX_CANARY", "canary hit", canary_reached_sink=True)
    repro_unverified = ReproductionResult(False, "UNVERIFIED", "not proven")

    sev_ok, score_ok, vec_ok = rubric.calibrate(hyp_prod, repro_confirmed, is_network_exposed=True)
    sev_down, score_down, _ = rubric.calibrate(hyp_prod, repro_unverified, is_network_exposed=False)
    assert sev_ok == "CRITICAL"
    assert score_ok >= 9.0
    assert vec_ok.startswith("CVSS:3.1/")
    assert score_down < score_ok - 1.5
    assert sev_down != "CRITICAL"


def test_patch_engine_neutralizes_and_validates_syntax(tmp_path: Path):
    vuln_file = tmp_path / "patchable.py"
    vuln_file.write_text(
        "import ast\n"
        "import subprocess\n"
        "import yaml\n\n"
        "def bad_cmd(user_cmd):\n"
        "    subprocess.run(user_cmd, shell=True)\n\n"
        "def bad_eval(expr):\n"
        "    return eval(expr)\n\n"
        "def bad_yaml(data):\n"
        "    return yaml.load(data)\n",
        encoding="utf-8",
    )

    tm = MantisThreatModeler().build_threat_model(str(tmp_path), [str(vuln_file)])
    hyps = MantisHypothesisGenerator().generate_hypotheses([str(vuln_file)], tm, depth=60)
    patcher = MantisPatchEngine()
    repro = MantisReproducer()

    by_rule = {h.rule_id: h for h in hyps}
    for required_rule in ("MANTIS-CMD-001", "MANTIS-EVAL-002", "MANTIS-DESER-004"):
        assert required_rule in by_rule
        res = patcher.generate_and_verify_patch(by_rule[required_rule], repro)
        assert res.patch_generated is True
        assert res.syntax_valid is True
        assert res.patch_verified is True
        assert "--- " in res.unified_diff and "+++ " in res.unified_diff
        ast.parse(res.patched_snippet.strip())


def test_mantis_integrator_persistence_and_sarif_export(monkeypatch: pytest.MonkeyPatch, sample_repo: Path, tmp_path: Path):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    reports_dir = tmp_path / "reports"
    db = Database(str(tmp_path / "persist.db"))
    integrator = MantisIntegrator(db=db, reports_dir=str(reports_dir))

    result = integrator.run_scan(target_path=str(sample_repo), depth=100, mode="patch")
    assert result["total_findings"] >= 4
    assert result["reproduced_count"] >= 1
    assert result["patched_verified_count"] >= 1

    # DB persistence check
    stored_tm = db.get_mantis_threat_model(target_repo=str(sample_repo.resolve()))
    assert stored_tm is not None
    assert stored_tm["model_id"] == result["threat_model_id"]
    stored_findings = db.get_mantis_findings(limit=50)
    assert len(stored_findings) == result["total_findings"]

    # SARIF 2.1.0 validation
    sarif_file = Path(result["report_files"]["sarif"])
    assert sarif_file.exists()
    sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == result["total_findings"]
    db.close()


def test_unified_all_scans_pipeline_and_combined_sarif(monkeypatch: pytest.MonkeyPatch, sample_repo: Path, tmp_path: Path):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    reports_dir = tmp_path / "all_reports"
    db = Database(str(tmp_path / "unified.db"))

    res = run_unified_all_scans(
        repo=str(sample_repo),
        depth=45,
        use_fusion=True,
        db=db,
        reports_dir=str(reports_dir),
    )
    assert res["fusion_enabled"] is True
    assert "mantis" in res["engines"]
    assert "aiscan" in res["engines"]
    assert "raptor" in res["engines"]
    assert "artex_dual_graph" in res["engines"]
    assert "prompt_smuggling" in res["engines"]
    assert res["engines"]["raptor"]["total_findings"] >= 1  # PyYAML==5.3 SCA fallback
    assert res["engines"]["prompt_smuggling"]["probes_generated"] >= 1

    combined_sarif_path = Path(res["report_files"]["combined_sarif"])
    combined_json_path = Path(res["report_files"]["combined_json"])
    assert combined_sarif_path.exists()
    assert combined_json_path.exists()
    sarif = json.loads(combined_sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) >= res["engines"]["mantis"]["total_findings"]
    db.close()


def test_cli_parsing_and_headless_execution(monkeypatch: pytest.MonkeyPatch, sample_repo: Path, tmp_path: Path):
    parser = rfc_hunt_swarm.build_swarm_parser()
    parsed = parser.parse_args(["--all", "--repo", str(sample_repo), "--depth", "50", "--mantis-mode", "patch"])
    assert parsed.run_all_scans is True
    assert parsed.repo == str(sample_repo)
    assert parsed.depth == 50
    assert parsed.mantis_mode == "patch"

    parsed_path = parser.parse_args(["--all", "--path", str(sample_repo / "routes" / "admin_api.py"), "--depth", "15"])
    assert parsed_path.run_all_scans is True
    assert parsed_path.path.endswith("admin_api.py")
    assert parsed_path.depth == 15

    # End-to-end headless CLI invocation of both entrypoints
    env = {**os.environ, "RFCHUNT_OFFLINE": "1", "PYTHONUTF8": "1"}
    out1 = tmp_path / "cli_out_swarm"
    out2 = tmp_path / "cli_out_main"

    proc1 = subprocess.run(
        [
            sys.executable,
            "rfc_hunt_swarm.py",
            "--all",
            "--repo",
            str(sample_repo),
            "--depth",
            "25",
            "--db",
            str(tmp_path / "cli1.db"),
            "--output-dir",
            str(out1),
        ],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert proc1.returncode == 0, proc1.stderr
    assert (out1 / "combined_report.sarif").exists()
    assert (out1 / "mantis_report.sarif").exists()

    proc2 = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--all",
            "--path",
            str(sample_repo / "routes" / "admin_api.py"),
            "--depth",
            "30",
            "--db",
            str(tmp_path / "cli2.db"),
            "--output-dir",
            str(out2),
        ],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert (out2 / "combined_report.sarif").exists()


def test_mcp_server_tools_run_all_and_mantis(monkeypatch: pytest.MonkeyPatch, sample_repo: Path, tmp_path: Path):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    server = TerminatorMCPServer(db_path=str(tmp_path / "mcp_mantis.db"))
    tool_names = {t["name"] for t in server._get_tool_definitions()}
    assert {"run_all_scans", "mantis_scan_all", "mantis_scan"}.issubset(tool_names)

    res_all = server._execute_tool(
        "run_all_scans",
        {"repo": str(sample_repo), "depth": 30, "output_dir": str(tmp_path / "mcp_out")},
    )
    assert res_all["fusion_enabled"] is True
    assert res_all["abliterated_model"] == DEFAULT_ABLITERATED_MODEL
    assert Path(res_all["report_files"]["combined_sarif"]).exists()

    res_mantis = server._execute_tool(
        "mantis_scan",
        {"path": str(sample_repo / "routes" / "admin_api.py"), "depth": 65, "mode": "patch", "output_dir": str(tmp_path / "mcp_out2")},
    )
    assert res_mantis["fusion_enabled"] is True
    assert res_mantis["total_findings"] >= 3
    assert res_mantis["patched_verified_count"] >= 2
    server.db.close()


def test_github_workflow_yaml_valid():
    wf_path = REPO_ROOT / ".github" / "workflows" / "mantis-all-scans.yml"
    assert wf_path.exists()
    data = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
    # PyYAML parses unquoted 'on:' either as 'on' or boolean True depending on version; handle cleanly
    triggers = data.get("on") if "on" in data else data.get(True)
    assert triggers is not None
    assert "push" in triggers and "pull_request" in triggers and "workflow_dispatch" in triggers
    assert data["permissions"]["security-events"] == "write"

    steps = data["jobs"]["unified-all-scans"]["steps"]
    run_scripts = "\n".join(s.get("run", "") for s in steps)
    assert "--all --repo ." in run_scripts
    uses_list = [s.get("uses", "") for s in steps]
    assert any("github/codeql-action/upload-sarif@v" in u for u in uses_list)
    assert any("actions/upload-artifact@v4" in u for u in uses_list)


def test_zero_day_synthesizer_deterministic_offline_fallback(sample_repo: Path):
    files = [str(p) for p in sorted(sample_repo.rglob("*.py"))]
    tm = MantisThreatModeler().build_threat_model(str(sample_repo), files)
    synthesizer = MantisZeroDaySynthesizer(fusion_arbiter=None)

    hyps = synthesizer.synthesize_hypotheses(tm)
    assert len(hyps) >= 1
    for h in hyps:
        assert h.rule_id.startswith("MANTIS-0DAY")
        assert h.is_zero_day is True
        assert h.hypothesis_id.startswith("HYP-0DAY-")
        assert h.confidence >= 0.5
        assert h.sink
        assert h.file_path
        assert h.description

    rule_ids = {h.rule_id for h in hyps}
    assert any(rid in rule_ids for rid in ("MANTIS-0DAY-XFLOW-001", "MANTIS-0DAY-DESYNC-002", "MANTIS-0DAY-CHAIN-003", "MANTIS-0DAY-FALLBACK-001"))


def test_zero_day_synthesizer_model_mode(monkeypatch: pytest.MonkeyPatch, sample_repo: Path):
    monkeypatch.delenv("RFCHUNT_OFFLINE", raising=False)
    files = [str(p) for p in sorted(sample_repo.rglob("*.py"))]
    tm = MantisThreatModeler().build_threat_model(str(sample_repo), files)

    class FakeFusionArbiter:
        def __init__(self):
            self.gemma_model = DEFAULT_ABLITERATED_MODEL
            self.sec_model = "fenkohq/foundation-sec-8b:latest"
            self.called = False

        def arbitrate_structured_json(self, task_name, system_prompt, user_prompt, default_payload=None, num_predict=512):
            self.called = True
            return {
                "status": "fused",
                "data": {
                    "hypotheses": [
                        {
                            "rule_id": "MANTIS-0DAY-MODEL-DESER",
                            "title": "Model-Synthesized Zero-Day Deserialization Exploit",
                            "cwe": "CWE-502",
                            "category": "Zero-Day Attack Surface",
                            "file_path": str(sample_repo / "routes" / "admin_api.py"),
                            "line_number": 15,
                            "function_name": "load_admin_token",
                            "sink": "pickle.loads",
                            "source_hint": "raw_token_header",
                            "code_snippet": "pickle.loads(token)",
                            "raw_severity": "CRITICAL",
                            "confidence": 0.94,
                            "description": "Synthesized zero-day exploit chaining token header to unsafe pickle load.",
                            "remediation": "Use safe JSON deserializer.",
                        }
                    ]
                },
            }

    fake_arbiter = FakeFusionArbiter()
    synthesizer = MantisZeroDaySynthesizer(fusion_arbiter=fake_arbiter)
    hyps = synthesizer.synthesize_hypotheses(tm)

    assert fake_arbiter.called is True
    assert len(hyps) == 1
    assert hyps[0].rule_id == "MANTIS-0DAY-MODEL-DESER"
    assert hyps[0].is_zero_day is True
    assert hyps[0].confidence == 0.94


def test_interprocedural_ast_taint_caller_callee():
    src = (
        "import subprocess\n"
        "\n"
        "def exec_sink(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n"
        "\n"
        "def handle_entry(user_param):\n"
        "    exec_sink(user_param)\n"
    )
    hyp = MantisHypothesis(
        hypothesis_id="HYP-TEST-001",
        rule_id="MANTIS-CMD-001",
        title="Command Injection",
        cwe="CWE-78",
        category="Command Execution",
        file_path="virtual_target.py",
        line_number=4,
        function_name="handle_entry",
        sink="subprocess.run(shell=True)",
        source_hint="user_param",
        code_snippet="subprocess.run(cmd, shell=True)",
        raw_severity="CRITICAL",
        confidence=0.92,
        description="Command injection sink in helper called by entry.",
        remediation="shell=False",
    )
    reproducer = MantisReproducer()
    res = reproducer._tier1_ast_taint(src, hyp)
    assert res.reproduced is True
    assert res.tier == "TIER_1_STATIC_TAINT"
    assert any("exec_sink.cmd" in step for step in res.taint_path)


def test_interprocedural_ast_taint_object_attribute():
    src = (
        "import os\n"
        "\n"
        "class Handler:\n"
        "    def set_data(self, user_val):\n"
        "        self.cached_command = user_val\n"
        "\n"
        "    def run_cached(self):\n"
        "        os.system(self.cached_command)\n"
    )
    hyp = MantisHypothesis(
        hypothesis_id="HYP-TEST-002",
        rule_id="MANTIS-CMD-001",
        title="Command Injection via Attribute",
        cwe="CWE-78",
        category="Command Execution",
        file_path="virtual_attr.py",
        line_number=8,
        function_name="run_cached",
        sink="os.system",
        source_hint="self.cached_command",
        code_snippet="os.system(self.cached_command)",
        raw_severity="CRITICAL",
        confidence=0.90,
        description="Command injection via self attribute assignment.",
        remediation="Validate attribute.",
    )
    reproducer = MantisReproducer()
    res = reproducer._tier1_ast_taint(src, hyp)
    assert res.reproduced is True
    assert res.tier == "TIER_1_STATIC_TAINT"
    assert any("cached_command" in step for step in res.taint_path)


def test_interprocedural_ast_taint_return_chain():
    src = (
        "import os\n"
        "\n"
        "def sanitize_strip(data):\n"
        "    return data.strip()\n"
        "\n"
        "def process_input(raw_input):\n"
        "    cleaned = sanitize_strip(raw_input)\n"
        "    os.system(cleaned)\n"
    )
    hyp = MantisHypothesis(
        hypothesis_id="HYP-TEST-003",
        rule_id="MANTIS-CMD-001",
        title="Command Injection via Return Chain",
        cwe="CWE-78",
        category="Command Execution",
        file_path="virtual_chain.py",
        line_number=8,
        function_name="process_input",
        sink="os.system",
        source_hint="raw_input",
        code_snippet="os.system(cleaned)",
        raw_severity="CRITICAL",
        confidence=0.88,
        description="Taint forwarded through return value chain.",
        remediation="Avoid shell evaluation.",
    )
    reproducer = MantisReproducer()
    res = reproducer._tier1_ast_taint(src, hyp)
    assert res.reproduced is True
    assert res.tier == "TIER_1_STATIC_TAINT"
    assert any("cleaned@" in step for step in res.taint_path)


def test_mantis_proto_010_ast_detection():
    src = (
        "def ai_query(user_query):\n"
        "    prompt = f'System: You are an agent.\\nUser: {user_query}\\nAssistant:'\n"
        "    return model.generate(prompt)\n"
        "\n"
        "def forward_wire(hdr, sock):\n"
        "    raw = f'GET / HTTP/1.1\\r\\nTransfer-Encoding: {hdr}\\r\\n\\r\\n'\n"
        "    sock.sendall(raw.encode())\n"
    )
    lines = src.splitlines()
    gen = MantisHypothesisGenerator()
    hyps = gen._scan_python_ast(
        file_path="proto_sample.py",
        src=src,
        lines=lines,
        allowed_tiers={"HIGH", "MEDIUM", "LOW"},
        pass_idx=1,
    )
    proto_hyps = [h for h in hyps if h.rule_id == "MANTIS-PROTO-010"]
    assert len(proto_hyps) >= 1
    assert any("header_framing" in h.sink or "unframed_prompt" in h.sink or "assign:prompt" in h.sink for h in proto_hyps)


def test_model_adapter_unpacking_data_nested(monkeypatch: pytest.MonkeyPatch, sample_repo: Path, tmp_path: Path):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    files = [str(sample_repo / "routes" / "admin_api.py")]

    class FakeNestedArbiter:
        def arbitrate_structured_json(self, task_name, system_prompt, user_prompt, default_payload=None, num_predict=256):
            if "Threat Modeling" in task_name:
                return {
                    "status": "fused",
                    "data": {
                        "summary": "Deep Nested STRIDE Summary via Data Key",
                        "threat_actors": ["APT-Protocol-Attacker", "AI-Prompt-Smuggler"],
                    },
                }
            if "Unified All-Scan" in task_name:
                return {
                    "status": "fused",
                    "data": {
                        "executive_summary": "Deep Nested Executive Summary via Data Key",
                    },
                }
            return {"status": "default", "data": default_payload or {}}

    fake_arb = FakeNestedArbiter()
    modeler = MantisThreatModeler(fusion_arbiter=fake_arb)
    tm = modeler.build_threat_model(str(sample_repo), files)
    assert tm.raw_summary == "Deep Nested STRIDE Summary via Data Key"
    assert "APT-Protocol-Attacker" in tm.threat_actors
    assert "AI-Prompt-Smuggler" in tm.threat_actors

    res = run_unified_all_scans(
        repo=str(sample_repo),
        depth=30,
        arbiter=fake_arb,
        reports_dir=str(tmp_path / "reports_nested"),
    )
    assert res["executive_summary"] == "Deep Nested Executive Summary via Data Key"


def test_mantis_scan_with_zero_day_findings_integrated(monkeypatch: pytest.MonkeyPatch, sample_repo: Path, tmp_path: Path):
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    integrator = MantisIntegrator(reports_dir=str(tmp_path / "zero_day_reports"))
    scan_res = integrator.run_scan(str(sample_repo), depth=100)

    assert scan_res["total_findings"] >= 1
    zero_day_findings = [f for f in scan_res["findings"] if f.get("is_zero_day") is True]
    assert len(zero_day_findings) >= 1
    for zf in zero_day_findings:
        assert zf["rule_id"].startswith("MANTIS-0DAY")
        assert zf["finding_id"].startswith("MANTIS-0DAY")
        assert zf["cwe"]

    # Verify SARIF document includes zero_day properties
    sarif_file = Path(scan_res["report_files"]["sarif"])
    assert sarif_file.exists()
    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    runs = sarif_data["runs"]
    assert len(runs) >= 1
    res_list = runs[0]["results"]
    assert any(r.get("properties", {}).get("is_zero_day") is True for r in res_list)


def test_unified_all_scans_string_entry_points_and_findings_resilience(monkeypatch: pytest.MonkeyPatch, sample_repo: Path, tmp_path: Path):
    """Regression test: string entry_points in threat_model and string findings in aiscan do not trigger AttributeError."""
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")

    orig_run_scan = MantisIntegrator.run_scan

    def mock_mantis_run_scan(self, target_path, depth=30, mode="balanced", **kwargs):
        res = orig_run_scan(self, target_path, depth=depth, mode=mode, **kwargs)
        if "threat_model" in res and isinstance(res["threat_model"], dict):
            res["threat_model"]["entry_points"] = ["/api/v1/auth", "/api/v1/admin", "/api/v1/chat"]
        return res

    monkeypatch.setattr(MantisIntegrator, "run_scan", mock_mantis_run_scan)

    from engine.aiscan_integrator import AiscanIntegrator
    orig_aiscan_scan = AiscanIntegrator.scan_target

    def mock_aiscan_scan(self, target_path, **kwargs):
        res = orig_aiscan_scan(self, target_path, **kwargs)
        res["findings"] = ["Unmetered LLM endpoint injection", "Prompt injection sink"]
        return res

    monkeypatch.setattr(AiscanIntegrator, "scan_target", mock_aiscan_scan)

    reports_dir = tmp_path / "reports_resilience"
    unified_res = run_unified_all_scans(
        repo=str(sample_repo),
        depth=30,
        reports_dir=str(reports_dir),
    )

    assert "chains" in unified_res
    engines_val = unified_res.get("engines", {})
    if isinstance(engines_val, dict):
        artex_status = engines_val.get("artex_dual_graph", {})
    else:
        artex_status = next((e for e in engines_val if isinstance(e, dict) and "ARTEX" in e.get("engine", "")), {})
    assert "error" not in artex_status or "'str' object has no attribute 'get'" not in str(artex_status.get("error"))
    assert unified_res.get("chains_synthesized", 0) > 0 or artex_status.get("chains_synthesized", 0) > 0


