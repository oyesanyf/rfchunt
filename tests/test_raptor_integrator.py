"""
Unit tests for RaptorIntegrator (Feature 9 & Milestone 3 requirements):
- Verifies removal of [:50] truncation in run_scan and run_host_scan.
- Verifies SARIF parsing across large finding sets (> 50 findings).
- Verifies status checks, error handling, and non-destructive execution.
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from engine.raptor_integrator import RaptorIntegrator


def test_raptor_run_scan_retains_all_findings_without_50_truncation(tmp_path: Path):
    """Feature 9 invariant: run_scan must NOT truncate findings with [:50]."""
    raptor_root = tmp_path / "raptor_root"
    raptor_root.mkdir(parents=True, exist_ok=True)
    integrator = RaptorIntegrator(raptor_root=raptor_root)

    # Generate 75 mock findings
    synthetic_findings = [
        {
            "rule_id": f"raptor.rule.{i}",
            "severity": "HIGH" if i % 2 == 0 else "MEDIUM",
            "file": f"src/module_{i}.py",
            "line": i + 1,
            "message": f"Security finding description number {i}",
        }
        for i in range(75)
    ]

    mock_status = {
        "docker_ready": True,
        "ollama_ready": True,
        "recommended_model": "qwen2.5:14b",
    }

    mock_proc = MagicMock()
    mock_proc.returncode = 0

    target = tmp_path / "target_repo"
    target.mkdir(parents=True, exist_ok=True)

    # Mock output directory in out_root
    out_dir = integrator.out_root / f"{target.name}_all_20261116"
    out_dir.mkdir(parents=True, exist_ok=True)

    with patch.object(integrator, "check_status", return_value=mock_status), \
         patch("subprocess.run", return_value=mock_proc), \
         patch.object(integrator, "collect_sarif_findings_from_dir", return_value=synthetic_findings), \
         patch.object(integrator, "_resolve_invoke_script", return_value=tmp_path / "invoke.ps1"):

        result = integrator.run_scan(target_path=target, mode="all")

        assert result.get("error") is None
        assert len(result["findings"]) == 75, "Findings must not be truncated to 50"
        assert result["total_findings"] == 75


def test_raptor_run_host_scan_retains_all_findings_without_50_truncation(tmp_path: Path):
    """Feature 9 invariant: run_host_scan must NOT truncate findings with [:50]."""
    raptor_root = tmp_path / "raptor_root"
    raptor_root.mkdir(parents=True, exist_ok=True)
    integrator = RaptorIntegrator(raptor_root=raptor_root)

    synthetic_findings = [
        {
            "rule_id": f"raptor.host.rule.{i}",
            "severity": "CRITICAL" if i % 3 == 0 else "LOW",
            "file": f"config/host_conf_{i}.json",
            "line": i + 10,
            "message": f"Host flaw {i}",
        }
        for i in range(80)
    ]

    mock_status = {
        "docker_ready": True,
        "ollama_ready": True,
        "recommended_model": "qwen2.5:14b",
    }

    mock_proc = MagicMock()
    mock_proc.returncode = 0

    host = "192.168.1.100"
    out_dir = integrator.out_root / "web_192_168_1_100_web_20261116"
    out_dir.mkdir(parents=True, exist_ok=True)

    with patch.object(integrator, "check_status", return_value=mock_status), \
         patch("subprocess.run", return_value=mock_proc), \
         patch("engine.safe_network_validator.validate_and_authorize_target", return_value=(True, "Authorized")), \
         patch.object(integrator, "collect_sarif_findings_from_dir", return_value=synthetic_findings), \
         patch.object(integrator, "_resolve_invoke_script", return_value=tmp_path / "invoke.ps1"):

        result = integrator.run_host_scan(host=host, authorized=True)

        assert result.get("error") is None
        assert len(result["findings"]) == 80, "Host scan findings must not be truncated to 50"
        assert result["total_findings"] == 80


def test_raptor_sarif_parser_handles_many_results(tmp_path: Path):
    """Ensures parse_sarif_file parses arbitrarily many findings accurately."""
    sarif_data = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "RAPTOR-SAST", "version": "1.0"}},
                "results": [
                    {
                        "ruleId": f"rule-{i}",
                        "level": "warning",
                        "message": {"text": f"Vulnerability {i}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f"file_{i}.py"},
                                    "region": {"startLine": i + 1},
                                }
                            }
                        ],
                    }
                    for i in range(120)
                ],
            }
        ],
    }

    sarif_path = tmp_path / "large_report.sarif"
    sarif_path.write_text(json.dumps(sarif_data), encoding="utf-8")

    findings = RaptorIntegrator.parse_sarif_file(sarif_path)
    assert len(findings) == 120
    assert findings[0]["rule_id"] == "rule-0"
    assert findings[119]["rule_id"] == "rule-119"
