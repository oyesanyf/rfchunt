"""
Zero-Mock Integration Tests for Auto-Loaded REA (`morluto/rea`) Hooks & Complete Ensemble Wiring.
"""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.ensemble_orchestrator import (
    ENGINE_WEIGHTS,
    EnsembleConsensusVoter,
    EnsembleOrchestrator,
)
from engine.linux_poc_runner import (
    probe_optional_backends,
    run_rea_hook,
    run_symbolic_hook,
)


def _create_sample_electron_js_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "sample_web_electron_app"
    src = repo / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "main.js").write_text(
        """
const { BrowserWindow, ipcMain } = require("electron");
const { execSync } = require("child_process");

function createWindow() {
  return new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webSecurity: false,
    },
  });
}

ipcMain.handle("run-shell", async (_event, cmd) => {
  return execSync(cmd);
});

async function callAi(prompt) {
  return fetch("/api/chat/completions", { method: "POST", body: prompt });
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return repo


def test_probe_optional_backends_autoloads_rea():
    probes = probe_optional_backends(timeout_sec=2.0)
    assert "rea" in probes
    rea = probes["rea"]
    assert rea["available"] is True
    assert rea["status"] == "available"
    assert rea["path_or_module"]


def test_run_rea_hook_and_symbolic_hook_detect_real_bundle_findings(tmp_path: Path):
    repo = _create_sample_electron_js_repo(tmp_path)

    direct = run_rea_hook(repo)
    assert direct["backend"] == "rea"
    assert direct["available"] is True
    assert direct["status"] == "passed"
    assert len(direct["findings"]) >= 1
    assert any(
        "nodeIntegration" in str(f.get("evidence", ""))
        or "nodeIntegration" in str(f.get("title", ""))
        for f in direct["findings"]
    )
    assert any("/api/chat/completions" in str(ep.get("route", "")) for ep in direct["discovered_endpoints"])

    via_sym = run_symbolic_hook("rea", repo)
    assert via_sym["backend"] == "rea"
    assert via_sym["available"] is True
    assert via_sym["status"] == "passed"
    assert len(via_sym["findings"]) == len(direct["findings"])


def test_run_rea_hook_fails_closed_on_unsafe_path_and_args(tmp_path: Path):
    missing = tmp_path / "does_not_exist_rea_target"
    res_missing = run_rea_hook(missing)
    assert res_missing["available"] is False
    assert res_missing["status"] == "rejected_unsafe"

    repo = _create_sample_electron_js_repo(tmp_path)
    res_bad_args = run_symbolic_hook("rea", repo, args=["--bad;rm -rf /"])
    assert res_bad_args["available"] is False
    assert res_bad_args["status"] == "rejected_unsafe"


def test_ensemble_orchestrator_auto_spawns_rea_in_embedded_and_full_modes(tmp_path: Path):
    repo = _create_sample_electron_js_repo(tmp_path)
    assert ENGINE_WEIGHTS["rea"] == 0.70

    findings, telemetry = EnsembleOrchestrator.run_exhaustive_local_engines(
        repo,
        embedded=True,
        enable_llm_verify=False,
        no_external_scanners=True,
    )
    assert "rea" in telemetry["engines_executed"]
    assert telemetry["rea"]["findings"] >= 1
    rea_findings = [f for f in findings if f.engine == "rea"]
    assert len(rea_findings) >= 1
    assert all(f.deterministic and f.confirmed for f in rea_findings)

    voter = EnsembleConsensusVoter(program="generic", quorum=1)
    clusters = voter.fuse(rea_findings)
    assert len(clusters) >= 1
    assert any("rea" in c.engines for c in clusters)
