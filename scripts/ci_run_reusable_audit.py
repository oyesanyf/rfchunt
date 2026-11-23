"""
Headless CI runner for RFCHunt's reusable GitHub Actions workflow (`workflow_call`).

Executes RFCHunt (`deep-audit`, `trust-boundary`, or `all-deep-audit`) strictly
read-only against a target repository, merges deep-audit findings into a valid
SARIF 2.1.0 report with repository-relative URIs for GitHub Code Scanning,
publishes a concise Markdown job summary to `$GITHUB_STEP_SUMMARY`, and enforces
optional `FAIL_ON_SEV` (`none` | `CRITICAL` | `HIGH`) policy gating.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_SEV_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _to_repo_relative_uri(raw_path: str, target_repo: Path) -> str:
    if not raw_path:
        return "README.md"
    cleaned = str(raw_path).strip()
    if ":" in cleaned and cleaned.startswith(("127.0.0.1:", "localhost:", "[::1]:")):
        return "proxy-loopback-target"
    try:
        p = Path(cleaned)
        if p.is_absolute():
            rel = p.resolve(strict=False).relative_to(target_repo.resolve(strict=False))
            return rel.as_posix()
    except Exception:
        pass
    norm = cleaned.replace("\\", "/")
    repo_posix = target_repo.resolve(strict=False).as_posix().rstrip("/") + "/"
    if norm.lower().startswith(repo_posix.lower()):
        return norm[len(repo_posix) :].lstrip("/") or "README.md"
    return norm.lstrip("./").lstrip("/") or "README.md"


def build_rfchunt_cli_argv(
    rfchunt_root: Path,
    target_repo: Path,
    report_dir: Path,
    db_path: Path,
    *,
    mode: str = "all-deep-audit",
    proxy: str = "",
    enable_poc: bool = True,
    trust_max_files: int = 80,
    depth: int = 50,
    python_exe: Optional[str] = None,
) -> List[str]:
    """Constructs a shell-free argv list for `rfc_hunt_swarm.py`."""
    py = python_exe or sys.executable
    entry = str((rfchunt_root / "rfc_hunt_swarm.py").resolve(strict=False))
    norm_mode = str(mode or "all-deep-audit").strip().lower()
    proxy_s = str(proxy or "").strip()

    if norm_mode == "trust-boundary":
        argv = [
            py,
            "-u",
            entry,
            "deep-audit",
            "--repo",
            str(target_repo),
            "--trust-boundary-review",
            "--trust-max-files",
            str(max(1, int(trust_max_files))),
            "--output-dir",
            str(report_dir),
            "--db",
            str(db_path),
            "--plain",
        ]
    elif norm_mode == "deep-audit":
        argv = [
            py,
            "-u",
            entry,
            "deep-audit",
            "--repo",
            str(target_repo),
            "--trust-boundary-review",
            "--coverage-fuzz",
            "--fuzz-dry-run",
            "--trust-max-files",
            str(max(1, int(trust_max_files))),
            "--output-dir",
            str(report_dir),
            "--db",
            str(db_path),
            "--plain",
        ]
    else:
        argv = [
            py,
            "-u",
            entry,
            "--all",
            "--repo",
            str(target_repo),
            "--deep-audit",
            "--fuzz-dry-run",
            "--depth",
            str(max(1, min(100, int(depth)))),
            "--trust-max-files",
            str(max(1, int(trust_max_files))),
            "--output-dir",
            str(report_dir),
            "--db",
            str(db_path),
            "--plain",
        ]

    if proxy_s:
        if proxy_s.lower() == "auto":
            argv.append("--proxy")
        else:
            argv.extend(["--proxy", proxy_s])
    if enable_poc:
        argv.append("--poc")
    return argv


def _deep_audit_findings_to_sarif_run(
    deep_summary: Dict[str, Any],
    target_repo: Path,
) -> Dict[str, Any]:
    findings = deep_summary.get("findings") or []
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        if not isinstance(f, dict):
            continue
        rule_id = str(f.get("rule_id") or "RFCHUNT-TB-000").strip()
        sev = str(f.get("severity") or "MEDIUM").strip().upper()
        level = _SEV_TO_SARIF_LEVEL.get(sev, "warning")
        title = str(f.get("title") or rule_id).strip()
        desc = str(f.get("description") or title).strip()
        remediation = str(f.get("remediation") or "").strip()

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title[:160]},
                "fullDescription": {"text": (desc + (f" Remediation: {remediation}" if remediation else ""))[:900]},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": ["security", "rfchunt", "trust-boundary"]},
            }

        rel_uri = _to_repo_relative_uri(str(f.get("file_path") or ""), target_repo)
        line_no = f.get("line_number")
        try:
            start_line = max(1, int(line_no)) if line_no is not None else 1
        except (TypeError, ValueError):
            start_line = 1

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"[{sev}] {title} -- {desc}"[:1000]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": rel_uri},
                            "region": {"startLine": start_line},
                        }
                    }
                ],
                "properties": {
                    "severity": sev,
                    "scanner": str(f.get("scanner") or "DeepRepoAudit"),
                    "category": str(f.get("category") or "trust_boundary"),
                },
            }
        )

    return {
        "tool": {
            "driver": {
                "name": "RFCHunt Deep Repo Audit",
                "informationUri": "https://github.com/oyesanyf/rfchunt",
                "version": "1.0.0",
                "rules": list(rules_by_id.values()),
            }
        },
        "results": results,
    }


def build_unified_ci_sarif(
    report_dir: Path,
    target_repo: Path,
) -> Tuple[Path, Dict[str, Any], Dict[str, Any]]:
    """
    Produces a guaranteed-valid SARIF 2.1.0 file at `<report_dir>/rfchunt_ci.sarif`
    combining any `--all` SARIF run with the Deep Repo Audit structural run.
    """
    combined_sarif_path = report_dir / "combined_report.sarif"
    deep_json_path = report_dir / "deep_audit" / "deep_audit_summary.json"
    poc_manifest_path = report_dir / "pocs" / "poc_manifest.json"

    deep_summary: Dict[str, Any] = {}
    if deep_json_path.is_file():
        try:
            deep_summary = json.loads(deep_json_path.read_text(encoding="utf-8"))
        except Exception:
            deep_summary = {}

    poc_summary: Dict[str, Any] = {}
    if poc_manifest_path.is_file():
        try:
            poc_summary = json.loads(poc_manifest_path.read_text(encoding="utf-8"))
        except Exception:
            poc_summary = {}

    sarif_doc: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }
    if combined_sarif_path.is_file():
        try:
            existing = json.loads(combined_sarif_path.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and isinstance(existing.get("runs"), list):
                for run in existing["runs"]:
                    if isinstance(run, dict):
                        for res in run.get("results") or []:
                            for loc in res.get("locations") or []:
                                art = (loc.get("physicalLocation") or {}).get("artifactLocation")
                                if isinstance(art, dict) and art.get("uri"):
                                    art["uri"] = _to_repo_relative_uri(str(art["uri"]), target_repo)
                        sarif_doc["runs"].append(run)
        except Exception:
            pass

    sarif_doc["runs"].append(_deep_audit_findings_to_sarif_run(deep_summary, target_repo))

    out_sarif = report_dir / "rfchunt_ci.sarif"
    out_sarif.parent.mkdir(parents=True, exist_ok=True)
    out_sarif.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
    return out_sarif, deep_summary, poc_summary


def render_step_summary(
    target_repo: Path,
    mode: str,
    deep_summary: Dict[str, Any],
    poc_summary: Dict[str, Any],
    sarif_path: Path,
) -> str:
    tb = deep_summary.get("trust_boundary_review") or {}
    lp = deep_summary.get("live_proxy_fuzz") or {}
    cf = deep_summary.get("coverage_fuzz") or {}
    findings: List[Dict[str, Any]] = list(deep_summary.get("findings") or [])

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = str(f.get("severity") or "INFO").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines = [
        "## RFCHunt Security Audit Summary",
        "",
        f"- **Repository**: `{target_repo.name}` (read-only audit)",
        f"- **Mode**: `{mode}`",
        f"- **Trust-Boundary Files Reviewed**: `{tb.get('files_reviewed', 0)}`",
        f"- **Live Loopback Proxy Fuzz**: `{lp.get('status', 'disabled')}` (probes=`{lp.get('probes_sent', 0)}`, divergences=`{len(lp.get('confirmed_divergences') or [])}`)",
        f"- **Coverage Fuzz Targets**: `{', '.join(cf.get('targets_scanned') or []) or 'disabled'}` (`dry_run={cf.get('dry_run', True)}`)",
        f"- **Deep-Audit Findings**: `{len(findings)}` (`CRITICAL={sev_counts['CRITICAL']}`, `HIGH={sev_counts['HIGH']}`, `MEDIUM={sev_counts['MEDIUM']}`, `LOW={sev_counts['LOW']}`)",
    ]
    if poc_summary:
        lines.append(
            f"- **Non-Destructive PoC Triage**: verified/actionable=`{poc_summary.get('verified_count', 0)}`, "
            f"rejected_false_positives=`{poc_summary.get('rejected_false_positives', 0)}`"
        )
    lines.append(f"- **SARIF 2.1.0 Report**: `{sarif_path.name}`")
    lines.append("")

    if findings:
        sorted_f = sorted(
            findings,
            key=lambda x: (_SEV_RANK.get(str(x.get("severity", "INFO")).upper(), 9), str(x.get("rule_id", ""))),
        )
        lines.append("### Top Structural & Dynamic Findings")
        lines.append("")
        lines.append("| Severity | Rule | Location | Title |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for f in sorted_f[:25]:
            sev = str(f.get("severity") or "INFO").upper()
            rule = str(f.get("rule_id") or "")
            rel = _to_repo_relative_uri(str(f.get("file_path") or ""), target_repo)
            ln = f.get("line_number")
            loc = f"{rel}:{ln}" if ln else rel
            title = str(f.get("title") or "").replace("|", "/")[:110]
            lines.append(f"| `{sev}` | `{rule}` | `{loc}` | {title} |")
        lines.append("")
    else:
        lines.append("No trust-boundary or live-proxy findings detected.")
        lines.append("")
    return "\n".join(lines)


def evaluate_severity_gate(deep_summary: Dict[str, Any], fail_on_severity: str) -> Tuple[bool, str]:
    gate = str(fail_on_severity or "none").strip().upper()
    if gate in ("", "NONE", "OFF", "FALSE"):
        return True, "Report-only mode (`fail_on_severity=none`)."
    threshold = _SEV_RANK.get(gate)
    if threshold is None:
        return True, f"Unrecognized fail_on_severity={gate!r}; defaulting to report-only."
    findings = deep_summary.get("findings") or []
    breaches = [
        f
        for f in findings
        if _SEV_RANK.get(str(f.get("severity") or "INFO").upper(), 9) <= threshold
    ]
    if breaches:
        return False, f"Severity gate `{gate}` tripped by {len(breaches)} finding(s)."
    return True, f"Severity gate `{gate}` passed (0 findings at or above `{gate}`)."


def main() -> int:
    rfchunt_root = Path(os.environ.get("RFCHUNT_ROOT") or Path(__file__).resolve().parent.parent).resolve(strict=False)
    target_repo = Path(os.environ.get("TARGET_REPO") or ".").resolve(strict=False)
    report_dir = Path(os.environ.get("REPORT_DIR") or (Path.cwd() / "rfchunt-reports")).resolve(strict=False)
    report_dir.mkdir(parents=True, exist_ok=True)

    mode = os.environ.get("RFCHUNT_MODE", "all-deep-audit").strip() or "all-deep-audit"
    proxy = os.environ.get("RFCHUNT_PROXY", "").strip()
    enable_poc = os.environ.get("RFCHUNT_ENABLE_POC", "true").strip().lower() in ("1", "true", "yes", "on")
    trust_max = int(os.environ.get("RFCHUNT_TRUST_MAX", "80") or "80")
    depth = int(os.environ.get("RFCHUNT_DEPTH", "50") or "50")
    fail_on_sev = os.environ.get("FAIL_ON_SEV", "none").strip() or "none"

    db_path = Path(tempfile.gettempdir()) / "rfchunt_ci_audit.db"
    if db_path.exists():
        try:
            db_path.unlink()
        except OSError:
            pass

    argv = build_rfchunt_cli_argv(
        rfchunt_root,
        target_repo,
        report_dir,
        db_path,
        mode=mode,
        proxy=proxy,
        enable_poc=enable_poc,
        trust_max_files=trust_max,
        depth=depth,
    )
    print(f"[rfchunt-ci] Executing: {' '.join(argv)}", flush=True)
    proc = subprocess.run(argv, cwd=str(rfchunt_root), shell=False, check=False)
    if proc.returncode != 0:
        print(f"[rfchunt-ci] RFCHunt CLI exited with code {proc.returncode}", file=sys.stderr, flush=True)
        return int(proc.returncode)

    sarif_path, deep_summary, poc_summary = build_unified_ci_sarif(report_dir, target_repo)
    summary_md = render_step_summary(target_repo, mode, deep_summary, poc_summary, sarif_path)
    (report_dir / "CI_STEP_SUMMARY.md").write_text(summary_md, encoding="utf-8")

    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if gh_summary:
        with open(gh_summary, "a", encoding="utf-8") as fh:
            fh.write(summary_md + "\n")

    passed, gate_msg = evaluate_severity_gate(deep_summary, fail_on_sev)
    print(f"[rfchunt-ci] {gate_msg}", flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
