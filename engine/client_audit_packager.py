"""
Paid Client Security Audit Packager (Revenue Track 2 — Consulting Deliverables).
==============================================================================
Packages verified RFCHunt findings, verbatim Linux PoC transcripts, and recommended
patches into a turnkey 5-artifact client deliverable folder:
  1. 01_EXECUTIVE_SUMMARY.md
  2. 02_TECHNICAL_FINDINGS.md
  3. 03_FINDINGS_TRACKER.csv   (formula-injection neutralized via advisory_exporter)
  4. 04_FINDINGS.sarif         (SARIF 2.1.0 compliant)
  5. 05_AUDIT_DASHBOARD.html   (XSS-safe offline executive dashboard)
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import html
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from engine.advisory_exporter import (
    _redact_inline_tokens,
    neutralize_csv_cell,
    redact_sensitive_headers,
)


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


@dataclass
class AuditFinding:
    """Normalized verified security finding for client audit delivery."""

    finding_id: str
    title: str
    severity: str
    cwe: str
    affected_location: str
    summary: str
    impact: str
    remediation: str
    poc_verified: bool = False
    poc_transcript: str = ""
    patch_diff: str = ""
    repo_commit: str = ""
    headers: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], index: int = 1) -> "AuditFinding":
        sev = str(
            raw.get("severity")
            or raw.get("severity_rating")
            or raw.get("technical_severity")
            or "MEDIUM"
        ).upper()
        if sev not in _SEVERITY_ORDER:
            if "CRIT" in sev:
                sev = "CRITICAL"
            elif "HIGH" in sev:
                sev = "HIGH"
            elif "MED" in sev:
                sev = "MEDIUM"
            elif "LOW" in sev:
                sev = "LOW"
            else:
                sev = "INFO"

        cwe_val = raw.get("weakness_cwe") or raw.get("cwe") or "CWE-200"
        if isinstance(cwe_val, list):
            cwe_str = ", ".join(str(x) for x in cwe_val)
        else:
            cwe_str = str(cwe_val)

        affected = raw.get("affected_location")
        if not affected:
            af = raw.get("affected_files")
            if isinstance(af, list) and af:
                affected = ", ".join(str(x) for x in af[:4])
            else:
                affected = str(raw.get("repo") or "unspecified")

        return cls(
            finding_id=str(raw.get("finding_id") or f"F-{index:02d}"),
            title=str(raw.get("title") or f"Untitled Finding {index}"),
            severity=sev,
            cwe=cwe_str,
            affected_location=str(affected),
            summary=str(raw.get("summary") or raw.get("vulnerability_information") or ""),
            impact=str(raw.get("impact") or ""),
            remediation=str(raw.get("remediation") or "Apply input validation and least-privilege controls."),
            poc_verified=bool(raw.get("poc_verified", False)),
            poc_transcript=str(raw.get("poc_transcript") or ""),
            patch_diff=str(raw.get("patch_diff") or ""),
            repo_commit=str(raw.get("head_commit") or raw.get("commit") or ""),
            headers=dict(raw.get("headers") or {}),
        )


@dataclass
class PackagedAuditBundle:
    """Paths to all 5 generated client deliverable artifacts."""

    client_name: str
    out_dir: Path
    executive_summary_md: Path
    technical_findings_md: Path
    findings_tracker_csv: Path
    findings_sarif: Path
    dashboard_html: Path
    finding_counts: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "client_name": self.client_name,
            "out_dir": str(self.out_dir),
            "executive_summary_md": str(self.executive_summary_md),
            "technical_findings_md": str(self.technical_findings_md),
            "findings_tracker_csv": str(self.findings_tracker_csv),
            "findings_sarif": str(self.findings_sarif),
            "dashboard_html": str(self.dashboard_html),
            "finding_counts": dict(self.finding_counts),
        }


class ClientAuditPackager:
    """Builds client-ready Markdown, CSV, SARIF 2.1.0, and HTML security audit deliverables."""

    def package(
        self,
        *,
        client_name: str,
        scope_description: str,
        findings: Sequence[Union[AuditFinding, Dict[str, Any]]],
        out_dir: Union[str, Path],
        auditor_name: str = "RFCHunt Security Engineering",
        transcripts_by_id: Optional[Dict[str, str]] = None,
    ) -> PackagedAuditBundle:
        dest = Path(out_dir)
        dest.mkdir(parents=True, exist_ok=True)
        audit_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        normalized: List[AuditFinding] = []
        for idx, item in enumerate(findings, start=1):
            f = item if isinstance(item, AuditFinding) else AuditFinding.from_dict(item, index=idx)
            if transcripts_by_id and f.finding_id in transcripts_by_id and not f.poc_transcript:
                f.poc_transcript = transcripts_by_id[f.finding_id]
                f.poc_verified = True
            normalized.append(f)

        normalized.sort(key=lambda x: (_SEVERITY_ORDER.get(x.severity, 9), x.finding_id))

        counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for f in normalized:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        exec_path = dest / "01_EXECUTIVE_SUMMARY.md"
        tech_path = dest / "02_TECHNICAL_FINDINGS.md"
        csv_path = dest / "03_FINDINGS_TRACKER.csv"
        sarif_path = dest / "04_FINDINGS.sarif"
        html_path = dest / "05_AUDIT_DASHBOARD.html"

        exec_path.write_text(
            self._render_executive_summary(client_name, scope_description, auditor_name, audit_date, normalized, counts),
            encoding="utf-8",
        )
        tech_path.write_text(
            self._render_technical_findings(client_name, audit_date, normalized),
            encoding="utf-8",
        )
        csv_path.write_text(self._render_csv(normalized), encoding="utf-8")
        sarif_path.write_text(
            json.dumps(self._build_sarif(client_name, normalized), indent=2),
            encoding="utf-8",
        )
        html_path.write_text(
            self._render_html_dashboard(client_name, scope_description, audit_date, normalized, counts),
            encoding="utf-8",
        )

        return PackagedAuditBundle(
            client_name=client_name,
            out_dir=dest,
            executive_summary_md=exec_path,
            technical_findings_md=tech_path,
            findings_tracker_csv=csv_path,
            findings_sarif=sarif_path,
            dashboard_html=html_path,
            finding_counts=counts,
        )

    def _render_executive_summary(
        self,
        client_name: str,
        scope_description: str,
        auditor_name: str,
        audit_date: str,
        findings: Sequence[AuditFinding],
        counts: Dict[str, int],
    ) -> str:
        verified_n = sum(1 for f in findings if f.poc_verified)
        lines = [
            f"# Security Audit Executive Summary — {client_name}",
            "",
            f"- **Audit Date (UTC):** `{audit_date}`",
            f"- **Prepared By:** `{auditor_name}`",
            f"- **Scope:** {scope_description}",
            f"- **Total Findings:** `{len(findings)}` (`{verified_n}` runtime-verified in isolated Linux)",
            "",
            "## Severity Distribution",
            "",
            "| Severity | Count | Priority SLA |",
            "|---|---:|---|",
            f"| **CRITICAL** | {counts['CRITICAL']} | P0 — Remediate immediately (24–48h) |",
            f"| **HIGH** | {counts['HIGH']} | P1 — Remediate within 7 days |",
            f"| **MEDIUM** | {counts['MEDIUM']} | P2 — Remediate within 30 days |",
            f"| **LOW** | {counts['LOW']} | P3 — Next scheduled hardening sprint |",
            f"| **INFO** | {counts['INFO']} | Hardening recommendation |",
            "",
            "## Findings Register",
            "",
            "| ID | Severity | CWE | Runtime PoC | Title |",
            "|---|---|---|---|---|",
        ]
        for f in findings:
            safe_title = f.title.replace("|", "\\|")
            poc_badge = "Verified" if f.poc_verified else "Static"
            lines.append(f"| `{f.finding_id}` | **{f.severity}** | `{f.cwe}` | {poc_badge} | {safe_title} |")
        return "\n".join(lines) + "\n"

    def _render_technical_findings(
        self,
        client_name: str,
        audit_date: str,
        findings: Sequence[AuditFinding],
    ) -> str:
        lines = [
            f"# Technical Security Findings — {client_name}",
            "",
            f"- **Audit Date (UTC):** `{audit_date}`",
            "",
        ]
        for f in findings:
            redacted_summary = _redact_inline_tokens(f.summary)
            redacted_impact = _redact_inline_tokens(f.impact)
            redacted_transcript = _redact_inline_tokens(f.poc_transcript)
            lines.extend(
                [
                    f"## [{f.finding_id}] {f.title}",
                    "",
                    f"- **Severity:** `{f.severity}`",
                    f"- **Weakness (CWE):** `{f.cwe}`",
                    f"- **Affected Location:** `{f.affected_location}`",
                    f"- **Commit / Ref:** `{f.repo_commit or 'HEAD'}`",
                    f"- **Runtime PoC Verified:** `{f.poc_verified}`",
                    "",
                ]
            )
            if f.headers:
                redacted_h = redact_sensitive_headers(f.headers)
                lines.append(f"- **Captured Headers (Redacted):** `{json.dumps(redacted_h)}`")
                lines.append("")
            if redacted_summary:
                lines.extend(["### Technical Analysis", "", redacted_summary, ""])
            if redacted_impact:
                lines.extend(["### Business & Security Impact", "", redacted_impact, ""])
            if redacted_transcript:
                lines.extend(
                    [
                        "### Verbatim Linux Verification Transcript",
                        "",
                        "```text",
                        redacted_transcript.rstrip(),
                        "```",
                        "",
                    ]
                )
            lines.extend(["### Recommended Remediation", "", f.remediation, ""])
            if f.patch_diff.strip():
                lines.extend(["```diff", f.patch_diff.rstrip(), "```", ""])
            lines.append("---")
            lines.append("")
        return "\n".join(lines)

    def _render_csv(self, findings: Sequence[AuditFinding]) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ID", "Severity", "CWE", "PoC_Verified", "Affected_Location", "Title", "Remediation"])
        for f in findings:
            writer.writerow(
                [
                    neutralize_csv_cell(f.finding_id),
                    neutralize_csv_cell(f.severity),
                    neutralize_csv_cell(f.cwe),
                    neutralize_csv_cell(str(f.poc_verified)),
                    neutralize_csv_cell(f.affected_location),
                    neutralize_csv_cell(f.title),
                    neutralize_csv_cell(f.remediation[:400]),
                ]
            )
        return buf.getvalue()

    def _build_sarif(self, client_name: str, findings: Sequence[AuditFinding]) -> Dict[str, Any]:
        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        seen_rules: set[str] = set()
        for f in findings:
            rule_id = f"RFCHUNT-{f.finding_id}"
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "name": f.title[:120],
                        "shortDescription": {"text": f.title},
                        "properties": {"cwe": f.cwe, "severity": f.severity},
                    }
                )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _SARIF_LEVEL.get(f.severity, "warning"),
                    "message": {"text": _redact_inline_tokens(f.impact or f.title)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.affected_location.split(",")[0].strip()}
                            }
                        }
                    ],
                }
            )
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "RFCHunt Client Security Audit",
                            "informationUri": "https://github.com/oyesanyf/rfchunt",
                            "rules": rules,
                        }
                    },
                    "properties": {"client": client_name},
                    "results": results,
                }
            ],
        }

    def _render_html_dashboard(
        self,
        client_name: str,
        scope_description: str,
        audit_date: str,
        findings: Sequence[AuditFinding],
        counts: Dict[str, int],
    ) -> str:
        rows = []
        for f in findings:
            rows.append(
                "<tr>"
                f"<td><code>{html.escape(f.finding_id)}</code></td>"
                f"<td><strong>{html.escape(f.severity)}</strong></td>"
                f"<td><code>{html.escape(f.cwe)}</code></td>"
                f"<td>{'Yes' if f.poc_verified else 'Static'}</td>"
                f"<td>{html.escape(f.title)}</td>"
                f"<td><code>{html.escape(f.affected_location)}</code></td>"
                "</tr>"
            )
        return (
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<title>Security Audit Dashboard - {html.escape(client_name)}</title>"
            "<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#111;background:#fafafa;}"
            "table{border-collapse:collapse;width:100%;background:#fff;}th,td{border:1px solid #ddd;padding:.6rem;text-align:left;}"
            "th{background:#f0f2f5;}.cards{display:flex;gap:1rem;margin:1rem 0;}"
            ".card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:.8rem 1.2rem;min-width:110px;}</style>"
            "</head><body>"
            f"<h1>Security Audit Dashboard — {html.escape(client_name)}</h1>"
            f"<p><strong>Date:</strong> {html.escape(audit_date)} | <strong>Scope:</strong> {html.escape(scope_description)}</p>"
            "<div class=\"cards\">"
            f"<div class=\"card\"><strong>CRITICAL</strong><div>{counts['CRITICAL']}</div></div>"
            f"<div class=\"card\"><strong>HIGH</strong><div>{counts['HIGH']}</div></div>"
            f"<div class=\"card\"><strong>MEDIUM</strong><div>{counts['MEDIUM']}</div></div>"
            f"<div class=\"card\"><strong>LOW</strong><div>{counts['LOW']}</div></div>"
            "</div>"
            "<table><thead><tr><th>ID</th><th>Severity</th><th>CWE</th><th>PoC Verified</th><th>Title</th><th>Location</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "</body></html>\n"
        )
