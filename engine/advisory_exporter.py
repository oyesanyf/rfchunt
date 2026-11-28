"""
GHSA Advisory, Formula-Safe CSV, and Encrypted Task Archive Exporter (Pillar 5)
===============================================================================
Exports verified RFCHunt findings, multi-step ARTEX attack chains, redacted HTTP
traffic receipts, and retest histories into:
1. GHSA-ready GitHub Security Advisory Markdown (`*.md`)
2. Formula-neutralized CSV (`*.csv`) defending against Excel/Calc CSV injection
3. AES-256-GCM encrypted task archives (`*.rfca`) with SHA-256 integrity checks
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from engine.secret_store import SecretBox

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n", "|")
_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-session-token",
    "x-csrf-token",
    "x-access-token",
}


def neutralize_csv_cell(value: Any) -> str:
    """
    Neutralizes spreadsheet formula injection (OWASP CSV Injection / ARTEX parity)
    by prefixing a leading single quote to any cell starting with `=`, `+`, `-`,
    `@`, tab (`\\t`), or carriage return (`\\r`), including leading-space variants.
    """
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if text[0] in _FORMULA_PREFIXES:
        return "'" + text
    stripped = text.lstrip()
    if stripped and stripped[0] in ("=", "+", "-", "@", "|"):
        return "'" + text
    return text


def redact_sensitive_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """
    Redacts credentials, bearer tokens, cookies, and API keys from HTTP headers
    while preserving auth scheme names (e.g., `Bearer <REDACTED>`) for triage.
    """
    if not headers or not isinstance(headers, dict):
        return {}
    redacted: dict[str, str] = {}
    for k, v in headers.items():
        key_str = str(k)
        val_str = str(v)
        if key_str.lower() in _SENSITIVE_HEADER_KEYS or "token" in key_str.lower() or "secret" in key_str.lower():
            if key_str.lower() in ("authorization", "proxy-authorization"):
                parts = val_str.strip().split(" ", 1)
                if len(parts) == 2 and parts[0]:
                    redacted[key_str] = f"{parts[0]} <REDACTED>"
                else:
                    redacted[key_str] = "<REDACTED>"
            elif key_str.lower() in ("cookie", "set-cookie"):
                # Preserve cookie names while redacting values
                pairs = []
                for chunk in val_str.split(";"):
                    chunk = chunk.strip()
                    if "=" in chunk:
                        cname, _ = chunk.split("=", 1)
                        pairs.append(f"{cname.strip()}=<REDACTED>")
                    elif chunk:
                        pairs.append(chunk)
                redacted[key_str] = "; ".join(pairs) if pairs else "<REDACTED>"
            else:
                redacted[key_str] = "<REDACTED>"
        else:
            redacted[key_str] = val_str
    return redacted


def _redact_inline_tokens(text: str) -> str:
    if not text:
        return ""
    out = re.sub(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        "<REDACTED_PRIVATE_KEY>",
        str(text),
    )
    out = re.sub(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "<REDACTED_JWT>", out)
    out = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer <REDACTED>", out)
    out = re.sub(r"\bgh[pous]_[A-Za-z0-9]{20,}\b", "<REDACTED_GITHUB_TOKEN>", out)
    out = re.sub(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "<REDACTED_GITHUB_PAT>", out)
    out = re.sub(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b", "<REDACTED_ANTHROPIC_KEY>", out)
    out = re.sub(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b", "<REDACTED_OPENAI_KEY>", out)
    out = re.sub(r"\bsk-[A-Za-z0-9]{48}\b", "<REDACTED_OPENAI_KEY>", out)
    out = re.sub(r"\bAIza[0-9A-Za-z_-]{35}\b", "<REDACTED_GOOGLE_API_KEY>", out)
    out = re.sub(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "<REDACTED_AWS_KEY>", out)
    out = re.sub(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b", "<REDACTED_STRIPE_KEY>", out)
    out = re.sub(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "<REDACTED_SLACK_TOKEN>", out)
    out = re.sub(
        r"([a-zA-Z][a-zA-Z0-9+.-]*://[^/@?#\s:\"'`<>]+:)[^/@?#\s\"'`<>]+(@)",
        r"\1<REDACTED>\2",
        out,
    )
    return out


def _fence_for(content: str, lang: str = "") -> tuple[str, str]:
    max_ticks = max((len(m.group(0)) for m in re.finditer(r"`+", content or "")), default=2)
    fence = "`" * max(3, max_ticks + 1)
    return f"{fence}{lang}", fence


def _decode_body_preview(body_b64: str | None, max_chars: int = 2000) -> str:
    if not body_b64:
        return ""
    try:
        raw = base64.b64decode(body_b64)
        text = raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        text = str(body_b64)
    text = _redact_inline_tokens(text)
    if len(text) > max_chars:
        return text[:max_chars] + "\n... [truncated]"
    return text


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "advisory")).strip("._")
    return cleaned[:96] or "advisory"


class AdvisoryExporter:
    """
    Exports GHSA Markdown advisories, formula-safe CSV sheets, and AES-256-GCM
    encrypted task archives from RFCHunt / ARTEX state.
    """

    def __init__(self, reports_dir: str | Path | None = None):
        self.reports_dir = Path(reports_dir) if reports_dir else Path("reports")

    def export_ghsa_markdown(
        self,
        chain: dict[str, Any],
        traffic_record: dict[str, Any] | None = None,
        retests: list[dict[str, Any]] | None = None,
        output_path: str | Path | None = None,
    ) -> str:
        """
        Renders a GHSA-ready GitHub Security Advisory Markdown report for a
        single attack chain (or finding) with redacted HTTP evidence and retest
        audit trail. Returns the rendered Markdown string (and writes to disk if
        `output_path` is provided).
        """
        chain_id = str(chain.get("chain_id") or chain.get("finding_id") or chain.get("node_id") or "CHAIN-UNKNOWN")
        title = str(chain.get("title") or chain.get("label") or chain.get("attack_type") or chain_id)
        attack_type = str(chain.get("attack_type") or chain.get("rule_id") or "MULTI_STEP_CHAIN")
        severity = str(chain.get("severity") or ("CRITICAL" if int(chain.get("hop_count") or 1) >= 3 or chain.get("has_ai_sink") else "HIGH")).upper()
        cwe = str(chain.get("cwe") or ("CWE-287" if "AUTH_BOUNDARY" in attack_type.upper() else "CWE-444"))
        poe_level = int(chain.get("poe_level") or 0)
        poe_labels = {
            0: "NONE",
            1: "PASSIVE_CORRELATION",
            2: "ACTIVE_ANOMALY",
            3: "VERIFIED_EXPLOIT",
        }
        poe_label = str(chain.get("poe_label") or poe_labels.get(poe_level, "NONE"))
        raw_ver_st = str(chain.get("verification_status") or "").strip().upper()
        if poe_level >= 3:
            ver_status = "FIXED" if raw_ver_st == "FIXED" else "VERIFIED"
        elif poe_level == 2:
            ver_status = "FIXED" if raw_ver_st == "FIXED" else "LEAD_ACTIVE_INDICATOR"
        elif poe_level == 1:
            ver_status = "FIXED" if raw_ver_st == "FIXED" else "LEAD_PASSIVE_CORRELATION"
        else:
            ver_status = "UNVERIFIED"
        if poe_level < 3 and title.upper().startswith("CONFIRMED:"):
            title = f"LEAD [POE={poe_level}]: " + title[len("CONFIRMED:") :].lstrip()
        target_host = str(chain.get("target_host") or chain.get("host") or "target")
        target_route = str(chain.get("target_route") or chain.get("target_endpoint") or chain.get("target_path") or "/")
        hop_count = int(chain.get("hop_count") or len(chain.get("chain_steps") or []) or 1)
        evidence_quote = _redact_inline_tokens(str(chain.get("evidence_quote") or ""))
        traffic_id = str(chain.get("traffic_id") or (traffic_record or {}).get("traffic_id") or "")
        evidence_text = _redact_inline_tokens(str(chain.get("evidence") or chain.get("description") or ""))
        remediation = str(
            chain.get("remediation")
            or (
                "Enforce strict audience (`aud`), authorized party (`azp`), and caller-type separation "
                "between end-user OIDC tokens and service-to-service credentials on internal/service routes."
                if "AUTH_BOUNDARY" in attack_type.upper()
                else "Enforce strict RFC 9112 framing normalization, authentication boundary checks, and least-privilege routing."
            )
        )
        source_scanners = chain.get("source_scanners") or []
        if isinstance(source_scanners, str):
            try:
                source_scanners = json.loads(source_scanners)
            except (json.JSONDecodeError, TypeError, ValueError):
                source_scanners = [source_scanners]
        chain_steps = chain.get("chain_steps") or chain.get("steps") or []
        if isinstance(chain_steps, str):
            try:
                chain_steps = json.loads(chain_steps)
            except (json.JSONDecodeError, TypeError, ValueError):
                chain_steps = []

        generated_at = datetime.now(UTC).isoformat()
        lines: list[str] = [
            f"# Security Advisory: {title}",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| **Advisory / Chain ID** | `{chain_id}` |",
            f"| **Severity** | **{severity}** |",
            f"| **CWE** | `{cwe}` |",
            f"| **Attack Class** | `{attack_type}` |",
            f"| **Target Surface** | `{target_host}` (`{target_route}`) |",
            f"| **Hop Count** | `{hop_count}` |",
            f"| **Proof-of-Exploit (POE)** | `POE={poe_level} ({poe_label})` — `{ver_status}` |",
            f"| **Correlated Scanners** | `{', '.join(str(s) for s in source_scanners) if source_scanners else 'RFCHunt-ARTEX'}` |",
            f"| **Evidence Traffic ID** | `{traffic_id or 'N/A'}` |",
            f"| **Generated (UTC)** | `{generated_at}` |",
            "",
            "## Summary",
            "",
            evidence_text or f"RFCHunt identified and correlated `{attack_type}` impacting `{target_host}` (`{target_route}`).",
            "",
        ]

        if chain_steps:
            lines.extend([
                "## Multi-Step Attack Chain Lineage",
                "",
                "| Step | Capability | Scanner | Finding / Description |",
                "|---|---|---|---|",
            ])
            for idx, step in enumerate(chain_steps, start=1):
                if isinstance(step, dict):
                    s_num = step.get("step", idx)
                    cap = str(step.get("capability") or "STEP")
                    sc = str(step.get("scanner") or "-")
                    desc = str(step.get("desc") or step.get("description") or step.get("finding_id") or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
                    lines.append(f"| {s_num} | `{cap}` | `{sc}` | {desc} |")
                else:
                    clean_step = str(step).replace("|", "\\|").replace("\r", " ").replace("\n", " ")
                    lines.append(f"| {idx} | `STEP` | `-` | {clean_step} |")
            lines.append("")

        if evidence_quote:
            f_open, f_close = _fence_for(evidence_quote, "text")
            lines.extend([
                "## Verbatim Proof-of-Exploit Quote",
                "",
                f_open,
                evidence_quote,
                f_close,
                "",
            ])

        if traffic_record:
            req_method = str(traffic_record.get("method") or "GET")
            req_url = str(traffic_record.get("url") or f"{target_host}{target_route}")
            req_headers = redact_sensitive_headers(traffic_record.get("request_headers") or {})
            resp_status = traffic_record.get("status_code") if traffic_record.get("status_code") is not None else traffic_record.get("response_status", "")
            resp_headers = redact_sensitive_headers(traffic_record.get("response_headers") or {})
            raw_req_b = str(traffic_record.get("request_body") or "")
            req_body = _redact_inline_tokens(raw_req_b) if raw_req_b else _decode_body_preview(traffic_record.get("request_body_b64"))
            resp_body = _decode_body_preview(traffic_record.get("response_body_b64"))
            rewrite_prov = traffic_record.get("rewrite_provenance") or []

            lines.extend([
                "## Redacted HTTP Traffic Receipt",
                "",
                f"- **Traffic ID**: `{traffic_record.get('traffic_id', traffic_id)}`",
                f"- **Captured At**: `{traffic_record.get('captured_at', '')}`",
                f"- **Response Status**: `HTTP {resp_status}`",
            ])
            if rewrite_prov:
                lines.append(f"- **Proxy Rewrite Provenance**: `{json.dumps(rewrite_prov)}`")
            req_open, req_close = _fence_for(req_body, "http")
            resp_open, resp_close = _fence_for(resp_body, "http")
            lines.extend([
                "",
                "### Request (Redacted)",
                "",
                req_open,
                f"{req_method} {req_url} HTTP/1.1",
            ])
            for hk, hv in req_headers.items():
                lines.append(f"{hk}: {hv}")
            if req_body:
                lines.append("")
                lines.append(req_body)
            lines.extend([
                req_close,
                "",
                "### Response (Redacted)",
                "",
                resp_open,
                f"HTTP/1.1 {resp_status}",
            ])
            for hk, hv in resp_headers.items():
                lines.append(f"{hk}: {hv}")
            if resp_body:
                lines.append("")
                lines.append(resp_body)
            lines.extend([resp_close, ""])

        if retests:
            lines.extend([
                "## Remediation & Retest Verification History",
                "",
                "| Retest ID | Verdict | Replay Traffic ID | Summary | Timestamp |",
                "|---|---|---|---|---|",
            ])
            for rt in retests:
                rid = str(rt.get("retest_id") or "-")
                verdict = str(rt.get("verdict") or "INCONCLUSIVE")
                rtid = str(rt.get("replay_traffic_id") or rt.get("traffic_id") or "-")
                rsum = str(rt.get("summary") or rt.get("evidence") or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
                rts = str(rt.get("tested_at") or rt.get("created_at") or "")
                lines.append(f"| `{rid}` | **{verdict}** | `{rtid}` | {rsum} | `{rts}` |")
            lines.append("")

        lines.extend([
            "## Recommended Remediation",
            "",
            remediation,
            "",
            "---",
            "*Generated by RFCHunt CLI (`engine/advisory_exporter.py`) with automatic credential redaction.*",
            "",
        ])

        markdown = "\n".join(lines)
        if output_path is not None:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(markdown, encoding="utf-8")
        return markdown

    def export_findings_csv(
        self,
        findings: Sequence[dict[str, Any]],
        chains: Sequence[dict[str, Any]] | None = None,
        output_path: str | Path | None = None,
    ) -> str:
        """
        Exports findings and attack chains to RFC 4180 CSV with mandatory
        formula-injection neutralization on every cell.
        """
        buf = io.StringIO()
        writer = csv.writer(buf)
        headers = [
            "record_type",
            "id",
            "rule_or_attack_type",
            "severity",
            "cwe",
            "title",
            "target_or_file",
            "poe_level",
            "verification_status",
            "hop_count",
            "traffic_id",
            "evidence_quote",
            "scanner",
        ]
        writer.writerow(headers)

        for item in findings or []:
            row = [
                "FINDING",
                item.get("finding_id") or item.get("id") or "",
                item.get("rule_id") or item.get("category") or "",
                item.get("severity") or "MEDIUM",
                item.get("cwe") or "",
                item.get("title") or "",
                f"{item.get('file_path') or item.get('file') or ''}:{item.get('line_number') or item.get('line') or ''}",
                item.get("poe_level") if item.get("poe_level") is not None else "",
                item.get("verification_status") or item.get("status") or "",
                item.get("hop_count") or 1,
                item.get("traffic_id") or "",
                item.get("evidence_quote") or item.get("evidence") or "",
                item.get("scanner") or "",
            ]
            writer.writerow([neutralize_csv_cell(c) for c in row])

        for ch in chains or []:
            ch_poe = int(ch.get("poe_level") if ch.get("poe_level") is not None else 0)
            ch_raw_st = str(ch.get("verification_status") or "").strip().upper()
            if ch_poe >= 3:
                ch_st = "FIXED" if ch_raw_st == "FIXED" else "VERIFIED"
            elif ch_poe == 2:
                ch_st = "FIXED" if ch_raw_st == "FIXED" else "LEAD_ACTIVE_INDICATOR"
            elif ch_poe == 1:
                ch_st = "FIXED" if ch_raw_st == "FIXED" else "LEAD_PASSIVE_CORRELATION"
            else:
                ch_st = "UNVERIFIED"
            row = [
                "ATTACK_CHAIN",
                ch.get("chain_id") or ch.get("node_id") or "",
                ch.get("attack_type") or "",
                ch.get("severity") or ("CRITICAL" if int(ch.get("hop_count") or 1) >= 3 else "HIGH"),
                ch.get("cwe") or "CWE-444",
                ch.get("label") or ch.get("title") or ch.get("attack_type") or "",
                f"{ch.get('target_host') or ''}{ch.get('target_route') or ch.get('target_endpoint') or ch.get('target_path') or ''}",
                ch_poe,
                ch_st,
                ch.get("hop_count") or 1,
                ch.get("traffic_id") or "",
                _redact_inline_tokens(str(ch.get("evidence_quote") or "")),
                ",".join(ch.get("source_scanners") or []) if isinstance(ch.get("source_scanners"), list) else str(ch.get("source_scanners") or "ARTEX"),
            ]
            writer.writerow([neutralize_csv_cell(c) for c in row])

        csv_text = buf.getvalue()
        if output_path is not None:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(csv_text, encoding="utf-8")
        return csv_text

    def export_task_archive(
        self,
        db: Any,
        output_path: str | Path,
        *,
        task_id: str | None = None,
        secret_box: SecretBox | None = None,
    ) -> dict[str, Any]:
        """
        Exports all persisted ARTEX task state from `db` into an AES-256-GCM
        encrypted archive (`*.rfca`) protected with a canonical SHA-256 digest.
        """
        box = secret_box or getattr(db, "secret_box", None) or SecretBox.from_env_or_keyfile(create_if_missing=True)
        if box is None:
            raise RuntimeError("No SecretBox encryption key available for encrypted archive export.")

        nodes = db.get_dual_graph_nodes() if hasattr(db, "get_dual_graph_nodes") else []
        edges = db.get_dual_graph_edges() if hasattr(db, "get_dual_graph_edges") else []
        if hasattr(db, "get_exploration_anchors"):
            try:
                anchors = db.get_exploration_anchors(task_id=task_id)
            except TypeError:
                anchors = db.get_exploration_anchors()
                if task_id:
                    anchors = [a for a in anchors if not a.get("task_id") or a.get("task_id") == task_id]
        else:
            anchors = []
        chains = db.get_attack_chains(limit=500, task_id=task_id) if hasattr(db, "get_attack_chains") else []
        traffic = db.list_traffic_evidence(task_id=task_id, limit=500) if hasattr(db, "list_traffic_evidence") else []
        todolist = db.get_todolist_items(task_id=task_id) if hasattr(db, "get_todolist_items") else []
        traces = db.list_worker_traces(task_id=task_id, limit=500) if hasattr(db, "list_worker_traces") else []
        retests = db.get_chain_retests(limit=500) if hasattr(db, "get_chain_retests") else []
        if task_id and retests:
            task_chain_ids = {str(c.get("chain_id") or "") for c in chains if c.get("chain_id")}
            retests = [r for r in retests if str(r.get("chain_id") or "") in task_chain_ids]
        approvals = db.get_approval_decisions(task_id=task_id, limit=500) if hasattr(db, "get_approval_decisions") else []
        llm_usage = db.get_task_llm_usage(task_id) if (task_id and hasattr(db, "get_task_llm_usage")) else {}

        payload = {
            "task_id": task_id or "ALL",
            "dual_graph_nodes": nodes,
            "dual_graph_edges": edges,
            "exploration_anchors": anchors,
            "attack_chains": chains,
            "traffic_evidence": traffic,
            "planner_todolist": todolist,
            "worker_traces": traces,
            "finding_retests": retests,
            "approval_decisions": approvals,
            "llm_usage": llm_usage,
        }
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sha256_hex = hashlib.sha256(canonical_payload).hexdigest()

        envelope = {
            "schema": "rfchunt-task-archive/v1",
            "task_id": task_id or "ALL",
            "exported_at": datetime.now(UTC).isoformat(),
            "sha256": sha256_hex,
            "payload": payload,
        }
        plaintext = json.dumps(envelope, sort_keys=True).encode("utf-8")
        ciphertext = box.encrypt_bytes(plaintext)

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(ciphertext)

        return {
            "path": str(out),
            "task_id": task_id or "ALL",
            "sha256": sha256_hex,
            "encrypted": True,
            "size_bytes": len(ciphertext),
            "counts": {
                "nodes": len(nodes),
                "edges": len(edges),
                "chains": len(chains),
                "traffic": len(traffic),
                "traces": len(traces),
                "retests": len(retests),
                "approvals": len(approvals),
            },
        }

    @staticmethod
    def import_task_archive(
        archive_path: str | Path,
        *,
        secret_box: SecretBox | None = None,
    ) -> dict[str, Any]:
        """
        Decrypts an AES-256-GCM `.rfca` archive and verifies its SHA-256 digest
        fail-closed before returning the unpacked dictionary.
        """
        box = secret_box or SecretBox.from_env_or_keyfile(create_if_missing=False)
        if box is None:
            raise RuntimeError("Encryption key required to decrypt task archive.")
        raw = Path(archive_path).read_bytes()
        plaintext = box.decrypt_bytes(raw)
        envelope = json.loads(plaintext.decode("utf-8"))
        if not isinstance(envelope, dict):
            raise ValueError("Task archive envelope malformed (expected JSON object).")  # noqa: TRY004
        if envelope.get("schema") != "rfchunt-task-archive/v1":
            raise ValueError(f"Unsupported task archive schema: {envelope.get('schema')}")
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("Task archive payload missing or malformed.")  # noqa: TRY004
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        actual_sha = hashlib.sha256(canonical).hexdigest()
        expected_sha = str(envelope.get("sha256") or "")
        if not expected_sha or actual_sha != expected_sha:
            raise ValueError(f"Archive SHA-256 mismatch: expected {expected_sha}, got {actual_sha}")
        return {
            "schema": envelope["schema"],
            "task_id": envelope.get("task_id"),
            "exported_at": envelope.get("exported_at"),
            "sha256": actual_sha,
            "verified": True,
            "payload": payload,
        }
