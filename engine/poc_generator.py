"""
Non-Destructive PoC Verification, Source-Aware False-Positive Triage & Regression Bundle Exporter.

Strictly defensive and CLI-only (zero GUI, zero weaponized payloads, zero destructive verbs).
Transforms RFCHunt findings (from `--all` unified scans, `combined_audit_summary.json`, or SQLite
`terminator.db` protocol research results) into:
  1. Source-aware triage verdicts distinguishing real reproducible issues (`VERIFIED_REPRODUCIBLE`),
     unverified production leads (`UNVERIFIED_CANDIDATE`), minor defense-in-depth notes
     (`HARDENING_NOTE`), synthetic test fixtures (`TEST_FIXTURE`), and false positives
     (`FALSE_POSITIVE`, e.g., regex patterns, comments, or passive `POE=1` chains over rejected roots).
  2. Standalone, non-destructive verification/regression test scripts (`verify_*.py`):
     - Code/repo findings: read-only static/AST invariant assertions (zero shell execution, zero
       target mutation, `--network=none` compatible, automatic secret redaction).
     - Protocol findings: strictly loopback-only (`127.0.0.1`/`localhost`/`::1` fail-closed) 3-trial
       RFC framing conformance verifiers paired with ModSecurity SecRules and Suricata IDS rules.
  3. Disclosure-ready `POC_INDEX.md` and machine-readable `poc_manifest.json` saved strictly inside
     the caller-specified output directory.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from engine.exploit_exporter import ExploitExporter
from engine.poe_container_verifier import (
    ContainerPOEVerifier,
    is_explicit_loopback_host,
)

# Strictly bounded source read limit to maintain memory discipline
MAX_SOURCE_BYTES = 512 * 1024
DEFAULT_MAX_POCS = 50

VERDICT_VERIFIED_REPRODUCIBLE = "VERIFIED_REPRODUCIBLE"
VERDICT_UNVERIFIED_CANDIDATE = "UNVERIFIED_CANDIDATE"
VERDICT_HARDENING_NOTE = "HARDENING_NOTE"
VERDICT_FALSE_POSITIVE = "FALSE_POSITIVE"
VERDICT_TEST_FIXTURE = "TEST_FIXTURE"

ALL_VERDICTS = (
    VERDICT_VERIFIED_REPRODUCIBLE,
    VERDICT_UNVERIFIED_CANDIDATE,
    VERDICT_HARDENING_NOTE,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TEST_FIXTURE,
)

_DESTRUCTIVE_HTTP_VERBS = frozenset({"DELETE", "PUT", "PATCH", "MKCOL", "PROPPATCH", "MOVE"})

_TEST_DIR_SEGMENTS = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures", "testdata", "mocks"}
)
_TEST_FILE_RE = re.compile(
    r"(^test_.*|\.(test|spec)\.[A-Za-z0-9]+$|_test\.[A-Za-z0-9]+$|Test\.[A-Za-z0-9]+$)",
    re.IGNORECASE,
)

_REGEX_CONTEXT_RE = re.compile(
    r"(/[^\n/]{4,}/[gimsuy]*\s*\.\s*(exec|test|match)\b"
    r"|/-----BEGIN\b"
    r"|re\.compile\s*\("
    r"|Regex::new\s*\("
    r"|regexp\.MustCompile\s*\("
    r"|new\s+RegExp\s*\("
    r"|\b(pattern|regex|re_[a-z0-9_]+)\s*[:=])",
    re.IGNORECASE,
)

_PLACEHOLDER_SECRET_RE = re.compile(
    r"\b(EXAMPLE|DUMMY|FAKE|PLACEHOLDER|YOUR_KEY|TEST_KEY|SAMPLE_KEY|CHANGEME|REDACTED|AKIAIOSFODNN7EXAMPLE)\b",
    re.IGNORECASE,
)

_SECRET_LITERAL_RE = re.compile(
    r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bghp_[A-Za-z0-9]{36}\b"
    r"|\bsk-[A-Za-z0-9]{20,}\b)"
)

_COMMENT_LINE_RE = re.compile(r"^\s*(///|//!|//|#|/\*|\*|--|<!--)")

_TRADEOFF_DOC_RE = re.compile(
    r"\b(accepted\s+trade[- ]?off|trade[- ]?off|dacl|intentional|deliberately|by\s+design)\b",
    re.IGNORECASE,
)

_CMD_CALL_RE = re.compile(
    r"\b(execSync|exec|execFileSync|spawnSync|spawn|system|popen|run|Popen)\s*\(\s*([^,\)\n]+)",
)

_STATIC_LITERAL_RE = re.compile(r"""^(?:r|b|u)?(?:'[^']*'|"(?:[^"\\]|\\.)*")$""")

_DYNAMIC_EXPR_RE = re.compile(
    r"(\$\{|\+|\bf['\"]|%s|\bformat\s*\(|\breq\.|\brequest\.|\bargv\b|\binput\b|\bparams\b|\bquery\b|\bbody\b|\buser)"
)

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_VERDICT_ORDER = {
    VERDICT_VERIFIED_REPRODUCIBLE: 0,
    VERDICT_UNVERIFIED_CANDIDATE: 1,
    VERDICT_HARDENING_NOTE: 2,
    VERDICT_FALSE_POSITIVE: 3,
    VERDICT_TEST_FIXTURE: 4,
}


@dataclass
class PoCTriageRecord:
    """Single finding triage decision and generated non-destructive verification artifact record."""

    finding_id: str
    rule_id: str
    title: str
    original_severity: str
    calibrated_severity: str
    file_path: str
    line: Optional[int]
    verdict: str
    poe_level: int
    disclosure_worthy: bool
    rationale: str
    remediation: str
    evidence_snippet: str = ""
    category: str = "code"
    generated_files: List[str] = field(default_factory=list)
    verification_status: str = "triaged"

    def to_dict(self) -> Dict[str, Any]:
        from engine.epistemic_state import attach_epistemic_metadata

        out = {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "original_severity": self.original_severity,
            "calibrated_severity": self.calibrated_severity,
            "file_path": self.file_path,
            "line": self.line,
            "verdict": self.verdict,
            "poe_level": self.poe_level,
            "disclosure_worthy": self.disclosure_worthy,
            "rationale": self.rationale,
            "remediation": self.remediation,
            "evidence_snippet": self.evidence_snippet,
            "category": self.category,
            "generated_files": list(self.generated_files),
            "verification_status": self.verification_status,
        }
        is_rt = self.verdict == VERDICT_VERIFIED_REPRODUCIBLE and int(self.poe_level) >= 3 and self.category != "secret"
        is_stat = self.verdict == VERDICT_VERIFIED_REPRODUCIBLE and self.category == "secret"
        is_ref = self.verdict in (VERDICT_FALSE_POSITIVE, VERDICT_TEST_FIXTURE, VERDICT_HARDENING_NOTE)
        attach_epistemic_metadata(
            out,
            runtime_poe_verified=is_rt,
            static_invariant_verified=is_stat,
            refuted=is_ref,
        )
        return out


@dataclass
class PoCBundleReport:
    """Summary report for a `--poc` verification and false-positive triage run."""

    target_path: Optional[str]
    output_dir: str
    total_findings_analyzed: int
    verdict_counts: Dict[str, int]
    disclosure_worthy_count: int
    generated_script_count: int
    records: List[PoCTriageRecord] = field(default_factory=list)
    index_markdown_path: str = ""
    manifest_json_path: str = ""
    container_verification: Optional[Dict[str, Any]] = None
    elapsed_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": "completed",
            "target_path": self.target_path,
            "output_dir": self.output_dir,
            "total_findings_analyzed": self.total_findings_analyzed,
            "verdict_counts": dict(self.verdict_counts),
            "disclosure_worthy_count": self.disclosure_worthy_count,
            "generated_script_count": self.generated_script_count,
            "index_markdown_path": self.index_markdown_path,
            "manifest_json_path": self.manifest_json_path,
            "container_verification": self.container_verification,
            "elapsed_sec": round(self.elapsed_sec, 3),
            "records": [r.to_dict() for r in self.records],
        }


def _sanitize_slug(value: str, fallback: str = "finding", max_len: int = 44) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    if not cleaned:
        cleaned = fallback
    return cleaned[:max_len]


def _redact_secrets(text: str) -> str:
    """Redacts potential secret tokens so verification reports never leak real credentials."""
    if not text:
        return ""
    redacted = re.sub(
        r"-----BEGIN ((?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY)-----[\s\S]{0,4000}?-----END \1-----",
        "***REDACTED_PRIVATE_KEY_BLOCK***",
        text,
    )
    redacted = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "AKIA***REDACTED***", redacted)
    redacted = re.sub(r"\bghp_[A-Za-z0-9]{36}\b", "ghp_***REDACTED***", redacted)
    redacted = re.sub(r"\bsk-[A-Za-z0-9]{20,}\b", "sk-***REDACTED***", redacted)
    return redacted


def _is_test_fixture_path(file_path: str) -> bool:
    if not file_path:
        return False
    norm = file_path.replace("\\", "/")
    parts = [p.lower() for p in norm.split("/") if p]
    if any(seg in _TEST_DIR_SEGMENTS for seg in parts[:-1]):
        return True
    if parts and _TEST_FILE_RE.search(parts[-1]):
        return True
    return False


def _extract_line_number(finding: Dict[str, Any]) -> Optional[int]:
    for key in ("line", "line_number", "start_line", "lineno"):
        val = finding.get(key)
        if isinstance(val, int) and val > 0:
            return val
        if isinstance(val, str) and val.isdigit() and int(val) > 0:
            return int(val)
    for key in ("location", "file", "file_path", "evidence", "description"):
        val = str(finding.get(key) or "")
        m = re.search(r":(\d{1,6})(?:\b|$)", val)
        if m:
            num = int(m.group(1))
            if num > 0:
                return num
    return None


def _extract_file_path(finding: Dict[str, Any]) -> str:
    raw = str(
        finding.get("file_path")
        or finding.get("file")
        or finding.get("path")
        or finding.get("location")
        or ""
    ).strip()
    # Strip trailing :line suffix if embedded in location field (preserving Windows drive C:\)
    m = re.match(r"^([A-Za-z]:[\\/].+|[^:]+):(\d{1,6})$", raw)
    if m:
        return m.group(1).strip()
    return raw


def _safe_resolve_under_repo(
    file_path: str,
    repo_path: Optional[Union[str, Path]],
) -> Optional[Path]:
    """Resolves `file_path` strictly inside `repo_path` (fail-closed against traversal)."""
    if not file_path or file_path in ("network-target", "unknown", "N/A"):
        return None
    if not repo_path:
        return None
    try:
        repo_root = Path(repo_path).resolve(strict=False)
        candidate_raw = Path(file_path)
        candidate = (
            candidate_raw.resolve(strict=False)
            if candidate_raw.is_absolute()
            else (repo_root / candidate_raw).resolve(strict=False)
        )
        if not candidate.is_relative_to(repo_root):
            return None
        if candidate.is_file():
            return candidate
    except Exception:
        return None
    return None


def _read_bounded_source(path: Optional[Path]) -> Tuple[List[str], bool]:
    if not path or not path.is_file():
        return [], False
    try:
        raw = path.read_bytes()[:MAX_SOURCE_BYTES]
        text = raw.decode("utf-8", errors="replace")
        return text.splitlines(), True
    except Exception:
        return [], False


def _resolve_constant_binding(lines: List[str], ident: str) -> Optional[str]:
    """Looks up a simple same-file constant string binding (TS/JS/Python/Rust/Go)."""
    if not ident or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", ident):
        return None
    escaped = re.escape(ident)
    patterns = (
        re.compile(rf"\b(?:const|let|var|final)\s+{escaped}\s*(?::[^=]+)?=\s*(['\"])((?:\\.|(?!\1).)*)\1"),
        re.compile(rf"^\s*{escaped}\s*(?::[^=]+)?=\s*(['\"])((?:\\.|(?!\1).)*)\1"),
        re.compile(rf"\b(?:pub\s+)?(?:const|static)\s+{escaped}\s*:[^=]+=\s*\"((?:\\.|[^\"])*)\""),
    )
    for ln in lines[:1200]:
        for pat in patterns:
            m = pat.search(ln)
            if m:
                val = m.group(m.lastindex) if m.lastindex else ""
                if "${" not in val:
                    return val
    return None


def _is_protocol_finding(finding: Dict[str, Any]) -> bool:
    raw_probe = finding.get("raw_probe") or finding.get("minimized_probe")
    if raw_probe:
        return True
    rule = str(finding.get("rule_id") or "").upper()
    if rule.startswith(("RFC-", "DESYNC-", "HTTP-", "VULN-RFC")):
        return True
    if finding.get("rfc_num") and (finding.get("reproducibility_rate") is not None):
        return True
    return False


def _is_chain_finding(finding: Dict[str, Any]) -> bool:
    rule = str(finding.get("rule_id") or "").upper()
    source = str(finding.get("source") or finding.get("engine") or "").upper()
    return rule.startswith("ARTEX-") or source == "ARTEX" or bool(finding.get("chain_id"))


def _extract_snippet(lines: List[str], line_num: Optional[int], radius: int = 3) -> str:
    if not lines:
        return ""
    if line_num is None or line_num < 1 or line_num > len(lines):
        return ""
    start = max(1, line_num - radius)
    end = min(len(lines), line_num + radius)
    out = [f"{i}: {lines[i - 1]}" for i in range(start, end + 1)]
    return _redact_secrets("\n".join(out))


def _triage_single_finding(
    idx: int,
    finding: Dict[str, Any],
    *,
    repo_path: Optional[Union[str, Path]] = None,
) -> PoCTriageRecord:
    """Performs source-aware, strictly non-destructive triage on a single non-chain finding."""
    rule_id = str(finding.get("rule_id") or finding.get("id") or f"FINDING-{idx + 1}").strip()
    finding_id = str(finding.get("finding_id") or finding.get("vuln_id") or f"{rule_id}-{idx + 1}").strip()
    title = str(finding.get("title") or finding.get("description") or rule_id).strip()
    orig_sev = str(finding.get("severity") or "MEDIUM").upper()
    file_path = _extract_file_path(finding)
    line_num = _extract_line_number(finding)
    rule_upper = rule_id.upper()
    title_lower = title.lower()
    desc_lower = str(finding.get("description") or "").lower()
    combined_text = f"{rule_upper} {title_lower} {desc_lower}"

    # 1. Protocol RFC finding
    if _is_protocol_finding(finding):
        attempts = int(finding.get("verification_attempts") or 0)
        repro_rate = float(finding.get("reproducibility_rate") or 0.0)
        poe = int(finding.get("poe_level") or (3 if attempts >= 3 and repro_rate >= 0.66 else 1))
        if attempts >= 3 and repro_rate >= 0.66:
            return PoCTriageRecord(
                finding_id=finding_id,
                rule_id=rule_id,
                title=title,
                original_severity=orig_sev,
                calibrated_severity=orig_sev if orig_sev in ("CRITICAL", "HIGH") else "HIGH",
                file_path=file_path or "protocol-target",
                line=line_num,
                verdict=VERDICT_VERIFIED_REPRODUCIBLE,
                poe_level=max(poe, 3),
                disclosure_worthy=True,
                rationale=(
                    f"Confirmed reproducible RFC protocol anomaly ({attempts} trials, "
                    f"{repro_rate * 100:.1f}% reproducibility). Loopback-only conformance "
                    "reproducer and ModSecurity/Suricata defenses generated."
                ),
                remediation=(
                    "Reject ambiguous HTTP framing (conflicting Content-Length/Transfer-Encoding, "
                    "CRLF/obs-fold/bare-LF) with 400 Bad Request per RFC 9112 and deploy the "
                    "exported ModSecurity/Suricata rules."
                ),
                evidence_snippet=_redact_secrets(str(finding.get("raw_probe") or finding.get("minimized_probe") or "")[:300]),
                category="protocol",
                verification_status="verified_protocol_3trial",
            )
        return PoCTriageRecord(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            original_severity=orig_sev,
            calibrated_severity="MEDIUM",
            file_path=file_path or "protocol-target",
            line=line_num,
            verdict=VERDICT_UNVERIFIED_CANDIDATE,
            poe_level=min(poe, 1),
            disclosure_worthy=False,
            rationale=(
                f"Protocol anomaly has fewer than 3 confirmed trials (attempts={attempts}, "
                f"rate={repro_rate:.2f}); requires 3-trial loopback reproduction before disclosure."
            ),
            remediation="Re-run against an authorized local test lab (`127.0.0.1`) with >=3 trials.",
            evidence_snippet=_redact_secrets(str(finding.get("raw_probe") or "")[:300]),
            category="protocol",
            verification_status="needs_3trial_confirmation",
        )

    # 2. Test-fixture gate
    if _is_test_fixture_path(file_path):
        return PoCTriageRecord(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            original_severity=orig_sev,
            calibrated_severity="INFO",
            file_path=file_path,
            line=line_num,
            verdict=VERDICT_TEST_FIXTURE,
            poe_level=0,
            disclosure_worthy=False,
            rationale="Flagged path is inside a test/fixture file, not production runtime code.",
            remediation="Confirm test credentials/keys are synthetic and excluded from production bundles.",
            category="code",
            verification_status="rejected_test_fixture",
        )

    resolved_path = _safe_resolve_under_repo(file_path, repo_path)
    lines, has_source = _read_bounded_source(resolved_path)
    target_line = lines[line_num - 1] if (has_source and line_num and 1 <= line_num <= len(lines)) else ""
    window_lines = (
        lines[max(0, line_num - 5) : min(len(lines), line_num + 5)]
        if (has_source and line_num and 1 <= line_num <= len(lines))
        else []
    )
    window_text = "\n".join(window_lines)
    snippet = _extract_snippet(lines, line_num)

    # 3. Secret-exposure triage (RAPTOR-SECRET-EXPOSED / CWE-798)
    if "SECRET" in rule_upper or "CWE-798" in combined_text or "private key" in title_lower or "access key" in title_lower:
        if has_source and line_num:
            if _COMMENT_LINE_RE.match(target_line):
                return PoCTriageRecord(
                    finding_id=finding_id,
                    rule_id=rule_id,
                    title=title,
                    original_severity=orig_sev,
                    calibrated_severity="INFO",
                    file_path=file_path,
                    line=line_num,
                    verdict=VERDICT_FALSE_POSITIVE,
                    poe_level=0,
                    disclosure_worthy=False,
                    rationale="Flagged line is a source comment rather than an embedded credential.",
                    remediation="No action required.",
                    evidence_snippet=snippet,
                    category="secret",
                    verification_status="rejected_comment_line",
                )
            if _REGEX_CONTEXT_RE.search(window_text):
                return PoCTriageRecord(
                    finding_id=finding_id,
                    rule_id=rule_id,
                    title=title,
                    original_severity=orig_sev,
                    calibrated_severity="INFO",
                    file_path=file_path,
                    line=line_num,
                    verdict=VERDICT_FALSE_POSITIVE,
                    poe_level=0,
                    disclosure_worthy=False,
                    rationale=(
                        "Flagged line is a regular-expression pattern validator (e.g., PEM/header "
                        "parsing regex), not a hardcoded private key or live credential."
                    ),
                    remediation="No security fix needed; optionally exclude regex literals in scanner rules.",
                    evidence_snippet=snippet,
                    category="secret",
                    verification_status="rejected_regex_pattern",
                )
            if _PLACEHOLDER_SECRET_RE.search(window_text):
                return PoCTriageRecord(
                    finding_id=finding_id,
                    rule_id=rule_id,
                    title=title,
                    original_severity=orig_sev,
                    calibrated_severity="INFO",
                    file_path=file_path,
                    line=line_num,
                    verdict=VERDICT_FALSE_POSITIVE,
                    poe_level=0,
                    disclosure_worthy=False,
                    rationale="Flagged string contains an explicit placeholder/example marker.",
                    remediation="Confirm placeholder is never accepted as a live authentication token.",
                    evidence_snippet=snippet,
                    category="secret",
                    verification_status="rejected_placeholder",
                )
            if _SECRET_LITERAL_RE.search(window_text):
                return PoCTriageRecord(
                    finding_id=finding_id,
                    rule_id=rule_id,
                    title=title,
                    original_severity=orig_sev,
                    calibrated_severity="CRITICAL",
                    file_path=file_path,
                    line=line_num,
                    verdict=VERDICT_VERIFIED_REPRODUCIBLE,
                    poe_level=3,
                    disclosure_worthy=True,
                    rationale=(
                        "Confirmed literal credential/private-key material in non-test production "
                        "source outside comments and regex patterns (value redacted in outputs)."
                    ),
                    remediation=(
                        "Immediately rotate/revoke the exposed credential, purge it from git history, "
                        "and load secrets exclusively from a runtime secret store or environment."
                    ),
                    evidence_snippet=snippet,
                    category="secret",
                    verification_status="verified_literal_secret",
                )
        return PoCTriageRecord(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            original_severity=orig_sev,
            calibrated_severity="MEDIUM",
            file_path=file_path,
            line=line_num,
            verdict=VERDICT_UNVERIFIED_CANDIDATE,
            poe_level=1,
            disclosure_worthy=False,
            rationale="Secret-exposure candidate could not be confirmed against target source line.",
            remediation="Inspect the flagged line manually to verify whether live key material exists.",
            evidence_snippet=snippet,
            category="secret",
            verification_status="unverified_no_source_match",
        )

    # 4. Comment-only lines (including documented trade-off doc comments like install.rs:75)
    if has_source and line_num and _COMMENT_LINE_RE.match(target_line):
        doc_window = "\n".join(lines[max(0, line_num - 3) : min(len(lines), line_num + 22)])
        if _TRADEOFF_DOC_RE.search(doc_window):
            return PoCTriageRecord(
                finding_id=finding_id,
                rule_id=rule_id,
                title=title,
                original_severity=orig_sev,
                calibrated_severity="LOW",
                file_path=file_path,
                line=line_num,
                verdict=VERDICT_HARDENING_NOTE,
                poe_level=0,
                disclosure_worthy=False,
                rationale=(
                    "Flagged line is a documentation comment explicitly describing an accepted "
                    "architectural/DACL trade-off rather than an undisclosed code flaw."
                ),
                remediation=(
                    "Review whether the documented multi-user/DACL trade-off remains acceptable "
                    "for your deployment threat model."
                ),
                evidence_snippet=snippet,
                category="doc_tradeoff",
                verification_status="documented_design_tradeoff",
            )
        return PoCTriageRecord(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            original_severity=orig_sev,
            calibrated_severity="INFO",
            file_path=file_path,
            line=line_num,
            verdict=VERDICT_FALSE_POSITIVE,
            poe_level=0,
            disclosure_worthy=False,
            rationale="Flagged line is a source comment with no executable code.",
            remediation="No action required.",
            evidence_snippet=snippet,
            category="code",
            verification_status="rejected_comment_line",
        )

    # 5. Command-execution sink triage (MANTIS-CMD-* / CWE-78)
    if "CMD" in rule_upper or "CWE-78" in combined_text or "command injection" in title_lower:
        if has_source and line_num:
            m_call = _CMD_CALL_RE.search(target_line) or _CMD_CALL_RE.search(window_text)
            if m_call:
                func_name = m_call.group(1)
                first_arg = m_call.group(2).strip()
                if _STATIC_LITERAL_RE.match(first_arg) and not _DYNAMIC_EXPR_RE.search(first_arg):
                    return PoCTriageRecord(
                        finding_id=finding_id,
                        rule_id=rule_id,
                        title=title,
                        original_severity=orig_sev,
                        calibrated_severity="LOW",
                        file_path=file_path,
                        line=line_num,
                        verdict=VERDICT_HARDENING_NOTE,
                        poe_level=0,
                        disclosure_worthy=False,
                        rationale=(
                            f"`{func_name}({first_arg})` invokes a hardcoded string literal with no "
                            "user-controlled input; not exploitable for command injection."
                        ),
                        remediation=(
                            f"Defense-in-depth: replace `{func_name}` with a shell-free argv API "
                            "(e.g., `execFileSync` or `subprocess.run([...], shell=False)`)."
                        ),
                        evidence_snippet=snippet,
                        category="command_sink",
                        verification_status="rejected_constant_command",
                    )
                resolved_const = _resolve_constant_binding(lines, first_arg)
                if resolved_const is not None:
                    return PoCTriageRecord(
                        finding_id=finding_id,
                        rule_id=rule_id,
                        title=title,
                        original_severity=orig_sev,
                        calibrated_severity="LOW",
                        file_path=file_path,
                        line=line_num,
                        verdict=VERDICT_HARDENING_NOTE,
                        poe_level=0,
                        disclosure_worthy=False,
                        rationale=(
                            f"`{func_name}({first_arg})` resolves to same-file constant "
                            f"{resolved_const!r} with zero user-controlled arguments; not exploitable "
                            "as command injection."
                        ),
                        remediation=(
                            f"Defense-in-depth: switch `{func_name}({first_arg})` to `execFileSync` "
                            "with an explicit argv array (avoiding shell invocation)."
                        ),
                        evidence_snippet=snippet,
                        category="command_sink",
                        verification_status="rejected_constant_binding",
                    )
                return PoCTriageRecord(
                    finding_id=finding_id,
                    rule_id=rule_id,
                    title=title,
                    original_severity=orig_sev,
                    calibrated_severity="HIGH",
                    file_path=file_path,
                    line=line_num,
                    verdict=VERDICT_UNVERIFIED_CANDIDATE,
                    poe_level=1,
                    disclosure_worthy=False,
                    rationale=(
                        f"`{func_name}({first_arg})` passes a non-constant expression into a command "
                        "execution sink in production source; requires dataflow/container POE==3 proof."
                    ),
                    remediation=(
                        f"Replace `{func_name}` with a shell-free argv API (`execFileSync` / "
                        "`subprocess.run(..., shell=False)`) and strictly allowlist dynamic arguments."
                    ),
                    evidence_snippet=snippet,
                    category="command_sink",
                    verification_status="dynamic_sink_candidate",
                )
        return PoCTriageRecord(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            original_severity=orig_sev,
            calibrated_severity="MEDIUM",
            file_path=file_path,
            line=line_num,
            verdict=VERDICT_UNVERIFIED_CANDIDATE,
            poe_level=1,
            disclosure_worthy=False,
            rationale="Command-sink candidate without verified dynamic argument reachability.",
            remediation="Verify whether caller-controlled input reaches the sink; prefer argv-only execution.",
            evidence_snippet=snippet,
            category="command_sink",
            verification_status="unverified_sink",
        )

    # 6. File-level static compound heuristics (MANTIS-0DAY-CHAIN-*)
    if "0DAY-CHAIN" in rule_upper or "COMPOUND" in combined_text:
        return PoCTriageRecord(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            original_severity=orig_sev,
            calibrated_severity="LOW" if line_num is None else "MEDIUM",
            file_path=file_path,
            line=line_num,
            verdict=VERDICT_UNVERIFIED_CANDIDATE,
            poe_level=1,
            disclosure_worthy=False,
            rationale=(
                "File-level multi-primitive heuristic without a concrete line-level proof or "
                "reproduced security invariant violation (POE=1)."
            ),
            remediation=(
                "Run call-graph taint slicing and isolated container invariant verification "
                "(`poe-verify` / `sandbox-invariants`) before treating as an exploitable bug."
            ),
            evidence_snippet=snippet,
            category="compound_heuristic",
            verification_status="static_heuristic_only",
        )

    # 7. Default production finding with explicit POE==3 already confirmed
    existing_poe = int(finding.get("poe_level") or 0)
    if existing_poe >= 3 and finding.get("verified") is True:
        return PoCTriageRecord(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            original_severity=orig_sev,
            calibrated_severity=orig_sev,
            file_path=file_path,
            line=line_num,
            verdict=VERDICT_VERIFIED_REPRODUCIBLE,
            poe_level=3,
            disclosure_worthy=True,
            rationale="Confirmed POE==3 security property violation in production source.",
            remediation="Patch the violated invariant and keep the generated regression test in CI.",
            evidence_snippet=snippet,
            category="code",
            verification_status="verified_poe3",
        )

    return PoCTriageRecord(
        finding_id=finding_id,
        rule_id=rule_id,
        title=title,
        original_severity=orig_sev,
        calibrated_severity=orig_sev if orig_sev in ("MEDIUM", "LOW", "INFO") else "MEDIUM",
        file_path=file_path,
        line=line_num,
        verdict=VERDICT_UNVERIFIED_CANDIDATE,
        poe_level=max(0, min(existing_poe, 2)),
        disclosure_worthy=False,
        rationale="Production finding requires isolated invariant verification (`POE==3`) before disclosure.",
        remediation="Verify reachability with the generated non-destructive regression check and patch if confirmed.",
        evidence_snippet=snippet,
        category="code",
        verification_status="unverified_candidate",
    )


def _triage_chain_finding(
    idx: int,
    finding: Dict[str, Any],
    concrete_records: Sequence[PoCTriageRecord],
) -> PoCTriageRecord:
    """Triages an ARTEX multi-hop chain against the verdicts of concrete root findings."""
    rule_id = str(finding.get("rule_id") or finding.get("id") or f"ARTEX-CHAIN-{idx + 1}").strip()
    finding_id = str(finding.get("finding_id") or finding.get("chain_id") or f"{rule_id}-{idx + 1}").strip()
    title = str(finding.get("title") or finding.get("description") or rule_id).strip()
    orig_sev = str(finding.get("severity") or "CRITICAL").upper()
    file_path = _extract_file_path(finding) or "network-target"
    poe = int(finding.get("poe_level") or 1)
    verified = bool(finding.get("verified", False))

    if poe >= 3 and verified:
        return PoCTriageRecord(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            original_severity=orig_sev,
            calibrated_severity=orig_sev,
            file_path=file_path,
            line=None,
            verdict=VERDICT_VERIFIED_REPRODUCIBLE,
            poe_level=3,
            disclosure_worthy=True,
            rationale="Live-verified POE==3 multi-hop chain.",
            remediation="Break the verified attack chain at the earliest trust boundary.",
            category="chain",
            verification_status="verified_chain_poe3",
        )

    # Check if ANY concrete line-level production finding survived triage
    surviving_concrete = [
        r
        for r in concrete_records
        if r.verdict == VERDICT_VERIFIED_REPRODUCIBLE
        or (r.verdict == VERDICT_UNVERIFIED_CANDIDATE and r.category != "compound_heuristic")
    ]
    if not surviving_concrete:
        return PoCTriageRecord(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            original_severity=orig_sev,
            calibrated_severity="INFO",
            file_path=file_path,
            line=None,
            verdict=VERDICT_FALSE_POSITIVE,
            poe_level=0,
            disclosure_worthy=False,
            rationale=(
                "Passive ARTEX graph correlation (`POE=1`) downgraded to FALSE_POSITIVE because "
                "zero concrete line-level production vulnerabilities survived source-aware triage."
            ),
            remediation="No immediate disclosure action; re-run with Docker `poe-verify` if new root sinks appear.",
            category="chain",
            verification_status="downgraded_passive_chain",
        )

    return PoCTriageRecord(
        finding_id=finding_id,
        rule_id=rule_id,
        title=title,
        original_severity=orig_sev,
        calibrated_severity="MEDIUM",
        file_path=file_path,
        line=None,
        verdict=VERDICT_UNVERIFIED_CANDIDATE,
        poe_level=1,
        disclosure_worthy=False,
        rationale=(
            "Passive ARTEX correlation (`POE=1`) linked to surviving production candidate(s); "
            "requires isolated `POE==3` reproduction before disclosure."
        ),
        remediation="Verify the underlying concrete production sink(s) inside an isolated test harness.",
        category="chain",
        verification_status="unverified_passive_chain",
    )


def generate_protocol_conformance_script(
    record: PoCTriageRecord,
    finding: Dict[str, Any],
) -> str:
    """
    Generates a strictly loopback-only (`127.0.0.1`/`localhost`/`::1` fail-closed),
    non-destructive 3-trial RFC protocol conformance verification script.
    """
    raw_probe = finding.get("raw_probe") or finding.get("minimized_probe") or b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    probe_bytes = raw_probe if isinstance(raw_probe, (bytes, bytearray)) else str(raw_probe).encode("latin-1", errors="replace")
    first_line = probe_bytes.decode("latin-1", errors="replace").splitlines()[0].strip() if probe_bytes else ""
    verb = first_line.split(" ")[0].strip().upper() if first_line else "GET"
    if verb in _DESTRUCTIVE_HTTP_VERBS:
        raise PermissionError(
            f"PoCVerificationGenerator strictly forbids destructive HTTP verb {verb!r} in conformance verifiers"
        )
    probe_hex = bytes(probe_bytes).hex()
    default_port = int(finding.get("target_port") or finding.get("port") or 8080)

    return f'''#!/usr/bin/env python3
"""
RFCHunt Non-Destructive RFC Conformance Verification Script
Finding ID : {record.finding_id}
Rule ID    : {record.rule_id}
Verdict    : {record.verdict} (POE={record.poe_level})

SAFETY GUARDRAIL:
  Strictly loopback-only (127.0.0.1 / localhost / ::1). Refuses any remote host
  fail-closed and performs 3 non-destructive RFC framing conformance trials.
"""

import argparse
import ipaddress
import json
import socket
import sys

LOOPBACK_HOSTS = frozenset({{"127.0.0.1", "localhost", "::1"}})
PROBE_BYTES = bytes.fromhex({probe_hex!r})
TRIALS = 3


def assert_loopback(host: str) -> None:
    cleaned = str(host or "").strip().lower().strip("[]")
    if cleaned in LOOPBACK_HOSTS:
        return
    try:
        if ipaddress.ip_address(cleaned).is_loopback:
            return
    except ValueError:
        pass
    raise PermissionError(f"Refusing non-loopback target host: {{host!r}} (loopback-only verifier)")


def run_trial(host: str, port: int, timeout: float = 3.0) -> dict:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(PROBE_BYTES)
        sock.settimeout(timeout)
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 32768:
                    break
            except socket.timeout:
                break
        raw = b"".join(chunks)
        first = raw.split(b"\\r\\n", 1)[0].decode("latin-1", errors="replace")
        parts = first.split(" ")
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        return {{"status": status, "first_line": first[:120], "bytes": len(raw)}}
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Loopback-only non-destructive RFC conformance verifier")
    parser.add_argument("--host", default="127.0.0.1", help="Loopback host (127.0.0.1 / localhost / ::1 only)")
    parser.add_argument("--port", type=int, default={default_port}, help="Loopback target port")
    args = parser.parse_args()
    assert_loopback(args.host)

    results = [run_trial(args.host, args.port) for _ in range(TRIALS)]
    anomalous = [r for r in results if r["status"] in (0, 200, 408, 500, 501, 505)]
    reproduced = len(anomalous) >= 2
    payload = {{
        "finding_id": {record.finding_id!r},
        "rule_id": {record.rule_id!r},
        "target": f"{{args.host}}:{{args.port}}",
        "trials": TRIALS,
        "reproduced": reproduced,
        "results": results,
    }}
    print(json.dumps(payload, indent=2))
    return 1 if reproduced else 0


if __name__ == "__main__":
    sys.exit(main())
'''


def generate_code_invariant_script(
    record: PoCTriageRecord,
    *,
    repo_path: Optional[Union[str, Path]] = None,
) -> str:
    """
    Generates a strictly read-only, non-destructive Python security regression verifier
    for a code finding (zero shell execution, zero target mutation, `--network=none` safe).
    """
    rel_target = record.file_path
    if repo_path and record.file_path:
        resolved = _safe_resolve_under_repo(record.file_path, repo_path)
        if resolved is not None:
            try:
                rel_target = resolved.relative_to(Path(repo_path).resolve(strict=False)).as_posix()
            except Exception:
                rel_target = resolved.name

    target_line = int(record.line or 1)
    check_kind = record.category

    return f'''#!/usr/bin/env python3
"""
RFCHunt Non-Destructive Security Invariant Regression Verifier
Finding ID : {record.finding_id}
Rule ID    : {record.rule_id}
Target     : {rel_target}:{target_line}
Verdict    : {record.verdict} (POE={record.poe_level})

SAFETY GUARDRAIL:
  Strictly read-only static/AST invariant verification. Zero shell execution,
  zero network I/O, and zero target file mutations.
  Exit 0 = security invariant HOLDS (no violation detected / fixed).
  Exit 1 = security invariant VIOLATED (reproducible issue confirmed).
"""

import argparse
import json
import re
import sys
from pathlib import Path

TARGET_REL_PATH = {rel_target!r}
TARGET_LINE = {target_line}
CHECK_KIND = {check_kind!r}

SECRET_LITERAL_RE = re.compile(
    r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"|\\bAKIA[0-9A-Z]{{16}}\\b|\\bghp_[A-Za-z0-9]{{36}}\\b|\\bsk-[A-Za-z0-9]{{20,}}\\b)"
)
REGEX_CONTEXT_RE = re.compile(
    r"(/-----BEGIN\\b|re\\.compile\\s*\\(|Regex::new\\s*\\(|new\\s+RegExp\\s*\\(|\\.exec\\s*\\()",
    re.IGNORECASE,
)
COMMENT_RE = re.compile(r"^\\s*(///|//!|//|#|/\\*|\\*)")
CMD_CALL_RE = re.compile(r"\\b(execSync|exec|spawnSync|spawn|system|popen|run|Popen)\\s*\\(\\s*([^,\\)\\n]+)")
STATIC_LIT_RE = re.compile(r"""^(?:r|b|u)?(?:'[^']*'|"(?:[^"\\\\]|\\\\.)*")$""")


def verify_invariant(repo_root: Path) -> dict:
    root = repo_root.resolve(strict=False)
    target = (root / TARGET_REL_PATH).resolve(strict=False)
    if not target.is_relative_to(root):
        raise PermissionError(f"Target escapes repository root: {{TARGET_REL_PATH!r}}")
    if not target.is_file():
        return {{"status": "target_missing", "violated": False, "detail": f"File not found: {{target}}"}}

    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    idx = max(0, min(len(lines) - 1, TARGET_LINE - 1)) if lines else 0
    line_text = lines[idx] if lines else ""
    window = "\\n".join(lines[max(0, idx - 4) : min(len(lines), idx + 5)])

    if CHECK_KIND == "secret":
        if COMMENT_RE.match(line_text) or REGEX_CONTEXT_RE.search(window):
            return {{"status": "invariant_holds", "violated": False, "detail": "Regex or comment only (no literal secret)."}}
        violated = bool(SECRET_LITERAL_RE.search(window))
        return {{
            "status": "invariant_violated" if violated else "invariant_holds",
            "violated": violated,
            "detail": "Literal secret block present in production code (redacted)." if violated else "No literal secret detected.",
        }}

    if CHECK_KIND == "command_sink":
        m = CMD_CALL_RE.search(line_text) or CMD_CALL_RE.search(window)
        if not m:
            return {{"status": "invariant_holds", "violated": False, "detail": "No shell command sink found at line."}}
        arg = m.group(2).strip()
        if STATIC_LIT_RE.match(arg):
            return {{"status": "invariant_holds", "violated": False, "detail": f"Hardcoded literal command only ({{arg}})."}}
        const_pat = re.compile(
            r"\\b(?:const|let|var)\\s+" + re.escape(arg) + r"\\s*(?::[^=]+)?=\\s*(['\\x22])((?:\\\\.|(?!\\1).)*)\\1"
        )
        for ln in lines[:1200]:
            cm = const_pat.search(ln)
            if cm and "${{" not in cm.group(2):
                return {{"status": "invariant_holds", "violated": False, "detail": f"Constant binding only ({{arg}})."}}
        return {{
            "status": "invariant_violated",
            "violated": True,
            "detail": f"Non-constant argument {{arg!r}} reaches shell execution sink {{m.group(1)}}.",
        }}

    return {{
        "status": "manual_review_required",
        "violated": False,
        "detail": "Static candidate requires domain-specific invariant assertion or container POE==3 run.",
    }}


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only security invariant regression verifier")
    parser.add_argument("--repo", default=".", help="Path to repository root")
    args = parser.parse_args()
    result = verify_invariant(Path(args.repo))
    result["finding_id"] = {record.finding_id!r}
    result["rule_id"] = {record.rule_id!r}
    result["target"] = f"{{TARGET_REL_PATH}}:{{TARGET_LINE}}"
    print(json.dumps(result, indent=2))
    return 1 if result.get("violated") else 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _safe_write_under_dir(base_dir: Path, rel_name: str, content: str) -> Path:
    base_resolved = base_dir.resolve(strict=False)
    p_name = Path(rel_name)
    suffix = p_name.suffix if re.match(r"^\.[A-Za-z0-9]{1,8}$", p_name.suffix or "") else ""
    stem = _sanitize_slug(p_name.stem if suffix else rel_name, fallback="artifact", max_len=72)
    safe_name = f"{stem}{suffix}"
    dest = (base_resolved / safe_name).resolve(strict=False)
    if not dest.is_relative_to(base_resolved):
        raise ValueError(f"Output filename escapes poc directory: {rel_name!r}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return dest


def _render_poc_index_markdown(report: PoCBundleReport) -> str:
    vc = report.verdict_counts
    lines = [
        "# RFCHunt `--poc` Non-Destructive Verification & Triage Index",
        "",
        f"- **Target**: `{report.target_path or 'N/A'}`",
        f"- **Output Directory**: `{report.output_dir}`",
        f"- **Findings Analyzed**: `{report.total_findings_analyzed}`",
        f"- **Disclosure-Worthy (`POE=3` Verified Production)**: **`{report.disclosure_worthy_count}`**",
        f"- **Verification Scripts / Defense Files Generated**: `{report.generated_script_count}`",
        f"- **Elapsed**: `{report.elapsed_sec:.3f}s`",
        "",
        "## Verdict Breakdown",
        "",
        "| Verdict | Count | Meaning |",
        "| :--- | ---: | :--- |",
        f"| `{VERDICT_VERIFIED_REPRODUCIBLE}` | {vc.get(VERDICT_VERIFIED_REPRODUCIBLE, 0)} | Confirmed reproducible (`POE=3`) production security issue |",
        f"| `{VERDICT_UNVERIFIED_CANDIDATE}` | {vc.get(VERDICT_UNVERIFIED_CANDIDATE, 0)} | Unverified production lead (`POE=1`); needs isolated reproduction before disclosure |",
        f"| `{VERDICT_HARDENING_NOTE}` | {vc.get(VERDICT_HARDENING_NOTE, 0)} | Non-exploitable defense-in-depth or documented design trade-off (`POE=0`) |",
        f"| `{VERDICT_FALSE_POSITIVE}` | {vc.get(VERDICT_FALSE_POSITIVE, 0)} | Rejected false positive (regex pattern, comment-only, or passive chain over rejected roots) |",
        f"| `{VERDICT_TEST_FIXTURE}` | {vc.get(VERDICT_TEST_FIXTURE, 0)} | Synthetic test/fixture file outside production runtime |",
        "",
    ]

    disclosure_items = [r for r in report.records if r.disclosure_worthy]
    lines.append("## Disclosure-Worthy Findings")
    lines.append("")
    if not disclosure_items:
        lines.append(
            "Zero findings met the strict `VERIFIED_REPRODUCIBLE` (`POE=3`) production threshold. "
            "**Do not submit a private vulnerability advisory based on unverified or rejected flags.**"
        )
    else:
        for r in disclosure_items:
            loc = f"`{r.file_path}:{r.line}`" if r.line else f"`{r.file_path}`"
            files_str = ", ".join(f"`{f}`" for f in r.generated_files) or "none"
            lines.append(
                f"- **[{r.calibrated_severity}] `{r.rule_id}`** ({loc}) — {r.rationale} | Verifier(s): {files_str}"
            )
    lines.append("")

    lines.append("## Detailed Triage & Verification Table")
    lines.append("")
    lines.append("| Finding | Rule | Orig -> Calibrated | Verdict | POE | Location | Verifier / Artifacts | Rationale |")
    lines.append("| :--- | :--- | :--- | :--- | ---: | :--- | :--- | :--- |")
    for r in report.records:
        loc = f"{r.file_path}:{r.line}" if r.line else r.file_path
        loc_short = loc[-56:] if len(loc) > 56 else loc
        files_str = ", ".join(r.generated_files) if r.generated_files else "-"
        rat = r.rationale.replace("|", "/").replace("\n", " ")[:140]
        lines.append(
            f"| `{r.finding_id[:28]}` | `{r.rule_id}` | `{r.original_severity}` -> `{r.calibrated_severity}` "
            f"| `{r.verdict}` | {r.poe_level} | `{loc_short}` | `{files_str}` | {rat} |"
        )
    lines.append("")
    return "\n".join(lines)


class PoCVerificationGenerator:
    """
    Parallel, source-aware false-positive triage engine and strictly non-destructive
    PoC/regression verification bundle generator (`--poc`).
    """

    def __init__(
        self,
        *,
        max_workers: Optional[int] = None,
        max_scripts: int = DEFAULT_MAX_POCS,
    ) -> None:
        cpu = os.cpu_count() or 4
        self.max_workers = max(1, min(int(max_workers or min(8, cpu * 2)), 16))
        self.max_scripts = max(1, int(max_scripts))

    def generate_bundle(
        self,
        findings: Sequence[Dict[str, Any]],
        *,
        output_dir: Union[str, Path],
        repo_path: Optional[Union[str, Path]] = None,
        include_rejected_scripts: bool = False,
        run_container_verify: bool = False,
        db: Any = None,
        task_id: str = "default",
    ) -> PoCBundleReport:
        t0 = time.perf_counter()
        out_path = Path(output_dir).resolve(strict=False)
        out_path.mkdir(parents=True, exist_ok=True)

        clean_findings = [f for f in (findings or []) if isinstance(f, dict)]
        concrete_pairs: List[Tuple[int, Dict[str, Any]]] = []
        chain_pairs: List[Tuple[int, Dict[str, Any]]] = []
        for idx, f in enumerate(clean_findings):
            if _is_chain_finding(f):
                chain_pairs.append((idx, f))
            else:
                concrete_pairs.append((idx, f))

        # Pass 1: Bounded multithreaded source-aware triage over concrete findings
        concrete_results: Dict[int, PoCTriageRecord] = {}
        if concrete_pairs:
            worker_count = min(self.max_workers, len(concrete_pairs))
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as pool:
                fut_map = {
                    pool.submit(_triage_single_finding, idx, item, repo_path=repo_path): idx
                    for idx, item in concrete_pairs
                }
                for fut in concurrent.futures.as_completed(fut_map):
                    idx = fut_map[fut]
                    concrete_results[idx] = fut.result()

        ordered_concrete = [concrete_results[idx] for idx, _ in concrete_pairs]

        # Pass 2: Chain triage informed by concrete root verdicts
        chain_results: Dict[int, PoCTriageRecord] = {}
        for idx, item in chain_pairs:
            chain_results[idx] = _triage_chain_finding(idx, item, ordered_concrete)

        all_records_by_idx: Dict[int, PoCTriageRecord] = {**concrete_results, **chain_results}

        # Optional ContainerPOEVerifier pass for surviving HIGH/CRITICAL UNVERIFIED_CANDIDATEs
        container_summary: Optional[Dict[str, Any]] = None
        if run_container_verify:
            candidate_idxs = [
                idx
                for idx, rec in all_records_by_idx.items()
                if rec.verdict == VERDICT_UNVERIFIED_CANDIDATE
                and rec.original_severity in ("CRITICAL", "HIGH")
            ]
            if candidate_idxs:
                verifier = ContainerPOEVerifier()
                candidate_inputs = [clean_findings[idx] for idx in candidate_idxs]
                batch = verifier.verify_findings(
                    candidate_inputs,
                    repo_path=str(repo_path) if repo_path else None,
                    db=db,
                    task_id=task_id,
                )
                container_summary = batch.to_dict()
                for res_item, orig_idx in zip(batch.results, candidate_idxs):
                    rec = all_records_by_idx[orig_idx]
                    if res_item.verified and res_item.poe_level >= 3:
                        rec.verdict = VERDICT_VERIFIED_REPRODUCIBLE
                        rec.poe_level = 3
                        rec.disclosure_worthy = True
                        rec.calibrated_severity = rec.original_severity
                        rec.verification_status = "container_poe3_verified"
                        rec.rationale = f"{rec.rationale} Container POE==3 verified: {res_item.evidence}"
                    elif res_item.status in ("not_reproduced", "false_positive"):
                        rec.verdict = VERDICT_FALSE_POSITIVE
                        rec.poe_level = 0
                        rec.disclosure_worthy = False
                        rec.calibrated_severity = "LOW"
                        rec.verification_status = "container_downgraded_fp"
                        rec.rationale = f"Container POE verifier did not reproduce violation: {res_item.evidence}"

        # Deterministic ordering (verified first, then unverified candidates, hardening, FP, fixtures)
        sorted_pairs = sorted(
            all_records_by_idx.items(),
            key=lambda kv: (
                _VERDICT_ORDER.get(kv[1].verdict, 9),
                _SEVERITY_ORDER.get(kv[1].calibrated_severity, 9),
                _SEVERITY_ORDER.get(kv[1].original_severity, 9),
                kv[0],
            ),
        )

        # Generate non-destructive verification scripts & defense rules
        scripts_written = 0
        for idx, rec in sorted_pairs:
            should_emit = rec.verdict in (
                VERDICT_VERIFIED_REPRODUCIBLE,
                VERDICT_UNVERIFIED_CANDIDATE,
                VERDICT_HARDENING_NOTE,
            ) or include_rejected_scripts
            # Avoid emitting noisy duplicate scripts for file-level heuristics or downgraded chains
            if rec.category in ("compound_heuristic", "chain") and rec.verdict != VERDICT_VERIFIED_REPRODUCIBLE:
                should_emit = include_rejected_scripts
            if not should_emit or scripts_written >= self.max_scripts:
                continue

            finding = clean_findings[idx]
            slug = _sanitize_slug(f"{idx + 1:03d}_{rec.rule_id}_{Path(rec.file_path).stem if rec.file_path else 'target'}")
            if rec.category == "protocol":
                try:
                    py_src = generate_protocol_conformance_script(rec, finding)
                    py_path = _safe_write_under_dir(out_path, f"verify_proto_{slug}.py", py_src)
                    rec.generated_files.append(py_path.name)
                    scripts_written += 1

                    # Pair with defensive WAF/IDS rules
                    modsec = ExploitExporter.export_modsecurity_rule(finding, rule_id_start=230000 + idx * 10)
                    ms_path = _safe_write_under_dir(out_path, f"defense_proto_{slug}_modsecurity.conf", modsec)
                    rec.generated_files.append(ms_path.name)

                    suricata = ExploitExporter.export_suricata_signature(finding, sid_start=3100000 + idx * 10)
                    su_path = _safe_write_under_dir(out_path, f"defense_proto_{slug}_suricata.rules", suricata)
                    rec.generated_files.append(su_path.name)
                except PermissionError as exc:
                    rec.verification_status = f"blocked_unsafe_verb:{exc}"
            else:
                py_src = generate_code_invariant_script(rec, repo_path=repo_path)
                py_path = _safe_write_under_dir(out_path, f"verify_code_{slug}.py", py_src)
                rec.generated_files.append(py_path.name)
                scripts_written += 1

        records = [rec for _, rec in sorted_pairs]
        verdict_counts = {v: 0 for v in ALL_VERDICTS}
        for rec in records:
            verdict_counts[rec.verdict] = verdict_counts.get(rec.verdict, 0) + 1

        elapsed = time.perf_counter() - t0
        report = PoCBundleReport(
            target_path=str(repo_path) if repo_path else None,
            output_dir=str(out_path),
            total_findings_analyzed=len(records),
            verdict_counts=verdict_counts,
            disclosure_worthy_count=sum(1 for r in records if r.disclosure_worthy),
            generated_script_count=sum(len(r.generated_files) for r in records),
            records=records,
            container_verification=container_summary,
            elapsed_sec=elapsed,
        )

        index_md_path = out_path / "POC_INDEX.md"
        manifest_json_path = out_path / "poc_manifest.json"
        report.index_markdown_path = str(index_md_path)
        report.manifest_json_path = str(manifest_json_path)

        index_md_path.write_text(_render_poc_index_markdown(report), encoding="utf-8")
        manifest_json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

        # Persist summary FACT into Cairn Blackboard if db supplied
        if db is not None and hasattr(db, "add_fact"):
            try:
                db.add_fact(
                    (
                        f"PoC verification triage: {report.total_findings_analyzed} analyzed, "
                        f"{report.disclosure_worthy_count} disclosure-worthy (POE=3), "
                        f"{verdict_counts.get(VERDICT_FALSE_POSITIVE, 0)} false positives, "
                        f"{verdict_counts.get(VERDICT_TEST_FIXTURE, 0)} test fixtures"
                    ),
                    node_id=f"fact:poc_verification:{task_id}",
                    task_id=task_id,
                    domain="global",
                    source_agent="poc_verification_generator",
                    payload={
                        "verdict_counts": verdict_counts,
                        "disclosure_worthy_count": report.disclosure_worthy_count,
                        "generated_script_count": report.generated_script_count,
                        "index_markdown_path": report.index_markdown_path,
                    },
                )
            except Exception:
                pass

        return report


def generate_poc_bundle(
    findings: Sequence[Dict[str, Any]],
    *,
    output_dir: Union[str, Path],
    repo_path: Optional[Union[str, Path]] = None,
    include_rejected_scripts: bool = False,
    run_container_verify: bool = False,
    max_scripts: int = DEFAULT_MAX_POCS,
    db: Any = None,
    task_id: str = "default",
) -> PoCBundleReport:
    """Convenience entry point for CLI `--poc` and `--all --poc`."""
    gen = PoCVerificationGenerator(max_scripts=max_scripts)
    return gen.generate_bundle(
        findings,
        output_dir=output_dir,
        repo_path=repo_path,
        include_rejected_scripts=include_rejected_scripts,
        run_container_verify=run_container_verify,
        db=db,
        task_id=task_id,
    )
