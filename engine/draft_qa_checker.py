"""
HackerOne Draft Quality Assurance (QA Phase) Checker & Auto-Fixer (`draft_qa_checker.py`).
==========================================================================================
Automated pre-submission Quality Assurance gate that inspects saved HackerOne Drafts
(and newly authored report drafts prior to staging) for formatting corruption, missing
citations, broken/omitted code ranges, overbroad platform claims, and upstream source
mismatches — automatically repairing deterministic text/formatting defects and producing
an actionable edit queue with clickable HackerOne report URLs.

Defect Classes Checked:
  1. QA_HTML_ENTITY_IN_CODE        (CRITICAL, auto-fixable): Literal &lt;, &gt;, &amp;,
     &quot;, &#39;, &#x27; inside Markdown inline code spans or fenced code blocks.
  2. QA_HTML_ENTITY_IN_PROSE       (HIGH, auto-fixable): Stray HTML entities in Markdown
     prose outside code spans.
  3. QA_FUNNY_OR_CONTROL_CHARS     (CRITICAL, auto-fixable): ASCII control characters
     (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F), U+FFFD replacement glyphs, or cp1252 mojibake.
  4. QA_UNBALANCED_CODE_FENCE      (CRITICAL): Unmatched triple-backtick code fences.
  5. QA_TITLE_LENGTH_OR_TRUNCATION (CRITICAL): Empty title, >150 char HackerOne cap, or
     abrupt truncation.
  6. QA_MISSING_REQUIRED_SECTIONS  (HIGH): Missing Summary / Code / Verification /
     Remediation / Impact sections.
  7. QA_MISSING_CLICKABLE_GITHUB_URL (HIGH): Repo/branch/file referenced without any
     clickable https://github.com/.../blob/... URL.
  8. QA_OMITTED_CITED_LINE_RANGE   (HIGH): Code header advertises line ranges (e.g.
     "lines 525-595 & 633-682") while skipping entire cited ranges in the code block.
  9. QA_NETLINK_SELINUX_OVERCLAIM  (HIGH, auto-fixable): Overclaiming unrestricted
     Android `untrusted_app` access to NETLINK_GENERIC without noting SELinux policy.
 10. QA_NLA_LEN_MISSING_HDRLEN     (HIGH): Analyzing `nla->nla_len` length math without
     accounting for `NLA_HDRLEN` (4 bytes) / `nla_len(nla)`.
 11. QA_STRNCPY_ZEROED_BSS_NITPICK (MEDIUM): Overclaiming missing NUL-termination on
     `strncpy(..., len)` into a static zero-initialized `[MAX + 1]` buffer.
 12. QA_UPSTREAM_FILE_NOT_FOUND    (CRITICAL, online check): Cited GitHub URL returns
     non-200 on raw.githubusercontent.com.
 13. QA_LINE_NUMBER_MISMATCH       (CRITICAL, online check): Quoted `NNN: <code>` line
     does not match the upstream source file near line NNN.
 14. QA_CONSTANT_MISMATCH          (CRITICAL, online check): Claimed macro value or
     Generic Netlink family name contradicts the upstream `#define` in source.

Strictly safe & defensive: NEVER clicks Submit or Delete, NEVER bypasses access controls,
and NEVER generates exploit payloads.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request

try:
    import httpx
except Exception:  # pragma: no cover - optional runtime dependency fallback
    httpx = None  # type: ignore[assignment]


DEFAULT_QA_DB = Path("reports/ensemble_hunt/draft_qa_tracker.sqlite3")
DEFAULT_QA_AUDIT_MD = Path("reports/ensemble_hunt/qa_draft_audit.md")
DEFAULT_QA_EDIT_QUEUE_JSON = Path("reports/ensemble_hunt/qa_edit_queue.json")
DEFAULT_HACKERONE_BASE_URL = "https://hackerone.com"
HACKERONE_MAX_TITLE_LEN = 150

_HTML_ENTITY_MAP: Dict[str, str] = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&#39;": "'",
    "&#x27;": "'",
    "&#x2F;": "/",
    "&amp;": "&",
}

_HTML_ENTITY_RE = re.compile(r"&(?:lt|gt|quot|amp|#39|#x27|#x2F);", re.IGNORECASE)
_PROSE_ENTITY_RE = re.compile(r"&(?:lt|gt|quot|#39|#x27);", re.IGNORECASE)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffd]")
_MOJIBAKE_RE = re.compile(r"(?:\u00e2\u20ac[\u201c\u201d\u2018\u2019\u2013\u2014\u00a2]|\u00c3[\u00a0-\u00bf])")
_GITHUB_BLOB_URL_RE = re.compile(
    r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/blob/([^\s)\]`\"'>#]+?)(?:#L\d+(?:-L\d+)?)?(?=[\s)\]`\"'>]|$)"
)
_REPO_SLUG_RE = re.compile(
    r"`([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)`"
)
_FENCED_BLOCK_RE = re.compile(r"(```[^\n]*\n)(.*?)(\n```)", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"(`+)([^`\n]+?)\1")
_NUMBERED_CODE_LINE_RE = re.compile(r"^\s*(\d{1,5})\s*:\s?(.*)$")
_LINE_RANGE_CLAUSE_RE = re.compile(
    r"\blines?\s+((?:\d{1,5}(?:\s*(?:-|\u2013|\u2014)\s*\d{1,5})?)"
    r"(?:\s*(?:,|&|/|and)\s*\d{1,5}(?:\s*(?:-|\u2013|\u2014)\s*\d{1,5})?)*)",
    re.IGNORECASE,
)
_PAIR_RANGE_RE = re.compile(r"(\d{1,5})\s*(?:-|\u2013|\u2014)\s*(\d{1,5})")
_DEFINE_INT_RE = re.compile(r"^\s*#\s*define\s+([A-Z][A-Z0-9_]{2,})\s+(0x[0-9a-fA-F]+|\d+)\b")
_DEFINE_STR_RE = re.compile(r'^\s*#\s*define\s+([A-Z][A-Z0-9_]*FAMILY_NAME[A-Z0-9_]*)\s+"([^"]+)"')
_GENL_FAMILY_CLAIM_RE = re.compile(
    r"(?:resolve\s+the|family(?:\s+name)?(?:\s+is)?)\s+[`\"]([A-Za-z0-9_.-]+)[`\"]\s*(?:Generic\s+Netlink|genl)?",
    re.IGNORECASE,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class QADefect:
    code: str
    severity: str  # CRITICAL | HIGH | MEDIUM
    message: str
    auto_fixable: bool = False
    sample: str = ""
    line_hint: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SourceCheckResult:
    github_url: str
    raw_url: str
    http_status: int
    line_count: int = 0
    verified_lines: int = 0
    mismatched_lines: List[Dict[str, Any]] = field(default_factory=list)
    constant_mismatches: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QAReportResult:
    report_id: int
    url: str
    program: str
    title: str
    state: str
    qa_status: str  # PASS | AUTO_FIXED_PENDING_PUSH | NEEDS_SOURCE_EDIT | FAIL
    defects: List[QADefect] = field(default_factory=list)
    auto_fix_applied: bool = False
    auto_fix_changes: List[str] = field(default_factory=list)
    original_title: str = ""
    repaired_title: str = ""
    original_body: str = ""
    repaired_body: str = ""
    source_checks: List[SourceCheckResult] = field(default_factory=list)
    edit_applied_live: bool = False
    checked_at_utc: str = field(default_factory=_utc_now_iso)

    @property
    def blocking_defect_count(self) -> int:
        return sum(1 for d in self.defects if d.severity in ("CRITICAL", "HIGH"))

    def to_dict(self, include_bodies: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "report_id": self.report_id,
            "url": self.url,
            "program": self.program,
            "title": self.title,
            "state": self.state,
            "qa_status": self.qa_status,
            "blocking_defect_count": self.blocking_defect_count,
            "defects": [d.to_dict() for d in self.defects],
            "auto_fix_applied": self.auto_fix_applied,
            "auto_fix_changes": list(self.auto_fix_changes),
            "source_checks": [s.to_dict() for s in self.source_checks],
            "edit_applied_live": self.edit_applied_live,
            "checked_at_utc": self.checked_at_utc,
        }
        if include_bodies:
            data["original_title"] = self.original_title
            data["repaired_title"] = self.repaired_title
            data["original_body"] = self.original_body
            data["repaired_body"] = self.repaired_body
        return data


@dataclass
class QASuiteSummary:
    checked_at_utc: str
    total_audited: int
    passed_count: int
    auto_fixed_pending_push_count: int
    needs_source_edit_count: int
    failed_count: int
    total_defects: int
    defect_counts_by_code: Dict[str, int]
    results: List[QAReportResult]
    audit_markdown_path: str = ""
    edit_queue_json_path: str = ""

    def to_dict(self, include_bodies: bool = False) -> Dict[str, Any]:
        return {
            "checked_at_utc": self.checked_at_utc,
            "total_audited": self.total_audited,
            "passed_count": self.passed_count,
            "auto_fixed_pending_push_count": self.auto_fixed_pending_push_count,
            "needs_source_edit_count": self.needs_source_edit_count,
            "failed_count": self.failed_count,
            "total_defects": self.total_defects,
            "defect_counts_by_code": dict(self.defect_counts_by_code),
            "audit_markdown_path": self.audit_markdown_path,
            "edit_queue_json_path": self.edit_queue_json_path,
            "results": [r.to_dict(include_bodies=include_bodies) for r in self.results],
        }


def _unescape_entities(text: str, *, include_amp: bool = True) -> str:
    def _repl(match: re.Match[str]) -> str:
        tok = match.group(0)
        low = tok.lower()
        if low == "&amp;" and not include_amp:
            return tok
        return _HTML_ENTITY_MAP.get(low, _HTML_ENTITY_MAP.get(tok, tok))

    pattern = _HTML_ENTITY_RE if include_amp else _PROSE_ENTITY_RE
    return pattern.sub(_repl, text)


def _strip_control_chars(text: str) -> str:
    cleaned = _CONTROL_CHAR_RE.sub("", text)
    # Repair the most frequent UTF-8-as-cp1252 sequences deterministically
    replacements = {
        "\u00e2\u20ac\u201d": " - ",
        "\u00e2\u20ac\u201c": "-",
        "\u00e2\u20ac\u2122": "'",
        "\u00e2\u20ac\u0153": '"',
        "\u00e2\u20ac\u009d": '"',
    }
    for bad, good in replacements.items():
        cleaned = cleaned.replace(bad, good)
    return cleaned


def _count_fence_lines(body: str) -> int:
    return sum(1 for ln in body.splitlines() if ln.lstrip().startswith("```"))


def _split_fenced_segments(body: str) -> List[Tuple[bool, str]]:
    """Split markdown into (is_code_fence, segment_text) segments."""
    segments: List[Tuple[bool, str]] = []
    pos = 0
    for m in _FENCED_BLOCK_RE.finditer(body):
        if m.start() > pos:
            segments.append((False, body[pos : m.start()]))
        segments.append((True, m.group(0)))
        pos = m.end()
    if pos < len(body):
        segments.append((False, body[pos:]))
    return segments


def _extract_github_blob_urls(body: str) -> List[Tuple[str, str]]:
    """Return list of (github_blob_url, raw_githubusercontent_url) deduplicated."""
    seen: set[str] = set()
    out: List[Tuple[str, str]] = []
    for m in _GITHUB_BLOB_URL_RE.finditer(body):
        owner, repo, ref_and_path = m.group(1), m.group(2), m.group(3)
        ref_and_path = ref_and_path.rstrip(".,;:")
        gh_url = f"https://github.com/{owner}/{repo}/blob/{ref_and_path}"
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref_and_path}"
        if raw_url not in seen:
            seen.add(raw_url)
            out.append((gh_url, raw_url))
    return out


def _normalize_code_for_match(line: str) -> str:
    # Strip trailing inline review annotations like `// <-- ...` or `# <-- ...`
    stripped = re.sub(r"\s*(?://|#)\s*<--.*$", "", line)
    # Collapse whitespace for resilient comparison across tabs vs spaces
    return re.sub(r"\s+", " ", stripped).strip()


def _check_omitted_line_ranges(body: str) -> List[QADefect]:
    """Detect code headers promising e.g. `lines 525-595 & 633-682` while skipping an entire range."""
    defects: List[QADefect] = []
    lines = body.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].lstrip().startswith("```"):
            header_ctx = "\n".join(lines[max(0, i - 3) : i])
            advertised: List[Tuple[int, int]] = []
            if not re.search(r"\b(?:selected\s+excerpts?|within\s+lines?|elided)\b", header_ctx, re.IGNORECASE):
                for cm in _LINE_RANGE_CLAUSE_RE.finditer(header_ctx):
                    for pm in _PAIR_RANGE_RE.finditer(cm.group(1)):
                        s_ln, e_ln = int(pm.group(1)), int(pm.group(2))
                        if e_ln > s_ln:
                            advertised.append((s_ln, e_ln))
            end_i = i + 1
            block_nums: List[int] = []
            while end_i < len(lines) and not lines[end_i].lstrip().startswith("```"):
                nm = _NUMBERED_CODE_LINE_RE.match(lines[end_i])
                if nm:
                    block_nums.append(int(nm.group(1)))
                end_i += 1
            if advertised and block_nums:
                for start_ln, end_ln in advertised:
                    # Flag if an advertised multi-line range (>= 15 lines) has ZERO numbered lines inside its first 70%
                    span = end_ln - start_ln
                    if span >= 15:
                        head_cutoff = start_ln + int(span * 0.7)
                        in_head = [n for n in block_nums if start_ln <= n <= head_cutoff]
                        if not in_head:
                            defects.append(
                                QADefect(
                                    code="QA_OMITTED_CITED_LINE_RANGE",
                                    severity="HIGH",
                                    message=(
                                        f"Header cites lines {start_ln}-{end_ln}, but lines "
                                        f"{start_ln}-{head_cutoff} are completely omitted from the code block."
                                    ),
                                    auto_fixable=False,
                                    sample=f"lines {start_ln}-{end_ln}",
                                    line_hint=start_ln,
                                )
                            )
            i = end_i + 1
            continue
        i += 1
    return defects


def auto_repair_markdown(title: str, body: str) -> Tuple[str, str, List[str]]:
    """
    Deterministically repair safe, lossless formatting and framing defects:
      1. Unescape HTML entities (&lt;, &gt;, &amp;, &quot;, &#39;) inside fenced blocks & inline code spans.
      2. Unescape stray &lt;, &gt;, &quot;, &#39; in Markdown prose.
      3. Strip control characters, U+FFFD, and cp1252 mojibake from title and body.
      4. Refine overbroad `untrusted_app` Netlink claims with accurate Android SELinux framing.
    """
    changes: List[str] = []

    repaired_title = _strip_control_chars(title).strip()
    if repaired_title != title.strip():
        changes.append("Cleaned control/mojibake characters from title")
    unescaped_title = _unescape_entities(repaired_title, include_amp=False)
    if unescaped_title != repaired_title:
        repaired_title = unescaped_title
        changes.append("Unescaped HTML entities in title")

    repaired = _strip_control_chars(body)
    if repaired != body:
        changes.append("Cleaned control/mojibake characters from body")

    # Pass 1: unescape entities inside fenced code blocks, inline code spans, and prose
    code_entity_fixes = 0
    prose_entity_fixes = 0
    rebuilt_parts: List[str] = []
    for is_fence, seg in _split_fenced_segments(repaired):
        if is_fence:
            hits = len(_HTML_ENTITY_RE.findall(seg))
            if hits:
                code_entity_fixes += hits
                seg = _unescape_entities(seg, include_amp=True)
            rebuilt_parts.append(seg)
        else:
            # Handle inline code spans separately from prose
            out_chunks: List[str] = []
            last = 0
            for m in _INLINE_CODE_RE.finditer(seg):
                prose_part = seg[last : m.start()]
                p_hits = len(_PROSE_ENTITY_RE.findall(prose_part))
                if p_hits:
                    prose_entity_fixes += p_hits
                    prose_part = _unescape_entities(prose_part, include_amp=False)
                out_chunks.append(prose_part)

                span_full = m.group(0)
                c_hits = len(_HTML_ENTITY_RE.findall(span_full))
                if c_hits:
                    code_entity_fixes += c_hits
                    span_full = _unescape_entities(span_full, include_amp=True)
                out_chunks.append(span_full)
                last = m.end()

            tail = seg[last:]
            t_hits = len(_PROSE_ENTITY_RE.findall(tail))
            if t_hits:
                prose_entity_fixes += t_hits
                tail = _unescape_entities(tail, include_amp=False)
            out_chunks.append(tail)
            rebuilt_parts.append("".join(out_chunks))

    repaired = "".join(rebuilt_parts)
    if code_entity_fixes:
        changes.append(f"Unescaped {code_entity_fixes} HTML entity occurrence(s) inside code blocks/spans")
    if prose_entity_fixes:
        changes.append(f"Unescaped {prose_entity_fixes} stray HTML entity occurrence(s) in prose")

    # Pass 2: refine overbroad Android `untrusted_app` claims on NETLINK_GENERIC drivers
    if re.search(r"\b(?:NETLINK_GENERIC|genl_ops|genl_family|GENL_ADMIN_PERM)\b", repaired, re.IGNORECASE):
        if re.search(r"untrusted_app", repaired, re.IGNORECASE) and not re.search(
            r"SELinux|netlink_generic_socket", repaired, re.IGNORECASE
        ):
            updated = re.sub(
                r"[Aa]ny\s+unprivileged\s+(?:local\s+)?Android\s+app(?:lication)?\s*\(`?untrusted_app`?\)",
                "Any local process permitted `NETLINK_GENERIC` socket access without `CAP_NET_ADMIN` "
                "(e.g., `shell` or non-privileged vendor SELinux domains)",
                repaired,
            )
            if updated != repaired:
                repaired = updated
                changes.append("Refined overbroad Android untrusted_app NETLINK_GENERIC claim with SELinux framing")

    return repaired_title, repaired, changes


def audit_draft_text(
    *,
    report_id: int,
    title: str,
    body: str,
    program: str = "",
    state: str = "Draft",
    base_url: str = DEFAULT_HACKERONE_BASE_URL,
) -> QAReportResult:
    """Run all deterministic offline QA rules + generate auto-repaired text."""
    defects: List[QADefect] = []
    url = f"{base_url.rstrip('/')}/reports/{report_id}"

    # 1. Title validation
    if not title or not title.strip():
        defects.append(
            QADefect(
                code="QA_TITLE_LENGTH_OR_TRUNCATION",
                severity="CRITICAL",
                message="Report title is empty.",
                auto_fixable=False,
            )
        )
    else:
        if len(title) > HACKERONE_MAX_TITLE_LEN:
            defects.append(
                QADefect(
                    code="QA_TITLE_LENGTH_OR_TRUNCATION",
                    severity="CRITICAL",
                    message=f"Title length {len(title)} exceeds HackerOne's {HACKERONE_MAX_TITLE_LEN}-character limit.",
                    auto_fixable=False,
                    sample=title[-40:],
                )
            )
        if title.rstrip().endswith(("...", "(", "[", "/", ":", "-", ",")):
            defects.append(
                QADefect(
                    code="QA_TITLE_LENGTH_OR_TRUNCATION",
                    severity="CRITICAL",
                    message="Title appears truncated at the end.",
                    auto_fixable=False,
                    sample=title[-40:],
                )
            )

    # 2. Control chars / mojibake in title or body
    ctrl_hits = _CONTROL_CHAR_RE.findall(title) + _CONTROL_CHAR_RE.findall(body)
    moj_hits = _MOJIBAKE_RE.findall(title) + _MOJIBAKE_RE.findall(body)
    if ctrl_hits or moj_hits:
        defects.append(
            QADefect(
                code="QA_FUNNY_OR_CONTROL_CHARS",
                severity="CRITICAL",
                message=(
                    f"Detected {len(ctrl_hits)} control/replacement char(s) and "
                    f"{len(moj_hits)} mojibake sequence(s)."
                ),
                auto_fixable=True,
                sample=repr((ctrl_hits + moj_hits)[:3]),
            )
        )

    # 3. Unbalanced code fences
    fence_count = _count_fence_lines(body)
    if fence_count % 2 != 0:
        defects.append(
            QADefect(
                code="QA_UNBALANCED_CODE_FENCE",
                severity="CRITICAL",
                message=f"Unbalanced triple-backtick code fences ({fence_count} fence markers).",
                auto_fixable=False,
            )
        )

    # 4. HTML entities inside fenced code blocks & inline code spans vs prose
    code_entities: List[str] = []
    prose_entities: List[str] = []
    for is_fence, seg in _split_fenced_segments(body):
        if is_fence:
            code_entities.extend(_HTML_ENTITY_RE.findall(seg))
        else:
            last = 0
            for m in _INLINE_CODE_RE.finditer(seg):
                prose_entities.extend(_PROSE_ENTITY_RE.findall(seg[last : m.start()]))
                code_entities.extend(_HTML_ENTITY_RE.findall(m.group(0)))
                last = m.end()
            prose_entities.extend(_PROSE_ENTITY_RE.findall(seg[last:]))

    if code_entities:
        defects.append(
            QADefect(
                code="QA_HTML_ENTITY_IN_CODE",
                severity="CRITICAL",
                message=(
                    f"Found {len(code_entities)} literal HTML entity occurrence(s) inside Markdown "
                    f"code blocks/spans (HackerOne renders them verbatim as e.g. {code_entities[0]})."
                ),
                auto_fixable=True,
                sample=", ".join(sorted(set(code_entities))[:5]),
            )
        )
    if prose_entities:
        defects.append(
            QADefect(
                code="QA_HTML_ENTITY_IN_PROSE",
                severity="HIGH",
                message=f"Found {len(prose_entities)} stray HTML entity occurrence(s) in Markdown prose.",
                auto_fixable=True,
                sample=", ".join(sorted(set(prose_entities))[:5]),
            )
        )

    # 5. Required report sections
    low_body = body.lower()
    missing_sections: List[str] = []
    if not re.search(r"(?:^|\n)#{1,3}\s*(?:summary|overview|vulnerability\s+summary)", low_body):
        missing_sections.append("Summary")
    if not re.search(r"(?:^|\n)#{1,3}\s*(?:steps\s+to\s+reproduce|reproduction|verification|proof\s+of\s+concept|poc)", low_body):
        missing_sections.append("Reproduction/Verification")
    if not re.search(r"(?:^|\n)#{1,3}\s*(?:recommended\s+remediation|remediation|fix|mitigation)", low_body):
        missing_sections.append("Remediation")
    if not re.search(r"(?:^|\n)#{1,3}\s*(?:impact|security\s+impact)", low_body):
        missing_sections.append("Impact")
    if missing_sections:
        defects.append(
            QADefect(
                code="QA_MISSING_REQUIRED_SECTIONS",
                severity="HIGH",
                message=f"Missing standard HackerOne section heading(s): {', '.join(missing_sections)}.",
                auto_fixable=False,
                sample=", ".join(missing_sections),
            )
        )

    # 6. Clickable GitHub URL check when referencing repo/branch/source
    gh_urls = _extract_github_blob_urls(body)
    has_repo_ref = bool(
        _REPO_SLUG_RE.search(body)
        or re.search(r"\b(?:branch|commit|vendor/|lib/|src/|packages/)\b", body)
    )
    if has_repo_ref and not gh_urls and "https://github.com/" not in body:
        defects.append(
            QADefect(
                code="QA_MISSING_CLICKABLE_GITHUB_URL",
                severity="HIGH",
                message="Report cites source repository/branch/files without any clickable https://github.com/... URL.",
                auto_fixable=False,
            )
        )

    # 7. Omitted cited line ranges
    defects.extend(_check_omitted_line_ranges(body))

    # 8. Android SELinux NETLINK_GENERIC overclaim
    if re.search(r"\b(?:NETLINK_GENERIC|genl_ops|genl_family|GENL_ADMIN_PERM)\b", body, re.IGNORECASE):
        if re.search(r"\buntrusted_app\b", body, re.IGNORECASE) and not re.search(
            r"\b(?:SELinux|netlink_generic_socket)\b", body, re.IGNORECASE
        ):
            defects.append(
                QADefect(
                    code="QA_NETLINK_SELINUX_OVERCLAIM",
                    severity="HIGH",
                    message=(
                        "Report claims `untrusted_app` can directly access NETLINK_GENERIC without noting "
                        "Android SELinux `netlink_generic_socket` policy boundaries."
                    ),
                    auto_fixable=True,
                    sample="untrusted_app + NETLINK_GENERIC",
                )
            )

    # 9. Netlink `nla->nla_len` accounting for NLA_HDRLEN
    if re.search(r"nla->nla_len\)?\s*(?:<|&lt;)", body) and not re.search(
        r"\bNLA_HDRLEN\b|\bnla_len\s*\(", body
    ):
        defects.append(
            QADefect(
                code="QA_NLA_LEN_MISSING_HDRLEN",
                severity="HIGH",
                message="Analyzes `nla->nla_len` bounds without accounting for `NLA_HDRLEN` (4 bytes) / `nla_len(nla)`.",
                auto_fixable=False,
            )
        )

    # 10. Static zeroed BSS strncpy NUL-termination nitpick check
    if re.search(r"strncpy.*?(?:does not|fails to|without)\s+(?:guarantee\s+)?NUL", body, re.IGNORECASE):
        if re.search(r"\bMAX_[A-Z0-9_]+\s*\+\s*1\b", body) and re.search(r"\bstatic\b", body):
            defects.append(
                QADefect(
                    code="QA_STRNCPY_ZEROED_BSS_NITPICK",
                    severity="MEDIUM",
                    message=(
                        "Claims `strncpy` lacks NUL-termination into a static `[MAX + 1]` buffer — verify "
                        "whether buffer is zero-initialized/memset-cleared before keeping this claim."
                    ),
                    auto_fixable=False,
                )
            )

    # Generate auto-repaired version
    repaired_title, repaired_body, fix_changes = auto_repair_markdown(title, body)
    auto_fixed = bool(fix_changes)

    blocking = [d for d in defects if d.severity in ("CRITICAL", "HIGH")]
    unfixable_blocking = [d for d in blocking if not d.auto_fixable]
    if not blocking:
        qa_status = "PASS"
    elif auto_fixed and not unfixable_blocking:
        qa_status = "AUTO_FIXED_PENDING_PUSH"
    elif unfixable_blocking:
        qa_status = "NEEDS_SOURCE_EDIT"
    else:
        qa_status = "FAIL"

    return QAReportResult(
        report_id=report_id,
        url=url,
        program=program,
        title=title,
        state=state,
        qa_status=qa_status,
        defects=defects,
        auto_fix_applied=auto_fixed,
        auto_fix_changes=fix_changes,
        original_title=title,
        repaired_title=repaired_title,
        original_body=body,
        repaired_body=repaired_body,
    )


def verify_body_against_upstream_source(
    body: str,
    github_url: str,
    raw_url: str,
    upstream_text: str,
    http_status: int = 200,
) -> Tuple[SourceCheckResult, List[QADefect]]:
    """Verify quoted numbered code lines and `#define` constants/family names against real upstream source."""
    defects: List[QADefect] = []
    if http_status != 200:
        res = SourceCheckResult(
            github_url=github_url,
            raw_url=raw_url,
            http_status=http_status,
            error=f"Upstream raw file returned HTTP {http_status}",
        )
        defects.append(
            QADefect(
                code="QA_UPSTREAM_FILE_NOT_FOUND",
                severity="CRITICAL",
                message=f"Cited GitHub source returned HTTP {http_status}: {raw_url}",
                auto_fixable=False,
                sample=raw_url,
            )
        )
        return res, defects

    src_lines = upstream_text.splitlines()
    norm_src = [_normalize_code_for_match(ln) for ln in src_lines]

    # Extract upstream #define numeric constants and GENL family name strings
    define_ints: Dict[str, int] = {}
    define_families: Dict[str, str] = {}
    for ln in src_lines:
        m_int = _DEFINE_INT_RE.match(ln)
        if m_int:
            try:
                define_ints[m_int.group(1)] = int(m_int.group(2), 0)
            except ValueError:
                pass
        m_fam = _DEFINE_STR_RE.match(ln)
        if m_fam:
            define_families[m_fam.group(1)] = m_fam.group(2)

    verified_lines = 0
    mismatched_lines: List[Dict[str, Any]] = []
    constant_mismatches: List[Dict[str, Any]] = []

    # Check numbered lines inside fenced blocks (after unescaping any HTML entities for comparison)
    for is_fence, seg in _split_fenced_segments(body):
        if not is_fence:
            continue
        clean_seg = _unescape_entities(seg, include_amp=True)
        for raw_ln in clean_seg.splitlines()[1:-1]:
            nm = _NUMBERED_CODE_LINE_RE.match(raw_ln)
            if not nm:
                continue
            ln_no = int(nm.group(1))
            quoted_norm = _normalize_code_for_match(nm.group(2))
            if not quoted_norm or quoted_norm in ("{", "}", "};", "...", "return;"):
                continue
            if ln_no < 1 or ln_no > len(src_lines):
                mismatched_lines.append(
                    {"line": ln_no, "quoted": quoted_norm, "actual": "<out-of-range>"}
                )
                continue
            # Allow +/- 2 line tolerance before marking mismatch
            window_lo = max(0, ln_no - 3)
            window_hi = min(len(norm_src), ln_no + 2)
            window = norm_src[window_lo:window_hi]
            if any(quoted_norm in cand or cand in quoted_norm for cand in window if cand):
                verified_lines += 1
            else:
                mismatched_lines.append(
                    {
                        "line": ln_no,
                        "quoted": quoted_norm,
                        "actual": norm_src[ln_no - 1],
                    }
                )

    if mismatched_lines:
        defects.append(
            QADefect(
                code="QA_LINE_NUMBER_MISMATCH",
                severity="CRITICAL",
                message=(
                    f"{len(mismatched_lines)} quoted numbered code line(s) do not match upstream "
                    f"{github_url} (first: L{mismatched_lines[0]['line']})."
                ),
                auto_fixable=False,
                sample=f"L{mismatched_lines[0]['line']}: {mismatched_lines[0]['quoted'][:80]}",
                line_hint=int(mismatched_lines[0]["line"]),
            )
        )

    # Check numeric macro value claims like `MAX_URL_LEN == 64` or `MAX_URL_LEN = 64`
    for macro, actual_val in define_ints.items():
        if macro not in body:
            continue
        claim_re = re.compile(rf"\b{re.escape(macro)}\b\s*(?:==|=|is)\s*(0x[0-9a-fA-F]+|\d+)\b")
        for m in claim_re.finditer(body):
            claimed_val = int(m.group(1), 0)
            if claimed_val != actual_val:
                constant_mismatches.append(
                    {"name": macro, "claimed": claimed_val, "actual": actual_val}
                )
                defects.append(
                    QADefect(
                        code="QA_CONSTANT_MISMATCH",
                        severity="CRITICAL",
                        message=(
                            f"Report claims `{macro}` is `{claimed_val}`, but upstream source defines "
                            f"`#define {macro} {actual_val}`."
                        ),
                        auto_fixable=False,
                        sample=f"{macro}: claimed {claimed_val} != actual {actual_val}",
                    )
                )

    # Check Generic Netlink family name claims against `#define ..._FAMILY_NAME "..."`
    if define_families:
        actual_names = set(define_families.values())
        for m in _GENL_FAMILY_CLAIM_RE.finditer(body):
            claimed_fam = m.group(1)
            if claimed_fam not in actual_names and claimed_fam not in define_families:
                constant_mismatches.append(
                    {"name": "GENL_FAMILY_NAME", "claimed": claimed_fam, "actual": sorted(actual_names)}
                )
                defects.append(
                    QADefect(
                        code="QA_CONSTANT_MISMATCH",
                        severity="CRITICAL",
                        message=(
                            f"Report cites Generic Netlink family `{claimed_fam}`, but upstream source defines "
                            f"{sorted(actual_names)}."
                        ),
                        auto_fixable=False,
                        sample=f"family `{claimed_fam}` != {sorted(actual_names)}",
                    )
                )

    res = SourceCheckResult(
        github_url=github_url,
        raw_url=raw_url,
        http_status=http_status,
        line_count=len(src_lines),
        verified_lines=verified_lines,
        mismatched_lines=mismatched_lines,
        constant_mismatches=constant_mismatches,
    )
    return res, defects


class DraftQATrackerDB:
    """SQLite WAL persistence for HackerOne Draft QA Phase results and edit verification."""

    def __init__(self, db_path: str | Path = DEFAULT_QA_DB) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS qa_draft_results (
                    report_id INTEGER PRIMARY KEY,
                    url TEXT NOT NULL,
                    program TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT 'Draft',
                    qa_status TEXT NOT NULL DEFAULT 'UNCHECKED',
                    blocking_defect_count INTEGER NOT NULL DEFAULT 0,
                    defects_json TEXT NOT NULL DEFAULT '[]',
                    auto_fix_applied INTEGER NOT NULL DEFAULT 0,
                    auto_fix_changes_json TEXT NOT NULL DEFAULT '[]',
                    edit_applied_live INTEGER NOT NULL DEFAULT 0,
                    checked_at_utc TEXT NOT NULL DEFAULT ''
                );
                """
            )

    def upsert_result(self, result: QAReportResult) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO qa_draft_results (
                    report_id, url, program, title, state, qa_status,
                    blocking_defect_count, defects_json, auto_fix_applied,
                    auto_fix_changes_json, edit_applied_live, checked_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(report_id) DO UPDATE SET
                    url=excluded.url,
                    program=excluded.program,
                    title=excluded.title,
                    state=excluded.state,
                    qa_status=excluded.qa_status,
                    blocking_defect_count=excluded.blocking_defect_count,
                    defects_json=excluded.defects_json,
                    auto_fix_applied=excluded.auto_fix_applied,
                    auto_fix_changes_json=excluded.auto_fix_changes_json,
                    edit_applied_live=excluded.edit_applied_live,
                    checked_at_utc=excluded.checked_at_utc
                """,
                (
                    result.report_id,
                    result.url,
                    result.program,
                    result.title,
                    result.state,
                    result.qa_status,
                    result.blocking_defect_count,
                    json.dumps([d.to_dict() for d in result.defects]),
                    int(result.auto_fix_applied),
                    json.dumps(result.auto_fix_changes),
                    int(result.edit_applied_live),
                    result.checked_at_utc,
                ),
            )

    def get_qa_status_map(self) -> Dict[int, str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT report_id, qa_status FROM qa_draft_results").fetchall()
        return {int(r["report_id"]): str(r["qa_status"]) for r in rows}

    def list_results(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM qa_draft_results ORDER BY blocking_defect_count DESC, report_id ASC"
            ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "report_id": int(r["report_id"]),
                    "url": str(r["url"]),
                    "program": str(r["program"]),
                    "title": str(r["title"]),
                    "state": str(r["state"]),
                    "qa_status": str(r["qa_status"]),
                    "blocking_defect_count": int(r["blocking_defect_count"]),
                    "defects": json.loads(str(r["defects_json"] or "[]")),
                    "auto_fix_applied": bool(r["auto_fix_applied"]),
                    "auto_fix_changes": json.loads(str(r["auto_fix_changes_json"] or "[]")),
                    "edit_applied_live": bool(r["edit_applied_live"]),
                    "checked_at_utc": str(r["checked_at_utc"]),
                }
            )
        return out


def render_qa_markdown(summary: QASuiteSummary) -> str:
    """Render a clickable Markdown QA Phase report with every HackerOne Draft URL."""
    lines: List[str] = [
        "# HackerOne Draft Quality Assurance (QA Phase) Audit",
        "",
        f"- **Audited (UTC):** `{summary.checked_at_utc}`",
        f"- **Total Drafts Audited:** `{summary.total_audited}`",
        f"- **QA PASS (Zero Blocking Defects):** `{summary.passed_count}`",
        f"- **Auto-Fixed (Ready to Push via Edit Information):** `{summary.auto_fixed_pending_push_count}`",
        f"- **Needs Source-Verified Edit:** `{summary.needs_source_edit_count}`",
        f"- **Failed:** `{summary.failed_count}`",
        f"- **Total Defects Detected:** `{summary.total_defects}`",
        "",
    ]

    if summary.defect_counts_by_code:
        lines.append("## Defect Breakdown")
        lines.append("")
        lines.append("| Defect Code | Count |")
        lines.append("|---|---:|")
        for code, cnt in sorted(summary.defect_counts_by_code.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"| `{code}` | {cnt} |")
        lines.append("")

    flagged = [r for r in summary.results if r.qa_status != "PASS"]
    if flagged:
        lines.append("## Drafts Requiring QA Edit (Clickable HackerOne URLs)")
        lines.append("")
        lines.append("| Report | Program | QA Status | Blocking | Defect Codes | Auto-Fix Ready |")
        lines.append("|---|---|---|---:|---|---|")
        for r in flagged:
            codes = ", ".join(sorted({d.code for d in r.defects})) or "none"
            lines.append(
                f"| [#{r.report_id}]({r.url}) | `{r.program}` | `{r.qa_status}` | "
                f"{r.blocking_defect_count} | `{codes}` | `{'yes' if r.auto_fix_applied else 'no'}` |"
            )
        lines.append("")

    passed = [r for r in summary.results if r.qa_status == "PASS"]
    if passed:
        lines.append("## QA PASS Drafts (Verified Clean)")
        lines.append("")
        lines.append("| Report | Program | Title |")
        lines.append("|---|---|---|")
        for r in passed:
            lines.append(f"| [#{r.report_id}]({r.url}) | `{r.program}` | {r.title} |")
        lines.append("")

    return "\n".join(lines)


def assert_qa_passed(
    title: str,
    body: str,
    *,
    report_id: int = 0,
    program: str = "",
) -> QAReportResult:
    """
    Pre-staging hard QA gate: returns QAReportResult and raises ValueError if any
    CRITICAL or HIGH defect remains unfixed.
    """
    res = audit_draft_text(report_id=report_id, title=title, body=body, program=program)
    if res.blocking_defect_count > 0:
        codes = ", ".join(sorted({d.code for d in res.defects if d.severity in ("CRITICAL", "HIGH")}))
        raise ValueError(
            f"QA Phase gate rejected draft #{report_id} ({res.qa_status}): "
            f"{res.blocking_defect_count} blocking defect(s) [{codes}]"
        )
    return res


class DraftQAChecker:
    """
    High-throughput, semaphore-bounded QA Phase engine for HackerOne drafts.

    Supports:
      - Offline deterministic markdown/entity/structure/SELinux QA + lossless auto-repair.
      - Concurrent `raw.githubusercontent.com` source-truth verification (HTTP 200,
        quoted line matching, `#define` numeric constant & GENL family name verification).
      - Generating a clickable QA dashboard (`qa_draft_audit.md`) and a machine-readable
        `qa_edit_queue.json` containing the exact repaired text for every flagged draft.
    """

    def __init__(
        self,
        db: Optional[DraftQATrackerDB] = None,
        *,
        base_url: str = DEFAULT_HACKERONE_BASE_URL,
        max_concurrency: int = 6,
        timeout_s: float = 12.0,
        raw_fetcher: Optional[Callable[[str], Tuple[int, str]]] = None,
    ) -> None:
        self.db = db or DraftQATrackerDB()
        self.base_url = base_url.rstrip("/")
        self.max_concurrency = max(1, min(16, int(max_concurrency)))
        self.timeout_s = float(timeout_s)
        self._raw_fetcher = raw_fetcher

    def _fetch_raw_sync(self, raw_url: str) -> Tuple[int, str]:
        req = urllib_request.Request(
            raw_url,
            headers={"User-Agent": "RFCHunt-DraftQAChecker/1.0 (read-only)"},
            method="GET",
        )
        try:
            with urllib_request.urlopen(req, timeout=self.timeout_s) as resp:
                return int(getattr(resp, "status", 200)), resp.read().decode("utf-8", errors="replace")
        except urllib_error.HTTPError as exc:
            return int(exc.code), ""
        except Exception:
            return 0, ""

    async def _fetch_raw(
        self,
        raw_url: str,
        sem: asyncio.Semaphore,
        cache: Dict[str, Tuple[int, str]],
        client: Any = None,
    ) -> Tuple[int, str]:
        if raw_url in cache:
            return cache[raw_url]
        async with sem:
            if raw_url in cache:
                return cache[raw_url]
            if self._raw_fetcher is not None:
                res = await asyncio.to_thread(self._raw_fetcher, raw_url)
            elif client is not None:
                try:
                    resp = await client.get(raw_url, follow_redirects=True)
                    res = (int(resp.status_code), resp.text if resp.status_code == 200 else "")
                except Exception:
                    res = (0, "")
            else:
                res = await asyncio.to_thread(self._fetch_raw_sync, raw_url)
            cache[raw_url] = res
            return res

    async def audit_snapshots_async(
        self,
        snapshots: Iterable[Dict[str, Any]],
        *,
        verify_sources: bool = True,
        out_md: Optional[str | Path] = DEFAULT_QA_AUDIT_MD,
        out_edit_queue: Optional[str | Path] = DEFAULT_QA_EDIT_QUEUE_JSON,
    ) -> QASuiteSummary:
        snap_list = [s for s in snapshots if isinstance(s, dict)]
        results: List[QAReportResult] = []
        for snap in snap_list:
            rid = int(snap.get("id") or snap.get("report_id") or 0)
            if rid <= 0:
                continue
            title = str(snap.get("title") or "")
            body = str(snap.get("vulnerability_information") or snap.get("body") or "")
            team = snap.get("team") if isinstance(snap.get("team"), dict) else {}
            program = str(snap.get("team_handle") or team.get("handle") or snap.get("program") or "")
            state = str(snap.get("state") or "Draft")
            results.append(
                audit_draft_text(
                    report_id=rid,
                    title=title,
                    body=body,
                    program=program,
                    state=state,
                    base_url=self.base_url,
                )
            )

        if verify_sources and results:
            sem = asyncio.Semaphore(self.max_concurrency)
            raw_cache: Dict[str, Tuple[int, str]] = {}

            async def _verify_one(res: QAReportResult, client: Any = None) -> None:
                urls = _extract_github_blob_urls(res.repaired_body)
                for gh_url, raw_url in urls:
                    status, text = await self._fetch_raw(raw_url, sem, raw_cache, client=client)
                    src_res, src_defects = verify_body_against_upstream_source(
                        res.original_body, gh_url, raw_url, text, http_status=status
                    )
                    res.source_checks.append(src_res)
                    if src_defects:
                        res.defects.extend(src_defects)
                # Re-evaluate qa_status after online source verification
                blocking = [d for d in res.defects if d.severity in ("CRITICAL", "HIGH")]
                unfixable = [d for d in blocking if not d.auto_fixable]
                if not blocking:
                    res.qa_status = "PASS"
                elif res.auto_fix_applied and not unfixable:
                    res.qa_status = "AUTO_FIXED_PENDING_PUSH"
                elif unfixable:
                    res.qa_status = "NEEDS_SOURCE_EDIT"
                else:
                    res.qa_status = "FAIL"

            if httpx is not None and self._raw_fetcher is None:
                async with httpx.AsyncClient(
                    timeout=self.timeout_s,
                    headers={"User-Agent": "RFCHunt-DraftQAChecker/1.0 (read-only)"},
                ) as client:
                    await asyncio.gather(*(_verify_one(r, client=client) for r in results))
            else:
                await asyncio.gather(*(_verify_one(r, client=None) for r in results))

        defect_counts: Dict[str, int] = {}
        total_defects = 0
        for r in results:
            self.db.upsert_result(r)
            for d in r.defects:
                total_defects += 1
                defect_counts[d.code] = defect_counts.get(d.code, 0) + 1

        summary = QASuiteSummary(
            checked_at_utc=_utc_now_iso(),
            total_audited=len(results),
            passed_count=sum(1 for r in results if r.qa_status == "PASS"),
            auto_fixed_pending_push_count=sum(1 for r in results if r.qa_status == "AUTO_FIXED_PENDING_PUSH"),
            needs_source_edit_count=sum(1 for r in results if r.qa_status == "NEEDS_SOURCE_EDIT"),
            failed_count=sum(1 for r in results if r.qa_status == "FAIL"),
            total_defects=total_defects,
            defect_counts_by_code=defect_counts,
            results=results,
            audit_markdown_path=str(out_md) if out_md else "",
            edit_queue_json_path=str(out_edit_queue) if out_edit_queue else "",
        )

        if out_md:
            md_path = Path(out_md)
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(render_qa_markdown(summary), encoding="utf-8")

        if out_edit_queue:
            q_path = Path(out_edit_queue)
            q_path.parent.mkdir(parents=True, exist_ok=True)
            queue_items = [
                {
                    "report_id": r.report_id,
                    "url": r.url,
                    "program": r.program,
                    "qa_status": r.qa_status,
                    "auto_fix_applied": r.auto_fix_applied,
                    "auto_fix_changes": r.auto_fix_changes,
                    "defects": [d.to_dict() for d in r.defects],
                    "repaired_title": r.repaired_title,
                    "repaired_body": r.repaired_body,
                }
                for r in results
                if r.qa_status != "PASS"
            ]
            q_path.write_text(json.dumps(queue_items, indent=2, ensure_ascii=False), encoding="utf-8")

        return summary

    def audit_snapshots(
        self,
        snapshots: Iterable[Dict[str, Any]],
        *,
        verify_sources: bool = True,
        out_md: Optional[str | Path] = DEFAULT_QA_AUDIT_MD,
        out_edit_queue: Optional[str | Path] = DEFAULT_QA_EDIT_QUEUE_JSON,
    ) -> QASuiteSummary:
        return asyncio.run(
            self.audit_snapshots_async(
                snapshots,
                verify_sources=verify_sources,
                out_md=out_md,
                out_edit_queue=out_edit_queue,
            )
        )
