"""Zero-mock unit & local-HTTP integration tests for HackerOne Draft QA Phase Checker (`draft_qa_checker.py`)."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading

import pytest

from engine.draft_qa_checker import (
    DraftQAChecker,
    DraftQATrackerDB,
    assert_qa_passed,
    audit_draft_text,
    auto_repair_markdown,
    verify_body_against_upstream_source,
)
from engine.draft_submit_checker import DraftSubmitChecker, DraftSubmitTrackerDB
from revenue_cli import run_revenue_cli


SAMPLE_UPSTREAM_C = "\n".join(
    [
        "// header line 1",
        "// header line 2",
        "#define MAX_URL_LEN 127",
        '#define OPLUS_DNS_HOOK_FAMILY_NAME "dns_hook"',
        "static int add_dns_hook_url(struct nlattr *nla)",
        "{",
        "    if (len > MAX_URL_LEN || ntohs(nla->nla_len) < (5 + len)) {",
        "        return -EINVAL;",
        "    }",
        "    return 0;",
        "}",
    ]
)

BROKEN_DRAFT_4243961_STYLE = """## Summary
In `oppo-source/android_kernel_modules_and_devicetree_oppo_sm8750` (branch `oppo/sm8750_v_15.0.1_find_n5`),
any unprivileged local Android app (`untrusted_app`) can invoke `OPLUS_DNS_HOOK_MSG_ENABLE` via `GENL_ADMIN_PERM` omission.
Bounds check `ntohs(nla->nla_len) &lt; (5 + len)` fails when `MAX_URL_LEN == 64`.

## Exact Vulnerable Code
File: `vendor/oplus/kernel/network/oplus_dns_hook/oplus_dns_hook.c` (lines 525-595 & 633-682):
```c
545: if (len > MAX_URL_LEN || ntohs(nla->nla_len) &lt; (5 + len)) { // &lt;-- ntohs bug
678:     .flags = 0, // &lt;-- missing flag
```

## Steps to Reproduce
1. Resolve the `oplus_dns_hook` Generic Netlink family via `CTRL_CMD_GETFAMILY`.

## Recommended Remediation
Fix bounds checks.

## Impact
Device-wide DNS impact.
"""


class _LocalSourceHandler(BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, str]] = {}

    def log_message(self, format: str, *args) -> None:  # pragma: no cover
        return

    def do_GET(self) -> None:  # noqa: N802
        status, text = self.routes.get(self.path, (404, ""))
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def test_audit_catches_all_4243961_defect_classes() -> None:
    res = audit_draft_text(
        report_id=4243961,
        title="Oplus DNS Hook Test Title",
        body=BROKEN_DRAFT_4243961_STYLE,
        program="oppo_bbp",
    )
    codes = {d.code for d in res.defects}
    assert "QA_HTML_ENTITY_IN_CODE" in codes
    assert "QA_MISSING_CLICKABLE_GITHUB_URL" in codes
    assert "QA_OMITTED_CITED_LINE_RANGE" in codes
    assert "QA_NETLINK_SELINUX_OVERCLAIM" in codes
    assert "QA_NLA_LEN_MISSING_HDRLEN" in codes
    assert res.qa_status == "NEEDS_SOURCE_EDIT"
    assert res.auto_fix_applied is True
    assert "&lt;" not in res.repaired_body
    assert "SELinux" in res.repaired_body


def test_auto_repair_unescapes_code_and_prose_and_strips_control_chars() -> None:
    dirty_title = "Test\x07 Title &lt;tag&gt;"
    dirty_body = (
        "## Summary\nSee `a &lt; b &amp;&amp; c &gt; d` and prose &lt;ok&gt;.\n\n"
        "```c\nif (x &lt; 10 &amp;&amp; y &gt; 0) { // &lt;-- bug\x08 }\n```\n"
    )
    new_title, new_body, changes = auto_repair_markdown(dirty_title, dirty_body)
    assert "\x07" not in new_title
    assert "\x08" not in new_body
    assert "&lt;" not in new_title
    assert "&lt;" not in new_body
    assert "&gt;" not in new_body
    assert "&amp;" not in new_body
    assert "a < b && c > d" in new_body
    assert "if (x < 10 && y > 0) { // <-- bug }" in new_body
    assert len(changes) >= 3


def test_upstream_source_verification_catches_wrong_family_macro_and_line() -> None:
    body = """## Summary
https://github.com/oppo-source/demo/blob/main/oplus_dns_hook.c
Resolve the `oplus_dns_hook` Generic Netlink family. Assumes `MAX_URL_LEN == 64`.

```c
7: if (len > MAX_URL_LEN || ntohs(nla->nla_len) < (5 + len)) { // <-- verified line
9: totally_fabricated_code_line();
```
"""
    src_res, defects = verify_body_against_upstream_source(
        body=body,
        github_url="https://github.com/oppo-source/demo/blob/main/oplus_dns_hook.c",
        raw_url="https://raw.githubusercontent.com/oppo-source/demo/main/oplus_dns_hook.c",
        upstream_text=SAMPLE_UPSTREAM_C,
        http_status=200,
    )
    codes = {d.code for d in defects}
    assert src_res.verified_lines == 1
    assert len(src_res.mismatched_lines) == 1
    assert "QA_LINE_NUMBER_MISMATCH" in codes
    assert "QA_CONSTANT_MISMATCH" in codes
    assert any(c["name"] == "MAX_URL_LEN" and c["actual"] == 127 for c in src_res.constant_mismatches)
    assert any(c["name"] == "GENL_FAMILY_NAME" and c["claimed"] == "oplus_dns_hook" for c in src_res.constant_mismatches)


def test_clean_draft_passes_qa_and_assert_qa_passed() -> None:
    clean_body = """## Summary
In OPPO's kernel module (`https://github.com/oppo-source/demo/blob/main/oplus_dns_hook.c`),
family `"dns_hook"` defines `MAX_URL_LEN 127`. Any local process permitted `NETLINK_GENERIC` socket
access without `CAP_NET_ADMIN` under ColorOS SELinux policy can reach the handler.
`nla->nla_len` includes `NLA_HDRLEN` (4 bytes), so `nla_len(nla)` must be validated.

## Exact Vulnerable Code
Lines 5-10:
```c
5: static int add_dns_hook_url(struct nlattr *nla)
7:     if (len > MAX_URL_LEN || ntohs(nla->nla_len) < (5 + len)) {
8:         return -EINVAL;
```

## Verification Breakdown
Verified directly against line 7 and `MAX_URL_LEN == 127`.

## Recommended Remediation
Enforce `GENL_ADMIN_PERM` and `nla_len(nla)`.

## Impact
Kernel slab out-of-bounds read on ARM64.
"""
    res = assert_qa_passed("Clean Oplus DNS Hook Report", clean_body, report_id=4243961, program="oppo_bbp")
    assert res.qa_status == "PASS"
    assert res.blocking_defect_count == 0


def test_assert_qa_passed_rejects_broken_draft() -> None:
    with pytest.raises(ValueError, match="QA Phase gate rejected"):
        assert_qa_passed("Broken Draft", BROKEN_DRAFT_4243961_STYLE, report_id=4243961)


def test_hackerone_porter_auto_repairs_built_drafts() -> None:
    from engine.hackerone_porter import HackerOneCampaign, build_hackerone_report_draft

    campaign = HackerOneCampaign(
        handle="oppo_bbp",
        name="OPPO",
        url="https://hackerone.com/oppo_bbp",
        submit_url="https://hackerone.com/oppo_bbp/reports/new",
        in_scope_assets=["ColorOS"],
    )
    finding = {
        "rule_id": "OPLUS-TEST-1",
        "title": "Bounds check `nla_len &lt; 5`\x07 in oplus_dns_hook.c",
        "description": "Check `ntohs(nla->nla_len) &lt; (5 + len)` fails.",
        "evidence": "if (a &lt; b &amp;&amp; c &gt; d) {}",
        "file_path": "vendor/oplus/kernel/network/oplus_dns_hook/oplus_dns_hook.c",
        "line_number": 545,
        "severity": "high",
        "cwe": "CWE-125",
    }
    draft = build_hackerone_report_draft(finding, campaign)
    assert "&lt;" not in draft.title
    assert "\x07" not in draft.title
    assert len(draft.title) <= 140
    assert "&lt;" not in draft.vulnerability_information
    assert "&amp;" not in draft.vulnerability_information
    assert "if (a < b && c > d) {}" in draft.vulnerability_information


def test_live_http_checker_and_submit_gate_integration(tmp_path: Path) -> None:
    _LocalSourceHandler.routes = {
        "/oppo-source/demo/main/oplus_dns_hook.c": (200, SAMPLE_UPSTREAM_C),
    }
    server = HTTPServer(("127.0.0.1", 0), _LocalSourceHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        qa_db_path = tmp_path / "qa.sqlite3"
        submit_db_path = tmp_path / "submit.sqlite3"
        audit_md = tmp_path / "qa_audit.md"
        edit_q = tmp_path / "qa_edit_queue.json"
        snap_file = tmp_path / "snaps.json"

        def _local_raw_fetcher(raw_url: str) -> tuple[int, str]:
            # Redirect raw.githubusercontent.com path to our real local HTTPServer
            from urllib import request as _req

            path_part = raw_url.split("raw.githubusercontent.com", 1)[-1]
            with _req.urlopen(f"http://127.0.0.1:{port}{path_part}", timeout=5) as r:
                return int(r.status), r.read().decode("utf-8")

        auto_fix_only_body = """## Summary
See https://github.com/oppo-source/demo/blob/main/oplus_dns_hook.c for `"dns_hook"` (`MAX_URL_LEN == 127`).

## Exact Vulnerable Code
```c
7: if (len > MAX_URL_LEN || ntohs(nla->nla_len) &lt; (5 + len)) {
```
`nla->nla_len` includes `NLA_HDRLEN` (4 bytes).

## Verification
Verified on ARM64.

## Recommended Remediation
Use `nla_len(nla)` and `GENL_ADMIN_PERM`.

## Impact
Kernel slab out-of-bounds read.
"""
        clean_body = auto_fix_only_body.replace("&lt;", "<")

        snaps = [
            {
                "id": 4243972,
                "title": "Auto-fixable Entity Draft",
                "team_handle": "anthropic",
                "state": "Draft",
                "vulnerability_information": auto_fix_only_body,
            },
            {
                "id": 4243977,
                "title": "Verified Clean Draft",
                "team_handle": "anthropic",
                "state": "Draft",
                "vulnerability_information": clean_body,
            },
        ]
        snap_file.write_text(json.dumps(snaps), encoding="utf-8")

        qa_db = DraftQATrackerDB(qa_db_path)
        checker = DraftQAChecker(db=qa_db, raw_fetcher=_local_raw_fetcher)
        summary = checker.audit_snapshots(snaps, verify_sources=True, out_md=audit_md, out_edit_queue=edit_q)

        assert summary.total_audited == 2
        assert summary.passed_count == 1
        assert summary.auto_fixed_pending_push_count == 1
        assert audit_md.exists()
        assert "https://hackerone.com/reports/4243972" in audit_md.read_text(encoding="utf-8")

        queue = json.loads(edit_q.read_text(encoding="utf-8"))
        assert len(queue) == 1
        assert queue[0]["report_id"] == 4243972
        assert "&lt;" not in queue[0]["repaired_body"]

        # Verify DraftSubmitChecker HARD-BLOCKS #4243972 (AUTO_FIXED_PENDING_PUSH) and recommends #4243977 (PASS)!
        submit_db = DraftSubmitTrackerDB(submit_db_path)
        submit_db.seed_default_queue()
        submit_db.sync_qa_statuses(qa_db.get_qa_status_map())

        submit_checker = DraftSubmitChecker(db=submit_db)
        ready_summary = submit_checker.ingest_snapshots(
            [
                {"id": 4243972, "state": "Draft", "substate": "editing", "abilities": {"can_submit_draft?": True}},
                {"id": 4243977, "state": "Draft", "substate": "editing", "abilities": {"can_submit_draft?": True}},
            ],
            max_per_day=1,
            out_md=tmp_path / "ready.md",
        )
        assert ready_summary.account_status == "CLEARED"
        assert len(ready_summary.recommended_next_batch) == 1
        assert ready_summary.recommended_next_batch[0]["report_id"] == 4243977

        # Verify CLI `qa-drafts` subcommand end-to-end (offline mode)
        rc = run_revenue_cli(
            [
                "qa-drafts",
                "--snapshot-json",
                str(snap_file),
                "--db",
                str(qa_db_path),
                "--submit-db",
                str(submit_db_path),
                "--no-verify-sources",
                "--out-md",
                str(tmp_path / "cli_qa.md"),
                "--out-edit-queue",
                str(tmp_path / "cli_edit_q.json"),
                "--strict",
            ]
        )
        assert rc == 1  # strict mode rejects because #4243972 still has &lt;
    finally:
        server.shutdown()
        server.server_close()
