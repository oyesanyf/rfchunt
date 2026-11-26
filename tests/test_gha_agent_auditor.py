"""Zero-mock unit tests for `engine/gha_agent_auditor.py`."""

from __future__ import annotations

from pathlib import Path

from engine.gha_agent_auditor import audit_gha_agent_repository


def test_detects_tmp_ipc_buffer_and_fail_open_bot_guard(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()

    (src / "post_comments.ts").write_text(
        'import { readFileSync } from "fs";\n'
        'const BUFFER_PATH = "/tmp/inline-comments-buffer.jsonl";\n'
        'export function run() { return readFileSync(BUFFER_PATH, "utf8"); }\n',
        encoding="utf-8",
    )
    (src / "permissions.ts").write_text(
        'export async function checkBot(ctx: any) {\n'
        '  if (!isPullRequestEvent(ctx) || !ctx.actor.endsWith("[bot]")) {\n'
        '    return true;\n'
        '  }\n'
        '  return false;\n'
        '}\n',
        encoding="utf-8",
    )
    (src / "workflow.yml").write_text(
        'jobs:\n  run:\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n',
        encoding="utf-8",
    )

    findings = audit_gha_agent_repository(tmp_path)
    by_id = {f.rule_id: f for f in findings}
    assert "GHA-TRIGGER-INJECT-001" in by_id
    assert by_id["GHA-TRIGGER-INJECT-001"].hygiene_only is False
    assert "GHA-AGENT-BOT-002" in by_id
    assert by_id["GHA-AGENT-BOT-002"].hygiene_only is False
    assert "GHA-AGENT-IPC-001" in by_id
    assert by_id["GHA-AGENT-IPC-001"].hygiene_only is True
