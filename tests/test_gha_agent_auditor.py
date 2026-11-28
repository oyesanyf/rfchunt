"""Zero-mock unit tests for `engine/gha_agent_auditor.py`."""

from __future__ import annotations

from pathlib import Path

from engine.gha_agent_auditor import (
    audit_gha_agent_repository,
    audit_gha_workflows,
    gha_agent_findings_to_sarif,
)


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


def test_mitigated_workflow_produces_zero_high_severity_findings(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "clean.yml").write_text(
        "name: Clean Hardened CI\n"
        "on:\n"
        "  pull_request:\n"
        "    branches: [main]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - name: Safely print PR title via env indirection\n"
        "        env:\n"
        "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
        "        run: |\n"
        '          echo "$PR_TITLE"\n'
        '          echo "STATUS=ok" >> "$GITHUB_OUTPUT"\n'
        "      - uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3 # v4.3.1\n"
        "        with:\n"
        "          name: build-log\n"
        "          path: dist/\n",
        encoding="utf-8",
    )

    findings = audit_gha_workflows(tmp_path)
    high_or_crit = [f for f in findings if f.severity.upper() in ("CRITICAL", "HIGH")]
    assert high_or_crit == [], f"Unexpected high-sev findings on clean workflow: {high_or_crit}"


def test_detects_all_r1_classes_and_token_fetch_and_emits_sarif(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    src = tmp_path / "src"
    src.mkdir()

    (src / "exfil_post.ts").write_text(
        'import { readFileSync } from "fs";\n'
        'const p = "/tmp/agent-output.jsonl";\n'
        'export async function post(targetUrl: string) {\n'
        '  const data = readFileSync(p, "utf8");\n'
        '  return fetch(targetUrl, { method: "POST", headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }, body: data });\n'
        '}\n',
        encoding="utf-8",
    )

    (wf_dir / "vuln.yml").write_text(
        "name: Vulnerable AI CI\n"
        "on:\n"
        "  pull_request_target:\n"
        "    types: [opened]\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  triage:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - uses: actions/github-script@main\n"
        "        with:\n"
        "          script: |\n"
        '            const body = "${{ github.event.pull_request.body }}";\n'
        "            console.log(body);\n"
        "      - run: |\n"
        '          echo "VAR=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"\n'
        "          npm ci && npm test\n"
        "      - uses: actions/download-artifact@v4\n"
        "        with:\n"
        "          name: pr-artifact\n"
        "      - run: bash ./pr-artifact/run.sh\n"
        "      - uses: anthropics/claude-code-action@v1\n"
        "        with:\n"
        "          direct_prompt: ${{ github.event.pull_request.title }}\n"
        "        env:\n"
        "          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n",
        encoding="utf-8",
    )

    findings = audit_gha_workflows(tmp_path)
    classes = {f.gha_class for f in findings}
    rule_ids = {f.rule_id for f in findings}
    assert "GHA-AGENT-ENV-003" in rule_ids
    assert {
        "pwn_request",
        "template_script_injection",
        "unpinned_or_impostor_uses",
        "excessive_permissions",
        "github_env_path_output_injection",
        "artifact_cache_poisoning",
        "ai_agent_trigger_boundary",
    }.issubset(classes)

    sarif = gha_agent_findings_to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) >= 5
    assert len(sarif["runs"][0]["results"]) == len(findings)
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in sarif["runs"][0]["results"])
