"""
Offline guardrail tests for Milestone M1 (`policy_budget_foundation`):
- F1: Shell-free ExecutionPolicy hardening & binary allowlist
- F2: ApprovalGate alignment & DualGraphAttackEngine -> ArtexWorker wiring
- F3: RunBudgetLedger per-intent enforcement & actual worker spend charging
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile

import pytest

from database import Database
from engine.approval_gate import ApprovalGate, ApprovalRule, match_argv_prefix, parse_simple_argv
from engine.dual_graph_engine import (
    ArtexWorker,
    DualGraphAttackEngine,
    ExplorationGraph,
    RunBudgetLedger,
)
from engine.execution_policy import (
    ActionType,
    ExecutionPolicy,
    ScannerTask,
    StructuredIntentProposal,
)


@pytest.fixture(autouse=True)
def _offline_env(monkeypatch):
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    ExecutionPolicy.reset_instance()
    yield
    ExecutionPolicy.reset_instance()


# =====================================================================
# F1: ExecutionPolicy Shell-Free Hardening & Allowlist
# =====================================================================


def test_execution_policy_rejects_shell_true_and_raw_strings():
    policy = ExecutionPolicy.get_instance()

    ok, reason = policy.validate_subprocess_command(["httpx", "-version"], shell=True)
    assert ok is False
    assert "Unrequested host OS command execution blocked" in reason
    assert "forbidden" in reason.lower()

    proposal_shell = StructuredIntentProposal(
        task=ScannerTask.ARTEX_DUAL_GRAPH,
        action_type=ActionType.SUBPROCESS_EXEC,
        command_args=["httpx", "-version"],
        metadata={"shell": True},
    )
    with pytest.raises(PermissionError, match=r"Unrequested host OS command execution blocked"):
        policy.validate_intent(proposal_shell)

    for bad_cmd in (
        "httpx -u https://example.com",
        b"httpx -version",
        bytearray(b"httpx -version"),
        None,
        [],
        [""],
        ["   "],
        {"httpx"},
        ["httpx", b"-u"],
        ["httpx", None],
    ):
        ok_bad, _ = policy.validate_subprocess_command(bad_cmd)  # type: ignore[arg-type]
        assert ok_bad is False, f"Expected rejection for {bad_cmd!r}"


def test_execution_policy_blocks_shells_wrappers_and_path_prefixed_variants():
    policy = ExecutionPolicy.get_instance()
    blocked_bins = (
        "sh", "sh.exe",
        "bash", "bash.exe",
        "zsh", "zsh.exe",
        "ksh", "ksh.exe",
        "csh", "csh.exe",
        "dash", "dash.exe",
        "ash", "fish",
        "cmd", "cmd.exe",
        "powershell", "powershell.exe",
        "pwsh", "pwsh.exe",
        "env", "env.exe",
        "sudo", "sudo.exe",
        "xargs", "xargs.exe",
        "nohup", "nohup.exe",
        "timeout", "timeout.exe",
        "wscript", "wscript.exe",
        "cscript", "cscript.exe",
        "mshta", "mshta.exe",
        "rundll32", "rundll32.exe",
    )
    for bin_name in blocked_bins:
        for candidate in (
            [bin_name, "-c", "id"],
            [f"/usr/bin/{bin_name}", "-c", "id"],
            [f"C:\\Windows\\System32\\{bin_name}", "/c", "whoami"],
        ):
            ok, reason = policy.validate_subprocess_command(candidate)
            assert ok is False, f"Expected {candidate!r} to be blocked"
            assert "forbidden" in reason.lower()

            proposal = StructuredIntentProposal(
                task=ScannerTask.MANTIS_REPRO,
                action_type=ActionType.SUBPROCESS_EXEC,
                command_args=candidate,
            )
            with pytest.raises(PermissionError) as exc_info:
                policy.validate_intent(proposal)
            msg = str(exc_info.value)
            assert "Unrequested host OS command execution blocked" in msg
            assert "forbidden" in msg.lower()


def test_execution_policy_blocks_excluded_native_scanners():
    policy = ExecutionPolicy.get_instance()
    excluded_cases = [
        ["nmap", "-sV", "127.0.0.1"],
        ["nmap.exe", "-p", "80", "example.com"],
        ["/usr/bin/nmap", "example.com"],
        [r"C:\Tools\ffuf.exe", "-u", "https://example.com/FUZZ"],
        ["ffuf", "-u", "https://example.com/FUZZ"],
        ["dalfox", "url", "https://example.com"],
        ["sqlmap", "-u", "https://example.com/?id=1"],
        ["python", "-m", "sqlmap", "-u", "https://example.com/?id=1"],
        ["python3", "-msqlmap", "--batch"],
        ["python", "-m", "ffuf.cli"],
        ["python", "/opt/tools/sqlmap.py", "--batch"],
        ["python", r"C:\tools\dalfox.py"],
        ["docker", "run", "--rm", "instrumentisto/nmap:latest", "example.com"],
        ["docker", "run", "--rm", "alpine", "ffuf"],
        ["docker", "run", "--rm", "secsi/sqlmap@sha256:deadbeef", "-u", "https://example.com"],
    ]
    for cmd in excluded_cases:
        ok, reason = policy.validate_subprocess_command(cmd)
        assert ok is False, f"Expected excluded scanner {cmd!r} to be blocked"
        assert "forbidden" in reason.lower()


def test_execution_policy_blocks_shell_metacharacters_and_arg_injection():
    policy = ExecutionPolicy.get_instance()
    injected_args = [
        "https://example.com|id",
        "https://example.com||id",
        "https://example.com&&whoami",
        "https://example.com;id",
        "https://example.com&whoami",
        "https://example.com>/tmp/pwn",
        "https://example.com>>/tmp/pwn",
        "https://example.com</etc/passwd",
        "$(whoami)",
        "`id`",
        "${IFS}cat",
        "arg\nid",
        "arg\rid",
        "arg(x)",
        "arg)",
        "arg\x00null",
    ]
    for bad in injected_args:
        for cmd in (
            ["httpx", "-u", bad],
            ["katana", "-u", bad],
            ["nuclei", "-u", bad],
            ["python", "script.py", bad],
            ["docker", "run", "--rm", "projectdiscovery/httpx:latest", "-u", bad],
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", "scripts/Invoke-RaptorScan.ps1", bad],
        ):
            ok, reason = policy.validate_subprocess_command(cmd)
            assert ok is False, f"Expected metacharacter {bad!r} in {cmd!r} to be blocked"
            assert "forbidden" in reason.lower()

    ok_nested, reason_nested = policy.validate_subprocess_command(
        ["docker", "run", "--rm", "alpine", "sh", "-c", "id"]
    )
    assert ok_nested is False
    assert "forbidden" in reason_nested.lower()


def test_execution_policy_allows_scanner_binaries_and_windows_paths():
    policy = ExecutionPolicy.get_instance()
    allowed_cmds = [
        ["httpx", "-u", "https://example.com", "-jsonl"],
        [r"C:\Program Files\ProjectDiscovery\httpx.exe", "-u", "https://example.com", "-jsonl"],
        ["/usr/local/bin/katana", "-u", "https://example.com", "-jsonl"],
        ["katana.exe", "-u", "https://example.com", "-jsonl"],
        ["nuclei", "-u", "https://example.com", "-jsonl", "-tags", "tech,misconfig"],
        [r"C:\Tools\nuclei.exe", "-u", "https://example.com/nmap", "-jsonl"],
        ["docker", "image", "inspect", "raptor-dast:latest", "--format", "{{.Id}}"],
        ["docker.exe", "run", "--rm", "projectdiscovery/httpx:latest", "-u", "https://example.com", "-jsonl"],
        ["python", "-I", "-S", str(Path(tempfile.gettempdir()) / "canary.py")],
        ["python3.13.exe", "-m", "pytest", "tests/"],
        ["python", "scripts/tool.py", "-c", "config.yml"],
        ["aiscan", "scan", "--format", "json", "."],
        ["ollama", "list"],
        ["ollama.exe", "list"],
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", "scripts/Invoke-RaptorScan.ps1"],
    ]
    for cmd in allowed_cmds:
        ok, reason = policy.validate_subprocess_command(cmd)
        assert ok is True, f"Expected {cmd!r} to be allowed, got: {reason}"


def test_execution_policy_blocks_python_inline_c_and_binary_spoofing(tmp_path, monkeypatch):
    policy = ExecutionPolicy.get_instance()

    for cmd in (
        ["python", "-c", "import os; print(1)"],
        ["python3", "-Ic", "import os"],
        ["python", "-cprint(1)"],
        ["python_evil.exe", "x.py"],
        ["aiscan.sh", "scan"],
        ["../bin/httpx", "-version"],
        [r"..\tools\nuclei.exe", "-version"],
    ):
        ok, _ = policy.validate_subprocess_command(cmd)
        assert ok is False, f"Expected {cmd!r} to be blocked"

    # Symlink / resolved-target escape check: pretend binary on disk resolves to bash.exe
    fake_httpx = tmp_path / "httpx.exe"
    fake_httpx.write_text("stub", encoding="utf-8")
    real_resolve = Path.resolve

    def _mock_resolve(self, *args, **kwargs):
        if self == fake_httpx:
            return tmp_path / "bash.exe"
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", _mock_resolve)
    ok_sym, reason_sym = policy.validate_subprocess_command([str(fake_httpx), "-version"])
    assert ok_sym is False
    assert "forbidden" in reason_sym.lower()


# =====================================================================
# F2: ApprovalGate Alignment
# =====================================================================


def test_approval_gate_hard_denies_before_approve_rules():
    gate = ApprovalGate(
        mode="policy",
        rules=[
            ApprovalRule(rule_id="allow_all_regex", rule_type="regex", action="APPROVE", pattern=".*"),
            ApprovalRule(rule_id="allow_nmap", rule_type="argv_prefix", action="APPROVE", pattern=["nmap"]),
            ApprovalRule(rule_id="allow_httpx", rule_type="argv_prefix", action="APPROVE", pattern=["httpx"]),
            ApprovalRule(rule_id="allow_docker", rule_type="argv_prefix", action="APPROVE", pattern=["docker"]),
        ],
    )

    hard_deny_cases = [
        dict(action_type="subprocess", target="nmap", command=["nmap", "-sV", "127.0.0.1"], is_high_risk=True),
        dict(action_type="subprocess", target="ffuf", command="ffuf -u https://example.com/FUZZ", is_high_risk=True),
        dict(action_type="subprocess_exec", target="dalfox.exe", command=["dalfox.exe", "url", "https://example.com"], is_high_risk=True),
        dict(action_type="subprocess", target="sqlmap", command=["python", "-m", "sqlmap", "-u", "https://example.com"], is_high_risk=True),
        dict(action_type="subprocess_exec", target="docker", command=["docker", "run", "--rm", "instrumentisto/nmap"], is_high_risk=True),
        dict(action_type="subprocess_exec", target="httpx", command=["httpx", "-version"], shell=True, is_high_risk=True),
        dict(action_type="subprocess_exec", target="httpx", command="httpx -u https://example.com", is_high_risk=True),
        dict(action_type="subprocess", target="httpx", command=b"httpx -version", is_high_risk=True),
        dict(action_type="subprocess", target="cmd", command=r"C:\Windows\System32\cmd.exe /c whoami", is_high_risk=True),
        dict(action_type="subprocess", target="ps", command=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c id", is_high_risk=True),
        dict(action_type="subprocess", target="env", command="FOO=bar httpx -u https://example.com", is_high_risk=True),
        dict(action_type="subprocess_exec", target="httpx", command=["httpx", "-u", "https://example.com;id"], is_high_risk=True),
        dict(action_type="subprocess_exec", target="httpx", command=["httpx", "-u", "https://example.com\x00id"], is_high_risk=True),
        dict(action_type="subprocess_exec", target="docker", command=["docker", "run", "--rm", "--privileged", "projectdiscovery/httpx:latest"], is_high_risk=True),
        dict(action_type="subprocess_exec", target="docker", command=["docker", "run", "--rm", "-v", "/:/host", "projectdiscovery/httpx:latest"], is_high_risk=True),
        dict(action_type="subprocess_exec", target="docker", command=["docker", "run", "--rm", "alpine", "sh", "-c", "id"], is_high_risk=True),
        dict(action_type="subprocess_exec", target="httpx", command=["httpx", "-u", "http://169.254.169.254/latest/meta-data"], is_high_risk=True),
    ]
    for case in hard_deny_cases:
        dec = gate.check(**case)
        assert dec.approved is False, f"Expected hard deny for {case}"
        assert dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Expected EXECUTION_POLICY_HARD_DENY for {case}, got {dec}"

    with pytest.raises(PermissionError):
        gate.require(action_type="subprocess_exec", target="httpx", command=["httpx", "-version"], shell=True)


def test_approval_gate_regex_inspects_command_and_argv_prefix_windows_exe():
    # Windows backslash string command preserves backslashes in parse_simple_argv
    win_tokens = parse_simple_argv(r"C:\Tools\httpx.exe -u https://example.com -jsonl")
    assert win_tokens == [r"C:\Tools\httpx.exe", "-u", "https://example.com", "-jsonl"]
    assert parse_simple_argv(r"C:\Windows\System32\cmd.exe /c whoami") is None
    assert parse_simple_argv(["nmap", "-sV", "127.0.0.1"]) is None

    # Pathless argv_prefix=["httpx"] matches Windows .exe path
    assert match_argv_prefix(["httpx"], [r"C:\Tools\httpx.exe", "-u", "https://example.com"]) is True
    assert match_argv_prefix(["docker", "run", "--rm"], ["docker.exe", "run", "--rm", "projectdiscovery/httpx:latest"]) is True
    # Path-qualified pattern stays strict
    assert match_argv_prefix(["/usr/local/bin/httpx"], [r"C:\Tools\httpx.exe", "-version"]) is False

    # regex rule inspects command flags/arguments even when target/rationale omit them
    gate = ApprovalGate(
        mode="policy",
        rules=[
            ApprovalRule(rule_id="deny_custom_dns", rule_type="regex", action="DENY", pattern=r"--dns=1\.1\.1\.1"),
            ApprovalRule(rule_id="allow_httpx", rule_type="argv_prefix", action="APPROVE", pattern=["httpx"]),
            ApprovalRule(rule_id="allow_docker", rule_type="argv_prefix", action="APPROVE", pattern=["docker"]),
        ],
    )
    dec_hard_net = gate.check(
        action_type="subprocess_exec",
        target="docker",
        command=["docker", "run", "--rm", "--network=host", "projectdiscovery/httpx:latest"],
        is_high_risk=True,
    )
    assert dec_hard_net.approved is False
    assert dec_hard_net.rule_id == "EXECUTION_POLICY_HARD_DENY"

    dec_deny = gate.check(
        action_type="subprocess_exec",
        target="docker",
        command=["docker", "run", "--rm", "--dns=1.1.1.1", "projectdiscovery/httpx:latest"],
        is_high_risk=True,
    )
    assert dec_deny.approved is False
    assert dec_deny.rule_id == "deny_custom_dns"

    dec_win = gate.check(
        action_type="subprocess_exec",
        target="httpx",
        command=[r"C:\Tools\httpx.exe", "-u", "https://example.com", "-jsonl"],
        is_high_risk=True,
    )
    assert dec_win.approved is True
    assert dec_win.rule_id == "allow_httpx"


def test_approval_gate_opt_in_scanners_across_modes_and_risk_levels():
    scanner_cmds = [
        ["httpx", "-u", "https://example.com", "-jsonl"],
        ["katana", "-u", "https://example.com", "-jsonl"],
        ["nuclei", "-u", "https://example.com", "-jsonl", "-tags", "tech"],
        ["docker", "run", "--rm", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
        ["docker", "image", "inspect", "raptor-dast:latest", "--format", "{{.Id}}"],
    ]

    # 1. policy mode, is_high_risk=False, no rules -> approved by policy
    gate_policy = ApprovalGate(mode="policy")
    for cmd in scanner_cmds:
        dec = gate_policy.check(action_type="subprocess_exec", target=cmd[0], command=cmd, is_high_risk=False)
        assert dec.approved is True and dec.decided_by == "policy", f"Expected policy approval for {cmd}, got {dec}"

    # 2. policy mode, is_high_risk=True, no rules -> denied by policy
    for cmd in scanner_cmds:
        dec = gate_policy.check(action_type="subprocess_exec", target=cmd[0], command=cmd, is_high_risk=True)
        assert dec.approved is False and dec.decided_by == "policy"

    # 3. unallowlisted non-high-risk subprocess with no matching rule -> denied
    dec_rm = gate_policy.check(action_type="subprocess", target="rm", command=["rm", "-rf", "/"], is_high_risk=False)
    assert dec_rm.approved is False and dec_rm.decided_by == "policy"

    # 4. legacy action_type="subprocess" with explicit APPROVE rule remains supported
    gate_git = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="allow_git_status", rule_type="argv_prefix", action="APPROVE", pattern=["git", "status"])],
    )
    dec_git = gate_git.check(
        action_type="subprocess",
        target="git status --short",
        command="git status --short",
        is_high_risk=True,
    )
    assert dec_git.approved is True and dec_git.rule_id == "allow_git_status"

    # 5. DENY rule overrides APPROVE rule
    gate_precedence = ApprovalGate(
        mode="policy",
        rules=[
            ApprovalRule(rule_id="allow_nuclei", rule_type="argv_prefix", action="APPROVE", pattern=["nuclei"]),
            ApprovalRule(rule_id="deny_nuclei_tags", rule_type="regex", action="DENY", pattern=r"-tags\s+tech"),
        ],
    )
    dec_prec = gate_precedence.check(
        action_type="subprocess_exec",
        target="nuclei",
        command=["nuclei", "-u", "https://example.com", "-jsonl", "-tags", "tech"],
        is_high_risk=True,
    )
    assert dec_prec.approved is False and dec_prec.rule_id == "deny_nuclei_tags" and dec_prec.decided_by == "rule"

    # 6. deny mode rejects unmatched httpx subprocess_exec
    gate_deny = ApprovalGate(mode="deny")
    dec_deny = gate_deny.check(
        action_type="subprocess_exec",
        target="httpx",
        command=["httpx", "-u", "https://example.com", "-jsonl"],
        is_high_risk=False,
    )
    assert dec_deny.approved is False and dec_deny.decided_by == "system"
    with pytest.raises(PermissionError):
        gate_deny.require(
            action_type="subprocess_exec",
            target="httpx",
            command=["httpx", "-u", "https://example.com", "-jsonl"],
        )

    # 7. prompt mode prompts for valid command, but fails closed BEFORE prompting for nmap/shell=True
    prompts_seen = []

    def _fake_input(_prompt: str) -> str:
        prompts_seen.append("prompted")
        return "a"

    gate_prompt = ApprovalGate(mode="prompt", input_fn=_fake_input, output_fn=lambda _msg: None)
    dec_nmap = gate_prompt.check(action_type="subprocess_exec", target="nmap", command=["nmap", "127.0.0.1"])
    assert dec_nmap.approved is False and dec_nmap.rule_id == "EXECUTION_POLICY_HARD_DENY"
    assert len(prompts_seen) == 0

    dec_ok_prompt = gate_prompt.check(
        action_type="subprocess_exec",
        target="httpx",
        command=["httpx", "-u", "https://example.com", "-jsonl"],
    )
    assert dec_ok_prompt.approved is True and dec_ok_prompt.decided_by == "human"
    assert len(prompts_seen) == 1


# =====================================================================
# F2 & F3: RunBudgetLedger & DualGraphAttackEngine -> ArtexWorker Wiring
# =====================================================================


def test_run_budget_ledger_per_intent_caps_env_and_snapshot(monkeypatch):
    monkeypatch.setenv("ARTEX_INTENT_BUDGET_TOKENS", "2500")
    monkeypatch.setenv("ARTEX_INTENT_BUDGET_TURNS", "4")

    ledger = RunBudgetLedger()
    assert ledger.max_intent_tokens == 2500
    assert ledger.max_intent_turns == 4
    snap = ledger.snapshot()
    assert snap["max_intent_tokens"] == 2500
    assert snap["max_intent_turns"] == 4
    assert snap["intents"] == {}

    # 0 = unlimited
    unlimited = RunBudgetLedger(max_intent_tokens=0, max_intent_turns=0)
    assert unlimited.can_start_intent(999_999, 999) is True

    # Boundary enforcement (>=)
    assert ledger.check_intent_budget(2499, 3) == (True, "")
    assert ledger.check_intent_budget(2500, 3)[0] is False
    assert ledger.check_intent_budget(100, 4)[0] is False
    assert ledger.can_start_intent(2499, 3) is True
    assert ledger.can_start_intent(2500, 0) is False
    assert ledger.can_start_intent(0, 4) is False

    # Task hard-cap fallback even when intent caps are higher
    task_capped = RunBudgetLedger(max_task_tokens=1000, max_intent_tokens=5000, max_intent_turns=10)
    task_capped.record_worker_run(tokens=1000, turns=1, intent_id="CAND-X")
    assert task_capped.check_intent_budget(10, 1)[0] is False
    assert task_capped.can_start_intent(10, 1) is False

    # Per-intent isolation via intent_id
    ledger.record_worker_run(tokens=2500, turns=2, intent_id="CAND-1")
    assert ledger.get_intent_usage("CAND-1") == {"tokens": 2500, "turns": 2}
    assert ledger.get_intent_usage("CAND-2") == {"tokens": 0, "turns": 0}
    assert ledger.can_start_intent(intent_id="CAND-1") is False
    assert ledger.can_start_intent(intent_id="CAND-2") is True
    assert ledger.snapshot()["intents"]["CAND-1"] == {"tokens": 2500, "turns": 2}


def test_artex_worker_charges_executor_usage_and_defers_exhausted_intent(tmp_path):
    # Backward compatibility: direct ArtexWorker instantiation without new kwargs
    legacy_worker = ArtexWorker(ExplorationGraph(task_id="LEGACY-TASK"))
    assert legacy_worker.approval_gate is None
    assert legacy_worker.arbiter is None
    assert legacy_worker.asset_graph is None

    db = Database(":memory:")
    try:
        eng = DualGraphAttackEngine(
            db=db,
            reports_dir=tmp_path / "r",
            task_id="TASK-INTENT-CHARGE",
            max_intent_tokens=1000,
            max_intent_turns=3,
        )
        cand1 = eng.exploration_graph.add_intent(
            node_id="CAND-CHARGE-1",
            node_type="ATTACK_CANDIDATE",
            label="Test 4-tuple spend",
            attributes={"target_host": "127.0.0.1", "target_route": "/api/test"},
        )
        seen_attrs = {}

        def _exec_4tuple(exec_attrs):
            seen_attrs.update(exec_attrs)
            return True, "verified", "GET /api/test", {"tokens_used": 640, "turns_used": 2}

        assert eng.worker.execute_candidate(cand1, executor_fn=_exec_4tuple) is True
        assert seen_attrs["intent_id"] == "CAND-CHARGE-1"
        assert eng.budget_ledger.used_tokens == 640
        assert eng.budget_ledger.used_turns == 2
        assert eng.budget_ledger.get_intent_usage("CAND-CHARGE-1") == {"tokens": 640, "turns": 2}
        assert cand1.attributes["intent_tokens_used"] == 640
        assert cand1.attributes["intent_turns_used"] == 2
        assert db.get_task_llm_usage("TASK-INTENT-CHARGE")["total_tokens"] == 640

        # Pre-exhausted intent is deferred BEFORE invoking executor_fn
        cand2 = eng.exploration_graph.add_intent(
            node_id="CAND-EXHAUSTED-2",
            node_type="ATTACK_CANDIDATE",
            label="Exhausted intent",
            attributes={"target_host": "127.0.0.1", "target_route": "/api/exhausted"},
        )
        eng.budget_ledger.record_worker_run(tokens=0, turns=3, intent_id="CAND-EXHAUSTED-2")
        called = []

        def _spy_exec(_attrs):
            called.append(True)
            return True, "should not run", ""

        assert eng.worker.execute_candidate(cand2, executor_fn=_spy_exec) is False
        assert called == []
        assert cand2.attributes["budget_deferred"] is True
        assert cand2.attributes["intent_budget_exhausted"] is True
        assert cand2.status == "PENDING"

        # Legacy 3-tuple executor charges tokens=0, turns=1
        cand3 = eng.exploration_graph.add_intent(
            node_id="CAND-LEGACY-3",
            node_type="ATTACK_CANDIDATE",
            label="Legacy 3-tuple",
            attributes={"target_host": "127.0.0.1", "target_route": "/api/legacy"},
        )
        assert eng.worker.execute_candidate(cand3, executor_fn=lambda _a: (True, "ok", "GET /api/legacy")) is True
        assert eng.budget_ledger.get_intent_usage("CAND-LEGACY-3") == {"tokens": 0, "turns": 1}
    finally:
        db.close()


def test_dual_graph_engine_wires_approval_gate_arbiter_asset_graph_and_offline_compat(tmp_path):
    class _OfflineArbiter:
        def arbitrate_structured_json(self, *a, **kw):
            return {"status": "offline_fallback", "data": {"intents": []}}

    db = Database(":memory:")
    try:
        gate = ApprovalGate(mode="policy", db=db)
        stub = _OfflineArbiter()
        eng = DualGraphAttackEngine(
            db=db,
            reports_dir=tmp_path / "r2",
            task_id="TASK-WIRING",
            approval_gate=gate,
            arbiter=stub,
            max_intent_tokens=1500,
            max_intent_turns=4,
        )
        assert eng.worker.approval_gate is gate
        assert eng.worker.arbiter is stub
        assert eng.worker.asset_graph is eng.asset_graph
        snap = eng.budget_ledger.snapshot()
        assert snap["max_intent_tokens"] == 1500
        assert snap["max_intent_turns"] == 4

        eng.ingest_target_infrastructure(host="127.0.0.1", port=8080, endpoints=["/internal/service"])
        eng.ingest_finding(
            {"rule_id": "MANTIS-AUTH-011", "title": "OIDC Service Route", "file_path": "/internal/service"},
            scanner="mantis",
        )
        eng.run_attack_chain_cycle(round_num=1)

        planner_rows = db.conn.execute(
            "SELECT * FROM llm_usage WHERE task_id='TASK-WIRING' AND role='planner'"
        ).fetchall()
        assert len(planner_rows) == 0
    finally:
        db.close()


def test_dual_graph_engine_run_attack_chain_cycle_defers_intent_exceeding_budget(tmp_path):
    for worker_count in (1, 2):
        db = Database(":memory:")
        try:
            eng = DualGraphAttackEngine(
                db=db,
                reports_dir=tmp_path / f"r_cyc_{worker_count}",
                task_id=f"TASK-CYC-{worker_count}",
                workers=worker_count,
                max_intent_tokens=500,
                max_intent_turns=2,
            )
            c_blocked = eng.exploration_graph.add_intent(
                node_id="CAND-PRE-EXHAUSTED",
                node_type="ATTACK_CANDIDATE",
                label="Pre-exhausted candidate",
                attributes={"target_host": "127.0.0.1", "target_route": "/blocked"},
            )
            c_allowed = eng.exploration_graph.add_intent(
                node_id="CAND-ALLOWED",
                node_type="ATTACK_CANDIDATE",
                label="Allowed candidate",
                attributes={"target_host": "127.0.0.1", "target_route": "/allowed"},
            )
            eng.budget_ledger.record_worker_run(tokens=500, turns=1, intent_id="CAND-PRE-EXHAUSTED")

            dispatched_ids = []

            def _exec(attrs):
                dispatched_ids.append(attrs["intent_id"])
                return True, "ok", "GET /allowed", {"tokens_used": 100, "turns_used": 1}

            res = eng.run_attack_chain_cycle(round_num=1, executor_fn=_exec)
            assert "CAND-PRE-EXHAUSTED" not in dispatched_ids
            assert "CAND-ALLOWED" in dispatched_ids
            assert c_blocked.attributes.get("intent_budget_exhausted") is True
            assert c_blocked.attributes.get("budget_deferred") is True
            assert c_allowed.status == "VERIFIED"
            assert res["budget"]["intents"]["CAND-ALLOWED"] == {"tokens": 100, "turns": 1}
        finally:
            db.close()


# =====================================================================
# Iteration 2 Hardening Regression Tests (Reviewers 1/2, Challengers 1/2, Auditor 1)
# =====================================================================


def test_execution_policy_iteration2_hardening_bypasses_and_whoami_url(tmp_path, monkeypatch):
    import socket

    policy = ExecutionPolicy.get_instance()

    # 1. os.PathLike spoofing __str__ vs __fspath__ (and bytes __fspath__)
    class _SpoofPathLike:
        def __init__(self, str_val: str, fs_val):
            self._s = str_val
            self._fs = fs_val

        def __str__(self) -> str:
            return self._s

        def __fspath__(self):
            return self._fs

    ok_spoof, _ = policy.validate_subprocess_command([_SpoofPathLike("httpx", "/bin/sh"), "-c", "id"])
    assert ok_spoof is False
    ok_bytes_fs, _ = policy.validate_subprocess_command([_SpoofPathLike("httpx", b"/bin/sh"), "-version"])
    assert ok_bytes_fs is False

    # 2. Prefix env assignments and whitespace obfuscation in tokens[0]
    for bad_t0 in (
        ["FOO=aiscan", "scan"],
        ["LD_PRELOAD=/tmp/x.so", "httpx"],
        ["httpx ", "-version"],
        [" httpx", "-version"],
        ["bash ", "-c", "id"],
    ):
        ok, _ = policy.validate_subprocess_command(bad_t0)
        assert ok is False, f"Expected rejection for {bad_t0!r}"

    # 3. Windows drive-relative path traversal
    for trav in ([r"C:..\httpx.exe", "-version"], ["D:../nuclei.exe", "-version"], ["C:.."]):
        ok, _ = policy.validate_subprocess_command(trav)
        assert ok is False, f"Expected traversal rejection for {trav!r}"

    # 4. Symlink / resolved-target must ALSO pass allowlist (e.g. katana.exe -> nc.exe)
    fake_katana = tmp_path / "katana.exe"
    fake_katana.write_text("stub", encoding="utf-8")
    real_resolve = Path.resolve

    def _mock_resolve_nc(self, *args, **kwargs):
        if self == fake_katana:
            return tmp_path / "nc.exe"
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", _mock_resolve_nc)
    ok_nc, reason_nc = policy.validate_subprocess_command([str(fake_katana), "-version"])
    assert ok_nc is False
    assert "forbidden" in reason_nc.lower()

    # 5. Tightened is_aiscan allowlist
    assert policy.validate_subprocess_command(["evil_aiscan_tool.exe", "--help"])[0] is False
    assert policy.validate_subprocess_command(["aiscan-cli", "scan"])[0] is True
    assert policy.validate_subprocess_command(["aiscan_runner.exe", "scan"])[0] is True
    assert policy.validate_subprocess_command(["aiscan-cli.sh", "scan"])[0] is False

    # 6. /api/whoami URL false-positive exemption (and no DNS lookup on domain hostnames)
    def _no_dns(*_args, **_kwargs):
        raise AssertionError("ExecutionPolicy.validate_subprocess_command must not invoke socket.getaddrinfo")

    monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
    assert policy.validate_subprocess_command(["httpx", "-u", "https://example.com/api/whoami"])[0] is True
    assert policy.validate_subprocess_command(["httpx", "-u=https://example.com/api/whoami"])[0] is True
    # Bare non-URL whoami argument remains blocked
    assert policy.validate_subprocess_command(["python", "scripts/tool.py", "whoami"])[0] is False

    # 7. IP-literal SSRF blocked in ExecutionPolicy without DNS
    for ssrf_cmd in (
        ["httpx", "-u", "http://169.254.169.254/latest/meta-data"],
        ["httpx", "-u=http://169.254.169.254/latest/meta-data"],
        ["httpx", "-u", "169.254.169.254"],
        ["httpx", "-u", "0.0.0.0"],
        ["httpx", "-u", "[::ffff:127.0.0.1]"],
        ["httpx", "-u", "http://10.0.0.1/"],
        ["httpx", "-u=http://"],
    ):
        assert policy.validate_subprocess_command(ssrf_cmd)[0] is False, f"Expected SSRF block for {ssrf_cmd!r}"
    # Loopback IP literal stays permitted
    assert policy.validate_subprocess_command(["httpx", "-u", "https://127.0.0.1:8080/api/whoami", "-jsonl"])[0] is True

    # 8. Python combined -m flags (-umsqlmap, -Imdalfox)
    for py_bad in (
        ["python", "-umsqlmap", "-u", "https://127.0.0.1"],
        ["python", "-Imdalfox"],
        ["python", "-W", "ignore", "-um", "sqlmap"],
    ):
        assert policy.validate_subprocess_command(py_bad)[0] is False, f"Expected Python -m block for {py_bad!r}"
    assert policy.validate_subprocess_command(["python", "-umpytest", "tests/"])[0] is True


def test_execution_policy_and_approval_gate_docker_and_powershell_unification():
    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(
        mode="policy",
        rules=[
            ApprovalRule(rule_id="allow_all", rule_type="regex", action="APPROVE", pattern=".*"),
            ApprovalRule(rule_id="allow_py", rule_type="argv_prefix", action="APPROVE", pattern=["python"]),
        ],
    )
    gate_no_rules = ApprovalGate(mode="policy")

    blocked_docker_cmds = [
        ["docker", "run", "--rm", "--privileged", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--privileged=true", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "/:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "/etc:/host_etc", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--volume=C:\\:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "C:\\:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "c:/:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--mount=type=bind,source=C:\\,target=/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--entrypoint=sh", "alpine"],
        ["docker", "run", "--rm", "--entrypoint=bash", "alpine"],
        ["docker", "run", "--rm", "--entrypoint=/bin/zsh", "alpine"],
        ["docker", "run", "--rm", "--entrypoint", "/bin/sh", "alpine"],
        ["docker", "run", "--rm", "--entrypoint=nmap", "alpine"],
        ["docker", "run", "--rm", "alpine", "/bin/sh"],
        ["docker", "run", "--rm", "alpine", "bash", "-lc", "id"],
        ["docker", "--debug", "run", "--rm", "alpine", "bash", "-lc", "id"],
        ["docker", "--context", "default", "run", "--rm", "alpine", "sh"],
        ["docker", "exec", "cid", "bash", "-lc", "id"],
    ]
    for cmd in blocked_docker_cmds:
        ok, _ = policy.validate_subprocess_command(cmd)
        assert ok is False, f"ExecutionPolicy must block {cmd!r}"
        with pytest.raises(PermissionError):
            policy.validate_intent(
                StructuredIntentProposal(
                    task=ScannerTask.ARTEX_DUAL_GRAPH,
                    action_type=ActionType.SUBPROCESS_EXEC,
                    command_args=cmd,
                )
            )
        dec_rule = gate.check(action_type="subprocess_exec", target="docker", command=cmd, is_high_risk=True)
        assert dec_rule.approved is False and dec_rule.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate(rules) must hard-deny {cmd!r}, got {dec_rule}"
        dec_plain = gate_no_rules.check(action_type="subprocess_exec", target="docker", command=cmd, is_high_risk=False)
        assert dec_plain.approved is False and dec_plain.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate(no rules) must hard-deny {cmd!r}, got {dec_plain}"

    # Safe docker image inspect & safe docker run remain allowed
    for safe_docker in (
        ["docker", "image", "inspect", "raptor-dast:latest", "--format", "{{.Id}}"],
        ["docker", "--context", "default", "image", "inspect", "raptor-dast:latest", "--format", "{{.Id}}"],
        ["docker", "run", "--rm", "projectdiscovery/httpx:latest", "-u", "https://127.0.0.1:8080/api/whoami", "-jsonl"],
    ):
        ok, reason = policy.validate_subprocess_command(safe_docker)
        assert ok is True, f"Expected safe docker command {safe_docker!r} allowed, got: {reason}"
        dec = gate_no_rules.check(action_type="subprocess_exec", target="docker", command=safe_docker, is_high_risk=False)
        assert dec.approved is True, f"Expected Gate approval for {safe_docker!r}, got: {dec}"

    # PowerShell _is_safe_raptor_ps1 bypasses must be rejected by both layers
    bad_ps_cmds = [
        ["powershell", "/Command", "Start-Process calc", "-File", "scripts/Invoke-RaptorScan.ps1"],
        ["powershell", "/EncodedCommand", "ZABpAHIA", "-File", "scripts/Invoke-RaptorScan.ps1"],
        ["powershell", "/c", "calc", "-File", "scripts/Invoke-RaptorScan.ps1"],
        ["powershell", "/ec", "ZABpAHIA", "-File", "scripts/Invoke-RaptorScan.ps1"],
        ["powershell", "evil.ps1", "-File", "scripts/Invoke-RaptorScan.ps1"],
        ["powershell", "-File", r"C:\evil\pwn.ps1", "-f", "Invoke-RaptorScan.ps1"],
        ["powershell", "-File", "scripts/evil.ps1", "-File", "scripts/Invoke-RaptorScan.ps1"],
    ]
    for ps_cmd in bad_ps_cmds:
        assert policy.validate_subprocess_command(ps_cmd)[0] is False, f"Policy must reject {ps_cmd!r}"
        dec = gate.check(action_type="subprocess_exec", target="powershell", command=ps_cmd, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate must hard-deny {ps_cmd!r}"

    # Trailing whitespace binary obfuscation & legacy subprocess python -c / -umsqlmap
    for hard_cmd, act_type in (
        (["bash ", "-c", "id"], "subprocess"),
        (["cmd.exe ", "/c", "calc"], "subprocess"),
        (["nmap ", "-sV", "127.0.0.1"], "subprocess"),
        (["python", "-c", "import os"], "subprocess"),
        (["python", "-Ic", "import os"], "subprocess"),
        (["python", "-umsqlmap", "-u", "https://127.0.0.1"], "subprocess"),
        (["python", "-umsqlmap", "-u", "https://127.0.0.1"], "subprocess_exec"),
    ):
        dec = gate.check(action_type=act_type, target=hard_cmd[0], command=hard_cmd, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate must hard-deny {act_type} {hard_cmd!r}, got {dec}"

    # ApprovalGate SSRF on -flag=URL, bare IP, and empty-host scheme
    for ssrf_cmd in (
        ["httpx", "-u=http://169.254.169.254/latest/meta-data/"],
        ["httpx", "--url=http://169.254.169.254/"],
        ["httpx", "-u", "169.254.169.254"],
        ["httpx", "-u", "0.0.0.0"],
        ["httpx", "-u", "[::ffff:127.0.0.1]"],
        ["httpx", "-u=http://"],
    ):
        dec_r = gate.check(action_type="subprocess_exec", target="httpx", command=ssrf_cmd, is_high_risk=True)
        assert dec_r.approved is False and dec_r.rule_id == "EXECUTION_POLICY_HARD_DENY"
        dec_n = gate_no_rules.check(action_type="subprocess_exec", target="httpx", command=ssrf_cmd, is_high_risk=False)
        assert dec_n.approved is False and dec_n.rule_id == "EXECUTION_POLICY_HARD_DENY"


def test_budget_ledger_malformed_inputs_min_turn_and_concurrent_task_cap(tmp_path, monkeypatch):
    import time

    # 1. Invalid env vars fail safely to 0 (unlimited) without raising ValueError
    for bad_env in ("abc", "10.5", "inf", "-5"):
        monkeypatch.setenv("ARTEX_INTENT_BUDGET_TOKENS", bad_env)
        monkeypatch.setenv("ARTEX_INTENT_BUDGET_TURNS", bad_env)
        ledger = RunBudgetLedger()
        assert ledger.max_intent_tokens == 0
        assert ledger.max_intent_turns == 0

    monkeypatch.delenv("ARTEX_INTENT_BUDGET_TOKENS", raising=False)
    monkeypatch.delenv("ARTEX_INTENT_BUDGET_TURNS", raising=False)

    # 2. Corrupt candidate attributes, float('inf') meta, and negative/zero turns_used
    db = Database(":memory:")
    try:
        eng = DualGraphAttackEngine(db=db, reports_dir=tmp_path / "r_safe", task_id="TASK-SAFE-PARSE")
        cand_bad = eng.exploration_graph.add_intent(
            node_id="CAND-BAD-ATTR",
            node_type="ATTACK_CANDIDATE",
            label="Corrupt attr",
            attributes={
                "target_host": "127.0.0.1",
                "target_route": "/bad",
                "intent_tokens_used": "corrupt",
                "intent_turns_used": float("inf"),
            },
        )
        assert eng.worker.execute_candidate(
            cand_bad,
            executor_fn=lambda _a: (True, "ok", "GET /bad", {"tokens_used": float("inf"), "turns_used": 1}),
        ) is True
        assert cand_bad.status == "VERIFIED"
        assert eng.budget_ledger.get_intent_usage("CAND-BAD-ATTR") == {"tokens": 0, "turns": 1}

        # turns_used <= 0 or False must still charge at least 1 turn
        for idx, meta_turns in enumerate((-3, 0, False), start=1):
            cid = f"CAND-MIN-TRN-{idx}"
            c = eng.exploration_graph.add_intent(
                node_id=cid,
                node_type="ATTACK_CANDIDATE",
                label=f"Min turn {idx}",
                attributes={"target_host": "127.0.0.1", "target_route": f"/min/{idx}"},
            )
            eng.worker.execute_candidate(
                c,
                executor_fn=lambda _a, mt=meta_turns: (False, "fail", "p", {"tokens_used": -50, "turns_used": mt}),
            )
            usage = eng.budget_ledger.get_intent_usage(cid)
            assert usage["tokens"] == 0
            assert usage["turns"] >= 1, f"Expected turns >= 1 for meta turns_used={meta_turns!r}, got {usage}"
    finally:
        db.close()

    # 3. Concurrent run_attack_chain_cycle must NEVER overshoot max_task_turns
    db_conc = Database(":memory:")
    try:
        eng_conc = DualGraphAttackEngine(
            db=db_conc,
            reports_dir=tmp_path / "r_conc",
            task_id="TASK-CONC-CAP-13",
            workers=8,
            max_task_tokens=0,
            max_task_turns=13,
        )
        for i in range(20):
            eng_conc.exploration_graph.add_intent(
                node_id=f"CAND-RACE-{i}",
                node_type="ATTACK_CANDIDATE",
                label=f"Race candidate {i}",
                attributes={"target_host": "127.0.0.1", "target_route": f"/race/{i}"},
            )

        def _slow_exec(_attrs):
            time.sleep(0.05)
            return True, "ok", "GET /race", {"tokens_used": 10, "turns_used": 1}

        res = eng_conc.run_attack_chain_cycle(round_num=1, executor_fn=_slow_exec)
        assert res["budget"]["used_turns"] <= 13
        assert eng_conc.budget_ledger.used_turns <= 13
    finally:
        db_conc.close()


# =====================================================================
# Iteration 3 Hardening Regression Tests (Reviewers 3/4, Challengers 3/4)
# =====================================================================


def test_execution_policy_and_approval_gate_iteration3_python_docker_and_ssrf(tmp_path, monkeypatch):
    import socket

    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="allow_all", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    gate_no_rules = ApprovalGate(mode="policy")

    # 1. Python combined value-taking short flags (-uW, -uX, -IX, -uWignore) & Docker python* payload
    bad_py_and_docker_py = [
        ["python", "-uW", "ignore", "-c", "import os"],
        ["python", "-uX", "dev", "-m", "sqlmap.cli"],
        ["python", "-IX", "dev", "-c", "id"],
        ["python", "-uWignore", "-c", "id"],
        ["docker", "run", "--rm", "alpine", "python", "-msqlmap"],
        ["docker", "run", "--rm", "alpine", "python3", "-uW", "ignore", "-c", "id"],
    ]
    for cmd in bad_py_and_docker_py:
        assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must block {cmd!r}"
        for act in ("subprocess_exec", "subprocess"):
            dec = gate.check(action_type=act, target=cmd[0], command=cmd, is_high_risk=True)
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate({act}) must block {cmd!r}, got {dec}"

    for safe_py in (
        ["python", "-uW", "ignore", "-m", "pytest", "tests/"],
        ["python", "-uWonce", "-m", "pytest", "tests/"],
        ["python", "-uX", "dev", "-m", "pytest", "tests/"],
    ):
        assert policy.validate_subprocess_command(safe_py)[0] is True, f"Expected safe python cmd allowed: {safe_py!r}"

    # 2. Docker nested subcommands, /c check order, redundant slashes, .., Windows dirs, -v=
    bad_docker_iter3 = [
        ["docker", "container", "run", "--rm", "alpine", "sh"],
        ["docker", "container", "run", "--rm", "alpine", "bash", "--login", "-c", "id"],
        ["docker", "container", "exec", "cid", "/bin/bash"],
        ["docker", "container", "create", "--rm", "alpine", "sh"],
        ["docker", "compose", "exec", "svc", "sh"],
        ["docker", "compose", "-f", "compose.yml", "exec", "svc", "sh"],
        ["docker", "compose", "--project-name", "p", "run", "svc", "/bin/sh"],
        ["docker", "service", "create", "alpine", "sh"],
        ["docker", "run", "--rm", "myimage", "/c", "calc"],
        ["docker", "run", "--rm", "-v", "//etc:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "-v", "///etc:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "-v", "//:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "-v", "/tmp/../etc:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "-v", "/home/..:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "-v", r"C:\Windows:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "-v", r"C:\Users\alice:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "-v=/:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--mount", "type=bind,source=/home/..,target=/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--mount=type=bind,source=///var/run/docker.sock,target=/var/run/docker.sock", "projectdiscovery/httpx:latest"],
    ]
    for cmd in bad_docker_iter3:
        assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must block {cmd!r}"
        dec_r = gate.check(action_type="subprocess_exec", target="docker", command=cmd, is_high_risk=True)
        assert dec_r.approved is False and dec_r.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate(rules) must block {cmd!r}, got {dec_r}"
        dec_n = gate_no_rules.check(action_type="subprocess_exec", target="docker", command=cmd, is_high_risk=False)
        assert dec_n.approved is False and dec_n.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate(no rules) must block {cmd!r}, got {dec_n}"

    for safe_docker in (
        ["docker", "compose", "ps"],
        ["docker", "run", "--rm", "-v", "/tmp/rfchunt_out:/out", "projectdiscovery/httpx:latest", "-u", "https://127.0.0.1:8080/api/whoami"],
    ):
        assert policy.validate_subprocess_command(safe_docker)[0] is True, f"Expected safe docker cmd allowed: {safe_docker!r}"

    # 3. Non-canonical IPv4 SSRF URLs (and zero DNS lookup on domain hostnames)
    def _no_dns(*_args, **_kwargs):
        raise AssertionError("validate_subprocess_command must not invoke socket.getaddrinfo")

    monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
    non_canonical_ssrf = [
        ["httpx", "-u", "http://2130706433/"],
        ["httpx", "-u", "http://0x7f000001/"],
        ["httpx", "-u", "http://127.1/"],
        ["httpx", "-u", "http://2852039166/latest/meta-data/"],
        ["httpx", "-u", "http://0xa9fea9fe/latest/meta-data/"],
        ["httpx", "-u", "http://0251.0376.0251.0376/"],
        ["httpx", "-u", "http://0:8080/"],
        ["httpx", "-u", "2130706433"],
        ["httpx", "-u=0xa9fea9fe"],
        ["httpx", "-u", "0"],
    ]
    for cmd in non_canonical_ssrf:
        assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject obfuscated SSRF {cmd!r}"
        dec_r = gate.check(action_type="subprocess_exec", target="httpx", command=cmd, is_high_risk=True)
        assert dec_r.approved is False and dec_r.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate must hard-deny {cmd!r}, got {dec_r}"

    assert policy.validate_subprocess_command(["httpx", "-u", "https://127.0.0.1:8080/api/whoami", "-jsonl"])[0] is True
    assert policy.validate_subprocess_command(["httpx", "-u", "https://example.com/api/whoami", "-retries", "0", "-rl", "10"])[0] is True

    # Network-action SSRF rejection for obfuscated IPv4 targets
    for net_target in ("http://2130706433/", "http://0xa9fea9fe/latest/meta-data/", "0251.0376.0251.0376"):
        dec_net = gate.check(action_type="network_socket", target=net_target, is_high_risk=True)
        assert dec_net.approved is False and dec_net.rule_id == "EXECUTION_POLICY_HARD_DENY"

    # 4. ApprovalGate(action_type="subprocess") symlink escape, C:.. traversal, and PowerShell --%
    fake_katana = tmp_path / "katana.exe"
    fake_katana.write_text("stub", encoding="utf-8")
    fake_py3 = tmp_path / "python3"
    fake_py3.write_text("stub", encoding="utf-8")
    real_resolve = Path.resolve

    def _mock_resolve(self, *args, **kwargs):
        if self == fake_katana:
            return tmp_path / "nc.exe"
        if self == fake_py3:
            return tmp_path / "python3.13"
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", _mock_resolve)

    dec_katana_sub = gate.check(
        action_type="subprocess",
        target=str(fake_katana),
        command=[str(fake_katana), "-version"],
        is_high_risk=True,
    )
    assert dec_katana_sub.approved is False and dec_katana_sub.rule_id == "EXECUTION_POLICY_HARD_DENY"

    dec_py3_sub = gate.check(
        action_type="subprocess",
        target=str(fake_py3),
        command=[str(fake_py3), "-m", "pytest", "tests/"],
        is_high_risk=True,
    )
    assert dec_py3_sub.approved is True

    dec_drive_rel_sub = gate.check(
        action_type="subprocess",
        target=r"C:..\httpx.exe",
        command=[r"C:..\httpx.exe", "-version"],
        is_high_risk=True,
    )
    assert dec_drive_rel_sub.approved is False and dec_drive_rel_sub.rule_id == "EXECUTION_POLICY_HARD_DENY"

    gate_git = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="allow_git_status", rule_type="argv_prefix", action="APPROVE", pattern=["git", "status"])],
    )
    dec_git = gate_git.check(action_type="subprocess", target="git status --short", command="git status --short", is_high_risk=True)
    assert dec_git.approved is True and dec_git.rule_id == "allow_git_status"

    for bad_ps_stop in (
        ["powershell", "--%", "-File", "scripts/Invoke-RaptorScan.ps1"],
        ["powershell", "-File", "scripts/Invoke-RaptorScan.ps1", "--%", "-Command", "id"],
    ):
        assert policy.validate_subprocess_command(bad_ps_stop)[0] is False
        dec_ps = gate.check(action_type="subprocess_exec", target="powershell", command=bad_ps_stop, is_high_risk=True)
        assert dec_ps.approved is False and dec_ps.rule_id == "EXECUTION_POLICY_HARD_DENY"


def test_budget_ledger_concurrent_max_task_tokens_no_overshoot(tmp_path):
    import time

    db = Database(":memory:")
    try:
        eng = DualGraphAttackEngine(
            db=db,
            reports_dir=tmp_path / "r_tok_cap",
            task_id="TASK-TOK-CONC-100K",
            workers=8,
            max_task_tokens=100_000,
            max_task_turns=0,
        )
        for i in range(15):
            eng.exploration_graph.add_intent(
                node_id=f"CAND-TOK-{i}",
                node_type="ATTACK_CANDIDATE",
                label=f"Token cap race {i}",
                attributes={"target_host": "127.0.0.1", "target_route": f"/tok/{i}"},
            )

        def _tok_exec(_attrs):
            time.sleep(0.03)
            return True, "ok", "GET /tok", {"tokens_used": 25_000, "turns_used": 1}

        res = eng.run_attack_chain_cycle(round_num=1, executor_fn=_tok_exec)
        snap = eng.budget_ledger.snapshot()
        assert res["budget"]["used_tokens"] <= 100_000
        assert snap["used_tokens"] <= 100_000
        assert res["budget"]["reserved_tokens"] == 0
        assert snap["reserved_tokens"] == 0
    finally:
        db.close()


# =====================================================================
# Iteration 4 Hardening Regression Tests (Reviewer 5/6, Challenger 5)
# =====================================================================


def test_execution_policy_and_approval_gate_iteration4_symlinks_entrypoint_mounts_and_numeric_flags(
    tmp_path, monkeypatch
):
    import socket

    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="allow_all", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    gate_no_rules = ApprovalGate(mode="policy")

    # 1. Cross-tool symlink resolution bypass vs same-family aliases
    fake_katana = tmp_path / "katana.exe"
    fake_httpx = tmp_path / "httpx.exe"
    fake_httpx_noext = tmp_path / "httpx"
    fake_docker = tmp_path / "docker.exe"
    fake_python = tmp_path / "python.exe"
    fake_py3 = tmp_path / "python3"
    fake_aiscan = tmp_path / "aiscan"
    fake_git = tmp_path / "git.exe"
    for p in (fake_katana, fake_httpx, fake_httpx_noext, fake_docker, fake_python, fake_py3, fake_aiscan, fake_git):
        p.write_text("stub", encoding="utf-8")

    real_resolve = Path.resolve
    alias_map = {
        fake_katana: tmp_path / "python3.13.exe",
        fake_httpx: tmp_path / "docker.exe",
        fake_httpx_noext: tmp_path / "httpx.exe",
        fake_docker: tmp_path / "python3.13.exe",
        fake_python: tmp_path / "docker.exe",
        fake_py3: tmp_path / "python3.13",
        fake_aiscan: tmp_path / "aiscan-worker",
        fake_git: tmp_path / "python3.13.exe",
    }

    def _mock_resolve(self, *args, **kwargs):
        if self in alias_map:
            return alias_map[self]
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", _mock_resolve)

    cross_tool_cmds = [
        [str(fake_katana), "-c", "import os"],
        [str(fake_katana), "-m", "sqlmap"],
        [str(fake_httpx), "run", "--privileged", "-v", "/:/host", "alpine", "sh"],
        [str(fake_docker), "-c", "import os"],
        [str(fake_python), "run", "--privileged", "-v", "/:/host", "alpine", "sh"],
        [str(fake_git), "-c", "import os"],
    ]
    for cmd in cross_tool_cmds:
        assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject cross-tool symlink {cmd!r}"
        with pytest.raises(PermissionError):
            policy.validate_intent(
                StructuredIntentProposal(
                    task=ScannerTask.ARTEX_DUAL_GRAPH,
                    action_type=ActionType.SUBPROCESS_EXEC,
                    command_args=cmd,
                )
            )
        for act in ("subprocess_exec", "subprocess"):
            dec = gate.check(action_type=act, target=cmd[0], command=cmd, is_high_risk=True)
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                f"Gate({act}) must hard-deny {cmd!r}, got {dec}"
            )
            dec_n = gate_no_rules.check(action_type=act, target=cmd[0], command=cmd, is_high_risk=False)
            assert dec_n.approved is False and dec_n.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                f"Gate-no-rules({act}) must hard-deny {cmd!r}, got {dec_n}"
            )

    same_family_cmds = [
        [str(fake_py3), "-m", "pytest", "tests/"],
        [str(fake_httpx_noext), "-u", "https://example.com", "-jsonl"],
        [str(fake_aiscan), "scan", "--format", "json", "."],
    ]
    for cmd in same_family_cmds:
        assert policy.validate_subprocess_command(cmd)[0] is True, f"Same-family alias must be allowed: {cmd!r}"
        dec = gate_no_rules.check(action_type="subprocess_exec", target=cmd[0], command=cmd, is_high_risk=False)
        assert dec.approved is True, f"Gate must allow same-family alias {cmd!r}, got {dec}"

    # 2. Docker --entrypoint=python* / --entrypoint python* payload validation
    bad_docker_py_ep = [
        ["docker", "run", "--rm", "--entrypoint=python3", "alpine", "-umsqlmap"],
        ["docker", "run", "--rm", "--entrypoint=python3", "alpine", "-m", "sqlmap.cli"],
        ["docker", "run", "--rm", "--entrypoint=python3", "alpine", "-Bc", "import os"],
        ["docker", "run", "--rm", "--entrypoint=python3", "alpine", "-cimport os"],
        ["docker", "run", "--rm", "--entrypoint", "python3", "alpine", "-Bc", "import os"],
        ["docker", "run", "--rm", "--entrypoint", "/usr/bin/python3.12", "alpine", "-uW", "ignore", "-c", "id"],
        ["docker", "container", "run", "--rm", "--entrypoint=python3", "alpine", "sqlmap.py"],
        ["docker", "run", "--rm", "--unknown-flag", "val", "--entrypoint=python3", "alpine", "-Bc", "import os"],
    ]
    for cmd in bad_docker_py_ep:
        assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject docker python entrypoint {cmd!r}"
        dec = gate.check(action_type="subprocess_exec", target="docker", command=cmd, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate must reject {cmd!r}, got {dec}"

    for safe_ep in (
        ["docker", "run", "--rm", "--entrypoint=python3", "alpine", "-m", "pytest", "tests/"],
        ["docker", "run", "--rm", "projectdiscovery/httpx:latest", "-u", "https://127.0.0.1:8080/api/whoami", "-jsonl"],
        ["docker", "image", "inspect", "raptor-dast:latest", "--format", "{{.Id}}"],
    ):
        assert policy.validate_subprocess_command(safe_ep)[0] is True, f"Expected safe docker cmd allowed: {safe_ep!r}"

    # 3. Docker mount . segment, UNC/Win32 device prefixes, and drive-relative Windows paths
    bad_docker_mounts = [
        ["docker", "run", "-v", "/./etc:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "/./:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "/.:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "/var/run/./docker.sock:/var/run/docker.sock", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "C:/./Windows:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", r"C:\.\Windows:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", r"\\?\C:\Windows:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", r"\\.\C:\Windows:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", r"\\127.0.0.1\c$:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "//./pipe/docker_engine:/var/run/docker.sock", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "//localhost/c$/Windows:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "c:windows:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--mount=type=bind,source=/./etc,target=/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--mount=type=bind,source=/./var/run/docker.sock,target=/var/run/docker.sock", "projectdiscovery/httpx:latest"],
    ]
    for cmd in bad_docker_mounts:
        assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject unsafe mount {cmd!r}"
        for act in ("subprocess_exec", "subprocess"):
            dec = gate.check(action_type=act, target="docker", command=cmd, is_high_risk=True)
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                f"Gate({act}) must reject mount {cmd!r}, got {dec}"
            )

    for safe_mount in (
        ["docker", "run", "--rm", "-v", "/tmp/rfchunt_out:/out", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
        ["docker", "run", "--rm", "-v", r"D:\work\out:/out", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
    ):
        assert policy.validate_subprocess_command(safe_mount)[0] is True, f"Expected safe mount allowed: {safe_mount!r}"

    # 4. Benign numeric CLI flags > 65535 allowed vs SSRF target flags rejected (with zero DNS lookups in ExecutionPolicy)
    def _no_dns(*_args, **_kwargs):
        raise AssertionError("validate_subprocess_command must not invoke socket.getaddrinfo")

    benign_numeric_cmds = [
        ["httpx", "-u", "https://example.com", "-body-read-limit", "1048576"],
        ["nuclei", "-u", "https://example.com", "-max-host-error", "100000"],
        ["python", "-m", "pytest", "--maxfail=100000", "tests/"],
    ]
    with monkeypatch.context() as m:
        m.setattr(socket, "getaddrinfo", _no_dns)
        for cmd in benign_numeric_cmds:
            ok, reason = policy.validate_subprocess_command(cmd)
            assert ok is True, f"Benign numeric flag must be allowed for {cmd!r}, got: {reason}"

    def _public_dns(host, *_args, **_kwargs):
        if host == "example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        raise AssertionError(f"Unexpected DNS lookup for {host!r}")

    with monkeypatch.context() as m:
        m.setattr(socket, "getaddrinfo", _public_dns)
        for cmd in benign_numeric_cmds:
            dec = gate_no_rules.check(action_type="subprocess_exec", target=cmd[0], command=cmd, is_high_risk=False)
            assert dec.approved is True, f"Gate must allow benign numeric flag {cmd!r}, got: {dec}"

    ssrf_target_cmds = [
        ["httpx", "--target", "2130706433"],
        ["httpx", "--proxy=2130706433"],
        ["httpx", "2130706433"],
        ["httpx", "-max-host-error", "2130706433:8080"],
        ["httpx", "-u", "http://2130706433/"],
        ["httpx", "-u", "http://0:8080/"],
    ]
    with monkeypatch.context() as m:
        m.setattr(socket, "getaddrinfo", _no_dns)
        for cmd in ssrf_target_cmds:
            assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject SSRF target {cmd!r}"
            dec = gate.check(action_type="subprocess_exec", target="httpx", command=cmd, is_high_risk=True)
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                f"Gate must reject SSRF target {cmd!r}, got {dec}"
            )


# =====================================================================
# Iteration 5 Hardening Regression Tests (Challenger 7 Findings 1-6)
# =====================================================================


def test_execution_policy_and_approval_gate_iteration5_challenger7_hardening(tmp_path, monkeypatch):
    import socket

    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="allow_all", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    gate_no_rules = ApprovalGate(mode="policy")

    def _no_dns(*_args, **_kwargs):
        raise AssertionError("validate_subprocess_command must not invoke socket.getaddrinfo")

    def _public_dns(host, *_args, **_kwargs):
        if host == "example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        raise AssertionError(f"Unexpected DNS lookup for {host!r}")

    # 1 & 3. Boolean / =val / unlisted proxy flags + URL authority backslash-@ differential
    ssrf_bypass_cmds = [
        ["httpx", "-jsonl", "2130706433"],
        ["httpx", "-silent", "2852039166"],
        ["httpx", "-u=https://example.com", "2852039166"],
        ["httpx", "-H", "X-Test: 1", "-jsonl", "2130706433"],
        ["nuclei", "-jsonl", "2130706433"],
        ["katana", "-jc", "017700000001"],
        ["httpx", "--proxy-url", "2130706433"],
        ["httpx", "-socks-proxy", "2130706433"],
        ["python", "-B", "2130706433"],
        ["python", "-u", "2130706433"],
        ["docker", "run", "--rm", "projectdiscovery/httpx:latest", "-u", "2130706433"],
        ["httpx", "-u", r"http://169.254.169.254\@example.com/"],
        ["httpx", r"-u=http://169.254.169.254\@example.com/"],
    ]
    with monkeypatch.context() as m:
        m.setattr(socket, "getaddrinfo", _no_dns)
        for cmd in ssrf_bypass_cmds:
            assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject SSRF bypass {cmd!r}"
            with pytest.raises(PermissionError):
                policy.validate_intent(
                    StructuredIntentProposal(
                        task=ScannerTask.ARTEX_DUAL_GRAPH,
                        action_type=ActionType.SUBPROCESS_EXEC,
                        command_args=cmd,
                    )
                )
    with monkeypatch.context() as m:
        m.setattr(socket, "getaddrinfo", _public_dns)
        for cmd in ssrf_bypass_cmds:
            for act in ("subprocess_exec", "subprocess"):
                dec = gate.check(action_type=act, target=cmd[0], command=cmd, is_high_risk=True)
                assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                    f"Gate({act}) must reject SSRF bypass {cmd!r}, got {dec}"
                )

        # Direct network_socket target backslash-@ check
        dec_net = gate.check(
            action_type="network_socket",
            target=r"http://169.254.169.254\@example.com/",
            is_high_risk=True,
        )
        assert dec_net.approved is False and dec_net.rule_id == "EXECUTION_POLICY_HARD_DENY"

    # 2. Docker -u 0 / -u 0:0 / -u 1000 positive controls (zero DNS lookups in ExecutionPolicy)
    docker_u_allowed = [
        ["docker", "run", "--rm", "--entrypoint", "python3", "-e", "VAR=1", "-u", "0", "--workdir", "/app", "alpine", "-m", "pytest", "tests/"],
        ["docker", "run", "--rm", "-u", "0", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
        ["docker", "run", "--rm", "-u", "0:0", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
        ["docker", "run", "--rm", "-u", "1000", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
        ["httpx", "-u", "https://example.com", "-timeout", "100000"],
        ["httpx", "-u", "https://example.com", "--max-size=1048576"],
        ["httpx", "-u", "https://example.com", "--body-read-limit=1048576"],
    ]
    with monkeypatch.context() as m:
        m.setattr(socket, "getaddrinfo", _no_dns)
        for cmd in docker_u_allowed:
            ok, reason = policy.validate_subprocess_command(cmd)
            assert ok is True, f"Expected positive control allowed: {cmd!r}, got: {reason}"
    with monkeypatch.context() as m:
        m.setattr(socket, "getaddrinfo", _public_dns)
        for cmd in docker_u_allowed:
            dec = gate_no_rules.check(action_type="subprocess_exec", target=cmd[0], command=cmd, is_high_risk=False)
            assert dec.approved is True, f"Gate(no rules) must allow {cmd!r}, got: {dec}"
            dec_r = gate.check(action_type="subprocess_exec", target=cmd[0], command=cmd, is_high_risk=True)
            assert dec_r.approved is True, f"Gate(allow_all) must allow {cmd!r}, got: {dec_r}"

    # 4. PowerShell .ps1 symlink bypass (raptorscan.ps1 / Invoke-RaptorScan.ps1 -> evil.ps1)
    fake_raptor1 = tmp_path / "raptorscan.ps1"
    fake_raptor2 = tmp_path / "Invoke-RaptorScan.ps1"
    fake_evil = tmp_path / "evil.ps1"
    for p in (fake_raptor1, fake_raptor2, fake_evil):
        p.write_text("# stub", encoding="utf-8")

    real_resolve = Path.resolve

    def _mock_ps1_resolve(self, *args, **kwargs):
        if self in (fake_raptor1, fake_raptor2):
            return fake_evil
        return real_resolve(self, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(Path, "resolve", _mock_ps1_resolve)
        for ps_cmd in (
            ["powershell", "-File", str(fake_raptor1)],
            ["powershell", "-NoProfile", "-File", str(fake_raptor2)],
        ):
            assert policy.validate_subprocess_command(ps_cmd)[0] is False, f"Policy must reject ps1 symlink {ps_cmd!r}"
            for act in ("subprocess_exec", "subprocess"):
                dec = gate.check(action_type=act, target="powershell", command=ps_cmd, is_high_risk=True)
                assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                    f"Gate({act}) must reject ps1 symlink {ps_cmd!r}, got {dec}"
                )

    # 5. Docker --mount CSV quotes/whitespace & Win32 trailing-dot/space mount bypasses
    bad_mounts_iter5 = [
        ["docker", "run", "--mount", 'type=bind,source="/etc",target=/host', "projectdiscovery/httpx:latest"],
        ["docker", "run", "--mount", 'type=bind,source="/./etc",target=/host', "projectdiscovery/httpx:latest"],
        ["docker", "run", "--mount", 'type=bind,"source=/etc",target=/host', "projectdiscovery/httpx:latest"],
        ["docker", "run", "--mount", "type=bind, source=/etc, target=/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "C:/Windows./:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "-v", "C:/Windows /:/host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--mount", r'type=bind,source="C:\Windows.",target=/host', "projectdiscovery/httpx:latest"],
    ]
    for cmd in bad_mounts_iter5:
        assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject mount {cmd!r}"
        for act in ("subprocess_exec", "subprocess"):
            dec = gate.check(action_type=act, target="docker", command=cmd, is_high_risk=True)
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                f"Gate({act}) must reject mount {cmd!r}, got {dec}"
            )

    # 6. Docker --entrypoint=python3.13t / pythonw & direct python3.13t / pythonw invocations
    bad_py_variants = [
        ["docker", "run", "--rm", "--entrypoint=python3.13t", "alpine", "-Bc", "import os"],
        ["docker", "run", "--rm", "--entrypoint=pythonw", "alpine", "-Bc", "import os"],
        ["docker", "run", "--rm", "--entrypoint", "python3.13t.exe", "alpine", "-m", "sqlmap"],
        ["python3.13t", "-c", "import os"],
        ["pythonw.exe", "-Ic", "import os"],
    ]
    for cmd in bad_py_variants:
        assert policy.validate_subprocess_command(cmd)[0] is False, f"Policy must reject python variant {cmd!r}"
        dec = gate.check(action_type="subprocess_exec", target=cmd[0], command=cmd, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
            f"Gate must reject python variant {cmd!r}, got {dec}"
        )

    assert policy.validate_subprocess_command(["docker", "run", "--rm", "--entrypoint=python3.13t", "alpine", "-m", "pytest", "tests/"])[0] is True
    assert policy.validate_subprocess_command(["pythonw", "-m", "pytest", "tests/"])[0] is True


def test_file_write_and_binary_candidate_canonical_containment(tmp_path, monkeypatch):
    from engine.approval_gate import ApprovalGate, ApprovalRule
    from engine.execution_policy import ActionType, ExecutionPolicy, ScannerTask, StructuredIntentProposal
    from engine.external_scanners import _validate_binary_candidate

    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="ALLOW-ALL", rule_type="regex", action="APPROVE", pattern=".*")],
    )

    fs_touches = []
    orig_exists = Path.exists
    orig_is_symlink = Path.is_symlink
    orig_is_dir = Path.is_dir
    orig_is_file = Path.is_file
    orig_resolve = Path.resolve

    def _is_probe(s: str) -> bool:
        norm = s.replace("\\", "/")
        norm_l = norm.lower()
        return (
            norm.startswith("//")
            or norm_l.startswith(("/??/", "/device/", "/global??/", "/dosdevices/"))
            or ":stream" in norm_l
            or ":$data" in norm_l
            or "\x00" in s
        )

    def _wrap(name, orig):
        def _inner(self, *args, **kwargs):
            s = str(self)
            if _is_probe(s):
                fs_touches.append((name, s))
            return orig(self, *args, **kwargs)
        return _inner

    monkeypatch.setattr(Path, "exists", _wrap("exists", orig_exists))
    monkeypatch.setattr(Path, "is_symlink", _wrap("is_symlink", orig_is_symlink))
    monkeypatch.setattr(Path, "is_dir", _wrap("is_dir", orig_is_dir))
    monkeypatch.setattr(Path, "is_file", _wrap("is_file", orig_is_file))
    monkeypatch.setattr(Path, "resolve", _wrap("resolve", orig_resolve))

    forbidden_writes = [
        r"reports\out.txt:stream",
        r"reports\out.txt:alt:$DATA",
        "reports/out.txt\x00.png",
        "reports/out.txt\r\n",
        "reports/out.txt/",
        "reports/out.txt.",
        "reports/out.txt ",
        r"\??\UNC\sample-host\share\out.txt",
        "/??/UNC/sample-host/share/out.txt",
        r"\Device\Mup\sample-host\share\out.txt",
        r"\Global??\UNC\sample-host\share\out.txt",
        r"\DosDevices\C:\out.txt",
        "C:out.txt",
        r"reports_evil\sample.txt",
        r"out_evil\sample.txt",
        str(Path(tempfile.gettempdir()).resolve().parent / "Temp_evil" / "sample.txt"),
        r"C:\Windows\Temp\sample_outside.db",
        "engine/evil.db",
        ".git/evil.sqlite",
    ]
    for target in forbidden_writes:
        proposal = StructuredIntentProposal(
            task=ScannerTask.ARTEX_DUAL_GRAPH,
            action_type=ActionType.FILE_WRITE,
            file_path=target,
            rationale="Adversarial file write",
        )
        with pytest.raises(PermissionError):
            policy.validate_intent(proposal)
        dec = gate.check(action_type="file_write", target=target, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", f"Gate must deny {target!r}: {dec}"

    for bad_bin in (
        r"\??\UNC\sample-host\share\httpx.exe",
        "/??/UNC/sample-host/share/httpx.exe",
        r"\Device\Mup\sample-host\share\httpx.exe",
        "C:httpx.exe",
        "httpx.exe:stream",
        "httpx.exe/",
        "httpx.exe.",
    ):
        with pytest.raises(PermissionError):
            _validate_binary_candidate(bad_bin, "httpx")

    assert fs_touches == [], f"Unexpected FS touches on adversarial paths: {fs_touches}"

    for ok_write in (
        "reports/out.txt",
        "terminator.db",
        "data/ok.sqlite",
        str(Path(tempfile.gettempdir()) / "rfchunt_test_ok.db"),
    ):
        proposal = StructuredIntentProposal(
            task=ScannerTask.ARTEX_DUAL_GRAPH,
            action_type=ActionType.FILE_WRITE,
            file_path=ok_write,
            rationale="Legitimate write",
        )
        assert policy.validate_intent(proposal) is True
        dec = gate.check(action_type="file_write", target=ok_write, is_high_risk=True)
        assert dec.approved is True, f"Legitimate write {ok_write!r} must be approved: {dec}"


def test_del_and_globalroot_canonical_and_mount_guardrails(monkeypatch):
    from engine.approval_gate import ApprovalGate, ApprovalRule, parse_simple_argv
    from engine.execution_policy import (
        ActionType,
        ExecutionPolicy,
        ScannerTask,
        StructuredIntentProposal,
        _is_unsafe_mount_source,
    )
    from engine.external_scanners import _validate_binary_candidate

    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="ALLOW-ALL", rule_type="regex", action="APPROVE", pattern=".*")],
    )

    fs_touches = []
    orig_exists = Path.exists
    orig_is_symlink = Path.is_symlink
    orig_is_dir = Path.is_dir
    orig_is_file = Path.is_file
    orig_resolve = Path.resolve

    def _wrap_all(name, orig):
        def _inner(self, *args, **kwargs):
            fs_touches.append((name, str(self)))
            return orig(self, *args, **kwargs)
        return _inner

    monkeypatch.setattr(Path, "exists", _wrap_all("exists", orig_exists))
    monkeypatch.setattr(Path, "is_symlink", _wrap_all("is_symlink", orig_is_symlink))
    monkeypatch.setattr(Path, "is_dir", _wrap_all("is_dir", orig_is_dir))
    monkeypatch.setattr(Path, "is_file", _wrap_all("is_file", orig_is_file))
    monkeypatch.setattr(Path, "resolve", _wrap_all("resolve", orig_resolve))

    for bad_write in (
        "reports/out.txt\x7f",
        r"\GlobalRoot\Device\Mup\sample-host\share\out.txt",
        "/GlobalRoot/Device/Mup/sample-host/share/out.txt",
    ):
        proposal = StructuredIntentProposal(
            task=ScannerTask.ARTEX_DUAL_GRAPH,
            action_type=ActionType.FILE_WRITE,
            file_path=bad_write,
            rationale="Adversarial DEL/GlobalRoot file write",
        )
        with pytest.raises(PermissionError):
            policy.validate_intent(proposal)
        dec = gate.check(action_type="file_write", target=bad_write, is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY"

    for bad_bin in (
        "httpx.exe\x7f",
        r"\GlobalRoot\Device\Mup\sample-host\share\httpx.exe",
        "/GlobalRoot/Device/Mup/sample-host/share/httpx.exe",
    ):
        assert parse_simple_argv([bad_bin, "-version"]) is None
        assert policy.validate_subprocess_command([bad_bin, "-version"])[0] is False
        dec = gate.check(action_type="subprocess", target=bad_bin, command=[bad_bin, "-version"], is_high_risk=True)
        assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY"
        with pytest.raises(PermissionError):
            _validate_binary_candidate(bad_bin, "httpx")

    assert _is_unsafe_mount_source("data\x7f") is True
    assert _is_unsafe_mount_source("/tmp/data\x7f") is True
    assert _is_unsafe_mount_source(r"\GlobalRoot\Device\Mup\sample-host\share\data") is True
    assert _is_unsafe_mount_source("/GlobalRoot/Device/Mup/sample-host/share/data") is True

    assert fs_touches == [], f"DEL/GlobalRoot guardrails must trigger 0 FS touches, got: {fs_touches}"
    fs_touches.clear()

    assert policy.validate_subprocess_command(
        ["docker", "run", "--rm", "-v", r"\GlobalRoot\Device\Mup\sample-host\share\data:/data", "projectdiscovery/httpx:latest"]
    )[0] is False
    assert policy.validate_subprocess_command(
        ["docker", "run", "--rm", "-v", "/tmp/data\x7f:/data", "projectdiscovery/httpx:latest"]
    )[0] is False

    assert all(p == "docker" for _, p in fs_touches), f"Unexpected FS touches on docker mount paths: {fs_touches}"


def test_execution_policy_and_approval_gate_docker_subcommands_escape_flags_and_payloads():
    policy = ExecutionPolicy.get_instance()
    gate_permissive = ApprovalGate(
        mode="policy",
        rules=[
            ApprovalRule(rule_id="allow_all", rule_type="regex", action="APPROVE", pattern=".*"),
            ApprovalRule(rule_id="allow_docker", rule_type="argv_prefix", action="APPROVE", pattern=["docker"]),
        ],
    )
    gate_policy = ApprovalGate(mode="policy")

    blocked_cmds = [
        # Disallowed docker subcommands
        ["docker"],
        ["docker", "--version"],
        ["docker", "version"],
        ["docker", "cp", "/etc/passwd", "cid:/tmp/p"],
        ["docker", "build", "-t", "evil", "."],
        ["docker", "save", "-o", "img.tar", "alpine"],
        ["docker", "export", "cid"],
        ["docker", "commit", "cid", "evil:latest"],
        ["docker", "login", "registry.example.com"],
        ["docker", "system", "prune"],
        ["docker", "rm", "-f", "cid"],
        ["docker", "kill", "cid"],
        ["docker", "container", "rm", "cid"],
        ["docker", "container", "exec", "cid", "id"],
        ["docker", "compose", "up", "-d"],
        ["docker", "exec", "cid", "cat", "/etc/shadow"],
        ["docker", "exec", "cid", "curl", "https://example.com"],
        ["docker", "create", "--rm", "alpine", "id"],
        # Container isolation-escape flags (--flag=val and --flag val)
        ["docker", "run", "--rm", "--network=host", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
        ["docker", "run", "--rm", "--network", "host", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
        ["docker", "run", "--rm", "--net=host", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
        ["docker", "run", "--rm", "--net", "host", "projectdiscovery/httpx:latest", "-u", "https://example.com"],
        ["docker", "run", "--rm", "--network=container:target", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--pid=host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--pid", "host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--ipc=host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--ipc", "host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--uts=host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--uts", "host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--userns=host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--cgroupns=host", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--cap-add=ALL", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--cap-add", "NET_ADMIN", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--security-opt=seccomp=unconfined", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--security-opt", "seccomp=unconfined", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--security-opt=apparmor=unconfined", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--security-opt=label=disable", "projectdiscovery/httpx:latest"],
        ["docker", "run", "--rm", "--security-opt=no-new-privileges=false", "projectdiscovery/httpx:latest"],
        # FORBIDDEN_SHELL_COMMANDS in docker run payload
        ["docker", "run", "--rm", "alpine", "cat", "/etc/shadow"],
        ["docker", "run", "--rm", "alpine", "curl", "https://example.com"],
        ["docker", "run", "--rm", "alpine", "wget", "https://example.com"],
        ["docker", "run", "--rm", "alpine", "whoami"],
    ]

    for cmd in blocked_cmds:
        ok, reason = policy.validate_subprocess_command(cmd, shell=False)
        assert ok is False, f"ExecutionPolicy must reject {cmd!r}, got: {reason}"
        with pytest.raises(PermissionError):
            policy.validate_intent(
                StructuredIntentProposal(
                    task=ScannerTask.ARTEX_DUAL_GRAPH,
                    action_type=ActionType.SUBPROCESS_EXEC,
                    command_args=cmd,
                )
            )
        for gate_obj, risk in ((gate_permissive, True), (gate_policy, False)):
            dec = gate_obj.check(
                action_type="subprocess_exec",
                target="docker",
                command=cmd,
                is_high_risk=risk,
            )
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                f"Expected EXECUTION_POLICY_HARD_DENY (risk={risk}) for {cmd!r}, got {dec}"
            )

    # Safe hardened docker invocations remain permitted
    for safe_cmd in (
        [
            "docker",
            "run",
            "--rm",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=128",
            "--memory=512m",
            "--cpus=1.0",
            "--network",
            "none",
            "projectdiscovery/httpx:latest",
            "-u",
            "http://127.0.0.1:8080",
            "-jsonl",
        ],
        ["docker", "container", "run", "--rm", "projectdiscovery/nuclei:latest", "-u", "http://127.0.0.1:8080"],
        ["docker", "image", "inspect", "raptor-dast:latest", "--format", "{{.Id}}"],
        ["docker", "compose", "ps"],
    ):
        ok, reason = policy.validate_subprocess_command(safe_cmd, shell=False)
        assert ok is True, f"Safe docker command {safe_cmd!r} rejected: {reason}"
        dec = gate_policy.check(action_type="subprocess_exec", target="docker", command=safe_cmd, is_high_risk=False)
        assert dec.approved is True, f"Safe docker command {safe_cmd!r} denied by policy gate: {dec}"


def test_budget_ledger_allows_worker_bootstrap_for_max_task_turns_2_to_12_preserving_wrapup(tmp_path):
    # max_task_turns=1 or 3 leaves 0 non-reserved turns after 1 planner turn (wrap-up protected)
    for cap in (1, 3):
        db = Database(":memory:")
        try:
            eng = DualGraphAttackEngine(
                db=db,
                reports_dir=tmp_path / f"r_cap_{cap}",
                task_id=f"TASK-CAP-{cap}",
                max_task_turns=cap,
                workers=1,
            )
            eng.ingest_target_infrastructure("127.0.0.1", 8080, endpoints=["/api/admin"])
            eng.ingest_finding(
                {"rule_id": "AUTH-1", "title": "Exposed admin", "route": "/api/admin", "capability_class": "AUTH_BOUNDARY"},
                scanner="nuclei",
            )
            ran = []
            eng.run_attack_chain_cycle(
                round_num=1,
                executor_fn=lambda a: (ran.append(a["intent_id"]) or True, "ok", "GET /api/admin", {"tokens_used": 10, "turns_used": 1}),
            )
            assert ran == []
            assert eng.budget_ledger.used_turns <= cap
        finally:
            db.close()

    # max_task_turns in {2, 4, 5, 10, 12} has >=1 non-reserved turn after 1 planner turn and must start worker
    for cap in (2, 4, 5, 10, 12):
        db = Database(":memory:")
        try:
            eng = DualGraphAttackEngine(
                db=db,
                reports_dir=tmp_path / f"r_cap_{cap}",
                task_id=f"TASK-CAP-{cap}",
                max_task_turns=cap,
                workers=1,
            )
            eng.ingest_target_infrastructure("127.0.0.1", 8080, endpoints=["/api/admin"])
            eng.ingest_finding(
                {"rule_id": "AUTH-1", "title": "Exposed admin", "route": "/api/admin", "capability_class": "AUTH_BOUNDARY"},
                scanner="nuclei",
            )
            ran = []
            eng.run_attack_chain_cycle(
                round_num=1,
                executor_fn=lambda a: (ran.append(a["intent_id"]) or True, "ok", "GET /api/admin", {"tokens_used": 10, "turns_used": 1}),
            )
            assert len(ran) >= 1, f"Expected worker execution for max_task_turns={cap}"
            assert eng.budget_ledger.used_turns <= cap
        finally:
            db.close()


def test_execution_policy_and_approval_gate_block_python_excluded_package_and_docker_compound_images():
    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="allow_all", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    blocked_cmds = [
        ["python", r"C:\tools\sqlmap\__main__.py"],
        ["python3", "/opt/sqlmap/cli.py", "--batch"],
        ["python", "--", r"C:\tools\ffuf\__main__.py"],
        ["python", "/srv/dalfox/sub/__main__.py"],
        ["python", r"C:\tools\nmap-7.94\__main__.py"],
        ["docker", "run", "--rm", "myrepo/sqlmap_runner:latest"],
        ["docker", "run", "--rm", "nmap-alpine"],
        ["docker", "run", "--rm", "sqlmap_org/runner:latest"],
        ["docker", "run", "--rm", "ghcr.io/org/runner:dalfox-v2"],
    ]
    for cmd in blocked_cmds:
        ok, _ = policy.validate_subprocess_command(cmd, shell=False)
        assert ok is False, f"ExecutionPolicy must block {cmd!r}"
        for act in ("subprocess_exec", "subprocess"):
            dec = gate.check(action_type=act, target=cmd[0], command=cmd, is_high_risk=True)
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                f"ApprovalGate({act}) must hard-deny {cmd!r}, got {dec}"
            )

    for allowed_cmd in (
        ["python", "scripts/tool.py", "-c", "config.yml"],
        ["docker", "run", "--rm", "projectdiscovery/httpx:latest", "-u", "https://example.com/nmap", "-jsonl"],
    ):
        assert policy.validate_subprocess_command(allowed_cmd, shell=False)[0] is True
        assert gate.check(action_type="subprocess_exec", target=allowed_cmd[0], command=allowed_cmd, is_high_risk=True).approved is True


def test_execution_policy_and_approval_gate_block_versioned_python_scripts_and_docker_attached_m():
    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="A", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    blocked_cmds = [
        ["python", r"C:\tools\sqlmap-1.8\sqlmapapi.py"],
        ["python", "-O", "-B", r"C:\tools\sqlmap-1.8\sqlmapapi.py"],
        ["python", r"C:\tools\sqlmap-1.8\cli.py"],
        ["python3", "/opt/ffuf-2.1/cli.py"],
        ["python", "/opt/dalfox_runner/main.py"],
        ["python", r"C:\tools\nmap-7.94\sub\__main__.py"],
        ["python", "/srv/dalfox_pkg/sub/__main__.py"],
        ["python", "scripts/sqlmapapi.py"],
        ["python", "-m", "sqlmapapi"],
        ["python", "-Bmsqlmapapi"],
        ["docker", "run", "--rm", "ghcr.io/myorg/custom_py:3.11", "-msqlmap"],
        ["docker", "run", "--rm", "ghcr.io/myorg/custom_py:3.11", "-Bmdalfox"],
        ["docker", "run", "--rm", "ubuntu:22.04", "-Wignore", "-msqlmap"],
        ["docker", "run", "--rm", "ubuntu:22.04", "-W", "ignore", "-OBmffuf.cli"],
        ["docker", "container", "run", "--rm", "ghcr.io/myorg/custom_py:3.11", "-Bm", "nmap"],
    ]
    for cmd in blocked_cmds:
        ok, reason = policy.validate_subprocess_command(cmd, shell=False)
        assert ok is False, f"ExecutionPolicy must block {cmd!r}, got: {reason}"
        with pytest.raises(PermissionError):
            policy.validate_intent(
                StructuredIntentProposal(
                    task=ScannerTask.ARTEX_DUAL_GRAPH,
                    action_type=ActionType.SUBPROCESS_EXEC,
                    command_args=cmd,
                )
            )
        for act in ("subprocess", "subprocess_exec"):
            dec = gate.check(action_type=act, target="localhost", command=cmd, shell=False, is_high_risk=True)
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                f"ApprovalGate({act}) must hard-deny {cmd!r}, got {dec}"
            )

    benign_cmds = [
        ["python", "scripts/tool.py", "-c", "config.yml"],
        ["python", "scripts/benign_check.py"],
        ["python", r"d:\harfile\rfchunt\scripts\sitemap_check.py"],
        [
            "docker",
            "run",
            "--rm",
            "projectdiscovery/httpx:latest",
            "-u",
            "https://example.com/nmap",
            "-jsonl",
            "-max-redirects",
            "2",
            "-match-code",
            "200",
        ],
    ]
    for benign in benign_cmds:
        ok, reason = policy.validate_subprocess_command(benign, shell=False)
        assert ok is True, f"Benign command {benign!r} rejected: {reason}"
        for act in ("subprocess", "subprocess_exec"):
            dec = gate.check(action_type=act, target="localhost", command=benign, shell=False, is_high_risk=True)
            assert dec.approved is True, f"ApprovalGate({act}) denied benign {benign!r}: {dec}"


def test_execution_policy_and_approval_gate_block_dotted_and_prefixed_module_specs():
    policy = ExecutionPolicy.get_instance()
    gate = ApprovalGate(
        mode="policy",
        rules=[ApprovalRule(rule_id="A", rule_type="regex", action="APPROVE", pattern=".*")],
    )
    blocked_cmds = [
        ["python", "-m", "tools.sqlmap"],
        ["python", "-m", "my_pkg.dalfox.cli"],
        ["python", "-Bmtools.sqlmap"],
        ["python", "-m", "my_sqlmap"],
        ["python", "-m", "pkg.sub.sqlmap_cli"],
        ["python3", "-m", "vendor.nmap"],
        ["python", "-m", "my_ffuf"],
        ["python", "-Bmvendor.dalfox"],
        ["python", "-X", "dev", "-m", "tools.sqlmap"],
        ["docker", "run", "--rm", "ubuntu:22.04", "-mtools.sqlmap"],
        ["docker", "run", "--rm", "--entrypoint=python3", "ubuntu:22.04", "-mtools.sqlmap"],
        ["python", "-m", "vendor.sqlmap"],
        ["python", "-m", "run_sqlmap"],
        ["python", "-m", "pkg.sqlmap"],
        ["docker", "run", "--rm", "--entrypoint=python3", "ubuntu:22.04", "-m", "vendor.sqlmap"],
    ]
    for cmd in blocked_cmds:
        ok, reason = policy.validate_subprocess_command(cmd, shell=False)
        assert ok is False, f"ExecutionPolicy must block {cmd!r}, got: {reason}"
        with pytest.raises(PermissionError):
            policy.validate_intent(
                StructuredIntentProposal(
                    task=ScannerTask.ARTEX_DUAL_GRAPH,
                    action_type=ActionType.SUBPROCESS_EXEC,
                    target_host="127.0.0.1",
                    command_args=cmd,
                )
            )
        for act in ("subprocess", "subprocess_exec"):
            dec = gate.check(
                action_type=act,
                target="127.0.0.1",
                command=cmd,
                shell=False,
                is_high_risk=True,
            )
            assert dec.approved is False and dec.rule_id == "EXECUTION_POLICY_HARD_DENY", (
                f"ApprovalGate({act}) must hard-deny {cmd!r}, got {dec}"
            )

    benign_cmds = [
        ["python", "-m", "pytest", "-q"],
        ["python", "-m", "http.server", "8000"],
        ["python", "-m", "unmap"],
        ["python", "-m", "unmapped"],
        ["python", "scripts/tool.py", "-c", "config.yml"],
        ["python", "scripts/benign_check.py"],
        ["docker", "run", "-m", "512m", "--rm", "ubuntu:22.04", "echo", "ok"],
        [
            "docker",
            "run",
            "--rm",
            "projectdiscovery/httpx:latest",
            "-u",
            "https://example.com/nmap",
            "-rlm",
            "60",
            "-mc",
            "200",
            "-match-code",
            "200",
            "-max-redirects",
            "2",
            "-method",
            "-nc",
            "-jsonl",
        ],
        [
            "docker",
            "run",
            "--rm",
            "projectdiscovery/katana:latest",
            "-u",
            "http://127.0.0.1",
            "-jc",
            "-nc",
            "-jsonl",
        ],
        [
            "docker",
            "run",
            "--rm",
            "projectdiscovery/nuclei:latest",
            "-u",
            "http://127.0.0.1",
            "-nc",
            "-ni",
            "-irr",
            "-mhe",
            "-no-mhe",
            "-menu",
            "-jsonl",
        ],
    ]
    for benign in benign_cmds:
        ok, reason = policy.validate_subprocess_command(benign, shell=False)
        assert ok is True, f"Benign command {benign!r} rejected: {reason}"
        for act in ("subprocess", "subprocess_exec"):
            dec = gate.check(
                action_type=act,
                target="127.0.0.1",
                command=benign,
                shell=False,
                is_high_risk=True,
            )
            assert dec.approved is True, f"ApprovalGate({act}) denied benign {benign!r}: {dec}"
