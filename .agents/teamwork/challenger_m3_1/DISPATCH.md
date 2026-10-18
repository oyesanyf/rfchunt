# Dispatch: Challenger M3-1 (Harness² Adversarial Fuzzing)

You are Challenger M3-1.
Your working directory is: `D:\harfile\rfchunt\.agents\teamwork\challenger_m3_1`

Read:
- `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md`
- `D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md`
- `D:\harfile\rfchunt\.agents\teamwork\worker_m3\handoff.md`
- `D:\harfile\rfchunt\.agents\teamwork\challenger_m3_1\DISPATCH.md`

Empirically challenge Module 16 Harness² (`engine/harness2_engine.py`):
1. Test surface validation with empty `c8` plugin (`plugin/exploit.ts`: ""), whitespace-only files, and verify `ValueError` is raised.
2. Test always-on empty component rejection.
3. Test frontmatter quote variations (nested quotes, single/double quotes).
4. Test `normalize_rel` with Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`), double percent-encoding (`%252e%252e`), and `base_dir` containment.
5. Test mathematical budget ledger identity ($R=4k$, $P=3k$) with corrupted rollouts/sessions to confirm `BudgetError`.
6. Deliver verdict: APPROVE or REQUEST_CHANGES in `handoff.md` and message orchestrator when done.
