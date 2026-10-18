# Dispatch: Explorer M4-3 (SQLite WAL & Concurrency Locks)

You are Explorer M4-3.
Your working directory is: `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_3`

Investigate:
1. SQLite connection and locking in `database.py`.
2. Check if `PRAGMA journal_mode = WAL;`, `PRAGMA busy_timeout = 30000;`, and `PRAGMA synchronous = NORMAL;` are configured on connections.
3. Check thread locks / process concurrency handling in `Database` class and connection pooling.
4. Inspect unclosed database connections across test files (`tests/test_raptor_integration.py`, `tests/test_terminator_rfc_selector.py`, `tests/test_harness2_integration.py`, etc.) that cause `PermissionError: [WinError 32]` on Windows during pytest directory cleanup in `.pytest_temp`.
5. Formulate the exact remediation plan to guarantee zero database file locks on Windows and eliminate all `[WinError 32]` issues.
Write your full findings to `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_3\report.md` and handoff to `handoff.md`.
Send a completion message back to orchestrator.
