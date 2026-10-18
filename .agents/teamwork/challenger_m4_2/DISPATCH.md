# Dispatch: Challenger M4-2 (Path Traversal & Concurrency Stress)

**Role**: Challenger M4-2 (Path Traversal & Concurrency Stress)
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\challenger_m4_2`

## Read:
- `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md`
- `D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md`
- `D:\harfile\rfchunt\.agents\teamwork\worker_m4\handoff.md`

## Mission:
Empirically stress-test path traversal defenses and SQLite concurrency:
1. Path Traversal Stress:
   - Test `normalize_rel` with recursive/multi-level percent-encoding (`%2525252e%2525252e/escape.py`, `%25252e`, `%252f`, `%255c`)
   - Test Windows reserved device names with trailing whitespace and dots (`con .py`, `CON.txt`, `prn .dat`, `aux.`, `nul.json`, `conin$.ts`, `clock$.py`)
   - Test URL-encoded device names (`%43%4f%4e.py`)
   - Test Unicode fullwidth homoglyphs (`\uff0e\uff0e\uff0f`, `\uff1a`, `\uff3c`)
   - Test single dot / empty / double slashes (`.`, `//`, `a//b`)
   - Verify `validate_tree` rejects all off-surface path attacks.
2. SQLite Concurrency Stress:
   - Run 10 concurrent threads (5 writers performing rapid inserts, 5 readers executing queries across all 9 read methods) on a shared `Database` instance in WAL mode.
   - Verify 0 `OperationalError`, 0 `InterfaceError`, and 0 API misuse exceptions.
   - Verify that repeatedly opening and closing `Database` instances in a temporary directory does not trigger `PermissionError: [WinError 32]` when removing the directory.
3. Deliver verdict: APPROVE or REQUEST_CHANGES in `handoff.md` and message orchestrator.
