# Handoff Report: Explorer M4-3 (SQLite WAL & Concurrency Locks)

**To**: Orchestrator / Worker M4  
**From**: Explorer M4-3  
**Date**: 2026-10-18T20:54:00Z  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_3`  
**Milestone**: M4 (Security Boundaries & Concurrency Locks) — Feature 17  

---

## 1. Observation

1. **`database.py` Connection Initialization (`database.py:15-20`)**:
   ```python
   class Database:
       def __init__(self, db_path: str = "terminator.db"):
           self.db_path = Path(db_path)
           self._lock = threading.Lock()
           self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
           self.conn.row_factory = sqlite3.Row
           self._init_schema()
   ```
   No `timeout` parameter is passed (Python defaults to 5.0 seconds). No PRAGMA statements are executed.

2. **Live Repository Database PRAGMAs (`terminator.db`)**:
   Querying `terminator.db` directly via Python:
   ```powershell
   py -3.12 -c "import sqlite3; conn = sqlite3.connect('terminator.db'); \
     print('journal_mode:', conn.execute('PRAGMA journal_mode').fetchone()[0]); \
     print('busy_timeout:', conn.execute('PRAGMA busy_timeout').fetchone()[0]); \
     print('synchronous:', conn.execute('PRAGMA synchronous').fetchone()[0]); conn.close()"
   ```
   Verbatim output:
   ```
   journal_mode: delete
   busy_timeout: 5000
   synchronous: 2
   ```
   `journal_mode = WAL;` is **not configured** (runs in `delete`). `busy_timeout = 30000;` is **not configured** (runs at `5000` ms). `synchronous = NORMAL;` is **not configured** (runs at `2` / `FULL`).

3. **Complete Absence of Close and Lifecycle Methods in `database.py`**:
   A search across all 808 lines of `database.py` for `def close` or `close` returned 0 results. The class defines no `close()`, no `__enter__`, no `__exit__`, and no `__del__`.

4. **Unsynchronized Read Methods in `database.py`**:
   Write methods (`save_rfc`, `save_fragments`, `save_probe`, `record_evaluation`, `save_harness2_run`, etc.) use `with self._lock: with self.conn:`. However, **9 read methods** call `cursor = self.conn.cursor(); cursor.execute(...)` without acquiring `self._lock`:
   - `get_ingested_rfc_ids()` (`database.py:231-234`)
   - `get_scanned_rfc_nums()` (`database.py:236-247`)
   - `get_unprocessed_fragments()` (`database.py:249-261`)
   - `get_pending_probes()` (`database.py:289-301`)
   - `get_confirmed_findings()` (`database.py:360-372`)
   - `get_tier_taxonomy_counts()` (`database.py:535-548`)
   - `get_anomaly_fingerprints()` (`database.py:569-574`)
   - `get_dynamic_permutations()` (`database.py:595-600`)
   - `get_probe_evaluation_count()` (`database.py:602-606`)

   In our empirical concurrent execution trial (3 writer threads, 3 reader threads on a shared connection with `check_same_thread=False`), unsynchronized cursor operations produced **62 API misuse / InterfaceError exceptions**:
   ```
   Concurrent errors observed: 62 [('writer', 'OperationalError', 'not an error'), ('writer', 'InterfaceError', 'bad parameter or other API misuse'), ...]
   ```
   Wrapping both reads and writes with `threading.RLock()` reduced errors to **0**.

5. **Pytest Directory Configuration & Temporary File Locking**:
   In `pytest.ini:2`: `addopts = --basetemp=d:/harfile/.pytest_temp`.
   When `tmp_path` fixture directories containing open `.db` files are deleted during pytest directory rotation or teardown, Windows kernel rejects the unlinking with:
   `PermissionError: [WinError 32] The process cannot access the file because it is being used by another process`.
   Empirical trial with WAL mode:
   ```
   WAL files created: ['test.db', 'test.db-shm', 'test.db-wal']
   Observed expected error without close: PermissionError [WinError 32] The process cannot access the file because it is being used by another process: '...\\test.db'
   Deletion succeeded after close: Directory removed cleanly
   ```

6. **Unclosed Connections in Test Files**:
   - `tests/test_raptor_integration.py:104`: `db = Database(test_db_path)` (never closed).
   - `tests/test_raptor_integration.py:121`: `server = TerminatorMCPServer(db_path=test_db)` (creates internal `self.db = Database(...)`; neither `server` nor `db` is closed).
   - `tests/test_terminator_rfc_selector.py:85`: `db = Database(db_file)` (never closed).
   - `tests/test_harness2_integration.py:133`: `db = Database(str(db_file))` (never closed).
   - `tests/test_harness2_integration.py:181, 196, 210`: `main_swarm(["harness2", ...])` calls `cmd_harness2(args)` which instantiates `db = Database(args.db)` twice without closing.
   - `tests/test_swarm_agent.py:22, 37, 68`: `ProtocolResearchSwarm(..., db_path=test_db)` creates internal `self.db = Database(...)` without closing.
   - `tests/test_rfcs.py:18-22`: `temp_env` fixture instantiates `db = Database(db_path)` and masks unclosed lock error with `shutil.rmtree(temp_dir, ignore_errors=True)`.
   - `tests/test_authorization_and_safety.py:128`: `Database(str(db_path))._seed_baseline_defensive_intelligence()` creates anonymous unclosed connection.

7. **Unclosed Connections in CLI & Production Modules**:
   - `rfc_hunt_swarm.py:1467`: `cmd_harness2` creates `db = Database(args.db)` without closing.
   - `rfc_hunt_swarm.py:1316`: `cmd_hosts` creates `con = sqlite3.connect(db_path)` without closing.
   - `rfc_hunt_swarm.py:1371`: `cmd_raptor` creates `db = Database(...)` without closing on `--status` or `--findings`.
   - `build_all.py:72`: `build_step_database` creates `db = Database(...)` without closing.
   - `mcp_server.py:152`: `TerminatorMCPServer` creates `self.db = Database(...)` without closing.
   - `continuous_scanner.py:56`: `ContinuousScanner` creates `self.db = Database(...)` without closing.
   - `test_lab_server.py:278`: creates `db = Database("terminator.db")` inside request handler without closing.

---

## 2. Logic Chain

1. **Premise**: Under Windows NT kernel semantics, open file descriptors and memory-mapped sections (`CreateFileMapping` / `MapViewOfFile` used by SQLite WAL `.db-shm` index) hold exclusive mandatory locks preventing file unlinking and directory deletion (Observation 5).
2. **Step 1**: Pytest directs temporary test directories to `d:/harfile/.pytest_temp` (`pytest.ini`) (Observation 5). When pytest runs, rotates `--basetemp`, or cleans up fixtures, it invokes `shutil.rmtree()` on these directories.
3. **Step 2**: Test files (`test_raptor_integration.py`, `test_terminator_rfc_selector.py`, `test_harness2_integration.py`, `test_swarm_agent.py`, `test_rfcs.py`, `test_authorization_and_safety.py`) instantiate `Database` objects in `tmp_path` without closing them (Observation 6).
4. **Step 3**: Because `Database` lacks `close()`, `__enter__`, `__exit__`, and `__del__`, `self.conn` remains open in the Python process memory indefinitely (Observation 3).
5. **Step 4**: When `shutil.rmtree()` attempts to delete the directory containing the open `.db` (or `.db-wal` / `.db-shm`), the Windows kernel throws `PermissionError: [WinError 32]` (Observation 5).
6. **Step 5**: In addition, `database.py` runs in `DELETE` journal mode with a 5s busy timeout (Observation 2). Under concurrent execution, write transactions acquire exclusive locks, blocking readers and triggering `OperationalError: database is locked`.
7. **Step 6**: Furthermore, 9 read methods access `self.conn.cursor()` without lock synchronization, causing 62 API misuse exceptions under concurrent load (Observation 4).
8. **Conclusion**: To eliminate `[WinError 32]` and database lock collisions on Windows, the remediation must simultaneously configure WAL mode (`PRAGMA journal_mode = WAL;`, `PRAGMA busy_timeout = 30000;`, `PRAGMA synchronous = NORMAL;`), enforce reentrant thread synchronization (`threading.RLock`) across ALL database methods, implement deterministic `close()` lifecycle methods across `Database`, wrapper classes, and test suites, and provide a pytest conftest cleanup fixture.

---

## 3. Caveats

1. **In-Memory SQLite**: `PRAGMA journal_mode = WAL;` is not supported on in-memory databases (`:memory:` or `mode=memory`). The connection initializer must check if the path is in-memory and skip WAL pragma in that specific case while still applying `busy_timeout` and `synchronous`.
2. **Network Drives / CIFS**: SQLite WAL mode requires POSIX shared-memory or Win32 file mapping primitives, which are unreliable over remote CIFS/SMB network shares. In `D:\harfile\rfchunt`, the workspace is on a local NTFS physical volume (`D:`), where WAL mode is fully supported.
3. **Subprocess Pytest Isolation**: While closing connections within the same process resolves in-process teardown collisions, running multiple independent pytest processes concurrently pointing to the exact same `--basetemp` path can still cause cross-process collisions if one process deletes the directory while another is executing. Using isolated basetemp directories per worker or sequential execution guarantees zero collisions.

---

## 4. Conclusion

The SQLite subsystem in `D:\harfile\rfchunt` requires 4 coordinated updates for Milestone 4 (Feature 17):
1. **Core Database Engine (`database.py`)**:
   - Update `Database.__init__` with `timeout=30.0` and `threading.RLock()`.
   - Execute `PRAGMA journal_mode = WAL;`, `PRAGMA busy_timeout = 30000;`, `PRAGMA synchronous = NORMAL;`, `PRAGMA foreign_keys = ON;`.
   - Implement `close()`, `is_closed`, `__enter__`, `__exit__`, and `__del__`.
   - Wrap the 9 unsynchronized read methods (`get_ingested_rfc_ids`, `get_scanned_rfc_nums`, `get_unprocessed_fragments`, `get_pending_probes`, `get_confirmed_findings`, `get_tier_taxonomy_counts`, `get_anomaly_fingerprints`, `get_dynamic_permutations`, `get_probe_evaluation_count`) in `with self._lock:`.
2. **Wrapper Classes Lifecycle (`rfc_hunt_swarm.py`, `mcp_server.py`, `continuous_scanner.py`, `build_all.py`)**:
   - Add `close()`, `__enter__`, `__exit__` to `ProtocolResearchSwarm`, `TerminatorMCPServer`, and `ContinuousScanner`.
   - Wrap `Database` and `sqlite3.connect` usages in `cmd_harness2`, `cmd_hosts`, `cmd_raptor`, and `build_step_database` with `try...finally: close()`.
3. **Test Suite Lifecycle (`tests/`)**:
   - Update `test_raptor_integration.py`, `test_terminator_rfc_selector.py`, `test_harness2_integration.py`, `test_swarm_agent.py`, `test_rfcs.py`, and `test_authorization_and_safety.py` to deterministically call `close()`.
4. **Pytest Conftest Safeguard (`tests/conftest.py`)**:
   - Provide an autouse teardown fixture invoking `gc.collect()` and Windows read-only file permission clearing to guarantee zero lingering handles.

---

## 5. Verification Method

To independently verify the implementation:

1. **Verify PRAGMA Configuration**:
   ```powershell
   py -3.12 -c "from database import Database; db = Database('test_check.db'); \
     assert db.conn.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'; \
     assert db.conn.execute('PRAGMA busy_timeout').fetchone()[0] == 30000; \
     assert db.conn.execute('PRAGMA synchronous').fetchone()[0] == 1; \
     db.close(); import os; os.remove('test_check.db')"
   ```
   *Invalidation condition*: Any assertion fails or file cannot be removed after `db.close()`.

2. **Verify Thread Concurrency Under Stress**:
   Run 3 writer threads (100 inserts each) and 3 reader threads (100 queries each) on a shared `Database` instance.
   *Invalidation condition*: Any exception (`InterfaceError`, `OperationalError`, or `ProgrammingError`) occurs.

3. **Verify Full Pytest Suite with Shared `--basetemp`**:
   ```powershell
   py -3.12 -m pytest tests/ test_protocol_ruler.py -v
   ```
   *Invalidation condition*: Any test fails or triggers `PermissionError: [WinError 32]` during teardown.

4. **Verify Build Pipeline**:
   ```powershell
   py -3.12 -u main.py build
   ```
   *Invalidation condition*: Exit code is non-zero or database check step reports lock errors.
