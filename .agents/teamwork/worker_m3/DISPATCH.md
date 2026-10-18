# Dispatch: Worker M3 (Module 16 Google Research Harness² & Protocol Ruler)

You are Worker M3.
Your working directory is: `D:\harfile\rfchunt\.agents\teamwork\worker_m3`

Read:
- `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md`
- `D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_1\report.md`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_1\handoff.md`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_2\report.md`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_2\handoff.md`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_2\protocol_ruler_remediation.patch`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_2\test_protocol_ruler_expansion.patch`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_3\report.md`
- `D:\harfile\rfchunt\.agents\teamwork\explorer_m3_3\handoff.md`

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your write ownership:
- `engine/harness2_engine.py`
- `protocol_ruler.py`
- `test_protocol_ruler.py`
- `tests/test_harness2_integration.py`
- `tests/test_research_engine.py`
- `build_all.py`

Tasks to implement:
1. **Module 16 Google Research Harness² (`engine/harness2_engine.py`)**:
   - `validate_tree`: Add non-empty content validation for `c8` (`plugin/<name>.ts`).
   - `reject_empty_always_on`: Fix logic so that any provided always-on file must be non-empty (`all(tree.get(a, "").strip() for a in surface.always_on if a in tree)`).
   - `_frontmatter_field`: Strip outer single/double quotes (`.strip("'\"")`) from frontmatter values.
   - `autotrigger`: Fix token matching to prevent partial substring matches.
   - `normalize_rel`: Reject Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`), reject double percent-encoding (`%252e`, `%255c`), and support `base_dir: Optional[Path] = None` per `PROJECT.md:68`.
   - `Library.record`: Update existing row in `INDEX.md` when a task is re-run (prevent duplicate rows).
   - `Library.entries`: Sort entries chronologically by modification time (`st_mtime`) instead of alphabetical.
2. **Protocol Ruler (`protocol_ruler.py`)**:
   - Apply fixes from Explorer M3-2 patch:
     * Fix socket resource leaks in `send_probe()` and `_open_socket()` via deterministic `finally: sock.close()`.
     * Fix bracket calibration by ensuring `min_size` and `max_size` are in `brackets` and properly sorted.
     * Fix false-positive expansion defect on rejected sequences (`REJECTED_OR_OVERSIZED`).
     * Expand error boundary status codes to include 413 (Payload Too Large) and 500 (Server error).
     * Fix CLI hex escaped sequence parser to handle both hex bytes and ASCII escape sequences without throwing ValueError.
3. **Protocol Ruler Tests (`test_protocol_ruler.py`)**:
   - Dynamic port allocation (eliminate hardcoded port 8092 conflict).
   - Expand test coverage with the 6 additional tests from `test_protocol_ruler_expansion.patch` (contractions, socket cleanup on reset, bracket boundaries, rejected sequences, format helper).
4. **Harness² Tests & Integration**:
   - Add `tests/test_research_engine.py` aliasing or forwarding to `test_engine_12_modules.py` to ensure complete path compatibility with `ORIGINAL_REQUEST.md:27`.
   - In `tests/test_harness2_integration.py`, add tests for `BudgetError` on excess rollouts / deficit sessions, plugin `c8` non-empty validation, quoted frontmatter handling, and Library task updates.
   - In `build_all.py`, update `build_step_harness2` to exercise `engine.run_mode("parallel", ...)` with domain library persistence.
5. **Verification**:
   - Run `python.cmd -m pytest tests/test_harness2_integration.py test_protocol_ruler.py tests/test_research_engine.py -v`
   - Run `python.cmd -m pytest tests/ test_protocol_ruler.py -q`
   - Run `python.cmd build_all.py` (verify all 8 stages pass with exit code 0)
6. Write handoff report to `D:\harfile\rfchunt\.agents\teamwork\worker_m3\handoff.md` and message orchestrator when done.
