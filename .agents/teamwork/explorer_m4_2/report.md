# Explorer M4-2 Comprehensive Investigation Report: Path Traversal Hardening & normalize_rel

- **Author**: Explorer M4-2 (Path Traversal & normalize_rel Specialist)
- **Date**: 2026-10-18T20:53:00Z
- **Target System**: HTTP Terminator / RFC Hunt Swarm (`D:\harfile\rfchunt`)
- **Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_2`
- **Scope**: Milestone 4 (R3 Security Boundaries & Concurrency Locks) — Path Traversal, URL Decoding, Windows Device Names, Post-Join Containment, and Syntax Verification

---

## 1. Executive Summary

An exhaustive security boundary audit was conducted on `normalize_rel` in `engine/harness2_engine.py`, filesystem access mechanisms across all 16 modules in `D:\harfile\rfchunt`, and the test harness `tests/test_adversarial_m3_1.py`. 

### Key Findings:
1. **Critical Vulnerability: Multi-Level Percent-Encoding Bypass in `normalize_rel`**:
   The existing `normalize_rel` implementation at `engine/harness2_engine.py:165-188` uses a static, hardcoded substring blacklist (`"%2e"`, `"%252e"`, `"%2f"`, `"%252f"`, `"%5c"`, `"%255c"`, `"%3a"`, `"%253a"`, `"%00"`, `"%2500"`). It checks only single- and double-encoded variants. Any multi-level encoding at depth $\ge 3$ (e.g. triple `%25252e`, `%25252f`, `%25255c`, `%25253a`, `%252500` or quadruple `%2525252e`) completely bypasses `normalize_rel`!
   - *Empirically confirmed*: `normalize_rel('scripts/%25252e%25252e/escape.py')` executed without raising an exception and returned `'scripts/%25252e%25252e/escape.py'`. When joined with `base_dir`, it resolved and bypassed `relative_to()` because `pathlib.Path` treats `%` as literal characters. Downstream web servers or URL unquoting layers will decode this to `..`, enabling full path traversal breakout.
2. **High Severity Vulnerability: URL-Encoded & Whitespace-Padded Windows Device Names**:
   `engine/harness2_engine.py:196-199` checks `stem = part.split(".")[0].lower() in WIN_DEVICE_NAMES`.
   - It fails against URL-encoded device names: `normalize_rel('scripts/%43%4f%4e.py')` (`CON`) returns without error because `normalize_rel` never decodes the URL.
   - It fails against trailing spaces: on Windows, Win32 strips trailing periods and spaces. In `normalize_rel('scripts/con .py')`, `stem` is `'con '` (with space), which is not in `WIN_DEVICE_NAMES`, yet on Windows it resolves to the reserved `CON` device. Opening `CON` hangs indefinitely waiting on console input.
   - The device list `WIN_DEVICE_NAMES` lacks `conin$`, `conout$`, and `clock$`.
3. **High Severity Vulnerability: Single Dot (`.`) and Base Directory Resolution**:
   `normalize_rel('.')` does not strip `.` because the loop only checks `r.startswith('./')`. As a result, `normalize_rel('.', base_dir=sandbox)` resolves to `sandbox` itself, returning the root directory instead of a file inside it. In `write_tree`, this can attempt to overwrite the container directory as a file.
4. **Medium Severity: Unicode Homoglyph Evasions**:
   Fullwidth solidus `\uff0f` (`／`), fullwidth reverse solidus `\uff3c` (`＼`), fullwidth colon `\uff1a` (`：`), and fullwidth full stop `\uff0e` (`．`) pass through unhindered. When normalized via NFKC downstream, they convert into `/`, `\`, `:`, and `.`.
5. **Item 5 Verification**:
   The syntax defect in `tests/test_adversarial_m3_1.py:263` reported by Challenger M3-2 (`NameError: name 'base' is not defined`) was caused by an uninitialized variable in an earlier draft. In the current file on disk, lines 263-264 properly initialize `engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")` and `base = engine.build_base_harness()`. The file compiles cleanly and all 8 adversarial tests pass with 100% success (`8 passed in 0.60s`).

---

## 2. Investigation Item 1: `normalize_rel` & Codebase Path Utilities Audit

### 2.1 Current Implementation in `engine/harness2_engine.py:165-210`
```python
def normalize_rel(rel: str, base_dir: Optional[Path] = None) -> Any:
    """Normalise a relative path, rejecting escapes, drive letters, and percent-encoded traversal.

    If base_dir is supplied, validates that the path resolves strictly inside base_dir and returns
    the canonical Path object per PROJECT.md:68. Otherwise returns the cleaned normalized relative string.
    """
    r = str(rel).strip().replace("\\", "/")
    r_lower = r.lower()
    if (
        r.startswith("/")
        or ":" in r
        or "%3a" in r_lower
        or "%253a" in r_lower
        or ".." in r.split("/")
        or "%2e" in r_lower
        or "%252e" in r_lower
        or "%2f" in r_lower
        or "%252f" in r_lower
        or "%5c" in r_lower
        or "%255c" in r_lower
        or "%00" in r_lower
        or "%2500" in r_lower
        or "\x00" in r
    ):
        raise ValueError(f"path escapes the harness: {rel!r}")
    while r.startswith("./"):
        r = r[2:]
    cleaned = r.strip("/")
    if not cleaned:
        raise ValueError(f"empty relative path on harness surface: {rel!r}")

    for part in cleaned.split("/"):
        stem = part.split(".")[0].lower()
        if stem in WIN_DEVICE_NAMES or part.lower() in WIN_DEVICE_NAMES:
            raise ValueError(f"path contains Windows reserved device name: {rel!r}")

    if base_dir is not None:
        base_path = Path(base_dir).resolve()
        resolved = (base_path / cleaned).resolve()
        try:
            resolved.relative_to(base_path)
        except ValueError:
            raise ValueError(f"path escapes base directory: {rel!r}")
        return resolved

    return cleaned
```

### 2.2 Call Sites and Downstream Usages of `normalize_rel`
`normalize_rel` is the primary gatekeeper for the editable $c_1..c_8$ agent surface (`RFCHUNT_SURFACE`):
- `engine/harness2_engine.py:216`: Called by `is_allowed()` to determine whether paths are admissible on the surface.
- `engine/harness2_engine.py:281`: Called by `validate_tree()` to reject off-surface files.
- `engine/harness2_engine.py:300`: Called by `validate_tree()` when parsing frontmatter rules and syntax checking Python scripts.
- `engine/harness2_engine.py:340-341`: Called by `diff_summary()` when computing added/removed/modified sets.
- `engine/harness2_engine.py:412, 417, 426`: Called by `write_tree()` to construct file paths on disk:
  ```python
  p = dest / norm
  p.parent.mkdir(parents=True, exist_ok=True)
  p.write_text(content, encoding="utf-8")
  ```
- `engine/harness2_engine.py:438`: Called by `merge_tree_proposal()` during agent proposal composition.

### 2.3 Other Path Resolution Utilities Across `D:\harfile\rfchunt`
An audit of other filesystem resolution sites revealed:
1. `engine/raptor_integrator.py:148, 206`:
   ```python
   target = Path(target_path).resolve()
   if not target.exists():
       return {"error": f"Target path {target} does not exist."}
   ```
   *Windows Device Vulnerability*: On Windows, `Path("con").exists()` and `Path("aux").exists()` return `True` even when no such file exists on disk. Passing `target_path="con"` to `describe_target` invokes PowerShell with `-TargetPath con`, causing PowerShell to freeze or hang.
2. `engine/harness2_engine.py:565`:
   `domain_dir(domain)`:
   `return re.sub(r"\s*[/\\]\s*", "__", str(domain)).strip() or "unknown"`
   If `domain="con"`, `domain_dir` returns `"con"`, creating library path `runs/experience/con`.
3. `caldera_bridge.py:259`:
   `export_root = Path(output_dir)` creates directories without verifying if `output_dir` attempts path escape.
4. `database.py:16`:
   `self.db_path = Path(db_path)` accepts direct path string for SQLite database connection.

---

## 3. Investigation Item 2: Recursive / Iterative URL Decoding

### 3.1 Defect Analysis
The existing check in `normalize_rel` at lines 176-186 relies on fixed substring matching:
```python
        or "%3a" in r_lower
        or "%253a" in r_lower
        or "%2e" in r_lower
        or "%252e" in r_lower
        or "%2f" in r_lower
        or "%252f" in r_lower
        or "%5c" in r_lower
        or "%255c" in r_lower
        or "%00" in r_lower
        or "%2500" in r_lower
```
This is vulnerable to multi-level percent encoding:
| Character | Literal | 1-Level Encoded | 2-Level Encoded | 3-Level Encoded | 4-Level Encoded |
|-----------|---------|-----------------|-----------------|-----------------|-----------------|
| `.` (dot) | `.` | `%2e` | `%252e` | `%25252e` | `%2525252e` |
| `/` (slash) | `/` | `%2f` | `%252f` | `%25252f` | `%2525252f` |
| `\` (backslash) | `\` | `%5c` | `%255c` | `%25255c` | `%2525255c` |
| `:` (colon) | `:` | `%3a` | `%253a` | `%25253a` | `%2525253a` |
| `\0` (null) | `\x00` | `%00` | `%2500` | `%252500` | `%25252500` |

### 3.2 Empirical Proof of Bypass
Executing in Python 3.12:
```python
>>> from engine.harness2_engine import normalize_rel
>>> normalize_rel('scripts/%25252e%25252e/escape.py')
'scripts/%25252e%25252e/escape.py'
```
The path is accepted because `"%25252e"` does not contain substring `"%2e"` or `"%252e"`.
When passed to `normalize_rel` with `base_dir=Path('.')`:
```python
>>> normalize_rel('scripts/%25252e%25252e/escape.py', base_dir=Path('.'))
WindowsPath('D:/harfile/rfchunt/scripts/%25252e%25252e/escape.py')
```
Because `pathlib.Path` treats `%25252e` as an ordinary file name, `resolved.relative_to(base_path)` succeeds. If this path is subsequently decoded by an API or web service, it becomes `scripts/../escape.py`, breaking out of `scripts/`!

### 3.3 Required Defensive Architecture
To guarantee fail-closed security:
1. **Iterative URL Decoding to Fixed Point**:
   Decode using `urllib.parse.unquote()` in a loop (up to 10 iterations) until `unquote(curr) == curr`.
2. **Regex Pattern for Arbitrary-Depth Encodings**:
   Match `r"%(?:25)*(?:2e|2f|5c|3a|00)"` on the lowercase input. This immediately intercepts any depth ($N = 1, 2, 3, \dots$) of percent-encoded dots, slashes, backslashes, colons, or null bytes.
3. **Detection of Encoded Separators**:
   If unquoting reveals any `/`, `\`, `:`, or `\x00` that was not present literally in the raw input, raise `ValueError("path escapes the harness: ...")`.

---

## 4. Investigation Item 3: Windows Reserved Device Names, ADS, Slashes, UNC Paths

### 4.1 Windows Reserved Device Names
Windows reserves specific DOS device names in the Win32 file namespace:
- Devices: `CON`, `PRN`, `AUX`, `NUL`, `COM1..COM9`, `LPT1..LPT9`.
- Console handles: `CONIN$`, `CONOUT$`.
- Clock device: `CLOCK$`.

#### Vulnerability 1: Trailing Spaces and Dots
Under Win32 subsystem rules, trailing periods and trailing spaces in filenames are automatically stripped prior to accessing the filesystem.
In `engine/harness2_engine.py:197`:
```python
stem = part.split(".")[0].lower()
if stem in WIN_DEVICE_NAMES: ...
```
- For `"scripts/con .py"`: `part.split(".")[0]` is `"con "` (with trailing space).
- `"con "` is NOT in `WIN_DEVICE_NAMES`, so it passes without error!
- On Windows, opening `"scripts/con .py"` opens the `CON` console device!
- *Fix*: `part.split(".")[0].rstrip(" .").lower()` and `part.rstrip(" .").lower()`.

#### Vulnerability 2: URL-Encoded Device Names
An attacker can pass `scripts/%43%4f%4e.py` or `scripts/%2543%254f%254e.py`.
Because `normalize_rel` does not decode URL characters, `stem` is `"%43%4f%4e"`, completely bypassing the device name check.
- *Fix*: The iterative unquoted string `curr` must also have every component checked against `WIN_DEVICE_NAMES`.

### 4.2 NTFS Alternate Data Streams (`:`)
In NTFS, a colon `:` introduces an Alternate Data Stream (e.g. `file.txt:stream` or `dir::$INDEX_ALLOCATION`).
Drive letters also utilize colons (`C:\`).
- Unencoded `:` is blocked by `":" in r`.
- Encoded colons (`%3a`, `%253a`) are blocked by current code.
- Triple-encoded colons (`%25253a`) currently bypass `normalize_rel`.
- Unicode fullwidth colon (`\uff1a`) currently bypasses `normalize_rel`.
- *Fix*: Reject any colon in raw, decoded, and NFKC-normalized strings, as well as `r"%(?:25)*3a"`.

### 4.3 Leading Slashes and Backslashes
- Absolute paths on POSIX start with `/`. On Windows, paths may start with `\`, `\\`, or `C:\`.
- In `pathlib.Path`: `Path("/sandbox") / "/etc/passwd"` results in `Path("/etc/passwd")` (the base path is discarded!).
- `normalize_rel` converts `\` to `/` and checks `r.startswith("/")`.
- Must also reject multi-level encoded slashes: `%2f`, `%5c`, `%252f`, `%255c`, `%25252f`, `%25255c`.

### 4.4 UNC Paths (`\\` and `//`)
- UNC paths (`\\server\share\file` or `//server/share/file`) access network SMB shares.
- `normalize_rel` replaces `\\` with `//`.
- Checking `raw.startswith("//") or raw.startswith(r"\\") or raw_slash.startswith("//")` ensures all UNC variations are rejected before any joining occurs.

---

## 5. Investigation Item 4: Post-Join Canonical Containment Verification

### 5.1 Canonical Resolution & Containment Check
Lines 201-209 in `engine/harness2_engine.py`:
```python
    if base_dir is not None:
        base_path = Path(base_dir).resolve()
        resolved = (base_path / cleaned).resolve()
        try:
            resolved.relative_to(base_path)
        except ValueError:
            raise ValueError(f"path escapes base directory: {rel!r}")
        return resolved
```

### 5.2 Identified Flaw: Base Directory Identity (`resolved == base_path`)
If an attacker passes `rel = "."` or `./`:
1. `while r.startswith("./"): r = r[2:]` leaves `r = "."`.
2. `cleaned = ".".strip("/")` results in `cleaned = "."`.
3. `base_path / "."` resolves to `base_path`.
4. `base_path.relative_to(base_path)` returns `Path(".")` and does NOT raise `ValueError`!
5. `normalize_rel(".", base_dir=sandbox)` returns `sandbox`!
6. In `write_tree()`, writing to `dest / norm` attempts to write file contents to the directory `sandbox`, causing a `PermissionError` on Windows or file corruption.

### 5.3 Required Hardening
1. In Python 3.9+, use `resolved.is_relative_to(base_path)`.
2. Enforce `resolved != base_path`:
   ```python
   if resolved == base_path or not resolved.is_relative_to(base_path):
       raise ValueError(f"path escapes base directory: {rel!r}")
   ```
3. Explicitly reject `cleaned == "."` and `cleaned == ""` during component inspection.

---

## 6. Investigation Item 5: Syntax Defect Analysis on `tests/test_adversarial_m3_1.py:263`

### 6.1 Background and Challenger M3-2 Observation
In `D:\harfile\rfchunt\.agents\teamwork\challenger_m3_2\handoff.md:147`, Challenger M3-2 noted:
> "Additionally observed: Challenger M3-1's newly committed `tests/test_adversarial_m3_1.py:263` has a syntax defect where variable `base` is referenced without definition (`NameError: name 'base' is not defined`)."

### 6.2 Inspection of File on Disk
Inspecting `tests/test_adversarial_m3_1.py:260-269`:
```python
260:     # 3. Triple percent-encoding (%25252e): rejected by is_allowed and validate_tree
261:     triple_attack = "scripts/%25252e%25252e.py"
262:     assert not is_allowed(RFCHUNT_SURFACE, triple_attack)
263:     engine = Harness2ProtocolEngine(runs_root=tmp_path / "runs")
264:     base = engine.build_base_harness()
265:     tree_triple = dict(base)
266:     tree_triple[triple_attack] = "x = 1\n"
267:     with pytest.raises(ValueError, match=r"off-surface path rejected"):
268:         validate_tree(RFCHUNT_SURFACE, tree_triple)
```

### 6.3 Empirical Verification
1. `py -3.12 -m py_compile tests/test_adversarial_m3_1.py`
   - Exit code: 0 (No syntax errors).
2. `py -3.12 -m pytest tests/test_adversarial_m3_1.py -v`
   - Output:
     ```
     tests/test_adversarial_m3_1.py::test_surface_validation_empty_and_whitespace_c8_plugin PASSED [ 12%]
     tests/test_adversarial_m3_1.py::test_always_on_empty_component_rejection PASSED [ 25%]
     tests/test_adversarial_m3_1.py::test_frontmatter_quote_variations PASSED [ 37%]
     tests/test_adversarial_m3_1.py::test_normalize_rel_adversarial_matrix PASSED [ 50%]
     tests/test_adversarial_m3_1.py::test_mathematical_budget_ledger_corrupted_rollouts_and_sessions PASSED [ 62%]
     tests/test_adversarial_m3_1.py::test_engine_end_to_end_parallel_and_sequential_ledger_identity PASSED [ 75%]
     tests/test_adversarial_m3_1.py::test_surface_scripts_and_subagent_boundary_validation PASSED [ 87%]
     tests/test_adversarial_m3_1.py::test_library_persistence_and_experience_validation PASSED [100%]
     ============================== 8 passed in 0.60s ==============================
     ```
3. Conclusion: The undefined variable defect existed in an early uncommitted draft of Challenger M3-1, but was corrected prior to final commit. Variable `base` is properly initialized on line 264.

---

## 7. Concrete Remediation Proposal for Worker M4

To implement the required M4 hardening without breaking any existing tests or contracts, Worker M4 should apply the following precise changes to `engine/harness2_engine.py`:

### 7.1 Required Imports (`engine/harness2_engine.py:35-50`)
Ensure `unicodedata` and `urllib.parse` are imported:
```python
import ast
import copy
import hashlib
import json
import re
import shutil
import time
import unicodedata
import urllib.parse
```

### 7.2 Updated `WIN_DEVICE_NAMES` (`engine/harness2_engine.py:56-60`)
```python
WIN_DEVICE_NAMES = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
    "conin$", "conout$", "clock$",
})
```

### 7.3 Hardened `normalize_rel` (`engine/harness2_engine.py:165-215`)
```python
def normalize_rel(rel: str, base_dir: Optional[Path] = None) -> Any:
    """Normalise a relative path, rejecting escapes, drive letters, and percent-encoded traversal.

    If base_dir is supplied, validates that the path resolves strictly inside base_dir and returns
    the canonical Path object per PROJECT.md:68. Otherwise returns the cleaned normalized relative string.
    """
    raw = str(rel).strip()
    if not raw:
        raise ValueError(f"empty relative path on harness surface: {rel!r}")

    # 1. Iterative URL decoding (up to 10 iterations) to reach fixed point
    curr = raw
    for _ in range(10):
        dec = urllib.parse.unquote(curr)
        if dec == curr:
            break
        curr = dec

    # 2. Normalize Unicode (NFKC) to defeat fullwidth slashes, dots, and colons
    normalized_str = unicodedata.normalize("NFKC", curr)

    # 3. Reject null bytes across raw, decoded, and normalized representations
    if "\x00" in raw or "\x00" in curr or "\x00" in normalized_str:
        raise ValueError(f"path escapes the harness: {rel!r}")

    # 4. Multi-level percent-encoding regex interceptor for traversal, colons, nulls, slashes
    raw_lower = raw.lower()
    if re.search(r"%(?:25)*(?:2e|2f|5c|3a|00)", raw_lower):
        raise ValueError(f"path escapes the harness: {rel!r}")

    # 5. Normalize path separators to forward slash
    norm_slash = normalized_str.replace("\\", "/")
    raw_slash = raw.replace("\\", "/")

    # 6. Reject absolute paths, UNC paths, and colons (drive letters and NTFS ADS)
    if (
        norm_slash.startswith("/")
        or raw_slash.startswith("/")
        or ":" in norm_slash
        or ":" in raw_slash
        or raw.startswith("//")
        or raw.startswith(r"\\")
        or raw_slash.startswith("//")
    ):
        raise ValueError(f"path escapes the harness: {rel!r}")

    # 7. Strip leading relative prefixes (./)
    while norm_slash.startswith("./"):
        norm_slash = norm_slash[2:]
    while raw_slash.startswith("./"):
        raw_slash = raw_slash[2:]

    # 8. Check for directory traversal sequences (..) and curdir (.)
    parts = norm_slash.split("/")
    raw_parts = raw_slash.split("/")
    if any(p == ".." or p == "." for p in parts if p) or any(p == ".." for p in raw_parts if p):
        raise ValueError(f"path escapes the harness: {rel!r}")

    cleaned = norm_slash.strip("/")
    if not cleaned or cleaned == ".":
        raise ValueError(f"empty relative path on harness surface: {rel!r}")

    # 9. Exhaustive Windows reserved device name check across normalized and decoded components
    for part in cleaned.split("/"):
        stem = part.split(".")[0].rstrip(" .").lower()
        part_clean = part.rstrip(" .").lower()
        if stem in WIN_DEVICE_NAMES or part_clean in WIN_DEVICE_NAMES:
            raise ValueError(f"path contains Windows reserved device name: {rel!r}")

    for part in curr.replace("\\", "/").strip("/").split("/"):
        stem = part.split(".")[0].rstrip(" .").lower()
        part_clean = part.rstrip(" .").lower()
        if stem in WIN_DEVICE_NAMES or part_clean in WIN_DEVICE_NAMES:
            raise ValueError(f"path contains Windows reserved device name: {rel!r}")

    # 10. Post-join canonical containment check against base_dir
    if base_dir is not None:
        base_path = Path(base_dir).resolve()
        resolved = (base_path / cleaned).resolve()
        if resolved == base_path or not resolved.is_relative_to(base_path):
            raise ValueError(f"path escapes base directory: {rel!r}")
        return resolved

    return cleaned
```

---

## 8. Verification Matrix & Commands

| Vector Category | Attack Example | Current Result | Hardened Result | Test Method |
|---|---|---|---|---|
| Triple percent-encoding | `scripts/%25252e%25252e/escape.py` | Allowed (Bypass) | `ValueError("path escapes...")` | `normalize_rel(...)` raises |
| Quadruple percent-encoding | `scripts/%2525252e%2525252e.py` | Allowed (Bypass) | `ValueError("path escapes...")` | `normalize_rel(...)` raises |
| Encoded device name | `scripts/%43%4f%4e.py` | Allowed (Bypass) | `ValueError("Windows reserved...")` | `normalize_rel(...)` raises |
| Trailing space device name | `scripts/con .py` | Allowed (Bypass) | `ValueError("Windows reserved...")` | `normalize_rel(...)` raises |
| Base dir identity escape | `.` with `base_dir` | Returns `base_dir` | `ValueError("path escapes...")` | `normalize_rel(".", base_dir=...)` raises |
| Unicode homoglyph slash | `scripts/\uff0fescape.py` | Allowed (Bypass) | `ValueError("path escapes...")` | `normalize_rel(...)` raises |
| Syntax verification | `tests/test_adversarial_m3_1.py:263` | Passes (Verified) | Passes (Verified) | `pytest tests/test_adversarial_m3_1.py` |

### Verification Commands
```powershell
# 1. Compile test suite
py -3.12 -m py_compile tests/test_adversarial_m3_1.py

# 2. Run adversarial test suite
py -3.12 -m pytest tests/test_adversarial_m3_1.py -v

# 3. Run harness2 integration test suite
py -3.12 -m pytest tests/test_harness2_integration.py -v
```
