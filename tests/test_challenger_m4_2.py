"""
Adversarial Stress Test Suite: Milestone 4 Challenger M4-2.
Empirically stress-tests path traversal defenses (normalize_rel, validate_tree)
and SQLite concurrency/file lock resilience (database.py).
"""

import gc
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from database import Database
from engine.harness2_engine import RFCHUNT_SURFACE, normalize_rel, validate_tree


# ==============================================================================
# Part 1: Path Traversal Stress Tests
# ==============================================================================

def test_normalize_rel_recursive_percent_encoding():
    """Verify normalize_rel rejects multi-level/recursive percent-encoded paths."""
    attacks = [
        "%2525252e%2525252e/escape.py",
        "%25252e",
        "%252f",
        "%255c",
        "%2525252fetc%2525252fpasswd",
        "skills/%25252e%25252e/escape.py",
        "sub_agents/%25252f..%25252froot/AGENT.md",
        "%25252525252e%25252525252e%25252525252f",
        "%252e%252e%252fetc%252fpasswd",
        "foo/%252e%252e/bar",
        "scripts/%255c..%255csteal.py",
    ]
    for attack in attacks:
        with pytest.raises(ValueError) as excinfo:
            normalize_rel(attack)
        assert "path escapes the harness" in str(excinfo.value) or "empty relative path" in str(excinfo.value)


def test_normalize_rel_windows_reserved_device_names_with_dots_and_spaces():
    """Verify normalize_rel rejects Windows reserved device names with trailing dots/spaces."""
    devices = [
        "con .py",
        "CON.txt",
        "prn .dat",
        "aux.",
        "nul.json",
        "conin$.ts",
        "clock$.py",
        "com1.",
        "com1 .",
        "com1.txt",
        "com9.dat",
        "lpt1.log",
        "lpt9.bin",
        "aux .txt",
        "nul .",
        "prn .",
        "conout$.ts",
        "CONIN$.TXT",
        "CONOUT$.TXT",
        "CLOCK$.TXT",
        "cOn.py",
        "CoN.txt",
        "AuX.bin",
        "nUl.dat",
        "pRn.doc",
        "skills/con/SKILL.md",
        "skills/aux./SKILL.md",
        "skills/clock$/SKILL.md",
        "sub_agents/con/AGENT.md",
    ]
    for dev in devices:
        with pytest.raises(ValueError) as excinfo:
            normalize_rel(dev)
        assert "path contains Windows reserved device name" in str(excinfo.value)


def test_normalize_rel_url_encoded_device_names():
    """Verify normalize_rel detects and rejects URL-encoded Windows device names."""
    encoded_devices = [
        "%43%4f%4e.py",      # CON.py
        "%41%55%58.json",    # AUX.json
        "%4e%55%4c.txt",     # NUL.txt
        "%50%52%4e.dat",     # PRN.dat
        "%63%6f%6e.py",      # con.py
        "%43%4f%4e%49%4e%24.ts",  # CONIN$.ts
        "skills/%43%4f%4e/SKILL.md",
    ]
    for enc in encoded_devices:
        with pytest.raises(ValueError) as excinfo:
            normalize_rel(enc)
        assert "path contains Windows reserved device name" in str(excinfo.value) or "path escapes the harness" in str(excinfo.value)


def test_normalize_rel_unicode_fullwidth_homoglyphs():
    """Verify normalize_rel rejects Unicode fullwidth dots, slashes, and colons."""
    homoglyphs = [
        "\uff0e\uff0e\uff0f",               # ../
        "\uff1a",                           # :
        "\uff3c",                           # \
        "\uff0e\uff0e\uff0fetc\uff0fpasswd", # ../etc/passwd
        "c\uff1a\uff0fwindows\uff0fsystem32",# c:/windows/system32
        "skills\uff0f\uff0e\uff0e\uff0fescape.py",
        "\uff0e\uff0e\uff3cescape.py",
        "foo/\uff0e\uff0e/bar",
        "foo\uff1abar",
    ]
    for h in homoglyphs:
        with pytest.raises(ValueError) as excinfo:
            normalize_rel(h)
        assert "path escapes the harness" in str(excinfo.value) or "empty relative path" in str(excinfo.value)


def test_normalize_rel_single_dot_empty_and_double_slashes():
    """Verify normalize_rel rejects empty paths, single dots, and consecutive slashes."""
    boundary_cases = [
        ".",
        "..",
        "//",
        "///",
        "////",
        "a//b",
        "skills//my_skill/SKILL.md",
        "skills/./my_skill/SKILL.md",
        "",
        "   ",
        "\t\n",
        "////etc/passwd",
        r"\\localhost\c$\secret",
        r"\\?\C:\windows",
    ]
    for b in boundary_cases:
        with pytest.raises(ValueError) as excinfo:
            normalize_rel(b)
        assert (
            "empty relative path" in str(excinfo.value)
            or "path escapes the harness" in str(excinfo.value)
        )


def test_validate_tree_rejects_all_off_surface_path_attacks():
    """Verify validate_tree rejects off-surface paths, escaping paths, and unauthorized files."""
    base_tree = {
        "systemprompt.md": "System prompt instructions.",
        "guardrails.md": "Safety rules and boundaries.",
        "LongTermMEMORY.md": "Long-term state notes.",
        "tool_descriptions/tool_guidance.md": "Guidance on tool usage.",
    }

    off_surface_attacks = [
        "%2525252e%2525252e/escape.py",
        "%25252e",
        "%252f",
        "%255c",
        "con .py",
        "CON.txt",
        "prn .dat",
        "aux.",
        "nul.json",
        "conin$.ts",
        "clock$.py",
        "%43%4f%4e.py",
        "\uff0e\uff0e\uff0f",
        "\uff1a",
        "\uff3c",
        ".",
        "//",
        "a//b",
        "evil.py",
        "README.md",
        "data/stolen.txt",
        "skills/my_skill/evil.sh",
        "scripts/sub/nested.py",
        "plugin/nested/sub.ts",
        "/etc/passwd",
        "C:/windows/system32/cmd.exe",
    ]

    for attack in off_surface_attacks:
        tree = dict(base_tree)
        tree[attack] = "payload"
        with pytest.raises(ValueError) as excinfo:
            validate_tree(RFCHUNT_SURFACE, tree)
        assert "off-surface path rejected" in str(excinfo.value)


def test_normalize_rel_canonical_base_dir_containment(tmp_path):
    """Verify normalize_rel with base_dir returns canonical Path strictly inside base_dir."""
    base_dir = tmp_path / "sandbox"
    base_dir.mkdir()
    valid_file = base_dir / "systemprompt.md"
    valid_file.write_text("Hello surface")

    resolved = normalize_rel("systemprompt.md", base_dir=base_dir)
    assert resolved == valid_file.resolve()
    assert resolved.is_relative_to(base_dir.resolve())

    # Path escape attempts when base_dir is enforced
    with pytest.raises(ValueError):
        normalize_rel("../outside.txt", base_dir=base_dir)

    with pytest.raises(ValueError):
        normalize_rel(".", base_dir=base_dir)


# ==============================================================================
# Part 2: SQLite Concurrency Stress Tests
# ==============================================================================

def test_sqlite_wal_concurrency_10_threads_zero_errors(tmp_path):
    """
    Stress-test SQLite Database concurrency with 10 simultaneous threads:
    - 5 writer threads performing rapid multi-table inserts
    - 5 reader threads cycling queries across all 11 read methods
    - Shared Database instance in WAL mode
    - Strict assertion of 0 OperationalError, 0 InterfaceError, and 0 exceptions.
    """
    db_file = tmp_path / "concurrent_stress.db"
    db = Database(str(db_file), timeout=30.0)

    # Initial anchor RFC
    db.save_rfc("RFC9110", "HTTP Semantics", "https://rfc-editor.org", "docs/rfc9110.txt")

    errors: List[Tuple[str, int, str, str]] = []
    lock = threading.Lock()
    writes_completed = [0]
    reads_completed = [0]
    iterations = 60

    def writer_worker(w_id: int):
        try:
            for i in range(iterations):
                t_rfc = f"RFC{w_id * 10000 + i}"
                db.save_rfc(t_rfc, f"Title {i}", "http://example.com", f"path/{i}")
                db.save_fragments(t_rfc, [(f"Fragment content {i}", "http,test")])
                p_id = db.save_probe(None, f"Rationale {i}", f"GET /w{w_id}_{i} HTTP/1.1\r\nHost: test\r\n\r\n")
                eval_id = db.record_evaluation(p_id, "127.0.0.1", 80, True, "CL.TE", "detail", "evidence")
                db.record_anomaly(eval_id, "test_blend", "desc", b"RAW_RESP")
                db.save_anomaly_fingerprint("desync", f"pat_{w_id}_{i}", "body", "test")
                db.save_dynamic_permutation(f"mut_{w_id}_{i}", "match", "replace")
                db.save_harness2_run({
                    "task_id": f"task_{w_id}_{i}",
                    "domain": "http",
                    "mode": "agg",
                    "k": 1,
                    "adopted_label": "c1",
                    "rollouts": {"c1": {"behavioral_score": 0.95}},
                    "ledger": {"actual_rollouts": 4, "actual_sessions": 3},
                    "experience": {"cue": "cue", "lesson": "lesson", "evidence": "ev"}
                })
                db.save_arm106_defensive_rule(f"RULE_{w_id}_{i}", "name", "WAF", "HTTP/1.1", "RFC9112", "content", "HIGH")
                db.save_arm107_regression_test(f"TEST_{w_id}_{i}", f"VULN_{w_id}_{i}", "HTTP/1.1", "400", "deadbeef", "Assert 400")
                db.save_rfc_requirement(f"REQ_{w_id}_{i}", t_rfc, "s1", "MUST", "Must not fail", "expr", "MUST")
                db.save_implementation_anomaly(f"ANOM_{w_id}_{i}", "engine_a", "cat", "obs", "exp", "probe", "resp")
                db.save_novel_technique(f"TECH_{w_id}_{i}", "title", "model", "inv", ["arch"], ["vuln"], "mit")
                db.save_reproducible_vulnerability(f"VULN_{w_id}_{i}", f"ANOM_{w_id}_{i}", "HIGH", "probe", 1.0, 3, 3, 2, ["p1", "p2"])
                with lock:
                    writes_completed[0] += 1
        except Exception as e:
            with lock:
                errors.append(("writer", w_id, type(e).__name__, str(e)))

    def reader_worker(r_id: int):
        try:
            for i in range(iterations):
                db.get_unprocessed_fragments(10)
                db.get_pending_probes("127.0.0.1", 10)
                db.get_confirmed_findings()
                db.get_dynamic_permutations()
                db.get_anomaly_fingerprints()
                db.get_harness2_runs(10)
                db.get_tier_taxonomy_counts()
                db.get_ingested_rfc_ids()
                db.get_scanned_rfc_nums()
                db.get_probe_evaluation_count(1)
                db.get_storage_stats()
                with lock:
                    reads_completed[0] += 1
        except Exception as e:
            with lock:
                errors.append(("reader", r_id, type(e).__name__, str(e)))

    threads = []
    for wid in range(5):
        threads.append(threading.Thread(target=writer_worker, args=(wid,)))
    for rid in range(5):
        threads.append(threading.Thread(target=reader_worker, args=(rid,)))

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    db.close()

    assert not errors, f"Concurrency stress errors encountered: {errors}"
    assert writes_completed[0] == 5 * iterations, f"Expected {5 * iterations} write iterations, got {writes_completed[0]}"
    assert reads_completed[0] == 5 * iterations, f"Expected {5 * iterations} read iterations, got {reads_completed[0]}"


def test_sqlite_windows_file_lock_leak_prevention():
    """
    Verify that repeatedly opening and closing Database instances in temporary directories
    releases all file handles and WAL mappings, preventing [WinError 32] on directory cleanup.
    """
    # 1. 20 consecutive cycles of create -> populate -> query -> close -> unlink
    for i in range(20):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / f"leak_test_{i}.db"
            db = Database(str(db_path))
            db.save_rfc("RFC1111", "Test RFC", "url", "path")
            db.save_fragments("RFC1111", [("fragment content", "kw")])
            stats = db.get_storage_stats()
            assert stats["total_rows"] >= 2
            db.close()
            assert db.is_closed

    # 2. Multiple simultaneous connections to the same file cleanly closing
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "multi_conn.db"
        conns = [Database(str(db_path)) for _ in range(5)]
        for idx, c in enumerate(conns):
            c.save_rfc(f"RFC{idx}", f"RFC Title {idx}", "url", "path")
            c.get_storage_stats()
        for c in conns:
            c.close()
            assert c.is_closed

    # 3. Context manager usage
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "ctx_mgr.db"
        with Database(str(db_path)) as db:
            db.save_rfc("RFC2222", "Context Manager Test", "url", "path")
            db.save_fragments("RFC2222", [("fragment data", "http")])
            assert len(db.get_ingested_rfc_ids()) == 1
        assert db.is_closed

    # 4. Implicit cleanup via __del__ and garbage collection
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "del_gc.db"
        db = Database(str(db_path))
        db.save_rfc("RFC3333", "GC Test", "url", "path")
        del db
        gc.collect()
