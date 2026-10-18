"""
Empirical Stress Test Suite: Milestone 4 Challenger Remediation 2.
Comprehensive stress testing of SQLite WAL concurrency (threads & processes),
Windows file lock release, and path traversal normalization defenses.
"""

import multiprocessing
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import Database
from engine.harness2_engine import RFCHUNT_SURFACE, normalize_rel, validate_tree


# ==============================================================================
# Helper worker for Multiprocess Concurrency
# ==============================================================================

def _multiprocess_writer_worker(worker_id: int, db_path: str, count: int, error_queue: multiprocessing.Queue):
    """Child process that opens its own Database connection and writes records concurrently."""
    try:
        db = Database(db_path, timeout=30.0)
        for i in range(count):
            rfc_id = f"RFC_MP_{worker_id}_{i}"
            db.save_rfc(rfc_id, f"Multiprocess RFC {worker_id}-{i}", "http://example.com", f"path/{worker_id}/{i}")
            db.save_fragments(rfc_id, [(f"Fragment from worker {worker_id} iteration {i}", "concurrency,mp")])
            p_id = db.save_probe(None, f"MP Rationale {worker_id}-{i}", f"GET /mp_{worker_id}_{i} HTTP/1.1\r\nHost: test\r\n\r\n")
            e_id = db.record_evaluation(p_id, "127.0.0.1", 80, True, "CL.TE", "mp test", "evidence")
            db.record_anomaly(e_id, "mp_anomaly", "desc", b"MP_RESP")
            db.save_arm106_defensive_rule(f"RULE_MP_{worker_id}_{i}", "mp_rule", "WAF", "HTTP/1.1", "RFC9112", "content", "HIGH")
        db.close()
    except Exception as e:
        error_queue.put((worker_id, type(e).__name__, str(e)))


def run_threaded_concurrency_stress():
    print("\n--- [STRESS 1] Running 20-Thread SQLite WAL Concurrency Stress (10 writers, 10 readers) ---")
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "threaded_stress.db"
        db = Database(str(db_path), timeout=30.0)
        db.save_rfc("RFC9110", "Base Semantics", "http://example.com", "path")

        writers = 10
        readers = 10
        iterations = 100
        errors: List[Tuple[str, int, str, str]] = []
        lock = threading.Lock()
        writes_completed = [0]
        reads_completed = [0]

        def writer_task(wid: int):
            try:
                for i in range(iterations):
                    t_rfc = f"RFC_T_{wid}_{i}"
                    db.save_rfc(t_rfc, f"Title {wid}-{i}", "http://example.com", f"path/{wid}/{i}")
                    db.save_fragments(t_rfc, [(f"Fragment {wid}-{i}", "kw")])
                    pid = db.save_probe(None, f"Rationale {wid}-{i}", f"GET /t_{wid}_{i} HTTP/1.1\r\n\r\n")
                    eid = db.record_evaluation(pid, "127.0.0.1", 80, False, None, "ok", "evidence")
                    db.save_arm106_defensive_rule(f"RULE_T_{wid}_{i}", "name", "WAF", "HTTP/1.1", "RFC9112", "content", "MED")
                    db.save_harness2_run({
                        "task_id": f"task_t_{wid}_{i}",
                        "domain": "http",
                        "mode": "agg",
                        "k": 1,
                        "adopted_label": "c1",
                        "rollouts": {"c1": {"behavioral_score": 0.99}},
                        "ledger": {"actual_rollouts": 4, "actual_sessions": 3},
                        "experience": {"cue": "c", "lesson": "l", "evidence": "e"}
                    })
                    with lock:
                        writes_completed[0] += 1
            except Exception as e:
                with lock:
                    errors.append(("writer", wid, type(e).__name__, str(e)))

        def reader_task(rid: int):
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
                    db.get_storage_stats()
                    with lock:
                        reads_completed[0] += 1
            except Exception as e:
                with lock:
                    errors.append(("reader", rid, type(e).__name__, str(e)))

        threads = []
        for w in range(writers):
            threads.append(threading.Thread(target=writer_task, args=(w,)))
        for r in range(readers):
            threads.append(threading.Thread(target=reader_task, args=(r,)))

        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        elapsed = time.perf_counter() - t0

        stats = db.get_storage_stats()
        db.close()

        print(f"  [+] Threaded stress finished in {elapsed:.2f}s")
        print(f"  [+] Writes completed: {writes_completed[0]} / {writers * iterations}")
        print(f"  [+] Reads completed:  {reads_completed[0]} / {readers * iterations}")
        print(f"  [+] Total DB rows:    {stats['total_rows']}")
        print(f"  [+] Errors:           {len(errors)}")

        assert not errors, f"Threaded stress encountered errors: {errors}"
        assert writes_completed[0] == writers * iterations
        assert reads_completed[0] == readers * iterations
        print("  [PASS] 20-Thread SQLite WAL Concurrency Stress passed 100% with ZERO errors.")


def run_multiprocess_concurrency_stress():
    print("\n--- [STRESS 2] Running Multi-Process SQLite Cross-Process Concurrency Stress ---")
    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "mp_stress.db")
        # Initialize schema with main Database instance
        init_db = Database(db_path, timeout=30.0)
        init_db.close()

        num_processes = 4
        iterations_per_proc = 50
        error_queue = multiprocessing.Queue()
        processes = []

        t0 = time.perf_counter()
        for p_id in range(num_processes):
            p = multiprocessing.Process(
                target=_multiprocess_writer_worker,
                args=(p_id, db_path, iterations_per_proc, error_queue)
            )
            processes.append(p)
            p.start()

        for p in processes:
            p.join(timeout=60)
        elapsed = time.perf_counter() - t0

        errors = []
        while not error_queue.empty():
            errors.append(error_queue.get())

        # Verify final state using fresh connection
        check_db = Database(db_path, timeout=30.0)
        stats = check_db.get_storage_stats()
        rfcs_count = stats["table_counts"].get("rfcs", 0)
        rules_count = stats["table_counts"].get("arm106_defensive_rules", 0)
        check_db.close()

        print(f"  [+] Multi-process stress finished in {elapsed:.2f}s across {num_processes} processes")
        print(f"  [+] RFCs inserted:          {rfcs_count} (expected {num_processes * iterations_per_proc})")
        print(f"  [+] Defensive rules saved:  {rules_count} (expected {num_processes * iterations_per_proc})")
        print(f"  [+] Errors:                 {len(errors)}")

        assert not errors, f"Multi-process concurrency errors: {errors}"
        assert rfcs_count == num_processes * iterations_per_proc, f"Expected {num_processes * iterations_per_proc} RFCs, got {rfcs_count}"
        assert rules_count == num_processes * iterations_per_proc, f"Expected {num_processes * iterations_per_proc} rules, got {rules_count}"
        print("  [PASS] Multi-Process Cross-Process SQLite Concurrency Stress passed 100% with ZERO errors.")


def run_windows_file_locking_leak_stress():
    print("\n--- [STRESS 3] Running Windows File Locking & Temp Directory Deletion Stress ---")
    cycles = 30
    t0 = time.perf_counter()
    for i in range(cycles):
        with tempfile.TemporaryDirectory() as td:
            db_file = Path(td) / f"cycle_{i}.db"
            db = Database(str(db_file), timeout=30.0)
            db.save_rfc(f"RFC{i}", f"Title {i}", "url", "path")
            db.save_fragments(f"RFC{i}", [(f"frag {i}", "kw")])
            stats = db.get_storage_stats()
            assert stats["total_rows"] >= 2
            db.close()
            assert db.is_closed
            # Exiting with context manager will trigger rmtree on td
            # If any SQLite handle or WAL SHM mapping remained open, Windows raises WinError 32
    elapsed = time.perf_counter() - t0
    print(f"  [+] Completed {cycles} consecutive DB create/close/delete cycles in {elapsed:.2f}s without [WinError 32]")
    print("  [PASS] Windows file locking & temp directory cleanup passed 100%.")


def run_path_traversal_deep_stress():
    print("\n--- [STRESS 4] Running Deep Path Traversal Adversarial Attack Stress ---")
    adversarial_payloads = [
        # Recursive / multi-level percent-encoding
        "%2525252e%2525252e/escape.py",
        "%25252e",
        "%252f",
        "%255c",
        "%2525252fetc%2525252fpasswd",
        "%25252525252e%25252525252e%25252525252f",
        "%252e%252e%252fetc%252fpasswd",
        "foo/%252e%252e/bar",
        "scripts/%255c..%255csteal.py",
        # Windows reserved device names (varied casing, extensions, spaces, dots)
        "con .py", "CON.txt", "prn .dat", "aux.", "nul.json",
        "conin$.ts", "clock$.py", "com1.", "com1 .", "com1.txt",
        "com9.dat", "lpt1.log", "lpt9.bin", "aux .txt", "nul .",
        "prn .", "conout$.ts", "CONIN$.TXT", "CONOUT$.TXT", "CLOCK$.TXT",
        "cOn.py", "CoN.txt", "AuX.bin", "nUl.dat", "pRn.doc",
        "skills/con/SKILL.md", "skills/aux./SKILL.md", "skills/clock$/SKILL.md",
        "sub_agents/con/AGENT.md",
        # URL encoded device names
        "%43%4f%4e.py", "%41%55%58.json", "%4e%55%4c.txt", "%50%52%4e.dat",
        "%63%6f%6e.py", "%43%4f%4e%49%4e%24.ts", "skills/%43%4f%4e/SKILL.md",
        # Unicode fullwidth homoglyphs
        "\uff0e\uff0e\uff0f", "\uff1a", "\uff3c", "\uff0e\uff0e\uff0fetc\uff0fpasswd",
        "c\uff1a\uff0fwindows\uff0fsystem32", "skills\uff0f\uff0e\uff0e\uff0fescape.py",
        "\uff0e\uff0e\uff3cescape.py", "foo/\uff0e\uff0e/bar", "foo\uff1abar",
        # NTFS Alternate Data Streams and colons
        "file.txt:stream", "file.txt::$DATA", "dir:stream:$DATA", "C:test.txt",
        # Empty paths, single dots, double slashes, UNC paths
        ".", "..", "//", "///", "////", "a//b", "skills//my_skill/SKILL.md",
        "skills/./my_skill/SKILL.md", "", "   ", "\t\n", "////etc/passwd",
        r"\\localhost\c$\secret", r"\\?\C:\windows",
        # Null byte injection
        "skills/normal\x00escape/SKILL.md",
        "scripts/test%00.py",
    ]

    rejected_count = 0
    for payload in adversarial_payloads:
        try:
            normalize_rel(payload)
            assert False, f"VULNERABILITY: normalize_rel allowed forbidden payload: {payload!r}"
        except ValueError:
            rejected_count += 1

    print(f"  [+] Tested {len(adversarial_payloads)} adversarial payloads; 100% rejected ({rejected_count}/{len(adversarial_payloads)})")

    # Canonical base directory containment check
    with tempfile.TemporaryDirectory() as td:
        base_dir = Path(td)
        valid = base_dir / "systemprompt.md"
        valid.write_text("Valid content")
        res = normalize_rel("systemprompt.md", base_dir=base_dir)
        assert res == valid.resolve()

        # Escape attempts with base_dir
        for esc in ["../outside.txt", "..", ".", "sub/../../outside"]:
            try:
                normalize_rel(esc, base_dir=base_dir)
                assert False, f"VULNERABILITY: normalize_rel permitted escape: {esc!r}"
            except ValueError:
                pass

    print("  [PASS] Deep Path Traversal Adversarial Attack Stress passed 100%.")


if __name__ == "__main__":
    print("=" * 78)
    print("  CHALLENGER M4 REMEDIATION 2 EMPIRICAL STRESS TEST HARNESS")
    print("=" * 78)

    run_path_traversal_deep_stress()
    run_threaded_concurrency_stress()
    run_multiprocess_concurrency_stress()
    run_windows_file_locking_leak_stress()

    print("\n" + "=" * 78)
    print("  [VERDICT] ALL 4 EMPIRICAL CHALLENGE SUITES PASSED 100% WITH ZERO DEFECTS.")
    print("=" * 78)
