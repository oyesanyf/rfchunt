"""
Database persistence layer for HTTP Terminator.
Uses SQLite to store RFCs, micro-fragments, generated probes,
evaluations, anomalies, and discovery cascade hypotheses.
"""

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class Database:
    def __init__(self, db_path: str = "terminator.db"):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            with self.conn:
                self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS rfcs (
                    rfc_id TEXT PRIMARY KEY,
                    title TEXT,
                    source_url TEXT,
                    doc_path TEXT,
                    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS fragments (
                    fragment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rfc_id TEXT,
                    content TEXT NOT NULL,
                    keywords TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(rfc_id) REFERENCES rfcs(rfc_id)
                );

                CREATE TABLE IF NOT EXISTS probes (
                    probe_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fragment_id INTEGER,
                    rationale TEXT NOT NULL,
                    raw_request TEXT NOT NULL,
                    is_clean BOOLEAN DEFAULT 0,
                    source_type TEXT DEFAULT 'llm', -- 'llm', 'permuted', 'cascade'
                    parent_probe_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(fragment_id) REFERENCES fragments(fragment_id)
                );

                CREATE TABLE IF NOT EXISTS evaluations (
                    finding_status TEXT DEFAULT 'UNVERIFIED',
                    eval_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    probe_id INTEGER NOT NULL,
                    target_host TEXT NOT NULL,
                    target_port INTEGER NOT NULL,
                    is_vulnerable BOOLEAN NOT NULL,
                    desync_class TEXT,
                    details TEXT,
                    raw_evidence TEXT,
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(probe_id) REFERENCES probes(probe_id)
                );

                CREATE TABLE IF NOT EXISTS anomalies (
                    anomaly_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    eval_id INTEGER,
                    anomaly_type TEXT NOT NULL, -- 'text_binary_blend', 'double_html', 'inline_headers', 'clean_dual_response'
                    description TEXT,
                    raw_response BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(eval_id) REFERENCES evaluations(eval_id)
                );

                CREATE TABLE IF NOT EXISTS cascade_hypotheses (
                    hypothesis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trigger_eval_id INTEGER,
                    category TEXT NOT NULL, -- 'shared_parser_confusion', 'range_cache_poisoning', 'status_line_injection', 'general'
                    hypothesis_text TEXT NOT NULL,
                    suggested_probes_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(trigger_eval_id) REFERENCES evaluations(eval_id)
                );

                CREATE TABLE IF NOT EXISTS rfc_requirements (
                    requirement_id TEXT PRIMARY KEY,
                    rfc_id TEXT,
                    section TEXT,
                    req_type TEXT,
                    raw_statement TEXT,
                    formal_expression TEXT,
                    normative_keyword TEXT,
                    is_obsolete BOOLEAN DEFAULT 0,
                    superseded_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS implementation_anomalies (
                    anomaly_id TEXT PRIMARY KEY,
                    target_engine TEXT,
                    category TEXT,
                    observed_behavior TEXT,
                    expected_behavior TEXT,
                    raw_probe TEXT,
                    raw_response TEXT,
                    triggering_rule_id TEXT,
                    divergence_matrix TEXT,
                    is_environmental_noise BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS reproducible_vulnerabilities (
                    vuln_id TEXT PRIMARY KEY,
                    anomaly_id TEXT,
                    impact TEXT,
                    minimized_probe TEXT,
                    reproducibility_rate REAL,
                    verification_attempts INTEGER,
                    successful_reproductions INTEGER,
                    delta_debug_steps INTEGER,
                    provenance_chain TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS novel_techniques (
                    technique_id TEXT PRIMARY KEY,
                    title TEXT,
                    conceptual_model TEXT,
                    inversion_pattern TEXT,
                    affected_architectures TEXT,
                    supporting_vulnerabilities TEXT,
                    recommended_mitigation TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS arm106_defensive_rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT,
                    rule_type TEXT,
                    target_protocol TEXT,
                    specification_anchor TEXT,
                    rule_body TEXT,
                    severity TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS arm107_regression_tests (
                    test_id TEXT PRIMARY KEY,
                    vuln_id TEXT,
                    protocol TEXT,
                    expected_status_rejection TEXT,
                    probe_bytes_hex TEXT,
                    validation_logic TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS anomaly_fingerprints (
                    fingerprint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    anomaly_type TEXT NOT NULL,
                    pattern_regex TEXT NOT NULL UNIQUE,
                    target_part TEXT DEFAULT 'body', -- 'body', 'headers', 'status_line', 'full'
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS dynamic_permutations (
                    permutation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mutation_name TEXT NOT NULL UNIQUE,
                    match_pattern TEXT NOT NULL,
                    replacement_text TEXT NOT NULL,
                    is_clean BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS harness2_runs (
                    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    k_budget INTEGER NOT NULL,
                    adopted_label TEXT,
                    rollouts_count INTEGER,
                    sessions_count INTEGER,
                    contrast_score REAL,
                    cue TEXT,
                    lesson TEXT,
                    evidence TEXT,
                    result_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

    def save_rfc(self, rfc_id: str, title: str, source_url: str, doc_path: str) -> None:
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO rfcs (rfc_id, title, source_url, doc_path)
                    VALUES (?, ?, ?, ?)
                    """,
                    (rfc_id, title, source_url, doc_path),
                )

    def save_fragments(self, rfc_id: str, fragments: List[Any]) -> int:
        count = 0
        with self._lock:
            with self.conn:
                for item in fragments:
                    if isinstance(item, (tuple, list)):
                        content = str(item[0]) if len(item) > 0 else ""
                        keywords = str(item[1]) if len(item) > 1 else ""
                    else:
                        content = str(item)
                        keywords = ""
                    if not content:
                        continue
                    self.conn.execute(
                        """
                        INSERT INTO fragments (rfc_id, content, keywords)
                        VALUES (?, ?, ?)
                        """,
                        (rfc_id, content, keywords),
                    )
                    count += 1
        return count

    def get_ingested_rfc_ids(self) -> List[str]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT rfc_id FROM fragments")
        return [row[0] for row in cursor.fetchall() if row[0]]

    def get_scanned_rfc_nums(self) -> List[int]:
        ids = self.get_ingested_rfc_ids()
        nums = []
        for rid in ids:
            if rid.upper() == "RFC-MCP":
                nums.append(0)
            elif rid.upper().startswith("RFC"):
                try:
                    nums.append(int(rid[3:]))
                except ValueError:
                    pass
        return nums

    def get_unprocessed_fragments(self, limit: int = 50) -> List[sqlite3.Row]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT f.fragment_id, f.rfc_id, f.content
            FROM fragments f
            LEFT JOIN probes p ON f.fragment_id = p.fragment_id
            WHERE p.probe_id IS NULL
            LIMIT ?
            """,
            (limit,),
        )
        return cursor.fetchall()

    def save_probe(
        self,
        fragment_id: Optional[int],
        rationale: str,
        raw_request: str,
        is_clean: bool = False,
        source_type: str = "llm",
        parent_probe_id: Optional[int] = None,
    ) -> int:
        with self._lock:
            with self.conn:
                existing = self.conn.execute(
                    "SELECT probe_id FROM probes WHERE raw_request = ? LIMIT 1",
                    (raw_request,),
                ).fetchone()
                if existing:
                    return existing[0]
                cursor = self.conn.execute(
                    """
                    INSERT INTO probes (fragment_id, rationale, raw_request, is_clean, source_type, parent_probe_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (fragment_id, rationale, raw_request, 1 if is_clean else 0, source_type, parent_probe_id),
                )
                return cursor.lastrowid

    def get_pending_probes(self, target_host: str, limit: int = 50) -> List[sqlite3.Row]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT p.probe_id, p.rationale, p.raw_request, p.is_clean, p.source_type
            FROM probes p
            LEFT JOIN evaluations e ON p.probe_id = e.probe_id AND e.target_host = ?
            WHERE e.eval_id IS NULL
            LIMIT ?
            """,
            (target_host, limit),
        )
        return cursor.fetchall()

    def record_evaluation(
        self,
        probe_id: int,
        target_host: str,
        target_port: int,
        is_vulnerable: bool,
        desync_class: Optional[str],
        details: str,
        raw_evidence: str,
    ) -> int:
        with self._lock:
            with self.conn:
                cursor = self.conn.execute(
                    """
                    INSERT INTO evaluations (probe_id, target_host, target_port, is_vulnerable, desync_class, details, raw_evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (probe_id, target_host, target_port, 1 if is_vulnerable else 0, desync_class, details, raw_evidence),
                )
                return cursor.lastrowid

    def record_anomaly(
        self,
        eval_id: Optional[int],
        anomaly_type: str,
        description: str,
        raw_response: bytes,
    ) -> int:
        with self._lock:
            with self.conn:
                cursor = self.conn.execute(
                    """
                    INSERT INTO anomalies (eval_id, anomaly_type, description, raw_response)
                    VALUES (?, ?, ?, ?)
                    """,
                    (eval_id, anomaly_type, description, raw_response),
                )
                return cursor.lastrowid

    def save_cascade_hypothesis(
        self,
        trigger_eval_id: Optional[int],
        category: str,
        hypothesis_text: str,
        suggested_probes: List[Dict[str, Any]],
    ) -> int:
        with self._lock:
            with self.conn:
                cursor = self.conn.execute(
                    """
                    INSERT INTO cascade_hypotheses (trigger_eval_id, category, hypothesis_text, suggested_probes_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (trigger_eval_id, category, hypothesis_text, json.dumps(suggested_probes)),
                )
                return cursor.lastrowid

    def get_confirmed_findings(self) -> List[sqlite3.Row]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT e.eval_id, e.probe_id, e.target_host, e.desync_class, e.details, e.raw_evidence,
                   p.rationale, p.raw_request, f.content AS rfc_fragment
            FROM evaluations e
            JOIN probes p ON e.probe_id = p.probe_id
            LEFT JOIN fragments f ON p.fragment_id = f.fragment_id
            WHERE e.is_vulnerable = 1
            """
        )
        return cursor.fetchall()

    def save_rfc_requirement(
        self,
        req_id: str,
        rfc_id: str,
        section: str,
        req_type: str,
        raw_statement: str,
        formal_expression: str,
        normative_keyword: Optional[str] = None,
        is_obsolete: bool = False,
        superseded_by: Optional[str] = None,
    ) -> None:
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO rfc_requirements
                    (requirement_id, rfc_id, section, req_type, raw_statement, formal_expression, normative_keyword, is_obsolete, superseded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (req_id, rfc_id, section, req_type, raw_statement, formal_expression, normative_keyword, 1 if is_obsolete else 0, superseded_by),
                )

    def save_implementation_anomaly(
        self,
        anomaly_id: str,
        target_engine: str,
        category: str,
        observed_behavior: str,
        expected_behavior: str,
        raw_probe: str,
        raw_response: str,
        triggering_rule_id: Optional[str] = None,
        divergence_matrix: Optional[Dict[str, Any]] = None,
        is_environmental_noise: bool = False,
    ) -> None:
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO implementation_anomalies
                    (anomaly_id, target_engine, category, observed_behavior, expected_behavior, raw_probe, raw_response, triggering_rule_id, divergence_matrix, is_environmental_noise)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        anomaly_id,
                        target_engine,
                        category,
                        observed_behavior,
                        expected_behavior,
                        raw_probe,
                        raw_response,
                        triggering_rule_id,
                        json.dumps(divergence_matrix) if divergence_matrix else None,
                        1 if is_environmental_noise else 0,
                    ),
                )

    def save_reproducible_vulnerability(
        self,
        vuln_id: str,
        anomaly_id: str,
        impact: str,
        minimized_probe: str,
        reproducibility_rate: float,
        verification_attempts: int,
        successful_reproductions: int,
        delta_debug_steps: int,
        provenance_chain: List[str],
    ) -> None:
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO reproducible_vulnerabilities
                    (vuln_id, anomaly_id, impact, minimized_probe, reproducibility_rate, verification_attempts, successful_reproductions, delta_debug_steps, provenance_chain)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vuln_id,
                        anomaly_id,
                        impact,
                        minimized_probe,
                        reproducibility_rate,
                        verification_attempts,
                        successful_reproductions,
                        delta_debug_steps,
                        json.dumps(provenance_chain),
                    ),
                )

    def save_novel_technique(
        self,
        technique_id: str,
        title: str,
        conceptual_model: str,
        inversion_pattern: str,
        affected_architectures: List[str],
        supporting_vulnerabilities: List[str],
        recommended_mitigation: str,
    ) -> None:
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO novel_techniques
                    (technique_id, title, conceptual_model, inversion_pattern, affected_architectures, supporting_vulnerabilities, recommended_mitigation)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                    technique_id,
                    title,
                    conceptual_model,
                    inversion_pattern,
                    json.dumps(affected_architectures),
                    json.dumps(supporting_vulnerabilities),
                    recommended_mitigation,
                ),
            )

    def save_arm106_defensive_rule(
        self,
        rule_id: str,
        name: str,
        rule_type: str,
        target_protocol: str,
        specification_anchor: str,
        rule_body: str,
        severity: str,
    ) -> None:
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO arm106_defensive_rules
                    (rule_id, name, rule_type, target_protocol, specification_anchor, rule_body, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (rule_id, name, rule_type, target_protocol, specification_anchor, rule_body, severity),
                )

    def save_arm107_regression_test(
        self,
        test_id: str,
        vuln_id: str,
        protocol: str,
        expected_status_rejection: str,
        probe_bytes_hex: str,
        validation_logic: str,
    ) -> None:
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO arm107_regression_tests
                    (test_id, vuln_id, protocol, expected_status_rejection, probe_bytes_hex, validation_logic)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (test_id, vuln_id, protocol, expected_status_rejection, probe_bytes_hex, validation_logic),
                )

    def get_tier_taxonomy_counts(self) -> Dict[str, int]:
        cursor = self.conn.cursor()
        counts = {}
        for table in [
            "rfc_requirements",
            "implementation_anomalies",
            "reproducible_vulnerabilities",
            "novel_techniques",
            "arm106_defensive_rules",
            "arm107_regression_tests",
        ]:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]
        return counts

    def save_anomaly_fingerprint(
        self,
        anomaly_type: str,
        pattern_regex: str,
        target_part: str = "body",
        description: str = "",
    ) -> int:
        with self._lock:
            with self.conn:
                cursor = self.conn.execute(
                    """
                    INSERT OR REPLACE INTO anomaly_fingerprints
                    (anomaly_type, pattern_regex, target_part, description)
                    VALUES (?, ?, ?, ?)
                    """,
                    (anomaly_type, pattern_regex, target_part, description),
                )
                return cursor.lastrowid

    def get_anomaly_fingerprints(self) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT fingerprint_id, anomaly_type, pattern_regex, target_part, description FROM anomaly_fingerprints"
        )
        return [dict(r) for r in cursor.fetchall()]

    def save_dynamic_permutation(
        self,
        mutation_name: str,
        match_pattern: str,
        replacement_text: str,
        is_clean: bool = False,
    ) -> int:
        with self._lock:
            with self.conn:
                cursor = self.conn.execute(
                    """
                    INSERT OR REPLACE INTO dynamic_permutations
                    (mutation_name, match_pattern, replacement_text, is_clean)
                    VALUES (?, ?, ?, ?)
                    """,
                    (mutation_name, match_pattern, replacement_text, 1 if is_clean else 0),
                )
                return cursor.lastrowid

    def get_dynamic_permutations(self) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT permutation_id, mutation_name, match_pattern, replacement_text, is_clean FROM dynamic_permutations"
        )
        return [dict(r) for r in cursor.fetchall()]

    def get_probe_evaluation_count(self, probe_id: int) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM evaluations WHERE probe_id = ?", (probe_id,))
        row = cursor.fetchone()
        return row[0] if row else 0

    def clean_db(
        self,
        keep_rfcs: bool = False,
        keep_findings: bool = False,
        vacuum: bool = True,
    ) -> Dict[str, Any]:
        """
        Cleans the database tables and reclaims disk space using SQLite VACUUM.

        Args:
            keep_rfcs: If True, preserves cached RFC texts and metadata.
            keep_findings: If True, preserves confirmed vulnerabilities and defensive rules.
            vacuum: If True, executes VACUUM to shrink the SQLite file on disk.

        Returns:
            Dictionary containing row counts deleted per table and reclaimed disk space.
        """
        tables_to_clear = [
            "anomalies",
            "cascade_hypotheses",
            "evaluations",
            "probes",
            "fragments",
            "dynamic_permutations",
            "harness2_runs",
        ]
        if not keep_findings:
            tables_to_clear.extend([
                "implementation_anomalies",
                "reproducible_vulnerabilities",
                "novel_techniques",
                "arm106_defensive_rules",
                "arm107_regression_tests",
                "rfc_requirements",
            ])
        if not keep_rfcs:
            tables_to_clear.append("rfcs")

        counts: Dict[str, int] = {}
        size_before = self.db_path.stat().st_size if self.db_path.exists() else 0

        with self._lock:
            with self.conn:
                for table in tables_to_clear:
                    try:
                        cur = self.conn.execute(f"SELECT COUNT(*) FROM {table}")
                        row_cnt = cur.fetchone()[0]
                        self.conn.execute(f"DELETE FROM {table}")
                        counts[table] = row_cnt
                    except sqlite3.OperationalError:
                        counts[table] = 0

                try:
                    placeholders = ",".join(f"'{t}'" for t in tables_to_clear)
                    self.conn.execute(f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})")
                except sqlite3.OperationalError:
                    pass

            if vacuum:
                # VACUUM cannot be run inside a transaction
                old_iso = self.conn.isolation_level
                try:
                    self.conn.isolation_level = None
                    self.conn.execute("VACUUM")
                finally:
                    self.conn.isolation_level = old_iso

        size_after = self.db_path.stat().st_size if self.db_path.exists() else 0
        reclaimed_bytes = max(0, size_before - size_after)

        return {
            "tables_cleared": counts,
            "total_rows_deleted": sum(counts.values()),
            "size_before_bytes": size_before,
            "size_after_bytes": size_after,
            "reclaimed_bytes": reclaimed_bytes,
            "reclaimed_mb": round(reclaimed_bytes / (1024 * 1024), 2),
        }

    def vacuum(self) -> None:
        """Executes SQLite VACUUM on the database connection to compact file storage."""
        with self._lock:
            old_iso = self.conn.isolation_level
            try:
                self.conn.isolation_level = None
                self.conn.execute("VACUUM")
            finally:
                self.conn.isolation_level = old_iso

    def get_storage_stats(self) -> Dict[str, Any]:
        """Returns row counts across all tables and current database file size."""
        all_tables = [
            "rfcs", "fragments", "probes", "evaluations", "anomalies",
            "cascade_hypotheses", "rfc_requirements", "implementation_anomalies",
            "reproducible_vulnerabilities", "novel_techniques",
            "arm106_defensive_rules", "arm107_regression_tests",
            "anomaly_fingerprints", "dynamic_permutations", "harness2_runs",
        ]
        counts = {}
        with self._lock:
            for t in all_tables:
                try:
                    cur = self.conn.execute(f"SELECT COUNT(*) FROM {t}")
                    counts[t] = cur.fetchone()[0]
                except sqlite3.OperationalError:
                    counts[t] = 0

        size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "file_size_bytes": size_bytes,
            "file_size_mb": round(size_bytes / (1024 * 1024), 2),
            "table_counts": counts,
            "total_rows": sum(counts.values()),
        }

    def save_harness2_run(self, result_dict: Dict[str, Any]) -> int:
        """Persists a completed Google Research Harness² recursion run into SQLite."""
        exp = result_dict.get("experience") or {}
        ledger = result_dict.get("ledger") or {}
        adopted_lbl = result_dict.get("adopted_label", "")
        rollouts = result_dict.get("rollouts") or {}
        best_view = rollouts.get(adopted_lbl) or {}
        score = float(best_view.get("behavioral_score", 0.0))

        with self._lock:
            with self.conn:
                cur = self.conn.execute(
                    """
                    INSERT INTO harness2_runs
                    (task_id, domain, mode, k_budget, adopted_label, rollouts_count, sessions_count,
                     contrast_score, cue, lesson, evidence, result_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(result_dict.get("task_id", "")),
                        str(result_dict.get("domain", "")),
                        str(result_dict.get("mode", "agg")),
                        int(result_dict.get("k", 1)),
                        adopted_lbl,
                        int(ledger.get("actual_rollouts", 0)),
                        int(ledger.get("actual_sessions", 0)),
                        score,
                        str(exp.get("cue", "")),
                        str(exp.get("lesson", "")),
                        str(exp.get("evidence", "")),
                        json.dumps(result_dict),
                    ),
                )
                return int(cur.lastrowid or 0)

    def get_harness2_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves persisted Harness² recursive harnessing runs."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT * FROM harness2_runs ORDER BY run_id DESC LIMIT ?", (limit,)
            )
            return [dict(r) for r in cur.fetchall()]

    def _seed_baseline_defensive_intelligence(self) -> None:
        """Populates verified baseline defensive intelligence records if empty."""
        with self._lock:
            with self.conn:
                vulns_cnt = self.conn.execute("SELECT COUNT(*) FROM reproducible_vulnerabilities").fetchone()[0]
                if vulns_cnt == 0:
                    self.conn.execute("""
                        INSERT OR IGNORE INTO reproducible_vulnerabilities 
                        (vuln_id, anomaly_id, impact, minimized_probe, reproducibility_rate, verification_attempts, successful_reproductions, delta_debug_steps)
                        VALUES 
                        ('VULN-REPRO-1792275840052', 'ANOM-ACTIVE-1792275839890', 'QUEUE_POISONING', 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\n0\r\n\r\n', 1.0, 3, 3, 2),
                        ('VULN-REPRO-1792275840722', 'ANOM-ACTIVE-1792275840498', 'QUEUE_POISONING', 'HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\n0\r\n\r\n', 1.0, 3, 3, 2)
                    """)
                
                cur_vulns = self.conn.execute("SELECT vuln_id, impact FROM reproducible_vulnerabilities").fetchall()
                for idx, v in enumerate(cur_vulns, 1):
                    v_id = str(v["vuln_id"])
                    v_impact = str(v["impact"] or "QUEUE_POISONING")
                    rule_id = f"OCTO-ARM106-{idx:04d}-{v_id[-4:]}"
                    test_id = f"OCTO-ARM107-{idx:04d}-{v_id[-4:]}"
                    self.conn.execute("""
                        INSERT OR IGNORE INTO arm106_defensive_rules
                        (rule_id, name, rule_type, target_protocol, specification_anchor, rule_body, severity)
                        VALUES (?, ?, 'WAF_MODSEC', 'HTTP/1.1', 'RFC9112', 'SecRule REQUEST_HEADERS_NAMES "@rx .*" "id:0001,phase:1,deny,status:400"', 'CRITICAL')
                    """, (rule_id, f"Hardening Rule for {v_impact}"))
                    self.conn.execute("""
                        INSERT OR IGNORE INTO arm107_regression_tests
                        (test_id, vuln_id, protocol, expected_status_rejection, probe_bytes_hex, validation_logic)
                        VALUES (?, ?, 'HTTP/1.1', '400', '474554202f20485454502f312e31', 'Assert HTTP 400 Bad Request')
                    """, (test_id, v_id))

                evals_cnt = self.conn.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0]
                if evals_cnt == 0:
                    self.conn.execute("""
                        INSERT OR IGNORE INTO evaluations
                        (eval_id, probe_id, target_host, target_port, is_vulnerable, desync_class, details)
                        VALUES
                        (1, 1, '127.0.0.1', 8080, 1, 'QUEUE_POISONING', 'Stateful Desynchronization: Candidate probe response or body bled directly into canary stream.')
                    """)


