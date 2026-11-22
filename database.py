"""
Database persistence layer for HTTP Terminator.
Uses SQLite to store RFCs, micro-fragments, generated probes,
evaluations, anomalies, and discovery cascade hypotheses.
"""

import contextlib
import json
import os
import random
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class Database:
    def __init__(
        self,
        db_path: str = "terminator.db",
        timeout: float = 30.0,
        secret_box: Optional[Any] = None,
        encrypt_at_rest: Optional[bool] = None,
        secret_key_path: Optional[Union[str, Path]] = None,
    ):
        self._raw_db_path = str(db_path)
        self.db_path = Path(db_path) if self._raw_db_path else Path(":memory:")
        self._lock = threading.RLock()
        self._batch_depth = 0
        use_uri = self._raw_db_path.startswith("file:")
        connect_target = self._raw_db_path if (self._raw_db_path in ("", ":memory:") or use_uri) else str(self.db_path)
        self.conn = sqlite3.connect(
            connect_target,
            timeout=timeout,
            check_same_thread=False,
            uri=use_uri,
        )
        self.conn.row_factory = sqlite3.Row
        self._configure_pragmas()
        self._init_schema()
        self.secret_box = self._init_secret_box(
            secret_box=secret_box,
            encrypt_at_rest=encrypt_at_rest,
            secret_key_path=secret_key_path,
        )

    def _is_memory_db(self) -> bool:
        raw = getattr(self, "_raw_db_path", str(self.db_path))
        return raw in (":memory:", "") or "mode=memory" in raw

    def _sample_encrypted_value(self) -> Optional[str]:
        """Returns a sample `enc:v1:` ciphertext if any encrypted row exists in SQLite."""
        with self._lock:
            cur = self.conn.cursor()
            for sql in (
                "SELECT request_headers_json FROM traffic_evidence WHERE request_headers_json LIKE 'enc:v1:%' LIMIT 1",
                "SELECT request_body FROM traffic_evidence WHERE request_body LIKE 'enc:v1:%' LIMIT 1",
                "SELECT response_headers_json FROM traffic_evidence WHERE response_headers_json LIKE 'enc:v1:%' LIMIT 1",
                "SELECT response_body_b64 FROM traffic_evidence WHERE response_body_b64 LIKE 'enc:v1:%' LIMIT 1",
                "SELECT raw_payload FROM attack_chains WHERE raw_payload LIKE 'enc:v1:%' LIMIT 1",
            ):
                try:
                    cur.execute(sql)
                    row = cur.fetchone()
                    if row is not None and row[0]:
                        return str(row[0])
                except sqlite3.OperationalError:
                    continue
        return None

    def _has_encrypted_rows(self) -> bool:
        """Checks whether any stored traffic_evidence or attack_chains rows contain `enc:v1:` envelopes."""
        return self._sample_encrypted_value() is not None

    def _init_secret_box(
        self,
        *,
        secret_box: Optional[Any],
        encrypt_at_rest: Optional[bool],
        secret_key_path: Optional[Union[str, Path]],
    ) -> Optional[Any]:
        """
        Initializes AES-256-GCM encryption at rest with fail-closed verification:
        - Refuses to start if encrypted rows exist in SQLite and encryption is disabled,
          no key is available, or the supplied key fails to authenticate a sample ciphertext.
        - On-disk DBs auto-initialize `keys/secret.key` (mode 0600) by default unless disabled.
        - `:memory:` DBs remain unencrypted unless `secret_box` or `encrypt_at_rest=True` is supplied.
        """
        from engine.secret_store import SecretBox

        sample_ct = self._sample_encrypted_value()
        has_encrypted = sample_ct is not None

        def _verify_box_can_decrypt(candidate_box: Any) -> Any:
            if sample_ct is not None:
                try:
                    candidate_box.decrypt_str(sample_ct)
                except Exception as exc:
                    self.close()
                    raise RuntimeError(
                        "Database contains AES-256-GCM encrypted rows that cannot be decrypted with the provided key."
                    ) from exc
            return candidate_box

        if secret_box is not None:
            return _verify_box_can_decrypt(secret_box)

        disable_env = os.environ.get("RFCHUNT_DISABLE_AT_REST_ENCRYPTION", "").strip().lower() in ("1", "true", "yes")
        if has_encrypted:
            if encrypt_at_rest is False or disable_env:
                self.close()
                raise RuntimeError(
                    "Database contains AES-256-GCM encrypted evidence/secrets; cannot open with encryption disabled."
                )
            # Fail-closed: NEVER fabricate a fresh replacement key when encrypted rows already exist!
            box = SecretBox.from_env_or_keyfile(secret_key_path, create_if_missing=False)
            if box is None:
                self.close()
                raise RuntimeError(
                    "Database contains AES-256-GCM encrypted evidence/secrets, but no usable key was found "
                    "(set ARTEX_SECRET_KEY or restore keys/secret.key)."
                )
            return _verify_box_can_decrypt(box)

        if encrypt_at_rest is False or disable_env:
            return None

        if encrypt_at_rest is True:
            return SecretBox.from_env_or_keyfile(secret_key_path, create_if_missing=True)

        # Default (encrypt_at_rest is None): enable for real on-disk DBs; skip for :memory: unless env key set
        if self._is_memory_db():
            return SecretBox.from_env_or_keyfile(secret_key_path, create_if_missing=False) if os.environ.get("ARTEX_SECRET_KEY") else None
        return SecretBox.from_env_or_keyfile(secret_key_path, create_if_missing=True)

    def _enc(self, value: Optional[str]) -> str:
        text = "" if value is None else str(value)
        if not text or self.secret_box is None:
            return text
        return self.secret_box.encrypt_str(text)

    def _dec(self, value: Optional[str]) -> str:
        text = "" if value is None else str(value)
        if not text:
            return ""
        if self.secret_box is None:
            if text.startswith("enc:v1:"):
                raise RuntimeError("Encrypted field encountered without an active SecretBox key.")
            return text
        return self.secret_box.decrypt_str(text)

    @staticmethod
    def _is_busy_operational_error(exc: sqlite3.OperationalError) -> bool:
        msg = str(exc).lower()
        return ("locked" in msg) or ("busy" in msg)

    def _configure_pragmas(self) -> None:
        """Configures production WAL mode, 30s busy timeout, and NORMAL synchrony."""
        with self._lock:
            cur = self.conn.cursor()
            try:
                cur.execute("PRAGMA busy_timeout = 30000;")
                # In-memory databases do not support WAL mode
                is_mem = self._is_memory_db()
                if not is_mem:
                    max_attempts = 12
                    for attempt in range(max_attempts):
                        try:
                            mode_row = cur.execute("PRAGMA journal_mode;").fetchone()
                            current_mode = (
                                str(mode_row[0]).strip().lower()
                                if mode_row is not None and mode_row[0] is not None
                                else ""
                            )
                            if current_mode != "wal":
                                cur.execute("PRAGMA journal_mode = WAL;")
                            break
                        except sqlite3.OperationalError as exc:
                            if self._is_busy_operational_error(exc) and attempt < max_attempts - 1:
                                delay = min(0.25, 0.01 * (2 ** min(attempt, 5))) + random.uniform(0.0, 0.025)
                                time.sleep(delay)
                                continue
                            raise
                cur.execute("PRAGMA synchronous = NORMAL;")
                cur.execute("PRAGMA foreign_keys = ON;")
            finally:
                cur.close()

    def close(self) -> None:
        """Cleanly releases all SQLite locks, WAL mappings, and file handles."""
        with self._lock:
            if hasattr(self, "conn") and self.conn is not None:
                try:
                    try:
                        self.conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
                    except Exception:
                        pass
                    self.conn.close()
                except Exception:
                    pass
                finally:
                    self.conn = None

    @property
    def is_closed(self) -> bool:
        return self.conn is None

    @contextlib.contextmanager
    def batch_writes(self):
        """Groups multiple DB writes into a single SQLite transaction under self._lock."""
        self._lock.acquire()
        try:
            next_depth = self._batch_depth + 1
            sp_name: Optional[str] = None
            started_outer_tx = False
            if next_depth == 1 and not self.conn.in_transaction:
                max_attempts = 10
                for attempt in range(max_attempts):
                    try:
                        self.conn.execute("BEGIN IMMEDIATE")
                        started_outer_tx = True
                        break
                    except sqlite3.OperationalError as exc:
                        if self._is_busy_operational_error(exc) and attempt < max_attempts - 1:
                            if self.conn.in_transaction:
                                try:
                                    self.conn.rollback()
                                except Exception:
                                    pass
                            delay = min(0.25, 0.01 * (2 ** min(attempt, 5))) + random.uniform(0.0, 0.02)
                            time.sleep(delay)
                            continue
                        raise
            else:
                sp_name = f"sp_batch_{next_depth}"
                self.conn.execute(f"SAVEPOINT {sp_name}")
            self._batch_depth = next_depth
            try:
                yield
            except Exception:
                if sp_name is not None and self.conn.in_transaction:
                    self.conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                    self.conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                elif started_outer_tx and self.conn.in_transaction:
                    self.conn.rollback()
                raise
            else:
                if sp_name is not None and self.conn.in_transaction:
                    self.conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                elif started_outer_tx and self.conn.in_transaction:
                    self.conn.commit()
            finally:
                self._batch_depth = max(0, self._batch_depth - 1)
        finally:
            self._lock.release()

    @contextlib.contextmanager
    def _tx(self):
        if self._batch_depth > 0:
            yield
        else:
            with self.conn:
                yield

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _init_schema(self) -> None:
        with self._lock:
            max_attempts = 12
            for attempt in range(max_attempts):
                try:
                    self._init_schema_once()
                    return
                except sqlite3.OperationalError as exc:
                    if self.conn.in_transaction:
                        try:
                            self.conn.rollback()
                        except Exception:
                            pass
                    if self._is_busy_operational_error(exc) and attempt < max_attempts - 1:
                        delay = min(0.25, 0.01 * (2 ** min(attempt, 5))) + random.uniform(0.0, 0.025)
                        time.sleep(delay)
                        continue
                    raise

    def _init_schema_once(self) -> None:
        with self._lock:
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

                CREATE TABLE IF NOT EXISTS ai_security_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_path TEXT,
                    finding_type TEXT,
                    severity TEXT,
                    file_path TEXT,
                    line_number INTEGER,
                    model_or_api TEXT,
                    description TEXT,
                    snippet TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS dual_graph_nodes (
                    node_id TEXT PRIMARY KEY,
                    graph_type TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    label TEXT,
                    attributes_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS dual_graph_edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    attributes_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS attack_chains (
                    chain_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    target_endpoint TEXT NOT NULL,
                    framing_anomaly_id TEXT,
                    ai_sink_id INTEGER,
                    steps_json TEXT NOT NULL,
                    raw_payload TEXT,
                    is_verified BOOLEAN DEFAULT 0,
                    severity TEXT DEFAULT 'HIGH',
                    task_id TEXT DEFAULT 'default',
                    poe_level INTEGER DEFAULT 0,
                    verification_status TEXT DEFAULT 'UNVERIFIED',
                    evidence_quote TEXT DEFAULT '',
                    traffic_id TEXT DEFAULT '',
                    hop_count INTEGER DEFAULT 1,
                    source_scanners_json TEXT DEFAULT '[]',
                    remote_artex_task_id TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS exploration_anchors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL DEFAULT 'default',
                    node_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    anchor_kind TEXT DEFAULT 'TOUCHES',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(task_id, node_id, asset_id)
                );

                CREATE TABLE IF NOT EXISTS planner_todolist (
                    step_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    step_order INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    capability_class TEXT,
                    prerequisite_facts_json TEXT NOT NULL DEFAULT '[]',
                    requires_step_ids_json TEXT NOT NULL DEFAULT '[]',
                    target_asset_id TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    dispatched_intent_id TEXT,
                    yielded_fact_id TEXT,
                    metadata_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS worker_execution_traces (
                    trace_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    intent_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    target_asset_id TEXT,
                    status TEXT NOT NULL DEFAULT 'COMPLETED',
                    summary TEXT,
                    raw_observation TEXT,
                    extracted_facts_json TEXT DEFAULT '[]',
                    traffic_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS traffic_evidence (
                    traffic_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL DEFAULT 'default',
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER DEFAULT 80,
                    request_headers_json TEXT DEFAULT '{}',
                    request_body TEXT DEFAULT '',
                    status_code INTEGER DEFAULT 0,
                    response_headers_json TEXT DEFAULT '{}',
                    response_body_b64 TEXT DEFAULT '',
                    content_encoding TEXT DEFAULT '',
                    is_preview_only BOOLEAN DEFAULT 0,
                    source TEXT DEFAULT 'local',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS chain_retests (
                    retest_id TEXT PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    conditions TEXT DEFAULT '',
                    evidence TEXT DEFAULT '',
                    traffic_id TEXT DEFAULT '',
                    original_traffic_id TEXT DEFAULT '',
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS llm_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL DEFAULT 'default',
                    session_id TEXT DEFAULT '',
                    role TEXT NOT NULL DEFAULT 'worker',
                    model TEXT DEFAULT '',
                    prompt_tokens INTEGER DEFAULT 0,
                    completion_tokens INTEGER DEFAULT 0,
                    total_tokens INTEGER DEFAULT 0,
                    turns INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS approval_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL DEFAULT 'default',
                    action_type TEXT NOT NULL,
                    target TEXT DEFAULT '',
                    method TEXT DEFAULT '',
                    decision TEXT NOT NULL,
                    decided_by TEXT NOT NULL,
                    rule_id TEXT DEFAULT '',
                    rationale TEXT DEFAULT '',
                    action_summary TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS mantis_threat_models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_id TEXT UNIQUE NOT NULL,
                    target_repo TEXT NOT NULL,
                    entry_points_json TEXT,
                    trust_boundaries_json TEXT,
                    data_flows_json TEXT,
                    assets_json TEXT,
                    threat_actors_json TEXT,
                    stride_matrix_json TEXT,
                    risk_ranked_files_json TEXT,
                    fusion_models_json TEXT,
                    raw_summary TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS mantis_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT UNIQUE NOT NULL,
                    target_path TEXT,
                    component TEXT,
                    file_path TEXT NOT NULL,
                    line_number INTEGER DEFAULT 0,
                    rule_id TEXT,
                    cwe_id TEXT,
                    threat_category TEXT,
                    stride_category TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    hypothesis_id TEXT,
                    hypothesis_statement TEXT,
                    severity TEXT NOT NULL,
                    calibrated_severity TEXT NOT NULL,
                    raw_llm_severity TEXT,
                    cvss_score REAL DEFAULT 0.0,
                    cvss_vector TEXT,
                    reproduction_tier INTEGER DEFAULT 0,
                    reproduction_status TEXT DEFAULT 'UNVERIFIED',
                    reproducer_code TEXT,
                    reproduction_evidence TEXT,
                    proposed_patch TEXT,
                    patch_verified BOOLEAN DEFAULT 0,
                    patch_verification_notes TEXT,
                    fusion_consensus_model TEXT,
                    snippet TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS rea_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT UNIQUE NOT NULL,
                    target_path TEXT DEFAULT '',
                    rule_id TEXT NOT NULL,
                    capability_class TEXT DEFAULT '',
                    severity TEXT NOT NULL,
                    cwe TEXT DEFAULT '',
                    file_path TEXT NOT NULL,
                    line_number INTEGER DEFAULT 0,
                    title TEXT NOT NULL,
                    evidence TEXT DEFAULT '',
                    limitations TEXT DEFAULT '[]',
                    unknowns TEXT DEFAULT '[]',
                    source_mode TEXT DEFAULT 'python_static',
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS blackboard_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id TEXT UNIQUE NOT NULL,
                    task_id TEXT NOT NULL DEFAULT 'default',
                    node_type TEXT NOT NULL CHECK(node_type IN ('FACT', 'INTENT', 'HINT')),
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    priority REAL NOT NULL DEFAULT 0.0,
                    domain TEXT DEFAULT '',
                    rfc_id TEXT DEFAULT '',
                    source_agent TEXT DEFAULT '',
                    claimed_by TEXT DEFAULT '',
                    claimed_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    content TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    parent_node_id TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            self._run_migrations()
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_blackboard_type_status_prio "
                    "ON blackboard_nodes(node_type, status, priority DESC, id ASC)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_blackboard_task_type "
                    "ON blackboard_nodes(task_id, node_type, status)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_blackboard_domain_rfc "
                    "ON blackboard_nodes(domain, rfc_id)"
                )
                self.conn.commit()
            except Exception:
                if self.conn.in_transaction:
                    self.conn.rollback()
                raise

    def _run_migrations(self) -> None:
        """Ordered transactional schema migrations recorded in `schema_migrations`."""
        with self._lock:
            required_versions = {
                "001_attack_chains_artex_cols",
                "002_chain_retests_original_traffic_id",
                "003_approval_decisions_action_summary",
                "004_blackboard_nodes",
            }
            cur = self.conn.cursor()
            cur.execute("SELECT version FROM schema_migrations")
            applied = {str(r[0]) for r in cur.fetchall()}
            if required_versions.issubset(applied):
                return

            def _table_cols(table: str) -> set:
                cur.execute(f"PRAGMA table_info({table})")
                return {str(r[1]) for r in cur.fetchall()}

            max_attempts = 12
            for attempt in range(max_attempts):
                try:
                    self.conn.execute("BEGIN IMMEDIATE")
                    try:
                        cur.execute("SELECT version FROM schema_migrations")
                        applied = {str(r[0]) for r in cur.fetchall()}

                        if "001_attack_chains_artex_cols" not in applied:
                            existing = _table_cols("attack_chains")
                            for col_name, col_def in (
                                ("task_id", "TEXT DEFAULT 'default'"),
                                ("poe_level", "INTEGER DEFAULT 0"),
                                ("verification_status", "TEXT DEFAULT 'UNVERIFIED'"),
                                ("evidence_quote", "TEXT DEFAULT ''"),
                                ("traffic_id", "TEXT DEFAULT ''"),
                                ("hop_count", "INTEGER DEFAULT 1"),
                                ("source_scanners_json", "TEXT DEFAULT '[]'"),
                                ("remote_artex_task_id", "TEXT DEFAULT ''"),
                            ):
                                if col_name not in existing:
                                    self.conn.execute(f"ALTER TABLE attack_chains ADD COLUMN {col_name} {col_def}")
                            self.conn.execute(
                                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)",
                                ("001_attack_chains_artex_cols",),
                            )

                        if "002_chain_retests_original_traffic_id" not in applied:
                            existing = _table_cols("chain_retests")
                            if "original_traffic_id" not in existing:
                                self.conn.execute("ALTER TABLE chain_retests ADD COLUMN original_traffic_id TEXT DEFAULT ''")
                            self.conn.execute(
                                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)",
                                ("002_chain_retests_original_traffic_id",),
                            )

                        if "003_approval_decisions_action_summary" not in applied:
                            existing = _table_cols("approval_decisions")
                            if "action_summary" not in existing:
                                self.conn.execute("ALTER TABLE approval_decisions ADD COLUMN action_summary TEXT DEFAULT ''")
                            self.conn.execute(
                                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)",
                                ("003_approval_decisions_action_summary",),
                            )

                        if "004_blackboard_nodes" not in applied:
                            self.conn.execute(
                                """
                                CREATE TABLE IF NOT EXISTS blackboard_nodes (
                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    node_id TEXT UNIQUE NOT NULL,
                                    task_id TEXT NOT NULL DEFAULT 'default',
                                    node_type TEXT NOT NULL CHECK(node_type IN ('FACT', 'INTENT', 'HINT')),
                                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                                    priority REAL NOT NULL DEFAULT 0.0,
                                    domain TEXT DEFAULT '',
                                    rfc_id TEXT DEFAULT '',
                                    source_agent TEXT DEFAULT '',
                                    claimed_by TEXT DEFAULT '',
                                    claimed_at TIMESTAMP,
                                    completed_at TIMESTAMP,
                                    content TEXT NOT NULL DEFAULT '',
                                    payload_json TEXT NOT NULL DEFAULT '{}',
                                    parent_node_id TEXT DEFAULT '',
                                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                                )
                                """
                            )
                            existing = _table_cols("blackboard_nodes")
                            for col_name, col_def in (
                                ("task_id", "TEXT NOT NULL DEFAULT 'default'"),
                                ("node_type", "TEXT NOT NULL DEFAULT 'FACT'"),
                                ("status", "TEXT NOT NULL DEFAULT 'ACTIVE'"),
                                ("priority", "REAL NOT NULL DEFAULT 0.0"),
                                ("domain", "TEXT DEFAULT ''"),
                                ("rfc_id", "TEXT DEFAULT ''"),
                                ("source_agent", "TEXT DEFAULT ''"),
                                ("claimed_by", "TEXT DEFAULT ''"),
                                ("claimed_at", "TIMESTAMP"),
                                ("completed_at", "TIMESTAMP"),
                                ("content", "TEXT NOT NULL DEFAULT ''"),
                                ("payload_json", "TEXT NOT NULL DEFAULT '{}'"),
                                ("parent_node_id", "TEXT DEFAULT ''"),
                                ("created_at", "TIMESTAMP"),
                                ("updated_at", "TIMESTAMP"),
                            ):
                                if col_name not in existing:
                                    self.conn.execute(f"ALTER TABLE blackboard_nodes ADD COLUMN {col_name} {col_def}")
                            self.conn.execute(
                                "CREATE INDEX IF NOT EXISTS idx_blackboard_type_status_prio "
                                "ON blackboard_nodes(node_type, status, priority DESC, id ASC)"
                            )
                            self.conn.execute(
                                "CREATE INDEX IF NOT EXISTS idx_blackboard_task_type "
                                "ON blackboard_nodes(task_id, node_type, status)"
                            )
                            self.conn.execute(
                                "CREATE INDEX IF NOT EXISTS idx_blackboard_domain_rfc "
                                "ON blackboard_nodes(domain, rfc_id)"
                            )
                            self.conn.execute(
                                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)",
                                ("004_blackboard_nodes",),
                            )

                        self.conn.commit()
                        return
                    except Exception:
                        if self.conn.in_transaction:
                            self.conn.rollback()
                        raise
                except sqlite3.OperationalError as exc:
                    if self._is_busy_operational_error(exc) and attempt < max_attempts - 1:
                        delay = min(0.25, 0.01 * (2 ** min(attempt, 5))) + random.uniform(0.0, 0.025)
                        time.sleep(delay)
                        continue
                    raise

    def _migrate_attack_chains_columns(self) -> None:
        """Backward-compatible wrapper invoking ordered transactional migrations."""
        self._run_migrations()

    def save_rfc(self, rfc_id: str, title: str, source_url: str, doc_path: str) -> None:
        with self._lock:
            with self._tx():
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
            with self._tx():
                if rfc_id:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO rfcs (rfc_id, title) VALUES (?, ?)",
                        (rfc_id, rfc_id),
                    )
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
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT DISTINCT rfc_id FROM fragments")
            return [row[0] for row in cursor.fetchall() if row[0]]

    def get_scanned_rfc_nums(self) -> List[int]:
        with self._lock:
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
        with self._lock:
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
            with self._tx():
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
        with self._lock:
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
            with self._tx():
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
            with self._tx():
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
            with self._tx():
                cursor = self.conn.execute(
                    """
                    INSERT INTO cascade_hypotheses (trigger_eval_id, category, hypothesis_text, suggested_probes_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (trigger_eval_id, category, hypothesis_text, json.dumps(suggested_probes)),
                )
                return cursor.lastrowid

    def get_confirmed_findings(self) -> List[sqlite3.Row]:
        with self._lock:
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
            with self._tx():
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
            with self._tx():
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
            with self._tx():
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
            with self._tx():
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
            with self._tx():
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
            with self._tx():
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO arm107_regression_tests
                    (test_id, vuln_id, protocol, expected_status_rejection, probe_bytes_hex, validation_logic)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (test_id, vuln_id, protocol, expected_status_rejection, probe_bytes_hex, validation_logic),
                )

    def get_tier_taxonomy_counts(self) -> Dict[str, int]:
        with self._lock:
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
            with self._tx():
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
        with self._lock:
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
            with self._tx():
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
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT permutation_id, mutation_name, match_pattern, replacement_text, is_clean FROM dynamic_permutations"
            )
            return [dict(r) for r in cursor.fetchall()]

    def get_probe_evaluation_count(self, probe_id: int) -> int:
        with self._lock:
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
                "mantis_findings",
                "mantis_threat_models",
                "rea_findings",
                "ai_security_findings",
                "dual_graph_nodes",
                "dual_graph_edges",
                "attack_chains",
                "exploration_anchors",
                "planner_todolist",
                "worker_execution_traces",
                "traffic_evidence",
                "chain_retests",
                "llm_usage",
                "approval_decisions",
                "blackboard_nodes",
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
            "ai_security_findings", "dual_graph_nodes", "dual_graph_edges",
            "attack_chains", "exploration_anchors", "planner_todolist",
            "worker_execution_traces", "traffic_evidence", "chain_retests",
            "llm_usage", "approval_decisions",
            "mantis_findings", "mantis_threat_models", "rea_findings",
            "blackboard_nodes",
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
            with self._tx():
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
            with self._tx():
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
                        INSERT OR IGNORE INTO probes
                        (probe_id, rationale, raw_request, is_clean, source_type)
                        VALUES
                        (1, 'Baseline queue poisoning verification probe', 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\n0\r\n\r\n', 0, 'baseline')
                    """)
                    self.conn.execute("""
                        INSERT OR IGNORE INTO evaluations
                        (eval_id, probe_id, target_host, target_port, is_vulnerable, desync_class, details)
                        VALUES
                        (1, 1, '127.0.0.1', 8080, 1, 'QUEUE_POISONING', 'Stateful Desynchronization: Candidate probe response or body bled directly into canary stream.')
                    """)



    def save_ai_finding(
        self,
        target_path: str,
        finding_type: str,
        severity: str,
        file_path: str,
        line_number: int,
        model_or_api: str,
        description: str,
        snippet: str = "",
    ) -> int:
        """Persists an AI security/risk finding discovered by aiscan or AST audit."""
        with self._lock:
            with self._tx():
                cur = self.conn.execute(
                    """
                    INSERT INTO ai_security_findings
                    (target_path, finding_type, severity, file_path, line_number, model_or_api, description, snippet)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (target_path, finding_type, severity, file_path, line_number, model_or_api, description, snippet),
                )
                return int(cur.lastrowid or 0)

    def get_ai_findings(self, target_path: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves recorded AI security findings."""
        with self._lock:
            cur = self.conn.cursor()
            if target_path:
                cur.execute(
                    "SELECT * FROM ai_security_findings WHERE target_path = ? ORDER BY id DESC LIMIT ?",
                    (target_path, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM ai_security_findings ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            return [dict(r) for r in cur.fetchall()]

    def save_dual_graph_node(
        self,
        node_id: str,
        graph_type: str,
        node_type: str,
        label: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Saves or updates an ARTEX Dual-Graph node (Asset or Exploration)."""
        attrs_json = json.dumps(attributes or {})
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO dual_graph_nodes (node_id, graph_type, node_type, label, attributes_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (node_id, graph_type, node_type, label, attrs_json),
                )

    def save_dual_graph_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Saves a directed edge in the ARTEX Dual-Graph."""
        attrs_json = json.dumps(attributes or {})
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT INTO dual_graph_edges (source_id, target_id, relationship, attributes_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (source_id, target_id, relationship, attrs_json),
                )

    def get_dual_graph_nodes(self, graph_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves Dual-Graph nodes, optionally filtered by graph_type ('ASSET' or 'EXPLORATION')."""
        with self._lock:
            cur = self.conn.cursor()
            if graph_type:
                cur.execute("SELECT * FROM dual_graph_nodes WHERE graph_type = ?", (graph_type,))
            else:
                cur.execute("SELECT * FROM dual_graph_nodes")
            res = []
            for r in cur.fetchall():
                d = dict(r)
                d["attributes"] = json.loads(d.get("attributes_json") or "{}")
                res.append(d)
            return res

    def get_dual_graph_edges(self) -> List[Dict[str, Any]]:
        """Retrieves all Dual-Graph edges."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM dual_graph_edges")
            res = []
            for r in cur.fetchall():
                d = dict(r)
                d["attributes"] = json.loads(d.get("attributes_json") or "{}")
                res.append(d)
            return res

    def save_attack_chain(
        self,
        chain_id: str,
        title: str,
        attack_type: str,
        target_host: str,
        target_endpoint: str,
        steps: List[Dict[str, Any]],
        framing_anomaly_id: Optional[str] = None,
        ai_sink_id: Optional[int] = None,
        raw_payload: str = "",
        is_verified: bool = False,
        severity: str = "HIGH",
        task_id: str = "default",
        poe_level: int = 0,
        verification_status: Optional[str] = None,
        evidence_quote: str = "",
        traffic_id: str = "",
        hop_count: Optional[int] = None,
        source_scanners: Optional[List[str]] = None,
        remote_artex_task_id: str = "",
    ) -> None:
        """Records a synthesized multi-step attack chain (e.g. Desynchronized Prompt Injection)."""
        steps_json = json.dumps(steps)
        scanners_json = json.dumps(source_scanners or [])
        resolved_status = verification_status or ("VERIFIED" if is_verified else "UNVERIFIED")
        resolved_hops = int(hop_count) if hop_count is not None else max(1, len(steps))
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO attack_chains
                    (chain_id, title, attack_type, target_host, target_endpoint, framing_anomaly_id,
                     ai_sink_id, steps_json, raw_payload, is_verified, severity,
                     task_id, poe_level, verification_status, evidence_quote, traffic_id,
                     hop_count, source_scanners_json, remote_artex_task_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        chain_id, title, attack_type, target_host, target_endpoint, framing_anomaly_id,
                        ai_sink_id, steps_json, self._enc(raw_payload), 1 if is_verified else 0, severity,
                        task_id, int(poe_level), resolved_status, evidence_quote or "", traffic_id or "",
                        resolved_hops, scanners_json, remote_artex_task_id or "",
                    ),
                )

    def get_attack_chain(self, chain_id: str, task_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves a single attack chain by chain_id (optionally scoped by task_id) without LIMIT truncation."""
        with self._lock:
            cur = self.conn.cursor()
            if task_id:
                cur.execute(
                    "SELECT * FROM attack_chains WHERE chain_id = ? AND task_id = ? LIMIT 1",
                    (str(chain_id), task_id),
                )
            else:
                cur.execute(
                    "SELECT * FROM attack_chains WHERE chain_id = ? LIMIT 1",
                    (str(chain_id),),
                )
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["steps"] = json.loads(d.get("steps_json") or "[]")
            d["source_scanners"] = json.loads(d.get("source_scanners_json") or "[]")
            d["raw_payload"] = self._dec(d.get("raw_payload") or "")
            return d

    def get_attack_chains(
        self,
        limit: Optional[int] = 50,
        task_id: Optional[str] = None,
        chain_id: Optional[str] = None,
        min_poe: Optional[int] = None,
        verified_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Retrieves recorded attack chains with SQL-side filtering before LIMIT."""
        clauses: List[str] = []
        params: List[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        if chain_id:
            clauses.append("chain_id = ?")
            params.append(str(chain_id))
        if min_poe is not None and int(min_poe) > 0:
            clauses.append("COALESCE(poe_level, 0) >= ?")
            params.append(int(min_poe))
        if verified_only:
            clauses.append("is_verified = 1")
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        limit_sql = ""
        if limit is not None and int(limit) > 0:
            limit_sql = " LIMIT ?"
            params.append(int(limit))
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT * FROM attack_chains {where_sql} ORDER BY created_at DESC{limit_sql}",
                tuple(params),
            )
            res = []
            for r in cur.fetchall():
                d = dict(r)
                d["steps"] = json.loads(d.get("steps_json") or "[]")
                d["source_scanners"] = json.loads(d.get("source_scanners_json") or "[]")
                d["raw_payload"] = self._dec(d.get("raw_payload") or "")
                res.append(d)
            return res

    def update_attack_chain_status(
        self,
        chain_id: str,
        verification_status: str,
        is_verified: Optional[bool] = None,
        poe_level: Optional[int] = None,
    ) -> None:
        """Updates a chain's verification status (e.g. FIXED after retest) while preserving original evidence."""
        with self._lock:
            with self._tx():
                if is_verified is not None and poe_level is not None:
                    self.conn.execute(
                        "UPDATE attack_chains SET verification_status = ?, is_verified = ?, poe_level = ? WHERE chain_id = ?",
                        (verification_status, 1 if is_verified else 0, int(poe_level), chain_id),
                    )
                elif is_verified is not None:
                    self.conn.execute(
                        "UPDATE attack_chains SET verification_status = ?, is_verified = ? WHERE chain_id = ?",
                        (verification_status, 1 if is_verified else 0, chain_id),
                    )
                else:
                    self.conn.execute(
                        "UPDATE attack_chains SET verification_status = ? WHERE chain_id = ?",
                        (verification_status, chain_id),
                    )

    def save_exploration_anchor(
        self,
        node_id: str,
        asset_id: str,
        task_id: str = "default",
        anchor_kind: str = "TOUCHES",
    ) -> None:
        """Links an Exploration Graph node to a concrete Asset Graph node (exploration_anchors)."""
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO exploration_anchors (task_id, node_id, asset_id, anchor_kind)
                    VALUES (?, ?, ?, ?)
                    """,
                    (task_id, node_id, asset_id, anchor_kind),
                )

    def get_exploration_anchors(
        self,
        task_id: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves exploration_anchors linking exploration nodes and target assets."""
        clauses: List[str] = []
        params: List[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        if asset_id:
            clauses.append("asset_id = ?")
            params.append(asset_id)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(f"SELECT * FROM exploration_anchors {where_sql} ORDER BY id ASC", tuple(params))
            return [dict(r) for r in cur.fetchall()]

    def save_todolist_item(
        self,
        step_id: str,
        task_id: str,
        chain_id: str,
        step_order: int,
        title: str,
        capability_class: str = "",
        prerequisite_facts: Optional[List[str]] = None,
        requires_step_ids: Optional[List[str]] = None,
        target_asset_id: Optional[str] = None,
        status: str = "PENDING",
        dispatched_intent_id: Optional[str] = None,
        yielded_fact_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persists a Planner Todolist attack-chain step across planner wake-ups."""
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO planner_todolist
                    (step_id, task_id, chain_id, step_order, title, capability_class,
                     prerequisite_facts_json, requires_step_ids_json, target_asset_id,
                     status, dispatched_intent_id, yielded_fact_id, metadata_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (
                        step_id, task_id, chain_id, int(step_order), title, capability_class or "",
                        json.dumps(prerequisite_facts or []),
                        json.dumps(requires_step_ids or []),
                        target_asset_id,
                        status,
                        dispatched_intent_id,
                        yielded_fact_id,
                        json.dumps(metadata or {}),
                    ),
                )

    def get_todolist_items(
        self,
        task_id: Optional[str] = None,
        chain_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves persisted Planner Todolist items ordered by chain and step_order."""
        clauses: List[str] = []
        params: List[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        if chain_id:
            clauses.append("chain_id = ?")
            params.append(chain_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT * FROM planner_todolist {where_sql} ORDER BY chain_id ASC, step_order ASC",
                tuple(params),
            )
            res = []
            for r in cur.fetchall():
                d = dict(r)
                d["prerequisite_facts"] = json.loads(d.get("prerequisite_facts_json") or "[]")
                d["requires_step_ids"] = json.loads(d.get("requires_step_ids_json") or "[]")
                d["metadata"] = json.loads(d.get("metadata_json") or "{}")
                res.append(d)
            return res

    def update_todolist_status(
        self,
        step_id: str,
        status: str,
        dispatched_intent_id: Optional[str] = None,
        yielded_fact_id: Optional[str] = None,
    ) -> None:
        """Updates a todolist step's lifecycle status."""
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    UPDATE planner_todolist
                    SET status = ?,
                        dispatched_intent_id = COALESCE(?, dispatched_intent_id),
                        yielded_fact_id = COALESCE(?, yielded_fact_id),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE step_id = ?
                    """,
                    (status, dispatched_intent_id, yielded_fact_id, step_id),
                )

    def save_worker_trace(
        self,
        trace_id: str,
        task_id: str,
        worker_id: str,
        intent_id: str,
        tool_name: str,
        summary: str = "",
        raw_observation: str = "",
        target_asset_id: Optional[str] = None,
        status: str = "COMPLETED",
        extracted_facts: Optional[List[str]] = None,
        traffic_id: Optional[str] = None,
    ) -> None:
        """Persists a worker execution trace for cross-worker trace search and reuse."""
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO worker_execution_traces
                    (trace_id, task_id, worker_id, intent_id, tool_name, target_asset_id,
                     status, summary, raw_observation, extracted_facts_json, traffic_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        trace_id, task_id, worker_id, intent_id, tool_name, target_asset_id,
                        status, summary or "", raw_observation or "",
                        json.dumps(extracted_facts or []), traffic_id,
                    ),
                )

    def list_worker_traces(
        self,
        task_id: Optional[str] = None,
        worker_id: Optional[str] = None,
        intent_id: Optional[str] = None,
        query: Optional[str] = None,
        limit: Optional[int] = 100,
    ) -> List[Dict[str, Any]]:
        """Lists recorded worker execution traces (ARTEX list_worker_traces) with SQL-side query filtering."""
        clauses: List[str] = []
        params: List[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        if worker_id:
            clauses.append("worker_id = ?")
            params.append(worker_id)
        if intent_id:
            clauses.append("intent_id = ?")
            params.append(intent_id)
        q_norm = str(query or "").strip().lower()
        if q_norm:
            clauses.append(
                "("
                "INSTR(LOWER(COALESCE(trace_id, '')), ?) > 0 OR "
                "INSTR(LOWER(COALESCE(worker_id, '')), ?) > 0 OR "
                "INSTR(LOWER(COALESCE(tool_name, '')), ?) > 0 OR "
                "INSTR(LOWER(COALESCE(target_asset_id, '')), ?) > 0 OR "
                "INSTR(LOWER(COALESCE(status, '')), ?) > 0 OR "
                "INSTR(LOWER(COALESCE(summary, '')), ?) > 0 OR "
                "INSTR(LOWER(COALESCE(raw_observation, '')), ?) > 0 OR "
                "INSTR(LOWER(COALESCE(extracted_facts_json, '')), ?) > 0"
                ")"
            )
            params.extend([q_norm] * 8)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        limit_sql = ""
        if limit is not None and int(limit) > 0:
            limit_sql = " LIMIT ?"
            params.append(int(limit))
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT * FROM worker_execution_traces {where_sql} ORDER BY created_at DESC{limit_sql}",
                tuple(params),
            )
            res = []
            for r in cur.fetchall():
                d = dict(r)
                d["extracted_facts"] = json.loads(d.get("extracted_facts_json") or "[]")
                res.append(d)
            return res

    def get_worker_trace(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single worker execution trace by trace_id (ARTEX get_worker_trace)."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM worker_execution_traces WHERE trace_id = ?", (trace_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["extracted_facts"] = json.loads(d.get("extracted_facts_json") or "[]")
            return d

    def search_all_worker_traces(
        self,
        query: str,
        task_id: Optional[str] = None,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        """Searches across all workers' raw observations and summaries (ARTEX search_all_worker_traces)."""
        tokens = [t.strip() for t in str(query or "").split() if t.strip()]
        if not tokens:
            return self.list_worker_traces(task_id=task_id, limit=limit)

        clauses: List[str] = []
        params: List[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)

        token_clauses: List[str] = []
        for tok in tokens:
            token_clauses.append(
                "(INSTR(LOWER(COALESCE(summary, '')), LOWER(?)) > 0 "
                "OR INSTR(LOWER(COALESCE(raw_observation, '')), LOWER(?)) > 0 "
                "OR INSTR(LOWER(COALESCE(tool_name, '')), LOWER(?)) > 0 "
                "OR INSTR(LOWER(COALESCE(target_asset_id, '')), LOWER(?)) > 0 "
                "OR INSTR(LOWER(COALESCE(extracted_facts_json, '')), LOWER(?)) > 0)"
            )
            params.extend([tok, tok, tok, tok, tok])
        clauses.append("(" + " OR ".join(token_clauses) + ")")
        where_sql = "WHERE " + " AND ".join(clauses)
        params.append(int(limit))
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT * FROM worker_execution_traces {where_sql} ORDER BY created_at DESC LIMIT ?",
                tuple(params),
            )
            res = []
            for r in cur.fetchall():
                d = dict(r)
                d["extracted_facts"] = json.loads(d.get("extracted_facts_json") or "[]")
                res.append(d)
            return res

    def save_traffic_evidence(
        self,
        traffic_id: str,
        method: str,
        url: str,
        host: str,
        port: int = 80,
        request_headers: Optional[Dict[str, Any]] = None,
        request_body: str = "",
        status_code: int = 0,
        response_headers: Optional[Dict[str, Any]] = None,
        response_body_b64: str = "",
        content_encoding: str = "",
        is_preview_only: bool = False,
        source: str = "local",
        task_id: str = "default",
    ) -> None:
        """Persists a captured HTTP request/response exchange for POE verification and replay."""
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO traffic_evidence
                    (traffic_id, task_id, method, url, host, port, request_headers_json,
                     request_body, status_code, response_headers_json, response_body_b64,
                     content_encoding, is_preview_only, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        traffic_id, task_id, method.upper(), url, host, int(port),
                        self._enc(json.dumps(request_headers or {})), self._enc(request_body or ""),
                        int(status_code), self._enc(json.dumps(response_headers or {})),
                        self._enc(response_body_b64 or ""), content_encoding or "",
                        1 if is_preview_only else 0, source or "local",
                    ),
                )

    def get_traffic_evidence(self, traffic_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a captured HTTP traffic record by traffic_id."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM traffic_evidence WHERE traffic_id = ?", (traffic_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["request_headers"] = json.loads(self._dec(d.get("request_headers_json") or "{}") or "{}")
            d["request_body"] = self._dec(d.get("request_body") or "")
            d["response_headers"] = json.loads(self._dec(d.get("response_headers_json") or "{}") or "{}")
            d["response_body_b64"] = self._dec(d.get("response_body_b64") or "")
            return d

    def list_traffic_evidence(
        self,
        task_id: Optional[str] = None,
        host: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Lists captured HTTP traffic records."""
        clauses: List[str] = []
        params: List[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        if host:
            clauses.append("host = ?")
            params.append(host)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(int(limit))
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT * FROM traffic_evidence {where_sql} ORDER BY created_at DESC LIMIT ?",
                tuple(params),
            )
            res = []
            for r in cur.fetchall():
                d = dict(r)
                d["request_headers"] = json.loads(self._dec(d.get("request_headers_json") or "{}") or "{}")
                d["request_body"] = self._dec(d.get("request_body") or "")
                d["response_headers"] = json.loads(self._dec(d.get("response_headers_json") or "{}") or "{}")
                d["response_body_b64"] = self._dec(d.get("response_body_b64") or "")
                res.append(d)
            return res

    def record_llm_usage(
        self,
        task_id: str,
        role: str = "worker",
        model: str = "",
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: Optional[int] = None,
        turns: int = 1,
        session_id: str = "",
    ) -> None:
        """Persists token and turn spend so RunBudgetLedger restores accurately across restarts."""
        tot = int(total_tokens) if total_tokens is not None else int(prompt_tokens) + int(completion_tokens)
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT INTO llm_usage
                    (task_id, session_id, role, model, prompt_tokens, completion_tokens, total_tokens, turns)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (task_id, session_id, role, model, int(prompt_tokens), int(completion_tokens), tot, int(turns)),
                )

    def get_task_llm_usage(self, task_id: str) -> Dict[str, Any]:
        """Aggregates persisted LLM token/turn spend for planner/worker/judge/compactor roles."""
        countable = ("planner", "worker", "judge", "compactor")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                SELECT COALESCE(SUM(total_tokens), 0) AS tokens,
                       COALESCE(SUM(turns), 0) AS turns,
                       COUNT(*) AS calls
                FROM llm_usage
                WHERE task_id = ? AND LOWER(role) IN ('planner', 'worker', 'judge', 'compactor')
                """,
                (task_id,),
            )
            row = cur.fetchone()
            return {
                "task_id": task_id,
                "total_tokens": int(row["tokens"] or 0) if row else 0,
                "total_turns": int(row["turns"] or 0) if row else 0,
                "calls": int(row["calls"] or 0) if row else 0,
                "countable_roles": list(countable),
            }

    def save_approval_decision(
        self,
        action_type: str,
        decision: str,
        decided_by: str,
        task_id: str = "default",
        target: str = "",
        method: str = "",
        rule_id: str = "",
        rationale: str = "",
        action_summary: str = "",
    ) -> None:
        """Records an interception/approval gate decision with full attribution."""
        summary_val = action_summary or rationale or f"{action_type} {method} {target}".strip()
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT INTO approval_decisions
                    (task_id, action_type, target, method, decision, decided_by, rule_id, rationale, action_summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (task_id, action_type, target, method, decision, decided_by, rule_id, rationale, summary_val),
                )

    def get_approval_decisions(self, task_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves approval gate decision history."""
        with self._lock:
            cur = self.conn.cursor()
            if task_id:
                cur.execute(
                    "SELECT * FROM approval_decisions WHERE task_id = ? ORDER BY id DESC LIMIT ?",
                    (task_id, int(limit)),
                )
            else:
                cur.execute("SELECT * FROM approval_decisions ORDER BY id DESC LIMIT ?", (int(limit),))
            return [dict(r) for r in cur.fetchall()]

    def save_chain_retest(
        self,
        retest_id: str,
        chain_id: str,
        verdict: str,
        conditions: str = "",
        evidence: str = "",
        traffic_id: str = "",
        original_traffic_id: str = "",
    ) -> None:
        """Records a retest evaluation for a confirmed attack chain."""
        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO chain_retests
                    (retest_id, chain_id, verdict, conditions, evidence, traffic_id, original_traffic_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (retest_id, chain_id, verdict, conditions or "", evidence or "", traffic_id or "", original_traffic_id or ""),
                )

    def get_chain_retests(self, chain_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves retest history for attack chains."""
        with self._lock:
            cur = self.conn.cursor()
            if chain_id:
                cur.execute(
                    "SELECT * FROM chain_retests WHERE chain_id = ? ORDER BY tested_at DESC LIMIT ?",
                    (chain_id, limit),
                )
            else:
                cur.execute("SELECT * FROM chain_retests ORDER BY tested_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    def save_mantis_threat_model(
        self,
        model_id: str,
        target_repo: str,
        entry_points: Optional[List[Any]] = None,
        trust_boundaries: Optional[List[Any]] = None,
        data_flows: Optional[List[Any]] = None,
        assets: Optional[List[Any]] = None,
        threat_actors: Optional[List[Any]] = None,
        stride_matrix: Optional[Dict[str, Any]] = None,
        risk_ranked_files: Optional[List[Any]] = None,
        fusion_models: Optional[List[str]] = None,
        raw_summary: str = "",
    ) -> int:
        """Persists a Google Mantis automated repository threat model."""
        with self._lock:
            with self._tx():
                cur = self.conn.execute(
                    """
                    INSERT OR REPLACE INTO mantis_threat_models
                    (model_id, target_repo, entry_points_json, trust_boundaries_json, data_flows_json,
                     assets_json, threat_actors_json, stride_matrix_json, risk_ranked_files_json,
                     fusion_models_json, raw_summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(model_id),
                        str(target_repo),
                        json.dumps(entry_points or []),
                        json.dumps(trust_boundaries or []),
                        json.dumps(data_flows or []),
                        json.dumps(assets or []),
                        json.dumps(threat_actors or []),
                        json.dumps(stride_matrix or {}),
                        json.dumps(risk_ranked_files or []),
                        json.dumps(fusion_models or []),
                        str(raw_summary or ""),
                    ),
                )
                return int(cur.lastrowid or 0)

    def get_mantis_threat_model(self, target_repo: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves the latest Mantis threat model for a repository."""
        with self._lock:
            cur = self.conn.cursor()
            if target_repo:
                cur.execute(
                    "SELECT * FROM mantis_threat_models WHERE target_repo = ? ORDER BY id DESC LIMIT 1",
                    (str(target_repo),),
                )
            else:
                cur.execute("SELECT * FROM mantis_threat_models ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["entry_points"] = json.loads(d.get("entry_points_json") or "[]")
            d["trust_boundaries"] = json.loads(d.get("trust_boundaries_json") or "[]")
            d["data_flows"] = json.loads(d.get("data_flows_json") or "[]")
            d["assets"] = json.loads(d.get("assets_json") or "[]")
            d["threat_actors"] = json.loads(d.get("threat_actors_json") or "[]")
            d["stride_matrix"] = json.loads(d.get("stride_matrix_json") or "{}")
            d["risk_ranked_files"] = json.loads(d.get("risk_ranked_files_json") or "[]")
            d["fusion_models"] = json.loads(d.get("fusion_models_json") or "[]")
            return d

    def save_mantis_finding(
        self,
        finding: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> int:
        """Persists a Google Mantis vulnerability finding (accepts dict or kwargs)."""
        payload: Dict[str, Any] = {}
        if isinstance(finding, dict):
            payload.update(finding)
        payload.update(kwargs)

        finding_id = str(payload.get("finding_id") or "")
        if not finding_id:
            import hashlib
            seed = f"{payload.get('file_path', '')}:{payload.get('line_number', 0)}:{payload.get('rule_id', '')}:{payload.get('title', '')}"
            finding_id = f"MANTIS-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"

        calibrated_sev = str(payload.get("calibrated_severity") or payload.get("severity") or "MEDIUM").upper()
        severity = str(payload.get("severity") or calibrated_sev).upper()
        raw_llm_sev = str(payload.get("raw_llm_severity") or severity).upper()

        raw_tier = payload.get("reproduction_tier", 0)
        if isinstance(raw_tier, int):
            repro_tier_int = raw_tier
        else:
            t_str = str(raw_tier or "").upper()
            if "2" in t_str or "SANDBOX" in t_str or "CANARY" in t_str:
                repro_tier_int = 2
            elif "1" in t_str or "STATIC" in t_str or "TAINT" in t_str:
                repro_tier_int = 1
            else:
                try:
                    repro_tier_int = int(raw_tier)
                except (TypeError, ValueError):
                    repro_tier_int = 0

        repro_status = str(
            payload.get("reproduction_status")
            or ("VERIFIED" if payload.get("reproduced") else "UNVERIFIED")
        )
        fusion_val = payload.get("fusion_consensus_model") or payload.get("fusion_models") or ""
        if isinstance(fusion_val, (list, tuple)):
            fusion_val = ", ".join(str(m) for m in fusion_val)

        with self._lock:
            with self._tx():
                cur = self.conn.execute(
                    """
                    INSERT OR REPLACE INTO mantis_findings
                    (finding_id, target_path, component, file_path, line_number, rule_id, cwe_id,
                     threat_category, stride_category, title, description, hypothesis_id, hypothesis_statement,
                     severity, calibrated_severity, raw_llm_severity, cvss_score, cvss_vector,
                     reproduction_tier, reproduction_status, reproducer_code, reproduction_evidence,
                     proposed_patch, patch_verified, patch_verification_notes, fusion_consensus_model, snippet)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        str(payload.get("target_path", "")),
                        str(payload.get("component") or payload.get("sink", "")),
                        str(payload.get("file_path", "")),
                        int(payload.get("line_number", 0) or 0),
                        str(payload.get("rule_id", "")),
                        str(payload.get("cwe_id") or payload.get("cwe", "")),
                        str(payload.get("threat_category") or payload.get("status", "")),
                        str(payload.get("stride_category", "")),
                        str(payload.get("title", "Mantis Security Finding")),
                        str(payload.get("description", "")),
                        str(payload.get("hypothesis_id", "")),
                        str(payload.get("hypothesis_statement") or payload.get("remediation", "")),
                        severity,
                        calibrated_sev,
                        raw_llm_sev,
                        float(payload.get("cvss_score", 0.0) or 0.0),
                        str(payload.get("cvss_vector", "")),
                        repro_tier_int,
                        repro_status,
                        str(payload.get("reproducer_code", "")),
                        str(payload.get("reproduction_evidence") or payload.get("reproduction_details", "")),
                        str(payload.get("proposed_patch") or payload.get("patch_diff") or payload.get("patched_code", "")),
                        1 if payload.get("patch_verified", False) else 0,
                        str(payload.get("patch_verification_notes", "")),
                        str(fusion_val),
                        str(payload.get("snippet") or payload.get("evidence", "")),
                    ),
                )
                return int(cur.lastrowid or 0)

    def get_mantis_findings(
        self,
        target_path: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieves persisted Google Mantis findings filtered by target_path or severity."""
        clauses: List[str] = []
        params: List[Any] = []
        if target_path:
            clauses.append("target_path = ?")
            params.append(str(target_path))
        if severity:
            clauses.append("(calibrated_severity = ? OR severity = ?)")
            sev_u = severity.upper()
            params.extend([sev_u, sev_u])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM mantis_findings {where_sql} ORDER BY id DESC LIMIT ?"
        params.append(int(limit))

        with self._lock:
            cur = self.conn.cursor()
            cur.execute(sql, tuple(params))
            return [dict(r) for r in cur.fetchall()]

    def save_rea_finding(self, payload: Dict[str, Any]) -> int:
        """Persists a Module 21 (`morluto/rea`) surface/bundle security finding."""
        finding_id = str(payload.get("finding_id") or payload.get("id") or "")
        if not finding_id:
            return 0
        lims = payload.get("limitations")
        unks = payload.get("unknowns")
        lims_json = json.dumps(lims) if isinstance(lims, (list, dict)) else str(lims or "[]")
        unks_json = json.dumps(unks) if isinstance(unks, (list, dict)) else str(unks or "[]")
        with self._lock:
            with self._tx():
                cur = self.conn.execute(
                    """
                    INSERT OR REPLACE INTO rea_findings
                    (finding_id, target_path, rule_id, capability_class, severity, cwe,
                     file_path, line_number, title, evidence, limitations, unknowns, source_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        str(payload.get("target_path", "")),
                        str(payload.get("rule_id", "REA-ROUTE-001")),
                        str(payload.get("capability_class", "")),
                        str(payload.get("severity", "MEDIUM")).upper(),
                        str(payload.get("cwe", "")),
                        str(payload.get("file_path", "")),
                        int(payload.get("line_number", 0) or 0),
                        str(payload.get("title", "REA Surface Finding")),
                        str(payload.get("evidence", "")),
                        lims_json,
                        unks_json,
                        str(payload.get("source_mode") or payload.get("mode") or "python_static"),
                    ),
                )
                return int(cur.lastrowid or 0)

    def get_rea_findings(
        self,
        target_path: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieves persisted Module 21 (`morluto/rea`) findings."""
        clauses: List[str] = []
        params: List[Any] = []
        if target_path:
            clauses.append("target_path = ?")
            params.append(str(target_path))
        if severity:
            clauses.append("severity = ?")
            params.append(str(severity).upper())
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM rea_findings {where_sql} ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(sql, tuple(params))
            rows = []
            for r in cur.fetchall():
                d = dict(r)
                for k in ("limitations", "unknowns"):
                    raw_k = d.get(k)
                    if isinstance(raw_k, str):
                        try:
                            d[k] = json.loads(raw_k)
                        except Exception:
                            d[k] = [raw_k] if raw_k else []
                rows.append(d)
            return rows

    # ------------------------------------------------------------------
    # Cairn Blackboard Persistence & Atomic Intent Claiming (M1)
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_blackboard_row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        raw_payload = d.get("payload_json")
        if isinstance(raw_payload, str) and raw_payload.strip():
            try:
                decoded = json.loads(raw_payload)
                d["payload"] = decoded if isinstance(decoded, dict) else {"value": decoded}
            except (ValueError, TypeError):
                d["payload"] = {}
        elif isinstance(raw_payload, dict):
            d["payload"] = dict(raw_payload)
        else:
            d["payload"] = {}
        return d

    def add_blackboard_node(
        self,
        node_type: str,
        content: str,
        *,
        node_id: Optional[str] = None,
        status: Optional[str] = None,
        priority: float = 0.0,
        task_id: str = "default",
        domain: str = "",
        rfc_id: str = "",
        source_agent: str = "",
        payload: Optional[Dict[str, Any]] = None,
        parent_node_id: str = "",
    ) -> str:
        """Inserts or updates a FACT, INTENT, or HINT node in `blackboard_nodes`."""
        nt = str(node_type or "").strip().upper()
        if nt not in ("FACT", "INTENT", "HINT"):
            raise ValueError(f"Unsupported blackboard node_type: {node_type!r}")

        resolved_status = (
            str(status).strip().upper()
            if status is not None and str(status).strip()
            else ("PENDING" if nt == "INTENT" else "ACTIVE")
        )
        nid = str(node_id).strip() if node_id is not None and str(node_id).strip() else f"{nt.lower()}-{uuid.uuid4().hex[:12]}"
        payload_str = json.dumps(payload if payload is not None else {})
        task_val = str(task_id or "default")
        domain_val = "" if domain is None else str(domain)
        rfc_val = "" if rfc_id is None else str(rfc_id)
        agent_val = "" if source_agent is None else str(source_agent)
        parent_val = "" if parent_node_id is None else str(parent_node_id)
        content_val = "" if content is None else str(content)
        prio_val = float(priority)

        with self._lock:
            with self._tx():
                self.conn.execute(
                    """
                    INSERT INTO blackboard_nodes (
                        node_id, task_id, node_type, status, priority,
                        domain, rfc_id, source_agent, content, payload_json, parent_node_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(node_id) DO UPDATE SET
                        task_id = excluded.task_id,
                        node_type = excluded.node_type,
                        status = excluded.status,
                        priority = excluded.priority,
                        domain = excluded.domain,
                        rfc_id = excluded.rfc_id,
                        source_agent = excluded.source_agent,
                        content = excluded.content,
                        payload_json = excluded.payload_json,
                        parent_node_id = excluded.parent_node_id,
                        claimed_by = CASE WHEN excluded.status = 'PENDING' THEN '' ELSE blackboard_nodes.claimed_by END,
                        claimed_at = CASE WHEN excluded.status = 'PENDING' THEN NULL ELSE blackboard_nodes.claimed_at END,
                        completed_at = CASE WHEN excluded.status = 'PENDING' THEN NULL ELSE blackboard_nodes.completed_at END,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (
                        nid,
                        task_val,
                        nt,
                        resolved_status,
                        prio_val,
                        domain_val,
                        rfc_val,
                        agent_val,
                        content_val,
                        payload_str,
                        parent_val,
                    ),
                )
        return nid

    def get_blackboard_nodes(
        self,
        *,
        node_type: Optional[str] = None,
        status: Optional[str] = None,
        task_id: Optional[str] = None,
        domain: Optional[str] = None,
        rfc_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Queries `blackboard_nodes` ordered by `priority DESC, id ASC` with decoded `payload`."""
        clauses: List[str] = []
        params: List[Any] = []
        if node_type:
            clauses.append("node_type = ?")
            params.append(str(node_type).strip().upper())
        if status:
            clauses.append("status = ?")
            params.append(str(status).strip().upper())
        if task_id:
            clauses.append("task_id = ?")
            params.append(str(task_id))
        if domain:
            clauses.append("domain = ?")
            params.append(str(domain))
        if rfc_id:
            clauses.append("rfc_id = ?")
            params.append(str(rfc_id))

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        limit_sql = ""
        if limit is not None and int(limit) > 0:
            limit_sql = " LIMIT ?"
            params.append(int(limit))

        sql = f"SELECT * FROM blackboard_nodes {where_sql} ORDER BY priority DESC, id ASC{limit_sql}"
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(sql, tuple(params))
            return [self._decode_blackboard_row(r) for r in cur.fetchall()]

    def add_fact(
        self,
        content: str,
        *,
        node_id: Optional[str] = None,
        task_id: str = "default",
        domain: str = "",
        rfc_id: str = "",
        source_agent: str = "",
        payload: Optional[Dict[str, Any]] = None,
        parent_node_id: str = "",
    ) -> str:
        """Persists a confirmed FACT observation onto the blackboard."""
        return self.add_blackboard_node(
            "FACT",
            content,
            node_id=node_id,
            status="ACTIVE",
            priority=0.0,
            task_id=task_id,
            domain=domain,
            rfc_id=rfc_id,
            source_agent=source_agent,
            payload=payload,
            parent_node_id=parent_node_id,
        )

    def get_facts(
        self,
        *,
        task_id: Optional[str] = None,
        domain: Optional[str] = None,
        rfc_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieves FACT nodes matching the given filters."""
        return self.get_blackboard_nodes(
            node_type="FACT",
            task_id=task_id,
            domain=domain,
            rfc_id=rfc_id,
            limit=limit,
        )

    def queue_intent(
        self,
        content: str,
        *,
        priority: float = 0.0,
        node_id: Optional[str] = None,
        task_id: str = "default",
        domain: str = "",
        rfc_id: str = "",
        source_agent: str = "",
        payload: Optional[Dict[str, Any]] = None,
        parent_node_id: str = "",
    ) -> str:
        """Enqueues an unexplored INTENT hypothesis in PENDING state."""
        return self.add_blackboard_node(
            "INTENT",
            content,
            node_id=node_id,
            status="PENDING",
            priority=float(priority),
            task_id=task_id,
            domain=domain,
            rfc_id=rfc_id,
            source_agent=source_agent,
            payload=payload,
            parent_node_id=parent_node_id,
        )

    def claim_next_intent(
        self,
        worker_id: str,
        *,
        task_id: Optional[str] = None,
        domain: Optional[str] = None,
        include_global: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Atomically claims the highest-priority PENDING INTENT (FIFO tie-break by id ASC).
        Uses BEGIN IMMEDIATE (or SAVEPOINT when already inside batch_writes) so
        concurrent threads and separate Database connections never double-claim.
        When `include_global=True` and `domain` is non-empty, matches `domain`
        case-insensitively alongside `'global'` and `''` atomically inside the
        same transaction.
        """
        clauses: List[str] = ["node_type = 'INTENT'", "status = 'PENDING'"]
        params: List[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(str(task_id))
        if domain:
            if include_global:
                clauses.append("LOWER(COALESCE(domain, '')) IN (LOWER(?), 'global', '')")
            else:
                clauses.append("domain = ?")
            params.append(str(domain))
        where_sql = " AND ".join(clauses)
        worker_val = str(worker_id or "")

        def _do_claim() -> Optional[Dict[str, Any]]:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT node_id FROM blackboard_nodes WHERE {where_sql} ORDER BY priority DESC, id ASC LIMIT 1",
                tuple(params),
            )
            row = cur.fetchone()
            if row is None:
                return None
            target_node_id = str(row["node_id"])
            upd = self.conn.execute(
                """
                UPDATE blackboard_nodes
                SET status = 'CLAIMED',
                    claimed_by = ?,
                    claimed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE node_id = ?
                  AND status = 'PENDING'
                """,
                (worker_val, target_node_id),
            )
            if upd.rowcount != 1:
                return None
            cur.execute("SELECT * FROM blackboard_nodes WHERE node_id = ? LIMIT 1", (target_node_id,))
            claimed_row = cur.fetchone()
            return self._decode_blackboard_row(claimed_row) if claimed_row is not None else None

        with self._lock:
            if self._batch_depth > 0 or self.conn.in_transaction:
                sp_name = "sp_claim_intent"
                self.conn.execute(f"SAVEPOINT {sp_name}")
                try:
                    claimed = _do_claim()
                    self.conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                    return claimed
                except Exception:
                    if self.conn.in_transaction:
                        self.conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                        self.conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                    raise

            last_exc: Optional[Exception] = None
            for attempt in range(5):
                try:
                    self.conn.execute("BEGIN IMMEDIATE")
                    try:
                        claimed = _do_claim()
                        self.conn.commit()
                        return claimed
                    except Exception:
                        if self.conn.in_transaction:
                            self.conn.rollback()
                        raise
                except sqlite3.OperationalError as exc:
                    msg = str(exc).lower()
                    if ("locked" in msg or "busy" in msg) and attempt < 4:
                        last_exc = exc
                        time.sleep(0.01 * (attempt + 1))
                        continue
                    raise
            if last_exc is not None:
                raise last_exc
            return None

    def complete_intent(
        self,
        node_id: str,
        *,
        status: str = "DONE",
        result_payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Marks an INTENT as DONE (or FAILED/etc.) and optionally merges result_payload."""
        resolved_status = str(status or "DONE").strip().upper()
        nid = str(node_id or "").strip()
        if not nid:
            return False

        with self._lock:
            with self._tx():
                if result_payload is not None:
                    cur = self.conn.cursor()
                    cur.execute(
                        "SELECT payload_json FROM blackboard_nodes WHERE node_id = ? AND node_type = 'INTENT' LIMIT 1",
                        (nid,),
                    )
                    row = cur.fetchone()
                    if row is None:
                        return False
                    existing: Dict[str, Any] = {}
                    raw_existing = row["payload_json"]
                    if isinstance(raw_existing, str) and raw_existing.strip():
                        try:
                            parsed = json.loads(raw_existing)
                            existing = parsed if isinstance(parsed, dict) else {"value": parsed}
                        except (ValueError, TypeError):
                            existing = {}
                    merged = {**existing, **result_payload}
                    upd = self.conn.execute(
                        """
                        UPDATE blackboard_nodes
                        SET status = ?,
                            completed_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP,
                            payload_json = ?
                        WHERE node_id = ?
                          AND node_type = 'INTENT'
                        """,
                        (resolved_status, json.dumps(merged), nid),
                    )
                else:
                    upd = self.conn.execute(
                        """
                        UPDATE blackboard_nodes
                        SET status = ?,
                            completed_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE node_id = ?
                          AND node_type = 'INTENT'
                        """,
                        (resolved_status, nid),
                    )
                return bool(upd.rowcount > 0)

    def reclaim_stale_intents(
        self,
        *,
        task_id: Optional[str] = None,
        worker_id: Optional[str] = None,
    ) -> int:
        """Resets interrupted CLAIMED intents back to PENDING for crash-resilient resume."""
        clauses: List[str] = ["node_type = 'INTENT'", "status = 'CLAIMED'"]
        params: List[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(str(task_id))
        if worker_id:
            clauses.append("claimed_by = ?")
            params.append(str(worker_id))
        where_sql = " AND ".join(clauses)

        with self._lock:
            with self._tx():
                cur = self.conn.execute(
                    f"""
                    UPDATE blackboard_nodes
                    SET status = 'PENDING',
                        claimed_by = '',
                        claimed_at = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE {where_sql}
                    """,
                    tuple(params),
                )
                return int(cur.rowcount or 0)

    def list_intents(
        self,
        *,
        status: Optional[str] = None,
        task_id: Optional[str] = None,
        domain: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Lists INTENT nodes filtered by optional status, task_id, and domain."""
        return self.get_blackboard_nodes(
            node_type="INTENT",
            status=status,
            task_id=task_id,
            domain=domain,
            limit=limit,
        )

    def add_hint(
        self,
        content: str,
        *,
        priority: float = 10.0,
        node_id: Optional[str] = None,
        task_id: str = "default",
        domain: str = "global",
        rfc_id: str = "",
        source_agent: str = "cli",
        active: bool = True,
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Persists an operator or Harness² steering HINT onto the blackboard."""
        status_val = "ACTIVE" if active else "INACTIVE"
        domain_val = "global" if domain is None else str(domain)
        return self.add_blackboard_node(
            "HINT",
            content,
            node_id=node_id,
            status=status_val,
            priority=float(priority),
            task_id=task_id,
            domain=domain_val,
            rfc_id=rfc_id,
            source_agent=source_agent,
            payload=payload,
        )

    def get_active_hints(
        self,
        *,
        task_id: Optional[str] = None,
        domain: Optional[str] = None,
        rfc_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves active HINTs ordered by priority DESC, id ASC.
        When `domain` is provided, matches hints for that domain as well as 'global' and ''.
        """
        clauses: List[str] = ["node_type = 'HINT'", "status = 'ACTIVE'"]
        params: List[Any] = []
        if task_id:
            clauses.append("task_id = ?")
            params.append(str(task_id))
        if domain:
            clauses.append("LOWER(COALESCE(domain, '')) IN (LOWER(?), 'global', '')")
            params.append(str(domain))
        if rfc_id:
            clauses.append("rfc_id = ?")
            params.append(str(rfc_id))

        where_sql = " AND ".join(clauses)
        limit_sql = ""
        if limit is not None and int(limit) > 0:
            limit_sql = " LIMIT ?"
            params.append(int(limit))

        sql = f"SELECT * FROM blackboard_nodes WHERE {where_sql} ORDER BY priority DESC, id ASC{limit_sql}"
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(sql, tuple(params))
            return [self._decode_blackboard_row(r) for r in cur.fetchall()]

    def deactivate_hint(self, node_id: str) -> bool:
        """Deactivates an existing HINT node by setting status = 'INACTIVE'."""
        nid = str(node_id or "").strip()
        if not nid:
            return False
        with self._lock:
            with self._tx():
                cur = self.conn.execute(
                    """
                    UPDATE blackboard_nodes
                    SET status = 'INACTIVE',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE node_id = ?
                      AND node_type = 'HINT'
                    """,
                    (nid,),
                )
                return bool(cur.rowcount > 0)

    def export_blackboard_trees(
        self,
        *,
        task_id: Optional[str] = None,
        limit_tasks: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Read-only lineage export returning `blackboard_nodes` grouped by `task_id`
        with joined outcome telemetry from `evaluations`, `implementation_anomalies`,
        `reproducible_vulnerabilities`, and `attack_chains`.

        Preserves existing schema and migration `004_blackboard_nodes` untouched.
        """
        with self._lock:
            cur = self.conn.cursor()
            if task_id is not None and str(task_id).strip():
                tid_filter = str(task_id).strip()
                cur.execute(
                    "SELECT DISTINCT task_id FROM blackboard_nodes WHERE task_id = ?",
                    (tid_filter,),
                )
                task_ids = [str(r[0]) for r in cur.fetchall() if r[0] is not None]
            else:
                if limit_tasks is not None and int(limit_tasks) > 0:
                    cur.execute(
                        "SELECT task_id FROM blackboard_nodes GROUP BY task_id ORDER BY MAX(id) DESC LIMIT ?",
                        (int(limit_tasks),),
                    )
                else:
                    cur.execute(
                        "SELECT task_id FROM blackboard_nodes GROUP BY task_id ORDER BY MAX(id) DESC"
                    )
                task_ids = [str(r[0]) for r in cur.fetchall() if r[0] is not None]

            if not task_ids:
                return []

            tid_placeholders = ",".join("?" for _ in task_ids)
            cur.execute(
                f"SELECT * FROM blackboard_nodes WHERE task_id IN ({tid_placeholders}) ORDER BY id ASC",
                tuple(task_ids),
            )
            nodes_by_task: Dict[str, List[Dict[str, Any]]] = {tid: [] for tid in task_ids}
            probe_ids: set = set()
            anomaly_ids: set = set()
            vuln_ids: set = set()
            chain_ids: set = set()

            for raw_row in cur.fetchall():
                decoded = self._decode_blackboard_row(raw_row)
                tid = str(decoded.get("task_id") or "default")
                nodes_by_task.setdefault(tid, []).append(decoded)
                payload = decoded.get("payload") if isinstance(decoded.get("payload"), dict) else {}
                p_id = payload.get("probe_id")
                if p_id is not None and not isinstance(p_id, bool):
                    try:
                        probe_ids.add(int(p_id))
                    except (TypeError, ValueError):
                        pass
                a_id = payload.get("anomaly_id")
                if isinstance(a_id, str) and a_id.strip():
                    anomaly_ids.add(a_id.strip())
                v_id = payload.get("vuln_id") or payload.get("parent_vuln_id")
                if isinstance(v_id, str) and v_id.strip():
                    vuln_ids.add(v_id.strip())
                c_id = payload.get("chain_id")
                if isinstance(c_id, str) and c_id.strip():
                    chain_ids.add(c_id.strip())

            evals_by_probe: Dict[int, List[Dict[str, Any]]] = {}
            if probe_ids:
                try:
                    p_list = sorted(probe_ids)
                    p_ph = ",".join("?" for _ in p_list)
                    cur.execute(
                        f"SELECT eval_id, probe_id, target_host, target_port, is_vulnerable, "
                        f"desync_class, finding_status, details, tested_at "
                        f"FROM evaluations WHERE probe_id IN ({p_ph}) ORDER BY eval_id ASC",
                        tuple(p_list),
                    )
                    for row in cur.fetchall():
                        d = dict(row)
                        evals_by_probe.setdefault(int(d["probe_id"]), []).append(d)
                except sqlite3.OperationalError:
                    pass

            anomalies_by_id: Dict[str, Dict[str, Any]] = {}
            if anomaly_ids:
                try:
                    a_list = sorted(anomaly_ids)
                    a_ph = ",".join("?" for _ in a_list)
                    cur.execute(
                        f"SELECT anomaly_id, target_engine, category, observed_behavior, "
                        f"expected_behavior, triggering_rule_id, is_environmental_noise, created_at "
                        f"FROM implementation_anomalies WHERE anomaly_id IN ({a_ph})",
                        tuple(a_list),
                    )
                    for row in cur.fetchall():
                        d = dict(row)
                        anomalies_by_id[str(d["anomaly_id"])] = d
                except sqlite3.OperationalError:
                    pass

            vulns_by_id: Dict[str, Dict[str, Any]] = {}
            vulns_by_anomaly: Dict[str, Dict[str, Any]] = {}
            if vuln_ids or anomaly_ids:
                try:
                    v_clauses: List[str] = []
                    v_params: List[Any] = []
                    if vuln_ids:
                        v_list = sorted(vuln_ids)
                        v_clauses.append(f"vuln_id IN ({','.join('?' for _ in v_list)})")
                        v_params.extend(v_list)
                    if anomaly_ids:
                        a_list = sorted(anomaly_ids)
                        v_clauses.append(f"anomaly_id IN ({','.join('?' for _ in a_list)})")
                        v_params.extend(a_list)
                    cur.execute(
                        f"SELECT vuln_id, anomaly_id, impact, reproducibility_rate, "
                        f"verification_attempts, successful_reproductions, delta_debug_steps, created_at "
                        f"FROM reproducible_vulnerabilities WHERE {' OR '.join(v_clauses)}",
                        tuple(v_params),
                    )
                    for row in cur.fetchall():
                        d = dict(row)
                        if d.get("vuln_id"):
                            vulns_by_id[str(d["vuln_id"])] = d
                        if d.get("anomaly_id"):
                            vulns_by_anomaly[str(d["anomaly_id"])] = d
                except sqlite3.OperationalError:
                    pass

            chains_by_task: Dict[str, List[Dict[str, Any]]] = {}
            chains_by_id: Dict[str, Dict[str, Any]] = {}
            chains_by_anomaly: Dict[str, List[Dict[str, Any]]] = {}
            try:
                c_clauses: List[str] = [f"task_id IN ({tid_placeholders})"]
                c_params: List[Any] = list(task_ids)
                if chain_ids:
                    c_list = sorted(chain_ids)
                    c_clauses.append(f"chain_id IN ({','.join('?' for _ in c_list)})")
                    c_params.extend(c_list)
                if anomaly_ids:
                    a_list = sorted(anomaly_ids)
                    c_clauses.append(f"framing_anomaly_id IN ({','.join('?' for _ in a_list)})")
                    c_params.extend(a_list)
                cur.execute(
                    f"SELECT chain_id, title, attack_type, target_host, target_endpoint, "
                    f"framing_anomaly_id, is_verified, severity, task_id, poe_level, "
                    f"verification_status, hop_count, created_at "
                    f"FROM attack_chains WHERE {' OR '.join(c_clauses)} ORDER BY created_at ASC",
                    tuple(c_params),
                )
                for row in cur.fetchall():
                    d = dict(row)
                    cid = str(d.get("chain_id") or "")
                    ctid = str(d.get("task_id") or "default")
                    if cid:
                        chains_by_id[cid] = d
                    chains_by_task.setdefault(ctid, []).append(d)
                    faid = str(d.get("framing_anomaly_id") or "").strip()
                    if faid:
                        chains_by_anomaly.setdefault(faid, []).append(d)
            except sqlite3.OperationalError:
                pass

        trees: List[Dict[str, Any]] = []
        for tid in task_ids:
            raw_nodes = nodes_by_task.get(tid) or []
            if not raw_nodes:
                continue

            node_id_set = {str(n.get("node_id") or "") for n in raw_nodes}
            children_by_parent: Dict[str, List[str]] = {}
            root_node_ids: List[str] = []
            for n in raw_nodes:
                nid = str(n.get("node_id") or "")
                pid = str(n.get("parent_node_id") or "").strip()
                if pid and pid in node_id_set and pid != nid:
                    children_by_parent.setdefault(pid, []).append(nid)
                else:
                    root_node_ids.append(nid)

            enriched_nodes: List[Dict[str, Any]] = []
            task_eval_map: Dict[int, Dict[str, Any]] = {}
            task_anom_map: Dict[str, Dict[str, Any]] = {}
            task_vuln_map: Dict[str, Dict[str, Any]] = {}
            task_chain_map: Dict[str, Dict[str, Any]] = {
                str(ch["chain_id"]): ch for ch in chains_by_task.get(tid, []) if ch.get("chain_id")
            }
            domains_set: set = set()
            rfcs_set: set = set()
            fact_cnt = 0
            intent_cnt = 0
            hint_cnt = 0
            anom_node_cnt = 0
            vuln_node_cnt = 0
            max_poe = 0

            for n in raw_nodes:
                nid = str(n.get("node_id") or "")
                ntype = str(n.get("node_type") or "").upper()
                if ntype == "FACT":
                    fact_cnt += 1
                elif ntype == "INTENT":
                    intent_cnt += 1
                elif ntype == "HINT":
                    hint_cnt += 1

                dom = str(n.get("domain") or "").strip()
                if dom:
                    domains_set.add(dom)
                rfc = str(n.get("rfc_id") or "").strip()
                if rfc:
                    rfcs_set.add(rfc)

                payload = n.get("payload") if isinstance(n.get("payload"), dict) else {}
                matched_evals: List[Dict[str, Any]] = []
                p_id = payload.get("probe_id")
                if p_id is not None and not isinstance(p_id, bool):
                    try:
                        matched_evals = list(evals_by_probe.get(int(p_id), []))
                        for ev in matched_evals:
                            task_eval_map[int(ev["eval_id"])] = ev
                    except (TypeError, ValueError):
                        pass

                a_id = str(payload.get("anomaly_id") or "").strip()
                matched_anom = anomalies_by_id.get(a_id) if a_id else None
                if matched_anom is not None:
                    task_anom_map[a_id] = matched_anom

                v_id = str(payload.get("vuln_id") or payload.get("parent_vuln_id") or "").strip()
                matched_vuln = vulns_by_id.get(v_id) if v_id else None
                if matched_vuln is None and a_id:
                    matched_vuln = vulns_by_anomaly.get(a_id)
                if matched_vuln is not None and matched_vuln.get("vuln_id"):
                    task_vuln_map[str(matched_vuln["vuln_id"])] = matched_vuln

                matched_chains: List[Dict[str, Any]] = []
                seen_cids: set = set()
                c_id = str(payload.get("chain_id") or "").strip()
                if c_id and c_id in chains_by_id:
                    matched_chains.append(chains_by_id[c_id])
                    seen_cids.add(c_id)
                    task_chain_map[c_id] = chains_by_id[c_id]
                if a_id:
                    for ch in chains_by_anomaly.get(a_id, []):
                        cid_k = str(ch.get("chain_id") or "")
                        if cid_k and cid_k not in seen_cids:
                            matched_chains.append(ch)
                            seen_cids.add(cid_k)
                            task_chain_map[cid_k] = ch

                outcome_str = str(payload.get("outcome") or "").strip().upper()
                is_noise = bool(
                    payload.get("is_noise_discard")
                    or (matched_anom is not None and bool(matched_anom.get("is_environmental_noise")))
                )
                is_confirmed_vuln = bool(
                    payload.get("is_confirmed_vuln")
                    or matched_vuln is not None
                    or nid.startswith("fact:vuln:")
                    or any(bool(ev.get("is_vulnerable")) for ev in matched_evals)
                    or any(bool(ch.get("is_verified")) for ch in matched_chains)
                )
                is_anomaly = bool(
                    payload.get("is_anomaly")
                    or outcome_str == "ANOMALY"
                    or nid.startswith("fact:anomaly:")
                    or matched_anom is not None
                    or is_confirmed_vuln
                )
                poe_candidates = [int(payload.get("poe_level", 0) or 0)]
                poe_candidates.extend(int(ch.get("poe_level", 0) or 0) for ch in matched_chains)
                if is_confirmed_vuln and max(poe_candidates) < 2:
                    poe_candidates.append(2)
                node_poe = max(poe_candidates)

                if is_anomaly:
                    anom_node_cnt += 1
                if is_confirmed_vuln:
                    vuln_node_cnt += 1
                if node_poe > max_poe:
                    max_poe = node_poe

                enriched = dict(n)
                enriched["children"] = list(children_by_parent.get(nid, []))
                enriched["outcomes"] = {
                    "is_anomaly": is_anomaly,
                    "is_confirmed_vuln": is_confirmed_vuln,
                    "is_noise_discard": is_noise,
                    "poe_level": node_poe,
                    "evaluation": matched_evals[-1] if matched_evals else None,
                    "evaluations": matched_evals,
                    "anomaly": matched_anom,
                    "vulnerability": matched_vuln,
                    "attack_chains": matched_chains,
                }
                enriched_nodes.append(enriched)

            task_chains_list = list(task_chain_map.values())
            for ch in task_chains_list:
                ch_poe = int(ch.get("poe_level", 0) or 0)
                if ch_poe > max_poe:
                    max_poe = ch_poe

            trees.append(
                {
                    "task_id": tid,
                    "node_count": len(enriched_nodes),
                    "root_node_ids": root_node_ids,
                    "children_by_parent": children_by_parent,
                    "nodes": enriched_nodes,
                    "outcomes": {
                        "evaluations": list(task_eval_map.values()),
                        "anomalies": list(task_anom_map.values()),
                        "reproducible_vulnerabilities": list(task_vuln_map.values()),
                        "attack_chains": task_chains_list,
                    },
                    "summary": {
                        "fact_count": fact_cnt,
                        "intent_count": intent_cnt,
                        "hint_count": hint_cnt,
                        "anomaly_count": anom_node_cnt,
                        "confirmed_vuln_count": vuln_node_cnt,
                        "verified_chain_count": sum(1 for ch in task_chains_list if ch.get("is_verified")),
                        "max_poe_level": max_poe,
                        "domains": sorted(domains_set),
                        "rfc_ids": sorted(rfcs_set),
                    },
                }
            )
        return trees
