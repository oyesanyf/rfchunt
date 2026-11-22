"""
Module 13: Protocol World Model (Dream-RSI Offline Replay Simulator).

Implements the in-memory environment simulator for Dream-RSI (Recursive Self-Improvement
through Evolving Worlds). Reconstructs target protocol behavior, state transitions,
framing characteristics, and anomaly triggers from accumulated research history
without making live network requests.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from engine.dream_replay_pool import ReplayTreePool

BACKEND_RECORDED_REPLAY = "recorded_blackboard_replay"
BACKEND_LATENT_JEPA = "latent_jepa_world_model"
BACKEND_SYNTHETIC_FALLBACK = "synthetic_heuristic_fallback"


@dataclass
class SimulatedResponse:
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    raw_response: bytes = b""
    latency: float = 0.05
    is_connection_closed: bool = False
    framing_type: str = "content-length"
    is_anomaly: bool = False
    anomaly_category: Optional[str] = None
    is_vulnerability: bool = False
    confidence: float = 1.0
    details: str = "Simulated from world model"
    backend_label: str = BACKEND_SYNTHETIC_FALLBACK


@dataclass
class WorldModelTrajectory:
    trajectory_id: str
    target_host: str
    target_port: int
    probe_bytes: bytes
    response_status: int
    framing_type: str
    is_anomaly: bool
    anomaly_category: Optional[str]
    is_vulnerability: bool
    desync_vectors: List[str] = field(default_factory=list)
    timestamp: float = 0.0


class ProtocolWorldModel:
    """
    Stateful protocol replay simulator. Converts empirical execution history
    into an off-policy Markov Decision Process (MDP) and recorded discovery
    tree replay pool for Dream-RSI exploration.
    """

    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 5006):
        self.target_host = target_host
        self.target_port = target_port
        self.exact_cache: Dict[str, SimulatedResponse] = {}
        self.trajectories: List[WorldModelTrajectory] = []
        self.known_anomaly_patterns: Set[str] = set()
        self.known_mutator_rewards: Dict[str, List[float]] = {}
        self.server_signature: str = "generic"
        self.replay_pool: ReplayTreePool = ReplayTreePool()
        self.jepa_model: Optional[Any] = None
        self.last_ingested_trees: int = 0

    @property
    def has_recorded_replay_trees(self) -> bool:
        return len(self.replay_pool) > 0

    @property
    def backend_label(self) -> str:
        """Explicit provenance label distinguishing recorded replay, calibrated JEPA, and cold-start fallback."""
        if len(self.replay_pool) > 0:
            return BACKEND_RECORDED_REPLAY
        if self.jepa_model is not None and bool(getattr(self.jepa_model, "calibrated", False)):
            return str(getattr(self.jepa_model, "backend_label", BACKEND_LATENT_JEPA))
        return BACKEND_SYNTHETIC_FALLBACK

    def attach_jepa_model(self, jepa_model: Optional[Any] = None, **init_kwargs: Any) -> Optional[Any]:
        """
        Attaches an existing LatentProtocolJEPA instance or lazily imports and
        instantiates one if `engine.latent_jepa_model` is available.
        """
        if jepa_model is not None:
            self.jepa_model = jepa_model
            return self.jepa_model
        try:
            from engine.latent_jepa_model import LatentProtocolJEPA
        except ImportError:
            return None
        self.jepa_model = LatentProtocolJEPA(**init_kwargs)
        return self.jepa_model

    def _hash_probe(self, probe_bytes: bytes) -> str:
        return hashlib.sha256(probe_bytes).hexdigest()

    def record_step(
        self,
        probe_bytes: bytes,
        status_code: int,
        raw_response: bytes = b"",
        latency: float = 0.05,
        is_anomaly: bool = False,
        anomaly_category: Optional[str] = None,
        is_vulnerability: bool = False,
        details: str = "",
    ) -> None:
        """Records a live execution step into the world model memory."""
        p_hash = self._hash_probe(probe_bytes)
        sim = SimulatedResponse(
            status_code=status_code,
            raw_response=raw_response,
            latency=latency,
            is_connection_closed=(b"connection: close" in raw_response.lower() or status_code in (400, 431, 500)),
            framing_type="chunked" if b"transfer-encoding: chunked" in raw_response.lower() else "content-length",
            is_anomaly=is_anomaly,
            anomaly_category=anomaly_category,
            is_vulnerability=is_vulnerability,
            confidence=1.0,
            details=details or "Empirical observation recorded",
            backend_label=BACKEND_RECORDED_REPLAY,
        )
        self.exact_cache[p_hash] = sim

        # Identify structural vectors
        p_lower = probe_bytes.lower()
        vectors = []
        if b"content-length" in p_lower and b"transfer-encoding" in p_lower:
            vectors.append("CL_TE")
        if b" :\t" in p_lower or b" :" in p_lower:
            vectors.append("COLON_WHITESPACE")
        if b"\r\n " in p_lower or b"\r\n\t" in p_lower:
            vectors.append("OBS_FOLD")
        if b"/nul" in p_lower:
            vectors.append("PATH_NUL")
        if b"multipart/byteranges" in p_lower:
            vectors.append("MULTIPART")

        traj = WorldModelTrajectory(
            trajectory_id=f"traj_{len(self.trajectories) + 1}",
            target_host=self.target_host,
            target_port=self.target_port,
            probe_bytes=probe_bytes,
            response_status=status_code,
            framing_type=sim.framing_type,
            is_anomaly=is_anomaly,
            anomaly_category=anomaly_category,
            is_vulnerability=is_vulnerability,
            desync_vectors=vectors,
        )
        self.trajectories.append(traj)

        if is_anomaly and anomaly_category:
            self.known_anomaly_patterns.add(anomaly_category)

    def _maybe_calibrate_jepa_from_trajectories(self) -> Optional[Dict[str, Any]]:
        """
        If `engine.latent_jepa_model` is importable and enough real benign
        trajectories have been ingested, fits & calibrates `self.jepa_model`.
        """
        benign = [t for t in self.trajectories if not t.is_vulnerability and not t.is_anomaly]
        if len(benign) < 200:
            return None
        try:
            from engine.latent_jepa_model import (
                LatentProtocolJEPA,
                extract_probe_action_vector,
                extract_response_state_vector,
            )
        except ImportError:
            return None

        if self.jepa_model is None:
            self.jepa_model = LatentProtocolJEPA(stack_profile=self.server_signature)

        if len(benign) < getattr(self.jepa_model, "min_benign_transitions", 200):
            return None

        baseline_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        prev_vec = extract_response_state_vector(baseline_resp)
        transitions: List[Tuple[List[float], List[float], List[float]]] = []
        for traj in benign:
            cached = self.exact_cache.get(self._hash_probe(traj.probe_bytes))
            raw_resp = (
                cached.raw_response
                if cached is not None and cached.raw_response
                else f"HTTP/1.1 {traj.response_status} OK\r\nContent-Length: 0\r\n\r\n".encode("latin-1")
            )
            action_vec = extract_probe_action_vector(traj.probe_bytes)
            next_vec = extract_response_state_vector(
                raw_resp,
                latency_ms=(cached.latency * 1000.0 if cached is not None else 50.0),
                socket_closed=(cached.is_connection_closed if cached is not None else False),
            )
            transitions.append((prev_vec, action_vec, next_vec))
            prev_vec = next_vec

        try:
            return self.jepa_model.fit_and_calibrate(transitions)
        except Exception:
            return None

    def ingest_history_from_db(self, db_path: Any = "terminator.db", *, limit_tasks: int = 100) -> int:
        """
        Loads historical execution traces from SQLite (or a `Database` / connection)
        into the world model, and automatically populates `self.replay_pool` whenever
        `blackboard_nodes` or `dual_graph_nodes` exists in the database.

        Returns the number of probe/evaluation trajectories loaded.
        """
        conn: Optional[sqlite3.Connection] = None
        owns_conn = False
        db_lock = None

        if isinstance(db_path, (str, Path)):
            p = Path(str(db_path))
            if not p.exists():
                return 0
            conn = sqlite3.connect(str(p))
            conn.row_factory = sqlite3.Row
            owns_conn = True
        elif isinstance(db_path, sqlite3.Connection):
            conn = db_path
        elif hasattr(db_path, "conn") and getattr(db_path, "conn") is not None:
            conn = db_path.conn
            db_lock = getattr(db_path, "_lock", None)
        else:
            return 0

        count = 0
        has_replay_tables = False
        try:
            def _load_probes() -> Tuple[int, bool]:
                loaded = 0
                replay_present = False
                prev_factory = conn.row_factory
                conn.row_factory = sqlite3.Row
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = {str(r[0]) for r in cursor.fetchall()}
                    replay_present = ("blackboard_nodes" in tables) or ("dual_graph_nodes" in tables)

                    if "probes" in tables:
                        if "evaluations" in tables:
                            cursor.execute("""
                                SELECT p.raw_request, e.is_vulnerable, e.desync_class, e.details
                                FROM probes p
                                LEFT JOIN evaluations e ON p.probe_id = e.probe_id
                                WHERE p.raw_request IS NOT NULL
                            """)
                        else:
                            cursor.execute("""
                                SELECT p.raw_request, 0 AS is_vulnerable, NULL AS desync_class, '' AS details
                                FROM probes p
                                WHERE p.raw_request IS NOT NULL
                            """)
                        for row in cursor.fetchall():
                            raw_req = row["raw_request"]
                            if isinstance(raw_req, str):
                                probe_b = raw_req.encode("latin-1", errors="replace")
                            else:
                                probe_b = raw_req or b""
                            if not probe_b:
                                continue

                            is_vuln = bool(row["is_vulnerable"]) if row["is_vulnerable"] is not None else False
                            desync = row["desync_class"]
                            details = row["details"] or ""

                            self.record_step(
                                probe_bytes=probe_b,
                                status_code=200 if not is_vuln else 400,
                                is_anomaly=is_vuln or bool(desync),
                                anomaly_category=desync,
                                is_vulnerability=is_vuln,
                                details=details,
                            )
                            loaded += 1
                except Exception:
                    pass
                finally:
                    conn.row_factory = prev_factory
                return (loaded, replay_present)

            if db_lock is not None:
                with db_lock:
                    count, has_replay_tables = _load_probes()
            else:
                count, has_replay_tables = _load_probes()
        finally:
            if owns_conn and conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        if has_replay_tables:
            try:
                self.last_ingested_trees = self.replay_pool.ingest_from_db(
                    db_path, limit_tasks=limit_tasks
                )
            except Exception:
                self.last_ingested_trees = 0

            if self.server_signature == "generic" and len(self.replay_pool) > 0:
                for tree in self.replay_pool.list_trees():
                    if tree.stack_profile and tree.stack_profile != "generic":
                        self.server_signature = tree.stack_profile
                        break

        self._maybe_calibrate_jepa_from_trajectories()
        return count

    def simulate_probe(self, probe_bytes: bytes) -> SimulatedResponse:
        """
        Simulates target server response to a candidate probe.
        Priority order:
          1. Exact recorded replay (`recorded_blackboard_replay`)
          2. Calibrated latent JEPA world model (`latent_jepa_world_model`)
          3. Cold-start structural heuristic fallback (`synthetic_heuristic_fallback`)
        """
        p_hash = self._hash_probe(probe_bytes)
        if p_hash in self.exact_cache:
            cached = self.exact_cache[p_hash]
            if not cached.backend_label:
                cached.backend_label = BACKEND_RECORDED_REPLAY
            return cached

        # Calibrated JEPA Latent Protocol World Model generalization
        if self.jepa_model is not None and bool(getattr(self.jepa_model, "calibrated", False)):
            predict_fn = getattr(self.jepa_model, "predict_anomaly_score", None)
            if callable(predict_fn):
                try:
                    score = predict_fn(probe_bytes)
                except Exception:
                    score = None
                if score is not None:
                    score_f = float(score)
                    threshold_f = max(1e-6, float(getattr(self.jepa_model, "threshold", 1.0) or 1.0))
                    is_anom = score_f > threshold_f
                    is_vuln = score_f > (threshold_f * 1.5)
                    p_lower_j = probe_bytes.lower()
                    backend = str(getattr(self.jepa_model, "backend_label", BACKEND_LATENT_JEPA))
                    return SimulatedResponse(
                        status_code=400 if is_anom else 200,
                        latency=0.06 if is_anom else 0.04,
                        is_connection_closed=is_vuln,
                        framing_type="chunked" if b"transfer-encoding" in p_lower_j else "content-length",
                        is_anomaly=is_anom,
                        anomaly_category="LATENT_JEPA_SURPRISE" if is_anom else None,
                        is_vulnerability=is_vuln,
                        confidence=min(0.95, max(0.55, 0.5 * (score_f / threshold_f))) if is_anom else 0.80,
                        details=f"Simulated via calibrated JEPA latent dynamics (surprise={score_f:.4f}, threshold={threshold_f:.4f}).",
                        backend_label=backend,
                    )

        # Structural Generalized Simulation (Cold-Start Fallback Rules)
        p_lower = probe_bytes.lower()

        # Check for un-framed client body
        has_cl = b"content-length:" in p_lower or b"content-length :" in p_lower
        has_te = b"transfer-encoding:" in p_lower or b"transfer-encoding :" in p_lower
        has_body = False
        if b"\r\n\r\n" in probe_bytes:
            _, body = probe_bytes.split(b"\r\n\r\n", 1)
            has_body = len(body.strip()) > 0

        # RFC 9112 Section 6.1 un-framed body
        if has_body and not has_cl and not has_te:
            return SimulatedResponse(
                status_code=400,
                latency=0.01,
                is_connection_closed=True,
                framing_type="content-length",
                is_anomaly=False,
                is_vulnerability=False,
                confidence=0.95,
                details="Simulated: Client framing omission (RFC 9112 Section 6.1); server rejects trailing socket data with 400.",
                backend_label=BACKEND_SYNTHETIC_FALLBACK,
            )

        # Dual-CL conflict
        if p_lower.count(b"content-length:") >= 2:
            return SimulatedResponse(
                status_code=400,
                latency=0.04,
                is_connection_closed=True,
                framing_type="content-length",
                is_anomaly=True,
                anomaly_category="DUAL_HEADER_CONFLICT",
                is_vulnerability=True,
                confidence=0.88,
                details="Simulated: Dual Content-Length detected; induces parser divergence across front/back-end.",
                backend_label=BACKEND_SYNTHETIC_FALLBACK,
            )

        # CL.TE conflict
        if has_cl and has_te:
            return SimulatedResponse(
                status_code=200,
                latency=0.08,
                is_connection_closed=False,
                framing_type="chunked",
                is_anomaly=True,
                anomaly_category="CL_TE_DESYNCHRONIZATION",
                is_vulnerability=True,
                confidence=0.90,
                details="Simulated: CL.TE conflicting framing triggers stateful boundary desync.",
                backend_label=BACKEND_SYNTHETIC_FALLBACK,
            )

        # Pre-colon whitespace
        if b" :" in probe_bytes or b"\t:" in probe_bytes:
            return SimulatedResponse(
                status_code=400,
                latency=0.02,
                is_connection_closed=True,
                framing_type="content-length",
                is_anomaly=False,
                is_vulnerability=False,
                confidence=0.95,
                details="Simulated: Pre-colon whitespace rejected under RFC 9112 Section 5.1 compliant parsing.",
                backend_label=BACKEND_SYNTHETIC_FALLBACK,
            )

        # Baseline default simulation
        return SimulatedResponse(
            status_code=200,
            latency=0.05,
            is_connection_closed=False,
            framing_type="content-length",
            is_anomaly=False,
            is_vulnerability=False,
            confidence=0.75,
            details="Simulated: Standard conforming HTTP request.",
            backend_label=BACKEND_SYNTHETIC_FALLBACK,
        )
