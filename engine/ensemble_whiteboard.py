"""
Thread-safe Planner-Worker-Verifier Shared Whiteboard for RFCHunt (`engine/ensemble_whiteboard.py`).

Provides `WhiteboardHypothesis` and `EnsembleWhiteboard` (aliased as `SharedWhiteboard`)
for coordinating parallel verification workers across Lean 4 domain/workspace checks,
sandboxed Linux PoC execution (`LinuxPocRunner`), and optional Cairn SQLite blackboard sync
(`database.py`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import math
import threading
from typing import Any, Dict, List, Optional, Sequence
import uuid

try:
    from engine.advisory_exporter import _redact_inline_tokens
except Exception:  # pragma: no cover - defensive fallback
    def _redact_inline_tokens(text: str) -> str:
        return str(text or "")


def _redact_recursive(value: Any) -> Any:
    """Recursively scrubs inline secret tokens from nested whiteboard structures."""
    if isinstance(value, str):
        return _redact_inline_tokens(value)
    if isinstance(value, dict):
        return {k: _redact_recursive(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_recursive(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact_recursive(v) for v in value)
    return value


def _validate_confidence(val: Any) -> float:
    if isinstance(val, bool):
        raise ValueError(f"Confidence cannot be a bool: {val!r}")
    c = float(val)
    if not math.isfinite(c) or c < 0.0 or c > 1.0:
        raise ValueError(f"Confidence must be finite and in [0.0, 1.0], got {val!r}")
    return c


_ACTIVE_STATUSES = frozenset({"OPEN", "DISPATCHED", "TESTING"})
_FINAL_TERMINAL_STATUSES = frozenset({"VERIFIED", "COUNTEREXAMPLE_FOUND", "REFUTED"})

HYPOTHESIS_STATUSES = frozenset(
    {
        "OPEN",
        "DISPATCHED",
        "TESTING",
        "VERIFIED",
        "COUNTEREXAMPLE_FOUND",
        "REFUTED",
        "UNVERIFIED_UNAVAILABLE",
    }
)

TERMINAL_STATUSES = frozenset(
    {
        "VERIFIED",
        "COUNTEREXAMPLE_FOUND",
        "REFUTED",
        "UNVERIFIED_UNAVAILABLE",
    }
)


@dataclass
class WhiteboardHypothesis:
    """Shared hypothesis posted by the Planner and refined by Workers/Verifiers."""

    hypothesis_id: str
    title: str
    domain: str = "general"
    file_path: str = ""
    line: int = 0
    cwe: str = ""
    severity: str = "MEDIUM"
    confidence: float = 0.65
    status: str = "OPEN"
    source_engine: str = ""
    round_idx: int = 0
    assigned_worker: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    counterexamples: List[Dict[str, Any]] = field(default_factory=list)
    verifier_outputs: List[Dict[str, Any]] = field(default_factory=list)
    worker_traces: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    updated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return _redact_recursive(asdict(self))


class EnsembleWhiteboard:
    """
    Thread-safe shared whiteboard (`threading.RLock()`) tracking Planner hypotheses,
    Worker dispatch transitions, Verifier outputs, backend availability, and optional
    duck-typed Cairn SQLite `blackboard_nodes` persistence.
    """

    def __init__(
        self,
        *,
        task_id: Optional[str] = None,
        db: Optional[Any] = None,
        enable_db_sync: bool = True,
        enabled: bool = True,
        proxy: Optional[str] = None,
    ) -> None:
        self._lock = threading.RLock()
        self.task_id = str(task_id or f"wb-{uuid.uuid4().hex[:10]}")
        self._db = db
        self._enable_db_sync = bool(enable_db_sync and db is not None)
        self.enabled = bool(enabled)
        self.proxy = proxy
        self._hypotheses: Dict[str, WhiteboardHypothesis] = {}
        self._order: List[str] = []
        self._facts: List[Dict[str, Any]] = []
        self._transitions: List[Dict[str, Any]] = []
        self._rounds: List[Dict[str, Any]] = []
        self._backend_status: Dict[str, Dict[str, Any]] = {}
        self._db_synced: bool = False
        self._sync_errors: List[str] = []

    def add_hypothesis(
        self,
        hypothesis: WhiteboardHypothesis,
        *,
        overwrite: bool = False,
    ) -> WhiteboardHypothesis:
        """Posts a new hypothesis onto the whiteboard, optionally syncing to Cairn DB."""
        with self._lock:
            if hypothesis.status not in HYPOTHESIS_STATUSES:
                raise ValueError(
                    f"Invalid hypothesis status {hypothesis.status!r}; "
                    f"expected one of {sorted(HYPOTHESIS_STATUSES)}"
                )
            hid = str(hypothesis.hypothesis_id or "").strip()
            if not hid:
                raise ValueError("hypothesis_id must be non-empty")
            if hid in self._hypotheses and not overwrite:
                raise ValueError(f"Duplicate hypothesis_id: {hid!r}")

            hypothesis.confidence = _validate_confidence(hypothesis.confidence)
            hypothesis.title = _redact_inline_tokens(str(hypothesis.title or ""))
            hypothesis.notes = _redact_inline_tokens(str(hypothesis.notes or ""))
            hypothesis.evidence = _redact_recursive(dict(hypothesis.evidence or {}))
            hypothesis.counterexamples = _redact_recursive(list(hypothesis.counterexamples or []))
            hypothesis.verifier_outputs = _redact_recursive(list(hypothesis.verifier_outputs or []))
            hypothesis.worker_traces = _redact_recursive(list(hypothesis.worker_traces or []))
            hypothesis.metadata = _redact_recursive(dict(hypothesis.metadata or {}))

            if hid not in self._hypotheses:
                self._order.append(hid)
            hypothesis.updated_at_utc = datetime.now(timezone.utc).isoformat()
            self._hypotheses[hid] = hypothesis

            if self._enable_db_sync and self._db is not None:
                self._sync_queue_intent(hypothesis)
            return hypothesis

    post_hypothesis = add_hypothesis

    def update_status(
        self,
        hypothesis_id: str,
        status: str,
        *,
        evidence: Optional[Dict[str, Any]] = None,
        counterexamples: Optional[Sequence[Dict[str, Any]]] = None,
        verifier_output: Optional[Dict[str, Any]] = None,
        worker_trace: Optional[Dict[str, Any]] = None,
        worker_id: Optional[str] = None,
        round_idx: Optional[int] = None,
        confidence: Optional[float] = None,
        severity: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> WhiteboardHypothesis:
        """Atomically transitions a hypothesis status and appends verification evidence."""
        with self._lock:
            if status not in HYPOTHESIS_STATUSES:
                raise ValueError(
                    f"Invalid hypothesis status {status!r}; "
                    f"expected one of {sorted(HYPOTHESIS_STATUSES)}"
                )
            if hypothesis_id not in self._hypotheses:
                raise KeyError(f"Unknown hypothesis_id: {hypothesis_id!r}")

            hyp = self._hypotheses[hypothesis_id]
            prev_status = hyp.status
            if prev_status in _FINAL_TERMINAL_STATUSES and status in _ACTIVE_STATUSES:
                raise ValueError(
                    f"Illegal terminal-to-active rollback for {hypothesis_id!r}: "
                    f"{prev_status!r} -> {status!r}"
                )
            validated_conf: Optional[float] = (
                _validate_confidence(confidence) if confidence is not None else None
            )

            hyp.status = status
            if worker_id is not None:
                hyp.assigned_worker = str(worker_id)
            if round_idx is not None:
                hyp.round_idx = int(round_idx)
            if validated_conf is not None:
                hyp.confidence = validated_conf
            if severity is not None:
                hyp.severity = str(severity)
            if notes is not None:
                hyp.notes = _redact_inline_tokens(str(notes))
            if evidence:
                hyp.evidence.update(_redact_recursive(dict(evidence)))
            if counterexamples:
                hyp.counterexamples.extend(_redact_recursive(dict(c)) for c in counterexamples)
            if verifier_output:
                hyp.verifier_outputs.append(_redact_recursive(dict(verifier_output)))
            if worker_trace:
                hyp.worker_traces.append(_redact_recursive(dict(worker_trace)))

            ts = datetime.now(timezone.utc).isoformat()
            hyp.updated_at_utc = ts
            self._transitions.append(
                {
                    "hypothesis_id": hypothesis_id,
                    "from_status": prev_status,
                    "to_status": status,
                    "worker_id": worker_id or "",
                    "round_idx": hyp.round_idx,
                    "timestamp_utc": ts,
                }
            )

            if self._enable_db_sync and self._db is not None and status in TERMINAL_STATUSES:
                self._sync_terminal_status(hyp, worker_id=worker_id)
            return hyp

    transition = update_status

    def get_hypothesis(self, hypothesis_id: str) -> Optional[WhiteboardHypothesis]:
        with self._lock:
            return self._hypotheses.get(hypothesis_id)

    def list_hypotheses(
        self,
        *,
        status: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> List[WhiteboardHypothesis]:
        with self._lock:
            out: List[WhiteboardHypothesis] = []
            for hid in self._order:
                hyp = self._hypotheses.get(hid)
                if hyp is None:
                    continue
                if status is not None and hyp.status != status:
                    continue
                if domain is not None and hyp.domain != domain:
                    continue
                out.append(hyp)
            return out

    def add_fact(
        self,
        fact_type: str,
        summary: str,
        *,
        payload: Optional[Dict[str, Any]] = None,
        source: str = "verifier",
        domain: str = "",
    ) -> Dict[str, Any]:
        with self._lock:
            entry = {
                "fact_type": str(fact_type),
                "summary": _redact_inline_tokens(str(summary)),
                "domain": str(domain),
                "source": str(source),
                "payload": _redact_recursive(dict(payload)) if payload else {},
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            }
            self._facts.append(entry)
            if self._enable_db_sync and self._db is not None:
                try:
                    add_fact_fn = getattr(self._db, "add_fact", None)
                    if callable(add_fact_fn):
                        add_fact_fn(
                            f"[{fact_type}] {summary}",
                            task_id=self.task_id,
                            domain=domain or fact_type,
                            source_agent=source,
                            payload=entry["payload"],
                        )
                        self._db_synced = True
                except Exception as exc:
                    self._sync_errors.append(f"add_fact({fact_type}): {exc}")
            return entry

    def set_backend_status(self, backend_status: Dict[str, Dict[str, Any]]) -> None:
        with self._lock:
            self._backend_status = {str(k): dict(v) for k, v in (backend_status or {}).items()}

    def record_round(
        self,
        round_idx: int,
        *,
        dispatched: int,
        updated: int,
        notes: str = "",
    ) -> Dict[str, Any]:
        with self._lock:
            rec = {
                "round_idx": int(round_idx),
                "dispatched": int(dispatched),
                "updated": int(updated),
                "notes": str(notes),
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            }
            self._rounds.append(rec)
            return rec

    def _sync_queue_intent(self, hyp: WhiteboardHypothesis) -> None:
        try:
            queue_intent_fn = getattr(self._db, "queue_intent", None)
            if not callable(queue_intent_fn):
                return
            queue_intent_fn(
                hyp.title,
                priority=float(hyp.confidence),
                node_id=hyp.hypothesis_id,
                task_id=self.task_id,
                domain=hyp.domain,
                source_agent=hyp.source_engine or "planner",
                payload=hyp.to_dict(),
            )
            self._db_synced = True
        except Exception as exc:
            self._sync_errors.append(f"queue_intent({hyp.hypothesis_id}): {exc}")

    def _sync_terminal_status(
        self,
        hyp: WhiteboardHypothesis,
        *,
        worker_id: Optional[str] = None,
    ) -> None:
        try:
            complete_intent_fn = getattr(self._db, "complete_intent", None)
            if callable(complete_intent_fn):
                db_status = (
                    "DONE"
                    if hyp.status in ("VERIFIED", "COUNTEREXAMPLE_FOUND", "REFUTED")
                    else "UNAVAILABLE"
                )
                complete_intent_fn(
                    hyp.hypothesis_id,
                    status=db_status,
                    result_payload={
                        "whiteboard_status": hyp.status,
                        "evidence": hyp.evidence,
                        "counterexamples": hyp.counterexamples,
                    },
                )
                self._db_synced = True
        except Exception as exc:
            self._sync_errors.append(f"complete_intent({hyp.hypothesis_id}): {exc}")

        if hyp.status in ("VERIFIED", "COUNTEREXAMPLE_FOUND"):
            try:
                add_fact_fn = getattr(self._db, "add_fact", None)
                if callable(add_fact_fn):
                    add_fact_fn(
                        f"[{hyp.status}] {hyp.title}",
                        task_id=self.task_id,
                        domain=hyp.domain,
                        source_agent=worker_id or hyp.assigned_worker or "verifier",
                        payload=hyp.to_dict(),
                        parent_node_id=hyp.hypothesis_id,
                    )
                    self._db_synced = True
            except Exception as exc:
                self._sync_errors.append(f"add_fact({hyp.hypothesis_id}): {exc}")

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            hyps = [
                self._hypotheses[hid].to_dict()
                for hid in self._order
                if hid in self._hypotheses
            ]
            counts_by_status: Dict[str, int] = {}
            for h in hyps:
                st = str(h.get("status") or "OPEN")
                counts_by_status[st] = counts_by_status.get(st, 0) + 1
            return _redact_recursive(
                {
                    "task_id": self.task_id,
                    "enabled": self.enabled,
                    "proxy": self.proxy,
                    "hypotheses": hyps,
                    "counts_by_status": counts_by_status,
                    "facts": list(self._facts),
                    "transitions": list(self._transitions),
                    "rounds": list(self._rounds),
                    "backend_status": dict(self._backend_status),
                    "db_synced": self._db_synced,
                    "sync_errors": list(self._sync_errors),
                }
            )

    snapshot = to_dict


SharedWhiteboard = EnsembleWhiteboard

__all__ = [
    "HYPOTHESIS_STATUSES",
    "TERMINAL_STATUSES",
    "WhiteboardHypothesis",
    "EnsembleWhiteboard",
    "SharedWhiteboard",
]
