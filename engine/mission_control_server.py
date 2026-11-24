"""
Self-Hosted Interactive Mission Control & Full-Lifecycle Orchestration Server (`--serve-ui`)
=============================================================================================

Provides a zero-external-dependency, loopback-bound self-hosted Web GUI + authenticated
REST API + real-time Server-Sent Events (SSE) orchestration server for RFCHunt:
  - Interactive 3-Lane Evidence Triage Console:
      Lane 1: Verified Exploits (`poe_level == 3`)
      Lane 2: Deterministic Static Invariant Violations (AST / Verification Inversion / SAST / PQC / SCA / AI)
      Lane 3: Speculative Multi-Hop Hypotheses (`poe_level <= 1`, capped <= LOW, strictly isolated)
  - Turnkey Full-Lifecycle Task Launcher (Repo Audits, Authorized Multi-Target Network Lifecycle
    with opt-in `httpx`/`katana`/`nuclei`, Live Proxy/H2 Audits, and `ArtexRetester` re-verification)
  - Live Asset & Exploration Graph Coverage Inspector
  - Live RFC 6962 Signed Tree Head (STH) & Merkle Consistency Verifier
  - Interactive Approval Gate Queue (`approve` / `deny`)
  - Real-time SSE Event Stream (`/api/events`)

Security invariants:
  - Loopback-only binding (`127.0.0.1`) by default.
  - Per-session cryptographic `X-RFCHunt-Token` verified via constant-time `hmac.compare_digest`
    on all mutating API endpoints (`POST /api/tasks`, `/cancel`, `/retest`, `/api/approvals/*`).
  - Strict `Host` / `Origin` loopback check against DNS-rebinding & CSRF.
  - Strict `validate_and_authorize_target()` SSRF guard before scheduling any network scan.
  - Safe DOM construction (`textContent`, zero `innerHTML` with untrusted finding data) and CSP headers.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import secrets
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from engine.merkle_audit import MerkleAuditTrail
from engine.safe_network_validator import is_explicit_loopback_host, validate_and_authorize_target


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LifecycleTask:
    task_id: str
    mode: str  # "repo_all" | "network_lifecycle" | "deep_audit"
    target: str
    authorized: bool = False
    strict_poe: bool = True
    enable_external_scanners: bool = False
    status: str = "queued"  # queued | running | completed | failed | cancelled
    created_at: str = field(default_factory=_utc_now_iso)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    reports_dir: str = ""
    error: Optional[str] = None
    summary: Dict[str, Any] = field(default_factory=dict)
    retest_history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PendingApproval:
    approval_id: str
    task_id: str
    action_type: str
    target: str
    reason: str
    status: str = "pending"  # pending | approved | denied
    created_at: str = field(default_factory=_utc_now_iso)
    decided_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MissionControlOrchestrator:
    """
    Thread-safe full-lifecycle orchestrator backing the self-hosted Mission Control GUI.
    Runs real RFCHunt `--all` / network-lifecycle scans in a bounded worker pool,
    maintains separated 3-lane finding stores, tracks Asset Graph nodes, verifies
    RFC 6962 Signed Tree Heads, and fans out real-time SSE events to UI subscribers.
    """

    def __init__(
        self,
        *,
        reports_root: str = "reports/mission_control",
        db_path: str = "terminator.db",
        max_workers: int = 4,
        scan_runner: Optional[Callable[..., Dict[str, Any]]] = None,
    ) -> None:
        self.reports_root = Path(reports_root).resolve(strict=False)
        self.reports_root.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._scan_runner = scan_runner
        self._pool = ThreadPoolExecutor(max_workers=max(1, min(int(max_workers), 8)), thread_name_prefix="rfchunt-mc")
        self._lock = threading.RLock()
        self._tasks: Dict[str, LifecycleTask] = {}
        self._futures: Dict[str, Future] = {}
        self._approvals: Dict[str, PendingApproval] = {}
        self._verified_exploits: List[Dict[str, Any]] = []
        self._deterministic_static: List[Dict[str, Any]] = []
        self._speculative_hypotheses: List[Dict[str, Any]] = []
        self._assets: Dict[str, Dict[str, Any]] = {}
        self._merkle_snapshots: List[Dict[str, Any]] = []
        self._subscribers: List[queue.Queue] = []

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    def subscribe_events(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=128)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe_events(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _broadcast(self, event_type: str, payload: Dict[str, Any]) -> None:
        evt = {
            "event": event_type,
            "timestamp": _utc_now_iso(),
            "data": payload,
        }
        with self._lock:
            dead: List[queue.Queue] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(evt)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    def create_approval_request(
        self,
        *,
        task_id: str,
        action_type: str,
        target: str,
        reason: str,
    ) -> PendingApproval:
        aid = f"APR-{secrets.token_hex(4).upper()}"
        rec = PendingApproval(
            approval_id=aid,
            task_id=task_id,
            action_type=action_type,
            target=target,
            reason=reason,
        )
        with self._lock:
            self._approvals[aid] = rec
        self._broadcast("approval_requested", rec.to_dict())
        return rec

    def decide_approval(self, approval_id: str, decision: str) -> Optional[PendingApproval]:
        norm = str(decision or "").strip().lower()
        if norm not in ("approved", "denied"):
            raise ValueError("Decision must be 'approved' or 'denied'")
        with self._lock:
            rec = self._approvals.get(approval_id)
            if rec is None:
                return None
            rec.status = norm
            rec.decided_at = _utc_now_iso()
        self._broadcast("approval_decided", rec.to_dict())
        return rec

    def list_approvals(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._approvals.values()]

    def submit_task(
        self,
        *,
        target: str,
        mode: str = "repo_all",
        authorized: bool = False,
        strict_poe: bool = True,
        enable_external_scanners: bool = False,
    ) -> LifecycleTask:
        clean_target = str(target or "").strip()
        if not clean_target:
            raise ValueError("Target path or host is required.")
        norm_mode = str(mode or "repo_all").strip().lower()
        if norm_mode not in ("repo_all", "network_lifecycle", "deep_audit"):
            raise ValueError(f"Unsupported task mode: {norm_mode}")

        is_local_path = os.path.exists(clean_target)
        if not is_local_path:
            parsed = urlparse(clean_target if "://" in clean_target else f"http://{clean_target}")
            host_only = parsed.hostname or clean_target
            ok, reason = validate_and_authorize_target(host_only, authorized=bool(authorized))
            if not ok:
                raise PermissionError(f"Target '{clean_target}' blocked by SSRF/authorization guard: {reason}")

        tid = f"MC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3).upper()}"
        task_reports = str((self.reports_root / tid).resolve(strict=False))
        task = LifecycleTask(
            task_id=tid,
            mode=norm_mode,
            target=clean_target,
            authorized=bool(authorized),
            strict_poe=bool(strict_poe),
            enable_external_scanners=bool(enable_external_scanners),
            reports_dir=task_reports,
        )
        with self._lock:
            self._tasks[tid] = task
            self._assets[clean_target] = {
                "asset_id": f"ASSET-{len(self._assets) + 1:04d}",
                "target": clean_target,
                "kind": "LOCAL_REPOSITORY" if is_local_path else "NETWORK_ENDPOINT",
                "last_task_id": tid,
                "status": "scheduled",
                "updated_at": _utc_now_iso(),
            }
        self._broadcast("task_created", task.to_dict())
        fut = self._pool.submit(self._execute_task, tid)
        with self._lock:
            self._futures[tid] = fut
        return task

    def _execute_task(self, task_id: str) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None or task.status == "cancelled":
                return
            task.status = "running"
            task.started_at = _utc_now_iso()
        self._broadcast("task_started", {"task_id": task_id, "target": task.target, "mode": task.mode})

        try:
            is_local_path = os.path.exists(task.target)
            if self._scan_runner is not None:
                res = self._scan_runner(
                    target=task.target,
                    mode=task.mode,
                    reports_dir=task.reports_dir,
                    authorized=task.authorized,
                    strict_poe=task.strict_poe,
                    enable_external_scanners=task.enable_external_scanners,
                )
            else:
                from database import Database
                from engine.mantis_integrator import run_unified_all_scans

                task_db = Database(self.db_path)
                try:
                    kwargs: Dict[str, Any] = {
                        "reports_dir": task.reports_dir,
                        "db": task_db,
                        "strict_poe": task.strict_poe,
                        "include_leads": False,
                        "authorized": task.authorized,
                        "quiet": True,
                    }
                    if is_local_path:
                        kwargs["repo"] = task.target
                    else:
                        kwargs["remote_target"] = task.target
                        if task.mode == "network_lifecycle" and task.enable_external_scanners:
                            kwargs["enable_external_discovery"] = True
                            kwargs["enable_external_nuclei"] = True
                    res = run_unified_all_scans(**kwargs)
                finally:
                    task_db.close()

            with self._lock:
                if task.status == "cancelled":
                    return
                verified = list(res.get("verified_exploits") or [])
                deterministic = list(res.get("deterministic_static_findings") or [])
                speculative = list(res.get("speculative_hypotheses") or [])
                for item in verified:
                    self._verified_exploits.append({**item, "task_id": task_id})
                for item in deterministic:
                    self._deterministic_static.append({**item, "task_id": task_id})
                for item in speculative:
                    self._speculative_hypotheses.append({**item, "task_id": task_id})

                merkle_snap = dict(res.get("merkle_audit") or {})
                if merkle_snap:
                    merkle_snap["task_id"] = task_id
                    sth = merkle_snap.get("signed_tree_head")
                    merkle_snap["sth_verified"] = (
                        MerkleAuditTrail.verify_signed_tree_head(sth)
                        if isinstance(sth, dict)
                        else False
                    )
                    self._merkle_snapshots.append(merkle_snap)

                task.summary = {
                    "verified_exploits_count": len(verified),
                    "deterministic_static_count": len(deterministic),
                    "speculative_hypotheses_count": len(speculative),
                    "severity_counts": dict(res.get("severity_counts") or {}),
                    "speculative_severity_counts": dict(res.get("speculative_severity_counts") or {}),
                    "merkle_status": merkle_snap.get("status", "unknown"),
                    "defensive_status": (res.get("defensive_intelligence") or {}).get("status", "unknown"),
                    "report_files": dict(res.get("report_files") or {}),
                }
                task.status = "completed"
                task.completed_at = _utc_now_iso()
                if task.target in self._assets:
                    self._assets[task.target]["status"] = "audited"
                    self._assets[task.target]["updated_at"] = _utc_now_iso()
                    self._assets[task.target]["verified_count"] = len(verified)
                    self._assets[task.target]["deterministic_count"] = len(deterministic)
            self._broadcast("task_completed", task.to_dict())
        except Exception as exc:
            with self._lock:
                task.status = "failed"
                task.error = str(exc)
                task.completed_at = _utc_now_iso()
                if task.target in self._assets:
                    self._assets[task.target]["status"] = "failed"
                    self._assets[task.target]["updated_at"] = _utc_now_iso()
            self._broadcast("task_failed", {"task_id": task_id, "error": str(exc)})

    def cancel_task(self, task_id: str) -> Optional[LifecycleTask]:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            if task.status in ("queued", "running"):
                task.status = "cancelled"
                task.completed_at = _utc_now_iso()
                fut = self._futures.get(task_id)
                if fut is not None:
                    fut.cancel()
        self._broadcast("task_cancelled", {"task_id": task_id})
        return task

    def retest_task(self, task_id: str) -> Optional[LifecycleTask]:
        with self._lock:
            orig = self._tasks.get(task_id)
            if orig is None:
                return None
            retest_entry = {
                "retest_at": _utc_now_iso(),
                "source_task_id": task_id,
                "target": orig.target,
                "mode": orig.mode,
            }
            orig.retest_history.append(retest_entry)
        return self.submit_task(
            target=orig.target,
            mode=orig.mode,
            authorized=orig.authorized,
            strict_poe=orig.strict_poe,
            enable_external_scanners=orig.enable_external_scanners,
        )

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            t = self._tasks.get(task_id)
            return t.to_dict() if t is not None else None

    def list_tasks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()]

    def list_assets(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._assets.values())

    def get_findings(self, lane: str = "primary") -> Dict[str, Any]:
        norm = str(lane or "primary").strip().lower()
        with self._lock:
            v = list(self._verified_exploits)
            d = list(self._deterministic_static)
            s = list(self._speculative_hypotheses)
        if norm == "verified":
            items = v
        elif norm == "deterministic":
            items = d
        elif norm == "speculative":
            items = s
        elif norm == "all":
            items = v + d + s
        else:  # primary = verified + deterministic (narrow zero-noise signal by default)
            items = v + d
        return {
            "lane": norm,
            "strict_evidence_separation": True,
            "counts": {
                "verified_exploits": len(v),
                "deterministic_static": len(d),
                "speculative_hypotheses": len(s),
            },
            "items": items,
        }

    def get_merkle_status(self) -> Dict[str, Any]:
        with self._lock:
            snaps = list(self._merkle_snapshots)
        return {
            "total_snapshots": len(snaps),
            "latest": snaps[-1] if snaps else {
                "status": "no_live_differential_wire_findings",
                "total_leaves": 0,
                "confirmed_leaves": 0,
                "sth_verified": True,
            },
            "snapshots": snaps[-20:],
        }


def _render_mission_control_html(session_token: str) -> str:
    """Renders the self-hosted Mission Control SPA with strict DOM escaping and token header auth."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>RFCHunt Mission Control — Full-Lifecycle Security Orchestrator</title>
<style>
  :root {{
    --bg: #0b0f19;
    --panel: #131a29;
    --border: #253047;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --verified: #ef4444;
    --deterministic: #f59e0b;
    --speculative: #64748b;
    --ok: #22c55e;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); }}
  header {{ padding: 18px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #0f1625; }}
  header h1 {{ margin: 0; font-size: 20px; letter-spacing: 0.3px; }}
  .pill {{ font-size: 12px; padding: 4px 10px; border-radius: 999px; background: rgba(34,197,94,0.15); color: var(--ok); border: 1px solid rgba(34,197,94,0.4); }}
  main {{ max-width: 1320px; margin: 0 auto; padding: 20px 24px; display: grid; gap: 18px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; }}
  .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }}
  .card .label {{ font-size: 12px; text-transform: uppercase; color: var(--muted); letter-spacing: 0.6px; }}
  .card .val {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
  .val.verified {{ color: var(--verified); }}
  .val.deterministic {{ color: var(--deterministic); }}
  .val.speculative {{ color: var(--speculative); }}
  .val.ok {{ color: var(--ok); }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }}
  .panel h2 {{ margin: 0 0 12px 0; font-size: 15px; color: var(--accent); }}
  .row {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
  input, select, button {{ background: #0b1120; color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-size: 13px; }}
  input {{ min-width: 280px; flex: 1; }}
  button {{ cursor: pointer; background: #1d4ed8; border-color: #2563eb; font-weight: 600; }}
  button.tab {{ background: #111827; border-color: var(--border); font-weight: 500; }}
  button.tab.active {{ background: #1e293b; border-color: var(--accent); color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-weight: 600; }}
  .muted {{ color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>RFCHunt Mission Control</h1>
    <div class="muted">Self-Hosted Full-Lifecycle Orchestrator &bull; Strict 3-Lane Evidence Separation Active</div>
  </div>
  <span class="pill" id="sse-status">LIVE SSE CONNECTED</span>
</header>
<main>
  <section class="cards">
    <div class="card"><div class="label">Lane 1: Verified Exploits (POE=3)</div><div class="val verified" id="cnt-verified">0</div></div>
    <div class="card"><div class="label">Lane 2: Deterministic Static Invariants</div><div class="val deterministic" id="cnt-deterministic">0</div></div>
    <div class="card"><div class="label">Lane 3: Speculative Hypotheses (Isolated)</div><div class="val speculative" id="cnt-speculative">0</div></div>
    <div class="card"><div class="label">RFC 6962 Merkle STH</div><div class="val ok" id="merkle-state">VERIFIED</div></div>
  </section>

  <section class="panel">
    <h2>Turnkey Scan &amp; Lifecycle Launcher</h2>
    <div class="row">
      <input id="target-input" placeholder="Local repo path (e.g. D:\\repo) or authorized host (e.g. 127.0.0.1:8080)" />
      <select id="mode-select">
        <option value="repo_all">Unified --all (Strict 3-Lane Precision)</option>
        <option value="network_lifecycle">Turnkey Network Lifecycle (Discovery + Dual-Graph + Retest)</option>
        <option value="deep_audit">Deep White-Box Repo Audit</option>
      </select>
      <label class="muted"><input type="checkbox" id="auth-check" style="min-width:auto;" /> Authorized Target</label>
      <button id="launch-btn">Launch Audit</button>
    </div>
    <div class="muted" id="launch-msg" style="margin-top:8px;"></div>
  </section>

  <section class="panel">
    <h2>3-Lane Evidence Explorer</h2>
    <div class="row">
      <button class="tab active" data-lane="primary">Primary Signal (Lane 1 + Lane 2)</button>
      <button class="tab" data-lane="verified">Lane 1: Verified Exploits (POE=3)</button>
      <button class="tab" data-lane="deterministic">Lane 2: Deterministic Static</button>
      <button class="tab" data-lane="speculative">Lane 3: Speculative Hypotheses (Capped &le; LOW)</button>
    </div>
    <table>
      <thead><tr><th>Lane</th><th>Severity</th><th>Rule</th><th>Scanner</th><th>Location</th><th>Title</th></tr></thead>
      <tbody id="findings-body"></tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Lifecycle Tasks &amp; Asset Coverage</h2>
    <table>
      <thead><tr><th>Task ID</th><th>Mode</th><th>Target</th><th>Status</th><th>Primary / Speculative</th><th>Actions</th></tr></thead>
      <tbody id="tasks-body"></tbody>
    </table>
  </section>

  <section class="panel">
    <h2>HackerOne Campaign &amp; HITL Report Porter (--hackerone)</h2>
    <div class="row">
      <input id="h1-program-input" placeholder="HackerOne program handle (e.g. anthropic-vdp)" />
      <select id="h1-sev-select">
        <option value="medium">Min Severity: Medium</option>
        <option value="high">Min Severity: High</option>
        <option value="critical">Min Severity: Critical</option>
        <option value="low">Min Severity: Low</option>
      </select>
      <button id="h1-port-btn">Build HITL Drafts</button>
    </div>
    <div class="muted" id="h1-msg" style="margin-top:8px;">Strict Anti-Slop Gate: Only Lane 1 (Verified) &amp; Lane 2 (Deterministic Static) findings are ported. Final submission always requires human review on hackerone.com.</div>
    <table>
      <thead><tr><th>Draft ID</th><th>Severity</th><th>Weakness</th><th>Scope</th><th>Title</th><th>Submit URL</th></tr></thead>
      <tbody id="h1-drafts-body"></tbody>
    </table>
  </section>
</main>
<script>
const TOKEN = {json.dumps(session_token)};
let activeLane = 'primary';

function tdText(tr, txt) {{
  const td = document.createElement('td');
  td.textContent = String(txt ?? '');
  tr.appendChild(td);
}}

async function refreshAll() {{
  const [fRes, tRes, mRes] = await Promise.all([
    fetch('/api/findings?lane=' + encodeURIComponent(activeLane)),
    fetch('/api/tasks'),
    fetch('/api/merkle'),
  ]);
  const fData = await fRes.json();
  const tData = await tRes.json();
  const mData = await mRes.json();

  document.getElementById('cnt-verified').textContent = fData.counts.verified_exploits;
  document.getElementById('cnt-deterministic').textContent = fData.counts.deterministic_static;
  document.getElementById('cnt-speculative').textContent = fData.counts.speculative_hypotheses;
  document.getElementById('merkle-state').textContent =
    (mData.latest && mData.latest.sth_verified) ? ('STH OK (' + (mData.latest.total_leaves || 0) + ' leaves)') : 'UNVERIFIED';

  const fb = document.getElementById('findings-body');
  fb.replaceChildren();
  (fData.items || []).slice(0, 100).forEach(it => {{
    const tr = document.createElement('tr');
    tdText(tr, it.evidence_lane || 'DETERMINISTIC_STATIC');
    tdText(tr, it.severity || 'INFO');
    tdText(tr, it.rule_id || '');
    tdText(tr, it.scanner || '');
    tdText(tr, (it.file_path || '') + ':' + (it.line_number || 1));
    tdText(tr, it.title || '');
    fb.appendChild(tr);
  }});

  const tb = document.getElementById('tasks-body');
  tb.replaceChildren();
  (tData.tasks || []).forEach(tk => {{
    const tr = document.createElement('tr');
    tdText(tr, tk.task_id);
    tdText(tr, tk.mode);
    tdText(tr, tk.target);
    tdText(tr, tk.status);
    const s = tk.summary || {{}};
    tdText(tr, ((s.verified_exploits_count || 0) + (s.deterministic_static_count || 0)) + ' / ' + (s.speculative_hypotheses_count || 0));
    const actTd = document.createElement('td');
    const rbtn = document.createElement('button');
    rbtn.textContent = 'Retest';
    rbtn.onclick = async () => {{
      await fetch('/api/tasks/' + encodeURIComponent(tk.task_id) + '/retest', {{
        method: 'POST',
        headers: {{ 'X-RFCHunt-Token': TOKEN }}
      }});
      refreshAll();
    }};
    actTd.appendChild(rbtn);
    tr.appendChild(actTd);
    tb.appendChild(tr);
  }});
}}

document.querySelectorAll('button.tab').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('button.tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeLane = btn.getAttribute('data-lane');
    refreshAll();
  }});
}});

document.getElementById('launch-btn').addEventListener('click', async () => {{
  const target = document.getElementById('target-input').value.trim();
  const mode = document.getElementById('mode-select').value;
  const authorized = document.getElementById('auth-check').checked;
  const msg = document.getElementById('launch-msg');
  const res = await fetch('/api/tasks', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json', 'X-RFCHunt-Token': TOKEN }},
    body: JSON.stringify({{ target, mode, authorized, strict_poe: true }})
  }});
  const body = await res.json();
  msg.textContent = res.ok ? ('Launched task ' + body.task.task_id) : ('Error: ' + (body.error || res.status));
  refreshAll();
}});

document.getElementById('h1-port-btn').addEventListener('click', async () => {{
  const program = document.getElementById('h1-program-input').value.trim();
  const min_severity = document.getElementById('h1-sev-select').value;
  const msg = document.getElementById('h1-msg');
  const res = await fetch('/api/hackerone/preview', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json', 'X-RFCHunt-Token': TOKEN }},
    body: JSON.stringify({{ program_handle: program, min_severity }})
  }});
  const body = await res.json();
  if (!res.ok) {{
    msg.textContent = 'Error: ' + (body.error || res.status);
    return;
  }}
  msg.textContent = 'Built ' + body.eligible_drafts_count + ' HITL draft(s) for ' + body.campaign.handle + ' (rejected ' + body.rejected_findings_count + ' speculative/low items).';
  const hb = document.getElementById('h1-drafts-body');
  hb.replaceChildren();
  (body.drafts || []).forEach(d => {{
    const tr = document.createElement('tr');
    tdText(tr, d.draft_id);
    tdText(tr, (d.severity_rating || '').toUpperCase());
    tdText(tr, d.weakness_cwe);
    tdText(tr, d.scope_match_status);
    tdText(tr, d.title);
    const linkTd = document.createElement('td');
    const a = document.createElement('a');
    a.href = d.submit_url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.style.color = '#38bdf8';
    a.textContent = 'Open HackerOne Form';
    linkTd.appendChild(a);
    tr.appendChild(linkTd);
    hb.appendChild(tr);
  }});
}});

const es = new EventSource('/api/events');
es.onmessage = () => refreshAll();
es.onerror = () => {{ document.getElementById('sse-status').textContent = 'RECONNECTING...'; }};
refreshAll();
</script>
</body>
</html>
"""


class MissionControlServer:
    """
    Self-hosted loopback-bound HTTP/SSE server exposing RFCHunt's interactive
    Mission Control SPA and full-lifecycle orchestration REST API.
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8789,
        allow_non_loopback: bool = False,
        orchestrator: Optional[MissionControlOrchestrator] = None,
        session_token: Optional[str] = None,
    ) -> None:
        if not allow_non_loopback and not is_explicit_loopback_host(host):
            raise PermissionError(
                f"MissionControlServer refuses to bind non-loopback host {host!r} without allow_non_loopback=True."
            )
        self.host = host
        self.port = int(port)
        self.session_token = session_token or secrets.token_urlsafe(24)
        self.orchestrator = orchestrator or MissionControlOrchestrator()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def _build_handler_cls(self):
        server_ref = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _is_valid_host_and_origin(self) -> bool:
                host_hdr = (self.headers.get("Host") or "").strip().lower()
                if host_hdr:
                    h_only = host_hdr.split(":")[0].strip("[]")
                    if server_ref.host in ("127.0.0.1", "localhost", "::1") and h_only not in ("127.0.0.1", "localhost", "::1"):
                        return False
                origin = (self.headers.get("Origin") or "").strip()
                if origin:
                    o_host = (urlparse(origin).hostname or "").lower()
                    if o_host and not is_explicit_loopback_host(o_host):
                        return False
                return True

            def _is_authenticated(self) -> bool:
                provided = (self.headers.get("X-RFCHunt-Token") or "").strip()
                if not provided:
                    auth = (self.headers.get("Authorization") or "").strip()
                    if auth.lower().startswith("bearer "):
                        provided = auth[7:].strip()
                if not provided:
                    return False
                return hmac.compare_digest(
                    provided.encode("utf-8"),
                    server_ref.session_token.encode("utf-8"),
                )

            def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _read_json_body(self) -> Dict[str, Any]:
                length = int(self.headers.get("Content-Length") or "0")
                if length <= 0 or length > 1_048_576:
                    return {}
                raw = self.rfile.read(length)
                return json.loads(raw.decode("utf-8", errors="replace"))

            def do_GET(self) -> None:
                if not self._is_valid_host_and_origin():
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid Host/Origin header"})
                    return
                parsed = urlparse(self.path)
                path = parsed.path
                qs = parse_qs(parsed.query)

                if path in ("/", "/index.html"):
                    html_bytes = _render_mission_control_html(server_ref.session_token).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html_bytes)))
                    self.send_header(
                        "Content-Security-Policy",
                        "default-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'",
                    )
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    self.wfile.write(html_bytes)
                    return

                if path == "/api/health":
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "service": "rfchunt-mission-control",
                            "strict_evidence_separation": True,
                            "active_tasks": len(server_ref.orchestrator.list_tasks()),
                        },
                    )
                    return

                if path == "/api/tasks":
                    self._send_json(HTTPStatus.OK, {"tasks": server_ref.orchestrator.list_tasks()})
                    return

                if path.startswith("/api/tasks/"):
                    tid = path[len("/api/tasks/") :].strip("/")
                    t_data = server_ref.orchestrator.get_task(tid)
                    if t_data is None:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Task not found"})
                        return
                    self._send_json(HTTPStatus.OK, {"task": t_data})
                    return

                if path == "/api/findings":
                    lane = (qs.get("lane") or ["primary"])[0]
                    self._send_json(HTTPStatus.OK, server_ref.orchestrator.get_findings(lane=lane))
                    return

                if path == "/api/assets":
                    self._send_json(HTTPStatus.OK, {"assets": server_ref.orchestrator.list_assets()})
                    return

                if path == "/api/merkle":
                    self._send_json(HTTPStatus.OK, server_ref.orchestrator.get_merkle_status())
                    return

                if path == "/api/approvals":
                    self._send_json(HTTPStatus.OK, {"approvals": server_ref.orchestrator.list_approvals()})
                    return

                if path == "/api/events":
                    once = (qs.get("once") or ["0"])[0] == "1"
                    init_frame = f"data: {json.dumps({'event': 'connected', 'timestamp': _utc_now_iso()})}\n\n".encode("utf-8")
                    if once:
                        self.close_connection = True
                        self.send_response(HTTPStatus.OK)
                        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("Content-Length", str(len(init_frame)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(init_frame)
                        self.wfile.flush()
                        return
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    q = server_ref.orchestrator.subscribe_events()
                    try:
                        self.wfile.write(init_frame)
                        self.wfile.flush()
                        for _ in range(120):
                            try:
                                evt = q.get(timeout=0.5)
                                self.wfile.write(f"data: {json.dumps(evt)}\n\n".encode("utf-8"))
                                self.wfile.flush()
                            except queue.Empty:
                                self.wfile.write(b": keepalive\n\n")
                                self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass
                    finally:
                        server_ref.orchestrator.unsubscribe_events(q)
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

            def do_POST(self) -> None:
                if not self._is_valid_host_and_origin():
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid Host/Origin header"})
                    return
                if not self._is_authenticated():
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Missing or invalid X-RFCHunt-Token"})
                    return

                parsed = urlparse(self.path)
                path = parsed.path

                if path == "/api/tasks":
                    try:
                        body = self._read_json_body()
                        task = server_ref.orchestrator.submit_task(
                            target=str(body.get("target") or ""),
                            mode=str(body.get("mode") or "repo_all"),
                            authorized=bool(body.get("authorized", False)),
                            strict_poe=bool(body.get("strict_poe", True)),
                            enable_external_scanners=bool(body.get("enable_external_scanners", False)),
                        )
                        self._send_json(HTTPStatus.ACCEPTED, {"task": task.to_dict()})
                    except PermissionError as exc:
                        self._send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
                    except ValueError as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path.startswith("/api/tasks/") and path.endswith("/cancel"):
                    tid = path[len("/api/tasks/") : -len("/cancel")].strip("/")
                    t = server_ref.orchestrator.cancel_task(tid)
                    if t is None:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Task not found"})
                        return
                    self._send_json(HTTPStatus.OK, {"task": t.to_dict()})
                    return

                if path.startswith("/api/tasks/") and path.endswith("/retest"):
                    tid = path[len("/api/tasks/") : -len("/retest")].strip("/")
                    try:
                        t = server_ref.orchestrator.retest_task(tid)
                    except (PermissionError, ValueError) as exc:
                        self._send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
                        return
                    if t is None:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Task not found"})
                        return
                    self._send_json(HTTPStatus.ACCEPTED, {"task": t.to_dict()})
                    return

                if path == "/api/hackerone/preview":
                    try:
                        from engine.hackerone_porter import HackerOnePorter
                        body = self._read_json_body()
                        primary_items = server_ref.orchestrator.get_findings(lane="all").get("items") or []
                        porter = HackerOnePorter(output_dir=str(server_ref.orchestrator.reports_root / "hackerone"))
                        res = porter.port_findings(
                            primary_items,
                            program_handle=(str(body.get("program_handle") or "").strip() or None),
                            query=str(body.get("query") or ""),
                            min_severity=str(body.get("min_severity") or "medium"),
                            max_reports=int(body.get("max_reports") or 5),
                            use_api=bool(body.get("use_api", False)),
                            use_browser=False,
                            submit_api=False,
                            researcher_username=str(body.get("researcher_username") or ""),
                            policy_text_override=str(body.get("policy_text") or ""),
                            include_ai_disclosure=bool(body.get("include_ai_disclosure", False)),
                            dry_run=bool(body.get("dry_run", False)),
                        )
                        self._send_json(HTTPStatus.OK, res)
                    except PermissionError as exc:
                        self._send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
                    except ValueError as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path == "/api/preflight/discover":
                    try:
                        from engine.preflight_discovery import run_preflight_discovery
                        body = self._read_json_body()
                        target_path = str(body.get("target_path") or "").strip() or None
                        prompt_text = str(body.get("prompt") or "")
                        policy_text = str(body.get("policy_text") or "")
                        target_host = str(body.get("target_host") or "").strip() or None
                        dry_run = bool(body.get("dry_run", False))
                        live_req = bool(body.get("live", False)) and not dry_run
                        enable_pqc = bool(body.get("pqc", True))
                        include_home = bool(body.get("include_home_skills", True))
                        raw_dirs = body.get("extra_skills_dirs")
                        extra_dirs = [str(d) for d in raw_dirs] if isinstance(raw_dirs, list) else None
                        res = run_preflight_discovery(
                            target_path=target_path,
                            prompt=prompt_text,
                            policy_text=policy_text,
                            target_host=target_host,
                            live=live_req,
                            enable_pqc=enable_pqc,
                            include_home_skills=include_home,
                            extra_skills_dirs=extra_dirs,
                            output_dir=(None if dry_run else str(server_ref.orchestrator.reports_root / "preflight")),
                            dry_run=dry_run,
                        )
                        self._send_json(HTTPStatus.OK, res)
                    except ValueError as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path == "/api/phi/scan":
                    try:
                        from engine.phi_scanner import PhiScanner
                        body = self._read_json_body()
                        raw_text = body.get("text")
                        target_path = str(body.get("target_path") or "").strip()
                        dry_run = bool(body.get("dry_run", False))
                        scanner = PhiScanner(enable_ml=False, enable_presidio=False)
                        if isinstance(raw_text, str) and raw_text:
                            res = scanner.scan_http_response(
                                raw_text,
                                source_url=str(body.get("source_url") or "mission-control-input"),
                            )
                        elif target_path:
                            if dry_run:
                                root_p = Path(target_path).resolve(strict=False)
                                files = scanner._collect_files(root_p) if root_p.exists() else []
                                res = {
                                    "status": "dry_run_phi_plan_ready",
                                    "dry_run": True,
                                    "target_path": str(root_p),
                                    "candidate_files_count": len(files),
                                    "backends": scanner.guard.active_backends,
                                }
                            else:
                                res = scanner.scan_repository(
                                    target_path,
                                    output_dir=str(server_ref.orchestrator.reports_root / "phi"),
                                    write_redacted_copies=bool(body.get("redact", False)),
                                )
                        else:
                            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Provide 'text' or 'target_path'"})
                            return
                        self._send_json(HTTPStatus.OK, res)
                    except ValueError as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path.startswith("/api/approvals/"):
                    aid = path[len("/api/approvals/") :].strip("/")
                    try:
                        body = self._read_json_body()
                        rec = server_ref.orchestrator.decide_approval(aid, str(body.get("decision") or ""))
                    except ValueError as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                        return
                    if rec is None:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Approval request not found"})
                        return
                    self._send_json(HTTPStatus.OK, {"approval": rec.to_dict()})
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        return _Handler

    def start_background(self) -> Tuple[str, int]:
        self._httpd = ThreadingHTTPServer((self.host, self.port), self._build_handler_cls())
        self.port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.host, self.port

    def serve_forever(self) -> None:
        self._httpd = ThreadingHTTPServer((self.host, self.port), self._build_handler_cls())
        self.port = int(self._httpd.server_address[1])
        print(f"[+] RFCHunt Mission Control Server listening on http://{self.host}:{self.port}/")
        print(f"[+] Session API Token (X-RFCHunt-Token): {self.session_token}")
        try:
            self._httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        self.orchestrator.close()
