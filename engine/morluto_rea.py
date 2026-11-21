"""
Module 21 (`morluto/rea`) Surface-Mining Adapter Hook for `LiveWorkerExecutorRegistry`.
Delegates dynamically to `engine.rea_integrator.ReaIntegrator` while remaining cleanly
toggleable in unit/E2E suites via `engine.morluto_rea`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from engine.rea_integrator import ReaAnalysisResult, ReaFinding, ReaIntegrator


def mine_surface(target_path: Optional[str] = None, query: str = "") -> Dict[str, Any]:
    """
    Executes offline pure-Python bundle/Electron/source-map surface mining on `target_path`
    and returns normalized `endpoints` and `ai_sinks` for `ArtexWorker` multi-turn loops.
    """
    if not target_path or not str(target_path).strip():
        return {"endpoints": [], "ai_sinks": []}
    integrator = ReaIntegrator()
    result = integrator.analyze(target_path=target_path, write_reports=False)
    endpoints = list(result.discovered_endpoints)
    ai_sinks = list(result.ai_sinks)
    if query and str(query).strip():
        q_low = str(query).strip().lower()
        filtered_ep = [
            ep for ep in endpoints
            if q_low in str(ep.get("route", "")).lower() or q_low in str(ep.get("node_type", "")).lower()
        ]
        if filtered_ep:
            endpoints = filtered_ep
            ai_sinks = [ep for ep in endpoints if str(ep.get("node_type", "")).upper() == "AI_SINK"]
    return {
        "endpoints": endpoints,
        "ai_sinks": ai_sinks,
        "ipc_channels": list(result.ipc_channels),
    }


discover_surface = mine_surface
analyze_surface = mine_surface

__all__ = [
    "ReaAnalysisResult",
    "ReaFinding",
    "ReaIntegrator",
    "analyze_surface",
    "discover_surface",
    "mine_surface",
]
