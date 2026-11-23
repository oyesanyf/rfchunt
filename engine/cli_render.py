"""
Pure-CLI Terminal Renderer (Pillar 6)
=====================================
Zero-GUI, terminal-native renderer for RFCHunt CLI subcommands (`chains`,
`traces`, `coverage`, `retest`, `export-advisory`, `archive`, `proxy`, `all`).
- Emits crisp `rich` tables/panels on interactive TTYs.
- Falls back automatically to clean ASCII plain text when piped, in CI, or with `--plain`.
- Emits strict machine-readable JSON when `--json` is passed.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from rich.console import Console
    from rich.live import Live
    from rich.markup import escape as _rich_escape
    from rich.panel import Panel
    from rich.table import Table
    _RICH_AVAILABLE = True
except Exception:
    _RICH_AVAILABLE = False

    def _rich_escape(text: str) -> str:
        return text


def _use_rich(plain: bool = False) -> bool:
    if plain or not _RICH_AVAILABLE:
        return False
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def render_json(data: Any) -> str:
    text = json.dumps(data, indent=2, default=str)
    print(text)
    return text


def render_table(
    title: str,
    columns: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    as_json: bool = False,
    plain: bool = False,
    raw_data: Any = None,
) -> str:
    if as_json:
        payload = raw_data if raw_data is not None else [
            dict(zip(columns, [str(c) for c in row])) for row in rows
        ]
        return render_json(payload)

    str_rows = [[str(cell if cell is not None else "") for cell in row] for row in rows]
    if _use_rich(plain=plain):
        console = Console()
        table = Table(title=_rich_escape(str(title)), show_lines=False)
        for col in columns:
            table.add_column(_rich_escape(str(col)))
        for r in str_rows:
            table.add_row(*(_rich_escape(cell) for cell in r))
        console.print(table)
        return title

    # Plain ASCII table fallback
    norm_cols = [str(c).replace("\r\n", " ").replace("\n", " ").replace("\r", " ") for c in columns]
    norm_rows = [[cell.replace("\r\n", " ").replace("\n", " ").replace("\r", " ") for cell in r] for r in str_rows]
    widths = [len(c) for c in norm_cols]
    for r in norm_rows:
        for idx, cell in enumerate(r):
            if idx < len(widths):
                widths[idx] = max(widths[idx], min(60, len(cell)))

    def _fmt_row(vals: Sequence[str]) -> str:
        cells = []
        for idx, v in enumerate(vals):
            w = widths[idx] if idx < len(widths) else 20
            clipped = v if len(v) <= 60 else (v[:57] + "...")
            cells.append(clipped.ljust(w))
        return " | ".join(cells)

    lines = [
        f"=== {title} ===",
        _fmt_row(norm_cols),
        "-+-".join("-" * w for w in widths),
    ]
    if not norm_rows:
        lines.append("(no records)")
    else:
        for r in norm_rows:
            lines.append(_fmt_row(r))
    out = "\n".join(lines)
    print(out)
    return out


def render_kv_panel(
    title: str,
    mapping: Dict[str, Any],
    *,
    as_json: bool = False,
    plain: bool = False,
) -> str:
    if as_json:
        return render_json(mapping)

    if _use_rich(plain=plain):
        console = Console()
        body_lines = [
            f"[bold]{_rich_escape(str(k))}[/bold]: {_rich_escape(str(v))}"
            for k, v in mapping.items()
        ]
        console.print(Panel("\n".join(body_lines), title=_rich_escape(str(title))))
        return title

    lines = [f"=== {title} ==="]
    max_k = max((len(str(k)) for k in mapping.keys()), default=10)
    for k, v in mapping.items():
        lines.append(f"{str(k).ljust(max_k)} : {v}")
    out = "\n".join(lines)
    print(out)
    return out


def _truthful_chain_status(ch: Dict[str, Any]) -> str:
    poe_i = int(ch.get("poe_level") or 0)
    raw_st = str(ch.get("verification_status") or "").strip().upper()
    if raw_st == "FIXED":
        return "FIXED"
    if poe_i >= 3:
        return "VERIFIED"
    if poe_i == 2:
        return "LEAD_ACTIVE_INDICATOR"
    if poe_i == 1:
        return "LEAD_PASSIVE_CORRELATION"
    return "UNVERIFIED"


def render_chains(
    chains: Sequence[Dict[str, Any]],
    *,
    title: str = "ARTEX Attack Chains",
    as_json: bool = False,
    plain: bool = False,
) -> str:
    columns = ["Chain ID", "Attack Type", "Hops", "POE", "Status", "Target", "Traffic ID"]
    rows = []
    for ch in chains:
        poe = f"POE={ch.get('poe_level', 0)}"
        status = _truthful_chain_status(ch)
        target = f"{ch.get('target_host', '')}{ch.get('target_endpoint') or ch.get('target_route') or ''}"
        rows.append([
            ch.get("chain_id") or ch.get("node_id") or "",
            ch.get("attack_type") or ch.get("rule_id") or "",
            ch.get("hop_count") or 1,
            poe,
            status,
            target,
            ch.get("traffic_id") or "-",
        ])
    return render_table(title, columns, rows, as_json=as_json, plain=plain, raw_data=list(chains))


def render_traces(
    traces: Sequence[Dict[str, Any]],
    *,
    as_json: bool = False,
    plain: bool = False,
) -> str:
    columns = ["Trace ID", "Worker", "Tool / Action", "Target Asset", "Status", "Summary"]
    rows = []
    for tr in traces:
        summary = tr.get("summary") or tr.get("evidence_quote") or tr.get("result_summary") or ""
        rows.append([
            tr.get("trace_id") or "",
            tr.get("worker_id") or "",
            tr.get("tool_name") or tr.get("action") or "",
            tr.get("target_asset_id") or tr.get("target") or "",
            tr.get("status") or "",
            str(summary)[:60],
        ])
    return render_table("ARTEX Shared Worker Traces", columns, rows, as_json=as_json, plain=plain, raw_data=list(traces))


def render_coverage(
    coverage: Dict[str, Any],
    *,
    as_json: bool = False,
    plain: bool = False,
) -> str:
    if as_json:
        return render_json(coverage)

    summary = {
        "Total In-Scope Assets": coverage.get("total_in_scope_assets", 0),
        "Tested Assets": coverage.get("tested_assets", 0),
        "Untested Assets": coverage.get("untested_assets", 0),
        "Coverage (%)": f"{coverage.get('coverage_pct', 0.0)}%",
    }
    render_kv_panel("ARTEX Asset Coverage Summary", summary, as_json=False, plain=plain)

    assets = coverage.get("assets") or []
    columns = ["Asset ID", "Type", "Label", "Tested", "Intents", "Findings", "Exploits"]
    rows = []
    for a in assets:
        rows.append([
            a.get("asset_id") or "",
            a.get("node_type") or "",
            a.get("label") or "",
            "YES" if a.get("tested") else "NO",
            len(a.get("linked_intents") or []),
            len(a.get("linked_findings") or []),
            len(a.get("linked_exploits") or []),
        ])
    return render_table("Asset Coverage Ledger", columns, rows, as_json=False, plain=plain)


def render_retest_results(
    results: Sequence[Dict[str, Any]],
    *,
    as_json: bool = False,
    plain: bool = False,
) -> str:
    columns = ["Retest ID", "Chain ID", "Verdict", "Replay Traffic", "Summary"]
    rows = []
    for rt in results:
        rows.append([
            rt.get("retest_id") or "",
            rt.get("chain_id") or "",
            rt.get("verdict") or "",
            rt.get("replay_traffic_id") or rt.get("traffic_id") or "-",
            str(rt.get("summary") or rt.get("evidence") or "")[:60],
        ])
    return render_table("ARTEX Retest Results", columns, rows, as_json=as_json, plain=plain, raw_data=list(results))


class LiveScanProgress:
    """
    Pure-CLI live terminal progress table using `rich.live.Live` when attached to
    a TTY, with automatic single-line plain ASCII fallback in CI or piped stdout.
    """

    def __init__(self, title: str = "RFCHunt Live Scan Progress", *, plain: bool = False):
        self.title = title
        self.plain = plain
        self._use_tty = _use_rich(plain=plain)
        self._rows: Dict[str, Tuple[str, str]] = {}
        self._live: Optional[Any] = None

    def _build_table(self) -> Any:
        table = Table(title=_rich_escape(str(self.title)), show_lines=False)
        table.add_column("Phase / Worker")
        table.add_column("Status")
        table.add_column("Detail")
        for phase, (status, detail) in self._rows.items():
            table.add_row(
                _rich_escape(phase),
                _rich_escape(status),
                _rich_escape(detail),
            )
        return table

    def __enter__(self) -> "LiveScanProgress":
        if self._use_tty:
            self._live = Live(self._build_table(), refresh_per_second=4)
            self._live.__enter__()
        return self

    def update(self, phase: str, status: str, detail: str = "") -> None:
        self._rows[str(phase)] = (str(status), str(detail))
        if self._use_tty and self._live is not None:
            self._live.update(self._build_table())
        else:
            suffix = f" - {detail}" if detail else ""
            print(f"[{phase}] {status}{suffix}")

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._live is not None:
            self._live.__exit__(exc_type, exc_val, exc_tb)
            self._live = None


def render_poe_summary(
    poe_breakdown: Optional[Dict[str, Any]],
    coverage: Optional[Dict[str, Any]] = None,
    chains: Optional[Sequence[Dict[str, Any]]] = None,
    traces: Optional[Sequence[Dict[str, Any]]] = None,
    *,
    strict_poe: bool = False,
    include_leads: bool = False,
    as_json: bool = False,
    plain: bool = False,
) -> str:
    """
    Renders POE level breakdown separating Verified Exploits (`POE=3`) from
    Manual Review Leads (`POE=1-2`), asset coverage %, chains, and worker traces.
    """
    poe = dict(poe_breakdown or {})
    cov = dict(coverage or {})
    all_chains = list(chains or [])
    verified_chains = [c for c in all_chains if int(c.get("poe_level") or 0) >= 3]
    lead_chains = [c for c in all_chains if int(c.get("poe_level") or 0) < 3]
    show_leads = bool(include_leads or not strict_poe)

    if as_json:
        return render_json({
            "poe_breakdown": poe,
            "coverage": cov,
            "verified_exploits": verified_chains,
            "manual_review_leads": lead_chains if show_leads else [],
            "chains": verified_chains + (lead_chains if show_leads else []),
            "traces": list(traces or []),
        })

    poe_line = (
        f"POE=3 (VERIFIED_EXPLOIT)={poe.get('VERIFIED_EXPLOIT', len(verified_chains))}, "
        f"POE=2 (ACTIVE_INDICATOR)={poe.get('ACTIVE_INDICATOR', 0)}, "
        f"POE=1 (PASSIVE_CORRELATION)={poe.get('PASSIVE_CORRELATION', 0)}, "
        f"POE=0 (NONE)={poe.get('NONE', 0)}"
    )
    summary = {
        "POE Breakdown": poe_line,
        "Verified Exploits (POE=3)": len(verified_chains),
        "Manual Review Leads (POE=1-2)": len(lead_chains),
        "Asset Coverage": f"{cov.get('tested_assets', 0)}/{cov.get('total_in_scope_assets', 0)} ({cov.get('coverage_pct', 0.0)}%)",
        "Worker Traces": len(traces or []),
    }
    parts = [render_kv_panel("ARTEX POE & Coverage Summary", summary, as_json=False, plain=plain)]
    parts.append(
        render_chains(
            verified_chains,
            title="Verified Exploits (POE=3)",
            as_json=False,
            plain=plain,
        )
    )
    if show_leads:
        parts.append(
            render_chains(
                lead_chains,
                title="Manual Review Leads (POE=1-2)",
                as_json=False,
                plain=plain,
            )
        )
    if traces:
        parts.append(render_traces(list(traces)[:20], as_json=False, plain=plain))
    return "\n".join(parts)
