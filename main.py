"""
Thin compatibility CLI forwarding shim for HTTP Terminator / RFCHunt.

All CLI subcommand handlers, unified `--all` orchestration, and argument parsing
live in `rfc_hunt_swarm.py`. This module re-exports the `cmd_*` handlers and
delegates `main()` to `rfc_hunt_swarm.main_swarm(..., caller_profile="main")`
so legacy `python main.py ...` scripts and test suites remain backwards-compatible
with zero duplicate CLI logic.
"""

from typing import Optional, Sequence

from database import Database
import rfc_hunt_swarm as _swarm
from rfc_hunt_swarm import (
    _cmd_evaluate_impl,
    _parse_csv_list,
    cmd_all,
    cmd_archive,
    cmd_artex,
    cmd_artex_loop,
    cmd_auto,
    cmd_build,
    cmd_caldera,
    cmd_cascade,
    cmd_chains,
    cmd_chunk,
    cmd_coverage,
    cmd_dream,
    cmd_ensemble,
    cmd_evaluate,
    cmd_export_advisory,
    cmd_fetch,
    cmd_formal,
    cmd_generate,
    cmd_harness2,
    cmd_hunt,
    cmd_lab,
    cmd_mantis,
    cmd_mcp,
    cmd_permute,
    cmd_proxy,
    cmd_rea,
    cmd_retest,
    cmd_ruler,
    cmd_scanner,
    cmd_stride,
    cmd_traces,
    cmd_weaponize,
)

_IS_SWARM_SHIM = True
_ORIGINAL_DATABASE = Database
_ORIGINAL_SWARM_BINDS = {
    name: obj
    for name, obj in globals().items()
    if name.startswith("cmd_") or name == "_cmd_evaluate_impl"
}

__all__ = [
    "Database",
    "_cmd_evaluate_impl",
    "_parse_csv_list",
    "cmd_all",
    "cmd_archive",
    "cmd_artex",
    "cmd_artex_loop",
    "cmd_auto",
    "cmd_build",
    "cmd_caldera",
    "cmd_cascade",
    "cmd_chains",
    "cmd_chunk",
    "cmd_coverage",
    "cmd_dream",
    "cmd_ensemble",
    "cmd_evaluate",
    "cmd_export_advisory",
    "cmd_fetch",
    "cmd_formal",
    "cmd_generate",
    "cmd_harness2",
    "cmd_hunt",
    "cmd_lab",
    "cmd_mantis",
    "cmd_mcp",
    "cmd_permute",
    "cmd_proxy",
    "cmd_rea",
    "cmd_retest",
    "cmd_ruler",
    "cmd_scanner",
    "cmd_stride",
    "cmd_traces",
    "cmd_weaponize",
    "main",
]


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Delegates `main.py` invocations directly to `rfc_hunt_swarm.main_swarm`."""
    _swarm.main_swarm(argv, caller_profile="main")


if __name__ == "__main__":
    main()
