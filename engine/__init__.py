"""
Protocol Research Engine package for HTTP Terminator and Agent Octopus.
"""

import os as _os
import sys as _sys

# Cap BLAS/OpenMP per-process thread arenas before numpy/scipy load to prevent
# Windows OpenBLAS commit-memory allocation failures in concurrent CLI/test subprocesses.
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "2")
_os.environ.setdefault("OMP_NUM_THREADS", "2")
_os.environ.setdefault("MKL_NUM_THREADS", "2")

# Guard against CPython 3.13+/3.14+ Windows `platform._wmi_query()` indefinite hangs
# when WMI (`winmgmt`) is busy/unresponsive (e.g., during `numpy`/`scipy`/`sklearn`
# imports that invoke `platform.machine()`). Setting `platform._wmi = None` triggers
# CPython's built-in non-blocking `sys.getwindowsversion()` + `winreg` fallback.
if _sys.platform == "win32":
    import platform as _platform

    if getattr(_platform, "_wmi", None) is not None:
        _platform._wmi = None

from engine.taxonomy import (
    AnomalyCategory,
    Arm106DefensiveRule,
    Arm107RegressionTest,
    ImpactClass,
    ImplementationAnomaly,
    NovelTechnique,
    ReproducibleVulnerability,
    RFCRequirement,
    RequirementType,
)
from engine.caldera_bridge import CalderaBridge
from engine.terminator_rfc_selector import TerminatorRFCSelector, TERMINATOR_CORE_RFCS

__all__ = [
    "AnomalyCategory",
    "Arm106DefensiveRule",
    "Arm107RegressionTest",
    "CalderaBridge",
    "ImpactClass",
    "ImplementationAnomaly",
    "NovelTechnique",
    "ReproducibleVulnerability",
    "RFCRequirement",
    "RequirementType",
    "TerminatorRFCSelector",
    "TERMINATOR_CORE_RFCS",
]

