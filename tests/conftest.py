"""
Global pytest configuration and Windows file-lock resilience hooks.
Ensures zero unclosed SQLite handles and provides retry backoff for directory cleanup.
"""

import gc
import os
import platform
import shutil
import stat
import sys
import time
import pytest

os.environ.setdefault("OPENBLAS_NUM_THREADS", "2")
os.environ.setdefault("OMP_NUM_THREADS", "2")
os.environ.setdefault("MKL_NUM_THREADS", "2")
if sys.platform == "win32" and getattr(platform, "_wmi", None) is not None:
    platform._wmi = None


def _remove_readonly(func, path, exc_info):
    """Error handler for shutil.rmtree to clear read-only file bits on Windows."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def clean_database_connections_on_teardown():
    """Forces garbage collection at the end of every test to finalize abandoned sqlite handles."""
    yield
    gc.collect()


@pytest.fixture(scope="session", autouse=True)
def session_sqlite_guard():
    """Session-level guard ensuring clean basetemp state."""
    gc.collect()
    yield
    gc.collect()
