"""
Cross-Process Ollama Concurrency Gate, HTTP 500 OOM Downshift & Circuit Breaker (M1 / Component 7).
====================================================================================================
Prevents concurrent `/swarm` hunters and ensemble scanners from thrashing local Ollama VRAM:
  1. Cross-process OS file lock (`msvcrt.locking` on Windows, `fcntl.flock` on POSIX) paired
     with an in-process reentrant `threading.RLock`.
  2. Deterministic HTTP 500 OOM detection and strict tier-step downshift ladder:
     `>7B -> <=7B -> <=3B -> 1.5B` (never retrying the failed model or jumping sideways).
  3. Bounded failure-threshold circuit breaker with automatic cooldown half-open recovery.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import re
import tempfile
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

if os.name == "nt":
    import msvcrt
else:
    import fcntl

from ollama_manager import is_embedding_model


DEFAULT_LOCK_FILENAME = "rfchunt_ollama_slot.lock"

OOM_ERROR_MARKERS: Tuple[str, ...] = (
    "out of memory",
    "oom",
    "vram",
    "unable to allocate",
    "failed to allocate",
    "requires more system memory",
    "not enough memory",
    "insufficient memory",
    "memory layout cannot be allocated",
    "cuda",
    "cudamalloc",
    "cublas",
    "hip error",
    "metal",
    "ggml_alloc",
    "runner process has terminated",
    "internal server error",
)

_NON_OOM_500_MARKERS: Tuple[str, ...] = (
    "invalid json",
    "json decode",
    "bad request",
    "malformed request",
    "unknown field",
)

_PARAM_SIZE_RE = re.compile(r"(?:^|[:\-_/])(\d+(?:\.\d+)?)\s*[bB](?=$|[:\-_/@])")

_NAMED_SIZE_BILLIONS: Dict[str, float] = {
    "nano": 1.0,
    "tiny": 1.1,
    "mini": 3.8,
    "small": 7.0,
    "medium": 14.0,
    "large": 32.0,
    "flash": 30.0,
}


def parse_model_param_billions(model_tag: str) -> Optional[float]:
    tl = (model_tag or "").strip().lower()
    if not tl:
        return None
    matches = _PARAM_SIZE_RE.findall(tl)
    if matches:
        try:
            return float(matches[-1])
        except ValueError:
            pass
    for kw, size_b in _NAMED_SIZE_BILLIONS.items():
        if re.search(rf"(?:^|[:\-_/]){kw}(?:$|[:\-_/@])", tl):
            return size_b
    return None


def model_size_tier(model_tag: str, *, default_unknown_tier: int = 2) -> Tuple[int, float]:
    """
    Maps a model tag to `(tier_index, params_billions)`:
      - Tier 3: `> 7B`
      - Tier 2: `<= 7B` (`3.0 < params <= 7.0`)
      - Tier 1: `<= 3B` (`1.5 < params <= 3.0`)
      - Tier 0: `<= 1.5B` (`params <= 1.5`)
    """
    params = parse_model_param_billions(model_tag)
    if params is None:
        if default_unknown_tier >= 3:
            return (3, 14.0)
        return (2, 7.0)
    if params > 7.0:
        return (3, params)
    if params > 3.0:
        return (2, params)
    if params > 1.5:
        return (1, params)
    return (0, params)


class OllamaConcurrencyGuard:
    """
    Cross-process single-slot Ollama concurrency gate with OOM tier downshift
    and a bounded cooldown circuit breaker.
    """

    def __init__(
        self,
        *,
        lock_path: Optional[Union[Path, str]] = None,
        acquire_timeout_sec: float = 30.0,
        failure_threshold: int = 2,
        cooldown_sec: float = 60.0,
    ) -> None:
        env_lock = os.environ.get("RFCHUNT_OLLAMA_LOCK_PATH", "").strip()
        if lock_path is not None:
            self.lock_path = Path(lock_path)
        elif env_lock:
            self.lock_path = Path(env_lock)
        else:
            self.lock_path = Path(tempfile.gettempdir()) / DEFAULT_LOCK_FILENAME

        self.acquire_timeout_sec = max(0.05, float(acquire_timeout_sec))
        self.failure_threshold = max(1, int(failure_threshold))
        self.cooldown_sec = max(0.05, float(cooldown_sec))

        self._thread_lock = threading.RLock()
        self._state_lock = threading.RLock()
        self._os_lock_depth = 0
        self._consecutive_failures = 0
        self._opened_at_monotonic: Optional[float] = None

    def _acquire_os_lock(self, deadline: float) -> Optional[int]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o666)
        try:
            if os.fstat(fd).st_size < 1:
                os.write(fd, b"0")
            while True:
                try:
                    if os.name == "nt":
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return fd
                except (OSError, BlockingIOError):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0.0:
                        os.close(fd)
                        return None
                    time.sleep(min(0.025, remaining))
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    @staticmethod
    def _release_os_lock(fd: int) -> None:
        try:
            if os.name == "nt":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    @contextlib.contextmanager
    def acquire(self, timeout_sec: Optional[float] = None) -> Iterator[bool]:
        """
        Acquires the single-slot Ollama concurrency lock (in-process RLock + cross-process
        OS file lock). Yields `True` if acquired within `timeout_sec`, else `False`.
        Reentrant on the same thread without self-deadlock.
        """
        eff_timeout = self.acquire_timeout_sec if timeout_sec is None else max(0.0, float(timeout_sec))
        deadline = time.monotonic() + eff_timeout
        got_thread = self._thread_lock.acquire(blocking=True, timeout=eff_timeout)
        if not got_thread:
            yield False
            return

        if self._os_lock_depth > 0:
            self._os_lock_depth += 1
            try:
                yield True
            finally:
                self._os_lock_depth -= 1
                self._thread_lock.release()
            return

        fd: Optional[int] = None
        try:
            fd = self._acquire_os_lock(deadline)
        except Exception:
            self._thread_lock.release()
            raise

        if fd is None:
            self._thread_lock.release()
            yield False
            return

        self._os_lock_depth = 1
        try:
            yield True
        finally:
            self._os_lock_depth = 0
            self._release_os_lock(fd)
            self._thread_lock.release()

    def downshift_candidates(
        self,
        failed_model: str,
        installed_models: Sequence[str],
    ) -> List[str]:
        """
        Returns installed generative fallback models strictly smaller in parameter tier
        than `failed_model`, ordered along the ladder `>7B -> <=7B -> <=3B -> 1.5B`.
        """
        failed_norm = (failed_model or "").strip().lower()
        failed_tier, _ = model_size_tier(failed_model, default_unknown_tier=3)

        deduped: List[str] = []
        seen: set[str] = set()
        for raw in installed_models:
            tag = str(raw or "").strip()
            if not tag:
                continue
            tag_l = tag.lower()
            if tag_l == failed_norm or tag_l in seen or is_embedding_model(tag):
                continue
            seen.add(tag_l)
            tier, params_b = model_size_tier(tag, default_unknown_tier=2)
            if tier < failed_tier:
                pref_penalty = 0 if ("abliterat" in tag_l or "qwen2.5" in tag_l or "sec" in tag_l) else 1
                deduped.append((tier, params_b, pref_penalty, tag_l, tag))  # type: ignore[arg-type]

        deduped.sort(key=lambda row: (-row[0], -row[1], row[2], row[3]))  # type: ignore[index]
        return [row[4] for row in deduped]  # type: ignore[index]

    def is_oom_500(self, status_code: int, body_text: str = "") -> bool:
        if int(status_code) != 500:
            return False
        body_l = (body_text or "").strip().lower()
        if not body_l:
            return True
        if any(m in body_l for m in _NON_OOM_500_MARKERS) and not any(
            m in body_l for m in OOM_ERROR_MARKERS
        ):
            return False
        return any(m in body_l for m in OOM_ERROR_MARKERS)

    def record_success(self) -> None:
        with self._state_lock:
            self._consecutive_failures = 0
            self._opened_at_monotonic = None

    def record_failure(self, *, is_oom: bool = False) -> None:
        _ = is_oom
        with self._state_lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold:
                self._opened_at_monotonic = time.monotonic()

    def is_circuit_open(self) -> bool:
        with self._state_lock:
            if self._opened_at_monotonic is None:
                return False
            if (time.monotonic() - self._opened_at_monotonic) < self.cooldown_sec:
                return True
            # Cooldown expired: transition to half-open (1 failure re-opens immediately)
            self._opened_at_monotonic = None
            self._consecutive_failures = max(0, self.failure_threshold - 1)
            return False

    def reset(self) -> None:
        with self._state_lock:
            self._consecutive_failures = 0
            self._opened_at_monotonic = None

    def telemetry(self) -> Dict[str, Any]:
        with self._state_lock:
            return {
                "lock_path": str(self.lock_path),
                "consecutive_failures": self._consecutive_failures,
                "failure_threshold": self.failure_threshold,
                "cooldown_sec": self.cooldown_sec,
                "circuit_open": self.is_circuit_open(),
            }


_SHARED_GUARD_LOCK = threading.Lock()
_SHARED_GUARD: Optional[OllamaConcurrencyGuard] = None


def get_shared_ollama_guard() -> OllamaConcurrencyGuard:
    global _SHARED_GUARD
    if _SHARED_GUARD is None:
        with _SHARED_GUARD_LOCK:
            if _SHARED_GUARD is None:
                _SHARED_GUARD = OllamaConcurrencyGuard()
    return _SHARED_GUARD
