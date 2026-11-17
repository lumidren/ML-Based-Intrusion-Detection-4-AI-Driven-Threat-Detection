"""Keep heavy jobs from starving the host machine.

Three guards, all used by the CLI and the experiment scripts:

* :func:`cap_threads` limits the native thread pools of polars, BLAS/OpenMP and LightGBM.
  It must run before those libraries are imported, so the CLI calls it first.
* :func:`lower_priority` drops the process to below-normal priority, so the desktop stays
  responsive while a job runs.
* :class:`MemoryWatchdog` samples the process RSS in a background thread and stops the job
  as soon as it exceeds its budget, or as soon as the machine runs low on free memory while
  this process is a significant consumer. Stopping early is better than letting the OS swap
  until the whole laptop freezes.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType

import psutil

MB = 1024 * 1024
DEFAULT_MEM_LIMIT_MB = 2500
DEFAULT_MIN_FREE_MB = 1000
DEFAULT_THREADS = 4
EXIT_CODE_MEMORY = 86
"""Process exit status when the watchdog stops a job."""

THREAD_ENV_VARS: tuple[str, ...] = (
    "POLARS_MAX_THREADS",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_MAX_THREADS",
)


def cap_threads(n: int = DEFAULT_THREADS) -> dict[str, str]:
    """Set thread-pool sizes (unless the user already set them); return what is in effect.

    Returns the effective values. Warns on stderr if polars was imported before the call,
    because its pool size is fixed at import time.
    """
    n = max(1, n)
    if "polars" in sys.modules:
        print("nids: polars already imported; POLARS_MAX_THREADS may not apply", file=sys.stderr)
    for var in THREAD_ENV_VARS:
        os.environ.setdefault(var, str(n))
    return {var: os.environ[var] for var in THREAD_ENV_VARS}


def lower_priority() -> bool:
    """Run the current process below normal priority. Returns False if the OS refused."""
    proc = psutil.Process()
    try:
        if sys.platform == "win32":
            proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        else:
            proc.nice(max(proc.nice(), 10))
    except (psutil.AccessDenied, OSError):
        return False
    return True


def _default_breach(message: str) -> None:  # pragma: no cover - terminates the process
    print(f"\nnids: {message}", file=sys.stderr, flush=True)
    os._exit(EXIT_CODE_MEMORY)


@dataclass
class Breach:
    rss_mb: float
    available_mb: float
    reason: str


class MemoryWatchdog:
    """Stop the job before it can exhaust the machine's memory.

    Trips when the process RSS exceeds ``limit_mb``, or when system available memory drops
    below ``min_free_mb`` while this process holds more than ``significant_mb``. On a trip
    it calls ``on_breach`` with a message (default: print and exit with status 86).
    """

    def __init__(
        self,
        limit_mb: int = DEFAULT_MEM_LIMIT_MB,
        min_free_mb: int = DEFAULT_MIN_FREE_MB,
        *,
        interval_s: float = 0.25,
        significant_mb: int = 512,
        on_breach: Callable[[str], None] | None = None,
    ) -> None:
        self.limit_mb = limit_mb
        self.min_free_mb = min_free_mb
        self.interval_s = interval_s
        self.significant_mb = significant_mb
        self.on_breach = on_breach or _default_breach
        self.peak_mb = 0.0
        self.breach: Breach | None = None
        self._proc = psutil.Process()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def check(self) -> Breach | None:
        """Take one sample; return a :class:`Breach` if a limit is crossed."""
        rss_mb = self._proc.memory_info().rss / MB
        avail_mb = psutil.virtual_memory().available / MB
        self.peak_mb = max(self.peak_mb, rss_mb)
        if rss_mb > self.limit_mb:
            return Breach(
                rss_mb, avail_mb, f"process memory {rss_mb:.0f} MB > limit {self.limit_mb} MB"
            )
        if avail_mb < self.min_free_mb and rss_mb > self.significant_mb:
            return Breach(
                rss_mb,
                avail_mb,
                f"system free memory {avail_mb:.0f} MB < {self.min_free_mb} MB "
                f"while this job holds {rss_mb:.0f} MB",
            )
        return None

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            breach = self.check()
            if breach is not None:
                self.breach = breach
                self.on_breach(
                    f"stopped to protect the machine: {breach.reason}. "
                    "Raise NIDS_MEM_LIMIT_MB only if the machine has the headroom."
                )
                return

    def start(self) -> MemoryWatchdog:
        self.check()
        self._thread = threading.Thread(target=self._run, name="nids-memory-watchdog", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> float:
        """Stop sampling; return the peak RSS in MB."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self.check()
        return self.peak_mb

    def __enter__(self) -> MemoryWatchdog:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()


def guard(
    limit_mb: int = DEFAULT_MEM_LIMIT_MB,
    min_free_mb: int = DEFAULT_MIN_FREE_MB,
    threads: int = DEFAULT_THREADS,
) -> MemoryWatchdog:
    """Apply all three guards and return the running watchdog (call ``stop()`` at the end)."""
    cap_threads(threads)
    lower_priority()
    return MemoryWatchdog(limit_mb, min_free_mb).start()
