"""
monitoring/process_monitor.py

Phase 2: Process Monitoring.

Responsibility of this module ONLY:
    - Continuously observe running processes using psutil.
    - Provide thread-safe read access to the latest snapshot.

This module does NOT decide whether a process is suspicious, and it does
NOT terminate anything. That separation is deliberate (Section 29 of the
spec: detection and response are different concerns). Termination lives
in response/process_terminator.py, added in a later phase.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import psutil

from utils.logger import get_logger

logger = get_logger("process_monitor")


@dataclass
class ProcessSnapshot:
    """Immutable-ish record of one process at one point in time."""
    pid: int
    name: str
    exe_path: Optional[str]
    cpu_percent: float
    memory_mb: float
    status: str
    create_time: Optional[float]
    username: Optional[str]
    captured_at: float = field(default_factory=time.time)


class ProcessMonitor:
    """
    Background poller that keeps an in-memory table of running processes.

    Usage:
        monitor = ProcessMonitor()
        monitor.start()
        ...
        procs = monitor.get_all_processes()
        one = monitor.get_process(1234)
        ...
        monitor.stop()
    """

    def __init__(self, poll_interval: float = 2.0):
        self.poll_interval = poll_interval

        self._snapshots: Dict[int, ProcessSnapshot] = {}
        self._lock = threading.Lock()

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Priming pass so psutil's internal cpu_percent baseline is set.
        # (psutil requires a first call to "warm up" per-process cpu_percent)
        self._prime_cpu_percent()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            logger.warning("ProcessMonitor.start() called but already running.")
            return

        logger.info("Starting process monitor (poll interval=%.1fs).", self.poll_interval)
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="ProcessMonitorThread", daemon=True
        )
        self._thread.start()

    def stop(self):
        logger.info("Stopping process monitor.")
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.poll_interval + 2)
        self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------
    def _prime_cpu_percent(self):
        """First call to cpu_percent() always returns 0.0; call it once
        per process now so subsequent readings are meaningful."""
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception:
                # Never let the background thread die silently (Section 38).
                logger.exception("Unexpected error during process poll.")
            self._stop_event.wait(self.poll_interval)

    def _poll_once(self):
        new_snapshots: Dict[int, ProcessSnapshot] = {}

        attrs = ["pid", "name", "exe", "status", "create_time", "username", "cpu_percent", "memory_info"]
        for proc in psutil.process_iter(attrs=attrs):
            try:
                info = proc.info
                cpu = info.get("cpu_percent")
                if cpu is None:
                    cpu = proc.cpu_percent(interval=None) or 0.0

                mem_info = info.get("memory_info")
                mem_mb = (mem_info.rss / (1024 * 1024)) if mem_info else 0.0

                snap = ProcessSnapshot(
                    pid=info.get("pid"),
                    name=info.get("name") or "unknown",
                    exe_path=info.get("exe"),
                    cpu_percent=round(float(cpu), 2),
                    memory_mb=round(mem_mb, 2),
                    status=info.get("status") or "unknown",
                    create_time=info.get("create_time"),
                    username=info.get("username"),
                )
                if snap.pid is not None:
                    new_snapshots[snap.pid] = snap

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                logger.debug("Error reading process info for a process.", exc_info=True)
                continue

        with self._lock:
            self._snapshots = new_snapshots

    # ------------------------------------------------------------------
    # Public read API (thread-safe)
    # ------------------------------------------------------------------
    def get_all_processes(self) -> List[ProcessSnapshot]:
        with self._lock:
            return list(self._snapshots.values())

    def get_process(self, pid: int) -> Optional[ProcessSnapshot]:
        with self._lock:
            return self._snapshots.get(pid)

    def process_count(self) -> int:
        with self._lock:
            return len(self._snapshots)


# ---------------------------------------------------------------------------
# Manual smoke test: `python monitoring/process_monitor.py`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    monitor = ProcessMonitor(poll_interval=2.0)
    monitor.start()
    try:
        for _ in range(3):
            time.sleep(2.5)
            procs = monitor.get_all_processes()
            print(f"\n--- {len(procs)} processes seen ---")
            for p in sorted(procs, key=lambda x: x.cpu_percent, reverse=True)[:5]:
                print(f"{p.pid:>6}  {p.name:<25} CPU={p.cpu_percent:5.1f}%  MEM={p.memory_mb:7.1f}MB  {p.status}")
    finally:
        monitor.stop()
