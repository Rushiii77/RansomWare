"""
monitoring/file_monitor.py

Phase 3: File-System Monitoring.

Watches a single directory (by default the safe test_environment folder,
Section 9) using `watchdog` and records CREATE / MODIFY / DELETE /
MOVE(RENAME) events with timestamps.

This module ONLY records what happened to files. It does not decide
whether the activity is suspicious (that is features/feature_extractor.py)
and it does not try to guess which process caused the event (Section 10 -
exact process attribution is not reliably available from watchdog alone,
so we do not fabricate it here).
"""

import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, List, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config
from utils.logger import get_logger

logger = get_logger("file_monitor")


@dataclass
class FileEvent:
    timestamp: float
    event_type: str          # "created" | "modified" | "deleted" | "moved"
    src_path: str
    dest_path: Optional[str] = None   # only set for "moved" (rename) events
    is_directory: bool = False
    dir_path: str = ""
    ext: str = ""

    def __post_init__(self):
        if not self.dir_path:
            self.dir_path = os.path.dirname(self.src_path) or self.src_path
        if not self.ext and not self.is_directory:
            target = self.dest_path or self.src_path
            _, ext = os.path.splitext(target)
            self.ext = ext.lower()


class _RansomwareBehaviorEventHandler(FileSystemEventHandler):
    """
    Translates raw watchdog callbacks into FileEvent records and pushes
    them into a thread-safe ring buffer owned by FileMonitor.
    """

    def __init__(self, buffer: Deque[FileEvent], lock: threading.Lock,
                 callback: Optional[Callable[[FileEvent], None]] = None):
        super().__init__()
        self._buffer = buffer
        self._lock = lock
        self._callback = callback
        self._ignored_patterns = getattr(config, "IGNORED_FILE_PATTERNS", set())

    def _should_ignore(self, path: str) -> bool:
        base = os.path.basename(path)
        return base in self._ignored_patterns or base.startswith(".~")

    def _record(self, event_type: str, src_path: str,
                dest_path: Optional[str] = None, is_directory: bool = False):
        if self._should_ignore(src_path) or (dest_path and self._should_ignore(dest_path)):
            return

        file_event = FileEvent(
            timestamp=time.time(),
            event_type=event_type,
            src_path=src_path,
            dest_path=dest_path,
            is_directory=is_directory,
        )
        with self._lock:
            self._buffer.append(file_event)

        logger.debug(
            "FS event: %-9s %s%s",
            event_type, src_path,
            f" -> {dest_path}" if dest_path else "",
        )

        if self._callback:
            try:
                self._callback(file_event)
            except Exception:
                logger.exception("Error in file event callback.")

    def on_created(self, event: FileSystemEvent):
        self._record("created", event.src_path, is_directory=event.is_directory)

    def on_modified(self, event: FileSystemEvent):
        # Directories fire spurious "modified" events on every child change;
        # we only care about file-level activity for behavioral features.
        if event.is_directory:
            return
        self._record("modified", event.src_path, is_directory=False)

    def on_deleted(self, event: FileSystemEvent):
        self._record("deleted", event.src_path, is_directory=event.is_directory)

    def on_moved(self, event: FileSystemEvent):
        # This is how watchdog reports renames as well as actual moves.
        self._record(
            "moved", event.src_path,
            dest_path=event.dest_path, is_directory=event.is_directory,
        )


class FileMonitor:
    """
    Watches `watch_path` (recursive=True) and keeps a bounded, thread-safe history of FileEvent objects.

    Usage:
        fm = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)
        fm.start()
        ...
        events = fm.get_recent_events(seconds=10)
        ...
        fm.stop()
    """

    def __init__(self, watch_path: str = config.DEFAULT_WATCH_DIRECTORY,
                 event_callback: Optional[Callable[[FileEvent], None]] = None,
                 history_limit: int = config.FILE_EVENT_HISTORY_LIMIT):
        self.watch_path = watch_path
        self._buffer: Deque[FileEvent] = deque(maxlen=history_limit)
        self._lock = threading.Lock()

        self._handler = _RansomwareBehaviorEventHandler(
            self._buffer, self._lock, callback=event_callback
        )
        self._observer: Optional[Observer] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self):
        if self._observer is not None:
            logger.warning("FileMonitor.start() called but already running.")
            return

        logger.info("Starting file monitor on: %s", self.watch_path)
        self._observer = Observer()
        self._observer.schedule(self._handler, self.watch_path, recursive=True)
        self._observer.start()

    def stop(self):
        if self._observer is None:
            return
        logger.info("Stopping file monitor.")
        self._observer.stop()
        self._observer.join(timeout=5)
        self._observer = None

    def is_running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    # ------------------------------------------------------------------
    # Public read API (thread-safe, O(K) optimized lookup)
    # ------------------------------------------------------------------
    def get_recent_events(self, seconds: Optional[float] = None) -> List[FileEvent]:
        """
        Return recorded events, optionally filtered to the last `seconds`.
        Optimized to scan backwards in O(K) time rather than copying the entire buffer.
        """
        with self._lock:
            if seconds is None:
                return list(self._buffer)

            cutoff = time.time() - seconds
            matched: List[FileEvent] = []
            for event in reversed(self._buffer):
                if event.timestamp >= cutoff:
                    matched.append(event)
                else:
                    break

        matched.reverse()
        return matched

    def clear_events(self):
        with self._lock:
            self._buffer.clear()

    def event_count(self) -> int:
        with self._lock:
            return len(self._buffer)


# ---------------------------------------------------------------------------
# Manual smoke test: `python monitoring/file_monitor.py`
# Create/modify/delete a file in test_environment/ while this runs and
# watch the events print.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    fm = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)
    fm.start()
    print(f"Watching {config.DEFAULT_WATCH_DIRECTORY} — try creating/editing a file there.")
    try:
        while True:
            time.sleep(2)
            events = fm.get_recent_events(seconds=2)
            for e in events:
                extra = f" -> {e.dest_path}" if e.dest_path else ""
                print(f"{time.strftime('%H:%M:%S', time.localtime(e.timestamp))}  "
                      f"{e.event_type.upper():<9} {e.src_path}{extra}")
    except KeyboardInterrupt:
        pass
    finally:
        fm.stop()
