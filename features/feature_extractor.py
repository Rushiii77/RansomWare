"""
features/feature_extractor.py

Phase 4: Feature Extraction.

Converts raw FileEvent history (from monitoring.file_monitor) and,
optionally, a ProcessSnapshot (from monitoring.process_monitor) into a
fixed-size behavioral feature dictionary that can later be fed into the
ML model (Phase 7+).

Every feature here maps directly back to something described in Section
11 of the spec. Nothing is added "just to have more features."
"""

import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import config
from monitoring.file_monitor import FileEvent
from monitoring.process_monitor import ProcessSnapshot
from utils.logger import get_logger

logger = get_logger("feature_extractor")


# Canonical, ordered feature names. Keeping this list explicit (rather than
# relying on dict key order) means the eventual ML pipeline can build a
# consistent feature vector regardless of dict construction order.
FEATURE_NAMES: List[str] = [
    "num_created",
    "num_modified",
    "num_deleted",
    "num_renamed",
    "total_operations",
    "operation_rate_per_sec",
    "unique_directories",
    "unique_extensions",
    "rename_modify_ratio",
    "cpu_percent",
    "memory_mb",
]


@dataclass
class FeatureWindowResult:
    """Feature dict plus the metadata needed to interpret it."""
    window_seconds: float
    event_count: int
    features: Dict[str, float]


class FeatureExtractor:
    """
    Stateless-ish extractor: given a list of FileEvents (already filtered
    to a time window by the caller, e.g. FileMonitor.get_recent_events)
    and an optional ProcessSnapshot, compute the behavioral feature set.

    Usage:
        extractor = FeatureExtractor(window_seconds=10)
        events = file_monitor.get_recent_events(seconds=extractor.window_seconds)
        result = extractor.extract(events, process_snapshot=snap)
    """

    def __init__(self, window_seconds: float = config.FEATURE_WINDOW_SECONDS):
        self.window_seconds = window_seconds

    def extract(self, events: List[FileEvent],
                process_snapshot: Optional[ProcessSnapshot] = None) -> FeatureWindowResult:
        num_created = 0
        num_modified = 0
        num_deleted = 0
        num_renamed = 0

        unique_dirs = set()
        unique_exts = set()

        for e in events:
            if e.is_directory:
                unique_dirs.add(e.dir_path or e.src_path)
                continue

            etype = e.event_type
            if etype == "created":
                num_created += 1
            elif etype == "modified":
                num_modified += 1
            elif etype == "deleted":
                num_deleted += 1
            elif etype == "moved":
                num_renamed += 1

            unique_dirs.add(e.dir_path or os.path.dirname(e.src_path))
            ext = e.ext or (os.path.splitext(e.dest_path or e.src_path)[1].lower() if (e.dest_path or e.src_path) else "")
            if ext:
                unique_exts.add(ext)

        total_ops = num_created + num_modified + num_deleted + num_renamed

        # Guard against divide-by-zero (Section 38: robust against runtime errors)
        operation_rate = total_ops / self.window_seconds if self.window_seconds > 0 else 0.0
        rename_modify_ratio = (
            num_renamed / num_modified if num_modified > 0 else float(num_renamed)
        )

        cpu_percent = process_snapshot.cpu_percent if process_snapshot else 0.0
        memory_mb = process_snapshot.memory_mb if process_snapshot else 0.0

        features = {
            "num_created": float(num_created),
            "num_modified": float(num_modified),
            "num_deleted": float(num_deleted),
            "num_renamed": float(num_renamed),
            "total_operations": float(total_ops),
            "operation_rate_per_sec": round(operation_rate, 3),
            "unique_directories": float(len(unique_dirs)),
            "unique_extensions": float(len(unique_exts)),
            "rename_modify_ratio": round(rename_modify_ratio, 3),
            "cpu_percent": float(cpu_percent),
            "memory_mb": float(memory_mb),
        }

        logger.debug("Extracted features over %.1fs window: %s", self.window_seconds, features)

        return FeatureWindowResult(
            window_seconds=self.window_seconds,
            event_count=len(events),
            features=features,
        )

    def extract_vector(self, events: List[FileEvent],
                       process_snapshot: Optional[ProcessSnapshot] = None) -> List[float]:
        """Directly extract an ordered vector of feature values for ML inference."""
        res = self.extract(events, process_snapshot=process_snapshot)
        return self.to_vector(res.features)

    @staticmethod
    def to_vector(features: Dict[str, float]) -> List[float]:
        """Return features as an ordered list matching FEATURE_NAMES, for
        future consumption by the ML model (Phase 7+)."""
        return [features.get(name, 0.0) for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# Manual smoke test: `python -m features.feature_extractor`
# Combines FileMonitor + FeatureExtractor over the test_environment folder.
# Create/modify files there while this runs to see features change.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from monitoring.file_monitor import FileMonitor

    fm = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)
    extractor = FeatureExtractor(window_seconds=10)

    fm.start()
    print(f"Watching {config.DEFAULT_WATCH_DIRECTORY} for {extractor.window_seconds:.0f}s rolling features.")
    try:
        while True:
            time.sleep(2)
            events = fm.get_recent_events(seconds=extractor.window_seconds)
            result = extractor.extract(events)
            print(f"\n[{time.strftime('%H:%M:%S')}] events_in_window={result.event_count}")
            for k, v in result.features.items():
                print(f"   {k:<24} {v}")
    except KeyboardInterrupt:
        pass
    finally:
        fm.stop()
